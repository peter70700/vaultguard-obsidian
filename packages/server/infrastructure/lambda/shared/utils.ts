/**
 * VaultGuard — Shared Utilities
 *
 * Common helpers used across all Lambda handlers:
 * - DynamoDB client helpers
 * - Permission evaluation logic (glob matching, inheritance resolution)
 * - Audit logging helper
 * - Error response formatter
 * - Request validation middleware
 * - JWT token verification
 */

import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  QueryCommand,
  DeleteCommand,
  UpdateCommand,
  ScanCommand,
  BatchWriteCommand,
} from '@aws-sdk/lib-dynamodb';
import { CognitoJwtVerifier } from 'aws-jwt-verify';
import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { randomBytes, randomUUID } from 'crypto';
import { EDITION } from './edition';

// ─── Environment Configuration ───────────────────────────────────────────────

const REGION = process.env.AWS_REGION || 'eu-west-1';
const COGNITO_USER_POOL_ID = process.env.COGNITO_USER_POOL_ID || process.env.USER_POOL_ID!;
const COGNITO_CLIENT_ID = process.env.COGNITO_CLIENT_ID || process.env.CLIENT_ID!;
// Table names must be supplied by the deploy. The previous silent fallbacks
// (e.g. 'VaultGuard-AuditLog') hid stack-deploy drift as IAM AccessDenied
// errors against tables that do not exist — Terraform names them
// `VaultGuard-${stage}-X`, never the unprefixed form. See vaultguard-stack.ts
// / terraform/modules/lambda/main.tf common_env. Fail loud at module load.
const AUDIT_TABLE = process.env.AUDIT_TABLE!;
const PERMISSIONS_TABLE = process.env.PERMISSIONS_TABLE!;
const SESSIONS_TABLE = process.env.SESSIONS_TABLE!;
const LEASES_TABLE = process.env.LEASES_TABLE!;
const USER_KEYS_TABLE = process.env.USER_KEYS_TABLE!;
const REVOKED_KEYS_TABLE = process.env.REVOKED_KEYS_TABLE!;
// Recovery tables are only referenced by the auth/users handlers (MFA flow),
// but living here keeps the table-name pattern consistent. Fail loud if a
// handler that depends on them is invoked before the env var is wired up.
const RECOVERY_CODES_TABLE = process.env.RECOVERY_CODES_TABLE!;
const RECOVERY_ATTEMPTS_TABLE = process.env.RECOVERY_ATTEMPTS_TABLE!;
const ORGANIZATIONS_TABLE = process.env.ORGANIZATIONS_TABLE!;
const VAULTS_TABLE = process.env.VAULTS_TABLE!;
const VAULT_MEMBERS_TABLE = process.env.VAULT_MEMBERS_TABLE!;
const VAULT_ACTIVITY_TABLE = process.env.VAULT_ACTIVITY_TABLE!;
const SUBSCRIPTIONS_TABLE = process.env.SUBSCRIPTIONS_TABLE!;
const ORG_SETTINGS_CACHE_TTL_MS = 60_000;
const VAULT_ACTIVITY_TTL_DAYS = 14;

// ─── DynamoDB Client ─────────────────────────────────────────────────────────

const dynamoClient = new DynamoDBClient({ region: REGION });

/**
 * DynamoDB Document Client configured with marshalling options.
 * Used across all handlers for table operations.
 */
export const docClient = DynamoDBDocumentClient.from(dynamoClient, {
  marshallOptions: {
    removeUndefinedValues: true,
    convertEmptyValues: false,
  },
});

// ─── Types ───────────────────────────────────────────────────────────────────

/** Represents a verified user identity extracted from a JWT token. */
export interface UserContext {
  userId: string;
  email: string;
  roles: string[];
  sessionId: string;
  /** Organization ID from custom:org token claim. */
  orgId: string;
  /** Whether the current authentication event satisfied an MFA challenge. */
  mfaAuthenticated: boolean;
  /** Unix timestamp of the upstream Cognito authentication event, if present. */
  authTime: number | null;
}

interface ServerSessionRecord {
  sessionId: string;
  userId: string;
  orgId: string;
  expiresAt: string;
  isActive: boolean;
}

/** Supported permission actions. */
export type PermissionAction = 'read' | 'write' | 'delete' | 'admin' | 'list';

/** A single permission rule stored in DynamoDB. */
export interface PermissionRule {
  id: string;
  /** Organization this rule belongs to. */
  orgId: string;
  /** Vault this rule applies to. Permissions are always vault-scoped. */
  vaultId: string;
  /** User ID or '*' for role-based rules. */
  userId: string;
  /** Role name for role-based rules, or null for user-specific. */
  role: string | null;
  /** Glob pattern for the path (e.g., '/engineering/*'). */
  pathPattern: string;
  /** Actions this rule grants or denies. */
  actions: PermissionAction[];
  /** Whether this is an allow or deny rule. */
  effect: 'allow' | 'deny';
  /** Priority for conflict resolution (higher = more specific). */
  priority: number;
  /** ISO timestamp of when the rule was created. */
  createdAt: string;
  /** ISO timestamp of the last update. */
  updatedAt: string;
  /** Optional ISO timestamp after which this rule is ignored (time-bound shares). */
  expiresAt?: string;
  /** User who created this rule. */
  createdBy: string;
}

// ─── Vault types ─────────────────────────────────────────────────────────────

/** Membership role within a single vault. Distinct from org-level role. */
export type VaultMemberRole = 'viewer' | 'editor' | 'admin';

/** Kind of vault — informs default UI affordances. */
export type VaultKind = 'team' | 'personal' | 'shared';

/** A vault — a named, isolated namespace inside an organization. */
export interface VaultRecord {
  /** Hash key — organization that owns this vault. */
  orgId: string;
  /** Range key — server-generated UUID. Stable forever. */
  vaultId: string;
  /** Human-readable display name (e.g., "Engineering Notes"). */
  name: string;
  /** URL-safe lowercased slug, unique within an org. */
  slug: string;
  /** Vault kind for UI labelling. */
  kind: VaultKind;
  /** Default action set granted to org members who join with no explicit role. */
  defaultRole: VaultMemberRole;
  /** ISO timestamp of when the vault was created. */
  createdAt: string;
  /** User ID of the creator. */
  createdBy: string;
  /** Soft-archive flag; archived vaults are read-only and hidden by default. */
  archived: boolean;
  /** Optional ISO description for admin pages. */
  description?: string;
  /**
   * Vault-wide opt-out list. Vault-relative paths or folder prefixes that
   * every member's client must keep off the sync wire. Layered on top of
   * each member's local `excludedPaths` setting.
   */
  excludedPaths?: string[];
  /**
   * Vault-wide curated list of community plugins. When present, member
   * clients prompt the user to enable each entry (after verifying the
   * already-synced bundle hash). This is how admins propagate plugins
   * across all vault members in a controlled way.
   */
  pluginAllowlist?: PluginAllowlistEntry[];
  /**
   * Monotonically increasing counter bumped on every file write/delete in
   * the vault. Lets clients short-circuit the expensive `/files/sync` call
   * whenever the cursor matches the value they last saw — a free way to
   * skip work for idle vaults.
   */
  revision?: number;
  /** ISO timestamp of the most recent file write/delete in this vault. */
  lastChangedAt?: string;
}

/**
 * One curated community-plugin entry attached to a vault.
 *
 * The bytes themselves are not stored here — the plugin's `main.js`,
 * `manifest.json`, and `styles.css` flow through the regular file sync
 * path (under `.obsidian/plugins/{pluginId}/`). This record only carries
 * the metadata members need to (a) decide whether to install the plugin
 * and (b) verify the synced bundle wasn't tampered with.
 */
export interface PluginAllowlistEntry {
  /** Folder name under `.obsidian/plugins/`. Stable identifier. */
  pluginId: string;
  /** Human-readable name shown in the consent prompt. */
  displayName: string;
  /** Pinned version string (from manifest.json), surfaced in the prompt. */
  version?: string;
  /**
   * Optional SHA-256 hex digest of the synced `main.js`. When set, the
   * member client refuses to enable the plugin unless the local copy
   * matches — defense against a malicious member tampering with bundle
   * bytes between admin approval and member install.
   */
  bundleSha256?: string;
  /** ISO timestamp the entry was added. */
  addedAt: string;
  /** User ID of the vault admin who added this entry. */
  addedBy: string;
  /** Free-form admin note shown in the consent prompt (e.g. "Required for export"). */
  note?: string;
}

/** A user's membership in a single vault. */
export interface VaultMemberRecord {
  vaultId: string;
  userId: string;
  /** The user's role inside this vault. */
  role: VaultMemberRole;
  /** ISO timestamp when this user joined. */
  joinedAt: string;
  /** User ID of the admin who granted membership. */
  invitedBy: string;
  /**
   * Optional human-readable name resolved from Cognito at read time.
   * Not persisted in DynamoDB — populated by API handlers so non-admin
   * vault members can render real names without calling the admin-only
   * `/users` endpoint.
   */
  displayName?: string;
  /** Optional email resolved from Cognito at read time. Same caveat. */
  email?: string;
}

/** Result of a permission evaluation. */
export interface PermissionCheckResult {
  allowed: boolean;
  /** The rule that determined the outcome (for audit). */
  matchedRule: PermissionRule | null;
  /** All rules that were evaluated. */
  evaluatedRules: PermissionRule[];
}

/** Audit log entry structure. */
export interface AuditEntry {
  id: string;
  timestamp: string;
  userId: string;
  userEmail?: string;
  orgId: string;
  /** Vault this event belongs to, when the event is vault-scoped. */
  vaultId?: string;
  action: string;
  resourcePath: string;
  outcome: 'success' | 'denied' | 'error';
  metadata?: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
}

/** Structured API error response. */
export interface ErrorResponse {
  statusCode: number;
  error: string;
  message: string;
  requestId?: string;
}

// ─── JWT Token Verification ──────────────────────────────────────────────────

/**
 * Verifies a Cognito JWT token and extracts user context.
 *
 * @param event - The API Gateway event containing the Authorization header
 * @returns The verified user context
 * @throws Error if the token is invalid, expired, or missing
 *
 * @example
 * ```ts
 * const user = await verifyToken(event);
 * console.log(user.userId, user.roles);
 * ```
 */
export async function verifyToken(event: APIGatewayProxyEvent): Promise<UserContext> {
  const authHeader = event.headers?.Authorization || event.headers?.authorization;

  if (!authHeader) {
    throw new AuthError('Missing Authorization header', 401);
  }

  const token = authHeader.replace(/^Bearer\s+/i, '');

  if (!token) {
    throw new AuthError('Invalid Authorization header format', 401);
  }

  if (!COGNITO_USER_POOL_ID || !COGNITO_CLIENT_ID) {
    throw new AuthError('Cognito not configured: missing USER_POOL_ID or CLIENT_ID', 500);
  }

  // Try ID token first (from API Gateway Cognito authorizer), fall back to access token
  const tokenTypes = ['id', 'access'] as const;

  for (const tokenUse of tokenTypes) {
    try {
      const verifier = CognitoJwtVerifier.create({
        userPoolId: COGNITO_USER_POOL_ID,
        tokenUse,
        clientId: COGNITO_CLIENT_ID,
      });
      const payload = await verifier.verify(token);

      return {
        userId: payload.sub,
        email: (payload as Record<string, unknown>).email as string || '',
        roles: extractRolesFromTokenPayload(payload as Record<string, unknown>),
        sessionId: (payload as Record<string, unknown>).jti as string || '',
        orgId: (payload as Record<string, unknown>)['custom:org'] as string || '',
        mfaAuthenticated: extractMfaAuthenticatedFromTokenPayload(payload as Record<string, unknown>),
        authTime:
          typeof (payload as Record<string, unknown>).auth_time === 'number'
            ? ((payload as Record<string, unknown>).auth_time as number)
            : null,
      };
    } catch {
      // Try next token type
    }
  }

  throw new AuthError('Token verification failed: invalid or expired token', 401);
}

/**
 * Verifies a Cognito token and enforces VaultGuard's server-side revocation
 * state. API Gateway's Cognito authorizer accepts a JWT until its natural
 * expiry; this guard closes the gap after admin revocation/session logout by
 * consulting DynamoDB on every protected handler path.
 *
 * The session check is enforced when callers send `X-VaultGuard-Session-Id`.
 * New plugin clients send it on all authenticated API requests. Older admin
 * web clients may not have a VaultGuard server session, so revocation still
 * fails closed through the revoked-key table while session invalidation stays
 * backward compatible.
 */
/**
 * Verifies the caller and asserts the org has an active SaaS subscription.
 *
 * Pass `{ allowPendingCheckout: true }` from billing endpoints so a freshly
 * signed-up org can reach `/billing/checkout` even though its subscription
 * status is still `pending_checkout`. Every other endpoint should use the
 * default — that's what enforces "no usage without a card on file."
 *
 * On `EDITION === 'community'` the subscription gate is a no-op (self-hosters
 * don't have Stripe in the loop).
 */
export async function verifyActiveUser(
  event: APIGatewayProxyEvent,
  options: { allowPendingCheckout?: boolean } = {}
): Promise<UserContext> {
  const user = await verifyToken(event);
  requireOrgId(user);
  await assertUserNotRevoked(user);
  await assertSessionActiveIfPresent(event, user);
  if (!options.allowPendingCheckout) {
    await assertSubscriptionAllowsAccess(user);
  }
  return user;
}

const ALLOWED_SUBSCRIPTION_STATUSES = new Set(['trialing', 'active', 'past_due']);

/**
 * Throws `AuthError(402)` when the org's subscription is missing or in a
 * non-paying state (`pending_checkout`, `canceled`, `unpaid`, …). The error
 * carries `code: 'checkout_required'` so the admin panel can route the user
 * to /#/billing without prompting a re-login.
 *
 * Community Edition installs have no Stripe — skip the check entirely there.
 */
async function assertSubscriptionAllowsAccess(user: UserContext): Promise<void> {
  if (EDITION !== 'pro') return;
  const result = await docClient.send(
    new GetCommand({
      TableName: SUBSCRIPTIONS_TABLE,
      Key: { orgId: user.orgId },
    })
  );
  const status = result.Item?.status as string | undefined;
  if (status && ALLOWED_SUBSCRIPTION_STATUSES.has(status)) return;

  throw new AuthError(
    'A Pro subscription is required. Complete checkout to continue.',
    402,
    'checkout_required'
  );
}

export async function assertUserNotRevoked(user: UserContext): Promise<void> {
  const result = await docClient.send(
    new GetCommand({
      TableName: REVOKED_KEYS_TABLE,
      Key: { userId: user.userId },
    })
  );

  if (result.Item) {
    throw new AuthError('Access has been revoked. Contact your administrator.', 403);
  }
}

async function assertSessionActiveIfPresent(
  event: APIGatewayProxyEvent,
  user: UserContext
): Promise<void> {
  const sessionId = getSessionIdFromRequest(event);
  if (!sessionId) return;

  const result = await docClient.send(
    new GetCommand({
      TableName: SESSIONS_TABLE,
      Key: { sessionId },
    })
  );

  const session = result.Item as ServerSessionRecord | undefined;
  if (
    !session ||
    !session.isActive ||
    session.userId !== user.userId ||
    session.orgId !== user.orgId
  ) {
    throw new AuthError('Session has been revoked. Please sign in again.', 401);
  }

  if (new Date(session.expiresAt) <= new Date()) {
    throw new AuthError('Session expired. Please sign in again.', 401);
  }
}

function getSessionIdFromRequest(event: APIGatewayProxyEvent): string {
  const headers = event.headers ?? {};
  const headerValue = Object.entries(headers).find(
    ([key]) => key.toLowerCase() === 'x-vaultguard-session-id'
  )?.[1];

  return typeof headerValue === 'string' ? headerValue.trim() : '';
}

function extractRolesFromTokenPayload(payload: Record<string, unknown>): string[] {
  const groupRoles = Array.isArray(payload['cognito:groups'])
    ? (payload['cognito:groups'] as unknown[])
        .filter((value): value is string => typeof value === 'string')
    : [];

  const customRoles = [
    payload['custom:orgRole'],
    payload['custom:role'],
  ].filter((value): value is string => typeof value === 'string' && value.length > 0);

  return [...new Set([...groupRoles, ...customRoles].map((role) => role.trim().toLowerCase()))];
}

function extractMfaAuthenticatedFromTokenPayload(payload: Record<string, unknown>): boolean {
  const rawAmr = payload.amr ?? payload['cognito:amr'];
  const methods = Array.isArray(rawAmr)
    ? rawAmr
        .filter((value): value is string => typeof value === 'string')
        .map((value) => value.trim().toLowerCase())
    : typeof rawAmr === 'string'
      ? rawAmr
          .split(/[,\s]+/)
          .map((value) => value.trim().toLowerCase())
          .filter((value) => value.length > 0)
      : [];

  return methods.some((method) =>
    method === 'mfa'
    || method === 'sms_mfa'
    || method === 'software_token_mfa'
    || method === 'totp'
    || method.includes('mfa')
  );
}

// ─── Permission Evaluation Logic ─────────────────────────────────────────────

/**
 * Evaluates whether a user is allowed to perform an action on a given path.
 *
 * Resolution strategy:
 * 1. Gather all rules matching the user (by userId, role, or wildcard).
 * 2. Filter rules whose pathPattern matches the target path (glob + inheritance).
 * 3. Sort by specificity (most-specific-path wins).
 * 4. Explicit deny always overrides allow at same specificity level.
 *
 * @param userId - The user requesting access
 * @param roles - The user's roles
 * @param action - The action being attempted
 * @param path - The resource path
 * @returns PermissionCheckResult with the decision and matched rules
 *
 * @example
 * ```ts
 * const result = await evaluatePermission('user-123', ['engineer'], 'read', '/engineering/docs/spec.md', 'org_abc');
 * if (!result.allowed) {
 *   return formatError(403, 'Access denied');
 * }
 * ```
 */
export async function evaluatePermission(
  userId: string,
  roles: string[],
  action: PermissionAction,
  path: string,
  orgId: string,
  vaultId: string
): Promise<PermissionCheckResult> {
  if (!vaultId) {
    throw new Error('CRITICAL: evaluatePermission called without vaultId — vault isolation breach prevented');
  }

  // Org admins / owners / vault-admins have full access in every vault within
  // their org. This mirrors `requireVaultMember()` which already bypasses the
  // membership check for org admins; without this bypass an org admin can
  // resolve a vault but still get 403 on individual file ops whenever the
  // vault has no permission rule for them (e.g. vaults created before the
  // default-rule helper existed, or members added before that code shipped).
  if (rolesIncludeOrgAdmin(roles)) {
    return { allowed: true, matchedRule: null, evaluatedRules: [] };
  }

  // Fetch all potentially applicable rules, scoped to the caller's org + vault.
  const rules = await fetchApplicableRules(userId, roles, orgId, vaultId);

  // Drop expired time-bound rules.
  const now = new Date().toISOString();
  const liveRules = rules.filter((rule) => !rule.expiresAt || rule.expiresAt > now);

  // Filter to rules that match the requested path
  const matchingRules = liveRules.filter((rule) => {
    return pathMatchesPattern(path, rule.pathPattern) && rule.actions.includes(action);
  });

  if (matchingRules.length === 0) {
    // Vault membership default — when a member has no rule that covers the
    // path (legacy memberships pre-dating the default-rule helper, brand-new
    // files at vault root, etc.), grant access at the membership role's
    // baseline. Without this, anyone whose default rule wasn't created
    // gets 403 on every file in their own vault.
    const membership = await getVaultMembership(vaultId, userId);
    if (membership && vaultRoleAllowsAction(membership.role, action)) {
      return { allowed: true, matchedRule: null, evaluatedRules: liveRules };
    }
    return { allowed: false, matchedRule: null, evaluatedRules: liveRules };
  }

  // Sort by specificity: more specific paths first, then deny over allow
  const sorted = matchingRules.sort((a, b) => {
    const specificityDiff = getPathSpecificity(b.pathPattern) - getPathSpecificity(a.pathPattern);
    if (specificityDiff !== 0) return specificityDiff;
    // At same specificity, deny wins over allow
    if (a.effect === 'deny' && b.effect === 'allow') return -1;
    if (a.effect === 'allow' && b.effect === 'deny') return 1;
    return b.priority - a.priority;
  });

  const winningRule = sorted[0];

  return {
    allowed: winningRule.effect === 'allow',
    matchedRule: winningRule,
    evaluatedRules: matchingRules,
  };
}

/**
 * Finds deny rules inside a requested key-lease scope for this user. A broad
 * DEK lease can decrypt every ciphertext produced under its scope, so issuing
 * `/**` while a user has a deny on `/secret/**` would undermine the ACL model.
 * Lease issuance uses this helper to fail closed whenever a requested scope
 * contains a live deny for the requested action.
 */
export async function findApplicableDenyRulesInScope(
  userId: string,
  roles: string[],
  action: PermissionAction,
  scope: string,
  orgId: string,
  vaultId: string
): Promise<PermissionRule[]> {
  if (rolesIncludeOrgAdmin(roles)) {
    return [];
  }

  const rules = await fetchApplicableRules(userId, roles, orgId, vaultId);
  const now = new Date().toISOString();
  return rules.filter((rule) => {
    if (rule.effect !== 'deny') return false;
    if (!rule.actions.includes(action)) return false;
    if (rule.expiresAt && rule.expiresAt <= now) return false;
    return scopesOverlap(scope, rule.pathPattern);
  });
}

function scopesOverlap(left: string, right: string): boolean {
  return pathMatchesPattern(left, right) || pathMatchesPattern(right, left);
}

/**
 * Fetches all permission rules applicable to a user (by ID, roles, or wildcard).
 *
 * @param userId - The user ID to fetch rules for
 * @param roles - The user's roles
 * @returns Array of matching permission rules
 */
async function fetchApplicableRules(
  userId: string,
  roles: string[],
  orgId: string,
  vaultId: string
): Promise<PermissionRule[]> {
  const results: PermissionRule[] = [];

  // Tenant + vault filter — every query enforces both layers of isolation.
  const scopeFilter = {
    FilterExpression: 'orgId = :orgId AND vaultId = :vaultId',
    scopeValues: { ':orgId': orgId, ':vaultId': vaultId } as Record<string, unknown>,
  };

  // Fetch user-specific rules
  const userRulesResult = await docClient.send(
    new QueryCommand({
      TableName: PERMISSIONS_TABLE,
      IndexName: 'userId-index',
      KeyConditionExpression: 'userId = :uid',
      FilterExpression: scopeFilter.FilterExpression,
      ExpressionAttributeValues: { ':uid': userId, ...scopeFilter.scopeValues },
    })
  );
  if (userRulesResult.Items) {
    results.push(...(userRulesResult.Items as PermissionRule[]));
  }

  // Fetch role-based rules
  for (const role of roles) {
    const roleRulesResult = await docClient.send(
      new QueryCommand({
        TableName: PERMISSIONS_TABLE,
        IndexName: 'role-index',
        KeyConditionExpression: '#role = :role',
        ExpressionAttributeNames: { '#role': 'role' },
        FilterExpression: scopeFilter.FilterExpression,
        ExpressionAttributeValues: { ':role': role, ...scopeFilter.scopeValues },
      })
    );
    if (roleRulesResult.Items) {
      results.push(...(roleRulesResult.Items as PermissionRule[]));
    }
  }

  // Fetch wildcard rules (apply to all users within the same org+vault)
  const wildcardResult = await docClient.send(
    new QueryCommand({
      TableName: PERMISSIONS_TABLE,
      IndexName: 'userId-index',
      KeyConditionExpression: 'userId = :uid',
      FilterExpression: scopeFilter.FilterExpression,
      ExpressionAttributeValues: { ':uid': '*', ...scopeFilter.scopeValues },
    })
  );
  if (wildcardResult.Items) {
    results.push(...(wildcardResult.Items as PermissionRule[]));
  }

  return results;
}

/**
 * Checks if a file path matches a permission pattern.
 * Supports glob patterns and parent-folder inheritance.
 *
 * Pattern rules:
 * - '*' matches any single path segment
 * - '**' matches zero or more path segments
 * - '/folder/' pattern grants access to all children (inheritance)
 * - Exact path matches take highest priority
 *
 * @param filePath - The actual file path to check
 * @param pattern - The glob pattern from the permission rule
 * @returns Whether the path matches the pattern
 */
export function pathMatchesPattern(filePath: string, pattern: string): boolean {
  // Normalize paths
  const normalizedPath = filePath.replace(/\/+/g, '/').replace(/\/$/, '');
  const normalizedPattern = pattern.replace(/\/+/g, '/').replace(/\/$/, '');

  // Exact match
  if (normalizedPath === normalizedPattern) {
    return true;
  }

  // Convert glob pattern to regex
  const regexStr = normalizedPattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&') // Escape special regex chars (not * or ?)
    .replace(/\*\*/g, '{{GLOBSTAR}}') // Temporarily replace **
    .replace(/\*/g, '[^/]+') // Single * = one segment
    .replace(/\?/g, '[^/]') // ? = single char
    .replace(/{{GLOBSTAR}}/g, '.*'); // ** = any number of segments

  const regex = new RegExp(`^${regexStr}$`);

  if (regex.test(normalizedPath)) {
    return true;
  }

  // Inheritance: check if any parent folder of filePath matches the pattern
  const pathSegments = normalizedPath.split('/');
  for (let i = pathSegments.length - 1; i >= 1; i--) {
    const parentPath = pathSegments.slice(0, i).join('/');
    if (regex.test(parentPath)) {
      return true;
    }
  }

  return false;
}

/**
 * Calculates path specificity for conflict resolution.
 * More segments and fewer wildcards = more specific.
 *
 * @param pattern - The path pattern to score
 * @returns Numeric specificity score (higher = more specific)
 */
function getPathSpecificity(pattern: string): number {
  const segments = pattern.split('/').filter(Boolean);
  let score = segments.length * 10;

  // Penalize wildcards (less specific)
  for (const segment of segments) {
    if (segment === '**') score -= 8;
    else if (segment === '*') score -= 5;
    else if (segment.includes('*') || segment.includes('?')) score -= 3;
  }

  return score;
}

// ─── Audit Logging ───────────────────────────────────────────────────────────

/**
 * Extracts the optional agent-attribution headers `X-VG-Agent-Name` and
 * `X-VG-Lease-Id` from an API Gateway event. Used by `logAudit` to tag
 * audit rows produced by agent-bridge-originated requests with the
 * calling agent's identity.
 *
 * Header lookup is case-insensitive (API Gateway preserves caller casing
 * but the spec is case-insensitive). Each value is stripped of
 * CR/LF/control chars (defense-in-depth against header smuggling — the
 * client also sanitizes in `sanitizeAgentField`) and capped at 128 chars
 * so an oversized lease ID can't bloat every audit row.
 *
 * Returns an object with only the keys present; absent or empty-after-
 * sanitization values are omitted so callers can spread the result
 * without leaking `agentName: undefined` keys into the saved metadata.
 */
function extractAgentHeaders(
  event?: APIGatewayProxyEvent
): { agentName?: string; leaseId?: string } {
  if (!event?.headers) return {};
  const lookup = (name: string): string | undefined => {
    const target = name.toLowerCase();
    for (const [k, v] of Object.entries(event.headers)) {
      if (k.toLowerCase() === target && typeof v === 'string') {
        // eslint-disable-next-line no-control-regex
        const cleaned = v.replace(/[\r\n\x00-\x1f\x7f]/g, '').trim().slice(0, 128);
        return cleaned || undefined;
      }
    }
    return undefined;
  };
  const result: { agentName?: string; leaseId?: string } = {};
  const agentName = lookup('X-VG-Agent-Name');
  if (agentName) result.agentName = agentName;
  const leaseId = lookup('X-VG-Lease-Id');
  if (leaseId) result.leaseId = leaseId;
  return result;
}

/**
 * Writes an audit log entry to the AuditLog DynamoDB table.
 * All handler operations must call this to maintain a complete audit trail.
 *
 * @param entry - The audit entry to log (id and timestamp auto-generated if missing)
 * @param event - Optional API Gateway event. When supplied, `X-VG-Agent-Name`
 *   and `X-VG-Lease-Id` headers (if present) are merged into the row's
 *   metadata so agent-bridge-originated operations are attributable.
 *   Header-derived values win over caller-supplied metadata of the same
 *   name (defense — headers are authenticated by the Cognito authorizer
 *   while caller metadata is not).
 *
 * @example
 * ```ts
 * await logAudit({
 *   userId: user.userId,
 *   action: 'file.read',
 *   resourcePath: '/engineering/spec.md',
 *   outcome: 'success',
 *   metadata: { fileSize: 2048 },
 * }, event);
 * ```
 */
export async function logAudit(
  entry: Omit<AuditEntry, 'id' | 'timestamp'> & { id?: string; timestamp?: string },
  event?: APIGatewayProxyEvent
): Promise<void> {
  const id = entry.id || generateId();
  const timestamp = entry.timestamp || new Date().toISOString();
  const dateStr = timestamp.split('T')[0]; // YYYY-MM-DD
  const expiresAtTtl = await getAuditExpiryTtl(entry.orgId, timestamp);
  const vaultId = entry.vaultId
    || extractVaultIdFromMetadata(entry.metadata)
    || extractVaultIdFromResourcePath(entry.resourcePath);

  // Header-derived agent attribution wins over caller metadata (see fn doc).
  const agentHeaders = extractAgentHeaders(event);
  const metadata = {
    ...(entry.metadata ?? {}),
    ...(agentHeaders.agentName ? { agentName: agentHeaders.agentName } : {}),
    ...(agentHeaders.leaseId ? { leaseId: agentHeaders.leaseId } : {}),
  };

  const auditEntry: Record<string, unknown> = {
    // DynamoDB composite key: pk = orgId#date, sk = timestamp#eventId
    pk: `${entry.orgId || 'system'}#${dateStr}`,
    sk: `${timestamp}#${id}`,
    id,
    timestamp,
    userId: entry.userId,
    orgId: entry.orgId,
    ...(vaultId ? { vaultId } : {}),
    action: entry.action,
    resourcePath: entry.resourcePath,
    outcome: entry.outcome,
    metadata,
    ipAddress: entry.ipAddress,
    userAgent: entry.userAgent,
    // GSI attributes
    filePath: entry.resourcePath,
    expiresAtTtl,
  };

  if (entry.userEmail) {
    auditEntry.userEmail = entry.userEmail;
  }

  try {
    await docClient.send(
      new PutCommand({
        TableName: AUDIT_TABLE,
        Item: auditEntry,
      })
    );
  } catch (err) {
    // Audit logging should never block the main operation.
    // Log the failure for monitoring but don't throw.
    console.error('[AUDIT_LOG_FAILURE]', err, { action: auditEntry.action, userId: auditEntry.userId, orgId: auditEntry.orgId });
  }
}

function extractVaultIdFromMetadata(metadata: Record<string, unknown> | undefined): string | undefined {
  const value = metadata?.vaultId;
  return typeof value === 'string' && value.trim() ? value : undefined;
}

function extractVaultIdFromResourcePath(resourcePath: string | undefined): string | undefined {
  if (!resourcePath) return undefined;
  const match = resourcePath.match(/^\/vaults\/([^/]+)/);
  return match?.[1] ? decodeURIComponent(match[1]) : undefined;
}

async function getAuditExpiryTtl(orgId: string | undefined, timestamp: string): Promise<number> {
  const fallbackRetentionDays = DEFAULT_ORG_SETTINGS.retentionDays;
  let retentionDays = fallbackRetentionDays;

  try {
    const settings = orgId ? await getEffectiveOrgSettings(orgId) : null;
    retentionDays = settings?.retentionDays ?? fallbackRetentionDays;
  } catch (error) {
    console.error('[AUDIT_RETENTION_LOOKUP_FAILURE]', (error as Error).message, { orgId });
  }

  const eventTimeMs = new Date(timestamp).getTime();
  const baseTimeMs = Number.isNaN(eventTimeMs) ? Date.now() : eventTimeMs;

  return Math.floor(baseTimeMs / 1000) + retentionDays * 24 * 60 * 60;
}

// ─── Error Handling ──────────────────────────────────────────────────────────

/**
 * Custom error class for authentication failures.
 * Carries an HTTP status code for proper API response formatting.
 */
export class AuthError extends Error {
  public statusCode: number;
  /** Optional machine-readable marker (e.g. `checkout_required`) so callers
   *  can route on the failure rather than just showing a toast. */
  public code?: string;

  constructor(message: string, statusCode: number = 401, code?: string) {
    super(message);
    this.name = 'AuthError';
    this.statusCode = statusCode;
    this.code = code;
  }
}

/**
 * Custom error class for permission/authorization failures.
 */
export class PermissionError extends Error {
  public statusCode: number;

  constructor(message: string, statusCode: number = 403) {
    super(message);
    this.name = 'PermissionError';
    this.statusCode = statusCode;
  }
}

/**
 * Custom error class for validation failures.
 */
export class ValidationError extends Error {
  public statusCode: number;
  public field?: string;

  constructor(message: string, field?: string) {
    super(message);
    this.name = 'ValidationError';
    this.statusCode = 400;
    this.field = field;
  }
}

const ALLOWED_CORS_ORIGIN = process.env.ALLOWED_CORS_ORIGIN || 'https://admin.example.com';

/** Standard security headers applied to every API response. */
function SECURITY_HEADERS(requestId?: string): Record<string, string> {
  return {
    'Content-Type': 'application/json',
    'X-Request-Id': requestId || '',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Cache-Control': 'no-store',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Access-Control-Allow-Origin': ALLOWED_CORS_ORIGIN,
    'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-VaultGuard-Session-Id',
  };
}

/**
 * Formats an error into a structured API Gateway response.
 *
 * @param statusCode - HTTP status code
 * @param message - Human-readable error message
 * @param requestId - Optional request ID for tracing
 * @returns Formatted API Gateway proxy result
 */
export function formatError(
  statusCode: number,
  message: string,
  requestId?: string,
  code?: string
): APIGatewayProxyResult {
  const errorName = getErrorName(statusCode);

  const body: ErrorResponse & { code?: string } = {
    statusCode,
    error: errorName,
    message,
    requestId,
  };
  if (code) body.code = code;

  return {
    statusCode,
    headers: SECURITY_HEADERS(requestId),
    body: JSON.stringify(body),
  };
}

/**
 * Formats a successful API response with standard headers.
 *
 * @param statusCode - HTTP status code (200, 201, etc.)
 * @param body - Response body to serialize as JSON
 * @param requestId - Optional request ID for tracing
 * @returns Formatted API Gateway proxy result
 */
export function formatSuccess(
  statusCode: number,
  body: unknown,
  requestId?: string
): APIGatewayProxyResult {
  return {
    statusCode,
    headers: SECURITY_HEADERS(requestId),
    body: JSON.stringify(body),
  };
}

/**
 * Maps HTTP status codes to standard error names.
 */
function getErrorName(statusCode: number): string {
  const map: Record<number, string> = {
    400: 'Bad Request',
    401: 'Unauthorized',
    402: 'Payment Required',
    403: 'Forbidden',
    404: 'Not Found',
    409: 'Conflict',
    422: 'Unprocessable Entity',
    429: 'Too Many Requests',
    500: 'Internal Server Error',
    503: 'Service Unavailable',
  };
  return map[statusCode] || 'Error';
}

// ─── Request Validation Middleware ───────────────────────────────────────────

/**
 * Validates that required fields exist in the request body.
 * Throws a ValidationError if any required field is missing.
 *
 * @param body - Parsed request body
 * @param requiredFields - Array of field names that must be present
 * @throws ValidationError if validation fails
 *
 * @example
 * ```ts
 * const body = parseBody(event);
 * validateRequiredFields(body, ['pathPattern', 'actions', 'effect']);
 * ```
 */
export function validateRequiredFields(
  body: Record<string, unknown>,
  requiredFields: string[]
): void {
  for (const field of requiredFields) {
    if (body[field] === undefined || body[field] === null || body[field] === '') {
      throw new ValidationError(`Missing required field: ${field}`, field);
    }
  }
}

/**
 * Safely parses the event body as JSON.
 * Returns an empty object if body is null or invalid JSON.
 *
 * @param event - The API Gateway event
 * @returns Parsed body object
 */
export function parseBody(event: APIGatewayProxyEvent): Record<string, unknown> {
  if (!event.body) return {};

  try {
    const body = event.isBase64Encoded
      ? Buffer.from(event.body, 'base64').toString('utf-8')
      : event.body;
    return JSON.parse(body);
  } catch {
    throw new ValidationError('Invalid JSON in request body');
  }
}

/**
 * Extracts the client IP address from the API Gateway event.
 *
 * @param event - The API Gateway event
 * @returns Client IP address string
 */
export function getClientIp(event: APIGatewayProxyEvent): string {
  return (
    event.headers?.['X-Forwarded-For']?.split(',')[0]?.trim() ||
    event.requestContext?.identity?.sourceIp ||
    'unknown'
  );
}

/**
 * Extracts the User-Agent from the request headers.
 *
 * @param event - The API Gateway event
 * @returns User-Agent string
 */
export function getUserAgent(event: APIGatewayProxyEvent): string {
  return event.headers?.['User-Agent'] || event.headers?.['user-agent'] || 'unknown';
}

// ─── Utility Helpers ─────────────────────────────────────────────────────────

/**
 * Generates a unique ID suitable for DynamoDB primary keys.
 * Uses cryptographically secure randomness. Several backend IDs double as
 * bearer material (session IDs, lease IDs, refresh tokens, reset/job IDs), so
 * `Math.random()` is never acceptable here.
 *
 * @returns A unique string ID
 */
export function generateId(): string {
  if (typeof randomUUID === 'function') {
    return randomUUID();
  }
  return randomBytes(16).toString('hex');
}

/**
 * Generates high-entropy bearer material for refresh/session-like secrets.
 * URL-safe base64 keeps tokens transport-friendly while preserving 256 bits
 * of entropy.
 */
export function generateSecretToken(): string {
  return randomBytes(32).toString('base64url');
}

/**
 * Checks if a user has admin role.
 *
 * @param user - The user context
 * @returns True if the user is an admin
 */
export function isAdmin(user: UserContext): boolean {
  return rolesIncludeOrgAdmin(user.roles);
}

/** Whether a roles list grants org-level admin privileges. */
export function rolesIncludeOrgAdmin(roles: string[] | undefined): boolean {
  if (!roles) return false;
  return roles.includes('admin')
    || roles.includes('vault-admin')
    || roles.includes('owner');
}

/**
 * Validates that the user has a non-empty orgId. Every authenticated API call
 * that touches tenant-scoped data MUST call this before proceeding.
 * Throws AuthError if orgId is missing — no fallback to empty string.
 */
export function requireOrgId(user: UserContext): string {
  if (!user.orgId) {
    throw new AuthError('Organization membership required. Contact your administrator.', 403);
  }
  return user.orgId;
}

/**
 * Sanitizes a file path to prevent directory traversal attacks.
 * Rejects paths containing '..', null bytes, or other escape sequences.
 * Returns the cleaned path or throws ValidationError.
 */
export function sanitizeFilePath(filePath: string): string {
  if (!filePath) {
    throw new ValidationError('File path is required', 'path');
  }

  // Reject null bytes
  if (filePath.includes('\0')) {
    throw new ValidationError('Invalid file path: contains null bytes', 'path');
  }

  // Normalize slashes and remove leading/trailing slashes
  const normalized = filePath
    .replace(/\\/g, '/')
    .replace(/\/+/g, '/')
    .replace(/^\/+/, '')
    .replace(/\/+$/, '');

  // Reject traversal sequences after normalization
  const segments = normalized.split('/');
  for (const segment of segments) {
    if (segment === '..' || segment === '.') {
      throw new ValidationError('Invalid file path: directory traversal not allowed', 'path');
    }
  }

  if (!normalized) {
    throw new ValidationError('File path is required', 'path');
  }

  return normalized;
}

// ─── Plan Limits (single source of truth) ───────────────────────────────────
// SaaS has no free tier: every org is Pro (or Enterprise) from signup, with a
// 14-day Stripe trial that requires a card on file. See docs/TERMINOLOGY.md
// and infrastructure/lambda/signup/handler.ts for the pending_checkout state.

export type PlanTier = 'pro' | 'enterprise';

export interface PlanLimits {
  maxUsers: number;
  maxStorageBytes: number;
}

export const PLAN_LIMITS: Record<PlanTier, PlanLimits> = {
  pro:        { maxUsers: 100,    maxStorageBytes: 100 * 1024 * 1024 * 1024 },        // 100 GB
  enterprise: { maxUsers: -1,     maxStorageBytes: -1 },                               // unlimited
};

export interface OrgSettings {
  orgId: string;
  orgName: string;
  syncMode: 'realtime' | 'periodic' | 'manual';
  syncIntervalMinutes: number;
  enforceEncryption: boolean;
  maxSessionDurationHours: number;
  requireMfa: boolean;
  allowedDomains: string[];
  retentionDays: number;
  autoLockMinutes: number;
}

export type PersistedOrgSettings = Omit<OrgSettings, 'orgId' | 'orgName'>;

export const DEFAULT_ORG_SETTINGS: PersistedOrgSettings = {
  syncMode: 'periodic',
  syncIntervalMinutes: 1,
  enforceEncryption: true,
  maxSessionDurationHours: 24,
  requireMfa: false,
  allowedDomains: [],
  retentionDays: 365,
  autoLockMinutes: 30,
};

const orgSettingsCache = new Map<string, {
  settings: OrgSettings;
  expiresAt: number;
}>();

// ─── Organization & Usage Enforcement ───────────────────────────────────────

/** Organization record from the Organizations DynamoDB table. */
export interface OrgRecord {
  slug: string;
  orgId: string;
  name: string;
  ownerUserId: string;
  ownerEmail?: string;
  tier: PlanTier;
  status: 'active' | 'suspended' | 'cancelled';
  maxUsers: number;
  maxStorageBytes: number;
  currentUsers: number;
  currentStorageBytes: number;
  stripeCustomerId?: string;
  stripeSubscriptionId?: string;
  createdAt?: string;
  updatedAt?: string;
  settings?: Partial<PersistedOrgSettings> | null;
}

/** Result of an org enforcement check. */
export interface OrgEnforcementResult {
  allowed: boolean;
  org: OrgRecord | null;
  reason?: string;
  code?: 'ORG_NOT_FOUND' | 'ORG_SUSPENDED' | 'USER_LIMIT' | 'STORAGE_LIMIT';
}

/**
 * Looks up the org by orgId (from the user's token) and checks that it is active.
 * Returns the org record if found and active, or an error result.
 */
export async function getActiveOrg(orgId: string): Promise<OrgEnforcementResult> {
  if (!orgId) {
    return { allowed: false, org: null, reason: 'No organization ID in user context', code: 'ORG_NOT_FOUND' };
  }

  const result = await docClient.send(
    new QueryCommand({
      TableName: ORGANIZATIONS_TABLE,
      IndexName: 'orgId-index',
      KeyConditionExpression: 'orgId = :oid',
      ExpressionAttributeValues: { ':oid': orgId },
    })
  );

  const org = result.Items?.[0] as OrgRecord | undefined;

  if (!org) {
    return { allowed: false, org: null, reason: `Organization not found: ${orgId}`, code: 'ORG_NOT_FOUND' };
  }

  if (org.status === 'suspended') {
    return { allowed: false, org, reason: 'Organization is suspended. Please update your billing to continue.', code: 'ORG_SUSPENDED' };
  }

  if (org.status === 'cancelled') {
    return { allowed: false, org, reason: 'Organization has been cancelled.', code: 'ORG_SUSPENDED' };
  }

  return { allowed: true, org };
}

export function buildOrgSettings(orgId: string, org: OrgRecord): OrgSettings {
  return {
    orgId,
    orgName: typeof org.name === 'string' && org.name.trim().length > 0 ? org.name.trim() : orgId,
    ...DEFAULT_ORG_SETTINGS,
    ...normalizeStoredOrgSettings(org.settings),
    enforceEncryption: true,
  };
}

export function normalizeStoredOrgSettings(
  rawSettings: Partial<PersistedOrgSettings> | null | undefined
): Partial<PersistedOrgSettings> {
  if (!rawSettings || typeof rawSettings !== 'object') {
    return {};
  }

  const normalized: Partial<PersistedOrgSettings> = {
    // Encryption is always enforced by VaultGuard. Ignore any persisted false value.
    enforceEncryption: true,
  };

  const syncMode = normalizeSyncMode(rawSettings.syncMode, undefined);
  if (syncMode) {
    normalized.syncMode = syncMode;
  }

  const syncIntervalMinutes = parsePositiveInteger(rawSettings.syncIntervalMinutes, undefined);
  if (syncIntervalMinutes !== undefined) {
    normalized.syncIntervalMinutes = syncIntervalMinutes;
  }

  const maxSessionDurationHours = parsePositiveInteger(
    rawSettings.maxSessionDurationHours,
    undefined
  );
  if (maxSessionDurationHours !== undefined) {
    normalized.maxSessionDurationHours = maxSessionDurationHours;
  }

  if (typeof rawSettings.requireMfa === 'boolean') {
    normalized.requireMfa = rawSettings.requireMfa;
  }

  const allowedDomains = normalizeAllowedDomains(rawSettings.allowedDomains, undefined);
  if (allowedDomains !== undefined) {
    normalized.allowedDomains = allowedDomains;
  }

  const retentionDays = parsePositiveInteger(rawSettings.retentionDays, undefined);
  if (retentionDays !== undefined) {
    normalized.retentionDays = retentionDays;
  }

  const autoLockMinutes = parseNonNegativeInteger(rawSettings.autoLockMinutes, undefined);
  if (autoLockMinutes !== undefined) {
    normalized.autoLockMinutes = autoLockMinutes;
  }

  return normalized;
}

export function normalizeSyncMode(
  value: unknown,
  fallback: PersistedOrgSettings['syncMode'] | undefined
): PersistedOrgSettings['syncMode'] | undefined {
  return value === 'realtime' || value === 'periodic' || value === 'manual' ? value : fallback;
}

export function parsePositiveInteger(value: unknown, fallback: number | undefined): number | undefined {
  const parsed =
    typeof value === 'number'
      ? value
      : typeof value === 'string' && value.trim().length > 0
        ? Number.parseInt(value, 10)
        : Number.NaN;

  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

export function parseNonNegativeInteger(
  value: unknown,
  fallback: number | undefined
): number | undefined {
  const parsed =
    typeof value === 'number'
      ? value
      : typeof value === 'string' && value.trim().length > 0
        ? Number.parseInt(value, 10)
        : Number.NaN;

  return Number.isInteger(parsed) && parsed >= 0 ? parsed : fallback;
}

export function normalizeAllowedDomains(
  value: unknown,
  fallback: string[] | undefined
): string[] | undefined {
  const domains =
    Array.isArray(value)
      ? value
      : typeof value === 'string'
        ? value.split(/[\n,]/)
        : null;

  if (!domains) {
    return fallback;
  }

  return [...new Set(
    domains
      .filter((domain): domain is string => typeof domain === 'string')
      .map((domain) => domain.trim().toLowerCase())
      .filter((domain) => domain.length > 0)
  )];
}

export function isEmailAllowedForOrg(email: string, settings: OrgSettings): boolean {
  if (settings.allowedDomains.length === 0) {
    return true;
  }

  const atIndex = email.lastIndexOf('@');
  if (atIndex === -1 || atIndex === email.length - 1) {
    return false;
  }

  const domain = email.slice(atIndex + 1).trim().toLowerCase();
  return settings.allowedDomains.includes(domain);
}

export async function getEffectiveOrgSettings(orgId: string): Promise<OrgSettings | null> {
  const cached = orgSettingsCache.get(orgId);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.settings;
  }

  const orgResult = await getActiveOrg(orgId);
  if (!orgResult.allowed || !orgResult.org) {
    return null;
  }

  const settings = buildOrgSettings(orgId, orgResult.org);
  orgSettingsCache.set(orgId, {
    settings,
    expiresAt: Date.now() + ORG_SETTINGS_CACHE_TTL_MS,
  });
  return settings;
}

export function invalidateOrgSettingsCache(orgId?: string): void {
  if (orgId) {
    orgSettingsCache.delete(orgId);
    return;
  }

  orgSettingsCache.clear();
}

/**
 * Checks if adding another user would exceed the org's user limit.
 */
export function checkUserLimit(org: OrgRecord): OrgEnforcementResult {
  if (org.currentUsers >= org.maxUsers) {
    return {
      allowed: false,
      org,
      reason: `User limit reached (${org.currentUsers}/${org.maxUsers}). Upgrade your plan to add more users.`,
      code: 'USER_LIMIT',
    };
  }
  return { allowed: true, org };
}

/**
 * Checks if uploading a file of the given size would exceed storage quota.
 */
export function checkStorageLimit(org: OrgRecord, additionalBytes: number): OrgEnforcementResult {
  if (org.currentStorageBytes + additionalBytes > org.maxStorageBytes) {
    const usedMB = Math.round(org.currentStorageBytes / 1024 / 1024);
    const maxMB = Math.round(org.maxStorageBytes / 1024 / 1024);
    return {
      allowed: false,
      org,
      reason: `Storage limit reached (${usedMB} MB / ${maxMB} MB). Upgrade your plan for more storage.`,
      code: 'STORAGE_LIMIT',
    };
  }
  return { allowed: true, org };
}

/**
 * Updates the org's currentStorageBytes counter by a delta (positive for upload, negative for delete).
 */
export async function updateOrgStorageUsage(orgSlug: string, deltaBytes: number): Promise<void> {
  try {
    await docClient.send(
      new UpdateCommand({
        TableName: ORGANIZATIONS_TABLE,
        Key: { slug: orgSlug },
        UpdateExpression: 'ADD currentStorageBytes :delta SET updatedAt = :now',
        ExpressionAttributeValues: {
          ':delta': deltaBytes,
          ':now': new Date().toISOString(),
        },
      })
    );
  } catch (err) {
    console.error(JSON.stringify({
      event: 'ORG_STORAGE_UPDATE_FAILURE',
      orgSlug,
      delta: deltaBytes,
      error: (err as Error).message,
    }));
  }
}

/**
 * Increments or decrements the org's currentUsers counter.
 */
export async function updateOrgUserCount(orgSlug: string, delta: number): Promise<void> {
  try {
    await docClient.send(
      new UpdateCommand({
        TableName: ORGANIZATIONS_TABLE,
        Key: { slug: orgSlug },
        UpdateExpression: 'ADD currentUsers :delta SET updatedAt = :now',
        ExpressionAttributeValues: {
          ':delta': delta,
          ':now': new Date().toISOString(),
        },
      })
    );
  } catch (err) {
    console.error(JSON.stringify({
      event: 'ORG_USER_COUNT_UPDATE_FAILURE',
      orgSlug,
      delta,
      error: (err as Error).message,
    }));
  }
}

// Re-export AWS SDK commands for convenience in handlers
// ─── Vault helpers ───────────────────────────────────────────────────────────

/**
 * Fetches a vault by (orgId, vaultId). Enforces tenant isolation: a caller
 * cannot resolve a vault from a different org even if they know the vaultId.
 *
 * Returns null if not found or if the vault belongs to a different org.
 */
export async function getVault(orgId: string, vaultId: string): Promise<VaultRecord | null> {
  if (!orgId || !vaultId) return null;
  const result = await docClient.send(
    new GetCommand({
      TableName: VAULTS_TABLE,
      Key: { orgId, vaultId },
    })
  );
  const item = result.Item as VaultRecord | undefined;
  if (!item || item.orgId !== orgId) return null;
  return item;
}

/**
 * Looks up a vault by (orgId, slug) using the slug-index GSI.
 * Returns null if no vault with that slug exists in the org.
 */
export async function getVaultBySlug(orgId: string, slug: string): Promise<VaultRecord | null> {
  if (!orgId || !slug) return null;
  const result = await docClient.send(
    new QueryCommand({
      TableName: VAULTS_TABLE,
      IndexName: 'slug-index',
      KeyConditionExpression: 'orgId = :orgId AND slug = :slug',
      ExpressionAttributeValues: { ':orgId': orgId, ':slug': slug.toLowerCase() },
      Limit: 1,
    })
  );
  const items = (result.Items ?? []) as VaultRecord[];
  return items[0] ?? null;
}

/**
 * Returns the current user's membership row for a vault, or null if none.
 *
 * Org admins do NOT automatically get vault memberships — instead, callers
 * should layer `isAdmin(user)` checks on top when full-org bypass is needed.
 */
export async function getVaultMembership(
  vaultId: string,
  userId: string
): Promise<VaultMemberRecord | null> {
  if (!vaultId || !userId) return null;
  const result = await docClient.send(
    new GetCommand({
      TableName: VAULT_MEMBERS_TABLE,
      Key: { vaultId, userId },
    })
  );
  return (result.Item as VaultMemberRecord | undefined) ?? null;
}

/**
 * Lists every vault `userId` is a direct member of within `orgId`.
 *
 * Iterates the userId-index then filters by orgId — vaultId encodes orgId
 * lookup via a follow-up GetCommand per item, so this is best for small
 * vault counts per user (< 100). For massive scale, denormalize orgId into
 * the membership row.
 */
export async function listVaultsForUser(
  orgId: string,
  userId: string
): Promise<VaultRecord[]> {
  if (!orgId || !userId) return [];
  const memberships = await docClient.send(
    new QueryCommand({
      TableName: VAULT_MEMBERS_TABLE,
      IndexName: 'userId-index',
      KeyConditionExpression: 'userId = :userId',
      ExpressionAttributeValues: { ':userId': userId },
    })
  );
  const rows = (memberships.Items ?? []) as VaultMemberRecord[];
  if (rows.length === 0) return [];

  const vaults = await Promise.all(
    rows.map((row) => getVault(orgId, row.vaultId))
  );
  return vaults.filter((v): v is VaultRecord => v !== null && !v.archived);
}

/**
 * Lists every vault in an organization. Used by org-admin UIs.
 * Includes archived vaults; callers filter as needed.
 */
export async function listVaultsForOrg(orgId: string): Promise<VaultRecord[]> {
  if (!orgId) return [];
  const result = await docClient.send(
    new QueryCommand({
      TableName: VAULTS_TABLE,
      KeyConditionExpression: 'orgId = :orgId',
      ExpressionAttributeValues: { ':orgId': orgId },
    })
  );
  return (result.Items ?? []) as VaultRecord[];
}

/**
 * Lists every member of a vault.
 */
export async function listVaultMembers(vaultId: string): Promise<VaultMemberRecord[]> {
  if (!vaultId) return [];
  const result = await docClient.send(
    new QueryCommand({
      TableName: VAULT_MEMBERS_TABLE,
      KeyConditionExpression: 'vaultId = :vaultId',
      ExpressionAttributeValues: { ':vaultId': vaultId },
    })
  );
  return (result.Items ?? []) as VaultMemberRecord[];
}

/**
 * Hard authorization gate for vault-scoped operations.
 *
 * Returns the resolved vault record on success. Throws AuthError otherwise.
 *
 * Authorization rules:
 *   1. Vault must exist and belong to the user's org (tenant isolation).
 *   2. The user must have an explicit VaultMember row, OR
 *      be an org-level admin/owner (full-org bypass).
 *   3. If `requiredRole` is provided, the membership role must meet/exceed it.
 *      Org admins bypass the role check.
 *
 * This function is the canonical permission check for /vaults/{vaultId}/* routes.
 */
export async function requireVaultMember(
  user: UserContext,
  vaultId: string,
  requiredRole: VaultMemberRole = 'viewer'
): Promise<VaultRecord> {
  const orgId = requireOrgId(user);
  const vault = await getVault(orgId, vaultId);
  if (!vault) {
    throw new AuthError(`Vault not found or access denied: ${vaultId}`);
  }
  if (vault.archived && requiredRole !== 'viewer') {
    throw new AuthError(`Vault is archived and read-only: ${vaultId}`);
  }

  const orgAdmin = isAdmin(user);
  if (orgAdmin) {
    return vault;
  }

  const membership = await getVaultMembership(vaultId, user.userId);
  if (!membership) {
    throw new AuthError(`You are not a member of this vault: ${vaultId}`);
  }

  if (!vaultRoleMeetsRequirement(membership.role, requiredRole)) {
    throw new AuthError(
      `Requires "${requiredRole}" in this vault; you are "${membership.role}".`
    );
  }

  return vault;
}

// ─── Vault Activity Log ──────────────────────────────────────────────────────
//
// Tier-2 sync optimization. Every file mutation appends a row here; sync calls
// query "everything in this vault since timestamp X" so the server can skip
// the full S3 listing scan when the client is up to date. The vault record's
// `revision` counter is bumped in the same call so cheap cursor checks can
// short-circuit before any of this is queried.

/**
 * A single mutation event on a vault, appended on every file write/delete
 * AND on every permission rule change. The permission_changed action is a
 * synthetic signal: it carries the rule's `pathPattern` (not a concrete
 * file path) and the warm-path sync uses its presence to force a full
 * S3 + permission-evaluation sweep, since one rule change can flip the
 * accessibility of every file in the vault simultaneously.
 */
export type VaultActivityAction = 'created' | 'modified' | 'deleted' | 'permission_changed';

export interface VaultActivityRecord {
  /** Hash key — vault that owns this event. */
  vaultId: string;
  /** Range key — `{15-digit-zero-padded epoch ms}#{8-char id}` for stable, unique ordering. */
  sk: string;
  /** ISO timestamp of when the event was recorded. */
  changedAt: string;
  /** Numeric epoch (ms) of when the event was recorded. */
  changedAtMs: number;
  /** Logical action this event represents. */
  action: VaultActivityAction;
  /** Vault-relative path with leading slash, OR a glob pathPattern for permission events. */
  path: string;
  /** User ID of whoever caused the change. */
  actorUserId: string;
  /** DynamoDB TTL — auto-purges the row after VAULT_ACTIVITY_TTL_DAYS. */
  ttl: number;
}

/** Snapshot of "what the vault looks like right now" for cheap polling. */
export interface VaultCursor {
  revision: number;
  lastChangedAt: string;
}

/**
 * Pads an epoch-ms number to 15 digits so string-compared sort keys order
 * the same way as numeric comparison. Year 33658 fits in 15 digits.
 */
function padEpochMs(ms: number): string {
  return ms.toString().padStart(15, '0');
}

/** Builds a sort key that is unique per event and orders by time. */
function buildActivitySortKey(epochMs: number): string {
  return `${padEpochMs(epochMs)}#${generateId().slice(0, 8)}`;
}

/**
 * Appends an activity-log row and bumps the vault's revision counter +
 * lastChangedAt timestamp. Writes are NOT transactional, so the order
 * matters for crash safety:
 *
 *   1. Append log row first.
 *   2. Then bump revision (the public "something changed" signal).
 *
 * Why this order: if the log write fails, no revision bump happens, and
 * clients don't see a phantom revision they can't reconcile. If the log
 * write succeeds but the revision bump fails, the log row is harmless —
 * clients just won't see it via the warm path until the cold-path full
 * scan reaches it. The reverse order (bump-first) would let clients
 * silently mark themselves up-to-date after a missing-log query and
 * permanently lose the delta.
 *
 * Both writes are best-effort: failures log but never throw, because the
 * user's actual file mutation must not be blocked by sync bookkeeping.
 *
 * Returns the new revision number on full success, otherwise null.
 */
export async function recordVaultActivity(params: {
  orgId: string;
  vaultId: string;
  action: VaultActivityAction;
  path: string;
  actorUserId: string;
}): Promise<number | null> {
  const now = new Date();
  const epochMs = now.getTime();
  const changedAt = now.toISOString();
  const ttl = Math.floor(epochMs / 1000) + VAULT_ACTIVITY_TTL_DAYS * 24 * 60 * 60;

  let logWritten = false;
  try {
    await docClient.send(
      new PutCommand({
        TableName: VAULT_ACTIVITY_TABLE,
        Item: {
          vaultId: params.vaultId,
          sk: buildActivitySortKey(epochMs),
          changedAt,
          changedAtMs: epochMs,
          action: params.action,
          path: params.path,
          actorUserId: params.actorUserId,
          ttl,
        },
      })
    );
    logWritten = true;
  } catch (err) {
    console.error('[VAULT_ACTIVITY_LOG_FAILURE]', err, {
      vaultId: params.vaultId,
      action: params.action,
      path: params.path,
    });
  }

  // If the log write failed, skip the revision bump — we don't want to
  // signal "something changed" to clients without a queryable record of
  // what changed. They'll pick the file up via the cold-path full scan.
  if (!logWritten) return null;

  try {
    const result = await docClient.send(
      new UpdateCommand({
        TableName: VAULTS_TABLE,
        Key: { orgId: params.orgId, vaultId: params.vaultId },
        UpdateExpression: 'ADD #rev :one SET lastChangedAt = :ts',
        ExpressionAttributeNames: { '#rev': 'revision' },
        ExpressionAttributeValues: { ':one': 1, ':ts': changedAt },
        ReturnValues: 'UPDATED_NEW',
      })
    );
    const updatedRevision = (result.Attributes as { revision?: number } | undefined)?.revision;
    return typeof updatedRevision === 'number' ? updatedRevision : null;
  } catch (err) {
    console.error('[VAULT_ACTIVITY_BUMP_FAILURE]', err, {
      vaultId: params.vaultId,
      action: params.action,
      path: params.path,
    });
    return null;
  }
}

/**
 * Reads the current cursor (revision + lastChangedAt) for a vault. Returns
 * a zeroed cursor for vaults that haven't recorded any activity yet — which
 * is correct: any non-zero client cursor is by definition newer than 0,
 * and any client with cursor 0 will fall through to a full sync.
 */
export async function getVaultCursor(orgId: string, vaultId: string): Promise<VaultCursor> {
  const vault = await getVault(orgId, vaultId);
  return {
    revision: typeof vault?.revision === 'number' ? vault.revision : 0,
    lastChangedAt: vault?.lastChangedAt ?? '1970-01-01T00:00:00.000Z',
  };
}

/**
 * Returns activity-log entries for `vaultId` whose `changedAtMs` is strictly
 * greater than `sinceMs`. Pages through the result set until exhausted or
 * `limit` is reached. The caller is expected to dedupe entries by path
 * (last action wins) before applying.
 */
export async function queryVaultActivity(
  vaultId: string,
  sinceMs: number,
  limit: number = 1000
): Promise<VaultActivityRecord[]> {
  const items: VaultActivityRecord[] = [];
  // `~` (0x7e) sorts after every alphanumeric, so the suffix marker is the
  // strict upper bound on any sort key whose epoch matches `sinceMs`. This
  // gives us "epoch strictly greater than sinceMs" semantics from a single
  // KeyConditionExpression.
  const sinceMarker = `${padEpochMs(sinceMs)}#~~~~~~~~`;
  let exclusiveStartKey: Record<string, unknown> | undefined;

  do {
    const result = await docClient.send(
      new QueryCommand({
        TableName: VAULT_ACTIVITY_TABLE,
        KeyConditionExpression: 'vaultId = :vid AND sk > :since',
        ExpressionAttributeValues: { ':vid': vaultId, ':since': sinceMarker },
        ExclusiveStartKey: exclusiveStartKey,
        Limit: Math.min(1000, limit - items.length),
      })
    );

    items.push(...((result.Items ?? []) as VaultActivityRecord[]));
    exclusiveStartKey = result.LastEvaluatedKey;
  } while (exclusiveStartKey && items.length < limit);

  return items;
}

/** Strict ordering of vault roles. Higher index = more permissive. */
const VAULT_ROLE_ORDER: VaultMemberRole[] = ['viewer', 'editor', 'admin'];

export function vaultRoleMeetsRequirement(
  actual: VaultMemberRole,
  required: VaultMemberRole
): boolean {
  return VAULT_ROLE_ORDER.indexOf(actual) >= VAULT_ROLE_ORDER.indexOf(required);
}

/**
 * Default actions granted by each vault role when no explicit rule covers
 * the requested path. Mirrors `actionsForVaultRole` in the vaults handler;
 * kept here so the permission evaluator stays self-contained.
 */
const VAULT_ROLE_DEFAULT_ACTIONS: Record<VaultMemberRole, PermissionAction[]> = {
  admin: ['read', 'write', 'delete', 'admin', 'list'],
  editor: ['read', 'write', 'delete', 'list'],
  viewer: ['read', 'list'],
};

export function vaultRoleAllowsAction(
  role: VaultMemberRole,
  action: PermissionAction
): boolean {
  return VAULT_ROLE_DEFAULT_ACTIONS[role].includes(action);
}

/**
 * Generates a URL-safe slug from a display name. Matches the rules used
 * by the org slug helper: lowercase, alphanumerics + hyphens only,
 * collapsed dashes, max 60 chars.
 */
export function slugifyVaultName(name: string): string {
  return name
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 60);
}

export {
  GetCommand,
  PutCommand,
  QueryCommand,
  DeleteCommand,
  UpdateCommand,
  ScanCommand,
  BatchWriteCommand,
};

export {
  AUDIT_TABLE,
  PERMISSIONS_TABLE,
  SESSIONS_TABLE,
  LEASES_TABLE,
  USER_KEYS_TABLE,
  REVOKED_KEYS_TABLE,
  RECOVERY_CODES_TABLE,
  RECOVERY_ATTEMPTS_TABLE,
  ORGANIZATIONS_TABLE,
  VAULTS_TABLE,
  VAULT_MEMBERS_TABLE,
  VAULT_ACTIVITY_TABLE,
  SUBSCRIPTIONS_TABLE,
  REGION,
};
