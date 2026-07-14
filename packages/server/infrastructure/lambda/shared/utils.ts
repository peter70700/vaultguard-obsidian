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
import type { QueryCommandInput } from '@aws-sdk/lib-dynamodb';
import { AdminGetUserCommand, CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { CognitoJwtVerifier } from 'aws-jwt-verify';
import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { createHash, randomBytes, randomUUID } from 'crypto';
import { EDITION } from './edition';
import { emitSecurityMetric } from './metrics';
import { isOffHours } from './time';

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
// SD-02-F3: 15s (was 60s) bounds the window in which a just-enabled `requireMfa`
// can still be served stale (false) by other warm Lambda containers —
// invalidateOrgSettingsCache only clears the container that wrote the change, so
// the cache is per-instance. A short TTL is a proportionate mitigation for this
// self-healing gap; a per-request uncached read was rejected as disproportionate.
const ORG_SETTINGS_CACHE_TTL_MS = 15_000;
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
  /**
   * Cognito group memberships from the verified `cognito:groups` claim ONLY.
   * Unlike `roles`, this is never polluted by the user-mutable custom:role /
   * custom:orgRole attributes — safe for privileged (super-admin) gating.
   */
  groups: string[];
  sessionId: string;
  /** Organization ID from custom:org token claim. */
  orgId: string;
  /** Whether the current authentication event satisfied an MFA challenge. */
  mfaAuthenticated: boolean;
  /**
   * Whether the verified token carries `email_verified === true`. Access
   * tokens lack the claim (and the email), so this is `false` for them.
   */
  emailVerified: boolean;
  /** Unix timestamp of the upstream Cognito authentication event, if present. */
  authTime: number | null;
  /**
   * Unix timestamp (epoch seconds) at which THIS token was issued (the `iat`
   * claim). Used as the fallback for the per-user logout cutoff (SD-02-F1)
   * when `auth_time` is absent — e.g. tokens minted via refresh, or access
   * tokens that omit `auth_time`.
   */
  iat: number | null;
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

export interface PermissionEvaluationOptions {
  /**
   * Legacy principal aliases for the same user, such as older rules that
   * stored an email address before the API canonicalized users to Cognito sub.
   */
  userAliases?: string[];
  /**
   * Rule IDs to ignore during this evaluation. Lets callers ask hypothetical
   * "what would the user's level be if rule X did not exist?" questions —
   * used by the set-level endpoint to compute the user's inherited level
   * (membership + broader rules) when deciding whether an exact rule is
   * needed to land them at the requested target.
   */
  excludeRuleIds?: string[];
  /**
   * When true (default), an org/vault admin/owner short-circuits to
   * allowed=true regardless of any deny rule on the path. When false, the
   * bypass is skipped and the standard rule evaluation pipeline runs even
   * for admins — used by callers that need per-file deny rules to bind
   * admins (the `allowAdminPerFileRestrictions` org setting). Caller-side
   * authorization checks (e.g. authorizePermissionMutation's admin probe)
   * should always leave this true; only target-side level computation and
   * file-operation auth should opt out.
   */
  respectAdminBypass?: boolean;
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
        groups: extractGroupsFromTokenPayload(payload as Record<string, unknown>),
        sessionId: (payload as Record<string, unknown>).jti as string || '',
        orgId: (payload as Record<string, unknown>)['custom:org'] as string || '',
        mfaAuthenticated: extractMfaAuthenticatedFromTokenPayload(payload as Record<string, unknown>),
        emailVerified: (payload as Record<string, unknown>).email_verified === true,
        authTime:
          typeof (payload as Record<string, unknown>).auth_time === 'number'
            ? ((payload as Record<string, unknown>).auth_time as number)
            : null,
        iat:
          typeof (payload as Record<string, unknown>).iat === 'number'
            ? ((payload as Record<string, unknown>).iat as number)
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
  await assertTokenNewerThanLogoutCutoff(user);
  await assertSessionActiveIfPresent(event, user);
  await assertOrgMfaSatisfied(user);
  if (!options.allowPendingCheckout) {
    await assertSubscriptionAllowsAccess(user);
  }
  return user;
}

/**
 * LA2: enforce the org's requireMfa policy on EVERY authenticated route, not
 * just the auth-handler login/lease paths. Previously a non-MFA token — from a
 * direct Cognito InitiateAuth (pool MFA is "optional", separate from this org
 * flag) or minted before MFA was enabled — could still hit file/permission/
 * share mutations, silently violating the compliance control the org advertised.
 * Org settings are cached (getEffectiveOrgSettings) so this adds no per-request
 * DB read in steady state. requireMfa defaults false, so orgs that never enable
 * it are unaffected; when it IS on, login already requires MFA, so this only
 * closes the stale-token / side-channel gap.
 */
async function assertOrgMfaSatisfied(user: UserContext): Promise<void> {
  const settings = await getEffectiveOrgSettings(user.orgId);
  if (settings?.requireMfa && !user.mfaAuthenticated) {
    throw new AuthError(
      'Multi-factor authentication is required by your organization. Sign in again with MFA.',
      403,
      'mfa_required'
    );
  }
}

const ALLOWED_SUBSCRIPTION_STATUSES = new Set(['trialing', 'active', 'past_due']);

/**
 * Parse a comma-separated list of billing-exempt email domains into a
 * normalized Set (lower-cased, trimmed, empties dropped). Fed from the
 * `BILLING_EXEMPT_DOMAINS` env var on the signup Lambda.
 */
export function parseExemptDomains(csv: string | undefined): Set<string> {
  return new Set(
    (csv || '')
      .split(',')
      .map((d) => d.trim().toLowerCase())
      .filter(Boolean)
  );
}

/**
 * True when the email's domain is exactly one of the exempt domains
 * (case-insensitive, matched on the part after the last `@`). Sub-domains do
 * NOT match (`sedmak.sk` matches `a@sedmak.sk` but not `a@x.sedmak.sk`). Used
 * at signup to stamp internal/company orgs as `comped` so they are never billed.
 */
export function isBillingExemptEmail(email: string, exemptDomains: Set<string>): boolean {
  if (!email || exemptDomains.size === 0) return false;
  const at = email.lastIndexOf('@');
  if (at < 0) return false;
  const domain = email.slice(at + 1).trim().toLowerCase();
  return domain.length > 0 && exemptDomains.has(domain);
}

// ─── Platform Super-Admin ────────────────────────────────────────────────────

/**
 * Cognito group that marks platform operators. Membership is assigned
 * manually (console/CLI) — no API code path may ever add a user to it.
 */
export const SUPER_ADMIN_GROUP = 'platform-superadmin';

/**
 * Group names that request-derived role/group values must NEVER create or
 * assign. Guarded (case-insensitively) at every AdminAddUserToGroup /
 * CreateGroup call site in the users and signup handlers.
 */
export const RESERVED_GROUP_NAMES = [SUPER_ADMIN_GROUP] as const;

/** True when a (request-derived) group name collides with a reserved group. */
export function isReservedGroupName(name: string | undefined | null): boolean {
  if (!name) return false;
  const normalized = name.trim().toLowerCase();
  return RESERVED_GROUP_NAMES.some((g) => g.toLowerCase() === normalized);
}

/**
 * Parse the `SUPER_ADMIN_EMAILS` env var (comma-separated, lower-cased,
 * trimmed, empties dropped). Mirrors `parseExemptDomains`.
 */
export function parseSuperAdminEmails(csv: string | undefined): Set<string> {
  return new Set(
    (csv || '')
      .split(',')
      .map((e) => e.trim().toLowerCase())
      .filter(Boolean)
  );
}

/**
 * Pure identity gate for the super-admin surface. Fail closed:
 * - caller must be in the `platform-superadmin` Cognito group (verified claim),
 * - the allowlist must be non-empty AND contain the caller's verified email.
 *
 * MFA is enforced separately (see `assertSuperAdminMfaEnrolled`) because it
 * needs an async account lookup. The thrown `AuthError(403)` carries a generic
 * message that never reveals which condition failed to the client; the specific
 * reason is logged server-side for operators.
 */
export function assertSuperAdminIdentity(user: UserContext, allowlist: Set<string>): void {
  const deny = (reason: string): never => {
    console.warn('[SUPERADMIN_DENY]', reason, {
      groups: user.groups,
      emailVerified: user.emailVerified,
    });
    throw new AuthError('Super-admin access denied', 403);
  };
  if (!user.groups.includes(SUPER_ADMIN_GROUP)) deny('not_in_group');
  const email = (user.email || '').trim().toLowerCase();
  if (!email || allowlist.size === 0 || !allowlist.has(email)) deny('email_not_allowlisted');
  if (user.emailVerified !== true) deny('email_unverified');
}

let superAdminCognitoClient: CognitoIdentityProviderClient | null = null;
function getSuperAdminCognitoClient(): CognitoIdentityProviderClient {
  if (!superAdminCognitoClient) {
    superAdminCognitoClient = new CognitoIdentityProviderClient({});
  }
  return superAdminCognitoClient;
}

/**
 * MFA enforcement for the super-admin surface.
 *
 * Cognito ID tokens do NOT reliably carry an MFA marker in `amr`, and tokens
 * minted via refresh drop `amr` entirely — so a token-only check (the previous
 * `user.mfaAuthenticated` gate) denies genuinely-MFA'd operators. We accept a
 * token that already asserts MFA as a fast path, and otherwise confirm the
 * account has an MFA method enrolled via AdminGetUser. Enrolled MFA is always
 * challenged at login, so account-level enrollment reliably enforces the same
 * intent without depending on fragile token claims.
 */
async function assertSuperAdminMfaEnrolled(user: UserContext): Promise<void> {
  const denied = new AuthError('Super-admin access denied', 403);
  if (user.mfaAuthenticated) return;
  const poolId = process.env.COGNITO_USER_POOL_ID || process.env.USER_POOL_ID;
  const username = (user.email || '').trim();
  if (!poolId || !username) {
    console.warn('[SUPERADMIN_DENY]', 'mfa_check_misconfigured');
    throw denied;
  }
  try {
    const res = await getSuperAdminCognitoClient().send(
      new AdminGetUserCommand({ UserPoolId: poolId, Username: username })
    );
    if ((res.UserMFASettingList ?? []).length === 0) {
      console.warn('[SUPERADMIN_DENY]', 'mfa_not_enrolled');
      throw denied;
    }
  } catch (err) {
    if (err instanceof AuthError) throw err;
    console.warn('[SUPERADMIN_DENY]', 'mfa_lookup_failed', (err as Error)?.message);
    throw denied;
  }
}

/**
 * Verifies the caller for the platform super-admin surface.
 *
 * Deliberately does NOT call `requireOrgId` (super-admins operate cross-org)
 * and does NOT run the subscription gate. Revocation and server-session state
 * are still enforced.
 */
export async function requireSuperAdmin(event: APIGatewayProxyEvent): Promise<UserContext> {
  const user = await verifyToken(event);
  assertSuperAdminIdentity(user, parseSuperAdminEmails(process.env.SUPER_ADMIN_EMAILS));
  await assertSuperAdminMfaEnrolled(user);
  await assertUserNotRevoked(user);
  await assertSessionActiveIfPresent(event, user);
  return user;
}

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
  // Comped orgs — internal/company accounts stamped by an exempt email domain
  // at signup (or backfilled) — are permanently exempt from the paywall,
  // regardless of Stripe state. Pure DB flag; no Stripe object required.
  if (result.Item?.comped === true) return;

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

/**
 * SD-02-F1 — per-user logout cutoff (header-independent session invalidation).
 *
 * `assertSessionActiveIfPresent` only fires when the caller sends the
 * `X-VaultGuard-Session-Id` header, so a stolen Cognito token replayed WITHOUT
 * that header keeps working for the residual token lifetime after the victim
 * logs out. This check closes that bypass for ALL clients: on logout the auth
 * handler records `logoutAt = now` under the synthetic SESSIONS_TABLE key
 * `logout-cutoff#<userId>`; here we reject any token whose issuance time
 * (`iat`, falling back to `auth_time`) predates that moment.
 *
 * Deliberately isolated from admin-revoke (`assertUserNotRevoked`): it reads a
 * SESSIONS_TABLE marker, never REVOKED_KEYS_TABLE, and trips no blanket 403 —
 * so a fresh token minted AFTER `logoutAt` passes and re-login works
 * immediately. When there is no cutoff item (the common case), behaviour is
 * unchanged (allow).
 */
async function assertTokenNewerThanLogoutCutoff(user: UserContext): Promise<void> {
  const result = await docClient.send(
    new GetCommand({
      TableName: SESSIONS_TABLE,
      Key: { sessionId: `logout-cutoff#${user.userId}` },
    })
  );

  const logoutAt = result.Item?.logoutAt;
  if (typeof logoutAt !== 'number') return; // no cutoff recorded → unchanged behaviour

  // `auth_time` / `iat` are epoch SECONDS; `logoutAt` is epoch MS — compare in ms.
  // Prefer `iat` (when THIS token was minted) over `auth_time`: Cognito
  // preserves the ORIGINAL login's `auth_time` across refresh-minted tokens,
  // so judging on `auth_time` locked out every OTHER refresh-restored session
  // of a user for up to 24h after they logged out anywhere (prod incident
  // 2026-07-11). `iat` still blocks the actual threat — replay of an access
  // token stolen BEFORE the logout — while letting live sessions recover by
  // refreshing. A token with neither claim is left untouched (fail-open,
  // unchanged behaviour); Cognito tokens always carry `iat`.
  const tokenIssuedSec = user.iat ?? user.authTime;
  if (typeof tokenIssuedSec !== 'number') return;

  if (tokenIssuedSec * 1000 < logoutAt) {
    throw new AuthError('Session ended. Please sign in again.', 401);
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

/**
 * Extracts the verified `cognito:groups` claim as-is. Unlike
 * `extractRolesFromTokenPayload` this deliberately ignores the user-mutable
 * custom:role / custom:orgRole attributes and does not lower-case, so exact
 * group membership (e.g. `platform-superadmin`) can be checked safely.
 */
function extractGroupsFromTokenPayload(payload: Record<string, unknown>): string[] {
  return Array.isArray(payload['cognito:groups'])
    ? (payload['cognito:groups'] as unknown[])
        .filter((value): value is string => typeof value === 'string')
        .map((value) => value.trim())
        .filter(Boolean)
    : [];
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
  vaultId: string,
  options: PermissionEvaluationOptions = {}
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
  //
  // `respectAdminBypass: false` opts out for callers that need per-file
  // deny rules to bind admins (the `allowAdminPerFileRestrictions` org
  // setting). The opt-out is narrow: admins still get implicit access when
  // no rule applies; they only lose access when an EXPLICIT deny rule on
  // the path strips it (handled at the rule-matching stage further down).
  // Without this narrowing, enabling the toggle would silently revoke
  // admins' access to every file they don't have an explicit rule for —
  // exactly the regression Pete reported on 2026-05-31 (org-admin login
  // on mobile showed an empty file browser because every file with no
  // pete-specific rule fell through to "no rule + not a vault member →
  // denied"). Caller-side auth checks (authorize a mutation, decide if
  // the caller can resolve the vault) should still leave respectAdminBypass
  // at default true so admins keep the "manage everything" rights the rest
  // of the system assumes.
  const respectAdminBypass = options.respectAdminBypass !== false;
  const callerIsOrgAdmin = rolesIncludeOrgAdmin(roles);
  if (respectAdminBypass && callerIsOrgAdmin) {
    return { allowed: true, matchedRule: null, evaluatedRules: [] };
  }

  // Fetch all potentially applicable rules, scoped to the caller's org + vault.
  const rules = await fetchApplicableRules(
    principalLookupValues(userId, options.userAliases),
    roles,
    orgId,
    vaultId
  );

  // Drop expired time-bound rules.
  const now = new Date().toISOString();
  // Hypothetical-removal seam: `excludeRuleIds` lets the set-level endpoint
  // ask "what would this user's level be if rule X did not exist?" so it can
  // decide between (a) deleting the exact rule because inheritance already
  // matches the target and (b) writing the right cap/grant rule. Production
  // callers omit the option and get exact evaluation.
  const excludeRuleIds = new Set(options.excludeRuleIds ?? []);
  const liveRules = rules.filter(
    (rule) => (!rule.expiresAt || rule.expiresAt > now) && !excludeRuleIds.has(rule.id)
  );

  // Filter to rules that match the requested path
  const matchingRules = liveRules.filter((rule) => {
    return pathMatchesPattern(path, rule.pathPattern) && rule.actions.includes(action);
  });

  if (matchingRules.length === 0) {
    // Org-admin baseline (allowAdminPerFileRestrictions narrowing). When the
    // bypass was skipped above because the caller opted into the toggle,
    // admins still need implicit access on files that no rule mentions —
    // the toggle's intent is "deny rules bind admins", not "admins lose
    // access by default". Without this branch, an org admin who isn't a
    // vault member on this vault would 403 on every file they don't have
    // an explicit rule for. See the comment above the bypass block for the
    // 2026-05-31 incident this fix unblocks.
    if (callerIsOrgAdmin) {
      return { allowed: true, matchedRule: null, evaluatedRules: liveRules };
    }
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

// ─── File-admin delegated permission authorization ───────────────────────────

/** Ordered access level derived from a rule's actions+effect. Higher = more power. */
export function ruleLevelRank(actions: PermissionAction[], effect: 'allow' | 'deny'): number {
  if (effect === 'deny') return 0;          // a deny rule grants nothing
  if (!actions.includes('read')) return 0;  // no read => effectively none
  if (actions.includes('admin')) return 3;  // admin
  if (actions.includes('write') || actions.includes('delete')) return 2; // write
  return 1;                                 // read
}

/** Desired rule shape for an authorization decision (the principal + grant). */
export interface PermissionMutationTarget {
  userId: string;          // canonical sub or '*'
  role: string | null;
  actions: PermissionAction[];
  effect: 'allow' | 'deny';
}

export interface AuthorizePermissionMutationResult { viaFileAdmin: boolean; }

/**
 * Dependency seam for {@link authorizePermissionMutation}. Production callers
 * omit this and get the real module functions. The seam exists ONLY so the unit
 * suite can drive `evaluatePermission` per-action (the path-scope admin check
 * and the admin→write→read cap probe call it with different `action` args, and
 * intra-module calls are otherwise not interceptable by vi.spyOn under ESM).
 * It does NOT alter production behavior — the defaults are the real functions.
 */
export interface AuthorizePermissionMutationDeps {
  evaluatePermission: typeof evaluatePermission;
  requireVaultMember: typeof requireVaultMember;
  getVaultMembership?: typeof getVaultMembership;
}

/**
 * Authorizes a permission create/update/delete. Vault/org admins keep full
 * power. A non-vault-admin is authorized IFF they hold file-level `admin` on
 * `pathPattern`, capped at their own DERIVED level, and may never drop their own admin.
 */
export async function authorizePermissionMutation(
  user: UserContext,
  vault: VaultRecord,
  pathPattern: string,
  targetLevel: PermissionMutationTarget,
  existingRule?: PermissionRule,
  deps: AuthorizePermissionMutationDeps = { evaluatePermission, requireVaultMember, getVaultMembership }
): Promise<AuthorizePermissionMutationResult> {
  // 1. Vault/org admin bypass — unchanged behavior.
  try {
    await deps.requireVaultMember(user, vault.vaultId, 'admin');
    return { viaFileAdmin: false };
  } catch {
    // fall through to file-admin path; the caller is at least a vault member
    // (route-level requireVaultMember(viewer) already ran in the dispatcher).
  }

  const aliases = user.email ? [user.email] : [];
  const membership = await deps.getVaultMembership?.(vault.vaultId, user.userId);
  const evaluationRoles = membership ? [membership.role] : user.roles;
  const heldRoles = new Set([...user.roles, ...evaluationRoles].map((role) => role.toLowerCase()));

  // 2. Path-scope guardrail. Authorization REQUIRES admin on the path — do NOT
  //    loosen this to let write-holders manage rules (scope-locked).
  const adminCheck = await deps.evaluatePermission(
    user.userId, evaluationRoles, 'admin', pathPattern, vault.orgId, vault.vaultId,
    { userAliases: aliases }
  );
  if (!adminCheck.allowed) {
    throw new AuthError(`You do not have admin on ${pathPattern}`, 403);
  }

  // 3. Cap at own level. Derive the caller's TRUE evaluated rank on the path via
  //    the admin→write→read probe (the same ordering resolvePathAccessLevel uses
  //    in permissions/handler.ts). This MUST be derived, never hardcoded: the cap
  //    has to survive the deferred folder-admin work, where a caller could hold a
  //    level below admin on the exact rule path while admin is required elsewhere.
  const callerRank = await deriveCallerRank(
    user.userId, evaluationRoles, pathPattern, vault.orgId, vault.vaultId, aliases,
    deps.evaluatePermission
  );
  if (ruleLevelRank(targetLevel.actions, targetLevel.effect) > callerRank) {
    throw new AuthError('Cannot grant a level above your own', 403);
  }

  // 4. Self-protection — reject any mutation that drops the caller's own admin.
  //    Self-targeting is detected via three vectors: exact userId, the '*'
  //    wildcard, or a role the caller holds.
  //
  //    ROLE-NAMESPACE NOTE: `targetLevel.role` is a permission-rule role field
  //    (which stores vault membership roles such as 'viewer'/'editor'/'admin'),
  //    whereas `user.roles` is the lowercased set of Cognito group names plus
  //    custom org-role claims (see extractRolesFromTokenPayload). The two
  //    namespaces OVERLAP (e.g. 'editor', 'admin') but are NOT guaranteed
  //    identical — a Cognito group could carry an org-level role with no vault
  //    equivalent. The role self-protection vector below is therefore best-effort
  //    until the two namespaces are formally reconciled; the '*' vector is exact
  //    and carries real protection weight.
  //
  //    USER-ID VECTOR (alias-aware, CR-01): a self-targeting rule can carry ANY
  //    form of the caller's principal — their Cognito sub OR their email alias.
  //    An email-aliased self-admin rule (targetLevel.userId='pete@x.com', caller
  //    sub='pete-sub') must still trigger self-protection. We expand the caller's
  //    principal to its full alias set via principalLookupValues (the SAME helper
  //    evaluatePermission and findApplicableDenyRulesInScope use) and compare
  //    case-insensitively (the helper de-dupes case-insensitively but returns
  //    original case, so we lowercase both sides here).
  const callerAliases = principalLookupValues(user.userId, user.email ? [user.email] : [])
    .map((v) => v.toLowerCase());
  // WR-02: user.roles is already lowercased+trimmed (extractRolesFromTokenPayload),
  // so lowercase ONLY the rule-side role here — a stored mixed-case role ('Editor')
  // must still match the caller's lowercased held role ('editor').
  //
  // WR-04: DynamoDB drops null/undefined attributes when an item is written
  // with `delete item.role` (the create handler strips `role: null` before
  // PutItem so the role-index GSI doesn't reject the row). When the rule is
  // read back, `role` is undefined, not null. The original `!== null` guards
  // missed this case — `undefined !== null` is true, so the code fell
  // through to `undefined.toLowerCase()` and threw 500. Same fix as the
  // existingTargetsSelf branch below (line ~760). And `userId` may be
  // undefined for legacy role-only rules that pre-date the canonicalization
  // pass — guard the same way rather than blowing up.
  const targetUserId = targetLevel.userId;
  const targetRole = targetLevel.role;
  const targetsSelf =
    (typeof targetUserId === 'string' &&
      callerAliases.includes(targetUserId.trim().toLowerCase())) ||
    targetUserId === '*' ||
    (typeof targetRole === 'string' && heldRoles.has(targetRole.toLowerCase()));
  if (targetsSelf) {
    // Demotion-to-none of a rule that currently grants the caller admin. Delete is
    // modeled by the handler passing effect:'deny' (the deny sentinel — see the
    // delete handler), so both an explicit deny and a delete surface here as
    // effect === 'deny'. There is no separate "actions === undefined" delete
    // branch: delete always passes the existing actions verbatim alongside the
    // deny sentinel.
    const droppedAdmin =
      (existingRule && existingRule.actions.includes('admin') && existingRule.effect === 'allow' &&
        (targetLevel.effect === 'deny' ||
         !targetLevel.actions.includes('admin'))) ||
      (!existingRule && targetLevel.effect === 'deny');
    if (droppedAdmin) {
      throw new AuthError('Cannot remove your own admin on this path', 403);
    }
  }

  // 5. REASSIGNMENT VECTOR (FADM-04). The block above only consults the
  //    POST-update principal (targetLevel.userId). A file-admin can hold a rule
  //    that CURRENTLY grants THEM admin and change ONLY userId to point at
  //    another principal (e.g. 'bob') — leaving targetsSelf (post-update) false,
  //    so the droppedAdmin guard never runs and their own admin is silently
  //    reassigned away (self-lockout). The EXISTING rule's principal is the
  //    source of truth for self-protection: if existingRule's principal IS the
  //    caller (sub/email alias, '*', or a held role) and granted them admin, the
  //    mutation must still preserve the caller's admin on this path — otherwise
  //    reject with the SAME canonical 403. Reuses callerAliases (computed once
  //    above) and the SAME three self-targeting vectors against existingRule.
  // WR-03: existingRule is an unvalidated DynamoDB cast — a legacy/role-only rule
  // may have no userId, so guard userId against null/undefined before .trim() the
  // SAME way the role term below is already guarded (a missing userId must not 500).
  // WR-02: lowercase the rule-side role (user.roles is already lowercased) so a
  // mixed-case stored role still matches the held role.
  const existingTargetsSelf = existingRule
    ? (
        (existingRule.userId !== null && existingRule.userId !== undefined &&
          callerAliases.includes(existingRule.userId.trim().toLowerCase())) ||
        existingRule.userId === '*' ||
        (existingRule.role !== null && existingRule.role !== undefined &&
          heldRoles.has(existingRule.role.toLowerCase()))
      )
    : false;
  const existingGrantedCallerAdmin =
    !!existingRule && existingRule.effect === 'allow' && existingRule.actions.includes('admin');
  // The post-update target preserves the caller's admin ONLY when the rule STAYS
  // on the same path P AND still targets the caller AND remains an allow that
  // includes admin. A path move (pathPattern changes — WR-01), a userId-only
  // reassignment (target points elsewhere), or an admin downgrade fails this. The
  // grant only "preserves" the caller's admin on P if the rule stays on P, so a
  // pathPattern-only move off P no longer reads as preserved and the step-5 guard
  // fires. (The flag is true when there is no existing rule, so creates are
  // unaffected.)
  const pathUnchanged = existingRule ? existingRule.pathPattern === pathPattern : true;
  const targetPreservesCallerAdmin =
    pathUnchanged && targetsSelf && targetLevel.effect === 'allow' && targetLevel.actions.includes('admin');
  if (existingTargetsSelf && existingGrantedCallerAdmin && !targetPreservesCallerAdmin) {
    throw new AuthError('Cannot remove your own admin on this path', 403);
  }

  return { viaFileAdmin: true };
}

/**
 * The caller's true evaluated access level on `path`, as an ordered rank that
 * lines up with ruleLevelRank (3 admin, 2 write, 1 read, 0 none). Reuses the
 * admin→write→read probe ordering from permissions/handler.ts:resolvePathAccessLevel.
 * Never a constant — this is what makes cap-at-own-level a real guardrail.
 */
async function deriveCallerRank(
  userId: string, roles: string[], path: string,
  orgId: string, vaultId: string, aliases: string[],
  evaluate: typeof evaluatePermission = evaluatePermission
): Promise<number> {
  const probes: Array<{ action: PermissionAction; rank: number }> = [
    { action: 'admin', rank: 3 },
    { action: 'write', rank: 2 },
    { action: 'read', rank: 1 },
  ];
  for (const probe of probes) {
    const result = await evaluate(
      userId, roles, probe.action, path, orgId, vaultId, { userAliases: aliases }
    );
    if (result.allowed) return probe.rank;   // first allowed wins
  }
  return 0;
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
  vaultId: string,
  options: PermissionEvaluationOptions = {}
): Promise<PermissionRule[]> {
  if (options.respectAdminBypass !== false && rolesIncludeOrgAdmin(roles)) {
    return [];
  }

  const rules = await fetchApplicableRules(
    principalLookupValues(userId, options.userAliases),
    roles,
    orgId,
    vaultId
  );
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
  userIds: string[],
  roles: string[],
  orgId: string,
  vaultId: string
): Promise<PermissionRule[]> {
  const results: PermissionRule[] = [];
  const seen = new Set<string>();
  const pushRules = (items: PermissionRule[] | undefined) => {
    for (const rule of items ?? []) {
      const key = rule.id || `${rule.userId}:${rule.role ?? ''}:${rule.pathPattern}:${rule.effect}`;
      if (seen.has(key)) continue;
      seen.add(key);
      results.push(rule);
    }
  };

  // Tenant + vault filter — every query enforces both layers of isolation.
  const scopeFilter = {
    FilterExpression: 'orgId = :orgId AND vaultId = :vaultId',
    scopeValues: { ':orgId': orgId, ':vaultId': vaultId } as Record<string, unknown>,
  };

  // Authorization must be complete. DynamoDB Query is capped at 1 MB and can
  // return LastEvaluatedKey even when a filter leaves few visible rows. A
  // single-page lookup can therefore miss a later deny rule and widen access.
  // Paginate every principal/role/wildcard query; any failed page rejects the
  // whole evaluation so callers fail closed.
  const queryAll = async (input: QueryCommandInput): Promise<PermissionRule[]> => {
    const items: PermissionRule[] = [];
    let exclusiveStartKey: Record<string, unknown> | undefined;
    do {
      const page = await docClient.send(
        new QueryCommand({
          ...input,
          ...(exclusiveStartKey ? { ExclusiveStartKey: exclusiveStartKey } : {}),
        })
      );
      items.push(...((page.Items ?? []) as PermissionRule[]));
      exclusiveStartKey = page.LastEvaluatedKey as Record<string, unknown> | undefined;
    } while (exclusiveStartKey);
    return items;
  };

  // Fetch user-specific rules. Include canonical subject id plus legacy
  // aliases (notably email-address principals) so old rules and new rules
  // are evaluated by the same backend source of truth.
  for (const lookupUserId of userIds) {
    pushRules(await queryAll({
      TableName: PERMISSIONS_TABLE,
      IndexName: 'userId-index',
      KeyConditionExpression: 'userId = :uid',
      FilterExpression: scopeFilter.FilterExpression,
      ExpressionAttributeValues: { ':uid': lookupUserId, ...scopeFilter.scopeValues },
    }));
  }

  // Fetch role-based rules
  for (const role of roles) {
    pushRules(await queryAll({
      TableName: PERMISSIONS_TABLE,
      IndexName: 'role-index',
      KeyConditionExpression: '#role = :role',
      ExpressionAttributeNames: { '#role': 'role' },
      FilterExpression: scopeFilter.FilterExpression,
      ExpressionAttributeValues: { ':role': role, ...scopeFilter.scopeValues },
    }));
  }

  // Fetch wildcard rules (apply to all users within the same org+vault)
  pushRules(await queryAll({
    TableName: PERMISSIONS_TABLE,
    IndexName: 'userId-index',
    KeyConditionExpression: 'userId = :uid',
    FilterExpression: scopeFilter.FilterExpression,
    ExpressionAttributeValues: { ':uid': '*', ...scopeFilter.scopeValues },
  }));

  return results;
}

function principalLookupValues(userId: string, aliases: string[] | undefined): string[] {
  const seen = new Set<string>();
  const values: string[] = [];
  for (const value of [userId, ...(aliases ?? [])]) {
    const trimmed = value.trim();
    if (!trimmed) continue;
    const key = trimmed.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    values.push(trimmed);
  }
  return values;
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
        // eslint-disable-next-line no-control-regex -- intentionally matches raw control characters (CR/LF/NUL..US/DEL) so header-injection bytes are stripped from agent header values
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

  // Org-configurable audit filtering: an org can opt specific actions out of
  // the audit trail via settings.disabledAuditActions. Look the settings up
  // once and reuse them for both the opt-out check and the retention TTL.
  // Fail open — if the lookup throws we still write the entry so a transient
  // settings error never silently drops audit data.
  let orgSettings: OrgSettings | null = null;
  if (entry.orgId) {
    try {
      orgSettings = await getEffectiveOrgSettings(entry.orgId);
    } catch (err) {
      console.error('[AUDIT_SETTINGS_LOOKUP_FAILURE]', (err as Error).message, { orgId: entry.orgId });
    }
  }
  if (orgSettings?.disabledAuditActions?.includes(entry.action)) {
    return;
  }

  const expiresAtTtl = computeAuditExpiryTtl(orgSettings, timestamp);
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

function computeAuditExpiryTtl(settings: OrgSettings | null, timestamp: string): number {
  const retentionDays = settings?.retentionDays ?? DEFAULT_ORG_SETTINGS.retentionDays;
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
const ALLOWED_CORS_HEADERS = 'Content-Type,Authorization,X-VaultGuard-Session-Id,X-VG-Agent-Name,X-VG-Lease-Id';
const ALLOWED_CORS_METHODS = 'GET,POST,PUT,PATCH,DELETE,OPTIONS';

/** Standard security headers applied to every API response. */
export function buildApiHeaders(
  requestId?: string,
  overrides: Record<string, string> = {}
): Record<string, string> {
  return {
    'Content-Type': 'application/json',
    'X-Request-Id': requestId || '',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Cache-Control': 'no-store',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Access-Control-Allow-Origin': ALLOWED_CORS_ORIGIN,
    'Access-Control-Allow-Headers': ALLOWED_CORS_HEADERS,
    'Access-Control-Allow-Methods': ALLOWED_CORS_METHODS,
    ...overrides,
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
    headers: buildApiHeaders(requestId),
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
    headers: buildApiHeaders(requestId),
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

// ─── Per-user debug logging ─────────────────────────────────────────────────
//
// Targeted CloudWatch logging that only fires for the email addresses listed
// in `DEBUG_USER_EMAILS`. Used for live-traffic investigations where the
// audit log isn't granular enough and CloudWatch search by user is the
// fastest path to a diagnosis. Strict allow-list so any other user's traffic
// produces zero debug output — no PII leakage, no extra spend.
//
// To investigate a different user, edit DEBUG_USER_EMAILS, redeploy the
// affected Lambda(s), and use `scripts/query-debug-logs.mjs` to read back.
// Remove instrumented calls (or empty the allow-list) once the investigation
// is over so production logs stay clean.
// 1.0.31 cleanup: emptied after the 2026-05-31 Pete investigation
// closed (Wave 1 + Wave 2 fixes shipped). Helper kept for future
// investigations — add an email here, insert one-off `debugUserLog`
// calls in the code paths under investigation, redeploy, query via
// `scripts/query-debug-logs.mjs`, then empty this set again.
//
// SD-14-F4: the emitted log never contains the raw email — it is reduced to a
// stable truncated SHA-256 `userTag` (see debugUserTag) so no plaintext PII
// sits in CloudWatch. The allow-list below still matches the real email; only
// the OUTPUT is hashed, and `query-debug-logs.mjs` hashes the same way to
// filter. Emails are low-entropy, so the tag is confirmable by a guesser who
// already has the address — the guarantee is "no standing plaintext PII in
// logs", not anonymity against a determined insider.
const DEBUG_USER_EMAILS = new Set<string>();

interface DebugUserContext {
  email?: string;
  userId?: string;
  roles?: string[];
}

/**
 * SD-14-F4: reduce an email to a stable, non-plaintext tag for debug logs so no
 * raw PII lands in CloudWatch. Deterministic (same email → same tag) so an
 * operator can correlate a known target's rows by hashing the address; the
 * reader (`scripts/query-debug-logs.mjs`) recomputes the identical tag to filter.
 */
export function debugUserTag(email: string): string {
  return createHash('sha256').update(email.trim().toLowerCase()).digest('hex').slice(0, 16);
}

export function debugUserLog(
  user: DebugUserContext | null | undefined,
  event: string,
  data: Record<string, unknown> = {}
): void {
  const email = user?.email?.trim().toLowerCase();
  if (!email || !DEBUG_USER_EMAILS.has(email)) return;
  // Single-line JSON so CloudWatch Logs Insights and grep both work.
  // `_dbg: 1` is the cheap discriminator the query script filters on.
  console.log(
    JSON.stringify({
      _dbg: 1,
      ts: new Date().toISOString(),
      userTag: debugUserTag(email),
      userId: user?.userId,
      roles: user?.roles,
      event,
      ...data,
    })
  );
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
  /**
   * Whether an idle timeout LOCKS the vault (evict keys + local-PIN unlock,
   * session preserved) or fully LOGS OUT. `DEFAULT_ORG_SETTINGS` resolves an
   * absent value to `'lock'` (quick 260711-l2e) so an idle vault locks instead
   * of forcing a full re-login; brand-new orgs are still seeded `'lock'` at
   * signup, and any org that EXPLICITLY stored `'logout'` keeps it unchanged.
   * This deliberately reverses the earlier O-1 back-compat default (`'logout'`):
   * legacy orgs that never set the field move logout->lock on the next Lambda
   * deploy. Safe by construction — with no PIN the plugin keeps the session
   * (never logs out on idle); with a PIN the lock is offline-unlockable. See the
   * D3 control model in the phase-12 planning docs.
   */
  idleAction: 'lock' | 'logout';
  /**
   * When false (default), vault admins/owners and org admins/owners bypass
   * every per-file deny rule — `evaluatePermission` short-circuits to
   * allowed=true for them. This is the safe default: lockout-prevention,
   * backward compatible, and matches the "admins can always see everything"
   * mental model.
   *
   * When true, per-file rules bind admins too. Pete (file-admin on /foo.md)
   * can write a deny rule that restricts peter@sedmak.sk (org owner) on
   * that file — the rule actually takes effect for both the access summary
   * AND the underlying file read/write/delete/list operations. Admins still
   * have admin rights elsewhere (managing users, vaults, billing) — the
   * restriction is scoped to file content only, and admins can always
   * re-elevate themselves via the permission management endpoints (those
   * still bypass for caller-authorization).
   *
   * Surface this via the admin-panel "Allow per-file restrictions on
   * admins" toggle. Off by default.
   */
  allowAdminPerFileRestrictions: boolean;
  /**
   * Low-risk, high-volume audit actions the org has opted OUT of recording.
   * Security/admin/auth/mutation/recovery events are intentionally not
   * disableable; normalizeDisabledAuditActions drops anything outside
   * DISABLEABLE_AUDIT_ACTIONS.
   */
  disabledAuditActions: string[];
}

export type PersistedOrgSettings = Omit<OrgSettings, 'orgId' | 'orgName'>;

export const DEFAULT_ORG_SETTINGS: PersistedOrgSettings = {
  syncMode: 'periodic',
  syncIntervalMinutes: 1,
  enforceEncryption: true,
  // 720h = 30 days: the "persistent trusted device" default (Phase 12 change #5).
  // The cap is NOT removed — assertSessionAgePolicy still enforces whatever the org
  // stores; existing orgs keep their stored value because normalizeStoredOrgSettings
  // only supplies this default when the field is absent. Tracks the 30-day
  // refresh-token window so active users are not force-relogin'd ~daily.
  maxSessionDurationHours: 720,
  requireMfa: false,
  allowedDomains: [],
  retentionDays: 365,
  autoLockMinutes: 30,
  // 'lock' (quick 260711-l2e): an idle vault locks (PIN unlock, session kept)
  // instead of forcing a full re-login. Reverses the earlier O-1 'logout'
  // default for absent-field orgs; explicitly-stored values still win.
  idleAction: 'lock',
  allowAdminPerFileRestrictions: false,
  disabledAuditActions: [],
};

export const DISABLEABLE_AUDIT_ACTIONS = [
  'files.list',
  'files.read',
  'files.history',
  'files.sync',
  'vault.overview',
  'permissions.check',
  'permissions.access',
  'permissions.access.batch',
  'shares.list',
] as const;

const DISABLEABLE_AUDIT_ACTION_SET = new Set<string>(DISABLEABLE_AUDIT_ACTIONS);

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

  // idleAction: keep ONLY the two known values. Absent or garbage is left
  // unset so buildOrgSettings falls through to DEFAULT ('lock' since quick
  // 260711-l2e — was 'logout' under O-1). This intentionally lets a legacy
  // org that never set the field pick up 'lock' on upgrade so idle locks
  // instead of logging the user out; an org that EXPLICITLY stored 'logout'
  // still round-trips unchanged. New orgs keep writing 'lock' at signup.
  const idleAction =
    rawSettings.idleAction === 'lock' || rawSettings.idleAction === 'logout'
      ? rawSettings.idleAction
      : undefined;
  if (idleAction !== undefined) {
    normalized.idleAction = idleAction;
  }

  if (typeof rawSettings.allowAdminPerFileRestrictions === 'boolean') {
    normalized.allowAdminPerFileRestrictions = rawSettings.allowAdminPerFileRestrictions;
  }

  const disabledAuditActions = normalizeDisabledAuditActions(rawSettings.disabledAuditActions, undefined);
  if (disabledAuditActions !== undefined) {
    normalized.disabledAuditActions = disabledAuditActions;
  }

  return normalized;
}

/**
 * Normalizes a stored `disabledAuditActions` value into a deduplicated array
 * of supported low-risk/noisy action strings. Security, admin, auth, mutation,
 * recovery, bridge, billing, and audit-management rows are always mandatory.
 * Returns `fallback` when the input is not an array so callers can distinguish
 * "not provided" from "explicitly empty".
 */
export function normalizeDisabledAuditActions(
  value: unknown,
  fallback: string[] | undefined
): string[] | undefined {
  if (!Array.isArray(value)) {
    return fallback;
  }
  const cleaned = value
    .filter((action): action is string => typeof action === 'string')
    .map((action) => action.trim())
    .filter((action) => DISABLEABLE_AUDIT_ACTION_SET.has(action));
  return Array.from(new Set(cleaned));
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

/**
 * Returns `false` when the org has `allowAdminPerFileRestrictions: true` —
 * the inverse mapping that target-level evaluators and file-op handlers
 * pass straight into `evaluatePermission`'s `respectAdminBypass` option.
 *
 * Centralizing the lookup here keeps the per-org setting check pinned to
 * the same cached `getEffectiveOrgSettings()` path the settings endpoint
 * already uses, so toggling the setting from the admin panel takes effect
 * within the existing cache TTL (no separate invalidation needed).
 */
export async function shouldRespectAdminBypassFor(orgId: string): Promise<boolean> {
  const settings = await getEffectiveOrgSettings(orgId);
  return !(settings?.allowAdminPerFileRestrictions === true);
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
  // LA4: -1 is the enterprise "unlimited" sentinel (PLAN_LIMITS.enterprise).
  // Without this guard `currentUsers >= -1` is always true and every invite is
  // blocked with "User limit reached (N/-1)".
  if (org.maxUsers < 0) return { allowed: true, org };
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
  // LA4: -1 is the enterprise "unlimited" sentinel — skip the quota check so
  // uploads aren't blocked with "Storage limit reached" on unlimited plans.
  if (org.maxStorageBytes < 0) return { allowed: true, org };
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
  // These are authorization failures, not authentication failures: the caller
  // has a valid session, they just lack access to this vault / role. They must
  // return 403, not the AuthError default of 401 — otherwise clients (the admin
  // panel and the plugin) mistake "you can't see this" for "your session
  // expired" and force a logout. A viewer opening an admin-only subpage was
  // being signed out for exactly this reason.
  if (!vault) {
    throw new AuthError(`Vault not found or access denied: ${vaultId}`, 403);
  }
  if (vault.archived && requiredRole !== 'viewer') {
    throw new AuthError(`Vault is archived and read-only: ${vaultId}`, 403);
  }

  const orgAdmin = isAdmin(user);
  if (orgAdmin) {
    return vault;
  }

  const membership = await getVaultMembership(vaultId, user.userId);
  if (!membership) {
    throw new AuthError(`You are not a member of this vault: ${vaultId}`, 403);
  }

  if (!vaultRoleMeetsRequirement(membership.role, requiredRole)) {
    throw new AuthError(
      `Requires "${requiredRole}" in this vault; you are "${membership.role}".`,
      403
    );
  }

  return vault;
}

/**
 * LF2: reject any mutation (write/delete/rename/permission-rule change) against
 * an archived vault. The dispatch-time requireVaultMember(..., 'viewer') check
 * intentionally allows viewers into archived vaults (read-only browse), which
 * means its archived guard is skipped — so every write/delete/permission
 * handler that only ran a 'viewer' membership check + evaluatePermission (which
 * has no archived awareness) would silently mutate a "frozen" vault. Call this
 * explicitly before any S3 mutation or permission-rule write. Archiving is a
 * legal-hold / retention-freeze, so this is a hard 403 regardless of role.
 */
export function assertVaultWritable(vault: VaultRecord): void {
  if (vault.archived) {
    throw new AuthError(`Vault is archived and read-only: ${vault.vaultId}`, 403);
  }
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

  // SD-09-F1: a permission change outside business hours feeds the
  // OffHoursPermissionChange alarm. recordVaultActivity is the single chokepoint
  // every permission mutation routes through (permissions/handler.ts), so
  // emitting here covers all mutation sites without touching each one. Only the
  // permissions handler passes 'permission_changed'; vaults/files callers pass
  // other actions and never emit. Fire-and-forget — never block the activity write.
  if (params.action === 'permission_changed' && isOffHours(changedAt)) {
    void emitSecurityMetric('OffHoursPermissionChange');
  }

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
 * The role namespace to use for per-file / per-scope permission evaluation of a
 * caller: their VAULT-membership role, NOT `user.roles` (the org/Cognito roles).
 *
 * Role-scoped permission rules (`{role:'editor', deny, read, /secret/**}`) are
 * keyed on the vault role, and `fetchApplicableRules` only fetches role-index
 * rows for the role strings actually passed in. A normal member's vault role
 * lives in VAULT_MEMBERS, never in the Cognito token, so evaluating with
 * `user.roles` silently fails to fetch (and therefore enforce) role-scoped
 * rules — the LF1 drift class. Org admins/owners keep `user.roles`: they
 * legitimately bypass membership (`evaluatePermission` short-circuits them, and
 * `findApplicableDenyRulesInScope` returns [] for them).
 *
 * This is the single source of truth for that decision. `files/handler.ts`
 * `resolveFileOpRoles` delegates here; the auth key-lease handler uses it for
 * the read-deny gate and scope probes. Never fold the vault role into
 * `user.roles` — a vault 'admin' would then be misread as an ORG admin by
 * `rolesIncludeOrgAdmin`.
 */
export async function resolveVaultEvaluationRoles(
  user: UserContext,
  vaultId: string
): Promise<string[]> {
  if (isAdmin(user)) return user.roles;
  const membership = await getVaultMembership(vaultId, user.userId);
  if (membership) return [membership.role];
  return user.roles;
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
