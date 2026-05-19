/**
 * VaultGuard — Vaults Lambda Handler
 *
 * CRUD for the Vault entity and its membership table. A "vault" is a named,
 * isolated namespace inside an organization. Files, permissions, and members
 * are all scoped to a single vault.
 *
 * Endpoints:
 *   GET    /vaults                                 — List vaults the caller can see
 *   POST   /vaults                                 — Create a new vault (org-admin)
 *   GET    /vaults/{vaultId}                       — Get vault details (member or admin)
 *   PATCH  /vaults/{vaultId}                       — Update name/desc/defaultRole/archived (vault-admin or org-admin)
 *   DELETE /vaults/{vaultId}                       — Soft-archive (org-admin)
 *
 *   GET    /vaults/{vaultId}/members               — List members (any member)
 *   POST   /vaults/{vaultId}/members               — Add member (vault-admin or org-admin)
 *   PATCH  /vaults/{vaultId}/members/{userId}      — Change role (vault-admin or org-admin)
 *   DELETE /vaults/{vaultId}/members/{userId}      — Remove member (vault-admin or org-admin)
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  CognitoIdentityProviderClient,
  ListUsersCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import {
  docClient,
  verifyActiveUser,
  requireOrgId,
  requireVaultMember,
  getVault,
  getVaultBySlug,
  getVaultMembership,
  listVaultsForUser,
  listVaultsForOrg,
  listVaultMembers,
  slugifyVaultName,
  isAdmin,
  logAudit,
  formatError,
  formatSuccess,
  parseBody,
  validateRequiredFields,
  getClientIp,
  getUserAgent,
  generateId,
  AuthError,
  ValidationError,
  PutCommand,
  DeleteCommand,
  UpdateCommand,
  QueryCommand,
  UserContext,
  VaultRecord,
  VaultMemberRecord,
  VaultMemberRole,
  VaultKind,
  PluginAllowlistEntry,
  PermissionAction,
  VAULTS_TABLE,
  VAULT_MEMBERS_TABLE,
  PERMISSIONS_TABLE,
  LEASES_TABLE,
} from '../shared/utils';

// Required env var — empty-string fallback would let Cognito calls fail
// confusingly downstream rather than at module load. Match the pattern in
// other handlers (e.g. users/handler.ts).
const USER_POOL_ID = process.env.USER_POOL_ID!;
const COGNITO_REGION = process.env.AWS_REGION || 'eu-west-1';
const cognitoClient = new CognitoIdentityProviderClient({ region: COGNITO_REGION });

interface CognitoIdentity {
  displayName: string;
  email: string;
}

/**
 * Builds a sub→{displayName,email} map for everyone in `orgId` from one
 * Cognito ListUsers call. Used to enrich vault membership rows with
 * human-readable names so non-admin members (who can't hit the admin-only
 * `/users` endpoint) still see real names in the file permission UI.
 *
 * Failures are non-fatal — callers fall back to bare userId rendering.
 */
async function buildOrgIdentityMap(orgId: string): Promise<Map<string, CognitoIdentity>> {
  const map = new Map<string, CognitoIdentity>();
  if (!USER_POOL_ID || !orgId) return map;

  try {
    const result = await cognitoClient.send(
      new ListUsersCommand({ UserPoolId: USER_POOL_ID, Limit: 60 })
    );

    for (const u of result.Users ?? []) {
      const attrs = Object.fromEntries(
        (u.Attributes ?? []).map((a) => [a.Name, a.Value ?? ''])
      );
      if (attrs['custom:org'] !== orgId) continue;

      const sub = attrs['sub'] || u.Username || '';
      if (!sub) continue;

      const givenName = attrs['given_name'] || '';
      const familyName = attrs['family_name'] || '';
      const explicitName = attrs['name']?.trim() || '';
      const email = attrs['email'] || '';
      const composed = [givenName, familyName].filter(Boolean).join(' ').trim();
      const displayName = explicitName || composed || email || sub;

      map.set(sub, { displayName, email });
    }
  } catch (err) {
    console.warn('[VAULTS_HANDLER] Cognito directory lookup failed', (err as Error).message);
  }

  return map;
}

// ─── Constants ───────────────────────────────────────────────────────────────

const VALID_KINDS: VaultKind[] = ['team', 'personal', 'shared'];
const VALID_ROLES: VaultMemberRole[] = ['viewer', 'editor', 'admin'];
const MAX_NAME_LENGTH = 80;
const MAX_DESCRIPTION_LENGTH = 500;
const DEFAULT_MEMBER_RULE_PRIORITY = 0;
const DEFAULT_MEMBER_RULE_SK = 'RULE';
const DEFAULT_MEMBER_RULE_SOURCE = 'vault-member-default';

// ─── Main Handler ────────────────────────────────────────────────────────────

export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId || generateId();
  const method = event.httpMethod?.toUpperCase();
  const resource = event.resource || '';

  try {
    const user = await verifyActiveUser(event);

    switch (true) {
      case method === 'GET' && resource === '/vaults':
        return await handleListVaults(event, user, requestId);

      case method === 'POST' && resource === '/vaults':
        return await handleCreateVault(event, user, requestId);

      case method === 'GET' && resource === '/vaults/{vaultId}':
        return await handleGetVault(event, user, requestId);

      case method === 'PATCH' && resource === '/vaults/{vaultId}':
        return await handleUpdateVault(event, user, requestId);

      case method === 'DELETE' && resource === '/vaults/{vaultId}':
        return await handleArchiveVault(event, user, requestId);

      case method === 'GET' && resource === '/vaults/{vaultId}/members':
        return await handleListMembers(event, user, requestId);

      case method === 'POST' && resource === '/vaults/{vaultId}/members':
        return await handleAddMember(event, user, requestId);

      case method === 'PATCH' && resource === '/vaults/{vaultId}/members/{userId}':
        return await handleUpdateMember(event, user, requestId);

      case method === 'DELETE' && resource === '/vaults/{vaultId}/members/{userId}':
        return await handleRemoveMember(event, user, requestId);

      default:
        return formatError(404, `Route not found: ${method} ${resource}`, requestId);
    }
  } catch (err: unknown) {
    if (err instanceof AuthError) {
      return formatError(err.statusCode, err.message, requestId, err.code);
    }
    if (err instanceof ValidationError) {
      return formatError(err.statusCode, err.message, requestId);
    }
    const message = err instanceof Error ? err.message : 'Internal server error';
    console.error('[VAULTS_HANDLER_ERROR]', message, err);
    return formatError(500, 'Internal server error', requestId);
  }
}

// ─── GET /vaults ─────────────────────────────────────────────────────────────

async function handleListVaults(
  event: APIGatewayProxyEvent,
  user: UserContext,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const orgId = requireOrgId(user);

  // Org admins see every vault in the org. Everyone else sees only the
  // vaults they are a direct member of.
  const vaults = isAdmin(user)
    ? await listVaultsForOrg(orgId)
    : await listVaultsForUser(orgId, user.userId);

  const visible = vaults.filter((v) => !v.archived || isAdmin(user));

  return formatSuccess(200, { vaults: visible }, requestId);
}

// ─── POST /vaults ────────────────────────────────────────────────────────────

async function handleCreateVault(
  event: APIGatewayProxyEvent,
  user: UserContext,
  requestId: string
): Promise<APIGatewayProxyResult> {
  if (!isAdmin(user)) {
    throw new AuthError('Only organization admins can create vaults.', 403);
  }

  const orgId = requireOrgId(user);
  const body = parseBody(event);
  validateRequiredFields(body, ['name']);

  const name = String(body.name).trim();
  if (name.length === 0 || name.length > MAX_NAME_LENGTH) {
    throw new ValidationError(`Name must be 1-${MAX_NAME_LENGTH} characters.`, 'name');
  }

  const description = typeof body.description === 'string' ? body.description.trim() : '';
  if (description.length > MAX_DESCRIPTION_LENGTH) {
    throw new ValidationError(`Description must be ≤${MAX_DESCRIPTION_LENGTH} characters.`, 'description');
  }

  const kind: VaultKind = VALID_KINDS.includes(body.kind as VaultKind)
    ? (body.kind as VaultKind)
    : 'team';

  const defaultRole: VaultMemberRole = VALID_ROLES.includes(body.defaultRole as VaultMemberRole)
    ? (body.defaultRole as VaultMemberRole)
    : 'editor';

  // Build a unique slug. Start with the slugified name, append a numeric
  // suffix if it collides with an existing vault in the same org.
  const requestedSlug = typeof body.slug === 'string' && body.slug.trim()
    ? slugifyVaultName(body.slug)
    : slugifyVaultName(name);
  const slug = await reserveUniqueSlug(orgId, requestedSlug || 'vault');

  const vaultId = generateId();
  const nowIso = new Date().toISOString();
  const vault: VaultRecord = {
    orgId,
    vaultId,
    name,
    slug,
    kind,
    defaultRole,
    createdAt: nowIso,
    createdBy: user.userId,
    archived: false,
    ...(description ? { description } : {}),
  };

  await docClient.send(
    new PutCommand({
      TableName: VAULTS_TABLE,
      Item: vault,
      ConditionExpression: 'attribute_not_exists(orgId) AND attribute_not_exists(vaultId)',
    })
  );

  // The creator becomes a vault admin automatically.
  const membership: VaultMemberRecord = {
    vaultId,
    userId: user.userId,
    role: 'admin',
    joinedAt: nowIso,
    invitedBy: user.userId,
  };
  await docClient.send(
    new PutCommand({
      TableName: VAULT_MEMBERS_TABLE,
      Item: membership,
    })
  );

  await upsertDefaultMemberPermission(vault, user.userId, 'admin', user.userId, nowIso);

  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId,
    action: 'vault.created',
    resourcePath: `/vaults/${vaultId}`,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: { vaultId, name, slug, kind },
  });

  return formatSuccess(201, { vault }, requestId);
}

async function reserveUniqueSlug(orgId: string, base: string): Promise<string> {
  let candidate = base;
  let suffix = 2;
  // Cap retries — the slug-index lookup is O(1) per attempt; on a real org
  // this loop terminates immediately. The cap is just a safety net.
  for (let attempt = 0; attempt < 50; attempt++) {
    const existing = await getVaultBySlug(orgId, candidate);
    if (!existing) return candidate;
    candidate = `${base}-${suffix++}`;
  }
  throw new Error(`Unable to allocate a unique slug for "${base}"`);
}

// ─── GET /vaults/{vaultId} ───────────────────────────────────────────────────

async function handleGetVault(
  event: APIGatewayProxyEvent,
  user: UserContext,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const vaultId = event.pathParameters?.vaultId || '';
  // Reading vault metadata requires viewer rights or org-admin.
  const vault = await requireVaultMember(user, vaultId, 'viewer');
  return formatSuccess(200, { vault }, requestId);
}

// ─── PATCH /vaults/{vaultId} ─────────────────────────────────────────────────

async function handleUpdateVault(
  event: APIGatewayProxyEvent,
  user: UserContext,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const vaultId = event.pathParameters?.vaultId || '';
  const body = parseBody(event);
  const updatesArchiveState = typeof body.archived === 'boolean';
  const orgAdmin = isAdmin(user);
  const orgId = requireOrgId(user);
  let vault: VaultRecord;

  if (updatesArchiveState) {
    if (!orgAdmin) {
      throw new AuthError('Only organization admins can archive or reactivate vaults.', 403);
    }
    const existingVault = await getVault(orgId, vaultId);
    if (!existingVault) {
      return formatError(404, `Vault not found: ${vaultId}`, requestId);
    }
    vault = existingVault;
  } else {
    vault = await requireVaultMember(user, vaultId, 'admin');
  }

  const updates: Record<string, unknown> = {};
  const setExprs: string[] = [];
  const exprNames: Record<string, string> = {};
  const exprValues: Record<string, unknown> = {};

  if (typeof body.name === 'string') {
    const name = body.name.trim();
    if (!name || name.length > MAX_NAME_LENGTH) {
      throw new ValidationError(`Name must be 1-${MAX_NAME_LENGTH} characters.`, 'name');
    }
    updates.name = name;
    setExprs.push('#name = :name');
    exprNames['#name'] = 'name';
    exprValues[':name'] = name;
  }

  if (typeof body.description === 'string') {
    const desc = body.description.trim();
    if (desc.length > MAX_DESCRIPTION_LENGTH) {
      throw new ValidationError(`Description must be ≤${MAX_DESCRIPTION_LENGTH} characters.`, 'description');
    }
    updates.description = desc;
    setExprs.push('description = :description');
    exprValues[':description'] = desc;
  }

  if (typeof body.defaultRole === 'string') {
    if (!VALID_ROLES.includes(body.defaultRole as VaultMemberRole)) {
      throw new ValidationError('defaultRole must be viewer, editor, or admin.', 'defaultRole');
    }
    updates.defaultRole = body.defaultRole;
    setExprs.push('defaultRole = :defaultRole');
    exprValues[':defaultRole'] = body.defaultRole;
  }

  if (typeof body.archived === 'boolean') {
    updates.archived = body.archived;
    setExprs.push('archived = :archived');
    exprValues[':archived'] = body.archived;
  }

  if (Array.isArray(body.excludedPaths)) {
    const cleaned = sanitizeExcludedPaths(body.excludedPaths);
    updates.excludedPaths = cleaned;
    setExprs.push('excludedPaths = :excludedPaths');
    exprValues[':excludedPaths'] = cleaned;
  }

  if (Array.isArray(body.pluginAllowlist)) {
    const cleaned = sanitizePluginAllowlist(body.pluginAllowlist, user.userId, vault.pluginAllowlist ?? []);
    updates.pluginAllowlist = cleaned;
    setExprs.push('pluginAllowlist = :pluginAllowlist');
    exprValues[':pluginAllowlist'] = cleaned;
  }

  if (setExprs.length === 0) {
    return formatSuccess(200, { vault }, requestId);
  }

  const result = await docClient.send(
    new UpdateCommand({
      TableName: VAULTS_TABLE,
      Key: { orgId: vault.orgId, vaultId: vault.vaultId },
      UpdateExpression: `SET ${setExprs.join(', ')}`,
      ExpressionAttributeNames: Object.keys(exprNames).length ? exprNames : undefined,
      ExpressionAttributeValues: exprValues,
      ReturnValues: 'ALL_NEW',
    })
  );

  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: vault.orgId,
    action: 'vault.updated',
    resourcePath: `/vaults/${vault.vaultId}`,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: { vaultId: vault.vaultId, updates },
  });

  return formatSuccess(200, { vault: result.Attributes }, requestId);
}

// ─── DELETE /vaults/{vaultId} ────────────────────────────────────────────────

async function handleArchiveVault(
  event: APIGatewayProxyEvent,
  user: UserContext,
  requestId: string
): Promise<APIGatewayProxyResult> {
  if (!isAdmin(user)) {
    throw new AuthError('Only organization admins can archive vaults.', 403);
  }
  const vaultId = event.pathParameters?.vaultId || '';
  const orgId = requireOrgId(user);
  const vault = await getVault(orgId, vaultId);
  if (!vault) {
    return formatError(404, `Vault not found: ${vaultId}`, requestId);
  }

  await docClient.send(
    new UpdateCommand({
      TableName: VAULTS_TABLE,
      Key: { orgId, vaultId },
      UpdateExpression: 'SET archived = :archived',
      ExpressionAttributeValues: { ':archived': true },
    })
  );

  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId,
    action: 'vault.archived',
    resourcePath: `/vaults/${vaultId}`,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: { vaultId, name: vault.name },
  });

  return formatSuccess(200, { archived: true, vaultId }, requestId);
}

// ─── GET /vaults/{vaultId}/members ───────────────────────────────────────────

async function handleListMembers(
  event: APIGatewayProxyEvent,
  user: UserContext,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const vaultId = event.pathParameters?.vaultId || '';
  await requireVaultMember(user, vaultId, 'viewer');

  const orgId = requireOrgId(user);
  const [members, identityMap] = await Promise.all([
    listVaultMembers(vaultId),
    buildOrgIdentityMap(orgId),
  ]);

  const enriched: VaultMemberRecord[] = members.map((member) => {
    const identity = identityMap.get(member.userId);
    if (!identity) return member;
    return { ...member, displayName: identity.displayName, email: identity.email };
  });

  return formatSuccess(200, { members: enriched }, requestId);
}

// ─── POST /vaults/{vaultId}/members ──────────────────────────────────────────

async function handleAddMember(
  event: APIGatewayProxyEvent,
  user: UserContext,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const vaultId = event.pathParameters?.vaultId || '';
  const vault = await requireVaultMember(user, vaultId, 'admin');

  const body = parseBody(event);
  validateRequiredFields(body, ['userId']);

  const targetUserId = String(body.userId).trim();
  if (!targetUserId) {
    throw new ValidationError('userId is required.', 'userId');
  }

  const role: VaultMemberRole = VALID_ROLES.includes(body.role as VaultMemberRole)
    ? (body.role as VaultMemberRole)
    : vault.defaultRole;

  const existing = await getVaultMembership(vaultId, targetUserId);
  if (existing) {
    return formatError(409, `User ${targetUserId} is already a member of this vault.`, requestId);
  }

  const membership: VaultMemberRecord = {
    vaultId,
    userId: targetUserId,
    role,
    joinedAt: new Date().toISOString(),
    invitedBy: user.userId,
  };

  await docClient.send(
    new PutCommand({
      TableName: VAULT_MEMBERS_TABLE,
      Item: membership,
    })
  );

  await upsertDefaultMemberPermission(
    vault,
    targetUserId,
    role,
    user.userId,
    membership.joinedAt
  );

  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: vault.orgId,
    action: 'vault.member_added',
    resourcePath: `/vaults/${vaultId}/members/${targetUserId}`,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: { vaultId, targetUserId, role },
  });

  return formatSuccess(201, { membership }, requestId);
}

// ─── PATCH /vaults/{vaultId}/members/{userId} ────────────────────────────────

async function handleUpdateMember(
  event: APIGatewayProxyEvent,
  user: UserContext,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const vaultId = event.pathParameters?.vaultId || '';
  const targetUserId = event.pathParameters?.userId || '';
  const vault = await requireVaultMember(user, vaultId, 'admin');

  const body = parseBody(event);
  if (typeof body.role !== 'string' || !VALID_ROLES.includes(body.role as VaultMemberRole)) {
    throw new ValidationError('role must be viewer, editor, or admin.', 'role');
  }
  const role = body.role as VaultMemberRole;

  const existing = await getVaultMembership(vaultId, targetUserId);
  if (!existing) {
    return formatError(404, `User ${targetUserId} is not a member of this vault.`, requestId);
  }

  await docClient.send(
    new UpdateCommand({
      TableName: VAULT_MEMBERS_TABLE,
      Key: { vaultId, userId: targetUserId },
      UpdateExpression: 'SET #role = :role',
      ExpressionAttributeNames: { '#role': 'role' },
      ExpressionAttributeValues: { ':role': role },
    })
  );

  await upsertDefaultMemberPermission(
    vault,
    targetUserId,
    role,
    user.userId,
    new Date().toISOString()
  );

  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: vault.orgId,
    action: 'vault.member_role_changed',
    resourcePath: `/vaults/${vaultId}/members/${targetUserId}`,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: { vaultId, targetUserId, oldRole: existing.role, newRole: role },
  });

  return formatSuccess(200, { membership: { ...existing, role } }, requestId);
}

// ─── DELETE /vaults/{vaultId}/members/{userId} ───────────────────────────────

async function handleRemoveMember(
  event: APIGatewayProxyEvent,
  user: UserContext,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const vaultId = event.pathParameters?.vaultId || '';
  const targetUserId = event.pathParameters?.userId || '';
  const vault = await requireVaultMember(user, vaultId, 'admin');

  const existing = await getVaultMembership(vaultId, targetUserId);
  if (!existing) {
    return formatError(404, `User ${targetUserId} is not a member of this vault.`, requestId);
  }

  // Prevent removing the last admin to avoid orphaning the vault.
  if (existing.role === 'admin') {
    const members = await listVaultMembers(vaultId);
    const otherAdmins = members.filter(
      (m) => m.role === 'admin' && m.userId !== targetUserId
    );
    if (otherAdmins.length === 0) {
      throw new ValidationError(
        'Cannot remove the last vault admin. Promote another member first.',
        'userId'
      );
    }
  }

  await docClient.send(
    new DeleteCommand({
      TableName: VAULT_MEMBERS_TABLE,
      Key: { vaultId, userId: targetUserId },
    })
  );

  await deleteDefaultMemberPermission(vaultId, targetUserId);

  // Cut the cryptographic-key plane in the same step as the data plane.
  // Without this, the removed user's outstanding leases stay active and they
  // can keep calling /auth/refresh to rotate a vault-scoped DEK they should
  // no longer hold (used to decrypt previously-cached or out-of-band ciphertext).
  const revokedLeases = await revokeUserVaultLeases(
    targetUserId,
    vaultId,
    vault.orgId,
    user.userId
  );

  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: vault.orgId,
    action: 'vault.member_removed',
    resourcePath: `/vaults/${vaultId}/members/${targetUserId}`,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: { vaultId, targetUserId, oldRole: existing.role, revokedLeases },
  });

  return formatSuccess(200, { removed: true, revokedLeases }, requestId);
}

/**
 * Revokes all active leases belonging to `userId` that are bound to `vaultId`
 * within `orgId`. Called when a member is removed from a vault so they cannot
 * keep refreshing a vault-scoped DEK after losing access. Returns the count
 * of leases revoked.
 */
async function revokeUserVaultLeases(
  userId: string,
  vaultId: string,
  orgId: string,
  revokedBy: string
): Promise<number> {
  const result = await docClient.send(
    new QueryCommand({
      TableName: LEASES_TABLE,
      IndexName: 'userId-index',
      KeyConditionExpression: 'userId = :uid',
      FilterExpression: '#s = :active AND orgId = :oid AND vaultId = :vid',
      ExpressionAttributeNames: { '#s': 'status' },
      ExpressionAttributeValues: {
        ':uid': userId,
        ':oid': orgId,
        ':vid': vaultId,
        ':active': 'active',
      },
    })
  );

  const activeLeases = result.Items || [];
  const now = new Date().toISOString();

  for (const lease of activeLeases) {
    await docClient.send(
      new UpdateCommand({
        TableName: LEASES_TABLE,
        Key: { leaseId: lease.leaseId as string },
        UpdateExpression: 'SET #s = :revoked, revokedAt = :now, revokedBy = :by',
        ExpressionAttributeNames: { '#s': 'status' },
        ExpressionAttributeValues: {
          ':revoked': 'revoked',
          ':now': now,
          ':by': revokedBy,
        },
      })
    );
  }

  return activeLeases.length;
}

function defaultMemberPermissionRuleId(vaultId: string, userId: string): string {
  return `${DEFAULT_MEMBER_RULE_SOURCE}#${vaultId}#${userId}`;
}

function actionsForVaultRole(role: VaultMemberRole): PermissionAction[] {
  switch (role) {
    case 'admin':
      return ['read', 'write', 'delete', 'admin', 'list'];
    case 'editor':
      return ['read', 'write', 'list'];
    case 'viewer':
    default:
      return ['read', 'list'];
  }
}

async function upsertDefaultMemberPermission(
  vault: VaultRecord,
  userId: string,
  role: VaultMemberRole,
  actorUserId: string,
  nowIso: string
): Promise<void> {
  const ruleId = defaultMemberPermissionRuleId(vault.vaultId, userId);
  await docClient.send(
    new PutCommand({
      TableName: PERMISSIONS_TABLE,
      Item: {
        pk: ruleId,
        sk: DEFAULT_MEMBER_RULE_SK,
        id: ruleId,
        orgId: vault.orgId,
        vaultId: vault.vaultId,
        userId,
        pathPattern: '/**',
        actions: actionsForVaultRole(role),
        effect: 'allow',
        priority: DEFAULT_MEMBER_RULE_PRIORITY,
        createdAt: nowIso,
        updatedAt: nowIso,
        createdBy: actorUserId,
        source: DEFAULT_MEMBER_RULE_SOURCE,
      },
    })
  );
}

/**
 * Normalises an inbound excludedPaths list: strips whitespace, drops empties,
 * removes leading/trailing slashes (we store vault-relative paths without
 * them), enforces a per-entry length cap, and dedupes. The whole-list cap
 * stops a malicious admin from blowing up every member's settings payload.
 */
function sanitizeExcludedPaths(input: unknown[]): string[] {
  const MAX_ENTRIES = 200;
  const MAX_LENGTH = 500;
  const seen = new Set<string>();
  const out: string[] = [];
  for (const raw of input) {
    if (typeof raw !== 'string') continue;
    const cleaned = raw.trim().replace(/^\/+/, '').replace(/\/+$/, '');
    if (!cleaned) continue;
    if (cleaned.length > MAX_LENGTH) {
      throw new ValidationError(
        `Excluded path entries must be ≤${MAX_LENGTH} characters.`,
        'excludedPaths'
      );
    }
    if (seen.has(cleaned)) continue;
    seen.add(cleaned);
    out.push(cleaned);
    if (out.length > MAX_ENTRIES) {
      throw new ValidationError(
        `Cannot have more than ${MAX_ENTRIES} excluded paths.`,
        'excludedPaths'
      );
    }
  }
  return out;
}

/**
 * Normalises a pluginAllowlist payload: validates required fields, caps
 * sizes, and stamps the `addedBy` and `addedAt` fields server-side so
 * clients can't forge a different admin. Existing entries (matched by
 * pluginId) keep their original timestamps unless the caller explicitly
 * changes the bundle hash, version, or note.
 */
function sanitizePluginAllowlist(
  input: unknown[],
  actorUserId: string,
  existing: PluginAllowlistEntry[]
): PluginAllowlistEntry[] {
  const MAX_ENTRIES = 50;
  const MAX_ID = 120;
  const MAX_NAME = 120;
  const MAX_NOTE = 500;
  const MAX_VERSION = 40;
  const HASH_RE = /^[0-9a-f]{64}$/i;
  const ID_RE = /^[a-z0-9][a-z0-9-_]*$/i;
  const nowIso = new Date().toISOString();
  const existingById = new Map(existing.map((e) => [e.pluginId, e]));
  const seen = new Set<string>();
  const out: PluginAllowlistEntry[] = [];

  for (const raw of input) {
    if (!raw || typeof raw !== 'object') continue;
    const entry = raw as Record<string, unknown>;
    const pluginId = typeof entry.pluginId === 'string' ? entry.pluginId.trim() : '';
    const displayName = typeof entry.displayName === 'string' ? entry.displayName.trim() : '';
    if (!pluginId || pluginId.length > MAX_ID || !ID_RE.test(pluginId)) {
      throw new ValidationError(
        `pluginId must match ${ID_RE.source} and be ≤${MAX_ID} chars.`,
        'pluginAllowlist.pluginId'
      );
    }
    if (!displayName || displayName.length > MAX_NAME) {
      throw new ValidationError(
        `displayName is required and must be ≤${MAX_NAME} chars.`,
        'pluginAllowlist.displayName'
      );
    }
    const version = typeof entry.version === 'string' ? entry.version.trim() : undefined;
    if (version !== undefined && version.length > MAX_VERSION) {
      throw new ValidationError(
        `version must be ≤${MAX_VERSION} chars.`,
        'pluginAllowlist.version'
      );
    }
    const bundleSha256 = typeof entry.bundleSha256 === 'string' ? entry.bundleSha256.trim().toLowerCase() : undefined;
    if (bundleSha256 !== undefined && bundleSha256 !== '' && !HASH_RE.test(bundleSha256)) {
      throw new ValidationError(
        'bundleSha256 must be a 64-character hex SHA-256 digest.',
        'pluginAllowlist.bundleSha256'
      );
    }
    const note = typeof entry.note === 'string' ? entry.note.trim() : undefined;
    if (note !== undefined && note.length > MAX_NOTE) {
      throw new ValidationError(
        `note must be ≤${MAX_NOTE} chars.`,
        'pluginAllowlist.note'
      );
    }

    if (seen.has(pluginId)) {
      throw new ValidationError(
        `Duplicate pluginId in allowlist: ${pluginId}.`,
        'pluginAllowlist'
      );
    }
    seen.add(pluginId);

    const prior = existingById.get(pluginId);
    out.push({
      pluginId,
      displayName,
      ...(version ? { version } : prior?.version ? { version: prior.version } : {}),
      ...(bundleSha256
        ? { bundleSha256 }
        : prior?.bundleSha256 && bundleSha256 === undefined
          ? { bundleSha256: prior.bundleSha256 }
          : {}),
      ...(note ? { note } : prior?.note && note === undefined ? { note: prior.note } : {}),
      addedAt: prior?.addedAt ?? nowIso,
      addedBy: prior?.addedBy ?? actorUserId,
    });

    if (out.length > MAX_ENTRIES) {
      throw new ValidationError(
        `Cannot allowlist more than ${MAX_ENTRIES} plugins per vault.`,
        'pluginAllowlist'
      );
    }
  }
  return out;
}

async function deleteDefaultMemberPermission(vaultId: string, userId: string): Promise<void> {
  await docClient.send(
    new DeleteCommand({
      TableName: PERMISSIONS_TABLE,
      Key: {
        pk: defaultMemberPermissionRuleId(vaultId, userId),
        sk: DEFAULT_MEMBER_RULE_SK,
      },
    })
  );
}
