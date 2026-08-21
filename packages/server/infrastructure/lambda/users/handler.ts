/**
 * VaultGuard — User Management Lambda Handler
 *
 * Manages user lifecycle via Cognito User Pool admin operations.
 *
 * Endpoints:
 * - GET    /users                      — List all users in the Cognito pool
 * - GET    /users/roles                — List assignable roles
 * - POST   /users/invite               — Create a new user and assign role
 * - PUT    /users/{userId}/role         — Change a user's role (Cognito group)
 * - PUT    /users/{userId}/profile     — Update a user's display name
 * - POST   /users/{userId}/revoke      — Disable user, remove from all groups
 * - POST   /users/{userId}/reactivate  — Re-enable a previously revoked user
 * - POST   /users/{userId}/resend-invite — Resend invitation email to pending user
 * - GET    /users/{userId}/activity     — Get recent activity from audit log
 * - GET    /orgs/{orgId}/settings      — Get organization settings
 * - PUT    /orgs/{orgId}/settings      — Update organization settings
 * - DELETE /orgs/{orgId}/settings      — Reset organization settings to defaults
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  CognitoIdentityProviderClient,
  ListUsersCommand,
  AdminCreateUserCommand,
  AdminDeleteUserCommand,
  AdminAddUserToGroupCommand,
  AdminRemoveUserFromGroupCommand,
  AdminListGroupsForUserCommand,
  AdminDisableUserCommand,
  AdminEnableUserCommand,
  AdminSetUserMFAPreferenceCommand,
  AdminGetUserCommand,
  AdminUpdateUserAttributesCommand,
  ListGroupsCommand,
  CreateGroupCommand,
  MessageActionType,
} from '@aws-sdk/client-cognito-identity-provider';
import type {
  AdminGetUserCommandOutput,
  ListUsersCommandOutput,
} from '@aws-sdk/client-cognito-identity-provider';
import {
  docClient,
  verifyActiveUser,
  logAudit,
  formatError,
  formatSuccess,
  parseBody,
  validateRequiredFields,
  getClientIp,
  getUserAgent,
  generateId,
  isAdmin,
  isReservedGroupName,
  AuthError,
  ValidationError,
  QueryCommand,
  GetCommand,
  PutCommand,
  DeleteCommand,
  AUDIT_TABLE,
  SESSIONS_TABLE,
  LEASES_TABLE,
  ORGANIZATIONS_TABLE,
  PERMISSIONS_TABLE,
  VAULT_MEMBERS_TABLE,
  RECOVERY_CODES_TABLE,
  BatchWriteCommand,
  PermissionAction,
  listVaultsForOrg,
  getActiveOrg,
  UserContext,
  requireOrgId,
  UpdateCommand,
  OrgRecord,
  OrgSettings,
  PersistedOrgSettings,
  DEFAULT_ORG_SETTINGS,
  buildOrgSettings,
  normalizeSyncMode,
  parsePositiveInteger,
  parseNonNegativeInteger,
  normalizeAllowedDomains,
  normalizeDisabledAuditActions,
  isEmailAllowedForOrg,
  invalidateOrgSettingsCache,
  VaultRecord,
  listVaultMembers,
  VaultMemberRecord,
} from '../shared/utils';
import {
  DEFAULT_GUEST_ACCESS_DAYS,
  GUEST_ORIGIN_ATTACHED,
  GUEST_ORIGIN_INVITE,
  GuestOrigin,
  guestAccessExpiresAt,
  isIdenticalGuestMembership,
  isExpiringAccessActive,
  isIdenticalGuestPermissionRule,
  normalizeGuestVaultIds,
  summarizeGuestAccess,
} from '../shared/guest-access';
import { UsersRouteContext, resolveUsersRouteContext } from '../shared/route-utils';
// Seat accounting and crypto-access teardown live in shared/ so the reconciler's
// guest-expiry sweeper can call the SAME implementation, and so the IAM grant
// guard can see the tables they touch. Layering is one-directional: this handler
// imports the module, never the reverse.
import {
  deleteGuestAccessRows,
  ensureRevokedSeatIdentity,
  releaseRevokedUserSeat,
  reserveReactivatedUserSeat,
  revokeUserCryptoAccess,
} from '../shared/access-revocation';
import { sendEmail } from '../email/handler';
import { syncStripeSeats } from '../billing/handler';

// ─── Configuration ───────────────────────────────────────────────────────────

const USER_POOL_ID = process.env.USER_POOL_ID!;
const REGION = process.env.AWS_REGION || 'eu-west-1';
// Required env var — fail loud rather than silently fall back to a name that
// might not match the deployed table. See auth/handler.ts for the full story.
const REVOKED_KEYS_TABLE = process.env.REVOKED_KEYS_TABLE!;

const cognitoClient = new CognitoIdentityProviderClient({ region: REGION });

// Valid roles that map to Cognito groups
const VALID_ROLES = ['admin', 'editor', 'viewer'] as const;
type UserRole = typeof VALID_ROLES[number];

type ResolvedTargetUser = {
  requestedUserId: string;
  username: string;
  subjectId: string;
  user: AdminGetUserCommandOutput;
  attributes: Record<string, string>;
};

/**
 * Best-effort server-side Stripe seat sync after a user mutation. Never throws:
 * a Stripe outage or DynamoDB hiccup logs to CloudWatch but does not fail the
 * parent user mutation. Free-tier orgs (no stripeSubscriptionId) are skipped
 * silently by the underlying helper.
 *
 * Awaited (not fire-and-forget) so the Lambda execution context stays warm
 * long enough for the Stripe HTTP request to complete.
 */
async function bestEffortSeatSync(orgId: string): Promise<void> {
  try {
    const result = await syncStripeSeats(orgId);
    if (result.synced) {
      console.log('[SEAT_SYNC]', { orgId, quantity: result.quantity, currentUsers: result.currentUsers });
    }
  } catch (err) {
    // Best-effort: never fail a user mutation on Stripe outage.
    console.error('[SEAT_SYNC_FAILURE]', orgId, (err as Error).message);
  }
}

function isConditionalCheckFailure(error: unknown): boolean {
  return (error as { name?: string })?.name === 'ConditionalCheckFailedException';
}

async function consumeAdminActionRateLimit(params: {
  action: 'invite' | 'resend';
  orgId: string;
  adminUserId: string;
  scope?: string;
  windowMs: number;
  limit: number;
}): Promise<boolean> {
  const windowStart = Math.floor(Date.now() / params.windowMs) * params.windowMs;
  const sessionId = [
    'admin-action-rate',
    params.action,
    params.orgId,
    params.adminUserId,
    (params.scope || 'all').trim().toLowerCase(),
    String(windowStart),
  ].join('#');
  try {
    await docClient.send(new UpdateCommand({
      TableName: SESSIONS_TABLE,
      Key: { sessionId },
      UpdateExpression: 'SET expiresAtTtl = :ttl, recordType = :recordType ADD requestCount :one',
      ConditionExpression: 'attribute_not_exists(requestCount) OR requestCount < :limit',
      ExpressionAttributeValues: {
        ':ttl': Math.ceil((windowStart + params.windowMs * 2) / 1000),
        ':recordType': 'admin-action-rate-limit',
        ':one': 1,
        ':limit': params.limit,
      },
    }));
    return true;
  } catch (error) {
    if (isConditionalCheckFailure(error)) return false;
    throw error;
  }
}

/**
 * Atomically reserves one org seat before Cognito provisioning. The temporary
 * token makes compensation idempotent: only the request that owns the token
 * can release the reservation, and a repeated release cannot decrement twice.
 */
async function reserveInviteSeat(org: OrgRecord, token: string): Promise<boolean> {
  try {
    await docClient.send(new UpdateCommand({
      TableName: ORGANIZATIONS_TABLE,
      Key: { slug: org.slug },
      UpdateExpression: 'SET updatedAt = :now ADD currentUsers :one, activeSeatReservations :tokens',
      ConditionExpression: [
        'attribute_exists(slug)',
        'attribute_exists(currentUsers)',
        'attribute_exists(maxUsers)',
        '(maxUsers < :zero OR currentUsers < maxUsers)',
        '(attribute_not_exists(activeSeatReservations) OR NOT contains(activeSeatReservations, :token))',
      ].join(' AND '),
      ExpressionAttributeValues: {
        ':now': new Date().toISOString(),
        ':one': 1,
        ':zero': 0,
        ':tokens': new Set([token]),
        ':token': token,
      },
    }));
    return true;
  } catch (error) {
    if (isConditionalCheckFailure(error)) return false;
    throw error;
  }
}

async function commitInviteSeatReservation(org: OrgRecord, token: string): Promise<void> {
  await docClient.send(new UpdateCommand({
    TableName: ORGANIZATIONS_TABLE,
    Key: { slug: org.slug },
    UpdateExpression: 'SET updatedAt = :now DELETE activeSeatReservations :tokens',
    ConditionExpression: 'contains(activeSeatReservations, :token)',
    ExpressionAttributeValues: {
      ':now': new Date().toISOString(),
      ':tokens': new Set([token]),
      ':token': token,
    },
  }));
}

async function releaseInviteSeatReservation(org: OrgRecord, token: string): Promise<void> {
  try {
    await docClient.send(new UpdateCommand({
      TableName: ORGANIZATIONS_TABLE,
      Key: { slug: org.slug },
      UpdateExpression: 'SET updatedAt = :now ADD currentUsers :minusOne DELETE activeSeatReservations :tokens',
      ConditionExpression: 'currentUsers > :zero AND contains(activeSeatReservations, :token)',
      ExpressionAttributeValues: {
        ':now': new Date().toISOString(),
        ':minusOne': -1,
        ':zero': 0,
        ':tokens': new Set([token]),
        ':token': token,
      },
    }));
  } catch (error) {
    // A missing token means this exact reservation was already released.
    if (!isConditionalCheckFailure(error)) throw error;
  }
}

function requiredCognitoSubjectId(
  attributes: Array<{ Name?: string; Value?: string }> | undefined
): string {
  const subjectId = attributes?.find((attribute) => attribute.Name === 'sub')?.Value?.trim();
  if (!subjectId) {
    throw new Error('Cognito user is missing the required sub attribute');
  }
  return subjectId;
}

type RevocationMarker = {
  userId: string;
  revokedAt?: string;
  revokedBy?: string;
  reason?: string;
  transitionState?: 'revoking' | 'revoked' | 'reactivating';
  transitionId?: string;
};

async function getRevocationMarker(subjectId: string): Promise<RevocationMarker | undefined> {
  const result = await docClient.send(new GetCommand({
    TableName: REVOKED_KEYS_TABLE,
    Key: { userId: subjectId },
  }));
  return result.Item as RevocationMarker | undefined;
}

async function claimRevocationTransition(params: {
  subjectId: string;
  adminUserId: string;
  transitionId: string;
  revokedAt: string;
}): Promise<boolean> {
  try {
    await docClient.send(new PutCommand({
      TableName: REVOKED_KEYS_TABLE,
      Item: {
        userId: params.subjectId,
        revokedAt: params.revokedAt,
        revokedBy: params.adminUserId,
        reason: 'admin_user_revoked',
        transitionState: 'revoking',
        transitionId: params.transitionId,
      },
      ConditionExpression: 'attribute_not_exists(userId)',
    }));
    return true;
  } catch (error) {
    if (isConditionalCheckFailure(error)) return false;
    throw error;
  }
}

async function claimReactivationTransition(
  subjectId: string,
  transitionId: string
): Promise<boolean> {
  try {
    await docClient.send(new UpdateCommand({
      TableName: REVOKED_KEYS_TABLE,
      Key: { userId: subjectId },
      UpdateExpression: 'SET transitionState = :reactivating, transitionId = :transitionId, reactivationStartedAt = :now',
      ConditionExpression: 'attribute_exists(userId) AND (attribute_not_exists(transitionState) OR transitionState = :revoked)',
      ExpressionAttributeValues: {
        ':reactivating': 'reactivating',
        ':revoked': 'revoked',
        ':transitionId': transitionId,
        ':now': new Date().toISOString(),
      },
    }));
    return true;
  } catch (error) {
    if (isConditionalCheckFailure(error)) return false;
    throw error;
  }
}

async function restoreRevocationMarker(params: {
  subjectId: string;
  adminUserId: string;
  revokedAt: string;
  reason: string;
}): Promise<void> {
  await docClient.send(new PutCommand({
    TableName: REVOKED_KEYS_TABLE,
    Item: {
      userId: params.subjectId,
      revokedAt: params.revokedAt,
      revokedBy: params.adminUserId,
      reason: params.reason,
      transitionState: 'revoked',
    },
  }));
}

// ─── Main Handler ────────────────────────────────────────────────────────────

export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId || generateId();
  const method = event.httpMethod?.toUpperCase();
  const route = resolveUsersRouteContext(event);
  const path = route.path;
  const action = route.action;

  try {
    // All user management endpoints require admin privileges
    const user = await verifyActiveUser(event);
    const orgId = requireOrgId(user);
    if (!isAdmin(user)) {
      await logAudit({
        userId: user.userId,
        userEmail: user.email,
        orgId,
        action: 'admin.access.denied',
        resourcePath: path,
        outcome: 'denied',
        ipAddress: getClientIp(event),
        userAgent: getUserAgent(event),
        metadata: { reason: 'insufficient_privileges' },
      });
      return formatError(403, 'Admin privileges required', requestId);
    }

    switch (true) {
      case method === 'GET' && path === '/users':
        return await handleListUsers(event, user, requestId);

      case method === 'GET' && path === '/users/roles':
        return await handleListRoles(event, user, requestId);

      case method === 'POST' && path === '/users/invite':
        return await handleInviteUser(event, user, requestId);

      case method === 'PUT' && action === 'role':
        return await handleUpdateRole(event, user, requestId, route);

      case method === 'PUT' && action === 'profile':
        return await handleUpdateProfile(event, user, requestId, route);

      case method === 'POST' && action === 'revoke':
        return await handleRevokeUser(event, user, requestId, route);

      case method === 'POST' && action === 'reactivate':
        return await handleReactivateUser(event, user, requestId, route);

      case method === 'POST' && action === 'resend-invite':
        return await handleResendInvite(event, user, requestId, route);

      case method === 'GET' && action === 'activity':
        return await handleGetActivity(event, user, requestId, route);

      case method === 'POST' && action === 'reset-mfa':
        return await handleResetMfa(event, user, requestId, route);

      case method === 'GET' && /^\/orgs\/[^/]+\/settings$/.test(path):
        return await handleGetOrgSettings(event, user, requestId, route);

      case method === 'PUT' && /^\/orgs\/[^/]+\/settings$/.test(path):
        return await handleUpdateOrgSettings(event, user, requestId, route);

      case method === 'DELETE' && /^\/orgs\/[^/]+\/settings$/.test(path):
        return await handleResetOrgSettings(event, user, requestId, route);

      default:
        return formatError(404, `Route not found: ${method} ${path}`, requestId);
    }
  } catch (err) {
    if (err instanceof AuthError) {
      return formatError(err.statusCode, err.message, requestId, err.code);
    }
    if (err instanceof ValidationError) {
      return formatError(err.statusCode, err.message, requestId);
    }

    // Cognito "User does not exist" — return 404 instead of 500
    const errName = (err as { name?: string }).name;
    if (errName === 'UserNotFoundException' || errName === 'ResourceNotFoundException') {
      return formatError(404, 'User not found', requestId);
    }

    console.error('[USERS_HANDLER_ERROR]', (err as Error).message);
    return formatError(500, 'Internal server error', requestId);
  }
}

// ─── GET /users/roles ──────────────────────────────────────────────────────

async function handleListRoles(
  event: APIGatewayProxyEvent,
  admin: UserContext,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const roles = VALID_ROLES.map((role) => ({
    id: role,
    name: role,
    type: 'role' as const,
    description: role === 'admin'
      ? 'Full administrative access'
      : role === 'editor'
        ? 'Read and write access'
        : 'Read-only access',
  }));

  await logAudit({
    userId: admin.userId,
    userEmail: admin.email,
    orgId: admin.orgId,
    action: 'admin.list_roles',
    resourcePath: '/users/roles',
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: { roleCount: roles.length },
  });

  return formatSuccess(200, roles, requestId);
}

// ─── GET /users ─────────────────────────────────────────────────────────────

async function handleListUsers(
  event: APIGatewayProxyEvent,
  admin: UserContext,
  requestId: string
): Promise<APIGatewayProxyResult> {
  // List all users then filter by org — Cognito ListUsers does not support
  // filtering on custom attributes, so we filter in code. LA3: the pool is
  // shared across all orgs, so a single 60-user page silently truncates an
  // org's member list once the pool exceeds 60 users pool-wide (member
  // visibility became a function of pool ordering, not org size). Page through
  // ALL users before filtering, mirroring findCognitoUsernameBySub.
  const allUsers: NonNullable<ListUsersCommandOutput['Users']> = [];
  let paginationToken: string | undefined;
  do {
    const listResult: ListUsersCommandOutput = await cognitoClient.send(
      new ListUsersCommand({
        UserPoolId: USER_POOL_ID,
        Limit: 60,
        PaginationToken: paginationToken,
      })
    );
    allUsers.push(...(listResult.Users || []));
    paginationToken = listResult.PaginationToken;
  } while (paginationToken);

  const orgUsers = allUsers.filter((u) => {
    const orgAttr = (u.Attributes || []).find((a) => a.Name === 'custom:org');
    return orgAttr?.Value === admin.orgId;
  });

  // DR-1: guest state is computed HERE, server-side, org-wide — not by either client
  // and not from whichever vault a client happens to have open. A guest scoped to any
  // vault in the org must be identified, so the membership fetch is org-scoped by
  // construction: one Query for the org's vaults, then one Query per vault.
  //
  // The per-user membership GSI is deliberately NOT used here: its rows carry no orgId
  // (it is org-blind, RESEARCH assumption A3) and it would cost one round trip per user.
  // This shape costs 1 + N_vaults Queries regardless of how many users the org has.
  //
  // One clock for the entire response. Re-reading the clock per user would let two users
  // in the same payload straddle an expiry boundary and disagree about the same instant.
  const nowMs = Date.now();
  const orgVaults = (await listVaultsForOrg(admin.orgId)).filter((vault) => !vault.archived);
  const vaultMemberships = await Promise.all(
    orgVaults.map((vault) => listVaultMembers(vault.vaultId))
  );
  const membershipsByUser = new Map<string, VaultMemberRecord[]>();
  for (const rows of vaultMemberships) {
    for (const row of rows) {
      const existing = membershipsByUser.get(row.userId);
      if (existing) {
        existing.push(row);
      } else {
        membershipsByUser.set(row.userId, [row]);
      }
    }
  }

  const users = await Promise.all(
    orgUsers.map(async (cognitoUser) => {
      const userId = cognitoUser.Username!;
      const attrs = Object.fromEntries(
        (cognitoUser.Attributes || []).map((a) => [a.Name, a.Value])
      );

      // Get user's groups (roles) and MFA status in parallel
      const [groupsResult, userDetail] = await Promise.all([
        cognitoClient.send(
          new AdminListGroupsForUserCommand({
            UserPoolId: USER_POOL_ID,
            Username: userId,
          })
        ),
        cognitoClient.send(
          new AdminGetUserCommand({
            UserPoolId: USER_POOL_ID,
            Username: userId,
          })
        ),
      ]);
      const groups = (groupsResult.Groups || []).map((g) => g.GroupName!);
      const role = resolveRole(groups);

      // UserMFASettingList contains active MFA methods (e.g. "SOFTWARE_TOKEN_MFA")
      const mfaMethods = userDetail.UserMFASettingList || [];
      const mfaEnabled = mfaMethods.length > 0;
      const displayName = buildUserDisplayName(attrs, attrs['email'] || userId);

      // VaultMembers rows are keyed on the Cognito SUB, which is the same value `id`
      // below returns — NOT on `cognitoUser.Username`. In this pool the two frequently
      // differ, and keying on Username yields a join that is silently empty: every
      // active guest would render as an ordinary viewer with no error anywhere.
      const subjectId = attrs['sub'] || userId;
      const guestSummary = summarizeGuestAccess(membershipsByUser.get(subjectId) ?? [], nowMs);

      return {
        id: attrs['sub'] || userId,
        email: attrs['email'] || '',
        displayName,
        name: attrs['name'] || buildDisplayNameFromParts(attrs['given_name'], attrs['family_name']) || '',
        givenName: attrs['given_name'] || '',
        familyName: attrs['family_name'] || '',
        role,
        status: mapCognitoStatus(cognitoUser.Enabled ?? true, cognitoUser.UserStatus || ''),
        lastActive: cognitoUser.UserLastModifiedDate?.toISOString() || '',
        createdAt: cognitoUser.UserCreateDate?.toISOString() || '',
        mfaEnabled,
        deviceCount: 0,
        type: 'user' as const,
        // Both fields are OMITTED rather than set to a falsy value for a non-guest, so
        // the client's `accessKind !== 'guest'` test stays the whole decision and the 13
        // pre-existing fields are untouched for every user.
        ...(guestSummary.isGuest ? { accessKind: 'guest' as const } : {}),
        ...(guestSummary.expiresAt !== undefined ? { expiresAt: guestSummary.expiresAt } : {}),
      };
    })
  );

  const guestCount = users.filter((user) => user.accessKind === 'guest').length;

  await logAudit({
    userId: admin.userId,
    userEmail: admin.email,
    orgId: admin.orgId,
    action: 'admin.list_users',
    resourcePath: '/users',
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: { userCount: users.length, guestCount },
  });

  return formatSuccess(200, users, requestId);
}

// ─── POST /users/invite ─────────────────────────────────────────────────────

/**
 * ONE message and ONE status for BOTH the cross-org and the not-found outcome of
 * resolving an already-existing email. Splitting them (403 vs 404, or two
 * wordings) would turn this route into an existence oracle over the shared
 * Cognito pool: an admin could type any address and read from the status
 * whether it belongs to somebody else's organization. Disclosure *within* the
 * caller's own org is fine — they can already list it — which is why the copy
 * may point at the user list.
 *
 * The `GUEST_` prefix is historical: this and `GUEST_ATTACH_REVOKED_MESSAGE`
 * are now returned on the MEMBER collision path too, byte-identically and with
 * the same status. That is the point — the anti-oracle property has to hold
 * across both `accessKind`s, or an admin reads the answer off whichever route
 * still leaks it.
 */
const GUEST_ATTACH_UNRESOLVABLE_MESSAGE =
  'Guest access could not be granted to that email address. If they are already in your organization, grant access from the user list instead.';

const GUEST_ATTACH_REVOKED_MESSAGE =
  "This user's access is revoked. Reactivate them first, then extend their guest access.";

/**
 * The member-invite collision that resolves to a live colleague in the caller's
 * OWN organization. Safe to be specific: the caller can already see this person
 * in `GET /users`, so nothing is disclosed that a list call would not.
 *
 * Deliberately NOT an attach. A guest invite carries an explicit vault list and
 * an expiry, so attaching is a bounded, requested grant; a member invite says
 * "create this person", and silently resolving it to somebody who already
 * exists would report a creation that never happened and could re-grant access
 * an admin had trimmed.
 */
const MEMBER_INVITE_EXISTS_MESSAGE =
  'That person already has an account in your organization. Grant them vault access from the user list instead of inviting them again.';

async function handleInviteUser(
  event: APIGatewayProxyEvent,
  admin: UserContext,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const body = parseBody(event);
  validateRequiredFields(body, ['email', 'role']);

  const email = (body.email as string).trim().toLowerCase();
  const requestedRole = body.role as string;
  const accessKind = body.accessKind === undefined ? 'member' : body.accessKind;
  if (accessKind !== 'member' && accessKind !== 'guest') {
    throw new ValidationError('accessKind must be either member or guest');
  }
  if (accessKind === 'guest' && requestedRole !== 'viewer') {
    throw new ValidationError('Guests are viewer-only');
  }
  const role = accessKind === 'guest' ? 'viewer' : requestedRole;
  const sendWelcomeEmail = body.sendWelcomeEmail !== false;
  const givenName = normalizeOptionalProfileField(
    getOptionalStringField(body, ['givenName', 'firstName']),
    'Name',
    64
  );
  const familyName = normalizeOptionalProfileField(
    getOptionalStringField(body, ['familyName', 'lastName', 'surname']),
    'Surname',
    64
  );
  const displayName = normalizeOptionalProfileField(
    getOptionalStringField(body, ['displayName']),
    'Display name',
    128
  ) || buildDisplayNameFromParts(givenName, familyName);

  if (!VALID_ROLES.includes(role as UserRole)) {
    throw new ValidationError(`Invalid role: ${role}. Must be one of: ${VALID_ROLES.join(', ')}`);
  }

  if (!email.includes('@')) {
    throw new ValidationError('Invalid email address');
  }

  let guestVaults: VaultRecord[] = [];
  let guestExpiresAt: string | undefined;
  if (accessKind === 'guest') {
    try {
      const expiresInDays = body.expiresInDays === undefined
        ? DEFAULT_GUEST_ACCESS_DAYS
        : body.expiresInDays;
      if (typeof expiresInDays !== 'number') {
        throw new RangeError('Guest access duration must be a number of whole days.');
      }
      guestExpiresAt = guestAccessExpiresAt(expiresInDays);
    } catch (error) {
      throw new ValidationError((error as Error).message);
    }
  }

  // User limit enforcement — always scoped to authenticated admin's org
  const orgCheck = await getActiveOrg(admin.orgId);
  if (!orgCheck.allowed) {
    return formatError(403, orgCheck.reason || 'Organization access denied', requestId);
  }
  if (!orgCheck.org) {
    return formatError(403, 'Organization access denied', requestId);
  }
  const org = orgCheck.org;
  const orgSettings = buildOrgSettings(admin.orgId, org);
  if (!isEmailAllowedForOrg(email, orgSettings)) {
    throw new ValidationError(
      `Invitations are restricted to these domains: ${orgSettings.allowedDomains.join(', ')}`
    );
  }

  if (accessKind === 'guest') {
    let requestedVaultIds: string[];
    try {
      requestedVaultIds = normalizeGuestVaultIds(body.vaultIds);
    } catch (error) {
      throw new ValidationError((error as Error).message);
    }
    const activeVaults = (await listVaultsForOrg(admin.orgId))
      .filter((vault) => !vault.archived);
    const byId = new Map(activeVaults.map((vault) => [vault.vaultId, vault]));
    const invalidVaultIds = requestedVaultIds.filter((vaultId) => !byId.has(vaultId));
    if (invalidVaultIds.length > 0) {
      throw new ValidationError(
        `Guest vaults must be active vaults in this organization: ${invalidVaultIds.join(', ')}`
      );
    }
    guestVaults = requestedVaultIds.map((vaultId) => byId.get(vaultId)!);
  }

  if (!await consumeAdminActionRateLimit({
    action: 'invite',
    orgId: admin.orgId,
    adminUserId: admin.userId,
    windowMs: 15 * 60 * 1000,
    limit: 20,
  })) {
    return formatError(429, 'Too many invitations. Wait before inviting more users.', requestId);
  }

  // Ensure the role group exists in Cognito
  assertNotReservedGroup(role);
  await ensureGroupExists(role);

  const seatReservationToken = `${requestId}:${email}:${generateId()}`;
  if (!await reserveInviteSeat(org, seatReservationToken)) {
    return formatError(
      402,
      `User limit reached (${org.currentUsers}/${org.maxUsers}). Upgrade your plan to add more users.`,
      requestId
    );
  }

  // Create user in Cognito — org is ALWAYS taken from authenticated admin context.
  // ALWAYS suppress Cognito's default email (which sends from no-reply@verificationemail.com
  // with the temp password in plaintext). We send our own branded email instead.
  let cognitoUsername: string | undefined;
  let userId: string;
  let attachedToExistingIdentity = false;
  try {
    const createResult = await cognitoClient.send(
      new AdminCreateUserCommand({
        UserPoolId: USER_POOL_ID,
        Username: email,
        UserAttributes: [
          { Name: 'email', Value: email },
          { Name: 'email_verified', Value: 'true' },
          ...(displayName ? [{ Name: 'name', Value: displayName }] : []),
          ...(givenName ? [{ Name: 'given_name', Value: givenName }] : []),
          ...(familyName ? [{ Name: 'family_name', Value: familyName }] : []),
          { Name: 'custom:role', Value: role },
          { Name: 'custom:org', Value: admin.orgId },
        ],
        MessageAction: MessageActionType.SUPPRESS,
      })
    );

    cognitoUsername = createResult.User?.Username;
    if (!cognitoUsername) {
      throw new Error('Cognito did not return a username for the invited user');
    }

    let subjectAttributes = createResult.User?.Attributes;
    if (!subjectAttributes?.some((attribute) => attribute.Name === 'sub' && attribute.Value)) {
      const createdUser = await getCognitoUserByUsername(cognitoUsername);
      subjectAttributes = createdUser.UserAttributes;
    }
    userId = requiredCognitoSubjectId(subjectAttributes);

    // Cognito APIs require Username, while every VaultGuard identity row and
    // response uses the immutable JWT subject.
    await cognitoClient.send(
      new AdminAddUserToGroupCommand({
        UserPoolId: USER_POOL_ID,
        Username: cognitoUsername,
        GroupName: role,
      })
    );
  } catch (error) {
    // CONTEXT.md DR-7 — a colleague who already has an account can be given
    // temporary access to one more vault. Fires for ANY invite whose identity
    // already exists; every other error still falls through to the
    // compensation below and rethrows.
    //
    // The member path used to be excluded from this branch, which meant an
    // `UsernameExistsException` on a member invite rethrew into the top-level
    // catch and came back as a bare 500 "Internal server error" — the exact
    // wall a sole admin hits when trying to recover an org by re-inviting
    // somebody who already exists. It now resolves the collision the same way
    // the guest path does and then diverges on the OUTCOME: a guest invite
    // attaches, a member invite refuses with an actionable 409.
    //
    // Nothing here creates, deletes, re-enables, re-groups or re-profiles an
    // identity: no AdminAddUserToGroup (it would put an existing editor in two
    // groups and let resolveRole change their org role), no
    // AdminUpdateUserAttributes (an invite form must not rewrite a colleague's
    // profile), no AdminDeleteUser. Only membership rows are added, by the
    // seeding call further down, whose conditional writes already refuse to
    // overwrite a permanent membership.
    if ((error as { name?: string }).name === 'UsernameExistsException') {
      let resolved: ResolvedTargetUser;
      try {
        resolved = await resolveTargetUserForOrg(
          email,
          admin.orgId,
          GUEST_ATTACH_UNRESOLVABLE_MESSAGE
        );
      } catch (resolveError) {
        await releaseInviteSeatReservation(org, seatReservationToken).catch((releaseError) => {
          console.error('[USERS_INVITE_COMPENSATION_SEAT_FAILED]', {
            orgId: admin.orgId,
            seatReservationToken,
            error: (releaseError as Error).message,
          });
        });
        // Both the foreign-org rejection and the unresolvable address collapse
        // into the same response. Anything else is an infrastructure failure
        // and must keep its own error.
        if (resolveError instanceof AuthError) {
          return formatError(404, GUEST_ATTACH_UNRESOLVABLE_MESSAGE, requestId);
        }
        throw resolveError;
      }

      const revocationMarker = await getRevocationMarker(resolved.subjectId);
      if (resolved.user.Enabled === false || revocationMarker) {
        // Attaching to a blanket-403'd identity would report success and
        // deliver nothing, and silently re-enabling one here would let an
        // invite undo a deliberate revoke. Point at the explicit flow instead.
        await releaseInviteSeatReservation(org, seatReservationToken).catch((releaseError) => {
          console.error('[USERS_INVITE_COMPENSATION_SEAT_FAILED]', {
            orgId: admin.orgId,
            seatReservationToken,
            error: (releaseError as Error).message,
          });
        });
        return formatError(409, GUEST_ATTACH_REVOKED_MESSAGE, requestId);
      }

      // The member path diverges HERE and nowhere earlier, so the two refusal
      // outcomes above — unresolvable/foreign-org and revoked — stay
      // byte-identical across both `accessKind`s. Anything that split them
      // would hand an admin an existence oracle on whichever route still
      // answered differently.
      //
      // The seat release is load-bearing on this return exactly as it is on the
      // two above: the reservation was taken before AdminCreateUser and nothing
      // downstream will commit or release it once we return from inside the
      // catch, so skipping it leaks a seat on every collided member invite.
      if (accessKind === 'member') {
        await releaseInviteSeatReservation(org, seatReservationToken).catch((releaseError) => {
          console.error('[USERS_INVITE_COMPENSATION_SEAT_FAILED]', {
            orgId: admin.orgId,
            seatReservationToken,
            error: (releaseError as Error).message,
          });
        });
        return formatError(409, MEMBER_INVITE_EXISTS_MESSAGE, requestId);
      }

      // No new identity means no new seat.
      await releaseInviteSeatReservation(org, seatReservationToken);
      userId = resolved.subjectId;
      attachedToExistingIdentity = true;
    } else {
      // cognitoUsername is still undefined when AdminCreateUser itself threw,
      // so a name collision never reaches AdminDeleteUser. That ordering is
      // load-bearing — keep it.
      if (cognitoUsername) {
        await cognitoClient.send(new AdminDeleteUserCommand({
          UserPoolId: USER_POOL_ID,
          Username: cognitoUsername,
        })).catch((deleteError) => {
          console.error('[USERS_INVITE_COMPENSATION_DELETE_FAILED]', {
            orgId: admin.orgId,
            cognitoUsername,
            error: (deleteError as Error).message,
          });
        });
      }
      await releaseInviteSeatReservation(org, seatReservationToken).catch((releaseError) => {
        console.error('[USERS_INVITE_COMPENSATION_SEAT_FAILED]', {
          orgId: admin.orgId,
          seatReservationToken,
          error: (releaseError as Error).message,
        });
      });
      throw error;
    }
  }

  // The reservation is already released on the attach path — committing it
  // would fail its own contains() condition and log a spurious error.
  if (!attachedToExistingIdentity) {
    await commitInviteSeatReservation(org, seatReservationToken).catch((error) => {
      // The user and the count are already correct. A stale reservation token
      // cannot release itself and is safe to reconcile out-of-band.
      console.error('[USERS_INVITE_RESERVATION_CLEANUP_FAILED]', {
        orgId: admin.orgId,
        seatReservationToken,
        error: (error as Error).message,
      });
    });
  }
  await bestEffortSeatSync(admin.orgId);

  // Seed baseline vault membership + /** allow rule for non-admin invites.
  // Admin-role invites are skipped: the inviting admin chooses which vaults to
  // attach them to manually. See CLAUDE.md vault-scoping rule — every rule
  // created here is per-vault, never org-wide.
  let bootstrap: { vaultsJoined: number; failures: number } | null = null;
  if (accessKind === 'guest') {
    try {
      // This is the only place in the codebase that knows whether the rows
      // about to be written belong to an identity the invite created or to one
      // that already existed, which is why the origin has to be decided here.
      // 17-09's sweeper reads it back through summarizeGuestAccess and
      // restrains instead of disabling when an attached grant lapses.
      bootstrap = await seedGuestVaultMembershipsForInvitee(
        admin.orgId,
        userId,
        guestVaults,
        guestExpiresAt!,
        admin.userId,
        attachedToExistingIdentity ? GUEST_ORIGIN_ATTACHED : GUEST_ORIGIN_INVITE
      );
    } catch (bootstrapErr) {
      bootstrap = { vaultsJoined: 0, failures: guestVaults.length };
      console.error(
        `[VaultGuard] Guest vault-membership bootstrap failed after successful invite`,
        { orgId: admin.orgId, newUserId: userId, error: bootstrapErr }
      );
    }
    if (bootstrap.failures > 0) {
      await logAudit({
        userId: admin.userId,
        userEmail: admin.email,
        orgId: admin.orgId,
        action: 'admin.user_invite_bootstrap_partial',
        resourcePath: `/users/${userId}`,
        outcome: 'error',
        ipAddress: getClientIp(event),
        userAgent: getUserAgent(event),
        metadata: {
          invitedEmail: email,
          role,
          accessKind,
          vaultsRequested: guestVaults.length,
          vaultsJoined: bootstrap.vaultsJoined,
          failures: bootstrap.failures,
        },
      });
    }
  } else if (role === 'editor' || role === 'viewer') {
    try {
      bootstrap = await seedDefaultVaultMembershipForInvitee(
        admin.orgId,
        userId,
        role,
        admin.userId
      );
      if (bootstrap.failures > 0) {
        await logAudit({
          userId: admin.userId,
          userEmail: admin.email,
          orgId: admin.orgId,
          action: 'admin.user_invite_bootstrap_partial',
          resourcePath: `/users/${userId}`,
          // The `outcome` enum doesn't include 'partial'; we mark it 'error'
          // so it stands out in audit filters, and the metadata distinguishes
          // partial from total failure via the (vaultsJoined, failures) pair.
          outcome: 'error',
          ipAddress: getClientIp(event),
          userAgent: getUserAgent(event),
          metadata: {
            invitedEmail: email,
            role,
            vaultsJoined: bootstrap.vaultsJoined,
            failures: bootstrap.failures,
          },
        });
      }
    } catch (bootstrapErr) {
      // Non-fatal: invite already succeeded. Log so admin can investigate.
      console.error(
        `[VaultGuard] Vault-membership bootstrap failed after successful invite`,
        { orgId: admin.orgId, newUserId: userId, error: bootstrapErr }
      );
    }
  }

  const guestProvisioningStatus = accessKind === 'guest'
    ? bootstrap && bootstrap.failures === 0
      ? 'complete'
      : bootstrap && bootstrap.vaultsJoined > 0
        ? 'partial'
        : 'failed'
    : undefined;

  // Our own branded invitation email (no plaintext password — the user sets one
  // via the "Forgot Password" flow in the plugin on first login). It is sent
  // AFTER provisioning so an invitation never announces access that does not
  // exist: a guest invite whose vault seeding failed completely sends nothing.
  // A 'partial' guest still gets it — they do have access to something — and
  // every member invite is unaffected, because the status is undefined for them.
  //
  // It is also suppressed when the grant was attached to somebody who already
  // has an account: the template tells the recipient to use "Forgot Password",
  // which to an existing user reads as a password-reset phishing prompt.
  const invitationEmailSent = sendWelcomeEmail
    && !attachedToExistingIdentity
    && guestProvisioningStatus !== 'failed';
  if (invitationEmailSent) {
    const orgName = org.name || admin.orgId;
    const orgSlug = org.slug;
    const inviterName = admin.email;
    await sendEmail('invitation', {
      email,
      orgName,
      orgSlug,
      inviterName,
      username: email,
    }, { throwOnError: true });
  }

  await logAudit({
    userId: admin.userId,
    userEmail: admin.email,
    orgId: admin.orgId,
    action: 'admin.user_invited',
    resourcePath: `/users/${userId}`,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: {
      invitedEmail: email,
      role,
      accessKind,
      sendWelcomeEmail,
      invitationEmailSent,
      attachedToExistingIdentity,
      ...(guestExpiresAt ? { expiresAt: guestExpiresAt } : {}),
      ...(accessKind === 'guest' ? { vaultIds: guestVaults.map((vault) => vault.vaultId) } : {}),
      ...(guestProvisioningStatus ? { provisioningStatus: guestProvisioningStatus } : {}),
      ...(displayName ? { displayName } : {}),
      ...(bootstrap ? { vaultsJoined: bootstrap.vaultsJoined, vaultBootstrapFailures: bootstrap.failures } : {}),
    },
  });

  // An attach is not an invitation, and saying so would be a lie the admin acts
  // on. The provisioning fields below keep reporting the real seeding outcome
  // either way, so "guest in 2 of 3 selected vaults because they are already an
  // editor of the third" still surfaces.
  const inviteMessage = attachedToExistingIdentity
    ? guestProvisioningStatus === 'partial'
      ? `${email} already has an account and was granted temporary access to some of the selected vaults`
      : guestProvisioningStatus === 'failed'
        ? `${email} already has an account, but temporary access to the selected vaults could not be provisioned`
        : `${email} already has an account and was granted temporary access to the selected vaults`
    : guestProvisioningStatus === 'partial'
      ? `User ${email} was invited, but access to some selected vaults could not be provisioned`
      : guestProvisioningStatus === 'failed'
        ? `User ${email} was invited, but selected-vault access could not be provisioned`
        : `User ${email} invited successfully`;

  return formatSuccess(201, {
    message: inviteMessage,
    userId,
    role,
    accessKind,
    ...(guestExpiresAt ? { expiresAt: guestExpiresAt } : {}),
    ...(accessKind === 'guest' ? { vaultIds: guestVaults.map((vault) => vault.vaultId) } : {}),
    ...(guestProvisioningStatus ? {
      provisioningStatus: guestProvisioningStatus,
      vaultsJoined: bootstrap?.vaultsJoined ?? 0,
      vaultProvisioningFailures: bootstrap?.failures ?? guestVaults.length,
    } : {}),
    // Emitted only on the attach path, so the ordinary invite response keeps
    // exactly the fields it had before.
    ...(attachedToExistingIdentity ? { attachedToExistingIdentity: true } : {}),
    displayName,
  }, requestId);
}

// ─── PUT /users/{userId}/role ───────────────────────────────────────────────

async function handleUpdateRole(
  event: APIGatewayProxyEvent,
  admin: UserContext,
  requestId: string,
  route: UsersRouteContext
): Promise<APIGatewayProxyResult> {
  const targetUserId = route.userId;
  if (!targetUserId) {
    throw new ValidationError('Missing userId path parameter');
  }

  const body = parseBody(event);
  validateRequiredFields(body, ['role']);

  const newRole = body.role as string;
  if (!VALID_ROLES.includes(newRole as UserRole)) {
    throw new ValidationError(`Invalid role: ${newRole}. Must be one of: ${VALID_ROLES.join(', ')}`);
  }

  const target = await resolveTargetUserForOrg(
    targetUserId,
    admin.orgId,
    'Cannot modify user from another organization'
  );

  // The milder half of the same hole as the revoke route: a sole admin who
  // demotes THEMSELVES leaves the organization with zero admins. They can still
  // sign in, but nobody can invite, revoke, re-role or manage anything ever
  // again, and there is no in-product lever that restores an admin.
  //
  // Compared on the RESOLVED subject for the same reason as there — the path
  // parameter may be a sub, a username or an email. Placed before the
  // guest-membership gate, `clearExpiredGuestRowsForPromotion` and every
  // Cognito group mutation, so a refused call writes nothing.
  //
  // Self→admin stays allowed: for an admin it is a no-op, and refusing it would
  // be pure noise on a request that changes nothing.
  //
  // Deliberately no `getActiveOrg` call here. This handler has never read the
  // org, the guard does not need it, and adding an org-status gate to a route
  // that never had one would be an unrelated behaviour change.
  if (target.subjectId === admin.userId && newRole !== 'admin') {
    throw new AuthError(
      'You cannot remove your own administrator access. Ask another organization admin to do it.',
      409,
      'self_demotion_forbidden'
    );
  }

  if (
    newRole !== 'viewer' &&
    await hasStoredGuestMembership([
      target.subjectId,
      target.username,
      target.requestedUserId,
    ])
  ) {
    throw new ValidationError(
      'Guest users are viewer-only. Remove their guest memberships and invite them as a member instead.'
    );
  }

  // ORDER IS LOAD-BEARING, NOT STYLISTIC. This runs BEFORE every Cognito
  // mutation below and its failure fails the whole request, which makes the
  // dangerous end state — promoted AND still holding lapsed temporary rows,
  // which the scheduled sweeper reads as fully expired and tears the account
  // down for — UNREACHABLE rather than merely reported. Running it afterwards
  // could only ever report that state after it already existed.
  //
  // The cost is the benign direction, accepted deliberately: the cleanup lands,
  // Cognito then fails, and the target remains a viewer minus rows that granted
  // nothing anyway (vault listing already filters lapsed rows out).
  //
  // A promotion to `viewer` is not a promotion — the gate above never fired, so
  // there is nothing to clean up and nothing is touched.
  const promotionCleanup = newRole === 'viewer'
    ? { membershipsDeleted: 0, permissionRulesDeleted: 0 }
    : await clearExpiredGuestRowsForPromotion([
        target.subjectId,
        target.username,
        target.requestedUserId,
      ]);

  // Get current groups and remove user from all role groups
  const currentGroups = await cognitoClient.send(
    new AdminListGroupsForUserCommand({
      UserPoolId: USER_POOL_ID,
      Username: target.username,
    })
  );

  const oldRole = resolveRole((currentGroups.Groups || []).map((g) => g.GroupName!));

  for (const group of currentGroups.Groups || []) {
    if (VALID_ROLES.includes(group.GroupName as UserRole)) {
      await cognitoClient.send(
        new AdminRemoveUserFromGroupCommand({
          UserPoolId: USER_POOL_ID,
          Username: target.username,
          GroupName: group.GroupName!,
        })
      );
    }
  }

  // Ensure the new role group exists and add user
  assertNotReservedGroup(newRole);
  await ensureGroupExists(newRole);
  await cognitoClient.send(
    new AdminAddUserToGroupCommand({
      UserPoolId: USER_POOL_ID,
      Username: target.username,
      GroupName: newRole,
    })
  );

  await logAudit({
    userId: admin.userId,
    userEmail: admin.email,
    orgId: admin.orgId,
    action: 'admin.role_changed',
    resourcePath: `/users/${targetUserId}/role`,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: {
      targetUserId: target.subjectId,
      targetUsername: target.username,
      oldRole,
      newRole,
      // Recorded on the EXISTING action rather than a new one: this is part of
      // the role change, not an event of its own.
      guestMembershipsDeleted: promotionCleanup.membershipsDeleted,
      guestPermissionRulesDeleted: promotionCleanup.permissionRulesDeleted,
    },
  });

  return formatSuccess(200, {
    message: `Role updated to ${newRole}`,
    userId: target.subjectId,
    role: newRole,
  }, requestId);
}

// ─── PUT /users/{userId}/profile ────────────────────────────────────────────

async function handleUpdateProfile(
  event: APIGatewayProxyEvent,
  admin: UserContext,
  requestId: string,
  route: UsersRouteContext
): Promise<APIGatewayProxyResult> {
  const targetUserId = route.userId;
  if (!targetUserId) {
    throw new ValidationError('Missing userId path parameter');
  }

  const body = parseBody(event);
  validateRequiredFields(body, ['displayName']);

  const displayName = (body.displayName as string).trim();
  if (displayName.length === 0) {
    throw new ValidationError('Display name cannot be empty');
  }
  if (displayName.length > 128) {
    throw new ValidationError('Display name must be 128 characters or fewer');
  }

  const target = await resolveTargetUserForOrg(
    targetUserId,
    admin.orgId,
    'Cannot modify user from another organization'
  );

  // Update the "name" attribute in Cognito (maps to displayName in our API)
  await cognitoClient.send(
    new AdminUpdateUserAttributesCommand({
      UserPoolId: USER_POOL_ID,
      Username: target.username,
      UserAttributes: [
        { Name: 'name', Value: displayName },
      ],
    })
  );

  await logAudit({
    userId: admin.userId,
    userEmail: admin.email,
    orgId: admin.orgId,
    action: 'admin.profile_updated',
    resourcePath: `/users/${targetUserId}/profile`,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: {
      targetUserId: target.subjectId,
      targetUsername: target.username,
      displayName,
    },
  });

  return formatSuccess(200, {
    message: `Display name updated to "${displayName}"`,
    userId: target.subjectId,
    displayName,
  }, requestId);
}

// ─── POST /users/{userId}/revoke ────────────────────────────────────────────

async function handleRevokeUser(
  event: APIGatewayProxyEvent,
  admin: UserContext,
  requestId: string,
  route: UsersRouteContext
): Promise<APIGatewayProxyResult> {
  const targetUserId = route.userId;
  if (!targetUserId) {
    throw new ValidationError('Missing userId path parameter');
  }

  const target = await resolveTargetUserForOrg(
    targetUserId,
    admin.orgId,
    'Cannot modify user from another organization'
  );

  // A sole org admin who revokes THEMSELVES bricks the organization. Cognito
  // refuses their next sign-in ("User is disabled"), `assertUserNotRevoked`
  // inside `verifyActiveUser` blanket-403s their very next request, and every
  // recovery lever needs something that no longer exists: reactivate needs an
  // admin session, a member re-invite collides on the identity, a guest
  // re-invite is refused as revoked, self-signup is refused as taken, and the
  // superadmin surface is read-only.
  //
  // A SELF-guard, not a headcount. Counting the remaining admins would need a
  // paginated Cognito ListUsers over the whole pool on every revoke, and would
  // still race two admins acting at once. With self-revoke blocked, revoking
  // the last admin is unreachable by construction: A can only revoke B, which
  // always leaves A behind.
  //
  // Compared on the RESOLVED subject, never on `targetUserId`:
  // `resolveTargetUserForOrg` above accepts a sub, a Cognito username OR an
  // email, so a raw-path-parameter comparison would be bypassed by addressing
  // yourself under any of the other two. Placed before the marker read, the
  // transition claim and every Cognito mutation, so a refused call changes
  // nothing at all.
  //
  // 409 rather than 403: the caller IS an org admin with full rights on this
  // route, so "you lack permission" would be false and would mislead the admin
  // panel into treating a policy refusal as a session failure. This is the same
  // shape as the 'revocation is already in progress' conflict below — a
  // well-formed, authorized request refused because of the target's state.
  if (target.subjectId === admin.userId) {
    throw new AuthError(
      'You cannot revoke your own access. Ask another organization admin to do it.',
      409,
      'self_revoke_forbidden'
    );
  }

  const existingMarker = await getRevocationMarker(target.subjectId);
  if (existingMarker) {
    if (target.user.Enabled !== false) {
      throw new AuthError('User revocation is already in progress', 409);
    }
    if (existingMarker.transitionState === 'reactivating') {
      throw new AuthError('User reactivation is already in progress', 409);
    }
    if (existingMarker.transitionState === 'revoked' || !existingMarker.transitionState) {
      return formatSuccess(200, {
        message: `Access is already revoked for user ${target.username}`,
        userId: target.subjectId,
        status: 'revoked',
        idempotent: true,
        revokedAt: existingMarker.revokedAt || null,
        reEncryptionJobId: null,
      }, requestId);
    }
  } else if (target.user.Enabled === false) {
    throw new AuthError('User is disabled without a VaultGuard revocation record', 409);
  }

  const currentGroups = await cognitoClient.send(
    new AdminListGroupsForUserCommand({
      UserPoolId: USER_POOL_ID,
      Username: target.username,
    })
  );
  const originalGroups = (currentGroups.Groups || [])
    .map((group) => group.GroupName)
    .filter((group): group is string => !!group);
  const transitionId = generateId();
  const revokedAt = existingMarker?.revokedAt || new Date().toISOString();
  if (!existingMarker && !await claimRevocationTransition({
    subjectId: target.subjectId,
    adminUserId: admin.userId,
    transitionId,
    revokedAt,
  })) {
    throw new AuthError('User revocation is already in progress', 409);
  }

  const orgResult = await getActiveOrg(admin.orgId);
  if (!orgResult.allowed || !orgResult.org) {
    if (!existingMarker) {
      await docClient.send(new DeleteCommand({
        TableName: REVOKED_KEYS_TABLE,
        Key: { userId: target.subjectId },
      }));
    }
    throw new AuthError(orgResult.reason || 'Organization access denied', 403);
  }

  let revocationCommitted = false;
  try {
    // Disable user in Cognito (prevents all sign-ins).
    await cognitoClient.send(
      new AdminDisableUserCommand({
        UserPoolId: USER_POOL_ID,
        Username: target.username,
      })
    );

    // Remove from all role groups.
    for (const group of originalGroups) {
      await cognitoClient.send(
        new AdminRemoveUserFromGroupCommand({
          UserPoolId: USER_POOL_ID,
          Username: target.username,
          GroupName: group,
        })
      );
    }

    await releaseRevokedUserSeat(orgResult.org, target.subjectId);
    revocationCommitted = true;

    const cryptoRevocation = await revokeUserCryptoAccess({
      targetUserId: target.subjectId,
      adminUserId: admin.userId,
      orgId: admin.orgId,
      reason: 'admin_user_revoked',
      revokedAt,
      // LD-4, stated EXPLICITLY rather than inherited from the default. An
      // admin offboarding a person is exactly the case org-wide re-encryption
      // exists for. The scheduled expiry sweeper passes `false` for the same
      // parameter, and the divergence between a human decision and a nightly
      // job should be legible at both call sites, not only at the one that
      // departs from the default.
      triggerReEncryption: true,
    });

    // DR-6 early revoke. Without this, an admin who ends someone's temporary
    // access early leaves rows that are NOT expired behind — so the expiry
    // sweeper never collects them, they keep the person badged as temporary,
    // and they keep jamming both the DR-3 promotion gate and the DR-4 reclaim.
    // The teardown itself is the SAME shared helper the sweeper uses.
    //
    // The membership delete is guarded on the row KIND rather than pinned to a
    // boundary, because the admin is deliberately overriding a boundary that
    // has not been reached. Selection is temporary rows only, so a revoke can
    // never strip a permanent member's vault records.
    //
    // Deliberately NON-FATAL, and deliberately last. The account is already
    // disabled, the marker written and the seat released; leaving rows behind
    // is strictly less harmful than failing the request and leaving an account
    // enabled, so a failure is recorded in the audit trail and moved past.
    let guestMembershipsDeleted = 0;
    let guestPermissionRulesDeleted = 0;
    let guestCleanupError: string | null = null;
    try {
      const guestRows = await listStoredGuestRows([
        target.subjectId,
        target.username,
        target.requestedUserId,
      ]);
      if (guestRows.length > 0) {
        const cleaned = await deleteGuestAccessRows(
          guestRows.map((row) => ({
            vaultId: row.vaultId,
            userId: row.userId,
            // Carried through unread by the kind guard; passing the row's own
            // value keeps the shape honest rather than synthesising one.
            expiresAt: row.expiresAt ?? '',
          })),
          { membershipGuard: 'kind' }
        );
        guestMembershipsDeleted = cleaned.membershipsDeleted;
        guestPermissionRulesDeleted = cleaned.permissionRulesDeleted;
      }
    } catch (cleanupError) {
      guestCleanupError = (cleanupError as Error).message;
      console.error('[USERS_REVOKE_GUEST_CLEANUP_FAILED]', {
        userId: target.subjectId,
        error: guestCleanupError,
      });
    }

    await bestEffortSeatSync(admin.orgId);

    await logAudit({
      userId: admin.userId,
      userEmail: admin.email,
      orgId: admin.orgId,
      action: 'admin.user_removed',
      resourcePath: `/users/${targetUserId}`,
      outcome: 'success',
      ipAddress: getClientIp(event),
      userAgent: getUserAgent(event),
      metadata: {
        targetUserId: target.subjectId,
        targetUsername: target.username,
        action: 'revoked',
        invalidatedSessions: cryptoRevocation.invalidatedSessions,
        revokedLeases: cryptoRevocation.revokedLeases,
        guestMembershipsDeleted,
        guestPermissionRulesDeleted,
        // Null on the happy path. Non-null is the only record that rows were
        // left behind, since the request still succeeded.
        guestCleanupError,
      },
    });

    return formatSuccess(200, {
      message: `Access revoked for user ${target.username}`,
      userId: target.subjectId,
      status: 'revoked',
      invalidatedSessions: cryptoRevocation.invalidatedSessions,
      revokedLeases: cryptoRevocation.revokedLeases,
      revokedAt: cryptoRevocation.revokedAt,
      reEncryptionJobId: cryptoRevocation.reEncryptionJobId,
    }, requestId);
  } catch (error) {
    if (!revocationCommitted) {
      // No crypto revocation has run yet, so the Cognito mutation is safely
      // compensatable. Restore the original groups and enabled state.
      for (const group of originalGroups) {
        await cognitoClient.send(new AdminAddUserToGroupCommand({
          UserPoolId: USER_POOL_ID,
          Username: target.username,
          GroupName: group,
        })).catch((rollbackError) => {
          console.error('[USERS_REVOKE_GROUP_ROLLBACK_FAILED]', {
            username: target.username,
            group,
            error: (rollbackError as Error).message,
          });
        });
      }
      await cognitoClient.send(new AdminEnableUserCommand({
        UserPoolId: USER_POOL_ID,
        Username: target.username,
      })).catch((rollbackError) => {
        console.error('[USERS_REVOKE_ENABLE_ROLLBACK_FAILED]', {
          username: target.username,
          error: (rollbackError as Error).message,
        });
      });
      if (!existingMarker) {
        await docClient.send(new DeleteCommand({
          TableName: REVOKED_KEYS_TABLE,
          Key: { userId: target.subjectId },
        })).catch((rollbackError) => {
          console.error('[USERS_REVOKE_MARKER_ROLLBACK_FAILED]', {
            userId: target.subjectId,
            error: (rollbackError as Error).message,
          });
        });
      }
    }
    throw error;
  }
}

// ─── POST /users/{userId}/reactivate ────────────────────────────────────────

async function handleReactivateUser(
  event: APIGatewayProxyEvent,
  admin: UserContext,
  requestId: string,
  route: UsersRouteContext
): Promise<APIGatewayProxyResult> {
  const targetUserId = route.userId;
  if (!targetUserId) {
    throw new ValidationError('Missing userId path parameter');
  }

  const target = await resolveTargetUserForOrg(
    targetUserId,
    admin.orgId,
    'Cannot modify user from another organization'
  );

  const body = parseBody(event);
  const role = (body.role as string) || 'viewer';

  if (!VALID_ROLES.includes(role as UserRole)) {
    throw new ValidationError(`Invalid role: ${role}. Must be one of: ${VALID_ROLES.join(', ')}`);
  }

  if (target.user.Enabled !== false) {
    throw new AuthError('Only a revoked user can be reactivated', 409);
  }
  if (
    role !== 'viewer' &&
    await hasStoredGuestMembership([
      target.subjectId,
      target.username,
      target.requestedUserId,
    ])
  ) {
    throw new ValidationError(
      'Guest users are viewer-only. Remove their guest memberships and invite them as a member instead.'
    );
  }

  // The SECOND promotion door, gated by the identical predicate above and
  // therefore carrying the identical hazard — a reactivate that names a
  // non-viewer role promotes just as surely as a role change does. Same shared
  // helper, same reason, same ordering: it runs before the seat reservation and
  // every Cognito mutation, so a failure here leaves nothing changed.
  //
  // Note the server-side default. A reactivate with no role in the body is a
  // viewer, which is not a promotion, so it cleans up nothing.
  const promotionCleanup = role === 'viewer'
    ? { membershipsDeleted: 0, permissionRulesDeleted: 0 }
    : await clearExpiredGuestRowsForPromotion([
        target.subjectId,
        target.username,
        target.requestedUserId,
      ]);

  const marker = await getRevocationMarker(target.subjectId);
  if (!marker || (marker.transitionState && marker.transitionState !== 'revoked')) {
    throw new AuthError('Only a fully revoked user can be reactivated', 409);
  }

  const orgResult = await getActiveOrg(admin.orgId);
  if (!orgResult.allowed || !orgResult.org) {
    throw new AuthError(orgResult.reason || 'Organization access denied', 403);
  }

  const transitionId = generateId();
  if (!await claimReactivationTransition(target.subjectId, transitionId)) {
    throw new AuthError('User reactivation is already in progress', 409);
  }

  // Backfill the idempotency set for users revoked before this seat-transition
  // protocol existed, then consume it atomically with the counter increment.
  let seatReserved = false;
  try {
    await ensureRevokedSeatIdentity(orgResult.org, target.subjectId);
    seatReserved = await reserveReactivatedUserSeat(orgResult.org, target.subjectId);
  } catch (error) {
    await releaseRevokedUserSeat(orgResult.org, target.subjectId).catch((rollbackError) => {
      console.error('[USERS_REACTIVATE_SEAT_UNCERTAIN_ROLLBACK_FAILED]', {
        userId: target.subjectId,
        error: (rollbackError as Error).message,
      });
    });
    await restoreRevocationMarker({
      subjectId: target.subjectId,
      adminUserId: marker.revokedBy || admin.userId,
      revokedAt: marker.revokedAt || new Date().toISOString(),
      reason: marker.reason || 'admin_user_revoked',
    });
    throw error;
  }
  if (!seatReserved) {
    await restoreRevocationMarker({
      subjectId: target.subjectId,
      adminUserId: marker.revokedBy || admin.userId,
      revokedAt: marker.revokedAt || new Date().toISOString(),
      reason: marker.reason || 'admin_user_revoked',
    });
    return formatError(
      402,
      `User limit reached (${orgResult.org.currentUsers}/${orgResult.org.maxUsers}). Upgrade your plan to add more users.`,
      requestId
    );
  }

  try {
    // Add back to a role group, using Cognito Username only at the Cognito API.
    assertNotReservedGroup(role);
    await ensureGroupExists(role);
    await cognitoClient.send(
      new AdminEnableUserCommand({
        UserPoolId: USER_POOL_ID,
        Username: target.username,
      })
    );
    await cognitoClient.send(
      new AdminAddUserToGroupCommand({
        UserPoolId: USER_POOL_ID,
        Username: target.username,
        GroupName: role,
      })
    );

    await docClient.send(
      new DeleteCommand({
        TableName: REVOKED_KEYS_TABLE,
        Key: { userId: target.subjectId },
        ConditionExpression: 'transitionState = :reactivating AND transitionId = :transitionId',
        ExpressionAttributeValues: {
          ':reactivating': 'reactivating',
          ':transitionId': transitionId,
        },
      })
    );
  } catch (error) {
    // Restore the revoked state and release the just-reserved seat. These
    // operations are themselves idempotent, so an uncertain SDK retry cannot
    // double-decrement the counter.
    await cognitoClient.send(new AdminRemoveUserFromGroupCommand({
      UserPoolId: USER_POOL_ID,
      Username: target.username,
      GroupName: role,
    })).catch((rollbackError) => {
      console.error('[USERS_REACTIVATE_GROUP_ROLLBACK_FAILED]', {
        username: target.username,
        role,
        error: (rollbackError as Error).message,
      });
    });
    await cognitoClient.send(new AdminDisableUserCommand({
      UserPoolId: USER_POOL_ID,
      Username: target.username,
    })).catch((rollbackError) => {
      console.error('[USERS_REACTIVATE_DISABLE_ROLLBACK_FAILED]', {
        username: target.username,
        error: (rollbackError as Error).message,
      });
    });
    await releaseRevokedUserSeat(orgResult.org, target.subjectId).catch((rollbackError) => {
      console.error('[USERS_REACTIVATE_SEAT_ROLLBACK_FAILED]', {
        userId: target.subjectId,
        error: (rollbackError as Error).message,
      });
    });
    await restoreRevocationMarker({
      subjectId: target.subjectId,
      adminUserId: marker.revokedBy || admin.userId,
      revokedAt: marker.revokedAt || new Date().toISOString(),
      reason: marker.reason || 'admin_user_revoked',
    }).catch((rollbackError) => {
      console.error('[USERS_REACTIVATE_MARKER_ROLLBACK_FAILED]', {
        userId: target.subjectId,
        error: (rollbackError as Error).message,
      });
    });
    throw error;
  }

  await bestEffortSeatSync(admin.orgId);

  await logAudit({
    userId: admin.userId,
    userEmail: admin.email,
    orgId: admin.orgId,
    action: 'admin.user_reactivated',
    resourcePath: `/users/${targetUserId}`,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: {
      targetUserId: target.subjectId,
      targetUsername: target.username,
      role,
      guestMembershipsDeleted: promotionCleanup.membershipsDeleted,
      guestPermissionRulesDeleted: promotionCleanup.permissionRulesDeleted,
    },
  });

  return formatSuccess(200, {
    message: `User ${target.username} reactivated with role ${role}`,
    userId: target.subjectId,
    status: 'active',
    role,
  }, requestId);
}

// ─── POST /users/{userId}/resend-invite ─────────────────────────────────────

async function handleResendInvite(
  event: APIGatewayProxyEvent,
  admin: UserContext,
  requestId: string,
  route: UsersRouteContext
): Promise<APIGatewayProxyResult> {
  const targetUserId = route.userId;
  if (!targetUserId) {
    throw new ValidationError('Missing userId path parameter');
  }

  const target = await resolveTargetUserForOrg(
    targetUserId,
    admin.orgId,
    'Cannot modify user from another organization'
  );

  // Only allow resend for pending (FORCE_CHANGE_PASSWORD) users
  const cognitoStatus = target.user.UserStatus || '';
  if (cognitoStatus !== 'FORCE_CHANGE_PASSWORD') {
    return formatError(400, 'Can only resend invitation for pending users', requestId);
  }

  const email = target.attributes['email'] || '';
  if (!email) {
    return formatError(400, 'User has no email address', requestId);
  }

  const actorAllowed = await consumeAdminActionRateLimit({
    action: 'resend',
    orgId: admin.orgId,
    adminUserId: admin.userId,
    windowMs: 15 * 60 * 1000,
    limit: 10,
  });
  const targetAllowed = actorAllowed && await consumeAdminActionRateLimit({
    action: 'resend',
    orgId: admin.orgId,
    adminUserId: admin.userId,
    scope: target.subjectId,
    windowMs: 5 * 60 * 1000,
    limit: 1,
  });
  if (!actorAllowed || !targetAllowed) {
    return formatError(429, 'Invitation was recently sent. Wait before resending.', requestId);
  }

  // Look up org name for the email
  const orgResult = await getActiveOrg(admin.orgId);
  const orgName = orgResult.org?.name as string || admin.orgId;
  const orgSlug = (orgResult.org?.slug as string) || '';

  await sendEmail('invitation', {
    email,
    orgName,
    orgSlug,
    inviterName: admin.email,
    username: email,
  }, { throwOnError: true });

  await logAudit({
    userId: admin.userId,
    userEmail: admin.email,
    orgId: admin.orgId,
    action: 'admin.invitation_resent',
    resourcePath: `/users/${targetUserId}/resend-invite`,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: {
      targetUserId: target.subjectId,
      targetUsername: target.username,
      targetEmail: email,
    },
  });

  return formatSuccess(200, {
    message: `Invitation resent to ${email}`,
    userId: target.subjectId,
  }, requestId);
}

// ─── GET /users/{userId}/activity ───────────────────────────────────────────

async function handleGetActivity(
  event: APIGatewayProxyEvent,
  admin: UserContext,
  requestId: string,
  route: UsersRouteContext
): Promise<APIGatewayProxyResult> {
  const targetUserId = route.userId;
  if (!targetUserId) {
    throw new ValidationError('Missing userId path parameter');
  }

  const target = await resolveTargetUserForOrg(
    targetUserId,
    admin.orgId,
    'Cannot view activity for user from another organization'
  );

  const limit = parseInt(event.queryStringParameters?.limit || '50', 10);

  const result = await docClient.send(
    new QueryCommand({
      TableName: AUDIT_TABLE,
      IndexName: 'userId-index',
      KeyConditionExpression: 'userId = :uid',
      FilterExpression: 'orgId = :orgId',
      ExpressionAttributeValues: { ':uid': target.subjectId, ':orgId': admin.orgId },
      Limit: limit,
      ScanIndexForward: false, // Most recent first
    })
  );

  const activities = (result.Items || []).map((item) => ({
    timestamp: item.timestamp as string,
    action: item.action as string,
    resourcePath: item.resourcePath as string,
    deviceInfo: item.userAgent as string || '',
  }));

  return formatSuccess(200, activities, requestId);
}

// ─── POST /users/{userId}/reset-mfa ─────────────────────────────────────────

/**
 * Admin-only. Clears the target user's TOTP MFA preference in Cognito and
 * wipes any stored recovery codes. The next login routes through MFA_SETUP,
 * forcing fresh enrollment.
 *
 * Used when a user loses their authenticator device and either can't or
 * won't go through the self-service recovery-code flow (e.g. they also lost
 * their recovery sheet).
 */
async function handleResetMfa(
  event: APIGatewayProxyEvent,
  admin: UserContext,
  requestId: string,
  route: UsersRouteContext
): Promise<APIGatewayProxyResult> {
  const targetUserId = route.userId;
  if (!targetUserId) {
    throw new ValidationError('Missing userId path parameter');
  }

  const target = await resolveTargetUserForOrg(
    targetUserId,
    admin.orgId,
    'Cannot reset MFA for user from another organization'
  );

  // Refuse to reset an admin's MFA from a peer-admin account by default.
  // The single-admin-org edge case is handled by letting an admin reset
  // their OWN MFA, since that's covered by the self-service recovery flow.
  // (Admins resetting their own MFA via this route is also fine — same
  // user, same authority.)
  // Block path: cross-admin reset where target ≠ caller.
  const targetIsAdmin = (target.attributes['custom:orgRole'] || target.attributes['custom:role'] || '')
    .toLowerCase()
    .split(/[,\s]+/)
    .includes('admin');
  if (targetIsAdmin && target.subjectId !== admin.userId) {
    await logAudit({
      userId: admin.userId,
      userEmail: admin.email,
      orgId: admin.orgId,
      action: 'admin.mfa_reset.denied',
      resourcePath: `/users/${targetUserId}/reset-mfa`,
      outcome: 'denied',
      ipAddress: getClientIp(event),
      userAgent: getUserAgent(event),
      metadata: {
        targetUserId: target.subjectId,
        reason: 'cannot_reset_peer_admin_mfa',
      },
    });
    return formatError(
      403,
      'Cannot reset MFA for another admin. The target user must use the self-service recovery flow.',
      requestId
    );
  }

  try {
    await cognitoClient.send(
      new AdminSetUserMFAPreferenceCommand({
        UserPoolId: USER_POOL_ID,
        Username: target.username,
        SoftwareTokenMfaSettings: { Enabled: false, PreferredMfa: false },
      })
    );
  } catch (err) {
    console.error('[USERS_RESET_MFA] AdminSetUserMFAPreference failed', (err as Error).message);
    throw err;
  }

  // Wipe stored recovery codes — they're tied to the now-cleared MFA preference.
  try {
    await deleteAllRecoveryCodesForUser(target.subjectId);
  } catch (err) {
    // Non-fatal: stale rows TTL out and will be overwritten at re-enrollment.
    console.warn('[USERS_RESET_MFA] recovery code wipe failed', (err as Error).message);
  }

  await logAudit({
    userId: admin.userId,
    userEmail: admin.email,
    orgId: admin.orgId,
    action: 'admin.mfa_reset',
    resourcePath: `/users/${targetUserId}/reset-mfa`,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: {
      targetUserId: target.subjectId,
      targetUsername: target.username,
    },
  });

  return formatSuccess(
    200,
    {
      message: `MFA reset for ${target.username}. User will be prompted to enroll a new authenticator on next sign-in.`,
      userId: target.subjectId,
    },
    requestId
  );
}

async function deleteAllRecoveryCodesForUser(userId: string): Promise<void> {
  const existing = await docClient.send(
    new QueryCommand({
      TableName: RECOVERY_CODES_TABLE,
      KeyConditionExpression: 'userId = :u',
      ExpressionAttributeValues: { ':u': userId },
      ProjectionExpression: 'userId, codeHash',
    })
  );

  const rows = existing.Items || [];
  if (rows.length === 0) return;

  const deletes = rows.map((row) => ({
    DeleteRequest: { Key: { userId: row.userId, codeHash: row.codeHash } },
  }));

  for (let i = 0; i < deletes.length; i += 25) {
    const chunk = deletes.slice(i, i + 25);
    await docClient.send(
      new BatchWriteCommand({
        RequestItems: { [RECOVERY_CODES_TABLE]: chunk },
      })
    );
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function attributesToRecord(
  attributes: Array<{ Name?: string; Value?: string }> = []
): Record<string, string> {
  return Object.fromEntries(
    attributes
      .filter((attribute): attribute is { Name: string; Value: string } => (
        typeof attribute.Name === 'string' && typeof attribute.Value === 'string'
      ))
      .map((attribute) => [attribute.Name, attribute.Value])
  );
}

function getOptionalStringField(body: Record<string, unknown>, fieldNames: string[]): string | undefined {
  for (const fieldName of fieldNames) {
    const value = body[fieldName];
    if (value === undefined || value === null || value === '') {
      continue;
    }
    if (typeof value !== 'string') {
      throw new ValidationError(`${fieldName} must be a string`);
    }
    return value;
  }
  return undefined;
}

function normalizeOptionalProfileField(
  value: string | undefined,
  label: string,
  maxLength: number
): string | undefined {
  const trimmed = value?.trim() || '';
  if (!trimmed) {
    return undefined;
  }
  if (trimmed.length > maxLength) {
    throw new ValidationError(`${label} must be ${maxLength} characters or fewer`);
  }
  return trimmed;
}

function buildDisplayNameFromParts(
  givenName: string | undefined,
  familyName: string | undefined
): string | undefined {
  const displayName = [givenName, familyName].filter(Boolean).join(' ').trim();
  return displayName || undefined;
}

function buildUserDisplayName(attrs: Record<string, string>, fallback: string): string {
  const explicitName = attrs['name']?.trim();
  if (explicitName) {
    return explicitName;
  }

  return buildDisplayNameFromParts(attrs['given_name'], attrs['family_name']) || fallback;
}

function isUserNotFoundError(err: unknown): boolean {
  const name = (err as { name?: string })?.name;
  const message = (err as { message?: string })?.message;
  return name === 'UserNotFoundException' || message === 'User does not exist.';
}

function escapeCognitoFilterValue(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

async function getCognitoUserByUsername(username: string): Promise<AdminGetUserCommandOutput> {
  return await cognitoClient.send(
    new AdminGetUserCommand({ UserPoolId: USER_POOL_ID, Username: username })
  );
}

async function findCognitoUsernameBySub(subjectId: string): Promise<string | undefined> {
  const filter = `sub = "${escapeCognitoFilterValue(subjectId)}"`;
  let paginationToken: string | undefined;

  try {
    do {
      const result: ListUsersCommandOutput = await cognitoClient.send(
        new ListUsersCommand({
          UserPoolId: USER_POOL_ID,
          Filter: filter,
          Limit: 60,
          PaginationToken: paginationToken,
        })
      );

      const match = findUserWithSub(result.Users || [], subjectId);
      if (match?.Username) {
        return match.Username;
      }

      paginationToken = result.PaginationToken;
    } while (paginationToken);
  } catch (err) {
    console.warn('[USERS_SUB_LOOKUP_FILTER_FAILED]', (err as Error).message);
  }

  paginationToken = undefined;
  do {
    const result: ListUsersCommandOutput = await cognitoClient.send(
      new ListUsersCommand({
        UserPoolId: USER_POOL_ID,
        Limit: 60,
        PaginationToken: paginationToken,
      })
    );

    const match = findUserWithSub(result.Users || [], subjectId);
    if (match?.Username) {
      return match.Username;
    }

    paginationToken = result.PaginationToken;
  } while (paginationToken);

  return undefined;
}

function findUserWithSub(
  users: Array<{ Username?: string; Attributes?: Array<{ Name?: string; Value?: string }> }>,
  subjectId: string
): { Username?: string } | undefined {
  return users.find((user) => (
    (user.Attributes || []).some((attribute) => (
      attribute.Name === 'sub' && attribute.Value === subjectId
    ))
  ));
}

async function resolveTargetUserForOrg(
  requestedUserId: string,
  orgId: string,
  crossOrgMessage: string
): Promise<ResolvedTargetUser> {
  let user: AdminGetUserCommandOutput;
  let username = requestedUserId;

  try {
    user = await getCognitoUserByUsername(requestedUserId);
    username = user.Username || requestedUserId;
  } catch (err) {
    if (!isUserNotFoundError(err)) {
      throw err;
    }

    const usernameForSub = await findCognitoUsernameBySub(requestedUserId);
    if (!usernameForSub) {
      throw new AuthError('User not found', 404);
    }

    username = usernameForSub;
    user = await getCognitoUserByUsername(usernameForSub);
  }

  const attributes = attributesToRecord(user.UserAttributes || []);
  if (attributes['custom:org'] !== orgId) {
    throw new AuthError(crossOrgMessage, 403);
  }
  const subjectId = requiredCognitoSubjectId(user.UserAttributes);

  return {
    requestedUserId,
    username,
    subjectId,
    user,
    attributes,
  };
}

/**
 * Rejects request-derived group/role names that collide (case-insensitively)
 * with a privileged platform group (e.g. platform-superadmin). No API code
 * path may ever create or assign a reserved group.
 */
function assertNotReservedGroup(groupName: string): void {
  if (isReservedGroupName(groupName)) {
    throw new ValidationError(`Group name "${groupName}" is reserved`);
  }
}

/**
 * Ensures a Cognito group exists, creating it if needed.
 */
async function ensureGroupExists(groupName: string): Promise<void> {
  assertNotReservedGroup(groupName);
  try {
    const existing = await cognitoClient.send(
      new ListGroupsCommand({ UserPoolId: USER_POOL_ID })
    );
    const exists = (existing.Groups || []).some((g) => g.GroupName === groupName);
    if (exists) return;
  } catch {
    // If listing fails, try creating anyway
  }

  try {
    await cognitoClient.send(
      new CreateGroupCommand({
        UserPoolId: USER_POOL_ID,
        GroupName: groupName,
        Description: `VaultGuard ${groupName} role`,
      })
    );
  } catch (err: any) {
    // Group already exists is fine
    if (err.name !== 'GroupExistsException') {
      throw err;
    }
  }
}

/**
 * Resolves a user's primary role from their Cognito group memberships.
 * Priority: admin > editor > viewer
 */
function resolveRole(groups: string[]): 'admin' | 'editor' | 'viewer' | 'custom' {
  if (groups.includes('admin')) return 'admin';
  if (groups.includes('editor')) return 'editor';
  if (groups.includes('viewer')) return 'viewer';
  return groups.length > 0 ? 'custom' : 'viewer';
}

/**
 * Maps Cognito user status to VaultGuard status.
 */
function mapCognitoStatus(
  enabled: boolean,
  cognitoStatus: string
): 'active' | 'suspended' | 'revoked' | 'pending' {
  if (!enabled) return 'revoked';
  if (cognitoStatus === 'FORCE_CHANGE_PASSWORD') return 'pending';
  if (cognitoStatus === 'CONFIRMED') return 'active';
  if (cognitoStatus === 'RESET_REQUIRED') return 'suspended';
  return 'active';
}

// ─── Organization Settings ──────────────────────────────────────────────────

async function loadAuthorizedOrgRecord(
  requestedOrgId: string | undefined,
  admin: UserContext
): Promise<OrgRecord> {
  if (!requestedOrgId) {
    throw new ValidationError('Missing orgId path parameter');
  }
  if (requestedOrgId !== admin.orgId) {
    throw new AuthError('Cannot access settings for another organization');
  }

  const orgResult = await getActiveOrg(admin.orgId);
  if (!orgResult.allowed || !orgResult.org) {
    throw new AuthError(
      orgResult.reason || 'Organization access denied',
      orgResult.code === 'ORG_NOT_FOUND' ? 404 : 403
    );
  }

  return orgResult.org;
}

async function persistOrgSettings(org: OrgRecord, settings: OrgSettings): Promise<void> {
  const persistedSettings: PersistedOrgSettings = {
    syncMode: settings.syncMode,
    syncIntervalMinutes: settings.syncIntervalMinutes,
    enforceEncryption: settings.enforceEncryption,
    maxSessionDurationHours: settings.maxSessionDurationHours,
    requireMfa: settings.requireMfa,
    allowedDomains: settings.allowedDomains,
    retentionDays: settings.retentionDays,
    autoLockMinutes: settings.autoLockMinutes,
    idleAction: settings.idleAction,
    allowAdminPerFileRestrictions: settings.allowAdminPerFileRestrictions,
    disabledAuditActions: settings.disabledAuditActions,
  };

  await docClient.send(
    new UpdateCommand({
      TableName: ORGANIZATIONS_TABLE,
      Key: { slug: org.slug },
      UpdateExpression: 'SET #name = :name, #settings = :settings, updatedAt = :updatedAt',
      ExpressionAttributeNames: {
        '#name': 'name',
        '#settings': 'settings',
      },
      ExpressionAttributeValues: {
        ':name': settings.orgName,
        ':settings': persistedSettings,
        ':updatedAt': new Date().toISOString(),
      },
    })
  );

  invalidateOrgSettingsCache(settings.orgId);
}

// ─── GET /orgs/{orgId}/settings ─────────────────────────────────────────────

async function handleGetOrgSettings(
  event: APIGatewayProxyEvent,
  admin: UserContext,
  requestId: string,
  route: UsersRouteContext
): Promise<APIGatewayProxyResult> {
  const orgId = route.orgId;
  const org = await loadAuthorizedOrgRecord(orgId, admin);
  const settings = buildOrgSettings(orgId!, org);

  return formatSuccess(200, settings, requestId);
}

// ─── PUT /orgs/{orgId}/settings ─────────────────────────────────────────────

async function handleUpdateOrgSettings(
  event: APIGatewayProxyEvent,
  admin: UserContext,
  requestId: string,
  route: UsersRouteContext
): Promise<APIGatewayProxyResult> {
  const orgId = route.orgId;
  const org = await loadAuthorizedOrgRecord(orgId, admin);
  const body = parseBody(event);
  const currentSettings = buildOrgSettings(orgId!, org);

  if (body.enforceEncryption === false) {
    throw new ValidationError(
      'VaultGuard always requires encryption and this setting cannot be disabled.'
    );
  }

  const settings: OrgSettings = {
    orgId: orgId!,
    orgName:
      typeof body.orgName === 'string' && body.orgName.trim().length > 0
        ? body.orgName.trim()
        : currentSettings.orgName,
    syncMode: normalizeSyncMode(body.syncMode, currentSettings.syncMode) || currentSettings.syncMode,
    syncIntervalMinutes:
      parsePositiveInteger(body.syncIntervalMinutes, currentSettings.syncIntervalMinutes) ||
      currentSettings.syncIntervalMinutes,
    enforceEncryption: true,
    maxSessionDurationHours:
      parsePositiveInteger(body.maxSessionDurationHours, currentSettings.maxSessionDurationHours) ||
      currentSettings.maxSessionDurationHours,
    requireMfa:
      typeof body.requireMfa === 'boolean' ? body.requireMfa : currentSettings.requireMfa,
    allowedDomains:
      normalizeAllowedDomains(body.allowedDomains, currentSettings.allowedDomains) ||
      currentSettings.allowedDomains,
    retentionDays:
      parsePositiveInteger(body.retentionDays, currentSettings.retentionDays) ||
      currentSettings.retentionDays,
    autoLockMinutes:
      parseNonNegativeInteger(body.autoLockMinutes, currentSettings.autoLockMinutes) ??
      currentSettings.autoLockMinutes,
    idleAction:
      body.idleAction === 'lock' || body.idleAction === 'logout'
        ? body.idleAction
        : currentSettings.idleAction,
    allowAdminPerFileRestrictions:
      typeof body.allowAdminPerFileRestrictions === 'boolean'
        ? body.allowAdminPerFileRestrictions
        : currentSettings.allowAdminPerFileRestrictions,
    disabledAuditActions:
      normalizeDisabledAuditActions(body.disabledAuditActions, currentSettings.disabledAuditActions) ??
      currentSettings.disabledAuditActions,
  };

  await persistOrgSettings(org, settings);

  await logAudit({
    userId: admin.userId,
    userEmail: admin.email,
    orgId: admin.orgId,
    action: 'admin.settings_updated',
    resourcePath: `/orgs/${orgId}/settings`,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: { orgId },
  });

  return formatSuccess(200, settings, requestId);
}

// ─── DELETE /orgs/{orgId}/settings ──────────────────────────────────────────

async function handleResetOrgSettings(
  event: APIGatewayProxyEvent,
  admin: UserContext,
  requestId: string,
  route: UsersRouteContext
): Promise<APIGatewayProxyResult> {
  const orgId = route.orgId;
  const org = await loadAuthorizedOrgRecord(orgId, admin);
  const currentSettings = buildOrgSettings(orgId!, org);
  const resetSettings: OrgSettings = {
    orgId: orgId!,
    orgName: currentSettings.orgName,
    ...DEFAULT_ORG_SETTINGS,
  };

  await persistOrgSettings(org, resetSettings);

  await logAudit({
    userId: admin.userId,
    userEmail: admin.email,
    orgId: admin.orgId,
    action: 'admin.settings_reset',
    resourcePath: `/orgs/${orgId}/settings`,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: { orgId },
  });

  return formatSuccess(200, resetSettings, requestId);
}

// ─── Vault-membership bootstrap for newly invited members ──────────────────

/**
 * Constants mirroring the canonical defaults in `vaults/handler.ts`. Kept
 * inline because each Lambda is bundled independently by `build-lambdas.mjs`
 * and cross-handler imports are not supported in the current build. If the
 * canonical values ever change in `vaults/handler.ts`, update both.
 */
const DEFAULT_MEMBER_RULE_PRIORITY = 0;
const DEFAULT_MEMBER_RULE_SK = 'RULE';
const DEFAULT_MEMBER_RULE_SOURCE = 'vault-member-default';

function defaultMemberPermissionRuleId(vaultId: string, userId: string): string {
  return `${DEFAULT_MEMBER_RULE_SOURCE}#${vaultId}#${userId}`;
}

/**
 * Mirrors `actionsForVaultRole` in vaults/handler.ts for editor and viewer
 * (the canonical action sets — see also `VAULT_ROLE_DEFAULT_ACTIONS` in
 * shared/utils.ts and `levelToActions('write')` in permissions/handler.ts;
 * keep all four in sync). `editor` includes `delete`: a write-level member
 * may delete their own files, so the seeded rule must grant it directly.
 * Admin role is intentionally not handled here — admins are not auto-added
 * to vaults at invite time (the inviting admin chooses which vaults to
 * attach them to manually).
 */
function actionsForOrgRole(role: 'editor' | 'viewer'): PermissionAction[] {
  if (role === 'editor') return ['read', 'write', 'delete', 'list'];
  return ['read', 'list'];
}

/**
 * Adds the newly invited user as a member of every vault in the org and
 * creates the baseline `/**` allow rule per vault. Best-effort: failures
 * are logged but do not roll back the Cognito invite, because the rule
 * landscape is self-healing — the admin can add the user to vaults
 * manually if any of these writes fail. We DO surface a non-fatal warning
 * in the invite audit log when partial failures occur.
 *
 * Per CLAUDE.md vault-scoping rule: every rule we write carries a real
 * `vaultId`. No org-wide rules are ever created.
 */
async function seedDefaultVaultMembershipForInvitee(
  orgId: string,
  newUserId: string,
  role: 'editor' | 'viewer',
  inviterUserId: string
): Promise<{ vaultsJoined: number; failures: number }> {
  let vaultsJoined = 0;
  let failures = 0;

  // 1. List every vault in the org. Reuses the shared helper so a future
  //    vault-table schema change only needs to touch one place.
  const vaults = await listVaultsForOrg(orgId);
  const nowIso = new Date().toISOString();

  // 2. For each vault, write (a) the membership and (b) the default rule.
  //    Both are idempotent on (vaultId, userId) so a partial retry is safe.
  for (const vault of vaults) {
    if (vault.archived) continue;
    try {
      try {
        await docClient.send(new PutCommand({
          TableName: VAULT_MEMBERS_TABLE,
          Item: {
            vaultId: vault.vaultId,
            userId: newUserId,
            role,                        // Vault role mirrors org role for non-admin invites.
            accessKind: 'member',
            joinedAt: nowIso,
            invitedBy: inviterUserId,
          },
          ConditionExpression: 'attribute_not_exists(vaultId) AND attribute_not_exists(userId)',
        }));
      } catch (memberErr) {
        // Conditional-check-failed means the user is already a vault member —
        // proceed to (re)write the default rule so we still self-heal.
        if ((memberErr as { name?: string }).name !== 'ConditionalCheckFailedException') {
          throw memberErr;
        }
      }

      const ruleId = defaultMemberPermissionRuleId(vault.vaultId, newUserId);
      await docClient.send(new PutCommand({
        TableName: PERMISSIONS_TABLE,
        Item: {
          pk: ruleId,
          sk: DEFAULT_MEMBER_RULE_SK,
          id: ruleId,
          orgId,
          vaultId: vault.vaultId,
          userId: newUserId,
          pathPattern: '/**',
          actions: actionsForOrgRole(role),
          effect: 'allow',
          priority: DEFAULT_MEMBER_RULE_PRIORITY,
          createdAt: nowIso,
          updatedAt: nowIso,
          createdBy: inviterUserId,
          source: DEFAULT_MEMBER_RULE_SOURCE,
        },
      }));

      vaultsJoined++;
    } catch (err) {
      console.error(
        `[VaultGuard] Failed to seed vault membership during invite`,
        { orgId, newUserId, vaultId: vault.vaultId, error: err }
      );
      failures++;
    }
  }

  return { vaultsJoined, failures };
}

const GUEST_MEMBER_RULE_SOURCE = 'guest-invite';

/**
 * True when any of these identities holds an ACTIVE guest membership row.
 *
 * DR-3: the active test is the fix. Before it, this asked only whether a guest row
 * EXISTED, so one lapsed row locked a former guest to viewer permanently — an admin
 * could never promote them, and could never reactivate them as anything but a viewer.
 * A lapsed row grants nothing (every enforcement site already fails closed on it), so
 * it must not block a promotion either. An unexpired guest row still blocks, which is
 * the rule this predicate exists to enforce.
 *
 * RESEARCH assumption A3: the per-identity index this Query uses is org-blind — its
 * rows carry no orgId — so the predicate can in principle observe a row belonging to
 * another org's vault. That is left as-is deliberately. This asks a per-identity
 * question rather than an org-scoped one, and the error direction is conservative in
 * the deny direction: a stray row can only BLOCK a promotion, never grant one.
 * Denormalising orgId onto the membership rows is explicitly out of scope for this phase.
 */
async function hasStoredGuestMembership(
  userIds: string[],
  nowMs = Date.now()
): Promise<boolean> {
  for (const userId of new Set(userIds.filter(Boolean))) {
    const result = await docClient.send(new QueryCommand({
      TableName: VAULT_MEMBERS_TABLE,
      IndexName: 'userId-index',
      KeyConditionExpression: 'userId = :userId',
      ExpressionAttributeValues: { ':userId': userId },
    }));
    if ((result?.Items ?? []).some(
      (item) => item.accessKind === 'guest' && isExpiringAccessActive(item.expiresAt, nowMs)
    )) {
      return true;
    }
  }
  return false;
}

/** One stored temporary membership row, as read back off the per-identity index. */
interface StoredGuestRow {
  vaultId: string;
  userId: string;
  expiresAt?: string;
}

/**
 * Every stored TEMPORARY membership row for these identities, deduped on
 * (vaultId, userId).
 *
 * Reuses the access pattern `hasStoredGuestMembership` already established —
 * VaultMembers `userId-index`, one Query per identity — rather than adding a
 * second one; RESEARCH assumption A3 (the index is org-blind) applies here
 * identically. The difference is only in what is returned: that predicate
 * answers "is any of these still ACTIVE", this hands back the rows so a caller
 * can decide per row.
 *
 * Permanent memberships are filtered out HERE, exactly once, so no caller can
 * hand one to a delete by accident. The test is `!== 'guest'` and never
 * `=== 'member'`: rows written before the temporary-access feature carry no
 * kind at all and must count as permanent.
 */
async function listStoredGuestRows(userIds: string[]): Promise<StoredGuestRow[]> {
  const rows = new Map<string, StoredGuestRow>();
  for (const userId of new Set(userIds.filter(Boolean))) {
    const result = await docClient.send(new QueryCommand({
      TableName: VAULT_MEMBERS_TABLE,
      IndexName: 'userId-index',
      KeyConditionExpression: 'userId = :userId',
      ExpressionAttributeValues: { ':userId': userId },
    }));
    for (const item of result?.Items ?? []) {
      if (item.accessKind !== 'guest') continue;
      const vaultId = item.vaultId as string | undefined;
      const rowUserId = item.userId as string | undefined;
      if (!vaultId || !rowUserId) continue;
      rows.set(`${vaultId}#${rowUserId}`, {
        vaultId,
        userId: rowUserId,
        expiresAt: item.expiresAt as string | undefined,
      });
    }
  }
  return [...rows.values()];
}

/**
 * DR-3, the half that makes a promotion STICK. Called from BOTH doors that can
 * promote a former temporary user — role change and reactivate-with-a-role —
 * so the two cannot diverge.
 *
 * WHY DELETING IS REQUIRED, and why a filter elsewhere could not substitute:
 * `summarizeGuestAccess` is purely row-shaped and takes no org role as input,
 * by design — it is the single rule behind both the admin-panel badge and the
 * scheduled expiry sweeper, and teaching it about roles is what makes those two
 * drift apart. So a promoted user who KEPT these rows still reads as fully
 * expired to that sweeper, which disables the account, writes a revocation
 * marker and releases the seat on its next run: the promotion silently undone,
 * and for a promotion to admin the org losing its own administrator overnight.
 * Removing the rows makes the answer structurally false instead of filtered.
 *
 * Selection is narrow on purpose. `hasStoredGuestMembership` has already run
 * and thrown if ANY temporary row is still active, so everything reaching here
 * is a row that already grants nothing — every enforcement site fails closed on
 * it, and vault listing filters it out. Permanent rows are excluded upstream by
 * `listStoredGuestRows`, and the boundary test is the shared predicate rather
 * than a date comparison written here.
 *
 * The delete is pinned to the exact boundary that was READ (the shared helper's
 * default guard), so an admin extending this user in another tab between the
 * read and the write wins the race: the condition fails and the now-active row
 * is left alone rather than deleted.
 */
async function clearExpiredGuestRowsForPromotion(
  userIds: string[],
  nowMs = Date.now()
): Promise<{ membershipsDeleted: number; permissionRulesDeleted: number }> {
  const lapsed = (await listStoredGuestRows(userIds)).filter(
    (row): row is StoredGuestRow & { expiresAt: string } =>
      !!row.expiresAt && !isExpiringAccessActive(row.expiresAt, nowMs)
  );
  if (lapsed.length === 0) return { membershipsDeleted: 0, permissionRulesDeleted: 0 };
  return await deleteGuestAccessRows(
    lapsed.map((row) => ({
      vaultId: row.vaultId,
      userId: row.userId,
      expiresAt: row.expiresAt,
    }))
  );
}

function guestPermissionRuleId(vaultId: string, userId: string): string {
  return `${GUEST_MEMBER_RULE_SOURCE}#${vaultId}#${userId}`;
}

/**
 * Creates viewer-only, expiring access for exactly the selected active vaults.
 * Conditional writes never replace a permanent member or a differently scoped
 * guest. A retry accepts only byte-for-byte-equivalent access boundaries.
 *
 * The origin parameter is REQUIRED rather than defaulted: a default would
 * silently classify a future caller's rows as invite-origin, which is the
 * direction that gets a pre-existing colleague's account disabled once their
 * temporary grant lapses. It rides the membership Put that already exists, so
 * the row is never briefly stored without it.
 */
async function seedGuestVaultMembershipsForInvitee(
  orgId: string,
  newUserId: string,
  vaults: VaultRecord[],
  expiresAt: string,
  inviterUserId: string,
  guestOrigin: GuestOrigin
): Promise<{ vaultsJoined: number; failures: number }> {
  let vaultsJoined = 0;
  let failures = 0;
  const nowIso = new Date().toISOString();

  for (const vault of vaults) {
    let membershipCreated = false;
    const expected = { vaultId: vault.vaultId, userId: newUserId, expiresAt };
    try {
      try {
        await docClient.send(new PutCommand({
          TableName: VAULT_MEMBERS_TABLE,
          Item: {
            vaultId: vault.vaultId,
            userId: newUserId,
            role: 'viewer',
            accessKind: 'guest',
            guestOrigin,
            joinedAt: nowIso,
            invitedBy: inviterUserId,
            expiresAt,
          },
          ConditionExpression: 'attribute_not_exists(vaultId) AND attribute_not_exists(userId)',
        }));
        membershipCreated = true;
      } catch (memberErr) {
        if ((memberErr as { name?: string }).name !== 'ConditionalCheckFailedException') {
          throw memberErr;
        }
        const existingResult = await docClient.send(new GetCommand({
          TableName: VAULT_MEMBERS_TABLE,
          Key: { vaultId: vault.vaultId, userId: newUserId },
        }));
        if (!isIdenticalGuestMembership(
          existingResult.Item as Record<string, unknown> | undefined,
          expected
        )) {
          throw new Error('Existing permanent or differently expiring vault membership was preserved.');
        }
      }

      const ruleId = guestPermissionRuleId(vault.vaultId, newUserId);
      try {
        await docClient.send(new PutCommand({
          TableName: PERMISSIONS_TABLE,
          Item: {
            pk: ruleId,
            sk: DEFAULT_MEMBER_RULE_SK,
            id: ruleId,
            orgId,
            vaultId: vault.vaultId,
            userId: newUserId,
            pathPattern: '/**',
            actions: ['read', 'list'],
            effect: 'allow',
            priority: DEFAULT_MEMBER_RULE_PRIORITY,
            createdAt: nowIso,
            updatedAt: nowIso,
            createdBy: inviterUserId,
            source: GUEST_MEMBER_RULE_SOURCE,
            expiresAt,
          },
          ConditionExpression: 'attribute_not_exists(pk) AND attribute_not_exists(sk)',
        }));
      } catch (ruleErr) {
        if ((ruleErr as { name?: string }).name !== 'ConditionalCheckFailedException') {
          throw ruleErr;
        }
        const existingResult = await docClient.send(new GetCommand({
          TableName: PERMISSIONS_TABLE,
          Key: { pk: ruleId, sk: DEFAULT_MEMBER_RULE_SK },
        }));
        if (!isIdenticalGuestPermissionRule(
          existingResult.Item as Record<string, unknown> | undefined,
          expected
        )) {
          throw new Error('Existing differently scoped guest permission rule was preserved.');
        }
      }

      vaultsJoined++;
    } catch (error) {
      if (membershipCreated) {
        await docClient.send(new DeleteCommand({
          TableName: VAULT_MEMBERS_TABLE,
          Key: { vaultId: vault.vaultId, userId: newUserId },
          ConditionExpression: '#kind = :guest AND expiresAt = :expiresAt',
          ExpressionAttributeNames: { '#kind': 'accessKind' },
          ExpressionAttributeValues: { ':guest': 'guest', ':expiresAt': expiresAt },
        })).catch((rollbackError) => {
          console.error('[VaultGuard] Failed to roll back partial guest membership', {
            orgId,
            newUserId,
            vaultId: vault.vaultId,
            error: rollbackError,
          });
        });
      }
      console.error('[VaultGuard] Failed to seed guest vault membership during invite', {
        orgId,
        newUserId,
        vaultId: vault.vaultId,
        error,
      });
      failures++;
    }
  }

  return { vaultsJoined, failures };
}
