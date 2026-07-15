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
import { EventBridgeClient, PutEventsCommand } from '@aws-sdk/client-eventbridge';
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
  checkUserLimit,
  updateOrgUserCount,
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
} from '../shared/utils';
import {
  DEFAULT_GUEST_ACCESS_DAYS,
  guestAccessExpiresAt,
  isIdenticalGuestMembership,
  isIdenticalGuestPermissionRule,
  normalizeGuestVaultIds,
} from '../shared/guest-access';
import { UsersRouteContext, resolveUsersRouteContext } from '../shared/route-utils';
import { sendEmail } from '../email/handler';
import { syncStripeSeats } from '../billing/handler';

// ─── Configuration ───────────────────────────────────────────────────────────

const USER_POOL_ID = process.env.USER_POOL_ID!;
const REGION = process.env.AWS_REGION || 'eu-west-1';
// Required env var — fail loud rather than silently fall back to a name that
// might not match the deployed table. See auth/handler.ts for the full story.
const REVOKED_KEYS_TABLE = process.env.REVOKED_KEYS_TABLE!;

const cognitoClient = new CognitoIdentityProviderClient({ region: REGION });
const eventBridgeClient = new EventBridgeClient({ region: REGION });

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
      };
    })
  );

  await logAudit({
    userId: admin.userId,
    userEmail: admin.email,
    orgId: admin.orgId,
    action: 'admin.list_users',
    resourcePath: '/users',
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: { userCount: users.length },
  });

  return formatSuccess(200, users, requestId);
}

// ─── POST /users/invite ─────────────────────────────────────────────────────

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
  if (orgCheck.org) {
    const limitCheck = checkUserLimit(orgCheck.org);
    if (!limitCheck.allowed) {
      return formatError(402, limitCheck.reason || 'User limit exceeded', requestId);
    }

    const orgSettings = buildOrgSettings(admin.orgId, orgCheck.org);
    if (!isEmailAllowedForOrg(email, orgSettings)) {
      throw new ValidationError(
        `Invitations are restricted to these domains: ${orgSettings.allowedDomains.join(', ')}`
      );
    }
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

  // Ensure the role group exists in Cognito
  assertNotReservedGroup(role);
  await ensureGroupExists(role);

  // Create user in Cognito — org is ALWAYS taken from authenticated admin context.
  // ALWAYS suppress Cognito's default email (which sends from no-reply@verificationemail.com
  // with the temp password in plaintext). We send our own branded email instead.
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

  const userId = createResult.User?.Username!;

  // Add user to role group
  await cognitoClient.send(
    new AdminAddUserToGroupCommand({
      UserPoolId: USER_POOL_ID,
      Username: userId,
      GroupName: role,
    })
  );

  // Increment org user count
  const orgResult = await getActiveOrg(admin.orgId);
  if (orgResult.org) {
    await updateOrgUserCount(orgResult.org.slug, 1);
    await bestEffortSeatSync(admin.orgId);
  }

  // Send our own branded invitation email (no plaintext password — user sets
  // their password via the "Forgot Password" flow in the plugin on first login)
  if (sendWelcomeEmail) {
    const orgName = orgResult.org?.name as string || admin.orgId;
    const orgSlug = (orgResult.org?.slug as string) || '';
    const inviterName = admin.email;
    await sendEmail('invitation', {
      email,
      orgName,
      orgSlug,
      inviterName,
      username: email,
    }, { throwOnError: true });
  }

  // Seed baseline vault membership + /** allow rule for non-admin invites.
  // Admin-role invites are skipped: the inviting admin chooses which vaults to
  // attach them to manually. See CLAUDE.md vault-scoping rule — every rule
  // created here is per-vault, never org-wide.
  let bootstrap: { vaultsJoined: number; failures: number } | null = null;
  if (accessKind === 'guest') {
    try {
      bootstrap = await seedGuestVaultMembershipsForInvitee(
        admin.orgId,
        userId,
        guestVaults,
        guestExpiresAt!,
        admin.userId
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
      ...(guestExpiresAt ? { expiresAt: guestExpiresAt } : {}),
      ...(accessKind === 'guest' ? { vaultIds: guestVaults.map((vault) => vault.vaultId) } : {}),
      ...(guestProvisioningStatus ? { provisioningStatus: guestProvisioningStatus } : {}),
      ...(displayName ? { displayName } : {}),
      ...(bootstrap ? { vaultsJoined: bootstrap.vaultsJoined, vaultBootstrapFailures: bootstrap.failures } : {}),
    },
  });

  return formatSuccess(201, {
    message: guestProvisioningStatus === 'partial'
      ? `User ${email} was invited, but access to some selected vaults could not be provisioned`
      : guestProvisioningStatus === 'failed'
        ? `User ${email} was invited, but selected-vault access could not be provisioned`
        : `User ${email} invited successfully`,
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

  // Disable user in Cognito (prevents all sign-ins)
  await cognitoClient.send(
    new AdminDisableUserCommand({
      UserPoolId: USER_POOL_ID,
      Username: target.username,
    })
  );

  // Remove from all role groups
  const currentGroups = await cognitoClient.send(
    new AdminListGroupsForUserCommand({
      UserPoolId: USER_POOL_ID,
      Username: target.username,
    })
  );

  for (const group of currentGroups.Groups || []) {
    await cognitoClient.send(
      new AdminRemoveUserFromGroupCommand({
        UserPoolId: USER_POOL_ID,
        Username: target.username,
        GroupName: group.GroupName!,
      })
    );
  }

  // Decrement org user count
  const orgResult = await getActiveOrg(admin.orgId);
  if (orgResult.org) {
    await updateOrgUserCount(orgResult.org.slug, -1);
    await bestEffortSeatSync(admin.orgId);
  }

  const cryptoRevocation = await revokeUserCryptoAccess({
    targetUserId: target.subjectId,
    adminUserId: admin.userId,
    orgId: admin.orgId,
    reason: 'admin_user_revoked',
  });

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
    },
  });

  return formatSuccess(200, {
    message: `Access revoked for user ${target.username}`,
    userId: target.subjectId,
    status: 'revoked',
    invalidatedSessions: cryptoRevocation.invalidatedSessions,
    revokedLeases: cryptoRevocation.revokedLeases,
    revokedAt: cryptoRevocation.revokedAt,
  }, requestId);
}

async function revokeUserCryptoAccess(params: {
  targetUserId: string;
  adminUserId: string;
  orgId: string;
  reason: string;
}): Promise<{ invalidatedSessions: number; revokedLeases: number; revokedAt: string }> {
  const revokedAt = new Date().toISOString();

  const sessionsResult = await docClient.send(
    new QueryCommand({
      TableName: SESSIONS_TABLE,
      IndexName: 'userId-index',
      KeyConditionExpression: 'userId = :uid',
      FilterExpression: 'isActive = :active AND orgId = :orgId',
      ExpressionAttributeValues: {
        ':uid': params.targetUserId,
        ':active': true,
        ':orgId': params.orgId,
      },
    })
  );

  const activeSessions = sessionsResult.Items || [];
  for (const session of activeSessions) {
    await docClient.send(
      new UpdateCommand({
        TableName: SESSIONS_TABLE,
        Key: { sessionId: session.sessionId as string },
        UpdateExpression: 'SET isActive = :inactive, invalidatedAt = :now',
        ExpressionAttributeValues: {
          ':inactive': false,
          ':now': revokedAt,
        },
      })
    );
  }

  const leasesResult = await docClient.send(
    new QueryCommand({
      TableName: LEASES_TABLE,
      IndexName: 'userId-index',
      KeyConditionExpression: 'userId = :uid',
      FilterExpression: '#s = :active AND orgId = :orgId',
      ExpressionAttributeNames: { '#s': 'status' },
      ExpressionAttributeValues: {
        ':uid': params.targetUserId,
        ':active': 'active',
        ':orgId': params.orgId,
      },
    })
  );

  const activeLeases = leasesResult.Items || [];
  for (const lease of activeLeases) {
    await docClient.send(
      new UpdateCommand({
        TableName: LEASES_TABLE,
        Key: { leaseId: lease.leaseId as string },
        UpdateExpression: 'SET #s = :revoked, revokedAt = :now, revokedBy = :by',
        ExpressionAttributeNames: { '#s': 'status' },
        ExpressionAttributeValues: {
          ':revoked': 'revoked',
          ':now': revokedAt,
          ':by': params.adminUserId,
        },
      })
    );
  }

  await docClient.send(
    new PutCommand({
      TableName: REVOKED_KEYS_TABLE,
      Item: {
        userId: params.targetUserId,
        revokedAt,
        revokedBy: params.adminUserId,
        reason: params.reason,
      },
    })
  );

  try {
    await eventBridgeClient.send(
      new PutEventsCommand({
        Entries: [
          {
            Source: 'vaultguard.auth',
            DetailType: 'UserAccessRevoked',
            Detail: JSON.stringify({
              targetUserId: params.targetUserId,
              orgId: params.orgId,
              triggeredBy: params.adminUserId,
              reason: params.reason,
            }),
          },
        ],
      })
    );
  } catch (err) {
    console.error('[USERS_REVOKE] EventBridge publish failed:', err);
  }

  return {
    invalidatedSessions: activeSessions.length,
    revokedLeases: activeLeases.length,
    revokedAt,
  };
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

  // Re-enable user in Cognito
  await cognitoClient.send(
    new AdminEnableUserCommand({
      UserPoolId: USER_POOL_ID,
      Username: target.username,
    })
  );

  // Add back to a role group
  assertNotReservedGroup(role);
  await ensureGroupExists(role);
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
    })
  );

  // Increment org user count
  const orgResult = await getActiveOrg(admin.orgId);
  if (orgResult.org) {
    await updateOrgUserCount(orgResult.org.slug, 1);
    await bestEffortSeatSync(admin.orgId);
  }

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

  return {
    requestedUserId,
    username,
    subjectId: attributes.sub || username,
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

async function hasStoredGuestMembership(userIds: string[]): Promise<boolean> {
  for (const userId of new Set(userIds.filter(Boolean))) {
    const result = await docClient.send(new QueryCommand({
      TableName: VAULT_MEMBERS_TABLE,
      IndexName: 'userId-index',
      KeyConditionExpression: 'userId = :userId',
      ExpressionAttributeValues: { ':userId': userId },
    }));
    if ((result?.Items ?? []).some((item) => item.accessKind === 'guest')) {
      return true;
    }
  }
  return false;
}

function guestPermissionRuleId(vaultId: string, userId: string): string {
  return `${GUEST_MEMBER_RULE_SOURCE}#${vaultId}#${userId}`;
}

/**
 * Creates viewer-only, expiring access for exactly the selected active vaults.
 * Conditional writes never replace a permanent member or a differently scoped
 * guest. A retry accepts only byte-for-byte-equivalent access boundaries.
 */
async function seedGuestVaultMembershipsForInvitee(
  orgId: string,
  newUserId: string,
  vaults: VaultRecord[],
  expiresAt: string,
  inviterUserId: string
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
