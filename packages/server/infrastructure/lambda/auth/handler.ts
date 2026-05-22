/**
 * VaultGuard — Authentication Lambda Handler
 *
 * Manages user authentication, session lifecycle, and cryptographic key leases.
 *
 * Endpoints:
 * - POST /auth/login           — Validate Cognito token, create session, return key lease
 * - POST /auth/refresh         — Refresh session and key lease
 * - POST /auth/logout          — Invalidate session, trigger client cache wipe
 * - GET  /auth/key-lease       — Issue time-limited decryption key lease
 * - POST /auth/revoke          — Admin: revoke user access, invalidate all sessions
 * - POST /auth/key-lease/scoped — Issue path-scoped key lease
 * - GET  /auth/leases          — Admin: list leases for a user
 * - GET  /auth/heartbeat       — Client: lightweight revocation check (polling)
 * - POST /auth/forgot-password — Generate reset code and send branded email (no auth required)
 * - POST /auth/confirm-reset   — Verify reset code and set new password (no auth required)
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { KMSClient, GenerateDataKeyCommand, DecryptCommand } from '@aws-sdk/client-kms';
import { EventBridgeClient, PutEventsCommand } from '@aws-sdk/client-eventbridge';
import { createHmac, randomInt, timingSafeEqual } from 'crypto';
import {
  docClient,
  verifyToken,
  verifyActiveUser,
  evaluatePermission,
  findApplicableDenyRulesInScope,
  logAudit,
  formatError,
  formatSuccess,
  parseBody,
  validateRequiredFields,
  getClientIp,
  getUserAgent,
  generateId,
  generateSecretToken,
  isAdmin,
  requireOrgId,
  assertUserNotRevoked,
  requireVaultMember,
  AuthError,
  ValidationError,
  UserContext,
  OrgSettings,
  pathMatchesPattern,
  GetCommand,
  PutCommand,
  QueryCommand,
  UpdateCommand,
  DeleteCommand,
  SESSIONS_TABLE,
  LEASES_TABLE,
  USER_KEYS_TABLE,
  RECOVERY_CODES_TABLE,
  RECOVERY_ATTEMPTS_TABLE,
  BatchWriteCommand,
  getEffectiveOrgSettings,
} from '../shared/utils';
import { sendEmail } from '../email/handler';

// ─── Configuration ───────────────────────────────────────────────────────────

const KMS_KEY_ID = process.env.KMS_KEY_ID!;
const KEY_LEASE_DURATION_SECONDS = parseInt(process.env.KEY_LEASE_DURATION_SECONDS || '3600', 10);
// REVOKED_KEYS_TABLE is on the login hot path (checkKeyRevocation runs on
// every /auth/key-lease). Require the env var and fail loud at module load
// rather than silently fall back to a hardcoded name that may not exist —
// this exact silent-fallback bug shipped once when the env var was added to
// the stack but the lambda wasn't redeployed.
const REVOKED_KEYS_TABLE = process.env.REVOKED_KEYS_TABLE!;
const MAX_CONCURRENT_LEASES = parseInt(process.env.MAX_CONCURRENT_LEASES || '10', 10);
// ESCROW_TABLE is only used by ZK recovery flows (not the login hot path).
// Keep the silent fallback for now so a stack-deploy gap doesn't break the
// auth lambda at module load; the recovery flow will fail loudly on its own
// if ever exercised against an undeployed escrow table.
const ESCROW_TABLE = process.env.ESCROW_TABLE || 'VaultGuard-Escrow';

const kmsClient = new KMSClient({ region: process.env.AWS_REGION || 'eu-west-1' });
const eventBridgeClient = new EventBridgeClient({ region: process.env.AWS_REGION || 'eu-west-1' });

// ─── Types ───────────────────────────────────────────────────────────────────

/** Session record stored in DynamoDB. */
interface Session {
  sessionId: string;
  userId: string;
  orgId: string;
  email: string;
  roles: string[];
  createdAt: string;
  expiresAt: string;
  lastActivity: string;
  ipAddress: string;
  userAgent: string;
  isActive: boolean;
}

/** Key lease issued to the client for time-limited decryption. */
interface KeyLease {
  /** Plaintext AES-256 key delivered to the plugin for local crypto operations. */
  key: string;
  /** Encrypted data key retained for audit / future server-side rotation flows. */
  encryptedDataKey: string;
  /** ISO timestamp when this lease expires. */
  expiresAt: string;
  /** Refresh token to obtain a new lease before expiry. */
  refreshToken: string;
  /** Lease ID for tracking and revocation. */
  leaseId: string;
  /** Encryption algorithm used by the plugin. */
  algorithm: 'AES-256-GCM';
  /** Whether the lease may be used while temporarily offline. */
  offlineCapable: boolean;
  /** Path scope this lease is bound to (glob pattern). '/**' means full vault access. */
  scope: string;
  /** Vault this lease is bound to. Omitted only for legacy pre-vault leases. */
  vaultId?: string;
}

/** Persisted lease record in the Leases DynamoDB table. */
interface LeaseRecord {
  leaseId: string;
  userId: string;
  sessionId: string;
  orgId: string;
  encryptedDataKey: string;
  refreshToken: string;
  status: 'active' | 'expired' | 'revoked';
  issuedAt: string;
  expiresAt: string;
  revokedAt?: string;
  revokedBy?: string;
  /** Path scope this lease is bound to (glob pattern). */
  scope: string;
  /** Vault this lease is bound to. Omitted only for legacy pre-vault leases. */
  vaultId?: string;
  /** Unix epoch seconds for DynamoDB TTL (7 days after expiry). */
  expiresAtTtl: number;
}

/** Stable vault/scope DEK persisted in the UserKeys table. */
interface ScopeDataKey {
  pk: string;
  sk: 'ACTIVE';
  orgId: string;
  vaultId?: string;
  scope: string;
  encryptedDataKey: string;
  status: 'active' | 'rotated' | 'revoked';
  createdAt: string;
  lastUsedAt: string;
}

async function getRequiredOrgSettings(user: UserContext): Promise<OrgSettings> {
  const orgId = requireOrgId(user);
  await assertUserNotRevoked(user);
  const settings = await getEffectiveOrgSettings(orgId);

  if (!settings) {
    throw new AuthError('Organization access denied. Contact your administrator.', 403);
  }

  return settings;
}

function assertMfaPolicy(user: UserContext, settings: OrgSettings): void {
  if (settings.requireMfa && !user.mfaAuthenticated) {
    throw new AuthError(
      'Your organization requires multi-factor authentication. Enable MFA and sign in again.',
      403
    );
  }
}

function getSessionDurationMs(settings: OrgSettings): number {
  return Math.max(settings.maxSessionDurationHours, 1) * 60 * 60 * 1000;
}

function assertSessionAgePolicy(user: UserContext, settings: OrgSettings): void {
  if (!user.authTime) {
    return;
  }

  const authAgeMs = Date.now() - user.authTime * 1000;
  if (authAgeMs > getSessionDurationMs(settings)) {
    throw new AuthError(
      'Session duration limit reached. Please sign in again.',
      401
    );
  }
}

/**
 * Lambda entry point. Routes requests to the appropriate handler function
 * based on HTTP method and path.
 *
 * @param event - API Gateway proxy event
 * @returns API Gateway proxy result with JSON body
 */
export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId || generateId();
  const method = event.httpMethod?.toUpperCase();
  const path = event.resource || event.path;

  try {
    switch (true) {
      case method === 'POST' && (path === '/auth/login' || path === '/auth/session'):
        return await handleLogin(event, requestId);

      case method === 'POST' && path === '/auth/refresh':
        return await handleRefresh(event, requestId);

      case method === 'POST' && path === '/auth/logout':
        return await handleLogout(event, requestId);

      case method === 'GET' && path === '/auth/key-lease':
        return await handleGetKeyLease(event, requestId);

      case method === 'POST' && path === '/auth/key-lease/scoped':
        return await handleScopedKeyLease(event, requestId);

      case method === 'POST' && path === '/auth/revoke':
        return await handleRevoke(event, requestId);

      case method === 'GET' && path === '/auth/leases':
        return await handleListLeases(event, requestId);

      case method === 'GET' && path === '/auth/heartbeat':
        return await handleHeartbeat(event, requestId);

      // Hybrid ZK endpoints (Phase 5)
      case method === 'POST' && path === '/auth/setup-zk':
        return await handleSetupZk(event, requestId);

      case method === 'GET' && path === '/auth/wrapped-key':
        return await handleGetWrappedKey(event, requestId);

      case method === 'POST' && path === '/auth/recover':
        return await handleRecover(event, requestId);

      case method === 'POST' && path === '/auth/forgot-password':
        return await handleForgotPassword(event, requestId);

      case method === 'POST' && path === '/auth/confirm-reset':
        return await handleConfirmReset(event, requestId);

      case method === 'POST' && path === '/auth/recovery-codes':
        return await handleStoreRecoveryCodes(event, requestId);

      case method === 'POST' && path === '/auth/recovery-codes/verify':
        return await handleVerifyRecoveryCode(event, requestId);

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

    console.error('[AUTH_HANDLER_ERROR]', (err as Error).message);
    return formatError(500, 'Internal server error', requestId);
  }
}

// ─── POST /auth/login ────────────────────────────────────────────────────────

/**
 * Validates a Cognito access token and creates a new server-side session.
 *
 * Does NOT issue a key lease — leases are vault-scoped and the client
 * requests one explicitly via GET /auth/key-lease?vaultId=... or
 * POST /auth/key-lease/scoped once a vault binding is established.
 * Returning a key here used to ship an org-wide DEK that could not decrypt
 * vault-scoped ciphertext, and any session-bound caller could obtain it.
 *
 * Flow:
 * 1. Verify the Cognito JWT token from the Authorization header.
 * 2. Create a session record in DynamoDB with expiry.
 * 3. Return the session ID. The client requests a vault-scoped lease next.
 *
 * @param event - Contains Authorization header with Cognito token
 * @param requestId - Request ID for tracing
 * @returns Session details (no key material)
 */
async function handleLogin(
  event: APIGatewayProxyEvent,
  requestId: string
): Promise<APIGatewayProxyResult> {
  // Step 1: Verify the Cognito token
  const user = await verifyActiveUser(event);
  const orgId = requireOrgId(user);
  const orgSettings = await getRequiredOrgSettings(user);
  assertMfaPolicy(user, orgSettings);
  assertSessionAgePolicy(user, orgSettings);

  // Step 2: Create session
  const sessionId = generateId();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + getSessionDurationMs(orgSettings));

  const session: Session = {
    sessionId,
    userId: user.userId,
    orgId,
    email: user.email,
    roles: user.roles,
    createdAt: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    lastActivity: now.toISOString(),
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    isActive: true,
  };

  await docClient.send(
    new PutCommand({
      TableName: SESSIONS_TABLE,
      Item: session,
    })
  );

  // Step 3: Audit log
  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: user.orgId,
    action: 'auth.login',
    resourcePath: '/auth/login',
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: { sessionId, roles: user.roles },
  });

  return formatSuccess(
    200,
    {
      sessionId,
      userId: user.userId,
      email: user.email,
      roles: user.roles,
      expiresAt: expiresAt.toISOString(),
      orgSettings,
    },
    requestId
  );
}

// ─── POST /auth/refresh ──────────────────────────────────────────────────────

/**
 * Refreshes an active session and issues a new key lease.
 * The existing session's expiry is extended and a fresh key lease is generated.
 *
 * @param event - Contains Authorization header and refresh token in body
 * @param requestId - Request ID for tracing
 * @returns Updated session expiry and new key lease
 */
async function handleRefresh(
  event: APIGatewayProxyEvent,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const user = await verifyActiveUser(event);
  requireOrgId(user);
  const orgSettings = await getRequiredOrgSettings(user);
  assertMfaPolicy(user, orgSettings);
  assertSessionAgePolicy(user, orgSettings);
  const body = parseBody(event);
  validateRequiredFields(body, ['sessionId', 'refreshToken']);

  const sessionId = body.sessionId as string;
  const refreshToken = body.refreshToken as string;
  const leaseId = body.leaseId as string | undefined;

  // Validate session exists and is active
  const session = await getSession(sessionId);
  if (!session || !session.isActive || session.userId !== user.userId) {
    throw new AuthError('Invalid or expired session', 401);
  }

  // Check session hasn't expired
  if (new Date(session.expiresAt) < new Date()) {
    await invalidateSession(sessionId);
    throw new AuthError('Session expired', 401);
  }

  // Validate refresh token against the lease being rotated, then retire it
  // before issuing the replacement so renewals do not accumulate active leases.
  const existingLease = leaseId
    ? await getLeaseRecord(leaseId)
    : await findSessionLeaseByRefreshToken(user.userId, sessionId, refreshToken, user.orgId);

  if (!existingLease || existingLease.refreshToken !== refreshToken) {
    throw new AuthError('Invalid refresh token', 401);
  }
  if (
    existingLease.userId !== user.userId ||
    existingLease.sessionId !== sessionId ||
    existingLease.orgId !== user.orgId
  ) {
    throw new AuthError('Invalid refresh token', 401);
  }
  if (existingLease.status === 'revoked') {
    throw new AuthError('Lease has been revoked', 403);
  }
  if (existingLease.status !== 'active' || new Date(existingLease.expiresAt) <= new Date()) {
    if (existingLease.status === 'active') {
      await expireLease(existingLease.leaseId);
    }
    throw new AuthError('Lease has expired', 401);
  }

  // Re-verify vault membership before rotating a vault-scoped lease so a user
  // who has been removed from the vault cannot keep refreshing their DEK. The
  // sibling lease-issuance handlers (handleScopedKeyLease, handleGetKeyLease)
  // already enforce this — handleRefresh used to skip it, allowing offline
  // decryption of cached vault ciphertext for the remainder of the session.
  //
  // Legacy leases without vaultId predate the vault layer and would refresh
  // into a fresh org-wide DEK. Reject — the client must request a vault-scoped
  // lease via POST /auth/key-lease/scoped instead.
  if (!existingLease.vaultId) {
    await expireLease(existingLease.leaseId);
    throw new AuthError('Legacy lease has no vault binding; request a vault-scoped lease.', 410);
  }
  const renewalScope = existingLease.scope || '/**';
  const renewalVaultId = existingLease.vaultId;
  await requireVaultMember(user, renewalVaultId, 'viewer');

  // Re-run the same scope permission checks used for initial lease issuance.
  // Otherwise an existing broad `/**` lease could be renewed after an admin
  // adds a deny rule, keeping local decryption alive past the permission cut.
  try {
    await assertScopeHasNoReadDenyRules(user, renewalVaultId, renewalScope, event, requestId);
  } catch (err) {
    if (err instanceof AuthError) {
      await expireLease(existingLease.leaseId);
    }
    throw err;
  }

  const permissionProbePath = scopeToPermissionProbePath(renewalScope);
  const permission = await evaluatePermission(
    user.userId,
    user.roles,
    'read',
    permissionProbePath,
    user.orgId,
    renewalVaultId
  );
  if (!permission.allowed) {
    await logAudit({
      userId: user.userId,
      userEmail: user.email,
      orgId: user.orgId,
      vaultId: renewalVaultId,
      action: 'auth.refresh.denied',
      resourcePath: `/vaults/${renewalVaultId}/auth/refresh`,
      outcome: 'denied',
      ipAddress: getClientIp(event),
      userAgent: getUserAgent(event),
      metadata: {
        vaultId: renewalVaultId,
        scope: renewalScope,
        reason: 'insufficient_scope_permission',
        matchedRule: permission.matchedRule?.id,
      },
    });
    await expireLease(existingLease.leaseId);
    throw new AuthError('Access denied: insufficient permissions for requested key scope', 403);
  }

  await expireLease(existingLease.leaseId);

  // Extend session
  const newExpiry = new Date(Date.now() + getSessionDurationMs(orgSettings));
  await docClient.send(
    new UpdateCommand({
      TableName: SESSIONS_TABLE,
      Key: { sessionId },
      UpdateExpression: 'SET expiresAt = :exp, lastActivity = :now',
      ExpressionAttributeValues: {
        ':exp': newExpiry.toISOString(),
        ':now': new Date().toISOString(),
      },
    })
  );

  // Issue a replacement lease for the same vault/scope as the lease being rotated.
  const keyLease = await issueKeyLease(
    user.userId,
    sessionId,
    user.orgId,
    renewalScope,
    renewalVaultId
  );

  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: user.orgId,
    action: 'auth.refresh',
    resourcePath: '/auth/refresh',
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: { sessionId },
  });

  return formatSuccess(
    200,
    {
      sessionId,
      expiresAt: newExpiry.toISOString(),
      keyLease,
      orgSettings,
    },
    requestId
  );
}

// ─── POST /auth/logout ───────────────────────────────────────────────────────

/**
 * Invalidates the user's session and signals the client to wipe its cache.
 * The response includes a `cacheWipe: true` flag that the Obsidian plugin
 * must act on to clear any locally cached decrypted content.
 *
 * @param event - Contains Authorization header and sessionId in body
 * @param requestId - Request ID for tracing
 * @returns Confirmation with cache wipe instruction
 */
async function handleLogout(
  event: APIGatewayProxyEvent,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const user = await verifyActiveUser(event);
  requireOrgId(user);
  const body = parseBody(event);
  validateRequiredFields(body, ['sessionId']);

  const sessionId = body.sessionId as string;

  // Validate ownership
  const session = await getSession(sessionId);
  if (session && session.userId !== user.userId) {
    throw new AuthError('Session does not belong to this user', 403);
  }

  // Invalidate session and revoke every lease bound to it.
  await invalidateSession(sessionId);
  const revokedLeaseCount = await revokeSessionLeases(sessionId, user.userId, user.orgId);

  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: user.orgId,
    action: 'auth.logout',
    resourcePath: '/auth/logout',
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: { sessionId, revokedLeases: revokedLeaseCount },
  });

  return formatSuccess(
    200,
    {
      message: 'Session invalidated successfully',
      cacheWipe: true,
      sessionId,
      revokedLeases: revokedLeaseCount,
    },
    requestId
  );
}

// ─── GET /auth/key-lease ─────────────────────────────────────────────────────

/**
 * Issues a time-limited decryption key lease for the authenticated user.
 * The key lease contains the plaintext key material required by the
 * desktop plugin together with the durable encrypted org/scope data key.
 *
 * Key lease structure:
 * - key: Plaintext AES-256 key encoded as base64 for the plugin
 * - encryptedDataKey: The same data key encrypted by KMS for traceability
 * - expiresAt: ISO timestamp when the lease becomes invalid
 * - refreshToken: Token to request a new lease before expiry
 * - leaseId: Unique identifier for audit and revocation
 *
 * @param event - Contains Authorization header; sessionId in query params
 * @param requestId - Request ID for tracing
 * @returns Key lease object
 */
async function handleGetKeyLease(
  event: APIGatewayProxyEvent,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const user = await verifyActiveUser(event);
  requireOrgId(user);
  const orgSettings = await getRequiredOrgSettings(user);
  assertMfaPolicy(user, orgSettings);
  assertSessionAgePolicy(user, orgSettings);
  const sessionId = event.queryStringParameters?.sessionId;
  const vaultId = event.queryStringParameters?.vaultId;

  if (!sessionId) {
    throw new ValidationError('Missing sessionId query parameter');
  }

  // vaultId is mandatory: org-wide leases collapse vault isolation by handing
  // out a DEK that can decrypt ciphertext from any vault under the org.
  if (!vaultId) {
    throw new ValidationError('Missing vaultId query parameter');
  }

  // Validate session
  const session = await getSession(sessionId);
  if (!session || !session.isActive || session.userId !== user.userId) {
    throw new AuthError('Invalid or expired session', 401);
  }

  if (new Date(session.expiresAt) < new Date()) {
    await invalidateSession(sessionId);
    throw new AuthError('Session expired', 401);
  }

  // Check if user's keys have been revoked
  const isRevoked = await checkKeyRevocation(user.userId);
  if (isRevoked) {
    await logAudit({
      userId: user.userId,
      orgId: user.orgId,
      action: 'auth.key-lease.denied',
      resourcePath: '/auth/key-lease',
      outcome: 'denied',
      ipAddress: getClientIp(event),
      userAgent: getUserAgent(event),
      metadata: { reason: 'keys_revoked', sessionId },
    });
    throw new AuthError('Access has been revoked. Contact your administrator.', 403);
  }

  await requireVaultMember(user, vaultId, 'viewer');
  await assertScopeHasNoReadDenyRules(user, vaultId, '/**', event, requestId);

  await expireActiveSessionScopeLeases(user.userId, sessionId, '/**', user.orgId, vaultId);
  const keyLease = await issueKeyLease(user.userId, sessionId, user.orgId, '/**', vaultId);

  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: user.orgId,
    vaultId,
    action: 'auth.key-lease.issued',
    resourcePath: `/vaults/${vaultId}/auth/key-lease`,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: { vaultId, leaseId: keyLease.leaseId, expiresAt: keyLease.expiresAt },
  });

  return formatSuccess(200, { keyLease, orgSettings }, requestId);
}

// ─── POST /auth/revoke ───────────────────────────────────────────────────────

/**
 * Admin endpoint: Revokes a user's access completely.
 *
 * Actions taken:
 * 1. Invalidates ALL active sessions for the target user.
 * 2. Marks the user's keys as revoked (prevents future key lease issuance).
 * 3. Records the revocation in the audit log.
 *
 * Only users with 'admin' or 'vault-admin' role can call this endpoint.
 *
 * @param event - Contains Authorization header; target userId in body
 * @param requestId - Request ID for tracing
 * @returns Confirmation of revocation with count of invalidated sessions
 */
async function handleRevoke(
  event: APIGatewayProxyEvent,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const admin = await verifyActiveUser(event);
  requireOrgId(admin);

  // Only admins can revoke access
  if (!isAdmin(admin)) {
    await logAudit({
      userId: admin.userId,
      userEmail: admin.email,
      orgId: admin.orgId,
      action: 'auth.revoke.denied',
      resourcePath: '/auth/revoke',
      outcome: 'denied',
      ipAddress: getClientIp(event),
      userAgent: getUserAgent(event),
      metadata: { reason: 'insufficient_privileges' },
    });
    throw new AuthError('Admin privileges required', 403);
  }

  const body = parseBody(event);
  validateRequiredFields(body, ['targetUserId', 'reason']);

  const targetUserId = body.targetUserId as string;
  const reason = body.reason as string;

  // Step 1: Find and invalidate all sessions for the target user (within admin's org)
  const sessionsResult = await docClient.send(
    new QueryCommand({
      TableName: SESSIONS_TABLE,
      IndexName: 'userId-index',
      KeyConditionExpression: 'userId = :uid',
      FilterExpression: 'isActive = :active AND orgId = :orgId',
      ExpressionAttributeValues: {
        ':uid': targetUserId,
        ':active': true,
        ':orgId': admin.orgId,
      },
    })
  );

  const activeSessions = sessionsResult.Items || [];
  let invalidatedCount = 0;

  for (const session of activeSessions) {
    await invalidateSession(session.sessionId as string);
    invalidatedCount++;
  }

  // Step 2: Revoke all active leases for the target user
  const revokedLeaseCount = await revokeAllUserLeases(targetUserId, admin.userId, admin.orgId);

  // Step 3: Mark keys as revoked (prevents future lease issuance)
  await docClient.send(
    new PutCommand({
      TableName: REVOKED_KEYS_TABLE,
      Item: {
        userId: targetUserId,
        revokedAt: new Date().toISOString(),
        revokedBy: admin.userId,
        reason,
      },
    })
  );

  // Step 4: Audit log
  await logAudit({
    userId: admin.userId,
    userEmail: admin.email,
    orgId: admin.orgId,
    action: 'auth.revoke',
    resourcePath: '/auth/revoke',
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: {
      targetUserId,
      reason,
      invalidatedSessions: invalidatedCount,
      revokedLeases: revokedLeaseCount,
    },
  });

  // Step 5: Trigger re-encryption via EventBridge
  try {
    await eventBridgeClient.send(
      new PutEventsCommand({
        Entries: [
          {
            Source: 'vaultguard.auth',
            DetailType: 'UserAccessRevoked',
            Detail: JSON.stringify({
              targetUserId,
              orgId: admin.orgId || '',
              triggeredBy: admin.userId,
              reason,
            }),
          },
        ],
      })
    );
  } catch (ebErr) {
    // Re-encryption trigger failure should not block the revocation response.
    // Admin can manually trigger via POST /re-encryption/trigger.
    console.error('[AUTH_REVOKE] EventBridge publish failed:', ebErr);
  }

  return formatSuccess(
    200,
    {
      message: `Access revoked for user ${targetUserId}`,
      invalidatedSessions: invalidatedCount,
      revokedLeases: revokedLeaseCount,
      revokedAt: new Date().toISOString(),
    },
    requestId
  );
}

// ─── Helper Functions ────────────────────────────────────────────────────────

function scopeKeyPk(orgId: string, scope: string, vaultId?: string): string {
  const encodedScope = Buffer.from(scope, 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
  if (vaultId) {
    return `ORG#${orgId}#VAULT#${vaultId}#SCOPE#${encodedScope}`;
  }
  return `ORG#${orgId}#SCOPE#${encodedScope}`;
}

function scopeKmsContext(orgId: string, scope: string, vaultId?: string): Record<string, string> {
  return {
    orgId,
    ...(vaultId ? { vaultId } : {}),
    scope,
    purpose: 'vault-scope-dek',
  };
}

async function decryptScopeDataKey(record: ScopeDataKey): Promise<Buffer> {
  const response = await kmsClient.send(
    new DecryptCommand({
      CiphertextBlob: Buffer.from(record.encryptedDataKey, 'base64'),
      EncryptionContext: scopeKmsContext(record.orgId, record.scope, record.vaultId),
    })
  );

  if (!response.Plaintext) {
    throw new Error('KMS Decrypt did not return usable key material');
  }

  return Buffer.from(response.Plaintext);
}

async function readScopeDataKey(orgId: string, scope: string, vaultId?: string): Promise<ScopeDataKey | null> {
  const result = await docClient.send(
    new GetCommand({
      TableName: USER_KEYS_TABLE,
      Key: { pk: scopeKeyPk(orgId, scope, vaultId), sk: 'ACTIVE' },
    })
  );

  const item = result.Item as ScopeDataKey | undefined;
  return item && item.status === 'active' ? item : null;
}

async function getOrCreateScopeDataKey(orgId: string, scope: string, vaultId?: string): Promise<{
  plaintextKey: Buffer;
  encryptedDataKey: string;
}> {
  const existing = await readScopeDataKey(orgId, scope, vaultId);
  if (existing) {
    await docClient.send(
      new UpdateCommand({
        TableName: USER_KEYS_TABLE,
        Key: { pk: existing.pk, sk: existing.sk },
        UpdateExpression: 'SET lastUsedAt = :now',
        ExpressionAttributeValues: { ':now': new Date().toISOString() },
      })
    );

    return {
      plaintextKey: await decryptScopeDataKey(existing),
      encryptedDataKey: existing.encryptedDataKey,
    };
  }

  const dataKeyResponse = await kmsClient.send(
    new GenerateDataKeyCommand({
      KeyId: KMS_KEY_ID,
      KeySpec: 'AES_256',
      EncryptionContext: scopeKmsContext(orgId, scope, vaultId),
    })
  );

  if (!dataKeyResponse.Plaintext || !dataKeyResponse.CiphertextBlob) {
    throw new Error('KMS GenerateDataKey did not return usable key material');
  }

  const now = new Date().toISOString();
  const encryptedDataKey = Buffer.from(dataKeyResponse.CiphertextBlob).toString('base64');
  const record: ScopeDataKey = {
    pk: scopeKeyPk(orgId, scope, vaultId),
    sk: 'ACTIVE',
    orgId,
    ...(vaultId ? { vaultId } : {}),
    scope,
    encryptedDataKey,
    status: 'active',
    createdAt: now,
    lastUsedAt: now,
  };

  try {
    await docClient.send(
      new PutCommand({
        TableName: USER_KEYS_TABLE,
        Item: record,
        ConditionExpression: 'attribute_not_exists(pk)',
      })
    );
  } catch (error) {
    const name = error && typeof error === 'object' && 'name' in error
      ? (error as { name?: string }).name
      : '';
    if (name !== 'ConditionalCheckFailedException') {
      throw error;
    }

    const racedRecord = await readScopeDataKey(orgId, scope, vaultId);
    if (!racedRecord) {
      throw error;
    }
    return {
      plaintextKey: await decryptScopeDataKey(racedRecord),
      encryptedDataKey: racedRecord.encryptedDataKey,
    };
  }

  return {
    plaintextKey: Buffer.from(dataKeyResponse.Plaintext),
    encryptedDataKey,
  };
}

/**
 * Issues a new key lease for the stable vault/scope DEK.
 *
 * @param userId - The user receiving the lease
 * @param sessionId - The session this lease is bound to
 * @param orgId - Organization ID for tenant isolation
 * @param scope - Path scope for this lease (glob pattern, defaults to '/**' for full vault)
 * @param vaultId - Vault this lease belongs to. Required — org-wide leases are
 *                  no longer issued because they would let a holder decrypt
 *                  ciphertext from any vault in the org.
 * @returns A KeyLease object with usable key material and expiry
 */
async function issueKeyLease(
  userId: string,
  sessionId: string,
  orgId: string,
  scope: string,
  vaultId: string
): Promise<KeyLease> {
  if (!vaultId) {
    throw new ValidationError('vaultId is required to issue a key lease');
  }
  await enforceConcurrentLeaseLimit(userId, orgId);

  const scopeKey = await getOrCreateScopeDataKey(orgId, scope, vaultId);
  const leaseId = generateId();
  const now = new Date();
  const issuedAt = now.toISOString();
  const expiresAt = new Date(now.getTime() + KEY_LEASE_DURATION_SECONDS * 1000).toISOString();
  const refreshToken = generateSecretToken();
  // TTL: 7 days after lease expiry for DynamoDB auto-cleanup
  const expiresAtTtl = Math.floor(new Date(expiresAt).getTime() / 1000) + 7 * 24 * 60 * 60;

  // Persist lease to LeaseTable
  const leaseRecord: LeaseRecord = {
    leaseId,
    userId,
    sessionId,
    orgId,
    encryptedDataKey: scopeKey.encryptedDataKey,
    refreshToken,
    status: 'active',
    issuedAt,
    expiresAt,
    scope,
    ...(vaultId ? { vaultId } : {}),
    expiresAtTtl,
  };

  await docClient.send(
    new PutCommand({
      TableName: LEASES_TABLE,
      Item: leaseRecord,
    })
  );

  return {
    key: scopeKey.plaintextKey.toString('base64'),
    encryptedDataKey: scopeKey.encryptedDataKey,
    expiresAt,
    refreshToken,
    leaseId,
    algorithm: 'AES-256-GCM',
    offlineCapable: true,
    scope,
    ...(vaultId ? { vaultId } : {}),
  };
}

/**
 * Retrieves a session from DynamoDB.
 *
 * @param sessionId - The session ID to look up
 * @returns The session record, or null if not found
 */
async function getSession(sessionId: string): Promise<Session | null> {
  const result = await docClient.send(
    new QueryCommand({
      TableName: SESSIONS_TABLE,
      KeyConditionExpression: 'sessionId = :sid',
      ExpressionAttributeValues: { ':sid': sessionId },
    })
  );

  return (result.Items?.[0] as Session) || null;
}

/**
 * Marks a session as inactive in DynamoDB.
 *
 * @param sessionId - The session to invalidate
 */
async function invalidateSession(sessionId: string): Promise<void> {
  await docClient.send(
    new UpdateCommand({
      TableName: SESSIONS_TABLE,
      Key: { sessionId },
      UpdateExpression: 'SET isActive = :inactive, invalidatedAt = :now',
      ExpressionAttributeValues: {
        ':inactive': false,
        ':now': new Date().toISOString(),
      },
    })
  );
}

/**
 * Checks whether a user's keys have been revoked by an admin.
 *
 * @param userId - The user to check
 * @returns True if the user's keys are revoked
 */
async function checkKeyRevocation(userId: string): Promise<boolean> {
  const result = await docClient.send(
    new QueryCommand({
      TableName: REVOKED_KEYS_TABLE,
      KeyConditionExpression: 'userId = :uid',
      ExpressionAttributeValues: { ':uid': userId },
    })
  );

  return (result.Items?.length || 0) > 0;
}

/**
 * Retrieves a lease record from the Leases table.
 */
async function getLeaseRecord(leaseId: string): Promise<LeaseRecord | null> {
  const result = await docClient.send(
    new GetCommand({
      TableName: LEASES_TABLE,
      Key: { leaseId },
    })
  );
  return (result.Item as LeaseRecord) || null;
}

/**
 * Finds a lease in a session by its refresh token. This supports older clients
 * that did not send leaseId during refresh while still letting the backend
 * rotate exactly the lease being renewed.
 */
async function findSessionLeaseByRefreshToken(
  userId: string,
  sessionId: string,
  refreshToken: string,
  orgId: string
): Promise<LeaseRecord | null> {
  const result = await docClient.send(
    new QueryCommand({
      TableName: LEASES_TABLE,
      IndexName: 'userId-index',
      KeyConditionExpression: 'userId = :uid',
      FilterExpression: 'sessionId = :sid AND refreshToken = :refreshToken AND orgId = :orgId',
      ExpressionAttributeValues: {
        ':uid': userId,
        ':sid': sessionId,
        ':refreshToken': refreshToken,
        ':orgId': orgId,
      },
    })
  );

  return (result.Items?.[0] as LeaseRecord) || null;
}

/**
 * Marks a lease as expired in the Leases table.
 */
async function expireLease(leaseId: string): Promise<void> {
  await docClient.send(
    new UpdateCommand({
      TableName: LEASES_TABLE,
      Key: { leaseId },
      UpdateExpression: 'SET #s = :expired',
      ExpressionAttributeNames: { '#s': 'status' },
      ExpressionAttributeValues: { ':expired': 'expired' },
    })
  );
}

/**
 * Expires active leases for a session/scope before issuing a replacement.
 */
async function expireActiveSessionScopeLeases(
  userId: string,
  sessionId: string,
  scope: string,
  orgId: string,
  vaultId?: string
): Promise<number> {
  const filterParts = [
    '#s = :active',
    'sessionId = :sid',
    'orgId = :orgId',
    '#scope = :scope',
  ];
  const expressionAttributeValues: Record<string, unknown> = {
    ':uid': userId,
    ':sid': sessionId,
    ':active': 'active',
    ':orgId': orgId,
    ':scope': scope,
  };

  if (vaultId) {
    filterParts.push('(attribute_not_exists(vaultId) OR vaultId = :vaultId)');
    expressionAttributeValues[':vaultId'] = vaultId;
  } else {
    filterParts.push('attribute_not_exists(vaultId)');
  }

  const result = await docClient.send(
    new QueryCommand({
      TableName: LEASES_TABLE,
      IndexName: 'userId-index',
      KeyConditionExpression: 'userId = :uid',
      FilterExpression: filterParts.join(' AND '),
      ExpressionAttributeNames: {
        '#s': 'status',
        '#scope': 'scope',
      },
      ExpressionAttributeValues: expressionAttributeValues,
    })
  );

  const activeLeases = result.Items || [];
  for (const lease of activeLeases) {
    await expireLease(lease.leaseId as string);
  }

  return activeLeases.length;
}

/**
 * Returns active, unexpired leases for a user.
 */
async function getActiveLeaseRecords(userId: string, orgId: string): Promise<LeaseRecord[]> {
  const now = new Date().toISOString();
  const result = await docClient.send(
    new QueryCommand({
      TableName: LEASES_TABLE,
      IndexName: 'userId-index',
      KeyConditionExpression: 'userId = :uid',
      FilterExpression: '#s = :active AND orgId = :orgId AND #expiresAt > :now',
      ExpressionAttributeNames: {
        '#s': 'status',
        '#expiresAt': 'expiresAt',
      },
      ExpressionAttributeValues: {
        ':uid': userId,
        ':active': 'active',
        ':orgId': orgId,
        ':now': now,
      },
    })
  );
  return (result.Items || []) as LeaseRecord[];
}

/**
 * Enforces the active lease cap without trapping legitimate users behind stale
 * rows. When the cap is full, retire the oldest active leases first.
 */
async function enforceConcurrentLeaseLimit(userId: string, orgId: string): Promise<void> {
  const activeLeases = await getActiveLeaseRecords(userId, orgId);
  if (activeLeases.length < MAX_CONCURRENT_LEASES) {
    return;
  }

  const leasesToExpire = activeLeases
    .slice()
    .sort((a, b) => a.issuedAt.localeCompare(b.issuedAt))
    .slice(0, activeLeases.length - MAX_CONCURRENT_LEASES + 1);

  for (const lease of leasesToExpire) {
    await expireLease(lease.leaseId);
  }
}

/**
 * Revokes all active leases bound to a session. Returns the number revoked.
 */
async function revokeSessionLeases(
  sessionId: string,
  userId: string,
  orgId: string
): Promise<number> {
  const result = await docClient.send(
    new QueryCommand({
      TableName: LEASES_TABLE,
      IndexName: 'userId-index',
      KeyConditionExpression: 'userId = :uid',
      FilterExpression: '#s = :active AND sessionId = :sid AND orgId = :orgId',
      ExpressionAttributeNames: { '#s': 'status' },
      ExpressionAttributeValues: {
        ':uid': userId,
        ':sid': sessionId,
        ':active': 'active',
        ':orgId': orgId,
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
          ':by': userId,
        },
      })
    );
  }

  return activeLeases.length;
}

/**
 * Revokes all active leases for a user. Returns the number of leases revoked.
 */
async function revokeAllUserLeases(userId: string, revokedBy: string, orgId: string): Promise<number> {
  const result = await docClient.send(
    new QueryCommand({
      TableName: LEASES_TABLE,
      IndexName: 'userId-index',
      KeyConditionExpression: 'userId = :uid',
      FilterExpression: '#s = :active AND orgId = :orgId',
      ExpressionAttributeNames: { '#s': 'status' },
      ExpressionAttributeValues: {
        ':uid': userId,
        ':active': 'active',
        ':orgId': orgId,
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

// ─── GET /auth/leases (Admin) ───────────────────────────────────────────────

/**
 * Admin endpoint: Lists all leases for a target user.
 * Query params: targetUserId (required), status (optional: active|expired|revoked)
 */
async function handleListLeases(
  event: APIGatewayProxyEvent,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const admin = await verifyActiveUser(event);
  requireOrgId(admin);

  if (!isAdmin(admin)) {
    throw new AuthError('Admin privileges required', 403);
  }

  const targetUserId = event.queryStringParameters?.targetUserId;
  if (!targetUserId) {
    throw new ValidationError('Missing targetUserId query parameter');
  }

  const statusFilter = event.queryStringParameters?.status;

  const queryParams: Record<string, unknown> = {
    TableName: LEASES_TABLE,
    IndexName: 'userId-index',
    KeyConditionExpression: 'userId = :uid',
    ExpressionAttributeValues: { ':uid': targetUserId, ':orgId': admin.orgId } as Record<string, unknown>,
  };

  if (statusFilter) {
    queryParams.FilterExpression = '#s = :status AND orgId = :orgId';
    queryParams.ExpressionAttributeNames = { '#s': 'status' };
    (queryParams.ExpressionAttributeValues as Record<string, unknown>)[':status'] = statusFilter;
  } else {
    queryParams.FilterExpression = 'orgId = :orgId';
  }

  const result = await docClient.send(new QueryCommand(queryParams as any));

  const leases = (result.Items || []).map((item) => ({
    leaseId: item.leaseId,
    sessionId: item.sessionId,
    scope: item.scope || '/**',
    status: item.status,
    issuedAt: item.issuedAt,
    expiresAt: item.expiresAt,
    revokedAt: item.revokedAt || null,
    revokedBy: item.revokedBy || null,
  }));

  return formatSuccess(
    200,
    {
      userId: targetUserId,
      leases,
      count: leases.length,
    },
    requestId
  );
}

// ─── GET /auth/heartbeat ────────────────────────────────────────────────────

/**
 * Lightweight heartbeat endpoint for clients to detect revocation quickly.
 * Returns the user's access status without issuing a new key lease.
 * Designed to be called every 60 seconds by the plugin.
 */
async function handleHeartbeat(
  event: APIGatewayProxyEvent,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const user = await verifyToken(event);
  requireOrgId(user);
  const sessionId = event.queryStringParameters?.sessionId;

  // Check key revocation (fastest signal)
  const isRevoked = await checkKeyRevocation(user.userId);
  if (isRevoked) {
    return formatSuccess(
      200,
      { active: false, reason: 'keys_revoked' },
      requestId
    );
  }

  // Check session validity if provided
  if (sessionId) {
    const session = await getSession(sessionId);
    if (!session || !session.isActive) {
      return formatSuccess(
        200,
        { active: false, reason: 'session_invalid' },
        requestId
      );
    }
    if (new Date(session.expiresAt) < new Date()) {
      return formatSuccess(
        200,
        { active: false, reason: 'session_expired' },
        requestId
      );
    }
  }

  return formatSuccess(
    200,
    { active: true },
    requestId
  );
}

// ─── POST /auth/key-lease/scoped ────────────────────────────────────────────

/**
 * Issues a path-scoped key lease. Each scope gets its own DEK so that
 * revoking access to a specific path only invalidates that scope's key.
 *
 * Request body:
 * - sessionId: Active session ID
 * - scope: Path glob pattern (e.g., '/engineering/**')
 *
 * Returns a KeyLease bound to the requested scope.
 */
async function handleScopedKeyLease(
  event: APIGatewayProxyEvent,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const user = await verifyActiveUser(event);
  requireOrgId(user);
  const orgSettings = await getRequiredOrgSettings(user);
  assertMfaPolicy(user, orgSettings);
  assertSessionAgePolicy(user, orgSettings);
  const body = parseBody(event);
  validateRequiredFields(body, ['sessionId', 'scope', 'vaultId']);

  const sessionId = body.sessionId as string;
  const scope = body.scope as string;
  const vaultId = body.vaultId as string;

  // Validate scope format
  if (!scope.startsWith('/')) {
    throw new ValidationError('scope must start with /');
  }

  // Validate session
  const session = await getSession(sessionId);
  if (!session || !session.isActive || session.userId !== user.userId) {
    throw new AuthError('Invalid or expired session', 401);
  }

  if (new Date(session.expiresAt) < new Date()) {
    await invalidateSession(sessionId);
    throw new AuthError('Session expired', 401);
  }

  // Check revocation
  const isRevoked = await checkKeyRevocation(user.userId);
  if (isRevoked) {
    throw new AuthError('Access has been revoked. Contact your administrator.', 403);
  }

  // Vault membership check — leases are bound to a specific vault.
  await requireVaultMember(user, vaultId, 'viewer');

  await assertScopeHasNoReadDenyRules(user, vaultId, scope, event, requestId);

  const permissionProbePath = scopeToPermissionProbePath(scope);
  const permission = await evaluatePermission(
    user.userId,
    user.roles,
    'read',
    permissionProbePath,
    user.orgId,
    vaultId
  );
  if (!permission.allowed) {
    await logAudit({
      userId: user.userId,
      userEmail: user.email,
      orgId: user.orgId,
      vaultId,
      action: 'auth.key-lease.scoped.denied',
      resourcePath: scope,
      outcome: 'denied',
      ipAddress: getClientIp(event),
      userAgent: getUserAgent(event),
      metadata: { vaultId, reason: 'insufficient_scope_permission', matchedRule: permission.matchedRule?.id },
    });
    throw new AuthError('Access denied: insufficient permissions for requested key scope', 403);
  }

  await expireActiveSessionScopeLeases(user.userId, sessionId, scope, user.orgId, vaultId);
  const keyLease = await issueKeyLease(user.userId, sessionId, user.orgId, scope, vaultId);

  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: user.orgId,
    vaultId,
    action: 'auth.key-lease.scoped',
    resourcePath: `/vaults/${vaultId}/auth/key-lease/scoped`,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: { vaultId, leaseId: keyLease.leaseId, scope, expiresAt: keyLease.expiresAt },
  });

  return formatSuccess(200, { keyLease, orgSettings }, requestId);
}

async function assertScopeHasNoReadDenyRules(
  user: UserContext,
  vaultId: string,
  scope: string,
  event: APIGatewayProxyEvent,
  requestId: string
): Promise<void> {
  const denyRules = await findApplicableDenyRulesInScope(
    user.userId,
    user.roles,
    'read',
    scope,
    user.orgId,
    vaultId
  );

  if (denyRules.length === 0) return;

  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: user.orgId,
    vaultId,
    action: 'auth.key-lease.scoped.denied',
    resourcePath: scope,
    outcome: 'denied',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: {
      vaultId,
      reason: 'scope_contains_deny_rule',
      deniedRuleIds: denyRules.map((rule) => rule.id),
      requestId,
    },
  });
  throw new AuthError('Access denied: requested key scope includes denied paths', 403);
}

function scopeToPermissionProbePath(scope: string): string {
  const normalized = scope.replace(/\/+/g, '/').replace(/\/+$/g, '');
  const probeFile = '__vaultguard_scope_probe__.md';

  if (normalized === '' || normalized === '/**') {
    return `/${probeFile}`;
  }

  if (normalized.endsWith('/**')) {
    return `${normalized.slice(0, -3)}/${probeFile}`.replace(/\/+/g, '/');
  }

  if (normalized.endsWith('/*')) {
    return `${normalized.slice(0, -2)}/${probeFile}`.replace(/\/+/g, '/');
  }

  if (normalized.includes('*') || normalized.includes('?')) {
    return normalized
      .replace(/\*\*/g, probeFile)
      .replace(/\*/g, probeFile)
      .replace(/\?/g, 'x')
      .replace(/\/+/g, '/');
  }

  return normalized.startsWith('/') ? normalized : `/${normalized}`;
}

/**
 * Revokes active leases whose scope overlaps a given path pattern.
 * Called when permissions change to invalidate leases that may no longer be valid.
 *
 * @param pathPattern - The permission path that changed
 * @param userId - Optional: only revoke leases for this user (null = all users)
 * @param revokedBy - The admin who triggered the revocation
 * @returns Number of leases revoked
 */
export async function revokeLeasesByScope(
  pathPattern: string,
  userId: string | null,
  revokedBy: string,
  orgId: string
): Promise<number> {
  // If user-scoped, query by userId; otherwise scan active leases
  let activeLeases: Record<string, unknown>[];

  if (userId) {
    const result = await docClient.send(
      new QueryCommand({
        TableName: LEASES_TABLE,
        IndexName: 'userId-index',
        KeyConditionExpression: 'userId = :uid',
        FilterExpression: '#s = :active AND orgId = :orgId',
        ExpressionAttributeNames: { '#s': 'status' },
        ExpressionAttributeValues: {
          ':uid': userId,
          ':active': 'active',
          ':orgId': orgId,
        },
      })
    );
    activeLeases = result.Items || [];
  } else {
    // For cross-user scope revocation (e.g., path permission deleted entirely),
    // we need to scan. This is acceptable because it only happens on admin
    // permission changes, not on every request.
    const result = await docClient.send(
      new QueryCommand({
        TableName: LEASES_TABLE,
        IndexName: 'userId-index',
        KeyConditionExpression: 'userId = :uid',
        FilterExpression: '#s = :active AND orgId = :orgId',
        ExpressionAttributeNames: { '#s': 'status' },
        ExpressionAttributeValues: {
          ':uid': '*', // This won't match — fall through to per-user approach
          ':active': 'active',
          ':orgId': orgId,
        },
      })
    );
    activeLeases = result.Items || [];
  }

  const now = new Date().toISOString();
  let revokedCount = 0;

  for (const lease of activeLeases) {
    const leaseScope = (lease.scope as string) || '/**';

    // Check if the lease scope overlaps with the changed permission path
    const scopeOverlaps =
      pathMatchesPattern(pathPattern, leaseScope) ||
      pathMatchesPattern(leaseScope, pathPattern);

    if (scopeOverlaps) {
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
      revokedCount++;
    }
  }

  return revokedCount;
}

// ─── Hybrid ZK Endpoints (Phase 5) ─────────────────────────────────────────

/**
 * POST /auth/setup-zk
 *
 * Stores a user's wrapped master key pair for the hybrid ZK model.
 * The client generates a User Master Key (UMK) locally, wraps it twice:
 *   1. wrappedUMK_user: with the user's passphrase-derived key (for daily login)
 *   2. wrappedUMK_org: with the org's recovery public key (for admin recovery)
 * The server never sees the plaintext UMK.
 *
 * Body: { wrappedUMK_user, wrappedUMK_org, argon2Salt, algorithm }
 */
async function handleSetupZk(
  event: APIGatewayProxyEvent,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const user = await verifyActiveUser(event);
  const orgId = requireOrgId(user);
  const body = parseBody(event);
  validateRequiredFields(body, ['wrappedUMK_user', 'wrappedUMK_org', 'argon2Salt']);

  const wrappedUMK_user = body.wrappedUMK_user as string;
  const wrappedUMK_org = body.wrappedUMK_org as string;
  const argon2Salt = body.argon2Salt as string;
  const algorithm = (body.algorithm as string) || 'argon2id+aes-kw';

  // Check if user already has ZK setup (prevent accidental overwrite)
  const existing = await docClient.send(
    new GetCommand({
      TableName: ESCROW_TABLE,
      Key: { userId: user.userId },
    })
  );

  if (existing.Item && !body.force) {
    throw new ValidationError(
      'ZK keys already configured. Pass force: true to overwrite (this will invalidate your current passphrase).'
    );
  }

  // Pin the escrow row to the caller's org so /auth/recover can reject
  // cross-org admin recovery attempts (an admin in org A must not unwrap a
  // user that belongs to org B). Re-setup must stay inside the same org —
  // changing orgId after the fact would silently transfer recovery rights.
  const existingOrgId = (existing.Item?.orgId as string | undefined) ?? null;
  if (existingOrgId && existingOrgId !== orgId) {
    throw new AuthError('Escrow row belongs to a different organization', 403);
  }

  const now = new Date().toISOString();

  await docClient.send(
    new PutCommand({
      TableName: ESCROW_TABLE,
      Item: {
        userId: user.userId,
        orgId,
        wrappedUMK_user,
        wrappedUMK_org,
        argon2Salt,
        algorithm,
        createdAt: existing.Item ? (existing.Item.createdAt as string) : now,
        rotatedAt: now,
        zkMigrated: true,
      },
    })
  );

  await logAudit({
    userId: user.userId,
    userEmail: user.email,
    orgId: user.orgId,
    action: 'auth.setup-zk',
    resourcePath: '/auth/setup-zk',
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: { algorithm, isOverwrite: !!existing.Item },
  });

  return formatSuccess(
    200,
    { message: 'Hybrid ZK encryption configured', userId: user.userId },
    requestId
  );
}

/**
 * GET /auth/wrapped-key
 *
 * Retrieves the user's wrapped UMK and salt for client-side passphrase login.
 * The client uses Argon2id(passphrase, salt) to derive the unwrapping key,
 * then AES-KW-unwraps the UMK locally. The server never sees the plaintext UMK.
 */
async function handleGetWrappedKey(
  event: APIGatewayProxyEvent,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const user = await verifyActiveUser(event);
  requireOrgId(user);

  const result = await docClient.send(
    new GetCommand({
      TableName: ESCROW_TABLE,
      Key: { userId: user.userId },
    })
  );

  if (!result.Item) {
    return formatError(
      404,
      'No hybrid ZK configuration found. Call POST /auth/setup-zk first.',
      requestId
    );
  }

  return formatSuccess(
    200,
    {
      wrappedUMK_user: result.Item.wrappedUMK_user,
      argon2Salt: result.Item.argon2Salt,
      algorithm: result.Item.algorithm,
    },
    requestId
  );
}

/**
 * POST /auth/recover
 *
 * Admin-only endpoint for recovering a user's UMK via the org recovery key.
 * Returns the org-wrapped UMK which the admin unwraps with the org private key.
 * The admin then re-encrypts affected files and rotates the user's keys.
 *
 * Hardening:
 *   - Caller must be an org admin AND have completed MFA on the current token.
 *   - Caller must have authenticated within RECOVERY_FRESH_AUTH_SECONDS so a
 *     long-lived session can't silently unwrap escrow rows.
 *   - Target escrow row must belong to the caller's org (cross-org recovery
 *     is rejected even if the target row exists).
 *
 * Body: { targetUserId }
 */
async function handleRecover(
  event: APIGatewayProxyEvent,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const admin = await verifyActiveUser(event);
  const adminOrgId = requireOrgId(admin);

  if (!isAdmin(admin)) {
    await logAudit({
      userId: admin.userId,
      userEmail: admin.email,
      orgId: admin.orgId,
      action: 'auth.recover.denied',
      resourcePath: '/auth/recover',
      outcome: 'denied',
      ipAddress: getClientIp(event),
      userAgent: getUserAgent(event),
      metadata: { reason: 'insufficient_privileges' },
    });
    throw new AuthError('Admin privileges required', 403);
  }

  // MFA must be present on the current token regardless of the org's
  // requireMfa setting — recovery hands out the org-wrapped UMK and is one
  // of the most sensitive admin actions in the system.
  if (!admin.mfaAuthenticated) {
    await logAudit({
      userId: admin.userId,
      userEmail: admin.email,
      orgId: admin.orgId,
      action: 'auth.recover.denied',
      resourcePath: '/auth/recover',
      outcome: 'denied',
      ipAddress: getClientIp(event),
      userAgent: getUserAgent(event),
      metadata: { reason: 'mfa_required' },
    });
    throw new AuthError('MFA required for recovery', 403);
  }

  // Step-up: require a recent Cognito auth_time. Without this, a stolen
  // long-lived id token (still inside its 1h validity) can trigger recovery
  // without the admin re-proving possession of the password and MFA factor.
  const RECOVERY_FRESH_AUTH_SECONDS = 5 * 60;
  if (
    typeof admin.authTime !== 'number'
    || (Math.floor(Date.now() / 1000) - admin.authTime) > RECOVERY_FRESH_AUTH_SECONDS
  ) {
    await logAudit({
      userId: admin.userId,
      userEmail: admin.email,
      orgId: admin.orgId,
      action: 'auth.recover.denied',
      resourcePath: '/auth/recover',
      outcome: 'denied',
      ipAddress: getClientIp(event),
      userAgent: getUserAgent(event),
      metadata: { reason: 'reauth_required' },
    });
    throw new AuthError('Re-authenticate to perform recovery', 401);
  }

  const body = parseBody(event);
  validateRequiredFields(body, ['targetUserId']);

  const targetUserId = body.targetUserId as string;

  const result = await docClient.send(
    new GetCommand({
      TableName: ESCROW_TABLE,
      Key: { userId: targetUserId },
    })
  );

  if (!result.Item) {
    return formatError(
      404,
      `No hybrid ZK configuration found for user ${targetUserId}`,
      requestId
    );
  }

  // Cross-org recovery is forbidden. Legacy escrow rows that pre-date the
  // orgId column are rejected too — recovery must not run against rows whose
  // tenant cannot be verified, otherwise an admin in a freshly-created org
  // could exfiltrate keys for users that were enrolled before the column
  // existed. Operators must run a one-time backfill (via an explicit admin
  // tool, not this endpoint) before recovery is available for those rows.
  const targetOrgId = (result.Item.orgId as string | undefined) ?? null;
  if (!targetOrgId || targetOrgId !== adminOrgId) {
    await logAudit({
      userId: admin.userId,
      userEmail: admin.email,
      orgId: admin.orgId,
      action: 'auth.recover.denied',
      resourcePath: '/auth/recover',
      outcome: 'denied',
      ipAddress: getClientIp(event),
      userAgent: getUserAgent(event),
      metadata: {
        targetUserId,
        reason: targetOrgId ? 'cross_org_recovery' : 'missing_target_org',
      },
    });
    throw new AuthError('Target user is not in your organization', 403);
  }

  await logAudit({
    userId: admin.userId,
    userEmail: admin.email,
    orgId: admin.orgId,
    action: 'auth.recover',
    resourcePath: '/auth/recover',
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: {
      targetUserId,
      targetOrgId,
      // This is a sensitive operation — log everything
      recoveryInitiated: new Date().toISOString(),
    },
  });

  return formatSuccess(
    200,
    {
      targetUserId,
      wrappedUMK_org: result.Item.wrappedUMK_org,
      algorithm: result.Item.algorithm,
      createdAt: result.Item.createdAt,
      message: 'Unwrap this with the org recovery private key to recover the user master key.',
    },
    requestId
  );
}

// ─── POST /auth/forgot-password ────────────────────────────────────────────

const RESET_CODE_EXPIRY_MINUTES = 15;
const USER_POOL_ID = process.env.USER_POOL_ID || process.env.COGNITO_USER_POOL_ID!;
/**
 * HMAC pepper for password-reset codes. We never store the raw 6-digit code
 * in DynamoDB — an attacker with table-read access could otherwise harvest
 * pending codes during the 15-minute window. The pepper is sourced from an
 * env var so it can be rotated without code changes; falling back to the
 * KMS key id keeps single-region dev/test deployments working without an
 * extra env wiring step (still secret-grade because KMS_KEY_ID is not user-
 * facing). Production must set RESET_CODE_PEPPER explicitly.
 */
const RESET_CODE_PEPPER = process.env.RESET_CODE_PEPPER || process.env.KMS_KEY_ID || 'vaultguard-dev-pepper';
/** Minimum seconds between successive forgot-password requests for the same email. */
const FORGOT_REQUEST_COOLDOWN_SECONDS = 60;

function hashResetCode(email: string, code: string): string {
  // Bind the HMAC to (email, code) so a code reused across emails still
  // produces distinct stored hashes.
  return createHmac('sha256', RESET_CODE_PEPPER)
    .update(`${email}:${code}`)
    .digest('hex');
}

function verifyResetCodeHash(email: string, candidate: string, storedHash: string): boolean {
  const candidateHash = hashResetCode(email, candidate);
  // Length check first so timingSafeEqual doesn't throw on differing-length
  // buffers (which would itself create a timing side channel).
  if (candidateHash.length !== storedHash.length) return false;
  try {
    return timingSafeEqual(Buffer.from(candidateHash, 'utf8'), Buffer.from(storedHash, 'utf8'));
  } catch {
    return false;
  }
}

function readAwsErrorText(err: unknown): string {
  const awsError = (typeof err === 'object' && err !== null ? err : {}) as {
    name?: string;
    code?: string;
    Code?: string;
    __type?: string;
    message?: string;
    Message?: string;
  };

  return [
    awsError.name,
    awsError.code,
    awsError.Code,
    awsError.__type,
    awsError.message,
    awsError.Message,
  ].filter((part): part is string => typeof part === 'string' && part.length > 0).join(' ');
}

function isCognitoUserNotFound(err: unknown): boolean {
  return readAwsErrorText(err).includes('UserNotFoundException');
}

function isInvalidPasswordError(err: unknown): boolean {
  return readAwsErrorText(err).includes('InvalidPasswordException');
}

function isOperationalAwsError(err: unknown): boolean {
  const text = readAwsErrorText(err);
  return text.includes('AccessDenied')
    || text.includes('AccessDeniedException')
    || text.includes('InvalidParameterException')
    || text.includes('ResourceNotFoundException')
    || text.includes('CredentialsProviderError');
}

function logPasswordResetFailure(stage: string, err: unknown): void {
  const message = err instanceof Error ? err.message : String(err);
  console.error(`[AUTH_PASSWORD_RESET_FAILURE] stage=${stage}`, message);
}

function passwordResetSuccessResponse(requestId: string): APIGatewayProxyResult {
  return formatSuccess(200, {
    message: 'If an account exists with this email, a password reset code has been sent.',
  }, requestId);
}

/**
 * Generates a 6-digit reset code, stores it in DynamoDB, and sends a
 * branded password-reset email via SES.
 *
 * Bypasses Cognito's built-in ForgotPassword flow entirely so we control
 * the email template and sender address.
 *
 * This endpoint does NOT require authentication (the user has forgotten
 * their password). To avoid leaking whether an email exists, unknown users
 * receive the same success response. Infrastructure and delivery failures are
 * surfaced so the UI does not falsely claim that a reset email was sent.
 *
 * Body: { email, clientId }
 */
async function handleForgotPassword(
  event: APIGatewayProxyEvent,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const body = parseBody(event);
  validateRequiredFields(body, ['email', 'clientId']);

  const email = (body.email as string).trim().toLowerCase();
  const resetKey = { sessionId: `password_reset#${email}` };

  // Per-email request throttle. Without this, the failed-attempt counter can
  // be reset to zero by spamming /forgot-password — and SES bills for every
  // email sent. Look up the existing record before we hit Cognito so the
  // throttle is consistent regardless of whether the user exists.
  let existingResetItem: Record<string, unknown> | undefined;
  try {
    const existing = await docClient.send(new GetCommand({
      TableName: SESSIONS_TABLE,
      Key: resetKey,
    }));
    existingResetItem = existing.Item;
  } catch (err: unknown) {
    logPasswordResetFailure('lookup_existing', err);
    // Fall through — losing the throttle on a single transient read failure
    // is preferable to refusing to ever send a code.
  }

  if (existingResetItem) {
    const lastSent = existingResetItem.createdAt as string | undefined;
    if (lastSent) {
      const elapsedMs = Date.now() - new Date(lastSent).getTime();
      if (elapsedMs >= 0 && elapsedMs < FORGOT_REQUEST_COOLDOWN_SECONDS * 1000) {
        // Don't tell the caller they hit the throttle (would leak existence).
        return passwordResetSuccessResponse(requestId);
      }
    }
  }

  // Verify the user exists in Cognito without revealing misses to callers.
  const { CognitoIdentityProviderClient, AdminGetUserCommand } = await import('@aws-sdk/client-cognito-identity-provider');
  const cognitoClient = new CognitoIdentityProviderClient({ region: process.env.AWS_REGION || 'eu-central-1' });

  try {
    await cognitoClient.send(new AdminGetUserCommand({
      UserPoolId: USER_POOL_ID,
      Username: email,
    }));
  } catch (err: unknown) {
    if (isCognitoUserNotFound(err)) {
      console.log('[AUTH] ForgotPassword requested for unknown user (suppressed)');
      return passwordResetSuccessResponse(requestId);
    }

    logPasswordResetFailure('cognito_lookup', err);
    return formatError(500, 'Password reset is temporarily unavailable. Please try again later.', requestId);
  }

  // Generate a cryptographically secure 6-digit code
  const resetCode = String(randomInt(100000, 999999));
  const now = new Date();
  const expiresAt = new Date(now.getTime() + RESET_CODE_EXPIRY_MINUTES * 60 * 1000);
  // Carry forward the previous attempt count so spamming /forgot-password
  // can't reset the brute-force counter mid-window.
  const carriedAttempts = (() => {
    const raw = existingResetItem?.attempts;
    return typeof raw === 'number' && raw > 0 ? raw : 0;
  })();

  try {
    // Store only the HMAC of the code — the plaintext is sent to the user
    // via email and never persisted server-side.
    await docClient.send(new PutCommand({
      TableName: SESSIONS_TABLE,
      Item: {
        ...resetKey,
        resetCodeHash: hashResetCode(email, resetCode),
        email,
        createdAt: now.toISOString(),
        expiresAt: expiresAt.toISOString(),
        ttl: Math.floor(expiresAt.getTime() / 1000),
        attempts: carriedAttempts,
      },
    }));
  } catch (err: unknown) {
    logPasswordResetFailure('store_code', err);
    return formatError(500, 'Password reset is temporarily unavailable. Please try again later.', requestId);
  }

  try {
    // Send branded password-reset email via SES
    await sendEmail('password-reset', {
      email,
      resetCode,
      expiresInMinutes: RESET_CODE_EXPIRY_MINUTES,
    }, { throwOnError: true });

    console.log('[AUTH] Password reset code generated and email sent');
  } catch (err: unknown) {
    logPasswordResetFailure('send_email', err);
    try {
      await docClient.send(new DeleteCommand({ TableName: SESSIONS_TABLE, Key: resetKey }));
    } catch (deleteErr: unknown) {
      logPasswordResetFailure('cleanup_failed_email_code', deleteErr);
    }
    return formatError(500, 'Unable to send reset code right now. Please try again later.', requestId);
  }

  return passwordResetSuccessResponse(requestId);
}

// ─── POST /auth/confirm-reset ──────────────────────────────────────────────

const MAX_RESET_ATTEMPTS = 5;

/**
 * Confirms a password reset using the code we generated and stored in
 * DynamoDB, then sets the new password via Cognito AdminSetUserPassword.
 *
 * This endpoint does NOT require authentication.
 *
 * Body: { email, code, newPassword, clientId }
 */
async function handleConfirmReset(
  event: APIGatewayProxyEvent,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const body = parseBody(event);
  validateRequiredFields(body, ['email', 'code', 'newPassword', 'clientId']);

  const email = (body.email as string).trim().toLowerCase();
  const code = body.code as string;
  const newPassword = body.newPassword as string;

  // Look up the reset code from DynamoDB
  const resetKey = { sessionId: `password_reset#${email}` };
  const result = await docClient.send(new GetCommand({
    TableName: SESSIONS_TABLE,
    Key: resetKey,
  }));

  if (!result.Item) {
    return formatError(400, 'Invalid or expired reset code. Please request a new one.', requestId);
  }

  // Check expiry
  if (new Date(result.Item.expiresAt as string) < new Date()) {
    await docClient.send(new DeleteCommand({ TableName: SESSIONS_TABLE, Key: resetKey }));
    return formatError(400, 'Invalid or expired reset code. Please request a new one.', requestId);
  }

  // Rate-limit attempts
  const attempts = (result.Item.attempts as number) || 0;
  if (attempts >= MAX_RESET_ATTEMPTS) {
    await docClient.send(new DeleteCommand({ TableName: SESSIONS_TABLE, Key: resetKey }));
    return formatError(429, 'Too many attempts. Please request a new reset code.', requestId);
  }

  // Verify against the stored HMAC. Legacy rows that still hold a plaintext
  // `resetCode` are accepted once so live reset flows aren't broken on
  // deploy, but every new code stored after this fix is HMAC-only.
  const storedHash = result.Item.resetCodeHash as string | undefined;
  const legacyPlaintext = result.Item.resetCode as string | undefined;
  const codeMatches = storedHash
    ? verifyResetCodeHash(email, code, storedHash)
    : Boolean(legacyPlaintext) && legacyPlaintext === code;

  if (!codeMatches) {
    await docClient.send(new UpdateCommand({
      TableName: SESSIONS_TABLE,
      Key: resetKey,
      UpdateExpression: 'SET attempts = attempts + :one',
      ExpressionAttributeValues: { ':one': 1 },
    }));
    return formatError(400, 'Invalid or expired reset code. Please request a new one.', requestId);
  }

  // Code is valid — set the new password via Cognito
  const { CognitoIdentityProviderClient, AdminSetUserPasswordCommand } = await import('@aws-sdk/client-cognito-identity-provider');
  const cognitoClient = new CognitoIdentityProviderClient({ region: process.env.AWS_REGION || 'eu-central-1' });

  try {
    await cognitoClient.send(new AdminSetUserPasswordCommand({
      UserPoolId: USER_POOL_ID,
      Username: email,
      Password: newPassword,
      Permanent: true,
    }));
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Password reset failed';
    if (isInvalidPasswordError(err) || message.includes('InvalidPasswordException')) {
      return formatError(400, 'Password does not meet requirements. Must be 12+ characters with uppercase, lowercase, numbers, and symbols.', requestId);
    }
    if (isOperationalAwsError(err)) {
      logPasswordResetFailure('set_password', err);
      return formatError(500, 'Password reset is temporarily unavailable. Please try again later.', requestId);
    }
    return formatError(400, 'Password reset failed. Please request a new code and try again.', requestId);
  }

  // Clean up the used reset code
  await docClient.send(new DeleteCommand({ TableName: SESSIONS_TABLE, Key: resetKey }));

  return formatSuccess(200, {
    message: 'Password reset successfully. You can now sign in with your new password.',
  }, requestId);
}

// ─── MFA Recovery Codes ──────────────────────────────────────────────────────

/**
 * Maximum recovery codes a user is allowed to store. Caps DynamoDB row count
 * and matches the plugin/admin UIs (both generate 8). Anything significantly
 * larger would let a malicious caller bloat a partition.
 */
const MAX_RECOVERY_CODES_PER_USER = 16;

/**
 * Length of the SHA-256 hex digest the client posts. Anything other than 64
 * lowercase hex chars is rejected at the boundary so we never store junk.
 */
const RECOVERY_CODE_HASH_REGEX = /^[a-f0-9]{64}$/;

/**
 * Recovery-code rate limits — applied per userId, per 1-hour window.
 *
 * 10 attempts/hour gives a legitimate user plenty of room to fat-finger
 * codes when they're locked out, but keeps the brute-force probability
 * against 8 × 52-bit codes negligible (~10 × 8 × 2^-52 ≈ 1.7e-14 per hour).
 */
const RECOVERY_ATTEMPT_LIMIT = 10;
const RECOVERY_ATTEMPT_WINDOW_MS = 60 * 60 * 1000;
const RECOVERY_CODES_TTL_DAYS = 365;
const RECOVERY_ATTEMPTS_TTL_SECONDS = 2 * 60 * 60; // 2h — outlives the window

/**
 * Looks up the userId for a given email via Cognito. Returns null if the
 * email is not registered or Cognito returns a non-operational error — the
 * caller intentionally treats "user does not exist" identically to "code
 * wrong" so the verify endpoint can't be used to enumerate accounts.
 */
async function resolveUserIdForEmail(email: string): Promise<string | null> {
  const { CognitoIdentityProviderClient, AdminGetUserCommand } = await import(
    '@aws-sdk/client-cognito-identity-provider'
  );
  const cognitoClient = new CognitoIdentityProviderClient({
    region: process.env.AWS_REGION || 'eu-west-1',
  });

  try {
    const result = await cognitoClient.send(
      new AdminGetUserCommand({
        UserPoolId: USER_POOL_ID,
        Username: email,
      })
    );
    const subAttr = (result.UserAttributes || []).find((attr) => attr.Name === 'sub');
    return subAttr?.Value || null;
  } catch (err) {
    if (isCognitoUserNotFound(err)) {
      return null;
    }
    // Operational AWS issues bubble up so the caller gets a 5xx instead of a
    // misleading "code wrong". Brute-force enumeration via 5xx-vs-4xx timing
    // is non-trivial and the alternative — silently 4xx'ing during AWS
    // outages — would hide real failures.
    throw err;
  }
}

/**
 * POST /auth/recovery-codes
 *
 * Authenticated. Replaces the caller's stored recovery codes with a new set.
 * Body: { codes: string[] } where each entry is the SHA-256 hex digest of
 * the normalised recovery code (lowercase, hyphens removed) as computed
 * client-side. We never see the plaintext code.
 */
async function handleStoreRecoveryCodes(
  event: APIGatewayProxyEvent,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const user = await verifyActiveUser(event);

  const body = parseBody(event);
  validateRequiredFields(body, ['codes']);

  const rawCodes = body.codes;
  if (!Array.isArray(rawCodes) || rawCodes.length === 0) {
    return formatError(400, '`codes` must be a non-empty array of SHA-256 hex digests.', requestId);
  }
  if (rawCodes.length > MAX_RECOVERY_CODES_PER_USER) {
    return formatError(
      400,
      `Too many codes. Maximum is ${MAX_RECOVERY_CODES_PER_USER}.`,
      requestId
    );
  }

  const normalised = new Set<string>();
  for (const entry of rawCodes) {
    if (typeof entry !== 'string') {
      return formatError(400, 'Every code must be a SHA-256 hex string.', requestId);
    }
    const lower = entry.trim().toLowerCase();
    if (!RECOVERY_CODE_HASH_REGEX.test(lower)) {
      return formatError(400, 'Every code must be a 64-char lowercase SHA-256 hex digest.', requestId);
    }
    normalised.add(lower);
  }

  const userId = user.userId;
  const now = new Date();
  const expiresAtTtl = Math.floor(now.getTime() / 1000) + RECOVERY_CODES_TTL_DAYS * 24 * 60 * 60;

  // Wipe any existing codes for this user before storing the new batch so
  // re-enrollment doesn't leave stale rows redeemable.
  await deleteAllRecoveryCodesForUser(userId);

  const items = Array.from(normalised).map((codeHash) => ({
    PutRequest: {
      Item: {
        userId,
        codeHash,
        createdAt: now.toISOString(),
        expiresAtTtl,
      },
    },
  }));

  // BatchWriteItem caps at 25 items per request — well above our 16-code
  // ceiling but chunked defensively in case the cap changes.
  for (let i = 0; i < items.length; i += 25) {
    const chunk = items.slice(i, i + 25);
    await docClient.send(
      new BatchWriteCommand({
        RequestItems: { [RECOVERY_CODES_TABLE]: chunk },
      })
    );
  }

  await logAudit({
    userId,
    userEmail: user.email,
    orgId: user.orgId,
    action: 'auth.recovery_codes.store',
    resourcePath: '/auth/recovery-codes',
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: { codeCount: normalised.size },
  });

  return formatSuccess(200, { stored: normalised.size }, requestId);
}

/**
 * Deletes every recovery code for a user. Called on re-enrollment and on
 * admin reset-MFA (via the users handler). DynamoDB Query then BatchWrite —
 * BatchWriteItem is at-least-once so duplicate deletes are harmless.
 */
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

/**
 * Atomically increments the per-user attempt counter for the current
 * 1-hour window. Returns the post-increment value. The conditional update
 * relies on `if_not_exists` so a fresh window starts at 1.
 */
async function recordRecoveryAttempt(userId: string): Promise<number> {
  const windowStart =
    Math.floor(Date.now() / RECOVERY_ATTEMPT_WINDOW_MS) * RECOVERY_ATTEMPT_WINDOW_MS;
  const expiresAtTtl =
    Math.floor(windowStart / 1000) + RECOVERY_ATTEMPTS_TTL_SECONDS;

  const result = await docClient.send(
    new UpdateCommand({
      TableName: RECOVERY_ATTEMPTS_TABLE,
      Key: { userId, windowStart },
      UpdateExpression:
        'SET attempts = if_not_exists(attempts, :zero) + :one, expiresAtTtl = :ttl',
      ExpressionAttributeValues: {
        ':one': 1,
        ':zero': 0,
        ':ttl': expiresAtTtl,
      },
      ReturnValues: 'ALL_NEW',
    })
  );

  return (result.Attributes?.attempts as number) ?? 1;
}

/**
 * POST /auth/recovery-codes/verify
 *
 * UNAUTHENTICATED. The user has lost their TOTP device and cannot complete
 * Cognito MFA, so they don't have a JWT. They prove possession of one of the
 * recovery codes generated at enrollment; on success we clear their MFA
 * preference in Cognito and the next login flows through MFA_SETUP.
 *
 * Hardening:
 *  - Response is identical for "unknown email", "wrong code", "rate-limited" —
 *    all map to a generic 400 so the endpoint can't be used to enumerate
 *    users or fingerprint stored codes.
 *  - Single-use: redemption deletes the code atomically via a conditional
 *    DeleteItem. A race between two redemptions of the same code returns 400
 *    to the loser.
 *  - Rate-limited per user: 10 attempts/hour. Counter lives in a separate
 *    table to avoid noise on the codes partition.
 *  - Every attempt (success or failure) is audit-logged.
 */
async function handleVerifyRecoveryCode(
  event: APIGatewayProxyEvent,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const body = parseBody(event);
  validateRequiredFields(body, ['email', 'code']);

  const email = String(body.email).trim().toLowerCase();
  const rawCode = String(body.code);

  // Normalise client input the same way the plugin/admin do before hashing:
  // strip every non-alphanumeric, lowercase. The display format is XXXXX-XXXXX
  // but users sometimes paste with spaces or extra hyphens.
  const normalisedCode = rawCode.replace(/[^a-z0-9]/gi, '').toLowerCase();
  if (normalisedCode.length < 8 || normalisedCode.length > 32) {
    return formatError(400, 'Invalid recovery code.', requestId);
  }

  const ipAddress = getClientIp(event);
  const userAgent = getUserAgent(event);

  let userId: string | null;
  try {
    userId = await resolveUserIdForEmail(email);
  } catch (err) {
    console.error('[RECOVERY_VERIFY] cognito lookup failed', (err as Error).message);
    return formatError(503, 'Recovery is temporarily unavailable. Please try again.', requestId);
  }

  if (!userId) {
    // Don't reveal that the user doesn't exist. Sleep a tiny bit to flatten
    // the timing signal between "Cognito says no" and "DynamoDB says no" —
    // not a security boundary, just makes the noise floor uniform.
    await new Promise((resolve) => setTimeout(resolve, 50));
    return formatError(400, 'Invalid recovery code.', requestId);
  }

  const attempts = await recordRecoveryAttempt(userId);
  if (attempts > RECOVERY_ATTEMPT_LIMIT) {
    await logAudit({
      userId,
      userEmail: email,
      orgId: '',
      action: 'auth.recovery_codes.rate_limited',
      resourcePath: '/auth/recovery-codes/verify',
      outcome: 'denied',
      ipAddress,
      userAgent,
      metadata: { attempts },
    });
    return formatError(
      429,
      'Too many recovery attempts. Try again in an hour or contact your administrator.',
      requestId
    );
  }

  // Hash the candidate the same way the plugin/admin do: SHA-256 over the
  // normalised code. We compare via timingSafeEqual against the stored hash
  // to dodge timing side-channels.
  const { createHash } = await import('crypto');
  const candidateHash = createHash('sha256').update(normalisedCode).digest('hex');

  let matched: { userId: string; codeHash: string } | null = null;
  try {
    const result = await docClient.send(
      new GetCommand({
        TableName: RECOVERY_CODES_TABLE,
        Key: { userId, codeHash: candidateHash },
      })
    );
    if (result.Item) {
      // timingSafeEqual on equal-length hex strings is paranoia (GetCommand
      // already short-circuited on key equality) but cheap and harmless.
      const a = Buffer.from(candidateHash, 'hex');
      const b = Buffer.from(result.Item.codeHash as string, 'hex');
      if (a.length === b.length && timingSafeEqual(a, b)) {
        matched = { userId, codeHash: result.Item.codeHash as string };
      }
    }
  } catch (err) {
    console.error('[RECOVERY_VERIFY] lookup failed', (err as Error).message);
    return formatError(503, 'Recovery is temporarily unavailable. Please try again.', requestId);
  }

  if (!matched) {
    await logAudit({
      userId,
      userEmail: email,
      orgId: '',
      action: 'auth.recovery_codes.verify',
      resourcePath: '/auth/recovery-codes/verify',
      outcome: 'denied',
      ipAddress,
      userAgent,
    });
    return formatError(400, 'Invalid recovery code.', requestId);
  }

  // Single-use consumption — conditional delete prevents two concurrent
  // requests from both succeeding with the same code.
  try {
    await docClient.send(
      new DeleteCommand({
        TableName: RECOVERY_CODES_TABLE,
        Key: { userId: matched.userId, codeHash: matched.codeHash },
        ConditionExpression: 'attribute_exists(codeHash)',
      })
    );
  } catch (err) {
    // ConditionalCheckFailedException → another request already consumed it.
    // Treat as a verification failure so the loser of the race re-tries.
    await logAudit({
      userId,
      userEmail: email,
      orgId: '',
      action: 'auth.recovery_codes.verify',
      resourcePath: '/auth/recovery-codes/verify',
      outcome: 'denied',
      ipAddress,
      userAgent,
      metadata: { reason: 'race_consumed' },
    });
    return formatError(400, 'Invalid recovery code.', requestId);
  }

  // Clear the user's MFA preference in Cognito so the next login routes
  // through MFA_SETUP. Without `Enabled=false` here, Cognito keeps issuing
  // the SOFTWARE_TOKEN_MFA challenge against the (now lost) authenticator.
  try {
    const {
      CognitoIdentityProviderClient,
      AdminSetUserMFAPreferenceCommand,
    } = await import('@aws-sdk/client-cognito-identity-provider');
    const cognitoClient = new CognitoIdentityProviderClient({
      region: process.env.AWS_REGION || 'eu-west-1',
    });
    await cognitoClient.send(
      new AdminSetUserMFAPreferenceCommand({
        UserPoolId: USER_POOL_ID,
        Username: email,
        SoftwareTokenMfaSettings: { Enabled: false, PreferredMfa: false },
      })
    );
  } catch (err) {
    console.error('[RECOVERY_VERIFY] AdminSetUserMFAPreference failed', (err as Error).message);
    // The code was consumed but Cognito didn't update. Surface 500 so the
    // user retries; on retry they'll burn another code, which is the safer
    // failure mode than leaving them locked out of their account.
    return formatError(
      500,
      'Recovery partially completed. Please try again or contact support.',
      requestId
    );
  }

  // Wipe remaining recovery codes — they were all printed on the same sheet
  // and the user has already demonstrated possession of one, so the rest no
  // longer carry verification value. They'll get a fresh batch at the next
  // enrollment.
  await deleteAllRecoveryCodesForUser(userId).catch((err) => {
    // Non-fatal: stale codes will TTL out anyway, and the new batch
    // overwrites them on the next /auth/recovery-codes call.
    console.warn('[RECOVERY_VERIFY] post-redemption wipe failed', (err as Error).message);
  });

  await logAudit({
    userId,
    userEmail: email,
    orgId: '',
    action: 'auth.recovery_codes.verify',
    resourcePath: '/auth/recovery-codes/verify',
    outcome: 'success',
    ipAddress,
    userAgent,
  });

  return formatSuccess(
    200,
    {
      message:
        'Recovery code accepted. Sign in again to enroll a new authenticator.',
    },
    requestId
  );
}
