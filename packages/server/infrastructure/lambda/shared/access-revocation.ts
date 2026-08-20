/**
 * VaultGuard — shared access-revocation primitives.
 *
 * Seat accounting and crypto-access teardown, extracted from `users/handler.ts`
 * so more than one Lambda can call them. Two Lambdas need them today: the users
 * Lambda (admin-initiated revoke / reactivate) and, from 17-09, the reconciler's
 * scheduled guest-expiry sweeper.
 *
 * WHY THIS LIVES IN `shared/` RATHER THAN BEHIND `users/handler.ts`:
 * `tests/lambda-iam-table-grants.test.ts` derives each Lambda role's required
 * DynamoDB grants by scanning every `*.ts` in the Lambda's directory and then
 * following `../shared/<module>` named imports into that module (limitation 4 of
 * that file). It deliberately does NOT follow cross-handler `../users/handler`
 * imports. A teardown reached through another handler would therefore contribute
 * ZERO required grants to the importing role — and a missing grant in this repo
 * is swallowed by a `try`/`catch` and surfaces as a silent zero-access success
 * (three confirmed instances already). Keeping these helpers in `shared/` is what
 * makes the reconciler's SESSIONS / LEASES / REVOKED_KEYS / ORGANIZATIONS /
 * VAULT_MEMBERS / PERMISSIONS grants visible to that guard.
 *
 * Layering is one-directional: `users/handler.ts` imports this module, never the
 * reverse. See `isConditionalCheckFailure` below for the one place that rule
 * costs us a three-line duplication, and why paying it is correct.
 */

import {
  AdminDisableUserCommand,
  CognitoIdentityProviderClient,
} from '@aws-sdk/client-cognito-identity-provider';
import { EventBridgeClient, PutEventsCommand } from '@aws-sdk/client-eventbridge';
import {
  DeleteCommand,
  LEASES_TABLE,
  ORGANIZATIONS_TABLE,
  PERMISSIONS_TABLE,
  PutCommand,
  QueryCommand,
  REVOKED_KEYS_TABLE,
  SESSIONS_TABLE,
  UpdateCommand,
  VAULT_MEMBERS_TABLE,
  docClient,
  generateId,
  logAudit,
} from './utils';
import type { OrgRecord } from './utils';

// ─── Configuration ───────────────────────────────────────────────────────────

const REGION = process.env.AWS_REGION || 'eu-west-1';

/**
 * Both spellings are accepted because the two callers are provisioned
 * differently: the users Lambda gets `USER_POOL_ID`, the reconciler gets
 * `COGNITO_USER_POOL_ID`. `shared/utils.ts` resolves the pool id the same way.
 */
const DEFAULT_USER_POOL_ID = process.env.COGNITO_USER_POOL_ID || process.env.USER_POOL_ID || '';

const cognitoClient = new CognitoIdentityProviderClient({ region: REGION });
const eventBridgeClient = new EventBridgeClient({ region: REGION });

/**
 * DELIBERATE THREE-LINE DUPLICATE of `users/handler.ts`'s predicate. Importing it
 * would mean `shared/access-revocation.ts` importing from `../users/handler`
 * while `users/handler.ts` imports this module — a circular pair that inverts
 * layering (a `shared/` library depending on a handler) and re-creates exactly the
 * cross-handler shape the IAM guard cannot follow, collapsing the entire reason
 * this module lives in `shared/`. Moving the original is not an option either:
 * five of its seven call sites belong to invite-path helpers this plan must not
 * relocate. If a later phase wants one copy, hoist it into `shared/utils.ts` —
 * never import across handlers.
 */
function isConditionalCheckFailure(error: unknown): boolean {
  return (error as { name?: string })?.name === 'ConditionalCheckFailedException';
}

// ─── Seat accounting ─────────────────────────────────────────────────────────

/**
 * Releases a user's seat exactly once. The subject set is mutated in the same
 * conditional update as the counter, so concurrent/repeated revocations cannot
 * drive the counter below the number of active users.
 */
export async function releaseRevokedUserSeat(org: OrgRecord, subjectId: string): Promise<boolean> {
  try {
    await docClient.send(new UpdateCommand({
      TableName: ORGANIZATIONS_TABLE,
      Key: { slug: org.slug },
      UpdateExpression: 'SET updatedAt = :now ADD currentUsers :minusOne, revokedSeatUserIds :subjects',
      ConditionExpression: [
        'currentUsers > :zero',
        '(attribute_not_exists(revokedSeatUserIds) OR NOT contains(revokedSeatUserIds, :subject))',
      ].join(' AND '),
      ExpressionAttributeValues: {
        ':now': new Date().toISOString(),
        ':minusOne': -1,
        ':zero': 0,
        ':subjects': new Set([subjectId]),
        ':subject': subjectId,
      },
    }));
    return true;
  } catch (error) {
    if (isConditionalCheckFailure(error)) return false;
    throw error;
  }
}

export async function ensureRevokedSeatIdentity(org: OrgRecord, subjectId: string): Promise<void> {
  await docClient.send(new UpdateCommand({
    TableName: ORGANIZATIONS_TABLE,
    Key: { slug: org.slug },
    UpdateExpression: 'SET updatedAt = :now ADD revokedSeatUserIds :subjects',
    ExpressionAttributeValues: {
      ':now': new Date().toISOString(),
      ':subjects': new Set([subjectId]),
    },
  }));
}

export async function reserveReactivatedUserSeat(org: OrgRecord, subjectId: string): Promise<boolean> {
  try {
    await docClient.send(new UpdateCommand({
      TableName: ORGANIZATIONS_TABLE,
      Key: { slug: org.slug },
      UpdateExpression: 'SET updatedAt = :now ADD currentUsers :one DELETE revokedSeatUserIds :subjects',
      ConditionExpression: [
        'contains(revokedSeatUserIds, :subject)',
        'attribute_exists(currentUsers)',
        'attribute_exists(maxUsers)',
        '(maxUsers < :zero OR currentUsers < maxUsers)',
      ].join(' AND '),
      ExpressionAttributeValues: {
        ':now': new Date().toISOString(),
        ':one': 1,
        ':zero': 0,
        ':subjects': new Set([subjectId]),
        ':subject': subjectId,
      },
    }));
    return true;
  } catch (error) {
    if (isConditionalCheckFailure(error)) return false;
    throw error;
  }
}

// ─── Crypto-access revocation ────────────────────────────────────────────────

/**
 * How the REVOKED_KEYS marker is written.
 *
 * - `'always'` (default) — unconditional `Put`, byte-identical to the behaviour
 *   `users/handler.ts` has always had. The admin revoke path OWNS the marker
 *   because it wrote the `revoking` claim itself moments earlier.
 * - `'ifAbsent'` — adds `attribute_not_exists(userId)` and treats a
 *   `ConditionalCheckFailedException` as success. Used by scheduled teardown so a
 *   re-run cannot clobber an admin's in-flight `revoking`/`reactivating`
 *   transition. Every other error still propagates.
 */
export type MarkerWriteMode = 'always' | 'ifAbsent';

export interface RevokeUserCryptoAccessParams {
  targetUserId: string;
  adminUserId: string;
  orgId: string;
  reason: string;
  revokedAt: string;
  /**
   * LD-4. Defaults to `true`, so every pre-existing admin-revoke call site is
   * byte-identical without passing anything. Only the scheduled guest sweeper
   * passes `false`: nightly guest expiry must not fire org-wide re-encryption,
   * and skipping the leg also keeps `events:PutEvents` off the reconciler role.
   */
  triggerReEncryption?: boolean;
  /** Defaults to `'always'` — see `MarkerWriteMode`. */
  markerWrite?: MarkerWriteMode;
}

export interface RevokeUserCryptoAccessResult {
  invalidatedSessions: number;
  revokedLeases: number;
  revokedAt: string;
  reEncryptionJobId: string | null;
}

export async function revokeUserCryptoAccess(
  params: RevokeUserCryptoAccessParams
): Promise<RevokeUserCryptoAccessResult> {
  const revokedAt = params.revokedAt;
  const triggerReEncryption = params.triggerReEncryption !== false;
  const markerWrite: MarkerWriteMode = params.markerWrite ?? 'always';

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

  try {
    await docClient.send(
      new PutCommand({
        TableName: REVOKED_KEYS_TABLE,
        Item: {
          userId: params.targetUserId,
          revokedAt,
          revokedBy: params.adminUserId,
          reason: params.reason,
          // `handleReactivateUser` hard-requires this exact value before it will
          // re-enable an account, so it is written unconditionally in both modes.
          transitionState: 'revoked',
        },
        ...(markerWrite === 'ifAbsent'
          ? { ConditionExpression: 'attribute_not_exists(userId)' }
          : {}),
      })
    );
  } catch (error) {
    // An existing marker in `ifAbsent` mode means an admin transition is already
    // in flight (or already finished). Either way the user is covered, so this is
    // success — not a failure to retry.
    if (markerWrite !== 'ifAbsent' || !isConditionalCheckFailure(error)) throw error;
  }

  let reEncryptionJobId: string | null = triggerReEncryption ? generateId() : null;
  if (triggerReEncryption) {
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
                jobId: reEncryptionJobId,
              }),
            },
          ],
        })
      );
    } catch (err) {
      reEncryptionJobId = null;
      console.error('[USERS_REVOKE] EventBridge publish failed:', err);
    }
  }

  return {
    invalidatedSessions: activeSessions.length,
    revokedLeases: activeLeases.length,
    revokedAt,
    reEncryptionJobId,
  };
}

// ─── Guest teardown ──────────────────────────────────────────────────────────

/** Sort key shared by both member permission rules. */
export const GUEST_RULE_SK = 'RULE';

/**
 * The guest permission-rule id.
 *
 * W7 — THIS IS THE THIRD CONSTRUCTOR OF THIS KEY, DELIBERATELY. The other two are
 * `guestPermissionRuleId` in `users/handler.ts` (which builds it from a
 * `GUEST_MEMBER_RULE_SOURCE` constant) and `guestMemberPermissionRuleId` in
 * `vaults/handler.ts`. Consolidating them is out of scope for this phase: both
 * are load-bearing on invite and reclaim paths this phase must not disturb, and
 * rewiring them would enlarge the blast radius across two handlers already
 * edited in three waves.
 *
 * The duplication is GUARDED, not overlooked. `tests/access-revocation.test.ts`
 * source-scans every `guest-invite#` template under `infrastructure/lambda/**` —
 * resolving constant indirection — and asserts that all of them agree on the
 * `{vaultId}#{userId}` segment ordering. It asserts AGREEMENT, never a count, so
 * a legitimate fourth constructor is covered automatically while a divergent
 * spelling fails the suite. Divergent spellings of this key are exactly how a
 * cleanup sweeper silently misses rows.
 */
export function guestPermissionRuleId(vaultId: string, userId: string): string {
  return `guest-invite#${vaultId}#${userId}`;
}

/** One expired guest membership, carrying the exact `expiresAt` that was read. */
export interface ExpiredGuestRow {
  vaultId: string;
  userId: string;
  expiresAt: string;
}

export interface EndGuestAccessParams {
  /** The org record the seat is accounted against. */
  org: OrgRecord;
  orgId: string;
  /** Cognito `Username` — what `AdminDisableUser` addresses. */
  username: string;
  /** Cognito `sub` — what the seat set, marker and audit rows are keyed by. */
  subjectId: string;
  /** The rows to tear down. Each carries the exact `expiresAt` that was read. */
  expiredRows: ExpiredGuestRow[];
  /** Actor label. `'system'` for the scheduled sweeper. */
  actorUserId?: string;
  /** Audit/marker reason. Distinct from the admin default for differentiation. */
  reason?: string;
  /** LD-4. Defaults to `true`; the scheduled sweeper passes `false`. */
  triggerReEncryption?: boolean;
  userPoolId?: string;
  nowIso?: string;
}

export interface EndGuestAccessResult {
  accountDisabled: boolean;
  seatReleased: boolean;
  membershipsDeleted: number;
  permissionRulesDeleted: number;
  invalidatedSessions: number;
  revokedLeases: number;
  revokedAt: string;
}

/**
 * How the membership delete is guarded. BOTH variants are conditional — this
 * function never issues an unguarded delete, because an unguarded delete on a
 * (vaultId, userId) key cannot tell a temporary row from a permanent one and
 * would silently strip a real member's vault access.
 *
 * - `'expiry'` (default) — pinned to the exact `expiresAt` that was READ. The
 *   scheduled sweeper and the org-promotion cleanup both need this: they are
 *   acting on rows they believe to be lapsed, so a row an admin extended
 *   between discovery and now must survive. The condition failing IS the
 *   correct outcome there, not an error.
 * - `'kind'` — guarded on the row kind alone. Admin-initiated early revoke is
 *   ending access that has NOT lapsed, so its rows carry a future boundary the
 *   admin is deliberately overriding; pinning to that value would express the
 *   opposite intent. It still cannot touch a permanent membership.
 */
export type GuestMembershipDeleteGuard = 'expiry' | 'kind';

export interface DeleteGuestAccessRowsOptions {
  /** Defaults to `'expiry'` — see `GuestMembershipDeleteGuard`. */
  membershipGuard?: GuestMembershipDeleteGuard;
}

export interface DeleteGuestAccessRowsResult {
  membershipsDeleted: number;
  permissionRulesDeleted: number;
}

/**
 * THE single implementation of "remove these temporary membership rows and
 * their permission rules". Three callers, deliberately: `endGuestAccess` below
 * (the scheduled sweeper's teardown), admin-initiated early revoke, and the
 * org-level promotion cleanup that makes DR-3 durable. A second copy is how a
 * cleanup path silently misses rows — the rule id in particular has to be
 * spelled the same way by everyone, which is why it comes from
 * `guestPermissionRuleId` here rather than from a template at each call site.
 *
 * The rule is deleted ONLY when its membership delete actually landed. If the
 * row was extended out from under us, deleting its rule anyway would leave a
 * member who can read nothing — worse than not cleaning up at all.
 *
 * SIGNATURE CONSTRAINT — `options?:`, never a defaulted object parameter, and
 * no brace character anywhere between this function's name and its body.
 * `tests/lambda-iam-table-grants.test.ts` takes a function's body to be the
 * text starting at the first opening brace after its name, and it does not
 * strip comments. A defaulted object parameter (or a brace inside an inline
 * comment in the parameter list) is therefore mistaken for the whole body, the
 * function contributes ZERO required grants, and the guard reports green while
 * the role is missing them. Both mistakes were made and measured while writing
 * this function: each reduced the extracted body to two characters, which hid
 * the users role's missing Permissions delete AND silently dropped the
 * reconciler's requirements, since those reach DynamoDB only THROUGH here.
 */
export async function deleteGuestAccessRows(
  rows: ExpiredGuestRow[],
  options?: DeleteGuestAccessRowsOptions
): Promise<DeleteGuestAccessRowsResult> {
  const membershipGuard: GuestMembershipDeleteGuard = options?.membershipGuard ?? 'expiry';

  let membershipsDeleted = 0;
  let permissionRulesDeleted = 0;

  for (const row of rows) {
    let membershipDeleted = false;
    try {
      await docClient.send(
        new DeleteCommand({
          TableName: VAULT_MEMBERS_TABLE,
          Key: { vaultId: row.vaultId, userId: row.userId },
          ...(membershipGuard === 'expiry'
            ? {
                ConditionExpression: '#kind = :guest AND expiresAt = :expiresAt',
                ExpressionAttributeNames: { '#kind': 'accessKind' },
                ExpressionAttributeValues: { ':guest': 'guest', ':expiresAt': row.expiresAt },
              }
            : {
                ConditionExpression: '#kind = :guest',
                ExpressionAttributeNames: { '#kind': 'accessKind' },
                ExpressionAttributeValues: { ':guest': 'guest' },
              }),
        })
      );
      membershipDeleted = true;
      membershipsDeleted++;
    } catch (error) {
      if (!isConditionalCheckFailure(error)) throw error;
    }

    if (membershipDeleted) {
      await docClient.send(
        new DeleteCommand({
          TableName: PERMISSIONS_TABLE,
          Key: { pk: guestPermissionRuleId(row.vaultId, row.userId), sk: GUEST_RULE_SK },
        })
      );
      permissionRulesDeleted++;
    }
  }

  return { membershipsDeleted, permissionRulesDeleted };
}

/**
 * THE single implementation of "end this user's guest access". Called by the
 * scheduled guest-expiry sweeper and by admin-initiated early revoke, so the two
 * cannot drift apart.
 *
 * ORDERING — forced by failure modes, not style:
 *
 *   1. disable  2. sessions/leases + revocation marker  3. seat release
 *   4. row deletes  5. audit
 *
 * This deliberately COLLAPSES steps 2 and 4 of the six-step research contract
 * into the single `revokeUserCryptoAccess` call, because that function already
 * performs both legs (sessions, leases, then the marker) in one place and
 * splitting it would create the second, subtly-different copy this phase exists
 * to avoid. The two invariants that ARE load-bearing survive intact:
 *
 * - **Disable BEFORE seat release.** The reconciler counts seats by Cognito
 *   `Enabled === true` with an absolute `SET currentUsers` recompute. Releasing a
 *   seat for a still-enabled user gets re-inflated on the next nightly run — the
 *   "reconciler fights the sweeper" scenario. A failed disable therefore aborts
 *   this user entirely and the error propagates so the caller can isolate it.
 * - **Row deletes LAST among the state changes.** Those rows are the sweeper's
 *   own work queue. A crash after deleting them but before releasing the seat
 *   leaks that seat permanently, because the next run cannot find the user. Every
 *   earlier step is independently idempotent, so a crashed run replays cleanly.
 *
 * The marker write is NOT optional. `verifyToken` uses `aws-jwt-verify`'s offline
 * JWKS verification, so a disabled Cognito account keeps passing token
 * verification until `exp`; the DynamoDB marker read by `assertUserNotRevoked` is
 * the only tier that closes that residual window. It is also what makes the
 * existing `POST /users/{userId}/reactivate` usable as the re-enable path, since
 * that handler hard-requires a marker with `transitionState === 'revoked'`.
 *
 * NEVER deletes the identity (LD-2): audit rows resolve `userId` to an email
 * through it, and an admin extending access must be able to re-enable. It also
 * never strips Cognito role groups — disable already blocks sign-in and the
 * marker already blocks the API, so removing groups would only add a moving part
 * that extend would have to undo — and it deliberately performs no best-effort
 * Stripe seat push of its own, because the reconciler's own phase 2 syncs Stripe
 * moments later.
 */
export async function endGuestAccess(params: EndGuestAccessParams): Promise<EndGuestAccessResult> {
  const nowIso = params.nowIso ?? new Date().toISOString();
  const actorUserId = params.actorUserId ?? 'system';
  const reason = params.reason ?? 'guest_access_expired';

  // Step 1 — disable first. A failure here aborts the whole teardown for this
  // user: no seat is released, no row is removed. Disabling an already-disabled
  // account is a no-op, so the step is naturally idempotent on replay.
  await cognitoClient.send(
    new AdminDisableUserCommand({
      UserPoolId: params.userPoolId || DEFAULT_USER_POOL_ID,
      Username: params.username,
    })
  );

  // Step 2 — sessions invalidated, leases revoked, marker written conditionally
  // so a replay cannot clobber an admin's in-flight transition.
  const crypto = await revokeUserCryptoAccess({
    targetUserId: params.subjectId,
    adminUserId: actorUserId,
    orgId: params.orgId,
    reason,
    revokedAt: nowIso,
    triggerReEncryption: params.triggerReEncryption,
    markerWrite: 'ifAbsent',
  });

  // Step 3 — the existing helper and the existing `revokedSeatUserIds` set. Its
  // condition IS the idempotency guard and returns false on a repeat. A parallel
  // set would break `reserveReactivatedUserSeat`, so extend would 402.
  const seatReleased = await releaseRevokedUserSeat(params.org, params.subjectId);

  // Step 4 — the work queue goes last. The delete itself lives in the shared
  // helper above, so this teardown, admin early revoke and the org-promotion
  // cleanup cannot drift apart. The default `'expiry'` guard is what this path
  // requires: it is acting on rows it believes lapsed, and a row extended out
  // from under it must survive.
  const { membershipsDeleted, permissionRulesDeleted } =
    await deleteGuestAccessRows(params.expiredRows);

  // Step 5 — after the state change, so the row describes what happened. No
  // tokens, no credentials, no key material.
  await logAudit({
    userId: actorUserId,
    orgId: params.orgId,
    action: 'guest.access_ended',
    resourcePath: `/users/${params.subjectId}`,
    outcome: 'success',
    metadata: {
      orgId: params.orgId,
      subjectId: params.subjectId,
      reason,
      vaultCount: membershipsDeleted,
      ruleCount: permissionRulesDeleted,
      seatReleased,
      invalidatedSessions: crypto.invalidatedSessions,
      revokedLeases: crypto.revokedLeases,
    },
  });

  return {
    accountDisabled: true,
    seatReleased,
    membershipsDeleted,
    permissionRulesDeleted,
    invalidatedSessions: crypto.invalidatedSessions,
    revokedLeases: crypto.revokedLeases,
    revokedAt: crypto.revokedAt,
  };
}
