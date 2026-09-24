/**
 * VaultGuard — VAULTGUARD-129: user revocation ends the user's remote-MCP
 * connector grants and agent sessions, and reactivation never revives them.
 *
 * Before this module, revoking a user (`revokeUserCryptoAccess`) disabled the
 * account, its web sessions and its key leases, but every connector grant and
 * agent session the user held stayed `active`. They were refused only by owners
 * that happened to read the revocation marker, and reactivation (which deletes
 * that marker) revived all of them, together with the delegated records bound
 * to them.
 *
 * THE SAFE DEFAULT (D-022, VAULTGUARD-129's source scope): a revoked user's
 * connector grants never revive. Reactivation restores the account, not its
 * connections; an AI host reconnects through consent again.
 *
 * HOW IT HOLDS, from the first write of a revocation onward:
 *
 * 1. While the revocation marker exists, `ConnectorAuthService` refuses every
 *    request of every grant the user holds (`admitsGrantSubject`), and the
 *    issuer refuses every code and token. `handleRevokeUser` writes that marker
 *    (`revoking`) before anything else, so this is the moment of revocation.
 * 2. This module then raises the user's connector cutoff and revokes every grant
 *    and session in the user's owner directory
 *    (`DynamoConnectorAuthorizationStore.endSubjectConnections`). Each revoke
 *    commits a content-free `connector.revoked` audit row and a receipt in the
 *    same transaction, and the run ends with one `connector.user_access_ended`
 *    summary row.
 * 3. Grants created at or before the cutoff are refused forever, so a grant the
 *    directory could not list, or a run that did not finish, cannot revive when
 *    the marker is gone.
 * 4. The run is idempotent. A repeated revoke re-drives it, and reactivation
 *    runs it again BEFORE re-enabling the account, refusing to reactivate if it
 *    cannot complete. That is the durable follow-up: an incomplete run is never
 *    a usable grant (1 and 3), and it is always completed before the marker can
 *    be removed (4).
 *
 * Nothing here reads or writes content, a scope list, a path or a credential.
 *
 * WHY THIS LIVES IN `shared/`: the users Lambda and the reconciler's guest
 * sweeper both revoke users (`shared/access-revocation.ts`), and a helper behind
 * another Lambda's handler is invisible to `tests/lambda-iam-table-grants.test.ts`.
 */

import { createHash } from 'node:crypto';
import type { APIGatewayProxyEvent } from 'aws-lambda';
import { GetCommand } from '@aws-sdk/lib-dynamodb';
import {
  ConnectorStoreError,
  DynamoConnectorAuthorizationStore,
  type SubjectConnectionTeardown,
} from './connector-auth-store';
import {
  AUDIT_TABLE,
  buildAuditEntry,
  docClient,
  getActiveOrg,
  getEffectiveOrgSettings,
  logAudit,
} from './utils';

/** Why the teardown ran. Recorded, content-free, on every row it writes. */
export type UserConnectorAccessCause = 'revocation' | 'reactivation' | 'recovery';

export interface EndUserConnectorAccessParams {
  orgId: string;
  /** The revoked user's Cognito `sub`: what grants, sessions and the marker are keyed by. */
  userId: string;
  /** The administrator's `sub`, or `'system'` for the scheduled guest sweeper. */
  actorUserId: string;
  cause: UserConnectorAccessCause;
  /** The revocation reason (`admin_user_revoked`, `guest_access_expired`, ...). */
  reason: string;
  event?: APIGatewayProxyEvent;
}

/** Injectable storage. Deployed callers pass nothing and get the Lambda's own. */
export interface EndUserConnectorAccessDependencies {
  /** The connector authorization table. Defaults to `CONNECTOR_AUTH_TABLE`. */
  tableName?: string;
  /** Defaults to the audit table of `shared/utils.ts`. */
  auditTable?: string;
  send?: (command: unknown) => Promise<unknown>;
  /** Epoch seconds. */
  now?: () => number;
}

export type UserConnectorAccessOutcome =
  /** No connector authorization table is configured, so no connector grant can exist. */
  | { state: 'not_configured' }
  | ({ state: 'ended' } & SubjectConnectionTeardown);

/**
 * The connector table this Lambda can reach, or `null`. Terraform sets
 * `CONNECTOR_AUTH_TABLE` on every Lambda that revokes users exactly when the
 * connector authorization server (and therefore its table) exists; with no
 * table, no connector grant can exist to end.
 */
export function connectorAuthTableName(env: NodeJS.ProcessEnv = process.env): string | null {
  const name = env.CONNECTOR_AUTH_TABLE ?? '';
  return name === '' ? null : name;
}

const digest = (value: unknown) => createHash('sha256').update(JSON.stringify(value)).digest('hex');

/**
 * Ends every connector grant and agent session `userId` holds in `orgId` and
 * records it. Throws when it cannot complete; callers decide whether that is
 * fatal (reactivation) or recorded and re-driven (revocation).
 */
export async function endUserConnectorAccess(
  params: EndUserConnectorAccessParams,
  deps?: EndUserConnectorAccessDependencies
): Promise<UserConnectorAccessOutcome> {
  const tableName = deps?.tableName ?? connectorAuthTableName();
  if (tableName === null) return { state: 'not_configured' };
  const send = deps?.send ?? ((command: unknown) => docClient.send(command as never) as Promise<unknown>);
  const auditTable = deps?.auditTable ?? AUDIT_TABLE;
  const nowSeconds = deps?.now?.() ?? Math.floor(Date.now() / 1000);
  const timestamp = new Date(nowSeconds * 1000).toISOString();
  const authority = params.cause === 'recovery' ? 'self_service_recovery' : params.actorUserId === 'system' ? 'system' : 'organization_admin';

  // Retention only. An organization cannot opt a revocation row out: these rows
  // are committed with the revocation itself, exactly as web revocations are.
  let settings: Awaited<ReturnType<typeof getEffectiveOrgSettings>> = null;
  try {
    settings = await getEffectiveOrgSettings(params.orgId);
  } catch {
    settings = null;
  }

  const receiptKey = (fingerprint: string) => ({ pk: `CONNECTOR-REVOCATION#${fingerprint}`, sk: 'STATE' });
  const fingerprintOf = (kind: string, id: string, expected: number) =>
    digest([params.cause === 'recovery' ? 'password-reset' : 'user-revocation', params.orgId, params.userId, kind, id, expected]);

  const store = new DynamoConnectorAuthorizationStore({
    tableName,
    // The widest vocabulary, so any grant this user holds validates on read.
    scopeProfile: 'workspace-transfer-v1',
    send,
    now: () => nowSeconds,
    getPolicyRevision: async (orgId) => {
      const active = await getActiveOrg(orgId, { consistentRead: true });
      const revision = active.org?.policyRevision;
      return active.allowed && Number.isSafeInteger(revision) && Number(revision) >= 0 ? Number(revision) : null;
    },
    revocation: {
      prepare: async (kind, id, expected) => {
        if (kind === 'client') throw new ConnectorStoreError('INVALID_STATE');
        const fingerprint = fingerprintOf(kind, id, expected);
        const audit = buildAuditEntry(
          {
            id: fingerprint,
            timestamp,
            userId: params.actorUserId,
            orgId: params.orgId,
            action: 'connector.revoked',
            resourcePath: `/connectors/${id}`,
            outcome: 'success',
            metadata: {
              kind,
              expectedRevision: expected,
              revision: expected + 1,
              cause: `user_${params.cause}`,
              authority,
              subjectUserId: params.userId,
              reason: params.reason,
            },
          },
          params.event,
          settings
        );
        return [
          { Put: { TableName: auditTable, Item: audit, ConditionExpression: 'attribute_not_exists(pk)' } },
          { Put: { TableName: tableName, Item: { ...receiptKey(fingerprint), fingerprint }, ConditionExpression: 'attribute_not_exists(pk)' } },
        ];
      },
      confirmed: async (kind, id, expected) => {
        const fingerprint = fingerprintOf(kind, id, expected);
        const result = (await send(
          new GetCommand({ TableName: tableName, Key: receiptKey(fingerprint), ConsistentRead: true })
        )) as { Item?: { fingerprint?: string } } | undefined;
        return result?.Item?.fingerprint === fingerprint;
      },
    },
  });

  const teardown = await store.endSubjectConnections(params.orgId, params.userId, nowSeconds);

  await logAudit(
    {
      userId: params.actorUserId,
      orgId: params.orgId,
      action: 'connector.user_access_ended',
      resourcePath: `/users/${params.userId}`,
      outcome: 'success',
      metadata: {
        subjectUserId: params.userId,
        cause: `user_${params.cause}`,
        authority,
        reason: params.reason,
        cutoffAt: teardown.cutoffAt,
        grantsRevoked: teardown.grantsRevoked,
        sessionsRevoked: teardown.sessionsRevoked,
        grantsAlreadyRevoked: teardown.grantsAlreadyRevoked,
        sessionsAlreadyRevoked: teardown.sessionsAlreadyRevoked,
        referencesWithoutRecord: teardown.referencesWithoutRecord,
        coverage: teardown.coverage,
      },
    },
    params.event
  );

  return { state: 'ended', ...teardown };
}

/**
 * A content-free label for an incomplete teardown: a store error code or an
 * error class name, never an error message.
 */
export function connectorTeardownFailureCode(error: unknown): string {
  if (error instanceof ConnectorStoreError) return error.code;
  const name = (error as { name?: unknown } | null)?.name;
  return typeof name === 'string' && /^[A-Za-z]{1,64}$/u.test(name) ? name : 'Error';
}
