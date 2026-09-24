import { randomUUID } from 'crypto';
import { TransactWriteCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { rotationControlPk, ROTATION_CONTROL_SK } from './rotation-fence-keys';
import { DynamoWorkspaceCohortControl } from './workspace-cohort-control';
import { WorkspaceRoutingError } from './workspace-routing';

import {
  AuthError,
  docClient,
} from './utils';

// Keep the fence self-contained at the shared-module boundary. Many focused
// handler tests replace `shared/utils` with a narrow mock; importing a
// configuration constant from that mock made an otherwise independent fence
// fail before the handler could run. This mirrors the table fallback used by
// the files and re-encryption handlers without adding a second data owner.
const USER_KEYS_TABLE = process.env.USER_KEYS_TABLE || 'UserKeysTable';

export { rotationControlPk, ROTATION_CONTROL_SK } from './rotation-fence-keys';
export const DEFAULT_FENCE_LEASE_MS = 20 * 60 * 1000;

function cohortControl() {
  const tableName = process.env.WORKSPACE_COHORT_CONTROL_TABLE;
  return tableName ? new DynamoWorkspaceCohortControl({ tableName, writerTableName: USER_KEYS_TABLE, send: command => docClient.send(command as Parameters<typeof docClient.send>[0]) }) : null;
}

async function publishPermit(command: UpdateCommand, scope: { orgId: string; vaultId: string }, enforceCohortAdmission = true, contract?: 'path' | 'workspace-revision') {
  const control = cohortControl();
  if (!control || !enforceCohortAdmission) return docClient.send(command);
  const condition = await control.writerCondition(scope, contract);
  return docClient.send(new TransactWriteCommand({ TransactItems: [
    { ConditionCheck: condition },
    { Update: { ...command.input, UpdateExpression: command.input.UpdateExpression! } },
  ] }));
}

function controlledScope(requested: string | undefined): string {
  // Cohort transitions cover the entire vault. Every participating rotation,
  // including a path-scoped job, must contend on that same physical fence.
  return process.env.WORKSPACE_COHORT_CONTROL_TABLE ? '/**' : (requested ?? '/**');
}

function validateControlledLease(now: number, expiry: number) {
  if (process.env.WORKSPACE_COHORT_CONTROL_TABLE && (!Number.isSafeInteger(now) || now < 0 || !Number.isSafeInteger(expiry) || expiry <= now || expiry - now > DEFAULT_FENCE_LEASE_MS)) {
    throw new WorkspaceRoutingError('COHORT_FENCE_REQUIRED');
  }
}

function isConditionalConflict(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false;
  const candidate = error as { name?: unknown; CancellationReasons?: { Code?: unknown }[] };
  return candidate.name === 'ConditionalCheckFailedException' ||
    (candidate.name === 'TransactionCanceledException' && candidate.CancellationReasons?.some(reason => reason.Code === 'ConditionalCheckFailed') === true);
}

export interface RotationLease {
  orgId: string;
  vaultId: string;
  scope: string;
  jobId: string;
  expiresAt: number;
}

export interface VaultMutationPermit {
  orgId: string;
  vaultId: string;
  scope: string;
  owner: string;
  expiresAt: number;
}

/**
 * Acquire the exclusive rotation side of the vault read/write fence. The
 * condition and owner publication are one DynamoDB update, so a normal write
 * can never pass the writer condition after this returns.
 */
interface RotationLeaseOptions {
  orgId: string;
  vaultId: string;
  scope?: string;
  jobId: string;
  nowMs?: number;
  leaseMs?: number;
}

export async function acquireRotationLease(options: RotationLeaseOptions): Promise<RotationLease> {
  return acquireRotationLeaseWithAdmission(options, true);
}

/** Operator-only acquisition for a conditional cohort transition. This permits
 * acquiring the existing exclusive fence while cohort writes are paused. */
export async function acquireWorkspaceCohortFence(options: RotationLeaseOptions): Promise<RotationLease> {
  if (!process.env.WORKSPACE_COHORT_CONTROL_TABLE) throw new WorkspaceRoutingError('COHORT_FENCE_REQUIRED');
  return acquireRotationLeaseWithAdmission({ ...options, scope: '/**' }, false);
}

async function acquireRotationLeaseWithAdmission(options: RotationLeaseOptions, enforceCohortAdmission: boolean): Promise<RotationLease> {
  const scope = controlledScope(options.scope);
  const now = options.nowMs ?? Date.now();
  const expiresAt = now + (options.leaseMs ?? DEFAULT_FENCE_LEASE_MS);
  validateControlledLease(now, expiresAt);
  try {
    await publishPermit(
      new UpdateCommand({
        TableName: USER_KEYS_TABLE,
        Key: { pk: rotationControlPk(options.orgId, options.vaultId, scope), sk: ROTATION_CONTROL_SK },
        UpdateExpression:
          'SET #rotationOwner = :owner, #rotationExpiresAt = :expiresAt, #updatedAt = :updatedAt',
        ConditionExpression:
          '(attribute_not_exists(#rotationOwner) OR #rotationExpiresAt < :now OR #rotationOwner = :owner) AND (attribute_not_exists(#writerOwner) OR #writerExpiresAt < :now)',
        ExpressionAttributeNames: {
          '#rotationOwner': 'rotationOwner',
          '#rotationExpiresAt': 'rotationExpiresAt',
          '#writerOwner': 'writerOwner',
          '#writerExpiresAt': 'writerExpiresAt',
          '#updatedAt': 'updatedAt',
        },
        ExpressionAttributeValues: {
          ':owner': options.jobId,
          ':expiresAt': expiresAt,
          ':now': now,
          ':updatedAt': new Date(now).toISOString(),
        },
      }), options, enforceCohortAdmission,
    );
  } catch (error) {
    if (isConditionalConflict(error)) {
      throw new AuthError(
        'A vault write or key rotation is already in progress; retry after it completes.',
        409,
        'ROTATION_FENCE_BUSY',
      );
    }
    throw error;
  }
  return {
    orgId: options.orgId,
    vaultId: options.vaultId,
    scope,
    jobId: options.jobId,
    expiresAt,
  };
}

export async function releaseRotationLease(lease: RotationLease, nowMs = Date.now()): Promise<void> {
  const controlled = !!process.env.WORKSPACE_COHORT_CONTROL_TABLE;
  await docClient.send(
    new UpdateCommand({
      TableName: USER_KEYS_TABLE,
      Key: { pk: rotationControlPk(lease.orgId, lease.vaultId, lease.scope), sk: ROTATION_CONTROL_SK },
      UpdateExpression: 'SET #updatedAt = :updatedAt REMOVE #rotationOwner, #rotationExpiresAt',
      ConditionExpression: '#rotationOwner = :owner' + (controlled ? ' AND #rotationExpiresAt = :expectedExpiry' : ''),
      ExpressionAttributeNames: {
        '#rotationOwner': 'rotationOwner',
        '#rotationExpiresAt': 'rotationExpiresAt',
        '#updatedAt': 'updatedAt',
      },
      ExpressionAttributeValues: {
        ':owner': lease.jobId,
        ':updatedAt': new Date(nowMs).toISOString(),
        ...(controlled ? { ':expectedExpiry': lease.expiresAt } : {}),
      },
    }),
  );
}

/**
 * Acquire a short exclusive writer permit. Serializing mutations per vault is
 * intentional: it gives rotation acquisition a single atomic condition with
 * no crash-prone counters. Expired owners recover automatically.
 */
export async function acquireVaultMutationPermit(options: {
  /** Trusted server composition only. Request bodies never select this admission. */
  contract?: 'workspace-revision';
  orgId: string;
  vaultId: string;
  scope?: string;
  owner?: string;
  nowMs?: number;
  leaseMs?: number;
}): Promise<VaultMutationPermit> {
  const scope = controlledScope(options.scope);
  const owner = options.owner ?? randomUUID();
  const now = options.nowMs ?? Date.now();
  const expiresAt = now + (options.leaseMs ?? DEFAULT_FENCE_LEASE_MS);
  validateControlledLease(now, expiresAt);
  try {
    await publishPermit(
      new UpdateCommand({
        TableName: USER_KEYS_TABLE,
        Key: { pk: rotationControlPk(options.orgId, options.vaultId, scope), sk: ROTATION_CONTROL_SK },
        UpdateExpression:
          'SET #writerOwner = :owner, #writerExpiresAt = :expiresAt, #updatedAt = :updatedAt',
        ConditionExpression:
          '(attribute_not_exists(#rotationOwner) OR #rotationExpiresAt < :now) AND (attribute_not_exists(#writerOwner) OR #writerExpiresAt < :now OR #writerOwner = :owner)',
        ExpressionAttributeNames: {
          '#rotationOwner': 'rotationOwner',
          '#rotationExpiresAt': 'rotationExpiresAt',
          '#writerOwner': 'writerOwner',
          '#writerExpiresAt': 'writerExpiresAt',
          '#updatedAt': 'updatedAt',
        },
        ExpressionAttributeValues: {
          ':owner': owner,
          ':expiresAt': expiresAt,
          ':now': now,
          ':updatedAt': new Date(now).toISOString(),
        },
      }), options, true, options.contract ?? 'path',
    );
  } catch (error) {
    if (isConditionalConflict(error)) {
      throw new AuthError(
        'Vault key rotation is in progress; retry this mutation after rotation completes.',
        409,
        'ROTATION_IN_PROGRESS',
      );
    }
    throw error;
  }
  return { orgId: options.orgId, vaultId: options.vaultId, scope, owner, expiresAt };
}

export async function releaseVaultMutationPermit(
  permit: VaultMutationPermit,
  nowMs = Date.now(),
): Promise<void> {
  const controlled = !!process.env.WORKSPACE_COHORT_CONTROL_TABLE;
  await docClient.send(
    new UpdateCommand({
      TableName: USER_KEYS_TABLE,
      Key: { pk: rotationControlPk(permit.orgId, permit.vaultId, permit.scope), sk: ROTATION_CONTROL_SK },
      UpdateExpression: 'SET #updatedAt = :updatedAt REMOVE #writerOwner, #writerExpiresAt',
      ConditionExpression: '#writerOwner = :owner' + (controlled ? ' AND #writerExpiresAt = :expectedExpiry' : ''),
      ExpressionAttributeNames: {
        '#writerOwner': 'writerOwner',
        '#writerExpiresAt': 'writerExpiresAt',
        '#updatedAt': 'updatedAt',
      },
      ExpressionAttributeValues: {
        ':owner': permit.owner,
        ':updatedAt': new Date(nowMs).toISOString(),
        ...(controlled ? { ':expectedExpiry': permit.expiresAt } : {}),
      },
    }),
  );
}

export async function withVaultMutationPermit<T>(
  options: Parameters<typeof acquireVaultMutationPermit>[0],
  operation: () => Promise<T>,
): Promise<T> {
  const permit = await acquireVaultMutationPermit(options);
  try {
    return await operation();
  } finally {
    await releaseVaultMutationPermit(permit);
  }
}
