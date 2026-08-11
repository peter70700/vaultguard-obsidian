import { randomUUID } from 'crypto';
import { UpdateCommand } from '@aws-sdk/lib-dynamodb';

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

export const ROTATION_CONTROL_SK = 'ROTATION_CONTROL';
export const DEFAULT_FENCE_LEASE_MS = 20 * 60 * 1000;

function encodedScope(scope: string): string {
  return Buffer.from(scope, 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

export function rotationControlPk(orgId: string, vaultId: string, scope = '/**'): string {
  if (!orgId || !vaultId || !scope) {
    throw new Error('Rotation fence requires orgId, vaultId, and scope');
  }
  return `ORG#${orgId}#VAULT#${vaultId}#SCOPE#${encodedScope(scope)}`;
}

function isConditionalConflict(error: unknown): boolean {
  return Boolean(
    error &&
      typeof error === 'object' &&
      'name' in error &&
      (error as { name?: unknown }).name === 'ConditionalCheckFailedException',
  );
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
export async function acquireRotationLease(options: {
  orgId: string;
  vaultId: string;
  scope?: string;
  jobId: string;
  nowMs?: number;
  leaseMs?: number;
}): Promise<RotationLease> {
  const scope = options.scope ?? '/**';
  const now = options.nowMs ?? Date.now();
  const expiresAt = now + (options.leaseMs ?? DEFAULT_FENCE_LEASE_MS);
  try {
    await docClient.send(
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
      }),
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
  await docClient.send(
    new UpdateCommand({
      TableName: USER_KEYS_TABLE,
      Key: { pk: rotationControlPk(lease.orgId, lease.vaultId, lease.scope), sk: ROTATION_CONTROL_SK },
      UpdateExpression: 'SET #updatedAt = :updatedAt REMOVE #rotationOwner, #rotationExpiresAt',
      ConditionExpression: '#rotationOwner = :owner',
      ExpressionAttributeNames: {
        '#rotationOwner': 'rotationOwner',
        '#rotationExpiresAt': 'rotationExpiresAt',
        '#updatedAt': 'updatedAt',
      },
      ExpressionAttributeValues: {
        ':owner': lease.jobId,
        ':updatedAt': new Date(nowMs).toISOString(),
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
  orgId: string;
  vaultId: string;
  scope?: string;
  owner?: string;
  nowMs?: number;
  leaseMs?: number;
}): Promise<VaultMutationPermit> {
  const scope = options.scope ?? '/**';
  const owner = options.owner ?? randomUUID();
  const now = options.nowMs ?? Date.now();
  const expiresAt = now + (options.leaseMs ?? DEFAULT_FENCE_LEASE_MS);
  try {
    await docClient.send(
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
      }),
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
  await docClient.send(
    new UpdateCommand({
      TableName: USER_KEYS_TABLE,
      Key: { pk: rotationControlPk(permit.orgId, permit.vaultId, permit.scope), sk: ROTATION_CONTROL_SK },
      UpdateExpression: 'SET #updatedAt = :updatedAt REMOVE #writerOwner, #writerExpiresAt',
      ConditionExpression: '#writerOwner = :owner',
      ExpressionAttributeNames: {
        '#writerOwner': 'writerOwner',
        '#writerExpiresAt': 'writerExpiresAt',
        '#updatedAt': 'updatedAt',
      },
      ExpressionAttributeValues: {
        ':owner': permit.owner,
        ':updatedAt': new Date(nowMs).toISOString(),
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
