import { observeWorkspaceOperation } from '../workspace-observability/telemetry';
import {
  GetCommand,
  PutCommand,
  QueryCommand,
  TransactWriteCommand,
  type TransactWriteCommandInput,
} from '@aws-sdk/lib-dynamodb';
import type { WorkspaceCohortCondition } from '../shared/workspace-cohort-control';

import { deepFreeze } from './manifest-store';
import type {
  CommittedWorkspaceRevisionRecord,
  PreparedWorkspaceRevisionRecord,
  VaultWorkspaceHead,
  WorkspaceScope,
  WorkspaceRevisionRepository,
} from './types';

export class WorkspaceRevisionImmutabilityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WorkspaceRevisionImmutabilityError';
  }
}

export class WorkspaceHeadCasError extends Error {
  constructor() {
    super('workspace head changed before publication');
    this.name = 'WorkspaceHeadCasError';
  }
}

export class WorkspaceRevisionPersistenceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WorkspaceRevisionPersistenceError';
  }
}

export function workspaceEventSortKey(sequence: number): string {
  if (!Number.isSafeInteger(sequence) || sequence < 1) throw new Error('invalid workspace event sequence');
  return `EVENT#${String(sequence).padStart(16, '0')}`;
}

function encodedSegment(value: string): string {
  return Buffer.from(value, 'utf8').toString('base64url');
}

export function workspaceRevisionPartitionKey(scope: WorkspaceScope): string {
  return `WORKSPACE#${encodedSegment(scope.orgId)}#${encodedSegment(scope.vaultId)}`;
}

export function revisionSortKey(workspaceRevisionId: string, state: 'prepared' | 'committed'): string {
  return `REVISION#${encodedSegment(workspaceRevisionId)}#${state.toUpperCase()}`;
}

function isConditionalFailure(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false;
  const candidate = error as {
    name?: unknown;
    CancellationReasons?: Array<{ Code?: unknown }>;
  };
  if (candidate.name === 'ConditionalCheckFailedException') return true;
  return (
    candidate.name === 'TransactionCanceledException' &&
    candidate.CancellationReasons?.some((reason) => reason.Code === 'ConditionalCheckFailed') === true
  );
}

function withoutKeys<T>(item: Record<string, unknown> | undefined): T | null {
  if (!item) return null;
  const { pk: _pk, sk: _sk, ...record } = item;
  return deepFreeze(record as T);
}

function stableRecordJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableRecordJson).join(',')}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${stableRecordJson(record[key])}`).join(',')}}`;
}

function recordsEqual(left: unknown, right: unknown): boolean {
  return stableRecordJson(left) === stableRecordJson(right);
}

function isManifestPointer(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false;
  const pointer = value as Record<string, unknown>;
  return (
    (pointer.encryption === undefined || (!!pointer.encryption && typeof pointer.encryption === 'object' &&
      (pointer.encryption as Record<string, unknown>).format === 'vault-aead-v1' &&
      typeof (pointer.encryption as Record<string, unknown>).cloudKeyId === 'string' &&
      /^[a-f0-9]{64}$/.test(String((pointer.encryption as Record<string, unknown>).ciphertextSha256)) &&
      Number.isSafeInteger((pointer.encryption as Record<string, unknown>).ciphertextBytes) &&
      Number((pointer.encryption as Record<string, unknown>).ciphertextBytes) >= 28)) &&
    typeof pointer.objectKey === 'string' &&
    pointer.objectKey.length > 0 &&
    typeof pointer.storageVersionId === 'string' &&
    pointer.storageVersionId.length > 0 &&
    typeof pointer.sha256 === 'string' &&
    /^[a-f0-9]{64}$/u.test(pointer.sha256) &&
    Number.isSafeInteger(pointer.byteLength) &&
    (pointer.byteLength as number) > 0
  );
}

export interface DynamoWorkspaceRevisionRepositoryDependencies {
  readonly send: (command: unknown) => Promise<unknown>;
  readonly tableName: string;
  readonly now?: () => number;
  /** Captured cohort generation; include it in the same transaction as HEAD. */
  /** Optional origin-specific live authority guards, never request-supplied. */
  readonly publicationGuards?: (scope: WorkspaceScope) => Promise<readonly WorkspaceCohortCondition[]>;
  readonly publicationCondition?: (scope: WorkspaceScope) => WorkspaceCohortCondition | Promise<WorkspaceCohortCondition>;
}

/** DynamoDB persistence for immutable revision rows and the single mutable head. */
export class DynamoWorkspaceRevisionRepository implements WorkspaceRevisionRepository {
  constructor(private readonly dependencies: DynamoWorkspaceRevisionRepositoryDependencies) {
    if (!dependencies.tableName) {
      throw new WorkspaceRevisionPersistenceError('workspace revisions table name is required');
    }
  }

  async getHead(scope: WorkspaceScope): Promise<VaultWorkspaceHead | null> {
    const result = (await this.dependencies.send(
      new GetCommand({
        TableName: this.dependencies.tableName,
        Key: { pk: workspaceRevisionPartitionKey(scope), sk: 'HEAD' },
        ConsistentRead: true,
      }),
    )) as { Item?: Record<string, unknown> };
    const head = withoutKeys<VaultWorkspaceHead>(result.Item);
    if (!head) return null;
    if (
      head.recordType !== 'workspace-head' ||
      head.orgId !== scope.orgId ||
      head.vaultId !== scope.vaultId ||
      typeof head.workspaceRevisionId !== 'string' ||
      !Number.isSafeInteger(head.sequence) ||
      head.sequence < 1 ||
      !isManifestPointer(head.committedManifest)
    ) {
      throw new WorkspaceRevisionPersistenceError('workspace head record is malformed or cross-scoped');
    }
    return head;
  }

  async putPrepared(
    record: PreparedWorkspaceRevisionRecord,
  ): Promise<'created' | 'already-prepared'> {
    const pk = workspaceRevisionPartitionKey(record);
    const sk = revisionSortKey(record.workspaceRevisionId, 'prepared');
    try {
      await this.dependencies.send(
        new PutCommand({
          TableName: this.dependencies.tableName,
          Item: { pk, sk, ...record },
          ConditionExpression: 'attribute_not_exists(pk) AND attribute_not_exists(sk)',
        }),
      );
      return 'created';
    } catch (error) {
      if (!isConditionalFailure(error)) throw error;
      const existing = await this.getPrepared(record, record.workspaceRevisionId);
      if (existing && recordsEqual(existing, record)) return 'already-prepared';
      throw new WorkspaceRevisionImmutabilityError(
        `workspace revision ${record.workspaceRevisionId} was already prepared with different content`,
      );
    }
  }

  /**
   * Reads the durable, sequence-ordered commit outbox: the committed revisions
   * whose sequence is strictly greater than `afterSequence`, ascending, at most
   * `limit` of them. Each `EVENT#` row is written in the same transaction as the
   * head it advanced, so the answer never names a revision that is not
   * committed. The sequence must be contiguous from `afterSequence + 1`; a gap
   * or a row from another scope is a persistence fault, never a shorter list.
   */
  async listCommittedEvents(
    scope: WorkspaceScope,
    afterSequence: number,
    limit: number,
  ): Promise<readonly { workspaceRevisionId: string; sequence: number; committedAt: string }[]> {
    if (!Number.isSafeInteger(afterSequence) || afterSequence < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
      throw new WorkspaceRevisionPersistenceError('workspace event range is invalid');
    }
    const result = (await this.dependencies.send(
      new QueryCommand({
        TableName: this.dependencies.tableName,
        KeyConditionExpression: 'pk = :pk AND sk BETWEEN :from AND :to',
        ExpressionAttributeValues: {
          ':pk': workspaceRevisionPartitionKey(scope),
          ':from': workspaceEventSortKey(afterSequence + 1),
          ':to': `EVENT#${'9'.repeat(16)}`,
        },
        ConsistentRead: true,
        ScanIndexForward: true,
        Limit: limit,
      }),
    )) as { Items?: Record<string, unknown>[] };
    const events = (result.Items ?? []).map((item, index) => {
      const event = withoutKeys<Record<string, unknown>>(item);
      if (
        event?.recordType !== 'workspace-event' ||
        event.orgId !== scope.orgId ||
        event.vaultId !== scope.vaultId ||
        event.sequence !== afterSequence + 1 + index ||
        typeof event.workspaceRevisionId !== 'string' ||
        event.workspaceRevisionId.length === 0 ||
        typeof event.committedAt !== 'string' ||
        !Number.isFinite(Date.parse(event.committedAt))
      ) {
        throw new WorkspaceRevisionPersistenceError('workspace event is malformed, cross-scoped or out of sequence');
      }
      return {
        workspaceRevisionId: event.workspaceRevisionId,
        sequence: event.sequence as number,
        committedAt: event.committedAt,
      };
    });
    if (events.length > limit) throw new WorkspaceRevisionPersistenceError('workspace event page is unbounded');
    return deepFreeze(events);
  }

  async getPrepared(
    scope: WorkspaceScope,
    workspaceRevisionId: string,
  ): Promise<PreparedWorkspaceRevisionRecord | null> {
    return this.getRevision(scope, workspaceRevisionId, 'prepared');
  }

  async getCommitted(
    scope: WorkspaceScope,
    workspaceRevisionId: string,
  ): Promise<CommittedWorkspaceRevisionRecord | null> {
    return this.getRevision(scope, workspaceRevisionId, 'committed');
  }

  private async getRevision<T>(
    scope: WorkspaceScope,
    workspaceRevisionId: string,
    state: 'prepared' | 'committed',
  ): Promise<T | null> {
    const result = (await this.dependencies.send(
      new GetCommand({
        TableName: this.dependencies.tableName,
        Key: {
          pk: workspaceRevisionPartitionKey(scope),
          sk: revisionSortKey(workspaceRevisionId, state),
        },
        ConsistentRead: true,
      }),
    )) as { Item?: Record<string, unknown> };
    const record = withoutKeys<Record<string, unknown>>(result.Item);
    const pointer = state === 'prepared' ? record?.preparedManifest : record?.committedManifest;
    if (!record) return null;
    if (
      record.recordType !== 'workspace-revision' ||
      record.state !== state ||
      record.orgId !== scope.orgId ||
      record.vaultId !== scope.vaultId ||
      record.workspaceRevisionId !== workspaceRevisionId ||
      !isManifestPointer(pointer)
    ) {
      throw new WorkspaceRevisionPersistenceError(
        `workspace ${state} revision record is malformed or cross-scoped`,
      );
    }
    return record as T;
  }

  async preparePublication(
    expectedHead: VaultWorkspaceHead | null,
    prepared: PreparedWorkspaceRevisionRecord,
    committed: CommittedWorkspaceRevisionRecord,
  ): Promise<NonNullable<TransactWriteCommandInput["TransactItems"]>> {
    const expectedSequence = expectedHead?.sequence ?? 0;
    if (
      prepared.orgId !== committed.orgId ||
      prepared.vaultId !== committed.vaultId ||
      prepared.workspaceRevisionId !== committed.workspaceRevisionId ||
      prepared.expectedWorkspaceRevisionId !== (expectedHead?.workspaceRevisionId ?? null) ||
      committed.expectedWorkspaceRevisionId !== prepared.expectedWorkspaceRevisionId ||
      committed.preparedManifestSha256 !== prepared.preparedManifest.sha256 ||
      committed.sequence !== expectedSequence + 1 ||
      (expectedHead !== null &&
        (expectedHead.orgId !== prepared.orgId || expectedHead.vaultId !== prepared.vaultId))
    ) {
      throw new WorkspaceRevisionPersistenceError('workspace publication records are inconsistent');
    }
    const pk = workspaceRevisionPartitionKey(prepared);
    const head: VaultWorkspaceHead = {
      recordType: 'workspace-head',
      orgId: committed.orgId,
      vaultId: committed.vaultId,
      workspaceRevisionId: committed.workspaceRevisionId,
      sequence: committed.sequence,
      preparedManifestSha256: committed.preparedManifestSha256,
      committedManifest: committed.committedManifest,
      publishedAt: committed.committedAt,
    };
    const expectedIsGenesis = expectedHead === null;
    const conditionExpression = expectedIsGenesis
      ? 'attribute_not_exists(#workspaceRevisionId) AND (attribute_not_exists(#sequence) OR #sequence = :zero)'
      : '#workspaceRevisionId = :expectedWorkspaceRevisionId AND #sequence = :expectedSequence';
    const headValues: Record<string, unknown> = {
      ':recordType': head.recordType,
      ':orgId': head.orgId,
      ':vaultId': head.vaultId,
      ':newWorkspaceRevisionId': head.workspaceRevisionId,
      ':newSequence': head.sequence,
      ':preparedManifestSha256': head.preparedManifestSha256,
      ':committedManifest': head.committedManifest,
      ':publishedAt': head.publishedAt,
      ...(!expectedIsGenesis
        ? {
            ':expectedWorkspaceRevisionId': expectedHead.workspaceRevisionId,
            ':expectedSequence': expectedHead.sequence,
          }
        : { ':zero': 0 }),
    };

    // Never refresh an existing intent's age: stale ambiguous attempts must be
    // fenced by recovery even if clients keep retrying.
    const recoveryKey = { pk, sk: `RECOVERY#${encodedSegment(committed.workspaceRevisionId)}` };
    try {
      await this.dependencies.send(new PutCommand({
        TableName: this.dependencies.tableName,
        Item: { ...recoveryKey, recordType: 'workspace-recovery',
          orgId: committed.orgId, vaultId: committed.vaultId,
          workspaceRevisionId: committed.workspaceRevisionId,
          preparedManifestSha256: committed.preparedManifestSha256, state: 'pending',
          createdAt: new Date(this.dependencies.now?.() ?? Date.now()).toISOString() },
        ConditionExpression: 'attribute_not_exists(pk)',
      }));
    } catch (error) {
      if (!isConditionalFailure(error)) throw error;
      const result = await this.dependencies.send(new GetCommand({
        TableName: this.dependencies.tableName, Key: recoveryKey, ConsistentRead: true,
      })) as { Item?: Record<string, unknown> };
      if (result.Item?.state !== 'pending' ||
        result.Item.preparedManifestSha256 !== committed.preparedManifestSha256) {
        throw new WorkspaceHeadCasError();
      }
    }

    const cohortCondition = await this.dependencies.publicationCondition?.(prepared);
    const originGuards = await this.dependencies.publicationGuards?.(prepared) ?? [];
    return [
            ...originGuards.map(ConditionCheck => ({ ConditionCheck })),
            ...(cohortCondition ? [{ ConditionCheck: cohortCondition }] : []),
            {
              Put: {
                TableName: this.dependencies.tableName,
                Item: { pk, sk: workspaceEventSortKey(committed.sequence),
                  recordType: 'workspace-event', orgId: committed.orgId, vaultId: committed.vaultId,
                  workspaceRevisionId: committed.workspaceRevisionId, sequence: committed.sequence,
                  preparedManifestSha256: committed.preparedManifestSha256,
                  committedAt: committed.committedAt },
                ConditionExpression: 'attribute_not_exists(pk)',
              },
            },
            {
              Put: {
                TableName: this.dependencies.tableName,
                Item: { pk, sk: `RECOVERY#${encodedSegment(committed.workspaceRevisionId)}`,
                  recordType: 'workspace-recovery', orgId: committed.orgId, vaultId: committed.vaultId,
                  workspaceRevisionId: committed.workspaceRevisionId,
                  preparedManifestSha256: committed.preparedManifestSha256,
                  state: 'committed', sequence: committed.sequence, createdAt: committed.committedAt },
                ConditionExpression: '#state = :pending AND preparedManifestSha256 = :digest',
                ExpressionAttributeNames: { '#state': 'state' },
                ExpressionAttributeValues: { ':pending': 'pending', ':digest': committed.preparedManifestSha256 },
              },
            },
            {
              ConditionCheck: {
                TableName: this.dependencies.tableName,
                Key: {
                  pk,
                  sk: revisionSortKey(prepared.workspaceRevisionId, 'prepared'),
                },
                ConditionExpression:
                  '#state = :preparedState AND #preparedManifest = :preparedManifest',
                ExpressionAttributeNames: {
                  '#state': 'state',
                  '#preparedManifest': 'preparedManifest',
                },
                ExpressionAttributeValues: {
                  ':preparedState': 'prepared',
                  ':preparedManifest': prepared.preparedManifest,
                },
              },
            },
            {
              Put: {
                TableName: this.dependencies.tableName,
                Item: {
                  pk,
                  sk: revisionSortKey(committed.workspaceRevisionId, 'committed'),
                  ...committed,
                },
                ConditionExpression: 'attribute_not_exists(pk) AND attribute_not_exists(sk)',
              },
            },
            {
              Update: {
                TableName: this.dependencies.tableName,
                Key: { pk, sk: 'HEAD' },
                UpdateExpression:
                  'SET #recordType = :recordType, #orgId = :orgId, #vaultId = :vaultId, ' +
                  '#workspaceRevisionId = :newWorkspaceRevisionId, #sequence = :newSequence, ' +
                  '#preparedManifestSha256 = :preparedManifestSha256, ' +
                  '#committedManifest = :committedManifest, #publishedAt = :publishedAt',
                ConditionExpression: conditionExpression,
                ExpressionAttributeNames: {
                  '#recordType': 'recordType',
                  '#orgId': 'orgId',
                  '#vaultId': 'vaultId',
                  '#workspaceRevisionId': 'workspaceRevisionId',
                  '#sequence': 'sequence',
                  '#preparedManifestSha256': 'preparedManifestSha256',
                  '#committedManifest': 'committedManifest',
                  '#publishedAt': 'publishedAt',
                },
                ExpressionAttributeValues: headValues,
              },
            },
          ];
  }

  publish(expectedHead: VaultWorkspaceHead | null, prepared: PreparedWorkspaceRevisionRecord, committed: CommittedWorkspaceRevisionRecord): Promise<void> {
    return observeWorkspaceOperation('head_publication', async (): Promise<void> => {
    const items = await this.preparePublication(expectedHead, prepared, committed);
    try {
      await this.dependencies.send(new TransactWriteCommand({ TransactItems: items }));
    } catch (error) {
      if (isConditionalFailure(error)) throw new WorkspaceHeadCasError();
      throw error;
    }
      });
  }
}
