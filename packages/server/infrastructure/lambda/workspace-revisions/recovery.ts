import { GetCommand, QueryCommand, TransactWriteCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { revisionSortKey, workspaceEventSortKey, workspaceRevisionPartitionKey, type DynamoWorkspaceRevisionRepositoryDependencies } from './head-store';
import { requireWorkspaceCapability, type WorkspaceCapabilityGate } from '../shared/workspace-capabilities';
import type { WorkspaceScope } from './types';

export { workspaceEventSortKey } from './head-store';
export interface WorkspaceEvent extends WorkspaceScope {
  recordType: 'workspace-event';
  workspaceRevisionId: string;
  sequence: number;
  preparedManifestSha256: string;
  committedAt: string;
}
export interface WorkspaceRecoveryState extends WorkspaceScope {
  recordType: 'workspace-recovery';
  preparedManifestSha256: string;
  workspaceRevisionId: string;
  state: 'pending' | 'committed' | 'not-published';
  createdAt: string;
  sequence?: number;
}

/** Durable ordered outbox. Events and recovery receipts have no TTL or delete path. */
export class WorkspaceRecoveryService {
  constructor(
    private readonly db: DynamoWorkspaceRevisionRepositoryDependencies,
    private readonly gate: WorkspaceCapabilityGate = requireWorkspaceCapability,
  ) {}

  /** Read-only reconciliation remains available with all product capabilities off.
   * Pending is intentionally never inferred to be failed: an in-flight transaction
   * could still commit. Committed is written atomically with the authoritative head.
   */
  async reconcile(scope: WorkspaceScope, revisionId: string): Promise<WorkspaceRecoveryState | null> {
    const result = await this.db.send(new GetCommand({
      TableName: this.db.tableName,
      Key: { pk: workspaceRevisionPartitionKey(scope), sk: `RECOVERY#${Buffer.from(revisionId).toString('base64url')}` },
      ConsistentRead: true,
    })) as { Item?: WorkspaceRecoveryState };
    const record = result.Item;
    if (!record) return null;
    if (record.workspaceRevisionId !== revisionId ||
      record.recordType !== 'workspace-recovery' || record.orgId !== scope.orgId || record.vaultId !== scope.vaultId ||
      !Number.isFinite(Date.parse(record.createdAt)) ||
      !/^[a-f0-9]{64}$/.test(record.preparedManifestSha256) ||
      !['pending', 'committed', 'not-published'].includes(record.state) ||
      (record.state === 'committed' && (!Number.isSafeInteger(record.sequence) || record.sequence! < 1))) {
      throw new Error('invalid workspace recovery record');
    }
    return record;
  }

  /** Fence an abandoned transaction before declaring it not published. The
   * publication transaction also requires pending, so either publication wins
   * atomically or recovery wins and a late publication can never become visible.
   */
  async settlePending(scope: WorkspaceScope, revisionId: string, now = Date.now()): Promise<WorkspaceRecoveryState | null> {
    const record = await this.reconcile(scope, revisionId);
    if (!record || record.state !== 'pending' || now - Date.parse(record.createdAt) < 120_000) return record;
    const pk = workspaceRevisionPartitionKey(scope);
    try {
      await this.db.send(new TransactWriteCommand({ TransactItems: [
        { ConditionCheck: {
          TableName: this.db.tableName,
          Key: { pk, sk: revisionSortKey(revisionId, 'committed') },
          ConditionExpression: 'attribute_not_exists(pk)',
        } },
        { Update: {
          TableName: this.db.tableName,
          Key: { pk, sk: `RECOVERY#${Buffer.from(revisionId).toString('base64url')}` },
          UpdateExpression: 'SET #state = :terminal, resolvedAt = :now',
          ConditionExpression: '#state = :pending AND createdAt = :createdAt AND preparedManifestSha256 = :digest',
          ExpressionAttributeNames: { '#state': 'state' },
          ExpressionAttributeValues: { ':terminal': 'not-published', ':now': new Date(now).toISOString(),
            ':pending': 'pending', ':createdAt': record.createdAt, ':digest': record.preparedManifestSha256 },
        } },
      ] }));
    } catch (error) {
      // A lost response or a competing publisher/reconciler must be resolved by
      // strong read. Never swallow an unresolved infrastructure failure.
      const current = await this.reconcile(scope, revisionId);
      if (current && current.state !== 'pending') return current;
      throw error;
    }
    return this.reconcile(scope, revisionId);
  }

  /** Bounded, resumable monitoring: preserve the continuation key, even on empty pages. */
  async health(scope: WorkspaceScope, cursor?: Record<string, unknown>) {
    const pk = workspaceRevisionPartitionKey(scope);
    if (cursor && (cursor.pk !== pk || typeof cursor.sk !== 'string' || !cursor.sk.startsWith('RECOVERY#'))) {
      throw new Error('invalid recovery cursor');
    }
    const result = await this.db.send(new QueryCommand({
      TableName: this.db.tableName, ConsistentRead: true, Limit: 100,
      KeyConditionExpression: 'pk = :pk AND begins_with(sk, :prefix)',
      ExpressionAttributeValues: { ':pk': pk, ':prefix': 'RECOVERY#' },
      ExclusiveStartKey: cursor,
    })) as { Items?: WorkspaceRecoveryState[]; LastEvaluatedKey?: Record<string, unknown> };
    const items = result.Items ?? [];
    return { pending: items.filter(item => item.state === 'pending'),
      committed: items.filter(item => item.state === 'committed').length,
      notPublished: items.filter(item => item.state === 'not-published').length,
      cursor: result.LastEvaluatedKey };
  }

  /** Deliver only the next sequence. The sink MUST durably deduplicate eventKey
   * and reject older versions. A crash after sink success replays the same key.
   * Each consumer has its own monotonically advancing checkpoint.
   */
  async deliverNext(
    scope: WorkspaceScope, consumer: string,
    sink: (event: WorkspaceEvent, eventKey: string) => Promise<void>,
  ): Promise<'idle' | 'delivered'> {
    await this.gate('projections');
    if (!/^[a-z][a-z0-9-]{0,63}$/.test(consumer)) throw new Error('invalid consumer');
    const pk = workspaceRevisionPartitionKey(scope);
    const checkpointKey = { pk, sk: `CHECKPOINT#${consumer}` };
    const checkpoint = await this.db.send(new GetCommand({
      TableName: this.db.tableName, Key: checkpointKey, ConsistentRead: true,
    })) as { Item?: { sequence: number } };
    const previous = checkpoint.Item?.sequence ?? 0;
    if (!Number.isSafeInteger(previous) || previous < 0) throw new Error('invalid checkpoint');
    const sk = workspaceEventSortKey(previous + 1);
    const result = await this.db.send(new GetCommand({
      TableName: this.db.tableName, Key: { pk, sk }, ConsistentRead: true,
    })) as { Item?: WorkspaceEvent };
    const event = result.Item;
    if (!event) return 'idle';
    if (event.recordType !== 'workspace-event' || event.orgId !== scope.orgId ||
      event.vaultId !== scope.vaultId || event.sequence !== previous + 1) throw new Error('invalid outbox event');
    await this.gate('projections');
    await sink(event, `${pk}#${sk}`);
    await this.gate('projections');
    await this.db.send(new UpdateCommand({
      TableName: this.db.tableName, Key: checkpointKey,
      UpdateExpression: 'SET #sequence = :next',
      ConditionExpression: checkpoint.Item ? '#sequence = :previous' : 'attribute_not_exists(pk)',
      ExpressionAttributeNames: { '#sequence': 'sequence' },
      ExpressionAttributeValues: { ':next': event.sequence, ...(checkpoint.Item ? { ':previous': previous } : {}) },
    }));
    return 'delivered';
  }
}
