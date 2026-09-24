import { GetCommand, ScanCommand, UpdateCommand } from '@aws-sdk/lib-dynamodb';
import { WorkspaceRecoveryService, type WorkspaceRecoveryState } from '../workspace-revisions/recovery';
import type { DynamoWorkspaceRevisionRepositoryDependencies } from '../workspace-revisions/head-store';

const CHECKPOINT = { pk: 'RECOVERY-WORKER', sk: 'SCAN' };

/** One bounded page per invocation; a durable cursor prevents large tables from
 * starving later workspaces. No product capability gate can stop recovery.
 */
export async function recoverWorkspacePage(db: DynamoWorkspaceRevisionRepositoryDependencies, now = Date.now()) {
  const checkpoint = await db.send(new GetCommand({
    TableName: db.tableName, Key: CHECKPOINT, ConsistentRead: true,
  })) as { Item?: { cursor?: Record<string, unknown>; generation: number } };
  const result = await db.send(new ScanCommand({
    TableName: db.tableName, ConsistentRead: true, Limit: 100,
    ExclusiveStartKey: checkpoint.Item?.cursor,
    FilterExpression: 'recordType = :type AND #state = :pending',
    ExpressionAttributeNames: { '#state': 'state' },
    ExpressionAttributeValues: { ':type': 'workspace-recovery', ':pending': 'pending' },
  })) as { Items?: WorkspaceRecoveryState[]; LastEvaluatedKey?: Record<string, unknown> };
  const recovery = new WorkspaceRecoveryService(db);
  let settled = 0;
  let pending = 0;
  let oldestPendingAge = 0;
  for (const record of result.Items ?? []) {
    const current = await recovery.settlePending(record, record.workspaceRevisionId, now);
    if (current?.state === 'pending') {
      pending++;
      oldestPendingAge = Math.max(oldestPendingAge, (now - Date.parse(current.createdAt)) / 1000);
    } else if (current) settled++;
  }
  // Only advance after the whole page completes. A failed/ambiguous cursor write
  // replays read/conditional reconciliation safely; never drops pending rows.
  await db.send(new UpdateCommand({
    TableName: db.tableName, Key: CHECKPOINT,
    UpdateExpression: result.LastEvaluatedKey ? 'SET #generation = :next, #cursor = :cursor' : 'SET #generation = :next REMOVE #cursor',
    ConditionExpression: checkpoint.Item ? '#generation = :previous' : 'attribute_not_exists(pk)',
    ExpressionAttributeNames: { '#generation': 'generation', '#cursor': 'cursor' },
    ExpressionAttributeValues: { ':next': (checkpoint.Item?.generation ?? 0) + 1,
      ...(checkpoint.Item ? { ':previous': checkpoint.Item.generation } : {}),
      ...(result.LastEvaluatedKey ? { ':cursor': result.LastEvaluatedKey } : {}) },
  }));
  return { pending, settled, oldestPendingAge, sweepComplete: !result.LastEvaluatedKey };
}
