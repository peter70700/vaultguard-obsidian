import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { recoverWorkspacePage } from './worker';

const client = DynamoDBDocumentClient.from(new DynamoDBClient({}));

/** Internal EventBridge invocation only. Emits metadata-only CloudWatch EMF. */
export async function handler(): Promise<void> {
  const tableName = process.env.WORKSPACE_REVISIONS_TABLE;
  if (!tableName) throw new Error('workspace revisions table required');
  const result = await recoverWorkspacePage({ tableName, send: command => client.send(command as Parameters<typeof client.send>[0]) });
  console.info(JSON.stringify({
    _aws: { Timestamp: Date.now(), CloudWatchMetrics: [{
      Namespace: 'VaultGuard/WorkspaceRecovery', Dimensions: [['Stage']],
      Metrics: [{ Name: 'Pending', Unit: 'Count' }, { Name: 'Settled', Unit: 'Count' },
        { Name: 'OldestPendingAge', Unit: 'Seconds' }, { Name: 'SweepComplete', Unit: 'Count' }],
    }] },
    Stage: process.env.STAGE ?? 'unknown', Pending: result.pending, Settled: result.settled,
    OldestPendingAge: result.oldestPendingAge, SweepComplete: result.sweepComplete ? 1 : 0,
  }));
}
