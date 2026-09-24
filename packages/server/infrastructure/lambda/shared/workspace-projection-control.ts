import { DynamoWorkspaceCohortControl } from './workspace-cohort-control';
import { rolloutKey, WorkspaceRoutingError } from './workspace-routing';
import type { WorkspaceScope } from '../workspace-revisions/types';

interface ProjectionDatabase {
  send(command: unknown): Promise<unknown>; tableName?: string; cohortTable?: string;
}
async function projectionRoute(scope: WorkspaceScope, database: ProjectionDatabase) {
  const tableName = database.cohortTable ?? process.env.WORKSPACE_COHORT_CONTROL_TABLE ?? database.tableName;
  if (!tableName) return null;
  const route = await new DynamoWorkspaceCohortControl({ tableName, writerTableName: tableName, send: database.send }).read(scope);
  if (route.rollout?.projectionsDisabled) throw new WorkspaceRoutingError('COHORT_DISABLED');
  return route;
}
/** Same durable route owner as writer admission. Controls normally share the
 * revision table; a separate table uses the existing writer deployment binding. */
export async function assertWorkspaceProjectionEnabled(scope: WorkspaceScope, database: ProjectionDatabase): Promise<void> {
  await projectionRoute(scope, database);
}
/** A rollback or rollback/re-enable during a read invalidates that result. No
 * alternate index/legacy read is attempted, and immutable artifacts are retained. */
export async function withWorkspaceProjectionRead<T>(scope: WorkspaceScope, database: ProjectionDatabase, read: () => Promise<T>): Promise<T> {
  const before = await projectionRoute(scope, database);
  const value = await read();
  const after = await projectionRoute(scope, database);
  if (before?.generation !== after?.generation || before?.mode !== after?.mode || before?.decisionId !== after?.decisionId ||
      (before && after && rolloutKey(before) !== rolloutKey(after))) throw new WorkspaceRoutingError('COHORT_CHANGED');
  return value;
}
