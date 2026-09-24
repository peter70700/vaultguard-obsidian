import { GetCommand, TransactWriteCommand, type TransactWriteCommandInput } from '@aws-sdk/lib-dynamodb';
import type { WorkspaceScope } from '../workspace-revisions/types';
import { rotationControlPk, ROTATION_CONTROL_SK } from './rotation-fence-keys';
import { readWorkspaceCohortRoute, WorkspaceRoutingError, type WorkspaceCohortRoute, type WorkspaceRouteMode, type WorkspaceRolloutControls, rolloutKey, routeKeysValid } from './workspace-routing';

export type WorkspaceCohortCondition = NonNullable<NonNullable<TransactWriteCommandInput['TransactItems']>[number]['ConditionCheck']>;
type Row = Record<string, unknown>;
const object = (value: unknown): value is Row => !!value && typeof value === 'object' && !Array.isArray(value);
const fail = (): never => { throw new WorkspaceRoutingError('INVALID_COHORT_ROUTES'); };
const unavailable = (): never => { throw new WorkspaceRoutingError('COHORT_CONTROL_UNAVAILABLE'); };
const same = (a: WorkspaceCohortRoute, b: WorkspaceCohortRoute) =>
  a.orgId === b.orgId && a.vaultId === b.vaultId && a.generation === b.generation && a.mode === b.mode && a.decisionId === b.decisionId && rolloutKey(a) === rolloutKey(b);

function checked(route: WorkspaceCohortRoute): WorkspaceCohortRoute {
  if (!object(route)) return fail();
  const fallback = readWorkspaceCohortRoute(route, '{"schemaVersion":1,"cohorts":[]}');
  if (!routeKeysValid(route)) return fail();
  if (same(route, fallback)) return fallback;
  const result = readWorkspaceCohortRoute(route, JSON.stringify({ schemaVersion: 1, cohorts: [route] }));
  if (result.generation === 0) return fail();
  return result;
}

export function workspaceCohortKey(scope: WorkspaceScope) {
  readWorkspaceCohortRoute(scope, '{"schemaVersion":1,"cohorts":[]}');
  return { pk: `WORKSPACE-COHORT#${Buffer.from(scope.orgId).toString('base64url')}#${Buffer.from(scope.vaultId).toString('base64url')}`, sk: 'CONTROL' };
}

/** Durable route owner. Route changes share one transaction with a live, exclusive
 * vault-wide writer/rotation fence check and an immutable transition record. The
 * transition reference records an operator decision, not human gate approval.
 * Keep controls and transition history: no delete or TTL method is provided.
 */
export class DynamoWorkspaceCohortControl {
  constructor(private readonly options: {
    tableName: string;
    writerTableName: string;
    send(command: unknown): Promise<unknown>;
    now?: () => number;
  }) {
    if (![options.tableName, options.writerTableName].every(value => /^[A-Za-z0-9_.-]{3,255}$/u.test(value))) fail();
  }

  private async row(Key: { pk: string; sk: string }): Promise<Row | null> {
    let result: unknown;
    try { result = await this.options.send(new GetCommand({ TableName: this.options.tableName, Key, ConsistentRead: true })); }
    catch { return unavailable(); }
    if (!object(result)) return unavailable();
    if (result.Item === undefined) return null;
    if (!object(result.Item) || result.Item.pk !== Key.pk || result.Item.sk !== Key.sk || result.Item.schemaVersion !== 1) return fail();
    return result.Item;
  }

  async read(scope: WorkspaceScope): Promise<WorkspaceCohortRoute> {
    const item = await this.row(workspaceCohortKey(scope));
    if (!item) return readWorkspaceCohortRoute(scope, '{"schemaVersion":1,"cohorts":[]}');
    if (Object.keys(item).sort().join(',') !== 'kind,pk,route,schemaVersion,sk' || item.kind !== 'cohort-control' || !object(item.route)) return fail();
    const route = checked(item.route as unknown as WorkspaceCohortRoute);
    if (route.orgId !== scope.orgId || route.vaultId !== scope.vaultId || route.generation === 0) return fail();
    return route;
  }

  condition(route: WorkspaceCohortRoute): WorkspaceCohortCondition {
    const expected = checked(route), Key = workspaceCohortKey(expected);
    if (expected.generation === 0) return { TableName: this.options.tableName, Key, ConditionExpression: 'attribute_not_exists(pk)' };
    return {
      TableName: this.options.tableName, Key,
      ConditionExpression: '#kind = :kind AND #schema = :schema AND #route.#org = :org AND #route.#vault = :vault AND #route.#generation = :generation AND #route.#mode = :mode AND #route.#decision = :decision AND ' + (expected.rollout ? '#route.#rollout = :rollout' : 'attribute_not_exists(#route.#rollout)'),
      ExpressionAttributeNames: { '#kind': 'kind', '#schema': 'schemaVersion', '#route': 'route', '#org': 'orgId', '#vault': 'vaultId', '#generation': 'generation', '#mode': 'mode', '#decision': 'decisionId', '#rollout': 'rollout' },
      ExpressionAttributeValues: { ':kind': 'cohort-control', ':schema': 1, ':org': expected.orgId, ':vault': expected.vaultId, ':generation': expected.generation, ':mode': expected.mode, ':decision': expected.decisionId, ...(expected.rollout ? { ':rollout': expected.rollout } : {}) },
    };
  }

  async writerCondition(scope: WorkspaceScope, contract?: 'path' | 'workspace-revision'): Promise<WorkspaceCohortCondition> {
    const route = await this.read(scope);
    if (route.rollout?.editDisabled) throw new WorkspaceRoutingError('COHORT_DISABLED');
    if (contract === 'workspace-revision') return this.revisionCondition(route);
    if (contract === 'path' && (route.mode === 'revision-read' || route.rollout?.intentEnforced)) throw new WorkspaceRoutingError('upgrade_required');
    if (route.mode === 'paused') throw new WorkspaceRoutingError('COHORT_DISABLED');
    return this.condition(route);
  }

  revisionCondition(route: WorkspaceCohortRoute): WorkspaceCohortCondition {
    const expected = checked(route);
    if (expected.rollout?.editDisabled || !['shadow', 'revision-read'].includes(expected.mode)) throw new WorkspaceRoutingError('COHORT_DISABLED');
    return this.condition(expected);
  }

  async transition(input: {
    expected: WorkspaceCohortRoute;
    mode: WorkspaceRouteMode;
    decisionId: string;
    rollout?: WorkspaceRolloutControls;
    /** Canary binds the exact head/client evidence in the same transaction. */
    admissionConditions?: readonly WorkspaceCohortCondition[];
    evidenceDigest?: string;
    fence: { orgId: string; vaultId: string; scope: string; jobId: string; expiresAt: number };
  }): Promise<WorkspaceCohortRoute> {
    if ((input.admissionConditions?.length ?? 0) > 95 || (input.evidenceDigest !== undefined && !/^[a-f0-9]{64}$/.test(input.evidenceDigest))) return fail();
    const before = checked(input.expected);
    const after = checked({ ...before, generation: before.generation + 1, mode: input.mode, decisionId: input.decisionId, ...(input.rollout ? { rollout: input.rollout } : {}) });
    if (before.rollout && after.rollout!.retainUntil < before.rollout.retainUntil) return fail();
    const fence = input.fence, now = this.options.now?.() ?? Date.now();
    if (!Number.isSafeInteger(now) || now < 0 || !Number.isSafeInteger(fence.expiresAt) || fence.expiresAt <= now || fence.orgId !== before.orgId || fence.vaultId !== before.vaultId || fence.scope !== '/**' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(fence.jobId)) {
      throw new WorkspaceRoutingError('COHORT_FENCE_REQUIRED');
    }
    const Key = workspaceCohortKey(before);
    const auditKey = { pk: Key.pk, sk: `TRANSITION#${String(after.generation).padStart(16, '0')}` };
    const intent = { before, after, fenceOwner: fence.jobId, fenceExpiresAt: fence.expiresAt, ...(input.evidenceDigest ? { evidenceDigest: input.evidenceDigest } : {}) };
    const matches = (record: Row | null) => record?.kind === 'cohort-transition' && object(record.before) && object(record.after) && same(record.before as unknown as WorkspaceCohortRoute, before) && same(record.after as unknown as WorkspaceCohortRoute, after) && record.fenceOwner === fence.jobId && record.fenceExpiresAt === fence.expiresAt && record.evidenceDigest === input.evidenceDigest;
    const existing = await this.row(auditKey);
    if (existing) {
      if (matches(existing)) return after;
      throw new WorkspaceRoutingError('COHORT_CHANGED');
    }
    const condition = this.condition(before);
    const { Key: _conditionKey, ...putCondition } = condition;
    try {
      await this.options.send(new TransactWriteCommand({
        TransactItems: [
          ...(input.admissionConditions ?? []).map(ConditionCheck => ({ ConditionCheck })),
          { ConditionCheck: {
            TableName: this.options.writerTableName,
            Key: { pk: rotationControlPk(before.orgId, before.vaultId), sk: ROTATION_CONTROL_SK },
            ConditionExpression: '#owner = :owner AND #expiry = :expiry AND #expiry > :now AND (attribute_not_exists(#writer) OR #writerExpiry < :now)',
            ExpressionAttributeNames: { '#owner': 'rotationOwner', '#expiry': 'rotationExpiresAt', '#writer': 'writerOwner', '#writerExpiry': 'writerExpiresAt' },
            ExpressionAttributeValues: { ':owner': fence.jobId, ':expiry': fence.expiresAt, ':now': now },
          } },
          { Put: { ...putCondition, Item: { ...Key, schemaVersion: 1, kind: 'cohort-control', route: after } } },
          { Put: { TableName: this.options.tableName, Item: { ...auditKey, schemaVersion: 1, kind: 'cohort-transition', ...intent, recordedAt: new Date(now).toISOString() }, ConditionExpression: 'attribute_not_exists(pk)' } },
        ],
      }));
    } catch (error) {
      // A lost response never triggers a replay or a compensating route change.
      // Confirm the immutable intent record or leave the outcome unavailable.
      if (matches(await this.row(auditKey))) return after;
      const conditional = object(error) && (error.name === 'ConditionalCheckFailedException' || (error.name === 'TransactionCanceledException' && Array.isArray(error.CancellationReasons) && error.CancellationReasons.some(reason => object(reason) && reason.Code === 'ConditionalCheckFailed')));
      throw new WorkspaceRoutingError(conditional ? 'COHORT_CHANGED' : 'COHORT_OUTCOME_UNKNOWN');
    }
    return after;
  }
}
