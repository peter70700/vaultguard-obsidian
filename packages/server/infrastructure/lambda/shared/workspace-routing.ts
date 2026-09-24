import { requireWorkspaceCapability, type WorkspaceCapabilityGate } from './workspace-capabilities';
import type { WorkspaceScope } from '../workspace-revisions/types';

export type WorkspaceRouteMode = 'path' | 'paused' | 'shadow' | 'revision-read';
export interface WorkspaceRolloutControls {
  readonly intentEnforced: boolean;
  readonly editDisabled: boolean;
  readonly projectionsDisabled: boolean;
  /** Earliest possible cleanup consideration, never authorization to delete history. */
  readonly retainUntil: number;
}
export const rolloutKey = (route: WorkspaceCohortRoute): string => JSON.stringify(route.rollout ? [route.rollout.intentEnforced, route.rollout.editDisabled, route.rollout.projectionsDisabled, route.rollout.retainUntil] : null);
export function validRollout(value: unknown): value is WorkspaceRolloutControls {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const row = value as WorkspaceRolloutControls;
  return Object.keys(row).sort().join(',') === 'editDisabled,intentEnforced,projectionsDisabled,retainUntil' &&
    [row.intentEnforced, row.editDisabled, row.projectionsDisabled].every(flag => typeof flag === 'boolean') &&
    Number.isSafeInteger(row.retainUntil) && row.retainUntil > 0;
}
export function routeKeysValid(route: object): boolean {
  return ['decisionId,generation,mode,orgId,vaultId', 'decisionId,generation,mode,orgId,rollout,vaultId'].includes(Object.keys(route).sort().join(','));
}
export interface WorkspaceCohortRoute extends WorkspaceScope {
  readonly rollout?: WorkspaceRolloutControls;
  readonly generation: number;
  readonly mode: WorkspaceRouteMode;
  /** Reference to operator evidence, not an authorization credential or gate approval. */
  readonly decisionId: string;
}

export class WorkspaceRoutingError extends Error {
  readonly statusCode: number;
  constructor(readonly code: 'INVALID_COHORT_ROUTES' | 'COHORT_DISABLED' | 'COHORT_CHANGED' | 'COHORT_CONTROL_UNAVAILABLE' | 'COHORT_FENCE_REQUIRED' | 'COHORT_OUTCOME_UNKNOWN' | 'upgrade_required') {
    super(code === 'upgrade_required' ? 'Upgrade this client to change this workspace. Keep local edits and use the versioned sync contract.' : code);
    this.name = 'WorkspaceRoutingError';
    this.statusCode = code === 'upgrade_required' ? 426 : code === 'COHORT_CHANGED' ? 409 : 503;
  }
}

const invalid = (): never => { throw new WorkspaceRoutingError('INVALID_COHORT_ROUTES'); };
const identifier = (value: unknown): value is string => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value);

/** Trusted operator configuration only. No request header/body may supply this value.
 * Missing configuration leaves the existing path API as authority. Invalid
 * configuration blocks dispatch; it must never accidentally enable a writer.
 */
export function readWorkspaceCohortRoute(
  scope: WorkspaceScope,
  raw = process.env.WORKSPACE_COHORT_ROUTES,
): WorkspaceCohortRoute {
  if (!identifier(scope.orgId) || !identifier(scope.vaultId)) return invalid();
  const identity = { orgId: scope.orgId, vaultId: scope.vaultId };
  if (raw === undefined) return Object.freeze({ ...identity, generation: 0, mode: 'path', decisionId: 'default' });
  if (raw.length > 64 * 1024) return invalid();
  let config: { schemaVersion: number; cohorts: WorkspaceCohortRoute[] };
  try { config = JSON.parse(raw); } catch { return invalid(); }
  if (!config || typeof config !== 'object' || Object.keys(config).sort().join(',') !== 'cohorts,schemaVersion' || config.schemaVersion !== 1 || !Array.isArray(config.cohorts) || config.cohorts.length > 100) return invalid();
  const seen = new Set<string>();
  for (const row of config.cohorts) {
    if (!row || typeof row !== 'object' || !routeKeysValid(row) || !identifier(row.orgId) || !identifier(row.vaultId) || !identifier(row.decisionId) || !Number.isSafeInteger(row.generation) || row.generation < 1 || !['path', 'paused', 'shadow', 'revision-read'].includes(row.mode) || (row.rollout !== undefined && (!validRollout(row.rollout) || (row.mode === 'revision-read' && !row.rollout.intentEnforced)))) return invalid();
    const key = JSON.stringify([row.orgId, row.vaultId]);
    if (seen.has(key)) return invalid();
    seen.add(key);
  }
  const match = config.cohorts.find(row => row.orgId === scope.orgId && row.vaultId === scope.vaultId);
  return Object.freeze(match ? { ...match, ...(match.rollout ? { rollout: Object.freeze({ ...match.rollout }) } : {}) } : { ...identity, generation: 0, mode: 'path', decisionId: 'default' });
}

function sameRoute(left: WorkspaceCohortRoute, right: WorkspaceCohortRoute): boolean {
  return left.orgId === right.orgId && left.vaultId === right.vaultId && left.generation === right.generation && left.mode === right.mode && left.decisionId === right.decisionId && rolloutKey(left) === rolloutKey(right);
}

/** Additive routing seam for a path-compatible caller. Callbacks retain their
 * existing membership/path checks. This class does not grant authorization,
 * replace a distributed writer fence, or wire a deployed API by itself.
 */
export class WorkspaceCohortRouter {
  private readonly scope: WorkspaceScope;
  constructor(scope: WorkspaceScope, private readonly control = readWorkspaceCohortRoute, private readonly globalGate: WorkspaceCapabilityGate = requireWorkspaceCapability) {
    this.scope = Object.freeze({ ...scope });
  }

  private current(): WorkspaceCohortRoute {
    const fallback = readWorkspaceCohortRoute(this.scope, '{"schemaVersion":1,"cohorts":[]}');
    const row = this.control(this.scope);
    if (!row || typeof row !== 'object' || !routeKeysValid(row)) return invalid();
    // Validate injected control-store responses as strictly as environment input.
    if (sameRoute(row, fallback)) return fallback;
    const checked = readWorkspaceCohortRoute(this.scope, JSON.stringify({ schemaVersion: 1, cohorts: [row] }));
    if (checked.generation === 0) return invalid();
    return checked;
  }

  private unchanged(before: WorkspaceCohortRoute): void {
    if (!sameRoute(before, this.current())) throw new WorkspaceRoutingError('COHORT_CHANGED');
  }

  /** No fallback on authorization, integrity, or ambiguous read errors. A route
   * change before egress requires a fresh, independently authorized request.
   */
  async read<T>(pathApi: () => Promise<T>, revisionApi: () => Promise<T>): Promise<T> {
    const before = this.current();
    const revision = before.mode === 'revision-read';
    if (revision) await this.globalGate('revision_reads');
    const result = await (revision ? revisionApi() : pathApi());
    this.unchanged(before);
    if (revision) await this.globalGate('revision_reads');
    return result;
  }

  /** Never replay an ambiguous write on another route. Revision-owned cohorts
   * require the versioned contract, even if a legacy caller declares force.
   */
  async write<T>(pathApi: () => Promise<T>): Promise<T> {
    const route = this.current();
    if (route.rollout?.editDisabled) throw new WorkspaceRoutingError('COHORT_DISABLED');
    if (route.mode === 'revision-read' || route.rollout?.intentEnforced) throw new WorkspaceRoutingError('upgrade_required');
    if (route.mode === 'paused') throw new WorkspaceRoutingError('COHORT_DISABLED');
    return pathApi();
  }

  /** Capture once per operation and inject into WorkspaceRevisionService or a
   * scoped migration's assertEnabled. Rechecked at each durable boundary; a
   * reused operation cannot survive rollback and re-enable (generation change).
   */
  revisionGate(): WorkspaceCapabilityGate {
    const before = this.current();
    return capability => {
      this.unchanged(before);
      const enabled = capability === 'revision_reads' ? before.mode === 'revision-read'
        : capability === 'revision_writes' ? !before.rollout?.editDisabled && (before.mode === 'shadow' || before.mode === 'revision-read')
        : false;
      if (!enabled) throw new WorkspaceRoutingError('COHORT_DISABLED');
      return this.globalGate(capability);
    };
  }
}

/** Async control-store routing. Use with the actual files handler and atomic
 * writer/publication admission; a read-before-write check alone is not a fence. */
export class DurableWorkspaceCohortRouter {
  constructor(
    private readonly scope: WorkspaceScope,
    private readonly control: (scope: WorkspaceScope) => Promise<WorkspaceCohortRoute>,
    private readonly globalGate: WorkspaceCapabilityGate = requireWorkspaceCapability,
  ) {}

  async snapshot(): Promise<WorkspaceCohortRoute> {
    const row = await this.control(this.scope);
    if (!row || typeof row !== 'object' || !routeKeysValid(row)) return invalid();
    const fallback = readWorkspaceCohortRoute(this.scope, '{"schemaVersion":1,"cohorts":[]}');
    if (sameRoute(row, fallback)) return fallback;
    const checked = readWorkspaceCohortRoute(this.scope, JSON.stringify({ schemaVersion: 1, cohorts: [row] }));
    if (checked.generation === 0) return invalid();
    return checked;
  }

  private async unchanged(before: WorkspaceCohortRoute): Promise<void> {
    if (!sameRoute(before, await this.snapshot())) throw new WorkspaceRoutingError('COHORT_CHANGED');
  }

  async read<T>(pathApi: () => Promise<T>, revisionApi: (route: WorkspaceCohortRoute) => Promise<T>): Promise<T> {
    const before = await this.snapshot(), revision = before.mode === 'revision-read';
    if (revision) await this.globalGate('revision_reads');
    const result = await (revision ? revisionApi(before) : pathApi());
    await this.unchanged(before);
    if (revision) await this.globalGate('revision_reads');
    return result;
  }

  async write<T>(pathApi: () => Promise<T>): Promise<T> {
    const route = await this.snapshot();
    if (route.rollout?.editDisabled) throw new WorkspaceRoutingError('COHORT_DISABLED');
    if (route.mode === 'revision-read' || route.rollout?.intentEnforced) throw new WorkspaceRoutingError('upgrade_required');
    if (route.mode === 'paused') throw new WorkspaceRoutingError('COHORT_DISABLED');
    return pathApi();
  }

  revisionGate(route: WorkspaceCohortRoute): WorkspaceCapabilityGate {
    const captured = Object.freeze({ ...route });
    return async capability => {
      await this.unchanged(captured);
      const enabled = capability === 'revision_reads' ? captured.mode === 'revision-read'
        : capability === 'revision_writes' ? !captured.rollout?.editDisabled && (captured.mode === 'shadow' || captured.mode === 'revision-read')
        : false;
      if (!enabled) throw new WorkspaceRoutingError('COHORT_DISABLED');
      await this.globalGate(capability);
    };
  }
}
