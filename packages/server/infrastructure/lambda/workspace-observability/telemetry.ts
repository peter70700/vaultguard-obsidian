import { AsyncLocalStorage } from 'node:async_hooks';
import { performance } from 'node:perf_hooks';
import {
  WORKSPACE_OPERATIONS, WORKSPACE_OUTCOMES, WORKSPACE_RESOURCE_UNITS,
  type WorkspaceObservation, type WorkspaceOperation, type WorkspaceOutcome,
  type WorkspaceResourceUnit, type WorkspaceGaugeObservation,
} from './model';

export interface WorkspaceTelemetry {
  /** Must be a synchronous bounded sink. Never pass request objects, errors, IDs or content. */
  emit(observation: WorkspaceObservation): void;
  /** Monotonic duration clock. Wall-clock timestamps are never emitted. */
  now?: () => number;
  /** Optional epoch clock for synthetic committed-event age only. */
  wallNow?: () => number;
}
const context = new AsyncLocalStorage<WorkspaceTelemetry>();
const contentFreeLog: WorkspaceTelemetry = { emit: value => console.info(JSON.stringify({ event: 'workspace_slo', ...value })) };
/** Off by default; does not enable any workspace capability. No SDK, network client or tenant labels. */
function current(): WorkspaceTelemetry | undefined {
  return context.getStore() ?? (process.env.WORKSPACE_SLO_TELEMETRY === 'content-free-v1' ? contentFreeLog : undefined);
}
export function withWorkspaceTelemetry<T>(telemetry: WorkspaceTelemetry, run: () => T): T {
  return context.run(telemetry, run);
}
const bounded = (value: number) => Number.isFinite(value) && value >= 0 && value <= Number.MAX_SAFE_INTEGER;
/** Reconstruct a closed record: even JavaScript callers cannot smuggle extra fields into a sink. */
export function sanitizeWorkspaceObservation(value: WorkspaceObservation): WorkspaceObservation | null {
  if (value?.schemaVersion !== 1) return null;
  if (value.kind === 'operation' && WORKSPACE_OPERATIONS.includes(value.operation) && WORKSPACE_OUTCOMES.includes(value.outcome) && bounded(value.durationMs))
    return Object.freeze({ schemaVersion: 1, kind: 'operation', operation: value.operation, outcome: value.outcome, durationMs: value.durationMs });
  if (value.kind === 'gauge' && ['projection_lag_ms', 'projection_lag_revisions', 'revocation_detection_ms'].includes(value.gauge) && bounded(value.value))
    return Object.freeze({ schemaVersion: 1, kind: 'gauge', gauge: value.gauge, value: value.value });
  if (value.kind === 'resource' && WORKSPACE_RESOURCE_UNITS.includes(value.resource) && bounded(value.value))
    return Object.freeze({ schemaVersion: 1, kind: 'resource', resource: value.resource, value: value.value });
  return null;
}
function emit(telemetry: WorkspaceTelemetry | undefined, value: WorkspaceObservation): void {
  try { const clean = sanitizeWorkspaceObservation(value); if (clean) telemetry?.emit(clean); } catch { /* Metrics cannot change an authorization or commit result. */ }
}
function clock(telemetry: WorkspaceTelemetry): number {
  try { const value = (telemetry.now ?? (() => performance.now()))(); return bounded(value) ? value : performance.now(); }
  catch { return performance.now(); }
}

const DENIED = new Set(['unauthenticated', 'permission_denied', 'not_found', 'approval_stale', 'approval_expired',
  'INVALID_CREDENTIAL', 'ISSUER_MISMATCH', 'AUDIENCE_MISMATCH', 'RESOURCE_MISMATCH', 'TOKEN_NOT_ACTIVE', 'TOKEN_EXPIRED',
  'CLIENT_MISMATCH', 'CLIENT_INACTIVE', 'GRANT_INACTIVE', 'SESSION_INACTIVE', 'POLICY_INACTIVE', 'SCOPE_DENIED', 'ORGANIZATION_REFUSED', 'USER_INACTIVE']);
const INVALID = new Set(['invalid_input', 'invalid_request', 'unsupported_source', 'unsupported_operation', 'idempotency_mismatch', 'INVALID_STATE']);
const CONFLICT = new Set(['conflict', 'context_version_conflict', 'stale_cursor', 'version_mismatch', 'workspace_head_conflict', 'reservation_fence_stale', 'CONFLICT']);
/** Codes are compared to constants and discarded; error messages/names/paths never leave the owner. */
export function workspaceErrorOutcome(error: unknown): WorkspaceOutcome {
  const record = error && typeof error === 'object' ? error as { code?: unknown; stableCode?: unknown; name?: unknown } : {};
  const code = record.stableCode ?? record.code;
  if (record.name === 'WorkspaceHeadConflictError' || record.name === 'WorkspaceHeadCasError') return 'conflict';
  if (record.name === 'WorkspaceCapabilityDisabledError') return 'unavailable';
  if (typeof code !== 'string') return 'failure';
  if (DENIED.has(code)) return 'denied';
  if (INVALID.has(code)) return 'invalid';
  if (CONFLICT.has(code)) return 'conflict';
  if (code === 'rate_limited' || code === 'throttled' || code === 'quota_exceeded') return 'throttled';
  if (code === 'unavailable' || code === 'temporarily_unavailable' || code === 'index_not_ready' || code === 'graph_not_ready' || code === 'index_unavailable' || code === 'index_stale' || code === 'UNAVAILABLE' || code === 'OUTCOME_UNKNOWN') return 'unavailable';
  return 'failure';
}
/** Settled domain failures are not successful requests merely because they resolved a promise. */
export function workspaceResultOutcome(value: unknown): WorkspaceOutcome {
  if (value === 'idle' || value === 'busy') return 'idle';
  if (value === 'retry') return 'unavailable';
  if (value === 'dead-letter') return 'failure';
  if (!value || typeof value !== 'object') return 'success';
  const result = value as { state?: unknown; code?: unknown; isError?: unknown };
  if (result.state === 'pending') return 'pending';
  if (result.state === 'conflicted' || result.state === 'conflict' || result.state === 'rebased') return 'conflict';
  if (result.state === 'failed' || result.isError === true) return workspaceErrorOutcome(result);
  return 'success';
}
export function observeWorkspaceOperation<T>(operation: WorkspaceOperation, run: () => Promise<T>): Promise<T> {
  const telemetry = current();
  // Preserve the owner's promise and scheduling when telemetry is disabled.
  return telemetry ? measureOperation(telemetry, operation, run) : run();
}
async function measureOperation<T>(telemetry: WorkspaceTelemetry, operation: WorkspaceOperation, run: () => Promise<T>): Promise<T> {
  const started = clock(telemetry);
  let outcome: WorkspaceOutcome = 'failure';
  try {
    const result = await run();
    try { outcome = workspaceResultOutcome(result); } catch { outcome = 'failure'; }
    return result;
  } catch (error) {
    try { outcome = workspaceErrorOutcome(error); } catch { outcome = 'failure'; }
    throw error;
  }
  finally { emit(telemetry, { schemaVersion: 1, kind: 'operation', operation, outcome, durationMs: Math.max(0, clock(telemetry) - started) }); }
}
export function observeWorkspaceGauge(gauge: WorkspaceGaugeObservation['gauge'], value: number): void {
  emit(current(), { schemaVersion: 1, kind: 'gauge', gauge, value });
}
export function observeWorkspaceResource(resource: WorkspaceResourceUnit, value: number): void {
  emit(current(), { schemaVersion: 1, kind: 'resource', resource, value });
}
/** Valid timestamps only: absent/bad timestamps are missing evidence, never zero lag. */
export function observeProjectionAge(committedAt: string, now?: number): void {
  try { now ??= current()?.wallNow?.() ?? Date.now(); } catch { return; }
  const at = Date.parse(committedAt);
  if (Number.isFinite(at) && now >= at) observeWorkspaceGauge('projection_lag_ms', now - at);
}
