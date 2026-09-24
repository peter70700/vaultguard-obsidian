/** P7-003/004: fixed, content-free telemetry vocabulary. No caller-controlled labels. */
export const WORKSPACE_OPERATIONS = [
  'auth', 'orientation', 'list', 'search', 'read', 'graph', 'base', 'context',
  'proposal', 'apply', 'head_publication', 'projection_graph', 'projection_lexical',
  'projection_rebuild', 'revocation', 'recovery',
  'migration_preflight', 'migration_adoption', 'migration_rollback', 'semantic', 'projection_semantic',
] as const;
export type WorkspaceOperation = typeof WORKSPACE_OPERATIONS[number];
export const WORKSPACE_OUTCOMES = ['success', 'denied', 'invalid', 'conflict', 'throttled', 'unavailable', 'pending', 'failure', 'idle'] as const;
export type WorkspaceOutcome = typeof WORKSPACE_OUTCOMES[number];
export const WORKSPACE_RESOURCE_UNITS = [
  'dynamodb_read_requests', 'dynamodb_write_requests', 'dynamodb_read_units', 'dynamodb_write_units',
  's3_get_requests', 's3_put_requests', 's3_list_requests', 's3_delete_requests',
  'kms_requests', 'compute_ms', 'egress_bytes', 'index_bytes', 'storage_byte_hours',
  'queue_requests', 'telemetry_bytes', 'backup_byte_hours', 'auth_active_users',
  'compute_gb_seconds', 'compute_invocations', 'database_byte_hours', 'kms_key_hours',
  'index_byte_hours', 'index_compute_gb_seconds', 'telemetry_storage_byte_hours',
  'telemetry_metric_hours', 'support_minutes', 'api_gateway_requests', 'semantic_provider_requests', 'semantic_provider_tokens',
] as const;
export type WorkspaceResourceUnit = typeof WORKSPACE_RESOURCE_UNITS[number];
export type WorkspaceResourceUsage = Partial<Record<WorkspaceResourceUnit, number>>;

export interface WorkspaceOperationObservation {
  readonly schemaVersion: 1;
  readonly kind: 'operation';
  readonly operation: WorkspaceOperation;
  readonly outcome: WorkspaceOutcome;
  readonly durationMs: number;
}
export interface WorkspaceGaugeObservation {
  readonly schemaVersion: 1;
  readonly kind: 'gauge';
  readonly gauge: 'projection_lag_ms' | 'projection_lag_revisions' | 'revocation_detection_ms';
  readonly value: number;
}
export interface WorkspaceResourceObservation {
  readonly schemaVersion: 1;
  readonly kind: 'resource';
  readonly resource: WorkspaceResourceUnit;
  readonly value: number;
}
export type WorkspaceObservation = WorkspaceOperationObservation | WorkspaceGaugeObservation | WorkspaceResourceObservation;

export interface ProposedWorkspaceSlo {
  readonly status: 'PROPOSED';
  readonly windowDays: 30;
  readonly availability: number;
  readonly latencyMs: { readonly p50: number; readonly p95: number; readonly p99: number };
}
const proposed = (p50: number, p95: number, p99: number): ProposedWorkspaceSlo =>
  Object.freeze({ status: 'PROPOSED', windowDays: 30, availability: 0.999, latencyMs: Object.freeze({ p50, p95, p99 }) });
/** Engineering hypotheses only. VAULTGUARD-69 owns accepted targets and deployed measurements. */
export const PROPOSED_WORKSPACE_SLOS: Readonly<Record<WorkspaceOperation, ProposedWorkspaceSlo>> = Object.freeze({
  auth: proposed(100, 500, 1_000), orientation: proposed(250, 1_000, 2_000),
  list: proposed(250, 1_000, 2_000), search: proposed(500, 2_000, 5_000), read: proposed(250, 1_000, 2_000),
  graph: proposed(500, 2_000, 5_000), base: proposed(500, 2_000, 5_000), context: proposed(1_000, 3_000, 8_000),
  proposal: proposed(1_000, 5_000, 15_000), apply: proposed(1_000, 5_000, 15_000),
  head_publication: proposed(100, 500, 2_000), projection_graph: proposed(5_000, 30_000, 120_000),
  projection_lexical: proposed(5_000, 30_000, 120_000), projection_rebuild: proposed(30_000, 300_000, 900_000),
  revocation: proposed(100, 1_000, 2_000), recovery: proposed(1_000, 10_000, 30_000),
  migration_preflight: proposed(5_000, 30_000, 120_000), migration_adoption: proposed(1_000, 5_000, 15_000),
  migration_rollback: proposed(1_000, 5_000, 15_000),
  semantic: proposed(1_000, 5_000, 20_000), projection_semantic: proposed(5_000, 30_000, 120_000),
});
export const PROPOSED_WORKSPACE_GAUGE_TARGETS = Object.freeze({
  status: 'PROPOSED' as const,
  projection_lag_ms: 60_000, projection_lag_revisions: 10, revocation_detection_ms: 1_000,
  recoveryPointObjective: 'No acknowledged committed revision lost; requires deployed durability drills',
  recoveryTimeObjectiveMs: 900_000,
});
/** Denials/invalid input/optimistic conflicts are reported, but not service availability failures. */
export function availabilityEligible(outcome: WorkspaceOutcome): boolean {
  return outcome !== 'denied' && outcome !== 'invalid' && outcome !== 'conflict' && outcome !== 'idle';
}
export const availabilityFailure = (outcome: WorkspaceOutcome): boolean =>
  outcome === 'throttled' || outcome === 'unavailable' || outcome === 'pending' || outcome === 'failure';
