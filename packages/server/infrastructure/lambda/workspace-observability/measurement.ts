import { PROPOSED_WORKSPACE_SLOS, PROPOSED_WORKSPACE_GAUGE_TARGETS, WORKSPACE_OPERATIONS, WORKSPACE_OUTCOMES, availabilityEligible, availabilityFailure,
  type WorkspaceObservation, type WorkspaceOperation, type WorkspaceResourceUsage, type WorkspaceOutcome } from './model';
import { sanitizeWorkspaceObservation } from './telemetry';

export const WORKSPACE_LOAD_PROFILES = Object.freeze({
  small: Object.freeze({ files: 100, bytesPerNote: 1_024, concurrency: 2, iterations: 20, hiddenFraction: 0.2 }),
  medium: Object.freeze({ files: 1_000, bytesPerNote: 2_048, concurrency: 4, iterations: 20, hiddenFraction: 0.4 }),
  large: Object.freeze({ files: 10_000, bytesPerNote: 4_096, concurrency: 8, iterations: 20, hiddenFraction: 0.6 }),
});
export type WorkspaceLoadProfile = keyof typeof WORKSPACE_LOAD_PROFILES;
/** Nearest-rank percentiles; zero samples are unknown, never a zero-ms success. */
export function percentiles(samples: readonly number[]) {
  if (samples.some(value => !Number.isFinite(value) || value < 0)) throw new Error('Invalid duration sample');
  const values = [...samples].sort((a, b) => a - b);
  const rank = (quantile: number) => values.length ? values[Math.max(0, Math.ceil(values.length * quantile) - 1)] : null;
  return { p50: rank(0.5), p95: rank(0.95), p99: rank(0.99) };
}
export class WorkspaceMeasurement {
  private readonly events: WorkspaceObservation[] = [];
  constructor(private readonly maximumSamples = 1_000_000) {
    if (!Number.isSafeInteger(maximumSamples) || maximumSamples < 1) throw new Error('Invalid sample bound');
  }
  /** A full collector is an explicit invalid measurement, never silently sampled data. */
  overflow = false;
  emit = (event: WorkspaceObservation): void => {
    const clean = sanitizeWorkspaceObservation(event);
    if (!clean) throw new Error('Invalid measurement');
    if (this.events.length >= this.maximumSamples) { this.overflow = true; return; }
    this.events.push(clean);
  };
  summary() {
    const operations = Object.fromEntries(WORKSPACE_OPERATIONS.map(operation => {
      const samples = this.events.filter(event => event.kind === 'operation' && event.operation === operation);
      const counts = Object.fromEntries(WORKSPACE_OUTCOMES.map(outcome => [outcome, 0])) as Record<WorkspaceOutcome, number>;
      const durations: number[] = [], allDurations: number[] = [];
      for (const event of samples) if (event.kind === 'operation') {
        counts[event.outcome]++; allDurations.push(event.durationMs);
        if (event.outcome === 'success') durations.push(event.durationMs);
      }
      const eligible = WORKSPACE_OUTCOMES.filter(availabilityEligible).reduce((sum, outcome) => sum + counts[outcome], 0);
      const failures = WORKSPACE_OUTCOMES.filter(availabilityFailure).reduce((sum, outcome) => sum + counts[outcome], 0);
      const target = PROPOSED_WORKSPACE_SLOS[operation], allowedFailures = eligible * (1 - target.availability);
      const latencyMs = percentiles(durations);
      return [operation, {
        samples: samples.length, successSamples: durations.length, outcomes: counts, latencyMs,
        allOutcomeLatencyMs: percentiles(allDurations), tailSampleSufficient: durations.length >= 1_000,
        eligible, failures, availability: eligible ? 1 - failures / eligible : null,
        errorBudget: { allowedFailures, remainingFailures: allowedFailures - failures,
          consumedFraction: eligible ? failures / allowedFailures : null },
        proposedTarget: target,
        meetsProposedTarget: eligible && durations.length ? failures <= allowedFailures &&
          (latencyMs.p50 as number) <= target.latencyMs.p50 && (latencyMs.p95 as number) <= target.latencyMs.p95 &&
          (latencyMs.p99 as number) <= target.latencyMs.p99 : null,
      }];
    })) as Record<WorkspaceOperation, unknown>;
    const resources: WorkspaceResourceUsage = {};
    for (const event of this.events) if (event.kind === 'resource') resources[event.resource] = (resources[event.resource] ?? 0) + event.value;
    const gauges = Object.fromEntries((['projection_lag_ms', 'projection_lag_revisions', 'revocation_detection_ms'] as const).map(gauge => {
      const values = this.events.flatMap(event => event.kind === 'gauge' && event.gauge === gauge ? [event.value] : []);
      const maximum = values.length ? values.reduce((maximum, value) => Math.max(maximum, value), 0) : null;
      return [gauge, { samples: values.length, ...percentiles(values), maximum,
        proposedTarget: PROPOSED_WORKSPACE_GAUGE_TARGETS[gauge],
        meetsProposedTarget: maximum === null ? null : maximum <= PROPOSED_WORKSPACE_GAUGE_TARGETS[gauge] }];
    }));
    return { valid: !this.overflow, observations: this.events.length, operations, gauges, resources,
      resourceCoverage: 'Only explicitly observed units; absent units are unknown, not zero',
      acceptance: 'PROPOSED targets; synthetic observations cannot establish a deployed SLO or 30-day error budget' };
  }
}
