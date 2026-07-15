export type LongOperationKind =
  | "vault-encrypt"
  | "vault-decrypt"
  | "sync"
  | "background-sync"
  | "initial-reconciliation"
  | "stress-test"
  | (string & {});

export type LongOperationPlacement = "protected" | "background" | "notice";

export type LongOperationLifecycleState =
  | "queued"
  | "running"
  | "paused"
  | "retrying"
  | "completed"
  | "failed"
  | "cancelled";

export type LongOperationStallState =
  | "working"
  | "slow"
  | "possibly-stalled"
  | "failed";

export interface EtaSnapshot {
  remainingMs: number | null;
  approximate: boolean;
  basis: "items" | "bytes" | "phase" | "unknown";
  confidence: "warming" | "estimated" | "unknown";
}

export interface ThroughputSnapshot {
  itemsPerSecond: number | null;
  bytesPerSecond: number | null;
}

export interface LongOperationCapabilities {
  canPause: boolean;
  canCancel: boolean;
  protectedPhase: boolean;
}

export interface LongOperationProgressSnapshot {
  id: string;
  kind: LongOperationKind;
  operationName: string;
  vaultId?: string;
  vaultName?: string;
  phase: string;
  lifecycleState: LongOperationLifecycleState;
  placement: LongOperationPlacement;
  processedItems: number;
  totalItems: number | null;
  processedBytes: number;
  totalBytes: number | null;
  percent: number | null;
  approximatePercent: boolean;
  eta: EtaSnapshot;
  throughput: ThroughputSnapshot;
  elapsedMs: number;
  startedAt: number;
  updatedAt: number;
  lastProgressAt: number;
  stallState: LongOperationStallState;
  capabilities: LongOperationCapabilities;
  message?: string;
  warning?: string;
  failureReason?: string;
}

export interface WorkloadGuardLimits {
  warnItems: number;
  maxItems: number;
  warnBytes: number;
  maxBytes: number;
  warnSingleItemBytes: number;
  maxSingleItemBytes: number;
}

export interface WorkloadSummary {
  totalItems: number;
  totalBytes: number | null;
  largestItemBytes: number | null;
}

export interface WorkloadGuardResult {
  ok: boolean;
  warnings: string[];
  error: string | null;
}

export const DEFAULT_LONG_OPERATION_LIMITS: WorkloadGuardLimits = {
  warnItems: 10_000,
  maxItems: 250_000,
  warnBytes: 1_024 * 1_024 * 1_024,
  maxBytes: 8 * 1_024 * 1_024 * 1_024,
  warnSingleItemBytes: 128 * 1_024 * 1_024,
  maxSingleItemBytes: 512 * 1_024 * 1_024,
};

export const DEFAULT_LONG_OPERATION_BATCH_SIZE = 25;
export const DEFAULT_PROGRESS_PUBLISH_INTERVAL_MS = 250;
export const DEFAULT_SLOW_OPERATION_MS = 15_000;
export const DEFAULT_STALLED_OPERATION_MS = 45_000;

const TERMINAL_STATES = new Set<LongOperationLifecycleState>([
  "completed",
  "failed",
  "cancelled",
]);

let operationSequence = 0;

function nextOperationId(kind: LongOperationKind): string {
  operationSequence += 1;
  return `vg-op-${kind}-${Date.now().toString(36)}-${operationSequence.toString(36)}`;
}

function clampPercent(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(100, value));
}

function defaultEta(approximate = false): EtaSnapshot {
  return {
    remainingMs: null,
    approximate,
    basis: "unknown",
    confidence: "unknown",
  };
}

function defaultThroughput(): ThroughputSnapshot {
  return {
    itemsPerSecond: null,
    bytesPerSecond: null,
  };
}

function isTerminalState(state: LongOperationLifecycleState): boolean {
  return TERMINAL_STATES.has(state);
}

function cloneSnapshot(snapshot: LongOperationProgressSnapshot): LongOperationProgressSnapshot {
  return {
    ...snapshot,
    eta: { ...snapshot.eta },
    throughput: { ...snapshot.throughput },
    capabilities: { ...snapshot.capabilities },
  };
}

export function summarizeFileLikeWorkload(
  files: Array<{ stat?: { size?: number } | null }>
): WorkloadSummary {
  let totalBytes = 0;
  let largestItemBytes = 0;
  let sawSize = false;

  for (const file of files) {
    const size = file.stat?.size;
    if (typeof size !== "number" || !Number.isFinite(size) || size < 0) {
      continue;
    }
    sawSize = true;
    totalBytes += size;
    largestItemBytes = Math.max(largestItemBytes, size);
  }

  return {
    totalItems: files.length,
    totalBytes: sawSize ? totalBytes : null,
    largestItemBytes: sawSize ? largestItemBytes : null,
  };
}

export function evaluateWorkloadGuard(
  workload: WorkloadSummary,
  limits: WorkloadGuardLimits = DEFAULT_LONG_OPERATION_LIMITS
): WorkloadGuardResult {
  const warnings: string[] = [];

  if (workload.totalItems > limits.maxItems) {
    return {
      ok: false,
      warnings,
      error:
        `VaultGuard refused to start this operation because it would touch ${workload.totalItems.toLocaleString()} items. ` +
        `The current safety limit is ${limits.maxItems.toLocaleString()} items.`,
    };
  }

  if (workload.totalBytes !== null && workload.totalBytes > limits.maxBytes) {
    return {
      ok: false,
      warnings,
      error:
        `VaultGuard refused to start this operation because it would process ${formatBytes(workload.totalBytes)}. ` +
        `The current safety limit is ${formatBytes(limits.maxBytes)}.`,
    };
  }

  if (
    workload.largestItemBytes !== null &&
    workload.largestItemBytes > limits.maxSingleItemBytes
  ) {
    return {
      ok: false,
      warnings,
      error:
        `VaultGuard refused to start this operation because one file is ${formatBytes(workload.largestItemBytes)}. ` +
        `The current per-file safety limit is ${formatBytes(limits.maxSingleItemBytes)}.`,
    };
  }

  if (workload.totalItems > limits.warnItems) {
    warnings.push(
      `Large vault workload: ${workload.totalItems.toLocaleString()} items. Progress will update in batches.`
    );
  }
  if (workload.totalBytes !== null && workload.totalBytes > limits.warnBytes) {
    warnings.push(
      `Large byte workload: ${formatBytes(workload.totalBytes)}. ETA is approximate.`
    );
  }
  if (
    workload.largestItemBytes !== null &&
    workload.largestItemBytes > limits.warnSingleItemBytes
  ) {
    warnings.push(
      `Large single file: ${formatBytes(workload.largestItemBytes)}. This step may look slow while that file is processed.`
    );
  }

  return { ok: true, warnings, error: null };
}

interface TimeWeightedRateState {
  baselineAt: number | null;
  baselineValue: number | null;
  lastObservedAt: number | null;
  lastSampleAt: number | null;
  lastValue: number | null;
  progressSamples: number;
  ratePerSecond: number | null;
}

function createTimeWeightedRateState(): TimeWeightedRateState {
  return {
    baselineAt: null,
    baselineValue: null,
    lastObservedAt: null,
    lastSampleAt: null,
    lastValue: null,
    progressSamples: 0,
    ratePerSecond: null,
  };
}

export class MovingAverageEstimator {
  private readonly itemRate = createTimeWeightedRateState();
  private readonly byteRate = createTimeWeightedRateState();

  record(input: {
    atMs: number;
    processedItems: number;
    processedBytes: number;
    totalItems?: number | null;
    totalBytes?: number | null;
    approximate?: boolean;
  }): { eta: EtaSnapshot; throughput: ThroughputSnapshot } {
    this.recordRate(this.itemRate, input.atMs, input.processedItems);
    this.recordRate(this.byteRate, input.atMs, input.processedBytes);

    const throughput = {
      itemsPerSecond: this.itemRate.ratePerSecond,
      bytesPerSecond: this.byteRate.ratePerSecond,
    };

    return {
      eta: this.estimateEta(input),
      throughput,
    };
  }

  private estimateEta(input: {
    processedItems: number;
    processedBytes: number;
    totalItems?: number | null;
    totalBytes?: number | null;
    approximate?: boolean;
  }): EtaSnapshot {
    if (
      input.totalBytes !== null &&
      input.totalBytes !== undefined &&
      input.totalBytes > 0 &&
      this.byteRate.ratePerSecond !== null &&
      this.byteRate.ratePerSecond > 0
    ) {
      return {
        remainingMs: Math.max(
          0,
          ((input.totalBytes - input.processedBytes) / this.byteRate.ratePerSecond) * 1000
        ),
        approximate: Boolean(input.approximate),
        basis: "bytes",
        confidence: "estimated",
      };
    }

    if (
      input.totalItems !== null &&
      input.totalItems !== undefined &&
      input.totalItems > 0 &&
      this.itemRate.ratePerSecond !== null &&
      this.itemRate.ratePerSecond > 0
    ) {
      return {
        remainingMs: Math.max(
          0,
          ((input.totalItems - input.processedItems) / this.itemRate.ratePerSecond) * 1000
        ),
        approximate: Boolean(input.approximate),
        basis: "items",
        confidence: "estimated",
      };
    }

    return {
      remainingMs: null,
      approximate: Boolean(input.approximate),
      basis: input.approximate ? "phase" : "unknown",
      confidence: "warming",
    };
  }

  private recordRate(state: TimeWeightedRateState, atMs: number, value: number): void {
    if (
      state.baselineAt === null ||
      state.baselineValue === null ||
      state.lastObservedAt === null ||
      state.lastSampleAt === null ||
      state.lastValue === null ||
      atMs < state.lastObservedAt ||
      value < state.lastValue
    ) {
      this.resetRate(state, atMs, value);
      return;
    }

    state.lastObservedAt = atMs;
    if (value <= state.lastValue) return;

    state.lastValue = value;
    if (atMs <= state.lastSampleAt) return;

    state.lastSampleAt = atMs;
    state.progressSamples += 1;
    const elapsedSeconds = (atMs - state.baselineAt) / 1000;
    const processedSinceBaseline = value - state.baselineValue;
    if (state.progressSamples < 2 || elapsedSeconds <= 0 || processedSinceBaseline <= 0) {
      state.ratePerSecond = null;
      return;
    }

    // Weight progress by the wall time for the whole counter series. This
    // prevents a single tiny or huge file from dominating ETA merely because
    // it was the most recent progress tick.
    state.ratePerSecond = processedSinceBaseline / elapsedSeconds;
  }

  private resetRate(state: TimeWeightedRateState, atMs: number, value: number): void {
    state.baselineAt = atMs;
    state.baselineValue = value;
    state.lastObservedAt = atMs;
    state.lastSampleAt = atMs;
    state.lastValue = value;
    state.progressSamples = 0;
    state.ratePerSecond = null;
  }
}

export function computeStallState(input: {
  nowMs: number;
  lastProgressAt: number;
  lifecycleState: LongOperationLifecycleState;
  slowAfterMs?: number;
  stalledAfterMs?: number;
}): LongOperationStallState {
  if (input.lifecycleState === "failed") return "failed";
  if (isTerminalState(input.lifecycleState) || input.lifecycleState === "paused") {
    return "working";
  }

  const idleMs = input.nowMs - input.lastProgressAt;
  if (idleMs >= (input.stalledAfterMs ?? DEFAULT_STALLED_OPERATION_MS)) {
    return "possibly-stalled";
  }
  if (idleMs >= (input.slowAfterMs ?? DEFAULT_SLOW_OPERATION_MS)) {
    return "slow";
  }
  return "working";
}

export function createThrottledPublisher<T>(
  publish: (value: T) => void,
  intervalMs = DEFAULT_PROGRESS_PUBLISH_INTERVAL_MS,
  now: () => number = Date.now
): (value: T, options?: { force?: boolean }) => boolean {
  let lastPublishedAt = -Infinity;
  return (value: T, options: { force?: boolean } = {}) => {
    const current = now();
    if (!options.force && current - lastPublishedAt < intervalMs) {
      return false;
    }
    lastPublishedAt = current;
    publish(value);
    return true;
  };
}

export class LongOperationToken {
  private pauseRequested = false;
  private cancelRequested = false;

  constructor(
    private capabilities: LongOperationCapabilities,
    private readonly sleep: (ms: number) => Promise<void> = delay
  ) {}

  get isPauseRequested(): boolean {
    return this.pauseRequested;
  }

  get isCancelRequested(): boolean {
    return this.cancelRequested;
  }

  requestPause(): boolean {
    if (!this.capabilities.canPause) return false;
    this.pauseRequested = true;
    return true;
  }

  resume(): boolean {
    if (!this.capabilities.canPause) return false;
    this.pauseRequested = false;
    return true;
  }

  requestCancel(): boolean {
    if (!this.capabilities.canCancel) return false;
    this.cancelRequested = true;
    return true;
  }

  updateCapabilities(capabilities: LongOperationCapabilities): void {
    this.capabilities = capabilities;
    if (!capabilities.canPause) {
      this.pauseRequested = false;
    }
    if (!capabilities.canCancel) {
      this.cancelRequested = false;
    }
  }

  throwIfCancellationRequested(): void {
    if (this.cancelRequested) {
      throw new LongOperationCancelledError("Operation cancellation requested.");
    }
  }

  async checkpoint(): Promise<void> {
    this.throwIfCancellationRequested();
    while (this.pauseRequested) {
      await this.sleep(250);
      this.throwIfCancellationRequested();
    }
  }
}

export class LongOperationCancelledError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LongOperationCancelledError";
  }
}

export class LongOperationConflictError extends Error {
  constructor(readonly conflict: LongOperationProgressSnapshot) {
    super(`VaultGuard operation already in progress: ${conflict.operationName}`);
    this.name = "LongOperationConflictError";
  }
}

interface ActiveOperation {
  estimator: MovingAverageEstimator;
  snapshot: LongOperationProgressSnapshot;
  token: LongOperationToken;
  conflictKey: string;
  conflictsWith: Set<LongOperationKind>;
  watchdogTimer: ReturnType<typeof setInterval> | null;
  cleanupTimer: ReturnType<typeof setTimeout> | null;
  slowAfterMs: number;
  stalledAfterMs: number;
}

export interface LongOperationStartOptions {
  id?: string;
  kind: LongOperationKind;
  operationName: string;
  phase?: string;
  vaultId?: string;
  vaultName?: string;
  placement?: LongOperationPlacement;
  totalItems?: number | null;
  totalBytes?: number | null;
  processedItems?: number;
  processedBytes?: number;
  approximatePercent?: boolean;
  approximateTotal?: boolean;
  percent?: number | null;
  message?: string;
  warning?: string;
  capabilities?: Partial<LongOperationCapabilities>;
  conflictKey?: string;
  conflictsWith?: LongOperationKind[];
  slowAfterMs?: number;
  stalledAfterMs?: number;
  watchdogIntervalMs?: number;
}

export interface LongOperationUpdate {
  phase?: string;
  lifecycleState?: LongOperationLifecycleState;
  processedItems?: number;
  totalItems?: number | null;
  processedBytes?: number;
  totalBytes?: number | null;
  percent?: number | null;
  approximatePercent?: boolean;
  message?: string;
  warning?: string;
  failureReason?: string;
  capabilities?: Partial<LongOperationCapabilities>;
}

export type LongOperationListener = (
  snapshot: LongOperationProgressSnapshot,
  event: "started" | "updated" | "finished" | "removed"
) => void;

export class LongOperationHandle {
  constructor(
    readonly id: string,
    readonly token: LongOperationToken,
    private readonly manager: LongOperationManager
  ) {}

  get snapshot(): LongOperationProgressSnapshot | null {
    return this.manager.getSnapshot(this.id);
  }

  update(update: LongOperationUpdate): void {
    this.manager.update(this.id, update);
  }

  complete(message?: string): void {
    this.manager.finish(this.id, "completed", message);
  }

  cancel(message?: string): void {
    this.manager.finish(this.id, "cancelled", message);
  }

  fail(error: unknown): void {
    const message = error instanceof Error ? error.message : String(error);
    this.manager.finish(this.id, "failed", message);
  }
}

export interface LongOperationManagerOptions {
  now?: () => number;
  terminalSnapshotTtlMs?: number;
}

export class LongOperationManager {
  private readonly operations = new Map<string, ActiveOperation>();
  private readonly listeners = new Set<LongOperationListener>();
  private readonly now: () => number;
  private readonly terminalSnapshotTtlMs: number;

  constructor(options: LongOperationManagerOptions = {}) {
    this.now = options.now ?? Date.now;
    this.terminalSnapshotTtlMs = options.terminalSnapshotTtlMs ?? 6_000;
  }

  begin(options: LongOperationStartOptions): LongOperationHandle {
    const conflictKey = options.conflictKey ?? "global";
    const conflictsWith = new Set<LongOperationKind>([
      options.kind,
      ...(options.conflictsWith ?? []),
    ]);
    const conflict = this.findConflict(conflictKey, conflictsWith);
    if (conflict) {
      throw new LongOperationConflictError(conflict);
    }

    const nowMs = this.now();
    const capabilities: LongOperationCapabilities = {
      canPause: options.capabilities?.canPause ?? false,
      canCancel: options.capabilities?.canCancel ?? false,
      protectedPhase: options.capabilities?.protectedPhase ?? false,
    };
    const token = new LongOperationToken(capabilities);
    const totalItems = options.totalItems ?? null;
    const totalBytes = options.totalBytes ?? null;
    const processedItems = options.processedItems ?? 0;
    const processedBytes = options.processedBytes ?? 0;
    const estimator = new MovingAverageEstimator();
    const estimate = estimator.record({
      atMs: nowMs,
      processedItems,
      processedBytes,
      totalItems,
      totalBytes,
      approximate: options.approximateTotal,
    });

    const snapshot: LongOperationProgressSnapshot = {
      id: options.id ?? nextOperationId(options.kind),
      kind: options.kind,
      operationName: options.operationName,
      vaultId: options.vaultId,
      vaultName: options.vaultName,
      phase: options.phase ?? "Starting",
      lifecycleState: "running",
      placement: options.placement ?? "background",
      processedItems,
      totalItems,
      processedBytes,
      totalBytes,
      percent: this.computePercent({
        percent: options.percent,
        processedItems,
        totalItems,
        processedBytes,
        totalBytes,
      }),
      approximatePercent: Boolean(options.approximatePercent ?? options.approximateTotal),
      eta: estimate.eta,
      throughput: estimate.throughput,
      elapsedMs: 0,
      startedAt: nowMs,
      updatedAt: nowMs,
      lastProgressAt: nowMs,
      stallState: "working",
      capabilities,
      message: options.message,
      warning: options.warning,
    };

    const active: ActiveOperation = {
      estimator,
      snapshot,
      token,
      conflictKey,
      conflictsWith,
      watchdogTimer: null,
      cleanupTimer: null,
      slowAfterMs: options.slowAfterMs ?? DEFAULT_SLOW_OPERATION_MS,
      stalledAfterMs: options.stalledAfterMs ?? DEFAULT_STALLED_OPERATION_MS,
    };
    this.operations.set(snapshot.id, active);
    active.watchdogTimer = setInterval(
      () => this.refreshWatchdog(snapshot.id),
      options.watchdogIntervalMs ?? 1_000
    );
    this.emit(snapshot, "started");

    return new LongOperationHandle(snapshot.id, token, this);
  }

  subscribe(listener: LongOperationListener): () => void {
    this.listeners.add(listener);
    for (const snapshot of this.getSnapshots()) {
      listener(snapshot, "updated");
    }
    return () => {
      this.listeners.delete(listener);
    };
  }

  getSnapshot(id: string): LongOperationProgressSnapshot | null {
    const active = this.operations.get(id);
    return active ? cloneSnapshot(active.snapshot) : null;
  }

  getSnapshots(): LongOperationProgressSnapshot[] {
    return [...this.operations.values()]
      .map((entry) => cloneSnapshot(entry.snapshot))
      .sort((a, b) => a.startedAt - b.startedAt);
  }

  getPrimarySnapshot(): LongOperationProgressSnapshot | null {
    const snapshots = this.getSnapshots();
    const active = snapshots.find((snapshot) => !isTerminalState(snapshot.lifecycleState));
    return active ?? (snapshots.length > 0 ? snapshots[snapshots.length - 1] : null);
  }

  requestCancel(id: string): boolean {
    const active = this.operations.get(id);
    if (!active) return false;
    return active.token.requestCancel();
  }

  requestPause(id: string): boolean {
    const active = this.operations.get(id);
    if (!active) return false;
    const ok = active.token.requestPause();
    if (ok) this.update(id, { lifecycleState: "paused" });
    return ok;
  }

  resume(id: string): boolean {
    const active = this.operations.get(id);
    if (!active) return false;
    const ok = active.token.resume();
    if (ok) this.update(id, { lifecycleState: "running" });
    return ok;
  }

  update(id: string, update: LongOperationUpdate): void {
    const active = this.operations.get(id);
    if (!active || isTerminalState(active.snapshot.lifecycleState)) return;

    const nowMs = this.now();
    const previous = active.snapshot;
    const processedItems = update.processedItems ?? previous.processedItems;
    const processedBytes = update.processedBytes ?? previous.processedBytes;
    const totalItems = update.totalItems !== undefined ? update.totalItems : previous.totalItems;
    const totalBytes = update.totalBytes !== undefined ? update.totalBytes : previous.totalBytes;
    const progressed =
      processedItems !== previous.processedItems ||
      processedBytes !== previous.processedBytes ||
      update.percent !== undefined ||
      update.phase !== undefined;
    const estimate = active.estimator.record({
      atMs: nowMs,
      processedItems,
      processedBytes,
      totalItems,
      totalBytes,
      approximate: update.approximatePercent ?? previous.approximatePercent,
    });

    const capabilities = {
      ...previous.capabilities,
      ...update.capabilities,
    };

    active.snapshot = {
      ...previous,
      phase: update.phase ?? previous.phase,
      lifecycleState: update.lifecycleState ?? previous.lifecycleState,
      processedItems,
      totalItems,
      processedBytes,
      totalBytes,
      percent: this.computePercent({
        percent: update.percent,
        processedItems,
        totalItems,
        processedBytes,
        totalBytes,
      }),
      approximatePercent: update.approximatePercent ?? previous.approximatePercent,
      eta: estimate.eta,
      throughput: estimate.throughput,
      elapsedMs: nowMs - previous.startedAt,
      updatedAt: nowMs,
      lastProgressAt: progressed ? nowMs : previous.lastProgressAt,
      stallState: computeStallState({
        nowMs,
        lastProgressAt: progressed ? nowMs : previous.lastProgressAt,
        lifecycleState: update.lifecycleState ?? previous.lifecycleState,
        slowAfterMs: active.slowAfterMs,
        stalledAfterMs: active.stalledAfterMs,
      }),
      capabilities,
      message: update.message ?? previous.message,
      warning: update.warning ?? previous.warning,
      failureReason: update.failureReason ?? previous.failureReason,
    };
    active.token.updateCapabilities(capabilities);
    this.emit(active.snapshot, "updated");
  }

  finish(
    id: string,
    lifecycleState: "completed" | "failed" | "cancelled",
    message?: string
  ): void {
    const active = this.operations.get(id);
    if (!active) return;
    const nowMs = this.now();
    if (active.watchdogTimer) {
      clearInterval(active.watchdogTimer);
      active.watchdogTimer = null;
    }
    active.snapshot = {
      ...active.snapshot,
      lifecycleState,
      phase:
        lifecycleState === "completed"
          ? "Complete"
          : lifecycleState === "cancelled"
            ? "Cancelled"
            : "Failed",
      percent: lifecycleState === "completed" ? 100 : active.snapshot.percent,
      elapsedMs: nowMs - active.snapshot.startedAt,
      updatedAt: nowMs,
      lastProgressAt: nowMs,
      stallState: lifecycleState === "failed" ? "failed" : "working",
      message: message ?? active.snapshot.message,
      failureReason: lifecycleState === "failed" ? message : active.snapshot.failureReason,
      capabilities: {
        ...active.snapshot.capabilities,
        canPause: false,
        canCancel: false,
        protectedPhase: false,
      },
      eta: {
        remainingMs: lifecycleState === "completed" ? 0 : null,
        approximate: false,
        basis: lifecycleState === "completed" ? "items" : "unknown",
        confidence: lifecycleState === "completed" ? "estimated" : "unknown",
      },
    };
    this.emit(active.snapshot, "finished");

    if (this.terminalSnapshotTtlMs <= 0) {
      this.remove(id);
      return;
    }

    active.cleanupTimer = setTimeout(() => this.remove(id), this.terminalSnapshotTtlMs);
  }

  remove(id: string): void {
    const active = this.operations.get(id);
    if (!active) return;
    if (active.watchdogTimer) clearInterval(active.watchdogTimer);
    if (active.cleanupTimer) clearTimeout(active.cleanupTimer);
    this.operations.delete(id);
    this.emit(active.snapshot, "removed");
  }

  destroy(): void {
    for (const id of [...this.operations.keys()]) {
      this.remove(id);
    }
    this.listeners.clear();
  }

  private findConflict(
    conflictKey: string,
    conflictsWith: Set<LongOperationKind>
  ): LongOperationProgressSnapshot | null {
    for (const operation of this.operations.values()) {
      if (operation.conflictKey !== conflictKey) continue;
      if (isTerminalState(operation.snapshot.lifecycleState)) continue;
      if (!conflictsWith.has(operation.snapshot.kind)) continue;
      return cloneSnapshot(operation.snapshot);
    }
    return null;
  }

  private refreshWatchdog(id: string): void {
    const active = this.operations.get(id);
    if (!active || isTerminalState(active.snapshot.lifecycleState)) return;
    const nowMs = this.now();
    const nextStallState = computeStallState({
      nowMs,
      lastProgressAt: active.snapshot.lastProgressAt,
      lifecycleState: active.snapshot.lifecycleState,
      slowAfterMs: active.slowAfterMs,
      stalledAfterMs: active.stalledAfterMs,
    });
    if (nextStallState === active.snapshot.stallState) return;
    active.snapshot = {
      ...active.snapshot,
      stallState: nextStallState,
      elapsedMs: nowMs - active.snapshot.startedAt,
      updatedAt: nowMs,
    };
    this.emit(active.snapshot, "updated");
  }

  private emit(
    snapshot: LongOperationProgressSnapshot,
    event: "started" | "updated" | "finished" | "removed"
  ): void {
    const cloned = cloneSnapshot(snapshot);
    for (const listener of this.listeners) {
      listener(cloned, event);
    }
  }

  private computePercent(input: {
    percent?: number | null;
    processedItems: number;
    totalItems: number | null;
    processedBytes: number;
    totalBytes: number | null;
  }): number | null {
    if (input.percent !== undefined) {
      return input.percent === null ? null : clampPercent(input.percent);
    }
    if (input.totalBytes !== null && input.totalBytes > 0) {
      return clampPercent((input.processedBytes / input.totalBytes) * 100);
    }
    if (input.totalItems !== null && input.totalItems > 0) {
      return clampPercent((input.processedItems / input.totalItems) * 100);
    }
    return null;
  }
}

export async function processInBatches<T>(
  items: Iterable<T>,
  processor: (item: T, index: number) => Promise<void> | void,
  options: {
    batchSize?: number;
    token?: LongOperationToken;
    onBatch?: (processed: number) => Promise<void> | void;
    yieldFn?: () => Promise<void>;
  } = {}
): Promise<void> {
  const batchSize = Math.max(1, options.batchSize ?? DEFAULT_LONG_OPERATION_BATCH_SIZE);
  const yieldFn = options.yieldFn ?? yieldToEventLoop;
  let index = 0;

  for (const item of items) {
    await options.token?.checkpoint();
    await processor(item, index);
    index += 1;
    if (index % batchSize === 0) {
      await options.onBatch?.(index);
      await yieldFn();
    }
  }

  if (index % batchSize !== 0) {
    await options.onBatch?.(index);
  }
}

export function yieldToEventLoop(): Promise<void> {
  return delay(0);
}

export function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function formatDuration(ms: number | null): string {
  if (ms === null || !Number.isFinite(ms)) return "calculating";
  const totalSeconds = Math.max(0, Math.round(ms / 1000));
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  const decimals = value >= 10 || unitIndex === 0 ? 0 : 1;
  return `${value.toFixed(decimals)} ${units[unitIndex]}`;
}

export function describeConflict(conflict: LongOperationProgressSnapshot): string {
  return `${conflict.operationName} is already ${conflict.lifecycleState} (${conflict.phase}).`;
}

export function isLongOperationConflict(error: unknown): error is LongOperationConflictError {
  return error instanceof LongOperationConflictError;
}
