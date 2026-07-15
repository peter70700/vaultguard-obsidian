import type { PermissionsGraphLayoutStore } from "./permissions-graph-layout";

export const PERMISSIONS_GRAPH_COMMITTED_TRANSITION_PHASE_F_MARKER =
  "vg-permissions-graph-transition-phase-f-v1";
export const PERMISSIONS_GRAPH_TRANSITION_MIN_DURATION_MS = 150;
export const PERMISSIONS_GRAPH_TRANSITION_MAX_DURATION_MS = 300;
export const PERMISSIONS_GRAPH_TRANSITION_DEFAULT_DURATION_MS = 300;
export const PERMISSIONS_GRAPH_TRANSITION_FRAME_GUARD_MS = 50;
export const PERMISSIONS_GRAPH_TRANSITION_NODE_GUARD = 50_000;
export const PERMISSIONS_GRAPH_TRANSITION_SOURCE_MEMORY_LIMIT_BYTES = 128 * 1024 * 1024;

export type PermissionsGraphCommittedTransitionMode = "animated" | "immediate";
export type PermissionsGraphCommittedTransitionImmediateReason =
  | "reduced-motion"
  | "node-limit"
  | "memory-limit"
  | "frame-budget"
  | null;
export type PermissionsGraphCommittedTransitionStatus =
  | "active"
  | "completed"
  | "cancelled"
  | "superseded";

export interface PermissionsGraphCommittedTransitionInput {
  readonly layout: PermissionsGraphLayoutStore;
  readonly topologyFingerprint: string;
  readonly layoutGeneration: number;
  readonly coordinateRevision: number;
  readonly ordinals: readonly number[] | Uint32Array;
  /** Interleaved x/y values in the same order as `ordinals`. */
  readonly sourceCoordinates: Float32Array;
  readonly startedAtMs?: number;
  readonly durationMs?: number;
  readonly reducedMotion?: boolean;
  readonly previousFrameDurationMs?: number;
  readonly sourceMemoryLimitBytes?: number;
  readonly signal?: AbortSignal;
}

export interface PermissionsGraphCommittedTransitionFrame {
  readonly marker: typeof PERMISSIONS_GRAPH_COMMITTED_TRANSITION_PHASE_F_MARKER;
  readonly status: PermissionsGraphCommittedTransitionStatus;
  readonly mode: PermissionsGraphCommittedTransitionMode;
  readonly immediateReason: PermissionsGraphCommittedTransitionImmediateReason;
  readonly progress: number;
  readonly ordinals: Uint32Array;
  readonly coordinates: Float32Array;
  readonly layoutGeneration: number;
  readonly coordinateRevision: number;
  readonly frameCount: number;
  readonly droppedFrameCount: number;
  readonly skippedFrameCount: number;
}

export interface PermissionsGraphCommittedTransitionMetrics {
  readonly status: PermissionsGraphCommittedTransitionStatus;
  readonly mode: PermissionsGraphCommittedTransitionMode;
  readonly immediateReason: PermissionsGraphCommittedTransitionImmediateReason;
  readonly ordinalCount: number;
  readonly durationMs: number;
  readonly progress: number;
  readonly frameCount: number;
  readonly droppedFrameCount: number;
  readonly skippedFrameCount: number;
  readonly maximumFrameDurationMs: number;
  readonly sourceBufferBytes: number;
  readonly targetBufferBytes: number;
  readonly layoutGeneration: number;
  readonly coordinateRevision: number;
}

export type PermissionsGraphCommittedTransitionErrorCode =
  | "IDENTITY_MISMATCH"
  | "INVALID_DURATION"
  | "INVALID_ORDINAL"
  | "INVALID_REVISION"
  | "INVALID_SOURCE";

export class PermissionsGraphCommittedTransitionError extends Error {
  constructor(readonly code: PermissionsGraphCommittedTransitionErrorCode, message: string) {
    super(message);
    this.name = "PermissionsGraphCommittedTransitionError";
  }
}

interface OrderedSource {
  readonly ordinal: number;
  readonly sourceX: number;
  readonly sourceY: number;
}

export class PermissionsGraphCommittedTransition {
  readonly marker = PERMISSIONS_GRAPH_COMMITTED_TRANSITION_PHASE_F_MARKER;
  readonly ordinals: Uint32Array;
  readonly durationMs: number;
  readonly startedAtMs: number;

  private readonly sourceCoordinates: Float32Array;
  private targetCoordinates: Float32Array;
  private _mode: PermissionsGraphCommittedTransitionMode;
  private _immediateReason: PermissionsGraphCommittedTransitionImmediateReason;
  private status: PermissionsGraphCommittedTransitionStatus = "active";
  private progress = 0;
  private frameCount = 0;
  private droppedFrameCount = 0;
  private skippedFrameCount = 0;
  private maximumFrameDurationMs = 0;
  private lastSampleAtMs: number | null = null;
  private terminalFrame: PermissionsGraphCommittedTransitionFrame | null = null;

  constructor(private readonly input: PermissionsGraphCommittedTransitionInput) {
    validateIdentity(input);
    const ordered = normalizeSources(input);
    this.ordinals = Uint32Array.from(ordered.map((entry) => entry.ordinal));
    this.targetCoordinates = targetCoordinates(input.layout, this.ordinals);
    const memoryLimit = normalizeMemoryLimit(input.sourceMemoryLimitBytes);
    const requiredSourceBytes = ordered.length * 2 * Float32Array.BYTES_PER_ELEMENT;
    this._immediateReason = selectImmediateReason(input, requiredSourceBytes, memoryLimit);
    this._mode = this._immediateReason === null ? "animated" : "immediate";
    this.durationMs = normalizeDuration(input.durationMs);
    this.startedAtMs = normalizeTime(input.startedAtMs ?? 0, "start timestamp");
    this.sourceCoordinates = new Float32Array(ordered.length * 2);
    for (let index = 0; index < ordered.length; index += 1) {
      const entry = ordered[index] as OrderedSource;
      const offset = index * 2;
      this.sourceCoordinates[offset] = this._mode === "animated"
        ? entry.sourceX
        : this.targetCoordinates[offset] as number;
      this.sourceCoordinates[offset + 1] = this._mode === "animated"
        ? entry.sourceY
        : this.targetCoordinates[offset + 1] as number;
    }
  }

  get mode(): PermissionsGraphCommittedTransitionMode {
    return this._mode;
  }

  get immediateReason(): PermissionsGraphCommittedTransitionImmediateReason {
    return this._immediateReason;
  }

  sample(timestampMs: number, preparationDurationMs = 0): PermissionsGraphCommittedTransitionFrame {
    if (this.terminalFrame) return this.terminalFrame;
    if (this.input.signal?.aborted) return this.cancel();
    if (!this.matchesCommittedIdentity()) {
      this.targetCoordinates = targetCoordinates(this.input.layout, this.ordinals);
      return this.supersede();
    }
    const timestamp = normalizeTime(timestampMs, "sample timestamp");
    const preparation = normalizeTime(preparationDurationMs, "frame preparation duration");
    this.maximumFrameDurationMs = Math.max(this.maximumFrameDurationMs, preparation);
    if (this._mode === "immediate") return this.finish("completed");
    if (preparation > PERMISSIONS_GRAPH_TRANSITION_FRAME_GUARD_MS) {
      this._mode = "immediate";
      this._immediateReason = "frame-budget";
      this.skippedFrameCount += 1;
      return this.finish("completed");
    }

    if (this.lastSampleAtMs !== null && timestamp > this.lastSampleAtMs) {
      const elapsed = timestamp - this.lastSampleAtMs;
      if (elapsed > 34) this.droppedFrameCount += Math.max(0, Math.floor(elapsed / 16.7) - 1);
    }
    this.lastSampleAtMs = Math.max(this.lastSampleAtMs ?? timestamp, timestamp);
    const nextProgress = Math.max(
      this.progress,
      Math.max(0, Math.min(1, (timestamp - this.startedAtMs) / this.durationMs)),
    );
    this.progress = nextProgress;
    this.frameCount += 1;
    if (nextProgress >= 1) return this.finish("completed", false);
    return this.freezeFrame(
      "active",
      nextProgress,
      interpolate(this.sourceCoordinates, this.targetCoordinates, nextProgress),
    );
  }

  cancel(): PermissionsGraphCommittedTransitionFrame {
    if (this.terminalFrame) return this.terminalFrame;
    return this.finish("cancelled");
  }

  supersede(): PermissionsGraphCommittedTransitionFrame {
    if (this.terminalFrame) return this.terminalFrame;
    return this.finish("superseded");
  }

  getMetrics(): PermissionsGraphCommittedTransitionMetrics {
    return Object.freeze({
      status: this.status,
      mode: this._mode,
      immediateReason: this._immediateReason,
      ordinalCount: this.ordinals.length,
      durationMs: this.durationMs,
      progress: this.progress,
      frameCount: this.frameCount,
      droppedFrameCount: this.droppedFrameCount,
      skippedFrameCount: this.skippedFrameCount,
      maximumFrameDurationMs: this.maximumFrameDurationMs,
      sourceBufferBytes: this._mode === "animated" ? this.sourceCoordinates.byteLength : 0,
      targetBufferBytes: this.targetCoordinates.byteLength,
      layoutGeneration: this.input.layout.layoutGeneration,
      coordinateRevision: this.input.layout.coordinateRevision,
    });
  }

  private matchesCommittedIdentity(): boolean {
    return this.input.layout.topologyFingerprint === this.input.topologyFingerprint &&
      this.input.layout.layoutGeneration === this.input.layoutGeneration &&
      this.input.layout.coordinateRevision === this.input.coordinateRevision;
  }

  private finish(
    status: Exclude<PermissionsGraphCommittedTransitionStatus, "active">,
    countFrame = true,
  ): PermissionsGraphCommittedTransitionFrame {
    if (countFrame) this.frameCount += 1;
    this.status = status;
    this.progress = 1;
    this.terminalFrame = this.freezeFrame(status, 1, this.targetCoordinates.slice());
    return this.terminalFrame;
  }

  private freezeFrame(
    status: PermissionsGraphCommittedTransitionStatus,
    progress: number,
    coordinates: Float32Array,
  ): PermissionsGraphCommittedTransitionFrame {
    return Object.freeze({
      marker: PERMISSIONS_GRAPH_COMMITTED_TRANSITION_PHASE_F_MARKER,
      status,
      mode: this._mode,
      immediateReason: this._immediateReason,
      progress,
      ordinals: this.ordinals,
      coordinates,
      layoutGeneration: this.input.layout.layoutGeneration,
      coordinateRevision: this.input.layout.coordinateRevision,
      frameCount: this.frameCount,
      droppedFrameCount: this.droppedFrameCount,
      skippedFrameCount: this.skippedFrameCount,
    });
  }
}

export function createPermissionsGraphCommittedTransition(
  input: PermissionsGraphCommittedTransitionInput,
): PermissionsGraphCommittedTransition {
  return new PermissionsGraphCommittedTransition(input);
}

function validateIdentity(input: PermissionsGraphCommittedTransitionInput): void {
  if (input.topologyFingerprint !== input.layout.topologyFingerprint) {
    throw new PermissionsGraphCommittedTransitionError(
      "IDENTITY_MISMATCH",
      "Committed transition topology does not match the layout.",
    );
  }
  if (!isUint32(input.layoutGeneration) || !isUint32(input.coordinateRevision)) {
    throw new PermissionsGraphCommittedTransitionError(
      "INVALID_REVISION",
      "Committed transition generation and revision must be Uint32 values.",
    );
  }
  if (
    input.layoutGeneration !== input.layout.layoutGeneration ||
    input.coordinateRevision !== input.layout.coordinateRevision
  ) {
    throw new PermissionsGraphCommittedTransitionError(
      "IDENTITY_MISMATCH",
      "Committed transition identity does not match the published layout revision.",
    );
  }
}

function normalizeSources(input: PermissionsGraphCommittedTransitionInput): OrderedSource[] {
  const ordinals = Array.from(input.ordinals);
  if (input.sourceCoordinates.length !== ordinals.length * 2) {
    throw new PermissionsGraphCommittedTransitionError(
      "INVALID_SOURCE",
      "Committed transition source coordinate length does not match its ordinals.",
    );
  }
  if (new Set(ordinals).size !== ordinals.length) {
    throw new PermissionsGraphCommittedTransitionError(
      "INVALID_ORDINAL",
      "Committed transition ordinals must be unique.",
    );
  }
  const ordered: OrderedSource[] = [];
  for (let index = 0; index < ordinals.length; index += 1) {
    const ordinal = ordinals[index] as number;
    if (!Number.isInteger(ordinal) || ordinal < 0 || ordinal >= input.layout.coordinateCount) {
      throw new PermissionsGraphCommittedTransitionError(
        "INVALID_ORDINAL",
        "Committed transition ordinal is outside the layout.",
      );
    }
    const sourceX = input.sourceCoordinates[index * 2];
    const sourceY = input.sourceCoordinates[index * 2 + 1];
    if (!Number.isFinite(sourceX) || !Number.isFinite(sourceY)) {
      throw new PermissionsGraphCommittedTransitionError(
        "INVALID_SOURCE",
        "Committed transition source coordinates must be finite.",
      );
    }
    ordered.push({ ordinal, sourceX: sourceX as number, sourceY: sourceY as number });
  }
  return ordered.sort((left, right) => left.ordinal - right.ordinal);
}

function targetCoordinates(
  layout: PermissionsGraphLayoutStore,
  ordinals: Uint32Array,
): Float32Array {
  const coordinates = new Float32Array(ordinals.length * 2);
  for (let index = 0; index < ordinals.length; index += 1) {
    const ordinal = ordinals[index] as number;
    const x = layout.x[ordinal];
    const y = layout.y[ordinal];
    if (!Number.isFinite(x) || !Number.isFinite(y)) {
      throw new PermissionsGraphCommittedTransitionError(
        "INVALID_SOURCE",
        "Committed transition target coordinates must be finite.",
      );
    }
    coordinates[index * 2] = x as number;
    coordinates[index * 2 + 1] = y as number;
  }
  return coordinates;
}

function selectImmediateReason(
  input: PermissionsGraphCommittedTransitionInput,
  sourceBytes: number,
  memoryLimit: number,
): PermissionsGraphCommittedTransitionImmediateReason {
  if (input.reducedMotion === true) return "reduced-motion";
  if (input.ordinals.length > PERMISSIONS_GRAPH_TRANSITION_NODE_GUARD) return "node-limit";
  if (sourceBytes > memoryLimit) return "memory-limit";
  if ((input.previousFrameDurationMs ?? 0) > PERMISSIONS_GRAPH_TRANSITION_FRAME_GUARD_MS) {
    return "frame-budget";
  }
  return null;
}

function normalizeDuration(value: number | undefined): number {
  if (value !== undefined && !Number.isFinite(value)) {
    throw new PermissionsGraphCommittedTransitionError(
      "INVALID_DURATION",
      "Committed transition duration must be finite.",
    );
  }
  return Math.max(
    PERMISSIONS_GRAPH_TRANSITION_MIN_DURATION_MS,
    Math.min(PERMISSIONS_GRAPH_TRANSITION_MAX_DURATION_MS, value ?? PERMISSIONS_GRAPH_TRANSITION_DEFAULT_DURATION_MS),
  );
}

function normalizeMemoryLimit(value: number | undefined): number {
  if (value === undefined) return PERMISSIONS_GRAPH_TRANSITION_SOURCE_MEMORY_LIMIT_BYTES;
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new PermissionsGraphCommittedTransitionError(
      "INVALID_SOURCE",
      "Committed transition source memory limit must be a non-negative safe integer.",
    );
  }
  return value;
}

function normalizeTime(value: number, label: string): number {
  if (!Number.isFinite(value) || value < 0) {
    throw new PermissionsGraphCommittedTransitionError(
      "INVALID_DURATION",
      `Committed transition ${label} must be finite and non-negative.`,
    );
  }
  return value;
}

function interpolate(source: Float32Array, target: Float32Array, progress: number): Float32Array {
  const coordinates = new Float32Array(target.length);
  for (let index = 0; index < target.length; index += 1) {
    const from = source[index] as number;
    coordinates[index] = from + ((target[index] as number) - from) * progress;
  }
  return coordinates;
}

function isUint32(value: number): boolean {
  return Number.isInteger(value) && value >= 0 && value <= 0xffff_ffff;
}
