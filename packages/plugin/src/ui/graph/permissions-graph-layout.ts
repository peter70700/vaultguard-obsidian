/**
 * Renderer-independent coordinate state for the permissions graph.
 *
 * Phase 3 is intentionally inert: this module consumes the Phase 1 model and
 * index, but nothing in the live Cytoscape view imports it. The binary helpers
 * only encode/decode plaintext bytes. A future runtime owner must protect those
 * bytes with AtRestCipher.encryptBinary/decryptBinary before persistence.
 */

import { yieldToEventLoop } from "../../plugin/long-operation";
import type {
  PermissionsGraphIndex,
  PermissionsGraphModel,
  PermissionsGraphNodeKind,
} from "./permissions-graph-model";

export const PERMISSIONS_GRAPH_LAYOUT_ALGORITHM_VERSION = 1;
export const PERMISSIONS_GRAPH_LAYOUT_BINARY_VERSION = 1;
export const PERMISSIONS_GRAPH_LAYOUT_COORDINATE_FORMAT_VERSION = 1;

const LAYOUT_MAGIC = new Uint8Array([0x56, 0x47, 0x50, 0x47, 0x4c, 0x4f, 0x33, 0x00]);
const LAYOUT_HEADER_BYTES = 72;
const FLAG_VELOCITY = 1;
const KNOWN_FLAGS = FLAG_VELOCITY;
const DEFAULT_CHECK_INTERVAL = 256;
const DEFAULT_YIELD_INTERVAL = 2_048;
const GRID_SPACING = 120;
const GROUP_GAP = 320;
const JITTER_RADIUS = 8;
const ESTIMATED_STORE_OVERHEAD_BYTES = 192;
const ESTIMATED_ID_ENTRY_OVERHEAD_BYTES = 24;
const ESTIMATED_MANUAL_ENTRY_OVERHEAD_BYTES = 32;

const NODE_KIND_ORDER: readonly PermissionsGraphNodeKind[] = Object.freeze([
  "vault",
  "folder",
  "aggregate",
  "file",
  "group",
  "user",
  "unknown",
]);

export interface PermissionsGraphCoordinate {
  readonly x: number;
  readonly y: number;
}

export interface PermissionsGraphManualPosition extends PermissionsGraphCoordinate {
  readonly nodeId: string;
}

export interface PermissionsGraphCoordinateBounds {
  readonly minX: number;
  readonly minY: number;
  readonly maxX: number;
  readonly maxY: number;
  readonly width: number;
  readonly height: number;
}

export interface PermissionsGraphLayoutMemoryEstimate {
  readonly coordinateBytes: number;
  readonly velocityBytes: number;
  readonly flagBytes: number;
  readonly generationBytes: number;
  readonly typedArrayBytes: number;
  readonly idMetadataBytes: number;
  readonly manualMetadataBytes: number;
  readonly fixedOverheadBytes: number;
  readonly totalEstimatedBytes: number;
  readonly perNodeEstimatedBytes: number;
  readonly nodeCount: number;
  readonly manualPositionCount: number;
  readonly hasVelocity: boolean;
}

/** Structural adapter accepted from the existing LongOperationToken. */
export interface PermissionsGraphCancellationToken {
  readonly isCancelRequested?: boolean;
  throwIfCancellationRequested(): void;
  checkpoint?(): Promise<void>;
}

export type PermissionsGraphCancellationSignal = AbortSignal | PermissionsGraphCancellationToken;

export interface PermissionsGraphSeedLayoutOptions {
  readonly seed?: number;
  readonly layoutGeneration?: number;
  readonly includeVelocity?: boolean;
  readonly signal?: PermissionsGraphCancellationSignal;
  /** Primarily useful for deterministic cancellation tests and later tuning. */
  readonly cancellationCheckInterval?: number;
  /** Main-thread cooperative yield cadence. Set to 0 to disable yielding. */
  readonly yieldInterval?: number;
  readonly yieldFn?: () => Promise<void>;
}

export interface PermissionsGraphReseedOptions extends PermissionsGraphSeedLayoutOptions {
  readonly preserveManualPositions?: boolean;
}

export interface PermissionsGraphManualPositionUpdate extends PermissionsGraphCoordinate {
  readonly nodeId: string;
}

export interface PermissionsGraphCoordinateUpdate extends PermissionsGraphCoordinate {
  readonly nodeId: string;
}

export interface PermissionsGraphCoordinateCommitOptions {
  /** The caller must prove it refined the same immutable model topology. */
  readonly topologyFingerprint: string;
  /** Defaults to true. */
  readonly preserveManualPositions?: boolean;
  /** Defaults to the next Uint32 generation when at least one coordinate changes. */
  readonly layoutGeneration?: number;
}

export interface PermissionsGraphCoordinateCommitResult {
  readonly changedNodeIds: readonly string[];
  readonly skippedManualNodeIds: readonly string[];
  readonly coordinateRevision: number;
  readonly layoutGeneration: number;
}

export type PermissionsGraphLayoutStateErrorCode =
  | "INDEX_MODEL_MISMATCH"
  | "INVALID_MODEL_ORDINAL"
  | "NON_FINITE_COORDINATE"
  | "INVALID_GENERATION"
  | "TOPOLOGY_MISMATCH"
  | "UNKNOWN_NODE_ID";

export class PermissionsGraphLayoutStateError extends Error {
  constructor(
    readonly code: PermissionsGraphLayoutStateErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "PermissionsGraphLayoutStateError";
  }
}

export class PermissionsGraphLayoutCancelledError extends Error {
  readonly code = "CANCELLED" as const;

  constructor(message = "Permissions graph layout operation was cancelled.") {
    super(message);
    this.name = "AbortError";
  }
}

export type PermissionsGraphLayoutPersistenceErrorCode =
  | "WRONG_MAGIC"
  | "UNSUPPORTED_VERSION"
  | "UNSUPPORTED_COORDINATE_FORMAT"
  | "INVALID_HEADER"
  | "TRUNCATED_DATA"
  | "CHECKSUM_MISMATCH"
  | "NODE_COUNT_MISMATCH"
  | "TOPOLOGY_MISMATCH"
  | "NON_FINITE_COORDINATE"
  | "INVALID_MANUAL_POSITION"
  | "UNKNOWN_MANUAL_NODE"
  | "CORRUPT_DATA";

export class PermissionsGraphLayoutPersistenceError extends Error {
  constructor(
    readonly code: PermissionsGraphLayoutPersistenceErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "PermissionsGraphLayoutPersistenceError";
  }
}

interface PermissionsGraphLayoutArrays {
  readonly x: Float32Array;
  readonly y: Float32Array;
  readonly vx: Float32Array | null;
  readonly vy: Float32Array | null;
  readonly manual: Uint8Array;
  readonly generations: Uint32Array;
}

interface PermissionsGraphLayoutInitialization extends PermissionsGraphLayoutArrays {
  readonly seed: number;
  readonly layoutGeneration: number;
  readonly coordinateRevision: number;
  readonly manualPositions?: readonly PermissionsGraphManualPosition[];
}

interface NormalizedSeedOptions {
  readonly seed: number;
  readonly layoutGeneration: number;
  readonly includeVelocity: boolean;
  readonly signal?: PermissionsGraphCancellationSignal;
  readonly cancellationCheckInterval: number;
  readonly yieldInterval: number;
  readonly yieldFn: () => Promise<void>;
}

/**
 * Dense coordinate store keyed by the model's deterministic node ordinals.
 * Typed arrays are exposed read-only at the property level for future renderer
 * integration; callers should mutate state only through the store APIs so
 * revisions, manual metadata, and bounds stay coherent.
 */
export class PermissionsGraphLayoutStore {
  readonly topologyFingerprint: string;
  readonly nodeIds: readonly string[];
  readonly layoutAlgorithmVersion = PERMISSIONS_GRAPH_LAYOUT_ALGORITHM_VERSION;

  private readonly ordinalByNodeId = new Map<string, number>();
  private readonly manualPositionByNodeId = new Map<string, PermissionsGraphCoordinate>();
  private _x: Float32Array;
  private _y: Float32Array;
  private _vx: Float32Array | null;
  private _vy: Float32Array | null;
  private _manual: Uint8Array;
  private _generations: Uint32Array;
  private _seed: number;
  private _layoutGeneration: number;
  private _coordinateRevision: number;
  private boundsCache: PermissionsGraphCoordinateBounds | null = null;

  constructor(
    readonly model: PermissionsGraphModel,
    readonly index: PermissionsGraphIndex,
    initialization?: PermissionsGraphLayoutInitialization,
  ) {
    validateModelAndIndex(model, index);
    this.topologyFingerprint = model.topologyFingerprint;
    this.nodeIds = Object.freeze(model.nodes.map((node) => node.id));
    for (const node of model.nodes) this.ordinalByNodeId.set(node.id, node.ordinal);

    const nodeCount = model.nodeCount;
    const initial = initialization ?? {
      x: new Float32Array(nodeCount),
      y: new Float32Array(nodeCount),
      vx: null,
      vy: null,
      manual: new Uint8Array(nodeCount),
      generations: new Uint32Array(nodeCount),
      seed: seedFromFingerprint(model.topologyFingerprint),
      layoutGeneration: 0,
      coordinateRevision: 0,
    };
    validateInitialization(initial, nodeCount);

    this._x = initial.x;
    this._y = initial.y;
    this._vx = initial.vx;
    this._vy = initial.vy;
    this._manual = initial.manual;
    this._generations = initial.generations;
    this._seed = normalizeUint32(initial.seed);
    this._layoutGeneration = normalizeGeneration(initial.layoutGeneration);
    this._coordinateRevision = normalizeUint32(initial.coordinateRevision);

    for (const position of initial.manualPositions ?? []) {
      const ordinal = this.ordinalByNodeId.get(position.nodeId);
      if (ordinal === undefined || this._manual[ordinal] !== 1) continue;
      this.manualPositionByNodeId.set(
        position.nodeId,
        Object.freeze({ x: position.x, y: position.y }),
      );
    }
    for (const node of model.nodes) {
      if (this._manual[node.ordinal] !== 1) continue;
      if (!this.manualPositionByNodeId.has(node.id)) {
        this.manualPositionByNodeId.set(
          node.id,
          Object.freeze({ x: this._x[node.ordinal], y: this._y[node.ordinal] }),
        );
      }
    }
  }

  get x(): Float32Array {
    return this._x;
  }

  get y(): Float32Array {
    return this._y;
  }

  get vx(): Float32Array | null {
    return this._vx;
  }

  get vy(): Float32Array | null {
    return this._vy;
  }

  get manualFlags(): Uint8Array {
    return this._manual;
  }

  get nodeLayoutGenerations(): Uint32Array {
    return this._generations;
  }

  get seed(): number {
    return this._seed;
  }

  get layoutGeneration(): number {
    return this._layoutGeneration;
  }

  get coordinateRevision(): number {
    return this._coordinateRevision;
  }

  get coordinateCount(): number {
    return this._x.length;
  }

  get manualPositionCount(): number {
    return this.manualPositionByNodeId.size;
  }

  get coordinateBounds(): PermissionsGraphCoordinateBounds {
    if (!this.boundsCache) this.boundsCache = calculateBounds(this._x, this._y);
    return this.boundsCache;
  }

  getPosition(nodeId: string): PermissionsGraphCoordinate | null {
    const ordinal = this.ordinalByNodeId.get(nodeId);
    if (ordinal === undefined) return null;
    return Object.freeze({ x: this._x[ordinal], y: this._y[ordinal] });
  }

  getPositionByOrdinal(ordinal: number): PermissionsGraphCoordinate | null {
    if (!Number.isInteger(ordinal) || ordinal < 0 || ordinal >= this.coordinateCount) return null;
    return Object.freeze({ x: this._x[ordinal], y: this._y[ordinal] });
  }

  getManualPositions(): readonly PermissionsGraphManualPosition[] {
    return Object.freeze(
      Array.from(this.manualPositionByNodeId.entries())
        .map(([nodeId, position]) => Object.freeze({ nodeId, ...position }))
        .sort((left, right) => compareStrings(left.nodeId, right.nodeId)),
    );
  }

  isManuallyPositioned(nodeId: string): boolean {
    const ordinal = this.ordinalByNodeId.get(nodeId);
    return ordinal !== undefined && this._manual[ordinal] === 1;
  }

  setManualPosition(nodeId: string, x: number, y: number): boolean {
    return this.setManualPositions([{ nodeId, x, y }]) > 0;
  }

  /**
   * Apply known updates atomically. Unknown IDs are ignored, duplicate IDs use
   * the final update, and the coordinate revision increments at most once.
   */
  setManualPositions(updates: readonly PermissionsGraphManualPositionUpdate[]): number {
    const byNodeId = new Map<string, PermissionsGraphManualPositionUpdate>();
    for (const update of updates) {
      if (!this.ordinalByNodeId.has(update.nodeId)) continue;
      assertFiniteCoordinate(update.x, update.y, `manual position for ${update.nodeId}`);
      byNodeId.set(update.nodeId, {
        nodeId: update.nodeId,
        x: toFiniteFloat32(update.x, `manual x for ${update.nodeId}`),
        y: toFiniteFloat32(update.y, `manual y for ${update.nodeId}`),
      });
    }

    const ordered = Array.from(byNodeId.values()).sort((left, right) =>
      (this.ordinalByNodeId.get(left.nodeId) ?? 0) -
      (this.ordinalByNodeId.get(right.nodeId) ?? 0)
    );
    let changed = 0;
    for (const update of ordered) {
      const ordinal = this.ordinalByNodeId.get(update.nodeId);
      if (ordinal === undefined) continue;
      const nextX = update.x;
      const nextY = update.y;
      if (
        this._manual[ordinal] === 1 &&
        Object.is(this._x[ordinal], nextX) &&
        Object.is(this._y[ordinal], nextY)
      ) {
        continue;
      }
      this._x[ordinal] = nextX;
      this._y[ordinal] = nextY;
      this._manual[ordinal] = 1;
      this.manualPositionByNodeId.set(
        update.nodeId,
        Object.freeze({ x: nextX, y: nextY }),
      );
      changed += 1;
    }
    if (changed > 0) {
      this._coordinateRevision = incrementUint32(this._coordinateRevision);
      this.boundsCache = null;
    }
    return changed;
  }

  /**
   * Commit ordinary layout coordinates atomically without marking them manual.
   * Unlike the forgiving manual-position API, an unknown ID rejects the whole
   * batch because refinement output is expected to match one exact topology.
   */
  commitCoordinateUpdates(
    updates: readonly PermissionsGraphCoordinateUpdate[],
    options: PermissionsGraphCoordinateCommitOptions,
  ): PermissionsGraphCoordinateCommitResult {
    if (options.topologyFingerprint !== this.topologyFingerprint) {
      throw new PermissionsGraphLayoutStateError(
        "TOPOLOGY_MISMATCH",
        "Permissions graph coordinate updates do not match the layout topology.",
      );
    }

    const byNodeId = new Map<string, PermissionsGraphCoordinateUpdate>();
    for (const update of updates) {
      const ordinal = this.ordinalByNodeId.get(update.nodeId);
      if (ordinal === undefined) {
        throw new PermissionsGraphLayoutStateError(
          "UNKNOWN_NODE_ID",
          `Permissions graph coordinate update references unknown node ${update.nodeId}.`,
        );
      }
      assertFiniteCoordinate(update.x, update.y, `coordinate update for ${update.nodeId}`);
      byNodeId.set(update.nodeId, {
        nodeId: update.nodeId,
        x: toFiniteFloat32(update.x, `coordinate x for ${update.nodeId}`),
        y: toFiniteFloat32(update.y, `coordinate y for ${update.nodeId}`),
      });
    }

    const nextGeneration = normalizeGeneration(
      options.layoutGeneration ?? incrementUint32(this._layoutGeneration),
    );
    const preserveManualPositions = options.preserveManualPositions !== false;
    const skippedManualNodeIds: string[] = [];
    const planned: Array<PermissionsGraphCoordinateUpdate & { readonly ordinal: number }> = [];
    for (const update of Array.from(byNodeId.values()).sort((left, right) =>
      (this.ordinalByNodeId.get(left.nodeId) ?? 0) -
      (this.ordinalByNodeId.get(right.nodeId) ?? 0)
    )) {
      const ordinal = this.ordinalByNodeId.get(update.nodeId);
      if (ordinal === undefined) continue;
      if (preserveManualPositions && this._manual[ordinal] === 1) {
        skippedManualNodeIds.push(update.nodeId);
        continue;
      }
      if (Object.is(this._x[ordinal], update.x) && Object.is(this._y[ordinal], update.y)) {
        continue;
      }
      planned.push({ ...update, ordinal });
    }

    const changedNodeIds = freezeSortedIds(planned.map((update) => update.nodeId));
    const frozenSkippedManualNodeIds = freezeSortedIds(skippedManualNodeIds);

    if (planned.length > 0) {
      for (const update of planned) {
        this._x[update.ordinal] = update.x;
        this._y[update.ordinal] = update.y;
        this._generations[update.ordinal] = nextGeneration;
        if (this._manual[update.ordinal] === 1) {
          this.manualPositionByNodeId.set(
            update.nodeId,
            Object.freeze({ x: update.x, y: update.y }),
          );
        }
      }
      this._layoutGeneration = nextGeneration;
      this._coordinateRevision = incrementUint32(this._coordinateRevision);
      this.boundsCache = null;
    }

    return Object.freeze({
      changedNodeIds,
      skippedManualNodeIds: frozenSkippedManualNodeIds,
      coordinateRevision: this._coordinateRevision,
      layoutGeneration: this._layoutGeneration,
    });
  }

  clearManualPosition(nodeId: string): boolean {
    const ordinal = this.ordinalByNodeId.get(nodeId);
    if (ordinal === undefined || this._manual[ordinal] !== 1) return false;
    this._manual[ordinal] = 0;
    this.manualPositionByNodeId.delete(nodeId);
    this._coordinateRevision = incrementUint32(this._coordinateRevision);
    return true;
  }

  clearAllManualPositions(): number {
    const cleared = this.manualPositionByNodeId.size;
    if (cleared === 0) return 0;
    this._manual.fill(0);
    this.manualPositionByNodeId.clear();
    this._coordinateRevision = incrementUint32(this._coordinateRevision);
    return cleared;
  }

  /** Rebuild seed coordinates off to the side and commit only after success. */
  async reseed(options: PermissionsGraphReseedOptions = {}): Promise<void> {
    const normalized = normalizeSeedOptions(this.model, {
      ...options,
      seed: options.seed ?? this._seed,
      layoutGeneration: options.layoutGeneration ?? incrementUint32(this._layoutGeneration),
      includeVelocity: options.includeVelocity ?? this._vx !== null,
    });
    const next = await computeSeedLayout(this.model, normalized);
    const preserveManual = options.preserveManualPositions !== false;
    const nextManualPositions: PermissionsGraphManualPosition[] = [];
    if (preserveManual) {
      for (const position of this.getManualPositions()) {
        const ordinal = this.ordinalByNodeId.get(position.nodeId);
        if (ordinal === undefined) continue;
        next.x[ordinal] = position.x;
        next.y[ordinal] = position.y;
        next.manual[ordinal] = 1;
        nextManualPositions.push(position);
      }
    }
    checkCancellation(normalized.signal);

    this._x = next.x;
    this._y = next.y;
    this._vx = next.vx;
    this._vy = next.vy;
    this._manual = next.manual;
    this._generations = next.generations;
    this._seed = normalized.seed;
    this._layoutGeneration = normalized.layoutGeneration;
    this._coordinateRevision = incrementUint32(this._coordinateRevision);
    this.manualPositionByNodeId.clear();
    for (const position of nextManualPositions) {
      this.manualPositionByNodeId.set(
        position.nodeId,
        Object.freeze({ x: position.x, y: position.y }),
      );
    }
    this.boundsCache = null;
  }

  getMemoryEstimate(): PermissionsGraphLayoutMemoryEstimate {
    return estimatePermissionsGraphLayoutMemory(this);
  }
}

/** Build deterministic seed coordinates without constructing Cytoscape state. */
export async function buildPermissionsGraphSeedLayout(
  model: PermissionsGraphModel,
  index: PermissionsGraphIndex,
  options: PermissionsGraphSeedLayoutOptions = {},
): Promise<PermissionsGraphLayoutStore> {
  validateModelAndIndex(model, index);
  const normalized = normalizeSeedOptions(model, options);
  checkCancellation(normalized.signal);
  const arrays = await computeSeedLayout(model, normalized);
  checkCancellation(normalized.signal);
  return new PermissionsGraphLayoutStore(model, index, {
    ...arrays,
    seed: normalized.seed,
    layoutGeneration: normalized.layoutGeneration,
    coordinateRevision: model.nodeCount > 0 ? 1 : 0,
  });
}

export function estimatePermissionsGraphLayoutMemory(
  store: PermissionsGraphLayoutStore,
): PermissionsGraphLayoutMemoryEstimate {
  const encoder = new TextEncoder();
  const coordinateBytes = store.x.byteLength + store.y.byteLength;
  const velocityBytes = (store.vx?.byteLength ?? 0) + (store.vy?.byteLength ?? 0);
  const flagBytes = store.manualFlags.byteLength;
  const generationBytes = store.nodeLayoutGenerations.byteLength;
  const typedArrayBytes = coordinateBytes + velocityBytes + flagBytes + generationBytes;
  const idMetadataBytes = store.nodeIds.reduce(
    (total, nodeId) => total + encoder.encode(nodeId).byteLength + ESTIMATED_ID_ENTRY_OVERHEAD_BYTES,
    0,
  );
  const manualMetadataBytes = store.getManualPositions().reduce(
    (total, position) =>
      total + encoder.encode(position.nodeId).byteLength + ESTIMATED_MANUAL_ENTRY_OVERHEAD_BYTES,
    0,
  );
  const totalEstimatedBytes =
    typedArrayBytes + idMetadataBytes + manualMetadataBytes + ESTIMATED_STORE_OVERHEAD_BYTES;
  return Object.freeze({
    coordinateBytes,
    velocityBytes,
    flagBytes,
    generationBytes,
    typedArrayBytes,
    idMetadataBytes,
    manualMetadataBytes,
    fixedOverheadBytes: ESTIMATED_STORE_OVERHEAD_BYTES,
    totalEstimatedBytes,
    perNodeEstimatedBytes: store.coordinateCount > 0
      ? totalEstimatedBytes / store.coordinateCount
      : 0,
    nodeCount: store.coordinateCount,
    manualPositionCount: store.manualPositionCount,
    hasVelocity: store.vx !== null,
  });
}

/**
 * Encode an unencrypted binary checkpoint. The caller owns user/vault scoping,
 * storage, and AtRestCipher.encryptBinary protection in a later runtime phase.
 */
export function encodePermissionsGraphLayoutStoreForPersistence(
  store: PermissionsGraphLayoutStore,
): Uint8Array {
  validateStoreCoordinates(store);
  const encoder = new TextEncoder();
  const fingerprint = encoder.encode(store.topologyFingerprint);
  const manualPositions = store.getManualPositions();
  const manualRecords = manualPositions.map((position) => ({
    position,
    idBytes: encoder.encode(position.nodeId),
  }));
  const arrayBytes = checkedAdd(
    checkedMultiply(store.coordinateCount, 4 * 2 + 4 + 1),
    store.vx ? checkedMultiply(store.coordinateCount, 8) : 0,
  );
  const manualBytes = manualRecords.reduce(
    (total, record) => checkedAdd(total, checkedAdd(12, record.idBytes.byteLength)),
    0,
  );
  const payloadLength = checkedAdd(fingerprint.byteLength, checkedAdd(arrayBytes, manualBytes));
  if (payloadLength > 0xffff_ffff) {
    throw new PermissionsGraphLayoutPersistenceError(
      "INVALID_HEADER",
      "Permissions graph layout payload exceeds the binary format size limit.",
    );
  }
  const totalLength = checkedAdd(LAYOUT_HEADER_BYTES, payloadLength);
  const bytes = new Uint8Array(totalLength);
  const view = new DataView(bytes.buffer);
  bytes.set(LAYOUT_MAGIC, 0);
  view.setUint16(8, PERMISSIONS_GRAPH_LAYOUT_BINARY_VERSION, true);
  view.setUint16(10, PERMISSIONS_GRAPH_LAYOUT_COORDINATE_FORMAT_VERSION, true);
  view.setUint32(12, LAYOUT_HEADER_BYTES, true);
  view.setUint32(16, store.vx ? FLAG_VELOCITY : 0, true);
  view.setUint32(20, store.coordinateCount, true);
  view.setUint32(24, store.layoutGeneration, true);
  view.setUint32(28, store.seed, true);
  view.setUint32(32, store.coordinateRevision, true);
  view.setUint32(36, fingerprint.byteLength, true);
  view.setUint32(40, manualRecords.length, true);
  view.setUint32(44, payloadLength, true);
  const bounds = store.coordinateBounds;
  view.setFloat32(52, bounds.minX, true);
  view.setFloat32(56, bounds.minY, true);
  view.setFloat32(60, bounds.maxX, true);
  view.setFloat32(64, bounds.maxY, true);

  let offset = LAYOUT_HEADER_BYTES;
  bytes.set(fingerprint, offset);
  offset += fingerprint.byteLength;
  offset = writeFloat32Array(view, offset, store.x);
  offset = writeFloat32Array(view, offset, store.y);
  offset = writeUint32Array(view, offset, store.nodeLayoutGenerations);
  bytes.set(store.manualFlags, offset);
  offset += store.manualFlags.byteLength;
  if (store.vx && store.vy) {
    offset = writeFloat32Array(view, offset, store.vx);
    offset = writeFloat32Array(view, offset, store.vy);
  }
  for (const record of manualRecords) {
    view.setUint32(offset, record.idBytes.byteLength, true);
    view.setFloat32(offset + 4, record.position.x, true);
    view.setFloat32(offset + 8, record.position.y, true);
    offset += 12;
    bytes.set(record.idBytes, offset);
    offset += record.idBytes.byteLength;
  }
  if (offset !== bytes.byteLength) {
    throw new PermissionsGraphLayoutPersistenceError(
      "CORRUPT_DATA",
      "Permissions graph layout encoder produced an inconsistent payload length.",
    );
  }
  view.setUint32(48, fnv1a32Bytes(bytes.subarray(LAYOUT_HEADER_BYTES)), true);
  return bytes;
}

/** Decode and validate an unencrypted binary checkpoint against current topology. */
export function decodePermissionsGraphLayoutStoreFromPersistence(
  input: ArrayBuffer | Uint8Array,
  model: PermissionsGraphModel,
  index: PermissionsGraphIndex,
): PermissionsGraphLayoutStore {
  validateModelAndIndex(model, index);
  const bytes = input instanceof Uint8Array
    ? new Uint8Array(input.buffer, input.byteOffset, input.byteLength)
    : new Uint8Array(input);
  if (bytes.byteLength < LAYOUT_HEADER_BYTES) {
    throw persistenceError("TRUNCATED_DATA", "Permissions graph layout header is truncated.");
  }
  for (let offset = 0; offset < LAYOUT_MAGIC.length; offset += 1) {
    if (bytes[offset] !== LAYOUT_MAGIC[offset]) {
      throw persistenceError("WRONG_MAGIC", "Permissions graph layout magic header is invalid.");
    }
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint16(8, true) !== PERMISSIONS_GRAPH_LAYOUT_BINARY_VERSION) {
    throw persistenceError("UNSUPPORTED_VERSION", "Permissions graph layout version is unsupported.");
  }
  if (view.getUint16(10, true) !== PERMISSIONS_GRAPH_LAYOUT_COORDINATE_FORMAT_VERSION) {
    throw persistenceError(
      "UNSUPPORTED_COORDINATE_FORMAT",
      "Permissions graph coordinate format is unsupported.",
    );
  }
  const headerLength = view.getUint32(12, true);
  const flags = view.getUint32(16, true);
  if (headerLength !== LAYOUT_HEADER_BYTES || (flags & ~KNOWN_FLAGS) !== 0) {
    throw persistenceError("INVALID_HEADER", "Permissions graph layout header fields are invalid.");
  }
  const nodeCount = view.getUint32(20, true);
  const layoutGeneration = view.getUint32(24, true);
  const seed = view.getUint32(28, true);
  const coordinateRevision = view.getUint32(32, true);
  const fingerprintLength = view.getUint32(36, true);
  const manualCount = view.getUint32(40, true);
  const payloadLength = view.getUint32(44, true);
  const checksum = view.getUint32(48, true);
  if (nodeCount !== model.nodeCount) {
    throw persistenceError(
      "NODE_COUNT_MISMATCH",
      `Layout contains ${nodeCount} nodes but the model contains ${model.nodeCount}.`,
    );
  }
  if (checkedAdd(headerLength, payloadLength) !== bytes.byteLength) {
    throw persistenceError("TRUNCATED_DATA", "Permissions graph layout payload length is invalid.");
  }
  const payload = bytes.subarray(headerLength);
  if (fnv1a32Bytes(payload) !== checksum) {
    throw persistenceError("CHECKSUM_MISMATCH", "Permissions graph layout checksum does not match.");
  }

  const decoder = new TextDecoder("utf-8", { fatal: true });
  let offset = headerLength;
  requireBytes(bytes, offset, fingerprintLength);
  let fingerprint: string;
  try {
    fingerprint = decoder.decode(bytes.subarray(offset, offset + fingerprintLength));
  } catch {
    throw persistenceError("CORRUPT_DATA", "Permissions graph topology fingerprint is not valid UTF-8.");
  }
  offset += fingerprintLength;
  if (fingerprint !== model.topologyFingerprint) {
    throw persistenceError(
      "TOPOLOGY_MISMATCH",
      "Permissions graph layout topology fingerprint does not match the current model.",
    );
  }

  const x = readFloat32Array(view, bytes, offset, nodeCount);
  offset += checkedMultiply(nodeCount, 4);
  const y = readFloat32Array(view, bytes, offset, nodeCount);
  offset += checkedMultiply(nodeCount, 4);
  const generations = readUint32Array(view, bytes, offset, nodeCount);
  offset += checkedMultiply(nodeCount, 4);
  requireBytes(bytes, offset, nodeCount);
  const manual = bytes.slice(offset, offset + nodeCount);
  offset += nodeCount;
  for (const flag of manual) {
    if (flag !== 0 && flag !== 1) {
      throw persistenceError("INVALID_MANUAL_POSITION", "Layout contains an invalid manual flag.");
    }
  }

  let vx: Float32Array | null = null;
  let vy: Float32Array | null = null;
  if ((flags & FLAG_VELOCITY) !== 0) {
    vx = readFloat32Array(view, bytes, offset, nodeCount);
    offset += checkedMultiply(nodeCount, 4);
    vy = readFloat32Array(view, bytes, offset, nodeCount);
    offset += checkedMultiply(nodeCount, 4);
  }

  const manualPositions: PermissionsGraphManualPosition[] = [];
  const manualNodeIds = new Set<string>();
  for (let recordIndex = 0; recordIndex < manualCount; recordIndex += 1) {
    requireBytes(bytes, offset, 12);
    const idLength = view.getUint32(offset, true);
    const manualX = view.getFloat32(offset + 4, true);
    const manualY = view.getFloat32(offset + 8, true);
    offset += 12;
    requireBytes(bytes, offset, idLength);
    let nodeId: string;
    try {
      nodeId = decoder.decode(bytes.subarray(offset, offset + idLength));
    } catch {
      throw persistenceError("CORRUPT_DATA", "Manual-position node ID is not valid UTF-8.");
    }
    offset += idLength;
    if (!Number.isFinite(manualX) || !Number.isFinite(manualY) || !nodeId) {
      throw persistenceError("INVALID_MANUAL_POSITION", "Layout contains an invalid manual position.");
    }
    if (manualNodeIds.has(nodeId)) {
      throw persistenceError("INVALID_MANUAL_POSITION", `Duplicate manual position for ${nodeId}.`);
    }
    const ordinal = index.getNodeOrdinal(nodeId);
    if (ordinal === undefined) {
      throw persistenceError("UNKNOWN_MANUAL_NODE", `Manual position references unknown node ${nodeId}.`);
    }
    if (manual[ordinal] !== 1 || !Object.is(x[ordinal], manualX) || !Object.is(y[ordinal], manualY)) {
      throw persistenceError(
        "INVALID_MANUAL_POSITION",
        `Manual-position metadata is inconsistent for ${nodeId}.`,
      );
    }
    manualNodeIds.add(nodeId);
    manualPositions.push(Object.freeze({ nodeId, x: manualX, y: manualY }));
  }
  if (offset !== bytes.byteLength || countFlags(manual) !== manualCount) {
    throw persistenceError("CORRUPT_DATA", "Permissions graph layout payload has trailing or missing data.");
  }

  const computedBounds = calculateBounds(x, y);
  const encodedBounds = [
    view.getFloat32(52, true),
    view.getFloat32(56, true),
    view.getFloat32(60, true),
    view.getFloat32(64, true),
  ];
  if (
    encodedBounds.some((value) => !Number.isFinite(value)) ||
    !Object.is(encodedBounds[0], computedBounds.minX) ||
    !Object.is(encodedBounds[1], computedBounds.minY) ||
    !Object.is(encodedBounds[2], computedBounds.maxX) ||
    !Object.is(encodedBounds[3], computedBounds.maxY)
  ) {
    throw persistenceError("CORRUPT_DATA", "Permissions graph layout bounds are inconsistent.");
  }

  return new PermissionsGraphLayoutStore(model, index, {
    x,
    y,
    vx,
    vy,
    manual,
    generations,
    seed,
    layoutGeneration,
    coordinateRevision,
    manualPositions,
  });
}

async function computeSeedLayout(
  model: PermissionsGraphModel,
  options: NormalizedSeedOptions,
): Promise<PermissionsGraphLayoutArrays> {
  checkCancellation(options.signal);
  const x = new Float32Array(model.nodeCount);
  const y = new Float32Array(model.nodeCount);
  const vx = options.includeVelocity ? new Float32Array(model.nodeCount) : null;
  const vy = options.includeVelocity ? new Float32Array(model.nodeCount) : null;
  const manual = new Uint8Array(model.nodeCount);
  const generations = new Uint32Array(model.nodeCount);
  const ordinalsByKind = new Map<PermissionsGraphNodeKind, number[]>(
    NODE_KIND_ORDER.map((kind) => [kind, []]),
  );

  for (let nodeIndex = 0; nodeIndex < model.nodes.length; nodeIndex += 1) {
    const node = model.nodes[nodeIndex];
    ordinalsByKind.get(node.kind)?.push(node.ordinal);
    await cooperativeCheckpoint(options, nodeIndex + 1);
  }

  const layouts = NODE_KIND_ORDER
    .map((kind) => {
      const ordinals = ordinalsByKind.get(kind) ?? [];
      const columns = Math.max(1, Math.ceil(Math.sqrt(ordinals.length)));
      const rows = Math.max(1, Math.ceil(ordinals.length / columns));
      return {
        kind,
        ordinals,
        columns,
        rows,
        width: ordinals.length > 0 ? Math.max(GRID_SPACING, (columns - 1) * GRID_SPACING) : 0,
      };
    })
    .filter((layout) => layout.ordinals.length > 0);
  const totalWidth = layouts.reduce((total, layout) => total + layout.width, 0) +
    Math.max(0, layouts.length - 1) * GROUP_GAP;
  let groupX = -totalWidth / 2;
  let processed = model.nodes.length;

  for (const layout of layouts) {
    const centerX = groupX + layout.width / 2;
    for (let groupIndex = 0; groupIndex < layout.ordinals.length; groupIndex += 1) {
      const ordinal = layout.ordinals[groupIndex];
      const node = model.nodes[ordinal];
      const column = groupIndex % layout.columns;
      const row = Math.floor(groupIndex / layout.columns);
      const baseX = centerX + (column - (layout.columns - 1) / 2) * GRID_SPACING;
      const baseY = (row - (layout.rows - 1) / 2) * GRID_SPACING;
      const hash = hashString(`${model.topologyFingerprint}:${options.seed}:${node.id}:${ordinal}`);
      const jitterX = hashToSignedUnit(hash) * JITTER_RADIUS;
      const jitterY = hashToSignedUnit(rotateUint32(hash, 13)) * JITTER_RADIUS;
      x[ordinal] = toFiniteFloat32(baseX + jitterX, `seed x for ${node.id}`);
      y[ordinal] = toFiniteFloat32(baseY + jitterY, `seed y for ${node.id}`);
      generations[ordinal] = options.layoutGeneration;
      processed += 1;
      await cooperativeCheckpoint(options, processed);
    }
    groupX += layout.width + GROUP_GAP;
  }

  checkCancellation(options.signal);
  return { x, y, vx, vy, manual, generations };
}

function normalizeSeedOptions(
  model: PermissionsGraphModel,
  options: PermissionsGraphSeedLayoutOptions,
): NormalizedSeedOptions {
  return {
    seed: normalizeUint32(options.seed ?? seedFromFingerprint(model.topologyFingerprint)),
    layoutGeneration: normalizeGeneration(options.layoutGeneration ?? 1),
    includeVelocity: options.includeVelocity === true,
    signal: options.signal,
    cancellationCheckInterval: normalizeInterval(
      options.cancellationCheckInterval,
      DEFAULT_CHECK_INTERVAL,
      false,
    ),
    yieldInterval: normalizeInterval(options.yieldInterval, DEFAULT_YIELD_INTERVAL, true),
    yieldFn: options.yieldFn ?? yieldToEventLoop,
  };
}

async function cooperativeCheckpoint(
  options: NormalizedSeedOptions,
  processed: number,
): Promise<void> {
  if (processed % options.cancellationCheckInterval === 0) checkCancellation(options.signal);
  if (options.yieldInterval > 0 && processed % options.yieldInterval === 0) {
    await checkpointCancellation(options.signal);
    await options.yieldFn();
    checkCancellation(options.signal);
  }
}

function checkCancellation(signal: PermissionsGraphCancellationSignal | undefined): void {
  if (!signal) return;
  if ("aborted" in signal && signal.aborted) throw new PermissionsGraphLayoutCancelledError();
  if ("isCancelRequested" in signal && signal.isCancelRequested) {
    signal.throwIfCancellationRequested();
  }
  if ("throwIfCancellationRequested" in signal && !("aborted" in signal)) {
    signal.throwIfCancellationRequested();
  }
}

async function checkpointCancellation(
  signal: PermissionsGraphCancellationSignal | undefined,
): Promise<void> {
  checkCancellation(signal);
  if (signal && "checkpoint" in signal && signal.checkpoint) await signal.checkpoint();
  checkCancellation(signal);
}

function validateModelAndIndex(
  model: PermissionsGraphModel,
  index: PermissionsGraphIndex,
): void {
  if (model.nodes.length !== model.nodeCount) {
    throw new PermissionsGraphLayoutStateError(
      "INVALID_MODEL_ORDINAL",
      "Permissions graph model node count does not match its node records.",
    );
  }
  for (let ordinal = 0; ordinal < model.nodes.length; ordinal += 1) {
    const node = model.nodes[ordinal];
    if (node.ordinal !== ordinal) {
      throw new PermissionsGraphLayoutStateError(
        "INVALID_MODEL_ORDINAL",
        `Permissions graph node ${node.id} has invalid dense ordinal ${node.ordinal}.`,
      );
    }
    if (index.getNode(node.id) !== node || index.getNodeOrdinal(node.id) !== ordinal) {
      throw new PermissionsGraphLayoutStateError(
        "INDEX_MODEL_MISMATCH",
        "Permissions graph index does not match the supplied model.",
      );
    }
  }
}

function validateInitialization(
  initialization: PermissionsGraphLayoutInitialization,
  nodeCount: number,
): void {
  const arrays = [
    initialization.x,
    initialization.y,
    initialization.manual,
    initialization.generations,
  ];
  if (arrays.some((array) => array.length !== nodeCount)) {
    throw new PermissionsGraphLayoutStateError(
      "INVALID_MODEL_ORDINAL",
      "Permissions graph layout array lengths do not match the model node count.",
    );
  }
  if ((initialization.vx === null) !== (initialization.vy === null)) {
    throw new PermissionsGraphLayoutStateError(
      "INVALID_MODEL_ORDINAL",
      "Permissions graph velocity arrays must both be present or both be absent.",
    );
  }
  if (
    initialization.vx &&
    initialization.vy &&
    (initialization.vx.length !== nodeCount || initialization.vy.length !== nodeCount)
  ) {
    throw new PermissionsGraphLayoutStateError(
      "INVALID_MODEL_ORDINAL",
      "Permissions graph velocity array lengths do not match the model node count.",
    );
  }
  for (let ordinal = 0; ordinal < nodeCount; ordinal += 1) {
    assertFiniteCoordinate(initialization.x[ordinal], initialization.y[ordinal], `ordinal ${ordinal}`);
    if (initialization.vx && initialization.vy) {
      assertFiniteCoordinate(initialization.vx[ordinal], initialization.vy[ordinal], `velocity ${ordinal}`);
    }
    if (initialization.manual[ordinal] !== 0 && initialization.manual[ordinal] !== 1) {
      throw new PermissionsGraphLayoutStateError(
        "INVALID_MODEL_ORDINAL",
        `Permissions graph manual flag at ordinal ${ordinal} is invalid.`,
      );
    }
  }
}

function validateStoreCoordinates(store: PermissionsGraphLayoutStore): void {
  for (let ordinal = 0; ordinal < store.coordinateCount; ordinal += 1) {
    if (!Number.isFinite(store.x[ordinal]) || !Number.isFinite(store.y[ordinal])) {
      throw persistenceError(
        "NON_FINITE_COORDINATE",
        `Permissions graph coordinate at ordinal ${ordinal} is not finite.`,
      );
    }
    if (store.vx && store.vy && (!Number.isFinite(store.vx[ordinal]) || !Number.isFinite(store.vy[ordinal]))) {
      throw persistenceError(
        "NON_FINITE_COORDINATE",
        `Permissions graph velocity at ordinal ${ordinal} is not finite.`,
      );
    }
  }
}

function calculateBounds(x: Float32Array, y: Float32Array): PermissionsGraphCoordinateBounds {
  if (x.length === 0) {
    return Object.freeze({ minX: 0, minY: 0, maxX: 0, maxY: 0, width: 0, height: 0 });
  }
  let minX = x[0];
  let minY = y[0];
  let maxX = x[0];
  let maxY = y[0];
  for (let ordinal = 0; ordinal < x.length; ordinal += 1) {
    const nextX = x[ordinal];
    const nextY = y[ordinal];
    if (!Number.isFinite(nextX) || !Number.isFinite(nextY)) {
      throw new PermissionsGraphLayoutStateError(
        "NON_FINITE_COORDINATE",
        `Permissions graph coordinate at ordinal ${ordinal} is not finite.`,
      );
    }
    minX = Math.min(minX, nextX);
    minY = Math.min(minY, nextY);
    maxX = Math.max(maxX, nextX);
    maxY = Math.max(maxY, nextY);
  }
  return Object.freeze({
    minX,
    minY,
    maxX,
    maxY,
    width: maxX - minX,
    height: maxY - minY,
  });
}

function assertFiniteCoordinate(x: number, y: number, description: string): void {
  if (!Number.isFinite(x) || !Number.isFinite(y)) {
    throw new PermissionsGraphLayoutStateError(
      "NON_FINITE_COORDINATE",
      `Permissions graph ${description} must contain finite coordinates.`,
    );
  }
}

function toFiniteFloat32(value: number, description: string): number {
  const converted = new Float32Array([value])[0];
  if (!Number.isFinite(converted)) {
    throw new PermissionsGraphLayoutStateError(
      "NON_FINITE_COORDINATE",
      `Permissions graph ${description} is outside the finite Float32 range.`,
    );
  }
  return converted;
}

function normalizeGeneration(value: number): number {
  if (!Number.isFinite(value) || value < 0 || value > 0xffff_ffff) {
    throw new PermissionsGraphLayoutStateError(
      "INVALID_GENERATION",
      "Permissions graph layout generation must be a Uint32 value.",
    );
  }
  return Math.floor(value) >>> 0;
}

function normalizeUint32(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.floor(value) >>> 0;
}

function incrementUint32(value: number): number {
  return (value + 1) >>> 0;
}

function normalizeInterval(
  value: number | undefined,
  fallback: number,
  allowZero: boolean,
): number {
  if (value === undefined) return fallback;
  if (!Number.isFinite(value)) return fallback;
  const minimum = allowZero ? 0 : 1;
  return Math.max(minimum, Math.floor(value));
}

function seedFromFingerprint(fingerprint: string): number {
  return hashString(`permissions-graph-layout:${fingerprint}`);
}

function hashString(value: string): number {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

function fnv1a32Bytes(bytes: Uint8Array): number {
  let hash = 0x811c9dc5;
  for (const byte of bytes) {
    hash ^= byte;
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

function rotateUint32(value: number, bits: number): number {
  return ((value << bits) | (value >>> (32 - bits))) >>> 0;
}

function hashToSignedUnit(value: number): number {
  return (value / 0xffff_ffff) * 2 - 1;
}

function writeFloat32Array(view: DataView, offset: number, values: Float32Array): number {
  for (const value of values) {
    view.setFloat32(offset, value, true);
    offset += 4;
  }
  return offset;
}

function writeUint32Array(view: DataView, offset: number, values: Uint32Array): number {
  for (const value of values) {
    view.setUint32(offset, value, true);
    offset += 4;
  }
  return offset;
}

function readFloat32Array(
  view: DataView,
  bytes: Uint8Array,
  offset: number,
  count: number,
): Float32Array {
  requireBytes(bytes, offset, checkedMultiply(count, 4));
  const values = new Float32Array(count);
  for (let index = 0; index < count; index += 1) {
    const value = view.getFloat32(offset + index * 4, true);
    if (!Number.isFinite(value)) {
      throw persistenceError(
        "NON_FINITE_COORDINATE",
        `Permissions graph binary coordinate ${index} is not finite.`,
      );
    }
    values[index] = value;
  }
  return values;
}

function readUint32Array(
  view: DataView,
  bytes: Uint8Array,
  offset: number,
  count: number,
): Uint32Array {
  requireBytes(bytes, offset, checkedMultiply(count, 4));
  const values = new Uint32Array(count);
  for (let index = 0; index < count; index += 1) {
    values[index] = view.getUint32(offset + index * 4, true);
  }
  return values;
}

function requireBytes(bytes: Uint8Array, offset: number, length: number): void {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0) {
    throw persistenceError("CORRUPT_DATA", "Permissions graph layout contains invalid offsets.");
  }
  if (offset > bytes.byteLength || length > bytes.byteLength - offset) {
    throw persistenceError("TRUNCATED_DATA", "Permissions graph layout data is truncated.");
  }
}

function checkedMultiply(left: number, right: number): number {
  const result = left * right;
  if (!Number.isSafeInteger(result) || result < 0) {
    throw persistenceError("INVALID_HEADER", "Permissions graph layout size is invalid.");
  }
  return result;
}

function checkedAdd(left: number, right: number): number {
  const result = left + right;
  if (!Number.isSafeInteger(result) || result < 0) {
    throw persistenceError("INVALID_HEADER", "Permissions graph layout size is invalid.");
  }
  return result;
}

function countFlags(flags: Uint8Array): number {
  let count = 0;
  for (const flag of flags) count += flag === 1 ? 1 : 0;
  return count;
}

function persistenceError(
  code: PermissionsGraphLayoutPersistenceErrorCode,
  message: string,
): PermissionsGraphLayoutPersistenceError {
  return new PermissionsGraphLayoutPersistenceError(code, message);
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function freezeSortedIds(values: Iterable<string>): readonly string[] {
  return Object.freeze(Array.from(new Set(values)).sort(compareStrings));
}
