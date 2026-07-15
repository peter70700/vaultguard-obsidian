/**
 * Pure Hybrid Phase A node buffers for a future permissions-graph overview.
 *
 * This module is intentionally inert. It owns no renderer, browser API,
 * Cytoscape object, persistence, cache, worker, vault, or network behavior.
 */

import type { PermissionsGraphLayoutStore } from "./permissions-graph-layout";
import type {
  PermissionsGraphIndex,
  PermissionsGraphModel,
  PermissionsGraphNodeKind,
} from "./permissions-graph-model";

export const PERMISSIONS_GRAPH_OVERVIEW_BUFFER_VERSION = 1;
export const PERMISSIONS_GRAPH_OVERVIEW_POINT_SIZE_MIN = 2;
export const PERMISSIONS_GRAPH_OVERVIEW_POINT_SIZE_MAX = 10;

export const PERMISSIONS_GRAPH_OVERVIEW_NODE_KIND_CODE = Object.freeze({
  unknown: 0,
  user: 1,
  file: 2,
  folder: 3,
  vault: 4,
  group: 5,
  aggregate: 6,
} as const);

/** Bitmask. Positive levels may be combined for mixed incident access. */
export const PERMISSIONS_GRAPH_OVERVIEW_ACCESS_CODE = Object.freeze({
  unknown: 0,
  none: 1,
  read: 2,
  write: 4,
  admin: 8,
} as const);

/** Semantic palette/shape tokens. Renderers map these to theme-aware colors. */
export const PERMISSIONS_GRAPH_OVERVIEW_VISUAL_TOKEN = Object.freeze({
  unknown: 0,
  principal: 1,
  document: 2,
  container: 3,
  vault: 4,
  group: 5,
  aggregate: 6,
} as const);

export const PERMISSIONS_GRAPH_OVERVIEW_AGGREGATE_STATE_CODE = Object.freeze({
  none: 0,
  aggregate: 1,
} as const);

export const PERMISSIONS_GRAPH_OVERVIEW_STATIC_FLAG = Object.freeze({
  aggregate: 1 << 0,
  manualPinned: 1 << 1,
  hasAggregateCount: 1 << 2,
  hasPositiveAccess: 1 << 3,
  diagnostic: 1 << 4,
} as const);

export const PERMISSIONS_GRAPH_OVERVIEW_DYNAMIC_FLAG = Object.freeze({
  selected: 1 << 0,
  focused: 1 << 1,
  hovered: 1 << 2,
  searchMatch: 1 << 3,
  materialized: 1 << 4,
  dimmed: 1 << 5,
  dragSuppressed: 1 << 6,
} as const);

const MAX_UINT32 = 0xffff_ffff;
const MAX_VISUAL_NIBBLE = 0x0f;

export type PermissionsGraphOverviewDiagnosticCode =
  | "ABSENT_OPTIONAL_WEIGHT"
  | "AGGREGATE_COUNT_CLAMPED"
  | "IGNORED_UNKNOWN_STATE_ID"
  | "POINT_SIZE_CLAMPED"
  | "UNKNOWN_ACCESS_LEVEL"
  | "UNKNOWN_NODE_KIND"
  | "WEIGHT_CLAMPED";

export interface PermissionsGraphOverviewDiagnostic {
  readonly code: PermissionsGraphOverviewDiagnosticCode;
  readonly message: string;
  readonly count: number;
  readonly firstOrdinal?: number;
}

export type PermissionsGraphOverviewBufferBuildErrorCode =
  | "INDEX_MODEL_MISMATCH"
  | "INVALID_COORDINATE_LENGTH"
  | "INVALID_LAYOUT_METADATA"
  | "INVALID_ORDINAL"
  | "LAYOUT_IDENTITY_MISMATCH"
  | "MISSING_ORDINAL_RECORD"
  | "NODE_COUNT_MISMATCH"
  | "NON_FINITE_COORDINATE"
  | "TOPOLOGY_MISMATCH"
  | "UNSAFE_INTEGER_OVERFLOW";

export class PermissionsGraphOverviewBufferBuildError extends Error {
  constructor(
    readonly code: PermissionsGraphOverviewBufferBuildErrorCode,
    message: string,
    readonly ordinal: number | null = null,
  ) {
    super(message);
    this.name = "PermissionsGraphOverviewBufferBuildError";
  }
}

export interface PermissionsGraphOverviewState {
  readonly revision?: number;
  readonly selectedNodeIds?: readonly string[];
  readonly focusedNodeIds?: readonly string[];
  readonly hoveredNodeIds?: readonly string[];
  readonly searchMatchNodeIds?: readonly string[];
  readonly materializedNodeIds?: readonly string[];
  readonly dimmedNodeIds?: readonly string[];
}

export interface PermissionsGraphOverviewBufferBuildOptions {
  /** Emit one aggregate diagnostic when the optional importance/weight field is absent. */
  readonly diagnoseMissingOptionalWeight?: boolean;
}

export interface PermissionsGraphOverviewBufferBuildInput {
  readonly model: PermissionsGraphModel;
  readonly index: PermissionsGraphIndex;
  readonly layout: PermissionsGraphLayoutStore;
  readonly state?: PermissionsGraphOverviewState;
  readonly options?: PermissionsGraphOverviewBufferBuildOptions;
}

export interface PermissionsGraphOverviewBufferRange {
  readonly startOrdinal: number;
  readonly endOrdinalExclusive: number;
}

/** Phase A emits full rebuilds; Phase D may emit dynamic-state-only ranges. */
export interface PermissionsGraphOverviewBufferUpdate {
  readonly kind: "full" | "dynamic" | "coordinates";
  readonly ranges: readonly PermissionsGraphOverviewBufferRange[];
}

export interface PermissionsGraphOverviewCoordinatePatchInput {
  readonly buffers: PermissionsGraphOverviewBuffers;
  readonly layout: PermissionsGraphLayoutStore;
  readonly previousCoordinateRevision: number;
  readonly movedOrdinals: readonly number[] | Uint32Array;
}

export interface PermissionsGraphOverviewCoordinatePatchResult {
  readonly buffers: PermissionsGraphOverviewBuffers;
  readonly changedOrdinals: readonly number[];
}

export interface PermissionsGraphOverviewBufferMemory {
  readonly positionsBytes: number;
  readonly pointSizesBytes: number;
  readonly kindCodesBytes: number;
  readonly accessCodesBytes: number;
  readonly visualTokensBytes: number;
  readonly visualAttributesBytes: number;
  readonly staticFlagsBytes: number;
  readonly dynamicFlagsBytes: number;
  readonly weightsBytes: number;
  readonly aggregateCountsBytes: number;
  readonly totalOwnedBytes: number;
  readonly sharedBorrowedBytes: 0;
  readonly combinedLogicalBytes: number;
  readonly expectedGpuMirrorBytes: number;
  readonly bytesPerNode: number;
  readonly phase3LayoutMemoryIncluded: false;
}

/**
 * Owned node-only buffers. Returned typed arrays belong exclusively to this
 * result and callers must treat them as immutable. Source arrays are never
 * mutated or aliased. JavaScript cannot reliably deep-freeze typed elements,
 * so immutability is an ownership contract rather than a runtime freeze.
 */
export interface PermissionsGraphOverviewBuffers {
  readonly version: typeof PERMISSIONS_GRAPH_OVERVIEW_BUFFER_VERSION;
  readonly nodeCount: number;
  readonly topologyFingerprint: string;
  readonly layoutGeneration: number;
  readonly coordinateRevision: number;
  readonly dynamicStateRevision: number | null;
  readonly positions: Float32Array;
  readonly pointSizes: Float32Array;
  readonly kindCodes: Uint8Array;
  readonly accessCodes: Uint8Array;
  readonly visualTokens: Uint8Array;
  /** Packed as kind/access/token/aggregate-bucket/static/version fields. */
  readonly visualAttributes: Uint32Array;
  readonly staticFlags: Uint8Array;
  readonly dynamicFlags?: Uint8Array;
  readonly weights: Uint32Array;
  readonly aggregateCounts: Uint32Array;
  readonly diagnostics: readonly PermissionsGraphOverviewDiagnostic[];
  readonly memory: PermissionsGraphOverviewBufferMemory;
  readonly bufferFingerprint: string;
  readonly invalidationKey: string;
  readonly update: PermissionsGraphOverviewBufferUpdate;
}

interface DiagnosticAccumulator {
  count: number;
  firstOrdinal?: number;
}

type DiagnosticMap = Map<PermissionsGraphOverviewDiagnosticCode, DiagnosticAccumulator>;

/** Build deterministic, renderer-independent buffers in dense node-ordinal order. */
export function buildPermissionsGraphOverviewBuffers(
  input: PermissionsGraphOverviewBufferBuildInput,
): PermissionsGraphOverviewBuffers {
  validateInputs(input.model, input.index, input.layout, input.state);
  const { model, index, layout } = input;
  const nodeCount = model.nodeCount;
  const positionLength = checkedMultiply(nodeCount, 2);
  const diagnostics: DiagnosticMap = new Map();

  const positions = allocate(() => new Float32Array(positionLength));
  const pointSizes = allocate(() => new Float32Array(nodeCount));
  const kindCodes = allocate(() => new Uint8Array(nodeCount));
  const accessCodes = allocate(() => new Uint8Array(nodeCount));
  const visualTokens = allocate(() => new Uint8Array(nodeCount));
  const visualAttributes = allocate(() => new Uint32Array(nodeCount));
  const staticFlags = allocate(() => new Uint8Array(nodeCount));
  const dynamicFlags = input.state ? allocate(() => new Uint8Array(nodeCount)) : undefined;
  const weights = allocate(() => new Uint32Array(nodeCount));
  const aggregateCounts = allocate(() => new Uint32Array(nodeCount));

  buildAccessCodes(model, index, accessCodes, diagnostics);

  for (let ordinal = 0; ordinal < nodeCount; ordinal += 1) {
    const node = model.nodes[ordinal];
    if (!node) {
      throw new PermissionsGraphOverviewBufferBuildError(
        "MISSING_ORDINAL_RECORD",
        `Permissions graph node record is missing at ordinal ${ordinal}.`,
        ordinal,
      );
    }

    const x = layout.x[ordinal];
    const y = layout.y[ordinal];
    if (!Number.isFinite(x) || !Number.isFinite(y)) {
      throw new PermissionsGraphOverviewBufferBuildError(
        "NON_FINITE_COORDINATE",
        `Permissions graph coordinate is not finite at ordinal ${ordinal}.`,
        ordinal,
      );
    }
    positions[ordinal * 2] = x;
    positions[ordinal * 2 + 1] = y;

    const kindCode = nodeKindCode(node.kind);
    kindCodes[ordinal] = kindCode;
    if (kindCode === PERMISSIONS_GRAPH_OVERVIEW_NODE_KIND_CODE.unknown) {
      addDiagnostic(diagnostics, "UNKNOWN_NODE_KIND", ordinal);
    }

    const aggregateCount = boundedAggregateCount(node.aggregateCounts?.readableFiles, ordinal, diagnostics);
    aggregateCounts[ordinal] = aggregateCount;
    const optionalWeight = readOptionalWeight(node.data);
    if (optionalWeight === null && input.options?.diagnoseMissingOptionalWeight === true) {
      addDiagnostic(diagnostics, "ABSENT_OPTIONAL_WEIGHT", ordinal);
    }
    const degree = index.getDegree(node.id).total;
    const weight = boundedWeight(degree, optionalWeight, ordinal, diagnostics);
    weights[ordinal] = weight;

    let flags = 0;
    if (node.aggregate) flags |= PERMISSIONS_GRAPH_OVERVIEW_STATIC_FLAG.aggregate;
    if (layout.manualFlags[ordinal] === 1) {
      flags |= PERMISSIONS_GRAPH_OVERVIEW_STATIC_FLAG.manualPinned;
    }
    if (aggregateCount > 0) flags |= PERMISSIONS_GRAPH_OVERVIEW_STATIC_FLAG.hasAggregateCount;
    if ((accessCodes[ordinal] & 0x0e) !== 0) {
      flags |= PERMISSIONS_GRAPH_OVERVIEW_STATIC_FLAG.hasPositiveAccess;
    }
    if (
      kindCode === PERMISSIONS_GRAPH_OVERVIEW_NODE_KIND_CODE.unknown ||
      accessCodes[ordinal] === PERMISSIONS_GRAPH_OVERVIEW_ACCESS_CODE.unknown
    ) {
      flags |= PERMISSIONS_GRAPH_OVERVIEW_STATIC_FLAG.diagnostic;
    }
    staticFlags[ordinal] = flags;

    const token = visualToken(node.kind, node.aggregate);
    visualTokens[ordinal] = token;
    const rawPointSize = calculatePointSize(node.kind, node.aggregate, weight, aggregateCount);
    const pointSize = Math.max(
      PERMISSIONS_GRAPH_OVERVIEW_POINT_SIZE_MIN,
      Math.min(PERMISSIONS_GRAPH_OVERVIEW_POINT_SIZE_MAX, rawPointSize),
    );
    pointSizes[ordinal] = pointSize;
    if (!Object.is(pointSize, rawPointSize)) {
      addDiagnostic(diagnostics, "POINT_SIZE_CLAMPED", ordinal);
    }

    const aggregateBucket = logarithmicBucket(aggregateCount);
    visualAttributes[ordinal] = packVisualAttributes(
      kindCode,
      accessCodes[ordinal],
      token,
      aggregateBucket,
      flags,
    );
  }

  if (dynamicFlags && input.state) {
    applyDynamicState(input.state, index, dynamicFlags, diagnostics);
  }

  const frozenDiagnostics = freezeDiagnostics(diagnostics);
  const memory = calculatePermissionsGraphOverviewBufferMemory({
    nodeCount,
    positions,
    pointSizes,
    kindCodes,
    accessCodes,
    visualTokens,
    visualAttributes,
    staticFlags,
    dynamicFlags,
    weights,
    aggregateCounts,
  });
  const dynamicStateRevision = input.state ? normalizeUint32(input.state.revision ?? 0) : null;
  const invalidationKey = [
    `v${PERMISSIONS_GRAPH_OVERVIEW_BUFFER_VERSION}`,
    model.topologyFingerprint,
    `g${layout.layoutGeneration}`,
    `r${layout.coordinateRevision}`,
    dynamicStateRevision === null ? "s-none" : `s${dynamicStateRevision}`,
    input.options?.diagnoseMissingOptionalWeight === true ? "w1" : "w0",
  ].join(":");
  const update = Object.freeze({
    kind: "full" as const,
    ranges: Object.freeze(nodeCount === 0
      ? []
      : [Object.freeze({ startOrdinal: 0, endOrdinalExclusive: nodeCount })]),
  });
  const bufferFingerprint = fingerprintBuffers(invalidationKey, [
    positions,
    pointSizes,
    kindCodes,
    accessCodes,
    visualTokens,
    visualAttributes,
    staticFlags,
    ...(dynamicFlags ? [dynamicFlags] : []),
    weights,
    aggregateCounts,
  ]);

  return Object.freeze({
    version: PERMISSIONS_GRAPH_OVERVIEW_BUFFER_VERSION,
    nodeCount,
    topologyFingerprint: model.topologyFingerprint,
    layoutGeneration: layout.layoutGeneration,
    coordinateRevision: layout.coordinateRevision,
    dynamicStateRevision,
    positions,
    pointSizes,
    kindCodes,
    accessCodes,
    visualTokens,
    visualAttributes,
    staticFlags,
    ...(dynamicFlags ? { dynamicFlags } : {}),
    weights,
    aggregateCounts,
    diagnostics: frozenDiagnostics,
    memory,
    bufferFingerprint,
    invalidationKey,
    update,
  });
}

/**
 * Publish coordinate-only ranges for one immediately committed layout
 * revision. Static and dynamic semantic arrays retain their immutable
 * identities; only the owned position array is replaced.
 */
export function patchPermissionsGraphOverviewCoordinates(
  input: PermissionsGraphOverviewCoordinatePatchInput,
): PermissionsGraphOverviewCoordinatePatchResult {
  const { buffers, layout } = input;
  if (buffers.topologyFingerprint !== layout.topologyFingerprint) {
    throw new PermissionsGraphOverviewBufferBuildError(
      "TOPOLOGY_MISMATCH",
      "Overview coordinate patch topology does not match the committed layout.",
    );
  }
  if (buffers.layoutGeneration !== layout.layoutGeneration) {
    throw new PermissionsGraphOverviewBufferBuildError(
      "LAYOUT_IDENTITY_MISMATCH",
      "Overview coordinate patch generation does not match the committed layout.",
    );
  }
  if (
    !isUint32(input.previousCoordinateRevision) ||
    buffers.coordinateRevision !== input.previousCoordinateRevision ||
    layout.coordinateRevision !== incrementUint32(input.previousCoordinateRevision)
  ) {
    throw new PermissionsGraphOverviewBufferBuildError(
      "LAYOUT_IDENTITY_MISMATCH",
      "Overview coordinate patch revision must be the immediately committed layout revision.",
    );
  }
  if (buffers.nodeCount !== layout.coordinateCount || buffers.positions.length !== buffers.nodeCount * 2) {
    throw new PermissionsGraphOverviewBufferBuildError(
      "INVALID_COORDINATE_LENGTH",
      "Overview coordinate patch position length does not match the layout.",
    );
  }

  const changedOrdinals = Array.from(new Set(Array.from(input.movedOrdinals))).sort((a, b) => a - b);
  for (const ordinal of changedOrdinals) {
    if (!Number.isInteger(ordinal) || ordinal < 0 || ordinal >= buffers.nodeCount) {
      throw new PermissionsGraphOverviewBufferBuildError(
        "INVALID_ORDINAL",
        `Overview coordinate patch ordinal ${ordinal} is outside the buffers.`,
        ordinal,
      );
    }
    if (!Number.isFinite(layout.x[ordinal]) || !Number.isFinite(layout.y[ordinal])) {
      throw new PermissionsGraphOverviewBufferBuildError(
        "NON_FINITE_COORDINATE",
        `Overview coordinate patch coordinate is not finite at ordinal ${ordinal}.`,
        ordinal,
      );
    }
  }

  const positions = buffers.positions.slice();
  for (const ordinal of changedOrdinals) {
    positions[ordinal * 2] = layout.x[ordinal] as number;
    positions[ordinal * 2 + 1] = layout.y[ordinal] as number;
  }
  const invalidationKey = `${buffers.invalidationKey}:c${layout.coordinateRevision}`;
  const positionFingerprint = fingerprintBuffers(invalidationKey, [positions]);
  const patched: PermissionsGraphOverviewBuffers = Object.freeze({
    ...buffers,
    coordinateRevision: layout.coordinateRevision,
    positions,
    invalidationKey,
    bufferFingerprint: `${buffers.bufferFingerprint}:${positionFingerprint}`,
    update: Object.freeze({
      kind: "coordinates" as const,
      ranges: coalesceOrdinals(changedOrdinals),
    }),
  });
  return Object.freeze({
    buffers: patched,
    changedOrdinals: Object.freeze(changedOrdinals),
  });
}

interface MemoryInput {
  readonly nodeCount: number;
  readonly positions: Float32Array;
  readonly pointSizes: Float32Array;
  readonly kindCodes: Uint8Array;
  readonly accessCodes: Uint8Array;
  readonly visualTokens: Uint8Array;
  readonly visualAttributes: Uint32Array;
  readonly staticFlags: Uint8Array;
  readonly dynamicFlags?: Uint8Array;
  readonly weights: Uint32Array;
  readonly aggregateCounts: Uint32Array;
}

/** Exact owned-byte accounting based only on actual typed-array byte lengths. */
export function calculatePermissionsGraphOverviewBufferMemory(
  input: MemoryInput,
): PermissionsGraphOverviewBufferMemory {
  const positionsBytes = input.positions.byteLength;
  const pointSizesBytes = input.pointSizes.byteLength;
  const kindCodesBytes = input.kindCodes.byteLength;
  const accessCodesBytes = input.accessCodes.byteLength;
  const visualTokensBytes = input.visualTokens.byteLength;
  const visualAttributesBytes = input.visualAttributes.byteLength;
  const staticFlagsBytes = input.staticFlags.byteLength;
  const dynamicFlagsBytes = input.dynamicFlags?.byteLength ?? 0;
  const weightsBytes = input.weights.byteLength;
  const aggregateCountsBytes = input.aggregateCounts.byteLength;
  const totalOwnedBytes = [
    positionsBytes,
    pointSizesBytes,
    kindCodesBytes,
    accessCodesBytes,
    visualTokensBytes,
    visualAttributesBytes,
    staticFlagsBytes,
    dynamicFlagsBytes,
    weightsBytes,
    aggregateCountsBytes,
  ].reduce((total, value) => total + value, 0);
  const expectedGpuMirrorBytes = positionsBytes + pointSizesBytes +
    visualAttributesBytes + dynamicFlagsBytes;
  return Object.freeze({
    positionsBytes,
    pointSizesBytes,
    kindCodesBytes,
    accessCodesBytes,
    visualTokensBytes,
    visualAttributesBytes,
    staticFlagsBytes,
    dynamicFlagsBytes,
    weightsBytes,
    aggregateCountsBytes,
    totalOwnedBytes,
    sharedBorrowedBytes: 0,
    combinedLogicalBytes: totalOwnedBytes,
    expectedGpuMirrorBytes,
    bytesPerNode: input.nodeCount === 0 ? 0 : totalOwnedBytes / input.nodeCount,
    phase3LayoutMemoryIncluded: false,
  });
}

export function packPermissionsGraphOverviewVisualAttributes(input: {
  readonly kindCode: number;
  readonly accessCode: number;
  readonly visualToken: number;
  readonly aggregateBucket: number;
  readonly staticFlags: number;
}): number {
  return packVisualAttributes(
    input.kindCode,
    input.accessCode,
    input.visualToken,
    input.aggregateBucket,
    input.staticFlags,
  );
}

function validateInputs(
  model: PermissionsGraphModel,
  index: PermissionsGraphIndex,
  layout: PermissionsGraphLayoutStore,
  state: PermissionsGraphOverviewState | undefined,
): void {
  if (!Number.isSafeInteger(model.nodeCount) || model.nodeCount < 0) {
    throw new PermissionsGraphOverviewBufferBuildError(
      "UNSAFE_INTEGER_OVERFLOW",
      "Permissions graph node count is not a non-negative safe integer.",
    );
  }
  if (model.nodes.length !== model.nodeCount) {
    throw new PermissionsGraphOverviewBufferBuildError(
      "NODE_COUNT_MISMATCH",
      "Permissions graph node count does not match its node records.",
    );
  }
  if (layout.topologyFingerprint !== model.topologyFingerprint) {
    throw new PermissionsGraphOverviewBufferBuildError(
      "TOPOLOGY_MISMATCH",
      "Permissions graph layout topology does not match the supplied model.",
    );
  }
  if (layout.model !== model || layout.index !== index) {
    throw new PermissionsGraphOverviewBufferBuildError(
      "LAYOUT_IDENTITY_MISMATCH",
      "Permissions graph layout does not own the supplied model and index.",
    );
  }
  if (
    layout.coordinateCount !== model.nodeCount ||
    layout.x.length !== model.nodeCount ||
    layout.y.length !== model.nodeCount ||
    layout.manualFlags.length !== model.nodeCount ||
    layout.nodeIds.length !== model.nodeCount
  ) {
    throw new PermissionsGraphOverviewBufferBuildError(
      "INVALID_COORDINATE_LENGTH",
      "Permissions graph layout arrays do not match the model node count.",
    );
  }
  if (!isUint32(layout.layoutGeneration) || !isUint32(layout.coordinateRevision)) {
    throw new PermissionsGraphOverviewBufferBuildError(
      "INVALID_LAYOUT_METADATA",
      "Permissions graph layout generation and revision must be Uint32 values.",
    );
  }
  if (state?.revision !== undefined && !isUint32(state.revision)) {
    throw new PermissionsGraphOverviewBufferBuildError(
      "INVALID_LAYOUT_METADATA",
      "Permissions graph dynamic-state revision must be a Uint32 value.",
    );
  }

  for (let ordinal = 0; ordinal < model.nodeCount; ordinal += 1) {
    const node = model.nodes[ordinal];
    if (!node) {
      throw new PermissionsGraphOverviewBufferBuildError(
        "MISSING_ORDINAL_RECORD",
        `Permissions graph node record is missing at ordinal ${ordinal}.`,
        ordinal,
      );
    }
    if (node.ordinal !== ordinal || index.getNodeOrdinal(node.id) !== ordinal) {
      throw new PermissionsGraphOverviewBufferBuildError(
        "INVALID_ORDINAL",
        `Permissions graph node ordinal is invalid at ordinal ${ordinal}.`,
        ordinal,
      );
    }
    if (index.getNode(node.id) !== node) {
      throw new PermissionsGraphOverviewBufferBuildError(
        "INDEX_MODEL_MISMATCH",
        "Permissions graph index does not match the supplied model.",
        ordinal,
      );
    }
    if (layout.nodeIds[ordinal] !== node.id) {
      throw new PermissionsGraphOverviewBufferBuildError(
        "LAYOUT_IDENTITY_MISMATCH",
        `Permissions graph layout ordinal identity is invalid at ordinal ${ordinal}.`,
        ordinal,
      );
    }
  }
}

function buildAccessCodes(
  model: PermissionsGraphModel,
  index: PermissionsGraphIndex,
  accessCodes: Uint8Array,
  diagnostics: DiagnosticMap,
): void {
  accessCodes.fill(PERMISSIONS_GRAPH_OVERVIEW_ACCESS_CODE.none);
  for (let ordinal = 0; ordinal < model.nodeCount; ordinal += 1) {
    const node = model.nodes[ordinal];
    if (!node) continue;
    const incidentMask = index.getIncidentPermissionAccessMask(node.id);
    const positiveAccess = incidentMask & 0x0e;
    const hasUnknownAccess = (incidentMask & 0x10) !== 0;
    if (hasUnknownAccess) addDiagnostic(diagnostics, "UNKNOWN_ACCESS_LEVEL", ordinal);
    if (positiveAccess !== 0) {
      accessCodes[ordinal] = positiveAccess;
    } else if (hasUnknownAccess) {
      accessCodes[ordinal] = PERMISSIONS_GRAPH_OVERVIEW_ACCESS_CODE.unknown;
    }
  }
}

function applyDynamicState(
  state: PermissionsGraphOverviewState,
  index: PermissionsGraphIndex,
  flags: Uint8Array,
  diagnostics: DiagnosticMap,
): void {
  const fields = [
    [state.selectedNodeIds, PERMISSIONS_GRAPH_OVERVIEW_DYNAMIC_FLAG.selected],
    [state.focusedNodeIds, PERMISSIONS_GRAPH_OVERVIEW_DYNAMIC_FLAG.focused],
    [state.hoveredNodeIds, PERMISSIONS_GRAPH_OVERVIEW_DYNAMIC_FLAG.hovered],
    [state.searchMatchNodeIds, PERMISSIONS_GRAPH_OVERVIEW_DYNAMIC_FLAG.searchMatch],
    [state.materializedNodeIds, PERMISSIONS_GRAPH_OVERVIEW_DYNAMIC_FLAG.materialized],
    [state.dimmedNodeIds, PERMISSIONS_GRAPH_OVERVIEW_DYNAMIC_FLAG.dimmed],
  ] as const;
  for (const [ids, bit] of fields) {
    for (const id of uniqueSorted(ids ?? [])) {
      const ordinal = index.getNodeOrdinal(id);
      if (ordinal === undefined) {
        addDiagnostic(diagnostics, "IGNORED_UNKNOWN_STATE_ID");
        continue;
      }
      flags[ordinal] |= bit;
    }
  }
}

function nodeKindCode(kind: PermissionsGraphNodeKind): number {
  return PERMISSIONS_GRAPH_OVERVIEW_NODE_KIND_CODE[kind] ??
    PERMISSIONS_GRAPH_OVERVIEW_NODE_KIND_CODE.unknown;
}

function visualToken(kind: PermissionsGraphNodeKind, aggregate: boolean): number {
  if (aggregate) return PERMISSIONS_GRAPH_OVERVIEW_VISUAL_TOKEN.aggregate;
  if (kind === "user") return PERMISSIONS_GRAPH_OVERVIEW_VISUAL_TOKEN.principal;
  if (kind === "file") return PERMISSIONS_GRAPH_OVERVIEW_VISUAL_TOKEN.document;
  if (kind === "folder") return PERMISSIONS_GRAPH_OVERVIEW_VISUAL_TOKEN.container;
  if (kind === "vault") return PERMISSIONS_GRAPH_OVERVIEW_VISUAL_TOKEN.vault;
  if (kind === "group") return PERMISSIONS_GRAPH_OVERVIEW_VISUAL_TOKEN.group;
  if (kind === "aggregate") return PERMISSIONS_GRAPH_OVERVIEW_VISUAL_TOKEN.aggregate;
  return PERMISSIONS_GRAPH_OVERVIEW_VISUAL_TOKEN.unknown;
}

function readOptionalWeight(data: Readonly<Record<string, unknown>>): number | null {
  const value = data.importance ?? data.weight;
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
}

function boundedWeight(
  degree: number,
  optionalWeight: number | null,
  ordinal: number,
  diagnostics: DiagnosticMap,
): number {
  const safeDegree = Number.isFinite(degree) && degree > 0 ? Math.floor(degree) : 0;
  const importance = optionalWeight === null ? 0 : Math.floor(optionalWeight);
  const combined = safeDegree + importance;
  if (!Number.isSafeInteger(combined) || combined >= MAX_UINT32) {
    addDiagnostic(diagnostics, "WEIGHT_CLAMPED", ordinal);
    return MAX_UINT32;
  }
  return 1 + combined;
}

function boundedAggregateCount(
  value: number | undefined,
  ordinal: number,
  diagnostics: DiagnosticMap,
): number {
  if (value === undefined || !Number.isFinite(value) || value <= 0) return 0;
  const integer = Math.floor(value);
  if (integer > MAX_UINT32) {
    addDiagnostic(diagnostics, "AGGREGATE_COUNT_CLAMPED", ordinal);
    return MAX_UINT32;
  }
  return integer;
}

function calculatePointSize(
  kind: PermissionsGraphNodeKind,
  aggregate: boolean,
  weight: number,
  aggregateCount: number,
): number {
  const base = aggregate || kind === "aggregate"
    ? 6
    : kind === "file"
      ? 3
      : 5;
  const degreeGrowth = Math.min(2, Math.log2(Math.max(1, weight)) * 0.25);
  const aggregateGrowth = aggregateCount > 0
    ? Math.min(4, Math.log2(aggregateCount + 1) * 0.5)
    : 0;
  return base + degreeGrowth + aggregateGrowth;
}

function logarithmicBucket(value: number): number {
  if (value <= 0) return PERMISSIONS_GRAPH_OVERVIEW_AGGREGATE_STATE_CODE.none;
  return Math.min(MAX_VISUAL_NIBBLE, 1 + Math.floor(Math.log2(value)));
}

function packVisualAttributes(
  kindCode: number,
  accessCode: number,
  visualToken: number,
  aggregateBucket: number,
  staticFlags: number,
): number {
  return (
    (kindCode & 0x0f) |
    ((accessCode & 0x0f) << 4) |
    ((visualToken & 0x0f) << 8) |
    ((aggregateBucket & 0x0f) << 12) |
    ((staticFlags & 0xff) << 16) |
    ((PERMISSIONS_GRAPH_OVERVIEW_BUFFER_VERSION & 0x0f) << 24)
  ) >>> 0;
}

function addDiagnostic(
  diagnostics: DiagnosticMap,
  code: PermissionsGraphOverviewDiagnosticCode,
  ordinal?: number,
): void {
  const existing = diagnostics.get(code);
  if (existing) {
    existing.count += 1;
    if (ordinal !== undefined) {
      existing.firstOrdinal = existing.firstOrdinal === undefined
        ? ordinal
        : Math.min(existing.firstOrdinal, ordinal);
    }
    return;
  }
  diagnostics.set(code, ordinal === undefined
    ? { count: 1 }
    : { count: 1, firstOrdinal: ordinal });
}

function freezeDiagnostics(
  diagnostics: DiagnosticMap,
): readonly PermissionsGraphOverviewDiagnostic[] {
  const messages: Readonly<Record<PermissionsGraphOverviewDiagnosticCode, string>> = Object.freeze({
    ABSENT_OPTIONAL_WEIGHT: "Optional importance/weight metadata was absent; degree-only weight was used.",
    AGGREGATE_COUNT_CLAMPED: "Aggregate child counts above Uint32 range were clamped.",
    IGNORED_UNKNOWN_STATE_ID: "Unknown dynamic-state node IDs were ignored.",
    POINT_SIZE_CLAMPED: "Calculated base point sizes were clamped to the documented bounds.",
    UNKNOWN_ACCESS_LEVEL: "Unknown permission access levels used the stable unknown fallback.",
    UNKNOWN_NODE_KIND: "Unknown node kinds used the stable unknown fallback.",
    WEIGHT_CLAMPED: "Degree/importance weights above Uint32 range were clamped.",
  });
  return Object.freeze(Array.from(diagnostics.entries())
    .sort((left, right) => compareStrings(left[0], right[0]))
    .map(([code, value]) => Object.freeze({
      code,
      message: messages[code],
      count: value.count,
      ...(value.firstOrdinal === undefined ? {} : { firstOrdinal: value.firstOrdinal }),
    })));
}

function fingerprintBuffers(key: string, arrays: readonly ArrayBufferView[]): string {
  let hash = 0x811c9dc5;
  const update = (byte: number): void => {
    hash ^= byte;
    hash = Math.imul(hash, 0x01000193) >>> 0;
  };
  for (let index = 0; index < key.length; index += 1) {
    const code = key.charCodeAt(index);
    update(code & 0xff);
    update(code >>> 8);
  }
  for (const array of arrays) {
    const bytes = new Uint8Array(array.buffer, array.byteOffset, array.byteLength);
    for (const byte of bytes) update(byte);
    update(0xff);
  }
  return `fnv1a32:${hash.toString(16).padStart(8, "0")}`;
}

function checkedMultiply(left: number, right: number): number {
  const value = left * right;
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new PermissionsGraphOverviewBufferBuildError(
      "UNSAFE_INTEGER_OVERFLOW",
      "Permissions graph typed-array length exceeds safe integer range.",
    );
  }
  return value;
}

function allocate<T extends ArrayBufferView>(factory: () => T): T {
  try {
    return factory();
  } catch (error) {
    if (error instanceof RangeError) {
      throw new PermissionsGraphOverviewBufferBuildError(
        "UNSAFE_INTEGER_OVERFLOW",
        "Permissions graph typed-array allocation exceeds the supported range.",
      );
    }
    throw error;
  }
}

function isUint32(value: number): boolean {
  return Number.isInteger(value) && value >= 0 && value <= MAX_UINT32;
}

function incrementUint32(value: number): number {
  return value === MAX_UINT32 ? 0 : value + 1;
}

function coalesceOrdinals(ordinals: readonly number[]): readonly PermissionsGraphOverviewBufferRange[] {
  if (ordinals.length === 0) return Object.freeze([] as PermissionsGraphOverviewBufferRange[]);
  const ranges: PermissionsGraphOverviewBufferRange[] = [];
  let start = ordinals[0] as number;
  let end = start + 1;
  for (let index = 1; index < ordinals.length; index += 1) {
    const ordinal = ordinals[index] as number;
    if (ordinal === end) {
      end += 1;
      continue;
    }
    ranges.push(Object.freeze({ startOrdinal: start, endOrdinalExclusive: end }));
    start = ordinal;
    end = ordinal + 1;
  }
  ranges.push(Object.freeze({ startOrdinal: start, endOrdinalExclusive: end }));
  return Object.freeze(ranges);
}

function normalizeUint32(value: number): number {
  return Math.floor(value) >>> 0;
}

function uniqueSorted(values: readonly string[]): readonly string[] {
  return Array.from(new Set(values)).sort(compareStrings);
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
