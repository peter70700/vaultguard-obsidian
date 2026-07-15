import type { PermissionsGraphLayoutStore } from "./permissions-graph-layout";
import type {
  PermissionsGraphEdgeRecord,
  PermissionsGraphIndex,
  PermissionsGraphModel,
} from "./permissions-graph-model";

export const PERMISSIONS_GRAPH_OVERVIEW_EDGE_PHASE_E_MARKER =
  "vg-permissions-graph-overview-edges-phase-e-v1";
export const PERMISSIONS_GRAPH_OVERVIEW_EDGE_VERSION = 1;

export const PERMISSIONS_GRAPH_OVERVIEW_EDGE_LIMITS = Object.freeze({
  localSegments: 10_000,
  structuralSamples: 2_048,
  bundleSegments: 4_096,
  prioritySegments: 2_000,
  maximumModelEdges: 1_000_000,
  temporaryMemoryBytes: 256 * 1024 * 1024,
});

export const PERMISSIONS_GRAPH_OVERVIEW_EDGE_STYLE_FLAG = Object.freeze({
  expiring: 1 << 6,
  priority: 1 << 7,
  bundle: 1 << 8,
  density: 1 << 9,
});

export type PermissionsGraphOverviewEdgeMode = "local" | "structural" | "extreme";

export interface PermissionsGraphOverviewEdgeMemory {
  readonly segmentCoordinateBytes: number;
  readonly segmentStyleBytes: number;
  readonly segmentWeightBytes: number;
  readonly totalOwnedBytes: number;
  readonly expectedGpuMirrorBytes: number;
}

export interface PermissionsGraphOverviewEdgeSnapshot {
  readonly version: 1;
  readonly mode: PermissionsGraphOverviewEdgeMode;
  readonly topologyFingerprint: string;
  readonly layoutGeneration: number;
  readonly coordinateRevision: number;
  readonly cameraRevision: number;
  readonly eligibleEdgeCount: number;
  readonly representedEdgeCount: number;
  readonly emittedSegmentCount: number;
  readonly prioritySegmentCount: number;
  readonly ordinarySampleSegmentCount: number;
  readonly bundleSegmentCount: number;
  readonly densitySegmentCount: number;
  readonly bundledEdgeCount: number;
  readonly omittedEdgeCount: number;
  readonly exact: boolean;
  /** Four world-coordinate values per segment: x1, y1, x2, y2. */
  readonly segmentCoordinates: Float32Array;
  /** Packed non-private kind/access/state bits, one per segment. */
  readonly segmentStyles: Uint32Array;
  /** One for ordinary segments; represented-edge count for summaries. */
  readonly segmentWeights: Float32Array;
  readonly bufferFingerprint: string;
  readonly diagnostics: readonly string[];
  readonly memory: PermissionsGraphOverviewEdgeMemory;
}

type OrdinalList = readonly number[] | Uint32Array;

export interface PermissionsGraphOverviewEdgePriorityState {
  readonly selected?: OrdinalList;
  readonly focused?: OrdinalList;
  readonly hovered?: OrdinalList;
  readonly search?: OrdinalList;
  readonly local?: OrdinalList;
}

export interface PermissionsGraphOverviewEdgeBuildInput {
  readonly model: PermissionsGraphModel;
  readonly index: PermissionsGraphIndex;
  readonly layout: PermissionsGraphLayoutStore;
  readonly projectedMedianSpacing: number;
  readonly cameraRevision: number;
  /** Optional numeric presentation coordinates for a same-identity transition frame. */
  readonly presentationPositions?: Float32Array;
  readonly visibleNodeMask?: Uint8Array;
  readonly visibleEdgeMask?: Uint8Array;
  readonly priorityNodeOrdinals?: PermissionsGraphOverviewEdgePriorityState;
  readonly signal?: AbortSignal;
}

export type PermissionsGraphOverviewEdgeBuildErrorCode =
  | "CANCELLED"
  | "INVALID_CAMERA_METADATA"
  | "INVALID_COORDINATE"
  | "INVALID_MASK_LENGTH"
  | "INVALID_ORDINAL"
  | "INVALID_PRESENTATION_POSITIONS"
  | "INVALID_SPACING"
  | "SAFETY_LIMIT_EXCEEDED"
  | "TOPOLOGY_MISMATCH";

export class PermissionsGraphOverviewEdgeBuildError extends Error {
  constructor(
    readonly code: PermissionsGraphOverviewEdgeBuildErrorCode,
    message: string,
  ) {
    super(message);
    this.name = code === "CANCELLED" ? "AbortError" : "PermissionsGraphOverviewEdgeBuildError";
  }
}

interface EdgeCandidate {
  readonly ordinal: number;
  readonly sourceOrdinal: number;
  readonly targetOrdinal: number;
  readonly x1: number;
  readonly y1: number;
  readonly x2: number;
  readonly y2: number;
  readonly style: number;
  readonly kindCode: number;
  readonly accessCode: number;
  readonly hash: number;
  readonly priorityRank: number | null;
}

interface OutputSegment {
  readonly x1: number;
  readonly y1: number;
  readonly x2: number;
  readonly y2: number;
  readonly style: number;
  readonly weight: number;
}

interface BundleAccumulator {
  readonly key: string;
  readonly hash: number;
  readonly style: number;
  count: number;
  x1: number;
  y1: number;
  x2: number;
  y2: number;
}

const BUNDLE_CELL_SIZE = 2_048;
const EDGE_TEMPORARY_BYTES_PER_CANDIDATE = 96;

export function selectPermissionsGraphOverviewEdgeMode(
  projectedMedianSpacing: number,
  eligibleEdgeCount: number,
): PermissionsGraphOverviewEdgeMode {
  if (!Number.isFinite(projectedMedianSpacing) || projectedMedianSpacing < 0) {
    throw new PermissionsGraphOverviewEdgeBuildError(
      "INVALID_SPACING",
      "Projected permissions graph node spacing must be finite and non-negative.",
    );
  }
  if (!Number.isSafeInteger(eligibleEdgeCount) || eligibleEdgeCount < 0) {
    throw new PermissionsGraphOverviewEdgeBuildError(
      "SAFETY_LIMIT_EXCEEDED",
      "Eligible permissions graph edge count must be a non-negative safe integer.",
    );
  }
  if (projectedMedianSpacing < 2 || eligibleEdgeCount > 100_000) return "extreme";
  if (projectedMedianSpacing <= 8 || eligibleEdgeCount > 10_000) return "structural";
  return "local";
}

export function buildPermissionsGraphOverviewEdges(
  input: PermissionsGraphOverviewEdgeBuildInput,
): PermissionsGraphOverviewEdgeSnapshot {
  validateInput(input);
  checkCancellation(input.signal);

  const priorityRanks = buildPriorityRanks(input.priorityNodeOrdinals, input.model.nodeCount);
  const candidates: EdgeCandidate[] = [];
  for (const edge of input.model.edges) {
    if ((edge.ordinal & 255) === 0) checkCancellation(input.signal);
    if (input.visibleEdgeMask && input.visibleEdgeMask[edge.ordinal] !== 1) continue;
    const sourceOrdinal = input.index.getNodeOrdinal(edge.sourceId);
    const targetOrdinal = input.index.getNodeOrdinal(edge.targetId);
    if (sourceOrdinal === undefined || targetOrdinal === undefined) {
      throw new PermissionsGraphOverviewEdgeBuildError(
        "TOPOLOGY_MISMATCH",
        "Permissions graph edge endpoint is absent from the matching index.",
      );
    }
    if (
      input.visibleNodeMask &&
      (input.visibleNodeMask[sourceOrdinal] !== 1 || input.visibleNodeMask[targetOrdinal] !== 1)
    ) {
      continue;
    }
    const positions = input.presentationPositions;
    const x1 = positions?.[sourceOrdinal * 2] ?? input.layout.x[sourceOrdinal];
    const y1 = positions?.[sourceOrdinal * 2 + 1] ?? input.layout.y[sourceOrdinal];
    const x2 = positions?.[targetOrdinal * 2] ?? input.layout.x[targetOrdinal];
    const y2 = positions?.[targetOrdinal * 2 + 1] ?? input.layout.y[targetOrdinal];
    if (![x1, y1, x2, y2].every(Number.isFinite)) {
      throw new PermissionsGraphOverviewEdgeBuildError(
        "INVALID_COORDINATE",
        "Permissions graph edge endpoint coordinate is not finite.",
      );
    }
    const kindCode = edgeKindCode(edge);
    const accessCode = edgeAccessCode(edge);
    const sourceRank = priorityRanks.get(sourceOrdinal);
    const targetRank = priorityRanks.get(targetOrdinal);
    const priorityRank = sourceRank === undefined
      ? targetRank ?? null
      : targetRank === undefined ? sourceRank : Math.min(sourceRank, targetRank);
    candidates.push({
      ordinal: edge.ordinal,
      sourceOrdinal,
      targetOrdinal,
      x1: x1 as number,
      y1: y1 as number,
      x2: x2 as number,
      y2: y2 as number,
      style: packEdgeStyle(kindCode, accessCode, edge.expiring),
      kindCode,
      accessCode,
      hash: hashText(edge.id),
      priorityRank,
    });
  }

  const mode = selectPermissionsGraphOverviewEdgeMode(
    input.projectedMedianSpacing,
    candidates.length,
  );
  const priority = candidates
    .filter((candidate) => candidate.priorityRank !== null)
    .sort(comparePriorityCandidates)
    .slice(0, PERMISSIONS_GRAPH_OVERVIEW_EDGE_LIMITS.prioritySegments);
  const priorityOrdinals = new Set(priority.map((candidate) => candidate.ordinal));
  const remaining = candidates.filter((candidate) => !priorityOrdinals.has(candidate.ordinal));
  const segments: OutputSegment[] = priority.map((candidate) => candidateSegment(
    candidate,
    candidate.style | PERMISSIONS_GRAPH_OVERVIEW_EDGE_STYLE_FLAG.priority,
  ));

  let sampled: EdgeCandidate[] = [];
  let bundleInput: EdgeCandidate[] = [];
  if (mode === "local") {
    sampled = [...remaining].sort(compareCandidates)
      .slice(0, PERMISSIONS_GRAPH_OVERVIEW_EDGE_LIMITS.localSegments);
  } else if (mode === "structural") {
    sampled = takeFairStructuralSample(
      remaining,
      PERMISSIONS_GRAPH_OVERVIEW_EDGE_LIMITS.structuralSamples,
    );
    const sampledOrdinals = new Set(sampled.map((candidate) => candidate.ordinal));
    bundleInput = remaining.filter((candidate) => !sampledOrdinals.has(candidate.ordinal));
  } else {
    bundleInput = remaining;
  }
  for (const candidate of sampled) segments.push(candidateSegment(candidate, candidate.style));

  const bundled = buildBundleSegments(bundleInput, mode === "extreme");
  segments.push(...bundled.segments);
  checkCancellation(input.signal);

  const representedEdgeCount = priority.length + sampled.length + bundled.representedEdgeCount;
  const omittedEdgeCount = candidates.length - representedEdgeCount;
  const segmentCoordinates = new Float32Array(segments.length * 4);
  const segmentStyles = new Uint32Array(segments.length);
  const segmentWeights = new Float32Array(segments.length);
  for (let index = 0; index < segments.length; index += 1) {
    const segment = segments[index] as OutputSegment;
    const offset = index * 4;
    segmentCoordinates[offset] = segment.x1;
    segmentCoordinates[offset + 1] = segment.y1;
    segmentCoordinates[offset + 2] = segment.x2;
    segmentCoordinates[offset + 3] = segment.y2;
    segmentStyles[index] = segment.style;
    segmentWeights[index] = segment.weight;
  }

  const memory = Object.freeze({
    segmentCoordinateBytes: segmentCoordinates.byteLength,
    segmentStyleBytes: segmentStyles.byteLength,
    segmentWeightBytes: segmentWeights.byteLength,
    totalOwnedBytes: segmentCoordinates.byteLength + segmentStyles.byteLength +
      segmentWeights.byteLength,
    expectedGpuMirrorBytes: segmentCoordinates.byteLength + segmentStyles.byteLength,
  });
  const fingerprint = fingerprintSnapshot(
    mode,
    input.cameraRevision,
    candidates.length,
    segmentCoordinates,
    segmentStyles,
    segmentWeights,
  );
  const diagnostics = Object.freeze([
    `mode:${mode}`,
    `eligible:${candidates.length}`,
    `emitted:${segments.length}`,
    `omitted:${omittedEdgeCount}`,
  ]);

  return Object.freeze({
    version: PERMISSIONS_GRAPH_OVERVIEW_EDGE_VERSION,
    mode,
    topologyFingerprint: input.model.topologyFingerprint,
    layoutGeneration: input.layout.layoutGeneration,
    coordinateRevision: input.layout.coordinateRevision,
    cameraRevision: input.cameraRevision,
    eligibleEdgeCount: candidates.length,
    representedEdgeCount,
    emittedSegmentCount: segments.length,
    prioritySegmentCount: priority.length,
    ordinarySampleSegmentCount: sampled.length,
    bundleSegmentCount: bundled.segments.length,
    densitySegmentCount: mode === "extreme" ? bundled.segments.length : 0,
    bundledEdgeCount: bundled.representedEdgeCount,
    omittedEdgeCount,
    exact: mode === "local" && omittedEdgeCount === 0,
    segmentCoordinates,
    segmentStyles,
    segmentWeights,
    bufferFingerprint: fingerprint,
    diagnostics,
    memory,
  });
}

function validateInput(input: PermissionsGraphOverviewEdgeBuildInput): void {
  if (
    !Number.isSafeInteger(input.model.edgeCount) || input.model.edgeCount < 0 ||
    input.model.edgeCount > PERMISSIONS_GRAPH_OVERVIEW_EDGE_LIMITS.maximumModelEdges ||
    input.model.edgeCount * EDGE_TEMPORARY_BYTES_PER_CANDIDATE >
      PERMISSIONS_GRAPH_OVERVIEW_EDGE_LIMITS.temporaryMemoryBytes
  ) {
    throw new PermissionsGraphOverviewEdgeBuildError(
      "SAFETY_LIMIT_EXCEEDED",
      "Permissions graph edge planning exceeds the bounded model or memory guard.",
    );
  }
  if (
    input.layout.model !== input.model || input.layout.index !== input.index ||
    input.layout.topologyFingerprint !== input.model.topologyFingerprint ||
    input.model.edges.length !== input.model.edgeCount
  ) {
    throw new PermissionsGraphOverviewEdgeBuildError(
      "TOPOLOGY_MISMATCH",
      "Permissions graph edge planning inputs do not share one model/index/layout identity.",
    );
  }
  selectPermissionsGraphOverviewEdgeMode(input.projectedMedianSpacing, 0);
  if (!Number.isInteger(input.cameraRevision) || input.cameraRevision < 0 || input.cameraRevision > 0xffff_ffff) {
    throw new PermissionsGraphOverviewEdgeBuildError(
      "INVALID_CAMERA_METADATA",
      "Permissions graph camera revision must be an unsigned 32-bit integer.",
    );
  }
  if (input.visibleNodeMask && input.visibleNodeMask.length !== input.model.nodeCount) {
    throw new PermissionsGraphOverviewEdgeBuildError(
      "INVALID_MASK_LENGTH",
      "Permissions graph node visibility mask length does not match the model.",
    );
  }
  if (input.visibleEdgeMask && input.visibleEdgeMask.length !== input.model.edgeCount) {
    throw new PermissionsGraphOverviewEdgeBuildError(
      "INVALID_MASK_LENGTH",
      "Permissions graph edge visibility mask length does not match the model.",
    );
  }
  if (
    input.presentationPositions &&
    input.presentationPositions.length !== input.model.nodeCount * 2
  ) {
    throw new PermissionsGraphOverviewEdgeBuildError(
      "INVALID_PRESENTATION_POSITIONS",
      "Permissions graph presentation position length does not match the model.",
    );
  }
}

function buildPriorityRanks(
  state: PermissionsGraphOverviewEdgePriorityState | undefined,
  nodeCount: number,
): Map<number, number> {
  const ranks = new Map<number, number>();
  const lists: readonly [OrdinalList | undefined, number][] = [
    [state?.selected, 0],
    [state?.focused, 1],
    [state?.hovered, 2],
    [state?.search, 3],
    [state?.local, 4],
  ];
  for (const [values, rank] of lists) {
    if (!values) continue;
    for (const ordinal of values) {
      if (!Number.isInteger(ordinal) || ordinal < 0 || ordinal >= nodeCount) {
        throw new PermissionsGraphOverviewEdgeBuildError(
          "INVALID_ORDINAL",
          "Permissions graph priority state contains an invalid node ordinal.",
        );
      }
      const current = ranks.get(ordinal);
      if (current === undefined || rank < current) ranks.set(ordinal, rank);
    }
  }
  return ranks;
}

function takeFairStructuralSample(
  candidates: readonly EdgeCandidate[],
  limit: number,
): EdgeCandidate[] {
  const buckets = new Map<string, EdgeCandidate[]>();
  for (const candidate of candidates) {
    const key = `${candidate.kindCode}:${candidate.accessCode}`;
    const values = buckets.get(key);
    if (values) values.push(candidate);
    else buckets.set(key, [candidate]);
  }
  const ordered = Array.from(buckets.entries()).sort((left, right) =>
    left[0].localeCompare(right[0], "en")
  );
  for (const [, values] of ordered) values.sort(compareCandidates);
  const offsets = new Map(ordered.map(([key]) => [key, 0]));
  const result: EdgeCandidate[] = [];
  while (result.length < limit) {
    let added = false;
    for (const [key, values] of ordered) {
      const offset = offsets.get(key) ?? 0;
      const candidate = values[offset];
      if (!candidate) continue;
      result.push(candidate);
      offsets.set(key, offset + 1);
      added = true;
      if (result.length >= limit) break;
    }
    if (!added) break;
  }
  return result;
}

function buildBundleSegments(
  candidates: readonly EdgeCandidate[],
  density: boolean,
): { readonly segments: readonly OutputSegment[]; readonly representedEdgeCount: number } {
  const groups = new Map<string, BundleAccumulator>();
  for (const candidate of candidates) {
    const key = [
      Math.floor(candidate.x1 / BUNDLE_CELL_SIZE),
      Math.floor(candidate.y1 / BUNDLE_CELL_SIZE),
      Math.floor(candidate.x2 / BUNDLE_CELL_SIZE),
      Math.floor(candidate.y2 / BUNDLE_CELL_SIZE),
      candidate.kindCode,
      candidate.accessCode,
    ].join(":");
    const existing = groups.get(key);
    if (existing) {
      existing.count += 1;
      existing.x1 += candidate.x1;
      existing.y1 += candidate.y1;
      existing.x2 += candidate.x2;
      existing.y2 += candidate.y2;
    } else {
      groups.set(key, {
        key,
        hash: hashText(key),
        style: candidate.style,
        count: 1,
        x1: candidate.x1,
        y1: candidate.y1,
        x2: candidate.x2,
        y2: candidate.y2,
      });
    }
  }
  const selected = Array.from(groups.values())
    .sort((left, right) => left.hash - right.hash || left.key.localeCompare(right.key, "en"))
    .slice(0, PERMISSIONS_GRAPH_OVERVIEW_EDGE_LIMITS.bundleSegments);
  let representedEdgeCount = 0;
  const segments = selected.map((group): OutputSegment => {
    representedEdgeCount += group.count;
    return Object.freeze({
      x1: group.x1 / group.count,
      y1: group.y1 / group.count,
      x2: group.x2 / group.count,
      y2: group.y2 / group.count,
      style: group.style | PERMISSIONS_GRAPH_OVERVIEW_EDGE_STYLE_FLAG.bundle |
        (density ? PERMISSIONS_GRAPH_OVERVIEW_EDGE_STYLE_FLAG.density : 0),
      weight: group.count,
    });
  });
  return Object.freeze({ segments: Object.freeze(segments), representedEdgeCount });
}

function candidateSegment(candidate: EdgeCandidate, style: number): OutputSegment {
  return Object.freeze({
    x1: candidate.x1,
    y1: candidate.y1,
    x2: candidate.x2,
    y2: candidate.y2,
    style,
    weight: 1,
  });
}

function edgeKindCode(edge: PermissionsGraphEdgeRecord): number {
  switch (edge.kind) {
    case "permission": return 1;
    case "containment": return 2;
    case "membership": return 3;
    default: return 0;
  }
}

function edgeAccessCode(edge: PermissionsGraphEdgeRecord): number {
  switch (edge.level) {
    case "read": return 1;
    case "write": return 2;
    case "admin": return 3;
    default: return 0;
  }
}

function packEdgeStyle(kindCode: number, accessCode: number, expiring: boolean): number {
  return (kindCode & 0x7) | ((accessCode & 0x7) << 3) |
    (expiring ? PERMISSIONS_GRAPH_OVERVIEW_EDGE_STYLE_FLAG.expiring : 0);
}

function comparePriorityCandidates(left: EdgeCandidate, right: EdgeCandidate): number {
  return (left.priorityRank ?? Number.MAX_SAFE_INTEGER) -
      (right.priorityRank ?? Number.MAX_SAFE_INTEGER) ||
    compareCandidates(left, right);
}

function compareCandidates(left: EdgeCandidate, right: EdgeCandidate): number {
  return left.hash - right.hash || left.ordinal - right.ordinal;
}

function hashText(value: string): number {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

function fingerprintSnapshot(
  mode: PermissionsGraphOverviewEdgeMode,
  cameraRevision: number,
  eligibleEdgeCount: number,
  coordinates: Float32Array,
  styles: Uint32Array,
  weights: Float32Array,
): string {
  let hash = hashText(`${PERMISSIONS_GRAPH_OVERVIEW_EDGE_VERSION}:${mode}:${cameraRevision}:${eligibleEdgeCount}`);
  const update = (value: number) => {
    hash ^= value >>> 0;
    hash = Math.imul(hash, 0x01000193) >>> 0;
  };
  const floatBits = new Uint32Array(1);
  const floatValue = new Float32Array(floatBits.buffer);
  for (const value of coordinates) {
    floatValue[0] = value;
    update(floatBits[0] ?? 0);
  }
  for (const value of styles) update(value);
  for (const value of weights) {
    floatValue[0] = value;
    update(floatBits[0] ?? 0);
  }
  return `pge1-${hash.toString(16).padStart(8, "0")}`;
}

function checkCancellation(signal: AbortSignal | undefined): void {
  if (!signal?.aborted) return;
  throw new PermissionsGraphOverviewEdgeBuildError(
    "CANCELLED",
    "Permissions graph edge overview build was cancelled.",
  );
}
