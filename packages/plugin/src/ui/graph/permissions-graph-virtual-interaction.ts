/**
 * Pure Hybrid Phase D virtual-interaction contracts.
 *
 * This module owns no DOM, Cytoscape core, Obsidian runtime, cache, vault,
 * network, worker, or timer. The QA-only adapter translates events and owns
 * scheduling/lifecycle; these helpers validate identities and produce bounded
 * deterministic state, hit, materialization, and no-jump decisions.
 */

import {
  renderedToPermissionsGraphWorldPoint,
  worldToPermissionsGraphRenderedPoint,
  type PermissionsGraphCameraState,
  type PermissionsGraphPoint,
} from "./permissions-graph-camera";
import type { PermissionsGraphLayoutStore } from "./permissions-graph-layout";
import type {
  PermissionsGraphMaterializationBudget,
  PermissionsGraphPreviousActiveSlice,
} from "./permissions-graph-materialization";
import type { PermissionsGraphIndex, PermissionsGraphModel } from "./permissions-graph-model";
import {
  PERMISSIONS_GRAPH_OVERVIEW_DYNAMIC_FLAG,
  type PermissionsGraphOverviewBufferRange,
  type PermissionsGraphOverviewBuffers,
} from "./permissions-graph-overview-buffers";
import type { PermissionsGraphModelSliceSource } from "./permissions-graph-renderer";
import type {
  PermissionsGraphNearestNodeResult,
  PermissionsGraphSpatialIndex,
} from "./permissions-graph-spatial";

export const PERMISSIONS_GRAPH_VIRTUAL_INTERACTION_PHASE_D_MARKER =
  "vg-permissions-virtual-interaction-phase-d-v1";
export const DEFAULT_PERMISSIONS_GRAPH_VIRTUAL_HOVER_DELAY_MS = 60;
export const DEFAULT_PERMISSIONS_GRAPH_VIRTUAL_MOUSE_HIT_RADIUS = 8;
export const DEFAULT_PERMISSIONS_GRAPH_VIRTUAL_TOUCH_HIT_RADIUS = 12;
export const MIN_PERMISSIONS_GRAPH_VIRTUAL_HIT_RADIUS = 6;
export const MAX_PERMISSIONS_GRAPH_VIRTUAL_HIT_RADIUS = 16;
export const DEFAULT_PERMISSIONS_GRAPH_VIRTUAL_HYSTERESIS_RADIUS = 3;
export const DEFAULT_PERMISSIONS_GRAPH_NO_JUMP_TOLERANCE = 0.01;
export const DEFAULT_PERMISSIONS_GRAPH_VIRTUAL_NEIGHBOR_LIMIT = 12;
export const DEFAULT_PERMISSIONS_GRAPH_KEYBOARD_WINDOW = 256;

export type PermissionsGraphVirtualSelectionSource =
  | "none"
  | "pointer"
  | "keyboard"
  | "cytoscape"
  | "search";

export interface PermissionsGraphNumericStageBounds {
  readonly left: number;
  readonly top: number;
  readonly width: number;
  readonly height: number;
}

export type PermissionsGraphPointerKind = "mouse" | "pen" | "touch";

export interface PermissionsGraphInteractionIdentity {
  readonly topologyFingerprint: string;
  readonly layoutGeneration: number;
  readonly coordinateRevision: number;
  readonly spatialLayoutGeneration: number;
  readonly spatialCoordinateRevision: number;
  readonly overviewBufferFingerprint: string;
  readonly overviewTopologyFingerprint: string;
  readonly overviewLayoutGeneration: number;
  readonly overviewCoordinateRevision: number;
  readonly cameraRevision: number;
  readonly activeMaterializationRevision: number;
}

export interface PermissionsGraphVirtualInteractionState {
  readonly revision: number;
  readonly hoveredNodeId: string | null;
  readonly selectedNodeId: string | null;
  readonly keyboardTargetNodeId: string | null;
  readonly materializedNodeIds: readonly string[];
  readonly selectionSource: PermissionsGraphVirtualSelectionSource;
}

export type PermissionsGraphVirtualDiagnosticCode =
  | "INVALID_POINTER"
  | "INVALID_STAGE"
  | "STALE_TOPOLOGY"
  | "STALE_LAYOUT"
  | "STALE_SPATIAL_INDEX"
  | "STALE_OVERVIEW_BUFFERS"
  | "STALE_CAMERA"
  | "STALE_MATERIALIZATION"
  | "NO_HIT"
  | "UNKNOWN_NODE"
  | "NODE_BUDGET_ZERO"
  | "NO_JUMP_MISMATCH";

export interface PermissionsGraphVirtualDiagnostic {
  readonly code: PermissionsGraphVirtualDiagnosticCode;
  readonly message: string;
}

export interface PermissionsGraphPointerConversionResult {
  readonly ok: boolean;
  readonly renderedPoint: PermissionsGraphPoint | null;
  readonly worldPoint: PermissionsGraphPoint | null;
  readonly diagnostic: PermissionsGraphVirtualDiagnostic | null;
}

export interface PermissionsGraphVirtualHitOptions {
  readonly pointerKind?: PermissionsGraphPointerKind;
  readonly renderedHitRadius?: number;
  readonly minimumRenderedHitRadius?: number;
  readonly maximumRenderedHitRadius?: number;
  readonly includePointSize?: boolean;
}

export interface PermissionsGraphVirtualHitResult {
  readonly ok: boolean;
  readonly hit: PermissionsGraphNearestNodeResult | null;
  readonly worldPoint: PermissionsGraphPoint | null;
  readonly renderedHitRadius: number;
  readonly worldHitRadius: number;
  readonly identity: PermissionsGraphInteractionIdentity;
  readonly diagnostic: PermissionsGraphVirtualDiagnostic | null;
}

export interface PermissionsGraphVirtualActivationToken {
  readonly nodeId: string;
  readonly worldPoint: PermissionsGraphPoint;
  readonly identity: PermissionsGraphInteractionIdentity;
}

export interface PermissionsGraphVirtualMaterializationRequest {
  readonly selectedNodeId?: string | null;
  readonly keyboardTargetNodeId?: string | null;
  readonly hoveredNodeId?: string | null;
  readonly pinnedNodeIds?: readonly string[];
  readonly focusedNeighborhoodNodeIds?: readonly string[];
  readonly searchResultNodeIds?: readonly string[];
  readonly previous?: PermissionsGraphPreviousActiveSlice;
  readonly viewportNodeIds?: readonly string[];
  readonly maxNeighbors?: number;
  readonly budget: PermissionsGraphMaterializationBudget;
}

export interface PermissionsGraphVirtualMaterializationOmission {
  readonly id: string;
  readonly reason: string;
}

export interface PermissionsGraphVirtualMaterializationPlan {
  readonly sourceTopologyFingerprint: string;
  readonly layoutGeneration: number;
  readonly coordinateRevision: number;
  readonly budget: PermissionsGraphMaterializationBudget;
  readonly includedNodeIds: readonly string[];
  readonly includedEdgeIds: readonly string[];
  readonly omittedNodes: readonly PermissionsGraphVirtualMaterializationOmission[];
  readonly omittedEdges: readonly PermissionsGraphVirtualMaterializationOmission[];
  readonly source: PermissionsGraphModelSliceSource;
  readonly selectedNodeIncluded: boolean;
}

export interface PermissionsGraphOverviewDynamicPatchState {
  readonly selectedNodeId?: string | null;
  readonly keyboardTargetNodeId?: string | null;
  readonly hoveredNodeId?: string | null;
  readonly materializedNodeIds?: readonly string[];
  readonly searchResultNodeIds?: readonly string[];
  readonly dimmedNodeIds?: readonly string[];
  readonly suppressedNodeIds?: readonly string[];
}

export interface PermissionsGraphOverviewDynamicPatchResult {
  readonly buffers: PermissionsGraphOverviewBuffers;
  readonly changed: boolean;
  readonly changedOrdinals: readonly number[];
  readonly unknownNodeIds: readonly string[];
}

export interface PermissionsGraphNoJumpValidationInput {
  readonly nodeId: string;
  readonly index: PermissionsGraphIndex;
  readonly layout: PermissionsGraphLayoutStore;
  readonly overviewBuffers: PermissionsGraphOverviewBuffers;
  readonly camera: PermissionsGraphCameraState;
  readonly presetPosition: PermissionsGraphPoint;
  readonly tolerance?: number;
}

export interface PermissionsGraphNoJumpValidationResult {
  readonly ok: boolean;
  readonly nodeId: string;
  readonly worldDelta: number;
  readonly renderedDelta: number;
  readonly maximumDelta: number;
  readonly expectedRenderedPosition: PermissionsGraphPoint | null;
  readonly diagnostic: PermissionsGraphVirtualDiagnostic | null;
}

export function createPermissionsGraphVirtualInteractionState(
  input: Partial<PermissionsGraphVirtualInteractionState> = {},
): PermissionsGraphVirtualInteractionState {
  return freezeState({
    revision: normalizeRevision(input.revision ?? 0),
    hoveredNodeId: normalizeId(input.hoveredNodeId),
    selectedNodeId: normalizeId(input.selectedNodeId),
    keyboardTargetNodeId: normalizeId(input.keyboardTargetNodeId),
    materializedNodeIds: freezeSortedIds(input.materializedNodeIds ?? []),
    selectionSource: input.selectionSource ?? "none",
  });
}

export function updatePermissionsGraphVirtualInteractionState(
  state: PermissionsGraphVirtualInteractionState,
  patch: Partial<Omit<PermissionsGraphVirtualInteractionState, "revision">>,
): PermissionsGraphVirtualInteractionState {
  const next = {
    revision: state.revision,
    hoveredNodeId: "hoveredNodeId" in patch ? normalizeId(patch.hoveredNodeId) : state.hoveredNodeId,
    selectedNodeId: "selectedNodeId" in patch ? normalizeId(patch.selectedNodeId) : state.selectedNodeId,
    keyboardTargetNodeId: "keyboardTargetNodeId" in patch
      ? normalizeId(patch.keyboardTargetNodeId)
      : state.keyboardTargetNodeId,
    materializedNodeIds: "materializedNodeIds" in patch
      ? freezeSortedIds(patch.materializedNodeIds ?? [])
      : state.materializedNodeIds,
    selectionSource: patch.selectionSource ?? state.selectionSource,
  };
  if (
    next.hoveredNodeId === state.hoveredNodeId &&
    next.selectedNodeId === state.selectedNodeId &&
    next.keyboardTargetNodeId === state.keyboardTargetNodeId &&
    next.selectionSource === state.selectionSource &&
    arraysEqual(next.materializedNodeIds, state.materializedNodeIds)
  ) return state;
  return freezeState({ ...next, revision: incrementRevision(state.revision) });
}

export function clearPermissionsGraphVirtualTransientState(
  state: PermissionsGraphVirtualInteractionState,
): PermissionsGraphVirtualInteractionState {
  return updatePermissionsGraphVirtualInteractionState(state, {
    hoveredNodeId: null,
    keyboardTargetNodeId: null,
  });
}

export function clientToPermissionsGraphStageRenderedPoint(
  clientPoint: PermissionsGraphPoint,
  stage: PermissionsGraphNumericStageBounds,
): PermissionsGraphPointerConversionResult {
  if (!finitePoint(clientPoint)) return failedConversion("INVALID_POINTER", "Pointer coordinates must be finite.");
  if (!validStage(stage)) {
    return failedConversion("INVALID_STAGE", "Graph-stage bounds must be finite and have positive size.");
  }
  const renderedPoint = Object.freeze({
    x: normalizeZero(clientPoint.x - stage.left),
    y: normalizeZero(clientPoint.y - stage.top),
  });
  return Object.freeze({ ok: true, renderedPoint, worldPoint: null, diagnostic: null });
}

export function clientToPermissionsGraphWorldPoint(
  clientPoint: PermissionsGraphPoint,
  stage: PermissionsGraphNumericStageBounds,
  camera: PermissionsGraphCameraState,
): PermissionsGraphPointerConversionResult {
  const rendered = clientToPermissionsGraphStageRenderedPoint(clientPoint, stage);
  if (!rendered.ok || !rendered.renderedPoint) return rendered;
  try {
    const worldPoint = renderedToPermissionsGraphWorldPoint(rendered.renderedPoint, camera);
    return Object.freeze({ ...rendered, worldPoint });
  } catch {
    return failedConversion("INVALID_POINTER", "Pointer-to-world conversion failed safely.");
  }
}

export function capturePermissionsGraphInteractionIdentity(input: {
  readonly model: PermissionsGraphModel;
  readonly layout: PermissionsGraphLayoutStore;
  readonly spatial: PermissionsGraphSpatialIndex;
  readonly overviewBuffers: PermissionsGraphOverviewBuffers;
  readonly camera: PermissionsGraphCameraState;
  readonly activeMaterializationRevision: number;
}): PermissionsGraphInteractionIdentity {
  return Object.freeze({
    topologyFingerprint: input.model.topologyFingerprint,
    layoutGeneration: input.layout.layoutGeneration,
    coordinateRevision: input.layout.coordinateRevision,
    spatialLayoutGeneration: input.spatial.layoutGeneration,
    spatialCoordinateRevision: input.spatial.coordinateRevision,
    overviewBufferFingerprint: input.overviewBuffers.bufferFingerprint,
    overviewTopologyFingerprint: input.overviewBuffers.topologyFingerprint,
    overviewLayoutGeneration: input.overviewBuffers.layoutGeneration,
    overviewCoordinateRevision: input.overviewBuffers.coordinateRevision,
    cameraRevision: input.camera.revision,
    activeMaterializationRevision: normalizeRevision(input.activeMaterializationRevision),
  });
}

export function validatePermissionsGraphInteractionIdentity(input: {
  readonly expected: PermissionsGraphInteractionIdentity;
  readonly current: PermissionsGraphInteractionIdentity;
  readonly requireCamera?: boolean;
  readonly requireMaterialization?: boolean;
}): PermissionsGraphVirtualDiagnostic | null {
  const { expected, current } = input;
  if (expected.topologyFingerprint !== current.topologyFingerprint) {
    return diagnostic("STALE_TOPOLOGY", "Interaction topology changed before activation.");
  }
  if (
    expected.layoutGeneration !== current.layoutGeneration ||
    expected.coordinateRevision !== current.coordinateRevision
  ) return diagnostic("STALE_LAYOUT", "Interaction layout changed before activation.");
  if (
    current.spatialLayoutGeneration !== current.layoutGeneration ||
    current.spatialCoordinateRevision !== current.coordinateRevision ||
    expected.spatialLayoutGeneration !== current.spatialLayoutGeneration ||
    expected.spatialCoordinateRevision !== current.spatialCoordinateRevision
  ) return diagnostic("STALE_SPATIAL_INDEX", "Spatial index revision is stale.");
  if (
    current.overviewTopologyFingerprint !== current.topologyFingerprint ||
    current.overviewLayoutGeneration !== current.layoutGeneration ||
    current.overviewCoordinateRevision !== current.coordinateRevision ||
    expected.overviewBufferFingerprint !== current.overviewBufferFingerprint
  ) return diagnostic("STALE_OVERVIEW_BUFFERS", "Overview buffer identity is stale.");
  if (input.requireCamera !== false && expected.cameraRevision !== current.cameraRevision) {
    return diagnostic("STALE_CAMERA", "Camera revision changed before activation.");
  }
  if (
    input.requireMaterialization !== false &&
    expected.activeMaterializationRevision !== current.activeMaterializationRevision
  ) return diagnostic("STALE_MATERIALIZATION", "Active materialization changed before activation.");
  return null;
}

export function hitTestPermissionsGraphVirtualNode(input: {
  readonly model: PermissionsGraphModel;
  readonly index: PermissionsGraphIndex;
  readonly layout: PermissionsGraphLayoutStore;
  readonly spatial: PermissionsGraphSpatialIndex;
  readonly overviewBuffers: PermissionsGraphOverviewBuffers;
  readonly camera: PermissionsGraphCameraState;
  readonly activeMaterializationRevision: number;
  readonly renderedPoint: PermissionsGraphPoint;
  readonly options?: PermissionsGraphVirtualHitOptions;
}): PermissionsGraphVirtualHitResult {
  const identity = capturePermissionsGraphInteractionIdentity(input);
  const stale = validateCurrentIdentities(input, identity);
  const radii = hitRadii(input.options, input.camera.zoom, 0);
  if (stale) return failedHit(identity, radii.rendered, radii.world, stale);
  if (!finitePoint(input.renderedPoint)) {
    return failedHit(
      identity,
      radii.rendered,
      radii.world,
      diagnostic("INVALID_POINTER", "Rendered pointer coordinates must be finite."),
    );
  }

  let worldPoint: PermissionsGraphPoint;
  try {
    worldPoint = renderedToPermissionsGraphWorldPoint(input.renderedPoint, input.camera);
  } catch {
    return failedHit(
      identity,
      radii.rendered,
      radii.world,
      diagnostic("INVALID_POINTER", "Rendered pointer conversion failed safely."),
    );
  }

  const maximumPointRadius = input.options?.includePointSize === false
    ? 0
    : maxPointRadius(input.overviewBuffers.pointSizes);
  const queryRadii = hitRadii(input.options, input.camera.zoom, maximumPointRadius);
  const candidate = input.spatial.nearest(worldPoint, queryRadii.world);
  if (!candidate) {
    return Object.freeze({
      ok: true,
      hit: null,
      worldPoint,
      renderedHitRadius: queryRadii.rendered,
      worldHitRadius: queryRadii.world,
      identity,
      diagnostic: diagnostic("NO_HIT", "No virtual node is inside the bounded hit radius."),
    });
  }
  const pointRadius = input.options?.includePointSize === false
    ? 0
    : (input.overviewBuffers.pointSizes[candidate.ordinal] ?? 0) / 2;
  const exactRadii = hitRadii(input.options, input.camera.zoom, pointRadius);
  if (candidate.distance > exactRadii.world) {
    return Object.freeze({
      ok: true,
      hit: null,
      worldPoint,
      renderedHitRadius: exactRadii.rendered,
      worldHitRadius: exactRadii.world,
      identity,
      diagnostic: diagnostic("NO_HIT", "Nearest node is outside its exact hit radius."),
    });
  }
  if (!input.index.getNode(candidate.nodeId)) {
    return failedHit(
      identity,
      exactRadii.rendered,
      exactRadii.world,
      diagnostic("UNKNOWN_NODE", "Spatial hit does not exist in the current model index."),
      worldPoint,
    );
  }
  return Object.freeze({
    ok: true,
    hit: candidate,
    worldPoint,
    renderedHitRadius: exactRadii.rendered,
    worldHitRadius: exactRadii.world,
    identity,
    diagnostic: null,
  });
}

export function createPermissionsGraphVirtualActivationToken(
  hit: PermissionsGraphVirtualHitResult,
): PermissionsGraphVirtualActivationToken | null {
  if (!hit.ok || !hit.hit || !hit.worldPoint) return null;
  return Object.freeze({ nodeId: hit.hit.nodeId, worldPoint: hit.worldPoint, identity: hit.identity });
}

export function validatePermissionsGraphVirtualActivationToken(input: {
  readonly token: PermissionsGraphVirtualActivationToken;
  readonly currentIdentity: PermissionsGraphInteractionIdentity;
}): PermissionsGraphVirtualDiagnostic | null {
  return validatePermissionsGraphInteractionIdentity({
    expected: input.token.identity,
    current: input.currentIdentity,
  });
}

export function planPermissionsGraphVirtualPriorityMaterialization(input: {
  readonly model: PermissionsGraphModel;
  readonly index: PermissionsGraphIndex;
  readonly layout: PermissionsGraphLayoutStore;
  readonly request: PermissionsGraphVirtualMaterializationRequest;
}): PermissionsGraphVirtualMaterializationPlan {
  const budget = Object.freeze({
    maxNodes: normalizedBudget(input.request.budget.maxNodes),
    maxEdges: normalizedBudget(input.request.budget.maxEdges),
  });
  const candidates: Array<{ id: string; reason: string }> = [];
  const add = (ids: Iterable<string>, reason: string) => {
    for (const id of ids) if (normalizeId(id)) candidates.push({ id, reason });
  };
  add(single(input.request.selectedNodeId), "selected");
  add(single(input.request.keyboardTargetNodeId), "keyboard-focused");
  add(single(input.request.hoveredNodeId), "hovered");
  add(input.request.pinnedNodeIds ?? [], "pinned");
  add(input.request.focusedNeighborhoodNodeIds ?? [], "focused-neighborhood");
  add(input.request.searchResultNodeIds ?? [], "search-result");
  add(input.request.previous?.nodeIds ?? [], "retained-active");
  add(input.request.viewportNodeIds ?? [], "viewport");

  const targetSeeds = uniqueIds([
    ...single(input.request.selectedNodeId),
    ...single(input.request.keyboardTargetNodeId),
    ...single(input.request.hoveredNodeId),
  ]);
  const neighborLimit = Math.min(
    DEFAULT_PERMISSIONS_GRAPH_VIRTUAL_NEIGHBOR_LIMIT,
    normalizedBudget(input.request.maxNeighbors ?? DEFAULT_PERMISSIONS_GRAPH_VIRTUAL_NEIGHBOR_LIMIT),
  );
  for (const seed of targetSeeds) {
    add(input.index.getAdjacentNodeIds(seed).slice(0, neighborLimit), "priority-neighbor");
  }

  const seen = new Set<string>();
  const included: Array<{ id: string; reason: string }> = [];
  const omittedNodes: PermissionsGraphVirtualMaterializationOmission[] = [];
  for (const candidate of candidates) {
    if (seen.has(candidate.id)) continue;
    seen.add(candidate.id);
    if (!input.index.getNode(candidate.id)) {
      omittedNodes.push(Object.freeze({ id: candidate.id, reason: "unknown-node" }));
      continue;
    }
    if (included.length >= budget.maxNodes) {
      omittedNodes.push(Object.freeze({ id: candidate.id, reason: "node-budget" }));
      continue;
    }
    included.push(candidate);
  }

  const includedNodeSet = new Set(included.map((entry) => entry.id));
  const previousEdgeIds = new Set(input.request.previous?.edgeIds ?? []);
  const candidateEdges = input.model.edges
    .filter((edge) => includedNodeSet.has(edge.sourceId) && includedNodeSet.has(edge.targetId))
    .sort((left, right) =>
      Number(!previousEdgeIds.has(left.id)) - Number(!previousEdgeIds.has(right.id)) ||
      edgePriority(left.kind) - edgePriority(right.kind) ||
      compareStrings(left.id, right.id)
    );
  const includedEdges = candidateEdges.slice(0, budget.maxEdges);
  const omittedEdges = candidateEdges.slice(includedEdges.length).map((edge) =>
    Object.freeze({ id: edge.id, reason: "edge-budget" })
  );
  const includedNodeIds = freezeSortedIds(included.map((entry) => entry.id));
  const includedEdgeIds = freezeSortedIds(includedEdges.map((edge) => edge.id));
  const source = Object.freeze({
    kind: "model-slice" as const,
    nodeIds: includedNodeIds,
    edgeIds: includedEdgeIds,
    budget,
  });
  const selectedId = normalizeId(input.request.selectedNodeId);
  return Object.freeze({
    sourceTopologyFingerprint: input.model.topologyFingerprint,
    layoutGeneration: input.layout.layoutGeneration,
    coordinateRevision: input.layout.coordinateRevision,
    budget,
    includedNodeIds,
    includedEdgeIds,
    omittedNodes: Object.freeze(sortOmissions(omittedNodes)),
    omittedEdges: Object.freeze(sortOmissions(omittedEdges)),
    source,
    selectedNodeIncluded: selectedId === null || includedNodeSet.has(selectedId),
  });
}

export function patchPermissionsGraphOverviewDynamicFlags(input: {
  readonly buffers: PermissionsGraphOverviewBuffers;
  readonly index: PermissionsGraphIndex;
  readonly state: PermissionsGraphOverviewDynamicPatchState;
  readonly revision: number;
}): PermissionsGraphOverviewDynamicPatchResult {
  const flags = new Uint8Array(input.buffers.nodeCount);
  const unknown = new Set<string>();
  const apply = (ids: Iterable<string>, flag: number) => {
    for (const id of ids) {
      const ordinal = input.index.getNodeOrdinal(id);
      if (ordinal === undefined || ordinal >= flags.length) unknown.add(id);
      else flags[ordinal] |= flag;
    }
  };
  apply(single(input.state.selectedNodeId), PERMISSIONS_GRAPH_OVERVIEW_DYNAMIC_FLAG.selected);
  apply(single(input.state.keyboardTargetNodeId), PERMISSIONS_GRAPH_OVERVIEW_DYNAMIC_FLAG.focused);
  apply(single(input.state.hoveredNodeId), PERMISSIONS_GRAPH_OVERVIEW_DYNAMIC_FLAG.hovered);
  apply(input.state.searchResultNodeIds ?? [], PERMISSIONS_GRAPH_OVERVIEW_DYNAMIC_FLAG.searchMatch);
  apply(input.state.materializedNodeIds ?? [], PERMISSIONS_GRAPH_OVERVIEW_DYNAMIC_FLAG.materialized);
  apply(input.state.dimmedNodeIds ?? [], PERMISSIONS_GRAPH_OVERVIEW_DYNAMIC_FLAG.dimmed);
  apply(
    input.state.suppressedNodeIds ?? [],
    PERMISSIONS_GRAPH_OVERVIEW_DYNAMIC_FLAG.dragSuppressed,
  );

  const previous = input.buffers.dynamicFlags ?? new Uint8Array(input.buffers.nodeCount);
  const changedOrdinals: number[] = [];
  for (let ordinal = 0; ordinal < flags.length; ordinal += 1) {
    if (flags[ordinal] !== previous[ordinal]) changedOrdinals.push(ordinal);
  }
  if (changedOrdinals.length === 0) {
    return Object.freeze({
      buffers: input.buffers,
      changed: false,
      changedOrdinals: Object.freeze([] as number[]),
      unknownNodeIds: freezeSortedIds(unknown),
    });
  }

  const dynamicRanges = coalesceOrdinals(changedOrdinals);
  const coordinatesPending = input.buffers.update.kind === "coordinates";
  const ranges = coordinatesPending
    ? mergeBufferRanges(input.buffers.update.ranges, dynamicRanges)
    : dynamicRanges;
  const revision = normalizeRevision(input.revision);
  const fingerprint = fingerprintDynamicFlags(flags);
  const addedBytes = input.buffers.dynamicFlags ? 0 : flags.byteLength;
  const memory = addedBytes === 0 ? input.buffers.memory : Object.freeze({
    ...input.buffers.memory,
    dynamicFlagsBytes: flags.byteLength,
    totalOwnedBytes: input.buffers.memory.totalOwnedBytes + addedBytes,
    combinedLogicalBytes: input.buffers.memory.combinedLogicalBytes + addedBytes,
    expectedGpuMirrorBytes: input.buffers.memory.expectedGpuMirrorBytes + addedBytes,
    bytesPerNode: input.buffers.nodeCount === 0
      ? 0
      : (input.buffers.memory.totalOwnedBytes + addedBytes) / input.buffers.nodeCount,
  });
  const buffers: PermissionsGraphOverviewBuffers = Object.freeze({
    ...input.buffers,
    dynamicStateRevision: revision,
    dynamicFlags: flags,
    memory,
    invalidationKey: `${input.buffers.invalidationKey}:d${revision}`,
    bufferFingerprint: `${input.buffers.bufferFingerprint}:d${revision}:${fingerprint}`,
    update: Object.freeze({
      kind: coordinatesPending ? "coordinates" as const : "dynamic" as const,
      ranges,
    }),
  });
  return Object.freeze({
    buffers,
    changed: true,
    changedOrdinals: Object.freeze(changedOrdinals),
    unknownNodeIds: freezeSortedIds(unknown),
  });
}

export function validatePermissionsGraphNoJumpHandoff(
  input: PermissionsGraphNoJumpValidationInput,
): PermissionsGraphNoJumpValidationResult {
  const ordinal = input.index.getNodeOrdinal(input.nodeId);
  const layoutPoint = input.layout.getPosition(input.nodeId);
  const tolerance = Number.isFinite(input.tolerance)
    ? Math.max(0, input.tolerance ?? DEFAULT_PERMISSIONS_GRAPH_NO_JUMP_TOLERANCE)
    : DEFAULT_PERMISSIONS_GRAPH_NO_JUMP_TOLERANCE;
  if (ordinal === undefined || !layoutPoint || ordinal >= input.overviewBuffers.nodeCount) {
    return noJumpFailure(input.nodeId, "UNKNOWN_NODE", "No-jump validation could not resolve the node.");
  }
  if (
    input.overviewBuffers.topologyFingerprint !== input.layout.topologyFingerprint ||
    input.overviewBuffers.layoutGeneration !== input.layout.layoutGeneration ||
    input.overviewBuffers.coordinateRevision !== input.layout.coordinateRevision
  ) {
    return noJumpFailure(
      input.nodeId,
      "STALE_OVERVIEW_BUFFERS",
      "No-jump validation rejected stale overview coordinates.",
    );
  }
  const overviewPoint = {
    x: input.overviewBuffers.positions[ordinal * 2] ?? Number.NaN,
    y: input.overviewBuffers.positions[ordinal * 2 + 1] ?? Number.NaN,
  };
  if (!finitePoint(overviewPoint) || !finitePoint(input.presetPosition)) {
    return noJumpFailure(input.nodeId, "NO_JUMP_MISMATCH", "No-jump coordinates are invalid.");
  }
  const expectedRenderedPosition = worldToPermissionsGraphRenderedPoint(layoutPoint, input.camera);
  const overviewRendered = worldToPermissionsGraphRenderedPoint(overviewPoint, input.camera);
  const presetRendered = worldToPermissionsGraphRenderedPoint(input.presetPosition, input.camera);
  const worldDelta = Math.max(distance(layoutPoint, overviewPoint), distance(layoutPoint, input.presetPosition));
  const renderedDelta = Math.max(
    distance(expectedRenderedPosition, overviewRendered),
    distance(expectedRenderedPosition, presetRendered),
  );
  const maximumDelta = Math.max(worldDelta, renderedDelta);
  const ok = maximumDelta <= tolerance;
  return Object.freeze({
    ok,
    nodeId: input.nodeId,
    worldDelta,
    renderedDelta,
    maximumDelta,
    expectedRenderedPosition,
    diagnostic: ok ? null : diagnostic("NO_JUMP_MISMATCH", "No-jump tolerance was exceeded."),
  });
}

export function navigatePermissionsGraphVirtualOrdinal(input: {
  readonly model: PermissionsGraphModel;
  readonly index: PermissionsGraphIndex;
  readonly currentNodeId?: string | null;
  readonly direction: "next" | "previous";
  readonly windowSize?: number;
}): string | null {
  if (input.model.nodeCount === 0) return null;
  const current = input.currentNodeId ? input.index.getNodeOrdinal(input.currentNodeId) : undefined;
  const windowSize = Math.max(1, Math.min(
    DEFAULT_PERMISSIONS_GRAPH_KEYBOARD_WINDOW,
    normalizedBudget(input.windowSize ?? DEFAULT_PERMISSIONS_GRAPH_KEYBOARD_WINDOW),
  ));
  const step = input.direction === "next" ? 1 : -1;
  let ordinal = current ?? (step > 0 ? -1 : 0);
  for (let offset = 0; offset < Math.min(windowSize, input.model.nodeCount); offset += 1) {
    ordinal = (ordinal + step + input.model.nodeCount) % input.model.nodeCount;
    const node = input.model.nodes[ordinal];
    if (node) return node.id;
  }
  return null;
}

function validateCurrentIdentities(
  input: {
    readonly model: PermissionsGraphModel;
    readonly layout: PermissionsGraphLayoutStore;
    readonly spatial: PermissionsGraphSpatialIndex;
    readonly overviewBuffers: PermissionsGraphOverviewBuffers;
  },
  identity: PermissionsGraphInteractionIdentity,
): PermissionsGraphVirtualDiagnostic | null {
  if (input.layout.topologyFingerprint !== input.model.topologyFingerprint) {
    return diagnostic("STALE_TOPOLOGY", "Layout topology does not match the model.");
  }
  if (input.spatial.layout !== input.layout || input.spatial.isStale) {
    return diagnostic("STALE_SPATIAL_INDEX", "Spatial index must be rebuilt before hit-testing.");
  }
  if (
    identity.overviewTopologyFingerprint !== identity.topologyFingerprint ||
    identity.overviewLayoutGeneration !== identity.layoutGeneration ||
    identity.overviewCoordinateRevision !== identity.coordinateRevision
  ) return diagnostic("STALE_OVERVIEW_BUFFERS", "Overview buffers do not match the current layout.");
  return null;
}

function hitRadii(
  options: PermissionsGraphVirtualHitOptions | undefined,
  zoom: number,
  pointRadius: number,
): { readonly rendered: number; readonly world: number } {
  const minimum = finiteClamp(
    options?.minimumRenderedHitRadius ?? MIN_PERMISSIONS_GRAPH_VIRTUAL_HIT_RADIUS,
    0,
    MAX_PERMISSIONS_GRAPH_VIRTUAL_HIT_RADIUS,
  );
  const maximum = finiteClamp(
    options?.maximumRenderedHitRadius ?? MAX_PERMISSIONS_GRAPH_VIRTUAL_HIT_RADIUS,
    Math.max(0, minimum),
    MAX_PERMISSIONS_GRAPH_VIRTUAL_HIT_RADIUS,
  );
  const defaultRadius = options?.pointerKind === "touch" || options?.pointerKind === "pen"
    ? DEFAULT_PERMISSIONS_GRAPH_VIRTUAL_TOUCH_HIT_RADIUS
    : DEFAULT_PERMISSIONS_GRAPH_VIRTUAL_MOUSE_HIT_RADIUS;
  const requested = Number.isFinite(options?.renderedHitRadius)
    ? options?.renderedHitRadius ?? defaultRadius
    : defaultRadius;
  const rendered = Math.min(maximum, Math.max(minimum, requested, pointRadius));
  return Object.freeze({ rendered, world: rendered / zoom });
}

function maxPointRadius(pointSizes: Float32Array): number {
  let maximum = 0;
  for (const size of pointSizes) if (Number.isFinite(size)) maximum = Math.max(maximum, size / 2);
  return maximum;
}

function failedConversion(
  code: PermissionsGraphVirtualDiagnosticCode,
  message: string,
): PermissionsGraphPointerConversionResult {
  return Object.freeze({ ok: false, renderedPoint: null, worldPoint: null, diagnostic: diagnostic(code, message) });
}

function failedHit(
  identity: PermissionsGraphInteractionIdentity,
  renderedHitRadius: number,
  worldHitRadius: number,
  failure: PermissionsGraphVirtualDiagnostic,
  worldPoint: PermissionsGraphPoint | null = null,
): PermissionsGraphVirtualHitResult {
  return Object.freeze({
    ok: false,
    hit: null,
    worldPoint,
    renderedHitRadius,
    worldHitRadius,
    identity,
    diagnostic: failure,
  });
}

function noJumpFailure(
  nodeId: string,
  code: PermissionsGraphVirtualDiagnosticCode,
  message: string,
): PermissionsGraphNoJumpValidationResult {
  return Object.freeze({
    ok: false,
    nodeId,
    worldDelta: Number.POSITIVE_INFINITY,
    renderedDelta: Number.POSITIVE_INFINITY,
    maximumDelta: Number.POSITIVE_INFINITY,
    expectedRenderedPosition: null,
    diagnostic: diagnostic(code, message),
  });
}

function coalesceOrdinals(ordinals: readonly number[]): readonly PermissionsGraphOverviewBufferRange[] {
  if (ordinals.length === 0) return Object.freeze([] as PermissionsGraphOverviewBufferRange[]);
  const ranges: PermissionsGraphOverviewBufferRange[] = [];
  let start = ordinals[0] ?? 0;
  let previous = start;
  for (const ordinal of ordinals.slice(1)) {
    if (ordinal === previous + 1) {
      previous = ordinal;
      continue;
    }
    ranges.push(Object.freeze({ startOrdinal: start, endOrdinalExclusive: previous + 1 }));
    start = ordinal;
    previous = ordinal;
  }
  ranges.push(Object.freeze({ startOrdinal: start, endOrdinalExclusive: previous + 1 }));
  return Object.freeze(ranges);
}

function mergeBufferRanges(
  left: readonly PermissionsGraphOverviewBufferRange[],
  right: readonly PermissionsGraphOverviewBufferRange[],
): readonly PermissionsGraphOverviewBufferRange[] {
  const ordered = [...left, ...right].sort((a, b) =>
    a.startOrdinal - b.startOrdinal || a.endOrdinalExclusive - b.endOrdinalExclusive
  );
  if (ordered.length === 0) return Object.freeze([] as PermissionsGraphOverviewBufferRange[]);
  const merged: PermissionsGraphOverviewBufferRange[] = [];
  let start = ordered[0]!.startOrdinal;
  let end = ordered[0]!.endOrdinalExclusive;
  for (let index = 1; index < ordered.length; index += 1) {
    const range = ordered[index]!;
    if (range.startOrdinal <= end) {
      end = Math.max(end, range.endOrdinalExclusive);
      continue;
    }
    merged.push(Object.freeze({ startOrdinal: start, endOrdinalExclusive: end }));
    start = range.startOrdinal;
    end = range.endOrdinalExclusive;
  }
  merged.push(Object.freeze({ startOrdinal: start, endOrdinalExclusive: end }));
  return Object.freeze(merged);
}

function fingerprintDynamicFlags(flags: Uint8Array): string {
  let hash = 0x811c9dc5;
  for (const flag of flags) {
    hash ^= flag;
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, "0");
}

function diagnostic(
  code: PermissionsGraphVirtualDiagnosticCode,
  message: string,
): PermissionsGraphVirtualDiagnostic {
  return Object.freeze({ code, message });
}

function freezeState(state: PermissionsGraphVirtualInteractionState): PermissionsGraphVirtualInteractionState {
  return Object.freeze({ ...state, materializedNodeIds: freezeSortedIds(state.materializedNodeIds) });
}

function normalizeId(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function single(value: unknown): readonly string[] {
  const id = normalizeId(value);
  return id ? [id] : [];
}

function uniqueIds(values: Iterable<string>): string[] {
  return Array.from(new Set(values));
}

function freezeSortedIds(values: Iterable<string>): readonly string[] {
  return Object.freeze(uniqueIds(values).sort(compareStrings));
}

function sortOmissions(
  values: readonly PermissionsGraphVirtualMaterializationOmission[],
): PermissionsGraphVirtualMaterializationOmission[] {
  const unique = new Map<string, PermissionsGraphVirtualMaterializationOmission>();
  for (const value of values) unique.set(`${value.id}\0${value.reason}`, value);
  return Array.from(unique.values()).sort((left, right) =>
    compareStrings(left.id, right.id) || compareStrings(left.reason, right.reason)
  );
}

function arraysEqual(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function finitePoint(point: PermissionsGraphPoint): boolean {
  return !!point && Number.isFinite(point.x) && Number.isFinite(point.y);
}

function validStage(stage: PermissionsGraphNumericStageBounds): boolean {
  return !!stage && [stage.left, stage.top, stage.width, stage.height].every(Number.isFinite) &&
    stage.width > 0 && stage.height > 0;
}

function distance(left: PermissionsGraphPoint, right: PermissionsGraphPoint): number {
  return Math.hypot(left.x - right.x, left.y - right.y);
}

function finiteClamp(value: number, minimum: number, maximum: number): number {
  return Number.isFinite(value) ? Math.min(maximum, Math.max(minimum, value)) : minimum;
}

function normalizedBudget(value: number): number {
  return Number.isFinite(value) ? Math.max(0, Math.floor(value)) : 0;
}

function edgePriority(kind: string): number {
  return kind === "containment" ? 0 : kind === "permission" ? 1 : 2;
}

function normalizeRevision(value: number): number {
  return Number.isFinite(value) ? Math.max(0, Math.floor(value)) >>> 0 : 0;
}

function incrementRevision(value: number): number {
  return value === 0xffff_ffff ? 0 : value + 1;
}

function normalizeZero(value: number): number {
  return Object.is(value, -0) ? 0 : value;
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
