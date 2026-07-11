/**
 * Inert Phase 4 bridge from the renderer-independent permissions graph to a
 * bounded Cytoscape active slice.
 *
 * This module is intentionally not imported by PermissionsGraphView or plugin
 * runtime wiring. The only stateful entry point is explicitly QA-named; the
 * current live graph and Auto behavior remain on the legacy renderer path.
 */

import type cytoscape from "cytoscape";

import {
  permissionsGraphAggregatePlanToElements,
  type PermissionsGraphAggregatePlan,
} from "./permissions-graph-budget";
import type { GraphElement } from "./permissions-graph-data";
import type {
  PermissionsGraphCoordinate,
  PermissionsGraphLayoutStore,
} from "./permissions-graph-layout";
import type {
  PermissionsGraphEdgeRecord,
  PermissionsGraphIndex,
  PermissionsGraphModel,
  PermissionsGraphNodeRecord,
} from "./permissions-graph-model";

export interface PermissionsGraphActiveBudget {
  readonly maxNodes: number;
  readonly maxEdges: number;
}

export interface PermissionsGraphModelSliceSource {
  readonly kind: "model-slice";
  readonly nodeIds: readonly string[];
  readonly edgeIds: readonly string[];
  readonly budget: PermissionsGraphActiveBudget;
}

export interface PermissionsGraphAggregateSliceSource {
  readonly kind: "aggregate-plan";
  readonly plan: PermissionsGraphAggregatePlan;
}

export type PermissionsGraphActiveSliceSource =
  | PermissionsGraphModelSliceSource
  | PermissionsGraphAggregateSliceSource;

export interface PermissionsGraphSelectionRequest {
  readonly nodeIds?: readonly string[];
  readonly edgeIds?: readonly string[];
}

export interface PermissionsGraphActiveSliceBuildInput {
  readonly model: PermissionsGraphModel;
  readonly index: PermissionsGraphIndex;
  readonly layout: PermissionsGraphLayoutStore;
  readonly source: PermissionsGraphActiveSliceSource;
  readonly selection?: PermissionsGraphSelectionRequest;
}

export type PermissionsGraphActiveSliceOmissionReason =
  | "unknown-node"
  | "unknown-edge"
  | "node-budget"
  | "edge-budget"
  | "dangling-edge";

export interface PermissionsGraphActiveSliceOmission {
  readonly id: string;
  readonly reason: PermissionsGraphActiveSliceOmissionReason;
}

export interface PermissionsGraphActiveNodeElement {
  readonly group: "nodes";
  readonly data: Readonly<Record<string, unknown>> & { readonly id: string };
  readonly classes: string;
  readonly position: PermissionsGraphCoordinate;
}

export interface PermissionsGraphActiveEdgeElement {
  readonly group: "edges";
  readonly data: Readonly<Record<string, unknown>> & {
    readonly id: string;
    readonly source: string;
    readonly target: string;
  };
  readonly classes: string;
}

export type PermissionsGraphActiveElement =
  | PermissionsGraphActiveNodeElement
  | PermissionsGraphActiveEdgeElement;

export interface PermissionsGraphRequestedSelection {
  readonly nodeIds: readonly string[];
  readonly edgeIds: readonly string[];
}

export interface PermissionsGraphActiveSlice {
  readonly sourceKind: PermissionsGraphActiveSliceSource["kind"];
  readonly sourceTopologyFingerprint: string;
  readonly layoutGeneration: number;
  readonly coordinateRevision: number;
  readonly budget: PermissionsGraphActiveBudget;
  readonly nodes: readonly PermissionsGraphActiveNodeElement[];
  readonly edges: readonly PermissionsGraphActiveEdgeElement[];
  readonly elements: readonly PermissionsGraphActiveElement[];
  readonly materializedNodeIds: readonly string[];
  readonly materializedEdgeIds: readonly string[];
  readonly requestedSelection: PermissionsGraphRequestedSelection | null;
  readonly fallbackPositionNodeIds: readonly string[];
  readonly omissions: readonly PermissionsGraphActiveSliceOmission[];
}

export type PermissionsGraphRendererCompatibilityErrorCode =
  | "INDEX_MODEL_MISMATCH"
  | "LAYOUT_MODEL_MISMATCH"
  | "PLAN_TOPOLOGY_MISMATCH";

export class PermissionsGraphRendererCompatibilityError extends Error {
  constructor(
    readonly code: PermissionsGraphRendererCompatibilityErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "PermissionsGraphRendererCompatibilityError";
  }
}

export interface PermissionsGraphElementUpdate<T extends PermissionsGraphActiveElement> {
  readonly id: string;
  readonly previous: T;
  readonly current: T;
  readonly dataChanged: boolean;
  readonly classesChanged: boolean;
  readonly positionChanged: boolean;
}

export type PermissionsGraphDiffOperationType =
  | "remove-edge"
  | "remove-node"
  | "add-node"
  | "add-edge"
  | "update-node"
  | "update-edge";

export interface PermissionsGraphDiffOperation {
  readonly type: PermissionsGraphDiffOperationType;
  readonly id: string;
}

export interface PermissionsGraphActiveSliceDiff {
  readonly removeEdges: readonly PermissionsGraphActiveEdgeElement[];
  readonly removeNodes: readonly PermissionsGraphActiveNodeElement[];
  readonly addNodes: readonly PermissionsGraphActiveNodeElement[];
  readonly addEdges: readonly PermissionsGraphActiveEdgeElement[];
  readonly updateNodes: readonly PermissionsGraphElementUpdate<PermissionsGraphActiveNodeElement>[];
  readonly updateEdges: readonly PermissionsGraphElementUpdate<PermissionsGraphActiveEdgeElement>[];
  readonly positionChanges: readonly PermissionsGraphElementUpdate<PermissionsGraphActiveNodeElement>[];
  readonly dataChanges: readonly PermissionsGraphElementUpdate<PermissionsGraphActiveElement>[];
  readonly classChanges: readonly PermissionsGraphElementUpdate<PermissionsGraphActiveElement>[];
  readonly operations: readonly PermissionsGraphDiffOperation[];
  readonly hasChanges: boolean;
}

export interface PermissionsGraphViewportBounds {
  readonly x1: number;
  readonly y1: number;
  readonly x2: number;
  readonly y2: number;
  readonly w: number;
  readonly h: number;
}

export interface PermissionsGraphViewportSnapshot {
  readonly pan: PermissionsGraphCoordinate;
  readonly zoom: number;
  readonly bounds: PermissionsGraphViewportBounds;
}

export interface PermissionsGraphRendererStateSnapshot {
  readonly selectedNodeIds: readonly string[];
  readonly selectedEdgeIds: readonly string[];
  readonly materializedNodeIds: readonly string[];
  readonly materializedEdgeIds: readonly string[];
  readonly viewport: PermissionsGraphViewportSnapshot;
}

export interface PermissionsGraphPreservedRendererState
  extends PermissionsGraphRendererStateSnapshot {
  readonly previousMaterializedNodeIds: readonly string[];
  readonly previousMaterializedEdgeIds: readonly string[];
}

export interface PermissionsGraphActiveRenderOptions {
  /** Defaults to true. */
  readonly preserveSelection?: boolean;
  /** Defaults to true. */
  readonly preserveViewport?: boolean;
  /** Explicitly skip viewport restoration after the diff. */
  readonly resetViewport?: boolean;
  /** Explicit viewport to restore instead of the current renderer viewport. */
  readonly viewport?: PermissionsGraphViewportSnapshot;
}

export interface PermissionsGraphActiveRenderResult {
  readonly diff: PermissionsGraphActiveSliceDiff;
  readonly stateBefore: PermissionsGraphRendererStateSnapshot;
  readonly stateAfter: PermissionsGraphPreservedRendererState;
}

export interface PermissionsGraphActiveSliceRendererForQa {
  render(
    nextSlice: PermissionsGraphActiveSlice,
    options?: PermissionsGraphActiveRenderOptions,
  ): PermissionsGraphActiveRenderResult;
  getCurrentSlice(): PermissionsGraphActiveSlice;
}

const EMPTY_IDS: readonly string[] = Object.freeze([] as string[]);
const EMPTY_OMISSIONS: readonly PermissionsGraphActiveSliceOmission[] = Object.freeze(
  [] as PermissionsGraphActiveSliceOmission[],
);

/**
 * Build only the requested/planned active Cytoscape elements. Model-backed
 * nodes always use the Phase 3 layout store. Synthetic planner nodes use a
 * deterministic finite fallback and are reported separately.
 */
export function buildPermissionsGraphActiveSlice(
  input: PermissionsGraphActiveSliceBuildInput,
): PermissionsGraphActiveSlice {
  assertCompatible(input.model, input.index, input.layout, input.source);
  const budget = activeBudget(input.source);
  const omissions: PermissionsGraphActiveSliceOmission[] = [];
  const fallbackPositionNodeIds: string[] = [];
  const candidateElements = input.source.kind === "aggregate-plan"
    ? aggregateCandidates(input.source.plan)
    : modelCandidates(input.model, input.index, input.source, omissions);

  const nodes: PermissionsGraphActiveNodeElement[] = [];
  for (const candidate of candidateElements.nodes) {
    if (nodes.length >= budget.maxNodes) {
      omissions.push(freezeOmission(candidate.data.id, "node-budget"));
      continue;
    }
    const storedPosition = input.layout.getPosition(candidate.data.id);
    const position = finitePosition(storedPosition)
      ? storedPosition
      : deterministicFallbackPosition(candidate.data.id, input.layout);
    if (!finitePosition(storedPosition)) fallbackPositionNodeIds.push(candidate.data.id);
    nodes.push(Object.freeze({
      group: "nodes",
      data: candidate.data,
      classes: candidate.classes,
      position: Object.freeze({ x: position.x, y: position.y }),
    }));
  }

  const includedNodeIds = new Set(nodes.map((node) => node.data.id));
  const edges: PermissionsGraphActiveEdgeElement[] = [];
  for (const candidate of candidateElements.edges) {
    if (!includedNodeIds.has(candidate.data.source) || !includedNodeIds.has(candidate.data.target)) {
      omissions.push(freezeOmission(candidate.data.id, "dangling-edge"));
      continue;
    }
    if (edges.length >= budget.maxEdges) {
      omissions.push(freezeOmission(candidate.data.id, "edge-budget"));
      continue;
    }
    edges.push(candidate);
  }

  const materializedNodeIds = freezeSortedIds(nodes.map((node) => node.data.id));
  const materializedEdgeIds = freezeSortedIds(edges.map((edge) => edge.data.id));
  const requestedSelection = input.selection
    ? Object.freeze({
        nodeIds: freezeIntersection(input.selection.nodeIds ?? EMPTY_IDS, materializedNodeIds),
        edgeIds: freezeIntersection(input.selection.edgeIds ?? EMPTY_IDS, materializedEdgeIds),
      })
    : null;
  const elements = Object.freeze([
    ...nodes,
    ...edges,
  ] as PermissionsGraphActiveElement[]);

  return Object.freeze({
    sourceKind: input.source.kind,
    sourceTopologyFingerprint: input.model.topologyFingerprint,
    layoutGeneration: input.layout.layoutGeneration,
    coordinateRevision: input.layout.coordinateRevision,
    budget,
    nodes: Object.freeze(nodes),
    edges: Object.freeze(edges),
    elements,
    materializedNodeIds,
    materializedEdgeIds,
    requestedSelection,
    fallbackPositionNodeIds: freezeSortedIds(fallbackPositionNodeIds),
    omissions: freezeSortedOmissions(omissions),
  });
}

/** Pure stable diff; operation order is the order the Cytoscape adapter uses. */
export function diffPermissionsGraphActiveSlices(
  previous: PermissionsGraphActiveSlice,
  current: PermissionsGraphActiveSlice,
): PermissionsGraphActiveSliceDiff {
  const previousNodes = mapById(previous.nodes);
  const currentNodes = mapById(current.nodes);
  const previousEdges = mapById(previous.edges);
  const currentEdges = mapById(current.edges);

  const removeNodes: PermissionsGraphActiveNodeElement[] = [];
  const addNodes: PermissionsGraphActiveNodeElement[] = [];
  const removeEdges: PermissionsGraphActiveEdgeElement[] = [];
  const addEdges: PermissionsGraphActiveEdgeElement[] = [];
  const updateNodes: PermissionsGraphElementUpdate<PermissionsGraphActiveNodeElement>[] = [];
  const updateEdges: PermissionsGraphElementUpdate<PermissionsGraphActiveEdgeElement>[] = [];

  for (const previousNode of previousNodes.values()) {
    if (!currentNodes.has(previousNode.data.id)) removeNodes.push(previousNode);
  }
  for (const currentNode of currentNodes.values()) {
    const previousNode = previousNodes.get(currentNode.data.id);
    if (!previousNode) {
      addNodes.push(currentNode);
      continue;
    }
    const update = nodeUpdate(previousNode, currentNode);
    if (update) updateNodes.push(update);
  }

  for (const previousEdge of previousEdges.values()) {
    const currentEdge = currentEdges.get(previousEdge.data.id);
    if (!currentEdge || endpointsChanged(previousEdge, currentEdge)) {
      removeEdges.push(previousEdge);
    }
  }
  for (const currentEdge of currentEdges.values()) {
    const previousEdge = previousEdges.get(currentEdge.data.id);
    if (!previousEdge || endpointsChanged(previousEdge, currentEdge)) {
      addEdges.push(currentEdge);
      continue;
    }
    const update = edgeUpdate(previousEdge, currentEdge);
    if (update) updateEdges.push(update);
  }

  removeEdges.sort(compareElementIds);
  removeNodes.sort(compareElementIds);
  addNodes.sort(compareElementIds);
  addEdges.sort(compareElementIds);
  updateNodes.sort(compareUpdateIds);
  updateEdges.sort(compareUpdateIds);

  const positionChanges = Object.freeze(
    updateNodes.filter((update) => update.positionChanged),
  );
  const allUpdates = [...updateNodes, ...updateEdges] as Array<
    PermissionsGraphElementUpdate<PermissionsGraphActiveElement>
  >;
  const dataChanges = Object.freeze(allUpdates.filter((update) => update.dataChanged));
  const classChanges = Object.freeze(allUpdates.filter((update) => update.classesChanged));
  const operations = Object.freeze([
    ...removeEdges.map((element) => freezeOperation("remove-edge", element.data.id)),
    ...removeNodes.map((element) => freezeOperation("remove-node", element.data.id)),
    ...addNodes.map((element) => freezeOperation("add-node", element.data.id)),
    ...addEdges.map((element) => freezeOperation("add-edge", element.data.id)),
    ...updateNodes.map((update) => freezeOperation("update-node", update.id)),
    ...updateEdges.map((update) => freezeOperation("update-edge", update.id)),
  ]);

  return Object.freeze({
    removeEdges: Object.freeze(removeEdges),
    removeNodes: Object.freeze(removeNodes),
    addNodes: Object.freeze(addNodes),
    addEdges: Object.freeze(addEdges),
    updateNodes: Object.freeze(updateNodes),
    updateEdges: Object.freeze(updateEdges),
    positionChanges,
    dataChanges,
    classChanges,
    operations,
    hasChanges: operations.length > 0,
  });
}

/** Apply a precomputed diff without destroying or replacing the Cytoscape core. */
export function applyPermissionsGraphActiveSliceDiff(
  cy: cytoscape.Core,
  diff: PermissionsGraphActiveSliceDiff,
): void {
  cy.batch(() => {
    for (const edge of diff.removeEdges) cy.getElementById(edge.data.id).remove();
    for (const node of diff.removeNodes) cy.getElementById(node.data.id).remove();
    for (const node of diff.addNodes) cy.add(toCytoscapeDefinition(node));
    for (const edge of diff.addEdges) cy.add(toCytoscapeDefinition(edge));
    for (const update of diff.updateNodes) applyElementUpdate(cy, update);
    for (const update of diff.updateEdges) applyElementUpdate(cy, update);
  });
}

export function capturePermissionsGraphRendererState(
  cy: cytoscape.Core,
): PermissionsGraphRendererStateSnapshot {
  return Object.freeze({
    selectedNodeIds: freezeSortedIds(cy.nodes(":selected").map((node) => node.id())),
    selectedEdgeIds: freezeSortedIds(cy.edges(":selected").map((edge) => edge.id())),
    materializedNodeIds: freezeSortedIds(cy.nodes().map((node) => node.id())),
    materializedEdgeIds: freezeSortedIds(cy.edges().map((edge) => edge.id())),
    viewport: capturePermissionsGraphViewport(cy),
  });
}

export function capturePermissionsGraphViewport(
  cy: cytoscape.Core,
): PermissionsGraphViewportSnapshot {
  const pan = cy.pan();
  const extent = cy.extent();
  return Object.freeze({
    pan: Object.freeze({ x: finiteOrZero(pan.x), y: finiteOrZero(pan.y) }),
    zoom: finitePositiveOrOne(cy.zoom()),
    bounds: Object.freeze({
      x1: finiteOrZero(extent.x1),
      y1: finiteOrZero(extent.y1),
      x2: finiteOrZero(extent.x2),
      y2: finiteOrZero(extent.y2),
      w: finiteOrZero(extent.w),
      h: finiteOrZero(extent.h),
    }),
  });
}

export function preservePermissionsGraphRendererState(
  previous: PermissionsGraphRendererStateSnapshot,
  current: PermissionsGraphActiveSlice,
  overrides: {
    readonly selection?: PermissionsGraphRequestedSelection;
    readonly viewport?: PermissionsGraphViewportSnapshot;
  } = {},
): PermissionsGraphPreservedRendererState {
  const selection = overrides.selection ?? {
    nodeIds: previous.selectedNodeIds,
    edgeIds: previous.selectedEdgeIds,
  };
  return Object.freeze({
    selectedNodeIds: freezeIntersection(selection.nodeIds, current.materializedNodeIds),
    selectedEdgeIds: freezeIntersection(selection.edgeIds, current.materializedEdgeIds),
    materializedNodeIds: current.materializedNodeIds,
    materializedEdgeIds: current.materializedEdgeIds,
    previousMaterializedNodeIds: previous.materializedNodeIds,
    previousMaterializedEdgeIds: previous.materializedEdgeIds,
    viewport: overrides.viewport ?? previous.viewport,
  });
}

export function restorePermissionsGraphRendererState(
  cy: cytoscape.Core,
  state: PermissionsGraphPreservedRendererState,
  options: { readonly restoreViewport?: boolean } = {},
): void {
  cy.elements().unselect();
  for (const nodeId of state.selectedNodeIds) cy.getElementById(nodeId).select();
  for (const edgeId of state.selectedEdgeIds) cy.getElementById(edgeId).select();
  if (options.restoreViewport !== false) {
    cy.viewport({
      zoom: finitePositiveOrOne(state.viewport.zoom),
      pan: {
        x: finiteOrZero(state.viewport.pan.x),
        y: finiteOrZero(state.viewport.pan.y),
      },
    });
  }
}

/**
 * Explicit QA/dev-only stateful renderer. Production UI does not import this
 * factory, so creating the adapter is always an intentional diagnostic action.
 */
export function createPermissionsGraphActiveSliceRendererForQa(
  cy: cytoscape.Core,
  initialSlice: PermissionsGraphActiveSlice = emptyPermissionsGraphActiveSlice(),
): PermissionsGraphActiveSliceRendererForQa {
  let currentSlice = initialSlice;
  return Object.freeze({
    render(
      nextSlice: PermissionsGraphActiveSlice,
      options: PermissionsGraphActiveRenderOptions = {},
    ): PermissionsGraphActiveRenderResult {
      const stateBefore = capturePermissionsGraphRendererState(cy);
      const diff = diffPermissionsGraphActiveSlices(currentSlice, nextSlice);
      const preserveSelection = options.preserveSelection !== false;
      const selection = nextSlice.requestedSelection ?? (preserveSelection
        ? undefined
        : { nodeIds: EMPTY_IDS, edgeIds: EMPTY_IDS });
      const viewport = options.viewport ?? stateBefore.viewport;
      const stateAfter = preservePermissionsGraphRendererState(stateBefore, nextSlice, {
        selection,
        viewport,
      });

      applyPermissionsGraphActiveSliceDiff(cy, diff);
      restorePermissionsGraphRendererState(cy, stateAfter, {
        restoreViewport: options.resetViewport !== true && options.preserveViewport !== false,
      });
      if (options.resetViewport === true) cy.reset();
      currentSlice = nextSlice;
      return Object.freeze({ diff, stateBefore, stateAfter });
    },
    getCurrentSlice(): PermissionsGraphActiveSlice {
      return currentSlice;
    },
  });
}

export function emptyPermissionsGraphActiveSlice(): PermissionsGraphActiveSlice {
  const budget = Object.freeze({ maxNodes: 0, maxEdges: 0 });
  return Object.freeze({
    sourceKind: "model-slice",
    sourceTopologyFingerprint: "",
    layoutGeneration: 0,
    coordinateRevision: 0,
    budget,
    nodes: Object.freeze([] as PermissionsGraphActiveNodeElement[]),
    edges: Object.freeze([] as PermissionsGraphActiveEdgeElement[]),
    elements: Object.freeze([] as PermissionsGraphActiveElement[]),
    materializedNodeIds: EMPTY_IDS,
    materializedEdgeIds: EMPTY_IDS,
    requestedSelection: null,
    fallbackPositionNodeIds: EMPTY_IDS,
    omissions: EMPTY_OMISSIONS,
  });
}

function modelCandidates(
  model: PermissionsGraphModel,
  index: PermissionsGraphIndex,
  source: PermissionsGraphModelSliceSource,
  omissions: PermissionsGraphActiveSliceOmission[],
): {
  readonly nodes: PermissionsGraphActiveNodeElement[];
  readonly edges: PermissionsGraphActiveEdgeElement[];
} {
  const nodes: PermissionsGraphActiveNodeElement[] = [];
  for (const id of uniqueSortedIds(source.nodeIds)) {
    const node = index.getNode(id);
    if (!node) {
      omissions.push(freezeOmission(id, "unknown-node"));
      continue;
    }
    nodes.push(nodeRecordToCandidate(node));
  }

  const edges: PermissionsGraphActiveEdgeElement[] = [];
  for (const id of uniqueSortedIds(source.edgeIds)) {
    const edge = index.getEdge(id);
    if (!edge) {
      omissions.push(freezeOmission(id, "unknown-edge"));
      continue;
    }
    edges.push(edgeRecordToElement(edge));
  }

  // The model identity check above protects against a caller pairing a stale
  // index with a new model. Keep the parameter to make that relationship clear.
  void model;
  return { nodes, edges };
}

function aggregateCandidates(plan: PermissionsGraphAggregatePlan): {
  readonly nodes: PermissionsGraphActiveNodeElement[];
  readonly edges: PermissionsGraphActiveEdgeElement[];
} {
  const nodes: PermissionsGraphActiveNodeElement[] = [];
  const edges: PermissionsGraphActiveEdgeElement[] = [];
  for (const element of permissionsGraphAggregatePlanToElements(plan)) {
    if (isGraphEdge(element)) edges.push(graphElementToEdge(element));
    else nodes.push(graphElementToNodeCandidate(element));
  }
  nodes.sort(compareElementIds);
  edges.sort(compareElementIds);
  return { nodes, edges };
}

function nodeRecordToCandidate(
  node: PermissionsGraphNodeRecord,
): PermissionsGraphActiveNodeElement {
  return Object.freeze({
    group: "nodes",
    data: activeNodeData(node.data, node.id),
    classes: normalizeClasses(node.classes),
    position: Object.freeze({ x: 0, y: 0 }),
  });
}

function edgeRecordToElement(
  edge: PermissionsGraphEdgeRecord,
): PermissionsGraphActiveEdgeElement {
  return Object.freeze({
    group: "edges",
    data: activeEdgeData(edge.data, edge.id, edge.sourceId, edge.targetId),
    classes: normalizeClasses(edge.classes),
  });
}

function graphElementToNodeCandidate(
  element: GraphElement,
): PermissionsGraphActiveNodeElement {
  return Object.freeze({
    group: "nodes",
    data: activeNodeData(element.data, element.data.id),
    classes: normalizeClasses(element.classes),
    position: Object.freeze({ x: 0, y: 0 }),
  });
}

function graphElementToEdge(element: GraphElement): PermissionsGraphActiveEdgeElement {
  const source = typeof element.data.source === "string" ? element.data.source : "";
  const target = typeof element.data.target === "string" ? element.data.target : "";
  return Object.freeze({
    group: "edges",
    data: activeEdgeData(element.data, element.data.id, source, target),
    classes: normalizeClasses(element.classes),
  });
}

function activeNodeData(
  data: Readonly<Record<string, unknown>>,
  id: string,
): PermissionsGraphActiveNodeElement["data"] {
  return Object.freeze({ ...data, id });
}

function activeEdgeData(
  data: Readonly<Record<string, unknown>>,
  id: string,
  source: string,
  target: string,
): PermissionsGraphActiveEdgeElement["data"] {
  return Object.freeze({ ...data, id, source, target });
}

function activeBudget(source: PermissionsGraphActiveSliceSource): PermissionsGraphActiveBudget {
  const raw = source.kind === "aggregate-plan"
    ? {
        maxNodes: source.plan.budget.maxRenderedNodes,
        maxEdges: source.plan.budget.maxRenderedEdges,
      }
    : source.budget;
  return Object.freeze({
    maxNodes: normalizeBudget(raw.maxNodes),
    maxEdges: normalizeBudget(raw.maxEdges),
  });
}

function normalizeBudget(value: number): number {
  return Number.isFinite(value) ? Math.max(0, Math.floor(value)) : 0;
}

function assertCompatible(
  model: PermissionsGraphModel,
  index: PermissionsGraphIndex,
  layout: PermissionsGraphLayoutStore,
  source: PermissionsGraphActiveSliceSource,
): void {
  for (const node of model.nodes) {
    if (index.getNode(node.id) !== node) {
      throw new PermissionsGraphRendererCompatibilityError(
        "INDEX_MODEL_MISMATCH",
        "The PermissionsGraphIndex does not match the active-slice model.",
      );
    }
  }
  for (const edge of model.edges) {
    if (index.getEdge(edge.id) !== edge) {
      throw new PermissionsGraphRendererCompatibilityError(
        "INDEX_MODEL_MISMATCH",
        "The PermissionsGraphIndex does not match the active-slice model.",
      );
    }
  }
  if (
    layout.model !== model ||
    layout.index !== index ||
    layout.topologyFingerprint !== model.topologyFingerprint
  ) {
    throw new PermissionsGraphRendererCompatibilityError(
      "LAYOUT_MODEL_MISMATCH",
      "The PermissionsGraphLayoutStore does not match the active-slice model/index.",
    );
  }
  if (
    source.kind === "aggregate-plan" &&
    source.plan.sourceTopologyFingerprint !== model.topologyFingerprint
  ) {
    throw new PermissionsGraphRendererCompatibilityError(
      "PLAN_TOPOLOGY_MISMATCH",
      "The Phase 2 aggregate plan does not match the active-slice model topology.",
    );
  }
}

function deterministicFallbackPosition(
  nodeId: string,
  layout: PermissionsGraphLayoutStore,
): PermissionsGraphCoordinate {
  const bounds = layout.coordinateBounds;
  const centerX = (bounds.minX + bounds.maxX) / 2;
  const centerY = (bounds.minY + bounds.maxY) / 2;
  const first = hashString(`x:${layout.topologyFingerprint}:${nodeId}`);
  const second = hashString(`y:${layout.topologyFingerprint}:${nodeId}`);
  return Object.freeze({
    x: centerX + hashToSignedUnit(first) * 120,
    y: centerY + hashToSignedUnit(second) * 120,
  });
}

function nodeUpdate(
  previous: PermissionsGraphActiveNodeElement,
  current: PermissionsGraphActiveNodeElement,
): PermissionsGraphElementUpdate<PermissionsGraphActiveNodeElement> | null {
  const dataChanged = !deepEqual(previous.data, current.data);
  const classesChanged = previous.classes !== current.classes;
  const positionChanged = !coordinatesEqual(previous.position, current.position);
  return dataChanged || classesChanged || positionChanged
    ? Object.freeze({
        id: current.data.id,
        previous,
        current,
        dataChanged,
        classesChanged,
        positionChanged,
      })
    : null;
}

function edgeUpdate(
  previous: PermissionsGraphActiveEdgeElement,
  current: PermissionsGraphActiveEdgeElement,
): PermissionsGraphElementUpdate<PermissionsGraphActiveEdgeElement> | null {
  const dataChanged = !deepEqual(previous.data, current.data);
  const classesChanged = previous.classes !== current.classes;
  return dataChanged || classesChanged
    ? Object.freeze({
        id: current.data.id,
        previous,
        current,
        dataChanged,
        classesChanged,
        positionChanged: false,
      })
    : null;
}

function endpointsChanged(
  previous: PermissionsGraphActiveEdgeElement,
  current: PermissionsGraphActiveEdgeElement,
): boolean {
  return previous.data.source !== current.data.source || previous.data.target !== current.data.target;
}

function applyElementUpdate(
  cy: cytoscape.Core,
  update: PermissionsGraphElementUpdate<PermissionsGraphActiveElement>,
): void {
  const element = cy.getElementById(update.id);
  if (element.empty()) return;
  if (update.dataChanged) {
    const currentData = element.data() as Record<string, unknown>;
    const protectedKeys = new Set(["id", "source", "target"]);
    const staleKeys = Object.keys(currentData).filter(
      (key) => !protectedKeys.has(key) && !(key in update.current.data),
    );
    if (staleKeys.length > 0) element.removeData(...staleKeys);
    element.data({ ...update.current.data });
  }
  if (update.classesChanged) element.classes(update.current.classes);
  if (update.positionChanged && update.current.group === "nodes") {
    element.position({ ...update.current.position });
  }
}

function toCytoscapeDefinition(
  element: PermissionsGraphActiveElement,
): cytoscape.ElementDefinition {
  if (element.group === "nodes") {
    return {
      group: "nodes",
      data: { ...element.data },
      classes: element.classes,
      position: { ...element.position },
    };
  }
  return {
    group: "edges",
    data: { ...element.data },
    classes: element.classes,
  };
}

function isGraphEdge(element: GraphElement): boolean {
  return typeof element.data.source === "string" && typeof element.data.target === "string";
}

function mapById<T extends PermissionsGraphActiveElement>(elements: readonly T[]): Map<string, T> {
  const map = new Map<string, T>();
  for (const element of elements) {
    if (map.has(element.data.id)) {
      throw new Error(`Duplicate active-slice element id: ${element.data.id}`);
    }
    map.set(element.data.id, element);
  }
  return map;
}

function normalizeClasses(classes: string | readonly string[]): string {
  const values = typeof classes === "string" ? classes.split(/\s+/) : classes;
  return uniqueSortedIds(values.map((entry) => entry.trim()).filter(Boolean)).join(" ");
}

function freezeIntersection(
  requested: readonly string[],
  available: readonly string[],
): readonly string[] {
  const availableIds = new Set(available);
  return freezeSortedIds(uniqueSortedIds(requested).filter((id) => availableIds.has(id)));
}

function freezeSortedIds(ids: Iterable<string>): readonly string[] {
  return Object.freeze(Array.from(ids).sort(compareStrings));
}

function uniqueSortedIds(ids: Iterable<string>): string[] {
  return Array.from(new Set(ids)).sort(compareStrings);
}

function freezeSortedOmissions(
  omissions: PermissionsGraphActiveSliceOmission[],
): readonly PermissionsGraphActiveSliceOmission[] {
  const unique = new Map<string, PermissionsGraphActiveSliceOmission>();
  for (const omission of omissions) {
    const key = `${omission.id}\u0000${omission.reason}`;
    if (!unique.has(key)) unique.set(key, omission);
  }
  return Object.freeze(
    Array.from(unique.values()).sort((left, right) =>
      compareStrings(left.id, right.id) || compareStrings(left.reason, right.reason)
    ),
  );
}

function freezeOmission(
  id: string,
  reason: PermissionsGraphActiveSliceOmissionReason,
): PermissionsGraphActiveSliceOmission {
  return Object.freeze({ id, reason });
}

function freezeOperation(
  type: PermissionsGraphDiffOperationType,
  id: string,
): PermissionsGraphDiffOperation {
  return Object.freeze({ type, id });
}

function finitePosition(
  position: PermissionsGraphCoordinate | null,
): position is PermissionsGraphCoordinate {
  return !!position && Number.isFinite(position.x) && Number.isFinite(position.y);
}

function coordinatesEqual(
  left: PermissionsGraphCoordinate,
  right: PermissionsGraphCoordinate,
): boolean {
  return Object.is(left.x, right.x) && Object.is(left.y, right.y);
}

function deepEqual(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) return true;
  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) return false;
    return left.every((entry, index) => deepEqual(entry, right[index]));
  }
  if (isRecord(left) || isRecord(right)) {
    if (!isRecord(left) || !isRecord(right)) return false;
    const leftKeys = Object.keys(left).sort(compareStrings);
    const rightKeys = Object.keys(right).sort(compareStrings);
    if (!deepEqual(leftKeys, rightKeys)) return false;
    return leftKeys.every((key) => deepEqual(left[key], right[key]));
  }
  return false;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hashString(value: string): number {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

function hashToSignedUnit(value: number): number {
  return (value / 0xffff_ffff) * 2 - 1;
}

function finiteOrZero(value: number): number {
  return Number.isFinite(value) ? value : 0;
}

function finitePositiveOrOne(value: number): number {
  return Number.isFinite(value) && value > 0 ? value : 1;
}

function compareElementIds(
  left: PermissionsGraphActiveElement,
  right: PermissionsGraphActiveElement,
): number {
  return compareStrings(left.data.id, right.data.id);
}

function compareUpdateIds(
  left: PermissionsGraphElementUpdate<PermissionsGraphActiveElement>,
  right: PermissionsGraphElementUpdate<PermissionsGraphActiveElement>,
): number {
  return compareStrings(left.id, right.id);
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
