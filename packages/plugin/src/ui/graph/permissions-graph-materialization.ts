/**
 * Inert Phase 5 virtual-materialization planners.
 *
 * These helpers consume the Phase 1 model/index, Phase 2 aggregate budgets,
 * Phase 3 layout, and Phase 5 spatial index. They never touch Cytoscape and are
 * not imported by the live PermissionsGraphView or plugin runtime.
 */

import type { GraphAccessLevel } from "./permissions-graph-data";
import type {
  PermissionsGraphAggregateEdgeDescriptor,
  PermissionsGraphAggregateNodeDescriptor,
  PermissionsGraphAggregatePlan,
  PermissionsGraphFolderAggregateDescriptor,
} from "./permissions-graph-budget";
import type { PermissionsGraphLayoutStore } from "./permissions-graph-layout";
import type {
  PermissionsGraphEdgeRecord,
  PermissionsGraphIndex,
  PermissionsGraphModel,
  PermissionsGraphNodeKind,
  PermissionsGraphNodeRecord,
} from "./permissions-graph-model";
import type {
  PermissionsGraphActiveSliceBuildInput,
  PermissionsGraphActiveSliceSource,
  PermissionsGraphSelectionRequest,
} from "./permissions-graph-renderer";
import {
  expandPermissionsGraphSpatialBounds,
  type PermissionsGraphNearestNodeResult,
  type PermissionsGraphSpatialBounds,
  type PermissionsGraphSpatialEntry,
  type PermissionsGraphSpatialIndex,
} from "./permissions-graph-spatial";

type PositiveAccessLevel = Exclude<GraphAccessLevel, "none">;

export type PermissionsGraphMaterializationKind =
  | "viewport"
  | "hover"
  | "search"
  | "focus"
  | "aggregate";

export interface PermissionsGraphMaterializationBudget {
  readonly maxNodes: number;
  readonly maxEdges: number;
}

export interface PermissionsGraphMaterializationFilters {
  readonly selectedUserIds?: readonly string[];
  readonly accessLevels?: Partial<Record<PositiveAccessLevel, boolean>>;
  readonly nodeKinds?: readonly PermissionsGraphNodeKind[];
  readonly pathPrefix?: string;
}

export interface PermissionsGraphMaterializationInclusion {
  readonly id: string;
  readonly reason: string;
}

export interface PermissionsGraphMaterializationOmission {
  readonly id: string;
  readonly reason: string;
}

export interface PermissionsGraphMaterializationSummary {
  readonly candidateNodeCount: number;
  readonly candidateEdgeCount: number;
  /** Nodes outside the planner's spatial/search/focus scope, kept as a count. */
  readonly outsideScopeNodeCount: number;
  readonly omissionReasonCounts: Readonly<Record<string, number>>;
  readonly truncated: boolean;
}

export interface PermissionsGraphMaterializationPlan {
  readonly kind: PermissionsGraphMaterializationKind;
  readonly sourceTopologyFingerprint: string;
  readonly layoutGeneration: number;
  readonly coordinateRevision: number;
  readonly budget: PermissionsGraphMaterializationBudget;
  readonly includedNodeIds: readonly string[];
  readonly includedEdgeIds: readonly string[];
  readonly nodeInclusions: readonly PermissionsGraphMaterializationInclusion[];
  readonly edgeInclusions: readonly PermissionsGraphMaterializationInclusion[];
  readonly omittedNodes: readonly PermissionsGraphMaterializationOmission[];
  readonly omittedEdges: readonly PermissionsGraphMaterializationOmission[];
  readonly diagnostics: readonly string[];
  readonly summary: PermissionsGraphMaterializationSummary;
  readonly rendererSource: PermissionsGraphActiveSliceSource;
}

export interface PermissionsGraphPreviousActiveSlice {
  readonly nodeIds: readonly string[];
  readonly edgeIds?: readonly string[];
}

export interface PermissionsGraphViewportMaterializationOptions {
  readonly viewport: PermissionsGraphSpatialBounds;
  readonly overscanMargin?: number;
  readonly hysteresisMargin?: number;
  readonly previous?: PermissionsGraphPreviousActiveSlice;
  readonly budget: PermissionsGraphMaterializationBudget;
  readonly includeNeighbors?: boolean;
  readonly maxNeighborsPerNode?: number;
  readonly filters?: PermissionsGraphMaterializationFilters;
}

export interface PermissionsGraphViewportMaterializationPlan
  extends PermissionsGraphMaterializationPlan {
  readonly kind: "viewport";
  readonly viewport: PermissionsGraphSpatialBounds;
  readonly overscanBounds: PermissionsGraphSpatialBounds | null;
  readonly hysteresisBounds: PermissionsGraphSpatialBounds | null;
}

export interface PermissionsGraphHoverMaterializationOptions {
  readonly x: number;
  readonly y: number;
  readonly hitRadius: number;
  readonly budget: PermissionsGraphMaterializationBudget;
  readonly maxNeighbors?: number;
  readonly filters?: PermissionsGraphMaterializationFilters;
}

export interface PermissionsGraphHoverMaterializationPlan
  extends PermissionsGraphMaterializationPlan {
  readonly kind: "hover";
  readonly hit: PermissionsGraphNearestNodeResult | null;
}

export interface PermissionsGraphSearchMatch {
  readonly nodeId: string;
  readonly rank: number;
  readonly matchedField: string;
  readonly label: string;
}

interface PermissionsGraphSearchEntry {
  readonly nodeId: string;
  readonly label: string;
  readonly kind: PermissionsGraphNodeKind;
  readonly fields: readonly string[];
  readonly tokens: ReadonlySet<string>;
}

/** Immutable Phase 5 search metadata built only from safe model/index fields. */
export class PermissionsGraphSearchIndex {
  private readonly entriesById = new Map<string, PermissionsGraphSearchEntry>();
  private readonly nodeIdsByField = new Map<string, readonly string[]>();
  private readonly nodeIdsByToken = new Map<string, readonly string[]>();
  private readonly fieldValues: readonly string[];

  constructor(
    readonly model: PermissionsGraphModel,
    readonly index: PermissionsGraphIndex,
  ) {
    assertIndexMatchesModel(model, index);
    const mutableNodeIdsByField = new Map<string, Set<string>>();
    const mutableNodeIdsByToken = new Map<string, Set<string>>();
    for (const node of model.nodes) {
      const entry = buildSearchEntry(node, index);
      this.entriesById.set(node.id, entry);
      for (const field of entry.fields) appendSetMapValue(mutableNodeIdsByField, field, node.id);
      for (const token of entry.tokens) appendSetMapValue(mutableNodeIdsByToken, token, node.id);
    }
    freezeSetMap(mutableNodeIdsByField, this.nodeIdsByField);
    freezeSetMap(mutableNodeIdsByToken, this.nodeIdsByToken);
    this.fieldValues = Object.freeze(Array.from(this.nodeIdsByField.keys()).sort(compareStrings));
  }

  search(
    rawQuery: string,
    options: { readonly kinds?: readonly PermissionsGraphNodeKind[] } = {},
  ): readonly PermissionsGraphSearchMatch[] {
    const query = normalizeSearchValue(rawQuery);
    if (!query) return Object.freeze([] as PermissionsGraphSearchMatch[]);
    const queryTokens = tokenize(query);
    const allowedKinds = options.kinds ? new Set(options.kinds) : null;
    const candidateIds = new Set<string>(this.nodeIdsByField.get(query) ?? []);
    for (const field of this.fieldValues) {
      if (field.startsWith(query) || field.includes(query)) {
        for (const nodeId of this.nodeIdsByField.get(field) ?? []) candidateIds.add(nodeId);
      }
    }
    if (queryTokens.length > 0) {
      const tokenSets = queryTokens.map((token) => new Set(this.nodeIdsByToken.get(token) ?? []));
      const first = tokenSets[0] ?? new Set<string>();
      for (const nodeId of first) {
        if (tokenSets.every((set) => set.has(nodeId))) candidateIds.add(nodeId);
      }
    }
    const matches: PermissionsGraphSearchMatch[] = [];

    for (const nodeId of Array.from(candidateIds).sort(compareStrings)) {
      const entry = this.entriesById.get(nodeId);
      if (!entry) continue;
      if (allowedKinds && !allowedKinds.has(entry.kind)) continue;
      const exact = entry.fields.find((field) => field === query);
      const prefix = exact ? undefined : entry.fields.find((field) => field.startsWith(query));
      const token = exact || prefix
        ? undefined
        : entry.fields.find(() => queryTokens.length > 0 && queryTokens.every((value) => entry.tokens.has(value)));
      const substring = exact || prefix || token
        ? undefined
        : entry.fields.find((field) => field.includes(query));
      const matchedField = exact ?? prefix ?? token ?? substring;
      if (!matchedField) continue;
      matches.push(Object.freeze({
        nodeId: entry.nodeId,
        rank: exact ? 0 : prefix ? 1 : token ? 2 : 3,
        matchedField,
        label: entry.label,
      }));
    }

    matches.sort((left, right) =>
      left.rank - right.rank ||
      compareStrings(left.label, right.label) ||
      compareStrings(left.nodeId, right.nodeId)
    );
    return Object.freeze(matches);
  }
}

export interface PermissionsGraphSearchMaterializationOptions {
  readonly query: string;
  readonly budget: PermissionsGraphMaterializationBudget;
  readonly maxResults?: number;
  readonly kinds?: readonly PermissionsGraphNodeKind[];
  readonly includeNeighbors?: boolean;
  readonly maxNeighborsPerResult?: number;
  readonly includeEdges?: boolean;
  readonly filters?: PermissionsGraphMaterializationFilters;
}

export interface PermissionsGraphSearchMaterializationPlan
  extends PermissionsGraphMaterializationPlan {
  readonly kind: "search";
  readonly query: string;
  readonly totalMatchCount: number;
  readonly matchedNodeIds: readonly string[];
}

export interface PermissionsGraphFocusMaterializationOptions {
  readonly focusNodeId: string;
  readonly depth: number;
  readonly budget: PermissionsGraphMaterializationBudget;
  readonly includeEdges?: boolean;
  readonly filters?: PermissionsGraphMaterializationFilters;
}

export interface PermissionsGraphFocusMaterializationPlan
  extends PermissionsGraphMaterializationPlan {
  readonly kind: "focus";
  readonly focusNodeId: string;
  readonly depth: number;
  readonly distanceByNodeId: Readonly<Record<string, number>>;
}

export type PermissionsGraphAggregateExpansionState = "collapsed" | "expanded" | "unknown";

export interface PermissionsGraphAggregateMaterializationOptions {
  readonly aggregateId: string;
  readonly expanded: boolean;
  readonly budget?: PermissionsGraphMaterializationBudget;
  readonly maxExpandedChildren?: number;
  readonly includeContextNeighbors?: boolean;
  readonly filters?: PermissionsGraphMaterializationFilters;
}

export interface PermissionsGraphAggregateMaterializationPlan
  extends PermissionsGraphMaterializationPlan {
  readonly kind: "aggregate";
  readonly aggregateId: string;
  readonly expansionState: PermissionsGraphAggregateExpansionState;
  readonly descriptor: PermissionsGraphAggregateNodeDescriptor | null;
  readonly aggregateCounts: PermissionsGraphFolderAggregateDescriptor["counts"] | null;
  readonly expandedChildNodeIds: readonly string[];
}

export type PermissionsGraphMaterializationCompatibilityErrorCode =
  | "INDEX_MODEL_MISMATCH"
  | "LAYOUT_MODEL_MISMATCH"
  | "SPATIAL_LAYOUT_MISMATCH"
  | "SEARCH_INDEX_MISMATCH"
  | "PLAN_TOPOLOGY_MISMATCH"
  | "INVALID_AGGREGATE_PLAN";

export class PermissionsGraphMaterializationCompatibilityError extends Error {
  constructor(
    readonly code: PermissionsGraphMaterializationCompatibilityErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "PermissionsGraphMaterializationCompatibilityError";
  }
}

interface CandidateNode {
  readonly id: string;
  readonly reason: string;
}

interface FinalizeModelPlanInput {
  readonly kind: Exclude<PermissionsGraphMaterializationKind, "aggregate"> | "aggregate";
  readonly model: PermissionsGraphModel;
  readonly index: PermissionsGraphIndex;
  readonly layout: PermissionsGraphLayoutStore;
  readonly budget: PermissionsGraphMaterializationBudget;
  readonly candidates: readonly CandidateNode[];
  readonly edgeReason: string;
  readonly outsideScopeNodeCount?: number;
  readonly diagnostics?: readonly string[];
  readonly preOmittedNodes?: readonly PermissionsGraphMaterializationOmission[];
  readonly preferredEdgeIds?: readonly string[];
  readonly includeEdges?: boolean;
  readonly filters?: PermissionsGraphMaterializationFilters;
}

/** Use Phase 2's normalized hard limits as the Phase 5 active-slice budget. */
export function permissionsGraphMaterializationBudgetFromAggregatePlan(
  plan: PermissionsGraphAggregatePlan,
): PermissionsGraphMaterializationBudget {
  return Object.freeze({
    maxNodes: plan.budget.maxRenderedNodes,
    maxEdges: plan.budget.maxRenderedEdges,
  });
}

export function planPermissionsGraphViewportMaterialization(
  model: PermissionsGraphModel,
  index: PermissionsGraphIndex,
  layout: PermissionsGraphLayoutStore,
  spatial: PermissionsGraphSpatialIndex,
  options: PermissionsGraphViewportMaterializationOptions,
): PermissionsGraphViewportMaterializationPlan {
  assertPlanningInputs(model, index, layout);
  if (spatial.layout !== layout) {
    throw new PermissionsGraphMaterializationCompatibilityError(
      "SPATIAL_LAYOUT_MISMATCH",
      "The PermissionsGraphSpatialIndex does not match the supplied layout store.",
    );
  }

  const viewport = normalizeBounds(options.viewport);
  const emptyViewport = !viewport || viewport.x2 <= viewport.x1 || viewport.y2 <= viewport.y1;
  const overscanBounds = viewport
    ? expandPermissionsGraphSpatialBounds(viewport, nonNegative(options.overscanMargin, 0))
    : null;
  const hysteresisBounds = viewport
    ? expandPermissionsGraphSpatialBounds(
        viewport,
        Math.max(
          nonNegative(options.overscanMargin, 0),
          nonNegative(options.hysteresisMargin, options.overscanMargin ?? 0),
        ),
      )
    : null;

  if (emptyViewport || !viewport || !overscanBounds || !hysteresisBounds) {
    const base = finalizeModelPlan({
      kind: "viewport",
      model,
      index,
      layout,
      budget: options.budget,
      candidates: [],
      edgeReason: "viewport-connecting-edge",
      outsideScopeNodeCount: model.nodeCount,
      diagnostics: ["empty-or-invalid-viewport"],
      filters: options.filters,
    });
    return Object.freeze({ ...base, kind: "viewport", viewport: options.viewport, overscanBounds, hysteresisBounds });
  }

  const core = spatial.query(viewport);
  const overscan = spatial.query(overscanBounds);
  const coreIds = new Set(core.map((entry) => entry.nodeId));
  const overscanIds = new Set(overscan.map((entry) => entry.nodeId));
  const center = { x: (viewport.x1 + viewport.x2) / 2, y: (viewport.y1 + viewport.y2) / 2 };
  const candidates: CandidateNode[] = [];
  const preOmittedNodes: PermissionsGraphMaterializationOmission[] = [];

  for (const entry of sortSpatialByDistance(core, center)) {
    candidates.push({ id: entry.nodeId, reason: "viewport" });
  }

  const retainedEntries: PermissionsGraphSpatialEntry[] = [];
  for (const nodeId of uniqueSorted(options.previous?.nodeIds ?? [])) {
    if (coreIds.has(nodeId)) continue;
    const position = layout.getPosition(nodeId);
    if (!position || !pointInBounds(position, hysteresisBounds)) {
      preOmittedNodes.push(Object.freeze({ id: nodeId, reason: "outside-hysteresis" }));
      continue;
    }
    const ordinal = index.getNodeOrdinal(nodeId);
    if (ordinal === undefined) {
      preOmittedNodes.push(Object.freeze({ id: nodeId, reason: "unknown-node" }));
      continue;
    }
    retainedEntries.push({ nodeId, ordinal, x: position.x, y: position.y, cellX: 0, cellY: 0 });
  }
  for (const entry of sortSpatialByDistance(retainedEntries, center)) {
    candidates.push({ id: entry.nodeId, reason: "hysteresis-retained" });
  }

  for (const entry of sortSpatialByDistance(
    overscan.filter((entry) => !coreIds.has(entry.nodeId) && !retainedEntries.some((item) => item.nodeId === entry.nodeId)),
    center,
  )) {
    candidates.push({ id: entry.nodeId, reason: "overscan" });
  }

  if (options.includeNeighbors) {
    appendBoundedNeighbors(
      candidates,
      index,
      candidates.slice(0, normalizeBudget(options.budget).maxNodes).map((candidate) => candidate.id),
      normalizeLimit(options.maxNeighborsPerNode, 1),
      "viewport-neighbor",
    );
  }

  const scopeIds = new Set([...overscanIds, ...retainedEntries.map((entry) => entry.nodeId)]);
  const base = finalizeModelPlan({
    kind: "viewport",
    model,
    index,
    layout,
    budget: options.budget,
    candidates,
    edgeReason: "viewport-connecting-edge",
    outsideScopeNodeCount: Math.max(0, model.nodeCount - scopeIds.size),
    diagnostics: spatial.getDiagnostics().map((diagnostic) => diagnostic.code),
    preOmittedNodes,
    preferredEdgeIds: options.previous?.edgeIds,
    filters: options.filters,
  });
  return Object.freeze({ ...base, kind: "viewport", viewport, overscanBounds, hysteresisBounds });
}

export function planPermissionsGraphHoverMaterialization(
  model: PermissionsGraphModel,
  index: PermissionsGraphIndex,
  layout: PermissionsGraphLayoutStore,
  spatial: PermissionsGraphSpatialIndex,
  options: PermissionsGraphHoverMaterializationOptions,
): PermissionsGraphHoverMaterializationPlan {
  assertPlanningInputs(model, index, layout);
  if (spatial.layout !== layout) {
    throw new PermissionsGraphMaterializationCompatibilityError(
      "SPATIAL_LAYOUT_MISMATCH",
      "The PermissionsGraphSpatialIndex does not match the supplied layout store.",
    );
  }
  const hit = spatial.nearest({ x: options.x, y: options.y }, options.hitRadius);
  const candidates: CandidateNode[] = [];
  if (hit) {
    candidates.push({ id: hit.nodeId, reason: "hover-target" });
    for (const neighborId of index.getAdjacentNodeIds(hit.nodeId).slice(
      0,
      normalizeLimit(options.maxNeighbors, 12),
    )) {
      candidates.push({ id: neighborId, reason: "hover-neighbor" });
    }
  }
  const base = finalizeModelPlan({
    kind: "hover",
    model,
    index,
    layout,
    budget: options.budget,
    candidates,
    edgeReason: "hover-neighborhood-edge",
    outsideScopeNodeCount: Math.max(0, model.nodeCount - new Set(candidates.map((entry) => entry.id)).size),
    diagnostics: hit ? [] : ["no-hover-hit"],
    filters: options.filters,
  });
  return Object.freeze({ ...base, kind: "hover", hit });
}

export function planPermissionsGraphSearchMaterialization(
  model: PermissionsGraphModel,
  index: PermissionsGraphIndex,
  layout: PermissionsGraphLayoutStore,
  searchIndex: PermissionsGraphSearchIndex,
  options: PermissionsGraphSearchMaterializationOptions,
): PermissionsGraphSearchMaterializationPlan {
  assertPlanningInputs(model, index, layout);
  if (searchIndex.model !== model || searchIndex.index !== index) {
    throw new PermissionsGraphMaterializationCompatibilityError(
      "SEARCH_INDEX_MISMATCH",
      "The PermissionsGraphSearchIndex does not match the supplied model/index.",
    );
  }
  const query = options.query.trim().toLowerCase();
  const matches = searchIndex.search(query, { kinds: options.kinds });
  const selectedMatches = matches.slice(0, normalizeLimit(options.maxResults, 100));
  const candidates: CandidateNode[] = selectedMatches.map((match) => ({
    id: match.nodeId,
    reason: "search-result",
  }));
  if (options.includeNeighbors) {
    appendBoundedNeighbors(
      candidates,
      index,
      selectedMatches.map((match) => match.nodeId),
      normalizeLimit(options.maxNeighborsPerResult, 1),
      "search-neighbor",
    );
  }
  const preOmittedNodes = matches.slice(selectedMatches.length).map((match) =>
    Object.freeze({ id: match.nodeId, reason: "search-result-budget" })
  );
  const base = finalizeModelPlan({
    kind: "search",
    model,
    index,
    layout,
    budget: options.budget,
    candidates,
    edgeReason: "search-connecting-edge",
    outsideScopeNodeCount: Math.max(0, model.nodeCount - new Set(matches.map((match) => match.nodeId)).size),
    diagnostics: query ? (matches.length > 0 ? [] : ["no-search-match"]) : ["empty-search-query"],
    preOmittedNodes,
    includeEdges: options.includeEdges !== false,
    filters: options.filters,
  });
  return Object.freeze({
    ...base,
    kind: "search",
    query,
    totalMatchCount: matches.length,
    matchedNodeIds: Object.freeze(selectedMatches.map((match) => match.nodeId)),
  });
}

export function planPermissionsGraphFocusMaterialization(
  model: PermissionsGraphModel,
  index: PermissionsGraphIndex,
  layout: PermissionsGraphLayoutStore,
  options: PermissionsGraphFocusMaterializationOptions,
): PermissionsGraphFocusMaterializationPlan {
  assertPlanningInputs(model, index, layout);
  const depth = Math.max(0, Math.min(8, Math.floor(Number.isFinite(options.depth) ? options.depth : 0)));
  const distanceByNodeId = new Map<string, number>();
  const candidates: CandidateNode[] = [];
  const diagnostics: string[] = [];

  if (!index.getNode(options.focusNodeId)) {
    diagnostics.push("unknown-focus-node");
  } else {
    const queue: Array<{ id: string; distance: number }> = [{ id: options.focusNodeId, distance: 0 }];
    distanceByNodeId.set(options.focusNodeId, 0);
    for (let cursor = 0; cursor < queue.length; cursor += 1) {
      const current = queue[cursor];
      candidates.push({
        id: current.id,
        reason: current.distance === 0 ? "focus-target" : `focus-depth-${current.distance}`,
      });
      if (current.distance >= depth) continue;
      for (const neighborId of index.getAdjacentNodeIds(current.id)) {
        if (distanceByNodeId.has(neighborId)) continue;
        distanceByNodeId.set(neighborId, current.distance + 1);
        queue.push({ id: neighborId, distance: current.distance + 1 });
      }
    }
  }

  const base = finalizeModelPlan({
    kind: "focus",
    model,
    index,
    layout,
    budget: options.budget,
    candidates,
    edgeReason: "focus-connecting-edge",
    outsideScopeNodeCount: Math.max(0, model.nodeCount - distanceByNodeId.size),
    diagnostics,
    includeEdges: options.includeEdges !== false,
    filters: options.filters,
  });
  return Object.freeze({
    ...base,
    kind: "focus",
    focusNodeId: options.focusNodeId,
    depth,
    distanceByNodeId: Object.freeze(Object.fromEntries(
      Array.from(distanceByNodeId.entries()).sort((left, right) => compareStrings(left[0], right[0])),
    )),
  });
}

export function planPermissionsGraphAggregateMaterialization(
  model: PermissionsGraphModel,
  index: PermissionsGraphIndex,
  layout: PermissionsGraphLayoutStore,
  aggregatePlan: PermissionsGraphAggregatePlan,
  options: PermissionsGraphAggregateMaterializationOptions,
): PermissionsGraphAggregateMaterializationPlan {
  assertPlanningInputs(model, index, layout);
  validateAggregatePlan(model, aggregatePlan);
  const descriptor = aggregatePlan.nodes.find((node) => node.id === options.aggregateId) ?? null;
  const aggregateCounts = descriptor?.kind === "folder" ? descriptor.counts : null;
  const budget = normalizeBudget(options.budget ?? permissionsGraphMaterializationBudgetFromAggregatePlan(aggregatePlan));

  if (!descriptor) {
    const base = finalizeModelPlan({
      kind: "aggregate",
      model,
      index,
      layout,
      budget,
      candidates: [],
      edgeReason: "aggregate-edge",
      outsideScopeNodeCount: model.nodeCount,
      diagnostics: ["unknown-aggregate-id"],
      filters: options.filters,
    });
    return Object.freeze({
      ...base,
      kind: "aggregate",
      aggregateId: options.aggregateId,
      expansionState: "unknown",
      descriptor: null,
      aggregateCounts: null,
      expandedChildNodeIds: Object.freeze([] as string[]),
    });
  }

  if (!options.expanded) {
    const includedNodeIds = freezeSortedIds(aggregatePlan.nodes.map((node) => node.id));
    const includedEdgeIds = freezeSortedIds(aggregatePlan.edges.map((edge) => edge.id));
    const omittedNodes = freezeOmissions(aggregatePlan.omittedNodes);
    const omittedEdges = freezeOmissions(aggregatePlan.omittedEdges);
    const materializationBudget = permissionsGraphMaterializationBudgetFromAggregatePlan(aggregatePlan);
    const rendererSource = Object.freeze({
      kind: "aggregate-plan" as const,
      plan: aggregatePlan,
    });
    const summary = buildSummary(
      aggregatePlan.candidateNodeCount,
      aggregatePlan.candidateEdgeCount,
      0,
      omittedNodes,
      omittedEdges,
      aggregatePlan.truncated,
    );
    return Object.freeze({
      kind: "aggregate",
      sourceTopologyFingerprint: model.topologyFingerprint,
      layoutGeneration: layout.layoutGeneration,
      coordinateRevision: layout.coordinateRevision,
      budget: materializationBudget,
      includedNodeIds,
      includedEdgeIds,
      nodeInclusions: Object.freeze(includedNodeIds.map((id) => Object.freeze({ id, reason: "aggregate-collapsed" }))),
      edgeInclusions: Object.freeze(includedEdgeIds.map((id) => Object.freeze({ id, reason: "aggregate-edge" }))),
      omittedNodes,
      omittedEdges,
      diagnostics: Object.freeze(aggregatePlan.diagnostics.map((diagnostic) => diagnostic.code)),
      summary,
      rendererSource,
      aggregateId: options.aggregateId,
      expansionState: "collapsed",
      descriptor,
      aggregateCounts,
      expandedChildNodeIds: Object.freeze([] as string[]),
    });
  }

  const maxChildren = normalizeLimit(options.maxExpandedChildren, Math.max(0, budget.maxNodes - 1));
  const rootId = descriptor.id;
  const childIds = aggregateChildModelIds(model, index, descriptor);
  const selectedChildren = childIds.slice(0, maxChildren);
  const preOmittedNodes = childIds.slice(selectedChildren.length).map((id) =>
    Object.freeze({ id, reason: "aggregate-child-budget" })
  );
  const candidates: CandidateNode[] = [];
  if (index.getNode(rootId)) candidates.push({ id: rootId, reason: "aggregate-root" });
  for (const id of selectedChildren) {
    if (id !== rootId) candidates.push({ id, reason: "aggregate-child" });
  }
  if (options.includeContextNeighbors !== false) {
    appendBoundedNeighbors(
      candidates,
      index,
      [rootId, ...selectedChildren],
      1,
      "aggregate-context",
    );
  }
  const base = finalizeModelPlan({
    kind: "aggregate",
    model,
    index,
    layout,
    budget,
    candidates,
    edgeReason: "aggregate-expanded-edge",
    outsideScopeNodeCount: Math.max(0, model.nodeCount - new Set([rootId, ...childIds]).size),
    diagnostics: descriptor.kind === "folder" ? [] : ["aggregate-user-expansion-is-one-hop"],
    preOmittedNodes,
    filters: options.filters,
  });
  const included = new Set(base.includedNodeIds);
  return Object.freeze({
    ...base,
    kind: "aggregate",
    aggregateId: options.aggregateId,
    expansionState: "expanded",
    descriptor,
    aggregateCounts,
    expandedChildNodeIds: Object.freeze(
      selectedChildren.filter((id) => id !== rootId && included.has(id)).sort(compareStrings),
    ),
  });
}

/** Pure bridge into the existing Phase 4 builder; it does not render. */
export function permissionsGraphMaterializationPlanToActiveSliceInput(input: {
  readonly model: PermissionsGraphModel;
  readonly index: PermissionsGraphIndex;
  readonly layout: PermissionsGraphLayoutStore;
  readonly plan: PermissionsGraphMaterializationPlan;
  readonly selection?: PermissionsGraphSelectionRequest;
}): PermissionsGraphActiveSliceBuildInput {
  assertPlanningInputs(input.model, input.index, input.layout);
  if (input.plan.sourceTopologyFingerprint !== input.model.topologyFingerprint) {
    throw new PermissionsGraphMaterializationCompatibilityError(
      "PLAN_TOPOLOGY_MISMATCH",
      "The Phase 5 materialization plan does not match the supplied model topology.",
    );
  }
  return Object.freeze({
    model: input.model,
    index: input.index,
    layout: input.layout,
    source: input.plan.rendererSource,
    selection: input.selection,
  });
}

export interface PermissionsGraphExplainLookupOptions {
  readonly aggregatePlan?: PermissionsGraphAggregatePlan;
  readonly materializedNodeIds?: readonly string[];
  readonly materializedEdgeIds?: readonly string[];
}

export type PermissionsGraphExplainLookupResult =
  | { readonly found: false; readonly id: string }
  | {
      readonly found: true;
      readonly id: string;
      readonly entityType: "node";
      readonly materialization: "virtual" | "materialized";
      readonly nodeKind: PermissionsGraphNodeKind;
      readonly label: string | null;
      readonly path: string | null;
      readonly userId: string | null;
      readonly role: string | null;
      readonly displayName: string | null;
      readonly email: string | null;
      readonly aggregate: boolean;
      readonly accessLevels: readonly PositiveAccessLevel[];
    }
  | {
      readonly found: true;
      readonly id: string;
      readonly entityType: "edge";
      readonly materialization: "virtual" | "materialized";
      readonly edgeKind: PermissionsGraphEdgeRecord["kind"];
      readonly sourceId: string;
      readonly targetId: string;
      readonly label: string | null;
      readonly path: string | null;
      readonly userId: string | null;
      readonly role: string | null;
      readonly level: GraphAccessLevel | null;
      readonly expiring: boolean;
      readonly aggregate: boolean;
    }
  | {
      readonly found: true;
      readonly id: string;
      readonly entityType: "aggregate-node";
      readonly materialization: "virtual" | "materialized";
      readonly descriptor: PermissionsGraphAggregateNodeDescriptor;
    }
  | {
      readonly found: true;
      readonly id: string;
      readonly entityType: "aggregate-edge";
      readonly materialization: "virtual" | "materialized";
      readonly descriptor: PermissionsGraphAggregateEdgeDescriptor;
    };

/**
 * Resolve safe graph metadata without reading vault files, plaintext contents,
 * cache bytes, or network/API state. The returned permission edge fields are
 * sufficient for a future caller to invoke the existing explainAccess trace.
 */
export function lookupPermissionsGraphExplainMetadata(
  model: PermissionsGraphModel,
  index: PermissionsGraphIndex,
  id: string,
  options: PermissionsGraphExplainLookupOptions = {},
): PermissionsGraphExplainLookupResult {
  assertIndexMatchesModel(model, index);
  const materializedNodes = new Set(options.materializedNodeIds ?? []);
  const materializedEdges = new Set(options.materializedEdgeIds ?? []);
  const aggregateNode = options.aggregatePlan?.nodes.find((node) => node.id === id);
  if (aggregateNode) {
    return Object.freeze({
      found: true,
      id,
      entityType: "aggregate-node",
      materialization: materializedNodes.has(id) ? "materialized" : "virtual",
      descriptor: aggregateNode,
    });
  }
  const aggregateEdge = options.aggregatePlan?.edges.find((edge) => edge.id === id);
  if (aggregateEdge) {
    return Object.freeze({
      found: true,
      id,
      entityType: "aggregate-edge",
      materialization: materializedEdges.has(id) ? "materialized" : "virtual",
      descriptor: aggregateEdge,
    });
  }

  const node = index.getNode(id);
  if (node) {
    const accessLevels = freezeSortedIds(
      index.getIncidentEdgeIds(id)
        .map((edgeId) => index.getEdge(edgeId)?.level)
        .filter((level): level is PositiveAccessLevel =>
          level === "read" || level === "write" || level === "admin"
        ),
    ) as readonly PositiveAccessLevel[];
    return Object.freeze({
      found: true,
      id,
      entityType: "node",
      materialization: materializedNodes.has(id) ? "materialized" : "virtual",
      nodeKind: node.kind,
      label: node.label,
      path: node.path,
      userId: node.userId,
      role: node.role,
      displayName: node.displayName,
      email: node.email,
      aggregate: node.aggregate,
      accessLevels,
    });
  }

  const edge = index.getEdge(id);
  if (edge) {
    return Object.freeze({
      found: true,
      id,
      entityType: "edge",
      materialization: materializedEdges.has(id) ? "materialized" : "virtual",
      edgeKind: edge.kind,
      sourceId: edge.sourceId,
      targetId: edge.targetId,
      label: edge.label,
      path: edge.path,
      userId: edge.userId,
      role: edge.role,
      level: edge.level,
      expiring: edge.expiring,
      aggregate: edge.aggregate,
    });
  }

  return Object.freeze({ found: false, id });
}

function finalizeModelPlan(input: FinalizeModelPlanInput): PermissionsGraphMaterializationPlan {
  const budget = normalizeBudget(input.budget);
  const filters = normalizeFilters(input.filters);
  const omittedNodes: PermissionsGraphMaterializationOmission[] = [
    ...(input.preOmittedNodes ?? []),
  ];
  const omittedEdges: PermissionsGraphMaterializationOmission[] = [];
  const candidateById = new Map<string, CandidateNode>();
  for (const candidate of input.candidates) {
    if (!candidateById.has(candidate.id)) candidateById.set(candidate.id, candidate);
  }

  const includedCandidates: CandidateNode[] = [];
  for (const candidate of candidateById.values()) {
    const node = input.index.getNode(candidate.id);
    if (!node) {
      omittedNodes.push(Object.freeze({ id: candidate.id, reason: "unknown-node" }));
      continue;
    }
    if (!nodeAllowed(node, filters)) {
      omittedNodes.push(Object.freeze({ id: candidate.id, reason: "filtered-node" }));
      continue;
    }
    if (includedCandidates.length >= budget.maxNodes) {
      omittedNodes.push(Object.freeze({ id: candidate.id, reason: "node-budget" }));
      continue;
    }
    includedCandidates.push(candidate);
  }

  const includedNodeSet = new Set(includedCandidates.map((candidate) => candidate.id));
  const preferredEdgeIds = new Set(input.preferredEdgeIds ?? []);
  const candidateEdges = input.model.edges
    .filter((edge) => includedNodeSet.has(edge.sourceId) && includedNodeSet.has(edge.targetId))
    .sort((left, right) =>
      Number(!preferredEdgeIds.has(left.id)) - Number(!preferredEdgeIds.has(right.id)) ||
      edgePriority(left) - edgePriority(right) ||
      compareStrings(left.id, right.id)
    );
  const includedEdges: PermissionsGraphEdgeRecord[] = [];
  for (const edge of candidateEdges) {
    if (input.includeEdges === false) {
      omittedEdges.push(Object.freeze({ id: edge.id, reason: "edge-disabled" }));
      continue;
    }
    if (!edgeAllowed(edge, input.index, filters)) {
      omittedEdges.push(Object.freeze({ id: edge.id, reason: "filtered-edge" }));
      continue;
    }
    if (includedEdges.length >= budget.maxEdges) {
      omittedEdges.push(Object.freeze({ id: edge.id, reason: "edge-budget" }));
      continue;
    }
    includedEdges.push(edge);
  }

  const includedNodeIds = freezeSortedIds(includedCandidates.map((candidate) => candidate.id));
  const includedEdgeIds = freezeSortedIds(includedEdges.map((edge) => edge.id));
  const nodeReasonById = new Map(includedCandidates.map((candidate) => [candidate.id, candidate.reason]));
  const rendererSource = Object.freeze({
    kind: "model-slice" as const,
    nodeIds: includedNodeIds,
    edgeIds: includedEdgeIds,
    budget,
  });
  const frozenOmittedNodes = freezeOmissions(omittedNodes);
  const frozenOmittedEdges = freezeOmissions(omittedEdges);
  const truncated = [...frozenOmittedNodes, ...frozenOmittedEdges].some((omission) =>
    omission.reason.includes("budget")
  );
  return Object.freeze({
    kind: input.kind,
    sourceTopologyFingerprint: input.model.topologyFingerprint,
    layoutGeneration: input.layout.layoutGeneration,
    coordinateRevision: input.layout.coordinateRevision,
    budget,
    includedNodeIds,
    includedEdgeIds,
    nodeInclusions: Object.freeze(includedNodeIds.map((id) => Object.freeze({
      id,
      reason: nodeReasonById.get(id) ?? "candidate",
    }))),
    edgeInclusions: Object.freeze(includedEdgeIds.map((id) => Object.freeze({
      id,
      reason: input.edgeReason,
    }))),
    omittedNodes: frozenOmittedNodes,
    omittedEdges: frozenOmittedEdges,
    diagnostics: Object.freeze(uniqueSorted(input.diagnostics ?? [])),
    summary: buildSummary(
      candidateById.size,
      candidateEdges.length,
      Math.max(0, input.outsideScopeNodeCount ?? 0),
      frozenOmittedNodes,
      frozenOmittedEdges,
      truncated,
    ),
    rendererSource,
  });
}

function buildSummary(
  candidateNodeCount: number,
  candidateEdgeCount: number,
  outsideScopeNodeCount: number,
  omittedNodes: readonly PermissionsGraphMaterializationOmission[],
  omittedEdges: readonly PermissionsGraphMaterializationOmission[],
  truncated: boolean,
): PermissionsGraphMaterializationSummary {
  const counts: Record<string, number> = {};
  for (const omission of [...omittedNodes, ...omittedEdges]) {
    counts[omission.reason] = (counts[omission.reason] ?? 0) + 1;
  }
  if (outsideScopeNodeCount > 0) counts["outside-scope"] = outsideScopeNodeCount;
  return Object.freeze({
    candidateNodeCount,
    candidateEdgeCount,
    outsideScopeNodeCount,
    omissionReasonCounts: Object.freeze(Object.fromEntries(
      Object.entries(counts).sort((left, right) => compareStrings(left[0], right[0])),
    )),
    truncated,
  });
}

function buildSearchEntry(
  node: PermissionsGraphNodeRecord,
  index: PermissionsGraphIndex,
): PermissionsGraphSearchEntry {
  const rawFields = [
    node.label,
    node.path,
    node.userId,
    node.kind,
    node.role,
    node.displayName,
    node.email,
  ];
  for (const edgeId of index.getIncidentEdgeIds(node.id)) {
    const edge = index.getEdge(edgeId);
    if (!edge) continue;
    rawFields.push(edge.level, edge.label, edge.userId, edge.role);
    if (edge.level) rawFields.push(`access:${edge.level}`);
  }
  const fields = uniqueSorted(rawFields
    .filter((field): field is string => typeof field === "string" && field.length > 0)
    .map(normalizeSearchValue)
    .filter(Boolean));
  const tokens = new Set(fields.flatMap(tokenize));
  return Object.freeze({
    nodeId: node.id,
    label: normalizeSearchValue(node.label ?? node.path ?? node.userId ?? node.id),
    kind: node.kind,
    fields: Object.freeze(fields),
    tokens,
  });
}

function appendBoundedNeighbors(
  candidates: CandidateNode[],
  index: PermissionsGraphIndex,
  seedIds: readonly string[],
  maxNeighborsPerSeed: number,
  reason: string,
): void {
  if (maxNeighborsPerSeed <= 0) return;
  const seen = new Set(candidates.map((candidate) => candidate.id));
  for (const seedId of uniqueSorted(seedIds)) {
    let added = 0;
    for (const neighborId of index.getAdjacentNodeIds(seedId)) {
      if (seen.has(neighborId)) continue;
      candidates.push({ id: neighborId, reason });
      seen.add(neighborId);
      added += 1;
      if (added >= maxNeighborsPerSeed) break;
    }
  }
}

function aggregateChildModelIds(
  model: PermissionsGraphModel,
  index: PermissionsGraphIndex,
  descriptor: PermissionsGraphAggregateNodeDescriptor,
): string[] {
  if (descriptor.kind === "user") {
    return [...index.getAdjacentNodeIds(descriptor.id)].sort(compareStrings);
  }
  return model.nodes
    .filter((node) =>
      node.id !== descriptor.id &&
      !!node.path &&
      (node.kind === "file" || node.kind === "folder") &&
      pathWithin(node.path, descriptor.path)
    )
    .sort((left, right) =>
      compareStrings(left.path ?? "", right.path ?? "") || compareStrings(left.id, right.id)
    )
    .map((node) => node.id);
}

function validateAggregatePlan(
  model: PermissionsGraphModel,
  plan: PermissionsGraphAggregatePlan,
): void {
  if (plan.sourceTopologyFingerprint !== model.topologyFingerprint) {
    throw new PermissionsGraphMaterializationCompatibilityError(
      "PLAN_TOPOLOGY_MISMATCH",
      "The Phase 2 aggregate plan does not match the supplied model topology.",
    );
  }
  const nodeIds = plan.nodes.map((node) => node.id);
  const edgeIds = plan.edges.map((edge) => edge.id);
  const includedNodes = new Set(nodeIds);
  if (includedNodes.size !== nodeIds.length || new Set(edgeIds).size !== edgeIds.length) {
    throw new PermissionsGraphMaterializationCompatibilityError(
      "INVALID_AGGREGATE_PLAN",
      "The Phase 2 aggregate plan contains duplicate element IDs.",
    );
  }
  if (plan.edges.some((edge) => !includedNodes.has(edge.sourceId) || !includedNodes.has(edge.targetId))) {
    throw new PermissionsGraphMaterializationCompatibilityError(
      "INVALID_AGGREGATE_PLAN",
      "The Phase 2 aggregate plan contains a dangling edge.",
    );
  }
}

function assertPlanningInputs(
  model: PermissionsGraphModel,
  index: PermissionsGraphIndex,
  layout: PermissionsGraphLayoutStore,
): void {
  assertIndexMatchesModel(model, index);
  if (
    layout.model !== model ||
    layout.index !== index ||
    layout.topologyFingerprint !== model.topologyFingerprint
  ) {
    throw new PermissionsGraphMaterializationCompatibilityError(
      "LAYOUT_MODEL_MISMATCH",
      "The PermissionsGraphLayoutStore does not match the supplied model/index.",
    );
  }
}

function assertIndexMatchesModel(
  model: PermissionsGraphModel,
  index: PermissionsGraphIndex,
): void {
  if (
    model.nodes.some((node) => index.getNode(node.id) !== node) ||
    model.edges.some((edge) => index.getEdge(edge.id) !== edge)
  ) {
    throw new PermissionsGraphMaterializationCompatibilityError(
      "INDEX_MODEL_MISMATCH",
      "The PermissionsGraphIndex does not match the supplied model.",
    );
  }
}

interface NormalizedFilters {
  readonly selectedUserIds: ReadonlySet<string>;
  readonly accessLevels: Readonly<Record<PositiveAccessLevel, boolean>>;
  readonly nodeKinds: ReadonlySet<PermissionsGraphNodeKind> | null;
  readonly pathPrefix: string;
}

function normalizeFilters(filters: PermissionsGraphMaterializationFilters | undefined): NormalizedFilters {
  return {
    selectedUserIds: new Set((filters?.selectedUserIds ?? []).map((id) => id.trim().toLowerCase()).filter(Boolean)),
    accessLevels: Object.freeze({
      read: filters?.accessLevels?.read !== false,
      write: filters?.accessLevels?.write !== false,
      admin: filters?.accessLevels?.admin !== false,
    }),
    nodeKinds: filters?.nodeKinds ? new Set(filters.nodeKinds) : null,
    pathPrefix: normalizePath(filters?.pathPrefix ?? ""),
  };
}

function nodeAllowed(node: PermissionsGraphNodeRecord, filters: NormalizedFilters): boolean {
  if (filters.nodeKinds && !filters.nodeKinds.has(node.kind)) return false;
  if (
    filters.selectedUserIds.size > 0 &&
    node.kind === "user" &&
    (!node.userId || !filters.selectedUserIds.has(node.userId.toLowerCase()))
  ) return false;
  if (filters.pathPrefix && node.path && !pathWithin(node.path, filters.pathPrefix)) return false;
  return true;
}

function edgeAllowed(
  edge: PermissionsGraphEdgeRecord,
  index: PermissionsGraphIndex,
  filters: NormalizedFilters,
): boolean {
  if (edge.kind !== "permission") return true;
  const level = edge.level;
  if (!level || level === "none" || !filters.accessLevels[level]) return false;
  if (filters.selectedUserIds.size === 0) return true;
  const userId = edge.userId ?? index.getNode(edge.sourceId)?.userId;
  return !!userId && filters.selectedUserIds.has(userId.toLowerCase());
}

function normalizeBudget(raw: PermissionsGraphMaterializationBudget): PermissionsGraphMaterializationBudget {
  return Object.freeze({
    maxNodes: normalizeLimit(raw.maxNodes, 0),
    maxEdges: normalizeLimit(raw.maxEdges, 0),
  });
}

function normalizeLimit(value: number | undefined, fallback: number): number {
  if (value === undefined) return Math.max(0, Math.floor(fallback));
  if (!Number.isFinite(value)) return Math.max(0, Math.floor(fallback));
  return Math.max(0, Math.floor(value));
}

function nonNegative(value: number | undefined, fallback: number): number {
  return Number.isFinite(value) ? Math.max(0, value ?? fallback) : Math.max(0, fallback);
}

function normalizeBounds(bounds: PermissionsGraphSpatialBounds): PermissionsGraphSpatialBounds | null {
  if ([bounds.x1, bounds.y1, bounds.x2, bounds.y2].some((value) => !Number.isFinite(value))) {
    return null;
  }
  return Object.freeze({
    x1: Math.min(bounds.x1, bounds.x2),
    y1: Math.min(bounds.y1, bounds.y2),
    x2: Math.max(bounds.x1, bounds.x2),
    y2: Math.max(bounds.y1, bounds.y2),
  });
}

function sortSpatialByDistance(
  entries: readonly PermissionsGraphSpatialEntry[],
  center: { readonly x: number; readonly y: number },
): PermissionsGraphSpatialEntry[] {
  return [...entries].sort((left, right) =>
    distanceSquared(left, center) - distanceSquared(right, center) ||
    compareStrings(left.nodeId, right.nodeId)
  );
}

function distanceSquared(
  left: { readonly x: number; readonly y: number },
  right: { readonly x: number; readonly y: number },
): number {
  const dx = left.x - right.x;
  const dy = left.y - right.y;
  return dx * dx + dy * dy;
}

function pointInBounds(
  point: { readonly x: number; readonly y: number },
  bounds: PermissionsGraphSpatialBounds,
): boolean {
  return point.x >= bounds.x1 && point.x <= bounds.x2 &&
    point.y >= bounds.y1 && point.y <= bounds.y2;
}

function edgePriority(edge: PermissionsGraphEdgeRecord): number {
  return edge.kind === "containment" ? 0 : edge.kind === "permission" ? 1 : 2;
}

function freezeOmissions<T extends { readonly id: string; readonly reason: string }>(
  omissions: readonly T[],
): readonly PermissionsGraphMaterializationOmission[] {
  const unique = new Map<string, PermissionsGraphMaterializationOmission>();
  for (const omission of omissions) {
    const key = `${omission.id}\u0000${omission.reason}`;
    if (!unique.has(key)) unique.set(key, Object.freeze({ id: omission.id, reason: omission.reason }));
  }
  return Object.freeze(Array.from(unique.values()).sort((left, right) =>
    compareStrings(left.id, right.id) || compareStrings(left.reason, right.reason)
  ));
}

function freezeSortedIds<T extends string>(ids: Iterable<T>): readonly T[] {
  return Object.freeze(Array.from(new Set(ids)).sort(compareStrings));
}

function uniqueSorted<T extends string>(values: Iterable<T>): T[] {
  return Array.from(new Set(values)).sort(compareStrings);
}

function normalizeSearchValue(value: string): string {
  return value.trim().toLowerCase();
}

function tokenize(value: string): string[] {
  return value.split(/[^a-z0-9@._:/-]+/i).map(normalizeSearchValue).filter(Boolean);
}

function appendSetMapValue<K>(map: Map<K, Set<string>>, key: K, value: string): void {
  const values = map.get(key);
  if (values) values.add(value);
  else map.set(key, new Set([value]));
}

function freezeSetMap<K>(source: Map<K, Set<string>>, target: Map<K, readonly string[]>): void {
  for (const [key, values] of source) target.set(key, freezeSortedIds(values));
}

function normalizePath(path: string): string {
  const trimmed = path.trim();
  if (!trimmed) return "";
  const normalized = trimmed.replace(/\\/g, "/").replace(/\/+/g, "/").replace(/\/$/, "");
  return normalized.startsWith("/") ? normalized : `/${normalized}`;
}

function pathWithin(path: string, prefix: string): boolean {
  const normalizedPath = normalizePath(path);
  const normalizedPrefix = normalizePath(prefix);
  if (!normalizedPrefix || normalizedPrefix === "/") return true;
  return normalizedPath === normalizedPrefix || normalizedPath.startsWith(`${normalizedPrefix}/`);
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
