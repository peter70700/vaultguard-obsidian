/**
 * Renderer-independent aggregate and budget planning for the permissions graph.
 *
 * Phase 2 keeps this module beside the legacy aggregate pipeline. The live view
 * continues to use buildAggregatedGraphElements; this planner consumes the
 * Phase 1 model/index and returns frozen descriptors that later virtualization
 * phases can materialize without importing or owning Cytoscape.
 */

import {
  colorForUser,
  type GraphAccessLevel,
  type GraphBuilderInput,
  type GraphElement,
} from "./permissions-graph-data";
import {
  buildPermissionsGraphModelFromGraphInput,
  type PermissionsGraphIndex,
  type PermissionsGraphModel,
  type PermissionsGraphModelBuildResult,
  type PermissionsGraphNodeRecord,
} from "./permissions-graph-model";
import {
  DEFAULT_GRAPH_BUDGETS,
  normalizeGraphPath,
  normalizeOptionalGraphPath,
  type GraphComplexityBudgets,
  type GraphRuntimeOptions,
} from "./permissions-graph-scale";

type PositiveAccessLevel = Exclude<GraphAccessLevel, "none">;

export interface PermissionsGraphAggregateAccessLevels {
  readonly read: boolean;
  readonly write: boolean;
  readonly admin: boolean;
}

export interface PermissionsGraphAggregatePlanOptions {
  readonly maxRenderedNodes: number;
  readonly maxRenderedEdges: number;
  /** Folder aggregate cap; defaults to the legacy 75% node-budget share. */
  readonly maxAggregateNodes?: number;
  /** Permission edges allowed per folder aggregate. */
  readonly maxEdgesPerAggregate?: number;
  readonly showUserNodes?: boolean;
  readonly selectedUserIds?: readonly string[];
  readonly accessLevels?: PermissionsGraphAggregateAccessLevels;
  readonly pathPrefix?: string;
  readonly maxDepth?: number;
  readonly expiringOnly?: boolean;
  readonly includeFileSummaries?: boolean;
  readonly includeFolderSummaries?: boolean;
  readonly tieBreak?: "stable-id";
}

export interface PermissionsGraphNormalizedAggregateBudget {
  readonly maxRenderedNodes: number;
  readonly maxRenderedEdges: number;
  readonly maxAggregateNodes: number;
  readonly maxEdgesPerAggregate: number;
}

export type PermissionsGraphPlanNodeReason =
  | "aggregate-folder"
  | "aggregate-user";

export type PermissionsGraphPlanEdgeReason =
  | "aggregate-containment"
  | "aggregate-permission";

export type PermissionsGraphPlanOmissionReason =
  | "user-hidden"
  | "aggregate-node-budget"
  | "node-budget"
  | "edge-budget"
  | "per-aggregate-edge-budget"
  | "conflicting-id";

export type PermissionsGraphPlanDiagnosticCode =
  | "INVALID_NODE_BUDGET"
  | "INVALID_EDGE_BUDGET"
  | "INVALID_AGGREGATE_NODE_BUDGET"
  | "AGGREGATE_NODE_BUDGET_CLAMPED"
  | "INVALID_PER_AGGREGATE_EDGE_BUDGET"
  | "INVALID_DEPTH"
  | "PRE_AGGREGATED_SOURCE_IGNORED"
  | "SOURCE_AGGREGATE_ID_CONFLICT"
  | "INDEX_MODEL_MISMATCH";

export interface PermissionsGraphPlanDiagnostic {
  readonly code: PermissionsGraphPlanDiagnosticCode;
  readonly message: string;
}

export interface PermissionsGraphFolderAggregateDescriptor {
  readonly id: string;
  readonly kind: "folder";
  readonly reason: "aggregate-folder";
  readonly path: string;
  readonly label: string;
  readonly aggregate: true;
  readonly counts: {
    readonly readableFiles: number;
    readonly writableFiles: number;
    readonly adminFiles: number;
    readonly expiringGrants: number;
  };
}

export interface PermissionsGraphAggregateUserDescriptor {
  readonly id: string;
  readonly kind: "user";
  readonly reason: "aggregate-user";
  readonly userId: string;
  readonly label: string;
  readonly color: string;
  readonly aggregate: false;
}

export type PermissionsGraphAggregateNodeDescriptor =
  | PermissionsGraphFolderAggregateDescriptor
  | PermissionsGraphAggregateUserDescriptor;

export interface PermissionsGraphAggregateContainmentDescriptor {
  readonly id: string;
  readonly kind: "containment";
  readonly reason: "aggregate-containment";
  readonly sourceId: string;
  readonly targetId: string;
  readonly aggregate: true;
}

export interface PermissionsGraphAggregatePermissionDescriptor {
  readonly id: string;
  readonly kind: "permission";
  readonly reason: "aggregate-permission";
  readonly sourceId: string;
  readonly targetId: string;
  readonly userId: string;
  readonly path: string;
  readonly level: PositiveAccessLevel;
  readonly aggregate: true;
}

export type PermissionsGraphAggregateEdgeDescriptor =
  | PermissionsGraphAggregateContainmentDescriptor
  | PermissionsGraphAggregatePermissionDescriptor;

export interface PermissionsGraphPlanOmission {
  readonly id: string;
  readonly reason: PermissionsGraphPlanOmissionReason;
}

export interface PermissionsGraphAggregatePlan {
  readonly sourceTopologyFingerprint: string;
  readonly budget: PermissionsGraphNormalizedAggregateBudget;
  readonly nodes: readonly PermissionsGraphAggregateNodeDescriptor[];
  readonly edges: readonly PermissionsGraphAggregateEdgeDescriptor[];
  readonly folderAggregates: readonly PermissionsGraphFolderAggregateDescriptor[];
  readonly userNodes: readonly PermissionsGraphAggregateUserDescriptor[];
  readonly containmentEdges: readonly PermissionsGraphAggregateContainmentDescriptor[];
  readonly permissionEdges: readonly PermissionsGraphAggregatePermissionDescriptor[];
  readonly includedNodeIds: readonly string[];
  readonly includedEdgeIds: readonly string[];
  readonly omittedNodes: readonly PermissionsGraphPlanOmission[];
  readonly omittedEdges: readonly PermissionsGraphPlanOmission[];
  readonly hiddenNodeCount: number;
  readonly hiddenEdgeCount: number;
  readonly candidateNodeCount: number;
  readonly candidateEdgeCount: number;
  readonly filteredSourcePermissionEdgeCount: number;
  readonly truncated: boolean;
  readonly diagnostics: readonly PermissionsGraphPlanDiagnostic[];
}

interface AggregateFolderStats {
  readonly path: string;
  readableFiles: number;
  writableFiles: number;
  adminFiles: number;
  expiringGrants: number;
  readonly userLevels: Map<string, PositiveAccessLevel>;
}

interface PermissionCandidate {
  readonly id: string;
  readonly userId: string;
  readonly path: string;
  readonly level: PositiveAccessLevel;
  readonly sourceId: string;
  readonly targetId: string;
}

interface ContainmentCandidate {
  readonly id: string;
  readonly sourceId: string;
  readonly targetId: string;
}

interface NormalizedPlanOptions {
  readonly budget: PermissionsGraphNormalizedAggregateBudget;
  readonly showUserNodes: boolean;
  readonly selectedUserIds: ReadonlySet<string>;
  readonly accessLevels: PermissionsGraphAggregateAccessLevels;
  readonly pathPrefix: string;
  readonly maxDepth: number;
  readonly expiringOnly: boolean;
  readonly includeFileSummaries: boolean;
  readonly includeFolderSummaries: boolean;
}

/**
 * Convert the current filtered graph dataset/input to a Phase 1 planning model.
 * User records remain present even when the renderer's user-node toggle is off,
 * because aggregate counts and selected-user filters still depend on edges.
 */
export function buildPermissionsGraphPlanningModel(
  input: GraphBuilderInput,
): PermissionsGraphModelBuildResult {
  return buildPermissionsGraphModelFromGraphInput({
    ...input,
    includeUsers: true,
    includeFiles: input.includeFiles !== false,
    includeFolders: input.includeFolders !== false,
  });
}

/** Preserve the legacy scale options/budgets as explicit planner inputs. */
export function graphRuntimeOptionsToAggregatePlanOptions(
  options: GraphRuntimeOptions,
  budgets: GraphComplexityBudgets = DEFAULT_GRAPH_BUDGETS,
): PermissionsGraphAggregatePlanOptions {
  const maxRenderedNodes = budgets.maxRenderedNodes;
  const budgetEdgeCap = budgets.maxRenderedEdges;
  const maxRenderedEdges = Math.max(
    0,
    Math.min(budgetEdgeCap, Math.floor(options.maxEdges)),
  );
  return {
    maxRenderedNodes,
    maxRenderedEdges,
    maxAggregateNodes: Math.max(1, Math.floor(maxRenderedNodes * 0.75)),
    maxEdgesPerAggregate: maxRenderedEdges,
    showUserNodes: options.nodeTypes.users,
    selectedUserIds: options.selectedUsers,
    accessLevels: {
      read: options.accessLevels.read && !options.writableAdminOnly,
      write: options.accessLevels.write,
      admin: options.accessLevels.admin,
    },
    pathPrefix: options.pathPrefix,
    maxDepth: options.depth,
    expiringOnly: options.expiringOnly,
    includeFileSummaries: options.nodeTypes.files,
    includeFolderSummaries: options.nodeTypes.folders,
    tieBreak: "stable-id",
  };
}

/**
 * Produce a deterministic aggregate/budget plan from the Phase 1 model/index.
 * The current aggregate builder remains the live rendering source of truth.
 */
export function buildPermissionsGraphAggregatePlan(
  model: PermissionsGraphModel,
  index: PermissionsGraphIndex,
  rawOptions: PermissionsGraphAggregatePlanOptions,
): PermissionsGraphAggregatePlan {
  const diagnostics: PermissionsGraphPlanDiagnostic[] = [];
  const options = normalizePlanOptions(rawOptions, diagnostics);
  const sourceEdgeIds = new Set(model.edges.map((edge) => edge.id));
  const aggregateSourceCount =
    model.nodes.filter((node) => node.aggregate).length +
    model.edges.filter((edge) => edge.aggregate).length;
  if (aggregateSourceCount > 0) {
    diagnostics.push({
      code: "PRE_AGGREGATED_SOURCE_IGNORED",
      message: `Ignored ${aggregateSourceCount} pre-aggregated source record(s); the planner requires detailed Phase 1 topology.`,
    });
  }

  if (!indexMatchesModel(model, index)) {
    diagnostics.push({
      code: "INDEX_MODEL_MISMATCH",
      message: "The supplied PermissionsGraphIndex does not match the supplied model; missing indexed records were ignored.",
    });
  }

  const selectedUsers = options.selectedUserIds;
  let filteredSourcePermissionEdgeCount = 0;
  const conflictIds = new Set<string>();

  const eligiblePermissionEdges = (targetId: string) => {
    const eligible = [] as Array<{
      readonly userId: string;
      readonly level: PositiveAccessLevel;
      readonly expiring: boolean;
    }>;
    for (const edgeId of index.getEdgeIdsByTarget(targetId)) {
      const edge = index.getEdge(edgeId);
      if (!edge || edge.aggregate || edge.kind !== "permission") continue;
      if (edge.id.startsWith("agg:")) {
        conflictIds.add(edge.id);
        filteredSourcePermissionEdgeCount += 1;
        continue;
      }
      const level = positiveAccessLevel(edge.level);
      const sourceNode = index.getNode(edge.sourceId);
      const userId = edge.userId ?? sourceNode?.userId;
      if (!level || !userId) {
        filteredSourcePermissionEdgeCount += 1;
        continue;
      }
      if (!options.accessLevels[level]) {
        filteredSourcePermissionEdgeCount += 1;
        continue;
      }
      if (selectedUsers.size > 0 && !selectedUsers.has(userId.toLowerCase())) {
        filteredSourcePermissionEdgeCount += 1;
        continue;
      }
      if (options.expiringOnly && !edge.expiring) {
        filteredSourcePermissionEdgeCount += 1;
        continue;
      }
      eligible.push({ userId, level, expiring: edge.expiring });
    }
    return eligible.sort((left, right) =>
      compareStrings(left.userId, right.userId) || compareStrings(left.level, right.level)
    );
  };

  const folderStats = new Map<string, AggregateFolderStats>();
  const ensureFolder = (path: string): AggregateFolderStats => {
    const normalized = normalizeGraphPath(path);
    const existing = folderStats.get(normalized);
    if (existing) return existing;
    const stats: AggregateFolderStats = {
      path: normalized,
      readableFiles: 0,
      writableFiles: 0,
      adminFiles: 0,
      expiringGrants: 0,
      userLevels: new Map(),
    };
    folderStats.set(normalized, stats);
    return stats;
  };

  const visibleFilePaths = new Set<string>();
  const visibleFolderPaths = new Set<string>();
  if (options.includeFileSummaries) {
    for (const fileNode of sortedSourceNodes(model, "file")) {
      if (fileNode.aggregate || !fileNode.path) continue;
      const path = normalizeGraphPath(fileNode.path);
      if (!pathMatchesPrefix(path, options.pathPrefix)) continue;
      const edges = eligiblePermissionEdges(fileNode.id);
      if (edges.length === 0) continue;
      const folders = aggregateFoldersForPath(path, options.pathPrefix, options.maxDepth);
      if (folders.length === 0) continue;
      const statsChain = folders.map(ensureFolder);
      const writable = edges.some((edge) => edge.level === "write" || edge.level === "admin");
      const admin = edges.some((edge) => edge.level === "admin");
      for (const stats of statsChain) {
        stats.readableFiles += 1;
        if (writable) stats.writableFiles += 1;
        if (admin) stats.adminFiles += 1;
      }
      for (const edge of edges) {
        for (const stats of statsChain) {
          stats.userLevels.set(
            edge.userId,
            maxAccessLevel(stats.userLevels.get(edge.userId), edge.level),
          );
          if (edge.expiring) stats.expiringGrants += 1;
        }
      }
      visibleFilePaths.add(path);
      for (const folder of ancestorFolderPaths(path)) visibleFolderPaths.add(folder);
    }
  }

  if (options.includeFolderSummaries) {
    for (const folderNode of sortedSourceNodes(model, "folder")) {
      if (folderNode.aggregate || !folderNode.path) continue;
      const path = normalizeGraphPath(folderNode.path);
      if (!pathMatchesPrefix(path, options.pathPrefix)) continue;
      if (visibleFilePaths.size > 0 && !visibleFolderPaths.has(path)) continue;
      const edges = eligiblePermissionEdges(folderNode.id);
      if (edges.length === 0) continue;
      const folders = aggregateFoldersForFolder(path, options.pathPrefix, options.maxDepth);
      const statsChain = folders.map(ensureFolder);
      for (const edge of edges) {
        for (const stats of statsChain) {
          stats.userLevels.set(
            edge.userId,
            maxAccessLevel(stats.userLevels.get(edge.userId), edge.level),
          );
        }
      }
    }
  }

  for (const id of Array.from(conflictIds).sort(compareStrings)) {
    diagnostics.push({
      code: "SOURCE_AGGREGATE_ID_CONFLICT",
      message: `Ignored source permission edge with reserved aggregate id: ${id}`,
    });
  }

  const allStats = Array.from(folderStats.values()).sort((left, right) =>
    compareStrings(left.path, right.path)
  );
  const renderedStats = allStats.slice(0, options.budget.maxAggregateNodes);
  const renderedFolderPaths = new Set(renderedStats.map((stats) => stats.path));
  const folderAggregates = renderedStats.map(folderDescriptor);
  const omittedNodeMap = new Map<string, PermissionsGraphPlanOmission>();
  const omittedEdgeMap = new Map<string, PermissionsGraphPlanOmission>();
  for (const stats of allStats.slice(renderedStats.length)) {
    addOmission(omittedNodeMap, folderNodeId(stats.path), "aggregate-node-budget");
  }

  const containmentCandidates = buildContainmentCandidates(allStats);
  const permissionCandidates = buildPermissionCandidates(allStats);
  const candidateUserIds = Array.from(
    new Set(permissionCandidates.map((candidate) => candidate.userId)),
  ).sort(compareStrings);
  const renderedUserIds = new Set<string>();
  const userNodes: PermissionsGraphAggregateUserDescriptor[] = [];
  const containmentEdges: PermissionsGraphAggregateContainmentDescriptor[] = [];
  const permissionEdges: PermissionsGraphAggregatePermissionDescriptor[] = [];
  let edgeCount = 0;
  let truncated = allStats.length > renderedStats.length;

  for (const candidate of containmentCandidates) {
    const sourcePath = folderPathFromNodeId(candidate.sourceId);
    const targetPath = folderPathFromNodeId(candidate.targetId);
    if (!renderedFolderPaths.has(sourcePath) || !renderedFolderPaths.has(targetPath)) {
      addOmission(omittedEdgeMap, candidate.id, "aggregate-node-budget");
      continue;
    }
    if (edgeCount >= options.budget.maxRenderedEdges) {
      addOmission(omittedEdgeMap, candidate.id, "edge-budget");
      truncated = true;
      continue;
    }
    containmentEdges.push(Object.freeze({
      id: candidate.id,
      kind: "containment",
      reason: "aggregate-containment",
      sourceId: candidate.sourceId,
      targetId: candidate.targetId,
      aggregate: true,
    }));
    edgeCount += 1;
  }

  const permissionCountByTarget = new Map<string, number>();
  const firstOmissionByUser = new Map<string, PermissionsGraphPlanOmissionReason>();
  for (const candidate of permissionCandidates) {
    if (!renderedFolderPaths.has(candidate.path)) {
      addOmission(omittedEdgeMap, candidate.id, "aggregate-node-budget");
      firstOmissionByUser.set(
        candidate.userId,
        firstOmissionByUser.get(candidate.userId) ?? "aggregate-node-budget",
      );
      continue;
    }
    if (!options.showUserNodes) {
      addOmission(omittedEdgeMap, candidate.id, "user-hidden");
      firstOmissionByUser.set(candidate.userId, "user-hidden");
      continue;
    }
    const targetCount = permissionCountByTarget.get(candidate.targetId) ?? 0;
    if (targetCount >= options.budget.maxEdgesPerAggregate) {
      addOmission(omittedEdgeMap, candidate.id, "per-aggregate-edge-budget");
      firstOmissionByUser.set(
        candidate.userId,
        firstOmissionByUser.get(candidate.userId) ?? "per-aggregate-edge-budget",
      );
      truncated = true;
      continue;
    }
    if (edgeCount >= options.budget.maxRenderedEdges) {
      addOmission(omittedEdgeMap, candidate.id, "edge-budget");
      firstOmissionByUser.set(
        candidate.userId,
        firstOmissionByUser.get(candidate.userId) ?? "edge-budget",
      );
      truncated = true;
      continue;
    }
    if (!renderedUserIds.has(candidate.userId)) {
      if (folderAggregates.length + userNodes.length >= options.budget.maxRenderedNodes) {
        addOmission(omittedEdgeMap, candidate.id, "node-budget");
        addOmission(omittedNodeMap, userNodeId(candidate.userId), "node-budget");
        firstOmissionByUser.set(candidate.userId, "node-budget");
        truncated = true;
        continue;
      }
      userNodes.push(userDescriptor(candidate.userId, index));
      renderedUserIds.add(candidate.userId);
    }
    if (sourceEdgeIds.has(candidate.id)) {
      addOmission(omittedEdgeMap, candidate.id, "conflicting-id");
      firstOmissionByUser.set(
        candidate.userId,
        firstOmissionByUser.get(candidate.userId) ?? "conflicting-id",
      );
      truncated = true;
      continue;
    }
    permissionEdges.push(Object.freeze({
      id: candidate.id,
      kind: "permission",
      reason: "aggregate-permission",
      sourceId: candidate.sourceId,
      targetId: candidate.targetId,
      userId: candidate.userId,
      path: candidate.path,
      level: candidate.level,
      aggregate: true,
    }));
    permissionCountByTarget.set(candidate.targetId, targetCount + 1);
    edgeCount += 1;
  }

  for (const userId of candidateUserIds) {
    if (renderedUserIds.has(userId)) continue;
    addOmission(
      omittedNodeMap,
      userNodeId(userId),
      firstOmissionByUser.get(userId) ?? (options.showUserNodes ? "edge-budget" : "user-hidden"),
    );
  }

  const nodes = Object.freeze([
    ...folderAggregates,
    ...userNodes.sort((left, right) => compareStrings(left.id, right.id)),
  ] as PermissionsGraphAggregateNodeDescriptor[]);
  const edges = Object.freeze([
    ...containmentEdges,
    ...permissionEdges,
  ] as PermissionsGraphAggregateEdgeDescriptor[]);
  const omittedNodes = freezeSortedOmissions(omittedNodeMap);
  const omittedEdges = freezeSortedOmissions(omittedEdgeMap);

  // Folder/user node IDs intentionally reuse the current stable detailed IDs;
  // only duplicate IDs inside the plan would be invalid.
  const includedNodeIds = freezeUniqueIds(nodes.map((node) => node.id));
  const includedEdgeIds = freezeUniqueIds(edges.map((edge) => edge.id));
  if (includedNodeIds.length !== nodes.length || includedEdgeIds.length !== edges.length) {
    truncated = true;
  }

  return Object.freeze({
    sourceTopologyFingerprint: model.topologyFingerprint,
    budget: options.budget,
    nodes,
    edges,
    folderAggregates: Object.freeze(folderAggregates),
    userNodes: Object.freeze(userNodes),
    containmentEdges: Object.freeze(containmentEdges),
    permissionEdges: Object.freeze(permissionEdges),
    includedNodeIds,
    includedEdgeIds,
    omittedNodes,
    omittedEdges,
    hiddenNodeCount: omittedNodes.length,
    hiddenEdgeCount: omittedEdges.length,
    candidateNodeCount: allStats.length + candidateUserIds.length,
    candidateEdgeCount: containmentCandidates.length + permissionCandidates.length,
    filteredSourcePermissionEdgeCount,
    truncated,
    diagnostics: Object.freeze(diagnostics),
  });
}

/** Explicit compatibility adapter; the planner itself never returns elements. */
export function permissionsGraphAggregatePlanToElements(
  plan: PermissionsGraphAggregatePlan,
): GraphElement[] {
  const nodes = plan.nodes.map((node): GraphElement => {
    if (node.kind === "folder") {
      return {
        data: {
          id: node.id,
          kind: "folder",
          label: node.label,
          path: node.path,
          aggregate: true,
          readableFiles: node.counts.readableFiles,
          writableFiles: node.counts.writableFiles,
          adminFiles: node.counts.adminFiles,
          expiringGrants: node.counts.expiringGrants,
        },
        classes: "folder aggregate",
      };
    }
    return {
      data: {
        id: node.id,
        kind: "user",
        label: node.label,
        userId: node.userId,
        color: node.color,
      },
      classes: "user aggregate",
    };
  });
  const edges = plan.edges.map((edge): GraphElement => {
    if (edge.kind === "containment") {
      return {
        data: {
          id: edge.id,
          kind: "containment",
          source: edge.sourceId,
          target: edge.targetId,
          aggregate: true,
        },
        classes: "containment aggregate",
      };
    }
    return {
      data: {
        id: edge.id,
        kind: "permission",
        source: edge.sourceId,
        target: edge.targetId,
        level: edge.level,
        label: edge.level,
        userId: edge.userId,
        path: edge.path,
        aggregate: true,
      },
      classes: `permission allow level-${edge.level} aggregate`,
    };
  });
  return [...nodes, ...edges];
}

function normalizePlanOptions(
  options: PermissionsGraphAggregatePlanOptions,
  diagnostics: PermissionsGraphPlanDiagnostic[],
): NormalizedPlanOptions {
  const maxRenderedNodes = normalizeBudget(
    options.maxRenderedNodes,
    1,
    "INVALID_NODE_BUDGET",
    "Rendered node budget must be a finite integer of at least 1; using 1.",
    diagnostics,
  );
  const maxRenderedEdges = normalizeBudget(
    options.maxRenderedEdges,
    0,
    "INVALID_EDGE_BUDGET",
    "Rendered edge budget must be a finite non-negative integer; using 0.",
    diagnostics,
  );
  const legacyAggregateShare = Math.max(1, Math.floor(maxRenderedNodes * 0.75));
  let maxAggregateNodes = options.maxAggregateNodes === undefined
    ? legacyAggregateShare
    : normalizeBudget(
        options.maxAggregateNodes,
        1,
        "INVALID_AGGREGATE_NODE_BUDGET",
        "Aggregate node budget must be a finite integer of at least 1; using 1.",
        diagnostics,
      );
  if (maxAggregateNodes > maxRenderedNodes) {
    maxAggregateNodes = maxRenderedNodes;
    diagnostics.push({
      code: "AGGREGATE_NODE_BUDGET_CLAMPED",
      message: "Aggregate node budget exceeded the rendered node budget and was clamped.",
    });
  }
  const maxEdgesPerAggregate = options.maxEdgesPerAggregate === undefined
    ? maxRenderedEdges
    : normalizeBudget(
        options.maxEdgesPerAggregate,
        0,
        "INVALID_PER_AGGREGATE_EDGE_BUDGET",
        "Per-aggregate edge budget must be a finite non-negative integer; using the rendered edge budget.",
        diagnostics,
        maxRenderedEdges,
      );
  let maxDepth = options.maxDepth ?? 2;
  if (!Number.isFinite(maxDepth) || maxDepth < 1 || maxDepth > 8) {
    diagnostics.push({
      code: "INVALID_DEPTH",
      message: "Aggregate depth must be a finite integer from 1 through 8 and was clamped.",
    });
  }
  maxDepth = Math.max(1, Math.min(8, Math.floor(Number.isFinite(maxDepth) ? maxDepth : 1)));
  const selectedUserIds = new Set(
    (options.selectedUserIds ?? [])
      .filter((entry): entry is string => typeof entry === "string" && entry.trim().length > 0)
      .map((entry) => entry.trim().toLowerCase()),
  );
  return {
    budget: Object.freeze({
      maxRenderedNodes,
      maxRenderedEdges,
      maxAggregateNodes,
      maxEdgesPerAggregate: Math.min(maxEdgesPerAggregate, maxRenderedEdges),
    }),
    showUserNodes: options.showUserNodes !== false,
    selectedUserIds,
    accessLevels: Object.freeze({
      read: options.accessLevels?.read !== false,
      write: options.accessLevels?.write !== false,
      admin: options.accessLevels?.admin !== false,
    }),
    pathPrefix: normalizeOptionalGraphPath(options.pathPrefix),
    maxDepth,
    expiringOnly: options.expiringOnly === true,
    includeFileSummaries: options.includeFileSummaries !== false,
    includeFolderSummaries: options.includeFolderSummaries !== false,
  };
}

function normalizeBudget(
  value: number,
  minimum: number,
  code: PermissionsGraphPlanDiagnosticCode,
  message: string,
  diagnostics: PermissionsGraphPlanDiagnostic[],
  fallback = minimum,
): number {
  if (!Number.isFinite(value) || value < minimum) {
    diagnostics.push({ code, message });
    return fallback;
  }
  return Math.floor(value);
}

function indexMatchesModel(model: PermissionsGraphModel, index: PermissionsGraphIndex): boolean {
  return model.nodes.every((node) => index.getNode(node.id) === node) &&
    model.edges.every((edge) => index.getEdge(edge.id) === edge);
}

function sortedSourceNodes(
  model: PermissionsGraphModel,
  kind: "file" | "folder",
): PermissionsGraphNodeRecord[] {
  return model.nodes
    .filter((node) => node.kind === kind)
    .sort((left, right) =>
      compareStrings(left.path ?? "", right.path ?? "") || compareStrings(left.id, right.id)
    );
}

function folderDescriptor(stats: AggregateFolderStats): PermissionsGraphFolderAggregateDescriptor {
  return Object.freeze({
    id: folderNodeId(stats.path),
    kind: "folder",
    reason: "aggregate-folder",
    path: stats.path,
    label: `${folderLabel(stats.path)} (${stats.readableFiles})`,
    aggregate: true,
    counts: Object.freeze({
      readableFiles: stats.readableFiles,
      writableFiles: stats.writableFiles,
      adminFiles: stats.adminFiles,
      expiringGrants: stats.expiringGrants,
    }),
  });
}

function userDescriptor(
  userId: string,
  index: PermissionsGraphIndex,
): PermissionsGraphAggregateUserDescriptor {
  const source = index.getNode(userNodeId(userId));
  const color = typeof source?.data.color === "string" ? source.data.color : colorForUser(userId);
  return Object.freeze({
    id: userNodeId(userId),
    kind: "user",
    reason: "aggregate-user",
    userId,
    label: source?.label ?? source?.displayName ?? source?.email ?? userId,
    color,
    aggregate: false,
  });
}

function buildContainmentCandidates(
  stats: readonly AggregateFolderStats[],
): ContainmentCandidate[] {
  const paths = new Set(stats.map((entry) => entry.path));
  const candidates: ContainmentCandidate[] = [];
  for (const entry of stats) {
    const parent = parentFolderPath(entry.path);
    if (!parent || !paths.has(parent)) continue;
    const sourceId = folderNodeId(parent);
    const targetId = folderNodeId(entry.path);
    candidates.push({
      id: `contain:${sourceId}->${targetId}`,
      sourceId,
      targetId,
    });
  }
  return candidates.sort((left, right) => compareStrings(left.id, right.id));
}

function buildPermissionCandidates(
  stats: readonly AggregateFolderStats[],
): PermissionCandidate[] {
  const candidates: PermissionCandidate[] = [];
  for (const entry of stats) {
    for (const [userId, level] of Array.from(entry.userLevels.entries()).sort((left, right) =>
      compareStrings(left[0], right[0])
    )) {
      candidates.push({
        id: `agg:${userId}->${entry.path}`,
        userId,
        path: entry.path,
        level,
        sourceId: userNodeId(userId),
        targetId: folderNodeId(entry.path),
      });
    }
  }
  return candidates.sort((left, right) =>
    compareStrings(left.path, right.path) || compareStrings(left.userId, right.userId)
  );
}

function addOmission(
  map: Map<string, PermissionsGraphPlanOmission>,
  id: string,
  reason: PermissionsGraphPlanOmissionReason,
): void {
  if (!map.has(id)) map.set(id, Object.freeze({ id, reason }));
}

function freezeSortedOmissions(
  map: Map<string, PermissionsGraphPlanOmission>,
): readonly PermissionsGraphPlanOmission[] {
  return Object.freeze(
    Array.from(map.values()).sort((left, right) => compareStrings(left.id, right.id)),
  );
}

function freezeUniqueIds(ids: readonly string[]): readonly string[] {
  return Object.freeze(Array.from(new Set(ids)));
}

function positiveAccessLevel(level: GraphAccessLevel | null): PositiveAccessLevel | null {
  return level === "read" || level === "write" || level === "admin" ? level : null;
}

function maxAccessLevel(
  current: PositiveAccessLevel | undefined,
  next: PositiveAccessLevel,
): PositiveAccessLevel {
  if (!current) return next;
  const rank = { read: 1, write: 2, admin: 3 } as const;
  return rank[next] > rank[current] ? next : current;
}

function aggregateFoldersForPath(path: string, prefix: string, maxDepth: number): string[] {
  const normalized = normalizeGraphPath(path);
  const ancestors = ancestorFolderPaths(normalized);
  return limitFoldersByPrefixAndDepth(
    ancestors.length > 0 ? ancestors : ["/"],
    prefix,
    maxDepth,
  );
}

function aggregateFoldersForFolder(path: string, prefix: string, maxDepth: number): string[] {
  const normalized = normalizeGraphPath(path);
  const folders = normalized === "/"
    ? ["/"]
    : [...ancestorFolderPaths(`${normalized}/__file`), normalized].map(normalizeGraphPath);
  return limitFoldersByPrefixAndDepth(folders, prefix, maxDepth);
}

function limitFoldersByPrefixAndDepth(
  folders: string[],
  prefix: string,
  maxDepth: number,
): string[] {
  const scoped = prefix
    ? folders.filter((folder) =>
        pathIsWithinPrefix(folder, prefix) || pathIsWithinPrefix(prefix, folder)
      )
    : folders;
  if (scoped.length === 0 && prefix) return [prefix];
  const prefixDepth = prefix ? pathDepth(prefix) : 0;
  return scoped
    .filter((folder) => pathDepth(folder) - prefixDepth <= maxDepth)
    .slice(0, maxDepth + 1);
}

function ancestorFolderPaths(path: string): string[] {
  const segments = path.split("/").filter(Boolean);
  const folders: string[] = [];
  for (let index = 1; index < segments.length; index += 1) {
    folders.push(`/${segments.slice(0, index).join("/")}`);
  }
  return folders;
}

function pathMatchesPrefix(path: string, prefix: string): boolean {
  return !prefix || pathIsWithinPrefix(path, prefix);
}

function pathIsWithinPrefix(path: string, prefix: string): boolean {
  const normalizedPath = normalizeGraphPath(path);
  const normalizedPrefix = normalizeGraphPath(prefix);
  return normalizedPath === normalizedPrefix || normalizedPath.startsWith(`${normalizedPrefix}/`);
}

function parentFolderPath(path: string): string | null {
  if (path === "/") return null;
  const parts = path.split("/").filter(Boolean);
  if (parts.length <= 1) return null;
  return `/${parts.slice(0, -1).join("/")}`;
}

function folderPathFromNodeId(id: string): string {
  return id.startsWith("folder:") ? id.slice("folder:".length) : id;
}

function folderLabel(path: string): string {
  if (path === "/") return "Vault root";
  const parts = path.split("/").filter(Boolean);
  return `${parts[parts.length - 1] ?? path}/`;
}

function pathDepth(path: string): number {
  return path === "/" ? 0 : path.split("/").filter(Boolean).length;
}

function folderNodeId(path: string): string {
  return `folder:${path}`;
}

function userNodeId(userId: string): string {
  return `user:${userId}`;
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
