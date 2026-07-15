import type {
  PermissionsGraphBackgroundMode,
  PermissionsGraphBackgroundPattern,
  PermissionsGraphColorMode,
  PermissionsGraphLabelsMode,
  PermissionsGraphLayoutMode,
  PermissionsGraphRenderMode,
  PermissionsGraphSavedState,
  PermissionsGraphSectionMode,
  PermissionsGraphSizeMode,
  PermissionsGraphSortDirection,
  PermissionsGraphSortMode,
} from "../../types";
import { explainAccess, pathMatchesPattern, type ExplainRule, type ExplainVaultRole } from "./permission-explain";
import {
  ancestorFolders,
  colorForUser,
  type GraphAccessLevel,
  type GraphElement,
  type GraphMember,
  type GraphPathSummary,
  type GraphPrincipal,
} from "./permissions-graph-data";

export type GraphActualMode = "detailed" | "aggregated" | "refused";
export type GraphSearchScope = "all" | "user" | "file" | "folder";

export interface GraphComplexityBudgets {
  maxRenderedNodes: number;
  maxRenderedEdges: number;
  maxRenderedLabels: number;
  maxExplainRows: number;
  maxForceLayoutEdges: number;
  maxInitialFiles: number;
  largeGraphThreshold: number;
}

export interface GraphNodeTypeOptions {
  users: boolean;
  files: boolean;
  folders: boolean;
}

export interface GraphAccessLevelOptions {
  read: boolean;
  write: boolean;
  admin: boolean;
}

export interface GraphStudioPaletteOptions {
  user: string;
  file: string;
  folder: string;
  read: string;
  write: string;
  admin: string;
  low: string;
  medium: string;
  high: string;
}

export interface GraphStudioAppearanceOptions {
  backgroundMode: PermissionsGraphBackgroundMode;
  backgroundPattern: PermissionsGraphBackgroundPattern;
  backgroundPrimary: string;
  backgroundSecondary: string;
  colorMode: PermissionsGraphColorMode;
  customPalette: boolean;
  palette: GraphStudioPaletteOptions;
  sizeMode: PermissionsGraphSizeMode;
  nodeScale: number;
  edgeScale: number;
  /** Multiplier for all label font sizes in the graph (Graph Studio → Text size). */
  labelScale: number;
}

export interface GraphStudioArrangementOptions {
  sectionBy: PermissionsGraphSectionMode;
  sortBy: PermissionsGraphSortMode;
  sortDirection: PermissionsGraphSortDirection;
}

export interface GraphRuntimeOptions {
  renderMode: PermissionsGraphRenderMode;
  layoutMode: PermissionsGraphLayoutMode;
  labelsMode: PermissionsGraphLabelsMode;
  pathPrefix: string;
  searchQuery: string;
  searchScope: GraphSearchScope;
  selectedUsers: string[];
  accessLevels: GraphAccessLevelOptions;
  nodeTypes: GraphNodeTypeOptions;
  expiringOnly: boolean;
  writableAdminOnly: boolean;
  explicitRulesOnly: boolean;
  maxFiles: number;
  maxEdges: number;
  depth: number;
  debugExpanded: boolean;
  appearance: GraphStudioAppearanceOptions;
  arrangement: GraphStudioArrangementOptions;
}

export interface GraphDatasetForScale {
  vaultId: string;
  members: GraphMember[];
  summaries: GraphPathSummary[];
  folderSummaries?: GraphPathSummary[];
  rules?: ExplainRule[];
}

export interface FilteredGraphDataset extends GraphDatasetForScale {
  folderSummaries: GraphPathSummary[];
  readableFileCount: number;
  readableFolderCount: number;
  omittedByMaxFiles: number;
  omittedByMaxEdges: number;
  omittedByFilters: number;
}

export interface GraphComplexityEstimate {
  nodeCount: number;
  edgeCount: number;
  labelCount: number;
  fileNodeCount: number;
  folderNodeCount: number;
  userNodeCount: number;
  permissionEdgeCount: number;
  containmentEdgeCount: number;
}

export interface GraphRenderDecision {
  requestedMode: PermissionsGraphRenderMode;
  actualMode: GraphActualMode;
  large: boolean;
  exceeded: string[];
  disabled: string[];
  labelModeUsed: "on" | "off";
  layoutModeUsed: "radial" | "force" | "grid" | "folder" | "sections";
  hoverEnabled: boolean;
  animationEnabled: boolean;
}

export interface AggregatedGraphResult {
  elements: GraphElement[];
  folderCount: number;
  userCount: number;
  edgeCount: number;
  truncated: boolean;
}

export interface GraphDebugReadoutModel {
  requestedMode: PermissionsGraphRenderMode;
  actualMode: GraphActualMode;
  nodeCount: number;
  edgeCount: number;
  estimatedNodeCount: number;
  estimatedEdgeCount: number;
  selectedLayout: GraphRenderDecision["layoutModeUsed"];
  labelMode: GraphRenderDecision["labelModeUsed"];
  activeDepth: number;
  maxFiles: number;
  maxEdges: number;
  exceeded: string[];
  disabled: string[];
}

export const DEFAULT_GRAPH_BUDGETS: GraphComplexityBudgets = {
  maxRenderedNodes: 900,
  maxRenderedEdges: 1600,
  maxRenderedLabels: 220,
  maxExplainRows: 60,
  maxForceLayoutEdges: 350,
  maxInitialFiles: 1000,
  largeGraphThreshold: 1200,
};

export const DEFAULT_GRAPH_STUDIO_PALETTE: GraphStudioPaletteOptions = {
  user: "#7c3aed",
  file: "#14b8a6",
  folder: "#f59e0b",
  read: "#22c55e",
  write: "#f59e0b",
  admin: "#ef4444",
  low: "#94a3b8",
  medium: "#3b82f6",
  high: "#a855f7",
};

export const DEFAULT_GRAPH_STUDIO_APPEARANCE: GraphStudioAppearanceOptions = {
  backgroundMode: "theme",
  backgroundPattern: "none",
  backgroundPrimary: "#1e1e1e",
  backgroundSecondary: "#252a34",
  colorMode: "current",
  customPalette: false,
  palette: { ...DEFAULT_GRAPH_STUDIO_PALETTE },
  sizeMode: "standard",
  nodeScale: 1,
  edgeScale: 1,
  labelScale: 1,
};

export const DEFAULT_GRAPH_STUDIO_ARRANGEMENT: GraphStudioArrangementOptions = {
  sectionBy: "folder",
  sortBy: "name",
  sortDirection: "asc",
};

export const DEFAULT_GRAPH_OPTIONS: GraphRuntimeOptions = {
  renderMode: "auto",
  layoutMode: "auto",
  labelsMode: "auto",
  pathPrefix: "",
  searchQuery: "",
  searchScope: "all",
  selectedUsers: [],
  accessLevels: { read: true, write: true, admin: true },
  nodeTypes: { users: true, files: true, folders: true },
  expiringOnly: false,
  writableAdminOnly: false,
  explicitRulesOnly: false,
  maxFiles: DEFAULT_GRAPH_BUDGETS.maxInitialFiles,
  maxEdges: DEFAULT_GRAPH_BUDGETS.maxRenderedEdges,
  depth: 2,
  debugExpanded: false,
  appearance: {
    ...DEFAULT_GRAPH_STUDIO_APPEARANCE,
    palette: { ...DEFAULT_GRAPH_STUDIO_APPEARANCE.palette },
  },
  arrangement: { ...DEFAULT_GRAPH_STUDIO_ARRANGEMENT },
};

const MAX_SAVED_VAULT_STATES = 50;
const MAX_SELECTED_USERS = 32;
const MAX_TEXT_FILTER_LENGTH = 240;
const GRAPH_STUDIO_PALETTE_KEYS = [
  "user",
  "file",
  "folder",
  "read",
  "write",
  "admin",
  "low",
  "medium",
  "high",
] as const;

export function normalizeGraphStudioColor(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim().toLowerCase();
  return /^#[0-9a-f]{6}$/.test(normalized) ? normalized : undefined;
}

export function normalizeGraphPath(path: string): string {
  const trimmed = path.trim();
  if (!trimmed || trimmed === "/") return "/";
  const normalized = trimmed.replace(/\\/g, "/").replace(/\/+/g, "/").replace(/\/$/, "");
  return normalized.startsWith("/") ? normalized : `/${normalized}`;
}

export function normalizeOptionalGraphPath(path: unknown): string {
  if (typeof path !== "string") return "";
  const trimmed = path.trim().slice(0, MAX_TEXT_FILTER_LENGTH);
  if (!trimmed) return "";
  return normalizeGraphPath(trimmed);
}

export function normalizeGraphOptions(
  defaults?: unknown,
  vaultState?: unknown,
  budgets: GraphComplexityBudgets = DEFAULT_GRAPH_BUDGETS,
): GraphRuntimeOptions {
  const base = parsePartialGraphOptions(defaults, budgets);
  const state = parsePartialGraphOptions(vaultState, budgets);
  return {
    ...DEFAULT_GRAPH_OPTIONS,
    ...base,
    ...state,
    accessLevels: {
      ...DEFAULT_GRAPH_OPTIONS.accessLevels,
      ...base.accessLevels,
      ...state.accessLevels,
    },
    nodeTypes: {
      ...DEFAULT_GRAPH_OPTIONS.nodeTypes,
      ...base.nodeTypes,
      ...state.nodeTypes,
    },
    appearance: {
      ...DEFAULT_GRAPH_OPTIONS.appearance,
      ...base.appearance,
      ...state.appearance,
      palette: {
        ...DEFAULT_GRAPH_OPTIONS.appearance.palette,
        ...base.appearance?.palette,
        ...state.appearance?.palette,
      },
    },
    arrangement: {
      ...DEFAULT_GRAPH_OPTIONS.arrangement,
      ...base.arrangement,
      ...state.arrangement,
    },
    selectedUsers: state.selectedUsers ?? base.selectedUsers ?? [],
  };
}

export function graphOptionsToSavedState(options: GraphRuntimeOptions): PermissionsGraphSavedState {
  return {
    schemaVersion: 2,
    renderMode: options.renderMode,
    layoutMode: options.layoutMode,
    labelsMode: options.labelsMode,
    pathPrefix: options.pathPrefix || undefined,
    searchQuery: options.searchQuery || undefined,
    searchScope: options.searchScope,
    selectedUsers: options.selectedUsers.slice(0, MAX_SELECTED_USERS),
    accessLevels: { ...options.accessLevels },
    nodeTypes: { ...options.nodeTypes },
    expiringOnly: options.expiringOnly || undefined,
    writableAdminOnly: options.writableAdminOnly || undefined,
    explicitRulesOnly: options.explicitRulesOnly || undefined,
    maxFiles: options.maxFiles,
    maxEdges: options.maxEdges,
    depth: options.depth,
    debugExpanded: options.debugExpanded || undefined,
    appearance: {
      ...options.appearance,
      palette: { ...options.appearance.palette },
    },
    arrangement: { ...options.arrangement },
    updatedAt: new Date().toISOString(),
  };
}

export function resetGraphStudioAppearance(options: GraphRuntimeOptions): GraphRuntimeOptions {
  return {
    ...options,
    appearance: {
      ...DEFAULT_GRAPH_STUDIO_APPEARANCE,
      palette: { ...DEFAULT_GRAPH_STUDIO_APPEARANCE.palette },
    },
  };
}

export function resetGraphStudioArrangement(options: GraphRuntimeOptions): GraphRuntimeOptions {
  return {
    ...options,
    layoutMode: DEFAULT_GRAPH_OPTIONS.layoutMode,
    labelsMode: DEFAULT_GRAPH_OPTIONS.labelsMode,
    arrangement: { ...DEFAULT_GRAPH_STUDIO_ARRANGEMENT },
  };
}

export function resetGraphStudioOptions(options: GraphRuntimeOptions): GraphRuntimeOptions {
  return resetGraphStudioArrangement(resetGraphStudioAppearance(options));
}

export function upsertGraphVaultState(
  states: Record<string, PermissionsGraphSavedState> | undefined,
  vaultId: string,
  state: PermissionsGraphSavedState,
): Record<string, PermissionsGraphSavedState> {
  const next = { ...(states ?? {}) };
  next[vaultId] = state;
  const entries = Object.entries(next).sort((a, b) =>
    String(b[1].updatedAt ?? "").localeCompare(String(a[1].updatedAt ?? "")),
  );
  return Object.fromEntries(entries.slice(0, MAX_SAVED_VAULT_STATES));
}

export function removeGraphVaultState(
  states: Record<string, PermissionsGraphSavedState> | undefined,
  vaultId: string,
): Record<string, PermissionsGraphSavedState> {
  const next = { ...(states ?? {}) };
  delete next[vaultId];
  return next;
}

export function filterGraphDataset(
  input: GraphDatasetForScale,
  options: GraphRuntimeOptions,
  budgets: GraphComplexityBudgets = DEFAULT_GRAPH_BUDGETS,
): FilteredGraphDataset {
  const maxFiles = clampInt(options.maxFiles, 1, budgets.maxInitialFiles);
  const maxEdges = clampInt(options.maxEdges, 0, budgets.maxRenderedEdges);
  const selectedUsers = new Set(options.selectedUsers.map((id) => id.toLowerCase()));
  const memberById = new Map(input.members.map((member) => [member.userId, member]));
  const normalizedRules = input.rules ?? [];
  const now = new Date().toISOString();
  let omittedByFilters = 0;
  let omittedByMaxEdges = 0;

  const filterSummary = (summary: GraphPathSummary, kind: "file" | "folder"): GraphPathSummary | null => {
    if (!summary.principals || summary.principals.length === 0) return null;
    const path = normalizeGraphPath(summary.path);
    if (!pathMatchesActivePathFilters(path, kind, options, memberById, summary.principals)) {
      omittedByFilters += 1;
      return null;
    }

    const principals = summary.principals.filter((principal) => {
      if (!principal.level || principal.level === "none") return false;
      if (!options.accessLevels[principal.level]) return false;
      if (options.writableAdminOnly && principal.level !== "write" && principal.level !== "admin") return false;
      if (selectedUsers.size > 0 && !selectedUsers.has(principal.userId.toLowerCase())) return false;
      if (options.searchQuery && (options.searchScope === "user")) {
        const label = principalSearchLabel(principal, memberById.get(principal.userId));
        if (!label.includes(options.searchQuery.toLowerCase())) return false;
      }
      if (options.expiringOnly && !hasExpiringRule(principal, path, normalizedRules, memberById, now)) {
        return false;
      }
      if (options.explicitRulesOnly && !hasLiveRuleForPrincipalPath(principal, path, normalizedRules, memberById, now)) {
        return false;
      }
      return true;
    });

    if (principals.length === 0) {
      omittedByFilters += 1;
      return null;
    }

    return { ...summary, path, principals };
  };

  const filteredFiles: GraphPathSummary[] = [];
  let omittedByMaxFiles = 0;
  for (const summary of input.summaries) {
    if (!options.nodeTypes.files) {
      omittedByFilters += 1;
      continue;
    }
    const filtered = filterSummary(summary, "file");
    if (!filtered) continue;
    if (filteredFiles.length >= maxFiles) {
      omittedByMaxFiles += 1;
      continue;
    }
    filteredFiles.push(filtered);
  }

  const visibleFolderPaths = new Set(
    filteredFiles.flatMap((summary) => ancestorFolders(summary.path).map(normalizeGraphPath)),
  );
  const filteredFolders: GraphPathSummary[] = [];
  if (options.nodeTypes.folders) {
    for (const summary of input.folderSummaries ?? []) {
      const path = normalizeGraphPath(summary.path);
      if (filteredFiles.length > 0 && !visibleFolderPaths.has(path)) continue;
      const filtered = filterSummary({ ...summary, path }, "folder");
      if (filtered) filteredFolders.push(filtered);
    }
  }

  const cappedFiles: GraphPathSummary[] = [];
  const cappedFolders: GraphPathSummary[] = [];
  let permissionEdges = 0;
  const capSummaryEdges = (summary: GraphPathSummary): GraphPathSummary | null => {
    if (!options.nodeTypes.users) return summary;
    const remaining = maxEdges - permissionEdges;
    if (remaining <= 0) {
      omittedByMaxEdges += summary.principals.filter((p) => p.level && p.level !== "none").length;
      return null;
    }
    const principals = summary.principals.slice(0, remaining);
    omittedByMaxEdges += Math.max(0, summary.principals.length - principals.length);
    permissionEdges += principals.length;
    return principals.length > 0 ? { ...summary, principals } : null;
  };

  for (const summary of filteredFiles) {
    const capped = capSummaryEdges(summary);
    if (capped) cappedFiles.push(capped);
  }
  for (const summary of filteredFolders) {
    const capped = capSummaryEdges(summary);
    if (capped) cappedFolders.push(capped);
  }

  const activeUserIds = new Set<string>();
  for (const summary of [...cappedFiles, ...cappedFolders]) {
    for (const principal of summary.principals) activeUserIds.add(principal.userId);
  }
  const members = options.nodeTypes.users
    ? input.members.filter((member) =>
        selectedUsers.size > 0
          ? selectedUsers.has(member.userId.toLowerCase())
          : activeUserIds.size === 0 || activeUserIds.has(member.userId),
      )
    : [];

  return {
    vaultId: input.vaultId,
    members,
    summaries: cappedFiles,
    folderSummaries: cappedFolders,
    rules: normalizedRules,
    readableFileCount: cappedFiles.length,
    readableFolderCount: cappedFolders.length,
    omittedByMaxFiles,
    omittedByMaxEdges,
    omittedByFilters,
  };
}

export function estimateDetailedGraphComplexity(
  input: FilteredGraphDataset,
  options: GraphRuntimeOptions,
): GraphComplexityEstimate {
  const users = new Set<string>();
  const folders = new Set<string>();
  const containmentEdges = new Set<string>();
  let fileNodeCount = 0;
  let permissionEdgeCount = 0;

  if (options.nodeTypes.users) {
    for (const member of input.members) users.add(member.userId);
  }

  for (const summary of input.summaries) {
    fileNodeCount += options.nodeTypes.files ? 1 : 0;
    if (options.nodeTypes.folders) {
      let parent: string | null = null;
      for (const folder of ancestorFolders(summary.path).map(normalizeGraphPath)) {
        folders.add(folder);
        if (parent) containmentEdges.add(`${parent}->${folder}`);
        parent = folder;
      }
      if (parent && options.nodeTypes.files) containmentEdges.add(`${parent}->${summary.path}`);
    }
    if (options.nodeTypes.users) {
      for (const principal of summary.principals) {
        if (principal.level && principal.level !== "none") {
          users.add(principal.userId);
          permissionEdgeCount += 1;
        }
      }
    }
  }

  for (const summary of input.folderSummaries) {
    if (!options.nodeTypes.folders) continue;
    folders.add(summary.path);
    if (options.nodeTypes.users) {
      for (const principal of summary.principals) {
        if (principal.level && principal.level !== "none") {
          users.add(principal.userId);
          permissionEdgeCount += 1;
        }
      }
    }
  }

  const folderNodeCount = options.nodeTypes.folders ? folders.size : 0;
  const userNodeCount = options.nodeTypes.users ? users.size : 0;
  const containmentEdgeCount = options.nodeTypes.folders ? containmentEdges.size : 0;
  const nodeCount = fileNodeCount + folderNodeCount + userNodeCount;
  const edgeCount = permissionEdgeCount + containmentEdgeCount;
  return {
    nodeCount,
    edgeCount,
    labelCount: nodeCount + permissionEdgeCount,
    fileNodeCount,
    folderNodeCount,
    userNodeCount,
    permissionEdgeCount,
    containmentEdgeCount,
  };
}

export function decideGraphRender(
  estimate: GraphComplexityEstimate,
  options: GraphRuntimeOptions,
  budgets: GraphComplexityBudgets = DEFAULT_GRAPH_BUDGETS,
): GraphRenderDecision {
  const exceeded: string[] = [];
  const disabled: string[] = [];
  if (estimate.nodeCount > budgets.maxRenderedNodes) exceeded.push("maxRenderedNodes");
  if (estimate.edgeCount > budgets.maxRenderedEdges) exceeded.push("maxRenderedEdges");
  if (estimate.labelCount > budgets.maxRenderedLabels) exceeded.push("maxRenderedLabels");
  if (estimate.nodeCount + estimate.edgeCount > budgets.largeGraphThreshold) exceeded.push("largeGraphThreshold");

  const labelModeUsed =
    options.labelsMode === "on"
      ? "on"
      : options.labelsMode === "off" || estimate.labelCount > budgets.maxRenderedLabels
        ? "off"
        : "on";
  if (labelModeUsed === "off" && options.labelsMode !== "off") disabled.push("labels");

  const forceUnsafe = estimate.edgeCount > budgets.maxForceLayoutEdges;
  let layoutModeUsed: GraphRenderDecision["layoutModeUsed"];
  if (options.layoutMode === "folder") layoutModeUsed = "folder";
  else if (options.layoutMode === "sections") layoutModeUsed = "sections";
  else if (options.layoutMode === "grid") layoutModeUsed = "grid";
  else if (options.layoutMode === "force" && !forceUnsafe) layoutModeUsed = "force";
  else if (options.layoutMode === "force" && forceUnsafe) {
    // Force needs a cheaper fallback once the edge count is past the sim budget.
    // Radial (concentric) is a deterministic O(n) placement and reads far better
    // than a rigid grid, so fall back to it rather than dropping to the lattice.
    layoutModeUsed = "radial";
    disabled.push("force layout");
  } else {
    // Auto and Radial both use the concentric "rings" layout. It is cheap and
    // deterministic (no force simulation), so neither a heavy edge count
    // (forceUnsafe) nor a label-budget overflow is a reason to fall back to the
    // rigid grid — doing so was what silently turned the circle into a static
    // square. Genuinely oversized graphs never reach a detailed render at all;
    // they become "aggregated" or "refused" upstream (see `unsafe`/`actualMode`
    // below), so concentric is always legible by the time we get here.
    layoutModeUsed = "radial";
  }

  const unsafe = exceeded.some((budget) => budget !== "maxRenderedLabels" || options.labelsMode === "on");
  const actualMode: GraphActualMode =
    options.renderMode === "aggregated"
      ? "aggregated"
      : options.renderMode === "detailed" && unsafe
        ? "refused"
        : options.renderMode === "auto" && unsafe
          ? "aggregated"
          : "detailed";

  // A label-budget overflow only means "hide labels" (already handled by
  // labelModeUsed); it does not make the graph structurally large, so it must
  // not switch off animation/hover for an otherwise-legible detailed graph.
  const structurallyLarge = exceeded.some((budget) => budget !== "maxRenderedLabels");
  const large = actualMode !== "detailed" || structurallyLarge;
  const hoverEnabled = !large && estimate.edgeCount <= budgets.maxForceLayoutEdges;
  if (!hoverEnabled) disabled.push("hover highlighting");
  const animationEnabled = !large && layoutModeUsed !== "grid";
  if (!animationEnabled) disabled.push("animations");

  return {
    requestedMode: options.renderMode,
    actualMode,
    large,
    exceeded,
    disabled: Array.from(new Set(disabled)),
    labelModeUsed,
    layoutModeUsed,
    hoverEnabled,
    animationEnabled,
  };
}

export function buildAggregatedGraphElements(
  input: FilteredGraphDataset,
  options: GraphRuntimeOptions,
  budgets: GraphComplexityBudgets = DEFAULT_GRAPH_BUDGETS,
): AggregatedGraphResult {
  const folderStats = new Map<string, AggregateFolderStats>();
  const memberById = new Map(input.members.map((member) => [member.userId, member]));
  const prefix = normalizeOptionalGraphPath(options.pathPrefix);
  const maxDepth = clampInt(options.depth, 1, 8);
  const now = new Date().toISOString();

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

  for (const summary of input.summaries) {
    const folders = aggregateFoldersForPath(summary.path, prefix, maxDepth);
    if (folders.length === 0) continue;
    const statsChain = folders.map(ensureFolder);
    const writable = summary.principals.some((principal) => principal.level === "write" || principal.level === "admin");
    const admin = summary.principals.some((principal) => principal.level === "admin");
    for (const stats of statsChain) {
      stats.readableFiles += 1;
      if (writable) stats.writableFiles += 1;
      if (admin) stats.adminFiles += 1;
    }
    for (const principal of summary.principals) {
      if (!principal.level || principal.level === "none") continue;
      const expiring = hasExpiringRule(principal, summary.path, input.rules ?? [], memberById, now);
      for (const stats of statsChain) {
        stats.userLevels.set(
          principal.userId,
          maxAccessLevel(stats.userLevels.get(principal.userId), principal.level),
        );
        if (expiring) stats.expiringGrants += 1;
      }
    }
  }

  for (const folderSummary of input.folderSummaries) {
    const folders = aggregateFoldersForFolder(folderSummary.path, prefix, maxDepth);
    if (folders.length === 0) continue;
    const statsChain = folders.map(ensureFolder);
    for (const principal of folderSummary.principals) {
      if (!principal.level || principal.level === "none") continue;
      for (const stats of statsChain) {
        stats.userLevels.set(
          principal.userId,
          maxAccessLevel(stats.userLevels.get(principal.userId), principal.level),
        );
      }
    }
  }

  const elements: GraphElement[] = [];
  const seen = new Set<string>();
  const push = (el: GraphElement): boolean => {
    if (seen.has(el.data.id)) return false;
    seen.add(el.data.id);
    elements.push(el);
    return true;
  };

  const nodeBudget = Math.max(1, budgets.maxRenderedNodes);
  const edgeBudget = Math.max(0, Math.min(budgets.maxRenderedEdges, clampInt(options.maxEdges, 0, budgets.maxRenderedEdges)));
  const sortedFolderStats = Array.from(folderStats.values()).sort((a, b) => a.path.localeCompare(b.path));
  const folderNodeLimit = Math.min(sortedFolderStats.length, Math.max(1, Math.floor(nodeBudget * 0.75)));
  const sortedFolders = sortedFolderStats.slice(0, folderNodeLimit);
  const renderedFolderPaths = new Set(sortedFolders.map((stats) => stats.path));
  let nodeCount = 0;
  let edgeCount = 0;
  let truncated = sortedFolderStats.length > sortedFolders.length;

  for (const stats of sortedFolders) {
    if (push({
      data: {
        id: folderNodeId(stats.path),
        kind: "folder",
        label: `${folderLabel(stats.path)} (${stats.readableFiles})`,
        path: stats.path,
        aggregate: true,
        readableFiles: stats.readableFiles,
        writableFiles: stats.writableFiles,
        adminFiles: stats.adminFiles,
        expiringGrants: stats.expiringGrants,
      },
      classes: "folder aggregate",
    })) {
      nodeCount += 1;
    }
  }

  for (const stats of sortedFolders) {
    const parent = parentFolderPath(stats.path);
    if (!parent || !folderStats.has(parent)) continue;
    if (!renderedFolderPaths.has(parent)) {
      truncated = true;
      continue;
    }
    if (edgeCount >= edgeBudget) {
      truncated = true;
      continue;
    }
    if (push({
      data: {
        id: `contain:${folderNodeId(parent)}->${folderNodeId(stats.path)}`,
        kind: "containment",
        source: folderNodeId(parent),
        target: folderNodeId(stats.path),
        aggregate: true,
      },
      classes: "containment aggregate",
    })) {
      edgeCount += 1;
    }
  }

  const users = new Set<string>();
  const renderedUsers = new Set<string>();
  if (options.nodeTypes.users) {
    for (const stats of sortedFolders) {
      for (const [uid, level] of stats.userLevels.entries()) {
        if (edgeCount >= edgeBudget) {
          truncated = true;
          continue;
        }
        const member = memberById.get(uid);
        if (!renderedUsers.has(uid)) {
          if (nodeCount >= nodeBudget) {
            truncated = true;
            continue;
          }
          if (push({
            data: {
              id: userNodeId(uid),
              kind: "user",
              label: member?.displayName?.trim() || member?.email?.trim() || uid,
              userId: uid,
              color: colorForUser(uid),
            },
            classes: "user aggregate",
          })) {
            nodeCount += 1;
          }
          renderedUsers.add(uid);
          users.add(uid);
        }
        if (push({
          data: {
            id: `agg:${uid}->${stats.path}`,
            kind: "permission",
            source: userNodeId(uid),
            target: folderNodeId(stats.path),
            level,
            label: level,
            userId: uid,
            path: stats.path,
            aggregate: true,
          },
          classes: `permission allow level-${level} aggregate`,
        })) {
          edgeCount += 1;
        }
      }
    }
  }

  return {
    elements,
    folderCount: sortedFolders.length,
    userCount: users.size,
    edgeCount,
    truncated,
  };
}

export function capExplainRows<T>(rows: T[], maxRows: number): { visible: T[]; hiddenCount: number; total: number } {
  const safeMax = clampInt(maxRows, 1, 1000);
  return {
    visible: rows.slice(0, safeMax),
    hiddenCount: Math.max(0, rows.length - safeMax),
    total: rows.length,
  };
}

export function buildGraphDebugReadoutModel(
  decision: GraphRenderDecision,
  estimate: GraphComplexityEstimate,
  actualNodeCount: number,
  actualEdgeCount: number,
  options: GraphRuntimeOptions,
): GraphDebugReadoutModel {
  return {
    requestedMode: decision.requestedMode,
    actualMode: decision.actualMode,
    nodeCount: actualNodeCount,
    edgeCount: actualEdgeCount,
    estimatedNodeCount: estimate.nodeCount,
    estimatedEdgeCount: estimate.edgeCount,
    selectedLayout: decision.layoutModeUsed,
    labelMode: decision.labelModeUsed,
    activeDepth: options.depth,
    maxFiles: options.maxFiles,
    maxEdges: options.maxEdges,
    exceeded: decision.exceeded,
    disabled: decision.disabled,
  };
}

interface AggregateFolderStats {
  path: string;
  readableFiles: number;
  writableFiles: number;
  adminFiles: number;
  expiringGrants: number;
  userLevels: Map<string, Exclude<GraphAccessLevel, "none">>;
}

type GraphStudioAppearancePatch = Omit<Partial<GraphStudioAppearanceOptions>, "palette"> & {
  palette?: Partial<GraphStudioPaletteOptions>;
};

type PartialGraphRuntimeOptions = Omit<Partial<GraphRuntimeOptions>, "appearance" | "arrangement"> & {
  appearance?: GraphStudioAppearancePatch;
  arrangement?: Partial<GraphStudioArrangementOptions>;
};

function parsePartialGraphOptions(
  raw: unknown,
  budgets: GraphComplexityBudgets,
): PartialGraphRuntimeOptions {
  if (!raw || typeof raw !== "object") return {};
  const value = raw as Partial<PermissionsGraphSavedState>;
  const parsed: PartialGraphRuntimeOptions = {};

  if (value.renderMode === "auto" || value.renderMode === "aggregated" || value.renderMode === "detailed") {
    parsed.renderMode = value.renderMode;
  }
  if (
    value.layoutMode === "auto" ||
    value.layoutMode === "radial" ||
    value.layoutMode === "force" ||
    value.layoutMode === "grid" ||
    value.layoutMode === "folder" ||
    value.layoutMode === "sections"
  ) {
    parsed.layoutMode = value.layoutMode;
  }
  if (value.labelsMode === "auto" || value.labelsMode === "on" || value.labelsMode === "off") {
    parsed.labelsMode = value.labelsMode;
  }
  parsed.pathPrefix = normalizeOptionalGraphPath(value.pathPrefix);
  if (typeof value.searchQuery === "string") {
    parsed.searchQuery = value.searchQuery.trim().slice(0, MAX_TEXT_FILTER_LENGTH);
  }
  if (value.searchScope === "all" || value.searchScope === "user" || value.searchScope === "file" || value.searchScope === "folder") {
    parsed.searchScope = value.searchScope;
  }
  if (Array.isArray(value.selectedUsers)) {
    parsed.selectedUsers = value.selectedUsers
      .filter((entry): entry is string => typeof entry === "string" && entry.trim().length > 0)
      .map((entry) => entry.trim().slice(0, MAX_TEXT_FILTER_LENGTH))
      .slice(0, MAX_SELECTED_USERS);
  }
  if (value.accessLevels && typeof value.accessLevels === "object") {
    parsed.accessLevels = {
      read: value.accessLevels.read !== false,
      write: value.accessLevels.write !== false,
      admin: value.accessLevels.admin !== false,
    };
  }
  if (value.nodeTypes && typeof value.nodeTypes === "object") {
    parsed.nodeTypes = {
      users: value.nodeTypes.users !== false,
      files: value.nodeTypes.files !== false,
      folders: value.nodeTypes.folders !== false,
    };
  }
  if (typeof value.expiringOnly === "boolean") parsed.expiringOnly = value.expiringOnly;
  if (typeof value.writableAdminOnly === "boolean") parsed.writableAdminOnly = value.writableAdminOnly;
  if (typeof value.explicitRulesOnly === "boolean") parsed.explicitRulesOnly = value.explicitRulesOnly;
  if (typeof value.maxFiles === "number") parsed.maxFiles = clampInt(value.maxFiles, 1, budgets.maxInitialFiles);
  if (typeof value.maxEdges === "number") parsed.maxEdges = clampInt(value.maxEdges, 0, budgets.maxRenderedEdges);
  if (typeof value.depth === "number") parsed.depth = clampInt(value.depth, 1, 8);
  if (typeof value.debugExpanded === "boolean") parsed.debugExpanded = value.debugExpanded;
  if (value.appearance && typeof value.appearance === "object") {
    const appearance: GraphStudioAppearancePatch = {};
    if (
      value.appearance.backgroundMode === "theme" ||
      value.appearance.backgroundMode === "solid" ||
      value.appearance.backgroundMode === "gradient"
    ) {
      appearance.backgroundMode = value.appearance.backgroundMode;
    }
    if (
      value.appearance.backgroundPattern === "none" ||
      value.appearance.backgroundPattern === "grid" ||
      value.appearance.backgroundPattern === "dots"
    ) {
      appearance.backgroundPattern = value.appearance.backgroundPattern;
    }
    const backgroundPrimary = normalizeGraphStudioColor(value.appearance.backgroundPrimary);
    if (backgroundPrimary) appearance.backgroundPrimary = backgroundPrimary;
    const backgroundSecondary = normalizeGraphStudioColor(value.appearance.backgroundSecondary);
    if (backgroundSecondary) appearance.backgroundSecondary = backgroundSecondary;
    if (
      value.appearance.colorMode === "current" ||
      value.appearance.colorMode === "type" ||
      value.appearance.colorMode === "folder" ||
      value.appearance.colorMode === "access" ||
      value.appearance.colorMode === "connections"
    ) {
      appearance.colorMode = value.appearance.colorMode;
    }
    if (typeof value.appearance.customPalette === "boolean") {
      appearance.customPalette = value.appearance.customPalette;
    }
    if (
      value.appearance.sizeMode === "standard" ||
      value.appearance.sizeMode === "uniform" ||
      value.appearance.sizeMode === "connections" ||
      value.appearance.sizeMode === "access"
    ) {
      appearance.sizeMode = value.appearance.sizeMode;
    }
    if (typeof value.appearance.nodeScale === "number" && Number.isFinite(value.appearance.nodeScale)) {
      appearance.nodeScale = clampNumber(value.appearance.nodeScale, 0.75, 1.75);
    }
    if (typeof value.appearance.edgeScale === "number" && Number.isFinite(value.appearance.edgeScale)) {
      appearance.edgeScale = clampNumber(value.appearance.edgeScale, 0.5, 2);
    }
    if (typeof value.appearance.labelScale === "number" && Number.isFinite(value.appearance.labelScale)) {
      appearance.labelScale = clampNumber(value.appearance.labelScale, 0.75, 2.5);
    }
    if (value.appearance.palette && typeof value.appearance.palette === "object") {
      const palette: Partial<GraphStudioPaletteOptions> = {};
      for (const key of GRAPH_STUDIO_PALETTE_KEYS) {
        const color = normalizeGraphStudioColor(value.appearance.palette[key]);
        if (color) palette[key] = color;
      }
      if (Object.keys(palette).length > 0) appearance.palette = palette;
    }
    parsed.appearance = appearance;
  }
  if (value.arrangement && typeof value.arrangement === "object") {
    const arrangement: Partial<GraphStudioArrangementOptions> = {};
    if (
      value.arrangement.sectionBy === "folder" ||
      value.arrangement.sectionBy === "type" ||
      value.arrangement.sectionBy === "access" ||
      value.arrangement.sectionBy === "connections"
    ) {
      arrangement.sectionBy = value.arrangement.sectionBy;
    }
    if (
      value.arrangement.sortBy === "name" ||
      value.arrangement.sortBy === "path" ||
      value.arrangement.sortBy === "access" ||
      value.arrangement.sortBy === "connections"
    ) {
      arrangement.sortBy = value.arrangement.sortBy;
    }
    if (value.arrangement.sortDirection === "asc" || value.arrangement.sortDirection === "desc") {
      arrangement.sortDirection = value.arrangement.sortDirection;
    }
    parsed.arrangement = arrangement;
  }

  return parsed;
}

function pathMatchesActivePathFilters(
  path: string,
  kind: "file" | "folder",
  options: GraphRuntimeOptions,
  memberById: Map<string, GraphMember>,
  principals: GraphPrincipal[],
): boolean {
  const prefix = normalizeOptionalGraphPath(options.pathPrefix);
  if (prefix && !pathIsWithinPrefix(path, prefix)) return false;

  const query = options.searchQuery.trim().toLowerCase();
  if (!query) return true;
  const pathMatch = path.toLowerCase().includes(query) || folderLabel(path).toLowerCase().includes(query);
  if (options.searchScope === kind) return pathMatch;
  if (options.searchScope === "file" || options.searchScope === "folder") return false;
  if (pathMatch) return true;
  return principals.some((principal) =>
    principalSearchLabel(principal, memberById.get(principal.userId)).includes(query),
  );
}

function pathIsWithinPrefix(path: string, prefix: string): boolean {
  const normalizedPath = normalizeGraphPath(path);
  const normalizedPrefix = normalizeGraphPath(prefix);
  return normalizedPath === normalizedPrefix || normalizedPath.startsWith(`${normalizedPrefix}/`);
}

function principalSearchLabel(principal: GraphPrincipal, member?: GraphMember): string {
  return [
    principal.displayName,
    principal.email,
    member?.displayName,
    member?.email,
    principal.userId,
  ]
    .filter((entry): entry is string => typeof entry === "string" && entry.length > 0)
    .join(" ")
    .toLowerCase();
}

function hasExpiringRule(
  principal: GraphPrincipal,
  path: string,
  rules: ExplainRule[],
  memberById: Map<string, GraphMember>,
  now: string,
): boolean {
  if (rules.length === 0) return false;
  const candidateRules = rules.filter((rule) =>
    ruleAppliesToPrincipalPath(rule, principal, path, memberById, now),
  );
  if (candidateRules.length === 0) return false;
  const role = roleForPrincipal(principal, memberById);
  return explainAccess({
    userId: principal.userId,
    role,
    path,
    action: "read",
    rules: candidateRules,
    serverLevel: principal.level,
    now,
  }).expiresAt !== null;
}

function hasLiveRuleForPrincipalPath(
  principal: GraphPrincipal,
  path: string,
  rules: ExplainRule[],
  memberById: Map<string, GraphMember>,
  now: string,
): boolean {
  return rules.some((rule) => ruleAppliesToPrincipalPath(rule, principal, path, memberById, now));
}

function ruleAppliesToPrincipalPath(
  rule: ExplainRule,
  principal: GraphPrincipal,
  path: string,
  memberById: Map<string, GraphMember>,
  now: string,
): boolean {
  if (rule.expiresAt && rule.expiresAt <= now) return false;
  const role = roleForPrincipal(principal, memberById).toLowerCase();
  const ruleUser = (rule.userId ?? "").toLowerCase();
  const ruleRole = (rule.role ?? "").toLowerCase();
  const principalMatch = ruleUser === principal.userId.toLowerCase() || rule.userId === "*" || (!!ruleRole && ruleRole === role);
  return principalMatch && pathMatchesPattern(path, rule.pathPattern);
}

function roleForPrincipal(principal: GraphPrincipal, memberById: Map<string, GraphMember>): ExplainVaultRole {
  const role = memberById.get(principal.userId)?.role ?? principal.role;
  return role === "admin" || role === "editor" || role === "viewer" ? role : "viewer";
}

function aggregateFoldersForPath(path: string, prefix: string, maxDepth: number): string[] {
  const normalized = normalizeGraphPath(path);
  const ancestors = ancestorFolders(normalized).map(normalizeGraphPath);
  return limitFoldersByPrefixAndDepth(ancestors.length > 0 ? ancestors : ["/"], prefix, maxDepth);
}

function aggregateFoldersForFolder(path: string, prefix: string, maxDepth: number): string[] {
  const normalized = normalizeGraphPath(path);
  const folders = normalized === "/" ? ["/"] : [...ancestorFolders(`${normalized}/__file`), normalized].map(normalizeGraphPath);
  return limitFoldersByPrefixAndDepth(folders, prefix, maxDepth);
}

function limitFoldersByPrefixAndDepth(folders: string[], prefix: string, maxDepth: number): string[] {
  const scoped = prefix
    ? folders.filter((folder) => pathIsWithinPrefix(folder, prefix) || pathIsWithinPrefix(prefix, folder))
    : folders;
  if (scoped.length === 0 && prefix) return [prefix];
  const prefixDepth = prefix ? pathDepth(prefix) : 0;
  return scoped.filter((folder) => pathDepth(folder) - prefixDepth <= maxDepth).slice(0, maxDepth + 1);
}

function maxAccessLevel(
  current: Exclude<GraphAccessLevel, "none"> | undefined,
  next: GraphAccessLevel,
): Exclude<GraphAccessLevel, "none"> {
  if (next === "none") return current ?? "read";
  if (!current) return next;
  const rank = { read: 1, write: 2, admin: 3 } as const;
  return rank[next] > rank[current] ? next : current;
}

function folderLabel(path: string): string {
  if (path === "/") return "Vault root";
  const parts = path.split("/").filter(Boolean);
  return `${parts[parts.length - 1] ?? path}/`;
}

function parentFolderPath(path: string): string | null {
  if (path === "/") return null;
  const parts = path.split("/").filter(Boolean);
  if (parts.length <= 1) return null;
  return `/${parts.slice(0, -1).join("/")}`;
}

function pathDepth(path: string): number {
  if (path === "/") return 0;
  return path.split("/").filter(Boolean).length;
}

function folderNodeId(path: string): string {
  return `folder:${path}`;
}

function userNodeId(uid: string): string {
  return `user:${uid}`;
}

function clampInt(value: number, min: number, max: number = Number.MAX_SAFE_INTEGER): number {
  if (!Number.isFinite(value)) return min;
  return Math.max(min, Math.min(max, Math.floor(value)));
}

function clampNumber(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}
