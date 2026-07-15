import type cytoscape from "cytoscape";

import type { GraphElement } from "./permissions-graph-data";
import {
  DEFAULT_GRAPH_OPTIONS,
  type GraphRuntimeOptions,
  type GraphStudioAppearanceOptions,
  type GraphStudioArrangementOptions,
} from "./permissions-graph-scale";

export type GraphStudioPresetId = "default" | "folder-map" | "access-audit" | "minimal";

export interface GraphStudioPosition {
  x: number;
  y: number;
}

export interface GraphStudioNodeMetric {
  stableId: string;
  kind: string;
  label: string;
  path: string;
  degree: number;
  accessMask: number;
  accessRank: number;
  accessProfile: string;
  topFolder: string;
  connectivityBand: "isolated" | "low" | "medium" | "high";
}

export interface GraphStudioNodePatch {
  studioColor?: string;
  studioSize?: number;
  studioSection?: string;
  studioOrder?: number;
}

export interface GraphStudioEdgePatch {
  studioColor?: string;
  studioWidth?: number;
}

export interface GraphStudioPresentation {
  metrics: Record<string, GraphStudioNodeMetric>;
  nodePatches: Record<string, GraphStudioNodePatch>;
  edgePatches: Record<string, GraphStudioEdgePatch>;
  positions: Record<string, GraphStudioPosition>;
  sectionKeys: string[];
}

export interface GraphStudioPresetPatch {
  layoutMode: GraphRuntimeOptions["layoutMode"];
  labelsMode: GraphRuntimeOptions["labelsMode"];
  appearance: GraphStudioAppearanceOptions;
  arrangement: GraphStudioArrangementOptions;
}

const NODE_STUDIO_DATA = ["studioColor", "studioSize", "studioSection", "studioOrder"] as const;
const EDGE_STUDIO_DATA = ["studioColor", "studioWidth"] as const;
const KIND_ORDER = ["vault", "user", "folder", "file"];
const SECTION_COLUMNS = 3;
const SECTION_NODE_COLUMNS = 4;

export function buildGraphStudioPresentation(
  elements: readonly GraphElement[],
  options: GraphRuntimeOptions,
): GraphStudioPresentation {
  const nodes = elements
    .filter((element) => !isEdge(element))
    .slice()
    .sort((a, b) => compareStableText(a.data.id, b.data.id));
  const edges = elements
    .filter(isEdge)
    .slice()
    .sort((a, b) => compareStableText(a.data.id, b.data.id));
  const metrics = buildMetrics(nodes, edges);
  const nodePatches: Record<string, GraphStudioNodePatch> = {};
  const edgePatches: Record<string, GraphStudioEdgePatch> = {};
  let positions: Record<string, GraphStudioPosition> = {};
  let sectionKeys: string[] = [];

  if (options.layoutMode === "folder") {
    const folderResult = buildFolderPositions(nodes, edges, metrics, options.arrangement);
    positions = folderResult.positions;
    sectionKeys = folderResult.sectionKeys;
    for (const [id, patch] of Object.entries(folderResult.nodePatches)) nodePatches[id] = patch;
  } else if (options.layoutMode === "sections") {
    const sectionResult = buildSectionPositions(nodes, metrics, options.arrangement);
    positions = sectionResult.positions;
    sectionKeys = sectionResult.sectionKeys;
    for (const [id, patch] of Object.entries(sectionResult.nodePatches)) nodePatches[id] = patch;
  }

  const hasNodeAppearance =
    options.appearance.colorMode !== "current" ||
    options.appearance.customPalette ||
    options.appearance.sizeMode !== "standard" ||
    options.appearance.nodeScale !== 1;
  if (hasNodeAppearance) {
    for (const node of nodes) {
      const metric = metrics[node.data.id];
      if (!metric) continue;
      const patch = nodePatches[node.data.id] ?? {};
      const color = nodeColor(metric, options.appearance);
      const size = nodeSize(metric, options.appearance);
      if (color) patch.studioColor = color;
      if (size !== undefined) patch.studioSize = size;
      if (Object.keys(patch).length > 0) nodePatches[node.data.id] = patch;
    }
  }

  const hasEdgeAppearance =
    options.appearance.colorMode === "access" ||
    options.appearance.customPalette ||
    options.appearance.edgeScale !== 1;
  if (hasEdgeAppearance) {
    for (const edge of edges) {
      const patch: GraphStudioEdgePatch = {};
      const level = edge.data.level;
      if ((options.appearance.colorMode === "access" || options.appearance.customPalette) && isAccessLevel(level)) {
        patch.studioColor = options.appearance.palette[level];
      }
      patch.studioWidth = edgeWidth(edge, options.appearance.edgeScale);
      edgePatches[edge.data.id] = patch;
    }
  }

  return { metrics, nodePatches, edgePatches, positions, sectionKeys };
}

export function applyGraphStudioPresentation(core: cytoscape.Core, presentation: GraphStudioPresentation): void {
  core.batch(() => {
    core.nodes().forEach((node) => {
      for (const key of NODE_STUDIO_DATA) node.removeData(key);
      const patch = presentation.nodePatches[node.id()];
      if (!patch) return;
      for (const [key, value] of Object.entries(patch)) node.data(key, value);
    });
    core.edges().forEach((edge) => {
      for (const key of EDGE_STUDIO_DATA) edge.removeData(key);
      const patch = presentation.edgePatches[edge.id()];
      if (!patch) return;
      for (const [key, value] of Object.entries(patch)) edge.data(key, value);
    });
  });
}

export function getGraphStudioPreset(id: GraphStudioPresetId): GraphStudioPresetPatch {
  const defaults = cloneDefaultPreset();
  if (id === "folder-map") {
    return {
      layoutMode: "folder",
      labelsMode: "auto",
      appearance: {
        ...defaults.appearance,
        backgroundPattern: "dots",
        colorMode: "folder",
        sizeMode: "connections",
      },
      arrangement: { sectionBy: "folder", sortBy: "path", sortDirection: "asc" },
    };
  }
  if (id === "access-audit") {
    return {
      layoutMode: "sections",
      labelsMode: "on",
      appearance: {
        ...defaults.appearance,
        backgroundPattern: "grid",
        colorMode: "access",
        sizeMode: "access",
      },
      arrangement: { sectionBy: "access", sortBy: "access", sortDirection: "desc" },
    };
  }
  if (id === "minimal") {
    return {
      layoutMode: "grid",
      labelsMode: "off",
      appearance: { ...defaults.appearance, sizeMode: "uniform" },
      arrangement: { sectionBy: "type", sortBy: "name", sortDirection: "asc" },
    };
  }
  return defaults;
}

function cloneDefaultPreset(): GraphStudioPresetPatch {
  return {
    layoutMode: DEFAULT_GRAPH_OPTIONS.layoutMode,
    labelsMode: DEFAULT_GRAPH_OPTIONS.labelsMode,
    appearance: {
      ...DEFAULT_GRAPH_OPTIONS.appearance,
      palette: { ...DEFAULT_GRAPH_OPTIONS.appearance.palette },
    },
    arrangement: { ...DEFAULT_GRAPH_OPTIONS.arrangement },
  };
}

function buildMetrics(
  nodes: readonly GraphElement[],
  edges: readonly GraphElement[],
): Record<string, GraphStudioNodeMetric> {
  const metrics: Record<string, GraphStudioNodeMetric> = {};
  for (const node of nodes) {
    const kind = String(node.data.kind ?? kindFromClasses(node.classes));
    const path = typeof node.data.path === "string" ? normalizePath(node.data.path) : "";
    metrics[node.data.id] = {
      stableId: node.data.id,
      kind,
      label: String(node.data.label ?? pathLeaf(path) ?? node.data.id),
      path,
      degree: 0,
      accessMask: 0,
      accessRank: 0,
      accessProfile: "none",
      topFolder: kind === "user" ? "People" : topFolder(path),
      connectivityBand: "isolated",
    };
  }
  for (const edge of edges) {
    const source = typeof edge.data.source === "string" ? metrics[edge.data.source] : undefined;
    const target = typeof edge.data.target === "string" ? metrics[edge.data.target] : undefined;
    if (source) source.degree += 1;
    if (target) target.degree += 1;
    if (!isAccessLevel(edge.data.level)) continue;
    const bit = accessBit(edge.data.level);
    const rank = accessRank(edge.data.level);
    if (source) {
      source.accessMask |= bit;
      source.accessRank = Math.max(source.accessRank, rank);
    }
    if (target) {
      target.accessMask |= bit;
      target.accessRank = Math.max(target.accessRank, rank);
    }
  }
  for (const metric of Object.values(metrics)) {
    metric.accessProfile = accessProfile(metric.accessMask);
    metric.connectivityBand = connectivityBand(metric.degree);
  }
  return metrics;
}

function buildFolderPositions(
  nodes: readonly GraphElement[],
  edges: readonly GraphElement[],
  metrics: Record<string, GraphStudioNodeMetric>,
  arrangement: GraphStudioArrangementOptions,
): Pick<GraphStudioPresentation, "positions" | "sectionKeys" | "nodePatches"> {
  const positions: Record<string, GraphStudioPosition> = {};
  const nodePatches: Record<string, GraphStudioNodePatch> = {};
  const nodeById = new Map(nodes.map((node) => [node.data.id, node]));
  const pathNodes = nodes.filter((node) => {
    const kind = metrics[node.data.id]?.kind;
    return kind === "file" || kind === "folder";
  });
  const users = nodes.filter((node) => metrics[node.data.id]?.kind === "user");
  const vaults = nodes.filter((node) => metrics[node.data.id]?.kind === "vault");
  const children = new Map<string, string[]>();
  const parentByChild = new Map<string, string>();
  for (const edge of edges) {
    if (edge.data.kind !== "containment" || typeof edge.data.source !== "string" || typeof edge.data.target !== "string") {
      continue;
    }
    if (!nodeById.has(edge.data.source) || !nodeById.has(edge.data.target)) continue;
    const parentMetric = metrics[edge.data.source];
    const childMetric = metrics[edge.data.target];
    if (!parentMetric?.path || !childMetric?.path) continue;
    const siblings = children.get(edge.data.source) ?? [];
    siblings.push(edge.data.target);
    children.set(edge.data.source, siblings);
    parentByChild.set(edge.data.target, edge.data.source);
  }
  const compare = metricComparator(metrics, arrangement);
  for (const siblings of children.values()) siblings.sort(compare);
  const roots = pathNodes.map((node) => node.data.id).filter((id) => !parentByChild.has(id)).sort(compare);
  const visited = new Set<string>();
  let nextLeafY = 0;
  let order = 0;

  const place = (id: string): number => {
    if (visited.has(id)) return positions[id]?.y ?? nextLeafY;
    visited.add(id);
    const childIds = (children.get(id) ?? []).filter((childId) => !visited.has(childId));
    const childYs = childIds.map(place);
    const y = childYs.length > 0 ? childYs.reduce((sum, childY) => sum + childY, 0) / childYs.length : nextLeafY;
    if (childYs.length === 0) nextLeafY += 72;
    const metric = metrics[id];
    positions[id] = { x: 220 + Math.max(1, pathDepth(metric?.path ?? "")) * 220, y };
    nodePatches[id] = { studioSection: metric?.topFolder ?? "Root", studioOrder: order++ };
    return y;
  };

  for (const root of roots) {
    place(root);
    nextLeafY += 88;
  }
  for (const node of pathNodes.map((entry) => entry.data.id).sort(compare)) {
    if (!visited.has(node)) place(node);
  }
  users.map((node) => node.data.id).sort(compare).forEach((id, index) => {
    positions[id] = { x: 0, y: index * 72 };
    nodePatches[id] = { studioSection: "People", studioOrder: index };
  });
  const pathY = Object.entries(positions)
    .filter(([id]) => metrics[id]?.kind === "file" || metrics[id]?.kind === "folder")
    .map(([, position]) => position.y);
  const vaultY = pathY.length > 0 ? pathY.reduce((sum, y) => sum + y, 0) / pathY.length : 0;
  vaults.map((node) => node.data.id).sort(compare).forEach((id, index) => {
    positions[id] = { x: 220, y: vaultY + index * 72 };
    nodePatches[id] = { studioSection: "Root", studioOrder: index };
  });

  const topFolders = Array.from(new Set(pathNodes.map((node) => metrics[node.data.id]?.topFolder ?? "Root"))).sort(
    compareStableText,
  );
  return { positions, nodePatches, sectionKeys: ["People", "Root", ...topFolders.filter((key) => key !== "Root")] };
}

function buildSectionPositions(
  nodes: readonly GraphElement[],
  metrics: Record<string, GraphStudioNodeMetric>,
  arrangement: GraphStudioArrangementOptions,
): Pick<GraphStudioPresentation, "positions" | "sectionKeys" | "nodePatches"> {
  const groups = new Map<string, string[]>();
  for (const node of nodes) {
    const metric = metrics[node.data.id];
    if (!metric) continue;
    const key = sectionKey(metric, arrangement.sectionBy);
    const group = groups.get(key) ?? [];
    group.push(node.data.id);
    groups.set(key, group);
  }
  const sectionKeys = Array.from(groups.keys()).sort((a, b) => compareSectionKeys(a, b, arrangement.sectionBy));
  const positions: Record<string, GraphStudioPosition> = {};
  const nodePatches: Record<string, GraphStudioNodePatch> = {};
  const compare = metricComparator(metrics, arrangement);
  let rowY = 0;
  for (let sectionStart = 0; sectionStart < sectionKeys.length; sectionStart += SECTION_COLUMNS) {
    const rowKeys = sectionKeys.slice(sectionStart, sectionStart + SECTION_COLUMNS);
    const rowCounts = rowKeys.map((key) => groups.get(key)?.length ?? 0);
    const rowHeight = 150 + Math.max(1, ...rowCounts.map((count) => Math.ceil(count / SECTION_NODE_COLUMNS))) * 76;
    rowKeys.forEach((key, column) => {
      const ids = (groups.get(key) ?? []).slice().sort(compare);
      ids.forEach((id, index) => {
        positions[id] = {
          x: column * 520 + (index % SECTION_NODE_COLUMNS) * 104,
          y: rowY + Math.floor(index / SECTION_NODE_COLUMNS) * 76,
        };
        nodePatches[id] = { studioSection: key, studioOrder: index };
      });
    });
    rowY += rowHeight;
  }
  return { positions, nodePatches, sectionKeys };
}

function metricComparator(
  metrics: Record<string, GraphStudioNodeMetric>,
  arrangement: GraphStudioArrangementOptions,
): (left: string, right: string) => number {
  return (left, right) => {
    const a = metrics[left];
    const b = metrics[right];
    if (!a || !b) return compareStableText(left, right);
    let primary = 0;
    if (arrangement.sortBy === "path") primary = compareStableText(a.path || a.label, b.path || b.label);
    else if (arrangement.sortBy === "access") primary = a.accessRank - b.accessRank;
    else if (arrangement.sortBy === "connections") primary = a.degree - b.degree;
    else primary = compareStableText(a.label, b.label);
    if (primary !== 0) return arrangement.sortDirection === "desc" ? -primary : primary;
    return compareStableText(a.stableId, b.stableId);
  };
}

function sectionKey(metric: GraphStudioNodeMetric, mode: GraphStudioArrangementOptions["sectionBy"]): string {
  if (mode === "type") return metric.kind;
  if (mode === "access") return metric.accessProfile;
  if (mode === "connections") return metric.connectivityBand;
  return metric.topFolder;
}

function compareSectionKeys(left: string, right: string, mode: GraphStudioArrangementOptions["sectionBy"]): number {
  if (mode === "type") return orderedCompare(left, right, KIND_ORDER);
  if (mode === "connections") return orderedCompare(left, right, ["isolated", "low", "medium", "high"]);
  if (mode === "access") {
    return orderedCompare(left, right, [
      "none",
      "read",
      "write",
      "read+write",
      "admin",
      "read+admin",
      "write+admin",
      "read+write+admin",
    ]);
  }
  return orderedCompare(left, right, ["People", "Root"]);
}

function orderedCompare(left: string, right: string, preferred: readonly string[]): number {
  const leftIndex = preferred.indexOf(left);
  const rightIndex = preferred.indexOf(right);
  if (leftIndex >= 0 || rightIndex >= 0) {
    if (leftIndex < 0) return 1;
    if (rightIndex < 0) return -1;
    if (leftIndex !== rightIndex) return leftIndex - rightIndex;
  }
  return compareStableText(left, right);
}

function nodeColor(metric: GraphStudioNodeMetric, appearance: GraphStudioAppearanceOptions): string | undefined {
  const mode = appearance.colorMode === "current" && appearance.customPalette ? "type" : appearance.colorMode;
  if (mode === "current") return undefined;
  if (mode === "folder") {
    if (metric.kind === "user") return appearance.palette.user;
    if (metric.kind === "vault") return appearance.palette.folder;
    return stableFolderColor(metric.topFolder);
  }
  if (mode === "access") {
    if (metric.accessRank === 3) return appearance.palette.admin;
    if (metric.accessRank === 2) return appearance.palette.write;
    if (metric.accessRank === 1) return appearance.palette.read;
    return appearance.palette.low;
  }
  if (mode === "connections") return appearance.palette[paletteBand(metric.connectivityBand)];
  if (metric.kind === "user") return appearance.palette.user;
  if (metric.kind === "file") return appearance.palette.file;
  return appearance.palette.folder;
}

function nodeSize(metric: GraphStudioNodeMetric, appearance: GraphStudioAppearanceOptions): number | undefined {
  if (appearance.sizeMode === "standard" && appearance.nodeScale === 1) return undefined;
  let size: number;
  if (appearance.sizeMode === "uniform") size = 20;
  else if (appearance.sizeMode === "connections") size = 14 + Math.min(metric.degree, 9) * 2;
  else if (appearance.sizeMode === "access") size = 16 + metric.accessRank * 5;
  else if (metric.kind === "vault") size = 38;
  else if (metric.kind === "folder") size = 20;
  else if (metric.kind === "user") size = 22 + Math.min(metric.degree, 14) * 1.6;
  else size = 13 + Math.min(metric.degree, 12) * 1.2;
  return round(Math.max(10, Math.min(56, size * appearance.nodeScale)));
}

function edgeWidth(edge: GraphElement, scale: number): number {
  let base = edge.data.kind === "containment" ? 1 : 1.5;
  if (edge.data.level === "write") base = 2;
  else if (edge.data.level === "admin") base = 2.5;
  return round(Math.max(0.5, Math.min(5, base * scale)));
}

function stableFolderColor(value: string): string {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return `hsl(${(hash >>> 0) % 360}, 62%, 55%)`;
}

function accessBit(level: "read" | "write" | "admin"): number {
  return level === "read" ? 1 : level === "write" ? 2 : 4;
}

function accessRank(level: "read" | "write" | "admin"): number {
  return level === "read" ? 1 : level === "write" ? 2 : 3;
}

function accessProfile(mask: number): string {
  const values: string[] = [];
  if ((mask & 1) !== 0) values.push("read");
  if ((mask & 2) !== 0) values.push("write");
  if ((mask & 4) !== 0) values.push("admin");
  return values.length > 0 ? values.join("+") : "none";
}

function connectivityBand(degree: number): GraphStudioNodeMetric["connectivityBand"] {
  if (degree === 0) return "isolated";
  if (degree <= 2) return "low";
  if (degree <= 5) return "medium";
  return "high";
}

function paletteBand(band: GraphStudioNodeMetric["connectivityBand"]): "low" | "medium" | "high" {
  return band === "isolated" ? "low" : band;
}

function isAccessLevel(value: unknown): value is "read" | "write" | "admin" {
  return value === "read" || value === "write" || value === "admin";
}

function isEdge(element: GraphElement): boolean {
  return typeof element.data.source === "string" && typeof element.data.target === "string";
}

function topFolder(path: string): string {
  return path.split("/").filter(Boolean)[0] ?? "Root";
}

function pathLeaf(path: string): string {
  const parts = path.split("/").filter(Boolean);
  return parts[parts.length - 1] ?? "";
}

function pathDepth(path: string): number {
  return path.split("/").filter(Boolean).length;
}

function normalizePath(path: string): string {
  const normalized = path.replace(/\\/g, "/").replace(/\/+/g, "/").replace(/\/$/, "");
  if (!normalized) return "/";
  return normalized.startsWith("/") ? normalized : `/${normalized}`;
}

function kindFromClasses(classes: string): string {
  return KIND_ORDER.find((kind) => classes.split(/\s+/).includes(kind)) ?? "unknown";
}

function compareStableText(left: string, right: string): number {
  const a = left.toLocaleLowerCase("en-US");
  const b = right.toLocaleLowerCase("en-US");
  return a < b ? -1 : a > b ? 1 : left < right ? -1 : left > right ? 1 : 0;
}

function round(value: number): number {
  return Math.round(value * 100) / 100;
}
