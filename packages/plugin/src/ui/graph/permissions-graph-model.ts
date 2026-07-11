/**
 * Renderer-independent permissions-graph model and lookup indexes.
 *
 * Phase 1 intentionally builds this snapshot alongside the existing
 * GraphElement pipeline. Nothing in this module imports Cytoscape or changes
 * the current view/render path; buildGraphElements remains the rendering source
 * of truth while these records provide deterministic compact topology for
 * parity tests and later virtualization phases.
 */

import {
  buildGraphElements,
  type GraphAccessLevel,
  type GraphBuilderInput,
  type GraphMember,
} from "./permissions-graph-data";

export type PermissionsGraphNodeKind =
  | "user"
  | "file"
  | "folder"
  | "vault"
  | "group"
  | "aggregate"
  | "unknown";

export type PermissionsGraphEdgeKind =
  | "permission"
  | "membership"
  | "containment"
  | "unknown";

export interface PermissionsGraphAggregateCounts {
  readonly readableFiles: number;
  readonly writableFiles: number;
  readonly adminFiles: number;
  readonly expiringGrants: number;
}

interface PermissionsGraphRecordBase {
  /** Stable VaultGuard/Cytoscape-compatible element ID. */
  readonly id: string;
  /** Explicit alias retained for later renderer conversion. */
  readonly elementId: string;
  /** Dense deterministic ordinal within the node or edge record array. */
  readonly ordinal: number;
  readonly label: string | null;
  readonly path: string | null;
  readonly userId: string | null;
  readonly role: string | null;
  readonly aggregate: boolean;
  readonly classes: readonly string[];
  /** Canonical frozen copy of every current GraphElement data field. */
  readonly data: Readonly<Record<string, unknown>>;
}

export interface PermissionsGraphNodeRecord extends PermissionsGraphRecordBase {
  readonly kind: PermissionsGraphNodeKind;
  readonly vaultId: string | null;
  readonly displayName: string | null;
  readonly email: string | null;
  readonly aggregateCounts: PermissionsGraphAggregateCounts | null;
}

export interface PermissionsGraphEdgeRecord extends PermissionsGraphRecordBase {
  readonly kind: PermissionsGraphEdgeKind;
  readonly sourceId: string;
  readonly targetId: string;
  readonly level: GraphAccessLevel | null;
  readonly expiring: boolean;
}

/** Immutable full snapshot of the current viewer-scoped graph elements. */
export interface PermissionsGraphModel {
  readonly vaultId: string | null;
  readonly nodes: readonly PermissionsGraphNodeRecord[];
  readonly edges: readonly PermissionsGraphEdgeRecord[];
  readonly nodeCount: number;
  readonly edgeCount: number;
  readonly topologyFingerprint: string;
}

export interface PermissionsGraphDegree {
  readonly incoming: number;
  readonly outgoing: number;
  readonly total: number;
}

export interface PermissionsGraphModelBuildOptions {
  readonly vaultId?: string;
  readonly userMetadata?: readonly PermissionsGraphUserMetadata[];
}

export interface PermissionsGraphUserMetadata {
  readonly userId: string;
  readonly role?: string;
  readonly displayName?: string;
  readonly email?: string;
}

export interface PermissionsGraphModelBuildResult {
  readonly model: PermissionsGraphModel;
  readonly index: PermissionsGraphIndex;
}

export type PermissionsGraphModelBuildErrorCode =
  | "INVALID_ELEMENT"
  | "INVALID_ELEMENT_ID"
  | "DUPLICATE_ELEMENT_ID"
  | "INVALID_EDGE_ENDPOINT"
  | "MISSING_EDGE_ENDPOINT";

/** Internal validation error; callers decide whether/how to surface it. */
export class PermissionsGraphModelBuildError extends Error {
  constructor(
    readonly code: PermissionsGraphModelBuildErrorCode,
    message: string,
    readonly elementId: string | null = null,
  ) {
    super(message);
    this.name = "PermissionsGraphModelBuildError";
  }
}

const EMPTY_IDS: readonly string[] = Object.freeze([] as string[]);
const ZERO_DEGREE: PermissionsGraphDegree = Object.freeze({
  incoming: 0,
  outgoing: 0,
  total: 0,
});
const NODE_KINDS = new Set<PermissionsGraphNodeKind>([
  "user",
  "file",
  "folder",
  "vault",
  "group",
  "aggregate",
]);
const EDGE_KINDS = new Set<PermissionsGraphEdgeKind>([
  "permission",
  "membership",
  "containment",
]);

/**
 * Dense read index over an immutable PermissionsGraphModel.
 *
 * Maps remain private so consumers cannot mutate finalized index state. Every
 * list returned by this class is sorted and frozen.
 */
export class PermissionsGraphIndex {
  private readonly nodesById = new Map<string, PermissionsGraphNodeRecord>();
  private readonly edgesById = new Map<string, PermissionsGraphEdgeRecord>();
  private readonly nodeOrdinalsById = new Map<string, number>();
  private readonly edgeOrdinalsById = new Map<string, number>();
  private readonly nodeIdsByKind = new Map<PermissionsGraphNodeKind, readonly string[]>();
  private readonly edgeIdsBySource = new Map<string, readonly string[]>();
  private readonly edgeIdsByTarget = new Map<string, readonly string[]>();
  private readonly adjacentNodeIds = new Map<string, readonly string[]>();
  private readonly incidentEdgeIds = new Map<string, readonly string[]>();
  private readonly degreeByNodeId = new Map<string, PermissionsGraphDegree>();
  private readonly nodeIdsByPath = new Map<string, readonly string[]>();
  private readonly nodeIdsByUserId = new Map<string, readonly string[]>();
  private readonly edgeIdsByAccessLevel = new Map<GraphAccessLevel, readonly string[]>();
  private readonly aggregateNodeIds: readonly string[];
  private readonly aggregateEdgeIds: readonly string[];

  constructor(model: PermissionsGraphModel) {
    const mutableNodeIdsByKind = new Map<PermissionsGraphNodeKind, string[]>();
    const mutableEdgeIdsBySource = new Map<string, string[]>();
    const mutableEdgeIdsByTarget = new Map<string, string[]>();
    const mutableAdjacentNodeIds = new Map<string, Set<string>>();
    const mutableIncidentEdgeIds = new Map<string, string[]>();
    const mutableDegreeByNodeId = new Map<string, { incoming: number; outgoing: number }>();
    const mutableNodeIdsByPath = new Map<string, string[]>();
    const mutableNodeIdsByUserId = new Map<string, string[]>();
    const mutableEdgeIdsByAccessLevel = new Map<GraphAccessLevel, string[]>();
    const aggregateNodeIds: string[] = [];
    const aggregateEdgeIds: string[] = [];

    for (const node of model.nodes) {
      this.nodesById.set(node.id, node);
      this.nodeOrdinalsById.set(node.id, node.ordinal);
      appendMapValue(mutableNodeIdsByKind, node.kind, node.id);
      if (node.path) appendMapValue(mutableNodeIdsByPath, node.path, node.id);
      if (node.userId) appendMapValue(mutableNodeIdsByUserId, node.userId, node.id);
      if (node.aggregate) aggregateNodeIds.push(node.id);
      mutableAdjacentNodeIds.set(node.id, new Set());
      mutableIncidentEdgeIds.set(node.id, []);
      mutableDegreeByNodeId.set(node.id, { incoming: 0, outgoing: 0 });
    }

    for (const edge of model.edges) {
      this.edgesById.set(edge.id, edge);
      this.edgeOrdinalsById.set(edge.id, edge.ordinal);
      appendMapValue(mutableEdgeIdsBySource, edge.sourceId, edge.id);
      appendMapValue(mutableEdgeIdsByTarget, edge.targetId, edge.id);
      appendMapValue(mutableIncidentEdgeIds, edge.sourceId, edge.id);
      if (edge.targetId !== edge.sourceId) {
        appendMapValue(mutableIncidentEdgeIds, edge.targetId, edge.id);
      }
      mutableAdjacentNodeIds.get(edge.sourceId)?.add(edge.targetId);
      mutableAdjacentNodeIds.get(edge.targetId)?.add(edge.sourceId);

      const sourceDegree = mutableDegreeByNodeId.get(edge.sourceId);
      if (sourceDegree) sourceDegree.outgoing += 1;
      const targetDegree = mutableDegreeByNodeId.get(edge.targetId);
      if (targetDegree) targetDegree.incoming += 1;

      if (edge.level) appendMapValue(mutableEdgeIdsByAccessLevel, edge.level, edge.id);
      if (edge.aggregate) aggregateEdgeIds.push(edge.id);
    }

    freezeArrayMap(mutableNodeIdsByKind, this.nodeIdsByKind);
    freezeArrayMap(mutableEdgeIdsBySource, this.edgeIdsBySource);
    freezeArrayMap(mutableEdgeIdsByTarget, this.edgeIdsByTarget);
    freezeArrayMap(mutableIncidentEdgeIds, this.incidentEdgeIds);
    freezeArrayMap(mutableNodeIdsByPath, this.nodeIdsByPath);
    freezeArrayMap(mutableNodeIdsByUserId, this.nodeIdsByUserId);
    freezeArrayMap(mutableEdgeIdsByAccessLevel, this.edgeIdsByAccessLevel);

    for (const [nodeId, adjacent] of mutableAdjacentNodeIds) {
      this.adjacentNodeIds.set(nodeId, freezeSortedIds(adjacent));
    }
    for (const [nodeId, degree] of mutableDegreeByNodeId) {
      this.degreeByNodeId.set(
        nodeId,
        Object.freeze({
          incoming: degree.incoming,
          outgoing: degree.outgoing,
          total: degree.incoming + degree.outgoing,
        }),
      );
    }

    this.aggregateNodeIds = freezeSortedIds(aggregateNodeIds);
    this.aggregateEdgeIds = freezeSortedIds(aggregateEdgeIds);
    Object.freeze(this);
  }

  getNode(id: string): PermissionsGraphNodeRecord | undefined {
    return this.nodesById.get(id);
  }

  getEdge(id: string): PermissionsGraphEdgeRecord | undefined {
    return this.edgesById.get(id);
  }

  getNodeOrdinal(id: string): number | undefined {
    return this.nodeOrdinalsById.get(id);
  }

  getEdgeOrdinal(id: string): number | undefined {
    return this.edgeOrdinalsById.get(id);
  }

  getNodeIdsByKind(kind: PermissionsGraphNodeKind): readonly string[] {
    return this.nodeIdsByKind.get(kind) ?? EMPTY_IDS;
  }

  getEdgeIdsBySource(nodeId: string): readonly string[] {
    return this.edgeIdsBySource.get(nodeId) ?? EMPTY_IDS;
  }

  getEdgeIdsByTarget(nodeId: string): readonly string[] {
    return this.edgeIdsByTarget.get(nodeId) ?? EMPTY_IDS;
  }

  getAdjacentNodeIds(nodeId: string): readonly string[] {
    return this.adjacentNodeIds.get(nodeId) ?? EMPTY_IDS;
  }

  getIncidentEdgeIds(nodeId: string): readonly string[] {
    return this.incidentEdgeIds.get(nodeId) ?? EMPTY_IDS;
  }

  getDegree(nodeId: string): PermissionsGraphDegree {
    return this.degreeByNodeId.get(nodeId) ?? ZERO_DEGREE;
  }

  getNodeIdsByPath(path: string): readonly string[] {
    return this.nodeIdsByPath.get(path) ?? EMPTY_IDS;
  }

  getNodeIdsByUserId(userId: string): readonly string[] {
    return this.nodeIdsByUserId.get(userId) ?? EMPTY_IDS;
  }

  getEdgeIdsByAccessLevel(level: GraphAccessLevel): readonly string[] {
    return this.edgeIdsByAccessLevel.get(level) ?? EMPTY_IDS;
  }

  getAggregateNodeIds(): readonly string[] {
    return this.aggregateNodeIds;
  }

  getAggregateEdgeIds(): readonly string[] {
    return this.aggregateEdgeIds;
  }
}

/** Incremental collector for existing GraphElement batches. */
export class PermissionsGraphModelBuilder {
  private readonly elements: unknown[] = [];

  constructor(private readonly options: PermissionsGraphModelBuildOptions = {}) {}

  addElements(elements: readonly unknown[]): this {
    this.elements.push(...elements);
    return this;
  }

  build(): PermissionsGraphModelBuildResult {
    return finalizePermissionsGraphModel(this.elements, this.options);
  }
}

/** Convert current GraphElement-shaped data into the compact model/index pair. */
export function buildPermissionsGraphModelFromElements(
  elements: readonly unknown[],
  options: PermissionsGraphModelBuildOptions = {},
): PermissionsGraphModelBuildResult {
  return new PermissionsGraphModelBuilder(options).addElements(elements).build();
}

/**
 * Build through the unchanged legacy data builder, then convert its exact
 * output. This helper is intentionally not wired into PermissionsGraphView.
 */
export function buildPermissionsGraphModelFromGraphInput(
  input: GraphBuilderInput,
): PermissionsGraphModelBuildResult {
  return buildPermissionsGraphModelFromElements(buildGraphElements(input), {
    vaultId: input.vaultId,
    userMetadata: collectUserMetadata(input),
  });
}

function finalizePermissionsGraphModel(
  rawElements: readonly unknown[],
  options: PermissionsGraphModelBuildOptions,
): PermissionsGraphModelBuildResult {
  const parsedNodes: ParsedNode[] = [];
  const parsedEdges: ParsedEdge[] = [];
  const seenIds = new Set<string>();

  for (const rawElement of rawElements) {
    const parsed = parseElement(rawElement);
    if (seenIds.has(parsed.id)) {
      throw new PermissionsGraphModelBuildError(
        "DUPLICATE_ELEMENT_ID",
        `Duplicate permissions graph element id: ${parsed.id}`,
        parsed.id,
      );
    }
    seenIds.add(parsed.id);
    if (parsed.type === "node") parsedNodes.push(parsed);
    else parsedEdges.push(parsed);
  }

  parsedNodes.sort(compareById);
  parsedEdges.sort(compareById);
  const nodeIds = new Set(parsedNodes.map((node) => node.id));
  for (const edge of parsedEdges) {
    const missing = [edge.sourceId, edge.targetId].filter((id) => !nodeIds.has(id));
    if (missing.length > 0) {
      throw new PermissionsGraphModelBuildError(
        "MISSING_EDGE_ENDPOINT",
        `Permissions graph edge ${edge.id} references missing endpoint(s): ${missing.join(", ")}`,
        edge.id,
      );
    }
  }

  const vaultId = optionalString(options.vaultId);
  const userMetadataById = new Map(
    (options.userMetadata ?? []).map((metadata) => [metadata.userId, metadata]),
  );
  const nodes = Object.freeze(
    parsedNodes.map((node, ordinal): PermissionsGraphNodeRecord => {
      const userId = optionalString(node.data.userId);
      const userMetadata = userId ? userMetadataById.get(userId) : undefined;
      return Object.freeze({
        id: node.id,
        elementId: node.id,
        ordinal,
        kind: node.kind,
        label: optionalString(node.data.label),
        path: optionalString(node.data.path),
        userId,
        role: optionalString(node.data.role) ?? optionalString(userMetadata?.role),
        vaultId: optionalString(node.data.vaultId) ?? vaultId,
        displayName: optionalString(node.data.displayName) ?? optionalString(userMetadata?.displayName),
        email: optionalString(node.data.email) ?? optionalString(userMetadata?.email),
        aggregate: node.data.aggregate === true,
        aggregateCounts: aggregateCountsFromData(node.data),
        classes: node.classes,
        data: node.data,
      });
    }),
  );
  const edges = Object.freeze(
    parsedEdges.map((edge, ordinal): PermissionsGraphEdgeRecord => {
      const userId = optionalString(edge.data.userId);
      const userMetadata = userId ? userMetadataById.get(userId) : undefined;
      return Object.freeze({
        id: edge.id,
        elementId: edge.id,
        ordinal,
        kind: edge.kind,
        sourceId: edge.sourceId,
        targetId: edge.targetId,
        label: optionalString(edge.data.label),
        path: optionalString(edge.data.path),
        userId,
        role: optionalString(edge.data.role) ?? optionalString(userMetadata?.role),
        level: graphAccessLevel(edge.data.level),
        expiring: edge.data.expiring === true,
        aggregate: edge.data.aggregate === true,
        classes: edge.classes,
        data: edge.data,
      });
    }),
  );

  const model: PermissionsGraphModel = Object.freeze({
    vaultId,
    nodes,
    edges,
    nodeCount: nodes.length,
    edgeCount: edges.length,
    topologyFingerprint: topologyFingerprint(nodes, edges),
  });

  return Object.freeze({ model, index: new PermissionsGraphIndex(model) });
}

interface ParsedElementBase {
  readonly id: string;
  readonly classes: readonly string[];
  readonly data: Readonly<Record<string, unknown>>;
}

interface ParsedNode extends ParsedElementBase {
  readonly type: "node";
  readonly kind: PermissionsGraphNodeKind;
}

interface ParsedEdge extends ParsedElementBase {
  readonly type: "edge";
  readonly kind: PermissionsGraphEdgeKind;
  readonly sourceId: string;
  readonly targetId: string;
}

function parseElement(rawElement: unknown): ParsedNode | ParsedEdge {
  if (!isRecord(rawElement) || !isRecord(rawElement.data)) {
    throw new PermissionsGraphModelBuildError(
      "INVALID_ELEMENT",
      "Permissions graph elements must contain a data record.",
    );
  }

  const data = stableFrozenRecord(rawElement.data);
  const id = requiredString(data.id);
  if (!id) {
    throw new PermissionsGraphModelBuildError(
      "INVALID_ELEMENT_ID",
      "Permissions graph elements require a non-empty string data.id.",
    );
  }

  const rawKind = optionalString(data.kind);
  const edgeKind = normalizeEdgeKind(rawKind);
  const isEdge =
    edgeKind !== "unknown" ||
    Object.prototype.hasOwnProperty.call(data, "source") ||
    Object.prototype.hasOwnProperty.call(data, "target");
  const classes = normalizeClasses(rawElement.classes);

  if (!isEdge) {
    return Object.freeze({
      type: "node",
      id,
      kind: normalizeNodeKind(rawKind),
      classes,
      data,
    });
  }

  const sourceId = requiredString(data.source);
  const targetId = requiredString(data.target);
  if (!sourceId || !targetId) {
    throw new PermissionsGraphModelBuildError(
      "INVALID_EDGE_ENDPOINT",
      `Permissions graph edge ${id} requires non-empty string source and target IDs.`,
      id,
    );
  }

  return Object.freeze({
    type: "edge",
    id,
    kind: edgeKind,
    sourceId,
    targetId,
    classes,
    data,
  });
}

function normalizeNodeKind(kind: string | null): PermissionsGraphNodeKind {
  return kind && NODE_KINDS.has(kind as PermissionsGraphNodeKind)
    ? (kind as PermissionsGraphNodeKind)
    : "unknown";
}

function normalizeEdgeKind(kind: string | null): PermissionsGraphEdgeKind {
  return kind && EDGE_KINDS.has(kind as PermissionsGraphEdgeKind)
    ? (kind as PermissionsGraphEdgeKind)
    : "unknown";
}

function graphAccessLevel(value: unknown): GraphAccessLevel | null {
  return value === "none" || value === "read" || value === "write" || value === "admin"
    ? value
    : null;
}

function aggregateCountsFromData(
  data: Readonly<Record<string, unknown>>,
): PermissionsGraphAggregateCounts | null {
  if (data.aggregate !== true) return null;
  return Object.freeze({
    readableFiles: finiteCount(data.readableFiles),
    writableFiles: finiteCount(data.writableFiles),
    adminFiles: finiteCount(data.adminFiles),
    expiringGrants: finiteCount(data.expiringGrants),
  });
}

function finiteCount(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? Math.max(0, value) : 0;
}

function normalizeClasses(value: unknown): readonly string[] {
  const classes = typeof value === "string"
    ? value.split(/\s+/)
    : Array.isArray(value)
      ? value.filter((entry): entry is string => typeof entry === "string")
      : [];
  return Object.freeze(
    Array.from(new Set(classes.map((entry) => entry.trim()).filter(Boolean))).sort(compareStrings),
  );
}

function optionalString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function requiredString(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stableFrozenRecord(value: Record<string, unknown>): Readonly<Record<string, unknown>> {
  return stableFrozenValue(value, new WeakMap()) as Readonly<Record<string, unknown>>;
}

function stableFrozenValue(value: unknown, seen: WeakMap<object, unknown>): unknown {
  if (Array.isArray(value)) {
    const existing = seen.get(value);
    if (existing) return existing;
    const clone: unknown[] = [];
    seen.set(value, clone);
    for (const entry of value) clone.push(stableFrozenValue(entry, seen));
    return Object.freeze(clone);
  }
  if (isRecord(value)) {
    const existing = seen.get(value);
    if (existing) return existing;
    const clone: Record<string, unknown> = {};
    seen.set(value, clone);
    for (const key of Object.keys(value).sort(compareStrings)) {
      clone[key] = stableFrozenValue(value[key], seen);
    }
    return Object.freeze(clone);
  }
  return value;
}

function topologyFingerprint(
  nodes: readonly PermissionsGraphNodeRecord[],
  edges: readonly PermissionsGraphEdgeRecord[],
): string {
  let hash = 0x811c9dc5;
  const update = (value: string): void => {
    for (let index = 0; index < value.length; index += 1) {
      hash ^= value.charCodeAt(index);
      hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    hash ^= 0x1f;
    hash = Math.imul(hash, 0x01000193) >>> 0;
  };
  for (const node of nodes) update(`n:${node.id}:${node.kind}`);
  for (const edge of edges) {
    update(`e:${edge.id}:${edge.kind}:${edge.sourceId}:${edge.targetId}`);
  }
  return `fnv1a32:${hash.toString(16).padStart(8, "0")}`;
}

function collectUserMetadata(input: GraphBuilderInput): PermissionsGraphUserMetadata[] {
  const metadataById = new Map<string, PermissionsGraphUserMetadata>();
  for (const member of input.members) {
    metadataById.set(member.userId, metadataFromMember(member));
  }
  for (const summary of [...input.summaries, ...(input.folderSummaries ?? [])]) {
    for (const principal of summary.principals ?? []) {
      const existing = metadataById.get(principal.userId);
      metadataById.set(principal.userId, {
        userId: principal.userId,
        role: existing?.role ?? principal.role,
        displayName: existing?.displayName ?? principal.displayName,
        email: existing?.email ?? principal.email,
      });
    }
  }
  return Array.from(metadataById.values()).sort((left, right) =>
    compareStrings(left.userId, right.userId),
  );
}

function metadataFromMember(member: GraphMember): PermissionsGraphUserMetadata {
  return {
    userId: member.userId,
    role: member.role,
    displayName: member.displayName,
    email: member.email,
  };
}

function compareById<T extends { id: string }>(left: T, right: T): number {
  return compareStrings(left.id, right.id);
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function appendMapValue<K>(map: Map<K, string[]>, key: K, value: string): void {
  const values = map.get(key);
  if (values) values.push(value);
  else map.set(key, [value]);
}

function freezeArrayMap<K>(source: Map<K, string[]>, target: Map<K, readonly string[]>): void {
  for (const [key, values] of source) {
    target.set(key, freezeSortedIds(values));
  }
}

function freezeSortedIds(values: Iterable<string>): readonly string[] {
  return Object.freeze(Array.from(values).sort(compareStrings));
}
