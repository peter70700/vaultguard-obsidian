// Result shapes and dependency contracts for the VaultGraph service
// (docs/AI-GRAPH-CONTEXT.md §3.1, §4). All shapes are intentionally compact —
// they are token-cheap by design so the model can navigate structure without
// reading whole files.

import type { PermissionLevel } from "../../types";

// ─────────────────────────────────────────────────────────────────────────────
// Dependency contracts
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Permission/scope gates the graph re-checks on the way out. Identical in
 * spirit to AgentBridgeDeps — `getPermission` is wired to the same
 * `getEffectivePermission`, `isPathExcluded` to the same `permissionStore`
 * matcher, and `matchesLeaseScope` to the per-lease scope predicate the
 * bridge builds from the lease.
 */
export interface GraphPermissionDeps {
  isPathExcluded(path: string): boolean;
  getPermission(path: string): Promise<PermissionLevel>;
  matchesLeaseScope(path: string): boolean;
}

/**
 * Narrow read-only slice of Obsidian's `App` that VaultGraph actually touches.
 * The real `App` satisfies this structurally, and tests can hand in a fake
 * without dragging the whole Obsidian surface in. VaultGraph reads ONLY this
 * in-memory metadata — never the filesystem, never the at-rest cipher.
 */
export interface GraphApp {
  metadataCache: GraphMetadataCache;
}

export interface GraphMetadataCache {
  // path → { linkedPath → count } for every resolved outgoing link in the vault.
  resolvedLinks: Record<string, Record<string, number>>;
  // Path-based cache lookup (Obsidian's `MetadataCache.getCache(path)`).
  getCache(path: string): GraphFileCache | null;
}

export interface GraphFileCache {
  links?: Array<{ link: string }>;
  embeds?: Array<{ link: string }>;
  tags?: Array<{ tag: string }>;
  frontmatter?: { tags?: unknown } & Record<string, unknown>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Result shapes (§3.1)
// ─────────────────────────────────────────────────────────────────────────────

export interface GraphLinkRef {
  path: string;
  count: number;
}

export interface SharedTagRef {
  path: string;
  tags: string[];
}

export interface NeighborsResult {
  path: string;
  outgoing: GraphLinkRef[];
  backlinks: GraphLinkRef[];
  tags: string[];
  sharedTags: SharedTagRef[];
  truncated: boolean;
}

export type RelatedVia = "link" | "backlink" | "shared-tag";

export interface RelatedRef {
  path: string;
  score: number;
  via: RelatedVia[];
}

export interface RelatedResult {
  path: string;
  related: RelatedRef[];
  truncated: boolean;
}

export interface TagResult {
  tag: string;
  notes: string[];
  truncated: boolean;
}

export interface OrphansResult {
  orphans: string[];
  truncated: boolean;
}

export interface HubRef {
  path: string;
  degree: number;
}

export interface HubsResult {
  hubs: HubRef[];
  truncated: boolean;
}

export interface TagCountRef {
  tag: string;
  count: number;
}

export interface OverviewResult {
  noteCount: number;
  linkCount: number;
  orphanCount: number;
  topHubs: HubRef[];
  topTags: TagCountRef[];
}

export type GraphOp =
  | "neighbors"
  | "related"
  | "tag"
  | "orphans"
  | "hubs"
  | "overview";

export interface GraphArgs {
  op: GraphOp;
  path?: string;
  tag?: string;
  depth?: number;
  limit?: number;
}

export type GraphResult =
  | NeighborsResult
  | RelatedResult
  | TagResult
  | OrphansResult
  | HubsResult
  | OverviewResult;
