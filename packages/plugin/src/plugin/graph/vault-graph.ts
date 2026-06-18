// VaultGraph — a read-only navigator over Obsidian's in-memory
// `app.metadataCache` (docs/AI-GRAPH-CONTEXT.md §4). It exposes the vault's
// link/backlink/tag structure to the AgentBridge tool surface WITHOUT reading
// any file off disk and WITHOUT shipping plaintext anywhere — the metadata
// cache is computed by Obsidian from already-decrypted content and lives in
// RAM only.
//
// THE LOAD-BEARING INVARIANT (§4.1): the metadata cache indexes the WHOLE
// vault, including notes outside the lease scope and notes the requester has
// no permission to read. Every path in every result MUST pass `canSee()`
// before it is emitted, or the graph becomes a side channel leaking the
// existence and link structure of files the requester can't read. This
// mirrors the Share-Link Rule: structure is not a capability — re-check
// permissions on the way out.

import { PermissionLevel } from "../../types";
import type {
  GraphApp,
  GraphLinkRef,
  GraphPermissionDeps,
  HubRef,
  HubsResult,
  NeighborsResult,
  OrphansResult,
  OverviewResult,
  RelatedRef,
  RelatedResult,
  RelatedVia,
  SharedTagRef,
  TagCountRef,
  TagResult,
} from "./graph-types";

const LOG_PREFIX = "[VaultGuard]";

const DEFAULT_NEIGHBORS_LIMIT = 50;
const DEFAULT_RELATED_LIMIT = 25;
const DEFAULT_TAG_LIMIT = 100;
const DEFAULT_ORPHANS_LIMIT = 100;
const DEFAULT_HUBS_LIMIT = 20;
const DEFAULT_OVERVIEW_TOP = 10;
const MAX_LIMIT = 100;
const MAX_DEPTH = 3;

// related() scoring weights (§4): a direct link or backlink is worth far more
// than merely sharing a tag.
const SCORE_LINK = 3;
const SCORE_BACKLINK = 3;
const SCORE_SHARED_TAG = 1;

export class VaultGraph {
  // Per-call memo of canSee() decisions. Cleared at the start of every public
  // op so a permission change between calls is always re-read, but a single op
  // never asks the same path twice.
  private canSeeCache = new Map<string, boolean>();

  constructor(
    private readonly app: GraphApp,
    private readonly deps: GraphPermissionDeps,
  ) {}

  async neighbors(path: string, depth = 1): Promise<NeighborsResult> {
    this.resetCache();
    const limit = this.clampLimit(undefined, DEFAULT_NEIGHBORS_LIMIT);
    const _depth = this.clampDepth(depth);
    const target = this.normalize(path);

    const result: NeighborsResult = {
      path: target,
      outgoing: [],
      backlinks: [],
      tags: [],
      sharedTags: [],
      truncated: false,
    };

    // If the requester can't see the target itself, reveal nothing about it.
    if (!target || !(await this.canSee(target))) {
      return result;
    }

    const resolved = this.resolvedLinks();

    // Outgoing: resolved links FROM the target. Filter every emitted path.
    const outgoing: GraphLinkRef[] = [];
    for (const [linked, count] of Object.entries(resolved[target] ?? {})) {
      const p = this.normalize(linked);
      if (p === target) continue;
      if (!(await this.canSee(p))) continue;
      outgoing.push({ path: p, count });
    }
    outgoing.sort((a, b) => b.count - a.count || a.path.localeCompare(b.path));

    // Backlinks: every note whose resolvedLinks include the target.
    const backlinks: GraphLinkRef[] = [];
    for (const [source, links] of Object.entries(resolved)) {
      const sp = this.normalize(source);
      if (sp === target) continue;
      const count = links[target];
      if (!count) continue;
      if (!(await this.canSee(sp))) continue;
      backlinks.push({ path: sp, count });
    }
    backlinks.sort((a, b) => b.count - a.count || a.path.localeCompare(b.path));

    // Tags on the target.
    const targetTags = this.tagsOf(target);
    result.tags = [...targetTags].sort();

    // Shared tags: other visible notes carrying at least one of the same tags.
    const sharedTags: SharedTagRef[] = [];
    if (targetTags.size > 0) {
      for (const candidate of this.allNotePaths()) {
        if (candidate === target) continue;
        const candTags = this.tagsOf(candidate);
        if (candTags.size === 0) continue;
        const shared = [...candTags].filter((t) => targetTags.has(t)).sort();
        if (shared.length === 0) continue;
        if (!(await this.canSee(candidate))) continue;
        sharedTags.push({ path: candidate, tags: shared });
      }
    }
    sharedTags.sort((a, b) => b.tags.length - a.tags.length || a.path.localeCompare(b.path));

    result.outgoing = this.capList(outgoing, limit, result);
    result.backlinks = this.capList(backlinks, limit, result);
    result.sharedTags = this.capList(sharedTags, limit, result);
    return result;
  }

  async related(path: string, depth = 1, limit?: number): Promise<RelatedResult> {
    this.resetCache();
    const cap = this.clampLimit(limit, DEFAULT_RELATED_LIMIT);
    const maxDepth = this.clampDepth(depth);
    const target = this.normalize(path);

    const result: RelatedResult = { path: target, related: [], truncated: false };
    if (!target || !(await this.canSee(target))) {
      return result;
    }

    const resolved = this.resolvedLinks();
    const targetTags = this.tagsOf(target);

    // score map keyed by visible candidate path
    const scores = new Map<string, { score: number; via: Set<RelatedVia> }>();
    const bump = (p: string, weight: number, via: RelatedVia) => {
      const entry = scores.get(p) ?? { score: 0, via: new Set<RelatedVia>() };
      entry.score += weight;
      entry.via.add(via);
      scores.set(p, entry);
    };

    // BFS over resolvedLinks (outgoing + backlinks) to `maxDepth`. Each hop's
    // contribution decays so closer notes outrank distant ones.
    const visited = new Set<string>([target]);
    let frontier: string[] = [target];
    for (let d = 0; d < maxDepth; d++) {
      const decay = maxDepth - d; // depth 1 → highest weight
      const next: string[] = [];
      for (const node of frontier) {
        // outgoing links
        for (const linked of Object.keys(resolved[node] ?? {})) {
          const p = this.normalize(linked);
          if (p === target) continue;
          if (!(await this.canSee(p))) continue;
          bump(p, SCORE_LINK * decay, "link");
          if (!visited.has(p)) {
            visited.add(p);
            next.push(p);
          }
        }
        // backlinks
        for (const [source, links] of Object.entries(resolved)) {
          if (!links[node]) continue;
          const sp = this.normalize(source);
          if (sp === target) continue;
          if (!(await this.canSee(sp))) continue;
          bump(sp, SCORE_BACKLINK * decay, "backlink");
          if (!visited.has(sp)) {
            visited.add(sp);
            next.push(sp);
          }
        }
      }
      frontier = next;
      if (frontier.length === 0) break;
    }

    // shared tags (depth-independent, weight 1)
    if (targetTags.size > 0) {
      for (const candidate of this.allNotePaths()) {
        if (candidate === target) continue;
        const candTags = this.tagsOf(candidate);
        if (candTags.size === 0) continue;
        const shared = [...candTags].filter((t) => targetTags.has(t));
        if (shared.length === 0) continue;
        if (!(await this.canSee(candidate))) continue;
        bump(candidate, SCORE_SHARED_TAG * shared.length, "shared-tag");
      }
    }

    const ranked: RelatedRef[] = [...scores.entries()]
      .map(([p, { score, via }]) => ({ path: p, score, via: [...via].sort() }))
      .sort((a, b) => b.score - a.score || a.path.localeCompare(b.path));

    if (ranked.length > cap) {
      result.related = ranked.slice(0, cap);
      result.truncated = true;
    } else {
      result.related = ranked;
    }
    return result;
  }

  async tag(tag: string, limit?: number): Promise<TagResult> {
    this.resetCache();
    const cap = this.clampLimit(limit, DEFAULT_TAG_LIMIT);
    const wanted = this.normalizeTag(tag);
    const result: TagResult = { tag: wanted, notes: [], truncated: false };
    if (!wanted) return result;

    const notes: string[] = [];
    for (const path of this.allNotePaths()) {
      if (!this.tagsOf(path).has(wanted)) continue;
      if (!(await this.canSee(path))) continue;
      notes.push(path);
    }
    notes.sort();
    if (notes.length > cap) {
      result.notes = notes.slice(0, cap);
      result.truncated = true;
    } else {
      result.notes = notes;
    }
    return result;
  }

  async orphans(limit?: number): Promise<OrphansResult> {
    this.resetCache();
    const cap = this.clampLimit(limit, DEFAULT_ORPHANS_LIMIT);
    // Visible-subgraph degree: a note linked ONLY by notes the requester
    // can't see is effectively an orphan to them, and counting those hidden
    // edges would leak their existence (§4.1).
    const degrees = await this.visibleDegreeMap();
    const result: OrphansResult = { orphans: [], truncated: false };

    const orphans: string[] = [];
    for (const path of this.allNotePaths()) {
      if ((degrees.get(path) ?? 0) > 0) continue;
      if (!(await this.canSee(path))) continue;
      orphans.push(path);
    }
    orphans.sort();
    if (orphans.length > cap) {
      result.orphans = orphans.slice(0, cap);
      result.truncated = true;
    } else {
      result.orphans = orphans;
    }
    return result;
  }

  async hubs(limit?: number): Promise<HubsResult> {
    this.resetCache();
    const cap = this.clampLimit(limit, DEFAULT_HUBS_LIMIT);
    // Degree over the visible subgraph only — the emitted `degree` must not
    // reflect edges to/from notes the requester can't see (§4.1).
    const degrees = await this.visibleDegreeMap();
    const result: HubsResult = { hubs: [], truncated: false };

    const hubs: HubRef[] = [];
    for (const [path, degree] of degrees.entries()) {
      if (degree <= 0) continue;
      if (!(await this.canSee(path))) continue;
      hubs.push({ path, degree });
    }
    hubs.sort((a, b) => b.degree - a.degree || a.path.localeCompare(b.path));
    if (hubs.length > cap) {
      result.hubs = hubs.slice(0, cap);
      result.truncated = true;
    } else {
      result.hubs = hubs;
    }
    return result;
  }

  async overview(): Promise<OverviewResult> {
    this.resetCache();
    const resolved = this.resolvedLinks();

    let noteCount = 0;
    let linkCount = 0;
    let orphanCount = 0;
    const hubList: HubRef[] = [];
    const tagCounts = new Map<string, number>();

    for (const path of this.allNotePaths()) {
      if (!(await this.canSee(path))) continue;
      noteCount++;

      // Count only links whose destination is ALSO visible — an invisible
      // target must not be inferable from an inflated link count.
      const outgoing = resolved[path] ?? {};
      let visibleDegree = 0;
      for (const [linked, count] of Object.entries(outgoing)) {
        const p = this.normalize(linked);
        if (p === path) continue;
        if (!(await this.canSee(p))) continue;
        linkCount += count;
        visibleDegree += count;
      }
      // backlink contribution to degree
      for (const [source, links] of Object.entries(resolved)) {
        const sp = this.normalize(source);
        if (sp === path) continue;
        if (!links[path]) continue;
        if (!(await this.canSee(sp))) continue;
        visibleDegree += links[path];
      }

      if (visibleDegree <= 0) orphanCount++;
      else hubList.push({ path, degree: visibleDegree });

      for (const t of this.tagsOf(path)) {
        tagCounts.set(t, (tagCounts.get(t) ?? 0) + 1);
      }
    }

    const topHubs = hubList
      .sort((a, b) => b.degree - a.degree || a.path.localeCompare(b.path))
      .slice(0, DEFAULT_OVERVIEW_TOP);

    const topTags: TagCountRef[] = [...tagCounts.entries()]
      .map(([t, count]) => ({ tag: t, count }))
      .sort((a, b) => b.count - a.count || a.tag.localeCompare(b.tag))
      .slice(0, DEFAULT_OVERVIEW_TOP);

    return { noteCount, linkCount, orphanCount, topHubs, topTags };
  }

  // ───────────────────────────────────────────────────────────────────────────
  // The load-bearing filter (§4.1)
  // ───────────────────────────────────────────────────────────────────────────

  private async canSee(path: string): Promise<boolean> {
    const p = this.normalize(path);
    if (!p) return false;
    const cached = this.canSeeCache.get(p);
    if (cached !== undefined) return cached;

    let visible: boolean;
    if (this.deps.isPathExcluded(p)) {
      visible = false;
    } else if (!this.deps.matchesLeaseScope(p)) {
      visible = false;
    } else {
      visible = (await this.deps.getPermission(p)) !== PermissionLevel.NONE;
    }
    this.canSeeCache.set(p, visible);
    return visible;
  }

  private resetCache(): void {
    this.canSeeCache.clear();
  }

  // ───────────────────────────────────────────────────────────────────────────
  // metadataCache readers (no filesystem access)
  // ───────────────────────────────────────────────────────────────────────────

  private resolvedLinks(): Record<string, Record<string, number>> {
    return this.app.metadataCache.resolvedLinks ?? {};
  }

  /**
   * Every note path Obsidian knows about: the union of resolvedLinks sources
   * and their resolved destinations. (A note with no links still shows up as
   * a key in resolvedLinks with an empty object, so orphans are covered.)
   */
  private allNotePaths(): string[] {
    const set = new Set<string>();
    const resolved = this.resolvedLinks();
    for (const [source, links] of Object.entries(resolved)) {
      set.add(this.normalize(source));
      for (const dest of Object.keys(links)) set.add(this.normalize(dest));
    }
    set.delete("");
    return [...set];
  }

  /**
   * Undirected degree (outgoing + incoming) over the VISIBLE subgraph only.
   * An edge contributes to a note's degree only when BOTH endpoints pass
   * canSee(), so a note's reported degree can never reflect — and thereby
   * leak — links to/from files the requester can't read (§4.1). Visible notes
   * with no visible edges still appear with degree 0 (orphans).
   */
  private async visibleDegreeMap(): Promise<Map<string, number>> {
    const degrees = new Map<string, number>();
    const add = (p: string, n: number) => degrees.set(p, (degrees.get(p) ?? 0) + n);
    const resolved = this.resolvedLinks();
    for (const [source, links] of Object.entries(resolved)) {
      const sp = this.normalize(source);
      if (!(await this.canSee(sp))) continue;
      if (!degrees.has(sp)) degrees.set(sp, 0); // ensure orphans appear with 0
      for (const [dest, count] of Object.entries(links)) {
        const dp = this.normalize(dest);
        if (dp === sp) continue;
        if (!(await this.canSee(dp))) continue;
        add(sp, count);
        add(dp, count);
      }
    }
    return degrees;
  }

  private tagsOf(path: string): Set<string> {
    const cache = this.app.metadataCache.getCache(path);
    const tags = new Set<string>();
    if (!cache) return tags;
    for (const t of cache.tags ?? []) {
      const clean = this.normalizeTag(t.tag);
      if (clean) tags.add(clean);
    }
    const fmTags = cache.frontmatter?.tags;
    if (typeof fmTags === "string") {
      const clean = this.normalizeTag(fmTags);
      if (clean) tags.add(clean);
    } else if (Array.isArray(fmTags)) {
      for (const raw of fmTags) {
        if (typeof raw !== "string") continue;
        const clean = this.normalizeTag(raw);
        if (clean) tags.add(clean);
      }
    }
    return tags;
  }

  // ───────────────────────────────────────────────────────────────────────────
  // helpers
  // ───────────────────────────────────────────────────────────────────────────

  private capList<T>(items: T[], limit: number, result: { truncated: boolean }): T[] {
    if (items.length > limit) {
      result.truncated = true;
      return items.slice(0, limit);
    }
    return items;
  }

  private normalize(path: string): string {
    return String(path ?? "")
      .replace(/\\/g, "/")
      .replace(/^\/+/, "")
      .replace(/\/+$/, "")
      .replace(/\/\/+/g, "/");
  }

  private normalizeTag(tag: string): string {
    return String(tag ?? "").trim().replace(/^#+/, "").toLocaleLowerCase();
  }

  private clampLimit(value: number | undefined, fallback: number): number {
    const v = value ?? fallback;
    if (!Number.isFinite(v)) return fallback;
    return Math.max(1, Math.min(MAX_LIMIT, Math.floor(v)));
  }

  private clampDepth(value: number | undefined): number {
    const v = value ?? 1;
    if (!Number.isFinite(v)) return 1;
    return Math.max(1, Math.min(MAX_DEPTH, Math.floor(v)));
  }
}

// Silence unused-prefix lint without changing the public log conventions; the
// service logs nothing on the hot path (it must stay cheap), but keeps the
// project-standard prefix available for future diagnostics.
void LOG_PREFIX;
