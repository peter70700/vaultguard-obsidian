/**
 * PermissionStore — unified permission cache + event bus for VaultGuard.
 *
 * Phase 9 (.planning/phases/09-obsidian-cache-index-coherence-...) extracts
 * the permission cache + warm-up + invalidation fan-out from main.ts into a
 * single class with one canonical API:
 *   - `getPermission(path)` — read with TTL, walk-up, admin shortcut, offline fallback
 *   - `warm(rules, vaultRole)` — seed root + literal-rule entries (fetchedAt=0 sentinel)
 *   - `emit('changed', { path?, serverConfirmed? })` — fan-out trigger
 *   - `on('changed', handler)` — surfaces subscribe (auto-cleanup via Component.registerEvent)
 *   - `invalidate(path?)` — INTERNAL mutation only; does NOT fire 'changed'
 *
 * **Invariant (Pitfall 3 — re-entrance guard):** external invalidation goes
 * through `emit('changed')`. Internal cache mutations use `invalidate()` and
 * MUST NOT call `this.trigger('changed', ...)`. Surface listeners must call
 * their own render method, never `store.invalidate()` — otherwise infinite loop.
 *
 * D-02 isolation: this file does NOT import main.ts. All dependencies are
 * injected via `PermissionStoreConfig` so Vitest can instantiate the store
 * with mocks (see `tests/permission-store.test.ts`).
 *
 * `sweepLeavesAfterWarm` and `detachLeafWithNotice` are wired from main.ts
 * (warm-up calls the sweep directly, bypassing the bus) without callers
 * needing to reach into the class internals.
 */

import { App, Events, Notice, WorkspaceLeaf } from "obsidian";
import type { PermissionRule, VaultMemberRole } from "../api/client";
import type { UserSession } from "../types";
import { PermissionLevel } from "../types";

// ── Config + types ───────────────────────────────────────────────────────────

/**
 * Dependencies the store needs from the host plugin. Injected at construction
 * so the store has no direct knowledge of main.ts (D-02). Tests pass mocks.
 *
 * Note: there is intentionally no `apiClient` field here. The server probe is
 * already injected as `fetchPermissionLevelFromServer` (per D-02), which is
 * the correct boundary for nullability — that callback is responsible for
 * checking `this.apiClient` and `this.session` at call time. Injecting the
 * apiClient itself would (a) crash construction during `onload()` for users
 * with an empty `apiEndpoint` (manual / Community-edition self-hosters), and
 * (b) capture a stale reference across `rebuildApiClient()` calls. If a
 * future change inside the store needs the client, inject a live getter
 * `getApiClient: () => VaultGuardApiClient | null` rather than a captured
 * reference. (CR-01 + WR-01)
 */
export interface PermissionStoreConfig {
  /** Live getter for the current user session — may return null pre-login. */
  getSession: () => UserSession | null;
  /** Live getter for the current vault membership role; null when unknown. */
  getVaultMemberRole: () => VaultMemberRole | null;
  /** True when the network is believed reachable. */
  isOnline: () => boolean;
  /** Debug log sink — gated on settings.debugLogging by the caller. */
  log: (msg: string) => void;
  /** Optional callback fired when isOnline transitions to false from a fetch failure. */
  onOfflineDetected?: () => void;
  /**
   * Server-side per-path probe. Injected so the store doesn't duplicate
   * `apiRequest` / `toPermissionPath` plumbing. Implementation lives in
   * main.ts (port of `fetchPermissionLevelFromServer`).
   */
  fetchPermissionLevelFromServer: (path: string) => Promise<PermissionLevel>;
  /** Network-error classifier — port of main.ts:isNetworkError. */
  isNetworkError: (err: unknown) => boolean;
  /** Obsidian App handle — needed for metadataCache + workspace leaf access. */
  app: App;
}

/** Single cache entry. `fetchedAt === 0` is the warm-up-seeded sentinel (D-10). */
interface CacheEntry {
  level: PermissionLevel;
  /** Epoch ms when entry was fetched from server. `0` = warm-up seed, exempt from TTL (Pitfall 4). */
  fetchedAt: number;
}

// ── Constants ────────────────────────────────────────────────────────────────

/** Unified per-entry TTL (D-09). Matches existing header/sidebar caches. */
const CACHE_TTL_MS = 60_000;

/** Per-path debounce window for "Access revoked" Notice (D-19). */
const NOTICE_DEBOUNCE_MS = 5_000;

/** Yield to the event loop every N leaves during sweep (D-18). */
const LEAF_SWEEP_YIELD_BATCH = 50;

/**
 * D-12: module-level guard ensuring the metadataCache.deletePath unavailability
 * warning is logged at most once per Obsidian session, even if the plugin is
 * disabled/re-enabled (which constructs a fresh PermissionStore instance).
 * A per-instance flag would re-warn on every reconstruction (IN-01).
 */
let metadataCacheWarnedOnce = false;
let metadataPurgeFallbackNoticeShown = false;

// ── Store ────────────────────────────────────────────────────────────────────

/**
 * Wave 2 Fix 2 (1.0.31): observable store state so consumers (file
 * header, file-explorer decorations, sidebar) can render a neutral
 * skeleton until the warm-up actually lands. The pre-fix store had no
 * way to distinguish "ready" from "we just haven't fetched yet" from
 * "we tried to fetch and got a 401" — collapsing the latter two into
 * the viewer-baseline lie was the 2026-05-31 Pete incident.
 */
export type PermissionStoreState =
  | { kind: "cold" }
  | { kind: "warming" }
  | { kind: "warmed"; warmedAt: number }
  | { kind: "fetch-failed"; statusCode: number | null; failedAt: number };

export type PermissionDecision =
  | { kind: "verified"; level: PermissionLevel }
  | { kind: "cached"; level: PermissionLevel }
  | { kind: "unknown" };

export class PermissionStore extends Events {
  /** Unified permission cache. Empty-string key = vault root (warm-up seed). */
  private cache: Map<string, CacheEntry> = new Map();

  /** Wave 2 Fix 2 (1.0.31): observable store state. */
  private state: PermissionStoreState = { kind: "cold" };

  /** Concurrent-call deduplication (R-09-01). Same in-flight promise returned for same path. */
  private inFlight: Map<string, Promise<PermissionDecision>> = new Map();

  /** Vault-default level derived during warm-up — mirrors removed main.ts field. */
  private vaultDefaultPermission: PermissionLevel | null = null;

  /** Warm-up coalescing (donor: main.ts:2791-2807). */
  private warmupPromise: Promise<void> | null = null;

  /**
   * Public read-only handle to the in-flight warm-up promise. `null` when no
   * warm-up is running. Callers (main.ts:awaitPermissionWarmup) race this
   * against a timeout instead of polling — `Promise.race` does not start
   * additional timers when the timeout wins, so a stuck warm-up cannot leak
   * a chained `setTimeout` loop (fixes WR-02).
   */
  get inFlightWarmup(): Promise<void> | null {
    return this.warmupPromise;
  }

  /** D-15: NONE-streak counter for the 2-consecutive-local-NONE debounce. */
  private noneStreak: Map<string, number> = new Map();

  /** D-19: per-path Notice timestamp for 5s debounce. */
  private lastNoticeAt: Map<string, number> = new Map();

  /** D-12: one-time feature-detect of undocumented metadataCache.deletePath. */
  private metadataCacheDeleteAvailable = false;

  /**
   * Paths whose access has resolved to NONE during a permission-change sweep.
   * This is a supported fallback that does not depend on Obsidian's
   * undocumented metadataCache.deletePath. VaultGuard graph/agent metadata
   * readers consult this set and suppress these paths even if Obsidian's native
   * metadata cache still contains backlinks/tags until restart.
   */
  private metadataSuppressedPaths: Set<string> = new Set();

  constructor(private cfg: PermissionStoreConfig) {
    super();

    // D-12: feature-detect metadataCache.deletePath once at construction.
    // The method is undocumented (not in obsidian.d.ts) but present at
    // runtime on current Obsidian versions. Degrade gracefully if absent.
    // The "warned once" guard is module-level (see top of file) so that a
    // plugin disable/enable cycle does not produce duplicate warnings (IN-01).
    const mc = cfg.app.metadataCache as unknown as { deletePath?: (p: string) => void };
    this.metadataCacheDeleteAvailable = typeof mc.deletePath === "function";
    if (!this.metadataCacheDeleteAvailable && !metadataCacheWarnedOnce) {
      console.warn(
        "[VaultGuard] metadataCache.deletePath unavailable in this Obsidian version — " +
          "backlinks/tags from restricted files may persist until restart"
      );
      metadataCacheWarnedOnce = true;
    }

    // Self-subscribe: emit('changed') fires our own purge + leaf-sweep handler.
    // External surfaces register their own listeners separately via
    // `plugin.registerEvent(store.on('changed', handler))` for auto-cleanup.
    this.on("changed", (...args: unknown[]) => {
      const payload =
        (args[0] as { path?: string; serverConfirmed?: boolean } | undefined) ?? {};
      void this.handleChanged(payload.path, payload.serverConfirmed === true);
    });
  }

  // ── Public read API ────────────────────────────────────────────────────────

  /**
   * Resolves the effective permission level for the current user on a path.
   * Port of main.ts:5716 (`getEffectivePermission`) — preserves admin shortcut,
   * cache walk-up, server fetch on cold cache, offline fallback, and
   * network-error tolerance (D-03).
   *
   * Concurrent calls for the same path within the TTL share one in-flight
   * promise (R-09-01 dedup acceptance).
   */
  async getPermission(path: string): Promise<PermissionLevel> {
    const decision = await this.getPermissionDecision(path);
    return decision.kind === "unknown" ? PermissionLevel.NONE : decision.level;
  }

  /**
   * Resolves permission without overloading NONE as "no information". UI
   * callers use this discriminated result so a cold offline lookup stays
   * unknown, while hard enforcement callers keep using getPermission() and
   * therefore fail closed on unknown.
   */
  async getPermissionDecision(path: string): Promise<PermissionDecision> {
    // Cache check first — TTL gated, sentinel-zero exempt.
    const entry = this.cache.get(path);
    if (entry && !this.isExpired(entry)) {
      return { kind: "cached", level: entry.level };
    }

    const session = this.cfg.getSession();

    // No session means no permission can be established; fail closed.
    if (!session) {
      return { kind: "verified", level: PermissionLevel.NONE };
    }

    // Admin and owner roles always have full access — no server round-trip needed.
    if (session.role === "admin" || session.role === "owner") {
      this.cache.set(path, { level: PermissionLevel.ADMIN, fetchedAt: Date.now() });
      return { kind: "verified", level: PermissionLevel.ADMIN };
    }

    // Cache walk-up — when warm-up has seeded specific paths plus a
    // vault-default at the root, the parent walk usually answers without
    // a network round-trip. Hot path for non-admin viewers post-warm-up.
    const cached = this.resolvePermissionFromCache(path);
    if (cached && cached.level > PermissionLevel.NONE) {
      // Cache the walk-up answer with sentinel 0 so it doesn't TTL-expire —
      // walk-up answers are invalidated by event, not by clock (D-10).
      this.cache.set(path, { level: cached.level, fetchedAt: 0 });
      return cached;
    }
    // A cached denial is authoritative offline, but online we still probe so
    // a reconnect can replace it with current server truth immediately.
    if (!this.cfg.isOnline() && cached) {
      return cached;
    }

    // Coalesce concurrent network probes for the same path (R-09-01).
    const existingInFlight = this.inFlight.get(path);
    if (existingInFlight) return existingInFlight;

    const probe = this.probeServer(path);
    this.inFlight.set(path, probe);
    try {
      return await probe;
    } finally {
      this.inFlight.delete(path);
    }
  }

  /**
   * Synchronous, cache-only permission decision for bulk/offline UI fallback.
   * Unlike `getPermissionDecision`, this method can never call the backend,
   * mutate the cache, or join an in-flight probe. Unknown stays explicit so a
   * caller cannot mistake absence of evidence for an authoritative denial or
   * grant.
   */
  peekPermissionDecision(path: string): PermissionDecision {
    const normalized = this.normalizeVaultPath(path);
    const session = this.cfg.getSession();
    if (!session) {
      return { kind: "verified", level: PermissionLevel.NONE };
    }
    if (session.role === "admin" || session.role === "owner") {
      return { kind: "verified", level: PermissionLevel.ADMIN };
    }
    return this.resolvePermissionFromCache(normalized) ?? { kind: "unknown" };
  }

  /**
   * Synchronous cache probe. Used by Plan 09-02 / 09-03 fan-out handlers to
   * check "did this path just drop to NONE without firing another fetch".
   * Returns `undefined` when the path is uncached.
   *
   * Wave 2 Fix 2 (1.0.31): kept as a literal-cache probe — the bug Fix 2
   * prevents is the root-sentinel poisoning that happened when
   * `runWarm` was called with an empty rule set after a fetch failure.
   * That seeding never happens now (the fetch-failed path skips
   * `runWarm` entirely; only the state flag flips). Direct cache reads
   * via `getPermission` still populate entries that this probe should
   * see, so this method intentionally does NOT consult `state`.
   * Consumers that want to render based on lifecycle (skeleton vs
   * chip) call `getStoreState()` instead.
   */
  getCachedPermission(path: string): PermissionLevel | undefined {
    return this.cache.get(path)?.level;
  }

  /**
   * Wave 2 Fix 2 (1.0.31): exposes the store's lifecycle state so the
   * file header, file-explorer decorations, sidebar, and read-only
   * guard can render a loading skeleton (or a retry affordance, on
   * `fetch-failed`) instead of inventing a baseline answer.
   */
  getStoreState(): PermissionStoreState {
    return this.state;
  }

  /**
   * Defense-in-depth metadata side-channel guard. Returns true after a path has
   * resolved to NONE during a permission-change sweep and before a later sweep
   * proves the path is readable again.
   */
  isMetadataSuppressed(path: string): boolean {
    return this.metadataSuppressedPaths.has(this.normalizeVaultPath(path));
  }

  /** Wave 2 Fix 2 (1.0.31): set before a warm-up cycle starts. */
  markWarming(): void {
    if (this.state.kind === "warming") return;
    this.state = { kind: "warming" };
    this.notifyStoreStateChanged();
  }

  /**
   * Wave 2 Fix 2 (1.0.31): set when `runPermissionWarmup`'s rule fetch
   * fails. The cache itself is left untouched — pre-existing warm
   * entries from an earlier successful warm stay usable until a new
   * warm overwrites them. The state flip is what tells consumers to
   * render the skeleton / retry affordance.
   */
  markFetchFailed(statusCode: number | null): void {
    this.state = {
      kind: "fetch-failed",
      statusCode,
      failedAt: Date.now(),
    };
    this.notifyStoreStateChanged();
  }

  /**
   * Wave 2 Fix 2 (1.0.31): fires the lifecycle-only `state-changed`
   * event. Distinct from `changed` because `changed` triggers
   * `handleChanged`'s wildcard invalidation, which would wipe the very
   * cache entries `runWarm` just populated. UI consumers that want to
   * re-render on lifecycle flip (skeleton ↔ chip) subscribe to
   * `state-changed`; cache-invalidation consumers continue to use
   * `changed`. Tests assert both paths in isolation.
   */
  private notifyStoreStateChanged(): void {
    this.trigger("state-changed", { storeState: this.state });
  }

  // ── Warm-up ────────────────────────────────────────────────────────────────

  /**
   * Pre-fills the cache so non-admin users open files instantly post-login
   * instead of paying a 3-call permission probe per file. Port of
   * main.ts:2790-2870 (`runPermissionWarmup`) per D-04, with two adaptations:
   *
   *   1. Rules are passed in (the caller in main.ts fetches them).
   *   2. All cache writes use `fetchedAt: 0` sentinel — warm-up entries
   *      are NOT TTL-eligible (D-10, Pitfall 4).
   */
  async warm(_rules: PermissionRule[], vaultRole: VaultMemberRole | null): Promise<void> {
    if (this.warmupPromise) return this.warmupPromise;

    const promise = this.runWarm(_rules, vaultRole);
    this.warmupPromise = promise;
    try {
      await promise;
    } finally {
      if (this.warmupPromise === promise) {
        this.warmupPromise = null;
      }
    }
  }

  private async runWarm(rules: PermissionRule[], vaultRole: VaultMemberRole | null): Promise<void> {
    const session = this.cfg.getSession();
    if (!session) return;

    // Org-level admins/owners take the fast path — every getPermission call
    // short-circuits via the admin shortcut. No warm-up state needed, but we
    // still flip state to `warmed` (Wave 2 Fix 2, 1.0.31) so the file
    // header / decorations stop showing the skeleton — admins always have
    // the answer locally. Uses the lifecycle-only event so we don't
    // trip handleChanged's wildcard invalidation.
    if (session.role === "admin" || session.role === "owner") {
      this.state = { kind: "warmed", warmedAt: Date.now() };
      this.notifyStoreStateChanged();
      return;
    }

    const applicableRules = rules.filter(
      (rule) => this.ruleAppliesToCurrentUser(rule, session, vaultRole) && !this.ruleIsExpired(rule)
    );
    const hasDynamicRules = applicableRules.some((rule) => this.isGlobPattern(rule.pathPattern));

    const defaultLevel = this.deriveDefaultPermissionLevel(session, vaultRole);
    if (defaultLevel !== null) {
      this.vaultDefaultPermission = defaultLevel;
      // A root default is only safe when every applicable rule can be
      // represented by the literal ancestor cache below. Glob rules need
      // the backend matcher — otherwise a cached viewer READ could bypass
      // `/secret/**` denies or miss `/editable/**` write grants.
      if (!hasDynamicRules) {
        // Sentinel 0 = warm-up seed, exempt from TTL (Pitfall 4).
        this.cache.set("", { level: defaultLevel, fetchedAt: 0 });
      }
    }

    for (const rule of applicableRules) {
      // Glob patterns can't be exact-matched in the path-walk cache —
      // leave them to the per-file network probe.
      if (this.isGlobPattern(rule.pathPattern)) continue;

      const level = this.ruleToPermissionLevel(rule);
      const cacheKey = this.normalizeVaultPath(rule.pathPattern);
      const existing = this.cache.get(cacheKey);

      // Deny wins over allow at the same literal path — matches backend evaluator.
      if (rule.effect === "deny") {
        this.cache.set(cacheKey, { level: PermissionLevel.NONE, fetchedAt: 0 });
        continue;
      }
      if (existing && existing.level === PermissionLevel.NONE) continue;
      if (existing && existing.level >= level) continue;
      this.cache.set(cacheKey, { level, fetchedAt: 0 });
    }

    // Wave 2 Fix 2 (1.0.31): flip the state to `warmed` so consumers
    // can stop rendering the skeleton. Uses the lifecycle-only
    // `state-changed` event so handleChanged's wildcard invalidation
    // does NOT wipe the cache entries we just seeded above. UI
    // consumers (file-permission-header) subscribe to this event
    // explicitly via `permissionStore.on('state-changed', ...)`.
    this.state = { kind: "warmed", warmedAt: Date.now() };
    this.notifyStoreStateChanged();
  }

  // ── Event bus surface ──────────────────────────────────────────────────────

  /**
   * Public emit — surfaces and main.ts call sites use this to fan out an
   * invalidation. Payload `{ path }` scopes the change; omitting `path`
   * means "all paths". `serverConfirmed: true` marks the signal as
   * authoritative (D-17 — drives immediate leaf detach).
   *
   * Internally delegates to `Events.trigger` so registered `on('changed')`
   * listeners fire synchronously.
   */
  emit(
    name: "changed",
    payload?: {
      path?: string;
      serverConfirmed?: boolean;
      /** Confirmed authorization mutation that may revoke semantic-index access. */
      semanticAuthorityChanged?: boolean;
      storeState?: PermissionStoreState;
    }
  ): void {
    this.trigger(name, payload ?? {});
  }

  /**
   * Pure cache mutation. Does NOT fire 'changed' — Pitfall 3 re-entrance
   * guard. Callers that want subscribers notified must call
   * `emit('changed', { path })` separately.
   *
   * Used by the store's own handler and (eventually) by the wildcard
   * sweep to drop stale entries before re-probing.
   *
   * **noneStreak is intentionally NOT cleared here** — it tracks NONE
   * resolutions ACROSS emits and is owned exclusively by `sweepLeaves`,
   * which resets it on any non-NONE resolution (D-15). Wiping the streak
   * on every invalidate would defeat the 2-consecutive-NONE debounce
   * (D-15, D-16) because every emit calls invalidate before sweeping.
   */
  invalidate(path?: string): void {
    if (path === undefined) {
      this.cache.clear();
      this.inFlight.clear();
    } else {
      this.cache.delete(path);
      this.inFlight.delete(path);
    }
  }

  /** Pure cache clear — equivalent to `invalidate()` with no args. */
  clearAllCache(): void {
    this.invalidate();
  }

  // ── Startup leaf sweep ─────────────────────────────────────────────────────

  /**
   * Startup leaf-restore filter (R-09-06, D-20, D-21).
   *
   * Called directly from `main.ts` `restoreSession()` after `store.warm()`
   * resolves — NOT via the bus. Reason: bus listeners would re-render with
   * stale data while the sweep is in flight; the direct call avoids that
   * fan-out cost (D-21).
   *
   * `serverConfirmed=true` because warm-up is authoritative — first NONE
   * detaches immediately, no 2-emit debounce wait (D-20).
   */
  async sweepLeavesAfterWarm(): Promise<void> {
    await this.sweepLeaves(true);
  }

  // ── Private: change handler (metadataCache purge + leaf detach) ────────────

  /**
   * Fires from the self-subscription on every `emit('changed', ...)`.
   *
   * Per-path branch: probe `getPermission(path)`; if NONE and metadataCache
   * supports `deletePath`, purge the entry (D-13). Access grants
   * (NONE → READ/WRITE) rely on Obsidian's natural indexing — no purge.
   *
   * Wildcard branch (path undefined): snapshot previously-cached paths,
   * clear only the per-path entries (NOT the root sentinel — the warm-up
   * seed at `""` is preserved so cache walk-up still answers without a
   * server round trip), then for each previously-cached non-root path
   * resolve fresh; for any path that resolves to NONE, call deletePath
   * (D-14). noneStreak is preserved per the invalidate() contract (D-15).
   *
   * Why preserve the root sentinel (WR-04): wiping it forces every
   * re-resolve to fall through to a per-path server probe (3 API calls
   * each via fetchPermissionLevelFromServer), turning a single wildcard
   * emit into 3N HTTP calls for N cached files. Preserving root lets the
   * walk-up answer the long tail; only paths with explicit cached entries
   * beyond root might disagree with the root level and need re-probe.
   *
   * The leaf-detach branch runs via `sweepLeaves` (called below).
   */
  private async handleChanged(
    path: string | undefined,
    serverConfirmed: boolean
  ): Promise<void> {
    if (path !== undefined) {
      // Per-path: drop the cached entry so getPermission re-resolves fresh.
      this.invalidate(path);
      // Wrap re-probe in try/catch (WR-05): we are dispatched as
      // `void this.handleChanged(...)` from the self-subscription, so any
      // unexpected throw becomes an unhandled rejection. probeServer has its
      // own catch-all but future changes to getPermission must not be able
      // to break the fan-out. Pattern mirrors sweepLeaves.
      let level: PermissionLevel;
      try {
        level = await this.getPermission(path);
      } catch (err) {
        this.cfg.log(
          `Permission store: per-path re-resolve skipped "${path}" (resolve failed: ${(err as Error).message})`
        );
        // Still run the leaf sweep — it has its own per-leaf try/catch.
        await this.sweepLeaves(serverConfirmed, path);
        return;
      }
      this.applyMetadataPrivacyGuard(path, level);
      // Leaf sweep (per-path). filterPath narrows the sweep to leaves
      // currently viewing this path (Pitfall 5: rename emits OLD path,
      // but the leaf may now view the NEW path → filter prevents a
      // false-positive Notice + detach).
      await this.sweepLeaves(serverConfirmed, path);
      return;
    }

    // Wildcard: snapshot per-path keys (skipping root), clear only those
    // entries (preserve the root sentinel so cache walk-up still answers
    // the long tail without a server probe — WR-04), then re-resolve each.
    const previouslyCachedNonRoot = Array.from(this.cache.keys()).filter((k) => k !== "");
    for (const k of previouslyCachedNonRoot) {
      this.cache.delete(k);
      this.inFlight.delete(k);
    }
    for (const cachedPath of previouslyCachedNonRoot) {
      let level: PermissionLevel;
      try {
        level = await this.getPermission(cachedPath);
      } catch (err) {
        this.cfg.log(
          `Permission store: wildcard re-resolve skipped "${cachedPath}" (resolve failed: ${(err as Error).message})`
        );
        continue;
      }
      this.applyMetadataPrivacyGuard(cachedPath, level);
    }
    // Leaf sweep (wildcard). No filterPath — sweep every open leaf.
    await this.sweepLeaves(serverConfirmed);
  }

  // ── Private: leaf sweep (R-09-04..R-09-06) ─────────────────────────────────

  /**
   * Walks workspace leaves and detaches any whose viewed path resolves to NONE.
   *
   * Debounce semantics:
   * - `serverConfirmed=true` → immediate detach on first NONE; sets
   *   `noneStreak` to 2 to lock-in so a follow-up local resolution doesn't
   *   accidentally reset and require re-confirmation (D-17).
   * - `serverConfirmed=false` → requires 2 consecutive NONE resolutions for
   *   the same path (D-15, D-16).
   *
   * Deferred-view safety (Obsidian 1.7.2+ — Pitfall 2):
   * - `leaf.view.file` is undefined for deferred (background) leaves.
   * - Fallback: `leaf.getViewState().state.file` exposes the path without
   *   loading the view.
   *
   * Re-entrance (Pitfall 3): this method NEVER calls `this.emit` or
   * `this.trigger`. It mutates `this.noneStreak` and calls `leaf.detach()`
   * directly. Surface listeners must follow the same rule.
   *
   * When `filterPath` is supplied, the sweep only considers leaves whose
   * CURRENT viewed path equals `filterPath` (Pitfall 5: rename emits the
   * OLD path but the leaf already shows the NEW path).
   */
  private async sweepLeaves(serverConfirmed: boolean, filterPath?: string): Promise<void> {
    const candidates: Array<{ leaf: WorkspaceLeaf; path: string }> = [];
    this.cfg.app.workspace.iterateAllLeaves((leaf) => {
      const view = leaf.view as unknown as { file?: { path?: string } };
      let path = view?.file?.path;
      if (!path) {
        // Deferred-view fallback (Pitfall 2). getViewState is on WorkspaceLeaf
        // (obsidian.d.ts:7302); .state for markdown view contains a `file` key.
        const state = (leaf as unknown as { getViewState?: () => { state?: { file?: string } } })
          .getViewState?.()
          ?.state;
        path = state?.file;
      }
      if (!path) return;
      if (filterPath !== undefined && path !== filterPath) return;
      candidates.push({ leaf, path });
    });

    let processed = 0;
    for (const { leaf, path } of candidates) {
      // Yield every LEAF_SWEEP_YIELD_BATCH to avoid jank (D-18).
      if (processed > 0 && processed % LEAF_SWEEP_YIELD_BATCH === 0) {
        await new Promise<void>((resolve) => setTimeout(resolve, 0));
      }
      processed += 1;

      let level: PermissionLevel;
      try {
        level = await this.getPermission(path);
      } catch (err) {
        this.cfg.log(`Permission store: sweep skipped "${path}" (resolve failed: ${(err as Error).message})`);
        continue;
      }

      if (level === PermissionLevel.NONE) {
        if (serverConfirmed) {
          this.noneStreak.set(path, 2); // D-17 lock-in
          await this.detachLeafWithNotice(leaf, path);
        } else {
          const streak = (this.noneStreak.get(path) ?? 0) + 1;
          this.noneStreak.set(path, streak);
          if (streak >= 2) {
            await this.detachLeafWithNotice(leaf, path);
          }
        }
      } else {
        // Non-NONE resolution resets the streak (D-15).
        this.noneStreak.delete(path);
      }
    }
  }

  private applyMetadataPrivacyGuard(path: string, level: PermissionLevel): void {
    const normalized = this.normalizeVaultPath(path);
    if (!normalized) return;

    if (level !== PermissionLevel.NONE) {
      this.metadataSuppressedPaths.delete(normalized);
      return;
    }

    this.metadataSuppressedPaths.add(normalized);

    if (!this.metadataCacheDeleteAvailable) {
      this.notifyMetadataPurgeFallback();
      return;
    }

    try {
      (this.cfg.app.metadataCache as unknown as { deletePath: (p: string) => void }).deletePath(normalized);
    } catch (err) {
      this.cfg.log(`[VaultGuard] metadataCache.deletePath('${normalized}') threw: ${(err as Error).message}`);
      this.notifyMetadataPurgeFallback();
    }
  }

  private notifyMetadataPurgeFallback(): void {
    if (metadataPurgeFallbackNoticeShown) return;
    metadataPurgeFallbackNoticeShown = true;
    new Notice(
      "VaultGuard Sync: Obsidian could not purge restricted-file metadata automatically. " +
        "VaultGuard graph and AI metadata are hidden for revoked paths; restart Obsidian to clear native backlinks/tags.",
      12000
    );
  }

  // ── Private: leaf detach ───────────────────────────────────────────────────

  /**
   * Detach a workspace leaf and fire a debounced "Access revoked" Notice.
   * Donor pattern: main.ts cloudDecryptFallbackNoticeAt / corruptedWriteNoticeAt
   * — per-path 5s debounce window so multi-pane detach of the same file
   * fires one Notice, not N (D-19).
   *
   * `leaf.detach()` is idempotent (assumption A3 in RESEARCH); a stray throw
   * is logged and swallowed so it can't break the sweep loop.
   *
   * Pitfall 3: this method does NOT call `this.emit` / `this.trigger`.
   */
  private async detachLeafWithNotice(leaf: WorkspaceLeaf, path: string): Promise<void> {
    const now = Date.now();
    const last = this.lastNoticeAt.get(path) ?? 0;
    try {
      leaf.detach();
    } catch (err) {
      this.cfg.log(`Permission store: leaf.detach failed for "${path}": ${(err as Error).message}`);
    }
    if (now - last > NOTICE_DEBOUNCE_MS) {
      new Notice(`Access revoked: ${this.basename(path)}`);
      this.lastNoticeAt.set(path, now);
    }
  }

  // ── Private: server probe + cache walk-up + helpers ────────────────────────

  private async probeServer(path: string): Promise<PermissionDecision> {
    try {
      if (this.cfg.isOnline()) {
        const level = await this.cfg.fetchPermissionLevelFromServer(path);
        this.cache.set(path, { level, fetchedAt: Date.now() });
        return { kind: "verified", level };
      }
      // Offline: cache-only resolution.
      return this.resolvePermissionFromCache(path) ?? { kind: "unknown" };
    } catch (error) {
      if (this.cfg.isNetworkError(error)) {
        this.cfg.onOfflineDetected?.();
        return this.resolvePermissionFromCache(path) ?? { kind: "unknown" };
      }
      this.cfg.log(`Permission check failed for "${path}", falling back to cache: ${error}`);
      return this.resolvePermissionFromCache(path) ?? { kind: "unknown" };
    }
  }

  /**
   * Walks up the directory hierarchy looking for cached permissions; falls
   * back to the empty-string root key (vault-default warm-up seed). Port of
   * main.ts:5891-5910 with one TTL adaptation: expired non-sentinel entries
   * are ignored so a stale server-fetched answer doesn't shadow a fresh
   * re-probe (the original didn't have TTL so this case never existed).
   */
  private resolvePermissionFromCache(
    path: string
  ): { kind: "cached"; level: PermissionLevel } | null {
    const segments = path.split("/");
    for (let i = segments.length; i > 0; i--) {
      const parentPath = segments.slice(0, i).join("/");
      const entry = this.cache.get(parentPath);
      if (entry && !this.isExpired(entry)) return { kind: "cached", level: entry.level };
    }
    const rootEntry = this.cache.get("");
    if (rootEntry && !this.isExpired(rootEntry)) {
      return { kind: "cached", level: rootEntry.level };
    }
    return null;
  }

  /** TTL check — sentinel-zero entries (warm-up seeds + walk-up cached) are exempt (D-10). */
  private isExpired(entry: CacheEntry): boolean {
    if (entry.fetchedAt === 0) return false;
    return Date.now() - entry.fetchedAt > CACHE_TTL_MS;
  }

  // ── Private: ruleset helpers (ported verbatim from main.ts:2872-2932) ──────

  private deriveDefaultPermissionLevel(
    session: UserSession,
    vaultRole: VaultMemberRole | null
  ): PermissionLevel | null {
    const role = vaultRole ?? this.deriveSessionVaultRole(session);
    if (!role) return null;
    switch (role) {
      case "admin":
        return PermissionLevel.ADMIN;
      case "editor":
        return PermissionLevel.WRITE;
      case "viewer":
        return PermissionLevel.READ;
      default:
        return null;
    }
  }

  private deriveSessionVaultRole(session: UserSession): VaultMemberRole | null {
    // Session roles are org-level; map onto the vault-member axis.
    const role = session.role;
    if (role === "admin" || role === "owner") return "admin";
    if (role === "editor") return "editor";
    if (role === "member") return "viewer";
    return null;
  }

  private ruleAppliesToCurrentUser(
    rule: PermissionRule,
    session: UserSession,
    vaultRole: VaultMemberRole | null
  ): boolean {
    if (rule.userId === "*") return true;
    if (rule.userId === session.userId) return true;
    if (
      session.email &&
      rule.userId.trim().toLowerCase() === session.email.trim().toLowerCase()
    ) {
      return true;
    }
    if (rule.role) {
      const userRoles = [
        ...(vaultRole ? [vaultRole] : []),
        ...(session.roles?.length ? session.roles : [session.role]),
      ];
      return userRoles.includes(rule.role);
    }
    return false;
  }

  private ruleToPermissionLevel(rule: PermissionRule): PermissionLevel {
    if (rule.effect === "deny") return PermissionLevel.NONE;
    if (rule.actions.includes("admin")) return PermissionLevel.ADMIN;
    if (rule.actions.includes("write") || rule.actions.includes("delete")) {
      return PermissionLevel.WRITE;
    }
    if (rule.actions.includes("read") || rule.actions.includes("list")) {
      return PermissionLevel.READ;
    }
    return PermissionLevel.NONE;
  }

  private ruleIsExpired(rule: PermissionRule): boolean {
    return typeof rule.expiresAt === "string" && rule.expiresAt <= new Date().toISOString();
  }

  private isGlobPattern(pattern: string): boolean {
    return pattern.includes("*") || pattern.includes("?") || pattern.includes("[");
  }

  private normalizeVaultPath(path: string): string {
    // Strip leading slashes; do not invoke obsidian's normalizePath here so
    // tests don't require an extra mock surface beyond what setup.ts provides.
    return path.replace(/^\/+/, "");
  }

  private basename(path: string): string {
    const idx = path.lastIndexOf("/");
    return idx >= 0 ? path.slice(idx + 1) : path;
  }
}

export default PermissionStore;
