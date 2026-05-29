/**
 * File Explorer Decorations — injects permission badges, sharing indicators,
 * and mini avatar stacks onto the native Obsidian file explorer via DOM manipulation.
 *
 * Uses a debounced MutationObserver to detect when the file explorer re-renders
 * and re-applies decorations. Permission data is fetched from the backend in
 * batches and cached so the sidebar dots/avatars stay perfectly aligned with
 * the file header's source of truth (the Lambda permission evaluator).
 */

import { App, setIcon } from "obsidian";
import {
  VaultGuardApiClient,
  PathAccessPrincipal,
  PathAccessSummary,
  PermissionAccessLevel,
  UserListEntry,
  VaultMemberRecord,
} from "../api/client";
import { PermissionLevel } from "../types";
import { buildAccessUserMap, getAccessUserDisplayName, getAccessUserNameInitials } from "./access-user-utils";

// ─── Constants ─────────────────────────────────────────────────────────────

const DECORATION_CLS = "vaultguard-fe-decoration";
const HIDDEN_CLS = "vaultguard-fe-hidden";
const CACHE_TTL_MS = 120_000; // 2 minutes
const PARTIAL_CACHE_TTL_MS = 15_000; // retry principal summaries quickly when only dots are known
const DEBOUNCE_MS = 300; // debounce observer-triggered repaints
const ATTACH_RETRY_MS = 1_000; // file explorer can mount after plugin load
const BATCH_PATH_LIMIT = 100; // matches backend cap

// ─── Types ─────────────────────────────────────────────────────────────────

type DecorationLevel = PermissionAccessLevel | "unknown";

interface DecorationCacheEntry {
  level: DecorationLevel;
  sharedWith: number;
  principals: Array<{ id: string; label: string; level: PermissionAccessLevel; type: "user" | "role" }>;
  fetchedAt: number;
  source?: "backend" | "level-only" | "fallback";
}

export interface FileExplorerDecorationsConfig {
  app: App;
  apiClient: VaultGuardApiClient;
  currentUserId: string;
  currentUserRole: string;
  isReady?: () => boolean;
  getPermissionLevel?: (path: string) => Promise<PermissionLevel>;
}

// ─── Main Class ────────────────────────────────────────────────────────────

export class FileExplorerDecorations {
  private config: FileExplorerDecorationsConfig;
  private cache: Map<string, DecorationCacheEntry> = new Map();
  private inFlightPaths: Map<string, Promise<void>> = new Map();
  private observer: MutationObserver | null = null;
  private observedContainer: HTMLElement | null = null;
  private enabled = false;
  private isDecorating = false; // guard against observer re-entry
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;
  private attachRetryTimer: ReturnType<typeof setTimeout> | null = null;
  private users: UserListEntry[] = [];
  private userMap: Map<string, UserListEntry> = new Map();
  private usersLoaded = false;
  private usersLoadPromise: Promise<void> | null = null;
  private vaultMembersLoaded = false;
  private vaultMembersLoadPromise: Promise<void> | null = null;
  private batchAccessUnavailable = false;

  constructor(config: FileExplorerDecorationsConfig) {
    this.config = config;
  }

  /**
   * Start observing the file explorer and decorating items.
   * Safe to call multiple times — will not stack observers.
   */
  enable(): void {
    if (this.enabled) {
      this.observeFileExplorer();
      this.scheduleDecorate();
      return;
    }
    this.enabled = true;
    this.observeFileExplorer();
    this.scheduleDecorate();
  }

  /**
   * Stop observing and remove all decorations.
   */
  disable(): void {
    this.enabled = false;
    this.cancelDebounce();
    this.cancelAttachRetry();
    this.stopObserver();
    this.removeAllDecorations();
  }

  /**
   * Force re-decoration of all visible items (e.g. after permission change).
   */
  refresh(): void {
    this.cache.clear();
    this.inFlightPaths.clear();
    if (this.enabled) {
      this.scheduleDecorate();
    }
  }

  /**
   * Invalidate cache for a specific path (or all). When called without a
   * path, also drops the user directory so a newly-invited user shows up
   * with their real name on the next decorate pass instead of their UUID.
   */
  invalidate(path?: string): void {
    if (path) {
      this.cache.delete(path);
      this.inFlightPaths.delete(path);
    } else {
      this.cache.clear();
      this.inFlightPaths.clear();
      // Clear the user directory too — a permission grant may target a user
      // who was just invited and isn't in the cached map. Without this,
      // their chip would render as their UUID until the next session.
      this.clearUserDirectory();
    }
    if (this.enabled) {
      this.scheduleDecorate();
    }
  }

  /**
   * Updates identity fields (currentUserId / currentUserRole) without
   * tearing the observer down. Used when the user's effective vault role
   * changes — e.g. after login completes or the vault binding is switched.
   * Clears the cache so badges re-render with the new role context.
   */
  setConfig(updates: { currentUserId?: string; currentUserRole?: string }): void {
    const identityChanged = updates.currentUserId !== undefined && updates.currentUserId !== this.config.currentUserId;
    if (updates.currentUserId !== undefined) {
      this.config.currentUserId = updates.currentUserId;
    }
    if (updates.currentUserRole !== undefined) {
      this.config.currentUserRole = updates.currentUserRole;
    }
    this.cache.clear();
    this.inFlightPaths.clear();
    if (identityChanged) {
      this.clearUserDirectory();
    }
    if (this.enabled) {
      this.scheduleDecorate();
    }
  }

  /**
   * Clean up observers and timers.
   */
  destroy(): void {
    this.disable();
    this.cache.clear();
    this.inFlightPaths.clear();
  }

  // ─── DOM Observation ──────────────────────────────────────────────────

  private observeFileExplorer(): void {
    const explorerEl = this.getFileExplorerContainer();
    if (!explorerEl) {
      this.stopObserver();
      this.scheduleAttachRetry();
      return;
    }

    this.cancelAttachRetry();

    if (this.observer && this.observedContainer === explorerEl) {
      return;
    }

    this.stopObserver();
    this.observedContainer = explorerEl;

    this.observer = new MutationObserver(() => {
      // If we caused the mutation ourselves, ignore it
      if (this.isDecorating) return;
      this.scheduleDecorate();
    });

    this.observer.observe(explorerEl, {
      childList: true,
      subtree: true,
    });
  }

  private stopObserver(): void {
    if (this.observer) {
      this.observer.disconnect();
      this.observer = null;
    }
    this.observedContainer = null;
  }

  private getFileExplorerContainer(): HTMLElement | null {
    const leaves = this.config.app.workspace.getLeavesOfType("file-explorer");
    if (leaves.length === 0) return null;

    const leaf = leaves[0] as typeof leaves[0] & {
      isDeferred?: boolean;
      loadIfDeferred?: () => Promise<void>;
    };

    // On mobile the file explorer lives in a collapsed left drawer. Under
    // Obsidian's deferred-views model (1.7.2+) the leaf's view is a placeholder
    // with no .nav-file-title rows until the drawer is shown. Reading
    // containerEl now would attach the observer to a stale element that never
    // gets file items. Force the real view to load and return null for this
    // pass — the attach-retry timer and the layout/leaf-change listeners
    // re-run decoration once the live view has mounted.
    if (leaf.isDeferred === true) {
      if (typeof leaf.loadIfDeferred === "function") {
        void leaf.loadIfDeferred().then(() => {
          if (this.enabled) this.scheduleDecorate();
        });
      }
      this.scheduleAttachRetry();
      return null;
    }

    return leaf.view.containerEl;
  }

  // ─── Debounced Decoration ─────────────────────────────────────────────

  private scheduleDecorate(): void {
    this.cancelDebounce();
    this.debounceTimer = setTimeout(() => {
      this.debounceTimer = null;
      this.decorateAll();
    }, DEBOUNCE_MS);
  }

  private cancelDebounce(): void {
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
    }
  }

  private scheduleAttachRetry(): void {
    if (!this.enabled || this.attachRetryTimer) return;
    this.attachRetryTimer = setTimeout(() => {
      this.attachRetryTimer = null;
      if (!this.enabled) return;
      this.observeFileExplorer();
      this.scheduleDecorate();
    }, ATTACH_RETRY_MS);
  }

  private cancelAttachRetry(): void {
    if (this.attachRetryTimer) {
      clearTimeout(this.attachRetryTimer);
      this.attachRetryTimer = null;
    }
  }

  // ─── Decoration Logic ─────────────────────────────────────────────────

  private async decorateAll(): Promise<void> {
    if (!this.enabled) return;

    if (!this.isReady()) {
      this.removeAllDecorations();
      return;
    }

    const container = this.getFileExplorerContainer();
    if (!container) {
      this.observeFileExplorer();
      return;
    }

    // The file explorer leaf can be replaced when Obsidian changes layout or
    // the left sidebar is toggled. Keep the observer attached to the live leaf.
    this.observeFileExplorer();

    // Snapshot visible items + paths so we know what to fetch.
    const items = this.getExplorerItems(container);
    const itemPaths: Array<{ item: HTMLElement; path: string; isFile: boolean }> = [];
    const pathsToFetch: string[] = [];
    const seenPaths = new Set<string>();

    for (const item of items) {
      const path = this.getItemPath(item);
      if (!path) continue;
      const isFile = this.isExplorerFileItem(item);
      itemPaths.push({ item, path, isFile });
      if (!seenPaths.has(path) && this.needsFetch(path)) {
        seenPaths.add(path);
        pathsToFetch.push(path);
      }
    }

    // Kick off backend fetches (user directory + path access summaries). If
    // those calls fail, rows still get a role-based fallback decoration below
    // so the native explorer never looks like VaultGuard forgot to render.
    await this.loadPrincipalDirectoryIfNeeded();
    if (pathsToFetch.length > 0) {
      await this.fetchAccessForPaths(pathsToFetch);
    }

    // Guard: set flag so observer ignores our own DOM mutations
    this.isDecorating = true;
    try {
      for (const { item, path, isFile } of itemPaths) {
        const cachedEntry = this.cache.get(path);
        const entry = cachedEntry ?? this.fallbackEntry();

        // Only file rows are hidden on an explicit no-access result. Folder
        // path checks are not reliable enough to collapse folder rows:
        // Obsidian only renders expanded descendants into the DOM, so a
        // collapsed folder can look like it has no accessible children even
        // when it contains readable files. Keeping folders visible prevents
        // an entire vault tree from disappearing.
        const shouldHide = cachedEntry ? this.shouldHideItem(isFile, cachedEntry) : false;
        item.classList.toggle(HIDDEN_CLS, shouldHide);

        this.applyDecoration(item, entry);
      }
    } finally {
      this.isDecorating = false;
    }
  }

  private needsFetch(path: string): boolean {
    if (this.inFlightPaths.has(path)) return false;
    const cached = this.cache.get(path);
    if (!cached) return true;
    if (cached.source !== "backend") {
      return Date.now() - cached.fetchedAt >= PARTIAL_CACHE_TTL_MS;
    }
    return Date.now() - cached.fetchedAt >= CACHE_TTL_MS;
  }

  private getExplorerItems(container: HTMLElement): HTMLElement[] {
    const primary = Array.from(
      container.querySelectorAll<HTMLElement>(".nav-file-title, .nav-folder-title")
    );
    if (primary.length > 0) return primary;

    // Obsidian's file-explorer markup has shifted across versions. Most
    // builds expose .nav-file-title/.nav-folder-title, but some place the
    // useful data-path on a generic tree item. Fall back to data-path rows so
    // native navigation still gets badges when the title classes are absent.
    return Array.from(container.querySelectorAll<HTMLElement>("[data-path]")).filter(
      (item) =>
        !item.classList.contains(DECORATION_CLS) &&
        !item.closest(`.${DECORATION_CLS}`) &&
        Boolean(
          item.classList.contains("nav-file-title") ||
          item.classList.contains("nav-folder-title") ||
          item.classList.contains("tree-item-self") ||
          item.closest(".nav-file") ||
          item.closest(".nav-folder")
        )
    );
  }

  private isExplorerFileItem(item: HTMLElement): boolean {
    if (item.classList.contains("nav-file-title")) return true;
    if (item.classList.contains("nav-folder-title")) return false;
    const owner = item.closest<HTMLElement>(".nav-file, .nav-folder");
    return Boolean(owner?.classList.contains("nav-file"));
  }

  private applyDecoration(item: HTMLElement, data: DecorationCacheEntry): void {
    // Remove existing decoration if present
    this.removeDecoration(item);

    const decoration = createDiv({ cls: DECORATION_CLS });

    // Permission level dot
    const levelDot = decoration.createSpan({
      cls: `vaultguard-fe-level-dot vaultguard-fe-dot-${data.level}`,
    });
    levelDot.title = this.formatLevel(data.level);

    // Sharing indicator — only show if shared with others
    if (data.sharedWith > 0) {
      const shareIndicator = decoration.createSpan({
        cls: "vaultguard-fe-share-indicator",
      });

      const avatarStack = shareIndicator.createSpan({
        cls: "vaultguard-fe-avatar-stack",
      });

      const maxAvatars = 3;
      const shown = data.principals.slice(0, maxAvatars);
      for (const principal of shown) {
        const avatar = avatarStack.createSpan({
          cls: `vaultguard-fe-mini-avatar vaultguard-fe-avatar-${principal.level}`,
        });

        if (principal.type === "role") {
          setIcon(avatar, "users");
        } else if (principal.id === "*") {
          setIcon(avatar, "globe");
        } else {
          avatar.setText(this.initials(principal.id, principal.label));
        }
        avatar.title = `${principal.label} (${this.formatLevel(principal.level)})`;
      }

      if (data.sharedWith > maxAvatars) {
        avatarStack.createSpan({
          cls: "vaultguard-fe-avatar-overflow",
          text: `+${data.sharedWith - maxAvatars}`,
        });
      }
    }

    item.appendChild(decoration);
  }

  private removeDecoration(item: HTMLElement): void {
    const existing = item.querySelector(`.${DECORATION_CLS}`);
    if (existing) existing.remove();
  }

  private removeAllDecorations(): void {
    const container = this.getFileExplorerContainer();
    if (!container) return;

    this.isDecorating = true;
    try {
      const decorations = Array.from(container.querySelectorAll(`.${DECORATION_CLS}`));
      for (const dec of decorations) {
        dec.remove();
      }
      const hidden = Array.from(container.querySelectorAll(`.${HIDDEN_CLS}`));
      for (const item of hidden) {
        item.classList.remove(HIDDEN_CLS);
      }
    } finally {
      this.isDecorating = false;
    }
  }

  private shouldHideItem(isFile: boolean, entry: DecorationCacheEntry): boolean {
    return entry.level === "none" && isFile;
  }

  private fallbackEntry(): DecorationCacheEntry {
    return {
      level: "unknown",
      sharedWith: 0,
      principals: [],
      fetchedAt: 0,
      source: "fallback",
    };
  }

  private getItemPath(item: HTMLElement): string | null {
    const directPath = item.dataset.path;
    if (directPath) return directPath;

    const owner = item.closest<HTMLElement>("[data-path]");
    return owner?.dataset.path ?? null;
  }

  // ─── Data Fetching (backend source of truth) ──────────────────────────

  /**
   * Fetches access summaries for the given paths via the batch endpoint and
   * stores them in the cache. Splits requests into chunks of `BATCH_PATH_LIMIT`
   * to respect the backend cap. Concurrent requests for the same path are
   * deduplicated via `inFlightPaths`.
   */
  private async fetchAccessForPaths(paths: string[]): Promise<void> {
    if (!this.isReady()) return;

    // Dedupe paths that already have an in-flight fetch.
    const pending: string[] = [];
    const inFlightForThisCall: Array<Promise<void>> = [];
    for (const path of paths) {
      const existing = this.inFlightPaths.get(path);
      if (existing) {
        inFlightForThisCall.push(existing);
      } else {
        pending.push(path);
      }
    }

    // Chunk + fire requests; record one promise per path so concurrent
    // decorate passes can coalesce on it.
    for (let i = 0; i < pending.length; i += BATCH_PATH_LIMIT) {
      const chunk = pending.slice(i, i + BATCH_PATH_LIMIT);
      const requestPromise = this.fetchPathDataChunk(chunk);
      for (const path of chunk) {
        this.inFlightPaths.set(path, requestPromise);
      }
      inFlightForThisCall.push(requestPromise);
      // Detach the cleanup so the in-flight entry clears whether or not
      // the request succeeded.
      requestPromise.finally(() => {
        for (const path of chunk) {
          if (this.inFlightPaths.get(path) === requestPromise) {
            this.inFlightPaths.delete(path);
          }
        }
      });
    }

    if (inFlightForThisCall.length > 0) {
      await Promise.allSettled(inFlightForThisCall);
    }
  }

  private async fetchPathDataChunk(paths: string[]): Promise<void> {
    await Promise.allSettled([this.fetchBatchChunk(paths)]);
    // Must run after access summaries: the PermissionStore/enforcement path is
    // authoritative for the current user's own dot. Access summaries provide
    // principals/avatars and can lag during backend rollout, so they must not
    // overwrite the enforced level.
    await this.fetchEffectiveLevelsForPaths(paths);
  }

  private async fetchBatchChunk(paths: string[]): Promise<void> {
    if (this.batchAccessUnavailable) {
      await this.fetchPerPathFallback(paths);
      return;
    }

    try {
      const summaries = await this.config.apiClient.getBatchPathAccess(paths);
      const byPath = new Map(summaries.map((s) => [this.normalizePath(s.path), s]));
      const now = Date.now();
      for (const path of paths) {
        const normalized = this.normalizePath(path);
        const summary = byPath.get(normalized);
        if (summary) {
          this.cache.set(path, this.summaryToCacheEntry(summary, now));
        }
      }
    } catch (err) {
      if (this.shouldSilentlySkipAccessFetch(err)) {
        return;
      }
      if (this.isMissingBatchAccessRoute(err)) {
        this.batchAccessUnavailable = true;
        await this.fetchPerPathFallback(paths);
        return;
      }
      // Batch endpoint failed — most likely a backend deployment-drift
      // where the /permissions/access/batch route's authorizer isn't wired
      // up correctly in the live stage (Terraform code has it, but the
      // deployed stage rejects valid Cognito tokens with a SigV4-style
      // challenge). The single-path /permissions/access endpoint uses the
      // same Lambda handler and works, so fall back to N parallel per-path
      // calls. Slower for large vaults, but correct, and prevents one
      // bad route from leaving the file explorer with no decorations.
      console.warn("[VaultGuard] Batch access fetch failed, falling back to per-path:", (err as Error)?.message ?? err);
      await this.fetchPerPathFallback(paths);
    }
  }

  /**
   * Resolves the current user's level through the same PermissionStore path
   * used by read-only/write/delete enforcement. The access-summary endpoint is
   * still useful for "who else has access" avatars, but this value owns the
   * native explorer's primary dot so the UI cannot claim READ when writes
   * would actually be allowed.
   */
  private async fetchEffectiveLevelsForPaths(paths: string[]): Promise<void> {
    if (!this.config.getPermissionLevel) return;

    const now = Date.now();
    await Promise.allSettled(
      paths.map(async (path) => {
        const level = await this.config.getPermissionLevel!(path);
        this.mergeEffectiveLevel(path, this.permissionLevelToAccessLevel(level), now);
      })
    );
  }

  private mergeEffectiveLevel(
    path: string,
    level: PermissionAccessLevel,
    fetchedAt: number
  ): void {
    const existing = this.cache.get(path);
    this.cache.set(path, {
      level,
      sharedWith: existing?.sharedWith ?? 0,
      principals: existing?.principals ?? [],
      fetchedAt,
      source: existing?.source ?? "level-only",
    });
  }

  /**
   * Per-path fallback for fetchBatchChunk. Issues N parallel
   * getPathAccess() requests, with caching on cache.set so subsequent
   * decorate passes (debounced via the MutationObserver) hit warm data.
   * Errors per path are individually swallowed so one failed file
   * doesn't poison the rest.
   */
  private async fetchPerPathFallback(paths: string[]): Promise<void> {
    const now = Date.now();
    await Promise.allSettled(
      paths.map(async (path) => {
        try {
          const summary = await this.config.apiClient.getPathAccess(path);
          this.cache.set(path, this.summaryToCacheEntry(summary, now));
        } catch {
          // Individual path failure — leave the cache untouched so a later
          // decorate pass will retry. Don't write a "none" entry: that
          // would hide a row whose access we genuinely don't know yet.
        }
      })
    );
  }

  private isReady(): boolean {
    return this.config.isReady ? this.config.isReady() : true;
  }

  private shouldSilentlySkipAccessFetch(err: unknown): boolean {
    const message = err instanceof Error ? err.message.toLowerCase() : String(err).toLowerCase();
    return (
      message.includes("not authenticated") ||
      message.includes("please log in") ||
      message.includes("session expired") ||
      message.includes("api endpoint appears to be pointing at a website")
    );
  }

  private isMissingBatchAccessRoute(err: unknown): boolean {
    const message = err instanceof Error ? err.message.toLowerCase() : String(err).toLowerCase();
    return (
      message.includes("route not found") &&
      message.includes("/permissions/access/batch")
    );
  }

  private normalizePath(path: string): string {
    const trimmed = path.trim().replace(/\/+/g, "/");
    return trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  }

  private summaryToCacheEntry(
    summary: PathAccessSummary,
    fetchedAt: number
  ): DecorationCacheEntry {
    const principals = summary.principals
      .filter((p) => p.userId !== this.config.currentUserId)
      .filter((p) => p.level !== "none")
      .map((p) => ({
        id: p.userId,
        label: this.principalLabel(p),
        level: p.level,
        type: "user" as const,
      }))
      .sort((a, b) => this.levelRank(b.level) - this.levelRank(a.level));

    return {
      level: summary.currentUserLevel,
      sharedWith: principals.length,
      principals,
      fetchedAt,
      source: "backend",
    };
  }

  private principalLabel(principal: PathAccessPrincipal): string {
    if (principal.displayName) return principal.displayName;
    if (principal.email) return principal.email;
    const user = this.userMap.get(principal.userId);
    if (user) return getAccessUserDisplayName(user);
    return principal.userId;
  }

  private async loadUsersIfNeeded(): Promise<void> {
    if (this.usersLoaded) return;
    if (this.usersLoadPromise) {
      await this.usersLoadPromise;
      return;
    }
    this.usersLoadPromise = (async () => {
      try {
        const users = await this.config.apiClient.listUsers();
        this.mergeUsersIntoDirectory(users);
        this.usersLoaded = true;
      } catch {
        // Silently fail — the org-wide /users route is admin-only in normal
        // deployments. Vault members and backend principal labels still give
        // non-admins real names, so do not retry this endpoint on every
        // decorate pass.
        this.usersLoaded = true;
      } finally {
        this.usersLoadPromise = null;
      }
    })();
    await this.usersLoadPromise;
  }

  private async loadVaultMembersIfNeeded(): Promise<void> {
    if (this.vaultMembersLoaded) return;
    if (this.vaultMembersLoadPromise) {
      await this.vaultMembersLoadPromise;
      return;
    }
    this.vaultMembersLoadPromise = (async () => {
      const getVaultId = this.config.apiClient.getVaultId;
      const vaultId = typeof getVaultId === "function"
        ? getVaultId.call(this.config.apiClient)
        : "";
      if (!vaultId) {
        this.vaultMembersLoaded = true;
        return;
      }

      try {
        if (typeof this.config.apiClient.listVaultMembers !== "function") {
          this.vaultMembersLoaded = true;
          return;
        }
        const members = await this.config.apiClient.listVaultMembers(vaultId);
        this.mergeVaultMembersIntoDirectory(members);
        this.vaultMembersLoaded = true;
      } catch {
        // Leave loaded=false so a later full refresh can try again. This
        // route is the non-admin-safe name source for avatar initials.
        this.vaultMembersLoaded = false;
      } finally {
        this.vaultMembersLoadPromise = null;
      }
    })();
    await this.vaultMembersLoadPromise;
  }

  private async loadPrincipalDirectoryIfNeeded(): Promise<void> {
    await Promise.allSettled([
      this.loadUsersIfNeeded(),
      this.loadVaultMembersIfNeeded(),
    ]);
  }

  private mergeUsersIntoDirectory(users: UserListEntry[]): void {
    if (users.length === 0) return;

    const byId = new Map(this.users.map((user) => [user.id, user]));
    for (const user of users) {
      byId.set(user.id, user);
    }
    this.users = [...byId.values()];
    this.userMap = buildAccessUserMap(this.users);
  }

  private mergeVaultMembersIntoDirectory(members: VaultMemberRecord[]): void {
    if (members.length === 0) return;

    const byId = new Map(this.users.map((user) => [user.id, user]));
    let changed = false;

    for (const member of members) {
      const existing = byId.get(member.userId);
      if (existing && this.shouldKeepExistingIdentity(existing, member)) continue;
      if (!member.displayName && !member.email) continue;

      byId.set(member.userId, {
        id: member.userId,
        email: member.email ?? "",
        displayName: member.displayName ?? "",
        name: member.displayName ?? "",
        role: this.mapVaultRoleToUserRole(member.role),
        status: "active",
        lastActive: "",
        createdAt: member.joinedAt,
        mfaEnabled: false,
        deviceCount: 0,
        type: "user",
      });
      changed = true;
    }

    if (!changed) return;
    this.users = [...byId.values()];
    this.userMap = buildAccessUserMap(this.users);
  }

  private clearUserDirectory(): void {
    this.users = [];
    this.userMap = new Map();
    this.usersLoaded = false;
    this.usersLoadPromise = null;
    this.vaultMembersLoaded = false;
    this.vaultMembersLoadPromise = null;
  }

  private shouldKeepExistingIdentity(user: UserListEntry, member: VaultMemberRecord): boolean {
    if (user.displayName?.trim() || user.name?.trim()) return true;
    return Boolean(user.email?.trim() && !member.displayName?.trim());
  }

  private mapVaultRoleToUserRole(role: VaultMemberRecord["role"]): UserListEntry["role"] {
    switch (role) {
      case "admin": return "admin";
      case "editor": return "editor";
      case "viewer":
      default: return "viewer";
    }
  }

  // ─── Helpers ──────────────────────────────────────────────────────────

  private levelRank(level: DecorationLevel): number {
    switch (level) {
      case "admin": return 3;
      case "write": return 2;
      case "read": return 1;
      default: return 0;
    }
  }

  private formatLevel(level: DecorationLevel): string {
    switch (level) {
      case "admin": return "Admin";
      case "write": return "Write";
      case "read": return "Read";
      case "none": return "No Access";
      case "unknown": return "Checking permissions";
    }
  }

  private permissionLevelToAccessLevel(level: PermissionLevel): PermissionAccessLevel {
    if (level >= PermissionLevel.ADMIN) return "admin";
    if (level >= PermissionLevel.WRITE) return "write";
    if (level >= PermissionLevel.READ) return "read";
    return "none";
  }

  private initials(userId: string, label: string): string {
    if (userId === "*") return "*";
    const user = this.userMap.get(userId);
    if (user) return getAccessUserNameInitials(user);
    // Prefer initials derived from the human label (display name / email)
    // before falling back to the UUID — UUIDs make for unreadable chips.
    const source = label && label !== userId ? label : userId;
    const parts = source.split(/[\s@._-]+/).filter(Boolean);
    return parts
      .slice(0, 2)
      .map((p) => p[0]?.toUpperCase() ?? "")
      .join("");
  }
}
