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
} from "../api/client";
import { buildAccessUserMap, getAccessUserDisplayName, getAccessUserNameInitials } from "./access-user-utils";

// ─── Constants ─────────────────────────────────────────────────────────────

const DECORATION_CLS = "vaultguard-fe-decoration";
const HIDDEN_CLS = "vaultguard-fe-hidden";
const CACHE_TTL_MS = 120_000; // 2 minutes
const DEBOUNCE_MS = 300; // debounce observer-triggered repaints
const ATTACH_RETRY_MS = 1_000; // file explorer can mount after plugin load
const BATCH_PATH_LIMIT = 100; // matches backend cap

// ─── Types ─────────────────────────────────────────────────────────────────

interface DecorationCacheEntry {
  level: PermissionAccessLevel;
  sharedWith: number;
  principals: Array<{ id: string; label: string; level: PermissionAccessLevel; type: "user" | "role" }>;
  fetchedAt: number;
}

export interface FileExplorerDecorationsConfig {
  app: App;
  apiClient: VaultGuardApiClient;
  currentUserId: string;
  currentUserRole: string;
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
  private userMap: Map<string, UserListEntry> = new Map();
  private usersLoaded = false;
  private usersLoadPromise: Promise<void> | null = null;

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
      this.userMap = new Map();
      this.usersLoaded = false;
      this.usersLoadPromise = null;
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
    if (updates.currentUserId !== undefined) {
      this.config.currentUserId = updates.currentUserId;
    }
    if (updates.currentUserRole !== undefined) {
      this.config.currentUserRole = updates.currentUserRole;
    }
    this.cache.clear();
    this.inFlightPaths.clear();
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
    return leaves[0].view.containerEl;
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

    const container = this.getFileExplorerContainer();
    if (!container) {
      this.observeFileExplorer();
      return;
    }

    // The file explorer leaf can be replaced when Obsidian changes layout or
    // the left sidebar is toggled. Keep the observer attached to the live leaf.
    this.observeFileExplorer();

    // Snapshot visible items + paths so we know what to fetch.
    const items = Array.from(
      container.querySelectorAll<HTMLElement>(".nav-file-title, .nav-folder-title")
    );
    const itemPaths: Array<{ item: HTMLElement; path: string; isFile: boolean }> = [];
    const pathsToFetch: string[] = [];
    const seenPaths = new Set<string>();

    for (const item of items) {
      const path = this.getItemPath(item);
      if (!path) continue;
      const isFile = item.classList.contains("nav-file-title");
      itemPaths.push({ item, path, isFile });
      if (!seenPaths.has(path) && this.needsFetch(path)) {
        seenPaths.add(path);
        pathsToFetch.push(path);
      }
    }

    // Kick off backend fetches (user directory + path access summaries).
    // The first paint may run before fetches return — items without cached
    // data render in their "loading" state (no decoration). The MutationObserver
    // would normally re-trigger us on every mutation; the in-flight guard
    // below keeps us from stampeding the server with duplicate requests.
    await this.loadUsersIfNeeded();
    if (pathsToFetch.length > 0) {
      await this.fetchAccessForPaths(pathsToFetch);
    }

    // Guard: set flag so observer ignores our own DOM mutations
    this.isDecorating = true;
    try {
      // First pass: resolve every path's effective level so we can decide
      // folder visibility based on whether any descendant grants access.
      const accessiblePaths = new Set<string>();
      for (const { path } of itemPaths) {
        const entry = this.cache.get(path);
        if (entry && entry.level !== "none") accessiblePaths.add(path);
      }

      const hasAccessibleDescendant = (folderPath: string): boolean => {
        const prefix = folderPath + "/";
        for (const p of accessiblePaths) {
          if (p.startsWith(prefix)) return true;
        }
        return false;
      };

      for (const { item, path, isFile } of itemPaths) {
        const entry = this.cache.get(path);

        // If we have no cached entry (fetch failed, or stale and refresh
        // pending), leave the row unhidden and skip decoration — never hide
        // a row based on a guess. The Obsidian file explorer treats absent
        // decorations as "no info" rather than "no access", which is the
        // safer default for a permission UI.
        if (!entry) {
          item.classList.remove(HIDDEN_CLS);
          this.removeDecoration(item);
          continue;
        }

        // Files: hide when the user has no access. Folders: hide only when
        // the user has no access AND no descendant grants access — otherwise
        // we'd hide a folder containing accessible children.
        const shouldHide =
          entry.level === "none" && (isFile || !hasAccessibleDescendant(path));
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
    return Date.now() - cached.fetchedAt >= CACHE_TTL_MS;
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
      const requestPromise = this.fetchBatchChunk(chunk);
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

  private async fetchBatchChunk(paths: string[]): Promise<void> {
    try {
      const summaries = await this.config.apiClient.getBatchPathAccess(paths);
      const byPath = new Map(summaries.map((s) => [this.normalizePath(s.path), s]));
      const now = Date.now();
      for (const path of paths) {
        const normalized = this.normalizePath(path);
        const summary = byPath.get(normalized);
        if (summary) {
          this.cache.set(path, this.summaryToCacheEntry(summary, now));
        } else {
          // Backend returned nothing for this path — treat as "no access"
          // so the row is hidden. This matches the explicit "currentUserLevel:
          // 'none'" branch the handler takes when the caller can't read the path.
          this.cache.set(path, {
            level: "none",
            sharedWith: 0,
            principals: [],
            fetchedAt: now,
          });
        }
      }
    } catch {
      // On error, don't poison the cache. The next decorate pass will retry
      // the path because needsFetch() sees no cached entry.
    }
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
        this.userMap = buildAccessUserMap(users);
        this.usersLoaded = true;
      } catch {
        // Silently fail — backend principal labels still come through; this
        // is only a fallback for initials.
      } finally {
        this.usersLoadPromise = null;
      }
    })();
    await this.usersLoadPromise;
  }

  // ─── Helpers ──────────────────────────────────────────────────────────

  private levelRank(level: PermissionAccessLevel): number {
    switch (level) {
      case "admin": return 3;
      case "write": return 2;
      case "read": return 1;
      default: return 0;
    }
  }

  private formatLevel(level: PermissionAccessLevel): string {
    switch (level) {
      case "admin": return "Admin";
      case "write": return "Write";
      case "read": return "Read";
      default: return "No Access";
    }
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
