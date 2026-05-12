/**
 * File Explorer Decorations — injects permission badges, sharing indicators,
 * and mini avatar stacks onto the native Obsidian file explorer via DOM manipulation.
 *
 * Uses a debounced MutationObserver to detect when the file explorer re-renders
 * and re-applies decorations. Permission data is fetched once in bulk and cached
 * to avoid excessive API calls.
 */

import { App, setIcon } from "obsidian";
import { VaultGuardApiClient, PermissionRule, UserListEntry } from "../api/client";
import { buildAccessUserMap, getAccessUserDisplayName, getAccessUserNameInitials } from "./access-user-utils";

// ─── Constants ─────────────────────────────────────────────────────────────

const DECORATION_CLS = "vaultguard-fe-decoration";
const HIDDEN_CLS = "vaultguard-fe-hidden";
const CACHE_TTL_MS = 120_000; // 2 minutes
const DEBOUNCE_MS = 300; // debounce observer-triggered repaints
const ATTACH_RETRY_MS = 1_000; // file explorer can mount after plugin load

// ─── Types ─────────────────────────────────────────────────────────────────

interface DecorationCacheEntry {
  level: string;
  sharedWith: number;
  principals: Array<{ id: string; label: string; level: string; type: "user" | "role" }>;
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
  private allRules: PermissionRule[] | null = null;
  private allRulesFetchedAt = 0;
  private observer: MutationObserver | null = null;
  private observedContainer: HTMLElement | null = null;
  private enabled = false;
  private isDecorating = false; // guard against observer re-entry
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;
  private attachRetryTimer: ReturnType<typeof setTimeout> | null = null;
  private fetchPromise: Promise<void> | null = null;
  private userMap: Map<string, UserListEntry> = new Map();
  private usersLoaded = false;

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
    this.allRules = null;
    this.allRulesFetchedAt = 0;
    this.cache.clear();
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
    } else {
      this.allRules = null;
      this.allRulesFetchedAt = 0;
      this.cache.clear();
      // Clear the user directory too — a permission grant may target a user
      // who was just invited and isn't in the cached map. Without this,
      // their chip would render as their UUID until the next session.
      this.userMap = new Map();
      this.usersLoaded = false;
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
    this.allRules = null;
    this.allRulesFetchedAt = 0;
    this.cache.clear();
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
    this.allRules = null;
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

    // Ensure we have rules loaded (single bulk fetch, not per-file)
    await this.ensureRulesLoaded();

    // Guard: set flag so observer ignores our own DOM mutations
    this.isDecorating = true;
    try {
      const items = Array.from(
        container.querySelectorAll<HTMLElement>(".nav-file-title, .nav-folder-title")
      );

      // First pass: resolve every path's effective level so we can decide
      // folder visibility based on whether any descendant grants access.
      const resolved: Array<{ item: HTMLElement; path: string; entry: DecorationCacheEntry; isFile: boolean }> = [];
      const accessiblePaths = new Set<string>();
      for (const item of items) {
        const path = this.getItemPath(item);
        if (!path) continue;
        const entry = this.getOrBuildCacheEntry(path);
        const isFile = item.classList.contains("nav-file-title");
        resolved.push({ item, path, entry, isFile });
        if (entry.level !== "none") accessiblePaths.add(path);
      }

      const hasAccessibleDescendant = (folderPath: string): boolean => {
        const prefix = folderPath + "/";
        for (const p of accessiblePaths) {
          if (p.startsWith(prefix)) return true;
        }
        return false;
      };

      for (const { item, path, entry, isFile } of resolved) {
        // Files: hide when the user has no access. Folders: hide only when
        // the user has no access AND no descendant grants access — otherwise
        // we'd hide a folder containing accessible children.
        const shouldHide =
          entry.level === "none" && (isFile || !hasAccessibleDescendant(path));
        item.classList.toggle(HIDDEN_CLS, shouldHide);

        // Always re-apply. The previous `cache.has(path)` skip was a no-op
        // because the first pass above populated the cache for every item
        // before we got here, so already-decorated rows (especially the
        // folder row, which Obsidian reuses) never re-rendered after a
        // permission change. `applyDecoration` removes any existing
        // decoration node first, so this is idempotent and flicker-free.
        this.applyDecoration(item, entry);
      }
    } finally {
      this.isDecorating = false;
    }
  }

  private applyDecoration(item: HTMLElement, data: DecorationCacheEntry): void {
    // Remove existing decoration if present
    const existing = item.querySelector(`.${DECORATION_CLS}`);
    if (existing) existing.remove();

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
          avatar.setText(this.initials(principal.id));
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

  // ─── Data Fetching (bulk, not per-file) ───────────────────────────────

  private async ensureRulesLoaded(): Promise<void> {
    const isStale = Date.now() - this.allRulesFetchedAt >= CACHE_TTL_MS;
    if (this.allRules && !isStale) return;

    // Deduplicate concurrent fetches
    if (this.fetchPromise) {
      await this.fetchPromise;
      return;
    }

    this.fetchPromise = this.fetchAllRules();
    try {
      await this.fetchPromise;
    } finally {
      this.fetchPromise = null;
    }
  }

  private async fetchAllRules(): Promise<void> {
    try {
      const [rules] = await Promise.all([
        this.config.apiClient.getPermissions(),
        this.loadUsersIfNeeded(),
      ]);
      this.allRules = rules;
      this.allRulesFetchedAt = Date.now();
      this.cache.clear(); // rebuild from fresh rules
    } catch {
      // On error, keep stale data if available
      if (!this.allRules) {
        this.allRules = [];
        this.allRulesFetchedAt = Date.now();
      }
    }
  }

  private async loadUsersIfNeeded(): Promise<void> {
    if (this.usersLoaded) return;
    try {
      const users = await this.config.apiClient.listUsers();
      this.userMap = buildAccessUserMap(users);
      this.usersLoaded = true;
    } catch {
      // Silently fail — degrades to showing user IDs
    }
  }

  private resolveUserLabel(userId: string): string {
    if (userId === "*") return "Everyone";
    const user = this.userMap.get(userId);
    return user ? getAccessUserDisplayName(user) : userId;
  }

  private getOrBuildCacheEntry(path: string): DecorationCacheEntry {
    const cached = this.cache.get(path);
    if (cached) return cached;

    const rules = this.allRules ?? [];
    const matchingRules = rules.filter((r) => this.ruleMatchesPath(r.pathPattern, path));
    const entry = this.rulesToCacheEntry(matchingRules);
    this.cache.set(path, entry);
    return entry;
  }

  private rulesToCacheEntry(rules: PermissionRule[]): DecorationCacheEntry {
    const myLevel = this.resolveMyLevel(rules);

    // Per-principal state — the same conflict-resolution shape used by the
    // header. Without specificity + denied tracking, a deny rule for a user
    // who also has an allow rule was simply skipped, leaving the avatar in
    // the sidebar even after admin revoked their access.
    interface PrincipalState {
      id: string;
      label: string;
      level: string;
      type: "user" | "role";
      specificity: number;
      denied: boolean;
    }

    const principals = new Map<string, PrincipalState>();

    const shouldReplace = (
      current: PrincipalState | undefined,
      nextLevel: string,
      specificity: number,
      denied: boolean
    ): boolean => {
      if (!current) return true;
      if (specificity > current.specificity) return true;
      if (specificity < current.specificity) return false;
      if (denied && !current.denied) return true;
      if (!denied && current.denied) return false;
      return this.levelRank(nextLevel) > this.levelRank(current.level);
    };

    for (const rule of rules) {
      const level = rule.effect === "deny" ? "none" : this.ruleLevelString(rule);
      const specificity = this.patternSpecificity(rule.pathPattern);
      const denied = rule.effect === "deny";

      if (rule.role) {
        const key = `role:${rule.role}`;
        if (!shouldReplace(principals.get(key), level, specificity, denied)) continue;
        principals.set(key, {
          id: rule.role,
          label: rule.role,
          level,
          type: "role",
          specificity,
          denied,
        });
        continue;
      }

      if (rule.userId === this.config.currentUserId) continue;
      const key = `user:${rule.userId}`;
      if (!shouldReplace(principals.get(key), level, specificity, denied)) continue;
      principals.set(key, {
        id: rule.userId,
        label: this.resolveUserLabel(rule.userId),
        level,
        type: "user",
        specificity,
        denied,
      });
    }

    // Drop anyone whose effective access resolved to "none" (revoked /
    // explicitly denied). Strip the conflict-resolution metadata before
    // returning so the cache entry shape stays minimal.
    const sortedPrincipals = [...principals.values()]
      .filter((principal) => principal.level !== "none")
      .map(({ id, label, level, type }) => ({ id, label, level, type }))
      .sort((a, b) => this.levelRank(b.level) - this.levelRank(a.level));

    return {
      level: myLevel,
      sharedWith: sortedPrincipals.length,
      principals: sortedPrincipals,
    };
  }

  // ─── Rule Matching ────────────────────────────────────────────────────

  private ruleMatchesPath(pattern: string, path: string): boolean {
    const normalizedPattern = pattern.replace(/^\/+/, "").replace(/\/+$/, "");
    const normalizedPath = path.replace(/^\/+/, "").replace(/\/+$/, "");

    if (normalizedPath === normalizedPattern) return true;

    if (!normalizedPattern.includes("*") && normalizedPath.startsWith(normalizedPattern + "/")) {
      return true;
    }

    if (normalizedPattern === "*" || normalizedPattern === "**") return true;

    if (normalizedPattern.includes("*")) {
      return this.matchGlob(normalizedPath, normalizedPattern);
    }

    return false;
  }

  private matchGlob(path: string, pattern: string): boolean {
    let regexStr = "^";
    let i = 0;

    while (i < pattern.length) {
      const char = pattern[i];
      if (char === "*") {
        if (pattern[i + 1] === "*") {
          if (pattern[i + 2] === "/") {
            regexStr += "(?:.+/)?";
            i += 3;
          } else {
            regexStr += ".*";
            i += 2;
          }
        } else {
          regexStr += "[^/]*";
          i++;
        }
      } else if (".+^${}()|[]\\".includes(char)) {
        regexStr += "\\" + char;
        i++;
      } else {
        regexStr += char;
        i++;
      }
    }

    regexStr += "$";

    try {
      return new RegExp(regexStr).test(path);
    } catch {
      return false;
    }
  }

  // ─── Helpers ──────────────────────────────────────────────────────────

  private resolveMyLevel(rules: PermissionRule[]): string {
    const role = this.config.currentUserRole;
    if (role === "admin" || role === "owner") return "admin";

    let bestLevel = "none";
    let bestSpecificity = -1;

    for (const rule of rules) {
      const applies =
        rule.userId === this.config.currentUserId ||
        rule.userId === "*" ||
        (rule.role && role === rule.role);

      if (!applies) continue;

      const specificity = this.patternSpecificity(rule.pathPattern);
      if (specificity > bestSpecificity) {
        bestSpecificity = specificity;
        bestLevel = rule.effect === "deny" ? "none" : this.ruleLevelString(rule);
      } else if (specificity === bestSpecificity) {
        const level = rule.effect === "deny" ? "none" : this.ruleLevelString(rule);
        if (this.levelRank(level) > this.levelRank(bestLevel)) {
          bestLevel = level;
        }
      }
    }

    if (bestLevel === "none" && bestSpecificity === -1) {
      return this.defaultLevelForRole();
    }

    return bestLevel;
  }

  private defaultLevelForRole(): string {
    const role = this.config.currentUserRole;
    if (role === "admin" || role === "owner") return "admin";
    if (role === "editor") return "write";
    return "read";
  }

  private ruleLevelString(rule: PermissionRule): string {
    if (rule.actions.includes("admin")) return "admin";
    if (rule.actions.includes("write") || rule.actions.includes("delete")) return "write";
    if (rule.actions.includes("read")) return "read";
    return "none";
  }

  private patternSpecificity(pattern: string): number {
    let score = 0;
    score += (pattern.match(/\//g) || []).length * 10;
    if (!pattern.includes("*")) score += 100;
    if (pattern.includes("**")) score -= 50;
    score += pattern.length;
    return score;
  }

  private levelRank(level: string): number {
    switch (level) {
      case "admin": return 3;
      case "write": return 2;
      case "read": return 1;
      default: return 0;
    }
  }

  private formatLevel(level: string): string {
    switch (level) {
      case "admin": return "Admin";
      case "write": return "Write";
      case "read": return "Read";
      default: return "No Access";
    }
  }

  private initials(userId: string): string {
    if (userId === "*") return "*";
    const user = this.userMap.get(userId);
    if (user) return getAccessUserNameInitials(user);
    const parts = userId.split(/[\s@._-]+/).filter(Boolean);
    return parts
      .slice(0, 2)
      .map((p) => p[0]?.toUpperCase() ?? "")
      .join("");
  }
}
