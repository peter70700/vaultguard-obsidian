/**
 * File Permission Header — injected into each markdown view to show
 * who has access, the current user's permission level, and (for admins)
 * a quick-access permission management panel.
 *
 * Resolves user IDs to real names/initials via the team directory.
 * Avatar chips are clickable — showing a user info popover.
 */

import { App, MarkdownView, Notice, TFile, setIcon } from "obsidian";
import {
  PathAccessPrincipal,
  PathAccessSummary,
  VaultGuardApiClient,
  PermissionRule,
  UserListEntry,
  VaultMemberRecord,
} from "../api/client";
import { PermissionLevel } from "../types";
import { EffectiveAccessPrincipal, FilePermissionPanel } from "./file-permission-panel";
import { setButtonLoading, setControlBusy } from "./loading-button";
import {
  buildAccessUserMap,
  getAccessUserDisplayName,
  getAccessUserNameInitials,
  formatAccessUserRole,
  formatAccessUserStatus,
  resolveAccessUserId,
  sortAccessUsers,
} from "./access-user-utils";

/** Identifies the injected header element so we can find/remove it. */
const HEADER_CLS = "vaultguard-file-header";

interface HeaderContext {
  app: App;
  apiClient: VaultGuardApiClient;
  currentUserId: string;
  currentUserEmail?: string;
  currentUserRole: string;
  isAdmin: boolean;
  /**
   * Optional callback fired after a rule mutation made from the header
   * (manage panel, popover dropdown). Lets the plugin invalidate global
   * caches (permission cache, file-explorer decorations, read-only guard)
   * so badges and dots in the sidebar refresh in lockstep with the
   * header itself.
   */
  onRulesChanged?: (path?: string) => void | Promise<void>;
  /**
   * Authoritative current-user permission resolver. Used when raw rule
   * listing is unavailable, so the "Your access" badge follows the same
   * backend check that enforces editor read/write protection.
   */
  getPermissionLevel?: (path: string) => Promise<PermissionLevel>;
  /**
   * Org-level "allow per-file restrictions on admins" toggle (mirrors the
   * backend setting of the same name). When true the header lets you
   * change vault admins' / org owner's per-file level, because the server
   * actually honors the resulting deny rule. When false (default) the
   * dropdown stays hidden for those principals — see
   * `isTargetVaultAdminOrOwner`. Plugin updates this via setContext()
   * after every org-settings refresh.
   */
  allowAdminPerFileRestrictions?: boolean;
  /** When provided and returns false, the banner is suppressed (settings toggle). */
  isEnabled?: () => boolean;
}

interface RuleCacheEntry {
  rules?: PermissionRule[];
  rulesAvailable?: boolean;
  access?: PathAccessSummary | null;
  currentUserLevel?: AccessLevel;
  fetchedAt: number;
  inFlight?: Promise<HeaderData>;
}

interface HeaderData {
  rules: PermissionRule[];
  rulesAvailable: boolean;
  access: PathAccessSummary | null;
  currentUserLevel: AccessLevel;
}

type AccessLevel = "unknown" | "none" | "read" | "write" | "admin";
type AccessPrincipal = {
  id: string;
  email?: string;
  label: string;
  level: AccessLevel;
  type: "user" | "role";
  /** Vault membership role for the principal, when known. Drives the
   * "can't edit per-file level for vault admins" UI guard. Vault roles are
   * viewer/editor/admin — "owner" is a Cognito org-level role only, and
   * org owners are added to vaults as `admin`, so checking `admin` covers
   * both. */
  vaultRole?: VaultMemberRecord["role"];
};

type AccessPrincipalState = AccessPrincipal & {
  specificity: number;
  denied: boolean;
};

interface AccessListOptions {
  includeVaultMemberDefaults?: boolean;
  currentUserLevel?: AccessLevel;
  accessPrincipals?: AccessPrincipal[];
}

export class FilePermissionHeader {
  private ctx: HeaderContext;
  private activeHeader: HTMLElement | null = null;
  private activePanel: FilePermissionPanel | null = null;
  private activePopover: HTMLElement | null = null;
  private activePath: string | null = null;
  private ruleCache: Map<string, RuleCacheEntry> = new Map();
  private readonly CACHE_TTL_MS = 60_000;

  /** Resolved user directory for displaying real names instead of UUIDs. */
  private users: UserListEntry[] = [];
  private userMap: Map<string, UserListEntry> = new Map();
  private usersLoaded = false;
  private usersLoadPromise: Promise<void> | null = null;

  /** Direct vault members, used to show people who inherit access from membership. */
  private vaultMembers: VaultMemberRecord[] = [];
  private vaultMembersLoaded = false;
  private vaultMembersLoadPromise: Promise<void> | null = null;

  constructor(ctx: HeaderContext) {
    this.ctx = ctx;
  }

  /**
   * Called on active-leaf-change / file-open.
   * Injects (or updates) the permission header for the currently visible file.
   */
  async update(options: { force?: boolean } = {}): Promise<void> {
    // Settings gate: when the "Show permission banner in notes" toggle is off,
    // tear the banner down and make the file-open / active-leaf-change
    // listeners no-ops while disabled.
    if (this.ctx.isEnabled && !this.ctx.isEnabled()) {
      this.remove();
      return;
    }

    const view = this.ctx.app.workspace.getActiveViewOfType(MarkdownView);
    if (!view || !view.file) {
      this.remove();
      return;
    }

    const file = view.file;
    const viewContent = view.containerEl.querySelector(".view-content");
    if (!viewContent) return;

    const sameTarget =
      this.activeHeader?.isConnected &&
      this.activeHeader.parentElement === viewContent &&
      this.activePath === file.path;

    let headerEl = this.activeHeader;

    if (!sameTarget || !headerEl) {
      this.remove();
      this.removeFromContainer(viewContent);

      headerEl = createDiv({ cls: HEADER_CLS });
      viewContent.insertBefore(headerEl, viewContent.firstChild);
      this.activeHeader = headerEl;
      this.activePath = file.path;
    }

    // Kick off user loading (non-blocking) if not done yet
    if (!this.usersLoaded && !this.usersLoadPromise) {
      this.usersLoadPromise = this.loadUsers();
    }
    if (!this.vaultMembersLoaded && !this.vaultMembersLoadPromise) {
      this.vaultMembersLoadPromise = this.loadVaultMembers();
    }

    const cached = this.ruleCache.get(file.path);
    const needsAuthoritativeLevelRefresh = Boolean(cached?.rules && this.ctx.getPermissionLevel);
    if (cached?.rules && !needsAuthoritativeLevelRefresh) {
      this.renderHeader(headerEl, file, cached.rules, this.optionsFromData(cached));
      this.updateActivePanel(cached.rules, this.optionsFromData(cached));
    } else {
      this.renderSkeleton(headerEl, file);
    }

    const shouldRefresh =
      options.force === true ||
      !cached?.rules ||
      this.isCacheStale(cached) ||
      Boolean(cached?.rules && this.ctx.getPermissionLevel);
    if (!shouldRefresh) {
      return;
    }

    // Show a subtle refresh indicator only when we have stale cached data
    // already on screen — otherwise the skeleton already conveys loading.
    const showRefreshing = Boolean(cached?.rules);
    if (showRefreshing) this.setRefreshing(headerEl, true);

    try {
      const data = await this.fetchHeaderDataForPath(file.path, options.force === true);
      // Check the element is still mounted (user may have switched files)
      if (!headerEl.isConnected || this.activeHeader !== headerEl || this.activePath !== file.path) return;
      this.renderHeader(headerEl, file, data.rules, this.optionsFromData(data));
      this.updateActivePanel(data.rules, this.optionsFromData(data));
    } catch {
      if (!headerEl.isConnected || this.activeHeader !== headerEl || this.activePath !== file.path) return;
      const currentUserLevel = await this.fetchCurrentUserLevel(file.path);
      if (!headerEl.isConnected || this.activeHeader !== headerEl || this.activePath !== file.path) return;
      this.renderHeader(headerEl, file, [], {
        includeVaultMemberDefaults: false,
        currentUserLevel,
      });
      this.updateActivePanel([], {
        includeVaultMemberDefaults: false,
        currentUserLevel,
      });
    } finally {
      if (showRefreshing && headerEl.isConnected) {
        this.setRefreshing(headerEl, false);
      }
    }
  }

  /**
   * Toggles a small spinner inside the header to signal that a background
   * refresh is in flight while stale cached data is still visible.
   */
  private setRefreshing(headerEl: HTMLElement, refreshing: boolean): void {
    const existing = headerEl.querySelector(".vaultguard-fh-refresh-indicator");
    if (refreshing) {
      if (existing) return;
      const indicator = headerEl.createSpan({
        cls: "vaultguard-fh-refresh-indicator vaultguard-sb-spinner",
        attr: { "aria-label": "Refreshing permissions" },
      });
      setIcon(indicator, "loader");
    } else if (existing) {
      existing.remove();
    }
  }

  /** Removes the header from the active view. */
  remove(): void {
    if (this.activeHeader?.isConnected) {
      this.activeHeader.remove();
    }
    this.activeHeader = null;
    this.activePath = null;
    this.closePanel();
    this.closePopover();
  }

  /** Clears the rule cache (e.g. after a permission change). */
  invalidateCache(path?: string): void {
    if (path) {
      this.ruleCache.delete(path);
      return;
    }

    this.invalidateDirectoryCache();
    this.ruleCache.clear();
  }

  /**
   * Updates identity context (current user id / role / admin flag) without
   * tearing down the header. Used after login completes and after a vault
   * binding change, when the user's effective role for the current vault
   * may have changed (e.g. org member promoted to vault admin).
   *
   * Also clears any cached rules and any open panel so the next render picks
   * up the new context cleanly.
   */
  setContext(updates: {
    currentUserId?: string;
    currentUserEmail?: string;
    currentUserRole?: string;
    isAdmin?: boolean;
    allowAdminPerFileRestrictions?: boolean;
  }): void {
    if (updates.currentUserId !== undefined) {
      this.ctx.currentUserId = updates.currentUserId;
    }
    if (updates.currentUserEmail !== undefined) {
      this.ctx.currentUserEmail = updates.currentUserEmail;
    }
    if (updates.currentUserRole !== undefined) {
      this.ctx.currentUserRole = updates.currentUserRole;
    }
    if (updates.isAdmin !== undefined) {
      this.ctx.isAdmin = updates.isAdmin;
    }
    if (updates.allowAdminPerFileRestrictions !== undefined) {
      this.ctx.allowAdminPerFileRestrictions = updates.allowAdminPerFileRestrictions;
    }
    this.ruleCache.clear();
    this.vaultMembers = [];
    this.vaultMembersLoaded = false;
    this.vaultMembersLoadPromise = null;
    this.closePanel();
    this.closePopover();
  }

  destroy(): void {
    this.remove();
    this.ruleCache.clear();
  }

  // ────────────────────────────────────────────────────────────────────

  private removeFromContainer(viewContent: Element): void {
    const existing = viewContent.querySelector(`.${HEADER_CLS}`);
    if (existing) existing.remove();
    this.closePanel();
    this.closePopover();
  }

  private closePanel(): void {
    if (this.activePanel) {
      this.activePanel.destroy();
      this.activePanel = null;
    }
  }

  private closePopover(): void {
    if (this.activePopover) {
      this.activePopover.remove();
      this.activePopover = null;
    }
  }

  private invalidateDirectoryCache(): void {
    this.users = [];
    this.userMap = new Map();
    this.usersLoaded = false;
    this.usersLoadPromise = null;
    this.vaultMembers = [];
    this.vaultMembersLoaded = false;
    this.vaultMembersLoadPromise = null;
  }

  // ─── User Directory ───────────────────────────────────────────────

  private async loadUsers(): Promise<void> {
    try {
      const users = await this.ctx.apiClient.listUsers();
      this.users = sortAccessUsers(users);
      this.userMap = buildAccessUserMap(this.users);
      this.usersLoaded = true;

      // Re-render header with resolved names if still mounted
      if (this.activeHeader?.isConnected && this.activePath) {
        const cached = this.ruleCache.get(this.activePath);
        if (cached?.rules) {
          const view = this.ctx.app.workspace.getActiveViewOfType(MarkdownView);
          if (view?.file?.path === this.activePath) {
            this.renderHeader(this.activeHeader, view.file, cached.rules, this.optionsFromData(cached));
          }
        }
      }
    } catch {
      // Silently fail — header degrades to UUID initials
    } finally {
      this.usersLoadPromise = null;
    }
  }

  private async loadVaultMembers(): Promise<void> {
    const vaultId = this.ctx.apiClient.getVaultId();
    if (!vaultId) {
      this.vaultMembers = [];
      this.vaultMembersLoaded = true;
      this.vaultMembersLoadPromise = null;
      return;
    }

    try {
      this.vaultMembers = await this.ctx.apiClient.listVaultMembers(vaultId);
      this.vaultMembersLoaded = true;

      // Vault members carry server-resolved displayName/email since the
      // /users admin endpoint is locked down for viewers. Fold them into
      // the user directory so non-admins also see real names instead of
      // raw UUIDs in the header chips and popover.
      this.mergeVaultMembersIntoDirectory();

      // Re-render header with inherited vault-member access if still mounted.
      if (this.activeHeader?.isConnected && this.activePath) {
        const cached = this.ruleCache.get(this.activePath);
        if (cached?.rules) {
          const view = this.ctx.app.workspace.getActiveViewOfType(MarkdownView);
          if (view?.file?.path === this.activePath) {
            this.renderHeader(this.activeHeader, view.file, cached.rules, this.optionsFromData(cached));
          }
        }
      }
    } catch {
      // Silently fail — explicit rules still render. Leave loaded=false so a
      // future forced refresh can try again.
      this.vaultMembers = [];
      this.vaultMembersLoaded = false;
    } finally {
      this.vaultMembersLoadPromise = null;
    }
  }

  /**
   * Folds enriched vault members into the local user directory so name
   * resolution works for non-admin users (who can't call the admin-only
   * /users endpoint). Admin-fetched UserListEntry rows always win — they
   * carry richer fields (status, mfa, lastActive). Vault-member-derived
   * rows fill in the gaps for everyone else.
   */
  private mergeVaultMembersIntoDirectory(): void {
    if (this.vaultMembers.length === 0) return;

    const knownIds = new Set(this.users.map((user) => user.id));
    const additions: UserListEntry[] = [];

    for (const member of this.vaultMembers) {
      if (knownIds.has(member.userId)) continue;
      // Only synthesize an entry if the server actually resolved a name —
      // otherwise we'd just shadow the UUID fallback with another UUID.
      if (!member.displayName && !member.email) continue;

      additions.push({
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
      knownIds.add(member.userId);
    }

    if (additions.length === 0) return;

    this.users = sortAccessUsers([...this.users, ...additions]);
    this.userMap = buildAccessUserMap(this.users);
  }

  private mapVaultRoleToUserRole(role: VaultMemberRecord["role"]): UserListEntry["role"] {
    switch (role) {
      case "admin": return "admin";
      case "editor": return "editor";
      case "viewer":
      default: return "viewer";
    }
  }

  private async loadVaultMembersIfNeeded(): Promise<void> {
    if (this.vaultMembersLoaded) return;
    if (this.vaultMembersLoadPromise) {
      await this.vaultMembersLoadPromise;
      return;
    }
    this.vaultMembersLoadPromise = this.loadVaultMembers();
    await this.vaultMembersLoadPromise;
  }

  private resolveUserLabel(userId: string): string {
    if (userId === "*") return "Everyone";
    const user = this.userMap.get(userId);
    return user ? getAccessUserDisplayName(user) : userId;
  }

  private resolveUserInitials(userId: string): string {
    if (userId === "*") return "*";
    const user = this.userMap.get(userId);
    if (user) {
      return getAccessUserNameInitials(user);
    }
    // Fallback: derive from the raw ID
    return this.initials(userId);
  }

  // ─── Data ──────────────────────────────────────────────────────────

  private async fetchRulesForPath(path: string, force = false): Promise<PermissionRule[]> {
    const data = await this.fetchHeaderDataForPath(path, force);
    return data.rules;
  }

  private async fetchHeaderDataForPath(path: string, force = false): Promise<HeaderData> {
    const cached = this.ruleCache.get(path);
    if (
      !force &&
      cached?.rules &&
      cached.access !== undefined &&
      cached.currentUserLevel !== undefined &&
      !this.isCacheStale(cached)
    ) {
      const currentUserLevel = await this.fetchCurrentUserLevel(path);
      const refreshedLevel = currentUserLevel === "unknown"
        ? cached.currentUserLevel
        : currentUserLevel;
      const displayedLevel = this.combineCurrentUserLevel(cached.access, refreshedLevel);
      if (displayedLevel !== cached.currentUserLevel) {
        this.ruleCache.set(path, {
          ...cached,
          currentUserLevel: displayedLevel,
        });
      }
      return {
        rules: cached.rules,
        rulesAvailable: cached.rulesAvailable === true,
        access: cached.access ?? null,
        currentUserLevel: displayedLevel,
      };
    }

    if (cached?.inFlight) {
      return cached.inFlight;
    }

    const accessRequest = this.fetchPathAccessForHeader(path);
    const currentUserLevelRequest = this.fetchCurrentUserLevel(path);

    const request = Promise.all([
      accessRequest,
      currentUserLevelRequest,
      this.loadVaultMembersIfNeeded(),
    ])
      .then(async ([access, currentUserLevel]) => {
        const displayedCurrentUserLevel = this.combineCurrentUserLevel(access, currentUserLevel);
        const rulesResult = await this.fetchEditableRulesForPath(path, displayedCurrentUserLevel);
        const matchingRules = rulesResult.rules.filter((rule) =>
          this.ruleMatchesPath(rule.pathPattern, path)
        );
        if (access) {
          this.mergePathAccessIntoDirectory(access.principals);
        }
        // Post-write read consistency: re-apply any pending set-level
        // patches that the server's read view (GSI) might not have
        // surfaced yet. Without this, a forced refresh fired right after a
        // write can stomp the chip back to its pre-write level.
        const reconciledAccess = access ? this.applyPendingPatchesToAccess(access) : access;
        this.ruleCache.set(path, {
          rules: matchingRules,
          rulesAvailable: rulesResult.rulesAvailable,
          access: reconciledAccess,
          currentUserLevel: displayedCurrentUserLevel,
          fetchedAt: Date.now(),
        });
        return {
          rules: matchingRules,
          rulesAvailable: rulesResult.rulesAvailable,
          access: reconciledAccess,
          currentUserLevel: displayedCurrentUserLevel,
        };
      })
      .catch((error) => {
        const fallback = this.ruleCache.get(path) ?? cached;
        if (fallback?.rules) {
          return {
            rules: fallback.rules,
            rulesAvailable: fallback.rulesAvailable === true,
            access: fallback.access ?? null,
            currentUserLevel: fallback.currentUserLevel ?? "unknown",
          };
        }
        throw error;
      })
      .finally(() => {
        const current = this.ruleCache.get(path);
        if (current?.inFlight === request) {
          if (current.rules) {
            this.ruleCache.set(path, {
              rules: current.rules,
              rulesAvailable: current.rulesAvailable,
              access: current.access,
              currentUserLevel: current.currentUserLevel,
              fetchedAt: current.fetchedAt,
            });
          } else if (cached?.rules) {
            this.ruleCache.set(path, {
              rules: cached.rules,
              rulesAvailable: cached.rulesAvailable,
              access: cached.access,
              currentUserLevel: cached.currentUserLevel,
              fetchedAt: cached.fetchedAt,
            });
          } else {
            this.ruleCache.delete(path);
          }
        }
      });

    this.ruleCache.set(path, {
      rules: cached?.rules,
      rulesAvailable: cached?.rulesAvailable,
      access: cached?.access,
      currentUserLevel: cached?.currentUserLevel,
      fetchedAt: cached?.fetchedAt ?? 0,
      inFlight: request,
    });

    return request;
  }

  private async fetchEditableRulesForPath(
    path: string,
    currentUserLevel: AccessLevel
  ): Promise<{ rules: PermissionRule[]; rulesAvailable: boolean }> {
    if (!this.ctx.isAdmin && currentUserLevel !== "admin") {
      return { rules: [], rulesAvailable: false };
    }

    try {
      const rules = this.ctx.isAdmin
        ? await this.ctx.apiClient.getPermissions()
        : await this.ctx.apiClient.getPermissions(path);
      return { rules, rulesAvailable: true };
    } catch {
      return { rules: [], rulesAvailable: false };
    }
  }

  private mergePathAccessIntoDirectory(principals: PathAccessPrincipal[]): void {
    if (principals.length === 0) return;

    const knownIds = new Set(this.users.map((user) => user.id));
    const additions: UserListEntry[] = [];
    for (const principal of principals) {
      if (knownIds.has(principal.userId)) continue;
      if (!principal.displayName && !principal.email) continue;
      additions.push({
        id: principal.userId,
        email: principal.email ?? "",
        displayName: principal.displayName ?? "",
        name: principal.displayName ?? "",
        role: this.mapVaultRoleToUserRole((principal.role ?? "viewer") as VaultMemberRecord["role"]),
        status: "active",
        lastActive: "",
        createdAt: "",
        mfaEnabled: false,
        deviceCount: 0,
        type: "user",
      });
      knownIds.add(principal.userId);
    }

    if (additions.length === 0) return;
    this.users = sortAccessUsers([...this.users, ...additions]);
    this.userMap = buildAccessUserMap(this.users);
  }

  private optionsFromAccess(access: PathAccessSummary | null | undefined): AccessListOptions {
    if (!access) return {};
    return {
      currentUserLevel: access.currentUserLevel,
      accessPrincipals: this.pathAccessToPrincipals(access.principals),
    };
  }

  private optionsFromData(data: {
    access?: PathAccessSummary | null;
    currentUserLevel?: AccessLevel;
    rulesAvailable?: boolean;
  }): AccessListOptions {
    // The backend access summary is the only place that already has the
    // complete server-computed effective-access table for every vault member
    // (including explicit "No access" rows). Use it whenever available; raw
    // rules remain a fallback for older/failed access-summary endpoints.
    const options = this.optionsFromAccess(data.access);
    if (data.currentUserLevel !== undefined && data.currentUserLevel !== "unknown") {
      options.currentUserLevel = data.currentUserLevel;
      options.accessPrincipals = this.withCurrentUserPrincipalLevel(
        options.accessPrincipals,
        data.currentUserLevel
      );
    }
    return options;
  }

  private combineCurrentUserLevel(
    access: PathAccessSummary | null | undefined,
    checkedLevel: AccessLevel
  ): AccessLevel {
    if (checkedLevel === "none") return "none";

    const accessLevel = access?.currentUserLevel;
    if (!accessLevel) return checkedLevel;
    if (checkedLevel === "unknown") return accessLevel;

    return this.levelRank(accessLevel) > this.levelRank(checkedLevel)
      ? accessLevel
      : checkedLevel;
  }

  private withCurrentUserPrincipalLevel(
    principals: AccessPrincipal[] | undefined,
    level: AccessLevel
  ): AccessPrincipal[] | undefined {
    if (!principals || level === "unknown") return principals;

    const currentUserId = this.resolveCanonicalUserId(this.ctx.currentUserId);
    const currentUserEmail = this.ctx.currentUserEmail?.trim().toLowerCase() ?? "";
    let foundCurrentUser = false;

    const updated = principals.map((principal) => {
      if (principal.type !== "user") return principal;
      const principalId = this.resolveCanonicalUserId(principal.id);
      const principalEmail = principal.email?.trim().toLowerCase() ?? "";
      const isCurrentUser =
        principal.id === this.ctx.currentUserId ||
        principalId === currentUserId ||
        (currentUserEmail.length > 0 && principalEmail === currentUserEmail);
      if (!isCurrentUser) {
        return principal;
      }
      foundCurrentUser = true;
      return { ...principal, id: currentUserId || principalId, level };
    });

    if (!foundCurrentUser && level !== "none") {
      updated.push({
        id: currentUserId,
        label: this.resolveUserLabel(currentUserId),
        level,
        type: "user",
      });
    }

    return updated
      .sort((a, b) => {
        const levelDiff = this.levelRank(b.level) - this.levelRank(a.level);
        if (levelDiff !== 0) return levelDiff;
        return a.label.localeCompare(b.label);
      });
  }

  private async fetchPathAccessForHeader(path: string): Promise<PathAccessSummary | null> {
    try {
      if (typeof this.ctx.apiClient.getBatchPathAccess === "function") {
        const summaries = await this.ctx.apiClient.getBatchPathAccess([path]);
        const target = this.normalizeAccessPath(path);
        const summary = summaries.find((entry) =>
          this.normalizeAccessPath(entry.path) === target
        );
        if (summary) return summary;
      }
    } catch {
      // Fall through to the single-path endpoint.
    }

    try {
      return await this.ctx.apiClient.getPathAccess(path);
    } catch {
      return null;
    }
  }

  private normalizeAccessPath(path: string): string {
    const trimmed = path.trim().replace(/\/+/g, "/");
    return trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  }

  private pathAccessToPrincipals(principals: PathAccessPrincipal[]): AccessPrincipal[] {
    return principals
      .map((principal) => {
        const label =
          principal.displayName ||
          principal.email ||
          this.resolveUserLabel(principal.userId);
        const rawRole = principal.role?.toLowerCase();
        const vaultRole: AccessPrincipal["vaultRole"] =
          rawRole === "admin" || rawRole === "editor" || rawRole === "viewer"
            ? rawRole
            : undefined;
        return {
          id: principal.userId,
          email: principal.email,
          label,
          level: principal.level,
          type: "user" as const,
          ...(vaultRole ? { vaultRole } : {}),
        };
      })
      .sort((a, b) => {
        const levelDiff = this.levelRank(b.level) - this.levelRank(a.level);
        if (levelDiff !== 0) return levelDiff;
        return a.label.localeCompare(b.label);
      });
  }

  private isCacheStale(entry: RuleCacheEntry): boolean {
    return Date.now() - entry.fetchedAt >= this.CACHE_TTL_MS;
  }

  // ─── Rendering ─────────────────────────────────────────────────────

  private renderSkeleton(container: HTMLElement, _file: TFile): void {
    container.empty();
    container.dataset.vaultguardCurrentUserLevel = "loading";
    const inner = container.createDiv({ cls: "vaultguard-fh-inner" });

    // Current user permission badge while rules are loading.
    const levelSection = inner.createDiv({ cls: "vaultguard-fh-level" });
    const badge = levelSection.createSpan({ cls: "vaultguard-fh-badge vaultguard-fh-badge-loading" });
    const shimmer = badge.createSpan({ cls: "vaultguard-fh-shimmer" });
    shimmer.setText("Loading...");

    // Skeleton avatar placeholders
    const accessSection = inner.createDiv({ cls: "vaultguard-fh-access" });
    const avatarGroup = accessSection.createDiv({ cls: "vaultguard-fh-avatar-group" });
    for (let i = 0; i < 3; i++) {
      avatarGroup.createDiv({ cls: "vaultguard-fh-chip-skeleton" });
    }
  }

  private renderHeader(
    container: HTMLElement,
    file: TFile,
    rules: PermissionRule[],
    options: AccessListOptions = {}
  ): void {
    container.empty();
    const inner = container.createDiv({ cls: "vaultguard-fh-inner" });

    // ── Section 1: Current user's effective level ────────────────────
    const myLevel = this.resolveMyLevel(file.path, rules, options);
    container.dataset.vaultguardCurrentUserLevel = myLevel;
    const levelSection = inner.createDiv({ cls: "vaultguard-fh-level" });

    const lockIcon = levelSection.createSpan({ cls: "vaultguard-fh-lock-icon" });
    setIcon(lockIcon, this.iconForLevel(myLevel));

    const badge = levelSection.createSpan({
      cls: `vaultguard-fh-badge vaultguard-fh-badge-${myLevel}`,
    });
    badge.setText(this.formatLevel(myLevel));

    // ── Separator ────────────────────────────────────────────────────
    inner.createDiv({ cls: "vaultguard-fh-separator" });

    // ── Section 2: Access list (avatars) ─────────────────────────────
    const accessSection = inner.createDiv({ cls: "vaultguard-fh-access" });
    this.renderAccessList(accessSection, file, rules, options);

    // ── Section 3: Actions ───────────────────────────────────────────
    const actionsSection = inner.createDiv({ cls: "vaultguard-fh-actions" });

    if (this.canManageFile(file, rules, options)) {
      const manageBtn = actionsSection.createEl("button", {
        cls: "vaultguard-fh-btn vaultguard-fh-btn-manage",
      });
      const manageIcon = manageBtn.createSpan({ cls: "vaultguard-fh-btn-icon" });
      setIcon(manageIcon, "settings");
      manageBtn.createSpan({ text: "Manage" });
      manageBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        this.closePopover();
        this.togglePanel(container, file, rules, options);
      });
    } else {
      const viewBtn = actionsSection.createEl("button", {
        cls: "vaultguard-fh-btn vaultguard-fh-btn-view",
      });
      const viewIcon = viewBtn.createSpan({ cls: "vaultguard-fh-btn-icon" });
      setIcon(viewIcon, "info");
      viewBtn.createSpan({ text: "Details" });
      viewBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        this.closePopover();
        this.togglePanel(container, file, rules, options);
      });
    }
  }

  /**
   * Resolves the principal chips to render, always reconciling the current
   * user's own chip with their authoritative level.
   *
   * `options.accessPrincipals` (from the backend access summary) is already
   * reconciled in `optionsFromData`, but the `buildVisibleAccessPrincipals`
   * fallback — used when the access summary is unavailable — seeds chips from
   * vault-member ROLE defaults (viewer→read), which ignores file-specific
   * grants. Without re-applying the override here, a viewer with a file-specific
   * WRITE/ADMIN grant sees their own chip stuck on the inherited "read" while
   * the header badge correctly shows the elevated level.
   */
  private visibleAccessPrincipals(
    rules: PermissionRule[],
    options: AccessListOptions = {}
  ): AccessPrincipal[] {
    const base = options.accessPrincipals ?? this.buildVisibleAccessPrincipals(rules, options);
    if (options.currentUserLevel && options.currentUserLevel !== "unknown") {
      return this.withCurrentUserPrincipalLevel(base, options.currentUserLevel) ?? base;
    }
    return base;
  }

  private renderAccessList(
    container: HTMLElement,
    file: TFile,
    rules: PermissionRule[],
    options: AccessListOptions = {}
  ): void {
    const sorted = this.visibleAccessPrincipals(rules, options);

    const MAX_SHOWN = 4;
    const shown = sorted.slice(0, MAX_SHOWN);
    const overflow = sorted.length - MAX_SHOWN;

    if (sorted.length === 0) {
      container.createSpan({
        cls: "vaultguard-fh-no-access",
        text: options.includeVaultMemberDefaults === false
          ? "Access details unavailable"
          : "No visible access",
      });
      return;
    }

    // Shared count indicator
    const countEl = container.createDiv({ cls: "vaultguard-fh-shared-count" });
    const countIcon = countEl.createSpan({ cls: "vaultguard-fh-shared-count-icon" });
    setIcon(countIcon, "users");
    countEl.createSpan({ text: `${sorted.length}` });

    const avatarGroup = container.createDiv({ cls: "vaultguard-fh-avatar-group" });

    for (const principal of shown) {
      const chip = avatarGroup.createDiv({
        cls: `vaultguard-fh-chip vaultguard-fh-chip-${principal.level}`,
        attr: { "aria-label": `${principal.label} (${this.formatLevel(principal.level)})` },
      });

      if (principal.type === "user" && principal.id !== "*") {
        chip.classList.add("vaultguard-fh-chip-clickable");
      }

      // Avatar
      if (principal.type === "role") {
        const icon = chip.createSpan({ cls: "vaultguard-fh-chip-icon" });
        setIcon(icon, "users");
      } else if (principal.id === "*") {
        const icon = chip.createSpan({ cls: "vaultguard-fh-chip-icon" });
        setIcon(icon, "globe");
      } else {
        const initialsEl = chip.createSpan({
          cls: `vaultguard-fh-chip-initials vaultguard-fh-initials-${principal.level}`,
          text: this.resolveUserInitials(principal.id),
        });
        // Tooltip on hover showing full name
        initialsEl.setAttribute("aria-label", principal.label);
      }

      chip.createSpan({ cls: "vaultguard-fh-chip-label", text: principal.label });

      const levelDot = chip.createSpan({
        cls: `vaultguard-fh-chip-level vaultguard-fh-dot-${principal.level}`,
      });
      levelDot.setText(this.formatLevel(principal.level));

      // Click handler for user chips — open popover
      if (principal.type === "user" && principal.id !== "*") {
        chip.addEventListener("click", (e) => {
          e.stopPropagation();
          this.showUserPopover(chip, principal.id, principal.level, file, rules, options);
        });
      }
    }

    if (overflow > 0) {
      const overflowChip = avatarGroup.createSpan({
        cls: "vaultguard-fh-overflow",
        text: `+${overflow}`,
      });
      overflowChip.setAttribute("aria-label", `${overflow} more people have access`);
      overflowChip.addEventListener("click", (e) => {
        e.stopPropagation();
        this.closePopover();
        const cached = this.ruleCache.get(file.path);
        this.togglePanel(this.activeHeader!, file, rules, this.optionsFromData(cached ?? {}));
      });
    }
  }

  // ─── User Popover ──────────────────────────────────────────────────

  private showUserPopover(
    anchorEl: HTMLElement,
    userId: string,
    level: AccessLevel,
    file: TFile,
    rules: PermissionRule[],
    options: AccessListOptions = {}
  ): void {
    // Toggle off if clicking the same chip
    if (this.activePopover) {
      this.closePopover();
      return;
    }

    const user = this.userMap.get(userId);
    const popover = document.body.createDiv({ cls: "vaultguard-fh-popover" });
    this.activePopover = popover;

    // Close on outside click
    const backdrop = document.body.createDiv({ cls: "vaultguard-fh-popover-backdrop" });
    backdrop.addEventListener("click", () => this.closePopover());

    // ── Popover content ──
    const popoverInner = popover.createDiv({ cls: "vaultguard-fh-popover-inner" });

    // User header row
    const headerRow = popoverInner.createDiv({ cls: "vaultguard-fh-popover-header" });

    const avatarEl = headerRow.createDiv({
      cls: `vaultguard-fh-popover-avatar vaultguard-fh-initials-${level}`,
    });
    avatarEl.setText(this.resolveUserInitials(userId));

    const nameCol = headerRow.createDiv({ cls: "vaultguard-fh-popover-name-col" });
    nameCol.createDiv({
      cls: "vaultguard-fh-popover-name",
      text: this.resolveUserLabel(userId),
    });

    if (user) {
      nameCol.createDiv({
        cls: "vaultguard-fh-popover-email",
        text: user.email,
      });
    } else {
      nameCol.createDiv({
        cls: "vaultguard-fh-popover-email",
        text: userId,
      });
    }

    // Info rows
    const infoSection = popoverInner.createDiv({ cls: "vaultguard-fh-popover-info" });

    // Permission level — editable dropdown for admins, static badge otherwise
    const levelRow = infoSection.createDiv({ cls: "vaultguard-fh-popover-row" });
    levelRow.createSpan({ cls: "vaultguard-fh-popover-label", text: "Access" });

    const exactUserRule = this.findExactUserRuleForFile(rules, userId, file);

    // Admins/owners cannot restrict themselves — the server bypasses deny rules for
    // org-admin/vault-admin/owner (see infrastructure/lambda/shared/utils.ts:528-530),
    // so offering the editable dropdown for the admin's own row would silently write
    // an orphan deny rule with no effect. Fold self-rows into the static-badge branch.
    if (this.canEditUserRow(userId, file, rules, options)) {
      const levelSelect = levelRow.createEl("select", {
        cls: "vaultguard-fh-popover-level-select",
      });
      const options = [
        { value: "admin", label: "Admin" },
        { value: "write", label: "Write" },
        { value: "read", label: "Read" },
        { value: "none", label: "No Access" },
      ];
      for (const opt of options) {
        const optEl = levelSelect.createEl("option", {
          text: opt.label,
          attr: { value: opt.value },
        });
        if (opt.value === level) optEl.selected = true;
      }
      const levelSpinner = levelRow.createSpan({
        cls: "vaultguard-sb-spinner vaultguard-fh-popover-spinner",
      });
      levelSpinner.hide();
      setIcon(levelSpinner, "loader");
      levelSelect.addEventListener("change", async () => {
        const newLevel = levelSelect.value as AccessLevel;
        setControlBusy(levelSelect, true);
        levelSpinner.show();
        try {
          // Server set-level returns the new effective level for the
          // principal. We don't drop it: patching the cache with that level
          // lets the chip flip immediately, while the force-refresh below
          // reconciles the rest of the principals on this path against the
          // server's authoritative view. The patch costs nothing if it agrees
          // with the refresh (the common case); if a race causes it to
          // disagree, the refresh corrects within one round-trip.
          const result = await this.upsertUserFileAccess(file, userId, newLevel, exactUserRule, level);
          this.closePopover();
          if (result) {
            this.patchCachedPrincipalLevel(file.path, result.canonicalUserId, result.effectiveLevel);
          }
          await this.update({ force: true });
          await this.ctx.onRulesChanged?.(file.path);
        } catch (error) {
          // Surface the failure — previously this catch was empty, which made
          // any server-side rejection look like a non-event to the user. Now
          // they see exactly what the server said (auth failure, validation
          // error, network blip), and the dropdown returns to its prior
          // state instead of getting stuck "loading".
          const message = (error as Error)?.message ?? "unknown error";
          new Notice(`Failed to update permission: ${message}`);
          console.error(`[VaultGuard] upsertUserFileAccess(${userId} → ${newLevel}) on ${file.path}`, error);
          setControlBusy(levelSelect, false);
          levelSpinner.hide();
        }
      });
    } else {
      const levelBadge = levelRow.createSpan({
        cls: `vaultguard-fh-badge vaultguard-fh-badge-${level}`,
      });
      levelBadge.setText(this.formatLevel(level));
    }

    // Role
    if (user) {
      const roleRow = infoSection.createDiv({ cls: "vaultguard-fh-popover-row" });
      roleRow.createSpan({ cls: "vaultguard-fh-popover-label", text: "Role" });
      roleRow.createSpan({
        cls: "vaultguard-fh-popover-value",
        text: formatAccessUserRole(user.role),
      });

      // Status
      const statusRow = infoSection.createDiv({ cls: "vaultguard-fh-popover-row" });
      statusRow.createSpan({ cls: "vaultguard-fh-popover-label", text: "Status" });
      const statusBadge = statusRow.createSpan({
        cls: `vaultguard-fh-popover-status vaultguard-fh-popover-status-${user.status}`,
      });
      statusBadge.setText(formatAccessUserStatus(user.status));
    }

    // Actions for admins: edit name + manage permissions
    if (this.ctx.isAdmin) {
      const actionSection = popoverInner.createDiv({ cls: "vaultguard-fh-popover-actions" });

      // ── Edit Name ──
      const editNameBtn = actionSection.createEl("button", {
        cls: "vaultguard-fh-popover-btn",
        attr: { type: "button" },
      });
      const editIcon = editNameBtn.createSpan({ cls: "vaultguard-fh-btn-icon" });
      setIcon(editIcon, "pencil");
      editNameBtn.createSpan({ text: "Edit Name" });

      // Edit name form — hidden by default, shown on button click
      const editForm = actionSection.createDiv({ cls: "vaultguard-fh-popover-edit-form" });
      editForm.hide();

      const editInput = editForm.createEl("input", {
        cls: "vaultguard-fh-popover-edit-input",
        attr: {
          type: "text",
          placeholder: "First last",
          value: user ? getAccessUserDisplayName(user) : "",
        },
      }) as HTMLInputElement;

      const editSaveBtn = editForm.createEl("button", {
        cls: "vaultguard-fh-popover-edit-save",
        text: "Save",
        attr: { type: "button" },
      });

      editNameBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        const isVisible = editForm.isShown();
        if (isVisible) {
          editForm.hide();
        } else {
          editForm.show();
        }
        if (!isVisible) {
          editInput.focus();
          editInput.select();
        }
      });

      const submitNameEdit = async (): Promise<void> => {
        const newName = editInput.value.trim();
        if (!newName) return;
        setButtonLoading(editSaveBtn, true, { label: "Saving" });
        try {
          await this.ctx.apiClient.updateUserProfile(userId, { displayName: newName });
          // Refresh the user map so the header reflects the change
          this.usersLoaded = false;
          this.usersLoadPromise = this.loadUsers();
          this.closePopover();
          this.invalidateCache();
          await this.update({ force: true });
        } catch {
          setButtonLoading(editSaveBtn, false);
          editSaveBtn.textContent = "Failed";
          setTimeout(() => {
            editSaveBtn.textContent = "Save";
            editSaveBtn.disabled = false;
          }, 1500);
        }
      };

      editSaveBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        void submitNameEdit();
      });

      editInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
          e.preventDefault();
          void submitNameEdit();
        }
      });

      // ── Manage Permissions ──
      const manageBtn = actionSection.createEl("button", {
        cls: "vaultguard-fh-popover-btn",
        attr: { type: "button" },
      });
      const manageIcon = manageBtn.createSpan({ cls: "vaultguard-fh-btn-icon" });
      setIcon(manageIcon, "settings");
      manageBtn.createSpan({ text: "Manage Permissions" });
      manageBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        this.closePopover();
        if (!this.activePanel) {
          const cached = this.ruleCache.get(file.path);
          this.togglePanel(this.activeHeader!, file, rules, this.optionsFromData(cached ?? {}));
        }
      });
    }

    // Position the popover below the anchor chip
    this.positionPopover(popover, anchorEl);

    // Store backdrop ref for cleanup
    popover.dataset.backdropId = "active";
    // Cleanup function
    const originalClose = this.closePopover.bind(this);
    this.closePopover = () => {
      backdrop.remove();
      this.closePopover = originalClose;
      originalClose();
    };
  }

  private positionPopover(popover: HTMLElement, anchor: HTMLElement): void {
    const isMobileSheet =
      document.body.classList.contains("is-phone") ||
      window.matchMedia("(max-width: 600px) and (hover: none) and (pointer: coarse)").matches;

    if (isMobileSheet) {
      popover.setCssStyles({
        top: "auto",
        left: "8px",
        right: "8px",
        bottom: "8px",
        width: "auto",
      });
      return;
    }

    const rect = anchor.getBoundingClientRect();
    const gap = 6;
    const popoverWidth = 260;

    let top = rect.bottom + gap;
    let left = rect.left + rect.width / 2 - popoverWidth / 2;

    // Keep within viewport
    left = Math.max(8, Math.min(left, window.innerWidth - popoverWidth - 8));
    if (top + 200 > window.innerHeight) {
      top = rect.top - gap - 200;
    }

    popover.setCssStyles({
      top: `${top}px`,
      left: `${left}px`,
      right: "auto",
      bottom: "auto",
      width: `${popoverWidth}px`,
    });
  }

  // ─── Panel Toggle ──────────────────────────────────────────────────

  private togglePanel(
    headerEl: HTMLElement,
    file: TFile,
    rules: PermissionRule[],
    options: AccessListOptions = {}
  ): void {
    if (this.activePanel) {
      this.closePanel();
      return;
    }

    const panelAccess = this.panelEffectiveAccess(rules, options);
    this.activePanel = new FilePermissionPanel({
      app: this.ctx.app,
      apiClient: this.ctx.apiClient,
      file,
      rules,
      effectivePrincipals: panelAccess.principals,
      effectiveAccessAvailable: panelAccess.available,
      canManageAccess: this.canManageFile(file, rules, options),
      isAdmin: this.ctx.isAdmin,
      currentUserId: this.ctx.currentUserId,
      currentUserEmail: this.ctx.currentUserEmail,
      allowAdminPerFileRestrictions: this.ctx.allowAdminPerFileRestrictions === true,
      anchorEl: headerEl,
      initialUsers: this.users,
      onRulesChanged: async () => {
        this.invalidateCache(file.path);
        await this.update({ force: true });
        await this.ctx.onRulesChanged?.(file.path);
      },
      onClose: () => {
        this.activePanel = null;
      },
    });
  }

  private updateActivePanel(rules: PermissionRule[], options: AccessListOptions): void {
    if (!this.activePanel) return;
    const panelAccess = this.panelEffectiveAccess(rules, options);
    this.activePanel.setData(rules, panelAccess.principals, panelAccess.available);
  }

  private panelEffectiveAccess(
    rules: PermissionRule[],
    options: AccessListOptions = {}
  ): { principals: EffectiveAccessPrincipal[]; available: boolean } {
    const accessSummaryAvailable = options.accessPrincipals !== undefined;
    return {
      principals: accessSummaryAvailable
        ? this.visibleAccessPrincipals(rules, options).map((principal) => ({
          id: principal.id,
          email: principal.email,
          label: principal.label,
          level: principal.level,
          type: principal.type,
          ...(principal.vaultRole ? { vaultRole: principal.vaultRole } : {}),
        }))
        : [],
      available: accessSummaryAvailable,
    };
  }

  // ─── Helpers ───────────────────────────────────────────────────────

  private async upsertUserFileAccess(
    file: TFile,
    userId: string,
    level: AccessLevel,
    _exactRule: PermissionRule | null,
    _knownCurrentLevel?: AccessLevel
  ): Promise<{ effectiveLevel: AccessLevel; canonicalUserId: string } | null> {
    await this.ensureUsersLoaded();
    const canonicalUserId = this.resolveCanonicalUserId(userId);

    // Delegate the decision (delete/cap/grant) to the server's set-level
    // endpoint. The server knows the principal's INHERITED level (membership
    // + broader rules) — that is the only correct basis for picking a single
    // rule shape that lands the user at exactly `level`. See the
    // permission transition matrix test for the failure modes that motivated
    // moving this logic out of the client.
    if (level === "unknown") return null;
    const response = await this.ctx.apiClient.setPermissionLevel({
      userId: canonicalUserId,
      role: null,
      pathPattern: this.fileRulePath(file),
      level,
    });
    // The server returns the principal's NEW effective level — that's the
    // authoritative value we'd otherwise have to round-trip a getPathAccess
    // call to learn. The popover handler uses it to patch the local cache
    // optimistically so the chip flips immediately while the background
    // refresh reconciles the rest of the principals on this path.
    return {
      effectiveLevel: (response?.level as AccessLevel) ?? level,
      canonicalUserId,
    };
  }

  /**
   * Mutates the cached path-access summary so the named principal shows the
   * given level on the next render, without needing a network round-trip.
   * Used as the optimistic-update side of "patch cache, then reconcile
   * against server in the background". The full refresh that fires next
   * still replaces the entire cache entry, so this patch is correct-by-
   * construction even when the cached snapshot is otherwise stale — any
   * lie the patch tells gets corrected within one network round-trip.
   *
   * No-op when the cached summary doesn't enumerate the principal (e.g.
   * legacy admin view without an access summary); the background refresh
   * still surfaces the correct level on completion.
   */
  patchCachedPrincipalLevel(
    path: string,
    userId: string,
    level: AccessLevel
  ): void {
    // `unknown` is a UI-only sentinel for "level not yet resolved" — the
    // server set-level endpoint never returns it. Bail rather than write a
    // value the PathAccessPrincipal contract doesn't permit.
    if (level === "unknown") return;

    // Record the pending patch so subsequent refreshes (which may briefly
    // read a stale GSI view) keep showing the new level until the server's
    // read view catches up. Self-clears once the server agrees.
    if (!this.pendingLevelPatches) this.pendingLevelPatches = new Map();
    const canonical = this.resolveCanonicalUserId(userId);
    let pending = this.pendingLevelPatches.get(path);
    if (!pending) {
      pending = new Map();
      this.pendingLevelPatches.set(path, pending);
    }
    pending.set(canonical, level as Exclude<AccessLevel, "unknown">);

    const cached = this.ruleCache.get(path);
    if (!cached?.access) return;
    const reconciled = this.applyPendingPatchesToAccess(cached.access, path);
    this.ruleCache.set(path, { ...cached, access: reconciled });
  }

  /** Pending set-level writes per path, awaiting server-read agreement. */
  private pendingLevelPatches: Map<string, Map<string, Exclude<AccessLevel, "unknown">>> = new Map();

  /**
   * Returns a `PathAccessSummary` with any pending patches applied for the
   * given path, AND drops patches the freshly-fetched summary now agrees
   * with. Called both at write-time (to reflect the optimistic value) and
   * at refresh-time (to keep optimistic values in place until the server
   * catches up).
   */
  private applyPendingPatchesToAccess(
    access: PathAccessSummary,
    path: string | null = null
  ): PathAccessSummary {
    if (!this.pendingLevelPatches) this.pendingLevelPatches = new Map();
    const targetPath = path ?? access.path;
    const pending = this.pendingLevelPatches.get(targetPath);
    if (!pending || pending.size === 0) return access;

    // Drop confirmed patches first.
    for (const [userId, level] of [...pending]) {
      const principal = access.principals.find(
        (p) => this.resolveCanonicalUserId(p.userId) === userId
      );
      if (principal && principal.level === level) {
        pending.delete(userId);
      }
    }
    if (pending.size === 0) {
      this.pendingLevelPatches.delete(targetPath);
      return access;
    }

    const principals = access.principals.map((p) => {
      const patched = pending.get(this.resolveCanonicalUserId(p.userId));
      return patched ? { ...p, level: patched } : p;
    });

    for (const [userId, level] of pending) {
      if (level === "none") continue;
      const exists = principals.some(
        (p) => this.resolveCanonicalUserId(p.userId) === userId
      );
      if (!exists) principals.push({ userId, level });
    }

    return { ...access, principals };
  }

  /**
   * Builds the (actions, effect) tuple that brings the user from
   * `previousLevel` to `level` on the target path.
   *
   * Permission rules carry ONE effect (allow OR deny), so a single rule cannot
   * simultaneously raise and lower access. We use the user's inherited /
   * effective baseline (previousLevel) to decide the shape:
   *
   *  - target === "none"        → deny all actions
   *  - target  <  previousLevel → deny the actions ABOVE target (cap from above
   *                                while leaving lower actions to inheritance)
   *  - target  >= previousLevel → allow up to target (grant the actions
   *                                explicitly; matches existing behavior for
   *                                upgrades and same-level no-ops)
   *
   * Why deny-cap on downgrade: when the user inherits a higher level (e.g. an
   * editor vault member, or a broader `/**` allow), a plain `allow [read,list]`
   * rule does NOT remove the inherited write — it only re-grants read. The
   * deny rule covers write/delete/admin so the higher actions are stripped
   * while the lower actions fall through to inheritance. This is the only
   * single-rule shape that yields the correct effective level.
   */
  private buildLevelMutation(
    level: AccessLevel,
    previousLevel: AccessLevel = "none"
  ): Pick<PermissionRule, "actions" | "effect"> {
    if (level === "none") {
      return {
        actions: ["read", "write", "delete", "admin", "list"],
        effect: "deny",
      };
    }

    const targetRank = this.levelRank(level);
    const previousRank = this.levelRank(previousLevel);

    if (targetRank < previousRank) {
      // Order is: read/list, write/delete, admin — kept stable across
      // downgrades so the resulting rules are bit-identical regardless of
      // which transition produced them (helps idempotency and test pinning).
      const denyActions: PermissionRule["actions"] = [];
      if (targetRank < 1) denyActions.push("read", "list");
      if (targetRank < 2) denyActions.push("write", "delete");
      if (targetRank < 3) denyActions.push("admin");
      return { actions: denyActions, effect: "deny" };
    }

    return {
      actions: this.levelToActions(level),
      effect: "allow",
    };
  }

  private resolvePrincipalLevelForFile(
    userId: string,
    file: TFile,
    rules: PermissionRule[]
  ): AccessLevel {
    const cached = this.ruleCache.get(file.path);
    const cachedOptions = cached ? this.optionsFromData(cached) : {};
    // Use the backend-aware resolver (visibleAccessPrincipals) — when the path
    // access summary is in cache, it carries the server-computed effective
    // level for every principal and overrides the local rule-derived view.
    // The local view (buildVisibleAccessPrincipals) misclassifies cases like a
    // stale `allow [read,list]` rule sitting on top of editor-membership write
    // inheritance: locally the rule reads as level=read, but the user
    // effectively still has write because the rule does not strip the
    // inherited write/delete grants. Trusting the backend here makes the
    // upsert flow downgrade through a deny cap instead of writing a no-op
    // allow-read rule on top of the broken state.
    return this.visibleAccessPrincipals(rules, cachedOptions)
      .find((principal) =>
        principal.type === "user" &&
        this.resolveCanonicalUserId(principal.id) === this.resolveCanonicalUserId(userId)
      )?.level ?? "none";
  }

  private findExactUserRuleForFile(
    rules: PermissionRule[],
    userId: string,
    file: TFile
  ): PermissionRule | null {
    const targetPath = this.normalizeRulePath(this.fileRulePath(file));
    const canonicalUserId = this.resolveCanonicalUserId(userId);
    return rules.find((rule) =>
      !rule.role &&
      this.resolveCanonicalUserId(rule.userId) === canonicalUserId &&
      this.normalizeRulePath(rule.pathPattern) === targetPath
    ) ?? null;
  }

  private fileRulePath(file: TFile): string {
    return file.path.startsWith("/") ? file.path : `/${file.path}`;
  }

  private normalizeRulePath(path: string): string {
    return path.replace(/^\/+/, "").replace(/\/+$/, "");
  }

  private async ensureUsersLoaded(): Promise<void> {
    if (this.usersLoaded) return;
    if (this.usersLoadPromise) {
      await this.usersLoadPromise;
      return;
    }
    this.usersLoadPromise = this.loadUsers();
    await this.usersLoadPromise;
  }

  private resolveCanonicalUserId(userId: string): string {
    const trimmed = userId.trim();
    const fromDirectory = resolveAccessUserId(this.users, trimmed);
    if (fromDirectory !== trimmed) {
      return fromDirectory;
    }

    const normalized = trimmed.toLowerCase();
    const member = this.vaultMembers.find((entry) =>
      entry.userId.toLowerCase() === normalized ||
      entry.email?.trim().toLowerCase() === normalized
    );
    return member?.userId ?? trimmed;
  }

  private async fetchCurrentUserLevel(path: string): Promise<AccessLevel> {
    if (!this.ctx.getPermissionLevel) {
      return "unknown";
    }

    try {
      return this.permissionLevelToAccessLevel(await this.ctx.getPermissionLevel(path));
    } catch {
      return "unknown";
    }
  }

  private permissionLevelToAccessLevel(level: PermissionLevel): AccessLevel {
    if (level >= PermissionLevel.ADMIN) return "admin";
    if (level >= PermissionLevel.WRITE) return "write";
    if (level >= PermissionLevel.READ) return "read";
    return "none";
  }

  private buildVisibleAccessPrincipals(
    rules: PermissionRule[],
    options: AccessListOptions = {}
  ): AccessPrincipal[] {
    const principals = new Map<string, AccessPrincipalState>();
    const includeVaultMemberDefaults = options.includeVaultMemberDefaults !== false;

    const applyUserAccess = (
      userId: string,
      level: AccessLevel,
      specificity: number,
      denied: boolean
    ): void => {
      const canonicalUserId = this.resolveCanonicalUserId(userId);
      const key = `user:${canonicalUserId}`;
      const current = principals.get(key);
      if (!this.shouldReplacePrincipalAccess(current, level, specificity, denied)) {
        return;
      }

      principals.set(key, {
        id: canonicalUserId,
        label: this.resolveUserLabel(canonicalUserId),
        level,
        type: "user",
        specificity,
        denied,
      });
    };

    const applyRoleAccess = (
      role: string,
      level: AccessLevel,
      specificity: number,
      denied: boolean
    ): void => {
      const key = `role:${role}`;
      const current = principals.get(key);
      if (!this.shouldReplacePrincipalAccess(current, level, specificity, denied)) {
        return;
      }

      principals.set(key, {
        id: role,
        label: role,
        level,
        type: "role",
        specificity,
        denied,
      });
    };

    // Seed with vault membership. A user can see the file unless a matching
    // path rule denies them later. This is the piece the old header missed:
    // inherited access from VaultMembers is real access, not merely metadata.
    if (includeVaultMemberDefaults) {
      for (const member of this.vaultMembers) {
        const level = this.levelForVaultMemberRole(member.role);
        if (level !== "none") {
          applyUserAccess(this.resolveCanonicalUserId(member.userId), level, Number.NEGATIVE_INFINITY, false);
        }
      }
    }

    for (const rule of rules) {
      const level = this.ruleAccessLevel(rule);
      const specificity = this.patternSpecificity(rule.pathPattern);
      const denied = rule.effect === "deny";

      if (rule.role) {
        const matchingMembers = this.vaultMembers.filter(
          (member) => member.role === rule.role
        );
        if (matchingMembers.length > 0) {
          for (const member of matchingMembers) {
            applyUserAccess(member.userId, level, specificity, denied);
          }
        } else {
          applyRoleAccess(rule.role, level, specificity, denied);
        }
        continue;
      }

      if (rule.userId === "*" && this.vaultMembers.length > 0) {
        for (const member of this.vaultMembers) {
          applyUserAccess(member.userId, level, specificity, denied);
        }
        continue;
      }

      applyUserAccess(this.resolveCanonicalUserId(rule.userId), level, specificity, denied);
    }

    return [...principals.values()]
      .sort((a, b) => {
        const levelDiff = this.levelRank(b.level) - this.levelRank(a.level);
        if (levelDiff !== 0) return levelDiff;
        return a.label.localeCompare(b.label);
      });
  }

  private shouldReplacePrincipalAccess(
    current: AccessPrincipalState | undefined,
    nextLevel: AccessLevel,
    specificity: number,
    denied: boolean
  ): boolean {
    if (!current) return true;
    if (specificity > current.specificity) return true;
    if (specificity < current.specificity) return false;
    if (denied && !current.denied) return true;
    if (!denied && current.denied) return false;
    return this.levelRank(nextLevel) > this.levelRank(current.level);
  }

  private levelForVaultMemberRole(role: VaultMemberRecord["role"]): AccessLevel {
    switch (role) {
      case "admin":
        return "admin";
      case "editor":
        return "write";
      case "viewer":
      default:
        return "read";
    }
  }

  /**
   * Whether the current user may edit `userId`'s level on `file` from the popover.
   * Org/vault admins (ctx.isAdmin) keep full power; a file-level admin
   * (resolveMyLevel === "admin") may also edit OTHER principals' rows. The
   * self-row is never editable — a user cannot drop their own access, mirroring
   * the backend self-protection guardrail (authorizePermissionMutation).
   */
  private canManageFile(
    file: TFile,
    rules: PermissionRule[],
    options: AccessListOptions = {}
  ): boolean {
    return this.resolveMyLevel(file.path, rules, options) === "admin";
  }

  private canEditUserRow(
    userId: string,
    file: TFile,
    rules: PermissionRule[],
    options: AccessListOptions = {}
  ): boolean {
    if (userId === this.ctx.currentUserId) return false;
    // Vault admins/owners bypass per-file deny rules in evaluatePermission
    // (utils.ts: rolesIncludeOrgAdmin → allowed=true unconditionally), so
    // by default any per-file mutation against them is a no-op and the
    // server returns 400. We hide the dropdown then — but when the org
    // has opted into `allowAdminPerFileRestrictions`, the bypass is
    // disabled for target-side evaluation and the deny rules DO take
    // effect, so the dropdown becomes editable. The plugin syncs the
    // setting via setContext after every org-settings refresh.
    if (
      !this.ctx.allowAdminPerFileRestrictions &&
      this.isTargetVaultAdminOrOwner(userId, options)
    ) {
      return false;
    }
    if (this.ctx.isAdmin) return true;
    return this.canManageFile(file, rules, options);
  }

  /**
   * Looks up the named principal's vault role from the cached access
   * summary. Returns true only when the role is explicitly "admin" or
   * "owner" — falling back to false (editable) when the role is unknown,
   * so the server-side 400 remains the authoritative guardrail rather than
   * a stale UI hint locking edits unnecessarily.
   */
  private isTargetVaultAdminOrOwner(
    userId: string,
    options: AccessListOptions = {}
  ): boolean {
    const canonical = this.resolveCanonicalUserId(userId);
    const principal = options.accessPrincipals?.find(
      (p) => p.type === "user" && this.resolveCanonicalUserId(p.id) === canonical
    );
    if (principal?.vaultRole === "admin") return true;
    // Fallback to vaultMembers when the access summary doesn't enumerate
    // a vaultRole (e.g. legacy backends that pre-date the role field).
    const member = this.vaultMembers.find(
      (m) => this.resolveCanonicalUserId(m.userId) === canonical
    );
    return member?.role === "admin";
  }

  private resolveMyLevel(
    _path: string,
    rules: PermissionRule[],
    options: AccessListOptions = {}
  ): AccessLevel {
    if (options.currentUserLevel) {
      return options.currentUserLevel;
    }

    if (this.ctx.currentUserRole === "admin" || this.ctx.currentUserRole === "owner") {
      return "admin";
    }

    let bestLevel: AccessLevel = this.levelForCurrentVaultMember();
    let bestSpecificity = Number.NEGATIVE_INFINITY;

    for (const rule of rules) {
      const applies =
        rule.userId === this.ctx.currentUserId ||
        rule.userId === "*" ||
        (rule.role && this.ctx.currentUserRole === rule.role);

      if (!applies) continue;

      const specificity = this.patternSpecificity(rule.pathPattern);
      if (specificity > bestSpecificity) {
        bestSpecificity = specificity;
        bestLevel = this.ruleAccessLevel(rule);
      } else if (specificity === bestSpecificity) {
        const level = this.ruleAccessLevel(rule);
        if (this.levelRank(level) > this.levelRank(bestLevel)) {
          bestLevel = level;
        }
      }
    }

    // If no rule matched, fall back to role-based defaults
    if (bestSpecificity === Number.NEGATIVE_INFINITY) {
      return bestLevel;
    }

    return bestLevel;
  }

  private levelForCurrentVaultMember(): AccessLevel {
    const member = this.vaultMembers.find(
      (entry) => entry.userId === this.ctx.currentUserId
    );
    if (member) return this.levelForVaultMemberRole(member.role);
    if (this.ctx.currentUserRole === "editor") return "write";
    return "read";
  }

  private ruleLevelString(rule: PermissionRule): AccessLevel {
    if (rule.actions.includes("admin")) return "admin";
    if (rule.actions.includes("write") || rule.actions.includes("delete")) return "write";
    if (rule.actions.includes("read")) return "read";
    return "none";
  }

  private ruleAccessLevel(rule: PermissionRule): AccessLevel {
    if (rule.effect !== "deny") return this.ruleLevelString(rule);
    if (rule.actions.includes("read") || rule.actions.includes("list")) return "none";
    if (rule.actions.includes("write") || rule.actions.includes("delete")) return "read";
    if (rule.actions.includes("admin")) return "write";
    return "none";
  }

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

  private levelToActions(level: string): Array<"read" | "write" | "delete" | "admin" | "list"> {
    switch (level) {
      case "admin": return ["read", "write", "delete", "admin", "list"];
      case "write": return ["read", "write", "delete", "list"];
      case "read": return ["read", "list"];
      default: return ["read", "list"];
    }
  }

  private formatLevel(level: string): string {
    switch (level) {
      case "unknown": return "Unknown";
      case "admin": return "Admin";
      case "write": return "Write";
      case "read": return "Read";
      default: return "No Access";
    }
  }

  private iconForLevel(level: AccessLevel): string {
    switch (level) {
      case "admin": return "shield";
      case "write": return "edit";
      case "read": return "eye";
      case "unknown": return "help-circle";
      default: return "lock";
    }
  }

  private initials(name: string): string {
    if (name === "*") return "*";
    const parts = name.split(/[\s@._-]+/).filter(Boolean);
    return parts
      .slice(0, 2)
      .map((p) => p[0]?.toUpperCase() ?? "")
      .join("");
  }
}
