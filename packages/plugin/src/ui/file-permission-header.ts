/**
 * File Permission Header — injected into each markdown view to show
 * who has access, the current user's permission level, and (for admins)
 * a quick-access permission management panel.
 *
 * Resolves user IDs to real names/initials via the team directory.
 * Avatar chips are clickable — showing a user info popover.
 */

import { App, MarkdownView, TFile, setIcon } from "obsidian";
import { VaultGuardApiClient, PermissionRule, UserListEntry, VaultMemberRecord } from "../api/client";
import { FilePermissionPanel } from "./file-permission-panel";
import { setButtonLoading, setControlBusy } from "./loading-button";
import {
  buildAccessUserMap,
  getAccessUserDisplayName,
  getAccessUserNameInitials,
  getAccessUserMeta,
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
}

interface RuleCacheEntry {
  rules?: PermissionRule[];
  fetchedAt: number;
  inFlight?: Promise<PermissionRule[]>;
}

type AccessLevel = "none" | "read" | "write" | "admin";
type AccessPrincipal = {
  id: string;
  label: string;
  level: AccessLevel;
  type: "user" | "role";
};

type AccessPrincipalState = AccessPrincipal & {
  specificity: number;
  denied: boolean;
};

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
    if (cached?.rules) {
      this.renderHeader(headerEl, file, cached.rules);
      this.activePanel?.setRules(cached.rules);
    } else {
      this.renderSkeleton(headerEl, file);
    }

    const shouldRefresh =
      options.force === true || !cached?.rules || this.isCacheStale(cached);
    if (!shouldRefresh) {
      return;
    }

    // Show a subtle refresh indicator only when we have stale cached data
    // already on screen — otherwise the skeleton already conveys loading.
    const showRefreshing = Boolean(cached?.rules);
    if (showRefreshing) this.setRefreshing(headerEl, true);

    try {
      const rules = await this.fetchRulesForPath(file.path, options.force === true);
      // Check the element is still mounted (user may have switched files)
      if (!headerEl.isConnected || this.activeHeader !== headerEl || this.activePath !== file.path) return;
      this.renderHeader(headerEl, file, rules);
      this.activePanel?.setRules(rules);
    } catch {
      if (!headerEl.isConnected || this.activeHeader !== headerEl || this.activePath !== file.path) return;
      this.renderHeader(headerEl, file, []);
      this.activePanel?.setRules([]);
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
    currentUserRole?: string;
    isAdmin?: boolean;
  }): void {
    if (updates.currentUserId !== undefined) {
      this.ctx.currentUserId = updates.currentUserId;
    }
    if (updates.currentUserRole !== undefined) {
      this.ctx.currentUserRole = updates.currentUserRole;
    }
    if (updates.isAdmin !== undefined) {
      this.ctx.isAdmin = updates.isAdmin;
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
            this.renderHeader(this.activeHeader, view.file, cached.rules);
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
            this.renderHeader(this.activeHeader, view.file, cached.rules);
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
    const cached = this.ruleCache.get(path);
    if (!force && cached?.rules && !this.isCacheStale(cached)) {
      return cached.rules;
    }

    if (cached?.inFlight) {
      return cached.inFlight;
    }

    const request = Promise.all([
      this.ctx.apiClient.getPermissions(),
      this.loadVaultMembersIfNeeded(),
    ])
      .then(([rules]) => {
        const matchingRules = rules.filter((rule) =>
          this.ruleMatchesPath(rule.pathPattern, path)
        );
        this.ruleCache.set(path, { rules: matchingRules, fetchedAt: Date.now() });
        return matchingRules;
      })
      .catch((error) => {
        const fallback = this.ruleCache.get(path)?.rules ?? cached?.rules;
        if (fallback) {
          return fallback;
        }
        throw error;
      })
      .finally(() => {
        const current = this.ruleCache.get(path);
        if (current?.inFlight === request) {
          if (current.rules) {
            this.ruleCache.set(path, {
              rules: current.rules,
              fetchedAt: current.fetchedAt,
            });
          } else if (cached?.rules) {
            this.ruleCache.set(path, {
              rules: cached.rules,
              fetchedAt: cached.fetchedAt,
            });
          } else {
            this.ruleCache.delete(path);
          }
        }
      });

    this.ruleCache.set(path, {
      rules: cached?.rules,
      fetchedAt: cached?.fetchedAt ?? 0,
      inFlight: request,
    });

    return request;
  }

  private isCacheStale(entry: RuleCacheEntry): boolean {
    return Date.now() - entry.fetchedAt >= this.CACHE_TTL_MS;
  }

  // ─── Rendering ─────────────────────────────────────────────────────

  private renderSkeleton(container: HTMLElement, _file: TFile): void {
    container.empty();
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

  private renderHeader(container: HTMLElement, file: TFile, rules: PermissionRule[]): void {
    container.empty();
    const inner = container.createDiv({ cls: "vaultguard-fh-inner" });

    // ── Section 1: Current user's effective level ────────────────────
    const myLevel = this.resolveMyLevel(file.path, rules);
    const levelSection = inner.createDiv({ cls: "vaultguard-fh-level" });

    const lockIcon = levelSection.createSpan({ cls: "vaultguard-fh-lock-icon" });
    setIcon(lockIcon, myLevel === "admin" ? "shield" : myLevel === "write" ? "edit" : myLevel === "read" ? "eye" : "lock");

    const badge = levelSection.createSpan({
      cls: `vaultguard-fh-badge vaultguard-fh-badge-${myLevel}`,
    });
    badge.setText(this.formatLevel(myLevel));

    // ── Separator ────────────────────────────────────────────────────
    inner.createDiv({ cls: "vaultguard-fh-separator" });

    // ── Section 2: Access list (avatars) ─────────────────────────────
    const accessSection = inner.createDiv({ cls: "vaultguard-fh-access" });
    this.renderAccessList(accessSection, file, rules);

    // ── Section 3: Actions ───────────────────────────────────────────
    const actionsSection = inner.createDiv({ cls: "vaultguard-fh-actions" });

    if (this.ctx.isAdmin) {
      const manageBtn = actionsSection.createEl("button", {
        cls: "vaultguard-fh-btn vaultguard-fh-btn-manage",
      });
      const manageIcon = manageBtn.createSpan({ cls: "vaultguard-fh-btn-icon" });
      setIcon(manageIcon, "settings");
      manageBtn.createSpan({ text: "Manage" });
      manageBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        this.closePopover();
        this.togglePanel(container, file, rules);
      });
    } else {
      const viewBtn = actionsSection.createEl("button", {
        cls: "vaultguard-fh-btn vaultguard-fh-btn-view",
      });
      const viewIcon = viewBtn.createSpan({ cls: "vaultguard-fh-btn-icon" });
      setIcon(viewIcon, "eye");
      viewBtn.createSpan({ text: "View" });
      viewBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        this.closePopover();
        this.togglePanel(container, file, rules);
      });
    }
  }

  private renderAccessList(container: HTMLElement, file: TFile, rules: PermissionRule[]): void {
    const sorted = this.buildVisibleAccessPrincipals(rules);

    const MAX_SHOWN = 4;
    const shown = sorted.slice(0, MAX_SHOWN);
    const overflow = sorted.length - MAX_SHOWN;

    if (sorted.length === 0) {
      container.createSpan({ cls: "vaultguard-fh-no-access", text: "No visible access" });
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
          this.showUserPopover(chip, principal.id, principal.level, file, rules);
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
        this.togglePanel(this.activeHeader!, file, rules);
      });
    }
  }

  // ─── User Popover ──────────────────────────────────────────────────

  private showUserPopover(
    anchorEl: HTMLElement,
    userId: string,
    level: AccessLevel,
    file: TFile,
    rules: PermissionRule[]
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

    if (this.ctx.isAdmin) {
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
      levelSpinner.style.display = "none";
      setIcon(levelSpinner, "loader");
      levelSelect.addEventListener("change", async () => {
        const newLevel = levelSelect.value as AccessLevel;
        setControlBusy(levelSelect, true);
        levelSpinner.style.display = "";
        try {
          await this.upsertUserFileAccess(file, userId, newLevel, exactUserRule);
          this.closePopover();
          this.invalidateCache(file.path);
          await this.update({ force: true });
          await this.ctx.onRulesChanged?.(file.path);
        } catch {
          setControlBusy(levelSelect, false);
          levelSpinner.style.display = "none";
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
      editForm.style.display = "none";

      const editInput = editForm.createEl("input", {
        cls: "vaultguard-fh-popover-edit-input",
        attr: {
          type: "text",
          placeholder: "First Last",
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
        const isVisible = editForm.style.display !== "none";
        editForm.style.display = isVisible ? "none" : "flex";
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
          this.togglePanel(this.activeHeader!, file, rules);
        }
      });
    }

    // Position the popover below the anchor chip
    this.positionPopover(popover, anchorEl);

    // Store backdrop ref for cleanup
    popover.dataset.backdropId = "active";
    const existingBackdrop = this.activePopover.previousElementSibling;
    // Cleanup function
    const originalClose = this.closePopover.bind(this);
    this.closePopover = () => {
      backdrop.remove();
      this.closePopover = originalClose;
      originalClose();
    };
  }

  private positionPopover(popover: HTMLElement, anchor: HTMLElement): void {
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

    popover.style.top = `${top}px`;
    popover.style.left = `${left}px`;
    popover.style.width = `${popoverWidth}px`;
  }

  // ─── Panel Toggle ──────────────────────────────────────────────────

  private togglePanel(headerEl: HTMLElement, file: TFile, rules: PermissionRule[]): void {
    if (this.activePanel) {
      this.closePanel();
      return;
    }

    this.activePanel = new FilePermissionPanel({
      app: this.ctx.app,
      apiClient: this.ctx.apiClient,
      file,
      rules,
      isAdmin: this.ctx.isAdmin,
      currentUserId: this.ctx.currentUserId,
      anchorEl: headerEl,
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

  // ─── Helpers ───────────────────────────────────────────────────────

  private async upsertUserFileAccess(
    file: TFile,
    userId: string,
    level: AccessLevel,
    exactRule: PermissionRule | null
  ): Promise<void> {
    const mutation = this.buildLevelMutation(level);
    await this.ensureUsersLoaded();
    const canonicalUserId = this.resolveCanonicalUserId(userId);

    const cachedRules = this.ruleCache.get(file.path)?.rules ?? [];
    const currentExactRule = exactRule ?? this.findExactUserRuleForFile(cachedRules, canonicalUserId, file);

    if (currentExactRule) {
      await this.ctx.apiClient.updatePermission(currentExactRule.id, {
        pathPattern: currentExactRule.pathPattern,
        ...mutation,
      });
      return;
    }

    await this.ctx.apiClient.createPermission({
      pathPattern: this.fileRulePath(file),
      ...mutation,
      userId: canonicalUserId,
      role: null,
    });
  }

  private buildLevelMutation(level: AccessLevel): Pick<PermissionRule, "actions" | "effect"> {
    if (level === "none") {
      return {
        actions: ["read", "write", "delete", "admin", "list"],
        effect: "deny",
      };
    }

    return {
      actions: this.levelToActions(level),
      effect: "allow",
    };
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
    return resolveAccessUserId(this.users, userId);
  }

  private buildVisibleAccessPrincipals(rules: PermissionRule[]): AccessPrincipal[] {
    const principals = new Map<string, AccessPrincipalState>();

    const applyUserAccess = (
      userId: string,
      level: AccessLevel,
      specificity: number,
      denied: boolean
    ): void => {
      const key = `user:${userId}`;
      const current = principals.get(key);
      if (!this.shouldReplacePrincipalAccess(current, level, specificity, denied)) {
        return;
      }

      principals.set(key, {
        id: userId,
        label: this.resolveUserLabel(userId),
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
    for (const member of this.vaultMembers) {
      const level = this.levelForVaultMemberRole(member.role);
      if (level !== "none") {
        applyUserAccess(this.resolveCanonicalUserId(member.userId), level, Number.NEGATIVE_INFINITY, false);
      }
    }

    for (const rule of rules) {
      const level = rule.effect === "deny" ? "none" : this.ruleLevelString(rule);
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
      .filter((principal) => principal.level !== "none")
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

  private resolveMyLevel(_path: string, rules: PermissionRule[]): AccessLevel {
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
        bestLevel = rule.effect === "deny" ? "none" : this.ruleLevelString(rule);
      } else if (specificity === bestSpecificity) {
        const level = rule.effect === "deny" ? "none" : this.ruleLevelString(rule);
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
      case "admin": return "Admin";
      case "write": return "Write";
      case "read": return "Read";
      default: return "No Access";
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
