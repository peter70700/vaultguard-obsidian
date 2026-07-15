/**
 * VaultGuard Sidebar View — a custom ItemView that shows a detailed
 * permission overview of vault files with user avatars, sharing status,
 * permission levels, and sync state.
 *
 * Registered as a workspace view and toggled via command or ribbon.
 */

import { ItemView, TFile, WorkspaceLeaf, setIcon } from "obsidian";
import {
  VaultGuardApiClient,
  PathAccessPrincipal,
  PathAccessSummary,
  PermissionAccessLevel,
  PermissionRule,
  UserListEntry,
  VaultMemberRole,
} from "../api/client";
import { PermissionLevel } from "../types";
import { buildAccessUserMap, getAccessUserDisplayName, getAccessUserNameInitials } from "./access-user-utils";
import { createI18n } from "../i18n";

// ─── Constants ─────────────────────────────────────────────────────────────

export const VAULTGUARD_VIEW_TYPE = "vaultguard-files-view";
const CACHE_TTL_MS = 60_000;
const SEARCH_DEBOUNCE_MS = 120;
const BATCH_PATH_LIMIT = 100; // matches backend /permissions/access/batch cap

// ─── Types ─────────────────────────────────────────────────────────────────

interface FileEntry {
  path: string;
  name: string;
  lowerPath: string;
  lowerName: string;
  level: PermissionAccessLevel;
  sharedWith: number;
  principals: Array<{
    id: string;
    label: string;
    level: PermissionAccessLevel;
    type: "user" | "role";
  }>;
  userIds: Set<string>;
  roleIds: Set<string>;
}

interface ViewCacheEntry {
  rules: PermissionRule[];
  fetchedAt: number;
}

type SortMode = "name-asc" | "name-desc" | "level-desc" | "shared-desc";

export interface VaultGuardSidebarViewConfig {
  apiClient: VaultGuardApiClient;
  currentUserId: string;
  currentUserRole: string;
  getPermissionLevel?: (path: string) => Promise<PermissionLevel>;
  onNavigateToFile?: (path: string) => void;
  onOpenMenu?: (evt?: MouseEvent) => void;
  onOpenSettings?: () => void;
  onOpenRecoveryCenter?: () => void;
  getPendingLargeFileSummary?: () => {
    count: number;
    retryable: number;
    blocked: number;
  };
  onRetryPendingLargeFiles?: () => void;
}

export interface VaultGuardSidebarAuthState {
  title: string;
  message: string;
  detail?: string;
  icon?: string;
  tone?: "neutral" | "warning" | "danger";
  actionLabel?: string;
}

export interface AtRestRecoverySurfaceState {
  needsRecovery: boolean;
  reason: string;
  canReset: boolean;
}

export interface VaultGuardSidebarViewOptions {
  getAuthState?: () => VaultGuardSidebarAuthState | null;
  /**
   * W1 pull path: the plugin's CURRENT at-rest recovery state. Mirrors
   * getAuthState — a freshly-instantiated leaf (a mid-session close/reopen)
   * seeds from this so it reflects the cipher's real state on first paint,
   * not only from a later push. The push-only default (false) is exactly why
   * a reopened leaf silently showed no banner while the cipher stayed locked
   * — which on mobile (no status bar) is the silent-failure class this closes.
   */
  getAtRestRecoveryState?: () => AtRestRecoverySurfaceState;
  onLogin?: () => void;
  onOpenSettings?: () => void;
  /** Primary needs-recovery CTA ("Fix now") — routes through the plugin's single
   * startAtRestRecoveryFlow() indirection (interim: Settings → Advanced). */
  onStartAtRestRecovery?: () => void;
  /** Secondary needs-recovery CTA ("Enter recovery code…") — the non-destructive
   * D5 alternate; opens the recovery-code restore flow. */
  onRestoreFromRecoveryCode?: () => void;
}

// ─── View Class ────────────────────────────────────────────────────────────

export class VaultGuardSidebarView extends ItemView {
  private readonly i18n = createI18n();
  private config: VaultGuardSidebarViewConfig | null = null;
  private options: VaultGuardSidebarViewOptions;
  private ruleCache: Map<string, ViewCacheEntry> = new Map();
  private accessCache: Map<string, { summary: PathAccessSummary; fetchedAt: number }> = new Map();
  private filterLevel: string = "all";
  private filterUser: string = "all";
  private filterRole: string = "all";
  private filterShared: boolean = false;
  private searchQuery: string = "";
  private sortMode: SortMode = "name-asc";
  private entries: FileEntry[] = [];
  private allRules: PermissionRule[] = [];
  private knownUsers: Array<{ id: string; label: string }> = [];
  private knownRoles: string[] = [];
  private userMap: Map<string, UserListEntry> = new Map();
  private isLoading = false;
  private hasLoadedOnce = false;
  private contentEl_: HTMLElement | null = null;
  private revoked = false;
  private revokeReason = "";
  private leaseExpiresAt: number | null = null;
  private batchAccessUnavailable = false;

  // At-rest needs-recovery banner state (Phase 13 #1). Driven by BOTH a live
  // push (setAtRestRecoveryState) and a fresh-view pull (getAtRestRecoveryState
  // seeded in onOpen/reload) so a mid-session leaf reopen still shows it.
  private atRestNeedsRecovery = false;
  private atRestRecoveryReason = "";
  private atRestCanReset = false;
  private atRestBannerEl: HTMLElement | null = null;

  // References to filter/UI elements so we can update them in place
  private userSelectEl: HTMLSelectElement | null = null;
  private roleSelectEl: HTMLSelectElement | null = null;
  private levelSelectEl: HTMLSelectElement | null = null;
  private sortSelectEl: HTMLSelectElement | null = null;
  private sharedToggleEl: HTMLInputElement | null = null;
  private searchInputEl: HTMLInputElement | null = null;
  private searchDebounce: number | null = null;

  constructor(leaf: WorkspaceLeaf, options: VaultGuardSidebarViewOptions = {}) {
    super(leaf);
    this.options = options;
  }

  /**
   * Inject configuration after construction (since Obsidian controls instantiation).
   */
  configure(config: VaultGuardSidebarViewConfig | null): void {
    this.config = config;
  }

  getViewType(): string {
    return VAULTGUARD_VIEW_TYPE;
  }

  getDisplayText(): string {
    return this.i18n.t("sidebar.title");
  }

  getIcon(): string {
    return "vaultguard-shield";
  }

  async onOpen(): Promise<void> {
    const container = this.containerEl.children[1] as HTMLElement;
    container.empty();
    container.addClass("vaultguard-sidebar");
    this.i18n.applyToRoot(container);

    this.contentEl_ = container;

    // W1 pull: seed from the cipher's CURRENT state BEFORE painting so a fresh
    // leaf (a mid-session reopen) reflects reality, not the push-only default.
    this.seedAtRestRecoveryFromPull();

    if (!this.config) {
      this.renderNotLoggedIn(container);
      // The banner shows even logged out — needs-recovery is real regardless of
      // auth, and mobile has no status bar, so this is the primary mobile surface.
      this.refreshAtRestBanner();
      return;
    }

    this.renderShell(container);
    this.refreshAtRestBanner();
    this.refreshPendingLargeFileBanner();
    await this.loadEntries();
  }

  async onClose(): Promise<void> {
    if (this.searchDebounce !== null) {
      window.clearTimeout(this.searchDebounce);
      this.searchDebounce = null;
    }
    this.ruleCache.clear();
    this.accessCache.clear();
    this.entries = [];
    this.allRules = [];
    this.knownUsers = [];
    this.knownRoles = [];
    this.userSelectEl = null;
    this.roleSelectEl = null;
    this.levelSelectEl = null;
    this.sortSelectEl = null;
    this.sharedToggleEl = null;
    this.searchInputEl = null;
    this.atRestBannerEl = null;
  }

  // ─── At-Rest Needs-Recovery Banner (Phase 13 #1) ──────────────────────

  /**
   * Push the current at-rest recovery state into the view — the live path
   * from the plugin's refreshAtRestRecoverySurfaces hub. Mirrors
   * updateLeaseExpiry: store the state + surgically refresh the single banner
   * element, never a full re-render.
   */
  setAtRestRecoveryState(state: AtRestRecoverySurfaceState): void {
    this.atRestNeedsRecovery = state.needsRecovery;
    this.atRestRecoveryReason = state.reason;
    this.atRestCanReset = state.canReset;
    this.refreshAtRestBanner();
  }

  /**
   * W1 pull path: seed the three at-rest fields from the plugin's CURRENT
   * cipher state so a freshly-instantiated leaf renders from reality on first
   * paint. A later setAtRestRecoveryState push still updates live.
   */
  private seedAtRestRecoveryFromPull(): void {
    const s = this.options.getAtRestRecoveryState?.();
    if (s) {
      this.atRestNeedsRecovery = s.needsRecovery;
      this.atRestRecoveryReason = s.reason;
      this.atRestCanReset = s.canReset;
    }
  }

  /**
   * Surgically insert (or remove) the single needs-recovery banner as the
   * FIRST child of the content container, independent of the shell/empty-state
   * below it — modeled on updateLeaseExpiry's in-place update, NOT a full
   * re-render, so it persists in both the renderShell and renderNotLoggedIn
   * layouts.
   */
  private refreshAtRestBanner(): void {
    const container = this.contentEl_;
    if (!container) return;

    // Drop any prior banner first (also clears a stale ref orphaned by a
    // container empty()), so we never stack duplicates on repeated refreshes.
    this.atRestBannerEl?.remove();
    this.atRestBannerEl = null;

    if (!this.atRestNeedsRecovery) return;

    const banner = container.createDiv({
      cls: "vaultguard-sb-at-rest-recovery mod-critical",
      prepend: true,
    });
    this.atRestBannerEl = banner;
    this.renderAtRestRecoveryBanner(banner);
  }

  private renderAtRestRecoveryBanner(container: HTMLElement): void {
    container.empty();

    const header = container.createDiv({ cls: "vaultguard-sb-at-rest-recovery-header" });
    const icon = header.createSpan({ cls: "vaultguard-sb-at-rest-recovery-icon" });
    setIcon(icon, "lock");
    header.createSpan({
      cls: "vaultguard-sb-at-rest-recovery-title",
      text: "Encryption locked — sync paused",
    });

    container.createDiv({
      cls: "vaultguard-sb-at-rest-recovery-reason",
      text:
        this.atRestRecoveryReason ||
        "Local at-rest encryption can't unlock on this device, so sync is paused.",
    });

    const actions = container.createDiv({ cls: "vaultguard-sb-at-rest-recovery-actions" });

    // Both CTAs always render — the banner always offers the route. The
    // honesty/enablement copy for the destructive reset lives in 13-03's
    // modal/settings, not here.
    const fixBtn = actions.createEl("button", {
      cls: "vaultguard-sb-at-rest-recovery-action vaultguard-sb-at-rest-recovery-fix mod-cta",
      text: "Fix now",
    });
    fixBtn.addEventListener("click", () => this.options.onStartAtRestRecovery?.());

    const restoreBtn = actions.createEl("button", {
      cls: "vaultguard-sb-at-rest-recovery-action vaultguard-sb-at-rest-recovery-restore",
      text: "Enter recovery code…",
    });
    restoreBtn.addEventListener("click", () => this.options.onRestoreFromRecoveryCode?.());
  }

  /**
   * Force reload all entries. If the view was opened before login,
   * this re-renders the full shell now that config is available.
   *
   * Also drops the cached user directory — a freshly-granted permission
   * may target a teammate who was just invited and isn't in the prior
   * map yet, which would otherwise render their chip as a raw UUID until
   * the next session.
   */
  async reload(): Promise<void> {
    this.ruleCache.clear();
    this.accessCache.clear();
    this.userMap = new Map();

    if (!this.contentEl_) return;

    // W1 pull: re-seed from CURRENT cipher state before repainting.
    this.seedAtRestRecoveryFromPull();

    if (!this.config) {
      this.contentEl_.empty();
      this.renderNotLoggedIn(this.contentEl_);
      this.refreshAtRestBanner();
      return;
    }

    // If we previously showed "not logged in", rebuild the full shell
    if (!this.contentEl_.querySelector(".vaultguard-sb-list")) {
      this.contentEl_.empty();
      this.renderShell(this.contentEl_);
    }

    this.refreshAtRestBanner();
    await this.loadEntries();
  }

  // ─── Shell Rendering ──────────────────────────────────────────────────

  private renderNotLoggedIn(container: HTMLElement): void {
    const authState = this.options.getAuthState?.() ?? null;
    const isLoggedOut = Boolean(authState);
    const header = container.createDiv({ cls: "vaultguard-sb-header" });
    const titleRow = header.createDiv({ cls: "vaultguard-sb-title-row" });
    const titleIcon = titleRow.createSpan({ cls: "vaultguard-sb-title-icon" });
    setIcon(titleIcon, "vaultguard-shield");
    titleRow.createSpan({ cls: "vaultguard-sb-title-text", text: this.i18n.t("sidebar.title") });

    const recoveryBtn = titleRow.createEl("button", {
      cls: "vaultguard-sb-recovery-btn clickable-icon",
      attr: {
        "aria-label": this.i18n.t("sidebar.recovery"),
        title: this.i18n.t("sidebar.recovery"),
        type: "button",
      },
    });
    setIcon(recoveryBtn, "history");
    recoveryBtn.addEventListener("click", () => this.config?.onOpenRecoveryCenter?.());

    const emptyState = container.createDiv({
      cls: isLoggedOut
        ? `vaultguard-sb-empty vaultguard-sb-auth-state vaultguard-sb-auth-state-${authState?.tone ?? "warning"}`
        : "vaultguard-sb-empty",
    });
    const icon = emptyState.createDiv({ cls: "vaultguard-sb-empty-icon" });
    setIcon(icon, authState?.icon ?? "lock");

    if (authState) {
      emptyState.createEl("h3", { text: authState.title });
      emptyState.createEl("p", { text: authState.message });
      if (authState.detail) {
        emptyState.createEl("p", {
          text: authState.detail,
          cls: "vaultguard-sb-empty-hint",
        });
      }

      if (this.options.onLogin) {
        const loginBtn = emptyState.createEl("button", {
          cls: "vaultguard-sb-empty-action vaultguard-sb-empty-action-primary",
          text: authState.actionLabel ?? this.i18n.t("sidebar.login"),
        });
        loginBtn.addEventListener("click", () => this.options.onLogin?.());
      } else if (this.options.onOpenSettings) {
        const settingsBtn = emptyState.createEl("button", {
          cls: "vaultguard-sb-empty-action vaultguard-sb-empty-action-primary",
          text: this.i18n.t("sidebar.openSettings"),
        });
        settingsBtn.addEventListener("click", () => this.options.onOpenSettings?.());
      }
      return;
    }

    emptyState.createEl("p", {
      text: this.i18n.t("sidebar.loginPrompt"),
    });
    emptyState.createEl("p", {
      text: this.i18n.t("sidebar.loginHint"),
      cls: "vaultguard-sb-empty-hint",
    });
  }

  /**
   * Show a revocation notice in the sidebar. Called by the main plugin
   * when the heartbeat or lease refresh detects revoked access.
   */
  showRevocationNotice(reason: string): void {
    this.revoked = true;
    this.revokeReason = reason;
    if (this.contentEl_) {
      this.contentEl_.empty();
      this.renderRevocationNotice(this.contentEl_);
    }
  }

  /**
   * Update the lease expiry display. Called periodically by the main plugin.
   */
  updateLeaseExpiry(expiresAt: number | null): void {
    this.leaseExpiresAt = expiresAt;
    const el = this.contentEl_?.querySelector(".vaultguard-lease-warning");
    if (el) {
      this.renderLeaseExpiryContent(el as HTMLElement);
    }
  }

  private renderRevocationNotice(container: HTMLElement): void {
    const notice = container.createDiv({ cls: "vaultguard-revocation-notice" });

    notice.createEl("h3", { text: "Access revoked" });
    notice.createEl("p", {
      text: "Your access to this vault has been revoked by an administrator.",
    });

    if (this.revokeReason) {
      notice.createEl("p", { text: `Reason: ${this.revokeReason}` });
    }

    notice.createEl("p", {
      text: "All locally cached data has been securely wiped. " +
        "If you believe this is an error, contact your organization administrator.",
    });

    notice.createEl("p", {
      text: "To regain access, you must be re-invited to the organization. " +
        "A new invitation will create fresh encryption keys.",
      cls: "setting-item-description",
    });
  }

  private renderLeaseStatus(container: HTMLElement): void {
    if (!this.leaseExpiresAt) return;

    const warning = container.createDiv({ cls: "vaultguard-lease-warning" });
    this.renderLeaseExpiryContent(warning);
  }

  private renderLeaseExpiryContent(el: HTMLElement): void {
    el.empty();

    if (!this.leaseExpiresAt) {
      el.hide();
      return;
    }

    const remaining = this.leaseExpiresAt - Date.now();
    const hoursLeft = Math.max(0, Math.floor(remaining / (1000 * 60 * 60)));
    const minutesLeft = Math.max(0, Math.floor((remaining % (1000 * 60 * 60)) / (1000 * 60)));

    el.show();

    if (remaining <= 0) {
      el.addClass("mod-critical");
      el.setText("Offline key lease expired. Reconnect to continue accessing files.");
    } else if (remaining < 30 * 60 * 1000) {
      // Less than 30 minutes
      el.addClass("mod-critical");
      el.setText(`Key lease expires in ${minutesLeft}m. Reconnect soon to avoid losing offline access.`);
    } else if (remaining < 2 * 60 * 60 * 1000) {
      // Less than 2 hours
      el.removeClass("mod-critical");
      el.setText(`Offline access: ${hoursLeft}h ${minutesLeft}m remaining`);
    } else {
      el.hide();
    }
  }

  private renderShell(container: HTMLElement): void {
    // Revocation takes priority over normal view
    if (this.revoked) {
      this.renderRevocationNotice(container);
      return;
    }

    // Lease expiry warning (shown above normal content)
    this.renderLeaseStatus(container);

    // Header
    const header = container.createDiv({ cls: "vaultguard-sb-header" });
    const titleRow = header.createDiv({ cls: "vaultguard-sb-title-row" });

    const titleIcon = titleRow.createSpan({ cls: "vaultguard-sb-title-icon" });
    setIcon(titleIcon, "vaultguard-shield");
    titleRow.createSpan({ cls: "vaultguard-sb-title-text", text: this.i18n.t("sidebar.title") });

    const menuBtn = titleRow.createEl("button", {
      cls: "vaultguard-sb-menu-btn clickable-icon",
      attr: {
        "aria-label": this.i18n.t("sidebar.menu"),
        title: this.i18n.t("sidebar.menu"),
        type: "button",
      },
    });
    setIcon(menuBtn, "more-horizontal");
    menuBtn.addEventListener("click", (evt) => {
      evt.preventDefault();
      evt.stopPropagation();
      if (this.config?.onOpenMenu) {
        this.config.onOpenMenu(evt);
      } else {
        this.config?.onOpenSettings?.();
      }
    });

    const refreshBtn = titleRow.createEl("button", {
      cls: "vaultguard-sb-refresh-btn clickable-icon",
      attr: {
        "aria-label": this.i18n.t("sidebar.refresh"),
        title: this.i18n.t("sidebar.refresh"),
        type: "button",
      },
    });
    setIcon(refreshBtn, "refresh-cw");
    refreshBtn.addEventListener("click", () => this.reload());

    // Search
    const searchRow = header.createDiv({ cls: "vaultguard-sb-search-row" });
    const searchWrap = searchRow.createDiv({ cls: "vaultguard-sb-search-wrap" });
    const searchIcon = searchWrap.createSpan({ cls: "vaultguard-sb-search-icon" });
    setIcon(searchIcon, "search");

    const searchInput = searchWrap.createEl("input", {
      cls: "vaultguard-sb-search",
      attr: {
        placeholder: this.i18n.t("sidebar.filter"),
        "aria-label": this.i18n.t("sidebar.filter"),
        type: "text",
        spellcheck: "false",
      },
    });
    this.searchInputEl = searchInput;

    const searchClear = searchWrap.createEl("button", {
      cls: "vaultguard-sb-search-clear",
      attr: {
        "aria-label": this.i18n.t("sidebar.clearSearch"),
        type: "button",
        title: this.i18n.t("sidebar.clearSearch"),
      },
    });
    setIcon(searchClear, "x");
    searchClear.hide();
    searchClear.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      this.clearSearch();
      searchInput.focus();
    });

    searchInput.addEventListener("input", () => {
      const value = searchInput.value;
      searchClear.toggle(value.length > 0);
      if (this.searchDebounce !== null) window.clearTimeout(this.searchDebounce);
      this.searchDebounce = window.setTimeout(() => {
        this.searchDebounce = null;
        this.searchQuery = value.toLowerCase().trim();
        this.renderEntries();
      }, SEARCH_DEBOUNCE_MS);
    });
    searchInput.addEventListener("keydown", (evt) => {
      if (evt.key === "Escape" && searchInput.value.length > 0) {
        evt.preventDefault();
        evt.stopPropagation();
        this.clearSearch();
      }
    });

    // Filter row 1: level + shared
    const filterRow1 = header.createDiv({ cls: "vaultguard-sb-filter-row" });

    const levelSelect = filterRow1.createEl("select", {
      cls: "vaultguard-sb-filter-select",
      attr: { "aria-label": "Filter by access level" },
    });
    for (const [value, label] of [
      ["all", "All Levels"],
      ["admin", "Admin"],
      ["write", "Write"],
      ["read", "Read"],
      ["none", "No Access"],
    ]) {
      levelSelect.createEl("option", { value, text: label });
    }
    levelSelect.value = this.filterLevel;
    levelSelect.addEventListener("change", () => {
      this.filterLevel = levelSelect.value;
      this.renderEntries();
    });
    this.levelSelectEl = levelSelect;

    const sharedToggle = filterRow1.createEl("label", {
      cls: "vaultguard-sb-filter-toggle",
      attr: { title: "Show only files shared with at least one other user or role" },
    });
    const checkbox = sharedToggle.createEl("input", { type: "checkbox" });
    checkbox.checked = this.filterShared;
    sharedToggle.createSpan({ text: "Shared only" });
    checkbox.addEventListener("change", () => {
      this.filterShared = checkbox.checked;
      this.renderEntries();
    });
    this.sharedToggleEl = checkbox;

    // Filter row 2: user + role
    const filterRow2 = header.createDiv({ cls: "vaultguard-sb-filter-row" });

    const userSelect = filterRow2.createEl("select", {
      cls: "vaultguard-sb-filter-select",
      attr: { "aria-label": "Filter by user" },
    });
    userSelect.createEl("option", { value: "all", text: "All users" });
    userSelect.addEventListener("change", () => {
      this.filterUser = userSelect.value;
      this.renderEntries();
    });
    this.userSelectEl = userSelect;

    const roleSelect = filterRow2.createEl("select", {
      cls: "vaultguard-sb-filter-select",
      attr: { "aria-label": "Filter by role" },
    });
    roleSelect.createEl("option", { value: "all", text: "All roles" });
    roleSelect.addEventListener("change", () => {
      this.filterRole = roleSelect.value;
      this.renderEntries();
    });
    this.roleSelectEl = roleSelect;

    // Filter row 3: sort
    const filterRow3 = header.createDiv({ cls: "vaultguard-sb-filter-row" });
    const sortSelect = filterRow3.createEl("select", {
      cls: "vaultguard-sb-filter-select",
      attr: { "aria-label": "Sort order" },
    });
    for (const [value, label] of [
      ["name-asc", "Sort: Name A-Z"],
      ["name-desc", "Sort: Name Z-A"],
      ["level-desc", "Sort: Access High → Low"],
      ["shared-desc", "Sort: Most Shared First"],
    ]) {
      sortSelect.createEl("option", { value, text: label });
    }
    sortSelect.value = this.sortMode;
    sortSelect.addEventListener("change", () => {
      this.sortMode = sortSelect.value as SortMode;
      this.renderEntries();
    });
    this.sortSelectEl = sortSelect;

    // Active filter chips row (populated dynamically in renderEntries)
    header.createDiv({ cls: "vaultguard-sb-chips" });

    container.createDiv({ cls: "vaultguard-sb-large-pending" });
    this.refreshPendingLargeFileBanner();

    // Entry list container
    container.createDiv({ cls: "vaultguard-sb-list" });
  }

  private refreshPendingLargeFileBanner(): void {
    const host = this.contentEl_?.querySelector<HTMLElement>(
      ".vaultguard-sb-large-pending",
    );
    if (!host) return;
    host.empty();
    const summary = this.config?.getPendingLargeFileSummary?.();
    if (!summary || summary.count === 0) {
      host.hide();
      return;
    }
    host.show();
    const icon = host.createSpan({ cls: "vaultguard-sb-large-pending-icon" });
    setIcon(icon, summary.blocked > 0 ? "alert-triangle" : "cloud-upload");
    const detail = host.createDiv({ cls: "vaultguard-sb-large-pending-detail" });
    detail.createEl("strong", {
      text: `${summary.count} large file${summary.count === 1 ? "" : "s"} pending`,
    });
    detail.createEl("span", {
      text: summary.blocked > 0
        ? `${summary.blocked} need conflict review; local copies are preserved.`
        : "Waiting for a safe encrypted upload; local copies are preserved.",
    });
    if (summary.retryable > 0) {
      const retry = host.createEl("button", { text: "Retry now" });
      retry.addEventListener("click", () => this.config?.onRetryPendingLargeFiles?.());
    }
  }

  private clearSearch(): void {
    if (this.searchInputEl) {
      this.searchInputEl.value = "";
      const clearBtn = this.searchInputEl.parentElement?.querySelector(".vaultguard-sb-search-clear") as HTMLElement | null;
      if (clearBtn) clearBtn.hide();
    }
    if (this.searchDebounce !== null) {
      window.clearTimeout(this.searchDebounce);
      this.searchDebounce = null;
    }
    this.searchQuery = "";
    this.renderEntries();
  }

  private clearAllFilters(): void {
    this.filterLevel = "all";
    this.filterUser = "all";
    this.filterRole = "all";
    this.filterShared = false;
    this.searchQuery = "";

    if (this.levelSelectEl) this.levelSelectEl.value = "all";
    if (this.userSelectEl) this.userSelectEl.value = "all";
    if (this.roleSelectEl) this.roleSelectEl.value = "all";
    if (this.sharedToggleEl) this.sharedToggleEl.checked = false;
    if (this.searchInputEl) {
      this.searchInputEl.value = "";
      const clearBtn = this.searchInputEl.parentElement?.querySelector(".vaultguard-sb-search-clear") as HTMLElement | null;
      if (clearBtn) clearBtn.hide();
    }
    if (this.searchDebounce !== null) {
      window.clearTimeout(this.searchDebounce);
      this.searchDebounce = null;
    }

    this.renderEntries();
  }

  private hasActiveFilters(): boolean {
    return (
      this.filterLevel !== "all" ||
      this.filterUser !== "all" ||
      this.filterRole !== "all" ||
      this.filterShared ||
      this.searchQuery.length > 0
    );
  }

  // ─── Data Loading ─────────────────────────────────────────────────────

  private async loadEntries(): Promise<void> {
    if (!this.config || !this.contentEl_) return;

    this.isLoading = true;
    this.renderEntries();

    try {
      // Get all vault files
      const allFiles = this.app.vault.getAllLoadedFiles();
      const paths: string[] = [];

      for (const file of allFiles) {
        if (file instanceof TFile) {
          paths.push(file.path);
        }
      }

      // Fetch effective access for every visible file. This endpoint is the
      // same source of truth used by the file header and file explorer dots,
      // and it works for non-admin vault members. Raw rule listing is still
      // useful for admin-only role filters, but it must never be the only
      // way the sidebar learns per-file permissions.
      this.allRules = [];
      const [rules, accessByPath] = await Promise.all([
        this.loadRulesIfAllowed(),
        this.loadAccessSummaries(paths),
        this.loadUsersIfNeeded(),
      ]).then(([rulesResult, accessResult]) => [rulesResult, accessResult] as const);

      this.allRules = rules;
      if (this.allRules.length > 0) {
        this.ruleCache.set("__all__", { rules: this.allRules, fetchedAt: Date.now() });
      }
      this.mergePathAccessIntoDirectory([...accessByPath.values()]);

      // Extract known users and roles from authoritative summaries plus
      // raw rules when an admin can list them.
      this.extractUsersAndRoles(this.allRules, [...accessByPath.values()]);
      this.populateFilterDropdowns();

      // Build entries from vault files regardless of API state
      this.entries = paths.map((path) =>
        this.buildEntry(path, this.allRules, accessByPath.get(this.normalizePath(path)))
      );
    } catch {
      this.entries = [];
    } finally {
      this.isLoading = false;
      this.hasLoadedOnce = true;
      this.renderEntries();
    }
  }

  private async loadUsersIfNeeded(): Promise<void> {
    if (this.userMap.size > 0) return;
    try {
      const users = await this.config!.apiClient.listUsers();
      this.userMap = buildAccessUserMap(users);
    } catch {
      // Silently fail — degrades to showing user IDs
    }
  }

  private async loadRulesIfAllowed(): Promise<PermissionRule[]> {
    if (!this.config || !this.isViewerEffectivelyAdmin()) {
      return [];
    }

    try {
      return await this.config.apiClient.getPermissions();
    } catch {
      return [];
    }
  }

  private async loadAccessSummaries(paths: string[]): Promise<Map<string, PathAccessSummary>> {
    const summariesByPath = new Map<string, PathAccessSummary>();
    if (!this.config || paths.length === 0) return summariesByPath;

    const pending: string[] = [];
    const now = Date.now();

    for (const path of paths) {
      const key = this.normalizePath(path);
      const cached = this.accessCache.get(key);
      if (cached && now - cached.fetchedAt < CACHE_TTL_MS) {
        summariesByPath.set(key, cached.summary);
      } else {
        pending.push(path);
      }
    }

    for (let i = 0; i < pending.length; i += BATCH_PATH_LIMIT) {
      const chunk = pending.slice(i, i + BATCH_PATH_LIMIT);
      for (const summary of await this.fetchAccessChunk(chunk)) {
        const key = this.normalizePath(summary.path);
        this.accessCache.set(key, { summary, fetchedAt: now });
        summariesByPath.set(key, summary);
      }
    }

    await this.applyEffectiveLevels(paths, summariesByPath, now);

    return summariesByPath;
  }

  private async fetchAccessChunk(paths: string[]): Promise<PathAccessSummary[]> {
    if (!this.config) return [];
    if (this.batchAccessUnavailable) return this.fetchAccessPerPath(paths);

    try {
      const summaries = await this.config.apiClient.getBatchPathAccess(paths);
      const byPath = new Map(summaries.map((summary) => [this.normalizePath(summary.path), summary]));
      return paths.flatMap((path) => {
        const key = this.normalizePath(path);
        const summary = byPath.get(key);
        return summary ? [summary] : [];
      });
    } catch (err) {
      if (this.isMissingBatchAccessRoute(err)) {
        this.batchAccessUnavailable = true;
      }
      return this.fetchAccessPerPath(paths);
    }
  }

  private async fetchAccessPerPath(paths: string[]): Promise<PathAccessSummary[]> {
    if (!this.config) return [];

    const settled = await Promise.allSettled(
      paths.map((path) => this.config!.apiClient.getPathAccess(path))
    );

    return settled.flatMap((result) =>
      result.status === "fulfilled" ? [result.value] : []
    );
  }

  private async applyEffectiveLevels(
    paths: string[],
    summariesByPath: Map<string, PathAccessSummary>,
    fetchedAt: number
  ): Promise<void> {
    if (!this.config?.getPermissionLevel) return;

    await Promise.allSettled(
      paths.map(async (path) => {
        const level = this.permissionLevelToAccessLevel(
          await this.config!.getPermissionLevel!(path)
        );
        const key = this.normalizePath(path);
        const existing = summariesByPath.get(key);
        const summary: PathAccessSummary = existing
          ? { ...existing, currentUserLevel: level }
          : { path: key, currentUserLevel: level, principals: [] };
        summariesByPath.set(key, summary);
        this.accessCache.set(key, { summary, fetchedAt });
      })
    );
  }

  private isMissingBatchAccessRoute(err: unknown): boolean {
    const message = err instanceof Error ? err.message.toLowerCase() : String(err).toLowerCase();
    return (
      message.includes("route not found") &&
      message.includes("/permissions/access/batch")
    );
  }

  private resolveUserLabel(userId: string): string {
    if (userId === "*") return "Everyone";
    const user = this.userMap.get(userId);
    return user ? getAccessUserDisplayName(user) : userId;
  }

  private principalLabel(principal: PathAccessPrincipal): string {
    if (principal.displayName) return principal.displayName;
    if (principal.email) return principal.email;
    return this.resolveUserLabel(principal.userId);
  }

  private mergePathAccessIntoDirectory(summaries: PathAccessSummary[]): void {
    if (summaries.length === 0) return;

    const usersById = new Map<string, UserListEntry>();
    for (const user of this.userMap.values()) {
      usersById.set(user.id, user);
    }

    for (const summary of summaries) {
      for (const principal of summary.principals) {
        if (usersById.has(principal.userId)) continue;
        if (!principal.displayName && !principal.email) continue;
        usersById.set(principal.userId, {
          id: principal.userId,
          email: principal.email ?? "",
          displayName: principal.displayName ?? "",
          name: principal.displayName ?? "",
          role: this.mapVaultRoleToUserRole(principal.role),
          status: "active",
          lastActive: "",
          createdAt: "",
          mfaEnabled: false,
          deviceCount: 0,
          type: "user",
        });
      }
    }

    this.userMap = buildAccessUserMap([...usersById.values()]);
  }

  private mapVaultRoleToUserRole(role: VaultMemberRole | string | undefined): UserListEntry["role"] {
    if (role === "admin" || role === "editor" || role === "viewer") return role;
    return "custom";
  }

  private extractUsersAndRoles(
    rules: PermissionRule[],
    summaries: PathAccessSummary[] = []
  ): void {
    const users = new Map<string, string>(); // id → label
    const roles = new Set<string>();
    const selfId = this.config?.currentUserId ?? "";

    // Seed the dropdown with every user in the loaded directory, not just
    // users who happen to have an explicit rule. Otherwise vault members
    // with default role-based access would never appear as filter options.
    // (userMap is keyed by id AND email — dedupe by user.id.)
    const seenUserIds = new Set<string>();
    for (const user of this.userMap.values()) {
      if (seenUserIds.has(user.id)) continue;
      seenUserIds.add(user.id);
      // Skip self — buildEntry excludes self from principals, so filtering
      // by self would always return 0.
      if (user.id === selfId) continue;
      // Skip revoked users — they're not actionable filter targets.
      if (user.status === "revoked") continue;
      users.set(user.id, getAccessUserDisplayName(user));
    }

    for (const summary of summaries) {
      for (const principal of summary.principals) {
        if (principal.role) {
          roles.add(principal.role);
        }
        if (
          principal.userId !== selfId &&
          principal.level !== "none" &&
          !users.has(principal.userId)
        ) {
          users.set(principal.userId, this.principalLabel(principal));
        }
      }
    }

    for (const rule of rules) {
      if (rule.role) {
        roles.add(rule.role);
      }
      if (rule.userId === "*") {
        users.set("*", "Everyone");
      }
      // Fallback: include rule-targeted users who aren't in the directory
      // (just-invited, soft-deleted, cross-org references, etc.) so a stale
      // rule still surfaces in the filter.
      if (
        rule.userId &&
        rule.userId !== "*" &&
        rule.userId !== selfId &&
        !users.has(rule.userId)
      ) {
        users.set(rule.userId, this.resolveUserLabel(rule.userId));
      }
    }

    this.knownUsers = [...users.entries()]
      .map(([id, label]) => ({ id, label }))
      .sort((a, b) => {
        // Pin "Everyone (*)" to the top
        if (a.id === "*" && b.id !== "*") return -1;
        if (b.id === "*" && a.id !== "*") return 1;
        return a.label.localeCompare(b.label);
      });

    this.knownRoles = [...roles].sort();
  }

  private populateFilterDropdowns(): void {
    if (this.userSelectEl) {
      const current = this.userSelectEl.value;
      while (this.userSelectEl.options.length > 1) {
        this.userSelectEl.remove(1);
      }
      for (const user of this.knownUsers) {
        this.userSelectEl.createEl("option", {
          value: user.id,
          text: user.id === "*" ? "Everyone (*)" : user.label,
        });
      }
      if (Array.from(this.userSelectEl.options).some((o) => o.value === current)) {
        this.userSelectEl.value = current;
      } else {
        this.userSelectEl.value = "all";
        this.filterUser = "all";
      }
    }

    if (this.roleSelectEl) {
      const current = this.roleSelectEl.value;
      while (this.roleSelectEl.options.length > 1) {
        this.roleSelectEl.remove(1);
      }
      for (const role of this.knownRoles) {
        this.roleSelectEl.createEl("option", { value: role, text: role });
      }
      if (Array.from(this.roleSelectEl.options).some((o) => o.value === current)) {
        this.roleSelectEl.value = current;
      } else {
        this.roleSelectEl.value = "all";
        this.filterRole = "all";
      }
    }
  }

  private buildEntry(
    path: string,
    allRules: PermissionRule[],
    access?: PathAccessSummary
  ): FileEntry {
    const name = path.split("/").pop() ?? path;

    if (access) {
      const principals = access.principals
        .filter((principal) => principal.userId !== this.config!.currentUserId)
        .filter((principal) => principal.level !== "none")
        .map((principal) => ({
          id: principal.userId,
          label: this.principalLabel(principal),
          level: principal.level,
          type: "user" as const,
          role: principal.role,
        }))
        .sort((a, b) => {
          const levelDiff = this.levelRank(b.level) - this.levelRank(a.level);
          if (levelDiff !== 0) return levelDiff;
          return a.label.localeCompare(b.label);
        });

      const userIds = new Set<string>();
      const roleIds = new Set<string>();
      for (const principal of principals) {
        userIds.add(principal.id);
        if (principal.role) roleIds.add(principal.role);
      }

      return {
        path,
        name,
        lowerPath: path.toLowerCase(),
        lowerName: name.toLowerCase(),
        level: access.currentUserLevel,
        sharedWith: principals.length,
        principals: principals.map(({ id, label, level, type }) => ({ id, label, level, type })),
        userIds,
        roleIds,
      };
    }

    // Filter rules that match this path
    const matchingRules = allRules.filter((r) => this.ruleMatchesPath(r.pathPattern, path));

    const myLevel = this.resolveMyLevel(matchingRules);

    // Per-principal state with the same conflict-resolution semantics the
    // header uses: more-specific path wins, deny wins at the same
    // specificity. Without this, a deny rule on a folder can be skipped
    // while older allow rules keep an avatar visible.
    interface PrincipalState {
      id: string;
      label: string;
      level: PermissionAccessLevel;
      type: "user" | "role";
      specificity: number;
      denied: boolean;
    }

    const principals = new Map<string, PrincipalState>();

    const shouldReplace = (
      current: PrincipalState | undefined,
      nextLevel: PermissionAccessLevel,
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

    for (const rule of matchingRules) {
      const level: PermissionAccessLevel = rule.effect === "deny" ? "none" : this.ruleLevelString(rule);
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

      if (rule.userId === this.config!.currentUserId) continue;
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

    const sortedPrincipals = [...principals.values()]
      .filter((principal) => principal.level !== "none")
      .map(({ id, label, level, type }) => ({ id, label, level, type }))
      .sort((a, b) => this.levelRank(b.level) - this.levelRank(a.level));

    const userIds = new Set<string>();
    const roleIds = new Set<string>();
    for (const p of sortedPrincipals) {
      if (p.type === "user") userIds.add(p.id);
      else roleIds.add(p.id);
    }

    return {
      path,
      name,
      lowerPath: path.toLowerCase(),
      lowerName: name.toLowerCase(),
      level: myLevel,
      sharedWith: sortedPrincipals.length,
      principals: sortedPrincipals,
      userIds,
      roleIds,
    };
  }

  // ─── Entry Rendering ──────────────────────────────────────────────────

  private renderEntries(): void {
    if (!this.contentEl_) return;

    const listEl = this.contentEl_.querySelector(".vaultguard-sb-list") as HTMLElement | null;
    const chipsEl = this.contentEl_.querySelector(".vaultguard-sb-chips") as HTMLElement | null;
    if (!listEl) return;

    listEl.empty();
    if (chipsEl) chipsEl.empty();

    if (this.isLoading) {
      const loadingEl = listEl.createDiv({ cls: "vaultguard-sb-loading" });
      loadingEl.setAttribute("role", "status");
      loadingEl.setAttribute("aria-live", "polite");
      loadingEl.setAttribute("aria-atomic", "true");
      const spinner = loadingEl.createSpan({ cls: "vaultguard-sb-spinner" });
      setIcon(spinner, "loader");
      loadingEl.createSpan({ text: this.i18n.t("sidebar.loadingPermissions") });
      return;
    }

    // Active-filter chips
    if (chipsEl && this.hasActiveFilters()) {
      this.renderFilterChips(chipsEl);
    }

    // Apply filters
    const total = this.entries.length;
    // Raw count before any filtering — used by the empty-state branch to
    // distinguish "vault has files but the viewer can read none of them"
    // from "vault has no files at all".
    const totalRawFiles = this.entries.length;
    let filtered = this.entries;

    // Non-admins can't read "no access" rows — those files don't appear in
    // the file-explorer either (HIDDEN_CLS), so showing them here would be
    // misleading. Admins keep full visibility because resolveMyLevel always
    // returns "admin" for them, so this filter is a no-op in their view.
    if (!this.isViewerEffectivelyAdmin()) {
      filtered = filtered.filter((e) => e.level !== "none");
    }

    if (this.filterLevel !== "all") {
      filtered = filtered.filter((e) => e.level === this.filterLevel);
    }

    if (this.filterShared) {
      filtered = filtered.filter((e) => e.sharedWith > 0);
    }

    if (this.filterUser !== "all") {
      const target = this.filterUser;
      // Use the resolved principals (effective access, deny-aware) — not
      // raw rules — so that a more-specific deny correctly hides the file
      // from this user's filter.
      filtered = filtered.filter((e) => e.userIds.has(target));
    }

    if (this.filterRole !== "all") {
      const target = this.filterRole;
      filtered = filtered.filter((e) => e.roleIds.has(target));
    }

    if (this.searchQuery) {
      const q = this.searchQuery;
      filtered = filtered.filter((e) => e.lowerName.includes(q) || e.lowerPath.includes(q));
    }

    // Sort
    filtered = this.applySort(filtered);

    // Summary bar (always shown so the user sees totals/filtered count)
    const summary = listEl.createDiv({ cls: "vaultguard-sb-summary" });
    if (this.hasActiveFilters() && filtered.length !== total) {
      summary.createSpan({
        text: `${filtered.length} of ${total} files`,
        cls: "vaultguard-sb-summary-count",
      });
    } else {
      summary.createSpan({
        text: `${filtered.length} ${filtered.length === 1 ? "file" : "files"}`,
        cls: "vaultguard-sb-summary-count",
      });
    }
    const sharedCount = filtered.filter((e) => e.sharedWith > 0).length;
    if (sharedCount > 0) {
      summary.createSpan({
        text: `${sharedCount} shared`,
        cls: "vaultguard-sb-summary-shared",
      });
    }

    if (filtered.length === 0) {
      const emptyEl = listEl.createDiv({ cls: "vaultguard-sb-empty" });
      const icon = emptyEl.createDiv({ cls: "vaultguard-sb-empty-icon" });

      // State A — active filters: keep existing "no match" + reset action.
      if (this.hasActiveFilters()) {
        setIcon(icon, "filter");
        emptyEl.createEl("p", { text: "No files match the current filters." });
        const resetBtn = emptyEl.createEl("button", {
          cls: "vaultguard-sb-empty-action",
          text: "Clear filters",
        });
        resetBtn.addEventListener("click", () => this.clearAllFilters());
        return;
      }

      // State B — vault has files but the non-admin viewer has read
      // permission to none of them. Only meaningful for non-admins (admins
      // skip the no-access filter via isViewerEffectivelyAdmin above).
      const noReadAccess =
        !this.isViewerEffectivelyAdmin() &&
        totalRawFiles > 0;

      if (noReadAccess) {
        setIcon(icon, "lock");
        emptyEl.createEl("p", {
          text: "You don't have read permission to any files in this vault yet.",
        });
        emptyEl.createEl("p", {
          text: "Ask your organization admin to grant you access. Newly granted permissions appear here within a few seconds of the next sync.",
          cls: "vaultguard-sb-empty-hint",
        });
        return;
      }

      // State C — vault has no files at all.
      setIcon(icon, "file-x");
      emptyEl.createEl("p", { text: "No files in this vault yet." });
      emptyEl.createEl("p", {
        text: this.isViewerEffectivelyAdmin()
          ? "Create a note in Obsidian and it will sync here automatically."
          : "When your admin adds files (or grants you access to existing ones), they'll appear here.",
        cls: "vaultguard-sb-empty-hint",
      });
      return;
    }

    // Render each entry
    for (const entry of filtered) {
      this.renderEntry(listEl, entry);
    }
  }

  private renderFilterChips(container: HTMLElement): void {
    const addChip = (label: string, onClear: () => void) => {
      const chip = container.createDiv({ cls: "vaultguard-sb-chip" });
      chip.createSpan({ cls: "vaultguard-sb-chip-label", text: label });
      const x = chip.createEl("button", {
        cls: "vaultguard-sb-chip-clear",
        attr: { "aria-label": `Remove ${label}`, type: "button", title: "Remove filter" },
      });
      setIcon(x, "x");
      x.addEventListener("click", (evt) => {
        evt.preventDefault();
        evt.stopPropagation();
        onClear();
      });
    };

    if (this.searchQuery) {
      addChip(`Search: "${this.searchQuery}"`, () => this.clearSearch());
    }
    if (this.filterLevel !== "all") {
      addChip(`Level: ${this.formatLevel(this.filterLevel)}`, () => {
        this.filterLevel = "all";
        if (this.levelSelectEl) this.levelSelectEl.value = "all";
        this.renderEntries();
      });
    }
    if (this.filterShared) {
      addChip("Shared only", () => {
        this.filterShared = false;
        if (this.sharedToggleEl) this.sharedToggleEl.checked = false;
        this.renderEntries();
      });
    }
    if (this.filterUser !== "all") {
      const userLabel = this.knownUsers.find((u) => u.id === this.filterUser)?.label ?? this.filterUser;
      const display = this.filterUser === "*" ? "Everyone" : userLabel;
      addChip(`User: ${display}`, () => {
        this.filterUser = "all";
        if (this.userSelectEl) this.userSelectEl.value = "all";
        this.renderEntries();
      });
    }
    if (this.filterRole !== "all") {
      addChip(`Role: ${this.filterRole}`, () => {
        this.filterRole = "all";
        if (this.roleSelectEl) this.roleSelectEl.value = "all";
        this.renderEntries();
      });
    }

    // Clear-all button when there's more than one filter
    const activeCount =
      (this.searchQuery ? 1 : 0) +
      (this.filterLevel !== "all" ? 1 : 0) +
      (this.filterShared ? 1 : 0) +
      (this.filterUser !== "all" ? 1 : 0) +
      (this.filterRole !== "all" ? 1 : 0);

    if (activeCount > 1) {
      const clearAll = container.createEl("button", {
        cls: "vaultguard-sb-chip-clear-all",
        text: "Clear all",
        attr: { type: "button" },
      });
      clearAll.addEventListener("click", (evt) => {
        evt.preventDefault();
        this.clearAllFilters();
      });
    }
  }

  private applySort(entries: FileEntry[]): FileEntry[] {
    const arr = [...entries];
    switch (this.sortMode) {
      case "name-asc":
        arr.sort((a, b) => a.lowerName.localeCompare(b.lowerName) || a.lowerPath.localeCompare(b.lowerPath));
        break;
      case "name-desc":
        arr.sort((a, b) => b.lowerName.localeCompare(a.lowerName) || b.lowerPath.localeCompare(a.lowerPath));
        break;
      case "level-desc":
        arr.sort((a, b) => {
          const diff = this.levelRank(b.level) - this.levelRank(a.level);
          if (diff !== 0) return diff;
          return a.lowerName.localeCompare(b.lowerName);
        });
        break;
      case "shared-desc":
        arr.sort((a, b) => {
          const diff = b.sharedWith - a.sharedWith;
          if (diff !== 0) return diff;
          return a.lowerName.localeCompare(b.lowerName);
        });
        break;
    }
    return arr;
  }

  private renderEntry(container: HTMLElement, entry: FileEntry): void {
    const row = container.createDiv({ cls: "vaultguard-sb-entry" });

    // Click to open file
    row.addEventListener("click", () => {
      const file = this.app.vault.getAbstractFileByPath(entry.path);
      if (file instanceof TFile) {
        this.app.workspace.getLeaf(false).openFile(file);
      }
    });

    // Left: icon + file info
    const left = row.createDiv({ cls: "vaultguard-sb-entry-left" });

    const fileIcon = left.createSpan({ cls: "vaultguard-sb-entry-icon" });
    setIcon(fileIcon, "file-text");

    const info = left.createDiv({ cls: "vaultguard-sb-entry-info" });
    const nameEl = info.createDiv({ cls: "vaultguard-sb-entry-name" });
    this.renderHighlighted(nameEl, entry.name, this.searchQuery);

    const pathDisplay = entry.path.includes("/")
      ? entry.path.substring(0, entry.path.lastIndexOf("/"))
      : "";
    if (pathDisplay) {
      const pathEl = info.createDiv({ cls: "vaultguard-sb-entry-path" });
      this.renderHighlighted(pathEl, pathDisplay, this.searchQuery);
    }

    // Right: permission badge + avatar stack
    const right = row.createDiv({ cls: "vaultguard-sb-entry-right" });

    // Permission badge
    const badge = right.createSpan({
      cls: `vaultguard-sb-badge vaultguard-sb-badge-${entry.level}`,
    });
    badge.setText(this.formatLevel(entry.level));

    // Avatar stack
    if (entry.sharedWith > 0) {
      const avatarStack = right.createDiv({ cls: "vaultguard-sb-avatars" });

      const maxAvatars = 4;
      const shown = entry.principals.slice(0, maxAvatars);

      for (const principal of shown) {
        const avatar = avatarStack.createSpan({
          cls: `vaultguard-sb-avatar vaultguard-sb-avatar-${principal.level}`,
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

      if (entry.sharedWith > maxAvatars) {
        avatarStack.createSpan({
          cls: "vaultguard-sb-avatar-overflow",
          text: `+${entry.sharedWith - maxAvatars}`,
        });
      }
    }
  }

  /**
   * Render text with case-insensitive search-term highlighting.
   * Falls back to plain text when there's no query.
   */
  private renderHighlighted(target: HTMLElement, text: string, query: string): void {
    if (!query) {
      target.setText(text);
      return;
    }
    const lowerText = text.toLowerCase();
    let cursor = 0;
    let idx = lowerText.indexOf(query, cursor);
    if (idx === -1) {
      target.setText(text);
      return;
    }
    while (idx !== -1) {
      if (idx > cursor) {
        target.appendText(text.slice(cursor, idx));
      }
      target.createSpan({ cls: "vaultguard-sb-match", text: text.slice(idx, idx + query.length) });
      cursor = idx + query.length;
      idx = lowerText.indexOf(query, cursor);
    }
    if (cursor < text.length) {
      target.appendText(text.slice(cursor));
    }
  }

  private normalizePath(path: string): string {
    const trimmed = path.trim().replace(/\/+/g, "/");
    return trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  }

  // ─── Rule Matching ────────────────────────────────────────────────────

  private ruleMatchesPath(pattern: string, path: string): boolean {
    const normalizedPattern = pattern.replace(/^\/+/, "").replace(/\/+$/, "");
    const normalizedPath = path.replace(/^\/+/, "").replace(/\/+$/, "");

    // Exact match
    if (normalizedPath === normalizedPattern) return true;

    // Folder inheritance
    if (normalizedPattern.endsWith("/") && normalizedPath.startsWith(normalizedPattern)) return true;
    if (!normalizedPattern.includes("*") && normalizedPath.startsWith(normalizedPattern + "/")) return true;

    // Wildcard * (single segment)
    if (normalizedPattern === "*" || normalizedPattern === "**") return true;

    // Glob matching
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

  /**
   * Mirrors `resolveMyLevel`'s admin short-circuit: org admins/owners
   * always have full access, so the no-access filter must be skipped for
   * them. Returns false until config is wired so the early-render path
   * doesn't accidentally elide entries.
   */
  private isViewerEffectivelyAdmin(): boolean {
    const role = this.config?.currentUserRole;
    return role === "admin" || role === "owner";
  }

  private resolveMyLevel(rules: PermissionRule[]): PermissionAccessLevel {
    if (!this.config) return "read";
    const role = this.config.currentUserRole;
    if (role === "admin" || role === "owner") return "admin";

    let bestLevel: PermissionAccessLevel = "none";
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
        const level: PermissionAccessLevel = rule.effect === "deny" ? "none" : this.ruleLevelString(rule);
        if (this.levelRank(level) > this.levelRank(bestLevel)) {
          bestLevel = level;
        }
      }
    }

    if (bestLevel === "none" && bestSpecificity === -1) {
      if (role === "editor") return "write";
      return "read";
    }

    return bestLevel;
  }

  private ruleLevelString(rule: PermissionRule): PermissionAccessLevel {
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

  private permissionLevelToAccessLevel(level: PermissionLevel): PermissionAccessLevel {
    if (level >= PermissionLevel.ADMIN) return "admin";
    if (level >= PermissionLevel.WRITE) return "write";
    if (level >= PermissionLevel.READ) return "read";
    return "none";
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
