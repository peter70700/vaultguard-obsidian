/**
 * Path Permissions Modal — shows who has access to a specific file or folder,
 * with inline admin controls for adding/editing/removing rules.
 * Opened from the file-explorer right-click context menu.
 */

import {
  App,
  Modal,
  ButtonComponent,
  Notice,
  setIcon,
} from "obsidian";
import { setButtonLoading, setControlBusy } from "./loading-button";
import {
  VaultGuardApiClient,
  PermissionRule,
  PermissionMutationInput,
  PathAccessPrincipal,
  PathAccessSummary,
  UserListEntry,
} from "../api/client";
import { PermissionEditor } from "../admin/permission-editor";
import {
  buildAccessUserMap,
  findExactAccessUserMatch,
  formatAccessUserRole,
  formatAccessUserStatus,
  getAccessUserDisplayName,
  getAccessUserInitials,
  getAccessUserNameInitials,
  getAccessUserMeta,
  getAccessUserPickerValue,
  matchesAccessUserQuery,
  resolveAccessUserId,
  sortAccessUsers,
} from "./access-user-utils";

interface PathPermissionsConfig {
  app: App;
  apiClient: VaultGuardApiClient;
  path: string;
  isFolder: boolean;
  isAdmin: boolean;
  currentUserId: string;
  currentUserRole: string;
  /** See FilePermissionHeader.HeaderContext.allowAdminPerFileRestrictions. */
  allowAdminPerFileRestrictions?: boolean;
  onRulesChanged?: () => void;
}

export class PathPermissionsModal extends Modal {
  private cfg: PathPermissionsConfig;
  private rules: PermissionRule[] = [];
  private users: UserListEntry[] = [];
  private userMap: Map<string, UserListEntry> = new Map();
  private usersLoading = false;
  private usersLoadError: string | null = null;
  private draftPrincipalType: "user" | "role" = "user";
  private draftPrincipalValue = "";
  private draftSelectedUserId: string | null = null;
  private draftLevel = "write";
  private permissionsLoaded = false;
  private isClosed = false;
  private canManage = false;
  private currentUserLevel: "none" | "read" | "write" | "admin" = "none";
  private accessSummary: PathAccessSummary | null = null;
  private permissionEditor: PermissionEditor;

  constructor(cfg: PathPermissionsConfig) {
    super(cfg.app);
    this.cfg = cfg;
    this.permissionEditor = new PermissionEditor(cfg.app, cfg.apiClient);
    this.canManage = cfg.isAdmin;
    this.usersLoading = cfg.isAdmin;
  }

  async onOpen(): Promise<void> {
    this.isClosed = false;
    this.permissionsLoaded = false;
    this.modalEl.addClass("vaultguard-path-perms-modal");
    this.contentEl.addClass("vaultguard-path-perms-content");
    this.renderLoading();

    try {
      this.accessSummary = await this.cfg.apiClient.getPathAccess(this.cfg.path).catch(() => null);
      this.currentUserLevel = this.accessSummary?.currentUserLevel ?? "none";
      this.mergeAccessSummaryIntoDirectory();
      this.canManage = this.cfg.isAdmin || this.currentUserLevel === "admin";
      this.usersLoading = this.cfg.isAdmin;
      if (this.cfg.isAdmin) {
        void this.loadUsers();
      }

      this.rules = this.canManage
        ? await this.cfg.apiClient.getPermissions(this.cfg.path).catch(() => [])
        : [];
      this.permissionsLoaded = true;
      this.render();
    } catch (error) {
      this.renderError((error as Error).message);
    }
  }

  onClose(): void {
    this.isClosed = true;
    this.modalEl.removeClass("vaultguard-path-perms-modal");
    this.contentEl.removeClass("vaultguard-path-perms-content");
    this.contentEl.empty();
  }

  // ─── Render ────────────────────────────────────────────────────────

  private renderLoading(): void {
    this.contentEl.empty();
    this.contentEl.createDiv({ cls: "vaultguard-loading", text: "Loading permissions..." });
  }

  private renderError(message: string): void {
    this.contentEl.empty();
    this.renderHeader();
    this.contentEl.createDiv({
      cls: "vaultguard-error",
      text: `Failed to load permissions: ${message}`,
    });
  }

  private render(): void {
    this.contentEl.empty();
    this.renderHeader();
    this.renderMyAccess();
    this.renderAccessList();
    if (this.canManage) {
      this.renderAddSection();
    }
  }

  private renderHeader(): void {
    const header = this.contentEl.createDiv({ cls: "vaultguard-pp-header" });

    const iconEl = header.createSpan({ cls: "vaultguard-pp-header-icon" });
    setIcon(iconEl, this.cfg.isFolder ? "folder" : "file-text");

    const textEl = header.createDiv({ cls: "vaultguard-pp-header-text" });
    textEl.createEl("h3", {
      text: this.cfg.isFolder ? "Folder Permissions" : "File Permissions",
    });
    textEl.createDiv({
      cls: "vaultguard-pp-path",
      text: this.cfg.path,
    });
  }

  // ─── My Access ─────────────────────────────────────────────────────

  private renderMyAccess(): void {
    const section = this.contentEl.createDiv({ cls: "vaultguard-pp-my-access" });
    const myLevel = this.resolveMyLevel();

    const row = section.createDiv({ cls: "vaultguard-pp-my-row" });

    const lockIcon = row.createSpan({ cls: "vaultguard-pp-my-icon" });
    setIcon(
      lockIcon,
      myLevel === "admin"
        ? "shield"
        : myLevel === "write"
          ? "edit"
          : myLevel === "read"
            ? "eye"
            : "lock"
    );

    row.createSpan({ cls: "vaultguard-pp-my-label", text: "Your access:" });

    const badge = row.createSpan({
      cls: `vaultguard-fh-badge vaultguard-fh-badge-${myLevel}`,
    });
    badge.setText(this.formatLevel(myLevel));
  }

  // ─── Access List ───────────────────────────────────────────────────

  private renderAccessList(): void {
    const section = this.contentEl.createDiv({ cls: "vaultguard-pp-section" });
    section.createDiv({ cls: "vaultguard-pp-section-title", text: "Who has access" });

    const listEl = section.createDiv({ cls: "vaultguard-pp-list" });

    if (this.accessSummary?.principals.length) {
      this.renderEffectiveAccessRows(listEl, this.accessSummary.principals);
      return;
    }

    if (this.rules.length === 0) {
      listEl.createDiv({
        cls: "vaultguard-pp-empty",
        text: "Access details unavailable.",
      });
      return;
    }

    // Sort: highest level first, then by principal
    const sorted = this.rawRulesForDisplay().sort((a, b) => {
      const la = this.ruleLevelRank(a);
      const lb = this.ruleLevelRank(b);
      if (la !== lb) return lb - la;
      return this.principalLabel(a).localeCompare(this.principalLabel(b));
    });

    for (const rule of sorted) {
      this.renderRuleRow(listEl, rule);
    }
  }

  private renderEffectiveAccessRows(container: HTMLElement, principals: PathAccessPrincipal[]): void {
    const sorted = this.normalizeAccessPrincipals(principals).sort((a, b) => {
      const levelDiff = this.levelRank(b.level) - this.levelRank(a.level);
      if (levelDiff !== 0) return levelDiff;
      return this.accessPrincipalLabel(a).localeCompare(this.accessPrincipalLabel(b));
    });

    for (const principal of sorted) {
      this.renderEffectiveAccessRow(container, principal);
    }
  }

  private renderEffectiveAccessRow(container: HTMLElement, principal: PathAccessPrincipal): void {
    const row = container.createDiv({ cls: "vaultguard-pp-row vaultguard-pp-row-effective" });

    const avatarEl = row.createDiv({ cls: "vaultguard-pp-avatar" });
    avatarEl.createSpan({
      cls: "vaultguard-pp-initials",
      text: this.userInitials(principal.userId),
    });

    const infoEl = row.createDiv({ cls: "vaultguard-pp-info" });
    infoEl.createDiv({ cls: "vaultguard-pp-name", text: this.accessPrincipalLabel(principal) });
    infoEl.createDiv({
      cls: "vaultguard-pp-meta",
      text: principal.email || "Effective access",
    });

    const levelEl = row.createDiv({ cls: "vaultguard-pp-level" });
    if (this.canEditAccessPrincipal(principal)) {
      const select = levelEl.createEl("select", { cls: "vaultguard-pp-select" });
      const options: { value: string; label: string }[] = [
        { value: "admin", label: "Admin" },
        { value: "write", label: "Write" },
        { value: "read", label: "Read" },
        { value: "none", label: "No Access" },
      ];
      for (const opt of options) {
        const optEl = select.createEl("option", { text: opt.label, attr: { value: opt.value } });
        if (opt.value === principal.level) optEl.selected = true;
      }
      select.addEventListener("change", async () => {
        setControlBusy(select, true);
        try {
          await this.handleAccessPrincipalLevelChange(principal, select.value);
          new Notice("Permission updated.");
          await this.refresh();
        } catch (error) {
          new Notice(`Failed: ${(error as Error).message}`);
          setControlBusy(select, false);
        }
      });
      return;
    }

    const badge = levelEl.createSpan({
      cls: `vaultguard-fh-badge vaultguard-fh-badge-${principal.level}`,
    });
    badge.setText(this.formatLevel(principal.level));
  }

  private renderRuleRow(container: HTMLElement, rule: PermissionRule): void {
    const row = container.createDiv({ cls: "vaultguard-pp-row" });

    // Avatar
    const avatarEl = row.createDiv({ cls: "vaultguard-pp-avatar" });
    if (rule.role) {
      setIcon(avatarEl, "users");
    } else if (rule.userId === "*") {
      setIcon(avatarEl, "globe");
    } else {
      avatarEl.createSpan({
        cls: "vaultguard-pp-initials",
        text: this.userInitials(rule.userId),
      });
    }

    // Info
    const infoEl = row.createDiv({ cls: "vaultguard-pp-info" });
    infoEl.createDiv({ cls: "vaultguard-pp-name", text: this.principalLabel(rule) });

    const meta: string[] = [];
    if (rule.effect === "deny") meta.push("Denied");
    meta.push(rule.pathPattern);
    infoEl.createDiv({ cls: "vaultguard-pp-meta", text: meta.join(" · ") });

    // Level + actions
    const levelEl = row.createDiv({ cls: "vaultguard-pp-level" });

    if (this.canManage) {
      // Dropdown to change level
      const select = levelEl.createEl("select", { cls: "vaultguard-pp-select" });
      const options: { value: string; label: string }[] = [
        { value: "admin", label: "Admin" },
        { value: "write", label: "Write" },
        { value: "read", label: "Read" },
        { value: "none", label: "No Access" },
      ];
      for (const opt of options) {
        const optEl = select.createEl("option", { text: opt.label, attr: { value: opt.value } });
        if (opt.value === this.displayLevelForRule(rule)) optEl.selected = true;
      }
      select.addEventListener("change", async () => {
        setControlBusy(select, true);
        try {
          await this.handleRuleLevelChange(rule, select.value);
          new Notice("Permission updated.");
          await this.refresh();
        } catch (error) {
          new Notice(`Failed: ${(error as Error).message}`);
          setControlBusy(select, false);
        }
      });

      // Delete button
      const deleteBtn = levelEl.createEl("button", {
        cls: "vaultguard-icon-btn vaultguard-danger",
        attr: { "aria-label": "Remove", type: "button" },
      });
      setIcon(deleteBtn, "trash-2");
      deleteBtn.addEventListener("click", async () => {
        setButtonLoading(deleteBtn, true);
        try {
          await this.cfg.apiClient.deletePermission(rule.id);
          new Notice("Rule removed.");
          await this.refresh();
        } catch (error) {
          new Notice(`Failed: ${(error as Error).message}`);
          if (deleteBtn.isConnected) setButtonLoading(deleteBtn, false);
        }
      });
    } else {
      // Read-only badge
      const level = this.displayLevelForRule(rule);
      const badge = levelEl.createSpan({
        cls: `vaultguard-fh-badge vaultguard-fh-badge-${level}`,
      });
      badge.setText(this.formatLevel(level));
    }
  }

  // ─── Add Rule ──────────────────────────────────────────────────────

  private renderAddSection(): void {
    this.syncSelectedUserFromDraft();

    const section = this.contentEl.createDiv({ cls: "vaultguard-pp-section" });
    section.createDiv({ cls: "vaultguard-pp-section-title", text: "Add access" });

    const form = section.createDiv({ cls: "vaultguard-pp-add-form" });

    // Type
    const typeSelect = form.createEl("select", { cls: "vaultguard-pp-input" });
    typeSelect.createEl("option", { text: "User", attr: { value: "user" } });
    typeSelect.createEl("option", { text: "Role", attr: { value: "role" } });
    typeSelect.value = this.draftPrincipalType;

    // Principal
    const principalInput = form.createEl("input", {
      cls: "vaultguard-pp-input vaultguard-pp-input-principal",
      attr: {
        type: "text",
        placeholder: this.draftPrincipalType === "user"
          ? "Search teammates or enter a user ID"
          : "Role name",
      },
    }) as HTMLInputElement;
    principalInput.value = this.draftPrincipalValue;

    // Level
    const levelSelect = form.createEl("select", { cls: "vaultguard-pp-input" });
    levelSelect.createEl("option", { text: "Read", attr: { value: "read" } });
    levelSelect.createEl("option", { text: "Write", attr: { value: "write" } });
    levelSelect.createEl("option", { text: "Admin", attr: { value: "admin" } });
    // "No Access" creates a deny rule for the principal at this path. Useful
    // for revoking inherited access (e.g. blocking one user from a folder
    // their role can otherwise read). Same option as the existing-rule
    // dropdown so admins have one consistent way to express deny.
    levelSelect.createEl("option", { text: "No Access", attr: { value: "none" } });
    levelSelect.value = this.draftLevel;

    const addBtn = new ButtonComponent(form)
      .setButtonText("Add")
      .setCta();
    addBtn.buttonEl.type = "button";

    const quickListEl = section.createDiv({ cls: "vaultguard-access-picker" });

    const updateQuickList = (): void => {
      this.draftPrincipalType = typeSelect.value as "user" | "role";
      this.draftPrincipalValue = principalInput.value;
      this.draftLevel = levelSelect.value;
      this.syncSelectedUserFromDraft();
      principalInput.placeholder = this.draftPrincipalType === "user"
        ? "Search teammates or enter a user ID"
        : "Role name";

      quickListEl.empty();

      if (this.draftPrincipalType !== "user") {
        quickListEl.createDiv({
          cls: "vaultguard-access-picker-note",
          text: "Role rules apply to everyone assigned to that role.",
        });
        return;
      }

      quickListEl.createDiv({
        cls: "vaultguard-access-picker-note",
        text: "Quick add from your team directory",
      });

      if (this.usersLoading) {
        quickListEl.createDiv({
          cls: "vaultguard-access-picker-state",
          text: "Loading teammates...",
        });
        return;
      }

      if (this.usersLoadError) {
        quickListEl.createDiv({
          cls: "vaultguard-access-picker-state",
          text: "Team directory unavailable right now. You can still type a user ID.",
        });
        return;
      }

      const directoryUsers = this.users.filter((user) => user.status !== "revoked");
      if (directoryUsers.length === 0) {
        quickListEl.createDiv({
          cls: "vaultguard-access-picker-state",
          text: "No teammates found yet. Invite someone from the Users tab first.",
        });
        return;
      }

      const filteredUsers = directoryUsers
        .filter((user) => matchesAccessUserQuery(user, principalInput.value))
        .slice(0, 8);

      if (filteredUsers.length === 0) {
        quickListEl.createDiv({
          cls: "vaultguard-access-picker-state",
          text: "No matching teammates.",
        });
        return;
      }

      const existingLevels = this.existingExactDirectUserLevels();
      const listEl = quickListEl.createDiv({ cls: "vaultguard-access-picker-list" });

      for (const user of filteredUsers) {
        const existingLevel = existingLevels.get(user.id);
        const userBtn = listEl.createEl("button", {
          cls: "vaultguard-access-picker-item",
          attr: { type: "button" },
        });

        userBtn.classList.toggle("is-selected", this.draftSelectedUserId === user.id);
        userBtn.classList.toggle("is-disabled", Boolean(existingLevel));
        userBtn.disabled = Boolean(existingLevel);

        const avatarEl = userBtn.createDiv({ cls: "vaultguard-access-picker-avatar" });
        avatarEl.createSpan({ text: getAccessUserNameInitials(user) });

        const bodyEl = userBtn.createDiv({ cls: "vaultguard-access-picker-body" });
        bodyEl.createDiv({
          cls: "vaultguard-access-picker-name",
          text: getAccessUserDisplayName(user),
        });
        bodyEl.createDiv({
          cls: "vaultguard-access-picker-meta",
          text: getAccessUserMeta(user),
        });

        const pillEl = userBtn.createSpan({ cls: "vaultguard-access-picker-pill" });
        if (existingLevel) {
          pillEl.classList.add(`vaultguard-access-picker-pill-level-${existingLevel}`);
          pillEl.setText(`Has ${this.formatLevel(existingLevel)}`);
        } else if (user.status !== "active") {
          pillEl.setText(formatAccessUserStatus(user.status));
        } else {
          pillEl.setText(formatAccessUserRole(user.role));
        }

        if (!existingLevel) {
          userBtn.addEventListener("click", () => {
            this.draftSelectedUserId = user.id;
            this.draftPrincipalValue = getAccessUserPickerValue(user);
            principalInput.value = this.draftPrincipalValue;
            principalInput.focus();
            updateQuickList();
          });
        }
      }
    };

    const submitAddRule = async (): Promise<void> => {
      const principalType = typeSelect.value as "user" | "role";
      const rawPrincipalValue = principalInput.value.trim();
      const level = levelSelect.value;

      this.draftPrincipalType = principalType;
      this.draftPrincipalValue = principalInput.value;
      this.draftLevel = level;
      this.syncSelectedUserFromDraft();

      const principalId = principalType === "user"
        ? this.resolveDraftUserId(rawPrincipalValue)
        : rawPrincipalValue;

      if (!principalId) {
        new Notice("Please enter a user ID or role name.");
        return;
      }

      if (principalType === "user") {
        const existingLevel = this.existingExactDirectUserLevels().get(principalId);
        if (existingLevel) {
          new Notice(`${this.userLabel(principalId)} already has a direct rule for this path.`);
          return;
        }
      }

      setButtonLoading(addBtn.buttonEl, true, { label: "Adding" });

      try {
        const pathPattern = this.toRulePath(this.cfg.path);
        const principalLabel = principalType === "user" ? this.userLabel(principalId) : principalId;
        const canonicalUserId = principalType === "user" ? principalId : "*";
        const response = await this.cfg.apiClient.setPermissionLevel({
          userId: canonicalUserId,
          role: principalType === "role" ? principalId : null,
          pathPattern,
          level: level as "none" | "read" | "write" | "admin",
        });
        new Notice(
          level === "none"
            ? `Access blocked for ${principalLabel}.`
            : `Access granted to ${principalLabel}.`
        );
        this.draftPrincipalValue = "";
        this.draftSelectedUserId = null;
        // Optimistic patch — show the new row before refresh().
        if (response?.level && principalType === "user") {
          this.patchAccessSummaryPrincipalLevel(canonicalUserId, response.level);
          this.optimisticRender();
        }
        await this.refresh();
      } catch (error) {
        new Notice(`Failed: ${(error as Error).message}`);
      } finally {
        if (!this.isClosed && addBtn.buttonEl.isConnected) {
          setButtonLoading(addBtn.buttonEl, false);
        }
      }
    };

    typeSelect.addEventListener("change", () => {
      const nextType = typeSelect.value as "user" | "role";
      if (nextType !== this.draftPrincipalType) {
        this.draftPrincipalValue = "";
        principalInput.value = "";
      }
      if (nextType !== "user") {
        this.draftSelectedUserId = null;
      }
      updateQuickList();
    });

    principalInput.addEventListener("input", () => {
      updateQuickList();
    });

    principalInput.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        void submitAddRule();
      }
    });

    levelSelect.addEventListener("change", () => {
      this.draftLevel = levelSelect.value;
    });

    addBtn.onClick(() => {
      void submitAddRule();
    });

    updateQuickList();

    // Also offer the full rule editor for advanced use
    const advancedRow = section.createDiv({ cls: "vaultguard-pp-advanced" });
    advancedRow.createEl("button", {
      cls: "vaultguard-pp-advanced-btn",
      text: "Advanced rule editor...",
      attr: { type: "button" },
    }).addEventListener("click", () => {
      const rulePath = this.toRulePath(this.cfg.path);
      this.permissionEditor.showAddRuleForPath(rulePath, async () => {
        await this.refresh();
      });
    });
  }

  // ─── Refresh ───────────────────────────────────────────────────────

  private async handleRuleLevelChange(rule: PermissionRule, newLevel: string): Promise<void> {
    // See file-permission-header for the architectural rationale — the
    // server picks the right (delete/cap/grant) shape from (target,
    // inherited). The client never has to know the principal's inherited
    // level to land them on the desired effective level.
    const canonicalUserId = rule.role ? "*" : this.resolveCanonicalUserId(rule.userId);
    const response = await this.cfg.apiClient.setPermissionLevel({
      userId: canonicalUserId,
      role: rule.role ?? null,
      pathPattern: this.toRulePath(this.cfg.path),
      level: newLevel as "none" | "read" | "write" | "admin",
    });
    // Optimistic patch — see file-permission-panel.handleLevelChange for
    // the rationale. The refresh() that fires in the dropdown's outer
    // handler reconciles against the server within one round-trip.
    if (response?.level && !rule.role) {
      this.patchAccessSummaryPrincipalLevel(canonicalUserId, response.level);
      this.optimisticRender();
    }
  }

  private async handleAccessPrincipalLevelChange(
    principal: PathAccessPrincipal,
    newLevel: string
  ): Promise<void> {
    const canonicalUserId = this.resolveCanonicalUserId(principal.userId);
    const response = await this.cfg.apiClient.setPermissionLevel({
      userId: canonicalUserId,
      role: null,
      pathPattern: this.toRulePath(this.cfg.path),
      level: newLevel as "none" | "read" | "write" | "admin",
    });
    if (response?.level) {
      this.patchAccessSummaryPrincipalLevel(canonicalUserId, response.level);
      this.optimisticRender();
    }
  }

  /**
   * Best-effort re-render after an optimistic patch. No-op when the modal
   * isn't mounted (tests using Object.create skip the constructor). The
   * authoritative render still fires through refresh() right after, so a
   * skipped optimistic render only loses the instant-flip, not correctness.
   */
  private optimisticRender(): void {
    if (this.isClosed) return;
    // PanelFakeElement (used in tests) lacks `parentNode` / `isConnected`,
    // so we look for the real-DOM-only `appendChild` to gate.
    const contentEl = this.contentEl as unknown as { appendChild?: unknown };
    if (typeof contentEl?.appendChild !== "function") return;
    this.render();
  }

  /**
   * Records a set-level write and reflects it in the cached path access
   * summary so the row updates immediately. The same value is parked in
   * `pendingLevelPatches` so subsequent refreshes — which may briefly read
   * a stale GSI view — keep showing the user the level the server
   * confirmed, not the stale read. Once the server's next refresh agrees,
   * the patch self-clears.
   */
  private patchAccessSummaryPrincipalLevel(
    canonicalUserId: string,
    level: "none" | "read" | "write" | "admin"
  ): void {
    if (!this.pendingLevelPatches) this.pendingLevelPatches = new Map();
    this.pendingLevelPatches.set(canonicalUserId, level);
    if (!this.accessSummary) return;
    this.reconcilePendingLevelPatches();
  }

  private async refresh(): Promise<void> {
    try {
      this.accessSummary = await this.cfg.apiClient.getPathAccess(this.cfg.path).catch(() => this.accessSummary);
      // Post-write read consistency: rules live in DDB tables that publish
      // to GSIs eventually (typically <1s, occasionally longer). A refresh
      // fired immediately after a set-level write can read the stale view
      // and flip the chip back to its prior state — exactly the bug users
      // keep reporting. We re-apply any patches that haven't been confirmed
      // by the server yet, and drop a patch as soon as the server's view
      // matches it (self-healing without TTL guesswork).
      this.reconcilePendingLevelPatches();
      this.currentUserLevel = this.accessSummary?.currentUserLevel ?? this.currentUserLevel;
      this.mergeAccessSummaryIntoDirectory();
      this.canManage = this.cfg.isAdmin || this.currentUserLevel === "admin";
      this.rules = this.canManage
        ? await this.cfg.apiClient.getPermissions(this.cfg.path).catch(() => [])
        : [];
      this.permissionsLoaded = true;
      this.render();
      this.cfg.onRulesChanged?.();
    } catch (error) {
      this.renderError((error as Error).message);
    }
  }

  /**
   * Tracks set-level results that the GSI may not have surfaced yet. Each
   * entry is removed once a subsequent `getPathAccess` confirms it (the
   * server's read view caught up). Until then, the entry overrides what the
   * server returns for that principal, so the chip stays on the value the
   * write produced rather than flipping back to a stale read.
   */
  private pendingLevelPatches = new Map<string, "none" | "read" | "write" | "admin">();

  private reconcilePendingLevelPatches(): void {
    if (!this.accessSummary) return;
    if (!this.pendingLevelPatches) this.pendingLevelPatches = new Map();

    // Drop any patch the server now agrees with.
    for (const [userId, level] of [...this.pendingLevelPatches]) {
      const principal = this.accessSummary.principals.find(
        (p) => this.resolveCanonicalUserId(p.userId) === userId
      );
      if (principal && principal.level === level) {
        this.pendingLevelPatches.delete(userId);
      }
    }

    if (this.pendingLevelPatches.size === 0) return;

    // Re-apply remaining patches against the freshly fetched summary.
    const principals = this.accessSummary.principals.map((p) => {
      const patched = this.pendingLevelPatches.get(this.resolveCanonicalUserId(p.userId));
      return patched ? { ...p, level: patched } : p;
    });

    // Seed principals the server hasn't enumerated yet (e.g. just-added rows).
    for (const [userId, level] of this.pendingLevelPatches) {
      if (level === "none") continue;
      const exists = principals.some(
        (p) => this.resolveCanonicalUserId(p.userId) === userId
      );
      if (!exists) principals.push({ userId, level });
    }

    this.accessSummary = { ...this.accessSummary, principals };
  }

  private async loadUsers(): Promise<void> {
    try {
      const users = await this.cfg.apiClient.listUsers();
      if (this.isClosed) return;

      this.users = sortAccessUsers(users);
      this.userMap = buildAccessUserMap(this.users);
      this.usersLoadError = null;
    } catch (error) {
      if (this.isClosed) return;
      this.usersLoadError = (error as Error).message;
    } finally {
      this.usersLoading = false;
      if (!this.isClosed && this.permissionsLoaded) {
        this.render();
      }
    }
  }

  // ─── Helpers ───────────────────────────────────────────────────────

  private toRulePath(path: string): string {
    let p = path;
    if (!p.startsWith("/")) p = "/" + p;
    if (this.cfg.isFolder && !p.endsWith("/")) p += "/";
    return p;
  }

  private resolveMyLevel(): string {
    if (this.cfg.currentUserRole === "admin" || this.cfg.currentUserRole === "owner") {
      return "admin";
    }
    if (this.currentUserLevel !== "none") {
      return this.currentUserLevel;
    }

    let bestLevel = "none";
    let bestSpecificity = -1;

    for (const rule of this.rules) {
      const applies =
        rule.userId === this.cfg.currentUserId ||
        rule.userId === "*" ||
        (rule.role && this.cfg.currentUserRole === rule.role);
      if (!applies) continue;

      const specificity = this.patternSpecificity(rule.pathPattern);
      if (specificity > bestSpecificity) {
        bestSpecificity = specificity;
        bestLevel = this.currentLevel(rule);
      } else if (specificity === bestSpecificity) {
        const level = this.currentLevel(rule);
        if (this.levelRank(level) > this.levelRank(bestLevel)) {
          bestLevel = level;
        }
      }
    }

    if (bestLevel === "none" && bestSpecificity === -1) {
      if (this.cfg.currentUserRole === "editor") return "write";
      return "read";
    }

    return bestLevel;
  }

  private principalLabel(rule: PermissionRule): string {
    if (rule.role) return `Role: ${rule.role}`;
    if (rule.userId === "*") return "Everyone";
    return this.userLabel(rule.userId);
  }

  private currentLevel(rule: PermissionRule): string {
    if (rule.effect === "deny") return this.deniedActionsCapLevel(rule.actions);
    if (rule.actions.includes("admin")) return "admin";
    if (rule.actions.includes("write") || rule.actions.includes("delete")) return "write";
    if (rule.actions.includes("read")) return "read";
    return "none";
  }

  /**
   * Backend-computed effective level for this rule's principal on the modal's
   * current path. Returns null when no access summary is available or the
   * rule targets a role/wildcard that the effective list does not enumerate.
   * Mirrors the helper in file-permission-panel.ts so the three UI surfaces
   * make the same downgrade-vs-upgrade decision from the same input.
   */
  private effectiveLevelForRulePrincipal(rule: PermissionRule): string | null {
    const principals = this.accessSummary?.principals;
    if (!principals || principals.length === 0) return null;
    if (rule.role || rule.userId === "*") return null;

    const canonicalUserId = this.resolveCanonicalUserId(rule.userId);
    const principal = principals.find((entry) =>
      this.resolveCanonicalUserId(entry.userId) === canonicalUserId
    );
    return principal ? principal.level : null;
  }

  private displayLevelForRule(rule: PermissionRule): string {
    let level = this.currentLevel(rule);
    if (rule.effect === "deny" || rule.role || rule.userId === "*" || !this.ruleTargetsCurrentPath(rule)) {
      return level;
    }

    const canonicalUserId = this.resolveCanonicalUserId(rule.userId);
    for (const candidate of this.rules) {
      if (candidate === rule || candidate.role || candidate.userId === "*") continue;
      if (this.ruleTargetsCurrentPath(candidate)) continue;
      if (this.resolveCanonicalUserId(candidate.userId) !== canonicalUserId) continue;

      const candidateLevel = this.currentLevel(candidate);
      if (this.levelRank(candidateLevel) > this.levelRank(level)) {
        level = candidateLevel;
      }
    }

    return level;
  }

  private formatLevel(level: string): string {
    switch (level) {
      case "admin": return "Admin";
      case "write": return "Write";
      case "read": return "Read";
      default: return "No Access";
    }
  }

  private levelToActions(level: string): PermissionMutationInput["actions"] {
    switch (level) {
      case "admin": return ["read", "write", "delete", "admin", "list"];
      case "write": return ["read", "write", "delete", "list"];
      case "read": return ["read", "list"];
      default: return ["read", "list"];
    }
  }

  /**
   * Identical-by-construction with the helpers in file-permission-header.ts
   * and file-permission-panel.ts so all three UI surfaces persist the same
   * rule shape for the same transition. See the header for the full
   * rationale; the downgrade branch covers every downgrade (admin→write,
   * admin→read, write→read) via a deny cap that strips the actions above
   * `level` while leaving lower actions to inheritance.
   */
  private buildLevelMutation(
    level: string,
    previousLevel: string = "none"
  ): Pick<PermissionMutationInput, "actions" | "effect"> {
    if (level === "none") {
      return {
        actions: ["read", "write", "delete", "admin", "list"],
        effect: "deny",
      };
    }

    const targetRank = this.levelRank(level);
    const previousRank = this.levelRank(previousLevel);

    if (targetRank < previousRank) {
      // See file-permission-header.ts for the ordering rationale.
      const denyActions: PermissionMutationInput["actions"] = [];
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

  private ruleLevelString(rule: PermissionRule): string {
    if (rule.actions.includes("admin")) return "admin";
    if (rule.actions.includes("write") || rule.actions.includes("delete")) return "write";
    if (rule.actions.includes("read")) return "read";
    return "none";
  }

  private ruleLevelRank(rule: PermissionRule): number {
    if (rule.effect === "deny") return this.levelRank(this.deniedActionsCapLevel(rule.actions));
    if (rule.actions.includes("admin")) return 3;
    if (rule.actions.includes("write")) return 2;
    if (rule.actions.includes("read")) return 1;
    return 0;
  }

  private userLabel(userId: string): string {
    const user = this.userMap.get(userId);
    return user ? getAccessUserDisplayName(user) : userId;
  }

  private accessPrincipalLabel(principal: PathAccessPrincipal): string {
    return principal.displayName || principal.email || this.userLabel(principal.userId);
  }

  private normalizeAccessPrincipals(principals: PathAccessPrincipal[]): PathAccessPrincipal[] {
    const byKey = new Map<string, PathAccessPrincipal>();

    for (const principal of principals) {
      const canonicalUserId = this.resolveCanonicalUserId(principal.userId);
      const email = principal.email?.trim().toLowerCase();
      const key = email || canonicalUserId;
      const normalized = { ...principal, userId: canonicalUserId };
      const existing = byKey.get(key);
      if (!existing || this.levelRank(normalized.level) > this.levelRank(existing.level)) {
        byKey.set(key, normalized);
      }
    }

    return [...byKey.values()];
  }

  private canEditAccessPrincipal(principal: PathAccessPrincipal): boolean {
    if (!this.canManage) return false;
    if (principal.userId === this.cfg.currentUserId) return false;
    // Vault admins/owners bypass per-file deny rules server-side
    // (utils.ts: rolesIncludeOrgAdmin → unconditional allowed=true), so any
    // attempted downgrade is a no-op that confuses the user — the chip
    // would flicker to the target level and snap back to admin on refresh.
    // Hide the dropdown and let the static "Admin" badge stand instead. The
    // server enforces the same constraint with a 400 if a request slips
    // through (e.g. via the legacy raw-rule editor).
    const targetRole = principal.role?.toLowerCase();
    if (!this.cfg.allowAdminPerFileRestrictions && targetRole === "admin") return false;
    return true;
  }

  private existingExactDirectUserLevels(): Map<string, string> {
    const levels = new Map<string, string>();

    for (const rule of this.rules) {
      if (rule.role || rule.userId === "*") continue;
      if (!this.ruleTargetsCurrentPath(rule)) continue;

      const level = this.currentLevel(rule);
      const existingLevel = levels.get(rule.userId);

      if (!existingLevel || this.levelRank(level) >= this.levelRank(existingLevel)) {
        levels.set(rule.userId, level);
      }
    }

    return levels;
  }

  private ruleTargetsCurrentPath(rule: PermissionRule): boolean {
    return this.normalizeRulePath(rule.pathPattern) === this.normalizeRulePath(this.toRulePath(this.cfg.path));
  }

  private findExactRuleForPrincipal(sourceRule: PermissionRule): PermissionRule | null {
    return this.rules.find((rule) => {
      if (!this.ruleTargetsCurrentPath(rule)) return false;
      if (sourceRule.role) return rule.role === sourceRule.role;
      return !rule.role &&
        this.resolveCanonicalUserId(rule.userId) === this.resolveCanonicalUserId(sourceRule.userId);
    }) ?? null;
  }

  private findExactUserRuleForCurrentPath(userId: string): PermissionRule | null {
    const canonicalUserId = this.resolveCanonicalUserId(userId);
    return this.rules.find((rule) =>
      !rule.role &&
      this.resolveCanonicalUserId(rule.userId) === canonicalUserId &&
      this.ruleTargetsCurrentPath(rule)
    ) ?? null;
  }

  private rawRulesForDisplay(): PermissionRule[] {
    const exactDirectUsers = new Set<string>();
    for (const rule of this.rules) {
      if (rule.role || rule.userId === "*" || !this.ruleTargetsCurrentPath(rule)) continue;
      exactDirectUsers.add(this.resolveCanonicalUserId(rule.userId));
    }

    if (exactDirectUsers.size === 0) return [...this.rules];

    return this.rules.filter((rule) => {
      if (rule.role || rule.userId === "*") return true;
      if (this.ruleTargetsCurrentPath(rule)) return true;
      return !exactDirectUsers.has(this.resolveCanonicalUserId(rule.userId));
    });
  }

  private normalizeRulePath(path: string): string {
    return path.replace(/^\/+/, "").replace(/\/+$/, "");
  }

  private resolveCanonicalUserId(userId: string): string {
    return resolveAccessUserId(this.users, userId);
  }

  private mergeAccessSummaryIntoDirectory(): void {
    const principals = this.accessSummary?.principals ?? [];
    if (principals.length === 0) return;

    const knownIds = new Set(this.users.map((user) => user.id));
    const additions: UserListEntry[] = [];

    for (const principal of principals) {
      if (knownIds.has(principal.userId)) continue;
      if (!principal.displayName && !principal.email) continue;

      additions.push({
        id: principal.userId,
        email: principal.email ?? "",
        displayName: principal.displayName ?? principal.email ?? principal.userId,
        name: principal.displayName ?? principal.email ?? principal.userId,
        role: this.mapVaultRoleToUserRole(principal.role),
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

  private mapVaultRoleToUserRole(role?: string): UserListEntry["role"] {
    switch (role) {
      case "admin": return "admin";
      case "editor": return "editor";
      case "viewer": return "viewer";
      default: return "custom";
    }
  }

  private syncSelectedUserFromDraft(): void {
    if (this.draftPrincipalType !== "user") {
      this.draftSelectedUserId = null;
      return;
    }

    const selectedUser = this.draftSelectedUserId
      ? this.userMap.get(this.draftSelectedUserId) ?? null
      : null;

    if (
      selectedUser &&
      this.normalizeValue(this.draftPrincipalValue) ===
        this.normalizeValue(getAccessUserPickerValue(selectedUser))
    ) {
      return;
    }

    this.draftSelectedUserId = findExactAccessUserMatch(this.users, this.draftPrincipalValue)?.id ?? null;
  }

  private resolveDraftUserId(rawValue: string): string {
    const selectedUser = this.draftSelectedUserId
      ? this.userMap.get(this.draftSelectedUserId) ?? null
      : null;

    if (
      selectedUser &&
      this.normalizeValue(rawValue) === this.normalizeValue(getAccessUserPickerValue(selectedUser))
    ) {
      return selectedUser.id;
    }

    return resolveAccessUserId(this.users, rawValue);
  }

  private normalizeValue(value: string): string {
    return value.trim().toLowerCase();
  }

  private levelRank(level: string): number {
    switch (level) {
      case "admin": return 3;
      case "write": return 2;
      case "read": return 1;
      default: return 0;
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

  private initials(name: string): string {
    if (name === "*") return "*";
    return getAccessUserInitials(name);
  }

  private userInitials(userId: string): string {
    if (userId === "*") return "*";
    const user = this.userMap.get(userId);
    return user ? getAccessUserNameInitials(user) : this.initials(userId);
  }

  private deniedActionsCapLevel(actions: PermissionRule["actions"]): string {
    if (actions.includes("read") || actions.includes("list")) return "none";
    if (actions.includes("write") || actions.includes("delete")) return "read";
    if (actions.includes("admin")) return "write";
    return "none";
  }
}
