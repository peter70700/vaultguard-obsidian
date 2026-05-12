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
  private permissionEditor: PermissionEditor;

  constructor(cfg: PathPermissionsConfig) {
    super(cfg.app);
    this.cfg = cfg;
    this.permissionEditor = new PermissionEditor(cfg.app, cfg.apiClient);
    this.usersLoading = cfg.isAdmin;
  }

  async onOpen(): Promise<void> {
    this.isClosed = false;
    this.permissionsLoaded = false;
    this.modalEl.addClass("vaultguard-path-perms-modal");
    this.contentEl.addClass("vaultguard-path-perms-content");
    this.renderLoading();

    if (this.cfg.isAdmin) {
      void this.loadUsers();
    }

    try {
      this.rules = await this.cfg.apiClient.getPermissions(this.cfg.path);
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
    if (this.cfg.isAdmin) {
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

    if (this.rules.length === 0) {
      listEl.createDiv({
        cls: "vaultguard-pp-empty",
        text: "No explicit permission rules. Access is based on default role permissions.",
      });
      return;
    }

    // Sort: highest level first, then by principal
    const sorted = [...this.rules].sort((a, b) => {
      const la = this.ruleLevelRank(a);
      const lb = this.ruleLevelRank(b);
      if (la !== lb) return lb - la;
      return this.principalLabel(a).localeCompare(this.principalLabel(b));
    });

    for (const rule of sorted) {
      this.renderRuleRow(listEl, rule);
    }
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

    if (this.cfg.isAdmin) {
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
        if (opt.value === this.currentLevel(rule)) optEl.selected = true;
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
      const level = this.currentLevel(rule);
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
        const input: PermissionMutationInput = {
          pathPattern,
          ...this.buildLevelMutation(level),
          userId: principalType === "user" ? principalId : "*",
          role: principalType === "role" ? principalId : null,
        };

        await this.cfg.apiClient.createPermission(input);
        new Notice(
          level === "none"
            ? `Access blocked for ${principalLabel}.`
            : `Access granted to ${principalLabel}.`
        );
        this.draftPrincipalValue = "";
        this.draftSelectedUserId = null;
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
    const mutation = this.buildLevelMutation(newLevel);
    const exactRule = this.ruleTargetsCurrentPath(rule)
      ? rule
      : this.findExactRuleForPrincipal(rule);

    if (exactRule) {
      await this.cfg.apiClient.updatePermission(exactRule.id, {
        pathPattern: exactRule.pathPattern,
        ...mutation,
      });
      return;
    }

    await this.cfg.apiClient.createPermission({
      pathPattern: this.toRulePath(this.cfg.path),
      ...mutation,
      userId: rule.role ? "*" : this.resolveCanonicalUserId(rule.userId),
      role: rule.role ?? null,
    });
  }

  private async refresh(): Promise<void> {
    try {
      this.rules = await this.cfg.apiClient.getPermissions(this.cfg.path);
      this.permissionsLoaded = true;
      this.render();
      this.cfg.onRulesChanged?.();
    } catch (error) {
      this.renderError((error as Error).message);
    }
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
        bestLevel = rule.effect === "deny" ? "none" : this.ruleLevelString(rule);
      } else if (specificity === bestSpecificity) {
        const level = rule.effect === "deny" ? "none" : this.ruleLevelString(rule);
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
    if (rule.effect === "deny") return "none";
    if (rule.actions.includes("admin")) return "admin";
    if (rule.actions.includes("write") || rule.actions.includes("delete")) return "write";
    if (rule.actions.includes("read")) return "read";
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

  private levelToActions(level: string): PermissionMutationInput["actions"] {
    switch (level) {
      case "admin": return ["read", "write", "delete", "admin", "list"];
      case "write": return ["read", "write", "delete", "list"];
      case "read": return ["read", "list"];
      default: return ["read", "list"];
    }
  }

  private buildLevelMutation(level: string): Pick<PermissionMutationInput, "actions" | "effect"> {
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

  private ruleLevelString(rule: PermissionRule): string {
    if (rule.actions.includes("admin")) return "admin";
    if (rule.actions.includes("write") || rule.actions.includes("delete")) return "write";
    if (rule.actions.includes("read")) return "read";
    return "none";
  }

  private ruleLevelRank(rule: PermissionRule): number {
    if (rule.effect === "deny") return -1;
    if (rule.actions.includes("admin")) return 3;
    if (rule.actions.includes("write")) return 2;
    if (rule.actions.includes("read")) return 1;
    return 0;
  }

  private userLabel(userId: string): string {
    const user = this.userMap.get(userId);
    return user ? getAccessUserDisplayName(user) : userId;
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

  private normalizeRulePath(path: string): string {
    return path.replace(/^\/+/, "").replace(/\/+$/, "");
  }

  private resolveCanonicalUserId(userId: string): string {
    return resolveAccessUserId(this.users, userId);
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
}
