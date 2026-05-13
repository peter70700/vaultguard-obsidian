/**
 * File Permission Panel — dropdown panel anchored below the file header
 * for viewing and managing per-file permissions (ClickUp-style).
 *
 * Admin users see full CRUD controls; non-admins see a read-only summary.
 */

import { App, TFile, Notice, setIcon } from "obsidian";
import {
  VaultGuardApiClient,
  PermissionRule,
  PermissionMutationInput,
  UserListEntry,
} from "../api/client";
import { setButtonLoading, setControlBusy } from "./loading-button";
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

export interface FilePermissionPanelConfig {
  app: App;
  apiClient: VaultGuardApiClient;
  file: TFile;
  rules: PermissionRule[];
  isAdmin: boolean;
  currentUserId: string;
  anchorEl: HTMLElement;
  initialUsers?: UserListEntry[];
  onRulesChanged: () => Promise<void>;
  onClose: () => void;
}

const PANEL_CLS = "vaultguard-fp-panel";

export class FilePermissionPanel {
  private cfg: FilePermissionPanelConfig;
  private panelEl: HTMLElement;
  private backdropEl: HTMLElement;
  private rules: PermissionRule[];
  private users: UserListEntry[] = [];
  private userMap: Map<string, UserListEntry> = new Map();
  private usersLoading = false;
  private usersLoadError: string | null = null;
  private draftPrincipalType: "user" | "role" = "user";
  private draftPrincipalValue = "";
  private draftSelectedUserId: string | null = null;
  private draftLevel = "write";
  private isDestroyed = false;
  private readonly handleViewportChange = () => this.positionPanel();
  private readonly handleKeyDown = (event: KeyboardEvent) => {
    if (event.key === "Escape") {
      this.destroy();
    }
  };

  constructor(cfg: FilePermissionPanelConfig) {
    this.cfg = cfg;
    this.rules = [...cfg.rules];
    this.users = sortAccessUsers(cfg.initialUsers ?? []);
    this.userMap = buildAccessUserMap(this.users);
    this.usersLoading = cfg.isAdmin;

    // Floating backdrop keeps outside-click handling simple while the panel
    // itself is rendered above it in the document body.
    this.backdropEl = document.body.createDiv({ cls: "vaultguard-fp-backdrop" });
    this.backdropEl.addEventListener("click", () => this.destroy());

    // Render the panel into the body so it is not trapped inside the header's
    // stacking context. This keeps the menu clickable.
    this.panelEl = document.body.createDiv({ cls: PANEL_CLS });
    this.render();
    this.positionPanel();

    window.addEventListener("resize", this.handleViewportChange);
    window.addEventListener("scroll", this.handleViewportChange, true);
    document.addEventListener("keydown", this.handleKeyDown);

    if (this.cfg.isAdmin) {
      void this.loadUsers();
    }
  }

  destroy(): void {
    if (this.isDestroyed) return;
    this.isDestroyed = true;

    window.removeEventListener("resize", this.handleViewportChange);
    window.removeEventListener("scroll", this.handleViewportChange, true);
    document.removeEventListener("keydown", this.handleKeyDown);

    this.panelEl.remove();
    this.backdropEl.remove();
    this.cfg.onClose();
  }

  setRules(rules: PermissionRule[]): void {
    this.rules = [...rules];
    this.render();
    this.positionPanel();
  }

  // ─── Rendering ─────────────────────────────────────────────────────

  private render(): void {
    this.panelEl.empty();

    // Panel header
    const header = this.panelEl.createDiv({ cls: "vaultguard-fp-header" });
    header.createEl("h4", {
      text: this.cfg.isAdmin ? "Manage Access" : "Who Has Access",
    });
    const closeBtn = header.createEl("button", {
      cls: "vaultguard-icon-btn",
      attr: { type: "button" },
    });
    setIcon(closeBtn, "x");
    closeBtn.addEventListener("click", () => this.destroy());

    // File path context
    this.panelEl.createDiv({
      cls: "vaultguard-fp-filepath",
      text: this.cfg.file.path,
    });

    // Divider
    this.panelEl.createEl("hr", { cls: "vaultguard-fp-divider" });

    // Rules list
    const listEl = this.panelEl.createDiv({ cls: "vaultguard-fp-list" });
    this.renderRuleList(listEl);

    // Admin: add rule section
    if (this.cfg.isAdmin) {
      this.panelEl.createEl("hr", { cls: "vaultguard-fp-divider" });
      this.renderAddRuleSection(this.panelEl);
    }
  }

  private renderRuleList(container: HTMLElement): void {
    if (this.rules.length === 0) {
      container.createDiv({
        cls: "vaultguard-fp-empty",
        text: "No permission rules for this file. Access is based on default role permissions.",
      });
      return;
    }

    // Sort: admins first, then by principal
    const sorted = [...this.rules].sort((a, b) => {
      const la = this.ruleLevelRank(a);
      const lb = this.ruleLevelRank(b);
      if (la !== lb) return lb - la;
      return this.principalLabel(a).localeCompare(this.principalLabel(b));
    });

    for (const rule of sorted) {
      this.renderRuleRow(container, rule);
    }
  }

  private renderRuleRow(container: HTMLElement, rule: PermissionRule): void {
    const row = container.createDiv({ cls: "vaultguard-fp-row" });

    // Avatar / icon
    const avatarEl = row.createDiv({ cls: "vaultguard-fp-row-avatar" });
    if (rule.role) {
      setIcon(avatarEl, "users");
    } else if (rule.userId === "*") {
      setIcon(avatarEl, "globe");
    } else {
      avatarEl.createSpan({
        cls: "vaultguard-fp-row-initials",
        text: this.userInitials(rule.userId),
      });
    }

    // Name + info
    const infoEl = row.createDiv({ cls: "vaultguard-fp-row-info" });
    infoEl.createDiv({
      cls: "vaultguard-fp-row-name",
      text: this.principalLabel(rule),
    });

    const meta: string[] = [];
    if (rule.effect === "deny") meta.push("Denied");
    meta.push(rule.pathPattern);
    infoEl.createDiv({
      cls: "vaultguard-fp-row-meta",
      text: meta.join(" - "),
    });

    // Level badge or dropdown
    const levelEl = row.createDiv({ cls: "vaultguard-fp-row-level" });

    if (this.cfg.isAdmin) {
      const select = levelEl.createEl("select", { cls: "vaultguard-fp-level-select" });
      const options: { value: string; label: string }[] = [
        { value: "admin", label: "Admin" },
        { value: "write", label: "Write" },
        { value: "read", label: "Read" },
        { value: "none", label: "No Access" },
      ];
      for (const opt of options) {
        const optEl = select.createEl("option", { text: opt.label, attr: { value: opt.value } });
        if (opt.value === this.currentLevel(rule)) {
          optEl.selected = true;
        }
      }
      select.addEventListener("change", async () => {
        setControlBusy(select, true);
        try {
          await this.handleLevelChange(rule, select.value);
        } finally {
          if (!this.isDestroyed) setControlBusy(select, false);
        }
      });

      // Delete button
      const deleteBtn = levelEl.createEl("button", {
        cls: "vaultguard-icon-btn vaultguard-danger",
        attr: { "aria-label": "Remove rule", type: "button" },
      });
      setIcon(deleteBtn, "trash-2");
      deleteBtn.addEventListener("click", async () => {
        setButtonLoading(deleteBtn, true);
        try {
          await this.handleDeleteRule(rule);
        } finally {
          if (!this.isDestroyed && deleteBtn.isConnected) {
            setButtonLoading(deleteBtn, false);
          }
        }
      });
    } else {
      const badge = levelEl.createSpan({
        cls: `vaultguard-fh-badge vaultguard-fh-badge-${this.currentLevel(rule)}`,
      });
      badge.setText(this.formatLevel(this.currentLevel(rule)));
    }
  }

  // ─── Add Rule ──────────────────────────────────────────────────────

  private renderAddRuleSection(container: HTMLElement): void {
    this.syncSelectedUserFromDraft();

    const section = container.createDiv({ cls: "vaultguard-fp-add" });
    section.createDiv({ cls: "vaultguard-fp-add-title", text: "Add access" });

    const form = section.createDiv({ cls: "vaultguard-fp-add-form" });

    // Type selector
    const typeSelect = form.createEl("select", { cls: "vaultguard-fp-add-input" });
    typeSelect.createEl("option", { text: "User", attr: { value: "user" } });
    typeSelect.createEl("option", { text: "Role", attr: { value: "role" } });
    typeSelect.value = this.draftPrincipalType;

    // Principal input
    const principalInput = form.createEl("input", {
      cls: "vaultguard-fp-add-input vaultguard-fp-add-principal",
      attr: {
        type: "text",
        placeholder: this.draftPrincipalType === "user"
          ? "Search teammates or enter a user ID"
          : "Role name",
      },
    }) as HTMLInputElement;
    principalInput.value = this.draftPrincipalValue;

    // Level selector
    const levelSelect = form.createEl("select", { cls: "vaultguard-fp-add-input" });
    levelSelect.createEl("option", { text: "Read", attr: { value: "read" } });
    levelSelect.createEl("option", { text: "Write", attr: { value: "write" } });
    levelSelect.createEl("option", { text: "Admin", attr: { value: "admin" } });
    // "No Access" creates a deny rule so admins can revoke inherited access
    // for one principal without removing them from the vault. Mirrors the
    // option already available in the existing-rule dropdown.
    levelSelect.createEl("option", { text: "No Access", attr: { value: "none" } });
    levelSelect.value = this.draftLevel;

    // Add button
    const addBtn = form.createEl("button", {
      cls: "vaultguard-fp-add-btn",
      attr: { type: "button" },
    });
    setIcon(addBtn, "plus");

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
          new Notice(`${this.userLabel(principalId)} already has a direct rule for this file.`);
          return;
        }
      }

      setButtonLoading(addBtn, true);

      try {
        const filePath = this.cfg.file.path;
        const pathPattern = filePath.startsWith("/") ? filePath : `/${filePath}`;
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
        await this.cfg.onRulesChanged();
      } catch (error) {
        new Notice(`Failed to add: ${(error as Error).message}`);
      } finally {
        if (!this.isDestroyed && addBtn.isConnected) {
          setButtonLoading(addBtn, false);
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

    addBtn.addEventListener("click", () => {
      void submitAddRule();
    });

    updateQuickList();
  }

  // ─── Handlers ──────────────────────────────────────────────────────

  private async handleLevelChange(rule: PermissionRule, newLevel: string): Promise<void> {
    try {
      const mutation = this.buildLevelMutation(newLevel);
      const exactRule = this.ruleTargetsCurrentPath(rule)
        ? rule
        : this.findExactRuleForPrincipal(rule);

      if (exactRule) {
        await this.cfg.apiClient.updatePermission(exactRule.id, {
          pathPattern: exactRule.pathPattern,
          ...mutation,
        });
      } else {
        await this.cfg.apiClient.createPermission({
          pathPattern: this.targetRulePath(),
          ...mutation,
          userId: rule.role ? "*" : this.resolveCanonicalUserId(rule.userId),
          role: rule.role ?? null,
        });
      }
      new Notice("Permission updated.");
      await this.cfg.onRulesChanged();
    } catch (error) {
      new Notice(`Failed to update: ${(error as Error).message}`);
    }
  }

  private async handleDeleteRule(rule: PermissionRule): Promise<void> {
    try {
      await this.cfg.apiClient.deletePermission(rule.id);
      new Notice("Permission rule removed.");
      await this.cfg.onRulesChanged();
    } catch (error) {
      new Notice(`Failed to delete: ${(error as Error).message}`);
    }
  }

  private async loadUsers(): Promise<void> {
    try {
      const users = await this.cfg.apiClient.listUsers();
      if (this.isDestroyed) return;

      this.users = sortAccessUsers(users);
      this.userMap = buildAccessUserMap(this.users);
      this.usersLoadError = null;
    } catch (error) {
      if (this.isDestroyed) return;
      this.usersLoadError = (error as Error).message;
    } finally {
      this.usersLoading = false;
      if (!this.isDestroyed) {
        this.render();
        this.positionPanel();
      }
    }
  }

  // ─── Helpers ───────────────────────────────────────────────────────

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

  private targetRulePath(): string {
    return this.cfg.file.path.startsWith("/") ? this.cfg.file.path : `/${this.cfg.file.path}`;
  }

  private ruleTargetsCurrentPath(rule: PermissionRule): boolean {
    return this.normalizeRulePath(rule.pathPattern) === this.normalizeRulePath(this.targetRulePath());
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

  private initials(name: string): string {
    if (name === "*") return "*";
    return getAccessUserInitials(name);
  }

  private userInitials(userId: string): string {
    if (userId === "*") return "*";
    const user = this.userMap.get(userId);
    return user ? getAccessUserNameInitials(user) : this.initials(userId);
  }

  private positionPanel(): void {
    if (!this.cfg.anchorEl.isConnected) {
      this.destroy();
      return;
    }

    const viewportMargin = 12;
    const gap = 8;
    const anchorRect = this.cfg.anchorEl.getBoundingClientRect();
    const availableWidth = Math.max(280, window.innerWidth - viewportMargin * 2);
    const panelWidth = Math.min(380, availableWidth);

    this.panelEl.style.width = `${panelWidth}px`;

    // Measure after width is applied so we can decide whether to place it
    // above or below the anchor based on available space.
    const panelHeight = this.panelEl.offsetHeight || 420;
    const preferredTop = anchorRect.bottom + gap;
    const availableBelow = window.innerHeight - preferredTop - viewportMargin;

    let top = preferredTop;
    if (availableBelow < Math.min(panelHeight, 220)) {
      top = Math.max(viewportMargin, anchorRect.top - panelHeight - gap);
    }

    const left = Math.max(
      viewportMargin,
      Math.min(anchorRect.right - panelWidth, window.innerWidth - panelWidth - viewportMargin)
    );
    const maxHeight = Math.max(220, window.innerHeight - top - viewportMargin);

    this.panelEl.style.top = `${top}px`;
    this.panelEl.style.left = `${left}px`;
    this.panelEl.style.maxHeight = `${maxHeight}px`;
  }
}
