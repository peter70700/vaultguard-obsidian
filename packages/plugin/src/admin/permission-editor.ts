import {
  App,
  Modal,
  Setting,
  TextComponent,
  ButtonComponent,
  Notice,
  TFolder,
  TFile,
  setIcon,
} from "obsidian";
import {
  PermissionMutationInput,
  PermissionRule,
  UserListEntry,
  VaultGuardApiClient,
  VaultMemberRecord,
} from "../api/client";

export type PermissionLevel = "none" | "read" | "write" | "admin";

type PrincipalType = "user" | "role";

interface PrincipalOption {
  id: string;
  label: string;
}

interface PrincipalTarget {
  userId: string;
  role: string | null;
}

const ROLE_OPTIONS: PrincipalOption[] = [
  { id: "viewer", label: "Viewer" },
  { id: "editor", label: "Editor" },
  { id: "admin", label: "Admin" },
];

export class PermissionEditor {
  private app: App;
  private apiClient: VaultGuardApiClient;

  constructor(app: App, apiClient: VaultGuardApiClient) {
    this.app = app;
    this.apiClient = apiClient;
  }

  /**
   * Opens the "Add Rule" dialog for creating a new permission rule.
   */
  async showAddRuleDialog(parentContainer: HTMLElement): Promise<void> {
    const modal = new PermissionRuleModal(this.app, this.apiClient, null, async () => {
      const event = new CustomEvent("vaultguard-refresh-permissions");
      parentContainer.dispatchEvent(event);
    });
    modal.open();
  }

  /**
   * Opens the "Edit Rule" dialog for an existing permission rule.
   */
  async showEditRuleDialog(parentContainer: HTMLElement, rule: PermissionRule): Promise<void> {
    const modal = new PermissionRuleModal(this.app, this.apiClient, rule, async () => {
      const event = new CustomEvent("vaultguard-refresh-permissions");
      parentContainer.dispatchEvent(event);
    });
    modal.open();
  }

  /**
   * Opens the "Add Rule" dialog pre-filled with a specific path.
   * Used by the file-explorer context menu.
   */
  showAddRuleForPath(path: string, onSave?: () => Promise<void>): void {
    const modal = new PermissionRuleModal(this.app, this.apiClient, null, async () => {
      if (onSave) await onSave();
    }, path);
    modal.open();
  }

  /**
   * Renders a preview of effective permissions for a given path.
   */
  async renderEffectivePermissions(container: HTMLElement, path: string): Promise<void> {
    container.empty();
    container.createDiv({
      cls: "vaultguard-empty-state",
      text: `Effective permission previews are not available for "${path}" with the current API.`,
    });
  }
}

/**
 * Modal for adding or editing a permission rule.
 * Provides path autocomplete, principal entry, and permission level mapping
 * to the backend's allow/deny action model.
 */
class PermissionRuleModal extends Modal {
  private apiClient: VaultGuardApiClient;
  private existingRule: PermissionRule | null;
  private onSave: () => Promise<void>;

  // Form state
  private selectedPath: string = "";
  private selectedPrincipalType: PrincipalType = "user";
  private selectedUserIds: string[] = ["*"];
  private selectedRoleId: string = ROLE_OPTIONS[0].id;
  private selectedLevel: PermissionLevel = "read";
  private selectedPriority: string = "";
  private userOptions: PrincipalOption[] = [];
  private userOptionsLoading: boolean = false;
  private userOptionsError: string | null = null;
  private userFilter: string = "";
  private isOpen: boolean = false;

  // UI references
  private saveButton: ButtonComponent | null = null;

  constructor(
    app: App,
    apiClient: VaultGuardApiClient,
    existingRule: PermissionRule | null,
    onSave: () => Promise<void>,
    initialPath?: string
  ) {
    super(app);
    this.apiClient = apiClient;
    this.existingRule = existingRule;
    this.onSave = onSave;

    if (initialPath) {
      this.selectedPath = initialPath;
    }

    if (existingRule) {
      this.selectedPath = existingRule.pathPattern;
      this.selectedPrincipalType = existingRule.role ? "role" : "user";
      this.selectedUserIds = existingRule.role ? ["*"] : [existingRule.userId || "*"];
      this.selectedRoleId = existingRule.role ?? ROLE_OPTIONS[0].id;
      this.selectedLevel = this.levelFromRule(existingRule);
      this.selectedPriority = String(existingRule.priority);
    }
  }

  onOpen(): void {
    this.isOpen = true;
    this.modalEl.addClass("vaultguard-permission-rule-modal");
    this.contentEl.addClass("vaultguard-dialog-content");
    this.renderModalContent();
    void this.loadPrincipalOptions();
  }

  private renderModalContent(): void {
    const { contentEl } = this;
    contentEl.empty();

    const title = this.existingRule ? "Edit Permission Rule" : "Add Permission Rule";
    contentEl.createEl("h3", { text: title });

    this.renderPathSelector(contentEl);
    this.renderPrincipalSelector(contentEl);
    this.renderLevelSelector(contentEl);
    this.renderPrioritySelector(contentEl);
    contentEl.createEl("p", {
      text: "No access blocks reading. Read only blocks editing by denying write/delete/admin. More specific child rules, priority ties, and admin bypass can still affect the final result.",
      cls: "setting-item-description",
    });

    // Action buttons
    const actionRow = contentEl.createDiv({ cls: "vaultguard-rule-actions" });
    new ButtonComponent(actionRow).setButtonText("Cancel").onClick(() => this.close());

    this.saveButton = new ButtonComponent(actionRow)
      .setButtonText(this.existingRule ? "Update Rule" : "Create Rule")
      .setCta()
      .onClick(() => this.handleSave());
  }

  onClose(): void {
    this.isOpen = false;
    this.modalEl.removeClass("vaultguard-permission-rule-modal");
    this.contentEl.removeClass("vaultguard-dialog-content");
    this.contentEl.empty();
  }

  private renderPathSelector(container: HTMLElement): void {
    const pathSetting = new Setting(container)
      .setName("Path")
      .setDesc("Select a folder or file path. Folder paths apply to their children.");

    pathSetting.addText((text) => {
      text
        .setValue(this.selectedPath)
        .setPlaceholder("e.g., projects/secret/ or notes/meeting.md")
        .onChange((value) => {
          this.selectedPath = value;
        });

      // Autocomplete from vault structure
      const inputEl = text.inputEl;
      inputEl.addClass("vaultguard-path-input");

      const suggestionsEl = container.createDiv({ cls: "vaultguard-path-suggestions" });
      suggestionsEl.hide();

      inputEl.addEventListener("input", () => {
        const value = inputEl.value;
        const suggestions = this.getPathSuggestions(value);
        this.renderPathSuggestions(suggestionsEl, suggestions, text);
      });

      inputEl.addEventListener("focus", () => {
        const value = inputEl.value;
        const suggestions = this.getPathSuggestions(value);
        this.renderPathSuggestions(suggestionsEl, suggestions, text);
      });

      inputEl.addEventListener("blur", () => {
        // Delay hiding to allow click events on suggestions
        window.setTimeout(() => {
          suggestionsEl.hide();
        }, 200);
      });
    });
  }

  private getPathSuggestions(query: string): string[] {
    const allPaths: string[] = [];
    const vault = this.app.vault;

    // Collect all folder paths
    const folders = vault.getAllLoadedFiles().filter((f) => f instanceof TFolder);
    for (const folder of folders) {
      if (folder.path !== "/") {
        allPaths.push(folder.path + "/");
      }
    }

    // Collect all file paths
    const files = vault.getAllLoadedFiles().filter((f) => f instanceof TFile);
    for (const file of files) {
      allPaths.push(file.path);
    }

    // Filter by query
    const lowerQuery = query.toLowerCase();
    return allPaths
      .filter((p) => p.toLowerCase().includes(lowerQuery))
      .sort()
      .slice(0, 20);
  }

  private renderPathSuggestions(
    container: HTMLElement,
    suggestions: string[],
    textComponent: TextComponent
  ): void {
    container.empty();
    if (suggestions.length === 0) {
      container.hide();
      return;
    }

    container.setCssStyles({ display: "block" });
    for (const path of suggestions) {
      const item = container.createDiv({ cls: "vaultguard-suggestion-item" });
      const iconSpan = item.createSpan({ cls: "vaultguard-suggestion-icon" });
      setIcon(iconSpan, path.endsWith("/") ? "folder" : "file");
      item.createSpan({ text: path });
      item.addEventListener("click", () => {
        this.selectedPath = path;
        textComponent.setValue(path);
        container.hide();
      });
    }
  }

  private renderPrincipalSelector(container: HTMLElement): void {
    new Setting(container)
      .setName("Principal type")
      .setDesc("Apply this access level to one user, all users, or a vault role")
      .addDropdown((dropdown) =>
        dropdown
          .addOption("user", "User")
          .addOption("role", "Role")
          .setValue(this.selectedPrincipalType)
          .onChange((value) => {
            this.selectedPrincipalType = value as PrincipalType;
            this.renderModalContent();
          })
      );

    if (this.selectedPrincipalType === "role") {
      this.renderRoleSelector(container);
      return;
    }

    this.renderUserSelector(container);
  }

  private renderUserSelector(container: HTMLElement): void {
    const desc = this.userOptionsLoading
      ? "Loading vault members..."
      : this.userOptionsError
        ? `Choose All users, or one or more specific users. User list failed to load: ${this.userOptionsError}`
        : "Choose All users, or select one or more specific users in this vault.";

    new Setting(container)
      .setName("Users / all users")
      .setDesc(desc);

    const picker = container.createDiv({ cls: "vaultguard-principal-picker" });
    const summaryEl = picker.createDiv({ cls: "vaultguard-principal-picker-summary" });
    const search = picker.createEl("input", {
      cls: "vaultguard-principal-picker-search",
      attr: { type: "search", placeholder: "Filter users..." },
    });
    search.value = this.userFilter;
    const listEl = picker.createDiv({ cls: "vaultguard-principal-picker-list" });

    const renderList = (): void => {
      summaryEl.setText(this.userSelectionSummary());
      this.renderUserCheckboxRows(listEl);
    };

    search.addEventListener("input", () => {
      this.userFilter = search.value;
      renderList();
    });

    renderList();
  }

  private renderRoleSelector(container: HTMLElement): void {
    new Setting(container)
      .setName("Vault role")
      .setDesc("Apply this access level to everyone with the selected vault role.")
      .addDropdown((dropdown) => {
        for (const option of ROLE_OPTIONS) {
          dropdown.addOption(option.id, option.label);
        }
        if (!ROLE_OPTIONS.some((option) => option.id === this.selectedRoleId)) {
          dropdown.addOption(this.selectedRoleId, `${this.selectedRoleId} (custom role)`);
        }
        dropdown.setValue(this.selectedRoleId).onChange((value) => {
          this.selectedRoleId = value;
        });
      });
  }

  private async loadPrincipalOptions(): Promise<void> {
    this.userOptionsLoading = true;
    this.userOptionsError = null;
    if (this.isOpen) this.renderModalContent();

    try {
      const usersPromise = this.apiClient.listUsers().catch(() => [] as UserListEntry[]);
      const vaultId = this.apiClient.getVaultId();
      const membersPromise = vaultId
        ? this.apiClient.listVaultMembers(vaultId).then(
            (members) => members,
            () => null
          )
        : Promise.resolve(null);
      const [users, members] = await Promise.all([usersPromise, membersPromise]);
      this.userOptions = this.buildUserOptions(users, members);
    } catch (error) {
      this.userOptions = [];
      this.userOptionsError = error instanceof Error ? error.message : String(error);
    } finally {
      this.userOptionsLoading = false;
      if (this.isOpen) this.renderModalContent();
    }
  }

  private buildUserOptions(users: UserListEntry[], members: VaultMemberRecord[] | null): PrincipalOption[] {
    const usersById = new Map(users.map((user) => [user.id, user]));
    const source = members && members.length > 0
      ? members.map((member) => {
          const user = usersById.get(member.userId);
          return {
            id: member.userId,
            label: this.formatUserOptionLabel({
              id: member.userId,
              displayName: member.displayName ?? user?.displayName,
              email: member.email ?? user?.email,
              role: member.role,
            }),
          };
        })
      : users.map((user) => ({
          id: user.id,
          label: this.formatUserOptionLabel({
            id: user.id,
            displayName: user.displayName,
            email: user.email,
            role: user.role,
          }),
        }));

    return source
      .filter((option) => option.id && option.id !== "*")
      .sort((a, b) => a.label.localeCompare(b.label));
  }

  private formatUserOptionLabel(user: {
    id: string;
    displayName?: string;
    email?: string;
    role?: string;
  }): string {
    const name = user.displayName || user.email || user.id;
    const secondary = user.email && user.email !== name ? ` (${user.email})` : "";
    const role = user.role ? ` - ${user.role}` : "";
    return `${name}${secondary}${role}`;
  }

  private renderUserCheckboxRows(container: HTMLElement): void {
    container.empty();

    this.renderUserCheckboxRow(container, {
      id: "*",
      label: "All users",
      checked: this.selectedUserIds.includes("*"),
      onChange: (checked) => {
        this.selectedUserIds = checked ? ["*"] : [];
      },
    });

    const options = this.filteredUserOptions();
    if (options.length === 0) {
      container.createDiv({
        cls: "vaultguard-principal-picker-empty",
        text: this.userOptionsLoading ? "Loading users..." : "No users match this filter.",
      });
      return;
    }

    for (const option of options) {
      this.renderUserCheckboxRow(container, {
        id: option.id,
        label: option.label,
        checked: this.selectedUserIds.includes(option.id),
        onChange: (checked) => this.setSpecificUserSelected(option.id, checked),
      });
    }
  }

  private renderUserCheckboxRow(
    container: HTMLElement,
    opts: { id: string; label: string; checked: boolean; onChange: (checked: boolean) => void }
  ): void {
    const row = container.createEl("label", { cls: "vaultguard-principal-picker-row" });
    const checkbox = row.createEl("input", { type: "checkbox" });
    checkbox.checked = opts.checked;
    const text = row.createSpan({ text: opts.label });
    if (opts.id === "*") text.addClass("vaultguard-principal-picker-all");
    checkbox.addEventListener("change", () => {
      opts.onChange(checkbox.checked);
      this.renderUserCheckboxRows(container);
      const summary = container.parentElement?.querySelector(".vaultguard-principal-picker-summary");
      if (summary instanceof HTMLElement) summary.setText(this.userSelectionSummary());
    });
  }

  private filteredUserOptions(): PrincipalOption[] {
    const options = [...this.userOptions];
    for (const id of this.selectedUserIds) {
      if (id !== "*" && !options.some((option) => option.id === id)) {
        options.push({ id, label: `${id} (not in loaded list)` });
      }
    }

    const q = this.userFilter.trim().toLowerCase();
    return (q
      ? options.filter((option) => option.label.toLowerCase().includes(q) || option.id.toLowerCase().includes(q))
      : options
    ).sort((a, b) => a.label.localeCompare(b.label));
  }

  private setSpecificUserSelected(userId: string, checked: boolean): void {
    const withoutWildcard = this.selectedUserIds.filter((id) => id !== "*");
    if (checked) {
      this.selectedUserIds = [...new Set([...withoutWildcard, userId])];
      return;
    }
    this.selectedUserIds = withoutWildcard.filter((id) => id !== userId);
  }

  private userSelectionSummary(): string {
    if (this.selectedUserIds.includes("*")) {
      return "Selected: all users";
    }
    const count = this.selectedUserIds.length;
    if (count === 0) {
      return "No users selected";
    }
    return `Selected: ${count} user${count === 1 ? "" : "s"}`;
  }

  private renderLevelSelector(container: HTMLElement): void {
    new Setting(container)
      .setName("Permission level")
      .setDesc(
        "No access = cannot read, read only = can view but not edit, write = view + edit, admin = manage access"
      )
      .addDropdown((dropdown) =>
        dropdown
          .addOption("none", "No access")
          .addOption("read", "Read only")
          .addOption("write", "Write")
          .addOption("admin", "Admin")
          .setValue(this.selectedLevel)
          .onChange((value) => {
            this.selectedLevel = value as PermissionLevel;
          })
      );
  }

  private renderPrioritySelector(container: HTMLElement): void {
    new Setting(container)
      .setName("Priority")
      .setDesc("Advanced conflict breaker for rules on the same path. Leave blank for automatic path-based priority.")
      .addText((text) => {
        text
          .setPlaceholder("auto")
          .setValue(this.selectedPriority)
          .onChange((value) => {
            this.selectedPriority = value.trim();
          });
        text.inputEl.type = "number";
        text.inputEl.min = "0";
        text.inputEl.step = "1";
      });
  }

  private normalizeRulePath(path: string): string {
    const trimmed = path.trim();
    if (!trimmed) {
      return trimmed;
    }
    return trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  }

  private levelFromRule(rule: PermissionRule): PermissionLevel {
    if (rule.effect === "deny") {
      return this.deniedActionsCapLevel(rule.actions);
    }
    if (rule.actions.includes("admin")) {
      return "admin";
    }
    if (rule.actions.includes("write") || rule.actions.includes("delete")) {
      return "write";
    }
    return "read";
  }

  private deniedActionsCapLevel(actions: PermissionRule["actions"]): PermissionLevel {
    if (actions.includes("read") || actions.includes("list")) return "none";
    if (actions.includes("write") || actions.includes("delete")) return "read";
    if (actions.includes("admin")) return "write";
    return "none";
  }

  private buildRulePayload(target: PrincipalTarget): PermissionMutationInput {
    const pathPattern = this.normalizeRulePath(this.selectedPath);
    const actions: PermissionMutationInput["actions"] =
      this.selectedLevel === "admin"
        ? ["read", "write", "delete", "admin", "list"]
        : this.selectedLevel === "write"
          ? ["read", "write", "delete", "list"]
          : this.selectedLevel === "read"
            ? ["read", "list"]
            : ["read", "write", "delete", "admin", "list"];

    return {
      pathPattern,
      actions,
      effect: this.selectedLevel === "none" ? "deny" : "allow",
      userId: target.userId,
      role: target.role,
    };
  }

  private selectedTargets(): PrincipalTarget[] {
    if (this.selectedPrincipalType === "role") {
      return [{ userId: "*", role: this.selectedRoleId }];
    }

    if (this.selectedUserIds.includes("*")) {
      return [{ userId: "*", role: null }];
    }

    return [...new Set(this.selectedUserIds)]
      .filter((id) => id.trim().length > 0)
      .map((userId) => ({ userId, role: null }));
  }

  private parseSelectedPriority(): number | undefined | null {
    const raw = this.selectedPriority.trim();
    if (!raw) {
      return undefined;
    }
    const priority = Number(raw);
    if (!Number.isInteger(priority) || priority < 0) {
      return null;
    }
    return priority;
  }

  private existingRuleMatchesTarget(pathPattern: string, target: PrincipalTarget): boolean {
    if (!this.existingRule || this.existingRule.pathPattern !== pathPattern) {
      return false;
    }
    if (this.existingRule.role || target.role) {
      return this.existingRule.role === target.role;
    }
    return this.existingRule.userId === target.userId;
  }

  private async handleSave(): Promise<void> {
    // Validation
    if (!this.selectedPath) {
      new Notice("Please select a path.");
      return;
    }
    const targets = this.selectedTargets();
    const priority = this.parseSelectedPriority();
    if (priority === null) {
      new Notice("Priority must be a whole number 0 or greater.");
      return;
    }
    if (this.selectedPrincipalType === "user" && targets.length === 0) {
      new Notice("Please select at least one user.");
      return;
    }
    if (this.selectedPrincipalType === "role" && !this.selectedRoleId) {
      new Notice("Please select a principal (user or role).");
      return;
    }

    // Disable save button during request
    if (this.saveButton) {
      this.saveButton.setDisabled(true);
      this.saveButton.setButtonText(targets.length > 1 ? `Saving ${targets.length}...` : "Saving...");
    }

    try {
      const pathPattern = this.normalizeRulePath(this.selectedPath);
      for (const target of targets) {
        const ruleData = this.buildRulePayload(target);
        await this.apiClient.setPermissionLevel({
          userId: ruleData.userId,
          role: ruleData.role,
          pathPattern: ruleData.pathPattern,
          level: this.selectedLevel,
          ...(priority !== undefined ? { priority } : {}),
        });
      }

      const existingStillCovered = targets.some((target) => this.existingRuleMatchesTarget(pathPattern, target));
      if (this.existingRule && !existingStillCovered) {
        await this.apiClient.deletePermission(this.existingRule.id);
      }

      new Notice(this.successNoticeText(targets));

      await this.onSave();
      this.close();
    } catch (error) {
      new Notice(`Failed to save: ${(error as Error).message}`);
    } finally {
      if (this.saveButton) {
        this.saveButton.setDisabled(false);
        this.saveButton.setButtonText(this.existingRule ? "Update Rule" : "Create Rule");
      }
    }
  }

  private successNoticeText(targets: PrincipalTarget[]): string {
    if (targets.length > 1) {
      return `Permission level set for ${targets.length} users.`;
    }
    const target = targets[0];
    if (target?.role) {
      return this.existingRule ? "Role permission level updated." : "Role permission level set.";
    }
    if (target?.userId === "*") {
      return this.existingRule ? "Permission level updated for all users." : "Permission level set for all users.";
    }
    return this.existingRule ? "Permission level updated." : "Permission level set.";
  }
}
