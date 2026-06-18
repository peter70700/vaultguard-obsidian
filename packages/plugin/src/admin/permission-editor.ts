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
import { VaultGuardApiClient, PermissionMutationInput, PermissionRule } from "../api/client";

export type PermissionLevel = "none" | "read" | "write" | "admin";

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
  private selectedPrincipalType: "user" | "role" = "user";
  private selectedPrincipalId: string = "";
  private selectedLevel: PermissionLevel = "read";

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
      this.selectedPrincipalId = existingRule.role ?? existingRule.userId;
      this.selectedLevel = this.levelFromRule(existingRule);
    }
  }

  onOpen(): void {
    const { contentEl } = this;
    contentEl.empty();
    this.modalEl.addClass("vaultguard-permission-rule-modal");
    contentEl.addClass("vaultguard-dialog-content");

    const title = this.existingRule ? "Edit Permission Rule" : "Add Permission Rule";
    contentEl.createEl("h3", { text: title });

    this.renderPathSelector(contentEl);
    this.renderPrincipalSelector(contentEl);
    this.renderLevelSelector(contentEl);
    contentEl.createEl("p", {
      text: "Expiry dates, conflict checks, and effective-permission previews are not exposed by the current backend yet.",
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
    this.modalEl.removeClass("vaultguard-permission-rule-modal");
    this.contentEl.removeClass("vaultguard-dialog-content");
    this.contentEl.empty();
  }

  private renderPathSelector(container: HTMLElement): void {
    const pathSetting = new Setting(container)
      .setName("Path")
      .setDesc("Select a folder or file path (supports autocomplete from vault structure)");

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
        setTimeout(() => {
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
    // Principal type selection
    new Setting(container)
      .setName("Principal Type")
      .setDesc("Apply this rule to a user or a role")
      .addDropdown((dropdown) =>
        dropdown
          .addOption("user", "User")
          .addOption("role", "Role")
          .setValue(this.selectedPrincipalType)
          .onChange((value) => {
            this.selectedPrincipalType = value as "user" | "role";
          })
      );

    new Setting(container)
      .setName("Principal")
      .setDesc("Enter a user ID, '*' wildcard, or role name that should receive this rule.")
      .addText((text) =>
        text
          .setValue(this.selectedPrincipalId)
          .setPlaceholder(this.selectedPrincipalType === "role" ? "engineering-admins" : "user-123 or *")
          .onChange((value) => {
            this.selectedPrincipalId = value.trim();
          })
      );
  }

  private renderLevelSelector(container: HTMLElement): void {
    new Setting(container)
      .setName("Permission Level")
      .setDesc(
        "None = explicit deny, Read = view only, Write = view + edit, Admin = full control including permission management"
      )
      .addDropdown((dropdown) =>
        dropdown
          .addOption("none", "None (Deny)")
          .addOption("read", "Read")
          .addOption("write", "Write")
          .addOption("admin", "Admin")
          .setValue(this.selectedLevel)
          .onChange((value) => {
            this.selectedLevel = value as PermissionLevel;
          })
      );
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
      return "none";
    }
    if (rule.actions.includes("admin")) {
      return "admin";
    }
    if (rule.actions.includes("write") || rule.actions.includes("delete")) {
      return "write";
    }
    return "read";
  }

  private buildRulePayload(): PermissionMutationInput {
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
      userId: this.selectedPrincipalType === "user" ? this.selectedPrincipalId : "*",
      role: this.selectedPrincipalType === "role" ? this.selectedPrincipalId : null,
    };
  }

  private async handleSave(): Promise<void> {
    // Validation
    if (!this.selectedPath) {
      new Notice("Please select a path.");
      return;
    }
    if (!this.selectedPrincipalId) {
      new Notice("Please select a principal (user or role).");
      return;
    }

    // Disable save button during request
    if (this.saveButton) {
      this.saveButton.setDisabled(true);
      this.saveButton.setButtonText("Saving...");
    }

    try {
      const ruleData = this.buildRulePayload();

      if (this.existingRule) {
        await this.apiClient.updatePermission(this.existingRule.id, ruleData);
        new Notice("Permission rule updated.");
      } else {
        await this.apiClient.createPermission(ruleData);
        new Notice("Permission rule created.");
      }

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
}
