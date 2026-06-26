/**
 * VaultPickerModal — first-time vault binding UI.
 *
 * After login, every Obsidian local vault must be bound to exactly one
 * server-side VaultGuard vault. This modal lets the user either:
 *   1. Pick an existing server vault they're a member of, or
 *   2. Create a new server vault (admins only).
 *
 * Without this binding the plugin refuses to send file/permission API
 * calls — preventing the cross-vault path-collision bug that the
 * pre-multi-vault model suffered from.
 */

import { App, ButtonComponent, Modal, Notice } from "obsidian";
import { VaultGuardApiClient, VaultKind, VaultMemberRole, VaultRecord } from "../api/client";

export interface VaultPickerResult {
  vaultId: string;
  name: string;
  slug: string;
}

interface VaultPickerOptions {
  /** Default name to suggest when creating a new vault — usually the local Obsidian folder name. */
  suggestedName: string;
  /** True when the current user is an org-admin (can create vaults). */
  canCreateVaults: boolean;
}

export class VaultPickerModal extends Modal {
  private apiClient: VaultGuardApiClient;
  private options: VaultPickerOptions;
  private onPick: (result: VaultPickerResult) => Promise<void>;
  private listEl: HTMLElement | null = null;
  private errorEl: HTMLElement | null = null;
  private busy = false;
  /** One-shot guard so single-vault auto-bind only fires once per modal. */
  private autoBindAttempted = false;

  constructor(
    app: App,
    apiClient: VaultGuardApiClient,
    options: VaultPickerOptions,
    onPick: (result: VaultPickerResult) => Promise<void>
  ) {
    super(app);
    this.apiClient = apiClient;
    this.options = options;
    this.onPick = onPick;
  }

  onOpen(): void {
    const { contentEl } = this;
    contentEl.empty();
    this.modalEl.addClass("vaultguard-vault-picker-modal");
    contentEl.addClass("vaultguard-vault-picker-content");

    contentEl.createEl("h2", {
      text: "Bind to a VaultGuard vault",
      cls: "vaultguard-modal-title",
    });
    contentEl.createEl("p", {
      text:
        "This Obsidian folder needs to be linked to a server-side vault. Pick one " +
        "you already belong to, or create a new one.",
      cls: "vaultguard-modal-description",
    });

    this.errorEl = contentEl.createDiv({ cls: "vaultguard-vault-picker-error" });
    this.errorEl.hide();

    // ── Existing vaults section ─────────────────────────────────────────
    contentEl.createEl("h3", {
      text: "Pick an existing vault",
      cls: "vaultguard-modal-section-title",
    });
    this.listEl = contentEl.createDiv({ cls: "vaultguard-vault-picker-list" });
    this.listEl.createEl("p", {
      text: "Loading...",
      cls: "setting-item-description",
    });
    void this.loadVaults();

    // ── Create vault section (admin only) ───────────────────────────────
    if (this.options.canCreateVaults) {
      contentEl.createEl("hr", { cls: "vaultguard-modal-divider" });
      contentEl.createEl("h3", {
        text: "Or create a new vault",
        cls: "vaultguard-modal-section-title",
      });
      const formEl = contentEl.createDiv({ cls: "vaultguard-vault-picker-create" });

      formEl.createEl("label", { text: "Name", cls: "vaultguard-field-label" });
      const nameInput = formEl.createEl("input", {
        cls: "vaultguard-field-input",
        attr: { type: "text", placeholder: this.options.suggestedName },
      });
      nameInput.value = this.options.suggestedName;

      formEl.createEl("label", {
        text: "Description (optional)",
        cls: "vaultguard-field-label",
      });
      const descInput = formEl.createEl("textarea", {
        cls: "vaultguard-field-input vaultguard-vault-picker-textarea",
        attr: { rows: "2", placeholder: "e.g. Engineering team handbook" },
      });

      formEl.createEl("label", { text: "Kind", cls: "vaultguard-field-label" });
      const kindSelect = formEl.createEl("select", { cls: "vaultguard-field-input" });
      for (const [value, label] of [
        ["team", "Team"],
        ["personal", "Personal"],
        ["shared", "Shared"],
      ] as Array<[VaultKind, string]>) {
        kindSelect.createEl("option", { text: label, value });
      }
      kindSelect.value = "team";

      formEl.createEl("label", {
        text: "Default role for new members",
        cls: "vaultguard-field-label",
      });
      const roleSelect = formEl.createEl("select", { cls: "vaultguard-field-input" });
      for (const [value, label] of [
        ["viewer", "Viewer (read only)"],
        ["editor", "Editor (read + write)"],
        ["admin", "Admin (full control)"],
      ] as Array<[VaultMemberRole, string]>) {
        roleSelect.createEl("option", { text: label, value });
      }
      roleSelect.value = "editor";

      const buttonRow = formEl.createDiv({ cls: "vaultguard-vault-picker-create-actions" });
      new ButtonComponent(buttonRow)
        .setButtonText("Create vault")
        .setCta()
        .onClick(async () => {
          const name = nameInput.value.trim();
          if (!name) {
            this.showError("Vault name is required.");
            return;
          }
          this.showError("");
          await this.createVault(
            name,
            descInput.value.trim(),
            kindSelect.value as VaultKind,
            roleSelect.value as VaultMemberRole
          );
        });
    } else {
      contentEl.createEl("p", {
        text:
          "Need a new vault? Ask an organization admin to create one and add " +
          "you as a member.",
        cls: "vaultguard-modal-note",
      });
    }
  }

  onClose(): void {
    this.modalEl.removeClass("vaultguard-vault-picker-modal");
    this.contentEl.removeClass("vaultguard-vault-picker-content");
    this.contentEl.empty();
  }

  private showError(message: string): void {
    if (!this.errorEl) return;
    if (message) {
      this.errorEl.setText(message);
      this.errorEl.show();
    } else {
      this.errorEl.hide();
    }
  }

  private async loadVaults(): Promise<void> {
    if (!this.listEl) return;
    try {
      const vaults = await this.apiClient.listVaults();
      this.renderVaultList(vaults);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to load vaults";
      this.listEl.empty();
      this.listEl.createEl("p", {
        text: `Could not load your vaults: ${msg}`,
        cls: "setting-item-description",
      });
    }
  }

  private renderVaultList(vaults: VaultRecord[]): void {
    if (!this.listEl) return;
    this.listEl.empty();

    const usable = vaults.filter((v) => !v.archived);

    // Single usable vault → bind automatically (admins and non-admins alike).
    // One-shot guard prevents a re-render loop; on failure autoBind falls back
    // to a normal selectable row.
    if (usable.length === 1 && !this.autoBindAttempted && !this.busy) {
      this.autoBindAttempted = true;
      this.listEl.createEl("p", {
        text: `Binding to "${usable[0].name}"…`,
        cls: "setting-item-description",
      });
      void this.autoBind(usable[0]);
      return;
    }

    if (usable.length === 0) {
      this.renderEmptyState();
      return;
    }

    this.renderVaultRows(usable);
  }

  /** Render one selectable "Select" row per usable vault. */
  private renderVaultRows(usable: VaultRecord[]): void {
    if (!this.listEl) return;
    this.listEl.empty();

    for (const vault of usable) {
      const row = this.listEl.createDiv({ cls: "vaultguard-vault-picker-row" });
      const info = row.createDiv({ cls: "vaultguard-vault-picker-info" });
      info.createEl("strong", {
        text: vault.name,
        cls: "vaultguard-vault-picker-name",
      });
      info.createEl("div", {
        text: `${vault.kind} - ${vault.slug}`,
        cls: "vaultguard-vault-picker-meta",
      });

      new ButtonComponent(row)
        .setButtonText("Select")
        .onClick(async () => {
          await this.pick({
            vaultId: vault.vaultId,
            name: vault.name,
            slug: vault.slug,
          });
        });
    }
  }

  /**
   * Auto-bind to the only usable vault. pick() closes the modal on success and
   * surfaces an error (without closing) on failure — so if the modal is still
   * open afterwards, binding failed and we fall back to a clickable row.
   */
  private async autoBind(vault: VaultRecord): Promise<void> {
    await this.pick({
      vaultId: vault.vaultId,
      name: vault.name,
      slug: vault.slug,
    });
    if (this.listEl && this.listEl.isConnected) {
      this.renderVaultRows([vault]);
    }
  }

  /** Friendly zero-vault state: explainer + Retry (always) + Contact-admin (non-admins). */
  private renderEmptyState(): void {
    if (!this.listEl) return;
    this.listEl.empty();

    const empty = this.listEl.createDiv({ cls: "vaultguard-vault-picker-empty" });

    if (this.options.canCreateVaults) {
      empty.createEl("p", {
        text: "You don't have any vaults yet — create one below ↓, or retry.",
        cls: "setting-item-description",
      });
      const actions = empty.createDiv({ cls: "vaultguard-vault-picker-empty-actions" });
      new ButtonComponent(actions)
        .setButtonText("Retry")
        .onClick(() => this.retry());
    } else {
      empty.createEl("p", {
        text:
          "You're not a member of any vault yet. Ask an organization admin to " +
          "add you, then retry.",
        cls: "setting-item-description",
      });
      const actions = empty.createDiv({ cls: "vaultguard-vault-picker-empty-actions" });
      new ButtonComponent(actions)
        .setButtonText("Contact your admin")
        .onClick(() => {
          window.open(
            "mailto:?subject=" +
              encodeURIComponent("VaultGuard: please add me to a vault"),
            "_blank"
          );
        });
      new ButtonComponent(actions)
        .setButtonText("Retry")
        .onClick(() => this.retry());
    }
  }

  /** Re-show "Loading…" then refetch the vault list. */
  private retry(): void {
    if (this.listEl) {
      this.listEl.empty();
      this.listEl.createEl("p", {
        text: "Loading...",
        cls: "setting-item-description",
      });
    }
    void this.loadVaults();
  }

  private async pick(result: VaultPickerResult): Promise<void> {
    if (this.busy) return;
    this.busy = true;
    try {
      await this.onPick(result);
      new Notice(`VaultGuard: bound to "${result.name}"`);
      this.close();
    } catch (err) {
      this.showError(err instanceof Error ? err.message : "Could not bind to vault");
    } finally {
      this.busy = false;
    }
  }

  private async createVault(
    name: string,
    description: string,
    kind: VaultKind,
    defaultRole: VaultMemberRole
  ): Promise<void> {
    if (this.busy) return;
    this.busy = true;
    try {
      const vault = await this.apiClient.createVault({
        name,
        ...(description ? { description } : {}),
        kind,
        defaultRole,
      });
      await this.onPick({
        vaultId: vault.vaultId,
        name: vault.name,
        slug: vault.slug,
      });
      new Notice(`VaultGuard: created and bound to "${vault.name}"`);
      this.close();
    } catch (err) {
      this.showError(err instanceof Error ? err.message : "Could not create vault");
    } finally {
      this.busy = false;
    }
  }
}
