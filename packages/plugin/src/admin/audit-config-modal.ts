/**
 * AuditConfigModal — org-wide "Audit logging" configuration for Obsidian.
 *
 * Mirrors the admin panel's AuditConfigModal: an admin picks, per category,
 * which audit actions are recorded. The org setting persists the INVERSE
 * (`disabledAuditActions`) so everything is logged by default and any
 * newly-shipped action keeps logging until explicitly turned off.
 *
 * Opened from the VaultGuard ribbon menu, next to "Audit log" (admin only).
 */

import { App, ButtonComponent, Modal, Notice, Setting } from "obsidian";
import type { VaultGuardApiClient } from "../api/client";
import { AUDIT_ACTION_CATALOG, ALL_AUDIT_ACTION_VALUES } from "./audit-actions";

export class AuditConfigModal extends Modal {
  private readonly apiClient: VaultGuardApiClient;
  /** Tracks the DISABLED set (actions opted out of logging). */
  private disabled: Set<string> = new Set();
  private activeCategory: string = AUDIT_ACTION_CATALOG[0].label;
  private loaded = false;
  private saving = false;
  private bodyEl!: HTMLElement;

  constructor(app: App, apiClient: VaultGuardApiClient) {
    super(app);
    this.apiClient = apiClient;
  }

  async onOpen(): Promise<void> {
    this.modalEl.addClass("vaultguard-audit-config");
    const c = this.contentEl;
    c.empty();
    c.createEl("h2", { text: "Audit logging" });
    c.createEl("p", {
      cls: "vaultguard-audit-config-subtitle",
      text:
        "Choose which actions are recorded in the audit log. Applies to the whole organization.",
    });

    this.bodyEl = c.createDiv({ cls: "vaultguard-audit-config-body" });
    this.bodyEl.createDiv({ cls: "vaultguard-loading", text: "Loading audit settings…" });

    try {
      const settings = await this.apiClient.getOrgSettings();
      this.disabled = new Set(settings.disabledAuditActions ?? []);
      this.loaded = true;
      this.renderBody();
    } catch (err) {
      this.bodyEl.empty();
      this.bodyEl.createDiv({
        cls: "vaultguard-error",
        text:
          err instanceof Error
            ? `Failed to load audit settings: ${err.message}`
            : "Failed to load audit settings.",
      });
    }
  }

  private get activeCategoryDef() {
    return (
      AUDIT_ACTION_CATALOG.find((cat) => cat.label === this.activeCategory) ??
      AUDIT_ACTION_CATALOG[0]
    );
  }

  private setActionEnabled(value: string, enabled: boolean): void {
    if (enabled) this.disabled.delete(value);
    else this.disabled.add(value);
  }

  private setCategoryEnabled(enabled: boolean): void {
    for (const action of this.activeCategoryDef.actions) {
      this.setActionEnabled(action.value, enabled);
    }
    this.renderBody();
  }

  private renderBody(): void {
    if (!this.loaded) return;
    const body = this.bodyEl;
    body.empty();

    const enabledCount = ALL_AUDIT_ACTION_VALUES.filter((v) => !this.disabled.has(v)).length;
    body.createDiv({
      cls: "vaultguard-audit-config-summary",
      text: `${enabledCount} of ${ALL_AUDIT_ACTION_VALUES.length} actions logged.`,
    });

    // Category switcher.
    const tabs = body.createDiv({ cls: "vaultguard-audit-config-tabs" });
    for (const cat of AUDIT_ACTION_CATALOG) {
      const onCount = cat.actions.filter((a) => !this.disabled.has(a.value)).length;
      const btn = tabs.createEl("button", {
        cls: "vaultguard-audit-config-tab",
        text: `${cat.label} (${onCount}/${cat.actions.length})`,
      });
      if (cat.label === this.activeCategory) btn.addClass("is-active");
      btn.onclick = () => {
        this.activeCategory = cat.label;
        this.renderBody();
      };
    }

    // Enable/disable-all controls for the active category.
    const category = this.activeCategoryDef;
    const categoryEnabledCount = category.actions.filter((a) => !this.disabled.has(a.value)).length;
    const bulk = body.createDiv({ cls: "vaultguard-audit-config-bulk" });
    new ButtonComponent(bulk)
      .setButtonText("Enable all")
      .setDisabled(categoryEnabledCount === category.actions.length)
      .onClick(() => this.setCategoryEnabled(true));
    new ButtonComponent(bulk)
      .setButtonText("Disable all")
      .setDisabled(categoryEnabledCount === 0)
      .onClick(() => this.setCategoryEnabled(false));

    // Per-action toggles.
    const list = body.createDiv({ cls: "vaultguard-audit-config-list" });
    for (const action of category.actions) {
      new Setting(list)
        .setName(action.label)
        .setDesc(action.value)
        .addToggle((toggle) =>
          toggle.setValue(!this.disabled.has(action.value)).onChange((value) => {
            this.setActionEnabled(action.value, value);
            // Refresh the summary + tab counts without rebuilding mid-toggle.
            this.renderBody();
          })
        );
    }

    // Footer actions.
    const footer = body.createDiv({ cls: "vaultguard-audit-config-actions" });
    new ButtonComponent(footer)
      .setButtonText("Cancel")
      .setDisabled(this.saving)
      .onClick(() => this.close());
    new ButtonComponent(footer)
      .setButtonText(this.saving ? "Saving…" : "Save")
      .setCta()
      .setDisabled(this.saving)
      .onClick(() => void this.handleSave());
  }

  private async handleSave(): Promise<void> {
    if (this.saving) return;
    this.saving = true;
    this.renderBody();
    try {
      // Persist only known catalog actions so stale entries can't accumulate.
      const payload = ALL_AUDIT_ACTION_VALUES.filter((v) => this.disabled.has(v));
      await this.apiClient.updateOrgSettings({ disabledAuditActions: payload });
      new Notice("VaultGuard: audit logging settings saved.");
      this.close();
    } catch (err) {
      this.saving = false;
      this.renderBody();
      new Notice(
        err instanceof Error
          ? `VaultGuard: failed to save audit settings — ${err.message}`
          : "VaultGuard: failed to save audit settings."
      );
    }
  }

  onClose(): void {
    this.contentEl.empty();
  }
}
