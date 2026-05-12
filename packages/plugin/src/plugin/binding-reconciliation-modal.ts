/**
 * BindingReconciliationModal — first-sync reconciliation preview.
 *
 * After the user binds this Obsidian local folder to a server vault, we
 * reconcile the two file trees before any writes happen. This modal shows
 * a summary of:
 *   - Server-only files (will be downloaded into this folder)
 *   - Local-only files (will be uploaded to the server vault)
 *   - Conflicts (files present in both with different content)
 *
 * The user picks how to resolve conflicts and confirms the plan. Without
 * this preview, the prior behaviour silently overwrote same-named local
 * files with the server's copy and stranded any local-only files (no
 * upload, no permission rules applied). See docs/VAULTS.md.
 */

import { App, ButtonComponent, Modal } from "obsidian";
import { ConflictResolutionStrategy } from "../types";

export interface ReconciliationPlan {
  serverOnly: string[];
  localOnly: string[];
  conflicts: string[];
}

export interface ReconciliationDecision {
  proceed: boolean;
  conflictStrategy: ConflictResolutionStrategy;
}

export class BindingReconciliationModal extends Modal {
  private plan: ReconciliationPlan;
  private defaultStrategy: ConflictResolutionStrategy;
  private resolveDecision: (decision: ReconciliationDecision) => void;
  private decided = false;

  constructor(
    app: App,
    plan: ReconciliationPlan,
    defaultStrategy: ConflictResolutionStrategy,
    resolveDecision: (decision: ReconciliationDecision) => void
  ) {
    super(app);
    this.plan = plan;
    this.defaultStrategy = defaultStrategy;
    this.resolveDecision = resolveDecision;
  }

  onOpen(): void {
    const { contentEl } = this;
    contentEl.empty();
    this.modalEl.addClass("vaultguard-reconciliation-modal");
    contentEl.addClass("vaultguard-reconciliation-content");

    contentEl.createEl("h2", {
      text: "Reconcile vault contents",
      cls: "vaultguard-modal-title",
    });
    contentEl.createEl("p", {
      text:
        "VaultGuard compared this Obsidian folder with the server vault. " +
        "Review the plan below before any files are downloaded, uploaded, or modified.",
      cls: "vaultguard-modal-description",
    });

    const summary = contentEl.createDiv({ cls: "vaultguard-reconciliation-summary" });

    this.renderRow(summary, "Download from server", this.plan.serverOnly.length, "Files that exist only on the server.");
    this.renderRow(summary, "Upload from this folder", this.plan.localOnly.length, "Files that exist only in this Obsidian folder.");
    this.renderRow(summary, "Conflicts", this.plan.conflicts.length, "Same path on both sides, different content.");

    if (this.plan.conflicts.length > 0) {
      const detail = contentEl.createEl("details", { cls: "vaultguard-reconciliation-details" });
      detail.createEl("summary", { text: `Show conflicting paths (${this.plan.conflicts.length})` });
      const list = detail.createEl("ul");
      for (const path of this.plan.conflicts.slice(0, 50)) {
        list.createEl("li", { text: path });
      }
      if (this.plan.conflicts.length > 50) {
        detail.createEl("p", {
          text: `…and ${this.plan.conflicts.length - 50} more.`,
          cls: "setting-item-description",
        });
      }

      contentEl.createEl("h3", {
        text: "Conflict resolution",
        cls: "vaultguard-modal-section-title",
      });
      const select = contentEl.createEl("select", { cls: "vaultguard-field-input" });
      const options: Array<[ConflictResolutionStrategy, string]> = [
        [ConflictResolutionStrategy.DUPLICATE, "Keep both - save my local copy as a duplicate (safest)"],
        [ConflictResolutionStrategy.KEEP_LOCAL, "Keep my local version - overwrite the server"],
        [ConflictResolutionStrategy.KEEP_REMOTE, "Keep the server version - overwrite my local file"],
      ];
      for (const [value, label] of options) {
        const opt = select.createEl("option", { text: label });
        opt.value = value;
      }
      const initial = options.some(([v]) => v === this.defaultStrategy)
        ? this.defaultStrategy
        : ConflictResolutionStrategy.DUPLICATE;
      select.value = initial;
      this.defaultStrategy = initial as ConflictResolutionStrategy;
      select.addEventListener("change", () => {
        this.defaultStrategy = select.value as ConflictResolutionStrategy;
      });
    }

    const buttonRow = contentEl.createDiv({ cls: "vaultguard-modal-actions" });

    new ButtonComponent(buttonRow)
      .setButtonText("Cancel")
      .onClick(() => {
        this.decided = true;
        this.close();
        this.resolveDecision({ proceed: false, conflictStrategy: this.defaultStrategy });
      });

    new ButtonComponent(buttonRow)
      .setButtonText(this.proceedLabel())
      .setCta()
      .onClick(() => {
        this.decided = true;
        this.close();
        this.resolveDecision({ proceed: true, conflictStrategy: this.defaultStrategy });
      });
  }

  onClose(): void {
    this.modalEl.removeClass("vaultguard-reconciliation-modal");
    this.contentEl.removeClass("vaultguard-reconciliation-content");
    this.contentEl.empty();
    if (!this.decided) {
      this.resolveDecision({ proceed: false, conflictStrategy: this.defaultStrategy });
    }
  }

  private renderRow(parent: HTMLElement, label: string, count: number, hint: string): void {
    parent.createEl("strong", {
      text: String(count),
      cls: "vaultguard-reconciliation-count",
    });
    const text = parent.createDiv({ cls: "vaultguard-reconciliation-row-text" });
    text.createEl("div", { text: label, cls: "vaultguard-reconciliation-row-label" });
    text.createEl("div", { text: hint, cls: "setting-item-description" });
  }

  private proceedLabel(): string {
    const { serverOnly, localOnly, conflicts } = this.plan;
    if (serverOnly.length === 0 && localOnly.length === 0 && conflicts.length === 0) {
      return "Finish (nothing to do)";
    }
    return "Apply plan";
  }
}
