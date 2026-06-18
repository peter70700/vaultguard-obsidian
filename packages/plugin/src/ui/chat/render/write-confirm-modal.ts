// Diff-enhanced write-confirmation modal (AI-CHAT-PANEL.md §9.5). Replaces the
// raw `window.confirm` preview with a red/green diff: `apply_patch` previews
// are unified diffs; `create` previews are rendered as an all-addition view of
// the new file content.
//
// Presentation only — it preserves the approve/reject `Promise<boolean>`
// contract of `confirmAgentBridgeWrite`. The preview string is already capped
// upstream; this modal does not re-truncate.

import { App, Modal, Setting } from "obsidian";

import { renderAllAdditions, renderUnifiedDiff } from "./diff-renderer";

export interface WriteConfirmRequest {
  agentName: string;
  operation: "create" | "apply_patch";
  path: string;
  scopes: string[];
  expiresAt: string;
  preview: string;
}

export class WriteConfirmModal extends Modal {
  private resolved = false;

  constructor(
    app: App,
    private readonly request: WriteConfirmRequest,
    private readonly onResolve: (allow: boolean) => void,
  ) {
    super(app);
  }

  onOpen(): void {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.addClass("vaultguard-chat-write-confirm");

    const opLabel = this.request.operation === "create" ? "create" : "patch";
    this.titleEl.setText(`Allow VaultGuard agent to ${opLabel} a file?`);

    contentEl.createEl("p", {
      cls: "vaultguard-chat-write-confirm-summary",
      text: `Agent "${this.request.agentName}" wants to ${opLabel} "${this.request.path}".`,
    });

    const meta = contentEl.createEl("p", { cls: "vaultguard-chat-write-confirm-meta" });
    meta.createSpan({ text: `Scope: ${this.request.scopes.join(", ") || "(none)"}` });
    meta.createEl("br");
    meta.createSpan({ text: `Lease expires: ${this.request.expiresAt}` });

    const diffWrap = contentEl.createDiv({ cls: "vaultguard-chat-write-confirm-diff" });
    if (this.request.operation === "create") {
      renderAllAdditions(diffWrap, this.request.preview);
    } else {
      renderUnifiedDiff(diffWrap, this.request.preview);
    }

    new Setting(contentEl)
      .addButton((btn) =>
        btn
          .setButtonText("Reject")
          .onClick(() => this.finish(false)),
      )
      .addButton((btn) =>
        btn
          .setButtonText("Allow write")
          .setCta()
          .onClick(() => this.finish(true)),
      );
  }

  onClose(): void {
    // Dismissing via Escape / clicking out counts as a reject so the caller's
    // Promise<boolean> always settles.
    this.finish(false);
    this.contentEl.empty();
  }

  private finish(allow: boolean): void {
    if (this.resolved) return;
    this.resolved = true;
    this.onResolve(allow);
    this.close();
  }
}
