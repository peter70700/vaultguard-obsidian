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

export type WriteConfirmOperation =
  | "create"
  | "apply_patch"
  | "delete"
  | "rename"
  | "set_permission"
  | "restore"
  | "share_create"
  | "share_revoke"
  | "member_add"
  | "member_remove"
  | "member_set_role";

// Verb shown in the confirmation prompt for each agent-bridge mutation. Shared
// with main.ts's headless fallback so both phrasings stay in sync.
export const AGENT_BRIDGE_CONFIRM_LABELS: Record<WriteConfirmOperation, string> = {
  create: "create",
  apply_patch: "patch",
  delete: "delete",
  rename: "move",
  set_permission: "change permissions on",
  restore: "restore",
  share_create: "create a share link for",
  share_revoke: "revoke a share link for",
  member_add: "add a member to",
  member_remove: "remove a member from",
  member_set_role: "change a member's role on",
};

export interface WriteConfirmRequest {
  agentName: string;
  operation: WriteConfirmOperation;
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

    const opLabel = AGENT_BRIDGE_CONFIRM_LABELS[this.request.operation] ?? "patch";
    this.titleEl.setText(`Allow VaultGuard agent to ${opLabel} ${this.titleObject()}?`);

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
    } else if (this.request.operation === "apply_patch") {
      renderUnifiedDiff(diffWrap, this.request.preview);
    } else {
      // delete / rename — no diff to show; render the plain-text preview.
      diffWrap.createEl("pre", {
        cls: "vaultguard-chat-write-confirm-plain",
        text: this.request.preview,
      });
    }

    new Setting(contentEl)
      .addButton((btn) =>
        btn
          .setButtonText("Reject")
          .onClick(() => this.finish(false)),
      )
      .addButton((btn) =>
        btn
          .setButtonText(this.request.operation === "delete" ? "Allow delete" : "Allow")
          .setCta()
          .onClick(() => this.finish(true)),
      );
  }

  // The noun the title's verb acts on. The verbs (AGENT_BRIDGE_CONFIRM_LABELS)
  // already embed the file/share object (e.g. "create a share link for"), so the
  // only object that differs is membership, which acts on the vault, not a file.
  private titleObject(): string {
    switch (this.request.operation) {
      case "member_add":
      case "member_remove":
      case "member_set_role":
        return "the vault";
      default:
        return "a file";
    }
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
