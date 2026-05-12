/**
 * PluginAllowlistModal — consent gate for vault-curated community plugins.
 *
 * When a vault admin adds a plugin to the allowlist, every member's
 * VaultGuard client surfaces this modal exactly once per (device, plugin)
 * pair. The user must consent before the plugin is enabled in Obsidian —
 * we deliberately stop short of "auto-enable on sync" because plugins
 * execute arbitrary code with full vault access, and the user is the
 * party best placed to refuse a malicious or buggy admin push.
 *
 * The modal also surfaces the bundle hash check result so the user can
 * see the synced bytes match what the admin signed off on.
 */

import { App, ButtonComponent, Modal } from "obsidian";

export interface PluginAllowlistPrompt {
  pluginId: string;
  displayName: string;
  version?: string;
  note?: string;
  /** Vault admin who added the entry, formatted for display (email or userId). */
  addedBy: string;
  /**
   * Verification status for the synced `main.js` bundle:
   *   - "verified": admin pinned a hash and the local copy matches.
   *   - "mismatch": admin pinned a hash and it does NOT match (refuse install).
   *   - "unsigned": admin did not pin a hash; user assumes the risk.
   *   - "missing": the bundle is not yet present locally (e.g. sync incomplete).
   */
  hashStatus: "verified" | "mismatch" | "unsigned" | "missing";
  /** Local SHA-256 of main.js, when available. */
  localHash?: string;
  /** Admin-pinned hash, when set. */
  expectedHash?: string;
}

export type PluginAllowlistDecision = "install" | "skip" | "ignore";

export class PluginAllowlistModal extends Modal {
  private prompt: PluginAllowlistPrompt;
  private resolveDecision: (decision: PluginAllowlistDecision) => void;
  private decided = false;

  constructor(
    app: App,
    prompt: PluginAllowlistPrompt,
    resolveDecision: (decision: PluginAllowlistDecision) => void
  ) {
    super(app);
    this.prompt = prompt;
    this.resolveDecision = resolveDecision;
  }

  onOpen(): void {
    const { contentEl } = this;
    contentEl.empty();
    this.modalEl.addClass("vaultguard-plugin-allowlist-modal");

    contentEl.createEl("h2", { text: `Install "${this.prompt.displayName}"?` });
    contentEl.createEl("p", {
      text:
        "Your vault admin has added this plugin to the team allowlist. " +
        "Plugins run code with full access to your vault, so VaultGuard always " +
        "asks before enabling one.",
    });

    const meta = contentEl.createDiv({ cls: "vaultguard-allowlist-meta" });
    this.renderField(meta, "Plugin ID", this.prompt.pluginId);
    if (this.prompt.version) this.renderField(meta, "Version", this.prompt.version);
    this.renderField(meta, "Added by", this.prompt.addedBy);
    if (this.prompt.note) this.renderField(meta, "Note", this.prompt.note);

    const status = contentEl.createDiv({ cls: "vaultguard-allowlist-status" });
    switch (this.prompt.hashStatus) {
      case "verified":
        status.createEl("p", {
          text: "✅ Bundle hash matches the admin-pinned signature.",
        });
        break;
      case "unsigned":
        status.createEl("p", {
          text:
            "⚠️ The admin did not pin a SHA-256 hash. The plugin's bytes have " +
            "not been verified against a signed reference. Proceed only if you trust " +
            "the admin and your sync channel.",
        });
        break;
      case "mismatch":
        status.createEl("p", {
          text:
            "❌ The synced plugin bytes do NOT match the admin's pinned hash. " +
            "This usually means the bundle was modified after the admin approved it. " +
            "Installation is disabled — contact your admin.",
        });
        if (this.prompt.expectedHash && this.prompt.localHash) {
          const detail = status.createEl("details");
          detail.createEl("summary", { text: "Show hashes" });
          detail.createEl("p", { text: `Expected: ${this.prompt.expectedHash}` });
          detail.createEl("p", { text: `Local: ${this.prompt.localHash}` });
        }
        break;
      case "missing":
        status.createEl("p", {
          text:
            "⏳ The plugin's main.js has not finished syncing to this device yet. " +
            "Try again after the next sync completes.",
        });
        break;
    }

    const buttons = contentEl.createDiv({ cls: "vaultguard-allowlist-actions" });

    const installBtn = new ButtonComponent(buttons)
      .setButtonText("Install and enable")
      .setCta()
      .onClick(() => this.decide("install"));
    if (this.prompt.hashStatus === "mismatch" || this.prompt.hashStatus === "missing") {
      installBtn.setDisabled(true);
    }

    new ButtonComponent(buttons)
      .setButtonText("Skip for now")
      .onClick(() => this.decide("skip"));

    new ButtonComponent(buttons)
      .setButtonText("Don't ask again")
      .setWarning()
      .onClick(() => this.decide("ignore"));
  }

  onClose(): void {
    this.contentEl.empty();
    if (!this.decided) {
      this.resolveDecision("skip");
    }
  }

  private renderField(parent: HTMLElement, label: string, value: string): void {
    const row = parent.createDiv({ cls: "vaultguard-allowlist-row" });
    row.createEl("strong", { text: `${label}: ` });
    row.createSpan({ text: value });
  }

  private decide(decision: PluginAllowlistDecision): void {
    this.decided = true;
    this.resolveDecision(decision);
    this.close();
  }
}
