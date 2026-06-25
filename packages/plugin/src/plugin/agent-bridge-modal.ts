import { ButtonComponent, Modal, Notice, Setting } from "obsidian";
import type VaultGuardPlugin from "./main";
import type {
  AgentBridgeLeaseSecret,
  AgentBridgeLeaseSummary,
  AgentBridgeServerInfo,
  AgentWriteMode,
} from "./agent-bridge";
import { AtRestPasswordConfirmModal } from "./at-rest-modals";

interface BridgeConnection {
  endpoint: string;
  mcpEndpoint: string;
  token: string;
  leaseId: string;
  expiresAt: string;
  tools: AgentBridgeServerInfo["tools"];
}

type LifetimePreset = "30m" | "1h" | "2h" | "until-logout";

export class AgentBridgeLeaseModal extends Modal {
  private plugin: VaultGuardPlugin;
  private onLeaseCreated?: () => void;
  private agentName = "LLM agent";
  private bridgeScope = "/**";
  private lifetime: LifetimePreset = "30m";
  private writeMode: AgentWriteMode = "confirm";

  private get persistent(): boolean {
    return this.lifetime === "until-logout";
  }

  private get ttlMinutes(): number {
    switch (this.lifetime) {
      case "30m":
        return 30;
      case "1h":
        return 60;
      case "2h":
        return 120;
      default:
        return 30; // value is unused for persistent leases
    }
  }

  constructor(plugin: VaultGuardPlugin, onLeaseCreated?: () => void) {
    super(plugin.app);
    this.plugin = plugin;
    this.onLeaseCreated = onLeaseCreated;
  }

  onOpen(): void {
    this.renderForm();
  }

  private renderForm(): void {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl("h2", { text: "Create Agent Bridge Lease" });
    contentEl.createEl("p", {
      text:
        "Mint a short-lived token for an external agent. The agent can only use VaultGuard bridge tools within the scope below; hidden and local-only files remain blocked.",
      cls: "setting-item-description",
    });

    // Inline hint that updates as the user toggles fields. Distinguishes
    // hard errors (block submit) from soft warnings (allow submit but let
    // the user see what they're agreeing to). Server-side rules are still
    // authoritative on the actual mint.
    let validationEl: HTMLElement | null = null;
    let createBtn: ButtonComponent | null = null;
    const refreshValidation = (): void => {
      if (!validationEl || !createBtn) return;
      const result = this.computeValidationState();
      validationEl.setText(result.message);
      validationEl.removeClass("vaultguard-modal-hint-error");
      validationEl.removeClass("vaultguard-modal-hint-warning");
      validationEl.removeClass("vaultguard-modal-hint-ok");
      if (result.severity === "error") {
        validationEl.addClass("vaultguard-modal-hint-error");
        createBtn.setDisabled(true);
      } else if (result.severity === "warning") {
        validationEl.addClass("vaultguard-modal-hint-warning");
        createBtn.setDisabled(false);
      } else {
        validationEl.addClass("vaultguard-modal-hint-ok");
        createBtn.setDisabled(false);
      }
    };

    new Setting(contentEl)
      .setName("Agent label")
      .setDesc("Shown in write confirmations and logs.")
      .addText((text) =>
        text
          .setPlaceholder("Claude Code, Codex, local model")
          .setValue(this.agentName)
          .onChange((value) => {
            this.agentName = value;
          })
      );

    new Setting(contentEl)
      .setName("Scope")
      .setDesc("Vault-relative path or glob, for example /project-x/**. Use /** only when the agent really needs the whole vault.")
      .addText((text) =>
        text
          .setPlaceholder("/project-x/**")
          .setValue(this.bridgeScope)
          .onChange((value) => {
            this.bridgeScope = value;
            refreshValidation();
          })
      );

    new Setting(contentEl)
      .setName("Lifetime")
      .setDesc(
        "Time-limited leases live in memory only and expire on the clock. 'Until logout' leases are persistent — they survive Obsidian restarts (encrypted on disk via the at-rest cipher) and end when you log out. Persistent leases require re-auth and cannot use 'Allow writes'."
      )
      .addDropdown((dropdown) =>
        dropdown
          .addOption("30m", "30 minutes")
          .addOption("1h", "1 hour")
          .addOption("2h", "2 hours (max time-limited)")
          .addOption("until-logout", "Until logout (persistent)")
          .setValue(this.lifetime)
          .onChange((value) => {
            this.lifetime = value as LifetimePreset;
            refreshValidation();
          })
      );

    new Setting(contentEl)
      .setName("Writes")
      .setDesc("Use confirmation unless you are running a fully trusted local model on a narrow scope.")
      .addDropdown((dropdown) =>
        dropdown
          .addOption("confirm", "Ask before each write")
          .addOption("deny", "Read-only")
          .addOption("allow", "Allow writes")
          .setValue(this.writeMode)
          .onChange((value) => {
            this.writeMode = value as AgentWriteMode;
            refreshValidation();
          })
      );

    validationEl = contentEl.createDiv({ cls: "vaultguard-modal-hint" });

    new Setting(contentEl)
      .addButton((button) => {
        createBtn = button;
        button
          .setButtonText("Create lease")
          .setCta()
          .onClick(async () => {
            button.setDisabled(true).setButtonText("Creating...");
            let lease: AgentBridgeLeaseSecret | null = null;
            try {
              if (this.persistent) {
                const ok = await this.confirmPersistentReauth();
                if (!ok) {
                  button.setDisabled(false).setButtonText("Create lease");
                  return;
                }
              }
              lease = await this.plugin.createAgentBridgeLease({
                agentName: this.agentName,
                scope: this.bridgeScope,
                ttlMinutes: this.ttlMinutes,
                writeMode: this.writeMode,
                persistent: this.persistent,
              });
              const server = await this.plugin.startAgentBridgeServer();
              const connection: BridgeConnection = {
                endpoint: server.endpoint,
                mcpEndpoint: server.mcpEndpoint,
                token: lease.token,
                leaseId: lease.leaseId,
                expiresAt: lease.expiresAt,
                tools: server.tools,
              };
              this.renderConnection(connection, lease);
              this.onLeaseCreated?.();
            } catch (err) {
              if (lease) this.plugin.revokeAgentBridgeLease(lease.leaseId);
              new Notice(
                `VaultGuard: Could not create agent bridge lease - ${
                  err instanceof Error ? err.message : String(err)
                }`,
                10000
              );
              button.setDisabled(false).setButtonText("Create lease");
            }
          });
      })
      .addButton((button) =>
        button.setButtonText("Cancel").onClick(() => this.close())
      );

    // Apply initial state so the button reflects current values.
    refreshValidation();
  }

  // Three states the form can be in: error blocks submit, warning allows
  // submit but signals real consequences, ok stays quiet.
  private computeValidationState(): {
    severity: "ok" | "warning" | "error";
    message: string;
  } {
    if (!this.persistent) return { severity: "ok", message: "" };

    const scope = this.bridgeScope.trim();
    if (!scope) {
      return {
        severity: "error",
        message: "Persistent leases need a scope. Try /** for the whole vault or /project-x/** for a folder.",
      };
    }
    if (this.writeMode === "allow") {
      return {
        severity: "error",
        message:
          'Persistent leases cannot use "Allow writes" — long-lived silent writes change the safety property. Pick "Read-only" or "Ask before each write".',
      };
    }
    if (scope === "/**" || scope === "**") {
      return {
        severity: "warning",
        message:
          "Heads up: this gives the agent access to every non-hidden file in this vault until you log out. The re-auth gate confirms you're sure.",
      };
    }
    return { severity: "ok", message: "" };
  }

  // Two-step flow so the user can review what's about to leave the
  // sandbox and copy it on a real user gesture. Auto-copying on lease
  // creation and immediately closing the modal raced with Electron's
  // clipboard handler — the writeText resolved but landed nothing on
  // the clipboard. Showing the JSON makes the copy a click and gives a
  // visible fallback (selectable text) when clipboard APIs misbehave.
  private renderConnection(
    connection: BridgeConnection,
    lease: AgentBridgeLeaseSummary
  ): void {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl("h2", { text: "Agent bridge lease ready" });

    const intro = contentEl.createEl("p");
    intro.appendText(
      `Lease for "${lease.agentName}" created. Scope: ${lease.scopes.join(", ")}. Write mode: ${lease.writeMode}. Expires ${lease.expiresAt}. Hand the agent only the snippets below — never the LAK, recovery code, or the vault folder itself.`
    );

    const rawJson = JSON.stringify(connection, null, 2);
    const mcpConfig = this.buildMcpServerConfig(connection);

    this.renderCopyableBlock(contentEl, {
      title: "Generic agent connection (custom HTTP-RPC)",
      description:
        "For agents you wrote yourself or that target VaultGuard's plain HTTP-RPC at /rpc. Paste this JSON wherever your agent expects its connection settings.",
      json: rawJson,
      copyLabel: "Copy connection JSON",
    });

    this.renderCopyableBlock(contentEl, {
      title: "Claudian / Claude Code MCP server",
      description:
        "Paste this snippet into Claudian's MCP servers settings (or into a Claude Code .mcp.json) to expose VaultGuard as an MCP server. After installing, author a slash command with `allowed-tools: mcp__vaultguard__*` so the CLI uses the bridge tools instead of its built-in Read/Glob/Grep against the encrypted vault folder.",
      json: mcpConfig,
      copyLabel: "Copy MCP config",
    });

    const buttons = contentEl.createDiv({ cls: "vaultguard-modal-actions" });
    const closeBtn = new ButtonComponent(buttons);
    closeBtn.setButtonText("Done").setCta().onClick(() => this.close());
  }

  // A persistent lease lives until logout — it deserves the same gate as
  // "View recovery code" / "Decrypt vault". An unattended unlocked
  // Obsidian shouldn't be enough to mint a long-lived agent capability.
  private confirmPersistentReauth(): Promise<boolean> {
    const scope = this.bridgeScope.trim();
    const isVaultWide = scope === "/**" || scope === "**";
    const description = isVaultWide
      ? `This persistent lease will give "${this.agentName}" access to every non-hidden file in this vault until you log out, surviving Obsidian restarts. Writes still go through ${this.writeMode === "deny" ? "read-only enforcement" : "per-file confirmation"}. Re-enter your VaultGuard password to confirm.`
      : `This persistent lease will let "${this.agentName}" use scope ${scope} until you log out, surviving Obsidian restarts. Writes still go through ${this.writeMode === "deny" ? "read-only enforcement" : "per-file confirmation"}. Re-enter your VaultGuard password to confirm.`;
    return new Promise((resolve) => {
      const modal = new AtRestPasswordConfirmModal(this.app, {
        title: "Confirm persistent agent bridge lease",
        description,
        onVerify: (password) => this.plugin.verifyAccountPassword(password),
        onConfirmed: () => resolve(true),
      });
      const originalOnClose = modal.onClose.bind(modal);
      modal.onClose = () => {
        originalOnClose();
        // If the user closed without confirming, resolve(false). The
        // confirm path resolves(true) above before the modal closes.
        // Use a microtask to make sure both callbacks are visible to
        // settle the promise exactly once.
        window.setTimeout(() => resolve(false), 0);
      };
      modal.open();
    });
  }

  private buildMcpServerConfig(connection: BridgeConnection): string {
    return JSON.stringify(
      {
        mcpServers: {
          vaultguard: {
            type: "http",
            url: connection.mcpEndpoint,
            headers: {
              Authorization: `Bearer ${connection.token}`,
              "X-VaultGuard-Lease": connection.leaseId,
            },
          },
        },
      },
      null,
      2
    );
  }

  private renderCopyableBlock(
    parent: HTMLElement,
    opts: { title: string; description: string; json: string; copyLabel: string }
  ): void {
    const block = parent.createDiv({ cls: "vaultguard-agent-bridge-block" });
    block.createEl("h3", { text: opts.title });
    block.createEl("p", { text: opts.description, cls: "setting-item-description" });

    const codeBox = block.createEl("pre", {
      cls: "vaultguard-agent-bridge-connection",
    });
    codeBox.setText(opts.json);

    const buttons = block.createDiv({ cls: "vaultguard-modal-actions" });
    const copyBtn = new ButtonComponent(buttons);
    copyBtn
      .setButtonText(opts.copyLabel)
      .onClick(async () => {
        try {
          await navigator.clipboard.writeText(opts.json);
          new Notice(`${opts.title} copied to clipboard.`, 4000);
          copyBtn.setButtonText("Copied ✓");
          window.setTimeout(() => copyBtn.setButtonText(opts.copyLabel), 2000);
        } catch {
          // Select the contents so the user can hit Cmd/Ctrl+C.
          const doc = typeof activeDocument === "undefined" ? codeBox.ownerDocument : activeDocument;
          const range = doc.createRange();
          range.selectNodeContents(codeBox);
          const selection = doc.getSelection();
          selection?.removeAllRanges();
          selection?.addRange(range);
          new Notice(
            "Couldn't copy automatically — the JSON is selected, press Cmd/Ctrl+C.",
            6000
          );
        }
      });
  }
}
