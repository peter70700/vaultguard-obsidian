/**
 * @fileoverview Settings interface and settings tab for the VaultGuard plugin.
 * Provides a comprehensive settings UI for configuring the permission-aware
 * encrypted cloud sync system.
 */

import { App, ButtonComponent, Notice, Platform, PluginSettingTab, Setting } from "obsidian";
import {
  AtRestPasswordConfirmModal,
  AtRestRecoveryCodeModal,
  AtRestRestoreModal,
} from "./at-rest-modals";
import { AgentBridgeLeaseModal } from "./agent-bridge-modal";
import type VaultGuardPlugin from "./main";
import {
  VaultGuardSettings,
  CacheEncryptionStrength,
  ConflictResolutionStrategy,
  UserSession,
} from "../types";
import type { AnthropicEffort } from "../types";
import { AnthropicKeyStore } from "../ui/chat/api-key-store";
import { AI_CHAT_MODELS, AI_CHAT_EFFORTS, AI_CHAT_PERMISSION_MODES } from "../ui/chat/models";
import {
  getClaudeAuthStatus,
  type ClaudeAuthStatus,
} from "../ui/chat/claude-cli/claude-detector";
import type {
  UserListEntry,
  VaultKind,
  VaultMemberRecord,
  VaultMemberRole,
  VaultRecord,
} from "../api/client";
import type {
  AgentBridgeLeaseSecret,
  AgentBridgeLeaseSummary,
  AgentBridgeServerInfo,
} from "./agent-bridge";
import type { SkillInstallStatus } from "./agent-bridge-skill/installer";
import { SAAS_DEFAULTS } from "../config/saas-defaults";

// ─────────────────────────────────────────────────────────────────────────────
// Default Settings
// ─────────────────────────────────────────────────────────────────────────────

// Re-exported for callers that import SAAS_DEFAULTS from settings.
export { SAAS_DEFAULTS };

/**
 * Default plugin settings applied on first installation or when
 * individual settings are missing from persisted data.
 */

export const DEFAULT_EXCLUDED_PATHS = [
  ".trash",
] as const;

export const DEFAULT_SETTINGS: VaultGuardSettings = {
  orgSlug: "",
  serverVaultId: "",
  apiEndpoint: "",
  organizationId: "",
  cognitoUserPoolId: "",
  cognitoClientId: "",
  syncInterval: 30,
  cacheEncryptionStrength: "standard",
  offlineKeyLeaseDuration: 24,
  autoWipeOnAuthFailure: false,
  showMyPermissionLevel: true,
  showOthersAccess: true,
  showPermissionBanner: true,
  defaultConflictResolution: ConflictResolutionStrategy.ASK_USER,
  debugLogging: false,
  maxRetryAttempts: 3,
  showStatusBar: true,
  excludedPaths: [...DEFAULT_EXCLUDED_PATHS],
  aiChatModel: "claude-opus-4-8",
  aiChatEffort: "high",
  // On by default for live token-by-token feedback. Desktop-only; mobile always
  // falls back to the Tier-1 requestUrl path (see chat-view streamingEnabled()).
  aiChatStreaming: true,
  aiChatPermissionMode: "confirm",
  aiChatProvider: "apiKey",
  deletionTombstones: {},
};


const VAULT_KIND_LABELS: Record<VaultKind, string> = {
  team: "Team",
  personal: "Personal",
  shared: "Shared",
};

const VAULT_ROLE_LABELS: Record<VaultMemberRole, string> = {
  viewer: "Viewer (read only)",
  editor: "Editor (read + write)",
  admin: "Admin (full control)",
};

const VAULT_KINDS: VaultKind[] = ["team", "personal", "shared"];
const VAULT_ROLES: VaultMemberRole[] = ["viewer", "editor", "admin"];

interface UserLabelIdentity {
  email?: string;
  displayName?: string;
  name?: string;
}

interface AgentBridgeConnectionReveal {
  leaseId: string;
  agentName: string;
  connectionJson: string;
  mcpConfig: string;
  copiedToClipboard: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// Settings Tab
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Settings tab UI for the VaultGuard plugin.
 * Renders all configuration options organized by category with
 * descriptions and validation.
 */
export class VaultGuardSettingTab extends PluginSettingTab {
  private plugin: VaultGuardPlugin;
  private latestAgentBridgeReveal: AgentBridgeConnectionReveal | null = null;
  private aiChatKeyStore: AnthropicKeyStore;

  constructor(app: App, plugin: VaultGuardPlugin) {
    super(app, plugin);
    this.plugin = plugin;
    this.aiChatKeyStore = new AnthropicKeyStore(plugin);
  }

  /**
   * Renders the settings tab content. Called by Obsidian when
   * the user opens the plugin's settings panel.
   */
  private renderPluginAllowlistSection(containerEl: HTMLElement): void {
    const allowlist = this.plugin.settings.serverPluginAllowlist ?? [];
    const ignored = this.plugin.settings.pluginAllowlistIgnored ?? [];

    if (allowlist.length === 0 && ignored.length === 0) {
      return;
    }

    new Setting(containerEl)
      .setName("Plugin allowlist (vault-wide)")
      .setDesc(
        "Plugins your vault admin has approved for the team. Each entry prompts you " +
        "for consent once before being enabled in Obsidian; bytes themselves arrive " +
        "via the regular sync channel."
      )
      .addButton((button) =>
        button
          .setButtonText("Re-check vault plugins")
          .onClick(async () => {
            try {
              button.setDisabled(true);
              await this.plugin.runPluginAllowlistReconciliation();
              this.showStatus(containerEl, "Plugin allowlist reconciled.", false);
            } catch (err) {
              this.showStatus(
                containerEl,
                err instanceof Error ? err.message : "Reconcile failed.",
                true
              );
            } finally {
              button.setDisabled(false);
            }
          })
      );

    if (allowlist.length > 0) {
      const list = containerEl.createEl("ul", { cls: "vaultguard-allowlist-display" });
      for (const entry of allowlist) {
        const li = list.createEl("li");
        li.createEl("strong", { text: entry.displayName });
        if (entry.version) li.createSpan({ text: ` (v${entry.version})` });
        li.createSpan({ text: ` — ${entry.pluginId}` });
        if (entry.bundleSha256) {
          li.createSpan({
            text: " · 🔒 hash-pinned",
            cls: "vaultguard-allowlist-hash-pin",
          });
        }
      }
    }

    if (ignored.length > 0) {
      new Setting(containerEl)
        .setName("Ignored plugins on this device")
        .setDesc(
          "Plugins you previously chose 'Don't ask again' for. Unmute one to be " +
          "re-prompted on the next reconciliation."
        );
      for (const pluginId of ignored) {
        new Setting(containerEl)
          .setName(pluginId)
          .addButton((button) =>
            button
              .setButtonText("Unmute")
              .onClick(async () => {
                this.plugin.settings.pluginAllowlistIgnored = (this.plugin.settings.pluginAllowlistIgnored ?? [])
                  .filter((id) => id !== pluginId);
                await this.plugin.saveSettings();
                this.display();
              })
          );
      }
    }
  }

  private showStatus(containerEl: HTMLElement, message: string, isError: boolean): void {
    const existing = containerEl.querySelector('.vaultguard-status-msg');
    if (existing) existing.remove();
    const el = containerEl.createDiv({ cls: 'vaultguard-status-msg' });
    el.addClass(isError ? 'is-error' : 'is-success');
    el.setText(message);
    window.setTimeout(() => el.remove(), 6000);
  }

  /**
   * Renders the "Local at-rest encryption" panel. Surfaces the cipher's
   * current state (unlocked / needs-recovery / disabled), an on-disk file
   * tally, and the four operations a user might want from this UI:
   * full-vault encrypt, full-vault decrypt, view recovery code, restore
   * from recovery code. Re-rendered after every successful action so the
   * tally and status reflect what's actually on disk.
   */
  /**
   * AI Chat configuration: provider selection, encrypted Anthropic API key
   * (masked, never echoed), model + adaptive-thinking effort pickers, streaming
   * toggle, custom instructions, and prompt templates. The key field writes
   * through AnthropicKeyStore and NEVER renders the stored secret back into the
   * DOM — it only shows whether a
   * key is set and accepts a new one.
   *
   * TODO(ai-chat-feature-gate): there is no `aiChat` flag on ServerFeatures
   * yet, so we cannot gate this with `plugin.featureEnabled("aiChat")`. When a
   * server feature flag lands (AI-CHAT-PANEL.md §11), wrap this section in that
   * check. For now AI Chat is a settings-level capability and makes no model
   * call until the user stores a key or uses a logged-in Claude Code subscription.
   */
  private renderAiChatSection(containerEl: HTMLElement): void {
    new Setting(containerEl).setName("AI chat").setHeading();

    this.renderAiProviderBlock(containerEl);

    const hasKey = this.aiChatKeyStore.hasKey();

    // ── API key (masked, write-only) ────────────────────────────────────────
    new Setting(containerEl)
      .setName("Anthropic API key")
      .setDesc(
        hasKey
          ? "A key is stored and encrypted on this device. Enter a new key to replace it, or clear it. " +
            "The stored key is never displayed."
          : "Stored encrypted on this device (OS keychain, or the local at-rest key as a fallback). " +
            "Used only when you run the AI Chat. Never sent anywhere except Anthropic.",
      )
      .addText((text) => {
        text.setPlaceholder(hasKey ? "•••• key stored — enter to replace" : "sk-ant-...");
        // Mask input so the typed key is not shoulder-surfable. We never set
        // a value here, so the stored secret never re-enters the DOM.
        text.inputEl.type = "password";
        text.inputEl.autocomplete = "off";
        text.inputEl.setAttribute("autocapitalize", "off");
        text.inputEl.setAttribute("spellcheck", "false");

        const inputEl = text.inputEl;
        const settingEl = inputEl.closest(".setting-item");
        const controlEl = settingEl?.querySelector(".setting-item-control");
        if (!controlEl) return;

        const saveBtn = controlEl.createEl("button", {
          text: "Save",
          cls: "mod-cta vaultguard-inline-save-btn",
        });
        saveBtn.addEventListener("click", async () => {
          const newKey = inputEl.value.trim();
          if (!newKey) {
            this.showStatus(containerEl, "Enter an Anthropic API key first.", true);
            return;
          }
          saveBtn.disabled = true;
          saveBtn.textContent = "Saving...";
          try {
            await this.aiChatKeyStore.setKey(newKey);
            // Wipe the plaintext from the field immediately after storing.
            inputEl.value = "";
            this.showStatus(containerEl, "Anthropic API key saved.", false);
            this.display();
          } catch (error) {
            this.showStatus(
              containerEl,
              `Failed to save key: ${(error as Error).message}`,
              true,
            );
          } finally {
            saveBtn.disabled = false;
            saveBtn.textContent = "Save";
          }
        });

        if (hasKey) {
          const clearBtn = controlEl.createEl("button", {
            text: "Clear",
            cls: "vaultguard-inline-save-btn",
          });
          clearBtn.addEventListener("click", async () => {
            clearBtn.disabled = true;
            try {
              await this.aiChatKeyStore.clearKey();
              this.showStatus(containerEl, "Anthropic API key removed.", false);
              this.display();
            } catch (error) {
              this.showStatus(
                containerEl,
                `Failed to clear key: ${(error as Error).message}`,
                true,
              );
            } finally {
              clearBtn.disabled = false;
            }
          });
        }
      });

    // ── Model ───────────────────────────────────────────────────────────────
    new Setting(containerEl)
      .setName("Model")
      .setDesc("Anthropic model used for AI chat turns.")
      .addDropdown((dropdown) => {
        for (const m of AI_CHAT_MODELS) dropdown.addOption(m.id, m.label);
        dropdown
          .setValue(this.plugin.settings.aiChatModel)
          .onChange(async (value) => {
            this.plugin.settings.aiChatModel = value;
            await this.plugin.saveSettings();
          });
      });

    // ── Effort ──────────────────────────────────────────────────────────────
    new Setting(containerEl)
      .setName("Thinking effort")
      .setDesc("How much adaptive-thinking budget the model spends per turn.")
      .addDropdown((dropdown) => {
        for (const e of AI_CHAT_EFFORTS) dropdown.addOption(e.id, e.label);
        dropdown
          .setValue(this.plugin.settings.aiChatEffort)
          .onChange(async (value) => {
            this.plugin.settings.aiChatEffort = value as AnthropicEffort;
            await this.plugin.saveSettings();
          });
      });

    // ── Streaming (Tier 2 — opt-in, desktop-only) ───────────────────────────
    new Setting(containerEl)
      .setName("Stream responses")
      .setDesc("Desktop only; streams responses token-by-token as they arrive. On by default (mobile always uses the non-streaming path).")
      .addToggle((toggle) => {
        toggle
          .setValue(this.plugin.settings.aiChatStreaming)
          .onChange(async (value) => {
            this.plugin.settings.aiChatStreaming = value;
            await this.plugin.saveSettings();
          });
      });

    // ── Permissions ────────────────────────────────────────────────────────
    new Setting(containerEl)
      .setName("AI chat permissions")
      .setDesc(
        "Choose whether AI-created writes need a manual diff confirmation. Skip mode is for trusted sessions; " +
          "VaultGuard still enforces vault scope, hidden-path blocks, and your server-side file permissions.",
      )
      .addDropdown((dropdown) => {
        for (const mode of AI_CHAT_PERMISSION_MODES) {
          dropdown.addOption(mode.id, mode.label);
        }
        dropdown
          .setValue(this.plugin.settings.aiChatPermissionMode)
          .onChange(async (value) => {
            this.plugin.settings.aiChatPermissionMode = value === "skip" ? "skip" : "confirm";
            await this.plugin.saveSettings();
          });
      });

    // ── Custom instructions (appended to the system prompt; API-key mode) ────
    new Setting(containerEl)
      .setName("Custom instructions")
      .setDesc(
        "Optional instructions appended to the assistant's system prompt (e.g. tone, formatting, " +
          "project conventions). They never override the built-in security and permission rules. " +
          "Applies in API-key mode.",
      )
      .addTextArea((ta) => {
        ta.setPlaceholder("e.g. Answer concisely. Prefer bullet points. Use British spelling.");
        ta.setValue(this.plugin.settings.aiChatSystemPrompt ?? "");
        ta.inputEl.rows = 4;
        ta.inputEl.addClass("vaultguard-chat-system-prompt-input");
        ta.onChange(async (value) => {
          const trimmed = value.trim();
          this.plugin.settings.aiChatSystemPrompt = trimmed.length > 0 ? value : undefined;
          await this.plugin.saveSettings();
        });
      });

    this.renderPromptTemplates(containerEl);
  }

  /**
   * Editor for user-defined chat prompt templates. Each row is a command name +
   * prompt body; `{{input}}` in the body is replaced with any text the user
   * types after the command. Optional frontmatter can set description,
   * argument-hint, and `kind: skill` (shown under `$`). Built-ins cannot be
   * shadowed — that is enforced in the chat input parser, not here.
   */
  private renderPromptTemplates(containerEl: HTMLElement): void {
    const templates = this.plugin.settings.aiChatPromptTemplates ?? [];

    new Setting(containerEl)
      .setName("Prompt templates")
      .setDesc(
        "Reusable chat commands and skills. Use /summarize for normal templates, or add " +
          "frontmatter with kind: skill to show a template as $name. Built-in Obsidian skills " +
          "such as $format-note and $frontmatter are available automatically.",
      )
      .addButton((btn) =>
        btn
          .setButtonText("Add template")
          .setCta()
          .onClick(async () => {
            const next = [...(this.plugin.settings.aiChatPromptTemplates ?? [])];
            next.push({ name: "", prompt: "" });
            this.plugin.settings.aiChatPromptTemplates = next;
            await this.plugin.saveSettings();
            this.display();
          }),
      );

    templates.forEach((tpl, index) => {
      const setting = new Setting(containerEl).setClass("vaultguard-chat-template-row");
      setting.addText((text) =>
        text
          .setPlaceholder("name (no / or $)")
          .setValue(tpl.name)
          .onChange(async (value) => {
            const next = [...(this.plugin.settings.aiChatPromptTemplates ?? [])];
            next[index] = { ...next[index], name: value.trim().replace(/^\/+/, "") };
            this.plugin.settings.aiChatPromptTemplates = next;
            await this.plugin.saveSettings();
          }),
      );
      setting.addTextArea((ta) => {
        ta.setPlaceholder("Prompt body — use {{input}}; optional frontmatter: description, argument-hint, kind: skill");
        ta.setValue(tpl.prompt);
        ta.inputEl.rows = 2;
        ta.onChange(async (value) => {
          const next = [...(this.plugin.settings.aiChatPromptTemplates ?? [])];
          next[index] = { ...next[index], prompt: value };
          this.plugin.settings.aiChatPromptTemplates = next;
          await this.plugin.saveSettings();
        });
      });
      setting.addExtraButton((btn) =>
        btn
          .setIcon("trash")
          .setTooltip("Remove template")
          .onClick(async () => {
            const next = [...(this.plugin.settings.aiChatPromptTemplates ?? [])];
            next.splice(index, 1);
            this.plugin.settings.aiChatPromptTemplates = next;
            await this.plugin.saveSettings();
            this.display();
          }),
      );
    });
  }

  /**
   * AI provider chooser + live subscription-detector status. The "subscription"
   * provider drives the official Claude Code CLI with the user's own Claude
   * Pro/Max login — the plugin NEVER handles the subscription token. The status
   * line runs `claude auth status --json` (read-only, no token touched), and the
   * "Sign in" button spawns `claude auth login` so the user authenticates in
   * Anthropic's own browser flow. Desktop-only; on mobile we show a fallback note
   * and the provider is forced to the API key.
   */
  private renderAiProviderBlock(containerEl: HTMLElement): void {
    const onMobile = Platform.isMobileApp;

    new Setting(containerEl)
      .setName("AI provider")
      .setDesc(
        "Choose how AI Chat talks to Claude. Subscription mode uses your own Claude Code login " +
          "(no API key, no per-token charge) and is desktop only; the plugin never handles your " +
          "subscription token.",
      )
      .addDropdown((dropdown) => {
        dropdown.addOption("subscription", "Claude subscription (Claude Code CLI)");
        dropdown.addOption("apiKey", "Anthropic API key");
        dropdown
          .setValue(this.plugin.settings.aiChatProvider)
          .onChange(async (value) => {
            this.plugin.settings.aiChatProvider = value === "subscription" ? "subscription" : "apiKey";
            this.plugin.settings.aiChatProviderExplicit = true;
            await this.plugin.saveSettings();
            // Re-render so the status line / API-key field reflect the choice.
            this.display();
          });
        if (onMobile) dropdown.setDisabled(true);
      });

    if (this.plugin.settings.aiChatProvider !== "subscription") return;

    // Status line + actions container (populated asynchronously by the detector).
    const statusSetting = new Setting(containerEl)
      .setName("Claude Code status")
      .setDesc("Checking…");

    if (onMobile) {
      statusSetting.setDesc(
        "Subscription mode needs desktop Obsidian — switch to an API key to chat on mobile.",
      );
      return;
    }

    void this.refreshClaudeStatus(statusSetting);
  }

  private async refreshClaudeStatus(statusSetting: Setting): Promise<void> {
    let status: ClaudeAuthStatus;
    try {
      status = await getClaudeAuthStatus();
    } catch (e) {
      statusSetting.setDesc(`Could not check Claude Code: ${(e as Error).message}`);
      return;
    }

    // Clear any prior action buttons before repopulating.
    statusSetting.clear();
    statusSetting.setName("Claude Code status");

    switch (status.classification) {
      case "logged-in-subscription": {
        const tier = status.subscriptionType
          ? status.subscriptionType.charAt(0).toUpperCase() + status.subscriptionType.slice(1)
          : "subscription";
        statusSetting.setDesc(
          `Signed in — ${tier} subscription${status.email ? ` (${status.email})` : ""}. ` +
            "Chat will use your Claude Code login; no API key needed.",
        );
        break;
      }
      case "logged-in-apikey": {
        statusSetting.setDesc(
          "Claude Code is signed in with an API key, not a Claude.ai subscription. " +
            "Sign in with your subscription to avoid per-token charges, or use the API-key provider.",
        );
        statusSetting.addButton((btn) =>
          btn.setButtonText("Sign in with subscription").onClick(() => void this.runClaudeLogin(statusSetting)),
        );
        break;
      }
      case "not-logged-in": {
        statusSetting.setDesc(
          "Claude Code is installed but not signed in. Sign in to use your Claude subscription.",
        );
        statusSetting.addButton((btn) =>
          btn
            .setButtonText("Sign in")
            .setCta()
            .onClick(() => void this.runClaudeLogin(statusSetting)),
        );
        break;
      }
      case "not-installed": {
        statusSetting.setDesc(
          "Claude Code CLI not found. Install it (npm i -g @anthropic-ai/claude-code, or see " +
            "code.claude.com/docs/setup), then re-open settings.",
        );
        break;
      }
      case "unsupported": {
        statusSetting.setDesc(
          status.error ?? "Subscription mode is unavailable in this runtime — use an API key.",
        );
        break;
      }
      case "error":
      default: {
        statusSetting.setDesc(
          `Could not determine Claude Code status${status.error ? `: ${status.error}` : "."}`,
        );
        break;
      }
    }
  }

  /**
   * Spawn `claude auth login` so the user signs in through Anthropic's own
   * browser OAuth flow, then re-check status. The plugin never reads the token;
   * `claude` stores it in its own keychain.
   */
  private async runClaudeLogin(statusSetting: Setting): Promise<void> {
    statusSetting.setDesc("Opening Claude Code sign-in… complete it in the window/browser that opens.");
    try {
      await this.plugin.startClaudeCliLogin();
    } catch (e) {
      statusSetting.setDesc(`Could not start Claude Code sign-in: ${(e as Error).message}`);
      return;
    }
    // Re-check after the login subprocess finishes.
    await this.refreshClaudeStatus(statusSetting);
  }

  /**
   * Wraps a group of settings in a native <details>/<summary> disclosure so
   * heavy, rarely-touched sections can default to collapsed and reduce the
   * settings-tab scroll. The summary is a plain-text label (NOT a setHeading —
   * a <summary> cannot host an Obsidian Setting); the builder writes into the
   * body div, where the existing render* helpers keep emitting their own
   * setHeading() labels unchanged. Defaults to CLOSED (no `open` attribute) by
   * design. Native <details> open/closed state is browser-managed and resets on
   * each this.display() re-render — accepted tradeoff for this mechanism.
   * Styling is class-only (no `.style` assignments) per CLAUDE.md / Obsidian review.
   */
  private renderCollapsibleSection(
    containerEl: HTMLElement,
    label: string,
    builder: (bodyEl: HTMLElement) => void
  ): void {
    const details = containerEl.createEl("details", {
      cls: "vaultguard-settings-section",
    });
    details.createEl("summary", {
      text: label,
      cls: "vaultguard-settings-section-summary",
    });
    const bodyEl = details.createDiv({ cls: "vaultguard-settings-section-body" });
    builder(bodyEl);
  }

  private renderAtRestSection(containerEl: HTMLElement): void {
    new Setting(containerEl).setName("Local at-rest encryption").setHeading();
    const atRestDesc = Platform.isMobileApp
      ? "Vault files on this device are encrypted on disk with a per-device key kept in this app's secure storage. Without VaultGuard Sync running, the files on disk are ciphertext — useful if your phone backs up app data to iCloud / Google Drive."
      : "Vault files on this device are encrypted on disk with a key bound to your OS keychain (or, if unavailable, a per-device key). Without VaultGuard Sync running, opening files in Finder shows ciphertext.";
    containerEl.createEl("p", {
      text: atRestDesc,
      cls: "setting-item-description",
    });

    const status = this.plugin.getAtRestStatus();
    const panel = containerEl.createDiv({ cls: "vaultguard-at-rest-panel" });
    this.renderAtRestStatusBadge(panel, status);

    const tallyEl = panel.createDiv({
      cls: "vaultguard-at-rest-tally setting-item-description",
    });
    tallyEl.setText("Counting files…");
    void this.plugin
      .tallyAtRestState()
      .then((tally) => {
        const summary =
          `${tally.encrypted} encrypted, ${tally.plaintext} plaintext, ` +
          `${tally.excluded} excluded` +
          (tally.failed > 0 ? `, ${tally.failed} unreadable` : "") +
          ` (${tally.total} files total).`;
        tallyEl.setText(summary);
        if (tally.plaintext > 0 && status.kind === "unlocked") {
          tallyEl.createDiv({
            cls: "vaultguard-at-rest-tally-warning",
            text: `${tally.plaintext} file(s) are still plaintext. Click "Encrypt all files now" to migrate them.`,
          });
        }
      })
      .catch((err) => {
        tallyEl.setText(
          `Could not count vault files: ${err instanceof Error ? err.message : String(err)}`
        );
        tallyEl.addClass("vaultguard-at-rest-tally-error");
      });

    const isUnlocked = status.kind === "unlocked";
    const needsRecovery = status.kind === "needs-recovery";

    const encryptSetting = new Setting(panel)
      .setName("Encrypt all files now")
      .setDesc(
        "Walks the vault and rewrites any plaintext files as ciphertext. Idempotent — files already encrypted are skipped."
      )
      .addButton((button) => {
        button
          .setButtonText("Encrypt vault")
          .setCta()
          .setDisabled(!isUnlocked)
          .onClick(async () => {
            button.setButtonText("Encrypting…").setDisabled(true);
            try {
              await this.plugin.migrateVaultToAtRest();
              this.showStatus(containerEl, "Vault encryption pass complete.", false);
            } catch (err) {
              this.showStatus(
                containerEl,
                `Encryption failed: ${(err as Error).message}`,
                true
              );
            } finally {
              this.display();
            }
          });
      });
    encryptSetting.settingEl.addClass("vaultguard-at-rest-action");

    const session = this.plugin.getSession();
    const canReauth = isUnlocked && Boolean(session);
    const reauthDisabledHint = !session
      ? " Log in to your VaultGuard account to enable this action — re-authentication is required so a brief unattended-laptop moment can't expose your at-rest key."
      : "";

    const decryptSetting = new Setting(panel)
      .setName("Decrypt all files (revert to plaintext)")
      .setDesc(
        "Reverse the at-rest encryption. Use this before disabling the plugin if you want the vault folder to remain readable through normal tools. Requires re-entering your account password — a logged-in but unattended Obsidian shouldn't be able to silently drop your at-rest protection." +
          reauthDisabledHint
      )
      .addButton((button) => {
        button
          .setButtonText("Decrypt vault")
          .setWarning()
          .setDisabled(!canReauth)
          .onClick(() => {
            new AtRestPasswordConfirmModal(this.app, {
              title: "Confirm: decrypt vault on this device",
              description:
                "This will rewrite every encrypted file in your vault back to plaintext. Anyone with disk access (or another logged-in user on this Mac) will then be able to read your notes through Finder. Re-enter your account password to confirm you're the one doing this.",
              onVerify: (pw) => this.plugin.verifyAccountPassword(pw),
              onConfirmed: () => {
                void (async () => {
                  button.setButtonText("Decrypting…").setDisabled(true);
                  try {
                    await this.plugin.revertVaultFromAtRest();
                    this.showStatus(containerEl, "Vault decryption pass complete.", false);
                  } catch (err) {
                    this.showStatus(
                      containerEl,
                      `Decryption failed: ${(err as Error).message}`,
                      true
                    );
                  } finally {
                    this.display();
                  }
                })();
              },
            }).open();
          });
      });
    decryptSetting.settingEl.addClass("vaultguard-at-rest-action");

    const recoverySetting = new Setting(panel)
      .setName("Recovery code")
      .setDesc(
        "Show the recovery code that lets you decrypt the files on this device after a keychain reset, OS reinstall, or move to a new machine. The code is unique to this device — every member, and every device per member, has its own. Requires re-entering your account password before display." +
          reauthDisabledHint
      )
      .addButton((button) =>
        button
          .setButtonText("View recovery code")
          .setDisabled(!canReauth)
          .onClick(() => {
            new AtRestPasswordConfirmModal(this.app, {
              title: "Confirm: reveal recovery code",
              description:
                "Anyone holding this code can decrypt every file on this device. Enter your account password to confirm before it's shown.",
              onVerify: (pw) => this.plugin.verifyAccountPassword(pw),
              onConfirmed: () => {
                void (async () => {
                  try {
                    const code = await this.plugin.exportAtRestRecoveryCode();
                    new AtRestRecoveryCodeModal(this.app, { code }).open();
                  } catch (err) {
                    this.showStatus(
                      containerEl,
                      `Could not export recovery code: ${(err as Error).message}`,
                      true
                    );
                  }
                })();
              },
            }).open();
          })
      );
    recoverySetting.settingEl.addClass("vaultguard-at-rest-action");

    const restoreSetting = new Setting(panel)
      .setName("Restore from recovery code")
      .setDesc(
        needsRecovery
          ? "This vault contains encrypted files that this device cannot decrypt. Paste the recovery code you saved when at-rest encryption was first set up to regain access."
          : "Use this on a new computer or after reinstalling. Replaces the local at-rest key with the one encoded in the recovery code."
      )
      .addButton((button) => {
        const btn = button.setButtonText("Enter recovery code…");
        if (needsRecovery) btn.setCta();
        btn.onClick(() => {
          new AtRestRestoreModal(this.app, {
            onSubmit: (code) => this.plugin.restoreAtRestFromRecoveryCode(code),
            onRestored: () => {
              new Notice(
                "VaultGuard Sync: at-rest key restored. Reopening any open notes will now load decrypted content.",
                7000
              );
              this.display();
            },
          }).open();
        });
      });
    restoreSetting.settingEl.addClass("vaultguard-at-rest-action");
  }

  /**
   * Renders the colored status badge at the top of the at-rest panel.
   * Mirrors the union variants of `AtRestStatus` so the icon and copy
   * always match the cipher's actual state — drift between the two has
   * caused real "is it on or not?" support questions on similar plugins.
   */
  private renderAtRestStatusBadge(
    parent: HTMLElement,
    status: ReturnType<VaultGuardPlugin["getAtRestStatus"]>
  ): void {
    const badge = parent.createDiv({ cls: "vaultguard-at-rest-status" });
    badge.addClass(`vaultguard-at-rest-status-${status.kind}`);

    let title = "";
    let body = "";

    switch (status.kind) {
      case "unlocked":
        title = "Active";
        body =
          status.method === "safe-storage"
            ? "Encryption key is sealed in your OS keychain. Strongest protection available on this device."
            : status.method === "localstorage-fallback"
              ? "Encryption key is stored in this Electron profile (OS keychain unavailable). Files in Finder are encrypted, but a full Electron-profile theft can recover the key. See docs/AT-REST-ENCRYPTION.md."
              : "Encryption key is in memory only (no persistent storage detected). Files written this session won't be readable after a restart.";
        if (status.method !== "safe-storage") {
          badge.addClass("vaultguard-at-rest-status-warning");
        }
        break;
      case "uninitialized":
        title = "Initializing";
        body = "VaultGuard Sync is setting up the local at-rest cipher.";
        break;
      case "locked":
        title = "Locked";
        body =
          "The at-rest cipher is currently locked. This usually clears itself on the next plugin load.";
        break;
      case "needs-recovery":
        title = "Needs recovery";
        body = status.reason;
        break;
      case "disabled":
        title = "Disabled";
        body = status.reason;
        break;
    }

    badge.createDiv({ cls: "vaultguard-at-rest-status-title", text: title });
    badge.createDiv({ cls: "vaultguard-at-rest-status-body", text: body });
  }

  private renderCurrentVaultSettings(containerEl: HTMLElement, session: UserSession | null): void {
    new Setting(containerEl).setName("Vault").setHeading();
    const sectionEl = containerEl.createDiv({ cls: "vaultguard-current-vault-settings" });

    if (!session) {
      new Setting(sectionEl)
        .setName("Not connected")
        .setDesc("Log in from the account section above to view, bind, create, or change server vaults.");
      return;
    }

    sectionEl.createDiv({
      text: "Loading vault settings…",
      cls: "setting-item-description vaultguard-current-vault-loading",
    });
    void this.renderCurrentVaultSettingsContent(sectionEl, containerEl, session);
  }

  private async renderCurrentVaultSettingsContent(
    sectionEl: HTMLElement,
    rootEl: HTMLElement,
    session: UserSession
  ): Promise<void> {
    let vaults: VaultRecord[] = [];
    let vaultListError: unknown = null;
    let currentVault: VaultRecord | null = null;
    let currentVaultError: unknown = null;
    let memberRole: VaultMemberRole | null = null;

    try {
      vaults = await this.plugin.listServerVaults();
    } catch (error) {
      vaultListError = error;
    }

    if (this.plugin.settings.serverVaultId) {
      try {
        currentVault = await this.plugin.getCurrentVaultRecord();
        memberRole = await this.plugin.getCurrentVaultMemberRole().catch(() => null);
      } catch (error) {
        currentVaultError = error;
      }
    }

    sectionEl.empty();

    // The current-vault summary (name/desc + Refresh/Switch/Permissions
    // buttons) stays VISIBLE on sectionEl. It is emitted into its own container
    // FIRST so it precedes the disclosure in the DOM. The heavier sub-sections
    // (Available vaults list, Create vault, Current vault options, Vault members)
    // move into a single "Manage vaults & members" disclosure to reduce overwhelm.
    const summaryEl = sectionEl.createDiv({ cls: "vaultguard-current-vault-summary" });
    this.renderCollapsibleSection(sectionEl, "Manage vaults & members", (manageBody) => {
      this.renderVaultBindingSettings(
        summaryEl,
        manageBody,
        sectionEl,
        rootEl,
        session,
        vaults,
        vaultListError,
        currentVault,
        currentVaultError,
        memberRole
      );

      if (currentVault) {
        this.renderLoadedVaultSettings(manageBody, sectionEl, rootEl, session, currentVault, memberRole);
        this.renderVaultMembersSettings(manageBody, sectionEl, rootEl, session, currentVault, memberRole);
      }

      this.renderCreateVaultSettings(manageBody, rootEl, session);
    });
  }

  private renderVaultBindingSettings(
    summaryEl: HTMLElement,
    listEl: HTMLElement,
    sectionEl: HTMLElement,
    rootEl: HTMLElement,
    session: UserSession,
    vaults: VaultRecord[],
    vaultListError: unknown,
    currentVault: VaultRecord | null,
    currentVaultError: unknown,
    memberRole: VaultMemberRole | null
  ): void {
    const cachedName = this.plugin.settings.serverVaultName || "Bound server vault";
    const cachedSlug = this.plugin.settings.serverVaultSlug;
    const boundId = this.plugin.settings.serverVaultId;
    const roleLabel = memberRole ? VAULT_ROLE_LABELS[memberRole] : "not a direct member";
    const currentDesc = currentVault
      ? [
          `${VAULT_KIND_LABELS[currentVault.kind]} · ${currentVault.slug}`,
          `Default role: ${VAULT_ROLE_LABELS[currentVault.defaultRole]}`,
          `Your vault role: ${roleLabel}`,
          currentVault.archived ? "Archived/read-only" : "Active",
        ].join(" · ")
      : boundId
        ? [
            cachedSlug ? `Slug: ${cachedSlug}` : null,
            `Vault ID: ${boundId}`,
            currentVaultError
              ? `Could not refresh details: ${this.errorMessage(currentVaultError)}`
              : null,
          ].filter((value): value is string => Boolean(value)).join(" · ")
        : "This Obsidian folder is not linked to a server-side vault yet.";

    new Setting(summaryEl)
      .setName(currentVault ? currentVault.name : boundId ? cachedName : "Bound server vault")
      .setDesc(currentDesc)
      .addButton((button) =>
        button
          .setButtonText("Refresh")
          .onClick(() => {
            void this.renderCurrentVaultSettingsContent(sectionEl, rootEl, session);
          })
      )
      .addButton((button) =>
        button
          .setButtonText(boundId ? "Switch vault" : "Pick vault")
          .setCta()
          .onClick(async () => {
            await this.handleSwitchVault(rootEl, button, boundId ? "Switch vault" : "Pick vault");
          })
      );

    if (boundId) {
      new Setting(summaryEl)
        .setName("Permissions")
        .setDesc(
          "View and manage every permission rule for this vault — the same table-style configuration as the web admin panel. (The per-file controls in the editor header are separate.)"
        )
        .addButton((button) =>
          button
            .setButtonText("Manage permissions")
            .setCta()
            .onClick(() => this.plugin.showPermissionRulesModal())
        );
    }

    if (currentVault?.description) {
      summaryEl.createDiv({
        text: currentVault.description,
        cls: "setting-item-description vaultguard-current-vault-description",
      });
    }

    if (boundId) {
      summaryEl.createDiv({
        text: `Vault ID: ${boundId}`,
        cls: "setting-item-description vaultguard-current-vault-id",
      });
    }

    new Setting(listEl).setName("Available vaults").setHeading();

    if (vaultListError) {
      new Setting(listEl)
        .setName("Could not load vault list")
        .setDesc(this.errorMessage(vaultListError));
      return;
    }

    if (vaults.length === 0) {
      new Setting(listEl)
        .setName("No vaults available")
        .setDesc(
          this.isOrgAdmin(session)
            ? "Create a server vault below, then bind this Obsidian folder to it."
            : "Ask an organization admin to add you to a vault."
        );
      return;
    }

    for (const vault of vaults) {
      const isBound = this.plugin.settings.serverVaultId === vault.vaultId;
      const desc = [
        `${VAULT_KIND_LABELS[vault.kind]} · ${vault.slug}`,
        `Default role: ${VAULT_ROLE_LABELS[vault.defaultRole]}`,
        vault.archived ? "Archived" : "Active",
      ].join(" · ");

      new Setting(listEl)
        .setName(isBound ? `${vault.name} (bound)` : vault.name)
        .setDesc(desc)
        .addButton((button) => {
          button
            .setButtonText(isBound ? "Bound" : "Bind")
            .setDisabled(isBound || vault.archived)
            .onClick(async () => {
              button.setButtonText("Binding...");
              button.setDisabled(true);
              try {
                const changed = await this.plugin.bindServerVault({
                  vaultId: vault.vaultId,
                  name: vault.name,
                  slug: vault.slug,
                });
                this.showStatus(
                  rootEl,
                  changed
                    ? "Vault binding updated. Sync will reconcile this folder with the selected vault."
                    : "Vault binding unchanged.",
                  false
                );
                this.display();
              } catch (error) {
                this.showStatus(rootEl, `Failed to bind vault: ${this.errorMessage(error)}`, true);
                button.setButtonText("Bind");
                button.setDisabled(false);
              }
            });
        });
    }
  }

  private renderCreateVaultSettings(
    bodyEl: HTMLElement,
    rootEl: HTMLElement,
    session: UserSession
  ): void {
    new Setting(bodyEl).setName("Create vault").setHeading();

    if (!this.isOrgAdmin(session)) {
      new Setting(bodyEl)
        .setName("New vaults")
        .setDesc("Only organization admins and owners can create server vaults.");
      return;
    }

    let nextName = this.app.vault.getName() || "My Vault";
    let nextDescription = "";
    let nextKind: VaultKind = "team";
    let nextDefaultRole: VaultMemberRole = "editor";

    new Setting(bodyEl)
      .setName("Name")
      .setDesc("Display name for the new server vault.")
      .addText((text) =>
        text
          .setPlaceholder("Engineering Notes")
          .setValue(nextName)
          .onChange((value) => {
            nextName = value;
          })
      );

    new Setting(bodyEl)
      .setName("Description")
      .setDesc("Optional note about what belongs in this vault.")
      .addTextArea((text) => {
        text
          .setPlaceholder("Team notes, specs, and runbooks")
          .setValue(nextDescription)
          .onChange((value) => {
            nextDescription = value;
          });
        text.inputEl.rows = 2;
      });

    new Setting(bodyEl)
      .setName("Kind")
      .setDesc("Used for labelling vaults in admin and plugin views.")
      .addDropdown((dropdown) => {
        for (const kind of VAULT_KINDS) {
          dropdown.addOption(kind, VAULT_KIND_LABELS[kind]);
        }
        dropdown
          .setValue(nextKind)
          .onChange((value) => {
            nextKind = value as VaultKind;
          });
      });

    new Setting(bodyEl)
      .setName("Default role for new members")
      .setDesc("Used when a vault admin adds a member without choosing a specific role.")
      .addDropdown((dropdown) => {
        for (const role of VAULT_ROLES) {
          dropdown.addOption(role, VAULT_ROLE_LABELS[role]);
        }
        dropdown
          .setValue(nextDefaultRole)
          .onChange((value) => {
            nextDefaultRole = value as VaultMemberRole;
          });
      });

    new Setting(bodyEl)
      .setName("Create and bind")
      .setDesc("Creates the vault, adds you as its admin, and links this Obsidian folder to it.")
      .addButton((button) =>
        button
          .setButtonText("Create vault")
          .setCta()
          .onClick(async () => {
            const trimmedName = nextName.trim();
            if (!trimmedName) {
              this.showStatus(rootEl, "Vault name cannot be empty.", true);
              return;
            }

            button.setButtonText("Creating...");
            button.setDisabled(true);
            try {
              const vault = await this.plugin.createServerVault({
                name: trimmedName,
                ...(nextDescription.trim() ? { description: nextDescription.trim() } : {}),
                kind: nextKind,
                defaultRole: nextDefaultRole,
              });
              await this.plugin.bindServerVault({
                vaultId: vault.vaultId,
                name: vault.name,
                slug: vault.slug,
              });
              this.showStatus(rootEl, `Created and bound to "${vault.name}".`, false);
              this.display();
            } catch (error) {
              this.showStatus(rootEl, `Failed to create vault: ${this.errorMessage(error)}`, true);
              button.setButtonText("Create vault");
              button.setDisabled(false);
            }
          })
      );
  }

  private renderLoadedVaultSettings(
    bodyEl: HTMLElement,
    sectionEl: HTMLElement,
    rootEl: HTMLElement,
    session: UserSession,
    vault: VaultRecord,
    memberRole: VaultMemberRole | null
  ): void {
    const canEdit = this.canManageVault(session, memberRole);
    const canArchive = this.isOrgAdmin(session);

    new Setting(bodyEl).setName("Vault details").setHeading();

    if (!canEdit) {
      new Setting(bodyEl)
        .setName("Vault metadata")
        .setDesc("Only vault admins, organization admins, and owners can edit the vault name, description, and default role.");
      return;
    }

    let nextName = vault.name;
    let nextDescription = vault.description ?? "";
    let nextDefaultRole: VaultMemberRole = vault.defaultRole;

    new Setting(bodyEl)
      .setName("Name")
      .setDesc("Display name shown in VaultGuard vault lists.")
      .addText((text) =>
        text
          .setValue(nextName)
          .onChange((value) => {
            nextName = value;
          })
      );

    new Setting(bodyEl)
      .setName("Description")
      .setDesc("Short note about what belongs in this vault.")
      .addTextArea((text) => {
        text
          .setValue(nextDescription)
          .onChange((value) => {
            nextDescription = value;
          });
        text.inputEl.rows = 3;
      });

    new Setting(bodyEl)
      .setName("Default role for new members")
      .setDesc("Used when a vault admin adds a member without choosing a specific role.")
      .addDropdown((dropdown) => {
        for (const role of VAULT_ROLES) {
          dropdown.addOption(role, VAULT_ROLE_LABELS[role]);
        }
        dropdown
          .setValue(nextDefaultRole)
          .onChange((value) => {
            nextDefaultRole = value as VaultMemberRole;
          });
      });

    new Setting(bodyEl)
      .setName("Save vault settings")
      .setDesc(vault.archived ? "Reactivate this vault before changing metadata." : "Updates server-side vault metadata for every member.")
      .addButton((button) =>
        button
          .setButtonText("Save")
          .setCta()
          .setDisabled(vault.archived)
          .onClick(async () => {
            const trimmedName = nextName.trim();
            if (!trimmedName) {
              this.showStatus(rootEl, "Vault name cannot be empty.", true);
              return;
            }

            button.setButtonText("Saving...");
            button.setDisabled(true);
            try {
              await this.plugin.updateCurrentVault({
                name: trimmedName,
                description: nextDescription.trim(),
                defaultRole: nextDefaultRole,
              });
              this.showStatus(rootEl, "Vault settings updated.", false);
              await this.renderCurrentVaultSettingsContent(sectionEl, rootEl, session);
            } catch (error) {
              this.showStatus(rootEl, `Failed to update vault: ${this.errorMessage(error)}`, true);
              button.setButtonText("Save");
              button.setDisabled(false);
            }
          })
      );

    if (canArchive) {
      new Setting(bodyEl)
        .setName(vault.archived ? "Reactivate vault" : "Archive vault")
        .setDesc(
          vault.archived
            ? "Makes this vault active again so members can sync and edit according to their permissions."
            : "Archives this vault. Members keep metadata visibility, but write and sync operations become read-only."
        )
        .addButton((button) =>
          button
            .setButtonText(vault.archived ? "Reactivate" : "Archive")
            .setWarning()
            .onClick(async () => {
              if (!vault.archived) {
                const confirmed = await this.showDestructiveConfirmation(
                  rootEl,
                  "ARCHIVE VAULT",
                  "Type ARCHIVE VAULT to confirm. This will make the current server vault read-only."
                );
                if (!confirmed) return;
              }

              button.setButtonText(vault.archived ? "Reactivating..." : "Archiving...");
              button.setDisabled(true);
              try {
                await this.plugin.updateCurrentVault({ archived: !vault.archived });
                this.showStatus(rootEl, vault.archived ? "Vault reactivated." : "Vault archived.", false);
                await this.renderCurrentVaultSettingsContent(sectionEl, rootEl, session);
              } catch (error) {
                this.showStatus(rootEl, `Failed to update archive status: ${this.errorMessage(error)}`, true);
                button.setButtonText(vault.archived ? "Reactivate" : "Archive");
                button.setDisabled(false);
              }
            })
        );
    }
  }

  private renderVaultMembersSettings(
    bodyEl: HTMLElement,
    sectionEl: HTMLElement,
    rootEl: HTMLElement,
    session: UserSession,
    vault: VaultRecord,
    memberRole: VaultMemberRole | null
  ): void {
    new Setting(bodyEl).setName("Vault members").setHeading();

    const membersEl = bodyEl.createDiv({ cls: "vaultguard-vault-members" });
    membersEl.createDiv({
      text: "Loading vault members…",
      cls: "setting-item-description vaultguard-current-vault-loading",
    });

    void this.renderVaultMembersContent(membersEl, sectionEl, rootEl, session, vault, memberRole);
  }

  private async renderVaultMembersContent(
    membersEl: HTMLElement,
    sectionEl: HTMLElement,
    rootEl: HTMLElement,
    session: UserSession,
    vault: VaultRecord,
    memberRole: VaultMemberRole | null
  ): Promise<void> {
    try {
      const [members, usersResult] = await Promise.all([
        this.plugin.listCurrentVaultMembers(),
        this.plugin.listOrganizationUsers()
          .then((users) => ({ users, error: null as unknown }))
          .catch((error) => ({ users: [] as UserListEntry[], error })),
      ]);
      const canManage = this.canManageVault(session, memberRole) && !vault.archived;
      const users = usersResult.users;
      const userById = this.buildVaultMemberUserLabelMap(members);
      userById.set(session.userId, {
        email: session.email,
        displayName: session.displayName,
        name: session.displayName,
      });
      for (const user of users) {
        userById.set(user.id, user);
      }
      const allMembersHaveLabels = members.every((member) => userById.has(member.userId));

      membersEl.empty();
      if (usersResult.error && (canManage || !allMembersHaveLabels)) {
        new Setting(membersEl)
          .setName(canManage ? "Add-member directory unavailable" : "User directory unavailable")
          .setDesc(
            allMembersHaveLabels
              ? `Existing members use vault member names. ${this.errorMessage(usersResult.error)}`
              : `Members without vault member names are shown by ID. ${this.errorMessage(usersResult.error)}`
          );
      }

      if (members.length === 0) {
        new Setting(membersEl)
          .setName("No members")
          .setDesc("This vault does not have any explicit members yet.");
      }

      for (const member of members) {
        this.renderVaultMemberRow(membersEl, sectionEl, rootEl, session, vault, member, userById, canManage);
      }

      if (vault.archived) {
        new Setting(membersEl)
          .setName("Add member")
          .setDesc("Archived vaults are read-only. Reactivate this vault before changing membership.");
        return;
      }

      if (!canManage) {
        new Setting(membersEl)
          .setName("Add member")
          .setDesc("Only vault admins, organization admins, and owners can add or remove vault members.");
        return;
      }

      this.renderAddVaultMemberForm(membersEl, sectionEl, rootEl, session, vault, members, users);
    } catch (error) {
      membersEl.empty();
      new Setting(membersEl)
        .setName("Could not load vault members")
        .setDesc(this.errorMessage(error));
    }
  }

  private renderVaultMemberRow(
    membersEl: HTMLElement,
    sectionEl: HTMLElement,
    rootEl: HTMLElement,
    session: UserSession,
    vault: VaultRecord,
    member: VaultMemberRecord,
    userById: Map<string, UserLabelIdentity>,
    canManage: boolean
  ): void {
    const user = userById.get(member.userId);
    const label = this.formatUserLabel(member.userId, user);
    const desc = [
      `Role: ${VAULT_ROLE_LABELS[member.role]}`,
      `Joined: ${this.formatDate(member.joinedAt)}`,
      member.invitedBy ? `Invited by: ${this.formatUserLabel(member.invitedBy, userById.get(member.invitedBy))}` : null,
    ].filter((value): value is string => Boolean(value)).join(" · ");

    const setting = new Setting(membersEl)
      .setName(label)
      .setDesc(desc);

    if (!canManage) {
      return;
    }

    let nextRole = member.role;
    setting.addDropdown((dropdown) => {
      for (const role of VAULT_ROLES) {
        dropdown.addOption(role, VAULT_ROLE_LABELS[role]);
      }
      dropdown
        .setValue(member.role)
        .onChange(async (value) => {
          nextRole = value as VaultMemberRole;
          try {
            await this.plugin.updateCurrentVaultMember(member.userId, nextRole);
            this.showStatus(rootEl, `Updated ${label}.`, false);
            await this.renderCurrentVaultSettingsContent(
              sectionEl,
              rootEl,
              session
            );
          } catch (error) {
            this.showStatus(rootEl, `Failed to update member: ${this.errorMessage(error)}`, true);
          }
        });
    });

    setting.addButton((button) =>
      button
        .setButtonText("Remove")
        .setWarning()
        .onClick(async () => {
          const confirmed = await this.showDestructiveConfirmation(
            rootEl,
            "REMOVE MEMBER",
            `Type REMOVE MEMBER to confirm removing ${label} from ${vault.name}.`
          );
          if (!confirmed) return;

          button.setButtonText("Removing...");
          button.setDisabled(true);
          try {
            await this.plugin.removeCurrentVaultMember(member.userId);
            this.showStatus(rootEl, `Removed ${label}.`, false);
            await this.renderCurrentVaultSettingsContent(
              sectionEl,
              rootEl,
              session
            );
          } catch (error) {
            this.showStatus(rootEl, `Failed to remove member: ${this.errorMessage(error)}`, true);
            button.setButtonText("Remove");
            button.setDisabled(false);
          }
        })
    );
  }

  private renderAddVaultMemberForm(
    membersEl: HTMLElement,
    sectionEl: HTMLElement,
    rootEl: HTMLElement,
    session: UserSession,
    vault: VaultRecord,
    members: VaultMemberRecord[],
    users: UserListEntry[]
  ): void {
    const existingIds = new Set(members.map((member) => member.userId));
    const candidates = users.filter((user) => !existingIds.has(user.id));
    let nextUserId = candidates[0]?.id ?? "";
    let nextRole: VaultMemberRole = vault.defaultRole;

    const setting = new Setting(membersEl)
      .setName("Add member")
      .setDesc(
        users.length > 0
          ? "Add an organization user to this vault."
          : "Enter a VaultGuard user ID to add them to this vault."
      );

    if (users.length > 0 && candidates.length === 0) {
      setting.setDesc("All organization users are already members of this vault.");
      return;
    }

    if (users.length > 0) {
      setting.addDropdown((dropdown) => {
        for (const user of candidates) {
          dropdown.addOption(user.id, this.formatUserLabel(user.id, user));
        }
        dropdown
          .setValue(nextUserId)
          .onChange((value) => {
            nextUserId = value;
          });
      });
    } else {
      setting.addText((text) =>
        text
          .setPlaceholder("user-id")
          .onChange((value) => {
            nextUserId = value.trim();
          })
      );
    }

    setting.addDropdown((dropdown) => {
      for (const role of VAULT_ROLES) {
        dropdown.addOption(role, VAULT_ROLE_LABELS[role]);
      }
      dropdown
        .setValue(nextRole)
        .onChange((value) => {
          nextRole = value as VaultMemberRole;
        });
    });

    setting.addButton((button) =>
      button
        .setButtonText("Add")
        .setCta()
        .onClick(async () => {
          if (!nextUserId.trim()) {
            this.showStatus(rootEl, "Choose or enter a user first.", true);
            return;
          }

          button.setButtonText("Adding...");
          button.setDisabled(true);
          try {
            await this.plugin.addCurrentVaultMember(nextUserId.trim(), nextRole);
            this.showStatus(rootEl, "Vault member added.", false);
            await this.renderCurrentVaultSettingsContent(
              sectionEl,
              rootEl,
              session
            );
          } catch (error) {
            this.showStatus(rootEl, `Failed to add member: ${this.errorMessage(error)}`, true);
            button.setButtonText("Add");
            button.setDisabled(false);
          }
        })
    );
  }

  private isOrgAdmin(session: UserSession): boolean {
    return session.role === "admin" || session.role === "owner";
  }

  private canManageVault(session: UserSession, memberRole: VaultMemberRole | null): boolean {
    return this.isOrgAdmin(session) || memberRole === "admin";
  }

  private formatDate(value: string): string {
    const timestamp = Date.parse(value);
    return Number.isNaN(timestamp) ? value : new Date(timestamp).toLocaleDateString();
  }

  private buildVaultMemberUserLabelMap(members: VaultMemberRecord[]): Map<string, UserLabelIdentity> {
    const userById = new Map<string, UserLabelIdentity>();
    for (const member of members) {
      const displayName = member.displayName?.trim() ?? "";
      const email = member.email?.trim() ?? "";
      if (!displayName && !email) continue;
      userById.set(member.userId, {
        email,
        displayName,
        name: displayName,
      });
    }
    return userById;
  }

  private formatUserLabel(userId: string, user?: UserLabelIdentity): string {
    if (!user) return userId;
    const email = user.email?.trim() ?? "";
    const name = user.displayName?.trim() || user.name?.trim() || email || userId;
    return email && name !== email ? `${name} (${email})` : name;
  }

  private errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : "Unknown error";
  }

  private async handleSwitchVault(
    rootEl: HTMLElement,
    button: { setButtonText(text: string): unknown; setDisabled(disabled: boolean): unknown },
    restoreLabel = "Switch vault"
  ): Promise<void> {
    button.setButtonText("Opening...");
    button.setDisabled(true);
    try {
      const changed = await this.plugin.switchServerVault();
      this.showStatus(
        rootEl,
        changed ? "Vault binding updated. Sync will reconcile this folder with the selected vault." : "Vault binding unchanged.",
        false
      );
      this.display();
    } catch (error) {
      this.showStatus(
        rootEl,
        `Failed to switch vault: ${error instanceof Error ? error.message : "Unknown error"}`,
        true
      );
      button.setButtonText(restoreLabel);
      button.setDisabled(false);
    }
  }

  display(): void {
    const { containerEl } = this;
    containerEl.empty();
    containerEl.addClass("vaultguard-settings-tab");

    // ── Header ──────────────────────────────────────────────────────────────
    // No top-level heading here: Obsidian already renders the plugin name as
    // the settings-tab title, and repeating it trips the community-review
    // linter (settings-tab/no-problematic-settings-headings, which also bans
    // "settings"/"options"/"general" in setHeading labels). Lead with the
    // description paragraph instead.
    containerEl.createEl("p", {
      text: "Enterprise-grade vault security with permission-aware encrypted cloud sync.",
      cls: "setting-item-description",
    });

    // `session` / `isManualMode` are computed once and read by both the
    // Connection and Account blocks below.
    const session = this.plugin.getSession();
    const isManualMode = this.plugin.settings.manualConfig ?? false;

    // ── Connection Settings ─────────────────────────────────────────────────
    new Setting(containerEl)
      .setName("Connection")
      .setHeading()
      .settingEl.setAttribute("id", "vaultguard-connection-section");

    new Setting(containerEl)
      .setName("Connected to")
      .setDesc(this.plugin.getConnectionTargetLabel());

    // Mode toggle
    new Setting(containerEl)
      .setName("Configuration mode")
      .setDesc(
        isManualMode
          ? "Using manual configuration for self-hosted deployments."
          : "Using VaultGuard Cloud defaults. Organization details are discovered after sign-in or invite redemption."
      )
      .addToggle((toggle) =>
        toggle
          .setTooltip("Toggle between auto and manual configuration")
          .setValue(isManualMode)
          .onChange(async (value) => {
            try {
              await this.plugin.setManualConfigurationMode(value);
              this.display();
            } catch (err) {
              this.showStatus(
                containerEl,
                `Failed: ${err instanceof Error ? err.message : "Unknown error"}`,
                true
              );
            }
          })
      );

    if (!isManualMode) {
      new Setting(containerEl)
        .setName("VaultGuard Cloud")
        .setDesc("Uses the bundled api.example.com and Cognito configuration. Sign in from the Account section above.")
        .addButton((button) =>
          button
            .setButtonText("Reset")
            .setTooltip("Clear locally cached connection fields and use the bundled cloud defaults")
            .onClick(async () => {
              button.setDisabled(true);
              try {
                await this.plugin.resetCloudConnectionDefaults();
                this.showStatus(containerEl, "VaultGuard Cloud defaults restored.", false);
                this.display();
              } catch (err) {
                this.showStatus(
                  containerEl,
                  `Failed: ${err instanceof Error ? err.message : "Unknown error"}`,
                  true
                );
              } finally {
                button.setDisabled(false);
              }
            })
        );

      // ── Auto mode: org slug ──────────────────────────────────────────────
      const orgSlugSetting = new Setting(containerEl)
        .setName("Organization slug")
        .setDesc(
          "Enter the slug your admin gave you (e.g., \"acme-corp\"). " +
          "All connection details will be configured automatically."
        );

      orgSlugSetting.addText((text) => {
        text
          .setPlaceholder("acme-corp")
          .setValue(this.plugin.settings.orgSlug)
          .onChange(async (value) => {
            this.plugin.settings.orgSlug = value.trim().toLowerCase();
            await this.plugin.saveSettings();
          });
      });

      orgSlugSetting.addButton((button) =>
        button
          .setButtonText("Connect")
          .setCta()
          .onClick(async () => {
            const slug = this.plugin.settings.orgSlug;
            if (!slug) {
              this.showStatus(containerEl, "Enter an organization slug first.", true);
              return;
            }
            button.setButtonText("Connecting...");
            button.setDisabled(true);
            try {
              await this.plugin.resolveOrgConfig(slug);
              this.showStatus(containerEl, `Connected to "${slug}" successfully!`, false);
              this.display();
            } catch (err) {
              this.showStatus(
                containerEl,
                `Failed: ${err instanceof Error ? err.message : "Unknown error"}`,
                true
              );
            } finally {
              button.setButtonText("Connect");
              button.setDisabled(false);
            }
          })
      );

      // ── Redeem invite link (paste fallback for the obsidian:// deep link) ──
      const redeemSetting = new Setting(containerEl)
        .setName("Redeem invite link")
        .setDesc(
          "Paste the obsidian://vaultguard-invite link from your invitation email " +
          "to auto-configure your organization and set your password."
        );

      let redeemInput: HTMLInputElement | null = null;
      redeemSetting.addText((text) => {
        text
          .setPlaceholder("obsidian://vaultguard-invite?org=...&email=...")
          .setValue("");
        redeemInput = text.inputEl;
      });

      redeemSetting.addButton((button) =>
        button
          .setButtonText("Redeem")
          .setCta()
          .onClick(async () => {
            const raw = redeemInput?.value.trim() ?? "";
            if (!raw) {
              this.showStatus(containerEl, "Paste your invite link first.", true);
              return;
            }
            const parsed = parseInviteLink(raw);
            if (!parsed.org) {
              this.showStatus(
                containerEl,
                "Could not find an org slug in that link. Make sure you copied the full obsidian://vaultguard-invite URL.",
                true
              );
              return;
            }
            button.setButtonText("Redeeming...");
            button.setDisabled(true);
            try {
              await this.plugin.redeemInvite(parsed);
              if (redeemInput) redeemInput.value = "";
              this.showStatus(
                containerEl,
                `Invite for "${parsed.org}" redeemed. Follow the prompts to set your password.`,
                false
              );
              this.display();
            } catch (err) {
              this.showStatus(
                containerEl,
                `Failed: ${err instanceof Error ? err.message : "Unknown error"}`,
                true
              );
            } finally {
              button.setButtonText("Redeem");
              button.setDisabled(false);
            }
          })
      );
    } else {
      const serverConfigSetting = new Setting(containerEl)
        .setName("Server config URL")
        .setDesc(
          "Paste your self-hosted server's public config URL, for example https://your-server.com/.well-known/vaultguard.json."
        );

      let serverConfigInput: HTMLInputElement | null = null;
      serverConfigSetting.addText((text) => {
        text
          .setPlaceholder("https://your-server.com/.well-known/vaultguard.json")
          .setValue("");
        serverConfigInput = text.inputEl;
      });

      serverConfigSetting.addButton((button) =>
        button
          .setButtonText("Apply")
          .setCta()
          .onClick(async () => {
            const raw = serverConfigInput?.value.trim() ?? "";
            if (!raw) {
              this.showStatus(containerEl, "Paste a server config URL first.", true);
              return;
            }
            button.setButtonText("Applying...");
            button.setDisabled(true);
            try {
              await this.plugin.applyManualServerConfigUrl(raw);
              if (serverConfigInput) serverConfigInput.value = "";
              this.showStatus(containerEl, "Self-hosted server configuration applied.", false);
              this.display();
            } catch (err) {
              this.showStatus(
                containerEl,
                `Failed: ${err instanceof Error ? err.message : "Unknown error"}`,
                true
              );
            } finally {
              button.setButtonText("Apply");
              button.setDisabled(false);
            }
          })
      );

      // ── Manual mode: direct field entry ──────────────────────────────────
      new Setting(containerEl)
        .setName("API endpoint")
        .setDesc(
          "VaultGuard REST API or CloudFront base URL. Pasted /settings or /orgs/... URLs are trimmed automatically."
        )
        .addText((text) =>
          text
            .setPlaceholder("https://d1234567890.cloudfront.net or https://api.example.com")
            .setValue(this.plugin.settings.apiEndpoint)
            .onChange(async (value) => {
              this.plugin.settings.apiEndpoint = value.trim();
              await this.plugin.saveSettings();
            })
        );

      new Setting(containerEl)
        .setName("Organization ID")
        .addText((text) =>
          text
            .setValue(this.plugin.settings.organizationId)
            .onChange(async (value) => {
              this.plugin.settings.organizationId = value.trim();
              await this.plugin.saveSettings();
            })
        );

      new Setting(containerEl)
        .setName("Cognito user pool ID")
        .addText((text) =>
          text
            .setPlaceholder("eu-central-1_XXXXXXXXX")
            .setValue(this.plugin.settings.cognitoUserPoolId)
            .onChange(async (value) => {
              this.plugin.settings.cognitoUserPoolId = value.trim();
              await this.plugin.saveSettings();
            })
        );

      new Setting(containerEl)
        .setName("Cognito client ID")
        .addText((text) =>
          text
            .setPlaceholder("1a2b3c4d5e6f7g8h9i0j")
            .setValue(this.plugin.settings.cognitoClientId)
            .onChange(async (value) => {
              this.plugin.settings.cognitoClientId = value.trim();
              await this.plugin.saveSettings();
            })
        );
    }

    // ── Account ─────────────────────────────────────────────────────────────
    if (session) {
      new Setting(containerEl).setName("Account").setHeading();

      new Setting(containerEl)
        .setName("Logged in as")
        .setDesc(`${session.email} (${session.role})`);

      // ── Profile: Display Name ────────────────────────────────────────────
      new Setting(containerEl)
        .setName("Display name")
        .setDesc(
          "Your name shown to teammates in permission headers and access lists. " +
          "Use your first and last name (e.g. \"Jane Smith\")."
        )
        .addText((text) => {
          text
            .setPlaceholder("Jane Smith")
            .setValue(session.displayName ?? "")
            .onChange(() => {
              // no-op: save on button click
            });

          const inputEl = text.inputEl;
          const settingEl = inputEl.closest('.setting-item');
          if (settingEl) {
            const controlEl = settingEl.querySelector('.setting-item-control');
            if (controlEl) {
              const saveBtn = controlEl.createEl('button', {
                text: 'Save',
                cls: 'mod-cta vaultguard-inline-save-btn',
              });
              saveBtn.addEventListener('click', async () => {
                const newName = inputEl.value.trim();
                if (!newName) {
                  this.showStatus(containerEl, "Display name cannot be empty.", true);
                  return;
                }
                saveBtn.disabled = true;
                saveBtn.textContent = "Saving...";
                try {
                  await this.plugin.updateUserProfile(session.userId, newName);
                  this.showStatus(containerEl, "Display name updated.", false);
                  this.display();
                } catch (error) {
                  this.showStatus(
                    containerEl,
                    `Failed to update name: ${(error as Error).message}`,
                    true
                  );
                } finally {
                  saveBtn.disabled = false;
                  saveBtn.textContent = "Save";
                }
              });
            }
          }
        });

      new Setting(containerEl)
        .setName("Logout")
        .setDesc(
          "Sign out and clear your session from this device."
        )
        .addButton((button) =>
          button
            .setButtonText("Logout")
            .onClick(async () => {
              await this.plugin.forceLogout();
              this.display();
            })
        );
    } else {
      new Setting(containerEl).setName("Account").setHeading();

      new Setting(containerEl)
        .setName("Not logged in")
        .setDesc(
          isManualMode
            ? "Sign in with your self-hosted VaultGuard server."
            : "Sign in with your VaultGuard Cloud account."
        )
        .addButton((button) =>
          button
            .setButtonText(isManualMode ? "Login" : "Continue with VaultGuard Cloud")
            .setCta()
            .onClick(() => {
              this.plugin.triggerLogin();
            })
        );

      // Single login entry point above. Point self-hosters at the Connection
      // section (manual configuration) instead of a second login button.
      if (!isManualMode) {
        const selfHostNote = containerEl.createDiv({
          cls: "setting-item-description vaultguard-selfhost-note",
        });
        selfHostNote.appendText("Self-hosting your own VaultGuard server? ");
        const link = selfHostNote.createEl("a", {
          text: "Configure it in connection settings",
          href: "#",
        });
        link.addEventListener("click", (e) => {
          e.preventDefault();
          containerEl
            .querySelector("#vaultguard-connection-section")
            ?.scrollIntoView({ behavior: "smooth", block: "start" });
        });
        selfHostNote.appendText(" below (switch to manual configuration).");
      }
    }

    this.renderCurrentVaultSettings(containerEl, session);

    // ── Sync Settings ───────────────────────────────────────────────────────
    new Setting(containerEl).setName("Synchronization").setHeading();
    const orgPolicy = this.plugin.getOrgPolicySettings();
    if (orgPolicy) {
      const policyDescription =
        orgPolicy.syncMode === "manual"
          ? "Manual sync only"
          : orgPolicy.syncMode === "realtime"
            ? "Real-time sync managed by your organization"
            : `Periodic sync every ${orgPolicy.syncIntervalMinutes} minute${
                orgPolicy.syncIntervalMinutes === 1 ? "" : "s"
              }`;

      new Setting(containerEl)
        .setName("Sync interval")
        .setDesc(`Managed by your organization: ${policyDescription}.`);
    } else {
      new Setting(containerEl)
        .setName("Sync interval")
        .setDesc(
          "How often to check for remote changes (in seconds). Minimum 10 seconds."
        )
        .addSlider((slider) =>
          slider
            .setLimits(10, 300, 5)
            .setValue(this.plugin.settings.syncInterval)
            .setDynamicTooltip()
            .onChange(async (value) => {
              this.plugin.settings.syncInterval = value;
              await this.plugin.saveSettings();
              this.plugin.restartSyncTimer();
            })
        );
    }

    new Setting(containerEl)
      .setName("Default conflict resolution")
      .setDesc(
        "How to handle sync conflicts when both local and remote versions have changed."
      )
      .addDropdown((dropdown) =>
        dropdown
          .addOption(ConflictResolutionStrategy.ASK_USER, "Ask me each time")
          .addOption(ConflictResolutionStrategy.KEEP_LOCAL, "Always keep local")
          .addOption(
            ConflictResolutionStrategy.KEEP_REMOTE,
            "Always keep remote"
          )
          .addOption(
            ConflictResolutionStrategy.DUPLICATE,
            "Create duplicate file"
          )
          .setValue(this.plugin.settings.defaultConflictResolution)
          .onChange(async (value) => {
            this.plugin.settings.defaultConflictResolution =
              value as ConflictResolutionStrategy;
            await this.plugin.saveSettings();
          })
      );

    const configDir = this.app.vault.configDir;
    const configWorkspacePath = `${configDir}/workspace.json`;
    const configPluginsPath = `${configDir}/plugins`;

    const excludedPathsSetting = new Setting(containerEl)
      .setName("Excluded paths (local-only)")
      .setDesc(
        "One path per line. Files and folders matching these patterns are never uploaded, " +
        "downloaded, or deleted on the server — they stay on this device only. Use exact " +
        `paths (e.g. ${configWorkspacePath}) or folder prefixes (e.g. ${configPluginsPath}). ` +
        "This setting applies to this device only; it does not change the server vault."
      )
      .addTextArea((textArea) => {
        textArea.inputEl.rows = 6;
        textArea.inputEl.addClass("vaultguard-mono-textarea");
        textArea
          .setPlaceholder(`${configWorkspacePath}\n${configPluginsPath}\n.trash`)
          .setValue((this.plugin.settings.excludedPaths ?? []).join("\n"))
          .onChange(async (value) => {
            this.plugin.settings.excludedPaths = value
              .split("\n")
              .map((line) => line.trim())
              .filter((line) => line.length > 0);
            await this.plugin.saveSettings();
          });
        return textArea;
      });
    excludedPathsSetting.settingEl.addClass("vaultguard-excluded-paths-setting");

    this.renderPluginAllowlistSection(containerEl);

    new Setting(containerEl)
      .setName("Purge excluded paths from server")
      .setDesc(
        "Delete every server-side copy of files that match the excluded paths above. " +
        "Useful after adding a new exclusion: without this, other members on other " +
        "devices keep pulling the file down. This affects the shared server vault."
      )
      .addButton((button) =>
        button
          .setButtonText("Purge from server")
          .setWarning()
          .onClick(async () => {
            const patterns = this.plugin.settings.excludedPaths ?? [];
            if (patterns.length === 0) {
              this.showStatus(containerEl, "No excluded paths configured.", true);
              return;
            }
            const confirmed = await this.showDestructiveConfirmation(
              containerEl,
              "PURGE FROM SERVER",
              "Delete every matching file from the shared server vault? " +
                "Other members will lose these files on their next sync. " +
                "Local copies on this device are kept.\n\n" +
                `Patterns:\n${patterns.join("\n")}\n\n` +
                "Type PURGE FROM SERVER to confirm."
            );
            if (!confirmed) return;
            try {
              button.setDisabled(true);
              button.setButtonText("Purging…");
              const result = await this.plugin.purgeExcludedFromServer();
              const summary = `Matched ${result.matched}, deleted ${result.deleted}` +
                (result.failed > 0 ? `, ${result.failed} failed` : "");
              this.showStatus(containerEl, summary, result.failed > 0);
            } catch (err) {
              this.showStatus(
                containerEl,
                err instanceof Error ? err.message : "Purge failed.",
                true
              );
            } finally {
              button.setDisabled(false);
              button.setButtonText("Purge from server");
            }
          })
      );

    // ── Display Settings ────────────────────────────────────────────────────
    new Setting(containerEl).setName("Display").setHeading();

    new Setting(containerEl)
      .setName("Show my permission level")
      .setDesc(
        "Show a colored dot for your own access level (admin / write / read / none) next to each file in the file explorer."
      )
      .addToggle((toggle) =>
        toggle
          .setValue(this.plugin.settings.showMyPermissionLevel)
          .onChange(async (value) => {
            this.plugin.settings.showMyPermissionLevel = value;
            await this.plugin.saveSettings();
            this.plugin.refreshFileExplorerDecorations();
          })
      );

    new Setting(containerEl)
      .setName("Show who else has access")
      .setDesc(
        "Show avatar chips for other people and roles that can access a file, next to it in the file explorer."
      )
      .addToggle((toggle) =>
        toggle
          .setValue(this.plugin.settings.showOthersAccess)
          .onChange(async (value) => {
            this.plugin.settings.showOthersAccess = value;
            await this.plugin.saveSettings();
            this.plugin.refreshFileExplorerDecorations();
          })
      );

    new Setting(containerEl)
      .setName("Show permission banner in notes")
      .setDesc(
        "Show a banner at the top of each open note with your access level and a quick way to manage sharing."
      )
      .addToggle((toggle) =>
        toggle
          .setValue(this.plugin.settings.showPermissionBanner)
          .onChange(async (value) => {
            this.plugin.settings.showPermissionBanner = value;
            await this.plugin.saveSettings();
            this.plugin.refreshFilePermissionHeader();
          })
      );

    new Setting(containerEl)
      .setName("Show status bar")
      .setDesc(
        "Display sync status and connection indicator in the bottom status bar."
      )
      .addToggle((toggle) =>
        toggle
          .setValue(this.plugin.settings.showStatusBar)
          .onChange(async (value) => {
            this.plugin.settings.showStatusBar = value;
            await this.plugin.saveSettings();
            this.plugin.toggleStatusBar(value);
          })
      );

    // ── Advanced (collapsed) ─────────────────────────────────────────────────
    // Security + Reliability + at-rest maintenance live behind one disclosure.
    this.renderCollapsibleSection(containerEl, "Advanced", (body) => {
      // ── Security ────────────────────────────────────────────────────────
      new Setting(body).setName("Security").setHeading();

      new Setting(body)
        .setName("Cache encryption strength")
        .setDesc(
          "Encryption level for locally cached files. Higher levels are more secure but slower."
        )
        .addDropdown((dropdown) =>
          dropdown
            .addOption("standard", "Standard (AES-256-GCM)")
            .addOption("high", "High (AES-256-GCM + key stretching)")
            .addOption(
              "maximum",
              "Maximum (AES-256-GCM + Argon2 key derivation)"
            )
            .setValue(this.plugin.settings.cacheEncryptionStrength)
            .onChange(async (value) => {
              this.plugin.settings.cacheEncryptionStrength =
                value as CacheEncryptionStrength;
              await this.plugin.saveSettings();
            })
        );

      new Setting(body)
        .setName("Offline key lease duration")
        .setDesc(
          "How long encryption keys remain valid when offline (in hours). After expiry, files cannot be decrypted until reconnection."
        )
        .addSlider((slider) =>
          slider
            .setLimits(1, 168, 1)
            .setValue(this.plugin.settings.offlineKeyLeaseDuration)
            .setDynamicTooltip()
            .onChange(async (value) => {
              this.plugin.settings.offlineKeyLeaseDuration = value;
              await this.plugin.saveSettings();
            })
        );

      new Setting(body)
        .setName("Auto-wipe on auth failure")
        .setDesc(
          "Automatically clear all cached vault data if authentication fails repeatedly. This prevents unauthorized access but may cause data loss for unsynced changes."
        )
        .addToggle((toggle) =>
          toggle
            .setValue(this.plugin.settings.autoWipeOnAuthFailure)
            .onChange(async (value) => {
              this.plugin.settings.autoWipeOnAuthFailure = value;
              await this.plugin.saveSettings();
            })
        );

      // ── Reliability (formerly the top-level "Advanced" heading) ──────────
      new Setting(body).setName("Reliability").setHeading();

      new Setting(body)
        .setName("Max retry attempts")
        .setDesc(
          "Maximum number of retry attempts for failed API calls before giving up."
        )
        .addSlider((slider) =>
          slider
            .setLimits(1, 10, 1)
            .setValue(this.plugin.settings.maxRetryAttempts)
            .setDynamicTooltip()
            .onChange(async (value) => {
              this.plugin.settings.maxRetryAttempts = value;
              await this.plugin.saveSettings();
            })
        );

      new Setting(body)
        .setName("Debug logging")
        .setDesc(
          "Enable verbose logging to the developer console. Useful for troubleshooting but may expose sensitive data in logs."
        )
        .addToggle((toggle) =>
          toggle
            .setValue(this.plugin.settings.debugLogging)
            .onChange(async (value) => {
              this.plugin.settings.debugLogging = value;
              await this.plugin.saveSettings();
            })
        );

      new Setting(body)
        .setName("Disable update checks")
        .setDesc(
          "When enabled, the plugin won't poll GitHub for new releases. Default off: the plugin checks once every 24 h and shows a notification when a newer version is available. No telemetry is sent — only an outbound HTTPS request to api.github.com."
        )
        .addToggle((toggle) =>
          toggle
            .setValue(this.plugin.settings.disableUpdateChecks ?? false)
            .onChange(async (value) => {
              this.plugin.settings.disableUpdateChecks = value;
              await this.plugin.saveSettings();
            })
        );

      // ── Local at-rest encryption ─────────────────────────────────────────
      this.renderAtRestSection(body);
    });

    // ── AI & automation (collapsed) ──────────────────────────────────────────
    // Agent bridge + AI chat live behind one disclosure. Both helpers keep
    // their own desktop gating and setHeading() labels.
    this.renderCollapsibleSection(containerEl, "AI & automation", (body) => {
      this.renderAgentBridgeSection(body);
      this.renderAiChatSection(body);
    });

    // ── Danger Zone ─────────────────────────────────────────────────────────
    new Setting(containerEl).setName("Danger zone").setHeading();
    containerEl.createEl("p", {
      text: "These actions cannot be undone.",
      cls: "setting-item-description mod-warning",
    });

    new Setting(containerEl)
      .setName("Clear local cache")
      .setDesc(
        "Remove all locally cached and encrypted vault data. Files will be re-downloaded on next sync."
      )
      .addButton((button) =>
        button
          .setButtonText("Clear cache")
          .setWarning()
          .onClick(async () => {
            const confirmed = await this.showDestructiveConfirmation(
              containerEl,
              "CLEAR CACHE",
              "Type CLEAR CACHE to confirm. This will delete all locally cached vault data."
            );
            if (confirmed) {
              await this.plugin.clearLocalCache();
            }
          })
      );
  }

  /**
   * Show a type-to-confirm dialog for destructive operations.
   * Returns true only if the user types the exact confirmation phrase.
   */
  private showDestructiveConfirmation(
    containerEl: HTMLElement,
    confirmPhrase: string,
    message: string
  ): Promise<boolean> {
    return new Promise((resolve) => {
      // Remove any existing confirmation dialog
      const existing = containerEl.querySelector(".vaultguard-destruct-confirm");
      if (existing) existing.remove();

      const dialog = containerEl.createDiv({ cls: "vaultguard-destruct-confirm" });
      dialog.createEl("p", { text: message, cls: "setting-item-description mod-warning" });

      const input = dialog.createEl("input", {
        cls: "vaultguard-confirm-input",
        attr: { type: "text", placeholder: confirmPhrase },
      });

      const btnRow = dialog.createDiv({ cls: "vaultguard-confirm-buttons" });
      const cancelBtn = btnRow.createEl("button", { text: "Cancel" });
      const confirmBtn = btnRow.createEl("button", {
        text: "Confirm",
        cls: "mod-warning",
        attr: { disabled: "true" },
      });

      input.addEventListener("input", () => {
        if (input.value === confirmPhrase) {
          confirmBtn.removeAttribute("disabled");
        } else {
          confirmBtn.setAttribute("disabled", "true");
        }
      });

      cancelBtn.addEventListener("click", () => {
        dialog.remove();
        resolve(false);
      });

      confirmBtn.addEventListener("click", () => {
        if (input.value === confirmPhrase) {
          dialog.remove();
          resolve(true);
        }
      });

      input.focus();
    });
  }

  /**
   * Renders the agent bridge management section. This is the visible home for
   * bridge operations in Settings: create a lease, revoke all leases, inspect
   * every active lease, rotate one token, or revoke one lease.
   */
  private renderAgentBridgeSection(containerEl: HTMLElement): void {
    new Setting(containerEl).setName("Agent bridge connections (desktop only.)").setHeading();

    // Agent bridge needs a local HTTP server (Node `http` module). That's
    // only reachable in desktop Obsidian's renderer. On mobile we surface
    // the limitation up-front instead of letting the user click "Create
    // bridge lease" and see a confusing failure later.
    if (Platform.isMobileApp) {
      containerEl.createEl("p", {
        cls: "setting-item-description",
        text:
          "Agent bridge is desktop-only. It exposes VaultGuard Sync's tools to local MCP clients (Claudian, Claude Code, Cursor) via a localhost HTTP server, which Obsidian mobile renderers can't host. Manage agent leases from a desktop install of this same vault.",
      });
      return;
    }

    containerEl.createEl("p", {
      cls: "setting-item-description",
      text:
        "Agent bridge leases let an external agent (Claudian, Claude Code, Cursor, custom MCP client) talk to this vault through VaultGuard Sync tools. Each lease has its own bearer token; revoking or rotating one does not disturb the others. Hidden paths (.obsidian, .trash, .git, ...) are always blocked.",
    });

    const surface = this.plugin.getAgentBridge();
    const description = surface.describe();
    const activeLeases = description.activeLeases;
    const server = description.server;
    const canCreate = Boolean(this.plugin.getSession() && this.plugin.settings.serverVaultId);

    new Setting(containerEl)
      .setName("Bridge lease actions")
      .setDesc(
        canCreate
          ? "Create a new scoped bridge lease, or revoke every current bridge lease for this vault."
          : "Log in and bind this Obsidian folder to a server vault before creating bridge leases."
      )
      .addButton((button) =>
        button
          .setButtonText("Create bridge lease")
          .setCta()
          .setDisabled(!canCreate)
          .onClick(() => {
            new AgentBridgeLeaseModal(this.plugin, () => this.display()).open();
          })
      )
      .addButton((button) =>
        button
          .setButtonText("Revoke all leases")
          .setWarning()
          .setDisabled(activeLeases.length === 0)
          .onClick(async () => {
            button.setDisabled(true).setButtonText("Revoking...");
            try {
              this.plugin.revokeAllAgentBridgeLeases();
              await this.plugin.stopAgentBridgeServer();
              this.latestAgentBridgeReveal = null;
              new Notice("VaultGuard Sync: all agent bridge leases revoked.");
              this.display();
            } catch (error) {
              new Notice(
                `VaultGuard Sync: could not revoke bridge leases - ${this.errorMessage(error)}`,
                8000
              );
              button.setDisabled(false).setButtonText("Revoke all leases");
            }
          })
      );

    this.renderAgentBridgeServerState(containerEl, server, activeLeases.length);
    this.renderLatestAgentBridgeReveal(containerEl);
    this.renderAgentBridgeSkillRow(containerEl);

    new Setting(containerEl).setName("Current leases").setHeading();

    if (activeLeases.length === 0) {
      const empty = containerEl.createDiv({ cls: "setting-item-description" });
      empty.appendText(
        "No active bridge leases. Create one here or from the command palette when you want to connect an agent."
      );
      return;
    }

    for (const lease of activeLeases) {
      this.renderAgentBridgeLeaseRow(containerEl, lease);
    }
  }

  private renderAgentBridgeServerState(
    containerEl: HTMLElement,
    server: AgentBridgeServerInfo | null,
    activeLeaseCount: number
  ): void {
    if (server) {
      const serverInfo = containerEl.createDiv({ cls: "vaultguard-agent-bridge-server" });
      serverInfo.createEl("strong", { text: "Bridge server: " });
      serverInfo.appendText(`${server.endpoint} (MCP at ${server.mcpEndpoint})`);

      const buttons = serverInfo.createDiv({ cls: "vaultguard-agent-bridge-inline-actions" });
      const copyRpc = new ButtonComponent(buttons);
      copyRpc.setButtonText("Copy RPC URL").onClick(async () => {
        const copied = await this.writeClipboard(server.endpoint);
        new Notice(copied ? "Bridge RPC URL copied." : "Could not copy the bridge RPC URL.");
      });

      const copyMcp = new ButtonComponent(buttons);
      copyMcp.setButtonText("Copy MCP URL").onClick(async () => {
        const copied = await this.writeClipboard(server.mcpEndpoint);
        new Notice(copied ? "Bridge MCP URL copied." : "Could not copy the bridge MCP URL.");
      });
      return;
    }

    if (activeLeaseCount > 0) {
      new Setting(containerEl)
        .setName("Bridge server")
        .setDesc(
          "There are active leases, but the local bridge server is not listening. Start it before connecting an agent."
        )
        .addButton((button) =>
          button
            .setButtonText("Start bridge server")
            .setCta()
            .onClick(async () => {
              button.setDisabled(true).setButtonText("Starting...");
              try {
                await this.plugin.startAgentBridgeServer();
                this.display();
              } catch (error) {
                new Notice(
                  `VaultGuard Sync: could not start the bridge server - ${this.errorMessage(error)}`,
                  8000
                );
                button.setDisabled(false).setButtonText("Start bridge server");
              }
            })
        );
      return;
    }

    const idleInfo = containerEl.createDiv({ cls: "setting-item-description" });
    idleInfo.appendText("Bridge server is idle. It starts when you create a lease.");
  }

  /**
   * Renders the "Claude Code skill" row. Shows current install state,
   * Claude Code availability, and Install / Update / Uninstall buttons.
   * The skill itself is a static SKILL.md at ~/.claude/skills/vaultguard/
   * — it has no per-user state, so it never needs to rotate when leases
   * change.
   */
  private renderAgentBridgeSkillRow(containerEl: HTMLElement): void {
    const status = this.plugin.getAgentBridgeSkillStatus();

    if (!status.available) {
      // Mobile or non-Node context. Show the row anyway so users on
      // those devices see it exists but understand why it's disabled.
      new Setting(containerEl)
        .setName("Claude Code skill")
        .setDesc(
          "Not available on this device — installing the skill needs Node filesystem access (desktop Obsidian only)."
        );
      return;
    }

    const desc = this.skillStatusDescription(status);
    const setting = new Setting(containerEl)
      .setName("Claude Code skill")
      .setDesc(desc);

    if (!status.claudeCodeAvailable) {
      setting.addButton((button) =>
        button
          .setButtonText("Install anyway")
          .setWarning()
          .onClick(async () => this.runSkillInstall(button, { force: true }))
      );
      return;
    }

    if (status.managedConflict) {
      setting.addButton((button) =>
        button
          .setButtonText("Overwrite existing SKILL.md")
          .setWarning()
          .onClick(async () => this.runSkillInstall(button, { overwriteUnmanaged: true }))
      );
      return;
    }

    if (!status.installed) {
      setting.addButton((button) =>
        button
          .setButtonText("Install skill")
          .setCta()
          .onClick(async () => this.runSkillInstall(button))
      );
      return;
    }

    setting
      .addButton((button) =>
        button
          .setButtonText("Update / re-install")
          .onClick(async () => this.runSkillInstall(button))
      )
      .addButton((button) =>
        button
          .setButtonText("Uninstall")
          .setWarning()
          .onClick(async () => this.runSkillUninstall(button))
      );
  }

  private skillStatusDescription(status: SkillInstallStatus & { available: true }): string {
    if (!status.claudeCodeAvailable) {
      return `Claude Code does not appear to be installed (no ~/.claude/skills/ directory). The skill would land at ${status.skillFilePath} if you install it anyway.`;
    }
    if (status.managedConflict) {
      return `A SKILL.md exists at ${status.skillFilePath} but wasn't installed by VaultGuard Sync. Overwriting will replace it. Cancel and inspect the file if you didn't expect this.`;
    }
    if (status.installed) {
      return `Installed at ${status.skillFilePath}. The skill teaches Claude Code (and any agent that loads ~/.claude/skills/) to use VaultGuard Sync's MCP tools instead of Read/Glob/Grep against encrypted vault files. Re-install to pull the latest skill body.`;
    }
    return `Writes a SKILL.md to ${status.skillFilePath}. Tells Claude Code to reach for VaultGuard Sync's MCP tools when it sees an encrypted vault, rather than reading ciphertext directly. Contains no tokens or per-user state.`;
  }

  private async runSkillInstall(
    button: ButtonComponent,
    options: { overwriteUnmanaged?: boolean; force?: boolean } = {}
  ): Promise<void> {
    const original = button.buttonEl.textContent ?? "Install skill";
    button.setDisabled(true).setButtonText("Installing...");
    try {
      const result = await this.plugin.installAgentBridgeSkill(options);
      const verb =
        result.action === "noop"
          ? "already current"
          : result.action === "created"
            ? "installed"
            : result.action === "overwrote-conflict"
              ? "overwrote existing file"
              : "updated";
      new Notice(`VaultGuard Sync: Claude Code skill ${verb} at ${result.filePath}.`, 6000);
      this.display();
    } catch (error) {
      new Notice(
        `VaultGuard Sync: could not install skill - ${this.errorMessage(error)}`,
        8000
      );
      button.setDisabled(false).setButtonText(original);
    }
  }

  private async runSkillUninstall(button: ButtonComponent): Promise<void> {
    button.setDisabled(true).setButtonText("Removing...");
    try {
      const result = await this.plugin.uninstallAgentBridgeSkill();
      if (result.removed) {
        new Notice(`VaultGuard Sync: Claude Code skill removed from ${result.filePath}.`, 6000);
      } else {
        new Notice("VaultGuard Sync: no managed skill file to remove.", 4000);
      }
      this.display();
    } catch (error) {
      new Notice(
        `VaultGuard Sync: could not uninstall skill - ${this.errorMessage(error)}`,
        8000
      );
      button.setDisabled(false).setButtonText("Uninstall");
    }
  }

  private renderLatestAgentBridgeReveal(containerEl: HTMLElement): void {
    const reveal = this.latestAgentBridgeReveal;
    if (!reveal) return;

    const block = containerEl.createDiv({ cls: "vaultguard-agent-bridge-reveal" });
    block.createEl("strong", { text: `New token for ${reveal.agentName}` });
    block.createEl("p", {
      cls: "setting-item-description",
      text: reveal.copiedToClipboard
        ? "The rotated MCP config was copied. It is also shown here until this settings panel refreshes again."
        : "The token was rotated, but clipboard copy was unavailable. Copy one of the snippets below before leaving this settings panel.",
    });

    this.renderAgentBridgeCopyBlock(block, {
      title: "MCP server config",
      body: reveal.mcpConfig,
      copyLabel: "Copy MCP config",
    });
    this.renderAgentBridgeCopyBlock(block, {
      title: "Generic HTTP-RPC connection",
      body: reveal.connectionJson,
      copyLabel: "Copy connection JSON",
    });
  }

  private renderAgentBridgeLeaseRow(
    containerEl: HTMLElement,
    lease: AgentBridgeLeaseSummary
  ): void {
    const block = containerEl.createDiv({ cls: "vaultguard-agent-bridge-lease" });
    block.addClass(lease.persistent ? "is-persistent" : "is-ephemeral");

    const header = block.createDiv({ cls: "vaultguard-agent-bridge-lease-header" });
    header.createEl("strong", { text: lease.agentName });
    header.createSpan({
      cls: "vaultguard-agent-bridge-lease-badge",
      text: lease.persistent ? "Until logout" : "Time-limited",
    });

    const details = block.createEl("dl", { cls: "vaultguard-agent-bridge-lease-details" });
    this.addAgentBridgeLeaseDetail(details, "Lease ID", lease.leaseId);
    this.addAgentBridgeLeaseDetail(details, "Scope", lease.scopes.join(", "));
    this.addAgentBridgeLeaseDetail(details, "Access", this.agentBridgeAccessLabel(lease));
    this.addAgentBridgeLeaseDetail(details, "Created", this.formatDateTime(lease.createdAt));
    this.addAgentBridgeLeaseDetail(
      details,
      "Expires",
      lease.persistent ? "When you log out" : this.formatDateTime(lease.expiresAt)
    );
    this.addAgentBridgeLeaseDetail(
      details,
      "Limits",
      `${this.formatBytes(lease.maxReadBytes)} max read, ${lease.maxSearchResults} search result${
        lease.maxSearchResults === 1 ? "" : "s"
      }`
    );

    const buttons = block.createDiv({ cls: "vaultguard-modal-actions" });

    const rotateBtn = new ButtonComponent(buttons);
    rotateBtn.setButtonText("Rotate token").onClick(() => {
      void this.rotateAgentBridgeLeaseToken(lease, rotateBtn);
    });

    const revokeBtn = new ButtonComponent(buttons);
    revokeBtn
      .setButtonText("Revoke lease")
      .setWarning()
      .onClick(() => {
        void this.revokeAgentBridgeLease(lease, revokeBtn);
      });
  }

  private addAgentBridgeLeaseDetail(parent: HTMLElement, label: string, value: string): void {
    parent.createEl("dt", { text: label });
    parent.createEl("dd", { text: value });
  }

  private agentBridgeAccessLabel(lease: AgentBridgeLeaseSummary): string {
    const read = lease.allowRead ? "read enabled" : "read disabled";
    const write =
      lease.writeMode === "deny"
        ? "read-only"
        : lease.writeMode === "confirm"
          ? "confirm writes"
          : "allow writes";
    return `${read}, ${write}`;
  }

  private async rotateAgentBridgeLeaseToken(
    lease: AgentBridgeLeaseSummary,
    button: ButtonComponent
  ): Promise<void> {
    button.setDisabled(true).setButtonText("Rotating...");
    try {
      const server = await this.plugin.startAgentBridgeServer();
      const refreshed = this.plugin.rotateAgentBridgeLeaseToken(lease.leaseId);
      const mcpConfig = this.buildAgentBridgeMcpConfig(refreshed, server);
      const connectionJson = this.buildAgentBridgeConnectionJson(refreshed, server);
      const copiedToClipboard = await this.writeClipboard(mcpConfig);

      this.latestAgentBridgeReveal = {
        leaseId: refreshed.leaseId,
        agentName: refreshed.agentName,
        connectionJson,
        mcpConfig,
        copiedToClipboard,
      };

      new Notice(
        copiedToClipboard
          ? "VaultGuard Sync: new MCP config copied. Update the agent using this lease."
          : "VaultGuard Sync: token rotated. Copy the new config shown in settings.",
        8000
      );
      this.display();
    } catch (error) {
      new Notice(
        `VaultGuard Sync: could not rotate bridge token - ${this.errorMessage(error)}`,
        8000
      );
      button.setDisabled(false).setButtonText("Rotate token");
    }
  }

  private async revokeAgentBridgeLease(
    lease: AgentBridgeLeaseSummary,
    button: ButtonComponent
  ): Promise<void> {
    button.setDisabled(true).setButtonText("Revoking...");
    try {
      const revoked = this.plugin.revokeAgentBridgeLease(lease.leaseId);
      if (!revoked) {
        new Notice("VaultGuard Sync: that bridge lease was already gone.");
      } else {
        new Notice(`VaultGuard Sync: revoked bridge lease for ${lease.agentName}.`);
      }

      if (this.latestAgentBridgeReveal?.leaseId === lease.leaseId) {
        this.latestAgentBridgeReveal = null;
      }

      const remaining = this.plugin.getAgentBridge().describe().activeLeases.length;
      if (remaining === 0) {
        await this.plugin.stopAgentBridgeServer();
      }
      this.display();
    } catch (error) {
      new Notice(
        `VaultGuard Sync: could not revoke bridge lease - ${this.errorMessage(error)}`,
        8000
      );
      button.setDisabled(false).setButtonText("Revoke lease");
    }
  }

  private buildAgentBridgeConnectionJson(
    lease: AgentBridgeLeaseSecret,
    server: Pick<AgentBridgeServerInfo, "endpoint" | "mcpEndpoint" | "tools">
  ): string {
    return JSON.stringify(
      {
        endpoint: server.endpoint,
        mcpEndpoint: server.mcpEndpoint,
        token: lease.token,
        leaseId: lease.leaseId,
        expiresAt: lease.expiresAt,
        tools: server.tools,
      },
      null,
      2
    );
  }

  private buildAgentBridgeMcpConfig(
    lease: AgentBridgeLeaseSecret,
    server: Pick<AgentBridgeServerInfo, "mcpEndpoint">
  ): string {
    return JSON.stringify(
      {
        mcpServers: {
          vaultguard: {
            type: "http",
            url: server.mcpEndpoint,
            headers: {
              Authorization: `Bearer ${lease.token}`,
              "X-VaultGuard-Lease": lease.leaseId,
            },
          },
        },
      },
      null,
      2
    );
  }

  private renderAgentBridgeCopyBlock(
    parent: HTMLElement,
    opts: { title: string; body: string; copyLabel: string }
  ): void {
    const wrapper = parent.createDiv({ cls: "vaultguard-agent-bridge-copy-block" });
    wrapper.createDiv({ text: opts.title, cls: "vaultguard-agent-bridge-copy-title" });
    const codeBox = wrapper.createEl("pre", {
      cls: "vaultguard-agent-bridge-connection",
    });
    codeBox.setText(opts.body);

    const buttons = wrapper.createDiv({ cls: "vaultguard-agent-bridge-inline-actions" });
    const copyBtn = new ButtonComponent(buttons);
    copyBtn.setButtonText(opts.copyLabel).onClick(async () => {
      const copied = await this.writeClipboard(opts.body);
      new Notice(copied ? `${opts.title} copied.` : `Could not copy ${opts.title}.`);
    });
  }

  private async writeClipboard(value: string): Promise<boolean> {
    if (typeof navigator === "undefined" || !navigator.clipboard?.writeText) {
      return false;
    }
    try {
      await navigator.clipboard.writeText(value);
      return true;
    } catch {
      return false;
    }
  }

  private formatDateTime(value: string): string {
    const timestamp = Date.parse(value);
    return Number.isNaN(timestamp) ? value : new Date(timestamp).toLocaleString();
  }

  private formatBytes(bytes: number): string {
    if (!Number.isFinite(bytes) || bytes < 0) return String(bytes);
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }
}

/**
 * Parses an invite link of any of these shapes into `{ org, email, api, token, exp }`:
 *   - `obsidian://vaultguard-invite?org=acme&email=user@x.com`
 *   - `obsidian://vaultguard-invite?slug=acme&email=user@x.com&token=...`
 *   - bare query string: `org=acme&email=user@x.com`
 */
function parseInviteLink(raw: string): {
  org?: string;
  email?: string;
  api?: string;
  token?: string;
  exp?: string;
} {
  const trimmed = raw.trim();
  if (!trimmed) return {};

  let queryString = trimmed;

  // obsidian://vaultguard-invite?... → keep only the query
  const protocolPrefix = "obsidian://";
  if (trimmed.toLowerCase().startsWith(protocolPrefix)) {
    const queryIndex = trimmed.indexOf("?");
    queryString = queryIndex >= 0 ? trimmed.slice(queryIndex + 1) : "";
  } else if (trimmed.includes("?")) {
    queryString = trimmed.slice(trimmed.indexOf("?") + 1);
  }

  // Strip a leading "?" or "#" if a user pasted with the separator.
  queryString = queryString.replace(/^[?#]/, "");

  let params: URLSearchParams;
  try {
    params = new URLSearchParams(queryString);
  } catch {
    return {};
  }

  const org = (params.get("org") ?? params.get("slug") ?? "").trim().toLowerCase();
  const email = (params.get("email") ?? "").trim();
  const api = (params.get("api") ?? "").trim();
  const token = (params.get("token") ?? "").trim();
  const exp = (params.get("exp") ?? "").trim();

  return {
    ...(org ? { org } : {}),
    ...(email ? { email } : {}),
    ...(api ? { api } : {}),
    ...(token ? { token } : {}),
    ...(exp ? { exp } : {}),
  };
}
