/**
 * @fileoverview Settings interface and settings tab for the VaultGuard plugin.
 * Provides a comprehensive settings UI for configuring the permission-aware
 * encrypted cloud sync system.
 */

import { App, ButtonComponent, Notice, PluginSettingTab, Setting } from "obsidian";
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
  ".obsidian/workspace.json",
  ".obsidian/workspace-mobile.json",
  ".obsidian/cache",
  ".obsidian/plugins",
  ".obsidian/community-plugins.json",
  ".trash",
] as const;

export const DEFAULT_SETTINGS: VaultGuardSettings = {
  orgSlug: "",
  serverVaultId: "",
  apiEndpoint: SAAS_DEFAULTS.apiEndpoint,
  organizationId: "",
  cognitoUserPoolId: SAAS_DEFAULTS.cognitoUserPoolId,
  cognitoClientId: SAAS_DEFAULTS.cognitoClientId,
  syncInterval: 30,
  cacheEncryptionStrength: "standard",
  offlineKeyLeaseDuration: 24,
  autoWipeOnAuthFailure: false,
  showPermissionIndicators: true,
  defaultConflictResolution: ConflictResolutionStrategy.ASK_USER,
  debugLogging: false,
  maxRetryAttempts: 3,
  showStatusBar: true,
  excludedPaths: [...DEFAULT_EXCLUDED_PATHS],
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

  constructor(app: App, plugin: VaultGuardPlugin) {
    super(app, plugin);
    this.plugin = plugin;
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
    setTimeout(() => el.remove(), 6000);
  }

  /**
   * Renders the "Local at-rest encryption" panel. Surfaces the cipher's
   * current state (unlocked / needs-recovery / disabled), an on-disk file
   * tally, and the four operations a user might want from this UI:
   * full-vault encrypt, full-vault decrypt, view recovery code, restore
   * from recovery code. Re-rendered after every successful action so the
   * tally and status reflect what's actually on disk.
   */
  private renderAtRestSection(containerEl: HTMLElement): void {
    containerEl.createEl("h2", { text: "Local at-rest encryption" });
    containerEl.createEl("p", {
      text:
        "Vault files on this device are encrypted on disk with a key bound to your OS keychain (or, if unavailable, a per-device key). Without VaultGuard running, opening files in Finder shows ciphertext.",
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
              onConfirmed: async () => {
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
              onConfirmed: async () => {
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
                "VaultGuard: at-rest key restored. Reopening any open notes will now load decrypted content.",
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
        body = "VaultGuard is setting up the local at-rest cipher.";
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
    containerEl.createEl("h2", { text: "Vault settings" });
    const sectionEl = containerEl.createDiv({ cls: "vaultguard-current-vault-settings" });

    if (!session) {
      new Setting(sectionEl)
        .setName("Not connected")
        .setDesc("Log in before viewing, binding, creating, or changing server vaults.")
        .addButton((button) =>
          button
            .setButtonText("Login")
            .setCta()
            .onClick(() => this.plugin.triggerLogin())
        );
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
    this.renderVaultBindingSettings(
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
      this.renderLoadedVaultSettings(sectionEl, rootEl, session, currentVault, memberRole);
      this.renderVaultMembersSettings(sectionEl, rootEl, session, currentVault, memberRole);
    }

    this.renderCreateVaultSettings(sectionEl, rootEl, session);
  }

  private renderVaultBindingSettings(
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

    new Setting(sectionEl)
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

    if (currentVault?.description) {
      sectionEl.createDiv({
        text: currentVault.description,
        cls: "setting-item-description vaultguard-current-vault-description",
      });
    }

    if (boundId) {
      sectionEl.createDiv({
        text: `Vault ID: ${boundId}`,
        cls: "setting-item-description vaultguard-current-vault-id",
      });
    }

    sectionEl.createEl("h3", {
      text: "Available vaults",
      cls: "vaultguard-current-vault-heading",
    });

    if (vaultListError) {
      new Setting(sectionEl)
        .setName("Could not load vault list")
        .setDesc(this.errorMessage(vaultListError));
      return;
    }

    if (vaults.length === 0) {
      new Setting(sectionEl)
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

      new Setting(sectionEl)
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
    sectionEl: HTMLElement,
    rootEl: HTMLElement,
    session: UserSession
  ): void {
    sectionEl.createEl("h3", {
      text: "Create vault",
      cls: "vaultguard-current-vault-heading",
    });

    if (!this.isOrgAdmin(session)) {
      new Setting(sectionEl)
        .setName("New vaults")
        .setDesc("Only organization admins and owners can create server vaults.");
      return;
    }

    let nextName = this.app.vault.getName() || "My Vault";
    let nextDescription = "";
    let nextKind: VaultKind = "team";
    let nextDefaultRole: VaultMemberRole = "editor";

    new Setting(sectionEl)
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

    new Setting(sectionEl)
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

    new Setting(sectionEl)
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

    new Setting(sectionEl)
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

    new Setting(sectionEl)
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
    sectionEl: HTMLElement,
    rootEl: HTMLElement,
    session: UserSession,
    vault: VaultRecord,
    memberRole: VaultMemberRole | null
  ): void {
    const canEdit = this.canManageVault(session, memberRole);
    const canArchive = this.isOrgAdmin(session);

    sectionEl.createEl("h3", {
      text: "Current vault options",
      cls: "vaultguard-current-vault-heading",
    });

    if (!canEdit) {
      new Setting(sectionEl)
        .setName("Vault metadata")
        .setDesc("Only vault admins, organization admins, and owners can edit the vault name, description, and default role.");
      return;
    }

    let nextName = vault.name;
    let nextDescription = vault.description ?? "";
    let nextDefaultRole: VaultMemberRole = vault.defaultRole;

    new Setting(sectionEl)
      .setName("Name")
      .setDesc("Display name shown in VaultGuard vault lists.")
      .addText((text) =>
        text
          .setValue(nextName)
          .onChange((value) => {
            nextName = value;
          })
      );

    new Setting(sectionEl)
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

    new Setting(sectionEl)
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

    new Setting(sectionEl)
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
      new Setting(sectionEl)
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
    sectionEl: HTMLElement,
    rootEl: HTMLElement,
    session: UserSession,
    vault: VaultRecord,
    memberRole: VaultMemberRole | null
  ): void {
    sectionEl.createEl("h3", {
      text: "Vault members",
      cls: "vaultguard-current-vault-heading",
    });

    const membersEl = sectionEl.createDiv({ cls: "vaultguard-vault-members" });
    membersEl.createDiv({
      text: "Loading vault members…",
      cls: "setting-item-description vaultguard-current-vault-loading",
    });

    void this.renderVaultMembersContent(membersEl, rootEl, session, vault, memberRole);
  }

  private async renderVaultMembersContent(
    membersEl: HTMLElement,
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
      const users = usersResult.users;
      const userById = new Map(users.map((user) => [user.id, user]));
      const canManage = this.canManageVault(session, memberRole) && !vault.archived;

      membersEl.empty();
      if (usersResult.error) {
        new Setting(membersEl)
          .setName("User directory unavailable")
          .setDesc(`Members are shown by ID. ${this.errorMessage(usersResult.error)}`);
      }

      if (members.length === 0) {
        new Setting(membersEl)
          .setName("No members")
          .setDesc("This vault does not have any explicit members yet.");
      }

      for (const member of members) {
        this.renderVaultMemberRow(membersEl, rootEl, session, vault, member, userById, canManage);
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

      this.renderAddVaultMemberForm(membersEl, rootEl, session, vault, members, users);
    } catch (error) {
      membersEl.empty();
      new Setting(membersEl)
        .setName("Could not load vault members")
        .setDesc(this.errorMessage(error));
    }
  }

  private renderVaultMemberRow(
    membersEl: HTMLElement,
    rootEl: HTMLElement,
    session: UserSession,
    vault: VaultRecord,
    member: VaultMemberRecord,
    userById: Map<string, UserListEntry>,
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
              membersEl.parentElement ?? membersEl,
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
              membersEl.parentElement ?? membersEl,
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
              membersEl.parentElement ?? membersEl,
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

  private formatUserLabel(userId: string, user?: UserListEntry): string {
    if (!user) return userId;
    const name = user.displayName || user.name || user.email;
    return user.email && name !== user.email ? `${name} (${user.email})` : name;
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
    containerEl.createEl("h1", { text: "VaultGuard" });
    containerEl.createEl("p", {
      text: "Enterprise vault security with permission-aware encrypted cloud sync.",
      cls: "setting-item-description",
    });

    // ── Account ─────────────────────────────────────────────────────────────
    const session = this.plugin.getSession();
    if (session) {
      containerEl.createEl("h2", { text: "Account" });

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
      containerEl.createEl("h2", { text: "Account" });

      new Setting(containerEl)
        .setName("Not logged in")
        .setDesc("Log in to start syncing your vault.")
        .addButton((button) =>
          button
            .setButtonText("Login")
            .setCta()
            .onClick(() => {
              this.plugin.triggerLogin();
            })
        );
    }

    this.renderCurrentVaultSettings(containerEl, session);

    // ── Connection Settings ─────────────────────────────────────────────────
    containerEl.createEl("h2", { text: "Connection" });

    const isManualMode = this.plugin.settings.manualConfig ?? false;

    // Mode toggle
    new Setting(containerEl)
      .setName("Configuration mode")
      .setDesc(
        isManualMode
          ? "Using manual configuration for self-hosted deployments."
          : "Auto-configure by entering your organization slug."
      )
      .addToggle((toggle) =>
        toggle
          .setTooltip("Toggle between auto and manual configuration")
          .setValue(isManualMode)
          .onChange(async (value) => {
            this.plugin.settings.manualConfig = value;
            await this.plugin.saveSettings();
            this.display();
          })
      );

    if (!isManualMode) {
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
        .setName("Cognito User Pool ID")
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
        .setName("Cognito Client ID")
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

    // ── Sync Settings ───────────────────────────────────────────────────────
    containerEl.createEl("h2", { text: "Synchronization" });
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
          .addOption(
            ConflictResolutionStrategy.MERGE,
            "Attempt auto-merge (markdown)"
          )
          .setValue(this.plugin.settings.defaultConflictResolution)
          .onChange(async (value) => {
            this.plugin.settings.defaultConflictResolution =
              value as ConflictResolutionStrategy;
            await this.plugin.saveSettings();
          })
      );

    const excludedPathsSetting = new Setting(containerEl)
      .setName("Excluded paths (local-only)")
      .setDesc(
        "One path per line. Files and folders matching these patterns are never uploaded, " +
        "downloaded, or deleted on the server — they stay on this device only. Use exact " +
        "paths (e.g. .obsidian/workspace.json) or folder prefixes (e.g. .obsidian/plugins). " +
        "This setting applies to this device only; it does not change the server vault."
      )
      .addTextArea((textArea) => {
        textArea.inputEl.rows = 6;
        textArea.inputEl.addClass("vaultguard-mono-textarea");
        textArea
          .setPlaceholder(".obsidian/workspace.json\n.obsidian/plugins\n.trash")
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
            const confirmed = window.confirm(
              "Delete every matching file from the shared server vault? " +
              "Other members will lose these files on their next sync. " +
              "Local copies on this device are kept.\n\n" +
              `Patterns:\n${patterns.join("\n")}`
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

    // ── Security Settings ───────────────────────────────────────────────────
    containerEl.createEl("h2", { text: "Security" });

    new Setting(containerEl)
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

    new Setting(containerEl)
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

    new Setting(containerEl)
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

    // ── Display Settings ────────────────────────────────────────────────────
    containerEl.createEl("h2", { text: "Display" });

    new Setting(containerEl)
      .setName("Show permission indicators")
      .setDesc(
        "Display permission level icons (lock, pencil, shield) next to files in the file explorer."
      )
      .addToggle((toggle) =>
        toggle
          .setValue(this.plugin.settings.showPermissionIndicators)
          .onChange(async (value) => {
            this.plugin.settings.showPermissionIndicators = value;
            await this.plugin.saveSettings();
            this.plugin.refreshFileExplorerDecorations();
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

    // ── Local at-rest encryption ────────────────────────────────────────────
    this.renderAtRestSection(containerEl);

    // ── Agent bridge connections ────────────────────────────────────────────
    this.renderAgentBridgeSection(containerEl);

    // ── Advanced Settings ───────────────────────────────────────────────────
    containerEl.createEl("h2", { text: "Advanced" });

    new Setting(containerEl)
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

    new Setting(containerEl)
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

    new Setting(containerEl)
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

    // ── Danger Zone ─────────────────────────────────────────────────────────
    containerEl.createEl("h2", { text: "Danger Zone" });
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
          .setButtonText("Clear Cache")
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

    new Setting(containerEl)
      .setName("Force logout")
      .setDesc(
        "Immediately invalidate your session and clear all credentials from this device."
      )
      .addButton((button) =>
        button
          .setButtonText("Logout")
          .setWarning()
          .onClick(async () => {
            const confirmed = await this.showDestructiveConfirmation(
              containerEl,
              "LOGOUT",
              "Type LOGOUT to confirm. This will invalidate your session and wipe local credentials."
            );
            if (confirmed) {
              await this.plugin.forceLogout();
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
    containerEl.createEl("h2", { text: "Agent bridge connections" });
    containerEl.createEl("p", {
      cls: "setting-item-description",
      text:
        "Agent bridge leases let an external agent (Claudian, Claude Code, Cursor, custom MCP client) talk to this vault through VaultGuard tools. Each lease has its own bearer token; revoking or rotating one does not disturb the others. Hidden paths (.obsidian, .trash, .git, ...) are always blocked.",
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
              new Notice("VaultGuard: all agent bridge leases revoked.");
              this.display();
            } catch (error) {
              new Notice(
                `VaultGuard: could not revoke bridge leases - ${this.errorMessage(error)}`,
                8000
              );
              button.setDisabled(false).setButtonText("Revoke all leases");
            }
          })
      );

    this.renderAgentBridgeServerState(containerEl, server, activeLeases.length);
    this.renderLatestAgentBridgeReveal(containerEl);
    this.renderAgentBridgeSkillRow(containerEl);

    containerEl.createEl("h3", {
      text: "Current leases",
      cls: "vaultguard-current-vault-heading",
    });

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
                  `VaultGuard: could not start the bridge server - ${this.errorMessage(error)}`,
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
      return `A SKILL.md exists at ${status.skillFilePath} but wasn't installed by VaultGuard. Overwriting will replace it. Cancel and inspect the file if you didn't expect this.`;
    }
    if (status.installed) {
      return `Installed at ${status.skillFilePath}. The skill teaches Claude Code (and any agent that loads ~/.claude/skills/) to use VaultGuard's MCP tools instead of Read/Glob/Grep against encrypted vault files. Re-install to pull the latest skill body.`;
    }
    return `Writes a SKILL.md to ${status.skillFilePath}. Tells Claude Code to reach for VaultGuard's MCP tools when it sees an encrypted vault, rather than reading ciphertext directly. Contains no tokens or per-user state.`;
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
      new Notice(`VaultGuard: Claude Code skill ${verb} at ${result.filePath}.`, 6000);
      this.display();
    } catch (error) {
      new Notice(
        `VaultGuard: could not install skill - ${this.errorMessage(error)}`,
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
        new Notice(`VaultGuard: Claude Code skill removed from ${result.filePath}.`, 6000);
      } else {
        new Notice("VaultGuard: no managed skill file to remove.", 4000);
      }
      this.display();
    } catch (error) {
      new Notice(
        `VaultGuard: could not uninstall skill - ${this.errorMessage(error)}`,
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
          ? "VaultGuard: new MCP config copied. Update the agent using this lease."
          : "VaultGuard: token rotated. Copy the new config shown in settings.",
        8000
      );
      this.display();
    } catch (error) {
      new Notice(
        `VaultGuard: could not rotate bridge token - ${this.errorMessage(error)}`,
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
        new Notice("VaultGuard: that bridge lease was already gone.");
      } else {
        new Notice(`VaultGuard: revoked bridge lease for ${lease.agentName}.`);
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
        `VaultGuard: could not revoke bridge lease - ${this.errorMessage(error)}`,
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
    wrapper.createEl("h4", { text: opts.title });
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
 * Parses an invite link of any of these shapes into `{ org, email, api }`:
 *   - `obsidian://vaultguard-invite?org=acme&email=user@x.com`
 *   - `obsidian://vaultguard-invite?slug=acme&email=user@x.com&api=https://...`
 *   - bare query string: `org=acme&email=user@x.com`
 */
function parseInviteLink(raw: string): { org?: string; email?: string; api?: string } {
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

  return {
    ...(org ? { org } : {}),
    ...(email ? { email } : {}),
    ...(api ? { api } : {}),
  };
}
