/**
 * @fileoverview Settings interface and settings tab for the VaultGuard plugin.
 * Provides a comprehensive settings UI for configuring the permission-aware
 * encrypted cloud sync system.
 */

import {
  App,
  ButtonComponent,
  Notice,
  Platform,
  PluginSettingTab,
  SearchComponent,
  SecretComponent,
  Setting,
  SettingGroup,
  requireApiVersion,
} from "obsidian";
import {
  AtRestPasswordConfirmModal,
  AtRestRecoveryCodeModal,
  AtRestRestoreModal,
} from "./at-rest-modals";
import {
  AtRestRecoveryModal,
  computeAtRestResetButtonState,
} from "../ui/at-rest-recovery-modal";
import { AgentBridgeLeaseModal } from "./agent-bridge-modal";
import type VaultGuardPlugin from "./main";
import {
  VaultGuardSettings,
  ConflictResolutionStrategy,
  UserSession,
} from "../types";
import type { AnthropicEffort, OptionalModuleId } from "../types";
import { AnthropicKeyStore, OpenAiKeyStore } from "../ui/chat/api-key-store";
import {
  AI_CHAT_MODELS,
  AI_CHAT_EFFORTS,
  AI_CHAT_PERMISSION_MODES,
  CLAUDE_SUBSCRIPTION_MODELS,
  DEFAULT_CLAUDE_SUBSCRIPTION_MODEL,
  OPENAI_CHAT_MODELS,
  OPENAI_REASONING_EFFORTS,
  OPENAI_VERBOSITIES,
} from "../ui/chat/models";
import {
  providerModelCatalog,
  type ProviderModelCatalogProvider,
} from "../ui/chat/model-catalog";
import {
  getClaudeAuthStatus,
  type ClaudeAuthStatus,
} from "../ui/chat/claude-cli/claude-detector";
import {
  getCodexAuthStatus,
  type CodexAuthStatus,
} from "../ui/chat/codex-cli/codex-detector";
import type {
  UserListEntry,
  VaultKind,
  VaultMemberRecord,
  VaultMemberRole,
  VaultRecord,
} from "../api/client";
import { deriveGuestPresentation } from "../admin/guest-presentation";
import type {
  AgentBridgeLeaseSecret,
  AgentBridgeLeaseSummary,
  AgentBridgeServerInfo,
  ChatGptConnectorSessionSecret,
  ChatGptConnectorSessionSummary,
} from "./agent-bridge";
import type { VaultOrientationSnapshot } from "./vault-orientation";
import {
  AUTOMATION_REGISTRY_SCHEMA_VERSION,
  normalizeAutomationRegistry,
  normalizeAutomationVaultPath,
  type AutomationRegistrySettings,
} from "./agent-automation-registry";
import {
  buildCodexAgentsGuidance,
  buildCodexConfigToml,
  buildCodexTempWorkspaceLaunchCommand,
  buildCodexTokenEnvCommand,
} from "./agent-bridge-codex";
import type { SkillInstallStatus } from "./agent-bridge-skill/installer";
import type { CodexSkillInstallStatus } from "./agent-bridge-codex-skill/installer";
import { SAAS_DEFAULTS } from "../config/saas-defaults";
import { SetPinModal, ChangePinModal, DisablePinModal } from "../ui/lock/pin-modals";
import { biometricAvailable } from "../crypto/biometric-probe";
import { createI18n } from "../i18n";

// ─────────────────────────────────────────────────────────────────────────────
// Default Settings
// ─────────────────────────────────────────────────────────────────────────────

// Re-exported for callers that import SAAS_DEFAULTS from settings.
export { SAAS_DEFAULTS };

/**
 * Human-readable label for the bundled API host, e.g. "api.example.com".
 * Derived from SAAS_DEFAULTS so UI copy can never state a host the build does
 * not actually use — the public export scrubs the domain everywhere except
 * saas-defaults.ts, so a hardcoded literal would ship as a false claim.
 */
export function saasDefaultsHostLabel(): string {
  const endpoint = SAAS_DEFAULTS.apiEndpoint.trim();
  if (!endpoint) return "cloud";
  try {
    return new URL(endpoint).host || "cloud";
  } catch {
    return endpoint.replace(/^https?:\/\//, "").replace(/\/.*$/, "") || "cloud";
  }
}

const MAX_AGENT_TEMPLATE_ALLOWLIST_ENTRIES = 64;
const MAX_AUTOMATION_POLICY_JSON_CHARACTERS = 128 * 1024;
const TEMPLATE_PATTERN_CHARACTERS = /[*?[\]{}]/;

/**
 * Tolerant persisted-settings parser for agent template trust. Only exact,
 * vault-relative Markdown paths survive; malformed input narrows to an empty or
 * smaller allowlist and can never widen agent access.
 */
/**
 * Normalize the "Save Claude artifact" destination folder.
 *
 * This is the traversal guard for the artifact importer: the value is persisted
 * in `data.json`, so a hand-edited or corrupted entry is untrusted input that
 * ends up in a `vault.create()` path. Anything that could aim a write outside
 * the vault — an absolute path, a Windows drive letter, a `..` segment — falls
 * back to the default rather than being "cleaned up", because a silently
 * rewritten path is harder to notice than a reset one.
 *
 * An empty/whitespace value is legitimate and means the vault root.
 */
export function normalizeArtifactImportFolder(value: unknown): string {
  if (typeof value !== "string") return DEFAULT_SETTINGS.artifactImportFolder;

  const trimmed = value.trim().replace(/\\/g, "/");
  if (trimmed.length === 0) return "";

  const isAbsolute = trimmed.startsWith("/") || /^[a-zA-Z]:\//.test(trimmed);
  const segments = trimmed.split("/").filter((segment) => segment.length > 0);
  const escapes = segments.some((segment) => segment === "..");
  if (isAbsolute || escapes) return DEFAULT_SETTINGS.artifactImportFolder;

  return segments.join("/");
}

export function normalizeAgentTemplateAllowlist(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const output: string[] = [];
  for (const candidate of value.slice(0, MAX_AGENT_TEMPLATE_ALLOWLIST_ENTRIES)) {
    if (typeof candidate !== "string") continue;
    const trimmed = candidate.trim();
    if (!trimmed || trimmed.startsWith("/") || TEMPLATE_PATTERN_CHARACTERS.test(trimmed)) {
      continue;
    }
    const normalized = normalizeAutomationVaultPath(trimmed);
    if (!normalized || !normalized.toLocaleLowerCase().endsWith(".md")) continue;
    if (!output.includes(normalized)) output.push(normalized);
  }
  return output;
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => stableJson(item)).join(",")}]`;
  const record = value as Record<string, unknown>;
  const members = Object.keys(record)
    .filter((key) => record[key] !== undefined)
    .sort((left, right) => left.localeCompare(right))
    .map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`);
  return `{${members.join(",")}}`;
}

export type AutomationPolicyJsonImportResult =
  | { ok: true; registry: AutomationRegistrySettings }
  | { ok: false; error: string };

/**
 * Strict human import lane. Persisted settings remain tolerant, but the editor
 * rejects the whole draft when normalization would drop or rewrite any policy.
 * The JSON is an entries array only, so it cannot alter the separate master
 * enable switch.
 */
export function parseAutomationPolicyJsonImport(
  value: string,
  masterEnabled: boolean,
): AutomationPolicyJsonImportResult {
  if (!value || value.length > MAX_AUTOMATION_POLICY_JSON_CHARACTERS) {
    return { ok: false, error: "Policy JSON is empty or exceeds the 128 KB limit." };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return { ok: false, error: "Policy JSON is not valid JSON." };
  }
  if (!Array.isArray(parsed)) {
    return {
      ok: false,
      error: "Policy JSON must be an array. The master switch is managed separately.",
    };
  }
  const normalized = normalizeAutomationRegistry({
    schemaVersion: AUTOMATION_REGISTRY_SCHEMA_VERSION,
    enabled: masterEnabled,
    entries: parsed,
  });
  if (
    normalized.entries.length !== parsed.length ||
    stableJson(normalized.entries) !== stableJson(parsed)
  ) {
    return {
      ok: false,
      error:
        "No policies were imported. Every entry must be canonical, unique, and outside VaultGuard's hard-denied command classes.",
    };
  }
  return {
    ok: true,
    registry: {
      ...normalized,
      enabled: masterEnabled,
    },
  };
}

export type AgentTemplateAllowlistImportResult =
  | { ok: true; paths: string[] }
  | { ok: false; error: string };

/** Strict editor lane: reject the whole draft instead of silently dropping a line. */
export function parseAgentTemplateAllowlistImport(
  value: string,
): AgentTemplateAllowlistImportResult {
  const requested = value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const normalized = normalizeAgentTemplateAllowlist(requested);
  if (
    requested.length !== normalized.length ||
    requested.some((path, index) => path !== normalized[index])
  ) {
    return {
      ok: false,
      error:
        "No template paths were saved. Use unique, exact vault-relative .md paths without hidden, traversal, absolute, or wildcard segments.",
    };
  }
  return { ok: true, paths: normalized };
}

/**
 * Default plugin settings applied on first installation or when
 * individual settings are missing from persisted data.
 */

export const DEFAULT_EXCLUDED_PATHS = [
  ".trash",
  // Same-device uninstall recovery. The manifest is non-secret and capsules
  // are sealed, but neither is vault content: never sync or at-rest-wrap them.
  ".vaultguard",
] as const;

export const DEFAULT_SETTINGS: VaultGuardSettings = {
  orgSlug: "",
  serverVaultId: "",
  apiEndpoint: "",
  organizationId: "",
  cognitoUserPoolId: "",
  cognitoClientId: "",
  loginVerificationMode: "disabled",
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
  showRibbonIcons: true,
  statusBarMode: "full",
  showAiChatRibbonIcon: true,
  showPermissionsGraphRibbonIcon: true,
  localProjectMemoryMode: false,
  localProjectMemoryModeAutoEnableSuppressed: false,
  optionalModules: {
    schemaVersion: 2,
    // AI chat + permissions graph ship enabled by default (each still has its own
    // ribbon icon and can be turned off per-vault in Settings → VaultGuard).
    aiChat: true,
    permissionsGraph: true,
    agentAccess: false,
    secureDiscovery: false,
  },
  semanticSearchEnabled: false,
  semanticEmbeddingEndpoint: "http://127.0.0.1:11434",
  semanticEmbeddingModel: "embeddinggemma",
  discoveryResultLimit: 50,
  automationRegistry: {
    schemaVersion: AUTOMATION_REGISTRY_SCHEMA_VERSION,
    enabled: false,
    entries: [],
  },
  agentTemplateAllowlist: [],
  excludedPaths: [...DEFAULT_EXCLUDED_PATHS],
  aiChatModel: "claude-opus-4-8",
  // A tier alias, not a version — the CLI resolves it to the newest Opus.
  claudeSubscriptionModel: DEFAULT_CLAUDE_SUBSCRIPTION_MODEL,
  aiChatEffort: "high",
  openAiModel: "gpt-5.5",
  codexModel: "gpt-5.5",
  codexAutoSelectLatest: true,
  openAiReasoningEffort: "medium",
  openAiVerbosity: "medium",
  openAiMaxOutputTokens: 8192,
  // On by default for live token-by-token feedback. Desktop-only; mobile always
  // falls back to the Tier-1 requestUrl path (see chat-view streamingEnabled()).
  aiChatStreaming: true,
  artifactImportFolder: "Claude Artifacts",
  anthropicKeyStorageMode: "vaultguard",
  openAiKeyStorageMode: "vaultguard",
  // On by default: a key entered on desktop auto-provisions on mobile without
  // re-entry. Stored server-side ONLY as a DEK-wrapped envelope (zero-knowledge).
  aiChatKeySyncEnabled: true,
  aiChatPermissionMode: "confirm",
  // Claude subscription first: a fresh desktop install should spend the user's
  // existing Claude Pro/Max login, not ask them to buy API credits. Nothing is
  // spawned or called until the user sends a message, and the panel explains how
  // to install/sign in — or switch to an API key — if the CLI isn't ready.
  // Mobile cannot run a CLI at all, so normalizeAiChatProvider() resolves this
  // to "apiKey" there at load time.
  aiChatProvider: "subscription",
  permissionsGraphDefaults: {
    schemaVersion: 2,
    renderMode: "auto",
    layoutMode: "auto",
    labelsMode: "auto",
    searchScope: "all",
    accessLevels: { read: true, write: true, admin: true },
    nodeTypes: { users: true, files: true, folders: true },
    maxFiles: 1000,
    maxEdges: 1600,
    depth: 2,
    appearance: {
      backgroundMode: "theme",
      backgroundPattern: "none",
      backgroundPrimary: "#1e1e1e",
      backgroundSecondary: "#252a34",
      colorMode: "current",
      customPalette: false,
      palette: {
        user: "#7c3aed",
        file: "#14b8a6",
        folder: "#f59e0b",
        read: "#22c55e",
        write: "#f59e0b",
        admin: "#ef4444",
        low: "#94a3b8",
        medium: "#3b82f6",
        high: "#a855f7",
      },
      sizeMode: "standard",
      nodeScale: 1,
      edgeScale: 1,
    },
    arrangement: {
      sectionBy: "folder",
      sortBy: "name",
      sortDirection: "asc",
    },
  },
  permissionsGraphVaultStates: {},
  deletionTombstones: {},
  pendingLargeFiles: {},
  // Persisted once-ever guard for the onboarding "Set a PIN" prompt (quick
  // 260708-el6). A persisted `true` overrides this default via the reload merge
  // (Object.assign({}, DEFAULT_SETTINGS, data)), so the prompt shows at most once.
  pinOnboardingPromptShown: false,
  // Passkey model by default (Phase 12-07): enrolling a PIN KEEPS the transparent
  // at-rest wrap, so login/startup unlock without a PIN and the PIN only re-locks
  // on idle. true = max-security (transparent wrap removed; PIN every startup).
  requirePinOnStartup: false,
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

/**
 * The narrow client surface the vault-member guest controls need, injected so
 * the orchestration below is callable from a `node` test without Obsidian, a
 * DOM or a network.
 *
 * `revokeUser` is here for two reasons: End now calls it, and the extend
 * sequence must be able to be OBSERVED not calling it (see
 * `runGuestExtendSequence`).
 */
export interface GuestMemberActionClient {
  extendGuestAccess(userId: string, expiresInDays: number): Promise<unknown>;
  reactivateUser(userId: string): Promise<void>;
  revokeUser(userId: string): Promise<void>;
}

/** Which guest controls a vault-member row should offer. */
export interface GuestMemberControls {
  /** Temporary access, so its boundary can be moved. */
  showExtend: boolean;
  /** Temporary access, so it can be ended before its boundary. */
  showEndNow: boolean;
  /**
   * This row IS the signed-in user.
   *
   * A row-level IDENTITY fact, not a guest fact — it is computed from the
   * session regardless of access kind, and the vault-role dropdown reads it on
   * every row, including permanent members who have no guest controls at all.
   * It lives here only because this is the one place the row's decisions are
   * observable from a test.
   */
  isSelf: boolean;
  /**
   * The identity is disabled while its guest row still EXISTS.
   *
   * This is a narrow, rare state: it arises only when the teardown failed
   * partway — the account was disabled and the seat released, but the row
   * deletes did not complete. It is NOT the normal post-expiry state, in which
   * the guest has no membership row at all and therefore never reaches this
   * row-level decision.
   */
  needsReactivateFirst: boolean;
}

/** The result of the reactivate-then-extend sequence. */
export type GuestExtendOutcome =
  | { status: "extended"; reactivated: boolean }
  | { status: "reactivate-failed"; message: string }
  | { status: "extend-failed"; message: string }
  | { status: "extend-failed-after-reactivate"; message: string };

interface AgentBridgeConnectionReveal {
  leaseId: string;
  agentName: string;
  connectionJson: string;
  mcpConfig: string;
  codexConfig: string;
  codexTokenCommand: string;
  codexLaunchCommand: string;
  codexAgentsGuidance: string;
  copiedToClipboard: boolean;
}

interface ChatGptConnectorReveal {
  sessionId: string;
  setupInstructions: string;
  copiedToClipboard: boolean;
}

interface SettingsStatusMessage {
  id: number;
  message: string;
  isError: boolean;
}

/** Every top-level Settings section is an independently tracked disclosure. */
type SettingsCollapsibleSectionId =
  | "protection"
  | "connection"
  | "account"
  | "vault"
  | "synchronization"
  | "access-unlock"
  | "display"
  | "capabilities"
  | "manage-vaults-members"
  | "encryption-maintenance"
  | "advanced"
  | "ai-automation"
  | "danger-zone";

/** Settings always loads with every section collapsed. */
const DEFAULT_OPEN_SECTIONS: readonly SettingsCollapsibleSectionId[] = [];

/** Marks the tab while a search is active, so non-`Setting` blocks (lead copy,
 *  notes, status panels) can drop out of a result list via CSS alone. */
const FILTERING_CLS = "vaultguard-settings-filtering";
/** Applied to rows, headings and disclosures filtered out by the search. */
const FILTER_HIDDEN_CLS = "vaultguard-settings-filter-hidden";
/** Wrapper for the search control itself — never filtered. */
const SEARCH_CLS = "vaultguard-settings-search";

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
  private readonly i18n = createI18n();
  private latestAgentBridgeReveal: AgentBridgeConnectionReveal | null = null;
  private latestChatGptConnectorReveal: ChatGptConnectorReveal | null = null;
  private aiChatKeyStore: AnthropicKeyStore | null = null;
  private openAiKeyStore: OpenAiKeyStore | null = null;
  private codexStatusAbort: AbortController | null = null;
  private codexModelAbort: AbortController | null = null;
  private latestVaultOrientationSnapshot: VaultOrientationSnapshot | null = null;
  private vaultOrientationRequestGeneration = 0;
  private readonly openCollapsibleSectionIds = new Set<SettingsCollapsibleSectionId>();
  /** Sections rendered at least once this session. Distinguishes "never shown,
   *  so apply its default" from "shown and currently closed by the user". */
  private readonly collapsibleSectionSeenIds = new Set<SettingsCollapsibleSectionId>();
  private collapsibleSectionSessionActive = false;
  private collapsibleSectionStateEpoch = 0;
  /** Current search text. Survives `display()` re-renders so a filtered view is
   *  not thrown away when a toggle triggers a re-render. Cleared by `hide()`. */
  private settingsFilterQuery = "";
  private latestSettingsStatus: SettingsStatusMessage | null = null;
  private settingsStatusSequence = 0;
  private settingsStatusTimer: number | null = null;
  /** Set while the filter opens disclosures programmatically. Without it the
   *  native `toggle` listener would record those forced opens as user intent and
   *  permanently mark every section as open once someone searched. */
  private suppressCollapsibleTracking = false;

  constructor(app: App, plugin: VaultGuardPlugin) {
    super(app, plugin);
    this.plugin = plugin;
  }

  private getAnthropicKeyStore(): AnthropicKeyStore {
    this.aiChatKeyStore ??= new AnthropicKeyStore(this.plugin);
    return this.aiChatKeyStore;
  }

  private getOpenAiKeyStore(): OpenAiKeyStore {
    this.openAiKeyStore ??= new OpenAiKeyStore(this.plugin);
    return this.openAiKeyStore;
  }

  private renderProviderKeyStorageSetting(
    containerEl: HTMLElement,
    provider: "anthropic" | "openai",
    keyStore: AnthropicKeyStore | OpenAiKeyStore,
  ): void {
    const field = provider === "anthropic"
      ? "anthropicKeyStorageMode"
      : "openAiKeyStorageMode";
    const current = this.plugin.settings[field] ?? "vaultguard";
    const nativeAvailable = keyStore.isObsidianSecretStorageAvailable() &&
      typeof SecretComponent === "function";

    new Setting(containerEl)
      .setName("API key storage")
      .setDesc(
        current === "obsidian"
          ? nativeAvailable
            ? "Use Obsidian's global encrypted secret store. VaultGuard persists only the selected secret ID."
            : "Native storage remains selected, but it needs Obsidian 1.11.5 or newer. VaultGuard will not fall back to another key source."
          : "Keep the key vault-local in VaultGuard's encrypted key envelope. This is compatible with older Obsidian versions.",
      )
      .addDropdown((dropdown) => {
        dropdown.addOption("vaultguard", "VaultGuard (this vault)");
        if (nativeAvailable || current === "obsidian") {
          dropdown.addOption(
            "obsidian",
            nativeAvailable
              ? "Obsidian secrets (global)"
              : "Obsidian secrets (requires 1.11.5)",
          );
        }
        dropdown
          .setValue(current)
          .onChange(async (value) => {
            if (value !== "vaultguard" && value !== "obsidian") return;
            this.plugin.settings[field] = value;
            if (provider === "anthropic" && value === "obsidian") {
              this.plugin.settings.aiChatKeySyncEnabled = false;
            }
            await this.plugin.saveSettings();
            providerModelCatalog.invalidate(provider);
            if (provider === "anthropic" && value === "obsidian") {
              // Remove an old VaultGuard roaming copy; the global Obsidian
              // secret remains exclusively owned by Obsidian.
              void this.plugin.aiKeySync.deleteRemote();
            }
            this.display();
          });
      });
  }

  private renderNativeProviderSecretSetting(
    containerEl: HTMLElement,
    providerLabel: "Anthropic" | "OpenAI",
    keyStore: AnthropicKeyStore | OpenAiKeyStore,
  ): void {
    const available = keyStore.isObsidianSecretStorageAvailable() &&
      typeof SecretComponent === "function";
    const hasKey = keyStore.hasKey();
    const setting = new Setting(containerEl)
      .setName(`${providerLabel} secret`)
      .setDesc(
        available
          ? hasKey
            ? "The selected native secret is available. Its value never enters VaultGuard settings."
            : "Choose or create a native secret. VaultGuard stores only its ID and never displays its value."
          : "Unavailable on this Obsidian version. Upgrade to 1.11.5 or newer, or switch back to VaultGuard storage.",
      );

    if (!available) return;

    new SecretComponent(this.app, setting.controlEl)
      .setValue(keyStore.getSecretId())
      .onChange(async (secretId) => {
        try {
          await keyStore.setSecretId(secretId);
          providerModelCatalog.invalidate(providerLabel.toLowerCase() as "anthropic" | "openai");
          this.showStatus(containerEl, `${providerLabel} secret reference saved.`, false);
          this.display();
        } catch (error) {
          this.showStatus(
            containerEl,
            `Failed to save secret reference: ${(error as Error).message}`,
            true,
          );
        }
      });

    if (keyStore.getSecretId()) {
      setting.addButton((button) => {
        button
          .setButtonText("Clear reference")
          .setTooltip("Forget this reference without deleting the global Obsidian secret")
          .onClick(async () => {
            await keyStore.clearKey();
            providerModelCatalog.invalidate(providerLabel.toLowerCase() as "anthropic" | "openai");
            this.display();
          });
      });
    }
  }

  hide(): void {
    this.codexStatusAbort?.abort();
    this.codexStatusAbort = null;
    this.codexModelAbort?.abort();
    this.codexModelAbort = null;
    this.vaultOrientationRequestGeneration += 1;
    this.latestVaultOrientationSnapshot = null;
    this.openCollapsibleSectionIds.clear();
    this.collapsibleSectionSeenIds.clear();
    this.collapsibleSectionSessionActive = false;
    this.collapsibleSectionStateEpoch += 1;
    // Reopening Settings should start from the configured defaults, not from
    // whatever someone last typed into the search box.
    this.settingsFilterQuery = "";
    this.latestSettingsStatus = null;
    if (this.settingsStatusTimer !== null) {
      window.clearTimeout(this.settingsStatusTimer);
      this.settingsStatusTimer = null;
    }
    super.hide();
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
        "for consent once before enabling the locally installed copy; VaultGuard syncs " +
        "only the allowlist metadata."
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
    const status: SettingsStatusMessage = {
      id: ++this.settingsStatusSequence,
      message,
      isError,
    };
    this.latestSettingsStatus = status;
    if (this.settingsStatusTimer !== null) {
      window.clearTimeout(this.settingsStatusTimer);
    }

    const sharedHost = this.containerEl.querySelector<HTMLElement>(
      ".vaultguard-settings-status-host",
    );
    if (sharedHost) {
      this.renderSettingsStatus(sharedHost);
    } else {
      // A few focused render helpers are exercised independently in tests and
      // modal flows. Preserve useful local feedback when the shared shell is
      // not mounted yet.
      const localHost = containerEl.createDiv({ cls: "vaultguard-settings-status-host" });
      this.renderSettingsStatus(localHost);
    }

    this.settingsStatusTimer = window.setTimeout(() => {
      if (this.latestSettingsStatus?.id !== status.id) return;
      this.latestSettingsStatus = null;
      this.settingsStatusTimer = null;
      const currentHost = this.containerEl.querySelector<HTMLElement>(
        ".vaultguard-settings-status-host",
      );
      if (currentHost) this.renderSettingsStatus(currentHost);
    }, 6000);
  }

  private renderSettingsStatus(host: HTMLElement): void {
    host.empty();
    const status = this.latestSettingsStatus;
    if (!status) {
      host.setAttribute("aria-hidden", "true");
      return;
    }
    host.removeAttribute("aria-hidden");
    const el = host.createDiv({ cls: "vaultguard-status-msg" });
    el.addClass(status.isError ? "is-error" : "is-success");
    el.setAttribute("role", status.isError ? "alert" : "status");
    el.setAttribute("aria-live", status.isError ? "assertive" : "polite");
    el.setAttribute("aria-atomic", "true");
    el.setText(status.message);
  }

  /** `nested` suppresses the section's own heading when an enclosing disclosure
   *  already shows the same label. */
  private renderOptionalModulesSection(containerEl: HTMLElement, nested = false): void {
    const modules = [
      {
        id: "aiChat" as const,
        nameKey: "settings.modules.ai.name" as const,
        descriptionKey: "settings.modules.ai.description" as const,
      },
      {
        id: "permissionsGraph" as const,
        nameKey: "settings.modules.graph.name" as const,
        descriptionKey: "settings.modules.graph.description" as const,
      },
      {
        id: "agentAccess" as const,
        nameKey: "settings.modules.agent.name" as const,
        descriptionKey: "settings.modules.agent.description" as const,
      },
      {
        id: "secureDiscovery" as const,
        nameKey: "settings.modules.discovery.name" as const,
        descriptionKey: "settings.modules.discovery.description" as const,
      },
    ];

    const configure = (
      setting: Setting,
      module: (typeof modules)[number],
    ): void => {
      const moduleName = this.i18n.t(module.nameKey);
      setting
        .setName(moduleName)
        .setDesc(this.i18n.t(module.descriptionKey))
        .addToggle((toggle) => {
          // Tag the switch so the focus restore below can find the *new*
          // element after `display()` has rebuilt the tab. `toggleEl` is public
          // API and Obsidian builds it as
          // `<label class="checkbox-container" tabindex="0">`, so it takes
          // focus directly. Typed as possibly-undefined because the test
          // doubles hand back a toggle component without it.
          const toggleEl: HTMLElement | undefined = toggle.toggleEl;
          if (toggleEl?.dataset) {
            toggleEl.dataset.vaultguardModule = module.id;
          }
          toggle
            .setValue(this.plugin.isOptionalModuleEnabled(module.id))
            .setDisabled(module.id === "agentAccess" && Platform.isMobileApp)
            .onChange(async (enabled) => {
              toggle.setDisabled(true);
              try {
                await this.plugin.setOptionalModuleEnabled(module.id, enabled);
                // No success banner here. The switch moving, plus the "AI &
                // automation" disclosure appearing or disappearing beneath it,
                // already says what happened, and Obsidian's own settings
                // never confirm a toggle. The failure branch below keeps its
                // banner: that one carries information the UI cannot show.
                this.display();
                this.restoreModuleToggleFocus(module.id);
              } catch (error) {
                this.showStatus(
                  containerEl,
                  this.i18n.t("settings.module.failed", {
                    name: moduleName,
                    message: error instanceof Error ? error.message : String(error),
                  }),
                  true,
                );
                toggle.setValue(this.plugin.isOptionalModuleEnabled(module.id));
                toggle.setDisabled(false);
              }
            });
        });
    };

    if (
      typeof requireApiVersion === "function" &&
      requireApiVersion("1.11.0") &&
      typeof SettingGroup === "function"
    ) {
      // Empty heading detaches the group's header row. The enclosing disclosure
      // already carries this label, and repeating it directly beneath the
      // summary reads as a rendering bug.
      const group = new SettingGroup(containerEl).setHeading(
        nested ? "" : this.i18n.t("settings.modules.heading"),
      );
      for (const module of modules) {
        group.addSetting((setting) => configure(setting, module));
      }
      return;
    }

    if (!nested) {
      new Setting(containerEl)
        .setName(this.i18n.t("settings.modules.heading"))
        .setHeading();
    }
    for (const module of modules) {
      configure(new Setting(containerEl), module);
    }
  }

  /**
   * Put focus back on a module switch after `display()` rebuilt the tab.
   *
   * `preventScroll` is mandatory. Without it the browser scrolls the newly
   * focused element into view, which re-creates the exact jump the scroll
   * restore at the end of `display()` just undid. `display()` is synchronous,
   * so this call lands after that restore and `preventScroll` keeps it.
   *
   * Both lookups degrade to a no-op: the section can be filtered out of the
   * DOM, and the node-environment test doubles have neither a matching
   * `querySelector` nor a `focus` method.
   */
  private restoreModuleToggleFocus(moduleId: OptionalModuleId): void {
    const restored = this.containerEl.querySelector<HTMLElement>(
      `[data-vaultguard-module="${moduleId}"]`,
    );
    if (restored && typeof restored.focus === "function") {
      restored.focus({ preventScroll: true });
    }
  }

  private renderSemanticDiscoverySection(containerEl: HTMLElement): void {
    if (!this.plugin.isOptionalModuleEnabled("secureDiscovery")) return;

    new Setting(containerEl)
      .setName(this.i18n.t("discovery.semantic.heading"))
      .setDesc(this.i18n.t("discovery.semantic.trust"))
      .setHeading();

    new Setting(containerEl)
      .setName("Default search result limit")
      .setDesc(
        "Maximum number of Secure Discovery results shown by default. Individual searches remain bounded to 100 results."
      )
      .addDropdown((dropdown) =>
        dropdown
          .addOption("10", "10 results")
          .addOption("25", "25 results")
          .addOption("50", "50 results")
          .addOption("100", "100 results")
          .setValue(String(this.plugin.settings.discoveryResultLimit))
          .onChange(async (value) => {
            const parsed = Number.parseInt(value, 10);
            if (![10, 25, 50, 100].includes(parsed)) return;
            this.plugin.settings.discoveryResultLimit = parsed;
            await this.plugin.saveSettings();
          })
      );

    if (Platform.isDesktopApp !== true) {
      containerEl.createEl("p", {
        cls: "setting-item-description vaultguard-semantic-settings-status",
        text: this.i18n.t("discovery.semantic.desktopOnly"),
      });
      return;
    }

    new Setting(containerEl)
      .setName(this.i18n.t("discovery.semantic.consent"))
      .setDesc(this.i18n.t("discovery.semantic.consentDetail"))
      .addToggle((toggle) =>
        toggle
          .setValue(this.plugin.settings.semanticSearchEnabled === true)
          .onChange(async (enabled) => {
            toggle.setDisabled(true);
            try {
              await this.plugin.setSemanticSearchEnabled(enabled);
              this.showStatus(
                containerEl,
                this.i18n.t(enabled ? "discovery.semantic.enabled" : "discovery.semantic.disabled"),
                false,
              );
              this.display();
            } catch (error) {
              toggle.setValue(this.plugin.settings.semanticSearchEnabled === true);
              toggle.setDisabled(false);
              this.showStatus(
                containerEl,
                this.i18n.t("discovery.semantic.error", {
                  message: error instanceof Error ? error.message : String(error),
                }),
                true,
              );
            }
          }),
      );

    let pendingOrigin = this.plugin.settings.semanticEmbeddingEndpoint;
    let pendingModel = this.plugin.settings.semanticEmbeddingModel;
    new Setting(containerEl)
      .setName(this.i18n.t("discovery.semantic.origin"))
      .setDesc(this.i18n.t("discovery.semantic.originDetail"))
      .addText((text) =>
        text
          .setPlaceholder("http://127.0.0.1:11434")
          .setValue(pendingOrigin)
          .onChange((value) => {
            pendingOrigin = value;
          }),
      );
    new Setting(containerEl)
      .setName(this.i18n.t("discovery.semantic.model"))
      .setDesc(this.i18n.t("discovery.semantic.modelDetail"))
      .addText((text) =>
        text
          .setPlaceholder("embeddinggemma")
          .setValue(pendingModel)
          .onChange((value) => {
            pendingModel = value;
          }),
      );
    new Setting(containerEl)
      .setName(this.i18n.t("discovery.semantic.providerActions"))
      .setDesc(this.i18n.t("discovery.semantic.providerActionsDetail"))
      .addButton((button) =>
        button
          .setButtonText(this.i18n.t("discovery.semantic.save"))
          .onClick(async () => {
            button.setDisabled(true);
            try {
              await this.plugin.updateSemanticProviderPreferences(pendingOrigin, pendingModel);
              this.showStatus(containerEl, this.i18n.t("discovery.semantic.saved"), false);
              this.display();
            } catch (error) {
              this.showStatus(
                containerEl,
                this.i18n.t("discovery.semantic.error", {
                  message: error instanceof Error ? error.message : String(error),
                }),
                true,
              );
              button.setDisabled(false);
            }
          }),
      )
      .addButton((button) =>
        button
          .setButtonText(this.i18n.t("discovery.semantic.test"))
          .setDisabled(this.plugin.settings.semanticSearchEnabled !== true)
          .onClick(async () => {
            button.setDisabled(true);
            try {
              const dimensions = await this.plugin.testSemanticProvider();
              this.showStatus(
                containerEl,
                this.i18n.t("discovery.semantic.testPassed", { dimensions }),
                false,
              );
            } catch (error) {
              this.showStatus(
                containerEl,
                this.i18n.t("discovery.semantic.error", {
                  message: error instanceof Error ? error.message : String(error),
                }),
                true,
              );
            } finally {
              button.setDisabled(this.plugin.settings.semanticSearchEnabled !== true);
            }
          }),
      );

    const status = this.plugin.getSemanticSearchStatus();
    let statusDescription = this.i18n.t(`discovery.semantic.status.${status.state}`, {
      files: status.indexedFiles,
      chunks: status.indexedChunks,
    });
    if (status.totalFiles !== undefined) {
      statusDescription += ` ${this.i18n.t("discovery.semantic.status.coverage", {
        processed: status.processedFiles ?? 0,
        total: status.totalFiles,
        skipped: status.skippedFiles ?? 0,
        failed: status.failedFiles ?? 0,
        limited: status.limitedFiles ?? 0,
      })}`;
    }
    new Setting(containerEl)
      .setName(this.i18n.t("discovery.semantic.indexActions"))
      .setDesc(statusDescription)
      .addButton((button) =>
        button
          .setButtonText(this.i18n.t("discovery.semantic.build"))
          .setCta()
          .setDisabled(this.plugin.settings.semanticSearchEnabled !== true)
          .onClick(async () => {
            button.setDisabled(true);
            this.showStatus(containerEl, this.i18n.t("discovery.semantic.building"), false);
            try {
              await this.plugin.buildSemanticIndex();
              this.display();
            } catch (error) {
              this.showStatus(
                containerEl,
                this.i18n.t("discovery.semantic.error", {
                  message: error instanceof Error ? error.message : String(error),
                }),
                true,
              );
              button.setDisabled(false);
            }
          }),
      )
      .addButton((button) =>
        button
          .setButtonText(this.i18n.t("discovery.semantic.cancel"))
          .onClick(() => {
            this.plugin.cancelSemanticIndexWork();
            this.showStatus(containerEl, this.i18n.t("discovery.semantic.cancelling"), false);
          }),
      )
      .addButton((button) =>
        button
          .setButtonText(this.i18n.t("discovery.semantic.purge"))
          .setWarning()
          .onClick(async () => {
            button.setDisabled(true);
            try {
              await this.plugin.purgeSemanticIndex();
              this.showStatus(containerEl, this.i18n.t("discovery.semantic.purged"), false);
              this.display();
            } catch (error) {
              this.showStatus(
                containerEl,
                this.i18n.t("discovery.semantic.error", {
                  message: error instanceof Error ? error.message : String(error),
                }),
                true,
              );
              button.setDisabled(false);
            }
          }),
      );
  }

  /**
   * The deduped union of this device's `excludedPaths` and the admin-pushed
   * `serverExcludedPaths`. Mirrors what `isPathExcluded` actually matches
   * against (`main.ts:8105` iterates `[...server, ...local]`), so the summary
   * count can never disagree with the runtime matcher.
   *
   * Normalization matches the matcher's: trim, strip leading and trailing
   * slashes. Without it "Archive" and "Archive/" would count twice while
   * behaving as one rule.
   */
  /**
   * Standalone explanatory paragraph in the settings tab.
   *
   * Obsidian's `.setting-item-description` is a caption style for one line of
   * text INSIDE a setting row — `--font-ui-smaller` (12px), tight line height,
   * `overflow: hidden` + `text-overflow: ellipsis`. Every standalone `<p>` in
   * this tab used it, so body copy rendered two steps smaller than the heading
   * above it with clipped descenders. Use this helper instead; `"lead"` is for
   * the paragraph directly under the tab title.
   */
  private renderSettingsNote(
    parent: HTMLElement,
    text: string,
    variant: "lead" | "note" = "note",
  ): HTMLElement {
    return parent.createEl("p", {
      text,
      cls: `vaultguard-settings-${variant}`,
    });
  }

  private effectiveExcludedPaths(): {
    local: string[];
    server: string[];
    union: string[];
  } {
    const normalize = (raw: string): string =>
      raw.trim().replace(/^\/+/, "").replace(/\/+$/, "");
    const local = (this.plugin.settings.excludedPaths ?? [])
      .map(normalize)
      .filter((entry) => entry.length > 0);
    const server = (this.plugin.settings.serverExcludedPaths ?? [])
      .map(normalize)
      .filter((entry) => entry.length > 0);
    return { local, server, union: [...new Set([...server, ...local])] };
  }

  /** Entries a user probably expects to glob but which match literally. */
  private wildcardExcludedPathEntries(entries: string[]): string[] {
    return entries.filter((entry) => entry.includes("*") || entry.includes("?"));
  }

  /**
   * "Protection scope" — the single place that answers *what does VaultGuard do
   * with this path?* at every scope, narrowest first.
   *
   * This section deliberately collects controls that used to live three places
   * apart: the whole-vault plaintext toggle (previously an unlabelled pair at
   * the very top of the tab), the excluded-path list (previously under
   * Synchronization, which understated that exclusion also disables at-rest
   * encryption), and the at-rest status (previously visible only inside the
   * Advanced collapsible). The full at-rest panel stays in Advanced — only its
   * status surfaces here.
   *
   * Ordering is deliberate: the narrow, reversible tool comes first and the
   * whole-vault escalation comes last. The old layout inverted that and, worse,
   * *hid* the exclusion list whenever the whole-vault mode was on — so the user
   * who only wanted to exempt one folder lost the control that would have done
   * it. Nothing here is hidden by the mode any more; controls that the mode
   * makes redundant render disabled with a reason.
   */
  private renderProtectionScopeSection(containerEl: HTMLElement): void {
    const enabled = this.plugin.isLocalProjectMemoryModeEnabled();

    // Deliberately NOT SettingGroup (unlike renderOptionalModulesSection):
    // SettingGroup only accepts Setting rows via addSetting(), with no seam for
    // the read-only summary paragraph or the at-rest status badge this section
    // leads with. A `<details>` takes arbitrary content and, unlike the plain
    // setHeading() this used to be, can actually be collapsed — which every
    // top-level section in this tab now can.
    this.renderCollapsibleSection(containerEl, "protection", "Protection", (body) =>
      this.renderProtectionScopeBody(body, enabled),
    );
  }

  private renderProtectionScopeBody(containerEl: HTMLElement, enabled: boolean): void {
    // Lead with what protection MEANS before any control to configure it. This
    // is the first copy in the tab, and for most users the only sentence they
    // need: their files on this disk are ciphertext.
    this.renderSettingsNote(containerEl, this.atRestExplanation());
    this.renderProtectionScopeSummary(containerEl, enabled);
    this.renderExcludedPathsSetting(containerEl, enabled);
    this.renderServerExcludedPathsSetting(containerEl);
    this.renderAlwaysExcludedSetting(containerEl);
    this.renderPurgeExcludedPathsSetting(containerEl, enabled);
    this.renderGitRepositoryDetectionSetting(containerEl, enabled);
    this.renderPlaintextVaultModeSetting(containerEl, enabled);
    // Promoted out of the collapsed Advanced disclosure — see
    // `renderRecoveryCodeSetting`. It belongs with the at-rest status badge this
    // section already leads with: the badge says the files are encrypted, and
    // this is what lets you read them again if this device is lost.
    this.renderRecoveryCodeSetting(containerEl);

    // The at-rest maintenance actions used to live in Advanced, which split one
    // concept across two sections at two depths: the exclusion rules that decide
    // WHAT is encrypted sat here, while the controls that encrypt, decrypt and
    // rebuild it sat behind a different disclosure — and both rendered their own
    // copy of the status badge. They are the same layer, so they are one section
    // now. The actions stay collapsed because they are rare and two of them are
    // destructive; the STATUS above is always visible.
    this.renderCollapsibleSection(
      containerEl,
      "encryption-maintenance",
      "Encryption maintenance",
      (body) => this.renderAtRestSection(body),
    );
  }

  private renderGitRepositoryDetectionSetting(
    containerEl: HTMLElement,
    localModeEnabled: boolean,
  ): void {
    const desktopUnavailable = Platform.isDesktopApp !== true;
    const setting = new Setting(containerEl)
      .setName("Detect Git repo folder")
      .setDesc(
        desktopUnavailable
          ? "Desktop-only profile preference. Configure it from desktop Obsidian. When enabled there, folders containing .git stay plaintext on local disk; cloud encryption, sync, permissions, and sharing remain separate."
          : "Keep detected Git repository folders plaintext on local disk so normal Git tools can read them. Cloud encryption, sync, permissions, and sharing remain active.",
      )
      .addToggle((toggle) =>
        toggle
          .setValue(this.plugin.isDetectGitRepoFolderEnabled())
          .setDisabled(desktopUnavailable)
          .onChange(async (value) => {
            if (desktopUnavailable) return;
            try {
              this.plugin.setDetectGitRepoFolderEnabled(value);
              const detection = await this.plugin.refreshDetectedGitRepositoryRoots();
              if (!detection.complete) {
                new Notice(
                  `VaultGuard Sync: Git repository folder detection stopped after ${detection.scannedEntries} entries. Undiscovered folders keep normal local encryption.`,
                  10000,
                );
              }
              if (value && !this.plugin.isLocalProjectMemoryModeEnabled()) {
                const transition = await this.plugin.convertDetectedGitRepositoryCiphertext();
                if (transition.failed > 0) {
                  new Notice(
                    `VaultGuard Sync: ${transition.failed} detected repository file(s) could not be converted to plaintext and remain protected. Review the console before using external Git tools.`,
                    12000,
                  );
                } else if (detection.complete) {
                  const repositorySummary = detection.roots.length === 0
                    ? "no repository folders found; normal local encryption remains active."
                    : `${detection.roots.length} repository folder(s) now stay plaintext locally; ${transition.decrypted} existing file(s) converted and ${transition.alreadyPlaintext} already plaintext.`;
                  new Notice(
                    `VaultGuard Sync: Git repository detection complete: ${repositorySummary} Cloud protections remain active.`,
                    8000,
                  );
                }
              }
              this.display();
            } catch (error) {
              this.showStatus(
                containerEl,
                error instanceof Error
                  ? error.message
                  : "Git repository folder detection update failed.",
                true,
              );
            }
          }),
      );
    setting.settingEl.addClass("vaultguard-plaintext-warning-setting");

    if (localModeEnabled && this.plugin.isDetectGitRepoFolderEnabled()) {
      this.renderSettingsNote(
        containerEl,
        "Git repo detection remains saved for this desktop profile, but the plaintext local-only vault setting currently supersedes it because the whole vault is already plaintext.",
      );
    }
  }

  /**
   * Read-only "where do I stand" line plus the at-rest status badge. The count
   * comes from the same union the runtime matcher uses, so a user can reconcile
   * this number against behaviour.
   */
  private renderProtectionScopeSummary(containerEl: HTMLElement, localMode: boolean): void {
    const { union } = this.effectiveExcludedPaths();
    const summary = localMode
      ? "Every file in this vault is plaintext on disk and local-only. Cloud sync, sharing, and organization permissions are off."
      : union.length === 0
        ? "Encrypted on disk and synced: every file in this vault, apart from the always-excluded paths listed below."
        : `Encrypted on disk and synced: every file in this vault, apart from ${union.length} excluded path${
            union.length === 1 ? "" : "s"
          } and the always-excluded paths listed below.`;

    this.renderSettingsNote(containerEl, summary);

    // The badge is only informative while at-rest encryption is in play. In
    // plaintext local-only mode getAtRestStatus() returns kind:"disabled" and
    // the badge would just restate the summary line above — using the mode's
    // internal wording, which no longer matches the label shown here.
    //
    // This is now the ONLY badge in the tab. The at-rest panel used to render a
    // second copy of it; that panel is nested inside this section's own
    // "Encryption maintenance" disclosure, so showing it again there would just
    // repeat what is already on screen a few rows above.
    if (!localMode) {
      this.renderAtRestStatusBadge(containerEl, this.plugin.getAtRestStatus());
    }
    // The file counts back the badge with something reconcilable against
    // observed behaviour, so they belong together.
    this.renderAtRestTally(containerEl, localMode);
  }

  /**
   * The local exclusion list. The description states BOTH effects on purpose:
   * `isAtRestExcluded()` is `configDir ∪ .trash ∪ isPathExcluded()`
   * (at-rest-adapter-runtime.ts), so adding a path here silently opts it out of
   * at-rest encryption as well as sync. The previous copy mentioned only the
   * server half, which made "exclude it to save bandwidth" quietly mean "and
   * leave it readable in Finder".
   */
  private renderExcludedPathsSetting(containerEl: HTMLElement, localMode: boolean): void {
    const configDir = this.app.vault.configDir;
    const configWorkspacePath = `${configDir}/workspace.json`;
    const configPluginsPath = `${configDir}/plugins`;

    const setting = new Setting(containerEl)
      .setName("Excluded paths (this device)")
      .setDesc(
        "One path per line. Matching files and folders are never uploaded, downloaded, or deleted on the server, " +
        "AND are left unencrypted on disk — exclusion opts a path out of local at-rest encryption too. " +
        `Use an exact path (e.g. ${configWorkspacePath}) or a folder prefix (e.g. ${configPluginsPath}); ` +
        "wildcards are not supported. Applies to this device only. \".trash\" is always re-added."
      );
    setting.settingEl.addClass("vaultguard-excluded-paths-setting");

    // Warning line lives outside the Setting so it can be re-rendered on every
    // keystroke without rebuilding the textarea (which would lose the caret).
    const warningEl = containerEl.createEl("p", {
      cls: "vaultguard-settings-note vaultguard-excluded-paths-warning",
    });
    const refreshWarning = (entries: string[]): void => {
      const wildcards = this.wildcardExcludedPathEntries(entries);
      warningEl.setText(
        wildcards.length === 0
          ? ""
          : `Matched literally, not as a pattern: ${wildcards.join(", ")}. ` +
            "Replace each with the exact path or the folder prefix it should cover."
      );
      warningEl.toggleClass("vaultguard-excluded-paths-warning-active", wildcards.length > 0);
    };
    refreshWarning(this.plugin.settings.excludedPaths ?? []);

    setting.addTextArea((textArea) => {
      textArea.inputEl.rows = 6;
      textArea.inputEl.addClass("vaultguard-mono-textarea");
      textArea
        .setPlaceholder(`${configWorkspacePath}\n${configPluginsPath}\n.trash`)
        .setValue((this.plugin.settings.excludedPaths ?? []).join("\n"))
        .setDisabled(localMode)
        .onChange(async (value) => {
          const entries = value
            .split("\n")
            .map((line) => line.trim())
            .filter((line) => line.length > 0);
          this.plugin.settings.excludedPaths = entries;
          refreshWarning(entries);
          await this.plugin.saveSettings();
        });
      return textArea;
    });

    if (localMode) {
      this.appendLocalModeRedundantNote(setting);
    }
  }

  /**
   * Admin-pushed exclusions, cached from the vault record. Read-only here by
   * design — a member cannot override them — but previously invisible, which
   * made the effective list impossible to reconcile with observed behaviour.
   */
  private renderServerExcludedPathsSetting(containerEl: HTMLElement): void {
    const { server } = this.effectiveExcludedPaths();
    if (server.length === 0) return;

    new Setting(containerEl)
      .setName("Excluded by your admin")
      .setDesc(
        `Set on the server vault and applied on top of your own list: ${server.join(", ")}. ` +
        "These cannot be removed from this device."
      );
  }

  private renderAlwaysExcludedSetting(containerEl: HTMLElement): void {
    new Setting(containerEl)
      .setName("Always excluded")
      .setDesc(
        `The "${this.app.vault.configDir}" folder and every vault-root entry whose name starts with a dot ` +
        "(.git, .trash, and other plugins' sidecar folders) are always local-only and always plaintext. " +
        "You do not need to list them."
      );
  }

  private renderPurgeExcludedPathsSetting(containerEl: HTMLElement, localMode: boolean): void {
    new Setting(containerEl)
      .setName("Purge excluded paths from server")
      .setDesc(
        "Delete every server-side copy of files that match the excluded paths above. " +
        "Useful after adding a new exclusion: without this, other members on other " +
        "devices keep pulling the file down. This affects the shared server vault."
      )
      .addButton((button) => {
        button
          .setButtonText("Purge from server")
          .setWarning()
          .setDisabled(localMode)
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
          });
      });
  }

  /**
   * The whole-vault escalation, last in the section. The stored setting key is
   * still `localProjectMemoryMode` and the notice/error strings it triggers are
   * unchanged — only the label a user reads is stated as the effect rather than
   * the originating use case.
   */
  private renderPlaintextVaultModeSetting(containerEl: HTMLElement, enabled: boolean): void {
    const setting = new Setting(containerEl)
      .setName("Plaintext local-only vault")
      .setDesc(
        "For vaults that are a code repository. Keeps every file plaintext on disk and turns off cloud sync, " +
        "sharing, and organization permissions for the whole vault. To exempt only some folders, " +
        "use the excluded paths above instead."
      )
      .addToggle((toggle) =>
        toggle
          .setValue(enabled)
          .onChange(async (value) => {
            try {
              if (value) {
                await this.plugin.enableLocalProjectMemoryMode();
              } else {
                await this.plugin.disableLocalProjectMemoryMode();
              }
              this.display();
            } catch (err) {
              this.showStatus(
                containerEl,
                err instanceof Error ? err.message : "Local Project Memory Mode update failed.",
                true,
              );
            }
          }),
      );
    setting.settingEl.addClass("vaultguard-plaintext-warning-setting");

    // Nested under the mode toggle it modifies. The scope that used to be
    // buried mid-description ("global desktop preference") is now in the name,
    // because this preference is NOT stored in the vault — it lives in the
    // shared profile store and applies to every vault on this computer.
    const autoEl = containerEl.createDiv({ cls: "vaultguard-protection-scope-nested" });
    new Setting(autoEl)
      .setName("Auto-enable in all Git repository vaults (this computer)")
      .setDesc(
        "Applies to every vault opened in this Obsidian profile, not just this one. On VaultGuard startup, a vault is activated only when .git exists at its root and the vault is plaintext, readable, unbound, and not locally opted out. Protected, encrypted, mobile, and uncertain vaults are skipped.",
      )
      .addToggle((toggle) =>
        toggle
          .setValue(this.plugin.isAutomaticLocalProjectMemoryModeForGitReposEnabled())
          .onChange(async (value) => {
            try {
              this.plugin.setAutomaticLocalProjectMemoryModeForGitRepos(value);
              if (value) {
                const result = await this.plugin.maybeAutoEnableLocalProjectMemoryMode();
                if (result.kind === "protected") {
                  new Notice(
                    "VaultGuard Sync: automatic Local Project Memory Mode was not enabled here because existing at-rest protection was detected. Review and decrypt this vault manually before changing modes.",
                    10000,
                  );
                } else if (result.kind === "inspection-failed") {
                  new Notice(
                    "VaultGuard Sync: automatic Local Project Memory Mode was not enabled here because the local protection inspection could not finish safely.",
                    10000,
                  );
                } else if (result.kind === "server-bound") {
                  new Notice(
                    "VaultGuard Sync: this vault remains unchanged because it is bound to a server vault.",
                    8000,
                  );
                } else if (result.kind === "suppressed") {
                  new Notice(
                    "VaultGuard Sync: this vault keeps its local opt-out. Manually enable Local Project Memory Mode to clear it.",
                    8000,
                  );
                }
              }
              this.display();
            } catch (err) {
              this.showStatus(
                containerEl,
                err instanceof Error
                  ? err.message
                  : "Git repository folder detection update failed.",
                true,
              );
            }
          }),
      );

    if (enabled) {
      containerEl.createEl("p", {
        cls: "vaultguard-settings-note",
        text:
          "Use this mode for repo-root vaults. AGENTS.md, 00_Index.md, docs, reports, handoffs, source, package, config, test, script, Terraform, and infrastructure files stay plaintext for coding agents and normal Git tools.",
      });
    }
  }

  /**
   * One-line reason attached to a control the plaintext local-only mode makes
   * redundant. Disabled-with-a-reason instead of hidden: the old layout removed
   * these controls entirely, which read as "this setting no longer exists"
   * rather than "this setting has nothing left to do".
   */
  private appendLocalModeRedundantNote(setting: Setting): void {
    setting.descEl.createDiv({
      cls: "setting-item-description vaultguard-setting-disabled-reason",
      text: "Every path is already local-only and plaintext in this mode.",
    });
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
 * call until the user stores a key or selects a verified subscription login.
   */
  private renderAiChatSection(containerEl: HTMLElement): void {
    new Setting(containerEl).setName("AI chat").setHeading();

    this.renderAiProviderBlock(containerEl);

    if (this.plugin.settings.aiChatProvider === "openai") {
      this.renderOpenAiChatProviderSettings(containerEl);
    } else if (this.plugin.settings.aiChatProvider === "codex") {
      this.renderCodexSubscriptionProviderSettings(containerEl);
    } else {
    const keyStore = this.getAnthropicKeyStore();
    this.renderProviderKeyStorageSetting(containerEl, "anthropic", keyStore);
    const hasKey = keyStore.hasKey();

    if (keyStore.usesObsidianSecretStorage()) {
      this.renderNativeProviderSecretSetting(containerEl, "Anthropic", keyStore);
    } else {

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
            await this.getAnthropicKeyStore().setKey(newKey);
            providerModelCatalog.invalidate("anthropic");
            // Wipe the plaintext from the field immediately after storing.
            inputEl.value = "";
            // Best-effort: push a DEK-wrapped copy to Cloud so the key roams to
            // the user's other devices (no-op when sync is off / no lease yet).
            void this.plugin.aiKeySync.uploadIfEnabled({ userInitiated: true });
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
              await this.getAnthropicKeyStore().clearKey();
              providerModelCatalog.invalidate("anthropic");
              // Best-effort: remove the roaming copy from Cloud too.
              void this.plugin.aiKeySync.deleteRemote();
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
    }

    // ── Sync API key across devices ─────────────────────────────────────────
    if (!keyStore.usesObsidianSecretStorage()) {
      new Setting(containerEl)
        .setName("Sync API key to your other devices")
        .setDesc(
          "Stores an ENCRYPTED copy of your Anthropic key — wrapped with your vault's key — in " +
            "VaultGuard Cloud, so mobile works without re-entering it. VaultGuard never sees the " +
            "plaintext key.",
        )
        .addToggle((toggle) => {
          toggle
            .setValue(this.plugin.settings.aiChatKeySyncEnabled)
            .onChange(async (value) => {
              this.plugin.settings.aiChatKeySyncEnabled = value;
              await this.plugin.saveSettings();
              if (value) {
                // Turned ON: push the current local key (if any) right away.
                void this.plugin.aiKeySync.uploadIfEnabled({ userInitiated: true });
              } else {
                // Turned OFF: best-effort remove the roaming copy from Cloud.
                void this.plugin.aiKeySync.deleteRemote();
              }
            });
        });
    } else {
      new Setting(containerEl)
        .setName("Key availability across devices")
        .setDesc(
          "Obsidian owns this secret. VaultGuard does not copy it into plugin data or VaultGuard Cloud. " +
            "Choose the same native secret on each device where you want to use AI chat.",
        );
    }

    // ── Model ───────────────────────────────────────────────────────────────
    if (this.plugin.settings.aiChatProvider === "subscription") {
      // Tier aliases, not versions. `claude --model opus` resolves to the newest
      // Opus at request time, so this list never needs a plugin release to keep
      // up with Anthropic. The concrete model is shown in the chat footer once
      // the CLI reports it for the session.
      this.renderClaudeSubscriptionModelSetting(containerEl);
    } else {
      const anthropicModelSetting = new Setting(containerEl)
        .setName("Model")
        .setDesc("Anthropic model used for AI chat turns. Available models load from your API account.")
        .addDropdown((dropdown) => {
          this.populateModelSelect(
            dropdown.selectEl,
            AI_CHAT_MODELS,
            this.plugin.settings.aiChatModel,
          );
          dropdown
            .setValue(this.plugin.settings.aiChatModel)
            .onChange(async (value) => {
              this.plugin.settings.aiChatModel = value;
              await this.plugin.saveSettings();
            });
        });
      const anthropicModelStatus = anthropicModelSetting.descEl.createDiv({
        cls: "vaultguard-model-catalog-status",
        text: hasKey ? "Loading models available to this Anthropic key…" : "Add an API key to load account models.",
      });
      void this.refreshProviderModelSelect(
        "anthropic",
        anthropicModelSetting.controlEl.querySelector("select"),
        anthropicModelStatus,
      );
    }

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
    // Hidden on mobile: streaming is force-disabled at runtime in the chat view
    // (streamingEnabled() → !Platform.isMobileApp), so the toggle would be a
    // dead control there. The runtime guard remains the actual enforcement.
    if (!Platform.isMobileApp) {
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
    }
    }

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
    // Stacked full-width: a 4-row textarea in Obsidian's default side-by-side
    // setting layout gets squeezed into the narrow right-hand control column,
    // which is unusable for prose. Same treatment the excluded-paths textarea
    // already had.
    const customInstructionsSetting = new Setting(containerEl)
      .setName("Custom instructions")
      .setDesc(
        "Optional instructions appended to the assistant's system prompt (e.g. tone, formatting, " +
        "project conventions). They never override the built-in security and permission rules.",
      )
      .addTextArea((ta) => {
        ta.setPlaceholder("e.g. Answer concisely. Prefer bullet points. Use British spelling.");
        ta.setValue(this.plugin.settings.aiChatSystemPrompt ?? "");
        ta.inputEl.rows = 5;
        ta.inputEl.addClass("vaultguard-chat-system-prompt-input");
        ta.onChange(async (value) => {
          const trimmed = value.trim();
          this.plugin.settings.aiChatSystemPrompt = trimmed.length > 0 ? value : undefined;
          await this.plugin.saveSettings();
        });
      });
    customInstructionsSetting.settingEl.addClass("vaultguard-stacked-textarea-setting");

    this.renderPromptTemplates(containerEl);
  }

  private renderOpenAiChatProviderSettings(containerEl: HTMLElement): void {
    const keyStore = this.getOpenAiKeyStore();
    this.renderProviderKeyStorageSetting(containerEl, "openai", keyStore);
    const hasKey = keyStore.hasKey();

    if (keyStore.usesObsidianSecretStorage()) {
      this.renderNativeProviderSecretSetting(containerEl, "OpenAI", keyStore);
    } else {

    new Setting(containerEl)
      .setName("OpenAI API key")
      .setDesc(
        hasKey
          ? "A key is stored and encrypted on this device. Enter a new key to replace it, or clear it. The stored key is never displayed."
          : "Stored encrypted on this device (OS keychain, or the local at-rest key as a fallback). Used only when you run AI Chat with OpenAI / GPT.",
      )
      .addText((text) => {
        text.setPlaceholder(hasKey ? "•••• key stored — enter to replace" : "sk-...");
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
            this.showStatus(containerEl, "Enter an OpenAI API key first.", true);
            return;
          }
          saveBtn.disabled = true;
          saveBtn.textContent = "Saving...";
          try {
            await this.getOpenAiKeyStore().setKey(newKey);
            providerModelCatalog.invalidate("openai");
            inputEl.value = "";
            this.showStatus(containerEl, "OpenAI API key saved.", false);
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
              await this.getOpenAiKeyStore().clearKey();
              providerModelCatalog.invalidate("openai");
              this.showStatus(containerEl, "OpenAI API key removed.", false);
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
    }

    const openAiModelSetting = new Setting(containerEl)
      .setName("Model")
      .setDesc("OpenAI model used for AI chat turns. Available models load from your API account, including previews.")
      .addDropdown((dropdown) => {
        this.populateModelSelect(
          dropdown.selectEl,
          OPENAI_CHAT_MODELS,
          this.plugin.settings.openAiModel,
        );
        dropdown
          .setValue(this.plugin.settings.openAiModel)
          .onChange(async (value) => {
            this.plugin.settings.openAiModel = value;
            await this.plugin.saveSettings();
          });
      });
    const openAiModelStatus = openAiModelSetting.descEl.createDiv({
      cls: "vaultguard-model-catalog-status",
      text: hasKey ? "Loading models available to this OpenAI key…" : "Add an API key to load account models.",
    });
    void this.refreshProviderModelSelect(
      "openai",
      openAiModelSetting.controlEl.querySelector("select"),
      openAiModelStatus,
    );

    new Setting(containerEl)
      .setName("Reasoning effort")
      .setDesc("How much reasoning budget the OpenAI model spends per turn.")
      .addDropdown((dropdown) => {
        for (const e of OPENAI_REASONING_EFFORTS) dropdown.addOption(e.id, e.label);
        dropdown
          .setValue(this.plugin.settings.openAiReasoningEffort)
          .onChange(async (value) => {
            this.plugin.settings.openAiReasoningEffort =
              value === "low" || value === "high" ? value : "medium";
            await this.plugin.saveSettings();
          });
      });

    new Setting(containerEl)
      .setName("Verbosity")
      .setDesc("How detailed GPT responses should be by default.")
      .addDropdown((dropdown) => {
        for (const v of OPENAI_VERBOSITIES) dropdown.addOption(v.id, v.label);
        dropdown
          .setValue(this.plugin.settings.openAiVerbosity)
          .onChange(async (value) => {
            this.plugin.settings.openAiVerbosity =
              value === "low" || value === "high" ? value : "medium";
            await this.plugin.saveSettings();
          });
      });

    new Setting(containerEl)
      .setName("OpenAI streaming")
      .setDesc(
        "OpenAI / GPT uses the non-streaming Responses API path in this phase. Anthropic streaming remains unchanged.",
      );
  }

  private renderCodexSubscriptionProviderSettings(containerEl: HTMLElement): void {
    new Setting(containerEl)
      .setName("ChatGPT subscription transport")
      .setDesc(
        "Uses the Codex runtime included with the ChatGPT desktop app, or a standalone Codex CLI when available. " +
          "VaultGuard launches a private app-server and never requests or stores an OpenAI API key.",
      );

    const modelSetting = new Setting(containerEl)
      .setName("Model")
      .setDesc(
        "Visible models are discovered automatically from the signed-in ChatGPT account before VaultGuard starts a chat thread.",
      )
      .addDropdown((dropdown) => {
        // OPENAI_CHAT_MODELS is an API-key fallback, not proof of this ChatGPT
        // account's subscription entitlements. Do not render a model selector
        // until the signed-in runtime's model/list result is available.
        dropdown.selectEl.replaceChildren(
          new Option("Discovering account models…", ""),
        );
        dropdown.selectEl.disabled = true;
        dropdown
          .onChange(async (value) => {
            this.plugin.settings.codexModel = value;
            this.plugin.settings.codexAutoSelectLatest = false;
            await this.plugin.saveSettings();
          });
      });
    const modelStatus = modelSetting.descEl.createDiv({
      cls: "vaultguard-model-catalog-status",
      text: "Discovering models from the signed-in Codex runtime…",
    });
    void this.refreshCodexModelSelect(
      modelSetting.controlEl.querySelector("select"),
      modelStatus,
    );

    new Setting(containerEl)
      .setName("Reasoning effort")
      .setDesc("How much reasoning effort Codex requests for each subscription turn.")
      .addDropdown((dropdown) => {
        for (const effort of OPENAI_REASONING_EFFORTS) {
          dropdown.addOption(effort.id, effort.label);
        }
        dropdown
          .setValue(this.plugin.settings.openAiReasoningEffort)
          .onChange(async (value) => {
            this.plugin.settings.openAiReasoningEffort =
              value === "low" || value === "high" ? value : "medium";
            await this.plugin.saveSettings();
          });
      });
  }

  /**
   * Model picker for the Claude-subscription transport. It lists TIERS, not
   * versions: the CLI resolves `opus` to whatever the newest Opus is at request
   * time, so a new Anthropic release reaches users without a plugin update —
   * which a pinned list (`claude-opus-4-8`) could never do.
   *
   * Bound to `claudeSubscriptionModel`, never `aiChatModel`: the Messages API
   * transport sends that field verbatim and rejects bare aliases.
   */
  private renderClaudeSubscriptionModelSetting(containerEl: HTMLElement): void {
    const setting = new Setting(containerEl)
      .setName("Model")
      .setDesc(
        "Which Claude your subscription chat uses. Each option tracks the newest model in " +
          "that family automatically, so it stays current without a plugin update.",
      )
      .addDropdown((dropdown) => {
        this.populateModelSelect(
          dropdown.selectEl,
          CLAUDE_SUBSCRIPTION_MODELS,
          this.plugin.settings.claudeSubscriptionModel,
        );
        dropdown
          .setValue(
            this.plugin.settings.claudeSubscriptionModel || DEFAULT_CLAUDE_SUBSCRIPTION_MODEL,
          )
          .onChange(async (value) => {
            this.plugin.settings.claudeSubscriptionModel = value;
            await this.plugin.saveSettings();
            this.plugin.notifyAiChatProviderChanged();
          });
      });
    setting.descEl.createDiv({
      cls: "vaultguard-model-catalog-status",
      text: "The chat footer shows the exact model Claude Code resolved for the session.",
    });
  }

  private populateModelSelect(
    selectEl: HTMLSelectElement,
    options: ReadonlyArray<{ id: string; label: string }>,
    selectedModel: string,
  ): void {
    selectEl.replaceChildren();
    const seen = new Set<string>();
    const merged = options.some((option) => option.id === selectedModel)
      ? options
      : [{ id: selectedModel, label: `${selectedModel} (current)` }, ...options];
    for (const option of merged) {
      if (!option.id || seen.has(option.id)) continue;
      seen.add(option.id);
      selectEl.add(new Option(option.label, option.id));
    }
    selectEl.value = selectedModel;
  }

  private async refreshProviderModelSelect(
    provider: Exclude<ProviderModelCatalogProvider, "codex">,
    selectEl: HTMLSelectElement | null,
    statusEl: HTMLElement,
  ): Promise<void> {
    if (!selectEl) return;
    const keyStore = provider === "openai"
      ? this.getOpenAiKeyStore()
      : this.getAnthropicKeyStore();
    const selectedModel =
      provider === "openai"
        ? this.plugin.settings.openAiModel
        : this.plugin.settings.aiChatModel;
    const apiKey = await keyStore.getKey();
    const catalog = await providerModelCatalog.resolve({
      provider,
      apiKey,
      selectedModel,
    });
    if (!selectEl.isConnected || !statusEl.isConnected) return;

    const currentModel =
      provider === "openai"
        ? this.plugin.settings.openAiModel
        : this.plugin.settings.aiChatModel;
    this.populateModelSelect(selectEl, catalog.options, currentModel);
    statusEl.setText(
      catalog.warning ??
        (catalog.source === "live"
          ? "Loaded from the provider API for this account."
          : catalog.source === "cache"
            ? "Loaded from a recent provider API result."
            : "Using bundled choices until an API key is available."),
    );
  }

  private isCurrentSettingsOwner(ownerEl: HTMLElement): boolean {
    return ownerEl.isConnected !== false;
  }

  private async refreshCodexModelSelect(
    selectEl: HTMLSelectElement | null,
    statusEl: HTMLElement,
  ): Promise<void> {
    if (!selectEl) return;
    this.codexModelAbort?.abort();
    const controller = new AbortController();
    this.codexModelAbort = controller;
    try {
      let status: CodexAuthStatus;
      try {
        status = await getCodexAuthStatus(undefined, controller.signal);
      } catch {
        if (controller.signal.aborted) return;
        selectEl.replaceChildren(new Option("Account models unavailable", ""));
        statusEl.setText("Could not check the Codex runtime; the saved selection remains unchanged.");
        return;
      }
      if (controller.signal.aborted) return;
      if (!status.loggedIn || !status.isChatGptSubscription || !status.binaryPath) {
        selectEl.replaceChildren(new Option("Account models unavailable", ""));
        statusEl.setText(
          status.classification === "not-installed"
            ? "ChatGPT desktop runtime not available. Install or update the ChatGPT app to discover subscription models."
            : "Sign in to the Codex runtime with ChatGPT to discover account models.",
        );
        return;
      }

      const catalog = await providerModelCatalog.resolve({
        provider: "codex",
        apiKey: null,
        codexBinaryPath: status.binaryPath,
        selectedModel: this.plugin.settings.codexModel,
        preferNewest: this.plugin.settings.codexAutoSelectLatest !== false,
        signal: controller.signal,
      });
      if (
        controller.signal.aborted ||
        this.plugin.settings.aiChatProvider !== "codex" ||
        !selectEl.isConnected || !statusEl.isConnected
      ) {
        return;
      }

      if (catalog.selectedModel !== this.plugin.settings.codexModel) {
        this.plugin.settings.codexModel = catalog.selectedModel;
        await this.plugin.saveSettings();
        if (
          controller.signal.aborted ||
          this.plugin.settings.aiChatProvider !== "codex" ||
          !selectEl.isConnected || !statusEl.isConnected
        ) {
          return;
        }
      }
      this.populateModelSelect(selectEl, catalog.options, catalog.selectedModel);
      selectEl.disabled = catalog.source === "fallback";
      statusEl.setText(
        catalog.warning ??
          (catalog.source === "live"
            ? "Loaded from this signed-in ChatGPT account."
            : catalog.source === "cache"
              ? "Loaded from a recent signed-in Codex runtime result."
              : "Showing only the saved selection until account model discovery is available."),
      );
    } finally {
      if (this.codexModelAbort === controller) this.codexModelAbort = null;
    }
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
        "Choose how AI Chat talks to an AI provider. Vault access still goes through VaultGuard-controlled tools.",
      )
      .addDropdown((dropdown) => {
        if (!onMobile) {
          dropdown.addOption("subscription", "Claude subscription (Claude Code CLI)");
          dropdown.addOption("codex", "ChatGPT subscription (ChatGPT app)");
        }
        dropdown.addOption("apiKey", "Anthropic API key");
        dropdown.addOption("openai", "OpenAI API key / GPT");
        dropdown
          .setValue(
            onMobile &&
              (this.plugin.settings.aiChatProvider === "subscription" ||
                this.plugin.settings.aiChatProvider === "codex")
              ? "apiKey"
              : this.plugin.settings.aiChatProvider,
          )
          .onChange(async (value) => {
            this.plugin.settings.aiChatProvider =
              value === "subscription" && !onMobile
                ? "subscription"
                : value === "codex" && !onMobile
                  ? "codex"
                : value === "openai"
                  ? "openai"
                  : "apiKey";
            this.plugin.settings.aiChatProviderExplicit = true;
            await this.plugin.saveSettings();
            this.plugin.notifyAiChatProviderChanged();
            // Re-render so the status line / API-key field reflect the choice.
            this.display();
          });
      });

    if (this.plugin.settings.aiChatProvider === "codex") {
      const statusSetting = new Setting(containerEl)
        .setName("Codex status")
        .setDesc("Checking…");
      if (onMobile) {
        statusSetting.setDesc(
          "ChatGPT subscription mode launches the Codex runtime and is desktop-only. " +
            "Use an API-key provider on mobile.",
        );
        return;
      }
      void this.refreshCodexStatus(statusSetting);
      return;
    }

    if (this.plugin.settings.aiChatProvider !== "subscription") return;

    // Status line + actions container (populated asynchronously by the detector).
    const statusSetting = new Setting(containerEl)
      .setName("Claude Code status")
      .setDesc("Checking…");

    if (onMobile) {
      statusSetting.setDesc(
        "Subscription mode drives the Claude Code CLI, which can't run inside mobile Obsidian — so " +
          "it's desktop-only. Use an Anthropic API key to chat on mobile. A key you saved on desktop " +
          "syncs here automatically when “Sync API key to your other devices” is on.",
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
      if (!this.isCurrentSettingsOwner(statusSetting.settingEl)) return;
      statusSetting.setDesc(`Could not check Claude Code: ${(e as Error).message}`);
      return;
    }

    if (!this.isCurrentSettingsOwner(statusSetting.settingEl)) return;

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
      if (!this.isCurrentSettingsOwner(statusSetting.settingEl)) return;
      statusSetting.setDesc(`Could not start Claude Code sign-in: ${(e as Error).message}`);
      return;
    }
    if (!this.isCurrentSettingsOwner(statusSetting.settingEl)) return;
    // Re-check after the login subprocess finishes.
    await this.refreshClaudeStatus(statusSetting);
  }

  private async refreshCodexStatus(statusSetting: Setting): Promise<void> {
    this.codexStatusAbort?.abort();
    const controller = new AbortController();
    this.codexStatusAbort = controller;
    let status: CodexAuthStatus;
    try {
      status = await getCodexAuthStatus(undefined, controller.signal);
    } catch (error) {
      if (
        controller.signal.aborted ||
        !this.isCurrentSettingsOwner(statusSetting.settingEl)
      ) {
        return;
      }
      statusSetting.setDesc(`Could not check Codex: ${(error as Error).message}`);
      return;
    } finally {
      if (this.codexStatusAbort === controller) this.codexStatusAbort = null;
    }

    if (
      controller.signal.aborted ||
      !this.isCurrentSettingsOwner(statusSetting.settingEl)
    ) {
      return;
    }

    statusSetting.clear();
    statusSetting.setName("Codex status");
    switch (status.classification) {
      case "logged-in-chatgpt":
        statusSetting.setDesc(
          `Signed in with ChatGPT${status.version ? ` (Codex ${status.version})` : ""}. ` +
            "Subscription chat uses this login; no OpenAI API key is required.",
        );
        break;
      case "logged-in-other":
        statusSetting.setDesc(
          "Codex is authenticated with an API key or access token, not a ChatGPT login. " +
            "This provider refuses that mode to avoid silently using metered API billing.",
        );
        statusSetting.addButton((button) =>
          button
            .setButtonText("Sign in with ChatGPT")
            .onClick(() => void this.runCodexLogin(statusSetting)),
        );
        break;
      case "not-logged-in":
        statusSetting.setDesc(
          "The Codex runtime is available but signed out. Sign in with ChatGPT to use your subscription.",
        );
        statusSetting.addButton((button) =>
          button
            .setButtonText("Sign in")
            .setCta()
            .onClick(() => void this.runCodexLogin(statusSetting)),
        );
        break;
      case "not-installed":
        statusSetting.setDesc(
          "No usable Codex runtime was found. Install or update the ChatGPT desktop app, sign in, then reopen settings. A separately installed Codex CLI is also supported.",
        );
        break;
      case "unsupported":
        statusSetting.setDesc(status.error ?? "Codex subscription chat is unavailable here.");
        break;
      case "error":
      default:
        statusSetting.setDesc(status.error ?? "Could not determine Codex readiness.");
        break;
    }
  }

  private async runCodexLogin(statusSetting: Setting): Promise<void> {
    statusSetting.setDesc("Opening the Codex sign-in flow…");
    try {
      await this.plugin.startCodexCliLogin();
    } catch (error) {
      if (!this.isCurrentSettingsOwner(statusSetting.settingEl)) return;
      statusSetting.setDesc(`Could not start Codex sign-in: ${(error as Error).message}`);
      return;
    }
    if (!this.isCurrentSettingsOwner(statusSetting.settingEl)) return;
    providerModelCatalog.invalidate("codex");
    await this.refreshCodexStatus(statusSetting);
    if (!this.isCurrentSettingsOwner(statusSetting.settingEl)) return;
    this.display();
  }

  /**
   * Wraps a group of settings in a native <details>/<summary> disclosure so
   * heavy, rarely-touched sections can default to collapsed without becoming
   * unreachable to in-place search. Bodies are rendered eagerly; the summary
   * is a plain-text label (NOT a setHeading —
   * a <summary> cannot host an Obsidian Setting); the builder writes into the
   * body div, where the existing render* helpers keep emitting their own
   * setHeading() labels unchanged. Each disclosure defaults to closed when the
   * settings tab is first opened, then keeps its state across this.display()
   * re-renders for as long as the tab remains open. hide() clears that transient
   * state, while a child modal layered above Settings leaves it untouched.
   * Styling is class-only (no `.style` assignments) per CLAUDE.md / Obsidian review.
   */
  private renderCollapsibleSection(
    containerEl: HTMLElement,
    sectionId: SettingsCollapsibleSectionId,
    label: string,
    builder: (bodyEl: HTMLElement) => void
  ): void {
    const details = containerEl.createEl("details", {
      cls: "vaultguard-settings-section",
    });
    details.dataset.vaultguardSettingsSection = sectionId;
    // Seed the default only the FIRST time a section is rendered in a Settings
    // session, then defer to tracked state so user changes survive re-renders.
    if (!this.collapsibleSectionSeenIds.has(sectionId)) {
      this.collapsibleSectionSeenIds.add(sectionId);
      if (DEFAULT_OPEN_SECTIONS.includes(sectionId)) {
        this.openCollapsibleSectionIds.add(sectionId);
      }
    }
    details.open = this.openCollapsibleSectionIds.has(sectionId);
    const stateEpoch = this.collapsibleSectionStateEpoch;
    details.addEventListener("toggle", () => {
      // Ignore a delayed native toggle from DOM belonging to an already-closed
      // Settings session.
      if (stateEpoch !== this.collapsibleSectionStateEpoch) return;
      // A search forces sections open so results are reachable. That is the
      // filter's doing, not the user's, so it must not become sticky state.
      if (this.suppressCollapsibleTracking) return;
      if (details.open) {
        this.openCollapsibleSectionIds.add(sectionId);
      } else {
        this.openCollapsibleSectionIds.delete(sectionId);
      }
    });
    details.createEl("summary", {
      text: label,
      cls: "vaultguard-settings-section-summary",
    });
    const bodyEl = details.createDiv({ cls: "vaultguard-settings-section-body" });
    builder(bodyEl);
  }

  /**
   * Search box pinned at the top of the tab.
   *
   * This tab renders 98 setting rows and more than half of them already sit
   * behind a disclosure, so the dominant complaint is not density — it is that
   * a setting cannot be found by name. Filtering reaches every row including
   * the collapsed ones (see `applySettingsFilter`), which is also what makes
   * collapsing safe: nothing becomes unreachable, it just stops being in the way.
   *
   * `SettingGroup.addSearch` renders a full-width search card; the guarded
   * fallback is a plain `Setting` row, whose `addSearch` is long-standing API.
   * The guard mirrors `renderOptionalModulesSection` — the community-review
   * linter honours only a literal `requireApiVersion()`.
   */
  private renderSettingsSearch(containerEl: HTMLElement): void {
    const configure = (search: SearchComponent): void => {
      search
        .setPlaceholder("Search settings…")
        .setValue(this.settingsFilterQuery)
        .onChange((value) => {
          this.settingsFilterQuery = value;
          this.applySettingsFilter(containerEl);
        });
    };

    if (
      typeof requireApiVersion === "function" &&
      requireApiVersion("1.11.0") &&
      typeof SettingGroup === "function"
    ) {
      new SettingGroup(containerEl).addClass("vaultguard-settings-search").addSearch(configure);
      return;
    }

    new Setting(containerEl).setClass("vaultguard-settings-search").addSearch(configure);
  }

  /**
   * Hides every row whose name/description does not contain the query, then
   * hides any heading and any disclosure left with nothing under it.
   *
   * Class-only (no `.style` writes) per CLAUDE.md / Obsidian review. Matching
   * rows inside a collapsed `<details>` force it open so results are visible;
   * `suppressCollapsibleTracking` keeps those forced opens out of the user's
   * remembered section state.
   */
  private applySettingsFilter(rootEl: HTMLElement): void {
    const query = this.settingsFilterQuery.trim().toLowerCase();
    const filtering = query.length > 0;
    rootEl.toggleClass(FILTERING_CLS, filtering);

    const isHiddenRow = (el: Element): boolean => el.classList.contains(FILTER_HIDDEN_CLS);
    const liveRowIn = (scope: ParentNode): boolean =>
      scope.querySelector(
        `.setting-item:not(.setting-item-heading):not(.${FILTER_HIDDEN_CLS})`,
      ) !== null;

    // 1. Rows. The search box itself is a Setting/SettingGroup and must survive.
    for (const item of Array.from(rootEl.querySelectorAll<HTMLElement>(".setting-item"))) {
      if (item.closest(`.${SEARCH_CLS}`) || item.closest(".setting-group-search")) continue;
      if (item.classList.contains("setting-item-heading")) continue;
      const haystack = (item.textContent ?? "").toLowerCase();
      item.toggleClass(FILTER_HIDDEN_CLS, filtering && !haystack.includes(query));
    }

    // 2. Headings. A heading survives when a row it OWNS survived.
    //
    //    Ownership is "nearest preceding heading in document order, within the
    //    same disclosure scope" — not a walk over following siblings. Sibling
    //    walking gets this wrong: a `<details>` that appears after a heading is
    //    a section in its own right, so a match inside it would wrongly keep the
    //    unrelated heading above it alive. Scoping by nearest ancestor
    //    disclosure also keeps a section's own headings from claiming rows that
    //    sit outside it (the Vault summary rows vs. the manage-vaults
    //    disclosure below them).
    const owningHeading = new Map<ParentNode, HTMLElement>();
    const survivingHeadings = new Set<HTMLElement>();
    for (const item of Array.from(rootEl.querySelectorAll<HTMLElement>(".setting-item"))) {
      if (item.closest(`.${SEARCH_CLS}`) || item.closest(".setting-group-search")) continue;
      const scope: ParentNode =
        item.closest("details.vaultguard-settings-section") ?? rootEl;
      if (item.classList.contains("setting-item-heading")) {
        owningHeading.set(scope, item);
        continue;
      }
      if (isHiddenRow(item)) continue;
      const owner = owningHeading.get(scope);
      if (owner) survivingHeadings.add(owner);
    }
    for (const heading of Array.from(
      rootEl.querySelectorAll<HTMLElement>(".setting-item-heading"),
    )) {
      if (heading.closest(`.${SEARCH_CLS}`)) continue;
      heading.toggleClass(FILTER_HIDDEN_CLS, filtering && !survivingHeadings.has(heading));
    }

    // 3. Disclosures. Force open around the tracking guard so a search can see
    //    into Advanced / AI & automation / Manage vaults without the forced
    //    state leaking into what the user chose to leave open.
    this.suppressCollapsibleTracking = true;
    try {
      for (const details of Array.from(
        rootEl.querySelectorAll<HTMLDetailsElement>(
          "details.vaultguard-settings-section[data-vaultguard-settings-section]",
        ),
      )) {
        const sectionId = details.dataset
          .vaultguardSettingsSection as SettingsCollapsibleSectionId;
        if (filtering) {
          const hasHit = liveRowIn(details);
          details.toggleClass(FILTER_HIDDEN_CLS, !hasHit);
          details.open = hasHit;
        } else {
          details.removeClass(FILTER_HIDDEN_CLS);
          details.open = this.openCollapsibleSectionIds.has(sectionId);
        }
      }
    } finally {
      this.suppressCollapsibleTracking = false;
    }
  }

  /**
   * Phase 12 (D3): the user-owned PIN lifecycle. Set a PIN to lock-instead-of-
   * logout on idle; change/disable it here. The biometric toggle is a hidden
   * D1/O-2 seam (never shown on current Obsidian; mobile is PIN-only).
   */
  private renderVaultLockSection(containerEl: HTMLElement): void {
    const plugin = this.plugin;
    const enrolled = plugin.pinLockEnrolled();
    const idleAction = plugin.effectiveIdleAction();

    new Setting(containerEl).setName("Vault lock / PIN").setHeading();

    if (!enrolled) {
      new Setting(containerEl)
        .setName("Set a PIN")
        .setDesc(
          `A PIN lets VaultGuard lock (instead of log you out) when the vault goes idle — you unlock with the PIN, no full re-login. Your organization's current idle action is "${idleAction}".`
        )
        .addButton((b) =>
          b
            .setButtonText("Set PIN")
            .setCta()
            .onClick(() => {
              new SetPinModal(this.app, async (secret) => {
                await plugin.enrollPinLock(secret);
                this.display();
              }).open();
            })
        );
    } else {
      new Setting(containerEl)
        .setName("Vault PIN")
        .setDesc(
          "Your vault locks instead of logging out when idle. Disabling the PIN restores transparent at-rest unlock on this device."
        )
        .addButton((b) =>
          b.setButtonText("Change PIN").onClick(() => {
            new ChangePinModal(this.app, async (current, next) => {
              await plugin.disablePinLock(current);
              await plugin.enrollPinLock(next);
              this.display();
            }).open();
          })
        )
        .addButton((b) =>
          b
            .setButtonText("Disable PIN")
            .setWarning()
            .onClick(() => {
              new DisablePinModal(this.app, async (secret) => {
                await plugin.disablePinLock(secret);
                this.display();
              }).open();
            })
        );
    }

    // "Require PIN on startup" — the passkey (default) vs max-security switch. Only
    // meaningful once a PIN is enrolled (it governs how that PIN behaves at startup /
    // login). Off = transparent unlock after login, PIN only re-locks on idle; on =
    // PIN required every startup (transparent wrap removed → true D2).
    if (enrolled) {
      const requireOnStartup = this.plugin.settings.requirePinOnStartup === true;
      new Setting(containerEl)
        .setName("Require PIN on startup")
        .setDesc(
          requireOnStartup
            ? "On: enter your PIN every time Obsidian starts or you log in. Your notes stay encrypted on disk until you do (maximum security)."
            : "Off: unlock transparently after login; the PIN only re-locks the vault when it goes idle."
        )
        .addToggle((t) =>
          t.setValue(requireOnStartup).onChange(async (value) => {
            await this.plugin.setRequirePinOnStartup(value);
            this.display();
          })
        );
    }

    // Biometric unlock (D1/O-2 seam): desktop-only AND only when the platform
    // actually exposes a user-verifying authenticator — which is NEVER on
    // current Obsidian, so this toggle stays hidden. Mobile is PIN-only.
    if (!Platform.isMobileApp) {
      void biometricAvailable().then((available) => {
        if (!available) return;
        new Setting(containerEl)
          .setName("Use biometric unlock")
          .setDesc("Unlock with your device biometrics instead of typing the PIN.")
          .addToggle((t) =>
            t.setValue(false).onChange(() => void plugin.enrollBiometric())
          );
      });
    }
  }

  /**
   * "View recovery code" — deliberately rendered in Protection scope, NOT in the
   * collapsed Advanced disclosure where it used to live alongside the at-rest
   * maintenance actions.
   *
   * This code is the only thing that decrypts this device's files after a
   * keychain reset, an OS reinstall, or a move to a new machine. Behind a
   * collapsed section, a user could run for months without learning it exists
   * and only discover it at the moment it is already too late to read it. It is
   * a safety control, so it is never more than zero clicks from view; the
   * destructive at-rest actions stay in Advanced.
   *
   * Rendered wherever it is called from — it recomputes its own preconditions
   * rather than inheriting them, so there is no hidden coupling to the at-rest
   * panel it was extracted from.
   */
  private renderRecoveryCodeSetting(containerEl: HTMLElement): void {
    const status = this.plugin.getAtRestStatus();
    const session = this.plugin.getSession();
    const canReauth = status.kind === "unlocked" && Boolean(session);
    const reauthDisabledHint = !session
      ? " Log in to your VaultGuard account to enable this action — re-authentication is required so a brief unattended-laptop moment can't expose your at-rest key."
      : "";

    const recoverySetting = new Setting(containerEl)
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
  }

  /**
   * "N encrypted, N plaintext, N excluded" — the reconcilable version of the
   * status badge, rendered directly beneath it at the top of Protection.
   *
   * This used to live inside the at-rest panel in the collapsed Advanced
   * section, which put the product's central claim ("your files are encrypted
   * on this disk") two clicks from view and duplicated the badge alongside it.
   * Status belongs where the user lands; only the maintenance ACTIONS are
   * rare enough to collapse.
   */
  private renderAtRestTally(parent: HTMLElement, localProjectMemoryMode: boolean): void {
    const status = this.plugin.getAtRestStatus();
    const tallyEl = parent.createDiv({
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
        if (localProjectMemoryMode && tally.encrypted > 0) {
          tallyEl.createDiv({
            cls: "vaultguard-at-rest-tally-warning",
            text: `${tally.encrypted} VG1 file(s) remain encrypted. Run "Decrypt vault and disable at-rest encryption" before using this repo-root vault for coding-agent memory.`,
          });
        } else if (tally.plaintext > 0 && status.kind === "unlocked") {
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
  }

  /**
   * At-rest MAINTENANCE actions: encrypt-all, decrypt-and-disable, guided reset,
   * restore-from-code. Rendered inside the "Encryption maintenance" disclosure
   * nested in Protection — not in Advanced, where it used to sit split away from
   * the exclusion settings that govern the very same layer.
   *
   * The status badge and tally are deliberately NOT rendered here: Protection
   * shows them once, above this disclosure.
   */
  /**
   * Plain-language "what this actually does to my files" copy. Rendered at the
   * top of Protection rather than beside the maintenance actions: it is the
   * sentence that answers a new user's first question, so it must not be behind
   * a disclosure.
   */
  private atRestExplanation(): string {
    if (this.plugin.isLocalProjectMemoryModeEnabled()) {
      return "Disabled by Local Project Memory Mode. Files are kept plaintext for repo-root project memory, Git tools, and coding agents.";
    }
    return Platform.isMobileApp
      ? "Vault files on this device are encrypted on disk with a per-device key kept in this app's secure storage. Without VaultGuard Sync running, the files on disk are ciphertext — useful if your phone backs up app data to iCloud / Google Drive."
      : "Vault files on this device are encrypted on disk with a key bound to your OS keychain (or, if unavailable, a per-device key). Without VaultGuard Sync running, opening files in Finder shows ciphertext.";
  }

  private renderAtRestSection(containerEl: HTMLElement): void {
    const localProjectMemoryMode = this.plugin.isLocalProjectMemoryModeEnabled();
    const status = this.plugin.getAtRestStatus();
    const panel = containerEl.createDiv({ cls: "vaultguard-at-rest-panel" });

    const isUnlocked = status.kind === "unlocked";
    const needsRecovery = status.kind === "needs-recovery";

    const encryptSetting = new Setting(panel)
      .setName("Encrypt all files now")
      .setDesc(
        localProjectMemoryMode
          ? "Disabled while Local Project Memory Mode is active. Repo-root project files must stay plaintext."
          : "Walks the vault and rewrites any plaintext files as ciphertext. Idempotent — files already encrypted are skipped."
      )
      .addButton((button) => {
        button
          .setButtonText("Encrypt vault")
          .setCta()
          .setDisabled(localProjectMemoryMode || !isUnlocked)
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
    const canDecrypt = localProjectMemoryMode || canReauth;
    const reauthDisabledHint = !session
      ? " Log in to your VaultGuard account to enable this action — re-authentication is required so a brief unattended-laptop moment can't expose your at-rest key."
      : "";

    const decryptSetting = new Setting(panel)
      .setName("Decrypt vault and disable at-rest encryption")
      .setDesc(
        localProjectMemoryMode
          ? "Recover any existing VG1 files to plaintext and keep at-rest encryption disabled. Uses a non-encrypting write path."
          : "Reverse the at-rest encryption, persist encryption disabled before plaintext writes, and keep files readable through normal tools. Requires re-entering your account password." +
            reauthDisabledHint
      )
      .addButton((button) => {
        button
          .setButtonText(localProjectMemoryMode ? "Decrypt and keep plaintext" : "Decrypt vault")
          .setWarning()
          .setDisabled(!canDecrypt)
          .onClick(() => {
            if (localProjectMemoryMode) {
              void (async () => {
                button.setButtonText("Decrypting…").setDisabled(true);
                try {
                  await this.plugin.decryptVaultAndDisableAtRestEncryption();
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
              return;
            }
            new AtRestPasswordConfirmModal(this.app, {
              title: "Confirm: decrypt vault on this device",
              description:
                "This will rewrite encrypted files back to plaintext and keep local at-rest encryption disabled. Anyone with disk access (or another logged-in user on this Mac) will then be able to read your notes through Finder. Re-enter your account password to confirm you're the one doing this.",
              onVerify: (pw) => this.plugin.verifyAccountPassword(pw),
              onConfirmed: () => {
                void (async () => {
                  button.setButtonText("Decrypting…").setDisabled(true);
                  try {
                    await this.plugin.decryptVaultAndDisableAtRestEncryption();
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

    // Door #2 (D4): the guided-reset entry point. Enabled PRECISELY when the
    // buttons above (Encrypt / Decrypt / View-code) are all disabled — i.e. in
    // needs-recovery with a session + online — so the button that lights up is
    // exactly the one a stuck user needs. Offline / logged-out → disabled +
    // honest copy, with the non-destructive "Enter recovery code…" alternate
    // sitting directly below (D5). It opens the SAME AtRestRecoveryModal as the
    // indicator CTA (door #1) — one flow, two doors. The 13-02 engine guard is
    // authoritative; this enablement is only UX (shared matrix, no second gate).
    const resetState = computeAtRestResetButtonState({
      needsRecovery,
      hasSession: Boolean(session),
      online: this.plugin.isConnectedOnline(),
    });
    if (resetState.visible) {
      const resetSetting = new Setting(panel)
        .setName("Reset local encryption & re-download from server")
        .setDesc(resetState.description)
        .addButton((button) => {
          button.setButtonText("Reset & re-download");
          if (resetState.cta) button.setCta();
          // LO-02: also dead while a reset is already running (the engine's
          // reentrancy guard is authoritative; this removes the trigger surface).
          const inFlight = this.plugin.isAtRestResetInFlight();
          button.setDisabled(!resetState.enabled || inFlight).onClick(() => {
            if (this.plugin.isAtRestResetInFlight()) {
              new Notice(
                "VaultGuard Sync: a local at-rest reset is already running. Please wait for it to finish.",
                6000,
              );
              return;
            }
            new AtRestRecoveryModal(this.app, this.plugin).open();
          });
        });
      resetSetting.settingEl.addClass("vaultguard-at-rest-action");
    }

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
            onSubmit: (code, opts) => this.plugin.restoreAtRestFromRecoveryCode(code, opts),
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

  private renderCurrentVaultSettings(rootContainerEl: HTMLElement, session: UserSession | null): void {
    this.renderCollapsibleSection(rootContainerEl, "vault", "Vault", (containerEl) =>
      this.renderCurrentVaultSettingsBody(containerEl, session),
    );
  }

  private renderCurrentVaultSettingsBody(
    containerEl: HTMLElement,
    session: UserSession | null,
  ): void {
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
    const ownerDetached = (): boolean =>
      sectionEl.isConnected === false || rootEl.isConnected === false;
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
    if (ownerDetached()) return;

    if (this.plugin.settings.serverVaultId) {
      try {
        currentVault = await this.plugin.getCurrentVaultRecord();
        memberRole = await this.plugin.getCurrentVaultMemberRole().catch(() => null);
      } catch (error) {
        currentVaultError = error;
      }
    }
    if (ownerDetached()) return;

    sectionEl.empty();

    // The current-vault summary (name/desc + Refresh/Switch/Permissions
    // buttons) stays VISIBLE on sectionEl. It is emitted into its own container
    // FIRST so it precedes the disclosure in the DOM. The heavier sub-sections
    // (Available vaults list, Create vault, Current vault options, Vault members)
    // move into a single "Manage vaults & members" disclosure to reduce overwhelm.
    const summaryEl = sectionEl.createDiv({ cls: "vaultguard-current-vault-summary" });
    this.renderCollapsibleSection(
      sectionEl,
      "manage-vaults-members",
      "Manage vaults & members",
      (manageBody) => {
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
      },
    );
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
    const ownerDetached = (): boolean =>
      membersEl.isConnected === false ||
      sectionEl.isConnected === false ||
      rootEl.isConnected === false;
    try {
      const [members, usersResult] = await Promise.all([
        this.plugin.listCurrentVaultMembers(),
        this.plugin.listOrganizationUsers()
          .then((users) => ({ users, error: null as unknown }))
          .catch((error) => ({ users: [] as UserListEntry[], error })),
      ]);
      if (ownerDetached()) return;
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
      // The target's ORG account status, which this tab already has from the
      // user list it just loaded. It selects between the one-step and the
      // two-step extend; it never decides whether the guest controls appear.
      const statusByUser = new Map<string, string>(users.map((user) => [user.id, user.status]));
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
        this.renderVaultMemberRow(membersEl, sectionEl, rootEl, session, vault, member, userById, canManage, statusByUser);
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
      if (ownerDetached()) return;
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
    canManage: boolean,
    statusByUser: Map<string, string> = new Map()
  ): void {
    const user = userById.get(member.userId);
    const label = this.formatUserLabel(member.userId, user);
    const desc = this.formatVaultMemberDescription(member, userById);

    const setting = new Setting(membersEl)
      .setName(label)
      .setDesc(desc);

    if (!canManage) {
      return;
    }

    // DR-6. Both guest controls exist only for a row that IS temporary access.
    // A guest whose access has fully lapsed has already had every membership
    // row deleted, so they never appear in this list and neither control is
    // ever rendered for them — their recovery lives on the user list.
    //
    // Computed before the dropdown because `isSelf` gates that too.
    const guestControls = this.guestMemberControlsFor(
      member,
      statusByUser.get(member.userId),
      canManage,
      session.userId
    );

    let nextRole = member.role;
    setting.addDropdown((dropdown) => {
      for (const role of VAULT_ROLES) {
        dropdown.addOption(role, VAULT_ROLE_LABELS[role]);
      }
      if (guestControls.isSelf) {
        // This is the VAULT member role, not the org role, and it is genuinely
        // unguarded server-side: `vaults/handler.ts` blocks removing the last
        // vault admin but not demoting one. Freezing your own row here is
        // cheap; the vault Lambda is out of scope for this change.
        dropdown.setDisabled(true);
        dropdown.selectEl.title =
          "You cannot change your own role in this vault. Ask another vault or organization admin to do it.";
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

    if (guestControls.showExtend) {
      setting.addButton((button) =>
        button
          .setButtonText("Extend")
          .onClick(async () => {
            const days = await this.promptForGuestExtension(
              rootEl,
              label,
              guestControls.needsReactivateFirst
            );
            if (days === null) return;

            button.setButtonText("Extending...");
            button.setDisabled(true);
            const outcome = await this.runGuestExtendSequence(this.guestMemberActionClient(), {
              userId: member.userId,
              expiresInDays: days,
              reactivateFirst: guestControls.needsReactivateFirst,
            });

            if (outcome.status === "extended") {
              this.showStatus(
                rootEl,
                outcome.reactivated
                  ? `Re-enabled ${label} and extended their access by ${days} days.`
                  : `Extended ${label}'s access by ${days} days.`,
                false
              );
              await this.renderCurrentVaultSettingsContent(sectionEl, rootEl, session);
              return;
            }

            this.showStatus(
              rootEl,
              outcome.status === "reactivate-failed"
                ? `Could not re-enable ${label}, so their access was not extended: ${outcome.message}`
                : `${label}: ${outcome.message}`,
              true
            );
            button.setButtonText("Extend");
            button.setDisabled(false);
          })
      );
    }

    if (guestControls.showEndNow) {
      setting.addButton((button) =>
        button
          .setButtonText("End now")
          .setWarning()
          .onClick(async () => {
            const confirmed = await this.showDestructiveConfirmation(
              rootEl,
              "END ACCESS",
              `Type END ACCESS to confirm. This ends ${label}'s access across the whole ` +
              "organization and disables their account — it is not limited to " +
              `${vault.name}. To take away only this vault, use Remove instead.`
            );
            if (!confirmed) return;

            button.setButtonText("Ending...");
            button.setDisabled(true);
            try {
              await this.guestMemberActionClient().revokeUser(member.userId);
              this.showStatus(rootEl, `Ended ${label}'s access.`, false);
              await this.renderCurrentVaultSettingsContent(sectionEl, rootEl, session);
            } catch (error) {
              this.showStatus(rootEl, `Failed to end access: ${this.errorMessage(error)}`, true);
              button.setButtonText("End now");
              button.setDisabled(false);
            }
          })
      );
    }

    setting.addButton((button) =>
      button
        .setButtonText("Remove")
        .setWarning()
        .onClick(async () => {
          const confirmed = await this.showDestructiveConfirmation(
            rootEl,
            "REMOVE MEMBER",
            `Type REMOVE MEMBER to confirm removing ${label} from ${vault.name}. ` +
            "This affects this vault only — their organization account is unchanged."
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

  /**
   * Composes the one-line description under a vault member's name.
   *
   * Extracted from `renderVaultMemberRow` so it can be asserted directly:
   * `Setting.setDesc()` returns `this` and drops the string, so the composed
   * text is invisible to any test that goes through the Setting mock.
   *
   * A permanent member's output is unchanged — `Role:`, `Joined:` and the
   * optional `Invited by:`, joined with `" · "`. A guest additionally carries a
   * `Guest` marker and an expiry segment whose verb separates a still-active
   * guest from a lapsed one; without it an expired guest reads as a permanent
   * viewer in the exact screen where an admin decides who to remove.
   *
   * The expiry verdict comes from `deriveGuestPresentation` — the same derive
   * the user list and the web admin panel use — so this row can never disagree
   * with them about whether a guest has lapsed.
   */
  private formatVaultMemberDescription(
    member: VaultMemberRecord,
    userById: Map<string, UserLabelIdentity>,
    nowMs = Date.now()
  ): string {
    const guest = deriveGuestPresentation(member, nowMs);
    return [
      `Role: ${VAULT_ROLE_LABELS[member.role]}`,
      guest ? "Guest" : null,
      guest?.date ? `${guest.expired ? "Expired" : "Expires"}: ${this.formatDate(guest.date)}` : null,
      `Joined: ${this.formatDate(member.joinedAt)}`,
      member.invitedBy ? `Invited by: ${this.formatUserLabel(member.invitedBy, userById.get(member.invitedBy))}` : null,
    ].filter((value): value is string => Boolean(value)).join(" · ");
  }

  /**
   * Which guest controls a vault-member row offers — DR-6.
   *
   * Extracted from `renderVaultMemberRow` because `Setting` discards the names
   * and descriptions it is given, so nothing about the rendered row is
   * observable from a test; the decision is.
   *
   * Guest-ness comes from the SAME derive the row description, the plugin user
   * list and the web admin panel read. No date comparison is made here, so
   * these controls cannot disagree with the badge beside them about who holds
   * temporary access.
   *
   * `accountStatus` is the target's ORG account status from `GET /users`, not
   * anything about this vault. It only ever selects between a one-step and a
   * two-step sequence; it never decides whether the controls appear.
   *
   * `sessionUserId` is the signed-in user, so the row can refuse to offer the
   * destructive control that targets THEM. Defense in depth only — the server
   * refuses a self-revoke outright — but a control that is going to be refused
   * should not be rendered as if it would work.
   */
  private guestMemberControlsFor(
    member: VaultMemberRecord,
    accountStatus: string | undefined,
    canManage: boolean,
    sessionUserId: string,
    nowMs = Date.now()
  ): GuestMemberControls {
    const manageableGuest = canManage && deriveGuestPresentation(member, nowMs) !== null;
    const isSelf = member.userId === sessionUserId;
    return {
      isSelf,
      showExtend: manageableGuest,
      // "End now" calls `revokeUser`, which is the ORG-wide revoke, not a vault
      // removal: on your own row it disables your own account. A sole admin who
      // pressed it locked themselves out of their organization for good.
      // `showExtend` is deliberately untouched — moving your own expiry boundary
      // outward is not destructive.
      showEndNow: manageableGuest && !isSelf,
      // Reaching this row at all means a membership row still exists. A
      // disabled identity that still has one is the narrow partial-teardown
      // state, NOT the ordinary post-expiry state — in that one the rows are
      // gone, the member never appears in this list, and the recovery is the
      // user list's grant-guest-access path instead.
      needsReactivateFirst:
        manageableGuest && (accountStatus === "revoked" || accountStatus === "suspended"),
    };
  }

  /**
   * Runs the extend, reactivating first where the row belongs to a disabled
   * identity, and reports what actually happened.
   *
   * Takes its client as an argument so the whole sequence — including both
   * failure directions — is exercisable without Obsidian or a network.
   */
  private async runGuestExtendSequence(
    client: GuestMemberActionClient,
    input: { userId: string; expiresInDays: number; reactivateFirst: boolean }
  ): Promise<GuestExtendOutcome> {
    if (input.reactivateFirst) {
      try {
        await client.reactivateUser(input.userId);
      } catch (error) {
        // Direction 1. Nothing has changed, so nothing needs undoing, and the
        // extend is deliberately NOT attempted: restoring vault access to an
        // account that is still disabled would be access nobody can use.
        return { status: "reactivate-failed", message: this.errorMessage(error) };
      }
    }

    try {
      await client.extendGuestAccess(input.userId, input.expiresInDays);
    } catch (error) {
      if (!input.reactivateFirst) {
        return { status: "extend-failed", message: this.errorMessage(error) };
      }
      // Direction 2, the expensive one. The reactivate above has ALREADY
      // re-taken the seat, so the organization is now paying for an enabled
      // account that got no access back. All three facts are stated, and the
      // lever that undoes it is named.
      //
      // `revokeUser` is deliberately NOT called here as a silent rollback:
      // revoking is an org-wide, audited, account-disabling action, and firing
      // it unattended out of a failed UI sequence is worse than telling the
      // operator what state they are in.
      return {
        status: "extend-failed-after-reactivate",
        message:
          "The account was re-enabled and a seat was consumed, but access was NOT extended: " +
          `${this.errorMessage(error)} Use End now if the account should not stay enabled.`,
      };
    }

    return { status: "extended", reactivated: input.reactivateFirst };
  }

  /**
   * The real client behind the guest controls, built from the plugin's public
   * wrappers so this file never reaches for the API client directly.
   */
  private guestMemberActionClient(): GuestMemberActionClient {
    return {
      extendGuestAccess: (userId, expiresInDays) =>
        this.plugin.extendCurrentVaultGuestAccess(userId, expiresInDays),
      reactivateUser: (userId) => this.plugin.reactivateOrganizationUser(userId),
      revokeUser: (userId) => this.plugin.revokeOrganizationUser(userId),
    };
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
    if (this.collapsibleSectionSessionActive) {
      const collapsibleSections = Array.from(
        this.containerEl.querySelectorAll<HTMLDetailsElement>(
          "details.vaultguard-settings-section[data-vaultguard-settings-section]",
        ),
      );
      for (const details of collapsibleSections) {
        const sectionId = details.dataset
          .vaultguardSettingsSection as SettingsCollapsibleSectionId;
        if (details.open) {
          this.openCollapsibleSectionIds.add(sectionId);
        } else {
          this.openCollapsibleSectionIds.delete(sectionId);
        }
      }
    } else {
      this.openCollapsibleSectionIds.clear();
      this.collapsibleSectionSeenIds.clear();
      this.collapsibleSectionStateEpoch += 1;
      this.collapsibleSectionSessionActive = true;
    }

    this.codexStatusAbort?.abort();
    this.codexStatusAbort = null;
    this.codexModelAbort?.abort();
    this.codexModelAbort = null;
    const { containerEl } = this;

    // This tab's own container IS the scroll container: Obsidian builds it as
    // `.vertical-tab-content`, which app.css gives `overflow-y: auto` and
    // `height: 100%`. So `empty()` collapses the content height and the
    // browser drops `scrollTop` to 0. With 51 `display()` call sites in this
    // file, every re-render — flipping an optional module, saving a field —
    // would otherwise throw the reader back to the top of a 98-row tab.
    //
    // The `childElementCount > 0` guard skips the very first render, so an
    // empty container can never restore a stale offset. It also makes the
    // whole thing a no-op against the node-environment test doubles, which
    // have neither property: `undefined > 0` is `false`.
    const previousScrollTop =
      this.containerEl.childElementCount > 0 ? this.containerEl.scrollTop : 0;

    containerEl.empty();
    containerEl.addClass("vaultguard-settings-tab");
    this.i18n.applyToRoot(containerEl);

    // ── Header ──────────────────────────────────────────────────────────────
    // No top-level heading here: Obsidian already renders the plugin name as
    // the settings-tab title, and repeating it trips the community-review
    // linter (settings-tab/no-problematic-settings-headings, which also bans
    // "settings"/"options"/"general" in setHeading labels). Lead with the
    // description paragraph instead.
    this.renderSettingsNote(containerEl, this.i18n.t("settings.intro"), "lead");
    this.renderSettingsSearch(containerEl);
    const statusHost = containerEl.createDiv({ cls: "vaultguard-settings-status-host" });
    this.renderSettingsStatus(statusHost);

    // ── Protection ──────────────────────────────────────────────────────────
    // First, and deliberately ahead of Connection / Account / Vault.
    //
    // The at-rest layer is INDEPENDENT of the cloud layer (docs/AT-REST-
    // ENCRYPTION.md: different keys, different recovery, "encrypting or
    // decrypting at one layer does not affect the other"). A user who never
    // signs in still gets local encryption, and the excluded-path rules govern
    // at-rest as well as sync — so nothing here waits on a connection.
    //
    // It also means the first thing anyone sees on opening Settings is the
    // at-rest status badge: reassurance that the product is doing its job,
    // rather than a configuration decision they are not yet equipped to make.
    this.renderProtectionScopeSection(containerEl);

    // `session` / `isManualMode` are computed once and read by both the
    // Connection and Account blocks below.
    const session = this.plugin.getSession();
    const isManualMode = this.plugin.settings.manualConfig ?? false;

    // ── Connection ──
    this.renderCollapsibleSection(containerEl, "connection", "Connection", (body) => {
      new Setting(body)
        .setName("Connected to")
        .setDesc(this.plugin.getConnectionTargetLabel());

      // Mode toggle
      new Setting(body)
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
                  body,
                  `Failed: ${err instanceof Error ? err.message : "Unknown error"}`,
                  true
                );
              }
            })
        );

      if (!isManualMode) {
        new Setting(body)
          .setName("VaultGuard Cloud")
          // Derived, not hardcoded: the public export scrubs example.com
          // outside saas-defaults, so a literal domain here would ship claiming
          // the build uses api.example.com while it actually uses the bundled
          // default. Reading the value means the sentence cannot contradict it.
          .setDesc(
            `Uses the bundled ${saasDefaultsHostLabel()} and Cognito configuration. Sign in from the Account section above.`
          )
          .addButton((button) =>
            button
              .setButtonText("Reset")
              .setTooltip("Clear locally cached connection fields and use the bundled cloud defaults")
              .onClick(async () => {
                button.setDisabled(true);
                try {
                  await this.plugin.resetCloudConnectionDefaults();
                  this.showStatus(body, "VaultGuard Cloud defaults restored.", false);
                  this.display();
                } catch (err) {
                  this.showStatus(
                    body,
                    `Failed: ${err instanceof Error ? err.message : "Unknown error"}`,
                    true
                  );
                } finally {
                  button.setDisabled(false);
                }
              })
          );

        const orgSlugSetting = new Setting(body)
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
                this.showStatus(body, "Enter an organization slug first.", true);
                return;
              }
              button.setButtonText("Connecting...");
              button.setDisabled(true);
              try {
                await this.plugin.resolveOrgConfig(slug);
                this.showStatus(body, `Connected to "${slug}" successfully!`, false);
                this.display();
              } catch (err) {
                this.showStatus(
                  body,
                  `Failed: ${err instanceof Error ? err.message : "Unknown error"}`,
                  true
                );
              } finally {
                button.setButtonText("Connect");
                button.setDisabled(false);
              }
            })
        );

        const redeemSetting = new Setting(body)
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
                this.showStatus(body, "Paste your invite link first.", true);
                return;
              }
              const parsed = parseInviteLink(raw);
              if (!parsed.org) {
                this.showStatus(
                  body,
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
                  body,
                  `Invite for "${parsed.org}" redeemed. Follow the prompts to set your password.`,
                  false
                );
                this.display();
              } catch (err) {
                this.showStatus(
                  body,
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
        const serverConfigSetting = new Setting(body)
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
                this.showStatus(body, "Paste a server config URL first.", true);
                return;
              }
              button.setButtonText("Applying...");
              button.setDisabled(true);
              try {
                await this.plugin.applyManualServerConfigUrl(raw);
                if (serverConfigInput) serverConfigInput.value = "";
                this.showStatus(body, "Self-hosted server configuration applied.", false);
                this.display();
              } catch (err) {
                this.showStatus(
                  body,
                  `Failed: ${err instanceof Error ? err.message : "Unknown error"}`,
                  true
                );
              } finally {
                button.setButtonText("Apply");
                button.setDisabled(false);
              }
            })
        );

        new Setting(body)
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

        new Setting(body)
          .setName("Organization ID")
          .addText((text) =>
            text
              .setValue(this.plugin.settings.organizationId)
              .onChange(async (value) => {
                this.plugin.settings.organizationId = value.trim();
                await this.plugin.saveSettings();
              })
          );

        new Setting(body)
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

        new Setting(body)
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

    });
    // ── Account ──
    this.renderCollapsibleSection(containerEl, "account", "Account", (body) => {
      if (session) {

        new Setting(body)
          .setName("Logged in as")
          .setDesc(`${session.email} (${session.role})`);

        new Setting(body)
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
                    this.showStatus(body, "Display name cannot be empty.", true);
                    return;
                  }
                  saveBtn.disabled = true;
                  saveBtn.textContent = "Saving...";
                  try {
                    await this.plugin.updateUserProfile(session.userId, newName);
                    this.showStatus(body, "Display name updated.", false);
                    this.display();
                  } catch (error) {
                    this.showStatus(
                      body,
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

        new Setting(body)
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

        new Setting(body)
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
          const selfHostNote = body.createDiv({
            cls: "setting-item-description vaultguard-selfhost-note",
          });
          selfHostNote.appendText("Self-hosting your own VaultGuard server? ");
          const link = selfHostNote.createEl("a", {
            text: "Configure it in connection settings",
            href: "#",
          });
          link.addEventListener("click", (e) => {
            e.preventDefault();
            // Connection is a disclosure now, and it is a sibling of this
            // section rather than an ancestor — so this resolves from the tab
            // root, not from `body`, and OPENS the section before scrolling.
            // Scrolling to a collapsed section would land the user on a closed
            // summary with nothing to configure.
            const target = this.containerEl.querySelector<HTMLDetailsElement>(
              'details[data-vaultguard-settings-section="connection"]',
            );
            if (!target) return;
            target.open = true;
            target.scrollIntoView({ behavior: "smooth", block: "start" });
          });
          selfHostNote.appendText(" after switching to manual configuration.");
        }
      }

    });
    this.renderCurrentVaultSettings(containerEl, session);

    // ── Synchronization ──
    this.renderCollapsibleSection(containerEl, "synchronization", "Synchronization", (body) => {
      const orgPolicy = this.plugin.getOrgPolicySettings();
      if (this.plugin.isLocalProjectMemoryModeEnabled()) {
        new Setting(body)
          .setName("Local-only")
          .setDesc(
            "Remote sync, share links, server vault binding, organization permissions, and team/admin features are disabled while Local Project Memory Mode is active.",
          );
      } else if (orgPolicy) {
        const policyDescription =
          orgPolicy.syncMode === "manual"
            ? "Manual sync only"
            : orgPolicy.syncMode === "realtime"
              ? "Real-time sync managed by your organization"
              : `Periodic sync every ${orgPolicy.syncIntervalMinutes} minute${
                  orgPolicy.syncIntervalMinutes === 1 ? "" : "s"
                }`;

        new Setting(body)
          .setName("Sync interval")
          .setDesc(`Managed by your organization: ${policyDescription}.`);
      } else {
        new Setting(body)
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

      // Excluded paths and the server purge now live in "Protection scope" —
      // they belong with the whole-vault plaintext toggle they are the narrow
      // alternative to, and their at-rest effect needed stating alongside it.
      //
      // What remains here is sync timing only. Controls the plaintext local-only
      // mode makes redundant are rendered DISABLED rather than removed: the
      // previous `if (!isLocalProjectMemoryModeEnabled())` wrapper deleted them
      // from the DOM, which read as "this setting is gone" instead of "this
      // setting has nothing to do right now".
      const localModeActive = this.plugin.isLocalProjectMemoryModeEnabled();

      const conflictSetting = new Setting(body)
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
            .setDisabled(localModeActive)
            .onChange(async (value) => {
              this.plugin.settings.defaultConflictResolution =
                value as ConflictResolutionStrategy;
              await this.plugin.saveSettings();
            })
        );
      if (localModeActive) {
        conflictSetting.descEl.createDiv({
          cls: "setting-item-description vaultguard-setting-disabled-reason",
          text: "Nothing syncs in this mode, so conflicts cannot occur.",
        });
      }
    });
    // ── Access & unlock ──
    this.renderCollapsibleSection(containerEl, "access-unlock", "Access & unlock", (body) => {
      // Recomputed rather than captured from the Synchronization closure above:
      // these are now sibling sections, not one block, so each owns its inputs.
      const localModeActive = this.plugin.isLocalProjectMemoryModeEnabled();

      // These two are server- and at-rest-driven respectively, so in plaintext
      // local-only mode there is no state for them to operate on. Name the
      // section and say why rather than rendering inert controls a user could
      // configure to no effect (e.g. enrolling a PIN that unlocks nothing).
      if (localModeActive) {
        new Setting(body)
          .setName("Allowed community plugins")
          .setDesc(
            "Not applicable in this mode — the allowlist is pushed by the server vault this folder is not bound to."
          );
        new Setting(body)
          .setName("Vault lock")
          .setDesc(
            "Not applicable in this mode — there is no local encryption key to lock. Turn off the plaintext local-only vault above to use a PIN."
          );
      } else {
        this.renderPluginAllowlistSection(body);
        this.renderVaultLockSection(body);
      }
    });

    // ── Display ──
    this.renderCollapsibleSection(containerEl, "display", "Display", (body) => {

      new Setting(body)
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

      new Setting(body)
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

      new Setting(body)
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

      new Setting(body)
        .setName("Status bar detail")
        .setDesc(
          "Choose the normal sync indicator. Recovery, authentication, permission-loading, and long-operation messages always keep their full text."
        )
        .addDropdown((dropdown) =>
          dropdown
            .addOption("full", "Full")
            .addOption("compact", "Compact")
            .addOption("hidden", "Hidden")
            .setValue(this.plugin.settings.statusBarMode)
            .onChange(async (value) => {
              if (value !== "full" && value !== "compact" && value !== "hidden") return;
              this.plugin.settings.statusBarMode = value;
              this.plugin.settings.showStatusBar = value !== "hidden";
              await this.plugin.saveSettings();
              this.plugin.applyStatusBarMode();
            })
        );

      new Setting(body)
        .setName("Show AI Chat shortcut")
        .setDesc(
          "Show the dedicated AI Chat icon in Obsidian's left ribbon. The VaultGuard shield stays visible."
        )
        .addToggle((toggle) =>
          toggle
            .setValue(this.plugin.settings.showAiChatRibbonIcon)
            .onChange(async (value) => {
              this.plugin.settings.showAiChatRibbonIcon = value;
              this.plugin.settings.showRibbonIcons =
                value && this.plugin.settings.showPermissionsGraphRibbonIcon;
              await this.plugin.saveSettings();
              this.plugin.applyRibbonIconLayout();
            })
        );

      new Setting(body)
        .setName("Show Permissions Graph shortcut")
        .setDesc(
          Platform.isMobileApp
            ? "The Permissions Graph shortcut is available in desktop Obsidian."
            : "Show the dedicated Permissions Graph icon in Obsidian's left ribbon. The VaultGuard shield stays visible."
        )
        .addToggle((toggle) =>
          toggle
            .setValue(this.plugin.settings.showPermissionsGraphRibbonIcon)
            .setDisabled(Platform.isMobileApp)
            .onChange(async (value) => {
              this.plugin.settings.showPermissionsGraphRibbonIcon = value;
              this.plugin.settings.showRibbonIcons =
                value && this.plugin.settings.showAiChatRibbonIcon;
              await this.plugin.saveSettings();
              this.plugin.applyRibbonIconLayout();
            })
        );

    });

    // ── Saved artifacts ─────────────────────────────────────────────────────
    // One everyday preference, so it sits at the top level next to the other
    // everyday settings rather than behind a disclosure — the commands that use
    // it ("Save Claude artifact from clipboard" / "Import Claude artifact
    // file…") are always available, including on mobile for the clipboard one.
    new Setting(containerEl)
      .setName("Claude artifact folder")
      .setDesc(
        "Where the \"Save Claude artifact\" commands create notes. Leave empty to use the vault root.",
      )
      .addText((text) =>
        text
          .setPlaceholder(DEFAULT_SETTINGS.artifactImportFolder)
          .setValue(this.plugin.settings.artifactImportFolder)
          .onChange(async (value) => {
            // Normalize on the way in as well as on load: this is the path that
            // reaches vault.create(), so an absolute path or a `..` segment
            // typed here must be rejected, not stored and rejected later.
            this.plugin.settings.artifactImportFolder = normalizeArtifactImportFolder(value);
            await this.plugin.saveSettings();
          }),
      );

    // ── Capabilities ────────────────────────────────────────────────────────
    // Placed after the everyday preferences and immediately before the sections
    // they gate: these four toggles are what add or remove "AI & automation"
    // below, so they read as the switchboard for what follows rather than as
    // more configuration competing with first-run setup at the top.
    this.renderCollapsibleSection(containerEl, "capabilities", "Optional modules", (body) => {
      this.renderOptionalModulesSection(body, true);
      this.renderSemanticDiscoverySection(body);
    });

    // ── Advanced (collapsed) ─────────────────────────────────────────────────
    // Security + Reliability + at-rest maintenance live behind one disclosure.
    this.renderCollapsibleSection(containerEl, "advanced", "Advanced", (body) => {
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

      // At-rest encryption used to be rendered here. It now lives in the
      // Protection section at the top of the tab, beside the exclusion rules
      // that govern the same layer — see `renderProtectionScopeSection`.
      // Advanced keeps only the tuning knobs: Security and Reliability.
    });

    // ── AI & automation (collapsed) ──────────────────────────────────────────
    // Agent bridge + AI chat live behind one disclosure. Both helpers keep
    // their own desktop gating and setHeading() labels.
    if (
      this.plugin.isOptionalModuleEnabled("aiChat") ||
      this.plugin.isOptionalModuleEnabled("agentAccess")
    ) {
      this.renderCollapsibleSection(
        containerEl,
        "ai-automation",
        "AI & automation",
        (body) => {
          if (this.plugin.isOptionalModuleEnabled("agentAccess")) {
            this.renderVaultOrientationSection(body);
            this.renderAgentBridgeSection(body);
          }
          // Governed automation is intentionally in-app-chat-only at runtime,
          // so its human policy controls remain available when AI Chat is on
          // even if external Agent Access is off. When Agent Bridge is enabled,
          // this stays directly beside its management section.
          this.renderGovernedAutomationSection(body);
          if (this.plugin.isOptionalModuleEnabled("agentAccess")) {
            this.renderChatGptConnectorSection(body);
          }
          if (this.plugin.isOptionalModuleEnabled("aiChat")) {
            this.renderAiChatSection(body);
          }
        },
      );
    }

    // ── Danger Zone (collapsed) ─────────────────────────────────────────────
    // Irreversible actions sit behind a disclosure so they cannot be hit while
    // scrolling past. The type-to-confirm gate on each action is unchanged —
    // this only stops the buttons sitting permanently open at the end of the
    // tab. Search still reaches them.
    this.renderCollapsibleSection(containerEl, "danger-zone", "Danger zone", (body) => {
      body.createEl("p", {
        text: "These actions cannot be undone.",
        cls: "setting-item-description mod-warning",
      });

      new Setting(body)
        .setName("Reset local sync state")
        .setDesc(
          "Clear cached permission, remote-file, queued offline, and sync-reconciliation state held by VaultGuard on this device. This does not delete vault files. Queued offline work that has not been reconciled will be discarded."
        )
        .addButton((button) =>
          button
            .setButtonText("Reset sync state")
            .setWarning()
            .onClick(async () => {
              const confirmed = await this.showDestructiveConfirmation(
                body,
                "RESET SYNC STATE",
                "Type RESET SYNC STATE to confirm. Vault files stay on disk, but cached permission, remote-file, queued offline, and sync-reconciliation state will be cleared."
              );
              if (confirmed) {
                try {
                  await this.plugin.clearLocalCache();
                  this.showStatus(
                    body,
                    "Local sync state reset. Vault files were not deleted.",
                    false,
                  );
                } catch {
                  this.showStatus(
                    body,
                    "Local sync state could not be reset. Queued offline work was retained; retry after checking disk access.",
                    true,
                  );
                }
              }
            })
        );
    });

    // The filter must run after every section exists, and again on each
    // re-render, or a toggle inside a filtered view would restore hidden rows.
    this.applySettingsFilter(containerEl);

    // After the filter, never before. `applySettingsFilter` hides rows and
    // force-opens disclosures, so it is the step that settles `scrollHeight`;
    // restoring earlier would clamp the offset against the wrong height.
    //
    // No clamping of our own: when the rebuilt tab is shorter than the old one
    // (turning Secure Discovery off drops a whole section) the browser clamps
    // to `scrollHeight - clientHeight` itself, and landing at the new bottom is
    // the right answer.
    if (previousScrollTop > 0) {
      this.containerEl.scrollTop = previousScrollTop;
    }
  }

  /**
   * Show a type-to-confirm dialog for destructive operations.
   * Returns true only if the user types the exact confirmation phrase.
   */
  /**
   * Asks for a whole number of days and confirms the extend.
   *
   * When the target's account is disabled the copy names that narrow state
   * explicitly rather than implying it is the ordinary post-expiry one, and
   * warns that a re-enabled account has to sign in again — the tokens revoked
   * at disable time are not resurrected.
   *
   * Resolves `null` on cancel.
   */
  private promptForGuestExtension(
    containerEl: HTMLElement,
    label: string,
    needsReactivateFirst: boolean
  ): Promise<number | null> {
    return new Promise((resolve) => {
      const existing = containerEl.querySelector(".vaultguard-guest-extend-prompt");
      if (existing) existing.remove();

      const dialog = containerEl.createDiv({ cls: "vaultguard-destruct-confirm vaultguard-guest-extend-prompt" });
      dialog.setAttribute("role", "dialog");
      dialog.setAttribute("aria-label", "Extend temporary access");
      const descriptionId = `vaultguard-guest-extend-${Date.now()}`;
      dialog.setAttribute("aria-describedby", descriptionId);
      dialog.createEl("p", {
        text: needsReactivateFirst
          ? `${label}'s account is disabled, but their access record for this vault still exists. ` +
            "Extending will first re-enable their organization account — consuming a seat — and then " +
            "move their expiry. They will have to sign in again."
          : `Extend ${label}'s temporary access by a whole number of days.`,
        cls: "setting-item-description",
        attr: { id: descriptionId },
      });

      const input = dialog.createEl("input", {
        cls: "vaultguard-confirm-input",
        attr: {
          type: "number",
          min: "1",
          max: "90",
          step: "1",
          value: "30",
          "aria-label": "Days to extend by",
        },
      });

      const btnRow = dialog.createDiv({ cls: "vaultguard-confirm-buttons" });
      const cancelBtn = btnRow.createEl("button", { text: "Cancel", attr: { type: "button" } });
      const confirmBtn = btnRow.createEl("button", {
        text: needsReactivateFirst ? "Re-enable and extend" : "Extend",
        cls: "mod-cta",
        attr: { type: "button" },
      });

      const finish = (value: number | null): void => {
        dialog.remove();
        resolve(value);
      };

      const submit = (): void => {
        const days = Number(input.value);
        // A local whole-day check only. The accepted range is the server's to
        // enforce, so a rejection there is reported rather than pre-empted.
        if (!Number.isInteger(days) || days < 1) {
          input.setAttribute("aria-invalid", "true");
          return;
        }
        finish(days);
      };

      cancelBtn.addEventListener("click", () => finish(null));
      confirmBtn.addEventListener("click", () => submit());
      dialog.addEventListener("keydown", (event) => {
        if (event.key === "Escape") {
          event.preventDefault();
          finish(null);
        } else if (event.key === "Enter") {
          event.preventDefault();
          submit();
        }
      });

      input.focus();
    });
  }

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
      dialog.setAttribute("role", "alertdialog");
      dialog.setAttribute("aria-label", "Confirm destructive action");
      const descriptionId = `vaultguard-destruct-confirm-${Date.now()}`;
      dialog.setAttribute("aria-describedby", descriptionId);
      dialog.createEl("p", {
        text: message,
        cls: "setting-item-description mod-warning",
        attr: { id: descriptionId },
      });

      const input = dialog.createEl("input", {
        cls: "vaultguard-confirm-input",
        attr: {
          type: "text",
          placeholder: confirmPhrase,
          "aria-label": `Type ${confirmPhrase} to confirm`,
        },
      });

      const btnRow = dialog.createDiv({ cls: "vaultguard-confirm-buttons" });
      const cancelBtn = btnRow.createEl("button", {
        text: "Cancel",
        attr: { type: "button" },
      });
      const confirmBtn = btnRow.createEl("button", {
        text: "Confirm",
        cls: "mod-warning",
        attr: { type: "button", disabled: "true" },
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

      dialog.addEventListener("keydown", (event) => {
        if (event.key === "Escape") {
          event.preventDefault();
          dialog.remove();
          resolve(false);
        } else if (event.key === "Enter" && input.value === confirmPhrase) {
          event.preventDefault();
          dialog.remove();
          resolve(true);
        }
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
  private renderVaultOrientationSection(containerEl: HTMLElement): void {
    new Setting(containerEl).setName("Vault orientation").setHeading();
    const summaryEl = containerEl.createDiv({ cls: "vaultguard-orientation-summary" });

    if (this.latestVaultOrientationSnapshot) {
      this.renderVaultOrientationSummary(summaryEl, this.latestVaultOrientationSnapshot);
    } else {
      summaryEl.createDiv({
        cls: "setting-item-description",
        text: "Loading orientation metadata...",
      });
    }

    const renderSnapshot = async (forceRefresh = false): Promise<VaultOrientationSnapshot | null> => {
      const requestGeneration = ++this.vaultOrientationRequestGeneration;
      try {
        const snapshot = await this.plugin.getVaultOrientationSnapshotForDiagnostics({
          includeKnownVaults: true,
          includeGit: true,
          forceRefresh,
        });
        if (
          requestGeneration !== this.vaultOrientationRequestGeneration ||
          summaryEl.isConnected === false
        ) {
          return null;
        }
        this.latestVaultOrientationSnapshot = snapshot;
        summaryEl.empty();
        this.renderVaultOrientationSummary(summaryEl, snapshot);
        return snapshot;
      } catch (error) {
        if (
          requestGeneration !== this.vaultOrientationRequestGeneration ||
          summaryEl.isConnected === false
        ) {
          return null;
        }
        summaryEl.empty();
        if (this.latestVaultOrientationSnapshot) {
          this.renderVaultOrientationSummary(summaryEl, this.latestVaultOrientationSnapshot);
        }
        const failureVerb = this.latestVaultOrientationSnapshot ? "refresh" : "load";
        summaryEl.createDiv({
          cls: "setting-item-description mod-warning",
          text: `Could not ${failureVerb} vault orientation: ${this.errorMessage(error)}`,
        });
        return null;
      }
    };

    void renderSnapshot(false);

    new Setting(containerEl)
      .setName("Orientation diagnostics")
      .setDesc(
        "Metadata only. Does not grant access and omits absolute paths, raw Git remotes, tokens, keys, and note contents.",
      )
      .addButton((button) =>
        button.setButtonText("Refresh").onClick(async () => {
          button.setDisabled(true).setButtonText("Refreshing...");
          await renderSnapshot(true);
          if (button.buttonEl.isConnected !== false) {
            button.setDisabled(false).setButtonText("Refresh");
          }
        }),
      )
      .addButton((button) =>
        button.setButtonText("Copy diagnostics").onClick(async () => {
          button.setDisabled(true).setButtonText("Copying...");
          const snapshot = await renderSnapshot(true);
          const copied = snapshot
            ? await this.writeClipboard(JSON.stringify(snapshot, null, 2))
            : false;
          if (button.buttonEl.isConnected === false) return;
          new Notice(copied ? "Vault orientation diagnostics copied." : "Could not copy diagnostics.");
          button.setDisabled(false).setButtonText("Copy diagnostics");
        }),
      );
  }

  private renderVaultOrientationSummary(parent: HTMLElement, snapshot: VaultOrientationSnapshot): void {
    const active = snapshot.activeVault;
    const git = active.git.detected
      ? `Git: detected${active.git.dirty === true ? ", dirty" : active.git.dirty === false ? ", clean" : ""}`
      : "Git: not detected";
    const rows = [
      `Active vault: ${active.displayName}`,
      `Vault kind: ${active.locationKind} / ${active.storageKind}`,
      `Protection: ${active.protection.localProjectMemoryMode ? "Local Project Memory Mode" : active.protection.encrypted ? "protected/encrypted" : "not encrypted"}`,
      git,
      `Connectors: Claude ${active.connectors.claude}, Codex ${active.connectors.codex}, GPT ${active.connectors.openaiChat}, ChatGPT ${active.connectors.chatgptRemote}`,
      `Write safety: ${active.safety.writeMode} - ${active.safety.reason}`,
    ];
    for (const row of rows) {
      parent.createDiv({ cls: "setting-item-description", text: row });
    }
    if (snapshot.knownVaults.length > 0) {
      parent.createDiv({
        cls: "setting-item-description",
        text: `Known vaults shown: ${snapshot.knownVaults.length} (bounded metadata only).`,
      });
    }
  }

  private renderChatGptConnectorSection(containerEl: HTMLElement): void {
    new Setting(containerEl).setName("ChatGPT connector / remote MCP (developer preview)").setHeading();

    if (this.plugin.isLocalProjectMemoryModeEnabled()) {
      containerEl.createEl("p", {
        cls: "vaultguard-settings-note",
        text:
          "ChatGPT connector sessions are disabled in Local Project Memory Mode. Repo-root project-memory vaults must stay local and plaintext for coding workflows.",
      });
      return;
    }

    if (Platform.isMobileApp) {
      containerEl.createEl("p", {
        cls: "vaultguard-settings-note",
        text:
          "ChatGPT connector is desktop-only. It needs the local VaultGuard MCP server and an HTTPS/Secure MCP Tunnel path that mobile Obsidian cannot host.",
      });
      return;
    }

    containerEl.createEl("p", {
      cls: "vaultguard-settings-note",
      text:
        "Developer preview only. This exposes selected read-only VaultGuard tools to ChatGPT through an HTTPS or Secure MCP Tunnel endpoint. Anything returned by a tool can leave this device and be processed by OpenAI. Use narrow scopes, short sessions, and revoke sessions when finished. Never paste Agent Bridge lease tokens, recovery keys, local access keys, OpenAI API keys, or vault secrets into ChatGPT.",
    });

    const description = this.plugin.describeChatGptConnector();
    const sessions = description.sessions;
    const canCreate = Boolean(this.plugin.getSession() && this.plugin.settings.serverVaultId);

    new Setting(containerEl)
      .setName("Connector actions")
      .setDesc(
        canCreate
          ? "Create a short-lived read-only connector session for Secure MCP Tunnel testing, or revoke current connector sessions."
          : "Log in and bind this Obsidian folder to a server vault before creating connector sessions.",
      )
      .addButton((button) =>
        button
          .setButtonText("Create read-only session")
          .setCta()
          .setDisabled(!canCreate)
          .onClick(async () => this.createChatGptConnectorSession(button)),
      )
      .addButton((button) =>
        button
          .setButtonText("Revoke all connector sessions")
          .setWarning()
          .setDisabled(sessions.length === 0)
          .onClick(async () => {
            button.setDisabled(true).setButtonText("Revoking...");
            try {
              const revoked = this.plugin.revokeAllChatGptConnectorSessions();
              this.latestChatGptConnectorReveal = null;
              new Notice(`VaultGuard Sync: revoked ${revoked} ChatGPT connector session${revoked === 1 ? "" : "s"}.`);
              this.display();
            } catch (error) {
              new Notice(
                `VaultGuard Sync: could not revoke ChatGPT connector sessions - ${this.errorMessage(error)}`,
                8000,
              );
              button.setDisabled(false).setButtonText("Revoke all connector sessions");
            }
          }),
      );

    if (description.server) {
      const serverInfo = containerEl.createDiv({ cls: "vaultguard-agent-bridge-server" });
      serverInfo.createEl("strong", { text: "Connector server: " });
      serverInfo.appendText(`${description.server.mcpEndpoint} (metadata at ${description.server.metadataEndpoint})`);
    }

    this.renderLatestChatGptConnectorReveal(containerEl);

    new Setting(containerEl).setName("Active ChatGPT connector sessions").setHeading();
    if (sessions.length === 0) {
      containerEl.createDiv({
        // `vaultguard-settings-inset` keeps standalone blocks on the tab's
        // single left content edge; a bare `setting-item-description` is only
        // inset when it sits inside a `.setting-item`.
        cls: "setting-item-description vaultguard-settings-inset",
        text: "No active ChatGPT connector sessions.",
      });
      return;
    }

    for (const session of sessions) {
      this.renderChatGptConnectorSessionRow(containerEl, session);
    }
  }

  private renderGovernedAutomationSection(containerEl: HTMLElement): void {
    new Setting(containerEl).setName("Governed automation (desktop only.)").setHeading();

    const desktopUnavailable = Platform.isDesktopApp !== true;
    const registry = normalizeAutomationRegistry(this.plugin.settings.automationRegistry);
    const activePolicyCount = registry.entries.filter((entry) => entry.enabled).length;
    containerEl.createEl("p", {
      cls: "vaultguard-settings-note mod-warning",
      text:
        "Governance is not a sandbox. An approved third-party command runs with that plugin's ordinary Obsidian authority. VaultGuard keeps this master switch off by default, exposes only semantic aliases to agents, always confirms side effects, and refuses hard-denied command classes.",
    });

    if (desktopUnavailable) {
      containerEl.createEl("p", {
        cls: "vaultguard-settings-note",
        text:
          "Governed command automation is unavailable on mobile or runtimes without the required desktop command APIs. Manage this registry from desktop Obsidian.",
      });
    }

    new Setting(containerEl)
      .setName("Enable governed automation")
      .setDesc(
        `Master switch only. ${activePolicyCount} ${activePolicyCount === 1 ? "policy is" : "policies are"} individually enabled. Turning this on never enables a disabled or invalid policy, and automation remains limited to eligible in-app chat sessions.`,
      )
      .addToggle((toggle) =>
        toggle
          .setValue(registry.enabled)
          .setDisabled(desktopUnavailable)
          .onChange(async (value) => {
            if (desktopUnavailable) return;
            const previous = this.plugin.settings.automationRegistry;
            this.plugin.settings.automationRegistry = {
              ...normalizeAutomationRegistry(previous),
              enabled: value,
            };
            try {
              await this.plugin.saveSettings();
              this.showStatus(
                containerEl,
                value
                  ? "Governed automation master switch enabled. Only separately enabled, runtime-eligible policies can run."
                  : "Governed automation disabled. Approved policies remain stored but cannot run.",
                false,
              );
            } catch {
              this.plugin.settings.automationRegistry = previous;
              toggle.setValue(previous.enabled);
              this.showStatus(
                containerEl,
                "The governed automation setting could not be saved.",
                true,
              );
            }
          }),
      );

    let policyDraft = JSON.stringify(registry.entries, null, 2);
    let policyTextArea: { setValue(value: string): unknown } | null = null;
    const policySetting = new Setting(containerEl)
      .setName("Approved automation policies (JSON)")
      .setDesc(
        "Human-only canonical policy array. Raw command IDs and private path rules stay in Settings and are never disclosed to agents. Drafts do not save while you type; JSON cannot change the master switch, and the entire import is rejected if any entry is invalid, duplicate, unsafe, or noncanonical.",
      )
      .addTextArea((textArea) => {
        policyTextArea = textArea;
        textArea.inputEl.rows = 14;
        textArea.inputEl.spellcheck = false;
        textArea.inputEl.addClass("vaultguard-mono-textarea");
        textArea
          .setPlaceholder("[]")
          .setValue(policyDraft)
          .setDisabled(desktopUnavailable)
          .onChange((value) => {
            policyDraft = value;
          });
      });
    policySetting.settingEl.addClass("vaultguard-stacked-textarea-setting");

    new Setting(containerEl)
      .setName("Import policy draft")
      .setDesc(
        "Validates every entry as one transaction. Use [] to clear all policies; the master switch keeps its current state.",
      )
      .addButton((button) =>
        button
          .setButtonText("Validate and import policies")
          .setCta()
          .setDisabled(desktopUnavailable)
          .onClick(async () => {
            const result = parseAutomationPolicyJsonImport(
              policyDraft,
              this.plugin.settings.automationRegistry.enabled,
            );
            if (!result.ok) {
              this.showStatus(containerEl, result.error, true);
              return;
            }
            const previous = this.plugin.settings.automationRegistry;
            button.setDisabled(true).setButtonText("Importing...");
            try {
              this.plugin.settings.automationRegistry = result.registry;
              await this.plugin.saveSettings();
              policyDraft = JSON.stringify(
                this.plugin.settings.automationRegistry.entries,
                null,
                2,
              );
              policyTextArea?.setValue(policyDraft);
              this.showStatus(
                containerEl,
                `${result.registry.entries.length} governed automation ${result.registry.entries.length === 1 ? "policy" : "policies"} imported. The master switch was not changed.`,
                false,
              );
            } catch {
              this.plugin.settings.automationRegistry = previous;
              this.showStatus(
                containerEl,
                "The governed automation policies could not be saved.",
                true,
              );
            } finally {
              button
                .setDisabled(desktopUnavailable)
                .setButtonText("Validate and import policies");
            }
          }),
      );

    let templateDraft = (this.plugin.settings.agentTemplateAllowlist ?? []).join("\n");
    let templateTextArea: { setValue(value: string): unknown } | null = null;
    const templateSetting = new Setting(containerEl)
      .setName("Trusted agent templates")
      .setDesc(
        "One exact vault-relative .md template path per line. Empty means no template is trusted. Hidden paths, absolute paths, traversal, patterns, duplicates, and non-Markdown files are rejected as one transaction.",
      )
      .addTextArea((textArea) => {
        templateTextArea = textArea;
        textArea.inputEl.rows = 6;
        textArea.inputEl.spellcheck = false;
        textArea.inputEl.addClass("vaultguard-mono-textarea");
        textArea
          .setPlaceholder("Templates/Daily note.md")
          .setValue(templateDraft)
          .setDisabled(desktopUnavailable)
          .onChange((value) => {
            templateDraft = value;
          });
      });
    templateSetting.settingEl.addClass("vaultguard-stacked-textarea-setting");

    new Setting(containerEl)
      .setName("Save trusted templates")
      .setDesc("Validates the complete allowlist before replacing the stored paths.")
      .addButton((button) =>
        button
          .setButtonText("Validate and save templates")
          .setCta()
          .setDisabled(desktopUnavailable)
          .onClick(async () => {
            const result = parseAgentTemplateAllowlistImport(templateDraft);
            if (!result.ok) {
              this.showStatus(containerEl, result.error, true);
              return;
            }
            const previous = this.plugin.settings.agentTemplateAllowlist;
            button.setDisabled(true).setButtonText("Saving...");
            try {
              this.plugin.settings.agentTemplateAllowlist = result.paths;
              await this.plugin.saveSettings();
              templateDraft = this.plugin.settings.agentTemplateAllowlist.join("\n");
              templateTextArea?.setValue(templateDraft);
              this.showStatus(
                containerEl,
                `${result.paths.length} trusted agent template ${result.paths.length === 1 ? "path" : "paths"} saved.`,
                false,
              );
            } catch {
              this.plugin.settings.agentTemplateAllowlist = previous;
              this.showStatus(containerEl, "The trusted template paths could not be saved.", true);
            } finally {
              button
                .setDisabled(desktopUnavailable)
                .setButtonText("Validate and save templates");
            }
          }),
      );
  }

  private renderAgentBridgeSection(containerEl: HTMLElement): void {
    new Setting(containerEl).setName("Agent bridge connections (desktop only.)").setHeading();

    const localProjectMemoryMode = this.plugin.isLocalProjectMemoryModeEnabled();
    if (localProjectMemoryMode) {
      containerEl.createEl("p", {
        cls: "vaultguard-settings-note",
        text:
          "Local Project Memory Mode allows explicitly authorized localhost MCP connections after VaultGuard sign-in. Leases are time-limited, kept only in memory, revoked with the login session or plugin, and cannot use the generic RPC or remote ChatGPT connector surfaces.",
      });
    }

    // Agent bridge needs a local HTTP server (Node `http` module). That's
    // only reachable in desktop Obsidian's renderer. On mobile we surface
    // the limitation up-front instead of letting the user click "Create
    // bridge lease" and see a confusing failure later.
    if (Platform.isMobileApp) {
      containerEl.createEl("p", {
        cls: "vaultguard-settings-note",
        text:
          "Agent bridge is desktop-only. It exposes VaultGuard Sync's tools to local MCP clients (Codex, Claudian, Claude Code, Cursor) via a localhost HTTP server, which Obsidian mobile renderers can't host. Manage agent leases from a desktop install of this same vault.",
      });
      return;
    }

    containerEl.createEl("p", {
      cls: "vaultguard-settings-note",
      text:
        localProjectMemoryMode
          ? "Create a scoped bearer lease for a local MCP client such as Codex, Claudian, Claude Code, or Cursor. The bridge remains on 127.0.0.1 and keeps the existing scope, write-confirmation, hidden-path, and audit gates. A server vault binding is not required."
          : "Agent bridge leases let an external agent (Codex, Claudian, Claude Code, Cursor, custom MCP client) talk to this vault through VaultGuard Sync tools. Each lease has its own bearer token; revoking or rotating one does not disturb the others. Hidden paths (.obsidian, .trash, .git, ...) are always blocked.",
    });

    const surface = this.plugin.getAgentBridge();
    const description = surface.describe();
    const activeLeases = description.activeLeases;
    const server = description.server;
    const canCreate = Boolean(
      this.plugin.getSession() &&
        (localProjectMemoryMode || this.plugin.settings.serverVaultId)
    );

    new Setting(containerEl)
      .setName("Bridge lease actions")
      .setDesc(
        canCreate
          ? "Create a new scoped bridge lease, or revoke every current bridge lease for this vault."
          : localProjectMemoryMode
            ? "Log in to VaultGuard before creating a local MCP bridge lease."
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
    this.renderAgentBridgeCodexSkillRow(containerEl);

    new Setting(containerEl).setName("Current leases").setHeading();

    if (activeLeases.length === 0) {
      const empty = containerEl.createDiv({
        cls: "setting-item-description vaultguard-settings-inset",
      });
      empty.appendText(
        "No active bridge leases. Create one here or from the command palette when you want to connect an agent."
      );
      return;
    }

    for (const lease of activeLeases) {
      this.renderAgentBridgeLeaseRow(containerEl, lease);
    }
  }

  private async createChatGptConnectorSession(button: ButtonComponent): Promise<void> {
    button.setDisabled(true).setButtonText("Creating...");
    try {
      const session: ChatGptConnectorSessionSecret = await this.plugin.createChatGptConnectorSession({
        agentName: "ChatGPT connector",
        scope: "/**",
        ttlMinutes: 30,
        tunnelMode: "secure-mcp-tunnel",
      });
      this.latestChatGptConnectorReveal = {
        sessionId: session.sessionId,
        setupInstructions: session.setupInstructions,
        copiedToClipboard: false,
      };
      new Notice("VaultGuard Sync: ChatGPT connector read-only session created.");
      this.display();
    } catch (error) {
      new Notice(
        `VaultGuard Sync: could not create ChatGPT connector session - ${this.errorMessage(error)}`,
        8000,
      );
      button.setDisabled(false).setButtonText("Create read-only session");
    }
  }

  private renderLatestChatGptConnectorReveal(containerEl: HTMLElement): void {
    const reveal = this.latestChatGptConnectorReveal;
    if (!reveal) return;
    const block = containerEl.createDiv({ cls: "vaultguard-agent-bridge-reveal" });
    block.createEl("strong", { text: "ChatGPT connector setup copied from the latest session" });
    block.createEl("p", {
      cls: "setting-item-description",
      text:
        "This setup block includes the short-lived connector access token. Copy it only into trusted developer tooling or the Secure MCP Tunnel setup flow. It is not an Agent Bridge lease token.",
    });
    this.renderAgentBridgeCopyBlock(block, {
      title: "ChatGPT connector setup",
      body: reveal.setupInstructions,
      copyLabel: "Copy connector setup",
    });
  }

  private renderChatGptConnectorSessionRow(
    containerEl: HTMLElement,
    session: ChatGptConnectorSessionSummary,
  ): void {
    const block = containerEl.createDiv({ cls: "vaultguard-agent-bridge-lease" });
    block.addClass("is-ephemeral");
    block.createEl("strong", { text: session.agentName });
    const details = block.createDiv({ cls: "vaultguard-agent-bridge-lease-details" });
    this.addAgentBridgeLeaseDetail(details, "Session ID", session.sessionId);
    this.addAgentBridgeLeaseDetail(details, "Profile", session.profile);
    this.addAgentBridgeLeaseDetail(details, "Scope", session.pathScopes.join(", "));
    this.addAgentBridgeLeaseDetail(details, "OAuth scopes", session.oauthScopes.join(", "));
    this.addAgentBridgeLeaseDetail(details, "Token ID", session.tokenId);
    this.addAgentBridgeLeaseDetail(details, "Created", this.formatDateTime(session.createdAt));
    this.addAgentBridgeLeaseDetail(details, "Expires", this.formatDateTime(session.expiresAt));
    this.addAgentBridgeLeaseDetail(
      details,
      "Limits",
      `${session.limits.maxListFiles} files, ${session.limits.maxSearchResults} search hits, ${this.formatBytes(session.limits.maxReadBytes)} reads`,
    );

    const actions = block.createDiv({ cls: "vaultguard-agent-bridge-inline-actions" });
    const revokeBtn = new ButtonComponent(actions);
    revokeBtn
      .setButtonText("Revoke session")
      .setWarning()
      .onClick(async () => {
        revokeBtn.setDisabled(true).setButtonText("Revoking...");
        try {
          const revoked = this.plugin.revokeChatGptConnectorSession(session.sessionId);
          if (this.latestChatGptConnectorReveal?.sessionId === session.sessionId) {
            this.latestChatGptConnectorReveal = null;
          }
          new Notice(
            revoked
              ? "VaultGuard Sync: ChatGPT connector session revoked."
              : "VaultGuard Sync: ChatGPT connector session was already gone.",
          );
          this.display();
        } catch (error) {
          new Notice(
            `VaultGuard Sync: could not revoke ChatGPT connector session - ${this.errorMessage(error)}`,
            8000,
          );
          revokeBtn.setDisabled(false).setButtonText("Revoke session");
        }
      });
  }

  private renderAgentBridgeServerState(
    containerEl: HTMLElement,
    server: AgentBridgeServerInfo | null,
    activeLeaseCount: number
  ): void {
    if (server) {
      const serverInfo = containerEl.createDiv({ cls: "vaultguard-agent-bridge-server" });
      serverInfo.createEl("strong", { text: "Bridge server: " });
      const localProjectMemoryMode = this.plugin.isLocalProjectMemoryModeEnabled();
      serverInfo.appendText(
        localProjectMemoryMode
          ? `${server.mcpEndpoint} (localhost MCP only)`
          : `${server.endpoint} (MCP at ${server.mcpEndpoint})`
      );

      const buttons = serverInfo.createDiv({ cls: "vaultguard-agent-bridge-inline-actions" });
      if (!localProjectMemoryMode) {
        const copyRpc = new ButtonComponent(buttons);
        copyRpc.setButtonText("Copy RPC URL").onClick(async () => {
          const copied = await this.writeClipboard(server.endpoint);
          new Notice(copied ? "Bridge RPC URL copied." : "Could not copy the bridge RPC URL.");
        });
      }

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

    const idleInfo = containerEl.createDiv({
      cls: "setting-item-description vaultguard-settings-inset",
    });
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

  private renderAgentBridgeCodexSkillRow(containerEl: HTMLElement): void {
    const status = this.plugin.getAgentBridgeCodexSkillStatus();

    if (!status.available) {
      new Setting(containerEl)
        .setName("Codex skill")
        .setDesc(
          "Not available on this device - installing the skill needs Node filesystem access (desktop Obsidian only)."
        );
      return;
    }

    const setting = new Setting(containerEl)
      .setName("Codex skill")
      .setDesc(this.codexSkillStatusDescription(status));

    if (!status.codexSkillsAvailable) {
      setting.addButton((button) =>
        button
          .setButtonText("Install anyway")
          .setWarning()
          .onClick(async () => this.runCodexSkillInstall(button, { force: true }))
      );
      return;
    }

    if (status.managedConflict) {
      setting.addButton((button) =>
        button
          .setButtonText("Overwrite existing SKILL.md")
          .setWarning()
          .onClick(async () => this.runCodexSkillInstall(button, { overwriteUnmanaged: true }))
      );
      return;
    }

    if (!status.installed) {
      setting.addButton((button) =>
        button
          .setButtonText("Install skill")
          .setCta()
          .onClick(async () => this.runCodexSkillInstall(button))
      );
      return;
    }

    setting
      .addButton((button) =>
        button
          .setButtonText("Update / re-install")
          .onClick(async () => this.runCodexSkillInstall(button))
      )
      .addButton((button) =>
        button
          .setButtonText("Uninstall")
          .setWarning()
          .onClick(async () => this.runCodexSkillUninstall(button))
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

  private codexSkillStatusDescription(
    status: CodexSkillInstallStatus & { available: true }
  ): string {
    if (!status.codexSkillsAvailable) {
      return `Codex skills directory was not found (no ~/.agents/skills/ directory). The skill would land at ${status.skillFilePath} if you install it anyway.`;
    }
    if (status.managedConflict) {
      return `A SKILL.md exists at ${status.skillFilePath} but was not installed by VaultGuard Sync. Overwriting will replace it. Cancel and inspect the file if you did not expect this.`;
    }
    if (status.installed) {
      return `Installed at ${status.skillFilePath}. The skill teaches Codex to use VaultGuard Sync's MCP tools instead of raw filesystem reads against protected vault content. Re-install to pull the latest skill body.`;
    }
    return `Writes a SKILL.md to ${status.skillFilePath}. Tells Codex to use the VaultGuard MCP bridge for protected Obsidian vault content and avoid raw filesystem access. Contains no tokens or per-user state.`;
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

  private async runCodexSkillInstall(
    button: ButtonComponent,
    options: { overwriteUnmanaged?: boolean; force?: boolean } = {}
  ): Promise<void> {
    const original = button.buttonEl.textContent ?? "Install skill";
    button.setDisabled(true).setButtonText("Installing...");
    try {
      const result = await this.plugin.installAgentBridgeCodexSkill(options);
      const verb =
        result.action === "noop"
          ? "already current"
          : result.action === "created"
            ? "installed"
            : result.action === "overwrote-conflict"
              ? "overwrote existing file"
              : "updated";
      new Notice(`VaultGuard Sync: Codex skill ${verb} at ${result.filePath}.`, 6000);
      this.display();
    } catch (error) {
      new Notice(
        `VaultGuard Sync: could not install Codex skill - ${this.errorMessage(error)}`,
        8000
      );
      button.setDisabled(false).setButtonText(original);
    }
  }

  private async runCodexSkillUninstall(button: ButtonComponent): Promise<void> {
    button.setDisabled(true).setButtonText("Removing...");
    try {
      const result = await this.plugin.uninstallAgentBridgeCodexSkill();
      if (result.removed) {
        new Notice(`VaultGuard Sync: Codex skill removed from ${result.filePath}.`, 6000);
      } else {
        new Notice("VaultGuard Sync: no managed Codex skill file to remove.", 4000);
      }
      this.display();
    } catch (error) {
      new Notice(
        `VaultGuard Sync: could not uninstall Codex skill - ${this.errorMessage(error)}`,
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
        ? "The rotated MCP config was copied. Codex snippets are also shown here until this settings panel refreshes again."
        : "The token was rotated, but clipboard copy was unavailable. Copy the needed snippets below before leaving this settings panel.",
    });

    this.renderAgentBridgeCopyBlock(block, {
      title: "MCP server config",
      body: reveal.mcpConfig,
      copyLabel: "Copy MCP config",
    });
    if (!this.plugin.isLocalProjectMemoryModeEnabled()) {
      this.renderAgentBridgeCopyBlock(block, {
        title: "Generic HTTP-RPC connection",
        body: reveal.connectionJson,
        copyLabel: "Copy connection JSON",
      });
    }
    this.renderAgentBridgeCopyBlock(block, {
      title: "Codex config.toml",
      body: reveal.codexConfig,
      copyLabel: "Copy Codex config",
    });
    this.renderAgentBridgeCopyBlock(block, {
      title: "Codex token environment command",
      body: reveal.codexTokenCommand,
      copyLabel: "Copy token command",
    });
    this.renderAgentBridgeCopyBlock(block, {
      title: "Codex empty workspace launch",
      body: reveal.codexLaunchCommand,
      copyLabel: "Copy launch command",
    });
    this.renderAgentBridgeCopyBlock(block, {
      title: "Codex AGENTS.md guidance",
      body: reveal.codexAgentsGuidance,
      copyLabel: "Copy AGENTS guidance",
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
      const codexConfig = buildCodexConfigToml({ mcpEndpoint: server.mcpEndpoint });
      const codexTokenCommand = buildCodexTokenEnvCommand(refreshed.token);
      const codexLaunchCommand = buildCodexTempWorkspaceLaunchCommand(refreshed.token);
      const codexAgentsGuidance = buildCodexAgentsGuidance();
      const copiedToClipboard = await this.writeClipboard(mcpConfig);

      this.latestAgentBridgeReveal = {
        leaseId: refreshed.leaseId,
        agentName: refreshed.agentName,
        connectionJson,
        mcpConfig,
        codexConfig,
        codexTokenCommand,
        codexLaunchCommand,
        codexAgentsGuidance,
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
