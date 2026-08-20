/**
 * @fileoverview Main plugin class for VaultGuard.
 * Implements permission-aware encrypted cloud sync by intercepting Obsidian's
 * vault adapter operations and routing them through an AWS backend that
 * enforces per-file permissions, end-to-end encryption, and audit logging.
 *
 * Architecture:
 * - Vault adapter interception: read/write/list/delete operations are wrapped
 *   with permission checks and encryption/decryption.
 * - Sync engine: Periodic bidirectional sync with conflict detection.
 * - Key lease system: Encryption keys are time-limited and require renewal.
 * - Offline support: Graceful degradation with cached keys and queued changes.
 */

import { Modal, Notice, Plugin, Platform, TFile, TFolder, Menu, normalizePath, requestUrl, RequestUrlResponse, requireApiVersion } from "obsidian";
import { VaultGuardSettingTab, DEFAULT_SETTINGS, SAAS_DEFAULTS } from "./settings";
import { LoginModal, LoginCredentials } from "./login-modal";
import { completePluginHumanVerification } from "./auth-human-verification";
import type { ConversationStore } from "../ui/chat/conversation-store";
import { BindingReconciliationModal, ReconciliationDecision, ReconciliationPlan } from "./binding-reconciliation-modal";
// Type-only: the modal itself is imported lazily at the one point of use, so a
// startup that never hits an account change never pays for it.
import type { AccountSwitchDiscardDecision } from "./account-switch-discard-modal";
import { ShareManagementModal } from "./share-management-modal";
import { PluginAllowlistModal, PluginAllowlistPrompt } from "./plugin-allowlist-modal";
import { cognitoLogin, cognitoRespondToChallenge, cognitoRefresh, cognitoRevokeToken, cognitoAssociateSoftwareToken, cognitoVerifySoftwareToken, vaultguardForgotPassword, vaultguardConfirmReset, vaultguardVerifyRecoveryCode, devServerLogin, isLocalDevAuth, CognitoAuthResult } from "./cognito-auth";
import { MfaSetupModal } from "./mfa-setup-modal";
import { deriveConnectionConfigFromTokenPayload } from "./session-config";
import { AuthorizationError, VaultGuardApiClient } from "../api/client";
import type {
  ExtendGuestAccessResult,
  OrgSettingsResponse,
  PermissionRule,
  UserListEntry,
  VaultKind,
  VaultMemberRecord,
  VaultMemberRole,
  VaultRecord,
} from "../api/client";
import {
  looksLikeAwsSignatureError,
  normalizeVaultGuardApiBaseUrl,
  resolveVaultGuardApiBaseUrl,
} from "../api/endpoint-resolver";
import { FilePermissionHeader } from "../ui/file-permission-header";
import { ReadOnlyGuard } from "./readonly-guard";
import { PermissionStore } from "./permission-store";
import { UpdateChecker } from "./update-checker";
import { SyncDiagnostics } from "./sync-diagnostics";
import type { AtRestCipher, AtRestRestoreOutcome } from "../crypto/at-rest-cipher";
import {
  PinLockManager,
  type PinLockStorage,
} from "../crypto/pin-lock-manager";
import { probeSafeStorage } from "../crypto/safe-storage";
import { LockCurtain, type LockCurtainController } from "../ui/lock/lock-curtain";
import { PinOnboardingPromptModal, SetPinModal } from "../ui/lock/pin-modals";
import {
  createAtRestAdapterRuntime,
  type AtRestDecryptAndDisableResult,
  type AtRestAdapterRuntime,
  type GitRepositoryDetectionResult,
  type GitRepositoryPlaintextTransitionResult,
} from "./at-rest-adapter-runtime";
import { AtRestRecoveryCodeModal, AtRestRestoreModal } from "./at-rest-modals";
import { AtRestRecoveryModal } from "../ui/at-rest-recovery-modal";
import { isKnownBinaryExtensionPath } from "./binary-content";
import {
  LOCAL_PROJECT_MEMORY_MODE_NOTICE,
  decideAutomaticLocalProjectMemoryMode,
  isLocalProjectMemoryModeEnabled,
  readAutomaticLocalProjectMemoryModePreference,
  writeAutomaticLocalProjectMemoryModePreference,
  type AutomaticLocalProjectMemoryModeDecision,
} from "./local-project-memory-mode";
import {
  readDetectGitRepoFolderPreference,
  writeDetectGitRepoFolderPreference,
} from "./git-repository-plaintext";
import { PathPermissionsModal } from "../ui/path-permissions-modal";
import { FileExplorerDecorations } from "../ui/file-explorer-decorations";
import { VaultGuardSidebarView, VAULTGUARD_VIEW_TYPE } from "../ui/vaultguard-sidebar-view";
import { createI18n } from "../i18n";
import {
  VAULTGUARD_CHAT_VIEW_TYPE,
  VAULTGUARD_DISCOVERY_VIEW_TYPE,
  VAULTGUARD_GRAPH_VIEW_TYPE,
} from "../ui/view-types";
import { RecoveryCenterModal, type RecoveryCenterTab } from "../ui/recovery-center-modal";
import { registerChatDebugCommand } from "../ui/chat/chat-debug-command";
import {
  type PermissionsGraphDataSource,
  type PermissionsGraphDataset,
} from "../ui/graph/permissions-graph-view";
import { findClaudeBinary } from "../ui/chat/claude-cli/claude-detector";
import { findCodexBinary } from "../ui/chat/codex-cli/codex-detector";
import {
  IN_APP_CHAT_CAPABILITY,
  type InAppChatCapability,
} from "../ui/chat/in-app-chat-capability";
import { ApiKeySync } from "../ui/chat/api-key-sync";
import type {
  VaultGuardSidebarAuthState,
  VaultGuardSidebarViewConfig,
} from "../ui/vaultguard-sidebar-view";
import type {
  AgentBridgeLeaseInput,
  AgentBridgeLeaseSecret,
  AgentBridgeServerInfo,
  AgentBridgeToolSurface,
  ChatGptConnectorDescription,
  ChatGptConnectorSessionInput,
  ChatGptConnectorSessionSecret,
} from "./agent-bridge";
import {
  createAgentBridgeRuntime,
  type AgentBridgeRuntime,
} from "./agent-bridge-wiring";
import { resolveAgentPermission } from "./agent-permission";
import type { MentionAccessContext } from "../ui/chat/mention-candidates";
import type {
  InstallResult,
  SkillInstallStatus,
} from "./agent-bridge-skill/installer";
import type {
  CodexInstallResult,
  CodexSkillInstallStatus,
} from "./agent-bridge-codex-skill/installer";
import { collectAttachmentPreviewData, registerVaultGuardCommands } from "./commands";
import { redactSecretString, stringifyForLog } from "./log-redaction";
import {
  registerFocusSyncHandlers as registerFocusSyncHandlersLifecycle,
  registerFolderLifecycleListeners as registerFolderLifecycleListenersLifecycle,
  registerInviteProtocolHandler as registerInviteProtocolHandlerLifecycle,
  registerObsidianSyncListener as registerObsidianSyncListenerLifecycle,
  registerObsidianSyncWarning,
  registerSessionActivityTracking as registerSessionActivityTrackingLifecycle,
  registerShareProtocolHandler as registerShareProtocolHandlerLifecycle,
  registerSidebarPermissionLifecycle,
  renderObsidianSyncNotice as renderObsidianSyncNoticeLifecycle,
} from "./lifecycle-events";
import {
  createPermissionStore,
  initFileExplorerDecorations as initFileExplorerDecorationsWiring,
  initFilePermissionHeader as initFilePermissionHeaderWiring,
  initReadOnlyGuard as initReadOnlyGuardWiring,
} from "./permission-wiring";
import {
  createPermissionsGraphRuntime,
  type PermissionsGraphRuntime,
} from "./permissions-graph-wiring";
import {
  VAULTGUARD_CHAT_ICON_ID,
  type AtRestAdapterRuntimeContext,
  type AgentBridgeRuntimeContext,
  type LifecycleEventsContext,
  type LocalManifestEntry,
  type MutationIntent,
  type PermissionStoreFactoryContext,
  type PermissionSurfaceContext,
  type ProtectedContentGate,
  type PermissionsGraphRuntimeContext,
  type SyncRuntimeContext,
  type VaultAdapterOriginalMethods,
  type OfflineQueueOperation,
  type PluginSettingsRuntimeContext,
  type RemoteWriteConflictResolutionResult,
  type VaultGuardCommandContext,
  type AttachmentPreviewReport,
  type VaultGuardRibbonContext,
  type VaultGuardSidebarActivationContext,
  type VaultGuardViewRegistrationContext,
} from "./plugin-runtime-types";
import {
  createPluginSettingsRuntime,
  type PluginSettingsRuntime,
} from "./settings-runtime";
import {
  didConnectionBoundaryChange,
  didExternallyLoadedSettingsChange,
  snapshotConnectionBoundary,
} from "./external-settings";
import {
  createSyncRuntime,
  type SyncRuntime,
} from "./sync-runtime";
import {
  LOCAL_RECOVERY_MANIFEST_PATH,
  LOCAL_RECOVERY_ROOT,
  LocalRecoveryCapsuleStore,
  type LocalRecoveryDeviceState,
  type LocalRecoveryRestoreResult,
} from "./local-recovery-capsule";
import {
  RemoteFileStateStore,
  type RemoteFileStateEntry,
  type RemoteFileStateUpdate,
} from "./remote-file-state";
import {
  LongOperationManager,
  type LongOperationHandle,
  type LongOperationStartOptions,
} from "./long-operation";
import {
  acquireResetLease,
  clearAllWipedPaths,
  clearWipedPath,
  deriveWipeSuppressionVaultKey,
  heartbeatResetLease,
  isPathWipeSuppressed,
  recordWipedPath,
  releaseResetLease,
} from "./wipe-suppression-registry";
import {
  LongOperationUiController,
  renderLongOperationStatusBar,
} from "../ui/long-operation-progress";
import {
  settleCleanupTasks,
  type NamedCleanupTask,
} from "./lifecycle-cleanup";
import {
  VaultOrientationService,
  type ConnectorStatusMatrix,
  type VaultOrientationSnapshot,
  diagnosticsConnectorContext,
} from "./vault-orientation";
import {
  activatePermissionsGraph as activatePermissionsGraphView,
  activateVaultGuardChat as activateVaultGuardChatView,
  activateVaultGuardSidebar as activateVaultGuardSidebarView,
  copyVaultGuardChatDomDebugReport as copyVaultGuardChatDomDebugReportView,
  ensureVaultGuardSidebar as ensureVaultGuardSidebarView,
  openNewVaultGuardChatTab as openNewVaultGuardChatTabView,
  openVaultGuardChatHistory as openVaultGuardChatHistoryView,
  registerVaultGuardRibbons,
  registerVaultGuardViews,
  reloadVaultGuardSidebar as reloadVaultGuardSidebarView,
} from "./views";
import {
  VaultGuardSettings,
  ServerEdition,
  ServerFeatures,
  ASSUMED_SERVER_FEATURES,
  UserSession,
  KeyLease,
  SyncState,
  ConnectionState,
  ConnectionStatus,
  PermissionLevel,
  FileMetadata,
  AuditAction,
  SyncConflict,
  ConflictResolutionStrategy,
  ApiResponse,
  PendingLargeFileRecord,
  OptionalModuleId,
  type StatusBarMode,
} from "../types";

export { VAULTGUARD_CHAT_ICON_ID };

function getActiveObsidianDocument(): Document | null {
  if (typeof activeDocument !== "undefined") {
    return activeDocument;
  }
  return null;
}

/**
 * The Notice's own message element — the element Obsidian created in the MAIN
 * window's realm. Building notice content directly into it is what makes a
 * notice realm-safe: Obsidian's `Element.prototype.setText` only appends a
 * message that passes `instanceof DocumentFragment || instanceof Node` against
 * the MAIN window's globals, so a fragment built from a popped-out window's own
 * document (a separate JS realm) silently stringifies to the literal
 * "[object DocumentFragment]". Writing into `messageEl` removes the realm
 * question entirely rather than papering over it.
 *
 * `messageEl` is `@since 1.8.7` and manifest.json's `minAppVersion` is `1.11.5`,
 * so it is ALWAYS present in any supported Obsidian — deliberately no version
 * guard and no `noticeEl` fallback. The `null` return exists solely for headless
 * harnesses where `Notice` is a `vi.fn()` stub with no `messageEl`.
 *
 * Duplicated per module per repo convention (no cross-module barrel imports for
 * tiny helpers) — at-rest-adapter-runtime.ts carries the same helper.
 */
function noticeBody(notice: Notice): HTMLElement | null {
  const el = (notice as { messageEl?: HTMLElement }).messageEl;
  if (!el || typeof el.createEl !== "function") return null;
  return el;
}

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/** Minimum allowed sync interval in seconds */
const MIN_SYNC_INTERVAL = 10;

/** Maximum time between connection retry attempts (2 minutes) */
const MAX_RETRY_INTERVAL_MS = 2 * 60 * 1000;

/** Base retry interval for exponential backoff (5 seconds) */
const BASE_RETRY_INTERVAL_MS = 5 * 1000;

/**
 * SD-02-F1: anti-storm floor between server-session re-mint ATTEMPTS in
 * `ensureServerSessionId` — successful or not. A client whose persisted session
 * carries no `sessionId` issues authenticated requests continuously (the
 * reconnect backoff probe alone produced 9,706 headerless samples from one user
 * in 7 days); without this floor, a heal that keeps failing would turn every one
 * of those into an extra `POST /auth/session`.
 *
 * 60 s is deliberately BELOW `MAX_RETRY_INTERVAL_MS` (120 s), the cap of the
 * connection-retry backoff, so a healthy retry loop is never throttled by it:
 * by the time the next probe fires the cooldown has already elapsed.
 */
const SESSION_REMINT_MIN_INTERVAL_MS = 60 * 1000;

/** Minimum spacing between repeated login-required notices */
const AUTH_REQUIRED_NOTICE_THROTTLE_MS = 5 * 1000;

/** Minimum spacing between repeated connection-lost notices */
const CONNECTION_LOST_NOTICE_THROTTLE_MS = 30 * 1000;

/**
 * Grace window before the "Connection lost" notice is shown. A transient blip
 * (one status-0 requestUrl, a momentary browser `offline` event on Wi-Fi/cell
 * handoff) flips status offline and self-heals within ~1s; firing the alarming
 * "working offline" toast immediately on every such hiccup is a false alarm.
 * The notice is scheduled this far out and cancelled the instant connectivity
 * returns (setConnectionStatus("online")), so only a sustained outage notifies.
 * The status-bar indicator still reflects the brief offline state immediately.
 */
const CONNECTION_LOST_NOTICE_GRACE_MS = 8 * 1000;

/** Plugin log prefix for console output */
const LOG_PREFIX = "[VaultGuard]";

/**
 * How long a PIN lifecycle action waits for the at-rest cipher to become ready
 * before refusing.
 *
 * `addSettingTab` runs early in `onload` while `initAtRestCipher()` is only
 * awaited much later, behind two full-vault scans
 * (`maybeAutoEnableLocalProjectMemoryMode`, `refreshDetectedGitRepositoryRoots`)
 * and the cipher's own `hasExistingCiphertext` walk. On a large vault that
 * window is seconds long — and Settings → VaultGuard is already open and
 * clickable inside it, so "Set PIN" saw `isReady() === false` and refused with
 * "Unlock the vault before setting a PIN" even though the vault unlocked a
 * moment later. Waiting this long absorbs that window; terminal cipher states
 * short-circuit the wait immediately (see `awaitCipherReadyForPin`).
 */
const PIN_CIPHER_READY_TIMEOUT_MS = 15 * 1000;

/** Poll spacing while waiting for the at-rest cipher in `awaitCipherReadyForPin`. */
const PIN_CIPHER_READY_POLL_MS = 250;

/**
 * Hard cap on per-session permission warmup retries. After this many
 * back-off retries fail, the store stays in `fetch-failed` until the
 * user does something explicit (focus event, login, settings change),
 * to avoid spinning forever in a degraded network. The store still
 * functions in `fetch-failed`: per-file network probes via
 * `getEffectivePermission`'s slow path still work; only the cache
 * pre-population is disabled. Pairs with Wave 2 Fix 2 (1.0.31).
 */
const MAX_WARMUP_RETRIES = 3;

/**
 * Bumped whenever a user-visible sync change ships. Surfaced by the "Status"
 * command so a user can confirm whether their Obsidian process has actually
 * reloaded the freshly-built `main.js`. Without a marker like this, "rebuilt
 * but not toggled in Settings → Community Plugins" looks identical to "code
 * never ran" — which is exactly the trap that caused the missing-toast report.
 */
const SYNC_FEATURE_REVISION = 9;

type AccessTokenRefreshResult =
  | { ok: true }
  | { ok: false; message: string; error?: unknown; terminal?: boolean };

/**
 * Why `awaitCipherReadyForPin` stopped waiting. Everything except `"ready"` is a
 * refusal the caller turns into its own actionable message — `"timeout"` is the
 * only one that means "still initialising", the rest are states no amount of
 * waiting can clear.
 */
type PinCipherReadyOutcome =
  | "ready"
  | "locked"
  | "needs-recovery"
  | "local-project-memory"
  | "disabled"
  | "timeout";

type LocalProtectionBootstrapState =
  | { kind: "unknown" }
  | { kind: "new" }
  | { kind: "existing"; source: "plugin-envelope" | "vault" | "profile" }
  | { kind: "needs-recovery"; reason: string };

type VaultBindingAuthorizationState =
  | "unbound"
  | "unverified"
  | "verified"
  // A DIFFERENT account is signed in than the one that last verified this
  // folder. Deliberately NOT "wrong-account": the local expectation is a
  // conservative pre-flight, not an authorization answer — the LAK is
  // device-local, so the same OS user decrypts this folder whichever account is
  // signed in, and `/vaults/{vaultId}` membership is the real boundary. Sync
  // stays hard-stopped until the user confirms, then the SERVER decides.
  | "account-changed"
  // A definitive 403/404 from `/vaults/{vaultId}` for this identity.
  | "wrong-account";

/**
 * PL4: Cognito refresh failures that can never succeed on retry — the refresh
 * token is expired/revoked or the user is disabled/deleted. Everything else
 * (network blips, throttling, Cognito 5xx) stays transient and keeps the
 * current keep-session-and-retry behavior.
 */
const TERMINAL_COGNITO_REFRESH_TYPES = new Set([
  "NotAuthorizedException",
  "UserNotFoundException",
  "PasswordResetRequiredException",
  "UserNotConfirmedException",
]);

function isTerminalCognitoRefreshError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  const type = (error as { cognitoErrorType?: string }).cognitoErrorType;
  if (type) return TERMINAL_COGNITO_REFRESH_TYPES.has(type);
  // No __type (older shims / dev): fall back to Cognito's terminal messages.
  return /refresh token has (expired|been revoked)|user is disabled/i.test(error.message);
}

/**
 * PL5: a Cognito challenge session (MFA / NEW_PASSWORD) lives ~3 minutes;
 * responding with a dead one surfaces "Invalid session for the user, session
 * is expired.". Replaying that session can never succeed — the login flow
 * must mint a fresh challenge instead.
 */
function isExpiredChallengeSessionError(message: string): boolean {
  return /session is expired|invalid session/i.test(message);
}

/**
 * Result shape for `collectRulesForWarmup` (Wave 2 Fix 2, 1.0.31).
 * The discriminator lets `runPermissionWarmup` decide between "seed the
 * cache" and "schedule a retry" — the pre-fix code returned an empty
 * array for both cases, which silently poisoned the cache with the
 * viewer-baseline whenever the rules fetch 401'd.
 */
type WarmupRulesResult =
  | { kind: "ok"; rules: PermissionRule[] }
  | { kind: "fetch-failed"; statusCode: number | null; error: unknown };

interface LeaseDeniedPath {
  pathPattern: string;
  ruleId: string;
}

function normalizeLeaseDeniedPaths(value: unknown): LeaseDeniedPath[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw new Error("VaultGuard Sync: Server returned malformed key-lease denied paths.");
  }
  const seen = new Set<string>();
  const result: LeaseDeniedPath[] = [];
  for (const entry of value) {
    if (!entry || typeof entry !== "object") {
      throw new Error("VaultGuard Sync: Server returned malformed key-lease denied paths.");
    }
    const candidate = entry as { pathPattern?: unknown; ruleId?: unknown };
    if (
      typeof candidate.pathPattern !== "string" ||
      !candidate.pathPattern.startsWith("/") ||
      typeof candidate.ruleId !== "string" ||
      candidate.ruleId.length === 0
    ) {
      throw new Error("VaultGuard Sync: Server returned malformed key-lease denied paths.");
    }
    const key = `${candidate.pathPattern}\u0000${candidate.ruleId}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push({ pathPattern: candidate.pathPattern, ruleId: candidate.ruleId });
  }
  return result.sort((a, b) =>
    a.pathPattern.localeCompare(b.pathPattern) || a.ruleId.localeCompare(b.ruleId)
  );
}

function keyLeasePathMatchesPattern(filePath: string, pattern: string): boolean {
  const normalize = (value: string) => {
    const normalized = value.replace(/\\/g, "/").replace(/\/+/g, "/").replace(/\/$/g, "");
    return normalized.startsWith("/") ? normalized : `/${normalized}`;
  };
  const normalizedPath = normalize(filePath);
  const normalizedPattern = normalize(pattern);
  if (normalizedPath === normalizedPattern) return true;

  const regexStr = normalizedPattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, "{{GLOBSTAR}}")
    .replace(/\*/g, "[^/]+")
    .replace(/\?/g, "[^/]")
    .replace(/{{GLOBSTAR}}/g, ".*");
  const regex = new RegExp(`^${regexStr}$`);
  if (regex.test(normalizedPath)) return true;

  const segments = normalizedPath.split("/");
  for (let index = segments.length - 1; index >= 1; index -= 1) {
    if (regex.test(segments.slice(0, index).join("/"))) return true;
  }
  return false;
}

interface RemoteFileContentResponse {
  content: string;
  encoding?: string;
  decrypted?: boolean;
  path?: string;
  contentType?: string;
  size?: number;
  lastModified?: string;
  versionId?: string;
  checksum?: string;
  encrypted?: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main Plugin Class
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Obsidian's desktop adapter surfaces fs errors either as a
 * NodeJS.ErrnoException (code === "ENOENT") or as a plain Error carrying the
 * ENOENT text in its MESSAGE with no `code` property at all (the live
 * capsule-race repro had the latter shape). Both mean the same thing here:
 * the file is already gone.
 */
function isFileAlreadyMissingError(error: unknown): boolean {
  if ((error as NodeJS.ErrnoException | null)?.code === "ENOENT") return true;
  const message = error instanceof Error ? error.message : String(error);
  return /enoent|no such file/i.test(message);
}

/**
 * VaultGuard Plugin - Enterprise vault security with permission-aware
 * encrypted cloud sync.
 *
 * This plugin replaces standard file sync with a system that:
 * 1. Enforces per-file read/write/admin permissions
 * 2. Encrypts all vault data end-to-end with time-limited key leases
 * 3. Provides full audit logging of all file operations
 * 4. Supports offline use with automatic conflict resolution
 */
export default class VaultGuardPlugin extends Plugin {
  private readonly i18n = createI18n();
  /** Runtime stylesheet fallback for installs where Obsidian misses styles.css. */

  /** Plugin settings persisted to disk */
  settings: VaultGuardSettings = DEFAULT_SETTINGS;

  /**
   * Edition + capabilities advertised by the connected backend via
   * `GET /orgs/{slug}/config`. Null until the first successful config fetch;
   * `featureEnabled()` treats null as Pro (the historic default).
   */
  serverEdition: ServerEdition | null = null;
  serverFeatures: ServerFeatures | null = null;

  /** Settings/config/session persistence runtime extracted from the entrypoint. */
  private settingsRuntime: PluginSettingsRuntime | null = null;

  /** Sync runtime for extracted behavior; sync state remains entrypoint-owned. */
  private syncRuntime: SyncRuntime | null = null;

  /**
   * Whether the connected backend advertises a given capability. Used by
   * UI surfaces (admin modal, file menu, sidebar) to hide Pro-only controls
   * when talking to a Community Edition server. Returns true when features
   * haven't been resolved yet — historic default is Pro.
   */
  featureEnabled(name: keyof ServerFeatures): boolean {
    if (this.isLocalProjectMemoryModeEnabled()) return false;
    return this.serverFeatures ? this.serverFeatures[name] : ASSUMED_SERVER_FEATURES[name];
  }

  isLocalProjectMemoryModeEnabled(): boolean {
    return isLocalProjectMemoryModeEnabled(this.settings);
  }

  isAutomaticLocalProjectMemoryModeForGitReposEnabled(): boolean {
    try {
      return readAutomaticLocalProjectMemoryModePreference(this.app);
    } catch (error) {
      this.logError("Reading the global automatic Local Project Memory Mode preference failed", error);
      return false;
    }
  }

  setAutomaticLocalProjectMemoryModeForGitRepos(enabled: boolean): void {
    writeAutomaticLocalProjectMemoryModePreference(this.app, enabled);
  }

  async maybeAutoEnableLocalProjectMemoryMode(): Promise<
    AutomaticLocalProjectMemoryModeDecision | { kind: "enabled" }
  > {
    const baseInput = {
      globalEnabled: this.isAutomaticLocalProjectMemoryModeForGitReposEnabled(),
      alreadyEnabled: this.isLocalProjectMemoryModeEnabled(),
      suppressed: this.settings.localProjectMemoryModeAutoEnableSuppressed === true,
      mobile: Platform.isMobileApp,
      serverBound: Boolean(this.settings.serverVaultId?.trim()),
      gitRootDetected: true,
      protection: { safe: true, reason: "safe" as const },
    };
    let decision = decideAutomaticLocalProjectMemoryMode(baseInput);
    if (decision.kind !== "eligible") return decision;

    let gitRootDetected = false;
    try {
      const git = await this.getVaultOrientationService().getGitSummary({
        includeStatus: false,
        forceRefresh: true,
      });
      gitRootDetected = git.detected;
    } catch (error) {
      this.logError("Automatic Local Project Memory Mode Git-root probe failed", error);
      return { kind: "inspection-failed" };
    }
    decision = decideAutomaticLocalProjectMemoryMode({
      ...baseInput,
      gitRootDetected,
    });
    if (decision.kind !== "eligible") return decision;

    let protection;
    try {
      protection = await this.ensureAtRestAdapterRuntimeObject()
        .inspectAutomaticLocalProjectMemoryModeSafety();
    } catch (error) {
      this.logError("Automatic Local Project Memory Mode protection inspection failed", error);
      return { kind: "inspection-failed" };
    }
    decision = decideAutomaticLocalProjectMemoryMode({
      ...baseInput,
      gitRootDetected,
      protection,
    });
    if (decision.kind !== "eligible") return decision;

    await this.enableLocalProjectMemoryMode("automatic");
    return { kind: "enabled" };
  }

  isDetectGitRepoFolderEnabled(): boolean {
    try {
      return readDetectGitRepoFolderPreference(this.app);
    } catch (error) {
      this.logError("Reading the Git repository folder detection preference failed", error);
      return false;
    }
  }

  setDetectGitRepoFolderEnabled(enabled: boolean): void {
    writeDetectGitRepoFolderPreference(this.app, enabled);
  }

  async refreshDetectedGitRepositoryRoots(): Promise<GitRepositoryDetectionResult> {
    try {
      return await this.ensureAtRestAdapterRuntimeObject().refreshDetectedGitRepositoryRoots({
        enabled: this.isDetectGitRepoFolderEnabled(),
        mobile: Platform.isMobileApp,
      });
    } catch (error) {
      this.logError("Git repository folder detection failed", error);
      return {
        roots: [],
        scannedEntries: 0,
        complete: false,
        reason: "listing-failed",
      };
    }
  }

  async convertDetectedGitRepositoryCiphertext(): Promise<GitRepositoryPlaintextTransitionResult> {
    if (this.isLocalProjectMemoryModeEnabled()) {
      return { decrypted: 0, alreadyPlaintext: 0, failed: 0, failures: [] };
    }
    try {
      return await this.ensureAtRestAdapterRuntimeObject()
        .convertDetectedGitRepositoryCiphertext();
    } catch (error) {
      this.logError("Converting detected Git repository files to plaintext failed", error);
      return {
        decrypted: 0,
        alreadyPlaintext: 0,
        failed: 1,
        failures: [{ path: "", error: error instanceof Error ? error.message : String(error) }],
      };
    }
  }

  async enableLocalProjectMemoryMode(
    source: "manual" | "automatic" = "manual",
  ): Promise<void> {
    this.settings.localProjectMemoryMode = true;
    if (source === "manual") {
      this.settings.localProjectMemoryModeAutoEnableSuppressed = false;
    }
    this.settings.atRestFirstRunDismissed = true;
    this.keyLease = null;
    this.vaultLeaseDenied = false;
    this.stopSyncTimer();
    this.stopKeyRenewalMonitor();
    this.stopHeartbeatMonitor();
    this.agentBridgeRuntime?.revokeAllLeases();
    await this.agentBridgeRuntime?.stopServerIfInitialized().catch((err) => {
      this.logError("Stopping agent bridge server for Local Project Memory Mode failed", err);
    });
    await this.saveSettings();
    this.updateStatusBar();
    new Notice(`VaultGuard Sync: ${LOCAL_PROJECT_MEMORY_MODE_NOTICE}`, 8000);
  }

  async disableLocalProjectMemoryMode(): Promise<void> {
    this.settings.localProjectMemoryMode = false;
    this.settings.localProjectMemoryModeAutoEnableSuppressed = true;
    await this.saveSettings();
    const repositoryDetection = await this.refreshDetectedGitRepositoryRoots();
    if (!repositoryDetection.complete) {
      new Notice(
        `VaultGuard Sync: Git repository folder detection was incomplete after leaving Local Project Memory Mode after ${repositoryDetection.scannedEntries} entries. Undiscovered folders keep normal local encryption.`,
        10000,
      );
    }
    await this.initAtRestCipher();
    const repositoryTransition = await this.convertDetectedGitRepositoryCiphertext();
    if (repositoryTransition.failed > 0) {
      new Notice(
        `VaultGuard Sync: ${repositoryTransition.failed} detected repository file(s) could not be converted to plaintext after leaving Local Project Memory Mode and remain protected. Review the console before using external Git tools.`,
        12000,
      );
    }
    this.restartSyncTimer();
    this.updateStatusBar();
  }

  /** Restart-safe, protected session backups persisted through Obsidian's plugin data file */
  private persistedSessions: Record<string, unknown> = {};

  /**
   * Per-vault membership role for the currently bound server vault.
   *
   * `session.role` only carries the user's *org-level* role (member / admin /
   * owner / vault-admin claim). It does NOT reflect their vault-specific role
   * on the server vault this Obsidian folder is bound to — an org "member"
   * may still be a vault "admin" on one vault and a "viewer" on another.
   *
   * The UI (file header, file-explorer decorations, sidebar) needs the
   * vault-scoped role to render correct read/write/admin affordances. We
   * fetch this after every login and on every vault binding change, then
   * propagate it to the live UI components.
   *
   * `null` means we haven't fetched yet (or the user is not a direct vault
   * member, in which case access is governed by org-level fallthrough).
   */
  private vaultMemberRole: VaultMemberRole | null = null;

  /**
   * Vault-unique session storage key derived at load time from runtime
   * identifiers (filesystem path / Obsidian appId / vault name).
   *
   * This replaces the old `settings.vaultBindingId` UUID, which was unsafe:
   * Electron's legacy browser storage is shared across every Obsidian vault window,
   * but the UUID lived inside the vault's own `data.json`. Duplicating a
   * vault folder propagated the same UUID, causing two vaults to read and
   * write the same `vaultguard-session:<id>` key — whichever account logged
   * in last would silently overwrite the other.
   *
   * Deriving from the vault's filesystem path (which by definition cannot
   * be shared between two distinct vaults) closes that collision class
   * by construction.
   */
  private derivedBindingId: string = "";

  /** Local uninstall/reinstall recovery classification for this vault root. */
  private localProtectionBootstrap: LocalProtectionBootstrapState = { kind: "unknown" };
  /** A restored capsule is not authoritative until its LAK opens an existing VG1. */
  private localRecoveryNeedsLakValidation = false;
  /** Account identity sealed in the capsule; never exposed through the manifest. */
  private localRecoveryExpectedAccountUserId: string | null = null;
  /** Same capsule, display only: lets the account-change prompt NAME that account. */
  private localRecoveryExpectedAccountEmail: string | null = null;
  /** One account-change prompt per signed-in identity — no modal storm on retry. */
  private accountChangePromptedForUserId: string | null = null;
  /** Sticky "working locally only" notice for a deferred account decision; one at a time. */
  private accountChangePausedNotice: Notice | null = null;

  /**
   * Sticky notice for a binding whose INITIAL RECONCILIATION never completed
   * (quick-260820-mv4). Tracked and deduped like the account-changed pair so
   * it can be replaced on a retry and dropped the moment sync actually
   * starts, instead of stacking one stale toast per attempt.
   */
  private reconciliationPausedNotice: Notice | null = null;
  /**
   * Sticky wrong-account notice, tracked so it can never outlive the state it
   * describes (quick-260820-ki7 stale-toast fix): hidden on forceLogout, on
   * completeLogin entry, on verify success, and on the transition into
   * account-changed. Deduped — a re-probe replaces instead of stacking.
   */
  private wrongAccountNotice: Notice | null = null;
  /**
   * Single-writer latch for the recovery-capsule store. persist()'s
   * crash-safety rotation (next → current → previous) assumes ONE writer; two
   * interleaved rotations race the same three slot files and the loser aborts
   * mid-rotation (handoff 2026-08-19 §2: ENOENT ×2 unlinking previous.v1.json
   * right after "Pick a different vault"). Both capsule wrappers serialize
   * through this chain; the ...Now() bodies must never be called directly.
   */
  private localRecoveryCapsuleOpChain: Promise<unknown> = Promise.resolve();
  /** A queued-but-not-started capsule persist that later callers may share. */
  private queuedLocalRecoveryCapsulePersist: Promise<boolean> | null = null;
  /** Exact `/vaults/{vaultId}` authorization gate for every sync/content path. */
  private vaultBindingAuthorizationState: VaultBindingAuthorizationState = "unbound";

  /**
   * Accessor pair, not a bare field (quick-260820-nqm). The ribbon's
   * blocked-binding badge has to track this value, and it is written from 17
   * places across restore, verify, probe, logout and binding changes — an
   * explicit refresh at each one is a rule that a future 18th site would
   * silently break, which is exactly how the badge came to be missing in the
   * first place. Routing every write through the setter makes the refresh
   * complete by construction.
   *
   * The refresh is skipped until the ribbon elements exist, so writes during
   * early startup (before `onload` wires the ribbons, and before settings are
   * loaded) stay inert.
   */
  private get vaultBindingAuthorization(): VaultBindingAuthorizationState {
    return this.vaultBindingAuthorizationState;
  }

  private set vaultBindingAuthorization(next: VaultBindingAuthorizationState) {
    if (this.vaultBindingAuthorizationState === next) return;
    this.vaultBindingAuthorizationState = next;
    if (this.vaultGuardRibbonEl) this.updateRibbonAuthIndicator();
  }

  /** Serializes saveData writes so settings and session updates do not clobber each other */
  private pluginDataSaveQueue: Promise<void> = Promise.resolve();

  /** API client for communicating with the VaultGuard backend */
  private apiClient: VaultGuardApiClient | null = null;

  /**
   * Cross-device AI-chat key sync. Instantiated in onload() once the api client
   * and settings are ready; reads its context lazily via getAiKeySyncContext().
   */
  aiKeySync!: ApiKeySync;

  /** Last saved API endpoint, used to detect live reconfiguration changes */
  private configuredApiEndpoint = "";

  /** Resolved API endpoint after stage auto-detection */
  private resolvedApiEndpoint: string | null = null;

  /** In-flight endpoint resolution to avoid duplicate probes */
  private apiEndpointResolutionPromise: Promise<string> | null = null;

  /** Current authenticated user session, null if not logged in */
  private session: UserSession | null = null;

  /**
   * Monotonic generation counter for `this.session`, bumped on EVERY identity
   * transition: a completed login, a logout, and the teardown in
   * `clearSensitiveData`.
   *
   * Why it exists: the background restore/refresh routines capture a
   * `UserSession` value, then `await` a network round trip (a key-lease GET, a
   * Cognito refresh) before writing it back to `this.session`. A logout landing
   * inside that window used to be silently undone — the late write resurrected
   * the session the user had just ended, `persistSession` wrote it back to disk,
   * and the ribbon (updated only by `forceLogout`) kept its logged-out badge
   * while the menu rendered the full signed-in state. `resumeStoredSession` is
   * fired unawaited from `onload`, so the window is the whole background resume:
   * on a slow first reconciliation it stays open for many seconds with the
   * ribbon live and clickable.
   *
   * A plain `if (this.session)` re-read is NOT enough. It cannot tell "still the
   * same session" from "logged out and signed back in as someone else" — that
   * case is worse, because the stale write clobbers the new user's session with
   * the previous user's tokens and identity. Comparing epochs distinguishes both.
   *
   * In-memory only, never persisted; the absolute value is meaningless, only
   * changes to it are.
   */
  private sessionEpoch = 0;

  /**
   * SD-02-F1 (M10): the session id of a PERSISTED session that is currently being
   * restored, held ONLY for the window of `restoreServerSession`'s first key-lease
   * request — set immediately before that `await`, cleared in its `finally`.
   *
   * Why it exists: during a restore the lease call runs BEFORE `this.session` is
   * assigned, so the header block below saw `undefined` and the request went out
   * headerless, with the candidate id travelling only in the query string where no
   * server-side session check reads it. This field closes that one-request gap.
   *
   * Why the window is exactly one await (and not the whole restore): the stale-session
   * self-heal branch calls `openServerSession` → `POST /auth/session` through the same
   * `apiRequest`. A stale candidate riding that mint would make the MINT itself 401
   * (the server validates a session header whenever one is present), breaking the very
   * self-heal that recovers from a dead session. The candidate must be gone before
   * either branch of the lease result runs.
   *
   * Never persisted, never read outside that window.
   */
  private restoreCandidateSessionId: string | null = null;

  /** Effective organization policies returned by the backend for the current session */
  private orgSettings: OrgSettingsResponse | null = null;

  /** Active encryption key lease for file operations */
  private keyLease: KeyLease | null = null;

  /**
   * True when the most recent vault-scoped key lease request returned a
   * permission-denied response (typically because the user has deny rules
   * overlapping `/**` or lacks read access on the root probe path). The
   * session itself is still valid — only the vault-wide DEK is unavailable.
   *
   * UI surfaces this as "Limited access". Downloads can still use the
   * permission-checked server-side decrypt path, but uploads stay disabled
   * until a client-side encryption lease is available.
   */
  private vaultLeaseDenied = false;

  /**
   * PL2: distinct from `vaultLeaseDenied` (a definitive 403). Set when a
   * key-lease acquisition fails TRANSIENTLY (5xx / network / statusCode 0) or
   * when a stored-session token refresh is deferred at startup. Unlike a 403
   * denial, a transient failure leaves the user with a null lease AND
   * `vaultLeaseDenied === false`, so the key-renewal monitor's recovery branch
   * would never retry and uploads would stay silently paused forever. The
   * monitor retries while either flag is set; this one clears on the next
   * successful lease acquisition.
   */
  private leaseRetryNeeded = false;

  /**
   * PL4: true while a terminal-refresh revocation logout is running. Breaks
   * the recursion forceLogout → apiRequest → refreshAccessToken(terminal) →
   * handleServerRevocation → forceLogout, and collapses concurrent callers
   * (heartbeat/sync timers) into one logout.
   */
  private terminalRefreshLogoutInProgress = false;

  /**
   * SD-02-F1: the single in-flight `ensureServerSessionId` attempt, or null.
   *
   * It is TWO guards in one:
   *   1. Concurrency collapse — many callers (sync timer, heartbeat, reconnect
   *      probe, UI action) can hit the headerless branch within the same tick;
   *      they all join this one promise instead of each starting a mint.
   *   2. Recursion brake — the mint itself travels through `apiRequest`, whose
   *      header block re-enters `ensureServerSessionId`. `openServerSession`
   *      opts out via `suppressSessionHeader` (the primary brake), and this
   *      field is the second, independent one. NOTE the ordering constraint:
   *      the field is assigned BEFORE the closure is awaited, so a re-entrant
   *      caller sees a non-null promise and returns it rather than awaiting a
   *      mint that has not been started yet.
   */
  private sessionReMintInFlight: Promise<void> | null = null;

  /**
   * SD-02-F1: timestamp of the last re-mint ATTEMPT (armed even when the attempt
   * throws), floored by `SESSION_REMINT_MIN_INTERVAL_MS`. A permanently failing
   * heal therefore costs at most one `POST /auth/session` per minute while every
   * request still proceeds headerless exactly as it does today.
   */
  private lastSessionReMintAttemptAt = 0;

  /**
   * Phase 12 (vault idle-lock): true while the vault is cryptographically locked
   * — the in-memory LAK + key-lease are evicted and the workspace is curtained,
   * but the SESSION + refresh token + revocation heartbeat are PRESERVED (unlike
   * forceLogout). A correct PIN clears it via unlockWithPin.
   */
  private isVaultLocked = false;

  /**
   * Phase 12: device PIN-lock manager (PBKDF2 + safeStorage pepper → AES-GCM
   * wrap of the LAK). Constructed in onload before initAtRestCipher so the
   * adapter's PIN-lock pre-check can see whether a PIN owns the LAK. null until
   * wired.
   */
  private pinLockManager: PinLockManager | null = null;

  /** Phase 12: the opaque lock-curtain overlay; lazily constructed on first lock. */
  private lockCurtain: LockCurtainController | null = null;

  /** Phase 12 (L-4): active file path captured at lock time, re-opened on unlock. */
  private preLockActiveFilePath: string | null = null;

  /** Phase 12: whether the one-time "set a PIN" nudge (lock policy, no PIN) has been shown. */
  private pinNudgeShown = false;

  /** Debounces the "Limited access" Notice so it isn't shown more than once per minute. */
  private lastLimitedAccessNoticeAt = 0;
  private lastSessionDegradedNoticeAt = 0;
  /**
   * Throttle for the transient "vault could not be verified right now" Notice.
   * That branch is now reachable from the reconnect loop rather than once per
   * startup, so it needs the same 60 s window the other degraded-state notices
   * use — the retry is meant to be quiet until it either heals or the user acts.
   */
  private lastBindingUnverifiedNoticeAt = 0;

  /**
   * P2: mobile has no status bar, so a needs-recovery cipher used to be
   * completely invisible there. This gates a one-per-episode mobile Notice; it
   * resets when the cipher leaves needs-recovery so a later relapse re-alarms.
   */
  private atRestMobileRecoveryNoticeShown = false;

  /**
   * Paths known to hold 36-byte VG1 placeholders pending hydration via the
   * server-side decrypt endpoint. In-memory only per D-09 (never persisted
   * to data.json). Populated by performInitialReconciliation in limited-
   * access mode and by a session-restore sweep over 36-byte VG1 files
   * (see sweepPlaceholderPaths). Consulted by interceptedRead as the
   * primary disambiguator vs the empty-plaintext fallback heuristic (D-13).
   */
  placeholderPaths: Set<string> = new Set();

  /** Current synchronization state */
  private syncState: SyncState = {
    lastSync: null,
    pendingChanges: 0,
    conflicts: [],
    status: "idle",
    bytesUploaded: 0,
    bytesDownloaded: 0,
    lastError: null,
  };

  /** Connection state tracking */
  private connectionState: ConnectionState = {
    status: "offline",
    lastConnected: null,
    failedAttempts: 0,
    nextRetryAt: null,
    latencyMs: null,
  };

  /**
   * Timer handle for the next scheduled sync. Adaptive: each successful
   * tick reschedules itself based on observed activity rather than firing
   * at a fixed interval. Pause-aware (cleared when window is hidden,
   * offline, or unbound).
   */
  private syncTimer: ReturnType<typeof setTimeout> | null = null;
  /** True when the periodic loop is paused (window hidden / offline). */
  private syncTimerPaused = false;

  /** Timer handle for key lease renewal checks */
  private keyRenewalTimer: ReturnType<typeof setInterval> | null = null;

  /** Timer handle for server revocation heartbeat checks */
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;

  /** Timer handle for connection retry */
  private connectionRetryTimer: ReturnType<typeof setTimeout> | null = null;

  /** In-flight offline queue flush, used to avoid duplicate replay bursts. */
  private offlineQueueFlushPromise: Promise<void> | null = null;

  /** Timer handle for organization-enforced inactivity lock */
  private autoLockTimer: ReturnType<typeof setTimeout> | null = null;

  /**
   * In-flight server-side resume for a synchronously restored local session.
   *
   * Obsidian may restore open tabs immediately after plugin load. If those
   * reads hit the adapter while this resume is still fetching vault membership
   * and warming the permission cache, a non-admin member can look like they
   * have no READ access at all. Interceptors wait briefly on this promise
   * before making destructive denied-read decisions.
   */
  private sessionResumePromise: Promise<void> | null = null;

  /**
   * True once the server side of this session is fully up: monitors started,
   * vault binding verified, lease resolved, status flipped online.
   *
   * `restoreServerSession` has several early returns and one rethrow that land
   * before all of that, and none of them leave a mark — so "we have a session"
   * and "the session is actually usable" used to be indistinguishable, and a
   * half-finished resume was simply never finished. `attemptReconnection` reads
   * this to decide whether a successful probe should also re-drive the resume.
   * Reset by `forceLogout`; a fresh `completeLogin` sets it directly.
   */
  private serverSessionResumeComplete = false;

  /**
   * Consecutive resumes that ended without completing. Feeds the reconnect
   * backoff so a resume that keeps failing over a REACHABLE backend still backs
   * off to the 2-minute ceiling instead of retrying every few seconds —
   * `connectionState.failedAttempts` cannot do that job alone because the
   * "online" flip that precedes each re-drive resets it to 0.
   */
  private incompleteResumeRetries = 0;

  /** Status bar element reference */
  private statusBarEl: HTMLElement | null = null;

  /** Primary VaultGuard shield ribbon button, used for persistent auth status. */
  private vaultGuardRibbonEl: HTMLElement | null = null;
  private vaultGuardChatRibbonEl: HTMLElement | null = null;
  private vaultGuardGraphRibbonEl: HTMLElement | null = null;

  /**
   * Last explicit logout reason for persistent UI surfaces. Notices disappear;
   * this keeps the status bar/sidebar honest until the next successful login.
   */
  private lastLogoutAuthState: VaultGuardSidebarAuthState | null = null;

  /** At-rest adapter runtime extracted from the Obsidian entrypoint. */
  private atRestAdapterRuntime: AtRestAdapterRuntime | null = null;

  /**
   * Test-compatible pass-through for the raw adapter methods. Runtime code owns
   * the state; main.ts keeps this property name because existing tests and
   * extracted runtimes still inspect or stub it through the plugin object.
   */
  private get originalAdapterMethods(): VaultAdapterOriginalMethods {
    return this.ensureAtRestAdapterRuntimeObject().getOriginalAdapterMethods();
  }

  private set originalAdapterMethods(methods: VaultAdapterOriginalMethods) {
    this.ensureAtRestAdapterRuntimeObject().setOriginalAdapterMethods(methods);
  }

  /**
   * Test-compatible pass-through for the local at-rest cipher. Runtime code owns
   * the cipher, while main.ts preserves the historical property surface.
   */
  private get atRestCipher(): AtRestCipher | null {
    return this.ensureAtRestAdapterRuntimeObject().getAtRestCipher();
  }

  private set atRestCipher(cipher: AtRestCipher | null) {
    this.ensureAtRestAdapterRuntimeObject().setAtRestCipher(cipher);
  }

  /**
   * Whether this plugin process has already run the "verify local files exist
   * on server" catch-up pass. Resets each time the plugin loads. Without this
   * pass, any local-only file that didn't reach the server during the initial
   * binding reconciliation (e.g. silently 403'd uploads) stays stranded
   * forever — `performSync` is delta-only and never notices.
   */
  private localOnlyCatchupCompleted = false;

  /**
   * Whether this plugin process has already run the mirror-image repair pass
   * that verifies server-side files and folders exist locally. This catches
   * older remote objects that delta sync can miss after a failed first apply.
   */
  private remoteInventoryRepairCompleted = false;

  /**
   * True while VaultGuard is applying server content into the local Obsidian
   * vault. Vault APIs route through the adapter methods we intercept, so this
   * guard prevents remote downloads from being re-uploaded as local edits.
   */
  private applyingRemoteWrite = false;

  /**
   * Phase 13-02 (guarded local-cache reset): true only for the duration of
   * `resetLocalAtRestAndResync()`. The reset wipes the dead local VG1 ciphertext
   * via the RAW `originalAdapterMethods.remove` (bypassing `interceptedDelete`'s
   * server DELETE), but Obsidian's file watcher still fires `vault.on('delete')`
   * for each removed file. `handleFolderDeleted` / `handleVaultFileDeleted`
   * early-return while this is set so NONE of those events can propagate a
   * deletion to the authoritative server copy. `applyingRemoteWrite` deliberately
   * does NOT cover deletes, so this is a separate, purpose-built suppression flag.
   */
  private resettingLocalCache = false;

  /**
   * Reentrancy latch for `resetLocalAtRestAndResync()` (CR-01). Distinct from
   * `resettingLocalCache` (which the delete listeners read to suppress
   * propagation) so the two concerns never overload: this one SERIALIZES the
   * recovery doors, that one SUPPRESSES delete events.
   *
   * True from the instant a reset commits (past the guards) until its `finally`.
   * A second concurrent reset must refuse at the very top — BEFORE any side
   * effect — because if it ran the shared-flag `finally` it would clear
   * `resettingLocalCache` + resume the sync loop WHILE the first reset is still
   * raw-removing files, un-suppressing that wipe's `vault.on('delete')` events
   * into server DELETEs (the exact zero-DELETE-invariant break the phase exists
   * to prevent).
   */
  private atRestResetInFlight = false;

  /**
   * Memoized key for this vault's entry in the cross-instance wipe-suppression
   * registry (SD-07-F4, `./wipe-suppression-registry`). The path-scoped
   * suppression set that used to live here as a private instance field now
   * lives in that `globalThis`-scoped registry, because instance-local state is
   * exactly what a hot reload mid-wipe destroys.
   */
  private wipeSuppressionVaultKeyCache: string | null = null;

  /**
   * Our owner token for the CROSS-INSTANCE at-rest reset lease (SD-07-F4), or
   * null when this instance does not hold it. Minted by the registry — never by
   * the plugin — because `lifecycleGeneration` is a per-instance counter that
   * restarts at 0 in a replacement instance and would therefore collide.
   * Release is ownership-guarded, so a superseded instance's late `finally`
   * cannot clobber a newer reset's lease.
   */
  private atRestResetLeaseOwnerId: string | null = null;

  /**
   * Whether we've already wired up the vault.on('create' | 'delete' | 'rename')
   * listeners that mirror folder lifecycle to the server. Registering twice
   * would double-fire every marker upload/delete; this flag stops that.
   */
  private folderLifecycleListenersRegistered = false;

  /**
   * Always-on, secret-free breadcrumb recorder for the startup/sync control
   * flow (DX4-DIAG). Pure additive instrumentation: every `.record(...)` call
   * is a standalone statement that changes no branch/return/timer behavior.
   * Surfaced read-only via the `sync-diagnostics` command.
   */
  private syncDiagnostics = new SyncDiagnostics();

  /**
   * Last wall-clock millisecond a focus-triggered sync fired. Used to debounce
   * the visibility/focus listeners — Obsidian fires both 'focus' on the window
   * and 'visibilitychange' on the document for the same user action, and
   * Cmd-Tab cycles can fire several focus events in quick succession.
   */
  private lastFocusSyncAt = 0;

  /** Last time a login-required Notice was shown, used to avoid toast storms */
  private lastAuthRequiredNoticeAt: number | null = null;

  /** Last time a connection-lost Notice was shown, used to avoid retry-loop toast storms */
  private lastConnectionLostNoticeAt: number | null = null;

  /** Pending debounced connection-lost Notice; cancelled if connectivity returns within the grace window. */
  private connectionLostNoticeTimer: ReturnType<typeof setTimeout> | null = null;

  /**
   * Tracks whether we've already warned the user this run that the OS keystore
   * is unreachable (so we'd otherwise be forced to log them in again on every
   * launch). One Notice per session is enough — repeated `persistSession`
   * calls (token refresh, displayName update, etc.) shouldn't toast-storm.
   */
  private safeStorageUnavailableNotified = false;

  /**
   * Unified permission cache + event bus (Phase 9). Replaces the previous
   * `permissionCache` Map, `vaultDefaultPermission`, and
   * `permissionWarmupPromise` fields. Constructed in `onload()` after
   * `rebuildApiClient()` so cfg.apiClient is non-null. All surface UI
   * invalidations now fan out via `permissionStore.emit('changed', ...)`;
   * the four `init*` methods subscribe with `registerEvent(...)` for
   * auto-cleanup.
   */
  private permissionStore!: PermissionStore;

  /**
   * Mirror of warm-up in-flight state for the status bar — the store
   * coalesces concurrent warm calls internally, but the status bar still
   * wants to render "Loading permissions..." while warm-up is running.
   * Counter (not boolean) so two overlapping warm-up triggers don't have the
   * later finally clear the flag while the earlier is still running (WR-03).
   * `> 0` = in-flight; incremented on entry, decremented in finally.
   */
  private permissionWarmupInFlight = 0;

  /**
   * Tracks the active warm-up cycle promise (collectRulesForWarmup + store.warm).
   *
   * Different from `permissionStore.inFlightWarmup`, which only spans the
   * inner `store.warm()` call. The plugin-level cycle promise is set BEFORE
   * the `collectRulesForWarmup` HTTP fetch, so `awaitPermissionWarmup` can
   * wait for the full cycle instead of racing against a null promise during
   * the rule-fetch gap (1.0.15 data-loss regression).
   */
  private warmupCyclePromise: Promise<void> | null = null;

  /**
   * Latches `true` after the first warm-up cycle completes successfully.
   * Used by `interceptedRead`/`interceptedReadBinary` as positive evidence
   * that a denial result reflects real server state and not a cold cache.
   * Without this, a fresh-start race could wipe vault content before the
   * first warm-up cycle ever ran.
   */
  private hasWarmedAtLeastOnce = false;

  /**
   * Wave 2 Fix 2 (1.0.31): per-session warmup-retry tracking. Resets
   * on every successful warm and on explicit user actions (focus,
   * login). Cap is `MAX_WARMUP_RETRIES`.
   */
  private warmupRetryCount = 0;
  private warmupRetryTimer: ReturnType<typeof setTimeout> | null = null;

  /** Queue of operations made while offline */
  private offlineQueue: OfflineQueueOperation[] = [];

  /**
   * Awaitable handle for the SY5 offline-queue envelope restore
   * (quick-260820-ki7). Startup stays fire-and-forget, but the takeover
   * lane's cleanliness check must positively know the restore finished
   * before trusting an empty in-memory queue — a null handle (load never
   * started: early lifecycle, harness) is treated as indeterminate, NOT
   * clean.
   */
  private offlineQueueLoadPromise: Promise<void> | null = null;

  /**
   * Paths mutated while the binding sat in a blocked state
   * (`account-changed` / `wrong-account`) — the belt-and-braces live-window
   * tracker for edits the offline queue never sees (external adds/modifies
   * Obsidian observes during the blocked window; quick-260820-ki7). Feeds
   * collectUnsyncedLocalChanges; cleared on verify success, forceLogout, and
   * discardUnsyncedLocalChanges.
   */
  private blockedStateLocalEdits = new Set<string>();

  /** SY5: debounce handle for persisting the offline queue envelope. */
  private offlineQueuePersistTimer: ReturnType<typeof setTimeout> | null = null;

  /** Serializes envelope writes so a reset deletion cannot be followed by an older write. */
  private offlineQueuePersistTail: Promise<void> = Promise.resolve();

  /** Per-file server version state used for optimistic write guards. */
  private remoteFileState = new RemoteFileStateStore();

  /** Debounce handle for the encrypted remote-file-state envelope. */
  private remoteFileStatePersistTimer: ReturnType<typeof setTimeout> | null = null;

  /** Serializes remote-state writes with user-confirmed reset deletion. */
  private remoteFileStatePersistTail: Promise<void> = Promise.resolve();

  /** Per-file permission header injected into markdown views */
  private filePermissionHeader: FilePermissionHeader | null = null;

  /** Locks the editor for files the user has below-WRITE access to */
  private readOnlyGuard: ReadOnlyGuard | null = null;

  /** File explorer decorations (permission badges, avatars on nav items) */
  private fileExplorerDecorations: FileExplorerDecorations | null = null;

  /** Background poller for new public releases of the plugin */
  private updateChecker: UpdateChecker | null = null;
  private settingTab: VaultGuardSettingTab | null = null;
  private externalSettingsReload: Promise<void> | null = null;
  private unloading = false;
  private lifecycleGeneration = 0;

  /** Sidebar view configuration (set once, injected into view instances) */
  private sidebarViewConfig: VaultGuardSidebarViewConfig | null = null;
  private chatViewRegistered = false;
  private graphViewRegistered = false;
  private discoveryViewRegistered = false;
  private discoveryBasesRegistered = false;
  private discoveryCliRegistered = false;
  private discoveryCommandRegistered = false;
  private discoveryRuntime: import("./discovery/discovery-runtime").DiscoveryRuntime | null = null;
  private discoveryRuntimePromise: Promise<import("./discovery/discovery-runtime").DiscoveryRuntime> | null = null;
  private semanticRuntime: import("./discovery/semantic-search-runtime").SemanticSearchRuntime | null = null;
  private semanticRuntimePromise: Promise<import("./discovery/semantic-search-runtime").SemanticSearchRuntime> | null = null;
  private readonly discoveryLifecycleListeners = new Set<() => void>();
  private readonly semanticStatusListeners = new Set<
    (status: import("./discovery/semantic-search-runtime").SemanticRuntimeStatus) => void
  >();
  private optionalViewRegistrationPromises = new Map<OptionalModuleId, Promise<boolean>>();

  /**
   * Explicit LLM/agent bridge. This is intentionally off by default and only
   * works with short-lived in-memory leases. Agents get a narrow tool surface;
   * they never receive the LAK, cloud key lease, refresh token, or raw vault
   * filesystem access.
   */
  private agentBridgeRuntime: AgentBridgeRuntime | null = null;
  private vaultOrientationService: VaultOrientationService | null = null;
  private permissionsGraphRuntime: PermissionsGraphRuntime | null = null;
  private permissionsGraphVirtualQaModal: { close(): void } | null = null;
  private readonly longOperations = new LongOperationManager();
  private longOperationUi: LongOperationUiController | null = null;
  private longOperationStatusUnsubscribe: (() => void) | null = null;

  private getLongOperationConflictKey(): string {
    const serverVaultId = this.settings.serverVaultId?.trim();
    if (serverVaultId) return `server-vault:${serverVaultId}`;
    const vaultName =
      typeof this.app?.vault?.getName === "function"
        ? this.app.vault.getName()
        : this.manifest?.id ?? "vaultguard";
    return `local-vault:${vaultName}`;
  }

  private beginLongOperation(options: LongOperationStartOptions): LongOperationHandle {
    const fallbackVaultName =
      this.settings.serverVaultName ||
      this.settings.serverVaultSlug ||
      (typeof this.app?.vault?.getName === "function" ? this.app.vault.getName() : undefined);
    return this.longOperations.begin({
      ...options,
      vaultId: options.vaultId ?? (this.settings.serverVaultId || undefined),
      vaultName: options.vaultName ?? fallbackVaultName,
      conflictKey: options.conflictKey ?? this.getLongOperationConflictKey(),
    });
  }

  /**
   * Shutdown ordering for long operations (SD-07-F4). Abort BEFORE destroy:
   * `destroy()` empties the operations map, after which there is nothing left to
   * abort and any in-flight PROTECTED mutation (notably the at-rest reset wipe,
   * which is `canCancel: false` and holds a live raw adapter `remove`) would
   * keep running with a live handle while the replacement instance boots.
   *
   * The abort is a checkpoint fence, not a join: the wipe loop exits at its next
   * per-item checkpoint. A `remove()` already awaited when the abort lands still
   * completes — bounded to one file, and that file registers itself as
   * delete-suppressed the instant it succeeds.
   */
  private shutdownLongOperations(): void {
    const aborted = this.longOperations.abortAllForShutdown();
    if (aborted > 0) this.log(`Unload: aborted ${aborted} in-flight long operation(s).`);
    this.longOperations.destroy();
  }

  getVaultOrientationService(): VaultOrientationService {
    if (!this.vaultOrientationService) {
      this.vaultOrientationService = new VaultOrientationService({
        app: this.app,
        getSettings: () => this.settings,
        getAtRestEncrypted: () => {
          if (this.isLocalProjectMemoryModeEnabled()) return false;
          const status = this.getAtRestStatus();
          return status.kind === "unlocked" || status.kind === "locked" || status.kind === "needs-recovery";
        },
        getConnectorStatus: () => this.getVaultOrientationConnectorStatus(),
        listServerVaults: () => this.listServerVaults(),
        logError: (message, error) => this.logError(message, error),
      });
    }
    return this.vaultOrientationService;
  }

  async getVaultOrientationSnapshotForDiagnostics(
    options: { includeKnownVaults?: boolean; includeGit?: boolean; forceRefresh?: boolean } = {},
  ): Promise<VaultOrientationSnapshot> {
    const service = this.getVaultOrientationService();
    const snapshot = await service.getSnapshot(diagnosticsConnectorContext(), {
      includeKnownVaults: options.includeKnownVaults ?? true,
      includeGit: options.includeGit ?? true,
      includeConnectorStatus: true,
      forceRefresh: options.forceRefresh === true,
    });
    return service.redactForClipboard(snapshot);
  }

  private getVaultOrientationConnectorStatus(): ConnectorStatusMatrix {
    const localMode = this.isLocalProjectMemoryModeEnabled();
    const claudeStatus = this.getAgentBridgeSkillStatus();
    const codexStatus = this.getAgentBridgeCodexSkillStatus();
    const openaiChat = this.settings.encryptedOpenAiKey ? "available" : "not-configured";
    return {
      claude:
        claudeStatus.available && claudeStatus.installed ? "available" : "not-configured",
      codex:
        codexStatus.available && codexStatus.installed ? "available" : "not-configured",
      openaiChat,
      chatgptRemote: localMode
        ? "disabled"
        : this.session && this.settings.serverVaultId
          ? "developer-only"
          : "not-configured",
    };
  }

  private createAtRestAdapterRuntimeContext(): AtRestAdapterRuntimeContext {
    const thisPlugin = this;
    return {
      app: this.app,
      manifestId: this.manifest?.id,
      get settings() {
        return thisPlugin.settings;
      },
      // Phase 12: the adapter's PIN-lock pre-check keys off this to skip
      // provisioning and land LOCKED on a PIN-enrolled cold start (edge #6).
      isPinLockEnrolled: () => this.pinLockManager?.isEnrolled() ?? false,
      // SD-05-F3 / D2: a recovery-code restore that REPLACED the LAK must not
      // leave a PIN envelope wrapping the dead key (same rule as the reset
      // engine at ~:10899).
      disablePinLock: async () => {
        await this.pinLockManager?.disable();
      },
      // SD-03-F15: `canDeletePath`'s org-admin short-circuit is gated on this.
      // Live-read arrow for the same reason as the permission-store context.
      isAdminRestrictionActive: () => this.isAdminRestrictionActive(),
      getSession: () => this.session,
      getKeyLease: () => this.keyLease,
      isVaultLeaseDenied: () => this.vaultLeaseDenied,
      getPlaceholderPaths: () => this.placeholderPaths,
      isApplyingRemoteWrite: () => this.applyingRemoteWrite,
      getSyncState: () => this.syncState,
      getOfflineQueue: () => this.offlineQueue,
      getPermissionStore: () => this.permissionStore,
      hasWarmedAtLeastOnce: () => this.hasWarmedAtLeastOnce,
      getProtectedContentGate: () => this.getProtectedContentGate(),
      saveSettings: () => this.saveSettings(),
      openVaultGuardSettings: () => this.openVaultGuardSettings(),
      showLoginRequiredNotice: (action, path) =>
        this.showLoginRequiredNotice(action, path),
      awaitPermissionReadiness: () => this.awaitPermissionReadiness(),
      getEffectivePermission: (path) => this.getEffectivePermission(path),
      resolvePermissionFromCache: (path) => this.resolvePermissionFromCache(path),
      isPathExcluded: (path) => this.isPathExcluded(path),
      normalizeVaultPath: (path) => this.normalizeVaultPath(path),
      vaultConfigPath: (...parts) => this.vaultConfigPath(...parts),
      toPermissionPath: (path) => this.toPermissionPath(path),
      isFolderMarkerPath: (path) => this.isFolderMarkerPath(path),
      readPlainFromDisk: (path) => this.readPlainFromDisk(path),
      writePlainToDisk: (path, data) => this.writePlainToDisk(path, data),
      readPlainBinaryFromDisk: (path) => this.readPlainBinaryFromDisk(path),
      writePlainBinaryToDisk: (path, data) =>
        this.writePlainBinaryToDisk(path, data),
      notifyCloudDecryptFallback: (path) => this.notifyCloudDecryptFallback(path),
      notifyCorruptedWrite: (path) => this.notifyCorruptedWrite(path),
      beginLongOperation: (options) => this.beginLongOperation(options),
      getLongOperationConflictKey: () => this.getLongOperationConflictKey(),
      isOnline: () => this.isOnline(),
      isNetworkError: (error) => this.isNetworkError(error),
      setConnectionStatus: (status, options) =>
        this.setConnectionStatus(status, options),
      shouldUploadChangesImmediately: () =>
        this.getProtectedContentGate().ok && this.shouldUploadChangesImmediately(),
      queueOfflineOperation: (operation, path, data, options) =>
        this.queueOfflineOperation(operation, path, data, options),
      getRemoteFileState: (path) => this.getRemoteFileState(path),
      getExpectedVersionId: (path) => this.getExpectedVersionId(path),
      resolveMutationIntent: (path) => this.resolveMutationIntent(path),
      recordRemoteFilePresent: (path, update) =>
        this.recordRemoteFilePresent(path, update),
      recordRemoteFileAbsent: (path) => this.recordRemoteFileAbsent(path),
      recordSyncDiagnostic: (event, detail) => this.syncDiagnostics.record(event, detail),
      handleRemoteWriteConflict: (path, localContent, baseVersionId, options) =>
        this.handleRemoteWriteConflict(path, localContent, baseVersionId, options),
      recordDeletionTombstone: (path) => this.recordDeletionTombstone(path),
      clearDeletionTombstone: (path) => this.clearDeletionTombstone(path),
      updateStatusBar: () => this.updateStatusBar(),
      // Phase 13 #1: the runtime fires the refresh hub after init/migration-
      // failure/restore transitions; the sticky's CTA + the recovery-code door
      // route through these plugin indirections.
      refreshAtRestRecoverySurfaces: () => this.refreshAtRestRecoverySurfaces(),
      startAtRestRecoveryFlow: () => this.startAtRestRecoveryFlow(),
      startAtRestRecoveryFromRecoveryCode: () =>
        this.startAtRestRecoveryFromRecoveryCode(),
      // Phase 13-02: the guarded local-cache reset flag, threaded so the runtime
      // can consult it if needed. main.ts owns set/clear around the wipe.
      isResettingLocalCache: () => this.isResettingLocalCache(),
      setResettingLocalCache: (v) => this.setResettingLocalCache(v),
      // SD-07-F4: the wipe registers each path in the CROSS-INSTANCE suppression
      // registry the instant its raw remove succeeds — the post-wipe bulk
      // registration below is unreachable once the promise is orphaned.
      recordWipedPathAwaitingRepull: (path) => this.recordWipedPathAwaitingRepull(path),
      encryptContent: (content) => this.encryptContent(content),
      computeHash: (content) => this.computeHash(content),
      // BIN-A / D-02: byte-crypto pass-throughs beside their string siblings so
      // the at-rest adapter runtime can (later waves) encrypt/decrypt/hash raw
      // binary bytes with the same lease/vault guards.
      encryptContentBytes: (content) => this.encryptContentBytes(content),
      decryptContentBytes: (content) => this.decryptContentBytes(content),
      computeHashBytes: (content) => this.computeHashBytes(content),
      uploadLargeEncryptedFile: (path, plaintext, contentType, expectedVersionId) =>
        this.uploadLargeEncryptedFile(path, plaintext, contentType, expectedVersionId),
      upsertPendingLargeFile: (record) => this.upsertPendingLargeFile(record),
      clearPendingLargeFile: (path) => this.clearPendingLargeFile(path),
      apiRequest: <T>(
        method: string,
        endpoint: string,
        body?: Record<string, unknown>,
        idTokenOverride?: string,
        options?: { timeoutMs?: number; maxAttempts?: number }
      ) => {
        // L2 (BIN-A): preserve the exact argument arity when no timeout override
        // is passed. Existing callers (and their toHaveBeenCalledWith assertions)
        // must keep seeing the same 2/3/4-arg shapes — trailing `undefined`s
        // change the call signature. Only a real { timeoutMs } widens to 5 args.
        if (options !== undefined) {
          return this.apiRequest<T>(method, endpoint, body, idTokenOverride, options);
        }
        return idTokenOverride !== undefined
          ? this.apiRequest<T>(method, endpoint, body, idTokenOverride)
          : body !== undefined
            ? this.apiRequest<T>(method, endpoint, body)
            : this.apiRequest<T>(method, endpoint);
      },
      vaultPath: (suffix = "") => this.vaultPath(suffix),
      readFileDecrypted: (path, options) =>
        options === undefined
          ? this.readFileDecrypted(path)
          : this.readFileDecrypted(path, options),
      fetchRemoteFileContent: (path, options) =>
        options === undefined
          ? this.fetchRemoteFileContent(path)
          : this.fetchRemoteFileContent(path, options),
      decodeRemoteFileContent: (path, data) =>
        this.decodeRemoteFileContent(path, data),
      decodeBase64Utf8: (base64) => this.decodeBase64Utf8(base64),
      isVaultBindingWireBlocked: () =>
        this.vaultBindingAuthorization === "account-changed" ||
        this.vaultBindingAuthorization === "wrong-account",
      emitAuditEvent: (action, resourcePath, metadata) =>
        this.emitAuditEvent(action as AuditAction, resourcePath, metadata),
      log: (message) => this.log(message),
      logError: (message, error) => this.logError(message, error),
    };
  }

  private createAtRestAdapterRuntime(): AtRestAdapterRuntime {
    return createAtRestAdapterRuntime(this.createAtRestAdapterRuntimeContext());
  }

  private ensureAtRestAdapterRuntimeObject(): AtRestAdapterRuntime {
    if (!this.atRestAdapterRuntime) {
      this.atRestAdapterRuntime = this.createAtRestAdapterRuntime();
    }
    return this.atRestAdapterRuntime;
  }

  private createSyncRuntimeContext(): SyncRuntimeContext {
    return {
      app: this.app,
      normalizeVaultPath: (path) => this.normalizeVaultPath(path),
      isPathExcluded: (path) => this.isPathExcluded(path),
      getSettings: () => this.settings,
      getSession: () => this.session,
      getSyncState: () => this.syncState,
      getConnectionState: () => this.connectionState,
      getKeyLease: () => this.keyLease,
      setKeyLease: (lease) => {
        this.keyLease = lease;
      },
      isPathDeniedByKeyLease: (path) => this.isPathDeniedByKeyLease(path),
      isVaultLeaseDenied: () => this.vaultLeaseDenied,
      // Phase 12 (NN-2 / key-renewal guard): the heartbeat survives the lock,
      // but checkKeyLeaseRenewal consults this to no-op while locked.
      isVaultLocked: () => this.isVaultLocked,
      getProtectedContentGate: () => this.getProtectedContentGate(),
      isLeaseRetryNeeded: () => this.leaseRetryNeeded,
      getEffectiveSyncMode: () => this.getEffectiveSyncMode(),
      getEffectiveSyncIntervalSeconds: () => this.getEffectiveSyncIntervalSeconds(),
      getSyncTimer: () => this.syncTimer,
      setSyncTimer: (timer) => {
        this.syncTimer = timer;
      },
      setSyncTimerPaused: (paused) => {
        this.syncTimerPaused = paused;
      },
      getKeyRenewalTimer: () => this.keyRenewalTimer,
      setKeyRenewalTimer: (timer) => {
        this.keyRenewalTimer = timer;
      },
      getHeartbeatTimer: () => this.heartbeatTimer,
      setHeartbeatTimer: (timer) => {
        this.heartbeatTimer = timer;
      },
      getOfflineQueue: () => this.offlineQueue,
      setOfflineQueue: (queue) => {
        this.offlineQueue = queue;
        // SY5: every queue mutation re-persists the LAK envelope (debounced)
        // so queued edits survive a restart.
        this.scheduleOfflineQueuePersist();
      },
      getOfflineQueueFlushPromise: () => this.offlineQueueFlushPromise,
      setOfflineQueueFlushPromise: (promise) => {
        this.offlineQueueFlushPromise = promise;
      },
      getLocalOnlyCatchupCompleted: () => this.localOnlyCatchupCompleted,
      setLocalOnlyCatchupCompleted: (completed) => {
        this.localOnlyCatchupCompleted = completed;
      },
      getRemoteInventoryRepairCompleted: () => this.remoteInventoryRepairCompleted,
      setRemoteInventoryRepairCompleted: (completed) => {
        this.remoteInventoryRepairCompleted = completed;
      },
      getPlaceholderPaths: () => this.placeholderPaths,
      getPlaceholderPathsSize: () => this.placeholderPaths.size,
      getOfflineQueueLength: () => this.offlineQueue.length,
      getDeletionTombstonesCount: () =>
        Object.keys(this.settings.deletionTombstones ?? {}).length,
      isSyncTimerAlive: () => !!this.syncTimer,
      isSyncTimerPaused: () => this.syncTimerPaused,
      isKeyRenewalTimerAlive: () => !!this.keyRenewalTimer,
      isHeartbeatTimerAlive: () => !!this.heartbeatTimer,
      isConnectionRetryTimerAlive: () => !!this.connectionRetryTimer,
      isConnectionLostNoticeTimerAlive: () => !!this.connectionLostNoticeTimer,
      isApplyingRemoteWrite: () => this.applyingRemoteWrite,
      setApplyingRemoteWrite: (value) => {
        this.applyingRemoteWrite = value;
      },
      isFolderLifecycleListenersRegistered: () =>
        this.folderLifecycleListenersRegistered,
      saveSettings: () => this.saveSettings(),
      isOnline: () => this.isOnline(),
      setConnectionStatus: (status, options) =>
        this.setConnectionStatus(status, options),
      getRemoteFileState: (path) => this.getRemoteFileState(path),
      getExpectedVersionId: (path) => this.getExpectedVersionId(path),
      resolveMutationIntent: (path) => this.resolveMutationIntent(path),
      recordRemoteFilePresent: (path, update) =>
        this.recordRemoteFilePresent(path, update),
      recordRemoteFileAbsent: (path) => this.recordRemoteFileAbsent(path),
      performInitialReconciliation: () => this.performInitialReconciliation(),
      showReconciliationPausedNotice: (reason) => this.showReconciliationPausedNotice(reason),
      hideReconciliationPausedNotice: () => this.hideReconciliationPausedNotice(),
      registerFolderLifecycleListeners: () => this.registerFolderLifecycleListeners(),
      performSync: (options) => this.performSync(options),
      buildLocalSyncManifest: () => this.buildLocalSyncManifest(),
      askReconciliationPlan: (plan) => this.askReconciliationPlan(plan),
      uploadReconciledFile: (path, content, options) =>
        this.uploadReconciledFile(path, content, options),
      ensureAtRestEncryptedInPlace: (path, remoteDurable) =>
        remoteDurable === undefined
          ? this.ensureAtRestEncryptedInPlace(path)
          : this.ensureAtRestEncryptedInPlace(path, remoteDurable),
      getPermissionStoreState: () => this.permissionStore.getStoreState(),
      uploadLocalOnlyFiles: () => this.uploadLocalOnlyFiles(),
      repairMissingRemoteItems: () => this.repairMissingRemoteItems(),
      collectLocalFolderPaths: () => this.collectLocalFolderPaths(),
      localPathExists: (path) => this.localPathExists(path),
      ensureLocalFolderPath: (folderPath) => this.ensureLocalFolderPath(folderPath),
      ensureParentFoldersForPath: (path) => this.ensureParentFoldersForPath(path),
      writeLocalFileFromRemote: (path, content) =>
        this.writeLocalFileFromRemote(path, content),
      syncFileRenameToServer: (oldPath, newPath) =>
        this.syncFileRenameToServer(oldPath, newPath),
      syncFileDeleteToServer: (path) => this.syncFileDeleteToServer(path),
      uploadFolderMarker: (folderPath) => this.uploadFolderMarker(folderPath),
      deleteFolderMarker: (folderPath) => this.deleteFolderMarker(folderPath),
      deleteFolderContentsOnServer: (folderPath) =>
        this.deleteFolderContentsOnServer(folderPath),
      applyRemoteChange: (metadata, prefetchedResponse) =>
        prefetchedResponse === undefined
          ? this.applyRemoteChange(metadata)
          : this.applyRemoteChange(metadata, prefetchedResponse),
      applyRemoteDeletion: (path, inferred) => this.applyRemoteDeletion(path, inferred),
      trashLocalPath: async (path) => {
        const adapter = this.app.vault.adapter;
        if (typeof adapter.trashLocal !== "function") return false;
        try {
          await adapter.trashLocal(path);
          return true;
        } catch (err) {
          this.logError(`Failed to move "${path}" to local trash`, err);
          return false;
        }
      },
      readFileDecrypted: (path, options) =>
        options === undefined
          ? this.readFileDecrypted(path)
          : this.readFileDecrypted(path, options),
      fetchRemoteFileContent: (path, options) =>
        options === undefined
          ? this.fetchRemoteFileContent(path)
          : this.fetchRemoteFileContent(path, options),
      decodeRemoteFileContent: (path, data) =>
        this.decodeRemoteFileContent(path, data),
      readRemotePlaintext: (path) => this.readRemotePlaintext(path),
      resolveReconciliationConflict: (path, strategy, localManifest, prefetchedResponse) =>
        prefetchedResponse === undefined
          ? this.resolveReconciliationConflict(path, strategy, localManifest)
          : this.resolveReconciliationConflict(
              path,
              strategy,
              localManifest,
              prefetchedResponse,
            ),
      hasOriginalAdapterRead: () => !!this.originalAdapterMethods.read,
      hasOriginalAdapterReadBinary: () => !!this.originalAdapterMethods.readBinary,
      // BIN-A / L13: wave-4 pull gate needs write-binary capability so a legacy
      // adapter without writeBinary can never silently drop a downloaded binary.
      hasOriginalAdapterWriteBinary: () =>
        !!this.originalAdapterMethods.writeBinary,
      hasOriginalAdapterWrite: () => !!this.originalAdapterMethods.write,
      hasOriginalAdapterRemove: () => !!this.originalAdapterMethods.remove,
      removeLocalPath: async (path) => {
        if (!this.originalAdapterMethods.remove) return;
        await this.originalAdapterMethods.remove(path);
      },
      readPlainFromDisk: (path) => this.readPlainFromDisk(path),
      readPlainBinaryFromDisk: (path) => this.readPlainBinaryFromDisk(path),
      writePlainToDisk: (path, data) => this.writePlainToDisk(path, data),
      // BIN-A / L13: byte sibling for writeLocalBinaryFileFromRemote's fallback.
      writePlainBinaryToDisk: (path, data) =>
        this.writePlainBinaryToDisk(path, data),
      decryptContent: (content) => this.decryptContent(content),
      bytesToBase64: (bytes) => this.bytesToBase64(bytes),
      notifyCloudDecryptFallback: (path) => this.notifyCloudDecryptFallback(path),
      getEffectivePermission: (path) => this.getEffectivePermission(path),
      emitAuditEvent: (action, resourcePath, metadata) =>
        this.emitAuditEvent(action as AuditAction, resourcePath, metadata),
      encryptContent: (content) => this.encryptContent(content),
      computeHash: (content) => this.computeHash(content),
      // BIN-A / D-02: byte-crypto pass-throughs beside their string siblings for
      // the sync runtime's push (encrypt/hash) and pull (decrypt) byte paths.
      encryptContentBytes: (content) => this.encryptContentBytes(content),
      decryptContentBytes: (content) => this.decryptContentBytes(content),
      computeHashBytes: (content) => this.computeHashBytes(content),
      uploadLargeEncryptedFile: (path, plaintext, contentType, expectedVersionId) =>
        this.uploadLargeEncryptedFile(path, plaintext, contentType, expectedVersionId),
      downloadLargeEncryptedFile: (path, versionId) =>
        versionId === undefined
          ? this.downloadLargeEncryptedFile(path)
          : this.downloadLargeEncryptedFile(path, versionId),
      upsertPendingLargeFile: (record) => this.upsertPendingLargeFile(record),
      clearPendingLargeFile: (path) => this.clearPendingLargeFile(path),
      apiRequest: <T>(
        method: string,
        endpoint: string,
        body?: Record<string, unknown>,
        idTokenOverride?: string,
        options?: { timeoutMs?: number; maxAttempts?: number }
      ) => {
        // L2 (BIN-A): preserve the exact argument arity when no timeout override
        // is passed. Existing callers (and their toHaveBeenCalledWith assertions)
        // must keep seeing the same 2/3/4-arg shapes — trailing `undefined`s
        // change the call signature. Only a real { timeoutMs } widens to 5 args.
        if (options !== undefined) {
          return this.apiRequest<T>(method, endpoint, body, idTokenOverride, options);
        }
        return idTokenOverride !== undefined
          ? this.apiRequest<T>(method, endpoint, body, idTokenOverride)
          : body !== undefined
            ? this.apiRequest<T>(method, endpoint, body)
            : this.apiRequest<T>(method, endpoint);
      },
      vaultPath: (suffix = "") => this.vaultPath(suffix),
      isNetworkError: (error) => this.isNetworkError(error),
      recordSyncDiagnostic: (event, detail) => this.syncDiagnostics.record(event, detail),
      beginLongOperation: (options) => this.beginLongOperation(options),
      getLongOperationConflictKey: () => this.getLongOperationConflictKey(),
      showNotice: (message, timeout) => {
        if (timeout === undefined) {
          new Notice(message);
        } else {
          new Notice(message, timeout);
        }
      },
      showLoginRequiredNotice: (action, path) =>
        this.showLoginRequiredNotice(action, path),
      updateStatusBar: () => this.updateStatusBar(),
      ensureVaultScopedKeyLease: () => this.ensureVaultScopedKeyLease(),
      renewKeyLease: () => this.renewKeyLease(),
      forceLogout: (noticeMessage) => this.forceLogout(noticeMessage),
      invalidatePermissionStore: () => this.permissionStore.invalidate(),
      emitPermissionChanged: (payload) => this.permissionStore.emit("changed", payload),
      clearPlaceholderPaths: () => {
        this.placeholderPaths.clear();
      },
      log: (message) => this.log(message),
      logError: (message, error) => this.logError(message, error),
    };
  }

  private ensureSyncRuntime(): SyncRuntime {
    if (!this.syncRuntime) {
      this.syncRuntime = createSyncRuntime(this.createSyncRuntimeContext());
    }
    return this.syncRuntime;
  }

  private createAgentBridgeRuntimeContext(): AgentBridgeRuntimeContext {
    return {
      app: this.app,
      pluginForModal: this,
      manifestId: this.manifest?.id,
      getSession: () => this.session,
      getServerVaultId: () => this.settings.serverVaultId,
      isLocalProjectMemoryModeEnabled: () => this.isLocalProjectMemoryModeEnabled(),
      getApiClient: () => this.apiClient,
      getSettings: () => this.settings,
      getSyncState: () => this.syncState,
      getConnectionState: () => this.connectionState,
      getOfflineQueueLength: () => this.offlineQueue.length,
      getAtRestCipher: () => this.getAtRestCipher(),
      getVaultOrientationService: () => this.getVaultOrientationService(),
      getAdapterReadBinary: () =>
        this.ensureAtRestAdapterRuntimeObject().getAdapterReadBinary(),
      getAdapterWriteBinary: () =>
        this.ensureAtRestAdapterRuntimeObject().getAdapterWriteBinary(),
      normalizeVaultPath: (path) => this.normalizeVaultPath(path),
      vaultConfigPath: (...parts) => this.vaultConfigPath(...parts),
      ensureParentFoldersForPath: (path) => this.ensureParentFoldersForPath(path),
      isPathExcluded: (path) => this.isPathExcluded(path),
      getEffectivePermission: (path) => this.getEffectivePermission(path),
      isMetadataSuppressed: (path) =>
        this.permissionStore?.isMetadataSuppressed(path) ?? false,
      readText: (path) => this.interceptedRead(path),
      writeText: (path, content) => this.interceptedWrite(path, content),
      deleteFile: (path) => this.interceptedDelete(path),
      renameFile: (oldPath, newPath) => this.interceptedRename(oldPath, newPath),
      emitAudit: (action, resourcePath, metadata) =>
        this.emitAuditEvent(action, resourcePath, metadata),
      log: (message) => this.log(message),
      logError: (message, error) => this.logError(message, error),
    };
  }

  private createAgentBridgeRuntime(): AgentBridgeRuntime {
    return createAgentBridgeRuntime(this.createAgentBridgeRuntimeContext());
  }

  private ensureAgentBridgeRuntimeObject(): AgentBridgeRuntime {
    if (!this.agentBridgeRuntime) {
      this.agentBridgeRuntime = this.createAgentBridgeRuntime();
    }
    return this.agentBridgeRuntime;
  }

  private createRibbonContext(): VaultGuardRibbonContext {
    return {
      addRibbonIcon: (icon, title, callback) =>
        this.addRibbonIcon(icon, title, callback),
      setVaultGuardRibbonEl: (el) => {
        this.vaultGuardRibbonEl = el;
      },
      setVaultGuardChatRibbonEl: (el) => {
        this.vaultGuardChatRibbonEl = el;
      },
      setVaultGuardGraphRibbonEl: (el) => {
        this.vaultGuardGraphRibbonEl = el;
      },
      showVaultGuardMenu: (evt) => this.showVaultGuardMenu(evt),
      updateRibbonAuthIndicator: () => this.updateRibbonAuthIndicator(),
      activateVaultGuardChat: () => this.activateVaultGuardChat(),
      activatePermissionsGraph: () => this.activatePermissionsGraph(),
    };
  }

  private createViewRegistrationContext(): VaultGuardViewRegistrationContext {
    const thisPlugin = this;
    return {
      registerView: (type, viewCreator) => this.registerView(type, viewCreator),
      get sidebarViewConfig() {
        return thisPlugin.sidebarViewConfig;
      },
      pluginForViews: this,
      getSidebarAuthState: () => this.getSidebarAuthState(),
      // Backs the sidebar's W1 pull-getter with the single source of truth so a
      // freshly-instantiated leaf reflects the cipher's CURRENT state on paint.
      getAtRestRecoveryState: () => this.computeAtRestRecoveryState(),
      handleLogin: () => this.handlePrimaryProtectionAction(),
      openVaultGuardSettings: () => this.openVaultGuardSettings(),
      startAtRestRecoveryFlow: () => this.startAtRestRecoveryFlow(),
      startAtRestRecoveryFromRecoveryCode: () =>
        this.startAtRestRecoveryFromRecoveryCode(),
    };
  }

  private createSidebarActivationContext(): VaultGuardSidebarActivationContext {
    return {
      app: this.app,
      isOptionalModuleEnabled: (moduleId) => this.isOptionalModuleEnabled(moduleId),
      ensureOptionalViewRegistered: (moduleId) =>
        this.ensureOptionalViewRegistered(moduleId),
      createSidebarViewConfig: () => this.createSidebarViewConfig(),
      getSidebarViewConfig: () => this.sidebarViewConfig,
      setSidebarViewConfig: (config) => {
        this.sidebarViewConfig = config;
      },
    };
  }

  private createPermissionStoreContext(): PermissionStoreFactoryContext {
    return {
      app: this.app,
      getSession: () => this.session,
      getVaultMemberRole: () => this.vaultMemberRole,
      isOnline: () => this.isOnline(),
      log: (msg) => this.log(msg),
      setConnectionOffline: () => this.setConnectionStatus("offline"),
      fetchPermissionLevelFromServer: (path) => this.fetchPermissionLevelFromServer(path),
      isNetworkError: (err) => this.isNetworkError(err),
      // SD-03-F15 / F16. Arrow functions, so both are read LIVE at call time:
      // this context object is built once during onload, long before any org
      // settings arrive, and a captured snapshot would pin the policy to
      // "absent" forever.
      isAdminRestrictionActive: () => this.isAdminRestrictionActive(),
      requestWarmup: () => this.requestPermissionWarmupRefresh(),
    };
  }

  private createPermissionSurfaceContext(): PermissionSurfaceContext {
    const thisPlugin = this;
    return {
      app: this.app,
      plugin: this,
      registerEvent: (eventRef) => this.registerEvent(eventRef),
      get apiClient() {
        return thisPlugin.apiClient;
      },
      get session() {
        return thisPlugin.session;
      },
      get orgSettings() {
        return thisPlugin.orgSettings;
      },
      get permissionStore() {
        return thisPlugin.permissionStore;
      },
      getEffectiveUiRole: () => this.getEffectiveUiRole(),
      isEffectiveAdmin: () => this.isEffectiveAdmin(),
      getEffectivePermission: (path) => this.getEffectivePermission(path),
      isFileExplorerDecorationDataReady: () => this.isFileExplorerDecorationDataReady(),
      syncFileExplorerDecorationsState: (refresh) =>
        this.syncFileExplorerDecorationsState(refresh),
      isPermissionBannerEnabled: () => this.settings.showPermissionBanner,
      isOnline: () => this.isOnline(),
      reconnectNow: () => this.reconnectNow(),
    };
  }

  private createCommandContext(): VaultGuardCommandContext {
    const thisPlugin = this;
    return {
      app: this.app,
      logPrefix: LOG_PREFIX,
      addCommand: (command) => {
        this.addCommand(command);
      },
      registerEvent: (eventRef) => {
        this.registerEvent(eventRef);
      },
      onFileMenu: (callback) => this.app.workspace.on("file-menu", callback),
      get session() {
        return thisPlugin.session;
      },
      get apiClient() {
        return thisPlugin.apiClient;
      },
      get settings() {
        return thisPlugin.settings;
      },
      get connectionState() {
        return thisPlugin.connectionState;
      },
      get syncState() {
        return thisPlugin.syncState;
      },
      get syncDiagnostics() {
        return thisPlugin.syncDiagnostics;
      },
      get manifestVersion() {
        return thisPlugin.manifest.version;
      },
      get folderLifecycleListenersRegistered() {
        return thisPlugin.folderLifecycleListenersRegistered;
      },
      get syncTimerAlive() {
        return !!thisPlugin.syncTimer;
      },
      get localOnlyCatchupCompleted() {
        return thisPlugin.localOnlyCatchupCompleted;
      },
      get keyLease() {
        return thisPlugin.keyLease;
      },
      get vaultLeaseDenied() {
        return thisPlugin.vaultLeaseDenied;
      },
      get placeholderPathsSize() {
        return thisPlugin.placeholderPaths.size;
      },
      get offlineQueueLength() {
        return thisPlugin.offlineQueue.length;
      },
      get offlineQueueSnapshot() {
        return thisPlugin.offlineQueue.map((op) => ({
          operation: op.operation,
          path: op.path,
          timestamp: op.timestamp,
          dataBytes: op.data?.length ?? 0,
          // BIN-A / D-11: carry the byte-vs-string discriminant (not the payload)
          // so the attachment debug report can separate legitimate byte-path
          // binary writes from AR1 string-pipeline regressions.
          encoding: op.encoding,
        }));
      },
      get deletionTombstonesCount() {
        return Object.keys(thisPlugin.settings.deletionTombstones ?? {}).length;
      },
      get pluginId() {
        return thisPlugin.manifest.id;
      },
      get localProjectMemoryMode() {
        return thisPlugin.isLocalProjectMemoryModeEnabled();
      },
      get vaultMemberRole() {
        return thisPlugin.vaultMemberRole;
      },
      isOptionalModuleEnabled: (moduleId) =>
        this.isOptionalModuleEnabled(moduleId),
      get permissionStore() {
        return thisPlugin.permissionStore;
      },
      get updateChecker() {
        return thisPlugin.updateChecker;
      },
      handleLogin: () => this.handleLogin(),
      forceLogout: (noticeMessage) => this.forceLogout(noticeMessage),
      isSessionTokenExpiring: () =>
        this.session ? this.isSessionTokenExpiring(this.session) : false,
      performSync: (options) => this.performSync(options),
      getEffectivePermission: (path) => this.getEffectivePermission(path),
      runConnectionDiagnostics: () => this.runConnectionDiagnostics(),
      featureEnabled: (name) => this.featureEnabled(name),
      isEffectiveAdmin: () => this.isEffectiveAdmin(),
      openShareManagementModal: () => this.openShareManagementModal(),
      showStatusNotice: () => this.showStatusNotice(),
      showVaultGuardMenu: (evt) => this.showVaultGuardMenu(evt),
      openAuditLog: () => this.openAuditLog(),
      openWebAdminPanel: () => this.openWebAdminPanel(),
      openVaultGuardSettings: () => this.openVaultGuardSettings(),
      showPermissionsModal: () => this.showPermissionsModal(),
      showPermissionRulesModal: (initialSearch) => this.showPermissionRulesModal(initialSearch),
      activateVaultGuardSidebar: () => this.activateVaultGuardSidebar(),
      openAgentBridgeLeaseModal: () => this.openAgentBridgeLeaseModal(),
      revokeAllAgentBridgeLeases: () => this.revokeAllAgentBridgeLeases(),
      stopAgentBridgeServer: () => this.stopAgentBridgeServer(),
      encryptVaultAtRest: () => this.encryptVaultAtRest(),
      decryptVaultAtRest: () => this.decryptVaultAtRest(),
      decryptVaultAndDisableAtRestEncryption: async () => {
        await this.decryptVaultAndDisableAtRestEncryption();
      },
      enableLocalProjectMemoryMode: () => this.enableLocalProjectMemoryMode(),
      switchServerVault: () => this.switchServerVault(),
      showAdminPanel: () => this.showAdminPanel(),
      showPathPermissionsModal: (path, isFolder, initialExplain) =>
        this.showPathPermissionsModal(path, isFolder, initialExplain),
      showAddPermissionForPath: (path, isFolder) =>
        this.showAddPermissionForPath(path, isFolder),
      copyShareLinkForPath: (path) => this.copyShareLinkForPath(path),
      activateVaultGuardChat: () => this.activateVaultGuardChat(),
      activatePermissionsGraph: () => this.activatePermissionsGraph(),
      openPermissionsGraphVirtualQaModal:
        process.env.NODE_ENV !== "production"
          ? async () => {
              try {
                if (Platform.isMobileApp || !this.settings.debugLogging) return;
                const { PermissionsGraphVirtualQaModal } = await import(
                  "../ui/graph/permissions-graph-qa-modal"
                );
                if (Platform.isMobileApp || !this.settings.debugLogging) return;

                this.permissionsGraphVirtualQaModal?.close();
                const modal = new PermissionsGraphVirtualQaModal(this.app, {
                  onClosed: (closedModal) => {
                    if (this.permissionsGraphVirtualQaModal === closedModal) {
                      this.permissionsGraphVirtualQaModal = null;
                    }
                  },
                });
                this.permissionsGraphVirtualQaModal = modal;
                modal.open();
              } catch (error) {
                this.logError("Opening virtual permissions graph QA failed", error);
                new Notice(
                  "VaultGuard Sync: the virtual permissions graph QA window could not be opened. Check the developer console for details.",
                  8000
                );
              }
            }
          : async () => {},
      openVaultGuardChatHistory: () => this.openVaultGuardChatHistory(),
      openNewVaultGuardChatTab: () => this.openNewVaultGuardChatTab(),
      copyVaultGuardChatDomDebugReport: () => this.copyVaultGuardChatDomDebugReport(),
      // Ternary (not just a guarded call) so the production define folds this
      // to a no-op and esbuild tree-shakes the whole chat-debug-command module
      // (incl. its prompt strings) out of the release bundle.
      registerChatDebugCommand:
        process.env.NODE_ENV !== "production"
          ? () => registerChatDebugCommand(this)
          : () => {},
      // Ternary (not a guarded call) so the production define folds this to a
      // no-op and esbuild tree-shakes the standalone diagnostic out of the
      // release bundle — mirrors registerChatDebugCommand above.
      collectAttachmentPreviewData:
        process.env.NODE_ENV !== "production"
          ? (limit) => {
              const adapter = this.app.vault.adapter as unknown as {
                getResourcePath?: ((p: string) => string) & { __vaultguard?: boolean };
              };
              return collectAttachmentPreviewData(
                {
                  files: this.app.vault
                    .getFiles()
                    .map((f) => ({ path: f.path, extension: f.extension })),
                  getResourcePath: (p) =>
                    adapter.getResourcePath
                      ? adapter.getResourcePath(p)
                      : "(getResourcePath unavailable)",
                  rawReadBinary: this.originalAdapterMethods.readBinary ?? undefined,
                  readDecrypted: (p) => this.readPlainBinaryFromDisk(p),
                  // The plugin overrides read/write/readBinary/... but NOT
                  // getResourcePath; a future preview fix tags its override with
                  // __vaultguard, flipping this true.
                  getResourcePathIntercepted: !!adapter.getResourcePath?.__vaultguard,
                  readBinaryIntercepted: !!this.originalAdapterMethods.readBinary,
                  atRestActive: !!this.atRestCipher?.isReady(),
                },
                limit
              );
            }
          : (): Promise<AttachmentPreviewReport> =>
              Promise.resolve({
                getResourcePathIntercepted: false,
                readBinaryIntercepted: false,
                atRestActive: false,
                totalAttachments: 0,
                analyzed: [],
              }),
      ensureParentFoldersForPath: (path) => this.ensureParentFoldersForPath(path),
      logError: (message, error) => this.logError(message, error),
    };
  }

  private createLifecycleEventsContext(): LifecycleEventsContext {
    const thisPlugin = this;
    const registerDomEvent = this.registerDomEvent.bind(this) as (
      target: Window | Document,
      type: string,
      callback: EventListenerOrEventListenerObject,
      options?: boolean | AddEventListenerOptions,
    ) => void;

    return {
      app: this.app,
      logPrefix: LOG_PREFIX,
      protocolHost: this as unknown as LifecycleEventsContext["protocolHost"],
      registerEvent: (eventRef) => {
        this.registerEvent(eventRef);
      },
      registerDomEvent: (target, type, callback, options) => {
        registerDomEvent(target, type, callback, options);
      },
      registerInterval: (id) => {
        this.registerInterval(id);
      },
      get session() {
        return thisPlugin.session;
      },
      get settings() {
        return thisPlugin.settings;
      },
      get syncState() {
        return thisPlugin.syncState;
      },
      get permissionStore() {
        return thisPlugin.permissionStore;
      },
      get folderLifecycleListenersRegistered() {
        return thisPlugin.folderLifecycleListenersRegistered;
      },
      setFolderLifecycleListenersRegistered: (registered) => {
        this.folderLifecycleListenersRegistered = registered;
      },
      get obsidianSyncNotice() {
        return thisPlugin.obsidianSyncNotice;
      },
      setObsidianSyncNotice: (notice) => {
        this.obsidianSyncNotice = notice;
      },
      get syncDiagnostics() {
        return thisPlugin.syncDiagnostics;
      },
      redeemInvite: (params) => this.redeemInvite(params),
      handleShareLink: (params) => this.handleShareLink(params),
      reloadVaultGuardSidebar: () => this.reloadVaultGuardSidebar(),
      ensureVaultGuardSidebar: () => this.ensureVaultGuardSidebar(),
      noteSessionActivity: () => this.noteSessionActivity(),
      handleFocusSyncTrigger: () => this.handleFocusSyncTrigger(),
      resumeSyncLoop: (reason) => this.resumeSyncLoop(reason),
      pauseSyncLoop: (reason) => this.pauseSyncLoop(reason),
      isVaultLocked: () => this.isVaultLocked,
      handleBrowserOnline: () => this.handleBrowserOnline(),
      handleBrowserOffline: () => this.handleBrowserOffline(),
      handleFolderCreated: (path) => this.handleFolderCreated(path),
      handleFolderDeleted: (path) => this.handleFolderDeleted(path),
      handleFolderRenamed: (path, oldPath) =>
        this.handleFolderRenamed(path, oldPath),
      handleVaultFileRenamed: (path, oldPath) =>
        this.handleVaultFileRenamed(path, oldPath),
      handleVaultFileDeleted: (path) => this.handleVaultFileDeleted(path),
      log: (message) => this.log(message),
      logError: (message, error) => this.logError(message, error),
    };
  }

  private getSettingsRuntime(): PluginSettingsRuntime {
    if (!this.settingsRuntime) {
      this.settingsRuntime = createPluginSettingsRuntime(
        this.createSettingsRuntimeContext(),
      );
    }
    return this.settingsRuntime;
  }

  private createSettingsRuntimeContext(): PluginSettingsRuntimeContext {
    const thisPlugin = this;
    return {
      app: this.app,
      loadData: () => this.loadData(),
      saveData: (data) => this.saveData(data),
      savePluginData: () => this.savePluginData(),
      get settings() {
        return thisPlugin.settings;
      },
      setSettings: (settings) => {
        this.settings = settings;
      },
      get persistedSessions() {
        return thisPlugin.persistedSessions;
      },
      setPersistedSessions: (sessions) => {
        this.persistedSessions = sessions;
      },
      get pluginDataSaveQueue() {
        return thisPlugin.pluginDataSaveQueue;
      },
      setPluginDataSaveQueue: (queue) => {
        this.pluginDataSaveQueue = queue;
      },
      get configuredApiEndpoint() {
        return thisPlugin.configuredApiEndpoint;
      },
      setConfiguredApiEndpoint: (endpoint) => {
        this.configuredApiEndpoint = endpoint;
      },
      get resolvedApiEndpoint() {
        return thisPlugin.resolvedApiEndpoint;
      },
      setResolvedApiEndpoint: (endpoint) => {
        this.resolvedApiEndpoint = endpoint;
      },
      get apiEndpointResolutionPromise() {
        return thisPlugin.apiEndpointResolutionPromise;
      },
      setApiEndpointResolutionPromise: (promise) => {
        this.apiEndpointResolutionPromise = promise;
      },
      get serverEdition() {
        return thisPlugin.serverEdition;
      },
      setServerEdition: (edition) => {
        this.serverEdition = edition;
      },
      get serverFeatures() {
        return thisPlugin.serverFeatures;
      },
      setServerFeatures: (features) => {
        this.serverFeatures = features;
      },
      get derivedBindingId() {
        return thisPlugin.derivedBindingId;
      },
      setDerivedBindingId: (bindingId) => {
        this.derivedBindingId = bindingId;
      },
      get apiClient() {
        return thisPlugin.apiClient;
      },
      setApiClient: (apiClient) => {
        this.apiClient = apiClient;
      },
      get session() {
        return thisPlugin.session;
      },
      setSession: (session) => {
        this.session = session;
      },
      get vaultMemberRole() {
        return thisPlugin.vaultMemberRole;
      },
      get atRestCipher() {
        return thisPlugin.atRestCipher;
      },
      get safeStorageUnavailableNotified() {
        return thisPlugin.safeStorageUnavailableNotified;
      },
      setSafeStorageUnavailableNotified: (notified) => {
        this.safeStorageUnavailableNotified = notified;
      },
      computeHash: (content) => this.computeHash(content),
      pruneDeletionTombstones: () => this.pruneDeletionTombstones(),
      protectSessionForStorage: (session) => this.protectSessionForStorage(session),
      protectSessionWithAtRest: (session) => this.protectSessionWithAtRest(session),
      forceLogout: (noticeMessage) => this.forceLogout(noticeMessage),
      refreshAccessToken: (session) => this.refreshAccessToken(session),
      initializeApiClientFromSession: (session) =>
        this.initializeApiClientFromSession(session),
      resolveRequestSessionId: () => this.resolveRequestSessionId(),
      log: (message) => this.log(message),
      logError: (message, error) => this.logError(message, error),
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Lifecycle
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Called by Obsidian when the plugin is activated.
   * Initializes authentication, sync engine, commands, and vault interception.
   */
  async onload(): Promise<void> {
    this.unloading = false;
    this.lifecycleGeneration += 1;
    this.log("Loading VaultGuard plugin...");
    this.syncDiagnostics.record("onload.start", { mobile: Platform.isMobileApp });

    // Register the ribbon buttons SYNCHRONOUSLY, up front, before the first
    // `await`. Ribbon buttons created *after* an await can be appended after
    // Obsidian has already taken its initial ribbon snapshot.
    registerVaultGuardRibbons(this.createRibbonContext());
    // Once the workspace (and thus the ribbon) is built, enforce the VaultGuard
    // icon order (shield -> chat -> graph) and the show/hide preference. This
    // runs AFTER Obsidian applies any per-vault ribbon order it persisted, so the
    // plugin gets the last word on grouping rather than depending on Obsidian's
    // saved order (which drifts when icons are added/removed across versions).
    const ribbonWorkspace = this.app.workspace;
    if (typeof ribbonWorkspace.onLayoutReady === "function") {
      ribbonWorkspace.onLayoutReady(() => this.applyRibbonIconLayout());
    } else {
      this.applyRibbonIconLayout();
    }

    // (sd4) The sd2 "Import local files" ribbon was retired. Importing is now an
    // agent-driven chat slash command (/import-knowledge) inside the AI chat
    // panel — the agent surveys the picked folder through a gated, sandboxed
    // source-read tool and builds an organized KB, rather than dumping files 1:1.

    // Register the stable core view before the first await so a preserved leaf
    // is never left as "Plugin no longer active" while startup initializes.
    // Optional views remain behind their cipher/settings prerequisites.
    registerVaultGuardViews(this.createViewRegistrationContext());

    // Load persisted settings
    await this.loadSettings();
    // Ribbon nodes are registered before the first await so Obsidian sees them
    // during its initial layout snapshot. Re-apply visibility after settings
    // load so persisted per-icon choices take effect without destroying those
    // node references.
    this.applyRibbonIconLayout();

    this.longOperationUi = new LongOperationUiController(this.app, this.longOperations);
    this.longOperationUi.start();
    this.longOperationStatusUnsubscribe = this.longOperations.subscribe(() => {
      this.updateStatusBar();
    });

    // Check for Obsidian Sync — VaultGuard is the sole sync/backup provider
    this.checkForObsidianSync();

    // Register the settings tab
    this.settingTab = new VaultGuardSettingTab(this.app, this);
    this.addSettingTab(this.settingTab);

    // Initialize the status bar from the canonical presentation mode.
    this.applyStatusBarMode();

    // Create API client (tokens are set later during session restore or login)
    this.rebuildApiClient();

    // Cross-device AI-chat key sync. Holds only a plugin reference and reads
    // its context (api client / session / bound vault) lazily at call time, so
    // it stays inert until a session + vault + lease exist (§11).
    this.aiKeySync = new ApiKeySync(this);

    // Phase 9: construct the unified permission store. The store does not
    // hold an apiClient reference (see PermissionStoreConfig note) — all
    // server probes go through the injected `fetchPermissionLevelFromServer`
    // callback, which itself checks `this.apiClient` and `this.session` at
    // call time. This is the correct nullability boundary: it lets onload()
    // succeed even when `apiEndpoint` is empty (manual / Community-edition
    // first-run). Must precede any init* method that subscribes via
    // `this.registerEvent(this.permissionStore.on('changed', ...))`.
    this.permissionStore = createPermissionStore(this.createPermissionStoreContext());
    this.registerEvent(
      this.permissionStore.on("changed", (...data: unknown[]) => {
        const payload = data[0] as {
          path?: string;
          serverConfirmed?: boolean;
          semanticAuthorityChanged?: boolean;
        } | undefined;
        if (
          payload?.serverConfirmed === true &&
          payload.semanticAuthorityChanged === true &&
          this.isOptionalModuleEnabled("secureDiscovery") &&
          this.settings.semanticSearchEnabled === true
        ) {
          // A confirmed authorization change invalidates every persisted vector.
          // Purge through the LAK-backed store while the session/cipher boundary
          // is still available; no provider request is made by this path.
          void this.purgeSemanticRuntime("manual").catch((error) =>
            this.logError("Purging semantic index after confirmed permission change failed", error),
          );
          return;
        }
        this.semanticRuntime?.handlePermissionInvalidation(payload?.path);
      }),
    );

    // Local file events only mark/remove in-memory semantic entries. They never
    // call the embedding provider; rebuilds remain explicit user actions.
    this.registerEvent(
      this.app.vault.on("create", (file) => {
        if (file instanceof TFile && file.extension.toLocaleLowerCase("en-US") === "md") {
          this.semanticRuntime?.markFileChanged(file.path);
        }
      }),
    );
    this.registerEvent(
      this.app.vault.on("modify", (file) => {
        if (file instanceof TFile && file.extension.toLocaleLowerCase("en-US") === "md") {
          this.semanticRuntime?.markFileChanged(file.path);
        }
      }),
    );
    this.registerEvent(
      this.app.vault.on("delete", (file) => {
        if (file instanceof TFile && file.extension.toLocaleLowerCase("en-US") === "md") {
          this.semanticRuntime?.removeFile(file.path);
        }
      }),
    );
    this.registerEvent(
      this.app.vault.on("rename", (file, oldPath) => {
        if (oldPath.toLocaleLowerCase("en-US").endsWith(".md")) {
          this.semanticRuntime?.removeFile(oldPath);
        }
        if (file instanceof TFile && file.extension.toLocaleLowerCase("en-US") === "md") {
          this.semanticRuntime?.markFileChanged(file.path);
        }
      }),
    );

    // Install the adapter intercept BEFORE any awaited startup work. Reads that
    // Obsidian fires during plugin load (workspace restore, initial indexer)
    // would otherwise go through the un-intercepted adapter and could return
    // raw VG1 ciphertext as a UTF-8 string, which the editor would then
    // re-save through the encryption path and permanently corrupt the file.
    // Early reads route through readPlainFromDisk, which fails closed via
    // `cipherInitPromise` until init settles.
    this.interceptVaultAdapter();

    // Evaluate the shared repo-root default after raw adapter methods are
    // captured for its fail-closed protection inspection and before local
    // at-rest initialization can provision or unlock protection.
    await this.maybeAutoEnableLocalProjectMemoryMode();

    // Discover Git repository plaintext boundaries only after raw adapter
    // delegates are captured, and before local at-rest initialization can
    // encrypt a repository write. This never changes Local Project Memory Mode.
    const startupRepositoryDetection = await this.refreshDetectedGitRepositoryRoots();
    if (!startupRepositoryDetection.complete) {
      new Notice(
        `VaultGuard Sync: Git repository folder detection was incomplete during startup after ${startupRepositoryDetection.scannedEntries} entries. Undiscovered folders keep normal local encryption.`,
        10000,
      );
    }

    // BIN-A preview: pre-decrypt an opened media file into the resource-preview
    // blob cache so standalone image/PDF views get a synchronous getResourcePath
    // cache hit instead of a broken-then-repaint flash. Guarded inside the
    // runtime (no-ops unless at-rest is active and the file is renderable media).
    this.registerEvent(
      this.app.workspace.on("file-open", (file) => {
        if (!file) return;
        this.noticeIfMediaOpenWhileLoggedOut(file.path);
        void this.prewarmAttachmentPreview(file.path);
      })
    );

    // Bring up the local at-rest cipher BEFORE restoring the session. On
    // mobile (no Electron `safeStorage`), session blobs are sealed with the
    // LAK rather than the OS keystore, so we need the cipher ready to
    // decrypt them. On desktop with a working safeStorage the session
    // decrypts via the synchronous path and doesn't touch the cipher.
    // If init fails (no keychain on this device, broken wrap) we surface
    // the reason in a Notice and continue in degraded plaintext mode so
    // the plugin remains usable while the user investigates.
    //
    // Recover same-device uninstall state before constructing the PIN manager:
    // the sealed capsule may restore its envelope + pepper/settings. Binding is
    // only a hint and remains hard-gated until exact-vault authorization.
    await this.restoreLocalRecoveryBeforeCipherInit();

    // Phase 12: construct the PIN-lock manager FIRST so initAtRestCipher's
    // PIN-lock pre-check (isPinLockEnrolled) can land the vault LOCKED instead of
    // provisioning/needs-recovery when a PIN owns the LAK (edge #6).
    this.initPinLockManager();
    await this.initAtRestCipher();
    await this.finalizeRecoveredLocalProtection();
    const startupRepositoryTransition = await this.convertDetectedGitRepositoryCiphertext();
    if (startupRepositoryTransition.failed > 0) {
      new Notice(
        `VaultGuard Sync: ${startupRepositoryTransition.failed} detected repository file(s) could not be converted to plaintext during startup and remain protected. Review the console before using external Git tools.`,
        12000,
      );
    }

    // SY5: restore queued offline operations (LAK-encrypted envelope) so
    // limited-access/offline edits survive a restart instead of evaporating
    // with the in-memory queue. Fire-and-forget — it waits for cipher init
    // internally and merges under any ops queued while it loads. The handle
    // is kept so collectUnsyncedLocalChanges can await the restore before
    // trusting an empty queue (quick-260820-ki7); the method catches
    // internally, and the defensive no-op catch keeps an unhandled rejection
    // structurally impossible.
    this.offlineQueueLoadPromise = this.loadPersistedOfflineQueue().catch(() => undefined);
    void this.offlineQueueLoadPromise;
    void this.loadPersistedRemoteFileState();

    // Restore session — synchronous safeStorage path first, async at-rest
    // path second. On desktop this is effectively zero-cost; on mobile it
    // adds a single AES-GCM decrypt (a few ms).
    await this.restoreSession();
    // Backfill healthy legacy installs and enrich a restored capsule with the
    // authenticated account identity once a session is available.
    void this.persistLocalRecoveryCapsule();

    // Phase 12-07 (passkey model): if a session was just restored, show the lock
    // curtain ONLY when the vault could not unlock transparently — the cipher is not
    // ready (legacy PIN device with no transparent wrap, or a corrupt wrap) OR the
    // user opted into "Require PIN on startup". A passkey-model device (transparent
    // lak.envelope present, toggle off) unlocked already in initAtRestCipher, so no
    // curtain and no double-auth. maybeEnterLockOnAuth mirrors the adapter's
    // landLocked decision, so an enrolled device that DID land locked still curtains
    // (H-1 dead-vault protection). idleAction is irrelevant here — it governs only
    // the live-session idle→lock transition, not this restart/login unlock.
    this.maybeEnterLockOnAuth();

    // P1a completion (mobile): on mobile the session is at-rest-sealed, so if the
    // cipher landed LOCKED before restoreSession ran (a lost fallback KEK routed
    // to the PIN via P1a-core, or a legacy/max-security PIN device), the session
    // could not be decrypted and this.session is null — so maybeEnterLockOnAuth
    // (which requires a session) did NOT curtain, leaving the user stranded with
    // no visible unlock. Show the PIN curtain so they can unlock and recover the
    // session (recoverSessionAfterPinUnlock re-runs restoreSession once the LAK
    // is back).
    this.maybeEnterPinRecoveryCurtain();

    // Wire the folder-lifecycle vault listeners NOW, unconditionally, decoupled
    // from sync-engine init. This is the fix for folder deletes never reaching
    // the server: registration used to live only inside initializeSyncEngine(),
    // which is not guaranteed to run on every session (e.g. when the binding is
    // already reconciled and restoreServerSession never reaches it), so the
    // per-child `vault.on('delete')` listeners were silently never wired and
    // folder/child deletes were never propagated. The listener bodies all
    // self-guard on `if (!this.settings.serverVaultId || !this.session) return;`
    // and the method is idempotent (folderLifecycleListenersRegistered), so it
    // is safe to call here at load time AND from initializeSyncEngine().
    this.syncDiagnostics.record("onload.registerFolderListenersEarly", {
      hasSession: !!this.session,
      hasServerVaultId: !!this.settings.serverVaultId,
    });
    this.registerFolderLifecycleListeners();

    // Blocked-window mutation tracker (quick-260820-ki7): while the binding
    // sits blocked (account-changed / wrong-account), stamp every vault
    // mutation Obsidian observes so the takeover lane's cleanliness check can
    // refuse the automatic reset. Registered in onload unconditionally,
    // mirroring the folder-lifecycle listeners above (c2be477) — a listener
    // that only exists when the sync engine initialized would miss exactly
    // the blocked sessions it is for.
    this.registerBlockedWindowMutationTracker();

    // Auto-encrypt externally-added files (Finder drops, git checkouts,
    // other tools writing into the vault folder): Obsidian indexes them and
    // fires vault.on("create"), but their bytes never passed through the
    // encrypting adapter, so they'd sit on disk as plaintext until first
    // save (lazy migration). Re-encrypt the identical bytes in place
    // instead. The layoutReady gate skips the initial-index flood (every
    // existing file fires "create" at startup); files added while Obsidian
    // was closed are covered by the catch-up hook in sync-runtime.
    this.registerEvent(
      this.app.vault.on("create", (file) => {
        if (!this.app.workspace.layoutReady) return;
        void this.encryptExternallyAddedFile(file.path);
      })
    );

    // HI-01 self-clean: the instant a path re-appears (reconcile re-pulled it,
    // or the user created a new file there), drop its wipe-delete suppression so
    // a genuine later delete of that path propagates. Deliberately UNGATED (no
    // layoutReady gate) and ordering-independent — it only ever mutates this
    // vault's tiny entry in the cross-instance wipe-suppression registry
    // (SD-07-F4) and is a no-op unless a reset just ran.
    this.registerEvent(
      this.app.vault.on("create", (file) => {
        this.clearWipeSuppressionForRecreatedPath(file.path);
      })
    );

    // Capabilities are public metadata. Refresh them in the background so
    // manual/self-hosted installs and restored sessions don't temporarily
    // fall back to the historic Pro UI after a restart.
    void this.refreshServerCapabilitiesFromConfiguredEndpoint().catch((err) => {
      this.logError("Server capability refresh failed", err);
    });

    // Track local activity so org auto-lock policies can be enforced.
    this.registerSessionActivityTracking();

    // Pull latest server state whenever the user comes back to Obsidian so
    // multi-user vaults feel live without paying for WebSocket infra. Pure
    // polling lags by the sync interval (10 s realtime / 60 s+ periodic);
    // a focus-triggered sync collapses that to ~immediate when it matters.
    this.registerFocusSyncHandlers();

    // (moved earlier — interceptVaultAdapter() now runs before initAtRestCipher()
    //  so adapter reads issued during plugin startup route through the guarded path.)

    // Restore persistent agent bridge leases (encrypted on disk via the LAK)
    // for the current session. Fire-and-forget so any persistence error
    // doesn't block the rest of plugin startup. Only persistent leases that
    // match this session's userId+vaultId are restored; orphans are dropped.
    if (
      !this.isLocalProjectMemoryModeEnabled() &&
      this.isOptionalModuleEnabled("agentAccess")
    ) {
      void this.restorePersistentAgentBridgeLeases();
    }

    // Register plugin commands
    this.registerCommands();

    this.registerInviteProtocolHandler();
    this.registerShareProtocolHandler();

    // Initialize file permission header (shows per-file access in markdown views)
    this.initFilePermissionHeader();

    // Lock the editor for files the user can't write — prevents view-only
    // users from accumulating edits that fail at save time.
    this.initReadOnlyGuard();

    await this.registerEnabledOptionalViews();

    // Phase 9: subscribe the sidebar to the unified permission bus. One
    // emit fans out to decorations + header + sidebar + readOnlyGuard.
    registerSidebarPermissionLifecycle(this.createLifecycleEventsContext());

    // Build sidebar config from current session (if restored)
    const sidebarConfig = this.createSidebarViewConfig();
    if (sidebarConfig) {
      this.sidebarViewConfig = sidebarConfig;
    }
    // A persisted sidebar leaf may have opened against the synchronous shell
    // before settings/session restore. Rehydrate it now without a manual close.
    this.reloadVaultGuardSidebar();

    // Initialize file explorer decorations (permission dots + avatar stacks)
    this.initFileExplorerDecorations();

    // Restore server-side session state and encryption lease in background.
    if (this.session) {
      const resumePromise = this.resumeStoredSession().catch((err) => {
        this.logError("Background session restore failed", err);
      });
      this.sessionResumePromise = resumePromise;
      resumePromise.finally(() => {
        if (this.sessionResumePromise === resumePromise) {
          this.sessionResumePromise = null;
        }
        // THE STARTUP BACKSTOP. `resumeStoredSession` has several early returns
        // and one rethrow (`restoreServerSession` → `openServerSession` throws
        // on any non-2xx or network failure) that land BEFORE
        // `startHeartbeatMonitor()` / `startKeyRenewalMonitor()` and before the
        // "online" flip. Reaching here unfinished therefore means the process
        // owns a session but has no liveness loop of any kind. Put a probe on
        // the schedule; `attemptReconnection` finishes the resume from there.
        this.armResumeRetryIfIncomplete();
      });
    }

    if (this.settings.debugLogging) {
      const loadBanner = `VaultGuard v${this.manifest.version} (sync-rev ${SYNC_FEATURE_REVISION}) loaded`;
      new Notice(loadBanner, 2500);
    }

    this.updateChecker = new UpdateChecker(this);

    this.log("VaultGuard plugin loaded successfully.");
  }

  async onExternalSettingsChange(): Promise<void> {
    const previousReload = this.externalSettingsReload ?? Promise.resolve();
    const reload = previousReload
      .catch(() => {
        // A prior external reload already surfaced its own failure. Continue
        // with the latest disk state instead of permanently wedging updates.
      })
      .then(() => this.applyExternalSettingsChange());
    this.externalSettingsReload = reload;
    try {
      await reload;
    } finally {
      if (this.externalSettingsReload === reload) {
        this.externalSettingsReload = null;
      }
    }
  }

  private async applyExternalSettingsChange(): Promise<void> {
    const before = this.settings;
    const previousModules = { ...before.optionalModules };
    const previousSemanticSearchEnabled = before.semanticSearchEnabled === true;
    const previousSemanticEmbeddingEndpoint = before.semanticEmbeddingEndpoint;
    const previousSemanticEmbeddingModel = before.semanticEmbeddingModel;
    const previousSyncInterval = before.syncInterval;
    const previousStatusBarMode = this.getStatusBarMode();
    const previousAiChatRibbonVisibility = this.shouldShowAiChatRibbonIcon();
    const previousPermissionsGraphRibbonVisibility =
      this.shouldShowPermissionsGraphRibbonIcon();
    const previousConnection = snapshotConnectionBoundary(before);

    await this.getSettingsRuntime().loadSettings("external");

    const connectionChanged = didConnectionBoundaryChange(
      previousConnection,
      this.settings,
    );
    if (this.session && connectionChanged) {
      Object.assign(this.settings, previousConnection);
      await this.getSettingsRuntime().saveSettings();
      new Notice(
        "VaultGuard Sync: synchronized connection or vault changes were not applied while signed in. Sign out before changing that security boundary.",
        9000,
      );
    } else if (connectionChanged) {
      this.rebuildApiClient();
    }

    // Obsidian can emit this hook for a file touch or a same-value rewrite.
    // Avoid rebuilding every settings section (and restarting its async UI)
    // when the effective settings did not actually change.
    if (!didExternallyLoadedSettingsChange(before, this.settings)) {
      return;
    }

    let externalSemanticAlreadyPurged = false;
    if (
      previousModules.secureDiscovery === true &&
      this.settings.optionalModules?.secureDiscovery !== true
    ) {
      try {
        await this.purgeSemanticRuntime("disable");
        externalSemanticAlreadyPurged = true;
      } catch (error) {
        this.settings.optionalModules = {
          ...this.settings.optionalModules,
          secureDiscovery: true,
        };
        await this.getSettingsRuntime().saveSettings();
        throw error;
      }
    }

    await this.reconcileOptionalModuleSettings(
      previousModules,
      externalSemanticAlreadyPurged,
    );

    const secureDiscoveryDisabled =
      previousModules.secureDiscovery === true &&
      this.settings.optionalModules?.secureDiscovery !== true;
    const secureDiscoveryEnabled = this.settings.optionalModules?.secureDiscovery === true;
    const semanticDisabled =
      previousSemanticSearchEnabled && this.settings.semanticSearchEnabled !== true;
    const semanticProviderChanged =
      previousSemanticEmbeddingEndpoint !== this.settings.semanticEmbeddingEndpoint ||
      previousSemanticEmbeddingModel !== this.settings.semanticEmbeddingModel;
    if (
      !secureDiscoveryDisabled &&
      secureDiscoveryEnabled &&
      (semanticDisabled || semanticProviderChanged)
    ) {
      await this.purgeSemanticRuntime(semanticDisabled ? "disable" : "provider-change");
    }
    if (
      previousSemanticSearchEnabled !== (this.settings.semanticSearchEnabled === true) ||
      semanticProviderChanged
    ) {
      this.notifyDiscoveryLifecycleChanged();
    }

    if (this.settings.syncInterval !== previousSyncInterval && this.session) {
      this.restartSyncTimer();
    }
    if (this.getStatusBarMode() !== previousStatusBarMode) {
      this.applyStatusBarMode();
    } else {
      this.updateStatusBar();
    }
    if (
      this.shouldShowAiChatRibbonIcon() !== previousAiChatRibbonVisibility ||
      this.shouldShowPermissionsGraphRibbonIcon() !==
        previousPermissionsGraphRibbonVisibility
    ) {
      this.applyRibbonIconLayout();
    }

    this.refreshFileExplorerDecorations();
    this.refreshFilePermissionHeader();
    this.reloadVaultGuardSidebar();
    this.updateRibbonAuthIndicator();
    this.vaultOrientationService?.invalidate("external-settings-changed");
    if (this.settingTab?.containerEl?.isConnected) {
      this.settingTab.display();
    }
  }

  private async reconcileOptionalModuleSettings(
    previous: VaultGuardSettings["optionalModules"],
    semanticAlreadyPurged = false,
  ): Promise<void> {
    for (const moduleId of [
      "aiChat",
      "permissionsGraph",
      "agentAccess",
      "secureDiscovery",
    ] as const) {
      const wasEnabled = previous?.[moduleId] === true;
      const enabled = this.isOptionalModuleEnabled(moduleId);
      if (enabled && !wasEnabled) {
        await this.ensureOptionalViewRegistered(moduleId).catch((error) =>
          this.logError(`Loading optional module ${moduleId} after settings sync failed`, error),
        );
      } else if (!enabled && wasEnabled) {
        await this.deactivateOptionalModule(
          moduleId,
          semanticAlreadyPurged && moduleId === "secureDiscovery",
        );
      }
    }
  }

  /**
   * Called by Obsidian when the plugin is deactivated.
   * Cleans up timers, restores original adapter methods, and clears
   * sensitive data from memory.
   */
  async onunload(): Promise<void> {
    this.unloading = true;
    this.lifecycleGeneration += 1;
    this.log("Unloading VaultGuard plugin...");
    const cleanupTasks: NamedCleanupTask[] = [];

    this.discoveryRuntime?.cancel();
    this.discoveryRuntime = null;
    this.discoveryRuntimePromise = null;
    const semanticRuntime = this.semanticRuntime;
    semanticRuntime?.cancel();
    this.semanticRuntime = null;
    this.semanticRuntimePromise = null;
    if (semanticRuntime) {
      cleanupTasks.push({
        name: "semantic-runtime",
        promise: semanticRuntime.cancelAndWait(),
      });
    }
    this.semanticStatusListeners.clear();
    this.discoveryLifecycleListeners.clear();
    this.settingTab = null;

    this.permissionsGraphVirtualQaModal?.close();
    this.permissionsGraphVirtualQaModal = null;

    // SY5: flush the pending (debounced) offline-queue persist so queued
    // edits survive the unload instead of dying with the timer.
    if (this.offlineQueuePersistTimer) {
      clearTimeout(this.offlineQueuePersistTimer);
      this.offlineQueuePersistTimer = null;
      cleanupTasks.push({
        name: "offline-queue-persist",
        promise: this.enqueueOfflineQueuePersist(() => this.persistOfflineQueue()),
      });
    }
    if (this.remoteFileStatePersistTimer) {
      clearTimeout(this.remoteFileStatePersistTimer);
      this.remoteFileStatePersistTimer = null;
      cleanupTasks.push({
        name: "remote-file-state-persist",
        promise: this.enqueueRemoteFileStatePersist(() => this.persistRemoteFileState()),
      });
    }

    // Stop all timers
    this.stopSyncTimer();
    this.stopKeyRenewalMonitor();
    this.stopHeartbeatMonitor();
    this.stopConnectionRetry();
    this.cancelConnectionLostNotice();
    this.stopAutoLockTimer();
    if (this.updateChecker) {
      this.updateChecker.stop();
      this.updateChecker = null;
    }
    this.longOperationStatusUnsubscribe?.();
    this.longOperationStatusUnsubscribe = null;
    this.longOperationUi?.destroy();
    this.longOperationUi = null;
    // SD-07-F4: abort in-flight operations BEFORE destroying the manager, so a
    // protected wipe cannot keep mutating the vault while the replacement
    // instance boots. See shutdownLongOperations().
    this.shutdownLongOperations();

    const agentBridgeRuntime = this.agentBridgeRuntime;
    this.agentBridgeRuntime = null;
    if (agentBridgeRuntime) {
      cleanupTasks.push({ name: "agent-bridge", promise: agentBridgeRuntime.shutdown() });
    }

    let cleanupSummary = { fulfilled: [] as string[], rejected: [] as string[], timedOut: [] as string[] };
    try {
      cleanupSummary = await settleCleanupTasks(cleanupTasks, 900);
    } finally {
      // Restore adapter/API/UI ownership even if a cleanup dependency ignores
      // cancellation. Late work has already lost live runtime references.
      this.restoreVaultAdapter();

      if (this.apiClient) {
        this.apiClient.destroy();
        this.apiClient = null;
      }

      this.clearSensitiveData(false);
      this.setGlobalAuthChromeState(false);

      if (this.filePermissionHeader) {
        this.filePermissionHeader.destroy();
        this.filePermissionHeader = null;
      }
      if (this.readOnlyGuard) {
        this.readOnlyGuard.destroy();
        this.readOnlyGuard = null;
      }
      if (this.fileExplorerDecorations) {
        this.fileExplorerDecorations.destroy();
        this.fileExplorerDecorations = null;
      }

      // Sidebar leaves remain attached so Obsidian can restore their placement.
      if (this.statusBarEl) {
        this.statusBarEl.remove();
        this.statusBarEl = null;
      }
    }

    if (cleanupSummary.rejected.length > 0) {
      this.logError(
        `Plugin unload cleanup rejected: ${cleanupSummary.rejected.join(", ")}`,
        new Error("Lifecycle cleanup rejected."),
      );
    }
    if (cleanupSummary.timedOut.length > 0) {
      this.logError(
        `Plugin unload cleanup timed out: ${cleanupSummary.timedOut.join(", ")}`,
        new Error("Lifecycle cleanup deadline exceeded."),
      );
    }
    this.log("VaultGuard plugin unloaded.");
  }

  private registerInviteProtocolHandler(): void {
    registerInviteProtocolHandlerLifecycle(this.createLifecycleEventsContext());
  }

  /**
   * Registers the `obsidian://vaultguard-share?token=...&vault=...` deep link
   * handler. A public web bridge (managed by the backend operator) translates
   * `https://.../s/{shareId}?v={vaultId}` browser clicks into this URI; here
   * we (a) check the click landed on the right locally-bound vault, and
   * (b) call the authenticated resolve endpoint to learn the path, then
   * open the file. The managed SaaS bridge lives at share.example.com;
   * self-hosters running Pro can deploy their own bridge under any hostname.
   * Community Edition does not include share links at all.
   *
   * The `vault` param is the *server* vaultId. If the active Obsidian
   * vault isn't bound to that vaultId, we tell the user which one to
   * switch to instead of silently opening the wrong file.
   */
  private registerShareProtocolHandler(): void {
    registerShareProtocolHandlerLifecycle(this.createLifecycleEventsContext());
  }

  /**
   * Resolves a share token to a (vaultId, relPath) and opens the file in
   * the active Obsidian vault — but only if the active vault is bound to
   * the same server vaultId carried in the link. Otherwise, surfaces a
   * notice telling the user which local vault to switch to.
   *
   * Param name note: we read `vaultId`, not `vault`. Obsidian reserves
   * `?vault=NAME` to route the URL to a specific local vault by name —
   * passing a server vaultId there triggers "Unable to find a vault for
   * the URL" before this handler is ever invoked.
   */
  async handleShareLink(params: { token?: string; vaultId?: string; [k: string]: string | undefined }): Promise<void> {
    if (this.isLocalProjectMemoryModeEnabled()) {
      new Notice("VaultGuard Sync: share links are disabled in Local Project Memory Mode.");
      return;
    }
    const token = (params.token ?? "").trim();
    const linkVaultId = (params.vaultId ?? "").trim();

    if (!token) {
      new Notice("VaultGuard Sync: Share link is missing its token.");
      return;
    }

    if (!this.session || !this.apiClient) {
      new Notice("VaultGuard Sync: Log in first, then click the share link again.");
      return;
    }

    const boundVaultId = this.settings.serverVaultId;
    if (!boundVaultId) {
      new Notice("VaultGuard Sync: This Obsidian vault isn't connected to a VaultGuard vault yet.");
      return;
    }

    // The vaultId in the URL is a hint — we still ask the server to resolve
    // the token. If the link's vault hint doesn't match the active vault,
    // we can short-circuit with a clear message before doing any network I/O.
    if (linkVaultId && linkVaultId !== boundVaultId) {
      new Notice(
        `VaultGuard Sync: This share link points to a different VaultGuard vault. ` +
        `Switch to the Obsidian vault bound to that VaultGuard vault and click the link again.`,
        8000
      );
      return;
    }

    let resolved;
    try {
      resolved = await this.apiClient.resolveShare(boundVaultId, token);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      new Notice(`VaultGuard Sync: Couldn't open share link — ${msg}`, 8000);
      return;
    }

    const file = this.app.vault.getAbstractFileByPath(normalizePath(resolved.relPath));
    if (!(file instanceof TFile)) {
      new Notice(
        `VaultGuard Sync: "${resolved.relPath}" isn't available in this vault — ` +
        `it may not be synced yet, or the source file was renamed or deleted.`,
        8000
      );
      return;
    }

    try {
      await this.app.workspace.getLeaf(false).openFile(file);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      new Notice(`VaultGuard Sync: Couldn't open "${resolved.relPath}" — ${msg}`, 8000);
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Agent Bridge
  // ─────────────────────────────────────────────────────────────────────────

  private initAgentBridge(): void {
    this.agentBridgeRuntime = this.createAgentBridgeRuntime();
    this.agentBridgeRuntime.init();
  }

  /**
   * Build a ConversationStore for the chat panel, backed by the plugin's own
   * config dir (`<configDir>/plugins/<id>/chat/`, which is `isPathExcluded` —
   * plugin data, not vault content) and LAK-encrypted via AtRestCipher. Mirrors
   * the agent-leases envelope mechanism: binary read/write through the raw
   * adapter, but ONLY for the plugin's own excluded chat dir.
   *
   * Returns null if the vault adapter isn't ready yet; the caller treats that
   * as "no persistence available" and continues.
   */
  getConversationStore(): ConversationStore | null {
    return this.ensureAgentBridgeRuntimeObject().getConversationStore();
  }

  private ensureAgentBridgeRuntime(): AgentBridgeRuntime {
    if (!this.agentBridgeRuntime) {
      this.initAgentBridge();
    }
    return this.agentBridgeRuntime!;
  }

  /**
   * Public plugin API for trusted integrations that want to call VaultGuard
   * tools instead of reading the vault folder. The returned surface cannot
   * mint its own leases; a user or admin must create one first.
   */
  getAgentBridge(): AgentBridgeToolSurface {
    return this.ensureAgentBridgeRuntime().getToolSurface();
  }

  /**
   * Permission context for the AI chat `@`-mention picker. The picker is a UI
   * enumeration surface, so it MUST gate on the same per-path value the Agent
   * Bridge list/read surface gates on (SD-13-F5): a path the user cannot read
   * must never be rendered or inserted, because a later `vaultguard_read`
   * denial cannot retract a disclosed filename.
   *
   * Narrower than the bridge list by design: it additionally honours the
   * metadata side-channel guard. It omits only the lease-scope checks, which
   * do not exist for a surface with no lease.
   */
  getChatMentionAccess(): MentionAccessContext {
    return {
      getPermission: (path) =>
        resolveAgentPermission(
          {
            // `getEffectivePermission` is private, so a public structural slot
            // cannot see it from outside the class. Wrapping both capabilities
            // in arrows *inside* the class body is the minimal legal bridge and
            // keeps the predicate itself single-defined in `agent-permission.ts`.
            isLocalProjectMemoryModeEnabled: () => this.isLocalProjectMemoryModeEnabled(),
            getEffectivePermission: (p) => this.getEffectivePermission(p),
          },
          path,
        ),
      isPathVisible: (path) => this.isMentionPathVisible(path),
      isMetadataSuppressed: (path) =>
        this.permissionStore?.isMetadataSuppressed(path) ?? false,
    };
  }

  async createAgentBridgeLease(input: AgentBridgeLeaseInput = {}): Promise<AgentBridgeLeaseSecret> {
    if (!this.isOptionalModuleEnabled("agentAccess")) {
      throw new Error("External agent access is off. Enable it in VaultGuard settings first.");
    }
    if (!this.session) {
      throw new Error("VaultGuard agent bridge requires an active VaultGuard login.");
    }
    const localProjectMemoryMode = this.isLocalProjectMemoryModeEnabled();
    if (localProjectMemoryMode && input.persistent === true) {
      throw new Error(
        "Local Project Memory Mode only supports time-limited, session-bound leases."
      );
    }
    const lease = this.ensureAgentBridgeRuntime().createLease({
      ...input,
      // Public/external leases never receive private Obsidian command authority.
      allowAutomation: false,
      // The current storage mode is plugin-owned. External callers cannot use
      // this input flag to bypass the normal server-vault prerequisite.
      localProjectMemoryMode,
      ...(localProjectMemoryMode
        ? {
            persistent: false,
            expiresWithSession: true,
            // Public local bridge leases remain clock-bounded as well as
            // session-bound. The trusted in-app lease omits a TTL separately.
            ttlMinutes: input.ttlMinutes ?? 30,
          }
        : {}),
    });
    this.vaultOrientationService?.invalidate("agent-bridge-lease-created");
    return lease;
  }

  isOptionalModuleEnabled(moduleId: OptionalModuleId): boolean {
    return this.settings.optionalModules?.[moduleId] === true;
  }

  async setOptionalModuleEnabled(
    moduleId: OptionalModuleId,
    enabled: boolean,
  ): Promise<void> {
    const semanticAlreadyPurged = moduleId === "secureDiscovery" && !enabled;
    if (semanticAlreadyPurged) {
      // Do not persist the parent module as off until its derived-content
      // envelope is gone. A purge failure leaves the prior toggle truthful.
      await this.purgeSemanticRuntime("disable");
    }
    const current = this.settings.optionalModules ?? DEFAULT_SETTINGS.optionalModules;
    this.settings.optionalModules = {
      schemaVersion: 2,
      aiChat: current.aiChat === true,
      permissionsGraph: current.permissionsGraph === true,
      agentAccess: current.agentAccess === true,
      secureDiscovery: current.secureDiscovery === true,
      [moduleId]: enabled,
    };
    await this.saveSettings();

    if (enabled) {
      try {
        await this.ensureOptionalViewRegistered(moduleId);
      } catch (error) {
        this.settings.optionalModules = {
          ...this.settings.optionalModules,
          [moduleId]: false,
        };
        await this.saveSettings();
        throw error;
      }
      if (moduleId === "secureDiscovery") this.notifyDiscoveryLifecycleChanged();
      return;
    }

    await this.deactivateOptionalModule(moduleId, semanticAlreadyPurged);
  }

  private async deactivateOptionalModule(
    moduleId: OptionalModuleId,
    semanticAlreadyPurged = false,
  ): Promise<void> {
    switch (moduleId) {
      case "aiChat":
        this.app.workspace.detachLeavesOfType(VAULTGUARD_CHAT_VIEW_TYPE);
        this.notifyAiChatProviderChanged();
        return;
      case "permissionsGraph":
        this.app.workspace.detachLeavesOfType(VAULTGUARD_GRAPH_VIEW_TYPE);
        return;
      case "agentAccess":
        if (this.agentBridgeRuntime) {
          this.agentBridgeRuntime.revokeAllLeases();
          await this.agentBridgeRuntime.stopServerIfInitialized();
        }
        return;
      case "secureDiscovery":
        if (!semanticAlreadyPurged) await this.purgeSemanticRuntime("disable");
        this.discoveryRuntime?.cancel();
        this.discoveryRuntime = null;
        this.discoveryRuntimePromise = null;
        this.app.workspace.detachLeavesOfType(VAULTGUARD_DISCOVERY_VIEW_TYPE);
        this.notifyDiscoveryLifecycleChanged();
        return;
    }
  }

  private async registerEnabledOptionalViews(): Promise<void> {
    if (this.isOptionalModuleEnabled("aiChat")) {
      await this.ensureOptionalViewRegistered("aiChat").catch((error) =>
        this.logError("Registering the optional Chat view failed", error),
      );
    }
    if (this.isOptionalModuleEnabled("permissionsGraph")) {
      await this.ensureOptionalViewRegistered("permissionsGraph").catch((error) =>
        this.logError("Registering the optional Permissions Graph view failed", error),
      );
    }
    if (this.isOptionalModuleEnabled("secureDiscovery")) {
      await this.ensureOptionalViewRegistered("secureDiscovery").catch((error) =>
        this.logError("Registering optional Secure Discovery failed", error),
      );
    }
  }

  private async ensureOptionalViewRegistered(
    moduleId: OptionalModuleId,
  ): Promise<boolean> {
    if (this.unloading) return false;
    if (!this.isOptionalModuleEnabled(moduleId)) return false;
    if (moduleId === "agentAccess") return true;
    if (moduleId === "aiChat" && this.chatViewRegistered) return true;
    if (moduleId === "permissionsGraph" && this.graphViewRegistered) return true;
    if (moduleId === "secureDiscovery" && this.discoveryViewRegistered) return true;

    const existing = this.optionalViewRegistrationPromises.get(moduleId);
    if (existing) return existing;

    const lifecycleGeneration = this.lifecycleGeneration;
    const mayRegister = () =>
      !this.unloading && lifecycleGeneration === this.lifecycleGeneration;
    const registration = (async (): Promise<boolean> => {
      switch (moduleId) {
        case "aiChat": {
          const { VaultGuardChatView } = await import("../ui/chat/chat-view");
          if (!mayRegister() || !this.isOptionalModuleEnabled(moduleId)) return false;
          this.registerView(
            VAULTGUARD_CHAT_VIEW_TYPE,
            (leaf) =>
              new VaultGuardChatView(
                leaf,
                this as ConstructorParameters<typeof VaultGuardChatView>[1],
              ),
          );
          this.chatViewRegistered = true;
          return true;
        }
        case "permissionsGraph": {
          const { PermissionsGraphView } = await import(
            "../ui/graph/permissions-graph-view"
          );
          if (!mayRegister() || !this.isOptionalModuleEnabled(moduleId)) return false;
          this.registerView(
            VAULTGUARD_GRAPH_VIEW_TYPE,
            (leaf) =>
              new PermissionsGraphView(
                leaf,
                this as ConstructorParameters<typeof PermissionsGraphView>[1],
              ),
          );
          this.graphViewRegistered = true;
          return true;
        }
        case "secureDiscovery": {
          const { SecureSearchView } = await import("../ui/discovery/secure-search-view");
          if (!mayRegister() || !this.isOptionalModuleEnabled(moduleId)) return false;
          this.registerView(
            VAULTGUARD_DISCOVERY_VIEW_TYPE,
            (leaf) => new SecureSearchView(leaf, this.createSecureSearchViewContext()),
          );
          this.discoveryViewRegistered = true;
          await this.registerSecureDiscoveryNativeSurfaces();
          return true;
        }
      }
    })().finally(() => {
      this.optionalViewRegistrationPromises.delete(moduleId);
    });

    this.optionalViewRegistrationPromises.set(moduleId, registration);
    return registration;
  }

  private notifyDiscoveryLifecycleChanged(): void {
    this.discoveryRuntime?.cancel();
    for (const listener of this.discoveryLifecycleListeners) {
      try {
        listener();
      } catch (error) {
        this.logError("Secure Discovery lifecycle listener failed", error);
      }
    }
  }

  private subscribeDiscoveryLifecycle(listener: () => void): () => void {
    this.discoveryLifecycleListeners.add(listener);
    return () => this.discoveryLifecycleListeners.delete(listener);
  }

  private createSecureSearchViewContext(): import("../ui/discovery/secure-search-view").SecureSearchViewContext {
    return {
      isEnabled: () => this.isOptionalModuleEnabled("secureDiscovery"),
      isReady: () =>
        Boolean(
          this.session &&
          this.apiClient &&
          this.settings.serverVaultId &&
          !this.isVaultLocked,
        ),
      getDefaultResultLimit: () => this.settings.discoveryResultLimit,
      search: async (request) => (await this.ensureDiscoveryRuntime()).search(request),
      cancel: () => this.discoveryRuntime?.cancel(),
      openLocalPath: (path) => this.openDiscoveryLocalPath(path),
      subscribeLifecycle: (listener) => this.subscribeDiscoveryLifecycle(listener),
      isSemanticSupported: () => Platform.isDesktopApp === true,
      isSemanticEnabled: () => this.settings.semanticSearchEnabled === true,
      getSemanticPreferences: () => ({
        origin: this.settings.semanticEmbeddingEndpoint,
        model: this.settings.semanticEmbeddingModel,
      }),
      getSemanticStatus: () => this.getSemanticSearchStatus(),
      subscribeSemanticStatus: (listener) => this.subscribeSemanticSearchStatus(listener),
      setSemanticEnabled: (enabled) => this.setSemanticSearchEnabled(enabled),
      updateSemanticPreferences: (origin, model) =>
        this.updateSemanticProviderPreferences(origin, model),
      testSemanticProvider: () => this.testSemanticProvider(),
      buildSemanticIndex: () => this.buildSemanticIndex(),
      cancelSemanticWork: () => this.cancelSemanticIndexWork(),
      purgeSemanticIndex: () => this.purgeSemanticIndex(),
    };
  }

  private async ensureDiscoveryRuntime(): Promise<import("./discovery/discovery-runtime").DiscoveryRuntime> {
    if (!this.isOptionalModuleEnabled("secureDiscovery")) {
      throw new Error("Secure Discovery is disabled.");
    }
    if (this.discoveryRuntime) return this.discoveryRuntime;
    if (this.discoveryRuntimePromise) return this.discoveryRuntimePromise;

    this.discoveryRuntimePromise = (async () => {
      const { DiscoveryRuntime } = await import("./discovery/discovery-runtime");
      if (!this.isOptionalModuleEnabled("secureDiscovery")) {
        throw new Error("Secure Discovery is disabled.");
      }
      const runtime = new DiscoveryRuntime({
        isModuleEnabled: () => this.isOptionalModuleEnabled("secureDiscovery"),
        getSession: () => this.session,
        getBoundVault: () =>
          this.settings.serverVaultId
            ? {
                id: this.settings.serverVaultId,
                name: this.settings.serverVaultName || "Bound vault",
              }
            : null,
        getLocalFiles: () =>
          this.app.vault.getMarkdownFiles().map((file) => ({
            path: file.path,
            size: file.stat.size,
          })),
        readLocalText: async (path) => {
          const file = this.app.vault.getAbstractFileByPath(path);
          if (!(file instanceof TFile) || file.extension.toLocaleLowerCase("en-US") !== "md") {
            throw new Error("Local Markdown file is unavailable.");
          }
          return await this.app.vault.cachedRead(file);
        },
        getPermissionDecision: (path) => this.permissionStore.getPermissionDecision(path),
        isPathExcluded: (path) => this.isPathExcluded(path),
        isMetadataSuppressed: (path) => this.permissionStore.isMetadataSuppressed(path),
        listVaults: async () => {
          if (!this.apiClient) throw new Error("VaultGuard API client unavailable.");
          return await this.apiClient.listVaults();
        },
        listVaultFilesPage: async (vaultId, options) => {
          if (!this.apiClient) throw new Error("VaultGuard API client unavailable.");
          return await this.apiClient.listVaultFilesPage(vaultId, options);
        },
        readVaultFileDecrypted: async (vaultId, path) => {
          if (!this.apiClient) throw new Error("VaultGuard API client unavailable.");
          return await this.apiClient.readVaultFileDecrypted(vaultId, path);
        },
        searchSemantic: async (request) => (await this.ensureSemanticRuntime()).query(request),
        cancelSemantic: () => this.semanticRuntime?.cancel(),
        yieldControl: () => new Promise<void>((resolve) => globalThis.setTimeout(resolve, 0)),
        now: () => Date.now(),
      });
      this.discoveryRuntime = runtime;
      return runtime;
    })().finally(() => {
      this.discoveryRuntimePromise = null;
    });
    return this.discoveryRuntimePromise;
  }

  private async ensureSemanticRuntime(): Promise<import("./discovery/semantic-search-runtime").SemanticSearchRuntime> {
    if (this.semanticRuntime) return this.semanticRuntime;
    if (this.semanticRuntimePromise) return this.semanticRuntimePromise;
    this.semanticRuntimePromise = (async () => {
      const [runtimeModule, providerModule, storeModule] = await Promise.all([
        import("./discovery/semantic-search-runtime"),
        import("./discovery/ollama-embedding-provider"),
        import("./discovery/semantic-index-store"),
      ]);
      const indexPath = this.vaultConfigPath(
        "plugins",
        this.manifest.id,
        "semantic",
        "index.v1.envelope",
      );
      const store = new storeModule.SemanticIndexStore({
        path: indexPath,
        getCipher: () => this.getAtRestCipher(),
        getStorage: () => {
          const methods = this.originalAdapterMethods;
          if (
            !methods.readBinary ||
            !methods.writeBinary ||
            !methods.remove ||
            !methods.rename
          ) {
            return null;
          }
          return {
            exists: (path: string) => this.app.vault.adapter.exists(path),
            readBinary: methods.readBinary,
            writeBinary: methods.writeBinary,
            remove: methods.remove,
            rename: methods.rename,
          };
        },
        ensureParent: (path) => this.ensureParentFoldersForPath(path),
      });
      const runtime = new runtimeModule.SemanticSearchRuntime({
        isParentEnabled: () => this.isOptionalModuleEnabled("secureDiscovery"),
        isSemanticEnabled: () =>
          Platform.isDesktopApp === true && this.settings.semanticSearchEnabled === true,
        getSession: () => this.session,
        getBoundVault: () =>
          this.settings.serverVaultId
            ? {
                id: this.settings.serverVaultId,
                name: this.settings.serverVaultName || "Bound vault",
              }
            : null,
        getLocalVaultId: () => this.derivedBindingId,
        getProviderConfig: () => ({
          origin: this.settings.semanticEmbeddingEndpoint,
          model: this.settings.semanticEmbeddingModel,
        }),
        createProvider: (config) => new providerModule.OllamaEmbeddingProvider(config),
        repository: store,
        getLocalFiles: () => this.app.vault.getMarkdownFiles().map((file) => ({
          path: file.path,
          size: file.stat.size,
        })),
        readLocalText: async (path) => {
          const file = this.app.vault.getAbstractFileByPath(path);
          if (!(file instanceof TFile) || file.extension.toLocaleLowerCase("en-US") !== "md") {
            throw new Error("Local Markdown file is unavailable.");
          }
          return await this.app.vault.cachedRead(file);
        },
        getPermissionDecision: (path) => this.permissionStore.getPermissionDecision(path),
        isPathExcluded: (path) => this.isPathExcluded(path),
        isMetadataSuppressed: (path) => this.permissionStore.isMetadataSuppressed(path),
        yieldControl: () => new Promise<void>((resolve) => globalThis.setTimeout(resolve, 0)),
        now: () => Date.now(),
      });
      runtime.subscribe((status) => this.notifySemanticStatus(status));
      this.semanticRuntime = runtime;
      return runtime;
    })().finally(() => {
      this.semanticRuntimePromise = null;
    });
    return this.semanticRuntimePromise;
  }

  getSemanticSearchStatus(): import("./discovery/semantic-search-runtime").SemanticRuntimeStatus {
    return this.semanticRuntime?.getStatus() ?? {
      state: "absent",
      indexedFiles: 0,
      indexedChunks: 0,
      stale: false,
    };
  }

  subscribeSemanticSearchStatus(
    listener: (status: import("./discovery/semantic-search-runtime").SemanticRuntimeStatus) => void,
  ): () => void {
    this.semanticStatusListeners.add(listener);
    listener(this.getSemanticSearchStatus());
    return () => this.semanticStatusListeners.delete(listener);
  }

  private notifySemanticStatus(
    status: import("./discovery/semantic-search-runtime").SemanticRuntimeStatus,
  ): void {
    for (const listener of this.semanticStatusListeners) {
      try {
        listener({ ...status });
      } catch (error) {
        this.logError("Semantic status listener failed", error);
      }
    }
  }

  async setSemanticSearchEnabled(enabled: boolean): Promise<void> {
    if (enabled && !this.isOptionalModuleEnabled("secureDiscovery")) {
      throw new Error("Enable Secure Discovery before semantic search.");
    }
    if (enabled && Platform.isDesktopApp !== true) {
      throw new Error("Local Ollama semantic search is available on desktop only.");
    }
    if (!enabled) await this.purgeSemanticRuntime("disable");
    this.settings.semanticSearchEnabled = enabled;
    await this.saveSettings();
    this.notifyDiscoveryLifecycleChanged();
  }

  async updateSemanticProviderPreferences(origin: string, model: string): Promise<void> {
    const { normalizeOllamaOrigin, validateOllamaModel } = await import(
      "./discovery/ollama-embedding-provider"
    );
    const normalizedOrigin = normalizeOllamaOrigin(origin);
    const normalizedModel = validateOllamaModel(model);
    const changed =
      normalizedOrigin !== this.settings.semanticEmbeddingEndpoint ||
      normalizedModel !== this.settings.semanticEmbeddingModel;
    if (changed) await this.purgeSemanticRuntime("provider-change");
    this.settings.semanticEmbeddingEndpoint = normalizedOrigin;
    this.settings.semanticEmbeddingModel = normalizedModel;
    await this.saveSettings();
    this.notifyDiscoveryLifecycleChanged();
  }

  async testSemanticProvider(): Promise<number> {
    if (!this.isOptionalModuleEnabled("secureDiscovery") || !this.settings.semanticSearchEnabled) {
      throw new Error("Enable semantic search before testing the provider.");
    }
    const { OllamaEmbeddingProvider } = await import("./discovery/ollama-embedding-provider");
    const provider = new OllamaEmbeddingProvider({
      origin: this.settings.semanticEmbeddingEndpoint,
      model: this.settings.semanticEmbeddingModel,
    });
    const vector = (await provider.embed(["VaultGuard semantic provider test"]))[0]!;
    return vector.length;
  }

  async buildSemanticIndex(): Promise<import("./discovery/semantic-search-runtime").SemanticRuntimeStatus> {
    return await (await this.ensureSemanticRuntime()).build();
  }

  cancelSemanticIndexWork(): void {
    this.semanticRuntime?.cancel();
  }

  async purgeSemanticIndex(): Promise<void> {
    await this.purgeSemanticRuntime("manual");
  }

  private async purgeSemanticRuntime(
    reason: import("./discovery/semantic-search-runtime").SemanticPurgeReason,
  ): Promise<void> {
    const runtime = this.semanticRuntime ?? await this.ensureSemanticRuntime();
    await runtime.purge(reason);
    this.semanticRuntime = null;
    this.semanticRuntimePromise = null;
    this.notifySemanticStatus(this.getSemanticSearchStatus());
  }

  private shouldPurgeSemanticIndex(): boolean {
    return Boolean(
      this.semanticRuntime ||
      (
        this.isOptionalModuleEnabled("secureDiscovery") &&
        this.settings.semanticSearchEnabled === true
      ),
    );
  }

  private async openDiscoveryLocalPath(path: string): Promise<void> {
    if (
      !this.isOptionalModuleEnabled("secureDiscovery") ||
      !this.session ||
      this.isVaultLocked ||
      this.isPathExcluded(path) ||
      this.permissionStore.isMetadataSuppressed(path)
    ) {
      throw new Error("Local result is no longer available.");
    }
    const decision = await this.permissionStore.getPermissionDecision(path);
    if (decision.kind === "unknown" || decision.level < PermissionLevel.READ) {
      throw new Error("Local result access could not be re-established.");
    }
    const file = this.app.vault.getAbstractFileByPath(path);
    if (!(file instanceof TFile)) throw new Error("Local result no longer exists.");
    await this.app.workspace.getLeaf(false).openFile(file);
  }

  private registerSecureDiscoveryCommand(): void {
    if (this.discoveryCommandRegistered) return;
    this.addCommand({
      id: "vaultguard-open-secure-search",
      name: this.i18n.t("discovery.search.title"),
      checkCallback: (checking) => {
        const available = Boolean(
          this.isOptionalModuleEnabled("secureDiscovery") &&
          this.session &&
          this.settings.serverVaultId &&
          !this.isVaultLocked,
        );
        if (!available) return false;
        if (!checking) {
          void this.activateSecureSearch().catch((error) => {
            this.logError("Opening Secure Search failed", error);
            new Notice("VaultGuard: Secure Search could not be opened.");
          });
        }
        return true;
      },
    });
    this.discoveryCommandRegistered = true;
  }

  private async activateSecureSearch(): Promise<void> {
    if (!(await this.ensureOptionalViewRegistered("secureDiscovery"))) {
      throw new Error("Secure Discovery is disabled.");
    }
    const { SecureSearchView } = await import("../ui/discovery/secure-search-view");
    const existing = this.app.workspace.getLeavesOfType(VAULTGUARD_DISCOVERY_VIEW_TYPE);
    if (existing.length > 0) {
      await this.app.workspace.revealLeaf(existing[0]!);
      if (existing[0]!.view instanceof SecureSearchView) existing[0]!.view.focusQuery();
      return;
    }
    const leaf = this.app.workspace.getLeaf("tab");
    await leaf.setViewState({ type: VAULTGUARD_DISCOVERY_VIEW_TYPE, active: true });
    await this.app.workspace.revealLeaf(leaf);
    if (leaf.view instanceof SecureSearchView) leaf.view.focusQuery();
  }

  private async registerSecureDiscoveryNativeSurfaces(): Promise<void> {
    this.registerSecureDiscoveryCommand();
    await this.tryRegisterDiscoveryBases();
    await this.tryRegisterDiscoveryCli();
  }

  private async tryRegisterDiscoveryBases(): Promise<boolean> {
    if (this.discoveryBasesRegistered) return true;
    if (
      !this.isOptionalModuleEnabled("secureDiscovery") ||
      typeof requireApiVersion !== "function" ||
      !requireApiVersion("1.10.0")
    ) {
      return false;
    }
    type BasesRegistrar = (
      viewId: string,
      registration: import("obsidian").BasesViewRegistration,
    ) => boolean;
    const registrar = (this as unknown as { registerBasesView?: BasesRegistrar }).registerBasesView;
    if (typeof registrar !== "function") return false;

    // Keep the BasesView subclass out of the startup module graph. Obsidian
    // 1.8.x cannot evaluate a class extending an export it does not have.
    const { VAULTGUARD_BASES_VIEW_ID, createPermissionBasesRegistration } =
      await import("../ui/discovery/permission-bases-view");
    if (!this.isOptionalModuleEnabled("secureDiscovery")) return false;

    const registration = createPermissionBasesRegistration({
      isEnabled: () => this.isOptionalModuleEnabled("secureDiscovery"),
      getBatchPathAccess: async (paths) => {
        if (!this.apiClient) throw new Error("VaultGuard API client unavailable");
        return await this.apiClient.getBatchPathAccess(paths);
      },
      peekPermissionDecision: (path) => this.permissionStore.peekPermissionDecision(path),
      isMetadataSuppressed: (path) => this.permissionStore.isMetadataSuppressed(path),
      isPathExcluded: (path) => this.isPathExcluded(path),
      isCurrentLocalPath: (path) => this.app.vault.getAbstractFileByPath(path) instanceof TFile,
      openPath: async (path) => {
        await this.app.workspace.openLinkText(path, "", false);
      },
      subscribePermissionChanges: (handler) => {
        const changed = this.permissionStore.on("changed", handler);
        const stateChanged = this.permissionStore.on("state-changed", handler);
        return () => {
          this.permissionStore.offref(changed);
          this.permissionStore.offref(stateChanged);
        };
      },
      subscribeModuleChanges: (handler) => this.subscribeDiscoveryLifecycle(handler),
      yieldControl: () => new Promise<void>((resolve) => window.setTimeout(resolve, 0)),
      labels: {
        off: this.i18n.t("discovery.bases.off"),
        verifying: this.i18n.t("discovery.bases.verifying"),
        prefix: this.i18n.t("discovery.bases.prefix"),
        readable: (count) => this.i18n.t("discovery.bases.readable", { count }),
        showing: (count) => this.i18n.t("discovery.bases.showing", { count }),
        unavailable: (count) => this.i18n.t("discovery.bases.unavailable", { count }),
        verified: this.i18n.t("discovery.provenance.verified"),
        cached: this.i18n.t("discovery.provenance.cached"),
      },
    });
    const registered = registrar.call(this, VAULTGUARD_BASES_VIEW_ID, registration);
    this.discoveryBasesRegistered = registered === true;
    return this.discoveryBasesRegistered;
  }

  private async tryRegisterDiscoveryCli(): Promise<boolean> {
    if (this.discoveryCliRegistered) return true;
    if (
      !this.isOptionalModuleEnabled("secureDiscovery") ||
      Platform.isDesktopApp !== true ||
      typeof requireApiVersion !== "function" ||
      !requireApiVersion("1.12.2")
    ) {
      return false;
    }
    type CliRegistrar = (
      command: string,
      description: string,
      flags: import("obsidian").CliFlags | null,
      handler: import("obsidian").CliHandler,
    ) => void;
    const registrar = (this as unknown as { registerCliHandler?: CliRegistrar }).registerCliHandler;
    if (typeof registrar !== "function") return false;
    const { createDiscoveryCliHandlers } = await import("./discovery/cli-handlers");
    if (!this.isOptionalModuleEnabled("secureDiscovery")) return false;
    const handlers = createDiscoveryCliHandlers({
      isModuleEnabled: () => this.isOptionalModuleEnabled("secureDiscovery"),
      isCliRuntimeSupported: () =>
        Platform.isDesktopApp === true &&
        typeof requireApiVersion === "function" &&
        requireApiVersion("1.12.2"),
      getSession: () => this.session,
      getConnectionStatus: () => this.connectionState.status,
      getBoundVault: () =>
        this.settings.serverVaultId
          ? {
              id: this.settings.serverVaultId,
              name: this.settings.serverVaultName || "Bound vault",
            }
          : null,
      getDefaultResultLimit: () => this.settings.discoveryResultLimit,
      getSemanticStatus: () => {
        const status = this.getSemanticSearchStatus();
        return {
          enabled: this.settings.semanticSearchEnabled === true,
          indexState: status.state,
          indexedFiles: status.indexedFiles,
          stale: status.stale,
        };
      },
      getCapabilities: () => ({
        bases: this.discoveryBasesRegistered,
        cli: this.discoveryCliRegistered,
        semanticProvider:
          Platform.isDesktopApp === true && this.settings.semanticSearchEnabled === true,
      }),
      getPermissionDecision: (path) => this.permissionStore.getPermissionDecision(path),
      search: async (request) => (await this.ensureDiscoveryRuntime()).search(request),
    });
    registrar.call(this, "vaultguard-sync:status", "Show safe VaultGuard discovery status", null, handlers.status);
    registrar.call(
      this,
      "vaultguard-sync:access",
      "Show effective access for one current-vault path",
      { path: { value: "<path>", description: "Vault-relative path", required: true } },
      handlers.access,
    );
    registrar.call(
      this,
      "vaultguard-sync:search",
      "Search authorized VaultGuard knowledge",
      {
        query: { value: "<text>", description: "Search text", required: true },
        scope: { value: "<current|all>", description: "Vault scope" },
        content: { description: "Allow bounded note-content reads" },
        semantic: { description: "Use the current local semantic index" },
        limit: { value: "<1-100>", description: "Maximum results" },
      },
      handlers.search,
    );
    this.discoveryCliRegistered = true;
    return true;
  }

  /**
   * Trusted in-app chat lease factory. Unlike the public bridge API this method
   * enables the in-app-only tool capabilities, force-binds the lease to the
   * current login session, and never persists it. Callers cannot opt into a
   * generic or longer-lived lease.
   */
  async createInAppChatAgentBridgeLease(
    capability: InAppChatCapability,
    input: AgentBridgeLeaseInput = {},
  ): Promise<AgentBridgeLeaseSecret> {
    if (capability !== IN_APP_CHAT_CAPABILITY) {
      throw new Error("Trusted in-app chat capability required.");
    }
    const localProjectMemoryMode = this.isLocalProjectMemoryModeEnabled();
    const lease = this.ensureAgentBridgeRuntime().createLease({
      ...input,
      persistent: false,
      expiresWithSession: true,
      localProjectMemoryMode,
      // Governed command aliases are private-API-backed and therefore only
      // available to the trusted desktop chat lease. Public lease callers can
      // never widen themselves into this capability.
      allowAutomation:
        Platform.isDesktopApp === true && input.allowAutomation === true,
    });
    this.vaultOrientationService?.invalidate("agent-bridge-lease-created");
    return lease;
  }

  describeChatGptConnector(): ChatGptConnectorDescription {
    return this.ensureAgentBridgeRuntime().describeChatGptConnector();
  }

  async createChatGptConnectorSession(
    input: ChatGptConnectorSessionInput = {},
  ): Promise<ChatGptConnectorSessionSecret> {
    if (!this.isOptionalModuleEnabled("agentAccess")) {
      throw new Error("External agent access is off. Enable it in VaultGuard settings first.");
    }
    if (this.isLocalProjectMemoryModeEnabled()) {
      throw new Error("ChatGPT connector sessions are disabled in Local Project Memory Mode.");
    }
    const session = await this.ensureAgentBridgeRuntime().createChatGptConnectorSession(input);
    this.vaultOrientationService?.invalidate("chatgpt-connector-session-created");
    return session;
  }

  revokeChatGptConnectorSession(sessionId: string): boolean {
    const revoked = this.ensureAgentBridgeRuntime().revokeChatGptConnectorSession(sessionId);
    if (revoked) this.vaultOrientationService?.invalidate("chatgpt-connector-session-revoked");
    return revoked;
  }

  revokeAllChatGptConnectorSessions(): number {
    const count = this.ensureAgentBridgeRuntime().revokeAllChatGptConnectorSessions();
    if (count > 0) this.vaultOrientationService?.invalidate("chatgpt-connector-sessions-revoked");
    return count;
  }

  /**
   * Arm the bridge's gated import session for /import-knowledge: registers the
   * picked folder as the ONLY root the chat's vaultguard_import_* tools may read
   * under (read-only, realpath-sandboxed). Returns the canonicalized root.
   * Throws on mobile / non-Electron (no import fs provider) or an invalid folder.
   */
  async beginAgentBridgeImportSession(absRoot: string): Promise<string> {
    return this.ensureAgentBridgeRuntime().beginImportSession(absRoot);
  }

  /** Clear the bridge import session so the gated source-read tools go inert. */
  endAgentBridgeImportSession(): void {
    this.agentBridgeRuntime?.endImportSession();
  }

  /** True when the bridge currently has an import session armed. Lets the chat
   * re-arm a remembered source root only when the singleton bridge isn't already
   * pointed at it (e.g. after a reload, resume, or import-tab switch). */
  hasActiveAgentBridgeImportSession(): boolean {
    return this.agentBridgeRuntime?.hasActiveImportSession() ?? false;
  }

  /**
   * Pre-flight write-capability check for /import-knowledge. Probes the
   * effective permission for a representative NEW note path — exactly what
   * `vaultguard_create` will hit — so the chat can fail fast with a clear
   * message instead of running the whole survey and only discovering the
   * account is read-only at create time (where the denial is thrown before
   * the confirm modal). Read-only; the probe path is never created.
   *
   * Fail-OPEN: returns `true` when the result is inconclusive (no session or a
   * probe error) so a transient hiccup never wrongly blocks an import — the
   * per-write permission gate remains the real enforcement.
   */
  async canCreateVaultNotes(): Promise<boolean> {
    if (!this.session) return true;
    try {
      const level = await this.getEffectivePermission("Clients/_vaultguard-import-probe.md");
      return level >= PermissionLevel.WRITE;
    } catch {
      return true;
    }
  }

  rotateAgentBridgeLeaseToken(leaseId: string): AgentBridgeLeaseSecret {
    return this.ensureAgentBridgeRuntime().rotateLeaseToken(leaseId);
  }

  async loadPersistedAgentBridgeLeases(): Promise<{ restored: number; dropped: number }> {
    return this.ensureAgentBridgeRuntime().loadPersistedLeases();
  }

  /**
   * Plugin-startup hook: rehydrate any encrypted persistent leases for the
   * current session and bring the bridge HTTP server up if any survived.
   * Silent on no-op (no session, no envelope, or no matching leases) so a
   * fresh-install / first-run user sees nothing. Fires a one-line Notice
   * when leases come back so the user is aware their vault is reachable
   * to an external agent right after Obsidian starts.
   */
  private async restorePersistentAgentBridgeLeases(): Promise<void> {
    if (this.isLocalProjectMemoryModeEnabled()) return;
    await this.ensureAgentBridgeRuntime().restorePersistentLeases();
  }

  async revokeAgentBridgeLeasesForSessionEnd(reason: string): Promise<number> {
    if (!this.agentBridgeRuntime) return 0;
    return this.agentBridgeRuntime.revokePersistentLeasesForSessionEnd(reason);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Claude Code skill installer
  //
  // Writes (or removes) a SKILL.md at ~/.claude/skills/vaultguard/ that
  // tells the model to use VaultGuard's MCP tools instead of the built-in
  // filesystem tools when working with an encrypted vault. Desktop-only —
  // mobile Obsidian has no Node FS or ~/.claude/. Audit-logged because
  // it touches the user's home directory.
  // ─────────────────────────────────────────────────────────────────────────

  getAgentBridgeSkillStatus(): (SkillInstallStatus & { available: true }) | { available: false } {
    return this.ensureAgentBridgeRuntimeObject().getSkillStatus();
  }

  getAgentBridgeCodexSkillStatus(): (CodexSkillInstallStatus & { available: true }) | { available: false } {
    return this.ensureAgentBridgeRuntimeObject().getCodexSkillStatus();
  }

  async installAgentBridgeSkill(
    options: { overwriteUnmanaged?: boolean; force?: boolean } = {}
  ): Promise<InstallResult> {
    return this.ensureAgentBridgeRuntimeObject().installSkill(options);
  }

  async installAgentBridgeCodexSkill(
    options: { overwriteUnmanaged?: boolean; force?: boolean } = {}
  ): Promise<CodexInstallResult> {
    return this.ensureAgentBridgeRuntimeObject().installCodexSkill(options);
  }

  async uninstallAgentBridgeSkill(options: { force?: boolean } = {}): Promise<{
    filePath: string;
    removed: boolean;
  }> {
    return this.ensureAgentBridgeRuntimeObject().uninstallSkill(options);
  }

  async uninstallAgentBridgeCodexSkill(options: { force?: boolean } = {}): Promise<{
    filePath: string;
    removed: boolean;
  }> {
    return this.ensureAgentBridgeRuntimeObject().uninstallCodexSkill(options);
  }

  revokeAgentBridgeLease(leaseId: string): boolean {
    const revoked = this.ensureAgentBridgeRuntime().revokeLease(leaseId);
    if (revoked) this.vaultOrientationService?.invalidate("agent-bridge-lease-revoked");
    return revoked;
  }

  revokeAllAgentBridgeLeases(): void {
    this.ensureAgentBridgeRuntime().revokeAllLeases();
    this.vaultOrientationService?.invalidate("agent-bridge-leases-revoked");
  }

  async startAgentBridgeServer(): Promise<AgentBridgeServerInfo> {
    if (!this.isOptionalModuleEnabled("agentAccess")) {
      throw new Error("External agent access is off. Enable it in VaultGuard settings first.");
    }
    if (!this.session) {
      throw new Error("VaultGuard agent bridge requires an active VaultGuard login.");
    }
    return this.ensureAgentBridgeRuntime().startServer();
  }

  /** Start the loopback server for a trusted in-app CLI chat transport. */
  async startInAppChatAgentBridgeServer(
    capability: InAppChatCapability,
  ): Promise<AgentBridgeServerInfo> {
    if (capability !== IN_APP_CHAT_CAPABILITY) {
      throw new Error("Trusted in-app chat capability required.");
    }
    return this.ensureAgentBridgeRuntime().startServer();
  }

  /** Immediately tear down active provider sessions after a settings switch. */
  notifyAiChatProviderChanged(): void {
    const leaves = this.app.workspace.getLeavesOfType("vaultguard-chat-view");
    for (const leaf of leaves) {
      const view = leaf.view as unknown as {
        handleProviderConfigurationChanged?: () => void;
      };
      view.handleProviderConfigurationChanged?.();
    }
  }

  async stopAgentBridgeServer(): Promise<void> {
    await this.agentBridgeRuntime?.stopServerIfInitialized();
  }

  /**
   * Spawn `claude auth login` so the user signs in to Claude Code through
   * Anthropic's own browser OAuth flow. The plugin NEVER reads, stores, or
   * transmits the resulting token — `claude` keeps it in its own keychain. We
   * only launch the official binary and wait for it to exit. Desktop-only.
   *
   * Resolves when the login subprocess closes (success or user-cancel). Rejects
   * only if the binary can't be found or launched.
   */
  async startClaudeCliLogin(): Promise<void> {
    if (Platform.isMobileApp) {
      throw new Error("Claude Code sign-in needs desktop Obsidian.");
    }
    const maybeWindow =
      typeof window !== "undefined" ? (window as unknown as Record<string, unknown>) : {};
    const req =
      typeof maybeWindow.require === "function"
        ? (maybeWindow.require as NodeRequire)
        : null;
    if (!req) {
      throw new Error("Node child_process is unavailable in this runtime.");
    }

    const binaryPath = await findClaudeBinary();
    if (!binaryPath) {
      throw new Error(
        "Claude Code CLI not found. Install it (see code.claude.com/docs/setup) and retry.",
      );
    }

    const childProcess = req("child_process") as {
      spawn(
        cmd: string,
        args: ReadonlyArray<string>,
        opts: { stdio?: "ignore" | "inherit"; env?: NodeJS.ProcessEnv },
      ): {
        on(ev: "error", cb: (err: Error) => void): void;
        on(ev: "close", cb: (code: number | null) => void): void;
      };
    };

    return new Promise<void>((resolve, reject) => {
      let settled = false;
      try {
        const child = childProcess.spawn(binaryPath, ["auth", "login"], {
          stdio: "ignore",
          env: typeof process !== "undefined" ? process.env : undefined,
        });
        child.on("error", (err) => {
          if (settled) return;
          settled = true;
          reject(new Error(`Could not start Claude Code sign-in: ${err.message}`));
        });
        child.on("close", () => {
          if (settled) return;
          settled = true;
          resolve();
        });
      } catch (e) {
        if (!settled) {
          settled = true;
          reject(e instanceof Error ? e : new Error(String(e)));
        }
      }
    });
  }

  private openAgentBridgeLeaseModal(): void {
    if (!this.isOptionalModuleEnabled("agentAccess")) {
      new Notice("VaultGuard Sync: Enable External agent access in settings first.");
      return;
    }
    this.ensureAgentBridgeRuntimeObject().openLeaseModal();
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Settings Management
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Loads settings from Obsidian's data store, merging with defaults
   * for any missing fields.
   */
  async loadSettings(): Promise<void> {
    await this.getSettingsRuntime().loadSettings();
  }

  private normalizeServerEdition(value: unknown): ServerEdition | null {
    return this.getSettingsRuntime().normalizeServerEdition(value);
  }

  private normalizeServerFeatures(value: unknown): ServerFeatures | null {
    return this.getSettingsRuntime().normalizeServerFeatures(value);
  }

  private cacheServerCapabilities(config: Record<string, unknown>): boolean {
    return this.getSettingsRuntime().cacheServerCapabilities(config);
  }

  private async refreshServerCapabilitiesFromConfiguredEndpoint(): Promise<boolean> {
    return this.getSettingsRuntime().refreshServerCapabilitiesFromConfiguredEndpoint();
  }

  /**
   * Persists current settings to Obsidian's data store.
   */
  async saveSettings(): Promise<void> {
    await this.getSettingsRuntime().saveSettings();
    this.vaultOrientationService?.invalidate("settings-saved");
  }

  async resetCloudConnectionDefaults(): Promise<void> {
    await this.getSettingsRuntime().resetCloudConnectionDefaults();
  }

  async setManualConfigurationMode(manualConfig: boolean): Promise<void> {
    await this.getSettingsRuntime().setManualConfigurationMode(manualConfig);
  }

  getConnectionTargetLabel(): string {
    return this.getSettingsRuntime().getConnectionTargetLabel();
  }

  private readConfigString(config: Record<string, unknown>, key: string): string {
    return this.getSettingsRuntime().readConfigString(config, key);
  }

  private applyResolvedConnectionConfig(
    config: Record<string, unknown>,
    fallbackApiEndpoint: string,
    fallbackOrgSlug = ""
  ): void {
    this.getSettingsRuntime().applyResolvedConnectionConfig(
      config,
      fallbackApiEndpoint,
      fallbackOrgSlug,
    );
  }

  async applyManualServerConfigUrl(rawUrl: string): Promise<void> {
    await this.getSettingsRuntime().applyManualServerConfigUrl(rawUrl);
  }

  /**
   * Returns the effective connection config. Manual mode uses only user-entered
   * values. Cloud mode starts from bundled SaaS defaults, then lets resolved
   * org config override them after sign-in, invite redemption, or slug connect.
   */
  getEffectiveConfig(): {
    apiEndpoint: string;
    cognitoUserPoolId: string;
    cognitoClientId: string;
    organizationId: string;
    loginVerificationMode: "disabled" | "observe" | "enforce";
  } {
    return this.getSettingsRuntime().getEffectiveConfig();
  }

  private rebuildApiClient(): void {
    this.getSettingsRuntime().rebuildApiClient();
  }

  private async getResolvedApiEndpoint(
    idToken?: string,
    probePath?: string,
    forceRefresh = false
  ): Promise<string> {
    return this.getSettingsRuntime().getResolvedApiEndpoint(idToken, probePath, forceRefresh);
  }
  // Command Registration
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Registers all plugin commands accessible via the command palette.
   */
  private registerCommands(): void {
    registerVaultGuardCommands(this.createCommandContext());

    // User-facing lock-on-demand command (quick 260708-g9m). Locks the vault at
    // will instead of waiting for the idle timer. Runtime-gated ONLY by PIN
    // enrollment inside lockVaultViaCommand() — intentionally registered OUTSIDE
    // the dev-only build guard below, because this ships to users. Obsidian
    // prefixes the palette label with the plugin name automatically.
    this.addCommand({
      id: "vaultguard-lock-vault",
      name: "Lock vault",
      callback: () => this.lockVaultViaCommand(),
    });

    this.addCommand({
      id: "vaultguard-open-recovery-center",
      name: "Open Recovery Center",
      callback: () => this.openRecoveryCenter(),
    });

    // Dev-only testing aid (quick 260708-el6): force-open the PIN onboarding
    // prompt on demand so it can be exercised without an idle-logout, without a
    // lock-policy server (12-02 idleAction deploy), and without disabling an
    // existing PIN. In production the esbuild `define` replaces
    // `process.env.NODE_ENV` with "production", folding this guard to `if (false)`
    // so esbuild DCE strips the whole block — and its command strings — from the
    // released bundle. It therefore exists ONLY in dev builds
    // (`npm run install:plugin:dev`), never in users' bundles. Mirrors the
    // NODE_ENV gating used by registerChatDebugCommand.
    if (process.env.NODE_ENV !== "production") {
      this.addCommand({
        id: "vaultguard-dev-test-pin-onboarding",
        name: "Dev: test PIN onboarding prompt",
        callback: () => {
          // Log the natural-gate state (so a tester can see whether the real
          // trigger WOULD have fired), then force-open regardless for the visual
          // click-through. The persisted once-only flag is intentionally not
          // reset here — force-open ignores it, so this command always works.
          this.log(
            `[dev] PIN onboarding gate: session=${!!this.session} ` +
              `idleAction=${this.effectiveIdleAction()} ` +
              `pinEnrolled=${this.pinLockEnrolled()} ` +
              `promptShown=${!!this.settings.pinOnboardingPromptShown} — force-opening prompt`,
          );
          this.openPinOnboardingPrompt();
        },
      });
    }
  }

  private getPermissionsGraphRuntime(): PermissionsGraphRuntime {
    if (!this.permissionsGraphRuntime) {
      this.permissionsGraphRuntime = createPermissionsGraphRuntime(
        this.createPermissionsGraphRuntimeContext(),
      );
    }
    return this.permissionsGraphRuntime;
  }

  private createPermissionsGraphRuntimeContext(): PermissionsGraphRuntimeContext {
    const thisPlugin = this;
    return {
      app: this.app,
      get apiClient() {
        return thisPlugin.apiClient;
      },
      get session() {
        return thisPlugin.session;
      },
      get manifestId() {
        return thisPlugin.manifest?.id;
      },
      get atRestCipher() {
        return thisPlugin.getAtRestCipher();
      },
      get adapterReadBinary() {
        return thisPlugin.ensureAtRestAdapterRuntimeObject().getAdapterReadBinary();
      },
      get adapterWriteBinary() {
        return thisPlugin.ensureAtRestAdapterRuntimeObject().getAdapterWriteBinary();
      },
      vaultConfigPath: (...parts) => this.vaultConfigPath(...parts),
      ensureParentFoldersForPath: (path) => this.ensureParentFoldersForPath(path),
      normalizeVaultPath: (path) => this.normalizeVaultPath(path),
      logError: (message, error) => this.logError(message, error),
    };
  }

  /**
   * Open (or reveal) the VaultGuard AI Chat panel in the right sidebar.
   */
  private async activateVaultGuardChat(): Promise<void> {
    await activateVaultGuardChatView(this.createSidebarActivationContext());
  }

  /**
   * Open (or reveal) the VaultGuard Permissions graph as a tab in the main
   * editor area (like Obsidian's own Graph view), not the right sidebar.
   */
  private async activatePermissionsGraph(): Promise<void> {
    await activatePermissionsGraphView(this.createSidebarActivationContext());
  }

  /**
   * Data source for the Permissions graph view. Delegates every call to the
   * authenticated API client (requestUrl underneath) and fails closed if the
   * client is not ready — mirroring the agent-bridge `queryAccess` wiring. The
   * view makes NO HTTP request of its own; the backend is the sole authority
   * (requireVaultMember + empty-principals scoping), so this never widens what
   * the signed-in user can see.
   */
  getPermissionsGraphDataSource(): PermissionsGraphDataSource {
    return this.getPermissionsGraphRuntime().getDataSource();
  }

  /** In-memory cached dataset for a vault, or null if absent/expired. */
  getPermissionsGraphCache(vaultId: string): PermissionsGraphDataset | null {
    return this.getPermissionsGraphRuntime().getCache(vaultId);
  }

  /**
   * Cached dataset for a vault, checking memory first then the encrypted disk
   * envelope (hydrating memory on a disk hit). Returns null when nothing fresh
   * exists for the current user.
   */
  async loadPersistedPermissionsGraphCache(vaultId: string): Promise<PermissionsGraphDataset | null> {
    return this.getPermissionsGraphRuntime().loadPersistedCache(vaultId);
  }

  async setPermissionsGraphCache(vaultId: string, data: PermissionsGraphDataset): Promise<void> {
    await this.getPermissionsGraphRuntime().setCache(vaultId, data);
  }

  /** Drop one vault's cache, or all of it when called with no argument. */
  invalidatePermissionsGraphCache(vaultId?: string): void {
    this.getPermissionsGraphRuntime().invalidateCache(vaultId);
  }

  /**
   * Open a brand-new VaultGuard AI Chat conversation as an in-panel tab. This
   * deliberately reuses/reveals the single chat view so users do not end up
   * with several standalone Obsidian chat leaves racing each other.
   */
  async openNewVaultGuardChatTab(): Promise<void> {
    await openNewVaultGuardChatTabView(this.createSidebarActivationContext());
  }

  /** Open the chat panel and pop the previous-chats picker. */
  private async openVaultGuardChatHistory(): Promise<void> {
    await openVaultGuardChatHistoryView(this.createSidebarActivationContext());
  }

  /** Copy a point-in-time DOM/CSS snapshot for diagnosing invisible chat rows. */
  private async copyVaultGuardChatDomDebugReport(): Promise<void> {
    await copyVaultGuardChatDomDebugReportView(this.createSidebarActivationContext());
  }

  /**
   * Mints a share link for the given vault-relative path and copies the
   * https URL to the clipboard. Falls back to a modal-style display if the
   * clipboard API is unavailable (e.g. some headless test environments).
   */
  /** Opens the share-management modal — listed in the command palette. */
  private openShareManagementModal(): void {
    if (this.isLocalProjectMemoryModeEnabled()) {
      new Notice("VaultGuard Sync: sharing is disabled in Local Project Memory Mode.");
      return;
    }
    if (!this.apiClient || !this.session) return;
    new ShareManagementModal(this.app, this.apiClient).open();
  }

  private openRecoveryCenter(initialTab: RecoveryCenterTab = "history"): void {
    if (!this.apiClient || !this.session || !this.settings.serverVaultId) {
      new Notice("VaultGuard Sync: Protect this vault before opening Recovery Center.");
      return;
    }
    const activePath = this.app.workspace.getActiveFile()?.path;
    new RecoveryCenterModal({
      app: this.app,
      apiClient: this.apiClient,
      initialPath: activePath ? this.normalizeVaultPath(activePath) : undefined,
      initialTab,
      getConflicts: () => [...this.syncState.conflicts],
      getConflictFiles: () =>
        this.app.vault
          .getFiles()
          .map((file) => this.normalizeVaultPath(file.path))
          .filter((path) => / \(conflict [^)]+\)(?:\.[^/]+)?$/i.test(path)),
      onOpenPath: async (path) => {
        const file = this.app.vault.getAbstractFileByPath(this.normalizeVaultPath(path));
        if (!(file instanceof TFile)) {
          new Notice(`VaultGuard: "${path}" is not available on this device.`);
          return;
        }
        await this.app.workspace.getLeaf(false).openFile(file);
      },
      onRestored: async () => {
        await this.performSync({ userInitiated: true, forceCatchup: true });
      },
    }).open();
  }

  private async copyShareLinkForPath(path: string): Promise<void> {
    if (this.isLocalProjectMemoryModeEnabled()) {
      new Notice("VaultGuard Sync: share links are disabled in Local Project Memory Mode.");
      return;
    }
    if (!this.session || !this.apiClient || !this.settings.serverVaultId) {
      new Notice("VaultGuard Sync: Log in and bind this vault before sharing.");
      return;
    }

    let share;
    try {
      share = await this.apiClient.createShare({ relPath: path });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      new Notice(`VaultGuard Sync: Couldn't create share link — ${msg}`, 8000);
      return;
    }

    try {
      await navigator.clipboard.writeText(share.url);
      new Notice(`VaultGuard Sync: Share link copied — ${share.url}`, 6000);
    } catch {
      // Clipboard unavailable (rare in Obsidian, but possible in restricted
      // sandboxes). Surface the URL via Notice so the user can copy by hand.
      new Notice(`VaultGuard Sync: Share link: ${share.url}`, 12000);
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Authentication
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Restores session from Obsidian vault-local storage. On desktop the safeStorage envelope
   * decrypts synchronously; on mobile (or any host with no safeStorage) we
   * fall through to the AtRestCipher-sealed envelope, which is async. Total
   * cost on mobile is one AES-GCM decrypt — a few milliseconds.
   *
   * Token refresh still happens in the background from onload.
   */
  private async restoreSession(): Promise<void> {
    // The at-rest load below is an await (the mobile / safeStorage-less decrypt
    // path), so a logout can land between reading the stored session and
    // installing it. Rehydrating is not a new identity — capture, never bump.
    const epoch = this.sessionEpoch;
    let storedSession = this.loadSessionFromStore();
    if (storedSession) {
      this.log("Session restored via safe-storage path");
    }
    if (!storedSession) {
      // safeStorage path returned nothing — either there's no session at all
      // or it was sealed via the AtRestCipher (mobile / safeStorage-less).
      storedSession = await this.loadAtRestSessionFromStore();
      if (storedSession) {
        this.log("Session restored via at-rest-cipher path");
      }
    }
    if (!storedSession) {
      this.log("No stored session found.");
      this.syncDiagnostics.record("restoreSession.noStoredSession");
      if (Platform.isMobileApp && this.settings.debugLogging) {
        new Notice(
          "VaultGuard diag: no stored session — login required",
          5000
        );
      }
      return;
    }

    if (!this.isSessionEpochCurrent(epoch)) {
      this.syncDiagnostics.record("restoreSession.abandoned.sessionEnded");
      return;
    }

    const payload = this.decodeJwtPayload(storedSession.idToken);
    const settingsChanged = this.syncSettingsFromTokenPayload(
      payload,
      storedSession.roles
    );
    if (settingsChanged) {
      this.rebuildApiClient();
      void this.saveSettings().catch((error) => {
        this.logError("Failed to persist session-derived settings", error);
      });
    }

    // Always restore the session immediately (even if tokens are expired).
    // The user is "logged in" as long as we have a refresh token.
    // Token refresh happens in background from onload.
    this.session = storedSession;
    this.syncDiagnostics.record("restoreSession.sessionRestored");
    this.clearLogoutAuthState();
    this.initializeApiClientFromSession(storedSession);

    // Wave 2 issue A (1.0.31): seed vaultMemberRole from the stored
    // session so the imminent runPermissionWarmup uses the real role.
    // refreshVaultMemberRole inside resumeStoredSession will still
    // overwrite this with the server-confirmed value once the background
    // resume lands; this prior is the best-effort answer for the gap.
    if (storedSession.vaultMemberRole !== undefined) {
      this.vaultMemberRole = storedSession.vaultMemberRole;
    }

    this.log(`Session restored for user: ${storedSession.displayName}`);
    this.updateStatusBar();

    if (Platform.isMobileApp && this.settings.debugLogging) {
      const userIdShort = (storedSession.userId ?? "").slice(0, 6) || "—";
      const rawVaultId = this.settings.serverVaultId ?? "";
      const vaultIdShort = rawVaultId.length > 0 ? rawVaultId.slice(0, 6) : "—";
      new Notice(
        `VaultGuard diag: session restored (user=${userIdShort}, vault=${vaultIdShort})`,
        5000
      );
    }

    // Phase 9 (D-20, D-21): warm the unified permission store and run the
    // post-warm leaf sweep. Non-blocking — slow backends won't lock up
    // workspace restore because each step has its own timeout/coalescing.
    void this.runPermissionWarmup()
      .then(() => this.permissionStore.sweepLeavesAfterWarm())
      .catch((err) => {
        this.logError("Permission store warm-up failed (non-blocking)", err);
      });
  }

  /**
   * Public entry point to open the login modal — used by UI surfaces outside
   * main.ts (e.g. the Permissions graph "Sign in" empty-state CTA) that can't
   * call the private handleLogin() directly.
   */
  openLoginModal(): void {
    this.handleLogin();
  }

  /**
   * Handles the login flow. Opens a login modal for the user
   * to enter their email, password, and optional MFA code.
   *
   * @param options.prefillEmail   Email to prefill (used for invite redemption).
   * @param options.firstTimeSetup When true, opens the modal directly in the
   *                               "set your password" form for new invitees.
   * @param options.requireOrgSlug  When true, the org-slug step runs before the
   *                                account step. A build that ships bundled
   *                                Cloud auth never needs it — see below.
   */
  private handleLogin(options?: {
    prefillEmail?: string;
    firstTimeSetup?: boolean;
    requireOrgSlug?: boolean;
  }): void {
    const manualMode = this.settings.manualConfig === true;
    // The org slug is NOT identity-bearing on Cloud, so asking for it up front
    // is pure friction. Every tenant shares one Cognito pool + app client (the
    // /orgs/{slug}/config response returns the same env-var pair for all orgs),
    // this build already ships them in SAAS_DEFAULTS, and the account's
    // custom:org claim supplies tenancy AFTER Cognito validates the password —
    // see the PL1 note in the submit handler below. Org metadata is re-fetched
    // post-login by org id in completeLogin(). The managed admin web login is
    // account-first for exactly these reasons.
    //
    // So: only require the slug when the build has no bundled Cognito pool to
    // fall back on. Manual/self-hosted keeps its own slug + /.well-known flow.
    const hasBundledCloudAuth =
      Boolean(SAAS_DEFAULTS.cognitoUserPoolId) &&
      Boolean(SAAS_DEFAULTS.cognitoClientId);
    const requireOrgSlug =
      options?.requireOrgSlug ?? (!manualMode && !hasBundledCloudAuth);

    const modal = new LoginModal(
      this.app,
      async (credentials: LoginCredentials) => {
        if (manualMode) {
          const cfg = this.getEffectiveConfig();
          // PL1: organizationId is NOT required to authenticate with Cognito —
          // it's derived post-login from the token's custom:org claim
          // (completeLogin → syncSettingsFromTokenPayload). The /.well-known
          // config a CE self-hoster pastes deliberately omits orgId, so
          // requiring it here dead-ended the well-known onboarding flow before
          // any auth could happen. Only the Cognito endpoint/pool/client are
          // genuinely needed up front.
          if (
            !cfg.apiEndpoint ||
            !cfg.cognitoUserPoolId ||
            !cfg.cognitoClientId
          ) {
            throw new Error(
              "Manual configuration requires API endpoint, Cognito User Pool ID, and Cognito Client ID."
            );
          }
          await this.refreshServerCapabilitiesFromConfiguredEndpoint();
        } else {
          // Resolve org config from slug if not already configured or if slug changed.
          const slug = credentials.orgSlug;
          if (slug && (slug !== this.settings.orgSlug || !this.serverFeatures)) {
            await this.resolveOrgConfig(slug);
          }
        }

        // Verify we now have the required config
        const cfg = this.getEffectiveConfig();
        if (!cfg.cognitoUserPoolId || !cfg.cognitoClientId) {
          throw new Error("Organization configuration could not be resolved. Check the slug and try again.");
        }

        await this.performLogin(credentials);
      },
      'server-managed',
      false,
      this.settings.orgSlug,
      async (email: string) => {
        const cfg = this.getEffectiveConfig();
        if (!cfg.apiEndpoint || !cfg.cognitoClientId) {
          throw new Error("Organization configuration not resolved. Please enter your org slug and try logging in first.");
        }
        // Route through the VaultGuard backend (not Cognito directly) so the
        // branded reset email is actually sent via SES. See item: reset code
        // never arrived when triggered from Obsidian.
        await vaultguardForgotPassword(
          cfg.apiEndpoint,
          cfg.cognitoClientId,
          email
        );
      },
      async (email: string, code: string, newPassword: string) => {
        const cfg = this.getEffectiveConfig();
        if (!cfg.apiEndpoint || !cfg.cognitoClientId) {
          throw new Error("Organization configuration not resolved. Please enter your org slug and try logging in first.");
        }
        await vaultguardConfirmReset(
          cfg.apiEndpoint,
          cfg.cognitoClientId,
          email,
          code,
          newPassword
        );
      },
      options?.prefillEmail ?? "",
      options?.firstTimeSetup ?? false,
      requireOrgSlug,
      async (email: string, code: string) => {
        const cfg = this.getEffectiveConfig();
        if (!cfg.apiEndpoint) {
          throw new Error(
            "API endpoint not configured. Enter your org slug or API endpoint first."
          );
        }
        await vaultguardVerifyRecoveryCode(cfg.apiEndpoint, email, code);
        // Clear any stale challenge so the next login starts from the
        // password step and Cognito routes the user to MFA_SETUP.
        this.pendingChallengeSession = null;
      },
      manualMode
        ? undefined
        : async (
            organization,
            email,
            generation,
            isGenerationCurrent,
            onVerificationRequired,
          ) => {
            // Account-first Cloud login carries no slug, so an empty value is
            // normal here and must not throw: the bundled Cloud defaults supply
            // the endpoint and client, and the server binds the attempt to the
            // account rather than an org. Resolve org config only when a slug
            // WAS supplied (saved org, invite redemption, self-hosted).
            const slug = organization.trim().toLowerCase();
            if (slug && (slug !== this.settings.orgSlug || !this.serverFeatures)) {
              await this.resolveOrgConfig(slug);
            }
            const cfg = this.getEffectiveConfig();
            // Check the policy before the config guard — when verification is
            // off there is nothing to fail on, and a missing endpoint must not
            // block a login that never needed a permit.
            if (cfg.loginVerificationMode === "disabled") {
              return { mode: "disabled" } as const;
            }
            if (!cfg.apiEndpoint || !cfg.cognitoClientId) {
              throw new Error("Human verification is temporarily unavailable. Please try again.");
            }
            onVerificationRequired();
            const binding = await completePluginHumanVerification({
              apiBaseUrl: cfg.apiEndpoint,
              organization: slug,
              email,
              clientId: cfg.cognitoClientId,
              generation,
              isGenerationCurrent,
            });
            return { mode: cfg.loginVerificationMode, binding };
          },
      // Self-hosted users are provisioned by their own admin, so only managed
      // Cloud builds point at hosted registration.
      !manualMode
    );
    modal.open();
  }

  /**
   * Redeem an invite — auto-configure the plugin from a deep link or pasted
   * URL of the form `obsidian://vaultguard-invite?org=slug&email=user@x.com`.
   *
   * Looks up the org's public config (Cognito IDs + API endpoint) by slug,
   * persists settings, then opens the login modal in "set your password" mode.
   */
  async redeemInvite(params: {
    org?: string;
    slug?: string;
    email?: string;
    api?: string;
    token?: string;
    exp?: string;
    [key: string]: string | undefined;
  }): Promise<void> {
    const slug = (params.org ?? params.slug ?? "").trim().toLowerCase();
    if (!slug) {
      new Notice("VaultGuard Sync invite link is missing the org slug.");
      throw new Error("Missing org slug in invite link.");
    }

    if (params.api) {
      if (!this.settings.manualConfig) {
        throw new Error(
          "Invite links cannot override the VaultGuard Cloud API endpoint. Switch to manual configuration for self-hosted invite links."
        );
      }
      const normalizedApi = normalizeVaultGuardApiBaseUrl(params.api);
      if (normalizedApi) {
        this.settings.apiEndpoint = normalizedApi;
        await this.saveSettings();
      }
    }

    new Notice(`VaultGuard Sync: Connecting to "${slug}"...`);

    try {
      await this.resolveOrgConfig(slug);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      new Notice(`VaultGuard Sync: Failed to resolve organization "${slug}". ${msg}`);
      throw err;
    }

    if (this.session) {
      new Notice(
        `VaultGuard Sync: Already signed in as ${this.session.email}. Logout first to redeem this invite.`
      );
      return;
    }

    const email = (params.email ?? "").trim();
    this.handleLogin({
      prefillEmail: email,
      firstTimeSetup: true,
      requireOrgSlug: false,
    });
  }

  /** Pending Cognito challenge session (for MFA flow) */
  private pendingChallengeSession: string | null = null;

  /**
   * True while a Cognito NEW_PASSWORD_REQUIRED challenge is awaiting the user's
   * new password (admin-issued temporary password). Paired with
   * `pendingChallengeSession` so the re-submit branch can respond to the
   * challenge instead of starting a fresh USER_PASSWORD_AUTH.
   */
  private pendingNewPasswordChallenge = false;

  /**
   * Performs login by authenticating directly with Cognito,
   * then using the JWT tokens for API calls.
   */
  private async performLogin(credentials: LoginCredentials): Promise<void> {
    const cfg = this.getEffectiveConfig();
    if (!cfg.cognitoUserPoolId || !cfg.cognitoClientId) {
      throw new Error("Cognito User Pool ID and Client ID must be configured in settings.");
    }

    let authResult: CognitoAuthResult;

    // Local dev server: bypass Cognito entirely and authenticate against the
    // mock /auth/login endpoint. No MFA / challenge flow in dev mode.
    if (isLocalDevAuth(cfg.cognitoUserPoolId)) {
      authResult = await devServerLogin(cfg.apiEndpoint, credentials.email, credentials.password);
      await this.completeLogin(authResult, credentials.email);
      return;
    }

    // If we have a pending NEW_PASSWORD_REQUIRED challenge and the user supplied
    // a new password, respond to that challenge (mirrors the MFA re-submit
    // below). The response may itself carry a follow-on challenge (e.g.
    // MFA_SETUP / SOFTWARE_TOKEN_MFA) or the final tokens, so route it through
    // the same handleAuthResult helper as the initial auth.
    if (this.pendingChallengeSession && this.pendingNewPasswordChallenge && credentials.newPassword) {
      let challengeResult: CognitoAuthResult;
      try {
        challengeResult = await cognitoRespondToChallenge(
          cfg.cognitoUserPoolId,
          cfg.cognitoClientId,
          "NEW_PASSWORD_REQUIRED",
          this.pendingChallengeSession,
          {
            USERNAME: credentials.email,
            NEW_PASSWORD: credentials.newPassword,
          }
        );
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (isExpiredChallengeSessionError(message)) {
          // A fresh InitiateAuth would run Cognito PreAuthentication again.
          // The prior human-verification permit was consumed by the original
          // attempt, so restart the journey and require a new proof instead of
          // silently retrying without metadata or replaying the old permit.
          this.pendingChallengeSession = null;
          this.pendingNewPasswordChallenge = false;
          throw new Error("AUTH_RESTART_REQUIRED");
        }
        if (/invalidpassword|conform to policy|password.*(policy|requirement)/i.test(message)) {
          throw new Error(
            "That password doesn't meet the requirements. Use at least 12 characters with upper/lowercase, a number, and a symbol."
          );
        }
        if (/attribute/i.test(message)) {
          throw new Error(
            "This account needs extra setup to set a password — contact your admin."
          );
        }
        throw err;
      }
      this.pendingChallengeSession = null;
      this.pendingNewPasswordChallenge = false;
      await this.handleAuthResult(challengeResult, credentials);
      return;
    }

    // If we have a pending MFA challenge, respond to it
    if (this.pendingChallengeSession && credentials.mfaCode) {
      try {
        authResult = await cognitoRespondToChallenge(
          cfg.cognitoUserPoolId,
          cfg.cognitoClientId,
          "SOFTWARE_TOKEN_MFA",
          this.pendingChallengeSession,
          {
            USERNAME: credentials.email,
            SOFTWARE_TOKEN_MFA_CODE: credentials.mfaCode,
          }
        );
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (isExpiredChallengeSessionError(message)) {
          // A new InitiateAuth requires a fresh, one-time human-verification
          // permit. Return to credentials so the modal invalidates the old
          // challenge generation and obtains a new browser proof.
          this.pendingChallengeSession = null;
          this.pendingNewPasswordChallenge = false;
          throw new Error("AUTH_RESTART_REQUIRED");
        }
        throw err;
      }
      this.pendingChallengeSession = null;
    } else {
      // Initial auth with email/password
      authResult = await cognitoLogin(
        cfg.cognitoUserPoolId,
        cfg.cognitoClientId,
        credentials.email,
        credentials.password,
        credentials.loginPermitMetadata,
      );
    }

    await this.handleAuthResult(authResult, credentials);
  }

  /**
   * Routes a Cognito auth result: handles any outstanding challenge
   * (MFA required, MFA setup, new password required) or completes the login
   * when tokens are present. Shared by the initial auth path and the
   * challenge re-submit paths so a challenge that follows another challenge
   * (e.g. NEW_PASSWORD_REQUIRED → MFA_SETUP) is handled identically.
   */
  private async handleAuthResult(
    authResult: CognitoAuthResult,
    credentials: LoginCredentials
  ): Promise<void> {
    // Handle challenges (MFA required, new password required, etc.)
    if (authResult.challengeName) {
      this.pendingChallengeSession = authResult.session ?? null;

      if (authResult.challengeName === "SOFTWARE_TOKEN_MFA" ||
          authResult.challengeName === "SMS_MFA") {
        throw new Error("MFA code required");
      }

      if (authResult.challengeName === "MFA_SETUP") {
        // User needs to register a TOTP device — open the setup modal
        await this.handleMfaSetup(authResult.session ?? "", credentials);
        return;
      }

      if (authResult.challengeName === "NEW_PASSWORD_REQUIRED") {
        // Admin-issued temporary password — drive the inline set-password
        // sub-form in the login modal via this sentinel. The modal re-submits
        // with credentials.newPassword, which performLogin responds to above.
        this.pendingChallengeSession = authResult.session ?? null;
        this.pendingNewPasswordChallenge = true;
        throw new Error("NEW_PASSWORD_REQUIRED");
      }
      throw new Error(`Authentication challenge: ${authResult.challengeName}`);
    }

    await this.completeLogin(authResult, credentials.email);
  }

  /**
   * Opens the MFA setup modal for first-time TOTP device registration.
   * After setup, completes the login by responding to the MFA_SETUP challenge
   * and then following the normal post-auth flow.
   */
  private async handleMfaSetup(session: string, credentials: LoginCredentials): Promise<void> {
    const cfg = this.getEffectiveConfig();
    // Get the TOTP secret from Cognito
    const associateResult = await cognitoAssociateSoftwareToken(
      cfg.cognitoUserPoolId,
      session
    );

    return new Promise<void>((resolve, reject) => {
      const modal = new MfaSetupModal(this.app, {
        secretCode: associateResult.secretCode,
        email: credentials.email,
        session: associateResult.session,
        onVerify: async (code: string, verifySession: string) => {
          return cognitoVerifySoftwareToken(
            cfg.cognitoUserPoolId,
            verifySession,
            code
          );
        },
        onCancel: () => {
          // Cancelling/closing the MFA-setup modal mid-login must settle the
          // awaited Promise (resolve, NOT reject — avoids a generic error toast)
          // so the login flow ends cleanly with no session instead of hanging.
          new Notice(
            "VaultGuard Sync: two-factor setup is required to finish signing in. You were not signed in — start the login again when you're ready."
          );
          resolve();
        },
        onComplete: (result) => {
          void (async () => {
            try {
              // Respond to the MFA_SETUP challenge to finish authentication
              const challengeResult = await cognitoRespondToChallenge(
                cfg.cognitoUserPoolId,
                cfg.cognitoClientId,
                "MFA_SETUP",
                result.session,
                {
                  USERNAME: credentials.email,
                }
              );

              // If Cognito now asks for the TOTP code (common after setup)
              if (challengeResult.challengeName === "SOFTWARE_TOKEN_MFA") {
                // Re-authenticate since we need a fresh MFA code
                this.pendingChallengeSession = challengeResult.session ?? null;
                new Notice("VaultGuard Sync: MFA enabled! Please log in again with your authenticator code.");
                resolve();
                return;
              }

              // MFA setup complete and tokens returned — finish login first so
              // the session is established, then push the recovery code hashes
              // to the backend using the now-active session token.
              if (challengeResult.tokens.idToken) {
                await this.completeLogin(challengeResult, credentials.email);
                await this.storeRecoveryCodes(
                  credentials.email,
                  result.recoveryCodes,
                  challengeResult.tokens.idToken
                );
                new Notice("VaultGuard Sync: MFA enabled and logged in successfully.");
              }
              resolve();
            } catch {
              // MFA was set up but challenge completion failed — user can log in with MFA next time
              new Notice("VaultGuard Sync: MFA enabled! Please log in again with your authenticator code.");
              resolve();
            }
          })();
        },
      });
      modal.open();
    });
  }

  /**
   * Stores hashed recovery codes for the user. Called after MFA setup once
   * the server session has been established. The hashes match the format
   * the backend's /auth/recovery-codes/verify endpoint expects:
   *   sha256(normalised code) where normalisation strips every non-alphanumeric
   *   and lowercases. The plain code (with hyphen) never leaves the client.
   *
   * The id token from the just-completed Cognito challenge is passed
   * explicitly so this works even if `this.session` is still being torn
   * down or rebuilt around the MFA transition.
   */
  private async storeRecoveryCodes(
    email: string,
    codes: string[],
    idTokenOverride?: string
  ): Promise<void> {
    const hashedCodes: string[] = [];
    for (const code of codes) {
      const normalised = code.replace(/[^a-z0-9]/gi, "").toLowerCase();
      hashedCodes.push(await this.computeHash(normalised));
    }

    try {
      const response = await this.apiRequest(
        "POST",
        "/auth/recovery-codes",
        { codes: hashedCodes },
        idTokenOverride
      );
      if (!response.success) {
        // Recovery codes are functional now (backend implements the route),
        // so a failure is worth surfacing. Don't block login but let the
        // user know they should regenerate.
        this.log(`Recovery codes not stored: ${response.error?.message ?? "unknown"}`);
        new Notice(
          "VaultGuard Sync: Couldn't save recovery codes to the server. Keep the codes you wrote down — you can regenerate from settings later."
        );
      }
    } catch (err) {
      this.log(`Failed to store recovery codes: ${(err as Error).message}`);
      new Notice(
        "VaultGuard Sync: Couldn't save recovery codes to the server. Keep the codes you wrote down — you can regenerate from settings later."
      );
    }
  }

  /**
   * Completes the login flow after successful Cognito authentication
   * (either direct or after MFA). Creates server session, initializes
   * API client, and starts sync.
   */
  private async completeLogin(authResult: CognitoAuthResult, email: string): Promise<void> {
    const idPayload = this.decodeJwtPayload(authResult.tokens.idToken);
    const expiresAt = new Date(Date.now() + authResult.tokens.expiresIn * 1000);
    const serverSession = await this.openServerSession(authResult.tokens.idToken);
    const backendRoles = serverSession.roles ?? [];
    const sessionRoles =
      backendRoles.length > 0 ? backendRoles : this.deriveFallbackRoles(idPayload);
    const derivedConfig = deriveConnectionConfigFromTokenPayload(
      idPayload,
      sessionRoles
    );
    const idSub = this.readConfigString(idPayload, "sub");
    const idName = this.readConfigString(idPayload, "name");
    const idEmail = this.readConfigString(idPayload, "email");

    const session: UserSession = {
      sessionId: serverSession.sessionId,
      userId: serverSession.userId || idSub,
      organizationId:
        derivedConfig.organizationId || this.getEffectiveConfig().organizationId,
      displayName: idName || serverSession.email || idEmail || email,
      email: serverSession.email || idEmail || email,
      accessToken: authResult.tokens.accessToken,
      idToken: authResult.tokens.idToken,
      refreshToken: authResult.tokens.refreshToken,
      tokenExpiresAt: expiresAt.toISOString(),
      role: this.derivePrimaryRole(idPayload, backendRoles),
      roles: sessionRoles,
      createdAt: new Date().toISOString(),
    };
    // A fresh identity is a session transition too: it must invalidate any
    // background restore still holding the PREVIOUS user's session, otherwise a
    // late write-back would replace this login with the account just signed out
    // of (see `sessionEpoch`).
    this.beginSessionEpoch();
    this.session = session;
    this.clearLogoutAuthState();
    // A fresh session entry supersedes any standing wrong-account toast —
    // that verdict was about the previous identity (quick-260820-ki7
    // stale-toast fix); this identity gets its own answer below.
    this.hideWrongAccountNotice();
    // POST /auth/session no longer issues a key lease — leases are vault-scoped
    // and are requested explicitly via /auth/key-lease/scoped after the vault
    // binding is resolved. This eliminates the org-wide DEK that used to leak
    // out at login and could decrypt ciphertext from any vault under the org.
    this.keyLease = null;
    this.applyOrgSettings(serverSession.orgSettings ?? this.orgSettings);

    const settingsChanged = this.syncSettingsFromTokenPayload(idPayload, sessionRoles);
    if (settingsChanged) {
      await this.saveSettings();
    }

    // The local dev server has no SaaS org-config endpoint (/orgs/{slug}/config),
    // so don't attempt the post-login refresh in dev mode — it would just log a
    // spurious "Organization not found" error every login.
    if (
      !this.settings.manualConfig &&
      session.organizationId &&
      !isLocalDevAuth(this.getEffectiveConfig().cognitoUserPoolId)
    ) {
      try {
        await this.resolveOrgConfig(session.organizationId, { silent: true });
      } catch (err) {
        this.logError("Cloud org config refresh after login failed", err);
      }
    }

    this.rebuildApiClient();
    this.initializeApiClientFromSession(session);

    await this.persistSession(session);
    if (this.isLocalProjectMemoryModeEnabled()) {
      this.keyLease = null;
      this.vaultLeaseDenied = false;
      this.stopSyncTimer();
      this.stopKeyRenewalMonitor();
      this.stopHeartbeatMonitor();
      this.setConnectionStatus("offline", { scheduleRetry: false, notify: false });
      // Offline here is the intended end state, not a failure to recover from.
      this.serverSessionResumeComplete = true;
      new Notice(`VaultGuard Sync: Logged in as ${session.displayName}; ${LOCAL_PROJECT_MEMORY_MODE_NOTICE}`, 8000);
      return;
    }
    this.startKeyRenewalMonitor();
    this.startHeartbeatMonitor();
    new Notice(`VaultGuard Sync: Logged in as ${session.displayName}`);

    // Vault binding gate: every Obsidian local folder must be tied to one
    // server-side vault. Defer sync engine boot — and the "online" status
    // flip that triggers offline-queue flushes — until binding is resolved
    // and a vault-scoped lease is loaded.
    if (!this.settings.serverVaultId) {
      // No binding → no vault-scoped operations possible yet. Safe to flip
      // online so the picker / API requests work.
      this.setConnectionStatus("online");
      await this.promptVaultBinding();
    }

    if (this.settings.serverVaultId) {
      // A persisted/recovered binding is only a hint. Prove this identity can
      // access the exact `/vaults/{vaultId}` resource before requesting a lease
      // or allowing reconciliation to reuse it.
      if (!(await this.verifyBoundVaultAuthorization())) {
        this.setConnectionStatus("online");
        this.maybeEnterLockOnAuth();
        this.refreshAtRestRecoverySurfaces();
        return;
      }
      // Resolve this user's per-vault role before starting sync so the UI
      // (file header, decorations, sidebar) renders the correct read /
      // write / admin affordances for *this* vault. Org role alone is
      // ambiguous: an org "member" may still be a vault "admin" here.
      await this.refreshVaultMemberRole();
      const leaseResult = await this.ensureVaultScopedKeyLease();

      // 401 path: session was destroyed by forceLogout. Bail before flipping
      // online and starting the sync engine — both would race on a wiped
      // session and produce the misleading "Connection restored, flushing
      // offline queue..." log immediately followed by "Sync skipped — not
      // logged in" that the limited-rights login bug originally surfaced.
      if (leaseResult === "logged-out" || !this.session) {
        return;
      }

      // 403 path ("limited"): session is intact, keyLease is null. Sync and
      // cloud reads can still download permission-allowed files through the
      // server-side decrypt path; encrypted uploads stay paused. We still
      // flip online because the API is reachable and other endpoints
      // (sidebar, audit, share-link mgmt) continue to work without a DEK.
      this.setConnectionStatus("online");
      // A completed login brings the server side up exactly as a completed
      // resume does (monitors started above, binding verified, lease decided),
      // so a later reconnect must not re-drive `resumeStoredSession` over it.
      this.serverSessionResumeComplete = true;
      this.syncDiagnostics.record("initializeSyncEngine.invoke", { caller: "login" });
      this.initializeSyncEngine().catch((err) => {
        this.logError("Sync engine init failed (non-blocking)", err);
      });

      // First-login race fix: the header/decorations refresh fired inside
      // refreshVaultMemberRole() above runs before the vault-scoped lease and
      // the permission warmup have settled, so the per-file access list can
      // render with only the current user (the access summary fell back before
      // members/principals were ready) and stays that way until a restart.
      // Once warmup settles, force one more refresh so every principal shows —
      // this is exactly the fresh fetch a restart performs, done automatically.
      void this.awaitPermissionWarmup().then(() => {
        this.filePermissionHeader?.invalidateCache();
        void this.filePermissionHeader?.update({ force: true });
        this.syncFileExplorerDecorationsState();
        // Repopulate any open Permissions graph now that session + vault binding
        // + permission warmup have all settled. The connection-edge refresh in
        // setConnectionStatus() can fire while serverVaultId is still empty
        // (login flips online before binding), leaving the panel pinned on its
        // "select a vault" empty state until reopened — this closes that gap.
        this.refreshPermissionsGraph();
      });
    } else {
      this.log("Vault binding skipped — sync engine deferred until a vault is picked.");
      // Nothing server-side is left to resume: the user declined to bind, and
      // picking a vault later runs its own bring-up. Marking it complete keeps a
      // reconnect from re-minting a session for a folder with no vault.
      this.serverSessionResumeComplete = true;
    }

    // Phase 12-07 (passkey model): a fresh login unlocks the vault transparently
    // when the transparent lak.envelope is present and "Require PIN on startup" is
    // off — no PIN prompt after the email+password+MFA login (the double-auth we
    // removed). maybeEnterLockOnAuth curtains ONLY for a legacy/no-wrap device or the
    // max-security toggle; when it does curtain, enterLockState stops sync +
    // key-renewal but keeps the heartbeat alive (NN-2).
    this.maybeEnterLockOnAuth();

    // Quick 260708-el6: a fresh login for a NEW user in a lock-policy org with no
    // PIN yet — offer the skippable, once-ever "Set a PIN" prompt so idle-lock is
    // discoverable. Gated + idempotent behind the persisted flag, so it shows at
    // most once across reloads. This is now the ONLY entry point.
    //
    // Unawaited on purpose: the offer waits for the at-rest cipher to hold a live
    // LAK (so the prompt can never appear on a vault that would then refuse the
    // PIN), and login must not stall behind that.
    void this.maybeOfferPinOnboarding().catch((err) =>
      this.logError("PIN onboarding offer failed", err)
    );

    // Login is an at-rest transition point: re-assert the #1 surfaces so a
    // needs-recovery cipher stays alarmed (and clears if login unlocked it).
    this.refreshAtRestRecoverySurfaces();
  }

  /**
   * Opens the VaultPickerModal so the user can pick (or create) a server-side
   * vault to bind this Obsidian folder to. Persists `serverVaultId` and
   * rebuilds the API client on success.
   */
  private async promptVaultBinding(): Promise<boolean> {
    if (!this.apiClient) {
      this.log("promptVaultBinding: no apiClient, skipping.");
      return false;
    }
    const folderName = this.app.vault.getName() || "My Vault";
    const isOrgAdmin =
      this.session?.role === "admin" || this.session?.role === "owner";
    let vaultChanged = false;
    // While blocked, an auto-bind is a zero-click "pick" that the blocked-lane
    // delegation in applyVaultBinding would treat as the user engaging the
    // takeover flow — the modal must show the state, not act on it
    // (quick-260820-fvo).
    const blockedAtOpen =
      this.vaultBindingAuthorization === "account-changed" ||
      this.vaultBindingAuthorization === "wrong-account";

    const { VaultPickerModal } = await import("./vault-picker-modal");
    await new Promise<void>((resolve) => {
      const modal = new VaultPickerModal(
        this.app,
        this.apiClient!,
        {
          suggestedName: folderName,
          canCreateVaults: isOrgAdmin,
          currentVaultId: this.settings.serverVaultId || undefined,
          disableAutoBind: blockedAtOpen,
        },
        async (result) => {
          vaultChanged = await this.applyVaultBinding(result);
        }
      );
      modal.onClose = () => {
        modal.contentEl.empty();
        resolve();
      };
      modal.open();
    });
    return vaultChanged;
  }

  private async applyVaultBinding(result: { vaultId: string; name: string; slug: string }): Promise<boolean> {
    const changed = this.settings.serverVaultId !== result.vaultId;
    const previousVaultId = this.settings.serverVaultId?.trim() ?? "";
    // Captured PRE-mutation beside the id (quick-260820-prn), because the
    // blocked lane's gate runs AFTER the settings below have been rewritten,
    // where this field already names the vault being JOINED.
    const previousVaultName = this.settings.serverVaultName?.trim() ?? "";
    const wasBlocked =
      this.vaultBindingAuthorization === "account-changed" ||
      this.vaultBindingAuthorization === "wrong-account";

    // VAULT-TO-VAULT SWITCH GATE (quick-260820-mv4). A folder that already
    // holds one vault's files cannot simply be re-pointed at another: the old
    // contents stay on disk and reconciliation offers to upload them into the
    // vault just connected. The switch replaces the local cache instead, which
    // needs the same consent boundary as an account takeover.
    //
    // Runs FIRST, before a single field is mutated, so:
    //   - the cross-check can still prove the vault being LEFT, and
    //   - a decline (or a headless runtime) leaves the binding exactly as it
    //     was — no half-switched state is reachable.
    //
    // Excluded lanes: a FIRST bind (`!previousVaultId`) has no previous cache
    // to purge and keeps today's reconciliation modal; a blocked binding
    // delegates to adoptBindingForCurrentAccount below, which owns its own
    // ki7 gate and must not be double-gated here.
    const isVaultSwitch = changed && !!previousVaultId && !!this.session && !wasBlocked;
    if (
      isVaultSwitch &&
      // The name is passed explicitly (quick-260820-prn) — same value the gate
      // used to read for itself, now sourced from the one place it is provably
      // the vault being LEFT: before any mutation.
      !(await this.confirmVaultSwitchLocalPurge(previousVaultId, result.name, {
        previousVaultName: this.settings.serverVaultName || undefined,
      }))
    ) {
      new Notice(
        `VaultGuard Sync: switch cancelled — this folder stays connected to ${
          this.settings.serverVaultName || "its current vault"
        }.`,
        6000
      );
      return false;
    }

    if (changed) {
      // Searches are authority-bound to the old server vault. Cancel before
      // mutating the binding so no late result can cross the switch boundary.
      this.notifyDiscoveryLifecycleChanged();
      if (this.shouldPurgeSemanticIndex()) {
        await this.purgeSemanticRuntime("vault-switch");
      }
      // Drop the old vault's lease *before* the vaultId flips. Any read or
      // write that fires between the vaultId change and the
      // ensureVaultScopedKeyLease call below would otherwise route a
      // request to the new vault's S3 prefix and try to decrypt it with
      // the old vault's DEK — guaranteed AES-GCM tag failure.
      // interceptedRead's `this.keyLease` guard short-circuits to the
      // local copy until the new lease lands.
      this.keyLease = null;
      this.ensureSyncRuntime().cancelActiveOperations("vault binding changed");
      this.vaultBindingAuthorization = "unverified";
      // The expectation SURVIVES the pick — deliberately (quick-260820-fvo).
      // It is FOLDER-scoped (it guards the on-disk LAK residue the previous
      // account left behind), not vault-scoped, so binding a different vault
      // does not dissolve it. adoptBindingForCurrentAccount needs it intact
      // to distinguish a takeover from a same-account re-bind; only adopt's
      // consented reset or a verify success may move it.
      this.accountChangePromptedForUserId = null;
    }

    this.settings.serverVaultId = result.vaultId;
    this.settings.serverVaultName = result.name;
    this.settings.serverVaultSlug = result.slug;

    if (changed) {
      delete this.settings.bindingReconciledVaultId;
      delete this.settings.lastSyncTimestamp;
      this.syncState.lastSync = null;
      // Phase 9: BROADCAST — vault binding changed, surfaces must refresh.
      // Subscriptions in the four init* methods invoke readOnlyGuard /
      // file-explorer / sidebar / header invalidations; the bus listener
      // replaces the explicit per-surface fan-out that lived here.
      // SD-03-F5: a vault switch invalidates the ENTIRE permission context, so
      // fully clear the cache — including the root sentinel "". emit()'s
      // wildcard handler deliberately PRESERVES root (WR-04), which would let
      // vault A's root level bleed into vault B and bypass its glob-deny rules.
      // Mirror the logout path: invalidate() (full clear) then emit().
      this.permissionStore.invalidate();
      this.permissionStore.emit("changed", { serverConfirmed: true });
      this.localOnlyCatchupCompleted = false;
      this.stopSyncTimer();
    }

    await this.saveSettings();
    this.rebuildApiClient();
    let capsulePersistDelegated = false;
    if (this.session) {
      this.initializeApiClientFromSession(this.session);
      if (wasBlocked) {
        // Blocked-pick delegation (quick-260820-fvo): an explicit pick — or
        // the picker's zero-click single-vault auto-bind — is NOT takeover
        // consent. adoptBindingForCurrentAccount owns the boundary: probe
        // WITHOUT stamping → cleanliness check (auto when clean, the discard
        // dialog when dirty; quick-260820-ki7) → the account-takeover reset
        // (wipe, re-key, re-pull); its same-account
        // lane covers a wrong-account state for the same identity. For a
        // CHANGED vault while identity-mismatched, the bookkeeping above then
        // a crash BEFORE the reset self-heals: the expectation still
        // mismatches, so the prompt re-arms on restart and the consented
        // reset re-pulls the newly bound vault — no silent adoption is
        // possible. Recursion audit: the reset and the resume path call
        // verify/probe, never applyVaultBinding (no cycle);
        // sessionResumePromise plus the resume-completion guard inside
        // resumeIncompleteServerSession hold off resume re-entry.
        if (changed) {
          // The old vault's role must not survive into the new binding; the
          // resume re-drive refreshes it.
          this.vaultMemberRole = null;
        }
        // Both previous-vault values are threaded (quick-260820-prn) so adopt's
        // same-identity lane can see that the VAULT changed underneath it — the
        // only thing its identity comparison structurally cannot know.
        await this.adoptBindingForCurrentAccount(previousVaultId, previousVaultName);
        // Early return — the quick-260819-u8a capsulePersistDelegated latch
        // extended to this lane: adopt's lanes persist via reset/verify, so
        // the trailing fire below must never add a second rotation. The
        // changed post-verify block is redundant here too — adopt's
        // unconditional resume re-drive performs refreshVaultMemberRole, the
        // lease and the sync-engine bring-up via restoreServerSession, and on
        // adopt failure a lease for an unadopted folder must NOT be acquired.
        return changed;
      }
      if (!(await this.verifyBoundVaultAuthorization())) return changed;
      // Verify's success branch already fired the capsule persist — and every
      // capsule-relevant input (serverVaultId/Name/Slug, session identity) was
      // set above before verify ran — so a second trailing fire here would
      // only schedule a redundant rotation.
      capsulePersistDelegated = true;
    }

    // Vault changed — the user's effective role may differ on the new
    // vault (e.g. admin on vault A but viewer on vault B). Always refresh
    // membership and propagate to the UI before returning.
    if (changed) {
      this.vaultMemberRole = null;
      await this.refreshVaultMemberRole();
      // Lease can come back as "limited" (403, viewer with deny rules) or
      // "logged-out" (401, session expired mid-binding). Both are handled
      // inside ensureVaultScopedKeyLease — we just need to surface the
      // outcome to the caller's UI flow without throwing.
      await this.ensureVaultScopedKeyLease();
      // No reload prompt here any more (quick-260820-mv4). The per-file access
      // list used to need one because the header held the API client captured
      // at `onload` — after a rebind it queried the PREVIOUS vault and
      // rendered "Access details unavailable" until Obsidian restarted. Both
      // permission surfaces now resolve the client live, and the
      // permission-store broadcast below already clears their directory
      // caches, so the access list repopulates in place.
    }

    // Consent (or proven cleanliness) was collected above, membership in the
    // NEW vault is verified and its lease is held: replace the local cache
    // (quick-260820-mv4). The reset wipes the previous vault's VG1 content,
    // re-provisions the LAK and re-pulls the newly bound vault — it issues no
    // server DELETEs, so the vault just left is untouched. Its own guard is
    // authoritative and refuses with zero side effects on any state miss.
    if (isVaultSwitch) {
      try {
        await this.resetLocalAtRestAndResync({ mode: "vault-switch", previousVaultId });
        new Notice(
          `VaultGuard Sync: this folder now holds ${
            this.settings.serverVaultName || "the selected vault"
          } — the local cache was replaced.`,
          6000
        );
      } catch (error) {
        this.logError("Vault-switch local reset failed", error);
        new Notice(
          "VaultGuard Sync: connecting this folder to the new vault failed while replacing the local cache. " +
            "Nothing was uploaded or deleted on either vault — open VaultGuard and retry the switch.",
          0
        );
      }
    }

    if (!capsulePersistDelegated) {
      void this.persistLocalRecoveryCapsule();
    }

    return changed;
  }

  /**
   * Decodes a JWT payload without verification (verification happens server-side).
   */
  private decodeJwtPayload(token: string): Record<string, unknown> {
    try {
      const payload = token.split(".")[1];
      const decoded = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
      const parsed: unknown = JSON.parse(decoded);
      return parsed && typeof parsed === "object" ? parsed as Record<string, unknown> : {};
    } catch {
      return {};
    }
  }

  private deriveFallbackRoles(idPayload: Record<string, unknown>): string[] {
    const groupClaim = idPayload["cognito:groups"];
    if (Array.isArray(groupClaim)) {
      return groupClaim.filter((value): value is string => typeof value === "string");
    }

    const roleCandidates = [
      idPayload["custom:orgRole"],
      idPayload["custom:role"],
    ].filter((value): value is string => typeof value === "string" && value.length > 0);

    return roleCandidates.length > 0 ? roleCandidates : ["member"];
  }

  private derivePrimaryRole(
    idPayload: Record<string, unknown>,
    roles: string[]
  ): UserSession["role"] {
    const candidates = [
      ...roles,
      ...this.deriveFallbackRoles(idPayload),
    ].map((value) => value.trim().toLowerCase());

    // Use exact matching consistent with backend isAdmin():
    // backend checks roles.includes('admin') / 'vault-admin' / 'owner'
    if (candidates.includes("owner")) {
      return "owner";
    }
    if (candidates.includes("admin") || candidates.includes("vault-admin")) {
      return "admin";
    }
    if (candidates.includes("editor") || candidates.includes("write")) {
      return "editor";
    }
    return "member";
  }

  /**
   * Returns the role string the UI should render for the *current vault*.
   *
   * Combines the user's org-level role (from the JWT) with their per-vault
   * membership role (from `/vaults/{id}/members`). Resolution order:
   *
   *   1. If the user is an org "owner" or "admin", that wins — they have
   *      full access regardless of vault membership. Matches the
   *      short-circuit in `getEffectivePermission`.
   *   2. Otherwise, prefer the vault membership role ("admin", "editor",
   *      "viewer") so the UI reflects each vault's per-vault grant rather
   *      than the user's flat org role.
   *   3. Fall back to the org role string when no vault membership has
   *      been resolved yet (e.g. before the first /vaults/{id}/members
   *      response, or when the user gets vault access via a role-based
   *      rule rather than a direct membership row).
   */
  private getEffectiveUiRole(): string {
    if (!this.session) {
      return "member";
    }
    if (this.session.role === "owner" || this.session.role === "admin") {
      return this.session.role;
    }
    if (this.vaultMemberRole) {
      return this.vaultMemberRole;
    }
    return this.session.role;
  }

  /**
   * True when the user should see admin-level UI affordances on the current
   * vault (manage permissions, invite members, change vault settings).
   */
  private isEffectiveAdmin(): boolean {
    const role = this.getEffectiveUiRole();
    return role === "admin" || role === "owner";
  }

  /**
   * True when this org has `allowAdminPerFileRestrictions` enabled — the single
   * client-side definition of "per-file deny rules bind admins" (SD-03-F15).
   * Every consumer (permission store, at-rest adapter runtime, file-permission
   * header, org-settings flip detection) reads THIS, so the value cannot drift
   * between surfaces.
   */
  private isAdminRestrictionActive(): boolean {
    return this.orgSettings?.allowAdminPerFileRestrictions === true;
  }

  /**
   * Refreshes `vaultMemberRole` from the server and pushes the resulting
   * effective role into every live UI surface (file header, file-explorer
   * decorations, sidebar). Also clears the per-file permission cache so the
   * next read/write check re-resolves against the new identity context.
   *
   * Safe to call multiple times. No-ops when there is no session or no
   * bound server vault. Network/permission failures are swallowed — the UI
   * just falls back to the org role until the next refresh succeeds.
   */
  private async refreshVaultMemberRole(): Promise<void> {
    if (!this.session || !this.settings.serverVaultId || !this.apiClient) {
      this.vaultMemberRole = null;
      this.applyEffectiveRoleToUi();
      return;
    }

    try {
      const role = await this.getCurrentVaultMemberRole();
      this.vaultMemberRole = role;
    } catch (error) {
      // Vault membership lookup is best-effort. A 403 here means the user
      // can't list members (they may still have file-level access via a
      // role-based rule) — fall back to org role rendering.
      this.logError("Failed to refresh vault membership role", error);
      this.vaultMemberRole = null;
    }

    // Phase 9: role changed — broadcast through the bus. The four init*
    // subscriptions handle readOnlyGuard / fileExplorer / sidebar / header.
    this.applyEffectiveRoleToUi();
    this.permissionStore.emit("changed", { serverConfirmed: true });

    // Kick off cache warm-up so subsequent file reads hit the cache and
    // skip the per-file network round trip. Non-blocking — the store's
    // warm() coalesces concurrent triggers internally.
    this.runPermissionWarmup().catch((err) => {
      this.logError("Permission cache warm-up failed (non-blocking)", err);
    });
  }

  /**
   * Fetches the applicable rule set so the caller can hand it to
   * `permissionStore.warm(rules, vaultRole)`. The store is decoupled from
   * the rule-fetch choice (D-04), so the call shape lives here.
   *
   * Wave 2 Fix 2 (1.0.31): returns a discriminated union so callers can
   * tell the difference between "user genuinely has no rules" and
   * "we couldn't fetch them". The pre-fix shape (return `[]` on error)
   * was the silent-poison vector behind the 2026-05-31 Pete incident —
   * an API failure looked identical to "this user has no permissions"
   * and seeded the store with the viewer baseline.
   */
  private async collectRulesForWarmup(): Promise<WarmupRulesResult> {
    if (!this.session || !this.apiClient) {
      return { kind: "ok", rules: [] };
    }
    // SD-03-F15: only an UNrestricted org admin may warm with no rules at all.
    // When the org restriction is on, falling through takes the
    // `isEffectiveAdmin()` branch below — `getPermissions()`, the vault-wide
    // rule list, which `handleListPermissions` already paginates fully (LF3) —
    // and `PermissionStore.warm` then filters it through
    // `ruleAppliesToCurrentUser`.
    if (
      !this.isAdminRestrictionActive() &&
      (this.session.role === "admin" || this.session.role === "owner")
    ) {
      return { kind: "ok", rules: [] };
    }
    try {
      const rules = this.isEffectiveAdmin()
        ? await this.apiClient.getPermissions()
        : await this.apiClient.getUserPermissions(this.session.userId);
      return { kind: "ok", rules };
    } catch (err) {
      const statusCode = this.extractStatusCode(err);
      this.log(
        `Permission warm-up: rules fetch failed (status=${statusCode ?? "?"}): ${(err as Error).message}`
      );
      return { kind: "fetch-failed", statusCode, error: err };
    }
  }

  /**
   * Best-effort status-code extraction for an unknown thrown value.
   * Covers our `ApiClient` error shape, Obsidian `requestUrl` errors,
   * and plain `Response`-style objects.
   */
  private extractStatusCode(err: unknown): number | null {
    if (!err || typeof err !== "object") return null;
    const candidate = err as {
      statusCode?: unknown;
      status?: unknown;
      response?: { status?: unknown; statusCode?: unknown } | undefined;
    };
    const direct = candidate.statusCode ?? candidate.status;
    if (typeof direct === "number" && Number.isFinite(direct)) return direct;
    const nested = candidate.response?.statusCode ?? candidate.response?.status;
    if (typeof nested === "number" && Number.isFinite(nested)) return nested;
    return null;
  }

  /**
   * Picks a backoff delay for the next warmup retry given the status
   * code of the failure that triggered it. 401/403 typically means the
   * idToken on the request didn't pass API Gateway authoriser — the
   * apiClient's auto-refresh should land before the retry; a short delay
   * is fine. 5xx → server hiccup → wait a bit more. Anything else (incl.
   * `null` for network errors) → assume the device is offline-ish and
   * wait a full minute.
   */
  private pickWarmupRetryDelayMs(statusCode: number | null): number {
    if (statusCode === 401 || statusCode === 403) return 5_000;
    if (statusCode !== null && statusCode >= 500) return 30_000;
    return 60_000;
  }

  /**
   * Schedules a single warmup retry. Capped at MAX_WARMUP_RETRIES per
   * session — after that, only an explicit user action (focus, login,
   * settings change) re-fires.
   */
  private scheduleWarmupRetry(statusCode: number | null): void {
    if (this.warmupRetryCount >= MAX_WARMUP_RETRIES) {
      this.log(
        `Permission warm-up: retry cap reached (${MAX_WARMUP_RETRIES}); waiting for focus / explicit refresh.`
      );
      return;
    }
    if (this.warmupRetryTimer !== null) {
      // Already a retry scheduled — leave it alone.
      return;
    }
    this.warmupRetryCount += 1;
    const delayMs = this.pickWarmupRetryDelayMs(statusCode);
    this.log(
      `Permission warm-up: scheduling retry ${this.warmupRetryCount}/${MAX_WARMUP_RETRIES} in ${delayMs}ms (status=${statusCode ?? "?"}).`
    );
    this.warmupRetryTimer = setTimeout(() => {
      this.warmupRetryTimer = null;
      void this.runPermissionWarmup().catch((err) =>
        this.logError("Permission warm-up retry failed (non-blocking)", err)
      );
    }, delayMs);
  }

  private resetWarmupRetryState(): void {
    this.warmupRetryCount = 0;
    if (this.warmupRetryTimer !== null) {
      clearTimeout(this.warmupRetryTimer);
      this.warmupRetryTimer = null;
    }
  }

  /**
   * Wave 2 issue D (1.0.31): focus-triggered re-warm. Self-heals the
   * permission cache after long backgrounding without forcing the
   * user through a logout/login dance. Skips the retry-cap when
   * invoked from a user-visible signal — focus is an explicit
   * "I'm here, please catch up" intent.
   */
  private maybeRewarmOnFocus(): void {
    if (!this.session || !this.settings.serverVaultId) return;
    const state = this.permissionStore.getStoreState();
    if (state.kind === "warming") return;
    if (state.kind === "warmed") {
      const ageMs = Date.now() - state.warmedAt;
      if (ageMs < 5 * 60 * 1000) return;
    }
    // Cold, fetch-failed, or stale-warmed → fire a fresh warm-up.
    // Reset the retry counter so a fetch-failed state that exhausted
    // its quiet-retries can recover on user-visible focus.
    this.resetWarmupRetryState();
    void this.runPermissionWarmup().catch((err) =>
      this.logError("Focus-triggered permission warm-up failed (non-blocking)", err)
    );
  }

  /**
   * Drives a single warm-up cycle through the PermissionStore. Coalesced
   * by the store internally (one in-flight promise per warm). Also bumps
   * `permissionWarmupInFlight` so the status bar can render "Loading
   * permissions..." until warm-up settles. The counter (vs a boolean) means
   * two overlapping triggers don't have the later finally clear the flag
   * while the earlier is still running (WR-03).
   */
  private async runPermissionWarmup(): Promise<void> {
    if (!this.session || !this.apiClient || !this.settings.serverVaultId) {
      return;
    }
    this.permissionStore.markWarming();
    this.permissionWarmupInFlight = this.permissionWarmupInFlight + 1;
    this.updateStatusBar();
    const cycle = (async () => {
      try {
        const result = await this.collectRulesForWarmup();
        if (result.kind === "fetch-failed") {
          // Wave 2 Fix 2 (1.0.31): do NOT seed the store with an empty
          // rule set when the fetch itself failed — that would put the
          // cache into the silent-poison state the 2026-05-31 incident
          // exposed. Mark the store fetch-failed (consumers render
          // skeleton) and schedule a status-aware retry.
          this.permissionStore.markFetchFailed(result.statusCode);
          this.scheduleWarmupRetry(result.statusCode);
          return;
        }
        await this.permissionStore.warm(result.rules, this.vaultMemberRole);
        this.hasWarmedAtLeastOnce = true;
        this.resetWarmupRetryState();
      } finally {
        this.permissionWarmupInFlight = Math.max(0, this.permissionWarmupInFlight - 1);
        this.updateStatusBar();
      }
    })();
    this.warmupCyclePromise = cycle;
    cycle.finally(() => {
      if (this.warmupCyclePromise === cycle) {
        this.warmupCyclePromise = null;
      }
    });
    return cycle;
  }

  /**
   * Pauses up to 5 s for the warm-up to finish so a cold-start file open
   * doesn't beat the cache. Returns immediately if no warm-up is in flight
   * or once the warm-up resolves. The cap exists so a stuck backend can't
   * lock up Obsidian's workspace restore — slow paths fall through to the
   * existing per-file network probe.
   *
   * Races the store's in-flight warm-up promise against a 5 s timeout. Using
   * Promise.race (not a polled setTimeout chain) means a stuck warm-up
   * cannot leak a chained 50 ms timer loop, and repeated calls cannot stack
   * multiple poll loops on the same in-flight warm (WR-02).
   */
  private async awaitPermissionWarmup(): Promise<void> {
    // Prefer the plugin-level cycle promise because it covers the
    // collectRulesForWarmup HTTP fetch window. permissionStore.inFlightWarmup
    // only spans the inner store.warm() call and is null during the gap
    // between runPermissionWarmup() entry and store.warm() being reached.
    const inFlight = this.warmupCyclePromise ?? this.permissionStore.inFlightWarmup;
    if (!inFlight) return;

    let timer: ReturnType<typeof setTimeout> | null = null;
    const timeout = new Promise<void>((resolve) => {
      timer = setTimeout(resolve, 5_000);
    });

    try {
      // Swallow rejection from the warm promise — this is a best-effort
      // pause, not an error surface. The race resolves on whichever fires
      // first; the loser's outcome is discarded.
      await Promise.race([inFlight.catch(() => undefined), timeout]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  /**
   * Re-fetch rules and re-warm AFTER a server-confirmed permission change
   * (SD-03-F16). Wired into `PermissionStore` as `requestWarmup`.
   *
   * Waits for any warm cycle already in flight FIRST: `PermissionStore.warm()`
   * coalesces on its in-flight promise, so starting a fresh warm while an older
   * cycle is mid-flight can have the post-change rules silently swallowed and
   * the PRE-change rule set seeded instead (DESIGN M9). Deliberately unbounded
   * (unlike `awaitPermissionWarmup`'s 5 s race) because a timeout here would
   * re-open exactly that stale-rule window; the caller is the `void`-dispatched
   * permission-change fan-out, which already tolerates slow network work and
   * wraps this call in try/catch.
   *
   * MUST NOT emit('changed') — directly or transitively (PermissionStore
   * Pitfall 3 re-entrance guard). Verified: the warm path only fires the
   * lifecycle-only `state-changed` event (markWarming / markFetchFailed /
   * runWarm's notifyStoreStateChanged).
   */
  private async requestPermissionWarmupRefresh(): Promise<void> {
    const inFlight = this.warmupCyclePromise ?? this.permissionStore.inFlightWarmup;
    if (inFlight) {
      await inFlight.catch(() => undefined);
    }
    await this.runPermissionWarmup();
  }

  /**
   * Waits briefly for restored-session permission context to become usable.
   *
   * This is intentionally bounded: if the backend is slow or unreachable,
   * Obsidian should not hang forever. But when the resume is healthy, this
   * closes the startup race where all non-admin files were evaluated against
   * an empty offline permission cache before the user's vault role loaded.
   */
  private async awaitPermissionReadiness(): Promise<void> {
    let timer: ReturnType<typeof setTimeout> | null = null;
    const timeout = new Promise<void>((resolve) => {
      timer = setTimeout(resolve, 5_000);
    });

    try {
      if (this.sessionResumePromise) {
        await Promise.race([this.sessionResumePromise, timeout]);
      }
    } finally {
      if (timer) clearTimeout(timer);
    }

    await this.awaitPermissionWarmup();
  }

  /**
   * Pushes the current effective role into already-mounted UI components.
   * Safe to call when components haven't been initialised yet (no-ops).
   */
  private applyEffectiveRoleToUi(): void {
    const role = this.getEffectiveUiRole();
    const userId = this.session?.userId ?? "";
    const isAdmin = this.isEffectiveAdmin();

    this.filePermissionHeader?.setContext({
      currentUserId: userId,
      currentUserEmail: this.session?.email ?? "",
      currentUserRole: role,
      isAdmin,
    });
    this.filePermissionHeader?.invalidateCache();
    void this.filePermissionHeader?.update({ force: true });

    this.fileExplorerDecorations?.setConfig({
      currentUserId: userId,
      currentUserRole: role,
    });
    this.syncFileExplorerDecorationsState();

    // Refresh sidebar config + ask any open sidebar view to re-render.
    const sidebarConfig = this.createSidebarViewConfig();
    if (sidebarConfig) {
      this.sidebarViewConfig = sidebarConfig;
      const leaves = this.app.workspace.getLeavesOfType(VAULTGUARD_VIEW_TYPE);
      for (const leaf of leaves) {
        const view = leaf.view as unknown as {
          configure?: (cfg: VaultGuardSidebarViewConfig) => void;
          reload?: () => Promise<void>;
        };
        if (view?.configure) {
          view.configure(sidebarConfig);
        }
        if (view?.reload) {
          void view.reload();
        }
      }
    }
  }

  private normalizeKeyLease(
    rawLease: Partial<KeyLease>,
    responseDeniedPaths?: LeaseDeniedPath[]
  ): KeyLease {
    if (!rawLease.key || !rawLease.expiresAt || !rawLease.refreshToken || !rawLease.leaseId) {
      throw new Error("VaultGuard Sync: Server did not return a usable encryption key lease.");
    }

    return {
      key: rawLease.key,
      expiresAt: rawLease.expiresAt,
      refreshToken: rawLease.refreshToken,
      leaseId: rawLease.leaseId,
      keyId: rawLease.keyId ?? rawLease.leaseId,
      algorithm: rawLease.algorithm ?? "AES-256-GCM",
      offlineCapable: rawLease.offlineCapable ?? true,
      encryptedDataKey: rawLease.encryptedDataKey,
      scope: rawLease.scope ?? '/**',
      vaultId: rawLease.vaultId,
      deniedPaths: normalizeLeaseDeniedPaths([
        ...normalizeLeaseDeniedPaths(rawLease.deniedPaths),
        ...normalizeLeaseDeniedPaths(responseDeniedPaths),
      ]),
    };
  }

  /**
   * Launch the official `codex login` flow. Codex owns the browser OAuth and
   * credential storage; VaultGuard never receives or reads the resulting token.
   */
  async startCodexCliLogin(): Promise<void> {
    if (Platform.isMobileApp) {
      throw new Error("Codex sign-in needs desktop Obsidian.");
    }
    const maybeWindow =
      typeof window !== "undefined" ? (window as unknown as Record<string, unknown>) : {};
    const req =
      typeof maybeWindow.require === "function"
        ? (maybeWindow.require as NodeRequire)
        : null;
    if (!req) {
      throw new Error("Node child_process is unavailable in this runtime.");
    }

    const found = await findCodexBinary();
    if (!found) {
      throw new Error(
        "No usable Codex runtime was found. Install or update the ChatGPT desktop app, sign in, and retry.",
      );
    }

    const childProcess = req("child_process") as {
      spawn(
        cmd: string,
        args: ReadonlyArray<string>,
        opts: {
          stdio?: "ignore" | "inherit";
          env?: NodeJS.ProcessEnv;
          shell?: boolean;
          windowsHide?: boolean;
        },
      ): {
        on(ev: "error", cb: (err: Error) => void): void;
        on(ev: "close", cb: (code: number | null) => void): void;
      };
    };

    return new Promise<void>((resolve, reject) => {
      let settled = false;
      try {
        const env = typeof process !== "undefined" ? { ...process.env } : undefined;
        if (env) {
          // `codex login` without --with-api-key is the ChatGPT OAuth flow.
          // Remove ambient API credentials as defense in depth so this action
          // cannot silently fall back to a metered provider mode.
          delete env.OPENAI_API_KEY;
          delete env.CODEX_API_KEY;
          delete env.OPENAI_ACCESS_TOKEN;
        }
        const child = childProcess.spawn(found.binaryPath, ["login"], {
          stdio: "ignore",
          env,
          shell: /\.(?:cmd|bat)$/i.test(found.binaryPath),
          windowsHide: true,
        });
        child.on("error", (error) => {
          if (settled) return;
          settled = true;
          reject(new Error(`Could not start Codex sign-in: ${error.message}`));
        });
        child.on("close", () => {
          if (settled) return;
          settled = true;
          resolve();
        });
      } catch (error) {
        if (settled) return;
        settled = true;
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    });
  }

  private isPathDeniedByKeyLease(path: string): boolean {
    const normalizedPath = this.normalizeVaultPath(path);
    return Boolean(this.keyLease?.deniedPaths?.some((entry) =>
      keyLeasePathMatchesPattern(normalizedPath, entry.pathPattern)
    ));
  }

  private async openServerSession(idToken: string): Promise<{
    sessionId: string;
    userId: string;
    email: string;
    roles: string[];
    expiresAt: string;
    orgSettings?: OrgSettingsResponse;
  }> {
    const response = await this.apiRequest<{
      sessionId: string;
      userId: string;
      email: string;
      roles: string[];
      expiresAt: string;
      orgSettings?: OrgSettingsResponse;
    }>(
      "POST",
      "/auth/session",
      { vaultId: this.settings.serverVaultId || undefined },
      idToken,
      { suppressSessionHeader: true }
    );

    if (!response.success || !response.data) {
      throw new Error(response.error?.message ?? "VaultGuard Sync: Failed to create a server session.");
    }

    return response.data;
  }

  /**
   * SD-02-F1: mints a replacement server session id for a live session that has
   * none, so the client stops issuing headerless authenticated requests.
   *
   * THE FINDING. A session persisted before the session-header work carries no
   * `sessionId` at all. `resolveRequestSessionId()` therefore returns `null`
   * forever and EVERY authenticated request goes out without
   * `X-VaultGuard-Session-Id` — permanently, with no path back, because nothing
   * in the running plugin ever re-mints mid-session. Production evidence: 9,965
   * server-side `[SESSION_TELEMETRY]` headerless samples over 7 days, 9,706 of
   * them (97%) from one real external user, all `GET /vaults` — the signature of
   * `attemptReconnection`'s backoff probe looping headerless against a session
   * that can never heal itself.
   *
   * WHY IT IS NOT `restoreServerSession`'S JOB. That method's else-branch (see
   * ~L5960) already re-mints ON THE HAPPY PATH and is deliberately left alone:
   * it also serves the stale-but-PRESENT `sessionId` case, which this method's
   * fast exit refuses by design (a present id is never re-minted here). This
   * method is the fallback for every path where that restore never ran, ran
   * before the id was needed, or failed — which is exactly the production
   * signature above.
   *
   * BEST-EFFORT BY CONTRACT. It is quiet on failure (a breadcrumb and a debug
   * log, no Notice), never rethrows, never calls `forceLogout`,
   * `handleServerRevocation` or `clearSession`, never nulls `this.session`, and
   * never blocks startup — `restoreSession()` does not call it, so offline
   * startup is byte-identical to before. A failed heal simply degrades to
   * today's headerless behavior and is retried on a later request.
   *
   * It also deliberately does NOT touch `this.keyLease` (unlike
   * `restoreServerSession`, this runs mid-session and must not evict a live
   * lease), starts/stops no monitor, and does not move the connection status.
   */
  private async ensureServerSessionId(): Promise<void> {
    if (!this.session) return;
    // THE hot path: a healthy session costs exactly this one truthiness check
    // and is never re-minted. Everything below is unreachable in steady state.
    if (this.session.sessionId) return;
    // A revocation logout owns the session right now — do not race it.
    if (this.terminalRefreshLogoutInProgress) return;

    // Join the attempt already running instead of starting a second one. This is
    // also the recursion brake if anything re-enters through `apiRequest`.
    if (this.sessionReMintInFlight) {
      return this.sessionReMintInFlight;
    }

    if (
      Date.now() - this.lastSessionReMintAttemptAt <
      SESSION_REMINT_MIN_INTERVAL_MS
    ) {
      this.syncDiagnostics.record("ensureServerSessionId.cooldown");
      return;
    }

    this.sessionReMintInFlight = (async () => {
      // FIRST statement: a throwing attempt must still arm the cooldown.
      this.lastSessionReMintAttemptAt = Date.now();

      const session = this.session;
      if (!session) return;

      if (this.isSessionTokenExpiring(session)) {
        const refreshResult = await this.refreshAccessToken(session);
        if (!refreshResult.ok) {
          // Deliberately does NOT escalate `refreshResult.terminal` to
          // handleServerRevocation/forceLogout. This is a background heal; the
          // existing apiRequest / resumeStoredSession terminal paths already own
          // that decision and will reach it through their own flow.
          this.syncDiagnostics.record("ensureServerSessionId.refreshDeferred", {
            message: refreshResult.message ?? "token refresh failed",
          });
          return;
        }
      }

      // Re-read across the await: refreshAccessToken reassigns `this.session`,
      // and a concurrent restoreServerSession may have won the race and already
      // supplied an id — in which case there is nothing left to heal.
      const live = this.session;
      if (!live || live.sessionId) return;

      // The plan's try/catch in promise form: the mint MUST NOT rethrow into the
      // caller (an apiRequest that would otherwise have simply gone out
      // headerless), and must leave the session exactly as it found it.
      const serverSession = await this.openServerSession(live.idToken).catch(
        (error: unknown) => {
          const message =
            error instanceof Error ? error.message : String(error);
          this.log(
            `Server session re-mint failed, keeping the existing session: ${message}`
          );
          this.syncDiagnostics.record("ensureServerSessionId.mintFailed", {
            message,
          });
          return null;
        }
      );
      if (!serverSession) return;

      const current = this.session;
      if (!current || current.sessionId) return;

      // Identity fields mapped exactly as restoreServerSession's else-branch:
      // role/roles come from the SERVER response, never widened locally.
      this.session = {
        ...current,
        sessionId: serverSession.sessionId,
        userId: serverSession.userId || current.userId,
        email: serverSession.email || current.email,
        role: this.derivePrimaryRole({}, serverSession.roles ?? current.roles),
        roles: serverSession.roles?.length ? serverSession.roles : current.roles,
      };
      this.clearLogoutAuthState();
      this.applyOrgSettings(serverSession.orgSettings ?? this.orgSettings);
      this.initializeApiClientFromSession(this.session);
      await this.persistSession(this.session);
      this.syncDiagnostics.record("ensureServerSessionId.minted");
    })().catch((error: unknown) => {
      // Belt and braces. Nothing above is expected to throw, but the stored
      // promise is awaited by concurrent joiners too, so it must never reject:
      // a best-effort heal may not turn into a failed user request.
      this.logError(
        "Server session re-mint failed unexpectedly (session kept)",
        error
      );
      this.syncDiagnostics.record("ensureServerSessionId.unexpectedError", {
        message: error instanceof Error ? error.message : String(error),
      });
    });

    try {
      await this.sessionReMintInFlight;
    } finally {
      // Cleared so a later trigger can retry once the cooldown has elapsed.
      this.sessionReMintInFlight = null;
    }
  }

  private async resumeStoredSession(): Promise<void> {
    this.syncDiagnostics.record("resumeStoredSession.enter", { hasSession: !!this.session });
    if (!this.session) {
      this.syncDiagnostics.record("resumeStoredSession.return.noSession");
      return;
    }

    // This whole routine is fired unawaited from `onload`, so a logout can land
    // anywhere inside it. Capture the generation once and abandon quietly if it
    // moves (see `sessionEpoch`).
    const epoch = this.sessionEpoch;

    let session = this.session;
    let tokenWasRefreshed = false;
    if (this.isSessionTokenExpiring(session)) {
      const refreshResult = await this.refreshAccessToken(session);
      // Checked BEFORE the failure branches below: a logout during the refresh
      // is not a degraded session that needs a Notice and a retry monitor, it is
      // the expected outcome of what the user just asked for.
      if (!this.isSessionEpochCurrent(epoch)) {
        this.syncDiagnostics.record("resumeStoredSession.return.sessionEnded");
        return;
      }
      if (!refreshResult.ok) {
        // PL4: a terminal rejection means the stored session is dead (refresh
        // token revoked/expired or user disabled) — clean it up now instead of
        // restoring a zombie session that can never talk to the backend.
        if (refreshResult.terminal) {
          this.syncDiagnostics.record("resumeStoredSession.return.terminalRefresh");
          this.terminalRefreshLogoutInProgress = true;
          try {
            await this.handleServerRevocation("stored session expired or revoked");
          } finally {
            this.terminalRefreshLogoutInProgress = false;
          }
          return;
        }
        // Fix 4 (1.0.30): surface the degraded state. Previously this was
        // a silent `this.log(...)` that left the user with a permission
        // cache poisoned by the earlier stale-token warm-up (Fix 1
        // comment below). At minimum the user now knows to re-login if
        // it persists.
        this.log(
          `Stored session token refresh deferred: ${refreshResult.message}`
        );
        this.notifySessionRestoreDegraded(refreshResult.message);
        // PL2: a transient refresh failure at startup used to return here
        // without ever starting the key-renewal monitor — so once connectivity
        // returned nothing re-requested the lease and uploads stayed paused.
        // Flag a lease retry and start the monitor so its recovery branch
        // re-attempts acquisition (apiRequest refreshes the token first) as
        // soon as the network is back.
        if (this.settings.serverVaultId) {
          this.leaseRetryNeeded = true;
          this.startKeyRenewalMonitor();
        }
        this.syncDiagnostics.record("resumeStoredSession.return.refreshDeferred");
        return;
      }
      if (!this.session) {
        this.syncDiagnostics.record("resumeStoredSession.return.noSessionAfterRefresh");
        return;
      }
      session = this.session;
      tokenWasRefreshed = true;
    }

    // Fix 1 (1.0.30): the warm-up fired from restoreSession() at the top
    // of onload() ran with the stored — possibly expired — access token.
    // On mobile, where the plugin is background-killed for hours at a
    // time, that warm-up's HTTP call almost always 401s; the resulting
    // empty rule set seeds PermissionStore with the vault-role baseline
    // only, and every per-file lookup then resolves to view-only. Now
    // that the refresh has landed fresh tokens onto the apiClient, fire
    // a fresh warm-up so the cache reflects the user's actual rules.
    // The 2026-05-31 Pete incident — mobile audit log silent for 4.5+
    // hours until an explicit logout/login — is the proof case.
    if (tokenWasRefreshed) {
      void this.runPermissionWarmup().catch((err) =>
        this.logError(
          "Post-refresh permission warm-up retry failed (non-blocking)",
          err
        )
      );
    }

    try {
      await this.restoreServerSession(session);
    } catch (err) {
      // Fix 1 + Fix 4 (1.0.30): treat any failure inside the server-side
      // resume as a session-degraded condition. Tokens are fresh by now
      // (we refreshed above if needed), so a single warm-up retry has a
      // real chance of repopulating the cache before the user opens a
      // file. The Notice is the user's escape hatch — re-login if it
      // doesn't self-heal within a focus cycle.
      this.logError("restoreServerSession failed", err);
      this.notifySessionRestoreDegraded(
        err instanceof Error ? err.message : "background session restore failed"
      );
      void this.runPermissionWarmup().catch((e) =>
        this.logError(
          "Post-failure permission warm-up retry failed (non-blocking)",
          e
        )
      );
      this.syncDiagnostics.record("resumeStoredSession.restoreServerSessionThrew", {
        message: err instanceof Error ? err.message : String(err),
      });
      throw err;
    }
  }

  /**
   * Throttled Notice for the "session is restored locally but the
   * background server-side resume couldn't finish" state (Fix 4, 1.0.30).
   * Previously this state was completely silent (`this.log(...)` only),
   * which is how the 2026-05-31 Pete incident hid for 4.5+ hours: mobile
   * showed cached/baseline permissions while the audit log showed zero
   * API activity, and the user had no way to know a re-login was the
   * fix. Reuses the same 60 s window as `notifyLimitedAccess` so the
   * two surfaces feel consistent.
   */
  private notifySessionRestoreDegraded(reason?: string): void {
    const now = Date.now();
    if (now - this.lastSessionDegradedNoticeAt < 60_000) {
      return;
    }
    this.lastSessionDegradedNoticeAt = now;
    const detail = reason ? ` (${reason})` : "";
    new Notice(
      `VaultGuard Sync: session refresh deferred${detail}. ` +
        `Recent permission changes may not appear yet. ` +
        `Re-login from settings if file permissions look wrong.`,
      8000
    );
  }

  private async restoreServerSession(session: UserSession): Promise<void> {
    this.syncDiagnostics.record("restoreServerSession.enter", {
      hasSessionId: !!session.sessionId,
      hasServerVaultId: !!this.settings.serverVaultId,
    });
    // `session` is a value captured before the network awaits below. If the user
    // logs out (or signs in as someone else) while those are in flight, writing
    // it back would resurrect a dead session — see `sessionEpoch`. Captured
    // BEFORE the binding-authorization gate, because that gate awaits too.
    const epoch = this.sessionEpoch;
    if (this.settings.serverVaultId && !(await this.verifyBoundVaultAuthorization())) {
      // Two very different failures land here and they must not be treated
      // alike. "wrong-account" is a DEFINITIVE server answer (403/404 for this
      // identity) — the API is demonstrably reachable, so flipping online is
      // honest and sync stays paused by design until the user picks an
      // authorized vault. "unverified" means the check could not be COMPLETED
      // (network failure, 5xx, timeout); claiming "online" there is a lie, and
      // because the gate is never re-run it used to pause sync permanently on a
      // single transient blip. Leave the status alone and let the reconnect loop
      // re-drive the whole resume instead.
      const definitive = this.vaultBindingAuthorization !== "unverified";
      if (definitive) {
        // "account-changed" is equally final for THIS loop — only the user can
        // move it — but it is reached without contacting the server at all, so
        // it proves nothing about reachability. Flipping "online" there would
        // be the same lie the branch above rejects. Leave the status alone and
        // let the reconnect probe earn it; sync stays gated on the decision
        // either way.
        if (this.vaultBindingAuthorization !== "account-changed") {
          this.setConnectionStatus("online");
        }
        // Nothing automatic can change a definitive answer, and the branch has
        // already put the decision in front of the user (a sticky Notice for
        // `wrong-account`, the account-change prompt for `account-changed`) — so
        // this counts as a finished resume and `armResumeRetryIfIncomplete` must
        // not restage it on a loop. Only the user moves it from here, and the
        // path that does (`adoptBindingForCurrentAccount` — reached directly,
        // or via `applyVaultBinding`'s blocked-pick delegation to it) clears
        // this flag itself and re-drives the resume.
        this.serverSessionResumeComplete = true;
      }
      this.syncDiagnostics.record("restoreServerSession.return.bindingAuthorizationGate", {
        state: this.vaultBindingAuthorization,
        definitive,
      });
      return;
    }
    let leaseResponse: ApiResponse<{
      keyLease: KeyLease;
      deniedPaths?: LeaseDeniedPath[];
      orgSettings?: OrgSettingsResponse;
    }> | null = null;

    // GET /auth/key-lease now requires vaultId — only attempt the warm-restore
    // path when the folder already has a vault binding. Without a binding
    // we open a fresh session and pick up the vault-scoped lease later via
    // ensureVaultScopedKeyLease() once binding is resolved.
    if (session.sessionId && this.settings.serverVaultId) {
      const params = new URLSearchParams({
        sessionId: session.sessionId,
        vaultId: this.settings.serverVaultId,
      });
      // SD-02-F1 (M10): direct callers may reach this method before assigning
      // `this.session`, so the candidate guarantees this authenticated lease
      // request still carries `X-VaultGuard-Session-Id`. Normal startup already
      // assigned the restored session, and the resolver returns the same id.
      //
      // The window is deliberately EXACTLY this one await. The else-branch below
      // calls `openServerSession` → `POST /auth/session` through the same
      // `apiRequest`; the server validates a session header whenever one is present,
      // so a stale candidate riding that mint would 401 the mint itself and kill the
      // stale-session self-heal. The `finally` guarantees the candidate is gone
      // before either branch of `leaseResponse` runs — on success, failure, or throw.
      this.restoreCandidateSessionId = session.sessionId;
      try {
        leaseResponse = await this.apiRequest<{
          keyLease: KeyLease;
          deniedPaths?: LeaseDeniedPath[];
          orgSettings?: OrgSettingsResponse;
        }>(
          "GET",
          `/auth/key-lease?${params.toString()}`,
          undefined,
          session.idToken
        );
      } finally {
        this.restoreCandidateSessionId = null;
      }
    }

    // The lease request above is the long await — on a slow first reconciliation
    // it can stay pending for many seconds with the ribbon menu live. A logout
    // inside that window owns the session now; drop the restore on the floor
    // rather than undoing it.
    if (!this.isSessionEpochCurrent(epoch)) {
      this.syncDiagnostics.record("restoreServerSession.abandoned.sessionEnded");
      return;
    }

    if (leaseResponse?.success && leaseResponse.data) {
      this.session = session;
      this.clearLogoutAuthState();
      // GET /auth/key-lease?vaultId=... returns the vault-scoped lease.
      this.keyLease = this.normalizeKeyLease(
        leaseResponse.data.keyLease,
        leaseResponse.data.deniedPaths
      );
      this.applyOrgSettings(leaseResponse.data.orgSettings ?? this.orgSettings);
    } else {
      const serverSession = await this.openServerSession(session.idToken);
      // Second await, same rule: a session minted for a user who has since
      // logged out must not be installed.
      if (!this.isSessionEpochCurrent(epoch)) {
        this.syncDiagnostics.record("restoreServerSession.abandoned.sessionEndedDuringMint");
        return;
      }
      this.session = {
        ...session,
        sessionId: serverSession.sessionId,
        userId: serverSession.userId || session.userId,
        email: serverSession.email || session.email,
        role: this.derivePrimaryRole({}, serverSession.roles ?? session.roles),
        roles: serverSession.roles?.length ? serverSession.roles : session.roles,
      };
      this.clearLogoutAuthState();
      // /auth/session no longer issues a key lease — leases are vault-scoped
      // and requested explicitly via ensureVaultScopedKeyLease() below.
      this.keyLease = null;
      this.applyOrgSettings(serverSession.orgSettings ?? this.orgSettings);
    }

    if (this.session) {
      this.initializeApiClientFromSession(this.session);
      await this.persistSession(this.session);
    }

    if (this.isLocalProjectMemoryModeEnabled()) {
      this.keyLease = null;
      this.vaultLeaseDenied = false;
      this.stopSyncTimer();
      this.stopKeyRenewalMonitor();
      this.stopHeartbeatMonitor();
      this.syncDiagnostics.record("restoreServerSession.skipped.localProjectMemoryMode");
      return;
    }

    this.startKeyRenewalMonitor();
    this.startHeartbeatMonitor();

    // Resume-time identity refresh: a returning user's per-vault role may
    // have changed since the last session was persisted (added to a vault,
    // demoted, etc.), and the stale UI would otherwise render whatever role
    // applied at the previous login. Refreshing here pushes the right
    // affordances into the UI before any file access happens.
    if (this.settings.serverVaultId) {
      await this.refreshVaultMemberRole();
      if (!this.keyLease) {
        const leaseResult = await this.ensureVaultScopedKeyLease();

        // 401 inside the lease call → forceLogout already cleared the session.
        // Abort the rest of restoreServerSession; flipping online or starting
        // sync would race on null state and emit misleading "Connection
        // restored" + "Sync skipped" log lines back-to-back.
        if (leaseResult === "logged-out" || !this.session) {
          this.syncDiagnostics.record("restoreServerSession.return.leaseGate", {
            leaseResult,
            hasSession: !!this.session,
          });
          return;
        }
        // "limited" (403) is fine — session still valid, keyLease still null,
        // sync engine + interceptedRead already null-guard on keyLease and
        // gracefully fall back to the local at-rest copy.
      }
      // Phase-8: if we ended up in limited-access mode, rebuild the in-memory
      // placeholderPaths set from on-disk 36-byte VG1 envelopes so reads of
      // previously-reconciled files still go through the hydration path after
      // a plugin reload (placeholderPaths is in-memory only per D-09).
      if (this.vaultLeaseDenied) {
        await this.sweepPlaceholderPaths();
      }
    }

    // Defer the "online" flip — and the offline-queue flush it triggers —
    // until the vault-scoped lease is in place. Otherwise queued writes
    // could be re-encrypted under the org-wide DEK and become unreadable.
    this.setConnectionStatus("online");
    // THE one place the restart path is declared finished. Everything above can
    // return early or throw; only reaching here means monitors are running, the
    // binding is verified and a lease decision has been made. Set AFTER the
    // online flip so a re-drive from `attemptReconnection` is never marked done
    // by a resume that did not actually get this far.
    this.serverSessionResumeComplete = true;
    this.syncDiagnostics.record("restoreServerSession.online");

    this.syncDiagnostics.record("restoreServerSession.syncTimerDecision", {
      syncTimerAlreadySet: !!this.syncTimer,
      willInit: !this.syncTimer,
    });
    if (!this.syncTimer) {
      this.syncDiagnostics.record("initializeSyncEngine.invoke", { caller: "restoreServerSession" });
      this.initializeSyncEngine().catch((err) => {
        this.logError("Sync engine init failed (non-blocking)", err);
      });
    }

    // NO PIN-onboarding nudge here — deliberately REVERSED from quick 260708-el6,
    // which also offered it on this returning-user path. This runs during the
    // unawaited background resume fired from `onload`, so the prompt ambushed the
    // user mid-startup: a modal appeared seconds after merely ENABLING the plugin,
    // with no action of theirs to explain it, and (because `initAtRestCipher()`
    // has not finished this early) "Set PIN" then failed with "Unlock the vault
    // before setting a PIN". The nudge now follows a login — a moment the user
    // initiated, and one where the vault is actually unlocked. Returning users who
    // never re-login keep the Notice from `lockSessionForInactivity`'s
    // session-kept branch, which was always the runtime's real nudge.

    // Session restore is an at-rest transition point too — re-assert the #1
    // surfaces from the cipher's real state (the init-time banner may have
    // fired before layout was ready on a fresh restore).
    this.refreshAtRestRecoverySurfaces();
  }

  /**
   * Refreshes an expired access token using Cognito directly.
   * NEVER clears the stored session — only forceLogout should do that.
   * On any failure, keeps the existing session so the user stays "logged in",
   * but tells callers not to send the now-stale ID token to the backend. That
   * avoids turning a transient Cognito/network refresh failure into a backend
   * 401 that higher-level lease/heartbeat callers could mistake for revocation.
   */
  private async refreshAccessToken(session: UserSession): Promise<AccessTokenRefreshResult> {
    const cfg = this.getEffectiveConfig();
    // Captured before the Cognito round trip below; a logout landing inside it
    // must not have its teardown undone by the write-back (see `sessionEpoch`).
    const epoch = this.sessionEpoch;

    // Local dev server has no token-refresh that returns fresh JWTs (it rotates
    // the session token server-side only). Dev tokens are valid for an hour,
    // which is plenty for a test session — keep the current session as-is.
    if (isLocalDevAuth(cfg.cognitoUserPoolId)) {
      this.session = session;
      return { ok: true };
    }

    if (!cfg.cognitoUserPoolId || !cfg.cognitoClientId || !session.refreshToken) {
      const message = "missing Cognito config or refresh token";
      this.log(`Cannot refresh: ${message}, keeping session.`);
      this.session = session;
      return { ok: false, message };
    }

    try {
      const tokens = await cognitoRefresh(
        cfg.cognitoUserPoolId,
        cfg.cognitoClientId,
        session.refreshToken
      );

      // Fresh tokens for a session that no longer exists are worthless — and
      // writing them back would both resurrect the session in memory and
      // re-persist it to disk, surviving an Obsidian restart.
      if (!this.isSessionEpochCurrent(epoch)) {
        this.log("Token refresh landed after logout; discarding the new tokens.");
        return { ok: false, message: "session ended during token refresh" };
      }

      const expiresAt = new Date(Date.now() + tokens.expiresIn * 1000);
      const idPayload = this.decodeJwtPayload(tokens.idToken);
      const settingsChanged = this.syncSettingsFromTokenPayload(
        idPayload,
        session.roles
      );

      this.session = {
        ...session,
        accessToken: tokens.accessToken,
        idToken: tokens.idToken,
        refreshToken: tokens.refreshToken,
        tokenExpiresAt: expiresAt.toISOString(),
        organizationId:
          deriveConnectionConfigFromTokenPayload(idPayload, session.roles)
            .organizationId || session.organizationId,
      };

      if (settingsChanged) {
        await this.saveSettings();
      }

      this.rebuildApiClient();
      this.initializeApiClientFromSession(this.session);

      await this.persistSession(this.session);
      this.log("Cognito tokens refreshed successfully.");
      return { ok: true };
    } catch (error) {
      // Keep the session on ANY failure — only forceLogout clears it. But
      // classify the error (PL4): a terminal Cognito rejection (revoked or
      // expired refresh token, disabled user) is flagged so callers escalate
      // to a revocation logout instead of retrying forever in "offline".
      const terminal = isTerminalCognitoRefreshError(error);
      this.logError(
        terminal
          ? "Cognito token refresh rejected terminally (refresh token revoked/expired or user disabled)"
          : "Cognito token refresh failed, keeping session",
        error
      );
      // "Keep the session" means keep the one that is still live — not restore
      // one that was torn down while Cognito was failing. A logout inside this
      // window already cleared it deliberately.
      if (!this.isSessionEpochCurrent(epoch)) {
        return { ok: false, message: "session ended during token refresh" };
      }
      this.session = session;
      return {
        ok: false,
        message: error instanceof Error ? error.message : "Token refresh failed",
        error,
        terminal,
      };
    }
  }

  private isSessionTokenExpiring(session: UserSession, bufferMs = 60_000): boolean {
    const expiresAt = new Date(session.tokenExpiresAt).getTime();
    return !Number.isFinite(expiresAt) || expiresAt - Date.now() <= bufferMs;
  }

  /**
   * Returns the current user session, or null if not logged in.
   */
  getSession(): UserSession | null {
    return this.session;
  }

  /**
   * Marks a session identity transition. Call this at every point that installs
   * a new session or tears the current one down — it is what invalidates the
   * epochs captured by in-flight background work (see `sessionEpoch`).
   */
  private beginSessionEpoch(): number {
    this.sessionEpoch += 1;
    return this.sessionEpoch;
  }

  /**
   * True when `epoch` is still the live session generation, i.e. no login or
   * logout has happened since the caller captured it.
   *
   * Async work that captured a session before an `await` MUST check this before
   * writing that value back to `this.session` (or persisting it). Returning
   * false means the caller's session is gone — abandon the work, do not restore
   * it.
   */
  private isSessionEpochCurrent(epoch: number): boolean {
    return this.sessionEpoch === epoch;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Public at-rest API (exposed to settings tab + first-run UX)
  // ─────────────────────────────────────────────────────────────────────────

  /** Snapshot of the cipher state for the settings UI. */
  getAtRestStatus(): import("../crypto/at-rest-cipher").AtRestStatus {
    return this.ensureAtRestAdapterRuntimeObject().getAtRestStatus();
  }

  /**
   * The local at-rest cipher, exposed for the AI-chat key store's
   * safeStorage-unavailable fallback (see src/ui/chat/api-key-store.ts).
   * Returns null before init or after the plugin unloads.
   */
  getAtRestCipher(): AtRestCipher | null {
    return this.ensureAtRestAdapterRuntimeObject().getAtRestCipher();
  }

  /**
   * Walk the vault and count files in each on-disk state — used by the
   * settings UI so the user can see "12 plaintext, 230 encrypted" before
   * deciding whether to migrate.
   *
   * Reads bytes directly via the raw adapter (the at-rest helpers would
   * decrypt and lose the on-disk state we want to inspect). Excluded
   * paths are skipped to match the encryption pass.
   */
  async tallyAtRestState(): Promise<{
    plaintext: number;
    encrypted: number;
    excluded: number;
    failed: number;
    total: number;
  }> {
    return this.ensureAtRestAdapterRuntimeObject().tallyAtRestState();
  }

  /**
   * Re-authenticate the currently-logged-in user against Cognito to
   * confirm they own the account before exposing high-stakes actions
   * (revealing the at-rest recovery code, decrypting the entire vault).
   *
   * The plugin's session token is not mutated — we only care whether
   * Cognito accepts the credentials. A successful auth (full token set or
   * any MFA challenge response) counts as proof of password knowledge.
   * Returns false on bad password and propagates network errors so the
   * UI can show a meaningful message rather than a generic "no".
   */
  async verifyAccountPassword(password: string): Promise<boolean> {
    if (!this.session?.email) {
      throw new Error("VaultGuard Sync: no active session to verify against.");
    }
    const config = this.getEffectiveConfig();
    if (!config.cognitoUserPoolId || !config.cognitoClientId) {
      throw new Error("VaultGuard Sync: Cognito is not configured for this vault.");
    }
    try {
      const result = isLocalDevAuth(config.cognitoUserPoolId)
        ? await devServerLogin(config.apiEndpoint, this.session.email, password)
        : await cognitoLogin(
            config.cognitoUserPoolId,
            config.cognitoClientId,
            this.session.email,
            password
          );
      // Success either when we get tokens back OR when Cognito asks for an
      // MFA challenge — both outcomes confirm the password was correct.
      // We deliberately do NOT continue the MFA flow here; we just want to
      // know the password matched.
      return Boolean(result.tokens?.accessToken) || Boolean(result.challengeName);
    } catch (err) {
      const message = err instanceof Error ? err.message.toLowerCase() : "";
      if (message.includes("invalid email or password")) return false;
      // Re-throw network/config errors so the modal can surface them.
      throw err;
    }
  }

  /** Public entry for the "Encrypt vault at rest" button in settings. */
  async migrateVaultToAtRest(): Promise<void> {
    return this.ensureAtRestAdapterRuntimeObject().migrateVaultToAtRest();
  }

  /** Public entry for the "Decrypt vault" button in settings. */
  async revertVaultFromAtRest(): Promise<void> {
    return this.ensureAtRestAdapterRuntimeObject().revertVaultFromAtRest();
  }

  async decryptVaultAndDisableAtRestEncryption(): Promise<AtRestDecryptAndDisableResult> {
    return this.ensureAtRestAdapterRuntimeObject().decryptVaultAtRestAndDisableEncryption();
  }

  /**
   * Generate the user-readable recovery code. Throws if the cipher is
   * locked / disabled — the caller (settings tab) should gate the button
   * on `getAtRestStatus().kind === "unlocked"`.
   */
  async exportAtRestRecoveryCode(): Promise<string> {
    return this.ensureAtRestAdapterRuntimeObject().exportAtRestRecoveryCode();
  }

  /**
   * Restore the cipher from a previously-exported recovery code.
   *
   * Returns the cipher's rich outcome (SD-05-F3) so the UI can tell a malformed
   * code from a valid code that doesn't open THIS vault. Pass
   * `{ confirmReplace: true }` only after the user has explicitly confirmed a
   * `needs-confirmation` key replacement.
   */
  async restoreAtRestFromRecoveryCode(
    code: string,
    opts?: { confirmReplace?: boolean }
  ): Promise<AtRestRestoreOutcome> {
    return this.ensureAtRestAdapterRuntimeObject().restoreAtRestFromRecoveryCode(code, opts);
  }

  /**
   * Opens the login modal. Exposed for use from the settings tab.
   */
  triggerLogin(): void {
    this.handleLogin();
  }

  openVaultGuardSettings(): void {
    const settingsApp = this.app as unknown as {
      setting?: {
        open?: () => void;
        openTabById?: (id: string) => void;
      };
    };
    const pluginId =
      (this as unknown as { manifest?: { id?: string } }).manifest?.id ??
      "vaultguard";

    try {
      if (settingsApp.setting?.open && settingsApp.setting?.openTabById) {
        settingsApp.setting.open();
        settingsApp.setting.openTabById(pluginId);
        return;
      }
    } catch (error) {
      this.logError("Could not open VaultGuard settings", error);
    }

    new Notice("VaultGuard Sync: Open Settings → Community plugins → VaultGuard Sync.");
  }

  /** Opens Obsidian's native Community plugins updater without private APIs. */
  async openCommunityPluginsForUpdate(): Promise<void> {
    const settingsApp = this.app as unknown as {
      setting?: {
        open?: () => void;
        openTabById?: (id: string) => void;
      };
    };

    try {
      if (settingsApp.setting?.open && settingsApp.setting?.openTabById) {
        settingsApp.setting.open();
        // Obsidian's built-in Community plugins tab (id "community-plugins")
        // hosts every plugin's native Update button — this is NOT the plugin's
        // own settings tab (this.manifest.id); do not substitute it here.
        settingsApp.setting.openTabById("community-plugins");
        return;
      }
    } catch (error) {
      this.logError("Could not open Community plugins for update", error);
    }

    new Notice("VaultGuard Sync: Open Settings → Community plugins to update VaultGuard Sync.");
  }

  private showVaultGuardMenu(evt?: MouseEvent): void {
    const menu = new Menu();
    const localProjectMemoryMode = this.isLocalProjectMemoryModeEnabled();
    const isLoggedIn = !!this.session;
    const isAdmin =
      this.session?.role === "admin" || this.session?.role === "owner";
    const currentVaultName =
      localProjectMemoryMode
        ? "Local Project Memory"
        : this.settings.serverVaultName ||
          this.settings.serverVaultSlug ||
          this.settings.serverVaultId ||
          "No server vault bound";

    menu.addItem((item) =>
      item
        .setTitle(
          isLoggedIn
            ? `${this.session!.email} · ${currentVaultName}`
            : "VaultGuard"
        )
        .setIcon("vaultguard-shield")
        .setDisabled(true)
    );

    menu.addSeparator();

    if (!isLoggedIn) {
      // Already-protected vault + no session ⇒ "Log in again"; only a brand-new,
      // never-bound vault gets the first-run "Protect this vault" onboarding CTA.
      const vaultProtected =
        !!this.settings.serverVaultId ||
        this.localProtectionBootstrap.kind === "existing" ||
        this.localProtectionBootstrap.kind === "needs-recovery";
      menu.addItem((item) =>
        item
          .setTitle(vaultProtected ? "Log in again" : "Protect this vault")
          .setIcon(vaultProtected ? "log-in" : "shield-check")
          .onClick(() => this.handlePrimaryProtectionAction())
      );

      menu.addSeparator();
      menu.addItem((item) =>
        item
          .setTitle("Vault settings")
          .setIcon("settings")
          .onClick(() => this.openVaultGuardSettings())
      );
      this.showMenu(menu, evt);
      return;
    }

    menu.addItem((item) =>
      item
        .setTitle("Vault settings")
        .setIcon("settings")
        .onClick(() => this.openVaultGuardSettings())
    );

    if (localProjectMemoryMode) {
      menu.addItem((item) =>
        item
          .setTitle("Open files panel")
          .setIcon("panel-right")
          .onClick(() => {
            void this.activateVaultGuardSidebar();
          })
      );

      menu.addItem((item) =>
        item
          .setTitle("Open AI chat")
          .setIcon(VAULTGUARD_CHAT_ICON_ID)
          .onClick(() => {
            void this.activateVaultGuardChat();
          })
      );

      menu.addSeparator();
      menu.addItem((item) =>
        item
          .setTitle("Logout")
          .setIcon("log-out")
          .onClick(() => {
            void this.forceLogout();
          })
      );
      this.showMenu(menu, evt);
      return;
    }

    menu.addItem((item) =>
      item
        .setTitle("Pick or switch server vault")
        .setIcon("database")
        .setDisabled(!this.apiClient)
        .onClick(() => {
          void this.switchServerVault();
        })
    );

    menu.addItem((item) =>
      item
        .setTitle("Open files panel")
        .setIcon("panel-right")
        .onClick(() => {
          void this.activateVaultGuardSidebar();
        })
    );

    menu.addItem((item) =>
      item
        .setTitle("Recovery Center")
        .setIcon("history")
        .setDisabled(!this.apiClient || !this.settings.serverVaultId)
        .onClick(() => this.openRecoveryCenter())
    );

    menu.addItem((item) =>
      item
        .setTitle("Open AI chat")
        .setIcon(VAULTGUARD_CHAT_ICON_ID)
        .onClick(() => {
          void this.activateVaultGuardChat();
        })
    );

    menu.addItem((item) =>
      item
        .setTitle("View my permissions")
        .setIcon("shield-check")
        .onClick(() => this.showPermissionsModal())
    );

    if (isAdmin) {
      menu.addItem((item) =>
        item
          .setTitle("Audit log")
          .setIcon("file-text")
          .setDisabled(!this.apiClient)
          .onClick(() => this.openAuditLog())
      );

      menu.addItem((item) =>
        item
          .setTitle("Audit log settings")
          .setIcon("sliders-horizontal")
          .setDisabled(!this.apiClient)
          .onClick(() => this.openAuditConfig())
      );
    }

    menu.addItem((item) =>
      item
        .setTitle("Web admin panel")
        .setIcon("external-link")
        .onClick(() => this.openWebAdminPanel())
    );

    menu.addItem((item) =>
      item
        .setTitle("Sync now")
        .setIcon("refresh-cw")
        .onClick(() => {
          void this.performSync({ userInitiated: true, forceCatchup: true });
        })
    );

    if (isAdmin) {
      menu.addSeparator();
      menu.addItem((item) =>
        item
          .setTitle("Manage organization")
          .setIcon("users")
          .onClick(() => this.showAdminPanel())
      );
    }

    menu.addSeparator();
    menu.addItem((item) =>
      item
        .setTitle("Logout")
        .setIcon("log-out")
        .onClick(() => {
          void this.forceLogout();
        })
    );

    this.showMenu(menu, evt);
  }

  private showMenu(menu: Menu, evt?: MouseEvent): void {
    if (evt) {
      menu.showAtMouseEvent(evt);
      return;
    }

    const fallbackPosition =
      typeof window === "undefined"
        ? { x: 0, y: 0 }
        : {
            x: Math.max(16, Math.round(window.innerWidth / 2)),
            y: Math.max(64, Math.round(window.innerHeight / 3)),
          };
    menu.showAtPosition(fallbackPosition);
  }

  private showLoginRequiredNotice(
    action: "open" | "browse" | "edit" | "delete" | "sync" | "view permissions",
    path?: string
  ): string {
    const normalizedPath = path ? this.normalizeVaultPath(path) : "";
    const target = normalizedPath ? `"${normalizedPath}"` : "protected files";
    const actionText = this.loginRequiredActionText(action, target);
    const message = `VaultGuard Sync: Login required to ${actionText}.`;
    const now = Date.now();

    if (
      this.lastAuthRequiredNoticeAt === null ||
      now - this.lastAuthRequiredNoticeAt >= AUTH_REQUIRED_NOTICE_THROTTLE_MS
    ) {
      new Notice(
        `${message}\nLog in from the VaultGuard Sync shield menu or run "VaultGuard Sync: Login" from the command palette.`,
        9000
      );
      this.lastAuthRequiredNoticeAt = now;
    }

    return message;
  }

  /**
   * When a signed-out user opens a renderable binary (image/PDF/…), surface the
   * same "login required" notice text files get. Media renders via
   * getResourcePath, which never calls interceptedRead/interceptedReadBinary, so
   * without this an attachment opened while logged out is a silent broken
   * preview. No-ops for text (interceptedRead already notices those), excluded
   * paths, and authenticated sessions; showLoginRequiredNotice is throttled.
   */
  private noticeIfMediaOpenWhileLoggedOut(path: string): void {
    if (
      !this.session &&
      isKnownBinaryExtensionPath(path) &&
      !this.isPathExcluded(path)
    ) {
      this.showLoginRequiredNotice("open", path);
    }
  }

  private getSidebarAuthState(): VaultGuardSidebarAuthState | null {
    if (this.localProtectionBootstrap.kind === "needs-recovery") {
      return {
        title: "Recovery required",
        message: "VaultGuard found existing local protection but could not restore its device key.",
        detail: "Restore with the recovery code. Existing encrypted files stay unchanged.",
        icon: "shield-alert",
        tone: "danger",
        actionLabel: "Restore protection",
      };
    }
    if (this.vaultBindingAuthorization === "account-changed") {
      const email = this.session?.email?.trim();
      return {
        title: "A different account is signed in",
        message: `This folder was connected by ${this.describeExpectedAccount()}.`,
        detail:
          "Until you continue, this folder works locally only — notes and edits stay on this device and nothing syncs. Continuing checks whether this account can use the same vault.",
        // `user-cog` is already rendered through setIcon elsewhere in this
        // plugin, so it is a known-good id — an unregistered one renders an
        // invisible, unclickable element rather than failing loudly.
        icon: "user-cog",
        tone: "warning",
        actionLabel: email ? `Continue as ${email}` : "Check my access",
      };
    }
    if (this.vaultBindingAuthorization === "wrong-account") {
      return {
        title: "No access to this folder's vault",
        message: `${this.describeCurrentAccount()} is not a member of the server vault this folder is bound to.`,
        detail:
          "Ask a vault admin for access, or log in as a different account. You can also switch this folder's vault from VaultGuard settings.",
        icon: "shield-x",
        tone: "danger",
        actionLabel: this.session ? "Log in as a different account" : "Log in again",
      };
    }
    if (this.session && this.settings.serverVaultId) {
      return null;
    }
    if (this.lastLogoutAuthState) return this.lastLogoutAuthState;
    // An already-protected vault (bound to a server vault) with no active session
    // is a returning user who needs to sign in again — NOT first-run setup. This
    // is the state after a reload/restart, which drops the in-memory logout state
    // (`lastLogoutAuthState`), so without this branch the sidebar wrongly showed
    // the "Protect this vault" onboarding CTA to someone who is simply logged out.
    if (
      !this.session &&
      (this.settings.serverVaultId || this.localProtectionBootstrap.kind === "existing")
    ) {
      return {
        title:
          this.localProtectionBootstrap.kind === "existing" ? "Existing protection restored" : "Logged out",
        message: "Log in again to reconnect this protected vault.",
        detail: "Your notes stay encrypted at rest until you reconnect.",
        icon: "log-out",
        tone: "warning",
        actionLabel: "Log in again",
      };
    }
    return {
      title: "Protect this vault",
      message: this.session
        ? "Choose or create the server vault that should protect this Obsidian folder."
        : "Sign in, choose a vault, and let VaultGuard protect it with encrypted sync.",
      detail: "Join an existing team or configure self-hosting from the next screen.",
      icon: "shield-check",
      tone: "neutral",
      actionLabel: "Protect this vault",
    };
  }

  private handlePrimaryProtectionAction(): void {
    if (this.localProtectionBootstrap.kind === "needs-recovery") {
      this.startAtRestRecoveryFromRecoveryCode();
      return;
    }
    // Re-offer the account-change resolution. It is one-shot per identity (a
    // resolution storm on every binding re-check would be its own bug), so
    // clear the latch first — this click IS the user asking for it again.
    if (this.session && this.vaultBindingAuthorization === "account-changed") {
      this.accountChangePromptedForUserId = null;
      void this.resolveAccountChange();
      return;
    }
    // Wrong-account is the server's verdict about THIS account: offering the
    // vault picker here was the dead end (§6.4) — the honest primary action
    // is switching accounts. Vault switching stays reachable from Settings
    // and the status-bar menu (switchServerVault), never from this surface.
    if (this.session && this.vaultBindingAuthorization === "wrong-account") {
      void (async () => {
        await this.forceLogout(
          "VaultGuard Sync: logged out. Sign in with an account that can use this folder's vault."
        );
        this.handleLogin();
      })();
      return;
    }
    if (this.session) {
      void this.switchServerVault();
      return;
    }
    this.handleLogin();
  }

  private clearLogoutAuthState(): void {
    this.lastLogoutAuthState = null;
    this.updateRibbonAuthIndicator();
  }

  private rememberLogoutAuthState(noticeMessage: string): void {
    const reason = this.formatLogoutReason(noticeMessage);
    const accessRevoked =
      this.isUserAccessRevokedMessage(reason) ||
      reason.toLowerCase().includes("access revoked");
    const inactivityLock = reason.toLowerCase().includes("inactivity");

    this.lastLogoutAuthState = {
      title: accessRevoked
        ? "Access revoked"
        : inactivityLock
          ? "Session locked"
          : "Logged out",
      message: accessRevoked
        ? "Your VaultGuard session was cleared because access changed."
        : inactivityLock
          ? "VaultGuard locked your session after inactivity."
          : "VaultGuard is no longer connected to your account.",
      detail: reason,
      icon: accessRevoked ? "shield-x" : inactivityLock ? "lock" : "log-out",
      tone: accessRevoked ? "danger" : "warning",
      actionLabel: "Log in again",
    };
    this.updateRibbonAuthIndicator();
  }

  private formatLogoutReason(noticeMessage: string): string {
    const withoutPrefix = noticeMessage
      .replace(/^VaultGuard Sync:\s*/i, "")
      .trim();
    return withoutPrefix || "Session ended.";
  }

  private loginRequiredActionText(
    action: "open" | "browse" | "edit" | "delete" | "sync" | "view permissions",
    target: string
  ): string {
    switch (action) {
      case "open":
        return `open ${target}`;
      case "browse":
        return "show protected files";
      case "edit":
        return `edit ${target}`;
      case "delete":
        return `delete ${target}`;
      case "sync":
        return "sync this vault";
      case "view permissions":
        return "view permissions";
    }
  }

  private createSidebarViewConfig(): VaultGuardSidebarViewConfig | null {
    if (!this.session || !this.apiClient || !this.settings.serverVaultId) {
      return null;
    }

    return {
      apiClient: this.apiClient,
      currentUserId: this.session.userId,
      // Use the effective UI role (org admin/owner > vault membership role >
      // org role) so the sidebar reflects what the user can actually do on
      // the currently bound vault.
      currentUserRole: this.getEffectiveUiRole(),
      getPermissionLevel: (path) => this.getEffectivePermission(path),
      onOpenMenu: (evt?: MouseEvent) => this.showVaultGuardMenu(evt),
      onOpenSettings: () => this.openVaultGuardSettings(),
      onOpenRecoveryCenter: () => this.openRecoveryCenter(),
      getPendingLargeFileSummary: () => {
        const records = Object.values(this.settings.pendingLargeFiles ?? {});
        return {
          count: records.length,
          blocked: records.filter((record) => record.state === "blocked").length,
          retryable: records.filter((record) => record.state !== "blocked").length,
        };
      },
      onRetryPendingLargeFiles: () => {
        void this.performSync({ userInitiated: true, forceCatchup: true });
      },
    };
  }

  /**
   * Opens the vault picker for the current Obsidian folder. When the binding
   * changes, the next sync run reconciles this local folder against the newly
   * selected server vault before regular sync resumes.
   */
  async switchServerVault(): Promise<boolean> {
    if (this.isLocalProjectMemoryModeEnabled()) {
      new Notice("VaultGuard Sync: server vault binding is disabled in Local Project Memory Mode.");
      return false;
    }
    const changed = await this.promptVaultBinding();
    if (changed && this.settings.serverVaultId && this.session) {
      this.syncDiagnostics.record("initializeSyncEngine.invoke", { caller: "switchServerVault" });
      this.initializeSyncEngine().catch((err) => {
        this.logError("Sync engine init failed after vault switch", err);
      });
      // A bound vault is the gate the Permissions graph waits on — refresh any
      // open panel so it loads (or re-targets) the newly selected vault live.
      this.refreshPermissionsGraph();
    }
    // The fvo "never silent" rule at its new home (quick-260820-ki7): with
    // the account-change modal's pick-vault case gone, Settings / the
    // status-bar menu are the only picker entries — a run that resolves with
    // the binding still blocked (picker dismissed, takeover declined,
    // membership denied) must land in the loud sd8 paused local-only state,
    // never silence ("I don't know that I can't do anything").
    // Never silent (fvo), and never the WRONG explanation (nqm): a run that
    // resolves still wrong-account re-raises the wrong-account notice — whose
    // own [Connect a different vault] button may well be what opened this
    // picker — rather than a paused notice about "the account change", which
    // describes a different state entirely.
    if (this.vaultBindingAuthorization === "wrong-account") {
      this.showWrongAccountNotice();
    } else if (this.vaultBindingAuthorization === "account-changed") {
      this.showAccountChangePausedNotice();
    }
    return changed;
  }

  async bindServerVault(result: { vaultId: string; name: string; slug: string }): Promise<boolean> {
    if (this.isLocalProjectMemoryModeEnabled()) {
      new Notice("VaultGuard Sync: server vault binding is disabled in Local Project Memory Mode.");
      return false;
    }
    const changed = await this.applyVaultBinding(result);
    if (changed && this.settings.serverVaultId && this.session) {
      this.syncDiagnostics.record("initializeSyncEngine.invoke", { caller: "bindServerVault" });
      this.initializeSyncEngine().catch((err) => {
        this.logError("Sync engine init failed after vault binding update", err);
      });
      // Same gate as switchServerVault — load the graph for the bound vault.
      this.refreshPermissionsGraph();
    }
    return changed;
  }

  async listServerVaults(): Promise<VaultRecord[]> {
    if (!this.apiClient) {
      throw new Error("Not connected");
    }
    return this.apiClient.listVaults();
  }

  async createServerVault(input: {
    name: string;
    description?: string;
    kind?: VaultKind;
    defaultRole?: VaultMemberRole;
  }): Promise<VaultRecord> {
    if (!this.apiClient) {
      throw new Error("Not connected");
    }
    return this.apiClient.createVault(input);
  }

  async getCurrentVaultRecord(): Promise<VaultRecord | null> {
    if (!this.settings.serverVaultId) {
      return null;
    }
    if (!this.apiClient) {
      throw new Error("Not connected");
    }

    const vault = await this.apiClient.getVaultRecord(this.settings.serverVaultId);
    await this.cacheCurrentVaultRecord(vault);
    return vault;
  }

  async getCurrentVaultMemberRole(): Promise<VaultMemberRole | null> {
    if (!this.session || !this.settings.serverVaultId) {
      return null;
    }
    if (!this.apiClient) {
      throw new Error("Not connected");
    }

    const members = await this.apiClient.listVaultMembers(this.settings.serverVaultId);
    return members.find((member) => member.userId === this.session!.userId)?.role ?? null;
  }

  async updateCurrentVault(updates: {
    name?: string;
    description?: string;
    defaultRole?: VaultMemberRole;
    archived?: boolean;
  }): Promise<VaultRecord> {
    if (!this.settings.serverVaultId) {
      throw new Error("No server vault is bound to this Obsidian folder.");
    }
    if (!this.apiClient) {
      throw new Error("Not connected");
    }

    const vault = await this.apiClient.updateVault(this.settings.serverVaultId, updates);
    await this.cacheCurrentVaultRecord(vault);
    return vault;
  }

  async listCurrentVaultMembers(): Promise<VaultMemberRecord[]> {
    if (!this.settings.serverVaultId) {
      throw new Error("No server vault is bound to this Obsidian folder.");
    }
    if (!this.apiClient) {
      throw new Error("Not connected");
    }
    return this.apiClient.listVaultMembers(this.settings.serverVaultId);
  }

  async listOrganizationUsers(): Promise<UserListEntry[]> {
    if (!this.apiClient) {
      throw new Error("Not connected");
    }
    return this.apiClient.listUsers();
  }

  async addCurrentVaultMember(userId: string, role: VaultMemberRole): Promise<VaultMemberRecord> {
    if (!this.settings.serverVaultId) {
      throw new Error("No server vault is bound to this Obsidian folder.");
    }
    if (!this.apiClient) {
      throw new Error("Not connected");
    }
    const membership = await this.apiClient.addVaultMember(this.settings.serverVaultId, userId, role);
    this.refreshPermissionUiAfterMembershipChange();
    return membership;
  }

  async updateCurrentVaultMember(userId: string, role: VaultMemberRole): Promise<VaultMemberRecord> {
    if (!this.settings.serverVaultId) {
      throw new Error("No server vault is bound to this Obsidian folder.");
    }
    if (!this.apiClient) {
      throw new Error("Not connected");
    }
    const membership = await this.apiClient.updateVaultMember(this.settings.serverVaultId, userId, role);
    this.refreshPermissionUiAfterMembershipChange();
    return membership;
  }

  async removeCurrentVaultMember(userId: string): Promise<void> {
    if (!this.settings.serverVaultId) {
      throw new Error("No server vault is bound to this Obsidian folder.");
    }
    if (!this.apiClient) {
      throw new Error("Not connected");
    }
    await this.apiClient.removeVaultMember(this.settings.serverVaultId, userId);
    this.refreshPermissionUiAfterMembershipChange();
  }

  /**
   * Pushes a temporary member's expiry out on the currently bound vault (DR-6).
   *
   * Same guard shape as the other member mutations above: the bound vault is
   * the only vault the settings tab lists members for, so the vault id is not
   * a caller's choice here.
   */
  async extendCurrentVaultGuestAccess(
    userId: string,
    expiresInDays: number
  ): Promise<ExtendGuestAccessResult> {
    if (!this.settings.serverVaultId) {
      throw new Error("No server vault is bound to this Obsidian folder.");
    }
    if (!this.apiClient) {
      throw new Error("Not connected");
    }
    const result = await this.apiClient.extendGuestAccess(
      this.settings.serverVaultId,
      userId,
      expiresInDays
    );
    this.refreshPermissionUiAfterMembershipChange();
    return result;
  }

  /**
   * Re-enables a disabled organization identity.
   *
   * Org-level, NOT vault-scoped: it re-enables the Cognito account, re-takes
   * the seat and deletes the revocation marker. Deliberately not folded into
   * the vault-member wrappers above for that reason.
   */
  async reactivateOrganizationUser(userId: string): Promise<void> {
    if (!this.apiClient) {
      throw new Error("Not connected");
    }
    await this.apiClient.reactivateUser(userId);
  }

  /**
   * Ends an organization identity's access immediately.
   *
   * Org-WIDE and account-disabling — this is not the per-vault lever. Removing
   * someone from a single vault is `removeCurrentVaultMember`.
   */
  async revokeOrganizationUser(userId: string): Promise<void> {
    if (!this.apiClient) {
      throw new Error("Not connected");
    }
    await this.apiClient.revokeUser(userId);
    this.refreshPermissionUiAfterMembershipChange();
  }

  private refreshPermissionUiAfterMembershipChange(): void {
    // Phase 9: single bus emit replaces the 5-call fan-out. The four
    // init* subscriptions invoke readOnlyGuard / fileExplorer / sidebar /
    // header invalidations. The `update({ force: true })` line is
    // preserved because it's a force-refresh of the CURRENT header view,
    // not an invalidation — the listener doesn't pass force: true.
    this.permissionStore.emit("changed", {
      serverConfirmed: true,
      semanticAuthorityChanged: true,
    });
    void this.filePermissionHeader?.update({ force: true });
  }

  private async cacheCurrentVaultRecord(vault: VaultRecord): Promise<void> {
    if (this.settings.serverVaultId !== vault.vaultId) {
      return;
    }

    const newServerExcluded = vault.excludedPaths ?? [];
    const newAllowlist = vault.pluginAllowlist ?? [];
    const oldServerExcluded = this.settings.serverExcludedPaths ?? [];
    const oldAllowlist = this.settings.serverPluginAllowlist ?? [];

    const nameChanged =
      this.settings.serverVaultName !== vault.name ||
      this.settings.serverVaultSlug !== vault.slug;
    const excludedChanged =
      newServerExcluded.length !== oldServerExcluded.length ||
      newServerExcluded.some((p, i) => p !== oldServerExcluded[i]);
    const allowlistChanged =
      JSON.stringify(newAllowlist) !== JSON.stringify(oldAllowlist);

    this.settings.serverVaultName = vault.name;
    this.settings.serverVaultSlug = vault.slug;
    this.settings.serverExcludedPaths = newServerExcluded;
    this.settings.serverPluginAllowlist = newAllowlist;

    if (nameChanged || excludedChanged || allowlistChanged) {
      await this.saveSettings();
    }

    if (allowlistChanged) {
      // Run the reconciliation in the background — never block sync on a
      // user-facing modal.
      void this.reconcilePluginAllowlist().catch((err: unknown) =>
        this.logError("Plugin allowlist reconciliation failed", err)
      );
    }
  }

  /**
   * Walks the cached plugin allowlist and prompts the user (one modal at a
   * time) to enable each plugin that is already present locally.
   *
   * The Obsidian plugin config folder is local-only (see `isPathExcluded`), so the bundle
   * bytes do NOT flow through VaultGuard sync — the user installs each
   * allowlisted plugin themselves via Obsidian's community plugin browser,
   * and this method handles only the consent + enable step. If a SHA-256 was
   * pinned by the admin, we hash the local main.js and refuse to enable on
   * mismatch — guards against a tampered bundle.
   *
   * Skipped plugins remain available for re-prompt on next sync. Plugins
   * the user explicitly chose to ignore are persisted in
   * `pluginAllowlistIgnored` and never re-prompted on this device.
   */
  /**
   * Public re-entry point for the plugin allowlist consent loop. Used by
   * the settings tab "Re-check vault plugins" button so the user can retry
   * after a sync brings new bundles down. Holds an in-flight guard so two
   * concurrent triggers don't stack modal dialogs.
   */
  async runPluginAllowlistReconciliation(): Promise<void> {
    return this.reconcilePluginAllowlist();
  }

  private allowlistReconcileInFlight: Promise<void> | null = null;

  private async reconcilePluginAllowlist(): Promise<void> {
    if (this.allowlistReconcileInFlight) {
      return this.allowlistReconcileInFlight;
    }
    this.allowlistReconcileInFlight = this.runAllowlistReconcileInternal();
    try {
      await this.allowlistReconcileInFlight;
    } finally {
      this.allowlistReconcileInFlight = null;
    }
  }

  private async runAllowlistReconcileInternal(): Promise<void> {
    const allowlist = this.settings.serverPluginAllowlist ?? [];
    if (allowlist.length === 0) return;

    const ignored = new Set(this.settings.pluginAllowlistIgnored ?? []);
    const adapter = this.app.vault.adapter;
    // Reach into Obsidian's internal plugin manager. This shape is not part
    // of the public API but has been stable across releases for years; the
    // alternatives (manual edits to community-plugins.json + asking the user
    // to reload Obsidian) are strictly worse UX.
    const pluginManager = (this.app as unknown as {
      plugins?: {
        manifests?: Record<string, unknown>;
        enabledPlugins?: Set<string>;
        enablePluginAndSave?: (id: string) => Promise<void>;
        loadManifests?: () => Promise<void>;
      };
    }).plugins;

    for (const entry of allowlist) {
      const pluginId = entry.pluginId;
      if (!this.isSafeObsidianPluginId(pluginId)) {
        this.logError(
          `Allowlist: refused unsafe plugin id "${pluginId}"`,
          new Error("unsafe plugin id"),
        );
        await this.emitAuditEvent("plugin.allowlist_skip", pluginId, {
          reason: "invalid-plugin-id",
        });
        continue;
      }

      if (ignored.has(pluginId)) continue;

      // Already enabled? Nothing to do.
      const enabledPlugins = pluginManager?.enabledPlugins;
      if (enabledPlugins instanceof Set && enabledPlugins.has(pluginId)) {
        continue;
      }

      const pluginRoot = this.vaultConfigPath("plugins", pluginId);
      const mainPath = `${pluginRoot}/main.js`;
      const manifestPath = `${pluginRoot}/manifest.json`;

      let hashStatus: PluginAllowlistPrompt["hashStatus"] = "unsigned";
      let localHash: string | undefined;
      let mainJs: string | null = null;

      try {
        const [hasMain, hasManifest] = await Promise.all([
          adapter.exists(mainPath),
          adapter.exists(manifestPath),
        ]);
        if (!hasMain || !hasManifest) {
          hashStatus = "missing";
        } else if (this.originalAdapterMethods.read) {
          mainJs = await this.originalAdapterMethods.read(mainPath);
          if (entry.bundleSha256) {
            localHash = await this.computeHash(mainJs);
            hashStatus = localHash === entry.bundleSha256.toLowerCase()
              ? "verified"
              : "mismatch";
          } else {
            hashStatus = "unsigned";
          }
        }
      } catch (err) {
        this.logError(`Allowlist: failed to inspect "${pluginId}"`, err);
        // Surface as missing — the user can retry after the next sync.
        hashStatus = "missing";
      }

      const decision = await this.promptPluginAllowlistDecision({
        pluginId,
        displayName: entry.displayName,
        version: entry.version,
        note: entry.note,
        addedBy: entry.addedBy,
        hashStatus,
        localHash,
        expectedHash: entry.bundleSha256,
      });

      if (decision === "ignore") {
        const ignoredList = new Set(this.settings.pluginAllowlistIgnored ?? []);
        ignoredList.add(pluginId);
        this.settings.pluginAllowlistIgnored = [...ignoredList];
        await this.saveSettings();
        await this.emitAuditEvent("plugin.allowlist_skip", pluginId, {
          permanent: true,
        });
        continue;
      }
      if (decision === "skip") {
        await this.emitAuditEvent("plugin.allowlist_skip", pluginId);
        continue;
      }

      // decision === "install"
      if (hashStatus !== "verified" && hashStatus !== "unsigned") {
        // Modal already disables the install button in these states; if we
        // somehow reach here, refuse loudly.
        new Notice(`VaultGuard Sync: Cannot install "${entry.displayName}" — ${hashStatus}.`);
        continue;
      }

      try {
        if (pluginManager?.loadManifests) {
          // Force Obsidian to re-scan its plugin config folder so it sees the newly
          // synced files. Without this, enablePluginAndSave throws because
          // the manifest cache is stale.
          await pluginManager.loadManifests();
        }
        if (typeof pluginManager?.enablePluginAndSave === "function") {
          await pluginManager.enablePluginAndSave(pluginId);
          new Notice(`VaultGuard Sync: Enabled "${entry.displayName}".`);
          await this.emitAuditEvent("plugin.allowlist_install", pluginId, {
            verified: hashStatus === "verified",
            version: entry.version,
          });
        } else {
          new Notice(
            `VaultGuard Sync: Could not auto-enable "${entry.displayName}" — please enable it manually in Settings → Community plugins.`
          );
        }
      } catch (err) {
        this.logError(`Allowlist: enable "${pluginId}" failed`, err);
        new Notice(
          `VaultGuard Sync: Failed to enable "${entry.displayName}" — ${err instanceof Error ? err.message : "unknown error"}.`
        );
      }
    }
  }

  private isSafeObsidianPluginId(pluginId: string): boolean {
    return (
      /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(pluginId) &&
      !pluginId.includes("..")
    );
  }

  private promptPluginAllowlistDecision(
    prompt: PluginAllowlistPrompt
  ): Promise<"install" | "skip" | "ignore"> {
    return new Promise((resolve) => {
      const modal = new PluginAllowlistModal(this.app, prompt, resolve);
      modal.open();
    });
  }

  /**
   * Updates the display name for a user. When updating the current user,
   * also updates the local session so the change is reflected immediately.
   */
  async updateUserProfile(userId: string, displayName: string): Promise<void> {
    if (!this.apiClient) throw new Error("Not connected");
    await this.apiClient.updateUserProfile(userId, { displayName });

    // If updating self, reflect in local session
    if (this.session && this.session.userId === userId) {
      this.session = { ...this.session, displayName };
      await this.persistSession(this.session);
    }
  }

  /**
   * Resolves org configuration from a slug via the public /orgs/{slug}/config endpoint.
   * Auto-fills apiEndpoint, organizationId, cognitoUserPoolId, and cognitoClientId.
   *
   * The org config endpoint is public (no auth required), so we use a well-known
   * SaaS API base URL or the currently configured apiEndpoint to discover it.
   */
  async resolveOrgConfig(slug: string, options: { silent?: boolean } = {}): Promise<void> {
    await this.getSettingsRuntime().resolveOrgConfig(slug, options);
  }

  private syncSettingsFromTokenPayload(
    payload: Record<string, unknown>,
    fallbackRoles: string[] = []
  ): boolean {
    return this.getSettingsRuntime().syncSettingsFromTokenPayload(payload, fallbackRoles);
  }
  getOrgPolicySettings(): OrgSettingsResponse | null {
    return this.orgSettings;
  }

  private applyOrgSettings(orgSettings?: OrgSettingsResponse | null): void {
    const restrictionWasActive = this.isAdminRestrictionActive();
    this.orgSettings = orgSettings ?? null;
    const restrictionIsActive = this.isAdminRestrictionActive();

    // Keep the file-permission header in sync with the per-org
    // allowAdminPerFileRestrictions toggle. Without this push, the header
    // would render based on whatever flag was passed at construction time
    // and would never pick up a setting change until the next plugin
    // reload.
    this.filePermissionHeader?.setContext({
      allowAdminPerFileRestrictions: restrictionIsActive,
    });

    if (restrictionWasActive !== restrictionIsActive) {
      // SD-03-F15/F16: the effective per-file policy just changed, so every
      // cached answer — including the root sentinel — was computed under the
      // OLD policy. One server-confirmed wildcard emit hands the invalidation
      // + re-warm + re-resolution to the store's existing machinery. The
      // assignment above happens FIRST so the fan-out's requestWarmup ->
      // collectRulesForWarmup reads the NEW policy.
      //
      // Only on a FLIP, and symmetric in both directions: turning the toggle
      // OFF must invalidate too, or a cached restricted NONE would outlive the
      // policy that produced it. applyOrgSettings also runs on every lease
      // refresh and session restore, so emitting unconditionally would turn
      // those into a wildcard storm.
      this.permissionStore.emit("changed", { serverConfirmed: true });
    }

    if (this.session) {
      this.restartSyncTimer();
      this.scheduleAutoLockTimer();
    } else {
      this.stopAutoLockTimer();
    }
  }

  private getEffectiveSyncMode(): OrgSettingsResponse["syncMode"] {
    if (this.isLocalProjectMemoryModeEnabled()) return "manual";
    return this.orgSettings?.syncMode ?? "periodic";
  }

  private getEffectiveSyncIntervalSeconds(): number {
    if (this.isLocalProjectMemoryModeEnabled()) return 0;
    if (!this.orgSettings) {
      return this.settings.syncInterval;
    }

    switch (this.orgSettings.syncMode) {
      case "realtime":
        return MIN_SYNC_INTERVAL;
      case "periodic":
        return this.orgSettings.syncIntervalMinutes * 60;
      case "manual":
      default:
        return 0;
    }
  }

  private shouldUploadChangesImmediately(): boolean {
    if (this.isLocalProjectMemoryModeEnabled()) return false;
    return this.getEffectiveSyncMode() !== "manual";
  }

  private registerSessionActivityTracking(): void {
    registerSessionActivityTrackingLifecycle(this.createLifecycleEventsContext());
  }

  private noteSessionActivity(): void {
    // Phase 12: while locked, user activity must NOT reschedule an auto-lock —
    // the vault is already locked and only a PIN (or a hard fallback) leaves it.
    if (!this.session || this.isVaultLocked) {
      return;
    }

    this.scheduleAutoLockTimer();
  }

  private scheduleAutoLockTimer(): void {
    this.stopAutoLockTimer();

    const autoLockMinutes = this.orgSettings?.autoLockMinutes ?? 0;
    if (!this.session || autoLockMinutes <= 0) {
      return;
    }

    this.autoLockTimer = setTimeout(() => {
      void this.lockSessionForInactivity(autoLockMinutes);
    }, autoLockMinutes * 60 * 1000);
  }

  private stopAutoLockTimer(): void {
    if (this.autoLockTimer) {
      clearTimeout(this.autoLockTimer);
      this.autoLockTimer = null;
    }
  }

  private async lockSessionForInactivity(autoLockMinutes: number): Promise<void> {
    if (!this.session) {
      return;
    }

    // Phase 12-07 idle matrix (persistent trusted device): idle must NEVER destroy
    // the session on the UNDEPLOYED idleAction fallback — that was the "nonstop
    // logout" bug (the old `?? "logout"` collapsed an absent field into a logout).
    // Read the RAW server field — "lock" | "logout" | undefined — and only the
    // EXPLICIT, deployed "logout" logs out.
    const action = this.orgSettings?.idleAction; // may be undefined (field undeployed)
    const enrolled = this.pinLockManager?.isEnrolled() ?? false;

    // (1) EXPLICIT "logout" policy → honor it (admin compliance). After quick
    // 260711-l2e the server default is "lock", so this branch fires only for an
    // org that DELIBERATELY stored idleAction="logout"; precedence keeps explicit
    // "logout" ahead of the PIN-lock branch, so we log out even if a PIN exists.
    if (action === "logout") {
      this.log(`Auto-logout (org policy) after ${autoLockMinutes} minutes of inactivity.`);
      // Actionable notice: the word "inactivity" is load-bearing — forceLogout's
      // rememberLogoutAuthState classifies the persistent sidebar state by
      // matching it (→ "Session locked"). Tell the user WHY and HOW to stop it.
      await this.forceLogout(
        `VaultGuard Sync: Signed out after ${autoLockMinutes} min of inactivity — your organization's idle policy is set to log out. An org admin can switch it to "Lock" in Manage organization → Org settings → On idle timeout, then set a PIN to unlock without a full re-login.`
      );
      return;
    }

    // (2) A PIN is enrolled → cryptographic lock, session preserved — whether
    // idleAction is "lock" OR still undeployed (undefined). A PIN device always
    // locks (never logs out) on idle. enterLockState keeps the heartbeat alive (NN-2).
    if (enrolled) {
      this.log(`Auto-lock: locking vault after ${autoLockMinutes} minutes of inactivity.`);
      await this.enterLockState();
      return;
    }

    // (3) No PIN and no explicit logout policy → do NOT log out (persistent trusted
    // device). Keep the session alive and nudge (once per session) toward setting a
    // PIN so the user gets real idle locking. This is the fix for the idle-logout UX.
    if (!this.pinNudgeShown) {
      this.pinNudgeShown = true;
      new Notice(
        "VaultGuard Sync: set a PIN in VaultGuard settings to lock the vault when it goes idle.",
        8000
      );
    }
    this.log(
      `Idle after ${autoLockMinutes} minutes — session kept (no PIN enrolled; set one to enable idle lock).`
    );
  }

  /**
   * Phase 12-07 (passkey model, supersedes H-1's "curtain on ANY auth"): fire the
   * lock curtain after an auth entry (cold-start restore OR fresh login) ONLY when
   * the vault could not unlock transparently — i.e. the cipher is not ready (legacy
   * PIN-only device with no transparent wrap, or a corrupt wrap) OR the user opted
   * into "Require PIN on startup" (max-security). When the transparent wrap already
   * unlocked the cipher and the toggle is off, we DON'T curtain — the full login
   * already proved identity, so a PIN on top is the double-auth this redesign kills.
   *
   * This still MIRRORS the adapter's landing decision (initAtRestCipher →
   * `landLocked`): the curtain shows exactly when the adapter landed LOCKED, so an
   * enrolled device whose cipher is locked never has managed reads fail closed with
   * no way to unlock (H-1 dead-vault protection preserved). Synchronous + eager:
   * callers MUST NOT await sessionResumePromise first. idleAction governs ONLY the
   * live-session idle→lock transition (lockSessionForInactivity), not this path.
   */
  private maybeEnterLockOnAuth(): void {
    if (!this.session || !this.pinLockManager?.isEnrolled() || this.isVaultLocked) {
      return;
    }
    // Passkey model: the cipher already unlocked transparently (login/startup found
    // the transparent lak.envelope) and the user hasn't opted into max-security →
    // don't curtain (no double-auth).
    const cipherReady = this.getAtRestCipher()?.isReady() ?? false;
    const requirePin = this.settings.requirePinOnStartup === true;
    if (cipherReady && !requirePin) {
      return;
    }
    // Otherwise the cipher could NOT unlock transparently (legacy/no-wrap device) or
    // the user wants max-security — curtain so the PIN can unlock.
    void this.enterLockState();
  }

  /**
   * P1a completion — mobile "session sealed behind a locked cipher".
   *
   * On mobile the session is encrypted with the at-rest LAK (no OS keychain),
   * so `restoreSession()` cannot decrypt it while the cipher is LOCKED. When the
   * cipher lands locked at startup (P1a-core routed a lost fallback KEK to the
   * PIN, or it's a legacy/max-security PIN device), `this.session` is therefore
   * null and `maybeEnterLockOnAuth()` — which returns early without a session —
   * never showed the unlock curtain. The user was stranded: content fails closed
   * and there is no visible way in.
   *
   * Show the PIN curtain here regardless of session. There is no session to
   * preserve, so we deliberately do NOT call `enterLockState()` (which requires
   * one and stops session-scoped timers); we just assert the fail-closed gate and
   * render the curtain. `unlockWithPin()` recovers the LAK and then
   * `recoverSessionAfterPinUnlock()` re-runs `restoreSession()` now that the LAK
   * is back. Desktop is unaffected (its session loads via safeStorage, so
   * `this.session` is set and this early-returns).
   */
  private maybeEnterPinRecoveryCurtain(): void {
    if (this.session || this.isVaultLocked) return;
    if (!this.pinLockManager?.isEnrolled()) return;
    // Only the LOCKED (PIN-recoverable) state — not needs-recovery/disabled,
    // which the PIN can't fix and which have their own recovery surfaces.
    if (this.getAtRestCipher()?.isReady() ?? false) return;
    if (!this.ensureAtRestAdapterRuntimeObject().isLocked()) return;

    this.isVaultLocked = true;
    this.ensureAtRestAdapterRuntimeObject().setLocked(true);
    this.showLockCurtain();
    this.log(
      "PIN recovery curtain shown at startup (cipher locked, session sealed behind it)."
    );
  }

  /**
   * P1a completion — after a PIN unlock that had NO in-memory session (the mobile
   * "session sealed behind the cipher" path from maybeEnterPinRecoveryCurtain).
   * The LAK is back now, so load the at-rest-sealed session, tear the recovery
   * curtain down, and resume. Distinct from exitLockState(), which requires a
   * live session (it re-acquires the vault key lease).
   */
  private async recoverSessionAfterPinUnlock(): Promise<void> {
    try {
      await this.restoreSession();
    } catch (err) {
      this.logError("Post-PIN-unlock session restore failed", err);
    }
    // The cipher is unlocked → local content is readable regardless — always tear
    // the recovery curtain down so the user is never stranded behind it.
    this.isVaultLocked = false;
    this.ensureAtRestAdapterRuntimeObject().setLocked(false);
    this.lockCurtain?.hide();
    this.lockCurtain = null;
    this.updateStatusBar();
    if (this.session) {
      void this.resumeStoredSession()
        .catch((err) =>
          this.logError("Post-PIN-unlock session resume failed", err)
        )
        // Same backstop as the `onload` resume: this path also owns a session
        // that has no liveness loop until the resume finishes, so a resume that
        // returns early or throws must still leave a reconnect probe armed.
        .finally(() => this.armResumeRetryIfIncomplete());
    } else {
      // Cipher recovered but no stored session was present — the user is simply
      // logged out; the normal login surfaces apply.
      this.log("PIN unlock recovered the cipher but no stored session was present.");
    }
  }

  /**
   * User-facing "Lock vault" command (quick 260708-g9m). Locks the vault on
   * demand — but ONLY when a PIN is enrolled, so a user can never strand
   * themselves behind an unlockable curtain (D-01). The four guard branches are
   * independent, in order:
   *   1. no session      → nudge to log in first; do NOT lock.
   *   2. already locked   → silent no-op (the curtain is already up).
   *   3. no PIN enrolled  → nudge (Notice + SetPinModal) INSTEAD of locking; the
   *                         nudge does NOT chain into a lock afterward.
   *   4. otherwise        → enter the cryptographic lock.
   * Independent of idleAction by design: locking is invokable at will regardless
   * of the org's idle policy; PIN enrollment is the only gate.
   */
  private lockVaultViaCommand(): void {
    if (!this.session) {
      new Notice("VaultGuard Sync: Log in before locking the vault.");
      return;
    }
    if (this.isVaultLocked) {
      return; // the curtain is already up — nothing to do
    }
    if (!this.pinLockEnrolled()) {
      new Notice(
        "VaultGuard Sync: Set a PIN first so you can unlock the vault after it locks."
      );
      new SetPinModal(this.app, async (secret) => {
        await this.enrollPinLock(secret);
      }).open();
      return;
    }
    void this.enterLockState();
  }

  /**
   * Enter the cryptographic lock (D2): evict the in-memory LAK + cloud key-lease,
   * revoke the decrypted-media blob cache, stop the sync + key-renewal timers,
   * and curtain the workspace — while PRESERVING the session, the apiClient
   * tokens, and (crucially) the revocation heartbeat.
   *
   * NON-NEGOTIABLE #2: the heartbeat MUST keep running so server revocation
   * (60s heartbeat / terminal token-refresh) and the configured maxSessionDurationHours
   * cap still force a REAL forceLogout even while locked — a locked session can
   * never resurrect a revoked/expired one. Only sync + key-renewal stop here.
   */
  private async enterLockState(): Promise<void> {
    if (!this.session || this.isVaultLocked) {
      return;
    }
    // Vectors are sensitive derived content. Purge the encrypted envelope and
    // in-memory generation before evicting the LAK so deletion can complete.
    if (this.shouldPurgeSemanticIndex()) {
      await this.purgeSemanticRuntime("lock").catch((error) =>
        this.logError("Purging semantic index before lock failed", error),
      );
    }
    this.atRestCipher?.lock(); // evict the in-memory LAK → managed reads fail closed
    this.keyLease = null; // evict the cloud DEK
    this.ensureAtRestAdapterRuntimeObject().setLocked(true); // fail-closed gate + revoke previews
    this.stopSyncTimer();
    this.stopKeyRenewalMonitor();
    // NN-2: deliberately NOT stopHeartbeatMonitor() — see the method doc above.
    this.isVaultLocked = true;
    this.captureAndDetachContentLeaves(); // Pitfall 1 + L-4: no plaintext behind the curtain
    this.showLockCurtain();
    this.log("Vault locked (session + refresh token + heartbeat preserved).");
  }

  /** Lazily construct + render the opaque lock curtain wired to unlock/forgot. */
  private showLockCurtain(): void {
    if (!this.lockCurtain) {
      this.lockCurtain = new LockCurtain(document);
    }
    this.lockCurtain.show({
      onSubmit: (secret) => void this.unlockWithPin(secret),
      onForgot: () => this.confirmForgotPin(),
    });
  }

  /**
   * Leave the lock: re-acquire the vault-scoped key lease, then tear the curtain
   * down and resume sync + key-renewal. edge #2: a 401 (revoked / 24h
   * maxSessionDurationHours cap) on the lease makes ensureVaultScopedKeyLease run
   * a REAL forceLogout and return "logged-out" — a stale lock never silently
   * resumes past the server cap. Plan 05 extends this to re-open the pre-lock file.
   */
  private async exitLockState(): Promise<void> {
    if (!this.isVaultLocked) {
      return;
    }
    let leaseResult: "ok" | "limited" | "logged-out";
    try {
      leaseResult = await this.ensureVaultScopedKeyLease();
    } catch (err) {
      // Transient lease failure (5xx / network): the LAK is already back in
      // memory, so local content is readable. Tear the curtain down and let the
      // key-renewal monitor retry (leaseRetryNeeded is set). This is NOT edge #2.
      this.logError("Key lease re-acquire after unlock failed transiently (will retry)", err);
      leaseResult = "limited";
    }
    if (leaseResult === "logged-out" || !this.session) {
      // ensureVaultScopedKeyLease already ran forceLogout (edge #2), which tore
      // the curtain down and reset isVaultLocked. Nothing more to do.
      return;
    }
    this.isVaultLocked = false;
    this.lockCurtain?.hide();
    this.lockCurtain = null;
    // resumeSyncLoop (not just restartSyncTimer) so we clear any paused flag set
    // while the window was hidden: if the vault locked while backgrounded, the
    // visibilitychange handler now skips resumeSyncLoop on a locked→visible
    // transition, leaving paused=true — restartSyncTimer alone would then skip
    // ("paused" reason) and leave sync dead after unlock. The user is looking at
    // the app (they just entered the PIN), so resuming is correct. If it was not
    // paused, resumeSyncLoop no-ops and restartSyncTimer starts the timer.
    this.resumeSyncLoop("vault unlocked");
    this.restartSyncTimer();
    this.startKeyRenewalMonitor();
    void this.reopenPreLockFile(); // L-4: unlock does not land on a blank workspace
    this.log("Vault unlocked.");
  }

  /**
   * Unlock with the user's PIN / passphrase. A wrong PIN shows a curtain error
   * and stays locked; reason "locked-out" (the attempt cap) forces a REAL
   * forceLogout. On success: adopt the PIN-unwrapped LAK, re-acquire the lease,
   * and tear the curtain down — with NO email/password/MFA re-login.
   */
  private async unlockWithPin(secret: string): Promise<void> {
    if (!this.pinLockManager || !this.isVaultLocked) {
      return;
    }
    this.lockCurtain?.setBusy(true);

    let res: Awaited<ReturnType<PinLockManager["unlock"]>>;
    try {
      res = await this.pinLockManager.unlock(secret);
    } catch (err) {
      this.logError("PIN unlock threw", err);
      this.lockCurtain?.showError("Unlock failed. Please try again.");
      return;
    }

    if (!res.ok) {
      if (res.reason === "locked-out") {
        await this.forceLogout(
          "VaultGuard Sync: Too many attempts — please log in again."
        );
      } else {
        this.lockCurtain?.showError("Incorrect PIN. Try again.");
      }
      return;
    }

    try {
      await this.ensureAtRestAdapterRuntimeObject().unlockCipherWithLak(res.lak);
    } catch (err) {
      this.logError("Adopting the PIN-unwrapped LAK failed", err);
      this.lockCurtain?.showError("Unlock failed. Please try again.");
      return;
    } finally {
      res.lak.fill(0); // defensive: the cipher took its own copy
    }

    if (this.localRecoveryNeedsLakValidation) {
      await this.finalizeRecoveredLocalProtection();
      if (this.localProtectionBootstrap.kind === "needs-recovery") {
        this.lockCurtain?.showError(
          "This device recovery capsule does not match the protected files. Restore with the vault recovery code.",
        );
        return;
      }
    }

    // Passkey migration (Phase 12-07): a device enrolled under the old model has NO
    // transparent lak.envelope (enroll used to delete it), so it lands LOCKED on
    // every startup. Now that this PIN unlock re-installed the LAK in the cipher,
    // regenerate the transparent wrap so the NEXT startup / login unlocks without a
    // PIN. Skipped in max-security mode (requirePinOnStartup) where the wrap must
    // stay absent. Best-effort: a failure never blocks the unlock (idempotent
    // re-write when the wrap is already present).
    if (this.settings.requirePinOnStartup !== true) {
      try {
        await this.getAtRestCipher()?.persistWrappedLak();
      } catch (err) {
        this.logError("Passkey migration (persistWrappedLak after PIN unlock) failed", err);
      }
      void this.persistLocalRecoveryCapsule();
    } else {
      // Also heals an interrupted max-security transition: make the PIN-only
      // capsule authoritative first, then remove any transparent wrapper that
      // survived a process death between those two commits.
      if (await this.persistLocalRecoveryCapsule()) {
        await this.getAtRestCipher()?.clearPersistedWrap().catch((err) => {
          this.logError("Removing a stale transparent wrap after PIN unlock failed", err);
        });
      }
    }

    // P1a completion: a PIN unlock that had NO in-memory session (mobile — the
    // session was sealed behind the cipher, so it couldn't be decrypted at
    // startup) recovers the session here. exitLockState() can't be used: it
    // re-acquires the vault key lease and early-returns without a session.
    if (!this.session) {
      await this.recoverSessionAfterPinUnlock();
      return;
    }

    await this.exitLockState();
  }

  /** True if a PIN is enrolled on this device (public accessor for the settings UI). */
  pinLockEnrolled(): boolean {
    return this.pinLockManager?.isEnrolled() ?? false;
  }

  /**
   * The effective org idle action ("lock" | "logout") for the settings UI and
   * the PIN-onboarding gate.
   *
   * The fallback MUST match what `lockSessionForInactivity` actually does with
   * an absent field, and it does NOT log out: only an EXPLICIT, deployed
   * "logout" reaches the forceLogout branch — an undefined idleAction falls
   * through to the PIN lock (2) or session-kept (3) branches. This accessor
   * predates that rule (it was written in 12-05, three days before quick
   * 260711-l2e flipped the server default to "lock" and taught the runtime to
   * read the raw field) and kept the very `?? "logout"` collapse the runtime
   * comment calls out by name as the old "nonstop logout" bug.
   *
   * The visible symptom was the Vault-lock settings panel telling a user on an
   * undeployed org that their idle action is "logout" when the runtime would
   * never log them out.
   *
   * NOTE: `maybeOfferPinOnboarding` deliberately does NOT use this accessor —
   * see the comment there. Prompt suppression while the policy is unknown is
   * intentional; describing the policy wrongly was not.
   */
  effectiveIdleAction(): "lock" | "logout" {
    return this.orgSettings?.idleAction ?? "lock";
  }

  /**
   * Lazy, once-ever discoverability prompt for lock-instead-of-logout (quick
   * 260708-el6). A new user in a lock-policy org who never sets a PIN silently
   * degrades to idle-LOGOUT (lockSessionForInactivity → action "lock" && !enrolled
   * → forceLogout). Offer a skippable "Set a PIN" nudge exactly once.
   *
   * LOGIN-ONLY. 260708-el6 also called this from `restoreServerSession`; that
   * entry point is gone (see the comment there). A background resume is not a
   * moment the user asked for anything, so the prompt read as the plugin
   * ambushing them seconds after they enabled it.
   *
   * READINESS-GATED. Prompting is pointless — and produces a refusal the user
   * can do nothing about — while the at-rest cipher has no live LAK to wrap, so
   * the offer waits the cipher out (bounded) and simply stays silent if it never
   * becomes ready. The persisted flag is NOT consumed in that case: an offer the
   * user never saw must not burn the one chance to make it.
   */
  private async maybeOfferPinOnboarding(): Promise<void> {
    // Reads the RAW field rather than effectiveIdleAction() on purpose (AC4).
    // `orgSettings` is also null before the policy has loaded, so an absent
    // value means "policy unknown", not "policy is lock" — surfacing an
    // onboarding modal in that window would race the settings fetch. The
    // runtime already nudges this user toward a PIN with a Notice from the
    // session-kept branch of lockSessionForInactivity, so nothing is lost by
    // waiting for an explicit policy here.
    if (!this.pinOnboardingGateOpen()) {
      return;
    }

    // Terminal cipher states (locked, needs-recovery, Local Project Memory Mode,
    // disabled) come back immediately, so an unpromptable vault costs nothing.
    const readiness = await this.awaitCipherReadyForPin(PIN_CIPHER_READY_TIMEOUT_MS);
    if (readiness !== "ready") {
      this.log(`PIN onboarding prompt skipped — cipher not ready (${readiness}).`);
      return;
    }

    // Re-read across the await: the user may have logged out, or set a PIN from
    // Settings, while the cipher was still coming up.
    if (!this.pinOnboardingGateOpen()) {
      return;
    }

    this.openPinOnboardingPrompt();
  }

  /** The cheap half of the onboarding gate, evaluated on both sides of the wait. */
  private pinOnboardingGateOpen(): boolean {
    return (
      !!this.session &&
      this.orgSettings?.idleAction === "lock" &&
      !this.pinLockEnrolled() &&
      !this.settings.pinOnboardingPromptShown
    );
  }

  /**
   * Show the soft two-button prompt. [Set PIN] reuses the canonical SetPinModal →
   * enrollPinLock wiring (mirrors the settings.ts Set-a-PIN button — AC2); [Not
   * now] (or any close) just persists the flag. Both choices funnel through
   * markPinOnboardingPromptShown so the prompt never reappears (AC3).
   */
  private openPinOnboardingPrompt(): void {
    new PinOnboardingPromptModal(this.app, {
      onSetPin: () => {
        void this.markPinOnboardingPromptShown().catch((err) =>
          this.logError("Persisting PIN onboarding flag failed", err)
        );
        new SetPinModal(this.app, async (secret) => {
          await this.enrollPinLock(secret);
        }).open();
      },
      onDismiss: () => {
        void this.markPinOnboardingPromptShown().catch((err) =>
          this.logError("Persisting PIN onboarding flag failed", err)
        );
      },
    }).open();
  }

  /**
   * Persist the once-ever onboarding-prompt guard. Idempotent: a no-op (no
   * redundant save) once the flag is already set, so a stray double-call from the
   * modal's onClose dismissal fallback is harmless.
   */
  private async markPinOnboardingPromptShown(): Promise<void> {
    if (this.settings.pinOnboardingPromptShown) {
      return;
    }
    this.settings.pinOnboardingPromptShown = true;
    await this.saveSettings();
  }

  /**
   * Wait (bounded) for the at-rest cipher to hold a live LAK, so a PIN action
   * that needs one doesn't refuse a vault that is merely still starting up.
   *
   * The bug this fixes: the settings tab is registered early in `onload`, but
   * `initAtRestCipher()` is only awaited later — behind two full-vault scans and
   * the cipher's own ciphertext walk. Clicking "Set PIN" inside that window hit
   * `isReady() === false` and got "Unlock the vault before setting a PIN", even
   * though the vault unlocked a second later. The same window opens whenever the
   * cipher re-initialises (leaving Local Project Memory Mode, an at-rest reset).
   *
   * Only `"timeout"` means "still initialising". The other refusals are terminal
   * — a curtained lock, a needs-recovery cipher, Local Project Memory Mode, or a
   * disabled cipher will never become ready on their own, so they short-circuit
   * instead of making the user watch a 15-second wait end in the wrong message.
   */
  private async awaitCipherReadyForPin(
    timeoutMs: number
  ): Promise<PinCipherReadyOutcome> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      if (this.getAtRestCipher()?.isReady() === true) {
        return "ready";
      }
      // Terminal states: more waiting cannot clear any of these.
      if (this.isVaultLocked || this.ensureAtRestAdapterRuntimeObject().isLocked()) {
        return "locked";
      }
      if (this.isLocalProjectMemoryModeEnabled()) {
        return "local-project-memory";
      }
      const status = this.getAtRestStatus();
      if (status.kind === "needs-recovery") {
        return "needs-recovery";
      }
      if (status.kind === "disabled") {
        return "disabled";
      }
      const remaining = deadline - Date.now();
      if (remaining <= 0) {
        return "timeout";
      }
      // Poll rather than awaiting `cipherInitPromise`: that promise is still null
      // during the pre-init scans that open most of this window, and its resolved
      // value doesn't distinguish "settled" from "timed out" anyway.
      await new Promise<void>((resolve) =>
        setTimeout(resolve, Math.min(PIN_CIPHER_READY_POLL_MS, remaining))
      );
    }
  }

  /**
   * Turn a non-ready `awaitCipherReadyForPin` outcome into a message that tells
   * the user what to actually do. `action` is the verb phrase for the attempted
   * operation ("set a PIN"), so one mapping serves every PIN entry point.
   */
  private pinCipherRefusalMessage(
    outcome: Exclude<PinCipherReadyOutcome, "ready">,
    action: string
  ): string {
    switch (outcome) {
      case "locked":
        return `Unlock the vault before you ${action}.`;
      case "needs-recovery":
        return `Local at-rest encryption needs recovery on this device, so there is no key to protect with a PIN. Restore from your recovery code in Settings → VaultGuard, then ${action}.`;
      case "local-project-memory":
        return `Local Project Memory Mode keeps this vault's files in plaintext, so there is no local encryption key to protect with a PIN. Turn it off in Settings → VaultGuard to ${action}.`;
      case "disabled":
        return `Local at-rest encryption is not active on this device, so there is no key to protect with a PIN. Enable it in Settings → VaultGuard, then ${action}.`;
      case "timeout":
        return `VaultGuard is still unlocking this vault. Wait a moment, then ${action} again.`;
    }
  }

  /**
   * Enroll a PIN so the vault locks-instead-of-logs-out on idle (D3) and can be
   * re-opened fast with the PIN. Requires the cipher UNLOCKED (the LAK must be in
   * memory to hand to the PIN wrap). A cipher that is merely still initialising
   * is waited out first — see `awaitCipherReadyForPin`.
   *
   * Passkey model (default, requirePinOnStartup off — Phase 12-07): KEEP the
   * transparent `lak.envelope` alongside the new `lak-pin.envelope`, so a full login
   * / app startup still unlock the vault transparently and the PIN only re-locks it
   * on idle. This relaxes D2 to the OS-keychain posture (a full-OS-access attacker on
   * the unlocked machine can decrypt — the SAME posture a no-PIN device already has),
   * documented honestly in docs/AT-REST-ENCRYPTION.md.
   *
   * Max-security (requirePinOnStartup on): remove the transparent wrap so
   * `lak-pin.envelope` is the ONLY wrap and the vault is undecryptable without the
   * PIN even with full OS access (true D2), at the cost of a PIN on every startup.
   *
   * Failure-safe order: write `lak-pin.envelope` FIRST (pinLockManager.enroll), THEN
   * — max-security only — remove `lak.envelope`, so a failed enroll never leaves the
   * device with NO way to load the LAK.
   */
  async enrollPinLock(secret: string): Promise<void> {
    const readiness = await this.awaitCipherReadyForPin(PIN_CIPHER_READY_TIMEOUT_MS);
    if (readiness !== "ready") {
      throw new Error(this.pinCipherRefusalMessage(readiness, "set a PIN"));
    }
    const cipher = this.getAtRestCipher();
    if (!cipher?.isReady()) {
      // Unreachable via awaitCipherReadyForPin (it only returns "ready" while
      // isReady() holds), kept so a future refactor of the wait can't silently
      // hand exportLakBytes a locked cipher.
      throw new Error("Unlock the vault before setting a PIN.");
    }
    if (!this.pinLockManager) {
      throw new Error("PIN lock is unavailable on this device.");
    }
    const lak = cipher.exportLakBytes();
    try {
      await this.pinLockManager.enroll(secret, lak); // writes lak-pin.envelope
      if (this.settings.requirePinOnStartup === true) {
        // Commit and verify the PIN-only recovery generation before removing the
        // last transparent wrapper. The capsule store also destroys every
        // rollback generation that could contain that wrapper.
        // A real Obsidian plugin instance always has a vault adapter. Keeping
        // the structural guard lets the crypto/PIN unit seam run without an App
        // while preserving the fail-closed ordering in production.
        if (
          this.app?.vault?.adapter &&
          !(await this.persistLocalRecoveryCapsule())
        ) {
          throw new Error(
            "VaultGuard could not persist the PIN-only uninstall recovery capsule. The transparent wrapper was retained; retry PIN setup.",
          );
        }
        // Max-security only (true D2): remove the transparent wrap so the PIN is the
        // sole key holder. Passkey mode (default) KEEPS lak.envelope so login /
        // startup unlock transparently and the PIN only re-locks the vault on idle.
        await cipher.clearPersistedWrap();
      }
    } finally {
      lak.fill(0);
    }
    new Notice(
      this.settings.requirePinOnStartup === true
        ? "VaultGuard Sync: PIN set. Your vault now requires this PIN on every startup and locks (not logs out) when idle."
        : "VaultGuard Sync: PIN set. Your vault now locks (not logs out) when idle — unlock with the PIN, no full re-login."
    );
    if (this.settings.requirePinOnStartup !== true) {
      await this.persistLocalRecoveryCapsule();
    }
  }

  /**
   * Toggle "Require PIN on startup" (Phase 12-07) — the passkey ↔ max-security
   * switch — and reconcile the on-disk wrap to match. Called only from the settings
   * tab, so cipher access is encapsulated here (the tab never touches the cipher).
   *
   *   enabled=true  (max-security / true D2): remove the transparent `lak.envelope`
   *                 so `lak-pin.envelope` is the ONLY wrap → PIN required on every
   *                 startup; vault undecryptable without it even with full OS access.
   *   enabled=false (passkey, default): restore `lak.envelope` (persistWrappedLak) so
   *                 login / startup unlock transparently and the PIN only re-locks
   *                 the vault on idle.
   *
   * With an enrolled PIN, the flag is committed only after its matching wrapper
   * posture is durable. This avoids a crash window where settings claim
   * max-security while a transparent wrapper remains. A cipher that is still
   * initialising is waited out (awaitCipherReadyForPin) rather than treated as
   * locked, because toggling this right after opening settings hits the same
   * startup window that made "Set PIN" refuse a perfectly healthy vault. The OFF
   * case is additionally self-healing via the unlockWithPin passkey migration.
   */
  async setRequirePinOnStartup(enabled: boolean): Promise<void> {
    const previousValue = this.settings.requirePinOnStartup === true;
    this.settings.requirePinOnStartup = enabled;

    if (!this.pinLockEnrolled()) {
      await this.saveSettings();
      return; // no PIN → nothing on disk to reconcile; the flag applies at next enroll
    }
    const readiness = await this.awaitCipherReadyForPin(PIN_CIPHER_READY_TIMEOUT_MS);
    const cipher = this.getAtRestCipher();
    if (readiness !== "ready" || !cipher?.isReady()) {
      // Enabling max-security cannot be recorded until its transparent wrapper
      // has actually been removed. Disabling is safe to record while locked;
      // the next PIN unlock performs the existing passkey migration.
      if (enabled) this.settings.requirePinOnStartup = previousValue;
      await this.saveSettings();
      new Notice(
        `VaultGuard Sync: ${this.pinCipherRefusalMessage(
          readiness === "ready" ? "timeout" : readiness,
          "change this PIN setting"
        )}`
      );
      return;
    }
    try {
      if (enabled) {
        // First make both recovery homes PIN-only and purge any rollback copy
        // carrying the transparent wrapper. Only after that durable transition
        // succeeds may the plugin-owned transparent wrapper be removed.
        if (!(await this.persistLocalRecoveryCapsule())) {
          throw new Error("Could not persist the PIN-only local recovery state.");
        }
        await cipher.clearPersistedWrap(); // max-security: PIN becomes the sole wrap
        await this.saveSettings();
      } else {
        await cipher.persistWrappedLak(); // passkey: restore transparent unlock
        if (!(await this.persistLocalRecoveryCapsule())) {
          await cipher.clearPersistedWrap();
          throw new Error("Could not persist the passkey local recovery state.");
        }
        await this.saveSettings();
      }
    } catch (err) {
      this.settings.requirePinOnStartup = previousValue;
      // Restore the previous wrapper posture before reporting failure. These
      // operations are idempotent and keep a failed toggle from silently
      // changing the device's security contract.
      if (previousValue) await cipher.clearPersistedWrap().catch(() => undefined);
      else await cipher.persistWrappedLak().catch(() => undefined);
      await this.saveSettings().catch(() => undefined);
      await this.persistLocalRecoveryCapsule();
      this.logError("Reconciling the at-rest wrap for requirePinOnStartup failed", err);
      new Notice(
        "VaultGuard Sync: couldn't update the PIN startup setting on disk. Try again."
      );
    }
  }

  /**
   * Disable the PIN, restoring transparent at-rest unlock on this device.
   * Requires the current secret (authorization). NN-1 reverse + failure-safe:
   * restore `lak.envelope` (persistWrappedLak) BEFORE removing the PIN material
   * (pinLockManager.disable), so the device always retains a way to load the LAK.
   */
  async disablePinLock(secret: string): Promise<void> {
    if (!this.pinLockManager?.isEnrolled()) {
      throw new Error("No PIN is set.");
    }
    const res = await this.pinLockManager.unlock(secret);
    if (!res.ok) {
      throw new Error(
        res.reason === "locked-out"
          ? "Too many attempts. Please try again later."
          : "Incorrect PIN."
      );
    }
    try {
      const cipher = this.getAtRestCipher();
      if (!cipher) {
        throw new Error("At-rest encryption is not initialized.");
      }
      // Ensure the LAK is live so persistWrappedLak can re-create lak.envelope
      // (normally the cipher is already unlocked when disabling from settings).
      if (!cipher.isReady()) {
        await this.ensureAtRestAdapterRuntimeObject().unlockCipherWithLak(res.lak);
      }
      await cipher.persistWrappedLak(); // NN-1 reverse: restore lak.envelope FIRST
      await this.pinLockManager.disable(); // then remove lak-pin.envelope + pepper
      await this.persistLocalRecoveryCapsule();
    } finally {
      res.lak.fill(0);
    }
    new Notice(
      "VaultGuard Sync: PIN removed. This device unlocks the vault transparently again."
    );
  }

  /**
   * Forgotten-PIN escape (Pitfall 2 / residual #2): disable the local pin-lock
   * FIRST (enrolled→false so the next cold start does NOT re-enter the lock
   * loop) THEN force a real logout. On re-login the cipher sees `lak.envelope`
   * absent + ciphertext present and routes to the EXISTING at-rest recovery
   * (recovery-code restore, or the "Reset at-rest encryption & re-sync" settings
   * action) — never a needs-recovery dead-end. The user is never stranded.
   */
  async forgotPin(): Promise<void> {
    await this.pinLockManager?.disable();
    await this.forceLogout(
      "VaultGuard Sync: PIN reset — please log in again. Your notes re-sync from the cloud."
    );
  }

  /** Confirm the forgotten-PIN reset (wired to the lock curtain's onForgot). */
  private confirmForgotPin(): void {
    const body =
      "You'll be logged out and your notes will re-sync from the cloud. Continue?";
    // The confirmation MUST render inside the curtain. Obsidian's
    // `.modal-container` is `z-index: var(--layer-modal)` — 50 — and the curtain
    // is 2147483647, so a `Modal` opened over the lock is painted behind an
    // opaque surface: the user clicks "Log in again" and nothing appears to
    // happen, which is the escape hatch failing in exactly the state it exists
    // for. The Modal fallback below is only reachable with no curtain up.
    if (this.lockCurtain) {
      this.lockCurtain.confirm({
        title: "Reset PIN?",
        body,
        confirmLabel: "Reset PIN & log out",
        onConfirm: () => void this.forgotPin(),
      });
      return;
    }
    const modal = new Modal(this.app);
    modal.titleEl.setText("Reset PIN?");
    modal.contentEl.createEl("p", { text: body });
    const row = modal.contentEl.createDiv({ cls: "modal-button-container" });
    row
      .createEl("button", { text: "Cancel" })
      .addEventListener("click", () => modal.close());
    const go = row.createEl("button", {
      text: "Reset PIN & log out",
      cls: "mod-warning",
    });
    go.addEventListener("click", () => {
      modal.close();
      void this.forgotPin();
    });
    modal.open();
  }

  /**
   * Pitfall 1 + L-4: on lock, capture the active file path and detach open
   * content leaves so already-rendered plaintext is gone even if the opaque
   * curtain had a gap. Reversed by reopenPreLockFile() on unlock. Best-effort
   * and workspace-shape-guarded (mobile-safe / test-safe).
   */
  private captureAndDetachContentLeaves(): void {
    try {
      this.preLockActiveFilePath = this.app.workspace.getActiveFile()?.path ?? null;
      const ws = this.app.workspace as unknown as {
        detachLeavesOfType?: (type: string) => void;
      };
      if (typeof ws.detachLeavesOfType === "function") {
        for (const type of ["markdown", "image", "pdf"]) {
          ws.detachLeavesOfType(type);
        }
      }
    } catch (err) {
      this.logError("Detaching content leaves on lock failed", err);
    }
  }

  /** L-4: re-open the file that was active at lock time, so unlock is not blank. */
  private async reopenPreLockFile(): Promise<void> {
    const path = this.preLockActiveFilePath;
    this.preLockActiveFilePath = null;
    if (!path) return;
    try {
      const file = this.app.vault.getAbstractFileByPath(path);
      if (file instanceof TFile) {
        await this.app.workspace.getLeaf().openFile(file);
      }
    } catch (err) {
      this.logError("Re-opening the pre-lock file after unlock failed", err);
    }
  }

  /**
   * Biometric enrollment is a DEFERRED seam (D1/O-2). WebAuthn platform auth is
   * unreachable from a community plugin on current Obsidian (Electron 39 < the 43
   * that exposes app.configureWebAuthn, plus a native module + signing
   * entitlements the plugin can't ship), so biometricAvailable() self-disables
   * everywhere and this never actually runs. It exists so the (hidden) settings
   * toggle compiles; biometric drops in additively later behind lak-prf.envelope.
   */
  async enrollBiometric(): Promise<void> {
    new Notice("VaultGuard Sync: biometric unlock is coming in a later version.");
  }

  /**
   * Forces logout: invalidates the session, clears credentials,
   * and optionally wipes local cache.
   */
  async forceLogout(noticeMessage = "VaultGuard Sync: Logged out successfully."): Promise<void> {
    // FIRST statement, before any await: this is the instant the user's intent to
    // end the session is recorded, so it is the instant every in-flight background
    // restore/refresh must stop being allowed to write `this.session` back. Bumping
    // later would leave the whole server-teardown round trip below as a window in
    // which a resuming session could reinstate itself (see `sessionEpoch`).
    this.beginSessionEpoch();

    // Fence the old identity/binding before any asynchronous logout request.
    // requestUrl itself is not abortable, but every reconciliation loop checks
    // the operation token before its next local/remote mutation.
    this.syncRuntime?.cancelActiveOperations("the account logged out");
    this.vaultBindingAuthorization = this.settings.serverVaultId ? "unverified" : "unbound";
    // A logout ends the identity the one-shot account-change prompt was latched
    // to. Without this, signing back in as that same account (the obvious thing
    // to do after "log in as the other account" turns out to be the wrong one)
    // would land in a silent paused state with no prompt.
    this.accountChangePromptedForUserId = null;
    // The paused-local-only notice describes a state the logout just ended.
    this.hideAccountChangePausedNotice();
    // The wrong-account toast describes the identity that just logged out —
    // left standing, it named the previous account after a re-login
    // (quick-260820-ki7 stale-toast fix).
    this.hideWrongAccountNotice();
    // The blocked-window mutation stamps belong to the identity/binding pair
    // this logout just ended (quick-260820-ki7).
    this.blockedStateLocalEdits.clear();
    // Phase 12: any hard-fallback logout while locked (forgotten PIN, attempt
    // cap, server revocation via the still-alive heartbeat, or the 24h cap on
    // unlock) must tear the curtain down FIRST so the workspace is reachable
    // again after the normal logout clears state.
    if (this.isVaultLocked) {
      this.lockCurtain?.hide();
      this.lockCurtain = null;
      this.isVaultLocked = false;
    }
    this.rememberLogoutAuthState(noticeMessage);

    try {
      if (this.session) {

        await this.apiRequest("POST", "/auth/logout", {
          sessionId: this.session.sessionId,
          vaultId: this.settings.serverVaultId || undefined,
        });

      }
    } catch {
      // Best-effort server notification; proceed with local cleanup regardless
    }


    // Persistent agent bridge leases are tied to the session — kill them
    // before we drop the session itself so the bridge's audit trail can
    // attribute the unbind to "logout" rather than "no session present".
    await this.revokeAgentBridgeLeasesForSessionEnd("logout").catch(() => {
      // Best-effort; logout proceeds.
    });
    await this.agentBridgeRuntime?.stopServerIfInitialized().catch(() => {});

    // Purge while the session identity and LAK are still present. A confirmed
    // permission-store event below is a second fail-closed signal, not the
    // primary lifecycle cleanup.
    if (this.shouldPurgeSemanticIndex()) {
      await this.purgeSemanticRuntime("logout").catch((error) =>
        this.logError("Purging semantic index during logout failed", error),
      );
    }

    // PL6: actually kill the refresh token at Cognito — deleting local copies
    // alone leaves any backup of data.json holding a credential that can mint
    // fresh id tokens indefinitely. Best-effort (runs after every backend
    // call that still needs a token); a failure never blocks local logout.
    if (this.session?.refreshToken) {
      const cfg = this.getEffectiveConfig();
      if (cfg.cognitoUserPoolId && cfg.cognitoClientId && !isLocalDevAuth(cfg.cognitoUserPoolId)) {
        try {
          await cognitoRevokeToken(
            cfg.cognitoUserPoolId,
            cfg.cognitoClientId,
            this.session.refreshToken
          );
          this.log("Cognito refresh token revoked.");
        } catch (error) {
          this.logError("Cognito RevokeToken failed (continuing local logout)", error);
        }
      }
    }

    this.session = null;
    // The next session starts its resume from scratch; carrying this over would
    // tell `attemptReconnection` a resume it never ran had already succeeded.
    this.serverSessionResumeComplete = false;
    this.incompleteResumeRetries = 0;
    this.notifyDiscoveryLifecycleChanged();
    this.updateRibbonAuthIndicator();
    this.sidebarViewConfig = null;
    this.keyLease = null;
    this.vaultLeaseDenied = false;
    this.lastLimitedAccessNoticeAt = 0;
    this.lastSessionDegradedNoticeAt = 0;
    this.lastBindingUnverifiedNoticeAt = 0;
    this.orgSettings = null;
    // Drop cached permission-graph data so a different user signing in next
    // never sees the previous session's (viewer-scoped) graph.
    this.invalidatePermissionsGraphCache();
    this.stopSyncTimer();
    this.stopKeyRenewalMonitor();
    this.stopHeartbeatMonitor();
    this.stopAutoLockTimer();
    this.stopConnectionRetry();
    this.clearSensitiveData();
    await this.clearStoredSession();
    this.setConnectionStatus("offline");
    this.syncFileExplorerDecorationsState();
    // Re-evaluate UI surfaces so already-open views flip from "no access"
    // overlay to the read-only banner without needing a tab close/reopen.
    // Phase 9: single bus emit replaces the 5-call fan-out — the four
    // init* subscriptions handle readOnlyGuard / fileExplorer / sidebar /
    // header. Server-confirmed because forceLogout is the authoritative
    // teardown signal.
    this.permissionStore.emit("changed", { serverConfirmed: true });
    this.reloadVaultGuardSidebar();
    this.showLogoutNotice(noticeMessage);
  }

  /**
   * Surface the logout to the user. On desktop the status bar keeps a
   * persistent "Logged out" indicator, so a normal transient Notice is enough.
   * Obsidian mobile has NO status bar and the ribbon (which carries the auth
   * indicator) lives behind the drawer, so a transient toast is easy to miss —
   * users report not realizing they were signed out. On mobile we therefore
   * show a STICKY notice (duration 0 = stays until tapped) that names the
   * reason and how to get back in.
   */
  private showLogoutNotice(noticeMessage: string): void {
    if (!Platform.isMobileApp) {
      new Notice(noticeMessage);
      return;
    }
    const state = this.lastLogoutAuthState;
    const title = state?.title ?? "Logged out";
    const detail = state?.detail ?? this.formatLogoutReason(noticeMessage);
    // Sticky until tapped so the signed-out state is unmissable on mobile.
    new Notice(
      `VaultGuard Sync — ${title}.\n${detail}\nOpen the VaultGuard panel or Settings to log in again.`,
      0,
    );
  }

  /**
   * Initializes the API client with tokens from an existing session.
   */
  private initializeApiClientFromSession(session: UserSession): void {
    if (this.apiClient && session.accessToken) {
      this.apiClient.initialize({
        accessToken: session.accessToken,
        refreshToken: session.refreshToken,
        idToken: session.idToken,
        expiresAt: new Date(session.tokenExpiresAt).getTime(),
      });
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Obsidian Sync Conflict Prevention
  // ─────────────────────────────────────────────────────────────────────────

  /** Persistent Notice shown while Obsidian Sync is enabled; null when not shown. */
  private obsidianSyncNotice: Notice | null = null;

  /**
   * Detects whether Obsidian Sync (the built-in sync plugin) is enabled and
   * warns the user. VaultGuard is the sole sync and backup provider — running
   * both simultaneously causes write races, phantom change propagation,
   * and conflicting conflict-resolution between the two systems.
   *
   * Renders once, then keeps the Notice in sync with the live plugin state
   * via an `internalPlugins.on("change", ...)` listener. Falls back to
   * polling if the event API is unavailable so the notice still clears after
   * the user disables Sync.
   */
  private checkForObsidianSync(): void {
    registerObsidianSyncWarning(this.createLifecycleEventsContext());
  }

  private renderObsidianSyncNotice(): void {
    renderObsidianSyncNoticeLifecycle(this.createLifecycleEventsContext());
  }

  private registerObsidianSyncListener(): void {
    registerObsidianSyncListenerLifecycle(this.createLifecycleEventsContext());
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Local At-Rest Adapter Runtime
  // ─────────────────────────────────────────────────────────────────────────

  private async initAtRestCipher(): Promise<void> {
    return this.ensureAtRestAdapterRuntimeObject().initAtRestCipher();
  }

  private async createLocalRecoveryStore(): Promise<LocalRecoveryCapsuleStore> {
    const adapter = this.app.vault.adapter;
    const pluginId = this.manifest?.id ?? "vaultguard-sync";
    const fallbackKekPath = this.vaultConfigPath("plugins", pluginId, "at-rest-kek.dat");
    let fallbackKek: string | null = null;
    try {
      const profileValue: unknown = this.app.loadLocalStorage("vaultguard.at-rest.kek.v1");
      if (typeof profileValue === "string" && profileValue.trim()) {
        fallbackKek = profileValue.trim();
      } else if (await adapter.exists(fallbackKekPath)) {
        const durable = (await adapter.read(fallbackKekPath)).trim();
        fallbackKek = durable || null;
      }
    } catch (error) {
      this.logError("Reading the local recovery sealing key failed", error);
    }
    return new LocalRecoveryCapsuleStore(
      {
        readVault: async (path) => {
          if (!(await adapter.exists(path))) return null;
          return adapter.read(path);
        },
        writeVault: async (path, value) => {
          await this.ensureParentFoldersForPath(path);
          await adapter.write(path, value);
        },
        renameVault: async (from, to) => {
          await adapter.rename(from, to);
        },
        removeVault: async (path) => {
          if (!(await adapter.exists(path))) return;
          try {
            await adapter.remove(path);
          } catch (error) {
            // The exists-guard is inherently TOCTOU-racy. The persist/clear
            // latch should keep this from ever firing, but a file that is
            // already gone is exactly the desired end state — never fail a
            // rotation over it. Anything else (EPERM/EIO) still propagates so
            // the store's error contracts and logError paths keep firing.
            if (!isFileAlreadyMissingError(error)) throw error;
          }
        },
        listVaultRecoveryFiles: async () => {
          if (!(await adapter.exists(LOCAL_RECOVERY_ROOT))) return [];
          const listed = await adapter.list(LOCAL_RECOVERY_ROOT);
          return listed.files;
        },
        ensureVaultRecoveryRoot: async () => {
          await this.ensureParentFoldersForPath(LOCAL_RECOVERY_MANIFEST_PATH);
        },
        loadProfile: (key) => this.app.loadLocalStorage(key),
        saveProfile: (key, value) => this.app.saveLocalStorage(key, value),
      },
      this.derivedBindingId,
      probeSafeStorage(),
      fallbackKek,
    );
  }

  /**
   * Runs after adapter interception but before PIN/cipher construction. It may
   * restore only device-wrapped material and sealed settings hints. A recovered
   * binding remains unverified and a recovered LAK remains unusable for sync
   * until post-init VG1 continuity validation succeeds.
   */
  private async restoreLocalRecoveryBeforeCipherInit(): Promise<void> {
    if (this.isLocalProjectMemoryModeEnabled()) {
      this.localProtectionBootstrap = { kind: "new" };
      this.vaultBindingAuthorization = "unbound";
      return;
    }
    const runtime = this.ensureAtRestAdapterRuntimeObject();
    const hasVg1 = await runtime.hasPriorAtRestCiphertext();
    const pluginId = this.manifest?.id ?? "vaultguard-sync";
    const transparentPath = this.vaultConfigPath("plugins", pluginId, "lak.envelope");
    const pinPath = this.lakPinEnvelopePath();
    const adapter = this.app.vault.adapter;
    const transparentEnvelopeExists = await adapter.exists(transparentPath);
    const pinEnvelopeExists = await adapter.exists(pinPath);
    const pluginEnvelopeExists =
      transparentEnvelopeExists ||
      (pinEnvelopeExists && this.settings.pinLock?.enrolled === true);

    // Compatibility/source priority: a complete plugin-owned envelope remains
    // authoritative. The recovery capsule is the fallback for uninstall or a
    // torn plugin directory, never a reason to replace healthy current state.
    if (pluginEnvelopeExists) {
      this.localProtectionBootstrap = { kind: "existing", source: "plugin-envelope" };
      this.vaultBindingAuthorization = this.settings.serverVaultId ? "unverified" : "unbound";
      return;
    }

    let result: LocalRecoveryRestoreResult;
    try {
      result = await (await this.createLocalRecoveryStore()).restore(hasVg1);
    } catch (error) {
      const reason = `VaultGuard could not inspect the local recovery capsule: ${
        error instanceof Error ? error.message : String(error)
      }. Existing encrypted files were left unchanged.`;
      this.localProtectionBootstrap = { kind: "needs-recovery", reason };
      this.vaultBindingAuthorization = this.settings.serverVaultId ? "unverified" : "unbound";
      this.logError("Local recovery capsule inspection failed", error);
      return;
    }

    if (result.kind === "none") {
      this.localProtectionBootstrap = pluginEnvelopeExists
        ? { kind: "existing", source: "plugin-envelope" }
        : { kind: "new" };
      this.vaultBindingAuthorization = this.settings.serverVaultId ? "unverified" : "unbound";
      return;
    }
    if (result.kind === "needs-recovery") {
      this.localProtectionBootstrap = { kind: "needs-recovery", reason: result.reason };
      this.vaultBindingAuthorization = this.settings.serverVaultId ? "unverified" : "unbound";
      return;
    }

    const state = result.state;
    await this.ensureParentFoldersForPath(transparentPath);
    if (state.requirePinOnStartup) {
      // Max-security invariant: restoring a capsule must never recreate the
      // transparent LAK wrap. The PIN envelope remains the sole LAK wrapper.
      if (await adapter.exists(transparentPath)) await adapter.remove(transparentPath);
    } else if (state.wrappedLak) {
      await adapter.write(transparentPath, state.wrappedLak);
    }
    if (state.pinEnvelope) {
      await this.ensureParentFoldersForPath(pinPath);
      await adapter.write(pinPath, state.pinEnvelope);
    }
    if (state.pinState) {
      this.settings.pinLock = {
        ...state.pinState,
        pepperWrapped: state.pinPepperWrapped,
      };
    }
    this.settings.requirePinOnStartup = state.requirePinOnStartup;
    if (state.pinOnboardingPromptShown !== undefined) {
      this.settings.pinOnboardingPromptShown = state.pinOnboardingPromptShown;
    }
    if (state.connection) {
      const connection = state.connection;
      if (connection.orgSlug !== undefined) this.settings.orgSlug = connection.orgSlug;
      if (connection.apiEndpoint !== undefined) this.settings.apiEndpoint = connection.apiEndpoint;
      if (connection.organizationId !== undefined) {
        this.settings.organizationId = connection.organizationId;
      }
      if (connection.cognitoUserPoolId !== undefined) {
        this.settings.cognitoUserPoolId = connection.cognitoUserPoolId;
      }
      if (connection.cognitoClientId !== undefined) {
        this.settings.cognitoClientId = connection.cognitoClientId;
      }
      if (connection.manualConfig !== undefined) this.settings.manualConfig = connection.manualConfig;
    }
    if (state.binding) {
      this.settings.serverVaultId = state.binding.serverVaultId;
      this.settings.serverVaultName = state.binding.serverVaultName;
      this.settings.serverVaultSlug = state.binding.serverVaultSlug;
      if (state.binding.organizationId) {
        this.settings.organizationId = state.binding.organizationId;
      }
      this.localRecoveryExpectedAccountUserId = state.binding.accountUserId ?? null;
      this.localRecoveryExpectedAccountEmail = state.binding.accountEmail ?? null;
      this.vaultBindingAuthorization = "unverified";
    } else {
      this.vaultBindingAuthorization = "unbound";
    }
    this.localProtectionBootstrap = { kind: "existing", source: result.source };
    this.localRecoveryNeedsLakValidation = true;
    await this.saveSettings();
    this.rebuildApiClient();
    this.log(`Restored existing local protection from the ${result.source} recovery capsule.`);
  }

  private async finalizeRecoveredLocalProtection(): Promise<void> {
    if (!this.localRecoveryNeedsLakValidation) return;
    const cipher = this.getAtRestCipher();
    if (!cipher?.isReady()) {
      // A PIN-only/max-security capsule intentionally lands locked. Validation
      // resumes immediately after the PIN unwrap; all sync gates stay closed.
      if (this.pinLockEnrolled()) return;
      const reason =
        "VaultGuard restored local recovery metadata but could not unlock its device-local key wrapper. Restore with the recovery code; no files were changed.";
      this.localProtectionBootstrap = { kind: "needs-recovery", reason };
      return;
    }
    if (!(await this.ensureAtRestAdapterRuntimeObject().validateCurrentLakAgainstExistingCiphertext())) {
      const status = this.getAtRestStatus();
      const reason =
        status.kind === "needs-recovery"
          ? status.reason
          : "The restored device-local key did not match this protected vault.";
      this.localProtectionBootstrap = { kind: "needs-recovery", reason };
      this.localRecoveryNeedsLakValidation = false;
      return;
    }
    this.localRecoveryNeedsLakValidation = false;
    await this.persistLocalRecoveryCapsule();
  }

  private getProtectedContentGate(): ProtectedContentGate {
    const status = this.getAtRestStatus();
    if (this.localProtectionBootstrap.kind === "needs-recovery" || status.kind === "needs-recovery") {
      return {
        ok: false,
        reason: "needs-recovery",
        message:
          "VaultGuard Sync is paused because local protection needs recovery. Restore from the local recovery code; protected files were not changed.",
      };
    }
    if (
      this.localRecoveryNeedsLakValidation ||
      status.kind === "uninitialized" ||
      status.kind === "disabled"
    ) {
      return {
        ok: false,
        reason: "at-rest-unavailable",
        message: "VaultGuard Sync is paused until local at-rest protection is available.",
      };
    }
    if (this.settings.serverVaultId && this.vaultBindingAuthorization === "account-changed") {
      return {
        ok: false,
        reason: "account-changed",
        message: this.accountChangeMessage(),
      };
    }
    if (this.settings.serverVaultId && this.vaultBindingAuthorization === "wrong-account") {
      return {
        ok: false,
        reason: "wrong-account",
        message:
          `VaultGuard Sync is paused: ${this.describeCurrentAccount()} is not a member of the server vault ` +
          `this folder is bound to${this.settings.serverVaultName ? ` ("${this.settings.serverVaultName}")` : ""}. ` +
          "Ask a vault admin to add this account, or connect this folder to a vault it is a member of. No sync was started.",
      };
    }
    if (this.settings.serverVaultId && this.vaultBindingAuthorization === "unverified") {
      return {
        ok: false,
        reason: "binding-unverified",
        message:
          "VaultGuard Sync is paused until the signed-in account is verified for this exact server vault.",
      };
    }
    return { ok: true };
  }

  private async verifyBoundVaultAuthorization(): Promise<boolean> {
    const vaultId = this.settings.serverVaultId?.trim();
    if (!vaultId) {
      this.vaultBindingAuthorization = "unbound";
      return false;
    }
    if (!this.session || !this.apiClient) {
      this.vaultBindingAuthorization = "unverified";
      return false;
    }
    this.vaultBindingAuthorization = "unverified";
    if (
      this.localRecoveryExpectedAccountUserId &&
      this.localRecoveryExpectedAccountUserId !== this.session.userId
    ) {
      // NOT an authorization answer — the server has not been asked yet. The
      // expectation is device-local bookkeeping, and a perfectly ordinary
      // second member of this same vault trips it. Stop sync (nothing crosses
      // the wire under an unconfirmed identity), then ASK; confirming re-runs
      // this method with the expectation cleared, so the server decides.
      this.vaultBindingAuthorization = "account-changed";
      this.stopSyncTimer();
      // A wrong-account toast must not survive into a different state — this
      // branch describes an unresolved QUESTION, not a server denial.
      this.hideWrongAccountNotice();
      // The status bar must stop claiming "Connected ✓" the moment this state
      // exists — it renders the paused branch off vaultBindingAuthorization.
      this.updateStatusBar();
      void this.resolveAccountChange();
      return false;
    }
    try {
      const vault = await this.apiClient.getVaultRecord(vaultId);
      if (vault.vaultId !== vaultId) {
        throw new AuthorizationError(`Vault identity mismatch for ${vaultId}`);
      }
      await this.cacheCurrentVaultRecord(vault);
      this.vaultBindingAuthorization = "verified";
      this.localRecoveryExpectedAccountUserId = this.session.userId;
      this.localRecoveryExpectedAccountEmail = this.session.email ?? null;
      this.accountChangePromptedForUserId = null;
      this.hideAccountChangePausedNotice();
      // A wrong-account toast must never outlive a successful verification.
      this.hideWrongAccountNotice();
      // A verified binding ends the blocked window; its mutation stamps
      // describe a state that no longer exists (quick-260820-ki7).
      this.blockedStateLocalEdits.clear();
      void this.persistLocalRecoveryCapsule();
      return true;
    } catch (error) {
      this.stopSyncTimer();
      if (error instanceof AuthorizationError || /not found|access denied|forbidden|\b403\b/i.test(String(error))) {
        this.vaultBindingAuthorization = "wrong-account";
        this.showWrongAccountNotice();
        this.logError("Bound vault authorization failed", error);
        return false;
      }
      this.vaultBindingAuthorization = "unverified";
      this.logError("Bound vault authorization could not be verified", error);
      const now = Date.now();
      if (now - this.lastBindingUnverifiedNoticeAt >= 60_000) {
        this.lastBindingUnverifiedNoticeAt = now;
        new Notice(
          "VaultGuard Sync: the protected vault could not be verified right now. Sync stays paused and will retry automatically.",
          9000,
        );
      }
      return false;
    }
  }

  /** Names the signed-in account when the session carries an email. */
  private describeCurrentAccount(): string {
    const email = this.session?.email?.trim();
    return email ? `the signed-in account (${email})` : "the signed-in account";
  }

  /** Names the account that last verified this folder, when the capsule has it. */
  private describeExpectedAccount(): string {
    const email = this.localRecoveryExpectedAccountEmail?.trim();
    return email ? `another account (${email})` : "a different account";
  }

  /**
   * Routes a detected account change (quick-260820-ki7: "auto when clean, ask
   * when dirty"). No modal lives here anymore — adoptBindingForCurrentAccount
   * owns the whole resolution (probe → cleanliness gates → automatic reset OR
   * the dirty-only discard dialog), and every lane below is loud on its own.
   * Deliberately once per signed-in identity: the binding check re-runs from
   * several places (startup resume, reconnect re-drive, an explicit re-pick),
   * and re-entering the resolution on each would be its own kind of broken.
   * `accountChangePromptedForUserId` is cleared whenever the binding verifies
   * or the account changes again, and every explicit re-offer entry point
   * (sidebar, status bar, sticky-notice button) clears it first — that click
   * IS the user asking again.
   */
  private async resolveAccountChange(): Promise<void> {
    const session = this.session;
    if (!session) return;
    if (this.accountChangePromptedForUserId === session.userId) return;
    this.accountChangePromptedForUserId = session.userId;
    // The resolution supersedes any standing paused notice (a re-offer via the
    // sidebar / status bar / notice button lands here).
    this.hideAccountChangePausedNotice();
    // Deliberately argument-free (quick-260820-prn): this method is reached
    // only from verify's `account-changed` branch, which requires an identity
    // mismatch, so it is structurally always the TAKEOVER path and can never
    // need the vault sub-lane. Passing a previous vault here would be
    // meaningless — no rebind is in flight.
    await this.adoptBindingForCurrentAccount();
  }

  /**
   * Server-membership probe for the current session against the bound vault
   * WITHOUT adopting it: no expectation restamp, no capsule persist, no
   * account-changed gate. The takeover path must know the server's answer
   * before the destructive local reset, but recording the adoption before the
   * reset completes would — after a crash mid-wipe — leave the previous
   * account's key running under the new account's name with the prompt
   * permanently disarmed. Denials land the same honest terminal state as
   * `verifyBoundVaultAuthorization` so both paths surface identical UX.
   */
  private async probeBoundVaultMembership(): Promise<boolean> {
    const vaultId = this.settings.serverVaultId?.trim();
    if (!vaultId || !this.session || !this.apiClient) return false;
    try {
      const vault = await this.apiClient.getVaultRecord(vaultId);
      if (vault.vaultId !== vaultId) {
        throw new AuthorizationError(`Vault identity mismatch for ${vaultId}`);
      }
      await this.cacheCurrentVaultRecord(vault);
      return true;
    } catch (error) {
      this.stopSyncTimer();
      if (
        error instanceof AuthorizationError ||
        /not found|access denied|forbidden|\b403\b/i.test(String(error))
      ) {
        this.vaultBindingAuthorization = "wrong-account";
        this.showWrongAccountNotice();
        this.logError("Bound vault authorization failed", error);
      } else {
        this.logError("Bound vault authorization could not be verified", error);
        new Notice(
          "VaultGuard Sync: the protected vault could not be verified right now. Sync stays paused and will retry automatically.",
          9000,
        );
      }
      return false;
    }
  }

  /**
   * Explicit destructive consent for the DIRTY takeover path
   * (quick-260820-ki7). Fail-closed: with no Obsidian document (unit
   * harnesses, embedders, headless startup) there is nobody to consent, so
   * the answer is "keep" — the paused account-changed state explains itself
   * and the sidebar keeps offering the action. The clean path never calls
   * this: no dialog object may be constructed there.
   */
  private async confirmDiscardUnsyncedChanges(
    changes: { items: string[]; indeterminate: boolean },
    crossCheck: { ok: boolean; unconfirmed: string[] },
    // quick-260820-mv4: the same gate serves the vault-to-vault switch. Only
    // the copy differs — `kind` picks it, and the vault lane passes the name
    // of the vault being left (the current binding has already been read for
    // it, but nothing is mutated until consent lands).
    //
    // quick-260820-prn: `bindingAlreadyApplied` picks the second vault-lane
    // variant, for the blocked adopt path where the binding has ALREADY
    // flipped. Its copy cannot offer to cancel a switch that has happened.
    variant?: {
      kind: "vault";
      previousVaultName?: string;
      nextVaultName?: string;
      bindingAlreadyApplied?: boolean;
    }
  ): Promise<boolean> {
    if (!getActiveObsidianDocument()) return false;
    const { AccountSwitchDiscardModal } = await import("./account-switch-discard-modal");
    // Asserted, not annotated: a plain literal initializer narrows `decision`
    // for the comparison below, because the modal callback that widens it is
    // not visible to control-flow analysis. "keep" is the fail-closed default
    // — a dismissal without a decision never discards.
    let decision = "keep" as AccountSwitchDiscardDecision;
    await new Promise<void>((resolve) => {
      const modal = new AccountSwitchDiscardModal(
        this.app,
        {
          kind: variant?.kind ?? "account",
          previousVaultName: variant?.previousVaultName,
          currentAccountEmail: this.session?.email ?? undefined,
          previousAccountEmail: this.localRecoveryExpectedAccountEmail ?? undefined,
          // `vaultName` is always the vault being CONNECTED TO. On the account
          // lane that is the current binding; on the vault lane the gate runs
          // BEFORE any mutation, so the settings still name the old vault and
          // the caller must supply the new one.
          vaultName:
            (variant?.kind === "vault"
              ? variant.nextVaultName
              : this.settings.serverVaultName) || undefined,
          items: changes.items,
          unconfirmed: crossCheck.unconfirmed,
          // A failed/capped cross-check means the server-side picture is
          // unknown — surfaced as "could not be fully listed", never hidden.
          indeterminate: changes.indeterminate || !crossCheck.ok,
          // quick-260820-prn. The modal reads this pair only on the
          // already-applied vault lane, so no other copy changes: there, a
          // failed cross-check has a concrete, nameable cause (this account
          // was denied the vault being left) and saying it is more honest
          // than the generic "could not be fully listed".
          bindingAlreadyApplied: variant?.bindingAlreadyApplied === true,
          previousVaultUnverifiable: !crossCheck.ok,
        },
        (result) => {
          decision = result;
        }
      );
      modal.onClose = () => {
        modal.contentEl.empty();
        resolve();
      };
      modal.open();
    });
    return decision === "discard";
  }

  /**
   * Resolves the account change. Let the SERVER answer — `/vaults/{vaultId}`
   * is the only authority on whether this account may use this binding — and,
   * when the account genuinely changed hands, replace the folder's local
   * protection before adopting. The LAK is device-scoped, so adopting without
   * a re-key would hand this account the previous account's entire decrypted
   * local cache (including server-denied files, via the deliberate read
   * fail-open).
   *
   * The takeover lane is "auto when clean, ask when dirty" (quick-260820-ki7)
   * and stays deliberately crash-safe:
   *   1. Probe membership WITHOUT stamping. A 403 lands the honest
   *      `wrong-account` state and nothing local changes.
   *   2. Prove cleanliness TWICE over: every local signal
   *      (collectUnsyncedLocalChanges — defaults to dirty on any uncertainty)
   *      AND the positive server-listing cross-check must pass.
   *   3. Clean → `resetLocalAtRestAndResync({ mode: "account-takeover" })`
   *      runs automatically (it destroys only server-recoverable cache);
   *      dirty → exactly one discard dialog names the concrete losses, and
   *      only an explicit [Discard and switch] — after actively clearing the
   *      tracked unsynced holders — reaches the reset. Declines, dismissals
   *      and headless land the loud paused local-only state.
   *   4. Only the reset re-stamps the expectation and re-verifies the
   *      binding, so a crash anywhere earlier re-arms the flow instead of
   *      silently running the old key under the new name.
   *
   * Same-account confirms (expectation empty or already this user) skip all of
   * that: clear the expectation and let `verifyBoundVaultAuthorization` decide,
   * exactly as before — UNLESS the vault changed too (quick-260820-prn, see the
   * sub-lane's own comment below). On success the expectation is re-stamped and
   * the capsule persisted; on a 403 the state becomes a real `wrong-account` and
   * every later check re-asks the server.
   *
   * `previousVaultId` / `previousVaultName` are PARAMETERS, never fields:
   * `applyVaultBinding` derives them live from settings immediately before the
   * mutation and hands them over for this single flow. An instance field would
   * let a re-entrant `resolveAccountChange()` replay a stale previous vault
   * against a settled binding — and `resetLocalAtRestAndResync` already takes
   * `previousVaultId` as a parameter for exactly this reason.
   */
  private async adoptBindingForCurrentAccount(
    previousVaultId?: string,
    previousVaultName?: string
  ): Promise<void> {
    if (!this.session) return;
    const expectedUserId = this.localRecoveryExpectedAccountUserId;
    const takeover = !!expectedUserId && expectedUserId !== this.session.userId;
    if (takeover) {
      if (!(await this.probeBoundVaultMembership())) {
        if (this.vaultBindingAuthorization === "account-changed") {
          // Transient failure — the probe's catch already showed the 9s retry
          // toast, but the blocked state PERSISTS, so its explanation must
          // too: sticky paused notice, re-offerable from the sidebar.
          this.showAccountChangePausedNotice();
        }
        // wrong-account: the probe already raised the tracked sticky
        // wrong-account notice — do not stack the paused notice on top.
        return;
      }
      // The probe round trip proved the API reachable — flip online so the
      // reset guard's isOnline() passes on the startup/restore lane (which
      // deliberately never flips online at the binding gate: a capsule
      // mismatch proves nothing about reachability). Safe: the online-flip
      // flush trigger is gate-checked, so nothing uploads while blocked.
      this.setConnectionStatus("online");
      this.hideWrongAccountNotice();

      // Cleanliness gates (quick-260820-ki7): BOTH must positively pass —
      // the local signals AND the server-listing cross-check (which covers
      // files added while Obsidian was closed, a class no local tracker can
      // see). Anything less routes to the dirty dialog.
      let changes = await this.collectUnsyncedLocalChanges();
      const crossCheck = await this.crossCheckLocalFilesAgainstServerListing();
      let clean = changes.clean && crossCheck.ok && crossCheck.unconfirmed.length === 0;

      // Pre-reset TOCTOU re-check: an edit may have landed between the clean
      // check and this point (the cross-check round trips gave it time).
      // Cheap in-memory signals only — no second network call. Anything new
      // routes to the dirty path instead of resetting over it.
      if (
        clean &&
        (this.offlineQueue.length > 0 ||
          this.blockedStateLocalEdits.size > 0 ||
          this.syncState.conflicts.length > 0)
      ) {
        clean = false;
        changes = await this.collectUnsyncedLocalChanges();
      }

      if (!clean) {
        const consent = await this.confirmDiscardUnsyncedChanges(changes, crossCheck);
        if (!consent) {
          // Sticky, not transient: the paused state persists after the
          // decline, so its explanation must too — a 9s toast left the folder
          // silently local-only once it faded (user report, 2026-08-20). The
          // expectation stays untouched so the flow re-arms.
          this.showAccountChangePausedNotice();
          return;
        }
        // Clear the tracked unsynced holders BEFORE the reset — otherwise the
        // "discarded" queued edits would survive the wipe and replay under
        // the new identity once re-verify opens the gate, contradicting the
        // consent copy. Cross-check misses need no discard bookkeeping — the
        // reset wipe + re-pull handles them.
        await this.discardUnsyncedLocalChanges();
      }
      // Clean: straight to the reset — no dialog object is constructed
      // anywhere on this path.
      try {
        await this.resetLocalAtRestAndResync({ mode: "account-takeover" });
      } catch (error) {
        this.logError("Account takeover local reset failed", error);
        new Notice(
          "VaultGuard Sync: resetting local protection for this account failed. Nothing was adopted — open VaultGuard and choose to continue as this account to retry.",
          0,
        );
        return;
      }
      // The reset re-stamped the expectation, re-verified the binding and
      // persisted the fresh capsule; fall through to the resume below.
      new Notice(
        `VaultGuard Sync: this folder now syncs as ${this.session.email || "the signed-in account"} — the local cache was refreshed for this account.`,
        6000
      );
    } else {
      // SAME IDENTITY — but possibly not the same VAULT (quick-260820-prn).
      //
      // This branch used to be identity-only: clear the expectation, verify,
      // done. That is correct when the folder is still pointed at the vault
      // whose files it holds, and wrong the moment it is not. A blocked
      // binding resolved with [Connect a different vault] arrives here with
      // the previous vault's entire local cache still on disk, which the next
      // reconciliation then reads as local-only against the newly bound vault
      // (handoff lane C2). The vault change needs the same consent boundary
      // as a takeover, so it gets the same gate.
      //
      // Read live from settings — `applyVaultBinding` has already written the
      // new vault by the time it delegates here.
      const priorVaultId = previousVaultId?.trim() ?? "";
      const vaultChanged =
        !!priorVaultId && priorVaultId !== (this.settings.serverVaultId?.trim() ?? "");
      if (!vaultChanged) {
        // Byte-identical to the pre-prn behaviour, and it needs no second copy
        // of applyVaultBinding's `changed` predicate: when the vault did not
        // change, priorVaultId simply equals the bound vault.
        this.localRecoveryExpectedAccountUserId = null;
        this.localRecoveryExpectedAccountEmail = null;
        if (!(await this.verifyBoundVaultAuthorization())) return;
        new Notice(
          `VaultGuard Sync: this folder is now connected as ${this.session.email || "the signed-in account"}.`,
          6000
        );
      } else {
        // THE VAULT-CHANGED SUB-LANE. Four things about its shape are
        // load-bearing:
        //
        // 1. It probes with the NON-STAMPING probe, exactly as the takeover
        //    branch does — `verifyBoundVaultAuthorization` CLEARS
        //    `blockedStateLocalEdits` on success, and those live blocked-window
        //    edits are one of the ki7 dirty signals. Verifying before the gate
        //    would destroy the evidence the gate exists to read.
        // 2. The gate runs BEFORE the expectation pair is touched and before
        //    any verify, for the same reason.
        // 3. It is mutually exclusive with the takeover branch by
        //    construction — it lives inside the `else` of the very
        //    `if (takeover)` that defines it — so a double-ask is structurally
        //    impossible rather than merely avoided. `applyVaultBinding`'s
        //    `isVaultSwitch` still excludes `wasBlocked`, so mv4's lane cannot
        //    ask either.
        // 4. In practice the cross-check on the previous vault FAILS here:
        //    this lane is reachable only when the server denied this account
        //    on the vault being left, so `listVaultFilesPage` 403s and the
        //    gate is dirty. That means it almost always asks rather than
        //    auto-purging — by design. You cannot discard what you cannot
        //    prove is safe to discard; do not relax the gate to "fix" it.
        if (!(await this.probeBoundVaultMembership())) {
          if (this.vaultBindingAuthorization !== "wrong-account") {
            // Transient failure — the probe's catch showed the 9 s retry
            // toast, but the blocked state PERSISTS, so its explanation must
            // too. A 403 already raised the tracked sticky wrong-account
            // notice; stacking on top of that would name the state twice.
            this.showAccountChangePausedNotice(
              this.blockedVaultSwitchPausedMessage(previousVaultName)
            );
          }
          return;
        }
        // The probe round trip proved the API reachable — flip online so the
        // vault-switch reset guard's isOnline() passes. Same justification and
        // same ordering as the takeover branch: connectionState is born
        // "offline", and the online-flip flush trigger is gate-checked, so
        // nothing uploads while the binding is still unverified.
        this.setConnectionStatus("online");
        this.hideWrongAccountNotice();

        const consented = await this.confirmVaultSwitchLocalPurge(
          priorVaultId,
          this.settings.serverVaultName ?? "",
          { previousVaultName, bindingAlreadyApplied: true }
        );
        if (!consented) {
          // Nothing purged, nothing adopted, no capsule persisted and the
          // expectation untouched. The previous vault's files stay on disk,
          // where or3's Phase 1b gate blocks any silent upload of them.
          this.showAccountChangePausedNotice(
            this.blockedVaultSwitchPausedMessage(previousVaultName)
          );
          return;
        }
        try {
          await this.resetLocalAtRestAndResync({
            mode: "vault-switch",
            previousVaultId: priorVaultId,
          });
        } catch (error) {
          this.logError("Blocked-lane vault-switch local reset failed", error);
          new Notice(
            "VaultGuard Sync: connecting this folder to the new vault failed while replacing the local cache. " +
              "Nothing was uploaded or deleted on either vault — open VaultGuard and retry the switch.",
            0
          );
          return;
        }
        // The reset re-verified the binding, stamped the expectation and
        // persisted the fresh capsule — nothing on this lane stamps anything
        // before it, so a crash at any earlier point re-arms the whole flow.
        new Notice(
          `VaultGuard Sync: this folder now holds ${
            this.settings.serverVaultName || "the selected vault"
          } — the local cache was replaced.`,
          6000
        );
      }
    }

    // The startup resume returned early at the binding gate and marked itself
    // finished (a pending user decision is not something the reconnect loop can
    // resolve). Now that the decision exists, re-open that path through the
    // existing guarded helper so monitors, the vault-scoped lease and the sync
    // engine all come back.
    this.serverSessionResumeComplete = false;
    this.resumeIncompleteServerSession();
  }

  /**
   * Positive server-presence proof for the takeover lane's clean gate
   * (quick-260820-ki7). Every non-excluded local file must appear in the
   * server vault's permission-filtered listing, accumulated across ALL pages
   * — this is what covers files added while Obsidian was closed or before the
   * blocked window began, the class the blocked-window event tracker
   * structurally cannot see.
   *
   * Fail-safe by construction: any listing/permission error and
   * pagination-cap exhaustion return `ok: false` (dirty), never clean.
   * Deliberately NOT `getFiles()`: that method returns a single
   * server-default-100 page and discards the continuation token, which would
   * false-dirty every vault over ~100 files and kill the auto path.
   *
   * Contract notes:
   * - The listing is PERMISSION-FILTERED: a file that exists server-side but
   *   is denied to this account is absent from it, so a miss is NOT provably
   *   an unsynced change. Callers must present misses as "could not be
   *   confirmed as synced", never as unsynced changes (honesty requirement).
   * - Presence bookkeeping uses a Set of normalized paths, which sidesteps
   *   the cold-path manifest falsy trap ("" = present / undefined = absent,
   *   fix 2e4c8f4) entirely; both sides are normalized identically before
   *   comparison (the handler emits '/' + relativePath shapes, and
   *   normalizeVaultPath strips the leading slash).
   */
  private async crossCheckLocalFilesAgainstServerListing(
    // quick-260820-mv4: the vault-SWITCH lane must prove the vault it is
    // LEAVING, which it can only do while that binding is still live — so the
    // target is explicit there. Omitted (the ki7 takeover lane) it defaults to
    // the current binding, byte-identically to before.
    targetVaultId?: string
  ): Promise<{
    ok: boolean;
    unconfirmed: string[];
  }> {
    const vaultId = (targetVaultId ?? this.settings.serverVaultId)?.trim();
    if (!vaultId || !this.apiClient) return { ok: false, unconfirmed: [] };
    const serverPaths = new Set<string>();
    try {
      let continuationToken: string | undefined;
      let pagesRead = 0;
      // ~50k files at 1000/page. Exhausting the cap means the listing could
      // not be proven complete — treated exactly like an error (dirty).
      const MAX_LISTING_PAGES = 50;
      for (;;) {
        if (pagesRead >= MAX_LISTING_PAGES) {
          return { ok: false, unconfirmed: [] };
        }
        const page = await this.apiClient.listVaultFilesPage(vaultId, {
          limit: 1000,
          continuationToken,
        });
        pagesRead++;
        for (const item of page.files) {
          serverPaths.add(this.normalizeVaultPath(item.path));
        }
        if (page.nextContinuationToken === null) break;
        continuationToken = page.nextContinuationToken;
      }
    } catch (error) {
      this.logError("Server-listing cross-check for the account takeover failed", error);
      return { ok: false, unconfirmed: [] };
    }
    const unconfirmed: string[] = [];
    for (const file of this.app.vault.getFiles()) {
      const normalized = this.normalizeVaultPath(file.path);
      if (!normalized || this.isPathExcluded(normalized)) continue;
      if (!serverPaths.has(normalized)) unconfirmed.push(normalized);
    }
    return { ok: true, unconfirmed };
  }

  /**
   * Shared copy for the wrong-account state (quick-260820-nqm). The same
   * sentence was inlined at the verify and probe denial branches; the notice
   * is now re-raisable from switchServerVault too, and three hand-maintained
   * copies of one message is how they drift.
   */
  private wrongAccountMessage(): string {
    const vault = this.settings.serverVaultName
      ? ` ("${this.settings.serverVaultName}")`
      : "";
    return (
      `VaultGuard Sync: ${this.describeCurrentAccount()} is not a member of the server vault ` +
      `this folder is bound to${vault}. This folder works locally only — nothing uploads or ` +
      `downloads until it is resolved. Connect it to a vault this account can use, ` +
      `log in as a different account, or ask a vault admin for access.`
    );
  }

  /** Shared copy for the account-change state — gate, sidebar and notices. */
  private accountChangeMessage(): string {
    const vault = this.settings.serverVaultName
      ? ` ("${this.settings.serverVaultName}")`
      : "";
    return (
      `VaultGuard Sync is paused: this folder was connected by ${this.describeExpectedAccount()}, ` +
      `and ${this.describeCurrentAccount()} has not been checked against its server vault${vault} yet. ` +
      `The folder works locally only — notes and edits stay on this device, nothing uploads or downloads. ` +
      `Open VaultGuard (sidebar or status bar) to continue as this account.`
    );
  }

  /**
   * Paused copy for the blocked same-identity VAULT change (quick-260820-prn).
   * The account is fine here — "resolve the account change" would send the
   * user looking for a problem that does not exist. What is unresolved is the
   * folder: it is connected to one vault while holding another's files.
   *
   * Its [Resolve now] action is not a dead end: the binding is `unverified`
   * and a session exists, so `handlePrimaryProtectionAction` opens the vault
   * picker. Picking again re-enters `applyVaultBinding` unblocked, which runs
   * mv4's pre-mutation gate, and the leftover files — absent from the bound
   * vault's listing — land in `unconfirmed`, where consent purges them.
   */
  private blockedVaultSwitchPausedMessage(previousVaultName?: string): string {
    const next = this.settings.serverVaultName?.trim();
    const prev = previousVaultName?.trim();
    return (
      `VaultGuard: sync is paused — this folder is now connected to ` +
      `${next ? `"${next}"` : "the selected vault"} but still holds the local files from ` +
      `${prev ? `"${prev}"` : "the vault it was connected to before"}. ` +
      `Nothing uploads or downloads until those files are replaced or this folder is ` +
      `connected to a different vault.`
    );
  }

  /**
   * The loud half of "decide later" (quick-260819-sd8). Dismissing the
   * account-change prompt parks the folder in a LOCAL-ONLY state — the sync
   * gate holds the wire, and interceptedRead's server-copy fetch is
   * wire-blocked so local edits stay visible. That state used to look
   * perfectly healthy (status bar said "Connected ✓", files and permissions
   * loaded), which made a paused vault read as a broken one. One sticky,
   * deduped notice names the state and carries the resolve action; the status
   * bar shows a paused label and is click-to-resolve while it lasts.
   */
  private showAccountChangePausedNotice(
    // quick-260820-prn: the blocked vault-change lane parks the folder in the
    // same paused local-only state, but "resolve the account change" would be
    // the wrong instruction there — the account is fine, the folder is holding
    // the previous vault's files. Applied to BOTH branches so the three
    // existing call sites keep their exact text.
    message?: string
  ): void {
    this.hideAccountChangePausedNotice();
    const notice = new Notice("", 0);
    const body = noticeBody(notice);
    if (!body) {
      // No DOM-capable Notice (headless / unit harness): keep the state named
      // with the plain sticky message instead of the actioned body.
      notice.hide?.();
      this.accountChangePausedNotice = new Notice(message ?? this.accountChangeMessage(), 0);
      this.updateStatusBar();
      return;
    }
    body.empty();
    body.appendText(
      message ??
        "VaultGuard: sync is paused — this folder is working locally only. " +
          "Notes and edits stay on this device; nothing uploads or downloads until you resolve the account change."
    );
    const actions = body.createDiv();
    actions.addClass("vaultguard-reload-notice-actions");
    const resolveBtn = actions.createEl("button", { text: "Resolve now" });
    resolveBtn.addEventListener("click", () => {
      this.hideAccountChangePausedNotice();
      this.handlePrimaryProtectionAction();
    });
    this.accountChangePausedNotice = notice;
    this.updateStatusBar();
  }

  private hideAccountChangePausedNotice(): void {
    this.accountChangePausedNotice?.hide?.();
    this.accountChangePausedNotice = null;
  }

  /**
   * "Sync never started" is a state, not an event (quick-260820-mv4).
   *
   * `initializeSyncEngine` bails before `performSync()` and `startSyncTimer()`
   * whenever the initial reconciliation does not complete — a dismissed
   * preview, a long-operation conflict, a protection-gate miss. Nothing
   * re-arms it, so the folder sat permanently un-synced until Obsidian was
   * restarted and `onload` re-entered the path. The user's report was exactly
   * that: "it does not load new files; when I refresh Obsidian it works."
   *
   * The dead end is now loud and self-serving: a sticky notice that names the
   * local-only state and carries the retry that used to require a restart.
   */
  showReconciliationPausedNotice(reason?: string): void {
    this.hideReconciliationPausedNotice();
    const detail = reason ? ` ${reason}` : "";
    const message =
      "VaultGuard Sync: sync has not started for this folder — it is working locally only. " +
      `Notes and edits stay on this device until this folder is reconciled with its server vault.${detail}`;

    const notice = new Notice("", 0);
    const body = noticeBody(notice);
    if (!body) {
      // No DOM-capable Notice (headless / unit harness): keep the state named
      // with the plain sticky message instead of the actioned body.
      notice.hide?.();
      this.reconciliationPausedNotice = new Notice(message, 0);
      this.updateStatusBar();
      return;
    }
    body.empty();
    body.appendText(message);
    const actions = body.createDiv();
    actions.addClass("vaultguard-reload-notice-actions");
    const retryBtn = actions.createEl("button", { text: "Reconcile now" });
    retryBtn.addEventListener("click", () => {
      this.hideReconciliationPausedNotice();
      this.syncDiagnostics.record("initializeSyncEngine.invoke", {
        caller: "reconciliationPausedNotice",
      });
      void this.initializeSyncEngine().catch((err) => {
        this.logError("Sync engine init failed from the reconciliation retry", err);
      });
    });
    this.reconciliationPausedNotice = notice;
    this.updateStatusBar();
  }

  hideReconciliationPausedNotice(): void {
    this.reconciliationPausedNotice?.hide?.();
    this.reconciliationPausedNotice = null;
  }

  /**
   * Sticky, deduped wrong-account notice (quick-260820-ki7). Both
   * wrong-account branches (verify + probe) used to raise bare untracked
   * Notices, which outlived the state they described — the toast still named
   * the previous account after a logout and re-login. Mirrors the
   * accountChangePausedNotice pair.
   */
  private showWrongAccountNotice(message: string = this.wrongAccountMessage()): void {
    this.hideWrongAccountNotice();
    const notice = new Notice("", 0);
    const body = noticeBody(notice);
    if (!body) {
      // No DOM-capable Notice (headless / unit harness): keep the state named
      // with the plain sticky message instead of the actioned body.
      notice.hide?.();
      this.wrongAccountNotice = new Notice(message, 0);
      return;
    }
    body.empty();
    body.appendText(message);
    const actions = body.createDiv();
    actions.addClass("vaultguard-reload-notice-actions");

    // TWO ways out, because this state has two honest causes (nqm follow-up).
    // ki7 §6.4 removed the vault picker from the wrong-account SIDEBAR action
    // because the picker was then a dead end and could auto-bind straight past
    // the takeover boundary (quick-260820-fvo). Both reasons are now gone: a
    // blocked pick delegates to adoptBindingForCurrentAccount, the picker
    // refuses to auto-bind while blocked, and switchServerVault is never
    // silent. So the option comes back — and it leads, because a wrong-account
    // verdict usually means the FOLDER points at the wrong vault, not that the
    // person signed in as the wrong human. Making them log out to fix a vault
    // binding is backwards.
    const vaultBtn = actions.createEl("button", { text: "Connect a different vault" });
    vaultBtn.addEventListener("click", () => {
      this.hideWrongAccountNotice();
      void this.switchServerVault();
    });

    // Same wording as the sidebar's wrong-account primary action
    // (quick-260820-ki7) — two labels for one action would be its own bug.
    const accountBtn = actions.createEl("button", { text: "Log in as a different account" });
    accountBtn.addEventListener("click", () => {
      this.hideWrongAccountNotice();
      this.handlePrimaryProtectionAction();
    });

    this.wrongAccountNotice = notice;
  }

  private hideWrongAccountNotice(): void {
    this.wrongAccountNotice?.hide?.();
    this.wrongAccountNotice = null;
  }

  /**
   * The single LOCAL cleanliness authority for the account-takeover lane
   * (quick-260820-ki7). Auto-takeover destroys anything unsynced, so
   * cleanliness must be POSITIVELY established and default to DIRTY: any
   * uncertainty (load handle absent, flush in flight, an active sync cycle,
   * an unrestored on-disk envelope) reports indeterminate instead of clean.
   * The takeover lane layers a positive server-listing cross-check on top
   * (crossCheckLocalFilesAgainstServerListing) for mutations no local signal
   * can see — files added while Obsidian was closed or before the blocked
   * window began.
   *
   * Deliberately EXCLUDED signals — do not "fix" them back in:
   * - `syncState.pendingChanges`: it increments on SUCCESSFUL immediate
   *   online uploads too (it counts changes-since-last-cycle, not unsynced
   *   work), so it would false-dirty virtually every session.
   * - Any disk-vs-remoteFileState "local-only file" scan: logout clears
   *   remoteFileState AND removes its envelope, so at every cross-account
   *   login the map is empty and the scan would classify EVERY file as
   *   local-only — permanently killing the auto path.
   */
  private async collectUnsyncedLocalChanges(): Promise<{
    clean: boolean;
    items: string[];
    indeterminate: boolean;
  }> {
    let indeterminate = false;

    if (this.offlineQueueLoadPromise) {
      await this.offlineQueueLoadPromise;
    } else {
      // The envelope restore never started (early lifecycle, harness): an
      // empty in-memory queue proves nothing.
      indeterminate = true;
    }
    if (this.offlineQueueFlushPromise) indeterminate = true;
    if (this.syncState.status === "syncing") indeterminate = true;

    const items = new Set<string>();
    for (const op of this.offlineQueue) {
      items.add(this.normalizeVaultPath(op.path));
    }
    for (const path of Object.keys(this.settings.pendingLargeFiles ?? {})) {
      items.add(this.normalizeVaultPath(path));
    }
    // Tombstones are unsynced local DELETES — they would replay under the
    // new identity, so they count as unsynced work here.
    for (const path of Object.keys(this.settings.deletionTombstones ?? {})) {
      items.add(this.normalizeVaultPath(path));
    }
    for (const conflict of this.syncState.conflicts) {
      items.add(this.normalizeVaultPath(conflict.path));
    }
    for (const path of this.blockedStateLocalEdits) {
      items.add(path);
    }

    // A still-present envelope with an EMPTY in-memory queue after the
    // awaited load means ops the restore did not materialize (cipher not
    // ready at load time, or a future-versioned envelope) —
    // unrestored/unrestorable work is dirty.
    try {
      if (
        this.offlineQueue.length === 0 &&
        (await this.app.vault.adapter.exists(this.offlineQueueEnvelopePath()))
      ) {
        indeterminate = true;
      }
    } catch {
      // Cannot prove the envelope absent — uncertainty defaults to dirty.
      indeterminate = true;
    }

    return {
      clean: items.size === 0 && !indeterminate,
      items: [...items],
      indeterminate,
    };
  }

  /**
   * The [Discard and switch] pre-reset step (quick-260820-ki7): actively drop
   * every tracked unsynced-work holder BEFORE the takeover reset, otherwise
   * the "discarded" queued edits would survive the wipe and replay under the
   * new identity once re-verify opens the gate — contradicting the consent
   * copy. `settings.deletionTombstones` are deliberately NOT touched here:
   * the takeover reset itself deletes them (its account-takeover branch).
   * resetLocalAtRestAndResync internals stay untouched by design.
   */
  private async discardUnsyncedLocalChanges(): Promise<void> {
    this.offlineQueue = [];
    // Empty queue => persistOfflineQueue removes the on-disk envelope; it
    // catches internally, and the serialized tail keeps ordering safe against
    // any concurrent scheduled persist.
    await this.enqueueOfflineQueuePersist(() => this.persistOfflineQueue());
    delete this.settings.pendingLargeFiles;
    await this.saveSettings();
    this.syncState.conflicts = [];
    this.blockedStateLocalEdits.clear();
  }

  /**
   * The vault-to-vault SWITCH gate (quick-260820-mv4) — the ki7 takeover gate
   * applied to the other way this folder's local cache stops matching its
   * binding.
   *
   * Re-pointing a folder at a different server vault used to leave the
   * previous vault's files on disk, where reconciliation then classified every
   * one of them as local-only and offered to UPLOAD them into the vault just
   * connected. The cache must be replaced instead, which makes this exactly
   * the takeover problem: prove cleanliness positively, wipe automatically
   * when there is nothing to lose, and ask exactly once when there is.
   *
   * Runs BEFORE any binding mutation, so `previousVaultId` is still the live
   * binding and the server-listing cross-check can prove the vault being LEFT
   * — the only vault that can answer "is this file already safe?".
   *
   * Fail-closed on every axis, same as ki7: `collectUnsyncedLocalChanges`
   * defaults to dirty on any uncertainty, a failed/capped cross-check is
   * dirty, and a headless runtime (no document to consent) declines. A
   * decline CANCELS THE SWITCH rather than landing the paused local-only
   * state — unlike a declined takeover, the existing binding is still
   * completely usable, so there is nothing to pause.
   */
  private async confirmVaultSwitchLocalPurge(
    previousVaultId: string,
    nextVaultName: string,
    // quick-260820-prn. `previousVaultName` used to be read implicitly off
    // `this.settings.serverVaultName` below, which is only correct while this
    // runs PRE-mutation. The blocked adopt lane calls it POST-mutation, where
    // that field already names the NEW vault — the dialog would have told the
    // user the folder is leaving the vault it is joining. The name is now
    // always supplied by the caller, from wherever it is provably right.
    // `bindingAlreadyApplied` selects that lane's copy variant.
    options?: { previousVaultName?: string; bindingAlreadyApplied?: boolean }
  ): Promise<boolean> {
    let changes = await this.collectUnsyncedLocalChanges();
    const crossCheck = await this.crossCheckLocalFilesAgainstServerListing(previousVaultId);
    let clean = changes.clean && crossCheck.ok && crossCheck.unconfirmed.length === 0;

    // Pre-reset TOCTOU re-check (ki7's, verbatim): the cross-check round trips
    // gave an edit time to land. Cheap in-memory signals only — anything new
    // routes to the dialog instead of wiping over it.
    if (
      clean &&
      (this.offlineQueue.length > 0 ||
        this.blockedStateLocalEdits.size > 0 ||
        this.syncState.conflicts.length > 0)
    ) {
      clean = false;
      changes = await this.collectUnsyncedLocalChanges();
    }

    if (clean) return true;

    const consent = await this.confirmDiscardUnsyncedChanges(changes, crossCheck, {
      kind: "vault",
      previousVaultName: options?.previousVaultName || undefined,
      nextVaultName,
      // Spread only when true, so the pre-mutation mv4 call site's argument
      // shape is exactly what it was before this parameter existed.
      ...(options?.bindingAlreadyApplied === true ? { bindingAlreadyApplied: true } : {}),
    });
    if (!consent) return false;

    // Same ordering rule as the takeover: clear the tracked unsynced holders
    // BEFORE the reset, or the "discarded" queued edits survive the wipe and
    // replay into the newly bound vault once the gate opens — contradicting
    // the consent copy. Tombstones are left to the reset's own branch.
    await this.discardUnsyncedLocalChanges();
    return true;
  }

  /**
   * Serialized, coalescing entry point for capsule persistence. Every call —
   * including each fire-and-forget `void this.persistLocalRecoveryCapsule()`
   * site — funnels through localRecoveryCapsuleOpChain, so store rotations can
   * never interleave (see the field's comment for the live ENOENT race this
   * prevents; those call sites are safe by construction now — do NOT
   * restructure them). A run that has not yet STARTED absorbs any number of
   * later callers (it captures their state when it runs); callers arriving
   * while a rotation is EXECUTING share exactly one trailing run. A burst
   * therefore costs at most two rotations (last-write-wins), and every awaited
   * boolean comes from a rotation started at-or-after the caller's call.
   */
  private persistLocalRecoveryCapsule(): Promise<boolean> {
    const queued = this.queuedLocalRecoveryCapsulePersist;
    if (queued) return queued;
    const run = this.localRecoveryCapsuleOpChain.then(() => {
      // clearLocalRecoveryCapsule may have dropped/replaced the slot; only
      // release it when it still points at this run.
      if (this.queuedLocalRecoveryCapsulePersist === run) {
        this.queuedLocalRecoveryCapsulePersist = null;
      }
      return this.persistLocalRecoveryCapsuleNow();
    });
    this.queuedLocalRecoveryCapsulePersist = run;
    // ...Now() never rejects (it logs and returns false), but the shared chain
    // must stay unpoisonable by construction.
    this.localRecoveryCapsuleOpChain = run.catch(() => undefined);
    return run;
  }

  /** Backfill every healthy install without exporting or rotating the LAK. */
  private async persistLocalRecoveryCapsuleNow(): Promise<boolean> {
    if (this.isLocalProjectMemoryModeEnabled()) return false;
    // Some isolated crypto/PIN callers (including embedders and unit
    // harnesses) intentionally exercise these methods before Obsidian has
    // attached an App. Capsule durability is startup integration work and is
    // simply deferred until the real vault adapter exists.
    if (!this.app?.vault?.adapter) return false;
    const status = this.getAtRestStatus();
    // Max-security installs intentionally never initialise the cipher until a
    // successful PIN unlock. They can still be healthy while landed locked,
    // and the already-sealed PIN envelope is exactly what must be backfilled.
    const healthyPinOnlyLockedState =
      this.settings.requirePinOnStartup === true &&
      this.pinLockManager?.isEnrolled() === true &&
      this.ensureAtRestAdapterRuntimeObject().isLocked();
    if (
      status.kind !== "unlocked" &&
      status.kind !== "locked" &&
      !healthyPinOnlyLockedState
    ) {
      return false;
    }
    const adapter = this.app.vault.adapter;
    const pluginId = this.manifest?.id ?? "vaultguard-sync";
    const transparentPath = this.vaultConfigPath("plugins", pluginId, "lak.envelope");
    const pinPath = this.lakPinEnvelopePath();
    const readIfPresent = async (path: string): Promise<string | undefined> => {
      if (!(await adapter.exists(path))) return undefined;
      const value = (await adapter.read(path)).trim();
      return value || undefined;
    };
    const requirePinOnStartup = this.settings.requirePinOnStartup === true;
    const pinEnvelope = await readIfPresent(pinPath);
    const wrappedLak = requirePinOnStartup ? undefined : await readIfPresent(transparentPath);
    if (!wrappedLak && !pinEnvelope) return false;
    const state: LocalRecoveryDeviceState = {
      ...(wrappedLak ? { wrappedLak } : {}),
      ...(pinEnvelope ? { pinEnvelope } : {}),
      ...(this.settings.pinLock?.pepperWrapped
        ? { pinPepperWrapped: this.settings.pinLock.pepperWrapped }
        : {}),
      ...(this.settings.pinLock
        ? {
            pinState: {
              enrolled: this.settings.pinLock.enrolled,
              failedAttempts: this.settings.pinLock.failedAttempts,
              lockedUntil: this.settings.pinLock.lockedUntil,
            },
          }
        : {}),
      requirePinOnStartup,
      pinOnboardingPromptShown: this.settings.pinOnboardingPromptShown,
      ...(this.settings.serverVaultId
        ? {
            binding: {
              serverVaultId: this.settings.serverVaultId,
              serverVaultName: this.settings.serverVaultName,
              serverVaultSlug: this.settings.serverVaultSlug,
              organizationId: this.settings.organizationId || undefined,
              accountUserId: this.session?.userId,
              accountEmail: this.session?.email || undefined,
            },
          }
        : {}),
      connection: {
        orgSlug: this.settings.orgSlug || undefined,
        apiEndpoint: this.settings.apiEndpoint || undefined,
        organizationId: this.settings.organizationId || undefined,
        cognitoUserPoolId: this.settings.cognitoUserPoolId || undefined,
        cognitoClientId: this.settings.cognitoClientId || undefined,
        manualConfig: this.settings.manualConfig,
      },
    };
    try {
      const persisted = await (await this.createLocalRecoveryStore()).persist(state);
      if (persisted.copies.length < 2) {
        this.log("Local recovery capsule persisted with only one durable copy; startup will retry.");
      }
      return persisted.copies.length > 0;
    } catch (error) {
      this.logError("Persisting the local uninstall recovery capsule failed", error);
      return false;
    }
  }

  /**
   * Serialized on the same chain as persist — a purge and a rotation must
   * never interleave. Callers arriving AFTER this clear must never coalesce
   * into a persist queued BEFORE it (the takeover flow's clear → re-persist
   * would otherwise await a pre-clear rotation and end up wiped), so the
   * queued-persist slot is dropped up front; that pre-clear run keeps its own
   * chain position and its awaiters.
   */
  private clearLocalRecoveryCapsule(): Promise<void> {
    this.queuedLocalRecoveryCapsulePersist = null;
    const run = this.localRecoveryCapsuleOpChain.then(() =>
      this.clearLocalRecoveryCapsuleNow(),
    );
    // ...Now() rethrows to its callers by contract; the shared chain still
    // must not be poisoned by that rejection.
    this.localRecoveryCapsuleOpChain = run.catch(() => undefined);
    return run;
  }

  private async clearLocalRecoveryCapsuleNow(): Promise<void> {
    if (!this.app?.vault?.adapter) return;
    try {
      await (await this.createLocalRecoveryStore()).clear();
    } catch (error) {
      this.logError("Clearing the local uninstall recovery capsule failed", error);
      throw error;
    }
  }

  private async maybeOfferFirstRunMigration(): Promise<void> {
    return this.ensureAtRestAdapterRuntimeObject().maybeOfferFirstRunMigration();
  }

  private showAtRestRecoveryBanner(reason: string): void {
    return this.ensureAtRestAdapterRuntimeObject().showAtRestRecoveryBanner(reason);
  }

  private async encryptVaultAtRest(): Promise<void> {
    return this.ensureAtRestAdapterRuntimeObject().encryptVaultAtRest();
  }

  private async decryptVaultAtRest(): Promise<void> {
    return this.ensureAtRestAdapterRuntimeObject().decryptVaultAtRest();
  }

  private async decryptVaultAtRestAndDisableEncryption(): Promise<AtRestDecryptAndDisableResult> {
    const result = await this.ensureAtRestAdapterRuntimeObject().decryptVaultAtRestAndDisableEncryption();
    if (result.failed === 0 && result.remainingCiphertextPaths.length === 0) {
      // The user explicitly chose plaintext/local-only mode. Retaining a sealed
      // LAK or a prior-protection marker after that point would both misclassify
      // a later reinstall and preserve key material the reset contract says is
      // gone.
      await this.clearLocalRecoveryCapsule();
      this.localProtectionBootstrap = { kind: "new" };
      this.localRecoveryNeedsLakValidation = false;
    }
    return result;
  }

  private interceptVaultAdapter(): void {
    return this.ensureAtRestAdapterRuntimeObject().interceptVaultAdapter();
  }

  /** BIN-A preview: pre-decrypt an opened media file into the blob cache. */
  private prewarmAttachmentPreview(path: string): Promise<void> {
    return this.ensureAtRestAdapterRuntimeObject().prewarmResourcePreview(path);
  }

  private restoreVaultAdapter(): void {
    return this.ensureAtRestAdapterRuntimeObject().restoreVaultAdapter();
  }

  private async interceptedRead(path: string): Promise<string> {
    return this.ensureAtRestAdapterRuntimeObject().interceptedRead(path);
  }

  private notifyDeniedLocalWipe(path: string): void {
    return this.ensureAtRestAdapterRuntimeObject().notifyDeniedLocalWipe(path);
  }

  private notifyCloudDecryptFallback(path: string): void {
    return this.ensureAtRestAdapterRuntimeObject().notifyCloudDecryptFallback(path);
  }

  private looksLikeCiphertext(data: string): boolean {
    return this.ensureAtRestAdapterRuntimeObject().looksLikeCiphertext(data);
  }

  private looksLikeCiphertextBytes(data: ArrayBuffer | Uint8Array): boolean {
    return this.ensureAtRestAdapterRuntimeObject().looksLikeCiphertextBytes(data);
  }

  private notifyCorruptedWrite(path: string): void {
    return this.ensureAtRestAdapterRuntimeObject().notifyCorruptedWrite(path);
  }

  private async interceptedWrite(path: string, data: string): Promise<void> {
    return this.ensureAtRestAdapterRuntimeObject().interceptedWrite(path, data);
  }

  private isAtRestExcluded(path: string): boolean {
    return this.ensureAtRestAdapterRuntimeObject().isAtRestExcluded(path);
  }

  private async readPlainFromDisk(path: string): Promise<string> {
    return this.ensureAtRestAdapterRuntimeObject().readPlainFromDisk(path);
  }

  private async waitForCipherInit(timeoutMs: number): Promise<boolean> {
    return this.ensureAtRestAdapterRuntimeObject().waitForCipherInit(timeoutMs);
  }

  private async writePlainToDisk(path: string, data: string): Promise<void> {
    return this.ensureAtRestAdapterRuntimeObject().writePlainToDisk(path, data);
  }

  private async readPlainBinaryFromDisk(path: string): Promise<ArrayBuffer> {
    return this.ensureAtRestAdapterRuntimeObject().readPlainBinaryFromDisk(path);
  }

  private async writePlainBinaryToDisk(path: string, data: ArrayBuffer): Promise<void> {
    return this.ensureAtRestAdapterRuntimeObject().writePlainBinaryToDisk(path, data);
  }

  private shouldDeferDenialWipe(path: string): boolean {
    return this.ensureAtRestAdapterRuntimeObject().shouldDeferDenialWipe(path);
  }

  private async interceptedReadBinary(path: string): Promise<ArrayBuffer> {
    return this.ensureAtRestAdapterRuntimeObject().interceptedReadBinary(path);
  }

  private async interceptedWriteBinary(path: string, data: ArrayBuffer): Promise<void> {
    return this.ensureAtRestAdapterRuntimeObject().interceptedWriteBinary(path, data);
  }

  private ensureAtRestEncryptedInPlace(path: string, remoteDurable = false): Promise<boolean> {
    return this.ensureAtRestAdapterRuntimeObject().ensureAtRestEncryptedInPlace(
      path,
      remoteDurable,
    );
  }

  private encryptExternallyAddedFile(path: string): Promise<void> {
    return this.ensureAtRestAdapterRuntimeObject().encryptExternallyAddedFile(path);
  }

  private async canDeletePath(path: string): Promise<boolean> {
    return this.ensureAtRestAdapterRuntimeObject().canDeletePath(path);
  }

  private async interceptedList(
    path: string
  ): Promise<{ files: string[]; folders: string[] }> {
    return this.ensureAtRestAdapterRuntimeObject().interceptedList(path);
  }

  private async interceptedDelete(path: string): Promise<void> {
    return this.ensureAtRestAdapterRuntimeObject().interceptedDelete(path);
  }

  private async interceptedRename(oldPath: string, newPath: string): Promise<void> {
    return this.ensureAtRestAdapterRuntimeObject().interceptedRename(oldPath, newPath);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Permission System
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Resolves the effective permission level for the current user on a given path.
   * Uses a cache to minimize API calls, with hierarchical path resolution.
   * @param path - The vault-relative path to check
   * @returns The effective permission level
   */
  /**
   * Thin wrapper over `permissionStore.getPermission(path)`. Many call
   * sites in main.ts still reference this method by name; this passthrough
   * preserves the surface area without duplicating cache/walk-up logic
   * (Phase 9). The store owns admin shortcut, walk-up, TTL, concurrent-call
   * dedup, offline fallback, and network-error tolerance.
   */
  private async getEffectivePermission(path: string): Promise<PermissionLevel> {
    return this.permissionStore.getPermission(path);
  }

  private async fetchPermissionLevelFromServer(path: string): Promise<PermissionLevel> {
    if (!this.session) {
      return PermissionLevel.NONE;
    }

    // SD-03-F13: do NOT transmit org-level session roles. The server re-derives
    // roles from the verified identity and ignores body.roles (permissions
    // handler handleCheckPermission); sending the wider org role was a latent
    // risk for any self-hosted fork that trusted body.roles.
    const permissionPath = this.toPermissionPath(path);
    const checks: Array<{ action: "admin" | "write" | "read"; level: PermissionLevel }> = [
      { action: "admin", level: PermissionLevel.ADMIN },
      { action: "write", level: PermissionLevel.WRITE },
      { action: "read", level: PermissionLevel.READ },
    ];

    // Run all three action checks in parallel — they're independent. The
    // previous sequential loop paid 3× round-trip latency on every viewer
    // file open, which manifested as "Failed to open ''" notices during
    // workspace restore on slow links.
    const responses = await Promise.all(
      checks.map((check) =>
        this.apiRequest<{ allowed: boolean }>("POST", this.vaultPath('/permissions/check'), {
          userId: this.session!.userId,
          action: check.action,
          path: permissionPath,
        })
      )
    );

    let hadApiError = false;
    let highestLevel: PermissionLevel = PermissionLevel.NONE;

    for (let i = 0; i < responses.length; i++) {
      const response = responses[i];
      const check = checks[i];

      // Auth/authorization failures are authoritative and must fail closed.
      if (!response.success && (response.error?.statusCode === 401 || response.error?.statusCode === 403)) {
        return PermissionLevel.NONE;
      }

      // Network-level failures should propagate to trigger offline fallback.
      if (!response.success && response.error?.statusCode === 0) {
        throw new Error(response.error.message);
      }

      if (response.success && response.data?.allowed) {
        if (check.level > highestLevel) highestLevel = check.level;
        continue;
      }

      // Track non-auth API errors (500, 404, etc.) so we can fall back gracefully
      if (!response.success) {
        hadApiError = true;
      }
    }

    if (highestLevel > PermissionLevel.NONE) {
      return highestLevel;
    }

    // If non-network API errors prevented a proper check, fail closed.
    if (hadApiError) {
      this.log(`Permission API error for "${path}", denying access until permissions can be verified`);
      return PermissionLevel.NONE;
    }

    return PermissionLevel.NONE;
  }

  private normalizeVaultPath(path: string): string {
    // Defensive against a missing/undefined input (e.g. an unset
    // `app.vault.configDir` in some hosts/tests) — coerce before stripping
    // leading slashes so callers like isPathExcluded never throw.
    return normalizePath(String(path ?? "").replace(/^\/+/, ""));
  }

  /**
   * V1–V4 of the chat mention picker's visibility rule: the non-lease part of
   * the Agent Bridge's `isPathAgentReadable` (`agent-bridge.ts:4222-4239`).
   * Rejects unnormalizable paths, any `..` segment anywhere (even mid-path),
   * vault-root hidden entries, and locally-excluded paths.
   */
  private isMentionPathVisible(path: string): boolean {
    const normalized = this.normalizeVaultPath(path);
    if (!normalized) return false;
    if (
      String(path ?? "")
        .replace(/\\/g, "/")
        .split("/")
        .some((segment) => segment === "..")
    ) {
      return false;
    }
    if (normalized.split("/")[0].startsWith(".")) return false;
    return !this.isPathExcluded(normalized);
  }

  private vaultConfigPath(...parts: string[]): string {
    return normalizePath([this.app.vault.configDir, ...parts].filter(Boolean).join("/"));
  }

  private toPermissionPath(path: string): string {
    return `/${this.normalizeVaultPath(path)}`;
  }

  /**
   * Local-only opt-out matcher. Returns true when the given vault-relative
   * path is covered by an entry in `settings.excludedPaths` — meaning it
   * must never be uploaded, downloaded, or deleted on the server. Excluded
   * paths flow through to the original adapter only, keeping them as
   * local-only files that never touch the sync wire.
   *
   * Patterns are interpreted as either an exact path or a folder prefix.
   * A config-dir workspace file pattern matches that file only. A plugin-dir pattern
   * matches the folder itself plus everything under it.
   */
  isPathExcluded(path: string): boolean {
    const normalized = this.normalizeVaultPath(path);
    if (!normalized) return false;
    const configDir = this.normalizeVaultPath(this.app.vault.configDir);
    if (normalized === configDir || normalized.startsWith(`${configDir}/`)) return true;

    // Hard-exclude every vault-root hidden entry (anything whose first path
    // segment starts with "."). By Obsidian/Unix convention these are system
    // or plugin-state folders, never note content: the config directory (Obsidian's
    // own settings + every community plugin's bundle and data), `.trash/`,
    // `.git/`, and plugin sidecar folders like `.claudian/`, `.smart-env/`,
    // `.kanban/`. Other plugins read and write these directly through the
    // vault adapter; if VaultGuard's interceptor blocks them when the user
    // isn't logged in (or lacks a permission rule covering the path), the
    // host plugin breaks — most visibly, plugin install/activate fails
    // because Obsidian can't load main.js or rewrite community-plugins.json.
    // Cross-device parity for allowed plugins is provided by the server-side
    // pluginAllowlist + per-user manual install, not by syncing bundle bytes.
    const firstSegment = normalized.split("/")[0];
    if (firstSegment.startsWith(".")) {
      return true;
    }

    const local = this.settings.excludedPaths ?? [];
    const server = this.settings.serverExcludedPaths ?? [];
    if (local.length === 0 && server.length === 0) return false;

    for (const raw of [...server, ...local]) {
      const cleaned = raw.trim().replace(/^\/+/, "").replace(/\/+$/, "");
      if (!cleaned) continue;
      if (normalized === cleaned) return true;
      if (normalized.startsWith(cleaned + "/")) return true;
    }
    return false;
  }

  /**
   * Resolves permission from cache by walking up the directory hierarchy.
   * If a parent directory has a cached permission, it cascades to children.
   * @param path - The path to resolve permissions for
   * @returns Cached permission level, or NONE when no cached grant applies
   */
  private resolvePermissionFromCache(path: string): PermissionLevel {
    // Walk up the path hierarchy looking for cached permissions (Phase 9:
    // store-backed). Uses `getCachedPermission` for sync probing — the
    // store's own internal walk-up runs inside async `getPermission`, so
    // the sync delete-probe call sites (interceptedDelete fallbacks)
    // need this explicit walk to stay synchronous.
    const segments = path.split("/");
    for (let i = segments.length; i > 0; i--) {
      const parentPath = segments.slice(0, i).join("/");
      const level = this.permissionStore.getCachedPermission(parentPath);
      if (level !== undefined) return level;
    }

    // Final fallback: the empty-string key acts as the vault root, where
    // the warm-up stores the user's vault-default level (READ for viewers,
    // WRITE for editors, etc.). Without this, any path not explicitly
    // cached fell through to the network even after warm-up.
    const rootLevel = this.permissionStore.getCachedPermission("");
    if (rootLevel !== undefined) return rootLevel;

    return PermissionLevel.NONE;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Sync Engine
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Initializes the sync engine: performs initial sync and starts periodic timer.
   */
  private async initializeSyncEngine(): Promise<void> {
    return this.ensureSyncRuntime().initializeSyncEngine();
  }

  /**
   * Wires Obsidian vault events so create/rename/delete of folders mirrors
   * to the server-side folder marker. Idempotent — only registers once per
   * plugin process. File events are deliberately ignored here because the
   * adapter interceptors already handle them; double-handling would mean
   * two PUT/DELETE round-trips for every direct file op.
   */
  private registerFolderLifecycleListeners(): void {
    registerFolderLifecycleListenersLifecycle(this.createLifecycleEventsContext());
  }

  /**
   * Blocked-window mutation tracker (quick-260820-ki7). While the binding
   * sits in a blocked state (`account-changed` / `wrong-account`) the offline
   * queue catches every interceptor-mediated edit, but external adds/modifies
   * that Obsidian merely OBSERVES (Finder drops, git checkouts) never enter
   * it — encryptExternallyAddedFile deliberately leaves them for sync
   * catch-up, which is dead while blocked. Stamp those paths so the takeover
   * lane's cleanliness check refuses the automatic reset.
   *
   * The "create" handler is gated on `workspace.layoutReady`: the startup
   * index fires "create" for EVERY existing file, and the
   * restart-with-mismatch lane is already blocked BEFORE layoutReady
   * (verify's mismatch branch is a pure local compare — no network), so an
   * ungated stamp would false-dirty the whole vault and kill the auto path on
   * its primary lane (mirrors the encryptExternallyAddedFile gate in onload).
   * That gate structurally excludes files added while Obsidian was CLOSED
   * from this tracker — the takeover lane's server-listing cross-check
   * (crossCheckLocalFilesAgainstServerListing) is what covers that subset.
   * Modify/delete/rename stamps stay unconditional (those events do not flood
   * at startup).
   */
  private registerBlockedWindowMutationTracker(): void {
    const stampBlockedWindowMutation = (path: string): void => {
      if (
        this.vaultBindingAuthorization !== "account-changed" &&
        this.vaultBindingAuthorization !== "wrong-account"
      ) {
        return;
      }
      const normalized = this.normalizeVaultPath(path);
      if (!normalized || this.isPathExcluded(normalized)) return;
      this.blockedStateLocalEdits.add(normalized);
    };
    this.registerEvent(
      this.app.vault.on("create", (file) => {
        if (!this.app.workspace.layoutReady) return;
        stampBlockedWindowMutation(file.path);
      })
    );
    this.registerEvent(
      this.app.vault.on("modify", (file) => stampBlockedWindowMutation(file.path))
    );
    this.registerEvent(
      this.app.vault.on("delete", (file) => stampBlockedWindowMutation(file.path))
    );
    this.registerEvent(
      this.app.vault.on("rename", (file, oldPath) => {
        stampBlockedWindowMutation(oldPath);
        stampBlockedWindowMutation(file.path);
      })
    );
  }

  private handleFolderCreated(path: string): void {
    return this.ensureSyncRuntime().handleFolderCreated(path);
  }

  private handleFolderDeleted(path: string): void {
    if (this.isWipeSuppressedDelete(path, true)) return; // 13-02/HI-01: never DELETE a wiped path on the server
    return this.ensureSyncRuntime().handleFolderDeleted(path);
  }

  private handleFolderRenamed(path: string, oldPath: string): void {
    return this.ensureSyncRuntime().handleFolderRenamed(path, oldPath);
  }

  private handleVaultFileRenamed(path: string, oldPath: string): void {
    return this.ensureSyncRuntime().handleVaultFileRenamed(path, oldPath);
  }

  private handleVaultFileDeleted(path: string): void {
    if (this.isWipeSuppressedDelete(path, false)) return; // 13-02/HI-01: never DELETE a wiped path on the server
    return this.ensureSyncRuntime().handleVaultFileDeleted(path);
  }

  /**
   * True when a `vault.on('delete')` for `path` is a stale artifact of the local
   * at-rest wipe (the file was raw-removed during a reset) rather than a genuine
   * user delete — so it must NOT propagate a server DELETE. Two layers, so a
   * wiped path is safe REGARDLESS of watcher timing:
   *
   *   1. `resettingLocalCache` — the global INSTANCE-LOCAL flag, up only across
   *      this instance's own reset window. Covers the common fast-watcher case
   *      (events drain in-window).
   *   2. The CROSS-INSTANCE wipe-suppression registry (SD-07-F4,
   *      `./wipe-suppression-registry`) — the path-scoped set that OUTLIVES both
   *      that window (HI-01) and THIS PLUGIN INSTANCE. It is `globalThis`-scoped
   *      and memory-only, so it survives a hot reload: a wipe orphaned mid-flight
   *      by a plugin reload keeps registering its paths, and the REPLACEMENT
   *      instance reads them here instead of mistaking the zombie's late watcher
   *      deletes for genuine user deletes. A wiped path stays registered until
   *      it exists again.
   *
   * For a folder delete we ALSO suppress when the folder still CONTAINS a
   * wiped-awaiting-repull descendant: a folder emptied by the wipe and removed
   * late by Obsidian would otherwise prefix-DELETE its (server-authoritative)
   * children. Once reconcile re-pulls those children their entries self-clear,
   * and a later user delete of the re-created folder propagates normally. That
   * rule moved into the registry — it did not change.
   */
  private isWipeSuppressedDelete(path: string, isFolder: boolean): boolean {
    if (this.resettingLocalCache) return true;
    return isPathWipeSuppressed(
      this.wipeSuppressionVaultKey(),
      this.normalizeVaultPath(path),
      isFolder,
    );
  }

  /**
   * Lazily memoized registry key for this vault (SD-07-F4). `this.app` is set by
   * the `Plugin` constructor before `onload`, so the first call always sees a
   * real app.
   */
  private wipeSuppressionVaultKey(): string {
    if (this.wipeSuppressionVaultKeyCache === null) {
      this.wipeSuppressionVaultKeyCache = deriveWipeSuppressionVaultKey(this.app);
    }
    return this.wipeSuppressionVaultKeyCache;
  }

  /**
   * Register one raw-removed path in the cross-instance suppression registry and
   * beat the reset lease (SD-07-F4). Called by the wipe the instant each remove
   * succeeds — progress IS the heartbeat, so no timer is needed and the beat can
   * never outlive the work it measures.
   */
  private recordWipedPathAwaitingRepull(path: string): void {
    const key = this.wipeSuppressionVaultKey();
    recordWipedPath(key, this.normalizeVaultPath(path));
    if (this.atRestResetLeaseOwnerId) {
      heartbeatResetLease(key, this.atRestResetLeaseOwnerId);
    }
  }

  /**
   * A path re-appeared on disk (reconcile re-pulled it, or the user created a new
   * file there) — so stop treating a future delete of it as a wipe artifact. Any
   * later delete of this path is now a genuine user action and must propagate.
   * This is the self-cleaning half of the HI-01 suppression: an entry lives
   * exactly until its path is back, never on a fixed timer. Wired to every
   * `vault.on('create')` (see `onload`); a no-op unless a reset just ran.
   */
  private clearWipeSuppressionForRecreatedPath(path: string): void {
    clearWipedPath(this.wipeSuppressionVaultKey(), this.normalizeVaultPath(path));
  }

  /** True while `resetLocalAtRestAndResync()` is wiping the local VG1 cache. */
  isResettingLocalCache(): boolean {
    return this.resettingLocalCache;
  }

  /**
   * True from the moment a local at-rest reset commits (past the guards) until
   * its `finally` — the reentrancy latch (CR-01) that serializes the recovery
   * doors. Read by the doors (LO-02) to refuse opening a second reset flow, and
   * by the engine itself to refuse a second concurrent entry.
   */
  isAtRestResetInFlight(): boolean {
    return this.atRestResetInFlight;
  }

  /**
   * Flip the local-cache-reset suppression flag. Set true before the raw-remove
   * wipe (so the vault delete listeners no-op) and false in the reset's `finally`
   * so normal delete propagation resumes even if the re-pull throws.
   */
  setResettingLocalCache(v: boolean): void {
    this.resettingLocalCache = v;
  }

  /**
   * Best-effort server-side rename of a single file. Idempotent so it can
   * fire alongside `interceptedRename` without duplicate side-effects.
   * Reads the renamed local file's content and PUTs it to the new key,
   * then DELETEs the old key.
   */
  private async syncFileRenameToServer(oldPath: string, newPath: string): Promise<void> {
    return this.ensureSyncRuntime().syncFileRenameToServer(oldPath, newPath);
  }

  /**
   * Best-effort server-side DELETE for a single file. Idempotent — duplicates
   * the work of `interceptedDelete` for direct file removals, but is the
   * only path that fires for child files of a deleted folder.
   */
  private async syncFileDeleteToServer(path: string): Promise<void> {
    return this.ensureSyncRuntime().syncFileDeleteToServer(path);
  }

  /**
   * First-sync reconciliation between this local Obsidian folder and the
   * just-bound server vault.
   *
   * The sync engine's ordinary delta loop assumes both sides have already
   * agreed on what files exist; on a fresh bind they have not. This routine
   * fills that gap:
   *
   *   1. Walks every local file via Obsidian's vault API and SHA-256s the
   *      content (the same hash the write API stores).
   *   2. Asks the server for its full file inventory (lastSyncTimestamp
   *      = epoch, no client checksums, so the server returns every file as
   *      "created"). We deliberately do NOT send our local checksums — the
   *      server interprets unknown client paths as "deleted", which would
   *      cause it to instruct us to nuke every local-only file.
   *   3. Bucketizes paths into server-only (download), local-only (upload),
   *      and both-exist. For both-exist we download + decrypt the server
   *      copy and compare hashes — the server's own checksum is the S3 ETag
   *      of the encrypted blob, so it isn't usable for plaintext equality.
   *   4. Shows a preview modal so the user can pick a conflict strategy and
   *      cancel before any disk or network writes happen.
   *   5. Applies the plan: downloads, uploads, conflict resolution.
   *   6. Persists `bindingReconciledVaultId` so this never runs again for
   *      the same binding (until the user re-binds to a different vault).
   *
   * Returns true if reconciliation completed (or there was nothing to do)
   * and the regular sync engine may proceed; false if the user cancelled.
   */
  private async performInitialReconciliation(): Promise<boolean> {
    return this.ensureSyncRuntime().performInitialReconciliation();
  }

  private askReconciliationPlan(plan: ReconciliationPlan): Promise<ReconciliationDecision> {
    // DOWNLOAD-ONLY plans apply without asking (quick-260820-mv4). The modal
    // exists to get consent for the two outcomes a user can regret — uploading
    // local-only files into a server vault, and resolving conflicts — and when
    // neither is present there is no question to ask: nothing on this device
    // can be lost, the plan only adds server files this account may already
    // read. This is what keeps the "auto when clean" promise intact after a
    // takeover or vault-switch reset, whose wipe leaves exactly this shape
    // (empty local side, everything server-only) and used to surface a
    // pointless "Apply plan ↓N" dialog at the end of an automatic flow.
    if (plan.localOnly.length === 0 && plan.conflicts.length === 0) {
      this.log(
        `Reconciliation: download-only plan (${plan.serverOnly.length} server file(s)) — applying without a prompt.`
      );
      return Promise.resolve({
        proceed: true,
        conflictStrategy: this.settings.defaultConflictResolution,
      });
    }

    return new Promise<ReconciliationDecision>((resolve) => {
      const modal = new BindingReconciliationModal(
        this.app,
        plan,
        this.settings.defaultConflictResolution,
        (decision) => resolve(decision)
      );
      modal.open();
    });
  }

  /**
   * Uploads a local-only file to the server vault during reconciliation.
   * Returns "uploaded" on success, a "skipped-*" outcome when the upload could
   * not proceed (no write permission / no key lease), and throws on any other
   * failure so the caller can count it accurately. SD-06-F4: a skipped
   * local-only file always stays on disk — no caller may treat any outcome as
   * licence to delete it.
   */
  private async uploadReconciledFile(
    path: string,
    content: string,
    // SD-06-F1 / DECISION 7: `intent` is required by type and forwarded
    // verbatim; the runtime supplies the `{kind:"unknown"}` fallback.
    options: { intent: MutationIntent; noWriteNotice?: string }
  ): Promise<
    | "uploaded"
    | "skipped-no-lease"
    | "skipped-no-permission"
    | "skipped-create-conflict"
  > {
    return this.ensureSyncRuntime().uploadReconciledFile(path, content, options);
  }

  /**
   * Walks the local Obsidian folder and uploads any files that don't exist on
   * the server vault yet. Used by `performSync` to self-heal vaults whose
   * initial reconciliation didn't fully land (silent 403s, network drops,
   * crashed app, etc.).
   *
   * Uses `lastSyncTimestamp = epoch` against `/files/sync` to fetch the full
   * server inventory in a single call — same shape `performInitialReconciliation`
   * relies on.
   */
  private async uploadLocalOnlyFiles(): Promise<{
    uploadedFiles: number;
    uploadedFolders: number;
    heldNoPermissionFiles: number;
    skippedFiles: number;
    failedFiles: number;
    failedFolders: number;
  } | null> {
    return this.ensureSyncRuntime().uploadLocalOnlyFiles();
  }

  /**
   * Walks the full server inventory and repairs anything missing locally.
   * Ordinary delta sync only sees objects newer than `lastSyncTimestamp`; if
   * an earlier download failed because its parent folder was missing, future
   * Sync Now runs can otherwise report "already in sync" while the local vault
   * still lacks older server files.
   */
  private async repairMissingRemoteItems(): Promise<{
    downloadedFiles: number;
    downloadedFolders: number;
    failedFiles: number;
    failedFolders: number;
  } | null> {
    return this.ensureSyncRuntime().repairMissingRemoteItems();
  }

  /**
   * Walks every TFolder under the Obsidian root and returns their normalised
   * vault-relative paths (no leading slash, root excluded). Used to decide
   * which folder markers to plant on the server.
   */
  private collectLocalFolderPaths(): string[] {
    const paths: string[] = [];
    const root = this.app.vault.getRoot();
    const visit = (folder: TFolder): void => {
      for (const child of folder.children) {
        if (child instanceof TFolder) {
          paths.push(this.normalizeVaultPath(child.path));
          visit(child);
        }
      }
    };
    visit(root);
    return paths;
  }

  private parentFolderPathsFor(path: string): string[] {
    return this.ensureSyncRuntime().parentFolderPathsFor(path);
  }

  private async localPathExists(path: string): Promise<boolean> {
    const normalized = this.normalizeVaultPath(path);
    if (!normalized) return true;

    try {
      return await this.app.vault.adapter.exists(normalized);
    } catch {
      return this.app.vault.getAbstractFileByPath(normalized) !== null;
    }
  }

  private async ensureLocalFolderPath(folderPath: string): Promise<boolean> {
    const normalized = this.normalizeVaultPath(folderPath);
    if (!normalized) return false;

    const segments = normalized.split("/").filter(Boolean);
    let current = "";
    let createdTarget = false;

    for (const segment of segments) {
      current = current ? `${current}/${segment}` : segment;
      if (await this.localPathExists(current)) continue;

      try {
        await this.app.vault.createFolder(current);
      } catch (err) {
        if (!(await this.localPathExists(current))) {
          throw err;
        }
      }

      if (current === normalized) {
        createdTarget = true;
      }
    }

    return createdTarget;
  }

  private async ensureParentFoldersForPath(path: string): Promise<void> {
    for (const folderPath of this.parentFolderPathsFor(path)) {
      await this.ensureLocalFolderPath(folderPath);
    }
  }

  private async writeLocalFileFromRemote(path: string, content: string): Promise<void> {
    return this.ensureSyncRuntime().writeLocalFileFromRemote(path, content);
  }

  /** True if `path` (no leading slash) ends in the folder-marker basename. */
  private isFolderMarkerPath(path: string): boolean {
    return this.ensureSyncRuntime().isFolderMarkerPath(path);
  }

  /** Strips the marker basename to recover the parent folder's vault-relative path. */
  private folderPathFromMarkerPath(markerPath: string): string {
    return this.ensureSyncRuntime().folderPathFromMarkerPath(markerPath);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Deletion tombstones (path-only, persisted)
  //
  // A tombstone records that THIS client initiated a local delete of a path so
  // the server-side DELETE can be re-attempted across restarts / transient
  // offline windows, and so initial reconciliation never resurrects a
  // locally-deleted file. SECURITY: tombstones are path → ISO timestamp only.
  // The in-memory offlineQueue (whose `write` ops carry plaintext content in
  // `op.data`) is NEVER persisted; only this path map rides settings → saveData.
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Record a tombstone for a locally-deleted path. No-ops for empty, excluded,
   * or folder-marker paths (those never reach the server, so they must never be
   * tombstoned or retried). Persists fire-and-forget.
   */
  private recordDeletionTombstone(path: string): void {
    return this.ensureSyncRuntime().recordDeletionTombstone(path);
  }

  /**
   * Clear a tombstone once the server confirms the delete (success or 404 =
   * already-gone), or rejects it permanently (401/403). No-op if absent.
   */
  private clearDeletionTombstone(path: string): void {
    return this.ensureSyncRuntime().clearDeletionTombstone(path);
  }

  /** True if a tombstone exists for the given (normalized) path. */
  private isPathTombstoned(path: string): boolean {
    return this.ensureSyncRuntime().isPathTombstoned(path);
  }

  /**
   * Drop tombstones older than the 30-day retention window (and any malformed /
   * unparseable timestamps). Called once at the end of loadSettings; does NOT
   * save — the next normal save persists the pruned set.
   */
  private pruneDeletionTombstones(): void {
    return this.ensureSyncRuntime().pruneDeletionTombstones();
  }

  /**
   * Re-attempt any outstanding tombstoned deletes against the server. Wired
   * into performSync Phase 1 (after the offline-queue flush). A server DELETE
   * needs no key lease; gating it with the existing flush keeps one
   * well-understood entry point. Success / 404 clears the tombstone; a
   * transient (statusCode 0) failure marks offline and stops (retry next
   * online); 401/403 clears it (the server decided).
   */
  private async retryOutstandingDeletions(): Promise<void> {
    return this.ensureSyncRuntime().retryOutstandingDeletions();
  }

  /**
   * Layer 3 reconciliation guard: issue a server-side DELETE for a tombstoned
   * serverOnly path (so a re-bind does not resurrect a locally-deleted file)
   * and clear the tombstone on success/404. On other failures the tombstone is
   * left in place to retry via retryOutstandingDeletions. Returns true on a
   * settled delete (the caller should skip downloading/placeholdering the path).
   * `normalized` must be a vault-relative path with no leading slash.
   */
  private async deleteTombstonedServerPath(normalized: string): Promise<boolean> {
    return this.ensureSyncRuntime().deleteTombstonedServerPath(normalized);
  }

  /**
   * Composes the marker file path the plugin writes to keep `folderPath`
   * alive on the server. Always normalised, never with a leading slash.
   * Throws if asked for the root marker — root is implicit and never marked.
   */
  private folderMarkerPath(folderPath: string): string {
    return this.ensureSyncRuntime().folderMarkerPath(folderPath);
  }

  /**
   * Builds the path manifest sent on `/files/sync` so the server can detect
   * deletions. Without this, the server's deletion-detection loop iterates an
   * empty object and never returns `action: "deleted"` deltas, so files
   * removed by another peer are never propagated to this client.
   *
   * Values are empty strings on purpose: the server uses the keys to diff
   * against its S3 listing, and the empty string is falsy so its checksum
   * mismatch branch is skipped — we don't need a real ETag here, just
   * presence.
   */
  private buildLocalSyncManifest(): Record<string, string> {
    return this.ensureSyncRuntime().buildLocalSyncManifest({
      filePaths: this.app.vault.getFiles().map((file) => file.path),
      folderPaths: this.collectLocalFolderPaths(),
    });
  }

  /**
   * Uploads a zero-byte folder marker for `folderPath`. Returns true when the
   * server accepted it, false when the user lacks write permission for that
   * path. Network failures throw and are caught by the caller.
   */
  private async uploadFolderMarker(folderPath: string): Promise<boolean> {
    return this.ensureSyncRuntime().uploadFolderMarker(folderPath);
  }

  /**
   * Removes the folder marker for `folderPath`. Silently ignores 404s — the
   * marker may have never been planted, which is harmless.
   */
  private async deleteFolderMarker(folderPath: string): Promise<void> {
    return this.ensureSyncRuntime().deleteFolderMarker(folderPath);
  }

  /**
   * Defense-in-depth folder delete: enumerate every server object under the
   * deleted folder's prefix and remove each one, then drop the folder marker.
   *
   * The per-child `vault.on('delete')` listener is the primary propagation
   * path, but it is event-driven and was historically coupled to a sync-init
   * step that did not always run — leaving children orphaned (live in S3) so
   * they re-downloaded on the next pull. This routine closes that gap and also
   * cleans up children that were already orphaned by an earlier missed event.
   *
   * Enumeration reuses `POST /files/sync` with a `prefix` (an epoch
   * lastSyncTimestamp + empty fileChecksums makes the server return every
   * object under the prefix as a delta). Each non-marker child is removed via
   * `syncFileDeleteToServer`, which carries the full DELETE + tombstone +
   * offline-retry semantics (so a transient failure is retried later rather
   * than lost). Marker deltas (this folder's and any sub-folders') are removed
   * via `deleteFolderMarker`. Honors vault-scoping (`vaultPath`/`apiRequest` →
   * `requestUrl`), `isPathExcluded`, and `isFolderMarkerPath`.
   */
  private async deleteFolderContentsOnServer(folderPath: string): Promise<void> {
    return this.ensureSyncRuntime().deleteFolderContentsOnServer(folderPath);
  }

  /**
   * Resolves a both-exist conflict according to the chosen strategy.
   * Reused for first-bind reconciliation; deliberately narrower than the
   * full handleConflict() flow because the user has already picked a
   * strategy in the preview modal.
   */
  private async resolveReconciliationConflict(
    path: string,
    strategy: ConflictResolutionStrategy,
    localManifest: Map<string, LocalManifestEntry>,
    prefetchedResponse?: ApiResponse<RemoteFileContentResponse>,
  ): Promise<void> {
    return prefetchedResponse === undefined
      ? this.ensureSyncRuntime().resolveReconciliationConflict(path, strategy, localManifest)
      : this.ensureSyncRuntime().resolveReconciliationConflict(
          path,
          strategy,
          localManifest,
          prefetchedResponse,
        );
  }

  /**
   * Surfaces auth/sync/binding state as a long-lived Notice. Used by the
   * "Status" command so a user can verify the plugin actually reloaded the
   * freshly-built `main.js` (the SYNC_FEATURE_REVISION will tick) and so they
   * can see at a glance why a sync might be silently no-op'ing.
   */
  private showStatusNotice(): void {
    const lines: string[] = [
      `VaultGuard v${this.manifest.version} (sync-rev ${SYNC_FEATURE_REVISION})`,
    ];
    lines.push(
      this.session
        ? `Logged in as ${this.session.email ?? this.session.userId}`
        : "Not logged in"
    );
    lines.push(`Connection: ${this.connectionState.status}`);
    lines.push(`Key lease: ${this.keyLease ? "present" : "missing"}`);
    lines.push(
      this.settings.serverVaultId
        ? `Vault: ${this.settings.serverVaultName || this.settings.serverVaultId}`
        : "Vault: not bound"
    );
    lines.push(
      `Sync: ${this.syncState.status}${
        this.syncState.lastSync ? ` · last ${new Date(this.syncState.lastSync).toLocaleTimeString()}` : ""
      }`
    );
    if (this.syncState.lastError) {
      lines.push(`Last error: ${this.syncState.lastError}`);
    }
    lines.push(`Pending offline ops: ${this.offlineQueue.length}`);
    new Notice(lines.join("\n"), 12000);
  }

  /**
   * Dev-only active connection diagnostic. The "Connection lost" toast only
   * tells the user an online→offline transition happened; it never says why,
   * because setConnectionStatus("offline") is called from ~6 sites without
   * recording a reason. This re-runs the cheapest authenticated probe
   * (GET /vaults) using a RAW requestUrl — deliberately NOT apiRequest, which
   * would itself flip connection status and hide the real result — then
   * classifies the outcome into a plain-language verdict (unreachable / auth
   * rejected / stale-flag / server error). Secret-free: only booleans, counts,
   * IDs, status codes, and error messages are ever emitted.
   */
  private async runConnectionDiagnostics(): Promise<void> {
    // Dev-only. The early return collapses to `if (true) return;` under the
    // production NODE_ENV define, so esbuild DCE drops the whole body (and its
    // verdict strings) from the released bundle — the command that calls this
    // is itself stripped, so this method is never reachable in prod anyway.
    if (process.env.NODE_ENV === "production") return;

    const lines: string[] = [
      `VaultGuard v${this.manifest.version} — connection diagnostics`,
    ];

    const configuredBase = normalizeVaultGuardApiBaseUrl(
      this.getEffectiveConfig().apiEndpoint
    );
    const hostOf = (urlStr: string): string => {
      try {
        return new URL(urlStr).host;
      } catch {
        return urlStr || "(none)";
      }
    };

    lines.push(`Connection status: ${this.connectionState.status}`);
    lines.push(`Failed attempts: ${this.connectionState.failedAttempts}`);
    lines.push(`Next retry at: ${this.connectionState.nextRetryAt ?? "—"}`);
    lines.push(`Last connected: ${this.connectionState.lastConnected ?? "—"}`);
    lines.push(`Last latency: ${this.connectionState.latencyMs ?? "—"}ms`);
    lines.push(`Session present: ${this.session ? "yes" : "no"}`);
    lines.push(`Server vault bound: ${this.settings.serverVaultId ? "yes" : "no"}`);
    lines.push(`Configured API host: ${hostOf(configuredBase)}`);
    lines.push(
      `Resolved API endpoint: ${this.resolvedApiEndpoint ?? "(not yet resolved)"}`
    );

    if (!this.session) {
      lines.push(
        "Verdict: No session — offline is expected (logged out). Log in first."
      );
      this.emitConnectionDiagnostics(lines);
      return;
    }

    if (this.isSessionTokenExpiring(this.session)) {
      lines.push(
        "WARNING: session token is expiring/expired — a refresh is needed (this alone can flip offline)."
      );
    }

    // Live raw probe. Bypasses apiRequest on purpose so it does not call
    // setConnectionStatus and mask whatever is actually happening right now.
    let base = "";
    try {
      base = await this.getResolvedApiEndpoint(this.session.idToken);
    } catch (err) {
      lines.push(
        `Verdict: ENDPOINT RESOLUTION FAILED — ${(err as Error)?.name ?? "Error"}: ${(err as Error)?.message ?? String(err)}.`
      );
      this.emitConnectionDiagnostics(lines);
      return;
    }

    const url = `${base}/vaults`;
    const headers: Record<string, string> = {};
    if (this.session.idToken) {
      headers["Authorization"] = this.session.idToken;
    }
    // SD-02-F1: the THIRD header-attach site, deliberately NOT routed through
    // `resolveRequestSessionId()`. This is the connection-diagnostics probe: it is
    // already guarded by an early return when `this.session` is absent (above), so a
    // restore candidate could never apply here, and the line it prints is meant to
    // report the LIVE-SESSION header state. Resolving a candidate here would make
    // "Session header sent: yes" ambiguous for the user reading the diagnostic.
    const sessionHeaderSent = !!this.session.sessionId;
    if (sessionHeaderSent) {
      headers["X-VaultGuard-Session-Id"] = this.session.sessionId;
    }
    lines.push(`Session header sent: ${sessionHeaderSent ? "yes" : "no"}`);

    const startedAt = Date.now();
    try {
      const response = await this.requestWithTimeout(
        requestUrl({ url, method: "GET", headers, throw: false })
      );
      const latency = Date.now() - startedAt;
      const status = response.status;
      lines.push(`Probe: GET ${url} → ${status} (${latency}ms)`);

      if (status === 0) {
        lines.push(
          `Verdict: BACKEND UNREACHABLE — network/DNS/TLS failure (${this.describeNetworkFailureResponse(response)}). Check internet and that ${hostOf(base)} resolves.`
        );
      } else if (status === 401 || status === 403) {
        lines.push(
          `Verdict: AUTH REJECTED (HTTP ${status}) — session/token expired or revoked. Log out and back in.`
        );
      } else if (status >= 200 && status < 300) {
        lines.push(
          this.connectionState.status === "online"
            ? `Verdict: BACKEND REACHABLE & AUTHORIZED (HTTP ${status}, ${latency}ms) — consistent with the online status. All good.`
            : `Verdict: BACKEND REACHABLE & AUTHORIZED (HTTP ${status}, ${latency}ms) — the "${this.connectionState.status}" flag is STALE. This was a transient blip; it should self-heal on the next retry. You can also run reconnectNow.`
        );
      } else if (status >= 500) {
        lines.push(
          `Verdict: BACKEND ERRORING (HTTP ${status}) — server-side issue, not your network.`
        );
      } else {
        lines.push(`Verdict: Unexpected HTTP ${status}.`);
      }
    } catch (err) {
      const latency = Date.now() - startedAt;
      const errName = (err as Error)?.name ?? "Error";
      const errMsg = (err as Error)?.message ?? String(err);
      lines.push(`Probe: GET ${url} → threw (${latency}ms)`);
      lines.push(
        `Verdict: BACKEND UNREACHABLE — network/DNS/TLS failure (${errName}: ${errMsg}). Check internet and that ${hostOf(base)} resolves.`
      );
    }

    this.emitConnectionDiagnostics(lines);
  }

  /**
   * Shared output sink for runConnectionDiagnostics: console.log (regardless of
   * debugLogging, like sync-diagnostics), a best-effort clipboard copy, and a
   * persistent Notice (0 = no auto-dismiss) so the verdict can be read/copied.
   */
  private async emitConnectionDiagnostics(lines: string[]): Promise<void> {
    if (process.env.NODE_ENV === "production") return;

    const report = lines.join("\n");
    console.log(`${LOG_PREFIX} ${report}`);
    try {
      if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(report);
      }
    } catch (err) {
      this.logError("Connection diagnostics: clipboard copy failed", err);
    }
    new Notice(report, 0);
  }

  /**
   * Wires window focus and document visibility events to trigger an
   * immediate sync when the user comes back to Obsidian. With pure
   * polling, multi-user changes only land on the next interval (10 s in
   * realtime mode, 60 s+ in periodic) — that's a long time to stare at
   * stale state. Debounced to avoid hammering the server when the OS
   * fires multiple focus events for one Cmd-Tab.
   */
  private registerFocusSyncHandlers(): void {
    registerFocusSyncHandlersLifecycle(this.createLifecycleEventsContext());
  }

  private handleFocusSyncTrigger(): void {
    if (!this.session || !this.settings.serverVaultId) return;
    // Never sync while the vault is locked: the LAK is evicted, so a pulled
    // change would fail-closed in writePlainToDisk (mobile "refusing to write …
    // local at-rest encryption is unavailable"). exitLockState re-pulls on
    // unlock. performSync has its own backstop, but bail before rewarm too.
    if (this.isVaultLocked) return;
    if (this.syncState.status === "syncing") return;
    const now = Date.now();
    if (now - this.lastFocusSyncAt < 3000) return;
    this.lastFocusSyncAt = now;
    void this.performSync().catch((err) =>
      this.logError("Focus-triggered sync failed", err)
    );
    // Wave 2 issue D (1.0.31): self-heal the permission cache on
    // focus. Catches the case where the initial warm-up ran while
    // tokens were still being refreshed (Fix 1 patches the
    // post-refresh side; this catches the longer-tail "Obsidian was
    // backgrounded for an hour, come back to find a stale cache"
    // case). Fires only if the store needs it — `warmed` < 5 min
    // ago is a no-op.
    this.maybeRewarmOnFocus();
  }

  private handleBrowserOnline(): void {
    this.log("Browser network online event received; probing VaultGuard API.");
    if (!this.session) {
      this.resumeSyncLoop("network online");
      return;
    }

    void this.attemptReconnection()
      .then(() => {
        if (this.isOnline()) {
          this.resumeSyncLoop("network online");
        }
      })
      .catch((err) => {
        this.logError("Network-online reconnection probe failed", err);
      });
  }

  private handleBrowserOffline(): void {
    this.setConnectionStatus("offline", { scheduleRetry: false });
    this.pauseSyncLoop("network offline");
  }

  /**
   * Removes every server-side file/folder marker whose path is currently
   * covered by `settings.excludedPaths`. Used to clean up files that were
   * uploaded before the user added the corresponding exclusion — without
   * this, members on other devices would keep pulling the file back down
   * indefinitely.
   *
   * Returns counts so the caller can show a Notice. Throws on hard failures
   * (auth, network) so the caller can react appropriately.
   */
  async purgeExcludedFromServer(): Promise<{
    matched: number;
    deleted: number;
    failed: number;
  }> {
    if (this.isLocalProjectMemoryModeEnabled()) {
      throw new Error("Server purge is disabled in Local Project Memory Mode.");
    }
    if (!this.session || !this.settings.serverVaultId) {
      throw new Error("Not connected to a server vault.");
    }
    if (!this.isOnline()) {
      throw new Error("VaultGuard Sync is offline — connect and try again.");
    }
    const patterns = this.settings.excludedPaths ?? [];
    if (patterns.length === 0) {
      return { matched: 0, deleted: 0, failed: 0 };
    }

    const inventory = await this.apiRequest<{
      deltas: Array<{ path: string; action: string }>;
    }>("POST", this.vaultPath("/files/sync"), {
      lastSyncTimestamp: new Date(0).toISOString(),
      fileChecksums: {},
    });

    if (!inventory.success || !inventory.data) {
      throw new Error(inventory.error?.message ?? "Failed to fetch server inventory.");
    }

    const targets: string[] = [];
    for (const delta of inventory.data.deltas) {
      if (delta.action === "deleted") continue;
      const normalized = this.normalizeVaultPath(delta.path);
      if (!normalized) continue;
      if (this.isPathExcluded(normalized)) {
        targets.push(normalized);
      }
    }

    let deleted = 0;
    let failed = 0;
    for (const path of targets) {
      try {
        const response = await this.apiRequest(
          "DELETE",
          this.vaultPath(`/files/${encodeURIComponent(path)}`)
        );
        if (response.success || response.error?.statusCode === 404) {
          deleted += 1;
          this.permissionStore.emit("changed", { path });
        } else {
          failed += 1;
          this.logError(`Purge: DELETE "${path}" failed`, new Error(response.error?.message ?? "unknown"));
        }
      } catch (err) {
        failed += 1;
        this.logError(`Purge: DELETE "${path}" threw`, err);
      }
    }

    await this.emitAuditEvent("excluded.purge", "", {
      matched: targets.length,
      deleted,
      failed,
    });

    return { matched: targets.length, deleted, failed };
  }

  /**
   * Performs a full bidirectional sync with the server.
   * Uploads pending local changes and downloads remote updates.
   *
   * @param options.userInitiated  When true, surface progress + skip reasons
   *   as Notices instead of silent log lines. The user clicked "Sync Now"
   *   and expects to see something happen.
   * @param options.forceCatchup   When true, run the local and remote repair
   *   passes even if they already ran in this process. Sync Now defaults this
   *   to true so subsequent clicks pick up stranded items instead of becoming
   *   no-ops after the first run.
   */
  async performSync(options: { userInitiated?: boolean; forceCatchup?: boolean } = {}): Promise<void> {
    return this.ensureSyncRuntime().performSync(options);
  }

  private async applyRemoteDeletion(
    normalizedPath: string,
    inferred: boolean
  ): Promise<void> {
    return this.ensureSyncRuntime().applyRemoteDeletion(normalizedPath, inferred);
  }

  /**
   * Applies a remote file change to the local vault.
   * @param metadata - The remote file metadata and change information
   */
  private async applyRemoteChange(
    metadata: Pick<FileMetadata, "path" | "size">,
    prefetchedResponse?: ApiResponse<RemoteFileContentResponse>,
  ): Promise<void> {
    const runtime = this.ensureSyncRuntime();
    return prefetchedResponse === undefined
      ? runtime.applyRemoteChange(metadata)
      : runtime.applyRemoteChange(metadata, prefetchedResponse);
  }

  /**
   * Handles a sync conflict according to the configured resolution strategy.
   * @param conflict - The detected sync conflict
   */
  private async handleConflict(conflict: SyncConflict): Promise<void> {
    return this.ensureSyncRuntime().handleConflict(conflict);
  }

  private getRemoteFileState(path: string): RemoteFileStateEntry | null {
    return this.remoteFileState.get(this.normalizeVaultPath(path));
  }

  private getExpectedVersionId(path: string): string | undefined {
    return this.remoteFileState.getExpectedVersionId(this.normalizeVaultPath(path));
  }

  /**
   * SD-06-F1: the non-lossy sibling of getExpectedVersionId, normalized the
   * same way so both accessors read the same store entry for the same path.
   */
  private resolveMutationIntent(path: string): MutationIntent {
    return this.remoteFileState.resolveMutationIntent(this.normalizeVaultPath(path));
  }

  private recordRemoteFilePresent(
    path: string,
    update: RemoteFileStateUpdate = {}
  ): void {
    this.remoteFileState.recordPresent(this.normalizeVaultPath(path), update);
    this.scheduleRemoteFileStatePersist();
  }

  private recordRemoteFileAbsent(path: string): void {
    this.remoteFileState.recordAbsent(this.normalizeVaultPath(path));
    this.scheduleRemoteFileStatePersist();
  }

  private async handleRemoteWriteConflict(
    path: string,
    localContent: string,
    baseVersionId?: string | null,
    // SD-06-F1 / DECISION 2: threaded through so the adapter seam can mark a
    // 409 that answered a declared create.
    options?: { createConflict?: boolean }
  ): Promise<RemoteWriteConflictResolutionResult> {
    return this.ensureSyncRuntime().handleRemoteWriteConflict(
      path,
      localContent,
      baseVersionId,
      options
    );
  }

  /**
   * Generates a conflict-suffixed file path for duplicate resolution.
   * @param originalPath - The original conflicted file path
   * @returns A new path with conflict timestamp suffix
   */
  private generateConflictPath(originalPath: string): string {
    return this.ensureSyncRuntime().generateConflictPath(originalPath);
  }

  /**
   * Fetches the current vault sync cursor from the server. Returns null on
   * failure — callers should treat null as "I don't know whether anything
   * changed" and fall through to a full sync rather than skipping.
   */
  private async fetchSyncCursor(): Promise<{
    revision: number;
    lastChangedAt: string;
    reconciliationRequired: boolean;
  } | null> {
    return this.ensureSyncRuntime().fetchSyncCursor();
  }

  private hasValidKeyLease(): boolean {
    return this.ensureSyncRuntime().hasValidKeyLease();
  }

  /**
   * Fetch a file's plaintext via the server-side decrypt endpoint
   * (GET /vaults/{vaultId}/files-decrypted/{path}). Used by the limited-
   * access read path (Phase 8) when the caller cannot receive a vault-wide
   * `/**` key lease. The server gates the route with requireVaultMember +
   * evaluatePermission; 404 on deny (per docs/SHARE-LINKS.md trust pattern).
   */
  private async readFileDecrypted(
    relPath: string,
    options?: { timeoutMs?: number; maxAttempts?: number },
  ): Promise<ApiResponse<RemoteFileContentResponse>> {
    const runtime = this.ensureSyncRuntime();
    return options === undefined
      ? runtime.readFileDecrypted(relPath)
      : runtime.readFileDecrypted(relPath, options);
  }

  private async fetchRemoteFileContent(
    path: string,
    options?: { timeoutMs?: number; maxAttempts?: number },
  ): Promise<ApiResponse<RemoteFileContentResponse>> {
    const runtime = this.ensureSyncRuntime();
    return options === undefined
      ? runtime.fetchRemoteFileContent(path)
      : runtime.fetchRemoteFileContent(path, options);
  }

  private decodeBase64Utf8(base64: string): string {
    return this.ensureSyncRuntime().decodeBase64Utf8(base64);
  }

  private remoteDecryptError(path: string, error: unknown): Error {
    return this.ensureSyncRuntime().remoteDecryptError(path, error);
  }

  private async decodeRemoteFileContent(
    path: string,
    data: RemoteFileContentResponse
  ): Promise<string> {
    return this.ensureSyncRuntime().decodeRemoteFileContent(path, data);
  }

  private async readRemotePlaintext(path: string): Promise<string> {
    return this.ensureSyncRuntime().readRemotePlaintext(path);
  }

  /**
   * Computes the next sync interval (ms) based on recent activity. The
   * configured/org interval acts as the *baseline* — we tighten the loop
   * after activity bursts and relax it when the vault has been idle.
   *
   * Schedule, given a `baseline` interval:
   *   - activity in last  60 s → max(baseline, MIN_SYNC_INTERVAL)
   *   - activity in last   5 m → 1.0× baseline
   *   - activity in last  30 m → 2.0× baseline (capped at 2 min)
   *   - older than that         → 4.0× baseline (capped at 5 min)
   *
   * The cap protects against runaway intervals when a user leaves Obsidian
   * open overnight on a vault no one else is touching.
   */
  private computeNextSyncDelayMs(): number {
    return this.ensureSyncRuntime().computeNextSyncDelayMs();
  }

  /** Starts (or reschedules) the adaptive sync loop. */
  private startSyncTimer(): void {
    this.ensureSyncRuntime().startSyncTimer();
  }

  /** Cancels the next scheduled sync, if any. */
  private stopSyncTimer(): void {
    this.ensureSyncRuntime().stopSyncTimer();
  }

  /** Restarts the sync loop (call when settings, mode, or session change). */
  restartSyncTimer(): void {
    this.ensureSyncRuntime().restartSyncTimer();
  }

  /**
   * Pauses the sync loop. Call when the window goes hidden or the client
   * goes offline. Pending timers are cleared and the loop stops scheduling
   * itself until `resumeSyncLoop` is called.
   */
  private pauseSyncLoop(reason: string): void {
    this.ensureSyncRuntime().pauseSyncLoop(reason);
  }

  /**
   * Resumes the sync loop after `pauseSyncLoop`. Triggers an immediate
   * sync on resume so the user doesn't have to wait one full interval to
   * see other peers' changes after returning to the window.
   */
  private resumeSyncLoop(reason: string): void {
    this.ensureSyncRuntime().resumeSyncLoop(reason);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Key Lease Management
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Requests a vault-scoped `/**` key lease so the plugin can encrypt/decrypt
   * the full vault DEK locally.
   *
   * Outcomes:
   * - `"ok"`        — lease issued and stored on `this.keyLease`.
   * - `"limited"`   — backend returned 403 (the user is authenticated but the
   *                   `/**` scope is denied: deny rules overlap, or no read
   *                   permission on the root probe path). Session is kept
   *                   intact, `keyLease` is cleared, and a debounced Notice
   *                   informs the user. Downloads use the server-side
   *                   decrypt fallback; encrypted uploads remain paused.
   * - `"logged-out"` — backend returned 401 (true session expiry / invalid
   *                   token). `forceLogout` was called; caller must abort.
   * - throws        — for any other error (network failure, 5xx, 4xx other
   *                   than 401/403). Callers decide how to surface.
   *
   * Critical: a 403 here is NOT a session failure. Logging the user out on
   * permission denial creates an infinite "login → logout" loop for any
   * viewer with deny rules or no root-allow.
   */
  private async ensureVaultScopedKeyLease(): Promise<
    "ok" | "limited" | "logged-out"
  > {
    if (!this.session || !this.settings.serverVaultId) {
      return "ok";
    }

    const response = await this.apiRequest<{
      keyLease: KeyLease;
      deniedPaths?: LeaseDeniedPath[];
      orgSettings?: OrgSettingsResponse;
    }>(
      "POST",
      "/auth/key-lease/scoped",
      {
        sessionId: this.session.sessionId,
        scope: "/**",
        vaultId: this.settings.serverVaultId,
      }
    );

    if (response.success && response.data) {
      this.keyLease = this.normalizeKeyLease(
        response.data.keyLease,
        response.data.deniedPaths
      );
      this.applyOrgSettings(response.data.orgSettings ?? this.orgSettings);
      this.vaultLeaseDenied = false;
      this.leaseRetryNeeded = false;
      this.log("Vault-scoped key lease: ok");
      return "ok";
    }

    const statusCode = response.error?.statusCode ?? 0;
    const message = response.error?.message ?? "Vault-scoped key lease request failed.";

    if (statusCode === 401) {
      // True session expiry — the session is unusable, log the user out.
      this.log(`Vault-scoped key lease: logged-out (status=${statusCode}, message=${message})`);
      await this.forceLogout(`VaultGuard Sync: ${message}`);
      return "logged-out";
    }

    if (statusCode === 403) {
      if (this.isUserAccessRevokedMessage(message)) {
        this.log(`Vault-scoped key lease: logged-out (status=${statusCode}, message=${message})`);
        await this.forceLogout(`VaultGuard Sync: ${message}`);
        return "logged-out";
      }

      // Permission denial on `/**` scope — the user authenticated fine, they
      // just can't be given a vault-wide DEK. Keep the session intact and
      // surface the limitation. Download paths can still request
      // permission-checked server-side decrypts; upload/encrypt paths keep
      // guarding on `keyLease`.
      this.keyLease = null;
      this.vaultLeaseDenied = true;
      // Definitive denial, not a transient failure — clear the transient-retry
      // flag so the two recovery paths don't fight.
      this.leaseRetryNeeded = false;
      this.log(`Vault-scoped key lease denied (limited access): status=${statusCode}, message=${message}`);
      this.notifyLimitedAccess(message);
      return "limited";
    }

    // PL2: transient failure (5xx / network / statusCode 0). Leave the session
    // intact but flag that a lease still needs acquiring so the key-renewal
    // monitor's recovery branch retries it — otherwise the null lease would
    // never be re-requested and uploads would stay silently paused.
    this.leaseRetryNeeded = true;
    throw new Error(message);
  }

  private isUserAccessRevokedMessage(message: string): boolean {
    const normalized = message.trim().toLowerCase();
    return (
      normalized.startsWith("access has been revoked") ||
      normalized.startsWith("session has been revoked")
    );
  }

  /**
   * One-shot self-healing walk over on-disk limited-access placeholders.
   * Implementation lives in AtRestAdapterRuntime; main.ts keeps the method
   * name because key-lease recovery and tests call it directly.
   */
  private async sweepPlaceholderPaths(): Promise<void> {
    return this.ensureAtRestAdapterRuntimeObject().sweepPlaceholderPaths();
  }

  /**
   * Shows a one-shot Notice about limited cloud access. Debounced to once
   * per minute so transient retries don't stampede the user.
   */
  private notifyLimitedAccess(reason: string): void {
    const now = Date.now();
    if (now - this.lastLimitedAccessNoticeAt < 60_000) {
      return;
    }
    this.lastLimitedAccessNoticeAt = now;
    const vaultLabel = this.settings.serverVaultName?.trim() || "this vault";
    new Notice(
      `VaultGuard Sync: Limited access to "${vaultLabel}". ${reason} ` +
        `Cloud sync and encrypted file access are unavailable. ` +
        `Contact your administrator if you expected full access.`,
      8000
    );
  }

  /**
   * Starts the server heartbeat loop. The backend returns `active:false`
   * within roughly one minute of user/session/key revocation, letting the
   * plugin clear leases and fail closed instead of waiting for Cognito JWT
   * or DEK lease expiry.
   */
  private startHeartbeatMonitor(): void {
    if (this.isLocalProjectMemoryModeEnabled()) return;
    this.ensureSyncRuntime().startHeartbeatMonitor();
  }

  private stopHeartbeatMonitor(): void {
    this.ensureSyncRuntime().stopHeartbeatMonitor();
  }

  private async checkRevocationHeartbeat(): Promise<void> {
    return this.ensureSyncRuntime().checkRevocationHeartbeat();
  }

  private async handleServerRevocation(reason: string): Promise<void> {
    return this.ensureSyncRuntime().handleServerRevocation(reason);
  }

  /**
   * Starts the periodic key lease renewal monitor.
   * Checks every minute if the lease needs renewal.
   */
  private startKeyRenewalMonitor(): void {
    if (this.isLocalProjectMemoryModeEnabled()) return;
    this.ensureSyncRuntime().startKeyRenewalMonitor();
  }

  /**
   * Stops the key lease renewal monitor.
   */
  private stopKeyRenewalMonitor(): void {
    this.ensureSyncRuntime().stopKeyRenewalMonitor();
  }

  /**
   * Checks if the current key lease needs renewal and initiates renewal
   * if within the grace period before expiry.
   *
   * Also doubles as the recovery point for limited-access sessions: when
   * the user's vault-scoped lease was previously denied (admin had deny
   * rules covering `/**`, or no root-allow rule), this loop retries the
   * lease request once a minute. As soon as permissions are widened
   * server-side the user upgrades from "limited" to "full" without needing
   * to logout/login.
   */
  private async checkKeyLeaseRenewal(): Promise<void> {
    return this.ensureSyncRuntime().checkKeyLeaseRenewal();
  }

  /**
   * Requests a new key lease from the server using the current refresh token.
   */
  private async renewKeyLease(): Promise<void> {
    if (!this.keyLease || !this.session) {
      return;
    }

    try {
      const response = await this.apiRequest<{
        sessionId: string;
        expiresAt: string;
        keyLease: KeyLease;
        deniedPaths?: LeaseDeniedPath[];
        orgSettings?: OrgSettingsResponse;
      }>(
        "POST",
        "/auth/refresh",
        {
          sessionId: this.session.sessionId,
          leaseId: this.keyLease.leaseId,
          refreshToken: this.keyLease.refreshToken,
        }
      );

      if (response.success && response.data) {
        this.keyLease = this.normalizeKeyLease(
          response.data.keyLease,
          response.data.deniedPaths
        );
        this.applyOrgSettings(response.data.orgSettings ?? this.orgSettings);
        this.log("Key lease renewed successfully.");
        if (this.session) {
          this.session = {
            ...this.session,
            sessionId: response.data.sessionId,
          };
          await this.persistSession(this.session);
        }
      } else {
        this.logError("Key lease renewal failed", response.error);

        if (
          response.error?.code === "TOKEN_REFRESH_FAILED" ||
          response.error?.code === "NETWORK_ERROR"
        ) {
          this.log("Key lease renewal deferred until session/network refresh succeeds.");
          return;
        }

        if (
          response.error?.statusCode === 401 ||
          response.error?.statusCode === 403 ||
          response.error?.statusCode === 410
        ) {
          const recovered = await this.recoverVaultScopedKeyLeaseAfterRenewalFailure(
            response.error.message
          );
          if (recovered) {
            return;
          }
          if (!this.session) {
            return;
          }
          new Notice(
            "VaultGuard Sync: Encryption key lease expired. Please reconnect to continue accessing files."
          );
          return;
        }

        // If we can't renew, notify the user
        new Notice(
          "VaultGuard Sync: Encryption key lease expired. Please reconnect to continue accessing files."
        );
      }
    } catch (error) {
      if (this.isNetworkError(error)) {
        this.setConnectionStatus("offline");
        // Key lease continues to work offline until its hard expiry
        this.log(
          "Key renewal failed due to network - using remaining lease time."
        );
      } else {
        this.logError("Key renewal error", error);
      }
    }
  }

  private async recoverVaultScopedKeyLeaseAfterRenewalFailure(reason: string): Promise<boolean> {
    if (!this.session || !this.settings.serverVaultId) {
      return false;
    }

    this.log(`Key lease renewal failed (${reason}); requesting a fresh vault-scoped lease.`);
    this.keyLease = null;

    const leaseResult = await this.ensureVaultScopedKeyLease();
    if (leaseResult === "ok") {
      this.log("Recovered by issuing a fresh vault-scoped key lease.");
      return true;
    }

    if (leaseResult === "limited") {
      this.log("Key lease renewal degraded to limited access without logging out.");
      return true;
    }

    return leaseResult === "logged-out";
  }

  /**
   * Checks if the current key lease has expired.
   * @returns true if expired or no lease exists
   */
  private isKeyLeaseExpired(): boolean {
    return this.ensureSyncRuntime().isKeyLeaseExpired();
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Encryption
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Encrypts file content using the current key lease.
   * Uses AES-256-GCM with a random nonce per encryption operation.
   * @param content - Plaintext content to encrypt
   * @returns Base64-encoded encrypted content (nonce + ciphertext + tag)
   * @throws Error if no valid key lease is available
   */
  private async encryptContent(content: string): Promise<string> {
    if (!this.keyLease || this.isKeyLeaseExpired()) {
      throw new Error(
        "VaultGuard Sync: Cannot encrypt - no valid key lease. Please reconnect."
      );
    }
    this.assertLeaseMatchesBoundVault("encrypt");

    // Use Web Crypto API for AES-256-GCM encryption
    const encoder = new TextEncoder();
    const data = encoder.encode(content);

    // Generate random 12-byte nonce
    const nonce = crypto.getRandomValues(new Uint8Array(12));

    // Import the key
    const keyBytes = this.base64ToBytes(this.keyLease.key);
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyBytes.buffer as ArrayBuffer,
      { name: "AES-GCM" },
      false,
      ["encrypt"]
    );

    // Encrypt
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce },
      cryptoKey,
      data
    );

    // Combine nonce + ciphertext and encode as base64
    const combined = new Uint8Array(nonce.length + ciphertext.byteLength);
    combined.set(nonce);
    combined.set(new Uint8Array(ciphertext), nonce.length);

    return this.bytesToBase64(combined);
  }

  /**
   * Byte variant of {@link encryptContent} (BIN-A / D-02). Encrypts raw bytes
   * with the SAME AES-256-GCM envelope (12-byte nonce ‖ ciphertext+tag, base64)
   * so the server sees an identical ciphertext shape — `decryptContent` can
   * decrypt this output and vice versa. Keeps the lease-expiry throw and the
   * `assertLeaseMatchesBoundVault` guard verbatim (T-11-01: no crypto op without
   * a valid vault-bound lease).
   * @param content - Plaintext bytes to encrypt
   * @returns Base64-encoded encrypted content (nonce + ciphertext + tag)
   * @throws Error if no valid key lease is available
   */
  private async encryptContentBytes(content: ArrayBuffer): Promise<string> {
    return this.bytesToBase64(new Uint8Array(await this.encryptContentBytesRaw(content)));
  }

  /** Encrypt raw bytes without base64 expansion for presigned direct transfer. */
  private async encryptContentBytesRaw(content: ArrayBuffer): Promise<ArrayBuffer> {
    if (!this.keyLease || this.isKeyLeaseExpired()) {
      throw new Error(
        "VaultGuard Sync: Cannot encrypt - no valid key lease. Please reconnect."
      );
    }
    this.assertLeaseMatchesBoundVault("encrypt");

    const data = new Uint8Array(content);

    // Generate random 12-byte nonce
    const nonce = crypto.getRandomValues(new Uint8Array(12));

    // Import the key
    const keyBytes = this.base64ToBytes(this.keyLease.key);
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyBytes.buffer as ArrayBuffer,
      { name: "AES-GCM" },
      false,
      ["encrypt"]
    );

    // Encrypt
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce },
      cryptoKey,
      data
    );

    // Combine nonce + ciphertext and encode as base64
    const combined = new Uint8Array(nonce.length + ciphertext.byteLength);
    combined.set(nonce);
    combined.set(new Uint8Array(ciphertext), nonce.length);

    return combined.buffer;
  }

  /**
   * Decrypts file content using the current key lease.
   * Expects base64-encoded data in format: nonce (12 bytes) + ciphertext + tag.
   * @param encryptedBase64 - Base64-encoded encrypted content
   * @returns Decrypted plaintext content
   * @throws Error if decryption fails or no valid key lease
   */
  private async decryptContent(encryptedBase64: string): Promise<string> {
    if (!this.keyLease || this.isKeyLeaseExpired()) {
      throw new Error(
        "VaultGuard Sync: Cannot decrypt - no valid key lease. Please reconnect."
      );
    }
    this.assertLeaseMatchesBoundVault("decrypt");

    const combined = this.base64ToBytes(encryptedBase64);

    // Nonce (first 12 bytes) + ciphertext (remainder, includes auth tag).
    const nonce = combined.slice(0, 12);
    const ciphertext = combined.slice(12);

    const keyBytes = this.base64ToBytes(this.keyLease.key);
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyBytes.buffer as ArrayBuffer,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce },
      cryptoKey,
      ciphertext
    );

    return new TextDecoder().decode(decrypted);
  }

  /**
   * Byte variant of {@link decryptContent} (BIN-A / D-02). Same envelope split
   * (`slice(0,12)` nonce / `slice(12)` ciphertext+tag) and the same lease/vault
   * guards, but returns the decrypted `ArrayBuffer` instead of UTF-8-decoding it
   * — the lossy `TextDecoder` step is exactly the AR1 failure class for binaries.
   * @param encryptedContent - Base64-encoded encrypted content
   * @returns Decrypted plaintext bytes
   * @throws Error if decryption fails or no valid key lease
   */
  private async decryptContentBytes(encryptedContent: string): Promise<ArrayBuffer> {
    const combined = this.base64ToBytes(encryptedContent);
    return this.decryptContentBytesRaw(combined.buffer as ArrayBuffer);
  }

  /** Decrypt raw direct-transfer bytes and authenticate the AES-GCM envelope. */
  private async decryptContentBytesRaw(encryptedContent: ArrayBuffer): Promise<ArrayBuffer> {
    if (!this.keyLease || this.isKeyLeaseExpired()) {
      throw new Error(
        "VaultGuard Sync: Cannot decrypt - no valid key lease. Please reconnect."
      );
    }
    this.assertLeaseMatchesBoundVault("decrypt");

    const combined = new Uint8Array(encryptedContent);

    // Nonce (first 12 bytes) + ciphertext (remainder, includes auth tag).
    const nonce = combined.slice(0, 12);
    const ciphertext = combined.slice(12);

    const keyBytes = this.base64ToBytes(this.keyLease.key);
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      keyBytes.buffer as ArrayBuffer,
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce },
      cryptoKey,
      ciphertext
    );

    return decrypted;
  }

  /**
   * Encrypts a large file once, uploads it through the isolated staging lane,
   * then finalizes the canonical version. No presigned URL is persisted or
   * included in errors, logs, diagnostics, or settings.
   */
  private async uploadLargeEncryptedFile(
    path: string,
    plaintext: ArrayBuffer,
    contentType: string,
    expectedVersionId?: string,
  ) {
    if (!this.apiClient) {
      throw new Error("VaultGuard Sync: Direct transfer is unavailable before sign-in.");
    }
    if (!this.keyLease || this.isKeyLeaseExpired()) {
      throw new Error("VaultGuard Sync: A current key lease is required for large files.");
    }
    this.assertLeaseMatchesBoundVault("encrypt");
    const encrypted = await this.encryptContentBytesRaw(plaintext);
    const plaintextSha256 = await this.computeHashBytes(plaintext);
    const encryptedSha256 = await this.computeHashBytes(encrypted);
    const result = await this.apiClient.uploadLargeEncryptedFile(path, encrypted, {
      plaintextSize: plaintext.byteLength,
      encryptedSize: encrypted.byteLength,
      plaintextSha256,
      encryptedSha256,
      contentType,
      activeKeyId: this.keyLease.keyId ?? this.keyLease.leaseId,
      ...(expectedVersionId ? { expectedVersionId } : {}),
    });
    return {
      path: this.normalizeVaultPath(result.path),
      hash: plaintextSha256,
      size: plaintext.byteLength,
      lastModified: result.lastModified,
      versionId: result.versionId,
      transferId: result.transferId,
    };
  }

  /** Download, hash-check, and decrypt a direct-transfer object before mutation. */
  private async downloadLargeEncryptedFile(path: string, versionId?: string) {
    if (!this.apiClient) {
      throw new Error("VaultGuard Sync: Direct transfer is unavailable before sign-in.");
    }
    const capability = await this.apiClient.issueDirectDownload(path, versionId);
    const encrypted = await this.apiClient.getDirectDownload(capability);
    const encryptedSha256 = await this.computeHashBytes(encrypted);
    if (encryptedSha256 !== capability.encryptedSha256) {
      throw new Error("VaultGuard direct download failed encrypted integrity verification.");
    }
    const bytes = await this.decryptContentBytesRaw(encrypted);
    if (bytes.byteLength !== capability.plaintextSize) {
      throw new Error("VaultGuard direct download failed plaintext size verification.");
    }
    const plaintextSha256 = await this.computeHashBytes(bytes);
    if (plaintextSha256 !== capability.plaintextSha256) {
      throw new Error("VaultGuard direct download failed plaintext integrity verification.");
    }
    return {
      bytes,
      plaintextSize: capability.plaintextSize,
      plaintextSha256,
      contentType: capability.contentType,
      versionId: capability.versionId,
    };
  }

  private async upsertPendingLargeFile(record: PendingLargeFileRecord): Promise<void> {
    const path = this.normalizeVaultPath(record.path);
    const current = this.settings.pendingLargeFiles?.[path];
    this.settings.pendingLargeFiles = {
      ...(this.settings.pendingLargeFiles ?? {}),
      [path]: {
        ...record,
        path,
        attempts: Math.max(record.attempts, current?.attempts ?? 0),
        updatedAt: new Date().toISOString(),
      },
    };
    await this.saveSettings();
    this.updateStatusBar();
    this.reloadVaultGuardSidebar();
  }

  private async clearPendingLargeFile(path: string): Promise<void> {
    const normalized = this.normalizeVaultPath(path);
    const pending = { ...(this.settings.pendingLargeFiles ?? {}) };
    if (!(normalized in pending)) return;
    delete pending[normalized];
    this.settings.pendingLargeFiles = pending;
    await this.saveSettings();
    this.updateStatusBar();
    this.reloadVaultGuardSidebar();
  }

  /**
   * Hard guard against ever using a lease that doesn't match the vault
   * we're operating on. Catches:
   *   - org-wide leases leaking into vault-scoped operations (no vaultId
   *     on the lease while a vault is bound)
   *   - vault-switch races where the lease lags one vault behind
   *
   * Throws synchronously so the caller surfaces a real error instead of
   * producing garbage ciphertext or hitting a much later AES-GCM tag fail.
   */
  private assertLeaseMatchesBoundVault(op: "encrypt" | "decrypt"): void {
    const boundVaultId = this.settings.serverVaultId;
    if (!boundVaultId) {
      throw new Error(
        `VaultGuard Sync: refusing to ${op} — no server vault is bound to this folder.`
      );
    }
    const leaseVaultId = this.keyLease?.vaultId;
    if (leaseVaultId !== boundVaultId) {
      throw new Error(
        `VaultGuard Sync: refusing to ${op} — key lease is bound to vault "${leaseVaultId ?? "(none)"}" ` +
        `but this folder is bound to vault "${boundVaultId}". Reload the plugin to recover.`
      );
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // AI-chat API key cross-device sync (crypto + context)
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Wraps the plaintext Anthropic API key with the LIVE vault DEK so it can be
   * stored server-side as an opaque, roaming envelope. Reuses the same
   * AES-256-GCM crypto as file encryption (fresh 12-byte nonce embedded inside
   * `ct`, matching the on-disk/cloud envelope — NOT a separate field) and the
   * same lease/vault-binding guard. Returns null (never throws) when there is
   * no valid, vault-matched lease, in which case the caller keeps the key
   * device-local only. The plaintext key is never sent to the server.
   */
  async wrapAiKeySecret(plaintext: string): Promise<string | null> {
    if (!this.keyLease || this.isKeyLeaseExpired() || !this.settings.serverVaultId) {
      return null;
    }
    try {
      const ct = await this.encryptContent(plaintext);
      const dekTag = await this.aiKeyDekTag();
      if (!dekTag) return null;
      return JSON.stringify({ v: 1, ct, dekTag });
    } catch (err) {
      this.log(`AI key wrap skipped: ${(err as Error).message}`);
      return null;
    }
  }

  /**
   * Reverses wrapAiKeySecret. Returns null (never throws) on a version
   * mismatch, a rotated/retired DEK (dekTag mismatch — soft-fail, debug log
   * only, so a device with a live key can still heal the blob), or any
   * decrypt failure.
   */
  async unwrapAiKeySecret(envelope: string): Promise<string | null> {
    let parsed: { v?: unknown; ct?: unknown; dekTag?: unknown };
    try {
      parsed = JSON.parse(envelope);
    } catch {
      return null;
    }
    if (parsed.v !== 1 || typeof parsed.ct !== "string") return null;
    const currentTag = await this.aiKeyDekTag();
    if (!currentTag || parsed.dekTag !== currentTag) {
      this.log("AI key envelope wrapped with a stale/rotated DEK — treating as no key.");
      return null;
    }
    try {
      return await this.decryptContent(parsed.ct);
    } catch {
      return null;
    }
  }

  /**
   * True when `envelope` was wrapped with a DEK other than the current live one
   * (or cannot be parsed / there is no valid lease) — i.e. a live-keyed device
   * should re-upload to heal it. Returns false ONLY when the envelope is
   * confidently current.
   */
  async isAiKeyEnvelopeStale(envelope: string): Promise<boolean> {
    let parsed: { dekTag?: unknown };
    try {
      parsed = JSON.parse(envelope);
    } catch {
      return true;
    }
    const currentTag = await this.aiKeyDekTag();
    if (!currentTag) return true;
    return parsed.dekTag !== currentTag;
  }

  /**
   * One-way, non-reversible 8-byte fingerprint of the live DEK
   * (SHA-256(DEK)[:8], base64). Safe to store/transmit in plaintext — it leaks
   * nothing usable about the 256-bit key. Used ONLY to detect DEK rotation so a
   * blob wrapped under a retired DEK fails soft. Null when no valid lease.
   */
  private async aiKeyDekTag(): Promise<string | null> {
    if (!this.keyLease || this.isKeyLeaseExpired()) return null;
    const keyBytes = this.base64ToBytes(this.keyLease.key);
    const digest = await crypto.subtle.digest(
      "SHA-256",
      keyBytes.buffer.slice(keyBytes.byteOffset, keyBytes.byteOffset + keyBytes.byteLength) as ArrayBuffer
    );
    return this.bytesToBase64(new Uint8Array(digest).slice(0, 8));
  }

  /**
   * Narrow accessor exposing exactly the three otherwise-private fields
   * ApiKeySync needs (api client, session, bound vault). This getter is their
   * only exposure to the sync module.
   */
  getAiKeySyncContext(): {
    apiClient: VaultGuardApiClient | null;
    session: UserSession | null;
    vaultId: string;
  } {
    return {
      apiClient: this.apiClient,
      session: this.session,
      vaultId: this.settings.serverVaultId,
    };
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Connection Management
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Updates the connection status and triggers appropriate side effects.
   * @param status - New connection status
   */
  private setConnectionStatus(
    status: ConnectionStatus,
    options: { scheduleRetry?: boolean; notify?: boolean } = {}
  ): void {
    const { scheduleRetry = true, notify = true } = options;
    const previousStatus = this.connectionState.status;
    this.connectionState.status = status;

    if (status === "online") {
      this.connectionState.lastConnected = new Date().toISOString();
      this.connectionState.failedAttempts = 0;
      this.connectionState.nextRetryAt = null;
      this.stopConnectionRetry();
      // Connectivity returned — kill any pending blip notice before it fires.
      this.cancelConnectionLostNotice();

      // Flush queued operations whenever connectivity is restored.
      if (previousStatus !== "online") {
        const protectedContentGate = this.getProtectedContentGate();
        if (protectedContentGate.ok) {
          this.log("Connection restored, flushing offline queue...");
          void this.flushOfflineQueue();
        } else {
          // Auth/session bootstrap requests can prove API connectivity before
          // this account has been authorized for the exact bound server vault.
          // Keep the queue intact until login/reconciliation opens the gate;
          // invoking the guarded flush here only creates an unhandled error and
          // must never become a bypass around binding verification.
          this.log(
            `Connection restored; offline queue remains paused (${protectedContentGate.reason ?? "protected content unavailable"}).`
          );
        }
      }
    } else if (status === "offline") {
      // Backoff still grows per DISTINCT outage, so only a real transition
      // counts as a new failure — a repeat "offline" while already offline must
      // not inflate the interval.
      if (previousStatus !== "offline") {
        this.connectionState.failedAttempts++;
      }
      if (scheduleRetry) {
        // Deliberately NOT gated on `previousStatus !== "offline"`. The class is
        // BORN "offline" (see the connectionState field initializer), so an
        // edge-only guard swallowed the very first offline signal of every
        // process: no `failedAttempts++`, no retry armed, and — because
        // `attemptReconnection` only ever runs from that timer while
        // `performSync` and its focus triggers are gated behind `isOnline()` —
        // no path back online short of a logout/login. That is the
        // "still offline after restarting Obsidian, fixed by signing out and
        // in" report. `ensureConnectionRecovery` is idempotent, so a live timer
        // keeps its place in the backoff sequence instead of being reset.
        this.ensureConnectionRecovery();
      } else {
        this.stopConnectionRetry();
        this.connectionState.nextRetryAt = null;
      }
      if (notify && this.session && previousStatus === "online") {
        this.scheduleConnectionLostNotice();
      }
    }

    this.updateStatusBar();

    // Populate any open Permissions graph that was waiting on connectivity, and
    // refresh the per-file permission header on the SAME edge for the same
    // reason. The "online" flip is deferred until the first sync, so a graph or
    // header that rendered its offline/unavailable state on launch self-corrects
    // on the offline→online edge — without the user reopening the panel or
    // switching files.
    if (status === "online" && previousStatus !== "online") {
      this.refreshPermissionsGraph();
      this.refreshFilePermissionHeader();
    }
  }

  /** Re-render every open Permissions graph view (e.g. after coming online). */
  private refreshPermissionsGraph(): void {
    this.getPermissionsGraphRuntime().refreshOpenViews();
  }

  /**
   * Debounced connection-lost notice. Schedules the toast CONNECTION_LOST_NOTICE_GRACE_MS
   * out instead of firing immediately, so a transient blip that recovers within
   * the grace window (cancelConnectionLostNotice runs on the online edge) never
   * surfaces an alarming "working offline" popup. Only a sustained outage gets a
   * toast. The 30s throttle still applies — but at fire time, not schedule time —
   * to avoid storms across repeated offline transitions.
   */
  private scheduleConnectionLostNotice(): void {
    // A notice is already pending for this outage; don't stack timers.
    if (this.connectionLostNoticeTimer) return;

    this.connectionLostNoticeTimer = setTimeout(() => {
      this.connectionLostNoticeTimer = null;

      // Recovered during the grace window — nothing to report.
      if (this.connectionState.status === "online") return;

      const now = Date.now();
      if (
        this.lastConnectionLostNoticeAt !== null &&
        now - this.lastConnectionLostNoticeAt < CONNECTION_LOST_NOTICE_THROTTLE_MS
      ) {
        return;
      }

      this.lastConnectionLostNoticeAt = now;
      new Notice("VaultGuard Sync: Connection lost. Working offline with cached data.");
    }, CONNECTION_LOST_NOTICE_GRACE_MS);
  }

  /** Cancels a pending debounced connection-lost notice (called on the online edge and on unload). */
  private cancelConnectionLostNotice(): void {
    if (this.connectionLostNoticeTimer) {
      clearTimeout(this.connectionLostNoticeTimer);
      this.connectionLostNoticeTimer = null;
    }
  }

  /**
   * Arms the reconnect loop if — and ONLY if — it is currently missing.
   *
   * THE INVARIANT IT ENFORCES: while a session exists and the status is not
   * "online", there is always exactly one live reconnect timer. Nothing else in
   * the plugin re-probes the backend on its own — `performSync` and its
   * focus/visibility triggers all return early on `!isOnline()`, and the
   * heartbeat / key-renewal monitors are only started from paths that a failing
   * startup resume never reaches. So a lost timer is not a degraded state, it is
   * a terminal one, and the user's only escape is a logout/login.
   *
   * Idempotent by design: a live timer is left exactly where it is, so repeated
   * offline signals during one outage can never reset the backoff sequence back
   * to 5 s. The `failedAttempts` floor keeps `scheduleConnectionRetry`'s
   * `2^(n-1)` arithmetic on whole steps when we arm from the birth state (where
   * no failure was ever counted).
   *
   * The `!this.session` early exit is load-bearing and matches
   * `scheduleConnectionRetry`'s own guard: `forceLogout` nulls the session
   * BEFORE its `setConnectionStatus("offline")`, so a logout still arms nothing
   * and the "Connection retry scheduled in 5s/10s/…" post-logout storm stays
   * fixed.
   */
  private ensureConnectionRecovery(): void {
    if (this.connectionRetryTimer) return;
    if (this.connectionState.status === "online") return;
    if (!this.session) return;
    // Local Project Memory Mode has no backend to reconnect to — it parks the
    // plugin offline on purpose (see completeLogin / restoreServerSession).
    if (this.isLocalProjectMemoryModeEnabled()) return;

    if (this.connectionState.failedAttempts < 1) {
      this.connectionState.failedAttempts = 1;
    }
    this.scheduleConnectionRetry();
  }

  /**
   * THE single backstop every `resumeStoredSession` caller runs when its resume
   * settles — success, early return, or throw.
   *
   * It exists because "reachable" and "resumed" are independent failures.
   * `ensureConnectionRecovery` alone is not enough: a resume can end incomplete
   * while the status reads ONLINE (the probe that triggered the re-drive
   * succeeded, or an unrelated request flipped it), and there the reconnect loop
   * correctly refuses to arm — leaving a plugin that answers "online" but has no
   * monitors, an unverified binding and no sync engine, with nothing scheduled
   * to ever try again.
   *
   * So: complete → just keep the ordinary offline-recovery invariant. Incomplete
   * → force a probe onto the schedule regardless of the current status, backing
   * off on `incompleteResumeRetries` (5 s, 10 s, 20 s … 2 min ceiling) because
   * the "online" flip ahead of each re-drive keeps resetting
   * `connectionState.failedAttempts` to 0.
   *
   * Note what is deliberately NOT retried: a DEFINITIVE server answer marks the
   * resume complete at its own call site (see the binding gate's `wrong-account`
   * branch), because re-asking cannot change it and the loop would only restage
   * the same sticky Notice.
   */
  private armResumeRetryIfIncomplete(): void {
    if (this.serverSessionResumeComplete) {
      this.incompleteResumeRetries = 0;
      this.ensureConnectionRecovery();
      return;
    }
    if (!this.session) return;
    if (this.isLocalProjectMemoryModeEnabled()) return;

    this.incompleteResumeRetries++;
    this.connectionState.failedAttempts = Math.max(
      this.connectionState.failedAttempts,
      this.incompleteResumeRetries
    );
    this.scheduleConnectionRetry();
  }

  /**
   * Schedules a connection retry with exponential backoff.
   */
  private scheduleConnectionRetry(): void {
    this.stopConnectionRetry();

    // No session = nothing to reconnect to. Without this guard, forceLogout
    // calls setConnectionStatus("offline") on its way out, which schedules a
    // retry, which fires `/vaults` with no auth, fails, schedules another at
    // 2× backoff, and so on — visible as the "Connection retry scheduled in
    // 5s/10s/…" lines after every logout.
    if (!this.session) return;

    const backoffMs = Math.min(
      BASE_RETRY_INTERVAL_MS *
        Math.pow(2, this.connectionState.failedAttempts - 1),
      MAX_RETRY_INTERVAL_MS
    );

    this.connectionState.nextRetryAt = new Date(
      Date.now() + backoffMs
    ).toISOString();

    this.connectionRetryTimer = setTimeout(async () => {
      await this.attemptReconnection();
    }, backoffMs);

    this.log(`Connection retry scheduled in ${backoffMs / 1000}s`);
  }

  /**
   * Attempts to reconnect to the VaultGuard backend.
   */
  /**
   * Public entry point for a user-initiated reconnect probe — used by UI
   * surfaces (e.g. the Permissions graph "Retry connection" empty-state CTA)
   * that can't call the private attemptReconnection() directly. On success it
   * flips the status online, which re-renders waiting Permissions graphs.
   */
  async reconnectNow(): Promise<void> {
    await this.attemptReconnection();
  }

  private async attemptReconnection(): Promise<void> {
    if (!this.session) {
      this.setConnectionStatus("offline", { scheduleRetry: false, notify: false });
      return;
    }

    try {
      this.setConnectionStatus("reconnecting", {
        scheduleRetry: false,
        notify: false,
      });

      // /vaults is the cheapest authenticated probe — it always exists
      // post-multi-vault and returns the user's vault list (small payload).
      const response = await this.apiRequest<{ vaults: unknown[] }>(
        "GET",
        "/vaults"
      );

      if (response.success) {
        this.setConnectionStatus("online");
        this.log("Reconnection successful.");
        // Connectivity alone is not recovery. If the startup resume never
        // finished, the plugin has no heartbeat, no key-renewal poll, an
        // unverified vault binding and no sync engine — it would sit "online"
        // and idle forever. Finish it now that the backend answers.
        this.resumeIncompleteServerSession();
      } else if (
        response.error?.statusCode === 401 ||
        response.error?.statusCode === 403
      ) {
        await this.forceLogout(
          `VaultGuard Sync: ${response.error.message || "Session expired. Please log in again."}`
        );
      } else {
        this.setConnectionStatus("offline");
      }
    } catch {
      this.setConnectionStatus("offline");
    }
  }

  /**
   * Re-drives a startup resume that never reached its end state, once the
   * backend is answering again.
   *
   * Fire-and-forget by contract — `attemptReconnection` must not start waiting
   * on a full session restore, and a second failure here is just another
   * incomplete resume that the next successful probe will retry. Re-entrancy is
   * held off by `sessionResumePromise`, the same handle `onload` and the
   * interceptors already use, so this can never run two resumes at once.
   *
   * `resumeStoredSession` is idempotent enough to re-run: the monitors
   * stop-then-start, `initializeSyncEngine` is guarded on `!this.syncTimer`, and
   * the vault-binding check re-runs from scratch. Re-minting a server session is
   * the one real cost, and it only happens when the previous one could not be
   * used anyway.
   */
  private resumeIncompleteServerSession(): void {
    if (this.serverSessionResumeComplete) return;
    if (!this.session) return;
    if (this.sessionResumePromise) return;
    if (this.isLocalProjectMemoryModeEnabled()) return;

    this.log("Reconnected with an unfinished session resume — retrying it.");
    this.syncDiagnostics.record("attemptReconnection.resumeRetry");
    const resumePromise = this.resumeStoredSession().catch((err) => {
      this.logError("Post-reconnect session resume failed (will retry)", err);
    });
    this.sessionResumePromise = resumePromise;
    void resumePromise.finally(() => {
      if (this.sessionResumePromise === resumePromise) {
        this.sessionResumePromise = null;
      }
      this.armResumeRetryIfIncomplete();
    });
  }

  /**
   * Stops any pending connection retry timer.
   */
  private stopConnectionRetry(): void {
    if (this.connectionRetryTimer) {
      clearTimeout(this.connectionRetryTimer);
      this.connectionRetryTimer = null;
    }
  }

  /**
   * Checks if the plugin is currently online and connected.
   * @returns true if connected to the VaultGuard backend
   */
  private isOnline(): boolean {
    return this.connectionState.status === "online";
  }

  /**
   * Public read-only view of the backend connection state, for UI surfaces
   * (e.g. the AI Chat status footer) that want to display online/offline
   * without reaching into the private connection-state machine.
   */
  isConnectedOnline(): boolean {
    return this.isOnline();
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Offline Queue
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Queues an operation for later execution when connectivity is restored.
   * @param operation - The type of operation
   * @param path - The file path
   * @param data - Optional file content (for write operations)
   */
  private queueOfflineOperation(
    operation: "write" | "delete",
    path: string,
    data?: string,
    // BIN-A / D-09 + version-guard: forward the optional binary-payload marker
    // and/or version-guard fields to the sync runtime.
    options?: {
      encoding?: "base64";
      contentType?: string;
      baseVersionId?: string;
      baseHash?: string;
    }
  ): void {
    return this.ensureSyncRuntime().queueOfflineOperation(operation, path, data, options);
  }

  /**
   * Flushes all queued offline operations to the server.
   * Operations are sent in chronological order.
   */
  private async flushOfflineQueue(): Promise<void> {
    return this.ensureSyncRuntime().flushOfflineQueue();
  }

  private async runOfflineQueueFlush(): Promise<void> {
    return this.ensureSyncRuntime().runOfflineQueueFlush();
  }

  private assertOfflineFlushResponse(
    response: ApiResponse<unknown>,
    op: { operation: "write" | "delete"; path: string }
  ): void {
    return this.ensureSyncRuntime().assertOfflineFlushResponse(response, op);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // API Communication
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Makes an authenticated API request to the VaultGuard backend.
   * Includes retry logic and proper error handling.
   * @param method - HTTP method
   * @param endpoint - API endpoint path (relative to apiEndpoint setting)
   * @param body - Optional request body
   * @returns Typed API response
   */
  /**
   * Returns the `/vaults/{vaultId}` URL prefix bound to this Obsidian folder.
   * Throws if no server vault has been picked yet — file/permission ops are
   * meaningless until the user binds.
   */
  private vaultPath(suffix: string = ''): string {
    const vaultId = this.settings.serverVaultId;
    if (!vaultId) {
      throw new Error(
        'VaultGuard: this Obsidian folder is not bound to a server vault yet. ' +
        'Open the VaultGuard sidebar to pick or create one.'
      );
    }
    return `/vaults/${encodeURIComponent(vaultId)}${suffix}`;
  }

  /**
   * SD-02-F1 (M10): THE SINGLE DEFINITION of "which session id does an outbound
   * request carry". Both PRODUCTION header-attach sites consume it:
   *
   *   1. `src/api/client.ts` — via the `getSessionId` callback wired in
   *      `src/plugin/settings-runtime.ts` (`VaultGuardApiClient` requests).
   *   2. `apiRequest` below — every `this.apiRequest(...)` call, which is the path
   *      the restore's first key-lease request actually takes.
   *
    * A live `this.session` always wins; the restore candidate is a fallback for
    * direct restore callers that have not assigned it yet. Do NOT reintroduce a
   * direct `this.session?.sessionId` read at either site — that is exactly the
   * drift this resolver was created to prevent.
   *
   * (The third occurrence of the header, in the connection-diagnostics probe, is
   * deliberately NOT routed through here — see the comment at its call site.)
   */
  private resolveRequestSessionId(): string | null {
    return this.session?.sessionId ?? this.restoreCandidateSessionId ?? null;
  }

  private async apiRequest<T>(
    method: string,
    endpoint: string,
    body?: Record<string, unknown>,
    idTokenOverride?: string,
    // L2 (BIN-A): optional per-request timeout override. Large binary PUTs pass a
    // longer timeout (BINARY_PUT_TIMEOUT_MS) so a slow uplink is not misread as a
    // network failure; omitted → the 30 s default in requestWithTimeout is unchanged.
    options?: {
      timeoutMs?: number;
      suppressSessionHeader?: boolean;
      maxAttempts?: number;
    }
  ): Promise<ApiResponse<T>> {
    if (!idTokenOverride && this.session) {
      if (this.isSessionTokenExpiring(this.session)) {
        const refreshResult = await this.refreshAccessToken(this.session);
        if (!refreshResult.ok) {
          // PL4: a TERMINAL rejection (refresh token revoked/expired, user
          // disabled) can never heal — fail closed like a server revocation
          // instead of parking in perpetual "offline" with a stale session.
          // The guard flag breaks recursion: forceLogout itself POSTs
          // /auth/logout through apiRequest with the same dead token.
          if (refreshResult.terminal && !this.terminalRefreshLogoutInProgress) {
            this.terminalRefreshLogoutInProgress = true;
            try {
              await this.handleServerRevocation("session expired or revoked");
            } finally {
              this.terminalRefreshLogoutInProgress = false;
            }
            return {
              success: false,
              data: null,
              error: {
                code: "SESSION_REVOKED",
                message:
                  "Your VaultGuard session has been revoked or has expired. Please sign in again.",
                details: null,
                statusCode: 401,
              },
              requestId: "",
            };
          }
          this.setConnectionStatus("offline");
          return {
            success: false,
            data: null,
            error: {
              code: "TOKEN_REFRESH_FAILED",
              message:
                `Could not refresh the VaultGuard session token: ${refreshResult.message}. ` +
                "The local session was kept and VaultGuard will retry.",
              details: null,
              statusCode: 0,
            },
            requestId: "",
          };
        }
      }
    }

    const idToken = idTokenOverride ?? this.session?.idToken;
    let baseUrl = await this.getResolvedApiEndpoint(idToken);
    let url = `${baseUrl}${endpoint}`;
    const headers: Record<string, string> = {};

    if (idToken) {
      // API Gateway Cognito authorizer expects the ID token (no Bearer prefix)
      headers["Authorization"] = idToken;
    }
    // SD-02-F1 (M10): read through the single resolver, never `this.session`
    // directly — during a restore the live session is not assigned yet and this
    // block used to attach nothing. Behavior with a live session is unchanged.
    // Session creation is the one authenticated bootstrap that must never carry
    // a restored/stale server-session id. `openServerSession` opts out explicitly;
    // every other protected request keeps using the single resolver.
    let requestSessionId = options?.suppressSessionHeader
      ? null
      : this.resolveRequestSessionId();

    // SD-02-F1: THE client-side choke point. Reaching here with an AUTHENTICATED
    // request and no id to send means the live session has none AT ALL — a
    // session persisted before the session-header work — and nothing else in a
    // running plugin ever repairs that, so this client would stay headerless
    // forever. Heal it here, before the request goes out, instead of only
    // leaving a breadcrumb behind it.
    //
    // `attemptReconnection`'s `/vaults` probe — the exact loop behind the
    // 9,706-sample production signature — deliberately gets NO hook of its own:
    // it is an `apiRequest` call, so it heals right here, before the probe is
    // sent. Same for every other plugin-issued authenticated request.
    //
    // Awaiting here is safe and bounded:
    //   * the hot path is a single truthiness check — `ensureServerSessionId`
    //     fast-exits on any session that already has an id, so a healthy client
    //     pays nothing and issues no extra request;
    //   * the mint opts out via `suppressSessionHeader`, so the mint can never
    //     trigger a mint. That check is LOAD-BEARING: without it the heal
    //     re-enters itself and deadlocks awaiting its own in-flight promise. The
    //     in-flight guard is the second, independent brake;
    //   * in-flight collapse plus the 60 s cooldown bound a FAILING heal to one
    //     attempt per minute, and the request still proceeds headerless exactly
    //     as it does today.
    if (!requestSessionId && idToken && !options?.suppressSessionHeader) {
      await this.ensureServerSessionId();
      // Re-resolve from live state — the heal may have landed a fresh id.
      requestSessionId = this.resolveRequestSessionId();
      // The heal can also refresh the Cognito tokens underneath us, and the
      // Authorization header above was built from the pre-heal value. Only for
      // session-derived tokens: an explicit override is the caller's choice and
      // is never second-guessed.
      if (idTokenOverride === undefined) {
        const healedIdToken = this.session?.idToken;
        if (healedIdToken && healedIdToken !== idToken) {
          headers["Authorization"] = healedIdToken;
        }
      }
    }

    if (requestSessionId) {
      headers["X-VaultGuard-Session-Id"] = requestSessionId;
    } else if (idToken) {
      // SD-02-F1: an AUTHENTICATED request going out with no session header. This is
      // the client-side mirror of the server's `[SESSION_TELEMETRY]` observe-mode
      // line — the two halves answer the same question from opposite ends, and a
      // future enforcement flip is only safe once both go quiet.
      //
      // After the self-heal above, the only expected hits are the `/auth/session`
      // mint itself (no id exists yet, M12, and it opts out of the heal) and the
      // requests a heal could not rescue in time — an offline/failed mint, a
      // deferred token refresh, or a request landing inside the 60 s cooldown of
      // a previous failure. A legacy session no longer produces a SUSTAINED
      // stream here; a persistent one now means the mint itself is failing.
      //
      // The query string is STRIPPED: the restore lease call puts the session id in
      // its query string, and this buffer is user-copyable ("Copy sync diagnostics").
      // A path + method is all the pointer needs to be.
      // `syncDiagnostics.record` is a no-op in production builds (NODE_ENV guard,
      // DCE-stripped by esbuild), so this costs nothing on a user's machine.
      this.syncDiagnostics.record("apiRequest.headerlessAuthenticated", {
        endpoint: endpoint.split("?")[0],
        method,
      });
    }

    const startedAt = Date.now();
    let lastError: Error | null = null;
    let sawNetworkError = false;
    // AC-API1: the latest REAL HTTP failure (429/5xx that exhausted retries).
    // Returned with its true status instead of collapsing to statusCode 0.
    let lastHttpFailure: ApiResponse<T> | null = null;
    let endpointRefreshAttempted = false;

    const configuredAttemptLimit = this.settings.maxRetryAttempts;
    const attemptLimit =
      options?.maxAttempts === undefined
        ? configuredAttemptLimit
        : Math.max(1, Math.min(configuredAttemptLimit, Math.floor(options.maxAttempts)));

    for (let attempt = 0; attempt < attemptLimit; attempt++) {
      try {
        // L2 (BIN-A): thread the optional per-request timeout override. NOTE:
        // Promise.race does NOT abort the underlying requestUrl — a timed-out PUT
        // may still land server-side. Binary PUTs are idempotent so a retry is
        // harmless, but nothing may assume at-most-once delivery.
        const response = await this.requestWithTimeout(
          requestUrl({
            url,
            method,
            headers,
            body: body ? JSON.stringify(body) : undefined,
            contentType: body ? "application/json" : undefined,
            throw: false,
          }),
          options?.timeoutMs
        );

        if (response.status === 0) {
          sawNetworkError = true;
          lastError = new Error(this.describeNetworkFailureResponse(response));
          if (attempt < attemptLimit - 1) {
            await this.delay(BASE_RETRY_INTERVAL_MS * Math.pow(2, attempt));
          }
          continue;
        }

        const contentLength = this.getHeaderValue(response.headers, "content-length");
        const data =
          response.status === 204 || contentLength === "0" || response.text.length === 0
            ? null
            : (response.json as unknown);

        if (response.status >= 200 && response.status < 300) {
          this.connectionState.latencyMs = Date.now() - startedAt;
          this.setConnectionStatus("online");
          return {
            success: true,
            data: data as T,
            error: null,
            requestId: this.getHeaderValue(response.headers, "x-request-id") ?? "",
          };
        }

        if (idToken && this.isGatewayMisrouteResponse(response)) {
          if (!endpointRefreshAttempted) {
            endpointRefreshAttempted = true;
            const refreshedBaseUrl = await this.getResolvedApiEndpoint(
              idToken,
              undefined,
              true
            );
            if (refreshedBaseUrl && refreshedBaseUrl !== baseUrl) {
              baseUrl = refreshedBaseUrl;
              url = `${baseUrl}${endpoint}`;
              continue;
            }
          }
          return this.buildMisroutedApiResponse<T>(response);
        }

        // AC-API1: every HTTP failure carries its REAL status to the caller.
        // Permanent statuses (404/409/413/…) return immediately — retrying
        // cannot change them, and collapsing them to statusCode 0 made
        // callers treat "already deleted" or "note too large" as a network
        // outage (offline flip + endless requeue). Only genuinely transient
        // failures (429, 5xx) retry, and when exhausted they ALSO return
        // their real status. statusCode 0 now means exactly "network
        // failure / request never reached the server".
        const httpFailure: ApiResponse<T> = {
          success: false,
          data: null,
          error: {
            code:
              ((data as Record<string, unknown> | null)?.code as string) ??
              (response.status === 401 || response.status === 403
                ? "AUTH_ERROR"
                : `HTTP_${response.status}`),
            message:
              ((data as Record<string, unknown> | null)?.message as string) ??
              (response.status === 401 || response.status === 403
                ? "Authentication failed"
                : `HTTP ${response.status}: Request failed`),
            details:
              ((data as Record<string, unknown> | null)?.details as Record<
                string,
                unknown
              > | null) ?? null,
            statusCode: response.status,
          },
          requestId: this.getHeaderValue(response.headers, "x-request-id") ?? "",
        };

        if (response.status !== 429 && response.status < 500) {
          return httpFailure;
        }

        lastHttpFailure = httpFailure;
        lastError = new Error(httpFailure.error?.message ?? `HTTP ${response.status}`);
      } catch (error) {
        lastError =
          error instanceof Error ? error : new Error("Unknown network error");

        // Only retry on network errors
        if (!this.isNetworkError(error)) {
          break;
        }
        sawNetworkError = true;
      }

      // Wait before retry with exponential backoff
      if (attempt < attemptLimit - 1) {
        await this.delay(BASE_RETRY_INTERVAL_MS * Math.pow(2, attempt));
      }
    }

    // All retries exhausted
    if (sawNetworkError) {
      this.setConnectionStatus("offline");
    }

    // A real HTTP failure (429/5xx) beats the generic network shape — the
    // caller learns the true status even when some attempts were network
    // errors.
    if (lastHttpFailure) {
      return lastHttpFailure;
    }

    return {
      success: false,
      data: null,
      error: {
        code: sawNetworkError ? "NETWORK_ERROR" : "REQUEST_FAILED",
        message: lastError?.message ?? "Request failed after all retries",
        details: null,
        statusCode: 0,
      },
      requestId: "",
    };
  }

  private isGatewayMisrouteResponse(response: RequestUrlResponse): boolean {
    const contentType =
      this.getHeaderValue(response.headers, "content-type")?.toLowerCase() ?? "";
    const jsonBody =
      response.json && typeof response.json === "object"
        ? response.json as Record<string, unknown>
        : null;
    const message =
      typeof jsonBody?.message === "string"
        ? jsonBody.message
        : typeof jsonBody?.Message === "string"
          ? jsonBody.Message
          : "";
    const bodyText = response.text ?? "";

    return looksLikeAwsSignatureError(message, bodyText, contentType);
  }

  private buildMisroutedApiResponse<T>(response: RequestUrlResponse): ApiResponse<T> {
    return {
      success: false,
      data: null,
      error: {
        code: "MISROUTED_API_REQUEST",
        message:
          "The VaultGuard API endpoint rejected the request before it reached VaultGuard. " +
          "Check the API endpoint in plugin settings; it should point to the VaultGuard REST API " +
          // Derived, not hardcoded: the public export scrubs example.com
          // outside saas-defaults, so a literal example here ships pointing at
          // api.example.com.
          `(for example ${SAAS_DEFAULTS.apiEndpoint || "your VaultGuard endpoint"}, your API Gateway URL, or your API CloudFront base URL). ` +
          "If the endpoint is correct, the deployed API authorizer may need to be refreshed.",
        details: null,
        statusCode: response.status,
      },
      requestId: this.getHeaderValue(response.headers, "x-request-id") ?? "",
    };
  }

  private describeNetworkFailureResponse(response: RequestUrlResponse): string {
    const text = (response.text ?? "").trim();
    if (text.length > 0) {
      return text;
    }

    return "Network request failed with status 0.";
  }

  private async requestWithTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number = 30_000
  ): Promise<T> {
    let timeoutId: ReturnType<typeof setTimeout> | null = null;

    try {
      return await Promise.race([
        promise,
        new Promise<T>((_, reject) => {
          timeoutId = setTimeout(() => {
            reject(new Error("Request timeout"));
          }, timeoutMs);
        }),
      ]);
    } finally {
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
    }
  }

  private getHeaderValue(headers: Record<string, string>, name: string): string | null {
    const matchedHeader = Object.entries(headers).find(
      ([headerName]) => headerName.toLowerCase() === name.toLowerCase()
    );

    return matchedHeader?.[1] ?? null;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Audit System
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Emits an audit event to the VaultGuard backend.
   * Events are fire-and-forget to avoid blocking user operations.
   * @param action - The action being audited
   * @param resourcePath - The affected resource path (if applicable)
   * @param metadata - Additional context metadata
   */
  private async emitAuditEvent(
    action: AuditAction,
    resourcePath: string | null,
    metadata: Record<string, unknown> = {}
  ): Promise<void> {
    // Bridge-lifecycle events (lease created/revoked/rotated, session
    // bound/unbound, tool invoked) are first-class audit rows posted to
    // the dedicated `audit/bridge` endpoint. File/auth/permission events
    // (anything not starting with "bridge.") are already recorded by the
    // backend on the corresponding Lambda call — emitting them here would
    // double-count, so we keep those as debug logs only.
    if (!action.startsWith("bridge.")) {
      this.log(`Audit event handled server-side: ${action} ${resourcePath ?? ""}`.trim());
      return;
    }

    if (!this.apiClient || !this.settings.serverVaultId) {
      this.log(`Audit event skipped (no client/vault): ${action}`);
      return;
    }

    try {
      await this.apiClient.postBridgeAudit(action, resourcePath, metadata);
    } catch (err) {
      // Audit emission is fire-and-forget — never break the caller.
      this.log(
        `Audit emission failed for ${action}: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // File Permission Header
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Initializes the per-file permission header that appears above
   * the editor in every markdown view. Shows the current user's access
   * level, who else has access, and (for admins) a manage-access panel.
   */
  private initFilePermissionHeader(): void {
    const header = initFilePermissionHeaderWiring(this.createPermissionSurfaceContext());
    if (header) {
      this.filePermissionHeader = header;
    }
  }

  /**
   * Re-renders the per-file permission banner after the "Show permission
   * banner in notes" setting toggles, so the change takes effect live without
   * reopening the note. When the toggle is now off, update() tears the banner
   * down via its isEnabled() gate.
   */
  refreshFilePermissionHeader(): void {
    this.filePermissionHeader?.invalidateCache();
    void this.filePermissionHeader?.update({ force: true });
  }

  /**
   * Initializes the read-only editor guard. When the active markdown view
   * targets a file the user lacks WRITE on, the CodeMirror editor is locked
   * via a Compartment so keystrokes never produce changes that would later
   * fail at save time. Re-applied on file-open / active-leaf-change, and
   * `refreshAll()` is called when the permission cache is invalidated.
   */
  private initReadOnlyGuard(): void {
    this.readOnlyGuard = initReadOnlyGuardWiring(this.createPermissionSurfaceContext());
  }

  // ─────────────────────────────────────────────────────────────────────────
  // File Explorer Decorations
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Initializes file explorer decorations that show permission level dots,
   * sharing indicators, and mini avatar stacks on the native file explorer items.
   */
  private initFileExplorerDecorations(): void {
    const decorations = initFileExplorerDecorationsWiring(this.createPermissionSurfaceContext());
    if (decorations) {
      this.fileExplorerDecorations = decorations;
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // VaultGuard Sidebar View
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Reloads the VaultGuard Files sidebar panel if it's open. Called from
   * the same onRulesChanged hooks that invalidate the file-explorer
   * decorations and the read-only guard so the panel's avatar list and
   * level chips stay in sync with rule edits made anywhere else.
   */
  private reloadVaultGuardSidebar(): void {
    reloadVaultGuardSidebarView(this.createSidebarActivationContext());
  }

  private isFileExplorerDecorationDataReady(): boolean {
    const apiClient = this.apiClient as
      | (typeof this.apiClient & { isAuthenticated?: () => boolean })
      | null;
    const apiAuthenticated =
      typeof apiClient?.isAuthenticated === "function"
        ? apiClient.isAuthenticated()
        : Boolean(this.session && apiClient);

    return Boolean(
      this.session &&
      apiAuthenticated &&
      this.settings.serverVaultId
    );
  }

  private syncFileExplorerDecorationsState(refresh = false): void {
    const decorations = this.fileExplorerDecorations as
      | (Partial<Pick<FileExplorerDecorations, "enable" | "disable" | "refresh" | "setDisplayOptions">>)
      | null;
    if (!decorations) return;

    const showMyLevel = this.settings.showMyPermissionLevel;
    const showOthersAccess = this.settings.showOthersAccess;

    // Visual indicator preferences must not disable permission-aware filename
    // hiding. Keep the observer/evaluator active whenever its authenticated
    // vault context is ready, even when both badges are intentionally hidden.
    if (this.isFileExplorerDecorationDataReady()) {
      decorations.setDisplayOptions?.({ showMyLevel, showOthersAccess });
      decorations.enable?.();
      if (refresh) {
        decorations.refresh?.();
      }
      return;
    }

    decorations.disable?.();
  }

  /**
   * Ensures the VaultGuard sidebar exists in the right panel.
   * Called on layout-ready to auto-open it, and idempotent for repeat calls.
   */
  private async ensureVaultGuardSidebar(): Promise<void> {
    await ensureVaultGuardSidebarView(this.createSidebarActivationContext());
  }

  /**
   * Opens (or reveals) the VaultGuard Files sidebar panel and reloads data.
   */
  private async activateVaultGuardSidebar(): Promise<void> {
    await activateVaultGuardSidebarView(this.createSidebarActivationContext());
  }

  // ─────────────────────────────────────────────────────────────────────────
  // UI Methods
  // ─────────────────────────────────────────────────────────────────────────

  private getStatusBarMode(): StatusBarMode {
    const mode = this.settings.statusBarMode;
    if (mode === "full" || mode === "compact" || mode === "hidden") {
      return mode;
    }
    return this.settings.showStatusBar === false ? "hidden" : "full";
  }

  private shouldShowAiChatRibbonIcon(): boolean {
    return typeof this.settings.showAiChatRibbonIcon === "boolean"
      ? this.settings.showAiChatRibbonIcon
      : this.settings.showRibbonIcons !== false;
  }

  private shouldShowPermissionsGraphRibbonIcon(): boolean {
    return typeof this.settings.showPermissionsGraphRibbonIcon === "boolean"
      ? this.settings.showPermissionsGraphRibbonIcon
      : this.settings.showRibbonIcons !== false;
  }

  private setRibbonIconVisibility(el: HTMLElement | null, visible: boolean): void {
    if (!el) return;
    if (visible) {
      el.removeClass("vaultguard-ribbon-hidden");
    } else {
      el.addClass("vaultguard-ribbon-hidden");
    }
  }

  private setGlobalAuthChromeState(loggedIn: boolean): void {
    const doc = getActiveObsidianDocument();
    if (!doc) {
      return;
    }
    doc.body.toggleClass("vaultguard-auth-logged-in", loggedIn);
  }

  /**
   * Enforce the VaultGuard ribbon icon presentation once the layout is ready:
   * force the permanent shield plus retained AI-chat and permissions-graph
   * nodes into a stable shield -> chat -> graph group, then apply each icon's
   * independent visibility class. Retaining the nodes makes hide/show changes
   * symmetric and immediate; no Obsidian reload is needed.
   */
  applyRibbonIconLayout(): void {
    try {
      const shield = this.vaultGuardRibbonEl;
      if (shield && this.vaultGuardChatRibbonEl) {
        shield.insertAdjacentElement("afterend", this.vaultGuardChatRibbonEl);
      }
      const anchor = this.vaultGuardChatRibbonEl ?? shield;
      if (anchor && this.vaultGuardGraphRibbonEl) {
        anchor.insertAdjacentElement("afterend", this.vaultGuardGraphRibbonEl);
      }
      this.setRibbonIconVisibility(
        this.vaultGuardChatRibbonEl,
        this.shouldShowAiChatRibbonIcon(),
      );
      this.setRibbonIconVisibility(
        this.vaultGuardGraphRibbonEl,
        this.shouldShowPermissionsGraphRibbonIcon(),
      );
    } catch (error) {
      this.logError("Applying VaultGuard ribbon icon layout failed", error);
    }
  }

  private updateRibbonAuthIndicator(): void {
    const shieldEl = this.vaultGuardRibbonEl;
    const ribbonEls = [
      this.vaultGuardRibbonEl,
      this.vaultGuardChatRibbonEl,
      this.vaultGuardGraphRibbonEl,
    ].filter((el): el is HTMLElement => Boolean(el));
    this.setGlobalAuthChromeState(Boolean(this.session));
    if (ribbonEls.length === 0) {
      return;
    }

    // A blocked binding is a PAUSED vault that otherwise looks perfectly
    // healthy (quick-260820-nqm). The logged-out state has carried a ribbon
    // badge for a long time; a logged-IN session whose binding is
    // account-changed or wrong-account showed the ordinary connected shield,
    // so once its notice was dismissed nothing outside the status bar said
    // sync had stopped — the same class of bug quick-260819-sd8 fixed for the
    // status bar, still open on the ribbon. Cleared on EVERY other path below
    // (including logged-out, which has its own badge) so it cannot stick.
    shieldEl?.removeClass("vaultguard-ribbon-binding-blocked");

    if (!this.session) {
      for (const el of ribbonEls) {
        el.removeClass("vaultguard-ribbon-auth-logged-in");
      }
      const detail =
        this.lastLogoutAuthState?.detail ??
        this.lastLogoutAuthState?.message ??
        "Not logged in";
      if (shieldEl) {
        shieldEl.addClass("vaultguard-ribbon-auth-logged-out");
        shieldEl.setAttr("aria-label", "VaultGuard Sync: logged out");
        shieldEl.setAttr(
          "title",
          `VaultGuard Sync: ${detail}. Click to log in or open settings.`
        );
      }
      this.vaultGuardChatRibbonEl?.setAttr("aria-label", "VaultGuard Chat");
      this.vaultGuardChatRibbonEl?.setAttr("title", "VaultGuard Chat");
      this.vaultGuardGraphRibbonEl?.setAttr("aria-label", "VaultGuard Permissions");
      this.vaultGuardGraphRibbonEl?.setAttr("title", "VaultGuard Permissions");
      return;
    }

    for (const el of ribbonEls) {
      el.addClass("vaultguard-ribbon-auth-logged-in");
      el.removeClass("vaultguard-ribbon-auth-logged-out");
    }

    const blockedReason =
      this.settings.serverVaultId &&
      (this.vaultBindingAuthorization === "account-changed" ||
        this.vaultBindingAuthorization === "wrong-account")
        ? this.vaultBindingAuthorization
        : null;
    if (blockedReason && shieldEl) {
      const vault = this.settings.serverVaultName
        ? ` ("${this.settings.serverVaultName}")`
        : "";
      shieldEl.addClass("vaultguard-ribbon-binding-blocked");
      shieldEl.setAttr("aria-label", "VaultGuard Sync: paused — account check needed");
      shieldEl.setAttr(
        "title",
        blockedReason === "wrong-account"
          ? `VaultGuard Sync is paused: ${this.describeCurrentAccount()} is not a member of this folder's server vault${vault}. ` +
            "This folder works locally only. Click to resolve."
          : `VaultGuard Sync is paused: this folder's server vault${vault} has not been checked against the signed-in account yet. ` +
            "This folder works locally only. Click to resolve."
      );
    } else {
      shieldEl?.setAttr("aria-label", "VaultGuard Sync");
      shieldEl?.setAttr(
        "title",
        `VaultGuard Sync: connected${
          this.session.email ? ` as ${this.session.email}` : ""
        }.`
      );
    }
    this.vaultGuardChatRibbonEl?.setAttr("aria-label", "VaultGuard Chat");
    this.vaultGuardChatRibbonEl?.setAttr(
      "title",
      "VaultGuard Chat: connected."
    );
    this.vaultGuardGraphRibbonEl?.setAttr("aria-label", "VaultGuard Permissions");
    this.vaultGuardGraphRibbonEl?.setAttr(
      "title",
      "VaultGuard Permissions: connected."
    );
  }

  /**
   * Updates the status bar with current auth and connection state.
   */
  private updateStatusBar(): void {
    if (!this.statusBarEl) {
      return;
    }
    this.i18n.applyToRoot(this.statusBarEl);
    this.statusBarEl.setAttr("role", "status");
    this.statusBarEl.setAttr("aria-live", "polite");
    this.statusBarEl.setAttr("aria-atomic", "true");
    // A compact routine state has its own descriptive label below. Clear it
    // before higher-priority branches so an alarm or auth message can never
    // inherit a stale "connected" label.
    this.statusBarEl.removeAttribute?.("aria-label");

    const longOperation = this.longOperations.getPrimarySnapshot();
    if (longOperation) {
      renderLongOperationStatusBar(this.statusBarEl, longOperation);
      return;
    }
    this.statusBarEl.classList?.remove("vaultguard-long-op-statusbar");
    this.statusBarEl.classList?.remove("vaultguard-status-at-rest-locked");

    // A locked at-rest cipher outranks BOTH connection and login state: the bug
    // is a keychain/KEK mismatch independent of auth, so surface it BEFORE the
    // no-session branch — a logged-out needs-recovery must still alarm (mobile
    // has no status bar, so this is the desktop half of that same signal).
    // D3: fires ONLY on needs-recovery — never the normal Phase-12 `locked`
    // idle-state (it has its own curtain) or the intentional `disabled` state.
    if (this.getAtRestStatus().kind === "needs-recovery") {
      this.statusBarEl.classList?.add("vaultguard-status-at-rest-locked");
      this.statusBarEl.setText(this.i18n.t("status.encryptionLocked"));
      this.statusBarEl.setAttr(
        "title",
        this.i18n.t("status.encryptionLockedDetail")
      );
      return;
    }

    if (!this.session) {
      if (this.lastLogoutAuthState) {
        this.statusBarEl.setText(this.i18n.t("status.loggedOut"));
        this.statusBarEl.setAttr(
          "title",
          `${this.lastLogoutAuthState.title}: ${this.lastLogoutAuthState.detail ?? this.lastLogoutAuthState.message}`
        );
      } else {
        this.statusBarEl.setText(this.i18n.t("status.notLoggedIn"));
        this.statusBarEl.setAttr(
          "title",
          this.i18n.t("status.notConnectedDetail")
        );
      }
      return;
    }

    if (this.permissionWarmupInFlight > 0) {
      this.statusBarEl.setText(this.i18n.t("status.loadingPermissions"));
      this.statusBarEl.setAttr("title", this.i18n.t("status.loadingPermissionsDetail"));
      return;
    }

    // A parked account decision (or a server "no") outranks the connection
    // line: "Connected ✓" was literally true (the API is reachable) but read
    // as "sync is healthy" while every upload and download was gated — the
    // deceptive half of the quick-260819-sd8 finding. Click-to-resolve is
    // wired in applyStatusBarMode.
    const bindingGate = this.getProtectedContentGate();
    if (
      !bindingGate.ok &&
      (bindingGate.reason === "account-changed" || bindingGate.reason === "wrong-account")
    ) {
      this.statusBarEl.setText(this.i18n.t("status.syncPausedAccount"));
      this.statusBarEl.setAttr("title", `${bindingGate.message} Click to resolve.`);
      return;
    }

    const connectionIcon =
      this.connectionState.status === "online"
        ? "\u2713"
        : this.connectionState.status === "reconnecting"
          ? "\u21BB"
          : "\u2717";

    const statusText = this.connectionState.status === "online"
      ? this.i18n.t("status.connected")
      : this.i18n.t("status.offline");

    const fullStatusText = `VaultGuard Sync ${connectionIcon} ${statusText}`;
    if (this.getStatusBarMode() === "compact") {
      this.statusBarEl.setText(`VaultGuard ${connectionIcon}`);
      this.statusBarEl.setAttr("aria-label", fullStatusText);
    } else {
      this.statusBarEl.setText(fullStatusText);
    }
    this.statusBarEl.setAttr(
      "title",
      `VaultGuard Sync: ${statusText}${
        this.session.email ? this.i18n.t("status.asUser", { email: this.session.email }) : ""
      }`
    );
  }

  /**
   * Apply the canonical status-bar mode. Changing between full and compact
   * reuses the existing element; hidden removes it from Obsidian's status bar.
   */
  applyStatusBarMode(): void {
    const show = this.getStatusBarMode() !== "hidden";
    this.settings.showStatusBar = show;
    if (show && !this.statusBarEl) {
      this.statusBarEl = this.addStatusBarItem();
      // Clickable affordance — but ONLY act in the alarm states, so a normal
      // Connected status bar is never hijacked (no-op otherwise).
      this.statusBarEl?.addEventListener("click", () => {
        if (this.getAtRestStatus().kind === "needs-recovery") {
          this.startAtRestRecoveryFlow();
          return;
        }
        if (
          this.vaultBindingAuthorization === "account-changed" ||
          this.vaultBindingAuthorization === "wrong-account"
        ) {
          this.hideAccountChangePausedNotice();
          this.handlePrimaryProtectionAction();
        }
      });
      this.updateStatusBar();
    } else if (!show && this.statusBarEl) {
      this.statusBarEl.remove();
      this.statusBarEl = null;
    } else if (show) {
      this.updateStatusBar();
    }
  }

  /**
   * Backward-compatible boolean adapter for callers from older settings UI.
   * New code should set `settings.statusBarMode` and call
   * `applyStatusBarMode()` instead.
   */
  toggleStatusBar(show: boolean): void {
    const currentMode = this.getStatusBarMode();
    this.settings.showStatusBar = show;
    this.settings.statusBarMode = show
      ? currentMode === "hidden"
        ? "full"
        : currentMode
      : "hidden";
    this.applyStatusBarMode();
  }

  // ─────────────────────────────────────────────────────────────────────────
  // At-rest needs-recovery surfacing (Phase 13 #1)
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * The SINGLE SOURCE OF TRUTH for the at-rest recovery triple. BOTH the
   * pull-getter (view ctx) AND the push hub read this, so the two paths can
   * never drift into a "surfaces say healthy while the cipher is locked" state.
   */
  private computeAtRestRecoveryState(): {
    needsRecovery: boolean;
    reason: string;
    canReset: boolean;
  } {
    const status = this.getAtRestStatus();
    const needsRecovery = status.kind === "needs-recovery";
    return {
      needsRecovery,
      reason: needsRecovery ? status.reason : "",
      // The indicator SHOWS regardless of auth/connectivity (needsRecovery), but
      // the destructive reset needs an authenticated + online session — the
      // server is authoritative for the re-pull. 13-03 consumes canReset to gate
      // the reset CTA; offline/logged-out falls back to the recovery-code path.
      canReset: needsRecovery && !!this.session && this.isOnline(),
    };
  }

  /**
   * The refresh hub: re-assert the persistent #1 surfaces (desktop status bar +
   * every live sidebar leaf) from the cipher's REAL state at every at-rest
   * transition — and, W2, hide the init-time sticky when we've LEFT
   * needs-recovery so recovery via ANY door (a sidebar/status-bar CTA or the
   * settings button) clears it, not only the sticky's own CTA click. It does NOT
   * re-fire a sticky (that is owned by showAtRestRecoveryBanner at init).
   */
  refreshAtRestRecoverySurfaces(): void {
    const state = this.computeAtRestRecoveryState();
    this.updateStatusBar();
    this.pushAtRestRecoveryStateToSidebar(state);
    if (!state.needsRecovery) {
      this.atRestAdapterRuntime?.clearAtRestRecoveryStickyNotice();
      this.atRestMobileRecoveryNoticeShown = false;
      return;
    }
    // P2: the status-bar alarm (updateStatusBar) is desktop-only — Obsidian does
    // not render a status bar on mobile — and the sidebar banner is only visible
    // when the sidebar is open. So on mobile a needs-recovery cipher was silent
    // (the "! never shows on mobile" report). Fire a mobile Notice with a clear
    // CTA, once per needs-recovery episode.
    if (Platform.isMobileApp && !this.atRestMobileRecoveryNoticeShown) {
      this.atRestMobileRecoveryNoticeShown = true;
      new Notice(
        "VaultGuard: local encryption is locked on this device and can't unlock automatically. " +
          "Open Settings → VaultGuard to restore from your recovery code.",
        15000,
      );
    }
  }

  /** Push the current recovery triple into every open sidebar leaf. */
  private pushAtRestRecoveryStateToSidebar(state: {
    needsRecovery: boolean;
    reason: string;
    canReset: boolean;
  }): void {
    const leaves = this.app.workspace.getLeavesOfType(VAULTGUARD_VIEW_TYPE);
    for (const leaf of leaves) {
      const view = leaf.view as unknown as {
        setAtRestRecoveryState?: (s: typeof state) => void;
      };
      view?.setAtRestRecoveryState?.(state);
    }
  }

  /**
   * The single CTA indirection every #1 surface (status bar, sidebar banner,
   * sticky notice) routes through — 13-01 wired every CTA here precisely so this
   * ONE body could be swapped without rewiring anything. It now opens the guided
   * `AtRestRecoveryModal` (door #1), the same modal the Settings → Advanced reset
   * button opens (door #2) — one flow, two doors (D4).
   */
  startAtRestRecoveryFlow(): void {
    // LO-02: don't open a second reset flow while one is already running. The
    // engine's reentrancy guard (CR-01) is the authoritative fix; this removes
    // the concrete trigger surface (and the confusing "second modal opens, then
    // errors with a conflict" UX). Covers every #1 door — the status-bar click,
    // the sidebar "Fix now" button, and the sticky notice all route here.
    if (this.isAtRestResetInFlight()) {
      new Notice(
        "VaultGuard Sync: a local at-rest reset is already running. Please wait for it to finish.",
        6000,
      );
      return;
    }
    new AtRestRecoveryModal(this.app, this).open();
  }

  /**
   * SC4 — after a successful reset, surface the NEW recovery code with a save
   * prompt. The freshly-provisioned LAK has its own per-device code; showing it
   * now is the user's one chance to save the non-destructive restore path for
   * next time (#3 onboarding capture is deferred — this is the minimum bar).
   *
   * Guarded so a stray call can't throw or leak: `exportRecoveryCode()` only
   * works when the cipher is `unlocked` (the state a successful reset lands in),
   * so we no-op otherwise. The code is shown via the existing
   * `AtRestRecoveryCodeModal` and is NEVER written to a log (T-13-10).
   */
  async surfaceNewRecoveryCodeAfterReset(): Promise<void> {
    if (this.getAtRestStatus().kind !== "unlocked") {
      // Reset didn't land unlocked (e.g. an incomplete wipe routed back to
      // needs-recovery) — there is no fresh code to show. Stay silent.
      return;
    }
    let code: string;
    try {
      code = await this.exportAtRestRecoveryCode();
    } catch (err) {
      // Never include the (absent) code in the log — only the error.
      this.logError("Could not export the new recovery code after reset", err);
      return;
    }
    new AtRestRecoveryCodeModal(this.app, {
      code,
      onSaved: () => {
        new Notice(
          "VaultGuard Sync: recovery code saved. You can view it again in Settings → Local at-rest encryption → “View recovery code”.",
          7000,
        );
      },
    }).open();
    new Notice(
      "VaultGuard Sync: local encryption was reset and your files are re-downloading. A NEW recovery code was generated — save it now (Settings → “View recovery code” if you dismiss it).",
      10000,
    );
  }

  /**
   * The non-destructive alternate (D5): open the existing recovery-code restore
   * flow directly. Works offline — the correct per-device code re-wraps the
   * exact LAK. On success, re-assert the surfaces so they clear.
   */
  startAtRestRecoveryFromRecoveryCode(): void {
    new AtRestRestoreModal(this.app, {
      onSubmit: (code, opts) => this.restoreAtRestFromRecoveryCode(code, opts),
      onRestored: () => {
        this.localProtectionBootstrap = { kind: "existing", source: "plugin-envelope" };
        this.localRecoveryNeedsLakValidation = false;
        void this.persistLocalRecoveryCapsule();
        new Notice(
          "VaultGuard Sync: at-rest key restored. Reopening any notes will now load decrypted content.",
          7000
        );
        this.refreshAtRestRecoverySurfaces();
      },
    }).open();
  }

  /**
   * Guarded escape hatch from at-rest `needs-recovery` (Phase 13-02, Feature #2 —
   * engine only; Plan 13-03 wires the confirm modal + settings button to this).
   *
   * From needs-recovery + authenticated + online + a bound serverVaultId: wipe
   * the dead local VG1 ciphertext + stale key material, provision a FRESH LAK,
   * and re-pull every file from the AUTHORITATIVE server under the new key —
   * WITHOUT deleting anything on the server.
   *
   * SAFETY (D1): this GUARD is authoritative — the 13-03 modal/button enablement
   * is only a UX pre-filter. A wrong-state call REFUSES here (no wipe, no key
   * change, no network), so it can never destroy live server data (threat
   * T-13-04). The wipe issues ZERO server DELETEs: files are removed via the raw
   * `originalAdapterMethods.remove` (bypassing interceptedDelete) under the
   * `resettingLocalCache` flag (no-ops the vault delete listeners) + a paused
   * sync loop (threat T-13-03).
   *
   * Does NOT surface the new recovery code — that is 13-03 (UI). Resolves on
   * success; the caller shows the code.
   *
   * SECOND ENTRY CONDITION — `mode: "account-takeover"` (quick-260819-ouh):
   * the same wipe+reprovision+re-pull, entered from a HEALTHY at-rest state
   * when a confirmed different account takes over this folder's binding. The
   * LAK is device-scoped, so adopting without a re-key hands the new account
   * the previous account's entire decrypted local cache (investigation report
   * §9.2). Takeover mode swaps the needs-recovery guard for a pending
   * expectation-mismatch guard, proves membership via the NON-stamping probe
   * (the expectation must survive until the reset completes), and additionally
   * drops the previous account's sync bookkeeping, caches and sealed sessions
   * before the re-pull. The caller (adoptBindingForCurrentAccount) has already
   * collected explicit destructive consent — this method still refuses on any
   * guard miss with zero side effects.
   *
   * THIRD ENTRY CONDITION — `mode: "vault-switch"` (quick-260820-mv4): the
   * SAME account re-points this folder at a DIFFERENT server vault. The local
   * cache belongs to the vault being left, so it must be replaced rather than
   * merged — without this, reconciliation classified the whole previous vault
   * as local-only and offered to upload it into the vault just connected.
   * Identity is unchanged, so the session re-seal and the account-expectation
   * bits of takeover mode do not apply; everything else (wipe, re-key,
   * bookkeeping reset, re-pull) is shared. The pending-switch proof is the
   * caller-supplied `previousVaultId` differing from the now-bound vault, so
   * a stray call on a settled binding refuses like any other guard miss.
   */
  async resetLocalAtRestAndResync(
    options?: {
      mode?: "needs-recovery" | "account-takeover" | "vault-switch";
      /** `vault-switch` only: the vault this folder held before the rebind. */
      previousVaultId?: string;
    }
  ): Promise<void> {
    const mode = options?.mode ?? "needs-recovery";
    const takeover = mode === "account-takeover";
    const vaultSwitch = mode === "vault-switch";
    // Both non-recovery modes replace a local cache that no longer matches the
    // binding, and share every step below except the identity-only ones.
    const rebind = takeover || vaultSwitch;
    // REENTRANCY GUARD (CR-01) — the VERY FIRST thing, before ANY side effect.
    // A second concurrent reset must refuse cleanly: if it fell through to the
    // shared-flag `finally` below it would run `setResettingLocalCache(false)` +
    // `resumeSyncLoop` WHILE the first reset is still raw-removing files,
    // un-suppressing that wipe's `vault.on('delete')` events into server DELETEs
    // (the zero-DELETE-invariant break). This throw touches NOTHING (no flag, no
    // pause, no wipe, no network) — the first reset's state is left intact.
    if (this.atRestResetInFlight) {
      const err = new Error(
        "VaultGuard Sync: a local at-rest reset is already in progress. Wait for it to finish before starting another."
      );
      err.name = "AtRestResetGuardError";
      throw err;
    }

    // GUARD (authoritative, D1). All four conditions are required; any miss
    // refuses with ZERO side effects (no flag flip, no pause, no wipe, no
    // network) so a wrong-state call can never delete live server data. In
    // takeover mode the at-rest-state condition is replaced by a REAL pending
    // account mismatch: the capsule must name a different user than the
    // session, or there is no takeover to perform and a stray call must not
    // wipe a healthy single-account vault.
    const takeoverPending =
      !!this.session &&
      !!this.localRecoveryExpectedAccountUserId &&
      this.localRecoveryExpectedAccountUserId !== this.session.userId;
    // The vault-switch analogue of `takeoverPending`: a REAL rebind must be in
    // flight. Without this a stray call would wipe a folder whose cache
    // matches its binding perfectly.
    const previousVaultId = options?.previousVaultId?.trim() ?? "";
    const vaultSwitchPending =
      !!previousVaultId && previousVaultId !== this.settings.serverVaultId?.trim();
    const modePrecondition = takeover
      ? takeoverPending
      : vaultSwitch
        ? vaultSwitchPending
        : this.getAtRestStatus().kind === "needs-recovery";
    if (
      !this.session ||
      !this.isOnline() ||
      !modePrecondition ||
      !this.settings.serverVaultId
    ) {
      const err = new Error(
        takeover
          ? "VaultGuard Sync: an account-takeover reset needs an authenticated session, an online connection, a bound vault, and a pending account change recorded for this folder. Refusing — no files were changed."
          : vaultSwitch
            ? "VaultGuard Sync: a vault-switch reset needs an authenticated session, an online connection, and a newly bound vault that differs from the one this folder held. Refusing — no files were changed."
            : "VaultGuard Sync: resetting local encryption needs a locked (needs-recovery) at-rest state, an authenticated session, an online connection, and a bound vault. Refusing — no files were changed."
      );
      err.name = "AtRestResetGuardError";
      throw err;
    }

    // A recovered serverVaultId is only a hint. Prove the current account can
    // still read that exact vault before the first destructive local action.
    // This probe changes no local files and prevents a stale/wrong-account
    // binding from wiping VG1 content that cannot subsequently be re-downloaded.
    // A real Obsidian plugin instance always has a vault adapter. The adapter
    // check only preserves the historical isolated reset-unit seam, which has
    // no API client or filesystem; production must prove the exact binding.
    // Takeover mode uses the NON-stamping probe: verifyBoundVaultAuthorization
    // would trip on the still-pending expectation mismatch (that mismatch IS
    // the takeover), and the expectation must not be re-stamped until the
    // reset has actually replaced the previous account's key.
    if (this.app?.vault?.adapter) {
      const authorized = takeover
        ? await this.probeBoundVaultMembership()
        : await this.verifyBoundVaultAuthorization();
      if (!authorized) {
        const err = new Error(
          "VaultGuard Sync: the bound server vault is not authorized for this account. Refusing the local reset — no files were changed.",
        );
        err.name = "AtRestResetGuardError";
        throw err;
      }
    }

    // CROSS-INSTANCE REENTRANCY (SD-07-F4). The latch above is instance-local,
    // so it cannot see a wipe orphaned by a hot reload — the exact case where a
    // second reset is most dangerous, because a still-live zombie wipe holds a
    // raw `remove`. Take the shared lease FIRST in the COMMIT block: it is the
    // first statement past the authoritative guards and before any side effect,
    // so a refusal still changes NOTHING (no flag, no pause, no wipe, no
    // network). The lease is heartbeat-driven (every successful raw remove) and
    // goes stale after 60 s, so a dead instance can never block recovery
    // forever.
    const wipeSuppressionKey = this.wipeSuppressionVaultKey();
    const lease = acquireResetLease(wipeSuppressionKey);
    if (!lease.acquired) {
      const err = new Error(
        `VaultGuard Sync: a local at-rest reset from a previous plugin session may still be running (last progress ${lease.ageMs}ms ago). Wait a moment and try again.`
      );
      err.name = "AtRestResetGuardError";
      throw err;
    }
    this.atRestResetLeaseOwnerId = lease.ownerId;
    if (lease.tookOverStaleLease) {
      this.log(
        "At-rest reset: took over a stale cross-instance reset lease (no progress for over 60s)."
      );
    }

    // COMMIT: past the guards, latch the reentrancy flag so any concurrent door
    // refuses above (CR-01), then raise the delete-suppression flag + pause sync.
    this.atRestResetInFlight = true;
    this.setResettingLocalCache(true);
    // Drop any stragglers from a prior reset (HI-01). Safe: a still-gone path
    // can't fire a delete, and a re-created one already self-cleared. The global
    // flag covers the window until the wipe repopulates this set below. Still
    // safe when we just took over a STALE lease from a possibly-live previous
    // instance: `resettingLocalCache` is up for our entire reset window, which
    // suppresses everything regardless of the set, and we re-wipe the same file
    // population, re-registering each path per-remove.
    clearAllWipedPaths(wipeSuppressionKey);
    this.pauseSyncLoop("at-rest reset");
    try {
      // D2: clear PIN enrollment FIRST. The PIN wrapped the now-dead LAK, so it
      // is stale; a still-enrolled PIN makes initAtRestCipher land LOCKED instead
      // of fresh-provisioning to `unlocked`. disable() clears lak-pin.envelope +
      // pepper with NO unlock precondition (the dead LAK is discarded — there is
      // nothing recoverable to preserve).
      await this.pinLockManager?.disable();

      // Wipe dead VG1 ciphertext + clear key material + fresh-provision the LAK.
      // The wipe uses the single sanctioned raw remove (documented at-rest-rule
      // exception in wipeAndReprovisionLocalAtRest).
      const { wipedPaths } =
        await this.ensureAtRestAdapterRuntimeObject().wipeAndReprovisionLocalAtRest();

      // The LAK was deliberately replaced. Destroy every capsule generation
      // carrying the dead key, classify the fresh plugin envelope as healthy,
      // and persist a new generation before the protected-content gate permits
      // the re-download.
      await this.clearLocalRecoveryCapsule();
      this.localProtectionBootstrap = { kind: "existing", source: "plugin-envelope" };
      this.localRecoveryNeedsLakValidation = false;
      this.localRecoveryExpectedAccountUserId = this.session.userId;
      this.localRecoveryExpectedAccountEmail = this.session.email ?? null;
      if (
        this.app?.vault?.adapter &&
        !(await this.persistLocalRecoveryCapsule())
      ) {
        throw new Error(
          "VaultGuard Sync: the fresh local key was created, but its uninstall recovery capsule could not be persisted. Re-download was paused; reopen VaultGuard and save the new recovery code.",
        );
      }

      // HI-01: keep suppressing each wiped path's delete even AFTER this method's
      // `finally` drops the global flag — a slow/debounced watcher can deliver
      // the wipe's delete event late. Entries self-clear on re-create (the
      // create listener), so a legitimate later user delete still propagates.
      //
      // SD-07-F4: this is idempotent belt-and-braces, NOT the primary
      // registration any more. Each path was already registered the instant its
      // raw remove succeeded, because this loop does not run at all when the
      // wipe throws — or when the wipe promise is orphaned by a hot reload,
      // which is precisely the case the per-remove callback exists to cover.
      for (const p of wipedPaths) {
        this.recordWipedPathAwaitingRepull(p);
      }

      // Settle Obsidian's TFile index so the wiped paths are gone from
      // app.vault.getFiles() before reconcile — else they are SY6 unreadable-
      // skipped and never re-pulled (threat T-13-06).
      await this.settleVaultIndexAfterWipe(wipedPaths);

      if (rebind) {
        // The local cache no longer belongs to this binding — on takeover
        // because the folder changed hands, on a vault switch because it now
        // points at a different vault. Either way none of the previous
        // relationship's bookkeeping may carry over: tombstones would replay
        // the previous queued deletes into the new world (report §3.4); the
        // delta cursor and reconciled-id describe a binding that no longer
        // exists; the permission cache, semantic index and decrypted-media
        // previews all derive from content read under the old key and the old
        // authority (SD-03-F5 rationale — an authority switch invalidates the
        // whole context).
        delete this.settings.deletionTombstones;
        delete this.settings.lastSyncTimestamp;
        delete this.settings.bindingReconciledVaultId;
        this.syncState.lastSync = null;
        await this.saveSettings();
        this.keyLease = null;
        // `!`-declared, assigned in onload — the optional calls keep the
        // orchestrator usable from the isolated reset-unit harness, same as
        // the pinLockManager/runtime members above.
        this.permissionStore?.invalidate();
        this.permissionStore?.emit("changed", { serverConfirmed: true });
        this.ensureAtRestAdapterRuntimeObject().revokeAllResourcePreviews?.();
        if (this.shouldPurgeSemanticIndex()) {
          await this.purgeSemanticRuntime(mode);
        }
        if (takeover) {
          // IDENTITY-ONLY, and therefore takeover-only: sweep EVERY sealed
          // session envelope (PL6 already covers stale binding ids from folder
          // renames — the previous account's refresh token must not survive
          // its own folder), then re-seal the current session under the fresh
          // key material. A vault switch never changes who is signed in, so
          // re-sealing there would churn a perfectly valid session envelope
          // for nothing.
          await this.clearStoredSession();
          await this.persistSession(this.session);
        }
        // The protected-content gate still reads "account-changed" (takeover)
        // or "unverified" (the vault switch set it when the binding flipped).
        // The expectation stamp above recorded the takeover, so this verify
        // sees no mismatch, asks the server once more, lands "verified", and
        // thereby opens the gate the re-pull below runs behind.
        if (!(await this.verifyBoundVaultAuthorization())) {
          throw new Error(
            "VaultGuard Sync: the local key was replaced but the binding could not be re-verified, so the re-download is still pending. Continue as this account from the sidebar to retry.",
          );
        }
      }

      // Re-pull every server file under the fresh LAK (set-based serverOnly
      // pull; binaries included, contingent on the deployed cold-path fix).
      await this.performInitialReconciliation();
    } finally {
      // Restore normal delete propagation + the sync loop even if the re-pull
      // throws, and re-assert the #1 surfaces so they reflect the outcome
      // (cleared on success; still-alarming if the wipe was incomplete and init
      // routed back to needs-recovery).
      this.setResettingLocalCache(false);
      this.resumeSyncLoop("at-rest reset complete");
      this.refreshAtRestRecoverySurfaces();
      // SD-07-F4: release the CROSS-INSTANCE lease, ownership-guarded.
      // `releaseResetLease` is a no-op unless we still own it, so a late
      // `finally` from a superseded instance can never clobber a newer reset's
      // marker. Deliberately does NOT clear the suppression entries — those
      // outlive the reset window by design (HI-01) and self-clear per path when
      // the path is back.
      if (this.atRestResetLeaseOwnerId) {
        releaseResetLease(this.wipeSuppressionVaultKey(), this.atRestResetLeaseOwnerId);
        this.atRestResetLeaseOwnerId = null;
      }
      // Release the reentrancy latch LAST — after the shared flag is down — so a
      // door that fires during this `finally` still refuses (CR-01).
      this.atRestResetInFlight = false;
    }
  }

  /**
   * After the raw-remove wipe, poll until Obsidian's TFile index has dropped
   * every removed path (or a short timeout). `performInitialReconciliation`
   * reads `app.vault.getFiles()`; a lingering just-deleted path would fail its
   * read and be SY6-skipped (unreadable), stranding the server copy instead of
   * re-pulling it. The wipe suppresses only OUR server propagation — Obsidian
   * still updates its own index, we just wait for it to drain.
   */
  private async settleVaultIndexAfterWipe(wipedPaths: string[]): Promise<void> {
    if (wipedPaths.length === 0) return;
    const wanted = new Set(wipedPaths.map((p) => this.normalizeVaultPath(p)));
    const deadline = Date.now() + 3000;
    for (;;) {
      const stillListed = this.app.vault
        .getFiles()
        .some((f) => wanted.has(this.normalizeVaultPath(f.path)));
      if (!stillListed) return;
      if (Date.now() >= deadline) return;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }

  /**
   * Refreshes file explorer decorations (permission dots + avatar chips).
   * Called when the "Show my permission level" or "Show who else has access"
   * settings change.
   */
  refreshFileExplorerDecorations(): void {
    this.syncFileExplorerDecorationsState(true);
  }

  private openAdminModal(
    initialTab: "users" | "permissions" | "audit" | "settings" | "recovery",
    permissionsUserId: string | null,
    permissionsInitialSearch?: string,
  ): void {
    const apiClient = this.apiClient;
    if (!apiClient) return;
    const context = this.createAdminModalContext(permissionsInitialSearch);
    void import("../admin/admin-modal")
      .then(({ AdminModal }) => {
        new AdminModal(
          this.app,
          apiClient,
          initialTab,
          permissionsUserId,
          context,
        ).open();
      })
      .catch((error) => {
        this.logError("Could not load organization administration", error);
        new Notice("VaultGuard Sync: organization administration could not be opened.");
      });
  }

  /**
   * Shows a modal displaying the current user's permissions across the vault.
   */
  private showPermissionsModal(): void {
    if (!this.session) {
      this.showLoginRequiredNotice("view permissions");
      return;
    }

    if (!this.apiClient) {
      new Notice("VaultGuard Sync: Please configure the API endpoint in settings first.");
      return;
    }

    this.openAdminModal("permissions", this.session.userId);
  }

  /**
   * Opens the vault-wide permission-rules manager (admin-panel-style table:
   * list every rule, add / edit / delete with principal dropdowns, level,
   * priority, and expiry). Distinct from the per-file controls in the header.
   */
  showPermissionRulesModal(initialSearch?: string): void {
    if (this.isLocalProjectMemoryModeEnabled()) {
      new Notice("VaultGuard Sync: organization permission rules are disabled in Local Project Memory Mode.");
      return;
    }
    if (!this.session) {
      this.showLoginRequiredNotice("view permissions");
      return;
    }
    if (!this.apiClient) {
      new Notice("VaultGuard Sync: Please configure the API endpoint in settings first.");
      return;
    }
    if (!this.settings.serverVaultId) {
      new Notice(
        "VaultGuard Sync: Bind this folder to a server vault first — open the VaultGuard sidebar to pick one."
      );
      return;
    }
    // Opens the Organization Admin modal at the "Vault access" tab, which now
    // renders the full permission-rules table (PermissionRulesView).
    this.openAdminModal("permissions", null, initialSearch);
  }

  /**
   * Refresh every permission surface (file header, file-explorer decorations,
   * sidebar) after vault-wide rules change in the Manage Permissions modal.
   * Drops the warmed rule cache, re-warms from the server, and fires the
   * shared "changed" bus event the per-file flow already uses.
   */
  notifyPermissionRulesChanged(): void {
    this.permissionStore.invalidate();
    this.permissionStore.emit("changed", {
      serverConfirmed: true,
      semanticAuthorityChanged: true,
    });
    void this.runPermissionWarmup().catch((err) =>
      this.logError("Permission re-warm after rule change failed", err)
    );
  }

  private createAdminModalContext(permissionsInitialSearch?: string) {
    return {
      orgId: this.settings.organizationId,
      orgSlug: this.settings.orgSlug,
      currentVaultId: this.settings.serverVaultId || undefined,
      currentUser: this.session
        ? {
            id: this.session.userId,
            displayName: this.session.displayName,
            email: this.session.email,
            orgRole: this.session.role,
            roles: this.session.roles,
            vaultRole: this.vaultMemberRole,
          }
        : undefined,
      features: this.serverFeatures ?? undefined,
      permissionsInitialSearch,
      onPermissionsChanged: () => this.notifyPermissionRulesChanged(),
    };
  }

  /**
   * Shows the admin panel for managing users and permissions.
   * Only accessible to users with admin or owner roles.
   */
  private showAdminPanel(): void {
    if (this.isLocalProjectMemoryModeEnabled()) {
      new Notice("VaultGuard Sync: organization management is disabled in Local Project Memory Mode.");
      return;
    }
    if (!this.session) {
      return;
    }

    if (!this.apiClient) {
      new Notice("VaultGuard Sync: Please configure the API endpoint in settings first.");
      return;
    }

    this.openAdminModal("users", null);
  }

  /**
   * Opens the admin modal preset to the audit log tab. Admin/owner only — the
   * caller (command checkCallback or ribbon-menu item) gates on role.
   */
  private openAuditLog(): void {
    if (this.isLocalProjectMemoryModeEnabled()) {
      new Notice("VaultGuard Sync: audit log is disabled in Local Project Memory Mode.");
      return;
    }
    if (!this.session) return;
    if (!this.apiClient) {
      new Notice("VaultGuard Sync: not connected to a server.");
      return;
    }
    // 4th arg is permissionsUserId; passing it puts AdminModal in
    // single-user-permissions mode (only "My vault access" tab shown), which
    // would hide the audit tab and override initialTab="audit" back to
    // "permissions" (admin-modal.ts:211). Pass null to get the full admin
    // view with all 5 tabs including audit.
    this.openAdminModal("audit", null);
  }

  /**
   * Opens the org-wide audit logging configuration modal where an admin can
   * pick which audit actions are recorded. Admin-only; reachable from the
   * VaultGuard ribbon menu beside "Audit log".
   */
  private openAuditConfig(): void {
    if (this.isLocalProjectMemoryModeEnabled()) {
      new Notice("VaultGuard Sync: audit settings are disabled in Local Project Memory Mode.");
      return;
    }
    if (!this.session) return;
    if (!this.apiClient) {
      new Notice("VaultGuard Sync: not connected to a server.");
      return;
    }
    const apiClient = this.apiClient;
    void import("../admin/audit-config-modal")
      .then(({ AuditConfigModal }) => new AuditConfigModal(this.app, apiClient).open())
      .catch((error) => {
        this.logError("Could not load audit settings", error);
        new Notice("VaultGuard Sync: audit settings could not be opened.");
      });
  }

  /**
   * Opens the web admin panel in a new browser tab. On Community Edition
   * servers (featureEnabled('webAdmin') === false) shows ProUpsellModal
   * instead of navigating.
   */
  private openWebAdminPanel(): void {
    if (this.isLocalProjectMemoryModeEnabled()) {
      new Notice("VaultGuard Sync: web admin is disabled in Local Project Memory Mode.");
      return;
    }
    if (!this.session) return;
    if (!this.featureEnabled("webAdmin")) {
      void import("../ui/pro-upsell-modal")
        .then(({ ProUpsellModal }) => new ProUpsellModal(this.app, "webAdmin").open())
        .catch((error) => this.logError("Could not load the upgrade dialog", error));
      return;
    }
    // The base URL comes from saas-defaults because the public export scrubs
    // example.com everywhere else — a literal here ships as a dead
    // admin.example.com link.
    const base = SAAS_DEFAULTS.adminBaseUrl.trim().replace(/\/+$/, "");
    if (!base) {
      new Notice("VaultGuard Sync: no hosted admin panel is configured for this build.");
      return;
    }
    const slug = this.settings.orgSlug?.trim() || "";
    const url = slug ? `${base}/${encodeURIComponent(slug)}` : base;
    window.open(url, "_blank", "noopener,noreferrer");
  }

  /**
   * Shows permissions for a specific file or folder path in a dedicated modal.
   * Displays who has access, current user's level, and admin controls.
   */
  private showPathPermissionsModal(path: string, isFolder: boolean, initialExplain = false): void {
    if (this.isLocalProjectMemoryModeEnabled()) {
      new Notice("VaultGuard Sync: sharing and permission views are disabled in Local Project Memory Mode.");
      return;
    }
    if (!this.session || !this.apiClient) {
      if (!this.session) {
        this.showLoginRequiredNotice("view permissions");
      } else {
        new Notice("VaultGuard Sync: Please configure the API endpoint in settings first.");
      }
      return;
    }

    const modal = new PathPermissionsModal({
      app: this.app,
      apiClient: this.apiClient,
      path,
      isFolder,
      isAdmin: this.isEffectiveAdmin(),
      currentUserId: this.session.userId,
      // Use effective role so a vault admin (org member elsewhere) gets
      // the admin-side controls in the path-permissions modal.
      currentUserRole: this.getEffectiveUiRole(),
      // Mirrors backend OrgSettings.allowAdminPerFileRestrictions so the
      // modal lets you edit a vault admin's per-file level when the org
      // opted in.
      allowAdminPerFileRestrictions:
        this.orgSettings?.allowAdminPerFileRestrictions === true,
      initialExplain,
      onRulesChanged: () => {
        // Phase 9: full invalidation via the bus. Rules edited from the
        // modal can include glob patterns (e.g. deleting an inherited
        // `/docs/**` rule from this file's panel), so per-path invalidation
        // would leave sibling files showing stale colors. The four init*
        // bus subscriptions handle the surface invalidations.
        this.permissionStore.emit("changed", {
          serverConfirmed: true,
          semanticAuthorityChanged: true,
        });
      },
      onOpenRulesOverview: (filter) => this.showPermissionRulesModal(filter),
    });
    modal.open();
  }

  /**
   * Opens the permission rule dialog pre-filled with a specific path.
   * Appends a trailing slash for folders so the rule applies recursively.
   */
  private showAddPermissionForPath(path: string, isFolder: boolean): void {
    if (this.isLocalProjectMemoryModeEnabled()) {
      new Notice("VaultGuard Sync: permission editing is disabled in Local Project Memory Mode.");
      return;
    }
    if (!this.apiClient) {
      new Notice("VaultGuard Sync: Please configure the API endpoint in settings first.");
      return;
    }

    const rulePath = isFolder ? (path.endsWith("/") ? path : path + "/") : path;
    const apiClient = this.apiClient;
    void import("../admin/permission-editor")
      .then(({ PermissionEditor }) => {
        const editor = new PermissionEditor(this.app, apiClient);
        editor.showAddRuleForPath(rulePath, async () => {
          // Phase 9: single bus emit replaces the 5-call fan-out.
          this.permissionStore.emit("changed", {
            serverConfirmed: true,
            semanticAuthorityChanged: true,
          });
        });
      })
      .catch((error) => {
        this.logError("Could not load permission editing", error);
        new Notice("VaultGuard Sync: permission editing could not be opened.");
      });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Cache Management
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Resets this device's persisted and in-memory synchronization state without
   * deleting vault files. Used by the user-confirmed recovery control.
   */
  async clearLocalCache(): Promise<void> {
    const queuedOperationsBeforeReset = [...this.offlineQueue];
    const remoteFileStateBeforeReset = this.remoteFileState.snapshot();

    if (this.offlineQueuePersistTimer) {
      clearTimeout(this.offlineQueuePersistTimer);
      this.offlineQueuePersistTimer = null;
    }
    if (this.remoteFileStatePersistTimer) {
      clearTimeout(this.remoteFileStatePersistTimer);
      this.remoteFileStatePersistTimer = null;
    }

    this.offlineQueue = [];
    this.remoteFileState.clear();

    try {
      // Reset is a user-confirmed destructive action, so do not use the normal
      // one-second debounce. Queue deletion behind every older persistence task
      // before reporting success, so an in-flight writer cannot resurrect stale
      // state after reset. Mutations that begin after these tasks are enqueued
      // remain ordered after the reset boundary and persist normally.
      const [remoteDeletion, queueDeletion] = await Promise.allSettled([
        this.enqueueRemoteFileStatePersist(() =>
          this.removePersistedEnvelope(this.remoteFileStateEnvelopePath())
        ),
        this.enqueueOfflineQueuePersist(() =>
          this.removePersistedEnvelope(this.offlineQueueEnvelopePath())
        ),
      ]);
      if (remoteDeletion.status === "rejected") throw remoteDeletion.reason;
      if (queueDeletion.status === "rejected") throw queueDeletion.reason;
    } catch (error) {
      // Keep the in-memory state aligned with the still-authoritative persisted
      // state and schedule a best-effort rewrite if one envelope was already
      // removed before the other operation failed. Preserve any new mutations
      // that arrived after the reset boundary as well as the pre-reset state.
      this.offlineQueue = [...queuedOperationsBeforeReset, ...this.offlineQueue];
      const remoteFileStateAfterResetStarted = this.remoteFileState.snapshot();
      const restoredRemoteEntries = new Map(
        remoteFileStateBeforeReset.entries.map((entry) => [entry.path, entry])
      );
      for (const entry of remoteFileStateAfterResetStarted.entries) {
        restoredRemoteEntries.set(entry.path, entry);
      }
      this.remoteFileState.load(Array.from(restoredRemoteEntries.values()));
      this.scheduleOfflineQueuePersist();
      this.scheduleRemoteFileStatePersist();
      this.logError("Failed to reset persisted local sync state", error);
      throw error;
    }

    // Phase 9: SILENT — teardown path, surfaces will be torn down
    // immediately by surrounding lifecycle code. No subscribers to notify.
    this.permissionStore.invalidate();
    this.readOnlyGuard?.refreshAll();
    this.syncState = {
      lastSync: null,
      pendingChanges: 0,
      conflicts: [],
      status: "idle",
      bytesUploaded: 0,
      bytesDownloaded: 0,
      lastError: null,
    };
    new Notice("VaultGuard Sync: Local sync state reset. Vault files were not deleted.");
    this.log("Local sync state reset.");
  }

  /**
   * Clears all sensitive data from memory.
   * Called on plugin unload and forced logout.
   */
  private clearSensitiveData(persistClearedState = true): void {
    // Covers the teardown paths that do not go through `forceLogout` (unload,
    // auto-lock). Bumping twice on the logout path is harmless — only a CHANGE
    // in the counter is meaningful, never its value.
    this.beginSessionEpoch();
    this.session = null;
    this.keyLease = null;
    // Drop the API client's cached JWTs so no privileged request (an open
    // admin/share modal, a queued call) can reuse the idToken after logout or
    // auto-lock. getAuthHeaders then fails closed until the user re-authenticates.
    this.apiClient?.clearTokens();
    // Revoke media-preview blob URLs decrypted during the session so an already-
    // open image/PDF pane can't keep showing decrypted content after logout/unload
    // (the getResourcePath session gate stops re-decrypting; this clears what's
    // already decrypted). Use the nullable field directly — teardown must never
    // instantiate the runtime via ensureAtRestAdapterRuntimeObject().
    this.atRestAdapterRuntime?.revokeResourcePreviews();
    this.orgSettings = null;
    this.vaultMemberRole = null;
    this.stopKeyRenewalMonitor();
    this.stopHeartbeatMonitor();
    this.stopAutoLockTimer();
    // Phase 9: SILENT — teardown path; no subscribers to notify.
    this.permissionStore.invalidate();
    this.offlineQueue = [];
    this.remoteFileState.clear();
    // SY5: an empty queue removes the persisted envelope, so a logout/lock
    // never leaves another user's queued edits on disk for the next session.
    if (persistClearedState) {
      this.scheduleOfflineQueuePersist();
      this.scheduleRemoteFileStatePersist();
    }
    this.log("Sensitive data cleared from memory.");
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Storage Helpers
  // ─────────────────────────────────────────────────────────────────────────

  // ── SY5: offline-queue persistence ──────────────────────────────────────
  // Queued offline writes carry PLAINTEXT vault content, so they can never
  // go into data.json (excluded from at-rest encryption). They persist as a
  // LAK-encrypted envelope in the plugin's own config dir — the same
  // mechanism as agent-leases.envelope — and are restored on load, so
  // limited-access/offline edits survive a restart.

  private offlineQueueEnvelopePath(): string {
    const pluginId = this.manifest?.id ?? "vaultguard-sync";
    return `${this.app.vault.configDir}/plugins/${pluginId}/offline-queue.envelope`;
  }

  // ── Phase 12: PIN-lock storage wiring ───────────────────────────────────────

  /**
   * Path of the PIN-wrapped LAK envelope. Unlike offline-queue.envelope this is
   * a RAW file (NOT LAK-encrypted): it WRAPS the LAK and must be readable while
   * the vault is locked. It lives under the excluded plugin folder
   * (`.obsidian/plugins/<id>/…`), so the Local At-Rest Rule's exclusion applies —
   * the sanctioned raw adapter.read/write/remove exception (mirrors lak.envelope).
   */
  private lakPinEnvelopePath(): string {
    const pluginId = this.manifest?.id ?? "vaultguard-sync";
    return `${this.app.vault.configDir}/plugins/${pluginId}/lak-pin.envelope`;
  }

  /** Non-secret PIN-lock slice from data.json, defaulted when absent (not enrolled). */
  private pinLockSettingsSlice(): {
    pepperWrapped?: string;
    enrolled: boolean;
    failedAttempts: number;
    lockedUntil: number | null;
  } {
    const cur = this.settings.pinLock;
    return {
      pepperWrapped: cur?.pepperWrapped,
      enrolled: cur?.enrolled ?? false,
      failedAttempts: cur?.failedAttempts ?? 0,
      lockedUntil: cur?.lockedUntil ?? null,
    };
  }

  /**
   * Construct the PinLockManager, wiring its storage seam to:
   *  - `lak-pin.envelope` (raw file under the excluded plugin folder) for the
   *    PIN-wrapped LAK envelope,
   *  - the safeStorage-wrapped device pepper + the persisted rate-limit counter
   *    in data.json (`this.settings.pinLock`),
   *  - `probeSafeStorage()` for the OS-keychain pepper wrap (degraded tier when
   *    unavailable, per PinLockManager).
   *
   * Called in onload BEFORE initAtRestCipher so the adapter's PIN-lock pre-check
   * (`isPinLockEnrolled`) sees a live manager. Enroll/disable UI is Plan 05; this
   * plan only reads the manager (unlock + isEnrolled).
   */
  private initPinLockManager(): void {
    const adapter = this.app.vault.adapter;
    const storage: PinLockStorage = {
      readEnvelope: async () => {
        const path = this.lakPinEnvelopePath();
        try {
          if (!(await adapter.exists(path))) return null;
          const raw = await adapter.read(path);
          return raw && raw.trim().length > 0 ? raw : null;
        } catch (err) {
          this.logError("Reading lak-pin.envelope failed", err);
          return null;
        }
      },
      writeEnvelope: async (blob) => {
        const path = this.lakPinEnvelopePath();
        await this.ensureParentFoldersForPath(path);
        await adapter.write(path, blob);
      },
      clearEnvelope: async () => {
        const path = this.lakPinEnvelopePath();
        try {
          if (await adapter.exists(path)) await adapter.remove(path);
        } catch (err) {
          this.logError("Removing lak-pin.envelope failed", err);
        }
      },
      readPepper: async () => this.settings.pinLock?.pepperWrapped ?? null,
      writePepper: async (blob) => {
        this.settings.pinLock = { ...this.pinLockSettingsSlice(), pepperWrapped: blob };
        await this.savePluginData();
      },
      clearPepper: async () => {
        this.settings.pinLock = { ...this.pinLockSettingsSlice(), pepperWrapped: undefined };
        await this.savePluginData();
      },
      loadPinState: () => {
        const slice = this.pinLockSettingsSlice();
        return {
          enrolled: slice.enrolled,
          failedAttempts: slice.failedAttempts,
          lockedUntil: slice.lockedUntil,
        };
      },
      savePinState: async (state) => {
        this.settings.pinLock = {
          ...this.pinLockSettingsSlice(),
          enrolled: state.enrolled,
          failedAttempts: state.failedAttempts,
          lockedUntil: state.lockedUntil,
        };
        await this.savePluginData();
      },
    };
    this.pinLockManager = new PinLockManager(storage, probeSafeStorage());
  }

  private scheduleOfflineQueuePersist(): void {
    if (this.unloading) return;
    if (this.offlineQueuePersistTimer) clearTimeout(this.offlineQueuePersistTimer);
    this.offlineQueuePersistTimer = setTimeout(() => {
      this.offlineQueuePersistTimer = null;
      void this.enqueueOfflineQueuePersist(() => this.persistOfflineQueue());
    }, 1_000);
  }

  private enqueueOfflineQueuePersist(task: () => Promise<void>): Promise<void> {
    const run = this.offlineQueuePersistTail.then(task);
    this.offlineQueuePersistTail = run.catch(() => undefined);
    return run;
  }

  private async removePersistedEnvelope(path: string): Promise<void> {
    if (await this.app.vault.adapter.exists(path)) {
      await this.app.vault.adapter.remove(path);
    }
  }

  private async persistOfflineQueue(): Promise<void> {
    const path = this.offlineQueueEnvelopePath();
    try {
      if (this.offlineQueue.length === 0) {
        await this.removePersistedEnvelope(path);
        return;
      }
      // Fail closed: never write queued plaintext unencrypted. If the cipher
      // or binary writes are unavailable, the queue simply stays memory-only
      // for this launch (the pre-fix behavior).
      if (!this.atRestCipher?.isReady() || !this.originalAdapterMethods.writeBinary) {
        return;
      }
      await this.ensureParentFoldersForPath(path);
      // BIN-A / D-09: always write envelope v2 from now on. v2 entries may carry
      // `encoding: "base64"` + `contentType` for binary payloads; text entries
      // are shape-identical to v1, so a v2 envelope holding only text ops is a
      // strict superset a v1 reader would still find well-formed apart from the
      // version tag (see the load gate / L11 downgrade note).
      const envelope = await this.atRestCipher.encryptString(
        JSON.stringify({ v: 2, ops: this.offlineQueue })
      );
      await this.originalAdapterMethods.writeBinary(path, envelope);
    } catch (error) {
      this.logError("Failed to persist the offline queue envelope", error);
    }
  }

  private async loadPersistedOfflineQueue(): Promise<void> {
    const readBinary = this.originalAdapterMethods.readBinary;
    if (!readBinary) return;
    const path = this.offlineQueueEnvelopePath();
    try {
      if (!(await this.app.vault.adapter.exists(path))) return;
      await this.waitForCipherInit(10_000);
      if (!this.atRestCipher?.isReady()) {
        // Keep the envelope on disk — it can still be restored next launch.
        this.log("Offline queue envelope present but the at-rest cipher is not ready; leaving it for the next launch.");
        return;
      }
      const plaintext = await this.atRestCipher.decryptString(await readBinary(path));
      const parsed = JSON.parse(plaintext) as {
        v?: number;
        ops?: Array<{
          operation?: string;
          path?: string;
          data?: string;
          timestamp?: string;
          encoding?: string;
          contentType?: string;
          baseVersionId?: string;
          baseHash?: string;
          // SD-06-F1 / DECISION 9: `unknown`, not MutationIntent — this value
          // comes off disk and is attacker-influenced on a compromised device.
          // It is validated field-by-field below before it can steer a write.
          intent?: unknown;
        }>;
      };
      // BIN-A / D-09 / L11: accept BOTH v1 (all-text, older builds) and v2
      // (may carry binary base64 entries). Write is always v2 (see persist).
      // NOTE (accepted downgrade, do not "fix"): a v1-only OLDER plugin reading a
      // v2 envelope hits its strict `v !== 1` gate, silently skips restore, and
      // leaves the envelope on disk for a newer build to pick up next launch.
      if ((parsed?.v !== 1 && parsed?.v !== 2) || !Array.isArray(parsed.ops)) return;
      const restored: OfflineQueueOperation[] = [];
      for (const op of parsed.ops) {
        if (
          !op ||
          (op.operation !== "write" && op.operation !== "delete") ||
          typeof op.path !== "string" ||
          op.path.length === 0 ||
          typeof op.timestamp !== "string"
        ) {
          continue;
        }
        // Fail closed against unknown/future encodings: only an undefined ("text")
        // or "base64" encoding can be replayed safely by this build. Anything else
        // drops THAT entry (never flush a mis-encoded op as text) while valid
        // siblings survive.
        if (op.encoding !== undefined && op.encoding !== "base64") {
          this.logError(
            `Dropping restored offline op ${op.operation} "${op.path}" — unknown queue encoding "${op.encoding}"`,
            new Error("unknown offline-queue entry encoding")
          );
          continue;
        }
        const entry: OfflineQueueOperation = {
          operation: op.operation,
          path: op.path,
          timestamp: op.timestamp,
        };
        if (typeof op.data === "string") entry.data = op.data;
        if (op.encoding === "base64") entry.encoding = "base64";
        if (typeof op.contentType === "string") entry.contentType = op.contentType;
        // Version-guard fields (theirs) travel with the entry so a replay after a
        // restart still carries its optimistic-concurrency baseline.
        if (typeof op.baseVersionId === "string") entry.baseVersionId = op.baseVersionId;
        if (typeof op.baseHash === "string") entry.baseHash = op.baseHash;
        // SD-06-F1 / DECISION 9 — typed validation of the persisted intent.
        //
        // The policy here is per-FIELD, deliberately UNLIKE the unknown-encoding
        // drop above, which is per-ENTRY. The asymmetry is the whole point:
        // ignoring an `encoding` CORRUPTS data (a base64 payload replayed as
        // text is a mangled server copy), while ignoring an `intent` merely
        // degrades to today's behavior — the op replays through the flush-time
        // store fallback and lands in the legacy lane. So a malformed intent
        // drops the FIELD and KEEPS the op; a malformed encoding drops the op.
        //
        // Only the four literal kinds are accepted, and `expect-version`
        // additionally requires a non-empty string versionId — an
        // `{kind:"expect-version"}` with a missing/blank version would otherwise
        // reach buildWriteBody and emit an invalid guard.
        const rawIntent = op.intent;
        if (rawIntent !== undefined) {
          const candidate = rawIntent as { kind?: unknown; versionId?: unknown };
          const kind =
            typeof rawIntent === "object" && rawIntent !== null ? candidate.kind : undefined;
          if (
            kind === "must-be-absent" ||
            kind === "force" ||
            kind === "unknown" ||
            (kind === "expect-version" &&
              typeof candidate.versionId === "string" &&
              candidate.versionId.length > 0)
          ) {
            entry.intent =
              kind === "expect-version"
                ? { kind, versionId: candidate.versionId as string }
                : { kind };
          } else {
            this.logError(
              `Dropping the persisted mutation intent on restored offline op ${op.operation} "${op.path}" — malformed value; the op is KEPT and replays through the store fallback`,
              new Error("malformed offline-queue entry intent")
            );
          }
        }
        restored.push(entry);
      }
      if (restored.length === 0) return;
      // Ops queued during this launch (while the load ran) are NEWER — they
      // win per-path; restored ops go first so the flush stays chronological.
      const livePaths = new Set(this.offlineQueue.map((op) => op.path));
      this.offlineQueue = [
        ...restored.filter((op) => !livePaths.has(op.path)),
        ...this.offlineQueue,
      ];
      this.log(`Restored ${restored.length} queued offline operation(s) from the envelope.`);
    } catch (error) {
      this.logError("Failed to restore the offline queue envelope", error);
    }
  }

  private remoteFileStateEnvelopePath(): string {
    const pluginId = this.manifest?.id ?? "vaultguard-sync";
    return `${this.app.vault.configDir}/plugins/${pluginId}/remote-file-state.envelope`;
  }

  private scheduleRemoteFileStatePersist(): void {
    if (this.unloading) return;
    if (this.remoteFileStatePersistTimer) clearTimeout(this.remoteFileStatePersistTimer);
    this.remoteFileStatePersistTimer = setTimeout(() => {
      this.remoteFileStatePersistTimer = null;
      void this.enqueueRemoteFileStatePersist(() => this.persistRemoteFileState());
    }, 1_000);
  }

  private enqueueRemoteFileStatePersist(task: () => Promise<void>): Promise<void> {
    const run = this.remoteFileStatePersistTail.then(task);
    this.remoteFileStatePersistTail = run.catch(() => undefined);
    return run;
  }

  private async persistRemoteFileState(): Promise<void> {
    const path = this.remoteFileStateEnvelopePath();
    try {
      if (this.remoteFileState.isEmpty()) {
        await this.removePersistedEnvelope(path);
        return;
      }
      if (!this.atRestCipher?.isReady() || !this.originalAdapterMethods.writeBinary) {
        return;
      }
      await this.ensureParentFoldersForPath(path);
      const envelope = await this.atRestCipher.encryptString(
        JSON.stringify(this.remoteFileState.snapshot())
      );
      await this.originalAdapterMethods.writeBinary(path, envelope);
    } catch (error) {
      this.logError("Failed to persist the remote file state envelope", error);
    }
  }

  private async loadPersistedRemoteFileState(): Promise<void> {
    const readBinary = this.originalAdapterMethods.readBinary;
    if (!readBinary) return;
    const path = this.remoteFileStateEnvelopePath();
    try {
      if (!(await this.app.vault.adapter.exists(path))) return;
      await this.waitForCipherInit(10_000);
      if (!this.atRestCipher?.isReady()) {
        this.log("Remote file state envelope present but the at-rest cipher is not ready; leaving it for the next launch.");
        return;
      }
      const plaintext = await this.atRestCipher.decryptString(await readBinary(path));
      const parsed = JSON.parse(plaintext) as {
        v?: number;
        entries?: RemoteFileStateEntry[];
      };
      if (parsed?.v !== 1 || !Array.isArray(parsed.entries)) return;
      this.remoteFileState.load(parsed.entries);
      this.log(`Restored remote version state for ${parsed.entries.length} path(s).`);
    } catch (error) {
      this.logError("Failed to restore the remote file state envelope", error);
    }
  }

  private async savePluginData(): Promise<void> {
    await this.getSettingsRuntime().savePluginData();
  }

  private async computeDerivedVaultBindingId(): Promise<string> {
    return this.getSettingsRuntime().computeDerivedVaultBindingId();
  }

  private protectSessionForStorage(session: UserSession) {
    return this.getSettingsRuntime().protectSessionForStorage(session);
  }

  private async protectSessionWithAtRest(session: UserSession) {
    return this.getSettingsRuntime().protectSessionWithAtRest(session);
  }

  private unprotectStoredSession(value: unknown): UserSession | null {
    return this.getSettingsRuntime().unprotectStoredSession(value);
  }

  private async unprotectAtRestSession(value: unknown): Promise<UserSession | null> {
    return this.getSettingsRuntime().unprotectAtRestSession(value);
  }

  private loadSessionFromStore(): UserSession | null {
    return this.getSettingsRuntime().loadSessionFromStore();
  }

  private async loadAtRestSessionFromStore(): Promise<UserSession | null> {
    return this.getSettingsRuntime().loadAtRestSessionFromStore();
  }

  private async persistSession(session: UserSession): Promise<void> {
    await this.getSettingsRuntime().persistSession(session);
  }

  private async clearStoredSession(): Promise<void> {
    await this.getSettingsRuntime().clearStoredSession();
  }

  private normalizePersistedSessions(
    storedSessions: Record<string, unknown> | undefined
  ): Record<string, unknown> {
    return this.getSettingsRuntime().normalizePersistedSessions(storedSessions);
  }

  private materializeSession(parsed: Partial<UserSession> | null): UserSession | null {
    return this.getSettingsRuntime().materializeSession(parsed);
  }
  // Utility Methods
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Computes a SHA-256 hash of the given content.
   * @param content - The content to hash
   * @returns Hex-encoded hash string
   */
  private async computeHash(content: string): Promise<string> {
    const encoder = new TextEncoder();
    const data = encoder.encode(content);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  /**
   * Byte variant of {@link computeHash} (BIN-A / D-02). SHA-256 over the raw
   * bytes with the identical lowercase-hex mapping, so
   * `computeHashBytes(new TextEncoder().encode(s).buffer)` === `computeHash(s)`.
   * @param content - The bytes to hash
   * @returns Hex-encoded hash string
   */
  private async computeHashBytes(content: ArrayBuffer): Promise<string> {
    const hashBuffer = await crypto.subtle.digest("SHA-256", content);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  /**
   * Converts a base64 string to a Uint8Array.
   * @param base64 - Base64-encoded string
   * @returns Decoded byte array
   */
  private base64ToBytes(base64: string): Uint8Array {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  /**
   * Converts a Uint8Array to a base64 string.
   * @param bytes - Byte array to encode
   * @returns Base64-encoded string
   */
  private bytesToBase64(bytes: Uint8Array): string {
    // L3 (BIN-A): chunked conversion. The old per-byte `+=` loop is O(n) with a
    // ~3-4x peak-memory spike at 7 MB (UTF-16 doubling). Build the binary string
    // in 0x8000-byte slices via String.fromCharCode.apply, then a single btoa.
    // Browser-native only — NO Node Buffer (mobile constraint, see client.ts:384).
    // Output is byte-identical to the old implementation.
    const CHUNK_SIZE = 0x8000;
    let binary = "";
    for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
      const chunk = bytes.subarray(i, i + CHUNK_SIZE);
      binary += String.fromCharCode.apply(null, chunk as unknown as number[]);
    }
    return btoa(binary);
  }


  /**
   * Checks if an error is a network/connectivity error.
   * @param error - The error to check
   * @returns true if the error indicates a network problem
   */
  private isNetworkError(error: unknown): boolean {
    // Obsidian's requestUrl can reject with a RequestUrlResponse object (status 0),
    // a plain string, or an Error instance depending on failure mode.
    if (error && typeof error === "object" && "status" in error && (error as { status: number }).status === 0) {
      return true;
    }

    const message = this.extractErrorMessage(error);
    if (!message) return false;

    return (
      message.includes("network") ||
      message.includes("timeout") ||
      message.includes("timed out") ||
      message.includes("econnrefused") ||
      message.includes("econnreset") ||
      message.includes("econnaborted") ||
      message.includes("enotfound") ||
      message.includes("etimedout") ||
      message.includes("eai_again") ||
      message.includes("enetunreach") ||
      message.includes("ehostunreach") ||
      message.includes("ehostdown") ||
      message.includes("err_name_not_resolved") ||
      message.includes("errname") ||
      message.includes("err_internet_disconnected") ||
      message.includes("err_network_changed") ||
      message.includes("connection refused") ||
      message.includes("connection reset") ||
      message.includes("connection closed") ||
      message.includes("socket hang up") ||
      message.includes("failed to fetch") ||
      message.includes("net::err_") ||
      message.includes("abort")
    );
  }

  private extractErrorMessage(error: unknown): string {
    if (error instanceof Error) return error.message.toLowerCase();
    if (typeof error === "string") return error.toLowerCase();
    if (error && typeof error === "object") {
      const obj = error as Record<string, unknown>;
      if (typeof obj.message === "string") return obj.message.toLowerCase();
      if (typeof obj.text === "string") return obj.text.toLowerCase();
    }
    return "";
  }

  /**
   * Creates a promise that resolves after the specified delay.
   * @param ms - Delay in milliseconds
   */
  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Logs a debug message to the console (if debug logging is enabled).
   * @param message - The message to log
   */
  private log(message: string): void {
    // Dev builds (`install:plugin:dev`, NODE_ENV="development") force logging ON so
    // troubleshooting needs no manual toggle. The dev term is evaluated FIRST so it
    // never touches this.settings (which can be undefined during very-early onload),
    // and esbuild constant-folds it to `false` in the production bundle
    // (NODE_ENV="production") — so prod logging stays gated ONLY on the user setting.
    if (process.env.NODE_ENV !== "production" || this.settings.debugLogging) {
      console.log(`${LOG_PREFIX} ${message}`);
    }
  }

  /**
   * Logs an error to the console.
   * @param message - Error context message
   * @param error - The error object
   */
  private logError(message: string, error: unknown): void {
    // SD-14-F3: this console.error is intentionally always-on (real errors must
    // surface regardless of debugLogging/NODE_ENV). Redact known secret shapes
    // first as defense-in-depth — but only swap in the sanitized string when a
    // secret was actually found, so the common (clean) case keeps DevTools'
    // clickable Error object + stack for debugging.
    const safeMessage = redactSecretString(message);
    const raw = stringifyForLog(error);
    const redacted = redactSecretString(raw);
    if (redacted === raw) {
      console.error(`${LOG_PREFIX} ${safeMessage}:`, error);
    } else {
      console.error(`${LOG_PREFIX} ${safeMessage}:`, redacted);
    }
  }
}
