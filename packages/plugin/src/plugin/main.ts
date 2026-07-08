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

import { Modal, Notice, Plugin, Platform, TFile, TFolder, Menu, normalizePath, requestUrl, RequestUrlResponse } from "obsidian";
import { VaultGuardSettingTab, DEFAULT_SETTINGS, SAAS_DEFAULTS } from "./settings";
import { LoginModal, LoginCredentials } from "./login-modal";
import type { ConversationStore } from "../ui/chat/conversation-store";
import { BindingReconciliationModal, ReconciliationDecision, ReconciliationPlan } from "./binding-reconciliation-modal";
import { ShareManagementModal } from "./share-management-modal";
import { PluginAllowlistModal, PluginAllowlistPrompt } from "./plugin-allowlist-modal";
import { cognitoLogin, cognitoRespondToChallenge, cognitoRefresh, cognitoRevokeToken, cognitoAssociateSoftwareToken, cognitoVerifySoftwareToken, vaultguardForgotPassword, vaultguardConfirmReset, vaultguardVerifyRecoveryCode, devServerLogin, isLocalDevAuth, CognitoAuthResult } from "./cognito-auth";
import { MfaSetupModal } from "./mfa-setup-modal";
import { deriveConnectionConfigFromTokenPayload } from "./session-config";
import { AdminModal } from "../admin/admin-modal";
import { AuditConfigModal } from "../admin/audit-config-modal";
import { VaultGuardApiClient } from "../api/client";
import type {
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
import { PermissionEditor } from "../admin/permission-editor";
import { FilePermissionHeader } from "../ui/file-permission-header";
import { ReadOnlyGuard } from "./readonly-guard";
import { PermissionStore } from "./permission-store";
import { UpdateChecker } from "./update-checker";
import { SyncDiagnostics } from "./sync-diagnostics";
import type { AtRestCipher } from "../crypto/at-rest-cipher";
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
} from "./at-rest-adapter-runtime";
import {
  LOCAL_PROJECT_MEMORY_MODE_NOTICE,
  isLocalProjectMemoryModeEnabled,
} from "./local-project-memory-mode";
import { PathPermissionsModal } from "../ui/path-permissions-modal";
import { ProUpsellModal } from "../ui/pro-upsell-modal";
import { FileExplorerDecorations } from "../ui/file-explorer-decorations";
import { VaultGuardSidebarView, VAULTGUARD_VIEW_TYPE } from "../ui/vaultguard-sidebar-view";
import { registerChatDebugCommand } from "../ui/chat/chat-debug-command";
import {
  type PermissionsGraphDataSource,
  type PermissionsGraphDataset,
} from "../ui/graph/permissions-graph-view";
import { findClaudeBinary } from "../ui/chat/claude-cli/claude-detector";
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
import type {
  InstallResult,
  SkillInstallStatus,
} from "./agent-bridge-skill/installer";
import type {
  CodexInstallResult,
  CodexSkillInstallStatus,
} from "./agent-bridge-codex-skill/installer";
import { collectAttachmentPreviewData, registerVaultGuardCommands } from "./commands";
import {
  registerFocusSyncHandlers as registerFocusSyncHandlersLifecycle,
  registerFolderLifecycleListeners as registerFolderLifecycleListenersLifecycle,
  registerInviteProtocolHandler as registerInviteProtocolHandlerLifecycle,
  registerObsidianSyncListener as registerObsidianSyncListenerLifecycle,
  registerObsidianSyncWarning,
  registerSessionActivityTracking as registerSessionActivityTrackingLifecycle,
  registerShareProtocolHandler as registerShareProtocolHandlerLifecycle,
  registerSidebarLayoutLifecycle,
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
  type PermissionStoreFactoryContext,
  type PermissionSurfaceContext,
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
  createSyncRuntime,
  type SyncRuntime,
} from "./sync-runtime";
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
  LongOperationUiController,
  renderLongOperationStatusBar,
} from "../ui/long-operation-progress";
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
} from "../types";

export { VAULTGUARD_CHAT_ICON_ID };

function getActiveObsidianDocument(): Document | null {
  if (typeof activeDocument !== "undefined") {
    return activeDocument;
  }
  return null;
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

  async enableLocalProjectMemoryMode(): Promise<void> {
    this.settings.localProjectMemoryMode = true;
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

  /** SY5: debounce handle for persisting the offline queue envelope. */
  private offlineQueuePersistTimer: ReturnType<typeof setTimeout> | null = null;

  /** Per-file server version state used for optimistic write guards. */
  private remoteFileState = new RemoteFileStateStore();

  /** Debounce handle for the encrypted remote-file-state envelope. */
  private remoteFileStatePersistTimer: ReturnType<typeof setTimeout> | null = null;

  /** Per-file permission header injected into markdown views */
  private filePermissionHeader: FilePermissionHeader | null = null;

  /** Locks the editor for files the user has below-WRITE access to */
  private readOnlyGuard: ReadOnlyGuard | null = null;

  /** File explorer decorations (permission badges, avatars on nav items) */
  private fileExplorerDecorations: FileExplorerDecorations | null = null;

  /** Background poller for new public releases of the plugin */
  private updateChecker: UpdateChecker | null = null;

  /** Sidebar view configuration (set once, injected into view instances) */
  private sidebarViewConfig: VaultGuardSidebarViewConfig | null = null;

  /**
   * Explicit LLM/agent bridge. This is intentionally off by default and only
   * works with short-lived in-memory leases. Agents get a narrow tool surface;
   * they never receive the LAK, cloud key lease, refresh token, or raw vault
   * filesystem access.
   */
  private agentBridgeRuntime: AgentBridgeRuntime | null = null;
  private vaultOrientationService: VaultOrientationService | null = null;
  private permissionsGraphRuntime: PermissionsGraphRuntime | null = null;
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
      claude: localMode
        ? "disabled"
        : claudeStatus.available && claudeStatus.installed
          ? "available"
          : "not-configured",
      codex: localMode
        ? "disabled"
        : codexStatus.available && codexStatus.installed
          ? "available"
          : "not-configured",
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
      getSession: () => this.session,
      getKeyLease: () => this.keyLease,
      isVaultLeaseDenied: () => this.vaultLeaseDenied,
      getPlaceholderPaths: () => this.placeholderPaths,
      isApplyingRemoteWrite: () => this.applyingRemoteWrite,
      getSyncState: () => this.syncState,
      getOfflineQueue: () => this.offlineQueue,
      getPermissionStore: () => this.permissionStore,
      hasWarmedAtLeastOnce: () => this.hasWarmedAtLeastOnce,
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
      shouldUploadChangesImmediately: () => this.shouldUploadChangesImmediately(),
      queueOfflineOperation: (operation, path, data, options) =>
        this.queueOfflineOperation(operation, path, data, options),
      getRemoteFileState: (path) => this.getRemoteFileState(path),
      getExpectedVersionId: (path) => this.getExpectedVersionId(path),
      recordRemoteFilePresent: (path, update) =>
        this.recordRemoteFilePresent(path, update),
      recordRemoteFileAbsent: (path) => this.recordRemoteFileAbsent(path),
      handleRemoteWriteConflict: (path, localContent, baseVersionId) =>
        this.handleRemoteWriteConflict(path, localContent, baseVersionId),
      recordDeletionTombstone: (path) => this.recordDeletionTombstone(path),
      clearDeletionTombstone: (path) => this.clearDeletionTombstone(path),
      updateStatusBar: () => this.updateStatusBar(),
      encryptContent: (content) => this.encryptContent(content),
      computeHash: (content) => this.computeHash(content),
      // BIN-A / D-02: byte-crypto pass-throughs beside their string siblings so
      // the at-rest adapter runtime can (later waves) encrypt/decrypt/hash raw
      // binary bytes with the same lease/vault guards.
      encryptContentBytes: (content) => this.encryptContentBytes(content),
      decryptContentBytes: (content) => this.decryptContentBytes(content),
      computeHashBytes: (content) => this.computeHashBytes(content),
      apiRequest: <T>(
        method: string,
        endpoint: string,
        body?: Record<string, unknown>,
        idTokenOverride?: string,
        options?: { timeoutMs?: number }
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
      readFileDecrypted: (path) => this.readFileDecrypted(path),
      fetchRemoteFileContent: (path) => this.fetchRemoteFileContent(path),
      decodeRemoteFileContent: (path, data) =>
        this.decodeRemoteFileContent(path, data),
      decodeBase64Utf8: (base64) => this.decodeBase64Utf8(base64),
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
      isVaultLeaseDenied: () => this.vaultLeaseDenied,
      // Phase 12 (NN-2 / key-renewal guard): the heartbeat survives the lock,
      // but checkKeyLeaseRenewal consults this to no-op while locked.
      isVaultLocked: () => this.isVaultLocked,
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
      recordRemoteFilePresent: (path, update) =>
        this.recordRemoteFilePresent(path, update),
      recordRemoteFileAbsent: (path) => this.recordRemoteFileAbsent(path),
      performInitialReconciliation: () => this.performInitialReconciliation(),
      registerFolderLifecycleListeners: () => this.registerFolderLifecycleListeners(),
      performSync: (options) => this.performSync(options),
      buildLocalSyncManifest: () => this.buildLocalSyncManifest(),
      askReconciliationPlan: (plan) => this.askReconciliationPlan(plan),
      uploadReconciledFile: (path, content, options) =>
        this.uploadReconciledFile(path, content, options),
      ensureAtRestEncryptedInPlace: (path) => this.ensureAtRestEncryptedInPlace(path),
      getPermissionStoreState: () => this.permissionStore.getStoreState(),
      removeUnsyncedLocalFile: (path) => this.removeUnsyncedLocalFile(path),
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
      applyRemoteChange: (metadata) => this.applyRemoteChange(metadata),
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
      readFileDecrypted: (path) => this.readFileDecrypted(path),
      fetchRemoteFileContent: (path) => this.fetchRemoteFileContent(path),
      decodeRemoteFileContent: (path, data) =>
        this.decodeRemoteFileContent(path, data),
      readRemotePlaintext: (path) => this.readRemotePlaintext(path),
      resolveReconciliationConflict: (path, strategy, localManifest) =>
        this.resolveReconciliationConflict(path, strategy, localManifest),
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
      apiRequest: <T>(
        method: string,
        endpoint: string,
        body?: Record<string, unknown>,
        idTokenOverride?: string,
        options?: { timeoutMs?: number }
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
      getApiClient: () => this.apiClient,
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
      handleLogin: () => this.handleLogin(),
      openVaultGuardSettings: () => this.openVaultGuardSettings(),
    };
  }

  private createSidebarActivationContext(): VaultGuardSidebarActivationContext {
    return {
      app: this.app,
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
      logError: (message, error) => this.logError(message, error),
    };
  }

  private createLifecycleEventsContext(): LifecycleEventsContext {
    const thisPlugin = this;
    const registerDomEvent = this.registerDomEvent.bind(this) as (
      target: Window | Document,
      type: string,
      callback: EventListenerOrEventListenerObject,
    ) => void;

    return {
      app: this.app,
      logPrefix: LOG_PREFIX,
      protocolHost: this as unknown as LifecycleEventsContext["protocolHost"],
      registerEvent: (eventRef) => {
        this.registerEvent(eventRef);
      },
      registerDomEvent: (target, type, callback) => {
        registerDomEvent(target, type, callback);
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
    this.log("Loading VaultGuard plugin...");
    this.syncDiagnostics.record("onload.start", { mobile: Platform.isMobileApp });

    // Register the ribbon buttons SYNCHRONOUSLY, up front, before the first
    // `await`. Ribbon buttons created *after* an await can be appended after
    // Obsidian has already taken its initial ribbon snapshot.
    registerVaultGuardRibbons(this.createRibbonContext());

    // (sd4) The sd2 "Import local files" ribbon was retired. Importing is now an
    // agent-driven chat slash command (/import-knowledge) inside the AI chat
    // panel — the agent surveys the picked folder through a gated, sandboxed
    // source-read tool and builds an organized KB, rather than dumping files 1:1.

    // Load persisted settings
    await this.loadSettings();

    this.longOperationUi = new LongOperationUiController(this.app, this.longOperations);
    this.longOperationUi.start();
    this.longOperationStatusUnsubscribe = this.longOperations.subscribe(() => {
      this.updateStatusBar();
    });

    // Check for Obsidian Sync — VaultGuard is the sole sync/backup provider
    this.checkForObsidianSync();

    // Register the settings tab
    this.addSettingTab(new VaultGuardSettingTab(this.app, this));

    // Initialize status bar
    if (this.settings.showStatusBar) {
      this.statusBarEl = this.addStatusBarItem();
      this.updateStatusBar();
    }

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

    // Install the adapter intercept BEFORE any awaited startup work. Reads that
    // Obsidian fires during plugin load (workspace restore, initial indexer)
    // would otherwise go through the un-intercepted adapter and could return
    // raw VG1 ciphertext as a UTF-8 string, which the editor would then
    // re-save through the encryption path and permanently corrupt the file.
    // Early reads route through readPlainFromDisk, which fails closed via
    // `cipherInitPromise` until init settles.
    this.interceptVaultAdapter();

    // BIN-A preview: pre-decrypt an opened media file into the resource-preview
    // blob cache so standalone image/PDF views get a synchronous getResourcePath
    // cache hit instead of a broken-then-repaint flash. Guarded inside the
    // runtime (no-ops unless at-rest is active and the file is renderable media).
    this.registerEvent(
      this.app.workspace.on("file-open", (file) => {
        if (file) void this.prewarmAttachmentPreview(file.path);
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
    // Phase 12: construct the PIN-lock manager FIRST so initAtRestCipher's
    // PIN-lock pre-check (isPinLockEnrolled) can land the vault LOCKED instead of
    // provisioning/needs-recovery when a PIN owns the LAK (edge #6).
    this.initPinLockManager();
    await this.initAtRestCipher();

    // SY5: restore queued offline operations (LAK-encrypted envelope) so
    // limited-access/offline edits survive a restart instead of evaporating
    // with the in-memory queue. Fire-and-forget — it waits for cipher init
    // internally and merges under any ops queued while it loads.
    void this.loadPersistedOfflineQueue();
    void this.loadPersistedRemoteFileState();

    // Restore session — synchronous safeStorage path first, async at-rest
    // path second. On desktop this is effectively zero-cost; on mobile it
    // adds a single AES-GCM decrypt (a few ms).
    await this.restoreSession();

    // Phase 12 (H-1 / edge #6): if a session was just restored AND a PIN is
    // enrolled, land LOCKED eagerly — keyed on isEnrolled() ALONE, never on
    // idleAction. idleAction is unknown here (applyOrgSettings runs inside the
    // BACKGROUNDED resumeStoredSession below, which we deliberately do NOT
    // await), and the adapter already hard-locked in initAtRestCipher whenever a
    // PIN owns the LAK — so gating the curtain on anything but isEnrolled() would
    // leave an enrolled user in a logout-policy org with locked reads and NO
    // curtain (a dead vault). idleAction governs ONLY the live-session idle→lock
    // transition, not this restart/login unlock.
    this.maybeEnterLockOnAuth();

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

    // Prepare the explicit LLM bridge. It remains inert until the user mints
    // a scoped lease; no server or token is created during normal plugin load.
    this.initAgentBridge();

    // Restore persistent agent bridge leases (encrypted on disk via the LAK)
    // for the current session. Fire-and-forget so any persistence error
    // doesn't block the rest of plugin startup. Only persistent leases that
    // match this session's userId+vaultId are restored; orphans are dropped.
    if (!this.isLocalProjectMemoryModeEnabled()) {
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

    registerVaultGuardViews(this.createViewRegistrationContext());

    // Phase 9: subscribe the sidebar to the unified permission bus. One
    // emit fans out to decorations + header + sidebar + readOnlyGuard.
    registerSidebarPermissionLifecycle(this.createLifecycleEventsContext());

    // Build sidebar config from current session (if restored)
    const sidebarConfig = this.createSidebarViewConfig();
    if (sidebarConfig) {
      this.sidebarViewConfig = sidebarConfig;
    }

    // Initialize file explorer decorations (permission dots + avatar stacks)
    this.initFileExplorerDecorations();

    // Auto-open the VaultGuard sidebar in the right panel on first load.
    registerSidebarLayoutLifecycle(this.createLifecycleEventsContext());

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
      });
    }

    if (this.settings.debugLogging) {
      const loadBanner = `VaultGuard v${this.manifest.version} (sync-rev ${SYNC_FEATURE_REVISION}) loaded`;
      new Notice(loadBanner, 2500);
    }

    this.updateChecker = new UpdateChecker(this);
    this.updateChecker.start();

    this.log("VaultGuard plugin loaded successfully.");
  }

  /**
   * Called by Obsidian when the plugin is deactivated.
   * Cleans up timers, restores original adapter methods, and clears
   * sensitive data from memory.
   */
  async onunload(): Promise<void> {
    this.log("Unloading VaultGuard plugin...");

    // SY5: flush the pending (debounced) offline-queue persist so queued
    // edits survive the unload instead of dying with the timer.
    if (this.offlineQueuePersistTimer) {
      clearTimeout(this.offlineQueuePersistTimer);
      this.offlineQueuePersistTimer = null;
      await this.persistOfflineQueue().catch(() => {});
    }
    if (this.remoteFileStatePersistTimer) {
      clearTimeout(this.remoteFileStatePersistTimer);
      this.remoteFileStatePersistTimer = null;
      await this.persistRemoteFileState().catch(() => {});
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
    this.longOperations.destroy();

    // Restore original vault adapter methods
    this.restoreVaultAdapter();

    if (this.agentBridgeRuntime) {
      await this.agentBridgeRuntime.shutdown();
      this.agentBridgeRuntime = null;
    }

    // Tear down API client
    if (this.apiClient) {
      this.apiClient.destroy();
      this.apiClient = null;
    }

    // Clear sensitive data from memory
    this.clearSensitiveData();
    this.setGlobalAuthChromeState(false);

    // Remove file permission header
    if (this.filePermissionHeader) {
      this.filePermissionHeader.destroy();
      this.filePermissionHeader = null;
    }

    // Unlock any editors locked by the read-only guard
    if (this.readOnlyGuard) {
      this.readOnlyGuard.destroy();
      this.readOnlyGuard = null;
    }

    // Remove file explorer decorations
    if (this.fileExplorerDecorations) {
      this.fileExplorerDecorations.destroy();
      this.fileExplorerDecorations = null;
    }

    // Note: VaultGuard sidebar leaves are intentionally NOT detached here.
    // Obsidian persists leaf placement, and detaching on unload resets the
    // view to its default location the next time the plugin loads, discarding
    // any spot the user moved it to.

    // Remove status bar
    if (this.statusBarEl) {
      this.statusBarEl.remove();
      this.statusBarEl = null;
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

  async createAgentBridgeLease(input: AgentBridgeLeaseInput = {}): Promise<AgentBridgeLeaseSecret> {
    const lease = this.ensureAgentBridgeRuntime().createLease(input);
    this.vaultOrientationService?.invalidate("agent-bridge-lease-created");
    return lease;
  }

  describeChatGptConnector(): ChatGptConnectorDescription {
    return this.ensureAgentBridgeRuntime().describeChatGptConnector();
  }

  async createChatGptConnectorSession(
    input: ChatGptConnectorSessionInput = {},
  ): Promise<ChatGptConnectorSessionSecret> {
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
    if (this.isLocalProjectMemoryModeEnabled()) {
      throw new Error("Agent bridge server leases are disabled in Local Project Memory Mode.");
    }
    return this.ensureAgentBridgeRuntime().startServer();
  }

  async stopAgentBridgeServer(): Promise<void> {
    await this.ensureAgentBridgeRuntime().stopServer();
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
    if (this.isLocalProjectMemoryModeEnabled()) {
      new Notice("VaultGuard Sync: server bridge leases are disabled in Local Project Memory Mode.", 6000);
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
   * @param options.requireOrgSlug  When true, the hosted slug field is required
   *                                before Cognito login. Cloud defaults make
   *                                this optional for first-run SaaS users.
   */
  private handleLogin(options?: {
    prefillEmail?: string;
    firstTimeSetup?: boolean;
    requireOrgSlug?: boolean;
  }): void {
    if (this.isLocalProjectMemoryModeEnabled()) {
      new Notice("VaultGuard Sync: organization login is disabled in Local Project Memory Mode.", 6000);
      return;
    }
    const manualMode = this.settings.manualConfig === true;
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
      }
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
    if (this.isLocalProjectMemoryModeEnabled()) {
      new Notice("VaultGuard Sync: invite redemption is disabled in Local Project Memory Mode.");
      return;
    }
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
          // PL5: the challenge session died while the user typed. Clear it and
          // re-authenticate with the (temporary) password to mint a fresh
          // NEW_PASSWORD_REQUIRED challenge — handleAuthResult re-drives the
          // modal's set-password form with the new session.
          this.pendingChallengeSession = null;
          this.pendingNewPasswordChallenge = false;
          const freshAuth = await cognitoLogin(
            cfg.cognitoUserPoolId,
            cfg.cognitoClientId,
            credentials.email,
            credentials.password
          );
          await this.handleAuthResult(freshAuth, credentials);
          return;
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
          // PL5: the ~3-minute challenge session expired while the user typed
          // the code. Replaying it fails forever — clear it, re-authenticate,
          // and surface a routed MFA prompt carrying the fresh session.
          this.pendingChallengeSession = null;
          const freshAuth = await cognitoLogin(
            cfg.cognitoUserPoolId,
            cfg.cognitoClientId,
            credentials.email,
            credentials.password
          );
          try {
            await this.handleAuthResult(freshAuth, credentials);
          } catch (freshErr) {
            const freshMsg = freshErr instanceof Error ? freshErr.message : String(freshErr);
            if (freshMsg === "MFA code required") {
              // Keep the modal on the MFA step ("mfa" routes there) but tell
              // the user why their previous code did nothing.
              throw new Error("Your MFA code expired — enter a fresh code to sign in.");
            }
            throw freshErr;
          }
          return;
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
        credentials.password
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
    this.session = session;
    this.clearLogoutAuthState();
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
    }

    // Phase 12 (H-1): a fresh login on a device that already has a PIN enrolled
    // lands LOCKED too — the LAK is PIN-wrapped so the adapter is locked, and the
    // curtain must appear regardless of idleAction. enterLockState stops the sync
    // + key-renewal this login may have just started; the heartbeat stays alive.
    this.maybeEnterLockOnAuth();

    // Quick 260708-el6: a fresh login for a NEW user in a lock-policy org with no
    // PIN yet — offer the skippable, once-ever "Set a PIN" prompt so idle-lock is
    // discoverable. Gated + idempotent behind the persisted flag, so it shows at
    // most once across both auth-entry points and across reloads.
    this.maybeOfferPinOnboarding();
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

    const { VaultPickerModal } = await import("./vault-picker-modal");
    await new Promise<void>((resolve) => {
      const modal = new VaultPickerModal(
        this.app,
        this.apiClient!,
        { suggestedName: folderName, canCreateVaults: isOrgAdmin },
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

    if (changed) {
      // Drop the old vault's lease *before* the vaultId flips. Any read or
      // write that fires between the vaultId change and the
      // ensureVaultScopedKeyLease call below would otherwise route a
      // request to the new vault's S3 prefix and try to decrypt it with
      // the old vault's DEK — guaranteed AES-GCM tag failure.
      // interceptedRead's `this.keyLease` guard short-circuits to the
      // local copy until the new lease lands.
      this.keyLease = null;
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
      this.permissionStore.emit("changed", { serverConfirmed: true });
      this.localOnlyCatchupCompleted = false;
      this.stopSyncTimer();
    }

    await this.saveSettings();
    this.rebuildApiClient();
    if (this.session) {
      this.initializeApiClientFromSession(this.session);
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
      // The per-file access list can render with only the current user until
      // the membership/permission data fully settles after a fresh bind.
      // A reload reliably picks up everyone's access, so offer it.
      this.offerReloadForAccessList();
    }

    return changed;
  }

  /**
   * Non-blocking prompt offering to reload Obsidian after binding a vault.
   * The per-file "who has access" list sometimes shows only the current user
   * right after the first bind (membership/permission data hasn't settled);
   * a reload reliably populates it. Dismissible — the user can ignore it.
   */
  private offerReloadForAccessList(): void {
    // No DOM outside the Electron runtime (e.g. unit tests) — nothing to show.
    const doc = getActiveObsidianDocument();
    if (!doc) return;
    const frag = doc.createDocumentFragment();
    frag.appendText(
      "VaultGuard: Vault connected. Reload Obsidian so every file shows everyone who has access to it."
    );
    const actions = frag.createDiv();
    actions.addClass("vaultguard-reload-notice-actions");
    const reloadBtn = actions.createEl("button", { text: "Reload now" });
    reloadBtn.addEventListener("click", () => {
      // "Reload app without saving" — re-runs the full startup (session
      // restore), which is the path that populates the access list correctly.
      (this.app as unknown as { commands: { executeCommandById: (id: string) => void } })
        .commands.executeCommandById("app:reload");
    });
    new Notice(frag, 20000);
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
    if (this.session.role === "admin" || this.session.role === "owner") {
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

  private normalizeKeyLease(rawLease: Partial<KeyLease>): KeyLease {
    if (!rawLease.key || !rawLease.expiresAt || !rawLease.refreshToken || !rawLease.leaseId) {
      throw new Error("VaultGuard Sync: Server did not return a usable encryption key lease.");
    }

    return {
      key: rawLease.key,
      expiresAt: rawLease.expiresAt,
      refreshToken: rawLease.refreshToken,
      leaseId: rawLease.leaseId,
      algorithm: rawLease.algorithm ?? "AES-256-GCM",
      offlineCapable: rawLease.offlineCapable ?? true,
      encryptedDataKey: rawLease.encryptedDataKey,
      scope: rawLease.scope ?? '/**',
      vaultId: rawLease.vaultId,
    };
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
    }>("POST", "/auth/session", { vaultId: this.settings.serverVaultId || undefined }, idToken);

    if (!response.success || !response.data) {
      throw new Error(response.error?.message ?? "VaultGuard Sync: Failed to create a server session.");
    }

    return response.data;
  }

  private async resumeStoredSession(): Promise<void> {
    this.syncDiagnostics.record("resumeStoredSession.enter", { hasSession: !!this.session });
    if (!this.session) {
      this.syncDiagnostics.record("resumeStoredSession.return.noSession");
      return;
    }

    let session = this.session;
    let tokenWasRefreshed = false;
    if (this.isSessionTokenExpiring(session)) {
      const refreshResult = await this.refreshAccessToken(session);
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
    let leaseResponse: ApiResponse<{
      keyLease: KeyLease;
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
      leaseResponse = await this.apiRequest<{ keyLease: KeyLease }>(
        "GET",
        `/auth/key-lease?${params.toString()}`,
        undefined,
        session.idToken
      );
    }

    if (leaseResponse?.success && leaseResponse.data) {
      this.session = session;
      this.clearLogoutAuthState();
      // GET /auth/key-lease?vaultId=... returns the vault-scoped lease.
      this.keyLease = this.normalizeKeyLease(leaseResponse.data.keyLease);
      this.applyOrgSettings(leaseResponse.data.orgSettings ?? this.orgSettings);
    } else {
      const serverSession = await this.openServerSession(session.idToken);
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

    // Quick 260708-el6: first lock-policy session for a returning/existing user
    // (the endorsed once-ever migration nudge, reusing the same persisted flag).
    // The flag guarantees at most one prompt across both entry points + reloads.
    this.maybeOfferPinOnboarding();
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
   * Restore the cipher from a previously-exported recovery code. Returns
   * false if the code is malformed / has a bad checksum so the UI can
   * show a generic "couldn't recognise that code" error.
   */
  async restoreAtRestFromRecoveryCode(code: string): Promise<boolean> {
    return this.ensureAtRestAdapterRuntimeObject().restoreAtRestFromRecoveryCode(code);
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

  /**
   * Opens Obsidian's own Settings → Community plugins screen — the built-in tab
   * that hosts each installed plugin's native Update button — after AWAITING a
   * best-effort, read-only refresh of Obsidian's available-updates list. Waiting
   * for the (async) refresh means the tab renders with the update already known,
   * so Obsidian's per-plugin Update button is visible on arrival instead of
   * appearing only after the user re-opens the tab a moment later.
   *
   * Policy: Obsidian's Developer Policies list updating the plugin itself under
   * "Not allowed", so VaultGuard must never download, replace, or self-apply its
   * own binary. This method therefore ONLY navigates to Obsidian's native
   * updater plus a read-only refresh of the available-updates list; the real
   * update is performed by Obsidian's built-in Update button, on the user's
   * explicit action. It never touches the plugin binary on disk.
   */
  async openCommunityPluginsForUpdate(): Promise<void> {
    // Best-effort, READ-ONLY refresh of Obsidian's available-updates list.
    // Reaches into Obsidian's internal plugin manager the same stable way
    // runAllowlistReconcileInternal does — not part of the public API but stable
    // across releases for years. This only refreshes the list Obsidian shows; it
    // is NOT an update mechanism and never installs anything.
    const pm = (this.app as unknown as {
      plugins?: { checkForUpdates?: () => unknown };
    }).plugins;
    if (pm?.checkForUpdates) {
      // Immediate feedback while the (network) refresh runs.
      new Notice("VaultGuard Sync: Checking for updates…");
      try {
        const result = pm.checkForUpdates();
        // checkForUpdates is async (fetches the community registry to populate
        // app.plugins.updates). AWAIT it so the Community plugins tab renders
        // AFTER the update is known — otherwise Obsidian's per-plugin Update
        // button isn't shown yet. Bounded so a hung network can't stall the UI.
        if (result && typeof (result as { then?: unknown }).then === "function") {
          await Promise.race([
            result as Promise<unknown>,
            new Promise<void>((resolve) => window.setTimeout(resolve, 10_000)),
          ]);
        }
      } catch {
        // Best-effort — still open the tab on failure.
      }
    }

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

    menu.addItem((item) =>
      item
        .setTitle("Vault settings")
        .setIcon("settings")
        .onClick(() => this.openVaultGuardSettings())
    );

    if (!isLoggedIn) {
      menu.addItem((item) =>
        item
          .setTitle("Login")
          .setIcon("log-in")
          .onClick(() => this.handleLogin())
      );
      this.showMenu(menu, evt);
      return;
    }

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

  private getSidebarAuthState(): VaultGuardSidebarAuthState | null {
    if (this.session) {
      return null;
    }

    return this.lastLogoutAuthState;
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
    if (!this.session || !this.apiClient) {
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

  private refreshPermissionUiAfterMembershipChange(): void {
    // Phase 9: single bus emit replaces the 5-call fan-out. The four
    // init* subscriptions invoke readOnlyGuard / fileExplorer / sidebar /
    // header invalidations. The `update({ force: true })` line is
    // preserved because it's a force-refresh of the CURRENT header view,
    // not an invalidation — the listener doesn't pass force: true.
    this.permissionStore.emit("changed", { serverConfirmed: true });
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
      if (ignored.has(entry.pluginId)) continue;

      // Already enabled? Nothing to do.
      const enabledPlugins = pluginManager?.enabledPlugins;
      if (enabledPlugins instanceof Set && enabledPlugins.has(entry.pluginId)) {
        continue;
      }

      const pluginRoot = this.vaultConfigPath("plugins", entry.pluginId);
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
        this.logError(`Allowlist: failed to inspect "${entry.pluginId}"`, err);
        // Surface as missing — the user can retry after the next sync.
        hashStatus = "missing";
      }

      const decision = await this.promptPluginAllowlistDecision({
        pluginId: entry.pluginId,
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
        ignoredList.add(entry.pluginId);
        this.settings.pluginAllowlistIgnored = [...ignoredList];
        await this.saveSettings();
        await this.emitAuditEvent("plugin.allowlist_skip", entry.pluginId, {
          permanent: true,
        });
        continue;
      }
      if (decision === "skip") {
        await this.emitAuditEvent("plugin.allowlist_skip", entry.pluginId);
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
          await pluginManager.enablePluginAndSave(entry.pluginId);
          new Notice(`VaultGuard Sync: Enabled "${entry.displayName}".`);
          await this.emitAuditEvent("plugin.allowlist_install", entry.pluginId, {
            verified: hashStatus === "verified",
            version: entry.version,
          });
        } else {
          new Notice(
            `VaultGuard Sync: Could not auto-enable "${entry.displayName}" — please enable it manually in Settings → Community plugins.`
          );
        }
      } catch (err) {
        this.logError(`Allowlist: enable "${entry.pluginId}" failed`, err);
        new Notice(
          `VaultGuard Sync: Failed to enable "${entry.displayName}" — ${err instanceof Error ? err.message : "unknown error"}.`
        );
      }
    }
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
    if (this.isLocalProjectMemoryModeEnabled()) {
      if (!options.silent) {
        new Notice("VaultGuard Sync: organization connection is disabled in Local Project Memory Mode.");
      }
      return;
    }
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
    this.orgSettings = orgSettings ?? null;

    // Keep the file-permission header in sync with the per-org
    // allowAdminPerFileRestrictions toggle. Without this push, the header
    // would render based on whatever flag was passed at construction time
    // and would never pick up a setting change until the next plugin
    // reload.
    this.filePermissionHeader?.setContext({
      allowAdminPerFileRestrictions: this.orgSettings?.allowAdminPerFileRestrictions === true,
    });

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

    // Phase 12 idle-behavior matrix (D3): the org's idleAction chooses lock vs
    // logout; a cryptographic lock additionally requires an enrolled PIN (there
    // is no secret to unlock with otherwise). Read the optional server field as
    // `?? "logout"` so un-upgraded servers / existing orgs keep today's behavior.
    const action = this.orgSettings?.idleAction ?? "logout";
    const enrolled = this.pinLockManager?.isEnrolled() ?? false;

    if (action === "lock" && enrolled) {
      this.log(`Auto-lock: locking vault after ${autoLockMinutes} minutes of inactivity.`);
      await this.enterLockState();
      return;
    }

    if (action === "lock" && !enrolled) {
      // Policy wants a lock but there's no PIN to unlock with — fall back to
      // logout and nudge (once) toward enrolling a PIN so lock-not-logout works.
      if (!this.pinNudgeShown) {
        this.pinNudgeShown = true;
        new Notice(
          "VaultGuard Sync: set a PIN in VaultGuard settings to lock instead of logging out.",
          8000
        );
      }
    }

    this.log(`Auto-lock triggered after ${autoLockMinutes} minutes of inactivity.`);
    await this.forceLogout(
      `VaultGuard Sync: Session locked after ${autoLockMinutes} minutes of inactivity.`
    );
  }

  /**
   * Phase 12 (H-1 / edge #6): fire the lock curtain on ANY auth entry — cold-
   * start session-restore OR a fresh login — whenever a PIN is enrolled, keyed on
   * `isEnrolled()` ALONE and NEVER on idleAction. The adapter already hard-locks
   * whenever a PIN owns the LAK (initAtRestCipher skips provisioning), so the
   * curtain gate MUST mirror that exact condition or an enrolled user in a
   * logout-policy org — or after an admin lock→logout flip — gets locked adapter
   * reads with no way to unlock (the dead-vault H-1 case). Synchronous + eager:
   * callers MUST NOT await sessionResumePromise first (idleAction is unknown until
   * the backgrounded resume settles). idleAction governs ONLY the live-session
   * idle→lock transition (lockSessionForInactivity), not restart/login unlock.
   */
  private maybeEnterLockOnAuth(): void {
    if (this.session && this.pinLockManager?.isEnrolled() && !this.isVaultLocked) {
      void this.enterLockState();
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
   * (60s heartbeat / terminal token-refresh) and the 24h maxSessionDurationHours
   * cap still force a REAL forceLogout even while locked — a locked session can
   * never resurrect a revoked/expired one. Only sync + key-renewal stop here.
   */
  private async enterLockState(): Promise<void> {
    if (!this.session || this.isVaultLocked) {
      return;
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

    await this.exitLockState();
  }

  /** True if a PIN is enrolled on this device (public accessor for the settings UI). */
  pinLockEnrolled(): boolean {
    return this.pinLockManager?.isEnrolled() ?? false;
  }

  /** The effective org idle action ("lock" | "logout") for the settings UI. */
  effectiveIdleAction(): "lock" | "logout" {
    return this.orgSettings?.idleAction ?? "logout";
  }

  /**
   * Lazy, once-ever discoverability prompt for lock-instead-of-logout (quick
   * 260708-el6). A new user in a lock-policy org who never sets a PIN silently
   * degrades to idle-LOGOUT (lockSessionForInactivity → action "lock" && !enrolled
   * → forceLogout). Offer a skippable "Set a PIN" nudge exactly once. Safe to call
   * from BOTH the fresh-login and session-restore entry points because it is
   * idempotent behind the persisted `pinOnboardingPromptShown` flag.
   */
  private maybeOfferPinOnboarding(): void {
    if (
      this.session &&
      this.effectiveIdleAction() === "lock" &&
      !this.pinLockEnrolled() &&
      !this.settings.pinOnboardingPromptShown
    ) {
      this.openPinOnboardingPrompt();
    }
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
   * Enroll a PIN so the vault locks-instead-of-logs-out (D2/D3). Requires the
   * cipher UNLOCKED (the LAK must be in memory to hand to the PIN wrap).
   *
   * NON-NEGOTIABLE #1 + failure-safe order: write `lak-pin.envelope` FIRST
   * (pinLockManager.enroll), THEN remove the transparent `lak.envelope`
   * (clearPersistedWrap). Without clearPersistedWrap a same-OS user auto-unwraps
   * the LAK PIN-free on the next cold start and D2 ("undecryptable without the
   * PIN") is FALSE. Doing enroll before clear guarantees a failed enroll never
   * leaves the device with NO way to load the LAK.
   */
  async enrollPinLock(secret: string): Promise<void> {
    const cipher = this.getAtRestCipher();
    if (!cipher?.isReady()) {
      throw new Error("Unlock the vault before setting a PIN.");
    }
    if (!this.pinLockManager) {
      throw new Error("PIN lock is unavailable on this device.");
    }
    const lak = cipher.exportLakBytes();
    try {
      await this.pinLockManager.enroll(secret, lak); // writes lak-pin.envelope
      await cipher.clearPersistedWrap(); // NN-1: remove the transparent lak.envelope
    } finally {
      lak.fill(0);
    }
    new Notice(
      "VaultGuard Sync: PIN set. Your vault now locks (not logs out) when idle."
    );
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
    const modal = new Modal(this.app);
    modal.titleEl.setText("Reset PIN?");
    modal.contentEl.createEl("p", {
      text: "You'll be logged out and your notes will re-sync from the cloud. Continue?",
    });
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
    this.updateRibbonAuthIndicator();
    this.sidebarViewConfig = null;
    this.keyLease = null;
    this.vaultLeaseDenied = false;
    this.lastLimitedAccessNoticeAt = 0;
    this.lastSessionDegradedNoticeAt = 0;
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
    return this.ensureAtRestAdapterRuntimeObject().decryptVaultAtRestAndDisableEncryption();
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

  private ensureAtRestEncryptedInPlace(path: string): Promise<boolean> {
    return this.ensureAtRestAdapterRuntimeObject().ensureAtRestEncryptedInPlace(path);
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

    const roles = this.session.roles?.length ? this.session.roles : [this.session.role];
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
          roles,
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

  private handleFolderCreated(path: string): void {
    return this.ensureSyncRuntime().handleFolderCreated(path);
  }

  private handleFolderDeleted(path: string): void {
    return this.ensureSyncRuntime().handleFolderDeleted(path);
  }

  private handleFolderRenamed(path: string, oldPath: string): void {
    return this.ensureSyncRuntime().handleFolderRenamed(path, oldPath);
  }

  private handleVaultFileRenamed(path: string, oldPath: string): void {
    return this.ensureSyncRuntime().handleVaultFileRenamed(path, oldPath);
  }

  private handleVaultFileDeleted(path: string): void {
    return this.ensureSyncRuntime().handleVaultFileDeleted(path);
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
   * Returns "uploaded" on success, "skipped" when the user lacks WRITE
   * permission, and throws on any other failure so the caller can count it
   * accurately. Callers decide whether a skipped local-only file stays local
   * or is removed as an unsynced ghost.
   */
  private async uploadReconciledFile(
    path: string,
    content: string,
    options: { noWriteNotice?: string } = {}
  ): Promise<"uploaded" | "skipped-no-lease" | "skipped-no-permission"> {
    return this.ensureSyncRuntime().uploadReconciledFile(path, content, options);
  }

  private async removeUnsyncedLocalFile(path: string): Promise<boolean> {
    return this.ensureSyncRuntime().removeUnsyncedLocalFile(path);
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
    removedLocalFiles: number;
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
    localManifest: Map<string, LocalManifestEntry>
  ): Promise<void> {
    return this.ensureSyncRuntime().resolveReconciliationConflict(path, strategy, localManifest);
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
  private async applyRemoteChange(metadata: Pick<FileMetadata, "path" | "size">): Promise<void> {
    return this.ensureSyncRuntime().applyRemoteChange(metadata);
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
    baseVersionId?: string | null
  ): Promise<RemoteWriteConflictResolutionResult> {
    return this.ensureSyncRuntime().handleRemoteWriteConflict(
      path,
      localContent,
      baseVersionId
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
  private async fetchSyncCursor(): Promise<{ revision: number; lastChangedAt: string } | null> {
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
  private async readFileDecrypted(relPath: string): Promise<ApiResponse<RemoteFileContentResponse>> {
    return this.ensureSyncRuntime().readFileDecrypted(relPath);
  }

  private async fetchRemoteFileContent(path: string): Promise<ApiResponse<RemoteFileContentResponse>> {
    return this.ensureSyncRuntime().fetchRemoteFileContent(path);
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
      this.keyLease = this.normalizeKeyLease(response.data.keyLease);
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
        this.keyLease = this.normalizeKeyLease(response.data.keyLease);
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

    return this.bytesToBase64(combined);
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
    if (!this.keyLease || this.isKeyLeaseExpired()) {
      throw new Error(
        "VaultGuard Sync: Cannot decrypt - no valid key lease. Please reconnect."
      );
    }
    this.assertLeaseMatchesBoundVault("decrypt");

    const combined = this.base64ToBytes(encryptedContent);

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
        this.log("Connection restored, flushing offline queue...");
        void this.flushOfflineQueue();
      }
    } else if (status === "offline" && previousStatus !== "offline") {
      this.connectionState.failedAttempts++;
      if (scheduleRetry) {
        this.scheduleConnectionRetry();
      } else {
        this.stopConnectionRetry();
        this.connectionState.nextRetryAt = null;
      }
      if (notify && this.session && previousStatus === "online") {
        this.scheduleConnectionLostNotice();
      }
    }

    this.updateStatusBar();

    // Populate any open Permissions graph that was waiting on connectivity.
    // The "online" flip is deferred until the first sync, so a panel opened on
    // launch renders its offline empty state first; re-render it on the
    // offline→online edge so it loads without the user reopening it.
    if (status === "online" && previousStatus !== "online") {
      this.refreshPermissionsGraph();
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

  private async apiRequest<T>(
    method: string,
    endpoint: string,
    body?: Record<string, unknown>,
    idTokenOverride?: string,
    // L2 (BIN-A): optional per-request timeout override. Large binary PUTs pass a
    // longer timeout (BINARY_PUT_TIMEOUT_MS) so a slow uplink is not misread as a
    // network failure; omitted → the 30 s default in requestWithTimeout is unchanged.
    options?: { timeoutMs?: number }
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
    if (this.session?.sessionId) {
      headers["X-VaultGuard-Session-Id"] = this.session.sessionId;
    }

    const startedAt = Date.now();
    let lastError: Error | null = null;
    let sawNetworkError = false;
    // AC-API1: the latest REAL HTTP failure (429/5xx that exhausted retries).
    // Returned with its true status instead of collapsing to statusCode 0.
    let lastHttpFailure: ApiResponse<T> | null = null;
    let endpointRefreshAttempted = false;

    for (let attempt = 0; attempt < this.settings.maxRetryAttempts; attempt++) {
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
          if (attempt < this.settings.maxRetryAttempts - 1) {
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
      if (attempt < this.settings.maxRetryAttempts - 1) {
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
          "(for example https://api.example.com, your API Gateway URL, or your API CloudFront base URL). " +
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

    if ((showMyLevel || showOthersAccess) && this.isFileExplorerDecorationDataReady()) {
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

  private setGlobalAuthChromeState(loggedIn: boolean): void {
    const doc = getActiveObsidianDocument();
    if (!doc) {
      return;
    }
    doc.body.toggleClass("vaultguard-auth-logged-in", loggedIn);
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
    shieldEl?.setAttr("aria-label", "VaultGuard Sync");
    shieldEl?.setAttr(
      "title",
      `VaultGuard Sync: connected${
        this.session.email ? ` as ${this.session.email}` : ""
      }.`
    );
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

    const longOperation = this.longOperations.getPrimarySnapshot();
    if (longOperation) {
      renderLongOperationStatusBar(this.statusBarEl, longOperation);
      return;
    }
    this.statusBarEl.classList?.remove("vaultguard-long-op-statusbar");

    if (!this.session) {
      if (this.lastLogoutAuthState) {
        this.statusBarEl.setText("VaultGuard Sync: Logged out");
        this.statusBarEl.setAttr(
          "title",
          `${this.lastLogoutAuthState.title}: ${this.lastLogoutAuthState.detail ?? this.lastLogoutAuthState.message}`
        );
      } else {
        this.statusBarEl.setText("VaultGuard Sync: Not logged in");
        this.statusBarEl.setAttr(
          "title",
          "VaultGuard Sync is not connected. Log in to enable cloud sync."
        );
      }
      return;
    }

    if (this.permissionWarmupInFlight > 0) {
      this.statusBarEl.setText("VaultGuard Sync ↻ Loading permissions...");
      this.statusBarEl.setAttr("title", "VaultGuard Sync is loading file permissions.");
      return;
    }

    const connectionIcon =
      this.connectionState.status === "online"
        ? "\u2713"
        : this.connectionState.status === "reconnecting"
          ? "\u21BB"
          : "\u2717";

    const statusText = this.connectionState.status === "online"
      ? "Connected"
      : "Offline";

    this.statusBarEl.setText(`VaultGuard Sync ${connectionIcon} ${statusText}`);
    this.statusBarEl.setAttr(
      "title",
      `VaultGuard Sync: ${statusText}${
        this.session.email ? ` as ${this.session.email}` : ""
      }`
    );
  }

  /**
   * Toggles the status bar visibility.
   * @param show - Whether to show or hide the status bar
   */
  toggleStatusBar(show: boolean): void {
    if (show && !this.statusBarEl) {
      this.statusBarEl = this.addStatusBarItem();
      this.updateStatusBar();
    } else if (!show && this.statusBarEl) {
      this.statusBarEl.remove();
      this.statusBarEl = null;
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

    const modal = new AdminModal(
      this.app,
      this.apiClient,
      "permissions",
      this.session.userId,
      this.createAdminModalContext()
    );
    modal.open();
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
    const modal = new AdminModal(
      this.app,
      this.apiClient,
      "permissions",
      null,
      this.createAdminModalContext(initialSearch)
    );
    modal.open();
  }

  /**
   * Refresh every permission surface (file header, file-explorer decorations,
   * sidebar) after vault-wide rules change in the Manage Permissions modal.
   * Drops the warmed rule cache, re-warms from the server, and fires the
   * shared "changed" bus event the per-file flow already uses.
   */
  notifyPermissionRulesChanged(): void {
    this.permissionStore.invalidate();
    this.permissionStore.emit("changed", { serverConfirmed: true });
    void this.runPermissionWarmup().catch((err) =>
      this.logError("Permission re-warm after rule change failed", err)
    );
  }

  private createAdminModalContext(permissionsInitialSearch?: string) {
    return {
      orgId: this.settings.organizationId,
      orgSlug: this.settings.orgSlug,
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

    const modal = new AdminModal(
      this.app,
      this.apiClient,
      "users",
      null,
      this.createAdminModalContext()
    );
    modal.open();
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
    new AdminModal(
      this.app,
      this.apiClient,
      "audit",
      null,
      this.createAdminModalContext()
    ).open();
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
    new AuditConfigModal(this.app, this.apiClient).open();
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
      new ProUpsellModal(this.app, "webAdmin").open();
      return;
    }
    const slug = this.settings.orgSlug?.trim() || "";
    const url = slug
      ? `https://admin.example.com/${encodeURIComponent(slug)}`
      : "https://admin.example.com";
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
        this.permissionStore.emit("changed", { serverConfirmed: true });
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
    const editor = new PermissionEditor(this.app, this.apiClient);
    editor.showAddRuleForPath(rulePath, async () => {
      // Phase 9: single bus emit replaces the 5-call fan-out.
      this.permissionStore.emit("changed", { serverConfirmed: true });
    });
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Cache Management
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Clears all locally cached vault data.
   * Used for security wipe or manual cache reset.
   */
  async clearLocalCache(): Promise<void> {
    // Phase 9: SILENT — teardown path, surfaces will be torn down
    // immediately by surrounding lifecycle code. No subscribers to notify.
    this.permissionStore.invalidate();
    this.readOnlyGuard?.refreshAll();
    this.offlineQueue = [];
    this.remoteFileState.clear();
    this.scheduleRemoteFileStatePersist();
    this.syncState = {
      lastSync: null,
      pendingChanges: 0,
      conflicts: [],
      status: "idle",
      bytesUploaded: 0,
      bytesDownloaded: 0,
      lastError: null,
    };
    new Notice("VaultGuard Sync: Local cache cleared.");
    this.log("Local cache cleared.");
  }

  /**
   * Clears all sensitive data from memory.
   * Called on plugin unload and forced logout.
   */
  private clearSensitiveData(): void {
    this.session = null;
    this.keyLease = null;
    // Drop the API client's cached JWTs so no privileged request (an open
    // admin/share modal, a queued call) can reuse the idToken after logout or
    // auto-lock. getAuthHeaders then fails closed until the user re-authenticates.
    this.apiClient?.clearTokens();
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
    this.scheduleOfflineQueuePersist();
    this.scheduleRemoteFileStatePersist();
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
    if (this.offlineQueuePersistTimer) clearTimeout(this.offlineQueuePersistTimer);
    this.offlineQueuePersistTimer = setTimeout(() => {
      this.offlineQueuePersistTimer = null;
      void this.persistOfflineQueue();
    }, 1_000);
  }

  private async persistOfflineQueue(): Promise<void> {
    const path = this.offlineQueueEnvelopePath();
    try {
      if (this.offlineQueue.length === 0) {
        if (await this.app.vault.adapter.exists(path)) {
          await this.app.vault.adapter.remove(path);
        }
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
    if (this.remoteFileStatePersistTimer) clearTimeout(this.remoteFileStatePersistTimer);
    this.remoteFileStatePersistTimer = setTimeout(() => {
      this.remoteFileStatePersistTimer = null;
      void this.persistRemoteFileState();
    }, 1_000);
  }

  private async persistRemoteFileState(): Promise<void> {
    const path = this.remoteFileStateEnvelopePath();
    try {
      if (this.remoteFileState.isEmpty()) {
        if (await this.app.vault.adapter.exists(path)) {
          await this.app.vault.adapter.remove(path);
        }
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
    if (this.settings.debugLogging) {
      console.log(`${LOG_PREFIX} ${message}`);
    }
  }

  /**
   * Logs an error to the console.
   * @param message - Error context message
   * @param error - The error object
   */
  private logError(message: string, error: unknown): void {
    console.error(`${LOG_PREFIX} ${message}:`, error);
  }
}
