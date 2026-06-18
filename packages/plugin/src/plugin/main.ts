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

import { Notice, Plugin, Platform, TFile, TFolder, TAbstractFile, Menu, normalizePath, addIcon, requestUrl, RequestUrlResponse, EventRef } from "obsidian";
import { VaultGuardSettingTab, DEFAULT_EXCLUDED_PATHS, DEFAULT_SETTINGS, SAAS_DEFAULTS } from "./settings";
import { LoginModal, LoginCredentials } from "./login-modal";
import { AgentBridgeLeaseModal } from "./agent-bridge-modal";
import { WriteConfirmModal } from "../ui/chat/render/write-confirm-modal";
import {
  ConversationStore,
  type ConversationStorageAdapter,
} from "../ui/chat/conversation-store";
import { BindingReconciliationModal, ReconciliationDecision, ReconciliationPlan } from "./binding-reconciliation-modal";
import { ShareManagementModal } from "./share-management-modal";
import { PluginAllowlistModal, PluginAllowlistPrompt } from "./plugin-allowlist-modal";
import { cognitoLogin, cognitoRespondToChallenge, cognitoRefresh, cognitoAssociateSoftwareToken, cognitoVerifySoftwareToken, cognitoSetUserMfaPreference, vaultguardForgotPassword, vaultguardConfirmReset, vaultguardVerifyRecoveryCode, devServerLogin, isLocalDevAuth, CognitoAuthResult } from "./cognito-auth";
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
  normalizeVaultGuardApiBaseUrl,
  resolveVaultGuardApiBaseUrl,
} from "../api/endpoint-resolver";
import { PermissionEditor } from "../admin/permission-editor";
import { FilePermissionHeader } from "../ui/file-permission-header";
import { ReadOnlyGuard } from "./readonly-guard";
import { PermissionStore } from "./permission-store";
import { UpdateChecker } from "./update-checker";
import { AtRestCipher, AtRestStorage } from "../crypto/at-rest-cipher";
import { SafeStorageLike, probeSafeStorage } from "../crypto/safe-storage";
import { PathPermissionsModal } from "../ui/path-permissions-modal";
import { ProUpsellModal } from "../ui/pro-upsell-modal";
import { FileExplorerDecorations } from "../ui/file-explorer-decorations";
import { VaultGuardSidebarView, VAULTGUARD_VIEW_TYPE } from "../ui/vaultguard-sidebar-view";
import { registerChatDebugCommand } from "../ui/chat/chat-debug-command";
import { VaultGuardChatView, VAULTGUARD_CHAT_VIEW_TYPE } from "../ui/chat/chat-view";
import { findClaudeBinary } from "../ui/chat/claude-cli/claude-detector";
import type { VaultGuardSidebarViewConfig } from "../ui/vaultguard-sidebar-view";
import {
  AgentBridgeLeaseInput,
  AgentBridgeLeaseSecret,
  AgentBridgeLeaseSummary,
  AgentBridgePersistenceAdapter,
  AgentBridgeServerInfo,
  AgentBridgeToolSurface,
  VaultGuardAgentBridge,
} from "./agent-bridge";
import { VaultGraph } from "./graph/vault-graph";
import {
  inspectSkillInstall,
  installSkill,
  uninstallSkill,
  type InstallResult,
  type SkillInstallStatus,
  type SkillInstallerDeps,
} from "./agent-bridge-skill/installer";

// Shield icon SVG for the ribbon
const VAULTGUARD_ICON = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>`;
// The AI Chat ribbon button and view tab use Obsidian's stock lucide
// `message-square` icon. Stock icons are pre-registered by Obsidian, so the
// ribbon button always carries its glyph at first paint. A custom `addIcon`
// icon can lose that registration race and render an INVISIBLE ribbon button —
// which is why the chat icon used to be missing until the view was opened from
// the command palette.
export const VAULTGUARD_CHAT_ICON_ID = "message-square";
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
  AuditEvent,
  AuditAction,
  SyncConflict,
  ConflictResolutionStrategy,
  ApiResponse,
} from "../types";

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/** Minimum allowed sync interval in seconds */
const MIN_SYNC_INTERVAL = 10;

/** Grace period before key expiry to trigger renewal (5 minutes) */
const KEY_RENEWAL_GRACE_MS = 5 * 60 * 1000;

/** Server heartbeat interval for revocation detection */
const HEARTBEAT_INTERVAL_MS = 60 * 1000;

/** Maximum time between connection retry attempts (2 minutes) */
const MAX_RETRY_INTERVAL_MS = 2 * 60 * 1000;

/** Base retry interval for exponential backoff (5 seconds) */
const BASE_RETRY_INTERVAL_MS = 5 * 1000;

/** Minimum spacing between repeated login-required notices */
const AUTH_REQUIRED_NOTICE_THROTTLE_MS = 5 * 1000;

/** Minimum spacing between repeated connection-lost notices */
const CONNECTION_LOST_NOTICE_THROTTLE_MS = 30 * 1000;

/** Plugin log prefix for console output */
const LOG_PREFIX = "[VaultGuard]";

/**
 * Hard cap on entries scanned by the limited-access placeholder sweep
 * (sweepPlaceholderPaths). Vaults larger than this should not be the
 * bootstrap target for v1 of limited-access mode; revisit with telemetry.
 */
const MAX_SWEEP_ENTRIES = 5000;

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
 * Plugin id -> list of historical plugin ids whose lak.envelope may still be
 * on disk and should be migrated INTO this id's folder before the at-rest
 * cipher initializes. Generic shape so a future rename appends cleanly.
 *
 * Why: commit 9495041 (2026-05-14) renamed manifest.id from `vaultguard` to
 * `vaultguard-sync`. The envelope path is derived from manifest.id, so on
 * upgrade init() saw no envelope at the new path and generated a fresh LAK
 * while every on-disk VG1 file was still ciphertext under the OLD LAK,
 * silently bricking decryption for any user who fell back to the disk LAK
 * (e.g. a stranded user with read-deny rules and no /** key lease).
 */
const PRIOR_PLUGIN_IDS_FOR_LAK_MIGRATION: Record<string, string[]> = {
  "vaultguard-sync": ["vaultguard"],
};

/**
 * Sentinel filename uploaded into every server-side folder so the empty-folder
 * case isn't lost across the round-trip. S3 has no native concept of an empty
 * directory — without this marker, a folder with no files in it disappears
 * entirely from the admin panel structure view.
 *
 * Must match the marker filename the backend writes for empty folders. Any
 * compatible self-hosted backend (see docs/openapi.yaml) must use the same
 * value or empty folders will not round-trip correctly.
 */
const FOLDER_MARKER_NAME = ".vaultguard-folder";

/**
 * Bumped whenever a user-visible sync change ships. Surfaced by the "Status"
 * command so a user can confirm whether their Obsidian process has actually
 * reloaded the freshly-built `main.js`. Without a marker like this, "rebuilt
 * but not toggled in Settings → Community Plugins" looks identical to "code
 * never ran" — which is exactly the trap that caused the missing-toast report.
 */
const SYNC_FEATURE_REVISION = 9;

type VaultGuardPluginData = Partial<VaultGuardSettings> & {
  storedSessions?: Record<string, unknown>;
};

interface ProtectedSessionEnvelope {
  v: 1;
  // "electron-safe-storage": desktop, sealed by Electron's safeStorage (OS keystore).
  // "at-rest-cipher": mobile / safeStorage-less hosts, sealed by AtRestCipher (AES-GCM
  // with the LAK whose own KEK falls back to a localStorage-stored AES key — same
  // security ceiling as the local at-rest encryption of vault content).
  storage: "electron-safe-storage" | "at-rest-cipher";
  ciphertext: string;
}

type AccessTokenRefreshResult =
  | { ok: true }
  | { ok: false; message: string; error?: unknown };

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

  /**
   * Whether the connected backend advertises a given capability. Used by
   * UI surfaces (admin modal, file menu, sidebar) to hide Pro-only controls
   * when talking to a Community Edition server. Returns true when features
   * haven't been resolved yet — historic default is Pro.
   */
  featureEnabled(name: keyof ServerFeatures): boolean {
    return this.serverFeatures ? this.serverFeatures[name] : ASSUMED_SERVER_FEATURES[name];
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
   * Electron's localStorage is shared across every Obsidian vault window,
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

  /** Original vault adapter methods (saved for restoration on unload) */
  private originalAdapterMethods: {
    read: ((normalizedPath: string) => Promise<string>) | null;
    write: ((normalizedPath: string, data: string) => Promise<void>) | null;
    readBinary: ((normalizedPath: string) => Promise<ArrayBuffer>) | null;
    writeBinary: ((normalizedPath: string, data: ArrayBuffer) => Promise<void>) | null;
    list: ((normalizedPath: string) => Promise<{ files: string[]; folders: string[] }>) | null;
    remove: ((normalizedPath: string) => Promise<void>) | null;
    rename: ((oldPath: string, newPath: string) => Promise<void>) | null;
  } = {
    read: null,
    write: null,
    readBinary: null,
    writeBinary: null,
    list: null,
    remove: null,
    rename: null,
  };

  /** Local at-rest cipher — encrypts vault files on disk so Finder shows ciphertext. */
  private atRestCipher: AtRestCipher | null = null;

  /** Per-process flag so the first-run "encrypt your plaintext files" Notice fires once. */
  private atRestFirstRunOffered = false;

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

  /**
   * Tracks whether we've already warned the user this run that the OS keystore
   * is unreachable (so we'd otherwise be forced to log them in again on every
   * launch). One Notice per session is enough — repeated `persistSession`
   * calls (token refresh, displayName update, etc.) shouldn't toast-storm.
   */
  private safeStorageUnavailableNotified = false;

  /**
   * Per-path timestamp for the denied-cache-wipe Notice. Obsidian re-reads the
   * same file on tab focus, sync, etc., and we don't want a Notice stampede
   * for a single denied path.
   */
  private readOnlyFallbackNoticeAt: Map<string, number> = new Map();

  /**
   * Per-path timestamp for the cloud-decrypt fallback Notice. Same stampede
   * concern as `readOnlyFallbackNoticeAt`, but for the case where the cloud
   * copy is encrypted with a key the current lease can't unwrap.
   */
  private cloudDecryptFallbackNoticeAt: Map<string, number> = new Map();

  /** Resolves when `initAtRestCipher()` finishes its first attempt. Reads
   * issued before init completes (e.g. early `onload()` adapter reads on
   * mobile, where session restore awaits the cipher) await this with a
   * 10s timeout before deciding to fail closed on VG1-prefixed bytes. */
  private cipherInitPromise: Promise<boolean> | null = null;

  /** Per-path 60s debounce for the corrupted-write Notice that fires when
   * an `interceptedWrite` / `interceptedWriteBinary` call would have
   * persisted bytes whose plaintext starts with the VG1 magic header. */
  private corruptedWriteNoticeAt: Map<string, number> = new Map();

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
  private offlineQueue: Array<{
    operation: "write" | "delete";
    path: string;
    data?: string;
    timestamp: string;
  }> = [];

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
  private agentBridge: VaultGuardAgentBridge | null = null;

  // ─────────────────────────────────────────────────────────────────────────
  // Lifecycle
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Called by Obsidian when the plugin is activated.
   * Initializes authentication, sync engine, commands, and vault interception.
   */
  async onload(): Promise<void> {
    this.log("Loading VaultGuard plugin...");

    // Register the ribbon buttons SYNCHRONOUSLY, up front, before the first
    // `await`. Ribbon buttons created *after* an await can be appended after
    // Obsidian has already taken its initial ribbon snapshot, leaving the button
    // missing until a later workspace event re-rendered the ribbon — which is
    // exactly why the chat icon only showed up after opening the view from the
    // command palette. The chat button uses a STOCK lucide icon, so its glyph is
    // always present at first paint (a custom `addIcon` icon can lose that race).
    addIcon("vaultguard-shield", VAULTGUARD_ICON);
    this.addRibbonIcon("vaultguard-shield", "VaultGuard", (evt: MouseEvent) => {
      this.showVaultGuardMenu(evt);
    });

    // AI Chat ribbon entry. TODO(ai-chat-feature-gate): no server `aiChat` flag
    // yet — always present for now; the view shows a connect state and makes no
    // model call until the user stores a key or uses a logged-in Claude Code
    // subscription (§11).
    this.addRibbonIcon(VAULTGUARD_CHAT_ICON_ID, "VaultGuard Chat", () => {
      void this.activateVaultGuardChat();
    });

    // Load persisted settings
    await this.loadSettings();

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

    // Phase 9: construct the unified permission store. The store does not
    // hold an apiClient reference (see PermissionStoreConfig note) — all
    // server probes go through the injected `fetchPermissionLevelFromServer`
    // callback, which itself checks `this.apiClient` and `this.session` at
    // call time. This is the correct nullability boundary: it lets onload()
    // succeed even when `apiEndpoint` is empty (manual / Community-edition
    // first-run). Must precede any init* method that subscribes via
    // `this.registerEvent(this.permissionStore.on('changed', ...))`.
    this.permissionStore = new PermissionStore({
      getSession: () => this.session,
      getVaultMemberRole: () => this.vaultMemberRole,
      isOnline: () => this.isOnline(),
      log: (msg) => this.log(msg),
      onOfflineDetected: () => this.setConnectionStatus("offline"),
      fetchPermissionLevelFromServer: (path) => this.fetchPermissionLevelFromServer(path),
      isNetworkError: (err) => this.isNetworkError(err),
      app: this.app,
    });

    // Install the adapter intercept BEFORE any awaited startup work. Reads that
    // Obsidian fires during plugin load (workspace restore, initial indexer)
    // would otherwise go through the un-intercepted adapter and could return
    // raw VG1 ciphertext as a UTF-8 string, which the editor would then
    // re-save through the encryption path and permanently corrupt the file.
    // Early reads route through readPlainFromDisk, which fails closed via
    // `cipherInitPromise` until init settles.
    this.interceptVaultAdapter();

    // Bring up the local at-rest cipher BEFORE restoring the session. On
    // mobile (no Electron `safeStorage`), session blobs are sealed with the
    // LAK rather than the OS keystore, so we need the cipher ready to
    // decrypt them. On desktop with a working safeStorage the session
    // decrypts via the synchronous path and doesn't touch the cipher.
    // If init fails (no keychain on this device, broken wrap) we surface
    // the reason in a Notice and continue in degraded plaintext mode so
    // the plugin remains usable while the user investigates.
    await this.initAtRestCipher();

    // Restore session — synchronous safeStorage path first, async at-rest
    // path second. On desktop this is effectively zero-cost; on mobile it
    // adds a single AES-GCM decrypt (a few ms).
    await this.restoreSession();

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
    void this.restorePersistentAgentBridgeLeases();

    // Register plugin commands
    this.registerCommands();

    this.registerInviteProtocolHandler();
    this.registerShareProtocolHandler();

    // Initialize file permission header (shows per-file access in markdown views)
    this.initFilePermissionHeader();

    // Lock the editor for files the user can't write — prevents view-only
    // users from accumulating edits that fail at save time.
    this.initReadOnlyGuard();

    // Register the VaultGuard sidebar view
    this.registerView(VAULTGUARD_VIEW_TYPE, (leaf) => {
      const view = new VaultGuardSidebarView(leaf);
      if (this.sidebarViewConfig) {
        view.configure(this.sidebarViewConfig);
      }
      return view;
    });

    // Register the VaultGuard AI Chat view. Construction wires it to the agent
    // bridge tool surface + lease minting + the encrypted key store + settings;
    // the view reaches vault content ONLY through the lease (encryption boundary
    // §3) and makes no model call until the user stores a key or uses a logged-in
    // Claude Code subscription (§11).
    // TODO(ai-chat-feature-gate): there is no `aiChat` ServerFeatures flag yet —
    // keep registration visible for now. Replace with featureEnabled("aiChat")
    // once the server advertises the capability.
    this.registerView(
      VAULTGUARD_CHAT_VIEW_TYPE,
      (leaf) => new VaultGuardChatView(leaf, this),
    );

    // Phase 9: subscribe the sidebar to the unified permission bus. One
    // emit fans out to decorations + header + sidebar + readOnlyGuard.
    this.registerEvent(
      this.permissionStore.on("changed", () => {
        this.reloadVaultGuardSidebar();
      })
    );

    // Build sidebar config from current session (if restored)
    const sidebarConfig = this.createSidebarViewConfig();
    if (sidebarConfig) {
      this.sidebarViewConfig = sidebarConfig;
    }

    // Initialize file explorer decorations (permission dots + avatar stacks)
    this.initFileExplorerDecorations();

    // Auto-open the VaultGuard sidebar in the right panel on first load.
    this.app.workspace.onLayoutReady(() => {
      this.ensureVaultGuardSidebar();
    });

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

    // Stop all timers
    this.stopSyncTimer();
    this.stopKeyRenewalMonitor();
    this.stopHeartbeatMonitor();
    this.stopConnectionRetry();
    this.stopAutoLockTimer();
    if (this.updateChecker) {
      this.updateChecker.stop();
      this.updateChecker = null;
    }

    // Restore original vault adapter methods
    this.restoreVaultAdapter();

    if (this.agentBridge) {
      await this.agentBridge.stopHttpServer().catch((err) =>
        this.logError("Stopping agent bridge server failed", err)
      );
      this.agentBridge.revokeAllLeases();
      this.agentBridge = null;
    }

    // Tear down API client
    if (this.apiClient) {
      this.apiClient.destroy();
      this.apiClient = null;
    }

    // Clear sensitive data from memory
    this.clearSensitiveData();

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
    const pluginWithProtocolHandler = this as unknown as {
      registerObsidianProtocolHandler?: (
        action: string,
        handler: (params: Record<string, string>) => unknown
      ) => void;
    };

    if (typeof pluginWithProtocolHandler.registerObsidianProtocolHandler !== "function") {
      this.log(
        "Obsidian protocol handlers are not available in this Obsidian version; invite links can still be pasted in settings."
      );
      return;
    }

    // Register `obsidian://vaultguard-invite?org=...&email=...` deep link
    // so invitees can click the email button and have the plugin auto-configure.
    pluginWithProtocolHandler.registerObsidianProtocolHandler(
      "vaultguard-invite",
      async (params) => {
        try {
          await this.redeemInvite(params);
        } catch (err) {
          this.logError("Invite redemption failed", err);
        }
      }
    );
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
    const pluginWithProtocolHandler = this as unknown as {
      registerObsidianProtocolHandler?: (
        action: string,
        handler: (params: Record<string, string>) => unknown
      ) => void;
    };

    if (typeof pluginWithProtocolHandler.registerObsidianProtocolHandler !== "function") {
      return;
    }

    pluginWithProtocolHandler.registerObsidianProtocolHandler(
      "vaultguard-share",
      async (params) => {
        try {
          await this.handleShareLink(params);
        } catch (err) {
          this.logError("Share link handling failed", err);
        }
      }
    );
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
    this.agentBridge = new VaultGuardAgentBridge({
      getSession: () => this.session,
      getServerVaultId: () => this.settings.serverVaultId,
      getAllFilePaths: () =>
        this.app.vault
          .getFiles()
          .map((file) => this.normalizeVaultPath(file.path)),
      fileExists: async (path) => this.app.vault.adapter.exists(path),
      ensureParentFolders: (path) => this.ensureParentFoldersForPath(path),
      isPathExcluded: (path) => this.isPathExcluded(path),
      getPermission: (path) => this.getEffectivePermission(path),
      // VaultGraph reads only the in-memory metadataCache. The bridge hands
      // in a per-lease GraphPermissionDeps (scope predicate + the same gates);
      // we supply the App so the same compiled service serves the in-plugin
      // chat and external MCP clients.
      makeVaultGraph: (graphDeps) => new VaultGraph(this.app, graphDeps),
      readText: (path) => this.interceptedRead(path),
      writeText: (path, content) => this.interceptedWrite(path, content),
      confirmWrite: (request) => this.confirmAgentBridgeWrite(request),
      log: (message) => this.log(message),
      emitAudit: (action, resourcePath, metadata) =>
        this.emitAuditEvent(action, resourcePath, metadata),
      // Forwards to the API client's instance-scoped agent-context stack so
      // every downstream HTTP request issued during `fn` carries
      // X-VG-Agent-Name / X-VG-Lease-Id and the backend's `logAudit`
      // helper merges them into the audit row's metadata. If the API
      // client is absent (early-startup race), we still run `fn` so the
      // bridge stays functional — the only loss is the attribution tag.
      withAgentContext: (agentName, leaseId, fn) =>
        this.apiClient
          ? this.apiClient.withAgentContext(agentName, leaseId, fn)
          : fn(),
      persistence: this.makeAgentBridgePersistenceAdapter(),
    });
  }

  /**
   * Persistence adapter for the agent bridge. Stores the lease envelope
   * encrypted by the at-rest cipher (so the on-disk file is opaque even
   * to a forensic image of the disk) and routes through the *raw*
   * adapter methods so the AtRestCipher layer doesn't double-encrypt
   * what we already encrypted at the application layer.
   */
  private makeAgentBridgePersistenceAdapter(): AgentBridgePersistenceAdapter | null {
    const pluginId = this.manifest?.id ?? "vaultguard-sync";
    const PATH = `.obsidian/plugins/${pluginId}/agent-leases.envelope`;
    return {
      readEnvelope: async (): Promise<string | null> => {
        if (!this.atRestCipher?.isReady()) return null;
        const readBin = this.originalAdapterMethods.readBinary;
        if (!readBin) return null;
        try {
          const exists = await this.app.vault.adapter.exists(PATH);
          if (!exists) return null;
          const cipherBytes = await readBin(PATH);
          const plaintext = await this.atRestCipher.decryptString(cipherBytes);
          return plaintext;
        } catch (err) {
          this.logError("Failed to read agent bridge lease envelope", err);
          return null;
        }
      },
      writeEnvelope: async (plaintext: string): Promise<void> => {
        if (!this.atRestCipher?.isReady()) {
          throw new Error(
            "VaultGuard Sync at-rest encryption is not ready; cannot persist agent bridge leases."
          );
        }
        const writeBin = this.originalAdapterMethods.writeBinary;
        if (!writeBin) {
          throw new Error(
            "Vault adapter is not initialized; cannot persist agent bridge leases."
          );
        }
        await this.ensureParentFoldersForPath(PATH);
        const cipher = await this.atRestCipher.encryptString(plaintext);
        await writeBin(PATH, cipher);
      },
      deleteEnvelope: async (): Promise<void> => {
        try {
          const exists = await this.app.vault.adapter.exists(PATH);
          if (!exists) return;
          await this.app.vault.adapter.remove(PATH);
        } catch (err) {
          this.logError("Failed to delete agent bridge lease envelope", err);
        }
      },
    };
  }

  /**
   * Build a ConversationStore for the chat panel, backed by the plugin's own
   * config dir (`.obsidian/plugins/<id>/chat/`, which is `isPathExcluded` —
   * plugin data, not vault content) and LAK-encrypted via AtRestCipher. Mirrors
   * the agent-leases envelope mechanism: binary read/write through the raw
   * adapter, but ONLY for the plugin's own excluded chat dir.
   *
   * Returns null if the vault adapter isn't ready yet; the caller treats that
   * as "no persistence available" and continues.
   */
  getConversationStore(): ConversationStore | null {
    const cipher = this.atRestCipher;
    if (!cipher) return null;

    const pluginId = this.manifest?.id ?? "vaultguard-sync";
    const DIR = `.obsidian/plugins/${pluginId}/chat`;
    const adapter: ConversationStorageAdapter = {
      exists: async (name) => {
        try {
          return await this.app.vault.adapter.exists(`${DIR}/${name}`);
        } catch {
          return false;
        }
      },
      readBinary: async (name) => {
        const readBin = this.originalAdapterMethods.readBinary;
        if (!readBin) throw new Error("Vault adapter not initialized.");
        return readBin(`${DIR}/${name}`);
      },
      writeBinary: async (name, bytes) => {
        const writeBin = this.originalAdapterMethods.writeBinary;
        if (!writeBin) throw new Error("Vault adapter not initialized.");
        await this.ensureParentFoldersForPath(`${DIR}/${name}`);
        await writeBin(`${DIR}/${name}`, bytes);
      },
      remove: async (name) => {
        try {
          if (await this.app.vault.adapter.exists(`${DIR}/${name}`)) {
            await this.app.vault.adapter.remove(`${DIR}/${name}`);
          }
        } catch (err) {
          this.logError("Failed to remove conversation envelope", err);
        }
      },
      list: async () => {
        try {
          if (!(await this.app.vault.adapter.exists(DIR))) return [];
          const listing = await this.app.vault.adapter.list(DIR);
          // adapter.list returns full paths under DIR; strip the dir prefix.
          return listing.files.map((p) => p.slice(p.lastIndexOf("/") + 1));
        } catch {
          return [];
        }
      },
    };

    return new ConversationStore({ cipher, adapter });
  }

  private ensureAgentBridge(): VaultGuardAgentBridge {
    if (!this.agentBridge) {
      this.initAgentBridge();
    }
    return this.agentBridge!;
  }

  /**
   * Public plugin API for trusted integrations that want to call VaultGuard
   * tools instead of reading the vault folder. The returned surface cannot
   * mint its own leases; a user or admin must create one first.
   */
  getAgentBridge(): AgentBridgeToolSurface {
    return this.ensureAgentBridge().getToolSurface();
  }

  async createAgentBridgeLease(input: AgentBridgeLeaseInput = {}): Promise<AgentBridgeLeaseSecret> {
    return this.ensureAgentBridge().createLease(input);
  }

  rotateAgentBridgeLeaseToken(leaseId: string): AgentBridgeLeaseSecret {
    return this.ensureAgentBridge().rotateLeaseToken(leaseId);
  }

  async loadPersistedAgentBridgeLeases(): Promise<{ restored: number; dropped: number }> {
    return this.ensureAgentBridge().loadPersistedLeases();
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
    if (!this.session || !this.settings.serverVaultId) return;
    if (!this.atRestCipher?.isReady()) {
      // No LAK, no envelope to read. Persistent leases require at-rest;
      // re-attempt later if the cipher is initialized after first-run.
      return;
    }
    try {
      const { restored } = await this.loadPersistedAgentBridgeLeases();
      if (restored > 0) {
        const server = await this.startAgentBridgeServer();
        new Notice(
          `VaultGuard Sync: ${restored} persistent agent bridge ${restored === 1 ? "lease is" : "leases are"} active. Endpoint: ${server.endpoint}.`,
          8000
        );
      }
    } catch (err) {
      this.logError("Failed to restore persistent agent bridge leases", err);
    }
  }

  async revokeAgentBridgeLeasesForSessionEnd(reason: string): Promise<number> {
    if (!this.agentBridge) return 0;
    return this.agentBridge.revokePersistentLeasesForSessionEnd(reason);
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

  /**
   * Resolves Node `fs`/`path`/`os` via Electron's require if available,
   * otherwise returns null. Mobile and other web-only contexts hit the
   * null path and the UI shows "skill install not available on this
   * device" instead of throwing.
   */
  private getSkillInstallerDeps(): SkillInstallerDeps | null {
    const maybeWindow = typeof window !== "undefined" ? (window as unknown as Record<string, unknown>) : {};
    const maybeGlobal = globalThis as unknown as Record<string, unknown>;
    const req =
      typeof maybeWindow.require === "function"
        ? (maybeWindow.require as NodeRequire)
        : typeof maybeGlobal.require === "function"
          ? (maybeGlobal.require as NodeRequire)
          : null;
    if (!req) return null;
    try {
      const fs = req("fs") as SkillInstallerDeps["fs"];
      const path = req("path") as SkillInstallerDeps["path"];
      const os = req("os") as { homedir(): string };
      return {
        fs,
        path,
        homedir: () => os.homedir(),
        log: (msg) => this.log(msg),
      };
    } catch (err) {
      this.logError("Could not load Node FS modules for skill installer", err);
      return null;
    }
  }

  getAgentBridgeSkillStatus(): (SkillInstallStatus & { available: true }) | { available: false } {
    const deps = this.getSkillInstallerDeps();
    if (!deps) return { available: false };
    return { ...inspectSkillInstall(deps), available: true };
  }

  async installAgentBridgeSkill(options: { overwriteUnmanaged?: boolean } = {}): Promise<InstallResult> {
    const deps = this.getSkillInstallerDeps();
    if (!deps) {
      throw new Error(
        "Skill install requires Node filesystem access (desktop Obsidian). Skipping on this device."
      );
    }
    const result = installSkill(deps, options);
    await this.emitAuditEvent("bridge.skill_installed", result.filePath, {
      action: result.action,
      overwriteUnmanaged: options.overwriteUnmanaged === true,
    });
    return result;
  }

  async uninstallAgentBridgeSkill(options: { force?: boolean } = {}): Promise<{
    filePath: string;
    removed: boolean;
  }> {
    const deps = this.getSkillInstallerDeps();
    if (!deps) {
      throw new Error("Skill uninstall requires Node filesystem access (desktop Obsidian).");
    }
    const result = uninstallSkill(deps, options);
    if (result.removed) {
      await this.emitAuditEvent("bridge.skill_uninstalled", result.filePath, {
        force: options.force === true,
      });
    }
    return result;
  }

  revokeAgentBridgeLease(leaseId: string): boolean {
    return this.ensureAgentBridge().revokeLease(leaseId);
  }

  revokeAllAgentBridgeLeases(): void {
    this.ensureAgentBridge().revokeAllLeases();
  }

  async startAgentBridgeServer(): Promise<AgentBridgeServerInfo> {
    return this.ensureAgentBridge().startHttpServer();
  }

  async stopAgentBridgeServer(): Promise<void> {
    await this.ensureAgentBridge().stopHttpServer();
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
    const maybeGlobal = globalThis as unknown as Record<string, unknown>;
    const req =
      typeof maybeWindow.require === "function"
        ? (maybeWindow.require as NodeRequire)
        : typeof maybeGlobal.require === "function"
          ? (maybeGlobal.require as NodeRequire)
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

  private async confirmAgentBridgeWrite(request: {
    lease: AgentBridgeLeaseSummary;
    operation: "create" | "apply_patch";
    path: string;
    preview: string;
  }): Promise<boolean> {
    // Render a real red/green diff in an Obsidian modal when the app UI is
    // available. This is presentation-only: the approve/reject Promise<boolean>
    // contract and the upstream-capped preview are unchanged.
    if (this.app?.workspace) {
      return new Promise<boolean>((resolve) => {
        new WriteConfirmModal(
          this.app,
          {
            agentName: request.lease.agentName,
            operation: request.operation,
            path: request.path,
            scopes: request.lease.scopes,
            expiresAt: request.lease.expiresAt,
            preview: request.preview,
          },
          (allow) => resolve(allow),
        ).open();
      });
    }

    // Headless fallback (tests / no-DOM hosts): keep the prior text confirm.
    const operationLabel =
      request.operation === "create" ? "create" : "patch";
    const message =
      `VaultGuard Sync: Agent "${request.lease.agentName}" wants to ${operationLabel} "${request.path}".\n\n` +
      `Scope: ${request.lease.scopes.join(", ")}\n` +
      `Lease expires: ${request.lease.expiresAt}\n\n` +
      `Preview:\n${request.preview}\n\nAllow this write?`;

    if (typeof window !== "undefined" && typeof window.confirm === "function") {
      return window.confirm(message);
    }

    return false;
  }

  private openAgentBridgeLeaseModal(): void {
    new AgentBridgeLeaseModal(this).open();
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Settings Management
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Loads settings from Obsidian's data store, merging with defaults
   * for any missing fields.
   */
  async loadSettings(): Promise<void> {
    const data = ((await this.loadData()) ?? {}) as VaultGuardPluginData;
    this.persistedSessions = this.normalizePersistedSessions(data.storedSessions);
    const { storedSessions: _storedSessions, ...settingsData } = data;
    this.settings = Object.assign({}, DEFAULT_SETTINGS, settingsData);
    this.settings.excludedPaths = this.withRequiredExcludedPaths(this.settings.excludedPaths);
    this.settings.apiEndpoint = normalizeVaultGuardApiBaseUrl(this.settings.apiEndpoint);
    this.configuredApiEndpoint = this.settings.apiEndpoint;
    this.serverEdition = this.normalizeServerEdition(this.settings.serverEdition);
    this.serverFeatures = this.normalizeServerFeatures(this.settings.serverFeatures);

    this.derivedBindingId = await this.computeDerivedVaultBindingId();
  }

  private normalizeServerEdition(value: unknown): ServerEdition | null {
    return value === "community" || value === "pro" ? value : null;
  }

  private normalizeServerFeatures(value: unknown): ServerFeatures | null {
    if (!value || typeof value !== "object") {
      return null;
    }
    const features = value as Partial<Record<keyof ServerFeatures, unknown>>;
    return {
      shareLinks: Boolean(features.shareLinks),
      advancedAudit: Boolean(features.advancedAudit),
      billing: Boolean(features.billing),
      webAdmin: Boolean(features.webAdmin),
    };
  }

  private communityServerFeatures(): ServerFeatures {
    return {
      shareLinks: false,
      advancedAudit: false,
      billing: false,
      webAdmin: false,
    };
  }

  private cacheServerCapabilities(config: Record<string, unknown>): boolean {
    const edition = this.normalizeServerEdition(config.edition) ?? "pro";
    const features =
      this.normalizeServerFeatures(config.features) ??
      (edition === "community"
        ? this.communityServerFeatures()
        : { ...ASSUMED_SERVER_FEATURES });

    const changed =
      this.serverEdition !== edition ||
      !this.serverFeatures ||
      this.serverFeatures.shareLinks !== features.shareLinks ||
      this.serverFeatures.advancedAudit !== features.advancedAudit ||
      this.serverFeatures.billing !== features.billing ||
      this.serverFeatures.webAdmin !== features.webAdmin;

    this.serverEdition = edition;
    this.serverFeatures = { ...features };
    this.settings.serverEdition = edition;
    this.settings.serverFeatures = { ...features };
    this.settings.serverFeaturesResolvedAt = new Date().toISOString();
    return changed;
  }

  private async refreshServerCapabilitiesFromConfiguredEndpoint(): Promise<boolean> {
    const cfg = this.getEffectiveConfig();
    const base = normalizeVaultGuardApiBaseUrl(cfg.apiEndpoint);
    const identifiers = Array.from(
      new Set(
        [
          this.settings.orgSlug,
          cfg.organizationId,
        ]
          .map((value) => (value ?? "").trim())
          .filter((value) => value.length > 0)
      )
    );

    if (!base || identifiers.length === 0) {
      return false;
    }

    let lastError: Error | null = null;
    for (const identifier of identifiers) {
      const url = `${base}/orgs/${encodeURIComponent(identifier)}/config`;
      try {
        const response = await requestUrl({ url, method: "GET", throw: false });
        if (response.status === 404) {
          continue;
        }
        if (response.status === 401 || response.status === 403) {
          return false;
        }
        if (response.status < 200 || response.status >= 300) {
          lastError = new Error(`Server returned ${response.status}`);
          continue;
        }
        if (!response.json || typeof response.json !== "object") {
          lastError = new Error("Invalid config response from server");
          continue;
        }

        const config = response.json as Record<string, unknown>;
        if (typeof config.orgSlug === "string" && config.orgSlug) {
          this.settings.orgSlug = config.orgSlug;
        }
        const changed = this.cacheServerCapabilities(config);
        await this.saveSettings();
        return changed;
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));
      }
    }

    if (lastError) {
      this.logError("Server capability discovery failed", lastError);
    }
    return false;
  }

  private withRequiredExcludedPaths(paths: string[] | undefined): string[] {
    const merged: string[] = [];
    const seen = new Set<string>();

    const add = (path: string): void => {
      const cleaned = path.trim().replace(/^\/+/, "").replace(/\/+$/, "");
      if (!cleaned || seen.has(cleaned)) return;
      seen.add(cleaned);
      merged.push(cleaned);
    };

    for (const path of paths ?? []) {
      add(path);
    }
    for (const path of DEFAULT_EXCLUDED_PATHS) {
      add(path);
    }

    return merged;
  }

  /**
   * Persists current settings to Obsidian's data store.
   */
  async saveSettings(): Promise<void> {
    const normalizedApiEndpoint = normalizeVaultGuardApiBaseUrl(this.settings.apiEndpoint);
    const apiEndpointChanged = normalizedApiEndpoint !== this.configuredApiEndpoint;
    this.settings.apiEndpoint = normalizedApiEndpoint;
    await this.savePluginData();

    if (apiEndpointChanged) {
      this.configuredApiEndpoint = normalizedApiEndpoint;
      this.resetResolvedApiEndpoint();
      this.rebuildApiClient();
    }
  }

  private clearResolvedConnectionFields(): void {
    this.settings.orgSlug = "";
    this.settings.apiEndpoint = "";
    this.settings.organizationId = "";
    this.settings.cognitoUserPoolId = "";
    this.settings.cognitoClientId = "";
    this.settings.serverEdition = undefined;
    this.settings.serverFeatures = undefined;
    this.settings.serverFeaturesResolvedAt = undefined;
    this.serverEdition = null;
    this.serverFeatures = null;
  }

  async resetCloudConnectionDefaults(): Promise<void> {
    if (this.session) {
      await this.forceLogout("VaultGuard Sync: Logged out because the connection target changed.");
    }
    this.settings.manualConfig = false;
    this.clearResolvedConnectionFields();
    await this.saveSettings();
  }

  async setManualConfigurationMode(manualConfig: boolean): Promise<void> {
    if ((this.settings.manualConfig ?? false) === manualConfig) {
      return;
    }

    if (this.session) {
      await this.forceLogout("VaultGuard Sync: Logged out because the connection mode changed.");
    }

    this.settings.manualConfig = manualConfig;
    this.clearResolvedConnectionFields();
    await this.saveSettings();
  }

  getConnectionTargetLabel(): string {
    const config = this.getEffectiveConfig();
    const endpoint = config.apiEndpoint || "not configured";
    const mode = this.settings.manualConfig ? "manual/self-hosted" : "VaultGuard Cloud";
    const org =
      this.settings.orgSlug ||
      this.settings.organizationId ||
      (this.settings.manualConfig ? "" : "not connected");
    return org ? `${mode}: ${endpoint} (${org})` : `${mode}: ${endpoint}`;
  }

  private readConfigString(config: Record<string, unknown>, key: string): string {
    const value = config[key];
    return typeof value === "string" ? value.trim() : "";
  }

  private applyResolvedConnectionConfig(
    config: Record<string, unknown>,
    fallbackApiEndpoint: string,
    fallbackOrgSlug = ""
  ): void {
    const cognitoUserPoolId = this.readConfigString(config, "cognitoUserPoolId");
    const cognitoClientId = this.readConfigString(config, "cognitoClientId");
    if (!cognitoUserPoolId || !cognitoClientId) {
      throw new Error("Invalid config response from server");
    }

    const apiEndpoint = normalizeVaultGuardApiBaseUrl(
      this.readConfigString(config, "apiEndpoint") || fallbackApiEndpoint
    );
    if (!apiEndpoint) {
      throw new Error("Invalid config response from server: missing API endpoint");
    }

    const orgSlug = this.readConfigString(config, "orgSlug") || fallbackOrgSlug;
    const organizationId =
      this.readConfigString(config, "orgId") ||
      this.readConfigString(config, "organizationId");

    if (orgSlug) {
      this.settings.orgSlug = orgSlug;
    }
    this.settings.apiEndpoint = apiEndpoint;
    this.settings.organizationId = organizationId;
    this.settings.cognitoUserPoolId = cognitoUserPoolId;
    this.settings.cognitoClientId = cognitoClientId;
    this.cacheServerCapabilities(config);
  }

  private assertHttpsOrLocalhostUrl(rawUrl: string, label: string): URL {
    let parsed: URL;
    try {
      parsed = new URL(rawUrl.trim());
    } catch {
      throw new Error(`Enter a valid ${label}.`);
    }

    const hostname = parsed.hostname.toLowerCase();
    const isLocalhost =
      hostname === "localhost" ||
      hostname === "127.0.0.1" ||
      hostname === "::1" ||
      hostname === "[::1]";
    if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && isLocalhost)) {
      throw new Error(`${label} must use HTTPS, except localhost during development.`);
    }

    return parsed;
  }

  private normalizeManualServerConfigUrl(rawUrl: string): string {
    const parsed = this.assertHttpsOrLocalhostUrl(rawUrl, "server config URL");
    return parsed.toString();
  }

  /**
   * Reasonable upper bound for a well-known config document. The legitimate
   * payload is ~500 bytes; 64 KB leaves ~125x headroom while preventing a
   * malicious server from exhausting Obsidian's memory with a multi-GB body.
   */
  private static readonly MANUAL_CONFIG_MAX_BYTES = 64 * 1024;

  /** Timeout for the manual config fetch — Obsidian's requestUrl has no abort. */
  private static readonly MANUAL_CONFIG_TIMEOUT_MS = 10_000;

  async applyManualServerConfigUrl(rawUrl: string): Promise<void> {
    const url = this.normalizeManualServerConfigUrl(rawUrl);
    const pastedOrigin = new URL(url);

    // WR-04: bound the wait with a manual timeout (requestUrl has no native
    // abort path) so a stalled or pathological server can't hang the plugin.
    const response = await Promise.race([
      requestUrl({ url, method: "GET", throw: false }),
      new Promise<never>((_resolve, reject) =>
        setTimeout(
          () => reject(new Error("Server config request timed out after 10 seconds.")),
          VaultGuardPlugin.MANUAL_CONFIG_TIMEOUT_MS
        )
      ),
    ]);

    if (response.status < 200 || response.status >= 300) {
      throw new Error(`Server returned ${response.status}`);
    }

    // WR-04: cap response size before doing any further parsing/work.
    const bodyText = response.text ?? "";
    if (bodyText.length > VaultGuardPlugin.MANUAL_CONFIG_MAX_BYTES) {
      throw new Error(
        "Server config response is unexpectedly large; rejecting to prevent memory exhaustion."
      );
    }

    // Strict shape: must be a JSON object literal (not null, not array, not primitive).
    if (
      !response.json ||
      typeof response.json !== "object" ||
      Array.isArray(response.json)
    ) {
      throw new Error("Invalid config response from server: expected a JSON object");
    }

    const config = response.json as Record<string, unknown>;

    // WR-05 + CR-01: validate the response shape AND enforce that any apiEndpoint
    // in the body shares the same hostname as the pasted URL. The well-known doc
    // is by RFC-8615 convention served from the API root, so the pasted URL's
    // host is the authoritative API host — the response body must not be allowed
    // to redirect the user to a different (attacker-controlled) host.
    this.validateWellKnownConfig(config, pastedOrigin);

    if (this.session) {
      await this.forceLogout("VaultGuard Sync: Logged out because the connection target changed.");
    }

    this.settings.manualConfig = true;
    // Use the pasted URL's origin as the apiEndpoint fallback when the body
    // omits it. When the body provides an apiEndpoint, it has just been
    // hostname-pinned to the pasted URL by validateWellKnownConfig.
    this.applyResolvedConnectionConfig(config, pastedOrigin.origin, this.settings.orgSlug);
    await this.saveSettings();
    this.rebuildApiClient();
  }

  /**
   * Strict validator for a manually-pasted /.well-known/vaultguard.json
   * response. Rejects the response — does not partial-apply — if any field
   * fails its format check, or if the body's apiEndpoint points at a host
   * other than the one the user pasted.
   */
  private validateWellKnownConfig(
    config: Record<string, unknown>,
    pastedOrigin: URL
  ): void {
    const cognitoUserPoolId = this.readConfigString(config, "cognitoUserPoolId");
    const cognitoClientId = this.readConfigString(config, "cognitoClientId");
    if (!cognitoUserPoolId || !cognitoClientId) {
      throw new Error("Invalid config response from server: missing Cognito identifiers");
    }

    // Cognito User Pool IDs follow `<region>_<random>` where region is a
    // standard AWS region name. Reject anything that doesn't match — a real
    // server can never return e.g. an HTML error page parsed as a string here.
    if (!/^[a-z]{2}-[a-z]+-\d+_[A-Za-z0-9]{6,}$/.test(cognitoUserPoolId)) {
      throw new Error(
        "Invalid config response from server: cognitoUserPoolId is not a valid Cognito pool identifier"
      );
    }

    // Cognito App Client IDs are 20-26 lowercase alphanumeric characters.
    if (!/^[a-z0-9]{20,26}$/.test(cognitoClientId)) {
      throw new Error(
        "Invalid config response from server: cognitoClientId is not a valid Cognito app client identifier"
      );
    }

    // orgSlug (if present) must match the backend's slug regex.
    const orgSlug = this.readConfigString(config, "orgSlug");
    if (orgSlug && !/^[a-z0-9][a-z0-9-]{0,46}[a-z0-9]$/.test(orgSlug)) {
      throw new Error(
        "Invalid config response from server: orgSlug is not a valid identifier"
      );
    }

    // CR-01: any apiEndpoint in the response body must point at the same host
    // the user pasted. We never honor a body-supplied redirect to a different
    // host — that would let a malicious .well-known doc silently route the
    // user's credentials and encrypted vault traffic to attacker infrastructure.
    const apiEndpoint = this.readConfigString(config, "apiEndpoint");
    if (apiEndpoint) {
      let parsed: URL;
      try {
        parsed = new URL(apiEndpoint);
      } catch {
        throw new Error(
          "Invalid config response from server: apiEndpoint is not a parseable URL"
        );
      }
      this.assertHttpsOrLocalhostUrl(apiEndpoint, "API endpoint");
      if (parsed.hostname.toLowerCase() !== pastedOrigin.hostname.toLowerCase()) {
        throw new Error(
          `Invalid config response from server: apiEndpoint host (${parsed.hostname}) does not match the pasted URL host (${pastedOrigin.hostname}). To use a separate API host, paste that host's /.well-known/vaultguard.json URL directly.`
        );
      }
    }
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
    if (this.settings.manualConfig) {
      return {
        apiEndpoint: this.settings.apiEndpoint,
        cognitoUserPoolId: this.settings.cognitoUserPoolId,
        cognitoClientId: this.settings.cognitoClientId,
        organizationId: this.settings.organizationId,
      };
    }
    return {
      apiEndpoint: this.settings.apiEndpoint || SAAS_DEFAULTS.apiEndpoint,
      cognitoUserPoolId: this.settings.cognitoUserPoolId || SAAS_DEFAULTS.cognitoUserPoolId,
      cognitoClientId: this.settings.cognitoClientId || SAAS_DEFAULTS.cognitoClientId,
      organizationId: this.settings.organizationId,
    };
  }

  private rebuildApiClient(): void {
    if (this.apiClient) {
      this.apiClient.destroy();
      this.apiClient = null;
    }

    const config = this.getEffectiveConfig();

    if (!config.apiEndpoint) {
      return;
    }

    this.apiClient = new VaultGuardApiClient({
      baseUrl: config.apiEndpoint,
      orgId: config.organizationId,
      vaultId: this.settings.serverVaultId,
      getAuthTokens: async (forceRefresh = false) => {
        if (!this.session) {
          return null;
        }

        const expiresAt = new Date(this.session.tokenExpiresAt).getTime();
        if (forceRefresh || expiresAt - Date.now() <= 60_000) {
          const refreshResult = await this.refreshAccessToken(this.session);
          if (!refreshResult.ok) {
            return null;
          }
        }

        if (!this.session) {
          return null;
        }

        return {
          accessToken: this.session.accessToken,
          refreshToken: this.session.refreshToken,
          idToken: this.session.idToken,
          expiresAt: new Date(this.session.tokenExpiresAt).getTime(),
        };
      },
      getSessionId: () => this.session?.sessionId ?? null,
    });

    if (this.session) {
      this.initializeApiClientFromSession(this.session);
    }
  }

  private resetResolvedApiEndpoint(): void {
    this.resolvedApiEndpoint = null;
    this.apiEndpointResolutionPromise = null;
  }

  private async getResolvedApiEndpoint(idToken?: string, probePath?: string): Promise<string> {
    const configuredApiEndpoint = normalizeVaultGuardApiBaseUrl(this.getEffectiveConfig().apiEndpoint);
    if (!configuredApiEndpoint) {
      return "";
    }

    if (this.resolvedApiEndpoint) {
      return this.resolvedApiEndpoint;
    }

    if (!idToken) {
      return configuredApiEndpoint;
    }

    if (this.apiEndpointResolutionPromise) {
      return await this.apiEndpointResolutionPromise;
    }

    const resolutionPromise = resolveVaultGuardApiBaseUrl(
      configuredApiEndpoint,
      idToken,
      probePath
    );
    this.apiEndpointResolutionPromise = resolutionPromise;

    try {
      this.resolvedApiEndpoint = await resolutionPromise;
      return this.resolvedApiEndpoint;
    } finally {
      if (this.apiEndpointResolutionPromise === resolutionPromise) {
        this.apiEndpointResolutionPromise = null;
      }
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Command Registration
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Registers all plugin commands accessible via the command palette.
   */
  private registerCommands(): void {
    // Login command
    this.addCommand({
      id: "login",
      name: "Login",
      callback: () => this.handleLogin(),
    });

    // Logout command (only shown when logged in)
    this.addCommand({
      id: "logout",
      name: "Logout",
      checkCallback: (checking: boolean) => {
        if (checking) {
          return !!this.session;
        }
        this.forceLogout();
      },
    });

    // Manual sync trigger
    this.addCommand({
      id: "sync-now",
      name: "Sync Now",
      callback: () => this.performSync({ userInitiated: true, forceCatchup: true }),
    });

    // Share-link lifecycle: list active links and revoke leaked ones. On
    // Community Edition the command opens a Pro-upsell modal instead of the
    // share-management modal — same compiled binary, show-but-block UX.
    this.addCommand({
      id: "manage-share-links",
      name: "Manage share links",
      checkCallback: (checking: boolean) => {
        const ready =
          !!this.session &&
          !!this.apiClient &&
          !!this.settings.serverVaultId;
        if (checking) return ready;
        if (ready) {
          if (!this.featureEnabled('shareLinks')) {
            new ProUpsellModal(this.app, "shareLinks").open();
          } else {
            this.openShareManagementModal();
          }
        }
      },
    });

    // Status — surfaces auth/sync state in a Notice. Useful for diagnosing
    // "is the plugin actually reloaded after my rebuild?" — if this command
    // doesn't exist in the palette, the new build isn't loaded.
    this.addCommand({
      id: "status",
      name: "Status",
      callback: () => this.showStatusNotice(),
    });

    // Main plugin menu
    this.addCommand({
      id: "open-menu",
      name: "Open VaultGuard Sync Menu",
      callback: () => this.showVaultGuardMenu(),
    });

    // Audit log — admin/owner only; opens AdminModal preset to the audit tab.
    this.addCommand({
      id: "open-audit-log",
      name: "Open Audit Log",
      checkCallback: (checking: boolean) => {
        const isAdmin =
          this.session?.role === "admin" || this.session?.role === "owner";
        const ready = !!this.session && isAdmin && !!this.apiClient;
        if (checking) return ready;
        if (ready) this.openAuditLog();
      },
    });

    // Web admin panel — any logged-in user; CE-branch shows ProUpsellModal.
    this.addCommand({
      id: "open-web-admin",
      name: "Open Web Admin Panel",
      checkCallback: (checking: boolean) => {
        const ready = !!this.session;
        if (checking) return ready;
        if (ready) this.openWebAdminPanel();
      },
    });

    // Direct settings entry point
    this.addCommand({
      id: "open-settings",
      name: "Open VaultGuard Sync Settings",
      callback: () => this.openVaultGuardSettings(),
    });

    // View current user's permissions
    this.addCommand({
      id: "view-permissions",
      name: "View Permissions",
      callback: () => this.showPermissionsModal(),
    });

    // Manage the whole vault's permission rules (admin-panel-style table)
    this.addCommand({
      id: "manage-permission-rules",
      name: "Manage Permissions",
      callback: () => this.showPermissionRulesModal(),
    });

    // Open VaultGuard Files sidebar
    this.addCommand({
      id: "files-panel",
      name: "Open VaultGuard Sync Files Panel",
      callback: () => this.activateVaultGuardSidebar(),
    });

    // Agent bridge needs Node `http` (local MCP server) — desktop only.
    // We still register on mobile via checkCallback returning false so the
    // command palette doesn't surface a broken entry.
    this.addCommand({
      id: "create-agent-bridge-lease",
      name: "Create Agent Bridge Lease",
      checkCallback: (checking: boolean) => {
        if (Platform.isMobileApp) return false;
        const ready = !!this.session && !!this.settings.serverVaultId;
        if (checking) return ready;
        this.openAgentBridgeLeaseModal();
      },
    });

    this.addCommand({
      id: "revoke-agent-bridge-leases",
      name: "Revoke Agent Bridge Leases",
      checkCallback: (checking: boolean) => {
        if (Platform.isMobileApp) return false;
        if (checking) return true;
        this.revokeAllAgentBridgeLeases();
        void this.stopAgentBridgeServer().catch((err) =>
          this.logError("Stopping agent bridge server failed", err)
        );
        new Notice("VaultGuard Sync: Agent bridge leases revoked.");
      },
    });

    // Always-present discoverability command so mobile users see a clear
    // explanation when they search the palette for "agent bridge" instead of
    // an empty result. On desktop, this opens the lease modal like the
    // primary command above (it's a synonym entry point).
    this.addCommand({
      id: "vaultguard-agent-bridge-info",
      name: "VaultGuard: Agent bridge (desktop only)",
      callback: () => {
        if (Platform.isMobileApp) {
          new Notice(
            "Agent bridge requires Obsidian desktop. This feature is unavailable on mobile.",
            6000
          );
          return;
        }
        if (!this.session || !this.settings.serverVaultId) {
          new Notice(
            "Agent bridge requires Obsidian desktop. Sign in and pick a vault to mint a lease.",
            6000
          );
          return;
        }
        this.openAgentBridgeLeaseModal();
      },
    });

    // Manual update probe — bypasses the 24h throttle. Lets users (and
    // support) confirm the plugin is the latest published version on demand.
    this.addCommand({
      id: "check-for-updates",
      name: "Check for plugin updates",
      callback: async () => {
        if (!this.updateChecker) {
          new Notice("VaultGuard Sync: update checker is not initialized.");
          return;
        }
        new Notice("VaultGuard Sync: checking for updates…");
        const result = await this.updateChecker.checkNow();
        if (result.latest === null) {
          new Notice(
            this.settings.disableUpdateChecks
              ? "VaultGuard Sync: update checks are disabled in settings."
              : "VaultGuard Sync: couldn't reach the release feed. Try again later.",
            6000
          );
          return;
        }
        if (!result.isNewer) {
          new Notice(
            `VaultGuard Sync: you're on the latest version (${this.manifest.version}).`,
            5000
          );
        }
        // If a newer version exists, the checker has already shown its own Notice.
      },
    });

    // One-shot at-rest encryption pass over the entire vault. Lazy migration
    // (encrypting on touch) is sufficient over time, but a user testing the
    // protection wants instant feedback. This command walks every file and
    // rewrites already-plaintext bytes as ciphertext.
    this.addCommand({
      id: "encrypt-vault-at-rest",
      name: "Encrypt vault at rest (full pass)",
      callback: () => void this.encryptVaultAtRest(),
    });

    // Reverse the at-rest encryption — useful before disabling the plugin
    // so the vault contents remain readable through normal Obsidian.
    this.addCommand({
      id: "decrypt-vault-at-rest",
      name: "Decrypt vault at rest (back to plaintext)",
      callback: () => void this.decryptVaultAtRest(),
    });

    // Pick / switch the bound server-side vault for this Obsidian folder.
    this.addCommand({
      id: "pick-vault",
      name: "Pick or Switch Server Vault",
      checkCallback: (checking: boolean) => {
        if (checking) {
          return !!this.session && !!this.apiClient;
        }
        void this.switchServerVault();
      },
    });

    // Admin panel (only shown to admin/owner users)
    this.addCommand({
      id: "admin",
      name: "Manage Organization",
      checkCallback: (checking: boolean) => {
        const isAdmin =
          this.session?.role === "admin" || this.session?.role === "owner";
        if (checking) {
          return isAdmin;
        }
        if (isAdmin) {
          this.showAdminPanel();
        }
      },
    });

    // Right-click context menu on files and folders in the file explorer
    this.registerEvent(
      this.app.workspace.on("file-menu", (menu: Menu, file: TAbstractFile) => {
        if (!this.session || !this.apiClient) return;

        const isAdmin = this.isEffectiveAdmin();

        const path = file.path;
        const isFolder = file instanceof TFolder;
        const label = isFolder ? "folder" : "file";

        // "View Permissions" — available to all authenticated users
        menu.addItem((item) => {
          item
            .setTitle(`VaultGuard Sync: View ${label} permissions`)
            .setIcon("shield")
            .onClick(() => {
              this.showPathPermissionsModal(path, isFolder);
            });
        });

        // "Copy share link" — files only, any vault member can mint a link
        // since the link itself grants nothing without team membership. On
        // Community Edition this opens a Pro-upsell modal explaining the
        // feature instead of minting a link.
        if (!isFolder) {
          menu.addItem((item) => {
            item
              .setTitle("VaultGuard Sync: Copy share link")
              .setIcon("link")
              .onClick(() => {
                if (!this.featureEnabled('shareLinks')) {
                  new ProUpsellModal(this.app, "shareLinks").open();
                  return;
                }
                void this.copyShareLinkForPath(path);
              });
          });
        }

        // "Set Permissions" — admin only
        if (isAdmin) {
          menu.addItem((item) => {
            item
              .setTitle(`VaultGuard Sync: Set permissions on ${label}`)
              .setIcon("lock")
              .onClick(() => {
                this.showAddPermissionForPath(path, isFolder);
              });
          });
        }
      })
    );

    // AI Chat — the real entry point for the chat panel.
    // TODO(ai-chat-feature-gate): no server `aiChat` flag yet — always listed;
    // the view stays offline until a key or logged-in subscription is available.
    this.addCommand({
      id: "vaultguard-open-chat",
      name: "VaultGuard Chat: Open AI chat panel",
      callback: () => {
        void this.activateVaultGuardChat();
      },
    });

    // Previous chats — open the panel and surface the saved-conversation list.
    this.addCommand({
      id: "vaultguard-chat-history",
      name: "VaultGuard Chat: Previous chats",
      callback: () => {
        void this.openVaultGuardChatHistory();
      },
    });

    // New chat in its own tab — lets several conversations stay open at once
    // (stacked in the right sidebar). The + button inside the panel still
    // resets the current chat in place; this opens a separate tab.
    this.addCommand({
      id: "vaultguard-chat-new-tab",
      name: "VaultGuard Chat: New chat (new tab)",
      callback: () => {
        void this.openNewVaultGuardChatTab();
      },
    });

    // The headless debug harness stays useful for proving the tool path, but the
    // chat view above is the real entry now. It remains invisible unless
    // settings.debugLogging is on (checkCallback guard).
    registerChatDebugCommand(this);
  }

  /**
   * Open (or reveal) the VaultGuard AI Chat panel in the right sidebar.
   */
  private async activateVaultGuardChat(): Promise<void> {
    const existing = this.app.workspace.getLeavesOfType(VAULTGUARD_CHAT_VIEW_TYPE);
    if (existing.length > 0) {
      this.app.workspace.revealLeaf(existing[0]);
      return;
    }

    const leaf = this.app.workspace.getRightLeaf(false);
    if (leaf) {
      await leaf.setViewState({ type: VAULTGUARD_CHAT_VIEW_TYPE, active: true });
      this.app.workspace.revealLeaf(leaf);
    }
  }

  /**
   * Open a brand-new VaultGuard AI Chat conversation in its OWN right-sidebar
   * tab, leaving any already-open chats untouched. `getRightLeaf(false)` creates
   * a new leaf stacked as a tab (not a split); the `fresh` state tells the view
   * to start blank instead of restoring the most-recent conversation.
   */
  async openNewVaultGuardChatTab(): Promise<void> {
    const leaf = this.app.workspace.getRightLeaf(false);
    if (!leaf) return;
    await leaf.setViewState({
      type: VAULTGUARD_CHAT_VIEW_TYPE,
      active: true,
      state: { fresh: true },
    });
    this.app.workspace.revealLeaf(leaf);
  }

  /** Open the chat panel and pop the previous-chats picker. */
  private async openVaultGuardChatHistory(): Promise<void> {
    await this.activateVaultGuardChat();
    const leaves = this.app.workspace.getLeavesOfType(VAULTGUARD_CHAT_VIEW_TYPE);
    const view = leaves[0]?.view;
    if (view instanceof VaultGuardChatView) {
      view.showHistoryPicker();
    }
  }

  /**
   * Mints a share link for the given vault-relative path and copies the
   * https URL to the clipboard. Falls back to a modal-style display if the
   * clipboard API is unavailable (e.g. some headless test environments).
   */
  /** Opens the share-management modal — listed in the command palette. */
  private openShareManagementModal(): void {
    if (!this.apiClient || !this.session) return;
    new ShareManagementModal(this.app, this.apiClient).open();
  }

  private async copyShareLinkForPath(path: string): Promise<void> {
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
   * Restores session from localStorage. On desktop the safeStorage envelope
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
          if (
            !cfg.apiEndpoint ||
            !cfg.organizationId ||
            !cfg.cognitoUserPoolId ||
            !cfg.cognitoClientId
          ) {
            throw new Error(
              "Manual configuration requires API endpoint, organization ID, Cognito User Pool ID, and Cognito Client ID."
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

    // If we have a pending MFA challenge, respond to it
    if (this.pendingChallengeSession && credentials.mfaCode) {
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
        throw new Error("Password change required. Please contact your administrator.");
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
        onComplete: async (result) => {
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
          } catch (error) {
            // MFA was set up but challenge completion failed — user can log in with MFA next time
            new Notice("VaultGuard Sync: MFA enabled! Please log in again with your authenticator code.");
            resolve();
          }
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

    this.session = {
      sessionId: serverSession.sessionId,
      userId: serverSession.userId || idPayload.sub || "",
      organizationId:
        derivedConfig.organizationId || this.getEffectiveConfig().organizationId,
      displayName: idPayload.name || serverSession.email || idPayload.email || email,
      email: serverSession.email || idPayload.email || email,
      accessToken: authResult.tokens.accessToken,
      idToken: authResult.tokens.idToken,
      refreshToken: authResult.tokens.refreshToken,
      tokenExpiresAt: expiresAt.toISOString(),
      role: this.derivePrimaryRole(idPayload, backendRoles),
      roles: sessionRoles,
      createdAt: new Date().toISOString(),
    };
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
      this.session.organizationId &&
      !isLocalDevAuth(this.getEffectiveConfig().cognitoUserPoolId)
    ) {
      try {
        await this.resolveOrgConfig(this.session.organizationId, { silent: true });
      } catch (err) {
        this.logError("Cloud org config refresh after login failed", err);
      }
    }

    this.rebuildApiClient();
    this.initializeApiClientFromSession(this.session);

    await this.persistSession(this.session);
    this.startKeyRenewalMonitor();
    this.startHeartbeatMonitor();
    new Notice(`VaultGuard Sync: Logged in as ${this.session.displayName}`);

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
      });
    } else {
      this.log("Vault binding skipped — sync engine deferred until a vault is picked.");
    }
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
    if (typeof document === "undefined") return;
    const frag = document.createDocumentFragment();
    frag.appendText(
      "VaultGuard: Vault connected. Reload Obsidian so every file shows everyone who has access to it."
    );
    const actions = frag.createDiv();
    actions.setCssStyles({ marginTop: "8px" });
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
  private decodeJwtPayload(token: string): Record<string, any> {
    try {
      const payload = token.split(".")[1];
      const decoded = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
      return JSON.parse(decoded);
    } catch {
      return {};
    }
  }

  private deriveFallbackRoles(idPayload: Record<string, any>): string[] {
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
    idPayload: Record<string, any>,
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
    if (!this.session) {
      return;
    }

    let session = this.session;
    let tokenWasRefreshed = false;
    if (this.isSessionTokenExpiring(session)) {
      const refreshResult = await this.refreshAccessToken(session);
      if (!refreshResult.ok) {
        // Fix 4 (1.0.30): surface the degraded state. Previously this was
        // a silent `this.log(...)` that left the user with a permission
        // cache poisoned by the earlier stale-token warm-up (Fix 1
        // comment below). At minimum the user now knows to re-login if
        // it persists.
        this.log(
          `Stored session token refresh deferred: ${refreshResult.message}`
        );
        this.notifySessionRestoreDegraded(refreshResult.message);
        return;
      }
      if (!this.session) {
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
      // /auth/session no longer issues a key lease — leases are vault-scoped
      // and requested explicitly via ensureVaultScopedKeyLease() below.
      this.keyLease = null;
      this.applyOrgSettings(serverSession.orgSettings ?? this.orgSettings);
    }

    if (this.session) {
      this.initializeApiClientFromSession(this.session);
      await this.persistSession(this.session);
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

    if (!this.syncTimer) {
      this.initializeSyncEngine().catch((err) => {
        this.logError("Sync engine init failed (non-blocking)", err);
      });
    }
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
      // Any failure: keep the session. The user stays logged in.
      // We'll retry refresh on the next API call or sync cycle.
      this.logError("Cognito token refresh failed, keeping session", error);
      this.session = session;
      return {
        ok: false,
        message: error instanceof Error ? error.message : "Token refresh failed",
        error,
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
    return this.atRestCipher?.getStatus() ?? { kind: "uninitialized" };
  }

  /**
   * The local at-rest cipher, exposed for the AI-chat key store's
   * safeStorage-unavailable fallback (see src/ui/chat/api-key-store.ts).
   * Returns null before init or after the plugin unloads.
   */
  getAtRestCipher(): AtRestCipher | null {
    return this.atRestCipher;
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
    const cipher = this.atRestCipher;
    const readBin = this.originalAdapterMethods.readBinary;
    const files = this.app.vault.getFiles();
    let plaintext = 0;
    let encrypted = 0;
    let excluded = 0;
    let failed = 0;
    if (!cipher || !readBin) {
      return { plaintext: 0, encrypted: 0, excluded: 0, failed: 0, total: files.length };
    }
    for (const file of files) {
      if (this.isAtRestExcluded(file.path)) {
        excluded += 1;
        continue;
      }
      try {
        const bytes = await readBin(file.path);
        if (cipher.isEncrypted(bytes)) encrypted += 1;
        else plaintext += 1;
      } catch {
        failed += 1;
      }
    }
    return { plaintext, encrypted, excluded, failed, total: files.length };
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
    return this.encryptVaultAtRest();
  }

  /** Public entry for the "Decrypt vault" button in settings. */
  async revertVaultFromAtRest(): Promise<void> {
    return this.decryptVaultAtRest();
  }

  /**
   * Generate the user-readable recovery code. Throws if the cipher is
   * locked / disabled — the caller (settings tab) should gate the button
   * on `getAtRestStatus().kind === "unlocked"`.
   */
  async exportAtRestRecoveryCode(): Promise<string> {
    if (!this.atRestCipher) {
      throw new Error("VaultGuard Sync: at-rest cipher not initialised.");
    }
    return this.atRestCipher.exportRecoveryCode();
  }

  /**
   * Restore the cipher from a previously-exported recovery code. Returns
   * false if the code is malformed / has a bad checksum so the UI can
   * show a generic "couldn't recognise that code" error.
   */
  async restoreAtRestFromRecoveryCode(code: string): Promise<boolean> {
    if (!this.atRestCipher) {
      // Cipher wasn't initialised yet (e.g. envelope load threw earlier).
      // Build a fresh one bound to the same envelope file so the restored
      // LAK gets persisted in the canonical location.
      await this.initAtRestCipher();
    }
    if (!this.atRestCipher) return false;
    return this.atRestCipher.restoreFromRecoveryCode(code);
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

  private showVaultGuardMenu(evt?: MouseEvent): void {
    const menu = new Menu();
    const isLoggedIn = !!this.session;
    const isAdmin =
      this.session?.role === "admin" || this.session?.role === "owner";
    const currentVaultName =
      this.settings.serverVaultName ||
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
    const changed = await this.promptVaultBinding();
    if (changed && this.settings.serverVaultId && this.session) {
      this.initializeSyncEngine().catch((err) => {
        this.logError("Sync engine init failed after vault switch", err);
      });
    }
    return changed;
  }

  async bindServerVault(result: { vaultId: string; name: string; slug: string }): Promise<boolean> {
    const changed = await this.applyVaultBinding(result);
    if (changed && this.settings.serverVaultId && this.session) {
      this.initializeSyncEngine().catch((err) => {
        this.logError("Sync engine init failed after vault binding update", err);
      });
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
   * `.obsidian/plugins/` is local-only (see `isPathExcluded`), so the bundle
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

      const pluginRoot = `.obsidian/plugins/${entry.pluginId}`;
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
          // Force Obsidian to re-scan .obsidian/plugins so it sees the newly
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
    const slugCandidates = Array.from(
      new Set(
        [slug.trim().toLowerCase(), slug.trim().toLowerCase().replace(/^org-/, "")]
          .filter((value) => value.length > 0)
      )
    );

    const fallbackBases = this.settings.manualConfig ? [] : [SAAS_DEFAULTS.fallbackApiUrl];
    const bases = Array.from(
      new Set(
        [
          this.getEffectiveConfig().apiEndpoint,
          ...fallbackBases,
        ].filter(Boolean)
      )
    );

    // If no base URL at all, the user must enter one manually
    if (bases.length === 0) {
      throw new Error(
        'No API endpoint configured. Enter an API endpoint manually or ask your admin for the org slug.'
      );
    }

    let lastError: Error | null = null;

    for (const base of bases) {
      const normalizedBase = normalizeVaultGuardApiBaseUrl(base);

      for (const slugCandidate of slugCandidates) {
        const url = `${normalizedBase}/orgs/${encodeURIComponent(slugCandidate)}/config`;

        try {
          const response = await requestUrl({ url, method: 'GET', throw: false });

          if (response.status === 404) {
            throw new Error(`Organization "${slug}" not found. Check the slug and try again.`);
          }

          if (response.status < 200 || response.status >= 300) {
            throw new Error(`Server returned ${response.status}`);
          }

          const config = response.json;

          if (!config || typeof config !== "object") {
            throw new Error('Invalid config response from server');
          }

          this.applyResolvedConnectionConfig(
            config as Record<string, unknown>,
            normalizedBase,
            slugCandidate
          );
          await this.saveSettings();

          // Rebuild the API client with new settings
          this.rebuildApiClient();

          this.log(`Org config resolved for "${this.settings.orgSlug}": API=${this.settings.apiEndpoint}`);
          if (!options.silent) {
            const orgName = this.readConfigString(config as Record<string, unknown>, "orgName");
            new Notice(`VaultGuard Sync: Connected to ${orgName || this.settings.orgSlug}`);
          }
          return;
        } catch (err) {
          lastError = err instanceof Error ? err : new Error(String(err));
        }
      }
    }

    throw lastError ?? new Error('Failed to resolve org configuration');
  }

  private syncSettingsFromTokenPayload(
    payload: Record<string, unknown>,
    fallbackRoles: string[] = []
  ): boolean {
    const derived = deriveConnectionConfigFromTokenPayload(payload, fallbackRoles);
    let changed = false;

    if (
      derived.organizationId &&
      derived.organizationId !== this.settings.organizationId
    ) {
      this.settings.organizationId = derived.organizationId;
      changed = true;
    }

    if (derived.orgSlug && derived.orgSlug !== this.settings.orgSlug) {
      this.settings.orgSlug = derived.orgSlug;
      changed = true;
    }

    if (
      derived.cognitoUserPoolId &&
      derived.cognitoUserPoolId !== this.settings.cognitoUserPoolId
    ) {
      this.settings.cognitoUserPoolId = derived.cognitoUserPoolId;
      changed = true;
    }

    if (
      derived.cognitoClientId &&
      derived.cognitoClientId !== this.settings.cognitoClientId
    ) {
      this.settings.cognitoClientId = derived.cognitoClientId;
      changed = true;
    }

    return changed;
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
    return this.orgSettings?.syncMode ?? "periodic";
  }

  private getEffectiveSyncIntervalSeconds(): number {
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
    return this.getEffectiveSyncMode() !== "manual";
  }

  private registerSessionActivityTracking(): void {
    const recordActivity = () => this.noteSessionActivity();

    this.registerDomEvent(document, "mousedown", recordActivity);
    this.registerDomEvent(document, "keydown", recordActivity);
    this.registerDomEvent(document, "touchstart", recordActivity);
    this.registerDomEvent(window, "focus", recordActivity);
  }

  private noteSessionActivity(): void {
    if (!this.session) {
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

    this.log(`Auto-lock triggered after ${autoLockMinutes} minutes of inactivity.`);
    await this.forceLogout(
      `VaultGuard Sync: Session locked after ${autoLockMinutes} minutes of inactivity.`
    );
  }

  /**
   * Forces logout: invalidates the session, clears credentials,
   * and optionally wipes local cache.
   */
  async forceLogout(noticeMessage = "VaultGuard Sync: Logged out successfully."): Promise<void> {
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
    if (this.agentBridge) {
      await this.agentBridge.stopHttpServer().catch(() => {});
    }

    this.session = null;
    this.keyLease = null;
    this.vaultLeaseDenied = false;
    this.lastLimitedAccessNoticeAt = 0;
    this.lastSessionDegradedNoticeAt = 0;
    this.orgSettings = null;
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
    new Notice(noticeMessage);
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
    this.renderObsidianSyncNotice();
    this.registerObsidianSyncListener();
  }

  private renderObsidianSyncNotice(): void {
    try {
      // internalPlugins is not part of the public Obsidian API but is stable
      // and the only way to detect that the built-in Sync core plugin is
      // active. We narrow the unknown shape to the minimal surface we touch
      // rather than casting to `any`.
      interface InternalPluginRef {
        readonly enabled?: boolean;
        readonly _loaded?: boolean;
      }
      interface InternalPlugins {
        getPluginById?(id: string): InternalPluginRef | undefined;
      }
      const appWithInternals = this.app as unknown as {
        internalPlugins?: InternalPlugins;
      };
      const syncPlugin = appWithInternals.internalPlugins?.getPluginById?.("sync");
      const isSyncEnabled = !!(syncPlugin && (syncPlugin.enabled ?? syncPlugin._loaded ?? false));

      if (isSyncEnabled && !this.obsidianSyncNotice) {
        console.warn(
          `${LOG_PREFIX} Obsidian Sync is active. VaultGuard handles all sync and backup — ` +
          "running both will cause file conflicts. Please disable Obsidian Sync."
        );
        this.obsidianSyncNotice = new Notice(
          "VaultGuard Sync: Obsidian Sync is enabled. VaultGuard Sync handles all sync and " +
          "backup for this vault — please disable Obsidian Sync to prevent " +
          "file conflicts.\n\nSettings → Core plugins → Sync → Disable",
          0 // persistent until dismissed
        );
      } else if (!isSyncEnabled && this.obsidianSyncNotice) {
        this.obsidianSyncNotice.hide();
        this.obsidianSyncNotice = null;
      }
    } catch {
      // Defensive: if the internal API changes, don't block plugin load
    }
  }

  private registerObsidianSyncListener(): void {
    try {
      interface InternalPluginsEvented {
        on?(event: string, cb: () => void): EventRef;
      }
      const appWithInternals = this.app as unknown as {
        internalPlugins?: InternalPluginsEvented;
      };
      const internalPlugins = appWithInternals.internalPlugins;

      // Primary: react to enable/disable events. `internalPlugins.on("change", ...)`
      // fires when any core plugin is toggled, so the Notice reconciles the
      // moment the user disables Sync.
      const ref = internalPlugins?.on?.("change", () => this.renderObsidianSyncNotice());
      if (ref) {
        this.registerEvent(ref);
        return;
      }

      // Fallback: poll every 60s if the event API isn't present on this
      // Obsidian build. registerInterval scopes the timer to plugin lifetime
      // so it's auto-cleared on unload.
      this.registerInterval(
        window.setInterval(() => this.renderObsidianSyncNotice(), 60_000)
      );
    } catch {
      // Defensive: never block plugin load
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Local At-Rest Cipher
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Provisions or unlocks the on-disk at-rest cipher. The wrapped LAK lives
   * in `data.json` under `wrappedLak` so it survives Obsidian restarts and
   * never leaks into the synced vault folder. Surface failures as a Notice
   * rather than throwing — a failed init must not block plugin loading,
   * because the user might need to log in to recover.
   */
  private async initAtRestCipher(): Promise<void> {
    // The wrapped LAK lives in a sidecar file inside the plugin folder, not
    // in data.json. Two reasons: (1) data.json is overwritten by
    // savePluginData() with a settings-only object, so any extra key would
    // get clobbered; (2) the LAK envelope is opaque bytes — keeping it out
    // of the human-readable JSON document makes reviews / debugging
    // settings clearer. The plugin folder is already in `isPathExcluded`,
    // so this file never participates in vault sync.
    const pluginId = this.manifest?.id ?? "vaultguard-sync";
    const envelopePath = `.obsidian/plugins/${pluginId}/lak.envelope`;
    const adapter = this.app.vault.adapter;

    // One-time envelope migration after a plugin-id rename. If no envelope
    // exists at the current path but one DOES exist under a historical
    // plugin id, copy it across before AtRestCipher.init() runs so the
    // existing unwrap path picks it up and on-disk VG1 files remain
    // decryptable. See PRIOR_PLUGIN_IDS_FOR_LAK_MIGRATION and commit
    // 9495041 (2026-05-14, vaultguard -> vaultguard-sync).
    let envelopeMigrationFailureReason: string | null = null;
    try {
      const currentExists = await adapter.exists(envelopePath);
      if (!currentExists) {
        const priorIds = PRIOR_PLUGIN_IDS_FOR_LAK_MIGRATION[pluginId] ?? [];
        for (const priorId of priorIds) {
          const priorPath = `.obsidian/plugins/${priorId}/lak.envelope`;
          try {
            if (!(await adapter.exists(priorPath))) continue;
            const priorBlob = await adapter.read(priorPath);
            if (!priorBlob || priorBlob.trim().length === 0) continue;
            try {
              await adapter.write(envelopePath, priorBlob);
              this.log(`[at-rest] Migrated LAK envelope from ${priorId} -> ${pluginId}`);
              // Source envelope intentionally NOT removed: a second Obsidian
              // window, a second install, or a rollback to the prior plugin
              // id all benefit from the original staying put.
              break;
            } catch (writeErr) {
              envelopeMigrationFailureReason =
                `Found an at-rest envelope under the previous plugin id (${priorId}) but could not copy it into the current plugin folder (${pluginId}): ${
                  writeErr instanceof Error ? writeErr.message : String(writeErr)
                }. Your encrypted files have NOT been overwritten — close Obsidian, copy ".obsidian/plugins/${priorId}/lak.envelope" to ".obsidian/plugins/${pluginId}/lak.envelope" manually, and reopen.`;
              break;
            }
          } catch (readErr) {
            // A prior-id folder exists but reading the envelope failed.
            // Treat as "no sibling found" and continue scanning the rest of
            // the prior id list — do not block init.
            this.logError(`[at-rest] Probing prior envelope at ${priorPath} failed`, readErr);
          }
        }
      }
    } catch (err) {
      // adapter.exists threw for the current path — extremely unusual.
      // Don't block init; fall through to AtRestStorage which has its own
      // try/catch around adapter.read.
      this.logError(`[at-rest] Probing current envelope at ${envelopePath} failed`, err);
    }

    const storage: AtRestStorage = {
      loadWrappedLak: async () => {
        try {
          if (!(await adapter.exists(envelopePath))) return null;
          const raw = await adapter.read(envelopePath);
          return raw.trim().length > 0 ? raw : null;
        } catch (err) {
          this.logError(`Reading at-rest envelope at ${envelopePath} failed`, err);
          return null;
        }
      },
      saveWrappedLak: async (blob: string) => {
        await adapter.write(envelopePath, blob);
      },
      clearWrappedLak: async () => {
        try {
          if (await adapter.exists(envelopePath)) {
            await adapter.remove(envelopePath);
          }
        } catch (err) {
          this.logError(`Removing at-rest envelope at ${envelopePath} failed`, err);
        }
      },
    };

    this.atRestCipher = new AtRestCipher(storage);

    // If the envelope migration found a sibling but failed to copy it,
    // short-circuit BEFORE running init(). Running init() now would see no
    // envelope and silently generate a fresh LAK, which is the exact failure
    // mode this migration block exists to prevent.
    if (envelopeMigrationFailureReason !== null) {
      const reason = envelopeMigrationFailureReason;
      this.app.workspace.onLayoutReady(() =>
        this.showAtRestRecoveryBanner(reason)
      );
      this.logError(
        "AtRestCipher init aborted: envelope migration failed",
        new Error(reason)
      );
      return;
    }

    try {
      const initPromise = this.atRestCipher.init();
      this.cipherInitPromise = initPromise;
      const ok = await initPromise.catch(() => false);
      if (this.cipherInitPromise === initPromise) {
        this.cipherInitPromise = null;
      }
      const status = this.atRestCipher.getStatus();
      if (!ok) {
        if (status.kind === "needs-recovery") {
          // Defer the banner until layout is ready — the recovery flow
          // routes through the settings tab, which doesn't exist yet at
          // this point in onload.
          this.app.workspace.onLayoutReady(() =>
            this.showAtRestRecoveryBanner(status.reason)
          );
        } else {
          const reason = status.kind === "disabled" ? status.reason : "unknown";
          new Notice(
            `VaultGuard Sync: local at-rest encryption disabled. ${reason}`,
            10000
          );
        }
        this.logError(
          "AtRestCipher init failed",
          new Error(status.kind === "needs-recovery" || status.kind === "disabled" ? status.reason : "unknown")
        );
        return;
      }
      const method = status.kind === "unlocked" ? status.method : "unknown";
      this.log(`AtRestCipher ready (${method}).`);
      if (Platform.isMobileApp && this.settings.debugLogging) {
        const ready = status.kind === "unlocked";
        new Notice(
          `VaultGuard diag: at-rest method=${method}, ready=${ready}`,
          5000
        );
      }
      if (method === "localstorage-fallback" && !Platform.isMobileApp) {
        new Notice(
          "VaultGuard Sync: at-rest encryption is using the localStorage fallback (OS keychain unavailable). Files in Finder are encrypted, but a full Electron-profile theft can recover the key. See docs/AT-REST-ENCRYPTION.md.",
          10000
        );
      }
      // First-run nudge: if we just provisioned a fresh LAK and there are
      // plaintext files on disk, the user almost certainly wants them
      // encrypted (they enabled the plugin). One Notice with a clear CTA;
      // we don't auto-encrypt without consent because some users keep
      // local-only vaults and may not want VaultGuard touching every file.
      this.app.workspace.onLayoutReady(() => {
        void this.maybeOfferFirstRunMigration();
      });
    } catch (err) {
      this.logError("AtRestCipher init threw", err);
    }
  }

  /**
   * Once per plugin process: if the vault still has plaintext files
   * (typical right after install) surface a Notice with an "Encrypt now"
   * link to the settings tab. Throttled by a settings flag so users who
   * dismiss it don't get pestered every reload.
   */
  private async maybeOfferFirstRunMigration(): Promise<void> {
    if (this.atRestFirstRunOffered) return;
    this.atRestFirstRunOffered = true;
    if (this.settings.atRestFirstRunDismissed) return;
    if (!this.atRestCipher?.isReady()) return;

    try {
      const tally = await this.tallyAtRestState();
      if (tally.plaintext === 0) return;
      const notice = new Notice("", 0);
      const frag = document.createDocumentFragment();
      const strong = frag.createEl("strong");
      strong.setText("VaultGuard Sync: at-rest encryption ready. ");
      frag.appendText(
        `${tally.plaintext} file${tally.plaintext === 1 ? "" : "s"} in this vault still on disk as plaintext. `
      );
      const link = frag.createEl("a", {
        text: "Encrypt them now →",
        cls: "vaultguard-notice-link",
      });
      link.addEventListener("click", () => {
        notice.hide();
        this.openVaultGuardSettings();
      });
      const dismiss = frag.createEl("a", {
        text: "  Dismiss",
        cls: "vaultguard-notice-dismiss",
      });
      dismiss.addEventListener("click", () => {
        this.settings.atRestFirstRunDismissed = true;
        void this.saveSettings();
        notice.hide();
      });
      notice.setMessage(frag);
    } catch (err) {
      this.logError("First-run at-rest tally failed", err);
    }
  }

  /**
   * Persistent banner shown when the cipher can't unwrap the LAK on this
   * device — typically because the user moved the vault between machines
   * or reinstalled the OS. Routes them to the settings tab where the
   * "Restore from recovery code" button lives. The Notice is sticky
   * (no timeout) because ignoring it leaves the vault unreadable.
   */
  private showAtRestRecoveryBanner(reason: string): void {
    const notice = new Notice("", 0);
    const frag = document.createDocumentFragment();
    const strong = frag.createEl("strong");
    strong.setText("VaultGuard Sync: cannot read encrypted files on this device. ");
    frag.appendText(reason + " ");
    const link = frag.createEl("a", {
      text: "Open settings to restore →",
      cls: "vaultguard-notice-link",
    });
    link.addEventListener("click", () => {
      notice.hide();
      this.openVaultGuardSettings();
    });
    notice.setMessage(frag);
  }

  /**
   * Walk the entire vault and rewrite each file as at-rest ciphertext.
   *
   * Safe to invoke repeatedly — files that already start with the at-rest
   * magic header are skipped. Excluded paths (.obsidian, .trash, plugin
   * folder) are never touched. Used for a one-shot migration of legacy
   * plaintext vaults; ongoing writes are encrypted automatically by the
   * adapter interceptor.
   */
  private async encryptVaultAtRest(): Promise<void> {
    if (!this.atRestCipher?.isReady() || !this.originalAdapterMethods.readBinary || !this.originalAdapterMethods.writeBinary) {
      new Notice("VaultGuard Sync: at-rest cipher not initialised — cannot run migration.");
      return;
    }
    const cipher = this.atRestCipher;
    const readBin = this.originalAdapterMethods.readBinary;
    const writeBin = this.originalAdapterMethods.writeBinary;

    const files = this.app.vault.getFiles();
    let encrypted = 0;
    let skipped = 0;
    let failed = 0;
    new Notice(`VaultGuard Sync: encrypting ${files.length} files at rest…`, 3000);

    for (const file of files) {
      if (this.isAtRestExcluded(file.path)) {
        skipped += 1;
        continue;
      }
      try {
        const bytes = await readBin(file.path);
        if (cipher.isEncrypted(bytes)) {
          skipped += 1;
          continue;
        }
        const ct = await cipher.encryptBinary(bytes);
        await writeBin(file.path, ct);
        encrypted += 1;
      } catch (err) {
        failed += 1;
        this.logError(`At-rest encrypt: failed for "${file.path}"`, err);
      }
    }
    new Notice(
      `VaultGuard Sync: at-rest encryption pass complete. ${encrypted} encrypted, ${skipped} already-encrypted/excluded, ${failed} failed.`,
      8000
    );
  }

  /**
   * Walk the vault and rewrite each at-rest-encrypted file back to
   * plaintext. Mirror of `encryptVaultAtRest`. Use before disabling the
   * plugin if you want the vault folder to remain readable through normal
   * tools.
   */
  private async decryptVaultAtRest(): Promise<void> {
    if (!this.atRestCipher?.isReady() || !this.originalAdapterMethods.readBinary || !this.originalAdapterMethods.writeBinary) {
      new Notice("VaultGuard Sync: at-rest cipher not initialised — cannot decrypt.");
      return;
    }
    const cipher = this.atRestCipher;
    const readBin = this.originalAdapterMethods.readBinary;
    const writeBin = this.originalAdapterMethods.writeBinary;

    const files = this.app.vault.getFiles();
    let decrypted = 0;
    let skipped = 0;
    let failed = 0;
    new Notice(`VaultGuard Sync: decrypting ${files.length} files at rest…`, 3000);

    for (const file of files) {
      if (this.isAtRestExcluded(file.path)) {
        skipped += 1;
        continue;
      }
      try {
        const bytes = await readBin(file.path);
        if (!cipher.isEncrypted(bytes)) {
          skipped += 1;
          continue;
        }
        const plain = await cipher.decryptBinary(bytes);
        await writeBin(file.path, plain);
        decrypted += 1;
      } catch (err) {
        failed += 1;
        this.logError(`At-rest decrypt: failed for "${file.path}"`, err);
      }
    }
    new Notice(
      `VaultGuard Sync: at-rest decryption pass complete. ${decrypted} decrypted, ${skipped} already-plaintext/excluded, ${failed} failed.`,
      8000
    );
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Vault Adapter Interception
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Intercepts the vault adapter's read, write, list, and delete methods
   * to route operations through permission checks and encryption.
   *
   * Original methods are stored for restoration on plugin unload.
   */
  private interceptVaultAdapter(): void {
    const adapter = this.app.vault.adapter;

    // Save original methods
    this.originalAdapterMethods.read = adapter.read.bind(adapter);
    this.originalAdapterMethods.write = adapter.write.bind(adapter);
    this.originalAdapterMethods.list = adapter.list.bind(adapter);
    this.originalAdapterMethods.remove = adapter.remove.bind(adapter);
    if (typeof (adapter as unknown as Record<string, unknown>).readBinary === "function") {
      this.originalAdapterMethods.readBinary = (
        adapter as unknown as { readBinary: (p: string) => Promise<ArrayBuffer> }
      ).readBinary.bind(adapter);
    }
    if (typeof (adapter as unknown as Record<string, unknown>).writeBinary === "function") {
      this.originalAdapterMethods.writeBinary = (
        adapter as unknown as { writeBinary: (p: string, d: ArrayBuffer) => Promise<void> }
      ).writeBinary.bind(adapter);
    }
    if (typeof adapter.rename === "function") {
      this.originalAdapterMethods.rename = adapter.rename.bind(adapter);
    }

    // Intercept read operations
    adapter.read = async (normalizedPath: string): Promise<string> => {
      return this.interceptedRead(normalizedPath);
    };

    // Intercept write operations
    adapter.write = async (
      normalizedPath: string,
      data: string
    ): Promise<void> => {
      return this.interceptedWrite(normalizedPath, data);
    };

    // Intercept binary read/write so attachments (images, PDFs, ...) also
    // get at-rest decryption/encryption. Without this, every non-text file
    // in the vault would round-trip in plaintext on disk.
    if (this.originalAdapterMethods.readBinary) {
      (adapter as unknown as {
        readBinary: (p: string) => Promise<ArrayBuffer>;
      }).readBinary = async (normalizedPath: string): Promise<ArrayBuffer> => {
        return this.interceptedReadBinary(normalizedPath);
      };
    }
    if (this.originalAdapterMethods.writeBinary) {
      (adapter as unknown as {
        writeBinary: (p: string, d: ArrayBuffer) => Promise<void>;
      }).writeBinary = async (
        normalizedPath: string,
        data: ArrayBuffer
      ): Promise<void> => {
        return this.interceptedWriteBinary(normalizedPath, data);
      };
    }

    // Intercept list operations
    adapter.list = async (
      normalizedPath: string
    ): Promise<{ files: string[]; folders: string[] }> => {
      return this.interceptedList(normalizedPath);
    };

    // Intercept delete operations
    adapter.remove = async (normalizedPath: string): Promise<void> => {
      return this.interceptedDelete(normalizedPath);
    };

    // Intercept rename — without this the server keeps the old name forever
    // (Obsidian renames don't go through write/remove, so the existing
    // interceptors never fire) and the renamed file appears as a duplicate
    // until the user manually deletes the old path.
    if (this.originalAdapterMethods.rename) {
      adapter.rename = async (oldPath: string, newPath: string): Promise<void> => {
        return this.interceptedRename(oldPath, newPath);
      };
    }

    this.log("Vault adapter methods intercepted.");
  }

  /**
   * Restores the original vault adapter methods.
   * Called during plugin unload to prevent issues with other plugins.
   */
  private restoreVaultAdapter(): void {
    const adapter = this.app.vault.adapter;

    if (this.originalAdapterMethods.read) {
      adapter.read = this.originalAdapterMethods.read;
    }
    if (this.originalAdapterMethods.write) {
      adapter.write = this.originalAdapterMethods.write;
    }
    if (this.originalAdapterMethods.readBinary) {
      (adapter as unknown as { readBinary: (p: string) => Promise<ArrayBuffer> }).readBinary =
        this.originalAdapterMethods.readBinary;
    }
    if (this.originalAdapterMethods.writeBinary) {
      (adapter as unknown as {
        writeBinary: (p: string, d: ArrayBuffer) => Promise<void>;
      }).writeBinary = this.originalAdapterMethods.writeBinary;
    }
    if (this.originalAdapterMethods.list) {
      adapter.list = this.originalAdapterMethods.list;
    }
    if (this.originalAdapterMethods.remove) {
      adapter.remove = this.originalAdapterMethods.remove;
    }
    if (this.originalAdapterMethods.rename) {
      adapter.rename = this.originalAdapterMethods.rename;
    }

    this.originalAdapterMethods = {
      read: null,
      write: null,
      readBinary: null,
      writeBinary: null,
      list: null,
      remove: null,
      rename: null,
    };
    this.log("Vault adapter methods restored.");
  }

  /**
   * Permission-checked and decryption-aware file read operation.
   * @param path - Normalized vault-relative file path
   * @returns Decrypted file content
   * @throws Error if the user lacks READ permission
   */
  private async interceptedRead(path: string): Promise<string> {
    if (this.isPathExcluded(path)) {
      if (!this.originalAdapterMethods.read) {
        throw new Error("VaultGuard Sync: vault adapter read method unavailable.");
      }
      return this.originalAdapterMethods.read(path);
    }

    if (!this.session) {
      throw new Error(this.showLoginRequiredNotice("open", path));
    }

    // Wait briefly for the cache warm-up before evaluating permission so
    // Obsidian's startup workspace restore doesn't show "Failed to open"
    // notices for paths that will resolve to ALLOW once the warm-up is
    // done. The warm-up is fast (one /permissions fetch) — capping the
    // wait at 5 s prevents an unresponsive backend from hanging the read.
    await this.awaitPermissionReadiness();

    const permission = await this.getEffectivePermission(path);

    if (permission < PermissionLevel.READ) {
      // Permission denial during read: log the denial for audit, but do
      // NOT wipe and do NOT throw. Rationale (1.0.17 hardening after
      // 1.0.15 data loss + 1.0.16 still-flooding incident):
      //
      //   * Wiping was the data-loss vector — destroying user files because
      //     the permission cache said NONE meant a single cache miss erased
      //     local content. Even with shouldDeferDenialWipe guarding the
      //     startup window, post-warm-up NONE for legitimately-denied files
      //     still destroyed them.
      //
      //   * Throwing produced the "stuck at indexing vault" symptom —
      //     Obsidian's indexer retries failed reads, flooding the console
      //     with errors per denied file on every startup.
      //
      //   * Revocation enforcement belongs in the sync engine, fired on a
      //     CONFIRMED server permission-change event, not on every read.
      //
      // Returning the on-disk content trades a narrow privacy concern
      // (someone with local disk access could read a file they no longer
      // have server permission for) for ending the data-loss + indexing-
      // flood incidents. At-rest encryption still protects the bytes on
      // disk; only an authenticated user with a valid LAK can decrypt
      // them, so the worst case is "user kept their own laptop after
      // losing vault access" — which the file system permits anyway.
      await this.emitAuditEvent("file.read", path, {
        outcome: "denied",
        reason: "permission-denied-read-fail-open",
      });
      this.log(`Permission denied for "${path}" (read fail-open).`);
      return this.readPlainFromDisk(path);
    }

    // Phase-8 limited-access primary branch (OD-4): if this path is a known
    // 36-byte VG1 placeholder, hydrate via the server-side decrypt endpoint
    // and replace the on-disk placeholder with LAK-encrypted plaintext.
    if (this.vaultLeaseDenied && this.placeholderPaths.has(path)) {
      const response = await this.readFileDecrypted(path);
      if (response.success && response.data?.decrypted === true) {
        const plaintext = this.decodeBase64Utf8(response.data.content);
        await this.writePlainToDisk(path, plaintext);
        this.placeholderPaths.delete(path);
        await this.emitAuditEvent("file.read", path);
        return plaintext;
      }
      if (response.error?.statusCode === 404) {
        // Read fail-open in limited-access mode. The prior behavior here
        // (wipe + throw) was the data-loss vector behind the 2026-05-31
        // Pete incident: any user with a deny-read rule overlapping /**
        // gets a 403 on /auth/key-lease/scoped (see
        // assertScopeHasNoReadDenyRules in auth/handler.ts), which forces
        // vaultLeaseDenied=true for the whole session. From there, every
        // read of a read-only file falls into this branch and erases
        // local content. A 404 from readFileDecrypted is ambiguous — it
        // could mean genuinely deleted, or denied-via-404 (share-bridge
        // pattern). Deletion enforcement belongs in the sync engine on a
        // confirmed permission_changed event, not on a single read 404.
        // Mirrors the post-1.0.17 read fail-open principle at the top of
        // this function.
        this.placeholderPaths.delete(path);
        await this.emitAuditEvent("file.read", path, {
          outcome: "denied",
          reason: "limited-access-placeholder-404-fail-open",
        });
        this.log(`Limited-access decrypt 404 for "${path}" (read fail-open).`);
        return this.readPlainFromDisk(path);
      }
      // Other errors (5xx, network) — fall through to existing logic which
      // already debounces a "decrypt failed" Notice.
    }

    try {
      // If online, fetch the newest server copy. Full-access sessions decrypt
      // locally with their lease; limited-access sessions ask the backend to
      // decrypt only this permission-checked file.
      if (this.isOnline()) {
        const response = await this.fetchRemoteFileContent(path);

        if (response.success && response.data) {
          try {
            const decrypted = await this.decodeRemoteFileContent(path, response.data);
            await this.emitAuditEvent("file.read", path);
            return decrypted;
          } catch (decryptErr) {
            // The cloud blob is encrypted with a key that doesn't match the
            // current lease — typically because the file was uploaded under
            // a different DEK (org-wide vs vault-scoped, or pre-rotation).
            // The local copy is encrypted at rest with the LAK and stays
            // readable, so fall back to it instead of letting an opaque
            // OperationError leak to Obsidian's read pipeline.
            this.logError(
              `Cloud copy of "${path}" could not be decrypted with the current key lease — using local copy.`,
              decryptErr
            );
            this.notifyCloudDecryptFallback(path);
            await this.emitAuditEvent("file.read", path, {
              source: "cache",
              reason: "decrypt-failed",
            });
            return this.readPlainFromDisk(path);
          }
        }

        if (response.error?.statusCode === 401 || response.error?.statusCode === 403) {
          throw new Error(response.error.message);
        }
      }

      // Fallback to local cached version if offline
      const localContent = await this.readPlainFromDisk(path);

      // Phase-8 secondary disambiguator (D-13): legacy on-disk placeholders
      // written by older plugin versions before placeholderPaths existed. If
      // decrypted plaintext is empty AND we're in limited-access mode, treat
      // as a (legacy) placeholder and try to hydrate. Best-effort; the
      // primary path is placeholderPaths.has(path) above. The vaultLeaseDenied
      // guard prevents this from firing on legitimately-empty notes in full-
      // access sessions (T-08-19).
      if (localContent === "" && this.vaultLeaseDenied) {
        try {
          const response = await this.readFileDecrypted(path);
          if (response.success && response.data?.decrypted === true) {
            const plaintext = this.decodeBase64Utf8(response.data.content);
            await this.writePlainToDisk(path, plaintext);
            this.placeholderPaths.delete(path);
            await this.emitAuditEvent("file.read", path);
            return plaintext;
          }
          if (response.error?.statusCode === 404) {
            // Read fail-open — see the branch above for full rationale.
            // Returning the (empty) localContent at least leaves the file
            // visible rather than wiping it; the primary placeholder
            // branch above will retry hydration on the next read once
            // the server-side decrypt succeeds.
            this.placeholderPaths.delete(path);
            await this.emitAuditEvent("file.read", path, {
              outcome: "denied",
              reason: "limited-access-empty-content-404-fail-open",
            });
            this.log(`Limited-access decrypt 404 for "${path}" (read fail-open).`);
            return localContent;
          }
        } catch (err) {
          if (this.isNetworkError(err)) {
            // Offline — return the empty local content; we'll retry next read.
          } else {
            throw err;
          }
        }
        // Fall through on other errors — return the empty local content.
      }

      await this.emitAuditEvent("file.read", path, { source: "cache" });
      return localContent;
    } catch (error) {
      // If network error, fall back to local cache
      if (this.isNetworkError(error)) {
        this.setConnectionStatus("offline");
        return this.readPlainFromDisk(path);
      }
      throw error;
    }
  }

  /**
   * Shows a one-shot Notice when a file is opened without server READ access
   * and the local cached content is wiped. Per-path debounced (60s) so tab
   * restores and re-focus reads don't produce a stampede.
   */
  private notifyDeniedLocalWipe(path: string): void {
    const now = Date.now();
    const last = this.readOnlyFallbackNoticeAt.get(path) ?? 0;
    if (now - last < 60_000) return;
    this.readOnlyFallbackNoticeAt.set(path, now);
    new Notice(
      `VaultGuard Sync: You don't have access to "${path}". Local cached content was wiped.`,
      5000
    );
  }

  /**
   * Shows a debounced Notice when the cloud copy of a file can't be decrypted
   * with the current key lease and we fall back to the local on-disk copy.
   * Same per-path 60s throttle as `notifyDeniedLocalWipe` so tab restores
   * don't produce a stampede.
   */
  private notifyCloudDecryptFallback(path: string): void {
    const now = Date.now();
    const last = this.cloudDecryptFallbackNoticeAt.get(path) ?? 0;
    if (now - last < 60_000) return;
    this.cloudDecryptFallbackNoticeAt.set(path, now);
    new Notice(
      `VaultGuard Sync: Couldn't decrypt the cloud copy of "${path}" — showing local copy.`,
      6000
    );
  }

  /**
   * Returns true if `data` starts with the VG1 magic header. Catches
   * corrupted-read cascades where ciphertext bytes were returned as a
   * UTF-8 string and now arrive at the write path.
   */
  private looksLikeCiphertext(data: string): boolean {
    return (
      data.length >= 4 &&
      data.charCodeAt(0) === 0x56 &&
      data.charCodeAt(1) === 0x47 &&
      data.charCodeAt(2) === 0x31 &&
      data.charCodeAt(3) === 0x00
    );
  }

  /**
   * Binary counterpart of `looksLikeCiphertext`. Prefers the cipher's
   * own header check when available (full length + version validation),
   * falls back to a manual 4-byte magic + version-byte test otherwise.
   */
  private looksLikeCiphertextBytes(data: ArrayBuffer | Uint8Array): boolean {
    if (this.atRestCipher) {
      return this.atRestCipher.isEncrypted(data);
    }
    const view = data instanceof Uint8Array ? data : new Uint8Array(data);
    if (view.length < 5) return false;
    return (
      view[0] === 0x56 &&
      view[1] === 0x47 &&
      view[2] === 0x31 &&
      view[3] === 0x00 &&
      view[4] === 0x01
    );
  }

  /**
   * Per-path-debounced Notice for a blocked corrupted write. Tells the
   * user explicitly to close the file WITHOUT saving — saving again
   * would just re-trigger the same block.
   */
  private notifyCorruptedWrite(path: string): void {
    const now = Date.now();
    const last = this.corruptedWriteNoticeAt.get(path) ?? 0;
    if (now - last < 60_000) return;
    this.corruptedWriteNoticeAt.set(path, now);
    new Notice(
      `VaultGuard Sync: refusing to save "${path}" — it looks like the editor has VaultGuard ciphertext as its content (likely a corrupted-read cascade). The write was BLOCKED to protect the file. Close the file WITHOUT saving and reload it.`,
      10000
    );
  }

  /**
   * Permission-checked and encryption-aware file write operation.
   * @param path - Normalized vault-relative file path
   * @param data - File content to write
   * @throws Error if the user lacks WRITE permission
   */
  private async interceptedWrite(path: string, data: string): Promise<void> {
    if (this.looksLikeCiphertext(data)) {
      this.notifyCorruptedWrite(path);
      this.logError(
        `Refusing to write ciphertext-as-plaintext to ${path}`,
        new Error("blocked: VG1 magic in plaintext write")
      );
      void this.emitAuditEvent("file.write", path, {
        outcome: "denied",
        reason: "ciphertext-as-plaintext-write-blocked",
      });
      throw new Error(
        `VaultGuard Sync: refusing to write "${path}" — content looks like at-rest ciphertext (corrupted-read cascade). File preserved.`
      );
    }

    if (this.applyingRemoteWrite) {
      await this.writePlainToDisk(path, data);
      return;
    }

    if (this.isPathExcluded(path)) {
      if (this.originalAdapterMethods.write) {
        await this.originalAdapterMethods.write(path, data);
      }
      return;
    }

    if (!this.session) {
      throw new Error(this.showLoginRequiredNotice("edit", path));
    }

    await this.awaitPermissionReadiness();
    const permission = await this.getEffectivePermission(path);

    if (permission < PermissionLevel.WRITE) {
      await this.emitAuditEvent("file.write", path, { outcome: "denied" });
      throw new Error(
        `VaultGuard Sync: Access denied. You do not have write permission for "${path}".`
      );
    }

    try {
      // In manual mode, defer remote writes until the user runs a sync explicitly.
      if (this.shouldUploadChangesImmediately() && this.isOnline() && this.keyLease) {
        const encrypted = await this.encryptContent(data);
        const response = await this.apiRequest("PUT", this.vaultPath(`/files/${encodeURIComponent(path)}`), {
          content: encrypted,
          hash: await this.computeHash(data),
        });

        if (!response.success) {
          if (response.error?.statusCode === 401 || response.error?.statusCode === 403) {
            throw new Error(response.error.message);
          }

          if (response.error?.statusCode === 0) {
            this.setConnectionStatus("offline");
            this.queueOfflineOperation("write", path, data);
          } else {
            throw new Error(response.error?.message ?? "Remote write failed.");
          }
        }

        await this.writePlainToDisk(path, data);
      } else {
        await this.writePlainToDisk(path, data);
        this.queueOfflineOperation("write", path, data);
      }

      await this.emitAuditEvent("file.write", path);
      this.syncState.pendingChanges++;
      this.updateStatusBar();
    } catch (error) {
      if (this.isNetworkError(error)) {
        this.setConnectionStatus("offline");
        await this.writePlainToDisk(path, data);
        this.queueOfflineOperation("write", path, data);
      } else {
        throw error;
      }
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Local at-rest read/write helpers
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Read a vault-relative file from local disk and return its plaintext.
   *
   * If the bytes on disk start with the at-rest magic header, decrypt with
   * the LAK. Otherwise, treat the bytes as legacy plaintext (UTF-8) and
   * return as-is — this is what makes lazy migration safe. Excluded paths
   * (plugin self, .obsidian internals) are passed through unchanged because
   * they were never encrypted.
   *
   * Internal plugin code (sync engine pulls, reconciliation, catch-up)
   * MUST use this helper rather than `originalAdapterMethods.read` directly,
   * or it will read raw ciphertext and corrupt downstream logic. See
   * docs/AT-REST-ENCRYPTION.md for the rationale.
   */
  /**
   * Paths that the at-rest cipher must never touch, regardless of the
   * sync-level `isPathExcluded` matcher. Obsidian reads its own settings,
   * plugin code, and theme files directly from disk before our plugin
   * loads, so encrypting any of these would brick the install. The sync
   * exclusion list is narrower (it only covers what shouldn't go to S3).
   */
  private isAtRestExcluded(path: string): boolean {
    const normalized = path.replace(/^\/+/, "");
    if (!normalized) return false;
    if (normalized === ".obsidian" || normalized.startsWith(".obsidian/")) return true;
    if (normalized === ".trash" || normalized.startsWith(".trash/")) return true;
    return this.isPathExcluded(path);
  }

  private async readPlainFromDisk(path: string): Promise<string> {
    if (this.isAtRestExcluded(path)) {
      if (!this.originalAdapterMethods.read) {
        throw new Error("VaultGuard Sync: vault adapter read method unavailable.");
      }
      return this.originalAdapterMethods.read(path);
    }

    // Prefer readBinary so we can detect the magic header bytes precisely.
    if (this.originalAdapterMethods.readBinary) {
      const bytes = await this.originalAdapterMethods.readBinary(path);
      if (this.atRestCipher?.isEncrypted(bytes)) {
        if (!this.atRestCipher.isReady()) {
          await this.waitForCipherInit(10_000);
        }
        if (!this.atRestCipher.isReady()) {
          throw new Error(
            `VaultGuard Sync: cannot read "${path}" — local at-rest encryption is not ready. Try again in a moment.`
          );
        }
        return this.atRestCipher.decryptString(bytes);
      }
      // Legacy plaintext (or external write). Decode as UTF-8.
      return new TextDecoder().decode(bytes);
    }

    // Legacy adapter without readBinary (rare; legacy mobile). Re-encode the
    // first 4 chars and check for the VG1 magic — if it matches, this is
    // ciphertext we must NOT return as a string.
    if (!this.originalAdapterMethods.read) {
      throw new Error("VaultGuard Sync: vault adapter read method unavailable.");
    }
    const text = await this.originalAdapterMethods.read(path);
    if (text.length >= 4) {
      const head = new TextEncoder().encode(text.slice(0, 4));
      if (
        head.length >= 4 &&
        head[0] === 0x56 &&
        head[1] === 0x47 &&
        head[2] === 0x31 &&
        head[3] === 0x00
      ) {
        throw new Error(
          `VaultGuard Sync: cannot read "${path}" — local at-rest encryption is not ready. Try again in a moment.`
        );
      }
    }
    return text;
  }

  /**
   * Wait up to `timeoutMs` for the at-rest cipher's init promise to settle.
   * Returns true if init completed (regardless of success); false on timeout.
   * No-op if `cipherInitPromise` is already null.
   */
  private async waitForCipherInit(timeoutMs: number): Promise<boolean> {
    const p = this.cipherInitPromise;
    if (!p) return false;
    const timeout = new Promise<boolean>((resolve) =>
      setTimeout(() => resolve(false), timeoutMs)
    );
    await Promise.race([p.then(() => true).catch(() => true), timeout]);
    return true;
  }

  /**
   * Write a plaintext UTF-8 string to local disk, encrypting with the LAK
   * before it touches storage.
   *
   * Excluded paths (plugin self, etc.) bypass at-rest encryption — see
   * `isPathExcluded`. Managed vault files fail closed if the at-rest cipher
   * is unavailable; writing plaintext would violate the local encryption
   * guarantee after keychain/reset failures.
   */
  private async writePlainToDisk(path: string, data: string): Promise<void> {
    if (this.looksLikeCiphertext(data)) {
      throw new Error(
        `VaultGuard Sync: writePlainToDisk refused for "${path}" — content has VG1 magic header (corrupted-read cascade).`
      );
    }
    if (this.isAtRestExcluded(path)) {
      if (!this.originalAdapterMethods.write) return;
      await this.originalAdapterMethods.write(path, data);
      return;
    }
    if (!this.atRestCipher?.isReady()) {
      throw new Error(
        `VaultGuard Sync: refusing to write "${path}" because local at-rest encryption is unavailable.`
      );
    }
    const ciphertext = await this.atRestCipher.encryptString(data);
    if (this.originalAdapterMethods.writeBinary) {
      await this.originalAdapterMethods.writeBinary(path, ciphertext);
      return;
    }
    // Adapter without writeBinary — fall back to write() with the ciphertext
    // re-encoded as a binary string. This path is rare (legacy mobile) and
    // best-effort; modern Obsidian always exposes writeBinary.
    if (this.originalAdapterMethods.write) {
      const bin = new Uint8Array(ciphertext);
      let s = "";
      for (let i = 0; i < bin.length; i++) s += String.fromCharCode(bin[i]);
      await this.originalAdapterMethods.write(path, s);
    }
  }

  /**
   * Read raw bytes from disk, decrypting with the LAK when the on-disk
   * format is at-rest-encrypted. Returns plaintext bytes — what every
   * caller who used to call `readBinary` actually wants.
   */
  private async readPlainBinaryFromDisk(path: string): Promise<ArrayBuffer> {
    if (!this.originalAdapterMethods.readBinary) {
      throw new Error("VaultGuard Sync: vault adapter readBinary unavailable.");
    }
    if (this.isAtRestExcluded(path)) {
      return this.originalAdapterMethods.readBinary(path);
    }
    const bytes = await this.originalAdapterMethods.readBinary(path);
    if (this.atRestCipher?.isEncrypted(bytes)) {
      if (!this.atRestCipher.isReady()) {
        await this.waitForCipherInit(10_000);
      }
      if (!this.atRestCipher.isReady()) {
        throw new Error(
          `VaultGuard Sync: cannot read "${path}" — local at-rest encryption is not ready. Try again in a moment.`
        );
      }
      return this.atRestCipher.decryptBinary(bytes);
    }
    return bytes;
  }

  /**
   * Write raw plaintext bytes to disk, encrypting with the LAK before
   * storage. Mirror of `writePlainToDisk` for binary attachments.
   */
  private async writePlainBinaryToDisk(path: string, data: ArrayBuffer): Promise<void> {
    if (this.looksLikeCiphertextBytes(data)) {
      throw new Error(
        `VaultGuard Sync: writePlainBinaryToDisk refused for "${path}" — content has VG1 magic header (corrupted-read cascade).`
      );
    }
    if (this.isAtRestExcluded(path)) {
      if (!this.originalAdapterMethods.writeBinary) return;
      await this.originalAdapterMethods.writeBinary(path, data);
      return;
    }
    if (!this.atRestCipher?.isReady()) {
      throw new Error(
        `VaultGuard Sync: refusing to write "${path}" because local at-rest encryption is unavailable.`
      );
    }
    const ciphertext = await this.atRestCipher.encryptBinary(data);
    if (this.originalAdapterMethods.writeBinary) {
      await this.originalAdapterMethods.writeBinary(path, ciphertext);
    }
  }

  /**
   * Returns true when a NONE permission result for `path` should be treated
   * as "permission unknown" rather than "explicitly denied". Used as a
   * last-line guard inside the read interceptors so a cold-cache startup
   * race cannot wipe vault content (1.0.15 data-loss regression).
   *
   * The check is deliberately strict: we only defer when there is no
   * positive evidence whatsoever — no completed warm-up cycle AND no
   * cached entry for this exact path. Once a warm-up has succeeded, a
   * NONE result is real and the wipe proceeds.
   */
  private shouldDeferDenialWipe(path: string): boolean {
    if (this.hasWarmedAtLeastOnce) return false;
    const cached = this.permissionStore.getCachedPermission(path);
    if (cached !== undefined) return false;
    return true;
  }

  /**
   * Permission-checked at-rest decrypted binary read.
   *
   * Same semantics as `interceptedRead`, but for non-text files
   * (images, PDFs, binary attachments). Routes through the at-rest cipher
   * so on-disk ciphertext is invisible to Obsidian and to the user.
   */
  private async interceptedReadBinary(path: string): Promise<ArrayBuffer> {
    if (!this.originalAdapterMethods.readBinary) {
      throw new Error("VaultGuard Sync: vault adapter readBinary unavailable.");
    }
    if (this.isPathExcluded(path)) {
      return this.originalAdapterMethods.readBinary(path);
    }
    if (!this.session) {
      throw new Error(this.showLoginRequiredNotice("open", path));
    }

    await this.awaitPermissionReadiness();
    const permission = await this.getEffectivePermission(path);
    if (permission < PermissionLevel.READ) {
      // See interceptedRead for the fail-open rationale. Binary reads must
      // not wipe or throw — they hit the same Obsidian-indexer retry loop
      // and the same data-loss vector as text reads.
      await this.emitAuditEvent("file.read", path, {
        outcome: "denied",
        reason: "permission-denied-read-fail-open",
      });
      this.log(`Permission denied for binary "${path}" (read fail-open).`);
      return this.readPlainBinaryFromDisk(path);
    }

    return this.readPlainBinaryFromDisk(path);
  }

  /**
   * Permission-checked at-rest encrypted binary write.
   *
   * Mirrors `interceptedWrite` for binary content. Managed binary writes fail
   * closed until the backend supports binary sync; silently keeping encrypted
   * attachments local would create a false sense of protected backup.
   */
  private async interceptedWriteBinary(path: string, data: ArrayBuffer): Promise<void> {
    if (!this.originalAdapterMethods.writeBinary) return;
    if (this.looksLikeCiphertextBytes(data)) {
      this.notifyCorruptedWrite(path);
      this.logError(
        `Refusing to write ciphertext-as-plaintext binary to ${path}`,
        new Error("blocked: VG1 magic in plaintext binary write")
      );
      void this.emitAuditEvent("file.write", path, {
        outcome: "denied",
        reason: "ciphertext-as-plaintext-write-blocked",
      });
      throw new Error(
        `VaultGuard Sync: refusing to write "${path}" — content looks like at-rest ciphertext (corrupted-read cascade). File preserved.`
      );
    }
    if (this.applyingRemoteWrite || this.isPathExcluded(path)) {
      await this.writePlainBinaryToDisk(path, data);
      return;
    }
    if (!this.session) {
      throw new Error(this.showLoginRequiredNotice("edit", path));
    }
    await this.awaitPermissionReadiness();
    const permission = await this.getEffectivePermission(path);
    if (permission < PermissionLevel.WRITE) {
      await this.emitAuditEvent("file.write", path, { outcome: "denied" });
      throw new Error(
        `VaultGuard Sync: Access denied. You do not have write permission for "${path}".`
      );
    }
    await this.emitAuditEvent("file.write", path, { outcome: "denied", reason: "binary-sync-unsupported" });
    throw new Error(
      `VaultGuard Sync: Binary files are not currently supported for protected sync. "${path}" was not written.`
    );
  }

  /**
   * Checks whether the current user may delete a path.
   * Delete is a distinct backend action, so WRITE does not imply deletion.
   */
  private async canDeletePath(path: string): Promise<boolean> {
    if (!this.session) {
      return false;
    }

    if (this.session.role === "admin" || this.session.role === "owner") {
      return true;
    }

    if (this.isOnline()) {
      const roles = this.session.roles?.length ? this.session.roles : [this.session.role];
      let response: ApiResponse<{ allowed: boolean }>;
      try {
        response = await this.apiRequest<{ allowed: boolean }>("POST", this.vaultPath('/permissions/check'), {
          userId: this.session.userId,
          roles,
          action: "delete",
          path: this.toPermissionPath(path),
        });
      } catch (error) {
        if (this.isNetworkError(error)) {
          this.setConnectionStatus("offline");
        } else {
          return false;
        }
        return this.resolvePermissionFromCache(path) >= PermissionLevel.ADMIN;
      }

      if (response.success) {
        return response.data?.allowed === true;
      }

      if (response.error?.statusCode === 401 || response.error?.statusCode === 403) {
        return false;
      }

      if (response.error?.statusCode !== 0) {
        return false;
      }
    }

    return this.resolvePermissionFromCache(path) >= PermissionLevel.ADMIN;
  }

  /**
   * Directory listing operation.
   *
   * Keep this path local-only. Obsidian calls adapter.list() while mounting the
   * native file explorer and during startup indexing; doing live permission
   * probes here can turn a cold cache or transient backend error into an empty
   * vault tree. The file-explorer decoration layer fetches backend-confirmed
   * access summaries asynchronously and hides explicit no-access file rows once
   * it has evidence. Mutating operations still enforce permissions.
   *
   * @param path - Normalized vault-relative directory path
   * @returns Raw local files and folders for the requested directory
   */
  private async interceptedList(
    path: string
  ): Promise<{ files: string[]; folders: string[] }> {
    if (!this.originalAdapterMethods.list) {
      return { files: [], folders: [] };
    }

    return this.originalAdapterMethods.list(path);
  }

  /**
   * Permission-checked file deletion operation.
   * @param path - Normalized vault-relative file path
   * @throws Error if the user lacks DELETE permission
   */
  private async interceptedDelete(path: string): Promise<void> {
    if (this.isPathExcluded(path)) {
      if (this.originalAdapterMethods.remove) {
        await this.originalAdapterMethods.remove(path);
      }
      return;
    }

    if (!this.session) {
      throw new Error(this.showLoginRequiredNotice("delete", path));
    }

    if (!(await this.canDeletePath(path))) {
      await this.emitAuditEvent("file.delete", path, { outcome: "denied" });
      throw new Error(
        `VaultGuard Sync: Access denied. You do not have permission to delete "${path}".`
      );
    }

    try {
      // In manual mode, defer remote deletes until the user runs a sync explicitly.
      if (this.shouldUploadChangesImmediately() && this.isOnline()) {
        const response = await this.apiRequest(
          "DELETE",
          this.vaultPath(`/files/${encodeURIComponent(path)}`)
        );

        if (!response.success) {
          if (response.error?.statusCode === 401 || response.error?.statusCode === 403) {
            throw new Error(response.error.message);
          }

          if (response.error?.statusCode === 0) {
            this.setConnectionStatus("offline");
            this.queueOfflineOperation("delete", path);
          } else {
            throw new Error(response.error?.message ?? "Remote delete failed.");
          }
        }
      } else {
        this.queueOfflineOperation("delete", path);
      }

      // Delete locally only after authorization and, when online, remote success.
      if (this.originalAdapterMethods.remove) {
        await this.originalAdapterMethods.remove(path);
      }

      await this.emitAuditEvent("file.delete", path);
      this.permissionStore.emit("changed", { path });
    } catch (error) {
      if (this.isNetworkError(error)) {
        this.setConnectionStatus("offline");
        this.queueOfflineOperation("delete", path);
      } else {
        throw error;
      }
    }
  }

  /**
   * Permission-checked file rename: keeps the local rename atomic with the
   * server-side move (PUT new path, then DELETE old path). The original
   * adapter rename runs first so the local file system is the source of
   * truth for the new content; if the server move fails partway, we queue
   * the missing half on the offline queue rather than rolling the local
   * rename back.
   */
  private async interceptedRename(oldPath: string, newPath: string): Promise<void> {
    const oldNormalized = this.normalizeVaultPath(oldPath);
    const newNormalized = this.normalizeVaultPath(newPath);

    // Local rename happens first regardless of permissions or network — the
    // existing adapter behaviour the user expects. Server reconciliation is
    // best-effort on top.
    if (this.originalAdapterMethods.rename) {
      await this.originalAdapterMethods.rename(oldPath, newPath);
    }

    // Skip server work for binding-less / offline / non-bound states. We
    // queue both halves so a future flush picks them up.
    if (!this.session || !this.settings.serverVaultId) {
      return;
    }

    // If either side of the rename is in the excluded list, treat as a
    // local-only move — the server has no record of these paths and
    // shouldn't gain one through a rename.
    if (this.isPathExcluded(oldNormalized) || this.isPathExcluded(newNormalized)) {
      // Pitfall 5: emit OLD path so cache + metadataCache invalidate; leaf
      // sweep resolves CURRENT view per leaf (Plan 09-03).
      this.permissionStore.emit("changed", { path: oldNormalized });
      return;
    }

    // If this rename targets a folder, the adapter call has already moved the
    // directory locally — but the existing file-mover logic below assumes a
    // single file with readable content and would fail trying to read folder
    // bytes. The vault.on('rename') folder listener handles the marker move
    // and the children's vault.on('rename') events handle each child. Bail
    // out here so we don't double-handle or corrupt the marker path.
    const renamedItem = this.app.vault.getAbstractFileByPath(newPath);
    if (renamedItem instanceof TFolder) {
      // Pitfall 5: rename emits OLD path.
      this.permissionStore.emit("changed", { path: oldNormalized });
      return;
    }
    // Marker files should never round-trip through this path either.
    if (this.isFolderMarkerPath(oldNormalized) || this.isFolderMarkerPath(newNormalized)) {
      return;
    }

    const writePermission = await this.getEffectivePermission(newNormalized);
    if (writePermission < PermissionLevel.WRITE) {
      await this.emitAuditEvent("file.rename", oldNormalized, {
        newPath: newNormalized,
        outcome: "denied",
      });
      new Notice(
        `VaultGuard Sync: Renamed locally, but the server copy of "${oldPath}" was not moved — you do not have write permission for "${newPath}".`
      );
      return;
    }

    if (!this.shouldUploadChangesImmediately() || !this.isOnline() || !this.keyLease) {
      // Queue both halves: read content from the just-renamed local file so the
      // queued write carries the right bytes when connectivity returns.
      try {
        const content = await this.readPlainFromDisk(newPath);
        this.queueOfflineOperation("write", newNormalized, content);
      } catch (err) {
        this.logError(`Rename: failed to queue offline write for "${newPath}"`, err);
      }
      this.queueOfflineOperation("delete", oldNormalized);
      // Pitfall 5: rename emits OLD path.
      this.permissionStore.emit("changed", { path: oldNormalized });
      return;
    }

    try {
      const content = await this.readPlainFromDisk(newPath);
      const encrypted = await this.encryptContent(content);

      const putResp = await this.apiRequest(
        "PUT",
        this.vaultPath(`/files/${encodeURIComponent(newNormalized)}`),
        {
          content: encrypted,
          hash: await this.computeHash(content),
        }
      );

      if (!putResp.success) {
        throw new Error(putResp.error?.message ?? `Rename: writing "${newPath}" failed.`);
      }

      const delResp = await this.apiRequest(
        "DELETE",
        this.vaultPath(`/files/${encodeURIComponent(oldNormalized)}`)
      );

      if (!delResp.success) {
        // New path is on the server but the old one wasn't deleted. Queue the
        // delete so the next flush retries — without this the admin panel
        // shows both names forever, which is exactly the duplicate-after-
        // rename bug we're fixing.
        this.logError(
          `Rename: DELETE of old path "${oldNormalized}" failed`,
          new Error(delResp.error?.message ?? "unknown")
        );
        this.queueOfflineOperation("delete", oldNormalized);
      }

      // Pitfall 5: rename emits OLD path.
      this.permissionStore.emit("changed", { path: oldNormalized });
      await this.emitAuditEvent("file.rename", oldNormalized, { newPath: newNormalized });
      this.syncState.pendingChanges = this.offlineQueue.length;
      this.updateStatusBar();
    } catch (error) {
      if (this.isNetworkError(error)) {
        this.setConnectionStatus("offline");
        try {
          const content = await this.readPlainFromDisk(newPath);
          this.queueOfflineOperation("write", newNormalized, content);
        } catch (err) {
          this.logError(`Rename: failed to queue offline write for "${newPath}"`, err);
        }
        this.queueOfflineOperation("delete", oldNormalized);
        // Pitfall 5: rename emits OLD path.
        this.permissionStore.emit("changed", { path: oldNormalized });
      } else {
        throw error;
      }
    }
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
    return normalizePath(path.replace(/^\/+/, ""));
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
   * `.obsidian/workspace.json` matches that file only. `.obsidian/plugins`
   * matches the folder itself plus everything under it.
   */
  isPathExcluded(path: string): boolean {
    const normalized = this.normalizeVaultPath(path);
    if (!normalized) return false;

    // Hard-exclude every vault-root hidden entry (anything whose first path
    // segment starts with "."). By Obsidian/Unix convention these are system
    // or plugin-state folders, never note content: `.obsidian/` (Obsidian's
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
    this.log("Initializing sync engine...");

    // Restore lastSync from persisted settings so a fresh process does not
    // pull every server file (and silently overwrite local edits) on startup.
    if (!this.syncState.lastSync && this.settings.lastSyncTimestamp) {
      this.syncState.lastSync = this.settings.lastSyncTimestamp;
    }

    // First-time bind for this serverVaultId: reconcile local↔server before
    // any sync writes happen. Without this, the initial /files/sync call with
    // lastSyncTimestamp = epoch causes every server file to come back as
    // "created" and silently overwrite same-named local files.
    const vaultId = this.settings.serverVaultId;
    if (vaultId && this.settings.bindingReconciledVaultId !== vaultId) {
      try {
        const reconciled = await this.performInitialReconciliation();
        if (!reconciled) {
          this.log("Initial reconciliation declined or aborted — sync engine will not start.");
          return;
        }
      } catch (err) {
        this.logError("Initial reconciliation failed", err);
        new Notice(
          `VaultGuard Sync: Couldn't reconcile this folder with the server vault: ${
            err instanceof Error ? err.message : "Unknown error"
          }. Sync paused — open the sidebar to retry.`
        );
        return;
      }
    }

    // Wire folder lifecycle listeners now that we have a bound vault. Files
    // are mirrored via the adapter interceptors; folders need vault events
    // because Obsidian doesn't expose mkdir/rmdir on the adapter pattern we
    // intercept, and S3 needs an explicit marker for empty-folder survival.
    this.registerFolderLifecycleListeners();

    // Perform initial sync
    await this.performSync();

    // Start periodic sync timer
    this.startSyncTimer();

    this.log("Sync engine initialized.");
  }

  /**
   * Wires Obsidian vault events so create/rename/delete of folders mirrors
   * to the server-side folder marker. Idempotent — only registers once per
   * plugin process. File events are deliberately ignored here because the
   * adapter interceptors already handle them; double-handling would mean
   * two PUT/DELETE round-trips for every direct file op.
   */
  private registerFolderLifecycleListeners(): void {
    if (this.folderLifecycleListenersRegistered) return;
    this.folderLifecycleListenersRegistered = true;

    this.registerEvent(
      this.app.vault.on("create", (file: TAbstractFile) => {
        if (!(file instanceof TFolder)) return;
        if (!this.settings.serverVaultId || !this.session) return;
        void this.uploadFolderMarker(file.path).catch((err) =>
          this.logError(`Folder create: marker for "${file.path}" failed`, err)
        );
      })
    );

    this.registerEvent(
      this.app.vault.on("delete", (file: TAbstractFile) => {
        if (!(file instanceof TFolder)) return;
        if (!this.settings.serverVaultId || !this.session) return;
        void this.deleteFolderMarker(file.path).catch((err) =>
          this.logError(`Folder delete: marker for "${file.path}" failed`, err)
        );
      })
    );

    this.registerEvent(
      this.app.vault.on("rename", (file: TAbstractFile, oldPath: string) => {
        if (!(file instanceof TFolder)) return;
        if (!this.settings.serverVaultId || !this.session) return;
        if (oldPath === file.path) return;
        void (async () => {
          try {
            await this.deleteFolderMarker(oldPath);
            await this.uploadFolderMarker(file.path);
          } catch (err) {
            this.logError(`Folder rename: marker move "${oldPath}" → "${file.path}" failed`, err);
          }
        })();
      })
    );

    // For files, vault.on('rename') is the only signal that fires when a
    // child file's path changes because its parent folder was renamed —
    // adapter.rename only fires once for the parent. Without this listener
    // every child file stays at its old key in S3 and the admin panel shows
    // duplicates after every folder rename. The DELETE old + PUT new logic
    // is idempotent with our adapter.rename interceptor for direct file
    // renames, so double-firing is harmless.
    this.registerEvent(
      this.app.vault.on("rename", (file: TAbstractFile, oldPath: string) => {
        if (!(file instanceof TFile)) return;
        if (!this.settings.serverVaultId || !this.session) return;
        if (oldPath === file.path) return;
        void this.syncFileRenameToServer(oldPath, file.path).catch((err) =>
          this.logError(`File rename via vault event "${oldPath}" → "${file.path}" failed`, err)
        );
      })
    );

    // Same rationale for delete: when a folder is removed, adapter.remove
    // doesn't fire for its child files (Obsidian uses adapter.rmdir under
    // the hood). The vault event is the only way to learn each child's path.
    this.registerEvent(
      this.app.vault.on("delete", (file: TAbstractFile) => {
        if (!(file instanceof TFile)) return;
        if (!this.settings.serverVaultId || !this.session) return;
        void this.syncFileDeleteToServer(file.path).catch((err) =>
          this.logError(`File delete via vault event "${file.path}" failed`, err)
        );
      })
    );

    this.log("Folder lifecycle listeners registered.");
  }

  /**
   * Best-effort server-side rename of a single file. Idempotent so it can
   * fire alongside `interceptedRename` without duplicate side-effects.
   * Reads the renamed local file's content and PUTs it to the new key,
   * then DELETEs the old key.
   */
  private async syncFileRenameToServer(oldPath: string, newPath: string): Promise<void> {
    if (!this.isOnline() || !this.keyLease) return;
    if (!this.originalAdapterMethods.read) return;

    const oldNormalized = this.normalizeVaultPath(oldPath);
    const newNormalized = this.normalizeVaultPath(newPath);
    if (this.isFolderMarkerPath(oldNormalized) || this.isFolderMarkerPath(newNormalized)) return;

    const permission = await this.getEffectivePermission(newNormalized);
    if (permission < PermissionLevel.WRITE) return;

    let content: string;
    try {
      content = await this.readPlainFromDisk(newPath);
    } catch (err) {
      // If we can't read the file (e.g. it was renamed and immediately
      // deleted), skip — the delete listener will clean up the old key.
      this.log(`Rename sync: cannot read "${newPath}" (${err}); skipping server move.`);
      return;
    }

    const encrypted = await this.encryptContent(content);
    const putResp = await this.apiRequest(
      "PUT",
      this.vaultPath(`/files/${encodeURIComponent(newNormalized)}`),
      { content: encrypted, hash: await this.computeHash(content) }
    );
    if (!putResp.success) {
      // 401/403 are non-recoverable here — the user lost permission since
      // the cache was warmed. Fall through to attempt the DELETE anyway so
      // we don't strand the old key.
      this.logError(
        `Rename sync: PUT "${newNormalized}" failed`,
        new Error(putResp.error?.message ?? "unknown")
      );
    }

    const delResp = await this.apiRequest(
      "DELETE",
      this.vaultPath(`/files/${encodeURIComponent(oldNormalized)}`)
    );
    if (!delResp.success && delResp.error?.statusCode !== 404) {
      this.logError(
        `Rename sync: DELETE "${oldNormalized}" failed`,
        new Error(delResp.error?.message ?? "unknown")
      );
    }
    // Pitfall 5: rename emits OLD path.
    this.permissionStore.emit("changed", { path: oldNormalized });
  }

  /**
   * Best-effort server-side DELETE for a single file. Idempotent — duplicates
   * the work of `interceptedDelete` for direct file removals, but is the
   * only path that fires for child files of a deleted folder.
   */
  private async syncFileDeleteToServer(path: string): Promise<void> {
    if (!this.isOnline()) return;
    const normalized = this.normalizeVaultPath(path);
    if (!normalized || this.isFolderMarkerPath(normalized)) return;

    const response = await this.apiRequest(
      "DELETE",
      this.vaultPath(`/files/${encodeURIComponent(normalized)}`)
    );
    if (!response.success && response.error?.statusCode !== 404) {
      this.logError(
        `Delete sync: DELETE "${normalized}" failed`,
        new Error(response.error?.message ?? "unknown")
      );
    }
    this.permissionStore.emit("changed", { path: normalized });
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
    if (!this.session || !this.isOnline()) {
      throw new Error(
        "Reconciliation requires an authenticated, online session."
      );
    }

    new Notice("VaultGuard Sync: Comparing your folder with the server vault…");

    // ── Step 1: Build local manifest ─────────────────────────────────────
    const localFiles = this.app.vault.getFiles();
    const localManifest = new Map<string, { content: string; hash: string }>();
    for (const file of localFiles) {
      try {
        const normalized = this.normalizeVaultPath(file.path);
        // Local-only opt-out: leave excluded paths out of the manifest so
        // they're never bucketed for upload or conflict resolution.
        if (this.isPathExcluded(normalized)) continue;
        const content = await this.readPlainFromDisk(file.path);
        const hash = await this.computeHash(content);
        // The server keys deltas with a leading slash — keep the same shape
        // for set-membership comparisons below.
        localManifest.set(`/${normalized}`, { content, hash });
      } catch (err) {
        this.logError(`Reconciliation: failed to read local file "${file.path}"`, err);
      }
    }

    // ── Step 2: Fetch server inventory ───────────────────────────────────
    const inventory = await this.apiRequest<{
      deltas: Array<{
        path: string;
        action: "created" | "modified" | "deleted";
        lastModified: string;
        checksum: string;
        size: number;
      }>;
      syncTimestamp: string;
    }>("POST", this.vaultPath("/files/sync"), {
      lastSyncTimestamp: new Date(0).toISOString(),
      fileChecksums: {},
    });

    if (!inventory.success || !inventory.data) {
      throw new Error(inventory.error?.message ?? "Could not fetch the server vault inventory.");
    }

    const serverPaths = new Set<string>();
    const serverFolderPaths = new Set<string>();
    for (const delta of inventory.data.deltas) {
      if (delta.action === "deleted") continue;
      // Folder markers are tracked separately so the bucketing below treats
      // them as folders to mirror, not as local-only files to "upload".
      const normalized = this.normalizeVaultPath(delta.path);
      if (this.isFolderMarkerPath(normalized)) {
        const folderPath = this.folderPathFromMarkerPath(normalized);
        if (this.isPathExcluded(folderPath)) continue;
        serverFolderPaths.add(folderPath);
        continue;
      }
      // Local-only opt-out: ignore the server's view of excluded paths.
      if (this.isPathExcluded(normalized)) continue;
      serverPaths.add(delta.path);
    }

    // ── Step 3: Bucketize ────────────────────────────────────────────────
    const serverOnly: string[] = [];
    const localOnly: string[] = [];
    const conflicts: string[] = [];
    const localManifestBoth: Array<{ path: string; localContent: string; localHash: string }> = [];

    for (const path of serverPaths) {
      if (!localManifest.has(path)) {
        serverOnly.push(path);
      }
    }
    for (const [path, entry] of localManifest.entries()) {
      if (!serverPaths.has(path)) {
        localOnly.push(path);
      } else {
        localManifestBoth.push({ path, localContent: entry.content, localHash: entry.hash });
      }
    }

    // Phase-8 limited-access branch (BLOCKER-2 Q2 RESOLVED): skip the async-ack
    // modal entirely — there is nothing for the user to acknowledge in this mode.
    // localOnly uploads silently fail (no lease → no encrypt); conflicts can't
    // be diffed (no plaintext at scale); serverOnly is written non-interactively
    // as 36-byte VG1 placeholders so Obsidian's file explorer renders the tree.
    // localOnly and conflicts handling defer to a follow-up phase (A4).
    if (this.vaultLeaseDenied) {
      for (const path of serverOnly) {
        const normalized = this.normalizeVaultPath(path);
        if (this.isPathExcluded(normalized)) continue;
        if (this.isFolderMarkerPath(normalized)) continue;
        await this.ensureParentFoldersForPath(normalized);
        await this.writePlainToDisk(normalized, ""); // 36-byte VG1 placeholder
        this.placeholderPaths.add(normalized);
      }
      // Mirror server-only folders too so the tree is visible.
      for (const folderPath of serverFolderPaths) {
        if (!folderPath) continue;
        try {
          await this.ensureLocalFolderPath(folderPath);
        } catch (err) {
          this.logError(`Reconciliation (limited): mkdir for "${folderPath}" failed`, err);
        }
      }
      // Persist completion so this binding isn't re-reconciled on every restart.
      this.settings.bindingReconciledVaultId = this.settings.serverVaultId;
      this.syncState.lastSync = inventory.data.syncTimestamp;
      this.settings.lastSyncTimestamp = inventory.data.syncTimestamp;
      await this.saveSettings();
      new Notice(
        `VaultGuard Sync: Limited-access reconciliation — ${serverOnly.length} files visible. ` +
          `Open one to fetch its content from the server.`,
        6000
      );
      return true;
    }

    // For paths on both sides, fetch + decrypt the server copy and hash to
    // determine real conflicts (the server's reported `checksum` is the S3
    // ETag of the encrypted blob — never equal to a plaintext SHA-256).
    const sameContent = new Set<string>();
    for (const item of localManifestBoth) {
      try {
        const remoteContent = await this.readRemotePlaintext(item.path);
        const remoteHash = await this.computeHash(remoteContent);
        if (remoteHash === item.localHash) {
          sameContent.add(item.path);
        } else {
          conflicts.push(item.path);
        }
      } catch (err) {
        this.logError(`Reconciliation: comparison failed for "${item.path}"`, err);
        conflicts.push(item.path);
      }
    }

    const plan: ReconciliationPlan = { serverOnly, localOnly, conflicts };

    // ── Step 4: Show preview modal ───────────────────────────────────────
    const decision = await this.askReconciliationPlan(plan);
    if (!decision.proceed) {
      new Notice("VaultGuard Sync: Binding cancelled — no files were modified.");
      return false;
    }

    // ── Step 5: Apply plan ───────────────────────────────────────────────
    new Notice(
      `VaultGuard Sync: Reconciling — ↓${serverOnly.length} ↑${localOnly.length} ⚠${conflicts.length}`
    );

    let downloaded = 0;
    let downloadFailed = 0;
    for (const path of serverOnly) {
      try {
        await this.applyRemoteChange({
          path: this.normalizeVaultPath(path),
          size: 0,
        });
        downloaded += 1;
      } catch (err) {
        this.logError(`Reconciliation: download failed for "${path}"`, err);
        downloadFailed += 1;
      }
    }

    let uploaded = 0;
    let uploadSkipped = 0;
    let uploadFailed = 0;
    for (const path of localOnly) {
      const entry = localManifest.get(path);
      if (!entry) continue;
      try {
        const outcome = await this.uploadReconciledFile(this.normalizeVaultPath(path), entry.content);
        if (outcome === "uploaded") uploaded += 1;
        else uploadSkipped += 1;
      } catch (err) {
        this.logError(`Reconciliation: upload failed for "${path}"`, err);
        uploadFailed += 1;
      }
    }

    let conflictsResolved = 0;
    let conflictFailed = 0;
    for (const path of conflicts) {
      try {
        await this.resolveReconciliationConflict(path, decision.conflictStrategy, localManifest);
        conflictsResolved += 1;
      } catch (err) {
        this.logError(`Reconciliation: conflict resolution failed for "${path}"`, err);
        conflictFailed += 1;
      }
    }

    // ── Folder structure ────────────────────────────────────────────────
    // Mirror folders both ways. Server-only folders become local mkdirs,
    // local-only folders get a marker on the server. Without this, empty
    // folders never make the round-trip — S3 has no native "empty folder"
    // primitive and the admin overview would render the vault structure
    // incorrectly (the original bug report).
    let foldersUploaded = 0;
    let foldersDownloaded = 0;
    let foldersFailed = 0;

    const localFolderPaths = new Set(this.collectLocalFolderPaths());

    for (const folderPath of serverFolderPaths) {
      if (!folderPath || localFolderPaths.has(folderPath)) continue;
      try {
        const created = await this.ensureLocalFolderPath(folderPath);
        if (created) foldersDownloaded += 1;
      } catch (err) {
        this.logError(`Reconciliation: mkdir for "${folderPath}" failed`, err);
        foldersFailed += 1;
      }
    }

    for (const folderPath of localFolderPaths) {
      if (serverFolderPaths.has(folderPath)) continue;
      try {
        const ok = await this.uploadFolderMarker(folderPath);
        if (ok) foldersUploaded += 1;
      } catch (err) {
        this.logError(`Reconciliation: folder marker upload for "${folderPath}" failed`, err);
        foldersFailed += 1;
      }
    }

    const fullySucceeded = uploadFailed === 0 && downloadFailed === 0 && conflictFailed === 0 && foldersFailed === 0;

    // ── Step 6: Persist completion ───────────────────────────────────────
    // Only mark this binding as reconciled when every step actually landed.
    // If anything failed, leave `bindingReconciledVaultId` unset so the next
    // start retries — otherwise local-only files stay stranded on disk and
    // the server vault silently disagrees with the plugin's "X uploaded"
    // summary forever (admin panel shows 0 files, plugin claims they synced).
    if (fullySucceeded) {
      this.settings.bindingReconciledVaultId = this.settings.serverVaultId;
    }
    this.syncState.lastSync = inventory.data.syncTimestamp;
    this.settings.lastSyncTimestamp = inventory.data.syncTimestamp;
    await this.saveSettings();

    const failureParts: string[] = [];
    if (uploadFailed > 0) failureParts.push(`${uploadFailed} upload failed`);
    if (uploadSkipped > 0) failureParts.push(`${uploadSkipped} skipped (no write permission)`);
    if (downloadFailed > 0) failureParts.push(`${downloadFailed} download failed`);
    if (conflictFailed > 0) failureParts.push(`${conflictFailed} conflict failed`);
    if (foldersFailed > 0) failureParts.push(`${foldersFailed} folders failed`);

    const summaryParts = [
      `${downloaded} downloaded`,
      `${uploaded} uploaded`,
      `${conflictsResolved} conflicts resolved`,
    ];
    if (foldersDownloaded > 0) summaryParts.push(`${foldersDownloaded} folders mirrored locally`);
    if (foldersUploaded > 0) summaryParts.push(`${foldersUploaded} folders preserved`);
    if (sameContent.size > 0) {
      summaryParts.push(`${sameContent.size} already in sync`);
    }
    if (failureParts.length > 0) {
      summaryParts.push(failureParts.join(", "));
    }
    const summary = `${summaryParts.join(", ")}.`;

    if (fullySucceeded) {
      new Notice(`VaultGuard Sync: Reconciliation complete. ${summary}`);
    } else {
      new Notice(
        `VaultGuard Sync: Reconciliation finished with errors — ${summary} Open the sidebar to retry.`,
        10000
      );
    }
    this.log(`Reconciliation complete: ${summary}`);
    return true;
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
  ): Promise<"uploaded" | "skipped"> {
    if (!this.hasValidKeyLease()) {
      this.log(`Reconciliation: skipping "${path}" — no encryption key lease available.`);
      new Notice(
        `VaultGuard Sync: Skipped upload of "${path}" — limited access sessions can download accessible files, but need a key lease to encrypt uploads.`
      );
      return "skipped";
    }

    const permission = await this.getEffectivePermission(path);
    if (permission < PermissionLevel.WRITE) {
      this.log(`Reconciliation: skipping "${path}" — no write permission.`);
      new Notice(
        options.noWriteNotice ??
          `VaultGuard Sync: Skipped upload of "${path}" — you do not have write permission. The file stays in this folder but is not synced.`
      );
      return "skipped";
    }
    const encrypted = await this.encryptContent(content);
    const response = await this.apiRequest("PUT", this.vaultPath(`/files/${encodeURIComponent(path)}`), {
      content: encrypted,
      hash: await this.computeHash(content),
    });
    if (!response.success) {
      throw new Error(response.error?.message ?? `Upload of "${path}" failed.`);
    }
    await this.emitAuditEvent("file.write", path, { reconciliation: true });
    return "uploaded";
  }

  private async removeUnsyncedLocalFile(path: string): Promise<boolean> {
    if (!this.originalAdapterMethods.remove) {
      this.log(`Catch-up: could not remove local-only "${path}" — adapter remove unavailable.`);
      return false;
    }

    try {
      await this.originalAdapterMethods.remove(path);
      this.permissionStore.emit("changed", { path });
      return true;
    } catch (err) {
      this.logError(`Catch-up: failed to remove local-only "${path}"`, err);
      return false;
    }
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
    if (!this.session || !this.settings.serverVaultId || !this.hasValidKeyLease()) return null;
    if (!this.originalAdapterMethods.read) return null;

    let inventory: { path: string; action: string }[] | null = null;
    try {
      const response = await this.apiRequest<{
        deltas: Array<{ path: string; action: string }>;
      }>("POST", this.vaultPath("/files/sync"), {
        lastSyncTimestamp: new Date(0).toISOString(),
        fileChecksums: {},
      });
      if (!response.success || !response.data) {
        this.log("Catch-up: could not fetch server inventory, skipping.");
        return null;
      }
      inventory = response.data.deltas;
    } catch (err) {
      this.logError("Catch-up: server inventory fetch failed", err);
      return null;
    }

    const serverFilePaths = new Set<string>();
    const serverFolderPaths = new Set<string>();
    for (const delta of inventory) {
      if (delta.action === "deleted") continue;
      const normalized = this.normalizeVaultPath(delta.path);
      if (this.isFolderMarkerPath(normalized)) {
        serverFolderPaths.add(this.folderPathFromMarkerPath(normalized));
      } else {
        serverFilePaths.add(`/${normalized}`);
      }
    }

    // ── Files ────────────────────────────────────────────────────────────
    const localFiles = this.app.vault.getFiles();
    let uploaded = 0;
    let removedLocal = 0;
    let failed = 0;
    let skipped = 0;
    for (const file of localFiles) {
      const normalized = this.normalizeVaultPath(file.path);
      // Skip our own marker files if any happen to exist on disk — they're
      // server-only infrastructure and must never be treated as user content.
      if (this.isFolderMarkerPath(normalized)) continue;
      // Local-only opt-out: never push excluded paths up to the server.
      if (this.isPathExcluded(normalized)) continue;
      const lookupKey = `/${normalized}`;
      if (serverFilePaths.has(lookupKey)) continue;

      try {
        const content = await this.readPlainFromDisk(file.path);
        const outcome = await this.uploadReconciledFile(normalized, content, {
          noWriteNotice:
            `VaultGuard Sync: Removed local-only "${normalized}" because this server vault ` +
            "does not contain it and you do not have write permission to add it.",
        });
        if (outcome === "uploaded") {
          uploaded += 1;
        } else {
          skipped += 1;
          if (await this.removeUnsyncedLocalFile(normalized)) {
            removedLocal += 1;
          }
        }
      } catch (err) {
        failed += 1;
        this.logError(`Catch-up: upload of "${file.path}" failed`, err);
      }
    }

    // ── Folders ──────────────────────────────────────────────────────────
    // S3 has no native folder concept, so empty Obsidian folders disappear
    // from the admin panel unless we plant a sentinel object inside them.
    // Mirror every local folder that lacks a server-side marker.
    let foldersUploaded = 0;
    let foldersFailed = 0;
    for (const folderPath of this.collectLocalFolderPaths()) {
      if (serverFolderPaths.has(folderPath)) continue;
      if (this.isPathExcluded(folderPath)) continue;
      try {
        const ok = await this.uploadFolderMarker(folderPath);
        if (ok) foldersUploaded += 1;
      } catch (err) {
        foldersFailed += 1;
        this.logError(`Catch-up: folder marker upload for "${folderPath}" failed`, err);
      }
    }

    const totalChanges = uploaded + removedLocal + skipped + failed + foldersUploaded + foldersFailed;
    if (totalChanges > 0) {
      const parts: string[] = [];
      if (uploaded > 0) parts.push(`${uploaded} files uploaded`);
      if (removedLocal > 0) parts.push(`${removedLocal} local-only files removed`);
      if (foldersUploaded > 0) parts.push(`${foldersUploaded} folders preserved`);
      if (skipped > 0) parts.push(`${skipped} skipped (no write permission)`);
      if (failed > 0) parts.push(`${failed} files failed`);
      if (foldersFailed > 0) parts.push(`${foldersFailed} folders failed`);
      const message = `VaultGuard Sync: Caught up local-only items — ${parts.join(", ")}.`;
      this.log(message);
    }

    return {
      uploadedFiles: uploaded,
      uploadedFolders: foldersUploaded,
      removedLocalFiles: removedLocal,
      skippedFiles: skipped,
      failedFiles: failed,
      failedFolders: foldersFailed,
    };
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
    if (!this.session || !this.settings.serverVaultId) return null;
    if (!this.originalAdapterMethods.write) return null;

    const response = await this.apiRequest<{
      deltas: Array<{ path: string; action: string; size?: number }>;
    }>("POST", this.vaultPath("/files/sync"), {
      lastSyncTimestamp: new Date(0).toISOString(),
      fileChecksums: {},
    });

    if (!response.success || !response.data) {
      throw new Error(response.error?.message ?? "Could not fetch the server vault inventory.");
    }

    const serverFiles: Array<{ path: string; size: number }> = [];
    const serverFolderPaths = new Set<string>();

    for (const delta of response.data.deltas) {
      if (delta.action === "deleted") continue;

      const normalizedPath = this.normalizeVaultPath(delta.path);
      if (!normalizedPath) continue;

      if (this.isFolderMarkerPath(normalizedPath)) {
        const folderPath = this.folderPathFromMarkerPath(normalizedPath);
        if (folderPath) serverFolderPaths.add(folderPath);
        continue;
      }

      for (const folderPath of this.parentFolderPathsFor(normalizedPath)) {
        serverFolderPaths.add(folderPath);
      }
      serverFiles.push({ path: normalizedPath, size: delta.size ?? 0 });
    }

    let downloadedFolders = 0;
    let failedFolders = 0;
    const foldersByDepth = [...serverFolderPaths].sort(
      (a, b) => a.split("/").length - b.split("/").length || a.localeCompare(b)
    );

    for (const folderPath of foldersByDepth) {
      if (this.isPathExcluded(folderPath)) continue;
      try {
        const created = await this.ensureLocalFolderPath(folderPath);
        if (created) downloadedFolders += 1;
      } catch (err) {
        failedFolders += 1;
        this.logError(`Remote repair: mkdir for "${folderPath}" failed`, err);
      }
    }

    let downloadedFiles = 0;
    let failedFiles = 0;
    for (const file of serverFiles) {
      if (this.isPathExcluded(file.path)) continue;
      if (await this.localPathExists(file.path)) continue;

      try {
        await this.applyRemoteChange(file);
        downloadedFiles += 1;
      } catch (err) {
        failedFiles += 1;
        this.logError(`Remote repair: download of "${file.path}" failed`, err);
      }
    }

    const totalChanges = downloadedFiles + downloadedFolders + failedFiles + failedFolders;
    if (totalChanges > 0) {
      const parts: string[] = [];
      if (downloadedFiles > 0) parts.push(`${downloadedFiles} files downloaded`);
      if (downloadedFolders > 0) parts.push(`${downloadedFolders} folders created`);
      if (failedFiles > 0) parts.push(`${failedFiles} files failed`);
      if (failedFolders > 0) parts.push(`${failedFolders} folders failed`);
      this.log(`VaultGuard Sync: Repaired missing remote items — ${parts.join(", ")}.`);
    }

    return {
      downloadedFiles,
      downloadedFolders,
      failedFiles,
      failedFolders,
    };
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
    const segments = this.normalizeVaultPath(path).split("/").filter(Boolean);
    segments.pop();

    const folders: string[] = [];
    let current = "";
    for (const segment of segments) {
      current = current ? `${current}/${segment}` : segment;
      folders.push(current);
    }
    return folders;
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
    const normalized = this.normalizeVaultPath(path);
    await this.ensureParentFoldersForPath(normalized);

    this.applyingRemoteWrite = true;
    try {
      const existing = this.app.vault.getAbstractFileByPath(normalized);
      if (existing instanceof TFile) {
        await this.app.vault.modify(existing, content);
        return;
      }

      try {
        await this.app.vault.create(normalized, content);
      } catch (err) {
        if (!this.originalAdapterMethods.write) throw err;
        // Fall back to direct adapter write — but route through the at-rest
        // helper so the on-disk bytes stay encrypted. Using the raw write
        // here is the bug that produced "Finder shows plaintext".
        await this.writePlainToDisk(normalized, content);
      }
    } finally {
      this.applyingRemoteWrite = false;
    }
  }

  /** True if `path` (no leading slash) ends in the folder-marker basename. */
  private isFolderMarkerPath(path: string): boolean {
    if (!path) return false;
    const segments = path.split("/").filter(Boolean);
    return segments.length > 0 && segments[segments.length - 1] === FOLDER_MARKER_NAME;
  }

  /** Strips the marker basename to recover the parent folder's vault-relative path. */
  private folderPathFromMarkerPath(markerPath: string): string {
    const segments = markerPath.split("/").filter(Boolean);
    segments.pop();
    return segments.join("/");
  }

  /**
   * Composes the marker file path the plugin writes to keep `folderPath`
   * alive on the server. Always normalised, never with a leading slash.
   * Throws if asked for the root marker — root is implicit and never marked.
   */
  private folderMarkerPath(folderPath: string): string {
    const normalized = this.normalizeVaultPath(folderPath);
    if (!normalized) {
      throw new Error("VaultGuard Sync: refused to plant a folder marker at the vault root.");
    }
    return `${normalized}/${FOLDER_MARKER_NAME}`;
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
    const manifest: Record<string, string> = {};
    const seen = new Set<string>();

    const addPath = (rawPath: string): void => {
      const normalized = this.normalizeVaultPath(rawPath);
      if (!normalized) return;
      if (this.isPathExcluded(normalized)) return;
      const key = `/${normalized}`;
      if (seen.has(key)) return;
      seen.add(key);
      manifest[key] = "";
    };

    for (const file of this.app.vault.getFiles()) {
      addPath(file.path);
    }

    // Folder markers are server-only sentinels; produce them from local
    // folders so the server doesn't see the marker as "deleted" just because
    // we didn't enumerate it.
    for (const folderPath of this.collectLocalFolderPaths()) {
      if (this.isPathExcluded(folderPath)) continue;
      try {
        addPath(this.folderMarkerPath(folderPath));
      } catch {
        // Root folder has no marker — skip silently.
      }
    }

    return manifest;
  }

  /**
   * Uploads a zero-byte folder marker for `folderPath`. Returns true when the
   * server accepted it, false when the user lacks write permission for that
   * path. Network failures throw and are caught by the caller.
   */
  private async uploadFolderMarker(folderPath: string): Promise<boolean> {
    if (!this.session || !this.settings.serverVaultId) return false;
    const normalized = this.normalizeVaultPath(folderPath);
    if (!normalized) return false;

    const permission = await this.getEffectivePermission(normalized);
    if (permission < PermissionLevel.WRITE) {
      this.log(`Folder marker: skipping "${normalized}" — no write permission.`);
      return false;
    }

    const markerPath = this.folderMarkerPath(normalized);
    // The server's required-field validator rejects empty strings, so we
    // can't send `content: ""` even though the marker is conceptually
    // zero-byte. Send a single newline as a placeholder — the body is only
    // ever read to verify the folder's existence, never displayed.
    const markerBody = "\n";
    const markerBase64 = this.bytesToBase64(new TextEncoder().encode(markerBody));
    const response = await this.apiRequest(
      "PUT",
      this.vaultPath(`/files/${encodeURIComponent(markerPath)}`),
      {
        content: markerBase64,
        contentType: "application/x-vaultguard-folder-marker",
        hash: await this.computeHash(markerBody),
      }
    );
    if (!response.success) {
      throw new Error(response.error?.message ?? `Folder marker upload for "${normalized}" failed.`);
    }
    return true;
  }

  /**
   * Removes the folder marker for `folderPath`. Silently ignores 404s — the
   * marker may have never been planted, which is harmless.
   */
  private async deleteFolderMarker(folderPath: string): Promise<void> {
    if (!this.session || !this.settings.serverVaultId) return;
    const normalized = this.normalizeVaultPath(folderPath);
    if (!normalized) return;

    const markerPath = this.folderMarkerPath(normalized);
    const response = await this.apiRequest(
      "DELETE",
      this.vaultPath(`/files/${encodeURIComponent(markerPath)}`)
    );
    if (!response.success && response.error?.statusCode !== 404) {
      this.logError(
        `Folder marker delete for "${normalized}" failed`,
        new Error(response.error?.message ?? "unknown")
      );
    }
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
    localManifest: Map<string, { content: string; hash: string }>
  ): Promise<void> {
    const normalizedPath = this.normalizeVaultPath(path);
    const entry = localManifest.get(path);

    switch (strategy) {
      case ConflictResolutionStrategy.KEEP_LOCAL: {
        if (!entry) return;
        await this.uploadReconciledFile(normalizedPath, entry.content);
        return;
      }
      case ConflictResolutionStrategy.KEEP_REMOTE: {
        await this.applyRemoteChange({ path: normalizedPath, size: 0 });
        return;
      }
      case ConflictResolutionStrategy.DUPLICATE:
      default: {
        // Save the local copy beside the original with a conflict suffix,
        // then bring the server copy to the original path. No data lost.
        if (entry && this.originalAdapterMethods.write) {
          const conflictPath = this.generateConflictPath(normalizedPath);
          await this.writeLocalFileFromRemote(conflictPath, entry.content);
        }
        await this.applyRemoteChange({ path: normalizedPath, size: 0 });
        return;
      }
    }
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
   * Wires window focus and document visibility events to trigger an
   * immediate sync when the user comes back to Obsidian. With pure
   * polling, multi-user changes only land on the next interval (10 s in
   * realtime mode, 60 s+ in periodic) — that's a long time to stare at
   * stale state. Debounced to avoid hammering the server when the OS
   * fires multiple focus events for one Cmd-Tab.
   */
  private registerFocusSyncHandlers(): void {
    const trigger = (): void => {
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
    };

    this.registerDomEvent(window, "focus", trigger);
    this.registerDomEvent(document, "visibilitychange", () => {
      if (document.visibilityState === "visible") {
        this.resumeSyncLoop("window visible");
        trigger();
      } else {
        this.pauseSyncLoop("window hidden");
      }
    });
    this.registerDomEvent(window, "online", () => {
      this.handleBrowserOnline();
    });
    this.registerDomEvent(window, "offline", () => {
      this.handleBrowserOffline();
    });
    this.log("Focus-sync handlers registered.");
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
    const { userInitiated = false, forceCatchup = false } = options;

    if (!this.session) {
      const message = userInitiated
        ? this.showLoginRequiredNotice("sync")
        : "VaultGuard Sync: Sync skipped — not logged in.";
      this.log(message);
      return;
    }
    if (!this.isOnline()) {
      const message = "VaultGuard Sync: Sync skipped — offline.";
      this.log(message);
      if (userInitiated) new Notice(message);
      return;
    }
    if (!this.settings.serverVaultId) {
      const message = "VaultGuard Sync: Sync skipped — this folder is not bound to a server vault yet.";
      this.log(message);
      if (userInitiated) new Notice(message);
      return;
    }

    if (this.syncState.status === "syncing") {
      const message = "VaultGuard Sync: A sync is already in progress.";
      this.log(message);
      if (userInitiated) new Notice(message);
      return;
    }

    if (userInitiated) {
      new Notice("VaultGuard Sync: Syncing…");
    }

    const canUploadEncryptedContent = this.hasValidKeyLease();
    if (!canUploadEncryptedContent) {
      this.log("Sync running in limited access mode — downloads only; encrypted uploads are paused until a key lease is available.");
      if (userInitiated) {
        new Notice("VaultGuard Sync: Limited access — downloading accessible server changes only.");
      }
    }

    let totalFilesUploaded = 0;
    let totalFoldersUploaded = 0;
    let totalFilesRemoved = 0;
    let totalFilesDownloaded = 0;
    let totalFoldersDownloaded = 0;
    let totalRepairFailures = 0;
    let deltaCount = 0;

    try {
      this.syncState.status = "syncing";
      this.updateStatusBar();

      // Phase 1: Upload queued offline operations
      const offlineQueueSizeBefore = this.offlineQueue.length;
      if (canUploadEncryptedContent) {
        await this.flushOfflineQueue();
      } else if (offlineQueueSizeBefore > 0) {
        this.log(
          `Sync: ${offlineQueueSizeBefore} queued operation(s) kept pending because no encryption key lease is available.`
        );
      }
      const flushedSomething = canUploadEncryptedContent && offlineQueueSizeBefore > 0;

      // Phase 1b: Catch up local-only files + folders. Auto-runs once per
      // plugin process to self-heal vaults whose first reconciliation never
      // landed; user-initiated syncs always force a re-run so subsequent
      // clicks aren't silent no-ops after the flag has been set.
      let catchupChanges = 0;
      if (canUploadEncryptedContent && (forceCatchup || !this.localOnlyCatchupCompleted)) {
        const result = await this.uploadLocalOnlyFiles();
        if (result) {
          totalFilesUploaded += result.uploadedFiles;
          totalFoldersUploaded += result.uploadedFolders;
          totalFilesRemoved += result.removedLocalFiles;
          catchupChanges = result.uploadedFiles + result.uploadedFolders + result.removedLocalFiles;
          this.localOnlyCatchupCompleted = true;
        }
      }

      // Phase 1c: Cursor short-circuit. Cheapest possible "is there anything
      // to do?" check — one DynamoDB GetItem on the server, tiny payload.
      // Skip the heavy `/files/sync` call entirely when:
      //   - we didn't push anything up (so server revision can't have moved
      //     because of us)
      //   - we have a previously observed revision to compare against
      //   - the user didn't ask for a force-catchup (which always runs the
      //     full repair pass to self-heal stranded items)
      const canShortCircuit =
        !flushedSomething &&
        catchupChanges === 0 &&
        !forceCatchup &&
        this.syncState.lastSeenRevision != null;

      if (canShortCircuit) {
        const cursor = await this.fetchSyncCursor();
        if (cursor) {
          // Always reflect the server's idea of "last change" so the
          // adaptive timer scales correctly even on hot/idle vaults that
          // never enter the full-sync branch.
          const cursorMs = Date.parse(cursor.lastChangedAt);
          if (Number.isFinite(cursorMs) && cursorMs > 0) {
            this.syncState.lastObservedActivityAt = cursorMs;
          }
          if (cursor.revision === this.syncState.lastSeenRevision) {
            this.syncState.status = "idle";
            this.syncState.lastError = null;
            this.syncState.pendingChanges = this.offlineQueue.length;
            this.log(
              `Sync skipped — cursor unchanged (revision ${cursor.revision}, last change ${cursor.lastChangedAt}).`
            );
            if (userInitiated) {
              new Notice("VaultGuard Sync: Already in sync — nothing to do.");
            }
            return;
          }
        }
        // Cursor differs (or fetch failed) — fall through to a full sync
        // and trust the server to tell us what changed.
      }

      // Phase 2: Fetch remote changes since last sync
      const response = await this.apiRequest<{
        deltas: Array<{
          path: string;
          action: "created" | "modified" | "deleted";
          lastModified: string;
          checksum: string;
          size: number;
        }>;
        syncTimestamp: string;
        revision?: number;
        mode?: string;
        permissionsChanged?: boolean;
      }>("POST", this.vaultPath('/files/sync'), {
        lastSyncTimestamp: this.syncState.lastSync ?? new Date(0).toISOString(),
        fileChecksums: this.buildLocalSyncManifest(),
      });

      if (!response.success || !response.data) {
        throw new Error(response.error?.message ?? "Sync request failed.");
      }

      // The server flips this true on the cold path when one or more
      // permission rules changed since `lastSyncTimestamp`. The local
      // permission cache could now be lying about file accessibility, so
      // wipe it — the next interceptedRead/Write will re-fetch from the
      // server and reflect the new rule set.
      if (response.data.permissionsChanged) {
        this.log("Sync: permission rules changed on the server — emitting bus event.");
        // Phase 9: single bus emit replaces the 5-call fan-out. Server-
        // confirmed because the sync delta carries an authoritative
        // permission-rules-changed signal from the server. The four init*
        // bus subscriptions handle the surface invalidations.
        this.permissionStore.emit("changed", { serverConfirmed: true });
      }

      deltaCount = response.data.deltas.length;

      for (const delta of response.data.deltas) {
        const normalizedPath = this.normalizeVaultPath(delta.path);

        // Local-only opt-out: ignore the server's view of excluded paths
        // entirely — neither create, modify, nor delete locally.
        if (this.isPathExcluded(normalizedPath)) {
          continue;
        }

        // Folder markers carry no content — mirror the folder locally if it
        // doesn't exist yet, but never try to download or write the marker
        // file itself.
        if (this.isFolderMarkerPath(normalizedPath)) {
          if (delta.action !== "deleted") {
            const folderPath = this.folderPathFromMarkerPath(normalizedPath);
            if (folderPath) {
              try {
                const created = await this.ensureLocalFolderPath(folderPath);
                if (created) totalFoldersDownloaded += 1;
              } catch (err) {
                // mkdir is idempotent in Obsidian; only log unexpected failures.
                this.log(`Sync: mkdir for "${folderPath}" no-op or failed: ${err}`);
              }
            }
          }
          continue;
        }

        if (delta.action === "deleted") {
          if (this.originalAdapterMethods.remove) {
            try {
              await this.originalAdapterMethods.remove(normalizedPath);
            } catch {
              // File may already be gone locally.
            }
          }
          continue;
        }

        await this.applyRemoteChange({
          path: normalizedPath,
          size: delta.size,
        });
      }

      // Phase 2b: repair missing server-side items that are older than our
      // lastSyncTimestamp. This is what makes Sync Now self-heal after an
      // earlier failed folder/file apply instead of becoming a silent no-op.
      if (forceCatchup || !this.remoteInventoryRepairCompleted) {
        const result = await this.repairMissingRemoteItems();
        if (result) {
          totalFilesDownloaded += result.downloadedFiles;
          totalFoldersDownloaded += result.downloadedFolders;
          totalRepairFailures += result.failedFiles + result.failedFolders;
          this.remoteInventoryRepairCompleted = totalRepairFailures === 0;
        }
      }

      this.syncState.lastSync = response.data.syncTimestamp;
      this.syncState.pendingChanges = this.offlineQueue.length;
      this.syncState.conflicts = [];
      this.syncState.status = "idle";
      this.syncState.lastError = null;
      // Capture the revision the server saw at the moment it built this
      // delta set so the next poll can short-circuit when nothing else
      // changes after this one.
      if (typeof response.data.revision === "number") {
        this.syncState.lastSeenRevision = response.data.revision;
      }
      if (deltaCount > 0) {
        this.syncState.lastObservedActivityAt = Date.now();
      }
      // Persist lastSync so a fresh process resumes deltas instead of
      // re-downloading the entire vault from epoch.
      if (this.settings.lastSyncTimestamp !== response.data.syncTimestamp) {
        this.settings.lastSyncTimestamp = response.data.syncTimestamp;
        void this.saveSettings().catch((err) =>
          this.logError("Failed to persist lastSyncTimestamp", err)
        );
      }

      if (userInitiated) {
        const summaryParts: string[] = [];
        if (totalFilesUploaded > 0) summaryParts.push(`${totalFilesUploaded} files uploaded`);
        if (totalFoldersUploaded > 0) summaryParts.push(`${totalFoldersUploaded} folders preserved`);
        if (totalFilesRemoved > 0) summaryParts.push(`${totalFilesRemoved} local-only files removed`);
        if (totalFilesDownloaded > 0) summaryParts.push(`${totalFilesDownloaded} files downloaded`);
        if (totalFoldersDownloaded > 0) summaryParts.push(`${totalFoldersDownloaded} folders created`);
        if (totalRepairFailures > 0) summaryParts.push(`${totalRepairFailures} repair failures`);
        if (deltaCount > 0) summaryParts.push(`${deltaCount} remote changes applied`);
        if (summaryParts.length === 0) {
          new Notice("VaultGuard Sync: Already in sync — nothing to do.");
        } else {
          new Notice(`VaultGuard Sync: Sync complete — ${summaryParts.join(", ")}.`);
        }
      }
    } catch (error) {
      this.syncState.status = "error";
      this.syncState.lastError =
        error instanceof Error ? error.message : "Unknown sync error";
      this.logError("Sync failed", error);

      if (userInitiated) {
        new Notice(
          `VaultGuard Sync: Sync failed — ${
            error instanceof Error ? error.message : "Unknown error"
          }`,
          10000
        );
      }

      if (this.isNetworkError(error)) {
        this.setConnectionStatus("offline");
      }
    } finally {
      this.updateStatusBar();
    }
  }

  /**
   * Applies a remote file change to the local vault.
   * @param metadata - The remote file metadata and change information
   */
  private async applyRemoteChange(metadata: Pick<FileMetadata, "path" | "size">): Promise<void> {
    const normalizedPath = this.normalizeVaultPath(metadata.path);
    // Local-only opt-out: never pull excluded paths down. Defence in depth
    // for callers that don't filter the delta list themselves.
    if (this.isPathExcluded(normalizedPath)) {
      this.log(`Sync: skipping excluded path "${normalizedPath}".`);
      return;
    }
    // Fetch and decrypt file content. Limited-access sessions lack the
    // client-side DEK, so `fetchRemoteFileContent` asks the server for a
    // permission-checked plaintext envelope instead.
    const response = await this.fetchRemoteFileContent(normalizedPath);

    if (!response.success || !response.data) {
      throw new Error(response.error?.message ?? `Failed to read ${normalizedPath} from the server.`);
    }

    if (!this.originalAdapterMethods.write) return;

    let decrypted: string;
    try {
      decrypted = await this.decodeRemoteFileContent(normalizedPath, response.data);
    } catch (decryptErr) {
      // Skip the file rather than aborting the whole sync pass — a single
      // undecryptable cloud blob (wrong-DEK upload, partial rotation) used
      // to crash sync wholesale. Local copy stays as it was.
      this.logError(
        `Sync: skipping "${normalizedPath}" — cloud copy could not be decrypted.`,
        decryptErr
      );
      this.notifyCloudDecryptFallback(normalizedPath);
      return;
    }
    await this.writeLocalFileFromRemote(normalizedPath, decrypted);
    this.syncState.bytesDownloaded += metadata.size ?? 0;
  }

  /**
   * Handles a sync conflict according to the configured resolution strategy.
   * @param conflict - The detected sync conflict
   */
  private async handleConflict(conflict: SyncConflict): Promise<void> {
    const strategy = this.settings.defaultConflictResolution;
    await this.emitAuditEvent("sync.conflict", conflict.path, {
      strategy,
      localHash: conflict.localHash,
      remoteHash: conflict.remoteHash,
    });

    switch (strategy) {
      case ConflictResolutionStrategy.KEEP_LOCAL: {
        // Re-upload local version
        const localContent = await this.readPlainFromDisk(conflict.path);
        const encrypted = await this.encryptContent(localContent);
        await this.apiRequest("PUT", this.vaultPath(`/files/${encodeURIComponent(conflict.path)}`), {
          content: encrypted,
          hash: await this.computeHash(localContent),
          forceOverwrite: true,
        });
        conflict.resolution = ConflictResolutionStrategy.KEEP_LOCAL;
        break;
      }

      case ConflictResolutionStrategy.KEEP_REMOTE:
        // Download remote version
        await this.applyRemoteChange({
          path: conflict.path,
          size: 0,
        });
        conflict.resolution = ConflictResolutionStrategy.KEEP_REMOTE;
        break;

      case ConflictResolutionStrategy.DUPLICATE: {
        // Create a conflict copy
        const conflictPath = this.generateConflictPath(conflict.path);
        const localContent = await this.readPlainFromDisk(conflict.path);
        await this.writePlainToDisk(conflictPath, localContent);
        // Then apply remote to original path
        await this.applyRemoteChange({
          path: conflict.path,
          size: 0,
        });
        conflict.resolution = ConflictResolutionStrategy.DUPLICATE;
        break;
      }

      case ConflictResolutionStrategy.ASK_USER:
      default:
        // Leave unresolved for user to handle via UI
        new Notice(
          `VaultGuard Sync: Sync conflict detected for "${conflict.path}". Use View Permissions to resolve.`
        );
        break;
    }
  }

  /**
   * Generates a conflict-suffixed file path for duplicate resolution.
   * @param originalPath - The original conflicted file path
   * @returns A new path with conflict timestamp suffix
   */
  private generateConflictPath(originalPath: string): string {
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const lastDot = originalPath.lastIndexOf(".");
    if (lastDot > 0) {
      return `${originalPath.slice(0, lastDot)} (conflict ${timestamp})${originalPath.slice(lastDot)}`;
    }
    return `${originalPath} (conflict ${timestamp})`;
  }

  /**
   * Fetches the current vault sync cursor from the server. Returns null on
   * failure — callers should treat null as "I don't know whether anything
   * changed" and fall through to a full sync rather than skipping.
   */
  private async fetchSyncCursor(): Promise<{ revision: number; lastChangedAt: string } | null> {
    if (!this.session || !this.settings.serverVaultId) return null;
    try {
      const response = await this.apiRequest<{
        revision: number;
        lastChangedAt: string;
        serverTime: string;
      }>("GET", this.vaultPath("/sync-cursor"));
      if (!response.success || !response.data) return null;
      return {
        revision: response.data.revision,
        lastChangedAt: response.data.lastChangedAt,
      };
    } catch (err) {
      this.logError("Sync cursor fetch failed", err);
      return null;
    }
  }

  private hasValidKeyLease(): boolean {
    return !!this.keyLease && !this.isKeyLeaseExpired();
  }

  /**
   * Fetch a file's plaintext via the server-side decrypt endpoint
   * (GET /vaults/{vaultId}/files-decrypted/{path}). Used by the limited-
   * access read path (Phase 8) when the caller cannot receive a vault-wide
   * `/**` key lease. The server gates the route with requireVaultMember +
   * evaluatePermission; 404 on deny (per docs/SHARE-LINKS.md trust pattern).
   */
  private async readFileDecrypted(relPath: string): Promise<ApiResponse<RemoteFileContentResponse>> {
    const normalizedPath = this.normalizeVaultPath(relPath);
    const encoded = normalizedPath
      .split("/")
      .map((segment) => encodeURIComponent(segment))
      .join("/");
    return this.apiRequest<RemoteFileContentResponse>(
      "GET",
      this.vaultPath(`/files-decrypted/${encoded}`)
    );
  }

  private async fetchRemoteFileContent(path: string): Promise<ApiResponse<RemoteFileContentResponse>> {
    const normalizedPath = this.normalizeVaultPath(path);
    const serverDecrypt = !this.hasValidKeyLease();
    if (serverDecrypt) {
      // Limited-access (no /** lease) — server-side decrypt sibling endpoint
      // (Phase 8, plan 08-01). The legacy decrypt-query URL is removed from
      // this caller; plan 08-04 deletes the Lambda branch.
      return this.readFileDecrypted(normalizedPath);
    }
    // Full-access — fetch ciphertext, plugin decrypts via its own DEK.
    return this.apiRequest<RemoteFileContentResponse>(
      "GET",
      this.vaultPath(`/files/${encodeURIComponent(normalizedPath)}`)
    );
  }

  private decodeBase64Utf8(base64: string): string {
    return new TextDecoder().decode(this.base64ToBytes(base64));
  }

  private remoteDecryptError(path: string, error: unknown): Error {
    const message = error instanceof Error ? error.message : String(error);
    const wrapped = new Error(
      `VaultGuard Sync: could not decrypt server copy of "${path}": ${message}`
    );
    wrapped.name = "VaultGuardRemoteDecryptError";
    return wrapped;
  }

  private async decodeRemoteFileContent(
    path: string,
    data: RemoteFileContentResponse
  ): Promise<string> {
    const normalizedPath = this.normalizeVaultPath(path);
    if (data.decrypted === true) {
      return this.decodeBase64Utf8(data.content);
    }

    if (!this.hasValidKeyLease()) {
      throw this.remoteDecryptError(
        normalizedPath,
        new Error("server returned encrypted bytes and no valid key lease is available")
      );
    }

    try {
      return await this.decryptContent(data.content);
    } catch (error) {
      throw this.remoteDecryptError(normalizedPath, error);
    }
  }

  private async readRemotePlaintext(path: string): Promise<string> {
    const normalizedPath = this.normalizeVaultPath(path);
    const response = await this.fetchRemoteFileContent(normalizedPath);
    if (!response.success || !response.data) {
      throw new Error(response.error?.message ?? `Failed to read ${normalizedPath} from the server.`);
    }
    return this.decodeRemoteFileContent(normalizedPath, response.data);
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
    const baseline = Math.max(this.getEffectiveSyncIntervalSeconds(), MIN_SYNC_INTERVAL) * 1000;
    const lastActivity = this.syncState.lastObservedActivityAt;
    if (lastActivity == null) return baseline;

    const idleMs = Math.max(0, Date.now() - lastActivity);
    if (idleMs < 60_000) return baseline;
    if (idleMs < 5 * 60_000) return baseline;
    if (idleMs < 30 * 60_000) return Math.min(baseline * 2, 2 * 60_000);
    return Math.min(baseline * 4, 5 * 60_000);
  }

  /** Starts (or reschedules) the adaptive sync loop. */
  private startSyncTimer(): void {
    this.stopSyncTimer();
    const syncMode = this.getEffectiveSyncMode();
    if (syncMode === "manual") {
      this.log("Sync timer disabled by organization manual-sync policy.");
      return;
    }
    if (this.syncTimerPaused) {
      this.log("Sync timer kept paused (window hidden / offline).");
      return;
    }

    const delay = this.computeNextSyncDelayMs();
    this.syncTimer = setTimeout(() => {
      this.syncTimer = null;
      // Don't fire a new sync on top of an in-flight one; just reschedule.
      if (this.syncState.status !== "syncing") {
        void this.performSync().catch((err) =>
          this.logError("Periodic sync failed", err)
        );
      }
      // Always chain the next tick — performSync is fire-and-forget here.
      this.startSyncTimer();
    }, delay);

    this.log(`Sync timer scheduled in ${Math.round(delay / 1000)}s (mode: ${syncMode}).`);
  }

  /** Cancels the next scheduled sync, if any. */
  private stopSyncTimer(): void {
    if (this.syncTimer) {
      clearTimeout(this.syncTimer);
      this.syncTimer = null;
    }
  }

  /** Restarts the sync loop (call when settings, mode, or session change). */
  restartSyncTimer(): void {
    if (this.session) {
      this.startSyncTimer();
    }
  }

  /**
   * Pauses the sync loop. Call when the window goes hidden or the client
   * goes offline. Pending timers are cleared and the loop stops scheduling
   * itself until `resumeSyncLoop` is called.
   */
  private pauseSyncLoop(reason: string): void {
    if (this.syncTimerPaused) return;
    this.syncTimerPaused = true;
    this.stopSyncTimer();
    this.log(`Sync loop paused (${reason}).`);
  }

  /**
   * Resumes the sync loop after `pauseSyncLoop`. Triggers an immediate
   * sync on resume so the user doesn't have to wait one full interval to
   * see other peers' changes after returning to the window.
   */
  private resumeSyncLoop(reason: string): void {
    if (!this.syncTimerPaused) return;
    this.syncTimerPaused = false;
    this.log(`Sync loop resumed (${reason}).`);
    if (!this.session || !this.settings.serverVaultId) return;
    void this.performSync().catch((err) =>
      this.logError("Resume-triggered sync failed", err)
    );
    this.startSyncTimer();
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
      this.log(`Vault-scoped key lease denied (limited access): status=${statusCode}, message=${message}`);
      this.notifyLimitedAccess(message);
      return "limited";
    }

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
   * One-shot self-healing walk over the on-disk vault. Adds every file whose
   * size is exactly 36 bytes AND whose first 4 bytes equal the VG1 magic
   * header [0x56, 0x47, 0x31, 0x00] to placeholderPaths. Handles mid-session
   * plugin reloads where placeholderPaths was lost from memory but on-disk
   * placeholders remain (D-09 keeps the set in-memory only).
   *
   * Bounded by MAX_SWEEP_ENTRIES (5000). Walks via originalAdapterMethods.list
   * (the raw, ciphertext-aware listing) because we are deliberately inspecting
   * the on-disk envelope shape, NOT reading plaintext. The 4-byte magic-header
   * read via originalAdapterMethods.readBinary is a documented exception to
   * the at-rest rule (CLAUDE.md Local At-Rest Rule): we are inspecting
   * ciphertext envelope bytes, not surfacing plaintext to disk.
   */
  private async sweepPlaceholderPaths(): Promise<void> {
    const adapter = this.app.vault.adapter;
    const rawList = this.originalAdapterMethods.list;
    const rawReadBinary = this.originalAdapterMethods.readBinary;
    if (!rawList || !rawReadBinary) return;
    let scanned = 0;
    let aborted = false;
    const queue: string[] = ["/"];
    while (queue.length > 0 && !aborted) {
      const dir = queue.shift()!;
      let listing: { files: string[]; folders: string[] };
      try {
        listing = await rawList(dir);
      } catch {
        continue;
      }
      for (const subdir of listing.folders) {
        if (this.isPathExcluded(subdir)) continue;
        queue.push(subdir);
      }
      for (const filePath of listing.files) {
        scanned++;
        if (scanned > MAX_SWEEP_ENTRIES) {
          aborted = true;
          break;
        }
        if (this.isPathExcluded(filePath)) continue;
        try {
          const stat = await adapter.stat(filePath);
          if (!stat || stat.size !== 36) continue;
          // Magic-byte verification (RESEARCH Q3 RESOLVED — not size-only).
          // Read first 4 bytes via the RAW binary method since we are
          // inspecting the ciphertext envelope, not the plaintext payload.
          const buf = await rawReadBinary(filePath);
          const view = new Uint8Array(buf, 0, 4);
          if (view[0] === 0x56 && view[1] === 0x47 && view[2] === 0x31 && view[3] === 0x00) {
            this.placeholderPaths.add(filePath);
          }
        } catch {
          // ignore individual file errors
        }
      }
    }
    if (aborted) {
      console.warn(
        `[VaultGuard] sweepPlaceholderPaths: aborting at ${MAX_SWEEP_ENTRIES} entries; placeholderPaths.size=${this.placeholderPaths.size}`
      );
    }
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
    this.stopHeartbeatMonitor();
    if (!this.session) return;

    this.heartbeatTimer = setInterval(
      () => void this.checkRevocationHeartbeat(),
      HEARTBEAT_INTERVAL_MS
    );
    void this.checkRevocationHeartbeat();
  }

  private stopHeartbeatMonitor(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  private async checkRevocationHeartbeat(): Promise<void> {
    if (!this.session) return;

    const params = new URLSearchParams({ sessionId: this.session.sessionId });
    const response = await this.apiRequest<{ active: boolean; reason?: string }>(
      "GET",
      `/auth/heartbeat?${params.toString()}`
    );

    if (response.success) {
      if (response.data && response.data.active === false) {
        await this.handleServerRevocation(response.data.reason ?? "revoked");
      }
      return;
    }

    const status = response.error?.statusCode ?? 0;
    if (status === 401 || status === 403) {
      await this.handleServerRevocation(response.error?.message ?? "revoked");
    }
  }

  private async handleServerRevocation(reason: string): Promise<void> {
    this.keyLease = null;
    // Phase 9: SILENT — forceLogout below broadcasts the wildcard 'changed'
    // (collapsed in Task 3 of plan 09-02). A broadcast here would double-fire.
    this.permissionStore.invalidate();
    await this.forceLogout(`VaultGuard Sync: Access revoked (${reason}). Local session cleared.`);
  }

  /**
   * Starts the periodic key lease renewal monitor.
   * Checks every minute if the lease needs renewal.
   */
  private startKeyRenewalMonitor(): void {
    this.stopKeyRenewalMonitor();
    this.keyRenewalTimer = setInterval(
      () => this.checkKeyLeaseRenewal(),
      60 * 1000
    );
  }

  /**
   * Stops the key lease renewal monitor.
   */
  private stopKeyRenewalMonitor(): void {
    if (this.keyRenewalTimer) {
      clearInterval(this.keyRenewalTimer);
      this.keyRenewalTimer = null;
    }
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
    if (!this.session) {
      return;
    }

    if (!this.keyLease) {
      // Limited-access recovery path. Only retry when the previous attempt
      // explicitly returned 403 — otherwise we'd hammer the API with lease
      // requests for sessions that legitimately have no vault binding yet.
      if (this.vaultLeaseDenied && this.settings.serverVaultId) {
        try {
          const result = await this.ensureVaultScopedKeyLease();
          if (result === "ok") {
            this.log("Vault-scoped key lease recovered — full access restored.");
            new Notice("VaultGuard Sync: Full vault access restored.");
            // Phase 9: BROADCAST — permission rules may have widened (per
            // pre-existing comment). Surfaces must refresh, otherwise post-
            // recovery views show stale deny-state visuals. The four init*
            // bus subscriptions invoke readOnlyGuard / fileExplorer /
            // sidebar / header invalidations. The explicit fan-out lines
            // that lived here are removed in Task 3 of plan 09-02.
            this.permissionStore.emit("changed", { serverConfirmed: true });
            // Phase-8: clear the in-memory placeholder set so subsequent reads
            // go through the normal readPlainFromDisk path (the on-disk VG1
            // bytes are still placeholders until the next reconcile writes
            // real content; that's the existing sync engine's job once the
            // lease is back).
            this.placeholderPaths.clear();
          }
        } catch (err) {
          // Network blips and 5xxs are expected during recovery polling.
          // Stay in limited-access state and try again next tick.
          this.logError("Limited-access lease retry failed (will retry)", err);
        }
      }
      return;
    }

    const expiresAt = new Date(this.keyLease.expiresAt).getTime();
    const now = Date.now();
    const timeUntilExpiry = expiresAt - now;

    if (timeUntilExpiry <= KEY_RENEWAL_GRACE_MS) {
      await this.renewKeyLease();
    }
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
    if (!this.keyLease) {
      return true;
    }
    return new Date(this.keyLease.expiresAt).getTime() < Date.now();
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
        this.notifyConnectionLost();
      }
    }

    this.updateStatusBar();
  }

  private notifyConnectionLost(): void {
    const now = Date.now();
    if (
      this.lastConnectionLostNoticeAt !== null &&
      now - this.lastConnectionLostNoticeAt < CONNECTION_LOST_NOTICE_THROTTLE_MS
    ) {
      return;
    }

    this.lastConnectionLostNoticeAt = now;
    new Notice("VaultGuard Sync: Connection lost. Working offline with cached data.");
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
    data?: string
  ): void {
    // Deduplicate: remove existing operations for the same path
    this.offlineQueue = this.offlineQueue.filter((op) => op.path !== path);

    this.offlineQueue.push({
      operation,
      path,
      data,
      timestamp: new Date().toISOString(),
    });

    this.log(
      `Queued offline operation: ${operation} "${path}" (queue size: ${this.offlineQueue.length})`
    );
  }

  /**
   * Flushes all queued offline operations to the server.
   * Operations are sent in chronological order.
   */
  private async flushOfflineQueue(): Promise<void> {
    if (this.offlineQueueFlushPromise) {
      return this.offlineQueueFlushPromise;
    }

    const flushPromise = this.runOfflineQueueFlush();
    this.offlineQueueFlushPromise = flushPromise;

    try {
      await flushPromise;
    } finally {
      if (this.offlineQueueFlushPromise === flushPromise) {
        this.offlineQueueFlushPromise = null;
      }
    }
  }

  private async runOfflineQueueFlush(): Promise<void> {
    if (this.offlineQueue.length === 0) {
      return;
    }

    this.log(`Flushing ${this.offlineQueue.length} queued operations...`);
    const queue = [...this.offlineQueue];
    this.offlineQueue = [];

    for (let index = 0; index < queue.length; index++) {
      const op = queue[index];
      // Local-only opt-out: drop any queued op whose path the user has
      // since added to the exclusion list, so we don't quietly upload it.
      if (this.isPathExcluded(op.path)) {
        continue;
      }
      try {
        switch (op.operation) {
          case "write":
            if (op.data) {
              const encrypted = await this.encryptContent(op.data);
              const response = await this.apiRequest("PUT", this.vaultPath(`/files/${encodeURIComponent(op.path)}`), {
                content: encrypted,
                hash: await this.computeHash(op.data),
              });
              this.assertOfflineFlushResponse(response, op);
            }
            break;
          case "delete": {
            const response = await this.apiRequest(
              "DELETE",
              this.vaultPath(`/files/${encodeURIComponent(op.path)}`)
            );
            this.assertOfflineFlushResponse(response, op);
            break;
          }
        }
      } catch (error) {
        // Re-queue this operation and everything after it to preserve order.
        this.offlineQueue.push(op, ...queue.slice(index + 1));
        this.logError(`Failed to flush operation: ${op.operation} "${op.path}"`, error);
        if (this.isNetworkError(error)) {
          this.setConnectionStatus("offline");
        }
        break;
      }
    }

    if (this.offlineQueue.length > 0) {
      this.log(
        `${this.offlineQueue.length} operations remain in queue after flush.`
      );
    }
  }

  private assertOfflineFlushResponse(
    response: ApiResponse<unknown>,
    op: { operation: "write" | "delete"; path: string }
  ): void {
    if (response.success) {
      return;
    }

    const status = response.error?.statusCode ?? 0;
    if (op.operation === "delete" && status === 404) {
      return;
    }

    const message = response.error?.message ?? "Offline operation failed.";
    if (status === 401 || status === 403) {
      this.logError(
        `Dropping queued ${op.operation} for "${op.path}" after server rejection`,
        new Error(message)
      );
      return;
    }

    throw new Error(message);
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
    idTokenOverride?: string
  ): Promise<ApiResponse<T>> {
    if (!idTokenOverride && this.session) {
      if (this.isSessionTokenExpiring(this.session)) {
        const refreshResult = await this.refreshAccessToken(this.session);
        if (!refreshResult.ok) {
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
    const baseUrl = await this.getResolvedApiEndpoint(idToken);
    const url = `${baseUrl}${endpoint}`;
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

    for (let attempt = 0; attempt < this.settings.maxRetryAttempts; attempt++) {
      try {
        const response = await this.requestWithTimeout(
          requestUrl({
            url,
            method,
            headers,
            body: body ? JSON.stringify(body) : undefined,
            contentType: body ? "application/json" : undefined,
            throw: false,
          })
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

        // Non-retryable errors
        if (response.status === 401 || response.status === 403) {
          return {
            success: false,
            data: null,
            error: {
              code: (data as Record<string, unknown> | null)?.code as string ?? "AUTH_ERROR",
              message: (data as Record<string, unknown> | null)?.message as string ?? "Authentication failed",
              details: ((data as Record<string, unknown> | null)?.details as Record<string, unknown> | null) ?? null,
              statusCode: response.status,
            },
            requestId: this.getHeaderValue(response.headers, "x-request-id") ?? "",
          };
        }

        lastError = new Error(`HTTP ${response.status}: ${(data as Record<string, unknown> | null)?.message ?? "Request failed"}`);
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

  private describeNetworkFailureResponse(response: RequestUrlResponse): string {
    const text = (response.text ?? "").trim();
    if (text.length > 0) {
      return text;
    }

    return "Network request failed with status 0.";
  }

  private async requestWithTimeout<T>(promise: Promise<T>): Promise<T> {
    let timeoutId: ReturnType<typeof setTimeout> | null = null;

    try {
      return await Promise.race([
        promise,
        new Promise<T>((_, reject) => {
          timeoutId = setTimeout(() => {
            reject(new Error("Request timeout"));
          }, 30_000);
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
    if (!this.apiClient) return;

    this.filePermissionHeader = new FilePermissionHeader({
      app: this.app,
      apiClient: this.apiClient,
      currentUserId: this.session?.userId ?? "",
      currentUserEmail: this.session?.email ?? "",
      // Use the effective UI role (org admin/owner > vault membership role >
      // org role). Without this, an org "member" who is a vault "admin"
      // would see read-only affordances.
      currentUserRole: this.getEffectiveUiRole(),
      isAdmin: this.isEffectiveAdmin(),
      // Mirrors the backend OrgSettings.allowAdminPerFileRestrictions
      // toggle so the per-file dropdown for vault admins/org owners
      // becomes editable when the org opted in. Refreshed via
      // applyOrgSettings() on every lease/session response that carries
      // org settings.
      allowAdminPerFileRestrictions:
        this.orgSettings?.allowAdminPerFileRestrictions === true,
      // Resolve the current user's level through the same PermissionStore the
      // sidebar, file-explorer dots, and read-only guard use. The store owns
      // the warm-up cache that recognises file-specific grants (matched by
      // canonical id, email, or role) and is invalidated on the permission bus,
      // so it stays in lockstep with those surfaces. The earlier live-only
      // `/permissions/check` probe diverged from them: the store matches grants
      // by email (case-insensitively) and by session roles, while the backend
      // self-check queries the userId index by exact value and collapses the
      // caller to their vault-membership role — so an elevated grant the store
      // honoured showed in the sidebar but the header fell back to inherited READ.
      getPermissionLevel: (path) => this.getEffectivePermission(path),
      // Propagate header-side rule edits (manage panel, popover dropdown)
      // to the rest of the UI so file-explorer dots and the read-only
      // editor guard refresh in lockstep — without this, only the header
      // re-renders while the sidebar still shows stale colors. Full
      // invalidation is the safe choice: deleting a glob rule (e.g. the
      // /** default-member rule) can affect every file, so per-path
      // invalidation here would leave neighboring files miscolored.
      onRulesChanged: () => {
        // Phase 9: single bus emit replaces the 4-call fan-out. The four
        // init* bus subscriptions handle the surface invalidations.
        this.permissionStore.emit("changed", { serverConfirmed: true });
      },
    });

    // Update header whenever the user switches files
    this.registerEvent(
      this.app.workspace.on("active-leaf-change", () => {
        this.filePermissionHeader?.update();
      })
    );

    // Also update on file-open (covers same-leaf file changes)
    this.registerEvent(
      this.app.workspace.on("file-open", () => {
        this.filePermissionHeader?.update();
      })
    );

    // Phase 9: subscribe to the unified permission bus. One emit fans out
    // here + to fileExplorerDecorations + sidebar + readOnlyGuard.
    this.registerEvent(
      this.permissionStore.on("changed", (...args: unknown[]) => {
        const payload = (args[0] as { path?: string } | undefined) ?? {};
        this.filePermissionHeader?.invalidateCache(payload.path);
        void this.filePermissionHeader?.update();
      })
    );

    // Wave 2 Fix 2 (1.0.31): also subscribe to the lifecycle-only
    // `state-changed` event so the header re-renders when the store
    // flips between cold / warming / fetch-failed / warmed. Without
    // this, a fetch-failed → warmed transition (the typical recovery
    // after Fix 1's post-refresh re-warm) would leave the header
    // showing whatever data it last loaded from the per-file probe
    // path until the next file open. `state-changed` is intentionally
    // wildcard — we invalidate the whole ruleCache so every visible
    // surface re-renders with the warmed authoritative data.
    this.registerEvent(
      this.permissionStore.on("state-changed", () => {
        this.filePermissionHeader?.invalidateCache();
        void this.filePermissionHeader?.update();
      })
    );

    // Initial render if a file is already open
    this.filePermissionHeader.update();
  }

  /**
   * Initializes the read-only editor guard. When the active markdown view
   * targets a file the user lacks WRITE on, the CodeMirror editor is locked
   * via a Compartment so keystrokes never produce changes that would later
   * fail at save time. Re-applied on file-open / active-leaf-change, and
   * `refreshAll()` is called when the permission cache is invalidated.
   */
  private initReadOnlyGuard(): void {
    this.readOnlyGuard = new ReadOnlyGuard({
      app: this.app,
      plugin: this,
      getPermissionLevel: (path) => this.getEffectivePermission(path),
      isLoggedIn: () => this.session !== null,
    });
    this.readOnlyGuard.start();

    // Phase 9: subscribe to the unified permission bus. readOnlyGuard
    // doesn't take a path — it refreshes the active leaf's lock state.
    this.registerEvent(
      this.permissionStore.on("changed", () => {
        this.readOnlyGuard?.refreshAll();
      })
    );
  }

  // ─────────────────────────────────────────────────────────────────────────
  // File Explorer Decorations
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Initializes file explorer decorations that show permission level dots,
   * sharing indicators, and mini avatar stacks on the native file explorer items.
   */
  private initFileExplorerDecorations(): void {
    if (!this.apiClient) return;

    this.fileExplorerDecorations = new FileExplorerDecorations({
      app: this.app,
      apiClient: this.apiClient,
      currentUserId: this.session?.userId ?? "",
      // Effective role so file-explorer badges reflect per-vault permissions
      // rather than the user's flat org role.
      currentUserRole: this.getEffectiveUiRole(),
      isReady: () => this.isFileExplorerDecorationDataReady(),
      getPermissionLevel: (path) => this.getEffectivePermission(path),
    });

    // Delay to let the file explorer render first on startup. The state sync
    // also checks auth + vault binding, so first-run/no-session startups do
    // not fire unauthenticated permission requests.
    setTimeout(() => {
      this.syncFileExplorerDecorationsState();
    }, 1000);

    // Phase 9: subscribe to the unified permission bus. Per-path payload
    // scopes the invalidation; wildcard payload (no path) re-renders all.
    this.registerEvent(
      this.permissionStore.on("changed", (...args: unknown[]) => {
        const payload = (args[0] as { path?: string } | undefined) ?? {};
        this.fileExplorerDecorations?.invalidate(payload.path);
      })
    );

    // Re-run decoration when the file explorer becomes visible. On mobile the
    // explorer lives in a collapsed drawer whose view is deferred until shown,
    // so the startup pass finds no items; opening the drawer fires these events
    // and re-attaches the observer to the now-live container. Harmless on
    // desktop where the explorer is already mounted.
    this.registerEvent(
      this.app.workspace.on("layout-change", () => {
        this.syncFileExplorerDecorationsState();
      })
    );
    this.registerEvent(
      this.app.workspace.on("active-leaf-change", () => {
        this.syncFileExplorerDecorationsState();
      })
    );
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
    const leaves = this.app.workspace.getLeavesOfType(VAULTGUARD_VIEW_TYPE);
    for (const leaf of leaves) {
      const view = leaf.view as VaultGuardSidebarView | undefined;
      if (view?.reload) {
        void view.reload();
      }
    }
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
      | (Partial<Pick<FileExplorerDecorations, "enable" | "disable" | "refresh">>)
      | null;
    if (!decorations) return;

    if (this.settings.showPermissionIndicators && this.isFileExplorerDecorationDataReady()) {
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
    const existing = this.app.workspace.getLeavesOfType(VAULTGUARD_VIEW_TYPE);
    if (existing.length > 0) return; // already open

    const leaf = this.app.workspace.getRightLeaf(false);
    if (leaf) {
      await leaf.setViewState({
        type: VAULTGUARD_VIEW_TYPE,
        active: true,
      });
    }
  }

  /**
   * Opens (or reveals) the VaultGuard Files sidebar panel and reloads data.
   */
  private async activateVaultGuardSidebar(): Promise<void> {
    // Update config from current session
    const sidebarConfig = this.createSidebarViewConfig();
    if (sidebarConfig) {
      this.sidebarViewConfig = sidebarConfig;
    }

    const existing = this.app.workspace.getLeavesOfType(VAULTGUARD_VIEW_TYPE);
    if (existing.length > 0) {
      this.app.workspace.revealLeaf(existing[0]);
      const view = existing[0].view as VaultGuardSidebarView;
      if (this.sidebarViewConfig) {
        view.configure(this.sidebarViewConfig);
      }
      await view.reload();
      return;
    }

    // Create new leaf in the right sidebar
    const leaf = this.app.workspace.getRightLeaf(false);
    if (leaf) {
      await leaf.setViewState({
        type: VAULTGUARD_VIEW_TYPE,
        active: true,
      });
      this.app.workspace.revealLeaf(leaf);

      const view = leaf.view as VaultGuardSidebarView;
      if (view?.configure && this.sidebarViewConfig) {
        view.configure(this.sidebarViewConfig);
        await view.reload();
      }
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // UI Methods
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Updates the status bar with current auth and connection state.
   */
  private updateStatusBar(): void {
    if (!this.statusBarEl) {
      return;
    }

    if (!this.session) {
      this.statusBarEl.setText("VaultGuard Sync: Not logged in");
      return;
    }

    if (this.permissionWarmupInFlight > 0) {
      this.statusBarEl.setText("VaultGuard Sync ↻ Loading permissions...");
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
   * Refreshes file explorer decorations (permission indicators).
   * Called when the showPermissionIndicators setting changes.
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
  showPermissionRulesModal(): void {
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
      this.createAdminModalContext()
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

  private createAdminModalContext() {
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
      onPermissionsChanged: () => this.notifyPermissionRulesChanged(),
    };
  }

  /**
   * Shows the admin panel for managing users and permissions.
   * Only accessible to users with admin or owner roles.
   */
  private showAdminPanel(): void {
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
  private showPathPermissionsModal(path: string, isFolder: boolean): void {
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
      onRulesChanged: () => {
        // Phase 9: full invalidation via the bus. Rules edited from the
        // modal can include glob patterns (e.g. deleting an inherited
        // `/docs/**` rule from this file's panel), so per-path invalidation
        // would leave sibling files showing stale colors. The four init*
        // bus subscriptions handle the surface invalidations.
        this.permissionStore.emit("changed", { serverConfirmed: true });
      },
    });
    modal.open();
  }

  /**
   * Opens the permission rule dialog pre-filled with a specific path.
   * Appends a trailing slash for folders so the rule applies recursively.
   */
  private showAddPermissionForPath(path: string, isFolder: boolean): void {
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
    this.orgSettings = null;
    this.vaultMemberRole = null;
    this.stopKeyRenewalMonitor();
    this.stopHeartbeatMonitor();
    this.stopAutoLockTimer();
    // Phase 9: SILENT — teardown path; no subscribers to notify.
    this.permissionStore.invalidate();
    this.offlineQueue = [];
    this.log("Sensitive data cleared from memory.");
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Storage Helpers
  // ─────────────────────────────────────────────────────────────────────────

  /** localStorage key prefix for per-vault session persistence. */
  private static readonly SESSION_STORAGE_KEY_PREFIX = "vaultguard-session:";

  private buildPluginData(): VaultGuardPluginData {
    return {
      ...this.settings,
      storedSessions: this.persistedSessions,
    };
  }

  private async savePluginData(): Promise<void> {
    const saveOperation = this.pluginDataSaveQueue
      .catch(() => undefined)
      .then(async () => {
        await this.saveData(this.buildPluginData());
      });

    this.pluginDataSaveQueue = saveOperation;
    await saveOperation;
  }

  private static generateVaultBindingId(): string {
    if (typeof crypto.randomUUID === "function") {
      return crypto.randomUUID();
    }

    const bytes = crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = Array.from(bytes, (byte) =>
      byte.toString(16).padStart(2, "0")
    );

    return [
      hex.slice(0, 4).join(""),
      hex.slice(4, 6).join(""),
      hex.slice(6, 8).join(""),
      hex.slice(8, 10).join(""),
      hex.slice(10, 16).join(""),
    ].join("-");
  }

  /**
   * Derives a stable, vault-unique binding ID from runtime identifiers.
   *
   * Preference order:
   *   1. Filesystem base path of the vault (desktop). Two distinct vaults
   *      cannot share a directory, so this is collision-free even when a
   *      vault folder is duplicated — the copy lives at a different path.
   *   2. Obsidian's `app.appId` (set per-vault by Obsidian itself).
   *   3. Vault display name.
   *
   * All available identifiers are concatenated and hashed so the resulting
   * key is fixed-length, opaque, and never leaks the user's filesystem path
   * into localStorage. If none are available we fall back to a random UUID
   * stored in `data.json`; that keeps non-standard/test hosts working, but
   * desktop Obsidian should always provide a runtime fingerprint.
   */
  private async computeDerivedVaultBindingId(): Promise<string> {
    const vault = (this.app as unknown as {
      vault?: {
        adapter?: Partial<{
          getBasePath: () => string;
          basePath: string;
        }>;
        getName?: () => string;
      };
    } | undefined)?.vault;
    const adapter = vault?.adapter as Partial<{
      getBasePath: () => string;
      basePath: string;
    }> | undefined;
    let basePath = "";
    try {
      basePath =
        typeof adapter?.getBasePath === "function"
          ? adapter.getBasePath() ?? ""
          : adapter?.basePath ?? "";
    } catch {
      basePath = "";
    }
    const appId = (
      (this.app as unknown as { appId?: string } | undefined)?.appId ?? ""
    ).toString();
    let vaultName = "";
    try {
      vaultName = typeof vault?.getName === "function" ? vault.getName() ?? "" : "";
    } catch {
      vaultName = "";
    }

    const fingerprintInput = [basePath, appId, vaultName]
      .map((part) => part.trim())
      .filter((part) => part.length > 0)
      .join("|");

    if (fingerprintInput) {
      const hash = await this.computeHash(`vaultguard-vault::${fingerprintInput}`);
      return hash.slice(0, 32);
    }

    // No usable runtime identifier — fall back to a random ID persisted only
    // to data.json (per-vault on disk), which still avoids the localStorage
    // collision because each vault generates its own.
    if (!this.settings.vaultBindingId) {
      this.settings.vaultBindingId = VaultGuardPlugin.generateVaultBindingId();
      await this.savePluginData();
    }
    return this.settings.vaultBindingId;
  }

  private getSessionBindingId(): string | null {
    if (!this.derivedBindingId) {
      this.log(
        "Derived vault binding ID is not yet available; refusing to use shared session storage."
      );
      return null;
    }

    return this.derivedBindingId;
  }

  private getSessionStorageKey(bindingId: string): string {
    return `${VaultGuardPlugin.SESSION_STORAGE_KEY_PREFIX}${bindingId}`;
  }

  private removeStoredSessionKey(bindingId: string): void {
    try {
      localStorage.removeItem(this.getSessionStorageKey(bindingId));
    } catch {
      // Storage may be unavailable in tests or restricted renderer contexts.
    }
  }

  /**
   * Wraps a session for at-rest storage using Electron's `safeStorage` (OS
   * keystore: DPAPI on Windows, Keychain on macOS, kwallet/libsecret on
   * Linux). Returns `null` only when the OS keystore is genuinely unreachable
   * — callers must treat that as "do not persist via safeStorage" and try the
   * AtRestCipher fallback (`protectSessionWithAtRest`) before giving up. We
   * never fall back to plaintext on disk.
   */
  private protectSessionForStorage(session: UserSession): ProtectedSessionEnvelope | null {
    const safeStorage = probeSafeStorage();
    if (!safeStorage) return null;

    try {
      const encrypted = safeStorage.encryptString(JSON.stringify(session));
      const bytes = encrypted instanceof Uint8Array ? encrypted : new Uint8Array(encrypted);
      return {
        v: 1,
        storage: "electron-safe-storage",
        ciphertext: this.bytesToBase64(bytes),
      };
    } catch (error) {
      this.logError("Failed to protect session with safeStorage", error);
      return null;
    }
  }

  /**
   * Mobile / safeStorage-less fallback: wrap the session via `AtRestCipher`.
   * Same security ceiling as the local at-rest encryption of vault content
   * (AES-256-GCM with the LAK, whose KEK either lives in the OS keystore on
   * desktop or in localStorage on mobile). Returns `null` if the cipher
   * isn't ready or encryption fails — the caller decides whether to warn.
   */
  private async protectSessionWithAtRest(
    session: UserSession
  ): Promise<ProtectedSessionEnvelope | null> {
    const cipher = this.atRestCipher;
    if (!cipher?.isReady()) return null;

    try {
      const ciphertext = await cipher.encryptString(JSON.stringify(session));
      const bytes = new Uint8Array(ciphertext);
      return {
        v: 1,
        storage: "at-rest-cipher",
        ciphertext: this.bytesToBase64(bytes),
      };
    } catch (error) {
      this.logError("Failed to protect session with AtRestCipher", error);
      return null;
    }
  }

  /**
   * Unwraps a stored session envelope synchronously. Handles the
   * `electron-safe-storage` variant only — the `at-rest-cipher` variant
   * decrypts via WebCrypto (async) and is routed through
   * `unprotectAtRestSession` / `loadAtRestSessionFromStore` instead.
   * Anything else (unknown shape, future formats, truncated JSON) returns
   * `null` and the caller falls through to the async path or forces re-auth.
   */
  private unprotectStoredSession(value: unknown): UserSession | null {
    if (!value || typeof value !== "object") return null;
    const envelope = value as Partial<ProtectedSessionEnvelope>;
    if (
      envelope.v !== 1 ||
      !this.isNonEmptyString(envelope.ciphertext) ||
      envelope.storage !== "electron-safe-storage"
    ) {
      return null;
    }

    const safeStorage = probeSafeStorage();
    if (!safeStorage) {
      this.notifySafeStorageUnavailable();
      return null;
    }

    try {
      const plaintext = safeStorage.decryptString(this.base64ToBytes(envelope.ciphertext));
      const parsed = JSON.parse(plaintext) as Partial<UserSession>;
      return this.materializeSession(parsed);
    } catch (error) {
      this.logError("Failed to restore protected session", error);
      return null;
    }
  }

  /**
   * Async counterpart for the `at-rest-cipher` envelope variant. Used on
   * mobile / safeStorage-less hosts where the LAK seals the session blob.
   * Returns `null` if the envelope shape is wrong, the cipher isn't ready,
   * or decryption fails.
   */
  private async unprotectAtRestSession(value: unknown): Promise<UserSession | null> {
    if (!value || typeof value !== "object") return null;
    const envelope = value as Partial<ProtectedSessionEnvelope>;
    if (
      envelope.v !== 1 ||
      envelope.storage !== "at-rest-cipher" ||
      !this.isNonEmptyString(envelope.ciphertext)
    ) {
      return null;
    }

    const cipher = this.atRestCipher;
    if (!cipher?.isReady()) {
      // The LAK isn't loaded (cipher in needs-recovery / disabled state).
      // We can't decrypt the envelope; treat it as "no session" so the
      // user re-authenticates. No Notice — the cipher init path already
      // surfaces its own banner when this happens.
      return null;
    }

    try {
      const ciphertext = this.base64ToBytes(envelope.ciphertext);
      const plaintext = await cipher.decryptString(ciphertext);
      const parsed = JSON.parse(plaintext) as Partial<UserSession>;
      return this.materializeSession(parsed);
    } catch (error) {
      this.logError("Failed to restore at-rest-protected session", error);
      return null;
    }
  }

  /**
   * Loads a stored session via the synchronous safeStorage path. Returns
   * `null` for the `at-rest-cipher` variant; callers should chain
   * `loadAtRestSessionFromStore()` to cover that case.
   */
  private loadSessionFromStore(): UserSession | null {
    const bindingId = this.getSessionBindingId();
    if (!bindingId) return null;

    try {
      const raw = localStorage.getItem(this.getSessionStorageKey(bindingId));
      if (raw) {
        const session = this.unprotectStoredSession(JSON.parse(raw));
        if (session) return session;
      }
    } catch {
      // Fall through to data.json backup.
    }

    return this.unprotectStoredSession(this.persistedSessions[bindingId]);
  }

  /**
   * Async counterpart for the `at-rest-cipher` envelope. Mirror of
   * `loadSessionFromStore` but routed through `unprotectAtRestSession`.
   * Called after the sync path returns `null` so desktop users with a
   * working safeStorage pay zero async cost.
   */
  private async loadAtRestSessionFromStore(): Promise<UserSession | null> {
    const bindingId = this.getSessionBindingId();
    if (!bindingId) return null;

    try {
      const raw = localStorage.getItem(this.getSessionStorageKey(bindingId));
      if (raw) {
        const session = await this.unprotectAtRestSession(JSON.parse(raw));
        if (session) return session;
      }
    } catch {
      // Fall through to data.json backup.
    }

    return this.unprotectAtRestSession(this.persistedSessions[bindingId]);
  }

  /**
   * Persists a session to localStorage and Obsidian's plugin data store.
   *
   * Write priority:
   *   1. Electron `safeStorage` (desktop — OS keystore-backed).
   *   2. `AtRestCipher` fallback (mobile / safeStorage-less hosts — same LAK
   *      that encrypts vault content; on mobile its KEK lives in localStorage
   *      since there's no OS keystore exposed to the renderer).
   *
   * If BOTH paths are unavailable we DO NOT touch existing on-disk state —
   * the in-memory session keeps working for this run, the user is warned
   * once, and the next plugin launch will require re-auth. We never silently
   * delete the previously-stored session, and we never write a plaintext
   * fallback.
   */
  private async persistSession(session: UserSession): Promise<void> {
    const bindingId = this.getSessionBindingId();
    if (!bindingId) return;

    // Wave 2 issue A (1.0.31): stamp the last-known vaultMemberRole
    // onto the session before sealing. On the next plugin reload,
    // restoreSession reads this back so the initial warmup uses the
    // real role instead of synthesizing one from session.role —
    // closes the race that mattered for users whose org role and
    // vault role disagree.
    const sessionToPersist: UserSession = {
      ...session,
      vaultMemberRole: this.vaultMemberRole ?? session.vaultMemberRole ?? null,
    };

    let protectedSession = this.protectSessionForStorage(sessionToPersist);
    if (!protectedSession) {
      // Desktop with broken keychain or mobile renderer — try the at-rest
      // cipher before warning. On mobile this is the normal path and the
      // user shouldn't see any Notice at all.
      protectedSession = await this.protectSessionWithAtRest(sessionToPersist);
    }
    if (!protectedSession) {
      this.notifySafeStorageUnavailable();
      return;
    }

    this.persistedSessions[bindingId] = protectedSession;
    try {
      localStorage.setItem(
        this.getSessionStorageKey(bindingId),
        JSON.stringify(protectedSession)
      );
    } catch (error) {
      this.logError("Failed to persist session to localStorage", error);
    }

    try {
      await this.savePluginData();
      this.log(`Session persisted for ${session.displayName}`);
    } catch (error) {
      this.logError("Failed to persist session to Obsidian data store", error);
    }
  }

  /**
   * Clears the stored session from localStorage and Obsidian's plugin data
   * store. This is the explicit-logout path and IS allowed to wipe — distinct
   * from `persistSession`'s no-silent-wipe rule on encryption failure.
   */
  private async clearStoredSession(): Promise<void> {
    const bindingId = this.getSessionBindingId();
    if (!bindingId) return;

    delete this.persistedSessions[bindingId];
    this.removeStoredSessionKey(bindingId);

    try {
      await this.savePluginData();
    } catch (error) {
      this.logError("Failed to remove persisted session from Obsidian data store", error);
    }

    this.log("Stored session cleared.");
  }

  /**
   * One-shot user warning when *no* secure session storage is available —
   * neither Electron's `safeStorage` nor the local `AtRestCipher`. This is
   * the truly degraded state (e.g. broken Linux keyring AND a cipher in
   * needs-recovery). On mobile Obsidian the at-rest cipher takes over
   * transparently and this Notice never fires.
   *
   * The in-memory session keeps working for the current run; the user just
   * has to log in again next launch.
   */
  private notifySafeStorageUnavailable(): void {
    if (this.safeStorageUnavailableNotified) return;
    this.safeStorageUnavailableNotified = true;
    this.log(
      "No secure session storage available (safeStorage unreachable AND at-rest cipher unavailable) — session will not be persisted to disk."
    );
    new Notice(
      "VaultGuard Sync: Your platform doesn't expose secure credential storage. " +
      "You'll need to log in each time the plugin loads — we never store " +
      "auth tokens in plaintext.",
      10000
    );
  }

  /**
   * Filters the on-load `storedSessions` map down to entries that look like
   * a recognised envelope (either safeStorage- or AtRestCipher-sealed).
   * Anything else is dropped — we don't carry broken or foreign blobs
   * through to subsequent saves.
   */
  private normalizePersistedSessions(
    storedSessions: Record<string, unknown> | undefined
  ): Record<string, unknown> {
    if (!storedSessions || typeof storedSessions !== "object") return {};

    const normalized: Record<string, unknown> = {};
    for (const [bindingId, value] of Object.entries(storedSessions)) {
      if (!value || typeof value !== "object") continue;
      const envelope = value as Partial<ProtectedSessionEnvelope>;
      const storage = envelope.storage;
      if (
        envelope.v === 1 &&
        (storage === "electron-safe-storage" || storage === "at-rest-cipher") &&
        this.isNonEmptyString(envelope.ciphertext)
      ) {
        normalized[bindingId] = value;
      }
    }
    return normalized;
  }

  /**
   * Validates a decrypted session payload and produces a fully-typed
   * `UserSession`. Strict: every required field must be present and a
   * non-empty string of the expected shape. Returns `null` on any defect
   * so the caller forces re-auth rather than running with a partial session.
   */
  private materializeSession(parsed: Partial<UserSession> | null): UserSession | null {
    if (!parsed || typeof parsed !== "object") return null;
    if (
      !this.isNonEmptyString(parsed.userId) ||
      !this.isNonEmptyString(parsed.refreshToken) ||
      !this.isNonEmptyString(parsed.idToken) ||
      !this.isNonEmptyString(parsed.accessToken) ||
      !this.isNonEmptyString(parsed.tokenExpiresAt) ||
      !this.isNonEmptyString(parsed.organizationId) ||
      !this.isNonEmptyString(parsed.displayName) ||
      !this.isNonEmptyString(parsed.email) ||
      !this.isValidSessionRole(parsed.role) ||
      !this.isNonEmptyString(parsed.createdAt)
    ) {
      return null;
    }

    const roles = Array.isArray(parsed.roles)
      ? parsed.roles.filter((role): role is string => this.isNonEmptyString(role))
      : [];

    return {
      sessionId: this.isNonEmptyString(parsed.sessionId) ? parsed.sessionId : "",
      userId: parsed.userId,
      organizationId: parsed.organizationId,
      displayName: parsed.displayName,
      email: parsed.email,
      accessToken: parsed.accessToken,
      idToken: parsed.idToken,
      refreshToken: parsed.refreshToken,
      tokenExpiresAt: parsed.tokenExpiresAt,
      role: parsed.role,
      roles: roles.length > 0 ? roles : [parsed.role],
      createdAt: parsed.createdAt,
      // Wave 2 issue A (1.0.31): preserve the last-known vault role
      // across plugin reloads. Optional, so older envelopes without
      // the field stay valid; `null` means "we don't know, fall back
      // to the synthesized derivation".
      vaultMemberRole: this.isValidVaultMemberRole(parsed.vaultMemberRole)
        ? parsed.vaultMemberRole
        : null,
    };
  }

  private isValidVaultMemberRole(
    value: unknown
  ): value is "admin" | "editor" | "viewer" {
    return value === "admin" || value === "editor" || value === "viewer";
  }

  private isValidSessionRole(value: unknown): value is UserSession["role"] {
    return (
      value === "member" ||
      value === "editor" ||
      value === "admin" ||
      value === "owner"
    );
  }

  private isNonEmptyString(value: unknown): value is string {
    return typeof value === "string" && value.trim().length > 0;
  }

  // ─────────────────────────────────────────────────────────────────────────
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
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
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
