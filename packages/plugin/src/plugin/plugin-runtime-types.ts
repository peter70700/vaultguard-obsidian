import type {
  App,
  Command,
  EventRef,
  Menu,
  Notice,
  Plugin,
  TAbstractFile,
  ViewCreator,
} from "obsidian";
import type {
  ReconciliationDecision,
  ReconciliationPlan,
} from "./binding-reconciliation-modal";
import type {
  OrgSettingsResponse,
  VaultMemberRole,
  VaultGuardApiClient,
} from "../api/client";
import type {
  ConnectionState,
  ConnectionStatus,
  ApiResponse,
  KeyLease,
  PermissionLevel,
  ServerEdition,
  ServerFeatures,
  SyncState,
  UserSession,
  VaultGuardSettings,
} from "../types";
import type { FileExplorerDecorations } from "../ui/file-explorer-decorations";
import type { FilePermissionHeader } from "../ui/file-permission-header";
import type {
  VaultGuardSidebarAuthState,
  VaultGuardSidebarViewConfig,
} from "../ui/vaultguard-sidebar-view";
import type { PermissionStore, PermissionStoreState } from "./permission-store";
import type { ReadOnlyGuard } from "./readonly-guard";
import type { SyncDiagnostics } from "./sync-diagnostics";
import type { UpdateChecker } from "./update-checker";
import type { AtRestCipher } from "../crypto/at-rest-cipher";
import type { BridgeAuditAction } from "./agent-bridge";
import type {
  RemoteFileStateEntry,
  RemoteFileStateUpdate,
} from "./remote-file-state";
import type {
  LongOperationHandle,
  LongOperationStartOptions,
} from "./long-operation";
import type { VaultOrientationService } from "./vault-orientation";

// Shield icon SVG for the ribbon.
export const VAULTGUARD_ICON = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>`;

// The AI Chat ribbon button and view tab use Obsidian's stock lucide
// `message-square` icon. Stock icons are pre-registered by Obsidian, so the
// ribbon button always carries its glyph at first paint.
export const VAULTGUARD_CHAT_ICON_ID = "message-square";

/**
 * Metadata-only view of a queued offline operation for debug reporting.
 * Deliberately has NO `data` field — queued write payloads are plaintext and
 * must never reach a debug report, the console, or the clipboard.
 */
export interface OfflineQueueDebugEntry {
  operation: "write" | "delete";
  path: string;
  timestamp: string;
  dataBytes: number;
  // BIN-A / D-11: discriminant only (never the payload). "base64" means the
  // queued write rides the byte pipeline (offline-queue v2); undefined means a
  // text (string-pipeline) write. Lets the attachment report tell a legitimate
  // byte-path binary write apart from a binary that leaked into the string queue.
  encoding?: "base64";
}

/**
 * One analyzed attachment in the preview diagnostic. Header hex only — never
 * more than the first handful of bytes, so no note plaintext reaches the report.
 * `onDiskHeaderHex` is what Obsidian's app:// renderer actually reads off disk;
 * `decryptedHeaderHex` is the real content after at-rest decryption. When at-rest
 * encryption is on, the two differ (VG1 vs the true PNG/PDF magic), which is
 * exactly why encrypted attachments fail to preview.
 */
export interface AttachmentPreviewDatum {
  path: string;
  /** The URL Obsidian's renderer loads for this file (adapter.getResourcePath). */
  resourceUrl: string;
  /** First bytes as they sit on disk — what the app:// renderer decodes. */
  onDiskHeaderHex: string;
  /** True when the on-disk bytes carry the VG1 at-rest magic (renderer can't decode). */
  onDiskEncrypted: boolean;
  /** First bytes after at-rest decryption — the real file content. null if decrypt failed. */
  decryptedHeaderHex: string | null;
  /** Set when a raw or decrypt read threw. */
  error?: string;
}

/** Structured result of the attachment-preview diagnostic (see collectAttachmentPreviewData). */
export interface AttachmentPreviewReport {
  /** Whether the plugin overrides adapter.getResourcePath (the render path). False until a preview fix lands. */
  getResourcePathIntercepted: boolean;
  /** Whether adapter.readBinary is intercepted (decrypts). True in normal operation. */
  readBinaryIntercepted: boolean;
  /** Whether at-rest encryption is active (files are VG1 on disk). */
  atRestActive: boolean;
  /** Total renderable-media attachments found in the vault. */
  totalAttachments: number;
  /** The subset actually analyzed (capped for cost). */
  analyzed: AttachmentPreviewDatum[];
}

export interface VaultGuardCommandContext {
  app: App;
  logPrefix: string;
  addCommand(command: Command): void;
  registerEvent(eventRef: EventRef): void;
  onFileMenu(callback: (menu: Menu, file: TAbstractFile) => void): EventRef;

  readonly session: UserSession | null;
  readonly apiClient: VaultGuardApiClient | null;
  readonly settings: VaultGuardSettings;
  readonly connectionState: ConnectionState;
  readonly syncState: SyncState;
  readonly syncDiagnostics: SyncDiagnostics;
  readonly manifestVersion: string;
  readonly folderLifecycleListenersRegistered: boolean;
  readonly syncTimerAlive: boolean;
  readonly keyLease: KeyLease | null;
  readonly vaultLeaseDenied: boolean;
  readonly placeholderPathsSize: number;
  readonly offlineQueueLength: number;
  readonly offlineQueueSnapshot: OfflineQueueDebugEntry[];
  readonly deletionTombstonesCount: number;
  readonly permissionStore: PermissionStore;
  readonly updateChecker: UpdateChecker | null;
  readonly pluginId: string;
  readonly localProjectMemoryMode: boolean;
  /** Live per-vault membership role (null = no explicit membership row; org role governs). */
  readonly vaultMemberRole: VaultMemberRole | null;

  handleLogin(): void;
  forceLogout(noticeMessage?: string): Promise<void>;
  isSessionTokenExpiring(): boolean;
  performSync(options?: { userInitiated?: boolean; forceCatchup?: boolean }): Promise<void>;
  getEffectivePermission(path: string): Promise<PermissionLevel>;
  runConnectionDiagnostics(): Promise<void>;
  featureEnabled(name: keyof ServerFeatures): boolean;
  isEffectiveAdmin(): boolean;
  openShareManagementModal(): void;
  showStatusNotice(): void;
  showVaultGuardMenu(evt?: MouseEvent): void;
  openAuditLog(): void;
  openWebAdminPanel(): void;
  openVaultGuardSettings(): void;
  showPermissionsModal(): void;
  showPermissionRulesModal(initialSearch?: string): void;
  activateVaultGuardSidebar(): Promise<void>;
  openAgentBridgeLeaseModal(): void;
  revokeAllAgentBridgeLeases(): void;
  stopAgentBridgeServer(): Promise<void>;
  encryptVaultAtRest(): Promise<void>;
  decryptVaultAtRest(): Promise<void>;
  decryptVaultAndDisableAtRestEncryption(): Promise<void>;
  enableLocalProjectMemoryMode(): Promise<void>;
  switchServerVault(): Promise<boolean>;
  showAdminPanel(): void;
  showPathPermissionsModal(path: string, isFolder: boolean, initialExplain?: boolean): void;
  showAddPermissionForPath(path: string, isFolder: boolean): void;
  copyShareLinkForPath(path: string): Promise<void>;
  activateVaultGuardChat(): Promise<void>;
  activatePermissionsGraph(): Promise<void>;
  openPermissionsGraphVirtualQaModal(): Promise<void>;
  openVaultGuardChatHistory(): Promise<void>;
  openNewVaultGuardChatTab(): Promise<void>;
  copyVaultGuardChatDomDebugReport(): Promise<void>;
  registerChatDebugCommand(): void;
  /**
   * BIN-A preview diagnostic: gathers, for up to `limit` renderable attachments,
   * the on-disk header (what the app:// renderer reads) vs the decrypted header
   * (the real content). Encapsulates the raw + decrypt reads so the general
   * command surface never gains a raw-disk-read capability.
   */
  collectAttachmentPreviewData(limit: number): Promise<AttachmentPreviewReport>;
  logError(message: string, error: unknown): void;
}

export interface VaultGuardRibbonElements {
  vaultGuardRibbonEl: HTMLElement | null;
  vaultGuardChatRibbonEl: HTMLElement | null;
  vaultGuardGraphRibbonEl: HTMLElement | null;
}

export interface VaultGuardRibbonContext {
  addRibbonIcon(
    icon: string,
    title: string,
    callback: (evt: MouseEvent) => unknown,
  ): HTMLElement | null | undefined;
  setVaultGuardRibbonEl(el: HTMLElement | null): void;
  setVaultGuardChatRibbonEl(el: HTMLElement | null): void;
  setVaultGuardGraphRibbonEl(el: HTMLElement | null): void;
  showVaultGuardMenu(evt?: MouseEvent): void;
  updateRibbonAuthIndicator(): void;
  activateVaultGuardChat(): Promise<void>;
  activatePermissionsGraph(): Promise<void>;
}

export interface VaultGuardViewRegistrationContext {
  registerView(type: string, viewCreator: ViewCreator): void;
  readonly sidebarViewConfig: VaultGuardSidebarViewConfig | null;
  readonly pluginForViews: unknown;
  getSidebarAuthState(): VaultGuardSidebarAuthState | null;
  // Phase 13 #1 — optional so the build stays green before the plugin supplies
  // the backing (createViewRegistrationContext, Task 2). getAtRestRecoveryState
  // backs the sidebar's W1 pull-getter; the two start* hooks route the banner
  // CTAs through the plugin's single recovery indirections.
  getAtRestRecoveryState?(): {
    needsRecovery: boolean;
    reason: string;
    canReset: boolean;
  };
  handleLogin(): void;
  openVaultGuardSettings(): void;
  startAtRestRecoveryFlow?(): void;
  startAtRestRecoveryFromRecoveryCode?(): void;
}

export interface VaultGuardSidebarActivationContext {
  app: App;
  createSidebarViewConfig(): VaultGuardSidebarViewConfig | null;
  getSidebarViewConfig(): VaultGuardSidebarViewConfig | null;
  setSidebarViewConfig(config: VaultGuardSidebarViewConfig | null): void;
}

export interface PermissionStoreFactoryContext {
  app: App;
  getSession(): UserSession | null;
  getVaultMemberRole(): VaultMemberRole | null;
  isOnline(): boolean;
  log(message: string): void;
  setConnectionOffline(): void;
  fetchPermissionLevelFromServer(path: string): Promise<PermissionLevel>;
  isNetworkError(error: unknown): boolean;
}

export interface PermissionSurfaceContext {
  app: App;
  plugin: Plugin;
  registerEvent(eventRef: EventRef): void;
  readonly apiClient: VaultGuardApiClient | null;
  readonly session: UserSession | null;
  readonly orgSettings: OrgSettingsResponse | null;
  readonly permissionStore: PermissionStore;
  getEffectiveUiRole(): string;
  isEffectiveAdmin(): boolean;
  getEffectivePermission(path: string): Promise<PermissionLevel>;
  isFileExplorerDecorationDataReady(): boolean;
  syncFileExplorerDecorationsState(refresh?: boolean): void;
  isPermissionBannerEnabled(): boolean;
  /**
   * Backend connection state as a PRESENTATION HINT only. It may be stale in
   * both directions (the "online" flip is deferred until the first sync), so UI
   * surfaces treat it as advisory and must never gate a network fetch on it.
   */
  isOnline(): boolean;
  /** User-initiated reconnect probe (flips status online on success). */
  reconnectNow(): Promise<void>;
}

export interface PermissionSurfaceInstances {
  filePermissionHeader?: FilePermissionHeader;
  readOnlyGuard?: ReadOnlyGuard;
  fileExplorerDecorations?: FileExplorerDecorations;
}

export interface LifecycleEventsContext {
  app: App;
  logPrefix: string;
  protocolHost: {
    registerObsidianProtocolHandler?: (
      action: string,
      handler: (params: Record<string, string>) => unknown,
    ) => void;
  };
  registerEvent(eventRef: EventRef): void;
  registerDomEvent(
    target: Window | Document,
    type: string,
    callback: EventListenerOrEventListenerObject,
    options?: boolean | AddEventListenerOptions,
  ): void;
  registerInterval(id: number): void;

  readonly session: UserSession | null;
  readonly settings: VaultGuardSettings;
  readonly syncState: SyncState;
  readonly permissionStore: PermissionStore;
  readonly folderLifecycleListenersRegistered: boolean;
  setFolderLifecycleListenersRegistered(registered: boolean): void;
  readonly obsidianSyncNotice: Notice | null;
  setObsidianSyncNotice(notice: Notice | null): void;
  readonly syncDiagnostics: SyncDiagnostics;

  redeemInvite(params: Record<string, string>): Promise<void>;
  handleShareLink(params: Record<string, string>): Promise<void>;
  reloadVaultGuardSidebar(): void;
  ensureVaultGuardSidebar(): Promise<void>;
  noteSessionActivity(): void;
  handleFocusSyncTrigger(): void;
  resumeSyncLoop(reason: string): void;
  pauseSyncLoop(reason: string): void;
  isVaultLocked(): boolean;
  handleBrowserOnline(): void;
  handleBrowserOffline(): void;
  handleFolderCreated(path: string): void;
  handleFolderDeleted(path: string): void;
  handleFolderRenamed(path: string, oldPath: string): void;
  handleVaultFileRenamed(path: string, oldPath: string): void;
  handleVaultFileDeleted(path: string): void;
  log(message: string): void;
  logError(message: string, error: unknown): void;
}

export interface PermissionsGraphRuntimeContext {
  app: App;
  readonly apiClient: VaultGuardApiClient | null;
  readonly session: UserSession | null;
  readonly manifestId: string | undefined;
  readonly atRestCipher: AtRestCipher | null;
  readonly adapterReadBinary: ((normalizedPath: string) => Promise<ArrayBuffer>) | null;
  readonly adapterWriteBinary:
    | ((normalizedPath: string, data: ArrayBuffer) => Promise<void>)
    | null;
  vaultConfigPath(...parts: string[]): string;
  ensureParentFoldersForPath(path: string): Promise<void>;
  normalizeVaultPath(path: string): string;
  logError(message: string, error: unknown): void;
}

export interface RemoteFileContentResponse {
  content: string;
  encoding?: string;
  decrypted?: boolean;
  // BIN-A / D-04 (additive): the GET /files response already returns the S3
  // object's contentType (files/handler.ts:947). The pull side uses it as the
  // authoritative binary discriminator (isBinaryContentType) — always present,
  // unlike cold-path delta contentType (L9).
  contentType?: string;
  path?: string;
  size?: number;
  lastModified?: string;
  versionId?: string;
  checksum?: string;
  encrypted?: boolean;
}

export interface RemoteFileWriteResponse {
  path?: string;
  size?: number;
  lastModified?: string;
  versionId?: string;
  checksum?: string;
}

/**
 * BIN-A / D-05 (wave 5): a reconciliation local-manifest entry, discriminated by
 * `kind`. TEXT entries carry the decoded string + its SHA-256 (computeHash);
 * BINARY entries carry the raw PLAIN bytes + their byte SHA-256 (computeHashBytes).
 * The `kind` discriminant lets every reconciliation pass (both-exist byte compare,
 * localOnly upload, conflict strategies) narrow type-safely, so a binary can never
 * be routed through the lossy string pipeline — the AR1 failure class (L4).
 *
 * Defined here, not module-local in sync-runtime, because the type crosses the ctx
 * boundary: resolveReconciliationConflict receives the manifest Map.
 */
export type LocalManifestEntry =
  | { kind: "text"; content: string; hash: string }
  | { kind: "binary"; bytes: ArrayBuffer; hash: string };

export interface VaultAdapterOriginalMethods {
  read: ((normalizedPath: string) => Promise<string>) | null;
  write: ((normalizedPath: string, data: string) => Promise<void>) | null;
  readBinary: ((normalizedPath: string) => Promise<ArrayBuffer>) | null;
  writeBinary:
    | ((normalizedPath: string, data: ArrayBuffer) => Promise<void>)
    | null;
  list:
    | ((normalizedPath: string) => Promise<{ files: string[]; folders: string[] }>)
    | null;
  remove: ((normalizedPath: string) => Promise<void>) | null;
  rename: ((oldPath: string, newPath: string) => Promise<void>) | null;
  // BIN-A preview: getResourcePath is the sync method Obsidian's renderer calls
  // to load media (returns an app://… URL read directly from disk). Captured so
  // the interceptor can serve at-rest-encrypted images/PDFs as decrypted blobs.
  getResourcePath: ((normalizedPath: string) => string) | null;
}

export interface OfflineQueueOperation {
  operation: "write" | "delete";
  path: string;
  data?: string;
  timestamp: string;
  // BIN-A / D-09 (offline-queue v2): when encoding === "base64", `data` holds the
  // base64 of the PLAIN attachment bytes (never the UTF-8 string path), and
  // `contentType` is the MIME label for the eventual byte PUT. Absent for text
  // ops (v1-compatible: an undefined encoding means "text", flushed as today).
  encoding?: "base64";
  contentType?: string;
  // Version-guard (optimistic concurrency): the server version + plaintext hash
  // this queued edit was based on, so a replay can detect a conflicting write.
  baseVersionId?: string;
  baseHash?: string;
}

export type RemoteWriteConflictResolutionResult =
  | "keep-local"
  | "keep-remote"
  | "duplicate"
  | "pending";

export interface AtRestAdapterRuntimeContext {
  app: App;
  readonly manifestId: string | undefined;
  readonly settings: VaultGuardSettings;

  /**
   * Phase 12 (vault idle-lock): true when a device PIN currently owns the LAK.
   * Optional so pre-existing ctx builders/tests keep compiling. When true,
   * `initAtRestCipher` skips provisioning (the LAK lives PIN-wrapped in
   * `lak-pin.envelope`; `lak.envelope` is absent by design — NN-1) and lands
   * the adapter LOCKED until the plugin calls `unlockCipherWithLak` with the
   * PIN-unwrapped LAK (edge #6).
   */
  isPinLockEnrolled?(): boolean;

  getSession(): UserSession | null;
  getKeyLease(): KeyLease | null;
  isVaultLeaseDenied(): boolean;
  getPlaceholderPaths(): Set<string>;
  isApplyingRemoteWrite(): boolean;
  getSyncState(): SyncState;
  getOfflineQueue(): OfflineQueueOperation[];
  getPermissionStore(): PermissionStore;
  hasWarmedAtLeastOnce(): boolean;

  saveSettings(): Promise<void>;
  openVaultGuardSettings(): void;
  showLoginRequiredNotice(
    action: "open" | "browse" | "edit" | "delete" | "sync" | "view permissions",
    path?: string,
  ): string;
  awaitPermissionReadiness(): Promise<void>;
  getEffectivePermission(path: string): Promise<PermissionLevel>;
  resolvePermissionFromCache(path: string): PermissionLevel;
  isPathExcluded(path: string): boolean;
  normalizeVaultPath(path: string): string;
  vaultConfigPath(...parts: string[]): string;
  toPermissionPath(path: string): string;
  isFolderMarkerPath(path: string): boolean;
  readPlainFromDisk(path: string): Promise<string>;
  writePlainToDisk(path: string, data: string): Promise<void>;
  readPlainBinaryFromDisk(path: string): Promise<ArrayBuffer>;
  writePlainBinaryToDisk(path: string, data: ArrayBuffer): Promise<void>;
  notifyCloudDecryptFallback(path: string): void;
  notifyCorruptedWrite(path: string): void;
  beginLongOperation(options: LongOperationStartOptions): LongOperationHandle;
  getLongOperationConflictKey(): string;

  isOnline(): boolean;
  isNetworkError(error: unknown): boolean;
  setConnectionStatus(
    status: ConnectionStatus,
    options?: { scheduleRetry?: boolean; notify?: boolean },
  ): void;
  shouldUploadChangesImmediately(): boolean;
  queueOfflineOperation(
    operation: "write" | "delete",
    path: string,
    data?: string,
    // BIN-A / D-09 + version-guard: binary payloads stamp encoding "base64" + a
    // MIME contentType; version-guarded writes/deletes stamp baseVersionId/baseHash.
    options?: {
      encoding?: "base64";
      contentType?: string;
      baseVersionId?: string;
      baseHash?: string;
    },
  ): void;
  getRemoteFileState(path: string): RemoteFileStateEntry | null;
  getExpectedVersionId(path: string): string | undefined;
  recordRemoteFilePresent(path: string, update?: RemoteFileStateUpdate): void;
  recordRemoteFileAbsent(path: string): void;
  handleRemoteWriteConflict(
    path: string,
    localContent: string,
    baseVersionId?: string | null,
  ): Promise<RemoteWriteConflictResolutionResult>;
  recordDeletionTombstone(path: string): void;
  clearDeletionTombstone(path: string): void;
  updateStatusBar(): void;
  // Phase 13 #1 — optional so existing ctx-builder test mocks keep compiling.
  // The runtime fires refreshAtRestRecoverySurfaces after init/migration-failure/
  // restore transitions; the sticky CTA + recovery-code door route through the
  // two start* indirections.
  refreshAtRestRecoverySurfaces?(): void;
  startAtRestRecoveryFlow?(): void;
  startAtRestRecoveryFromRecoveryCode?(): void;
  // Phase 13-02 (guarded local-cache reset) — optional so existing ctx-builder
  // test mocks keep compiling. main.ts owns setting/clearing the flag around the
  // raw-remove wipe; the vault delete listeners honor it to suppress server DELETEs.
  isResettingLocalCache?(): boolean;
  setResettingLocalCache?(v: boolean): void;

  encryptContent(content: string): Promise<string>;
  computeHash(content: string): Promise<string>;
  // BIN-A / D-02: byte-crypto declarations beside the string versions.
  encryptContentBytes(content: ArrayBuffer): Promise<string>;
  decryptContentBytes(encryptedContent: string): Promise<ArrayBuffer>;
  computeHashBytes(content: ArrayBuffer): Promise<string>;
  apiRequest<T>(
    method: string,
    endpoint: string,
    body?: Record<string, unknown>,
    idTokenOverride?: string,
    // L2 (BIN-A): optional per-request timeout override threaded to requestWithTimeout.
    options?: { timeoutMs?: number },
  ): Promise<ApiResponse<T>>;
  vaultPath(suffix?: string): string;
  readFileDecrypted(path: string): Promise<ApiResponse<RemoteFileContentResponse>>;
  fetchRemoteFileContent(path: string): Promise<ApiResponse<RemoteFileContentResponse>>;
  decodeRemoteFileContent(path: string, data: RemoteFileContentResponse): Promise<string>;
  decodeBase64Utf8(base64: string): string;

  emitAuditEvent(
    action: BridgeAuditAction | "file.read" | "file.write" | "file.delete" | "file.rename",
    resourcePath: string | null,
    metadata?: Record<string, unknown>,
  ): Promise<void>;
  log(message: string): void;
  logError(message: string, error: unknown): void;
}

export interface SyncRuntimeSnapshot {
  syncState: SyncState;
  connectionState: ConnectionState;
  keyLease: KeyLease | null;
  vaultLeaseDenied: boolean;
  placeholderPathsSize: number;
  offlineQueueLength: number;
  deletionTombstonesCount: number;
  syncTimerAlive: boolean;
  syncTimerPaused: boolean;
  keyRenewalTimerAlive: boolean;
  heartbeatTimerAlive: boolean;
  connectionRetryTimerAlive: boolean;
  connectionLostNoticeTimerAlive: boolean;
  applyingRemoteWrite: boolean;
  folderLifecycleListenersRegistered: boolean;
}

export interface SyncRuntimeContext {
  app: App;
  normalizeVaultPath(path: string): string;
  isPathExcluded(path: string): boolean;
  getSettings(): VaultGuardSettings;
  getSession(): UserSession | null;
  getSyncState(): SyncState;
  getConnectionState(): ConnectionState;
  getKeyLease(): KeyLease | null;
  setKeyLease(lease: KeyLease | null): void;
  isVaultLeaseDenied(): boolean;
  /**
   * Phase 12 (vault idle-lock): true while the vault is cryptographically locked.
   * The revocation heartbeat deliberately keeps running while locked (NN-2), but
   * the key-renewal monitor must be a no-op — the lease is evicted, so a renewal
   * tick while locked would spuriously log out or re-acquire a lease the lock
   * just dropped. checkKeyLeaseRenewal consults this to early-return.
   */
  isVaultLocked(): boolean;
  /** PL2: a lease acquisition failed transiently (not a 403) and needs retry. */
  isLeaseRetryNeeded(): boolean;
  getEffectiveSyncMode(): OrgSettingsResponse["syncMode"];
  getEffectiveSyncIntervalSeconds(): number;
  getSyncTimer(): ReturnType<typeof setTimeout> | null;
  setSyncTimer(timer: ReturnType<typeof setTimeout> | null): void;
  setSyncTimerPaused(paused: boolean): void;
  getKeyRenewalTimer(): ReturnType<typeof setInterval> | null;
  setKeyRenewalTimer(timer: ReturnType<typeof setInterval> | null): void;
  getHeartbeatTimer(): ReturnType<typeof setInterval> | null;
  setHeartbeatTimer(timer: ReturnType<typeof setInterval> | null): void;
  getOfflineQueue(): OfflineQueueOperation[];
  setOfflineQueue(queue: OfflineQueueOperation[]): void;
  getOfflineQueueFlushPromise(): Promise<void> | null;
  setOfflineQueueFlushPromise(promise: Promise<void> | null): void;
  getLocalOnlyCatchupCompleted(): boolean;
  setLocalOnlyCatchupCompleted(completed: boolean): void;
  getRemoteInventoryRepairCompleted(): boolean;
  setRemoteInventoryRepairCompleted(completed: boolean): void;
  getPlaceholderPaths(): Set<string>;
  getPlaceholderPathsSize(): number;
  getOfflineQueueLength(): number;
  getDeletionTombstonesCount(): number;
  isSyncTimerAlive(): boolean;
  isSyncTimerPaused(): boolean;
  isKeyRenewalTimerAlive(): boolean;
  isHeartbeatTimerAlive(): boolean;
  isConnectionRetryTimerAlive(): boolean;
  isConnectionLostNoticeTimerAlive(): boolean;
  isApplyingRemoteWrite(): boolean;
  setApplyingRemoteWrite(value: boolean): void;
  isFolderLifecycleListenersRegistered(): boolean;
  saveSettings(): Promise<void>;
  isOnline(): boolean;
  setConnectionStatus(
    status: ConnectionStatus,
    options?: { scheduleRetry?: boolean; notify?: boolean },
  ): void;
  getRemoteFileState(path: string): RemoteFileStateEntry | null;
  getExpectedVersionId(path: string): string | undefined;
  recordRemoteFilePresent(path: string, update?: RemoteFileStateUpdate): void;
  recordRemoteFileAbsent(path: string): void;
  performInitialReconciliation(): Promise<boolean>;
  registerFolderLifecycleListeners(): void;
  performSync(options?: { userInitiated?: boolean; forceCatchup?: boolean }): Promise<void>;
  buildLocalSyncManifest(): Record<string, string>;
  askReconciliationPlan(plan: ReconciliationPlan): Promise<ReconciliationDecision>;
  uploadReconciledFile(
    path: string,
    content: string,
    options?: { noWriteNotice?: string },
  ): Promise<"uploaded" | "skipped-no-lease" | "skipped-no-permission">;
  /** Re-encrypts an externally-added plaintext text file in place (no-op for
   * VG1/binary/excluded paths). Fire-and-forget hygiene after catch-up uploads. */
  ensureAtRestEncryptedInPlace(path: string): Promise<boolean>;
  /** Current permission-store state — used to refuse deleting local-only files
   * on an unconfirmed (cold/warming/fetch-failed) permission baseline (SY2). */
  getPermissionStoreState(): PermissionStoreState;
  removeUnsyncedLocalFile(path: string): Promise<boolean>;
  uploadLocalOnlyFiles(): Promise<{
    uploadedFiles: number;
    uploadedFolders: number;
    removedLocalFiles: number;
    skippedFiles: number;
    failedFiles: number;
    failedFolders: number;
  } | null>;
  repairMissingRemoteItems(): Promise<{
    downloadedFiles: number;
    downloadedFolders: number;
    failedFiles: number;
    failedFolders: number;
  } | null>;
  collectLocalFolderPaths(): string[];
  localPathExists(path: string): Promise<boolean>;
  ensureLocalFolderPath(folderPath: string): Promise<boolean>;
  ensureParentFoldersForPath(path: string): Promise<void>;
  writeLocalFileFromRemote(path: string, content: string): Promise<void>;
  syncFileRenameToServer(oldPath: string, newPath: string): Promise<void>;
  syncFileDeleteToServer(path: string): Promise<void>;
  uploadFolderMarker(folderPath: string): Promise<boolean>;
  deleteFolderMarker(folderPath: string): Promise<void>;
  deleteFolderContentsOnServer(folderPath: string): Promise<void>;
  applyRemoteChange(metadata: { path: string; size: number }): Promise<void>;
  /**
   * Apply a server-reported deletion locally. `inferred` is true when the delta
   * came from the COLD (full-scan) sync path, where deletion is inferred from
   * "in your manifest but not in S3" and cannot distinguish a real remote delete
   * from a file this client simply never uploaded — such deletions must be
   * recoverable, never a permanent wipe.
   */
  applyRemoteDeletion(path: string, inferred: boolean): Promise<void>;
  /**
   * Move a local path to the vault's recoverable trash (`.trash`). Returns false
   * if the adapter has no trash support, in which case the caller must NOT fall
   * back to a permanent delete for inferred deletions.
   */
  trashLocalPath(path: string): Promise<boolean>;
  readFileDecrypted(path: string): Promise<ApiResponse<RemoteFileContentResponse>>;
  fetchRemoteFileContent(path: string): Promise<ApiResponse<RemoteFileContentResponse>>;
  decodeRemoteFileContent(path: string, data: RemoteFileContentResponse): Promise<string>;
  readRemotePlaintext(path: string): Promise<string>;
  resolveReconciliationConflict(
    path: string,
    strategy: import("../types").ConflictResolutionStrategy,
    localManifest: Map<string, LocalManifestEntry>,
  ): Promise<void>;
  hasOriginalAdapterRead(): boolean;
  hasOriginalAdapterReadBinary(): boolean;
  // BIN-A / L13: wave-4 pull gate needs write-binary capability so a legacy
  // adapter without writeBinary can never silently drop a downloaded binary.
  hasOriginalAdapterWriteBinary(): boolean;
  hasOriginalAdapterWrite(): boolean;
  hasOriginalAdapterRemove(): boolean;
  removeLocalPath(path: string): Promise<void>;
  readPlainFromDisk(path: string): Promise<string>;
  readPlainBinaryFromDisk(path: string): Promise<ArrayBuffer>;
  writePlainToDisk(path: string, data: string): Promise<void>;
  // BIN-A / L13 (wave-4 pull): byte sibling of writePlainToDisk — the fallback
  // disk write for writeLocalBinaryFileFromRemote when the vault binary API is
  // unavailable. VG1-encrypts before disk; refuses VG1-magic plaintext.
  writePlainBinaryToDisk(path: string, data: ArrayBuffer): Promise<void>;
  decryptContent(content: string): Promise<string>;
  // BIN-A / D-02: byte-crypto declarations beside the string versions.
  encryptContentBytes(content: ArrayBuffer): Promise<string>;
  decryptContentBytes(encryptedContent: string): Promise<ArrayBuffer>;
  computeHashBytes(content: ArrayBuffer): Promise<string>;
  bytesToBase64(bytes: Uint8Array): string;
  notifyCloudDecryptFallback(path: string): void;
  getEffectivePermission(path: string): Promise<PermissionLevel>;
  emitAuditEvent(
    action: "file.write" | "sync.conflict",
    resourcePath: string | null,
    metadata?: Record<string, unknown>,
  ): Promise<void>;
  encryptContent(content: string): Promise<string>;
  computeHash(content: string): Promise<string>;
  apiRequest<T>(
    method: string,
    endpoint: string,
    body?: Record<string, unknown>,
    idTokenOverride?: string,
    // L2 (BIN-A): optional per-request timeout override threaded to requestWithTimeout.
    options?: { timeoutMs?: number },
  ): Promise<ApiResponse<T>>;
  vaultPath(suffix?: string): string;
  isNetworkError(error: unknown): boolean;
  recordSyncDiagnostic(event: string, detail?: Record<string, unknown>): void;
  beginLongOperation(options: LongOperationStartOptions): LongOperationHandle;
  getLongOperationConflictKey(): string;
  showNotice(message: string, timeout?: number): void;
  showLoginRequiredNotice(
    action: "open" | "browse" | "edit" | "delete" | "sync" | "view permissions",
    path?: string,
  ): string;
  updateStatusBar(): void;
  ensureVaultScopedKeyLease(): Promise<"ok" | "limited" | "logged-out">;
  renewKeyLease(): Promise<void>;
  forceLogout(noticeMessage?: string): Promise<void>;
  invalidatePermissionStore(): void;
  emitPermissionChanged(payload?: { path?: string; serverConfirmed?: boolean }): void;
  clearPlaceholderPaths(): void;
  log(message: string): void;
  logError(message: string, error: unknown): void;
}

export interface AgentBridgeRuntimeContext {
  app: App;
  pluginForModal: unknown;
  readonly manifestId: string | undefined;
  getSession(): UserSession | null;
  getServerVaultId(): string;
  isLocalProjectMemoryModeEnabled(): boolean;
  getApiClient(): VaultGuardApiClient | null;
  getAtRestCipher(): AtRestCipher | null;
  getVaultOrientationService(): VaultOrientationService | null;
  getAdapterReadBinary(): ((normalizedPath: string) => Promise<ArrayBuffer>) | null;
  getAdapterWriteBinary():
    | ((normalizedPath: string, data: ArrayBuffer) => Promise<void>)
    | null;
  normalizeVaultPath(path: string): string;
  vaultConfigPath(...parts: string[]): string;
  ensureParentFoldersForPath(path: string): Promise<void>;
  isPathExcluded(path: string): boolean;
  getEffectivePermission(path: string): Promise<PermissionLevel>;
  isMetadataSuppressed(path: string): boolean;
  readText(path: string): Promise<string>;
  writeText(path: string, content: string): Promise<void>;
  deleteFile(path: string): Promise<void>;
  renameFile(oldPath: string, newPath: string): Promise<void>;
  emitAudit(
    action: BridgeAuditAction,
    resourcePath: string | null,
    metadata: Record<string, unknown>,
  ): void | Promise<void>;
  log(message: string): void;
  logError(message: string, error: unknown): void;
}

export type SettingsRuntimeTokenRefreshResult =
  | { ok: true }
  | { ok: false; message: string; error?: unknown };

export interface PluginSettingsRuntimeContext {
  app: App;
  loadData(): Promise<unknown>;
  saveData(data: unknown): Promise<void>;
  savePluginData(): Promise<void>;

  readonly settings: VaultGuardSettings;
  setSettings(settings: VaultGuardSettings): void;
  readonly persistedSessions: Record<string, unknown>;
  setPersistedSessions(sessions: Record<string, unknown>): void;
  readonly pluginDataSaveQueue: Promise<void>;
  setPluginDataSaveQueue(queue: Promise<void>): void;
  readonly configuredApiEndpoint: string;
  setConfiguredApiEndpoint(endpoint: string): void;
  readonly resolvedApiEndpoint: string | null;
  setResolvedApiEndpoint(endpoint: string | null): void;
  readonly apiEndpointResolutionPromise: Promise<string> | null;
  setApiEndpointResolutionPromise(promise: Promise<string> | null): void;
  readonly serverEdition: ServerEdition | null;
  setServerEdition(edition: ServerEdition | null): void;
  readonly serverFeatures: ServerFeatures | null;
  setServerFeatures(features: ServerFeatures | null): void;
  readonly derivedBindingId: string;
  setDerivedBindingId(bindingId: string): void;
  readonly apiClient: VaultGuardApiClient | null;
  setApiClient(apiClient: VaultGuardApiClient | null): void;
  readonly session: UserSession | null;
  setSession(session: UserSession | null): void;
  readonly vaultMemberRole: VaultMemberRole | null;
  readonly atRestCipher: AtRestCipher | null;
  readonly safeStorageUnavailableNotified: boolean;
  setSafeStorageUnavailableNotified(notified: boolean): void;

  computeHash(content: string): Promise<string>;
  pruneDeletionTombstones(): void;
  protectSessionForStorage(session: UserSession): unknown;
  protectSessionWithAtRest(session: UserSession): Promise<unknown>;
  forceLogout(noticeMessage?: string): Promise<void>;
  refreshAccessToken(session: UserSession): Promise<SettingsRuntimeTokenRefreshResult>;
  initializeApiClientFromSession(session: UserSession): void;
  log(message: string): void;
  logError(message: string, error: unknown): void;
}
