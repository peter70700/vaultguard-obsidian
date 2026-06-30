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
import type { PermissionStore } from "./permission-store";
import type { ReadOnlyGuard } from "./readonly-guard";
import type { SyncDiagnostics } from "./sync-diagnostics";
import type { UpdateChecker } from "./update-checker";
import type { AtRestCipher } from "../crypto/at-rest-cipher";
import type { BridgeAuditAction } from "./agent-bridge";

// Shield icon SVG for the ribbon.
export const VAULTGUARD_ICON = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>`;

// The AI Chat ribbon button and view tab use Obsidian's stock lucide
// `message-square` icon. Stock icons are pre-registered by Obsidian, so the
// ribbon button always carries its glyph at first paint.
export const VAULTGUARD_CHAT_ICON_ID = "message-square";

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
  readonly deletionTombstonesCount: number;
  readonly permissionStore: PermissionStore;
  readonly updateChecker: UpdateChecker | null;

  handleLogin(): void;
  forceLogout(noticeMessage?: string): Promise<void>;
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
  switchServerVault(): Promise<boolean>;
  showAdminPanel(): void;
  showPathPermissionsModal(path: string, isFolder: boolean, initialExplain?: boolean): void;
  showAddPermissionForPath(path: string, isFolder: boolean): void;
  copyShareLinkForPath(path: string): Promise<void>;
  activateVaultGuardChat(): Promise<void>;
  activatePermissionsGraph(): Promise<void>;
  openVaultGuardChatHistory(): Promise<void>;
  openNewVaultGuardChatTab(): Promise<void>;
  copyVaultGuardChatDomDebugReport(): Promise<void>;
  registerChatDebugCommand(): void;
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
  handleLogin(): void;
  openVaultGuardSettings(): void;
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
}

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
}

export interface OfflineQueueOperation {
  operation: "write" | "delete";
  path: string;
  data?: string;
  timestamp: string;
}

export interface AtRestAdapterRuntimeContext {
  app: App;
  readonly manifestId: string | undefined;
  readonly settings: VaultGuardSettings;

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

  isOnline(): boolean;
  isNetworkError(error: unknown): boolean;
  setConnectionStatus(
    status: ConnectionStatus,
    options?: { scheduleRetry?: boolean; notify?: boolean },
  ): void;
  shouldUploadChangesImmediately(): boolean;
  queueOfflineOperation(operation: "write" | "delete", path: string, data?: string): void;
  recordDeletionTombstone(path: string): void;
  clearDeletionTombstone(path: string): void;
  updateStatusBar(): void;

  encryptContent(content: string): Promise<string>;
  computeHash(content: string): Promise<string>;
  apiRequest<T>(
    method: string,
    endpoint: string,
    body?: Record<string, unknown>,
    idTokenOverride?: string,
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
  performInitialReconciliation(): Promise<boolean>;
  registerFolderLifecycleListeners(): void;
  performSync(options?: { userInitiated?: boolean; forceCatchup?: boolean }): Promise<void>;
  buildLocalSyncManifest(): Record<string, string>;
  askReconciliationPlan(plan: ReconciliationPlan): Promise<ReconciliationDecision>;
  uploadReconciledFile(
    path: string,
    content: string,
    options?: { noWriteNotice?: string },
  ): Promise<"uploaded" | "skipped">;
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
  applyRemoteDeletion(path: string): Promise<void>;
  readFileDecrypted(path: string): Promise<ApiResponse<RemoteFileContentResponse>>;
  fetchRemoteFileContent(path: string): Promise<ApiResponse<RemoteFileContentResponse>>;
  decodeRemoteFileContent(path: string, data: RemoteFileContentResponse): Promise<string>;
  readRemotePlaintext(path: string): Promise<string>;
  resolveReconciliationConflict(
    path: string,
    strategy: import("../types").ConflictResolutionStrategy,
    localManifest: Map<string, { content: string; hash: string }>,
  ): Promise<void>;
  hasOriginalAdapterRead(): boolean;
  hasOriginalAdapterWrite(): boolean;
  hasOriginalAdapterRemove(): boolean;
  removeLocalPath(path: string): Promise<void>;
  readPlainFromDisk(path: string): Promise<string>;
  writePlainToDisk(path: string, data: string): Promise<void>;
  decryptContent(content: string): Promise<string>;
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
  ): Promise<ApiResponse<T>>;
  vaultPath(suffix?: string): string;
  isNetworkError(error: unknown): boolean;
  recordSyncDiagnostic(event: string, detail?: Record<string, unknown>): void;
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
  getApiClient(): VaultGuardApiClient | null;
  getAtRestCipher(): AtRestCipher | null;
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
