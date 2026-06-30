import { Notice, TFile } from "obsidian";
import type {
  OfflineQueueOperation,
  RemoteFileContentResponse,
  SyncRuntimeContext,
  SyncRuntimeSnapshot,
} from "./plugin-runtime-types";
import {
  ConflictResolutionStrategy,
  PermissionLevel,
  type ApiResponse,
  type FileMetadata,
  type SyncConflict,
} from "../types";

export interface LocalSyncManifestInput {
  filePaths: string[];
  folderPaths: string[];
}

/**
 * Sentinel filename uploaded into every server-side folder so the empty-folder
 * case isn't lost across the round-trip. Must match the backend marker name.
 */
const FOLDER_MARKER_NAME = ".vaultguard-folder";

/**
 * Maximum age of a deletion tombstone (30 days). Tombstones older than this
 * are pruned on load so a path that never reconciles cannot grow the set
 * unbounded.
 */
const DELETION_TOMBSTONE_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/** Minimum allowed adaptive sync interval in seconds. */
const MIN_SYNC_INTERVAL = 10;

/** Grace period before key expiry to trigger renewal (5 minutes). */
const KEY_RENEWAL_GRACE_MS = 5 * 60 * 1000;

/** Server heartbeat interval for revocation detection. */
const HEARTBEAT_INTERVAL_MS = 60 * 1000;

/** Periodic key-lease renewal check cadence. */
const KEY_RENEWAL_INTERVAL_MS = 60 * 1000;

/**
 * Runtime for sync behavior extracted from the plugin entrypoint.
 *
 * This runtime intentionally owns no sync state. The plugin entrypoint supplies
 * state and integration callbacks while sync orchestration, reconciliation,
 * remote apply, folder lifecycle, and deletion propagation live here.
 */
export class SyncRuntime {
  constructor(private readonly ctx: SyncRuntimeContext) {}

  async initializeSyncEngine(): Promise<void> {
    this.ctx.log("Initializing sync engine...");
    this.ctx.recordSyncDiagnostic("initializeSyncEngine.enter");

    // Restore lastSync from persisted settings so a fresh process does not
    // pull every server file (and silently overwrite local edits) on startup.
    const syncState = this.ctx.getSyncState();
    const settings = this.ctx.getSettings();
    if (!syncState.lastSync && settings.lastSyncTimestamp) {
      syncState.lastSync = settings.lastSyncTimestamp;
    }

    // First-time bind for this serverVaultId: reconcile local<->server before
    // any sync writes happen. The context callback preserves the plugin-level
    // pass-through surface while the behavior stays in this runtime.
    const vaultId = settings.serverVaultId;
    this.ctx.recordSyncDiagnostic("initializeSyncEngine.reconcileDecision", {
      willReconcile: !!vaultId && settings.bindingReconciledVaultId !== vaultId,
    });
    if (vaultId && settings.bindingReconciledVaultId !== vaultId) {
      try {
        const reconciled = await this.ctx.performInitialReconciliation();
        if (!reconciled) {
          this.ctx.log("Initial reconciliation declined or aborted — sync engine will not start.");
          this.ctx.recordSyncDiagnostic("initializeSyncEngine.return.reconcileDeclined");
          return;
        }
      } catch (err) {
        this.ctx.logError("Initial reconciliation failed", err);
        this.ctx.showNotice(
          `VaultGuard Sync: Couldn't reconcile this folder with the server vault: ${
            err instanceof Error ? err.message : "Unknown error"
          }. Sync paused — open the sidebar to retry.`
        );
        this.ctx.recordSyncDiagnostic("initializeSyncEngine.return.reconcileFailed");
        return;
      }
    }

    // Listener registration remains plugin lifecycle wiring; registered
    // handlers delegate back into this runtime through the plugin surface.
    this.ctx.recordSyncDiagnostic("initializeSyncEngine.reachedRegisterListeners");
    this.ctx.registerFolderLifecycleListeners();

    this.ctx.recordSyncDiagnostic("initializeSyncEngine.reachedPerformSync");
    await this.ctx.performSync();

    this.ctx.recordSyncDiagnostic("initializeSyncEngine.reachedStartTimer");
    this.startSyncTimer();

    this.ctx.log("Sync engine initialized.");
  }

  getSyncState(): SyncRuntimeSnapshot["syncState"] {
    return this.ctx.getSyncState();
  }

  getConnectionState(): SyncRuntimeSnapshot["connectionState"] {
    return this.ctx.getConnectionState();
  }

  getOfflineQueueLength(): number {
    return this.ctx.getOfflineQueueLength();
  }

  getDeletionTombstonesCount(): number {
    return this.ctx.getDeletionTombstonesCount();
  }

  isSyncTimerAlive(): boolean {
    return this.ctx.isSyncTimerAlive();
  }

  isFolderLifecycleListenersRegistered(): boolean {
    return this.ctx.isFolderLifecycleListenersRegistered();
  }

  computeNextSyncDelayMs(): number {
    const baseline =
      Math.max(this.ctx.getEffectiveSyncIntervalSeconds(), MIN_SYNC_INTERVAL) * 1000;
    const lastActivity = this.ctx.getSyncState().lastObservedActivityAt;
    if (lastActivity == null) return baseline;

    const idleMs = Math.max(0, Date.now() - lastActivity);
    if (idleMs < 60_000) return baseline;
    if (idleMs < 5 * 60_000) return baseline;
    if (idleMs < 30 * 60_000) return Math.min(baseline * 2, 2 * 60_000);
    return Math.min(baseline * 4, 5 * 60_000);
  }

  /** Starts (or reschedules) the adaptive sync loop. */
  startSyncTimer(): void {
    this.stopSyncTimer();
    const syncMode = this.ctx.getEffectiveSyncMode();
    if (syncMode === "manual") {
      this.ctx.log("Sync timer disabled by organization manual-sync policy.");
      this.ctx.recordSyncDiagnostic("startSyncTimer.skipped", { reason: "manual" });
      return;
    }
    if (this.ctx.isSyncTimerPaused()) {
      this.ctx.log("Sync timer kept paused (window hidden / offline).");
      this.ctx.recordSyncDiagnostic("startSyncTimer.skipped", { reason: "paused" });
      return;
    }

    const delay = this.computeNextSyncDelayMs();
    const timer = setTimeout(() => {
      this.ctx.setSyncTimer(null);
      // Don't fire a new sync on top of an in-flight one; just reschedule.
      if (this.ctx.getSyncState().status !== "syncing") {
        void this.ctx.performSync().catch((err) =>
          this.ctx.logError("Periodic sync failed", err)
        );
      }
      // Always chain the next tick - performSync is fire-and-forget here.
      this.startSyncTimer();
    }, delay);
    this.ctx.setSyncTimer(timer);

    this.ctx.log(`Sync timer scheduled in ${Math.round(delay / 1000)}s (mode: ${syncMode}).`);
    this.ctx.recordSyncDiagnostic("startSyncTimer.scheduled", { delayMs: delay, syncMode });
  }

  /** Cancels the next scheduled sync, if any. */
  stopSyncTimer(): void {
    const timer = this.ctx.getSyncTimer();
    if (timer) {
      clearTimeout(timer);
      this.ctx.setSyncTimer(null);
    }
  }

  /** Restarts the sync loop (call when settings, mode, or session change). */
  restartSyncTimer(): void {
    if (this.ctx.getSession()) {
      this.startSyncTimer();
    }
  }

  /**
   * Pauses the sync loop. Call when the window goes hidden or the client
   * goes offline. Pending timers are cleared and the loop stops scheduling
   * itself until `resumeSyncLoop` is called.
   */
  pauseSyncLoop(reason: string): void {
    if (this.ctx.isSyncTimerPaused()) return;
    this.ctx.setSyncTimerPaused(true);
    this.stopSyncTimer();
    this.ctx.log(`Sync loop paused (${reason}).`);
  }

  /**
   * Resumes the sync loop after `pauseSyncLoop`. Triggers an immediate
   * sync on resume so the user doesn't have to wait one full interval to
   * see other peers' changes after returning to the window.
   */
  resumeSyncLoop(reason: string): void {
    if (!this.ctx.isSyncTimerPaused()) return;
    this.ctx.setSyncTimerPaused(false);
    this.ctx.log(`Sync loop resumed (${reason}).`);
    if (!this.ctx.getSession() || !this.ctx.getSettings().serverVaultId) return;
    void this.ctx.performSync().catch((err) =>
      this.ctx.logError("Resume-triggered sync failed", err)
    );
    this.startSyncTimer();
  }

  /**
   * Performs a full bidirectional sync with the server.
   * Uploads pending local changes and downloads remote updates.
   */
  async performSync(
    options: { userInitiated?: boolean; forceCatchup?: boolean } = {}
  ): Promise<void> {
    const { userInitiated = false, forceCatchup = false } = options;
    const settings = this.ctx.getSettings();
    const syncState = this.ctx.getSyncState();

    if (!this.ctx.getSession()) {
      const message = userInitiated
        ? this.ctx.showLoginRequiredNotice("sync")
        : "VaultGuard Sync: Sync skipped — not logged in.";
      this.ctx.log(message);
      this.ctx.recordSyncDiagnostic("performSync.skipped", { reason: "notLoggedIn" });
      return;
    }
    if (!this.ctx.isOnline()) {
      const message = "VaultGuard Sync: Sync skipped — offline.";
      this.ctx.log(message);
      if (userInitiated) this.ctx.showNotice(message);
      this.ctx.recordSyncDiagnostic("performSync.skipped", { reason: "offline" });
      return;
    }
    if (!settings.serverVaultId) {
      const message =
        "VaultGuard Sync: Sync skipped — this folder is not bound to a server vault yet.";
      this.ctx.log(message);
      if (userInitiated) this.ctx.showNotice(message);
      this.ctx.recordSyncDiagnostic("performSync.skipped", { reason: "noVault" });
      return;
    }

    if (syncState.status === "syncing") {
      const message = "VaultGuard Sync: A sync is already in progress.";
      this.ctx.log(message);
      if (userInitiated) this.ctx.showNotice(message);
      this.ctx.recordSyncDiagnostic("performSync.skipped", { reason: "alreadySyncing" });
      return;
    }

    if (userInitiated) {
      this.ctx.showNotice("VaultGuard Sync: Syncing…");
    }

    const canUploadEncryptedContent = this.hasValidKeyLease();
    if (!canUploadEncryptedContent) {
      this.ctx.log(
        "Sync running in limited access mode — downloads only; encrypted uploads are paused until a key lease is available."
      );
      if (userInitiated) {
        this.ctx.showNotice(
          "VaultGuard Sync: Limited access — downloading accessible server changes only."
        );
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
      syncState.status = "syncing";
      this.ctx.recordSyncDiagnostic("performSync.start", { userInitiated });
      this.ctx.updateStatusBar();

      // Phase 1: Upload queued offline operations
      const offlineQueueSizeBefore = this.ctx.getOfflineQueueLength();
      if (canUploadEncryptedContent) {
        await this.flushOfflineQueue();
        // Layer 2: re-attempt any outstanding tombstoned deletes that never
        // reached the server. Gating it with the flush keeps the historical
        // entry point and retry ordering.
        await this.retryOutstandingDeletions();
      } else if (offlineQueueSizeBefore > 0) {
        this.ctx.log(
          `Sync: ${offlineQueueSizeBefore} queued operation(s) kept pending because no encryption key lease is available.`
        );
      }
      const flushedSomething = canUploadEncryptedContent && offlineQueueSizeBefore > 0;

      // Phase 1b: Catch up local-only files + folders.
      let catchupChanges = 0;
      if (
        canUploadEncryptedContent &&
        (forceCatchup || !this.ctx.getLocalOnlyCatchupCompleted())
      ) {
        const result = await this.ctx.uploadLocalOnlyFiles();
        if (result) {
          totalFilesUploaded += result.uploadedFiles;
          totalFoldersUploaded += result.uploadedFolders;
          totalFilesRemoved += result.removedLocalFiles;
          catchupChanges =
            result.uploadedFiles + result.uploadedFolders + result.removedLocalFiles;
          this.ctx.setLocalOnlyCatchupCompleted(true);
        }
      }

      // Phase 1c: Cursor short-circuit.
      const canShortCircuit =
        !flushedSomething &&
        catchupChanges === 0 &&
        !forceCatchup &&
        syncState.lastSeenRevision != null;

      if (canShortCircuit) {
        const cursor = await this.fetchSyncCursor();
        if (cursor) {
          const cursorMs = Date.parse(cursor.lastChangedAt);
          if (Number.isFinite(cursorMs) && cursorMs > 0) {
            syncState.lastObservedActivityAt = cursorMs;
          }
          if (cursor.revision === syncState.lastSeenRevision) {
            syncState.status = "idle";
            syncState.lastError = null;
            syncState.pendingChanges = this.ctx.getOfflineQueueLength();
            this.ctx.log(
              `Sync skipped — cursor unchanged (revision ${cursor.revision}, last change ${cursor.lastChangedAt}).`
            );
            if (userInitiated) {
              this.ctx.showNotice("VaultGuard Sync: Already in sync — nothing to do.");
            }
            return;
          }
        }
      }

      // Phase 2: Fetch remote changes since last sync
      const response = await this.ctx.apiRequest<{
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
      }>("POST", this.ctx.vaultPath("/files/sync"), {
        lastSyncTimestamp: syncState.lastSync ?? new Date(0).toISOString(),
        fileChecksums: this.ctx.buildLocalSyncManifest(),
      });

      if (!response.success || !response.data) {
        throw new Error(response.error?.message ?? "Sync request failed.");
      }

      if (response.data.permissionsChanged) {
        this.ctx.log("Sync: permission rules changed on the server — emitting bus event.");
        this.ctx.emitPermissionChanged({ serverConfirmed: true });
      }

      deltaCount = response.data.deltas.length;

      for (const delta of response.data.deltas) {
        const normalizedPath = this.ctx.normalizeVaultPath(delta.path);

        if (this.ctx.isPathExcluded(normalizedPath)) {
          continue;
        }

        if (this.isFolderMarkerPath(normalizedPath)) {
          if (delta.action !== "deleted") {
            const folderPath = this.folderPathFromMarkerPath(normalizedPath);
            if (folderPath) {
              try {
                const created = await this.ctx.ensureLocalFolderPath(folderPath);
                if (created) totalFoldersDownloaded += 1;
              } catch (err) {
                this.ctx.log(`Sync: mkdir for "${folderPath}" no-op or failed: ${err}`);
              }
            }
          }
          continue;
        }

        if (delta.action === "deleted") {
          await this.ctx.applyRemoteDeletion(normalizedPath);
          continue;
        }

        await this.ctx.applyRemoteChange({
          path: normalizedPath,
          size: delta.size,
        });
      }

      // Phase 2b: repair missing server-side items that are older than our
      // lastSyncTimestamp.
      if (forceCatchup || !this.ctx.getRemoteInventoryRepairCompleted()) {
        const result = await this.ctx.repairMissingRemoteItems();
        if (result) {
          totalFilesDownloaded += result.downloadedFiles;
          totalFoldersDownloaded += result.downloadedFolders;
          totalRepairFailures += result.failedFiles + result.failedFolders;
          this.ctx.setRemoteInventoryRepairCompleted(totalRepairFailures === 0);
        }
      }

      syncState.lastSync = response.data.syncTimestamp;
      syncState.pendingChanges = this.ctx.getOfflineQueueLength();
      syncState.conflicts = [];
      syncState.status = "idle";
      syncState.lastError = null;
      if (typeof response.data.revision === "number") {
        syncState.lastSeenRevision = response.data.revision;
      }
      if (deltaCount > 0) {
        syncState.lastObservedActivityAt = Date.now();
      }
      if (settings.lastSyncTimestamp !== response.data.syncTimestamp) {
        settings.lastSyncTimestamp = response.data.syncTimestamp;
        void this.ctx.saveSettings().catch((err) =>
          this.ctx.logError("Failed to persist lastSyncTimestamp", err)
        );
      }

      if (userInitiated) {
        const summaryParts: string[] = [];
        if (totalFilesUploaded > 0) summaryParts.push(`${totalFilesUploaded} files uploaded`);
        if (totalFoldersUploaded > 0) {
          summaryParts.push(`${totalFoldersUploaded} folders preserved`);
        }
        if (totalFilesRemoved > 0) {
          summaryParts.push(`${totalFilesRemoved} local-only files removed`);
        }
        if (totalFilesDownloaded > 0) {
          summaryParts.push(`${totalFilesDownloaded} files downloaded`);
        }
        if (totalFoldersDownloaded > 0) {
          summaryParts.push(`${totalFoldersDownloaded} folders created`);
        }
        if (totalRepairFailures > 0) {
          summaryParts.push(`${totalRepairFailures} repair failures`);
        }
        if (deltaCount > 0) summaryParts.push(`${deltaCount} remote changes applied`);
        if (summaryParts.length === 0) {
          this.ctx.showNotice("VaultGuard Sync: Already in sync — nothing to do.");
        } else {
          this.ctx.showNotice(`VaultGuard Sync: Sync complete — ${summaryParts.join(", ")}.`);
        }
      }
      this.ctx.recordSyncDiagnostic("performSync.done", { ok: true });
    } catch (error) {
      syncState.status = "error";
      syncState.lastError =
        error instanceof Error ? error.message : "Unknown sync error";
      this.ctx.logError("Sync failed", error);
      this.ctx.recordSyncDiagnostic("performSync.done", {
        ok: false,
        message: error instanceof Error ? error.message : String(error),
      });

      if (userInitiated) {
        this.ctx.showNotice(
          `VaultGuard Sync: Sync failed — ${
            error instanceof Error ? error.message : "Unknown error"
          }`,
          10000
        );
      }

      if (this.ctx.isNetworkError(error)) {
        this.ctx.setConnectionStatus("offline");
      }
    } finally {
      this.ctx.updateStatusBar();
    }
  }

  /**
   * Fetches the current vault sync cursor from the server. Returns null on
   * failure so callers fall through to full sync instead of incorrectly
   * skipping.
   */
  async fetchSyncCursor(): Promise<{ revision: number; lastChangedAt: string } | null> {
    if (!this.ctx.getSession() || !this.ctx.getSettings().serverVaultId) return null;
    try {
      const response = await this.ctx.apiRequest<{
        revision: number;
        lastChangedAt: string;
        serverTime: string;
      }>("GET", this.ctx.vaultPath("/sync-cursor"));
      if (!response.success || !response.data) return null;
      return {
        revision: response.data.revision,
        lastChangedAt: response.data.lastChangedAt,
      };
    } catch (err) {
      this.ctx.logError("Sync cursor fetch failed", err);
      return null;
    }
  }

  async readFileDecrypted(
    relPath: string
  ): Promise<ApiResponse<RemoteFileContentResponse>> {
    const normalizedPath = this.ctx.normalizeVaultPath(relPath);
    const encoded = normalizedPath
      .split("/")
      .map((segment) => encodeURIComponent(segment))
      .join("/");
    return this.ctx.apiRequest<RemoteFileContentResponse>(
      "GET",
      this.ctx.vaultPath(`/files-decrypted/${encoded}`)
    );
  }

  async fetchRemoteFileContent(
    path: string
  ): Promise<ApiResponse<RemoteFileContentResponse>> {
    const normalizedPath = this.ctx.normalizeVaultPath(path);
    const serverDecrypt = !this.hasValidKeyLease();
    if (serverDecrypt) {
      return this.ctx.readFileDecrypted(normalizedPath);
    }
    return this.ctx.apiRequest<RemoteFileContentResponse>(
      "GET",
      this.ctx.vaultPath(`/files/${encodeURIComponent(normalizedPath)}`)
    );
  }

  async decodeRemoteFileContent(
    path: string,
    data: RemoteFileContentResponse
  ): Promise<string> {
    const normalizedPath = this.ctx.normalizeVaultPath(path);
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
      return await this.ctx.decryptContent(data.content);
    } catch (error) {
      throw this.remoteDecryptError(normalizedPath, error);
    }
  }

  async readRemotePlaintext(path: string): Promise<string> {
    const normalizedPath = this.ctx.normalizeVaultPath(path);
    const response = await this.ctx.fetchRemoteFileContent(normalizedPath);
    if (!response.success || !response.data) {
      throw new Error(
        response.error?.message ?? `Failed to read ${normalizedPath} from the server.`
      );
    }
    return this.ctx.decodeRemoteFileContent(normalizedPath, response.data);
  }

  async applyRemoteDeletion(normalizedPath: string): Promise<void> {
    if (!this.ctx.hasOriginalAdapterRemove()) return;
    try {
      await this.ctx.removeLocalPath(normalizedPath);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (!/enoent|no such file|does not exist|not found/i.test(msg)) {
        this.ctx.logError(`Sync: failed to delete "${normalizedPath}" locally`, err);
      }
    }
  }

  async applyRemoteChange(metadata: Pick<FileMetadata, "path" | "size">): Promise<void> {
    const normalizedPath = this.ctx.normalizeVaultPath(metadata.path);
    if (this.ctx.isPathExcluded(normalizedPath)) {
      this.ctx.log(`Sync: skipping excluded path "${normalizedPath}".`);
      return;
    }

    const response = await this.ctx.fetchRemoteFileContent(normalizedPath);
    if (!response.success || !response.data) {
      throw new Error(
        response.error?.message ?? `Failed to read ${normalizedPath} from the server.`
      );
    }

    if (!this.ctx.hasOriginalAdapterWrite()) return;

    let decrypted: string;
    try {
      decrypted = await this.ctx.decodeRemoteFileContent(normalizedPath, response.data);
    } catch (decryptErr) {
      this.ctx.logError(
        `Sync: skipping "${normalizedPath}" — cloud copy could not be decrypted.`,
        decryptErr
      );
      this.ctx.notifyCloudDecryptFallback(normalizedPath);
      return;
    }

    await this.ctx.writeLocalFileFromRemote(normalizedPath, decrypted);
    this.ctx.getSyncState().bytesDownloaded += metadata.size ?? 0;
  }

  async writeLocalFileFromRemote(path: string, content: string): Promise<void> {
    const normalized = this.ctx.normalizeVaultPath(path);
    await this.ctx.ensureParentFoldersForPath(normalized);

    this.ctx.setApplyingRemoteWrite(true);
    try {
      const existing = this.ctx.app.vault.getAbstractFileByPath(normalized);
      if (existing instanceof TFile) {
        await this.ctx.app.vault.modify(existing, content);
        return;
      }

      try {
        await this.ctx.app.vault.create(normalized, content);
      } catch (err) {
        if (!this.ctx.hasOriginalAdapterWrite()) throw err;
        await this.ctx.writePlainToDisk(normalized, content);
      }
    } finally {
      this.ctx.setApplyingRemoteWrite(false);
    }
  }

  async syncFileRenameToServer(oldPath: string, newPath: string): Promise<void> {
    if (!this.ctx.isOnline() || !this.ctx.getKeyLease()) return;
    if (!this.ctx.hasOriginalAdapterRead()) return;

    const oldNormalized = this.ctx.normalizeVaultPath(oldPath);
    const newNormalized = this.ctx.normalizeVaultPath(newPath);
    if (this.isFolderMarkerPath(oldNormalized) || this.isFolderMarkerPath(newNormalized)) {
      return;
    }

    const permission = await this.ctx.getEffectivePermission(newNormalized);
    if (permission < PermissionLevel.WRITE) return;

    let content: string;
    try {
      content = await this.ctx.readPlainFromDisk(newPath);
    } catch (err) {
      this.ctx.log(
        `Rename sync: cannot read "${newPath}" (${err}); skipping server move.`
      );
      return;
    }

    const encrypted = await this.ctx.encryptContent(content);
    const putResp = await this.ctx.apiRequest(
      "PUT",
      this.ctx.vaultPath(`/files/${encodeURIComponent(newNormalized)}`),
      { content: encrypted, hash: await this.ctx.computeHash(content) }
    );
    if (!putResp.success) {
      this.ctx.logError(
        `Rename sync: PUT "${newNormalized}" failed`,
        new Error(putResp.error?.message ?? "unknown")
      );
    }

    const delResp = await this.ctx.apiRequest(
      "DELETE",
      this.ctx.vaultPath(`/files/${encodeURIComponent(oldNormalized)}`)
    );
    if (!delResp.success && delResp.error?.statusCode !== 404) {
      this.ctx.logError(
        `Rename sync: DELETE "${oldNormalized}" failed`,
        new Error(delResp.error?.message ?? "unknown")
      );
    }
    this.ctx.emitPermissionChanged({ path: oldNormalized });
  }

  async syncFileDeleteToServer(path: string): Promise<void> {
    const normalized = this.ctx.normalizeVaultPath(path);
    if (!normalized || this.isFolderMarkerPath(normalized) || this.ctx.isPathExcluded(normalized)) {
      return;
    }

    if (!this.ctx.isOnline()) {
      this.recordDeletionTombstone(normalized);
      this.queueOfflineOperation("delete", normalized);
      return;
    }

    const response = await this.ctx.apiRequest(
      "DELETE",
      this.ctx.vaultPath(`/files/${encodeURIComponent(normalized)}`)
    );
    if (response.success || response.error?.statusCode === 404) {
      this.clearDeletionTombstone(normalized);
    } else if (response.error?.statusCode === 0) {
      this.ctx.setConnectionStatus("offline");
      this.recordDeletionTombstone(normalized);
      this.queueOfflineOperation("delete", normalized);
    } else {
      this.recordDeletionTombstone(normalized);
      this.ctx.logError(
        `Delete sync: DELETE "${normalized}" failed`,
        new Error(response.error?.message ?? "unknown")
      );
    }
    this.ctx.emitPermissionChanged({ path: normalized });
  }

  async performInitialReconciliation(): Promise<boolean> {
    if (!this.ctx.getSession() || !this.ctx.isOnline()) {
      throw new Error("Reconciliation requires an authenticated, online session.");
    }

    new Notice("VaultGuard Sync: Comparing your folder with the server vault…");

    const localFiles = this.ctx.app.vault.getFiles();
    const localManifest = new Map<string, { content: string; hash: string }>();
    for (const file of localFiles) {
      try {
        const normalized = this.ctx.normalizeVaultPath(file.path);
        if (this.ctx.isPathExcluded(normalized)) continue;
        const content = await this.ctx.readPlainFromDisk(file.path);
        const hash = await this.ctx.computeHash(content);
        localManifest.set(`/${normalized}`, { content, hash });
      } catch (err) {
        this.ctx.logError(`Reconciliation: failed to read local file "${file.path}"`, err);
      }
    }

    const inventory = await this.ctx.apiRequest<{
      deltas: Array<{
        path: string;
        action: "created" | "modified" | "deleted";
        lastModified: string;
        checksum: string;
        size: number;
      }>;
      syncTimestamp: string;
    }>("POST", this.ctx.vaultPath("/files/sync"), {
      lastSyncTimestamp: new Date(0).toISOString(),
      fileChecksums: {},
    });

    if (!inventory.success || !inventory.data) {
      throw new Error(
        inventory.error?.message ?? "Could not fetch the server vault inventory."
      );
    }

    const serverPaths = new Set<string>();
    const serverFolderPaths = new Set<string>();
    for (const delta of inventory.data.deltas) {
      if (delta.action === "deleted") continue;
      const normalized = this.ctx.normalizeVaultPath(delta.path);
      if (this.isFolderMarkerPath(normalized)) {
        const folderPath = this.folderPathFromMarkerPath(normalized);
        if (this.ctx.isPathExcluded(folderPath)) continue;
        serverFolderPaths.add(folderPath);
        continue;
      }
      if (this.ctx.isPathExcluded(normalized)) continue;
      serverPaths.add(delta.path);
    }

    const serverOnly: string[] = [];
    const localOnly: string[] = [];
    const conflicts: string[] = [];
    const localManifestBoth: Array<{
      path: string;
      localContent: string;
      localHash: string;
    }> = [];

    for (const path of serverPaths) {
      if (!localManifest.has(path)) {
        serverOnly.push(path);
      }
    }
    for (const [path, entry] of localManifest.entries()) {
      if (!serverPaths.has(path)) {
        localOnly.push(path);
      } else {
        localManifestBoth.push({
          path,
          localContent: entry.content,
          localHash: entry.hash,
        });
      }
    }

    if (this.ctx.isVaultLeaseDenied()) {
      for (const path of serverOnly) {
        const normalized = this.ctx.normalizeVaultPath(path);
        if (this.ctx.isPathExcluded(normalized)) continue;
        if (this.isFolderMarkerPath(normalized)) continue;
        if (this.isPathTombstoned(normalized)) {
          await this.deleteTombstonedServerPath(normalized);
          continue;
        }
        await this.ctx.ensureParentFoldersForPath(normalized);
        await this.ctx.writePlainToDisk(normalized, "");
        this.ctx.getPlaceholderPaths().add(normalized);
      }
      for (const folderPath of serverFolderPaths) {
        if (!folderPath) continue;
        try {
          await this.ctx.ensureLocalFolderPath(folderPath);
        } catch (err) {
          this.ctx.logError(
            `Reconciliation (limited): mkdir for "${folderPath}" failed`,
            err
          );
        }
      }
      const settings = this.ctx.getSettings();
      const syncState = this.ctx.getSyncState();
      settings.bindingReconciledVaultId = settings.serverVaultId;
      syncState.lastSync = inventory.data.syncTimestamp;
      settings.lastSyncTimestamp = inventory.data.syncTimestamp;
      await this.ctx.saveSettings();
      new Notice(
        `VaultGuard Sync: Limited-access reconciliation — ${serverOnly.length} files visible. ` +
          "Open one to fetch its content from the server.",
        6000
      );
      return true;
    }

    const sameContent = new Set<string>();
    for (const item of localManifestBoth) {
      try {
        const remoteContent = await this.ctx.readRemotePlaintext(item.path);
        const remoteHash = await this.ctx.computeHash(remoteContent);
        if (remoteHash === item.localHash) {
          sameContent.add(item.path);
        } else {
          conflicts.push(item.path);
        }
      } catch (err) {
        this.ctx.logError(`Reconciliation: comparison failed for "${item.path}"`, err);
        conflicts.push(item.path);
      }
    }

    const decision = await this.ctx.askReconciliationPlan({
      serverOnly,
      localOnly,
      conflicts,
    });
    if (!decision.proceed) {
      new Notice("VaultGuard Sync: Binding cancelled — no files were modified.");
      return false;
    }

    new Notice(
      `VaultGuard Sync: Reconciling — ↓${serverOnly.length} ↑${localOnly.length} ⚠${conflicts.length}`
    );

    let downloaded = 0;
    let downloadFailed = 0;
    let deletedOnServer = 0;
    for (const path of serverOnly) {
      const normalized = this.ctx.normalizeVaultPath(path);
      if (this.isPathTombstoned(normalized)) {
        if (await this.deleteTombstonedServerPath(normalized)) {
          deletedOnServer += 1;
        }
        continue;
      }
      try {
        await this.ctx.applyRemoteChange({ path: normalized, size: 0 });
        downloaded += 1;
      } catch (err) {
        this.ctx.logError(`Reconciliation: download failed for "${path}"`, err);
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
        const outcome = await this.ctx.uploadReconciledFile(
          this.ctx.normalizeVaultPath(path),
          entry.content
        );
        if (outcome === "uploaded") uploaded += 1;
        else uploadSkipped += 1;
      } catch (err) {
        this.ctx.logError(`Reconciliation: upload failed for "${path}"`, err);
        uploadFailed += 1;
      }
    }

    let conflictsResolved = 0;
    let conflictFailed = 0;
    for (const path of conflicts) {
      try {
        await this.ctx.resolveReconciliationConflict(
          path,
          decision.conflictStrategy,
          localManifest
        );
        conflictsResolved += 1;
      } catch (err) {
        this.ctx.logError(`Reconciliation: conflict resolution failed for "${path}"`, err);
        conflictFailed += 1;
      }
    }

    let foldersUploaded = 0;
    let foldersDownloaded = 0;
    let foldersFailed = 0;

    const localFolderPaths = new Set(this.ctx.collectLocalFolderPaths());

    for (const folderPath of serverFolderPaths) {
      if (!folderPath || localFolderPaths.has(folderPath)) continue;
      try {
        const created = await this.ctx.ensureLocalFolderPath(folderPath);
        if (created) foldersDownloaded += 1;
      } catch (err) {
        this.ctx.logError(`Reconciliation: mkdir for "${folderPath}" failed`, err);
        foldersFailed += 1;
      }
    }

    for (const folderPath of localFolderPaths) {
      if (serverFolderPaths.has(folderPath)) continue;
      try {
        const ok = await this.ctx.uploadFolderMarker(folderPath);
        if (ok) foldersUploaded += 1;
      } catch (err) {
        this.ctx.logError(
          `Reconciliation: folder marker upload for "${folderPath}" failed`,
          err
        );
        foldersFailed += 1;
      }
    }

    const fullySucceeded =
      uploadFailed === 0 &&
      downloadFailed === 0 &&
      conflictFailed === 0 &&
      foldersFailed === 0;

    const settings = this.ctx.getSettings();
    const syncState = this.ctx.getSyncState();
    if (fullySucceeded) {
      settings.bindingReconciledVaultId = settings.serverVaultId;
    }
    syncState.lastSync = inventory.data.syncTimestamp;
    settings.lastSyncTimestamp = inventory.data.syncTimestamp;
    await this.ctx.saveSettings();

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
    if (deletedOnServer > 0) summaryParts.push(`${deletedOnServer} removed on server`);
    if (foldersDownloaded > 0) {
      summaryParts.push(`${foldersDownloaded} folders mirrored locally`);
    }
    if (foldersUploaded > 0) summaryParts.push(`${foldersUploaded} folders preserved`);
    if (sameContent.size > 0) summaryParts.push(`${sameContent.size} already in sync`);
    if (failureParts.length > 0) summaryParts.push(failureParts.join(", "));
    const summary = `${summaryParts.join(", ")}.`;

    if (fullySucceeded) {
      new Notice(`VaultGuard Sync: Reconciliation complete. ${summary}`);
    } else {
      new Notice(
        `VaultGuard Sync: Reconciliation finished with errors — ${summary} Open the sidebar to retry.`,
        10000
      );
    }
    this.ctx.log(`Reconciliation complete: ${summary}`);
    return true;
  }

  async uploadReconciledFile(
    path: string,
    content: string,
    options: { noWriteNotice?: string } = {}
  ): Promise<"uploaded" | "skipped"> {
    if (!this.hasValidKeyLease()) {
      this.ctx.log(`Reconciliation: skipping "${path}" — no encryption key lease available.`);
      new Notice(
        `VaultGuard Sync: Skipped upload of "${path}" — limited access sessions can download accessible files, but need a key lease to encrypt uploads.`
      );
      return "skipped";
    }

    const permission = await this.ctx.getEffectivePermission(path);
    if (permission < PermissionLevel.WRITE) {
      this.ctx.log(`Reconciliation: skipping "${path}" — no write permission.`);
      new Notice(
        options.noWriteNotice ??
          `VaultGuard Sync: Skipped upload of "${path}" — you do not have write permission. The file stays in this folder but is not synced.`
      );
      return "skipped";
    }
    const encrypted = await this.ctx.encryptContent(content);
    const response = await this.ctx.apiRequest(
      "PUT",
      this.ctx.vaultPath(`/files/${encodeURIComponent(path)}`),
      { content: encrypted, hash: await this.ctx.computeHash(content) }
    );
    if (!response.success) {
      throw new Error(response.error?.message ?? `Upload of "${path}" failed.`);
    }
    await this.ctx.emitAuditEvent("file.write", path, { reconciliation: true });
    return "uploaded";
  }

  async removeUnsyncedLocalFile(path: string): Promise<boolean> {
    if (!this.ctx.hasOriginalAdapterRemove()) {
      this.ctx.log(`Catch-up: could not remove local-only "${path}" — adapter remove unavailable.`);
      return false;
    }

    try {
      await this.ctx.removeLocalPath(path);
      this.ctx.emitPermissionChanged({ path });
      return true;
    } catch (err) {
      this.ctx.logError(`Catch-up: failed to remove local-only "${path}"`, err);
      return false;
    }
  }

  async uploadLocalOnlyFiles(): Promise<{
    uploadedFiles: number;
    uploadedFolders: number;
    removedLocalFiles: number;
    skippedFiles: number;
    failedFiles: number;
    failedFolders: number;
  } | null> {
    const settings = this.ctx.getSettings();
    if (!this.ctx.getSession() || !settings.serverVaultId || !this.hasValidKeyLease()) {
      return null;
    }
    if (!this.ctx.hasOriginalAdapterRead()) return null;

    let inventory: { path: string; action: string }[] | null = null;
    try {
      const response = await this.ctx.apiRequest<{
        deltas: Array<{ path: string; action: string }>;
      }>("POST", this.ctx.vaultPath("/files/sync"), {
        lastSyncTimestamp: new Date(0).toISOString(),
        fileChecksums: {},
      });
      if (!response.success || !response.data) {
        this.ctx.log("Catch-up: could not fetch server inventory, skipping.");
        return null;
      }
      inventory = response.data.deltas;
    } catch (err) {
      this.ctx.logError("Catch-up: server inventory fetch failed", err);
      return null;
    }

    const serverFilePaths = new Set<string>();
    const serverFolderPaths = new Set<string>();
    for (const delta of inventory) {
      if (delta.action === "deleted") continue;
      const normalized = this.ctx.normalizeVaultPath(delta.path);
      if (this.isFolderMarkerPath(normalized)) {
        serverFolderPaths.add(this.folderPathFromMarkerPath(normalized));
      } else {
        serverFilePaths.add(`/${normalized}`);
      }
    }

    const localFiles = this.ctx.app.vault.getFiles();
    let uploaded = 0;
    let removedLocal = 0;
    let failed = 0;
    let skipped = 0;
    for (const file of localFiles) {
      const normalized = this.ctx.normalizeVaultPath(file.path);
      if (this.isFolderMarkerPath(normalized)) continue;
      if (this.ctx.isPathExcluded(normalized)) continue;
      const lookupKey = `/${normalized}`;
      if (serverFilePaths.has(lookupKey)) continue;

      try {
        const content = await this.ctx.readPlainFromDisk(file.path);
        const outcome = await this.ctx.uploadReconciledFile(normalized, content, {
          noWriteNotice:
            `VaultGuard Sync: Removed local-only "${normalized}" because this server vault ` +
            "does not contain it and you do not have write permission to add it.",
        });
        if (outcome === "uploaded") {
          uploaded += 1;
        } else {
          skipped += 1;
          if (await this.ctx.removeUnsyncedLocalFile(normalized)) {
            removedLocal += 1;
          }
        }
      } catch (err) {
        failed += 1;
        this.ctx.logError(`Catch-up: upload of "${file.path}" failed`, err);
      }
    }

    let foldersUploaded = 0;
    let foldersFailed = 0;
    for (const folderPath of this.ctx.collectLocalFolderPaths()) {
      if (serverFolderPaths.has(folderPath)) continue;
      if (this.ctx.isPathExcluded(folderPath)) continue;
      try {
        const ok = await this.ctx.uploadFolderMarker(folderPath);
        if (ok) foldersUploaded += 1;
      } catch (err) {
        foldersFailed += 1;
        this.ctx.logError(`Catch-up: folder marker upload for "${folderPath}" failed`, err);
      }
    }

    const totalChanges =
      uploaded + removedLocal + skipped + failed + foldersUploaded + foldersFailed;
    if (totalChanges > 0) {
      const parts: string[] = [];
      if (uploaded > 0) parts.push(`${uploaded} files uploaded`);
      if (removedLocal > 0) parts.push(`${removedLocal} local-only files removed`);
      if (foldersUploaded > 0) parts.push(`${foldersUploaded} folders preserved`);
      if (skipped > 0) parts.push(`${skipped} skipped (no write permission)`);
      if (failed > 0) parts.push(`${failed} files failed`);
      if (foldersFailed > 0) parts.push(`${foldersFailed} folders failed`);
      this.ctx.log(`VaultGuard Sync: Caught up local-only items — ${parts.join(", ")}.`);
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

  async repairMissingRemoteItems(): Promise<{
    downloadedFiles: number;
    downloadedFolders: number;
    failedFiles: number;
    failedFolders: number;
  } | null> {
    const settings = this.ctx.getSettings();
    if (!this.ctx.getSession() || !settings.serverVaultId) return null;
    if (!this.ctx.hasOriginalAdapterWrite()) return null;

    const response = await this.ctx.apiRequest<{
      deltas: Array<{ path: string; action: string; size?: number }>;
    }>("POST", this.ctx.vaultPath("/files/sync"), {
      lastSyncTimestamp: new Date(0).toISOString(),
      fileChecksums: {},
    });

    if (!response.success || !response.data) {
      throw new Error(
        response.error?.message ?? "Could not fetch the server vault inventory."
      );
    }

    const serverFiles: Array<{ path: string; size: number }> = [];
    const serverFolderPaths = new Set<string>();

    for (const delta of response.data.deltas) {
      if (delta.action === "deleted") continue;

      const normalizedPath = this.ctx.normalizeVaultPath(delta.path);
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
      if (this.ctx.isPathExcluded(folderPath)) continue;
      try {
        const created = await this.ctx.ensureLocalFolderPath(folderPath);
        if (created) downloadedFolders += 1;
      } catch (err) {
        failedFolders += 1;
        this.ctx.logError(`Remote repair: mkdir for "${folderPath}" failed`, err);
      }
    }

    let downloadedFiles = 0;
    let failedFiles = 0;
    for (const file of serverFiles) {
      if (this.ctx.isPathExcluded(file.path)) continue;
      if (await this.ctx.localPathExists(file.path)) continue;

      try {
        await this.ctx.applyRemoteChange(file);
        downloadedFiles += 1;
      } catch (err) {
        failedFiles += 1;
        this.ctx.logError(`Remote repair: download of "${file.path}" failed`, err);
      }
    }

    const totalChanges =
      downloadedFiles + downloadedFolders + failedFiles + failedFolders;
    if (totalChanges > 0) {
      const parts: string[] = [];
      if (downloadedFiles > 0) parts.push(`${downloadedFiles} files downloaded`);
      if (downloadedFolders > 0) parts.push(`${downloadedFolders} folders created`);
      if (failedFiles > 0) parts.push(`${failedFiles} files failed`);
      if (failedFolders > 0) parts.push(`${failedFolders} folders failed`);
      this.ctx.log(`VaultGuard Sync: Repaired missing remote items — ${parts.join(", ")}.`);
    }

    return {
      downloadedFiles,
      downloadedFolders,
      failedFiles,
      failedFolders,
    };
  }

  async uploadFolderMarker(folderPath: string): Promise<boolean> {
    const settings = this.ctx.getSettings();
    if (!this.ctx.getSession() || !settings.serverVaultId) return false;
    const normalized = this.ctx.normalizeVaultPath(folderPath);
    if (!normalized) return false;

    const permission = await this.ctx.getEffectivePermission(normalized);
    if (permission < PermissionLevel.WRITE) {
      this.ctx.log(`Folder marker: skipping "${normalized}" — no write permission.`);
      return false;
    }

    const markerPath = this.folderMarkerPath(normalized);
    const markerBody = "\n";
    const markerBase64 = this.ctx.bytesToBase64(new TextEncoder().encode(markerBody));
    const response = await this.ctx.apiRequest(
      "PUT",
      this.ctx.vaultPath(`/files/${encodeURIComponent(markerPath)}`),
      {
        content: markerBase64,
        contentType: "application/x-vaultguard-folder-marker",
        hash: await this.ctx.computeHash(markerBody),
      }
    );
    if (!response.success) {
      throw new Error(
        response.error?.message ?? `Folder marker upload for "${normalized}" failed.`
      );
    }
    return true;
  }

  async deleteFolderMarker(folderPath: string): Promise<void> {
    const settings = this.ctx.getSettings();
    if (!this.ctx.getSession() || !settings.serverVaultId) return;
    const normalized = this.ctx.normalizeVaultPath(folderPath);
    if (!normalized) return;

    const markerPath = this.folderMarkerPath(normalized);
    const response = await this.ctx.apiRequest(
      "DELETE",
      this.ctx.vaultPath(`/files/${encodeURIComponent(markerPath)}`)
    );
    if (!response.success && response.error?.statusCode !== 404) {
      this.ctx.logError(
        `Folder marker delete for "${normalized}" failed`,
        new Error(response.error?.message ?? "unknown")
      );
    }
  }

  async deleteFolderContentsOnServer(folderPath: string): Promise<void> {
    const settings = this.ctx.getSettings();
    if (!this.ctx.getSession() || !settings.serverVaultId) return;
    const normalized = this.ctx.normalizeVaultPath(folderPath);
    if (!normalized) return;

    if (!this.ctx.isOnline()) {
      await this.ctx.deleteFolderMarker(normalized);
      return;
    }

    const prefix = `${normalized}/`;

    let childPaths: string[] = [];
    try {
      const inventory = await this.ctx.apiRequest<{
        deltas: Array<{ path: string; action: string }>;
      }>("POST", this.ctx.vaultPath("/files/sync"), {
        lastSyncTimestamp: new Date(0).toISOString(),
        fileChecksums: {},
        prefix,
      });
      if (inventory.success && inventory.data?.deltas) {
        childPaths = inventory.data.deltas.map((d) => d.path);
      } else if (inventory.error?.statusCode === 0) {
        this.ctx.setConnectionStatus("offline");
        await this.ctx.deleteFolderMarker(normalized);
        return;
      }
    } catch (err) {
      this.ctx.logError(`Folder delete: could not enumerate "${normalized}" on server`, err);
    }

    for (const rawPath of childPaths) {
      const childNormalized = this.ctx.normalizeVaultPath(rawPath);
      if (!childNormalized) continue;
      if (this.ctx.isPathExcluded(childNormalized)) continue;
      if (this.isFolderMarkerPath(childNormalized)) {
        const subFolder = this.folderPathFromMarkerPath(childNormalized);
        await this.ctx.deleteFolderMarker(subFolder);
        continue;
      }
      await this.ctx.syncFileDeleteToServer(childNormalized);
    }

    await this.ctx.deleteFolderMarker(normalized);
  }

  handleFolderCreated(path: string): void {
    const settings = this.ctx.getSettings();
    if (!settings.serverVaultId || !this.ctx.getSession()) return;
    void this.ctx.uploadFolderMarker(path).catch((err) =>
      this.ctx.logError(`Folder create: marker for "${path}" failed`, err)
    );
  }

  handleFolderDeleted(path: string): void {
    const settings = this.ctx.getSettings();
    if (!settings.serverVaultId || !this.ctx.getSession()) return;
    void this.ctx.deleteFolderContentsOnServer(path).catch((err) =>
      this.ctx.logError(`Folder delete: server cleanup for "${path}" failed`, err)
    );
  }

  handleFolderRenamed(path: string, oldPath: string): void {
    const settings = this.ctx.getSettings();
    if (!settings.serverVaultId || !this.ctx.getSession()) return;
    void (async () => {
      try {
        await this.ctx.deleteFolderMarker(oldPath);
        await this.ctx.uploadFolderMarker(path);
      } catch (err) {
        this.ctx.logError(`Folder rename: marker move "${oldPath}" → "${path}" failed`, err);
      }
    })();
  }

  handleVaultFileRenamed(path: string, oldPath: string): void {
    const settings = this.ctx.getSettings();
    if (!settings.serverVaultId || !this.ctx.getSession()) return;
    void this.ctx.syncFileRenameToServer(oldPath, path).catch((err) =>
      this.ctx.logError(`File rename via vault event "${oldPath}" → "${path}" failed`, err)
    );
  }

  handleVaultFileDeleted(path: string): void {
    const settings = this.ctx.getSettings();
    if (!settings.serverVaultId || !this.ctx.getSession()) return;
    void this.ctx.syncFileDeleteToServer(path).catch((err) =>
      this.ctx.logError(`File delete via vault event "${path}" failed`, err)
    );
  }

  async resolveReconciliationConflict(
    path: string,
    strategy: ConflictResolutionStrategy,
    localManifest: Map<string, { content: string; hash: string }>
  ): Promise<void> {
    const normalizedPath = this.ctx.normalizeVaultPath(path);
    const entry = localManifest.get(path);

    switch (strategy) {
      case ConflictResolutionStrategy.KEEP_LOCAL: {
        if (!entry) return;
        await this.ctx.uploadReconciledFile(normalizedPath, entry.content);
        return;
      }
      case ConflictResolutionStrategy.KEEP_REMOTE: {
        await this.ctx.applyRemoteChange({ path: normalizedPath, size: 0 });
        return;
      }
      case ConflictResolutionStrategy.DUPLICATE:
      default: {
        if (entry && this.ctx.hasOriginalAdapterWrite()) {
          const conflictPath = this.generateConflictPath(normalizedPath);
          await this.ctx.writeLocalFileFromRemote(conflictPath, entry.content);
        }
        await this.ctx.applyRemoteChange({ path: normalizedPath, size: 0 });
        return;
      }
    }
  }

  async handleConflict(conflict: SyncConflict): Promise<void> {
    const strategy = this.ctx.getSettings().defaultConflictResolution;
    await this.ctx.emitAuditEvent("sync.conflict", conflict.path, {
      strategy,
      localHash: conflict.localHash,
      remoteHash: conflict.remoteHash,
    });

    switch (strategy) {
      case ConflictResolutionStrategy.KEEP_LOCAL: {
        const localContent = await this.ctx.readPlainFromDisk(conflict.path);
        const encrypted = await this.ctx.encryptContent(localContent);
        await this.ctx.apiRequest(
          "PUT",
          this.ctx.vaultPath(`/files/${encodeURIComponent(conflict.path)}`),
          {
            content: encrypted,
            hash: await this.ctx.computeHash(localContent),
            forceOverwrite: true,
          }
        );
        conflict.resolution = ConflictResolutionStrategy.KEEP_LOCAL;
        break;
      }

      case ConflictResolutionStrategy.KEEP_REMOTE:
        await this.ctx.applyRemoteChange({ path: conflict.path, size: 0 });
        conflict.resolution = ConflictResolutionStrategy.KEEP_REMOTE;
        break;

      case ConflictResolutionStrategy.DUPLICATE: {
        const conflictPath = this.generateConflictPath(conflict.path);
        const localContent = await this.ctx.readPlainFromDisk(conflict.path);
        await this.ctx.writePlainToDisk(conflictPath, localContent);
        await this.ctx.applyRemoteChange({ path: conflict.path, size: 0 });
        conflict.resolution = ConflictResolutionStrategy.DUPLICATE;
        break;
      }

      case ConflictResolutionStrategy.ASK_USER:
      default:
        new Notice(
          `VaultGuard Sync: Sync conflict detected for "${conflict.path}". Use View Permissions to resolve.`
        );
        break;
    }
  }

  hasValidKeyLease(): boolean {
    return !!this.ctx.getKeyLease() && !this.isKeyLeaseExpired();
  }

  /**
   * Starts the server heartbeat loop. The backend returns `active:false`
   * within roughly one minute of user/session/key revocation, letting the
   * plugin clear leases and fail closed instead of waiting for Cognito JWT
   * or DEK lease expiry.
   */
  startHeartbeatMonitor(): void {
    this.stopHeartbeatMonitor();
    if (!this.ctx.getSession()) return;

    const timer = setInterval(
      () => void this.checkRevocationHeartbeat(),
      HEARTBEAT_INTERVAL_MS
    );
    this.ctx.setHeartbeatTimer(timer);
    void this.checkRevocationHeartbeat();
  }

  stopHeartbeatMonitor(): void {
    const timer = this.ctx.getHeartbeatTimer();
    if (timer) {
      clearInterval(timer);
      this.ctx.setHeartbeatTimer(null);
    }
  }

  async checkRevocationHeartbeat(): Promise<void> {
    const session = this.ctx.getSession();
    if (!session) return;

    const params = new URLSearchParams({ sessionId: session.sessionId });
    const response = await this.ctx.apiRequest<{ active: boolean; reason?: string }>(
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

  async handleServerRevocation(reason: string): Promise<void> {
    this.ctx.setKeyLease(null);
    this.ctx.invalidatePermissionStore();
    await this.ctx.forceLogout(
      `VaultGuard Sync: Access revoked (${reason}). Local session cleared.`
    );
  }

  /**
   * Starts the periodic key lease renewal monitor.
   * Checks every minute if the lease needs renewal.
   */
  startKeyRenewalMonitor(): void {
    this.stopKeyRenewalMonitor();
    const timer = setInterval(
      () => this.checkKeyLeaseRenewal(),
      KEY_RENEWAL_INTERVAL_MS
    );
    this.ctx.setKeyRenewalTimer(timer);
  }

  /**
   * Stops the key lease renewal monitor.
   */
  stopKeyRenewalMonitor(): void {
    const timer = this.ctx.getKeyRenewalTimer();
    if (timer) {
      clearInterval(timer);
      this.ctx.setKeyRenewalTimer(null);
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
  async checkKeyLeaseRenewal(): Promise<void> {
    if (!this.ctx.getSession()) {
      return;
    }

    const keyLease = this.ctx.getKeyLease();
    if (!keyLease) {
      // Limited-access recovery path. Only retry when the previous attempt
      // explicitly returned 403 - otherwise we'd hammer the API with lease
      // requests for sessions that legitimately have no vault binding yet.
      if (this.ctx.isVaultLeaseDenied() && this.ctx.getSettings().serverVaultId) {
        try {
          const result = await this.ctx.ensureVaultScopedKeyLease();
          if (result === "ok") {
            this.ctx.log("Vault-scoped key lease recovered — full access restored.");
            this.ctx.showNotice("VaultGuard Sync: Full vault access restored.");
            this.ctx.emitPermissionChanged({ serverConfirmed: true });
            this.ctx.clearPlaceholderPaths();
          }
        } catch (err) {
          // Network blips and 5xxs are expected during recovery polling.
          // Stay in limited-access state and try again next tick.
          this.ctx.logError("Limited-access lease retry failed (will retry)", err);
        }
      }
      return;
    }

    const expiresAt = new Date(keyLease.expiresAt).getTime();
    const now = Date.now();
    const timeUntilExpiry = expiresAt - now;

    if (timeUntilExpiry <= KEY_RENEWAL_GRACE_MS) {
      await this.ctx.renewKeyLease();
    }
  }

  /**
   * Checks if the current key lease has expired.
   * @returns true if expired or no lease exists
   */
  isKeyLeaseExpired(): boolean {
    const keyLease = this.ctx.getKeyLease();
    if (!keyLease) {
      return true;
    }
    return new Date(keyLease.expiresAt).getTime() < Date.now();
  }

  parentFolderPathsFor(path: string): string[] {
    const segments = this.ctx.normalizeVaultPath(path).split("/").filter(Boolean);
    segments.pop();

    const folders: string[] = [];
    let current = "";
    for (const segment of segments) {
      current = current ? `${current}/${segment}` : segment;
      folders.push(current);
    }
    return folders;
  }

  /** True if `path` (no leading slash) ends in the folder-marker basename. */
  isFolderMarkerPath(path: string): boolean {
    if (!path) return false;
    const segments = path.split("/").filter(Boolean);
    return segments.length > 0 && segments[segments.length - 1] === FOLDER_MARKER_NAME;
  }

  /** Strips the marker basename to recover the parent folder's vault-relative path. */
  folderPathFromMarkerPath(markerPath: string): string {
    const segments = markerPath.split("/").filter(Boolean);
    segments.pop();
    return segments.join("/");
  }

  /**
   * Composes the marker file path the plugin writes to keep `folderPath`
   * alive on the server. Always normalised, never with a leading slash.
   * Throws if asked for the root marker, because root is implicit.
   */
  folderMarkerPath(folderPath: string): string {
    const normalized = this.ctx.normalizeVaultPath(folderPath);
    if (!normalized) {
      throw new Error("VaultGuard Sync: refused to plant a folder marker at the vault root.");
    }
    return `${normalized}/${FOLDER_MARKER_NAME}`;
  }

  /**
   * Builds the path manifest sent on `/files/sync` so the server can detect
   * deletions. Values stay empty strings; only path presence matters here.
   */
  buildLocalSyncManifest(input: LocalSyncManifestInput): Record<string, string> {
    const manifest: Record<string, string> = {};
    const seen = new Set<string>();

    const addPath = (rawPath: string): void => {
      const normalized = this.ctx.normalizeVaultPath(rawPath);
      if (!normalized) return;
      if (this.ctx.isPathExcluded(normalized)) return;
      const key = `/${normalized}`;
      if (seen.has(key)) return;
      seen.add(key);
      manifest[key] = "";
    };

    for (const filePath of input.filePaths) {
      addPath(filePath);
    }

    // Folder markers are server-only sentinels; produce them from local
    // folders so the server doesn't see the marker as "deleted" just because
    // we didn't enumerate it.
    for (const folderPath of input.folderPaths) {
      if (this.ctx.isPathExcluded(folderPath)) continue;
      try {
        addPath(this.folderMarkerPath(folderPath));
      } catch {
        // Root folder has no marker; skip silently.
      }
    }

    return manifest;
  }

  /**
   * Generates a conflict-suffixed file path for duplicate resolution.
   * @param originalPath - The original conflicted file path
   * @returns A new path with conflict timestamp suffix
   */
  generateConflictPath(originalPath: string): string {
    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const lastDot = originalPath.lastIndexOf(".");
    if (lastDot > 0) {
      return `${originalPath.slice(0, lastDot)} (conflict ${timestamp})${originalPath.slice(lastDot)}`;
    }
    return `${originalPath} (conflict ${timestamp})`;
  }

  decodeBase64Utf8(base64: string): string {
    return new TextDecoder().decode(this.base64ToBytes(base64));
  }

  remoteDecryptError(path: string, error: unknown): Error {
    const message = error instanceof Error ? error.message : String(error);
    const wrapped = new Error(
      `VaultGuard Sync: could not decrypt server copy of "${path}": ${message}`
    );
    wrapped.name = "VaultGuardRemoteDecryptError";
    return wrapped;
  }

  /**
   * Record a tombstone for a locally-deleted path. No-ops for empty, excluded,
   * or folder-marker paths (those never reach the server, so they must never be
   * tombstoned or retried). Persists fire-and-forget.
   */
  recordDeletionTombstone(path: string): void {
    const normalized = this.ctx.normalizeVaultPath(path);
    if (!normalized) return;
    if (this.ctx.isPathExcluded(normalized)) return;
    if (this.isFolderMarkerPath(normalized)) return;
    const settings = this.ctx.getSettings();
    if (!settings.deletionTombstones) settings.deletionTombstones = {};
    settings.deletionTombstones[normalized] = new Date().toISOString();
    this.ctx.log(`Recorded deletion tombstone for "${normalized}".`);
    void this.ctx.saveSettings().catch((error) => {
      this.ctx.logError("Failed to persist deletion tombstone", error);
    });
  }

  /**
   * Clear a tombstone once the server confirms the delete (success or 404 =
   * already-gone), or rejects it permanently (401/403). No-op if absent.
   */
  clearDeletionTombstone(path: string): void {
    const normalized = this.ctx.normalizeVaultPath(path);
    if (!normalized) return;
    const settings = this.ctx.getSettings();
    if (!settings.deletionTombstones) return;
    if (settings.deletionTombstones[normalized] === undefined) return;
    delete settings.deletionTombstones[normalized];
    this.ctx.log(`Cleared deletion tombstone for "${normalized}".`);
    void this.ctx.saveSettings().catch((error) => {
      this.ctx.logError("Failed to persist deletion tombstone removal", error);
    });
  }

  /** True if a tombstone exists for the given (normalized) path. */
  isPathTombstoned(path: string): boolean {
    const normalized = this.ctx.normalizeVaultPath(path);
    if (!normalized) return false;
    return Boolean(this.ctx.getSettings().deletionTombstones?.[normalized]);
  }

  /**
   * Drop tombstones older than DELETION_TOMBSTONE_TTL_MS (and any malformed /
   * unparseable timestamps). Called once at the end of loadSettings; does NOT
   * save - the next normal save persists the pruned set.
   */
  pruneDeletionTombstones(): void {
    const tombstones = this.ctx.getSettings().deletionTombstones;
    if (!tombstones) return;
    const now = Date.now();
    for (const [path, deletedAt] of Object.entries(tombstones)) {
      const ts = Date.parse(deletedAt);
      if (Number.isNaN(ts) || now - ts > DELETION_TOMBSTONE_TTL_MS) {
        delete tombstones[path];
      }
    }
  }

  /**
   * Re-attempt any outstanding tombstoned deletes against the server. Wired
   * into performSync Phase 1 (after the offline-queue flush). A server DELETE
   * needs no key lease; gating it with the existing flush keeps one
   * well-understood entry point. Success / 404 clears the tombstone; a
   * transient (statusCode 0) failure marks offline and stops (retry next
   * online); 401/403 clears it (the server decided).
   */
  async retryOutstandingDeletions(): Promise<void> {
    const settings = this.ctx.getSettings();
    if (!this.ctx.getSession() || !settings.serverVaultId || !this.ctx.isOnline()) return;
    const tombstones = settings.deletionTombstones;
    if (!tombstones) return;
    const paths = Object.keys(tombstones);
    if (paths.length === 0) return;

    for (const path of paths) {
      const normalized = this.ctx.normalizeVaultPath(path);
      if (!normalized) {
        this.clearDeletionTombstone(path);
        continue;
      }
      if (this.ctx.isPathExcluded(normalized) || this.isFolderMarkerPath(normalized)) {
        this.clearDeletionTombstone(normalized);
        continue;
      }
      const response = await this.ctx.apiRequest(
        "DELETE",
        this.ctx.vaultPath(`/files/${encodeURIComponent(normalized)}`)
      );
      if (response.success || response.error?.statusCode === 404) {
        this.clearDeletionTombstone(normalized);
        continue;
      }
      if (response.error?.statusCode === 0) {
        // Transient - stop and retry on the next online sync.
        this.ctx.setConnectionStatus("offline");
        return;
      }
      if (response.error?.statusCode === 401 || response.error?.statusCode === 403) {
        // The server permanently rejected the delete - do not loop forever.
        this.clearDeletionTombstone(normalized);
        continue;
      }
      // Other failures (5xx etc.): leave the tombstone in place to retry later.
      this.ctx.logError(
        `Deletion retry: DELETE "${normalized}" failed`,
        new Error(response.error?.message ?? "unknown")
      );
    }
  }

  /**
   * Layer 3 reconciliation guard: issue a server-side DELETE for a tombstoned
   * serverOnly path (so a re-bind does not resurrect a locally-deleted file)
   * and clear the tombstone on success/404. On other failures the tombstone is
   * left in place to retry via retryOutstandingDeletions. Returns true on a
   * settled delete (the caller should skip downloading/placeholdering the path).
   * `normalized` must be a vault-relative path with no leading slash.
   */
  async deleteTombstonedServerPath(normalized: string): Promise<boolean> {
    if (!normalized) return false;
    try {
      const response = await this.ctx.apiRequest(
        "DELETE",
        this.ctx.vaultPath(`/files/${encodeURIComponent(normalized)}`)
      );
      if (response.success || response.error?.statusCode === 404) {
        this.clearDeletionTombstone(normalized);
        this.ctx.log(`Reconciliation: deleted tombstoned server path "${normalized}".`);
        return true;
      }
      this.ctx.logError(
        `Reconciliation: server delete of tombstoned path "${normalized}" failed`,
        new Error(response.error?.message ?? "unknown")
      );
    } catch (err) {
      this.ctx.logError(
        `Reconciliation: server delete of tombstoned path "${normalized}" threw`,
        err
      );
    }
    return false;
  }

  /**
   * Queues an operation for later execution when connectivity is restored.
   * @param operation - The type of operation
   * @param path - The file path
   * @param data - Optional file content (for write operations)
   */
  queueOfflineOperation(
    operation: OfflineQueueOperation["operation"],
    path: string,
    data?: string
  ): void {
    // Deduplicate: remove existing operations for the same path
    this.ctx.setOfflineQueue(this.ctx.getOfflineQueue().filter((op) => op.path !== path));

    this.ctx.setOfflineQueue([
      ...this.ctx.getOfflineQueue(),
      {
        operation,
        path,
        data,
        timestamp: new Date().toISOString(),
      },
    ]);

    this.ctx.log(
      `Queued offline operation: ${operation} "${path}" (queue size: ${this.ctx.getOfflineQueue().length})`
    );
  }

  /**
   * Flushes all queued offline operations to the server.
   * Operations are sent in chronological order.
   */
  async flushOfflineQueue(): Promise<void> {
    const inFlight = this.ctx.getOfflineQueueFlushPromise();
    if (inFlight) {
      return inFlight;
    }

    const flushPromise = this.runOfflineQueueFlush();
    this.ctx.setOfflineQueueFlushPromise(flushPromise);

    try {
      await flushPromise;
    } finally {
      if (this.ctx.getOfflineQueueFlushPromise() === flushPromise) {
        this.ctx.setOfflineQueueFlushPromise(null);
      }
    }
  }

  async runOfflineQueueFlush(): Promise<void> {
    if (this.ctx.getOfflineQueue().length === 0) {
      return;
    }

    this.ctx.log(`Flushing ${this.ctx.getOfflineQueue().length} queued operations...`);
    const queue = [...this.ctx.getOfflineQueue()];
    this.ctx.setOfflineQueue([]);

    for (let index = 0; index < queue.length; index++) {
      const op = queue[index];
      // Local-only opt-out: drop any queued op whose path the user has
      // since added to the exclusion list, so we don't quietly upload it.
      if (this.ctx.isPathExcluded(op.path)) {
        continue;
      }
      try {
        switch (op.operation) {
          case "write":
            if (op.data) {
              const encrypted = await this.ctx.encryptContent(op.data);
              const response = await this.ctx.apiRequest("PUT", this.ctx.vaultPath(`/files/${encodeURIComponent(op.path)}`), {
                content: encrypted,
                hash: await this.ctx.computeHash(op.data),
              });
              this.assertOfflineFlushResponse(response, op);
            }
            break;
          case "delete": {
            const response = await this.ctx.apiRequest(
              "DELETE",
              this.ctx.vaultPath(`/files/${encodeURIComponent(op.path)}`)
            );
            // Returns on success / 404 / 401 / 403 (throws on other failures,
            // leaving the tombstone in place to retry). Any return means the
            // server has settled this delete - clear its tombstone.
            this.assertOfflineFlushResponse(response, op);
            this.clearDeletionTombstone(op.path);
            break;
          }
        }
      } catch (error) {
        // Re-queue this operation and everything after it to preserve order.
        this.ctx.getOfflineQueue().push(op, ...queue.slice(index + 1));
        this.ctx.logError(`Failed to flush operation: ${op.operation} "${op.path}"`, error);
        if (this.ctx.isNetworkError(error)) {
          this.ctx.setConnectionStatus("offline");
        }
        break;
      }
    }

    if (this.ctx.getOfflineQueue().length > 0) {
      this.ctx.log(
        `${this.ctx.getOfflineQueue().length} operations remain in queue after flush.`
      );
    }
  }

  assertOfflineFlushResponse(
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
      this.ctx.logError(
        `Dropping queued ${op.operation} for "${op.path}" after server rejection`,
        new Error(message)
      );
      return;
    }

    throw new Error(message);
  }

  getSnapshot(): SyncRuntimeSnapshot {
    return {
      syncState: this.ctx.getSyncState(),
      connectionState: this.ctx.getConnectionState(),
      keyLease: this.ctx.getKeyLease(),
      vaultLeaseDenied: this.ctx.isVaultLeaseDenied(),
      placeholderPathsSize: this.ctx.getPlaceholderPathsSize(),
      offlineQueueLength: this.ctx.getOfflineQueueLength(),
      deletionTombstonesCount: this.ctx.getDeletionTombstonesCount(),
      syncTimerAlive: this.ctx.isSyncTimerAlive(),
      syncTimerPaused: this.ctx.isSyncTimerPaused(),
      keyRenewalTimerAlive: this.ctx.isKeyRenewalTimerAlive(),
      heartbeatTimerAlive: this.ctx.isHeartbeatTimerAlive(),
      connectionRetryTimerAlive: this.ctx.isConnectionRetryTimerAlive(),
      connectionLostNoticeTimerAlive: this.ctx.isConnectionLostNoticeTimerAlive(),
      applyingRemoteWrite: this.ctx.isApplyingRemoteWrite(),
      folderLifecycleListenersRegistered:
        this.ctx.isFolderLifecycleListenersRegistered(),
    };
  }

  shutdown(): void {
    this.stopSyncTimer();
    this.stopKeyRenewalMonitor();
    this.stopHeartbeatMonitor();
  }

  private base64ToBytes(base64: string): Uint8Array {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
}

export function createSyncRuntime(ctx: SyncRuntimeContext): SyncRuntime {
  return new SyncRuntime(ctx);
}
