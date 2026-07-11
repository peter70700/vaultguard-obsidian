import { Notice, TFile } from "obsidian";
import type {
  LocalManifestEntry,
  OfflineQueueOperation,
  RemoteFileContentResponse,
  RemoteFileWriteResponse,
  RemoteWriteConflictResolutionResult,
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
// BIN-A: byte push + flush fork reuse the shared size ceiling (OD-3), the
// large-body upload timeout (L2), and the outgoing-MIME map.
import {
  BINARY_PUT_TIMEOUT_MS,
  BINARY_SYNC_MAX_BYTES,
  contentTypeForPath,
  isBinaryContentType,
  isKnownBinaryExtensionPath,
} from "./binary-content";
import {
  DEFAULT_LONG_OPERATION_BATCH_SIZE,
  DEFAULT_STALLED_OPERATION_MS,
  describeConflict,
  isLongOperationConflict,
  yieldToEventLoop,
  type LongOperationHandle,
} from "./long-operation";

export interface LocalSyncManifestInput {
  filePaths: string[];
  folderPaths: string[];
}

/**
 * Discriminated outcome of a reconciliation upload. The distinction matters for
 * data safety (SY2): only `skipped-no-permission` — and only once the
 * permission store has actually warmed — may lead a caller to remove a
 * local-only file. `skipped-no-lease` is transient (a lease may still return)
 * and must never trigger deletion.
 */
export type UploadReconciledOutcome =
  | "uploaded"
  | "skipped-no-lease"
  | "skipped-no-permission";

/**
 * BIN-A / D-07: byte-upload outcome. Every text outcome (SY2) plus
 * `skipped-too-large` — the client-side `BINARY_SYNC_MAX_BYTES` ceiling (OD-3),
 * enforced BEFORE any encrypt/network work and permanent until the BIN-B
 * presigned-URL path ships. Like `skipped-no-lease`, `skipped-too-large` is
 * fail-closed: a caller must NEVER delete or overwrite the local file on it —
 * the on-disk bytes are the only copy of an attachment that could not be pushed
 * (SY2 extended). Only `skipped-no-permission` (on a warmed store) may lead to
 * local removal.
 *
 * This is a superset SIBLING of UploadReconciledOutcome rather than a widening
 * of it, so the string uploadReconciledFile contract (and its ctx forwarding)
 * stays narrow — the text path can never return `skipped-too-large`, so no
 * text-path caller has to guard a case it cannot produce.
 */
export type UploadReconciledBinaryOutcome =
  | UploadReconciledOutcome
  | "skipped-too-large";

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

/**
 * BIN-A: per-path throttle window for the "binary too large" Notice, so a
 * repeated oversize file does not re-notify on every push pass.
 */
const BINARY_TOO_LARGE_NOTICE_THROTTLE_MS = 60_000;

/** Grace period before key expiry to trigger renewal (5 minutes). */
const KEY_RENEWAL_GRACE_MS = 5 * 60 * 1000;

/** Server heartbeat interval for revocation detection. */
const HEARTBEAT_INTERVAL_MS = 60 * 1000;

/** Periodic key-lease renewal check cadence. */
const KEY_RENEWAL_INTERVAL_MS = 60 * 1000;

/**
 * BIN-A / L3: chunked Uint8Array → base64 for queuing a binary rename payload.
 * Mirrors main.ts's bytesToBase64 and at-rest-adapter-runtime.ts's
 * uint8ToBase64Chunked (0x8000-byte slices via String.fromCharCode.apply) —
 * browser-native (no Node Buffer, mobile constraint) and GC-friendly at 7 MB.
 * Duplicated per module per repo convention (no cross-module barrel imports for
 * tiny helpers). Output is byte-identical to a per-byte reference loop, and the
 * base64ToBytes method below is its exact inverse for the flush replay.
 */
function uint8ToBase64Chunked(bytes: Uint8Array): string {
  const CHUNK_SIZE = 0x8000;
  let binary = "";
  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
    const chunk = bytes.subarray(i, i + CHUNK_SIZE);
    binary += String.fromCharCode.apply(null, chunk as unknown as number[]);
  }
  return btoa(binary);
}

/**
 * Runtime for sync behavior extracted from the plugin entrypoint.
 *
 * This runtime intentionally owns no sync state. The plugin entrypoint supplies
 * state and integration callbacks while sync orchestration, reconciliation,
 * remote apply, folder lifecycle, and deletion propagation live here.
 */
export class SyncRuntime {
  private currentSyncOperation: LongOperationHandle | null = null;

  constructor(private readonly ctx: SyncRuntimeContext) {}

  /**
   * BIN-A / L10/L12: per-path throttle for the "binary too large" Notice. This
   * is presentation state only (not sync state) — it prevents a repeated
   * oversize file from re-notifying on every push pass. Mirrors the
   * `binaryWriteNoticeAt` throttle interceptedRename established in 11-02.
   */
  private readonly binaryTooLargeNoticeAt = new Map<string, number>();

  private isLocalProjectMemoryMode(): boolean {
    return this.ctx.getSettings().localProjectMemoryMode === true;
  }

  private buildWriteBody(
    path: string,
    encryptedContent: string,
    hash: string,
    options: { forceOverwrite?: boolean; expectedVersionId?: string | null } = {}
  ): Record<string, unknown> {
    const body: Record<string, unknown> = {
      content: encryptedContent,
      hash,
    };
    const expectedVersionId =
      options.expectedVersionId === undefined
        ? this.ctx.getExpectedVersionId(path)
        : options.expectedVersionId ?? undefined;
    if (!options.forceOverwrite && expectedVersionId) {
      body.expectedVersionId = expectedVersionId;
    }
    return body;
  }

  private buildDeleteBody(
    path: string,
    expectedVersionId = this.ctx.getExpectedVersionId(path)
  ): Record<string, unknown> | undefined {
    return expectedVersionId ? { expectedVersionId } : undefined;
  }

  private recordSuccessfulWrite(
    path: string,
    hash: string,
    response: ApiResponse<RemoteFileWriteResponse>
  ): void {
    if (!response.success) return;
    this.ctx.recordRemoteFilePresent(path, {
      versionId: response.data?.versionId,
      baseHash: hash,
      checksum: response.data?.checksum,
      lastModified: response.data?.lastModified,
      size: response.data?.size,
    });
  }

  private recordRemoteReadState(
    path: string,
    data: RemoteFileContentResponse,
    plaintextHash: string
  ): void {
    this.ctx.recordRemoteFilePresent(path, {
      versionId: data.versionId,
      baseHash: plaintextHash,
      checksum: data.checksum,
      lastModified: data.lastModified,
      size: data.size,
    });
  }

  async initializeSyncEngine(): Promise<void> {
    if (this.isLocalProjectMemoryMode()) {
      this.ctx.log("Sync engine disabled by Local Project Memory Mode.");
      this.ctx.recordSyncDiagnostic("initializeSyncEngine.skipped", {
        reason: "localProjectMemoryMode",
      });
      this.stopSyncTimer();
      return;
    }
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
    if (this.isLocalProjectMemoryMode()) {
      this.ctx.log("Sync timer disabled by Local Project Memory Mode.");
      this.ctx.recordSyncDiagnostic("startSyncTimer.skipped", {
        reason: "localProjectMemoryMode",
      });
      return;
    }
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
    if (this.isLocalProjectMemoryMode()) {
      this.stopSyncTimer();
      return;
    }
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
    if (this.isLocalProjectMemoryMode()) return;
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

    if (this.isLocalProjectMemoryMode()) {
      const message =
        "VaultGuard Sync: Sync skipped — Local Project Memory Mode keeps this vault plaintext and local-only.";
      this.ctx.log(message);
      if (userInitiated) this.ctx.showNotice(message);
      this.ctx.recordSyncDiagnostic("performSync.skipped", {
        reason: "localProjectMemoryMode",
      });
      return;
    }

    if (!this.ctx.getSession()) {
      const message = userInitiated
        ? this.ctx.showLoginRequiredNotice("sync")
        : "VaultGuard Sync: Sync skipped — not logged in.";
      this.ctx.log(message);
      this.ctx.recordSyncDiagnostic("performSync.skipped", { reason: "notLoggedIn" });
      return;
    }
    // Authoritative lock backstop: while the vault is locked the LAK is evicted
    // (atRestCipher.lock() in enterLockState), so isReady() is false and any
    // pulled server change would hit writePlainToDisk's fail-closed guard and
    // throw "refusing to write … local at-rest encryption is unavailable". The
    // periodic timer is already stopped on lock, but the focus/visibility
    // triggers reach performSync directly — this guard covers every caller.
    // exitLockState restarts the timer and pulls on unlock, so nothing is lost.
    if (this.ctx.isVaultLocked?.()) {
      const message = "VaultGuard Sync: Sync skipped — vault is locked.";
      this.ctx.log(message);
      if (userInitiated) this.ctx.showNotice(message);
      this.ctx.recordSyncDiagnostic("performSync.skipped", { reason: "vaultLocked" });
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

    let operation: LongOperationHandle;
    try {
      operation = this.ctx.beginLongOperation({
        kind: userInitiated ? "sync" : "background-sync",
        operationName: userInitiated ? "Sync now" : "Background sync",
        phase: "Queued",
        placement: "background",
        approximatePercent: true,
        percent: 2,
        capabilities: {
          protectedPhase: false,
          canCancel: false,
          canPause: false,
        },
        conflictsWith: ["sync", "background-sync", "vault-encrypt", "vault-decrypt", "initial-reconciliation"],
        stalledAfterMs: DEFAULT_STALLED_OPERATION_MS,
      });
    } catch (error) {
      if (isLongOperationConflict(error)) {
        const message = `VaultGuard Sync: ${describeConflict(error.conflict)}`;
        this.ctx.log(message);
        if (userInitiated) this.ctx.showNotice(message, 6000);
        this.ctx.recordSyncDiagnostic("performSync.skipped", {
          reason: "longOperationConflict",
          conflictKind: error.conflict.kind,
        });
        return;
      }
      throw error;
    }
    this.currentSyncOperation = operation;

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
      operation.update({
        phase: "Preparing sync",
        percent: 5,
        approximatePercent: true,
      });
      this.ctx.updateStatusBar();

      // Phase 1: Upload queued offline operations
      const offlineQueueSizeBefore = this.ctx.getOfflineQueueLength();
      operation.update({
        phase: "Flushing queued changes",
        processedItems: 0,
        totalItems: offlineQueueSizeBefore,
        percent: 10,
        approximatePercent: true,
      });
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
        operation.update({
          phase: "Catching up local-only files",
          percent: 25,
          approximatePercent: true,
        });
        const result = await this.ctx.uploadLocalOnlyFiles();
        if (result) {
          totalFilesUploaded += result.uploadedFiles;
          totalFoldersUploaded += result.uploadedFolders;
          totalFilesRemoved += result.removedLocalFiles;
          catchupChanges =
            result.uploadedFiles + result.uploadedFolders + result.removedLocalFiles;
          // SY7: only mark catch-up complete when nothing failed. A transient
          // upload/folder failure previously still flipped the flag true, so
          // catch-up never re-ran (until forceCatchup) and the affected files
          // stayed local-only and unsynced indefinitely.
          this.ctx.setLocalOnlyCatchupCompleted(
            result.failedFiles === 0 && result.failedFolders === 0
          );
        }
      }

      // Phase 1c: Cursor short-circuit.
      const canShortCircuit =
        !flushedSomething &&
        catchupChanges === 0 &&
        !forceCatchup &&
        syncState.lastSeenRevision != null;

      if (canShortCircuit) {
        operation.update({
          phase: "Checking server cursor",
          percent: 45,
          approximatePercent: true,
        });
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
            operation.complete("Already in sync — nothing to do.");
            return;
          }
        }
      }

      // Phase 2: Fetch remote changes since last sync
      operation.update({
        phase: "Building local sync manifest",
        percent: 50,
        approximatePercent: true,
      });
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
      operation.update({
        phase: "Applying remote changes",
        processedItems: 0,
        totalItems: deltaCount,
        ...(deltaCount === 0 ? { percent: 70 } : {}),
        approximatePercent: false,
        message: `${deltaCount} remote change(s) received.`,
      });

      let appliedDeltaIndex = 0;
      let appliedDeltaBytes = 0;
      for (const delta of response.data.deltas) {
        appliedDeltaIndex += 1;
        const normalizedPath = this.ctx.normalizeVaultPath(delta.path);
        try {

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

          // SY5: a path with a pending offline op is locally DIRTY — its queued
          // write/delete never reached the server (limited-access skips the
          // Phase-1 flush entirely). Applying the remote delta would overwrite
          // the user's local edit with the older server copy, or delete a file
          // they just changed. Leave the path alone; the flush and the next
          // sync cycle reconcile it.
          if (this.hasPendingOfflineOperation(normalizedPath)) {
            this.ctx.log(
              `Sync: skipping remote delta for "${normalizedPath}" — a queued local operation is pending.`
            );
            continue;
          }

          if (delta.action === "deleted") {
            // Cold-path (full-scan) deletions are INFERRED from manifest-vs-S3
            // absence and must be recoverable; warm-path (activity-log) deletions
            // are real events and delete permanently. Anything not explicitly
            // "activity-log" is treated as inferred (the safe, recoverable side).
            const inferred = response.data.mode !== "activity-log";
            await this.ctx.applyRemoteDeletion(normalizedPath, inferred);
            continue;
          }

          await this.ctx.applyRemoteChange({
            path: normalizedPath,
            size: delta.size,
          });
          appliedDeltaBytes += delta.size ?? 0;
        } finally {
          operation.update({
            phase: "Applying remote changes",
            processedItems: appliedDeltaIndex,
            totalItems: deltaCount,
            processedBytes: appliedDeltaBytes,
            message: `${appliedDeltaIndex} of ${deltaCount} remote change(s) processed.`,
          });
          if (appliedDeltaIndex % DEFAULT_LONG_OPERATION_BATCH_SIZE === 0) {
            await yieldToEventLoop();
          }
        }
      }

      // Phase 2b: repair missing server-side items that are older than our
      // lastSyncTimestamp.
      if (forceCatchup || !this.ctx.getRemoteInventoryRepairCompleted()) {
        operation.update({
          phase: "Repairing missing remote items",
          percent: 85,
          approximatePercent: true,
        });
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
      operation.complete(
        summaryParts.length === 0
          ? "Already in sync — nothing to do."
          : `Sync complete — ${summaryParts.join(", ")}.`,
      );
      if (userInitiated) {
        if (summaryParts.length === 0) {
          this.ctx.showNotice("VaultGuard Sync: Already in sync — nothing to do.");
        } else {
          this.ctx.showNotice(`VaultGuard Sync: Sync complete — ${summaryParts.join(", ")}.`);
        }
      }
      this.ctx.recordSyncDiagnostic("performSync.done", { ok: true });
    } catch (error) {
      operation.fail(error);
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
      if (this.currentSyncOperation === operation) {
        this.currentSyncOperation = null;
      }
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
    const plaintext = await this.ctx.decodeRemoteFileContent(normalizedPath, response.data);
    this.recordRemoteReadState(
      normalizedPath,
      response.data,
      await this.ctx.computeHash(plaintext)
    );
    return plaintext;
  }

  async applyRemoteDeletion(normalizedPath: string, inferred: boolean): Promise<void> {
    this.ctx.recordRemoteFileAbsent(normalizedPath);
    if (!this.ctx.hasOriginalAdapterRemove()) return;

    if (inferred) {
      // Cold-path deletions are inferred from "in your manifest but not in S3",
      // which cannot tell a real remote delete apart from a file this client
      // never uploaded (edits made in limited-access mode, a memory-only offline
      // queue lost across a restart, or a catch-up upload that failed). A
      // routine event like an admin permission-rule change forces this cold
      // path, so hard-deleting here permanently destroys never-uploaded local
      // content. Per the never-wipe-on-ambiguity invariant, move the file to the
      // vault's recoverable trash instead.
      const trashed = await this.ctx.trashLocalPath(normalizedPath);
      if (trashed) {
        this.ctx.log(
          `Sync: inferred deletion of "${normalizedPath}" moved to local trash (recoverable), not permanently deleted.`
        );
        return;
      }
      // No trash support → do NOT hard-delete. Leaving the file is safe: a
      // genuinely-deleted file will re-arrive as a warm-path delete event later,
      // and a never-uploaded file gets picked up by the next catch-up upload.
      this.ctx.log(
        `Sync: skipped inferred deletion of "${normalizedPath}" (no trash support; leaving file intact).`
      );
      return;
    }

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

    // BIN-A / D-06 (pull side): the SINGLE chokepoint all three download surfaces
    // route through (performSync delta loop, reconciliation serverOnly,
    // repairMissingRemoteItems). Fork on the per-file GET response's contentType
    // — the ONLY authoritative binary discriminator (L9). The delta contentType
    // is a warm-path-only hint (cold-path ListObjectsV2 carries none) and the
    // list route hardcodes application/octet-stream, so neither may decide the
    // write path. undefined / text/* → the byte-identical string flow below
    // (fail-safe = today's behavior). A binary NEVER flows through
    // decodeRemoteFileContent / writeLocalFileFromRemote (the lossy UTF-8 decode
    // is the AR1 corruption class).
    if (isBinaryContentType(response.data.contentType)) {
      let bytes: ArrayBuffer;
      try {
        // L5: a server-decrypted (/files-decrypted) response is base64 of the
        // PLAIN bytes — decode DIRECTLY, never via decodeBase64Utf8 (a lossy
        // UTF-8 round-trip). Otherwise decrypt the ciphertext with the byte sibling.
        bytes =
          response.data.decrypted === true
            ? (this.base64ToBytes(response.data.content).buffer as ArrayBuffer)
            : await this.ctx.decryptContentBytes(response.data.content);
      } catch (decryptErr) {
        // OD-2: a decode/decrypt failure skips with a notice and NEVER wipes or
        // overwrites the local copy — identical discipline to the string catch.
        this.ctx.logError(
          `Sync: skipping "${normalizedPath}" — cloud binary could not be decrypted.`,
          decryptErr
        );
        this.ctx.notifyCloudDecryptFallback(normalizedPath);
        return;
      }
      this.ctx.recordSyncDiagnostic("applyRemoteChange.binary-pull", {
        path: normalizedPath,
      });
      await this.writeLocalBinaryFileFromRemote(normalizedPath, bytes);
      this.ctx.getSyncState().bytesDownloaded += metadata.size ?? 0;
      return;
    }

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
    this.recordRemoteReadState(
      normalizedPath,
      response.data,
      await this.ctx.computeHash(decrypted)
    );
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

  /**
   * BIN-A / D-06 (pull side): byte sibling of writeLocalFileFromRemote. Writes a
   * pulled binary to disk VG1-encrypted, mirroring the string sibling's
   * applyingRemoteWrite bracket + parent-folder creation + vault-API-preferred
   * structure with byte substitutions (createBinary/modifyBinary/
   * writePlainBinaryToDisk instead of create/modify/writePlainToDisk).
   *
   * L13 gate FIRST: writePlainBinaryToDisk SILENTLY no-ops when the adapter has
   * no writeBinary (unlike the string writePlainToDisk's AR2 throw), so a legacy
   * adapter must skip here — downloaded content is never silently discarded, and
   * legacy adapters keep today's no-binary behavior (D-10).
   *
   * The setApplyingRemoteWrite bracket is mandatory: it passes this write through
   * interceptedWriteBinary's EXISTING applyingRemoteWrite bypass
   * (at-rest-adapter-runtime.ts) while the CR-1 ingestion block is still in
   * place, and prevents an echo-upload. Pull-side VG1 writes are CR-1-safe in ANY
   * wave — a pulled binary has a server copy by definition. Pull-written binaries
   * read back immediately: adapter.readBinary → interceptedReadBinary decrypts
   * VG1 transparently.
   */
  private async writeLocalBinaryFileFromRemote(
    path: string,
    bytes: ArrayBuffer
  ): Promise<void> {
    if (!this.ctx.hasOriginalAdapterWriteBinary()) {
      this.ctx.log(
        `Sync: skipping binary "${path}" — legacy adapter without writeBinary — binary pull skipped.`
      );
      return;
    }
    const normalized = this.ctx.normalizeVaultPath(path);
    await this.ctx.ensureParentFoldersForPath(normalized);

    this.ctx.setApplyingRemoteWrite(true);
    try {
      const existing = this.ctx.app.vault.getAbstractFileByPath(normalized);
      if (existing instanceof TFile) {
        await this.ctx.app.vault.modifyBinary(existing, bytes);
        return;
      }

      try {
        await this.ctx.app.vault.createBinary(normalized, bytes);
      } catch {
        // Vault binary API unavailable / create raced: fall back to the VG1 byte
        // writer (refuses VG1-magic plaintext — corrupted-read cascade guard).
        await this.ctx.writePlainBinaryToDisk(normalized, bytes);
      }
    } finally {
      this.ctx.setApplyingRemoteWrite(false);
    }
  }

  /**
   * BIN-A (D-10): the single content-based reader that feeds every push
   * surface (rename, reconciliation, catch-up). Reads the on-disk PLAIN bytes
   * EXACTLY ONCE, then classifies by a strict UTF-8 probe:
   *   - text (losslessly decodable) → `{ kind: "text", text }` rides the string
   *     pipeline exactly as before;
   *   - binary (any invalid-UTF-8 byte) → `{ kind: "binary", bytes }` rides the
   *     byte pipeline. The bytes are already in hand — no second disk read.
   *
   * Legacy adapters without readBinary can't detect binary content without
   * changing text behavior, so they ALWAYS classify as text via the legacy
   * string read (AR2 / D-10) — mobile keeps today's behavior end-to-end.
   *
   * Errors propagate: callers' existing catch blocks preserve the
   * unreadable/SY6 "leave the on-disk file untouched" semantics unchanged.
   */
  private async readForSync(
    path: string
  ): Promise<{ kind: "text"; text: string } | { kind: "binary"; bytes: ArrayBuffer }> {
    if (!this.ctx.hasOriginalAdapterReadBinary()) {
      return { kind: "text", text: await this.ctx.readPlainFromDisk(path) };
    }
    const bytes = await this.ctx.readPlainBinaryFromDisk(path);
    try {
      // Same BOM handling as readPlainFromDisk's TextDecoder; fatal:true
      // rejects (instead of U+FFFD-mangling) anything that isn't UTF-8 text.
      const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      return { kind: "text", text };
    } catch {
      return { kind: "binary", bytes };
    }
  }

  async syncFileRenameToServer(oldPath: string, newPath: string): Promise<void> {
    if (this.isLocalProjectMemoryMode()) return;
    if (!this.ctx.hasOriginalAdapterRead()) return;

    const oldNormalized = this.ctx.normalizeVaultPath(oldPath);
    const newNormalized = this.ctx.normalizeVaultPath(newPath);
    if (this.isFolderMarkerPath(oldNormalized) || this.isFolderMarkerPath(newNormalized)) {
      return;
    }

    const permission = await this.ctx.getEffectivePermission(newNormalized);
    if (permission < PermissionLevel.WRITE) return;

    if (!this.ctx.isOnline() || !this.ctx.getKeyLease()) {
      // SY4: offline/lease-less folder renames route every child through
      // here, and a bare return orphaned them — the server kept old/*, the
      // next repair resurrected it locally, and new/* stayed local-only
      // (deletion-eligible). Queue both halves like interceptedRename and
      // tombstone the old path so repair can't resurrect it before the
      // flush lands.
      try {
        const result = await this.readForSync(newPath);
        if (result.kind === "binary") {
          // BIN-A / L1/L10: a binary rename queues through the byte path
          // (base64 of the PLAIN bytes, encoding "base64"), mirroring the
          // interceptedRename fix (11-02). Oversize → skip BOTH halves: never
          // remove a server copy without a replacement.
          if (result.bytes.byteLength > BINARY_SYNC_MAX_BYTES) {
            this.notifyBinaryTooLarge(newPath);
            return;
          }
          const base64 = uint8ToBase64Chunked(new Uint8Array(result.bytes));
          this.queueOfflineOperation("write", newNormalized, base64, {
            encoding: "base64",
            contentType: contentTypeForPath(newNormalized),
          });
        } else {
          this.queueOfflineOperation("write", newNormalized, result.text);
        }
      } catch (err) {
        this.ctx.logError(
          `Rename sync: failed to queue offline write for "${newPath}"`,
          err
        );
      }
      this.recordDeletionTombstone(oldNormalized);
      this.queueOfflineOperation("delete", oldNormalized);
      return;
    }

    // BIN-A / L1: probe once, then dispatch. Exactly one of content/binaryBytes
    // is set. Oversize binaries fail closed: skip the PUT AND the old-path
    // DELETE (never orphan-delete a server copy we can't replace — L10).
    let content: string | null = null;
    let binaryBytes: ArrayBuffer | null = null;
    try {
      const result = await this.readForSync(newPath);
      if (result.kind === "binary") {
        if (result.bytes.byteLength > BINARY_SYNC_MAX_BYTES) {
          this.notifyBinaryTooLarge(newPath);
          return;
        }
        binaryBytes = result.bytes;
      } else {
        content = result.text;
      }
    } catch (err) {
      this.ctx.log(
        `Rename sync: cannot read "${newPath}" (${err}); skipping server move.`
      );
      return;
    }

    // PUT the new path — byte body for binaries (D-03: contentType + large-body
    // timeout L2), string body for text (byte-identical to pre-BIN-A). Both carry
    // the optimistic version guard (expectedVersionId) via buildWriteBody.
    const baseVersionId = this.ctx.getExpectedVersionId(newNormalized);
    let hash: string;
    let putResp;
    if (binaryBytes !== null) {
      const encrypted = await this.ctx.encryptContentBytes(binaryBytes);
      hash = await this.ctx.computeHashBytes(binaryBytes);
      const body = this.buildWriteBody(newNormalized, encrypted, hash, {
        expectedVersionId: baseVersionId,
      });
      body.contentType = contentTypeForPath(newNormalized);
      putResp = await this.ctx.apiRequest<RemoteFileWriteResponse>(
        "PUT",
        this.ctx.vaultPath(`/files/${encodeURIComponent(newNormalized)}`),
        body,
        undefined,
        { timeoutMs: BINARY_PUT_TIMEOUT_MS }
      );
    } else {
      const textContent = content as string;
      const encrypted = await this.ctx.encryptContent(textContent);
      hash = await this.ctx.computeHash(textContent);
      putResp = await this.ctx.apiRequest<RemoteFileWriteResponse>(
        "PUT",
        this.ctx.vaultPath(`/files/${encodeURIComponent(newNormalized)}`),
        this.buildWriteBody(newNormalized, encrypted, hash, { expectedVersionId: baseVersionId })
      );
    }
    if (!putResp.success) {
      // Text 409 → interactive conflict resolution (handleRemoteWriteConflict is
      // text-only). Binary 409 falls through to the SY3 requeue path below.
      if (putResp.error?.statusCode === 409 && content !== null) {
        await this.handleRemoteWriteConflict(newNormalized, content, baseVersionId);
        return;
      }
      // SY3: the new-path PUT failed (5xx/403/offline). We must NOT delete the
      // old server path — doing so would leave the server holding neither copy
      // and lose the file. Queue the write for retry and return before the
      // DELETE, mirroring interceptedRename's failure handling. Binaries requeue
      // with encoding "base64" so the flush replays them byte-safely (L1).
      this.ctx.logError(
        `Rename sync: PUT "${newNormalized}" failed; deferring server move (old path left intact)`,
        new Error(putResp.error?.message ?? "unknown")
      );
      if (binaryBytes !== null) {
        this.queueOfflineOperation(
          "write",
          newNormalized,
          uint8ToBase64Chunked(new Uint8Array(binaryBytes)),
          { encoding: "base64", contentType: contentTypeForPath(newNormalized) }
        );
      } else {
        this.queueOfflineOperation("write", newNormalized, content as string);
      }
      this.queueOfflineOperation("delete", oldNormalized);
      return;
    }
    this.recordSuccessfulWrite(newNormalized, hash, putResp);

    const delResp = await this.ctx.apiRequest(
      "DELETE",
      this.ctx.vaultPath(`/files/${encodeURIComponent(oldNormalized)}`),
      this.buildDeleteBody(oldNormalized)
    );
    if (!delResp.success && delResp.error?.statusCode !== 404) {
      this.ctx.logError(
        `Rename sync: DELETE "${oldNormalized}" failed`,
        new Error(delResp.error?.message ?? "unknown")
      );
    } else {
      this.ctx.recordRemoteFileAbsent(oldNormalized);
    }
    this.ctx.emitPermissionChanged({ path: oldNormalized });
  }

  async syncFileDeleteToServer(path: string): Promise<void> {
    if (this.isLocalProjectMemoryMode()) return;
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
      this.ctx.vaultPath(`/files/${encodeURIComponent(normalized)}`),
      this.buildDeleteBody(normalized)
    );
    if (response.success || response.error?.statusCode === 404) {
      this.clearDeletionTombstone(normalized);
      this.ctx.recordRemoteFileAbsent(normalized);
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
    if (this.isLocalProjectMemoryMode()) {
      this.ctx.log("Initial reconciliation skipped by Local Project Memory Mode.");
      return false;
    }
    if (!this.ctx.getSession() || !this.ctx.isOnline()) {
      throw new Error("Reconciliation requires an authenticated, online session.");
    }

    new Notice("VaultGuard Sync: Comparing your folder with the server vault…");

    let operation: LongOperationHandle;
    try {
      operation = this.ctx.beginLongOperation({
        kind: "initial-reconciliation",
        operationName: "Initial vault reconciliation",
        phase: "Preparing reconciliation",
        placement: "protected",
        percent: 2,
        approximatePercent: true,
        capabilities: {
          protectedPhase: true,
          canCancel: false,
          canPause: false,
        },
        conflictsWith: ["sync", "background-sync", "vault-encrypt", "vault-decrypt"],
        stalledAfterMs: DEFAULT_STALLED_OPERATION_MS,
      });
    } catch (error) {
      if (isLongOperationConflict(error)) {
        const message = `VaultGuard Sync: ${describeConflict(error.conflict)}`;
        this.ctx.log(message);
        new Notice(message, 6000);
        return false;
      }
      throw error;
    }

    try {
    const localFiles = this.ctx.app.vault.getFiles();
    const localManifest = new Map<string, LocalManifestEntry>();
    // SY6: paths that EXIST locally but could not be read this pass (transient
    // decrypt hiccup, partial write). They must never be classified serverOnly
    // and overwritten/emptied — the on-disk file is real content we simply
    // couldn't read right now. Tracked separately so the serverOnly pass skips
    // them and leaves the file untouched.
    const unreadable = new Set<string>();
    // D-10 (byte-identical legacy safety net): the pre-BIN-A exclusion set for
    // binaries that must never ride the string pipeline. On CAPABLE adapters the
    // readForSync content-probe now routes in-size binaries to first-class
    // manifest entries (D-05) and oversize ones to `oversizeBinaryLocal`, so this
    // set stays empty in practice — but the mechanism + its Notice are preserved
    // so any legacy/no-readBinary detection path continues to fail safe.
    const binaryLocal = new Set<string>();
    // L10: an oversize binary can't reach the server until BIN-B, so it is
    // excluded from the manifest exactly like binaryLocal (the serverOnly pass
    // skips both) — never uploaded, never downloaded, never overwritten. The
    // local plaintext copy is the only copy and must stay untouched (CR-1).
    const oversizeBinaryLocal = new Set<string>();
    let localFileIndex = 0;
    operation.update({
      phase: "Reading local files",
      processedItems: 0,
      totalItems: localFiles.length,
      percent: 5,
      approximatePercent: true,
    });
    for (const file of localFiles) {
      try {
        const normalized = this.ctx.normalizeVaultPath(file.path);
        if (this.ctx.isPathExcluded(normalized)) continue;
        const result = await this.readForSync(file.path);
        if (result.kind === "binary") {
          // BIN-A / D-05 (wave 5): in-size binaries are FIRST-CLASS manifest
          // entries, hashed by BYTE (computeHashBytes). From here they upload,
          // download, and conflict exactly like text files (byte both-exist
          // compare + byte conflict strategies below). Legacy adapters never
          // reach this branch — readForSync string-reads on them (D-10), so
          // mobile keeps today's behavior end-to-end.
          if (result.bytes.byteLength > BINARY_SYNC_MAX_BYTES) {
            // L10: oversize → keep it OUT of the manifest (never uploaded, never
            // serverOnly, never overwritten). Throttled size Notice naming the
            // limit + BIN-B, plus a diagnostics breadcrumb. Local copy untouched.
            oversizeBinaryLocal.add(`/${normalized}`);
            this.notifyBinaryTooLarge(file.path);
            this.ctx.recordSyncDiagnostic("reconciliation.binary-oversize-skip", {
              path: normalized,
            });
            continue;
          }
          const hash = await this.ctx.computeHashBytes(result.bytes);
          localManifest.set(`/${normalized}`, {
            kind: "binary",
            bytes: result.bytes,
            hash,
          });
          continue;
        }
        const hash = await this.ctx.computeHash(result.text);
        localManifest.set(`/${normalized}`, {
          kind: "text",
          content: result.text,
          hash,
        });
      } catch (err) {
        this.ctx.logError(`Reconciliation: failed to read local file "${file.path}"`, err);
        unreadable.add(`/${this.ctx.normalizeVaultPath(file.path)}`);
      } finally {
        localFileIndex += 1;
        operation.update({
          phase: "Reading local files",
          processedItems: localFileIndex,
          totalItems: localFiles.length,
          approximatePercent: true,
          message: `${localManifest.size} readable, ${binaryLocal.size} binary, ${unreadable.size} unreadable.`,
        });
        if (localFileIndex % DEFAULT_LONG_OPERATION_BATCH_SIZE === 0) {
          await yieldToEventLoop();
        }
      }
    }

    operation.update({
      phase: "Fetching server inventory",
      processedItems: 0,
      totalItems: null,
      percent: 25,
      approximatePercent: true,
    });
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
    let inventoryIndex = 0;
    operation.update({
      phase: "Scanning server inventory",
      processedItems: 0,
      totalItems: inventory.data.deltas.length,
      percent: 35,
      approximatePercent: true,
    });
    for (const delta of inventory.data.deltas) {
      try {
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
      } finally {
        inventoryIndex += 1;
        if (inventoryIndex % DEFAULT_LONG_OPERATION_BATCH_SIZE === 0) {
          operation.update({
            phase: "Scanning server inventory",
            processedItems: inventoryIndex,
            totalItems: inventory.data.deltas.length,
            approximatePercent: true,
            message: `${serverPaths.size} server file(s), ${serverFolderPaths.size} folder(s).`,
          });
          await yieldToEventLoop();
        }
      }
    }

    const serverOnly: string[] = [];
    const localOnly: string[] = [];
    const conflicts: string[] = [];
    const localManifestBoth: Array<{
      path: string;
      localContent: string;
      localHash: string;
    }> = [];
    // BIN-A / D-05: binary files present on BOTH sides. Compared by BYTE hash in
    // the byte pass below (never the string readRemotePlaintext + computeHash,
    // which UTF-8-mangles bytes). A binary whose server copy reports text/* is a
    // pre-BIN-A lossy artifact routed to the L7 heal list, not a conflict.
    const binaryBoth: Array<{ path: string; bytes: ArrayBuffer; hash: string }> = [];

    let classifyIndex = 0;
    const classificationTotal = serverPaths.size + localManifest.size;
    operation.update({
      phase: "Classifying reconciliation plan",
      processedItems: 0,
      totalItems: classificationTotal,
      percent: 45,
      approximatePercent: true,
    });
    for (const path of serverPaths) {
      try {
        if (localManifest.has(path)) continue;
        // SY6: a path that's on the server AND unreadable locally is NOT
        // server-only — the local file exists, we just couldn't read it. Skip it
        // so the reconciler never overwrites/empties the on-disk content.
        if (unreadable.has(path)) continue;
        // D-10: legacy safety-net exclusion (see binaryLocal above).
        if (binaryLocal.has(path)) continue;
        // L10: oversize local binary — never overwrite the intact (only) local
        // copy of an attachment that can't yet sync to the server.
        if (oversizeBinaryLocal.has(path)) continue;
        serverOnly.push(path);
      } finally {
        classifyIndex += 1;
        if (classifyIndex % DEFAULT_LONG_OPERATION_BATCH_SIZE === 0) {
          operation.update({
            phase: "Classifying reconciliation plan",
            processedItems: classifyIndex,
            totalItems: classificationTotal,
            approximatePercent: true,
          });
          await yieldToEventLoop();
        }
      }
    }
    if (binaryLocal.size > 0) {
      new Notice(
        `VaultGuard Sync: ${binaryLocal.size} binary file(s) were left local-only — binary attachments are not yet supported for protected sync.`,
        8000
      );
    }
    if (unreadable.size > 0) {
      new Notice(
        `VaultGuard Sync: ${unreadable.size} local file(s) could not be read this pass and were left untouched (not overwritten). Reopen the vault to retry; they will sync once readable.`,
        8000
      );
    }
    for (const [path, entry] of localManifest.entries()) {
      try {
        if (!serverPaths.has(path)) {
          localOnly.push(path);
        } else if (entry.kind === "binary") {
          // BIN-A / D-05: binary both-exist → the byte compare + L7 heal pass below.
          binaryBoth.push({ path, bytes: entry.bytes, hash: entry.hash });
        } else {
          localManifestBoth.push({
            path,
            localContent: entry.content,
            localHash: entry.hash,
          });
        }
      } finally {
        classifyIndex += 1;
        if (classifyIndex % DEFAULT_LONG_OPERATION_BATCH_SIZE === 0) {
          operation.update({
            phase: "Classifying reconciliation plan",
            processedItems: classifyIndex,
            totalItems: classificationTotal,
            approximatePercent: true,
          });
          await yieldToEventLoop();
        }
      }
    }

    if (this.ctx.isVaultLeaseDenied()) {
      operation.update({
        phase: "Creating limited-access placeholders",
        processedItems: 0,
        totalItems: serverOnly.length + serverFolderPaths.size,
        percent: 65,
        approximatePercent: true,
      });
      let limitedIndex = 0;
      for (const path of serverOnly) {
        try {
          const normalized = this.ctx.normalizeVaultPath(path);
          if (this.ctx.isPathExcluded(normalized)) continue;
          if (this.isFolderMarkerPath(normalized)) continue;
          if (this.isPathTombstoned(normalized)) {
            await this.deleteTombstonedServerPath(normalized);
            continue;
          }
          // BIN-A / L6 (option b), OD-2: skip empty-placeholder creation for
          // known-binary paths — an empty binary placeholder can never hydrate
          // (interceptedReadBinary has no hydration branch), and an empty file
          // also passes the strict-UTF-8 push probe as valid empty TEXT, so a
          // later push could upload it over the real server copy. Fail-safe: the
          // binary appears on a full-access pull (D-06). Server-only paths only,
          // so no existing local file is touched (OD-2).
          if (isKnownBinaryExtensionPath(normalized)) {
            this.ctx.log(
              `Reconciliation (limited): skipping binary placeholder for "${normalized}" — binaries appear on a full-access pull (BIN-A/L6).`
            );
            continue;
          }
          await this.ctx.ensureParentFoldersForPath(normalized);
          await this.ctx.writePlainToDisk(normalized, "");
          this.ctx.getPlaceholderPaths().add(normalized);
        } finally {
          limitedIndex += 1;
          operation.update({
            phase: "Creating limited-access placeholders",
            processedItems: limitedIndex,
            totalItems: serverOnly.length + serverFolderPaths.size,
            approximatePercent: true,
          });
          if (limitedIndex % DEFAULT_LONG_OPERATION_BATCH_SIZE === 0) {
            await yieldToEventLoop();
          }
        }
      }
      for (const folderPath of serverFolderPaths) {
        try {
          if (!folderPath) continue;
          await this.ctx.ensureLocalFolderPath(folderPath);
        } catch (err) {
          this.ctx.logError(
            `Reconciliation (limited): mkdir for "${folderPath}" failed`,
            err
          );
        } finally {
          limitedIndex += 1;
          operation.update({
            phase: "Creating limited-access placeholders",
            processedItems: limitedIndex,
            totalItems: serverOnly.length + serverFolderPaths.size,
            approximatePercent: true,
          });
          if (limitedIndex % DEFAULT_LONG_OPERATION_BATCH_SIZE === 0) {
            await yieldToEventLoop();
          }
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
      operation.complete(
        `Limited-access reconciliation complete — ${serverOnly.length} visible file(s).`
      );
      return true;
    }

    const sameContent = new Set<string>();
    operation.update({
      phase: "Comparing matching files",
      processedItems: 0,
      totalItems: localManifestBoth.length,
      percent: 55,
      approximatePercent: true,
    });
    let compareIndex = 0;
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
      } finally {
        compareIndex += 1;
        operation.update({
          phase: "Comparing matching files",
          processedItems: compareIndex,
          totalItems: localManifestBoth.length,
          approximatePercent: true,
        });
        if (compareIndex % DEFAULT_LONG_OPERATION_BATCH_SIZE === 0) {
          await yieldToEventLoop();
        }
      }
    }

    // BIN-A / L4 + L7: byte both-exist compare. Fetch each server copy and BYTE
    // hash it; a server copy that reports text/* while the local file is binary
    // is a pre-BIN-A LOSSY ARTIFACT and is routed to the heal list (upload local,
    // never download). The upload itself is deferred to the work phase below so a
    // cancelled binding still modifies nothing.
    const healBinary: Array<{ path: string; bytes: ArrayBuffer }> = [];
    for (const item of binaryBoth) {
      try {
        const response = await this.ctx.fetchRemoteFileContent(item.path);
        if (!response.success || !response.data) {
          // OD-2: couldn't read the server side → skip (neither same, conflict,
          // nor heal). Never wipe; both copies stay put, retried next repair.
          this.ctx.logError(
            `Reconciliation: server read failed for binary "${item.path}"`,
            response.error
          );
          continue;
        }
        if (!isBinaryContentType(response.data.contentType)) {
          // L7 HEALING RULE: the server copy reports text/markdown (or any
          // text/*) while the local copy is binary — a lossy artifact of one of
          // two historical generators: the pre-AR1 string sync pipeline (bytes
          // UTF-8-decoded before PUT) and the pre-11-02 interceptedRename path
          // (same lossy decode on rename). HEAL by uploading the intact local
          // bytes over it; NEVER download the artifact over local content. This
          // extends the former AR1 "ignore" guard to "heal".
          healBinary.push({ path: item.path, bytes: item.bytes });
          continue;
        }
        // Genuine server binary → compare by byte hash. L5: a server-decrypted
        // (/files-decrypted) response is base64 of the PLAIN bytes — decode
        // directly, never via a lossy UTF-8 round-trip; else decrypt the
        // ciphertext with the byte sibling.
        const remoteBytes =
          response.data.decrypted === true
            ? (this.base64ToBytes(response.data.content).buffer as ArrayBuffer)
            : await this.ctx.decryptContentBytes(response.data.content);
        const remoteHash = await this.ctx.computeHashBytes(remoteBytes);
        if (remoteHash === item.hash) {
          sameContent.add(item.path);
        } else {
          conflicts.push(item.path);
        }
      } catch (err) {
        // OD-2: a decrypt/decode failure skips — never wipes. NOT a conflict:
        // routing it to conflict could let KEEP_REMOTE try to pull a copy we
        // just failed to decrypt.
        this.ctx.logError(
          `Reconciliation: binary comparison failed for "${item.path}"`,
          err
        );
        continue;
      }
    }

    const decision = await this.ctx.askReconciliationPlan({
      serverOnly,
      localOnly,
      conflicts,
    });
    if (!decision.proceed) {
      new Notice("VaultGuard Sync: Binding cancelled — no files were modified.");
      operation.cancel("Binding cancelled — no files were modified.");
      return false;
    }

    new Notice(
      `VaultGuard Sync: Reconciling — ↓${serverOnly.length} ↑${localOnly.length} ⚠${conflicts.length}`
    );

    let downloaded = 0;
    let downloadFailed = 0;
    let deletedOnServer = 0;
    operation.update({
      phase: "Downloading server-only files",
      processedItems: 0,
      totalItems: serverOnly.length,
      percent: 65,
      approximatePercent: true,
    });
    let downloadIndex = 0;
    for (const path of serverOnly) {
      try {
        const normalized = this.ctx.normalizeVaultPath(path);
        if (this.isPathTombstoned(normalized)) {
          if (await this.deleteTombstonedServerPath(normalized)) {
            deletedOnServer += 1;
          }
          continue;
        }
        await this.ctx.applyRemoteChange({ path: normalized, size: 0 });
        downloaded += 1;
      } catch (err) {
        this.ctx.logError(`Reconciliation: download failed for "${path}"`, err);
        downloadFailed += 1;
      } finally {
        downloadIndex += 1;
        operation.update({
          phase: "Downloading server-only files",
          processedItems: downloadIndex,
          totalItems: serverOnly.length,
          approximatePercent: true,
          message: `${downloaded} downloaded, ${downloadFailed} failed.`,
        });
        if (downloadIndex % DEFAULT_LONG_OPERATION_BATCH_SIZE === 0) {
          await yieldToEventLoop();
        }
      }
    }

    let uploaded = 0;
    let uploadSkipped = 0;
    let uploadFailed = 0;
    operation.update({
      phase: "Uploading local-only files",
      processedItems: 0,
      totalItems: localOnly.length,
      percent: 75,
      approximatePercent: true,
    });
    let uploadIndex = 0;
    for (const path of localOnly) {
      try {
        const entry = localManifest.get(path);
        if (!entry) continue;
        const normalized = this.ctx.normalizeVaultPath(path);
        // BIN-A / D-05 + D-11: a local-only in-size binary uploads via the BYTE
        // path and counts as an upload, exactly like a text file.
        const outcome =
          entry.kind === "binary"
            ? await this.uploadReconciledBinaryFile(normalized, entry.bytes)
            : await this.ctx.uploadReconciledFile(normalized, entry.content);
        if (outcome === "uploaded") uploaded += 1;
        else uploadSkipped += 1;
      } catch (err) {
        this.ctx.logError(`Reconciliation: upload failed for "${path}"`, err);
        uploadFailed += 1;
      } finally {
        uploadIndex += 1;
        operation.update({
          phase: "Uploading local-only files",
          processedItems: uploadIndex,
          totalItems: localOnly.length,
          approximatePercent: true,
          message: `${uploaded} uploaded, ${uploadSkipped} skipped, ${uploadFailed} failed.`,
        });
        if (uploadIndex % DEFAULT_LONG_OPERATION_BATCH_SIZE === 0) {
          await yieldToEventLoop();
        }
      }
    }

    // BIN-A / L7: heal pre-BIN-A lossy server artifacts by uploading the local
    // bytes. Runs only after the user confirmed the plan (above), so a cancelled
    // binding heals nothing. Counted in the UPLOAD bucket (D-11). This loop only
    // ever UPLOADS — downloading the artifact over local content is structurally
    // impossible here (T-11-16). A "skipped-*" outcome leaves both copies as-is,
    // never a deletion (SY2 extended).
    for (const heal of healBinary) {
      try {
        const outcome = await this.uploadReconciledBinaryFile(
          this.ctx.normalizeVaultPath(heal.path),
          heal.bytes
        );
        if (outcome === "uploaded") uploaded += 1;
        else uploadSkipped += 1;
      } catch (err) {
        this.ctx.logError(`Reconciliation: heal upload failed for "${heal.path}"`, err);
        uploadFailed += 1;
      }
    }

    let conflictsResolved = 0;
    let conflictFailed = 0;
    operation.update({
      phase: "Resolving conflicts",
      processedItems: 0,
      totalItems: conflicts.length,
      percent: 85,
      approximatePercent: true,
    });
    let conflictIndex = 0;
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
      } finally {
        conflictIndex += 1;
        operation.update({
          phase: "Resolving conflicts",
          processedItems: conflictIndex,
          totalItems: conflicts.length,
          approximatePercent: true,
          message: `${conflictsResolved} resolved, ${conflictFailed} failed.`,
        });
        if (conflictIndex % DEFAULT_LONG_OPERATION_BATCH_SIZE === 0) {
          await yieldToEventLoop();
        }
      }
    }

    let foldersUploaded = 0;
    let foldersDownloaded = 0;
    let foldersFailed = 0;

    const localFolderPaths = new Set(this.ctx.collectLocalFolderPaths());
    const folderTotal = serverFolderPaths.size + localFolderPaths.size;
    let folderIndex = 0;
    operation.update({
      phase: "Reconciling folders",
      processedItems: 0,
      totalItems: folderTotal,
      percent: 92,
      approximatePercent: true,
    });

    for (const folderPath of serverFolderPaths) {
      try {
        if (!folderPath || localFolderPaths.has(folderPath)) continue;
        const created = await this.ctx.ensureLocalFolderPath(folderPath);
        if (created) foldersDownloaded += 1;
      } catch (err) {
        this.ctx.logError(`Reconciliation: mkdir for "${folderPath}" failed`, err);
        foldersFailed += 1;
      } finally {
        folderIndex += 1;
        if (folderIndex % DEFAULT_LONG_OPERATION_BATCH_SIZE === 0) {
          operation.update({
            phase: "Reconciling folders",
            processedItems: folderIndex,
            totalItems: folderTotal,
            approximatePercent: true,
          });
          await yieldToEventLoop();
        }
      }
    }

    for (const folderPath of localFolderPaths) {
      try {
        if (serverFolderPaths.has(folderPath)) continue;
        const ok = await this.ctx.uploadFolderMarker(folderPath);
        if (ok) foldersUploaded += 1;
      } catch (err) {
        this.ctx.logError(
          `Reconciliation: folder marker upload for "${folderPath}" failed`,
          err
        );
        foldersFailed += 1;
      } finally {
        folderIndex += 1;
        if (folderIndex % DEFAULT_LONG_OPERATION_BATCH_SIZE === 0) {
          operation.update({
            phase: "Reconciling folders",
            processedItems: folderIndex,
            totalItems: folderTotal,
            approximatePercent: true,
          });
          await yieldToEventLoop();
        }
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
    operation.complete(`Reconciliation complete — ${summary}`);
    return true;
    } catch (error) {
      operation.fail(error);
      throw error;
    }
  }

  async uploadReconciledFile(
    path: string,
    content: string,
    options: { noWriteNotice?: string } = {}
  ): Promise<UploadReconciledOutcome> {
    if (this.isLocalProjectMemoryMode()) {
      this.ctx.log(`Reconciliation: skipping "${path}" — Local Project Memory Mode is local-only.`);
      return "skipped-no-lease";
    }
    if (!this.hasValidKeyLease()) {
      this.ctx.log(`Reconciliation: skipping "${path}" — no encryption key lease available.`);
      new Notice(
        `VaultGuard Sync: Skipped upload of "${path}" — limited access sessions can download accessible files, but need a key lease to encrypt uploads.`
      );
      // SY2: transient (lease may return). Callers must NOT treat this as a
      // reason to delete the local-only file.
      return "skipped-no-lease";
    }

    const permission = await this.ctx.getEffectivePermission(path);
    if (permission < PermissionLevel.WRITE) {
      this.ctx.log(`Reconciliation: skipping "${path}" — no write permission.`);
      new Notice(
        options.noWriteNotice ??
          `VaultGuard Sync: Skipped upload of "${path}" — you do not have write permission. The file stays in this folder but is not synced.`
      );
      return "skipped-no-permission";
    }
    const encrypted = await this.ctx.encryptContent(content);
    const hash = await this.ctx.computeHash(content);
    const response = await this.ctx.apiRequest<RemoteFileWriteResponse>(
      "PUT",
      this.ctx.vaultPath(`/files/${encodeURIComponent(path)}`),
      this.buildWriteBody(path, encrypted, hash, { expectedVersionId: null })
    );
    if (!response.success) {
      throw new Error(response.error?.message ?? `Upload of "${path}" failed.`);
    }
    this.recordSuccessfulWrite(path, hash, response);
    await this.ctx.emitAuditEvent("file.write", path, { reconciliation: true });
    return "uploaded";
  }

  /**
   * BIN-A / D-07: byte sibling of uploadReconciledFile. Pushes PLAIN bytes as
   * encryptContentBytes ciphertext with a computeHashBytes hash, the real MIME
   * contentType, and the large-body timeout (L2) — reusing the vault-scoped
   * JSON /files path (D-03; the dormant client.ts putFile/getFile stay dormant,
   * PATTERNS §8 option (a)). Mirrors the string sibling's outcome discipline
   * (SY2) with ONE addition and ONE ordering rule:
   *   - a `skipped-too-large` outcome for files over the client ceiling, and
   *   - the size gate runs FIRST — before the lease/permission/network work —
   *     so an unsendable attachment never triggers a misleading "no lease"
   *     Notice and never encrypts megabytes for nothing (L10/L12).
   * Private: only the catch-up and rename push sites call it, and its extended
   * outcome (UploadReconciledBinaryOutcome) never needs to thread through the
   * narrow ctx uploadReconciledFile declaration.
   */
  private async uploadReconciledBinaryFile(
    path: string,
    bytes: ArrayBuffer,
    options: { noWriteNotice?: string } = {}
  ): Promise<UploadReconciledBinaryOutcome> {
    // Size gate FIRST (cheapest, and must precede the lease gate — L10/L12).
    if (bytes.byteLength > BINARY_SYNC_MAX_BYTES) {
      this.notifyBinaryTooLarge(path);
      // Fail-closed like skipped-no-lease: callers must NEVER delete or
      // overwrite the local file on this outcome (SY2 extended).
      return "skipped-too-large";
    }

    if (!this.hasValidKeyLease()) {
      this.ctx.log(`Reconciliation: skipping "${path}" — no encryption key lease available.`);
      new Notice(
        `VaultGuard Sync: Skipped upload of "${path}" — limited access sessions can download accessible files, but need a key lease to encrypt uploads.`
      );
      // SY2: transient (lease may return). Callers must NOT delete the file.
      return "skipped-no-lease";
    }

    const permission = await this.ctx.getEffectivePermission(path);
    if (permission < PermissionLevel.WRITE) {
      this.ctx.log(`Reconciliation: skipping "${path}" — no write permission.`);
      new Notice(
        options.noWriteNotice ??
          `VaultGuard Sync: Skipped upload of "${path}" — you do not have write permission. The file stays in this folder but is not synced.`
      );
      return "skipped-no-permission";
    }

    const encrypted = await this.ctx.encryptContentBytes(bytes);
    const response = await this.ctx.apiRequest(
      "PUT",
      this.ctx.vaultPath(`/files/${encodeURIComponent(path)}`),
      {
        content: encrypted,
        hash: await this.ctx.computeHashBytes(bytes),
        contentType: contentTypeForPath(path),
      },
      undefined,
      { timeoutMs: BINARY_PUT_TIMEOUT_MS }
    );
    if (!response.success) {
      throw new Error(response.error?.message ?? `Upload of "${path}" failed.`);
    }
    await this.ctx.emitAuditEvent("file.write", path, { reconciliation: true });
    // BIN-A / D-11: complete the binary breadcrumb family (pull, oversize-skip,
    // and size-gate-skip already record) with the push-SUCCESS event. Dev-only —
    // recordSyncDiagnostic is a NODE_ENV-gated ring buffer, DCE-stripped from
    // production builds. Path + byte count only (metadata, no content).
    this.ctx.recordSyncDiagnostic("upload.binary-push", {
      path,
      bytes: bytes.byteLength,
    });
    return "uploaded";
  }

  /**
   * BIN-A (OD-1/OD-3): per-path-throttled Notice that a binary exceeds the
   * ~7 MiB JSON-path ceiling and cannot sync until BIN-B. Fired on every push
   * surface that trips the size gate (catch-up upload, both rename paths).
   * Never deletes or LAK-encrypts the file — it stays local plaintext (CR-1).
   */
  private notifyBinaryTooLarge(path: string): void {
    const now = Date.now();
    const last = this.binaryTooLargeNoticeAt.get(path) ?? 0;
    if (now - last < BINARY_TOO_LARGE_NOTICE_THROTTLE_MS) return;
    this.binaryTooLargeNoticeAt.set(path, now);
    this.ctx.log(
      `Sync: "${path}" exceeds the ~7 MiB binary sync limit; skipping upload (large-file support arrives with BIN-B).`
    );
    new Notice(
      `VaultGuard Sync: "${path}" is larger than 7 MiB and can't be synced yet. Large-file support arrives with BIN-B; the file stays in this folder but is not uploaded.`,
      8000
    );
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
    if (this.isLocalProjectMemoryMode()) return null;
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
    const operation = this.currentSyncOperation;
    operation?.update({
      phase: "Catching up local-only files",
      processedItems: 0,
      totalItems: localFiles.length,
      percent: 25,
      approximatePercent: true,
    });
    let uploaded = 0;
    let removedLocal = 0;
    let failed = 0;
    let skipped = 0;
    let localFileIndex = 0;
    for (const file of localFiles) {
      try {
        const normalized = this.ctx.normalizeVaultPath(file.path);
        if (this.isFolderMarkerPath(normalized)) continue;
        if (this.ctx.isPathExcluded(normalized)) continue;
        const lookupKey = `/${normalized}`;
        if (serverFilePaths.has(lookupKey)) continue;

        const result = await this.readForSync(file.path);
        if (result.kind === "binary") {
          // BIN-A / D-07: binaries now ride the byte upload path instead of the
          // AR1 skip. In-size files upload and count as uploads (D-11
          // truthfulness); oversize files fail closed (L10). Legacy adapters
          // never reach here — readForSync returns text for them (D-10).
          const outcome = await this.uploadReconciledBinaryFile(normalized, result.bytes, {
            noWriteNotice:
              `VaultGuard Sync: Removed local-only "${normalized}" because this server vault ` +
              "does not contain it and you do not have write permission to add it.",
          });
          if (outcome === "uploaded") {
            uploaded += 1;
            // CR-1/D-01: the post-upload at-rest hygiene call fires ONLY after
            // "uploaded", exactly as for text. It is a harmless no-op for
            // binaries until the wave-6 ingestion flip (server-copy-first —
            // never LAK-encrypt a binary that has no server copy).
            void this.ctx.ensureAtRestEncryptedInPlace(normalized);
          } else if (outcome === "skipped-too-large") {
            // The size-gate Notice already fired inside the byte sibling — do
            // NOT double-Notice, and NEVER LAK-encrypt an unsendable file
            // (CR-1/L10: no post-upload hygiene call here).
            skipped += 1;
            this.ctx.recordSyncDiagnostic("catchup.binary-skip-too-large", {
              path: normalized,
            });
          } else if (outcome === "skipped-no-lease") {
            // SY2: transient, applies to every remaining file — stop the loop
            // and leave everything intact for the next (leased) sync.
            skipped += 1;
            this.ctx.log(
              "Catch-up: key lease unavailable mid-catch-up — stopping; local-only files left intact for retry."
            );
            break;
          } else {
            // skipped-no-permission: IDENTICAL removal rule to the text path —
            // remove ONLY on a warmed store, never on skipped-too-large /
            // skipped-no-lease (SY2 extended).
            skipped += 1;
            const storeState = this.ctx.getPermissionStoreState();
            if (storeState.kind === "warmed") {
              if (await this.ctx.removeUnsyncedLocalFile(normalized)) {
                removedLocal += 1;
              }
            } else {
              this.ctx.log(
                `Catch-up: leaving local-only "${normalized}" in place — no write permission but the permission store is "${storeState.kind}", not warmed; refusing to delete on an unconfirmed baseline.`
              );
            }
          }
          continue;
        }
        const content = result.text;
        const outcome = await this.ctx.uploadReconciledFile(normalized, content, {
          noWriteNotice:
            `VaultGuard Sync: Removed local-only "${normalized}" because this server vault ` +
            "does not contain it and you do not have write permission to add it.",
        });
        if (outcome === "uploaded") {
          uploaded += 1;
          // A local-only text file usually means it was added OUTSIDE
          // Obsidian (Finder drop while the app was closed, git checkout),
          // so its on-disk form is still plaintext. Now that the server has
          // the content, flip the local copy to at-rest ciphertext.
          // Fire-and-forget: hygiene must never fail the catch-up loop.
          void this.ctx.ensureAtRestEncryptedInPlace(normalized);
        } else if (outcome === "skipped-no-lease") {
          // SY2: the key lease expired/disappeared mid-loop. This is transient
          // and applies to EVERY remaining file — continuing would return
          // skipped-no-lease for all of them. Never remove a never-uploaded
          // file for a transient reason; stop the loop and leave everything
          // intact so the next sync (with a lease) can retry.
          skipped += 1;
          this.ctx.log(
            "Catch-up: key lease unavailable mid-catch-up — stopping; local-only files left intact for retry."
          );
          break;
        } else {
          // outcome === "skipped-no-permission": the user genuinely lacks write
          // permission, so the file cannot be added to this vault. Only remove
          // it once the permission store has actually WARMED — a cold or
          // fetch-failed store can report a spurious NONE/viewer baseline, and
          // deleting on that is the exact data-loss class we must avoid.
          skipped += 1;
          const storeState = this.ctx.getPermissionStoreState();
          if (storeState.kind === "warmed") {
            if (await this.ctx.removeUnsyncedLocalFile(normalized)) {
              removedLocal += 1;
            }
          } else {
            this.ctx.log(
              `Catch-up: leaving local-only "${normalized}" in place — no write permission but the permission store is "${storeState.kind}", not warmed; refusing to delete on an unconfirmed baseline.`
            );
          }
        }
      } catch (err) {
        failed += 1;
        this.ctx.logError(`Catch-up: upload of "${file.path}" failed`, err);
      } finally {
        localFileIndex += 1;
        operation?.update({
          phase: "Catching up local-only files",
          processedItems: localFileIndex,
          totalItems: localFiles.length,
          approximatePercent: true,
          message: `${uploaded} uploaded, ${removedLocal} removed, ${skipped} skipped, ${failed} failed.`,
        });
        if (localFileIndex % DEFAULT_LONG_OPERATION_BATCH_SIZE === 0) {
          await yieldToEventLoop();
        }
      }
    }

    let foldersUploaded = 0;
    let foldersFailed = 0;
    const localFolderPaths = this.ctx.collectLocalFolderPaths();
    let folderIndex = 0;
    operation?.update({
      phase: "Catching up local-only folders",
      processedItems: 0,
      totalItems: localFolderPaths.length,
      approximatePercent: true,
    });
    for (const folderPath of localFolderPaths) {
      try {
        if (serverFolderPaths.has(folderPath)) continue;
        if (this.ctx.isPathExcluded(folderPath)) continue;
        const ok = await this.ctx.uploadFolderMarker(folderPath);
        if (ok) foldersUploaded += 1;
      } catch (err) {
        foldersFailed += 1;
        this.ctx.logError(`Catch-up: folder marker upload for "${folderPath}" failed`, err);
      } finally {
        folderIndex += 1;
        operation?.update({
          phase: "Catching up local-only folders",
          processedItems: folderIndex,
          totalItems: localFolderPaths.length,
          approximatePercent: true,
          message: `${foldersUploaded} folders preserved, ${foldersFailed} failed.`,
        });
        if (folderIndex % DEFAULT_LONG_OPERATION_BATCH_SIZE === 0) {
          await yieldToEventLoop();
        }
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
    if (this.isLocalProjectMemoryMode()) return null;
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
    const operation = this.currentSyncOperation;

    let folderIndex = 0;
    operation?.update({
      phase: "Repairing missing remote folders",
      processedItems: 0,
      totalItems: foldersByDepth.length,
      percent: 85,
      approximatePercent: true,
    });
    for (const folderPath of foldersByDepth) {
      try {
        if (this.ctx.isPathExcluded(folderPath)) continue;
        const created = await this.ctx.ensureLocalFolderPath(folderPath);
        if (created) downloadedFolders += 1;
      } catch (err) {
        failedFolders += 1;
        this.ctx.logError(`Remote repair: mkdir for "${folderPath}" failed`, err);
      } finally {
        folderIndex += 1;
        operation?.update({
          phase: "Repairing missing remote folders",
          processedItems: folderIndex,
          totalItems: foldersByDepth.length,
          approximatePercent: true,
          message: `${downloadedFolders} folders created, ${failedFolders} failed.`,
        });
        if (folderIndex % DEFAULT_LONG_OPERATION_BATCH_SIZE === 0) {
          await yieldToEventLoop();
        }
      }
    }

    let downloadedFiles = 0;
    let failedFiles = 0;
    let fileIndex = 0;
    operation?.update({
      phase: "Repairing missing remote files",
      processedItems: 0,
      totalItems: serverFiles.length,
      percent: 90,
      approximatePercent: true,
    });
    for (const file of serverFiles) {
      try {
        if (this.ctx.isPathExcluded(file.path)) continue;
        if (await this.ctx.localPathExists(file.path)) continue;

        await this.ctx.applyRemoteChange(file);
        downloadedFiles += 1;
      } catch (err) {
        failedFiles += 1;
        this.ctx.logError(`Remote repair: download of "${file.path}" failed`, err);
      } finally {
        fileIndex += 1;
        operation?.update({
          phase: "Repairing missing remote files",
          processedItems: fileIndex,
          totalItems: serverFiles.length,
          approximatePercent: true,
          message: `${downloadedFiles} files downloaded, ${failedFiles} failed.`,
        });
        if (fileIndex % DEFAULT_LONG_OPERATION_BATCH_SIZE === 0) {
          await yieldToEventLoop();
        }
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
    if (this.isLocalProjectMemoryMode()) return false;
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
    const hash = await this.ctx.computeHash(markerBody);
    const response = await this.ctx.apiRequest<RemoteFileWriteResponse>(
      "PUT",
      this.ctx.vaultPath(`/files/${encodeURIComponent(markerPath)}`),
      {
        content: markerBase64,
        contentType: "application/x-vaultguard-folder-marker",
        hash,
      }
    );
    if (!response.success) {
      throw new Error(
        response.error?.message ?? `Folder marker upload for "${normalized}" failed.`
      );
    }
    this.recordSuccessfulWrite(markerPath, hash, response);
    return true;
  }

  async deleteFolderMarker(folderPath: string): Promise<void> {
    if (this.isLocalProjectMemoryMode()) return;
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
        `Folder marker delete for "${normalized}" failed; queuing retry`,
        new Error(response.error?.message ?? "unknown")
      );
      // SY8: a transient (non-404) failure used to be logged and forgotten, so
      // the marker persisted and repair recreated the empty folder on the next
      // sync/restart. Queue the marker delete so it retries via the offline
      // flush / retryOutstandingDeletions, same durability as file deletes.
      this.queueOfflineOperation("delete", markerPath);
    } else {
      this.ctx.recordRemoteFileAbsent(markerPath);
    }
  }

  async deleteFolderContentsOnServer(folderPath: string): Promise<void> {
    if (this.isLocalProjectMemoryMode()) return;
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
    if (this.isLocalProjectMemoryMode()) return;
    const settings = this.ctx.getSettings();
    if (!settings.serverVaultId || !this.ctx.getSession()) return;
    void this.ctx.uploadFolderMarker(path).catch((err) =>
      this.ctx.logError(`Folder create: marker for "${path}" failed`, err)
    );
  }

  handleFolderDeleted(path: string): void {
    if (this.isLocalProjectMemoryMode()) return;
    const settings = this.ctx.getSettings();
    if (!settings.serverVaultId || !this.ctx.getSession()) return;
    void this.ctx.deleteFolderContentsOnServer(path).catch((err) =>
      this.ctx.logError(`Folder delete: server cleanup for "${path}" failed`, err)
    );
  }

  handleFolderRenamed(path: string, oldPath: string): void {
    if (this.isLocalProjectMemoryMode()) return;
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
    if (this.isLocalProjectMemoryMode()) return;
    const settings = this.ctx.getSettings();
    if (!settings.serverVaultId || !this.ctx.getSession()) return;
    void this.ctx.syncFileRenameToServer(oldPath, path).catch((err) =>
      this.ctx.logError(`File rename via vault event "${oldPath}" → "${path}" failed`, err)
    );
  }

  handleVaultFileDeleted(path: string): void {
    if (this.isLocalProjectMemoryMode()) return;
    const settings = this.ctx.getSettings();
    if (!settings.serverVaultId || !this.ctx.getSession()) return;
    void this.ctx.syncFileDeleteToServer(path).catch((err) =>
      this.ctx.logError(`File delete via vault event "${path}" failed`, err)
    );
  }

  async resolveReconciliationConflict(
    path: string,
    strategy: ConflictResolutionStrategy,
    localManifest: Map<string, LocalManifestEntry>
  ): Promise<void> {
    const normalizedPath = this.ctx.normalizeVaultPath(path);
    const entry = localManifest.get(path);

    switch (strategy) {
      case ConflictResolutionStrategy.KEEP_LOCAL: {
        if (!entry) return;
        if (entry.kind === "binary") {
          // BIN-A / L4: KEEP_LOCAL byte-uploads the local bytes (never the
          // string uploader — that would lossily UTF-8-encode them). The byte
          // uploader's outcome union is respected; no skip leads to a deletion.
          await this.uploadReconciledBinaryFile(normalizedPath, entry.bytes);
        } else {
          await this.ctx.uploadReconciledFile(normalizedPath, entry.content);
        }
        return;
      }
      case ConflictResolutionStrategy.KEEP_REMOTE: {
        // BIN-A / L4: applyRemoteChange forks byte-vs-string internally on the
        // GET-response contentType (D-06 chokepoint), so this ONE call pulls a
        // binary remote through the byte writer and a text remote through the
        // string writer — no branch needed here.
        await this.ctx.applyRemoteChange({ path: normalizedPath, size: 0 });
        return;
      }
      case ConflictResolutionStrategy.DUPLICATE:
      default: {
        if (entry?.kind === "binary") {
          // BIN-A / L4: DUPLICATE for a binary writes the LOCAL bytes to the
          // conflict-named path via the pull byte writer (reused, NOT a third
          // writer — it VG1-encrypts on disk and is L13 write-capability gated),
          // then byte-pulls the remote into the original path below.
          const conflictPath = this.generateConflictPath(normalizedPath);
          await this.writeLocalBinaryFileFromRemote(conflictPath, entry.bytes);
        } else if (entry && this.ctx.hasOriginalAdapterWrite()) {
          const conflictPath = this.generateConflictPath(normalizedPath);
          await this.ctx.writeLocalFileFromRemote(conflictPath, entry.content);
        }
        await this.ctx.applyRemoteChange({ path: normalizedPath, size: 0 });
        return;
      }
    }
  }

  async handleRemoteWriteConflict(
    path: string,
    localContent: string,
    baseVersionId?: string | null
  ): Promise<RemoteWriteConflictResolutionResult> {
    const normalizedPath = this.ctx.normalizeVaultPath(path);
    const priorState = this.ctx.getRemoteFileState(normalizedPath);
    const response = await this.ctx.fetchRemoteFileContent(normalizedPath);
    const localHash = await this.ctx.computeHash(localContent);
    let remoteContent: string | null = null;
    let remoteHash = "remote-deleted";
    let remoteModified = new Date().toISOString();
    let remoteVersionId: string | null = null;
    const remoteDeleted =
      !response.success &&
      (response.error?.statusCode === 404 || response.error?.statusCode === 410);

    if (remoteDeleted) {
      this.ctx.recordRemoteFileAbsent(normalizedPath);
    } else {
      if (!response.success || !response.data) {
        throw new Error(
          response.error?.message ??
            `Failed to fetch current remote copy for "${normalizedPath}".`
        );
      }

      remoteContent = await this.ctx.decodeRemoteFileContent(
        normalizedPath,
        response.data
      );
      remoteHash = await this.ctx.computeHash(remoteContent);
      remoteModified = response.data.lastModified ?? remoteModified;
      remoteVersionId = response.data.versionId ?? null;
      this.recordRemoteReadState(normalizedPath, response.data, remoteHash);
    }

    const conflict: SyncConflict = {
      path: normalizedPath,
      localHash,
      remoteHash,
      baseHash: priorState?.baseHash ?? null,
      detectedAt: new Date().toISOString(),
      resolution: null,
      localModified: new Date().toISOString(),
      remoteModified,
      remoteDeleted,
    };
    const syncState = this.ctx.getSyncState();
    syncState.conflicts = syncState.conflicts.filter(
      (existing) => existing.path !== normalizedPath
    );
    syncState.conflicts.push(conflict);

    const strategy = this.ctx.getSettings().defaultConflictResolution;
    await this.ctx.emitAuditEvent("sync.conflict", normalizedPath, {
      strategy,
      localHash,
      remoteHash,
      baseVersionId: baseVersionId ?? null,
      remoteVersionId,
      remoteDeleted,
    });

    switch (strategy) {
      case ConflictResolutionStrategy.KEEP_LOCAL: {
        const encrypted = await this.ctx.encryptContent(localContent);
        const writeResponse = await this.ctx.apiRequest<RemoteFileWriteResponse>(
          "PUT",
          this.ctx.vaultPath(`/files/${encodeURIComponent(normalizedPath)}`),
          this.buildWriteBody(normalizedPath, encrypted, localHash, {
            forceOverwrite: true,
          })
        );
        if (!writeResponse.success) {
          throw new Error(
            writeResponse.error?.message ??
              `Conflict overwrite for "${normalizedPath}" failed.`
          );
        }
        this.recordSuccessfulWrite(normalizedPath, localHash, writeResponse);
        conflict.resolution = ConflictResolutionStrategy.KEEP_LOCAL;
        return "keep-local";
      }

      case ConflictResolutionStrategy.KEEP_REMOTE:
        if (remoteDeleted) {
          await this.ctx.applyRemoteDeletion(normalizedPath, false);
        } else if (remoteContent !== null) {
          await this.ctx.writeLocalFileFromRemote(normalizedPath, remoteContent);
        } else {
          throw new Error(`Conflict for "${normalizedPath}" has no remote content.`);
        }
        conflict.resolution = ConflictResolutionStrategy.KEEP_REMOTE;
        return "keep-remote";

      case ConflictResolutionStrategy.DUPLICATE: {
        const conflictPath = this.generateConflictPath(normalizedPath);
        await this.ctx.writePlainToDisk(conflictPath, localContent);
        if (remoteDeleted) {
          await this.ctx.applyRemoteDeletion(normalizedPath, false);
        } else if (remoteContent !== null) {
          await this.ctx.writeLocalFileFromRemote(normalizedPath, remoteContent);
        } else {
          throw new Error(`Conflict for "${normalizedPath}" has no remote content.`);
        }
        conflict.resolution = ConflictResolutionStrategy.DUPLICATE;
        return "duplicate";
      }

      case ConflictResolutionStrategy.ASK_USER:
      default:
        syncState.status = "error";
        syncState.lastError = `Sync conflict detected for "${normalizedPath}".`;
        new Notice(
          `VaultGuard Sync: Sync conflict detected for "${normalizedPath}". Use View Permissions to resolve.`
        );
        return "pending";
    }
  }

  async handleConflict(conflict: SyncConflict): Promise<void> {
    const strategy = this.ctx.getSettings().defaultConflictResolution;
    await this.ctx.emitAuditEvent("sync.conflict", conflict.path, {
      strategy,
      localHash: conflict.localHash,
      remoteHash: conflict.remoteHash,
      remoteDeleted: conflict.remoteDeleted === true,
    });

    switch (strategy) {
      case ConflictResolutionStrategy.KEEP_LOCAL: {
        const localContent = await this.ctx.readPlainFromDisk(conflict.path);
        const encrypted = await this.ctx.encryptContent(localContent);
        const hash = await this.ctx.computeHash(localContent);
        const response = await this.ctx.apiRequest<RemoteFileWriteResponse>(
          "PUT",
          this.ctx.vaultPath(`/files/${encodeURIComponent(conflict.path)}`),
          this.buildWriteBody(conflict.path, encrypted, hash, { forceOverwrite: true })
        );
        if (!response.success) {
          throw new Error(response.error?.message ?? `Conflict overwrite for "${conflict.path}" failed.`);
        }
        this.recordSuccessfulWrite(conflict.path, hash, response);
        conflict.resolution = ConflictResolutionStrategy.KEEP_LOCAL;
        break;
      }

      case ConflictResolutionStrategy.KEEP_REMOTE:
        if (conflict.remoteDeleted) {
          await this.ctx.applyRemoteDeletion(conflict.path, false);
        } else {
          await this.ctx.applyRemoteChange({ path: conflict.path, size: 0 });
        }
        conflict.resolution = ConflictResolutionStrategy.KEEP_REMOTE;
        break;

      case ConflictResolutionStrategy.DUPLICATE: {
        const conflictPath = this.generateConflictPath(conflict.path);
        const localContent = await this.ctx.readPlainFromDisk(conflict.path);
        await this.ctx.writePlainToDisk(conflictPath, localContent);
        if (conflict.remoteDeleted) {
          await this.ctx.applyRemoteDeletion(conflict.path, false);
        } else {
          await this.ctx.applyRemoteChange({ path: conflict.path, size: 0 });
        }
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
   *
   * Phase 12 NON-NEGOTIABLE #2: this monitor deliberately SURVIVES the vault
   * lock — enterLockState stops the sync + key-renewal timers but never this
   * one. The heartbeat depends only on the session (not the LAK/lease), so a
   * revoked/offboarded user or the 24h maxSessionDurationHours cap still drives
   * checkRevocationHeartbeat → handleServerRevocation → a REAL forceLogout while
   * the vault is merely locked. A locked session can never resurrect a
   * revoked/expired one. Do NOT add an isVaultLocked guard here.
   */
  startHeartbeatMonitor(): void {
    this.stopHeartbeatMonitor();
    if (this.isLocalProjectMemoryMode()) return;
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
    if (this.isLocalProjectMemoryMode()) return;
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
    if (this.isLocalProjectMemoryMode()) return;
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
    // Phase 12 (NN-2 belt-and-suspenders): while the vault is locked the key
    // lease is evicted and enterLockState already stopped this monitor — but a
    // scheduled tick that slipped through must be a strict no-op, never an
    // attempted renewal / recovery that could spuriously log the user out or
    // re-acquire the lease the lock just dropped. The revocation heartbeat is
    // the ONLY server-facing loop that keeps running while locked.
    if (this.ctx.isVaultLocked?.()) {
      return;
    }
    if (!this.ctx.getSession()) {
      return;
    }
    // Local Project Memory Mode disables cloud sync entirely, so lease renewal is
    // a no-op. Checked after the session guard so the (session-less) NN-2 lock
    // path never touches settings — see idle-lock-policy.test.ts.
    if (this.isLocalProjectMemoryMode()) return;

    const keyLease = this.ctx.getKeyLease();
    if (!keyLease) {
      // Recovery path. Retry when the previous attempt either returned 403
      // (limited access — permissions may have widened) OR failed transiently
      // (PL2 — a 5xx/network blip / a deferred startup refresh left a null
      // lease). We deliberately do NOT retry for a plain null lease with
      // neither flag set — that's a session with no vault binding yet, and
      // hammering the API would be wrong.
      const wasDenied = this.ctx.isVaultLeaseDenied();
      const retryNeeded = this.ctx.isLeaseRetryNeeded();
      if ((wasDenied || retryNeeded) && this.ctx.getSettings().serverVaultId) {
        try {
          const result = await this.ctx.ensureVaultScopedKeyLease();
          if (result === "ok") {
            this.ctx.log("Vault-scoped key lease recovered.");
            // Only announce "full access restored" if the user was actually in
            // limited-access mode — a transient-retry recovery never showed a
            // limitation, so a restore notice would be confusing.
            if (wasDenied) {
              this.ctx.showNotice("VaultGuard Sync: Full vault access restored.");
            }
            this.ctx.emitPermissionChanged({ serverConfirmed: true });
            this.ctx.clearPlaceholderPaths();
          }
        } catch (err) {
          // Network blips and 5xxs are expected during recovery polling.
          // Stay in the pending state and try again next tick.
          this.ctx.logError("Key lease retry failed (will retry)", err);
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
  /** True when an offline write/delete for this normalized path is queued. */
  private hasPendingOfflineOperation(path: string): boolean {
    return this.ctx.getOfflineQueue().some((op) => op.path === path);
  }

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
    data?: string,
    // BIN-A / D-09 + version-guard: `options` may mark a binary payload (encoding
    // "base64" + MIME contentType, `data` = base64 of plain bytes) and/or carry
    // the version-guard baseline (baseVersionId/baseHash). Defaults to {} so all
    // existing text call sites stay valid unchanged.
    options: {
      encoding?: "base64";
      contentType?: string;
      baseVersionId?: string;
      baseHash?: string;
    } = {}
  ): void {
    const normalizedPath = this.ctx.normalizeVaultPath(path);
    // Deduplicate: remove existing operations for the same path
    this.ctx.setOfflineQueue(
      this.ctx.getOfflineQueue().filter((op) => op.path !== normalizedPath)
    );

    const entry: OfflineQueueOperation = {
      operation,
      path: normalizedPath,
      data,
      baseVersionId:
        options.baseVersionId ?? this.ctx.getExpectedVersionId(normalizedPath),
      baseHash:
        options.baseHash ?? this.ctx.getRemoteFileState(normalizedPath)?.baseHash,
      timestamp: new Date().toISOString(),
    };
    // BIN-A / D-09: stamp binary payloads (base64 + MIME) so the flush fork
    // replays them through the byte crypto path.
    if (options.encoding !== undefined) {
      entry.encoding = options.encoding;
    }
    if (options.contentType !== undefined) {
      entry.contentType = options.contentType;
    }

    this.ctx.setOfflineQueue([...this.ctx.getOfflineQueue(), entry]);

    this.ctx.log(
      `Queued offline operation: ${operation} "${normalizedPath}" (queue size: ${this.ctx.getOfflineQueue().length})`
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
    const operation = this.currentSyncOperation;
    operation?.update({
      phase: "Flushing queued changes",
      processedItems: 0,
      totalItems: queue.length,
      percent: 10,
      approximatePercent: true,
    });

    for (let index = 0; index < queue.length; index++) {
      const op = queue[index];
      try {
        // Local-only opt-out: drop any queued op whose path the user has
        // since added to the exclusion list, so we don't quietly upload it.
        if (this.ctx.isPathExcluded(op.path)) {
          continue;
        }
        switch (op.operation) {
          case "write":
            if (op.data) {
              if (op.encoding === "base64") {
                // BIN-A: binary payloads replay through the BYTE crypto path —
                // decode the stored base64 of the PLAIN bytes, byte-encrypt, and
                // PUT with the real MIME contentType and the large-body timeout
                // (L2). Never the string path: a lossy UTF-8 re-encode would
                // corrupt the server copy (AR1/L1). The optimistic version guard
                // rides along via buildWriteBody, but binary conflicts resolve
                // through the byte assert path below (handleRemoteWriteConflict is
                // text-only), so a binary 409 is requeued rather than diffed.
                const bytes = this.base64ToBytes(op.data);
                const byteBuffer = bytes.buffer as ArrayBuffer;
                const encrypted = await this.ctx.encryptContentBytes(byteBuffer);
                const hash = await this.ctx.computeHashBytes(byteBuffer);
                const expectedVersionId =
                  op.baseVersionId ?? this.ctx.getExpectedVersionId(op.path);
                const body = this.buildWriteBody(op.path, encrypted, hash, {
                  expectedVersionId,
                });
                body.contentType = op.contentType ?? contentTypeForPath(op.path);
                const response = await this.ctx.apiRequest<RemoteFileWriteResponse>(
                  "PUT",
                  this.ctx.vaultPath(`/files/${encodeURIComponent(op.path)}`),
                  body,
                  undefined,
                  { timeoutMs: BINARY_PUT_TIMEOUT_MS }
                );
                this.assertOfflineFlushResponse(response, op);
                this.recordSuccessfulWrite(op.path, hash, response);
              } else {
                const encrypted = await this.ctx.encryptContent(op.data);
                const hash = await this.ctx.computeHash(op.data);
                const expectedVersionId =
                  op.baseVersionId ?? this.ctx.getExpectedVersionId(op.path);
                const response = await this.ctx.apiRequest<RemoteFileWriteResponse>(
                  "PUT",
                  this.ctx.vaultPath(`/files/${encodeURIComponent(op.path)}`),
                  this.buildWriteBody(op.path, encrypted, hash, { expectedVersionId })
                );
                if (!response.success && response.error?.statusCode === 409) {
                  const resolution = await this.handleRemoteWriteConflict(
                    op.path,
                    op.data,
                    expectedVersionId
                  );
                  if (resolution === "pending") {
                    throw new Error(
                      response.error?.message ?? `Conflict for "${op.path}" requires resolution.`
                    );
                  }
                  break;
                }
                this.assertOfflineFlushResponse(response, op);
                this.recordSuccessfulWrite(op.path, hash, response);
              }
            }
            break;
          case "delete": {
            const response = await this.ctx.apiRequest(
              "DELETE",
              this.ctx.vaultPath(`/files/${encodeURIComponent(op.path)}`),
              this.buildDeleteBody(op.path, op.baseVersionId)
            );
            // Returns on success / 404 / 401 / 403 (throws on other failures,
            // leaving the tombstone in place to retry). Any return means the
            // server has settled this delete - clear its tombstone.
            this.assertOfflineFlushResponse(response, op);
            this.clearDeletionTombstone(op.path);
            if (response.success || response.error?.statusCode === 404) {
              this.ctx.recordRemoteFileAbsent(op.path);
            }
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
      } finally {
        operation?.update({
          phase: "Flushing queued changes",
          processedItems: index + 1,
          totalItems: queue.length,
          approximatePercent: true,
          message: `${Math.max(0, queue.length - index - 1)} queued operation(s) remaining.`,
        });
        if ((index + 1) % DEFAULT_LONG_OPERATION_BATCH_SIZE === 0) {
          await yieldToEventLoop();
        }
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
    // BIN-A / L8: `encoding` lets the permanent-drop branch tell a user's binary
    // attachment apart from a text edge case (Notice vs console-only).
    op: { operation: "write" | "delete"; path: string; encoding?: "base64" }
  ): void {
    if (response.success) {
      return;
    }

    const status = response.error?.statusCode ?? 0;
    if (op.operation === "delete" && status === 404) {
      return;
    }
    if (op.operation === "delete" && status === 409) {
      throw new Error(response.error?.message ?? "Offline delete conflict.");
    }
    if (op.operation === "write" && status === 409) {
      throw new Error(response.error?.message ?? "Offline write conflict.");
    }

    const message = response.error?.message ?? "Offline operation failed.";
    if (status === 401 || status === 403) {
      this.ctx.logError(
        `Dropping queued ${op.operation} for "${op.path}" after server rejection`,
        new Error(message)
      );
      return;
    }

    // AC-API1: transient failures (network / 5xx / 429) throw so the flush
    // requeues the op and retries later.
    if (status === 0 || status === 429 || status >= 500) {
      throw new Error(message);
    }

    // Permanent 4xx (413 too-large, 409, 400…): the server will never accept
    // this op — drop it instead of jamming the flush queue forever. The local
    // file is untouched; catch-up will surface it as local-only.
    this.ctx.logError(
      `Dropping queued ${op.operation} for "${op.path}" after permanent server rejection (HTTP ${status})`,
      new Error(message)
    );
    // L8 (BIN-A): a dropped TEXT op is a rare edge case (console-only, today's
    // behavior). A dropped BINARY op is a user's attachment silently vanishing —
    // e.g. 402 storage-quota, which can't be pre-gated client-side. Surface a
    // Notice naming the file so the drop is visible. AC-API1 classification above
    // is unchanged: this only adds visibility, never alters which statuses drop.
    if (op.encoding === "base64") {
      new Notice(
        `VaultGuard Sync: Queued upload of "${op.path}" was rejected by the server (HTTP ${status}) and removed from the queue.`,
        10000
      );
    }
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
