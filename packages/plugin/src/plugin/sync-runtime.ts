import { Notice, TFile } from "obsidian";
import type {
  LocalManifestEntry,
  MutationIntent,
  OfflineQueueOperation,
  RemoteFileContentResponse,
  RemoteFileFetchOptions,
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
  JSON_SYNC_MAX_ENCRYPTED_BYTES,
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
 * Discriminated outcome of a reconciliation upload.
 *
 * SD-06-F4: **no** outcome may cause the removal of a local-only file. A file
 * that reaches these callers is by construction one the server has never
 * received, so deleting it destroys the only copy. `skipped-no-permission`
 * means the file is un-syncable *for now* (the user lacks write permission) and
 * the local copy is HELD; `skipped-no-lease` is transient (a lease may still
 * return) and is likewise held. The permission-store state is a diagnostic log
 * field, never a delete gate.
 */
export type UploadReconciledOutcome =
  | "uploaded"
  | "skipped-no-lease"
  | "skipped-no-permission"
  // SD-06-F1 (16-03): the upload DECLARED `mustBeAbsent` — its caller had
  // proven absence from a fresh inventory — and the server answered 409, so
  // another device created the path in between. A lost create RACE, not a
  // failure: the loop must continue, the local file must stay, and the outcome
  // must be visibly non-"uploaded". It belongs in the SKIPPED bucket, never a
  // delete (SY2 / SD-06-F4). Reconciliation's conflict classification resolves
  // the divergence on the next pass.
  | "skipped-create-conflict";

/**
 * Byte-upload outcome. Every text outcome plus `pending-large`, returned when
 * an above-JSON-threshold direct transfer could not complete.
 *
 * SD-06-F4: as with the text sibling, no outcome may delete or overwrite the
 * local file. `pending-large` and `skipped-no-lease` are transient (retry later),
 * `skipped-no-permission` is held indefinitely — held always means intact.
 *
 * This is a superset SIBLING of UploadReconciledOutcome rather than a widening
 * of it, so the string uploadReconciledFile contract (and its ctx forwarding)
 * stays narrow — the text path can never return `pending-large`, so no
 * text-path caller has to guard a case it cannot produce.
 */
export type UploadReconciledBinaryOutcome =
  | UploadReconciledOutcome
  | "pending-large";

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
 * Per-path throttle window for a pending large-file Notice.
 */

/** Grace period before key expiry to trigger renewal (5 minutes). */
const KEY_RENEWAL_GRACE_MS = 5 * 60 * 1000;

/** Server heartbeat interval for revocation detection. */
const HEARTBEAT_INTERVAL_MS = 60 * 1000;

/**
 * Maximum number of ordinary remote-file GETs allowed in flight while a sync
 * applies a delta page. Local mutations remain ordered and single-threaded;
 * only the network reads overlap. Four keeps memory/request pressure bounded
 * while removing the N × round-trip latency penalty for small reconciliation
 * pages.
 */
const REMOTE_APPLY_PREFETCH_CONCURRENCY = 4;

/**
 * A sync page must not spend the generic three-attempt (~105 s) envelope on
 * one tiny file while later completed reads wait behind it. Obsidian's
 * requestUrl has no abort handle, so each prefetch gets one bounded attempt:
 * after the race times out there can be one orphaned GET, never three.
 */
const REMOTE_APPLY_PREFETCH_TIMEOUT_MS = 15_000;
const REMOTE_APPLY_PREFETCH_REQUEST_OPTIONS: Readonly<RemoteFileFetchOptions> = {
  timeoutMs: REMOTE_APPLY_PREFETCH_TIMEOUT_MS,
  maxAttempts: 1,
};

type RemoteChangePrefetchOutcome =
  | { response: ApiResponse<RemoteFileContentResponse>; error?: never }
  | { response?: never; error: unknown };

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
  private currentInitialReconciliationOperation: LongOperationHandle | null = null;

  constructor(private readonly ctx: SyncRuntimeContext) {}

  cancelActiveOperations(reason = "session context changed"): void {
    for (const operation of [
      this.currentInitialReconciliationOperation,
      this.currentSyncOperation,
    ]) {
      if (!operation) continue;
      operation.token.abortForShutdown();
      operation.cancel(`Stopped because ${reason}.`);
    }
    this.currentInitialReconciliationOperation = null;
    this.currentSyncOperation = null;
    this.stopSyncTimer();
  }

  private protectedContentGate(): ReturnType<NonNullable<SyncRuntimeContext["getProtectedContentGate"]>> {
    return this.ctx.getProtectedContentGate?.() ?? { ok: true };
  }

  private assertProtectedContentAllowed(): void {
    const gate = this.protectedContentGate();
    if (!gate.ok) throw new Error(gate.message);
  }

  private canPrefetchRemoteChange(metadata: { path: string; size: number }): boolean {
    const normalizedPath = this.ctx.normalizeVaultPath(metadata.path);
    return (
      this.protectedContentGate().ok &&
      !this.ctx.isPathExcluded(normalizedPath) &&
      !this.ctx.getSettings().pendingLargeFiles?.[normalizedPath] &&
      metadata.size <= JSON_SYNC_MAX_ENCRYPTED_BYTES
    );
  }

  /**
   * Starts a bounded rolling window of remote GETs and yields each response in
   * input order. Callers still apply local mutations one at a time, preserving
   * event ordering and the applyingRemoteWrite no-echo guard.
   */
  private createRemoteChangePrefetchWindow<T extends { path: string; size: number }>(
    items: readonly T[],
    shouldPrefetch: (item: T) => boolean,
  ): { take(index: number): Promise<ApiResponse<RemoteFileContentResponse> | undefined> } {
    const pending = new Map<number, Promise<RemoteChangePrefetchOutcome>>();
    const schedule = (index: number): void => {
      const item = items[index];
      if (!item || !shouldPrefetch(item)) return;
      const normalizedPath = this.ctx.normalizeVaultPath(item.path);
      const startedAt = Date.now();
      this.ctx.recordSyncDiagnostic("remotePrefetch.start", {
        index,
        path: normalizedPath,
        timeoutMs: REMOTE_APPLY_PREFETCH_TIMEOUT_MS,
      });
      pending.set(
        index,
        this.ctx.fetchRemoteFileContent(
          normalizedPath,
          REMOTE_APPLY_PREFETCH_REQUEST_OPTIONS,
        ).then(
          (response) => {
            this.ctx.recordSyncDiagnostic("remotePrefetch.done", {
              index,
              path: normalizedPath,
              elapsedMs: Date.now() - startedAt,
              success: response.success,
              statusCode: response.error?.statusCode ?? null,
              requestId: response.requestId || null,
            });
            return { response };
          },
          (error) => {
            this.ctx.recordSyncDiagnostic("remotePrefetch.done", {
              index,
              path: normalizedPath,
              elapsedMs: Date.now() - startedAt,
              success: false,
              message: error instanceof Error ? error.message : String(error),
            });
            return { error };
          },
        ),
      );
    };

    for (
      let index = 0;
      index < Math.min(REMOTE_APPLY_PREFETCH_CONCURRENCY, items.length);
      index += 1
    ) {
      schedule(index);
    }

    return {
      take: async (index) => {
        const prefetched = pending.get(index);
        pending.delete(index);
        const outcome = prefetched ? await prefetched : undefined;
        // Advance only after this slot settles, keeping the in-flight request
        // count at or below the configured cap. Non-prefetched entries still
        // advance their slot so tombstones/markers cannot starve later files.
        schedule(index + REMOTE_APPLY_PREFETCH_CONCURRENCY);
        if (outcome?.error) throw outcome.error;
        return outcome?.response;
      },
    };
  }

  private applyRemoteChangeWithOptionalPrefetch(
    metadata: { path: string; size: number },
    prefetchedResponse?: ApiResponse<RemoteFileContentResponse>,
  ): Promise<void> {
    return prefetchedResponse === undefined
      ? this.ctx.applyRemoteChange(metadata)
      : this.ctx.applyRemoteChange(metadata, prefetchedResponse);
  }

  /** Prove a prefetched payload is readable before DUPLICATE mutates local state. */
  private async fetchServerDecryptedFallback(
    path: string,
  ): Promise<ApiResponse<RemoteFileContentResponse>> {
    const response = await this.ctx.readFileDecrypted(
      path,
      REMOTE_APPLY_PREFETCH_REQUEST_OPTIONS,
    );
    if (!response.success || !response.data || response.data.decrypted !== true) {
      throw new Error(
        response.error?.message ??
          `Server-authorized decrypt fallback for "${path}" did not return plaintext.`,
      );
    }
    return response;
  }

  private async validateRemoteChangeResponse(
    path: string,
    response: ApiResponse<RemoteFileContentResponse>,
  ): Promise<ApiResponse<RemoteFileContentResponse>> {
    this.assertProtectedContentAllowed();
    if (!response.success || !response.data) {
      throw new Error(response.error?.message ?? `Failed to read ${path} from the server.`);
    }
    try {
      if (isBinaryContentType(response.data.contentType)) {
        if (response.data.decrypted === true) {
          this.base64ToBytes(response.data.content);
        } else {
          await this.ctx.decryptContentBytes(response.data.content);
        }
      } else {
        await this.ctx.decodeRemoteFileContent(path, response.data);
      }
    } catch (error) {
      if (response.data.decrypted === true) throw error;
      const fallback = await this.fetchServerDecryptedFallback(path);
      return this.validateRemoteChangeResponse(path, fallback);
    }
    this.assertProtectedContentAllowed();
    return response;
  }

  private isLocalProjectMemoryMode(): boolean {
    return this.ctx.getSettings().localProjectMemoryMode === true;
  }

  /**
   * SD-06-F1 — `ctx.resolveMutationIntent` with 16-02's DECISION 5 runtime
   * guard. `tests/` is not typechecked, so a hand-built ctx that predates the
   * accessor must DEGRADE to today's behavior rather than throw. Returning
   * `undefined` (not `{kind:"unknown"}`) is deliberate: an undefined intent
   * leaves buildWriteBody on its legacy `expectedVersionId` derivation, so the
   * call site keeps whatever guard it passes today; a supplied `unknown` would
   * skip that derivation and silently DROP the guard.
   */
  private resolveIntentSafely(path: string): MutationIntent | undefined {
    const resolve = this.ctx.resolveMutationIntent;
    if (typeof resolve !== "function") return undefined;
    return resolve.call(this.ctx, path) ?? undefined;
  }

  /**
   * SD-06-F1 / DECISION 6 — the intent a RENAME DESTINATION declares.
   *
   * Resolve from the store first, then upgrade an `unknown` to
   * `must-be-absent`. The upgrade is justified by a STRUCTURAL fact, not a
   * probe: Obsidian refuses a rename onto an existing local path, so a rename
   * destination is by definition a locally-new path.
   *
   * Resolving first is strictly better than a blanket `mustBeAbsent`: a rename
   * back onto a path this client previously deleted resolves to
   * `must-be-absent` from the store anyway, and a rename onto a path the store
   * knows is `present(v)` resolves to `expect-version` — self-correcting, and
   * it is what keeps the P18 anchor (both paths seeded present) byte-identical.
   */
  private resolveRenameDestIntent(destPath: string): MutationIntent | undefined {
    const intent = this.resolveIntentSafely(destPath);
    if (intent === undefined) return undefined;
    return intent.kind === "unknown" ? { kind: "must-be-absent" } : intent;
  }

  private buildWriteBody(
    path: string,
    encryptedContent: string,
    hash: string,
    options: {
      forceOverwrite?: boolean;
      expectedVersionId?: string | null;
      intent?: MutationIntent;
      lane?: string;
    } = {},
  ): Record<string, unknown> {
    const body: Record<string, unknown> = {
      content: encryptedContent,
      hash,
    };
    // SD-06-F1 — DECISION 3 precedence. THIS FUNCTION IS DUPLICATED: the copy in
    // sync-runtime.ts and the copy in at-rest-adapter-runtime.ts are kept
    // TEXTUALLY IDENTICAL. Diff both bodies after any edit — drift here means
    // one runtime silently stops declaring intent while the other still does.
    //
    //   1. `forceOverwrite: true` wins outright: it is how the conflict
    //      KEEP_LOCAL path already declares a deliberate unconditional write.
    //   2. else an explicitly supplied `options.intent`.
    //   3. else — and ONLY when `intent` was not supplied at all — today's
    //      derivation from `options.expectedVersionId` / the store lookup, so
    //      every untouched call site keeps its exact current body.
    //
    // The legacy branch PRESERVES the pre-existing `undefined`-vs-`null`
    // distinction exactly: `undefined` means "option not supplied, look the
    // version up in the store"; `null` means "force-omit the guard, do NOT look
    // anything up" (the reconciliation JSON lane depends on that). Collapsing
    // the two would start sending `expectedVersionId` on catch-up re-uploads.
    const legacyExpectedVersionId =
      options.expectedVersionId === undefined
        ? this.ctx.getExpectedVersionId(path)
        : options.expectedVersionId ?? undefined;
    const intent: MutationIntent = options.forceOverwrite
      ? { kind: "force" }
      : (options.intent ??
        (legacyExpectedVersionId
          ? { kind: "expect-version", versionId: legacyExpectedVersionId }
          : { kind: "unknown" }));
    // Field names are 16-01's SHIPPED wire contract, verbatim (16-01-SUMMARY.md
    // — "The wire contract you must emit, verbatim"): `expectedVersionId` is a
    // string, `mustBeAbsent` / `force` are the boolean LITERAL `true`, and at
    // most one of the three may appear or the server answers 400.
    if (intent.kind === "expect-version") {
      body.expectedVersionId = intent.versionId;
    } else if (intent.kind === "must-be-absent") {
      body.mustBeAbsent = true;
    } else if (intent.kind === "force") {
      body.force = true;
    } else {
      // Unknown lane: TODAY's exact body (no intent key at all) plus ONE
      // device-local breadcrumb, so the residual is measurable before anyone
      // flips server enforcement. Never map unknown to `force` — that would
      // make every lost-track write an explicit unconditional overwrite forever
      // and permanently blind the telemetry the flip depends on. Never map it
      // to `must-be-absent` either: not knowing is not knowing.
      this.ctx.recordSyncDiagnostic?.("mutationIntent.unknown", {
        path,
        lane: options.lane ?? "unspecified",
      });
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

  private recordDirectWrite(
    path: string,
    hash: string,
    result: { versionId?: string; lastModified: string; size: number },
  ): void {
    this.ctx.recordRemoteFilePresent(path, {
      versionId: result.versionId,
      baseHash: hash,
      lastModified: result.lastModified,
      size: result.size,
    });
  }

  private async markPendingLargeFile(
    path: string,
    bytes: ArrayBuffer,
    contentType: string,
    reason: import("../types").PendingLargeFileRecord["reason"],
    previousPath?: string,
  ): Promise<void> {
    const normalized = this.ctx.normalizeVaultPath(path);
    const existing = this.ctx.getSettings().pendingLargeFiles?.[normalized];
    await this.ctx.upsertPendingLargeFile({
      path: normalized,
      ...(previousPath
        ? { previousPath: this.ctx.normalizeVaultPath(previousPath) }
        : {}),
      size: bytes.byteLength,
      sha256: await this.ctx.computeHashBytes(bytes),
      contentType,
      reason,
      state: reason === "conflict" ? "blocked" : "retryable",
      localProtection: "plaintext-pending",
      attempts: (existing?.attempts ?? 0) + 1,
      updatedAt: new Date().toISOString(),
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
    const protectionGate = this.protectedContentGate();
    if (!protectionGate.ok) {
      this.ctx.log(protectionGate.message);
      this.ctx.recordSyncDiagnostic("initializeSyncEngine.skipped", {
        reason: protectionGate.reason,
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
    // quick-260820-or3: routed through the same helper the Phase 1b catch-up
    // gate uses, so "may I upload" and "must I reconcile" cannot drift apart —
    // that drift is exactly the hole the silent local-only upload came through.
    // Provably unchanged: with `vaultId` truthy the helper's `!!serverVaultId`
    // term is satisfied and it reduces to `bindingReconciledVaultId === vaultId`;
    // negated, `!== vaultId` — the expression this replaces.
    const vaultId = settings.serverVaultId;
    this.ctx.recordSyncDiagnostic("initializeSyncEngine.reconcileDecision", {
      willReconcile: !!vaultId && !this.isBindingReconciled(),
    });
    if (vaultId && !this.isBindingReconciled()) {
      try {
        const reconciled = await this.ctx.performInitialReconciliation();
        if (!reconciled) {
          this.ctx.log("Initial reconciliation declined or aborted — sync engine will not start.");
          this.ctx.recordSyncDiagnostic("initializeSyncEngine.return.reconcileDeclined");
          // NEVER a silent dead end (quick-260820-mv4). This return skips
          // performSync() and startSyncTimer(), and nothing else re-arms
          // them — before this the folder simply stopped syncing until
          // Obsidian was restarted, with no visible reason. The sticky notice
          // names the state and carries the retry.
          this.ctx.showReconciliationPausedNotice(
            "Reconciling compares this folder with the server vault before the first sync."
          );
          return;
        }
      } catch (err) {
        this.ctx.logError("Initial reconciliation failed", err);
        this.ctx.recordSyncDiagnostic("initializeSyncEngine.return.reconcileFailed");
        this.ctx.showReconciliationPausedNotice(
          `Reconciling failed: ${err instanceof Error ? err.message : "Unknown error"}.`
        );
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

    // Sync is armed — the paused state is over, so its sticky notice goes.
    this.ctx.hideReconciliationPausedNotice();
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

    const protectionGate = this.protectedContentGate();
    if (!protectionGate.ok) {
      this.ctx.log(protectionGate.message);
      if (userInitiated) this.ctx.showNotice(protectionGate.message, 9000);
      this.ctx.recordSyncDiagnostic("performSync.skipped", { reason: protectionGate.reason });
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
    let totalFilesHeld = 0;
    let totalFilesDownloaded = 0;
    let totalFoldersDownloaded = 0;
    let totalRepairFailures = 0;
    let deltaCount = 0;
    let remoteApplyFailures = 0;

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
      const retriedLargeFiles = canUploadEncryptedContent
        ? await this.retryPendingLargeFiles(userInitiated)
        : 0;
      totalFilesUploaded += retriedLargeFiles;
      const flushedSomething =
        canUploadEncryptedContent &&
        (offlineQueueSizeBefore > 0 || retriedLargeFiles > 0);

      // Phase 1b: Catch up local-only files + folders.
      let catchupChanges = 0;
      const catchupArmed = forceCatchup || !this.ctx.getLocalOnlyCatchupCompleted();
      // quick-260820-or3: a SEPARATE conjunct, deliberately NOT folded into the
      // disjunction above. Every "Sync now" entry point passes
      // `forceCatchup: true` (commands.ts:426, main.ts:4546 / :7180 / :7453), so
      // an `||` here would hand a user who DECLINED the reconciliation preview
      // exactly what they refused the moment they pressed "Sync now", and would
      // let a rebound folder push the OLD vault's leftovers into the NEW one.
      // `forceCatchup` means "re-run the repair passes", never "skip consent".
      const bindingReconciled = this.isBindingReconciled();
      if (canUploadEncryptedContent && catchupArmed && bindingReconciled) {
        operation.update({
          phase: "Catching up local-only files",
          percent: 25,
          approximatePercent: true,
        });
        const result = await this.ctx.uploadLocalOnlyFiles();
        if (result) {
          totalFilesUploaded += result.uploadedFiles;
          totalFoldersUploaded += result.uploadedFolders;
          totalFilesHeld += result.heldNoPermissionFiles;
          // SD-06-F4: held files are deliberately NOT a catch-up "change".
          // Holding alters neither local nor server state, so counting it here
          // would suppress the cursor short-circuit below forever. (The old
          // term was correct only because the outcome used to be a deletion,
          // which did change local state.)
          catchupChanges = result.uploadedFiles + result.uploadedFolders;
          // SY7: only mark catch-up complete when nothing failed. A transient
          // upload/folder failure previously still flipped the flag true, so
          // catch-up never re-ran (until forceCatchup) and the affected files
          // stayed local-only and unsynced indefinitely.
          this.ctx.setLocalOnlyCatchupCompleted(
            result.failedFiles === 0 && result.failedFolders === 0
          );
        }
      } else if (canUploadEncryptedContent && catchupArmed) {
        // The binding was never reconciled (first bind), was rebound, or the
        // user declined the preview. Reconciliation — the one path that ASKS
        // (askReconciliationPlan) — is the only route these files may take.
        //
        // Deliberately does NOT call setLocalOnlyCatchupCompleted: leaving the
        // flag armed is what lets the catch-up run by itself the moment the
        // binding does reconcile.
        this.ctx.recordSyncDiagnostic("performSync.catchupSkipped", {
          reason: "bindingNotReconciled",
          serverVaultId: settings.serverVaultId,
          bindingReconciledVaultId: settings.bindingReconciledVaultId ?? null,
        });
        this.ctx.log(
          `Sync: local-only catch-up skipped — this folder is bound to ${
            settings.serverVaultId
          } but was last reconciled with ${
            settings.bindingReconciledVaultId ?? "no vault"
          }. Reconciling reviews those files before anything is uploaded.`
        );
        if (userInitiated) {
          // No file count: producing one would need the full server inventory
          // walk that is exactly what is being skipped. Background syncs stay
          // silent — mv4's sticky paused notice already owns this state.
          this.ctx.showNotice(
            "VaultGuard Sync: Local-only files were not uploaded — this folder has not been reconciled with its server vault yet. Reconciling shows what would be uploaded and asks first.",
            9000
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
          if (!cursor.reconciliationRequired && cursor.revision === syncState.lastSeenRevision) {
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
        reconciliationRequired?: boolean;
      }>("POST", this.ctx.vaultPath("/files/sync"), {
        lastSyncTimestamp: syncState.lastSync ?? new Date(0).toISOString(),
        fileChecksums: this.ctx.buildLocalSyncManifest(),
      });

      if (!response.success || !response.data) {
        throw new Error(response.error?.message ?? "Sync request failed.");
      }
      await operation.token.checkpoint();

      if (response.data.permissionsChanged) {
        this.ctx.log("Sync: permission rules changed on the server — emitting bus event.");
        this.ctx.emitPermissionChanged({
          serverConfirmed: true,
          semanticAuthorityChanged: true,
        });
      }
      if (response.data.reconciliationRequired) {
        this.ctx.log(
          "Sync: a durable server mutation is awaiting activity reconciliation; full-scan results remain authoritative."
        );
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
      const prefetchWindow = this.createRemoteChangePrefetchWindow(
        response.data.deltas,
        (delta) => {
          const normalizedPath = this.ctx.normalizeVaultPath(delta.path);
          return (
            delta.action !== "deleted" &&
            !this.isFolderMarkerPath(normalizedPath) &&
            !this.hasPendingOfflineOperation(normalizedPath) &&
            this.canPrefetchRemoteChange(delta)
          );
        },
      );

      for (const [deltaIndex, delta] of response.data.deltas.entries()) {
        await operation.token.checkpoint();
        appliedDeltaIndex += 1;
        const normalizedPath = this.ctx.normalizeVaultPath(delta.path);
        try {
          operation.update({
            phase: "Applying remote changes",
            processedItems: appliedDeltaIndex - 1,
            totalItems: deltaCount,
            processedBytes: appliedDeltaBytes,
            message: `Downloading remote change ${appliedDeltaIndex} of ${deltaCount}: ${normalizedPath}`,
          });
          const prefetchedResponse = await prefetchWindow.take(deltaIndex);

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

          await this.applyRemoteChangeWithOptionalPrefetch(
            {
              path: normalizedPath,
              size: delta.size,
            },
            prefetchedResponse,
          );
          appliedDeltaBytes += delta.size ?? 0;
        } catch (error) {
          remoteApplyFailures += 1;
          this.ctx.logError(
            `Sync: remote change ${appliedDeltaIndex} of ${deltaCount} failed for "${normalizedPath}"; continuing without advancing the sync cursor.`,
            error,
          );
          this.ctx.recordSyncDiagnostic("remoteApply.failed", {
            index: deltaIndex,
            path: normalizedPath,
            action: delta.action,
            message: error instanceof Error ? error.message : String(error),
          });
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

      await operation.token.checkpoint();

      if (remoteApplyFailures > 0) {
        const remoteApplySuccesses = deltaCount - remoteApplyFailures;
        const message =
          `VaultGuard Sync: ${remoteApplyFailures} of ${deltaCount} remote changes failed; ` +
          `${remoteApplySuccesses} succeeded. The failed item was not skipped in sync state — ` +
          "the cursor was kept so Sync now can retry it.";
        const error = new Error(message);
        syncState.status = "error";
        syncState.lastError = message;
        operation.fail(error);
        this.ctx.logError("Sync finished with remote-apply failures", error);
        this.ctx.recordSyncDiagnostic("performSync.remoteApplyIncomplete", {
          failed: remoteApplyFailures,
          succeeded: remoteApplySuccesses,
          total: deltaCount,
        });
        this.ctx.showNotice(message, 12000);
        return;
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

      await operation.token.checkpoint();

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
      if (totalFilesHeld > 0) {
        summaryParts.push(`${totalFilesHeld} local-only files kept (no write permission)`);
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
  async fetchSyncCursor(): Promise<{
    revision: number;
    lastChangedAt: string;
    reconciliationRequired: boolean;
  } | null> {
    if (!this.ctx.getSession() || !this.ctx.getSettings().serverVaultId) return null;
    try {
      const response = await this.ctx.apiRequest<{
        revision: number;
        lastChangedAt: string;
        reconciliationRequired?: boolean;
        serverTime: string;
      }>("GET", this.ctx.vaultPath("/sync-cursor"));
      if (!response.success || !response.data) return null;
      return {
        revision: response.data.revision,
        lastChangedAt: response.data.lastChangedAt,
        reconciliationRequired: response.data.reconciliationRequired === true,
      };
    } catch (err) {
      this.ctx.logError("Sync cursor fetch failed", err);
      return null;
    }
  }

  async readFileDecrypted(
    relPath: string,
    options?: RemoteFileFetchOptions,
  ): Promise<ApiResponse<RemoteFileContentResponse>> {
    const normalizedPath = this.ctx.normalizeVaultPath(relPath);
    const encoded = normalizedPath
      .split("/")
      .map((segment) => encodeURIComponent(segment))
      .join("/");
    const endpoint = this.ctx.vaultPath(`/files-decrypted/${encoded}`);
    return options === undefined
      ? this.ctx.apiRequest<RemoteFileContentResponse>("GET", endpoint)
      : this.ctx.apiRequest<RemoteFileContentResponse>(
          "GET",
          endpoint,
          undefined,
          undefined,
          options,
        );
  }

  async fetchRemoteFileContent(
    path: string,
    options?: RemoteFileFetchOptions,
  ): Promise<ApiResponse<RemoteFileContentResponse>> {
    const normalizedPath = this.ctx.normalizeVaultPath(path);
    const serverDecrypt =
      !this.hasValidKeyLease() || this.ctx.isPathDeniedByKeyLease(normalizedPath);
    if (serverDecrypt) {
      return options === undefined
        ? this.ctx.readFileDecrypted(normalizedPath)
        : this.ctx.readFileDecrypted(normalizedPath, options);
    }
    const endpoint = this.ctx.vaultPath(`/files/${encodeURIComponent(normalizedPath)}`);
    return options === undefined
      ? this.ctx.apiRequest<RemoteFileContentResponse>("GET", endpoint)
      : this.ctx.apiRequest<RemoteFileContentResponse>(
          "GET",
          endpoint,
          undefined,
          undefined,
          options,
        );
  }

  async decodeRemoteFileContent(
    path: string,
    data: RemoteFileContentResponse
  ): Promise<string> {
    const normalizedPath = this.ctx.normalizeVaultPath(path);
    // Server-authorized plaintext takes precedence over the lease carve-out.
    // A `deniedPaths` entry is a *raw* deny rule (the backend's
    // findApplicableDenyRulesInScope does not resolve allow-overrides), so a
    // path whose deny is beaten by a higher-priority/more-specific allow is
    // still listed here. When the server returns already-decrypted bytes it
    // means its own authoritative per-file gate (evaluatePermission over the
    // vault-membership role) allowed the read — that is the source of truth,
    // so honor it rather than over-block a file the user can legitimately read
    // (SD-03-F8/F2 over-block regression).
    if (data.decrypted === true) {
      return this.decodeBase64Utf8(data.content);
    }
    // Raw-ciphertext branch only: refuse to decrypt a carve-out-denied path
    // with the broad vault DEK. fetchRemoteFileContent already routes denied
    // paths to the server (so a denied path never reaches here with raw
    // bytes) — this is defense-in-depth for any direct caller.
    if (this.ctx.isPathDeniedByKeyLease(normalizedPath)) {
      throw this.remoteDecryptError(
        normalizedPath,
        new Error("key lease explicitly denies this path")
      );
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
      // SD-06-F1: a STRICT 404/410 is authoritative absence — the cheapest
      // absence knowledge the client has, and today it is thrown away. The
      // predicate is copied VERBATIM from the conflict re-fetch in
      // handleRemoteWriteConflict so all three sites agree exactly.
      //
      // Deliberately NOT recorded for statusCode 0 (offline), any 5xx, 401/403,
      // or a decrypt/shape failure: a permission or network failure is not
      // evidence of absence, and recording it would make the user's next save
      // declare mustBeAbsent and 409 against a file that exists. That is the
      // F1-adjacent denial-of-service trap (T-16-11).
      //
      // The throw below is unchanged — same control flow, same message, same
      // thrown type.
      if (
        !response.success &&
        (response.error?.statusCode === 404 || response.error?.statusCode === 410)
      ) {
        this.ctx.recordRemoteFileAbsent(normalizedPath);
      }
      throw new Error(
        response.error?.message ?? `Failed to read ${normalizedPath} from the server.`
      );
    }
    let readableData: RemoteFileContentResponse = response.data;
    try {
      await this.ctx.decodeRemoteFileContent(normalizedPath, readableData);
    } catch (error) {
      if (readableData.decrypted === true) throw error;
      const fallback = await this.fetchServerDecryptedFallback(normalizedPath);
      readableData = fallback.data!;
    }
    const plaintext = await this.ctx.decodeRemoteFileContent(
      normalizedPath,
      readableData,
    );
    this.recordRemoteReadState(
      normalizedPath,
      readableData,
      await this.ctx.computeHash(plaintext)
    );
    return plaintext;
  }

  async applyRemoteDeletion(normalizedPath: string, inferred: boolean): Promise<void> {
    this.assertProtectedContentAllowed();
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

  async applyRemoteChange(
    metadata: Pick<FileMetadata, "path" | "size">,
    prefetchedResponse?: ApiResponse<RemoteFileContentResponse>,
  ): Promise<void> {
    this.assertProtectedContentAllowed();
    const normalizedPath = this.ctx.normalizeVaultPath(metadata.path);
    if (this.ctx.isPathExcluded(normalizedPath)) {
      this.ctx.log(`Sync: skipping excluded path "${normalizedPath}".`);
      return;
    }
    if (
      this.ctx.isPathDeniedByKeyLease(normalizedPath) &&
      (
        prefetchedResponse === undefined ||
        (prefetchedResponse.success === true &&
          prefetchedResponse.data?.decrypted !== true)
      )
    ) {
      this.ctx.log(`Sync: skipping key-lease-denied path "${normalizedPath}".`);
      return;
    }
    if (this.ctx.getSettings().pendingLargeFiles?.[normalizedPath]) {
      this.ctx.log(
        `Sync: skipping remote apply for "${normalizedPath}" — a local large-file transfer is pending.`,
      );
      return;
    }

    // S3 metadata is ciphertext size. The JSON lane may be exactly
    // BINARY_SYNC_MAX_BYTES of plaintext plus the fixed 28-byte GCM envelope.
    if (metadata.size > JSON_SYNC_MAX_ENCRYPTED_BYTES) {
      if (!this.ctx.hasOriginalAdapterWrite()) return;
      try {
        const direct = await this.ctx.downloadLargeEncryptedFile(normalizedPath);
        this.assertProtectedContentAllowed();
        if (isBinaryContentType(direct.contentType)) {
          await this.writeLocalBinaryFileFromRemote(normalizedPath, direct.bytes);
        } else {
          const text = new TextDecoder("utf-8", { fatal: true }).decode(direct.bytes);
          await this.ctx.writeLocalFileFromRemote(normalizedPath, text);
        }
        this.ctx.recordRemoteFilePresent(normalizedPath, {
          versionId: direct.versionId,
          baseHash: direct.plaintextSha256,
          size: direct.plaintextSize,
        });
        this.ctx.getSyncState().bytesDownloaded += direct.plaintextSize;
        this.ctx.recordSyncDiagnostic("applyRemoteChange.direct-pull", {
          path: normalizedPath,
          bytes: direct.plaintextSize,
        });
      } catch (error) {
        this.ctx.logError(
          `Sync: direct download of "${normalizedPath}" failed integrity or authorization checks; local copy preserved.`,
          error,
        );
        this.ctx.notifyCloudDecryptFallback(normalizedPath);
        throw error;
      }
      return;
    }

    const response =
      prefetchedResponse ?? (await this.ctx.fetchRemoteFileContent(normalizedPath));
    this.assertProtectedContentAllowed();
    if (!response.success || !response.data) {
      // SD-06-F1: same strict 404/410 absence recording as readRemotePlaintext,
      // same verbatim predicate, same traps excluded (0 / 5xx / 401 / 403 are
      // NOT absence). Control flow, message and thrown type are unchanged. The
      // large/direct branch above is deliberately untouched — it preserves the
      // local copy and notifies, and the direct lane is already race-safe (P3).
      if (
        !response.success &&
        (response.error?.statusCode === 404 || response.error?.statusCode === 410)
      ) {
        this.ctx.recordRemoteFileAbsent(normalizedPath);
      }
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
        if (response.data.decrypted !== true) {
          try {
            const fallback = await this.fetchServerDecryptedFallback(normalizedPath);
            return this.applyRemoteChange(metadata, fallback);
          } catch (fallbackError) {
            decryptErr = fallbackError;
          }
        }
        // OD-2: a decode/decrypt failure NEVER wipes or overwrites the local
        // copy. It must still reject: reconciliation/conflict callers count a
        // fulfilled promise as an applied file and may otherwise advance their
        // cursor after a no-op (the Apply-plan false-success regression).
        this.ctx.logError(
          `Sync: skipping "${normalizedPath}" — cloud binary could not be decrypted.`,
          decryptErr
        );
        this.ctx.notifyCloudDecryptFallback(normalizedPath);
        throw this.remoteDecryptError(normalizedPath, decryptErr);
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
      if (response.data.decrypted !== true) {
        try {
          const fallback = await this.fetchServerDecryptedFallback(normalizedPath);
          return this.applyRemoteChange(metadata, fallback);
        } catch (fallbackError) {
          decryptErr = fallbackError;
        }
      }
      this.ctx.logError(
        `Sync: skipping "${normalizedPath}" — cloud copy could not be decrypted.`,
        decryptErr
      );
      this.ctx.notifyCloudDecryptFallback(normalizedPath);
      // Preserve the local bytes but make the no-apply outcome explicit to all
      // callers. In particular, initial reconciliation must count this as a
      // failed conflict and retain its previous binding/cursor for retry.
      throw this.remoteDecryptError(normalizedPath, decryptErr);
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
    this.assertProtectedContentAllowed();
    const normalized = this.ctx.normalizeVaultPath(path);
    await this.ctx.ensureParentFoldersForPath(normalized);
    if (!this.ctx.hasOriginalAdapterWrite()) {
      throw new Error(`VaultGuard Sync: cannot write "${normalized}" — vault adapter unavailable.`);
    }

    // The Obsidian vault create/modify promise can remain pending even after
    // its adapter write has durably landed (observed during first-bind recovery).
    // Await the authoritative VG1 at-rest writer instead; Obsidian's file
    // watcher indexes the resulting create/modify asynchronously. This also
    // avoids holding the global applyingRemoteWrite flag across a host promise.
    await this.ctx.writePlainToDisk(normalized, content);
  }

  /**
   * BIN-A / D-06 (pull side): byte sibling of writeLocalFileFromRemote. Writes a
   * pulled binary to disk VG1-encrypted through the authoritative direct
   * at-rest writer. Obsidian's watcher indexes the resulting path afterward.
   *
   * L13 gate FIRST: writePlainBinaryToDisk SILENTLY no-ops when the adapter has
   * no writeBinary (unlike the string writePlainToDisk's AR2 throw), so a legacy
   * adapter must skip here — downloaded content is never silently discarded, and
   * legacy adapters keep today's no-binary behavior (D-10).
   *
   * Pull-side VG1 writes are CR-1-safe in any wave: a pulled binary has a server
   * copy by definition. Pull-written binaries read back immediately through the
   * intercepted adapter, which decrypts VG1 transparently.
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

    await this.ctx.writePlainBinaryToDisk(normalized, bytes);
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
    this.assertProtectedContentAllowed();
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
          // interceptedRename fix (11-02). Above-threshold content becomes a
          // metadata-only pending rename; never remove the old server copy
          // without a durable replacement.
          if (result.bytes.byteLength > BINARY_SYNC_MAX_BYTES) {
            await this.markPendingLargeFile(
              newNormalized,
              result.bytes,
              contentTypeForPath(newNormalized),
              !this.ctx.isOnline() ? "offline" : "lease-unavailable",
              oldNormalized,
            );
            return;
          }
          const base64 = uint8ToBase64Chunked(new Uint8Array(result.bytes));
          this.queueOfflineOperation("write", newNormalized, base64, {
            encoding: "base64",
            contentType: contentTypeForPath(newNormalized),
            intent: { kind: "must-be-absent" },
          });
        } else {
          const view = new TextEncoder().encode(result.text);
          const bytes = view.buffer.slice(
            view.byteOffset,
            view.byteOffset + view.byteLength,
          ) as ArrayBuffer;
          if (bytes.byteLength > BINARY_SYNC_MAX_BYTES) {
            await this.markPendingLargeFile(
              newNormalized,
              bytes,
              "text/markdown",
              !this.ctx.isOnline() ? "offline" : "lease-unavailable",
              oldNormalized,
            );
            return;
          }
          this.queueOfflineOperation("write", newNormalized, result.text, {
            intent: { kind: "must-be-absent" },
          });
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

    // Probe once, then dispatch. Exactly one of content/binaryBytes is set.
    // Above-threshold files use replacement-first direct transfer.
    let content: string | null = null;
    let binaryBytes: ArrayBuffer | null = null;
    try {
      const result = await this.readForSync(newPath);
      if (result.kind === "binary") {
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

    const largeBytes = binaryBytes !== null
      ? binaryBytes
      : (() => {
          const view = new TextEncoder().encode(content as string);
          return view.buffer.slice(
            view.byteOffset,
            view.byteOffset + view.byteLength,
          ) as ArrayBuffer;
        })();
    if (largeBytes.byteLength > BINARY_SYNC_MAX_BYTES) {
      const contentType = binaryBytes !== null
        ? contentTypeForPath(newNormalized)
        : "text/markdown";
      const hash = await this.ctx.computeHashBytes(largeBytes);
      try {
        const result = await this.ctx.uploadLargeEncryptedFile(
          newNormalized,
          largeBytes,
          contentType,
          this.ctx.getExpectedVersionId(newNormalized),
        );
        this.recordDirectWrite(newNormalized, hash, result);
        const delResp = await this.ctx.apiRequest(
          "DELETE",
          this.ctx.vaultPath(`/files/${encodeURIComponent(oldNormalized)}`),
          this.buildDeleteBody(oldNormalized),
        );
        if (!delResp.success && delResp.error?.statusCode !== 404) {
          this.queueOfflineOperation("delete", oldNormalized);
        } else {
          this.ctx.recordRemoteFileAbsent(oldNormalized);
        }
        await this.ctx.clearPendingLargeFile(newNormalized);
        await this.ctx.ensureAtRestEncryptedInPlace(newNormalized, true);
      } catch (error) {
        await this.markPendingLargeFile(
          newNormalized,
          largeBytes,
          contentType,
          /conflict|409/i.test(String(error)) ? "conflict" : "upload-failed",
          oldNormalized,
        );
        this.ctx.logError(
          `Rename sync: direct replacement for "${newNormalized}" is pending; old server path preserved`,
          error,
        );
      }
      return;
    }

    // PUT the new path — byte body for binaries (D-03: contentType + large-body
    // timeout L2), string body for text (byte-identical to pre-BIN-A). Both carry
    // the optimistic version guard (expectedVersionId) via buildWriteBody.
    const baseVersionId = this.ctx.getExpectedVersionId(newNormalized);
    // SD-06-F1 / DECISION 6: the DESTINATION's intent. Obsidian refuses a
    // rename onto an existing local path, so this destination is by definition
    // locally new — an `unknown` store answer is upgraded to `must-be-absent`
    // on that structural fact, while a `present(v)` answer still wins.
    const destIntent = this.resolveRenameDestIntent(newNormalized);
    let hash: string;
    let putResp;
    if (binaryBytes !== null) {
      const encrypted = await this.ctx.encryptContentBytes(binaryBytes);
      hash = await this.ctx.computeHashBytes(binaryBytes);
      const body = this.buildWriteBody(newNormalized, encrypted, hash, {
        expectedVersionId: baseVersionId,
        intent: destIntent,
        lane: "rename-dest",
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
        this.buildWriteBody(newNormalized, encrypted, hash, {
          expectedVersionId: baseVersionId,
          intent: destIntent,
          lane: "rename-dest",
        })
      );
    }
    if (!putResp.success) {
      // Text 409 → interactive conflict resolution (handleRemoteWriteConflict is
      // text-only). Returns BEFORE the DELETE below, so the old server copy
      // survives — verified per-function for 16-03.
      if (putResp.error?.statusCode === 409 && content !== null) {
        await this.handleRemoteWriteConflict(newNormalized, content, baseVersionId);
        return;
      }
      // SD-06-F1 / DECISION 4 — the BINARY destination 409.
      //
      // This used to fall through to the SY3 branch below, which queues a write
      // for the new path AND a DELETE for the old one. Under `mustBeAbsent`
      // that queued write can never succeed, so either it jams the flush queue
      // or — once it drops — the delete destroys the surviving old copy and the
      // server holds NEITHER version. Both outcomes are data loss.
      //
      // Correct handling: hold loudly, queue NOTHING, leave the old server copy
      // exactly where it is. The local file is untouched, so reconciliation
      // surfaces the divergence as a binaryBoth conflict on the next pass.
      if (putResp.error?.statusCode === 409) {
        this.ctx.logError(
          `Rename sync: destination "${newNormalized}" already exists on the server (HTTP 409); old path preserved, nothing queued`,
          new Error(putResp.error?.message ?? "rename destination conflict")
        );
        new Notice(
          `VaultGuard Sync: "${newNormalized}" already exists on the server — the rename is on hold and your local file is kept. Run sync to reconcile.`,
          10000
        );
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
          {
            encoding: "base64",
            contentType: contentTypeForPath(newNormalized),
            intent: { kind: "must-be-absent" },
          }
        );
      } else {
        this.queueOfflineOperation("write", newNormalized, content as string, {
          intent: { kind: "must-be-absent" },
        });
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
    this.assertProtectedContentAllowed();
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
    const protectionGate = this.protectedContentGate();
    if (!protectionGate.ok) {
      this.ctx.log(protectionGate.message);
      this.ctx.showNotice(protectionGate.message, 9000);
      this.ctx.recordSyncDiagnostic("initialReconciliation.skipped", {
        reason: protectionGate.reason,
      });
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
    this.currentInitialReconciliationOperation = operation;

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
    // readForSync content-probe now routes binaries to first-class manifest
    // entries, so this
    // so any legacy/no-readBinary detection path continues to fail safe.
    const binaryLocal = new Set<string>();
    let localFileIndex = 0;
    operation.update({
      phase: "Reading local files",
      processedItems: 0,
      totalItems: localFiles.length,
      percent: 5,
      approximatePercent: true,
    });
    for (const file of localFiles) {
      await operation.token.checkpoint();
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
    const serverFileSizes = new Map<string, number>();
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
      await operation.token.checkpoint();
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
        serverFileSizes.set(delta.path, Math.max(0, delta.size ?? 0));
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
      await operation.token.checkpoint();
      try {
        if (localManifest.has(path)) continue;
        // SY6: a path that's on the server AND unreadable locally is NOT
        // server-only — the local file exists, we just couldn't read it. Skip it
        // so the reconciler never overwrites/empties the on-disk content.
        if (unreadable.has(path)) continue;
        // D-10: legacy safety-net exclusion (see binaryLocal above).
        if (binaryLocal.has(path)) continue;
        // A locally present binary or pending large file is never classified as
        // server-only; preserve the intact local copy during reconciliation.
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
      await operation.token.checkpoint();
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
        await operation.token.checkpoint();
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
    const comparisonFailures = new Set<string>();
    operation.update({
      phase: "Comparing matching files",
      processedItems: 0,
      totalItems: localManifestBoth.length,
      percent: 55,
      approximatePercent: true,
    });
    let compareIndex = 0;
    for (const item of localManifestBoth) {
      await operation.token.checkpoint();
      try {
        const localView = new TextEncoder().encode(item.localContent);
        const remoteHash = localView.byteLength > BINARY_SYNC_MAX_BYTES
          ? (await this.ctx.downloadLargeEncryptedFile(item.path)).plaintextSha256
          : await this.ctx.computeHash(await this.ctx.readRemotePlaintext(item.path));
        if (remoteHash === item.localHash) {
          sameContent.add(item.path);
        } else {
          conflicts.push(item.path);
        }
      } catch (err) {
        this.ctx.logError(`Reconciliation: comparison failed for "${item.path}"`, err);
        comparisonFailures.add(item.path);
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
      await operation.token.checkpoint();
      try {
        if (item.bytes.byteLength > BINARY_SYNC_MAX_BYTES) {
          const direct = await this.ctx.downloadLargeEncryptedFile(item.path);
          if (!isBinaryContentType(direct.contentType)) {
            healBinary.push({ path: item.path, bytes: item.bytes });
            continue;
          }
          if (direct.plaintextSha256 === item.hash) {
            sameContent.add(item.path);
          } else {
            conflicts.push(item.path);
          }
          continue;
        }
        const response = await this.ctx.fetchRemoteFileContent(item.path);
        if (!response.success || !response.data) {
          // OD-2: couldn't read the server side → skip (neither same, conflict,
          // nor heal). Never wipe; both copies stay put, retried next repair.
          this.ctx.logError(
            `Reconciliation: server read failed for binary "${item.path}"`,
            response.error
          );
          comparisonFailures.add(item.path);
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
        const readableResponse = await this.validateRemoteChangeResponse(
          item.path,
          response,
        );
        const remoteBytes = readableResponse.data!.decrypted === true
          ? (this.base64ToBytes(readableResponse.data!.content).buffer as ArrayBuffer)
          : await this.ctx.decryptContentBytes(readableResponse.data!.content);
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
        comparisonFailures.add(item.path);
        continue;
      }
    }

    if (comparisonFailures.size > 0) {
      const message =
        `VaultGuard Sync: Reconciliation could not safely compare ${comparisonFailures.size} ` +
        "server file(s). No plan was applied and the previous sync cursor was kept. " +
        "Retry after refreshing access, or open VaultGuard status for details.";
      const error = new Error(message);
      const syncState = this.ctx.getSyncState();
      syncState.status = "error";
      syncState.lastError = message;
      await this.ctx.saveSettings();
      new Notice(message, 12000);
      this.ctx.logError("Reconciliation comparison incomplete", error);
      this.ctx.recordSyncDiagnostic("initialReconciliation.comparison-failed", {
        failedCount: comparisonFailures.size,
        paths: [...comparisonFailures],
      });
      operation.fail(error);
      return false;
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
    const totalDownloadBytes = serverOnly.reduce(
      (sum, path) => sum + (serverFileSizes.get(path) ?? 0),
      0,
    );
    let processedDownloadBytes = 0;
    const reconciliationItems = serverOnly.map((path) => ({
      path,
      size: serverFileSizes.get(path) ?? 0,
    }));
    const reconciliationPrefetchWindow = this.createRemoteChangePrefetchWindow(
      reconciliationItems,
      (item) =>
        !this.isPathTombstoned(this.ctx.normalizeVaultPath(item.path)) &&
        this.canPrefetchRemoteChange(item),
    );
    operation.update({
      phase: "Downloading server-only files",
      processedItems: 0,
      totalItems: serverOnly.length,
      processedBytes: 0,
      totalBytes: totalDownloadBytes > 0 ? totalDownloadBytes : null,
      percent: 65,
      approximatePercent: true,
      message:
        serverOnly.length > 0
          ? `Preparing item 1 of ${serverOnly.length}.`
          : "No server-only files to download.",
    });
    let downloadIndex = 0;
    for (const [serverOnlyIndex, path] of serverOnly.entries()) {
      await operation.token.checkpoint();
      try {
        const normalized = this.ctx.normalizeVaultPath(path);
        const size = serverFileSizes.get(path) ?? 0;
        operation.update({
          phase: "Downloading server-only files",
          processedItems: downloadIndex,
          totalItems: serverOnly.length,
          processedBytes: processedDownloadBytes,
          totalBytes: totalDownloadBytes > 0 ? totalDownloadBytes : null,
          percent: 65 + (serverOnly.length > 0 ? (downloadIndex / serverOnly.length) * 10 : 10),
          approximatePercent: true,
          message: `Downloading item ${downloadIndex + 1} of ${serverOnly.length}: ${normalized}`,
        });
        const prefetchedResponse = await reconciliationPrefetchWindow.take(serverOnlyIndex);
        if (this.isPathTombstoned(normalized)) {
          if (await this.deleteTombstonedServerPath(normalized)) {
            deletedOnServer += 1;
          }
          continue;
        }
        await this.applyRemoteChangeWithOptionalPrefetch(
          { path: normalized, size },
          prefetchedResponse,
        );
        await operation.token.checkpoint();
        downloaded += 1;
      } catch (err) {
        this.ctx.logError(`Reconciliation: download failed for "${path}"`, err);
        downloadFailed += 1;
      } finally {
        processedDownloadBytes += serverFileSizes.get(path) ?? 0;
        downloadIndex += 1;
        operation.update({
          phase: "Downloading server-only files",
          processedItems: downloadIndex,
          totalItems: serverOnly.length,
          processedBytes: processedDownloadBytes,
          totalBytes: totalDownloadBytes > 0 ? totalDownloadBytes : null,
          percent: 65 + (serverOnly.length > 0 ? (downloadIndex / serverOnly.length) * 10 : 10),
          approximatePercent: true,
          message: `${downloaded} downloaded, ${downloadFailed} failed; ${downloadIndex} of ${serverOnly.length} processed.`,
        });
        if (downloadIndex % DEFAULT_LONG_OPERATION_BATCH_SIZE === 0) {
          await yieldToEventLoop();
        }
      }
    }
    await operation.token.checkpoint();

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
      await operation.token.checkpoint();
      try {
        const entry = localManifest.get(path);
        if (!entry) continue;
        const normalized = this.ctx.normalizeVaultPath(path);
        // BIN-A / D-05 + D-11: a local-only in-size binary uploads via the BYTE
        // path and counts as an upload, exactly like a text file.
        // SD-06-F1 / DECISION 7 — CREATE. Absence is PROVEN, not guessed: this
        // path reached `localOnly` because `!serverPaths.has(path)` against a
        // fresh full server inventory built earlier in this same pass.
        const outcome =
          entry.kind === "binary"
            ? await this.uploadReconciledBinaryFile(normalized, entry.bytes, {
                intent: { kind: "must-be-absent" },
              })
            : await this.ctx.uploadReconciledFile(normalized, entry.content, {
                intent: { kind: "must-be-absent" },
              });
        if (outcome === "uploaded") uploaded += 1;
        // "skipped-create-conflict" is counted as SKIPPED, deliberately and
        // explicitly: another device won the create race. It must never reach a
        // delete branch and must never be counted as a failure.
        else if (outcome === "skipped-create-conflict") uploadSkipped += 1;
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
    await operation.token.checkpoint();

    // BIN-A / L7: heal pre-BIN-A lossy server artifacts by uploading the local
    // bytes. Runs only after the user confirmed the plan (above), so a cancelled
    // binding heals nothing. Counted in the UPLOAD bucket (D-11). This loop only
    // ever UPLOADS — downloading the artifact over local content is structurally
    // impossible here (T-11-16). A "skipped-*" outcome leaves both copies as-is,
    // never a deletion (SY2 extended).
    for (const heal of healBinary) {
      await operation.token.checkpoint();
      try {
        // SD-06-F1 / DECISION 7 — FORCE. This is the L7 heal of a pre-BIN-A
        // LOSSY server artifact: the server copy is known-corrupt and the local
        // bytes are the only faithful copy. The user confirmed the plan before
        // this loop runs, which is what sanctions an unconditional overwrite.
        const outcome = await this.uploadReconciledBinaryFile(
          this.ctx.normalizeVaultPath(heal.path),
          heal.bytes,
          { intent: { kind: "force" } }
        );
        if (outcome === "uploaded") uploaded += 1;
        // A force lane cannot produce "skipped-create-conflict" (the server
        // never 409s a declared force), but the skipped bucket is the correct
        // sink if it ever did.
        else uploadSkipped += 1;
      } catch (err) {
        this.ctx.logError(`Reconciliation: heal upload failed for "${heal.path}"`, err);
        uploadFailed += 1;
      }
    }

    let conflictsResolved = 0;
    let conflictFailed = 0;
    // KEEP_REMOTE and DUPLICATE both pull the authoritative server copy after
    // the user confirms the plan. Bound those GETs exactly like server-only
    // reconciliation: network reads overlap, while conflict writes/applies stay
    // ordered and serial. KEEP_LOCAL is upload-only and schedules no GET.
    const conflictPrefetchWindow =
      decision.conflictStrategy === ConflictResolutionStrategy.KEEP_LOCAL
        ? null
        : this.createRemoteChangePrefetchWindow(
            conflicts.map((path) => ({ path, size: serverFileSizes.get(path) ?? 0 })),
            (item) => this.canPrefetchRemoteChange(item),
          );
    operation.update({
      phase: "Resolving conflicts",
      processedItems: 0,
      totalItems: conflicts.length,
      percent: 85,
      approximatePercent: true,
    });
    let conflictIndex = 0;
    for (const [conflictListIndex, path] of conflicts.entries()) {
      await operation.token.checkpoint();
      try {
        const prefetchedResponse = conflictPrefetchWindow
          ? await conflictPrefetchWindow.take(conflictListIndex)
          : undefined;
        if (prefetchedResponse === undefined) {
          await this.ctx.resolveReconciliationConflict(
            path,
            decision.conflictStrategy,
            localManifest,
          );
        } else {
          await this.ctx.resolveReconciliationConflict(
            path,
            decision.conflictStrategy,
            localManifest,
            prefetchedResponse,
          );
        }
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
      await operation.token.checkpoint();
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
      await operation.token.checkpoint();
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
      uploadSkipped === 0 &&
      downloadFailed === 0 &&
      conflictFailed === 0 &&
      foldersFailed === 0;

    const settings = this.ctx.getSettings();
    const syncState = this.ctx.getSyncState();
    if (fullySucceeded) {
      settings.bindingReconciledVaultId = settings.serverVaultId;
      syncState.lastSync = inventory.data.syncTimestamp;
      settings.lastSyncTimestamp = inventory.data.syncTimestamp;
    }
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
      this.ctx.log(`Reconciliation complete: ${summary}`);
      operation.complete(`Reconciliation complete — ${summary}`);
      return true;
    }

    const incompleteMessage =
      `VaultGuard Sync: Reconciliation incomplete — ${summary} ` +
      "The previous sync cursor was kept so failed items remain eligible. Open the sidebar to retry.";
    const incompleteError = new Error(incompleteMessage);
    syncState.status = "error";
    syncState.lastError = incompleteMessage;
    new Notice(incompleteMessage, 12000);
    this.ctx.logError("Reconciliation incomplete", incompleteError);
    this.ctx.recordSyncDiagnostic("initialReconciliation.incomplete", {
      downloadFailed,
      uploadFailed,
      conflictFailed,
      foldersFailed,
    });
    operation.fail(incompleteError);
    return false;
    } catch (error) {
      operation.fail(error);
      throw error;
    } finally {
      if (this.currentInitialReconciliationOperation === operation) {
        this.currentInitialReconciliationOperation = null;
      }
    }
  }

  /**
   * SD-06-F1 / DECISION 7 — `options.intent` is REQUIRED BY TYPE.
   *
   * This uploader serves three mutually exclusive intents (reconciliation
   * create, catch-up create, conflict KEEP_LOCAL / lossy-artifact heal) and
   * could not tell them apart. Its create-callers hold PROVEN absence from a
   * fresh full inventory; that proof was being discarded. The parameter is how
   * the proof reaches the wire — the store cannot supply it, because inventory
   * knowledge is deliberately never mass-recorded (P6).
   *
   * At runtime the intent falls back to `{kind:"unknown"}` (= today's exact
   * body plus a breadcrumb), because `tests/` is not typechecked and a missed
   * call site must degrade rather than throw.
   *
   * P8 resolved: both lanes now derive from THIS intent. The JSON lane's
   * hard-coded `expectedVersionId: null` and the large lane's independent
   * `getExpectedVersionId(path)` lookup are both gone.
   */
  async uploadReconciledFile(
    path: string,
    content: string,
    options: { intent: MutationIntent; noWriteNotice?: string }
  ): Promise<UploadReconciledOutcome> {
    this.assertProtectedContentAllowed();
    const intent: MutationIntent = options?.intent ?? { kind: "unknown" };
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
        options?.noWriteNotice ??
          `VaultGuard Sync: Skipped upload of "${path}" — you do not have write permission. The file stays in this folder but is not synced.`
      );
      return "skipped-no-permission";
    }
    const textView = new TextEncoder().encode(content);
    const textBytes = textView.buffer.slice(
      textView.byteOffset,
      textView.byteOffset + textView.byteLength,
    ) as ArrayBuffer;
    if (textBytes.byteLength > BINARY_SYNC_MAX_BYTES) {
      const hash = await this.ctx.computeHashBytes(textBytes);
      try {
        const result = await this.ctx.uploadLargeEncryptedFile(
          path,
          textBytes,
          "text/markdown",
          // C18: uploadLargeEncryptedFile's signature is UNCHANGED — it takes a
          // plain `string | undefined`. The direct/large lane is already
          // absence-safe server-side (it PUTs with its own S3 request
          // condition), so it needs no mustBeAbsent equivalent; it only needs
          // the version when one was declared.
          intent.kind === "expect-version" ? intent.versionId : undefined,
        );
        this.recordDirectWrite(path, hash, result);
        await this.ctx.clearPendingLargeFile(path);
        await this.ctx.emitAuditEvent("file.write", path, {
          reconciliation: true,
          directTransfer: true,
          bytes: textBytes.byteLength,
        });
        return "uploaded";
      } catch (error) {
        await this.markPendingLargeFile(
          path,
          textBytes,
          "text/markdown",
          /conflict|409/i.test(String(error)) ? "conflict" : "upload-failed",
        );
        throw error;
      }
    }
    const encrypted = await this.ctx.encryptContent(content);
    const hash = await this.ctx.computeHash(content);
    const response = await this.ctx.apiRequest<RemoteFileWriteResponse>(
      "PUT",
      this.ctx.vaultPath(`/files/${encodeURIComponent(path)}`),
      this.buildWriteBody(path, encrypted, hash, { intent, lane: "reconciled-text" })
    );
    if (!response.success) {
      if (response.error?.statusCode === 409 && intent.kind === "must-be-absent") {
        return this.reportLostCreateRace(path, response.error?.message);
      }
      throw new Error(response.error?.message ?? `Upload of "${path}" failed.`);
    }
    this.recordSuccessfulWrite(path, hash, response);
    await this.ctx.emitAuditEvent("file.write", path, { reconciliation: true });
    return "uploaded";
  }

  /**
   * SD-06-F1 — the shared tail for a reconciliation/catch-up upload that
   * DECLARED a create and lost the race.
   *
   * Deliberately NOT a throw. Both uploaders run inside loops whose catch
   * blocks count a FAILURE, and a failure is the wrong classification: nothing
   * is broken, another device simply got there first. Returning a skip outcome
   * keeps the loop running, leaves the local file exactly where it is, and
   * lands in the skipped bucket that SY2's "never delete on a skip" rule
   * already governs. The divergence is resolved on the next reconciliation
   * pass, which classifies it as a conflict and asks the user.
   */
  private reportLostCreateRace(
    path: string,
    message?: string
  ): "skipped-create-conflict" {
    this.ctx.log(
      `Reconciliation: "${path}" was created on another device first (HTTP 409) — local copy kept, conflict resolution deferred to the next pass.${
        message ? ` Server said: ${message}` : ""
      }`
    );
    this.ctx.recordSyncDiagnostic("upload.create-conflict", { path });
    return "skipped-create-conflict";
  }

  /**
   * Byte sibling of uploadReconciledFile. JSON-size content uses the encrypted
   * vault-scoped `/files` path; larger content uses direct transfer. It mirrors
   * the string sibling's outcome discipline with a `pending-large` outcome so
   * failed direct transfers preserve the local file and retry metadata.
   * Private: only the catch-up and rename push sites call it, and its extended
   * outcome (UploadReconciledBinaryOutcome) never needs to thread through the
   * narrow ctx uploadReconciledFile declaration.
   */
  private async uploadReconciledBinaryFile(
    path: string,
    bytes: ArrayBuffer,
    // SD-06-F1 / DECISION 7: required by type, `{kind:"unknown"}` at runtime —
    // same contract as the string sibling.
    options: { intent: MutationIntent; noWriteNotice?: string }
  ): Promise<UploadReconciledBinaryOutcome> {
    this.assertProtectedContentAllowed();
    const intent: MutationIntent = options?.intent ?? { kind: "unknown" };
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
        options?.noWriteNotice ??
          `VaultGuard Sync: Skipped upload of "${path}" — you do not have write permission. The file stays in this folder but is not synced.`
      );
      return "skipped-no-permission";
    }

    if (bytes.byteLength > BINARY_SYNC_MAX_BYTES) {
      const hash = await this.ctx.computeHashBytes(bytes);
      try {
        const result = await this.ctx.uploadLargeEncryptedFile(
          path,
          bytes,
          contentTypeForPath(path),
          // C18, same rule as the string sibling: unchanged signature, and the
          // large lane is already absence-safe server-side.
          intent.kind === "expect-version" ? intent.versionId : undefined,
        );
        this.recordDirectWrite(path, hash, result);
        await this.ctx.clearPendingLargeFile(path);
        await this.ctx.emitAuditEvent("file.write", path, {
          reconciliation: true,
          directTransfer: true,
          bytes: bytes.byteLength,
        });
        this.ctx.recordSyncDiagnostic("upload.binary-direct", {
          path,
          bytes: bytes.byteLength,
        });
        return "uploaded";
      } catch (error) {
        await this.markPendingLargeFile(
          path,
          bytes,
          contentTypeForPath(path),
          /conflict|409/i.test(String(error)) ? "conflict" : "upload-failed",
        );
        new Notice(
          `VaultGuard Sync: Large encrypted upload for "${path}" is pending; the local file was preserved.`,
          8000,
        );
        return "pending-large";
      }
    }

    const encrypted = await this.ctx.encryptContentBytes(bytes);
    // SD-06-F1 / P7: this used to be a hand-built body that could carry NO
    // guard of any kind — one of the two bypass sites. It now goes through
    // buildWriteBody like every other lane, so the declared intent reaches the
    // wire here too.
    const byteHash = await this.ctx.computeHashBytes(bytes);
    const body = this.buildWriteBody(path, encrypted, byteHash, {
      intent,
      lane: "reconciled-binary",
    });
    body.contentType = contentTypeForPath(path);
    const response = await this.ctx.apiRequest(
      "PUT",
      this.ctx.vaultPath(`/files/${encodeURIComponent(path)}`),
      body,
      undefined,
      { timeoutMs: BINARY_PUT_TIMEOUT_MS }
    );
    if (!response.success) {
      if (response.error?.statusCode === 409 && intent.kind === "must-be-absent") {
        return this.reportLostCreateRace(path, response.error?.message);
      }
      throw new Error(response.error?.message ?? `Upload of "${path}" failed.`);
    }
    await this.ctx.emitAuditEvent("file.write", path, { reconciliation: true });
    // Complete the binary breadcrumb family with the JSON-path push success
    // event. Dev-only —
    // recordSyncDiagnostic is a NODE_ENV-gated ring buffer, DCE-stripped from
    // production builds. Path + byte count only (metadata, no content).
    this.ctx.recordSyncDiagnostic("upload.binary-push", {
      path,
      bytes: bytes.byteLength,
    });
    return "uploaded";
  }

  private async retryPendingLargeFiles(userInitiated: boolean): Promise<number> {
    const pending = Object.values(this.ctx.getSettings().pendingLargeFiles ?? {})
      .filter((record) => record.state !== "blocked")
      .sort((a, b) => a.updatedAt.localeCompare(b.updatedAt))
      .slice(0, 5);
    let uploaded = 0;
    for (const record of pending) {
      const ageMs = Date.now() - Date.parse(record.updatedAt);
      const backoffMs = Math.min(5 * 60_000, 1_000 * 2 ** Math.min(record.attempts, 8));
      if (!userInitiated && Number.isFinite(ageMs) && ageMs < backoffMs) continue;
      try {
        const item = this.ctx.app.vault.getAbstractFileByPath(record.path);
        if (!(item instanceof TFile)) {
          await this.ctx.clearPendingLargeFile(record.path);
          continue;
        }
        const local = await this.readForSync(record.path);
        let bytes: ArrayBuffer;
        let contentType: string;
        if (local.kind === "binary") {
          bytes = local.bytes;
          contentType = contentTypeForPath(record.path);
        } else {
          const view = new TextEncoder().encode(local.text);
          bytes = view.buffer.slice(
            view.byteOffset,
            view.byteOffset + view.byteLength,
          ) as ArrayBuffer;
          contentType = "text/markdown";
        }
        if (bytes.byteLength <= BINARY_SYNC_MAX_BYTES) {
          await this.ctx.clearPendingLargeFile(record.path);
          continue;
        }
        await this.ctx.upsertPendingLargeFile({
          ...record,
          size: bytes.byteLength,
          sha256: await this.ctx.computeHashBytes(bytes),
          contentType,
          state: "uploading",
          attempts: record.attempts + 1,
          updatedAt: new Date().toISOString(),
        });
        const hash = await this.ctx.computeHashBytes(bytes);
        const result = await this.ctx.uploadLargeEncryptedFile(
          record.path,
          bytes,
          contentType,
          this.ctx.getExpectedVersionId(record.path),
        );
        this.recordDirectWrite(record.path, hash, result);
        if (record.previousPath) {
          const delResp = await this.ctx.apiRequest(
            "DELETE",
            this.ctx.vaultPath(`/files/${encodeURIComponent(record.previousPath)}`),
            this.buildDeleteBody(record.previousPath),
          );
          if (!delResp.success && delResp.error?.statusCode !== 404) {
            this.queueOfflineOperation("delete", record.previousPath);
          } else {
            this.ctx.recordRemoteFileAbsent(record.previousPath);
          }
        }
        await this.ctx.ensureAtRestEncryptedInPlace(record.path, true);
        await this.ctx.clearPendingLargeFile(record.path);
        uploaded += 1;
      } catch (error) {
        await this.ctx.upsertPendingLargeFile({
          ...record,
          reason: /conflict|409/i.test(String(error)) ? "conflict" : "upload-failed",
          state: /conflict|409/i.test(String(error)) ? "blocked" : "retryable",
          attempts: record.attempts + 1,
          updatedAt: new Date().toISOString(),
        });
        this.ctx.logError(
          `Sync: pending large-file retry failed for "${record.path}"`,
          error,
        );
      }
      await yieldToEventLoop();
    }
    return uploaded;
  }

  /**
   * Walks the local vault and uploads everything the server inventory does not
   * already list.
   *
   * SD-06-F4 invariant: this loop may NEVER remove a local file. Every file it
   * touches is one the server has never received, so the local copy is the only
   * copy. A file that cannot be uploaded is HELD (counted in
   * `heldNoPermissionFiles`, logged, and surfaced in the sync summary), never
   * deleted. Trash/quarantine after an explicit user decision is a separate,
   * later concern.
   */
  async uploadLocalOnlyFiles(): Promise<{
    uploadedFiles: number;
    uploadedFolders: number;
    heldNoPermissionFiles: number;
    skippedFiles: number;
    failedFiles: number;
    failedFolders: number;
  } | null> {
    this.assertProtectedContentAllowed();
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
    let heldNoPermission = 0;
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
          // Binaries ride the byte path. JSON-size files use the original API;
          // larger files use direct transfer and remain pending on failure.
          // Legacy adapters never reach here; readForSync returns text for them.
          // SD-06-F1 / DECISION 7 — CREATE. Proven absence: this file is only
          // reached because `!serverFilePaths.has(lookupKey)` against the full
          // inventory fetched at the top of this catch-up.
          const outcome = await this.uploadReconciledBinaryFile(normalized, result.bytes, {
            intent: { kind: "must-be-absent" },
            noWriteNotice: this.heldNoPermissionNotice(normalized),
          });
          if (outcome === "uploaded") {
            uploaded += 1;
            // Post-upload at-rest hygiene runs only after remote durability.
            if (result.bytes.byteLength > BINARY_SYNC_MAX_BYTES) {
              void this.ctx.ensureAtRestEncryptedInPlace(normalized, true);
            } else {
              void this.ctx.ensureAtRestEncryptedInPlace(normalized);
            }
          } else if (outcome === "pending-large") {
            // The direct-transfer Notice already fired inside the byte sibling.
            // Do not double-notify or LAK-encrypt before remote durability.
            skipped += 1;
            this.ctx.recordSyncDiagnostic("catchup.binary-pending-large", {
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
          } else if (outcome === "skipped-create-conflict") {
            // SD-06-F1: another device created this path between the inventory
            // fetch and the PUT. Per-file and NOT transient-for-everyone, so the
            // loop CONTINUES (unlike skipped-no-lease). The bytes stay on disk
            // and reconciliation classifies the divergence next pass.
            skipped += 1;
          } else {
            // skipped-no-permission: IDENTICAL hold rule to the text path
            // (SD-06-F4). The bytes stay on disk — for a VG1 at-rest file this
            // is the sole ciphertext copy.
            skipped += 1;
            heldNoPermission += 1;
            this.logHeldNoPermission(normalized);
          }
          continue;
        }
        const content = result.text;
        // SD-06-F1 / DECISION 7 — CREATE, same proof as the binary branch
        // above (`!serverFilePaths.has(lookupKey)` on the fresh inventory).
        const outcome = await this.ctx.uploadReconciledFile(normalized, content, {
          intent: { kind: "must-be-absent" },
          noWriteNotice: this.heldNoPermissionNotice(normalized),
        });
        if (outcome === "uploaded") {
          uploaded += 1;
          // A local-only text file usually means it was added OUTSIDE
          // Obsidian (Finder drop while the app was closed, git checkout),
          // so its on-disk form is still plaintext. Now that the server has
          // the content, flip the local copy to at-rest ciphertext.
          // Fire-and-forget: hygiene must never fail the catch-up loop.
          if (new TextEncoder().encode(content).byteLength > BINARY_SYNC_MAX_BYTES) {
            void this.ctx.ensureAtRestEncryptedInPlace(normalized, true);
          } else {
            void this.ctx.ensureAtRestEncryptedInPlace(normalized);
          }
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
        } else if (outcome === "skipped-create-conflict") {
          // SD-06-F1: lost the create race. Per-file, not transient-for-all —
          // continue the loop, keep the local copy, defer to reconciliation.
          // Explicitly branched so it can never be mislabelled as the
          // no-permission hold below (which logs a permission diagnostic).
          skipped += 1;
        } else {
          // outcome === "skipped-no-permission": the user genuinely lacks write
          // permission, so the file cannot be ADDED to this vault. That says
          // nothing about whether the user wants to KEEP it, and this file has
          // never reached the server, so the local copy is the only copy
          // (SD-06-F4). Hold it — unconditionally, on any permission-store
          // state.
          skipped += 1;
          heldNoPermission += 1;
          this.logHeldNoPermission(normalized);
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
          message: `${uploaded} uploaded, ${heldNoPermission} kept (no write permission), ${skipped} skipped, ${failed} failed.`,
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
      uploaded + heldNoPermission + skipped + failed + foldersUploaded + foldersFailed;
    if (totalChanges > 0) {
      const parts: string[] = [];
      if (uploaded > 0) parts.push(`${uploaded} files uploaded`);
      if (heldNoPermission > 0) {
        parts.push(`${heldNoPermission} kept (no write permission)`);
      }
      if (foldersUploaded > 0) parts.push(`${foldersUploaded} folders preserved`);
      if (skipped > 0) parts.push(`${skipped} skipped (no write permission)`);
      if (failed > 0) parts.push(`${failed} files failed`);
      if (foldersFailed > 0) parts.push(`${foldersFailed} folders failed`);
      this.ctx.log(`VaultGuard Sync: Caught up local-only items — ${parts.join(", ")}.`);
    }

    return {
      uploadedFiles: uploaded,
      uploadedFolders: foldersUploaded,
      heldNoPermissionFiles: heldNoPermission,
      skippedFiles: skipped,
      failedFiles: failed,
      failedFolders: foldersFailed,
    };
  }

  /**
   * SD-06-F4: the user-facing Notice for a catch-up file that could not be
   * uploaded for want of write permission. It must state that the file was KEPT
   * and must not claim the server lacks the path — `POST /files/sync` is
   * read-permission filtered server-side, so absence from the inventory is not
   * evidence of absence from the vault.
   */
  private heldNoPermissionNotice(path: string): string {
    return (
      `VaultGuard Sync: Kept local-only "${path}" on this device — you do not have ` +
      "write permission to sync it to this vault. Nothing was deleted; the file " +
      "stays in your folder but will not be uploaded."
    );
  }

  /**
   * SD-06-F4: log + diagnostic for a held catch-up file. The permission-store
   * state is recorded as a diagnostic FIELD only; it is never a gate, because
   * "the store finished warming" was never evidence that the local content is
   * redundant.
   */
  private logHeldNoPermission(path: string): void {
    this.ctx.log(
      `Catch-up: kept local-only "${path}" on this device — no write permission to sync it, ` +
        "so nothing was uploaded and nothing was deleted. The server inventory is " +
        "read-permission filtered, so its absence from that inventory is not proof the " +
        "server vault lacks this path."
    );
    this.ctx.recordSyncDiagnostic("catchup.held-no-permission", {
      path,
      permissionStore: this.ctx.getPermissionStoreState().kind,
    });
  }

  async repairMissingRemoteItems(): Promise<{
    downloadedFiles: number;
    downloadedFolders: number;
    failedFiles: number;
    failedFolders: number;
  } | null> {
    this.assertProtectedContentAllowed();
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
    this.assertProtectedContentAllowed();
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
        // SD-06-F1 / DECISION 8 + P7: the second bypass site. This body is
        // hand-built (it is a zero-byte sentinel, not vault content) and could
        // carry no guard at all. A marker upload is ALWAYS a create — the
        // caller only reaches here for a folder the server inventory does not
        // have — so the intent is unconditional, and stating it here is why
        // this body does not need buildWriteBody's resolution machinery.
        mustBeAbsent: true,
      }
    );
    if (!response.success) {
      // DECISION 8 — ENSURE-EXISTS semantics. A 409 means the marker is already
      // there, which IS the goal state ("this folder is represented on the
      // server"). The marker is a zero-byte sentinel with identical content on
      // every device: there is nothing to lose, nothing to merge and nothing a
      // user could choose between, so this is success, not a conflict.
      if (response.error?.statusCode === 409) {
        // ORCHESTRATOR AMENDMENT 2 — kept with an HONEST rationale. This does
        // NOT change the marker flow: the body above is unconditionally
        // `mustBeAbsent`, so the next marker attempt declares a create again
        // and treats its 409 as success again. What the record IS for is OTHER
        // write paths that may target this exact path — `deleteFolderMarker`'s
        // queued retry and the offline flush both resolve intent from the
        // store, and leaving the store ignorant of a marker we have just proven
        // exists would send them down the unknown lane.
        this.ctx.recordRemoteFilePresent(markerPath, {});
        this.ctx.log(
          `Folder marker for "${normalized}" already exists on the server (HTTP 409) — goal state reached.`
        );
        return true;
      }
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
    this.assertProtectedContentAllowed();
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
    localManifest: Map<string, LocalManifestEntry>,
    prefetchedResponse?: ApiResponse<RemoteFileContentResponse>,
  ): Promise<void> {
    const normalizedPath = this.ctx.normalizeVaultPath(path);
    const entry = localManifest.get(path);

    switch (strategy) {
      case ConflictResolutionStrategy.KEEP_LOCAL: {
        if (!entry) throw new Error(`Local conflict source "${normalizedPath}" is unavailable.`);
        // SD-06-F1 / DECISION 7 — FORCE, both branches. The USER chose
        // KEEP_LOCAL for this reconciliation conflict, which is the sanctioned
        // "force only after a conflict choice" lane. Declaring it explicitly is
        // what makes a deliberate overwrite distinguishable from a lost-track
        // one on the wire.
        //
        // The outcome is intentionally not inspected here (unchanged): every
        // outcome of this uploader leaves the local file intact, and a force
        // lane cannot produce "skipped-create-conflict".
        if (entry.kind === "binary") {
          // BIN-A / L4: KEEP_LOCAL byte-uploads the local bytes (never the
          // string uploader — that would lossily UTF-8-encode them). The byte
          // uploader's outcome union is respected; no skip leads to a deletion.
          const outcome = await this.uploadReconciledBinaryFile(normalizedPath, entry.bytes, {
            intent: { kind: "force" },
          });
          if (outcome !== "uploaded") {
            throw new Error(`Conflict upload for "${normalizedPath}" was not completed (${outcome}).`);
          }
        } else {
          const outcome = await this.ctx.uploadReconciledFile(normalizedPath, entry.content, {
            intent: { kind: "force" },
          });
          if (outcome !== "uploaded") {
            throw new Error(`Conflict upload for "${normalizedPath}" was not completed (${outcome}).`);
          }
        }
        return;
      }
      case ConflictResolutionStrategy.KEEP_REMOTE: {
        // BIN-A / L4: applyRemoteChange forks byte-vs-string internally on the
        // GET-response contentType (D-06 chokepoint), so this ONE call pulls a
        // binary remote through the byte writer and a text remote through the
        // string writer — no branch needed here.
        await this.applyRemoteChangeWithOptionalPrefetch(
          { path: normalizedPath, size: 0 },
          prefetchedResponse,
        );
        return;
      }
      case ConflictResolutionStrategy.DUPLICATE:
      default: {
        const response =
          prefetchedResponse ??
          await this.ctx.fetchRemoteFileContent(
            normalizedPath,
            REMOTE_APPLY_PREFETCH_REQUEST_OPTIONS,
          );
        // A retry must not create another conflict-suffix file when the remote
        // payload is still unreadable. Validate first, then commit the ordered
        // duplicate + original overwrite using this exact response (one GET).
        const readableResponse = await this.validateRemoteChangeResponse(
          normalizedPath,
          response,
        );
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
        await this.applyRemoteChangeWithOptionalPrefetch(
          { path: normalizedPath, size: 0 },
          readableResponse,
        );
        return;
      }
    }
  }

  /**
   * SD-06-F1 / DECISION 2 + DECISION 3 — `options.createConflict`.
   *
   * Set it ONLY when the 409 answered a write that DECLARED `mustBeAbsent`.
   * It changes two things and nothing else:
   *
   *  1. identical remote content auto-converges (returns `"converged"`, records
   *     no conflict entry, shows no Notice, emits no `sync.conflict` event);
   *  2. the ASK_USER copy names a concurrent CREATE instead of a modification.
   *
   * The gate exists because the conflict entry is pushed BEFORE any hash
   * comparison, so an ungated short-circuit would silently retire today's
   * update-409 behavior (a conflict IS recorded even when the hashes match).
   */
  async handleRemoteWriteConflict(
    path: string,
    localContent: string,
    baseVersionId?: string | null,
    options: { createConflict?: boolean } = {}
  ): Promise<RemoteWriteConflictResolutionResult> {
    this.assertProtectedContentAllowed();
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

    // A 404/410 is authoritative absence ONLY when it came back through the
    // plain `/files` route. `fetchRemoteFileContent` routes every lease-less or
    // carve-out-denied read to `/files-decrypted`, and that endpoint answers a
    // permission deny with 404 BY DESIGN (D-02) so a caller cannot probe for
    // existence — its own comment says "indistinguishable from permission deny".
    // Trusting that 404 as proof of deletion is the never-wipe-on-ambiguity
    // violation: under KEEP_REMOTE it hard-deleted local content that the server
    // still holds and the user has merely lost READ access to (a deny rule can
    // scope `read` alone, and the write gate is evaluated independently — so the
    // PUT still 409s into this handler).
    //
    // The predicate is copied VERBATIM from fetchRemoteFileContent's route
    // selector so the two cannot drift, the same discipline the SD-06-F1
    // absence-recording predicate applies to its own copy. `applyRemoteChange`
    // already carries this guard; this sibling call site was missing it.
    const absenceIsAmbiguous =
      remoteDeleted &&
      (!this.hasValidKeyLease() || this.ctx.isPathDeniedByKeyLease(normalizedPath));

    if (remoteDeleted) {
      // Only a plain-route 404 is positive evidence of absence. Recording an
      // ambiguous one poisons the manifest with a permission artifact and makes
      // the user's next save declare `mustBeAbsent` against a file that exists —
      // the T-16-11 trap the SD-06-F1 predicate already excludes 401/403 for.
      //
      // Deliberately NOT symmetric with applyRemoteDeletion's own internal
      // record: once a strategy HAS removed the file locally, recording it
      // absent is consistent with local state. This site fires for every
      // strategy including the ones that keep the file — ASK_USER (the default)
      // and KEEP_LOCAL — where the record would be pure poisoning.
      if (!absenceIsAmbiguous) {
        this.ctx.recordRemoteFileAbsent(normalizedPath);
      }
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

    // SD-06-F1 / DECISION 2 — identical-content convergence, create lane ONLY.
    // Two devices created the same bytes (an empty note, the same template, the
    // same daily-note stub). There is no divergence to resolve and nothing a
    // user could choose between, so this must NOT become a conflict entry, a
    // Notice or a `sync.conflict` audit event — that is the empty-note /
    // template-storm false-positive class. Placed BEFORE the conflict object is
    // constructed and pushed, because that push is unconditional today.
    //
    // The store is left holding the FETCHED version, so the next divergent
    // write on this path is guarded by `expectedVersionId` rather than
    // re-declaring a create — which is what keeps T-16-23 (a real conflict
    // hiding behind a coincidental match) out of reach: after convergence the
    // path is `present`, not `absent`.
    //
    // DEVIATION from DECISION 2's letter, recorded deliberately: the plan asked
    // for an explicit `recordRemoteFilePresent(path, {versionId, baseHash})`
    // here. It would be a redundant duplicate — convergence is only reachable
    // when `!remoteDeleted`, and that branch has ALREADY run
    // `recordRemoteReadState` with the same fetched versionId and hash plus the
    // checksum/lastModified/size this call could not supply. Adding a second,
    // strictly poorer write would imply the first one does not happen. The
    // guarantee is asserted directly instead (C9 checks the post-converge
    // resolution is `expect-version` on the FETCHED version).
    if (options.createConflict && !remoteDeleted && remoteHash === localHash) {
      this.ctx.log(
        `Sync: concurrent create of "${normalizedPath}" produced identical content — converged, no conflict raised.`
      );
      return "converged";
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
          // `inferred` already means exactly "we cannot be certain the remote is
          // really gone", which routes the delete through trash-or-refuse
          // instead of a hard delete. An authoritative plain-route 404 still
          // takes the hard-delete branch, so genuine remote deletions converge
          // unchanged.
          await this.ctx.applyRemoteDeletion(normalizedPath, absenceIsAmbiguous);
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
          // Same ambiguity gate as KEEP_REMOTE above. This lane already wrote a
          // conflict copy, so the local bytes survive either way — passing the
          // flag keeps the two branches honest rather than relying on that.
          await this.ctx.applyRemoteDeletion(normalizedPath, absenceIsAmbiguous);
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
        // SD-06-F1 / DECISION 3: same workflow, create-flavored copy. Telling a
        // user their brand-new note "has a sync conflict" when nothing was ever
        // modified is unactionable; naming the concurrent create is. Both
        // copies are HELD — the local bytes are already on disk (DECISION 1)
        // and the remote copy is untouched.
        syncState.lastError = options.createConflict
          ? `Concurrent create detected for "${normalizedPath}".`
          : `Sync conflict detected for "${normalizedPath}".`;
        new Notice(
          options.createConflict
            ? `VaultGuard Sync: "${normalizedPath}" was created on another device at the same time. Both versions are kept; use View Permissions to resolve.`
            : `VaultGuard Sync: Sync conflict detected for "${normalizedPath}". Use View Permissions to resolve.`
        );
        return "pending";
    }
  }

  async handleConflict(conflict: SyncConflict): Promise<void> {
    this.assertProtectedContentAllowed();
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
   * The "these files belong here" proof the local-only catch-up never had.
   *
   * `bindingReconciledVaultId` is stamped only by a COMPLETED initial
   * reconciliation — the single upload path that ASKS first
   * (`askReconciliationPlan`). `applyVaultBinding` (main.ts:5502 / :5516)
   * deletes that stamp and re-arms `localOnlyCatchupCompleted = false` on the
   * same binding change, so an unstamped binding means precisely: this folder
   * was just pointed at a different vault (or has never been reconciled with
   * one), and the files sitting on disk have no claim on it yet.
   *
   * Reads settings FRESH on every call — never a field, never a constructor
   * capture. quick-260820-mv4's post-mortem: long-lived surfaces that captured
   * state by value across a rebind kept answering for the OLD vault.
   *
   * See reports/HANDOFF-2026-08-20-silent-local-only-upload.md §7 (Option 1).
   */
  private isBindingReconciled(): boolean {
    const settings = this.ctx.getSettings();
    const vaultId = settings.serverVaultId;
    return !!vaultId && settings.bindingReconciledVaultId === vaultId;
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
   * revoked/offboarded user or the configured maxSessionDurationHours cap still drives
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
    this.assertProtectedContentAllowed();
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
    this.assertProtectedContentAllowed();
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
      // SD-06-F1 / DECISION 9: an explicit override. Left unset by all 25
      // upstream call sites — the central default below covers them, which is
      // the entire point of capturing here rather than at each caller.
      intent?: MutationIntent;
    } = {}
  ): void {
    const normalizedPath = this.ctx.normalizeVaultPath(path);
    // Deduplicate: remove existing operations for the same path
    this.ctx.setOfflineQueue(
      this.ctx.getOfflineQueue().filter((op) => op.path !== normalizedPath)
    );

    const remoteState = this.ctx.getRemoteFileState(normalizedPath);
    const entry: OfflineQueueOperation = {
      operation,
      path: normalizedPath,
      data,
      baseVersionId:
        options.baseVersionId ?? this.ctx.getExpectedVersionId(normalizedPath),
      baseHash: options.baseHash ?? remoteState?.baseHash,
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
    // SD-06-F1 / DECISION 9 — intent capture, at the ONE central enqueue site.
    // Every queueing path in both runtimes funnels through here (verified: 11
    // call sites in this file, 14 in at-rest-adapter-runtime.ts, no bypass), so
    // a create queued offline stays a create across a restart without touching
    // a single caller.
    //
    // Deliberately NO local-new probe here: the enqueue site has no reliable
    // pre-write signal, and store resolution is the conservative answer.
    // An `unknown` resolution is NOT stored — see the type's comment.
    const capturedIntent = options.intent ?? this.resolveIntentSafely(normalizedPath);
    if (capturedIntent !== undefined && capturedIntent.kind !== "unknown") {
      entry.intent = capturedIntent;
    }

    this.ctx.setOfflineQueue([...this.ctx.getOfflineQueue(), entry]);

    this.ctx.log(
      `Queued offline operation: ${operation} "${normalizedPath}" (queue size: ${this.ctx.getOfflineQueue().length})`
    );
  }

  /**
   * SD-06-F1 / DECISION 9 — map a queued op back to the intent its replay
   * should DECLARE.
   *
   * Two rules, both load-bearing:
   *
   * 1. **Explicit union check, never a truthiness test.** `op.intent` is an
   *    object, so `op.intent ? … : …` is true for *any* shape — including a
   *    future/foreign one — and would silently hand an unvalidated value to the
   *    wire. The resolution is read from the discriminant instead.
   * 2. **`unknown` degrades to "no intent supplied" (`undefined`), not to a
   *    supplied `{kind:"unknown"}`.** A *supplied* intent skips buildWriteBody's
   *    legacy derivation entirely; for a queue restored from an envelope written
   *    by an older build that would DROP the `expectedVersionId` guard
   *    `op.baseVersionId` still provides. 16-02's DECISION 5 rule applies:
   *    degrade to today's exact behavior, never to something weaker.
   */
  private resolveFlushIntent(op: OfflineQueueOperation): MutationIntent | undefined {
    const intent = op.intent ?? this.resolveIntentSafely(op.path);
    return intent === undefined || intent.kind === "unknown" ? undefined : intent;
  }

  /**
   * Flushes all queued offline operations to the server.
   * Operations are sent in chronological order.
   */
  async flushOfflineQueue(): Promise<void> {
    this.assertProtectedContentAllowed();
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
                const flushIntent = this.resolveFlushIntent(op);
                const body = this.buildWriteBody(op.path, encrypted, hash, {
                  expectedVersionId,
                  intent: flushIntent,
                  lane: "offline-flush-binary",
                });
                body.contentType = op.contentType ?? contentTypeForPath(op.path);
                const response = await this.ctx.apiRequest<RemoteFileWriteResponse>(
                  "PUT",
                  this.ctx.vaultPath(`/files/${encodeURIComponent(op.path)}`),
                  body,
                  undefined,
                  { timeoutMs: BINARY_PUT_TIMEOUT_MS }
                );
                // SD-06-F1 / DECISION 5 — a DECLARED create that lost the race
                // can NEVER succeed on retry: the path is occupied, so every
                // replay 409s again. Requeueing it (which is what
                // assertOfflineFlushResponse's write-409 throw triggers via the
                // catch below) would jam this op AND everything behind it
                // forever. Same philosophy the permanent-4xx branch already
                // states: "the server will never accept this op — drop it
                // instead of jamming the flush queue forever."
                //
                // The local file is untouched; reconciliation classifies the
                // divergence as `binaryBoth` and routes it to a user-chosen
                // strategy on the next pass, so nothing is lost by dropping.
                //
                // GATED ON THE DECLARED INTENT. An `expect-version` (or legacy
                // intent-less) binary 409 is a STALE UPDATE, which a later
                // replay could still win once the store catches up — it keeps
                // today's throw/requeue/break behavior untouched.
                if (
                  !response.success &&
                  response.error?.statusCode === 409 &&
                  flushIntent?.kind === "must-be-absent"
                ) {
                  this.ctx.logError(
                    `Dropping queued write for "${op.path}" — it declared a create but the path was taken on another device (HTTP 409)`,
                    new Error(response.error?.message ?? "Offline create conflict.")
                  );
                  new Notice(
                    `VaultGuard Sync: "${op.path}" was created on another device before this queued upload ran. Your local copy is kept — run sync to reconcile the two.`,
                    10000
                  );
                  break;
                }
                this.assertOfflineFlushResponse(response, op);
                this.recordSuccessfulWrite(op.path, hash, response);
              } else {
                const encrypted = await this.ctx.encryptContent(op.data);
                const hash = await this.ctx.computeHash(op.data);
                const expectedVersionId =
                  op.baseVersionId ?? this.ctx.getExpectedVersionId(op.path);
                // SD-06-F1 / DECISION 9: the intent this op captured at enqueue
                // time, falling back to a fresh store resolution for a queue
                // restored from an envelope written before this build.
                // `expectedVersionId` stays computed regardless — it is still
                // handed to handleRemoteWriteConflict below and to
                // buildDeleteBody in the delete case.
                const flushIntent = this.resolveFlushIntent(op);
                const declaredCreate = flushIntent?.kind === "must-be-absent";
                const response = await this.ctx.apiRequest<RemoteFileWriteResponse>(
                  "PUT",
                  this.ctx.vaultPath(`/files/${encodeURIComponent(op.path)}`),
                  this.buildWriteBody(op.path, encrypted, hash, {
                    expectedVersionId,
                    intent: flushIntent,
                    lane: "offline-flush-text",
                  })
                );
                if (!response.success && response.error?.statusCode === 409) {
                  const resolution = await this.handleRemoteWriteConflict(
                    op.path,
                    op.data,
                    expectedVersionId,
                    { createConflict: declaredCreate }
                  );
                  // SD-06-F1 / DECISION 2 consumer audit: every resolution other
                  // than `"pending"` — INCLUDING the new `"converged"` — is a
                  // settled outcome, so the op is consumed and the loop moves on.
                  if (resolution === "pending") {
                    // DECISION 5, EXTENDED TO THE TEXT LANE (deviation, recorded).
                    //
                    // DECISION 5 addressed only the binary flush because the text
                    // lane already intercepts 409 before assertOfflineFlushResponse.
                    // But this phase makes a CREATE-409 reachable here, and a
                    // `mustBeAbsent` op can never succeed on retry: throwing would
                    // requeue it and everything behind it on every flush, forever.
                    // That is exactly the jam the scope ceiling forbids ("No
                    // create-409 may jam the offline flush queue").
                    //
                    // Dropping is safe precisely BECAUSE the resolution was
                    // `"pending"`: handleRemoteWriteConflict has already recorded
                    // the SyncConflict entry and raised the Notice, and the local
                    // file is on disk (it was written when the op was queued). The
                    // content survives in both places; only the doomed replay is
                    // discarded.
                    //
                    // Gated on the declared create, so a stale UPDATE conflict —
                    // which a later replay CAN still win — keeps today's exact
                    // throw/requeue/break behavior.
                    if (declaredCreate) {
                      this.ctx.logError(
                        `Dropping queued write for "${op.path}" — it declared a create, the path was taken on another device, and the conflict is now recorded for the user to resolve`,
                        new Error(response.error?.message ?? "Offline create conflict.")
                      );
                      break;
                    }
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
