import { Notice, Platform, TFolder } from "obsidian";
import {
  AtRestCipher,
  type AtRestCiphertextSample,
  type AtRestRestoreOutcome,
  type AtRestStorage,
  type AtRestStatus,
} from "../crypto/at-rest-cipher";
import {
  PermissionLevel,
  type ApiResponse,
  type ConnectionStatus,
  type PendingLargeFileRecord,
} from "../types";
import type {
  AtRestAdapterRuntimeContext,
  MutationIntent,
  RemoteFileContentResponse,
  RemoteFileWriteResponse,
  RemoteWriteConflictResolutionResult,
  VaultAdapterOriginalMethods,
} from "./plugin-runtime-types";
// BIN-A / L1: interceptedRename's binary branch reuses the shared size ceiling,
// upload timeout, and MIME map.
import {
  BINARY_PUT_TIMEOUT_MS,
  BINARY_SYNC_MAX_BYTES,
  contentTypeForPath,
  isKnownBinaryExtensionPath,
} from "./binary-content";
import {
  DEFAULT_LONG_OPERATION_BATCH_SIZE,
  DEFAULT_STALLED_OPERATION_MS,
  describeConflict,
  evaluateWorkloadGuard,
  isLongOperationConflict,
  processInBatches,
  summarizeFileLikeWorkload,
  type LongOperationHandle,
} from "./long-operation";
import {
  LOCAL_PROJECT_MEMORY_MODE_NOTICE,
  isLocalProjectMemoryModeEnabled,
  isLocalProjectMemoryPlaintextPath,
} from "./local-project-memory-mode";
import {
  compactGitRepositoryRoots,
  isPathInDetectedGitRepository,
  normalizeGitRepositoryRoot,
} from "./git-repository-plaintext";
// SD-07-F5: cross-generation adapter ownership — unwrap-at-capture plus the
// detached-delegate error. See adapter-ownership.ts for why the marker is a
// plain string and not a Symbol.
import {
  AtRestAdapterDetachedError,
  markAdapterWrapper,
  resolveAdapterMethodBase,
} from "./adapter-ownership";
import {
  AtRestProtectionStateStore,
  classifyAtRestPayload,
  type AtRestPayloadClassification,
} from "./at-rest-protection-state";

function getActiveObsidianDocument(): Document | null {
  if (typeof activeDocument !== "undefined") {
    return activeDocument;
  }
  return null;
}

/**
 * BIN-A / L3: chunked Uint8Array → base64 for queuing a binary rename payload.
 * Mirrors main.ts's bytesToBase64 (0x8000-byte slices via String.fromCharCode.apply)
 * — browser-native (no Node Buffer, mobile constraint) and GC-friendly at 7 MB.
 * Duplicated per module per repo convention (no cross-module barrel imports for
 * tiny helpers). Output is byte-identical to a per-byte reference loop.
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
 * Hard cap on entries scanned by the limited-access placeholder sweep.
 */
const MAX_SWEEP_ENTRIES = 5000;

const PRIOR_PLUGIN_IDS_FOR_LAK_MIGRATION: Record<string, string[]> = {
  "vaultguard-sync": ["vaultguard"],
};

const emptyAdapterMethods = (): VaultAdapterOriginalMethods => ({
  read: null,
  write: null,
  readBinary: null,
  writeBinary: null,
  list: null,
  remove: null,
  rename: null,
  getResourcePath: null,
});

export interface AtRestDecryptAndDisableResult {
  decrypted: number;
  skipped: number;
  failed: number;
  remainingCiphertextPaths: string[];
  failures: Array<{ path: string; error: string }>;
}

export interface AutomaticLocalProjectMemoryModeSafetyInspection {
  safe: boolean;
  reason: "safe" | "ciphertext" | "inspection-failed";
  inspectedFiles: number;
  evidencePath?: string;
}

export interface AutomaticLocalProjectMemoryModeInspectionBudget {
  maxFiles: number;
  maxBytes: number;
  maxElapsedMs: number;
}

/**
 * Budgets for the pre-activation ciphertext sweep. Large repositories fail
 * closed instead of holding plugin startup open or enabling on partial proof.
 */
export const AUTO_LOCAL_PROJECT_MEMORY_INSPECTION_MAX_FILES = 20_000;
export const AUTO_LOCAL_PROJECT_MEMORY_INSPECTION_MAX_BYTES = 256 * 1024 * 1024;
export const AUTO_LOCAL_PROJECT_MEMORY_INSPECTION_MAX_MS = 10_000;

export const GIT_REPOSITORY_DISCOVERY_MAX_ENTRIES = 20_000;
export const GIT_REPOSITORY_DISCOVERY_MAX_MS = 10_000;
export const GIT_REPOSITORY_TRANSITION_FAILURE_DETAIL_LIMIT = 20;

export interface GitRepositoryDetectionOptions {
  enabled: boolean;
  mobile: boolean;
  maxEntries?: number;
  maxElapsedMs?: number;
}

function arrayBuffersEqual(left: ArrayBuffer, right: ArrayBuffer): boolean {
  if (left.byteLength !== right.byteLength) return false;
  const leftBytes = new Uint8Array(left);
  const rightBytes = new Uint8Array(right);
  for (let index = 0; index < leftBytes.length; index += 1) {
    if (leftBytes[index] !== rightBytes[index]) return false;
  }
  return true;
}

function boundedErrorMessage(error: unknown, maxLength = 240): string {
  const message = error instanceof Error ? error.message : String(error);
  return message.length <= maxLength ? message : `${message.slice(0, maxLength - 1)}…`;
}

export interface GitRepositoryDetectionResult {
  roots: string[];
  scannedEntries: number;
  complete: boolean;
  reason?:
    | "disabled"
    | "mobile"
    | "adapter-unavailable"
    | "budget-exhausted"
    | "listing-failed";
}

export interface GitRepositoryPlaintextTransitionResult {
  decrypted: number;
  alreadyPlaintext: number;
  failed: number;
  failures: Array<{ path: string; error: string }>;
}

export class AtRestAdapterRuntime {
  private originalAdapterMethods: VaultAdapterOriginalMethods = emptyAdapterMethods();
  /**
   * The exact wrapper functions this runtime installed on the adapter.
   *
   * Obsidian's `unloadPlugin` calls `plugin.unload()` without awaiting, and
   * `Component.unload()` / `onunload()` are declared `: void` — so an async
   * `onunload` tail keeps running while the next plugin instance boots and
   * installs its own interception. Restoring by identity means a superseded
   * instance can never strip the live instance's at-rest interception (which
   * would silently write plaintext and read raw ciphertext for the session).
   */
  private installedAdapterMethods: VaultAdapterOriginalMethods = emptyAdapterMethods();
  /**
   * SD-07-F5: true once restoreVaultAdapter has released this runtime's
   * delegates. A null delegate then means "we let go", not "the adapter never
   * had this method" — and a mutation must fail loud rather than report success.
   */
  private adapterDetached = false;
  /**
   * Method names this runtime actually captured a live delegate for. Retained
   * across detach precisely so the two meanings of a null delegate stay
   * distinguishable. Names only — holding the functions would keep the old
   * adapter alive for nothing.
   */
  private capturedAdapterMethodNames: Set<keyof VaultAdapterOriginalMethods> = new Set();
  private atRestCipher: AtRestCipher | null = null;
  /** Durable, path-hashed memory of files that must remain valid VG1. */
  private atRestProtectionState: AtRestProtectionStateStore | null = null;
  /** Current vault-relative repository roots; replaced atomically on every refresh. */
  private detectedGitRepositoryRoots: string[] = [];
  /**
   * Phase 12 (vault idle-lock): fail-closed content gate. When true the LAK is
   * evicted and every VG1 read short-circuits with a clean "vault locked" error
   * (no 10s waitForCipherInit hang — Pitfall 4). Set by the plugin's
   * enterLockState (via setLocked) and on a PIN-enrolled cold start
   * (initAtRestCipher lands LOCKED, edge #6); cleared by unlockCipherWithLak.
   */
  private locked = false;
  private atRestFirstRunOffered = false;
  /** One-shot proof reused by initAtRestCipher after automatic activation. */
  private automaticLocalProjectMemoryPlaintextVerified = false;
  private readOnlyFallbackNoticeAt: Map<string, number> = new Map();
  private cloudDecryptFallbackNoticeAt: Map<string, number> = new Map();
  private cipherInitPromise: Promise<boolean> | null = null;
  /**
   * W2: handle to the sticky init-time needs-recovery Notice so it can be
   * cleared on recovery via ANY door — not just its own CTA click. Held here
   * (instead of a local `const`) precisely so refreshAtRestRecoverySurfaces can
   * hide it on the transition OUT of needs-recovery.
   */
  private atRestRecoveryNotice: Notice | null = null;
  private corruptedWriteNoticeAt: Map<string, number> = new Map();
  private binaryWriteNoticeAt: Map<string, number> = new Map();
  /** Paths currently being re-encrypted in place (dedupes concurrent triggers). */
  private inPlaceEncryptionInFlight: Set<string> = new Set();
  /**
   * BIN-A preview: path → decrypted `blob:` URL + the resource mtime it was
   * decrypted at. `getResourcePath` (sync) serves these so at-rest-encrypted
   * media renders; the async decrypt populates the cache and swaps the DOM src.
   */
  private resourcePreviewCache: Map<string, { url: string; mtime: string }> = new Map();
  /** Paths whose decrypted blob is currently being produced (dedupes concurrent renders). */
  private resourcePreviewInFlight: Set<string> = new Set();

  constructor(private ctx: AtRestAdapterRuntimeContext) {}

  getOriginalAdapterMethods(): VaultAdapterOriginalMethods {
    return this.originalAdapterMethods;
  }

  setOriginalAdapterMethods(methods: VaultAdapterOriginalMethods): void {
    this.originalAdapterMethods = methods;
    // SD-07-F5: an explicit re-seed re-attaches this runtime. Keep the detach
    // discriminator in sync or a re-seeded runtime keeps throwing.
    this.adapterDetached = false;
    this.capturedAdapterMethodNames = new Set(
      (Object.keys(methods) as Array<keyof VaultAdapterOriginalMethods>).filter(
        (name) => methods[name] != null,
      ),
    );
  }

  getAtRestCipher(): AtRestCipher | null {
    return this.atRestCipher;
  }

  setAtRestCipher(cipher: AtRestCipher | null): void {
    this.atRestCipher = cipher;
  }

  // ─── Phase 12 vault idle-lock: fail-closed lock state ───────────────────────

  /** True while the vault is cryptographically locked (LAK evicted). */
  isLocked(): boolean {
    return this.locked;
  }

  /**
   * Flip the fail-closed lock flag. Locking also revokes the decrypted-media
   * blob-URL cache (Pitfall 1) so already-rendered images/PDFs can't leak
   * behind the curtain. The plugin's enterLockState calls setLocked(true) AFTER
   * evicting the in-memory LAK via `atRestCipher.lock()`; unlockCipherWithLak
   * clears it. Distinct from `atRestCipher.lock()`: this flag makes reads fail
   * CLOSED immediately (no waitForCipherInit), independent of cipher readiness.
   */
  setLocked(locked: boolean): void {
    this.locked = locked;
    if (locked) {
      this.revokeAllResourcePreviews();
    }
  }

  /**
   * Adopt a PIN-unwrapped LAK and lift the lock: import the raw key into the
   * cipher (without recreating the transparent `lak.envelope` — NN-1) and clear
   * the fail-closed flag so VG1 reads succeed again. Called by the plugin's
   * unlockWithPin once PinLockManager yields the LAK.
   */
  async unlockCipherWithLak(bytes: Uint8Array): Promise<void> {
    await this.getAtRestCipher()?.unlockWithLak(bytes);
    this.setLocked(false);
  }

  getAtRestStatus(): AtRestStatus {
    if (this.isLocalProjectMemoryModeEnabled()) {
      return {
        kind: "disabled",
        reason: "Local Project Memory Mode keeps project files plaintext.",
      };
    }
    return this.atRestCipher?.getStatus() ?? { kind: "uninitialized" };
  }

  isLocalProjectMemoryModeEnabled(): boolean {
    return isLocalProjectMemoryModeEnabled(this.settings);
  }

  isLocalProjectMemoryPlaintextPath(path: string): boolean {
    return isLocalProjectMemoryPlaintextPath(path, this.app.vault.configDir);
  }

  getDetectedGitRepositoryRoots(): string[] {
    return [...this.detectedGitRepositoryRoots];
  }

  isDetectedGitRepositoryPath(path: string): boolean {
    return isPathInDetectedGitRepository(path, this.detectedGitRepositoryRoots);
  }

  /**
   * Discover vault-root and nested Git repositories without executing Git or
   * reading repository configuration. The current root set is always replaced,
   * including on failure, so a moved/deleted repository cannot remain a stale
   * plaintext boundary.
   */
  async refreshDetectedGitRepositoryRoots(
    options: GitRepositoryDetectionOptions,
  ): Promise<GitRepositoryDetectionResult> {
    this.detectedGitRepositoryRoots = [];
    if (!options.enabled) {
      return { roots: [], scannedEntries: 0, complete: true, reason: "disabled" };
    }
    if (options.mobile) {
      return { roots: [], scannedEntries: 0, complete: true, reason: "mobile" };
    }

    const list = this.originalAdapterMethods.list;
    if (!list) {
      return {
        roots: [],
        scannedEntries: 0,
        complete: false,
        reason: "adapter-unavailable",
      };
    }

    const maxEntries = options.maxEntries ?? GIT_REPOSITORY_DISCOVERY_MAX_ENTRIES;
    const maxElapsedMs = options.maxElapsedMs ?? GIT_REPOSITORY_DISCOVERY_MAX_MS;
    const startedAt = Date.now();
    const queue: string[] = [""];
    const roots: string[] = [];
    let scannedEntries = 0;

    const finish = (
      complete: boolean,
      reason?: GitRepositoryDetectionResult["reason"],
    ): GitRepositoryDetectionResult => {
      this.detectedGitRepositoryRoots = compactGitRepositoryRoots(roots);
      return {
        roots: this.getDetectedGitRepositoryRoots(),
        scannedEntries,
        complete,
        ...(reason ? { reason } : {}),
      };
    };

    while (queue.length > 0) {
      if (Date.now() - startedAt > maxElapsedMs) {
        this.log(
          `Git repository folder detection stopped after ${scannedEntries} entries: time budget exhausted.`,
        );
        return finish(false, "budget-exhausted");
      }

      const current = queue.shift()!;
      let listing: { files: string[]; folders: string[] };
      try {
        listing = await list(current || "/");
      } catch (error) {
        this.logError("Git repository folder detection could not list a vault folder", error);
        return finish(false, "listing-failed");
      }

      scannedEntries += listing.files.length + listing.folders.length;
      if (scannedEntries > maxEntries) {
        this.log(
          `Git repository folder detection stopped after ${scannedEntries} entries: entry budget exhausted.`,
        );
        return finish(false, "budget-exhausted");
      }

      const entries = [...listing.files, ...listing.folders];
      const markerFound = entries.some((entry) => {
        const normalized = normalizeGitRepositoryRoot(entry);
        return normalized?.split("/").pop() === ".git";
      });
      if (markerFound) {
        roots.push(current);
        continue;
      }

      for (const folder of listing.folders) {
        const normalized = normalizeGitRepositoryRoot(folder);
        if (normalized === null) continue;
        const child =
          current && normalized !== current && !normalized.startsWith(`${current}/`)
            ? `${current}/${normalized}`
            : normalized;
        const configDir = normalizeGitRepositoryRoot(this.app.vault.configDir);
        if (
          child === ".trash" ||
          child.startsWith(".trash/") ||
          (configDir !== null && (child === configDir || child.startsWith(`${configDir}/`)))
        ) {
          continue;
        }
        queue.push(child);
      }
    }

    return finish(true);
  }

  /**
   * Rewrite residual VG1 files inside detected repositories to plaintext.
   *
   * The repository boundary is local-at-rest only: this pass deliberately
   * leaves Local Project Memory Mode, sync exclusions, cloud encryption, and
   * permission state untouched. Each write is verified and a failed write is
   * rolled back to the exact original bytes on a best-effort basis.
   */
  async convertDetectedGitRepositoryCiphertext(): Promise<GitRepositoryPlaintextTransitionResult> {
    const targets = this.app.vault
      .getFiles()
      .filter((file) => this.isDetectedGitRepositoryPath(file.path));
    if (targets.length === 0 || this.isLocalProjectMemoryModeEnabled()) {
      return { decrypted: 0, alreadyPlaintext: 0, failed: 0, failures: [] };
    }

    const readBinary = this.originalAdapterMethods.readBinary;
    const writeBinary = this.originalAdapterMethods.writeBinary;
    const cipher = this.atRestCipher;
    if (this.locked || !cipher?.isReady() || !readBinary || !writeBinary) {
      const reason = this.locked
        ? "Vault is locked; existing encrypted content was preserved."
        : !cipher?.isReady()
          ? "Local at-rest encryption is not ready; existing encrypted content was preserved."
          : !readBinary
            ? "Vault adapter binary reads are unavailable; existing content was preserved."
            : "Vault adapter binary writes are unavailable; existing content was preserved.";
      return {
        decrypted: 0,
        alreadyPlaintext: 0,
        failed: targets.length,
        failures: targets
          .slice(0, GIT_REPOSITORY_TRANSITION_FAILURE_DETAIL_LIMIT)
          .map((file) => ({ path: file.path, error: reason })),
      };
    }
    let decrypted = 0;
    let alreadyPlaintext = 0;
    let failed = 0;
    let processed = 0;
    let processedBytes = 0;
    const failures: Array<{ path: string; error: string }> = [];
    const workload = summarizeFileLikeWorkload(targets);
    const guard = evaluateWorkloadGuard(workload);
    const operation = this.ctx.beginLongOperation({
      kind: "vault-decrypt",
      operationName: "Decrypt detected Git repositories",
      phase: "Preparing detected repository plaintext pass",
      placement: "protected",
      totalItems: targets.length,
      totalBytes: workload.totalBytes,
      warning: guard.warnings.join(" ") || undefined,
      capabilities: {
        protectedPhase: true,
        canCancel: false,
        canPause: false,
      },
      conflictsWith: ["vault-encrypt", "sync", "background-sync", "initial-reconciliation"],
      stalledAfterMs: DEFAULT_STALLED_OPERATION_MS,
    });

    if (!guard.ok) {
      const error = new Error(
        guard.error ?? "VaultGuard workload guard blocked detected repository decryption.",
      );
      operation.fail(error);
      throw error;
    }

    try {
      await processInBatches(
        targets,
        async (file) => {
          let originalBytes: ArrayBuffer | null = null;
          try {
            originalBytes = await readBinary(file.path);
            if (!this.looksLikeCiphertextBytes(originalBytes)) {
              alreadyPlaintext += 1;
              return;
            }
            if (this.locked || !cipher.isReady()) {
              throw new Error("Local at-rest encryption is not ready; existing encrypted content was preserved.");
            }

            const plaintext = await cipher.decryptBinary(originalBytes);
            try {
              await writeBinary(file.path, plaintext);
              const storedBytes = await readBinary(file.path);
              if (!arrayBuffersEqual(storedBytes, plaintext)) {
                throw new Error("Plaintext write verification failed.");
              }
              await this.forgetAtRestProtected(file.path);
            } catch (writeError) {
              let rollbackVerified = false;
              try {
                await writeBinary(file.path, originalBytes);
                rollbackVerified = arrayBuffersEqual(await readBinary(file.path), originalBytes);
              } catch (rollbackError) {
                this.logError(
                  `Detected Git repository plaintext rollback failed for "${file.path}"`,
                  rollbackError,
                );
              }
              const reason = writeError instanceof Error ? writeError.message : String(writeError);
              throw new Error(
                rollbackVerified
                  ? `${reason} Original encrypted bytes were restored.`
                  : `${reason} Original-byte rollback could not be verified.`,
              );
            }
            decrypted += 1;
          } catch (error) {
            failed += 1;
            const message = boundedErrorMessage(error);
            failures.push({ path: file.path, error: message });
            this.logError(
              `Detected Git repository plaintext conversion failed for "${file.path}"`,
              error,
            );
          } finally {
            processed += 1;
            processedBytes += file.stat?.size ?? originalBytes?.byteLength ?? 0;
            operation.update({
              phase: "Decrypting detected repository files",
              processedItems: processed,
              processedBytes,
              message: `${decrypted} decrypted, ${alreadyPlaintext} already plaintext, ${failed} failed.`,
            });
          }
        },
        {
          batchSize: DEFAULT_LONG_OPERATION_BATCH_SIZE,
          token: operation.token,
        },
      );
    } catch (error) {
      operation.fail(error);
      throw error;
    }

    operation.complete(
      `${decrypted} decrypted, ${alreadyPlaintext} already plaintext, ${failed} failed.`,
    );
    return { decrypted, alreadyPlaintext, failed, failures };
  }

  async tallyAtRestState(): Promise<{
    plaintext: number;
    encrypted: number;
    excluded: number;
    failed: number;
    total: number;
  }> {
    if (this.isLocalProjectMemoryModeEnabled()) {
      return this.tallyLocalProjectMemoryAtRestState();
    }
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
        const classification = await this.classifyAtRestBytes(file.path, bytes);
        if (classification.kind === "encrypted") {
          encrypted += 1;
          await this.rememberAtRestProtected(file.path);
        } else if (classification.kind === "corrupt-protected") failed += 1;
        else plaintext += 1;
      } catch {
        failed += 1;
      }
    }
    return { plaintext, encrypted, excluded, failed, total: files.length };
  }

  private async tallyLocalProjectMemoryAtRestState(): Promise<{
    plaintext: number;
    encrypted: number;
    excluded: number;
    failed: number;
    total: number;
  }> {
    const readBin = this.originalAdapterMethods.readBinary;
    const files = this.app.vault.getFiles();
    let plaintext = 0;
    let encrypted = 0;
    let failed = 0;
    if (!readBin) {
      return { plaintext: 0, encrypted: 0, excluded: 0, failed: 0, total: files.length };
    }
    for (const file of files) {
      try {
        const bytes = await readBin(file.path);
        const classification = await this.classifyAtRestBytes(file.path, bytes);
        if (classification.kind === "encrypted") {
          encrypted += 1;
          await this.rememberAtRestProtected(file.path);
        } else if (classification.kind === "corrupt-protected") failed += 1;
        else plaintext += 1;
      } catch {
        failed += 1;
      }
    }
    return { plaintext, encrypted, excluded: 0, failed, total: files.length };
  }

  async migrateVaultToAtRest(): Promise<void> {
    return this.encryptVaultAtRest();
  }

  async revertVaultFromAtRest(): Promise<void> {
    await this.decryptVaultAtRestAndDisableEncryption();
  }

  async exportAtRestRecoveryCode(): Promise<string> {
    if (!this.atRestCipher) {
      throw new Error("VaultGuard Sync: at-rest cipher not initialised.");
    }
    return this.atRestCipher.exportRecoveryCode();
  }

  /** True when at least one managed VG1 file survives outside plugin data. */
  async hasPriorAtRestCiphertext(): Promise<boolean> {
    return this.hasAtRestCiphertextOnDisk();
  }

  /**
   * Authenticate the currently loaded LAK against an existing VG1 payload.
   * A locally sealed uninstall capsule is still advisory until this succeeds:
   * it may be stale or copied from another vault. No plaintext is retained.
   */
  async validateCurrentLakAgainstExistingCiphertext(): Promise<boolean> {
    const cipher = this.atRestCipher;
    if (!cipher?.isReady()) return false;
    try {
      for await (const sample of this.iterateCiphertextForValidation()) {
        const plaintext = new Uint8Array(await cipher.decryptBinary(sample.bytes));
        plaintext.fill(0);
        return true;
      }
      return true; // no VG1 remains; the device wrapper is still authenticated locally
    } catch (error) {
      const reason =
        "The restored same-device key capsule does not authenticate this vault's existing protected files. Restore with the vault's recovery code; no files were changed.";
      cipher.requireRecovery(reason);
      this.locked = false;
      this.logError("Recovered local at-rest key failed VG1 continuity validation", error);
      this.ctx.refreshAtRestRecoverySurfaces?.();
      return false;
    }
  }

  /**
   * SD-05-F3: yield every managed VG1 file for recovery-code validation,
   * SMALLEST FIRST so a wrong code is refused after one cheap decrypt.
   *
   * FAIL-CLOSED (binding): every failure THROWS out of the iterator. The cipher
   * treats a throw as "cannot verify" and refuses the restore with nothing
   * changed. This deliberately does NOT copy `hasExistingCiphertext`'s per-file
   * "catch and keep scanning" swallow — that swallow is open finding SD-05-F5,
   * and replicating it here would let an unreadable file silently downgrade
   * validation to "no ciphertext exists" and re-open exactly this finding.
   *
   * Raw `originalAdapterMethods.readBinary` is the sanctioned Local-At-Rest-Rule
   * exception (same one `hasExistingCiphertext` uses): this is cipher-internal
   * key machinery, not content access, and the bytes stay ciphertext throughout.
   */
  private async *iterateCiphertextForValidation(): AsyncGenerator<AtRestCiphertextSample> {
    const readBin = this.originalAdapterMethods.readBinary;
    if (!readBin) {
      throw new Error(
        "VaultGuard Sync: cannot verify the recovery code — the vault adapter's binary read is unavailable."
      );
    }
    const files = this.app.vault
      .getFiles()
      .filter((file) => !this.isAtRestExcluded(file.path))
      .sort((a, b) => (a.stat?.size ?? 0) - (b.stat?.size ?? 0));
    for (const file of files) {
      const bytes = await readBin(file.path); // throws -> fail closed, by design
      const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
      if (!this.looksLikeCiphertextBytes(view)) continue; // plaintext/legacy: not ours to check
      yield { path: file.path, bytes: view };
    }
  }

  async restoreAtRestFromRecoveryCode(
    code: string,
    opts?: { confirmReplace?: boolean }
  ): Promise<AtRestRestoreOutcome> {
    if (!this.atRestCipher) {
      await this.initAtRestCipher();
    }
    if (!this.atRestCipher) {
      // Fail closed: with no cipher we cannot even ask the question.
      return { ok: false, reason: "validation-error" };
    }
    const result = await this.atRestCipher.restoreFromRecoveryCode(code, opts);

    // D2 (main.ts:10899-10904): a PIN wraps a SPECIFIC LAK. When the key was
    // REPLACED rather than proven (`continuity: "replaced"` — a confirmed
    // zero-ciphertext replacement), the PIN envelope wraps a key this device no
    // longer uses. Leaving it enrolled would let a later PIN unlock resurrect
    // the old key. Continuity proven ("same-key"/"verified") => PIN untouched:
    // it wraps exactly the key we just re-adopted.
    if (result.ok && result.continuity === "replaced" && this.isPinLockEnrolled()) {
      try {
        await this.ctx.disablePinLock?.();
        new Notice(
          "VaultGuard Sync: your PIN was removed because the local encryption key was replaced. Set a new PIN in Settings if you want one.",
          9000
        );
      } catch (err) {
        this.logError("Clearing PIN enrollment after a recovery-code key replacement failed", err);
      }
    }

    // Recovery-code door: re-assert the #1 surfaces so a successful restore
    // CLEARS the status bar + sidebar banner + sticky (W2). A refusal changes
    // nothing, so there is nothing to refresh.
    if (result.ok) this.ctx.refreshAtRestRecoverySurfaces?.();
    return result;
  }

  getAdapterReadBinary(): ((normalizedPath: string) => Promise<ArrayBuffer>) | null {
    return this.originalAdapterMethods.readBinary ?? null;
  }

  getAdapterWriteBinary():
    | ((normalizedPath: string, data: ArrayBuffer) => Promise<void>)
    | null {
    return this.originalAdapterMethods.writeBinary ?? null;
  }

  private get app() {
    return this.ctx.app;
  }

  private get manifest(): { id?: string } | undefined {
    return this.ctx.manifestId ? { id: this.ctx.manifestId } : undefined;
  }

  private get settings() {
    return this.ctx.settings;
  }

  /** True when a device PIN currently owns the LAK (Phase 12; optional ctx signal). */
  private isPinLockEnrolled(): boolean {
    return this.ctx.isPinLockEnrolled?.() ?? false;
  }

  /**
   * True when the org has per-file restrictions on admins enabled (SD-03-F15;
   * optional ctx signal). The optional call plus `=== true` is required:
   * partial `any` ctx fixtures in existing suites do not supply the member,
   * and absent must mean "unrestricted" (today's behaviour).
   */
  private adminRestrictionActive(): boolean {
    return this.ctx.isAdminRestrictionActive?.() === true;
  }

  private get session() {
    return this.ctx.getSession();
  }

  private get keyLease() {
    return this.ctx.getKeyLease();
  }

  private get vaultLeaseDenied() {
    return this.ctx.isVaultLeaseDenied();
  }

  private get placeholderPaths() {
    return this.ctx.getPlaceholderPaths();
  }

  private get applyingRemoteWrite() {
    return this.ctx.isApplyingRemoteWrite();
  }

  private get syncState() {
    return this.ctx.getSyncState();
  }

  private get offlineQueue() {
    return this.ctx.getOfflineQueue();
  }

  private get permissionStore() {
    return this.ctx.getPermissionStore();
  }

  private get hasWarmedAtLeastOnce() {
    return this.ctx.hasWarmedAtLeastOnce();
  }

  private saveSettings(): Promise<void> {
    return this.ctx.saveSettings();
  }

  private openVaultGuardSettings(): void {
    this.ctx.openVaultGuardSettings();
  }

  private showLoginRequiredNotice(
    action: "open" | "browse" | "edit" | "delete" | "sync" | "view permissions",
    path?: string,
  ): string {
    return this.ctx.showLoginRequiredNotice(action, path);
  }

  private awaitPermissionReadiness(): Promise<void> {
    return this.ctx.awaitPermissionReadiness();
  }

  private getEffectivePermission(path: string): Promise<PermissionLevel> {
    return this.ctx.getEffectivePermission(path);
  }

  private resolvePermissionFromCache(path: string): PermissionLevel {
    return this.ctx.resolvePermissionFromCache(path);
  }

  private isPathExcluded(path: string): boolean {
    return this.ctx.isPathExcluded(path);
  }

  private normalizeVaultPath(path: string): string {
    return this.ctx.normalizeVaultPath(path);
  }

  private vaultConfigPath(...parts: string[]): string {
    return this.ctx.vaultConfigPath(...parts);
  }

  private toPermissionPath(path: string): string {
    return this.ctx.toPermissionPath(path);
  }

  private isFolderMarkerPath(path: string): boolean {
    return this.ctx.isFolderMarkerPath(path);
  }

  private isOnline(): boolean {
    return this.ctx.isOnline();
  }

  private isNetworkError(error: unknown): boolean {
    return this.ctx.isNetworkError(error);
  }

  private setConnectionStatus(status: ConnectionStatus): void {
    this.ctx.setConnectionStatus(status);
  }

  private shouldUploadChangesImmediately(): boolean {
    return this.ctx.shouldUploadChangesImmediately();
  }

  private queueOfflineOperation(
    operation: "write" | "delete",
    path: string,
    data?: string,
    // BIN-A / D-09 + version-guard: forward the optional binary-payload marker
    // (encoding + MIME) and/or version-guard fields to the runtime queue. All
    // existing 3-arg (text) call sites stay valid.
    options?: {
      encoding?: "base64";
      contentType?: string;
      baseVersionId?: string;
      baseHash?: string;
      intent?: MutationIntent;
    },
  ): void {
    this.ctx.queueOfflineOperation(operation, path, data, options);
  }

  private getExpectedVersionId(path: string): string | undefined {
    return this.ctx.getExpectedVersionId(path);
  }

  /**
   * SD-06-F1 / DECISION 6 — probe input for the local-new upgrade: did `path`
   * exist in the vault index immediately BEFORE this write?
   *
   * MUST be captured before any `await` in the calling write — an await lets
   * Obsidian's vault index move underneath us and the answer stops describing
   * "before this write".
   *
   * FAIL-SAFE DIRECTION: when the index cannot be probed at all (a host or a
   * test double without `getAbstractFileByPath`, or a lookup that throws) this
   * returns TRUE — "it existed" — which SUPPRESSES the create upgrade and
   * leaves the write in today's exact lane. Every failure mode of this probe
   * must point that way.
   */
  private localFileExistedBeforeWrite(path: string): boolean {
    const vault = this.app?.vault as
      | { getAbstractFileByPath?: (p: string) => unknown }
      | undefined;
    if (typeof vault?.getAbstractFileByPath !== "function") return true;
    try {
      return vault.getAbstractFileByPath(path) != null;
    } catch {
      return true;
    }
  }

  /**
   * SD-06-F1 / DECISION 6 — the mutation intent for an ONLINE small-file write.
   *
   * Store resolution, plus a local-new upgrade that fires only when ALL THREE
   * of these hold:
   *   1. the store resolution is `unknown`,
   *   2. the store holds NO entry at all for the path (never tracked), and
   *   3. the local file did not exist immediately before this write.
   *
   * Two conditions would not be enough. A `present`-but-versionless entry (P17)
   * and an explicit `unknown` entry BOTH resolve to `{kind:"unknown"}`, but the
   * store has SEEN those paths — its absence knowledge is not fresh — so
   * declaring `mustBeAbsent` for them could 409 a file that really exists. The
   * "no entry at all" condition is what separates "never heard of it" from
   * "heard of it, lost the details".
   *
   * Why the probe is acceptable without an fs `stat`: Obsidian's
   * `vault.create()` calls `adapter.write()` BEFORE the new `TFile` is
   * registered in the index, so the probe reads null for a genuine create and
   * non-null for a `vault.modify()`. If a future Obsidian version registered
   * the TFile first, the probe would return non-null, the intent would stay
   * `unknown`, and the write would land in TODAY's exact lane. The probe can
   * only ever fail *toward* current behavior.
   *
   * Returns `undefined` — not `{kind:"unknown"}` — when the context predates
   * `resolveMutationIntent` (DECISION 5). An undefined intent leaves
   * buildWriteBody on its legacy `expectedVersionId` derivation, i.e. today's
   * exact body; forcing the unknown lane instead would silently DROP the
   * version guard that call site passes.
   */
  /**
   * SD-06-F1 / DECISION 6 — the intent a RENAME DESTINATION declares. Twin of
   * `SyncRuntime.resolveRenameDestIntent`; duplicated per module rather than
   * shared through a barrel, matching this file's existing convention for tiny
   * helpers.
   *
   * Resolve from the store, then upgrade an `unknown` to `must-be-absent` on a
   * STRUCTURAL fact rather than a probe: Obsidian refuses a rename onto an
   * existing local path, so a rename destination is by definition locally new.
   * A destination the store knows is `present(v)` still resolves to
   * `expect-version` — which is what keeps the P18 anchor byte-identical.
   */
  private resolveRenameDestIntent(destPath: string): MutationIntent | undefined {
    const resolve = this.ctx.resolveMutationIntent;
    if (typeof resolve !== "function") return undefined;
    const intent = resolve.call(this.ctx, destPath);
    if (!intent) return undefined;
    return intent.kind === "unknown" ? { kind: "must-be-absent" } : intent;
  }

  private resolveWriteIntent(
    path: string,
    existedLocally: boolean,
  ): MutationIntent | undefined {
    const resolve = this.ctx.resolveMutationIntent;
    if (typeof resolve !== "function") return undefined;
    const intent = resolve.call(this.ctx, path);
    if (!intent || intent.kind !== "unknown") return intent;
    if (existedLocally) return intent;
    if (this.ctx.getRemoteFileState(path) !== null) return intent;
    return { kind: "must-be-absent" };
  }

  private recordRemoteFilePresent(
    path: string,
    update: {
      versionId?: string | null;
      baseHash?: string | null;
      checksum?: string | null;
      lastModified?: string | null;
      size?: number | null;
    } = {},
  ): void {
    this.ctx.recordRemoteFilePresent(path, update);
  }

  private recordRemoteFileAbsent(path: string): void {
    this.ctx.recordRemoteFileAbsent(path);
  }

  private handleRemoteWriteConflict(
    path: string,
    localContent: string,
    baseVersionId?: string | null,
    // SD-06-F1 / DECISION 2: forwarded verbatim — see the ctx declaration.
    options?: { createConflict?: boolean },
  ): Promise<RemoteWriteConflictResolutionResult> {
    return this.ctx.handleRemoteWriteConflict(path, localContent, baseVersionId, options);
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
    expectedVersionId = this.getExpectedVersionId(path),
  ): Record<string, unknown> | undefined {
    return expectedVersionId ? { expectedVersionId } : undefined;
  }

  private recordSuccessfulWrite(
    path: string,
    hash: string,
    response: ApiResponse<RemoteFileWriteResponse>,
  ): void {
    if (!response.success) return;
    this.recordRemoteFilePresent(path, {
      versionId: response.data?.versionId,
      baseHash: hash,
      checksum: response.data?.checksum,
      lastModified: response.data?.lastModified,
      size: response.data?.size,
    });
  }

  private recordDeletionTombstone(path: string): void {
    this.ctx.recordDeletionTombstone(path);
  }

  private clearDeletionTombstone(path: string): void {
    this.ctx.clearDeletionTombstone(path);
  }

  private updateStatusBar(): void {
    this.ctx.updateStatusBar();
  }

  private encryptContent(content: string): Promise<string> {
    return this.ctx.encryptContent(content);
  }

  private computeHash(content: string): Promise<string> {
    return this.ctx.computeHash(content);
  }

  // BIN-A / D-02: byte-crypto wrappers mirroring the string siblings above. The
  // ctx exposes both from plan 11-01; interceptedRename's binary branch calls
  // these (never this.ctx.* directly) so the interception body stays uniform.
  private encryptContentBytes(bytes: ArrayBuffer): Promise<string> {
    return this.ctx.encryptContentBytes(bytes);
  }

  private computeHashBytes(bytes: ArrayBuffer): Promise<string> {
    return this.ctx.computeHashBytes(bytes);
  }

  /**
   * Read-only, fail-closed inspection used before automatically entering Local
   * Project Memory Mode. Raw adapter reads ensure existing VG1 ciphertext is
   * detected before the whole-vault plaintext mode can be enabled.
   */
  async inspectAutomaticLocalProjectMemoryModeSafety(
    budget: Partial<AutomaticLocalProjectMemoryModeInspectionBudget> = {},
  ): Promise<AutomaticLocalProjectMemoryModeSafetyInspection> {
    const readBinary = this.originalAdapterMethods.readBinary;
    if (!readBinary) {
      return {
        safe: false,
        reason: "inspection-failed",
        inspectedFiles: 0,
      };
    }

    const maxFiles = budget.maxFiles ?? AUTO_LOCAL_PROJECT_MEMORY_INSPECTION_MAX_FILES;
    const maxBytes = budget.maxBytes ?? AUTO_LOCAL_PROJECT_MEMORY_INSPECTION_MAX_BYTES;
    const maxElapsedMs = budget.maxElapsedMs ?? AUTO_LOCAL_PROJECT_MEMORY_INSPECTION_MAX_MS;
    const startedAt = Date.now();

    const exhausted = (
      reason: string,
      inspectedFiles: number,
    ): AutomaticLocalProjectMemoryModeSafetyInspection => {
      this.log(
        `Automatic Local Project Memory Mode inspection stopped after ${inspectedFiles} file(s): ${reason}. Leaving this vault unchanged.`,
      );
      return { safe: false, reason: "inspection-failed", inspectedFiles };
    };

    const files = this.app.vault.getFiles();
    if (files.length > maxFiles) {
      return exhausted(`vault holds ${files.length} files (limit ${maxFiles})`, 0);
    }

    let inspectedFiles = 0;
    let inspectedBytes = 0;
    for (const file of files) {
      if (Date.now() - startedAt > maxElapsedMs) {
        return exhausted(`exceeded the ${maxElapsedMs} ms deadline`, inspectedFiles);
      }
      try {
        const bytes = await readBinary(file.path);
        inspectedFiles += 1;
        inspectedBytes += bytes.byteLength;
        if (this.hasVg1MagicBytes(bytes)) {
          return {
            safe: false,
            reason: "ciphertext",
            inspectedFiles,
            evidencePath: file.path,
          };
        }
        if (inspectedBytes > maxBytes) {
          return exhausted(`read past the ${maxBytes} byte budget`, inspectedFiles);
        }
      } catch (error) {
        this.logError("Automatic Local Project Memory Mode ciphertext probe failed", error);
        return {
          safe: false,
          reason: "inspection-failed",
          inspectedFiles,
          evidencePath: file.path,
        };
      }
    }

    this.automaticLocalProjectMemoryPlaintextVerified = true;
    return { safe: true, reason: "safe", inspectedFiles };
  }

  private async markLargeFilePending(
    path: string,
    bytes: ArrayBuffer,
    contentType: string,
    reason: PendingLargeFileRecord["reason"],
    previousPath?: string,
  ): Promise<void> {
    if (!this.ctx.upsertPendingLargeFile) return;
    const normalized = this.normalizeVaultPath(path);
    const existing = this.settings.pendingLargeFiles?.[normalized];
    await this.ctx.upsertPendingLargeFile({
      path: normalized,
      ...(previousPath ? { previousPath: this.normalizeVaultPath(previousPath) } : {}),
      size: bytes.byteLength,
      sha256: await this.computeHashBytes(bytes),
      contentType,
      reason,
      state: reason === "conflict" ? "blocked" : "retryable",
      localProtection: "plaintext-pending",
      attempts: (existing?.attempts ?? 0) + 1,
      updatedAt: new Date().toISOString(),
    });
  }

  private recordDirectWrite(
    path: string,
    hash: string,
    result: { versionId?: string; lastModified: string; size: number },
  ): void {
    this.recordRemoteFilePresent(path, {
      versionId: result.versionId,
      baseHash: hash,
      lastModified: result.lastModified,
      size: result.size,
    });
  }

  private apiRequest<T>(
    method: string,
    endpoint: string,
    body?: Record<string, unknown>,
    idTokenOverride?: string,
    // L2 (BIN-A): optional per-request timeout override for large binary PUTs.
    // Arity-preserving: existing callers keep the exact 3/4-arg shape (trailing
    // undefineds would break toHaveBeenCalledWith assertions — see 11-01 b5142b1).
    options?: { timeoutMs?: number },
  ): Promise<ApiResponse<T>> {
    if (options !== undefined) {
      return this.ctx.apiRequest<T>(method, endpoint, body, idTokenOverride, options);
    }
    return this.ctx.apiRequest<T>(method, endpoint, body, idTokenOverride);
  }

  private vaultPath(suffix = ""): string {
    return this.ctx.vaultPath(suffix);
  }

  private readFileDecrypted(path: string): Promise<ApiResponse<RemoteFileContentResponse>> {
    return this.ctx.readFileDecrypted(path);
  }

  private fetchRemoteFileContent(path: string): Promise<ApiResponse<RemoteFileContentResponse>> {
    return this.ctx.fetchRemoteFileContent(path);
  }

  private decodeRemoteFileContent(path: string, data: RemoteFileContentResponse): Promise<string> {
    return this.ctx.decodeRemoteFileContent(path, data);
  }

  private decodeBase64Utf8(base64: string): string {
    return this.ctx.decodeBase64Utf8(base64);
  }

  private hostReadPlainFromDisk(path: string): Promise<string> {
    return this.ctx.readPlainFromDisk(path);
  }

  private hostWritePlainToDisk(path: string, data: string): Promise<void> {
    return this.ctx.writePlainToDisk(path, data);
  }

  private hostReadPlainBinaryFromDisk(path: string): Promise<ArrayBuffer> {
    return this.ctx.readPlainBinaryFromDisk(path);
  }

  private hostWritePlainBinaryToDisk(
    path: string,
    data: ArrayBuffer,
  ): Promise<void> {
    return this.ctx.writePlainBinaryToDisk(path, data);
  }

  private hostNotifyCloudDecryptFallback(path: string): void {
    this.ctx.notifyCloudDecryptFallback(path);
  }

  private hostNotifyCorruptedWrite(path: string): void {
    this.ctx.notifyCorruptedWrite(path);
  }

  private emitAuditEvent(
    action: "file.read" | "file.write" | "file.delete" | "file.rename",
    resourcePath: string | null,
    metadata?: Record<string, unknown>,
  ): Promise<void> {
    return this.ctx.emitAuditEvent(action, resourcePath, metadata);
  }

  private log(message: string): void {
    this.ctx.log(message);
  }

  private logError(message: string, error: unknown): void {
    this.ctx.logError(message, error);
  }

  // Local At-Rest Cipher
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Provisions or unlocks the on-disk at-rest cipher. The wrapped LAK lives
   * in `data.json` under `wrappedLak` so it survives Obsidian restarts and
   * never leaks into the synced vault folder. Surface failures as a Notice
   * rather than throwing — a failed init must not block plugin loading,
   * because the user might need to log in to recover.
   */
  async initAtRestCipher(): Promise<void> {
    // The wrapped LAK lives in a sidecar file inside the plugin folder, not
    // in data.json. Two reasons: (1) data.json is overwritten by
    // savePluginData() with a settings-only object, so any extra key would
    // get clobbered; (2) the LAK envelope is opaque bytes — keeping it out
    // of the human-readable JSON document makes reviews / debugging
    // settings clearer. The plugin folder is already in `isPathExcluded`,
    // so this file never participates in vault sync.
    // Phase 12 (edge #6 / NN-1): when a device PIN owns the LAK, the LAK lives
    // PIN-wrapped in `lak-pin.envelope` and the transparent `lak.envelope` is
    // absent by design. Running the normal init below would see absent-envelope
    // + existing VG1 ciphertext and route to `needs-recovery` — wrong for this
    // flow. We instead construct the cipher, land LOCKED, and await the PIN.
    const pinEnrolled = this.isPinLockEnrolled();

    const pluginId = this.manifest?.id ?? "vaultguard-sync";
    const envelopePath = this.vaultConfigPath("plugins", pluginId, "lak.envelope");
    const adapter = this.app.vault.adapter;
    const protectionStatePath = this.vaultConfigPath(
      "plugins",
      pluginId,
      "at-rest-path-state.v1.json",
    );
    this.atRestProtectionState = new AtRestProtectionStateStore({
      read: async () => {
        if (!(await adapter.exists(protectionStatePath))) return null;
        return adapter.read(protectionStatePath);
      },
      write: async (serialized) => {
        await adapter.write(protectionStatePath, serialized);
      },
    });
    // Force validation now. A malformed/corrupt protection index makes the
    // plaintext-vs-ciphertext decision ambiguous, so cipher initialization
    // must stop before any managed note is read.
    await this.atRestProtectionState.isProtected("__vaultguard_state_probe__");

    // Durable home for the device-local fallback KEK (the key that wraps the LAK
    // when the OS keychain / safeStorage is unavailable — the normal case on
    // mobile). It was historically single-homed in localStorage, which Obsidian
    // mobile does NOT durably persist: the OS evicts the WebView store on
    // backgrounding, the LAK could then no longer be unwrapped, and the user was
    // silently logged out with their files un-decryptable. Mirror it to an
    // adapter file (a sibling of lak.envelope, inside the at-rest-EXCLUDED plugin
    // folder) so eviction can't orphan the LAK. localStorage stays the fast
    // primary; the file is the durable backup. Security note: the durable copy
    // shares lak.envelope's posture — anyone with the plugin folder holds both
    // the KEK and the wrapped LAK. That is the same "file access → decrypt"
    // trade-off a no-PIN / passkey-model device already accepts; users who want
    // more enroll a PIN (PIN-derived key, nothing on disk unwraps the LAK) and
    // requirePinOnStartup removes the transparent envelope entirely, so the
    // durable KEK then wraps nothing decryptable. See docs/AT-REST-ENCRYPTION.md.
    const fallbackKekPath = this.vaultConfigPath("plugins", pluginId, "at-rest-kek.dat");
    const fallbackKekLsKey = "vaultguard.at-rest.kek.v1";

    const localProjectMemoryMode = this.isLocalProjectMemoryModeEnabled();

    if (localProjectMemoryMode) {
      let envelopeExists = false;
      try {
        envelopeExists = await adapter.exists(envelopePath);
      } catch (err) {
        this.logError(`[local-project-memory] Probing at-rest envelope at ${envelopePath} failed`, err);
      }
      const ciphertextExists = this.automaticLocalProjectMemoryPlaintextVerified
        ? false
        : await this.hasAtRestCiphertextOnDisk();
      this.automaticLocalProjectMemoryPlaintextVerified = false;
      if (!envelopeExists) {
        this.atRestCipher = null;
        this.cipherInitPromise = null;
        this.app.workspace.onLayoutReady(() => {
          void this.warnIfLocalProjectMemoryCiphertextPresent();
        });
        this.log(
          ciphertextExists
            ? "Local Project Memory Mode active: VG1 files are present, but no LAK envelope exists; cipher provisioning skipped."
            : "Local Project Memory Mode active: local at-rest cipher provisioning skipped.",
        );
        return;
      }
    }

    // One-time envelope migration after a plugin-id rename. If no envelope
    // exists at the current path but one DOES exist under a historical
    // plugin id, copy it across before AtRestCipher.init() runs so the
    // existing unwrap path picks it up and on-disk VG1 files remain
    // decryptable. See PRIOR_PLUGIN_IDS_FOR_LAK_MIGRATION and commit
    // 9495041 (2026-05-14, vaultguard -> vaultguard-sync).
    //
    // Skipped entirely when a PIN is enrolled: copying a prior-id `lak.envelope`
    // back in would recreate the PIN-free auto-unwrap path NN-1 deliberately
    // removed (a same-OS user could then decrypt without the PIN, defeating D2).
    let envelopeMigrationFailureReason: string | null = null;
    if (!pinEnrolled) try {
      const currentExists = await adapter.exists(envelopePath);
      if (!currentExists) {
        const priorIds = PRIOR_PLUGIN_IDS_FOR_LAK_MIGRATION[pluginId] ?? [];
        for (const priorId of priorIds) {
          const priorPath = this.vaultConfigPath("plugins", priorId, "lak.envelope");
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
                }. Your encrypted files have NOT been overwritten — close Obsidian, copy "${priorPath}" to "${envelopePath}" manually, and reopen.`;
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
      // Provisioning-safe probe: only "absent" (envelope genuinely does not
      // exist) may lead init() to generate a fresh LAK. A read failure, a probe
      // failure, or an existing-but-empty envelope (truncated/crash-damaged)
      // return "error" so init() refuses to overwrite the real key. Collapsing
      // any of these to null via loadWrappedLak() is the data-loss bug this
      // method exists to prevent.
      probeWrappedLak: async () => {
        let exists: boolean;
        try {
          exists = await adapter.exists(envelopePath);
        } catch (err) {
          this.logError(`Probing at-rest envelope existence at ${envelopePath} failed`, err);
          return {
            kind: "error" as const,
            reason: err instanceof Error ? err.message : String(err),
          };
        }
        if (!exists) return { kind: "absent" as const };
        try {
          const raw = await adapter.read(envelopePath);
          if (raw.trim().length === 0) {
            // The file is present but empty — it was never written empty (only
            // saveWrappedLak writes it, always non-empty), so this indicates a
            // truncated/corrupted envelope, NOT first-run.
            return { kind: "error" as const, reason: "envelope file is present but empty" };
          }
          return { kind: "present" as const, blob: raw };
        } catch (err) {
          this.logError(`Reading at-rest envelope at ${envelopePath} failed`, err);
          return {
            kind: "error" as const,
            reason: err instanceof Error ? err.message : String(err),
          };
        }
      },
      // Consulted by init() only when the envelope is absent, before it
      // provisions a fresh LAK. Short-circuits on the first VG1-headed file so
      // a reinstall/fresh-device open (envelope gone, ciphertext intact) routes
      // to recovery instead of orphaning every encrypted note. Non-managed
      // (excluded) paths are skipped — they were never at-rest encrypted.
      hasExistingCiphertext: async () => {
        const readBin = this.originalAdapterMethods.readBinary;
        const managedFiles = this.app.vault
          .getFiles()
          .filter((file) => !this.isAtRestExcluded(file.path));
        if (managedFiles.length === 0) return false;
        if (!readBin) {
          throw new Error(
            "VaultGuard Sync: cannot prove that no encrypted files remain because the vault adapter has no binary reader.",
          );
        }
        for (const file of managedFiles) {
          try {
            const bytes = await readBin(file.path);
            const classification = await this.classifyAtRestBytes(file.path, bytes);
            if (classification.kind === "corrupt-protected") {
              throw new Error(
                `VaultGuard Sync: protected file "${file.path}" has an invalid VG1 envelope (${classification.reason}).`,
              );
            }
            if (classification.kind === "encrypted") {
              await this.rememberAtRestProtected(file.path);
              return true;
            }
          } catch (error) {
            throw new Error(
              `VaultGuard Sync: cannot prove that no encrypted files remain because "${file.path}" could not be inspected: ${boundedErrorMessage(error)}`,
            );
          }
        }
        return false;
      },
      // SD-05-F3: candidate-key validation source for restoreFromRecoveryCode.
      // Fail-closed: the generator THROWS rather than skipping unreadable files.
      listCiphertextForValidation: () => this.iterateCiphertextForValidation(),
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
          throw err;
        }
      },
      loadFallbackKek: async () => {
        // Single "best value" reader used by the WRAP/provision path
        // (getOrCreateFallbackKek). The UNWRAP path uses loadFallbackKekCandidates
        // below, which never triggers a mint — so a transient read here can no
        // longer clobber the real KEK.
        const ls: unknown = this.app.loadLocalStorage(fallbackKekLsKey);
        if (typeof ls === "string" && ls.length > 0) {
          // Repair the durable copy when it is absent OR present-but-empty/torn (a
          // partial adapter.write). Guarding on `!exists` alone left a torn file
          // latent until the next eviction. Do NOT overwrite a present, NON-empty
          // durable value — it may be the authoritative one; the candidate unwrap
          // reconciles any disagreement.
          try {
            let durableUsable = false;
            if (await adapter.exists(fallbackKekPath)) {
              durableUsable = (await adapter.read(fallbackKekPath)).trim().length > 0;
            }
            if (!durableUsable) {
              await adapter.write(fallbackKekPath, ls);
            }
          } catch (err) {
            this.logError(`Back-filling durable fallback KEK at ${fallbackKekPath} failed`, err);
          }
          return ls;
        }
        // localStorage empty (e.g. mobile eviction after backgrounding) — recover
        // from the durable adapter file and RE-SEED localStorage so subsequent
        // reads take the fast path again.
        try {
          if (await adapter.exists(fallbackKekPath)) {
            const trimmed = (await adapter.read(fallbackKekPath)).trim();
            if (trimmed.length > 0) {
              try {
                this.app.saveLocalStorage(fallbackKekLsKey, trimmed);
              } catch {
                // Re-seed is best-effort; the durable file is authoritative.
              }
              return trimmed;
            }
          }
        } catch (err) {
          this.logError(`Reading durable fallback KEK at ${fallbackKekPath} failed`, err);
        }
        return null;
      },
      loadFallbackKekCandidates: async () => {
        // READ-ONLY: every distinct, non-empty KEK the device can offer. The
        // cipher's unwrap path tries each and NEVER mints — so a transient
        // durable-file read error coincident with an evicted localStorage routes
        // to needs-recovery (retryable) instead of overwriting the real,
        // still-recoverable KEK with a fresh one (permanent data loss).
        const out: string[] = [];
        const push = (v: unknown): void => {
          if (typeof v === "string" && v.trim().length > 0 && !out.includes(v.trim())) {
            out.push(v.trim());
          }
        };
        try {
          push(this.app.loadLocalStorage(fallbackKekLsKey));
        } catch {
          // localStorage unavailable — the durable file may still carry the KEK.
        }
        try {
          if (await adapter.exists(fallbackKekPath)) {
            push(await adapter.read(fallbackKekPath));
          }
        } catch (err) {
          this.logError(`Reading durable fallback KEK candidate at ${fallbackKekPath} failed`, err);
        }
        return out;
      },
      saveFallbackKek: async (kekBase64: string) => {
        // Write BOTH homes: localStorage (fast/common) and the durable adapter
        // file (survives mobile localStorage eviction). The file is what makes
        // the KEK — and therefore the LAK and the persisted session — outlive a
        // background kill.
        let cachedInRenderer = false;
        try {
          this.app.saveLocalStorage(fallbackKekLsKey, kekBase64);
          cachedInRenderer = true;
        } catch (err) {
          this.logError("Persisting fallback KEK to localStorage failed", err);
        }
        try {
          await adapter.write(fallbackKekPath, kekBase64);
        } catch (err) {
          this.logError(`Persisting durable fallback KEK at ${fallbackKekPath} failed`, err);
          // The adapter file is the restart-survival boundary. A renderer-only
          // copy may be evicted on mobile, so never report provisioning success
          // when this write failed. Best-effort removal also avoids leaving a
          // cache entry for a KEK whose wrapped LAK was never durably committed.
          if (cachedInRenderer) {
            try {
              this.app.saveLocalStorage(fallbackKekLsKey, null);
            } catch (cleanupError) {
              this.logError("Rolling back the renderer fallback KEK failed", cleanupError);
            }
          }
          throw new Error(
            `VaultGuard Sync: durable fallback KEK persistence failed at ${fallbackKekPath}.`,
          );
        }
      },
      clearFallbackKek: async () => {
        const failures: unknown[] = [];
        try {
          this.app.saveLocalStorage(fallbackKekLsKey, null);
        } catch (err) {
          failures.push(err);
          this.logError("Removing the renderer fallback KEK failed", err);
        }
        try {
          if (await adapter.exists(fallbackKekPath)) {
            await adapter.remove(fallbackKekPath);
          }
        } catch (err) {
          this.logError(`Removing durable fallback KEK at ${fallbackKekPath} failed`, err);
          // If remove() failed, neutralize the residue so a later re-provision
          // ROTATES the device KEK instead of silently reusing the old one. An
          // empty file reads as "absent" everywhere (candidates skip it,
          // loadFallbackKek returns null → getOrCreateFallbackKek mints fresh).
          try {
            await adapter.write(fallbackKekPath, "");
          } catch (wipeErr) {
            failures.push(wipeErr);
            this.logError(`Neutralizing durable fallback KEK at ${fallbackKekPath} failed`, wipeErr);
          }
          failures.push(err);
        }
        if (failures.length > 0) {
          throw new Error(
            `VaultGuard Sync: fallback KEK cleanup failed on ${failures.length} storage operation(s).`,
          );
        }
      },
    };

    this.atRestCipher = new AtRestCipher(storage);

    // Phase 12-07 passkey model: a PIN-enrolled device lands LOCKED only when it
    // CANNOT unlock transparently — i.e. the transparent `lak.envelope` is absent
    // (legacy PIN-only device, or a corrupt/unreadable wrap) OR the user opted into
    // "Require PIN on startup" (max-security / true D2). When the transparent wrap is
    // present and the toggle is off, fall through to cipher.init() below so the LAK
    // unwraps transparently and the vault lands UNLOCKED — no PIN prompt after a
    // login / app start; the PIN is then only the fast idle re-lock.
    //
    // Probe via storage.probeWrappedLak() (not a bare exists): 'present' = a valid
    // wrap → transparent unlock; 'absent' OR 'error' (corrupt/unreadable) → land
    // LOCKED and let the PIN unlock, which self-heals the wrap via the unlockWithPin
    // passkey migration. Landing LOCKED still skips cipher.init(), so the "absent
    // envelope + VG1 ciphertext → needs-recovery" misroute never fires for a PIN
    // device (edge #6 preserved).
    let transparentWrapPresent = false;
    if (pinEnrolled) {
      try {
        // Prefer the careful probe (distinguishes a valid wrap from a corrupt/empty
        // one → 'error' lands LOCKED so the PIN self-heals it); fall back to a bare
        // existence check if the seam doesn't expose probeWrappedLak.
        transparentWrapPresent = storage.probeWrappedLak
          ? (await storage.probeWrappedLak()).kind === "present"
          : await adapter.exists(envelopePath);
      } catch (err) {
        this.logError(
          "Probing the transparent LAK wrap for the PIN landing decision failed",
          err
        );
        transparentWrapPresent = false; // fall back to the PIN unlock (self-heals)
      }
    }
    const requirePinOnStartup = this.settings.requirePinOnStartup === true;
    const landLocked = pinEnrolled && (!transparentWrapPresent || requirePinOnStartup);
    if (landLocked) {
      this.locked = true;
      this.log(
        `AtRestCipher: PIN enrolled — landing LOCKED, awaiting unlock (${
          requirePinOnStartup ? "require-PIN-on-startup" : "no transparent wrap"
        }).`
      );
      return;
    }

    // If the envelope migration found a sibling but failed to copy it,
    // short-circuit BEFORE running init(). Running init() now would see no
    // envelope and silently generate a fresh LAK, which is the exact failure
    // mode this migration block exists to prevent.
    if (envelopeMigrationFailureReason !== null) {
      const reason = envelopeMigrationFailureReason;
      this.app.workspace.onLayoutReady(() => {
        this.showAtRestRecoveryBanner(reason);
        // Re-assert the persistent status bar + sidebar now that layout exists.
        this.ctx.refreshAtRestRecoverySurfaces?.();
      });
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
        if (status.kind === "needs-recovery" && pinEnrolled) {
          // P1a: a failed transparent unwrap is NOT the end of the road when a
          // PIN is enrolled — the PIN envelope (lak-pin.envelope) is an
          // INDEPENDENT wrap that can still recover the LAK. The landing probe
          // above is presence-only: it can't tell a decryptable transparent wrap
          // from an orphaned one (e.g. both fallback-KEK homes were lost), so it
          // may have taken the transparent path and dead-ended here. Route to the
          // PIN instead: transition the cipher to LOCKED (fail-closed, awaiting
          // unlock) rather than raising the needs-recovery banner, so a PIN
          // unlock can recover the LAK and self-heal the wrap. ("disabled" is a
          // different failure the PIN can't fix — it falls through below.)
          this.atRestCipher.lock();
          this.locked = true;
          this.log(
            "AtRestCipher: transparent unwrap failed but a PIN is enrolled — landing LOCKED for PIN recovery instead of needs-recovery."
          );
          return;
        }
        if (status.kind === "needs-recovery") {
          // Defer the banner until layout is ready — the recovery flow
          // routes through the settings tab, which doesn't exist yet at
          // this point in onload.
          this.app.workspace.onLayoutReady(() => {
            this.showAtRestRecoveryBanner(status.reason);
            // Re-assert the persistent status bar + sidebar surfaces so init
            // landing in needs-recovery no longer leaves them blind (the gap
            // that let the failure stay silent until Settings → Advanced).
            this.ctx.refreshAtRestRecoverySurfaces?.();
          });
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
      try {
        await this.seedAtRestProtectionState();
      } catch (error) {
        this.logError("Seeding durable at-rest protection state failed", error);
        this.app.workspace.onLayoutReady(() => {
          new Notice(
            "VaultGuard Sync: protected-file integrity state could not be fully updated. Encrypted bytes were preserved; restart after checking vault storage access.",
            10000,
          );
        });
      }
      if (Platform.isMobileApp && this.settings.debugLogging) {
        const ready = status.kind === "unlocked";
        new Notice(
          `VaultGuard diag: at-rest method=${method}, ready=${ready}`,
          5000
        );
      }
      if (method === "localstorage-fallback" && !Platform.isMobileApp) {
        new Notice(
          "VaultGuard Sync: at-rest encryption is using the vault-local fallback (OS keychain unavailable). Files in Finder are encrypted, but a full Electron-profile theft can recover the key. See docs/AT-REST-ENCRYPTION.md.",
          10000
        );
      }
      // First-run nudge: if we just provisioned a fresh LAK and there are
      // plaintext files on disk, the user almost certainly wants them
      // encrypted (they enabled the plugin). One Notice with a clear CTA;
      // we don't auto-encrypt without consent because some users keep
      // local-only vaults and may not want VaultGuard touching every file.
      this.app.workspace.onLayoutReady(() => {
        if (this.isLocalProjectMemoryModeEnabled()) {
          void this.warnIfLocalProjectMemoryCiphertextPresent();
          return;
        }
        void this.maybeOfferFirstRunMigration();
      });
    } catch (err) {
      this.logError("AtRestCipher init threw", err);
    }
  }

  private async hasAtRestCiphertextOnDisk(): Promise<boolean> {
    const found = await this.findAtRestCiphertextFiles({ limit: 1 });
    return found.length > 0;
  }

  /**
   * One-time/ongoing migration for vaults encrypted before the durable
   * protected-path index existed. Intact VG1 paths are hashed and persisted in
   * one write. Unreadable files do not block cipher use, but the failure is
   * surfaced because those paths cannot yet gain the corruption guard.
   */
  private async seedAtRestProtectionState(): Promise<void> {
    const state = this.atRestProtectionState;
    if (!state) return;
    if (await state.isMigrationComplete()) return;
    const managedFiles = this.app.vault
      .getFiles()
      .filter((file) => !this.isAtRestExcluded(file.path));
    if (managedFiles.length === 0) return;
    const readBin = this.originalAdapterMethods.readBinary;
    if (!readBin) {
      throw new Error("the vault adapter has no binary reader");
    }

    const protectedPaths: string[] = [];
    let failed = 0;
    for (const file of managedFiles) {
      try {
        const classification = classifyAtRestPayload(await readBin(file.path), false);
        if (classification.kind === "encrypted") protectedPaths.push(file.path);
      } catch {
        failed += 1;
      }
    }
    if (failed > 0) {
      await state.markProtectedMany(protectedPaths);
      throw new Error(`${failed} managed file(s) could not be inspected`);
    }
    await state.completeMigration(protectedPaths);
  }

  private async findAtRestCiphertextFiles(
    options: { limit?: number; failClosed?: boolean } = {},
  ): Promise<string[]> {
    const readBin = this.originalAdapterMethods.readBinary;
    const failClosed = options.failClosed !== false;
    if (!readBin) {
      if (failClosed) {
        throw new Error(
          "VaultGuard Sync: cannot inspect protected local files because the vault adapter has no binary reader.",
        );
      }
      return [];
    }
    const limit = options.limit ?? Number.POSITIVE_INFINITY;
    const paths: string[] = [];
    for (const file of this.app.vault.getFiles()) {
      try {
        const bytes = await readBin(file.path);
        const classification = await this.classifyAtRestBytes(file.path, bytes);
        if (classification.kind === "encrypted") {
          await this.rememberAtRestProtected(file.path);
          paths.push(file.path);
          if (paths.length >= limit) break;
        } else if (classification.kind === "corrupt-protected") {
          paths.push(file.path);
          if (paths.length >= limit) break;
        }
      } catch (error) {
        if (failClosed) {
          throw new Error(
            `VaultGuard Sync: protected-file inspection failed for "${file.path}": ${boundedErrorMessage(error)}`,
          );
        }
      }
    }
    return paths;
  }

  async warnIfLocalProjectMemoryCiphertextPresent(): Promise<void> {
    if (!this.isLocalProjectMemoryModeEnabled()) return;
    const paths = await this.findAtRestCiphertextFiles({ limit: 20, failClosed: false });
    if (paths.length === 0) return;
    const doc = getActiveObsidianDocument();
    if (!doc) {
      new Notice(
        `VaultGuard Sync: Local Project Memory Mode is active, but ${paths.length} encrypted VG1 file(s) were detected. Open VaultGuard settings and run "Decrypt vault and disable at-rest encryption".`,
        12000,
      );
      return;
    }
    const notice = new Notice("", 0);
    const frag = doc.createDocumentFragment();
    const strong = frag.createEl("strong");
    strong.setText("VaultGuard Sync: encrypted repo files detected. ");
    frag.appendText(
      `Local Project Memory Mode will not encrypt more files, but ${paths.length} VG1 file(s) still need recovery. `,
    );
    const link = frag.createEl("a", {
      text: "Open settings to decrypt →",
      cls: "vaultguard-notice-link",
    });
    link.addEventListener("click", () => {
      notice.hide();
      this.openVaultGuardSettings();
    });
    notice.setMessage(frag);
  }

  /**
   * Once per plugin process: if the vault still has plaintext files
   * (typical right after install) surface a Notice with an "Encrypt now"
   * link to the settings tab. Throttled by a settings flag so users who
   * dismiss it don't get pestered every reload.
   */
  async maybeOfferFirstRunMigration(): Promise<void> {
    if (this.atRestFirstRunOffered) return;
    this.atRestFirstRunOffered = true;
    if (this.isLocalProjectMemoryModeEnabled()) return;
    if (this.settings.atRestFirstRunDismissed) return;
    if (!this.atRestCipher?.isReady()) return;

    try {
      const tally = await this.tallyAtRestState();
      if (tally.plaintext === 0) return;
      const doc = getActiveObsidianDocument();
      if (!doc) return;
      const notice = new Notice("", 0);
      const frag = doc.createDocumentFragment();
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
  showAtRestRecoveryBanner(reason: string): void {
    const doc = getActiveObsidianDocument();
    if (!doc) return;
    // W2: keep the handle in a field (hide any prior one first so notices never
    // stack) so recovery via a different door can clear it via
    // clearAtRestRecoveryStickyNotice.
    this.atRestRecoveryNotice?.hide();
    const notice = new Notice("", 0);
    this.atRestRecoveryNotice = notice;
    const frag = doc.createDocumentFragment();
    const strong = frag.createEl("strong");
    strong.setText("VaultGuard Sync: cannot read encrypted files on this device. ");
    frag.appendText(reason + " ");
    const link = frag.createEl("a", {
      text: "Open settings to restore →",
      cls: "vaultguard-notice-link",
    });
    link.addEventListener("click", () => {
      // Route through the plugin's single recovery indirection (interim →
      // Settings → Advanced; 13-03 swaps only that body). Hide on click too.
      this.clearAtRestRecoveryStickyNotice();
      this.ctx.startAtRestRecoveryFlow?.();
    });
    notice.setMessage(frag);
  }

  /** W2: hide + drop the init-time sticky recovery notice. */
  clearAtRestRecoveryStickyNotice(): void {
    this.atRestRecoveryNotice?.hide();
    this.atRestRecoveryNotice = null;
  }

  /**
   * Walk the entire vault and rewrite each file as at-rest ciphertext.
   *
   * Safe to invoke repeatedly — files that already start with the at-rest
   * magic header are skipped. Excluded paths (config folder, trash, plugin
   * folder) are never touched. Used for a one-shot migration of legacy
   * plaintext vaults; ongoing writes are encrypted automatically by the
   * adapter interceptor.
   */
  async encryptVaultAtRest(): Promise<void> {
    if (this.isLocalProjectMemoryModeEnabled()) {
      new Notice(
        "VaultGuard Sync: encryption is disabled in Local Project Memory Mode. Files will remain plaintext.",
        8000,
      );
      return;
    }
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
    let processed = 0;
    let processedBytes = 0;
    const workload = summarizeFileLikeWorkload(files);
    const guard = evaluateWorkloadGuard(workload);
    const warning = guard.warnings.join(" ");

    let operation: LongOperationHandle;
    try {
      operation = this.ctx.beginLongOperation({
        kind: "vault-encrypt",
        operationName: "Encrypt vault at rest",
        phase: "Preparing local encryption pass",
        placement: "protected",
        totalItems: files.length,
        totalBytes: workload.totalBytes,
        warning: warning || undefined,
        capabilities: {
          protectedPhase: true,
          canCancel: false,
          canPause: false,
        },
        conflictsWith: ["vault-decrypt", "sync", "background-sync", "initial-reconciliation"],
        stalledAfterMs: DEFAULT_STALLED_OPERATION_MS,
      });
    } catch (error) {
      if (isLongOperationConflict(error)) {
        new Notice(`VaultGuard Sync: ${describeConflict(error.conflict)}`, 6000);
        return;
      }
      throw error;
    }

    if (!guard.ok) {
      operation.fail(new Error(guard.error ?? "VaultGuard workload guard blocked encryption."));
      new Notice(guard.error ?? "VaultGuard Sync: encryption blocked by workload guard.", 10000);
      return;
    }

    try {
      await processInBatches(
        files,
        async (file) => {
          if (this.isAtRestExcluded(file.path)) {
            skipped += 1;
            processed += 1;
            processedBytes += file.stat?.size ?? 0;
            operation.update({
              phase: "Encrypting local files",
              processedItems: processed,
              processedBytes,
              message: `${encrypted} encrypted, ${skipped} skipped, ${failed} failed.`,
            });
            return;
          }

          try {
            const bytes = await readBin(file.path);
            const classification = await this.classifyAtRestBytes(file.path, bytes);
            if (classification.kind === "corrupt-protected") {
              throw this.corruptProtectedReadError(file.path, classification.reason);
            }
            if (classification.kind === "encrypted") {
              await this.rememberAtRestProtected(file.path);
              skipped += 1;
              processed += 1;
              processedBytes += file.stat?.size ?? bytes.byteLength;
              operation.update({
                phase: "Encrypting local files",
                processedItems: processed,
                processedBytes,
                message: `${encrypted} encrypted, ${skipped} skipped, ${failed} failed.`,
              });
              return;
            }
            const ct = await cipher.encryptBinary(bytes);
            await writeBin(file.path, ct);
            await this.rememberAtRestProtected(file.path);
            encrypted += 1;
            processed += 1;
            processedBytes += file.stat?.size ?? bytes.byteLength;
          } catch (err) {
            failed += 1;
            processed += 1;
            processedBytes += file.stat?.size ?? 0;
            this.logError(`At-rest encrypt: failed for "${file.path}"`, err);
          }

          operation.update({
            phase: "Encrypting local files",
            processedItems: processed,
            processedBytes,
            message: `${encrypted} encrypted, ${skipped} skipped, ${failed} failed.`,
          });
        },
        {
          batchSize: DEFAULT_LONG_OPERATION_BATCH_SIZE,
          token: operation.token,
        },
      );
      operation.complete(
        `${encrypted} encrypted, ${skipped} already encrypted or excluded, ${failed} failed.`,
      );
      new Notice(
        `VaultGuard Sync: at-rest encryption pass complete. ${encrypted} encrypted, ${skipped} already-encrypted/excluded, ${failed} failed.`,
        8000
      );
    } catch (error) {
      operation.fail(error);
      new Notice(
        `VaultGuard Sync: at-rest encryption failed — ${
          error instanceof Error ? error.message : "Unknown error"
        }`,
        10000,
      );
    }
  }

  /**
   * Guarded local-cache reset — the wipe-then-provision half of the phase's
   * escape hatch from `needs-recovery` (Phase 13-02, decision D1).
   *
   * Enumerate every on-disk VG1 ciphertext file and remove it via the RAW
   * `originalAdapterMethods.remove`, clear the stale key material
   * (wrapped LAK + fallback KEK), then re-run `initAtRestCipher()` so its
   * fresh-provision path (envelope absent + no VG1 ciphertext + no PIN) mints a
   * NEW LAK and lands `unlocked`. The caller (plugin) must have disabled the PIN
   * BEFORE calling this — otherwise init lands LOCKED, not unlocked (D2).
   *
   * ── AT-REST RULE EXCEPTION (documented) ──────────────────────────────────────
   * This method contains the SINGLE sanctioned direct use of
   * `originalAdapterMethods.remove`. Everywhere else, vault content is touched
   * ONLY through readPlainFromDisk / writePlainToDisk (the CLAUDE.md at-rest
   * rule). The raw remove is REQUIRED here because the intercepted delete
   * (`interceptedDelete`) tombstones the path AND issues a server
   * `DELETE /files/…`, which would destroy the AUTHORITATIVE server copy — the
   * exact opposite of recovery. The raw remove deletes ONLY the local disk file.
   * The plugin sets `resettingLocalCache` + pauses the sync loop around this call
   * so the `vault.on('delete')` listeners can't propagate a deletion either.
   * DO NOT "fix" this back to interceptedDelete / readPlainFromDisk.
   *
   * Returns the wiped paths so the caller can settle Obsidian's TFile index
   * before reconciliation — a lingering just-deleted path would be SY6
   * unreadable-skipped and never re-pulled (threat T-13-06).
   *
   * Safety net (threat T-13-05): the fresh LAK is minted ONLY by
   * initAtRestCipher's backstop, which refuses to provision while readable VG1
   * ciphertext survives. So an INCOMPLETE wipe routes back to `needs-recovery`
   * rather than orphaning readable data under a brand-new key.
   */
  async wipeAndReprovisionLocalAtRest(): Promise<{ wipedPaths: string[] }> {
    // AT-REST RULE EXCEPTION (see method doc): the raw remove captured here is
    // the ONE sanctioned direct originalAdapterMethods.remove — it bypasses
    // interceptedDelete's server DELETE. DO NOT route this through the helpers.
    const remove = this.originalAdapterMethods.remove;
    if (!remove) {
      // No raw remove capability → we cannot safely wipe. Refuse WITHOUT
      // clearing key material or reprovisioning: minting a fresh LAK over the
      // surviving ciphertext would orphan it (threat T-13-05).
      throw new Error(
        "VaultGuard Sync: cannot reset at-rest encryption — the vault adapter has no raw remove capability.",
      );
    }

    const ciphertextPaths = await this.findAtRestCiphertextFiles();

    let operation: LongOperationHandle;
    try {
      operation = this.ctx.beginLongOperation({
        kind: "at-rest-reset",
        operationName: "Reset local at-rest encryption",
        phase: "Removing unreadable local ciphertext",
        placement: "protected",
        totalItems: ciphertextPaths.length,
        capabilities: {
          protectedPhase: true,
          canCancel: false,
          canPause: false,
        },
        // Never overlap a sync / reconcile / (de)encrypt pass — they read or
        // rewrite the same files the wipe is removing.
        conflictsWith: [
          "vault-encrypt",
          "vault-decrypt",
          "sync",
          "background-sync",
          "initial-reconciliation",
        ],
        stalledAfterMs: DEFAULT_STALLED_OPERATION_MS,
      });
    } catch (error) {
      if (isLongOperationConflict(error)) {
        new Notice(`VaultGuard Sync: ${describeConflict(error.conflict)}`, 6000);
      }
      throw error;
    }

    const wipedPaths: string[] = [];
    try {
      let processed = 0;
      let failed = 0;
      await processInBatches(
        ciphertextPaths,
        async (path) => {
          processed += 1;
          // Excluded paths (plugin config, workspace.json, …) were never at-rest
          // encrypted — never touch them.
          if (this.isAtRestExcluded(path)) {
            operation.update({ processedItems: processed });
            return;
          }
          try {
            // ⚠ AT-REST RULE EXCEPTION (see method doc): the ONE sanctioned direct
            // raw remove. Bypasses interceptedDelete's server DELETE and deletes
            // ONLY the local disk file. The plugin's resettingLocalCache flag +
            // paused sync loop suppress the vault.on('delete') propagation path.
            await remove(path);
            await this.forgetAtRestProtected(path);
            wipedPaths.push(path);
            // SD-07-F4: register in the CROSS-INSTANCE suppression registry the
            // instant the file is gone. The post-wipe bulk registration in the
            // caller is unreachable if this promise is orphaned by a hot reload
            // or aborted at unload. Only after a SUCCESSFUL remove: a failed
            // remove leaves the file on disk, so a later delete event for it is
            // genuine and must propagate.
            this.ctx.recordWipedPathAwaitingRepull?.(path);
          } catch (err) {
            failed += 1;
            this.logError(`At-rest reset: failed to remove "${path}"`, err);
          }
          operation.update({
            processedItems: processed,
            message: `${wipedPaths.length} removed, ${failed} failed.`,
          });
        },
        {
          batchSize: DEFAULT_LONG_OPERATION_BATCH_SIZE,
          token: operation.token,
        },
      );

      // Clear the stale key material: locks the cipher, clears the wrapped LAK
      // envelope AND the fallback KEK. The dead LAK is discarded — there is
      // nothing recoverable to preserve.
      await this.atRestCipher?.reset();

      // Re-provision. With the envelope cleared, all VG1 gone, and the PIN
      // disabled by the plugin BEFORE this call, init takes the fresh-provision
      // path → `unlocked`. An incomplete wipe routes back to needs-recovery.
      await this.initAtRestCipher();

      operation.complete(`${wipedPaths.length} removed, ${failed} failed.`);
    } catch (error) {
      operation.fail(error);
      throw error;
    }

    return { wipedPaths };
  }

  /**
   * Walk the vault and rewrite each at-rest-encrypted file back to
   * plaintext. Mirror of `encryptVaultAtRest`. Use before disabling the
   * plugin if you want the vault folder to remain readable through normal
   * tools.
   */
  async decryptVaultAtRest(): Promise<void> {
    await this.decryptVaultAtRestAndDisableEncryption();
  }

  async decryptVaultAtRestAndDisableEncryption(): Promise<AtRestDecryptAndDisableResult> {
    if (!this.atRestCipher?.isReady() || !this.originalAdapterMethods.readBinary || !this.originalAdapterMethods.writeBinary) {
      const remaining = await this.findAtRestCiphertextFiles();
      if (remaining.length === 0) {
        this.settings.localProjectMemoryMode = true;
        this.settings.localProjectMemoryModeAutoEnableSuppressed = false;
        this.settings.atRestFirstRunDismissed = true;
        await this.saveSettings();
        new Notice("VaultGuard Sync: at-rest encryption disabled; no VG1 files were found.", 6000);
        return {
          decrypted: 0,
          skipped: this.app.vault.getFiles().length,
          failed: 0,
          remainingCiphertextPaths: [],
          failures: [],
        };
      }
      const message =
        "VaultGuard Sync: at-rest cipher not initialised — cannot decrypt existing VG1 files.";
      new Notice(message, 10000);
      throw new Error(message);
    }
    const cipher = this.atRestCipher;
    const readBin = this.originalAdapterMethods.readBinary;
    const writeBin = this.originalAdapterMethods.writeBinary;

    const files = this.app.vault.getFiles();
    let decrypted = 0;
    let skipped = 0;
    let failed = 0;
    const failures: Array<{ path: string; error: string }> = [];
    let processed = 0;
    let processedBytes = 0;
    const workload = summarizeFileLikeWorkload(files);
    const guard = evaluateWorkloadGuard(workload);
    const warning = guard.warnings.join(" ");

    let operation: LongOperationHandle;
    try {
      operation = this.ctx.beginLongOperation({
        kind: "vault-decrypt",
        operationName: "Decrypt vault at rest",
        phase: "Preparing local decryption pass",
        placement: "protected",
        totalItems: files.length,
        totalBytes: workload.totalBytes,
        warning: warning || undefined,
        capabilities: {
          protectedPhase: true,
          canCancel: false,
          canPause: false,
        },
        conflictsWith: ["vault-encrypt", "sync", "background-sync", "initial-reconciliation"],
        stalledAfterMs: DEFAULT_STALLED_OPERATION_MS,
      });
    } catch (error) {
      if (isLongOperationConflict(error)) {
        new Notice(`VaultGuard Sync: ${describeConflict(error.conflict)}`, 6000);
        return {
          decrypted: 0,
          skipped: files.length,
          failed: 0,
          remainingCiphertextPaths: [],
          failures: [],
        };
      }
      throw error;
    }

    if (!guard.ok) {
      operation.fail(new Error(guard.error ?? "VaultGuard workload guard blocked decryption."));
      new Notice(guard.error ?? "VaultGuard Sync: decryption blocked by workload guard.", 10000);
      throw new Error(guard.error ?? "VaultGuard workload guard blocked decryption.");
    }

    try {
      await processInBatches(
        files,
        async (file) => {
          try {
            const bytes = await readBin(file.path);
            const classification = await this.classifyAtRestBytes(file.path, bytes);
            if (classification.kind === "corrupt-protected") {
              throw this.corruptProtectedReadError(file.path, classification.reason);
            }
            if (classification.kind !== "encrypted") {
              skipped += 1;
              processed += 1;
              processedBytes += file.stat?.size ?? bytes.byteLength;
              operation.update({
                phase: "Decrypting local files",
                processedItems: processed,
                processedBytes,
                message: `${decrypted} decrypted, ${skipped} skipped, ${failed} failed.`,
              });
              return;
            }
            const plain = await cipher.decryptBinary(bytes);
            await writeBin(file.path, plain);
            await this.forgetAtRestProtected(file.path);
            decrypted += 1;
            processed += 1;
            processedBytes += file.stat?.size ?? bytes.byteLength;
          } catch (err) {
            failed += 1;
            processed += 1;
            processedBytes += file.stat?.size ?? 0;
            failures.push({
              path: file.path,
              error: err instanceof Error ? err.message : String(err),
            });
            this.logError(`At-rest decrypt: failed for "${file.path}"`, err);
          }

          operation.update({
            phase: "Decrypting local files",
            processedItems: processed,
            processedBytes,
            message: `${decrypted} decrypted, ${skipped} skipped, ${failed} failed.`,
          });
        },
        {
          batchSize: DEFAULT_LONG_OPERATION_BATCH_SIZE,
          token: operation.token,
        },
      );
    } catch (error) {
      operation.fail(error);
      throw error;
    }
    const remainingCiphertextPaths = await this.findAtRestCiphertextFiles();
    const verified = remainingCiphertextPaths.length === 0;
    if (verified && failed === 0) {
      // Publish plaintext/LPM mode only after the complete pass and fail-closed
      // final scan prove that no valid or damaged protected payload remains.
      // Until then normal adapter writes continue to use encryption.
      this.settings.localProjectMemoryMode = true;
      this.settings.localProjectMemoryModeAutoEnableSuppressed = false;
      this.settings.atRestFirstRunDismissed = true;
      await this.saveSettings();
      await cipher.reset();
      this.atRestCipher = null;
      this.cipherInitPromise = null;
      this.locked = false;
    }
    operation.complete(
      verified
        ? `${decrypted} decrypted, ${skipped} already plaintext, ${failed} failed.`
        : `${remainingCiphertextPaths.length} VG1 file(s) remain after decrypt.`,
    );
    const remainingSummary = remainingCiphertextPaths.slice(0, 5).join(", ");
    const remainingSuffix =
      remainingCiphertextPaths.length > 5
        ? `; first paths: ${remainingSummary}; ${remainingCiphertextPaths.length - 5} more not shown`
        : remainingSummary.length > 0
          ? `: ${remainingSummary}`
          : "";
    new Notice(
      verified
        ? `VaultGuard Sync: at-rest decryption complete. ${decrypted} decrypted, ${skipped} already plaintext, ${failed} failed. Encryption is now disabled.`
        : `VaultGuard Sync: decryption did not complete; ${remainingCiphertextPaths.length} protected or damaged file(s) remain${remainingSuffix}. Encryption remains enabled so those files cannot be overwritten as plaintext.`,
      verified ? 8000 : 12000,
    );
    return {
      decrypted,
      skipped,
      failed,
      remainingCiphertextPaths,
      failures,
    };
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
  interceptVaultAdapter(): void {
    const adapter = this.app.vault.adapter;

    // SD-07-F5: a fresh interception re-attaches this runtime.
    this.adapterDetached = false;
    this.capturedAdapterMethodNames.clear();

    // Save original methods.
    //
    // SD-07-F5: capture the REAL adapter method, not whatever wrapper happens to
    // be installed. A superseded instance's un-awaited unload tail may still own
    // the adapter here; chaining onto its wrapper leaves this runtime delegating
    // into functions the old runtime is about to null. Every wrapper this plugin
    // installs carries the base it delegates to, so resolveAdapterMethodBase
    // walks back to the true adapter method (a LOOP — A→B→C generations stack).
    // An unwrapped base is NOT re-bound: it was already `.bind(adapter)`-ed by
    // the generation that first captured it, and re-binding would mint a fresh
    // function object per generation.
    const baseRead = resolveAdapterMethodBase(adapter.read) ?? adapter.read.bind(adapter);
    this.originalAdapterMethods.read = baseRead;
    this.capturedAdapterMethodNames.add("read");
    const baseWrite = resolveAdapterMethodBase(adapter.write) ?? adapter.write.bind(adapter);
    this.originalAdapterMethods.write = baseWrite;
    this.capturedAdapterMethodNames.add("write");
    const baseList = resolveAdapterMethodBase(adapter.list) ?? adapter.list.bind(adapter);
    this.originalAdapterMethods.list = baseList;
    this.capturedAdapterMethodNames.add("list");
    const baseRemove = resolveAdapterMethodBase(adapter.remove) ?? adapter.remove.bind(adapter);
    this.originalAdapterMethods.remove = baseRemove;
    this.capturedAdapterMethodNames.add("remove");
    const rawReadBinary = (adapter as unknown as Record<string, unknown>).readBinary;
    if (typeof rawReadBinary === "function") {
      const fn = rawReadBinary as (p: string) => Promise<ArrayBuffer>;
      this.originalAdapterMethods.readBinary = resolveAdapterMethodBase(fn) ?? fn.bind(adapter);
      this.capturedAdapterMethodNames.add("readBinary");
    }
    const rawWriteBinary = (adapter as unknown as Record<string, unknown>).writeBinary;
    if (typeof rawWriteBinary === "function") {
      const fn = rawWriteBinary as (p: string, d: ArrayBuffer) => Promise<void>;
      this.originalAdapterMethods.writeBinary = resolveAdapterMethodBase(fn) ?? fn.bind(adapter);
      this.capturedAdapterMethodNames.add("writeBinary");
    }
    if (typeof adapter.rename === "function") {
      const fn = adapter.rename;
      this.originalAdapterMethods.rename = resolveAdapterMethodBase(fn) ?? fn.bind(adapter);
      this.capturedAdapterMethodNames.add("rename");
    }
    const rawGetResourcePath = (adapter as unknown as Record<string, unknown>).getResourcePath;
    if (typeof rawGetResourcePath === "function") {
      const fn = rawGetResourcePath as (p: string) => string;
      this.originalAdapterMethods.getResourcePath =
        resolveAdapterMethodBase(fn) ?? fn.bind(adapter);
      this.capturedAdapterMethodNames.add("getResourcePath");
    }

    // Intercept read operations. Every install is marked with the base it
    // delegates to (SD-07-F5) so the NEXT generation can unwrap past it.
    this.installedAdapterMethods.read = markAdapterWrapper(
      async (normalizedPath: string): Promise<string> => this.interceptedRead(normalizedPath),
      baseRead,
    );
    adapter.read = this.installedAdapterMethods.read;

    // Intercept write operations
    this.installedAdapterMethods.write = markAdapterWrapper(
      async (normalizedPath: string, data: string): Promise<void> =>
        this.interceptedWrite(normalizedPath, data),
      baseWrite,
    );
    adapter.write = this.installedAdapterMethods.write;

    // Intercept binary read/write so attachments (images, PDFs, ...) also
    // get at-rest decryption/encryption. Without this, every non-text file
    // in the vault would round-trip in plaintext on disk.
    const baseReadBinary = this.originalAdapterMethods.readBinary;
    if (baseReadBinary) {
      this.installedAdapterMethods.readBinary = markAdapterWrapper(
        async (normalizedPath: string): Promise<ArrayBuffer> =>
          this.interceptedReadBinary(normalizedPath),
        baseReadBinary,
      );
      (adapter as unknown as {
        readBinary: (p: string) => Promise<ArrayBuffer>;
      }).readBinary = this.installedAdapterMethods.readBinary;
    }
    const baseWriteBinary = this.originalAdapterMethods.writeBinary;
    if (baseWriteBinary) {
      this.installedAdapterMethods.writeBinary = markAdapterWrapper(
        async (normalizedPath: string, data: ArrayBuffer): Promise<void> =>
          this.interceptedWriteBinary(normalizedPath, data),
        baseWriteBinary,
      );
      (adapter as unknown as {
        writeBinary: (p: string, d: ArrayBuffer) => Promise<void>;
      }).writeBinary = this.installedAdapterMethods.writeBinary;
    }

    // Intercept list operations
    this.installedAdapterMethods.list = markAdapterWrapper(
      async (normalizedPath: string): Promise<{ files: string[]; folders: string[] }> =>
        this.interceptedList(normalizedPath),
      baseList,
    );
    adapter.list = this.installedAdapterMethods.list;

    // Intercept delete operations
    this.installedAdapterMethods.remove = markAdapterWrapper(
      async (normalizedPath: string): Promise<void> => this.interceptedDelete(normalizedPath),
      baseRemove,
    );
    adapter.remove = this.installedAdapterMethods.remove;

    // Intercept rename — without this the server keeps the old name forever
    // (Obsidian renames don't go through write/remove, so the existing
    // interceptors never fire) and the renamed file appears as a duplicate
    // until the user manually deletes the old path.
    const baseRename = this.originalAdapterMethods.rename;
    if (baseRename) {
      this.installedAdapterMethods.rename = markAdapterWrapper(
        async (oldPath: string, newPath: string): Promise<void> =>
          this.interceptedRename(oldPath, newPath),
        baseRename,
      );
      adapter.rename = this.installedAdapterMethods.rename;
    }

    // Intercept getResourcePath so at-rest-encrypted media (images, PDFs, ...)
    // renders. Obsidian's renderer loads media via getResourcePath()→app:// which
    // reads the on-disk bytes directly, bypassing readBinary decryption — without
    // this, encrypted attachments preview as broken. The override is tagged
    // __vaultguard so the preview diagnostic reports interception as active.
    const baseGetResourcePath = this.originalAdapterMethods.getResourcePath;
    if (baseGetResourcePath) {
      const override = markAdapterWrapper(
        ((normalizedPath: string): string =>
          this.interceptedGetResourcePath(normalizedPath)) as ((p: string) => string) & {
          __vaultguard?: boolean;
        },
        baseGetResourcePath,
      );
      override.__vaultguard = true;
      this.installedAdapterMethods.getResourcePath = override;
      (adapter as unknown as { getResourcePath: (p: string) => string }).getResourcePath =
        override;
    }

    this.log("Vault adapter methods intercepted.");
  }

  /**
   * Restores the original vault adapter methods.
   * Called during plugin unload to prevent issues with other plugins.
   *
   * Restores by identity: a method is handed back only while the adapter still
   * holds the wrapper THIS runtime installed. Obsidian does not await
   * `onunload` (`Component.unload()`/`onunload()` are `: void`, and
   * `unloadPlugin` calls `plugin.unload()` un-awaited), so a superseded
   * instance can reach this point after the next instance has already
   * intercepted the adapter. Blind reassignment there would strip live at-rest
   * interception and leave the vault writing plaintext for the rest of the
   * session.
   */
  restoreVaultAdapter(): void {
    const adapter = this.app.vault.adapter;
    const mutableAdapter = adapter as unknown as Record<string, unknown>;
    const superseded: string[] = [];

    const restoreMethod = (name: keyof VaultAdapterOriginalMethods): void => {
      const original = this.originalAdapterMethods[name];
      if (!original) return;
      const installed = this.installedAdapterMethods[name];
      // No recorded wrapper means this runtime never installed one (legacy
      // callers, partial interception) — fall back to the previous behavior.
      if (installed && mutableAdapter[name] !== installed) {
        superseded.push(name);
        return;
      }
      mutableAdapter[name] = original;
    };

    restoreMethod("read");
    restoreMethod("write");
    restoreMethod("readBinary");
    restoreMethod("writeBinary");
    restoreMethod("list");
    restoreMethod("remove");
    restoreMethod("rename");
    restoreMethod("getResourcePath");

    if (superseded.length > 0) {
      this.log(
        `Vault adapter restore skipped for ${superseded.join(", ")}: another VaultGuard instance owns the adapter.`
      );
    }
    this.installedAdapterMethods = emptyAdapterMethods();

    // Revoke every decrypted blob URL so they don't leak past unload.
    this.revokeAllResourcePreviews();

    // SD-07-F5: mark detached BEFORE clearing, so every guard below can tell a
    // released delegate from an adapter that never had the method.
    this.adapterDetached = true;

    this.originalAdapterMethods = {
      read: null,
      write: null,
      readBinary: null,
      writeBinary: null,
      list: null,
      remove: null,
      rename: null,
      getResourcePath: null,
    };
    this.log("Vault adapter methods restored.");
  }

  /**
   * SD-07-F5. A null delegate has two meanings and only one is an error:
   *
   *   - NEVER CAPTURED (a legacy adapter with no writeBinary/rename/…): the
   *     documented silent/no-op behavior is preserved verbatim. See
   *     interceptedWriteBinary's doc contract ("Legacy adapters without
   *     writeBinary retain the existing silent return").
   *   - DETACHED (captured, then cleared by this runtime's restoreVaultAdapter):
   *     a stale caller from a torn-down generation. Reporting success for a write
   *     that cannot reach disk is the SD-07-F5 failure mode itself, so throw.
   *
   * With the unwrap-at-capture fix in place a LIVE generation can never hold a
   * dead delegate, so this only fires for genuinely stale references — an old
   * instance's in-flight async flow calling its own runtime after unload.
   */
  private failIfAdapterDetached(
    method: keyof VaultAdapterOriginalMethods,
    path: string,
  ): void {
    if (!this.adapterDetached) return;
    if (!this.capturedAdapterMethodNames.has(method)) return;
    throw new AtRestAdapterDetachedError(
      `VaultGuard Sync: cannot ${method} "${path}" — this VaultGuard instance has been unloaded and no longer owns the vault adapter. The change was NOT written to disk.`,
    );
  }

  private async readLocalProjectMemoryText(path: string): Promise<string> {
    if (this.originalAdapterMethods.readBinary) {
      const bytes = await this.originalAdapterMethods.readBinary(path);
      const classification = await this.classifyAtRestBytes(path, bytes);
      if (classification.kind === "corrupt-protected") {
        throw this.corruptProtectedReadError(path, classification.reason);
      }
      if (classification.kind === "encrypted") {
        await this.rememberAtRestProtected(path);
        if (this.atRestCipher?.isReady()) {
          return this.atRestCipher.decryptString(bytes);
        }
        throw new Error(
          `VaultGuard Sync: "${path}" is still VG1 ciphertext. Run "Decrypt vault and disable at-rest encryption" before editing this repo-root vault.`,
        );
      }
      return new TextDecoder().decode(bytes);
    }
    if (!this.originalAdapterMethods.read) {
      throw new Error("VaultGuard Sync: vault adapter read method unavailable.");
    }
    return this.originalAdapterMethods.read(path);
  }

  private async readLocalProjectMemoryBinary(path: string): Promise<ArrayBuffer> {
    if (!this.originalAdapterMethods.readBinary) {
      throw new Error("VaultGuard Sync: vault adapter readBinary unavailable.");
    }
    const bytes = await this.originalAdapterMethods.readBinary(path);
    const classification = await this.classifyAtRestBytes(path, bytes);
    if (classification.kind === "corrupt-protected") {
      throw this.corruptProtectedReadError(path, classification.reason);
    }
    if (classification.kind === "encrypted") {
      await this.rememberAtRestProtected(path);
      if (this.atRestCipher?.isReady()) {
        return this.atRestCipher.decryptBinary(bytes);
      }
      throw new Error(
        `VaultGuard Sync: "${path}" is still VG1 ciphertext. Run "Decrypt vault and disable at-rest encryption" before editing this repo-root vault.`,
      );
    }
    return bytes;
  }

  private async writeLocalProjectMemoryText(path: string, data: string): Promise<void> {
    if (!this.originalAdapterMethods.write) {
      this.failIfAdapterDetached("write", path);
      return; // legacy adapter without this method: unchanged silent return
    }
    await this.originalAdapterMethods.write(path, data);
  }

  private async writeLocalProjectMemoryBinary(path: string, data: ArrayBuffer): Promise<void> {
    if (!this.originalAdapterMethods.writeBinary) {
      this.failIfAdapterDetached("writeBinary", path);
      return; // legacy adapter without this method: unchanged silent return
    }
    await this.originalAdapterMethods.writeBinary(path, data);
  }

  /**
   * Permission-checked and decryption-aware file read operation.
   * @param path - Normalized vault-relative file path
   * @returns Decrypted file content
   * @throws Error if the user lacks READ permission
   */
  async interceptedRead(path: string): Promise<string> {
    if (this.isLocalProjectMemoryModeEnabled()) {
      return this.readLocalProjectMemoryText(path);
    }
    if (this.isPathExcluded(path)) {
      if (this.isDetectedGitRepositoryPath(path)) {
        return this.readPlainFromDisk(path);
      }
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
      return this.hostReadPlainFromDisk(path);
    }

    // Phase-8 limited-access primary branch (OD-4): if this path is a known
    // 36-byte VG1 placeholder, hydrate via the server-side decrypt endpoint
    // and replace the on-disk placeholder with LAK-encrypted plaintext.
    if (this.vaultLeaseDenied && this.placeholderPaths.has(path)) {
      const response = await this.readFileDecrypted(path);
      if (response.success && response.data?.decrypted === true) {
        const plaintext = this.decodeBase64Utf8(response.data.content);
        await this.hostWritePlainToDisk(path, plaintext);
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
        return this.hostReadPlainFromDisk(path);
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
            this.hostNotifyCloudDecryptFallback(path);
            await this.emitAuditEvent("file.read", path, {
              source: "cache",
              reason: "decrypt-failed",
            });
            return this.hostReadPlainFromDisk(path);
          }
        }

        if (response.error?.statusCode === 401 || response.error?.statusCode === 403) {
          throw new Error(response.error.message);
        }
      }

      // Fallback to local cached version if offline
      const localContent = await this.hostReadPlainFromDisk(path);

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
            await this.hostWritePlainToDisk(path, plaintext);
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
        return this.hostReadPlainFromDisk(path);
      }
      throw error;
    }
  }

  /**
   * Shows a one-shot Notice when a file is opened without server READ access
   * and the local cached content is wiped. Per-path debounced (60s) so tab
   * restores and re-focus reads don't produce a stampede.
   */
  notifyDeniedLocalWipe(path: string): void {
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
  notifyCloudDecryptFallback(path: string): void {
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
  looksLikeCiphertext(data: string): boolean {
    return (
      data.length >= 4 &&
      data.charCodeAt(0) === 0x56 &&
      data.charCodeAt(1) === 0x47 &&
      data.charCodeAt(2) === 0x31 &&
      data.charCodeAt(3) === 0x00
    );
  }

  hasVg1MagicBytes(data: ArrayBuffer | Uint8Array): boolean {
    const view = data instanceof Uint8Array ? data : new Uint8Array(data);
    return (
      view.length >= 4 &&
      view[0] === 0x56 &&
      view[1] === 0x47 &&
      view[2] === 0x31 &&
      view[3] === 0x00
    );
  }

  /**
   * Binary counterpart of `looksLikeCiphertext`. Prefers the cipher's
   * own header check when available (full length + version validation),
   * falls back to a manual 4-byte magic + version-byte test otherwise.
   */
  looksLikeCiphertextBytes(data: ArrayBuffer | Uint8Array): boolean {
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
  notifyCorruptedWrite(path: string): void {
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
  async interceptedWrite(path: string, data: string): Promise<void> {
    // SD-06-F1 / DECISION 6: capture the local-new probe at the EARLIEST point
    // in the function — before the ciphertext check and therefore before any
    // `await` — so it still describes the vault index as it was *before* this
    // write. Only the online JSON lane below consumes it.
    const existedLocally = this.localFileExistedBeforeWrite(path);
    if (this.looksLikeCiphertext(data)) {
      this.hostNotifyCorruptedWrite(path);
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

    if (this.isLocalProjectMemoryModeEnabled()) {
      await this.writeLocalProjectMemoryText(path, data);
      return;
    }

    if (this.applyingRemoteWrite) {
      await this.hostWritePlainToDisk(path, data);
      return;
    }

    if (this.isPathExcluded(path)) {
      if (this.originalAdapterMethods.write) {
        await this.originalAdapterMethods.write(path, data);
      } else {
        this.failIfAdapterDetached("write", path);
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

    const textBytesView = new TextEncoder().encode(data);
    const textBytes = textBytesView.buffer.slice(
      textBytesView.byteOffset,
      textBytesView.byteOffset + textBytesView.byteLength,
    ) as ArrayBuffer;
    if (textBytes.byteLength > BINARY_SYNC_MAX_BYTES) {
      const hash = await this.computeHashBytes(textBytes);
      const baseVersionId = this.getExpectedVersionId(path);
      const canUploadNow =
        this.shouldUploadChangesImmediately() &&
        this.isOnline() &&
        Boolean(this.keyLease) &&
        Boolean(this.ctx.uploadLargeEncryptedFile);
      if (canUploadNow) {
        try {
          const result = await this.ctx.uploadLargeEncryptedFile!(
            path,
            textBytes,
            "text/markdown",
            baseVersionId,
          );
          this.recordDirectWrite(path, hash, result);
          await this.hostWritePlainToDisk(path, data);
          await this.ctx.clearPendingLargeFile?.(path);
          await this.emitAuditEvent("file.write", path, {
            directTransfer: true,
            bytes: textBytes.byteLength,
          });
          this.syncState.pendingChanges++;
          this.updateStatusBar();
          return;
        } catch (error) {
          if (this.isNetworkError(error)) this.setConnectionStatus("offline");
          if (this.originalAdapterMethods.write) {
            await this.originalAdapterMethods.write(path, data);
          } else {
            this.failIfAdapterDetached("write", path);
          }
          await this.markLargeFilePending(
            path,
            textBytes,
            "text/markdown",
            /conflict|409/i.test(String(error)) ? "conflict" : "upload-failed",
          );
          new Notice(
            `VaultGuard Sync: Saved "${path}" locally. Its large encrypted upload is pending and can be retried from the VaultGuard sidebar.`,
            10000,
          );
          this.updateStatusBar();
          return;
        }
      }

      if (this.originalAdapterMethods.write) {
        await this.originalAdapterMethods.write(path, data);
      } else {
        this.failIfAdapterDetached("write", path);
      }
      const reason: PendingLargeFileRecord["reason"] = !this.isOnline()
        ? "offline"
        : !this.keyLease
          ? "lease-unavailable"
          : "manual-sync";
      await this.markLargeFilePending(path, textBytes, "text/markdown", reason);
      new Notice(
        `VaultGuard Sync: Saved "${path}" locally. Its large encrypted upload is pending.`,
        8000,
      );
      this.syncState.pendingChanges++;
      this.updateStatusBar();
      return;
    }

    const hash = await this.computeHash(data);
    const baseVersionId = this.getExpectedVersionId(path);

    try {
      // In manual mode, defer remote writes until the user runs a sync explicitly.
      if (this.shouldUploadChangesImmediately() && this.isOnline() && this.keyLease) {
        const encrypted = await this.encryptContent(data);
        // SD-06-F1: resolved ONCE so the 409 branch below can route on the
        // intent this write actually DECLARED, rather than re-deriving it after
        // the round trip (the store may have moved in between).
        const writeIntent = this.resolveWriteIntent(path, existedLocally);
        const declaredCreate = writeIntent?.kind === "must-be-absent";
        const response = await this.apiRequest<RemoteFileWriteResponse>(
          "PUT",
          this.vaultPath(`/files/${encodeURIComponent(path)}`),
          // SD-06-F1: declare what we know. `expectedVersionId` stays as the
          // DECISION 5 fallback — if the ctx predates resolveMutationIntent the
          // intent is undefined and buildWriteBody's legacy derivation produces
          // today's exact body rather than dropping the guard.
          this.buildWriteBody(path, encrypted, hash, {
            expectedVersionId: baseVersionId,
            intent: writeIntent,
            lane: "online-text",
          })
        );

        if (!response.success) {
          if (response.error?.statusCode === 409) {
            // SD-06-F1 / DECISION 1 — a create-409 must NEVER lose the bytes.
            // For an UPDATE the old content is already on disk, so "leave the
            // local file untouched" preserves it. For a CREATE there is no
            // local file yet (Obsidian's vault.create() calls adapter.write()
            // first), so returning without writing means the user's brand-new
            // note exists nowhere. Persist first, then route — every outcome
            // below then operates on a file that survives.
            //
            // Gated on the DECLARED intent, so update-409 behavior is
            // byte-identical to today.
            if (declaredCreate) {
              await this.hostWritePlainToDisk(path, data);
            }
            const resolution = await this.handleRemoteWriteConflict(
              path,
              data,
              baseVersionId,
              { createConflict: declaredCreate },
            );
            if (resolution === "keep-local") {
              await this.hostWritePlainToDisk(path, data);
              await this.emitAuditEvent("file.write", path);
              this.updateStatusBar();
            } else if (resolution === "converged") {
              // DECISION 2: both devices created the same bytes. This is a
              // successful write, so it runs the same tail as the success path
              // — no conflict was recorded and none should be implied.
              await this.emitAuditEvent("file.write", path);
              this.syncState.pendingChanges++;
              this.updateStatusBar();
            }
            return;
          }

          if (response.error?.statusCode === 401 || response.error?.statusCode === 403) {
            throw new Error(response.error.message);
          }

          // AC-API1: queue only TRANSIENT failures (network / 5xx / 429) for
          // replay. A permanent 4xx (413 note-too-large, 409) can never
          // succeed on retry — queuing it used to jam the offline flush.
          const status = response.error?.statusCode ?? 0;
          if (status === 0 || status === 429 || status >= 500) {
            if (status === 0) this.setConnectionStatus("offline");
            this.queueOfflineOperation("write", path, data, {
              baseVersionId,
              baseHash: hash,
            });
          } else {
            throw new Error(response.error?.message ?? "Remote write failed.");
          }
        } else {
          this.recordSuccessfulWrite(path, hash, response);
        }

        await this.hostWritePlainToDisk(path, data);
      } else {
        await this.hostWritePlainToDisk(path, data);
        this.queueOfflineOperation("write", path, data, {
          baseVersionId,
          baseHash: hash,
        });
      }

      await this.emitAuditEvent("file.write", path);
      this.syncState.pendingChanges++;
      this.updateStatusBar();
    } catch (error) {
      if (this.isNetworkError(error)) {
        this.setConnectionStatus("offline");
        await this.hostWritePlainToDisk(path, data);
        this.queueOfflineOperation("write", path, data, {
          baseVersionId,
          baseHash: hash,
        });
      } else {
        throw error;
      }
    }
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Local at-rest read/write helpers
  // ─────────────────────────────────────────────────────────────────────────

  private async classifyAtRestBytes(
    path: string,
    bytes: ArrayBuffer | Uint8Array,
  ): Promise<AtRestPayloadClassification> {
    const durablyProtected = (await this.atRestProtectionState?.isProtected(path)) ?? false;
    return classifyAtRestPayload(bytes, durablyProtected);
  }

  private async rememberAtRestProtected(path: string): Promise<void> {
    await this.atRestProtectionState?.markProtected(path);
  }

  private async forgetAtRestProtected(path: string): Promise<void> {
    await this.atRestProtectionState?.clear(path);
  }

  private corruptProtectedReadError(path: string, reason: string): Error {
    return new Error(
      `VaultGuard Sync: refusing to read "${path}" because durable at-rest state says it is protected but its VG1 envelope is damaged (${reason}). Restore a known-good version or use the recovery workflow; the bytes were preserved.`,
    );
  }

  /**
   * Read a vault-relative file from local disk and return its plaintext.
   *
   * If the bytes on disk start with the at-rest magic header, decrypt with
   * the LAK. Otherwise, treat bytes as legacy plaintext only when durable
   * protection state does not say the path was VG1-protected. Excluded paths
   * (plugin self, Obsidian internals) are passed through unchanged because
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
  isAtRestExcluded(path: string): boolean {
    if (this.isLocalProjectMemoryModeEnabled()) return true;
    if (this.isDetectedGitRepositoryPath(path)) return true;
    const normalized = path.replace(/^\/+/, "");
    if (!normalized) return false;
    const configDir = this.normalizeVaultPath(this.app.vault.configDir);
    if (normalized === configDir || normalized.startsWith(`${configDir}/`)) return true;
    if (normalized === ".trash" || normalized.startsWith(".trash/")) return true;
    return this.isPathExcluded(path);
  }

  async readPlainFromDisk(path: string): Promise<string> {
    if (this.isLocalProjectMemoryModeEnabled()) {
      return this.readLocalProjectMemoryText(path);
    }
    const detectedGitRepositoryPath = this.isDetectedGitRepositoryPath(path);
    if (this.isAtRestExcluded(path) && !detectedGitRepositoryPath) {
      if (!this.originalAdapterMethods.read) {
        throw new Error("VaultGuard Sync: vault adapter read method unavailable.");
      }
      return this.originalAdapterMethods.read(path);
    }

    // Prefer readBinary so we can detect the magic header bytes precisely.
    if (this.originalAdapterMethods.readBinary) {
      const bytes = await this.originalAdapterMethods.readBinary(path);
      const classification = await this.classifyAtRestBytes(path, bytes);
      if (classification.kind === "corrupt-protected") {
        throw this.corruptProtectedReadError(path, classification.reason);
      }
      if (classification.kind === "encrypted") {
        await this.rememberAtRestProtected(path);
        // Phase 12 fail-CLOSED (Pitfall 4): a locked vault rejects a managed VG1
        // read IMMEDIATELY — no 10s waitForCipherInit hang, no plaintext
        // fallback. This is intentional fail-CLOSED, distinct from the
        // fail-OPEN decrypt-error path below. Excluded paths already returned
        // above, so the plugin can still read its own config while locked.
        if (this.locked) {
          throw new Error("VaultGuard: vault is locked");
        }
        if (!this.atRestCipher?.isReady()) {
          await this.waitForCipherInit(10_000);
        }
        if (!this.atRestCipher?.isReady()) {
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
    if (await this.atRestProtectionState?.isProtected(path)) {
      throw this.corruptProtectedReadError(path, "binary inspection unavailable");
    }
    if (text.length >= 4) {
      const head = new TextEncoder().encode(text.slice(0, 4));
      if (
        head.length >= 4 &&
        head[0] === 0x56 &&
        head[1] === 0x47 &&
        head[2] === 0x31 &&
        head[3] === 0x00
      ) {
        // Phase 12 fail-CLOSED: a locked vault rejects VG1 content fast, even on
        // this legacy no-readBinary path.
        if (this.locked) {
          throw new Error("VaultGuard: vault is locked");
        }
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
  async waitForCipherInit(timeoutMs: number): Promise<boolean> {
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
  async writePlainToDisk(path: string, data: string): Promise<void> {
    if (this.looksLikeCiphertext(data)) {
      throw new Error(
        `VaultGuard Sync: writePlainToDisk refused for "${path}" — content has VG1 magic header (corrupted-read cascade).`
      );
    }
    if (this.isLocalProjectMemoryModeEnabled()) {
      await this.writeLocalProjectMemoryText(path, data);
      await this.forgetAtRestProtected(path);
      return;
    }
    if (this.isAtRestExcluded(path)) {
      if (!this.originalAdapterMethods.write) {
        this.failIfAdapterDetached("write", path);
        return; // legacy adapter without this method: unchanged silent return
      }
      await this.originalAdapterMethods.write(path, data);
      await this.forgetAtRestProtected(path);
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
      await this.rememberAtRestProtected(path);
      return;
    }
    // AR2: no writeBinary means the ciphertext cannot reach disk intact —
    // write() UTF-8-encodes the string, so every byte >= 0x80 in the
    // fromCharCode round-trip becomes a multi-byte sequence and the stored
    // blob can never decrypt again. Fail closed instead of corrupting; modern
    // Obsidian (desktop + mobile) always exposes writeBinary.
    throw new Error(
      `VaultGuard Sync: cannot write "${path}" — this vault adapter lacks binary writes, and encrypting through a string write would corrupt the file.`
    );
  }

  /**
   * Read raw bytes from disk, decrypting with the LAK when the on-disk
   * format is at-rest-encrypted. Returns plaintext bytes — what every
   * caller who used to call `readBinary` actually wants.
   */
  async readPlainBinaryFromDisk(path: string): Promise<ArrayBuffer> {
    if (!this.originalAdapterMethods.readBinary) {
      throw new Error("VaultGuard Sync: vault adapter readBinary unavailable.");
    }
    if (this.isLocalProjectMemoryModeEnabled()) {
      return this.readLocalProjectMemoryBinary(path);
    }
    const detectedGitRepositoryPath = this.isDetectedGitRepositoryPath(path);
    if (this.isAtRestExcluded(path) && !detectedGitRepositoryPath) {
      return this.originalAdapterMethods.readBinary(path);
    }
    const bytes = await this.originalAdapterMethods.readBinary(path);
    const classification = await this.classifyAtRestBytes(path, bytes);
    if (classification.kind === "corrupt-protected") {
      throw this.corruptProtectedReadError(path, classification.reason);
    }
    if (classification.kind === "encrypted") {
      await this.rememberAtRestProtected(path);
      // Phase 12 fail-CLOSED (Pitfall 4): a locked vault rejects a managed VG1
      // binary read immediately — no 10s wait, no plaintext fallback.
      if (this.locked) {
        throw new Error("VaultGuard: vault is locked");
      }
      if (!this.atRestCipher?.isReady()) {
        await this.waitForCipherInit(10_000);
      }
      if (!this.atRestCipher?.isReady()) {
        throw new Error(
          `VaultGuard Sync: cannot read "${path}" — local at-rest encryption is not ready. Try again in a moment.`
        );
      }
      return this.atRestCipher.decryptBinary(bytes);
    }
    return bytes;
  }

  // ─────────────────────────────────────────────────────────────────────────
  // At-rest media preview (BIN-A): serve decrypted blob URLs for getResourcePath
  // ─────────────────────────────────────────────────────────────────────────

  /** Max decrypted blob URLs kept alive at once (older entries are revoked FIFO). */
  private static readonly RESOURCE_PREVIEW_CAP = 64;

  /**
   * getResourcePath override. Obsidian's renderer loads media from the returned
   * URL directly off disk; for at-rest-encrypted media that would be VG1
   * ciphertext (a broken preview). On a warm-cache hit we return the decrypted
   * `blob:` URL synchronously; on a miss we return the real (ciphertext) URL and
   * kick off an async decrypt that repopulates the cache and swaps the rendered
   * element's src. Non-media, excluded, or not-yet-encrypted paths pass straight
   * through to the original method. Logged out (no cloud session) short-circuits
   * to the ciphertext URL BEFORE the cache lookup — mirroring interceptedRead's
   * `!this.session` guard — so sign-out hides encrypted media even though the
   * local LAK stays ready, and no stale cached blob is served post-logout.
   */
  interceptedGetResourcePath(path: string): string {
    const original = this.originalAdapterMethods.getResourcePath;
    if (!original) return path;
    const originalUrl = original(path);
    if (
      !this.session ||
      !this.atRestCipher?.isReady() ||
      (this.isAtRestExcluded(path) && !this.isDetectedGitRepositoryPath(path)) ||
      !isKnownBinaryExtensionPath(path)
    ) {
      return originalUrl;
    }
    const mtime = this.parseResourceMtime(originalUrl);
    const cached = this.resourcePreviewCache.get(path);
    if (cached && cached.mtime === mtime) {
      return cached.url;
    }
    void this.warmResourcePreview(path, mtime, originalUrl);
    return originalUrl;
  }

  /**
   * Pre-decrypt a media file into the blob cache before its view reads
   * getResourcePath (e.g. on file-open), so standalone image/PDF views get a
   * synchronous cache hit instead of the miss→fallback→swap flash.
   */
  async prewarmResourcePreview(path: string): Promise<void> {
    const original = this.originalAdapterMethods.getResourcePath;
    if (
      !original ||
      !this.session ||
      !this.atRestCipher?.isReady() ||
      (this.isAtRestExcluded(path) && !this.isDetectedGitRepositoryPath(path)) ||
      !isKnownBinaryExtensionPath(path)
    ) {
      return;
    }
    const originalUrl = original(path);
    const mtime = this.parseResourceMtime(originalUrl);
    if (this.resourcePreviewCache.get(path)?.mtime === mtime) return;
    await this.warmResourcePreview(path, mtime, originalUrl);
  }

  /** Extracts the `?<mtime>` cache-buster Obsidian appends to resource URLs. */
  private parseResourceMtime(url: string): string {
    const q = url.indexOf("?");
    return q >= 0 ? url.slice(q + 1) : "";
  }

  /**
   * Decrypts a media file, caches a `blob:` URL for it, and swaps any already-
   * rendered element still pointing at the ciphertext URL. Fails open: on any
   * error the ciphertext fallback stays in place (a broken preview), never a
   * wipe. Dedupes concurrent renders of the same path.
   */
  private async warmResourcePreview(
    path: string,
    mtime: string,
    ciphertextUrl: string
  ): Promise<void> {
    if (this.resourcePreviewInFlight.has(path)) return;
    this.resourcePreviewInFlight.add(path);
    try {
      // Authoritative post-logout decryption choke point: never decrypt media
      // without a cloud session (the finally still clears the in-flight dedupe).
      if (!this.session) return;
      const existing = this.resourcePreviewCache.get(path);
      if (existing?.mtime === mtime) return;
      const bytes = await this.readPlainBinaryFromDisk(path);
      if (existing) {
        try {
          URL.revokeObjectURL(existing.url);
        } catch {
          /* ignore */
        }
        this.resourcePreviewCache.delete(path);
      }
      const url = URL.createObjectURL(
        new Blob([bytes], { type: contentTypeForPath(path) })
      );
      this.resourcePreviewCache.set(path, { url, mtime });
      this.enforceResourcePreviewCap();
      this.refreshRenderedResource(ciphertextUrl, url);
    } catch (err) {
      this.logError(`At-rest preview: could not decrypt "${path}" for rendering`, err);
    } finally {
      this.resourcePreviewInFlight.delete(path);
    }
  }

  /**
   * Swaps the src of any already-rendered element still pointing at the
   * ciphertext resource URL over to the decrypted blob URL, so the broken
   * preview repaints without a manual reload. Scoped to the workspace DOM and
   * guarded so it no-ops when there is no document (tests / headless).
   */
  private refreshRenderedResource(ciphertextUrl: string, blobUrl: string): void {
    try {
      const base = ciphertextUrl.split("?")[0];
      const ws = this.app?.workspace as unknown as { containerEl?: HTMLElement } | undefined;
      const root =
        ws?.containerEl ?? (typeof document !== "undefined" ? document.body : null);
      if (!root || typeof root.querySelectorAll !== "function") return;
      root
        .querySelectorAll("img, video, audio, source, embed, iframe")
        .forEach((el) => {
          const src = el.getAttribute("src");
          if (src && src.split("?")[0] === base) {
            el.setAttribute("src", blobUrl);
          }
        });
    } catch (err) {
      this.logError("At-rest preview: DOM refresh failed", err);
    }
  }

  /** Revokes and drops the cached blob URL for a single path (on delete/rename). */
  private evictResourcePreview(path: string): void {
    const entry = this.resourcePreviewCache.get(path);
    if (!entry) return;
    try {
      URL.revokeObjectURL(entry.url);
    } catch {
      /* ignore */
    }
    this.resourcePreviewCache.delete(path);
  }

  /** Bounds cache memory: revokes the oldest blob URLs once over the cap (FIFO). */
  private enforceResourcePreviewCap(): void {
    while (this.resourcePreviewCache.size > AtRestAdapterRuntime.RESOURCE_PREVIEW_CAP) {
      const oldest = this.resourcePreviewCache.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.evictResourcePreview(oldest);
    }
  }

  /** Revokes every cached blob URL (plugin unload / adapter restore). */
  private revokeAllResourcePreviews(): void {
    for (const entry of this.resourcePreviewCache.values()) {
      try {
        URL.revokeObjectURL(entry.url);
      } catch {
        /* ignore */
      }
    }
    this.resourcePreviewCache.clear();
    this.resourcePreviewInFlight.clear();
  }

  /**
   * Revoke all decrypted media-preview blob URLs. Called on logout/deauth so
   * images/PDFs decrypted during an authenticated session can't linger in an
   * open pane after sign-out. Distinct from the lock path: logout does NOT evict
   * the LAK (files stay readable at rest), so the sync getResourcePath session
   * guard — not cipher readiness — is what stops re-decryption; this call clears
   * the already-decrypted blobs.
   */
  revokeResourcePreviews(): void {
    this.revokeAllResourcePreviews();
  }

  /**
   * Write raw plaintext bytes to disk, encrypting with the LAK before
   * storage. Mirror of `writePlainToDisk` for binary attachments.
   */
  /**
   * Re-encrypts an externally-added plaintext file in place: reads the raw
   * on-disk bytes and, when they are not already VG1, writes the IDENTICAL
   * bytes back through the encrypting write path. The content never changes —
   * only the on-disk representation flips from plaintext to ciphertext. Files
   * written through Obsidian never need this (the adapter interceptors encrypt
   * them); this exists for files that bypass Obsidian entirely: Finder drops,
   * git checkouts, external tools.
   *
   * Files at or below BINARY_SYNC_MAX_BYTES use the JSON sync path. Larger text
   * and binary files use direct transfer. A large externally-added file remains
   * plaintext until the caller proves its encrypted remote copy is durable;
   * otherwise LAK-envelope loss could make the only copy unrecoverable.
   *
   * `isEncrypted` is checked FIRST so a file already carrying the VG1 magic
   * (e.g. one written through the now-unblocked interceptedWriteBinary) is a
   * no-op — no double-encryption hazard. Never throws — background hygiene
   * must not break its callers. Returns true when the file was re-encrypted.
   */
  async ensureAtRestEncryptedInPlace(path: string, remoteDurable = false): Promise<boolean> {
    const readBin = this.originalAdapterMethods.readBinary;
    if (this.isLocalProjectMemoryModeEnabled()) return false;
    if (!readBin || !this.atRestCipher?.isReady()) return false;
    if (this.isAtRestExcluded(path)) return false;
    if (this.inPlaceEncryptionInFlight.has(path)) return false;
    this.inPlaceEncryptionInFlight.add(path);
    try {
      const bytes = await readBin(path);
      // isEncrypted FIRST (research §5): an already-VG1 file is a no-op.
      const classification = await this.classifyAtRestBytes(path, bytes);
      if (classification.kind === "corrupt-protected") {
        throw this.corruptProtectedReadError(path, classification.reason);
      }
      if (classification.kind === "encrypted") {
        await this.rememberAtRestProtected(path);
        return false;
      }
      // Direct-transfer / CR-1: do not LAK-encrypt a large external file until
      // its direct transfer has been finalized. The sync caller passes
      // remoteDurable=true only after successful promotion.
      if (bytes.byteLength > BINARY_SYNC_MAX_BYTES && !remoteDurable) {
        this.log(
          `At-rest: leaving large file "${path}" plaintext until its server copy is durable.`
        );
        return false;
      }
      // In-size binaries are now safe to encrypt in place: the sync engine can
      // upload them (11-03 catch-up / reconciliation push), so the on-disk VG1
      // copy is never the sole copy. Text files were always safe.
      await this.writePlainBinaryToDisk(path, bytes);
      this.log(`At-rest: encrypted externally added file in place: ${path}`);
      return true;
    } catch (err) {
      this.logError(`At-rest: in-place encryption of externally added "${path}" failed`, err);
      return false;
    } finally {
      this.inPlaceEncryptionInFlight.delete(path);
    }
  }

  /**
   * vault.on("create") entry point for externally-added files. Waits a beat
   * and requires a stable stat (size + mtime unchanged across the window) so
   * a Finder/iCloud copy still in flight is never half-encrypted — writing
   * the ciphertext of a truncated prefix would clobber the rest of the copy.
   * Unstable or vanished files are left alone; the local-only catch-up hook
   * in sync-runtime retries them on the next sync.
   */
  async encryptExternallyAddedFile(path: string): Promise<void> {
    try {
      if (this.isLocalProjectMemoryModeEnabled()) return;
      if (this.isAtRestExcluded(path)) return;
      if (!this.atRestCipher?.isReady()) return;
      const before = await this.app.vault.adapter.stat(path);
      if (!before || before.type !== "file") return;
      await new Promise((resolve) => setTimeout(resolve, 1500));
      const after = await this.app.vault.adapter.stat(path);
      if (!after || after.size !== before.size || after.mtime !== before.mtime) {
        this.log(`At-rest: "${path}" still changing after create event — leaving for sync catch-up.`);
        return;
      }
      await this.ensureAtRestEncryptedInPlace(path);
    } catch (err) {
      this.logError(`At-rest: external-add encryption check failed for "${path}"`, err);
    }
  }

  async writePlainBinaryToDisk(path: string, data: ArrayBuffer): Promise<void> {
    if (this.looksLikeCiphertextBytes(data)) {
      throw new Error(
        `VaultGuard Sync: writePlainBinaryToDisk refused for "${path}" — content has VG1 magic header (corrupted-read cascade).`
      );
    }
    if (this.isLocalProjectMemoryModeEnabled()) {
      await this.writeLocalProjectMemoryBinary(path, data);
      await this.forgetAtRestProtected(path);
      return;
    }
    if (this.isAtRestExcluded(path)) {
      if (!this.originalAdapterMethods.writeBinary) {
        this.failIfAdapterDetached("writeBinary", path);
        return; // legacy adapter without this method: unchanged silent return
      }
      await this.originalAdapterMethods.writeBinary(path, data);
      await this.forgetAtRestProtected(path);
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
      await this.rememberAtRestProtected(path);
      return;
    }
    this.failIfAdapterDetached("writeBinary", path);
    // R-3: a legacy adapter with no writeBinary still resolves silently here.
    // Unchanged on purpose — never-captured semantics are frozen by SD-07-F5's
    // constraints. Asymmetric with writePlainToDisk, which throws AR2; fixing
    // that is a separate behavior change outside this finding's scope.
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
  shouldDeferDenialWipe(path: string): boolean {
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
  async interceptedReadBinary(path: string): Promise<ArrayBuffer> {
    if (!this.originalAdapterMethods.readBinary) {
      throw new Error("VaultGuard Sync: vault adapter readBinary unavailable.");
    }
    if (this.isLocalProjectMemoryModeEnabled()) {
      return this.readLocalProjectMemoryBinary(path);
    }
    if (this.isPathExcluded(path)) {
      if (this.isDetectedGitRepositoryPath(path)) {
        return this.readPlainBinaryFromDisk(path);
      }
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
      return this.hostReadPlainBinaryFromDisk(path);
    }

    return this.hostReadPlainBinaryFromDisk(path);
  }

  /**
   * Permission-checked at-rest encrypted binary write.
   *
   * This is the drag-drop/paste ingestion path. JSON-size content follows the
   * existing encrypted request path. Larger content uses direct transfer; if it
   * cannot become durable remotely, exact plaintext bytes stay on disk with a
   * metadata-only pending record. Legacy adapters without writeBinary retain
   * the existing silent return.
   */
  async interceptedWriteBinary(path: string, data: ArrayBuffer): Promise<void> {
    // SD-06-F1 / DECISION 6: same earliest-point capture as interceptedWrite —
    // before any `await`, so it describes the index before this write.
    const existedLocally = this.localFileExistedBeforeWrite(path);
    if (!this.originalAdapterMethods.writeBinary) {
      this.failIfAdapterDetached("writeBinary", path);
      return; // legacy adapter without this method: unchanged silent return
    }
    if (this.looksLikeCiphertextBytes(data)) {
      this.hostNotifyCorruptedWrite(path);
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
    if (this.isLocalProjectMemoryModeEnabled()) {
      await this.writeLocalProjectMemoryBinary(path, data);
      return;
    }
    if (this.applyingRemoteWrite || this.isPathExcluded(path)) {
      await this.hostWritePlainBinaryToDisk(path, data);
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
    // Files over the JSON ceiling use a direct encrypted transfer. The
    // canonical server copy is finalized before local VG1 encryption. If that
    // cannot happen yet, preserve the exact plaintext bytes locally and persist
    // metadata-only retry state instead of dropping the user's attachment.
    if (data.byteLength > BINARY_SYNC_MAX_BYTES) {
      const contentType = contentTypeForPath(path);
      const hash = await this.computeHashBytes(data);
      const baseVersionId = this.getExpectedVersionId(path);
      const canUploadNow =
        this.shouldUploadChangesImmediately() &&
        this.isOnline() &&
        Boolean(this.keyLease) &&
        Boolean(this.ctx.uploadLargeEncryptedFile);
      if (canUploadNow) {
        try {
          const result = await this.ctx.uploadLargeEncryptedFile!(
            path,
            data,
            contentType,
            baseVersionId,
          );
          this.recordDirectWrite(path, hash, result);
          await this.hostWritePlainBinaryToDisk(path, data);
          await this.ctx.clearPendingLargeFile?.(path);
          await this.emitAuditEvent("file.write", path, {
            directTransfer: true,
            bytes: data.byteLength,
          });
          this.syncState.pendingChanges++;
          this.updateStatusBar();
          return;
        } catch (error) {
          if (this.isNetworkError(error)) this.setConnectionStatus("offline");
          await this.originalAdapterMethods.writeBinary(path, data);
          await this.markLargeFilePending(
            path,
            data,
            contentType,
            /conflict|409/i.test(String(error)) ? "conflict" : "upload-failed",
          );
          new Notice(
            `VaultGuard Sync: Saved "${path}" locally. Its large encrypted upload is pending and can be retried from the VaultGuard sidebar.`,
            10000,
          );
          this.updateStatusBar();
          return;
        }
      }

      await this.originalAdapterMethods.writeBinary(path, data);
      const reason: PendingLargeFileRecord["reason"] = !this.isOnline()
        ? "offline"
        : !this.keyLease
          ? "lease-unavailable"
          : "manual-sync";
      await this.markLargeFilePending(path, data, contentType, reason);
      const now = Date.now();
      if (now - (this.binaryWriteNoticeAt.get(path) ?? 0) >= 60_000) {
        this.binaryWriteNoticeAt.set(path, now);
        new Notice(
          `VaultGuard Sync: Saved "${path}" locally. Its large encrypted upload is pending.`,
          10000
        );
      }
      this.syncState.pendingChanges++;
      this.updateStatusBar();
      return;
    }

    // BIN-A / D-08: in-size binary ingestion mirrors interceptedWrite exactly,
    // with byte substitutions (encryptContentBytes / computeHashBytes /
    // hostWritePlainBinaryToDisk) + a real contentType label + the large-body
    // upload timeout. AC-API1 status discipline is copied verbatim.
    const contentType = contentTypeForPath(path);
    const hash = await this.computeHashBytes(data);
    const baseVersionId = this.getExpectedVersionId(path);
    try {
      // In manual mode, defer remote writes until the user runs a sync explicitly.
      if (this.shouldUploadChangesImmediately() && this.isOnline() && this.keyLease) {
        const encrypted = await this.encryptContentBytes(data);
        // SD-06-F1: resolved once, same reason as interceptedWrite — the 409
        // branch routes on what this write DECLARED.
        const writeIntent = this.resolveWriteIntent(path, existedLocally);
        const declaredCreate = writeIntent?.kind === "must-be-absent";
        const response = await this.apiRequest<RemoteFileWriteResponse>(
          "PUT",
          this.vaultPath(`/files/${encodeURIComponent(path)}`),
          {
            // SD-06-F1: the binary seam is wired INDEPENDENTLY of the text seam
            // (same DECISION 5 fallback rationale as interceptedWrite).
            ...this.buildWriteBody(path, encrypted, hash, {
              expectedVersionId: baseVersionId,
              intent: writeIntent,
              lane: "online-binary",
            }),
            contentType,
          },
          undefined,
          { timeoutMs: BINARY_PUT_TIMEOUT_MS }
        );

        if (!response.success) {
          if (response.error?.statusCode === 409) {
            if (declaredCreate) {
              // SD-06-F1 / DECISION 1 — persist the pasted attachment BEFORE
              // throwing, or it exists nowhere. This DELIBERATELY departs from
              // the CR-1 PUT-first ordering documented below, and the departure
              // is sound: CR-1 protects against an orphaned local-only VG1
              // binary with NO server copy at that path, but a create-409
              // PROVES a server copy exists there. The resulting divergence is
              // classified by reconciliation as `binaryBoth`, which routes to a
              // user-chosen strategy and never auto-forces. Losing the paste to
              // uphold an invariant whose premise does not hold would be the
              // wrong trade under the availability rule.
              //
              // The store is left ABSENT for this path (no recordSuccessfulWrite
              // runs on a failed response, and nothing else records presence),
              // so a retry re-declares the create and stays loud rather than
              // silently clobbering the other device's copy.
              await this.hostWritePlainBinaryToDisk(path, data);
              new Notice(
                `VaultGuard Sync: "${path}" was created on another device at the same time. Your copy is saved locally — run sync to reconcile the two.`,
                10000
              );
            } else {
              new Notice(
                `VaultGuard Sync: Remote copy of "${path}" changed before this attachment upload completed. Run sync to reconcile before retrying.`,
                10000
              );
            }
            throw new Error(response.error.message);
          }
          if (response.error?.statusCode === 401 || response.error?.statusCode === 403) {
            throw new Error(response.error.message);
          }

          // AC-API1: queue only TRANSIENT failures (network / 5xx / 429) for
          // replay. A permanent 4xx (413 too-large, 409) can never succeed on
          // retry — queuing it would jam the offline flush.
          const status = response.error?.statusCode ?? 0;
          if (status === 0 || status === 429 || status >= 500) {
            if (status === 0) this.setConnectionStatus("offline");
            this.queueOfflineOperation(
              "write",
              path,
              uint8ToBase64Chunked(new Uint8Array(data)),
              { encoding: "base64", contentType, baseVersionId, baseHash: hash }
            );
          } else {
            throw new Error(response.error?.message ?? "Remote write failed.");
          }
        } else {
          this.recordSuccessfulWrite(path, hash, response);
        }

        // CR-1: PUT first, local VG1 write second. A permanent PUT failure
        // throws above before we reach here, so we never leave an orphaned
        // local-only LAK-encrypted binary with no server copy.
        await this.hostWritePlainBinaryToDisk(path, data);
      } else {
        // Manual / offline / no-lease: the local VG1 write is safe here because
        // the queued op IS the server-copy path (CR-1 satisfied by the queue).
        await this.hostWritePlainBinaryToDisk(path, data);
        this.queueOfflineOperation(
          "write",
          path,
          uint8ToBase64Chunked(new Uint8Array(data)),
          { encoding: "base64", contentType, baseVersionId, baseHash: hash }
        );
      }

      await this.emitAuditEvent("file.write", path);
      this.syncState.pendingChanges++;
      this.updateStatusBar();
    } catch (error) {
      if (this.isNetworkError(error)) {
        this.setConnectionStatus("offline");
        await this.hostWritePlainBinaryToDisk(path, data);
        this.queueOfflineOperation(
          "write",
          path,
          uint8ToBase64Chunked(new Uint8Array(data)),
          { encoding: "base64", contentType, baseVersionId, baseHash: hash }
        );
      } else {
        throw error;
      }
    }
  }

  /**
   * Checks whether the current user may delete a path.
   * Delete is a distinct backend action, so WRITE does not imply deletion.
   */
  async canDeletePath(path: string): Promise<boolean> {
    if (!this.session) {
      return false;
    }

    // SD-03-F15: the org-admin short-circuit is the fourth client fast path
    // (the other three live in PermissionStore). With the org restriction on,
    // fall through to the EXISTING member path: online => POST
    // /permissions/check with action:"delete" (policy-aware server-side since
    // plan 14-01); offline or transient failure => the cached-permission
    // fallback, where a warmed root ADMIN still answers (M6) and a cold cache
    // denies exactly as it does for every member today (M5).
    if (
      !this.adminRestrictionActive() &&
      (this.session.role === "admin" || this.session.role === "owner")
    ) {
      return true;
    }

    if (this.isOnline()) {
      let response: ApiResponse<{ allowed: boolean }>;
      try {
        response = await this.apiRequest<{ allowed: boolean }>("POST", this.vaultPath('/permissions/check'), {
          userId: this.session.userId,
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

      // AC-API1: a permanent 4xx is an authoritative "no". Transient failures
      // (network / 5xx / 429) fall through to the cached-permission fallback,
      // matching the pre-fix behavior when those collapsed to statusCode 0.
      {
        const status = response.error?.statusCode ?? 0;
        if (status !== 0 && status !== 429 && status < 500) {
          return false;
        }
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
  async interceptedList(
    path: string
  ): Promise<{ files: string[]; folders: string[] }> {
    if (!this.originalAdapterMethods.list) {
      this.failIfAdapterDetached("list", path);
      return { files: [], folders: [] };
    }

    return this.originalAdapterMethods.list(path);
  }

  /**
   * Permission-checked file deletion operation.
   * @param path - Normalized vault-relative file path
   * @throws Error if the user lacks DELETE permission
   */
  async interceptedDelete(path: string): Promise<void> {
    this.evictResourcePreview(path);
    if (this.isLocalProjectMemoryModeEnabled()) {
      if (this.originalAdapterMethods.remove) {
        await this.originalAdapterMethods.remove(path);
      }
      await this.forgetAtRestProtected(path);
      return;
    }
    if (this.isPathExcluded(path)) {
      if (this.originalAdapterMethods.remove) {
        await this.originalAdapterMethods.remove(path);
        await this.forgetAtRestProtected(path);
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

    // Tombstone the local removal up front (the point we commit to deleting
    // locally): if the remote DELETE below is deferred (manual/offline) or is
    // interrupted before it confirms, the tombstone survives a restart / re-bind
    // so reconciliation cannot resurrect the file. A confirmed server DELETE
    // (success or 404) clears it again immediately.
    this.recordDeletionTombstone(path);

    try {
      // In manual mode, defer remote deletes until the user runs a sync explicitly.
      if (this.shouldUploadChangesImmediately() && this.isOnline()) {
        const response = await this.apiRequest(
          "DELETE",
          this.vaultPath(`/files/${encodeURIComponent(path)}`),
          this.buildDeleteBody(path)
        );

        if (response.success || response.error?.statusCode === 404) {
          // Success or already-gone == done — clear the tombstone for this path.
          this.clearDeletionTombstone(path);
          this.recordRemoteFileAbsent(path);
        } else {
          if (response.error?.statusCode === 401 || response.error?.statusCode === 403) {
            throw new Error(response.error.message);
          }

          // AC-API1: transient failures (network / 5xx / 429) queue for
          // replay; permanent 4xx rejections fail loudly instead.
          const status = response.error?.statusCode ?? 0;
          if (status === 0 || status === 429 || status >= 500) {
            if (status === 0) this.setConnectionStatus("offline");
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
        await this.forgetAtRestProtected(path);
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
  async interceptedRename(oldPath: string, newPath: string): Promise<void> {
    const oldNormalized = this.normalizeVaultPath(oldPath);
    const newNormalized = this.normalizeVaultPath(newPath);
    // The old path's decrypted blob is stale after a rename; drop it (the new
    // path re-warms on next render).
    this.evictResourcePreview(oldNormalized);
    this.evictResourcePreview(oldPath);

    // Local rename happens first regardless of permissions or network — the
    // existing adapter behaviour the user expects. Server reconciliation is
    // best-effort on top.
    if (this.originalAdapterMethods.rename) {
      await this.originalAdapterMethods.rename(oldPath, newPath);
      await this.atRestProtectionState?.move(oldPath, newPath);
    } else {
      this.failIfAdapterDetached("rename", oldPath);
    }

    if (this.isLocalProjectMemoryModeEnabled()) {
      return;
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

    // BIN-A / L1: fix the live binary-corruption bug. Before this, BOTH the
    // offline-queue branch and the online PUT read the just-renamed file via
    // hostReadPlainFromDisk (a NON-fatal UTF-8 decode) and pushed the mangled
    // result — silently corrupting the server copy of any binary (photo.png,
    // *.pdf, …). Route capable adapters through a content probe: text keeps the
    // exact string flow; binary rides the byte path (encryptContentBytes /
    // computeHashBytes / queue with encoding:"base64"). Legacy adapters (no
    // readBinary — D-10 / AR2) keep today's string-only flow verbatim.
    if (!this.originalAdapterMethods.readBinary) {
      await this.pushRenamedStringToServer(
        oldNormalized,
        newNormalized,
        oldPath,
        newPath,
        () => this.hostReadPlainFromDisk(newPath),
      );
      return;
    }

    let renamedBytes: ArrayBuffer;
    try {
      renamedBytes = await this.readPlainBinaryFromDisk(newPath);
    } catch (err) {
      // Can't read the renamed file's plaintext bytes — nothing safe to push.
      // The local rename already happened; surface the OLD path for cache
      // invalidation and bail (matches the offline read-failure handling).
      this.logError(`Rename: failed to read "${newPath}" for server sync`, err);
      this.permissionStore.emit("changed", { path: oldNormalized });
      return;
    }

    let decodedText: string | null;
    try {
      // fatal:true rejects (instead of U+FFFD-mangling) anything that isn't valid
      // UTF-8 — the exact content-based text/binary split readTextForSync uses.
      decodedText = new TextDecoder("utf-8", { fatal: true }).decode(renamedBytes);
    } catch {
      decodedText = null;
    }

    if (decodedText === null) {
      await this.pushRenamedBinaryToServer(
        oldNormalized,
        newNormalized,
        oldPath,
        newPath,
        renamedBytes,
      );
      return;
    }

    // TEXT on a capable adapter: reuse the already-decoded string (no second disk
    // read) and run the identical string push flow.
    const decoded = decodedText;
    await this.pushRenamedStringToServer(
      oldNormalized,
      newNormalized,
      oldPath,
      newPath,
      () => Promise.resolve(decoded),
    );
  }

  /**
   * Existing string rename push (offline-queue + online PUT + network-error
   * fallback), factored out of interceptedRename so both the legacy-adapter path
   * (readContent = hostReadPlainFromDisk) and the capable-adapter TEXT path
   * (readContent = the already-decoded string) share one implementation.
   * Behavior is byte-identical to the pre-BIN-A inline flow.
   */
  private async pushRenamedStringToServer(
    oldNormalized: string,
    newNormalized: string,
    oldPath: string,
    newPath: string,
    readContent: () => Promise<string>,
  ): Promise<void> {
    let content: string;
    try {
      content = await readContent();
    } catch (err) {
      this.logError(`Rename: failed to read "${newPath}" for server sync`, err);
      this.permissionStore.emit("changed", { path: oldNormalized });
      return;
    }
    const view = new TextEncoder().encode(content);
    const bytes = view.buffer.slice(
      view.byteOffset,
      view.byteOffset + view.byteLength,
    ) as ArrayBuffer;
    if (bytes.byteLength > BINARY_SYNC_MAX_BYTES) {
      await this.pushRenamedLargeFileToServer(
        oldNormalized,
        newNormalized,
        newPath,
        bytes,
        "text/markdown",
      );
      return;
    }

    if (!this.shouldUploadChangesImmediately() || !this.isOnline() || !this.keyLease) {
      this.queueOfflineOperation("write", newNormalized, content, {
        intent: { kind: "must-be-absent" },
      });
      this.queueOfflineOperation("delete", oldNormalized);
      // Pitfall 5: rename emits OLD path.
      this.permissionStore.emit("changed", { path: oldNormalized });
      return;
    }

    try {
      const encrypted = await this.encryptContent(content);
      const hash = await this.computeHash(content);
      const baseVersionId = this.getExpectedVersionId(newNormalized);

      const putResp = await this.apiRequest<RemoteFileWriteResponse>(
        "PUT",
        this.vaultPath(`/files/${encodeURIComponent(newNormalized)}`),
        // SD-06-F1 / DECISION 6: declare the destination's intent.
        this.buildWriteBody(newNormalized, encrypted, hash, {
          expectedVersionId: baseVersionId,
          intent: this.resolveRenameDestIntent(newNormalized),
          lane: "rename-dest",
        })
      );

      if (!putResp.success) {
        // 409 → conflict flow and RETURN, before the DELETE below. The old
        // server copy survives; verified per-function for 16-03.
        if (putResp.error?.statusCode === 409) {
          await this.handleRemoteWriteConflict(newNormalized, content, baseVersionId);
          return;
        }
        throw new Error(putResp.error?.message ?? `Rename: writing "${newPath}" failed.`);
      }
      this.recordSuccessfulWrite(newNormalized, hash, putResp);

      const delResp = await this.apiRequest(
        "DELETE",
        this.vaultPath(`/files/${encodeURIComponent(oldNormalized)}`),
        this.buildDeleteBody(oldNormalized)
      );

      if (!delResp.success && delResp.error?.statusCode !== 404) {
        // New path is on the server but the old one wasn't deleted. Queue the
        // delete so the next flush retries — without this the admin panel
        // shows both names forever, which is exactly the duplicate-after-
        // rename bug we're fixing.
        this.logError(
          `Rename: DELETE of old path "${oldNormalized}" failed`,
          new Error(delResp.error?.message ?? "unknown")
        );
        this.queueOfflineOperation("delete", oldNormalized);
      } else {
        this.recordRemoteFileAbsent(oldNormalized);
      }

      // Pitfall 5: rename emits OLD path.
      this.permissionStore.emit("changed", { path: oldNormalized });
      await this.emitAuditEvent("file.rename", oldNormalized, { newPath: newNormalized });
      this.syncState.pendingChanges = this.offlineQueue.length;
      this.updateStatusBar();
    } catch (error) {
      if (this.isNetworkError(error)) {
        this.setConnectionStatus("offline");
        this.queueOfflineOperation("write", newNormalized, content, {
          intent: { kind: "must-be-absent" },
        });
        this.queueOfflineOperation("delete", oldNormalized);
        // Pitfall 5: rename emits OLD path.
        this.permissionStore.emit("changed", { path: oldNormalized });
      } else {
        throw error;
      }
    }
  }

  private async pushRenamedLargeFileToServer(
    oldNormalized: string,
    newNormalized: string,
    newPath: string,
    bytes: ArrayBuffer,
    contentType: string,
  ): Promise<void> {
    const canUploadNow =
      this.shouldUploadChangesImmediately() &&
      this.isOnline() &&
      Boolean(this.keyLease) &&
      Boolean(this.ctx.uploadLargeEncryptedFile);
    if (!canUploadNow) {
      const reason: PendingLargeFileRecord["reason"] = !this.isOnline()
        ? "offline"
        : !this.keyLease
          ? "lease-unavailable"
          : "manual-sync";
      await this.markLargeFilePending(
        newNormalized,
        bytes,
        contentType,
        reason,
        oldNormalized,
      );
      new Notice(
        `VaultGuard Sync: Kept the local rename to "${newPath}". The large server rename is pending; the old server copy was preserved.`,
        10000,
      );
      this.permissionStore.emit("changed", { path: oldNormalized });
      return;
    }

    const hash = await this.computeHashBytes(bytes);
    try {
      const result = await this.ctx.uploadLargeEncryptedFile!(
        newNormalized,
        bytes,
        contentType,
        this.getExpectedVersionId(newNormalized),
      );
      this.recordDirectWrite(newNormalized, hash, result);
      const delResp = await this.apiRequest(
        "DELETE",
        this.vaultPath(`/files/${encodeURIComponent(oldNormalized)}`),
        this.buildDeleteBody(oldNormalized),
      );
      if (!delResp.success && delResp.error?.statusCode !== 404) {
        this.queueOfflineOperation("delete", oldNormalized);
      } else {
        this.recordRemoteFileAbsent(oldNormalized);
      }
      await this.ctx.clearPendingLargeFile?.(newNormalized);
      await this.ensureAtRestEncryptedInPlace(newNormalized, true);
      await this.emitAuditEvent("file.rename", oldNormalized, {
        newPath: newNormalized,
        directTransfer: true,
      });
    } catch (error) {
      if (this.isNetworkError(error)) this.setConnectionStatus("offline");
      await this.markLargeFilePending(
        newNormalized,
        bytes,
        contentType,
        /conflict|409/i.test(String(error)) ? "conflict" : "upload-failed",
        oldNormalized,
      );
      new Notice(
        `VaultGuard Sync: Kept the local rename to "${newPath}". The replacement upload is pending; the old server copy was preserved.`,
        10000,
      );
    } finally {
      this.permissionStore.emit("changed", { path: oldNormalized });
      this.updateStatusBar();
    }
  }

  /**
   * Byte-safe rename push for binary content. Mirrors the string flow but (a)
   * dispatches above-threshold bytes to direct transfer, (b) encrypts/hashes RAW
   * bytes (no lossy UTF-8 decode — the L1 corruption fix), (c) sends a real
   * contentType + the large-body timeout, and (d) queues base64 with
   * encoding:"base64" when offline.
   */
  private async pushRenamedBinaryToServer(
    oldNormalized: string,
    newNormalized: string,
    oldPath: string,
    newPath: string,
    bytes: ArrayBuffer,
  ): Promise<void> {
    // Above-threshold bytes cannot ride the JSON path. Direct-transfer the
    // replacement first; its helper preserves the old remote path and records
    // metadata-only pending state if promotion cannot complete.
    if (bytes.byteLength > BINARY_SYNC_MAX_BYTES) {
      await this.pushRenamedLargeFileToServer(
        oldNormalized,
        newNormalized,
        newPath,
        bytes,
        contentTypeForPath(newNormalized),
      );
      return;
    }

    const contentType = contentTypeForPath(newNormalized);
    const hash = await this.computeHashBytes(bytes);
    const baseVersionId = this.getExpectedVersionId(newNormalized);

    if (!this.shouldUploadChangesImmediately() || !this.isOnline() || !this.keyLease) {
      // Offline / manual: queue the byte write (base64 + encoding marker) and the
      // old-path delete, exactly as the string flow queues its two halves.
      const base64 = uint8ToBase64Chunked(new Uint8Array(bytes));
      this.queueOfflineOperation("write", newNormalized, base64, {
        encoding: "base64",
        contentType,
        baseVersionId,
        baseHash: hash,
        intent: { kind: "must-be-absent" },
      });
      this.queueOfflineOperation("delete", oldNormalized);
      // Pitfall 5: rename emits OLD path.
      this.permissionStore.emit("changed", { path: oldNormalized });
      return;
    }

    try {
      const encrypted = await this.encryptContentBytes(bytes);

      const putResp = await this.apiRequest<RemoteFileWriteResponse>(
        "PUT",
        this.vaultPath(`/files/${encodeURIComponent(newNormalized)}`),
        {
          // SD-06-F1 / DECISION 6: declare the destination's intent.
          ...this.buildWriteBody(newNormalized, encrypted, hash, {
            expectedVersionId: baseVersionId,
            intent: this.resolveRenameDestIntent(newNormalized),
            lane: "rename-dest",
          }),
          contentType,
        },
        undefined,
        { timeoutMs: BINARY_PUT_TIMEOUT_MS }
      );

      if (!putResp.success) {
        if (putResp.error?.statusCode === 409) {
          new Notice(
            `VaultGuard Sync: Remote copy of "${newNormalized}" changed before this attachment rename completed. Run sync to reconcile before retrying.`,
            10000
          );
        }
        // The throw below is a NON-network error, so the catch at the bottom of
        // this function rethrows rather than queueing — which is what skips the
        // old-path DELETE. Verified per-function for 16-03; do not "simplify"
        // the catch into a blanket queue-and-continue.
        throw new Error(putResp.error?.message ?? `Rename: writing "${newPath}" failed.`);
      }
      this.recordSuccessfulWrite(newNormalized, hash, putResp);

      const delResp = await this.apiRequest(
        "DELETE",
        this.vaultPath(`/files/${encodeURIComponent(oldNormalized)}`),
        this.buildDeleteBody(oldNormalized)
      );

      if (!delResp.success && delResp.error?.statusCode !== 404) {
        this.logError(
          `Rename: DELETE of old path "${oldNormalized}" failed`,
          new Error(delResp.error?.message ?? "unknown")
        );
        this.queueOfflineOperation("delete", oldNormalized);
      } else {
        this.recordRemoteFileAbsent(oldNormalized);
      }

      // Pitfall 5: rename emits OLD path.
      this.permissionStore.emit("changed", { path: oldNormalized });
      await this.emitAuditEvent("file.rename", oldNormalized, { newPath: newNormalized });
      this.syncState.pendingChanges = this.offlineQueue.length;
      this.updateStatusBar();
    } catch (error) {
      if (this.isNetworkError(error)) {
        this.setConnectionStatus("offline");
        const base64 = uint8ToBase64Chunked(new Uint8Array(bytes));
        this.queueOfflineOperation("write", newNormalized, base64, {
          encoding: "base64",
          contentType,
          baseVersionId,
          baseHash: hash,
          intent: { kind: "must-be-absent" },
        });
        this.queueOfflineOperation("delete", oldNormalized);
        // Pitfall 5: rename emits OLD path.
        this.permissionStore.emit("changed", { path: oldNormalized });
      } else {
        throw error;
      }
    }
  }

  // ─────────────────────────────────────────────────────────────────────────


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
  async sweepPlaceholderPaths(): Promise<void> {
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


}

export function createAtRestAdapterRuntime(
  ctx: AtRestAdapterRuntimeContext,
): AtRestAdapterRuntime {
  return new AtRestAdapterRuntime(ctx);
}
