import { Notice, Platform, TFolder } from "obsidian";
import {
  AtRestCipher,
  type AtRestStorage,
  type AtRestStatus,
} from "../crypto/at-rest-cipher";
import {
  PermissionLevel,
  type ApiResponse,
  type ConnectionStatus,
} from "../types";
import type {
  AtRestAdapterRuntimeContext,
  RemoteFileContentResponse,
  VaultAdapterOriginalMethods,
} from "./plugin-runtime-types";

function getActiveObsidianDocument(): Document | null {
  if (typeof activeDocument !== "undefined") {
    return activeDocument;
  }
  return null;
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
});

export class AtRestAdapterRuntime {
  private originalAdapterMethods: VaultAdapterOriginalMethods = emptyAdapterMethods();
  private atRestCipher: AtRestCipher | null = null;
  private atRestFirstRunOffered = false;
  private readOnlyFallbackNoticeAt: Map<string, number> = new Map();
  private cloudDecryptFallbackNoticeAt: Map<string, number> = new Map();
  private cipherInitPromise: Promise<boolean> | null = null;
  private corruptedWriteNoticeAt: Map<string, number> = new Map();

  constructor(private ctx: AtRestAdapterRuntimeContext) {}

  getOriginalAdapterMethods(): VaultAdapterOriginalMethods {
    return this.originalAdapterMethods;
  }

  setOriginalAdapterMethods(methods: VaultAdapterOriginalMethods): void {
    this.originalAdapterMethods = methods;
  }

  getAtRestCipher(): AtRestCipher | null {
    return this.atRestCipher;
  }

  setAtRestCipher(cipher: AtRestCipher | null): void {
    this.atRestCipher = cipher;
  }

  getAtRestStatus(): AtRestStatus {
    return this.atRestCipher?.getStatus() ?? { kind: "uninitialized" };
  }

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

  async migrateVaultToAtRest(): Promise<void> {
    return this.encryptVaultAtRest();
  }

  async revertVaultFromAtRest(): Promise<void> {
    return this.decryptVaultAtRest();
  }

  async exportAtRestRecoveryCode(): Promise<string> {
    if (!this.atRestCipher) {
      throw new Error("VaultGuard Sync: at-rest cipher not initialised.");
    }
    return this.atRestCipher.exportRecoveryCode();
  }

  async restoreAtRestFromRecoveryCode(code: string): Promise<boolean> {
    if (!this.atRestCipher) {
      await this.initAtRestCipher();
    }
    if (!this.atRestCipher) return false;
    return this.atRestCipher.restoreFromRecoveryCode(code);
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

  private queueOfflineOperation(operation: "write" | "delete", path: string, data?: string): void {
    this.ctx.queueOfflineOperation(operation, path, data);
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

  private apiRequest<T>(
    method: string,
    endpoint: string,
    body?: Record<string, unknown>,
    idTokenOverride?: string,
  ): Promise<ApiResponse<T>> {
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
    const pluginId = this.manifest?.id ?? "vaultguard-sync";
    const envelopePath = this.vaultConfigPath("plugins", pluginId, "lak.envelope");
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
      loadFallbackKek: async () => {
        const value: unknown = this.app.loadLocalStorage("vaultguard.at-rest.kek.v1");
        return typeof value === "string" && value.length > 0 ? value : null;
      },
      saveFallbackKek: async (kekBase64: string) => {
        this.app.saveLocalStorage("vaultguard.at-rest.kek.v1", kekBase64);
      },
      clearFallbackKek: async () => {
        this.app.saveLocalStorage("vaultguard.at-rest.kek.v1", null);
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
  async maybeOfferFirstRunMigration(): Promise<void> {
    if (this.atRestFirstRunOffered) return;
    this.atRestFirstRunOffered = true;
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
    const notice = new Notice("", 0);
    const frag = doc.createDocumentFragment();
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
   * magic header are skipped. Excluded paths (config folder, trash, plugin
   * folder) are never touched. Used for a one-shot migration of legacy
   * plaintext vaults; ongoing writes are encrypted automatically by the
   * adapter interceptor.
   */
  async encryptVaultAtRest(): Promise<void> {
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
  async decryptVaultAtRest(): Promise<void> {
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
  interceptVaultAdapter(): void {
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
  restoreVaultAdapter(): void {
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
  async interceptedRead(path: string): Promise<string> {
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

    if (this.applyingRemoteWrite) {
      await this.hostWritePlainToDisk(path, data);
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

        await this.hostWritePlainToDisk(path, data);
      } else {
        await this.hostWritePlainToDisk(path, data);
        this.queueOfflineOperation("write", path, data);
      }

      await this.emitAuditEvent("file.write", path);
      this.syncState.pendingChanges++;
      this.updateStatusBar();
    } catch (error) {
      if (this.isNetworkError(error)) {
        this.setConnectionStatus("offline");
        await this.hostWritePlainToDisk(path, data);
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
    const normalized = path.replace(/^\/+/, "");
    if (!normalized) return false;
    const configDir = this.normalizeVaultPath(this.app.vault.configDir);
    if (normalized === configDir || normalized.startsWith(`${configDir}/`)) return true;
    if (normalized === ".trash" || normalized.startsWith(".trash/")) return true;
    return this.isPathExcluded(path);
  }

  async readPlainFromDisk(path: string): Promise<string> {
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
  async readPlainBinaryFromDisk(path: string): Promise<ArrayBuffer> {
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
  async writePlainBinaryToDisk(path: string, data: ArrayBuffer): Promise<void> {
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
      return this.hostReadPlainBinaryFromDisk(path);
    }

    return this.hostReadPlainBinaryFromDisk(path);
  }

  /**
   * Permission-checked at-rest encrypted binary write.
   *
   * Mirrors `interceptedWrite` for binary content. Managed binary writes fail
   * closed until the backend supports binary sync; silently keeping encrypted
   * attachments local would create a false sense of protected backup.
   */
  async interceptedWriteBinary(path: string, data: ArrayBuffer): Promise<void> {
    if (!this.originalAdapterMethods.writeBinary) return;
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
    await this.emitAuditEvent("file.write", path, { outcome: "denied", reason: "binary-sync-unsupported" });
    throw new Error(
      `VaultGuard Sync: Binary files are not currently supported for protected sync. "${path}" was not written.`
    );
  }

  /**
   * Checks whether the current user may delete a path.
   * Delete is a distinct backend action, so WRITE does not imply deletion.
   */
  async canDeletePath(path: string): Promise<boolean> {
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
  async interceptedList(
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
  async interceptedDelete(path: string): Promise<void> {
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
          this.vaultPath(`/files/${encodeURIComponent(path)}`)
        );

        if (response.success || response.error?.statusCode === 404) {
          // Success or already-gone == done — clear the tombstone for this path.
          this.clearDeletionTombstone(path);
        } else {
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
  async interceptedRename(oldPath: string, newPath: string): Promise<void> {
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
        const content = await this.hostReadPlainFromDisk(newPath);
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
      const content = await this.hostReadPlainFromDisk(newPath);
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
          const content = await this.hostReadPlainFromDisk(newPath);
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
