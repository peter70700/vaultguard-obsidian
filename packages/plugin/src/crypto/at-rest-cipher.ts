/**
 * VaultGuard - Local At-Rest Cipher
 *
 * Encrypts vault files on the local disk so the contents are unreadable in
 * Finder / Explorer / by other processes. Files are written with a small
 * header so we can distinguish encrypted-on-disk content from legacy
 * plaintext (which we still need to read while migrating).
 *
 * Key hierarchy:
 *   OS keychain (Electron safeStorage)
 *     -> KEK (key-encrypting key, opaque to JS)
 *           -> LAK (32-byte AES-256 key, wrapped on disk, in-memory while unlocked)
 *                 -> per-file ciphertext
 *
 * If `safeStorage.isEncryptionAvailable()` is false we degrade to a
 * device-local KEK persisted through Obsidian's vault-scoped storage. That still defeats
 * casual filesystem inspection of the vault folder, but anyone with the whole
 * Electron profile directory can recover the LAK. Documented in
 * `docs/AT-REST-ENCRYPTION.md`.
 *
 * Canonical reference: docs/AT-REST-ENCRYPTION.md
 */

import { SafeStorageLike, probeSafeStorage } from "./safe-storage";

const MAGIC = new Uint8Array([0x56, 0x47, 0x31, 0x00]); // "VG1\0"
const VERSION = 0x01;
const HEADER_LEN = 8;     // 4 magic + 1 version + 3 reserved
const NONCE_LEN = 12;     // AES-GCM standard
const TAG_LEN = 16;       // AES-GCM auth tag (appended to ciphertext by WebCrypto)
const KEY_LEN = 32;       // AES-256

/**
 * Storage hooks injected by the plugin. We deliberately don't import Obsidian
 * here so the cipher remains testable in plain Node.
 */
/**
 * Result of probing for the wrapped LAK. Critically distinguishes "no envelope
 * exists yet" (safe to provision a fresh key) from "an envelope exists but we
 * could not read it" (a transient I/O error / truncated file — provisioning
 * here would OVERWRITE the only wrapped copy of the LAK and orphan every
 * at-rest ciphertext on disk). A bare `string | null` cannot express that
 * difference, which is why `loadWrappedLak` alone is unsafe for the provisioning
 * decision.
 */
export type WrappedLakProbe =
  | { kind: "absent" }
  | { kind: "present"; blob: string }
  | { kind: "error"; reason: string };

export interface AtRestStorage {
  /** Read the wrapped LAK blob (base64 string), or null if not yet provisioned. */
  loadWrappedLak(): Promise<string | null>;
  /**
   * Richer probe that distinguishes absent / present / read-error. When a
   * storage implementation provides this, `init()` uses it INSTEAD of
   * `loadWrappedLak()` for the provisioning decision, so a transient read
   * failure is never mistaken for first-run and the existing envelope is never
   * overwritten. Implementations that omit it fall back to `loadWrappedLak()`
   * (null → absent), preserving the previous behaviour for in-memory test mocks.
   */
  probeWrappedLak?(): Promise<WrappedLakProbe>;
  /**
   * Optional guard consulted ONLY when `probeWrappedLak` reports `absent`,
   * before a fresh LAK is provisioned. Returns true if any at-rest ciphertext
   * (a VG1-headed file) still exists on disk. A missing envelope with existing
   * ciphertext is NOT a first run — it's a same-id reinstall or a synced copy
   * opened on a new device, where the plugin folder (holding the envelope) was
   * deleted but the encrypted notes survive. Minting a new LAK there would
   * orphan every one of those files under a key that no longer exists. When
   * this returns true, `init()` routes to `needs-recovery` instead of
   * provisioning. Implementations that omit it keep the previous
   * provision-on-absent behaviour (safe for in-memory test mocks, which have no
   * vault to scan).
   */
  hasExistingCiphertext?(): Promise<boolean>;
  /** Persist the wrapped LAK blob (base64). */
  saveWrappedLak(blob: string): Promise<void>;
  /** Remove the wrapped LAK blob entirely (on plugin disable / decrypt-and-leave). */
  clearWrappedLak(): Promise<void>;
  /** Read the device-local fallback KEK, or null if none is provisioned. */
  loadFallbackKek?(): Promise<string | null>;
  /**
   * Read EVERY distinct fallback-KEK candidate the device can offer (e.g. a
   * localStorage copy AND a durable on-disk copy that may transiently disagree),
   * so the UNWRAP path can try each and never has to guess. Pure read: it must
   * never mint or persist. Implementations that omit it fall back to
   * `loadFallbackKek()` as a single-candidate source.
   */
  loadFallbackKekCandidates?(): Promise<string[]>;
  /** Persist the device-local fallback KEK. */
  saveFallbackKek?(kekBase64: string): Promise<void>;
  /** Remove the device-local fallback KEK. */
  clearFallbackKek?(): Promise<void>;
}

export type AtRestStatus =
  | { kind: "uninitialized" }
  | { kind: "unlocked"; method: "safe-storage" | "localstorage-fallback" | "ephemeral" }
  | { kind: "locked"; method: "safe-storage" | "localstorage-fallback" }
  | {
      kind: "needs-recovery";
      reason: string;
    }
  | { kind: "disabled"; reason: string };

/** Prefix that tags a v1 recovery code so we can refuse stranger formats. */
const RECOVERY_CODE_PREFIX = "VG1";

/** Bytes of SHA-256 used as a transcription-error checksum on recovery codes. */
const RECOVERY_CHECKSUM_BYTES = 2;

/**
 * AtRestCipher owns the LAK and provides encrypt/decrypt for both string
 * (markdown) and binary (attachments) payloads. It is intentionally
 * synchronous-after-init from the caller's perspective: `init()` is awaited
 * once, then encrypt/decrypt run against the in-memory key.
 */
export class AtRestCipher {
  private lak: Uint8Array | null = null;
  private cryptoKey: CryptoKey | null = null;
  private storage: AtRestStorage;
  private safeStorage: SafeStorageLike | null = null;
  private method: "safe-storage" | "localstorage-fallback" | "ephemeral" | null = null;
  private status: AtRestStatus = { kind: "uninitialized" };

  constructor(storage: AtRestStorage) {
    this.storage = storage;
  }

  /**
   * Initialize the cipher. On first call generates a fresh LAK; on subsequent
   * loads, unwraps the persisted LAK using safeStorage (or the vault-local
   * fallback). Returns true if the cipher is ready to encrypt/decrypt.
   */
  async init(): Promise<boolean> {
    this.safeStorage = probeSafeStorage();

    const probe = await this.probeWrapped();

    if (probe.kind === "error") {
      // The envelope EXISTS but could not be read (transient I/O error,
      // truncated/empty blob, locked file). Provisioning a fresh LAK here would
      // overwrite the only wrapped copy of the real key and permanently orphan
      // every at-rest ciphertext on disk. Refuse to provision; route the user
      // to recovery instead. This is the data-loss failure mode the envelope
      // migration guard was written to prevent, generalised to all read errors.
      this.status = {
        kind: "needs-recovery",
        reason: `Could not read the local at-rest key envelope: ${probe.reason}. This is usually transient — reopen the vault to retry. If it persists, restore from your recovery code in Settings → VaultGuard. Your encrypted files are intact; VaultGuard will not overwrite the key.`,
      };
      return false;
    }

    if (probe.kind === "absent") {
      // No envelope exists. Before provisioning a fresh LAK, confirm this is a
      // genuine first run and not a same-id reinstall / fresh-device open where
      // the plugin folder (which holds the envelope) was deleted but the
      // vault's VG1 ciphertext survives on disk. Minting a new LAK there would
      // orphan every encrypted note under a key that no longer exists. The
      // prior-plugin-id envelope migration does NOT cover a same-id
      // uninstall/reinstall, so this ciphertext scan is the backstop.
      if (this.storage.hasExistingCiphertext) {
        let hasCiphertext = false;
        try {
          hasCiphertext = await this.storage.hasExistingCiphertext();
        } catch {
          // If we cannot even scan for ciphertext, fail safe: assume it may
          // exist rather than risk provisioning over it.
          hasCiphertext = true;
        }
        if (hasCiphertext) {
          this.status = {
            kind: "needs-recovery",
            reason:
              "The local at-rest key is missing but this vault still contains encrypted files — this usually happens after reinstalling the plugin or opening a synced copy on a new device. Restore from your recovery code in Settings → VaultGuard to regain access. VaultGuard will not create a new key over your existing encrypted files.",
          };
          return false;
        }
      }
      // First-time provisioning: no envelope AND no existing ciphertext.
      const fresh = crypto.getRandomValues(new Uint8Array(KEY_LEN));
      const blob = await this.wrapLak(fresh);
      await this.storage.saveWrappedLak(blob);
      this.lak = fresh;
    } else {
      try {
        this.lak = await this.unwrapLak(probe.blob);
      } catch (err) {
        // The persisted blob can't be unwrapped — most likely the user moved
        // their vault to a different machine, the OS keychain entry was
        // wiped, or the user reinstalled the plugin on a fresh device.
        // Distinguish this from a plain "disabled" state so the UI can
        // route the user to the recovery-code restore flow instead of
        // silently treating the vault as unencryptable.
        this.status = {
          kind: "needs-recovery",
          reason: `Could not unwrap the local at-rest key: ${
            err instanceof Error ? err.message : String(err)
          }. Restore from your recovery code in Settings → VaultGuard, or run "Decrypt vault at rest" if you intend to discard the encrypted files.`,
        };
        return false;
      }
    }

    this.cryptoKey = await crypto.subtle.importKey(
      "raw",
      this.lak as BufferSource,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );

    this.status = { kind: "unlocked", method: this.method! };
    return true;
  }

  /**
   * Resolve the wrapped-LAK state, preferring the storage's richer
   * `probeWrappedLak()` (which separates a genuine "absent" from an unreadable
   * envelope). Implementations that only supply `loadWrappedLak()` fall back to
   * the legacy null→absent mapping; that is safe for the in-memory test mocks
   * because they never throw, but the production adapter MUST implement the
   * probe so a real disk read error surfaces as `error`, not `absent`.
   */
  private async probeWrapped(): Promise<WrappedLakProbe> {
    if (this.storage.probeWrappedLak) {
      return this.storage.probeWrappedLak();
    }
    const wrapped = await this.storage.loadWrappedLak();
    return wrapped ? { kind: "present", blob: wrapped } : { kind: "absent" };
  }

  /** True if the cipher is unlocked and ready. */
  isReady(): boolean {
    return this.cryptoKey !== null;
  }

  /** Current status, suitable for surfacing in UI. */
  getStatus(): AtRestStatus {
    return this.status;
  }

  /** Wipe LAK from memory. Subsequent reads/writes will fail until re-init. */
  lock(): void {
    if (this.lak) {
      this.lak.fill(0);
      this.lak = null;
    }
    this.cryptoKey = null;
    if (this.method) {
      this.status = { kind: "locked", method: this.method === "ephemeral" ? "localstorage-fallback" : this.method };
    } else {
      this.status = { kind: "uninitialized" };
    }
  }

  /**
   * Reset all on-disk key material. Used when the user runs "Decrypt vault at
   * rest" before disabling the plugin: after the vault is decrypted there's
   * no reason to keep the wrapped key around.
   */
  async reset(): Promise<void> {
    this.lock();
    await this.storage.clearWrappedLak();
    try {
      await this.storage.clearFallbackKek?.();
    } catch {
      // Vault-local fallback storage unavailable in some hosts (tests) — ignore.
    }
    this.status = { kind: "uninitialized" };
  }

  // ─── PIN-lock seam (Phase 12) ──────────────────────────────────────────────
  //
  // These four methods let a PIN own the LAK without standing up a parallel
  // crypto path. They are DORMANT until the lock loop + enrollment UI wire them
  // (Plans 04/05); nothing here changes runtime behaviour on its own.

  /**
   * Export a defensive COPY of the raw 32-byte LAK.
   *
   * Used by the PIN-enroll flow (Plan 05) to hand the LAK to
   * `PinLockManager.enroll`, which wraps it under a PIN-derived key. Returns a
   * copy so callers can zero their buffer without corrupting the cipher's live
   * key. Throws when locked — there is no LAK to export.
   */
  exportLakBytes(): Uint8Array {
    if (!this.lak) {
      throw new Error("AtRestCipher: cannot export LAK while locked. Unlock first.");
    }
    return this.lak.slice();
  }

  /**
   * Adopt a raw LAK (e.g. one a PIN just unwrapped) and become `unlocked`
   * WITHOUT persisting a safeStorage wrap.
   *
   * This is the PIN-unlock entry point. It deliberately does NOT mirror
   * `restoreFromRecoveryCode`, which re-wraps the LAK via safeStorage and
   * recreates `lak.envelope`. Recreating that transparent wrap would restore a
   * PIN-free auto-unwrap path on the next cold start and silently defeat D2
   * ("undecryptable without the PIN"). While a PIN is enrolled the authoritative
   * wrap is `lak-pin.envelope` (owned by PinLockManager); the transparent
   * `lak.envelope` must stay gone. NON-NEGOTIABLE #1.
   */
  async unlockWithLak(bytes: Uint8Array): Promise<void> {
    if (bytes.length !== KEY_LEN) {
      throw new Error(
        `AtRestCipher: unlockWithLak expects a ${KEY_LEN}-byte LAK, got ${bytes.length}.`
      );
    }
    // The cipher may be unlocking straight from a locked / failed-init state, so
    // ensure safeStorage has been probed (mirrors restoreFromRecoveryCode :518).
    if (!this.safeStorage) this.safeStorage = probeSafeStorage();

    if (this.lak) this.lak.fill(0);
    this.lak = bytes.slice();

    this.cryptoKey = await crypto.subtle.importKey(
      "raw",
      this.lak as BufferSource,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );

    // Record which tier we would wrap under IF a transparent wrap existed — but
    // do NOT create one here (no wrapLakBytes / saveWrappedLak call).
    const method = this.safeStorage?.isEncryptionAvailable()
      ? "safe-storage"
      : "localstorage-fallback";
    this.method = method;
    this.status = { kind: "unlocked", method };
  }

  /**
   * Remove `lak.envelope` while staying unlocked — used when a PIN takes
   * ownership of the LAK; the PIN envelope (`lak-pin.envelope`) is written
   * separately by PinLockManager. Contrast `reset()`, which locks first: here
   * the in-memory LAK stays live so the user keeps working. Enroll half of
   * NON-NEGOTIABLE #1.
   */
  async clearPersistedWrap(): Promise<void> {
    await this.storage.clearWrappedLak();
  }

  /**
   * Re-create `lak.envelope` from the live in-memory LAK. Reverses
   * `clearPersistedWrap()` when a PIN is disabled, restoring the transparent
   * safeStorage auto-unwrap. Disable half of NON-NEGOTIABLE #1. Throws when
   * locked — there is no LAK to wrap.
   */
  async persistWrappedLak(): Promise<void> {
    if (!this.lak) {
      throw new Error("AtRestCipher: cannot persist wrapped LAK while locked. Unlock first.");
    }
    const blob = await this.wrapLakBytes(this.lak);
    await this.storage.saveWrappedLak(blob);
  }

  /**
   * Returns true if `bytes` looks like a VaultGuard at-rest-encrypted file.
   * Cheap (4-byte magic check). Used to gate decryption — anything that
   * doesn't match is treated as legacy plaintext.
   */
  isEncrypted(bytes: ArrayBuffer | Uint8Array): boolean {
    const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    if (view.length < HEADER_LEN + NONCE_LEN + TAG_LEN) return false;
    for (let i = 0; i < MAGIC.length; i++) {
      if (view[i] !== MAGIC[i]) return false;
    }
    return view[4] === VERSION;
  }

  /** Encrypt a UTF-8 string and return the on-disk byte layout. */
  async encryptString(plaintext: string): Promise<ArrayBuffer> {
    const data = new TextEncoder().encode(plaintext);
    return this.encryptBytes(data);
  }

  /** Decrypt an on-disk blob back to the original UTF-8 string. */
  async decryptString(encrypted: ArrayBuffer | Uint8Array): Promise<string> {
    const plaintext = await this.decryptBytes(encrypted);
    return new TextDecoder().decode(plaintext);
  }

  /** Encrypt arbitrary bytes (used for binary attachments). */
  async encryptBinary(plaintext: ArrayBuffer | Uint8Array): Promise<ArrayBuffer> {
    const view = plaintext instanceof Uint8Array ? plaintext : new Uint8Array(plaintext);
    return this.encryptBytes(view);
  }

  /** Decrypt arbitrary bytes back to plaintext. */
  async decryptBinary(encrypted: ArrayBuffer | Uint8Array): Promise<ArrayBuffer> {
    return this.decryptBytes(encrypted);
  }

  // ─── internal: encryption ──────────────────────────────────────────────────

  private async encryptBytes(data: Uint8Array): Promise<ArrayBuffer> {
    if (!this.cryptoKey) {
      throw new Error("AtRestCipher: not initialised. Call init() first.");
    }
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
    const ciphertext = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce as BufferSource },
        this.cryptoKey,
        data as BufferSource
      )
    );

    const out = new Uint8Array(HEADER_LEN + NONCE_LEN + ciphertext.length);
    out.set(MAGIC, 0);
    out[4] = VERSION;
    // bytes 5..7 reserved (already zero)
    out.set(nonce, HEADER_LEN);
    out.set(ciphertext, HEADER_LEN + NONCE_LEN);
    return out.buffer;
  }

  private async decryptBytes(input: ArrayBuffer | Uint8Array): Promise<ArrayBuffer> {
    if (!this.cryptoKey) {
      throw new Error("AtRestCipher: not initialised. Call init() first.");
    }
    const view = input instanceof Uint8Array ? input : new Uint8Array(input);
    if (!this.isEncrypted(view)) {
      throw new Error("AtRestCipher: bytes do not have the expected magic header.");
    }
    const nonce = view.slice(HEADER_LEN, HEADER_LEN + NONCE_LEN);
    const ciphertext = view.slice(HEADER_LEN + NONCE_LEN);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce as BufferSource },
      this.cryptoKey,
      ciphertext as BufferSource
    );
    return plaintext;
  }

  // ─── internal: LAK wrap / unwrap ───────────────────────────────────────────

  /**
   * Wrap raw LAK bytes for on-disk storage. Returns a base64 envelope that
   * includes a method tag so we know how to unwrap later. Format:
   *   "ss:<base64 safeStorage blob>"      (preferred path)
   *   "ls:<nonce(12)>:<ciphertext>"        (vault-local fallback KEK)
   */
  private async wrapLak(lak: Uint8Array): Promise<string> {
    if (this.safeStorage) {
      try {
        const blob = this.safeStorage.encryptString(this.bytesToBase64(lak));
        const buf = blob instanceof Uint8Array ? blob : new Uint8Array(blob);
        this.method = "safe-storage";
        return `ss:${this.bytesToBase64(buf)}`;
      } catch {
        // fall through to vault-local fallback
      }
    }

    // Fallback: encrypt LAK with a per-device key kept in vault-scoped
    // local storage. Worse than safeStorage (the key sits next to the data on
    // disk for an attacker with the entire profile dir) but still defeats
    // bare filesystem inspection of the vault folder.
    const kek = await this.getOrCreateFallbackKek();
    const cryptoKek = await crypto.subtle.importKey(
      "raw",
      kek as BufferSource,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
    const wrapped = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce as BufferSource },
        cryptoKek,
        lak as BufferSource
      )
    );
    return `ls:${this.bytesToBase64(nonce)}:${this.bytesToBase64(wrapped)}`;
  }

  private async unwrapLak(blob: string): Promise<Uint8Array> {
    if (blob.startsWith("ss:")) {
      if (!this.safeStorage) {
        // The wrap was made on a machine with a working keychain; this
        // machine doesn't have one (or it's broken). We can't recover.
        throw new Error(
          "OS keychain (safeStorage) is unavailable on this device — the local at-rest key cannot be unwrapped."
        );
      }
      const wrapped = this.base64ToBytes(blob.slice(3));
      const decoded = this.safeStorage.decryptString(wrapped);
      this.method = "safe-storage";
      return this.base64ToBytes(decoded);
    }
    if (blob.startsWith("ls:")) {
      const [, nonceB64, ctB64] = blob.split(":");
      if (!nonceB64 || !ctB64) {
        throw new Error("Malformed wrapped LAK blob (ls).");
      }
      const nonce = this.base64ToBytes(nonceB64);
      const ct = this.base64ToBytes(ctB64);
      // An `ls:` envelope IS a localstorage-fallback wrap — record the tier now so
      // that even if no KEK unwraps it, a subsequent lock() reports "locked"
      // (localstorage-fallback), not "uninitialized". (Pre-fix, the mint inside
      // getOrCreateFallbackKek set this as a side effect; the read path no longer
      // mints, so set it explicitly.)
      this.method = "localstorage-fallback";

      // READ path: gather every KEK the device can offer and try each. CRITICAL:
      // never mint here. getOrCreateFallbackKek() would mint+persist a fresh KEK
      // when none is *readable* — but `null`/empty conflates "genuinely absent"
      // with "transient read error / torn file", so a single flaky read (common
      // on mobile, where localStorage is also evicted) would overwrite the real,
      // still-recoverable KEK and PERMANENTLY orphan the LAK. A fresh random KEK
      // can never unwrap a pre-existing LAK anyway. If nothing unwraps we throw,
      // and init() routes to needs-recovery — non-destructive and retryable.
      const candidates = await this.loadFallbackKekCandidates();
      if (candidates.length === 0) {
        throw new Error(
          "The device-local fallback KEK is missing or unreadable — cannot unwrap the local at-rest key. This is usually transient (reopen the vault) or recoverable via your recovery code."
        );
      }
      let lastErr: unknown = null;
      for (const kek of candidates) {
        try {
          const cryptoKek = await crypto.subtle.importKey(
            "raw",
            kek as BufferSource,
            { name: "AES-GCM" },
            false,
            ["encrypt", "decrypt"]
          );
          const lak = new Uint8Array(
            await crypto.subtle.decrypt(
              { name: "AES-GCM", iv: nonce as BufferSource },
              cryptoKek,
              ct as BufferSource
            )
          );
          // Heal divergence: converge both homes on the KEK that actually works,
          // so a poisoned/partial localStorage can't keep shadowing the good
          // durable KEK on later loads. Best-effort — never blocks the unwrap.
          if (this.storage.saveFallbackKek) {
            try {
              await this.storage.saveFallbackKek(this.bytesToBase64(kek));
            } catch {
              // ignore — the unwrap already succeeded
            }
          }
          return lak;
        } catch (err) {
          lastErr = err;
        }
      }
      throw new Error(
        `Could not unwrap the local at-rest key with any available device KEK: ${
          lastErr instanceof Error ? lastErr.message : String(lastErr)
        }`
      );
    }
    throw new Error("Unknown wrapped LAK envelope format.");
  }

  /**
   * READ-ONLY fetch of every distinct fallback-KEK candidate, for the unwrap
   * path. NEVER mints or persists (contrast getOrCreateFallbackKek, which the
   * WRAP/provision path uses). Prefers the storage's multi-candidate hook so a
   * divergent localStorage-vs-durable-file pair yields BOTH; falls back to the
   * single-value loadFallbackKek for older/simple storage implementations.
   */
  private async loadFallbackKekCandidates(): Promise<Uint8Array[]> {
    const seen = new Set<string>();
    const out: Uint8Array[] = [];
    const push = (value: string | null | undefined): void => {
      if (typeof value !== "string") return;
      const trimmed = value.trim();
      if (trimmed.length === 0 || seen.has(trimmed)) return;
      seen.add(trimmed);
      out.push(this.base64ToBytes(trimmed));
    };
    if (this.storage.loadFallbackKekCandidates) {
      for (const v of await this.storage.loadFallbackKekCandidates()) push(v);
    } else if (this.storage.loadFallbackKek) {
      push(await this.storage.loadFallbackKek());
    }
    return out;
  }

  /**
   * Read or generate the fallback KEK in vault-scoped storage. The key never leaves
   * the device's Electron profile, but unlike safeStorage it is not bound to
   * the OS keychain — see threat-model docs for the reduced guarantee.
   */
  private async getOrCreateFallbackKek(): Promise<Uint8Array> {
    if (!this.storage.loadFallbackKek || !this.storage.saveFallbackKek) {
      // Tests / headless: derive an ephemeral KEK that lives only in memory.
      // Files written with this mode aren't recoverable across restarts —
      // intentional, because there's no other persistence to bind to.
      this.method = "ephemeral";
      return crypto.getRandomValues(new Uint8Array(KEY_LEN));
    }
    const existing = await this.storage.loadFallbackKek();
    if (existing) {
      this.method = "localstorage-fallback";
      return this.base64ToBytes(existing);
    }
    const fresh = crypto.getRandomValues(new Uint8Array(KEY_LEN));
    await this.storage.saveFallbackKek(this.bytesToBase64(fresh));
    this.method = "localstorage-fallback";
    return fresh;
  }

  // ─── recovery code (export / import) ──────────────────────────────────────

  /**
   * Export the current LAK as a copy-pasteable recovery code.
   *
   * The code IS the key — anyone holding the string can decrypt every
   * encrypted file in the vault. Treat it like a password manager master
   * password: write it down once, store it somewhere offline, never share
   * it. The plugin only ever shows it to the user; it is never persisted
   * or transmitted.
   *
   * Format: `VG1-XXXX-XXXX-...-XXXX` where each `XXXX` is 4 hex chars.
   * 64 hex chars = 32-byte LAK; trailing 4 hex chars = a 2-byte SHA-256
   * checksum that catches transcription errors at restore time.
   *
   * Throws when the cipher is not unlocked — there is no LAK to export.
   */
  async exportRecoveryCode(): Promise<string> {
    if (!this.lak) {
      throw new Error(
        "AtRestCipher: cannot export recovery code while locked. Unlock first."
      );
    }
    const lakHex = this.bytesToHex(this.lak);
    const checksum = await this.recoveryChecksum(this.lak);
    const checksumHex = this.bytesToHex(checksum);
    const groups = this.groupBy(lakHex + checksumHex, 4);
    return `${RECOVERY_CODE_PREFIX}-${groups.join("-")}`;
  }

  /**
   * Restore the LAK from a recovery code, validate the checksum, and
   * re-wrap it with the local KEK so subsequent loads work normally on
   * this device.
   *
   * Returns false on any malformed input so the UI can render a generic
   * "invalid code" error without leaking which part failed (length /
   * checksum / prefix). Returns true on success and leaves the cipher
   * unlocked and ready for read/write.
   *
   * Idempotent: calling with the *same* code that produced the current
   * LAK is a no-op success. Calling with a *different* code replaces the
   * LAK — any files already encrypted with the old key will become
   * undecodable, which is by design (it's the same as restoring a wrong
   * backup).
   */
  async restoreFromRecoveryCode(code: string): Promise<boolean> {
    const stripped = code.replace(/\s+/g, "").toUpperCase();
    if (!stripped.startsWith(`${RECOVERY_CODE_PREFIX}-`)) return false;

    const body = stripped.slice(RECOVERY_CODE_PREFIX.length + 1).replace(/-/g, "");
    const expectedLen = (KEY_LEN + RECOVERY_CHECKSUM_BYTES) * 2;
    if (body.length !== expectedLen) return false;
    if (!/^[0-9A-F]+$/.test(body)) return false;

    const lakHex = body.slice(0, KEY_LEN * 2);
    const checksumHex = body.slice(KEY_LEN * 2);
    const candidate = this.hexToBytes(lakHex);
    const expected = await this.recoveryChecksum(candidate);
    if (this.bytesToHex(expected).toUpperCase() !== checksumHex) {
      return false;
    }

    // Probe safeStorage in case it wasn't probed yet (e.g. the cipher
    // failed init and the caller is restoring directly).
    if (!this.safeStorage) this.safeStorage = probeSafeStorage();

    const blob = await this.wrapLakBytes(candidate);
    await this.storage.saveWrappedLak(blob);

    if (this.lak) this.lak.fill(0);
    this.lak = candidate;
    this.cryptoKey = await crypto.subtle.importKey(
      "raw",
      this.lak as BufferSource,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
    this.status = { kind: "unlocked", method: this.method! };
    return true;
  }

  /**
   * Two-byte SHA-256 checksum used by the recovery-code format. Cheap and
   * sufficient: collisions are 1 in 65k, more than enough to flag
   * transcription errors. Not a security primitive — the cryptographic
   * authenticity comes from AES-GCM at decrypt time.
   */
  private async recoveryChecksum(bytes: Uint8Array): Promise<Uint8Array> {
    const digest = await crypto.subtle.digest(
      "SHA-256",
      bytes as BufferSource
    );
    return new Uint8Array(digest).slice(0, RECOVERY_CHECKSUM_BYTES);
  }

  /**
   * Wrap raw LAK bytes using whichever method is available on this device.
   * Extracted so `restoreFromRecoveryCode` can persist after import without
   * duplicating the safeStorage / fallback dance in `wrapLak`.
   */
  private async wrapLakBytes(lak: Uint8Array): Promise<string> {
    return this.wrapLak(lak);
  }

  // ─── tiny base64 helpers (avoid Buffer dependency for browser parity) ─────

  private bytesToBase64(bytes: Uint8Array): string {
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return typeof btoa === "function"
      ? btoa(bin)
      : Buffer.from(bin, "binary").toString("base64");
  }

  private base64ToBytes(b64: string): Uint8Array {
    const bin =
      typeof atob === "function"
        ? atob(b64)
        : Buffer.from(b64, "base64").toString("binary");
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  private bytesToHex(bytes: Uint8Array): string {
    let out = "";
    for (let i = 0; i < bytes.length; i++) {
      out += bytes[i].toString(16).padStart(2, "0");
    }
    return out;
  }

  private hexToBytes(hex: string): Uint8Array {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return out;
  }

  private groupBy(s: string, n: number): string[] {
    const out: string[] = [];
    for (let i = 0; i < s.length; i += n) out.push(s.slice(i, i + n));
    return out;
  }
}
