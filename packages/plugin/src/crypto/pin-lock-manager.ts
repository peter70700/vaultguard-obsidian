/**
 * VaultGuard - PIN Lock Manager (Phase 12, vault idle-lock)
 *
 * Wraps the 32-byte Local At-rest Key (LAK) under a user-chosen PIN /
 * passphrase so a locked vault is genuinely undecryptable without the secret,
 * even with full disk + OS access (decision D2). This is the PIN cryptographic
 * foundation with ZERO plugin/UI wiring — later waves (Plans 04/05) reach it
 * from `main.ts` and the settings UI. Nothing here runs at load time yet.
 *
 * Wrap scheme (all native crypto.subtle — no dependencies, no network):
 *
 *   PDK  = HKDF-SHA256( ikm = PBKDF2-SHA256(secret, salt, 600k, 256b),
 *                       salt = pepper,           // 32 random bytes, OS-keychain held
 *                       info = "vaultguard-pin-lock-v1" ) → AES-256-GCM key
 *   ct   = AES-256-GCM( PDK, nonce, LAK )
 *   envelope (lak-pin.envelope) = { v, kdf, iters, salt, nonce, ct }   (base64)
 *
 * Why two KDF inputs (PIN + pepper): a stolen disk/backup WITHOUT the OS
 * keychain cannot even begin an offline PIN brute-force, because the pepper is
 * a required second input and lives in the keychain (cold-disk-theft defense).
 * A full-OS-access attacker can read the pepper and brute-force a short PIN —
 * that residual is inherent to any short local secret and is documented as
 * out of scope in docs/AT-REST-ENCRYPTION.md; we blunt it by allowing an
 * alphanumeric passphrase (PIN_MIN_LENGTH, no digit restriction).
 *
 * Wrong-PIN detection is ONLY the AES-GCM auth-tag failure on unwrap — there is
 * NO stored PIN hash / verifier anywhere, so there is no oracle to leak.
 *
 * Canonical references: 12-RESEARCH.md ("Wrap Scheme", "Storage Layout",
 * "Local Rate-Limiting"), docs/AT-REST-ENCRYPTION.md.
 */

import type { SafeStorageLike } from "./safe-storage";

// ─── Constants ────────────────────────────────────────────────────────────────

/**
 * Minimum secret length. A "PIN" here may be a full alphanumeric passphrase —
 * we deliberately do NOT restrict to digits, to blunt offline brute-force by a
 * full-OS-access attacker who can read the pepper (12-RESEARCH.md Pitfall 3).
 */
export const PIN_MIN_LENGTH = 6;

/**
 * PBKDF2-HMAC-SHA256 iteration count. 600,000 is the OWASP current
 * recommendation and the FIPS-140 floor, and matches the repo's existing
 * constant (src/crypto/passphrase-manager.ts:26).
 */
export const PBKDF2_ITERATIONS = 600_000;

/** Random PBKDF2 salt length (bytes). */
export const PIN_SALT_BYTES = 16;

/** Device pepper length (bytes) — the safeStorage-held second KDF input. */
export const PEPPER_BYTES = 32;

/**
 * Wrong-PIN attempts before the caller must force a full logout. When the
 * counter reaches this cap, `unlock` returns reason "locked-out" (the signal
 * the lock loop turns into a `forceLogout` in Plan 04/05).
 */
export const MAX_FAILED_ATTEMPTS = 5;

/**
 * Backoff window (ms) imposed once the counter is within one attempt of
 * MAX_FAILED_ATTEMPTS. Schedule:
 *   attempts 1 .. MAX-2  → reason "wrong", no delay
 *   attempt  MAX-1       → reason "wrong", a LOCKOUT_BACKOFF_MS delay before the
 *                          final try (slows the last guesses)
 *   attempt  MAX         → reason "locked-out", LOCKOUT_BACKOFF_MS window
 * The window is persisted (lockedUntil), so killing the app during backoff
 * cannot reset it (Pitfall 5).
 */
export const LOCKOUT_BACKOFF_MS = 30_000;

/** AES-GCM nonce length (bytes). */
const NONCE_LEN = 12;

/** HKDF domain-separation label for the PIN-lock wrapping key. */
const HKDF_INFO = "vaultguard-pin-lock-v1";

// ─── Types ────────────────────────────────────────────────────────────────────

/**
 * Persisted lock state. Lives in data.json (an excluded, non-at-rest path).
 * Non-secret: the salt is in the envelope, the wrapping key is only the
 * PIN + pepper. `failedAttempts` / `lockedUntil` are the persisted rate-limit
 * counter that must survive an app kill.
 */
export interface PinLockState {
  enrolled: boolean;
  failedAttempts: number;
  lockedUntil: number | null;
}

/**
 * Storage seam. The plugin wires these to `lak-pin.envelope` (via
 * vaultConfigPath), the safeStorage-wrapped pepper, and the `pinLock` slice of
 * data.json in Plans 04/05. Tests inject in-memory mocks — the same
 * injected-storage discipline AtRestCipher uses.
 */
export interface PinLockStorage {
  /** Read the PIN envelope JSON blob, or null if no PIN is enrolled. */
  readEnvelope(): Promise<string | null>;
  /** Persist the PIN envelope JSON blob. */
  writeEnvelope(blob: string): Promise<void>;
  /** Remove the PIN envelope (on disable). */
  clearEnvelope(): Promise<void>;
  /** Read the stored (safeStorage-wrapped, or raw when degraded) pepper blob. */
  readPepper(): Promise<string | null>;
  /** Persist the pepper blob. */
  writePepper(blob: string): Promise<void>;
  /** Remove the pepper (on disable). */
  clearPepper(): Promise<void>;
  /** Load the persisted lock state synchronously (read on construction). */
  loadPinState(): PinLockState;
  /** Persist the lock state (written on every enroll/unlock/disable). */
  savePinState(state: PinLockState): Promise<void>;
}

/** On-disk PIN envelope (lak-pin.envelope). salt/nonce/ct are base64. */
export type PinEnvelopeV1 = {
  v: 1;
  kdf: "pbkdf2-sha256";
  iters: number;
  salt: string;
  nonce: string;
  ct: string;
};

/**
 * Result of an unlock attempt. On success the raw LAK is handed back (the
 * caller passes it to `AtRestCipher.unlockWithLak`). On failure NO key material
 * is returned; `reason` distinguishes a wrong secret from a lockout.
 */
export type UnlockResult =
  | { ok: true; lak: Uint8Array }
  | {
      ok: false;
      reason: "wrong" | "locked-out";
      failedAttempts: number;
      lockedUntil: number | null;
    };

// ─── PinLockManager ────────────────────────────────────────────────────────────

export class PinLockManager {
  private state: PinLockState;

  constructor(
    private readonly storage: PinLockStorage,
    private readonly safeStorage: SafeStorageLike | null
  ) {
    // Read the persisted rate-limit counter synchronously so a fresh instance
    // (a restarted app) starts from the last saved state, not a clean slate.
    this.state = storage.loadPinState();
  }

  /** True if a PIN is currently enrolled on this device. */
  isEnrolled(): boolean {
    return this.state.enrolled;
  }

  /**
   * Enroll a PIN: wrap the raw LAK under a PIN-derived key and persist the
   * envelope. Called while the cipher is UNLOCKED (LAK in memory). Rejects a
   * secret shorter than PIN_MIN_LENGTH. The secret and derived key are dropped
   * when this returns — never persisted.
   */
  async enroll(secret: string, lak: Uint8Array): Promise<void> {
    if (secret.length < PIN_MIN_LENGTH) {
      throw new Error(
        `PinLockManager: secret must be at least ${PIN_MIN_LENGTH} characters.`
      );
    }
    const salt = crypto.getRandomValues(new Uint8Array(PIN_SALT_BYTES));
    const pepper = await this.getOrCreatePepper();
    const pdk = await this.derivePdk(secret, salt, pepper);

    const nonce = crypto.getRandomValues(new Uint8Array(NONCE_LEN));
    const ct = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce as BufferSource },
        pdk,
        lak as BufferSource
      )
    );

    const envelope: PinEnvelopeV1 = {
      v: 1,
      kdf: "pbkdf2-sha256",
      iters: PBKDF2_ITERATIONS,
      salt: this.bytesToBase64(salt),
      nonce: this.bytesToBase64(nonce),
      ct: this.bytesToBase64(ct),
    };
    await this.storage.writeEnvelope(JSON.stringify(envelope));

    this.state = { enrolled: true, failedAttempts: 0, lockedUntil: null };
    await this.storage.savePinState(this.state);
  }

  /**
   * Attempt to unlock with a secret. On success returns the raw LAK and resets
   * the failure counter. On a wrong secret (the ONLY failure signal is the
   * AES-GCM auth-tag rejecting) increments the persisted counter and, at the
   * cap, returns reason "locked-out". A missing envelope is treated exactly
   * like a wrong secret (no oracle: an attacker can't distinguish
   * not-enrolled from wrong-PIN).
   */
  async unlock(secret: string): Promise<UnlockResult> {
    const now = Date.now();

    // Persisted lockout guard — survives an app kill (Pitfall 5).
    if (this.state.lockedUntil !== null && now < this.state.lockedUntil) {
      return {
        ok: false,
        reason: "locked-out",
        failedAttempts: this.state.failedAttempts,
        lockedUntil: this.state.lockedUntil,
      };
    }

    const raw = await this.storage.readEnvelope();
    if (raw === null) {
      return this.registerFailure(now);
    }

    let envelope: PinEnvelopeV1;
    try {
      envelope = JSON.parse(raw) as PinEnvelopeV1;
    } catch {
      return this.registerFailure(now);
    }

    const salt = this.base64ToBytes(envelope.salt);
    const nonce = this.base64ToBytes(envelope.nonce);
    const ct = this.base64ToBytes(envelope.ct);
    const pepper = await this.getOrCreatePepper();
    const pdk = await this.derivePdk(secret, salt, pepper);

    let lakBuf: ArrayBuffer;
    try {
      lakBuf = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonce as BufferSource },
        pdk,
        ct as BufferSource
      );
    } catch {
      // Wrong PIN — the ONLY wrong-detection path. No stored verifier exists.
      return this.registerFailure(now);
    }

    // Correct PIN — reset the rate-limit counter and hand back the LAK.
    this.state = { enrolled: true, failedAttempts: 0, lockedUntil: null };
    await this.storage.savePinState(this.state);
    return { ok: true, lak: new Uint8Array(lakBuf) };
  }

  /**
   * Disable the PIN: clear the envelope + pepper and reset state to
   * not-enrolled. The caller (Plan 05) restores the transparent safeStorage LAK
   * wrap via `AtRestCipher.persistWrappedLak()` — that reversal is the disable
   * half of NON-NEGOTIABLE #1 and lives outside this manager.
   */
  async disable(): Promise<void> {
    await this.storage.clearEnvelope();
    await this.storage.clearPepper();
    this.state = { enrolled: false, failedAttempts: 0, lockedUntil: null };
    await this.storage.savePinState(this.state);
  }

  // ─── internal ────────────────────────────────────────────────────────────────

  /**
   * Increment the persisted failure counter and decide the response per the
   * LOCKOUT_BACKOFF_MS schedule. Always persists before returning so the
   * counter can't be reset by an app kill.
   */
  private async registerFailure(now: number): Promise<UnlockResult> {
    const failedAttempts = this.state.failedAttempts + 1;

    if (failedAttempts >= MAX_FAILED_ATTEMPTS) {
      const lockedUntil = now + LOCKOUT_BACKOFF_MS;
      this.state = { enrolled: this.state.enrolled, failedAttempts, lockedUntil };
      await this.storage.savePinState(this.state);
      return { ok: false, reason: "locked-out", failedAttempts, lockedUntil };
    }

    // Within one attempt of the cap → impose a backoff before the final try.
    const lockedUntil =
      failedAttempts >= MAX_FAILED_ATTEMPTS - 1 ? now + LOCKOUT_BACKOFF_MS : null;
    this.state = { enrolled: this.state.enrolled, failedAttempts, lockedUntil };
    await this.storage.savePinState(this.state);
    return { ok: false, reason: "wrong", failedAttempts, lockedUntil };
  }

  /**
   * Derive the AES-256-GCM wrapping key (PDK): PBKDF2-SHA256(secret) →
   * HKDF-SHA256 combined with the device pepper. Non-extractable.
   */
  private async derivePdk(
    secret: string,
    salt: Uint8Array,
    pepper: Uint8Array
  ): Promise<CryptoKey> {
    const pdkBits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: salt as BufferSource,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256",
      },
      await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(secret) as BufferSource,
        { name: "PBKDF2" },
        false,
        ["deriveBits"]
      ),
      256
    );

    return crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: pepper as BufferSource,
        info: new TextEncoder().encode(HKDF_INFO) as BufferSource,
      },
      await crypto.subtle.importKey("raw", pdkBits, { name: "HKDF" }, false, [
        "deriveKey",
      ]),
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  /**
   * Read or mint the 32-byte device pepper. Preferred path wraps it via
   * safeStorage (OS keychain); the degraded path (no safeStorage) stores the
   * raw base64 pepper — weaker, matching the at-rest degraded tier. Idempotent:
   * a second call returns the same pepper, so re-enrolling reuses one pepper.
   */
  private async getOrCreatePepper(): Promise<Uint8Array> {
    const existing = await this.storage.readPepper();
    if (existing !== null) {
      if (this.safeStorage) {
        const decoded = this.safeStorage.decryptString(this.base64ToBytes(existing));
        return this.base64ToBytes(decoded);
      }
      // Degraded tier: the stored blob is the raw base64 pepper.
      return this.base64ToBytes(existing);
    }

    const pepper = crypto.getRandomValues(new Uint8Array(PEPPER_BYTES));
    if (this.safeStorage) {
      const enc = this.safeStorage.encryptString(this.bytesToBase64(pepper));
      const encBytes = enc instanceof Uint8Array ? enc : new Uint8Array(enc);
      await this.storage.writePepper(this.bytesToBase64(encBytes));
    } else {
      // Degraded tier (documented weaker in docs/AT-REST-ENCRYPTION.md): no OS
      // keychain, so the pepper sits next to the envelope. Still defeats bare
      // cold-disk theft only marginally — the PIN remains the real boundary.
      await this.storage.writePepper(this.bytesToBase64(pepper));
    }
    return pepper;
  }

  // ─── tiny base64 helpers (avoid Buffer dependency for browser parity) ────────

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
}
