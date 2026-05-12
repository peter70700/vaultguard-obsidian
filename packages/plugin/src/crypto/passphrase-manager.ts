/**
 * VaultGuard - Passphrase-Based Key Management (Hybrid ZK — Phase 5)
 *
 * Handles client-side key derivation for the hybrid zero-knowledge model.
 * The server never sees the User Master Key (UMK), passphrase, or derived DEKs.
 *
 * Key hierarchy:
 *   Passphrase → PBKDF2 → Passphrase Key → AES-KW unwrap → UMK → HKDF → DEK
 *
 * Note: Uses PBKDF2 as an interim key derivation function. Production deployments
 * should migrate to Argon2id via argon2-browser WASM for memory-hard derivation.
 * The algorithm field in the escrow record tracks which KDF was used.
 */

import { EncryptionKey } from '../types';

// ─── Constants ──────────────────────────────────────────────────────────────

/** PBKDF2 iterations (interim until Argon2id WASM is integrated) */
const PBKDF2_ITERATIONS = 600_000;
const PBKDF2_HASH = 'SHA-256';

/** AES-KW key length for wrapping the UMK */
const AES_KW_KEY_LENGTH = 256;

/** UMK length in bytes */
const UMK_LENGTH = 32;

/** Salt length for new key setup */
const SALT_LENGTH = 32;

/** HKDF info prefix for deriving file DEKs from UMK */
const HKDF_DEK_INFO = 'vaultguard-file-encryption-v1';

// ─── Types ──────────────────────────────────────────────────────────────────

/** Result of the ZK setup process, to be sent to the server. */
export interface ZkSetupResult {
  /** UMK wrapped with the passphrase-derived key (base64) */
  wrappedUMK_user: string;
  /** UMK wrapped with the org recovery public key (base64) */
  wrappedUMK_org: string;
  /** Salt used for passphrase key derivation (base64) */
  argon2Salt: string;
  /** Algorithm identifier for the escrow record */
  algorithm: string;
}

/** Material needed for daily ZK login, fetched from the server. */
export interface ZkLoginMaterial {
  wrappedUMK_user: string;
  argon2Salt: string;
  algorithm: string;
}

// ─── PassphraseManager ──────────────────────────────────────────────────────

/**
 * Manages passphrase-based key derivation for the hybrid ZK model.
 * All cryptographic operations happen locally — nothing leaves the client.
 */
export class PassphraseManager {
  private umk: CryptoKey | null = null;
  /** Raw UMK bytes kept for re-wrapping during passphrase changes. Zeroed on lock(). */
  private umkRaw: Uint8Array | null = null;

  /**
   * Set up hybrid ZK for a new user or passphrase change.
   *
   * 1. Generate a random UMK
   * 2. Derive a wrapping key from the passphrase
   * 3. Wrap UMK with the passphrase key (for daily login)
   * 4. Wrap UMK with the org recovery public key (for admin recovery)
   *
   * @param passphrase - User-chosen passphrase
   * @param orgRecoveryPublicKey - Org's RSA-OAEP public key (for admin recovery)
   * @returns ZkSetupResult to be stored on the server
   */
  async setup(
    passphrase: string,
    orgRecoveryPublicKey: CryptoKey
  ): Promise<ZkSetupResult> {
    // Generate random salt
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));

    // Generate random UMK
    const umkRaw = crypto.getRandomValues(new Uint8Array(UMK_LENGTH));

    // Derive passphrase wrapping key
    const passphraseKey = await this.derivePassphraseKey(passphrase, salt);

    // Import UMK as a CryptoKey for AES-KW wrapping
    const umkForWrap = await crypto.subtle.importKey(
      'raw',
      umkRaw,
      { name: 'AES-GCM', length: AES_KW_KEY_LENGTH },
      true, // extractable for wrapping
      ['encrypt', 'decrypt']
    );

    // Wrap UMK with passphrase key (AES-KW)
    const wrappedUMK_user = await crypto.subtle.wrapKey(
      'raw',
      umkForWrap,
      passphraseKey,
      'AES-KW'
    );

    // Wrap UMK with org recovery key (RSA-OAEP)
    const wrappedUMK_org = await crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      orgRecoveryPublicKey,
      umkRaw
    );

    // Store raw UMK bytes for re-wrapping on passphrase change
    this.umkRaw = new Uint8Array(umkRaw);

    // Store the UMK as HKDF key for immediate use
    this.umk = await crypto.subtle.importKey(
      'raw',
      umkRaw,
      { name: 'HKDF' },
      false,
      ['deriveKey']
    );

    // Zero out the local variable (this.umkRaw retains the copy)
    umkRaw.fill(0);

    return {
      wrappedUMK_user: this.bufferToBase64(wrappedUMK_user),
      wrappedUMK_org: this.bufferToBase64(wrappedUMK_org),
      argon2Salt: this.bufferToBase64(salt.buffer),
      algorithm: 'pbkdf2+aes-kw',
    };
  }

  /**
   * Login with passphrase: derive key, unwrap UMK from server-provided material.
   *
   * @param passphrase - User's passphrase
   * @param material - Wrapped key material from the server
   * @returns true if unwrap succeeded (passphrase correct)
   */
  async login(passphrase: string, material: ZkLoginMaterial): Promise<boolean> {
    const salt = this.base64ToBuffer(material.argon2Salt);
    const wrappedUMK = this.base64ToBuffer(material.wrappedUMK_user);

    const passphraseKey = await this.derivePassphraseKey(passphrase, new Uint8Array(salt));

    try {
      // First unwrap as extractable AES-GCM to capture raw bytes for re-wrapping
      const umkExtractable = await crypto.subtle.unwrapKey(
        'raw',
        wrappedUMK,
        passphraseKey,
        'AES-KW',
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      );

      // Export raw bytes for passphrase change support
      const rawBytes = await crypto.subtle.exportKey('raw', umkExtractable);
      this.umkRaw = new Uint8Array(rawBytes);

      // Re-import as non-extractable HKDF key for DEK derivation
      this.umk = await crypto.subtle.importKey(
        'raw',
        rawBytes,
        { name: 'HKDF' },
        false,
        ['deriveKey']
      );

      return true;
    } catch {
      // Unwrap failed — wrong passphrase
      return false;
    }
  }

  /**
   * Derive a file encryption key (DEK) from the UMK using HKDF.
   * Each scope gets a unique DEK derived from the same UMK.
   *
   * @param scope - Path scope for key derivation context (e.g., '/engineering/**')
   * @returns AES-256-GCM key for encrypting/decrypting files in this scope
   */
  async deriveDek(scope: string = '/**'): Promise<EncryptionKey> {
    if (!this.umk) {
      throw new Error('UMK not available. Call setup() or login() first.');
    }

    const info = new TextEncoder().encode(`${HKDF_DEK_INFO}:${scope}`);

    const dek = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(32), // Static salt — scope provides domain separation
        info,
      },
      this.umk,
      { name: 'AES-GCM', length: 256 },
      true, // extractable to get raw bytes
      ['encrypt', 'decrypt']
    );

    // Export to raw bytes for EncryptionEngine compatibility
    const rawKey = await crypto.subtle.exportKey('raw', dek);
    return rawKey;
  }

  /**
   * Check if the UMK is currently loaded in memory.
   */
  isUnlocked(): boolean {
    return this.umk !== null;
  }

  /**
   * Wipe the UMK from memory. Called on lock/logout.
   */
  lock(): void {
    if (this.umkRaw) {
      this.umkRaw.fill(0);
      this.umkRaw = null;
    }
    this.umk = null;
  }

  /**
   * Import an RSA-OAEP public key from base64-encoded SPKI format.
   * Used for importing the org recovery public key.
   */
  async importOrgPublicKey(base64Spki: string): Promise<CryptoKey> {
    const spkiBuffer = this.base64ToBuffer(base64Spki);
    return crypto.subtle.importKey(
      'spki',
      spkiBuffer,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['encrypt']
    );
  }

  /**
   * Change the passphrase without changing the UMK.
   * Re-wraps the existing UMK with a new passphrase-derived key.
   *
   * @param newPassphrase - The new passphrase
   * @returns New wrappedUMK_user and salt to send to the server
   */
  async changePassphrase(
    newPassphrase: string
  ): Promise<{ wrappedUMK_user: string; argon2Salt: string }> {
    if (!this.umkRaw) {
      throw new Error('UMK not available. Call login() or setup() first.');
    }

    const newSalt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
    const newPassphraseKey = await this.derivePassphraseKey(newPassphrase, newSalt);

    // Import the original UMK raw bytes as a wrappable key
    const umkForWrap = await crypto.subtle.importKey(
      'raw',
      this.umkRaw as BufferSource,
      { name: 'AES-GCM', length: AES_KW_KEY_LENGTH },
      true,
      ['encrypt', 'decrypt']
    );

    // Wrap the original UMK with the new passphrase-derived key
    const wrappedUMK_user = await crypto.subtle.wrapKey(
      'raw',
      umkForWrap,
      newPassphraseKey,
      'AES-KW'
    );

    return {
      wrappedUMK_user: this.bufferToBase64(wrappedUMK_user),
      argon2Salt: this.bufferToBase64(newSalt.buffer),
    };
  }

  // ─── Private Helpers ────────────────────────────────────────────────────────

  /**
   * Derive a wrapping key from a passphrase using PBKDF2.
   * Returns an AES-KW CryptoKey suitable for wrapping/unwrapping the UMK.
   */
  private async derivePassphraseKey(
    passphrase: string,
    salt: Uint8Array
  ): Promise<CryptoKey> {
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(passphrase),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt as BufferSource,
        iterations: PBKDF2_ITERATIONS,
        hash: PBKDF2_HASH,
      },
      keyMaterial,
      { name: 'AES-KW', length: AES_KW_KEY_LENGTH },
      false,
      ['wrapKey', 'unwrapKey']
    );
  }

  private bufferToBase64(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  private base64ToBuffer(base64: string): ArrayBuffer {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }
}
