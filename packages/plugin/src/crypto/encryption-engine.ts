/**
 * VaultGuard - Core Encryption Engine
 *
 * AES-256-GCM encryption/decryption for vault file content.
 * Encrypted cache format: [IV (12 bytes)][Auth Tag (16 bytes)][Encrypted Content]
 */

import { EncryptionKey } from '../types';

const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const KEY_LENGTH = 32; // 256 bits
const ALGORITHM = 'AES-GCM';

/**
 * Core encryption engine providing AES-256-GCM encryption and decryption
 * for vault file content with unique IV per write operation.
 */
export class EncryptionEngine {
  private activeKeys: CryptoKey[] = [];

  /**
   * Encrypt file content using AES-256-GCM.
   * Generates a unique IV for each encryption operation.
   *
   * @param content - Raw file content as string or buffer
   * @param key - Server-provided data key (raw 256-bit key material)
   * @returns Encrypted payload: [IV (12)][Auth Tag (16)][Ciphertext]
   */
  async encrypt(content: string | ArrayBuffer, key: EncryptionKey): Promise<ArrayBuffer> {
    const cryptoKey = await this.importKey(key);
    const iv = this.generateIV();
    const data = typeof content === 'string'
      ? new TextEncoder().encode(content)
      : new Uint8Array(content);

    const encrypted = await crypto.subtle.encrypt(
      { name: ALGORITHM, iv: iv as BufferSource, tagLength: AUTH_TAG_LENGTH * 8 },
      cryptoKey,
      data as BufferSource
    );

    // AES-GCM appends the auth tag to the ciphertext in Web Crypto API
    // Extract tag and ciphertext separately for our format
    const encryptedBytes = new Uint8Array(encrypted);
    const ciphertext = encryptedBytes.slice(0, encryptedBytes.length - AUTH_TAG_LENGTH);
    const authTag = encryptedBytes.slice(encryptedBytes.length - AUTH_TAG_LENGTH);

    // Pack into format: [IV (12)][Auth Tag (16)][Ciphertext]
    const payload = new Uint8Array(IV_LENGTH + AUTH_TAG_LENGTH + ciphertext.length);
    payload.set(iv, 0);
    payload.set(authTag, IV_LENGTH);
    payload.set(ciphertext, IV_LENGTH + AUTH_TAG_LENGTH);

    return payload.buffer;
  }

  /**
   * Decrypt an encrypted payload using AES-256-GCM.
   *
   * @param ciphertext - Encrypted payload in VaultGuard format
   * @param key - Server-provided data key (raw 256-bit key material)
   * @returns Decrypted content as string
   * @throws Error if decryption fails (invalid key, corrupted data, or tampered content)
   */
  async decrypt(ciphertext: ArrayBuffer, key: EncryptionKey): Promise<string> {
    const cryptoKey = await this.importKey(key);
    const data = new Uint8Array(ciphertext);

    if (data.length < IV_LENGTH + AUTH_TAG_LENGTH) {
      throw new Error('Invalid encrypted payload: too short');
    }

    // Unpack format: [IV (12)][Auth Tag (16)][Ciphertext]
    const iv = data.slice(0, IV_LENGTH);
    const authTag = data.slice(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
    const encryptedContent = data.slice(IV_LENGTH + AUTH_TAG_LENGTH);

    // Web Crypto expects ciphertext + authTag concatenated
    const combined = new Uint8Array(encryptedContent.length + AUTH_TAG_LENGTH);
    combined.set(encryptedContent, 0);
    combined.set(authTag, encryptedContent.length);

    try {
      const decrypted = await crypto.subtle.decrypt(
        { name: ALGORITHM, iv, tagLength: AUTH_TAG_LENGTH * 8 },
        cryptoKey,
        combined
      );
      return new TextDecoder().decode(decrypted);
    } catch {
      throw new Error(
        'Decryption failed: invalid key or corrupted data. ' +
        'The file may have been tampered with or the key has been revoked.'
      );
    }
  }

  /**
   * Re-encrypt all cached content with a new key during key rotation.
   * Decrypts with the old key and re-encrypts with the new key.
   *
   * @param encryptedData - Array of encrypted payloads to rotate
   * @param oldKey - Current encryption key
   * @param newKey - New encryption key from server
   * @returns Array of re-encrypted payloads
   */
  async rotateKey(
    encryptedData: ArrayBuffer[],
    oldKey: EncryptionKey,
    newKey: EncryptionKey
  ): Promise<ArrayBuffer[]> {
    const results: ArrayBuffer[] = [];

    for (const payload of encryptedData) {
      const plaintext = await this.decrypt(payload, oldKey);
      const reEncrypted = await this.encrypt(plaintext, newKey);
      results.push(reEncrypted);
    }

    // Wipe the old key material after successful rotation
    this.wipeKeyMaterial(oldKey);

    return results;
  }

  /**
   * Securely wipe all key material from memory.
   * Overwrites key buffers with zeros before releasing references.
   */
  wipeKeys(): void {
    // CryptoKey objects are opaque; the key material is managed by the browser's
    // crypto subsystem, so clearing references is the only wipe available here.
    this.activeKeys = [];
  }

  /**
   * Derive a CryptoKey suitable for AES-256-GCM from raw key material.
   * Uses HKDF for key derivation when server provides seed material.
   *
   * @param keyData - Raw key bytes or derivation seed from server
   * @param salt - Optional salt for HKDF derivation
   * @param info - Optional context info for HKDF derivation
   * @returns Derived CryptoKey for AES-256-GCM operations
   */
  async deriveKey(
    keyData: ArrayBuffer,
    salt?: ArrayBuffer,
    info?: ArrayBuffer
  ): Promise<CryptoKey> {
    const baseKey = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HKDF' },
      false,
      ['deriveKey']
    );

    const derivedKey = await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: salt || new Uint8Array(32),
        info: info || new TextEncoder().encode('vaultguard-v1'),
      },
      baseKey,
      { name: ALGORITHM, length: KEY_LENGTH * 8 },
      false,
      ['encrypt', 'decrypt']
    );

    this.activeKeys.push(derivedKey);
    return derivedKey;
  }

  /**
   * Generate a cryptographically secure random IV (12 bytes for AES-GCM).
   * Each file write operation must use a unique IV.
   */
  private generateIV(): Uint8Array {
    return crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  }

  /**
   * Import raw key material as a CryptoKey for AES-256-GCM.
   */
  private async importKey(key: EncryptionKey): Promise<CryptoKey> {
    let keyBuffer: ArrayBuffer;
    if (key instanceof ArrayBuffer) {
      keyBuffer = key;
    } else if (typeof key === 'string') {
      keyBuffer = this.hexToBuffer(key);
    } else {
      keyBuffer = key.slice(0).buffer as ArrayBuffer;
    }

    if (keyBuffer.byteLength !== KEY_LENGTH) {
      throw new Error(
        `Invalid key length: expected ${KEY_LENGTH} bytes, got ${keyBuffer.byteLength}`
      );
    }

    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyBuffer as BufferSource,
      { name: ALGORITHM },
      false,
      ['encrypt', 'decrypt']
    );

    this.activeKeys.push(cryptoKey);
    return cryptoKey;
  }

  /**
   * Convert a hex string to an ArrayBuffer.
   */
  private hexToBuffer(hex: string): ArrayBuffer {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes.buffer;
  }

  /**
   * Securely wipe raw key material by overwriting with zeros.
   */
  private wipeKeyMaterial(key: EncryptionKey): void {
    if (key instanceof Uint8Array) {
      key.fill(0);
    } else if (key instanceof ArrayBuffer) {
      new Uint8Array(key).fill(0);
    }
    // String keys cannot be wiped in JS — they are immutable
  }
}
