/**
 * EncryptionEngine test suite
 *
 * Covers:
 * - AES-256-GCM encrypt/decrypt roundtrip
 * - Payload binary format: [IV (12)][AuthTag (16)][Ciphertext]
 * - Unique IV per encryption (no IV reuse)
 * - Decryption with wrong key fails with descriptive error
 * - Decryption of truncated/corrupted payload fails
 * - Key rotation re-encrypts data correctly
 * - wipeKeys() clears activeKeys array
 * - Key length validation
 * - Multiple key types: ArrayBuffer, Uint8Array, hex string
 * - deriveKey() via HKDF
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { EncryptionEngine } from '../src/crypto/encryption-engine';

// Helper: generate a random 256-bit key as ArrayBuffer
function randomKey(): ArrayBuffer {
  return crypto.getRandomValues(new Uint8Array(32)).buffer as ArrayBuffer;
}

// Helper: convert ArrayBuffer to hex string
function bufferToHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

describe('EncryptionEngine', () => {
  let engine: EncryptionEngine;

  beforeEach(() => {
    engine = new EncryptionEngine();
  });

  // ── Encrypt / Decrypt Roundtrip ────────────────────────────────────────────

  describe('encrypt/decrypt roundtrip', () => {
    it('roundtrips a string through encrypt → decrypt', async () => {
      const key = randomKey();
      const plaintext = 'Hello, VaultGuard!';

      const encrypted = await engine.encrypt(plaintext, key);
      const decrypted = await engine.decrypt(encrypted, key);

      expect(decrypted).toBe(plaintext);
    });

    it('roundtrips an empty string', async () => {
      const key = randomKey();
      const encrypted = await engine.encrypt('', key);
      const decrypted = await engine.decrypt(encrypted, key);
      expect(decrypted).toBe('');
    });

    it('roundtrips a large string (10 KB)', async () => {
      const key = randomKey();
      const plaintext = 'x'.repeat(10_000);
      const encrypted = await engine.encrypt(plaintext, key);
      const decrypted = await engine.decrypt(encrypted, key);
      expect(decrypted).toBe(plaintext);
    });

    it('roundtrips unicode content', async () => {
      const key = randomKey();
      const plaintext = '日本語テスト 🔐 مرحبا';
      const encrypted = await engine.encrypt(plaintext, key);
      const decrypted = await engine.decrypt(encrypted, key);
      expect(decrypted).toBe(plaintext);
    });

    it('roundtrips markdown content with frontmatter', async () => {
      const key = randomKey();
      const plaintext = `---
title: Secret Note
tags: [private, encrypted]
---

# My Secret Note

This is **encrypted** content with [links](https://example.com).

- Item 1
- Item 2
`;
      const encrypted = await engine.encrypt(plaintext, key);
      const decrypted = await engine.decrypt(encrypted, key);
      expect(decrypted).toBe(plaintext);
    });

    it('accepts ArrayBuffer content input', async () => {
      const key = randomKey();
      const plaintext = 'binary input test';
      const inputBuffer = new TextEncoder().encode(plaintext).buffer;

      const encrypted = await engine.encrypt(inputBuffer, key);
      const decrypted = await engine.decrypt(encrypted, key);
      expect(decrypted).toBe(plaintext);
    });
  });

  // ── Key Types ──────────────────────────────────────────────────────────────

  describe('key type support', () => {
    const plaintext = 'key type test';

    it('works with ArrayBuffer keys', async () => {
      const key = randomKey();
      const encrypted = await engine.encrypt(plaintext, key);
      expect(await engine.decrypt(encrypted, key)).toBe(plaintext);
    });

    it('works with Uint8Array keys', async () => {
      const keyBytes = crypto.getRandomValues(new Uint8Array(32));
      const encrypted = await engine.encrypt(plaintext, keyBytes);
      expect(await engine.decrypt(encrypted, keyBytes)).toBe(plaintext);
    });

    it('works with hex string keys', async () => {
      const keyBuf = randomKey();
      const hexKey = bufferToHex(keyBuf);
      const encrypted = await engine.encrypt(plaintext, hexKey);
      expect(await engine.decrypt(encrypted, hexKey)).toBe(plaintext);
    });
  });

  // ── Payload Format ─────────────────────────────────────────────────────────

  describe('payload format', () => {
    it('produces payload with IV (12) + AuthTag (16) + Ciphertext', async () => {
      const key = randomKey();
      const encrypted = await engine.encrypt('test', key);
      const bytes = new Uint8Array(encrypted);

      // Must be at least IV + AuthTag long
      expect(bytes.length).toBeGreaterThan(12 + 16);
    });

    it('produces different ciphertext for the same plaintext (unique IV)', async () => {
      const key = randomKey();
      const plaintext = 'same content';

      const enc1 = await engine.encrypt(plaintext, key);
      const enc2 = await engine.encrypt(plaintext, key);

      const bytes1 = new Uint8Array(enc1);
      const bytes2 = new Uint8Array(enc2);

      // IVs (first 12 bytes) must differ
      const iv1 = bytes1.slice(0, 12);
      const iv2 = bytes2.slice(0, 12);
      const ivsMatch = iv1.every((b, i) => b === iv2[i]);
      expect(ivsMatch).toBe(false);
    });
  });

  // ── Decryption Failures ────────────────────────────────────────────────────

  describe('decryption failures', () => {
    it('fails with wrong key', async () => {
      const key1 = randomKey();
      const key2 = randomKey();
      const encrypted = await engine.encrypt('secret', key1);

      await expect(engine.decrypt(encrypted, key2)).rejects.toThrow(
        'Decryption failed: invalid key or corrupted data'
      );
    });

    it('fails with truncated payload (too short)', async () => {
      const key = randomKey();
      const tooShort = new ArrayBuffer(10);

      await expect(engine.decrypt(tooShort, key)).rejects.toThrow(
        'Invalid encrypted payload: too short'
      );
    });

    it('fails with tampered ciphertext', async () => {
      const key = randomKey();
      const encrypted = await engine.encrypt('tamper me', key);
      const bytes = new Uint8Array(encrypted);

      // Flip a byte in the ciphertext region (past IV + AuthTag)
      bytes[30] ^= 0xff;

      await expect(engine.decrypt(bytes.buffer, key)).rejects.toThrow(
        'Decryption failed'
      );
    });

    it('fails with tampered auth tag', async () => {
      const key = randomKey();
      const encrypted = await engine.encrypt('integrity check', key);
      const bytes = new Uint8Array(encrypted);

      // Tamper the auth tag (bytes 12..27)
      bytes[14] ^= 0xff;

      await expect(engine.decrypt(bytes.buffer, key)).rejects.toThrow(
        'Decryption failed'
      );
    });
  });

  // ── Key Validation ─────────────────────────────────────────────────────────

  describe('key validation', () => {
    it('rejects key shorter than 32 bytes', async () => {
      const shortKey = new Uint8Array(16).buffer;
      await expect(engine.encrypt('test', shortKey)).rejects.toThrow(
        'Invalid key length'
      );
    });

    it('rejects key longer than 32 bytes', async () => {
      const longKey = new Uint8Array(64).buffer;
      await expect(engine.encrypt('test', longKey)).rejects.toThrow(
        'Invalid key length'
      );
    });
  });

  // ── Key Rotation ───────────────────────────────────────────────────────────

  describe('key rotation', () => {
    it('re-encrypts data with a new key', async () => {
      const oldKey = randomKey();
      const newKey = randomKey();
      const plaintext = 'rotate me';

      const encrypted1 = await engine.encrypt(plaintext, oldKey);
      const encrypted2 = await engine.encrypt('another file', oldKey);

      const rotated = await engine.rotateKey([encrypted1, encrypted2], oldKey, newKey);

      expect(rotated).toHaveLength(2);
      // Rotated data should decrypt with new key
      const decrypted = await engine.decrypt(rotated[0], newKey);
      expect(decrypted).toBe(plaintext);

      // Old key should no longer work on rotated data
      await expect(engine.decrypt(rotated[0], oldKey)).rejects.toThrow();
    });
  });

  // ── wipeKeys ───────────────────────────────────────────────────────────────

  describe('wipeKeys', () => {
    it('clears the activeKeys array', async () => {
      const key = randomKey();
      // Trigger importKey to populate activeKeys
      await engine.encrypt('test', key);

      // Access internal state
      const internalKeys = (engine as any).activeKeys as CryptoKey[];
      expect(internalKeys.length).toBeGreaterThan(0);

      engine.wipeKeys();

      expect((engine as any).activeKeys).toHaveLength(0);
    });
  });

  // ── deriveKey (HKDF) ──────────────────────────────────────────────────────

  describe('deriveKey', () => {
    it('derives a CryptoKey from raw key material', async () => {
      const keyData = crypto.getRandomValues(new Uint8Array(32)).buffer;
      const derived = await engine.deriveKey(keyData);

      expect(derived).toBeDefined();
      expect(derived.algorithm).toMatchObject({ name: 'AES-GCM' });
      expect(derived.usages).toEqual(expect.arrayContaining(['encrypt', 'decrypt']));
    });

    it('derives different keys for different info contexts', async () => {
      const keyData = crypto.getRandomValues(new Uint8Array(32)).buffer;
      const info1 = new TextEncoder().encode('context-a');
      const info2 = new TextEncoder().encode('context-b');

      const key1 = await engine.deriveKey(keyData, undefined, info1.buffer);
      const key2 = await engine.deriveKey(keyData, undefined, info2.buffer);

      // Derived keys are non-extractable CryptoKeys, so we can't compare bytes directly.
      // Instead verify they are functionally different: encrypt with key1, decrypt with key2 should fail.
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const plaintext = new TextEncoder().encode('test');

      const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, tagLength: 128 },
        key1,
        plaintext
      );

      await expect(
        crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key2, encrypted)
      ).rejects.toThrow();
    });

    it('tracks derived keys in activeKeys', async () => {
      engine.wipeKeys(); // start clean
      const keyData = crypto.getRandomValues(new Uint8Array(32)).buffer;
      await engine.deriveKey(keyData);

      expect((engine as any).activeKeys).toHaveLength(1);
    });
  });
});
