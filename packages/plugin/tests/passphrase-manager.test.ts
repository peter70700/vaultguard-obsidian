/**
 * PassphraseManager test suite
 *
 * Covers:
 * - setup() → login() roundtrip (passphrase wraps then unwraps UMK)
 * - Wrong passphrase login fails gracefully (returns false)
 * - deriveDek() returns valid AES-256-GCM key material
 * - Different scopes produce different DEKs
 * - lock() zeroes umkRaw and nullifies umk
 * - isUnlocked() state transitions
 * - deriveDek() throws when locked
 * - changePassphrase() re-wraps without changing UMK
 * - importOrgPublicKey() for RSA-OAEP
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { PassphraseManager } from '../src/crypto/passphrase-manager';

// Helper: generate an RSA-OAEP key pair for testing org recovery wrapping
async function generateOrgKeyPair() {
  return crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt']
  );
}

describe('PassphraseManager', () => {
  let pm: PassphraseManager;

  beforeEach(() => {
    pm = new PassphraseManager();
  });

  // ── Setup → Login Roundtrip ───────────────────────────────────────────────

  describe('setup and login', () => {
    it('setup produces valid wrapped key material', async () => {
      const keyPair = await generateOrgKeyPair();
      const result = await pm.setup('my-secure-passphrase', keyPair.publicKey);

      expect(result.wrappedUMK_user).toBeTruthy();
      expect(result.wrappedUMK_org).toBeTruthy();
      expect(result.argon2Salt).toBeTruthy();
      expect(result.algorithm).toBe('pbkdf2+aes-kw');
    });

    it('login succeeds with correct passphrase', async () => {
      const keyPair = await generateOrgKeyPair();
      const setupResult = await pm.setup('correct-passphrase', keyPair.publicKey);

      // Create a fresh manager (simulates new session)
      const pm2 = new PassphraseManager();
      const success = await pm2.login('correct-passphrase', {
        wrappedUMK_user: setupResult.wrappedUMK_user,
        argon2Salt: setupResult.argon2Salt,
        algorithm: setupResult.algorithm,
      });

      expect(success).toBe(true);
      expect(pm2.isUnlocked()).toBe(true);
    });

    it('login fails with wrong passphrase', async () => {
      const keyPair = await generateOrgKeyPair();
      const setupResult = await pm.setup('correct-passphrase', keyPair.publicKey);

      const pm2 = new PassphraseManager();
      const success = await pm2.login('wrong-passphrase', {
        wrappedUMK_user: setupResult.wrappedUMK_user,
        argon2Salt: setupResult.argon2Salt,
        algorithm: setupResult.algorithm,
      });

      expect(success).toBe(false);
      expect(pm2.isUnlocked()).toBe(false);
    });
  });

  // ── DEK Derivation ────────────────────────────────────────────────────────

  describe('deriveDek', () => {
    it('returns 32-byte AES key material', async () => {
      const keyPair = await generateOrgKeyPair();
      await pm.setup('passphrase', keyPair.publicKey);

      const dek = await pm.deriveDek('/**');

      expect(dek).toBeInstanceOf(ArrayBuffer);
      expect(new Uint8Array(dek as ArrayBuffer).length).toBe(32);
    });

    it('produces different DEKs for different scopes', async () => {
      const keyPair = await generateOrgKeyPair();
      await pm.setup('passphrase', keyPair.publicKey);

      const dek1 = await pm.deriveDek('/engineering/**');
      const dek2 = await pm.deriveDek('/marketing/**');

      const bytes1 = new Uint8Array(dek1 as ArrayBuffer);
      const bytes2 = new Uint8Array(dek2 as ArrayBuffer);

      const areEqual = bytes1.every((b, i) => b === bytes2[i]);
      expect(areEqual).toBe(false);
    });

    it('produces the same DEK for the same scope (deterministic)', async () => {
      const keyPair = await generateOrgKeyPair();
      await pm.setup('passphrase', keyPair.publicKey);

      const dek1 = await pm.deriveDek('/engineering/**');
      const dek2 = await pm.deriveDek('/engineering/**');

      const bytes1 = new Uint8Array(dek1 as ArrayBuffer);
      const bytes2 = new Uint8Array(dek2 as ArrayBuffer);

      const areEqual = bytes1.every((b, i) => b === bytes2[i]);
      expect(areEqual).toBe(true);
    });

    it('throws when UMK is not loaded', async () => {
      await expect(pm.deriveDek('/**')).rejects.toThrow(
        'UMK not available'
      );
    });
  });

  // ── Lock / Unlock State ───────────────────────────────────────────────────

  describe('lock and isUnlocked', () => {
    it('starts locked', () => {
      expect(pm.isUnlocked()).toBe(false);
    });

    it('unlocks after setup', async () => {
      const keyPair = await generateOrgKeyPair();
      await pm.setup('passphrase', keyPair.publicKey);
      expect(pm.isUnlocked()).toBe(true);
    });

    it('unlocks after login', async () => {
      const keyPair = await generateOrgKeyPair();
      const setupResult = await pm.setup('passphrase', keyPair.publicKey);

      const pm2 = new PassphraseManager();
      await pm2.login('passphrase', {
        wrappedUMK_user: setupResult.wrappedUMK_user,
        argon2Salt: setupResult.argon2Salt,
        algorithm: setupResult.algorithm,
      });

      expect(pm2.isUnlocked()).toBe(true);
    });

    it('lock() zeroes umkRaw and nullifies umk', async () => {
      const keyPair = await generateOrgKeyPair();
      await pm.setup('passphrase', keyPair.publicKey);

      // Verify raw bytes exist before lock
      const rawBefore = (pm as any).umkRaw as Uint8Array;
      expect(rawBefore).not.toBeNull();
      const hadNonZero = rawBefore.some((b: number) => b !== 0);
      expect(hadNonZero).toBe(true);

      pm.lock();

      // umk should be null
      expect((pm as any).umk).toBeNull();
      // umkRaw should be null (reference cleared)
      expect((pm as any).umkRaw).toBeNull();
      // The original buffer should be zeroed (fill(0) was called before nulling)
      const allZero = rawBefore.every((b: number) => b === 0);
      expect(allZero).toBe(true);
    });

    it('deriveDek() throws after lock', async () => {
      const keyPair = await generateOrgKeyPair();
      await pm.setup('passphrase', keyPair.publicKey);

      pm.lock();

      await expect(pm.deriveDek('/**')).rejects.toThrow('UMK not available');
    });

    it('isUnlocked() returns false after lock', async () => {
      const keyPair = await generateOrgKeyPair();
      await pm.setup('passphrase', keyPair.publicKey);
      expect(pm.isUnlocked()).toBe(true);

      pm.lock();
      expect(pm.isUnlocked()).toBe(false);
    });
  });

  // ── Passphrase Change ─────────────────────────────────────────────────────

  describe('changePassphrase', () => {
    it('re-wraps UMK with a new passphrase without changing DEKs', async () => {
      const keyPair = await generateOrgKeyPair();
      await pm.setup('old-passphrase', keyPair.publicKey);

      // Derive a DEK before change
      const dekBefore = await pm.deriveDek('/scope1');

      // Change passphrase
      const changeResult = await pm.changePassphrase('new-passphrase');
      expect(changeResult.wrappedUMK_user).toBeTruthy();
      expect(changeResult.argon2Salt).toBeTruthy();

      // DEK should still be the same (UMK unchanged)
      const dekAfter = await pm.deriveDek('/scope1');
      const bytesBefore = new Uint8Array(dekBefore as ArrayBuffer);
      const bytesAfter = new Uint8Array(dekAfter as ArrayBuffer);
      expect(bytesBefore.every((b, i) => b === bytesAfter[i])).toBe(true);

      // New passphrase should work for login
      const pm2 = new PassphraseManager();
      const success = await pm2.login('new-passphrase', {
        wrappedUMK_user: changeResult.wrappedUMK_user,
        argon2Salt: changeResult.argon2Salt,
        algorithm: 'pbkdf2+aes-kw',
      });
      expect(success).toBe(true);
    });

    it('old passphrase no longer works after change', async () => {
      const keyPair = await generateOrgKeyPair();
      await pm.setup('old-passphrase', keyPair.publicKey);
      const changeResult = await pm.changePassphrase('new-passphrase');

      const pm2 = new PassphraseManager();
      const success = await pm2.login('old-passphrase', {
        wrappedUMK_user: changeResult.wrappedUMK_user,
        argon2Salt: changeResult.argon2Salt,
        algorithm: 'pbkdf2+aes-kw',
      });
      expect(success).toBe(false);
    });

    it('throws when UMK is not available', async () => {
      await expect(pm.changePassphrase('new')).rejects.toThrow(
        'UMK not available'
      );
    });
  });

  // ── Org Public Key Import ─────────────────────────────────────────────────

  describe('importOrgPublicKey', () => {
    it('imports an RSA-OAEP public key from base64 SPKI', async () => {
      const keyPair = await generateOrgKeyPair();
      const exported = await crypto.subtle.exportKey('spki', keyPair.publicKey);
      const base64 = btoa(String.fromCharCode(...new Uint8Array(exported)));

      const imported = await pm.importOrgPublicKey(base64);
      expect(imported.algorithm).toMatchObject({ name: 'RSA-OAEP' });
      expect(imported.usages).toContain('encrypt');
    });
  });
});
