/**
 * Integration test suite — end-to-end auth & data protection flows
 *
 * Tests cross-component scenarios that verify the full protection model:
 * - Login → encrypt → logout → data sealed
 * - Key rotation preserves data access
 * - Revocation cascade: KeyManager → EncryptionEngine → CacheStore
 * - Hybrid-ZK: setup → login → derive → encrypt → lock → data sealed
 * - Grace period: keys survive briefly after lease expiry
 * - Multiple scopes: revoke one scope, others remain accessible
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';

vi.mock('obsidian', () => ({
  requestUrl: vi.fn(),
  Notice: vi.fn(),
  Plugin: class {},
}));

import { requestUrl } from 'obsidian';
import { EncryptionEngine } from '../src/crypto/encryption-engine';
import { CacheStore } from '../src/crypto/cache-store';
import { KeyManager } from '../src/crypto/key-manager';
import { PassphraseManager } from '../src/crypto/passphrase-manager';

const mockRequestUrl = vi.mocked(requestUrl);

function randomKey(): ArrayBuffer {
  return crypto.getRandomValues(new Uint8Array(32)).buffer as ArrayBuffer;
}

function makeBase64Key(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes));
}

describe('Integration: Auth & Data Protection', () => {
  let engine: EncryptionEngine;

  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    mockRequestUrl.mockReset();
    engine = new EncryptionEngine();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  // ── Login → Encrypt → Logout → Data Sealed ─────────────────────────────

  describe('login → encrypt → logout → data sealed', () => {
    it('encrypted data becomes unreadable after key wipe', async () => {
      const key = randomKey();

      // Simulate active session: encrypt data
      const encrypted = await engine.encrypt('Top Secret Document', key);
      const decrypted = await engine.decrypt(encrypted, key);
      expect(decrypted).toBe('Top Secret Document');

      // Simulate logout: wipe the key material
      new Uint8Array(key).fill(0);
      engine.wipeKeys();

      // Data should now be unreadable (the key material is zeroed)
      // Need a fresh key to attempt decryption — the zeroed key won't work
      const zeroedKey = new Uint8Array(32).buffer;
      await expect(engine.decrypt(encrypted, zeroedKey)).rejects.toThrow(
        'Decryption failed'
      );

      // And a random wrong key shouldn't work either
      await expect(engine.decrypt(encrypted, randomKey())).rejects.toThrow(
        'Decryption failed'
      );
    });
  });

  // ── CacheStore: data sealed after key change ──────────────────────────────

  describe('CacheStore: data sealed after key change', () => {
    it('cached files become unreadable with wrong key', async () => {
      const key = randomKey();
      const store = new CacheStore('/vault', engine);
      await store.initialize(key);

      // Store encrypted content
      await store.set('secret.md', 'Classified Information', key);

      // Verify readable with correct key
      expect(await store.get('secret.md', key)).toBe('Classified Information');

      // Simulate key revocation: try to read with different key
      const wrongKey = randomKey();
      const result = await store.get('secret.md', wrongKey);

      // CacheStore.get() catches decryption errors → returns null
      expect(result).toBeNull();
    });

    it('wipeAll clears cache even without correct key', async () => {
      const key = randomKey();
      const store = new CacheStore('/vault', engine);
      await store.initialize(key);

      await store.set('a.md', 'content-a', key);
      await store.set('b.md', 'content-b', key);
      expect(store.getManifest().entries.size).toBe(2);

      await store.wipeAll();

      expect(store.getManifest().entries.size).toBe(0);
      expect(await store.has('a.md')).toBe(false);
    });
  });

  // ── Key Rotation: data re-encrypted with new key ──────────────────────────

  describe('key rotation', () => {
    it('rotated data is readable with new key, not old key', async () => {
      const oldKey = randomKey();
      const newKey = randomKey();

      // Encrypt with old key
      const encrypted = await engine.encrypt('rotate me', oldKey);

      // Rotate
      const rotated = await engine.rotateKey([encrypted], oldKey, newKey);

      // New key works
      expect(await engine.decrypt(rotated[0], newKey)).toBe('rotate me');

      // Old key fails (its material was wiped during rotation)
      await expect(engine.decrypt(rotated[0], oldKey)).rejects.toThrow();
    });
  });

  // ── KeyManager Revocation Cascade ─────────────────────────────────────────

  describe('KeyManager revocation cascade', () => {
    it('revokeAndWipe clears key, wipes engine keys, and calls callback', async () => {
      const km = new KeyManager(
        'https://api.vaultguard.test',
        'auth-token',
        engine
      );

      const onRevoked = vi.fn().mockResolvedValue(undefined);
      km.onAccessRevoked(onRevoked);

      // Acquire a lease
      mockRequestUrl.mockResolvedValueOnce({
        status: 200,
        json: {
          success: true,
          payload: {
            keyId: 'key-001',
            key: makeBase64Key(),
            expiresAt: new Date(Date.now() + 3600_000).toISOString(),
            issuedAt: new Date().toISOString(),
            refreshToken: 'refresh-abc',
            scope: '/**',
          },
        },
      } as any);

      await km.requestLease();
      expect(km.getKey()).not.toBeNull();

      // Revoke
      await (km as any).revokeAndWipe();

      // Everything should be cleared
      expect(km.getKey()).toBeNull();
      expect(km.getLease()).toBeNull();
      expect(onRevoked).toHaveBeenCalledTimes(1);

      km.destroy();
    });
  });

  // ── Hybrid-ZK: Full Lifecycle ─────────────────────────────────────────────

  describe('hybrid-zk lifecycle', () => {
    it('setup → login → derive → encrypt → lock → data sealed', async () => {
      const pm = new PassphraseManager();

      // Generate org recovery key pair
      const orgKeyPair = await crypto.subtle.generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256',
        },
        true,
        ['encrypt', 'decrypt']
      );

      // Setup: creates wrapped UMK
      const setupResult = await pm.setup('my-secure-passphrase', orgKeyPair.publicKey);

      // Login on a fresh manager
      const pm2 = new PassphraseManager();
      const loginOk = await pm2.login('my-secure-passphrase', {
        wrappedUMK_user: setupResult.wrappedUMK_user,
        argon2Salt: setupResult.argon2Salt,
        algorithm: setupResult.algorithm,
      });
      expect(loginOk).toBe(true);

      // Derive a DEK for file encryption
      const dek = await pm2.deriveDek('/engineering/**');
      expect(dek).toBeTruthy();

      // Encrypt a file with the derived DEK
      const encrypted = await engine.encrypt('Engineering secrets', dek);
      expect(await engine.decrypt(encrypted, dek)).toBe('Engineering secrets');

      // Lock the passphrase manager (simulates logout)
      pm2.lock();
      expect(pm2.isUnlocked()).toBe(false);

      // Cannot derive new keys
      await expect(pm2.deriveDek('/engineering/**')).rejects.toThrow('UMK not available');

      // The encrypted data is still on "disk" — but without the DEK, it's sealed
      // A random key won't work
      await expect(engine.decrypt(encrypted, randomKey())).rejects.toThrow('Decryption failed');

      // Re-login with correct passphrase restores access
      const pm3 = new PassphraseManager();
      const reLoginOk = await pm3.login('my-secure-passphrase', {
        wrappedUMK_user: setupResult.wrappedUMK_user,
        argon2Salt: setupResult.argon2Salt,
        algorithm: setupResult.algorithm,
      });
      expect(reLoginOk).toBe(true);

      const dekAgain = await pm3.deriveDek('/engineering/**');
      expect(await engine.decrypt(encrypted, dekAgain)).toBe('Engineering secrets');
    });

    it('wrong passphrase cannot derive keys to decrypt data', async () => {
      const pm = new PassphraseManager();
      const orgKeyPair = await crypto.subtle.generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256',
        },
        true,
        ['encrypt', 'decrypt']
      );

      const setupResult = await pm.setup('correct-passphrase', orgKeyPair.publicKey);

      // Derive DEK and encrypt
      const dek = await pm.deriveDek('/**');
      const encrypted = await engine.encrypt('Protected data', dek);

      // Attacker tries with wrong passphrase
      const attacker = new PassphraseManager();
      const loginResult = await attacker.login('wrong-passphrase', {
        wrappedUMK_user: setupResult.wrappedUMK_user,
        argon2Salt: setupResult.argon2Salt,
        algorithm: setupResult.algorithm,
      });

      expect(loginResult).toBe(false);
      expect(attacker.isUnlocked()).toBe(false);
      await expect(attacker.deriveDek('/**')).rejects.toThrow('UMK not available');
    });
  });

  // ── Multiple Scopes ───────────────────────────────────────────────────────

  describe('multi-scope key isolation', () => {
    it('different scopes produce different DEKs (cross-scope isolation)', async () => {
      const pm = new PassphraseManager();
      const orgKeyPair = await crypto.subtle.generateKey(
        {
          name: 'RSA-OAEP',
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: 'SHA-256',
        },
        true,
        ['encrypt', 'decrypt']
      );

      await pm.setup('passphrase', orgKeyPair.publicKey);

      const dekEngineering = await pm.deriveDek('/engineering/**');
      const dekMarketing = await pm.deriveDek('/marketing/**');

      // Encrypt with engineering DEK
      const encrypted = await engine.encrypt('Engineering only', dekEngineering);

      // Marketing DEK should not decrypt it
      await expect(engine.decrypt(encrypted, dekMarketing)).rejects.toThrow(
        'Decryption failed'
      );

      // Engineering DEK should work
      expect(await engine.decrypt(encrypted, dekEngineering)).toBe('Engineering only');
    });
  });

  // ── Grace Period ──────────────────────────────────────────────────────────

  describe('grace period', () => {
    it('key remains valid during grace period, then expires', async () => {
      const km = new KeyManager(
        'https://api.vaultguard.test',
        'auth-token',
        engine,
        {
          gracePeriodMs: 5000, // 5 second grace period for testing
          refreshBufferMs: 1000,
          refreshIntervalMs: 60000,
        }
      );

      // Lease expires in 1 second
      mockRequestUrl.mockResolvedValueOnce({
        status: 200,
        json: {
          success: true,
          payload: {
            keyId: 'key-001',
            key: makeBase64Key(),
            expiresAt: new Date(Date.now() + 1000).toISOString(),
            issuedAt: new Date().toISOString(),
            refreshToken: 'refresh-abc',
            scope: '/**',
            gracePeriodMs: 5000,
          },
        },
      } as any);

      await km.requestLease();
      expect(km.isLeaseValid()).toBe(true);

      // Advance past expiry but within grace period
      vi.advanceTimersByTime(2000);
      expect(km.isLeaseValid()).toBe(true); // still valid (grace)

      // Advance past grace period
      vi.advanceTimersByTime(5000);
      expect(km.isLeaseValid()).toBe(false); // expired

      km.destroy();
    });
  });
});
