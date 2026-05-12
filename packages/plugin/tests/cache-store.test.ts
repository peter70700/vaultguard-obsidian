/**
 * CacheStore test suite
 *
 * Covers:
 * - set/get roundtrip (content encrypted at rest, decrypted on read)
 * - get returns null for uncached files
 * - delete removes entry and file
 * - has() checks existence
 * - wipeAll() clears everything
 * - wipeScope() only removes matching paths
 * - Manifest tracks entries correctly
 * - getCacheSize() sums encrypted sizes
 * - getContentHash() for delta sync
 * - invalidate() removes changed paths
 * - Decryption fails with wrong key (data sealed after key wipe)
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { CacheStore } from '../src/crypto/cache-store';
import { EncryptionEngine } from '../src/crypto/encryption-engine';

function randomKey(): ArrayBuffer {
  return crypto.getRandomValues(new Uint8Array(32)).buffer as ArrayBuffer;
}

describe('CacheStore', () => {
  let store: CacheStore;
  let engine: EncryptionEngine;
  let key: ArrayBuffer;

  beforeEach(async () => {
    engine = new EncryptionEngine();
    key = randomKey();
    // Uses the built-in StubFileAdapter (in-memory Map)
    store = new CacheStore('/vault', engine);
    await store.initialize(key);
  });

  // ── Set / Get Roundtrip ───────────────────────────────────────────────────

  describe('set and get', () => {
    it('roundtrips content through encrypt → store → retrieve → decrypt', async () => {
      await store.set('notes/secret.md', 'My secret note', key);
      const content = await store.get('notes/secret.md', key);
      expect(content).toBe('My secret note');
    });

    it('returns null for uncached file', async () => {
      const content = await store.get('nonexistent.md', key);
      expect(content).toBeNull();
    });

    it('overwrites existing entry on re-set', async () => {
      await store.set('file.md', 'version 1', key);
      await store.set('file.md', 'version 2', key);
      const content = await store.get('file.md', key);
      expect(content).toBe('version 2');
    });

    it('stores multiple files independently', async () => {
      await store.set('a.md', 'content-a', key);
      await store.set('b.md', 'content-b', key);

      expect(await store.get('a.md', key)).toBe('content-a');
      expect(await store.get('b.md', key)).toBe('content-b');
    });
  });

  // ── has() ─────────────────────────────────────────────────────────────────

  describe('has', () => {
    it('returns false for uncached file', async () => {
      expect(await store.has('missing.md')).toBe(false);
    });

    it('returns true for cached file', async () => {
      await store.set('cached.md', 'data', key);
      expect(await store.has('cached.md')).toBe(true);
    });
  });

  // ── delete ────────────────────────────────────────────────────────────────

  describe('delete', () => {
    it('removes a cached file', async () => {
      await store.set('delete-me.md', 'data', key);
      expect(await store.has('delete-me.md')).toBe(true);

      await store.delete('delete-me.md', key);
      expect(await store.has('delete-me.md')).toBe(false);
      expect(await store.get('delete-me.md', key)).toBeNull();
    });

    it('no-ops for non-existent file', async () => {
      // Should not throw
      await store.delete('nonexistent.md', key);
    });
  });

  // ── wipeAll ───────────────────────────────────────────────────────────────

  describe('wipeAll', () => {
    it('clears all cached files and manifest', async () => {
      await store.set('a.md', 'a', key);
      await store.set('b.md', 'b', key);

      await store.wipeAll();

      expect(await store.has('a.md')).toBe(false);
      expect(await store.has('b.md')).toBe(false);
      expect(store.getManifest().entries.size).toBe(0);
    });
  });

  // ── wipeScope ─────────────────────────────────────────────────────────────

  describe('wipeScope', () => {
    it('only removes files within the scope pattern', async () => {
      await store.set('engineering/api.ts', 'api code', key);
      await store.set('engineering/db.ts', 'db code', key);
      await store.set('marketing/campaign.md', 'campaign', key);

      // Scope pattern must match the stored paths (no leading slash since stored paths lack one)
      await store.wipeScope('engineering/**', key);

      // Engineering files should be gone
      expect(await store.has('engineering/api.ts')).toBe(false);
      expect(await store.has('engineering/db.ts')).toBe(false);
      // Marketing file should remain
      expect(await store.has('marketing/campaign.md')).toBe(true);
    });
  });

  // ── Manifest ──────────────────────────────────────────────────────────────

  describe('manifest', () => {
    it('tracks entries with correct metadata', async () => {
      await store.set('test.md', 'test content', key, {
        lastModified: 1700000000000,
        size: 12,
      });

      const manifest = store.getManifest();
      expect(manifest.entries.size).toBe(1);

      const entry = Array.from(manifest.entries.values())[0];
      expect(entry.originalPath).toBe('test.md');
      expect(entry.size).toBe(12); // original content length
      expect(entry.lastModified).toBe(1700000000000);
      expect(entry.encryptedSize).toBeGreaterThan(0);
      expect(entry.contentHash).toBeTruthy();
    });

    it('returns a copy (not a reference)', async () => {
      await store.set('test.md', 'data', key);
      const m1 = store.getManifest();
      const m2 = store.getManifest();

      expect(m1.entries).not.toBe(m2.entries);
    });
  });

  // ── getCacheSize ──────────────────────────────────────────────────────────

  describe('getCacheSize', () => {
    it('returns 0 for empty cache', () => {
      expect(store.getCacheSize()).toBe(0);
    });

    it('sums encrypted sizes of all entries', async () => {
      await store.set('a.md', 'aaaa', key);
      await store.set('b.md', 'bbbbbbbb', key);

      expect(store.getCacheSize()).toBeGreaterThan(0);
    });
  });

  // ── getContentHash ────────────────────────────────────────────────────────

  describe('getContentHash', () => {
    it('returns hash for cached file', async () => {
      await store.set('hashed.md', 'hello', key);
      const hash = await store.getContentHash('hashed.md');
      expect(hash).toBeTruthy();
      expect(typeof hash).toBe('string');
    });

    it('returns null for uncached file', async () => {
      expect(await store.getContentHash('missing.md')).toBeNull();
    });

    it('returns different hashes for different content', async () => {
      await store.set('a.md', 'content-a', key);
      await store.set('b.md', 'content-b', key);

      const hashA = await store.getContentHash('a.md');
      const hashB = await store.getContentHash('b.md');

      expect(hashA).not.toBe(hashB);
    });
  });

  // ── invalidate ────────────────────────────────────────────────────────────

  describe('invalidate', () => {
    it('removes specified paths from cache', async () => {
      await store.set('keep.md', 'keep', key);
      await store.set('remove.md', 'remove', key);

      await store.invalidate(['remove.md'], key);

      expect(await store.has('keep.md')).toBe(true);
      expect(await store.has('remove.md')).toBe(false);
    });
  });

  // ── Data Sealed After Key Change ──────────────────────────────────────────

  describe('data protection', () => {
    it('cannot decrypt cached data with a different key', async () => {
      await store.set('secret.md', 'classified', key);

      const wrongKey = randomKey();
      const content = await store.get('secret.md', wrongKey);

      // get() catches decryption errors and returns null
      expect(content).toBeNull();
    });
  });
});
