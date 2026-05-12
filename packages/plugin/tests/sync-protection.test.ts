/**
 * Sync Permission Enforcement test suite
 *
 * Tests that the SyncEngine respects permission checks during push/pull
 * operations. Files the user lacks permission for are skipped (not synced).
 *
 * Covers:
 * - pushChanges: files without write permission go to failed[], not pushed
 * - pushChanges: files with write permission are uploaded normally
 * - pushChanges: mixed queue (some allowed, some denied)
 * - pullChanges: files without read permission are silently skipped
 * - pullChanges: files with read permission are downloaded
 * - pullChanges: mixed listing (some readable, some not)
 *
 * Strategy: we populate the PermissionChecker with grants directly and
 * mock the server endpoints to test actual push/pull permission gating.
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';

vi.mock('obsidian', () => ({
  requestUrl: vi.fn(),
  Notice: vi.fn(),
  Plugin: class {},
}));

import { requestUrl } from 'obsidian';
import { SyncEngine } from '../src/sync/sync-engine';
import { SyncEngineState, SyncEventType, PermissionLevel } from '../src/types';
import { CacheStore } from '../src/crypto/cache-store';
import { KeyManager } from '../src/crypto/key-manager';
import { EncryptionEngine } from '../src/crypto/encryption-engine';
import { PermissionChecker } from '../src/sync/permission-checker';
import { ConflictResolver } from '../src/sync/conflict-resolver';

const mockRequestUrl = vi.mocked(requestUrl);

function randomKey(): ArrayBuffer {
  return crypto.getRandomValues(new Uint8Array(32)).buffer as ArrayBuffer;
}

function makeBase64Key(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes));
}

/**
 * Helper: populate grants directly on the PermissionChecker.
 */
function setGrants(checker: PermissionChecker, grants: Array<{
  pattern: string;
  level: PermissionLevel;
}>) {
  const internal = checker as any;
  internal.grants = grants.map(g => ({
    pattern: g.pattern,
    level: g.level,
    grantedBy: 'admin',
    expiresAt: null,
    createdAt: new Date().toISOString(),
  }));
  internal.lastRefresh = Date.now();
}

describe('Sync Permission Enforcement', () => {
  let syncEngine: SyncEngine;
  let keyManager: KeyManager;
  let cacheStore: CacheStore;
  let permissionChecker: PermissionChecker;
  let conflictResolver: ConflictResolver;
  let encryptionEngine: EncryptionEngine;

  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    mockRequestUrl.mockReset();

    encryptionEngine = new EncryptionEngine();
    cacheStore = new CacheStore('/vault', encryptionEngine);

    keyManager = new KeyManager(
      'https://api.vaultguard.test',
      'auth-token',
      encryptionEngine
    );

    permissionChecker = new PermissionChecker(
      'https://api.vaultguard.test',
      'auth-token'
    );

    conflictResolver = new ConflictResolver(
      'https://api.vaultguard.test',
      'auth-token',
      vi.fn()
    );

    syncEngine = new SyncEngine(
      'https://api.vaultguard.test',
      'auth-token',
      cacheStore,
      keyManager,
      permissionChecker,
      conflictResolver,
      { intervalMs: 30_000 }
    );
  });

  afterEach(() => {
    syncEngine.destroy();
    keyManager.destroy();
    vi.useRealTimers();
  });

  // ── pushChanges: Permission Gating ───────────────────────────────────

  describe('pushChanges — permission gating', () => {
    it('skips files user cannot write and adds them to failed list', async () => {
      // User has read-only access to docs/
      setGrants(permissionChecker, [
        { pattern: 'docs/**', level: PermissionLevel.READ },
      ]);

      // Queue a change to a read-only file
      syncEngine.queueChange({ path: 'docs/readonly.md', type: 'modify', content: 'new content', timestamp: Date.now() });

      const key = randomKey();
      const result = await syncEngine.pushChanges(key);

      expect(result.pushed).toBe(0);
      expect(result.failed).toContain('docs/readonly.md');
    });

    it('uploads files user has write permission for', async () => {
      setGrants(permissionChecker, [
        { pattern: '**', level: PermissionLevel.WRITE },
      ]);

      syncEngine.queueChange({ path: 'notes/editable.md', type: 'modify', content: 'updated', timestamp: Date.now() });

      // Mock successful upload
      mockRequestUrl.mockResolvedValueOnce({
        status: 200,
        json: { success: true },
        text: '{"success":true}',
        headers: {},
        arrayBuffer: new ArrayBuffer(0),
      } as any);

      const key = randomKey();
      const result = await syncEngine.pushChanges(key);

      expect(result.pushed).toBe(1);
      expect(result.failed).toHaveLength(0);
    });

    it('handles mixed queue: uploads allowed files, fails denied files', async () => {
      // Write access to engineering/, read-only to docs/
      setGrants(permissionChecker, [
        { pattern: 'engineering/**', level: PermissionLevel.WRITE },
        { pattern: 'docs/**', level: PermissionLevel.READ },
      ]);

      syncEngine.queueChange({ path: 'engineering/api.ts', type: 'modify', content: 'code', timestamp: Date.now() });
      syncEngine.queueChange({ path: 'docs/readonly.md', type: 'modify', content: 'denied', timestamp: Date.now() });

      // Mock successful upload for the allowed file
      mockRequestUrl.mockResolvedValueOnce({
        status: 200,
        json: { success: true },
        text: '{"success":true}',
        headers: {},
        arrayBuffer: new ArrayBuffer(0),
      } as any);

      const key = randomKey();
      const result = await syncEngine.pushChanges(key);

      expect(result.pushed).toBe(1);
      expect(result.failed).toEqual(['docs/readonly.md']);
    });

    it('files with NONE permission are failed', async () => {
      setGrants(permissionChecker, [
        { pattern: 'secret/**', level: PermissionLevel.NONE },
      ]);

      syncEngine.queueChange({ path: 'secret/classified.md', type: 'modify', content: 'data', timestamp: Date.now() });

      const key = randomKey();
      const result = await syncEngine.pushChanges(key);

      expect(result.pushed).toBe(0);
      expect(result.failed).toContain('secret/classified.md');
    });

    it('files with no matching grant are failed (implicit deny)', async () => {
      // Only engineering/ is granted
      setGrants(permissionChecker, [
        { pattern: 'engineering/**', level: PermissionLevel.WRITE },
      ]);

      syncEngine.queueChange({ path: 'marketing/campaign.md', type: 'modify', content: 'data', timestamp: Date.now() });

      const key = randomKey();
      const result = await syncEngine.pushChanges(key);

      expect(result.pushed).toBe(0);
      expect(result.failed).toContain('marketing/campaign.md');
    });
  });

  // ── pullChanges: Permission Gating ───────────────────────────────────

  describe('pullChanges — permission gating', () => {
    it('skips files user cannot read', async () => {
      // User has NO read access
      setGrants(permissionChecker, [
        { pattern: 'public/**', level: PermissionLevel.READ },
      ]);

      // Server returns a file the user can't read
      mockRequestUrl.mockResolvedValueOnce({
        status: 200,
        json: {
          files: [
            { path: 'secret/classified.md', contentHash: 'hash-123', lastModified: Date.now(), size: 100 },
          ],
        },
        text: '',
        headers: {},
        arrayBuffer: new ArrayBuffer(0),
      } as any);

      const key = randomKey();
      const result = await syncEngine.pullChanges(key);

      expect(result.pulled).toBe(0);
      // No download attempt should have been made
      // (only 1 requestUrl call for the file list, none for download)
      expect(mockRequestUrl).toHaveBeenCalledTimes(1);
    });

    it('downloads files user has read permission for', async () => {
      setGrants(permissionChecker, [
        { pattern: '**', level: PermissionLevel.READ },
      ]);

      // Server returns a readable file
      mockRequestUrl
        .mockResolvedValueOnce({
          status: 200,
          json: {
            files: [
              { path: 'docs/readme.md', contentHash: 'new-hash', lastModified: Date.now(), size: 50 },
            ],
          },
          text: '',
          headers: {},
          arrayBuffer: new ArrayBuffer(0),
        } as any)
        // Download request
        .mockResolvedValueOnce({
          status: 200,
          text: '# README\nFile content',
          json: {},
          headers: {},
          arrayBuffer: new ArrayBuffer(0),
        } as any);

      const key = randomKey();
      const result = await syncEngine.pullChanges(key);

      expect(result.pulled).toBe(1);
    });

    it('handles mixed listing: downloads readable files, skips unreadable', async () => {
      // Read access only to docs/
      setGrants(permissionChecker, [
        { pattern: 'docs/**', level: PermissionLevel.READ },
      ]);

      mockRequestUrl
        .mockResolvedValueOnce({
          status: 200,
          json: {
            files: [
              { path: 'docs/readme.md', contentHash: 'hash-1', lastModified: Date.now(), size: 50 },
              { path: 'secret/hidden.md', contentHash: 'hash-2', lastModified: Date.now(), size: 100 },
            ],
          },
          text: '',
          headers: {},
          arrayBuffer: new ArrayBuffer(0),
        } as any)
        // Only one download (for the readable file)
        .mockResolvedValueOnce({
          status: 200,
          text: 'public content',
          json: {},
          headers: {},
          arrayBuffer: new ArrayBuffer(0),
        } as any);

      const key = randomKey();
      const result = await syncEngine.pullChanges(key);

      expect(result.pulled).toBe(1);
      // 1 file list request + 1 download = 2 total (no download for secret/)
      expect(mockRequestUrl).toHaveBeenCalledTimes(2);
    });

    it('does not pull files when all are denied', async () => {
      setGrants(permissionChecker, [
        { pattern: 'allowed/**', level: PermissionLevel.READ },
      ]);

      mockRequestUrl.mockResolvedValueOnce({
        status: 200,
        json: {
          files: [
            { path: 'denied/a.md', contentHash: 'h1', lastModified: Date.now(), size: 10 },
            { path: 'denied/b.md', contentHash: 'h2', lastModified: Date.now(), size: 20 },
          ],
        },
        text: '',
        headers: {},
        arrayBuffer: new ArrayBuffer(0),
      } as any);

      const key = randomKey();
      const result = await syncEngine.pullChanges(key);

      expect(result.pulled).toBe(0);
      expect(result.conflicts).toHaveLength(0);
      // Only the file list request, no downloads
      expect(mockRequestUrl).toHaveBeenCalledTimes(1);
    });
  });

  // ── Permission + Revocation during Sync ──────────────────────────────

  describe('revocation during sync', () => {
    it('sync rejects after access revocation', async () => {
      await syncEngine.handleRevocation();

      await expect(syncEngine.sync()).rejects.toThrow('access has been revoked');
    });

    it('push is impossible after revocation (queue cleared)', async () => {
      syncEngine.queueChange({ path: 'file.md', type: 'modify', content: 'data', timestamp: Date.now() });

      await syncEngine.handleRevocation();

      // Queue was cleared by handleRevocation
      expect(syncEngine.getStatus().queuedChanges).toBe(0);
    });

    it('pull responds to 401 by throwing auth error', async () => {
      setGrants(permissionChecker, [
        { pattern: '**', level: PermissionLevel.READ },
      ]);

      // Server returns 401 for file list
      mockRequestUrl.mockResolvedValueOnce({
        status: 401,
        json: {},
        text: '',
        headers: {},
        arrayBuffer: new ArrayBuffer(0),
      } as any);

      const key = randomKey();
      await expect(syncEngine.pullChanges(key)).rejects.toThrow('Access revoked');
    });
  });
});
