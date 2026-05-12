/**
 * SyncEngine test suite
 *
 * Covers:
 * - start/stop lifecycle (timer management)
 * - sync() blocks when REVOKED
 * - sync() transitions to OFFLINE when no key
 * - handleRevocation() stops sync, clears queue, sets REVOKED
 * - Event emission (state changes, revocation)
 * - queueChange() deduplicates by path
 * - getStatus() reflects current state
 * - destroy() cleans up
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';

vi.mock('obsidian', () => ({
  requestUrl: vi.fn(),
  Notice: vi.fn(),
  Plugin: class {},
}));

import { requestUrl } from 'obsidian';
import { SyncEngine } from '../src/sync/sync-engine';
import { SyncEngineState, SyncEventType } from '../src/types';
import { CacheStore } from '../src/crypto/cache-store';
import { KeyManager } from '../src/crypto/key-manager';
import { EncryptionEngine } from '../src/crypto/encryption-engine';
import { PermissionChecker } from '../src/sync/permission-checker';
import { ConflictResolver } from '../src/sync/conflict-resolver';

const mockRequestUrl = vi.mocked(requestUrl);

describe('SyncEngine', () => {
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

  // ── Start / Stop ──────────────────────────────────────────────────────────

  describe('start and stop', () => {
    it('start creates a sync timer', () => {
      // getKey returns null → sync won't actually do a server call,
      // but the timer should be set
      syncEngine.start();

      const timer = (syncEngine as any).syncTimer;
      expect(timer).not.toBeNull();
    });

    it('stop clears the sync timer', () => {
      syncEngine.start();
      syncEngine.stop();

      expect((syncEngine as any).syncTimer).toBeNull();
    });

    it('start is idempotent (no duplicate timers)', () => {
      syncEngine.start();
      const firstTimer = (syncEngine as any).syncTimer;

      syncEngine.start();
      const secondTimer = (syncEngine as any).syncTimer;

      expect(firstTimer).toBe(secondTimer);
    });
  });

  // ── sync() Behavior ───────────────────────────────────────────────────────

  describe('sync', () => {
    it('throws when state is REVOKED', async () => {
      await syncEngine.handleRevocation();

      await expect(syncEngine.sync()).rejects.toThrow('access has been revoked');
    });

    it('transitions to OFFLINE when no encryption key is available', async () => {
      const stateChanges: any[] = [];
      syncEngine.on(SyncEventType.STATE_CHANGED, (e) => stateChanges.push(e.data));

      // keyManager.getKey() returns null by default (no lease)
      const status = await syncEngine.sync();

      expect(status.state).toBe(SyncEngineState.OFFLINE);
      expect(status.error).toBe('No valid encryption key available');
    });
  });

  // ── handleRevocation ──────────────────────────────────────────────────────

  describe('handleRevocation', () => {
    it('stops sync, clears queue, sets REVOKED state', async () => {
      syncEngine.start();
      syncEngine.queueChange({ path: 'file.md', type: 'modify', timestamp: Date.now() });

      await syncEngine.handleRevocation();

      expect((syncEngine as any).state).toBe(SyncEngineState.REVOKED);
      expect((syncEngine as any).offlineQueue).toHaveLength(0);
      expect((syncEngine as any).syncTimer).toBeNull();
    });

    it('emits ACCESS_REVOKED event', async () => {
      const events: any[] = [];
      syncEngine.on(SyncEventType.ACCESS_REVOKED, (e) => events.push(e));

      await syncEngine.handleRevocation();

      expect(events).toHaveLength(1);
      expect(events[0].type).toBe(SyncEventType.ACCESS_REVOKED);
    });
  });

  // ── Event System ──────────────────────────────────────────────────────────

  describe('events', () => {
    it('on/off registers and removes listeners', () => {
      const listener = vi.fn();

      syncEngine.on(SyncEventType.STATE_CHANGED, listener);
      (syncEngine as any).setState(SyncEngineState.OFFLINE);
      expect(listener).toHaveBeenCalledTimes(1);

      syncEngine.off(SyncEventType.STATE_CHANGED, listener);
      (syncEngine as any).setState(SyncEngineState.IDLE);
      expect(listener).toHaveBeenCalledTimes(1); // not called again
    });

    it('does not emit STATE_CHANGED when state is the same', () => {
      const listener = vi.fn();
      syncEngine.on(SyncEventType.STATE_CHANGED, listener);

      // Default state is IDLE, setting to IDLE again should not emit
      (syncEngine as any).setState(SyncEngineState.IDLE);
      expect(listener).not.toHaveBeenCalled();
    });

    it('emits CHANGE_QUEUED when queueChange is called', () => {
      const listener = vi.fn();
      syncEngine.on(SyncEventType.CHANGE_QUEUED, listener);

      syncEngine.queueChange({ path: 'test.md', type: 'create', timestamp: Date.now() });

      expect(listener).toHaveBeenCalledTimes(1);
      expect(listener.mock.calls[0][0].data.path).toBe('test.md');
    });
  });

  // ── queueChange ───────────────────────────────────────────────────────────

  describe('queueChange', () => {
    it('adds changes to the offline queue', () => {
      syncEngine.queueChange({ path: 'a.md', type: 'create', timestamp: 1 });
      syncEngine.queueChange({ path: 'b.md', type: 'modify', timestamp: 2 });

      expect((syncEngine as any).offlineQueue).toHaveLength(2);
    });

    it('deduplicates by path (keeps latest)', () => {
      syncEngine.queueChange({ path: 'a.md', type: 'create', timestamp: 1 });
      syncEngine.queueChange({ path: 'a.md', type: 'modify', content: 'updated', timestamp: 2 });

      const queue = (syncEngine as any).offlineQueue;
      expect(queue).toHaveLength(1);
      expect(queue[0].type).toBe('modify');
      expect(queue[0].timestamp).toBe(2);
    });
  });

  // ── getStatus ─────────────────────────────────────────────────────────────

  describe('getStatus', () => {
    it('reflects current state', () => {
      const status = syncEngine.getStatus();
      expect(status.state).toBe(SyncEngineState.IDLE);
      expect(status.queuedChanges).toBe(0);
      expect(status.lastSync).toBe(0);
    });

    it('includes queued change count', () => {
      syncEngine.queueChange({ path: 'a.md', type: 'create', timestamp: 1 });
      syncEngine.queueChange({ path: 'b.md', type: 'create', timestamp: 2 });

      expect(syncEngine.getStatus().queuedChanges).toBe(2);
    });
  });

  // ── destroy ───────────────────────────────────────────────────────────────

  describe('destroy', () => {
    it('stops timer, clears listeners, and clears queue', () => {
      syncEngine.start();
      syncEngine.queueChange({ path: 'a.md', type: 'create', timestamp: 1 });

      const listener = vi.fn();
      syncEngine.on(SyncEventType.STATE_CHANGED, listener);

      syncEngine.destroy();

      expect((syncEngine as any).syncTimer).toBeNull();
      expect((syncEngine as any).offlineQueue).toHaveLength(0);
      expect((syncEngine as any).listeners.size).toBe(0);
    });
  });
});
