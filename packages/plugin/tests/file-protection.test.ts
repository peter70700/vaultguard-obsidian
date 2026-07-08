/**
 * File Protection test suite — vault adapter interception layer
 *
 * Tests the core .md file protection mechanism: VaultGuardPlugin intercepts
 * Obsidian's vault adapter read/write/list/delete operations and enforces
 * permission checks before allowing any file operation.
 *
 * Covers:
 * - interceptedRead: blocks read when permission < READ and wipes denied cache, falls back to cache offline
 * - interceptedWrite: blocks write when permission < WRITE, queues offline ops
 * - interceptedDelete: blocks delete when permission < WRITE
 * - interceptedList: returns the local directory tree without live permission probes
 * - getEffectivePermission: cache, admin role shortcut, server fetch, offline fallback
 * - resolvePermissionFromCache: hierarchical walk, role defaults, key lease fallback
 * - Audit events emitted on denied operations
 *
 * Strategy: we instantiate the plugin with a comprehensive Obsidian mock,
 * then set its private fields directly to control state (session, permissions,
 * connection status, key lease). This tests the actual plugin code paths.
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';

vi.mock('obsidian', () => ({
  requestUrl: vi.fn(),
  Notice: vi.fn(),
  Plugin: class {
    app: any = {
      vault: { adapter: { read: vi.fn(), write: vi.fn(), list: vi.fn(), remove: vi.fn() } },
      workspace: {
        on: vi.fn(() => ({ id: 'mock-event-ref' })),
        getActiveViewOfType: vi.fn(() => null),
        getLeavesOfType: vi.fn(() => []),
      },
      internalPlugins: { getPluginById: vi.fn(() => null) },
    };
    manifest: any = { id: 'vaultguard', name: 'VaultGuard', version: '0.1.0' };
    addSettingTab = vi.fn();
    addRibbonIcon = vi.fn();
    addStatusBarItem = vi.fn(() => document.createElement('div'));
    addCommand = vi.fn();
    registerView = vi.fn();
    registerEvent = vi.fn();
    registerDomEvent = vi.fn();
    loadData = vi.fn().mockResolvedValue(null);
    saveData = vi.fn().mockResolvedValue(undefined);
  },
  TFile: class {},
  TFolder: class {},
  TAbstractFile: class {},
  Menu: class { addItem = vi.fn(() => this); showAtMouseEvent = vi.fn(); },
  normalizePath: (p: string) => p,
  addIcon: vi.fn(),
  setIcon: vi.fn(),
  Events: class {
    private listeners = new Map<string, Array<(...args: unknown[]) => unknown>>();
    on(name: string, cb: (...args: unknown[]) => unknown) {
      const arr = this.listeners.get(name) ?? [];
      arr.push(cb);
      this.listeners.set(name, arr);
      return { name, cb };
    }
    off(name: string, cb: (...args: unknown[]) => unknown) {
      const arr = this.listeners.get(name) ?? [];
      this.listeners.set(name, arr.filter((x) => x !== cb));
    }
    offref(ref: { name: string; cb: (...args: unknown[]) => unknown }) {
      if (ref && typeof ref === "object" && "name" in ref && "cb" in ref) {
        this.off(ref.name as string, ref.cb as (...args: unknown[]) => unknown);
      }
    }
    trigger(name: string, ...args: unknown[]) {
      for (const cb of this.listeners.get(name) ?? []) cb(...args);
    }
    tryTrigger() {}
  },
  Modal: class {
    app: any;
    containerEl: any = document.createElement('div');
    contentEl: any = document.createElement('div');
    constructor(app: any) { this.app = app; }
    open = vi.fn();
    close = vi.fn();
    onOpen = vi.fn();
    onClose = vi.fn();
  },
  PluginSettingTab: class {
    app: any;
    containerEl: any = document.createElement('div');
    constructor(app: any) { this.app = app; }
    display = vi.fn();
    hide = vi.fn();
  },
  Setting: class {
    settingEl: any = document.createElement('div');
    constructor() {}
    setName = vi.fn(() => this);
    setDesc = vi.fn(() => this);
    addText = vi.fn(() => this);
    addToggle = vi.fn(() => this);
    addDropdown = vi.fn(() => this);
    addButton = vi.fn(() => this);
  },
  MarkdownView: class {},
  ItemView: class {
    containerEl: any = document.createElement('div');
    contentEl: any = document.createElement('div');
    getViewType = vi.fn(() => 'vaultguard');
    getDisplayText = vi.fn(() => 'VaultGuard');
    getIcon = vi.fn(() => 'shield');
  },
  WorkspaceLeaf: class {},
  DropdownComponent: class {},
  TextComponent: class {},
  ButtonComponent: class { buttonEl: any = document.createElement('button'); setCta = vi.fn(() => this); setButtonText = vi.fn(() => this); onClick = vi.fn(() => this); },
  RequestUrlResponse: class {},
}));

import { Notice } from 'obsidian';
import VaultGuardPlugin from '../src/plugin/main';
import { PermissionLevel } from '../src/types';

const mockNotice = vi.mocked(Notice);

// ─── Helpers ──────────────────────────────────────────────────────────────

/**
 * Create a plugin instance with minimal required state for protection testing.
 * Does NOT call onload() — instead, sets private fields directly.
 */
function createTestPlugin() {
  const plugin = new VaultGuardPlugin() as any;
  plugin.app.vault.configDir = '.obsidian';
  plugin.app.vault.adapter.exists = vi.fn().mockResolvedValue(false);

  // Mock original adapter methods (the real filesystem operations).
  // writeBinary is present because writePlainToDisk fails closed without it
  // (AR2) — encrypted content only ever lands via writeBinary.
  plugin.originalAdapterMethods = {
    read: vi.fn().mockResolvedValue('local file content'),
    write: vi.fn().mockResolvedValue(undefined),
    writeBinary: vi.fn().mockResolvedValue(undefined),
    list: vi.fn().mockResolvedValue({
      files: ['public/doc.md', 'private/secret.md', 'shared/notes.md'],
      folders: ['public', 'private', 'shared'],
    }),
    remove: vi.fn().mockResolvedValue(undefined),
  };

  // Phase 9: the production code routes all permission reads through
  // `this.permissionStore` instead of a plain `permissionCache` Map.
  // Install a backing-Map-only stub that keeps the historical
  // `plugin.permissionCache.set(path, level)` test seeding API working.
  const permissionCache = new Map<string, PermissionLevel>();
  plugin.permissionCache = permissionCache;
  plugin.permissionStore = {
    async getPermission(path: string): Promise<PermissionLevel> {
      if (!plugin.session) return PermissionLevel.NONE;
      if (plugin.session.role === 'admin' || plugin.session.role === 'owner') {
        permissionCache.set(path, PermissionLevel.ADMIN);
        return PermissionLevel.ADMIN;
      }
      const exact = permissionCache.get(path);
      if (exact !== undefined) return exact;
      // Walk-up: parent segments then root sentinel.
      const segments = path.split('/');
      for (let i = segments.length - 1; i > 0; i--) {
        const parent = segments.slice(0, i).join('/');
        const lvl = permissionCache.get(parent);
        if (lvl !== undefined) return lvl;
      }
      const root = permissionCache.get('');
      if (root !== undefined) return root;
      return PermissionLevel.NONE;
    },
    getCachedPermission(path: string): PermissionLevel | undefined {
      return permissionCache.get(path);
    },
    get inFlightWarmup(): Promise<void> | null { return null; },
    emit: vi.fn((event: string, payload?: { path?: string; serverConfirmed?: boolean }) => {
      // Mirror PermissionStore's 'changed' handler enough for tests: when a
      // specific path is invalidated, drop its cache entry so subsequent
      // getCachedPermission/getPermission re-resolves. When the payload is a
      // server-confirmed wildcard (no path), clear the whole cache.
      if (event !== 'changed') return;
      if (payload && typeof payload.path === 'string') {
        permissionCache.delete(payload.path);
      } else if (payload?.serverConfirmed) {
        permissionCache.clear();
      }
    }),
    on: vi.fn(() => ({ name: '', cb: () => undefined })),
    off: vi.fn(),
    offref: vi.fn(),
    trigger: vi.fn(),
    tryTrigger: vi.fn(),
    invalidate: vi.fn(),
    sweepLeavesAfterWarm: vi.fn().mockResolvedValue(undefined),
    warm: vi.fn().mockResolvedValue(undefined),
  };
  plugin.offlineQueue = [];
  plugin.keyLease = null;
  plugin.atRestCipher = {
    isReady: vi.fn(() => true),
    encryptString: vi.fn(async (data: string) => new TextEncoder().encode(data)),
    encryptBinary: vi.fn(async (data: ArrayBuffer) => data),
    isEncrypted: vi.fn(() => false),
    decryptString: vi.fn(async (data: ArrayBuffer) => new TextDecoder().decode(data)),
    decryptBinary: vi.fn(async (data: ArrayBuffer) => data),
    getStatus: vi.fn(() => ({ kind: 'ready' })),
  };
  plugin.session = null;
  plugin.connectionState = { status: 'online', lastConnected: null, failedAttempts: 0, nextRetryAt: null, latencyMs: null };
  plugin.settings = {
    orgSlug: '',
    serverVaultId: 'vault-test-001',
    apiEndpoint: 'https://api.vaultguard.test',
    organizationId: 'org-1',
    cognitoUserPoolId: '',
    cognitoClientId: '',
    syncInterval: 30,
    cacheEncryptionStrength: 'standard',
    offlineKeyLeaseDuration: 24,
    autoWipeOnAuthFailure: false,
    showMyPermissionLevel: true,
    showOthersAccess: true,
    showPermissionBanner: true,
    defaultConflictResolution: 'ask_user',
    debugLogging: false,
    maxRetryAttempts: 1,
    showStatusBar: false,
  };
  plugin.orgSettings = null;
  plugin.syncState = {
    lastSync: null, pendingChanges: 0, conflicts: [],
    status: 'idle', bytesUploaded: 0, bytesDownloaded: 0, lastError: null,
  };

  return plugin;
}

function makeSession(role: 'member' | 'editor' | 'admin' | 'owner' = 'member') {
  return {
    sessionId: 'sess-001',
    userId: 'user-001',
    organizationId: 'org-1',
    displayName: 'Test User',
    email: 'test@vaultguard.test',
    accessToken: 'access-token',
    idToken: 'id-token',
    refreshToken: 'refresh-token',
    tokenExpiresAt: new Date(Date.now() + 3600_000).toISOString(),
    role,
    roles: [role],
    createdAt: new Date().toISOString(),
  };
}

function makeKeyLease(expiresInMs: number = 3600_000) {
  const keyBytes = crypto.getRandomValues(new Uint8Array(32));
  return {
    key: Buffer.from(keyBytes).toString('base64'),
    expiresAt: new Date(Date.now() + expiresInMs).toISOString(),
    refreshToken: 'refresh-token',
    leaseId: 'lease-001',
    algorithm: 'AES-256-GCM' as const,
    offlineCapable: true,
    scope: '/**',
    vaultId: 'vault-test-001',
  };
}

// ─── Tests ────────────────────────────────────────────────────────────────

describe('File Protection: Vault Adapter Interception', () => {
  let plugin: any;

  beforeEach(() => {
    mockNotice.mockReset();
    plugin = createTestPlugin();
  });

  // ── interceptedRead ──────────────────────────────────────────────────

  describe('interceptedRead', () => {
    it('shows a login-required notice when opening a protected file while logged out', async () => {
      plugin.session = null;

      await expect(plugin.interceptedRead('docs/readme.md'))
        .rejects.toThrow('Login required to open "docs/readme.md"');

      expect(mockNotice).toHaveBeenCalledWith(
        expect.stringContaining('VaultGuard Sync: Login required to open "docs/readme.md".'),
        9000
      );
      expect(plugin.originalAdapterMethods.read).not.toHaveBeenCalled();
    });

    it('throttles login-required notices from repeated logged-out adapter probes', async () => {
      const dateNow = vi.spyOn(Date, 'now').mockReturnValue(1000);
      plugin.session = null;

      try {
        await plugin.interceptedList('');
        await expect(plugin.interceptedRead('docs/readme.md'))
          .rejects.toThrow('Login required');

        expect(mockNotice).toHaveBeenCalledTimes(1);

        dateNow.mockReturnValue(7000);
        await expect(plugin.interceptedRead('docs/second.md'))
          .rejects.toThrow('Login required');

        expect(mockNotice).toHaveBeenCalledTimes(2);
      } finally {
        dateNow.mockRestore();
      }
    });

    it('returns disk content on NONE permission without wiping (1.0.17 fail-open)', async () => {
      // 1.0.17 hardening: the read path NEVER wipes and NEVER throws on
      // permission denial. Wiping was the 1.0.15 data-loss vector;
      // throwing was the 1.0.16 indexer-flood vector. Revocation
      // enforcement belongs in the sync engine, not the read interceptor.
      plugin.session = makeSession('member');
      plugin.permissionCache.set('secret/classified.md', PermissionLevel.NONE);

      const content = await plugin.interceptedRead('secret/classified.md');

      expect(content).toBe('local file content');
      expect(plugin.originalAdapterMethods.read).toHaveBeenCalledWith('secret/classified.md');
      expect(plugin.originalAdapterMethods.write).not.toHaveBeenCalled();
      expect(mockNotice).not.toHaveBeenCalled();
    });

    it('allows read from local cache when permission >= READ and offline', async () => {
      plugin.session = makeSession('member');
      plugin.permissionCache.set('docs/readme.md', PermissionLevel.READ);
      plugin.connectionState.status = 'offline';

      const content = await plugin.interceptedRead('docs/readme.md');
      expect(content).toBe('local file content');
      expect(plugin.originalAdapterMethods.read).toHaveBeenCalledWith('docs/readme.md');
    });

    it('waits for restored-session permission warm-up before wiping a startup read', async () => {
      plugin.session = makeSession('member');
      plugin.connectionState.status = 'offline';

      let resolveResume!: () => void;
      plugin.sessionResumePromise = new Promise<void>((resolve) => {
        resolveResume = () => {
          plugin.permissionCache.set('', PermissionLevel.READ);
          resolve();
        };
      });

      const readPromise = plugin.interceptedRead('docs/startup.md');
      await Promise.resolve();

      expect(plugin.originalAdapterMethods.write).not.toHaveBeenCalled();

      resolveResume();

      await expect(readPromise).resolves.toBe('local file content');
      expect(plugin.originalAdapterMethods.read).toHaveBeenCalledWith('docs/startup.md');
      expect(plugin.originalAdapterMethods.write).not.toHaveBeenCalled();
    });

    it('REGRESSION 1.0.15: does not wipe when warm-up has not yet completed (production sequence)', async () => {
      // Reproduces the 1.0.15 data-loss race. Production sequence:
      //   1. onload sets sessionResumePromise = restoreServerSession()
      //   2. Obsidian's "indexing vault" starts read()ing files immediately
      //   3. restoreServerSession kicks off runPermissionWarmup fire-and-forget
      //   4. restoreServerSession returns -> sessionResumePromise resolves
      //   5. Warm-up is still in flight (collectRulesForWarmup HTTP fetch)
      //   6. interceptedRead's awaitPermissionReadiness sees resolved
      //      sessionResumePromise + null inFlightWarmup -> proceeds
      //   7. getEffectivePermission returns NONE (cache cold) -> WIPE
      // The fix: shouldDeferDenialWipe returns true while hasWarmedAtLeastOnce
      // is false AND no cached entry exists, so the read returns disk content
      // unchanged instead of wiping.
      plugin.session = makeSession('member');
      plugin.connectionState.status = 'offline';

      // sessionResumePromise resolves BEFORE warm-up populates anything
      // (the actual production timing).
      plugin.sessionResumePromise = Promise.resolve();
      // hasWarmedAtLeastOnce remains false; no cache seeded.

      const content = await plugin.interceptedRead('docs/startup.md');

      expect(content).toBe('local file content');
      expect(plugin.originalAdapterMethods.read).toHaveBeenCalledWith('docs/startup.md');
      expect(plugin.originalAdapterMethods.write).not.toHaveBeenCalled();
    });

    it('REGRESSION 1.0.16: does not throw post-warmup on denial (1.0.17 fail-open)', async () => {
      // 1.0.16 still wiped + threw once hasWarmedAtLeastOnce was true,
      // causing Obsidian's indexer to flood the console with "Access
      // denied" errors per file ("stuck at indexing vault" report).
      // 1.0.17 returns disk content silently.
      plugin.session = makeSession('member');
      plugin.connectionState.status = 'offline';
      plugin.hasWarmedAtLeastOnce = true;

      const content = await plugin.interceptedRead('secret/post-warmup-denied.md');

      expect(content).toBe('local file content');
      expect(plugin.originalAdapterMethods.write).not.toHaveBeenCalled();
    });

    it('REGRESSION 1.0.16: does not throw on explicit cache denial entry (1.0.17 fail-open)', async () => {
      plugin.session = makeSession('member');
      plugin.connectionState.status = 'offline';
      plugin.permissionCache.set('secret/explicitly-denied.md', PermissionLevel.NONE);

      const content = await plugin.interceptedRead('secret/explicitly-denied.md');

      expect(content).toBe('local file content');
      expect(plugin.originalAdapterMethods.write).not.toHaveBeenCalled();
    });

    it('allows read when permission is WRITE', async () => {
      plugin.session = makeSession('editor');
      plugin.permissionCache.set('docs/readme.md', PermissionLevel.WRITE);
      plugin.connectionState.status = 'offline';

      const content = await plugin.interceptedRead('docs/readme.md');
      expect(content).toBe('local file content');
    });

    it('allows read when permission is ADMIN', async () => {
      plugin.session = makeSession('admin');
      plugin.permissionCache.set('docs/readme.md', PermissionLevel.ADMIN);
      plugin.connectionState.status = 'offline';

      const content = await plugin.interceptedRead('docs/readme.md');
      expect(content).toBe('local file content');
    });

    it('falls back to local cache on network error', async () => {
      plugin.session = makeSession('member');
      plugin.permissionCache.set('docs/file.md', PermissionLevel.READ);
      plugin.connectionState.status = 'online';
      plugin.keyLease = makeKeyLease();

      // Mock apiRequest to simulate network failure
      plugin.apiRequest = vi.fn().mockRejectedValue(new Error('net::ERR_CONNECTION_REFUSED'));

      const content = await plugin.interceptedRead('docs/file.md');
      expect(content).toBe('local file content');
    });

    it('emits a denied audit event when permission is missing (1.0.17 fail-open: no throw)', async () => {
      plugin.session = makeSession('member');
      plugin.permissionCache.set('secret.md', PermissionLevel.NONE);
      const auditSpy = vi.spyOn(plugin, 'emitAuditEvent').mockResolvedValue(undefined);

      // 1.0.17: no throw, but the audit event still fires so server-side
      // observability captures the access attempt.
      const content = await plugin.interceptedRead('secret.md');
      expect(content).toBe('local file content');

      expect(auditSpy).toHaveBeenCalledWith(
        'file.read',
        'secret.md',
        expect.objectContaining({
          outcome: 'denied',
          reason: 'permission-denied-read-fail-open',
        })
      );
    });
  });

  // ── noticeIfMediaOpenWhileLoggedOut ──────────────────────────────────

  describe('noticeIfMediaOpenWhileLoggedOut (media open bypasses the read notice)', () => {
    it('warns login-required when a signed-out user opens a renderable binary', () => {
      plugin.session = null;
      plugin.noticeIfMediaOpenWhileLoggedOut('attachments/photo.png');
      expect(mockNotice).toHaveBeenCalledWith(
        expect.stringContaining('VaultGuard Sync: Login required to open "attachments/photo.png".'),
        9000
      );
    });
    it('stays silent for a signed-out text file (interceptedRead already notices those)', () => {
      plugin.session = null;
      plugin.noticeIfMediaOpenWhileLoggedOut('docs/readme.md');
      expect(mockNotice).not.toHaveBeenCalled();
    });
    it('stays silent when authenticated', () => {
      plugin.session = makeSession('member');
      plugin.noticeIfMediaOpenWhileLoggedOut('attachments/photo.png');
      expect(mockNotice).not.toHaveBeenCalled();
    });
  });

  // ── interceptedWrite ─────────────────────────────────────────────────

  describe('interceptedWrite', () => {
    it('blocks write when effective permission is READ', async () => {
      plugin.session = makeSession('member');
      plugin.permissionCache.set('docs/readonly.md', PermissionLevel.READ);

      await expect(plugin.interceptedWrite('docs/readonly.md', 'new content'))
        .rejects.toThrow('Access denied');
      await expect(plugin.interceptedWrite('docs/readonly.md', 'new content'))
        .rejects.toThrow('write permission');
    });

    it('blocks write when effective permission is NONE', async () => {
      plugin.session = makeSession('member');
      plugin.permissionCache.set('secret.md', PermissionLevel.NONE);

      await expect(plugin.interceptedWrite('secret.md', 'content'))
        .rejects.toThrow('Access denied');
    });

    it('blocks write and includes file path in error message', async () => {
      plugin.session = makeSession('member');
      plugin.permissionCache.set('protected/file.md', PermissionLevel.READ);

      await expect(plugin.interceptedWrite('protected/file.md', 'content'))
        .rejects.toThrow('protected/file.md');
    });

    it('allows write when permission is WRITE', async () => {
      plugin.session = makeSession('editor');
      plugin.permissionCache.set('docs/editable.md', PermissionLevel.WRITE);
      plugin.connectionState.status = 'offline';

      await plugin.interceptedWrite('docs/editable.md', 'updated content');

      // Managed writes land encrypted via writeBinary (AR2) — the passthrough
      // cipher makes the bytes decodable back to the plaintext.
      expect(plugin.originalAdapterMethods.writeBinary).toHaveBeenCalledTimes(1);
      const [wbPath, wbBytes] = plugin.originalAdapterMethods.writeBinary.mock.calls[0];
      expect(wbPath).toBe('docs/editable.md');
      expect(new TextDecoder().decode(wbBytes)).toBe('updated content');
    });

    it('allows write when permission is ADMIN', async () => {
      plugin.session = makeSession('admin');
      plugin.permissionCache.set('docs/file.md', PermissionLevel.ADMIN);
      plugin.connectionState.status = 'offline';

      await plugin.interceptedWrite('docs/file.md', 'admin edit');

      expect(plugin.originalAdapterMethods.writeBinary).toHaveBeenCalledTimes(1);
      const [wbPath, wbBytes] = plugin.originalAdapterMethods.writeBinary.mock.calls[0];
      expect(wbPath).toBe('docs/file.md');
      expect(new TextDecoder().decode(wbBytes)).toBe('admin edit');
    });

    it('fails closed instead of corrupting ciphertext when the adapter lacks writeBinary (AR2)', async () => {
      plugin.session = makeSession('editor');
      plugin.permissionCache.set('docs/editable.md', PermissionLevel.WRITE);
      plugin.connectionState.status = 'offline';
      delete plugin.originalAdapterMethods.writeBinary;

      // A string write() would UTF-8-encode the ciphertext (every byte >=
      // 0x80 becomes multi-byte) and the file could never decrypt again.
      await expect(
        plugin.interceptedWrite('docs/editable.md', 'updated content')
      ).rejects.toThrow('lacks binary writes');
      expect(plugin.originalAdapterMethods.write).not.toHaveBeenCalled();
    });

    it('queues offline operation when offline', async () => {
      plugin.session = makeSession('editor');
      plugin.permissionCache.set('notes.md', PermissionLevel.WRITE);
      plugin.connectionState.status = 'offline';
      plugin.remoteFileState.recordPresent('notes.md', { versionId: 'v-base' });

      await plugin.interceptedWrite('notes.md', 'offline edit');

      expect(plugin.offlineQueue.length).toBe(1);
      expect(plugin.offlineQueue[0].operation).toBe('write');
      expect(plugin.offlineQueue[0].path).toBe('notes.md');
      expect(plugin.offlineQueue[0].baseVersionId).toBe('v-base');
    });

    it('sends expectedVersionId for online writes with known remote state', async () => {
      plugin.session = makeSession('editor');
      plugin.permissionCache.set('notes.md', PermissionLevel.WRITE);
      plugin.connectionState.status = 'online';
      plugin.keyLease = makeKeyLease();
      plugin.remoteFileState.recordPresent('notes.md', { versionId: 'v1' });
      plugin.apiRequest = vi.fn().mockResolvedValue({
        success: true,
        data: {
          path: '/notes.md',
          versionId: 'v2',
          checksum: '"etag-2"',
          size: 42,
          lastModified: '2026-07-03T00:00:00.000Z',
        },
        error: null,
        requestId: 'req-write',
      });

      await plugin.interceptedWrite('notes.md', 'online edit');

      expect(plugin.apiRequest).toHaveBeenCalledWith(
        'PUT',
        '/vaults/vault-test-001/files/notes.md',
        expect.objectContaining({ expectedVersionId: 'v1' })
      );
      expect(plugin.remoteFileState.getExpectedVersionId('notes.md')).toBe('v2');
      expect(plugin.originalAdapterMethods.writeBinary).toHaveBeenCalledOnce();
    });

    it('routes online write 409 responses to conflict handling without writing or queuing blindly', async () => {
      plugin.session = makeSession('editor');
      plugin.permissionCache.set('notes.md', PermissionLevel.WRITE);
      plugin.connectionState.status = 'online';
      plugin.keyLease = makeKeyLease();
      plugin.remoteFileState.recordPresent('notes.md', { versionId: 'v1' });
      plugin.handleRemoteWriteConflict = vi.fn().mockResolvedValue('pending');
      plugin.apiRequest = vi.fn().mockResolvedValue({
        success: false,
        data: null,
        error: {
          code: 'CONFLICT',
          message: 'stale version',
          details: null,
          statusCode: 409,
        },
        requestId: 'req-conflict',
      });

      await plugin.interceptedWrite('notes.md', 'conflicting edit');

      expect(plugin.handleRemoteWriteConflict).toHaveBeenCalledWith(
        'notes.md',
        'conflicting edit',
        'v1'
      );
      expect(plugin.originalAdapterMethods.writeBinary).not.toHaveBeenCalled();
      expect(plugin.offlineQueue).toHaveLength(0);
    });

    it('does not call original write when permission denied', async () => {
      plugin.session = makeSession('member');
      plugin.permissionCache.set('readonly.md', PermissionLevel.READ);

      try { await plugin.interceptedWrite('readonly.md', 'content'); } catch {}

      expect(plugin.originalAdapterMethods.write).not.toHaveBeenCalled();
    });

    it('does not write locally when the online backend rejects a stale cached grant', async () => {
      plugin.session = makeSession('editor');
      plugin.permissionCache.set('stale.md', PermissionLevel.WRITE);
      plugin.connectionState.status = 'online';
      plugin.keyLease = makeKeyLease();
      plugin.apiRequest = vi.fn().mockResolvedValue({
        success: false,
        data: null,
        error: {
          code: 'AUTH_ERROR',
          message: 'Access denied',
          details: null,
          statusCode: 403,
        },
        requestId: 'req-denied',
      });

      await expect(plugin.interceptedWrite('stale.md', 'should not land locally'))
        .rejects.toThrow('Access denied');

      expect(plugin.originalAdapterMethods.write).not.toHaveBeenCalled();
      expect(plugin.offlineQueue).toHaveLength(0);
    });
  });

  // ── interceptedWriteBinary ───────────────────────────────────────────

  describe('interceptedWriteBinary (BIN-A / D-08)', () => {
    // PNG magic + invalid-UTF-8 continuation bytes: real attachment content,
    // NOT VG1 ciphertext and NOT valid UTF-8 (so it is a genuine binary drop).
    const PNG = () =>
      new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x80, 0xff, 0xfe, 0x00]);

    it('uploads an in-size binary via the byte PUT, then writes VG1 to disk (PUT first — CR-1)', async () => {
      plugin.session = makeSession('editor');
      plugin.keyLease = makeKeyLease();
      plugin.connectionState.status = 'online';
      plugin.permissionCache.set('img/pic.png', PermissionLevel.WRITE);

      const bytes = PNG();
      const puts: any[] = [];
      const callOrder: string[] = [];
      plugin.apiRequest = vi.fn(async (method: string, endpoint: string, body: any, _id?: unknown, options?: unknown) => {
        if (method === 'PUT' && endpoint.includes('/files/')) {
          puts.push({ endpoint, body, options });
          callOrder.push('PUT');
        }
        return { success: true, data: {}, error: null, requestId: 'r' };
      });
      plugin.originalAdapterMethods.writeBinary = vi.fn(async () => { callOrder.push('writeBinary'); });

      await plugin.interceptedWriteBinary('img/pic.png', bytes.buffer);

      expect(puts).toHaveLength(1);
      expect(puts[0].endpoint).toContain('img%2Fpic.png');
      expect(puts[0].body.contentType).toBe('image/png');
      expect(puts[0].options).toEqual({ timeoutMs: 120_000 });
      // The PUT hash is the byte hash of the PLAINTEXT bytes…
      expect(puts[0].body.hash).toBe(await plugin.computeHashBytes(bytes.buffer));
      // …and the ciphertext decrypts back to the EXACT original bytes (no lossy
      // UTF-8 decode — the AR1 corruption class stays gone).
      const decrypted = await plugin.decryptContentBytes(puts[0].body.content);
      expect(new Uint8Array(decrypted)).toEqual(bytes);
      // CR-1 ordering: successful/queued PUT first, local VG1 write second.
      expect(callOrder).toEqual(['PUT', 'writeBinary']);
    });

    it('queues an in-size binary (base64 + encoding + contentType) and writes VG1 when offline', async () => {
      plugin.session = makeSession('editor');
      plugin.connectionState.status = 'offline';
      plugin.permissionCache.set('img/pic.png', PermissionLevel.WRITE);

      const bytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x80, 0xff]);
      plugin.apiRequest = vi.fn();

      await plugin.interceptedWriteBinary('img/pic.png', bytes.buffer);

      // No PUT offline. The local VG1 write is safe: the queued op IS the
      // server-copy path (CR-1 satisfied by the queue).
      expect(plugin.apiRequest).not.toHaveBeenCalled();
      expect(plugin.originalAdapterMethods.writeBinary).toHaveBeenCalledTimes(1);
      const writeOp = plugin.offlineQueue.find((op: any) => op.operation === 'write');
      expect(writeOp).toMatchObject({ path: 'img/pic.png', encoding: 'base64', contentType: 'image/png' });
      expect(new Uint8Array(Buffer.from(writeOp.data, 'base64'))).toEqual(bytes);
    });

    it('rejects an oversize binary fail-closed: throw + throttled Notice + zero disk + zero queue (OD-1)', async () => {
      plugin.session = makeSession('editor');
      plugin.keyLease = makeKeyLease();
      plugin.connectionState.status = 'online';
      plugin.permissionCache.set('img/huge.bin', PermissionLevel.WRITE);
      plugin.apiRequest = vi.fn();
      mockNotice.mockClear();

      const huge = new Uint8Array(7 * 1024 * 1024 + 16);
      huge[0] = 0xff;
      huge[1] = 0xfe;

      await expect(plugin.interceptedWriteBinary('img/huge.bin', huge.buffer))
        .rejects.toThrow(/attachment sync limit/);

      // OD-1: nothing lands on disk, nothing queues, no PUT ever fires.
      expect(plugin.apiRequest).not.toHaveBeenCalled();
      expect(plugin.originalAdapterMethods.writeBinary).not.toHaveBeenCalled();
      expect(plugin.offlineQueue).toHaveLength(0);
      expect(mockNotice).toHaveBeenCalledTimes(1);
      expect(mockNotice).toHaveBeenCalledWith(expect.stringContaining('7 MB'), 10000);

      // Throttled: a second oversize drop of the same path throws again but
      // does not stack a second Notice.
      mockNotice.mockClear();
      await expect(plugin.interceptedWriteBinary('img/huge.bin', huge.buffer))
        .rejects.toThrow(/attachment sync limit/);
      expect(mockNotice).not.toHaveBeenCalled();
    });

    it('AC-API1: a permanent 4xx (413) throws and queues nothing (no local VG1 orphan)', async () => {
      plugin.session = makeSession('editor');
      plugin.keyLease = makeKeyLease();
      plugin.connectionState.status = 'online';
      plugin.permissionCache.set('img/pic.png', PermissionLevel.WRITE);
      plugin.apiRequest = vi.fn().mockResolvedValue({
        success: false,
        data: null,
        error: { code: 'PAYLOAD_TOO_LARGE', message: 'Payload too large', details: null, statusCode: 413 },
        requestId: 'req-413',
      });

      const bytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x80, 0xff]);
      await expect(plugin.interceptedWriteBinary('img/pic.png', bytes.buffer))
        .rejects.toThrow('Payload too large');

      // Permanent failure: no local VG1 write (CR-1 — never orphan a copy the
      // server refused), nothing queued (AC-API1).
      expect(plugin.originalAdapterMethods.writeBinary).not.toHaveBeenCalled();
      expect(plugin.offlineQueue).toHaveLength(0);
    });

    it('AC-API1: statusCode 0 flips offline, queues (base64 + encoding), then writes VG1', async () => {
      plugin.session = makeSession('editor');
      plugin.keyLease = makeKeyLease();
      plugin.connectionState.status = 'online';
      plugin.permissionCache.set('img/pic.png', PermissionLevel.WRITE);
      plugin.setConnectionStatus = vi.fn();
      plugin.apiRequest = vi.fn().mockResolvedValue({
        success: false,
        data: null,
        error: { code: 'NETWORK', message: 'network', details: null, statusCode: 0 },
        requestId: 'req-0',
      });

      const bytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x80, 0xff]);
      await plugin.interceptedWriteBinary('img/pic.png', bytes.buffer);

      // The ctx setConnectionStatus lambda forwards a trailing options arg.
      expect(plugin.setConnectionStatus).toHaveBeenCalledWith('offline', undefined);
      const writeOp = plugin.offlineQueue.find((op: any) => op.operation === 'write');
      expect(writeOp).toMatchObject({ path: 'img/pic.png', encoding: 'base64', contentType: 'image/png' });
      // A transient failure still lands the local VG1 copy (the queued op is
      // the server-copy path).
      expect(plugin.originalAdapterMethods.writeBinary).toHaveBeenCalledTimes(1);
    });

    it('AC-API1: 401/403 throws and never queues (auth is permanent)', async () => {
      plugin.session = makeSession('editor');
      plugin.keyLease = makeKeyLease();
      plugin.connectionState.status = 'online';
      plugin.permissionCache.set('img/pic.png', PermissionLevel.WRITE);
      plugin.apiRequest = vi.fn().mockResolvedValue({
        success: false,
        data: null,
        error: { code: 'AUTH_ERROR', message: 'Access denied', details: null, statusCode: 403 },
        requestId: 'req-403',
      });

      const bytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x80, 0xff]);
      await expect(plugin.interceptedWriteBinary('img/pic.png', bytes.buffer))
        .rejects.toThrow('Access denied');
      expect(plugin.originalAdapterMethods.writeBinary).not.toHaveBeenCalled();
      expect(plugin.offlineQueue).toHaveLength(0);
    });

    it('refuses bytes that already carry the VG1 magic (guard kept verbatim)', async () => {
      plugin.session = makeSession('editor');
      plugin.permissionCache.set('img/pic.png', PermissionLevel.WRITE);
      // Force the cipher to recognise these bytes as at-rest ciphertext.
      plugin.atRestCipher.isEncrypted = vi.fn(() => true);
      const vg1 = new Uint8Array([0x56, 0x47, 0x31, 0x00, 0x01, 0x02]).buffer;

      await expect(plugin.interceptedWriteBinary('img/pic.png', vg1))
        .rejects.toThrow(/at-rest ciphertext/);
      expect(plugin.originalAdapterMethods.writeBinary).not.toHaveBeenCalled();
    });

    it('bypasses upload/permission during an applyingRemoteWrite (writes VG1 directly)', async () => {
      // A remote pull sets applyingRemoteWrite; the interceptor must pass the
      // bytes straight to the at-rest disk write with no PUT / permission gate.
      plugin.applyingRemoteWrite = true;
      plugin.apiRequest = vi.fn();
      const bytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x80, 0xff]).buffer;

      await plugin.interceptedWriteBinary('img/pic.png', bytes);

      expect(plugin.apiRequest).not.toHaveBeenCalled();
      expect(plugin.originalAdapterMethods.writeBinary).toHaveBeenCalledTimes(1);
    });

    it('silently returns on a legacy adapter without writeBinary (D-10, byte-identical to today)', async () => {
      plugin.session = makeSession('editor');
      plugin.permissionCache.set('img/pic.png', PermissionLevel.WRITE);
      plugin.originalAdapterMethods.writeBinary = null;
      plugin.apiRequest = vi.fn();
      const bytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x80, 0xff]).buffer;

      // No throw, no PUT, no queue — exactly today's behavior.
      await expect(plugin.interceptedWriteBinary('img/pic.png', bytes)).resolves.toBeUndefined();
      expect(plugin.apiRequest).not.toHaveBeenCalled();
      expect(plugin.offlineQueue).toHaveLength(0);
    });
  });

  // ── interceptedRename binary (BIN-A / L1) ────────────────────────────

  describe('interceptedRename binary (BIN-A/L1)', () => {
    // AR1-style: PNG magic + invalid-UTF-8 continuation bytes. A lossy UTF-8
    // decode (the pre-fix bug) would mangle these into U+FFFD before the PUT.
    const PNG = () =>
      new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x80, 0xff, 0xfe, 0x00]);

    // Capture only file-PUTs, tolerant of a 5th (timeout options) arg.
    function capturingApiRequest(puts: any[]) {
      return vi.fn(async (method: string, endpoint: string, body: any, _id?: unknown, options?: unknown) => {
        if (method === 'PUT' && endpoint.includes('/files/')) puts.push({ endpoint, body, options });
        return { success: true, data: {}, error: null, requestId: 'r' };
      });
    }

    beforeEach(() => {
      // interceptedRename probes for a folder rename (TFolder) before touching
      // content — the base app mock has no vault.getAbstractFileByPath, so a
      // plain-file stand-in (null ⇒ not a folder) lets the file path proceed.
      plugin.app.vault.getAbstractFileByPath = vi.fn(() => null);
    });

    it('renames a binary via the byte PUT — contentType, byte hash, round-trips (no lossy decode)', async () => {
      plugin.session = makeSession('editor');
      plugin.keyLease = makeKeyLease();
      plugin.connectionState.status = 'online';
      plugin.permissionCache.set('img/new.png', PermissionLevel.WRITE);

      const bytes = PNG();
      plugin.originalAdapterMethods.rename = vi.fn().mockResolvedValue(undefined);
      plugin.originalAdapterMethods.readBinary = vi.fn().mockResolvedValue(bytes.buffer);

      const puts: any[] = [];
      plugin.apiRequest = capturingApiRequest(puts);

      await plugin.interceptedRename('img/old.png', 'img/new.png');

      expect(puts).toHaveLength(1);
      expect(puts[0].endpoint).toContain('img%2Fnew.png');
      expect(puts[0].body.contentType).toBe('image/png');
      expect(puts[0].options).toEqual({ timeoutMs: 120_000 });
      // Byte hash of the plain bytes…
      expect(puts[0].body.hash).toBe(await plugin.computeHashBytes(bytes.buffer));
      // …and the ciphertext decrypts back to the EXACT original bytes — proving
      // the L1 lossy-decode corruption is gone (byte-identical server copy).
      const decrypted = await plugin.decryptContentBytes(puts[0].body.content);
      expect(new Uint8Array(decrypted)).toEqual(bytes);
    });

    it('queues a binary rename as base64 (encoding + contentType) when offline', async () => {
      plugin.session = makeSession('editor');
      plugin.connectionState.status = 'offline';
      plugin.permissionCache.set('img/new.png', PermissionLevel.WRITE);

      const bytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x80, 0xff]);
      plugin.originalAdapterMethods.rename = vi.fn().mockResolvedValue(undefined);
      plugin.originalAdapterMethods.readBinary = vi.fn().mockResolvedValue(bytes.buffer);
      plugin.apiRequest = vi.fn();

      await plugin.interceptedRename('img/old.png', 'img/new.png');

      expect(plugin.apiRequest).not.toHaveBeenCalled();
      const writeOp = plugin.offlineQueue.find((op: any) => op.operation === 'write');
      const deleteOp = plugin.offlineQueue.find((op: any) => op.operation === 'delete');
      expect(writeOp).toMatchObject({ path: 'img/new.png', encoding: 'base64', contentType: 'image/png' });
      expect(deleteOp).toMatchObject({ path: 'img/old.png' });
      // The queued base64 decodes back to the original bytes.
      expect(new Uint8Array(Buffer.from(writeOp.data, 'base64'))).toEqual(bytes);
    });

    it('skips ALL server ops for an oversize binary rename and Notices once (throttled)', async () => {
      plugin.session = makeSession('editor');
      plugin.keyLease = makeKeyLease();
      plugin.connectionState.status = 'online';
      plugin.permissionCache.set('img/huge.bin', PermissionLevel.WRITE);

      // > 7 MiB and invalid UTF-8 (leading 0xff) so it is probed as binary.
      const huge = new Uint8Array(7 * 1024 * 1024 + 16);
      huge[0] = 0xff;
      huge[1] = 0xfe;
      plugin.originalAdapterMethods.rename = vi.fn().mockResolvedValue(undefined);
      plugin.originalAdapterMethods.readBinary = vi.fn().mockResolvedValue(huge.buffer);
      plugin.apiRequest = vi.fn();
      mockNotice.mockClear();

      await plugin.interceptedRename('img/old.bin', 'img/huge.bin');

      // No PUT, no queued write, and NO delete of the old server path.
      expect(plugin.apiRequest).not.toHaveBeenCalled();
      expect(plugin.offlineQueue).toHaveLength(0);
      expect(mockNotice).toHaveBeenCalledTimes(1);
      expect(mockNotice).toHaveBeenCalledWith(expect.stringContaining('7 MB'), 10000);

      // Second rename onto the SAME new path within 60 s: throttle suppresses it.
      mockNotice.mockClear();
      await plugin.interceptedRename('img/old2.bin', 'img/huge.bin');
      expect(mockNotice).not.toHaveBeenCalled();
      expect(plugin.apiRequest).not.toHaveBeenCalled();
      expect(plugin.offlineQueue).toHaveLength(0);
    });

    it('keeps the legacy string rename path when the adapter lacks readBinary (D-10)', async () => {
      plugin.session = makeSession('editor');
      plugin.keyLease = makeKeyLease();
      plugin.connectionState.status = 'online';
      plugin.permissionCache.set('notes/new.md', PermissionLevel.WRITE);

      // Legacy adapter: no readBinary → today's string flow verbatim.
      plugin.originalAdapterMethods.readBinary = null;
      plugin.originalAdapterMethods.rename = vi.fn().mockResolvedValue(undefined);
      plugin.readPlainFromDisk = vi.fn().mockResolvedValue('# renamed note');

      const puts: any[] = [];
      plugin.apiRequest = capturingApiRequest(puts);

      await plugin.interceptedRename('notes/old.md', 'notes/new.md');

      // The STRING read path ran (proving the legacy branch)…
      expect(plugin.readPlainFromDisk).toHaveBeenCalledWith('notes/new.md');
      // …and the PUT body is today's { content, hash } shape (no contentType, no
      // timeout override) — legacy behavior unchanged.
      expect(puts).toHaveLength(1);
      expect(puts[0].body).toEqual({ content: expect.any(String), hash: expect.any(String) });
      expect(puts[0].body).not.toHaveProperty('contentType');
      expect(puts[0].options).toBeUndefined();
    });

    it('renames a TEXT file via the string flow even on a capable adapter (no contentType/timeout)', async () => {
      plugin.session = makeSession('editor');
      plugin.keyLease = makeKeyLease();
      plugin.connectionState.status = 'online';
      plugin.permissionCache.set('notes/new.md', PermissionLevel.WRITE);

      // Valid UTF-8 → probed as text; a capable adapter still routes through the
      // string path (reusing the decoded string, no double read).
      const text = new TextEncoder().encode('# hello world\n');
      plugin.originalAdapterMethods.rename = vi.fn().mockResolvedValue(undefined);
      plugin.originalAdapterMethods.readBinary = vi.fn().mockResolvedValue(text.buffer);

      const puts: any[] = [];
      plugin.apiRequest = capturingApiRequest(puts);

      await plugin.interceptedRename('notes/old.md', 'notes/new.md');

      expect(puts).toHaveLength(1);
      expect(puts[0].body).toEqual({ content: expect.any(String), hash: expect.any(String) });
      expect(puts[0].body).not.toHaveProperty('contentType');
      expect(puts[0].options).toBeUndefined();
      // The PUT content decrypts via the STRING decrypt back to the text.
      const decrypted = await plugin.decryptContent(puts[0].body.content);
      expect(decrypted).toBe('# hello world\n');
    });
  });

  // ── ensureAtRestEncryptedInPlace (externally-added files) ────────────

  describe('ensureAtRestEncryptedInPlace', () => {
    const textBytes = () => new TextEncoder().encode('# externally added note\n').buffer;

    beforeEach(() => {
      plugin.originalAdapterMethods.readBinary = vi.fn().mockResolvedValue(textBytes());
    });

    it('re-encrypts an externally-added plaintext text file in place with identical bytes', async () => {
      const result = await plugin.ensureAtRestEncryptedInPlace('dropped/note.md');

      expect(result).toBe(true);
      expect(plugin.atRestCipher.encryptBinary).toHaveBeenCalledOnce();
      const encryptedInput = plugin.atRestCipher.encryptBinary.mock.calls[0][0];
      expect(new TextDecoder().decode(encryptedInput)).toBe('# externally added note\n');
      expect(plugin.originalAdapterMethods.writeBinary).toHaveBeenCalledOnce();
    });

    it('no-ops for files that are already VG1 ciphertext', async () => {
      plugin.atRestCipher.isEncrypted = vi.fn(() => true);

      const result = await plugin.ensureAtRestEncryptedInPlace('already/encrypted.md');

      expect(result).toBe(false);
      expect(plugin.originalAdapterMethods.writeBinary).not.toHaveBeenCalled();
    });

    it('encrypts an in-size external binary in place (VG1) now that BIN-A can sync it', async () => {
      const bytes = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x80, 0xff]);
      plugin.originalAdapterMethods.readBinary = vi.fn().mockResolvedValue(bytes.buffer);

      const result = await plugin.ensureAtRestEncryptedInPlace('img/photo.png');

      expect(result).toBe(true);
      // The RAW binary bytes were handed to the at-rest cipher, byte-identical.
      expect(plugin.atRestCipher.encryptBinary).toHaveBeenCalledOnce();
      expect(new Uint8Array(plugin.atRestCipher.encryptBinary.mock.calls[0][0])).toEqual(bytes);
      expect(plugin.originalAdapterMethods.writeBinary).toHaveBeenCalledOnce();
    });

    it('leaves an OVERSIZE external binary plaintext — provably NOT LAK-encrypted (L10 / CR-1)', async () => {
      // > 7 MiB and invalid UTF-8 (leading 0xff) → classified binary. Until BIN-B
      // it has no server copy, so LAK-encrypting it would be the CR-1 data-loss
      // class: envelope loss = permanent loss.
      const huge = new Uint8Array(7 * 1024 * 1024 + 16);
      huge[0] = 0xff;
      huge[1] = 0xfe;
      plugin.originalAdapterMethods.readBinary = vi.fn().mockResolvedValue(huge.buffer);

      const result = await plugin.ensureAtRestEncryptedInPlace('img/huge.bin');

      expect(result).toBe(false);
      // No cipher call, no disk write — the oversize binary stays readable plaintext.
      expect(plugin.atRestCipher.encryptBinary).not.toHaveBeenCalled();
      expect(plugin.originalAdapterMethods.writeBinary).not.toHaveBeenCalled();
    });

    it('skips binary in-place encryption on a legacy adapter without readBinary (D-10)', async () => {
      plugin.originalAdapterMethods.readBinary = null;

      const result = await plugin.ensureAtRestEncryptedInPlace('img/photo.png');

      expect(result).toBe(false);
      expect(plugin.originalAdapterMethods.writeBinary).not.toHaveBeenCalled();
    });

    it('skips excluded paths', async () => {
      const result = await plugin.ensureAtRestEncryptedInPlace('.obsidian/workspace.json');

      expect(result).toBe(false);
      expect(plugin.originalAdapterMethods.writeBinary).not.toHaveBeenCalled();
    });

    it('returns false without throwing when the cipher is not ready', async () => {
      plugin.atRestCipher.isReady = vi.fn(() => false);

      const result = await plugin.ensureAtRestEncryptedInPlace('dropped/note.md');

      expect(result).toBe(false);
      expect(plugin.originalAdapterMethods.writeBinary).not.toHaveBeenCalled();
    });

    it('returns false without throwing when the raw read fails', async () => {
      plugin.originalAdapterMethods.readBinary = vi.fn().mockRejectedValue(new Error('EBUSY'));

      const result = await plugin.ensureAtRestEncryptedInPlace('dropped/note.md');

      expect(result).toBe(false);
      expect(plugin.originalAdapterMethods.writeBinary).not.toHaveBeenCalled();
    });
  });

  // ── interceptedDelete ────────────────────────────────────────────────

  describe('interceptedDelete', () => {
    it('blocks delete when effective permission is READ', async () => {
      plugin.session = makeSession('member');
      plugin.permissionCache.set('docs/important.md', PermissionLevel.READ);

      await expect(plugin.interceptedDelete('docs/important.md'))
        .rejects.toThrow('Access denied');
      await expect(plugin.interceptedDelete('docs/important.md'))
        .rejects.toThrow('permission to delete');
    });

    it('blocks delete when effective permission is NONE', async () => {
      plugin.session = makeSession('member');
      plugin.permissionCache.set('secret.md', PermissionLevel.NONE);

      await expect(plugin.interceptedDelete('secret.md'))
        .rejects.toThrow('Access denied');
    });

    it('blocks delete and includes file path in error', async () => {
      plugin.session = makeSession('member');
      plugin.permissionCache.set('protected/doc.md', PermissionLevel.READ);

      await expect(plugin.interceptedDelete('protected/doc.md'))
        .rejects.toThrow('protected/doc.md');
    });

    it('blocks delete when effective permission is WRITE but no delete grant is known', async () => {
      plugin.session = makeSession('editor');
      plugin.permissionCache.set('trash/old.md', PermissionLevel.WRITE);
      plugin.connectionState.status = 'offline';

      await expect(plugin.interceptedDelete('trash/old.md')).rejects.toThrow('Access denied');

      expect(plugin.originalAdapterMethods.remove).not.toHaveBeenCalled();
    });

    it('allows delete when permission is ADMIN', async () => {
      plugin.session = makeSession('admin');
      plugin.permissionCache.set('old-file.md', PermissionLevel.ADMIN);
      plugin.connectionState.status = 'offline';

      await plugin.interceptedDelete('old-file.md');

      expect(plugin.originalAdapterMethods.remove).toHaveBeenCalledWith('old-file.md');
    });

    it('allows delete when the backend delete action is explicitly allowed', async () => {
      plugin.session = makeSession('editor');
      plugin.connectionState.status = 'online';
      plugin.apiRequest = vi.fn()
        .mockResolvedValueOnce({ success: true, data: { allowed: true }, error: null, requestId: 'check' })
        .mockResolvedValueOnce({ success: true, data: {}, error: null, requestId: 'delete' });

      await plugin.interceptedDelete('trash/old.md');

      expect(plugin.apiRequest).toHaveBeenNthCalledWith(1, 'POST', '/vaults/vault-test-001/permissions/check', expect.objectContaining({
        action: 'delete',
        path: '/trash/old.md',
      }));
      expect(plugin.originalAdapterMethods.remove).toHaveBeenCalledWith('trash/old.md');
    });

    it('removes path from permission cache after successful delete', async () => {
      plugin.session = makeSession('admin');
      plugin.permissionCache.set('to-delete.md', PermissionLevel.ADMIN);
      plugin.connectionState.status = 'offline';

      await plugin.interceptedDelete('to-delete.md');

      expect(plugin.permissionCache.has('to-delete.md')).toBe(false);
    });

    it('does not call original remove when permission denied', async () => {
      plugin.session = makeSession('member');
      plugin.permissionCache.set('protected.md', PermissionLevel.READ);

      try { await plugin.interceptedDelete('protected.md'); } catch {}

      expect(plugin.originalAdapterMethods.remove).not.toHaveBeenCalled();
    });
  });

  // ── interceptedList ──────────────────────────────────────────────────

  describe('interceptedList', () => {
    it('returns files from the local adapter without live permission probes', async () => {
      plugin.session = makeSession('member');
      plugin.permissionCache.set('public/doc.md', PermissionLevel.READ);
      plugin.permissionCache.set('private/secret.md', PermissionLevel.NONE);
      plugin.permissionCache.set('shared/notes.md', PermissionLevel.WRITE);
      plugin.permissionStore.getPermission = vi.fn().mockResolvedValue(PermissionLevel.NONE);

      const listing = await plugin.interceptedList('');

      expect(listing.files).toEqual(['public/doc.md', 'private/secret.md', 'shared/notes.md']);
      expect(plugin.permissionStore.getPermission).not.toHaveBeenCalled();
    });

    it('keeps folders visible even when folder permission cache is NONE', async () => {
      plugin.session = makeSession('member');
      plugin.permissionCache.set('public', PermissionLevel.READ);
      plugin.permissionCache.set('private', PermissionLevel.NONE);
      plugin.permissionCache.set('shared', PermissionLevel.WRITE);

      const listing = await plugin.interceptedList('');

      expect(listing.folders).toEqual(['public', 'private', 'shared']);
    });

    it('returns the local listing before auth so Obsidian can render the tree', async () => {
      plugin.session = null;

      const listing = await plugin.interceptedList('');

      expect(listing.files).toEqual(['public/doc.md', 'private/secret.md', 'shared/notes.md']);
      expect(listing.folders).toEqual(['public', 'private', 'shared']);
      expect(mockNotice).not.toHaveBeenCalled();
    });

    it('returns empty when no original list method', async () => {
      plugin.session = makeSession('member');
      plugin.originalAdapterMethods.list = null;

      const listing = await plugin.interceptedList('');

      expect(listing.files).toHaveLength(0);
      expect(listing.folders).toHaveLength(0);
    });
  });
});

// ── Permission Resolution ──────────────────────────────────────────────

describe('File Protection: Permission Resolution', () => {
  let plugin: any;

  beforeEach(() => {
    plugin = createTestPlugin();
  });

  describe('getEffectivePermission', () => {
    it('returns cached value when available', async () => {
      plugin.session = makeSession('member');
      plugin.permissionCache.set('docs/cached.md', PermissionLevel.WRITE);

      const result = await plugin.getEffectivePermission('docs/cached.md');
      expect(result).toBe(PermissionLevel.WRITE);
    });

    it('auto-grants ADMIN for admin role (no server round-trip)', async () => {
      plugin.session = makeSession('admin');

      const result = await plugin.getEffectivePermission('any/file.md');

      expect(result).toBe(PermissionLevel.ADMIN);
      // Verify it was also cached
      expect(plugin.permissionCache.get('any/file.md')).toBe(PermissionLevel.ADMIN);
    });

    it('auto-grants ADMIN for owner role', async () => {
      plugin.session = makeSession('owner');

      const result = await plugin.getEffectivePermission('any/file.md');
      expect(result).toBe(PermissionLevel.ADMIN);
    });

    it('returns NONE when no session (pre-auth fail closed)', async () => {
      plugin.session = null;

      const result = await plugin.getEffectivePermission('file.md');
      expect(result).toBe(PermissionLevel.NONE);
    });

    it('falls back to cache on network error for member', async () => {
      plugin.session = makeSession('member');
      plugin.permissionCache.set('docs', PermissionLevel.READ);
      plugin.connectionState.status = 'online';

      // Mock apiRequest to fail with network error
      plugin.apiRequest = vi.fn().mockRejectedValue(new Error('net::ERR_CONNECTION_REFUSED'));

      const result = await plugin.getEffectivePermission('docs/child.md');

      // Should walk up and find 'docs' in cache
      expect(result).toBe(PermissionLevel.READ);
    });
  });

  describe('resolvePermissionFromCache', () => {
    it('walks up directory hierarchy to find cached permission', () => {
      plugin.session = makeSession('member');
      plugin.permissionCache.set('engineering', PermissionLevel.WRITE);

      const result = plugin.resolvePermissionFromCache('engineering/api/routes.ts');
      expect(result).toBe(PermissionLevel.WRITE);
    });

    it('uses most specific cached ancestor', () => {
      plugin.session = makeSession('member');
      plugin.permissionCache.set('docs', PermissionLevel.READ);
      plugin.permissionCache.set('docs/admin', PermissionLevel.ADMIN);

      const result = plugin.resolvePermissionFromCache('docs/admin/settings.md');
      expect(result).toBe(PermissionLevel.ADMIN);
    });

    it('returns NONE with valid key lease and no cache match', () => {
      plugin.session = makeSession('member');
      plugin.keyLease = makeKeyLease(3600_000); // valid for 1 hour

      const result = plugin.resolvePermissionFromCache('unknown/path.md');
      expect(result).toBe(PermissionLevel.NONE);
    });

    it('returns NONE for admin role with no cache match inside cache-only resolver', () => {
      plugin.session = makeSession('admin');

      const result = plugin.resolvePermissionFromCache('unknown/path.md');
      expect(result).toBe(PermissionLevel.NONE);
    });

    it('returns NONE for owner role with no cache match inside cache-only resolver', () => {
      plugin.session = makeSession('owner');

      const result = plugin.resolvePermissionFromCache('unknown/path.md');
      expect(result).toBe(PermissionLevel.NONE);
    });

    it('returns NONE for editor role with no cache match', () => {
      plugin.session = makeSession('editor');

      const result = plugin.resolvePermissionFromCache('unknown/path.md');
      expect(result).toBe(PermissionLevel.NONE);
    });

    it('returns NONE for member role with no cache match and no key lease', () => {
      plugin.session = makeSession('member');
      plugin.keyLease = null;

      const result = plugin.resolvePermissionFromCache('unknown/path.md');
      expect(result).toBe(PermissionLevel.NONE);
    });

    it('returns NONE when no session at all', () => {
      plugin.session = null;

      const result = plugin.resolvePermissionFromCache('any/path.md');
      expect(result).toBe(PermissionLevel.NONE);
    });

    it('returns NONE for member with expired key lease', () => {
      plugin.session = makeSession('member');
      plugin.keyLease = makeKeyLease(-60_000); // expired 1 minute ago

      const result = plugin.resolvePermissionFromCache('unknown/path.md');
      expect(result).toBe(PermissionLevel.NONE);
    });
  });
});

// ── End-to-End Protection Flows ────────────────────────────────────────

describe('File Protection: End-to-End Flows', () => {
  let plugin: any;

  beforeEach(() => {
    plugin = createTestPlugin();
  });

  it('read-only member cannot edit .md files', async () => {
    plugin.session = makeSession('member');
    plugin.permissionCache.set('shared/team-notes.md', PermissionLevel.READ);

    // Can read
    plugin.connectionState.status = 'offline';
    const content = await plugin.interceptedRead('shared/team-notes.md');
    expect(content).toBe('local file content');

    // Cannot write
    await expect(plugin.interceptedWrite('shared/team-notes.md', 'unauthorized edit'))
      .rejects.toThrow('Access denied');

    // Cannot delete
    await expect(plugin.interceptedDelete('shared/team-notes.md'))
      .rejects.toThrow('Access denied');

    // Original adapter was NOT called for write/delete
    expect(plugin.originalAdapterMethods.write).not.toHaveBeenCalled();
    expect(plugin.originalAdapterMethods.remove).not.toHaveBeenCalled();
  });

  it('editor can read and write but cannot delete with WRITE alone', async () => {
    plugin.session = makeSession('editor');
    plugin.permissionCache.set('project/design.md', PermissionLevel.WRITE);
    plugin.connectionState.status = 'offline';

    // Can read
    const content = await plugin.interceptedRead('project/design.md');
    expect(content).toBe('local file content');

    // Can write (encrypted content lands via writeBinary — AR2)
    await plugin.interceptedWrite('project/design.md', 'design update');
    expect(plugin.originalAdapterMethods.writeBinary).toHaveBeenCalled();

    await expect(plugin.interceptedDelete('project/design.md')).rejects.toThrow('Access denied');
    expect(plugin.originalAdapterMethods.remove).not.toHaveBeenCalled();
  });

  it('admin has full access to all operations', async () => {
    plugin.session = makeSession('admin');
    // Admin role auto-grants ADMIN via getEffectivePermission, no cache needed
    plugin.connectionState.status = 'offline';

    await plugin.interceptedRead('any/file.md');
    await plugin.interceptedWrite('any/file.md', 'admin content');
    await plugin.interceptedDelete('any/file.md');

    expect(plugin.originalAdapterMethods.read).toHaveBeenCalledTimes(1);
    expect(plugin.originalAdapterMethods.writeBinary).toHaveBeenCalledTimes(1);
    expect(plugin.originalAdapterMethods.remove).toHaveBeenCalledTimes(1);
  });

  it('permission changes are enforced immediately from cache', async () => {
    plugin.session = makeSession('member');
    plugin.connectionState.status = 'offline';

    // Initially has WRITE
    plugin.permissionCache.set('file.md', PermissionLevel.WRITE);
    await plugin.interceptedWrite('file.md', 'allowed');
    expect(plugin.originalAdapterMethods.writeBinary).toHaveBeenCalledTimes(1);

    // Permission downgraded to READ
    plugin.permissionCache.set('file.md', PermissionLevel.READ);
    await expect(plugin.interceptedWrite('file.md', 'blocked'))
      .rejects.toThrow('Access denied');
    expect(plugin.originalAdapterMethods.writeBinary).toHaveBeenCalledTimes(1); // not called again
  });

  it('revoked access (NONE) blocks writes/deletes, returns disk content on reads (1.0.17 fail-open)', async () => {
    plugin.session = makeSession('member');
    plugin.permissionCache.set('revoked.md', PermissionLevel.NONE);

    // 1.0.17: reads no longer wipe or throw on denial. Writes and deletes
    // still throw because those are mutations that the sync layer needs to
    // block.
    const content = await plugin.interceptedRead('revoked.md');
    expect(content).toBe('local file content');

    await expect(plugin.interceptedWrite('revoked.md', 'data')).rejects.toThrow('Access denied');
    await expect(plugin.interceptedDelete('revoked.md')).rejects.toThrow('Access denied');

    expect(plugin.originalAdapterMethods.read).toHaveBeenCalledWith('revoked.md');
    expect(plugin.originalAdapterMethods.write).not.toHaveBeenCalled();
    expect(plugin.originalAdapterMethods.remove).not.toHaveBeenCalled();
  });

  it('directory listing stays raw; sidebar decorations hide confirmed no-access files', async () => {
    plugin.session = makeSession('member');
    plugin.permissionCache.set('public/doc.md', PermissionLevel.READ);
    plugin.permissionCache.set('private/secret.md', PermissionLevel.NONE);
    plugin.permissionCache.set('shared/notes.md', PermissionLevel.WRITE);
    plugin.permissionCache.set('public', PermissionLevel.READ);
    plugin.permissionCache.set('private', PermissionLevel.NONE);
    plugin.permissionCache.set('shared', PermissionLevel.WRITE);

    const listing = await plugin.interceptedList('');

    // Permission-driven visibility is handled by FileExplorerDecorations
    // after backend access summaries arrive. adapter.list() itself must not
    // collapse the tree while permissions are cold or unavailable.
    expect(listing.files).toEqual(['public/doc.md', 'private/secret.md', 'shared/notes.md']);
    expect(listing.folders).toEqual(['public', 'private', 'shared']);
  });

  it('offline queue deduplicates writes to the same file', async () => {
    plugin.session = makeSession('editor');
    plugin.permissionCache.set('notes.md', PermissionLevel.WRITE);
    plugin.connectionState.status = 'offline';

    await plugin.interceptedWrite('notes.md', 'version 1');
    await plugin.interceptedWrite('notes.md', 'version 2');
    await plugin.interceptedWrite('notes.md', 'version 3');

    // Should only have 1 entry for notes.md (latest)
    const notesOps = plugin.offlineQueue.filter((op: any) => op.path === 'notes.md');
    expect(notesOps).toHaveLength(1);
    expect(notesOps[0].data).toBe('version 3');
  });
});

describe('File Protection: at-rest media preview (BIN-A / getResourcePath)', () => {
  const PNG = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 1, 2, 3, 4]);
  let plugin: any;
  let runtime: any;
  let createObjectURL: ReturnType<typeof vi.fn>;
  let revokeObjectURL: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    plugin = createTestPlugin();
    plugin.app.vault.configDir = '.obsidian';
    // Media read primitives the default harness omits: readBinary (raw on-disk)
    // and getResourcePath (the sync URL Obsidian's renderer loads).
    const methods = plugin.originalAdapterMethods;
    methods.readBinary = vi.fn(async () => PNG.buffer.slice(0));
    methods.getResourcePath = vi.fn((p: string) => `app://host/${p}?42`);
    runtime = plugin.ensureAtRestAdapterRuntimeObject();
    // The preview path is now session-gated (mirrors interceptedRead's
    // `if (!this.session)`): authenticate so the existing decrypt-and-serve tests
    // exercise the authenticated behavior. Logged-out cases set session = null.
    plugin.session = makeSession();

    createObjectURL = vi.fn(() => 'blob:vg/1');
    revokeObjectURL = vi.fn();
    (globalThis.URL as any).createObjectURL = createObjectURL;
    (globalThis.URL as any).revokeObjectURL = revokeObjectURL;
  });

  afterEach(() => {
    delete (globalThis.URL as any).createObjectURL;
    delete (globalThis.URL as any).revokeObjectURL;
  });

  it('passes text/non-media paths straight through to the original getResourcePath', () => {
    expect(runtime.interceptedGetResourcePath('notes/foo.md')).toBe('app://host/notes/foo.md?42');
    expect(createObjectURL).not.toHaveBeenCalled();
  });

  it('passes through unchanged when the at-rest cipher is not ready', () => {
    plugin.atRestCipher.isReady = vi.fn(() => false);
    expect(runtime.interceptedGetResourcePath('img/pic.png')).toBe('app://host/img/pic.png?42');
    expect(createObjectURL).not.toHaveBeenCalled();
  });

  it('prewarm decrypts a media file into a blob URL that getResourcePath then serves synchronously', async () => {
    await runtime.prewarmResourcePreview('img/pic.png');
    expect(plugin.originalAdapterMethods.readBinary).toHaveBeenCalledWith('img/pic.png');
    expect(createObjectURL).toHaveBeenCalledTimes(1);
    // Now the sync render path gets the decrypted blob URL, not the ciphertext.
    expect(runtime.interceptedGetResourcePath('img/pic.png')).toBe('blob:vg/1');
  });

  it('a cold getResourcePath miss returns the ciphertext URL but warms the cache for next time', async () => {
    // First (cold) call: sync fallback to the real URL, warm fired in the background.
    expect(runtime.interceptedGetResourcePath('img/pic.png')).toBe('app://host/img/pic.png?42');
    await new Promise((r) => setTimeout(r, 0)); // let the fire-and-forget decrypt settle
    expect(createObjectURL).toHaveBeenCalledTimes(1);
    // Warm hit: now the decrypted blob URL is served.
    expect(runtime.interceptedGetResourcePath('img/pic.png')).toBe('blob:vg/1');
  });

  it('revokes every cached blob URL on adapter restore (no leak past unload)', async () => {
    await runtime.prewarmResourcePreview('img/pic.png');
    runtime.revokeAllResourcePreviews();
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:vg/1');
    // Cache cleared → next call is a cold miss again.
    expect(runtime.interceptedGetResourcePath('img/pic.png')).toBe('app://host/img/pic.png?42');
  });

  it('evicts and revokes a file\'s cached blob on delete', async () => {
    await runtime.prewarmResourcePreview('img/pic.png');
    runtime.evictResourcePreview('img/pic.png');
    expect(revokeObjectURL).toHaveBeenCalledWith('blob:vg/1');
    expect(runtime.interceptedGetResourcePath('img/pic.png')).toBe('app://host/img/pic.png?42');
  });

  it('blocks getResourcePath when logged out (returns ciphertext URL, no decrypt)', () => {
    plugin.session = null;
    // The !this.session guard precedes cipher-readiness and the cache lookup, so a
    // logged-out user gets the ciphertext app:// URL — a broken preview matching the
    // "no access" header — even though the local LAK is still ready.
    expect(runtime.interceptedGetResourcePath('img/pic.png')).toBe('app://host/img/pic.png?42');
    expect(createObjectURL).not.toHaveBeenCalled();
  });

  it('prewarm is a no-op when logged out (never reads or decrypts)', async () => {
    plugin.session = null;
    await runtime.prewarmResourcePreview('img/pic.png');
    expect(plugin.originalAdapterMethods.readBinary).not.toHaveBeenCalled();
    expect(createObjectURL).not.toHaveBeenCalled();
  });

  it('does not serve an authenticated-session blob after the session goes null', async () => {
    // Warm the cache while authenticated (session set in beforeEach).
    await runtime.prewarmResourcePreview('img/pic.png');
    expect(runtime.interceptedGetResourcePath('img/pic.png')).toBe('blob:vg/1');
    // Session drops (logout): the guard precedes the cache lookup, so the stale
    // decrypted blob is never served — the ciphertext URL comes back instead.
    plugin.session = null;
    expect(runtime.interceptedGetResourcePath('img/pic.png')).toBe('app://host/img/pic.png?42');
  });
});
