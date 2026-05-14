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
 * - interceptedList: filters out inaccessible files/folders
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

  // Mock original adapter methods (the real filesystem operations)
  plugin.originalAdapterMethods = {
    read: vi.fn().mockResolvedValue('local file content'),
    write: vi.fn().mockResolvedValue(undefined),
    list: vi.fn().mockResolvedValue({
      files: ['public/doc.md', 'private/secret.md', 'shared/notes.md'],
      folders: ['public', 'private', 'shared'],
    }),
    remove: vi.fn().mockResolvedValue(undefined),
  };

  // Default: no session, no cache
  plugin.permissionCache = new Map();
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
    showPermissionIndicators: true,
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

    it('fails closed and wipes local cache when effective permission is NONE', async () => {
      plugin.session = makeSession('member');
      plugin.permissionCache.set('secret/classified.md', PermissionLevel.NONE);

      await expect(plugin.interceptedRead('secret/classified.md'))
        .rejects.toThrow('Local cached content for "secret/classified.md" was wiped');

      expect(plugin.originalAdapterMethods.read).not.toHaveBeenCalled();
      expect(plugin.originalAdapterMethods.write).toHaveBeenCalledWith('secret/classified.md', '');
      expect(mockNotice).toHaveBeenCalledWith(
        expect.stringContaining('secret/classified.md'),
        expect.any(Number)
      );
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

    it('emits a denied audit event when permission is missing before wiping local cache', async () => {
      plugin.session = makeSession('member');
      plugin.permissionCache.set('secret.md', PermissionLevel.NONE);
      const auditSpy = vi.spyOn(plugin, 'emitAuditEvent').mockResolvedValue(undefined);

      await expect(plugin.interceptedRead('secret.md')).rejects.toThrow('Access denied');

      expect(auditSpy).toHaveBeenCalledWith(
        'file.read',
        'secret.md',
        expect.objectContaining({ outcome: 'denied' })
      );
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

      expect(plugin.originalAdapterMethods.write).toHaveBeenCalledWith(
        'docs/editable.md', 'updated content'
      );
    });

    it('allows write when permission is ADMIN', async () => {
      plugin.session = makeSession('admin');
      plugin.permissionCache.set('docs/file.md', PermissionLevel.ADMIN);
      plugin.connectionState.status = 'offline';

      await plugin.interceptedWrite('docs/file.md', 'admin edit');

      expect(plugin.originalAdapterMethods.write).toHaveBeenCalledWith(
        'docs/file.md', 'admin edit'
      );
    });

    it('queues offline operation when offline', async () => {
      plugin.session = makeSession('editor');
      plugin.permissionCache.set('notes.md', PermissionLevel.WRITE);
      plugin.connectionState.status = 'offline';

      await plugin.interceptedWrite('notes.md', 'offline edit');

      expect(plugin.offlineQueue.length).toBe(1);
      expect(plugin.offlineQueue[0].operation).toBe('write');
      expect(plugin.offlineQueue[0].path).toBe('notes.md');
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
    it('filters out files without READ permission', async () => {
      plugin.session = makeSession('member');
      plugin.permissionCache.set('public/doc.md', PermissionLevel.READ);
      plugin.permissionCache.set('private/secret.md', PermissionLevel.NONE);
      plugin.permissionCache.set('shared/notes.md', PermissionLevel.WRITE);
      plugin.permissionCache.set('public', PermissionLevel.READ);
      plugin.permissionCache.set('private', PermissionLevel.NONE);
      plugin.permissionCache.set('shared', PermissionLevel.WRITE);

      const listing = await plugin.interceptedList('');

      expect(listing.files).toContain('public/doc.md');
      expect(listing.files).toContain('shared/notes.md');
      expect(listing.files).not.toContain('private/secret.md');
    });

    it('filters out folders without READ permission', async () => {
      plugin.session = makeSession('member');
      plugin.permissionCache.set('public/doc.md', PermissionLevel.READ);
      plugin.permissionCache.set('private/secret.md', PermissionLevel.NONE);
      plugin.permissionCache.set('shared/notes.md', PermissionLevel.WRITE);
      plugin.permissionCache.set('public', PermissionLevel.READ);
      plugin.permissionCache.set('private', PermissionLevel.NONE);
      plugin.permissionCache.set('shared', PermissionLevel.WRITE);

      const listing = await plugin.interceptedList('');

      expect(listing.folders).toContain('public');
      expect(listing.folders).toContain('shared');
      expect(listing.folders).not.toContain('private');
    });

    it('returns an empty listing when no session (pre-auth fail closed)', async () => {
      plugin.session = null;

      const listing = await plugin.interceptedList('');

      expect(listing.files).toHaveLength(0);
      expect(listing.folders).toHaveLength(0);
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

    // Can write
    await plugin.interceptedWrite('project/design.md', 'design update');
    expect(plugin.originalAdapterMethods.write).toHaveBeenCalled();

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
    expect(plugin.originalAdapterMethods.write).toHaveBeenCalledTimes(1);
    expect(plugin.originalAdapterMethods.remove).toHaveBeenCalledTimes(1);
  });

  it('permission changes are enforced immediately from cache', async () => {
    plugin.session = makeSession('member');
    plugin.connectionState.status = 'offline';

    // Initially has WRITE
    plugin.permissionCache.set('file.md', PermissionLevel.WRITE);
    await plugin.interceptedWrite('file.md', 'allowed');
    expect(plugin.originalAdapterMethods.write).toHaveBeenCalledTimes(1);

    // Permission downgraded to READ
    plugin.permissionCache.set('file.md', PermissionLevel.READ);
    await expect(plugin.interceptedWrite('file.md', 'blocked'))
      .rejects.toThrow('Access denied');
    expect(plugin.originalAdapterMethods.write).toHaveBeenCalledTimes(1); // not called again
  });

  it('revoked access (NONE) blocks reads, writes, and deletes while wiping local read cache', async () => {
    plugin.session = makeSession('member');
    plugin.permissionCache.set('revoked.md', PermissionLevel.NONE);

    await expect(plugin.interceptedRead('revoked.md')).rejects.toThrow('Access denied');
    await expect(plugin.interceptedWrite('revoked.md', 'data')).rejects.toThrow('Access denied');
    await expect(plugin.interceptedDelete('revoked.md')).rejects.toThrow('Access denied');

    expect(plugin.originalAdapterMethods.read).not.toHaveBeenCalled();
    expect(plugin.originalAdapterMethods.write).toHaveBeenCalledWith('revoked.md', '');
    expect(plugin.originalAdapterMethods.remove).not.toHaveBeenCalled();
  });

  it('hidden files are excluded from directory listing', async () => {
    plugin.session = makeSession('member');
    plugin.permissionCache.set('public/doc.md', PermissionLevel.READ);
    plugin.permissionCache.set('private/secret.md', PermissionLevel.NONE);
    plugin.permissionCache.set('shared/notes.md', PermissionLevel.WRITE);
    plugin.permissionCache.set('public', PermissionLevel.READ);
    plugin.permissionCache.set('private', PermissionLevel.NONE);
    plugin.permissionCache.set('shared', PermissionLevel.WRITE);

    const listing = await plugin.interceptedList('');

    // private/secret.md and private/ should be hidden
    expect(listing.files).toEqual(['public/doc.md', 'shared/notes.md']);
    expect(listing.folders).toEqual(['public', 'shared']);
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
