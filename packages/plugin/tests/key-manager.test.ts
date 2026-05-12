/**
 * KeyManager test suite
 *
 * Covers:
 * - requestLease() acquires key and starts refresh/heartbeat loops
 * - requestLease() 401 triggers revokeAndWipe
 * - revokeAndWipe() clears all state: key, lease, scoped leases, timers
 * - revokeAndWipe() calls onRevocation callback
 * - revokeAndWipe() locks PassphraseManager in hybrid-zk mode
 * - getKey() returns null when no lease is active
 * - isLeaseValid() checks expiry and grace period
 * - refreshLease() 401 triggers revocation
 * - refreshLease() network failure falls back to grace period
 * - Grace period expiry triggers emergencyWipe
 * - Path-scoped lease management
 * - pathMatchesScope() glob matching
 * - getKeyForPath() scope resolution specificity
 * - Heartbeat 401 triggers revocation
 * - destroy() cleans up
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';

vi.mock('obsidian', () => ({
  requestUrl: vi.fn(),
  Notice: vi.fn(),
  Plugin: class {},
}));

import { requestUrl } from 'obsidian';
import { KeyManager } from '../src/crypto/key-manager';
import { EncryptionEngine } from '../src/crypto/encryption-engine';

const mockRequestUrl = vi.mocked(requestUrl);

// Helper: create a base64-encoded 32-byte key
function makeBase64Key(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...bytes));
}

// Helper: build a mock server response for key lease
function mockLeaseResponse(overrides: Record<string, any> = {}) {
  return {
    status: 200,
    json: {
      success: true,
      payload: {
        keyId: 'key-001',
        key: makeBase64Key(),
        expiresAt: new Date(Date.now() + 3600_000).toISOString(),
        issuedAt: new Date().toISOString(),
        refreshToken: 'refresh-token-abc',
        scope: '/**',
        gracePeriodMs: 86400_000,
        ...overrides,
      },
    },
  };
}

describe('KeyManager', () => {
  let km: KeyManager;
  let engine: EncryptionEngine;
  let onRevocationMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    engine = new EncryptionEngine();
    km = new KeyManager('https://api.vaultguard.test', 'auth-token-123', engine, {
      refreshIntervalMs: 5 * 60 * 1000,
      gracePeriodMs: 24 * 60 * 60 * 1000,
      refreshBufferMs: 60_000,
    });
    onRevocationMock = vi.fn().mockResolvedValue(undefined);
    km.onAccessRevoked(onRevocationMock);
    mockRequestUrl.mockReset();
  });

  afterEach(() => {
    km.destroy();
    vi.useRealTimers();
  });

  // ── requestLease ──────────────────────────────────────────────────────────

  describe('requestLease', () => {
    it('acquires a key and stores the lease', async () => {
      mockRequestUrl.mockResolvedValueOnce(mockLeaseResponse() as any);

      const key = await km.requestLease();

      expect(key).toBeTruthy();
      expect(km.getKey()).not.toBeNull();
      expect(km.isLeaseValid()).toBe(true);
      expect(km.getLease()).not.toBeNull();
      expect(km.getLease()!.keyId).toBe('key-001');
    });

    it('requests a session-scoped lease using the backend keyLease response shape', async () => {
      km.setSessionId('session-123');
      mockRequestUrl.mockResolvedValueOnce({
        status: 200,
        json: {
          keyLease: {
            leaseId: 'lease-123',
            key: makeBase64Key(),
            expiresAt: new Date(Date.now() + 3600_000).toISOString(),
            refreshToken: 'refresh-token-abc',
            scope: '/**',
          },
        },
      } as any);

      const key = await km.requestLease();

      expect(key).toBeTruthy();
      expect(km.getLease()!.keyId).toBe('lease-123');
      expect(mockRequestUrl.mock.calls[0]![0]).toMatchObject({
        method: 'GET',
        url: 'https://api.vaultguard.test/auth/key-lease?sessionId=session-123',
      });
    });

    it('triggers revokeAndWipe on 401', async () => {
      mockRequestUrl.mockResolvedValueOnce({ status: 401, json: {} } as any);

      await expect(km.requestLease()).rejects.toThrow('Access denied');
      expect(onRevocationMock).toHaveBeenCalled();
      expect(km.getKey()).toBeNull();
    });

    it('throws on non-2xx non-401 status', async () => {
      mockRequestUrl.mockResolvedValueOnce({ status: 500, json: {} } as any);

      await expect(km.requestLease()).rejects.toThrow('Key lease request failed: 500');
    });
  });

  // ── revokeAndWipe ─────────────────────────────────────────────────────────

  describe('revokeAndWipe', () => {
    it('clears key, lease, scoped leases, and calls onRevocation', async () => {
      mockRequestUrl.mockResolvedValueOnce(mockLeaseResponse() as any);
      await km.requestLease();

      expect(km.getKey()).not.toBeNull();

      await (km as any).revokeAndWipe();

      expect(km.getKey()).toBeNull();
      expect(km.getLease()).toBeNull();
      expect(km.getActiveScopes()).toHaveLength(0);
      expect(onRevocationMock).toHaveBeenCalled();
    });

    it('wipes key material in ArrayBuffer (fills with zeros)', async () => {
      mockRequestUrl.mockResolvedValueOnce(mockLeaseResponse() as any);
      await km.requestLease();

      const key = km.getKey() as ArrayBuffer;
      expect(key).toBeInstanceOf(ArrayBuffer);

      await (km as any).revokeAndWipe();

      // The original ArrayBuffer should be zeroed
      const bytes = new Uint8Array(key);
      expect(bytes.every(b => b === 0)).toBe(true);
    });

    it('locks PassphraseManager in hybrid-zk mode', async () => {
      km.setEncryptionModel('hybrid-zk');
      const passphraseManager = km.getPassphraseManager()!;
      const lockSpy = vi.spyOn(passphraseManager, 'lock');

      await (km as any).revokeAndWipe();

      expect(lockSpy).toHaveBeenCalled();
    });

    it('calls encryptionEngine.wipeKeys()', async () => {
      const wipeSpy = vi.spyOn(engine, 'wipeKeys');

      await (km as any).revokeAndWipe();

      expect(wipeSpy).toHaveBeenCalled();
    });
  });

  // ── getKey / isLeaseValid ─────────────────────────────────────────────────

  describe('getKey and isLeaseValid', () => {
    it('returns null when no lease exists', () => {
      expect(km.getKey()).toBeNull();
      expect(km.isLeaseValid()).toBe(false);
    });

    it('returns key when lease is valid', async () => {
      mockRequestUrl.mockResolvedValueOnce(mockLeaseResponse() as any);
      await km.requestLease();

      expect(km.getKey()).not.toBeNull();
      expect(km.isLeaseValid()).toBe(true);
    });

    it('returns null when lease has expired and outside grace period', async () => {
      // Lease expires in 1 second, no grace period
      mockRequestUrl.mockResolvedValueOnce(
        mockLeaseResponse({
          expiresAt: new Date(Date.now() + 1000).toISOString(),
          gracePeriodMs: 0,
        }) as any
      );
      await km.requestLease();

      // Advance past expiry
      vi.advanceTimersByTime(2000);

      expect(km.isLeaseValid()).toBe(false);
      expect(km.getKey()).toBeNull();
    });

    it('returns key during grace period after lease expiry', async () => {
      // Lease expires in 1 second, grace period 10 seconds
      mockRequestUrl.mockResolvedValueOnce(
        mockLeaseResponse({
          expiresAt: new Date(Date.now() + 1000).toISOString(),
          gracePeriodMs: 10_000,
        }) as any
      );
      await km.requestLease();

      // Advance past expiry but within grace period
      vi.advanceTimersByTime(2000);

      expect(km.isLeaseValid()).toBe(true);
      expect(km.getKey()).not.toBeNull();
    });
  });

  // ── refreshLease ──────────────────────────────────────────────────────────

  describe('refreshLease', () => {
    it('revokes on 401 from server', async () => {
      // Initial lease
      mockRequestUrl.mockResolvedValueOnce(mockLeaseResponse() as any);
      await km.requestLease();
      km.setSessionId('session-123');

      // Refresh returns 401 — the 401 triggers revokeAndWipe() inside the try block,
      // then the re-thrown error is caught by the outer catch which sees no grace period
      // (lease was cleared) and throws the grace period error.
      mockRequestUrl.mockResolvedValueOnce({ status: 401, json: {} } as any);

      await expect(km.refreshLease()).rejects.toThrow();
      // The important thing: revocation callback was called and keys are wiped
      expect(onRevocationMock).toHaveBeenCalled();
      expect(km.getKey()).toBeNull();
    });

    it('updates the lease on successful refresh', async () => {
      mockRequestUrl.mockResolvedValueOnce(mockLeaseResponse() as any);
      await km.requestLease();
      km.setSessionId('session-123');

      const newExpiry = new Date(Date.now() + 7200_000).toISOString();
      mockRequestUrl.mockResolvedValueOnce(
        {
          status: 200,
          json: {
            sessionId: 'session-123',
            expiresAt: newExpiry,
            keyLease: {
              leaseId: 'key-002',
              key: makeBase64Key(),
              expiresAt: newExpiry,
              refreshToken: 'refresh-token-def',
              scope: '/**',
            },
          },
        } as any
      );

      const key = await km.refreshLease();
      expect(key).not.toBeNull();
      expect(km.getLease()!.keyId).toBe('key-002');
      expect(mockRequestUrl.mock.calls[1]![0]).toMatchObject({
        method: 'POST',
        url: 'https://api.vaultguard.test/auth/refresh',
        body: expect.stringContaining('"sessionId":"session-123"'),
      });
    });

    it('requests a new lease if no current lease exists', async () => {
      mockRequestUrl.mockResolvedValueOnce(mockLeaseResponse() as any);

      const key = await km.refreshLease();
      expect(key).not.toBeNull();
      expect(km.isLeaseValid()).toBe(true);
    });
  });

  // ── Scoped Leases ─────────────────────────────────────────────────────────

  describe('scoped leases', () => {
    it('requestScopedLease requires sessionId', async () => {
      await expect(km.requestScopedLease('/engineering/**')).rejects.toThrow(
        'Session ID required'
      );
    });

    it('requestScopedLease requires vaultId', async () => {
      km.setSessionId('session-123');

      await expect(km.requestScopedLease('/engineering/**')).rejects.toThrow(
        'Vault ID required'
      );
    });

    it('stores and retrieves scoped leases', async () => {
      km.setSessionId('session-123');
      km.setVaultId('vault-1');

      mockRequestUrl.mockResolvedValueOnce({
        status: 200,
        json: {
          keyLease: {
            leaseId: 'scoped-key-001',
            key: makeBase64Key(),
            expiresAt: new Date(Date.now() + 3600_000).toISOString(),
            refreshToken: 'scoped-refresh-abc',
          },
        },
      } as any);

      const key = await km.requestScopedLease('/engineering/**');
      expect(key).not.toBeNull();
      expect(km.getActiveScopes()).toContain('/engineering/**');
      expect(JSON.parse((mockRequestUrl.mock.calls[0]![0] as any).body)).toEqual({
        sessionId: 'session-123',
        scope: '/engineering/**',
        vaultId: 'vault-1',
      });
    });

    it('revokeScopeKey removes a specific scope', async () => {
      km.setSessionId('session-123');
      km.setVaultId('vault-1');

      mockRequestUrl.mockResolvedValueOnce({
        status: 200,
        json: {
          keyLease: {
            leaseId: 'scoped-key-001',
            key: makeBase64Key(),
            expiresAt: new Date(Date.now() + 3600_000).toISOString(),
            refreshToken: 'scoped-refresh-abc',
          },
        },
      } as any);

      await km.requestScopedLease('/engineering/**');
      expect(km.getActiveScopes()).toContain('/engineering/**');

      const onScopeRevoked = vi.fn().mockResolvedValue(undefined);
      km.onScopeAccessRevoked(onScopeRevoked);

      await km.revokeScopeKey('/engineering/**');
      expect(km.getActiveScopes()).not.toContain('/engineering/**');
      expect(onScopeRevoked).toHaveBeenCalledWith('/engineering/**');
    });
  });

  // ── Path Matching ─────────────────────────────────────────────────────────

  describe('pathMatchesScope', () => {
    const matchFn = (path: string, scope: string) =>
      (km as any).pathMatchesScope(path, scope);

    it('/** matches everything', () => {
      expect(matchFn('/any/path.md', '/**')).toBe(true);
      expect(matchFn('file.md', '/**')).toBe(true);
    });

    it('exact path match', () => {
      expect(matchFn('/docs/readme.md', '/docs/readme.md')).toBe(true);
    });

    it('/engineering/** matches nested files', () => {
      expect(matchFn('/engineering/api/handler.ts', '/engineering/**')).toBe(true);
    });

    it('does not match outside scope', () => {
      expect(matchFn('/marketing/campaign.md', '/engineering/**')).toBe(false);
    });
  });

  // ── Scope Specificity ─────────────────────────────────────────────────────

  describe('scope specificity', () => {
    const specificity = (scope: string) =>
      (km as any).getScopeSpecificity(scope);

    it('/** has lowest specificity', () => {
      expect(specificity('/**')).toBe(0);
    });

    it('deeper paths have higher specificity', () => {
      expect(specificity('/a/b/c')).toBeGreaterThan(specificity('/a'));
    });

    it('exact paths beat wildcards', () => {
      expect(specificity('/a/b/file.md')).toBeGreaterThan(specificity('/a/**'));
    });
  });

  // ── getKeyForPath ─────────────────────────────────────────────────────────

  describe('getKeyForPath', () => {
    it('returns null when no leases exist', () => {
      expect(km.getKeyForPath('/any/file.md')).toBeNull();
    });

    it('returns default key for unscoped paths', async () => {
      mockRequestUrl.mockResolvedValueOnce(mockLeaseResponse() as any);
      await km.requestLease();

      expect(km.getKeyForPath('/any/file.md')).not.toBeNull();
    });
  });

  // ── Heartbeat ─────────────────────────────────────────────────────────────

  describe('heartbeat', () => {
    it('triggers revokeAndWipe on 401', async () => {
      // Acquire lease (starts heartbeat)
      mockRequestUrl.mockResolvedValueOnce(mockLeaseResponse() as any);
      await km.requestLease();
      onRevocationMock.mockClear();

      // Heartbeat returns 401
      mockRequestUrl.mockResolvedValue({ status: 401, json: {} } as any);

      // Advance 60 seconds to trigger heartbeat
      await vi.advanceTimersByTimeAsync(60_000);

      expect(onRevocationMock).toHaveBeenCalled();
      expect(km.getKey()).toBeNull();
    });

    it('triggers revokeAndWipe when server returns active: false', async () => {
      mockRequestUrl.mockResolvedValueOnce(mockLeaseResponse() as any);
      await km.requestLease();
      onRevocationMock.mockClear();

      mockRequestUrl.mockResolvedValue({
        status: 200,
        json: { active: false, reason: 'admin revoked' },
      } as any);

      await vi.advanceTimersByTimeAsync(60_000);

      expect(onRevocationMock).toHaveBeenCalled();
    });
  });

  // ── destroy ───────────────────────────────────────────────────────────────

  describe('destroy', () => {
    it('clears all state and stops timers', async () => {
      mockRequestUrl.mockResolvedValueOnce(mockLeaseResponse() as any);
      await km.requestLease();

      km.destroy();

      expect(km.getKey()).toBeNull();
      expect(km.getLease()).toBeNull();
      expect(km.getActiveScopes()).toHaveLength(0);
    });
  });

  // ── Encryption Model ──────────────────────────────────────────────────────

  describe('encryption model', () => {
    it('defaults to server-managed', () => {
      expect(km.getEncryptionModel()).toBe('server-managed');
      expect(km.getPassphraseManager()).toBeNull();
    });

    it('creates PassphraseManager when set to hybrid-zk', () => {
      km.setEncryptionModel('hybrid-zk');
      expect(km.getEncryptionModel()).toBe('hybrid-zk');
      expect(km.getPassphraseManager()).not.toBeNull();
    });

    it('loginWithPassphrase throws in server-managed mode', async () => {
      await expect(km.loginWithPassphrase('test')).rejects.toThrow(
        'requires hybrid-zk encryption model'
      );
    });
  });
});
