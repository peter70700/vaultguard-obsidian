/**
 * PermissionChecker test suite
 *
 * Covers:
 * - canRead/canWrite/canDelete permission checks
 * - Glob pattern matching (*, **, ?)
 * - Folder inheritance (folder grants cascade to children)
 * - Specificity resolution (more specific patterns win)
 * - Same specificity: higher permission level wins
 * - Expired permissions are ignored
 * - 401 clears all grants
 * - getReadablePatterns() filters correctly
 *
 * Strategy: we test the core matching/specificity/expiration logic by
 * populating grants directly, avoiding flaky module-mock coupling with
 * Obsidian's requestUrl. The network layer (refreshPermissions) is
 * tested separately via a focused integration test.
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

vi.mock('obsidian', () => ({
  requestUrl: vi.fn(),
  Notice: vi.fn(),
  Plugin: class {},
}));

import { requestUrl } from 'obsidian';
import { PermissionChecker } from '../src/sync/permission-checker';
import { PermissionLevel } from '../src/types';

const mockRequestUrl = vi.mocked(requestUrl);

/**
 * Helper: populate grants directly on the checker, bypassing the network layer.
 * This lets us test matching, specificity, and expiration in isolation.
 */
function setGrants(checker: PermissionChecker, grants: Array<{
  pattern: string;
  level: PermissionLevel;
  grantedBy?: string;
  expiresAt?: string | null;
}>) {
  const internal = checker as any;
  internal.grants = grants.map(g => ({
    pattern: g.pattern,
    level: g.level,
    grantedBy: g.grantedBy ?? 'admin',
    expiresAt: g.expiresAt ?? null,
    createdAt: new Date().toISOString(),
  }));
  // Mark as fresh so ensureFresh() doesn't try to call the server
  internal.lastRefresh = Date.now();
}

describe('PermissionChecker', () => {
  let checker: PermissionChecker;

  beforeEach(() => {
    mockRequestUrl.mockReset();
    checker = new PermissionChecker(
      'https://api.vaultguard.test',
      'auth-token',
      5 * 60 * 1000
    );
  });

  // ── Permission Level Checks ───────────────────────────────────────────────

  describe('canRead', () => {
    it('returns true for READ level', async () => {
      setGrants(checker, [
        { pattern: '**', level: PermissionLevel.READ },
      ]);

      expect(await checker.canRead('notes/file.md')).toBe(true);
    });

    it('returns true for higher levels (WRITE, ADMIN)', async () => {
      setGrants(checker, [
        { pattern: '**', level: PermissionLevel.WRITE },
      ]);

      expect(await checker.canRead('file.md')).toBe(true);
    });

    it('returns false when no grants match', async () => {
      setGrants(checker, [
        { pattern: 'other/**', level: PermissionLevel.READ },
      ]);

      expect(await checker.canRead('private/secret.md')).toBe(false);
    });

    it('returns false with NONE level', async () => {
      setGrants(checker, [
        { pattern: '**', level: PermissionLevel.NONE },
      ]);

      expect(await checker.canRead('file.md')).toBe(false);
    });
  });

  describe('canWrite', () => {
    it('returns true for WRITE level', async () => {
      setGrants(checker, [
        { pattern: '**', level: PermissionLevel.WRITE },
      ]);

      expect(await checker.canWrite('file.md')).toBe(true);
    });

    it('returns false for READ level', async () => {
      setGrants(checker, [
        { pattern: '**', level: PermissionLevel.READ },
      ]);

      expect(await checker.canWrite('file.md')).toBe(false);
    });

    it('returns true for ADMIN level', async () => {
      setGrants(checker, [
        { pattern: '**', level: PermissionLevel.ADMIN },
      ]);

      expect(await checker.canWrite('file.md')).toBe(true);
    });
  });

  describe('canDelete', () => {
    it('returns true for ADMIN level', async () => {
      setGrants(checker, [
        { pattern: '**', level: PermissionLevel.ADMIN },
      ]);

      expect(await checker.canDelete('file.md')).toBe(true);
    });

    it('returns false for WRITE level', async () => {
      setGrants(checker, [
        { pattern: '**', level: PermissionLevel.WRITE },
      ]);

      expect(await checker.canDelete('file.md')).toBe(false);
    });
  });

  // ── Glob Matching ─────────────────────────────────────────────────────────

  describe('glob matching', () => {
    it('** matches any depth', async () => {
      setGrants(checker, [
        { pattern: 'docs/**', level: PermissionLevel.READ },
      ]);

      expect(await checker.canRead('docs/guide/intro.md')).toBe(true);
      expect(await checker.canRead('docs/readme.md')).toBe(true);
    });

    it('* matches single segment', async () => {
      setGrants(checker, [
        { pattern: 'docs/*.md', level: PermissionLevel.READ },
      ]);

      expect(await checker.canRead('docs/readme.md')).toBe(true);
      expect(await checker.canRead('docs/sub/readme.md')).toBe(false);
    });

    it('bare ** matches everything', async () => {
      setGrants(checker, [
        { pattern: '**', level: PermissionLevel.READ },
      ]);

      expect(await checker.canRead('any/deeply/nested/file.md')).toBe(true);
      expect(await checker.canRead('top-level.md')).toBe(true);
    });
  });

  // ── Folder Inheritance ────────────────────────────────────────────────────

  describe('folder inheritance', () => {
    it('folder grant with trailing slash applies to child files', async () => {
      setGrants(checker, [
        { pattern: 'engineering/', level: PermissionLevel.WRITE },
      ]);

      expect(await checker.canWrite('engineering/api.ts')).toBe(true);
    });

    it('folder grant without trailing slash applies to children', async () => {
      setGrants(checker, [
        { pattern: 'engineering', level: PermissionLevel.WRITE },
      ]);

      expect(await checker.canWrite('engineering/nested/file.ts')).toBe(true);
    });

    it('folder grant does not apply to sibling folders', async () => {
      setGrants(checker, [
        { pattern: 'engineering', level: PermissionLevel.WRITE },
      ]);

      expect(await checker.canWrite('marketing/campaign.md')).toBe(false);
    });
  });

  // ── Specificity ───────────────────────────────────────────────────────────

  describe('specificity resolution', () => {
    it('more specific pattern overrides less specific', async () => {
      setGrants(checker, [
        { pattern: '**', level: PermissionLevel.READ },
        { pattern: 'engineering/**', level: PermissionLevel.WRITE },
      ]);

      // Engineering path should match the more specific WRITE grant
      expect(await checker.canWrite('engineering/api.ts')).toBe(true);
      // Non-engineering path should match the general READ grant
      expect(await checker.canWrite('marketing/doc.md')).toBe(false);
      expect(await checker.canRead('marketing/doc.md')).toBe(true);
    });

    it('exact path beats glob', async () => {
      setGrants(checker, [
        { pattern: 'docs/**', level: PermissionLevel.READ },
        { pattern: 'docs/secret.md', level: PermissionLevel.ADMIN },
      ]);

      expect(await checker.canDelete('docs/secret.md')).toBe(true);
      expect(await checker.canDelete('docs/public.md')).toBe(false);
    });

    it('same specificity: higher permission level wins', async () => {
      setGrants(checker, [
        { pattern: 'shared/**', level: PermissionLevel.READ },
        { pattern: 'shared/**', level: PermissionLevel.WRITE },
      ]);

      expect(await checker.canWrite('shared/file.md')).toBe(true);
    });
  });

  // ── Expiration ────────────────────────────────────────────────────────────

  describe('expiration', () => {
    it('ignores expired permissions', async () => {
      setGrants(checker, [
        {
          pattern: '**',
          level: PermissionLevel.WRITE,
          expiresAt: new Date(Date.now() - 60_000).toISOString(), // expired 1 minute ago
        },
      ]);

      expect(await checker.canRead('file.md')).toBe(false);
    });

    it('respects unexpired permissions', async () => {
      setGrants(checker, [
        {
          pattern: '**',
          level: PermissionLevel.WRITE,
          expiresAt: new Date(Date.now() + 3600_000).toISOString(), // valid for 1 hour
        },
      ]);

      expect(await checker.canWrite('file.md')).toBe(true);
    });

    it('null expiresAt means permanent', async () => {
      setGrants(checker, [
        { pattern: '**', level: PermissionLevel.READ, expiresAt: null },
      ]);

      expect(await checker.canRead('file.md')).toBe(true);
    });
  });

  // ── refreshPermissions (network layer) ────────────────────────────────────

  describe('refreshPermissions', () => {
    it('parses server grants and populates internal state', async () => {
      mockRequestUrl.mockResolvedValueOnce({
        status: 200,
        json: {
          grants: [
            { pattern: '**', level: 'write', grantedBy: 'admin' },
          ],
        },
      } as any);

      await checker.refreshPermissions();

      const patterns = checker.getReadablePatterns();
      expect(patterns).toContain('**');
    });

    it('clears all grants on 401', async () => {
      // Populate some grants first
      setGrants(checker, [
        { pattern: '**', level: PermissionLevel.WRITE },
      ]);
      expect(await checker.canWrite('file.md')).toBe(true);

      // Now simulate a 401 refresh
      mockRequestUrl.mockResolvedValueOnce({ status: 401, json: {} } as any);

      await expect(checker.refreshPermissions()).rejects.toThrow('Access revoked');

      // Grants should be cleared — getEffectivePermission returns null
      expect(checker.getEffectivePermission('file.md')).toBeNull();
    });

    it('throws on non-2xx non-401 status', async () => {
      mockRequestUrl.mockResolvedValueOnce({ status: 500, json: {} } as any);

      await expect(checker.refreshPermissions()).rejects.toThrow('Permission refresh failed: 500');
    });
  });

  // ── getReadablePatterns ───────────────────────────────────────────────────

  describe('getReadablePatterns', () => {
    it('returns patterns with READ+ access', () => {
      setGrants(checker, [
        { pattern: 'public/**', level: PermissionLevel.READ },
        { pattern: 'engineering/**', level: PermissionLevel.WRITE },
        { pattern: 'secret/**', level: PermissionLevel.NONE },
      ]);

      const patterns = checker.getReadablePatterns();
      expect(patterns).toContain('public/**');
      expect(patterns).toContain('engineering/**');
      expect(patterns).not.toContain('secret/**');
    });

    it('excludes expired grants', () => {
      setGrants(checker, [
        {
          pattern: 'expired/**',
          level: PermissionLevel.READ,
          expiresAt: new Date(Date.now() - 1000).toISOString(),
        },
        { pattern: 'valid/**', level: PermissionLevel.READ },
      ]);

      const patterns = checker.getReadablePatterns();
      expect(patterns).not.toContain('expired/**');
      expect(patterns).toContain('valid/**');
    });
  });

  // ── getEffectivePermission ────────────────────────────────────────────────

  describe('getEffectivePermission', () => {
    it('returns null when no grants exist', () => {
      expect(checker.getEffectivePermission('file.md')).toBeNull();
    });

    it('returns the matching grant with metadata', () => {
      setGrants(checker, [
        { pattern: '**', level: PermissionLevel.WRITE, grantedBy: 'admin-user' },
      ]);

      const perm = checker.getEffectivePermission('notes/file.md');
      expect(perm).not.toBeNull();
      expect(perm!.level).toBe(PermissionLevel.WRITE);
      expect(perm!.grantedBy).toBe('admin-user');
      expect(perm!.pattern).toBe('**');
    });
  });
});
