/**
 * VaultGuard - Client-Side Permission Enforcement
 *
 * Caches and enforces permission grants from the server.
 * Supports folder inheritance and glob pattern matching.
 */

import { requestUrl } from "obsidian";
import { EffectivePermission, PermissionGrant, PermissionLevel } from '../types';

/**
 * Client-side permission checker that caches server-granted permissions
 * and enforces them before any file operation.
 */
export class PermissionChecker {
  private grants: PermissionGrant[] = [];
  private lastRefresh: number = 0;
  private serverBaseUrl: string;
  private authToken: string;
  private refreshIntervalMs: number;

  /**
   * @param serverBaseUrl - Base URL of the VaultGuard server
   * @param authToken - Bearer token for authentication
   * @param refreshIntervalMs - How often to refresh permissions (default: 5 min)
   */
  constructor(
    serverBaseUrl: string,
    authToken: string,
    refreshIntervalMs: number = 5 * 60 * 1000
  ) {
    this.serverBaseUrl = serverBaseUrl;
    this.authToken = authToken;
    this.refreshIntervalMs = refreshIntervalMs;
  }

  /**
   * Check if the user can read a file at the given path.
   *
   * @param path - Vault-relative file path
   * @returns True if read access is granted
   */
  async canRead(path: string): Promise<boolean> {
    await this.ensureFresh();
    const permission = this.getEffectivePermission(path);
    return permission !== null && permission.level >= PermissionLevel.READ;
  }

  /**
   * Check if the user can write to a file at the given path.
   *
   * @param path - Vault-relative file path
   * @returns True if write access is granted
   */
  async canWrite(path: string): Promise<boolean> {
    await this.ensureFresh();
    const permission = this.getEffectivePermission(path);
    return permission !== null && permission.level >= PermissionLevel.WRITE;
  }

  /**
   * Check if the user can delete a file at the given path.
   *
   * @param path - Vault-relative file path
   * @returns True if delete access is granted
   */
  async canDelete(path: string): Promise<boolean> {
    await this.ensureFresh();
    const permission = this.getEffectivePermission(path);
    return permission !== null && permission.level >= PermissionLevel.ADMIN;
  }

  /**
   * Refresh permissions from the server.
   * Fetches the latest permission grants and caches them locally.
   *
   * @throws Error if the server request fails
   */
  async refreshPermissions(): Promise<void> {
    const response = await requestUrl({
      url: `${this.serverBaseUrl}/auth/permissions`,
      method: 'GET',
      headers: {
        Authorization: `Bearer ${this.authToken}`,
      },
      throw: false,
    });

    if (response.status === 401) {
      // Access revoked — clear all permissions
      this.grants = [];
      this.lastRefresh = Date.now();
      throw new Error('Access revoked: permission refresh returned 401');
    }

    if (response.status < 200 || response.status >= 300) {
      throw new Error(`Permission refresh failed: ${response.status}`);
    }

    const data = response.json;
    this.grants = this.parseGrants(data.grants);
    this.lastRefresh = Date.now();
  }

  /**
   * Get the effective permission for a specific path.
   * Resolves inheritance (folder grants apply to child files)
   * and glob pattern matching (wildcards in grant paths).
   *
   * @param path - Vault-relative file path
   * @returns The highest applicable permission, or null if no access
   */
  getEffectivePermission(path: string): EffectivePermission | null {
    const normalizedPath = this.normalizePath(path);
    let bestMatch: EffectivePermission | null = null;
    let bestSpecificity = -Infinity;

    for (const grant of this.grants) {
      if (this.matchesGrant(normalizedPath, grant)) {
        const specificity = this.calculateSpecificity(grant.pattern);

        // More specific grants override less specific ones
        if (specificity > bestSpecificity) {
          bestSpecificity = specificity;
          bestMatch = {
            level: grant.level,
            grantedBy: grant.grantedBy,
            expiresAt: grant.expiresAt,
            pattern: grant.pattern,
          };
        } else if (specificity === bestSpecificity && bestMatch) {
          // Same specificity: take the higher permission level
          if (grant.level > bestMatch.level) {
            bestMatch = {
              level: grant.level,
              grantedBy: grant.grantedBy,
              expiresAt: grant.expiresAt,
              pattern: grant.pattern,
            };
          }
        }
      }
    }

    // Check if the permission has expired
    if (bestMatch?.expiresAt && new Date(bestMatch.expiresAt).getTime() < Date.now()) {
      return null;
    }

    return bestMatch;
  }

  /**
   * Get all paths the user has read access to.
   * Useful for building the file tree UI.
   *
   * @returns Array of grant patterns with read+ access
   */
  getReadablePatterns(): string[] {
    return this.grants
      .filter(g => g.level >= PermissionLevel.READ)
      .filter(g => !g.expiresAt || new Date(g.expiresAt).getTime() > Date.now())
      .map(g => g.pattern);
  }

  /**
   * Check if permissions cache needs refresh and refresh if stale.
   */
  private async ensureFresh(): Promise<void> {
    const elapsed = Date.now() - this.lastRefresh;
    if (elapsed > this.refreshIntervalMs || this.grants.length === 0) {
      try {
        await this.refreshPermissions();
      } catch (error) {
        // If refresh fails and we have cached permissions, continue with stale cache
        if (this.grants.length === 0) {
          throw error;
        }
        console.warn('[VaultGuard] Permission refresh failed, using stale cache:', error);
      }
    }
  }

  /**
   * Check if a path matches a permission grant pattern.
   * Supports:
   * - Exact path match
   * - Folder inheritance (grant on "folder/" applies to "folder/file.md")
   * - Glob patterns (* and ** wildcards)
   */
  private matchesGrant(path: string, grant: PermissionGrant): boolean {
    const pattern = this.normalizePath(grant.pattern);

    // Exact match
    if (path === pattern) {
      return true;
    }

    // Folder inheritance: grant on "folder" or "folder/" applies to children
    if (pattern.endsWith('/') && path.startsWith(pattern)) {
      return true;
    }
    if (!pattern.includes('*') && path.startsWith(pattern + '/')) {
      return true;
    }

    // Glob pattern matching
    if (pattern.includes('*')) {
      return this.matchGlob(path, pattern);
    }

    return false;
  }

  /**
   * Match a path against a glob pattern.
   * Supports:
   * - `*` — matches any characters except `/`
   * - `**` — matches any characters including `/` (recursive)
   * - `?` — matches a single character
   */
  private matchGlob(path: string, pattern: string): boolean {
    // Convert glob to regex
    let regexStr = '^';
    let i = 0;

    while (i < pattern.length) {
      const char = pattern[i];

      if (char === '*') {
        if (pattern[i + 1] === '*') {
          // ** matches anything including path separators
          if (pattern[i + 2] === '/') {
            regexStr += '(?:.+/)?';
            i += 3;
          } else {
            regexStr += '.*';
            i += 2;
          }
        } else {
          // * matches anything except path separator
          regexStr += '[^/]*';
          i++;
        }
      } else if (char === '?') {
        regexStr += '[^/]';
        i++;
      } else if ('.+^${}()|[]\\'.includes(char)) {
        regexStr += '\\' + char;
        i++;
      } else {
        regexStr += char;
        i++;
      }
    }

    regexStr += '$';

    try {
      const regex = new RegExp(regexStr);
      return regex.test(path);
    } catch {
      return false;
    }
  }

  /**
   * Calculate specificity of a permission pattern.
   * More specific patterns (deeper paths, fewer wildcards) win over general ones.
   */
  private calculateSpecificity(pattern: string): number {
    const normalized = this.normalizePath(pattern);
    let score = 0;

    // Deeper paths are more specific
    score += (normalized.match(/\//g) || []).length * 10;

    // Exact paths are more specific than globs
    if (!normalized.includes('*')) {
      score += 100;
    }

    // Single * is more specific than **
    if (normalized.includes('**')) {
      score -= 50;
    }

    // Longer patterns are generally more specific
    score += normalized.length;

    return score;
  }

  /**
   * Normalize a file path (remove leading/trailing slashes, collapse doubles).
   */
  private normalizePath(path: string): string {
    return path
      .replace(/^\/+/, '')
      .replace(/\/+$/, '')
      .replace(/\/\/+/g, '/');
  }

  /**
   * Parse raw grant data from the server into typed PermissionGrant objects.
   */
  private parseGrants(rawGrants: unknown[]): PermissionGrant[] {
    return rawGrants.map((raw) => {
      const g = raw as {
        pattern: string;
        level: string | number;
        grantedBy?: string;
        expiresAt?: string | null;
        createdAt?: string;
      };
      return {
        pattern: g.pattern,
        level: this.parseLevel(g.level),
        grantedBy: g.grantedBy ?? 'server',
        expiresAt: g.expiresAt ?? null,
        createdAt: g.createdAt ?? new Date().toISOString(),
      };
    });
  }

  /**
   * Parse a permission level string or number into the PermissionLevel enum.
   */
  private parseLevel(level: string | number): PermissionLevel {
    if (typeof level === 'number') return level;

    switch (level.toLowerCase()) {
      case 'read': return PermissionLevel.READ;
      case 'write': return PermissionLevel.WRITE;
      case 'delete': return PermissionLevel.ADMIN;
      case 'admin': return PermissionLevel.ADMIN;
      default: return PermissionLevel.NONE;
    }
  }
}
