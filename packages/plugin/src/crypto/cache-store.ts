/**
 * VaultGuard - Encrypted File Cache Store
 *
 * Stores encrypted vault files in `.vaultguard-cache/` with path-hashed filenames.
 * Maintains an encrypted manifest mapping hashes to original paths and metadata.
 */

import { CacheEntry, CacheManifest, EncryptionKey } from '../types';

/** Metadata passed when caching a file. */
interface CacheFileMetadata {
  lastModified?: number;
  size?: number;
  contentHash?: string;
}
import { EncryptionEngine } from './encryption-engine';

const CACHE_DIR = '.vaultguard-cache';
const MANIFEST_FILENAME = '.manifest.enc';

/**
 * Encrypted file cache that stores vault content in a local `.vaultguard-cache/` folder.
 * File names are SHA-256 hashes to prevent path enumeration.
 */
export class CacheStore {
  private encryptionEngine: EncryptionEngine;
  private manifest: CacheManifest;
  private vaultBasePath: string;
  private cachePath: string;
  private adapter: FileAdapter;

  /**
   * @param vaultBasePath - Absolute path to the Obsidian vault root
   * @param encryptionEngine - Encryption engine for encrypt/decrypt operations
   * @param adapter - File adapter for disk operations (Obsidian's vault adapter)
   */
  constructor(vaultBasePath: string, encryptionEngine: EncryptionEngine, adapter?: FileAdapter) {
    this.vaultBasePath = vaultBasePath;
    this.encryptionEngine = encryptionEngine;
    this.cachePath = `${vaultBasePath}/${CACHE_DIR}`;
    this.manifest = { entries: new Map(), lastUpdated: 0 };
    this.adapter = adapter ?? new InMemoryFileAdapter(vaultBasePath);
  }

  /**
   * Initialize the cache store — create cache directory and load manifest.
   *
   * @param key - Encryption key for decrypting the manifest
   */
  async initialize(key: EncryptionKey): Promise<void> {
    await this.ensureCacheDirectory();
    await this.loadManifest(key);
  }

  /**
   * Retrieve decrypted file content from the cache.
   *
   * @param path - Original vault-relative file path
   * @param key - Encryption key for decryption
   * @returns Decrypted file content, or null if not cached
   */
  async get(path: string, key: EncryptionKey): Promise<string | null> {
    const hash = await this.hashPath(path);
    const entry = this.manifest.entries.get(hash);

    if (!entry) {
      return null;
    }

    try {
      const encryptedData = await this.readCacheFile(hash);
      if (!encryptedData) {
        return null;
      }
      return await this.encryptionEngine.decrypt(encryptedData, key);
    } catch (error) {
      console.error(`[VaultGuard] Cache read failed for ${path}:`, error);
      return null;
    }
  }

  /**
   * Store encrypted file content in the cache.
   *
   * @param path - Original vault-relative file path
   * @param content - Plain text file content to encrypt and store
   * @param key - Encryption key for encryption
   * @param metadata - Optional file metadata (mtime, size, content hash)
   */
  async set(
    path: string,
    content: string,
    key: EncryptionKey,
    metadata?: CacheFileMetadata
  ): Promise<void> {
    const hash = await this.hashPath(path);
    const encrypted = await this.encryptionEngine.encrypt(content, key);

    await this.writeCacheFile(hash, encrypted);

    const contentHash = await this.hashContent(content);

    this.manifest.entries.set(hash, {
      pathHash: hash,
      originalPath: path,
      contentHash,
      size: content.length,
      encryptedSize: encrypted.byteLength,
      lastModified: metadata?.lastModified ?? Date.now(),
      cachedAt: Date.now(),
    });
    this.manifest.lastUpdated = Date.now();

    await this.saveManifest(key);
  }

  /**
   * Delete a file from the encrypted cache.
   *
   * @param path - Original vault-relative file path
   * @param key - Encryption key for re-saving the manifest
   */
  async delete(path: string, key: EncryptionKey): Promise<void> {
    const hash = await this.hashPath(path);

    if (this.manifest.entries.has(hash)) {
      await this.deleteCacheFile(hash);
      this.manifest.entries.delete(hash);
      this.manifest.lastUpdated = Date.now();
      await this.saveManifest(key);
    }
  }

  /**
   * Wipe the entire cache — delete all encrypted files and the manifest.
   * Called on access revocation to ensure no readable data remains.
   */
  async wipeAll(): Promise<void> {
    try {
      const adapter = this.getFileAdapter();

      // Delete all cache files
      for (const [hash] of this.manifest.entries) {
        await this.deleteCacheFile(hash);
      }

      // Delete the manifest
      const manifestPath = `${CACHE_DIR}/${MANIFEST_FILENAME}`;
      if (await adapter.exists(manifestPath)) {
        await adapter.remove(manifestPath);
      }

      // Clear in-memory manifest
      this.manifest = { entries: new Map(), lastUpdated: 0 };
    } catch (error) {
      console.error('[VaultGuard] Cache wipe failed:', error);
      // Even if file deletion fails, clear the in-memory manifest
      this.manifest = { entries: new Map(), lastUpdated: 0 };
      throw error;
    }
  }

  /**
   * Wipe cached files whose original path falls within a given scope pattern.
   * Called on scope-specific lease revocation so that only the affected
   * path subtree is removed from the local cache.
   *
   * @param scopePattern - Glob pattern (e.g., '/engineering/**')
   * @param key - Encryption key for re-saving the manifest
   */
  async wipeScope(scopePattern: string, key: EncryptionKey): Promise<void> {
    const toDelete: string[] = [];

    for (const [hash, entry] of this.manifest.entries) {
      if (this.pathMatchesScope(entry.originalPath, scopePattern)) {
        await this.deleteCacheFile(hash);
        toDelete.push(hash);
      }
    }

    for (const hash of toDelete) {
      this.manifest.entries.delete(hash);
    }

    if (toDelete.length > 0) {
      this.manifest.lastUpdated = Date.now();
      await this.saveManifest(key);
    }
  }

  /**
   * Check if a file path falls within a scope pattern.
   * Supports glob patterns: '**' matches any segments, '*' matches one segment.
   */
  private pathMatchesScope(filePath: string, scopePattern: string): boolean {
    const normalizedPath = filePath.replace(/\/+/g, '/').replace(/\/$/, '');
    const normalizedPattern = scopePattern.replace(/\/+/g, '/').replace(/\/$/, '');

    if (normalizedPattern === '/**') return true;
    if (normalizedPath === normalizedPattern) return true;

    const regexStr = normalizedPattern
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*\*/g, '{{GLOBSTAR}}')
      .replace(/\*/g, '[^/]+')
      .replace(/\?/g, '[^/]')
      .replace(/{{GLOBSTAR}}/g, '.*');

    const regex = new RegExp(`^${regexStr}$`);
    if (regex.test(normalizedPath)) return true;

    // Check parent inheritance
    const pathSegments = normalizedPath.split('/');
    for (let i = pathSegments.length - 1; i >= 1; i--) {
      const parentPath = pathSegments.slice(0, i).join('/');
      if (regex.test(parentPath)) return true;
    }

    return false;
  }

  /**
   * Get the decrypted manifest mapping path hashes to file metadata.
   *
   * @returns Copy of the current cache manifest
   */
  getManifest(): CacheManifest {
    return {
      entries: new Map(this.manifest.entries),
      lastUpdated: this.manifest.lastUpdated,
    };
  }

  /**
   * Check if a file exists in the cache.
   *
   * @param path - Original vault-relative file path
   */
  async has(path: string): Promise<boolean> {
    const hash = await this.hashPath(path);
    return this.manifest.entries.has(hash);
  }

  /**
   * Get the content hash for a cached file (for delta sync comparison).
   *
   * @param path - Original vault-relative file path
   * @returns Content hash or null if not cached
   */
  async getContentHash(path: string): Promise<string | null> {
    const hash = await this.hashPath(path);
    const entry = this.manifest.entries.get(hash);
    return entry?.contentHash ?? null;
  }

  /**
   * Invalidate cache entries that have changed on the server.
   *
   * @param changedPaths - Paths whose server content has changed
   * @param key - Encryption key for re-saving the manifest
   */
  async invalidate(changedPaths: string[], key: EncryptionKey): Promise<void> {
    for (const path of changedPaths) {
      const hash = await this.hashPath(path);
      if (this.manifest.entries.has(hash)) {
        await this.deleteCacheFile(hash);
        this.manifest.entries.delete(hash);
      }
    }
    this.manifest.lastUpdated = Date.now();
    await this.saveManifest(key);
  }

  /**
   * Get total cache size in bytes.
   */
  getCacheSize(): number {
    let total = 0;
    for (const [, entry] of this.manifest.entries) {
      total += entry.encryptedSize;
    }
    return total;
  }

  /**
   * SHA-256 hash of a file path for cache file naming.
   * Prevents enumeration of vault file paths from cache directory.
   */
  private async hashPath(path: string): Promise<string> {
    const data = new TextEncoder().encode(path);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return this.bufferToHex(hashBuffer);
  }

  /**
   * SHA-256 hash of file content for delta sync detection.
   */
  private async hashContent(content: string): Promise<string> {
    const data = new TextEncoder().encode(content);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return this.bufferToHex(hashBuffer);
  }

  /**
   * Convert an ArrayBuffer to a hex string.
   */
  private bufferToHex(buffer: ArrayBuffer): string {
    const bytes = new Uint8Array(buffer);
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Read an encrypted cache file by its hash name.
   */
  private async readCacheFile(hash: string): Promise<ArrayBuffer | null> {
    const adapter = this.getFileAdapter();
    const filePath = `${CACHE_DIR}/${hash}.enc`;

    try {
      if (await adapter.exists(filePath)) {
        return await adapter.readBinary(filePath);
      }
      return null;
    } catch {
      return null;
    }
  }

  /**
   * Write an encrypted cache file.
   */
  private async writeCacheFile(hash: string, data: ArrayBuffer): Promise<void> {
    const adapter = this.getFileAdapter();
    const filePath = `${CACHE_DIR}/${hash}.enc`;
    await adapter.writeBinary(filePath, data);
  }

  /**
   * Delete a cache file by its hash name.
   */
  private async deleteCacheFile(hash: string): Promise<void> {
    const adapter = this.getFileAdapter();
    const filePath = `${CACHE_DIR}/${hash}.enc`;

    try {
      if (await adapter.exists(filePath)) {
        await adapter.remove(filePath);
      }
    } catch (error) {
      console.warn(`[VaultGuard] Failed to delete cache file ${hash}:`, error);
    }
  }

  /**
   * Load and decrypt the cache manifest from disk.
   */
  private async loadManifest(key: EncryptionKey): Promise<void> {
    const adapter = this.getFileAdapter();
    const manifestPath = `${CACHE_DIR}/${MANIFEST_FILENAME}`;

    try {
      if (await adapter.exists(manifestPath)) {
        const encryptedManifest = await adapter.readBinary(manifestPath);
        const decrypted = await this.encryptionEngine.decrypt(encryptedManifest, key);
        const parsed = JSON.parse(decrypted);

        this.manifest = {
          entries: new Map(Object.entries(parsed.entries)),
          lastUpdated: parsed.lastUpdated,
        };
      }
    } catch (error) {
      console.warn('[VaultGuard] Failed to load manifest, starting fresh:', error);
      this.manifest = { entries: new Map(), lastUpdated: 0 };
    }
  }

  /**
   * Encrypt and save the cache manifest to disk.
   */
  private async saveManifest(key: EncryptionKey): Promise<void> {
    const adapter = this.getFileAdapter();
    const manifestPath = `${CACHE_DIR}/${MANIFEST_FILENAME}`;

    const serialized = JSON.stringify({
      entries: Object.fromEntries(this.manifest.entries),
      lastUpdated: this.manifest.lastUpdated,
    });

    const encrypted = await this.encryptionEngine.encrypt(serialized, key);
    await adapter.writeBinary(manifestPath, encrypted);
  }

  /**
   * Ensure the cache directory exists.
   */
  private async ensureCacheDirectory(): Promise<void> {
    const adapter = this.getFileAdapter();
    if (!(await adapter.exists(CACHE_DIR))) {
      await adapter.mkdir(CACHE_DIR);
    }
  }

  /**
   * Get the file adapter for disk operations.
   */
  private getFileAdapter(): FileAdapter {
    return this.adapter;
  }
}

/**
 * File adapter interface matching Obsidian's vault adapter API.
 */
export interface FileAdapter {
  exists(path: string): Promise<boolean>;
  readBinary(path: string): Promise<ArrayBuffer>;
  writeBinary(path: string, data: ArrayBuffer): Promise<void>;
  remove(path: string): Promise<void>;
  mkdir(path: string): Promise<void>;
}

/**
 * In-memory file adapter used by tests and non-Obsidian execution.
 */
class InMemoryFileAdapter implements FileAdapter {
  private basePath: string;
  private store = new Map<string, ArrayBuffer>();

  constructor(basePath: string) {
    this.basePath = basePath;
  }

  async exists(path: string): Promise<boolean> {
    return this.store.has(path);
  }

  async readBinary(path: string): Promise<ArrayBuffer> {
    const data = this.store.get(path);
    if (!data) throw new Error(`File not found: ${path}`);
    return data;
  }

  async writeBinary(path: string, data: ArrayBuffer): Promise<void> {
    this.store.set(path, data);
  }

  async remove(path: string): Promise<void> {
    this.store.delete(path);
  }

  async mkdir(_path: string): Promise<void> {
    // Directory structure is implicit in the in-memory adapter.
  }
}
