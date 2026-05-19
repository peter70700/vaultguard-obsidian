/**
 * VaultGuard - Permission-Aware Sync Engine
 *
 * Handles periodic synchronization with the VaultGuard server, including
 * delta sync, offline change queuing, and conflict detection.
 */

import { requestUrl } from "obsidian";
import {
  SyncEngineState,
  SyncEngineStatus,
  SyncEvent,
  SyncEventType,
  SyncConfig,
  FileChange,
  ConflictInfo,
  EncryptionKey,
  ServerFileEntry,
} from '../types';
import { CacheStore } from '../crypto/cache-store';
import { KeyManager } from '../crypto/key-manager';
import { PermissionChecker } from './permission-checker';
import { ConflictResolver, ResolutionStrategy } from './conflict-resolver';

/** Default sync configuration */
const DEFAULT_SYNC_INTERVAL_MS = 30 * 1000; // 30 seconds
const DEFAULT_BATCH_SIZE = 50;

/**
 * Permission-aware sync engine that manages bidirectional file synchronization
 * between the local encrypted cache and the VaultGuard server.
 */
export class SyncEngine {
  private state: SyncEngineState = SyncEngineState.IDLE;
  private syncTimer: ReturnType<typeof setInterval> | null = null;
  private offlineQueue: FileChange[] = [];
  private listeners: Map<SyncEventType, Set<(event: SyncEvent) => void>> = new Map();
  private lastSyncTimestamp: number = 0;
  private config: Required<SyncConfig>;
  private serverBaseUrl: string;
  private authToken: string;

  private cacheStore: CacheStore;
  private keyManager: KeyManager;
  private permissionChecker: PermissionChecker;
  private conflictResolver: ConflictResolver;

  /**
   * @param serverBaseUrl - Base URL of the VaultGuard sync server
   * @param authToken - Bearer token for server authentication
   * @param cacheStore - Encrypted cache store for file content
   * @param keyManager - Key manager for accessing encryption keys
   * @param permissionChecker - Permission checker for access control
   * @param conflictResolver - Conflict resolver for handling sync conflicts
   * @param config - Optional sync configuration overrides
   */
  constructor(
    serverBaseUrl: string,
    authToken: string,
    cacheStore: CacheStore,
    keyManager: KeyManager,
    permissionChecker: PermissionChecker,
    conflictResolver: ConflictResolver,
    config?: SyncConfig
  ) {
    this.serverBaseUrl = serverBaseUrl;
    this.authToken = authToken;
    this.cacheStore = cacheStore;
    this.keyManager = keyManager;
    this.permissionChecker = permissionChecker;
    this.conflictResolver = conflictResolver;
    this.config = {
      intervalMs: config?.intervalMs ?? DEFAULT_SYNC_INTERVAL_MS,
      batchSize: config?.batchSize ?? DEFAULT_BATCH_SIZE,
      autoResolveStrategy: config?.autoResolveStrategy ?? ResolutionStrategy.SERVER_WINS,
    };
  }

  /**
   * Start the periodic sync loop.
   */
  start(): void {
    if (this.syncTimer) return;

    this.syncTimer = setInterval(async () => {
      if (this.state === SyncEngineState.IDLE) {
        await this.sync();
      }
    }, this.config.intervalMs);

    // Perform an immediate initial sync
    this.sync();
  }

  /**
   * Stop the periodic sync loop.
   */
  stop(): void {
    if (this.syncTimer) {
      clearInterval(this.syncTimer);
      this.syncTimer = null;
    }
  }

  /**
   * Perform a full bidirectional sync cycle.
   * Pulls server changes, pushes local changes, and resolves conflicts.
   *
   * @returns Sync status summary
   */
  async sync(): Promise<SyncEngineStatus> {
    if (this.state === SyncEngineState.REVOKED) {
      throw new Error('Cannot sync: access has been revoked');
    }

    const key = this.keyManager.getKey();
    if (!key) {
      this.setState(SyncEngineState.OFFLINE);
      console.log("[VaultGuard] Sync skipped: no key lease (sync() early return — keyManager.getKey() returned null)");
      return this.buildStatus('No valid encryption key available');
    }

    this.setState(SyncEngineState.SYNCING);
    this.emit({ type: SyncEventType.SYNC_STARTED, timestamp: Date.now() });

    try {
      // Pull remote changes first
      const pullResult = await this.pullChanges(key);

      // Push local changes (queued offline changes + new local modifications)
      const pushResult = await this.pushChanges(key);

      // Handle any conflicts detected during pull/push
      if (pullResult.conflicts.length > 0) {
        this.setState(SyncEngineState.CONFLICT);
        await this.handleConflicts(pullResult.conflicts, key);
      }

      this.lastSyncTimestamp = Date.now();
      this.setState(SyncEngineState.IDLE);

      const status = this.buildStatus(null, {
        pulled: pullResult.pulled,
        pushed: pushResult.pushed,
        conflicts: pullResult.conflicts.length,
      });

      this.emit({
        type: SyncEventType.SYNC_COMPLETED,
        timestamp: Date.now(),
        data: status,
      });

      return status;
    } catch (error) {
      if (this.isNetworkError(error)) {
        this.setState(SyncEngineState.OFFLINE);
        this.emit({
          type: SyncEventType.SYNC_OFFLINE,
          timestamp: Date.now(),
          data: { reason: (error as Error).message },
        });
      } else if (this.isAuthError(error)) {
        this.setState(SyncEngineState.REVOKED);
        this.emit({
          type: SyncEventType.ACCESS_REVOKED,
          timestamp: Date.now(),
        });
      } else {
        this.setState(SyncEngineState.IDLE);
      }

      return this.buildStatus((error as Error).message);
    }
  }

  /**
   * Push local changes to the server.
   * Replays offline queue first, then pushes new local modifications.
   *
   * @param key - Encryption key for decrypting local cache before upload
   * @returns Summary of pushed changes
   */
  async pushChanges(key?: EncryptionKey): Promise<{ pushed: number; failed: string[] }> {
    const encKey = key ?? this.keyManager.getKey();
    if (!encKey) {
      throw new Error('No valid key for push operation');
    }

    const failed: string[] = [];
    let pushed = 0;

    // Replay offline queue
    const queue = [...this.offlineQueue];
    this.offlineQueue = [];

    for (const change of queue) {
      try {
        if (!(await this.permissionChecker.canWrite(change.path))) {
          failed.push(change.path);
          continue;
        }

        await this.uploadFile(change, encKey);
        pushed++;
      } catch (error) {
        // Re-queue on network failure
        if (this.isNetworkError(error)) {
          this.offlineQueue.push(change);
        } else {
          failed.push(change.path);
        }
      }
    }

    this.emit({
      type: SyncEventType.PUSH_COMPLETED,
      timestamp: Date.now(),
      data: { pushed, failed },
    });

    return { pushed, failed };
  }

  /**
   * Pull remote changes from the server.
   * Only downloads files that have changed since the last sync (delta sync).
   *
   * @param key - Encryption key for encrypting pulled content into local cache
   * @returns Summary of pulled changes and detected conflicts
   */
  async pullChanges(key?: EncryptionKey): Promise<{ pulled: number; conflicts: ConflictInfo[] }> {
    const encKey = key ?? this.keyManager.getKey();
    if (!encKey) {
      throw new Error('No valid key for pull operation');
    }

    const conflicts: ConflictInfo[] = [];
    let pulled = 0;

    // Get permission-filtered file listing with content hashes
    const serverFiles = await this.fetchServerFileList();

    for (const serverFile of serverFiles) {
      if (!(await this.permissionChecker.canRead(serverFile.path))) {
        continue;
      }

      const localHash = await this.cacheStore.getContentHash(serverFile.path);

      // Skip unchanged files (delta sync)
      if (localHash === serverFile.contentHash) {
        continue;
      }

      // Check for conflict: local has changes AND server has changes
      if (localHash && localHash !== serverFile.contentHash) {
        const localChange = this.offlineQueue.find(c => c.path === serverFile.path);
        if (localChange) {
          conflicts.push({
            path: serverFile.path,
            localHash,
            serverHash: serverFile.contentHash,
            localModified: localChange.timestamp,
            serverModified: serverFile.lastModified,
          });
          continue;
        }
      }

      // Download and cache the file
      try {
        const content = await this.downloadFile(serverFile.path);
        await this.cacheStore.set(serverFile.path, content, encKey, {
          lastModified: serverFile.lastModified,
        });
        pulled++;
      } catch (error) {
        console.error(`[VaultGuard] Failed to pull ${serverFile.path}:`, error);
      }
    }

    this.emit({
      type: SyncEventType.PULL_COMPLETED,
      timestamp: Date.now(),
      data: { pulled, conflicts: conflicts.length },
    });

    return { pulled, conflicts };
  }

  /**
   * Resolve a sync conflict for a specific file.
   *
   * @param path - File path with the conflict
   * @param strategy - Resolution strategy to apply
   * @param mergedContent - Optional manually merged content (for MANUAL strategy)
   */
  async resolveConflict(
    path: string,
    strategy: ResolutionStrategy,
    mergedContent?: string
  ): Promise<void> {
    const key = this.keyManager.getKey();
    if (!key) {
      console.log("[VaultGuard] Sync skipped: no key lease (handleConflicts() — keyManager.getKey() returned null)");
      throw new Error('No valid key for conflict resolution');
    }

    const resolution = await this.conflictResolver.resolve(
      path,
      strategy,
      mergedContent
    );

    if (resolution.content) {
      await this.cacheStore.set(path, resolution.content, key);

      if (strategy !== ResolutionStrategy.SERVER_WINS) {
        this.offlineQueue.push({
          path,
          type: 'modify',
          content: resolution.content,
          timestamp: Date.now(),
        });
      }
    }

    this.emit({
      type: SyncEventType.CONFLICT_RESOLVED,
      timestamp: Date.now(),
      data: { path, strategy },
    });

    // Check if all conflicts are resolved
    const remaining = this.conflictResolver.getPendingConflicts();
    if (remaining.length === 0 && this.state === SyncEngineState.CONFLICT) {
      this.setState(SyncEngineState.IDLE);
    }
  }

  /**
   * Queue a local file change for sync.
   * Used when files are modified while offline.
   *
   * @param change - File change to queue
   */
  queueChange(change: FileChange): void {
    // Deduplicate: keep only the latest change per path
    this.offlineQueue = this.offlineQueue.filter(c => c.path !== change.path);
    this.offlineQueue.push(change);

    this.emit({
      type: SyncEventType.CHANGE_QUEUED,
      timestamp: Date.now(),
      data: { path: change.path, queueSize: this.offlineQueue.length },
    });
  }

  /**
   * Get the current sync status.
   */
  getStatus(): SyncEngineStatus {
    return {
      state: this.state,
      lastSync: this.lastSyncTimestamp,
      queuedChanges: this.offlineQueue.length,
      pendingConflicts: this.conflictResolver.getPendingConflicts().length,
      error: null,
    };
  }

  /**
   * Register an event listener for sync events.
   *
   * @param type - Event type to listen for
   * @param listener - Callback function
   */
  on(type: SyncEventType, listener: (event: SyncEvent) => void): void {
    if (!this.listeners.has(type)) {
      this.listeners.set(type, new Set());
    }
    this.listeners.get(type)!.add(listener);
  }

  /**
   * Remove an event listener.
   */
  off(type: SyncEventType, listener: (event: SyncEvent) => void): void {
    this.listeners.get(type)?.delete(listener);
  }

  /**
   * Handle access revocation — stop sync and clear state.
   */
  async handleRevocation(): Promise<void> {
    this.stop();
    this.setState(SyncEngineState.REVOKED);
    this.offlineQueue = [];
    this.emit({ type: SyncEventType.ACCESS_REVOKED, timestamp: Date.now() });
  }

  /**
   * Clean up resources on plugin unload.
   */
  destroy(): void {
    this.stop();
    this.listeners.clear();
    this.offlineQueue = [];
  }

  // --- Private Methods ---

  /**
   * Update sync state and emit state change event.
   */
  private setState(newState: SyncEngineState): void {
    const oldState = this.state;
    this.state = newState;

    if (oldState !== newState) {
      this.emit({
        type: SyncEventType.STATE_CHANGED,
        timestamp: Date.now(),
        data: { from: oldState, to: newState },
      });
    }
  }

  /**
   * Emit a sync event to all registered listeners.
   */
  private emit(event: SyncEvent): void {
    const listeners = this.listeners.get(event.type);
    if (listeners) {
      for (const listener of listeners) {
        try {
          listener(event);
        } catch (error) {
          console.error('[VaultGuard] Event listener error:', error);
        }
      }
    }
  }

  /**
   * Handle detected conflicts using the configured auto-resolve strategy.
   */
  private async handleConflicts(conflicts: ConflictInfo[], key: EncryptionKey): Promise<void> {
    for (const conflict of conflicts) {
      this.conflictResolver.registerConflict(conflict);

      // Auto-resolve if configured
      if (this.config.autoResolveStrategy !== ResolutionStrategy.MANUAL) {
        await this.resolveConflict(conflict.path, this.config.autoResolveStrategy as ResolutionStrategy);
      } else {
        this.emit({
          type: SyncEventType.CONFLICT_DETECTED,
          timestamp: Date.now(),
          data: conflict,
        });
      }
    }
  }

  /**
   * Fetch the permission-filtered file listing from the server.
   */
  private async fetchServerFileList(): Promise<ServerFileEntry[]> {
    const response = await requestUrl({
      url: `${this.serverBaseUrl}/sync/files`,
      method: 'GET',
      headers: {
        Authorization: `Bearer ${this.authToken}`,
        'X-Last-Sync': this.lastSyncTimestamp.toString(),
      },
      throw: false,
    });

    if (response.status === 401) {
      throw new AuthError('Access revoked');
    }

    if (response.status < 200 || response.status >= 300) {
      throw new Error(`Server file list request failed: ${response.status}`);
    }

    return response.json.files as ServerFileEntry[];
  }

  /**
   * Download a single file from the server.
   */
  private async downloadFile(path: string): Promise<string> {
    const response = await requestUrl({
      url: `${this.serverBaseUrl}/sync/file`,
      method: 'GET',
      headers: {
        Authorization: `Bearer ${this.authToken}`,
        'X-File-Path': encodeURIComponent(path),
      },
      throw: false,
    });

    if (response.status < 200 || response.status >= 300) {
      throw new Error(`File download failed for ${path}: ${response.status}`);
    }

    return response.text;
  }

  /**
   * Upload a file change to the server.
   */
  private async uploadFile(change: FileChange, key: EncryptionKey): Promise<void> {
    const content = change.content ?? await this.cacheStore.get(change.path, key);

    const response = await requestUrl({
      url: `${this.serverBaseUrl}/sync/file`,
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${this.authToken}`,
      },
      contentType: 'application/json',
      body: JSON.stringify({
        path: change.path,
        content,
        type: change.type,
        timestamp: change.timestamp,
      }),
      throw: false,
    });

    if (response.status === 401) {
      throw new AuthError('Access revoked');
    }

    if (response.status === 409) {
      // Conflict detected server-side
      throw new ConflictError(change.path);
    }

    if (response.status < 200 || response.status >= 300) {
      throw new Error(`File upload failed for ${change.path}: ${response.status}`);
    }
  }

  /**
   * Build a SyncEngineStatus object.
   */
  private buildStatus(
    error: string | null,
    stats?: { pulled?: number; pushed?: number; conflicts?: number }
  ): SyncEngineStatus {
    return {
      state: this.state,
      lastSync: this.lastSyncTimestamp,
      queuedChanges: this.offlineQueue.length,
      pendingConflicts: this.conflictResolver.getPendingConflicts().length,
      error,
      pulled: stats?.pulled,
      pushed: stats?.pushed,
      conflictsDetected: stats?.conflicts,
    };
  }

  private isNetworkError(error: unknown): boolean {
    if (error && typeof error === 'object' && 'status' in error && (error as { status: number }).status === 0) {
      return true;
    }
    const message = this.extractErrorMessage(error);
    if (!message) return false;
    return (
      message.includes('network') ||
      message.includes('timeout') ||
      message.includes('econnrefused') ||
      message.includes('enotfound') ||
      message.includes('err_name_not_resolved') ||
      message.includes('errname') ||
      message.includes('failed to fetch') ||
      message.includes('net::err_') ||
      message.includes('abort')
    );
  }

  private extractErrorMessage(error: unknown): string {
    if (error instanceof Error) return error.message.toLowerCase();
    if (typeof error === 'string') return error.toLowerCase();
    if (error && typeof error === 'object') {
      const obj = error as Record<string, unknown>;
      if (typeof obj.message === 'string') return obj.message.toLowerCase();
      if (typeof obj.text === 'string') return obj.text.toLowerCase();
    }
    return '';
  }

  private isAuthError(error: unknown): boolean {
    return error instanceof AuthError;
  }
}

/** Custom error for authentication/authorization failures. */
class AuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthError';
  }
}

/** Custom error for sync conflicts detected server-side. */
class ConflictError extends Error {
  public path: string;

  constructor(path: string) {
    super(`Conflict detected for: ${path}`);
    this.name = 'ConflictError';
    this.path = path;
  }
}
