/**
 * VaultGuard - Sync Conflict Handling
 *
 * Detects and resolves conflicts when both local and server copies of a file
 * have diverged since the last successful sync.
 */

import { requestUrl } from "obsidian";
import { ConflictInfo, ConflictRecord, ConflictResolutionResult } from '../types';

/**
 * Available conflict resolution strategies.
 */
export enum ResolutionStrategy {
  /** Server version overwrites local (default for auto-resolve) */
  SERVER_WINS = 'server_wins',
  /** Local version is pushed to server */
  LOCAL_WINS = 'local_wins',
  /** User resolves manually via diff UI */
  MANUAL = 'manual',
  /** Attempt line-by-line merge for markdown files */
  MERGE = 'merge',
}

/**
 * Handles sync conflict detection, resolution, and history tracking.
 */
export class ConflictResolver {
  private pendingConflicts: Map<string, ConflictRecord> = new Map();
  private conflictHistory: ConflictRecord[] = [];
  private maxHistorySize: number;
  private serverBaseUrl: string;
  private authToken: string;
  private notifyUser: (message: string, path: string) => void;
  private readLocalFile: ((path: string) => Promise<string | null>) | null;

  /**
   * @param serverBaseUrl - Base URL of the VaultGuard server
   * @param authToken - Bearer token for authentication
   * @param notifyUser - Callback to display conflict notifications (Obsidian Notice)
   * @param maxHistorySize - Maximum conflict history entries to retain
   * @param readLocalFile - Callback to read local file content from the cache store
   */
  constructor(
    serverBaseUrl: string,
    authToken: string,
    notifyUser: (message: string, path: string) => void,
    maxHistorySize: number = 100,
    readLocalFile?: (path: string) => Promise<string | null>
  ) {
    this.serverBaseUrl = serverBaseUrl;
    this.authToken = authToken;
    this.notifyUser = notifyUser;
    this.maxHistorySize = maxHistorySize;
    this.readLocalFile = readLocalFile ?? null;
  }

  /**
   * Register a detected conflict for resolution.
   * Notifies the user via Obsidian Notice.
   *
   * @param conflict - Conflict information from the sync engine
   */
  registerConflict(conflict: ConflictInfo): void {
    const record: ConflictRecord = {
      ...conflict,
      detectedAt: Date.now(),
      resolvedAt: null,
      resolution: null,
      strategy: null,
    };

    this.pendingConflicts.set(conflict.path, record);

    // Notify user via Obsidian Notice
    this.notifyUser(
      `Sync conflict detected: "${this.getFileName(conflict.path)}" was modified both locally and on the server.`,
      conflict.path
    );
  }

  /**
   * Resolve a conflict using the specified strategy.
   *
   * @param path - File path with the conflict
   * @param strategy - Resolution strategy to apply
   * @param mergedContent - Optional manually merged content (for MANUAL/MERGE strategies)
   * @returns Resolution result with the content to use
   */
  async resolve(
    path: string,
    strategy: ResolutionStrategy,
    mergedContent?: string
  ): Promise<ConflictResolutionResult> {
    const record = this.pendingConflicts.get(path);
    if (!record) {
      throw new Error(`No pending conflict found for path: ${path}`);
    }

    let resolution: ConflictResolutionResult;

    switch (strategy) {
      case ResolutionStrategy.SERVER_WINS:
        resolution = await this.resolveServerWins(path);
        break;

      case ResolutionStrategy.LOCAL_WINS:
        resolution = await this.resolveLocalWins(path);
        break;

      case ResolutionStrategy.MANUAL:
        if (!mergedContent) {
          throw new Error('Manual resolution requires merged content');
        }
        resolution = {
          path,
          content: mergedContent,
          strategy,
          resolvedAt: Date.now(),
        };
        break;

      case ResolutionStrategy.MERGE:
        resolution = await this.resolveMerge(path);
        break;

      default:
        throw new Error(`Unknown resolution strategy: ${strategy}`);
    }

    // Move from pending to history
    record.resolvedAt = Date.now();
    record.resolution = resolution;
    record.strategy = strategy;
    this.pendingConflicts.delete(path);
    this.addToHistory(record);

    return resolution;
  }

  /**
   * Get all currently pending (unresolved) conflicts.
   *
   * @returns Array of conflict records awaiting resolution
   */
  getPendingConflicts(): ConflictRecord[] {
    return Array.from(this.pendingConflicts.values());
  }

  /**
   * Get the conflict history log.
   *
   * @param limit - Maximum entries to return (default: all)
   * @returns Array of resolved conflict records, newest first
   */
  getHistory(limit?: number): ConflictRecord[] {
    const history = [...this.conflictHistory].reverse();
    return limit ? history.slice(0, limit) : history;
  }

  /**
   * Check if a specific path has a pending conflict.
   */
  hasConflict(path: string): boolean {
    return this.pendingConflicts.has(path);
  }

  /**
   * Clear all pending conflicts (e.g., on full re-sync or revocation).
   */
  clearPending(): void {
    this.pendingConflicts.clear();
  }

  /**
   * Clear conflict history.
   */
  clearHistory(): void {
    this.conflictHistory = [];
  }

  // --- Resolution Strategy Implementations ---

  /**
   * Resolve by accepting the server version.
   * Downloads the server copy and discards local changes.
   */
  private async resolveServerWins(path: string): Promise<ConflictResolutionResult> {
    const serverContent = await this.fetchServerVersion(path);

    return {
      path,
      content: serverContent,
      strategy: ResolutionStrategy.SERVER_WINS,
      resolvedAt: Date.now(),
    };
  }

  /**
   * Resolve by keeping the local version.
   * The local content will be pushed to the server on next sync.
   */
  private async resolveLocalWins(path: string): Promise<ConflictResolutionResult> {
    // Local content is already in the cache — no content needed in resolution
    // The sync engine will push local changes
    return {
      path,
      content: null,
      strategy: ResolutionStrategy.LOCAL_WINS,
      resolvedAt: Date.now(),
    };
  }

  /**
   * Attempt an automatic line-by-line merge for markdown files.
   * Falls back to MANUAL if merge conflicts are detected within the diff.
   */
  private async resolveMerge(path: string): Promise<ConflictResolutionResult> {
    if (!this.isMarkdownFile(path)) {
      throw new Error('Merge strategy is only supported for markdown files');
    }

    const serverContent = await this.fetchServerVersion(path);
    const localContent = await this.fetchLocalVersion(path);
    const baseContent = await this.fetchBaseVersion(path);

    if (!localContent) {
      // If we cannot get local content, fall back to server wins
      return {
        path,
        content: serverContent,
        strategy: ResolutionStrategy.MERGE,
        resolvedAt: Date.now(),
        mergeDetails: { fallback: 'server_wins', reason: 'local content unavailable' },
      };
    }

    const merged = this.threeWayMerge(baseContent, localContent, serverContent);

    if (merged.hasConflicts) {
      // Cannot auto-merge — notify user for manual resolution
      this.notifyUser(
        `Auto-merge failed for "${this.getFileName(path)}". Manual resolution required.`,
        path
      );

      return {
        path,
        content: merged.content,
        strategy: ResolutionStrategy.MERGE,
        resolvedAt: Date.now(),
        mergeDetails: {
          hasConflicts: true,
          conflictMarkers: merged.conflictCount,
        },
      };
    }

    return {
      path,
      content: merged.content,
      strategy: ResolutionStrategy.MERGE,
      resolvedAt: Date.now(),
      mergeDetails: { hasConflicts: false },
    };
  }

  /**
   * Perform a three-way merge on markdown content.
   * Uses line-by-line comparison with the common ancestor (base).
   *
   * @param base - Common ancestor content (last synced version)
   * @param local - Local modified version
   * @param server - Server modified version
   * @returns Merged content with conflict markers if needed
   */
  private threeWayMerge(
    base: string | null,
    local: string,
    server: string
  ): { content: string; hasConflicts: boolean; conflictCount: number } {
    const baseLines = (base ?? '').split('\n');
    const localLines = local.split('\n');
    const serverLines = server.split('\n');

    const result: string[] = [];
    let hasConflicts = false;
    let conflictCount = 0;

    const maxLines = Math.max(baseLines.length, localLines.length, serverLines.length);

    for (let i = 0; i < maxLines; i++) {
      const baseLine = baseLines[i] ?? '';
      const localLine = localLines[i] ?? '';
      const serverLine = serverLines[i] ?? '';

      if (localLine === serverLine) {
        // Both agree — use either
        result.push(localLine);
      } else if (localLine === baseLine) {
        // Only server changed — accept server
        result.push(serverLine);
      } else if (serverLine === baseLine) {
        // Only local changed — accept local
        result.push(localLine);
      } else {
        // Both changed differently — conflict
        hasConflicts = true;
        conflictCount++;
        result.push('<<<<<<< LOCAL');
        result.push(localLine);
        result.push('=======');
        result.push(serverLine);
        result.push('>>>>>>> SERVER');
      }
    }

    return {
      content: result.join('\n'),
      hasConflicts,
      conflictCount,
    };
  }

  /**
   * Fetch the server's current version of a file.
   */
  private async fetchServerVersion(path: string): Promise<string> {
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
      throw new Error(`Failed to fetch server version for ${path}: ${response.status}`);
    }

    return response.text;
  }

  /**
   * Fetch the local cached version of a file.
   * Delegates to the readLocalFile callback provided at construction.
   */
  private async fetchLocalVersion(path: string): Promise<string | null> {
    if (this.readLocalFile) {
      return this.readLocalFile(path);
    }
    return null;
  }

  /**
   * Fetch the base (common ancestor) version of a file.
   * This is the last successfully synced version.
   */
  private async fetchBaseVersion(path: string): Promise<string | null> {
    try {
      const response = await requestUrl({
        url: `${this.serverBaseUrl}/sync/file/base`,
        method: 'GET',
        headers: {
          Authorization: `Bearer ${this.authToken}`,
          'X-File-Path': encodeURIComponent(path),
        },
        throw: false,
      });

      if (response.status < 200 || response.status >= 300) return null;
      return response.text;
    } catch {
      return null;
    }
  }

  /**
   * Add a resolved conflict to the history log.
   */
  private addToHistory(record: ConflictRecord): void {
    this.conflictHistory.push(record);

    // Trim history to max size
    if (this.conflictHistory.length > this.maxHistorySize) {
      this.conflictHistory = this.conflictHistory.slice(-this.maxHistorySize);
    }
  }

  /**
   * Check if a file is a markdown file (eligible for merge).
   */
  private isMarkdownFile(path: string): boolean {
    return path.endsWith('.md') || path.endsWith('.markdown');
  }

  /**
   * Extract the filename from a path for display.
   */
  private getFileName(path: string): string {
    return path.split('/').pop() ?? path;
  }
}
