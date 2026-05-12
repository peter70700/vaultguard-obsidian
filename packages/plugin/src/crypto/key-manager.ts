/**
 * VaultGuard - Server-Managed Key Lifecycle
 *
 * Handles key lease acquisition, renewal, revocation, and offline grace periods.
 * Keys are stored in memory only — never persisted to disk in plaintext.
 *
 * Supports two encryption models:
 * - 'server-managed' (Model A): Server issues plaintext DEKs via KMS
 * - 'hybrid-zk' (Model C): Server returns wrapped UMK; client derives DEKs locally
 */

import { requestUrl } from "obsidian";
import { EncryptionKey, KeyManagerConfig } from '../types';
import { EncryptionEngine } from './encryption-engine';
import { PassphraseManager, ZkLoginMaterial } from './passphrase-manager';

/** Encryption model for the org */
export type EncryptionModel = 'server-managed' | 'hybrid-zk';

/** Internal key lease representation used by KeyManager. */
interface KeyLeaseInternal {
  /** Unique identifier for this key lease */
  keyId: string;
  /** Base64-encoded encryption key */
  key: string;
  /** ISO timestamp when the lease expires */
  expiresAt: string;
  /** ISO timestamp when the lease was issued */
  issuedAt: string;
  /** Token required to refresh this lease */
  refreshToken: string;
  /** Path scope this lease is bound to */
  scope: string;
  /** Offline grace period in milliseconds */
  gracePeriodMs?: number;
}

/** A scoped lease entry with its decoded key material. */
interface ScopedLeaseEntry {
  lease: KeyLeaseInternal;
  key: EncryptionKey;
}

/** Default heartbeat interval (60 seconds) */
const DEFAULT_HEARTBEAT_INTERVAL_MS = 60 * 1000;
/** Number of consecutive heartbeat failures before entering offline mode */
const HEARTBEAT_FAILURE_THRESHOLD = 3;

/** Default configuration values */
const DEFAULT_REFRESH_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes
const DEFAULT_GRACE_PERIOD_MS = 24 * 60 * 60 * 1000; // 24 hours
const DEFAULT_REFRESH_BUFFER_MS = 60 * 1000; // Refresh 1 minute before expiry

/**
 * Manages the lifecycle of server-provided encryption keys.
 * Keys exist only in memory and are wiped on revocation or expiry.
 */
export class KeyManager {
  private currentLease: KeyLeaseInternal | null = null;
  private encryptionKey: EncryptionKey | null = null;
  /** Scoped leases: scope pattern → lease + decoded key */
  private scopedLeases: Map<string, ScopedLeaseEntry> = new Map();
  private refreshTimer: ReturnType<typeof setTimeout> | null = null;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private heartbeatFailures: number = 0;
  private lastServerContact: number = 0;
  private sessionId: string | null = null;
  private config: Required<KeyManagerConfig>;
  private encryptionEngine: EncryptionEngine;
  private serverBaseUrl: string;
  private authToken: string;
  private onRevocation: (() => Promise<void>) | null = null;
  private onScopeRevoked: ((scope: string) => Promise<void>) | null = null;
  /** Encryption model for the current org */
  private encryptionModel: EncryptionModel = 'server-managed';
  /** Passphrase manager for hybrid-zk mode */
  private passphraseManager: PassphraseManager | null = null;

  /**
   * @param serverBaseUrl - Base URL of the VaultGuard key server
   * @param authToken - Bearer token for authenticating with the server
   * @param encryptionEngine - Encryption engine instance for key wiping
   * @param config - Optional configuration overrides
   */
  constructor(
    serverBaseUrl: string,
    authToken: string,
    encryptionEngine: EncryptionEngine,
    config?: KeyManagerConfig
  ) {
    this.serverBaseUrl = serverBaseUrl;
    this.authToken = authToken;
    this.encryptionEngine = encryptionEngine;
    this.config = {
      refreshIntervalMs: config?.refreshIntervalMs ?? DEFAULT_REFRESH_INTERVAL_MS,
      gracePeriodMs: config?.gracePeriodMs ?? DEFAULT_GRACE_PERIOD_MS,
      refreshBufferMs: config?.refreshBufferMs ?? DEFAULT_REFRESH_BUFFER_MS,
      vaultId: config?.vaultId ?? '',
    };
  }

  /**
   * Register a callback to invoke when access is revoked.
   * The callback should handle cache wiping and UI notification.
   */
  onAccessRevoked(callback: () => Promise<void>): void {
    this.onRevocation = callback;
  }

  /**
   * Request a new key lease from the server.
   * Initiates the refresh loop upon successful lease acquisition.
   *
   * @returns The encryption key for cache operations
   * @throws Error if the server rejects the request or is unreachable
   */
  async requestLease(): Promise<EncryptionKey> {
    const params = this.sessionId ? `?sessionId=${encodeURIComponent(this.sessionId)}` : '';
    const response = await this.fetchFromServer(`/auth/key-lease${params}`, {
      method: 'GET',
    });

    if (response.status === 401) {
      await this.revokeAndWipe();
      throw new Error('Access denied: key lease request rejected by server');
    }

    if (response.status < 200 || response.status >= 300) {
      throw new Error(`Key lease request failed: ${response.status}`);
    }

    const data = response.json;
    const leaseData = data.payload ?? data.keyLease;
    if (!leaseData) {
      throw new Error('Key lease response did not include a key lease');
    }
    const keyId = leaseData.keyId ?? leaseData.leaseId;
    if (!keyId) {
      throw new Error('Key lease response did not include a lease ID');
    }

    this.currentLease = {
      keyId,
      key: leaseData.key,
      expiresAt: leaseData.expiresAt,
      issuedAt: leaseData.issuedAt ?? new Date().toISOString(),
      refreshToken: leaseData.refreshToken,
      scope: leaseData.scope ?? '/**',
      gracePeriodMs: leaseData.gracePeriodMs ?? this.config.gracePeriodMs,
    };

    this.encryptionKey = this.decodeKey(leaseData.key);
    this.lastServerContact = Date.now();

    // Also store as a scoped lease entry
    this.scopedLeases.set(this.currentLease.scope, {
      lease: this.currentLease,
      key: this.encryptionKey,
    });

    this.startRefreshLoop();
    this.startHeartbeat();

    return this.encryptionKey;
  }

  /**
   * Set the session ID for heartbeat and refresh requests.
   * Should be called after login when the session ID is known.
   */
  setSessionId(sessionId: string): void {
    this.sessionId = sessionId;
  }

  /**
   * Set or update the default vault ID for scoped lease requests.
   */
  setVaultId(vaultId: string): void {
    this.config.vaultId = vaultId;
  }

  /**
   * Register a callback invoked when a specific scope's lease is revoked.
   * The callback receives the scope pattern and should handle scope-specific cache wipe.
   */
  onScopeAccessRevoked(callback: (scope: string) => Promise<void>): void {
    this.onScopeRevoked = callback;
  }

  /**
   * Request a path-scoped key lease from the server.
   * Each scope gets its own DEK, enabling path-level revocation.
   *
   * @param scope - Path glob pattern (e.g., '/engineering/**')
   * @param vaultId - Vault ID this scope belongs to. Uses config.vaultId when omitted.
   * @returns The encryption key for that scope
   */
  async requestScopedLease(scope: string, vaultId?: string): Promise<EncryptionKey> {
    if (!this.sessionId) {
      throw new Error('Session ID required for scoped lease requests. Call setSessionId() first.');
    }
    const effectiveVaultId = vaultId ?? this.config.vaultId;
    if (!effectiveVaultId) {
      throw new Error('Vault ID required for scoped lease requests. Call setVaultId() first or pass vaultId.');
    }

    const response = await this.fetchFromServer('/auth/key-lease/scoped', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sessionId: this.sessionId, scope, vaultId: effectiveVaultId }),
    });

    if (response.status === 401 || response.status === 403) {
      throw new Error(`Scoped lease denied for '${scope}': ${response.status}`);
    }

    if (response.status < 200 || response.status >= 300) {
      throw new Error(`Scoped lease request failed: ${response.status}`);
    }

    const data = response.json;
    const leaseData = data.keyLease || data.payload;

    const lease: KeyLeaseInternal = {
      keyId: leaseData.leaseId,
      key: leaseData.key,
      expiresAt: leaseData.expiresAt,
      issuedAt: new Date().toISOString(),
      refreshToken: leaseData.refreshToken,
      scope,
    };

    const key = this.decodeKey(leaseData.key);

    this.scopedLeases.set(scope, { lease, key });
    this.lastServerContact = Date.now();

    return key;
  }

  /**
   * Get the encryption key for a given file path.
   * Resolves the most specific matching scope from active leases.
   * Falls back to the default lease ('/**') if no scoped lease matches.
   *
   * @param filePath - Vault-relative file path
   * @returns The encryption key, or null if no valid lease covers this path
   */
  getKeyForPath(filePath: string): EncryptionKey | null {
    let bestMatch: ScopedLeaseEntry | null = null;
    let bestSpecificity = -1;

    for (const [scope, entry] of this.scopedLeases) {
      if (this.pathMatchesScope(filePath, scope)) {
        const specificity = this.getScopeSpecificity(scope);
        if (specificity > bestSpecificity) {
          // Check this scoped lease is still valid
          const expiresAt = new Date(entry.lease.expiresAt).getTime();
          if (Date.now() < expiresAt || this.isWithinGracePeriod()) {
            bestMatch = entry;
            bestSpecificity = specificity;
          }
        }
      }
    }

    if (bestMatch) {
      return bestMatch.key;
    }

    // Fall back to the default lease
    return this.getKey();
  }

  /**
   * Revoke a specific scope's lease and wipe its key from memory.
   * Triggers the onScopeRevoked callback for scope-specific cache wipe.
   *
   * @param scope - The scope pattern to revoke
   */
  async revokeScopeKey(scope: string): Promise<void> {
    const entry = this.scopedLeases.get(scope);
    if (entry) {
      this.wipeKeyFromMemory(entry.key);
      this.scopedLeases.delete(scope);

      if (this.onScopeRevoked) {
        await this.onScopeRevoked(scope);
      }
    }
  }

  /**
   * Get all active scope patterns with valid leases.
   */
  getActiveScopes(): string[] {
    const scopes: string[] = [];
    const now = Date.now();
    for (const [scope, entry] of this.scopedLeases) {
      const expiresAt = new Date(entry.lease.expiresAt).getTime();
      if (now < expiresAt || this.isWithinGracePeriod()) {
        scopes.push(scope);
      }
    }
    return scopes;
  }

  // ─── Hybrid ZK Mode ─────────────────────────────────────────────────────────

  /**
   * Set the encryption model for this org.
   * In 'hybrid-zk' mode, keys are derived client-side from a passphrase.
   */
  setEncryptionModel(model: EncryptionModel): void {
    this.encryptionModel = model;
    if (model === 'hybrid-zk' && !this.passphraseManager) {
      this.passphraseManager = new PassphraseManager();
    }
  }

  /**
   * Get the current encryption model.
   */
  getEncryptionModel(): EncryptionModel {
    return this.encryptionModel;
  }

  /**
   * Get the PassphraseManager instance (only available in hybrid-zk mode).
   */
  getPassphraseManager(): PassphraseManager | null {
    return this.passphraseManager;
  }

  /**
   * Login with passphrase in hybrid-zk mode.
   * Fetches wrapped key material from the server and unwraps locally.
   *
   * @param passphrase - User's passphrase
   * @returns The derived DEK for the default scope
   */
  async loginWithPassphrase(passphrase: string): Promise<EncryptionKey> {
    if (this.encryptionModel !== 'hybrid-zk') {
      throw new Error('loginWithPassphrase() requires hybrid-zk encryption model');
    }

    if (!this.passphraseManager) {
      this.passphraseManager = new PassphraseManager();
    }

    // Fetch wrapped key material from server
    const response = await this.fetchFromServer('/auth/wrapped-key', {
      method: 'GET',
    });

    if (response.status < 200 || response.status >= 300) {
      throw new Error(`Failed to fetch wrapped key: ${response.status}`);
    }

    const material: ZkLoginMaterial = response.json;

    // Unwrap UMK locally with passphrase
    const success = await this.passphraseManager.login(passphrase, material);
    if (!success) {
      throw new Error('Incorrect passphrase');
    }

    // Derive the default DEK from the UMK
    const dek = await this.passphraseManager.deriveDek('/**');
    this.encryptionKey = dek;
    this.lastServerContact = Date.now();

    this.startHeartbeat();

    return dek;
  }

  /**
   * Derive a scope-specific DEK in hybrid-zk mode.
   * Each scope gets a unique key derived from the same UMK.
   *
   * @param scope - Path scope for key derivation
   * @returns The derived DEK
   */
  async deriveKeyForScope(scope: string): Promise<EncryptionKey> {
    if (!this.passphraseManager || !this.passphraseManager.isUnlocked()) {
      throw new Error('UMK not available. Call loginWithPassphrase() first.');
    }

    return this.passphraseManager.deriveDek(scope);
  }

  /**
   * Refresh the current key lease before it expires.
   * If the server returns 401, triggers full revocation and wipe.
   *
   * @returns Updated encryption key (may be the same or rotated)
   * @throws Error if refresh fails and grace period has elapsed
   */
  async refreshLease(): Promise<EncryptionKey> {
    if (!this.currentLease) {
      return this.requestLease();
    }

    try {
      const response = await this.fetchFromServer('/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          keyId: this.currentLease.keyId,
          leaseId: this.currentLease.keyId,
          refreshToken: this.currentLease.refreshToken,
          sessionId: this.sessionId,
        }),
      });

      if (response.status === 401) {
        await this.revokeAndWipe();
        throw new Error('Access revoked during lease refresh');
      }

      if (response.status < 200 || response.status >= 300) {
        throw new Error(`Lease refresh failed: ${response.status}`);
      }

      const data = response.json;
      const leaseData = data.payload ?? data.keyLease;
      if (!leaseData) {
        throw new Error('Lease refresh response did not include a key lease');
      }
      const nextKeyId = leaseData.keyId ?? leaseData.leaseId;
      if (!nextKeyId) {
        throw new Error('Lease refresh response did not include a lease ID');
      }

      // Handle key rotation if the server provides a new key
      if (nextKeyId !== this.currentLease.keyId) {
        const newKey = this.decodeKey(leaseData.key);
        // Key rotation is handled by the caller through the rotateKey event
        this.encryptionKey = newKey;
      }

      this.currentLease = {
        keyId: nextKeyId,
        key: leaseData.key,
        expiresAt: leaseData.expiresAt,
        issuedAt: leaseData.issuedAt ?? new Date().toISOString(),
        refreshToken: leaseData.refreshToken,
        scope: leaseData.scope ?? '/**',
        gracePeriodMs: leaseData.gracePeriodMs ?? this.config.gracePeriodMs,
      };

      // Update scoped lease map
      this.scopedLeases.set(this.currentLease.scope, {
        lease: this.currentLease,
        key: this.encryptionKey!,
      });

      this.lastServerContact = Date.now();
      this.heartbeatFailures = 0;
      return this.encryptionKey!;
    } catch (error) {
      // If we cannot reach the server, check grace period
      if (this.isWithinGracePeriod()) {
        return this.encryptionKey!;
      }

      // Grace period expired — emergency wipe
      await this.emergencyWipe();
      throw new Error('Key lease expired: offline grace period exceeded');
    }
  }

  /**
   * Check if the current key lease is valid.
   * Considers both expiry time and offline grace period.
   *
   * @returns True if the lease is active and usable
   */
  isLeaseValid(): boolean {
    if (!this.currentLease || !this.encryptionKey) {
      return false;
    }

    const now = Date.now();
    const expiresAt = new Date(this.currentLease.expiresAt).getTime();

    // Lease not yet expired
    if (now < expiresAt) {
      return true;
    }

    // Lease expired but within offline grace period
    if (this.isWithinGracePeriod()) {
      return true;
    }

    return false;
  }

  /**
   * Get the current encryption key if the lease is valid.
   *
   * @returns The active encryption key or null if lease is invalid
   */
  getKey(): EncryptionKey | null {
    if (!this.isLeaseValid()) {
      return null;
    }
    return this.encryptionKey;
  }

  /**
   * Get the current lease metadata.
   */
  getLease(): KeyLeaseInternal | null {
    return this.currentLease;
  }

  /**
   * Handle server-initiated key revocation.
   * Wipes all key material and encrypted cache, then notifies the UI.
   */
  async revokeAndWipe(): Promise<void> {
    this.stopRefreshLoop();
    this.stopHeartbeat();

    // Wipe encryption keys from memory
    if (this.encryptionKey) {
      this.wipeKeyFromMemory(this.encryptionKey);
    }

    // Wipe all scoped lease keys
    for (const [, entry] of this.scopedLeases) {
      this.wipeKeyFromMemory(entry.key);
    }
    this.scopedLeases.clear();

    this.encryptionEngine.wipeKeys();

    // Lock passphrase manager (hybrid-zk mode)
    if (this.passphraseManager) {
      this.passphraseManager.lock();
    }

    this.currentLease = null;
    this.encryptionKey = null;

    // Invoke the revocation callback (cache wipe, UI notification)
    if (this.onRevocation) {
      await this.onRevocation();
    }
  }

  /**
   * Clean up resources (stop timers, wipe keys).
   * Call this when the plugin is unloaded.
   */
  destroy(): void {
    this.stopRefreshLoop();
    this.stopHeartbeat();
    if (this.encryptionKey) {
      this.wipeKeyFromMemory(this.encryptionKey);
    }
    for (const [, entry] of this.scopedLeases) {
      this.wipeKeyFromMemory(entry.key);
    }
    this.scopedLeases.clear();
    this.encryptionEngine.wipeKeys();
    if (this.passphraseManager) {
      this.passphraseManager.lock();
    }
    this.currentLease = null;
    this.encryptionKey = null;
  }

  /**
   * Check if we are within the offline grace period.
   */
  private isWithinGracePeriod(): boolean {
    if (!this.currentLease) return false;
    const gracePeriod = this.currentLease.gracePeriodMs ?? this.config.gracePeriodMs;
    const elapsed = Date.now() - this.lastServerContact;
    return elapsed < gracePeriod;
  }

  /**
   * Emergency wipe when grace period expires without server contact.
   */
  private async emergencyWipe(): Promise<void> {
    console.warn('[VaultGuard] Emergency wipe: offline grace period exceeded');
    await this.revokeAndWipe();
  }

  /**
   * Start the automatic lease refresh loop.
   * Refreshes the lease before it expires based on configured buffer.
   */
  private startRefreshLoop(): void {
    this.stopRefreshLoop();

    if (!this.currentLease) return;

    const expiresAt = new Date(this.currentLease.expiresAt).getTime();
    const timeUntilExpiry = expiresAt - Date.now();
    const refreshIn = Math.max(
      timeUntilExpiry - this.config.refreshBufferMs,
      this.config.refreshIntervalMs
    );

    this.refreshTimer = setTimeout(async () => {
      try {
        await this.refreshLease();
      } catch (error) {
        console.error('[VaultGuard] Lease refresh failed:', error);
      }
    }, refreshIn);
  }

  /**
   * Stop the automatic lease refresh loop.
   */
  private stopRefreshLoop(): void {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
  }

  /**
   * Start the heartbeat polling loop.
   * Polls the server every 60 seconds to detect revocation quickly.
   * On revoked response, triggers immediate revokeAndWipe().
   */
  private startHeartbeat(): void {
    this.stopHeartbeat();
    this.heartbeatFailures = 0;

    this.heartbeatTimer = setInterval(async () => {
      try {
        const params = this.sessionId ? `?sessionId=${this.sessionId}` : '';
        const response = await this.fetchFromServer(`/auth/heartbeat${params}`, {
          method: 'GET',
        });

        if (response.status === 401) {
          // Token invalid — revoke immediately
          await this.revokeAndWipe();
          return;
        }

        if (response.status >= 200 && response.status < 300) {
          const data = response.json;
          this.heartbeatFailures = 0;
          this.lastServerContact = Date.now();

          if (data.active === false) {
            console.warn(`[VaultGuard] Heartbeat: access revoked (${data.reason})`);
            await this.revokeAndWipe();
          }
        } else {
          this.heartbeatFailures++;
        }
      } catch {
        this.heartbeatFailures++;
        if (this.heartbeatFailures >= HEARTBEAT_FAILURE_THRESHOLD) {
          console.warn(`[VaultGuard] Heartbeat: ${this.heartbeatFailures} consecutive failures, entering offline mode`);
        }
      }
    }, DEFAULT_HEARTBEAT_INTERVAL_MS);
  }

  /**
   * Stop the heartbeat polling loop.
   */
  private stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
    this.heartbeatFailures = 0;
  }

  /**
   * Make an authenticated request to the key server.
   */
  private async fetchFromServer(
    path: string,
    options: { method?: string; headers?: Record<string, string>; body?: string } = {}
  ) {
    const url = `${this.serverBaseUrl}${path}`;
    return requestUrl({
      url,
      method: options.method ?? 'GET',
      headers: {
        Authorization: `Bearer ${this.authToken}`,
        ...options.headers,
      },
      body: options.body,
      contentType: options.headers?.['Content-Type'],
      throw: false,
    });
  }

  /**
   * Decode a base64-encoded key string from the server into key material.
   */
  private decodeKey(encodedKey: string): EncryptionKey {
    const binaryString = atob(encodedKey);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }

  /**
   * Overwrite key material in memory with zeros.
   */
  private wipeKeyFromMemory(key: EncryptionKey): void {
    if (key instanceof ArrayBuffer) {
      new Uint8Array(key).fill(0);
    } else if (key instanceof Uint8Array) {
      key.fill(0);
    }
  }

  /**
   * Check if a file path falls within a scope pattern.
   */
  private pathMatchesScope(filePath: string, scopePattern: string): boolean {
    if (scopePattern === '/**') return true;

    const normalizedPath = filePath.replace(/\/+/g, '/').replace(/\/$/, '');
    const normalizedPattern = scopePattern.replace(/\/+/g, '/').replace(/\/$/, '');

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
   * Calculate specificity score for a scope pattern.
   * More segments and fewer wildcards = more specific.
   */
  private getScopeSpecificity(scope: string): number {
    if (scope === '/**') return 0;
    const segments = scope.split('/').filter(Boolean);
    let score = segments.length * 10;
    for (const segment of segments) {
      if (segment === '**') score -= 8;
      else if (segment === '*') score -= 5;
      else if (segment.includes('*') || segment.includes('?')) score -= 3;
    }
    return score;
  }
}
