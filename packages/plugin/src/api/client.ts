/**
 * VaultGuard - API Client
 *
 * Handles all communication with the VaultGuard backend API.
 * Features: token management, auto-refresh, retry with exponential backoff,
 * offline detection, and request queuing.
 */

import { RequestUrlResponse, requestUrl } from "obsidian";
import {
  looksLikeAwsSignatureError,
  normalizeVaultGuardApiBaseUrl,
  resolveVaultGuardApiBaseUrl,
} from "./endpoint-resolver";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  idToken: string;
  expiresAt: number; // Unix timestamp in ms
}

export interface ServerSessionRequest {
  /** Optional bound vault used by the backend for login audit attribution. */
  vaultId?: string;
}

export interface ServerSessionResponse {
  sessionId: string;
  userId: string;
  email: string;
  roles: string[];
  expiresAt: string;
  orgSettings: OrgSettingsResponse;
}

export interface UserInfo {
  id: string;
  email: string;
  displayName: string;
  role: string;
  orgId: string;
}

export interface FileMetadata {
  path: string;
  hash: string;
  size: number;
  lastModified: string;
  encryptedKey: string;
}

export interface PermissionRule {
  id: string;
  /** Vault this rule lives in. Permissions are vault-scoped post-multi-vault. */
  vaultId: string;
  userId: string;
  role: string | null;
  pathPattern: string;
  actions: Array<"read" | "write" | "delete" | "admin" | "list">;
  effect: "allow" | "deny";
  priority: number;
  createdAt: string;
  updatedAt: string;
  /** Optional ISO timestamp after which this rule is ignored. */
  expiresAt?: string;
  createdBy: string;
}

export type PermissionAccessLevel = "none" | "read" | "write" | "admin";

export interface PathAccessPrincipal {
  userId: string;
  email?: string;
  displayName?: string;
  role?: string;
  level: PermissionAccessLevel;
}

export interface PathAccessSummary {
  path: string;
  currentUserLevel: PermissionAccessLevel;
  principals: PathAccessPrincipal[];
}

/**
 * A share-link record minted by a vault member. The token itself carries
 * no authority — resolving it to a path still requires vault membership
 * server-side. Lives at `${SHARE_BASE_URL}/s/{shareId}`.
 */
export interface ShareRecord {
  shareId: string;
  vaultId: string;
  /** Vault-relative path of the file at mint time. */
  relPath: string;
  /** ISO timestamp the share was created. */
  createdAt: string;
  /** User ID of the creator. Only they (or vault admins) can revoke. */
  createdBy: string;
  /** Optional ISO expiry. */
  expiresAt?: string | null;
  /** Full https URL the user should copy into Slack/email. */
  url: string;
}

/** Server response for resolving a share token to a concrete (vault, path) pair. */
export interface ResolvedShare {
  shareId: string;
  vaultId: string;
  /** Display name of the cloud vault — used in user-facing messages. */
  vaultName: string;
  vaultSlug: string;
  relPath: string;
  createdBy: string;
  createdAt: string;
  expiresAt: string | null;
}

/** Vault role inside a single vault. Distinct from org-level role. */
export type VaultMemberRole = "viewer" | "editor" | "admin";

/** Vault category used for UI labelling and create flows. */
export type VaultKind = "team" | "personal" | "shared";

/** Server-side Vault entity — a named, isolated namespace inside an org. */
export interface VaultRecord {
  orgId: string;
  vaultId: string;
  name: string;
  slug: string;
  kind: VaultKind;
  defaultRole: VaultMemberRole;
  createdAt: string;
  createdBy: string;
  archived: boolean;
  description?: string;
  /** Vault-wide opt-out list managed by the admin. */
  excludedPaths?: string[];
  /** Vault-wide curated plugin allowlist managed by the admin. */
  pluginAllowlist?: PluginAllowlistEntry[];
}

/** Curated entry on the vault's plugin allowlist. Mirrors the backend type. */
export interface PluginAllowlistEntry {
  pluginId: string;
  displayName: string;
  version?: string;
  bundleSha256?: string;
  addedAt: string;
  addedBy: string;
  note?: string;
}

/** A user's membership in a single vault. */
export interface VaultMemberRecord {
  vaultId: string;
  userId: string;
  role: VaultMemberRole;
  joinedAt: string;
  invitedBy: string;
  /**
   * Server-resolved display name from Cognito. Optional because the
   * server may degrade (Cognito unreachable) and older deployments
   * don't return it.
   */
  displayName?: string;
  /** Server-resolved email. Same caveat as `displayName`. */
  email?: string;
}

export interface ApiError {
  statusCode: number;
  message: string;
  code: string;
  requestId?: string;
}

export interface UserListEntry {
  id: string;
  email: string;
  displayName: string;
  name: string;
  givenName?: string;
  familyName?: string;
  role: "admin" | "editor" | "viewer" | "custom";
  status: "active" | "suspended" | "revoked" | "pending";
  lastActive: string;
  createdAt: string;
  mfaEnabled: boolean;
  deviceCount: number;
  type: "user";
}

export interface RoleEntry {
  id: string;
  name: string;
  type: "role";
  description?: string;
  memberCount?: number;
}

export interface UserActivityEntry {
  timestamp: string;
  action: string;
  resourcePath: string;
  deviceInfo?: string;
}

export interface AuditLogEntry {
  id: string;
  timestamp: string;
  orgId?: string;
  vaultId?: string;
  userId: string;
  userEmail?: string;
  action: string;
  resourcePath: string;
  outcome: "success" | "denied" | "error";
  ipAddress?: string;
  userAgent?: string;
  metadata?: Record<string, unknown>;
}

/** Metadata-only vault overview (no content/keys). Mirrors the files-Lambda. */
export interface VaultOverviewResponse {
  vaultId: string;
  generatedAt: string;
  fileCount: number;
  folderCount: number;
  totalSizeBytes: number;
  maxDepth: number;
  latestModified: string | null;
  extensions: { extension: string; count: number; totalSizeBytes: number }[];
  largestFiles: { path: string; name?: string; size: number; lastModified: string }[];
  isTruncated: boolean;
}

export interface AuditLogPageResponse {
  entries: AuditLogEntry[];
  count: number;
  nextCursor: string | null;
  lastEvaluatedKey?: Record<string, unknown> | null;
}

export interface ReEncryptionJob {
  status: string;
  processedFiles?: number;
  totalFiles?: number;
  failedFiles?: number;
  startedAt?: string;
  completedAt?: string;
  errors?: string[];
}

export interface ReEncryptionJobStatusResponse {
  job?: ReEncryptionJob | null;
}

export interface PermissionCheckEntry {
  allowed: boolean;
  userId: string;
  action: string;
  path: string;
  matchedRule: {
    id: string;
    pathPattern: string;
    effect: "allow" | "deny";
    priority: number;
  } | null;
  evaluatedRules: Array<{
    id: string;
    pathPattern: string;
    effect: "allow" | "deny";
    actions: string[];
  }>;
  explanation: string;
}

export interface PermissionMutationInput {
  userId?: string;
  role?: string | null;
  pathPattern: string;
  actions: Array<"read" | "write" | "delete" | "admin" | "list">;
  effect: "allow" | "deny";
  priority?: number;
  /** ISO timestamp; when set, the rule auto-expires (timed/time-bound access). */
  expiresAt?: string | null;
  /**
   * When true, POST /permissions updates an existing exact principal/path rule
   * instead of returning a duplicate-rule conflict.
   */
  upsert?: boolean;
}

export interface OrgSettingsResponse {
  orgId: string;
  orgName: string;
  syncMode: "realtime" | "periodic" | "manual";
  syncIntervalMinutes: number;
  enforceEncryption: boolean;
  maxSessionDurationHours: number;
  requireMfa: boolean;
  allowedDomains: string[];
  retentionDays: number;
  autoLockMinutes: number;
  /**
   * When true, per-file deny rules bind admins too (the backend's bypass
   * is opt-in disabled for target-side evaluation and file ops). The
   * plugin UI uses this to decide whether the per-file level dropdown is
   * editable for vault admins/owners — off by default.
   */
  allowAdminPerFileRestrictions?: boolean;
  /**
   * Audit actions the org has opted OUT of recording. The backend's
   * `logAudit` skips writing a row whenever its action appears here. Empty
   * by default (every action logged). Edited via the AuditConfigModal.
   */
  disabledAuditActions?: string[];
}

export interface QueuedRequest {
  id: string;
  method: string;
  path: string;
  body?: unknown;
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  timestamp: number;
  retryCount: number;
}

type ConnectionStatus = "online" | "offline" | "degraded";
type ConnectionListener = (status: ConnectionStatus) => void;
type HttpResponse = RequestUrlResponse;
type TimeoutHandle = number;
type IntervalHandle = number;

// ─── Configuration ──────────────────────────────────────────────────────────

export interface VaultGuardApiConfig {
  baseUrl: string;
  orgId: string;
  /**
   * Server-side vault ID this client is bound to. All file and permission
   * operations route through `/vaults/{vaultId}/...`. Empty until the user
   * picks or creates a server vault for this Obsidian folder.
   */
  vaultId: string;
  maxRetries: number;
  baseRetryDelayMs: number;
  maxRetryDelayMs: number;
  requestTimeoutMs: number;
  offlineQueueMaxSize: number;
  healthCheckIntervalMs: number;
  getAuthTokens?: (forceRefresh?: boolean) => Promise<AuthTokens | null>;
  getSessionId?: () => string | null;
}

const DEFAULT_CONFIG: VaultGuardApiConfig = {
  baseUrl: "",
  orgId: "",
  vaultId: "",
  maxRetries: 3,
  baseRetryDelayMs: 1000,
  maxRetryDelayMs: 30000,
  requestTimeoutMs: 30000,
  offlineQueueMaxSize: 100,
  healthCheckIntervalMs: 30000,
};

// ─── Base64 helpers ─────────────────────────────────────────────────────────
//
// Browser-native base64 over Uint8Array. We deliberately don't use Node's
// `Buffer` here so the plugin runs on Obsidian mobile without relying on a
// Buffer polyfill being present in the renderer.

function uint8ToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(b64: string): ArrayBuffer {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// ─── Agent-bridge context helpers ──────────────────────────────────────────
//
// Defense-in-depth sanitizer for the agent-name / lease-id HTTP headers.
// CR/LF would let a hostile caller inject extra response headers (header
// smuggling); control chars confuse intermediaries. Server also sanitizes
// in `extractAgentHeaders` (infrastructure/lambda/shared/utils.ts). We
// cap at 128 chars so an oversized lease ID can't bloat every request.

// eslint-disable-next-line no-control-regex -- intentionally matches raw control characters (CR/LF/NUL..US/DEL) so they can be stripped from agent header values before they reach the wire
const AGENT_FIELD_FORBIDDEN_RE = /[\r\n\x00-\x1f\x7f]/g;
const AGENT_FIELD_MAX_LENGTH = 128;

function sanitizeAgentField(value: string): string {
  return (value ?? "").replace(AGENT_FIELD_FORBIDDEN_RE, "").slice(0, AGENT_FIELD_MAX_LENGTH);
}

// ─── API Client ─────────────────────────────────────────────────────────────

export class VaultGuardApiClient {
  private config: VaultGuardApiConfig;
  private tokens: AuthTokens | null = null;
  private connectionStatus: ConnectionStatus = "offline";
  private connectionListeners: Set<ConnectionListener> = new Set();
  private offlineQueue: QueuedRequest[] = [];
  private healthCheckTimer: IntervalHandle | null = null;
  private refreshPromise: Promise<AuthTokens | null> | null = null;
  private resolvedBaseUrl: string | null = null;
  private baseUrlResolutionPromise: Promise<string> | null = null;
  // LIFO stack of agent contexts. Pushed by `withAgentContext` on entry,
  // popped on exit (in a `finally` so it's exception-safe). When non-empty,
  // `getAuthHeaders` reads the top entry and appends X-VG-Agent-Name /
  // X-VG-Lease-Id to outbound requests so the server can attribute audit
  // rows to the calling agent. Instance-scoped (not AsyncLocalStorage)
  // because Obsidian's renderer doesn't ship ALS on globalThis and the
  // agent-bridge dispatch is strictly serial per executeTool invocation.
  private agentContextStack: Array<{ agentName: string; leaseId: string }> = [];

  constructor(config: Partial<VaultGuardApiConfig>) {
    this.config = {
      ...DEFAULT_CONFIG,
      ...config,
      baseUrl: normalizeVaultGuardApiBaseUrl(config.baseUrl ?? DEFAULT_CONFIG.baseUrl),
    };
  }

  // ─── Lifecycle ──────────────────────────────────────────────────────

  /**
   * Initialize the client with auth tokens.
   * Sets status to "online" when valid tokens are provided.
   * Does NOT start aggressive health polling — connection status is
   * determined by actual API call success/failure.
   */
  initialize(tokens?: AuthTokens): void {
    if (tokens) {
      this.tokens = tokens;
      this.setConnectionStatus("online");
    }
  }

  /**
   * Tear down the client: stop health checks, clear queue.
   */
  destroy(): void {
    this.stopHealthCheck();
    this.offlineQueue = [];
    this.connectionListeners.clear();
  }

  // ─── Connection Status ──────────────────────────────────────────────

  isConnected(): boolean {
    return this.connectionStatus === "online";
  }

  /** Returns true if the client has auth tokens (user is logged in). */
  isAuthenticated(): boolean {
    return this.tokens !== null;
  }

  getConnectionStatus(): ConnectionStatus {
    return this.connectionStatus;
  }

  onConnectionStatusChange(listener: ConnectionListener): () => void {
    this.connectionListeners.add(listener);
    return () => this.connectionListeners.delete(listener);
  }

  private setConnectionStatus(status: ConnectionStatus): void {
    if (this.connectionStatus !== status) {
      this.connectionStatus = status;
      for (const listener of this.connectionListeners) {
        listener(status);
      }
      // Flush queue when coming back online
      if (status === "online") {
        this.flushOfflineQueue();
      }
    }
  }

  private startHealthCheck(): void {
    this.stopHealthCheck();
    this.healthCheckTimer = window.setInterval(async () => {
      await this.checkHealth();
    }, this.config.healthCheckIntervalMs);
  }

  private stopHealthCheck(): void {
    if (this.healthCheckTimer) {
      window.clearInterval(this.healthCheckTimer);
      this.healthCheckTimer = null;
    }
  }

  private async checkHealth(): Promise<void> {
    try {
      const headers = this.tokens ? await this.getAuthHeaders() : undefined;
      // /vaults always exists post-multi-vault (returns user's vault list).
      // It's authenticated, but it's the cheapest "is the API reachable" probe.
      const response = await this.sendRequest("GET", "/vaults", { headers });

      if (this.isSuccessStatus(response.status)) {
        this.setConnectionStatus("online");
      } else {
        this.setConnectionStatus("degraded");
      }
    } catch (error) {
      if (this.isNetworkError(error)) {
        this.setConnectionStatus("offline");
      } else {
        this.setConnectionStatus("degraded");
      }
    }
  }

  // ─── Auth Methods ───────────────────────────────────────────────────

  async openServerSession(input: ServerSessionRequest = {}): Promise<ServerSessionResponse> {
    const body = input.vaultId ? { vaultId: input.vaultId } : undefined;
    return this.request<ServerSessionResponse>("POST", "/auth/session", body);
  }

  async logout(): Promise<void> {
    try {
      await this.request("POST", "/auth/logout");
    } finally {
      this.tokens = null;
    }
  }

  async refreshTokens(): Promise<AuthTokens> {
    const providedTokens = await this.syncTokensFromProvider(true);
    if (providedTokens) {
      return providedTokens;
    }

    throw new AuthenticationError("Session expired. Please log in again.");
  }

  getTokens(): AuthTokens | null {
    return this.tokens;
  }

  // ─── Vault Binding ──────────────────────────────────────────────────

  /**
   * Returns the path prefix `/vaults/{vaultId}` for vault-scoped routes.
   * Throws if no vault is bound — this is intentional: it prevents the
   * plugin from accidentally talking to an org-wide endpoint that no
   * longer exists post-multi-vault rollout.
   */
  private vaultBase(): string {
    if (!this.config.vaultId) {
      throw new Error(
        'VaultGuard: this Obsidian folder is not bound to a server vault yet. ' +
        'Open the VaultGuard sidebar to pick or create one.'
      );
    }
    return `/vaults/${encodeURIComponent(this.config.vaultId)}`;
  }

  /** Returns the currently bound server vault ID, or empty string if unbound. */
  getVaultId(): string {
    return this.config.vaultId;
  }

  /** Updates the bound vault. Subsequent calls scope to the new vault. */
  setVaultId(vaultId: string): void {
    this.config = { ...this.config, vaultId };
  }

  // ─── Vault Operations ───────────────────────────────────────────────

  async listVaults(): Promise<VaultRecord[]> {
    const response = await this.request<{ vaults: VaultRecord[] }>("GET", "/vaults");
    return response.vaults ?? [];
  }

  async createVault(input: { name: string; description?: string; kind?: VaultKind; defaultRole?: VaultMemberRole; slug?: string }): Promise<VaultRecord> {
    const response = await this.request<{ vault: VaultRecord }>("POST", "/vaults", input);
    return response.vault;
  }

  async getVaultRecord(vaultId: string): Promise<VaultRecord> {
    const response = await this.request<{ vault: VaultRecord }>("GET", `/vaults/${encodeURIComponent(vaultId)}`);
    return response.vault;
  }

  async updateVault(vaultId: string, updates: Partial<VaultRecord>): Promise<VaultRecord> {
    const response = await this.request<{ vault: VaultRecord }>("PATCH", `/vaults/${encodeURIComponent(vaultId)}`, updates);
    return response.vault;
  }

  async archiveVault(vaultId: string): Promise<void> {
    await this.request<void>("DELETE", `/vaults/${encodeURIComponent(vaultId)}`);
  }

  async listVaultMembers(vaultId: string): Promise<VaultMemberRecord[]> {
    const response = await this.request<{ members: VaultMemberRecord[] }>("GET", `/vaults/${encodeURIComponent(vaultId)}/members`);
    return response.members ?? [];
  }

  async addVaultMember(vaultId: string, userId: string, role?: string): Promise<VaultMemberRecord> {
    const response = await this.request<{ membership: VaultMemberRecord }>(
      "POST",
      `/vaults/${encodeURIComponent(vaultId)}/members`,
      { userId, role }
    );
    return response.membership;
  }

  async updateVaultMember(vaultId: string, userId: string, role: string): Promise<VaultMemberRecord> {
    const response = await this.request<{ membership: VaultMemberRecord }>(
      "PATCH",
      `/vaults/${encodeURIComponent(vaultId)}/members/${encodeURIComponent(userId)}`,
      { role }
    );
    return response.membership;
  }

  async removeVaultMember(vaultId: string, userId: string): Promise<void> {
    await this.request<void>(
      "DELETE",
      `/vaults/${encodeURIComponent(vaultId)}/members/${encodeURIComponent(userId)}`
    );
  }

  // ─── File Operations (vault-scoped) ─────────────────────────────────

  async getFiles(folderPath?: string): Promise<FileMetadata[]> {
    const params = folderPath ? `?prefix=${encodeURIComponent(folderPath)}` : "";
    const response = await this.request<{ files: FileMetadata[] }>("GET", `${this.vaultBase()}/files${params}`);
    return response.files ?? [];
  }

  async getFile(path: string): Promise<ArrayBuffer> {
    const response = await this.request<{ content: string }>("GET", `${this.vaultBase()}/files/${encodeURIComponent(path)}`);
    return base64ToArrayBuffer(response.content);
  }

  async putFile(path: string, content: ArrayBuffer, metadata: Partial<FileMetadata>): Promise<FileMetadata> {
    const response = await this.request<FileMetadata>("PUT", `${this.vaultBase()}/files/${encodeURIComponent(path)}`, {
      content: uint8ToBase64(new Uint8Array(content)),
      contentType: metadata.encryptedKey ? "application/octet-stream" : "text/markdown",
    });
    return response;
  }

  async deleteFile(path: string): Promise<void> {
    await this.request<void>("DELETE", `${this.vaultBase()}/files/${encodeURIComponent(path)}`);
  }

  async getFileHistory(path: string): Promise<{ version: string; timestamp: string; userId: string }[]> {
    return this.request("GET", `${this.vaultBase()}/files/${encodeURIComponent(path)}/history`);
  }

  /**
   * Lists soft-deleted files (current S3 head is a delete marker). Admin-only
   * server-side, and per-row filtered to paths the caller can read. Returns
   * the delete-marker version id + deletion timestamp so a file can be restored.
   */
  async getDeletedFiles(): Promise<
    { path: string; deleteMarkerVersionId: string; deletedAt: string }[]
  > {
    const response = await this.request<{
      files: { path: string; deleteMarkerVersionId: string; deletedAt: string }[];
    }>("GET", `${this.vaultBase()}/files/deleted`);
    return response.files ?? [];
  }

  /**
   * Restores a soft-deleted file by removing its current S3 delete marker,
   * re-promoting the prior version. Admin + write-permission gated server-side.
   * The restored file re-appears locally on the next sync pull.
   */
  async restoreDeletedFile(
    path: string
  ): Promise<{ path: string; versionId: string; restoredFrom: string }> {
    return this.request(
      "POST",
      `${this.vaultBase()}/files/${encodeURIComponent(path)}/restore-delete`
    );
  }

  /**
   * Metadata-only vault overview (file/folder counts, total size, largest
   * files, extension breakdown). Never reads object bodies; admin-only.
   */
  async getVaultOverview(): Promise<VaultOverviewResponse> {
    return this.request<VaultOverviewResponse>("GET", `${this.vaultBase()}/overview`);
  }

  // ─── Permission Operations (vault-scoped) ───────────────────────────

  async getPermissions(path?: string): Promise<PermissionRule[]> {
    const params = path ? `?pathFilter=${encodeURIComponent(path)}` : "";
    const response = await this.request<{ rules: PermissionRule[] }>("GET", `${this.vaultBase()}/permissions${params}`);
    return response.rules ?? [];
  }

  async createPermission(rule: PermissionMutationInput): Promise<PermissionRule> {
    const response = await this.request<{ rule: PermissionRule }>("POST", `${this.vaultBase()}/permissions`, rule);
    return response.rule;
  }

  /**
   * Sets a principal's effective level on a path to exactly `level`, letting
   * the server pick the right rule shape (delete / deny-cap / allow). This is
   * the correct primitive for "make user X have level L on file F" — the
   * legacy {@link createPermission} / {@link updatePermission} only work when
   * the caller already knows the principal's INHERITED level (membership +
   * broader rules), which is data the UI doesn't have. See the
   * `handleSetLevel` Lambda for the decision logic.
   *
   * Body schema is dispatched server-side on the same POST /permissions
   * route — when `level` is present the server runs the set-level pipeline;
   * otherwise it runs the legacy create. No new API Gateway resource is
   * required.
   */
  async setPermissionLevel(input: {
    userId?: string;
    role?: string | null;
    pathPattern: string;
    level: "none" | "read" | "write" | "admin";
    priority?: number;
  }): Promise<{
    decision: "create" | "update" | "delete" | "noop";
    level: "none" | "read" | "write" | "admin";
    inheritedLevel: "none" | "read" | "write" | "admin";
    rule: PermissionRule | null;
  }> {
    return this.request<{
      decision: "create" | "update" | "delete" | "noop";
      level: "none" | "read" | "write" | "admin";
      inheritedLevel: "none" | "read" | "write" | "admin";
      rule: PermissionRule | null;
    }>("POST", `${this.vaultBase()}/permissions`, input);
  }

  async updatePermission(id: string, rule: Partial<PermissionMutationInput>): Promise<PermissionRule> {
    const response = await this.request<{ rule: PermissionRule }>("PUT", `${this.vaultBase()}/permissions/${encodeURIComponent(id)}`, rule);
    return response.rule;
  }

  async deletePermission(id: string): Promise<void> {
    await this.request<void>("DELETE", `${this.vaultBase()}/permissions/${encodeURIComponent(id)}`);
  }

  async getUserPermissions(userId: string): Promise<PermissionRule[]> {
    const response = await this.request<{ rules: PermissionRule[] }>("GET", `${this.vaultBase()}/permissions/user/${encodeURIComponent(userId)}`);
    return response.rules ?? [];
  }

  async getPathAccess(path: string): Promise<PathAccessSummary> {
    const response = await this.request<PathAccessSummary>("POST", `${this.vaultBase()}/permissions/access`, {
      path: path.startsWith("/") ? path : `/${path}`,
    });
    return {
      path: response.path,
      currentUserLevel: response.currentUserLevel ?? "none",
      principals: response.principals ?? [],
    };
  }

  /**
   * Batched variant of `getPathAccess`. Pass up to 100 paths in one request;
   * the server returns one summary per unique path in the same order as
   * input. Used by the file-explorer decorator so the sidebar dots/avatars
   * stay aligned with the file header's source of truth.
   */
  async getBatchPathAccess(paths: string[]): Promise<PathAccessSummary[]> {
    if (!Array.isArray(paths) || paths.length === 0) return [];
    const normalized = paths
      .filter((p): p is string => typeof p === "string" && p.trim().length > 0)
      .map((p) => (p.startsWith("/") ? p : `/${p}`));
    if (normalized.length === 0) return [];
    const response = await this.request<{ summaries: PathAccessSummary[] }>(
      "POST",
      `${this.vaultBase()}/permissions/access/batch`,
      { paths: normalized }
    );
    return (response.summaries ?? []).map((summary) => ({
      path: summary.path,
      currentUserLevel: summary.currentUserLevel ?? "none",
      principals: summary.principals ?? [],
    }));
  }

  // ─── Share Link Operations (vault-scoped) ───────────────────────────
  //
  // Mint, list, resolve, or revoke opaque deep-link tokens that route a
  // teammate to a specific file in this vault. Tokens carry no authority
  // on their own — `resolveShare` still requires vault membership, which
  // is what makes share links "internal team only".

  async createShare(input: { relPath: string; expiresAt?: string }): Promise<ShareRecord> {
    const response = await this.request<{ share: ShareRecord; url: string }>(
      "POST",
      `${this.vaultBase()}/shares`,
      input
    );
    // The server attaches `url` next to `share`; flatten so callers get a
    // single object that matches `listShares`.
    return { ...response.share, url: response.url };
  }

  async listShares(): Promise<ShareRecord[]> {
    const response = await this.request<{ shares: ShareRecord[] }>(
      "GET",
      `${this.vaultBase()}/shares`
    );
    return response.shares ?? [];
  }

  async resolveShare(vaultId: string, shareId: string): Promise<ResolvedShare> {
    return this.request<ResolvedShare>(
      "GET",
      `/vaults/${encodeURIComponent(vaultId)}/shares/${encodeURIComponent(shareId)}`
    );
  }

  async revokeShare(shareId: string): Promise<void> {
    await this.request<void>(
      "DELETE",
      `${this.vaultBase()}/shares/${encodeURIComponent(shareId)}`
    );
  }

  // ─── User Operations ────────────────────────────────────────────────

  async listUsers(): Promise<UserListEntry[]> {
    return this.request<UserListEntry[]>("GET", "/users");
  }

  async listRoles(): Promise<RoleEntry[]> {
    return this.request<RoleEntry[]>("GET", "/users/roles");
  }

  async inviteUser(invite: {
    email: string;
    role: string;
    sendWelcomeEmail: boolean;
    givenName?: string;
    familyName?: string;
  }): Promise<void> {
    await this.request<void>("POST", "/users/invite", invite);
  }

  async updateUserRole(userId: string, role: string): Promise<void> {
    await this.request<void>("PUT", `/users/${encodeURIComponent(userId)}/role`, { role });
  }

  async revokeUser(userId: string): Promise<void> {
    await this.request<void>("POST", `/users/${encodeURIComponent(userId)}/revoke`);
  }

  async reactivateUser(userId: string): Promise<void> {
    await this.request<void>("POST", `/users/${encodeURIComponent(userId)}/reactivate`);
  }

  async resendInvitation(userId: string): Promise<void> {
    await this.request<void>("POST", `/users/${encodeURIComponent(userId)}/resend-invite`);
  }

  async updateUserProfile(userId: string, profile: { displayName: string }): Promise<void> {
    await this.request<void>("PUT", `/users/${encodeURIComponent(userId)}/profile`, profile);
  }

  async getUserActivity(userId: string, limit = 50): Promise<UserActivityEntry[]> {
    return this.request<UserActivityEntry[]>("GET", `/users/${encodeURIComponent(userId)}/activity?limit=${limit}`);
  }

  // ─── Audit Log Operations ──────────────────────────────────────────

  async getAuditLogPage(filters: {
    search?: string;
    action?: string;
    path?: string;
    outcome?: AuditLogEntry["outcome"];
    dateFrom?: string;
    dateTo?: string;
    cursor?: string | null;
    limit?: number;
  }): Promise<AuditLogPageResponse> {
    const params = new URLSearchParams();
    if (filters.search) params.set("search", filters.search);
    if (filters.action && filters.action !== "all") params.set("action", filters.action);
    if (filters.path) params.set("path", filters.path);
    if (filters.outcome) params.set("outcome", filters.outcome);
    if (filters.dateFrom) params.set("startDate", filters.dateFrom);
    if (filters.dateTo) params.set("endDate", filters.dateTo);
    if (filters.cursor) params.set("cursor", filters.cursor);
    params.set("limit", String(filters.limit || 50));

    const response = await this.request<AuditLogPageResponse>("GET", `${this.vaultBase()}/audit?${params.toString()}`);
    return {
      entries: response.entries ?? [],
      count: response.count ?? (response.entries?.length ?? 0),
      nextCursor: response.nextCursor ?? null,
      lastEvaluatedKey: response.lastEvaluatedKey ?? null,
    };
  }

  async getAuditLog(filters: {
    search?: string;
    action?: string;
    dateFrom?: string;
    dateTo?: string;
    cursor?: string | null;
    limit?: number;
  }): Promise<AuditLogEntry[]> {
    const response = await this.getAuditLogPage(filters);
    return response.entries;
  }

  async exportAuditLogCsv(filters: {
    search?: string;
    action?: string;
    dateFrom?: string;
    dateTo?: string;
    outcome?: AuditLogEntry["outcome"];
  } = {}): Promise<Blob> {
    const headers = await this.getAuthHeaders();
    const response = await this.sendRequest("POST", `${this.vaultBase()}/audit/export`, {
      headers,
      body: JSON.stringify({
        search: filters.search,
        action: filters.action && filters.action !== "all" ? filters.action : undefined,
        startDate: filters.dateFrom,
        endDate: filters.dateTo,
        outcome: filters.outcome,
        format: "csv",
      }),
      contentType: "application/json",
    });

    if (!this.isSuccessStatus(response.status)) {
      await this.handleErrorResponse(response);
    }

    return new Blob([response.arrayBuffer], {
      type: this.getHeaderValue(response.headers, "content-type") ?? "text/csv",
    });
  }

  // ─── Agent-Bridge Audit ────────────────────────────────────────────
  //
  // The agent-bridge layer wraps every tool invocation in `withAgentContext`
  // so that the standard file/permission audit rows produced by downstream
  // API calls carry the calling agent's identity (via X-VG-Agent-Name and
  // X-VG-Lease-Id headers). For *bridge-lifecycle* events (lease created,
  // session bound, tool invoked, etc.) the plugin posts directly to the
  // dedicated `audit/bridge` endpoint via `postBridgeAudit` below. The
  // server enforces an action allowlist — only `bridge.*` actions are
  // accepted — so this surface can't be used to forge file/auth audit rows.

  /**
   * Runs `fn` with the given agent context pushed onto the LIFO stack.
   * While the stack is non-empty, all outbound requests (auth-bearing or
   * not) carry `X-VG-Agent-Name` and `X-VG-Lease-Id` headers. The stack
   * is restored on exit via a `finally` so thrown errors don't leak the
   * context into a subsequent unrelated request.
   */
  async withAgentContext<T>(
    agentName: string,
    leaseId: string,
    fn: () => Promise<T>
  ): Promise<T> {
    this.agentContextStack.push({
      agentName: sanitizeAgentField(agentName),
      leaseId: sanitizeAgentField(leaseId),
    });
    try {
      return await fn();
    } finally {
      this.agentContextStack.pop();
    }
  }

  /**
   * Emits a single bridge-lifecycle audit row to the backend. Used by the
   * plugin's `emitAuditEvent` helper for events that don't naturally
   * trigger a downstream API call (e.g. `bridge.lease_created`,
   * `bridge.session_bound`). Throws if no vault is bound — callers
   * (`emitAuditEvent` in main.ts) swallow the error so audit emission
   * stays fire-and-forget.
   */
  async postBridgeAudit(
    action: string,
    resourcePath: string | null,
    metadata: Record<string, unknown> = {}
  ): Promise<void> {
    const body = { action, resourcePath, metadata };
    await this.request<void>("POST", `${this.vaultBase()}/audit/bridge`, body);
  }

  // ─── Organization Settings ─────────────────────────────────────────

  async getOrgSettings(): Promise<OrgSettingsResponse> {
    return this.request<OrgSettingsResponse>("GET", `/orgs/${this.config.orgId}/settings`);
  }

  async updateOrgSettings(settings: Partial<OrgSettingsResponse>): Promise<void> {
    await this.request("PUT", `/orgs/${this.config.orgId}/settings`, settings);
  }

  async resetOrgSettings(): Promise<void> {
    await this.request("DELETE", `/orgs/${this.config.orgId}/settings`);
  }

  // ─── Re-encryption & Recovery ────────────────────────────────────────

  async triggerReEncryption(targetUserId: string): Promise<{ jobId: string }> {
    return this.request("POST", "/re-encryption/trigger", { targetUserId });
  }

  async getReEncryptionJobStatus(jobId: string): Promise<ReEncryptionJobStatusResponse> {
    return this.request("GET", `/re-encryption/${jobId}`);
  }

  async recoverUserKey(targetUserId: string): Promise<{ wrappedUMK_org?: string; message?: string }> {
    return this.request("POST", "/auth/recover", { targetUserId });
  }

  // ─── Core Request Methods ──────────────────────────────────────────

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    return this.executeWithRetry<T>(async () => {
      const response = await this.rawRequest<T>(method, path, body);
      return response;
    });
  }

  private async requestBinary(method: string, path: string): Promise<ArrayBuffer> {
    return this.executeWithRetry<ArrayBuffer>(async () => {
      const response = await this.requestRaw(method, path);
      return response.arrayBuffer;
    });
  }

  private async requestFormData<T>(method: string, path: string, body: Record<string, unknown>): Promise<T> {
    return this.executeWithRetry<T>(async () => {
      const headers = await this.getAuthHeaders();
      const response = await this.sendRequest(method, path, {
        headers,
        body: JSON.stringify(body),
        contentType: "application/json",
      });

      if (!this.isSuccessStatus(response.status)) {
        await this.handleErrorResponse(response);
      }

      const data: unknown = response.json;
      return data as T;
    });
  }

  private async requestRaw(method: string, path: string): Promise<RequestUrlResponse> {
    const headers = await this.getAuthHeaders();
    const response = await this.sendRequest(method, path, { headers });

    if (!this.isSuccessStatus(response.status)) {
      await this.handleErrorResponse(response);
    }

    return response;
  }

  private async rawRequest<T>(
    method: string,
    path: string,
    body?: unknown
  ): Promise<T> {
    const headers = await this.getAuthHeaders();

    const response = await this.sendRequest(method, path, {
      headers,
      body: body && method !== "GET" ? JSON.stringify(body) : undefined,
      contentType: body && method !== "GET" ? "application/json" : undefined,
    });

    if (!this.isSuccessStatus(response.status)) {
      await this.handleErrorResponse(response);
    }

    // Handle empty responses (204, etc.)
    const contentLength = this.getHeaderValue(response.headers, "content-length");
    if (response.status === 204 || contentLength === "0" || response.text.length === 0) {
      return undefined as unknown as T;
    }

    return this.parseJsonResponse<T>(response);
  }

  // ─── Auth Header Management ────────────────────────────────────────

  private async getAuthHeaders(): Promise<Record<string, string>> {
    const providedTokens = await this.syncTokensFromProvider(false);
    if (providedTokens) {
      this.tokens = providedTokens;
    }

    if (!this.tokens) {
      throw new Error("Not authenticated. Please log in first.");
    }

    // Check if token is expired or about to expire (within 60s)
    const now = Date.now();
    if (this.tokens.expiresAt - now < 60000) {
      try {
        await this.refreshTokens();
      } catch {
        throw new Error("Session expired. Please log in again.");
      }
    }

    // API Gateway Cognito authorizer expects the raw ID token (no Bearer prefix)
    const headers: Record<string, string> = {
      Authorization: this.tokens.idToken,
    };
    const sessionId = this.config.getSessionId?.();
    if (sessionId) {
      headers["X-VaultGuard-Session-Id"] = sessionId;
    }
    // Agent-bridge attribution: if an agent context is active on the LIFO
    // stack, tag this outbound request with the agent name + lease id so
    // the server-side `logAudit` helper can merge them into the audit row's
    // metadata. Sanitization happens at push time in `withAgentContext`.
    const top = this.agentContextStack[this.agentContextStack.length - 1];
    if (top) {
      headers["X-VG-Agent-Name"] = top.agentName;
      headers["X-VG-Lease-Id"] = top.leaseId;
    }
    return headers;
  }

  private async syncTokensFromProvider(forceRefresh: boolean): Promise<AuthTokens | null> {
    if (!this.config.getAuthTokens) {
      return this.tokens;
    }

    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    const refreshOperation = (async () => {
      const tokens = await this.config.getAuthTokens?.(forceRefresh);
      if (tokens) {
        this.tokens = tokens;
      }
      return tokens ?? null;
    })();

    this.refreshPromise = refreshOperation;

    try {
      return await refreshOperation;
    } finally {
      if (this.refreshPromise === refreshOperation) {
        this.refreshPromise = null;
      }
    }
  }

  // ─── Error Handling ────────────────────────────────────────────────

  private async handleErrorResponse(response: HttpResponse): Promise<never> {
    if (response.status === 0) {
      throw new NetworkError(
        response.text?.trim() || "Network request failed with status 0."
      );
    }

    let errorBody: ApiError;

    try {
      errorBody = await this.parseErrorBody(response);
    } catch (error) {
      const parsedApiError =
        error instanceof VaultGuardError ? error.apiError : undefined;
      errorBody = {
        statusCode: response.status,
        message:
          error instanceof Error
            ? error.message
            : this.getResponseStatusText(response),
        code: parsedApiError?.code ?? "UNKNOWN_ERROR",
        requestId: parsedApiError?.requestId,
      };
    }

    // Handle 401 specifically — attempt token refresh
    if (response.status === 401 && (this.tokens?.refreshToken || this.config.getAuthTokens)) {
      try {
        await this.refreshTokens();
      } catch {
        // Refresh failed — user needs to re-authenticate
        this.tokens = null;
        throw new AuthenticationError("Session expired. Please log in again.");
      }

      // Caller should retry after refresh
      throw new RetryableError(errorBody.message, errorBody);
    }

    // Categorize error
    if (response.status === 403) {
      throw new AuthorizationError(errorBody.message);
    }
    if (response.status === 429) {
      throw new RateLimitError(errorBody.message);
    }
    if (response.status >= 500) {
      throw new ServerError(errorBody.message, errorBody);
    }

    throw new VaultGuardError(errorBody.message, errorBody);
  }

  // ─── Retry Logic ───────────────────────────────────────────────────

  private async executeWithRetry<T>(fn: () => Promise<T>, attempt = 0): Promise<T> {
    try {
      const result = await fn();
      // Successful request means we're online
      this.setConnectionStatus("online");
      return result;
    } catch (error) {
      if (this.isNetworkError(error)) {
        if (attempt < this.config.maxRetries) {
          const delay = this.calculateBackoff(attempt);
          await this.sleep(delay);
          return this.executeWithRetry(fn, attempt + 1);
        }
        this.setConnectionStatus("offline");
        throw new NetworkError("Network unavailable. Request will be retried when connection is restored.");
      }

      // Retryable errors (5xx, rate limits, token refresh)
      if (this.isRetryable(error) && attempt < this.config.maxRetries) {
        const delay = this.calculateBackoff(attempt);
        await this.sleep(delay);
        return this.executeWithRetry(fn, attempt + 1);
      }

      throw error;
    }
  }

  private isRetryable(error: unknown): boolean {
    if (error instanceof RetryableError) return true;
    if (error instanceof RateLimitError) return true;
    if (error instanceof ServerError) return true;
    return false;
  }

  private isNetworkError(error: unknown): boolean {
    // Obsidian's requestUrl can reject with a RequestUrlResponse object (status 0),
    // a plain string, or an Error instance depending on failure mode.
    if (error && typeof error === "object" && "status" in error && (error as { status: number }).status === 0) {
      return true;
    }

    const message = this.extractErrorMessage(error);
    if (!message) return false;

    return (
      message.includes("network") ||
      message.includes("timeout") ||
      message.includes("timed out") ||
      message.includes("econnrefused") ||
      message.includes("econnreset") ||
      message.includes("econnaborted") ||
      message.includes("enotfound") ||
      message.includes("etimedout") ||
      message.includes("eai_again") ||
      message.includes("enetunreach") ||
      message.includes("ehostunreach") ||
      message.includes("ehostdown") ||
      message.includes("err_name_not_resolved") ||
      message.includes("errname") ||
      message.includes("err_internet_disconnected") ||
      message.includes("err_network_changed") ||
      message.includes("connection refused") ||
      message.includes("connection reset") ||
      message.includes("connection closed") ||
      message.includes("socket hang up") ||
      message.includes("failed to fetch") ||
      message.includes("net::err_") ||
      message.includes("abort")
    );
  }

  private extractErrorMessage(error: unknown): string {
    if (error instanceof Error) return error.message.toLowerCase();
    if (typeof error === "string") return error.toLowerCase();
    if (error && typeof error === "object") {
      const obj = error as Record<string, unknown>;
      if (typeof obj.message === "string") return obj.message.toLowerCase();
      if (typeof obj.text === "string") return obj.text.toLowerCase();
    }
    return "";
  }

  private async sendRequest(
    method: string,
    path: string,
    options: {
      headers?: Record<string, string>;
      body?: string;
      contentType?: string;
    } = {}
  ): Promise<RequestUrlResponse> {
    const authToken = options.headers?.Authorization;
    const baseUrl = await this.resolveBaseUrl(authToken);
    const response = await this.sendRequestToBaseUrl(baseUrl, method, path, options);

    if (!authToken || !this.isMisroutedResponse(response)) {
      return response;
    }

    const fallbackBaseUrl = await this.resolveBaseUrl(authToken, path, true);
    if (!fallbackBaseUrl || fallbackBaseUrl === baseUrl) {
      return response;
    }

    return this.sendRequestToBaseUrl(fallbackBaseUrl, method, path, options);
  }

  private async sendRequestToBaseUrl(
    baseUrl: string,
    method: string,
    path: string,
    options: {
      headers?: Record<string, string>;
      body?: string;
      contentType?: string;
    } = {}
  ): Promise<RequestUrlResponse> {
    return this.withTimeout(
      requestUrl({
        url: `${baseUrl}${path}`,
        method,
        headers: options.headers,
        body: options.body,
        contentType: options.contentType,
        throw: false,
      })
    );
  }

  private async resolveBaseUrl(
    authToken?: string,
    probePath?: string,
    forceRefresh = false
  ): Promise<string> {
    const configuredBaseUrl = normalizeVaultGuardApiBaseUrl(this.config.baseUrl);
    if (!configuredBaseUrl) {
      return configuredBaseUrl;
    }

    if (!forceRefresh && this.resolvedBaseUrl) {
      return this.resolvedBaseUrl;
    }

    if (!authToken) {
      return configuredBaseUrl;
    }

    if (!forceRefresh && this.baseUrlResolutionPromise) {
      return await this.baseUrlResolutionPromise;
    }

    const resolutionPromise = resolveVaultGuardApiBaseUrl(
      configuredBaseUrl,
      authToken,
      probePath
    );
    if (!forceRefresh) {
      this.baseUrlResolutionPromise = resolutionPromise;
    }

    try {
      const resolvedBaseUrl = await resolutionPromise;
      this.resolvedBaseUrl = resolvedBaseUrl;
      return resolvedBaseUrl;
    } finally {
      if (!forceRefresh && this.baseUrlResolutionPromise === resolutionPromise) {
        this.baseUrlResolutionPromise = null;
      }
    }
  }

  private isMisroutedResponse(response: HttpResponse): boolean {
    const contentType =
      this.getHeaderValue(response.headers, "content-type")?.toLowerCase() ?? "";
    const text = response.text ?? "";

    return (
      looksLikeAwsSignatureError("", text, contentType) ||
      contentType.includes("text/html") ||
      text.trimStart().startsWith("<!DOCTYPE") ||
      text.trimStart().startsWith("<html")
    );
  }

  private async withTimeout<T>(promise: Promise<T>): Promise<T> {
    let timeoutId: TimeoutHandle | null = null;

    try {
      return await Promise.race([
        promise,
        new Promise<T>((_, reject) => {
          timeoutId = window.setTimeout(() => {
            reject(new Error("Request timeout"));
          }, this.config.requestTimeoutMs);
        }),
      ]);
    } finally {
      if (timeoutId) {
        window.clearTimeout(timeoutId);
      }
    }
  }

  private async parseErrorBody(response: HttpResponse): Promise<ApiError> {
    if (!response.text || response.text.length === 0) {
      throw new Error("Empty response body");
    }

    return this.parseJsonResponse<ApiError>(response);
  }

  /**
   * Safely parse a response as JSON, guarding against HTML or other
   * non-JSON bodies that would otherwise surface cryptic parse errors
   * like "Unexpected token '<', \"<!DOCTYPE \"... is not valid JSON".
   */
  private parseJsonResponse<T>(response: HttpResponse): T {
    const contentType =
      this.getHeaderValue(response.headers, "content-type")?.toLowerCase() ?? "";
    const text = response.text ?? "";

    if (looksLikeAwsSignatureError("", text, contentType)) {
      throw new VaultGuardError(
        "The API endpoint appears to be pointing at a website or routed page instead of the VaultGuard REST API. " +
          "Check the API endpoint in plugin settings. If you pasted a URL ending in /settings, /users, or /orgs/..., " +
          "keep only the API or CloudFront base URL.",
        {
          statusCode: response.status,
          message: "Misrouted API request",
          code: "MISROUTED_API_REQUEST",
        }
      );
    }

    // Detect HTML responses (DOCTYPE, tags, or explicit content-type)
    if (
      contentType.includes("text/html") ||
      text.trimStart().startsWith("<!DOCTYPE") ||
      text.trimStart().startsWith("<html")
    ) {
      throw new VaultGuardError(
        "The API endpoint returned an HTML page instead of JSON. " +
          "Check that the API Endpoint in plugin settings points to the VaultGuard REST API " +
          "(e.g. a CloudFront base URL like https://d1234567890.cloudfront.net or your direct API URL), " +
          "not a website or admin panel URL.",
        {
          statusCode: response.status,
          message: "Non-JSON response from API",
          code: "HTML_RESPONSE",
        }
      );
    }

    try {
      const data: unknown = response.json;
      return data as T;
    } catch {
      throw new VaultGuardError(
        `The API returned an unexpected response (not valid JSON). Status: ${response.status}`,
        {
          statusCode: response.status,
          message: "Invalid JSON in API response",
          code: "INVALID_JSON",
        }
      );
    }
  }

  private getResponseStatusText(response: HttpResponse): string {
    return response.text || "Unknown error";
  }

  private getHeaderValue(
    headers: Record<string, string>,
    name: string
  ): string | null {

    const matchedEntry = Object.entries(headers).find(
      ([headerName]) => headerName.toLowerCase() === name.toLowerCase()
    );
    return matchedEntry?.[1] ?? null;
  }

  private isSuccessStatus(status: number): boolean {
    return status >= 200 && status < 300;
  }

  private calculateBackoff(attempt: number): number {
    // Exponential backoff with jitter
    const baseDelay = this.config.baseRetryDelayMs * Math.pow(2, attempt);
    const jitter = this.secureRandomFraction() * baseDelay * 0.1;
    return Math.min(baseDelay + jitter, this.config.maxRetryDelayMs);
  }

  private secureRandomFraction(): number {
    const bytes = crypto.getRandomValues(new Uint32Array(1));
    return bytes[0] / 0xffffffff;
  }

  private sleep(ms: number): Promise<void> {
    // Bare setTimeout — the API client is deliberately node-safe (no browser
    // globals; see the Networking Rule) so it works in tests and any host.
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  // ─── Offline Queue ─────────────────────────────────────────────────

  /**
   * Queue a request for execution when the connection is restored.
   */
  queueRequest(method: string, path: string, body?: unknown): Promise<unknown> {
    return new Promise((resolve, reject) => {
      if (this.offlineQueue.length >= this.config.offlineQueueMaxSize) {
        reject(new Error("Offline queue is full. Please try again when connection is restored."));
        return;
      }

      const request: QueuedRequest = {
        id: this.generateRequestId(),
        method,
        path,
        body,
        resolve,
        reject,
        timestamp: Date.now(),
        retryCount: 0,
      };

      this.offlineQueue.push(request);
    });
  }

  /**
   * Get current queue size for UI display.
   */
  getQueueSize(): number {
    return this.offlineQueue.length;
  }

  /**
   * Process all queued requests when coming back online.
   */
  private async flushOfflineQueue(): Promise<void> {
    const queue = [...this.offlineQueue];
    this.offlineQueue = [];

    for (const request of queue) {
      try {
        const result = await this.request(request.method, request.path, request.body);
        request.resolve(result);
      } catch (error) {
        if (this.connectionStatus === "offline") {
          // Back offline — re-queue remaining
          this.offlineQueue.push(request, ...queue.slice(queue.indexOf(request) + 1));
          break;
        }
        request.reject(error as Error);
      }
    }
  }

  private generateRequestId(): string {
    if (typeof crypto.randomUUID === "function") {
      return `req_${crypto.randomUUID()}`;
    }
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    return `req_${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
  }
}

// ─── Custom Error Classes ───────────────────────────────────────────────────

export class VaultGuardError extends Error {
  public apiError?: ApiError;

  constructor(message: string, apiError?: ApiError) {
    super(message);
    this.name = "VaultGuardError";
    this.apiError = apiError;
  }
}

export class AuthenticationError extends VaultGuardError {
  constructor(message: string) {
    super(message);
    this.name = "AuthenticationError";
  }
}

export class AuthorizationError extends VaultGuardError {
  constructor(message: string) {
    super(message);
    this.name = "AuthorizationError";
  }
}

export class RetryableError extends VaultGuardError {
  constructor(message: string, apiError?: ApiError) {
    super(message, apiError);
    this.name = "RetryableError";
  }
}

export class RateLimitError extends VaultGuardError {
  constructor(message: string) {
    super(message);
    this.name = "RateLimitError";
  }
}

export class ServerError extends VaultGuardError {
  constructor(message: string, apiError?: ApiError) {
    super(message, apiError);
    this.name = "ServerError";
  }
}

export class NetworkError extends VaultGuardError {
  constructor(message: string) {
    super(message);
    this.name = "NetworkError";
  }
}
