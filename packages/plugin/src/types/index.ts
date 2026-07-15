/**
 * @fileoverview Core type definitions for the VaultGuard plugin.
 * Defines all interfaces, enums, and types used across the permission-aware
 * encrypted cloud sync system.
 */

// ─────────────────────────────────────────────────────────────────────────────
// Permission System
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Permission levels in ascending order of privilege.
 * Each level includes all capabilities of lower levels.
 */
export enum PermissionLevel {
  /** No access - file is hidden from the user */
  NONE = 0,
  /** Read-only access - can view but not modify */
  READ = 1,
  /** Read and write access - can view and modify */
  WRITE = 2,
  /** Full administrative access - can manage permissions for others */
  ADMIN = 3,
}

/**
 * Represents a single permission grant for a file or folder path.
 * Permissions are evaluated hierarchically (folder permissions cascade to children).
 */
export interface Permission {
  /** The vault-relative path this permission applies to (supports glob patterns) */
  path: string;
  /** The principal (user ID or group ID) this permission is granted to */
  principal: string;
  /** The level of access granted */
  level: PermissionLevel;
  /** User ID of the admin who granted this permission */
  grantedBy: string;
  /** ISO 8601 timestamp when permission was granted */
  grantedAt: string;
  /** Optional ISO 8601 expiration timestamp; null means permanent */
  expiresAt: string | null;
  /** Whether this permission applies recursively to subdirectories */
  recursive: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// File Metadata
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Metadata about a single file in the vault, including its sync state
 * and effective permissions for the current user.
 */
export interface FileMetadata {
  /** Vault-relative file path */
  path: string;
  /** SHA-256 content hash for integrity verification */
  hash: string;
  /** File size in bytes */
  size: number;
  /** ISO 8601 timestamp of last modification */
  lastModified: string;
  /** The effective permission level for the current user on this file */
  permissions: PermissionLevel;
  /** Server-assigned version number for conflict detection */
  version: number;
  /** Whether the file is encrypted at rest on the server */
  encrypted: boolean;
  /** MIME type of the file content */
  mimeType: string;
  /** S3/object version identifier returned by the server when available */
  versionId?: string;
  /** Backend checksum/ETag when available */
  checksum?: string;
  /** MIME type as returned by newer file APIs */
  contentType?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Sync System
// ─────────────────────────────────────────────────────────────────────────────

/** Possible states of the sync engine */
export type SyncStatus = "idle" | "syncing" | "error" | "offline" | "paused";

/**
 * Represents the current synchronization state of the plugin.
 * Tracks pending changes, last successful sync, and any conflicts.
 */
export interface SyncState {
  /** ISO 8601 timestamp of last successful sync operation */
  lastSync: string | null;
  /** Number of local changes pending upload */
  pendingChanges: number;
  /** List of unresolved sync conflicts */
  conflicts: SyncConflict[];
  /** Current sync engine status */
  status: SyncStatus;
  /** Bytes uploaded in the current/last sync cycle */
  bytesUploaded: number;
  /** Bytes downloaded in the current/last sync cycle */
  bytesDownloaded: number;
  /** Error message if status is 'error', null otherwise */
  lastError: string | null;
  /**
   * Last vault revision number observed from the server's sync-cursor or
   * sync response. Null until the first cursor read. Used by the polling
   * loop to skip the heavy `/files/sync` call when nothing has changed.
   */
  lastSeenRevision?: number | null;
  /**
   * Wall-clock timestamp (ms since epoch) of the most recent server-side
   * change observed by this client. Drives the adaptive polling cadence —
   * recent activity tightens the loop, idle stretches relax it.
   */
  lastObservedActivityAt?: number | null;
}

/**
 * Strategies for resolving sync conflicts between local and remote versions.
 */
export enum ConflictResolutionStrategy {
  /** Keep the local version, discard remote changes */
  KEEP_LOCAL = "keep_local",
  /** Keep the remote version, discard local changes */
  KEEP_REMOTE = "keep_remote",
  /** Create a duplicate file with conflict suffix */
  DUPLICATE = "duplicate",
  /** Defer resolution to the user via UI prompt */
  ASK_USER = "ask_user",
}

/**
 * Represents a sync conflict between local and remote file versions.
 * Occurs when both sides have been modified since last sync.
 */
export interface SyncConflict {
  /** Vault-relative path of the conflicted file */
  path: string;
  /** Hash of the local version */
  localHash: string;
  /** Hash of the remote version */
  remoteHash: string;
  /** Hash of the common ancestor version (for three-way merge) */
  baseHash: string | null;
  /** ISO 8601 timestamp when the conflict was detected */
  detectedAt: string;
  /** The resolution strategy applied, or null if unresolved */
  resolution: ConflictResolutionStrategy | null;
  /** ISO 8601 timestamp of local modification */
  localModified: string;
  /** ISO 8601 timestamp of remote modification */
  remoteModified: string;
  /** True when the remote side of the conflict is a deletion/tombstone */
  remoteDeleted?: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// Encryption & Key Management
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Represents a time-limited encryption key lease from the server.
 * Keys are leased (not permanently stored) to enable revocation
 * and enforce offline time limits.
 */
export interface KeyLease {
  /** The AES-256-GCM encryption key (base64-encoded) used by the plugin */
  key: string;
  /** ISO 8601 timestamp when this lease expires */
  expiresAt: string;
  /** Token used to request a lease renewal before expiry */
  refreshToken: string;
  /** Unique identifier for this key lease (for audit trail) */
  leaseId: string;
  /** Active vault data-key identifier used to bind direct transfers to the lease. */
  keyId?: string;
  /** The key derivation algorithm used */
  algorithm: "AES-256-GCM";
  /** Whether this lease permits offline use */
  offlineCapable: boolean;
  /** Optional encrypted copy retained for backend audit / future rotation flows */
  encryptedDataKey?: string;
  /** Path scope this lease is bound to (glob pattern). '/**' means full vault access. */
  scope: string;
  /** Server vault this lease is bound to. Omitted only for legacy leases. */
  vaultId?: string;
  /** Live read-deny carve-outs returned with a broad lease. */
  deniedPaths?: Array<{ pathPattern: string; ruleId: string }>;
}

/** Supported encryption strength levels for local cache */
export type CacheEncryptionStrength = "standard" | "high" | "maximum";

// ─────────────────────────────────────────────────────────────────────────────
// Authentication & Sessions
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Represents an authenticated user session with the VaultGuard backend.
 */
export interface UserSession {
  /** Server-side VaultGuard session identifier used for key leases and logout */
  sessionId: string;
  /** Unique user identifier */
  userId: string;
  /** Organization/workspace the user belongs to */
  organizationId: string;
  /** Display name for UI */
  displayName: string;
  /** User's email address */
  email: string;
  /** JWT access token for API calls */
  accessToken: string;
  /** JWT ID token for API Gateway Cognito authorizer */
  idToken: string;
  /** Refresh token for obtaining new access tokens */
  refreshToken: string;
  /** ISO 8601 timestamp when the access token expires */
  tokenExpiresAt: string;
  /** The user's global role within the organization */
  role: "member" | "editor" | "admin" | "owner";
  /** Raw backend roles / groups used for permission evaluation */
  roles: string[];
  /** ISO 8601 timestamp of session creation */
  createdAt: string;
  /**
   * Wave 2 issue A (1.0.31): last-known per-vault role for this user
   * on `serverVaultId`, stamped at `persistSession` time. Restored
   * before the initial `runPermissionWarmup` fires so the warm-up
   * doesn't synthesize a fallback from `session.role` while the real
   * value is still null (pre-fix race). The server-confirmed value
   * still overwrites this on `refreshVaultMemberRole`; this field is
   * a best-effort prior, not a source of truth.
   */
  vaultMemberRole?: "admin" | "editor" | "viewer" | null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit System
// ─────────────────────────────────────────────────────────────────────────────

/** All auditable actions in the system */
export type AuditAction =
  | "file.read"
  | "file.write"
  | "file.delete"
  | "file.create"
  | "file.rename"
  | "permission.grant"
  | "permission.revoke"
  | "permission.modify"
  | "auth.login"
  | "auth.logout"
  | "auth.token_refresh"
  | "auth.failed_attempt"
  | "sync.started"
  | "sync.completed"
  | "sync.conflict"
  | "sync.error"
  | "key.leased"
  | "key.renewed"
  | "key.expired"
  | "admin.settings_changed"
  | "admin.user_invited"
  | "admin.user_removed"
  | "excluded.purge"
  | "plugin.allowlist_install"
  | "plugin.allowlist_skip"
  | "bridge.lease_created"
  | "bridge.lease_revoked"
  | "bridge.lease_token_rotated"
  | "bridge.tool_invoked"
  | "bridge.session_bound"
  | "bridge.session_unbound"
  | "bridge.import_session_started"
  | "bridge.import_session_ended"
  | "bridge.skill_installed"
  | "bridge.skill_uninstalled";

/**
 * Represents an audit log entry for compliance and security tracking.
 * All sensitive operations generate audit events sent to the backend.
 */
export interface AuditEvent {
  /** Unique event identifier (UUID v4) */
  eventId: string;
  /** ISO 8601 timestamp of the event */
  timestamp: string;
  /** The user who performed the action */
  userId: string;
  /** The server vault this event belongs to, when vault-scoped */
  vaultId?: string;
  /** The action that was performed */
  action: AuditAction;
  /** The resource path affected (if applicable) */
  resourcePath: string | null;
  /** Additional context about the event */
  metadata: Record<string, unknown>;
  /** Client IP address at time of event */
  ipAddress: string | null;
  /** Device/client identifier */
  deviceId: string;
  /** Whether the action was permitted or denied */
  outcome: "success" | "denied" | "error";
}

// ─────────────────────────────────────────────────────────────────────────────
// Plugin Settings
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Complete settings interface for the VaultGuard plugin.
 * Persisted to Obsidian's plugin data store.
 */
/**
 * Edition advertised by the connected backend. Drives which UI surfaces the
 * plugin renders.
 *
 * - 'pro'       — managed SaaS or paid self-host. Full feature set.
 * - 'community' — open-source self-host. Share links, advanced audit, and
 *                 billing surfaces are unavailable and must be hidden.
 */
export type ServerEdition = 'community' | 'pro';

/**
 * Capability flags advertised by `GET /orgs/{slug}/config`. Used by the plugin
 * to hide UI surfaces the backend won't serve. Unknown / null means "treat as
 * Pro" — the historic default, since most existing installs talk to the
 * managed SaaS.
 */
export interface ServerFeatures {
  /** Share-link tokens + share-bridge SPA. */
  shareLinks: boolean;
  /** Advanced audit dashboards/alerts/exports. */
  advancedAudit: boolean;
  /** Stripe billing surface (checkout, portal, subscription). */
  billing: boolean;
  /** Hosted admin.example.com SPA — info only; plugin does not link to it on CE. */
  webAdmin: boolean;
}

/** Conservative default when the server has not yet advertised capabilities. */
export const ASSUMED_SERVER_FEATURES: ServerFeatures = {
  shareLinks:    true,
  advancedAudit: true,
  billing:       true,
  webAdmin:      true,
};

export type PermissionsGraphRenderMode = "auto" | "aggregated" | "detailed";
export type PermissionsGraphLayoutMode = "auto" | "radial" | "force" | "grid" | "folder" | "sections";
export type PermissionsGraphLabelsMode = "auto" | "on" | "off";
export type PermissionsGraphSearchScope = "all" | "user" | "file" | "folder";
export type PermissionsGraphBackgroundMode = "theme" | "solid" | "gradient";
export type PermissionsGraphBackgroundPattern = "none" | "grid" | "dots";
export type PermissionsGraphColorMode = "current" | "type" | "folder" | "access" | "connections";
export type PermissionsGraphSizeMode = "standard" | "uniform" | "connections" | "access";
export type PermissionsGraphSectionMode = "folder" | "type" | "access" | "connections";
export type PermissionsGraphSortMode = "name" | "path" | "access" | "connections";
export type PermissionsGraphSortDirection = "asc" | "desc";

export interface PermissionsGraphStudioPalette {
  user?: string;
  file?: string;
  folder?: string;
  read?: string;
  write?: string;
  admin?: string;
  low?: string;
  medium?: string;
  high?: string;
}

export interface PermissionsGraphStudioAppearance {
  backgroundMode?: PermissionsGraphBackgroundMode;
  backgroundPattern?: PermissionsGraphBackgroundPattern;
  backgroundPrimary?: string;
  backgroundSecondary?: string;
  colorMode?: PermissionsGraphColorMode;
  customPalette?: boolean;
  palette?: PermissionsGraphStudioPalette;
  sizeMode?: PermissionsGraphSizeMode;
  nodeScale?: number;
  edgeScale?: number;
  labelScale?: number;
}

export interface PermissionsGraphStudioArrangement {
  sectionBy?: PermissionsGraphSectionMode;
  sortBy?: PermissionsGraphSortMode;
  sortDirection?: PermissionsGraphSortDirection;
}

export interface PermissionsGraphSavedState {
  schemaVersion?: 1 | 2;
  renderMode?: PermissionsGraphRenderMode;
  layoutMode?: PermissionsGraphLayoutMode;
  labelsMode?: PermissionsGraphLabelsMode;
  pathPrefix?: string;
  searchQuery?: string;
  searchScope?: PermissionsGraphSearchScope;
  selectedUsers?: string[];
  accessLevels?: {
    read?: boolean;
    write?: boolean;
    admin?: boolean;
  };
  nodeTypes?: {
    users?: boolean;
    files?: boolean;
    folders?: boolean;
  };
  expiringOnly?: boolean;
  writableAdminOnly?: boolean;
  explicitRulesOnly?: boolean;
  maxFiles?: number;
  maxEdges?: number;
  depth?: number;
  debugExpanded?: boolean;
  appearance?: PermissionsGraphStudioAppearance;
  arrangement?: PermissionsGraphStudioArrangement;
  updatedAt?: string;
}

export type PendingLargeFileReason =
  | "offline"
  | "manual-sync"
  | "lease-unavailable"
  | "upload-failed"
  | "finalize-failed"
  | "conflict";

export type PendingLargeFileState = "pending" | "uploading" | "retryable" | "blocked";

/**
 * Metadata-only retry state for a large file that cannot use the bounded
 * JSON/offline queue. Never add plaintext, ciphertext, presigned URLs, or key
 * material to this record.
 */
export interface PendingLargeFileRecord {
  path: string;
  previousPath?: string;
  size: number;
  sha256: string;
  contentType: string;
  reason: PendingLargeFileReason;
  state: PendingLargeFileState;
  localProtection: "plaintext-pending" | "encrypted-recoverable";
  attempts: number;
  updatedAt: string;
}

/** Advanced modules that are opt-in for fresh installs. */
export type OptionalModuleId =
  | "aiChat"
  | "permissionsGraph"
  | "agentAccess"
  | "secureDiscovery";

/** Versioned optional-module preferences persisted in plugin data. */
export interface OptionalModulePreferences {
  schemaVersion: 2;
  aiChat: boolean;
  permissionsGraph: boolean;
  agentAccess: boolean;
  /** Permission-aware Bases, CLI, and secure search surfaces. Always opt-in. */
  secureDiscovery: boolean;
}

/** Observable local semantic-index lifecycle state. */
export type SemanticIndexState =
  | "absent"
  | "loading"
  | "ready"
  | "stale"
  | "building"
  | "failed";

/** Provider-key storage boundary selected explicitly by the user. */
export type ProviderKeyStorageMode = "vaultguard" | "obsidian";

export interface VaultGuardSettings {
  /**
   * Per-vault UUID used only as a fallback binding ID when the runtime
   * cannot supply a fingerprint (vault basePath / appId / name). On normal
   * desktop Obsidian we hash the fingerprint instead and this field stays
   * unset. Lazily generated by `computeDerivedVaultBindingId` on first
   * use in fallback hosts.
   */
  vaultBindingId?: string;
  /**
   * Server-side Vault entity bound to this Obsidian local vault.
   *
   * VaultGuard now models vaults as first-class server-side entities (an
   * org can have many). This local Obsidian folder syncs to exactly one
   * server vault — its UUID is stored here. Empty until the user picks or
   * creates a vault during first connection.
   */
  serverVaultId: string;
  /** Display name of the server-side vault, cached for UX. */
  serverVaultName?: string;
  /** Slug of the server-side vault, cached for UX. */
  serverVaultSlug?: string;
  /** Organization slug for SaaS auto-config (e.g., "acme-corp") */
  orgSlug: string;
  /** Base URL for the VaultGuard API backend (auto-filled from org config or manual) */
  apiEndpoint: string;
  /** Organization identifier for multi-tenant routing (auto-filled from org config) */
  organizationId: string;
  /** Cognito User Pool ID (auto-filled from org config or manual) */
  cognitoUserPoolId: string;
  /** Cognito App Client ID (auto-filled from org config or manual) */
  cognitoClientId: string;
  /**
   * Last backend edition advertised by `GET /orgs/{slug}/config`.
   * Persisted so Community Edition UI gating survives plugin restarts.
   */
  serverEdition?: ServerEdition;
  /**
   * Last backend capability flags advertised by `GET /orgs/{slug}/config`.
   * Persisted so manual self-hosted configuration does not fall back to Pro UI.
   */
  serverFeatures?: ServerFeatures;
  /** ISO timestamp of the last successful backend capability discovery. */
  serverFeaturesResolvedAt?: string;
  /** Sync interval in seconds (minimum 10, default 30) */
  syncInterval: number;
  /** Encryption strength for local file cache */
  cacheEncryptionStrength: CacheEncryptionStrength;
  /** Hours before offline key lease expires (default 24) */
  offlineKeyLeaseDuration: number;
  /** Whether to wipe local cache on authentication failure */
  autoWipeOnAuthFailure: boolean;
  /**
   * @deprecated Legacy single "show permission indicators" toggle. Split into
   * the three granular toggles below (`showMyPermissionLevel`,
   * `showOthersAccess`, `showPermissionBanner`). Retained as optional so
   * persisted `data.json` that predates the split still type-checks and the
   * one-time migration in `loadSettings()` can consume it. No live code reads
   * this field except that migration's raw-`data` read.
   */
  showPermissionIndicators?: boolean;
  /** Show a colored dot for the current user's own access level in the file explorer. */
  showMyPermissionLevel: boolean;
  /** Show avatar chips for other principals' access next to a file in the file explorer. */
  showOthersAccess: boolean;
  /** Show the per-note permission banner at the top of open notes. */
  showPermissionBanner: boolean;
  /** Default conflict resolution strategy */
  defaultConflictResolution: ConflictResolutionStrategy;
  /** Enable detailed debug logging */
  debugLogging: boolean;
  /** Maximum number of retry attempts for failed API calls */
  maxRetryAttempts: number;
  /** Whether to show sync status in the status bar */
  showStatusBar: boolean;
  /**
   * Whether the dedicated AI-chat + permissions-graph quick-access ribbon icons
   * are shown. Defaults to true; the VaultGuard menu (shield) icon is always shown.
   */
  showRibbonIcons: boolean;
  /**
   * Plaintext repo-root mode for using an Obsidian vault as local project
   * memory. Disables local at-rest encryption, sync, sharing, and org/team
   * management surfaces while leaving local navigation and agent-context
   * workflows available.
   */
  localProjectMemoryMode: boolean;
  /**
   * Mainstream installs start with advanced modules off. A one-time migration
   * enables them for established installs that predate this preference.
   */
  optionalModules: OptionalModulePreferences;
  /** Second consent inside Secure Discovery; never enabled by migration. */
  semanticSearchEnabled: boolean;
  /** Non-secret loopback embedding origin. Runtime validation remains fail-closed. */
  semanticEmbeddingEndpoint: string;
  /** Non-secret local embedding model identifier. */
  semanticEmbeddingModel: string;
  /** Default bounded result count shared by the view and CLI. */
  discoveryResultLimit: number;
  /** Whether to use manual connection configuration instead of org slug auto-config */
  manualConfig?: boolean;
  /**
   * True once the user has dismissed the "encrypt remaining plaintext files"
   * Notice. Prevents the first-run nudge from re-firing on every plugin
   * load. Resetting this in settings is not exposed — the user can always
   * re-run the encrypt-vault command from the at-rest panel anyway.
   */
  atRestFirstRunDismissed?: boolean;
  /**
   * The serverVaultId for which the local-folder ↔ server-vault first-sync
   * reconciliation has been completed. When this matches the current
   * `serverVaultId`, the plugin skips reconciliation; when it differs (e.g.
   * after re-binding to a different vault), reconciliation runs again.
   */
  bindingReconciledVaultId?: string;
  /**
   * Persisted ISO timestamp of the most recent successful sync. Survives
   * plugin reloads so that a fresh process does not pull every file from the
   * server (and silently overwrite local edits) on every startup.
   */
  lastSyncTimestamp?: string;
  /**
   * Path-only deletion tombstones (vault-relative normalized path -> ISO
   * deletedAt). Records that a local delete was initiated so it can be
   * re-attempted on the server after a restart or transient-offline window,
   * and so initial reconciliation does not resurrect a locally-deleted file.
   * CONTAINS NO FILE CONTENT — never store the offline queue (which carries
   * plaintext write payloads) here.
   */
  deletionTombstones?: Record<string, string>;
  /**
   * Metadata-only large-file retry ledger, keyed by normalized vault-relative
   * path. Bodies stay in the vault and never enter plugin settings.
   */
  pendingLargeFiles?: Record<string, PendingLargeFileRecord>;
  /**
   * Local-only opt-out list. Files whose vault-relative path matches any
   * entry are kept off the sync wire entirely: never uploaded, never pulled
   * from the server, never deleted remotely. Each entry is either an exact
   * vault-relative path (e.g. `.obsidian/workspace.json`) or a folder
   * prefix (e.g. `.obsidian/plugins`) — anything under the prefix is
   * excluded. This is a per-device setting; other members of the same
   * vault are unaffected.
   */
  excludedPaths?: string[];
  /**
   * Server-side vault exclusion policy, cached from the most recent vault
   * record fetch. Layered with `excludedPaths` (union) by `isPathExcluded`.
   * Members cannot edit this from the plugin — it is set by the vault admin
   * via the admin panel.
   */
  serverExcludedPaths?: string[];
  /**
   * Server-side curated plugin allowlist, cached from the most recent vault
   * record fetch. Triggers the consent prompt for plugin auto-install.
   */
  serverPluginAllowlist?: Array<{
    pluginId: string;
    displayName: string;
    version?: string;
    bundleSha256?: string;
    addedAt: string;
    addedBy: string;
    note?: string;
  }>;
  /**
   * Plugin IDs the user has explicitly skipped or chosen to ignore on this
   * device. Prevents the consent modal from re-firing every sync.
   */
  pluginAllowlistIgnored?: string[];
  /** @deprecated Update discovery is native/manual-only; retained for data compatibility. */
  disableUpdateChecks?: boolean;
  /**
   * Global defaults for the Permissions Graph options panel. These are UI
   * preferences only; they never store permission payloads or graph elements.
   */
  permissionsGraphDefaults?: PermissionsGraphSavedState;
  /**
   * Per-server-vault graph filters/options. Bounded and tolerant-parsed by the
   * graph view so old, partial, or stale values never break startup.
   */
  permissionsGraphVaultStates?: Record<string, PermissionsGraphSavedState>;
  /**
   * Persisted state of the update checker so the 24 h throttle and
   * already-notified-version suppression survive plugin reloads.
   */
  updateCheckState?: {
    lastCheckedAt: number;
    lastSeenVersion: string;
  };
  /**
   * Anthropic API key for the AI Chat panel, stored as a method-tagged,
   * base64-encoded encrypted envelope (never plaintext). Written and read
   * exclusively through `AnthropicKeyStore` (src/ui/chat/api-key-store.ts):
   * "ss:" = OS-keychain safeStorage, "ar:" = local AtRestCipher fallback.
   */
  encryptedAnthropicKey?: string;
  /** Explicit storage boundary for the Anthropic provider key. */
  anthropicKeyStorageMode?: ProviderKeyStorageMode;
  /** Named Obsidian secret reference; never the secret value. */
  anthropicSecretId?: string;
  /**
   * OpenAI API key for the AI Chat panel, stored as a method-tagged,
   * base64-encoded encrypted envelope (never plaintext). Written and read
   * exclusively through `OpenAiKeyStore` (src/ui/chat/api-key-store.ts):
   * "ss:" = OS-keychain safeStorage, "ar:" = local AtRestCipher fallback.
   */
  encryptedOpenAiKey?: string;
  /** Explicit storage boundary for the OpenAI provider key. */
  openAiKeyStorageMode?: ProviderKeyStorageMode;
  /** Named Obsidian secret reference; never the secret value. */
  openAiSecretId?: string;
  /** Anthropic model id for the AI Chat panel (default "claude-opus-4-8"). */
  aiChatModel: string;
  /** Adaptive-thinking effort level for AI Chat turns (default "high"). */
  aiChatEffort: AnthropicEffort;
  /** OpenAI Responses API model id for the AI Chat panel (default "gpt-5.5"). */
  openAiModel: string;
  /** Reasoning effort for OpenAI Responses API turns (default "medium"). */
  openAiReasoningEffort: OpenAiReasoningEffort;
  /** Text verbosity for OpenAI Responses API turns (default "medium"). */
  openAiVerbosity: OpenAiVerbosity;
  /** Max output tokens for OpenAI Responses API turns (default 8192). */
  openAiMaxOutputTokens: number;
  /**
   * Whether to stream AI Chat responses token-by-token (Tier 2). Default true;
   * desktop-only (mobile always falls back to the non-streaming requestUrl path).
   */
  aiChatStreaming: boolean;
  /**
   * Whether to store an ENCRYPTED (DEK-wrapped) copy of the Anthropic API key
   * in VaultGuard Cloud so it auto-provisions on the user's other devices
   * (e.g. mobile) without re-entry. Default true. The plaintext key is never
   * sent to the server — only an opaque, vault-DEK-wrapped envelope.
   */
  aiChatKeySyncEnabled: boolean;
  /**
   * AI Chat action permission mode.
   * - "confirm": default/recommended; writes and deletes show the in-app diff
   *   confirmation modal before touching disk.
   * - "skip": mint the ephemeral chat lease with writeMode "allow", so writes
   *   proceed without per-action prompts while still enforcing vault scope,
   *   exclusions, and the user's server-side file permissions.
   */
  aiChatPermissionMode: AiChatPermissionMode;
  /**
   * Which AI Chat transport to use:
   *   "subscription" — drive the official Claude Code CLI with the user's own
   *      Claude Pro/Max login (desktop only; the plugin never touches the
   *      subscription token). Vault access stays MCP-only via AgentBridge.
   *   "apiKey" — call the Anthropic Messages API with the user's stored key.
   *   "openai" — call the OpenAI Responses API with the user's stored key.
   *   "codex" — drive the official local Codex client with the user's ChatGPT
   *      subscription login (desktop only; no OpenAI API key). Vault access is
   *      limited to the dedicated VaultGuard loopback MCP chat lease.
   * Defaults to "apiKey". The user's explicit choice is persisted.
   */
  aiChatProvider: AiChatProvider;
  /**
   * True once the user has explicitly picked an AI provider. Provider
   * detection is user-triggered and never silently changes this setting.
   */
  aiChatProviderExplicit?: boolean;
  /**
   * Optional user-authored instructions appended to the frozen system prompt
   * (API-key mode). They refine behavior but NEVER override the built-in
   * security / permission rules. Empty/undefined = no custom instructions.
   */
  aiChatSystemPrompt?: string;
  /**
   * User-defined AI chat prompt templates (e.g. `/summarize`). Each maps a
   * command name to a prompt body; an `{{input}}` placeholder is substituted with
   * any text typed after the command (omit it and that text is appended instead).
   * Optional YAML frontmatter supports `description`, `argument-hint`, and
   * `kind: skill` (shown under `$`). Built-ins (`/clear`, `/model`) always take
   * precedence and cannot be shadowed.
   */
  aiChatPromptTemplates?: ChatPromptTemplate[];
  /**
   * Phase 12 (vault idle-lock): device PIN-lock state. `pepperWrapped` is the
   * safeStorage-wrapped (or, in the degraded no-keychain tier, raw base64)
   * 32-byte device pepper — a second KDF input combined with the PIN to wrap the
   * LAK. `enrolled` / `failedAttempts` / `lockedUntil` are the persisted
   * rate-limit counter that must survive an app kill (12-RESEARCH.md Pitfall 5).
   *
   * NEVER stored here: the PIN, the derived wrapping key, or the raw LAK. The
   * PIN-wrapped LAK lives only in `lak-pin.envelope`. Absent until the user
   * enrolls a PIN (enrollment UI is Plan 05); read as `?? { enrolled: false, … }`.
   */
  pinLock?: {
    pepperWrapped?: string;
    enrolled: boolean;
    failedAttempts: number;
    lockedUntil: number | null;
  };
  /**
   * Persisted, once-ever guard for the onboarding "Set a PIN" prompt (quick
   * 260708-el6). Set to `true` the first time the soft prompt is shown OR
   * dismissed, so it never reappears — including across a plugin reload. This is
   * the DURABLE flag; contrast the in-memory, per-session `pinNudgeShown`
   * backstop in main.ts (which only throttles the idle-logout Notice and resets
   * each session). Optional so an existing data.json without the key reads as
   * falsy = "not yet prompted".
   */
  pinOnboardingPromptShown?: boolean;
  /**
   * "Require PIN on startup" — the passkey-vs-max-security switch (Phase 12-07).
   *
   * Default (absent / false = passkey model): enrolling a PIN KEEPS the transparent
   * safeStorage LAK wrap (`lak.envelope`) alongside the PIN wrap, so a full login or
   * app startup unlocks the vault transparently — the PIN only re-locks the vault
   * when it goes idle. Accepted trade-off: a full-OS-access attacker on the unlocked
   * machine can decrypt (the SAME posture a no-PIN device already has).
   *
   * `true` = max-security (true D2): the transparent wrap is removed, so
   * `lak-pin.envelope` is the ONLY wrap and the vault is genuinely undecryptable
   * without the PIN even with full OS access — at the cost of a PIN prompt on every
   * startup / login. Read EVERYWHERE as `=== true` so an absent key means "off".
   */
  requirePinOnStartup?: boolean;
}

/** A user-defined slash-command prompt template for the AI Chat panel. */
export interface ChatPromptTemplate {
  /** Command name without the leading slash/dollar prefix, e.g. "summarize". */
  name: string;
  /** Prompt body; supports {{input}} substitution and optional YAML metadata. */
  prompt: string;
}

/** AI Chat transport selection. */
export type AiChatProvider = "subscription" | "apiKey" | "openai" | "codex";

/** AI Chat write-confirmation behavior. */
export type AiChatPermissionMode = "confirm" | "skip";

/** Adaptive-thinking effort levels accepted by the Anthropic Messages API. */
export type AnthropicEffort = "low" | "medium" | "high" | "xhigh" | "max";

/** Reasoning effort levels used by the OpenAI Responses API. */
export type OpenAiReasoningEffort = "low" | "medium" | "high";

/** Text verbosity levels used by GPT models through the OpenAI Responses API. */
export type OpenAiVerbosity = "low" | "medium" | "high";

/** Union used by compact chat UI controls that render either provider's effort. */
export type AiChatEffort = AnthropicEffort | OpenAiReasoningEffort;

// ─────────────────────────────────────────────────────────────────────────────
// API Communication
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Standard API response wrapper from the VaultGuard backend.
 */
export interface ApiResponse<T> {
  /** Whether the request was successful */
  success: boolean;
  /** Response payload (present on success) */
  data: T | null;
  /** Error information (present on failure) */
  error: ApiError | null;
  /** Request identifier for debugging */
  requestId: string;
}

/**
 * Structured error response from the VaultGuard API.
 */
export interface ApiError {
  /** Machine-readable error code */
  code: string;
  /** Human-readable error message */
  message: string;
  /** Additional error details */
  details: Record<string, unknown> | null;
  /** HTTP status code */
  statusCode: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Connection State
// ─────────────────────────────────────────────────────────────────────────────

/** Online/offline connection states */
export type ConnectionStatus = "online" | "offline" | "reconnecting";

/**
 * Tracks the plugin's connection to the VaultGuard backend.
 */
export interface ConnectionState {
  /** Current connection status */
  status: ConnectionStatus;
  /** ISO 8601 timestamp of last successful server communication */
  lastConnected: string | null;
  /** Number of consecutive failed connection attempts */
  failedAttempts: number;
  /** ISO 8601 timestamp of next scheduled retry (if offline) */
  nextRetryAt: string | null;
  /** Server-reported latency in milliseconds */
  latencyMs: number | null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Encryption Engine Types
// ─────────────────────────────────────────────────────────────────────────────

/** Encryption key material — raw bytes, ArrayBuffer, or hex string. */
export type EncryptionKey = ArrayBuffer | Uint8Array | string;

/** Encrypted data payload in VaultGuard cache format. */
export interface EncryptedPayload {
  /** Initialization vector (12 bytes) */
  iv: Uint8Array;
  /** GCM authentication tag (16 bytes) */
  authTag: Uint8Array;
  /** Encrypted file content */
  ciphertext: Uint8Array;
}

// ─────────────────────────────────────────────────────────────────────────────
// Key Manager Types
// ─────────────────────────────────────────────────────────────────────────────

/** Configuration for the KeyManager. */
export interface KeyManagerConfig {
  /** How often to refresh the lease (ms) */
  refreshIntervalMs?: number;
  /** How long the key remains valid without server contact (ms) */
  gracePeriodMs?: number;
  /** Buffer time before expiry to trigger refresh (ms) */
  refreshBufferMs?: number;
  /** Default server vault for scoped key leases */
  vaultId?: string;
}

/** Generic server response wrapper for key operations. */
export interface ServerResponse<T> {
  success: boolean;
  payload: T;
  error?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Cache Store Types
// ─────────────────────────────────────────────────────────────────────────────

/** Metadata for a cached file entry in the encrypted cache. */
export interface CacheEntry {
  /** SHA-256 hash of the original path */
  pathHash: string;
  /** Original vault-relative file path */
  originalPath: string;
  /** SHA-256 hash of the file content (for delta sync) */
  contentHash: string;
  /** Original file size in bytes */
  size: number;
  /** Encrypted file size in bytes */
  encryptedSize: number;
  /** Last modification timestamp */
  lastModified: number;
  /** When the file was cached */
  cachedAt: number;
}

/** The encrypted cache manifest. */
export interface CacheManifest {
  /** Map of path hash to cache entry */
  entries: Map<string, CacheEntry>;
  /** Timestamp of last manifest update */
  lastUpdated: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Sync Engine Types
// ─────────────────────────────────────────────────────────────────────────────

/** Sync engine states. */
export enum SyncEngineState {
  /** No sync in progress */
  IDLE = 'idle',
  /** Active sync operation */
  SYNCING = 'syncing',
  /** Unresolved conflicts exist */
  CONFLICT = 'conflict',
  /** Cannot reach server (within grace period) */
  OFFLINE = 'offline',
  /** Access revoked — all operations blocked */
  REVOKED = 'revoked',
}

/** Current sync engine status. */
export interface SyncEngineStatus {
  state: SyncEngineState;
  lastSync: number;
  queuedChanges: number;
  pendingConflicts: number;
  error: string | null;
  pulled?: number;
  pushed?: number;
  conflictsDetected?: number;
}

/** Sync event types for the event emitter. */
export enum SyncEventType {
  SYNC_STARTED = 'sync_started',
  SYNC_COMPLETED = 'sync_completed',
  SYNC_OFFLINE = 'sync_offline',
  PUSH_COMPLETED = 'push_completed',
  PULL_COMPLETED = 'pull_completed',
  CHANGE_QUEUED = 'change_queued',
  STATE_CHANGED = 'state_changed',
  CONFLICT_DETECTED = 'conflict_detected',
  CONFLICT_RESOLVED = 'conflict_resolved',
  ACCESS_REVOKED = 'access_revoked',
}

/** Sync event payload. */
export interface SyncEvent {
  type: SyncEventType;
  timestamp: number;
  data?: unknown;
}

/** Sync engine configuration. */
export interface SyncConfig {
  /** Sync interval in milliseconds */
  intervalMs?: number;
  /** Max files per sync batch */
  batchSize?: number;
  /** Default strategy for auto-resolving conflicts */
  autoResolveStrategy?: string;
}

/** A local file change queued for sync. */
export interface FileChange {
  /** Vault-relative file path */
  path: string;
  /** Type of change */
  type: 'create' | 'modify' | 'delete';
  /** File content (for create/modify) */
  content?: string;
  /** Timestamp when the change occurred */
  timestamp: number;
}

/** A file entry from the server's file listing. */
export interface ServerFileEntry {
  /** Vault-relative file path */
  path: string;
  /** SHA-256 content hash */
  contentHash: string;
  /** Last modification timestamp on server */
  lastModified: number;
  /** File size in bytes */
  size: number;
}

// ─────────────────────────────────────────────────────────────────────────────
// Conflict Resolution Types
// ─────────────────────────────────────────────────────────────────────────────

/** Information about a detected sync conflict. */
export interface ConflictInfo {
  /** File path with the conflict */
  path: string;
  /** Content hash of the local version */
  localHash: string;
  /** Content hash of the server version */
  serverHash: string;
  /** When the local version was last modified */
  localModified: number;
  /** When the server version was last modified */
  serverModified: number;
}

/** A full conflict record including resolution state. */
export interface ConflictRecord extends ConflictInfo {
  /** When the conflict was detected */
  detectedAt: number;
  /** When the conflict was resolved (null if pending) */
  resolvedAt: number | null;
  /** The resolution result (null if pending) */
  resolution: ConflictResolutionResult | null;
  /** The strategy used to resolve (null if pending) */
  strategy: string | null;
}

/** Result of a conflict resolution. */
export interface ConflictResolutionResult {
  /** File path */
  path: string;
  /** Resolved content (null for LOCAL_WINS where content is already in cache) */
  content: string | null;
  /** Strategy that was applied */
  strategy: string;
  /** Timestamp of resolution */
  resolvedAt: number;
  /** Additional merge details */
  mergeDetails?: {
    hasConflicts?: boolean;
    conflictMarkers?: number;
    fallback?: string;
    reason?: string;
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Permission Checker Types
// ─────────────────────────────────────────────────────────────────────────────

/** A permission grant from the server (for the PermissionChecker). */
export interface PermissionGrant {
  /** Glob pattern this grant applies to */
  pattern: string;
  /** Permission level granted */
  level: PermissionLevel;
  /** Who/what granted this permission */
  grantedBy: string;
  /** ISO timestamp when the grant expires (null = permanent) */
  expiresAt: string | null;
  /** ISO timestamp when the grant was created */
  createdAt: string;
}

/** Resolved effective permission for a specific path. */
export interface EffectivePermission {
  level: PermissionLevel;
  grantedBy: string;
  expiresAt: string | null;
  pattern: string;
}
