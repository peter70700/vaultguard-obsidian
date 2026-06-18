import { AuditAction, PermissionLevel, UserSession } from "../types";
import type { GraphArgs, GraphPermissionDeps, GraphResult } from "./graph/graph-types";
import type { VaultGraph } from "./graph/vault-graph";

// Cherry-picked from AuditAction so the bridge only emits its own events
// and gets a compile error if those names drift.
export type BridgeAuditAction = Extract<AuditAction, `bridge.${string}`>;

export type AgentBridgeToolName =
  | "vaultguard_list"
  | "vaultguard_search"
  | "vaultguard_read"
  | "vaultguard_apply_patch"
  | "vaultguard_create"
  | "vaultguard_graph";

export type AgentWriteMode = "deny" | "confirm" | "allow";

export interface AgentBridgeLeaseInput {
  agentName?: string;
  scope?: string | string[];
  ttlMinutes?: number;
  allowRead?: boolean;
  writeMode?: AgentWriteMode;
  maxReadBytes?: number;
  maxSearchResults?: number;
  // When true, the lease is bound to the current VaultGuard session
  // instead of a wall-clock TTL. It survives Obsidian restarts (encrypted
  // on disk via the LAK) and dies on logout. Stricter scope/writeMode
  // rules apply — see createLease().
  persistent?: boolean;
}

export interface AgentBridgeLeaseSummary {
  leaseId: string;
  agentName: string;
  scopes: string[];
  allowRead: boolean;
  writeMode: AgentWriteMode;
  createdAt: string;
  // ISO timestamp for ephemeral leases. For persistent leases this is the
  // string "session" — reading code should branch on `persistent` rather
  // than parsing the value.
  expiresAt: string;
  persistent: boolean;
  maxReadBytes: number;
  maxSearchResults: number;
  tools: AgentBridgeToolName[];
}

// Includes the bearer token. Only returned to the caller that mints the
// lease (or rotates its token) — never surfaced from describe(), persisted
// only inside the LAK-encrypted envelope, and never logged.
export interface AgentBridgeLeaseSecret extends AgentBridgeLeaseSummary {
  token: string;
}

export interface AgentBridgeServerInfo {
  endpoint: string;
  mcpEndpoint: string;
  leaseIds: string[];
  tools: AgentBridgeToolName[];
}

export interface AgentBridgeListResult {
  files: Array<{
    path: string;
    permission: "read" | "write" | "admin";
  }>;
  truncated: boolean;
}

export interface AgentBridgeSearchResult {
  matches: Array<{
    path: string;
    line: number;
    snippet: string;
  }>;
  truncated: boolean;
}

export interface AgentBridgeReadResult {
  path: string;
  content: string;
  truncated: boolean;
  bytes: number;
}

export interface AgentBridgeWriteResult {
  path: string;
  bytes: number;
}

export interface AgentBridgeToolSurface {
  describe(): {
    tools: AgentBridgeToolName[];
    activeLeases: AgentBridgeLeaseSummary[];
    server: Omit<AgentBridgeServerInfo, "token"> | null;
  };
  list(leaseId: string, args?: { scope?: string; limit?: number }): Promise<AgentBridgeListResult>;
  search(leaseId: string, args: { query: string; scope?: string; limit?: number }): Promise<AgentBridgeSearchResult>;
  read(leaseId: string, args: { path: string; maxBytes?: number }): Promise<AgentBridgeReadResult>;
  applyPatch(leaseId: string, args: { path: string; diff: string }): Promise<AgentBridgeWriteResult>;
  create(leaseId: string, args: { path: string; content: string }): Promise<AgentBridgeWriteResult>;
  graph(leaseId: string, args: GraphArgs): Promise<GraphResult>;
}

interface AgentBridgeLease extends AgentBridgeLeaseSummary {
  // Bearer token. Per-lease so leases can be revoked or rotated
  // individually without affecting siblings.
  token: string;
  // Ephemeral leases use a wall-clock expiry. Persistent leases use
  // Number.POSITIVE_INFINITY here (and a literal "session" sentinel in
  // expiresAt) so the prune check is a simple `expiresAtMs <= now`.
  expiresAtMs: number;
  // Pinning a persistent lease to the session that created it — restored
  // leases for a different user or vault binding are dropped on load.
  // null for ephemeral leases.
  sessionUserId: string | null;
  sessionVaultId: string | null;
}

export interface AgentBridgePersistenceAdapter {
  // Reads/writes the encrypted lease envelope. Implementations should run
  // through VaultGuard's at-rest cipher so the file on disk is opaque to
  // anything but a logged-in plugin instance with the LAK.
  readEnvelope(): Promise<string | null>;
  writeEnvelope(plaintext: string): Promise<void>;
  deleteEnvelope(): Promise<void>;
}

interface AgentBridgeDeps {
  getSession(): UserSession | null;
  getServerVaultId(): string;
  getAllFilePaths(): string[];
  fileExists(path: string): Promise<boolean>;
  ensureParentFolders(path: string): Promise<void>;
  isPathExcluded(path: string): boolean;
  getPermission(path: string): Promise<PermissionLevel>;
  // Factory for the read-only metadataCache navigator. The bridge supplies a
  // per-lease GraphPermissionDeps (scope predicate + the same permission/
  // exclusion gates) so VaultGraph re-checks every emitted path on the way
  // out. main.ts wires the App in; when graph support is unavailable (e.g.
  // headless tests that don't need it) this may be absent and graph() fails
  // closed with a clear error.
  makeVaultGraph?: (deps: GraphPermissionDeps) => VaultGraph;
  readText(path: string): Promise<string>;
  writeText(path: string, content: string): Promise<void>;
  confirmWrite(request: {
    lease: AgentBridgeLeaseSummary;
    operation: "create" | "apply_patch";
    path: string;
    preview: string;
  }): Promise<boolean>;
  log(message: string): void;
  emitAudit(
    action: BridgeAuditAction,
    resourcePath: string | null,
    metadata: Record<string, unknown>
  ): void | Promise<void>;
  // Wraps `fn` so that any HTTP requests it makes carry agent-attribution
  // headers (X-VG-Agent-Name / X-VG-Lease-Id). Wired in main.ts to
  // `apiClient.withAgentContext`. The bridge calls this around every
  // `executeTool` dispatch so the resulting file/permission audit rows on
  // the backend pick up the calling agent's identity automatically.
  withAgentContext: <T>(
    agentName: string,
    leaseId: string,
    fn: () => Promise<T>
  ) => Promise<T>;
  // Optional — only present when at-rest encryption is ready. The bridge
  // gates persistent leases on this; when absent, persistent-mode lease
  // creation fails closed with a clear error rather than silently
  // downgrading to plaintext on disk.
  persistence?: AgentBridgePersistenceAdapter | null;
  // Override for tests. In production we always try the preferred port
  // first so the URL is stable across reloads, but back-to-back test runs
  // collide on it.
  preferredPort?: number;
}

type NodeIncomingMessage = {
  method?: string;
  url?: string;
  headers: Record<string, string | string[] | undefined>;
  on(event: "data", cb: (chunk: Uint8Array | string) => void): void;
  on(event: "end", cb: () => void): void;
  on(event: "error", cb: (err: Error) => void): void;
};

type NodeServerResponse = {
  statusCode: number;
  setHeader(name: string, value: string): void;
  end(body?: string): void;
};

type NodeHttpServer = {
  listen(port: number, hostname: string, cb: () => void): void;
  close(cb?: (err?: Error) => void): void;
  address(): { port: number } | string | null;
  on(event: "error", cb: (err: Error) => void): void;
};

type NodeHttpModule = {
  createServer(handler: (req: NodeIncomingMessage, res: NodeServerResponse) => void): NodeHttpServer;
};

const TOOLS: AgentBridgeToolName[] = [
  "vaultguard_list",
  "vaultguard_search",
  "vaultguard_read",
  "vaultguard_apply_patch",
  "vaultguard_create",
  "vaultguard_graph",
];

// Latest MCP spec revision we implement. Clients usually accept any version
// the server reports back in `initialize.result.protocolVersion`.
const MCP_PROTOCOL_VERSION = "2025-06-18";

interface McpToolDefinition {
  internal: AgentBridgeToolName;
  description: string;
  inputSchema: Record<string, unknown>;
}

// Short, MCP-facing tool names. Clients see them prefixed by the server label
// (e.g. `mcp__vaultguard__read`), so we drop the redundant `vaultguard_`.
// The internal AgentBridgeToolName stays the long form so the existing
// /rpc surface and tests are unchanged.
const MCP_TOOLS: Record<string, McpToolDefinition> = {
  list: {
    internal: "vaultguard_list",
    description:
      "List vault files visible to this lease, with their effective permission. Filters out hidden, excluded, and out-of-scope paths.",
    inputSchema: {
      type: "object",
      properties: {
        scope: { type: "string", description: "Optional vault-relative glob to narrow within the lease scope (e.g. /project-x/**)." },
        limit: { type: "integer", minimum: 1, description: "Maximum number of files to return." },
      },
      additionalProperties: false,
    },
  },
  search: {
    internal: "vaultguard_search",
    description:
      "Search the visible text files for a literal substring. Returns path, line number, and a short snippet for each match.",
    inputSchema: {
      type: "object",
      required: ["query"],
      properties: {
        query: { type: "string", description: "Literal substring to search for (case-insensitive)." },
        scope: { type: "string", description: "Optional vault-relative glob to narrow within the lease scope." },
        limit: { type: "integer", minimum: 1 },
      },
      additionalProperties: false,
    },
  },
  read: {
    internal: "vaultguard_read",
    description:
      "Read a single text file from the vault as plaintext. Goes through VaultGuard's permission and at-rest decrypt path; refuses non-text files and out-of-scope paths.",
    inputSchema: {
      type: "object",
      required: ["path"],
      properties: {
        path: { type: "string", description: "Vault-relative path (e.g. project-x/Plan.md)." },
        maxBytes: { type: "integer", minimum: 1, description: "Truncate the response to at most this many UTF-8 bytes." },
      },
      additionalProperties: false,
    },
  },
  apply_patch: {
    internal: "vaultguard_apply_patch",
    description:
      "Apply a unified diff (with @@ hunks) to an existing text file. The hunks must match the current file exactly. Subject to writeMode (deny / confirm / allow) on the lease.",
    inputSchema: {
      type: "object",
      required: ["path", "diff"],
      properties: {
        path: { type: "string", description: "Vault-relative path of the file to patch." },
        diff: { type: "string", description: "Unified diff with @@ hunk headers." },
      },
      additionalProperties: false,
    },
  },
  create: {
    internal: "vaultguard_create",
    description:
      "Create a new text file with the given content. Refuses to overwrite an existing file. Subject to writeMode on the lease.",
    inputSchema: {
      type: "object",
      required: ["path", "content"],
      properties: {
        path: { type: "string", description: "Vault-relative path of the new file." },
        content: { type: "string", description: "File content as a UTF-8 string." },
      },
      additionalProperties: false,
    },
  },
  graph: {
    internal: "vaultguard_graph",
    description:
      "Navigate the vault's structure without reading whole files. Cheaper than listing+reading. " +
      "Ops: 'neighbors' (links/backlinks/shared-tags of a note), 'related' (top notes connected to a " +
      "note, ranked), 'tag' (notes carrying a tag), 'orphans' (unlinked notes), 'hubs' (most-connected " +
      "notes), 'overview' (vault-wide structural summary). Results respect your permissions.",
    inputSchema: {
      type: "object",
      required: ["op"],
      properties: {
        op: { type: "string", enum: ["neighbors", "related", "tag", "orphans", "hubs", "overview"] },
        path: { type: "string", description: "Target note (required for neighbors/related)." },
        tag: { type: "string", description: "Tag without '#' (required for op=tag)." },
        depth: { type: "integer", minimum: 1, maximum: 3, description: "Hops for neighbors/related (default 1)." },
        limit: { type: "integer", minimum: 1, maximum: 100 },
      },
      additionalProperties: false,
    },
  },
};

interface JsonRpcRequest {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: Record<string, unknown>;
}

const DEFAULT_TTL_MINUTES = 30;
const MIN_TTL_MINUTES = 1;
const MAX_TTL_MINUTES = 120;
const DEFAULT_MAX_READ_BYTES = 256 * 1024;
const MAX_READ_BYTES = 1024 * 1024;
const DEFAULT_MAX_SEARCH_RESULTS = 50;
const MAX_SEARCH_RESULTS = 200;
const DEFAULT_LIST_LIMIT = 1000;
const MAX_LIST_LIMIT = 5000;
const HTTP_BODY_LIMIT_BYTES = 1024 * 1024;
// Try this localhost port first so the URL pasted into Claudian / .mcp.json
// stays stable across plugin reloads. Falls back to a random port if the
// preferred one is taken (another VaultGuard instance, another process).
const PREFERRED_BRIDGE_PORT = 47711;
const PERSISTED_LEASE_ENVELOPE_VERSION = 1;
const SESSION_EXPIRY_SENTINEL = "session";

interface PersistedLeaseRecord {
  leaseId: string;
  token: string;
  agentName: string;
  scopes: string[];
  allowRead: boolean;
  writeMode: AgentWriteMode;
  createdAt: string;
  maxReadBytes: number;
  maxSearchResults: number;
  sessionUserId: string;
  sessionVaultId: string;
}

interface PersistedLeaseEnvelope {
  version: number;
  leases: PersistedLeaseRecord[];
}

const TEXT_EXTENSIONS = new Set([
  ".md",
  ".txt",
  ".canvas",
  ".csv",
  ".tsv",
  ".json",
  ".yaml",
  ".yml",
]);

export class VaultGuardAgentBridge {
  private deps: AgentBridgeDeps;
  private leases: Map<string, AgentBridgeLease> = new Map();
  // Reverse index of token → leaseId for O(1) bearer matching on every
  // request. Kept in lockstep with `leases` by every code path that
  // creates / revokes / rotates a lease.
  private tokenIndex: Map<string, string> = new Map();
  private server: NodeHttpServer | null = null;
  private serverEndpoint: string | null = null;
  private serverMcpEndpoint: string | null = null;
  private persistedLoaded = false;

  constructor(deps: AgentBridgeDeps) {
    this.deps = deps;
  }

  /**
   * Hydrate persistent leases from the LAK-encrypted envelope. Idempotent;
   * only filters in records that match the current session's userId+vaultId
   * so a logged-out / wrong-user scenario can't reanimate someone else's
   * leases. Safe to call repeatedly — subsequent calls are no-ops once
   * loaded for the current session.
   */
  async loadPersistedLeases(): Promise<{ restored: number; dropped: number }> {
    if (this.persistedLoaded) return { restored: 0, dropped: 0 };
    if (!this.deps.persistence) return { restored: 0, dropped: 0 };

    const session = this.deps.getSession();
    const vaultId = this.deps.getServerVaultId();
    if (!session || !vaultId) {
      // Don't load until we know who we are. The plugin will call back
      // after login. Stay marked as not-loaded so we re-check on next
      // session change.
      return { restored: 0, dropped: 0 };
    }

    let envelope: PersistedLeaseEnvelope | null = null;
    try {
      const raw = await this.deps.persistence.readEnvelope();
      if (!raw) {
        this.persistedLoaded = true;
        return { restored: 0, dropped: 0 };
      }
      const parsed = JSON.parse(raw) as PersistedLeaseEnvelope;
      if (
        parsed.version !== PERSISTED_LEASE_ENVELOPE_VERSION ||
        !Array.isArray(parsed.leases)
      ) {
        throw new Error("Unexpected envelope shape.");
      }
      envelope = parsed;
    } catch (err) {
      this.deps.log(
        `Failed to read persisted agent leases: ${err instanceof Error ? err.message : String(err)}`
      );
      // Don't pretend we restored cleanly — but don't crash. The user
      // can re-mint; existing access via ephemeral leases is unaffected.
      this.persistedLoaded = true;
      return { restored: 0, dropped: 0 };
    }

    let restored = 0;
    let dropped = 0;

    for (const record of envelope.leases) {
      if (
        record.sessionUserId !== session.userId ||
        record.sessionVaultId !== vaultId
      ) {
        dropped++;
        continue;
      }

      const lease: AgentBridgeLease = {
        leaseId: record.leaseId,
        agentName: record.agentName,
        scopes: [...record.scopes],
        allowRead: record.allowRead,
        writeMode: record.writeMode,
        createdAt: record.createdAt,
        expiresAt: SESSION_EXPIRY_SENTINEL,
        expiresAtMs: Number.POSITIVE_INFINITY,
        persistent: true,
        maxReadBytes: record.maxReadBytes,
        maxSearchResults: record.maxSearchResults,
        tools: [...TOOLS],
        token: record.token,
        sessionUserId: record.sessionUserId,
        sessionVaultId: record.sessionVaultId,
      };
      this.leases.set(lease.leaseId, lease);
      this.tokenIndex.set(lease.token, lease.leaseId);
      restored++;
    }

    this.persistedLoaded = true;
    if (restored > 0) {
      void this.deps.emitAudit("bridge.session_bound", null, {
        restored,
        dropped,
        userId: session.userId,
        vaultId,
      });
    }
    if (dropped > 0) {
      this.deps.log(
        `Dropped ${dropped} persisted agent lease(s) belonging to a different user/vault.`
      );
      // Persist the cleaned set so we don't keep dropping the same orphans
      // forever.
      await this.persistLeases().catch((err) =>
        this.deps.log(
          `Failed to rewrite agent lease envelope after dropping orphans: ${err instanceof Error ? err.message : String(err)}`
        )
      );
    }
    return { restored, dropped };
  }

  /**
   * Revoke every persistent lease and emit a single session_unbound audit
   * event. Called by the host plugin when the session ends (logout,
   * refresh failure, account disabled). Ephemeral leases are also dropped
   * — they wouldn't outlive the session anyway, but being explicit keeps
   * the bridge state consistent.
   */
  async revokePersistentLeasesForSessionEnd(reason: string): Promise<number> {
    const before = this.leases.size;
    this.leases.clear();
    this.tokenIndex.clear();
    this.persistedLoaded = false;
    if (this.deps.persistence) {
      await this.deps.persistence.deleteEnvelope().catch((err) =>
        this.deps.log(
          `Failed to delete persisted agent leases on session end: ${err instanceof Error ? err.message : String(err)}`
        )
      );
    }
    if (before > 0) {
      void this.deps.emitAudit("bridge.session_unbound", null, {
        revoked: before,
        reason,
      });
    }
    return before;
  }

  // In-process tool dispatch (the in-plugin AI chat via getToolSurface, and any
  // trusted getAgentBridge() integration). Routes through the SAME
  // invokeToolWithAudit wrapper as the rpc/mcp transports so in-process AI
  // actions emit bridge.tool_invoked AND run inside withAgentContext (backend
  // writes attributed to the lease). Without this, API-key-provider chat actions
  // were invisible to the audit trail and indistinguishable from manual edits.
  private invokeInProcess(
    tool: AgentBridgeToolName,
    leaseId: string,
    args: Record<string, unknown>,
  ): Promise<unknown> {
    const lease = this.requireLease(leaseId);
    return this.invokeToolWithAudit(tool, lease, args, "inproc");
  }

  getToolSurface(): AgentBridgeToolSurface {
    return {
      describe: () => this.describe(),
      list: (leaseId, args) =>
        this.invokeInProcess(
          "vaultguard_list",
          leaseId,
          (args ?? {}) as Record<string, unknown>,
        ) as Promise<AgentBridgeListResult>,
      search: (leaseId, args) =>
        this.invokeInProcess(
          "vaultguard_search",
          leaseId,
          args as Record<string, unknown>,
        ) as Promise<AgentBridgeSearchResult>,
      read: (leaseId, args) =>
        this.invokeInProcess(
          "vaultguard_read",
          leaseId,
          args as Record<string, unknown>,
        ) as Promise<AgentBridgeReadResult>,
      applyPatch: (leaseId, args) =>
        this.invokeInProcess(
          "vaultguard_apply_patch",
          leaseId,
          args as Record<string, unknown>,
        ) as Promise<AgentBridgeWriteResult>,
      create: (leaseId, args) =>
        this.invokeInProcess(
          "vaultguard_create",
          leaseId,
          args as Record<string, unknown>,
        ) as Promise<AgentBridgeWriteResult>,
      graph: (leaseId, args) =>
        this.invokeInProcess(
          "vaultguard_graph",
          leaseId,
          args as unknown as Record<string, unknown>,
        ) as Promise<GraphResult>,
    };
  }

  describe(): ReturnType<AgentBridgeToolSurface["describe"]> {
    this.pruneExpiredLeases();
    const server =
      this.serverEndpoint && this.serverMcpEndpoint
        ? {
            endpoint: this.serverEndpoint,
            mcpEndpoint: this.serverMcpEndpoint,
            leaseIds: Array.from(this.leases.keys()),
            tools: TOOLS,
          }
        : null;
    return {
      tools: TOOLS,
      activeLeases: Array.from(this.leases.values()).map((lease) => this.summarizeLease(lease)),
      server,
    };
  }

  createLease(input: AgentBridgeLeaseInput = {}): AgentBridgeLeaseSecret {
    this.assertBridgePrereqs();

    const persistent = input.persistent === true;
    const scopes = this.normalizeScopes(input.scope ?? "/**");
    const writeMode = input.writeMode ?? "deny";

    if (persistent) {
      // Persistent leases live as long as the session does, so the
      // no-silent-write rule applies at creation. Scope width itself is
      // not restricted — `/**` is already vault-scoped (the bridge only
      // knows about one vault) and forcing narrowing was UX friction
      // without a real threat-model justification: the agent can read
      // the same files via an ephemeral `/**` lease today. The rules we
      // keep here only protect against differences that a longer lease
      // *actually* introduces.
      if (!this.deps.persistence) {
        throw new Error(
          "VaultGuard agent bridge cannot mint a persistent lease until at-rest encryption is initialized."
        );
      }
      if (writeMode === "allow") {
        // `confirm` and `allow` both let writes happen, but `confirm`
        // surfaces every write to the user — even a forgotten persistent
        // lease can't silently rewrite the vault. `allow + persistent`
        // is a meaningful capability change vs ephemeral, not a
        // duplicate of one.
        throw new Error(
          'Persistent agent bridge leases cannot use writeMode "allow" — "confirm" still allows writes but surfaces each one to the user. Use "deny" or "confirm".'
        );
      }
    }

    const ttlMinutes = this.clampNumber(input.ttlMinutes ?? DEFAULT_TTL_MINUTES, MIN_TTL_MINUTES, MAX_TTL_MINUTES);
    const now = Date.now();
    const maxReadBytes = this.clampNumber(input.maxReadBytes ?? DEFAULT_MAX_READ_BYTES, 1024, MAX_READ_BYTES);
    const maxSearchResults = this.clampNumber(
      input.maxSearchResults ?? DEFAULT_MAX_SEARCH_RESULTS,
      1,
      MAX_SEARCH_RESULTS
    );

    const session = this.deps.getSession();
    const vaultId = this.deps.getServerVaultId();
    const lease: AgentBridgeLease = {
      leaseId: this.randomId("agl"),
      agentName: this.cleanAgentName(input.agentName),
      scopes,
      allowRead: input.allowRead !== false,
      writeMode,
      createdAt: new Date(now).toISOString(),
      expiresAt: persistent
        ? SESSION_EXPIRY_SENTINEL
        : new Date(now + ttlMinutes * 60_000).toISOString(),
      expiresAtMs: persistent
        ? Number.POSITIVE_INFINITY
        : now + ttlMinutes * 60_000,
      persistent,
      maxReadBytes,
      maxSearchResults,
      tools: TOOLS,
      token: this.randomId("agt"),
      sessionUserId: persistent ? session?.userId ?? null : null,
      sessionVaultId: persistent ? vaultId || null : null,
    };

    this.leases.set(lease.leaseId, lease);
    this.tokenIndex.set(lease.token, lease.leaseId);

    if (persistent) {
      // Save before we tell the caller the lease exists — if persistence
      // throws, the lease shouldn't be alive in memory either.
      void this.persistLeases().catch((err) => {
        this.leases.delete(lease.leaseId);
        this.tokenIndex.delete(lease.token);
        throw err;
      });
    }

    this.deps.log(
      `Agent bridge lease ${lease.leaseId} created for ${lease.agentName} (${lease.scopes.join(", ")}, ${persistent ? "persistent" : "ephemeral"})`
    );

    void this.deps.emitAudit("bridge.lease_created", null, {
      leaseId: lease.leaseId,
      agentName: lease.agentName,
      scopes: lease.scopes,
      writeMode: lease.writeMode,
      allowRead: lease.allowRead,
      persistent,
      ttlMinutes: persistent ? null : ttlMinutes,
      sessionUserId: lease.sessionUserId,
      sessionVaultId: lease.sessionVaultId,
    });

    return this.summarizeLeaseWithSecret(lease);
  }

  revokeLease(leaseId: string): boolean {
    const lease = this.leases.get(leaseId);
    if (!lease) return false;
    this.leases.delete(leaseId);
    this.tokenIndex.delete(lease.token);
    if (lease.persistent) {
      void this.persistLeases().catch((err) =>
        this.deps.log(
          `Failed to persist lease envelope after revoke: ${err instanceof Error ? err.message : String(err)}`
        )
      );
    }
    void this.deps.emitAudit("bridge.lease_revoked", null, {
      leaseId,
      agentName: lease.agentName,
      persistent: lease.persistent,
    });
    return true;
  }

  revokeAllLeases(): void {
    const persistentLeaseIds: string[] = [];
    for (const lease of this.leases.values()) {
      if (lease.persistent) persistentLeaseIds.push(lease.leaseId);
    }
    this.leases.clear();
    this.tokenIndex.clear();
    if (persistentLeaseIds.length > 0) {
      void this.persistLeases().catch((err) =>
        this.deps.log(
          `Failed to clear lease envelope after revokeAll: ${err instanceof Error ? err.message : String(err)}`
        )
      );
      void this.deps.emitAudit("bridge.lease_revoked", null, {
        leaseIds: persistentLeaseIds,
        scope: "all",
      });
    }
  }

  /**
   * Mints a new bearer token for an existing lease and invalidates the old
   * one. The agent must update its `Authorization` header; until then it
   * gets 401s. Returns the lease summary plus the new token. The lease's
   * scope, writeMode, and persistent flag are unchanged.
   */
  rotateLeaseToken(leaseId: string): AgentBridgeLeaseSecret {
    const lease = this.requireLease(leaseId);
    const oldToken = lease.token;
    lease.token = this.randomId("agt");
    this.tokenIndex.delete(oldToken);
    this.tokenIndex.set(lease.token, lease.leaseId);

    if (lease.persistent) {
      void this.persistLeases().catch((err) =>
        this.deps.log(
          `Failed to persist lease envelope after token rotate: ${err instanceof Error ? err.message : String(err)}`
        )
      );
    }

    void this.deps.emitAudit("bridge.lease_token_rotated", null, {
      leaseId,
      agentName: lease.agentName,
      persistent: lease.persistent,
    });

    return this.summarizeLeaseWithSecret(lease);
  }

  private async persistLeases(): Promise<void> {
    if (!this.deps.persistence) return;
    const persistent = Array.from(this.leases.values()).filter((l) => l.persistent);
    if (persistent.length === 0) {
      await this.deps.persistence.deleteEnvelope();
      return;
    }
    const envelope: PersistedLeaseEnvelope = {
      version: PERSISTED_LEASE_ENVELOPE_VERSION,
      leases: persistent.map<PersistedLeaseRecord>((lease) => ({
        leaseId: lease.leaseId,
        token: lease.token,
        agentName: lease.agentName,
        scopes: [...lease.scopes],
        allowRead: lease.allowRead,
        writeMode: lease.writeMode,
        createdAt: lease.createdAt,
        maxReadBytes: lease.maxReadBytes,
        maxSearchResults: lease.maxSearchResults,
        sessionUserId: lease.sessionUserId ?? "",
        sessionVaultId: lease.sessionVaultId ?? "",
      })),
    };
    await this.deps.persistence.writeEnvelope(JSON.stringify(envelope));
  }

  async startHttpServer(): Promise<AgentBridgeServerInfo> {
    if (this.server && this.serverEndpoint) {
      return this.getServerInfo();
    }

    const http = this.loadNodeHttp();
    const server = await this.bindServer(http);

    const address = server.address();
    if (!address || typeof address === "string") {
      server.close();
      throw new Error("VaultGuard agent bridge could not determine its localhost port.");
    }

    this.server = server;
    this.serverEndpoint = `http://127.0.0.1:${address.port}/rpc`;
    this.serverMcpEndpoint = `http://127.0.0.1:${address.port}/mcp`;
    this.deps.log(
      `Agent bridge server listening on ${this.serverEndpoint} (MCP at ${this.serverMcpEndpoint})`
    );
    return this.getServerInfo();
  }

  /**
   * Try the preferred port first so the URL pasted into Claudian / .mcp.json
   * survives plugin reloads. Fall back to a random port if EADDRINUSE — the
   * user gets a notice via the lease modal showing the actual URL.
   */
  private async bindServer(http: NodeHttpModule): Promise<NodeHttpServer> {
    const tryPort = (port: number): Promise<NodeHttpServer> =>
      new Promise((resolve, reject) => {
        const server = http.createServer((req, res) => {
          void this.handleHttpRequest(req, res);
        });
        let settled = false;
        server.on("error", (err) => {
          if (settled) return;
          settled = true;
          server.close();
          reject(err);
        });
        server.listen(port, "127.0.0.1", () => {
          if (settled) return;
          settled = true;
          resolve(server);
        });
      });

    const preferred = this.deps.preferredPort ?? PREFERRED_BRIDGE_PORT;
    if (preferred === 0) return tryPort(0);

    try {
      return await tryPort(preferred);
    } catch (err) {
      const code = (err as NodeJS.ErrnoException | undefined)?.code;
      if (code === "EADDRINUSE" || code === "EACCES") {
        this.deps.log(
          `Preferred agent bridge port ${preferred} unavailable (${code}); falling back to a random port.`
        );
        return tryPort(0);
      }
      throw err;
    }
  }

  async stopHttpServer(): Promise<void> {
    const server = this.server;
    this.server = null;
    this.serverEndpoint = null;
    this.serverMcpEndpoint = null;

    if (!server) return;

    await new Promise<void>((resolve, reject) => {
      server.close((err?: Error) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  getServerInfo(): AgentBridgeServerInfo {
    if (!this.serverEndpoint || !this.serverMcpEndpoint) {
      throw new Error("VaultGuard agent bridge server is not running.");
    }
    this.pruneExpiredLeases();
    return {
      endpoint: this.serverEndpoint,
      mcpEndpoint: this.serverMcpEndpoint,
      leaseIds: Array.from(this.leases.keys()),
      tools: TOOLS,
    };
  }

  async list(
    leaseId: string,
    args: { scope?: string; limit?: number } = {}
  ): Promise<AgentBridgeListResult> {
    const lease = this.requireLease(leaseId);
    if (!lease.allowRead) {
      throw new Error("VaultGuard agent lease does not allow reads.");
    }

    const scope = args.scope ? this.normalizeScope(args.scope) : null;
    const limit = this.clampNumber(args.limit ?? DEFAULT_LIST_LIMIT, 1, MAX_LIST_LIMIT);
    const files: AgentBridgeListResult["files"] = [];

    for (const rawPath of this.deps.getAllFilePaths()) {
      const path = this.normalizePath(rawPath);
      if (!path || !this.isPathAgentReadable(path, lease, scope)) continue;

      const permission = await this.deps.getPermission(path);
      if (permission < PermissionLevel.READ) continue;

      files.push({
        path,
        permission: this.permissionLabel(permission),
      });

      if (files.length >= limit) {
        return { files, truncated: true };
      }
    }

    files.sort((a, b) => a.path.localeCompare(b.path));
    return { files, truncated: false };
  }

  async search(
    leaseId: string,
    args: { query: string; scope?: string; limit?: number }
  ): Promise<AgentBridgeSearchResult> {
    const lease = this.requireLease(leaseId);
    if (!lease.allowRead) {
      throw new Error("VaultGuard agent lease does not allow reads.");
    }

    const query = (args.query ?? "").trim();
    if (!query) {
      throw new Error("vaultguard_search requires a non-empty query.");
    }

    const limit = this.clampNumber(args.limit ?? lease.maxSearchResults, 1, lease.maxSearchResults);
    const listed = await this.list(leaseId, { scope: args.scope, limit: MAX_LIST_LIMIT });
    const needle = query.toLocaleLowerCase();
    const matches: AgentBridgeSearchResult["matches"] = [];

    for (const file of listed.files) {
      if (!this.isTextPath(file.path)) continue;

      let content: string;
      try {
        content = await this.deps.readText(file.path);
      } catch {
        continue;
      }

      const lines = content.split(/\r?\n/);
      for (let i = 0; i < lines.length; i++) {
        const haystack = lines[i].toLocaleLowerCase();
        const index = haystack.indexOf(needle);
        if (index === -1) continue;

        matches.push({
          path: file.path,
          line: i + 1,
          snippet: this.makeSnippet(lines[i], index, query.length),
        });

        if (matches.length >= limit) {
          return { matches, truncated: true };
        }
      }
    }

    return { matches, truncated: listed.truncated };
  }

  async read(
    leaseId: string,
    args: { path: string; maxBytes?: number }
  ): Promise<AgentBridgeReadResult> {
    const lease = this.requireLease(leaseId);
    if (!lease.allowRead) {
      throw new Error("VaultGuard agent lease does not allow reads.");
    }

    const path = this.requireReadablePath(args.path, lease);
    if (!this.isTextPath(path)) {
      throw new Error(`VaultGuard agent bridge refuses to read non-text file "${path}".`);
    }

    const content = await this.deps.readText(path);
    const bytes = this.utf8Bytes(content);
    const maxBytes = this.clampNumber(args.maxBytes ?? lease.maxReadBytes, 1, lease.maxReadBytes);

    if (bytes <= maxBytes) {
      return { path, content, bytes, truncated: false };
    }

    return {
      path,
      content: this.truncateUtf8(content, maxBytes),
      bytes,
      truncated: true,
    };
  }

  async applyPatch(
    leaseId: string,
    args: { path: string; diff: string }
  ): Promise<AgentBridgeWriteResult> {
    const lease = this.requireLease(leaseId);
    const path = await this.requireWritablePath(args.path, lease, "apply_patch", args.diff ?? "");
    const diff = args.diff ?? "";
    if (!diff.trim()) {
      throw new Error("vaultguard_apply_patch requires a non-empty unified diff.");
    }

    const current = await this.deps.readText(path);
    const next = applyUnifiedDiff(current, diff);
    if (next === current) {
      return { path, bytes: this.utf8Bytes(next) };
    }

    await this.deps.writeText(path, next);
    return { path, bytes: this.utf8Bytes(next) };
  }

  async create(
    leaseId: string,
    args: { path: string; content: string }
  ): Promise<AgentBridgeWriteResult> {
    const lease = this.requireLease(leaseId);
    const path = await this.requireWritablePath(args.path, lease, "create", args.content ?? "");
    if (await this.deps.fileExists(path)) {
      throw new Error(`VaultGuard agent bridge refuses to overwrite existing file "${path}" via create.`);
    }

    await this.deps.ensureParentFolders(path);
    await this.deps.writeText(path, args.content ?? "");
    return { path, bytes: this.utf8Bytes(args.content ?? "") };
  }

  // Read-only structural navigation over Obsidian's metadataCache. Resolves
  // the lease exactly like list/search, then builds a VaultGraph whose
  // canSee() re-checks every emitted path against the SAME gates the other
  // tools use: lease scope (matchesAnyScope), exclusion/hidden/traversal
  // (isBlockedPath), and per-file permission (getPermission). The graph must
  // never leak the existence or link structure of a file the lease can't read
  // (AI-GRAPH-CONTEXT.md §4.1).
  async graph(leaseId: string, args: GraphArgs): Promise<GraphResult> {
    const lease = this.requireLease(leaseId);
    if (!lease.allowRead) {
      throw new Error("VaultGuard agent lease does not allow reads.");
    }
    if (!this.deps.makeVaultGraph) {
      throw new Error("VaultGuard agent bridge graph navigation is unavailable in this environment.");
    }

    const graph = this.deps.makeVaultGraph({
      // The lease scope predicate — identical scope semantics to list/search.
      matchesLeaseScope: (path) => this.matchesAnyScope(this.normalizePath(path), lease.scopes),
      // Exclusion + hidden + traversal gate, reused from the read/list path.
      isPathExcluded: (path) => this.isBlockedPath(path),
      getPermission: (path) => this.deps.getPermission(this.normalizePath(path)),
    });

    const op = args.op;
    switch (op) {
      case "neighbors":
        return graph.neighbors(this.requireGraphPath(args, "neighbors"), args.depth);
      case "related":
        return graph.related(this.requireGraphPath(args, "related"), args.depth, args.limit);
      case "tag": {
        const tag = (args.tag ?? "").trim();
        if (!tag) throw new Error("vaultguard_graph op=tag requires a non-empty tag.");
        return graph.tag(tag, args.limit);
      }
      case "orphans":
        return graph.orphans(args.limit);
      case "hubs":
        return graph.hubs(args.limit);
      case "overview":
        return graph.overview();
      default:
        throw new Error(`vaultguard_graph: unknown op "${String(op)}".`);
    }
  }

  private requireGraphPath(args: GraphArgs, op: string): string {
    const path = (args.path ?? "").trim();
    if (!path) {
      throw new Error(`vaultguard_graph op=${op} requires a "path".`);
    }
    return path;
  }

  private async requireWritablePath(
    rawPath: string,
    lease: AgentBridgeLease,
    operation: "create" | "apply_patch",
    preview: string
  ): Promise<string> {
    const path = this.requirePathInLease(rawPath, lease);

    if (!this.isTextPath(path)) {
      throw new Error(`VaultGuard agent bridge refuses to write non-text file "${path}".`);
    }

    if (lease.writeMode === "deny") {
      throw new Error("VaultGuard agent lease is read-only.");
    }

    const permission = await this.deps.getPermission(path);
    if (permission < PermissionLevel.WRITE) {
      throw new Error(`VaultGuard agent bridge: no WRITE permission for "${path}".`);
    }

    if (lease.writeMode === "confirm") {
      const ok = await this.deps.confirmWrite({
        lease: this.summarizeLease(lease),
        operation,
        path,
        preview: this.makeWritePreview(preview),
      });
      if (!ok) {
        throw new Error(`VaultGuard agent bridge write to "${path}" was not approved.`);
      }
    }

    return path;
  }

  private requireReadablePath(rawPath: string, lease: AgentBridgeLease): string {
    return this.requirePathInLease(rawPath, lease);
  }

  private requirePathInLease(rawPath: string, lease: AgentBridgeLease): string {
    const path = this.normalizePath(rawPath);
    if (!path) {
      throw new Error("VaultGuard agent bridge requires a vault-relative path.");
    }
    if (this.isBlockedPath(path)) {
      throw new Error(`VaultGuard agent bridge refuses access to local-only or hidden path "${path}".`);
    }
    if (!this.matchesAnyScope(path, lease.scopes)) {
      throw new Error(`VaultGuard agent lease does not cover "${path}".`);
    }
    return path;
  }

  private isPathAgentReadable(path: string, lease: AgentBridgeLease, toolScope: string | null): boolean {
    if (this.isBlockedPath(path)) return false;
    if (!this.matchesAnyScope(path, lease.scopes)) return false;
    if (toolScope && !this.matchesScope(path, toolScope)) return false;
    return true;
  }

  private isBlockedPath(path: string): boolean {
    const normalized = this.normalizePath(path);
    if (!normalized) return true;
    if (this.hasTraversalSegment(path)) return true;
    const firstSegment = normalized.split("/")[0];
    if (firstSegment.startsWith(".")) return true;
    return this.deps.isPathExcluded(normalized);
  }

  // Reject any `..` segment anywhere in the input — even mid-path
  // (`legit/../etc/passwd`). The scope check happens to catch the simple
  // leading-`..` case today, but a wider scope or a future relaxed
  // matcher could let `legit/../escape` through; this is the
  // defense-in-depth gate that doesn't depend on scope semantics.
  private hasTraversalSegment(path: string): boolean {
    const raw = String(path ?? "").replace(/\\/g, "/");
    return raw.split("/").some((segment) => segment === "..");
  }

  private assertBridgePrereqs(): void {
    if (!this.deps.getSession()) {
      throw new Error("VaultGuard agent bridge requires an active VaultGuard login.");
    }
    if (!this.deps.getServerVaultId()) {
      throw new Error("VaultGuard agent bridge requires this Obsidian folder to be bound to a server vault.");
    }
  }

  private requireLease(leaseId: string): AgentBridgeLease {
    this.assertBridgePrereqs();
    this.pruneExpiredLeases();
    const lease = this.leases.get(leaseId);
    if (!lease) {
      throw new Error("VaultGuard agent lease is missing, expired, or revoked.");
    }
    return lease;
  }

  private pruneExpiredLeases(): void {
    const now = Date.now();
    for (const [id, lease] of this.leases.entries()) {
      if (lease.expiresAtMs <= now) {
        this.leases.delete(id);
        this.tokenIndex.delete(lease.token);
      }
    }
  }

  private summarizeLease(lease: AgentBridgeLease): AgentBridgeLeaseSummary {
    const {
      expiresAtMs: _expiresAtMs,
      token: _token,
      sessionUserId: _sessionUserId,
      sessionVaultId: _sessionVaultId,
      ...summary
    } = lease;
    return { ...summary, scopes: [...summary.scopes], tools: [...summary.tools] };
  }

  private summarizeLeaseWithSecret(lease: AgentBridgeLease): AgentBridgeLeaseSecret {
    return { ...this.summarizeLease(lease), token: lease.token };
  }

  private normalizeScopes(scope: string | string[]): string[] {
    const rawScopes = Array.isArray(scope) ? scope : [scope];
    const scopes = rawScopes.map((item) => this.normalizeScope(item));
    if (scopes.length === 0) {
      throw new Error("VaultGuard agent lease requires at least one scope.");
    }
    return Array.from(new Set(scopes));
  }

  private normalizeScope(scope: string): string {
    const trimmed = scope.trim();
    if (!trimmed) {
      throw new Error("VaultGuard agent lease scope cannot be empty.");
    }
    if (trimmed === "/**" || trimmed === "**") return "/**";

    const normalized = this.normalizePath(trimmed);
    if (!normalized) {
      throw new Error("VaultGuard agent lease scope cannot target the vault root without /**.");
    }
    if (this.isBlockedPath(normalized)) {
      throw new Error(`VaultGuard agent lease cannot target hidden or local-only scope "${trimmed}".`);
    }

    if (trimmed.endsWith("/**")) return `/${normalized.replace(/\/\*\*$/, "")}/**`;
    if (trimmed.endsWith("/*")) return `/${normalized.replace(/\/\*$/, "")}/*`;
    if (trimmed.includes("*")) return `/${normalized}`;
    return `/${normalized}`;
  }

  private normalizePath(path: string): string {
    return String(path ?? "")
      .replace(/\\/g, "/")
      .replace(/^\/+/, "")
      .replace(/\/+$/, "")
      .replace(/\/\/+/g, "/");
  }

  private matchesAnyScope(path: string, scopes: string[]): boolean {
    return scopes.some((scope) => this.matchesScope(path, scope));
  }

  private matchesScope(path: string, scope: string): boolean {
    const normalizedPath = this.normalizePath(path);
    const normalizedScope = scope.startsWith("/") ? scope.slice(1) : scope;

    if (normalizedScope === "**") return true;
    if (normalizedScope.endsWith("/**")) {
      const prefix = normalizedScope.slice(0, -3);
      return normalizedPath === prefix || normalizedPath.startsWith(`${prefix}/`);
    }
    if (normalizedScope.endsWith("/*")) {
      const prefix = normalizedScope.slice(0, -2);
      if (!normalizedPath.startsWith(`${prefix}/`)) return false;
      return normalizedPath.slice(prefix.length + 1).indexOf("/") === -1;
    }
    if (normalizedScope.includes("*")) {
      return globToRegExp(normalizedScope).test(normalizedPath);
    }
    return normalizedPath === normalizedScope || normalizedPath.startsWith(`${normalizedScope}/`);
  }

  private permissionLabel(permission: PermissionLevel): "read" | "write" | "admin" {
    if (permission >= PermissionLevel.ADMIN) return "admin";
    if (permission >= PermissionLevel.WRITE) return "write";
    return "read";
  }

  private isTextPath(path: string): boolean {
    const normalized = this.normalizePath(path).toLocaleLowerCase();
    const slash = normalized.lastIndexOf("/");
    const basename = slash === -1 ? normalized : normalized.slice(slash + 1);
    const dot = basename.lastIndexOf(".");
    if (dot === -1) return true;
    return TEXT_EXTENSIONS.has(basename.slice(dot));
  }

  private cleanAgentName(agentName: string | undefined): string {
    const cleaned = (agentName ?? "LLM agent").trim().replace(/\s+/g, " ");
    return cleaned.slice(0, 80) || "LLM agent";
  }

  private clampNumber(value: number, min: number, max: number): number {
    if (!Number.isFinite(value)) return min;
    return Math.max(min, Math.min(max, Math.floor(value)));
  }

  private randomId(prefix: string): string {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
    return `${prefix}_${hex}`;
  }

  private makeSnippet(line: string, index: number, queryLength: number): string {
    const radius = 100;
    const start = Math.max(0, index - radius);
    const end = Math.min(line.length, index + Math.max(queryLength, 1) + radius);
    const prefix = start > 0 ? "..." : "";
    const suffix = end < line.length ? "..." : "";
    return `${prefix}${line.slice(start, end)}${suffix}`;
  }

  private makeWritePreview(value: string): string {
    const normalized = value.replace(/\r\n/g, "\n");
    if (normalized.length <= 2000) return normalized;
    return `${normalized.slice(0, 2000)}\n...`;
  }

  private utf8Bytes(value: string): number {
    return new TextEncoder().encode(value).byteLength;
  }

  private truncateUtf8(value: string, maxBytes: number): string {
    const encoder = new TextEncoder();
    let bytes = 0;
    let out = "";
    for (const char of value) {
      const charBytes = encoder.encode(char).byteLength;
      if (bytes + charBytes > maxBytes) break;
      out += char;
      bytes += charBytes;
    }
    return out;
  }

  private loadNodeHttp(): NodeHttpModule {
    const maybeWindow = typeof window !== "undefined" ? (window as unknown as Record<string, unknown>) : {};
    const maybeGlobal = globalThis as unknown as Record<string, unknown>;
    const req =
      typeof maybeWindow.require === "function"
        ? maybeWindow.require
        : typeof maybeGlobal.require === "function"
          ? maybeGlobal.require
          : null;

    if (!req) {
      throw new Error(
        "VaultGuard agent bridge server is available only in desktop Obsidian with Node integration."
      );
    }

    const http = req("http") as NodeHttpModule;
    if (!http || typeof http.createServer !== "function") {
      throw new Error("VaultGuard agent bridge could not load Node's http module.");
    }
    return http;
  }

  private async handleHttpRequest(req: NodeIncomingMessage, res: NodeServerResponse): Promise<void> {
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("Cache-Control", "no-store");

    const url = req.url ?? "";
    if (req.method === "POST" && url === "/mcp") {
      await this.handleMcpRequest(req, res);
      return;
    }
    if (req.method === "POST" && url === "/rpc") {
      await this.handleRpcRequest(req, res);
      return;
    }
    this.writeJson(res, 404, { ok: false, error: { message: "Not found" } });
  }

  private async handleRpcRequest(req: NodeIncomingMessage, res: NodeServerResponse): Promise<void> {
    try {
      const lease = this.resolveLeaseFromBearer(req);
      if (!lease) {
        this.writeJson(res, 401, { ok: false, error: { message: "Unauthorized" } });
        return;
      }

      const body = await this.readHttpBody(req);
      const payload = JSON.parse(body) as {
        tool?: AgentBridgeToolName;
        leaseId?: string;
        args?: Record<string, unknown>;
        arguments?: Record<string, unknown>;
      };
      const tool = payload.tool;
      const args = (payload.args ?? payload.arguments ?? {}) as Record<string, unknown>;

      if (!tool || !TOOLS.includes(tool)) {
        this.writeJson(res, 400, { ok: false, error: { message: "Unknown or missing tool." } });
        return;
      }
      // body.leaseId is optional; if present it must match the bearer's
      // lease (defense-in-depth against a misconfigured client mixing
      // tokens between leases).
      if (payload.leaseId && payload.leaseId !== lease.leaseId) {
        this.writeJson(res, 400, {
          ok: false,
          error: { message: "leaseId in request body does not match bearer token." },
        });
        return;
      }

      const result = await this.invokeToolWithAudit(tool, lease, args, "rpc");
      this.writeJson(res, 200, { ok: true, result });
    } catch (err) {
      this.writeJson(res, 400, {
        ok: false,
        error: {
          message: err instanceof Error ? err.message : String(err),
        },
      });
    }
  }

  // MCP Streamable-HTTP transport. Per-lease bearer is the source of truth:
  // the bearer alone identifies which lease the request runs under, so the
  // user only has to keep one secret in their MCP config. We still accept
  // an optional X-VaultGuard-Lease header for clients that already wire it
  // up, but it has to match the bearer's lease.
  private async handleMcpRequest(req: NodeIncomingMessage, res: NodeServerResponse): Promise<void> {
    const lease = this.resolveLeaseFromBearer(req);
    if (!lease) {
      this.writeJson(res, 401, this.makeJsonRpcError(null, -32001, "Unauthorized"));
      return;
    }
    const headerLeaseId = this.extractLeaseHeader(req);
    if (headerLeaseId && headerLeaseId !== lease.leaseId) {
      this.writeJson(
        res,
        401,
        this.makeJsonRpcError(null, -32001, "X-VaultGuard-Lease header does not match bearer token.")
      );
      return;
    }

    let request: JsonRpcRequest;
    try {
      const body = await this.readHttpBody(req);
      request = JSON.parse(body) as JsonRpcRequest;
    } catch (err) {
      this.writeJson(
        res,
        400,
        this.makeJsonRpcError(null, -32700, err instanceof Error ? err.message : "Parse error")
      );
      return;
    }

    const id = request.id ?? null;
    const method = request.method;
    const params = (request.params ?? {}) as Record<string, unknown>;

    // Notifications (no `id`) are fire-and-forget. Per spec we acknowledge
    // with 202 and an empty body.
    const isNotification = id === null && typeof method === "string" && method.startsWith("notifications/");
    if (isNotification) {
      res.statusCode = 202;
      res.end();
      return;
    }

    try {
      switch (method) {
        case "initialize":
          this.writeJson(res, 200, this.makeJsonRpcResult(id, this.handleMcpInitialize()));
          return;
        case "ping":
          this.writeJson(res, 200, this.makeJsonRpcResult(id, {}));
          return;
        case "tools/list":
          this.writeJson(res, 200, this.makeJsonRpcResult(id, this.handleMcpToolsList()));
          return;
        case "tools/call": {
          const result = await this.handleMcpToolsCall(lease, params);
          this.writeJson(res, 200, this.makeJsonRpcResult(id, result));
          return;
        }
        default:
          this.writeJson(
            res,
            200,
            this.makeJsonRpcError(id, -32601, `Method not found: ${method ?? "(none)"}`)
          );
          return;
      }
    } catch (err) {
      this.writeJson(
        res,
        200,
        this.makeJsonRpcError(id, -32603, err instanceof Error ? err.message : String(err))
      );
    }
  }

  private handleMcpInitialize(): Record<string, unknown> {
    return {
      protocolVersion: MCP_PROTOCOL_VERSION,
      capabilities: {
        // We expose tools and react to lease state; resources/prompts are
        // intentionally not advertised (would let the client cache content
        // outside our permission gates).
        tools: { listChanged: false },
      },
      serverInfo: {
        name: "vaultguard-agent-bridge",
        version: "1",
      },
      instructions:
        "VaultGuard exposes vault files through six tools: list, search, read, apply_patch, create, graph. All paths are vault-relative. Hidden files (.obsidian, .trash, ...) are blocked. Writes obey the lease writeMode (deny / confirm / allow). Prefer graph (related/neighbors/tag) to discover a small candidate set, then read only the few files that matter. Do not ask the user for a filesystem path; use list/search/graph to discover files first.",
    };
  }

  private handleMcpToolsList(): Record<string, unknown> {
    return {
      tools: Object.entries(MCP_TOOLS).map(([name, def]) => ({
        name,
        description: def.description,
        inputSchema: def.inputSchema,
      })),
    };
  }

  private async handleMcpToolsCall(
    lease: AgentBridgeLease,
    params: Record<string, unknown>
  ): Promise<Record<string, unknown>> {
    const name = typeof params.name === "string" ? params.name : "";
    const args = (params.arguments ?? {}) as Record<string, unknown>;
    const def = MCP_TOOLS[name];
    if (!def) {
      return this.makeMcpToolError(`Unknown tool "${name}".`);
    }

    try {
      const result = await this.invokeToolWithAudit(def.internal, lease, args, "mcp");
      // MCP expects content as an array. We return the JSON-stringified
      // tool result as a single text item — the model can parse it back to
      // structured data, and humans reviewing transcripts get a readable
      // payload. (Could be split into per-file content blocks later if
      // models start preferring that shape.)
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (err) {
      return this.makeMcpToolError(err instanceof Error ? err.message : String(err));
    }
  }

  private makeMcpToolError(message: string): Record<string, unknown> {
    // Tool-level errors are surfaced via `isError: true` on the result, NOT
    // via JSON-RPC error. Spec is explicit: JSON-RPC errors are reserved
    // for transport/protocol issues. The model needs to see the message
    // so it can recover (e.g. retry with a different path).
    return {
      isError: true,
      content: [
        {
          type: "text",
          text: message,
        },
      ],
    };
  }

  private makeJsonRpcResult(id: string | number | null, result: unknown): Record<string, unknown> {
    return { jsonrpc: "2.0", id, result };
  }

  private makeJsonRpcError(
    id: string | number | null,
    code: number,
    message: string
  ): Record<string, unknown> {
    return { jsonrpc: "2.0", id, error: { code, message } };
  }

  private extractLeaseHeader(req: NodeIncomingMessage): string | null {
    const header = req.headers["x-vaultguard-lease"];
    const value = Array.isArray(header) ? header[0] : header;
    if (typeof value === "string" && value.trim().length > 0) {
      return value.trim();
    }
    return null;
  }

  // Each request is bound to a single lease via its bearer token. The
  // token-to-lease lookup is the only auth check on the wire — the lease
  // itself carries the scope, writeMode, and audit identity.
  private resolveLeaseFromBearer(req: NodeIncomingMessage): AgentBridgeLease | null {
    const header = req.headers.authorization;
    const auth = Array.isArray(header) ? header[0] : header;
    if (typeof auth !== "string" || !auth.startsWith("Bearer ")) return null;
    const token = auth.slice("Bearer ".length).trim();
    if (!token) return null;
    this.pruneExpiredLeases();
    const leaseId = this.tokenIndex.get(token);
    if (!leaseId) return null;
    return this.leases.get(leaseId) ?? null;
  }

  // Wrap every tool invocation with an audit emit. Outcome is "success" if
  // executeTool resolves, "denied" if the lease/scope/permission gates
  // throw, "error" otherwise. We only record the *shape* of the args
  // (tool, path, scope, query, lengths) — never the diff/content body —
  // so audit logs don't accidentally retain plaintext.
  private async invokeToolWithAudit(
    tool: AgentBridgeToolName,
    lease: AgentBridgeLease,
    args: Record<string, unknown>,
    transport: "rpc" | "mcp" | "inproc"
  ): Promise<unknown> {
    const auditMeta: Record<string, unknown> = {
      leaseId: lease.leaseId,
      agentName: lease.agentName,
      persistent: lease.persistent,
      transport,
      tool,
    };
    if (typeof args.path === "string") auditMeta.path = args.path;
    if (typeof args.scope === "string") auditMeta.scope = args.scope;
    // Graph calls: record op + tag + depth (structure-only, never content).
    if (typeof args.op === "string") auditMeta.op = args.op;
    if (typeof args.tag === "string") auditMeta.tag = args.tag;
    if (typeof args.depth === "number") auditMeta.depth = args.depth;
    if (typeof args.query === "string") {
      auditMeta.queryLength = args.query.length;
    }
    if (typeof args.diff === "string") {
      auditMeta.diffLength = args.diff.length;
    }
    if (typeof args.content === "string") {
      auditMeta.contentLength = args.content.length;
    }
    try {
      // Wrap dispatch so every downstream API call (files.read, files.write,
      // etc.) carries X-VG-Agent-Name / X-VG-Lease-Id and the resulting
      // backend audit rows are attributed to this lease. Wrapping at the
      // dispatch boundary (rather than inside each individual tool method)
      // means new tools added later inherit attribution automatically.
      // The audit emit calls themselves are intentionally OUTSIDE the
      // wrapper — they hit the dedicated bridge.* endpoint which already
      // carries `agentName` / `leaseId` in its body, so adding the headers
      // would be redundant.
      const result = await this.deps.withAgentContext(
        lease.agentName,
        lease.leaseId,
        () => this.executeTool(tool, lease.leaseId, args)
      );
      void this.deps.emitAudit("bridge.tool_invoked", auditMeta.path as string ?? null, {
        ...auditMeta,
        outcome: "success",
      });
      return result;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const denied =
        message.includes("does not allow") ||
        message.includes("refuses access") ||
        message.includes("not approved") ||
        message.includes("read-only") ||
        message.includes("does not cover") ||
        message.includes("WRITE permission");
      void this.deps.emitAudit("bridge.tool_invoked", auditMeta.path as string ?? null, {
        ...auditMeta,
        outcome: denied ? "denied" : "error",
        error: message,
      });
      throw err;
    }
  }

  private async executeTool(
    tool: AgentBridgeToolName,
    leaseId: string,
    args: Record<string, unknown>
  ): Promise<unknown> {
    switch (tool) {
      case "vaultguard_list":
        return this.list(leaseId, {
          scope: typeof args.scope === "string" ? args.scope : undefined,
          limit: typeof args.limit === "number" ? args.limit : undefined,
        });
      case "vaultguard_search":
        return this.search(leaseId, {
          query: typeof args.query === "string" ? args.query : "",
          scope: typeof args.scope === "string" ? args.scope : undefined,
          limit: typeof args.limit === "number" ? args.limit : undefined,
        });
      case "vaultguard_read":
        return this.read(leaseId, {
          path: typeof args.path === "string" ? args.path : "",
          maxBytes: typeof args.maxBytes === "number" ? args.maxBytes : undefined,
        });
      case "vaultguard_apply_patch":
        return this.applyPatch(leaseId, {
          path: typeof args.path === "string" ? args.path : "",
          diff: typeof args.diff === "string" ? args.diff : "",
        });
      case "vaultguard_create":
        return this.create(leaseId, {
          path: typeof args.path === "string" ? args.path : "",
          content: typeof args.content === "string" ? args.content : "",
        });
      case "vaultguard_graph":
        return this.graph(leaseId, {
          op: (typeof args.op === "string" ? args.op : "") as GraphArgs["op"],
          path: typeof args.path === "string" ? args.path : undefined,
          tag: typeof args.tag === "string" ? args.tag : undefined,
          depth: typeof args.depth === "number" ? args.depth : undefined,
          limit: typeof args.limit === "number" ? args.limit : undefined,
        });
    }
  }

  private readHttpBody(req: NodeIncomingMessage): Promise<string> {
    return new Promise((resolve, reject) => {
      let size = 0;
      const chunks: string[] = [];
      req.on("data", (chunk) => {
        const text = typeof chunk === "string" ? chunk : new TextDecoder().decode(chunk);
        size += text.length;
        if (size > HTTP_BODY_LIMIT_BYTES) {
          reject(new Error("VaultGuard agent bridge request body is too large."));
          return;
        }
        chunks.push(text);
      });
      req.on("end", () => resolve(chunks.join("")));
      req.on("error", reject);
    });
  }

  private writeJson(res: NodeServerResponse, statusCode: number, body: unknown): void {
    res.statusCode = statusCode;
    res.end(JSON.stringify(body));
  }
}

function globToRegExp(pattern: string): RegExp {
  let regex = "^";
  for (let i = 0; i < pattern.length; i++) {
    const char = pattern[i];
    if (char === "*") {
      if (pattern[i + 1] === "*") {
        regex += ".*";
        i += 1;
      } else {
        regex += "[^/]*";
      }
    } else if (char === "?") {
      regex += "[^/]";
    } else if ("\\.^$+{}()|[]".includes(char)) {
      regex += `\\${char}`;
    } else {
      regex += char;
    }
  }
  regex += "$";
  return new RegExp(regex);
}

export function applyUnifiedDiff(original: string, diff: string): string {
  const diffLines = diff.replace(/\r\n/g, "\n").split("\n");
  const hunks: Array<{
    oldStart: number;
    lines: string[];
  }> = [];

  for (let i = 0; i < diffLines.length; i++) {
    const line = diffLines[i];
    const match = /^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@/.exec(line);
    if (!match) continue;

    const hunkLines: string[] = [];
    i += 1;
    while (i < diffLines.length && !diffLines[i].startsWith("@@ ")) {
      const hunkLine = diffLines[i];
      if (hunkLine.startsWith("\\ No newline at end of file")) {
        i += 1;
        continue;
      }
      if (hunkLine === "" && i === diffLines.length - 1) break;
      hunkLines.push(hunkLine);
      i += 1;
    }
    i -= 1;
    hunks.push({
      oldStart: Number(match[1]),
      lines: hunkLines,
    });
  }

  if (hunks.length === 0) {
    throw new Error("VaultGuard agent bridge only accepts unified diffs with @@ hunks.");
  }

  const hadFinalNewline = original.endsWith("\n");
  const originalLines = original.split("\n");
  if (hadFinalNewline) originalLines.pop();

  const result: string[] = [];
  let originalCursor = 0;

  for (const hunk of hunks) {
    const hunkStart = hunk.oldStart - 1;
    if (hunkStart < originalCursor || hunkStart > originalLines.length) {
      throw new Error("Unified diff hunk is out of range for the current file.");
    }

    result.push(...originalLines.slice(originalCursor, hunkStart));
    let cursor = hunkStart;

    for (const hunkLine of hunk.lines) {
      const prefix = hunkLine[0];
      const text = hunkLine.slice(1);

      if (prefix === " ") {
        assertPatchLine(originalLines[cursor], text);
        result.push(text);
        cursor += 1;
      } else if (prefix === "-") {
        assertPatchLine(originalLines[cursor], text);
        cursor += 1;
      } else if (prefix === "+") {
        result.push(text);
      } else if (hunkLine === "") {
        assertPatchLine(originalLines[cursor], "");
        result.push("");
        cursor += 1;
      } else {
        throw new Error(`Unsupported unified diff line prefix "${prefix}".`);
      }
    }

    originalCursor = cursor;
  }

  result.push(...originalLines.slice(originalCursor));
  return result.join("\n") + (hadFinalNewline ? "\n" : "");
}

function assertPatchLine(actual: string | undefined, expected: string): void {
  if (actual !== expected) {
    throw new Error("Unified diff does not apply cleanly to the current file.");
  }
}
