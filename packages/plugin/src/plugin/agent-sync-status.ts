/**
 * Closed, content-redacted projection of local VaultGuard sync state.
 *
 * The projector never starts synchronization, never returns queue entries,
 * conflicts, keys, endpoints, paths, or raw diagnostics, and defaults every
 * remote-verification claim to false. A future remote-evidence contract must be
 * introduced explicitly rather than inferring success from a local timestamp.
 */

export const AGENT_SYNC_MAX_COUNT = 1_000_000;

export type AgentSyncEngineState =
  | "idle"
  | "syncing"
  | "error"
  | "offline"
  | "paused"
  | "disabled"
  | "unavailable"
  | "unknown";

export type AgentSyncConnectionState =
  | "online"
  | "offline"
  | "reconnecting"
  | "local-only"
  | "unbound"
  | "unavailable"
  | "unknown";

export interface AgentSyncStatus {
  vaultId: string | null;
  engineState: AgentSyncEngineState;
  connectionState: AgentSyncConnectionState;
  offline: boolean;
  pendingChanges: number;
  queuedOperations: number;
  conflictCount: number;
  lastSuccessfulSync: string | null;
  lastError: string | null;
  remoteVerified: false;
  observedAt: string;
}

export interface AgentSyncRuntimeState {
  status?: unknown;
  pendingChanges?: unknown;
  conflicts?: unknown;
  lastSync?: unknown;
  lastError?: unknown;
}

export interface AgentSyncConnectionRuntimeState {
  status?: unknown;
}

export type AgentSyncStatusSource =
  | {
      kind: "vaultguard";
      observedAt: string;
      vaultId: string | null;
      syncState?: AgentSyncRuntimeState | null;
      connectionState?: AgentSyncConnectionRuntimeState | null;
      offlineQueueLength?: unknown;
    }
  | {
      kind: "local-project-memory";
      observedAt: string;
    }
  | {
      kind: "unavailable";
      observedAt: string;
    };

function invalid(message: string): never {
  throw new Error(`Invalid sync status source: ${message}`);
}

function normalizedTimestamp(value: unknown, label: string): string | null {
  if (value === null || value === undefined) return null;
  if (typeof value !== "string" || value.length > 100) {
    return label === "observedAt" ? invalid(`${label} must be an ISO timestamp.`) : null;
  }
  const timestamp = new Date(value);
  if (!Number.isFinite(timestamp.getTime())) {
    return label === "observedAt" ? invalid(`${label} must be an ISO timestamp.`) : null;
  }
  return timestamp.toISOString();
}

function normalizedVaultId(value: string | null): string | null {
  if (value === null) return null;
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value)) {
    return invalid("vaultId is not a bounded opaque identifier.");
  }
  return value;
}

function boundedCount(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) return 0;
  return Math.min(Math.floor(value), AGENT_SYNC_MAX_COUNT);
}

function conflictCount(value: unknown): number {
  if (Array.isArray(value)) return Math.min(value.length, AGENT_SYNC_MAX_COUNT);
  return boundedCount(value);
}

function engineState(value: unknown): AgentSyncEngineState {
  switch (value) {
    case "idle":
    case "syncing":
    case "error":
    case "offline":
    case "paused":
      return value;
    default:
      return "unknown";
  }
}

function connectionState(value: unknown): AgentSyncConnectionState {
  switch (value) {
    case "online":
    case "offline":
    case "reconnecting":
      return value;
    default:
      return "unknown";
  }
}

/**
 * Convert an arbitrary runtime error to a small category. Raw text is never
 * copied, so a provider error containing note content, paths, endpoints,
 * credentials, or queue payloads cannot become an Agent Bridge side channel.
 */
export function redactAgentSyncError(value: unknown): string | null {
  if (value === null || value === undefined || value === "") return null;
  const raw = value instanceof Error
    ? value.message
    : typeof value === "string"
      ? value
      : "";
  const lower = raw.toLowerCase();
  if (/unauth|authentication|expired session|login/.test(lower)) {
    return "authentication failed";
  }
  if (/forbidden|permission|authoriz|access denied/.test(lower)) {
    return "authorization failed";
  }
  if (/timeout|timed out|deadline/.test(lower)) return "sync timeout";
  if (/network|dns|socket|connect|offline|unreachable/.test(lower)) {
    return "network unavailable";
  }
  if (/conflict|precondition|stale/.test(lower)) return "conflict requires attention";
  if (/encrypt|decrypt|cipher|key lease/.test(lower)) return "encryption operation failed";
  if (/storage|quota|disk|upload|download|object/.test(lower)) return "storage operation failed";
  return "sync operation failed";
}

function fixedStatus(
  observedAt: string,
  values: Pick<AgentSyncStatus, "vaultId" | "engineState" | "connectionState" | "lastError">,
): AgentSyncStatus {
  return {
    ...values,
    offline: true,
    pendingChanges: 0,
    queuedOperations: 0,
    conflictCount: 0,
    lastSuccessfulSync: null,
    remoteVerified: false,
    observedAt,
  };
}

export function projectAgentSyncStatus(source: AgentSyncStatusSource): AgentSyncStatus {
  if (!source || typeof source !== "object") return invalid("input must be an object.");
  const observedAt = normalizedTimestamp(source.observedAt, "observedAt");
  if (observedAt === null) return invalid("observedAt is required.");

  if (source.kind === "unavailable") {
    return fixedStatus(observedAt, {
      vaultId: null,
      engineState: "unavailable",
      connectionState: "unavailable",
      lastError: "sync status provider unavailable",
    });
  }

  if (source.kind === "local-project-memory") {
    return fixedStatus(observedAt, {
      vaultId: "local-project-memory",
      engineState: "disabled",
      connectionState: "local-only",
      lastError: null,
    });
  }

  if (source.kind !== "vaultguard") return invalid("kind is unsupported.");
  const vaultId = normalizedVaultId(source.vaultId);
  if (vaultId === null) {
    return fixedStatus(observedAt, {
      vaultId: null,
      engineState: "disabled",
      connectionState: "unbound",
      lastError: null,
    });
  }

  const runtime = source.syncState ?? {};
  const engine = engineState(runtime.status);
  const connection = connectionState(source.connectionState?.status);
  return {
    vaultId,
    engineState: engine,
    connectionState: connection,
    offline: connection !== "online" || engine === "offline",
    pendingChanges: boundedCount(runtime.pendingChanges),
    queuedOperations: boundedCount(source.offlineQueueLength),
    conflictCount: conflictCount(runtime.conflicts),
    lastSuccessfulSync: normalizedTimestamp(runtime.lastSync, "lastSuccessfulSync"),
    lastError: redactAgentSyncError(runtime.lastError),
    // Local state is not remote proof, even if lastSync is populated.
    remoteVerified: false,
    observedAt,
  };
}
