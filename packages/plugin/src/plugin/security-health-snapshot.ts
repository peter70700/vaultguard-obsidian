export const SECURITY_HEALTH_SCHEMA_VERSION = 1 as const;

export const SECURITY_HEALTH_CHECK_IDS = [
  "at_rest_coverage",
  "plaintext_anomalies",
  "secure_storage",
  "session_freshness",
  "mfa_freshness",
  "vault_binding",
  "key_lease",
  "sync_queue",
  "sync_conflicts",
  "audit_delivery",
  "connector_leases",
  "provider_egress",
  "version_update",
] as const;

export type SecurityHealthCheckId = (typeof SECURITY_HEALTH_CHECK_IDS)[number];
export type SecurityHealthStatus = "healthy" | "warning" | "error" | "unavailable" | "unverified";

export type SecurityHealthReasonCode =
  | "configured"
  | "current"
  | "expired"
  | "partial_coverage"
  | "anomaly_detected"
  | "queue_pending"
  | "conflict_detected"
  | "provider_unavailable"
  | "not_observed"
  | "stale_observation"
  | "contradictory_observation"
  | "invalid_observation";

export interface SecurityHealthCheck {
  checkId: SecurityHealthCheckId;
  status: SecurityHealthStatus;
  reasonCode: SecurityHealthReasonCode;
  observedAt: string;
  freshness: "current" | "stale" | "unknown";
}

export interface SecurityHealthSnapshot {
  schemaVersion: typeof SECURITY_HEALTH_SCHEMA_VERSION;
  observedAt: string;
  overallStatus: SecurityHealthStatus;
  checks: SecurityHealthCheck[];
}

const STATUS_RANK: Readonly<Record<SecurityHealthStatus, number>> = {
  healthy: 1,
  unverified: 2,
  unavailable: 3,
  warning: 4,
  error: 5,
};

const STATUS_VALUES = new Set<SecurityHealthStatus>([
  "healthy",
  "warning",
  "error",
  "unavailable",
  "unverified",
]);

const REASON_VALUES = new Set<SecurityHealthReasonCode>([
  "configured",
  "current",
  "expired",
  "partial_coverage",
  "anomaly_detected",
  "queue_pending",
  "conflict_detected",
  "provider_unavailable",
  "not_observed",
  "stale_observation",
  "contradictory_observation",
  "invalid_observation",
]);

export function createSecurityHealthSnapshot(input: unknown): SecurityHealthSnapshot {
  const record = asRecord(input);
  const observedAt = normalizeTimestamp(record?.observedAt) ?? new Date(0).toISOString();
  const nowMs = Date.parse(observedAt);
  const staleAfterMs = normalizeStaleAfter(record?.staleAfterMs);
  const rawObservations = Array.isArray(record?.observations) ? record.observations : [];
  const grouped = new Map<SecurityHealthCheckId, ParsedObservation[]>();

  for (const value of rawObservations.slice(0, 256)) {
    const parsed = parseObservation(value);
    if (!parsed) continue;
    const group = grouped.get(parsed.checkId) ?? [];
    group.push(parsed);
    grouped.set(parsed.checkId, group);
  }

  const checks = SECURITY_HEALTH_CHECK_IDS.map((checkId): SecurityHealthCheck => {
    const observations = grouped.get(checkId) ?? [];
    if (observations.length === 0) return missingCheck(checkId, observedAt);

    const signatures = new Set(observations.map((item) => `${item.status}:${item.reasonCode}`));
    if (signatures.size > 1) {
      return {
        checkId,
        status: "error",
        reasonCode: "contradictory_observation",
        observedAt,
        freshness: "current",
      };
    }

    const latest = observations.sort(
      (left, right) => Date.parse(right.observedAt) - Date.parse(left.observedAt),
    )[0];
    const ageMs = nowMs - Date.parse(latest.observedAt);
    if (!Number.isFinite(ageMs) || ageMs < 0) {
      return {
        checkId,
        status: "unavailable",
        reasonCode: "invalid_observation",
        observedAt,
        freshness: "unknown",
      };
    }
    if (ageMs > staleAfterMs) {
      return {
        checkId,
        status: "unverified",
        reasonCode: "stale_observation",
        observedAt: latest.observedAt,
        freshness: "stale",
      };
    }
    return { ...latest, freshness: "current" };
  });

  const overallStatus = checks.reduce<SecurityHealthStatus>(
    (current, check) => (STATUS_RANK[check.status] > STATUS_RANK[current] ? check.status : current),
    "healthy",
  );
  return {
    schemaVersion: SECURITY_HEALTH_SCHEMA_VERSION,
    observedAt,
    overallStatus,
    checks,
  };
}

export function exportSecurityHealthSnapshot(snapshot: SecurityHealthSnapshot): string {
  const observedAt = normalizeTimestamp(snapshot.observedAt) ?? new Date(0).toISOString();
  const checks = SECURITY_HEALTH_CHECK_IDS.map((checkId) => {
    const raw = snapshot.checks.find((candidate) => candidate.checkId === checkId);
    if (!raw || !STATUS_VALUES.has(raw.status) || !REASON_VALUES.has(raw.reasonCode)) {
      return missingCheck(checkId, observedAt);
    }
    return {
      checkId,
      status: raw.status,
      reasonCode: raw.reasonCode,
      observedAt: normalizeTimestamp(raw.observedAt) ?? observedAt,
      freshness:
        raw.freshness === "current" || raw.freshness === "stale" || raw.freshness === "unknown"
          ? raw.freshness
          : "unknown",
    };
  });
  const overallStatus = checks.reduce<SecurityHealthStatus>(
    (current, check) => (STATUS_RANK[check.status] > STATUS_RANK[current] ? check.status : current),
    "healthy",
  );
  return `${JSON.stringify(
    {
      schemaVersion: SECURITY_HEALTH_SCHEMA_VERSION,
      observedAt,
      overallStatus,
      checks,
    },
    null,
    2,
  )}\n`;
}

interface ParsedObservation {
  checkId: SecurityHealthCheckId;
  status: SecurityHealthStatus;
  reasonCode: SecurityHealthReasonCode;
  observedAt: string;
}

function parseObservation(value: unknown): ParsedObservation | null {
  const record = asRecord(value);
  if (!record || !SECURITY_HEALTH_CHECK_IDS.includes(record.checkId as SecurityHealthCheckId)) {
    return null;
  }
  const observedAt = normalizeTimestamp(record.observedAt);
  if (!observedAt || !STATUS_VALUES.has(record.status as SecurityHealthStatus)) return null;
  if (!REASON_VALUES.has(record.reasonCode as SecurityHealthReasonCode)) {
    return {
      checkId: record.checkId as SecurityHealthCheckId,
      status: "unavailable",
      reasonCode: "invalid_observation",
      observedAt,
    };
  }
  return {
    checkId: record.checkId as SecurityHealthCheckId,
    status: record.status as SecurityHealthStatus,
    reasonCode: record.reasonCode as SecurityHealthReasonCode,
    observedAt,
  };
}

function missingCheck(checkId: SecurityHealthCheckId, observedAt: string): SecurityHealthCheck {
  return {
    checkId,
    status: "unverified",
    reasonCode: "not_observed",
    observedAt,
    freshness: "unknown",
  };
}

function normalizeTimestamp(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? new Date(timestamp).toISOString() : null;
}

function normalizeStaleAfter(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) && value >= 1_000
    ? Math.min(Math.floor(value), 30 * 24 * 60 * 60 * 1_000)
    : 5 * 60 * 1_000;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}
