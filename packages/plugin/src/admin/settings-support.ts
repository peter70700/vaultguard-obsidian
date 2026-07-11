import type { OrgSettingsResponse } from "../api/client";

export function shouldUseFallbackOrgSettings(error: unknown): boolean {
  const apiStatusCode =
    error &&
    typeof error === "object" &&
    "apiError" in error &&
    error.apiError &&
    typeof error.apiError === "object" &&
    "statusCode" in error.apiError &&
    typeof error.apiError.statusCode === "number"
      ? error.apiError.statusCode
      : undefined;
  const message =
    error instanceof Error
      ? error.message
      : typeof error === "string"
        ? error
        : "";
  const normalized = message.toLowerCase();

  return (
    apiStatusCode === 500 ||
    (typeof apiStatusCode === "number" && apiStatusCode >= 502 && apiStatusCode <= 504) ||
    (error instanceof Error && error.name === "ServerError") ||
    normalized.includes("pointing at a website or routed page") ||
    normalized.includes("missing authentication token") ||
    normalized.includes("route not found") ||
    normalized.includes("not found") ||
    normalized.includes("internal server error") ||
    normalized.includes("service unavailable") ||
    normalized.includes("bad gateway") ||
    normalized.includes("gateway timeout")
  );
}

export function buildFallbackOrgSettings(
  orgId: string,
  orgSlug?: string | null
): OrgSettingsResponse {
  return {
    orgId: orgId || "unknown",
    orgName: deriveOrgName(orgSlug),
    syncMode: "periodic",
    syncIntervalMinutes: 1,
    enforceEncryption: true,
    maxSessionDurationHours: 720,
    requireMfa: false,
    allowedDomains: [],
    retentionDays: 365,
    autoLockMinutes: 30,
    // Offline / unknown-org fallback: "lock" mirrors the server default
    // (DEFAULT_ORG_SETTINGS, quick 260711-l2e) so an idle vault locks instead of
    // forcing a re-login. Safe offline — the old "you can't unlock a locked vault
    // offline" worry no longer holds: with no PIN the plugin keeps the session
    // (branch 3, never logs out on idle); with a PIN the lock is offline-unlockable.
    idleAction: "lock",
  };
}

function deriveOrgName(orgSlug?: string | null): string {
  if (!orgSlug) {
    return "Current Organization";
  }

  return orgSlug
    .split("-")
    .filter((segment) => segment.length > 0)
    .map((segment) => segment[0].toUpperCase() + segment.slice(1))
    .join(" ");
}
