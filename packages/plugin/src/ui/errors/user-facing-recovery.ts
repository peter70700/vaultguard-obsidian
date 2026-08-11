export type UserFacingRecoveryCategory =
  | "authentication_required"
  | "authorization_denied"
  | "vault_binding"
  | "provider_unavailable"
  | "executable_missing"
  | "network_unavailable"
  | "rate_limited"
  | "unknown";

export type UserFacingRecoveryActionCode =
  | "reauthenticate"
  | "refresh_binding"
  | "select_vault"
  | "request_access"
  | "reconnect_provider"
  | "install_executable"
  | "retry"
  | "retry_later"
  | "open_diagnostics";

export type UserFacingRecoverySummaryCode =
  | "sign_in_required"
  | "access_denied"
  | "vault_binding_needs_attention"
  | "provider_unavailable"
  | "executable_missing"
  | "network_unavailable"
  | "rate_limited"
  | "unexpected_failure";

export interface UserFacingRecoveryGuidance {
  category: UserFacingRecoveryCategory;
  summaryCode: UserFacingRecoverySummaryCode;
  retryable: boolean;
  actionCodes: UserFacingRecoveryActionCode[];
}

const TRUSTED_CODE_GUIDANCE: Readonly<Record<string, UserFacingRecoveryGuidance>> = {
  SESSION_EXPIRED: guidance("authentication_required", "sign_in_required", false, ["reauthenticate"]),
  AUTHENTICATION_REQUIRED: guidance("authentication_required", "sign_in_required", false, ["reauthenticate"]),
  UNAUTHORIZED: guidance("authentication_required", "sign_in_required", false, ["reauthenticate"]),
  VAULT_BINDING_MISSING: guidance("vault_binding", "vault_binding_needs_attention", false, [
    "refresh_binding",
    "select_vault",
  ]),
  VAULT_BINDING_STALE: guidance("vault_binding", "vault_binding_needs_attention", false, [
    "refresh_binding",
    "select_vault",
  ]),
  PERMISSION_DENIED: guidance("authorization_denied", "access_denied", false, ["request_access"]),
  FORBIDDEN: guidance("authorization_denied", "access_denied", false, ["request_access"]),
  PROVIDER_OFFLINE: guidance("provider_unavailable", "provider_unavailable", true, [
    "reconnect_provider",
    "retry",
  ]),
  PROVIDER_AUTH_REQUIRED: guidance("provider_unavailable", "provider_unavailable", false, [
    "reconnect_provider",
  ]),
  EXECUTABLE_NOT_FOUND: guidance("executable_missing", "executable_missing", true, [
    "install_executable",
    "retry",
  ]),
  NETWORK_OFFLINE: guidance("network_unavailable", "network_unavailable", true, ["retry"]),
  CONNECTION_FAILED: guidance("network_unavailable", "network_unavailable", true, ["retry"]),
  RATE_LIMITED: guidance("rate_limited", "rate_limited", true, ["retry_later"]),
};

export function classifyUserFacingRecovery(input: unknown): UserFacingRecoveryGuidance {
  const record = asRecord(input);
  const authenticated = record?.authenticated === true;
  const httpStatus = typeof record?.httpStatus === "number" ? record.httpStatus : null;

  // Never disclose whether a vault, identity, provider, or permission exists to
  // a caller that has not established an authenticated session.
  if (!authenticated || httpStatus === 401) {
    return cloneGuidance(TRUSTED_CODE_GUIDANCE.AUTHENTICATION_REQUIRED);
  }

  const code = typeof record?.code === "string" ? record.code : "";
  const trusted = TRUSTED_CODE_GUIDANCE[code];
  if (trusted) return cloneGuidance(trusted);
  if (httpStatus === 403) {
    return cloneGuidance(TRUSTED_CODE_GUIDANCE.PERMISSION_DENIED);
  }
  if (httpStatus === 429) {
    return cloneGuidance(TRUSTED_CODE_GUIDANCE.RATE_LIMITED);
  }
  if (httpStatus !== null && httpStatus >= 500) {
    return cloneGuidance(TRUSTED_CODE_GUIDANCE.CONNECTION_FAILED);
  }
  return guidance("unknown", "unexpected_failure", true, ["open_diagnostics", "retry"]);
}

export function recoveryGuidanceMessage(guidanceValue: UserFacingRecoveryGuidance): string {
  switch (guidanceValue.summaryCode) {
    case "sign_in_required":
      return "Sign in again, then retry.";
    case "access_denied":
      return "Access was denied. Request access from a vault administrator.";
    case "vault_binding_needs_attention":
      return "Refresh the vault binding or select the intended vault.";
    case "provider_unavailable":
      return "Reconnect the provider, then retry.";
    case "executable_missing":
      return "Install or select the required executable, then retry.";
    case "network_unavailable":
      return "Check the network connection, then retry.";
    case "rate_limited":
      return "The current usage limit was reached. Retry later.";
    default:
      return "The operation could not be completed. Open diagnostics or retry.";
  }
}

function guidance(
  category: UserFacingRecoveryCategory,
  summaryCode: UserFacingRecoverySummaryCode,
  retryable: boolean,
  actionCodes: UserFacingRecoveryActionCode[],
): UserFacingRecoveryGuidance {
  return { category, summaryCode, retryable, actionCodes };
}

function cloneGuidance(value: UserFacingRecoveryGuidance): UserFacingRecoveryGuidance {
  return { ...value, actionCodes: [...value.actionCodes] };
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}
