import type { VaultGuardSettings } from "../types";

export const CONNECTION_BOUNDARY_KEYS = [
  "manualConfig",
  "orgSlug",
  "apiEndpoint",
  "organizationId",
  "cognitoUserPoolId",
  "cognitoClientId",
  "serverVaultId",
  "serverVaultName",
  "serverVaultSlug",
] as const;

export type ConnectionBoundarySnapshot = Pick<
  VaultGuardSettings,
  (typeof CONNECTION_BOUNDARY_KEYS)[number]
>;

/**
 * Capture only the settings that can redirect authentication or vault-scoped
 * API calls. External settings sync may refresh everything else while signed
 * in, but this boundary must remain stable until the session is closed.
 */
export function snapshotConnectionBoundary(
  settings: VaultGuardSettings,
): ConnectionBoundarySnapshot {
  return Object.fromEntries(
    CONNECTION_BOUNDARY_KEYS.map((key) => [key, settings[key]]),
  ) as ConnectionBoundarySnapshot;
}

export function didConnectionBoundaryChange(
  before: ConnectionBoundarySnapshot,
  after: VaultGuardSettings,
): boolean {
  return CONNECTION_BOUNDARY_KEYS.some((key) => after[key] !== before[key]);
}
