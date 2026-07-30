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

function areJsonSettingsValuesEqual(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) return true;
  if (left === null || right === null) return false;

  if (Array.isArray(left) || Array.isArray(right)) {
    if (!Array.isArray(left) || !Array.isArray(right) || left.length !== right.length) {
      return false;
    }
    return left.every((value, index) => areJsonSettingsValuesEqual(value, right[index]));
  }

  if (typeof left !== "object" || typeof right !== "object") return false;

  const leftRecord = left as Record<string, unknown>;
  const rightRecord = right as Record<string, unknown>;
  const leftKeys = Object.keys(leftRecord)
    .filter((key) => leftRecord[key] !== undefined)
    .sort();
  const rightKeys = Object.keys(rightRecord)
    .filter((key) => rightRecord[key] !== undefined)
    .sort();

  if (leftKeys.length !== rightKeys.length) return false;
  return leftKeys.every(
    (key, index) =>
      key === rightKeys[index] &&
      areJsonSettingsValuesEqual(leftRecord[key], rightRecord[key]),
  );
}

/**
 * Compares the effective, JSON-persisted settings after Obsidian reports an
 * external data.json change. Object key order and omitted undefined values do
 * not count as changes, matching the persisted JSON representation.
 */
export function didExternallyLoadedSettingsChange(
  before: VaultGuardSettings,
  after: VaultGuardSettings,
): boolean {
  return !areJsonSettingsValuesEqual(before, after);
}
