import type { VaultGuardSettings } from "../types";

export const LOCAL_PROJECT_MEMORY_MODE_NOTICE =
  "Local Project Memory Mode keeps this vault plaintext and disables VaultGuard encryption, sync, sharing, and organization controls for repo-root project memory use.";

/** Legacy vault-scoped key, read once for migration. Written through `App.saveLocalStorage`. */
export const AUTO_LOCAL_PROJECT_MEMORY_MODE_GIT_REPOS_KEY =
  "vaultguard.local-project-memory.auto-git-repos.v1";

/**
 * Profile-shared key. Deliberately distinct from the legacy key: the two stores
 * are different namespaces in real Obsidian (`App.saveLocalStorage` prefixes
 * with the vault's `appId`), but keeping the names distinct means clearing the
 * legacy value can never clobber the profile value regardless of how the
 * vault-scoped wrapper is implemented.
 */
export const AUTO_LOCAL_PROJECT_MEMORY_MODE_GIT_REPOS_PROFILE_KEY =
  "vaultguard.local-project-memory.auto-git-repos.profile.v1";

export interface LocalProjectMemoryPreferenceStorage {
  loadLocalStorage(key: string): unknown;
  saveLocalStorage(key: string, value: unknown | null): void;
}

/**
 * The shared, un-prefixed `localStorage` used for the profile-wide preference.
 *
 * Obsidian's `App.saveLocalStorage` writes `localStorage[appId + "-" + key]`
 * (documented as "Save vault-specific value") — it is per-vault, so it cannot
 * carry a preference that is supposed to apply to every repository vault on
 * this desktop profile. `localStorage` itself is shared across the vaults of
 * one Obsidian install, so an un-prefixed key gives the intended scope.
 */
export interface ProfilePreferenceStore {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export function defaultProfilePreferenceStore(): ProfilePreferenceStore | null {
  try {
    const candidate = (globalThis as { localStorage?: ProfilePreferenceStore }).localStorage;
    if (
      candidate &&
      typeof candidate.getItem === "function" &&
      typeof candidate.setItem === "function" &&
      typeof candidate.removeItem === "function"
    ) {
      return candidate;
    }
  } catch {
    // Sandboxed runtimes can throw on the property access itself.
  }
  return null;
}

export type AutomaticLocalProjectMemoryProtectionReason =
  | "safe"
  | "ciphertext"
  | "inspection-failed";

export interface AutomaticLocalProjectMemoryProtectionState {
  safe: boolean;
  reason: AutomaticLocalProjectMemoryProtectionReason;
}

export type AutomaticLocalProjectMemoryModeDecision =
  | { kind: "already-enabled" }
  | { kind: "global-disabled" }
  | { kind: "suppressed" }
  | { kind: "mobile" }
  | { kind: "server-bound" }
  | { kind: "not-git-root" }
  | { kind: "protected" }
  | { kind: "inspection-failed" }
  | { kind: "eligible" };

export interface AutomaticLocalProjectMemoryModeDecisionInput {
  globalEnabled: boolean;
  alreadyEnabled: boolean;
  suppressed: boolean;
  mobile: boolean;
  serverBound: boolean;
  gitRootDetected: boolean;
  protection: AutomaticLocalProjectMemoryProtectionState;
}

/**
 * Read the profile-wide preference, migrating a legacy vault-scoped opt-in.
 *
 * Reads fall back to the vault-scoped store when `localStorage` is unavailable
 * (mobile shells, tests) so behavior degrades to the previous per-vault
 * semantics instead of throwing. A legacy `true` found while the profile store
 * is available is adopted forward once, so users who opted in before this fix
 * keep their preference — and gain the cross-vault behavior they were promised.
 */
export function readAutomaticLocalProjectMemoryModePreference(
  storage: LocalProjectMemoryPreferenceStorage,
  profileStore: ProfilePreferenceStore | null = defaultProfilePreferenceStore(),
): boolean {
  const legacyEnabled =
    storage.loadLocalStorage(AUTO_LOCAL_PROJECT_MEMORY_MODE_GIT_REPOS_KEY) === true;
  if (!profileStore) return legacyEnabled;

  let stored: string | null = null;
  try {
    stored = profileStore.getItem(AUTO_LOCAL_PROJECT_MEMORY_MODE_GIT_REPOS_PROFILE_KEY);
  } catch {
    return legacyEnabled;
  }
  if (stored !== null) return stored === "true";

  if (legacyEnabled) {
    writeAutomaticLocalProjectMemoryModePreference(storage, true, profileStore);
    return true;
  }
  return false;
}

export function writeAutomaticLocalProjectMemoryModePreference(
  storage: LocalProjectMemoryPreferenceStorage,
  enabled: boolean,
  profileStore: ProfilePreferenceStore | null = defaultProfilePreferenceStore(),
): void {
  const value = enabled === true;
  if (!profileStore) {
    storage.saveLocalStorage(AUTO_LOCAL_PROJECT_MEMORY_MODE_GIT_REPOS_KEY, value);
    return;
  }
  try {
    profileStore.setItem(
      AUTO_LOCAL_PROJECT_MEMORY_MODE_GIT_REPOS_PROFILE_KEY,
      value ? "true" : "false",
    );
  } catch {
    storage.saveLocalStorage(AUTO_LOCAL_PROJECT_MEMORY_MODE_GIT_REPOS_KEY, value);
    return;
  }
  // One source of truth: drop the superseded vault-scoped copy.
  storage.saveLocalStorage(AUTO_LOCAL_PROJECT_MEMORY_MODE_GIT_REPOS_KEY, null);
}

export function decideAutomaticLocalProjectMemoryMode(
  input: AutomaticLocalProjectMemoryModeDecisionInput,
): AutomaticLocalProjectMemoryModeDecision {
  if (input.alreadyEnabled) return { kind: "already-enabled" };
  if (!input.globalEnabled) return { kind: "global-disabled" };
  if (input.suppressed) return { kind: "suppressed" };
  if (input.mobile) return { kind: "mobile" };
  if (input.serverBound) return { kind: "server-bound" };
  if (!input.gitRootDetected) return { kind: "not-git-root" };
  if (!input.protection.safe) {
    return input.protection.reason === "inspection-failed"
      ? { kind: "inspection-failed" }
      : { kind: "protected" };
  }
  return { kind: "eligible" };
}

const PLAINTEXT_FOLDER_PREFIXES = [
  ".git",
  ".obsidian",
  "docs",
  "reports",
  "handoffs",
  "src",
  "tests",
  "scripts",
  "terraform",
  "infrastructure",
  "share-bridge",
] as const;

const PLAINTEXT_EXACT_PATHS = new Set([
  "agents.md",
  "00_index.md",
  "package.json",
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lock",
  "bun.lockb",
]);

const PLAINTEXT_EXTENSIONS = [
  ".ts",
  ".tsx",
  ".js",
  ".json",
  ".css",
  ".tf",
] as const;

export function isLocalProjectMemoryModeEnabled(
  settings: Pick<VaultGuardSettings, "localProjectMemoryMode">,
): boolean {
  return settings.localProjectMemoryMode === true;
}

export function normalizeLocalProjectMemoryPath(path: string): string {
  return path.replace(/\\/g, "/").replace(/^\/+/, "").toLowerCase();
}

export function isLocalProjectMemoryPlaintextPath(
  path: string,
  configDir = ".obsidian",
): boolean {
  const normalized = normalizeLocalProjectMemoryPath(path);
  if (!normalized) return false;

  const normalizedConfigDir = normalizeLocalProjectMemoryPath(configDir);
  if (
    normalizedConfigDir &&
    (normalized === normalizedConfigDir || normalized.startsWith(`${normalizedConfigDir}/`))
  ) {
    return true;
  }

  if (PLAINTEXT_EXACT_PATHS.has(normalized)) return true;

  for (const prefix of PLAINTEXT_FOLDER_PREFIXES) {
    if (normalized === prefix || normalized.startsWith(`${prefix}/`)) {
      return true;
    }
  }

  if (normalized.startsWith("vite.config.")) return true;
  if (normalized === "tsconfig.json" || /^tsconfig[^/]*\.json$/.test(normalized)) {
    return true;
  }

  return PLAINTEXT_EXTENSIONS.some((extension) => normalized.endsWith(extension));
}
