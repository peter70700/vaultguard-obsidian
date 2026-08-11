/** Current vault-scoped fallback key used only when profile localStorage is unavailable. */
export const DETECT_GIT_REPO_FOLDER_KEY =
  "vaultguard.git-repository-plaintext.detect-folder.v1";

/** Profile-wide source of truth for the replacement Git repository detector. */
export const DETECT_GIT_REPO_FOLDER_PROFILE_KEY =
  "vaultguard.git-repository-plaintext.detect-folder.profile.v1";

/** Superseded automatic Local Project Memory Mode keys, read once for migration. */
export const LEGACY_AUTO_LOCAL_PROJECT_MEMORY_MODE_GIT_REPOS_KEY =
  "vaultguard.local-project-memory.auto-git-repos.v1";
export const LEGACY_AUTO_LOCAL_PROJECT_MEMORY_MODE_GIT_REPOS_PROFILE_KEY =
  "vaultguard.local-project-memory.auto-git-repos.profile.v1";

export interface GitRepositoryPreferenceStorage {
  loadLocalStorage(key: string): unknown;
  saveLocalStorage(key: string, value: unknown | null): void;
}

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
    // Sandboxed runtimes can throw while reading global localStorage.
  }
  return null;
}

function parseStoredBoolean(value: unknown): boolean | null {
  if (value === true || value === "true") return true;
  if (value === false || value === "false") return false;
  return null;
}

function clearLegacyPreference(
  storage: GitRepositoryPreferenceStorage,
  profileStore: ProfilePreferenceStore | null,
): void {
  storage.saveLocalStorage(LEGACY_AUTO_LOCAL_PROJECT_MEMORY_MODE_GIT_REPOS_KEY, null);
  if (!profileStore) return;
  try {
    profileStore.removeItem(LEGACY_AUTO_LOCAL_PROJECT_MEMORY_MODE_GIT_REPOS_PROFILE_KEY);
  } catch {
    // The current preference has already been persisted. A stale legacy key is
    // harmless and can be retried the next time settings are read.
  }
}

/**
 * Read the profile preference and migrate the setting that previously enabled
 * Local Project Memory Mode automatically. The migrated value now controls only
 * detected-repository local plaintext; it never changes the mode itself.
 */
export function readDetectGitRepoFolderPreference(
  storage: GitRepositoryPreferenceStorage,
  profileStore: ProfilePreferenceStore | null = defaultProfilePreferenceStore(),
): boolean {
  if (!profileStore) {
    const current = parseStoredBoolean(storage.loadLocalStorage(DETECT_GIT_REPO_FOLDER_KEY));
    if (current !== null) {
      storage.saveLocalStorage(LEGACY_AUTO_LOCAL_PROJECT_MEMORY_MODE_GIT_REPOS_KEY, null);
      return current;
    }
    const legacy = parseStoredBoolean(
      storage.loadLocalStorage(LEGACY_AUTO_LOCAL_PROJECT_MEMORY_MODE_GIT_REPOS_KEY),
    );
    if (legacy === null) return false;
    storage.saveLocalStorage(DETECT_GIT_REPO_FOLDER_KEY, legacy);
    storage.saveLocalStorage(LEGACY_AUTO_LOCAL_PROJECT_MEMORY_MODE_GIT_REPOS_KEY, null);
    return legacy;
  }

  try {
    const current = parseStoredBoolean(profileStore.getItem(DETECT_GIT_REPO_FOLDER_PROFILE_KEY));
    if (current !== null) {
      clearLegacyPreference(storage, profileStore);
      return current;
    }

    const legacyProfile = parseStoredBoolean(
      profileStore.getItem(LEGACY_AUTO_LOCAL_PROJECT_MEMORY_MODE_GIT_REPOS_PROFILE_KEY),
    );
    const legacyVault = parseStoredBoolean(
      storage.loadLocalStorage(LEGACY_AUTO_LOCAL_PROJECT_MEMORY_MODE_GIT_REPOS_KEY),
    );
    const migrated = legacyProfile ?? legacyVault;
    if (migrated === null) return false;

    profileStore.setItem(DETECT_GIT_REPO_FOLDER_PROFILE_KEY, migrated ? "true" : "false");
    clearLegacyPreference(storage, profileStore);
    return migrated;
  } catch {
    const fallback = parseStoredBoolean(storage.loadLocalStorage(DETECT_GIT_REPO_FOLDER_KEY));
    if (fallback !== null) return fallback;
    return (
      parseStoredBoolean(
        storage.loadLocalStorage(LEGACY_AUTO_LOCAL_PROJECT_MEMORY_MODE_GIT_REPOS_KEY),
      ) ?? false
    );
  }
}

export function writeDetectGitRepoFolderPreference(
  storage: GitRepositoryPreferenceStorage,
  enabled: boolean,
  profileStore: ProfilePreferenceStore | null = defaultProfilePreferenceStore(),
): void {
  const value = enabled === true;
  if (!profileStore) {
    storage.saveLocalStorage(DETECT_GIT_REPO_FOLDER_KEY, value);
    storage.saveLocalStorage(LEGACY_AUTO_LOCAL_PROJECT_MEMORY_MODE_GIT_REPOS_KEY, null);
    return;
  }

  try {
    profileStore.setItem(DETECT_GIT_REPO_FOLDER_PROFILE_KEY, value ? "true" : "false");
    storage.saveLocalStorage(DETECT_GIT_REPO_FOLDER_KEY, null);
    clearLegacyPreference(storage, profileStore);
  } catch {
    storage.saveLocalStorage(DETECT_GIT_REPO_FOLDER_KEY, value);
    storage.saveLocalStorage(LEGACY_AUTO_LOCAL_PROJECT_MEMORY_MODE_GIT_REPOS_KEY, null);
  }
}

/** Normalize a vault-relative folder path, rejecting traversal outside the vault. */
export function normalizeGitRepositoryRoot(path: string): string | null {
  const segments: string[] = [];
  for (const segment of path.replace(/\\/g, "/").split("/")) {
    if (!segment || segment === ".") continue;
    if (segment === "..") return null;
    segments.push(segment);
  }
  return segments.join("/");
}

/** Sort, dedupe, and remove roots already covered by a detected ancestor. */
export function compactGitRepositoryRoots(roots: Iterable<string>): string[] {
  const normalized = new Set<string>();
  for (const root of roots) {
    const candidate = normalizeGitRepositoryRoot(root);
    if (candidate !== null) normalized.add(candidate);
  }

  const ordered = [...normalized].sort((left, right) => {
    const depth = left.split("/").filter(Boolean).length - right.split("/").filter(Boolean).length;
    return depth || left.localeCompare(right);
  });
  const compacted: string[] = [];
  for (const root of ordered) {
    if (root === "") return [""];
    if (compacted.some((ancestor) => root.startsWith(`${ancestor}/`))) continue;
    compacted.push(root);
  }
  return compacted;
}

export function isPathInDetectedGitRepository(path: string, roots: readonly string[]): boolean {
  const normalized = normalizeGitRepositoryRoot(path);
  if (!normalized) return false;
  return roots.some(
    (root) => root === "" || normalized === root || normalized.startsWith(`${root}/`),
  );
}
