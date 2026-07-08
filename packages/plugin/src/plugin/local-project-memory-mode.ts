import type { VaultGuardSettings } from "../types";

export const LOCAL_PROJECT_MEMORY_MODE_NOTICE =
  "Local Project Memory Mode keeps this vault plaintext and disables VaultGuard encryption, sync, sharing, and organization controls for repo-root project memory use.";

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
