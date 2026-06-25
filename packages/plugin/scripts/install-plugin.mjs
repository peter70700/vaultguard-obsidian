import {
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";

const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(readFileSync(join(rootDir, "manifest.json"), "utf8"));

// Persist the most-recently-used vault path under the user's home directory so
// subsequent `npm run install:plugin` invocations don't need the argument.
// This makes a build -> install loop feasible without re-typing absolute paths,
// which is the most common reason developers skip the install step and end up
// running stale code in Obsidian.
const configPath = join(homedir(), ".vaultguard-dev-install.json");
const savedConfig = readJsonFile(configPath, {});
const vaultPathArgs = process.argv.slice(2);
const vaultPaths = resolveTargetVaultPaths(vaultPathArgs, savedConfig);

if (vaultPaths.length === 0) {
  console.error('Usage: npm run install:plugin -- "/absolute/path/to/ObsidianVault" [...more vaults]');
  console.error(
    "Without arguments, this installs to open Obsidian vaults where VaultGuard is enabled or installed."
  );
  console.error("(Subsequent runs reuse the detected or provided paths automatically.)");
  process.exit(1);
}

const assets = ["main.js", "manifest.json", "styles.css"];
const installedPluginDirs = [];

for (const vaultPath of vaultPaths) {
  installedPluginDirs.push(installToVault(vaultPath, assets));
}

writeFileSync(
  configPath,
  `${JSON.stringify({ vaultPath: vaultPaths[0], vaultPaths }, null, 2)}\n`
);

const vaultLabel = installedPluginDirs.length === 1 ? "vault" : "vaults";
console.log(`Installed ${manifest.name} ${manifest.version} to ${installedPluginDirs.length} ${vaultLabel}:`);
for (const pluginDir of installedPluginDirs) {
  console.log(`- ${pluginDir}`);
}
console.log("Reload: Cmd+, -> Community Plugins -> toggle VaultGuard off then on (or restart Obsidian).");

function installToVault(vaultPath, assets) {
  const obsidianDir = join(vaultPath, ".obsidian");
  const pluginDir = join(obsidianDir, "plugins", manifest.id);

  if (!existsSync(obsidianDir)) {
    console.warn(`Warning: ${obsidianDir} does not exist yet. Creating plugin directory anyway.`);
  }

  mkdirSync(pluginDir, { recursive: true });

  // If a previous install used symlinks, replace them with real copies. Some
  // Obsidian / Electron builds resolve symlinks once at plugin-enable time and
  // then refuse to re-read the target on toggle, which makes "rebuild -> toggle"
  // look like a no-op. Real files always reload predictably.
  for (const asset of assets) {
    const dest = join(pluginDir, asset);
    removeSymlinkIfPresent(dest);
    copyFileSync(join(rootDir, asset), dest);
  }

  return pluginDir;
}

function resolveTargetVaultPaths(vaultPathArgs, savedConfig) {
  if (vaultPathArgs.length > 0) {
    return uniquePaths(vaultPathArgs.map(normalizeVaultPath));
  }

  const knownVaults = readObsidianVaults();
  const openPluginVaults = knownVaults
    .filter((vault) => vault.open && hasVaultGuardPlugin(vault.path))
    .map((vault) => vault.path);
  const savedVaultPaths = readSavedVaultPaths(savedConfig);
  const configuredTargets = uniquePaths([...openPluginVaults, ...savedVaultPaths]);

  if (configuredTargets.length > 0) {
    return configuredTargets;
  }

  return uniquePaths(
    knownVaults.filter((vault) => hasVaultGuardPlugin(vault.path)).map((vault) => vault.path)
  );
}

function readSavedVaultPaths(savedConfig) {
  const paths = [];
  if (Array.isArray(savedConfig.vaultPaths)) {
    paths.push(...savedConfig.vaultPaths);
  }
  if (typeof savedConfig.vaultPath === "string") {
    paths.push(savedConfig.vaultPath);
  }
  return paths.map(normalizeVaultPath);
}

function readObsidianVaults() {
  const obsidianConfigPath = join(homedir(), "Library", "Application Support", "obsidian", "obsidian.json");
  const obsidianConfig = readJsonFile(obsidianConfigPath, {});
  const vaults = Object.values(obsidianConfig.vaults ?? {}).filter(
    (vault) => vault && typeof vault.path === "string"
  );

  return vaults
    .map((vault) => ({
      path: normalizeVaultPath(vault.path),
      open: vault.open === true,
      ts: typeof vault.ts === "number" ? vault.ts : 0,
    }))
    .sort((a, b) => Number(b.open) - Number(a.open) || b.ts - a.ts);
}

function hasVaultGuardPlugin(vaultPath) {
  return isVaultGuardEnabled(vaultPath) || existsSync(join(vaultPath, ".obsidian", "plugins", manifest.id));
}

function isVaultGuardEnabled(vaultPath) {
  const communityPlugins = readJsonFile(join(vaultPath, ".obsidian", "community-plugins.json"), []);
  return Array.isArray(communityPlugins) && communityPlugins.includes(manifest.id);
}

function normalizeVaultPath(vaultPath) {
  if (vaultPath === "~") {
    return homedir();
  }

  if (vaultPath.startsWith("~/")) {
    return resolve(join(homedir(), vaultPath.slice(2)));
  }

  return resolve(vaultPath);
}

function uniquePaths(paths) {
  return [...new Set(paths.filter(Boolean))];
}

function removeSymlinkIfPresent(path) {
  try {
    if (lstatSync(path).isSymbolicLink()) {
      unlinkSync(path);
    }
  } catch {
    /* ignore missing destination */
  }
}

function readJsonFile(path, fallback) {
  if (!existsSync(path)) {
    return fallback;
  }

  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return fallback;
  }
}
