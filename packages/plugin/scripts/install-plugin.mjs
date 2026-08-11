import {
  closeSync,
  copyFileSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { homedir } from "node:os";

const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(readFileSync(join(rootDir, "manifest.json"), "utf8"));
const DEFAULT_ASSETS = ["main.js", "manifest.json", "styles.css"];
export const INSTALL_TRANSACTION_DIR_NAME = ".vaultguard-install-transaction";
const INSTALL_JOURNAL_FILE = "journal.json";
const INSTALL_JOURNAL_VERSION = 1;
const INSTALL_LOCK_STALE_AFTER_MS = 30 * 60 * 1000;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;
const JOURNAL_PHASES = new Set(["preparing", "prepared", "activating", "activated"]);

// Persist the most-recently-used vault path under the user's home directory so
// subsequent `npm run install:plugin` invocations don't need the argument.
// This makes a build -> install loop feasible without re-typing absolute paths,
// which is the most common reason developers skip the install step and end up
// running stale code in Obsidian.
export class InstallTransactionError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "InstallTransactionError";
    this.code = code;
  }
}

export function formatInstallFailureSummary(successCount, failedTargetNumber, code) {
  if (successCount > 0) {
    const label = successCount === 1 ? "target" : "targets";
    return (
      `VaultGuard install partially completed (${code}): ${successCount} ${label} succeeded; ` +
      `target ${failedTargetNumber} failed. Successful targets were not rolled back.`
    );
  }
  return `VaultGuard install failed (${code}) before any target completed; target ${failedTargetNumber} was not installed.`;
}

export function runCli(argv = process.argv.slice(2)) {
  const configPath = join(homedir(), ".vaultguard-dev-install.json");
  const savedConfig = readJsonFile(configPath, {});
  const vaultPaths = resolveTargetVaultPaths(argv, savedConfig);

  if (vaultPaths.length === 0) {
    console.error('Usage: npm run install:plugin -- "/absolute/path/to/ObsidianVault" [...more vaults]');
    console.error(
      "Without arguments, this installs to open Obsidian vaults where VaultGuard is enabled or installed."
    );
    console.error("(Subsequent runs reuse the detected or provided paths automatically.)");
    process.exitCode = 1;
    return;
  }

  const installed = [];
  try {
    for (let index = 0; index < vaultPaths.length; index++) {
      installed.push(
        installToVault(vaultPaths[index], DEFAULT_ASSETS, {
          transactionId: `${process.pid}-${Date.now()}-${index}`,
        }),
      );
    }
  } catch (error) {
    const code = error instanceof InstallTransactionError ? error.code : "unexpected_failure";
    console.error(formatInstallFailureSummary(installed.length, installed.length + 1, code));
    process.exitCode = 1;
    return;
  }

  writeFileSync(
    configPath,
    `${JSON.stringify({ vaultPath: vaultPaths[0], vaultPaths }, null, 2)}\n`
  );

  const vaultLabel = installed.length === 1 ? "vault" : "vaults";
  console.log(`Installed ${manifest.name} ${manifest.version} to ${installed.length} ${vaultLabel}.`);
  for (let index = 0; index < installed.length; index++) {
    console.log(`- target ${index + 1}: ${installed[index].pluginRelativePath}`);
  }
  console.log("Reload: Community Plugins -> toggle VaultGuard off then on (or restart Obsidian).");
}

function installToVault(vaultPath, assets, options = {}) {
  const obsidianDir = join(vaultPath, ".obsidian");

  if (!existsSync(obsidianDir)) {
    console.warn("Warning: the target vault has no .obsidian directory yet; creating the plugin directory.");
  }

  return installAssetsTransaction({
    sourceRoot: rootDir,
    vaultPath,
    pluginId: manifest.id,
    assets,
    transactionId: options.transactionId ?? `${process.pid}-${Date.now()}`,
  });
}

export function installAssetsTransaction(input) {
  const sourceRoot = resolve(String(input?.sourceRoot ?? ""));
  const vaultPath = resolve(String(input?.vaultPath ?? ""));
  const pluginId = validatePluginId(input?.pluginId);
  const assets = validateAssets(input?.assets);
  const transactionId = validateTransactionId(input?.transactionId);
  const pluginsRoot = resolve(vaultPath, ".obsidian", "plugins");
  const pluginDir = resolve(pluginsRoot, pluginId);
  assertContained(pluginsRoot, pluginDir, "unsafe_destination");

  // Lexical containment cannot see junctions/reparse points. Inspect every
  // existing component before mkdir follows it, then prove the completed
  // physical layout remains inside the selected vault.
  assertNoLinkedDestinationComponents(vaultPath, pluginDir);
  mkdirSync(pluginDir, { recursive: true });
  assertSafeDestinationLayout(vaultPath, pluginsRoot, pluginDir);

  // A fixed per-plugin transaction directory is both the inter-process lock and
  // the crash-recovery anchor. Recover a stale owner before looking at the new
  // source bundle; this can restore a missing live asset even when today's
  // source bundle is incomplete.
  recoverAbandonedInstallTransaction({ vaultPath, pluginsRoot, pluginDir, pluginId });
  assertSafeDestinationLayout(vaultPath, pluginsRoot, pluginDir);

  const sources = assets.map((asset) => {
    const source = resolve(sourceRoot, asset);
    assertContained(sourceRoot, source, "unsafe_source");
    if (!existsSync(source) || !lstatSync(source).isFile() || lstatSync(source).isSymbolicLink()) {
      throw new InstallTransactionError("invalid_source_asset", "A required source asset is unavailable.");
    }
    return { asset, source, sha256: sha256File(source) };
  });

  const journalAssets = sources.map(({ asset, sha256 }) => {
    const destination = join(pluginDir, asset);
    const previousSha256 = safeFileDigest(destination, "unsafe_destination");
    return {
      asset,
      newSha256: sha256,
      hadOriginal: previousSha256 !== null,
      previousSha256,
    };
  });

  const transactionDir = resolve(pluginDir, INSTALL_TRANSACTION_DIR_NAME);
  assertContained(pluginDir, transactionDir, "unsafe_transaction_path");
  assertSafeDestinationLayout(vaultPath, pluginsRoot, pluginDir);
  try {
    // Non-recursive mkdir is the atomic lock acquisition. A second live
    // installer cannot silently share staging/backup state.
    mkdirSync(transactionDir);
  } catch (error) {
    if (isNodeErrorCode(error, "EEXIST")) {
      throw new InstallTransactionError("transaction_locked", "Another plugin install transaction is active.");
    }
    throw new InstallTransactionError("transaction_create_failed", "The plugin install transaction could not be created.");
  }
  assertSafeTransactionDirectory(pluginDir, transactionDir);

  const journalPath = join(transactionDir, INSTALL_JOURNAL_FILE);
  const journal = {
    version: INSTALL_JOURNAL_VERSION,
    pluginId,
    transactionId,
    ownerPid: process.pid,
    startedAtMs: Date.now(),
    phase: "preparing",
    assets: journalAssets,
  };
  const stagingDir = join(transactionDir, "staging");
  const backupDir = join(transactionDir, "backup");
  try {
    writeRecoveryJournal(journalPath, journal);
    mkdirSync(stagingDir);
    mkdirSync(backupDir);
  } catch {
    try {
      recoverAbandonedInstallTransaction(
        { vaultPath, pluginsRoot, pluginDir, pluginId },
        { ignoreLiveOwner: true },
      );
    } catch {
      throw new InstallTransactionError(
        "recovery_failed",
        "The plugin install transaction could not be initialized or recovered.",
      );
    }
    throw new InstallTransactionError(
      "transaction_create_failed",
      "The plugin install transaction could not be initialized.",
    );
  }

  const expectedAssetState = new Map(journalAssets.map((item) => [item.asset, item]));
  const completedResult = () => ({
    pluginRelativePath: `.obsidian/plugins/${pluginId}`,
    assetDigests: sources.map(({ asset, sha256 }) => ({ asset, sha256 })),
  });

  try {
    for (const sourceAsset of sources) {
      const staged = join(stagingDir, sourceAsset.asset);
      copyFileSync(sourceAsset.source, staged);
      if (sha256File(staged) !== sourceAsset.sha256) {
        throw new InstallTransactionError("staging_hash_mismatch", "A staged asset failed digest verification.");
      }
    }
    journal.phase = "prepared";
    writeRecoveryJournal(journalPath, journal);

    journal.phase = "activating";
    writeRecoveryJournal(journalPath, journal);
    for (const sourceAsset of sources) {
      assertSafeDestinationLayout(vaultPath, pluginsRoot, pluginDir);
      const destination = join(pluginDir, sourceAsset.asset);
      const backup = join(backupDir, sourceAsset.asset);
      const expected = expectedAssetState.get(sourceAsset.asset);
      const currentDigest = safeFileDigest(destination, "unsafe_destination");
      if (!expected || currentDigest !== expected.previousSha256) {
        throw new InstallTransactionError(
          "activation_conflict",
          "An installed asset changed after the transaction was prepared.",
        );
      }
      if (existsSync(destination)) renameSync(destination, backup);
      renameSync(join(stagingDir, sourceAsset.asset), destination);
      input?.hooks?.afterActivateAsset?.(sourceAsset.asset);
    }

    assertSafeDestinationLayout(vaultPath, pluginsRoot, pluginDir);
    for (const sourceAsset of sources) {
      if (safeFileDigest(join(pluginDir, sourceAsset.asset), "unsafe_destination") !== sourceAsset.sha256) {
        throw new InstallTransactionError("activation_hash_mismatch", "An activated asset failed digest verification.");
      }
    }

    journal.phase = "activated";
    writeRecoveryJournal(journalPath, journal);
    removeTransactionDirectory(pluginDir, transactionDir);
    return completedResult();
  } catch (error) {
    try {
      const recovery = recoverAbandonedInstallTransaction(
        { vaultPath, pluginsRoot, pluginDir, pluginId },
        { ignoreLiveOwner: true },
      );
      if (recovery.outcome === "committed") return completedResult();
    } catch {
      throw new InstallTransactionError(
        "recovery_failed",
        "Plugin activation failed and the prior installation could not be recovered automatically.",
      );
    }
    if (error instanceof InstallTransactionError) throw error;
    throw new InstallTransactionError("activation_failed", "Plugin activation failed and installed assets were restored.");
  }
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

function validatePluginId(value) {
  if (typeof value !== "string" || !/^[a-z0-9][a-z0-9-]{0,79}$/.test(value)) {
    throw new InstallTransactionError("invalid_plugin_id", "The plugin identifier is invalid.");
  }
  return value;
}

function validateAssets(value) {
  if (!Array.isArray(value) || value.length === 0 || value.length > 32) {
    throw new InstallTransactionError("invalid_asset_list", "The install asset list is invalid.");
  }
  const assets = value.map((asset) => {
    if (typeof asset !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/.test(asset)) {
      throw new InstallTransactionError("invalid_asset_list", "The install asset list is invalid.");
    }
    return asset;
  });
  if (new Set(assets).size !== assets.length) {
    throw new InstallTransactionError("invalid_asset_list", "The install asset list is invalid.");
  }
  return assets;
}

function validateTransactionId(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/.test(value)) {
    throw new InstallTransactionError("invalid_transaction_id", "The install transaction identifier is invalid.");
  }
  return value;
}

function assertContained(parent, child, code) {
  const rel = relative(resolve(parent), resolve(child));
  if (!rel || rel === "." || rel.startsWith("..") || rel.includes(`..${sep}`) || resolve(rel) === rel) {
    throw new InstallTransactionError(code, "An install path escaped its allowed root.");
  }
}

function comparablePath(path) {
  const normalized = resolve(path);
  return process.platform === "win32" ? normalized.toLowerCase() : normalized;
}

function assertNoLinkedDestinationComponents(vaultPath, pluginDir) {
  const root = resolve(vaultPath);
  const destination = resolve(pluginDir);
  const rel = relative(root, destination);
  if (rel.startsWith("..") || resolve(rel) === rel) {
    throw new InstallTransactionError("unsafe_destination", "The plugin destination escaped the selected vault.");
  }

  const components = [root];
  let current = root;
  for (const part of rel.split(/[\\/]+/).filter(Boolean)) {
    current = join(current, part);
    components.push(current);
  }

  let physicalParent = null;
  for (const component of components) {
    if (!existsSync(component)) break;
    const stat = lstatSync(component);
    if (stat.isSymbolicLink()) {
      throw new InstallTransactionError(
        "unsafe_destination_link",
        "A plugin destination ancestor is a symbolic link or junction.",
      );
    }
    if (!stat.isDirectory()) {
      throw new InstallTransactionError("unsafe_destination", "A plugin destination ancestor is not a directory.");
    }

    const physical = realpathSync(component);
    if (physicalParent !== null) {
      const expected = join(physicalParent, component.slice(component.lastIndexOf(sep) + 1));
      if (comparablePath(physical) !== comparablePath(expected)) {
        throw new InstallTransactionError(
          "unsafe_destination_link",
          "A plugin destination ancestor resolves through a reparse point.",
        );
      }
    }
    physicalParent = physical;
  }
}

function assertSafeDestinationLayout(vaultPath, pluginsRoot, pluginDir) {
  assertNoLinkedDestinationComponents(vaultPath, pluginDir);
  const realVault = realpathSync(vaultPath);
  const realPluginsRoot = realpathSync(pluginsRoot);
  const realPluginDir = realpathSync(pluginDir);
  assertContained(realVault, realPluginsRoot, "unsafe_destination");
  assertContained(realPluginsRoot, realPluginDir, "unsafe_destination");
}

function safeFileDigest(path, code) {
  if (!existsSync(path)) return null;
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new InstallTransactionError(code, "An install asset path is not a regular file.");
  }
  return sha256File(path);
}

function isNodeErrorCode(error, code) {
  return Boolean(error && typeof error === "object" && error.code === code);
}

function isProcessAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return isNodeErrorCode(error, "EPERM");
  }
}

function writeRecoveryJournal(journalPath, journal) {
  const tempPath = `${journalPath}.tmp`;
  writeFileSync(tempPath, `${JSON.stringify(journal, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  const descriptor = openSync(tempPath, "r+");
  try {
    fsyncSync(descriptor);
  } finally {
    closeSync(descriptor);
  }
  renameSync(tempPath, journalPath);
}

function parseRecoveryJournal(transactionDir, pluginId) {
  const journalPath = join(transactionDir, INSTALL_JOURNAL_FILE);
  if (!existsSync(journalPath)) return null;
  let value;
  try {
    value = JSON.parse(readFileSync(journalPath, "utf8"));
  } catch {
    throw new InstallTransactionError("recovery_journal_invalid", "The prior install journal is invalid.");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new InstallTransactionError("recovery_journal_invalid", "The prior install journal is invalid.");
  }
  if (
    value.version !== INSTALL_JOURNAL_VERSION ||
    value.pluginId !== pluginId ||
    typeof value.transactionId !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/.test(value.transactionId) ||
    !Number.isSafeInteger(value.ownerPid) ||
    value.ownerPid <= 0 ||
    !Number.isSafeInteger(value.startedAtMs) ||
    value.startedAtMs <= 0 ||
    !JOURNAL_PHASES.has(value.phase) ||
    !Array.isArray(value.assets) ||
    value.assets.length === 0 ||
    value.assets.length > 32
  ) {
    throw new InstallTransactionError("recovery_journal_invalid", "The prior install journal is invalid.");
  }

  const seen = new Set();
  for (const item of value.assets) {
    if (
      !item ||
      typeof item !== "object" ||
      typeof item.asset !== "string" ||
      !/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/.test(item.asset) ||
      seen.has(item.asset) ||
      typeof item.newSha256 !== "string" ||
      !SHA256_PATTERN.test(item.newSha256) ||
      typeof item.hadOriginal !== "boolean" ||
      (item.hadOriginal
        ? typeof item.previousSha256 !== "string" || !SHA256_PATTERN.test(item.previousSha256)
        : item.previousSha256 !== null)
    ) {
      throw new InstallTransactionError("recovery_journal_invalid", "The prior install journal is invalid.");
    }
    seen.add(item.asset);
  }
  return value;
}

function assertSafeTransactionDirectory(pluginDir, transactionDir) {
  assertContained(pluginDir, transactionDir, "unsafe_transaction_path");
  if (!existsSync(transactionDir)) return;
  const stat = lstatSync(transactionDir);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new InstallTransactionError(
      "unsafe_transaction_path",
      "The install transaction path is not a regular directory.",
    );
  }
  const realPluginDir = realpathSync(pluginDir);
  const realTransactionDir = realpathSync(transactionDir);
  assertContained(realPluginDir, realTransactionDir, "unsafe_transaction_path");
}

function validateTransactionTree(transactionDir, journal) {
  const assetNames = new Set(journal.assets.map((item) => item.asset));
  const allowedRootEntries = new Set([
    INSTALL_JOURNAL_FILE,
    `${INSTALL_JOURNAL_FILE}.tmp`,
    "staging",
    "backup",
  ]);
  for (const name of readdirSync(transactionDir)) {
    if (!allowedRootEntries.has(name)) {
      throw new InstallTransactionError("recovery_journal_invalid", "The prior install transaction has unexpected files.");
    }
  }

  for (const directoryName of ["staging", "backup"]) {
    const directory = join(transactionDir, directoryName);
    if (!existsSync(directory)) continue;
    const stat = lstatSync(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      throw new InstallTransactionError("recovery_journal_invalid", "The prior install transaction is unsafe.");
    }
    for (const name of readdirSync(directory)) {
      if (!assetNames.has(name)) {
        throw new InstallTransactionError("recovery_journal_invalid", "The prior install transaction has unexpected files.");
      }
      safeFileDigest(join(directory, name), "recovery_journal_invalid");
    }
  }

  const tempJournal = join(transactionDir, `${INSTALL_JOURNAL_FILE}.tmp`);
  if (existsSync(tempJournal)) safeFileDigest(tempJournal, "recovery_journal_invalid");

  for (const item of journal.assets) {
    const stagedDigest = safeFileDigest(
      join(transactionDir, "staging", item.asset),
      "recovery_journal_invalid",
    );
    const backupDigest = safeFileDigest(
      join(transactionDir, "backup", item.asset),
      "recovery_journal_invalid",
    );
    if (stagedDigest !== null && stagedDigest !== item.newSha256) {
      throw new InstallTransactionError(
        "recovery_journal_invalid",
        "A staged install asset failed digest validation.",
      );
    }
    if (
      backupDigest !== null &&
      (!item.hadOriginal || backupDigest !== item.previousSha256)
    ) {
      throw new InstallTransactionError(
        "recovery_journal_invalid",
        "A backup install asset failed digest validation.",
      );
    }
  }
}

function rollbackInstallTransaction(pluginDir, transactionDir, journal) {
  const stagingDir = join(transactionDir, "staging");
  const backupDir = join(transactionDir, "backup");
  for (const item of [...journal.assets].reverse()) {
    const destination = join(pluginDir, item.asset);
    const staged = join(stagingDir, item.asset);
    const backup = join(backupDir, item.asset);
    const destinationDigest = safeFileDigest(destination, "recovery_conflict");
    const stagedDigest = safeFileDigest(staged, "recovery_journal_invalid");
    const backupDigest = safeFileDigest(backup, "recovery_journal_invalid");

    if (stagedDigest !== null && stagedDigest !== item.newSha256) {
      throw new InstallTransactionError("recovery_journal_invalid", "A staged install asset failed digest validation.");
    }
    if (
      backupDigest !== null &&
      (!item.hadOriginal || backupDigest !== item.previousSha256)
    ) {
      throw new InstallTransactionError("recovery_journal_invalid", "A backup install asset failed digest validation.");
    }
    if (
      destinationDigest !== null &&
      destinationDigest !== item.newSha256 &&
      destinationDigest !== item.previousSha256
    ) {
      throw new InstallTransactionError("recovery_conflict", "A live install asset changed during recovery.");
    }

    if (item.hadOriginal) {
      if (backupDigest !== null) {
        if (destinationDigest === item.newSha256) unlinkSync(destination);
        if (!existsSync(destination)) renameSync(backup, destination);
      } else if (destinationDigest !== item.previousSha256) {
        throw new InstallTransactionError("recovery_incomplete", "The prior installed asset cannot be restored.");
      }
    } else {
      if (backupDigest !== null) {
        throw new InstallTransactionError("recovery_journal_invalid", "An unexpected install backup exists.");
      }
      if (destinationDigest === item.newSha256) unlinkSync(destination);
    }
  }
}

function transactionIsFullyActivated(pluginDir, journal) {
  return journal.assets.every(
    (item) => safeFileDigest(join(pluginDir, item.asset), "recovery_conflict") === item.newSha256,
  );
}

export function recoverAbandonedInstallTransaction(layout, options = {}) {
  const { vaultPath, pluginsRoot, pluginDir, pluginId } = layout;
  const transactionDir = resolve(pluginDir, INSTALL_TRANSACTION_DIR_NAME);
  if (!existsSync(transactionDir)) return { recovered: false, outcome: "none" };

  assertSafeDestinationLayout(vaultPath, pluginsRoot, pluginDir);
  assertSafeTransactionDirectory(pluginDir, transactionDir);
  const journal = parseRecoveryJournal(transactionDir, pluginId);
  if (journal === null) {
    // The journal is written before staging/backup directories are created, so
    // a journal-less directory is removable only while it contains no state.
    const entries = readdirSync(transactionDir);
    if (entries.some((name) => name !== `${INSTALL_JOURNAL_FILE}.tmp`)) {
      throw new InstallTransactionError("recovery_journal_missing", "A prior install transaction has no recovery journal.");
    }
    removeTransactionDirectory(pluginDir, transactionDir);
    return { recovered: true, outcome: "empty-lock" };
  }

  const lockIsStale = Date.now() - journal.startedAtMs >= INSTALL_LOCK_STALE_AFTER_MS;
  if (!options.ignoreLiveOwner && !lockIsStale && isProcessAlive(journal.ownerPid)) {
    throw new InstallTransactionError("transaction_locked", "Another plugin install transaction is active.");
  }

  validateTransactionTree(transactionDir, journal);
  if (journal.phase === "activated" && transactionIsFullyActivated(pluginDir, journal)) {
    removeTransactionDirectory(pluginDir, transactionDir);
    return { recovered: true, outcome: "committed" };
  }

  rollbackInstallTransaction(pluginDir, transactionDir, journal);
  removeTransactionDirectory(pluginDir, transactionDir);
  return { recovered: true, outcome: "rolled-back" };
}

function removeTransactionDirectory(pluginDir, transactionDir) {
  assertContained(pluginDir, transactionDir, "unsafe_transaction_path");
  assertSafeTransactionDirectory(pluginDir, transactionDir);
  rmSync(transactionDir, { recursive: true, force: true });
}

function sha256File(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
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

const invokedPath = process.argv[1] ? resolve(process.argv[1]) : "";
if (invokedPath === resolve(fileURLToPath(import.meta.url))) runCli();
