import type { App } from "obsidian";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { stat } from "node:fs/promises";
import path from "node:path";
import type { VaultRecord } from "../api/client";
import type { AiChatProvider, AiChatPermissionMode, VaultGuardSettings } from "../types";

export type AgentConnectorKind =
  | "claude-mcp"
  | "codex-mcp"
  | "internal-openai-chat"
  | "internal-claude-chat"
  | "chatgpt-remote"
  | "unknown";

export type AgentConnectorTransport = "mcp" | "rpc" | "inproc" | "chatgpt-mcp";
export type AgentConnectorProfile =
  | "external-lease"
  | "internal-chat"
  | "chatgpt-read-only"
  | "diagnostics";
export type OrientationWriteMode = "disabled" | "confirm" | "allowed";

export interface AgentConnectorContext {
  connector: AgentConnectorKind;
  transport: AgentConnectorTransport;
  profile: AgentConnectorProfile;
  writeMode: OrientationWriteMode;
}

export interface VaultOrientationOptions {
  includeKnownVaults?: boolean;
  includeGit?: boolean;
  includeConnectorStatus?: boolean;
  forceRefresh?: boolean;
}

export interface GitOrientationSummary {
  detected: boolean;
  rootRelativePath?: string;
  branch?: string;
  dirty?: boolean;
  ahead?: number;
  behind?: number;
  remoteHostKinds?: string[];
  remoteUrlsRedacted?: boolean;
  statusReason?: string;
}

export type ConnectorAvailability =
  | "available"
  | "not-configured"
  | "disabled"
  | "developer-only"
  | "not-implemented";

export interface ConnectorStatusMatrix {
  claude: ConnectorAvailability;
  codex: ConnectorAvailability;
  openaiChat: ConnectorAvailability;
  chatgptRemote: ConnectorAvailability;
}

export interface VaultOrientationEntry {
  id: string;
  displayName: string;
  role: "active" | "known" | "recent" | "linked";
  locationKind: "local" | "cloud" | "org" | "remote" | "unknown";
  storageKind: "local-filesystem" | "vaultguard-cloud" | "hybrid" | "unknown";
  protection: {
    encrypted: boolean;
    localProjectMemoryMode: boolean;
    protectedContentRequiresVaultGuardTools: boolean;
  };
  git: GitOrientationSummary;
  connectors: ConnectorStatusMatrix;
  capabilities: {
    canList: boolean;
    canSearch: boolean;
    canRead: boolean;
    canGraph: boolean;
    canWriteWithConfirmation: boolean;
    canDeleteWithConfirmation: boolean;
    canRenameWithConfirmation: boolean;
  };
  safety: {
    rawFilesystemAccessAllowed: boolean;
    writeMode: OrientationWriteMode;
    reason: string;
  };
}

export interface VaultOrientationSnapshot {
  activeVault: VaultOrientationEntry;
  knownVaults: VaultOrientationEntry[];
  connectorContext: AgentConnectorContext;
  generatedAt: string;
  limits: {
    maxVaults: number;
    maxGitRemotesShown: number;
    redactedFields: string[];
  };
}

export interface VaultOrientationDeps {
  app: App;
  getSettings(): VaultGuardSettings;
  getAtRestEncrypted(): boolean;
  getConnectorStatus(): ConnectorStatusMatrix;
  listServerVaults(): Promise<VaultRecord[]>;
  logError(message: string, error: unknown): void;
}

interface SnapshotCacheEntry {
  key: string;
  expiresAt: number;
  value: VaultOrientationSnapshot;
}

interface GitCacheEntry {
  basePath: string;
  includeStatus: boolean;
  expiresAt: number;
  value: GitOrientationSummary;
}

const SNAPSHOT_TTL_MS = 10_000;
const GIT_TTL_MS = 20_000;
const GIT_TIMEOUT_MS = 2_000;
const GIT_MAX_BUFFER = 64 * 1024;
const MAX_VAULTS = 25;
const MAX_GIT_REMOTES_SHOWN = 5;
const REDACTED_FIELDS = [
  "absoluteLocalPath",
  "gitRemoteUrl",
  "gitRemoteUsername",
  "gitRemoteToken",
  "apiKey",
  "bridgeToken",
  "connectorAccessToken",
  "sessionToken",
  "recoveryKey",
  "localAccessKey",
  "cloudKeyLease",
];

export class VaultOrientationService {
  private snapshotCache: SnapshotCacheEntry | null = null;
  private gitCache: GitCacheEntry | null = null;

  constructor(private readonly deps: VaultOrientationDeps) {}

  invalidate(_reason: string): void {
    this.snapshotCache = null;
    this.gitCache = null;
  }

  async getSnapshot(
    context: AgentConnectorContext,
    options: VaultOrientationOptions = {},
  ): Promise<VaultOrientationSnapshot> {
    const normalizedOptions = {
      includeKnownVaults: options.includeKnownVaults === true,
      includeGit: options.includeGit !== false,
      includeConnectorStatus: options.includeConnectorStatus !== false,
    };
    const key = JSON.stringify({ context, options: normalizedOptions });
    const now = Date.now();
    if (!options.forceRefresh && this.snapshotCache?.key === key && this.snapshotCache.expiresAt > now) {
      return this.snapshotCache.value;
    }

    const connectors = normalizedOptions.includeConnectorStatus
      ? this.deps.getConnectorStatus()
      : disabledConnectorStatus();
    const git = normalizedOptions.includeGit
      ? await this.getGitSummary({ includeStatus: true })
      : { detected: false, statusReason: "Git summary omitted by request." };
    const activeVault = await this.getActiveVaultEntry(context, { connectors, git });
    const knownVaults = normalizedOptions.includeKnownVaults
      ? await this.listKnownVaults({ activeVault, connectors })
      : [];
    const snapshot: VaultOrientationSnapshot = {
      activeVault,
      knownVaults,
      connectorContext: context,
      generatedAt: new Date().toISOString(),
      limits: {
        maxVaults: MAX_VAULTS,
        maxGitRemotesShown: MAX_GIT_REMOTES_SHOWN,
        redactedFields: [...REDACTED_FIELDS],
      },
    };

    this.snapshotCache = { key, expiresAt: now + SNAPSHOT_TTL_MS, value: snapshot };
    return snapshot;
  }

  async getActiveVaultEntry(
    context: AgentConnectorContext,
    precomputed?: { connectors?: ConnectorStatusMatrix; git?: GitOrientationSummary },
  ): Promise<VaultOrientationEntry> {
    const settings = this.deps.getSettings();
    const hasServerVault = Boolean(settings.serverVaultId?.trim());
    const localMode = settings.localProjectMemoryMode === true;
    const encrypted = !localMode && this.deps.getAtRestEncrypted();
    const displayName =
      settings.serverVaultName?.trim() ||
      settings.serverVaultSlug?.trim() ||
      this.safeVaultName();
    const localBasePath = this.getLocalVaultBasePath();
    const id = hasServerVault
      ? `server-vault:${settings.serverVaultId.trim()}`
      : `local-vault:${this.hashLocalVaultId(localBasePath ?? this.safeVaultName())}`;
    const connectors = precomputed?.connectors ?? this.deps.getConnectorStatus();
    const git = precomputed?.git ?? { detected: false, statusReason: "Git summary not requested." };
    const storageKind = localMode
      ? "local-filesystem"
      : hasServerVault
        ? "hybrid"
        : localBasePath
          ? "local-filesystem"
          : "unknown";

    return {
      id,
      displayName,
      role: "active",
      locationKind: localMode ? "local" : hasServerVault ? "org" : "local",
      storageKind,
      protection: {
        encrypted,
        localProjectMemoryMode: localMode,
        protectedContentRequiresVaultGuardTools: !localMode && (encrypted || hasServerVault),
      },
      git,
      connectors,
      capabilities: capabilitiesForContext(context),
      safety: safetyForContext(context, localMode, encrypted || hasServerVault),
    };
  }

  async listKnownVaults(options: {
    activeVault?: VaultOrientationEntry;
    connectors?: ConnectorStatusMatrix;
  } = {}): Promise<VaultOrientationEntry[]> {
    const activeVault =
      options.activeVault ??
      (await this.getActiveVaultEntry(diagnosticsConnectorContext(), {
        connectors: options.connectors,
        git: { detected: false, statusReason: "Git summary omitted for known vault list." },
      }));
    const settings = this.deps.getSettings();
    if (settings.localProjectMemoryMode) return [activeVault];

    let records: VaultRecord[] = [];
    try {
      records = await this.deps.listServerVaults();
    } catch {
      return [activeVault];
    }

    const connectors = options.connectors ?? this.deps.getConnectorStatus();
    const known = records.slice(0, MAX_VAULTS).map((vault) =>
      this.entryFromServerVault(vault, connectors, vault.vaultId === settings.serverVaultId),
    );
    if (!known.some((entry) => entry.id === activeVault.id)) {
      known.unshift(activeVault);
    }
    return known.slice(0, MAX_VAULTS);
  }

  getConnectorStatus(): ConnectorStatusMatrix {
    return this.deps.getConnectorStatus();
  }

  async getGitSummary(options: { includeStatus?: boolean; forceRefresh?: boolean } = {}): Promise<GitOrientationSummary> {
    const basePath = this.getLocalVaultBasePath();
    if (!basePath) {
      return {
        detected: false,
        statusReason: "Local filesystem adapter is unavailable.",
      };
    }

    const includeStatus = options.includeStatus === true;
    const now = Date.now();
    if (
      !options.forceRefresh &&
      this.gitCache?.basePath === basePath &&
      this.gitCache.includeStatus === includeStatus &&
      this.gitCache.expiresAt > now
    ) {
      return this.gitCache.value;
    }

    const gitPath = path.join(basePath, ".git");
    const detected = await pathExists(gitPath);
    if (!detected) {
      const value = { detected: false, statusReason: "No .git entry at the active vault root." };
      this.gitCache = { basePath, includeStatus, expiresAt: now + GIT_TTL_MS, value };
      return value;
    }

    let value: GitOrientationSummary = {
      detected: true,
      rootRelativePath: ".",
      statusReason: includeStatus ? undefined : "Git status omitted by request.",
    };
    if (includeStatus) {
      value = await this.readGitStatus(basePath, value);
    }
    this.gitCache = { basePath, includeStatus, expiresAt: now + GIT_TTL_MS, value };
    return value;
  }

  redactForClipboard(snapshot: VaultOrientationSnapshot): VaultOrientationSnapshot {
    return JSON.parse(JSON.stringify(snapshot)) as VaultOrientationSnapshot;
  }

  private entryFromServerVault(
    vault: VaultRecord,
    connectors: ConnectorStatusMatrix,
    active: boolean,
  ): VaultOrientationEntry {
    const localMode = this.deps.getSettings().localProjectMemoryMode === true;
    return {
      id: `server-vault:${vault.vaultId}`,
      displayName: vault.name || vault.slug || "VaultGuard vault",
      role: active ? "active" : "known",
      locationKind: "org",
      storageKind: active ? "hybrid" : "vaultguard-cloud",
      protection: {
        encrypted: !localMode,
        localProjectMemoryMode: localMode,
        protectedContentRequiresVaultGuardTools: !localMode,
      },
      git: active
        ? { detected: false, statusReason: "Git summary omitted for server vault list." }
        : { detected: false, statusReason: "Git is only detected for the active local vault root." },
      connectors,
      capabilities: capabilitiesForContext(diagnosticsConnectorContext()),
      safety: {
        rawFilesystemAccessAllowed: false,
        writeMode: "confirm",
        reason: "Server vault metadata only. File access must go through VaultGuard permission checks.",
      },
    };
  }

  private async readGitStatus(basePath: string, fallback: GitOrientationSummary): Promise<GitOrientationSummary> {
    try {
      const status = await runGit(basePath, ["status", "--porcelain=v1", "--branch", "--untracked-files=no"]);
      const remoteOutput = await runGit(basePath, ["remote", "-v"]).catch(() => "");
      return {
        ...fallback,
        ...parseGitStatus(status),
        ...parseGitRemotes(remoteOutput),
      };
    } catch (error) {
      this.deps.logError("Vault orientation Git status failed", error);
      return {
        ...fallback,
        statusReason: "Git repository detected, but bounded status command failed.",
      };
    }
  }

  private getLocalVaultBasePath(): string | null {
    const adapter = this.deps.app.vault.adapter;
    const maybeAdapter = adapter as { getBasePath?: () => string };
    if (typeof maybeAdapter.getBasePath === "function") {
      try {
        return maybeAdapter.getBasePath();
      } catch {
        return null;
      }
    }
    return null;
  }

  private safeVaultName(): string {
    try {
      return this.deps.app.vault.getName() || "Current Obsidian vault";
    } catch {
      return "Current Obsidian vault";
    }
  }

  private hashLocalVaultId(value: string): string {
    return createHash("sha256").update(value).digest("hex").slice(0, 16);
  }
}

export function diagnosticsConnectorContext(): AgentConnectorContext {
  return {
    connector: "unknown",
    transport: "inproc",
    profile: "diagnostics",
    writeMode: "confirm",
  };
}

export function connectorContextForProvider(
  provider: AiChatProvider,
  permissionMode: AiChatPermissionMode,
): AgentConnectorContext {
  const connector =
    provider === "openai"
      ? "internal-openai-chat"
      : provider === "subscription" || provider === "apiKey"
        ? "internal-claude-chat"
        : "unknown";
  return {
    connector,
    transport: "inproc",
    profile: "internal-chat",
    writeMode: permissionMode === "skip" ? "allowed" : "confirm",
  };
}

function capabilitiesForContext(context: AgentConnectorContext): VaultOrientationEntry["capabilities"] {
  const canWrite = context.writeMode === "confirm" || context.writeMode === "allowed";
  const readOnly = context.profile === "chatgpt-read-only";
  return {
    canList: true,
    canSearch: true,
    canRead: true,
    canGraph: true,
    canWriteWithConfirmation: canWrite && !readOnly,
    canDeleteWithConfirmation: canWrite && !readOnly,
    canRenameWithConfirmation: canWrite && !readOnly,
  };
}

function safetyForContext(
  context: AgentConnectorContext,
  localProjectMemoryMode: boolean,
  protectedContent: boolean,
): VaultOrientationEntry["safety"] {
  if (context.profile === "chatgpt-read-only") {
    return {
      rawFilesystemAccessAllowed: false,
      writeMode: "disabled",
      reason: "ChatGPT connector profile is read-only and must use scoped VaultGuard tools.",
    };
  }
  if (localProjectMemoryMode) {
    return {
      rawFilesystemAccessAllowed: context.profile === "diagnostics",
      writeMode: context.writeMode,
      reason: "Local Project Memory Mode keeps repo-root project files plaintext; protected VaultGuard cloud features stay disabled.",
    };
  }
  return {
    rawFilesystemAccessAllowed: false,
    writeMode: context.writeMode,
    reason: protectedContent
      ? "Use VaultGuard tools for protected content; writes remain permission-checked and confirmation-gated."
      : "Use VaultGuard tools for agent operations; do not assume raw filesystem access.",
  };
}

function disabledConnectorStatus(): ConnectorStatusMatrix {
  return {
    claude: "disabled",
    codex: "disabled",
    openaiChat: "disabled",
    chatgptRemote: "disabled",
  };
}

async function pathExists(target: string): Promise<boolean> {
  try {
    await stat(target);
    return true;
  } catch {
    return false;
  }
}

function runGit(cwd: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(
      "git",
      ["-C", cwd, ...args],
      {
        timeout: GIT_TIMEOUT_MS,
        windowsHide: true,
        maxBuffer: GIT_MAX_BUFFER,
      },
      (error, stdout) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(stdout);
      },
    );
  });
}

function parseGitStatus(output: string): Pick<GitOrientationSummary, "branch" | "dirty" | "ahead" | "behind"> {
  const lines = output.split(/\r?\n/).filter(Boolean);
  const branchLine = lines.find((line) => line.startsWith("## "));
  const statusLines = lines.filter((line) => !line.startsWith("## "));
  const parsed: Pick<GitOrientationSummary, "branch" | "dirty" | "ahead" | "behind"> = {
    dirty: statusLines.length > 0,
  };
  if (!branchLine) return parsed;

  const rawBranch = branchLine.slice(3).split(" ")[0];
  parsed.branch = rawBranch.split("...")[0];
  const aheadMatch = /\bahead\s+(\d+)/.exec(branchLine);
  const behindMatch = /\bbehind\s+(\d+)/.exec(branchLine);
  if (aheadMatch) parsed.ahead = Number(aheadMatch[1]);
  if (behindMatch) parsed.behind = Number(behindMatch[1]);
  return parsed;
}

function parseGitRemotes(output: string): Pick<GitOrientationSummary, "remoteHostKinds" | "remoteUrlsRedacted"> {
  const hostKinds = new Set<string>();
  for (const line of output.split(/\r?\n/)) {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 2) continue;
    hostKinds.add(hostKindFromRemote(parts[1]));
    if (hostKinds.size >= MAX_GIT_REMOTES_SHOWN) break;
  }
  return {
    remoteHostKinds: Array.from(hostKinds),
    remoteUrlsRedacted: hostKinds.size > 0,
  };
}

function hostKindFromRemote(remote: string): string {
  const lower = remote.toLowerCase();
  if (lower.includes("github.com")) return "github";
  if (lower.includes("gitlab.com")) return "gitlab";
  if (lower.includes("bitbucket.org")) return "bitbucket";
  if (lower.includes("dev.azure.com") || lower.includes("visualstudio.com")) return "azure";
  if (lower.startsWith("http://") || lower.startsWith("https://") || lower.includes("@")) return "other";
  return "local";
}
