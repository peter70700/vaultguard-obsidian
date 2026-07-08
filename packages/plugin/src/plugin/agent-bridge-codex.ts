export const CODEX_MCP_SERVER_ID = "vaultguard";
export const CODEX_TOKEN_ENV_VAR = "VAULTGUARD_AGENT_TOKEN";

export const CODEX_MCP_ENABLED_TOOLS = [
  "list",
  "get_vault_orientation",
  "search",
  "graph",
  "read",
  "apply_patch",
  "create",
  "delete",
  "rename",
] as const;

export interface CodexConfigOptions {
  mcpEndpoint: string;
  serverId?: string;
  tokenEnvVar?: string;
  enabledTools?: ReadonlyArray<string>;
  startupTimeoutSec?: number;
  toolTimeoutSec?: number;
}

function tomlString(value: string): string {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function tomlArray(values: ReadonlyArray<string>): string {
  return `[${values.map((value) => tomlString(value)).join(", ")}]`;
}

function powershellSingleQuoted(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

export function buildCodexConfigToml(options: CodexConfigOptions): string {
  const serverId = options.serverId ?? CODEX_MCP_SERVER_ID;
  const tokenEnvVar = options.tokenEnvVar ?? CODEX_TOKEN_ENV_VAR;
  const enabledTools = options.enabledTools ?? CODEX_MCP_ENABLED_TOOLS;
  const startupTimeoutSec = options.startupTimeoutSec ?? 20;
  const toolTimeoutSec = options.toolTimeoutSec ?? 120;

  return [
    "# Paste into ~/.codex/config.toml, or into a trusted non-vault project .codex/config.toml.",
    "# Do not paste the VaultGuard bearer token here. Set VAULTGUARD_AGENT_TOKEN in",
    "# the shell that launches Codex.",
    "",
    `[mcp_servers.${serverId}]`,
    `url = ${tomlString(options.mcpEndpoint)}`,
    `bearer_token_env_var = ${tomlString(tokenEnvVar)}`,
    "enabled = true",
    `enabled_tools = ${tomlArray(enabledTools)}`,
    'default_tools_approval_mode = "prompt"',
    `startup_timeout_sec = ${startupTimeoutSec}`,
    `tool_timeout_sec = ${toolTimeoutSec}`,
  ].join("\n");
}

export function buildCodexTokenEnvCommand(
  token: string,
  tokenEnvVar = CODEX_TOKEN_ENV_VAR,
): string {
  return `$env:${tokenEnvVar} = ${powershellSingleQuoted(token)}`;
}

export function buildCodexTempWorkspaceLaunchCommand(
  token: string,
  tokenEnvVar = CODEX_TOKEN_ENV_VAR,
): string {
  return [
    "$workspace = Join-Path $env:TEMP 'vaultguard-codex-empty'",
    "New-Item -ItemType Directory -Force -Path $workspace | Out-Null",
    buildCodexTokenEnvCommand(token, tokenEnvVar),
    "codex --cd $workspace",
  ].join("\n");
}

export function buildCodexAgentsGuidance(): string {
  return [
    "## VaultGuard-Protected Obsidian Vaults",
    "",
    "Do not inspect protected vault contents through raw filesystem reads, shell commands, or editor file tools. Use the configured VaultGuard MCP server: `mcp__vaultguard__get_vault_orientation/list/search/graph/read/apply_patch/create/delete/rename`.",
    "",
    "Call `mcp__vaultguard__get_vault_orientation` first when a task may involve multiple vaults, protected/encrypted content, Git state, connector readiness, or write safety. Treat the active vault as the default target unless the user names another vault, and confirm the target vault before cross-vault writes.",
    "",
    "Launch Codex from an empty temporary working directory for protected-vault work. Treat `VG1\\0` bytes as ciphertext. All writes must go through VaultGuard MCP mutation tools and may require Obsidian confirmation.",
  ].join("\n");
}
