// MCP config + tool allow/deny lists for driving the official `claude` binary
// against VaultGuard's AgentBridge (docs/AI-CHAT-PANEL.md "Auth & providers").
//
// ENCRYPTION BOUNDARY: the spawned `claude` must reach vault content ONLY
// through the AgentBridge MCP server (localhost, lease-scoped, permission-checked,
// confirmWrite-gated). We enforce that with three locks, all set here / by the
// client:
//   1. --strict-mcp-config + this single HTTP MCP server entry (no .mcp.json /
//      CLAUDE.md discovery — the client also spawns in a neutral empty cwd).
//   2. --allowedTools = ONLY the six mcp__vaultguard__* tools.
//   3. --permission-mode dontAsk so anything not explicitly allowed is denied
//      without an interactive prompt. We intentionally do not pass
//      --disallowedTools because built-in names vary across CLI versions.
//
// This module is pure (string/JSON building) so it is trivially unit-tested.

// The six AgentBridge tools, namespaced the way `claude` exposes MCP tools:
// mcp__<serverName>__<toolName>. Server name is "vaultguard" (see buildMcpConfig).
export const VAULTGUARD_MCP_TOOL_NAMES: ReadonlyArray<string> = [
  "mcp__vaultguard__list",
  "mcp__vaultguard__search",
  "mcp__vaultguard__read",
  "mcp__vaultguard__apply_patch",
  "mcp__vaultguard__create",
  "mcp__vaultguard__graph",
];

// Built-in tools to explicitly deny. Belt-and-suspenders alongside
// --permission-mode dontAsk (which already denies anything not in --allowedTools):
// enumerating these makes the intent auditable and survives a future default
// where unlisted tools might be auto-allowed. Names verified against the
// `system`/init `tools[]` array emitted by claude 2.1.181.
export const BUILTIN_DENY: ReadonlyArray<string> = [
  // Filesystem + shell — the tools that would bypass the encryption boundary.
  "Bash",
  "Read",
  "Write",
  "Edit",
  "MultiEdit",
  "NotebookEdit",
  "Glob",
  "Grep",
  // Web egress.
  "WebFetch",
  "WebSearch",
  // Agent / task / planning machinery we don't want spawned.
  "Task",
  "TodoWrite",
  "AskUserQuestion",
  "ToolSearch",
  "Skill",
  "EnterPlanMode",
  "ExitPlanMode",
];

// The MCP server name the tools namespace under. Keep in sync with the
// mcp__vaultguard__ prefix in VAULTGUARD_MCP_TOOL_NAMES.
const MCP_SERVER_NAME = "vaultguard";

export interface McpConfigJson {
  mcpServers: {
    [name: string]: {
      type: "http";
      url: string;
      headers: { Authorization: string };
    };
  };
}

/**
 * Build the strict HTTP-MCP config object pointing `claude` at VaultGuard's
 * AgentBridge MCP endpoint, authenticated with a lease bearer token.
 *
 * The returned object is passed to `claude --mcp-config '<json>'`. The lease
 * token is the AgentBridge per-lease bearer (NOT an Anthropic token) — it scopes
 * the CLI to exactly the files the lease permits, with writes diff-gated.
 */
export function buildMcpConfig(mcpUrl: string, leaseToken: string): McpConfigJson {
  return {
    mcpServers: {
      [MCP_SERVER_NAME]: {
        type: "http",
        url: mcpUrl,
        headers: { Authorization: `Bearer ${leaseToken}` },
      },
    },
  };
}

/** Serialize the MCP config for the `--mcp-config` CLI argument. */
export function serializeMcpConfig(config: McpConfigJson): string {
  return JSON.stringify(config);
}
