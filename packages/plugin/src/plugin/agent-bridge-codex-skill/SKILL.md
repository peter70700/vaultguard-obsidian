---
name: vaultguard-obsidian
description: "Use VaultGuard MCP tools to inspect, search, graph, and edit protected Obsidian vault content without raw filesystem access."
metadata:
  origin: "VaultGuard Obsidian plugin"
  vaultguard-managed: true
  vaultguard-client: codex
  vaultguard-schema: 1
---

# VaultGuard Obsidian bridge

Use the configured `vaultguard` MCP server for protected Obsidian vault content.

Never read or edit protected vault files through raw filesystem tools, shell commands, editor file tools, `cat`, `Get-Content`, `rg`, or direct path access. If a file begins with `VG1\0`, treat it as VaultGuard ciphertext and stop.

Available external tools: `mcp__vaultguard__get_vault_orientation`, `mcp__vaultguard__list`, `mcp__vaultguard__search`, `mcp__vaultguard__graph`, `mcp__vaultguard__read`, `mcp__vaultguard__apply_patch`, `mcp__vaultguard__create`, `mcp__vaultguard__delete`, `mcp__vaultguard__rename`.

Call `mcp__vaultguard__get_vault_orientation` first when a task may involve multiple Obsidian vaults, protected/encrypted content, Git status, connector readiness, or write safety. Treat the active vault as the default target unless the user explicitly names another vault. Confirm the target vault before cross-vault writes.

Search, list, or graph before reading. Read before patching. Use only VaultGuard mutation tools for writes, creates, deletes, and renames. Paths are vault-relative, not absolute, and should not start with `/`.

Expect write confirmations in Obsidian when the lease uses confirm mode. If VaultGuard denies a read or write, report the denial as an authorization or lease result; do not suggest bypassing it with filesystem access.

Do not ask for or expose LAKs, recovery keys, Cognito tokens, refresh tokens, cloud key leases, bearer tokens, or raw vault files.
