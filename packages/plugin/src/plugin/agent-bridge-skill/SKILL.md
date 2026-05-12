---
name: vaultguard
description: "Read, search, and edit files inside an Obsidian vault that's protected by the VaultGuard plugin's at-rest encryption. Use this skill whenever the user asks you to look at notes, find something in their vault, or edit a file under an Obsidian vault path AND the on-disk files start with the bytes 'VG1' (a VaultGuard ciphertext header). Triggers on: 'find X in my notes', 'read my note about Y', 'edit Z in my vault', 'search my Obsidian vault', or any case where Read/Grep/Glob against vault paths returns binary that starts with VG1."
metadata:
  origin: "VaultGuard Obsidian plugin"
  vaultguard-managed: true
  vaultguard-schema: 2
---

# VaultGuard agent bridge

The user is working in an Obsidian vault that the VaultGuard plugin encrypts on disk. Files in the vault folder are not plaintext — every protected file starts with the four bytes `VG1\0` (hex `56 47 31 00`) followed by AES-256-GCM ciphertext. Standard filesystem reads return that ciphertext. To get plaintext, you must call VaultGuard's MCP tools instead of `Read`/`Glob`/`Grep`/`Edit`/`Write` against the vault directory.

## When this skill applies

Use this skill when **all** of these are true:

1. The path the user is asking about lives inside an Obsidian vault (e.g. anything under a folder containing `.obsidian/`).
2. Either the user has explicitly told you the vault is protected by VaultGuard, or you tried `Read` on a vault file and the first bytes were `VG1\0` / the content looks like binary garbage.
3. The user has registered the `vaultguard` MCP server with the agent (so `mcp__vaultguard__*` tools are available in this session).

If the MCP server is not registered, **stop** and tell the user: "Your vault appears to be protected by VaultGuard but the `vaultguard` MCP server isn't connected. Open Obsidian → run `VaultGuard: Create Agent Bridge Lease`, paste the connection JSON into your MCP config, and restart this session." Do not fall back to reading the encrypted bytes.

## The tools

All paths are vault-relative (no leading `/`, no absolute filesystem paths). Hidden directories like `.obsidian/`, `.trash/`, `.git/` are always blocked — do not try to read them.

- **`mcp__vaultguard__list({ scope?, limit? })`** — list visible files in the vault. Use first when the user asks "find X" or names a file you don't have an exact path for. `scope` is an optional vault-relative glob (e.g. `project-x/**`) to narrow within the lease scope. The result includes a `permission` label per file (`read` / `write` / `admin`) — that's the user's *file-level* permission, separate from the lease.

- **`mcp__vaultguard__search({ query, scope?, limit? })`** — case-insensitive substring search across visible text files. Returns `{ path, line, snippet }` per match. Always prefer this to listing every file and reading them.

- **`mcp__vaultguard__read({ path, maxBytes? })`** — read a single text file as plaintext. Refuses non-text files (only `.md`, `.txt`, `.canvas`, `.csv`, `.tsv`, `.json`, `.yaml`, `.yml`). Result is `{ path, content, bytes, truncated }` — if `truncated: true`, you saw only the first `maxBytes` of UTF-8.

- **`mcp__vaultguard__apply_patch({ path, diff })`** — apply a unified diff (with `@@` hunks) to an existing text file. Hunks must match the current file exactly. Subject to the permission stack below.

- **`mcp__vaultguard__create({ path, content })`** — create a new text file. Refuses to overwrite existing files; use `apply_patch` for edits. Subject to the permission stack below.

## Permission stack (READ THIS BEFORE SUGGESTING FIXES)

A write attempt can be rejected at three independent layers. The error message tells you *which* layer rejected — read it carefully and only suggest the matching fix. **Do not blanket-suggest "ask the user to mint a writeMode: allow lease".** That's almost never the right answer, and `allow` mode isn't even available for persistent leases.

The three layers, evaluated in order:

### Layer 1 — Lease scope (path coverage)

Every lease has one or more glob scopes (e.g. `/project-x/**`). A path outside every scope is rejected before any permission check.

- **Error:** `VaultGuard agent lease does not cover "X"`
- **Fix:** The lease was minted for a narrower set of paths than the user wants to touch. Tell them the current scope and the requested path, and ask whether they want to mint a *new* lease with broader scope (or work within the current one). Do not suggest changing the lease's writeMode — scope is a different gate.

### Layer 2 — Lease writeMode (bridge-side write gate)

Each lease has a `writeMode`: `deny` (read-only), `confirm` (every write pops an in-Obsidian prompt), or `allow` (writes proceed silently — only available for ephemeral leases, never persistent ones).

- **Error:** `VaultGuard agent lease is read-only` → the lease was minted as `writeMode: deny`. Ask the user to mint a new lease with `writeMode: confirm`. Do **not** ask for `writeMode: allow` — `confirm` already works (the user just sees a per-file prompt) and `allow` is rejected for persistent leases.
- **Error:** `VaultGuard agent lease does not allow reads` → the lease has `allowRead: false`. Same fix shape: ask for a new lease with reads enabled.
- **Error:** `VaultGuard agent bridge write to "X" was not approved` → the lease is `writeMode: confirm` and the user clicked "deny" on the confirmation prompt. They saw the write and rejected it. Don't retry — ask whether they intended to deny, and surface what was about to be written so they can decide.

### Layer 3 — File-level VaultGuard permission

Independent of the lease, VaultGuard enforces per-file permissions (NONE / READ / WRITE / ADMIN) for the logged-in user. Even with `writeMode: allow` on the lease, a write to a file the user doesn't have WRITE permission on still fails.

- **Error:** `VaultGuard agent bridge: no WRITE permission for "X"` → the user's *vault-side* permissions deny WRITE on this specific file. **This is not a lease problem; minting a new lease will not fix it.** Tell the user: "You don't have WRITE permission on `X` according to VaultGuard's vault-side permission rules — that's separate from the agent lease. To grant WRITE, open the file in Obsidian and check the permission header (or ask a vault admin). If you only need to read this file, I can do that instead."

### Quick diagnostic table

| Error contains | Layer | Right fix |
|---|---|---|
| `does not cover` | scope | New lease with wider scope (or work within current scope) |
| `is read-only` | writeMode | New lease with `writeMode: confirm` (not `allow`) |
| `does not allow reads` | writeMode | New lease with reads enabled |
| `was not approved` | writeMode (user denied) | Don't retry; ask the user what they intended |
| `no WRITE permission for` | file-level | User changes vault permissions; new lease won't help |
| `refuses access to local-only or hidden path` | excluded paths | Stop — `.obsidian/`, `.trash/`, etc. are out of scope by design |
| `is missing, expired, or revoked` | lease lifecycle | User mints a new lease (TTL ran out / they logged out / they revoked it) |
| `refuses to overwrite existing file` | tool semantics | Use `apply_patch` instead of `create` |
| `refuses to read non-text file` | tool semantics | The file isn't `.md`/`.txt`/`.canvas`/etc.; can't be read through this surface |

## Workflow

1. **Always discover before reading.** If the user says "look at my notes about X", call `mcp__vaultguard__search({ query: "X" })` first. Only call `read` once you have an exact path.

2. **Never call `Read`, `Glob`, `Grep`, `Edit`, `Write`, or shell commands against the vault directory.** Even if the path looks innocent, the file is ciphertext. Use the MCP tools.

3. **Don't mix transports for the same vault.** If you read a file via `mcp__vaultguard__read`, edit it via `mcp__vaultguard__apply_patch` — not via the built-in `Edit` tool. Otherwise the at-rest encryption layer breaks: built-in `Edit` would write the new content as plaintext, and the next time the Obsidian plugin opens the file it would see plaintext where ciphertext is expected.

4. **Check the `permission` label from `list` before attempting a write.** When you call `mcp__vaultguard__list`, each entry includes a `permission` label. If it's `"read"`, don't even try `apply_patch` / `create` — you'll hit a Layer-3 error and waste the round-trip. Tell the user up front: "I see you have read-only access to `X` according to VaultGuard. I can read it but can't edit it without a permission change."

5. **Patch carefully.** `apply_patch` expects a strict unified diff. Read the file first, compute the diff against that exact content, then patch. If `apply_patch` returns "does not apply cleanly", re-read the file (it may have changed) and recompute.

6. **Never recommend `writeMode: allow` reflexively.** It's the riskiest mode (writes happen silently with no per-file confirmation), it's *rejected* for persistent leases, and `confirm` already works for any "I want to allow writes" use case. The user gets one prompt per write — that's the safety property they're paying for.

## What VaultGuard's MCP tools do not do

- **No filesystem walks outside the vault.** You cannot use these tools to read anything outside the bound vault folder.
- **No binary file content.** Images, PDFs, audio, etc. are blocked at the bridge — VaultGuard's text-only tool surface is intentional.
- **No raw key material.** The bridge never returns the local at-rest key, the cloud key lease, or the user's Cognito tokens. Don't ask for them; they aren't reachable through this surface.
- **No long-running operations.** Each tool call is request/response; there's no streaming and no progress indication.
- **No vault-side permission changes.** The bridge cannot grant WRITE on a file you don't have it for. That's a separate operation done in the Obsidian permission UI.

If the user asks for something outside this surface (read a PNG, run a shell command in the vault folder, get a key, grant themselves WRITE on a file), explain that the bridge intentionally doesn't expose that, and ask them what they're actually trying to accomplish.
