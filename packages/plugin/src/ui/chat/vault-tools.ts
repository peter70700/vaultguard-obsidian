// Claude tool definitions for the vault surface (AI-CHAT-PANEL.md §6.1).
//
// These mirror the EXACT input schemas declared for the MCP surface in
// `src/plugin/agent-bridge.ts` (MCP_TOOLS, ~lines 219-290) so there is one
// source of truth for the tool shapes — same field names, same type/minimum/
// required constraints — but using the long `vaultguard_*` names the in-process
// tool runtime dispatches on.

export type VaultToolName =
  | "vaultguard_list"
  | "vaultguard_search"
  | "vaultguard_read"
  | "vaultguard_apply_patch"
  | "vaultguard_create"
  | "vaultguard_graph";

export interface VaultToolDef {
  name: VaultToolName;
  description: string;
  input_schema: Record<string, unknown>;
}

export const VAULT_TOOL_DEFS = [
  {
    name: "vaultguard_list",
    description:
      "List vault files visible to this lease, with their effective permission. Filters out hidden, excluded, and out-of-scope paths.",
    input_schema: {
      type: "object",
      properties: {
        scope: {
          type: "string",
          description: "Optional vault-relative glob to narrow within the lease scope (e.g. /project-x/**).",
        },
        limit: { type: "integer", minimum: 1, description: "Maximum number of files to return." },
      },
      additionalProperties: false,
    },
  },
  {
    name: "vaultguard_search",
    description:
      "Search the visible text files for a literal substring. Returns path, line number, and a short snippet for each match.",
    input_schema: {
      type: "object",
      required: ["query"],
      properties: {
        query: { type: "string", description: "Literal substring to search for (case-insensitive)." },
        scope: { type: "string", description: "Optional vault-relative glob to narrow within the lease scope." },
        limit: { type: "integer", minimum: 1 },
      },
      additionalProperties: false,
    },
  },
  {
    name: "vaultguard_read",
    description:
      "Read a single text file from the vault as plaintext. Goes through VaultGuard's permission and at-rest decrypt path; refuses non-text files and out-of-scope paths.",
    input_schema: {
      type: "object",
      required: ["path"],
      properties: {
        path: { type: "string", description: "Vault-relative path (e.g. project-x/Plan.md)." },
        maxBytes: { type: "integer", minimum: 1, description: "Truncate the response to at most this many UTF-8 bytes." },
      },
      additionalProperties: false,
    },
  },
  {
    name: "vaultguard_apply_patch",
    description:
      "Apply a unified diff (with @@ hunks) to an existing text file. The hunks must match the current file exactly. Subject to writeMode (deny / confirm / allow) on the lease.",
    input_schema: {
      type: "object",
      required: ["path", "diff"],
      properties: {
        path: { type: "string", description: "Vault-relative path of the file to patch." },
        diff: { type: "string", description: "Unified diff with @@ hunk headers." },
      },
      additionalProperties: false,
    },
  },
  {
    name: "vaultguard_create",
    description:
      "Create a new text file with the given content. Refuses to overwrite an existing file. Subject to writeMode on the lease.",
    input_schema: {
      type: "object",
      required: ["path", "content"],
      properties: {
        path: { type: "string", description: "Vault-relative path of the new file." },
        content: { type: "string", description: "File content as a UTF-8 string." },
      },
      additionalProperties: false,
    },
  },
  {
    name: "vaultguard_graph",
    description:
      "Navigate the vault's structure without reading whole files. Cheaper than listing+reading. " +
      "Ops: 'neighbors' (links/backlinks/shared-tags of a note), 'related' (top notes connected to a " +
      "note, ranked), 'tag' (notes carrying a tag), 'orphans' (unlinked notes), 'hubs' (most-connected " +
      "notes), 'overview' (vault-wide structural summary). Results respect your permissions.",
    input_schema: {
      type: "object",
      required: ["op"],
      properties: {
        op: { type: "string", enum: ["neighbors", "related", "tag", "orphans", "hubs", "overview"] },
        path: { type: "string", description: "Target note (required for neighbors/related)." },
        tag: { type: "string", description: "Tag without '#' (required for op=tag)." },
        depth: { type: "integer", minimum: 1, maximum: 3, description: "Hops for neighbors/related (default 1)." },
        limit: { type: "integer", minimum: 1, maximum: 100 },
      },
      additionalProperties: false,
    },
  },
] as const satisfies readonly VaultToolDef[];
