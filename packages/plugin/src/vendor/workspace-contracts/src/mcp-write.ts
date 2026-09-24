import mcpWriteToolsSchema from "../schemas/mcp-write-tools.schema.json";

/**
 * The closed §8.5–§8.7 MCP write-tool vocabulary and its normative input
 * schemas.
 *
 * Every unserved write tool in the tool contract appears here exactly once. The
 * schema document is the single reconciliation point between the contract's
 * prose rows and the implemented closed contracts (`CreateProposalInput`,
 * `ApplyProposalInput`, `ResolveConflictInput`, the `restore` proposal
 * operation, `AccessCommand` and `ContextDefinition`); §8.9 of
 * `contracts/mcp-tools.md` records every rename.
 *
 * The three §8.8 transfer tools are deliberately absent: they are already
 * implemented with closed input schemas in `infrastructure/lambda/mcp/file-tools.ts`
 * and need admission and host composition, not a new contract.
 */
export const MCP_WRITE_TOOL_NAMES = [
  "propose_change_set",
  "get_change_set",
  "list_change_sets",
  "apply_change_set",
  "cancel_change_set",
  "comment_on_change_set",
  "list_conflicts",
  "get_conflict",
  "propose_conflict_resolution",
  "restore_file_version",
  "restore_deleted_file",
  "propose_access_change",
  "apply_access_change",
  "propose_share_change",
  "apply_share_change",
  "propose_context_change",
  "list_work_items",
  "get_work_item",
  "claim_work_item",
  "release_work_item",
  "declare_path_intent",
  "release_path_intent",
] as const;

export type McpWriteToolName = (typeof MCP_WRITE_TOOL_NAMES)[number];

export interface McpWriteToolShape {
  /** Every property the closed schema declares, sorted. */
  readonly properties: readonly string[];
  /** Every property the closed schema requires, sorted. */
  readonly required: readonly string[];
}

type JsonRecord = Readonly<Record<string, unknown>>;

const definitions = (mcpWriteToolsSchema as { $defs: Record<string, JsonRecord> }).$defs;

function toolSchema(name: McpWriteToolName): JsonRecord {
  const schema = definitions[name];
  // A missing entry is a build-time contract error, not a runtime condition:
  // the name list and the schema document are published together.
  if (!schema || typeof schema !== "object") {
    throw new Error(`Missing MCP write-tool input schema: ${name}`);
  }
  return schema;
}

export const MCP_WRITE_TOOL_INPUT_SCHEMAS: Readonly<Record<McpWriteToolName, JsonRecord>> =
  Object.freeze(
    Object.fromEntries(MCP_WRITE_TOOL_NAMES.map((name) => [name, toolSchema(name)])) as Record<
      McpWriteToolName,
      JsonRecord
    >,
  );

export function isMcpWriteToolName(value: unknown): value is McpWriteToolName {
  return typeof value === "string" && (MCP_WRITE_TOOL_NAMES as readonly string[]).includes(value);
}

/**
 * The property and required-field shape a served descriptor must agree with.
 * The MCP write registry refuses a descriptor that declares another property or
 * another required field, so no adapter can invent its own mapping.
 */
export function mcpWriteToolShape(name: McpWriteToolName): McpWriteToolShape {
  const schema = MCP_WRITE_TOOL_INPUT_SCHEMAS[name] as {
    properties?: Record<string, unknown>;
    required?: readonly string[];
  };
  return Object.freeze({
    properties: Object.freeze([...Object.keys(schema.properties ?? {})].sort()),
    required: Object.freeze([...(schema.required ?? [])].sort()),
  });
}
