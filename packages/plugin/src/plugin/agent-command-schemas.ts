/**
 * Shared, closed JSON Schemas for Spec 019 Agent Command Expansion tools.
 *
 * Both the loopback MCP surface and in-app provider definitions consume these
 * objects so a transport cannot silently gain fields or operations that the
 * other transport rejects. Runtime code still performs every bound and
 * cross-field check because clients may ignore JSON Schema constraints.
 */

export interface AgentCommandSchemaDefinition {
  description: string;
  inputSchema: Record<string, unknown>;
}

interface AgentCommandSchemaNode {
  type?: "object" | "array" | "string" | "number" | "integer" | "boolean" | "null";
  const?: unknown;
  enum?: readonly unknown[];
  required?: readonly string[];
  properties?: Readonly<Record<string, AgentCommandSchemaNode>>;
  additionalProperties?: false | AgentCommandSchemaNode;
  items?: AgentCommandSchemaNode;
  anyOf?: readonly AgentCommandSchemaNode[];
  oneOf?: readonly AgentCommandSchemaNode[];
  allOf?: readonly AgentCommandSchemaNode[];
  if?: AgentCommandSchemaNode;
  then?: AgentCommandSchemaNode;
  minLength?: number;
  maxLength?: number;
  pattern?: string;
  minimum?: number;
  maximum?: number;
  maxItems?: number;
  maxProperties?: number;
}

const HASH = {
  type: "string",
  pattern: "^[a-fA-F0-9]{64}$",
  description: "SHA-256 of the complete plaintext note observed before mutation.",
} as const;

const IDEMPOTENCY_KEY = {
  type: "string",
  minLength: 1,
  maxLength: 128,
  description: "Process-scoped retry key. Reusing it with different arguments is refused.",
} as const;

const PATH = {
  type: "string",
  minLength: 1,
  maxLength: 1024,
  description: "Vault-relative path. Absolute, hidden, excluded, traversal, and out-of-scope paths are refused.",
} as const;

const LIMIT = { type: "integer", minimum: 1, maximum: 200 } as const;

const PRIMITIVE_VALUE = {
  anyOf: [
    { type: "string", maxLength: 10_000 },
    { type: "number" },
    { type: "boolean" },
    { type: "null" },
  ],
} as const;

const NOTE_TARGET = {
  oneOf: [
    { required: ["path"] },
    {
      required: ["daily"],
      properties: { daily: { const: true } },
    },
  ],
} as const;

function whenOperation(
  operation: string,
  then: Readonly<Record<string, unknown>>,
): Readonly<Record<string, unknown>> {
  return {
    if: {
      required: ["op"],
      properties: { op: { const: operation } },
    },
    then,
  };
}

export const AGENT_COMMAND_SCHEMAS = {
  vaultguard_note: {
    description:
      "Inspect a note's hash or atomically append/prepend bounded text, optionally under an exact heading. Use daily=true only for the configured Daily Note. Mutations are stale-aware, permission-checked, confirmed according to the lease, and return a verified receipt.",
    inputSchema: {
      type: "object",
      required: ["op"],
      properties: {
        op: { type: "string", enum: ["state", "append", "prepend"] },
        path: PATH,
        daily: { type: "boolean" },
        content: { type: "string", maxLength: 262_144 },
        section: { type: "string", minLength: 1, maxLength: 300 },
        expectedContentHash: HASH,
        idempotencyKey: IDEMPOTENCY_KEY,
      },
      allOf: [
        whenOperation("state", NOTE_TARGET),
        whenOperation("append", {
          required: ["content", "expectedContentHash"],
          ...NOTE_TARGET,
        }),
        whenOperation("prepend", {
          required: ["content", "expectedContentHash"],
          ...NOTE_TARGET,
        }),
      ],
      additionalProperties: false,
    },
  },
  vaultguard_property: {
    description:
      "Read, set, or remove one typed Markdown frontmatter property while preserving unrelated note content. Mutations require the current content hash and return a verified, content-redacted receipt.",
    inputSchema: {
      type: "object",
      required: ["op", "path", "key"],
      properties: {
        op: { type: "string", enum: ["get", "set", "remove"] },
        path: PATH,
        key: { type: "string", minLength: 1, maxLength: 120 },
        value: {
          anyOf: [
            PRIMITIVE_VALUE,
            { type: "array", maxItems: 100, items: PRIMITIVE_VALUE },
          ],
        },
        valueType: { type: "string", enum: ["string", "number", "boolean", "date", "list", "null"] },
        expectedContentHash: HASH,
        idempotencyKey: IDEMPOTENCY_KEY,
      },
      allOf: [
        whenOperation("set", { required: ["value", "expectedContentHash"] }),
        whenOperation("remove", { required: ["expectedContentHash"] }),
      ],
      additionalProperties: false,
    },
  },
  vaultguard_task: {
    description:
      "List or exactly mutate Markdown checkbox tasks. Targeted changes require path, one-based line, original line hash, and current note hash; stale or ambiguous references are refused. Recurrence syntax is preserved but not interpreted.",
    inputSchema: {
      type: "object",
      required: ["op"],
      properties: {
        op: { type: "string", enum: ["list", "create", "update", "toggle", "set_status"] },
        path: PATH,
        scope: { type: "string", maxLength: 1024 },
        line: { type: "integer", minimum: 1 },
        originalTextHash: HASH,
        expectedContentHash: HASH,
        text: { type: "string", maxLength: 10_000 },
        status: { type: "string", minLength: 1, maxLength: 1 },
        section: { type: "string", minLength: 1, maxLength: 300 },
        limit: LIMIT,
        idempotencyKey: IDEMPOTENCY_KEY,
      },
      allOf: [
        whenOperation("create", {
          required: ["path", "text", "expectedContentHash"],
        }),
        whenOperation("update", {
          required: ["path", "line", "originalTextHash", "expectedContentHash", "text"],
        }),
        whenOperation("toggle", {
          required: ["path", "line", "originalTextHash", "expectedContentHash"],
        }),
        whenOperation("set_status", {
          required: ["path", "line", "originalTextHash", "expectedContentHash", "status"],
        }),
      ],
      additionalProperties: false,
    },
  },
  vaultguard_inspect: {
    description:
      "Return bounded permission-filtered file information, outline, tags, unresolved links, visible-subgraph dead ends, recent notes, word counts, or a finite typed frontmatter collection query. Never returns raw metadata-cache objects.",
    inputSchema: {
      type: "object",
      required: ["op"],
      properties: {
        op: {
          type: "string",
          enum: ["file_info", "outline", "tags", "unresolved_links", "dead_ends", "recent", "word_count", "collection"],
        },
        path: PATH,
        scope: { type: "string", maxLength: 1024 },
        limit: LIMIT,
        fields: {
          type: "array",
          maxItems: 32,
          items: { type: "string", minLength: 1, maxLength: 120 },
        },
        filters: {
          type: "array",
          maxItems: 16,
          items: {
            type: "object",
            required: ["field", "op"],
            properties: {
              field: { type: "string", minLength: 1, maxLength: 120 },
              op: { type: "string", enum: ["eq", "ne", "contains", "starts_with", "gt", "gte", "lt", "lte", "exists"] },
              value: PRIMITIVE_VALUE,
            },
            additionalProperties: false,
          },
        },
        sort: {
          type: "object",
          required: ["field"],
          properties: {
            field: { type: "string", minLength: 1, maxLength: 120 },
            direction: { type: "string", enum: ["asc", "desc"] },
          },
          additionalProperties: false,
        },
      },
      allOf: [
        whenOperation("file_info", { required: ["path"] }),
        whenOperation("outline", { required: ["path"] }),
        whenOperation("word_count", { required: ["path"] }),
      ],
      additionalProperties: false,
    },
  },
  vaultguard_template: {
    description:
      "List/read/preview trusted core templates or create/insert notes from them with deterministic placeholders only. Template paths remain inside the configured trusted boundary; scripts and overwrite are refused.",
    inputSchema: {
      type: "object",
      required: ["op"],
      properties: {
        op: { type: "string", enum: ["list", "read", "preview", "insert", "create"] },
        templatePath: PATH,
        path: PATH,
        uniqueName: { type: "string", minLength: 1, maxLength: 200 },
        position: { type: "string", enum: ["append", "prepend"] },
        section: { type: "string", minLength: 1, maxLength: 300 },
        variables: {
          type: "object",
          maxProperties: 16,
          additionalProperties: { type: "string", maxLength: 1000 },
        },
        maxBytes: { type: "integer", minimum: 1, maximum: 262_144 },
        limit: LIMIT,
        expectedContentHash: HASH,
        idempotencyKey: IDEMPOTENCY_KEY,
      },
      allOf: [
        whenOperation("read", { required: ["templatePath"] }),
        whenOperation("preview", { required: ["templatePath"] }),
        whenOperation("insert", {
          required: ["path", "templatePath", "expectedContentHash"],
        }),
        whenOperation("create", {
          required: ["templatePath"],
          oneOf: [{ required: ["path"] }, { required: ["uniqueName"] }],
        }),
      ],
      additionalProperties: false,
    },
  },
  vaultguard_sync_status: {
    description:
      "Report a bounded local observation of VaultGuard sync state for the current vault. This never starts synchronization and never claims remote verification.",
    inputSchema: {
      type: "object",
      properties: {},
      additionalProperties: false,
    },
  },
  vaultguard_automation: {
    description:
      "List or run only human-approved governed automation aliases. Agents never receive raw Obsidian command IDs. Side effects are always confirmed and success requires the declared postcondition.",
    inputSchema: {
      type: "object",
      required: ["op"],
      properties: {
        op: { type: "string", enum: ["list", "run"] },
        alias: { type: "string", pattern: "^[a-z][a-z0-9-]{0,63}$" },
        revision: { type: "string", minLength: 1, maxLength: 128 },
        path: PATH,
        arguments: {
          type: "array",
          maxItems: 16,
          items: {
            type: "object",
            required: ["name", "value"],
            properties: {
              name: { type: "string", minLength: 1, maxLength: 64 },
              value: PRIMITIVE_VALUE,
            },
            additionalProperties: false,
          },
        },
        idempotencyKey: IDEMPOTENCY_KEY,
        limit: LIMIT,
      },
      allOf: [
        // The agent-visible list intentionally withholds the private policy
        // revision. A caller may supply a previously observed revision as an
        // extra stale-state guard, but alias alone is sufficient: planRun()
        // snapshots the current revision and revalidates it after confirmation
        // and immediately before invocation.
        whenOperation("run", { required: ["alias"] }),
      ],
      additionalProperties: false,
    },
  },
} as const satisfies Record<string, AgentCommandSchemaDefinition>;

export type AgentCommandToolName = keyof typeof AGENT_COMMAND_SCHEMAS;

const hasOwn = (value: object, key: string): boolean =>
  Object.prototype.hasOwnProperty.call(value, key);

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function schemaError(
  value: unknown,
  schema: AgentCommandSchemaNode,
  path: string,
  depth = 0,
): string | null {
  if (depth > 64) return `${path} exceeds the validation depth limit`;

  if (schema.type !== undefined) {
    const typeMatches = (() => {
      switch (schema.type) {
        case "object":
          return isPlainRecord(value);
        case "array":
          return Array.isArray(value);
        case "string":
          return typeof value === "string";
        case "number":
          return typeof value === "number" && Number.isFinite(value);
        case "integer":
          return typeof value === "number" && Number.isSafeInteger(value);
        case "boolean":
          return typeof value === "boolean";
        case "null":
          return value === null;
      }
    })();
    if (!typeMatches) return `${path} must be ${schema.type}`;
  }

  if (schema.const !== undefined && !Object.is(value, schema.const)) {
    return `${path} does not match the required operation`;
  }
  if (schema.enum !== undefined && !schema.enum.some((entry) => Object.is(entry, value))) {
    return `${path} must use an allowed value`;
  }

  if (typeof value === "string") {
    const length = Array.from(value).length;
    if (schema.minLength !== undefined && length < schema.minLength) {
      return `${path} is shorter than the allowed minimum`;
    }
    if (schema.maxLength !== undefined && length > schema.maxLength) {
      return `${path} exceeds the allowed length`;
    }
    if (schema.pattern !== undefined && !new RegExp(schema.pattern, "u").test(value)) {
      return `${path} does not match the required format`;
    }
  }

  if (typeof value === "number" && Number.isFinite(value)) {
    if (schema.minimum !== undefined && value < schema.minimum) {
      return `${path} is below the allowed minimum`;
    }
    if (schema.maximum !== undefined && value > schema.maximum) {
      return `${path} exceeds the allowed maximum`;
    }
  }

  if (Array.isArray(value)) {
    if (schema.maxItems !== undefined && value.length > schema.maxItems) {
      return `${path} contains too many items`;
    }
    if (schema.items !== undefined) {
      for (let index = 0; index < value.length; index += 1) {
        const error = schemaError(value[index], schema.items, `${path}[${index}]`, depth + 1);
        if (error) return error;
      }
    }
  }

  if (isPlainRecord(value)) {
    if (Object.getOwnPropertySymbols(value).length > 0) {
      return `${path} contains an unsupported field`;
    }
    const keys = Object.keys(value);
    if (schema.maxProperties !== undefined && keys.length > schema.maxProperties) {
      return `${path} contains too many fields`;
    }
    for (const required of schema.required ?? []) {
      if (!hasOwn(value, required)) return `${path}.${required} is required`;
    }
    for (const key of keys) {
      const propertySchema = schema.properties?.[key];
      if (propertySchema !== undefined) {
        const error = schemaError(value[key], propertySchema, `${path}.${key}`, depth + 1);
        if (error) return error;
        continue;
      }
      if (schema.additionalProperties === false) {
        return `${path} contains an unsupported field`;
      }
      if (schema.additionalProperties !== undefined) {
        const error = schemaError(value[key], schema.additionalProperties, `${path}.*`, depth + 1);
        if (error) return error;
      }
    }
  }

  if (schema.anyOf !== undefined) {
    const matches = schema.anyOf.some(
      (candidate) => schemaError(value, candidate, path, depth + 1) === null,
    );
    if (!matches) return `${path} does not match any allowed shape`;
  }
  if (schema.oneOf !== undefined) {
    const matches = schema.oneOf.filter(
      (candidate) => schemaError(value, candidate, path, depth + 1) === null,
    ).length;
    if (matches !== 1) return `${path} must match exactly one allowed shape`;
  }
  for (const candidate of schema.allOf ?? []) {
    const error = schemaError(value, candidate, path, depth + 1);
    if (error) return error;
  }
  if (
    schema.if !== undefined &&
    schema.then !== undefined &&
    schemaError(value, schema.if, path, depth + 1) === null
  ) {
    return schemaError(value, schema.then, path, depth + 1);
  }
  return null;
}

export function isAgentCommandToolName(value: string): value is AgentCommandToolName {
  return hasOwn(AGENT_COMMAND_SCHEMAS, value);
}

/**
 * Validate model-controlled arguments against the same closed schema advertised
 * to MCP and in-app providers. Errors describe structure only and never echo
 * caller-provided values.
 */
export function validateAgentCommandInput(
  tool: AgentCommandToolName,
  input: unknown,
): asserts input is Record<string, unknown> {
  const schema = AGENT_COMMAND_SCHEMAS[tool].inputSchema as AgentCommandSchemaNode;
  const error = schemaError(input, schema, "input");
  if (error) throw new Error(`${tool} input is invalid: ${error}.`);
}

export function toClaudeAgentCommandToolDefinitions(): ReadonlyArray<{
  name: AgentCommandToolName;
  description: string;
  input_schema: Record<string, unknown>;
}> {
  return Object.entries(AGENT_COMMAND_SCHEMAS).map(([name, definition]) => ({
    name: name as AgentCommandToolName,
    description: definition.description,
    input_schema: definition.inputSchema,
  }));
}
