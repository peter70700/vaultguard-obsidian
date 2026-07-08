import type { OpenAiFunctionTool } from "./openai-client";
import { VAULT_TOOL_DEFS } from "./vault-tools";

export function toOpenAiFunctionTools(): OpenAiFunctionTool[] {
  return VAULT_TOOL_DEFS.map((tool) => ({
    type: "function",
    name: tool.name,
    description: tool.description,
    parameters: tool.input_schema,
  }));
}
