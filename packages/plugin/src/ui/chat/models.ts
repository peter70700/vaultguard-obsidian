// Single source of truth for the AI Chat model + effort option lists
// (AI-CHAT-PANEL.md §4). Shared by the settings tab (dropdowns) and the chat
// panel's in-footer model/effort menu so the two never drift. No filesystem,
// no network — pure config data.

import type { AnthropicEffort } from "../../types";

export interface ChatModelOption {
  id: string;
  label: string;
}

// Labels mirror docs/AI-CHAT-PANEL.md §4 and the MODEL_PRICING table in
// status-panel.ts (keep the ids in sync with both).
export const AI_CHAT_MODELS: ReadonlyArray<ChatModelOption> = [
  { id: "claude-opus-4-8", label: "Claude Opus 4.8 (default)" },
  { id: "claude-sonnet-4-6", label: "Claude Sonnet 4.6" },
  { id: "claude-haiku-4-5", label: "Claude Haiku 4.5" },
  { id: "claude-fable-5", label: "Claude Fable 5" },
];

export const AI_CHAT_EFFORTS: ReadonlyArray<{ id: AnthropicEffort; label: string }> = [
  { id: "low", label: "Low" },
  { id: "medium", label: "Medium" },
  { id: "high", label: "High (default)" },
  { id: "xhigh", label: "Extra high" },
  { id: "max", label: "Max" },
];

/** Just the model ids, for membership checks (e.g. validating `/model <id>`). */
export const AI_CHAT_MODEL_IDS: ReadonlyArray<string> = AI_CHAT_MODELS.map((m) => m.id);

/** Human label for a model id, falling back to the raw id for unknown models. */
export function modelLabel(id: string): string {
  return AI_CHAT_MODELS.find((m) => m.id === id)?.label ?? id;
}
