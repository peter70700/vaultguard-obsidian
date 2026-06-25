// Single source of truth for the AI Chat model + effort option lists
// (AI-CHAT-PANEL.md §4). Shared by the settings tab (dropdowns) and the chat
// panel's in-footer model/effort menu so the two never drift. No filesystem,
// no network — pure config data.

import type { AgentWriteMode } from "../../plugin/agent-bridge";
import type { AiChatPermissionMode, AnthropicEffort } from "../../types";

export interface ChatModelOption {
  id: string;
  label: string;
}

export interface ChatPermissionModeOption {
  id: AiChatPermissionMode;
  label: string;
  statusLabel: string;
  description: string;
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

export const AI_CHAT_PERMISSION_MODES: ReadonlyArray<ChatPermissionModeOption> = [
  {
    id: "confirm",
    label: "Confirm writes (default)",
    statusLabel: "Confirm",
    description: "Ask before each AI-created file change, showing the diff before it touches disk.",
  },
  {
    id: "skip",
    label: "Skip write confirmations",
    statusLabel: "Skip",
    description:
      "Let AI Chat write without per-action prompts. Vault scope, hidden-path blocks, and server permissions still apply.",
  },
];

/** Just the model ids, for membership checks (e.g. validating `/model <id>`). */
export const AI_CHAT_MODEL_IDS: ReadonlyArray<string> = AI_CHAT_MODELS.map((m) => m.id);

/** Human label for a model id, falling back to the raw id for unknown models. */
export function modelLabel(id: string): string {
  return AI_CHAT_MODELS.find((m) => m.id === id)?.label ?? id;
}

/** Short label for compact surfaces such as the chat status footer. */
export function compactModelLabel(id: string): string {
  return modelLabel(id).replace(/\s+\(default\)$/, "");
}

/** Human label for a thinking-effort id, falling back to the raw id. */
export function effortLabel(id: AnthropicEffort): string {
  return AI_CHAT_EFFORTS.find((e) => e.id === id)?.label.replace(/\s+\(default\)$/, "") ?? id;
}

export function normalizeChatPermissionMode(value: unknown): AiChatPermissionMode {
  return value === "skip" ? "skip" : "confirm";
}

export function permissionModeLabel(id: AiChatPermissionMode): string {
  const normalized = normalizeChatPermissionMode(id);
  return AI_CHAT_PERMISSION_MODES.find((m) => m.id === normalized)?.label.replace(/\s+\(default\)$/, "") ?? normalized;
}

export function permissionModeStatusLabel(id: AiChatPermissionMode): string {
  const normalized = normalizeChatPermissionMode(id);
  return AI_CHAT_PERMISSION_MODES.find((m) => m.id === normalized)?.statusLabel ?? normalized;
}

export function chatPermissionWriteMode(id: AiChatPermissionMode): AgentWriteMode {
  return normalizeChatPermissionMode(id) === "skip" ? "allow" : "confirm";
}
