// Helpers for distinguishing a USER PROMPT turn (a plain string, or an array of
// text/image blocks when the prompt carries attachments) from internal
// tool_result plumbing (also a user-role message, but all tool_result blocks).
// Used by the runtime (regenerate/edit truncation) and the view (rendering +
// turn counting) so both treat string and image-bearing prompts identically.

import type {
  AnthropicContentBlock,
  AnthropicConversationMessage,
  AnthropicImageBlock,
} from "./anthropic-client";

/** True when `m` is a user prompt the user actually typed (not tool_result). */
export function isUserPrompt(m: AnthropicConversationMessage): boolean {
  if (m.role !== "user") return false;
  if (typeof m.content === "string") return true;
  return (
    Array.isArray(m.content) &&
    m.content.some((b) => b.type === "text" || b.type === "image")
  );
}

/** The text of a user prompt (the string itself, or its first text block). */
export function userPromptText(m: AnthropicConversationMessage): string {
  if (typeof m.content === "string") return m.content;
  if (Array.isArray(m.content)) {
    for (const b of m.content as AnthropicContentBlock[]) {
      if (b.type === "text" && b.text) return b.text;
    }
  }
  return "";
}

/** The image blocks attached to a user prompt (empty for plain-text turns). */
export function userPromptImages(m: AnthropicConversationMessage): AnthropicImageBlock[] {
  if (!Array.isArray(m.content)) return [];
  return (m.content as AnthropicContentBlock[]).filter(
    (b): b is AnthropicImageBlock => b.type === "image",
  );
}

/**
 * Truncate a message list to everything BEFORE the Nth (0-based) user prompt,
 * returning the kept messages and the removed prompt's text. Counts prompts with
 * `isUserPrompt` (so image-bearing turns are indexed identically to how the view
 * renders + counts them), and never trips over tool_result plumbing turns.
 * Returns null when `n` is out of range. Pure — no mutation, no I/O. Shared by
 * the runtime (edit/delete truncation) and the view (no-runtime fallback) so the
 * two can never drift.
 */
export function sliceBeforeUserTurn(
  messages: AnthropicConversationMessage[],
  n: number,
): { kept: AnthropicConversationMessage[]; removedText: string } | null {
  const indices: number[] = [];
  messages.forEach((m, i) => {
    if (isUserPrompt(m)) indices.push(i);
  });
  if (n < 0 || n >= indices.length) return null;
  const at = indices[n];
  return { kept: messages.slice(0, at), removedText: userPromptText(messages[at]) };
}
