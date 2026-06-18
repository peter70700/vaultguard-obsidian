// Renders assistant `thinking` blocks as a dimmed, collapsed-by-default
// collapsible (AI-CHAT-PANEL.md §9.4). Thinking is reasoning, not an answer —
// it's available for inspection but stays out of the way by default.

import type { AnthropicMessage } from "../anthropic-client";
import { createCollapsible } from "./collapsible";

const THINKING_CLS = "vaultguard-chat-thinking";
const THINKING_TEXT_CLS = "vaultguard-chat-thinking-text";

interface ThinkingBlockShape {
  type: "thinking";
  thinking: string;
}

function isThinkingBlock(b: { type: string }): b is ThinkingBlockShape {
  return b.type === "thinking" && typeof (b as ThinkingBlockShape).thinking === "string";
}

/**
 * Pull the `thinking` text out of an assistant message. Multiple thinking
 * blocks are concatenated with a blank line. Returns "" when there's none.
 */
export function extractThinking(msg: AnthropicMessage): string {
  const parts: string[] = [];
  for (const block of msg.content) {
    if (isThinkingBlock(block) && block.thinking.trim()) {
      parts.push(block.thinking.trim());
    }
  }
  return parts.join("\n\n");
}

/**
 * Render a thinking block into `parent`. No-op (returns null) when there's no
 * thinking text, so callers can render unconditionally.
 */
export function renderThinking(parent: HTMLElement, thinking: string): HTMLElement | null {
  const text = thinking.trim();
  if (!text) return null;

  const collapsible = createCollapsible(parent, { open: false, extraClass: THINKING_CLS });
  collapsible.setLabel("Thinking");
  collapsible.body.createDiv({ cls: THINKING_TEXT_CLS, text });
  return collapsible.root;
}

export { THINKING_CLS };
