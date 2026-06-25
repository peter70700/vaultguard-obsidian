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

// A standalone CommonMark thematic break: `---`, `***`, `___` (3+), optionally
// spaced (`- - -`), with up to 3 leading spaces. Table delimiter rows carry `|`
// and 2-char runs (`--`) fall short of the `{2,}` repeat, so neither matches.
const THEMATIC_BREAK_RE = /^ {0,3}([-*_])(?:[ \t]*\1){2,}[ \t]*$/;

// A fenced-code-block delimiter line (``` or ~~~, 3+), up to 3 leading spaces.
const CODE_FENCE_RE = /^ {0,3}(?:`{3,}|~{3,})/;

/**
 * Strip standalone markdown thematic breaks from assistant chat narration and
 * normalise blank runs. Pure — no I/O.
 *
 * Claude routinely separates multi-step "working…" narration with `---`, and
 * Obsidian's MarkdownRenderer turns each `---`/`***`/`___` into a full-width
 * `<hr>`; in the chat bubble (especially low-contrast themes where the bubble
 * background matches the panel) these read as stray stacked horizontal lines.
 * In a chat transcript such dividers carry no information, so we drop them.
 *
 * Safety:
 * - Lines inside fenced code blocks are never touched (a `---` there is code).
 * - Standalone break lines are always dropped. In this chat surface they are
 *   almost always model narration separators; setext headings (`Heading` +
 *   `---`) are intentionally sacrificed to avoid rendering stray rule stacks.
 * - Table delimiter rows (`|---|`) carry pipes and never match.
 *
 * Resulting runs of 3+ blank lines collapse to one and the ends are trimmed.
 */
export function stripChatThematicBreaks(md: string): string {
  const lines = md.split("\n");
  const out: string[] = [];
  let inFence = false;
  for (const line of lines) {
    if (CODE_FENCE_RE.test(line)) {
      inFence = !inFence;
      out.push(line);
      continue;
    }
    if (!inFence && THEMATIC_BREAK_RE.test(line)) continue;
    out.push(line);
  }
  return out.join("\n").replace(/\n{3,}/g, "\n\n").replace(/^\s+|\s+$/g, "");
}
