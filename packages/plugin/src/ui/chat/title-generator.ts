// Conversation title generation (AI-CHAT-PANEL.md §4, §11). After the first
// successful exchange we ask a cheap Haiku model for a 4–6 word title. This is
// network — and §11 forbids any network on the no-key path — so the caller MUST
// only invoke this when an Anthropic key exists. The AnthropicClient already
// requires a key in its config, which structurally enforces that here.
//
// Robustness: on ANY error (network, refusal, empty) we fall back to the first
// ~6 words of the user message. Title generation never blocks or breaks a turn.

import type { AnthropicMessage, AnthropicMessagesRequest } from "./anthropic-client";

const TITLE_MODEL = "claude-haiku-4-5";
const TITLE_MAX_TOKENS = 32;
const MAX_TITLE_WORDS = 8;
const MAX_TITLE_CHARS = 64;

// Structural client subset so tests can inject a fake without the real
// AnthropicClient. AnthropicClient satisfies this.
export interface TitleClient {
  send(req: AnthropicMessagesRequest, signal?: AbortSignal): Promise<AnthropicMessage>;
}

const SYSTEM_PROMPT =
  "You generate a concise chat title. Reply with ONLY a 4-6 word title in Title " +
  "Case for the conversation below. No quotes, no punctuation at the end, no " +
  "preamble — just the title.";

/**
 * Generate a short title for a conversation from its first exchange. Returns a
 * sanitized title on success, or a fallback derived from the user message on
 * any failure. Never throws.
 */
export async function generateTitle(
  client: TitleClient,
  firstUserText: string,
  firstAssistantText: string,
): Promise<string> {
  const fallback = fallbackTitle(firstUserText);
  try {
    const prompt =
      `User: ${truncate(firstUserText, 500)}\n\n` +
      `Assistant: ${truncate(firstAssistantText, 500)}`;

    const res = await client.send({
      model: TITLE_MODEL,
      max_tokens: TITLE_MAX_TOKENS,
      system: SYSTEM_PROMPT,
      // No tools — this is a one-shot text completion.
      messages: [{ role: "user", content: prompt }],
    });

    const raw = extractText(res);
    const cleaned = sanitizeTitle(raw);
    return cleaned || fallback;
  } catch {
    return fallback;
  }
}

// Pull the first text block out of the assistant response.
function extractText(msg: AnthropicMessage): string {
  if (!msg || !Array.isArray(msg.content)) return "";
  for (const block of msg.content) {
    if (block.type === "text" && block.text) return block.text;
  }
  return "";
}

/**
 * Strip quotes, surrounding whitespace, trailing punctuation, and collapse to
 * a short single line. Caps at MAX_TITLE_WORDS / MAX_TITLE_CHARS.
 */
export function sanitizeTitle(raw: string): string {
  let t = (raw ?? "").trim();
  // Drop a leading "Title:" label if the model added one.
  t = t.replace(/^title:\s*/i, "");
  // Take the first line only.
  t = t.split(/\r?\n/)[0] ?? "";
  // Strip wrapping quotes.
  t = t.replace(/^["'`]+|["'`]+$/g, "").trim();
  // Strip trailing sentence punctuation.
  t = t.replace(/[.!?,;:]+$/g, "").trim();
  if (!t) return "";
  // Cap word count.
  const words = t.split(/\s+/).slice(0, MAX_TITLE_WORDS);
  t = words.join(" ");
  // Cap char count.
  if (t.length > MAX_TITLE_CHARS) t = t.slice(0, MAX_TITLE_CHARS).trim();
  return t;
}

/** Fallback title: first ~6 words of the user message. */
export function fallbackTitle(firstUserText: string): string {
  const words = (firstUserText ?? "").trim().split(/\s+/).filter(Boolean).slice(0, 6);
  return words.length > 0 ? words.join(" ") : "New chat";
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) : s;
}

export { TITLE_MODEL };
