// The manual agentic loop (AI-CHAT-PANEL.md §9). No SDK tool-runner — we need
// confirmation gates and custom rendering, so the loop is hand-rolled.
//
// Loop invariants (all load-bearing):
//  - Append the FULL assistant.content every step (thinking + tool_use), never
//    just text — dropping thinking blocks 400s on Opus 4.7+ multi-step turns.
//  - One tool_result per tool_use, matched by tool_use_id, all in a single
//    following user turn.
//  - Terminate on any non-tool_use stop_reason (end_turn / max_tokens /
//    stop_sequence) and on "refusal". A MAX_STEPS guard backstops a runaway.
//  - AbortController support: the signal is threaded into client.send and
//    checked at the top of each loop iteration; on abort the loop returns
//    cleanly without another send().

import type {
  AnthropicContentBlock,
  AnthropicConversationMessage,
  AnthropicImageBlock,
  AnthropicMessage,
  AnthropicMessagesRequest,
  AnthropicToolResultBlock,
  AnthropicToolUseBlock,
} from "./anthropic-client";
import type { StreamHandlers } from "./anthropic-stream";
import { isUserPrompt, sliceBeforeUserTurn } from "./message-utils";
import { VAULT_TOOL_DEFS } from "./vault-tools";

const MAX_STEPS = 12;
const LOG_PREFIX = "[VaultGuard Chat]";

// Minimal structural interfaces so tests can inject plain-object fakes.
// AnthropicClient and VaultToolRuntime satisfy these structurally.
export interface ChatRuntimeClient {
  send(req: AnthropicMessagesRequest, signal?: AbortSignal): Promise<AnthropicMessage>;
  /**
   * Optional Tier-2 streaming counterpart. When the runtime is configured with
   * `streaming: true` AND the client provides this method, each step streams
   * token-by-token; otherwise the loop falls back to `send`. Loop / stop_reason
   * / tool_result logic is identical for both transports.
   */
  stream?(
    req: AnthropicMessagesRequest,
    handlers: StreamHandlers,
    signal?: AbortSignal,
  ): Promise<AnthropicMessage>;
}

export interface ChatRuntimeToolRuntime {
  execute(name: string, input: Record<string, unknown>): Promise<{ content: string; isError: boolean }>;
}

export interface ChatProgress {
  onAssistant?(msg: AnthropicMessage): void;
  onToolCall?(name: string, input: unknown): void;
  onToolResult?(name: string, result: { content: string; isError: boolean }): void;
  onRefusal?(msg: AnthropicMessage): void;
  onStepLimit?(): void;
  onText?(text: string): void;
  /**
   * Live token-by-token assistant text (streaming transport only). Tier-1 turns
   * never call this — they deliver whole text blocks via `onText`. The view
   * appends these deltas to the active bubble as they arrive.
   */
  onTextDelta?(text: string): void;
  /** Live token-by-token thinking-summary text (streaming transport only). */
  onThinkingDelta?(text: string): void;
}

export interface ChatRuntimeConfig {
  system?: unknown;
  model?: string;
  maxTokens?: number;
  /**
   * Opt into Tier-2 streaming. Only takes effect when the client also exposes a
   * `stream` method (desktop-only is decided by the caller before constructing
   * the runtime). Defaults to false → byte-identical Tier-1 behavior.
   */
  streaming?: boolean;
}

export interface ChatRuntimeDeps {
  client: ChatRuntimeClient;
  toolRuntime: ChatRuntimeToolRuntime;
  config?: ChatRuntimeConfig;
  progress?: ChatProgress;
}

// Thin console logger used when no progress callback is supplied.
function defaultProgress(): ChatProgress {
  return {
    onText: (text) => console.log(`${LOG_PREFIX} ${text}`),
    onToolCall: (name, input) => console.log(`${LOG_PREFIX} tool_use ${name}`, input),
    onToolResult: (name, result) =>
      console.log(`${LOG_PREFIX} tool_result ${name} (isError=${result.isError})`, result.content),
    onRefusal: () => console.warn(`${LOG_PREFIX} model refused the request`),
    onStepLimit: () => console.warn(`${LOG_PREFIX} reached the step limit for one turn`),
  };
}

function isTextBlock(b: AnthropicContentBlock): b is { type: "text"; text: string } {
  return b.type === "text";
}

function isToolUseBlock(b: AnthropicContentBlock): b is AnthropicToolUseBlock {
  return b.type === "tool_use";
}

export class ChatRuntime {
  private readonly client: ChatRuntimeClient;
  private readonly toolRuntime: ChatRuntimeToolRuntime;
  private readonly config: ChatRuntimeConfig;
  private readonly progress: ChatProgress;
  private messages: AnthropicConversationMessage[] = [];

  constructor(deps: ChatRuntimeDeps) {
    this.client = deps.client;
    this.toolRuntime = deps.toolRuntime;
    this.config = deps.config ?? {};
    this.progress = deps.progress ?? defaultProgress();
  }

  getMessages(): AnthropicConversationMessage[] {
    return this.messages;
  }

  /**
   * Rehydrate the message history from a persisted conversation so the next
   * turn carries prior context. Replaces the in-memory array wholesale.
   */
  setMessages(messages: AnthropicConversationMessage[]): void {
    this.messages = [...messages];
  }

  reset(): void {
    this.messages = [];
  }

  async runTurn(
    userText: string,
    signal?: AbortSignal,
    images?: AnthropicImageBlock[],
  ): Promise<void> {
    // With attachments the user turn becomes a content-block array (images then
    // optional text); otherwise it stays a plain string for byte-identical
    // behavior. Do not append an empty text block for image-only prompts.
    const content =
      images && images.length > 0
        ? [
            ...images,
            ...(userText.length > 0
              ? [{ type: "text", text: userText } as AnthropicContentBlock]
              : []),
          ]
        : userText;
    this.messages.push({ role: "user", content });
    await this.runLoop(signal);
  }

  /**
   * Drop everything after the last plain-string user message (the previous
   * assistant turn + its tool_result plumbing) and re-run the loop, so the model
   * answers the same prompt again. Returns the kept message list so the view can
   * re-render the conversation up to that prompt. Resolves without running when
   * there is no regenerable turn.
   */
  async regenerateLast(signal?: AbortSignal): Promise<void> {
    const idx = this.lastUserStringIndex();
    if (idx < 0) return;
    this.messages = this.messages.slice(0, idx + 1);
    await this.runLoop(signal);
  }

  /** The kept messages after truncating to the last user prompt (for re-render). */
  truncateToLastUser(): AnthropicConversationMessage[] | null {
    const idx = this.lastUserStringIndex();
    if (idx < 0) return null;
    this.messages = this.messages.slice(0, idx + 1);
    return this.messages;
  }

  /**
   * Remove the Nth (0-based) plain-string user message and everything after it
   * (used by edit/delete). Returns the removed prompt text + the kept messages,
   * or null when `n` is out of range.
   */
  removeFromUserTurn(n: number): { kept: AnthropicConversationMessage[]; removedText: string } | null {
    const sliced = sliceBeforeUserTurn(this.messages, n);
    if (!sliced) return null;
    this.messages = sliced.kept;
    return sliced;
  }

  private lastUserStringIndex(): number {
    for (let i = this.messages.length - 1; i >= 0; i--) {
      if (isUserPrompt(this.messages[i])) return i;
    }
    return -1;
  }

  private async runLoop(signal?: AbortSignal): Promise<void> {
    let guard = 0;
    while (guard++ < MAX_STEPS) {
      if (signal?.aborted) {
        return;
      }

      const req: AnthropicMessagesRequest = {
        model: this.config.model,
        max_tokens: this.config.maxTokens,
        system: this.config.system,
        tools: VAULT_TOOL_DEFS as unknown as unknown[],
        messages: this.messages,
      };

      // Stream only when opted-in AND the client can stream; otherwise Tier-1.
      const streaming = this.config.streaming === true && typeof this.client.stream === "function";

      let assistant: AnthropicMessage;
      if (streaming) {
        assistant = await this.client.stream!(
          req,
          {
            onTextDelta: (t) => this.progress.onTextDelta?.(t),
            onThinkingDelta: (t) => this.progress.onThinkingDelta?.(t),
          },
          signal,
        );
        // Live deltas already painted text + thinking. Surface usage / tool
        // bookkeeping via onAssistant, but DO NOT re-emit text blocks through
        // onText — that would duplicate what the deltas already rendered.
        this.progress.onAssistant?.(assistant);
      } else {
        assistant = await this.client.send(req, signal);
        this.progress.onAssistant?.(assistant);
        for (const block of assistant.content) {
          if (isTextBlock(block) && block.text) {
            this.progress.onText?.(block.text);
          }
        }
      }

      // Append the FULL assistant content (thinking + tool_use preserved).
      this.messages.push({ role: "assistant", content: assistant.content });

      if (assistant.stop_reason === "refusal") {
        this.progress.onRefusal?.(assistant);
        return;
      }

      if (assistant.stop_reason !== "tool_use") {
        // end_turn / max_tokens / stop_sequence / pause_turn → done.
        return;
      }

      const toolUses = assistant.content.filter(isToolUseBlock);
      const results: AnthropicToolResultBlock[] = [];
      for (const tu of toolUses) {
        this.progress.onToolCall?.(tu.name, tu.input);
        const r = await this.toolRuntime.execute(tu.name, tu.input);
        this.progress.onToolResult?.(tu.name, r);
        results.push({
          type: "tool_result",
          tool_use_id: tu.id,
          content: r.content,
          is_error: r.isError,
        });
      }

      // One following user turn carries all tool_result blocks.
      this.messages.push({ role: "user", content: results });
    }

    // Fell out of the loop via the guard → runaway backstop.
    this.progress.onStepLimit?.();
  }
}

export { MAX_STEPS };
