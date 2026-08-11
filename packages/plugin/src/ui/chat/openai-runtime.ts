// Manual OpenAI Responses API tool loop for VaultGuard AI Chat.
// Vault operations still execute in-process through VaultToolRuntime/AgentBridge.

import type {
  AnthropicContentBlock,
  AnthropicConversationMessage,
  AnthropicImageBlock,
  AnthropicMessage,
  AnthropicToolResultBlock,
  AnthropicToolUseBlock,
  AnthropicUsage,
} from "./anthropic-client";
import {
  MAX_STEPS,
  buildAnthropicTurnContent,
  type ChatProgress,
  type ChatRuntimeToolRuntime,
} from "./chat-runtime";
import {
  type OpenAiFunctionCallItem,
  type OpenAiInputItem,
  type OpenAiMessageInputContent,
  type OpenAiOutputItem,
  type OpenAiResponse,
  type OpenAiResponsesRequest,
} from "./openai-client";
import { toOpenAiFunctionTools } from "./openai-tools";
import type { PreparedDocument } from "./attachment-model";
import { isUserPrompt, sliceBeforeUserTurn } from "./message-utils";

export const OPENAI_TOOL_OUTPUT_MAX_CHARS = 120_000;

export interface OpenAiChatRuntimeConfig {
  instructions: string;
}

export interface OpenAiRuntimeClient {
  create(req: OpenAiResponsesRequest, signal?: AbortSignal): Promise<OpenAiResponse>;
}

export interface OpenAiChatRuntimeDeps {
  client: OpenAiRuntimeClient;
  toolRuntime: ChatRuntimeToolRuntime;
  config: OpenAiChatRuntimeConfig;
  progress?: ChatProgress;
}

interface TransientOpenAiUserTurn {
  index: number;
  content: AnthropicContentBlock[];
}

export class OpenAiChatRuntime {
  private readonly client: OpenAiRuntimeClient;
  private readonly toolRuntime: ChatRuntimeToolRuntime;
  private readonly config: OpenAiChatRuntimeConfig;
  private readonly progress: ChatProgress;
  private messages: AnthropicConversationMessage[] = [];

  constructor(deps: OpenAiChatRuntimeDeps) {
    this.client = deps.client;
    this.toolRuntime = deps.toolRuntime;
    this.config = deps.config;
    this.progress = deps.progress ?? {};
  }

  getMessages(): AnthropicConversationMessage[] {
    return this.messages;
  }

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
    documents?: PreparedDocument[],
  ): Promise<void> {
    const persistedContent =
      images && images.length > 0
        ? [
            ...images,
            ...(userText.length > 0
              ? [{ type: "text", text: userText } as AnthropicContentBlock]
              : []),
          ]
        : userText;
    const promptIndex = this.messages.length;
    this.messages.push({ role: "user", content: persistedContent });
    const transient =
      documents && documents.length > 0
        ? {
            index: promptIndex,
            content: buildAnthropicTurnContent(userText, images ?? [], documents),
          }
        : undefined;
    await this.runLoop(signal, transient);
  }

  async regenerateLast(signal?: AbortSignal): Promise<void> {
    const idx = this.lastUserStringIndex();
    if (idx < 0) return;
    this.messages = this.messages.slice(0, idx + 1);
    await this.runLoop(signal);
  }

  truncateToLastUser(): AnthropicConversationMessage[] | null {
    const idx = this.lastUserStringIndex();
    if (idx < 0) return null;
    this.messages = this.messages.slice(0, idx + 1);
    return this.messages;
  }

  removeFromUserTurn(n: number): {
    kept: AnthropicConversationMessage[];
    removedText: string;
    removedImages?: AnthropicImageBlock[];
  } | null {
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

  private async runLoop(
    signal?: AbortSignal,
    transient?: TransientOpenAiUserTurn,
  ): Promise<void> {
    let guard = 0;
    let input = displayMessagesToOpenAiInput(this.messages, transient);

    while (guard++ < MAX_STEPS) {
      if (signal?.aborted) return;

      const req: OpenAiResponsesRequest = {
        instructions: this.config.instructions,
        input,
        tools: toOpenAiFunctionTools(),
      };
      const response = await this.client.create(req, signal);
      this.progress.onAssistant?.(toSyntheticAssistant(response));

      const text = extractResponseText(response);
      const calls = extractFunctionCalls(response.output ?? []);
      const assistantBlocks: AnthropicContentBlock[] = [];

      if (text) {
        this.progress.onText?.(text);
        assistantBlocks.push({ type: "text", text });
      }

      for (const call of calls) {
        const parsed = parseFunctionArguments(call.arguments);
        const toolInput = parsed.ok ? parsed.value : {};
        assistantBlocks.push({
          type: "tool_use",
          id: call.call_id,
          name: call.name,
          input: toolInput,
        } as AnthropicToolUseBlock);
      }

      if (assistantBlocks.length) {
        this.messages.push({ role: "assistant", content: assistantBlocks });
      }

      input = [
        ...input,
        ...((response.output ?? []) as OpenAiInputItem[]),
      ];

      if (calls.length === 0) return;

      const toolResults: AnthropicToolResultBlock[] = [];
      const callOutputs: OpenAiInputItem[] = [];

      for (const call of calls) {
        const parsed = parseFunctionArguments(call.arguments);
        const toolInput = parsed.ok ? parsed.value : {};
        this.progress.onToolCall?.(call.name, toolInput);

        const result = parsed.ok
          ? await this.toolRuntime.execute(call.name, toolInput)
          : { content: parsed.error, isError: true };
        const bounded = boundToolResult(result.content);
        const modelContent = bounded.truncated
          ? JSON.stringify({
              isError: result.isError,
              truncated: true,
              content: bounded.content,
            })
          : result.content;
        const renderedResult = { content: modelContent, isError: result.isError };

        this.progress.onToolResult?.(call.name, renderedResult);
        toolResults.push({
          type: "tool_result",
          tool_use_id: call.call_id,
          content: modelContent,
          is_error: result.isError,
        });
        callOutputs.push({
          type: "function_call_output",
          call_id: call.call_id,
          output: modelContent,
        });
      }

      this.messages.push({ role: "user", content: toolResults });
      input = [...input, ...callOutputs];
    }

    this.progress.onStepLimit?.();
  }
}

export function displayMessagesToOpenAiInput(
  messages: AnthropicConversationMessage[],
  transient?: TransientOpenAiUserTurn,
): OpenAiInputItem[] {
  const input: OpenAiInputItem[] = [];
  const effectiveMessages = transient
    ? messages.map((message, index) =>
        index === transient.index ? { role: "user" as const, content: transient.content } : message,
      )
    : messages;
  for (const message of effectiveMessages) {
    if (message.role === "user") {
      if (typeof message.content === "string") {
        input.push({ role: "user", content: message.content });
        continue;
      }
      if (Array.isArray(message.content)) {
        if (isUserPrompt(message)) {
          const content: OpenAiMessageInputContent[] = [];
          const blocks = message.content as AnthropicContentBlock[];
          const textBlocks = blocks.filter(
            (block): block is { type: "text"; text: string } =>
              block.type === "text" && Boolean(block.text),
          );
          const userText = textBlocks.at(-1);
          if (userText) content.push({ type: "input_text", text: userText.text });
          for (const block of textBlocks.slice(0, -1)) {
            content.push({ type: "input_text", text: block.text });
          }
          for (const block of blocks) {
            if (block.type === "image") {
              content.push({
                type: "input_image",
                image_url: `data:${block.source.media_type};base64,${block.source.data}`,
                detail: "auto",
              });
            } else if (block.type === "document") {
              content.push({
                type: "input_file",
                filename: block.title || "document.pdf",
                file_data: `data:application/pdf;base64,${block.source.data}`,
              });
            }
          }
          if (content.length > 0) input.push({ role: "user", content });
        } else {
          const toolText = summarizeToolResults(message.content as AnthropicToolResultBlock[]);
          if (toolText) input.push({ role: "user", content: toolText });
        }
      }
      continue;
    }

    if (Array.isArray(message.content)) {
      const text = (message.content as AnthropicContentBlock[])
        .filter((block): block is { type: "text"; text: string } => block.type === "text")
        .map((block) => block.text)
        .join("\n\n")
        .trim();
      if (text) input.push({ role: "assistant", content: text });
    }
  }
  return input;
}

function summarizeToolResults(blocks: AnthropicToolResultBlock[]): string {
  const lines = blocks
    .filter((block) => block.type === "tool_result")
    .map((block) => {
      const content = boundToolResult(block.content).content;
      return `Tool result ${block.tool_use_id}${block.is_error ? " (error)" : ""}: ${content}`;
    });
  return lines.join("\n\n");
}

function extractFunctionCalls(output: OpenAiOutputItem[]): OpenAiFunctionCallItem[] {
  return output.filter((item): item is OpenAiFunctionCallItem => {
    if (!item || typeof item !== "object") return false;
    return (
      (item as { type?: unknown }).type === "function_call" &&
      typeof (item as { call_id?: unknown }).call_id === "string" &&
      typeof (item as { name?: unknown }).name === "string" &&
      typeof (item as { arguments?: unknown }).arguments === "string"
    );
  });
}

function extractResponseText(response: OpenAiResponse): string {
  if (typeof response.output_text === "string" && response.output_text.trim()) {
    return response.output_text;
  }
  const parts: string[] = [];
  for (const item of response.output ?? []) {
    if (!item || typeof item !== "object") continue;
    if ((item as { type?: unknown }).type !== "message") continue;
    const content = (item as { content?: unknown }).content;
    if (!Array.isArray(content)) continue;
    for (const block of content) {
      if (!block || typeof block !== "object") continue;
      const type = (block as { type?: unknown }).type;
      const text = (block as { text?: unknown }).text;
      if ((type === "output_text" || type === "text") && typeof text === "string") {
        parts.push(text);
      }
    }
  }
  return parts.join("\n\n").trim();
}

function parseFunctionArguments(raw: string): { ok: true; value: Record<string, unknown> } | { ok: false; error: string } {
  try {
    const parsed = raw.trim() ? JSON.parse(raw) : {};
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { ok: false, error: "OpenAI tool-call arguments must be a JSON object." };
    }
    return { ok: true, value: parsed as Record<string, unknown> };
  } catch (e) {
    return {
      ok: false,
      error: `OpenAI tool-call arguments were not valid JSON: ${(e as Error).message}`,
    };
  }
}

function boundToolResult(content: string): { content: string; truncated: boolean } {
  if (content.length <= OPENAI_TOOL_OUTPUT_MAX_CHARS) {
    return { content, truncated: false };
  }
  const marker = "\n\n[VaultGuard truncated this tool result before sending it back to OpenAI.]";
  const keep = Math.max(0, OPENAI_TOOL_OUTPUT_MAX_CHARS - marker.length);
  return {
    content: content.slice(0, keep) + marker,
    truncated: true,
  };
}

function toSyntheticAssistant(response: OpenAiResponse): AnthropicMessage {
  return {
    role: "assistant",
    stop_reason: extractFunctionCalls(response.output ?? []).length ? "tool_use" : "end_turn",
    content: [],
    usage: toAnthropicUsage(response.usage),
  };
}

function toAnthropicUsage(usage: OpenAiResponse["usage"]): AnthropicUsage | undefined {
  if (!usage) return undefined;
  return {
    input_tokens: usage.input_tokens ?? 0,
    output_tokens: usage.output_tokens ?? 0,
  };
}
