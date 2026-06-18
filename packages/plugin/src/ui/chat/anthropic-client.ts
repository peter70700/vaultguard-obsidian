// Typed Anthropic Messages API client (Tier 1 — non-streaming) over Obsidian's
// `requestUrl` (AI-CHAT-PANEL.md §5.2). House style mirrors src/api/client.ts:
// `throw: false` + manual status handling, NodeJS networking under the hood
// (never browser fetch — Networking Rule in CLAUDE.md).
//
// This file is transport-only. It does NOT read settings or SafeStorage — the
// apiKey + model come in via config so the encryption-key handling lives in one
// place (the settings/UI layer in a later phase).

import { requestUrl } from "obsidian";

import { NetworkError, VaultGuardError } from "../../api/client";
import { mapAnthropicError } from "./anthropic-errors";
import { streamMessages, type StreamHandlers } from "./anthropic-stream";

const MESSAGES_URL = "https://api.anthropic.com/v1/messages";
const COUNT_TOKENS_URL = "https://api.anthropic.com/v1/messages/count_tokens";
const ANTHROPIC_VERSION = "2023-06-01";
const DEFAULT_MODEL = "claude-opus-4-8";
const DEFAULT_MAX_TOKENS = 8192;

// ─── Content block shapes (assistant side) ──────────────────────────────────

export interface AnthropicTextBlock {
  type: "text";
  text: string;
}

export interface AnthropicThinkingBlock {
  type: "thinking";
  thinking: string;
  signature?: string;
}

export interface AnthropicToolUseBlock {
  type: "tool_use";
  id: string;
  name: string;
  input: Record<string, unknown>;
}

// User-side image input (vision). Only ever appears in a user-turn content
// array alongside a text block — the model never emits these.
export interface AnthropicImageBlock {
  type: "image";
  source: { type: "base64"; media_type: string; data: string };
}

export type AnthropicContentBlock =
  | AnthropicTextBlock
  | AnthropicThinkingBlock
  | AnthropicToolUseBlock
  | AnthropicImageBlock;

// A tool_result block is sent back to the model inside a user turn.
export interface AnthropicToolResultBlock {
  type: "tool_result";
  tool_use_id: string;
  content: string;
  is_error?: boolean;
}

// ─── Message + usage shapes ──────────────────────────────────────────────────

export type AnthropicStopReason =
  | "end_turn"
  | "tool_use"
  | "max_tokens"
  | "stop_sequence"
  | "refusal"
  | "pause_turn";

export interface AnthropicUsage {
  input_tokens: number;
  output_tokens: number;
  cache_read_input_tokens?: number;
  cache_creation_input_tokens?: number;
}

// The assistant message returned by /v1/messages (stream:false).
export interface AnthropicMessage {
  id?: string;
  role: "assistant";
  content: AnthropicContentBlock[];
  stop_reason: AnthropicStopReason;
  usage?: AnthropicUsage;
}

// A conversation message in the request `messages` array. Content can be a
// plain string (a user prompt), assistant content blocks (the full prior
// assistant turn, incl. thinking + tool_use), or tool_result blocks.
export interface AnthropicConversationMessage {
  role: "user" | "assistant";
  content: AnthropicContentBlock[] | AnthropicToolResultBlock[] | string;
}

// ─── Client config + request ─────────────────────────────────────────────────

export type AnthropicEffort = "low" | "medium" | "high" | "xhigh" | "max";

export interface AnthropicClientConfig {
  apiKey: string;
  model: string;
  maxTokens?: number;
  effort?: AnthropicEffort;
}

export interface AnthropicMessagesRequest {
  system?: unknown;
  tools?: unknown[];
  messages: AnthropicConversationMessage[];
  max_tokens?: number;
  model?: string;
}

export interface CountTokensRequest {
  model?: string;
  system?: unknown;
  tools?: unknown[];
  messages: AnthropicConversationMessage[];
}

export class AnthropicClient {
  constructor(private readonly config: AnthropicClientConfig) {}

  private headers(): Record<string, string> {
    return {
      "x-api-key": this.config.apiKey,
      "anthropic-version": ANTHROPIC_VERSION,
    };
  }

  /**
   * Send a non-streaming Messages request. Merges the project's default
   * model / max_tokens / adaptive-thinking / effort config. Explicitly does
   * NOT set temperature/top_p/top_k (they 400 on Opus 4.7+/Fable 5).
   *
   * `signal` is honored as a pre-flight check only — requestUrl buffers the
   * full response and cannot be aborted mid-flight (true mid-stream cancel
   * lands in the Tier-2 streaming phase).
   */
  async send(req: AnthropicMessagesRequest, signal?: AbortSignal): Promise<AnthropicMessage> {
    if (signal?.aborted) {
      throw new NetworkError("Request aborted before it was sent.");
    }

    const body = {
      model: req.model ?? this.config.model ?? DEFAULT_MODEL,
      max_tokens: req.max_tokens ?? this.config.maxTokens ?? DEFAULT_MAX_TOKENS,
      thinking: { type: "adaptive", display: "summarized" },
      output_config: { effort: this.config.effort ?? "high" },
      stream: false,
      ...(req.system !== undefined ? { system: req.system } : {}),
      ...(req.tools !== undefined ? { tools: req.tools } : {}),
      messages: req.messages,
    };

    let res;
    try {
      res = await requestUrl({
        url: MESSAGES_URL,
        method: "POST",
        contentType: "application/json",
        headers: this.headers(),
        body: JSON.stringify(body),
        throw: false,
      });
    } catch (e) {
      // requestUrl threw at the transport layer (connection refused, DNS,
      // status 0 with throw on some platforms) → treat as a network error.
      throw new NetworkError(
        `Could not reach Anthropic: ${(e as Error).message ?? "connection failed"}`,
      );
    }

    if (res.status < 200 || res.status >= 300) {
      throw mapAnthropicError(res.status, res.json);
    }

    return res.json as AnthropicMessage;
  }

  /**
   * Tier-2 streaming counterpart to `send()` (AI-CHAT-PANEL.md §5.2). Builds the
   * IDENTICAL request body, then streams it over Node `https` via
   * `streamMessages`. Resolves the fully-assembled `AnthropicMessage` once the
   * stream ends, so the agentic loop is transport-agnostic. Delta handlers fire
   * live as tokens arrive; `signal` truly aborts the in-flight request.
   *
   * Desktop-only + opt-in is enforced by the caller (chat-view) — this method
   * never checks platform so it stays a pure transport.
   */
  async stream(
    req: AnthropicMessagesRequest,
    deltaHandlers: StreamHandlers,
    signal?: AbortSignal,
  ): Promise<AnthropicMessage> {
    if (signal?.aborted) {
      throw new NetworkError("Request aborted before it was sent.");
    }

    const body = {
      model: req.model ?? this.config.model ?? DEFAULT_MODEL,
      max_tokens: req.max_tokens ?? this.config.maxTokens ?? DEFAULT_MAX_TOKENS,
      thinking: { type: "adaptive", display: "summarized" },
      output_config: { effort: this.config.effort ?? "high" },
      ...(req.system !== undefined ? { system: req.system } : {}),
      ...(req.tools !== undefined ? { tools: req.tools } : {}),
      messages: req.messages,
    };

    return streamMessages(this.config.apiKey, body, deltaHandlers, signal);
  }

  /**
   * Count input tokens for a prospective request (drives the context-budget
   * meter and pre-413 warnings). Same headers; `stream` is omitted.
   */
  async countTokens(req: CountTokensRequest): Promise<{ input_tokens: number }> {
    const body = {
      model: req.model ?? this.config.model ?? DEFAULT_MODEL,
      ...(req.system !== undefined ? { system: req.system } : {}),
      ...(req.tools !== undefined ? { tools: req.tools } : {}),
      messages: req.messages,
    };

    let res;
    try {
      res = await requestUrl({
        url: COUNT_TOKENS_URL,
        method: "POST",
        contentType: "application/json",
        headers: this.headers(),
        body: JSON.stringify(body),
        throw: false,
      });
    } catch (e) {
      throw new NetworkError(
        `Could not reach Anthropic: ${(e as Error).message ?? "connection failed"}`,
      );
    }

    if (res.status < 200 || res.status >= 300) {
      throw mapAnthropicError(res.status, res.json);
    }

    return res.json as { input_tokens: number };
  }
}

// Re-export so consumers that only need the error base don't reach into client.ts.
export type { VaultGuardError };
