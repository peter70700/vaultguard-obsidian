// OpenAI Responses API client for VaultGuard AI Chat. Uses Obsidian requestUrl
// only; no browser fetch and no SDK-managed tool runner.

import { requestUrl } from "obsidian";

import { NetworkError, VaultGuardError } from "../../api/client";
import type { OpenAiReasoningEffort, OpenAiVerbosity } from "../../types";
import { mapOpenAiError, redactOpenAiSecret } from "./openai-errors";

const RESPONSES_URL = "https://api.openai.com/v1/responses";
const DEFAULT_MODEL = "gpt-5.5";
const DEFAULT_MAX_OUTPUT_TOKENS = 8192;

export interface OpenAiClientConfig {
  apiKey: string;
  model: string;
  maxOutputTokens?: number;
  reasoningEffort?: OpenAiReasoningEffort;
  verbosity?: OpenAiVerbosity;
}

export interface OpenAiFunctionTool {
  type: "function";
  name: string;
  description: string;
  parameters: Record<string, unknown>;
}

export interface OpenAiMessageInputItem {
  role: "user" | "assistant";
  content: string;
}

export interface OpenAiFunctionCallOutputItem {
  type: "function_call_output";
  call_id: string;
  output: string;
}

export interface OpenAiFunctionCallItem {
  type: "function_call";
  call_id: string;
  name: string;
  arguments: string;
  id?: string;
}

export interface OpenAiMessageOutputItem {
  type: "message";
  role: "assistant";
  content?: Array<{ type?: string; text?: string; [key: string]: unknown }>;
}

export interface OpenAiReasoningOutputItem {
  type: "reasoning";
  [key: string]: unknown;
}

export type OpenAiInputItem =
  | OpenAiMessageInputItem
  | OpenAiFunctionCallItem
  | OpenAiFunctionCallOutputItem
  | OpenAiReasoningOutputItem
  | OpenAiMessageOutputItem;

export type OpenAiOutputItem =
  | OpenAiFunctionCallItem
  | OpenAiMessageOutputItem
  | OpenAiReasoningOutputItem
  | Record<string, unknown>;

export interface OpenAiResponsesRequest {
  instructions: string;
  input: OpenAiInputItem[];
  tools: OpenAiFunctionTool[];
}

export interface OpenAiUsage {
  input_tokens?: number;
  output_tokens?: number;
  total_tokens?: number;
}

export interface OpenAiResponse {
  id?: string;
  output?: OpenAiOutputItem[];
  output_text?: string;
  usage?: OpenAiUsage;
}

export class OpenAiResponsesClient {
  constructor(private readonly config: OpenAiClientConfig) {}

  async create(req: OpenAiResponsesRequest, signal?: AbortSignal): Promise<OpenAiResponse> {
    if (signal?.aborted) {
      throw new NetworkError("Request aborted before it was sent.");
    }

    const body = {
      model: this.config.model || DEFAULT_MODEL,
      instructions: req.instructions,
      input: req.input,
      tools: req.tools,
      reasoning: { effort: this.config.reasoningEffort ?? "medium" },
      text: { verbosity: this.config.verbosity ?? "medium" },
      max_output_tokens: this.config.maxOutputTokens ?? DEFAULT_MAX_OUTPUT_TOKENS,
      store: false,
    };

    let res;
    try {
      res = await requestUrl({
        url: RESPONSES_URL,
        method: "POST",
        contentType: "application/json",
        headers: {
          Authorization: `Bearer ${this.config.apiKey}`,
        },
        body: JSON.stringify(body),
        throw: false,
      });
    } catch (e) {
      throw new NetworkError(
        `Could not reach OpenAI: ${redactOpenAiSecret((e as Error).message ?? "connection failed")}`,
      );
    }

    if (res.status < 200 || res.status >= 300) {
      throw mapOpenAiError(res.status, res.json);
    }

    return res.json as OpenAiResponse;
  }
}

export type { VaultGuardError };
