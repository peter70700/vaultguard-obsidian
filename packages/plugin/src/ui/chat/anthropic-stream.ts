// Tier-2 streaming transport for the AI chat (AI-CHAT-PANEL.md §5.2, §9.2/§9.4).
//
// `requestUrl` buffers and cannot stream Server-Sent Events, so this is the ONE
// sanctioned non-`requestUrl` HTTP path in the plugin: it uses Node's built-in
// `https.request` — the SAME Node.js networking layer `requestUrl` wraps
// internally, NOT browser `fetch`/`EventSource`. See the "Streaming exception"
// subsection under the Networking Rule in CLAUDE.md. tests/telemetry-policy.test.ts
// registers this egress (api.anthropic.com only) so it can never be a silent
// channel.
//
// ENCRYPTION BOUNDARY: this module is transport-only. It touches NO filesystem
// and NO vault content — vault access stays solely via the lease + tool surface.
// It never reads settings or SafeStorage; the apiKey arrives via the caller.

import { NetworkError } from "../../api/client";
import type { VaultGuardError } from "../../api/client";
import type {
  AnthropicContentBlock,
  AnthropicMessage,
  AnthropicStopReason,
  AnthropicToolUseBlock,
  AnthropicUsage,
} from "./anthropic-client";
import { mapAnthropicError } from "./anthropic-errors";

const ANTHROPIC_HOSTNAME = "api.anthropic.com";
const ANTHROPIC_PATH = "/v1/messages";
const ANTHROPIC_VERSION = "2023-06-01";

// ─── SSE event shapes (the subset we act on) ─────────────────────────────────

interface SseContentBlockStart {
  type: "content_block_start";
  index: number;
  content_block:
    | { type: "text"; text?: string }
    | { type: "thinking"; thinking?: string }
    | { type: "tool_use"; id: string; name: string; input?: Record<string, unknown> };
}

interface SseContentBlockDelta {
  type: "content_block_delta";
  index: number;
  delta:
    | { type: "text_delta"; text: string }
    | { type: "thinking_delta"; thinking: string }
    | { type: "signature_delta"; signature: string }
    | { type: "input_json_delta"; partial_json: string };
}

interface SseContentBlockStop {
  type: "content_block_stop";
  index: number;
}

interface SseMessageDelta {
  type: "message_delta";
  delta: { stop_reason?: AnthropicStopReason | null; stop_sequence?: string | null };
  usage?: Partial<AnthropicUsage>;
}

interface SseMessageStart {
  type: "message_start";
  message: { id?: string; usage?: Partial<AnthropicUsage> };
}

interface SseGeneric {
  type:
    | "message_stop"
    | "ping"
    | "error"
    | string;
  [key: string]: unknown;
}

export type SseEvent =
  | SseContentBlockStart
  | SseContentBlockDelta
  | SseContentBlockStop
  | SseMessageDelta
  | SseMessageStart
  | SseGeneric;

// ─── Delta handlers the runtime forwards into the live UI ─────────────────────

export interface StreamHandlers {
  /** Incremental assistant visible text. */
  onTextDelta(text: string): void;
  /** Incremental thinking-summary text. */
  onThinkingDelta(text: string): void;
  /** A content block opened (used to surface tool_use cards as they begin). */
  onContentBlockStart?(block: AnthropicContentBlock): void;
  /** stop_reason + usage as the message finishes. */
  onMessageDelta?(delta: { stop_reason?: AnthropicStopReason; usage?: AnthropicUsage }): void;
}

// ─── Pure SSE framing parser (unit-tested in isolation) ───────────────────────

/**
 * Parse one raw SSE frame (the text between two "\n\n" separators) into its
 * JSON `data:` payload. Returns `null` for frames with no data line (e.g. a
 * bare `event: ping` keepalive) or unparseable JSON. PURE — no I/O, no state.
 *
 * SSE frames look like:
 *   event: content_block_delta
 *   data: {"type":"content_block_delta","index":0,"delta":{...}}
 */
export function parseSseEvent(raw: string): SseEvent | null {
  const dataLines: string[] = [];
  for (const line of raw.split("\n")) {
    // Per the SSE spec a value after "data:" may carry one leading space.
    if (line.startsWith("data:")) {
      dataLines.push(line.slice("data:".length).replace(/^ /, ""));
    }
  }
  if (dataLines.length === 0) return null;
  const payload = dataLines.join("\n");
  if (payload === "[DONE]") return null;
  try {
    return JSON.parse(payload) as SseEvent;
  } catch {
    return null;
  }
}

// ─── Streaming assembler ──────────────────────────────────────────────────────

// Accumulates streamed content blocks (by index) into a final AnthropicMessage
// so the agentic loop in chat-runtime.ts is unchanged — it still receives one
// fully-formed assistant message with content blocks, stop_reason, and usage.
class StreamAssembler {
  private readonly blocks = new Map<
    number,
    | { type: "text"; text: string }
    | { type: "thinking"; thinking: string; signature?: string }
    | { type: "tool_use"; id: string; name: string; partialJson: string }
  >();
  private stopReason: AnthropicStopReason = "end_turn";
  private usage: AnthropicUsage = { input_tokens: 0, output_tokens: 0 };

  constructor(private readonly handlers: StreamHandlers) {}

  ingest(event: SseEvent): void {
    switch (event.type) {
      case "message_start": {
        const u = (event as SseMessageStart).message?.usage;
        if (u) this.mergeUsage(u);
        break;
      }
      case "content_block_start":
        this.onBlockStart(event as SseContentBlockStart);
        break;
      case "content_block_delta":
        this.onBlockDelta(event as SseContentBlockDelta);
        break;
      case "message_delta":
        this.onMessageDelta(event as SseMessageDelta);
        break;
      // content_block_stop / message_stop / ping carry nothing we accumulate.
      // `error` events never reach the assembler — the transport rejects on
      // them first (mapSseErrorEvent in streamMessages).
      default:
        break;
    }
  }

  private onBlockStart(event: SseContentBlockStart): void {
    const cb = event.content_block;
    if (cb.type === "tool_use") {
      this.blocks.set(event.index, {
        type: "tool_use",
        id: cb.id,
        name: cb.name,
        partialJson: "",
      });
      const startBlock: AnthropicToolUseBlock = {
        type: "tool_use",
        id: cb.id,
        name: cb.name,
        input: {},
      };
      this.handlers.onContentBlockStart?.(startBlock);
    } else if (cb.type === "thinking") {
      this.blocks.set(event.index, { type: "thinking", thinking: cb.thinking ?? "" });
    } else {
      this.blocks.set(event.index, { type: "text", text: cb.text ?? "" });
    }
  }

  private onBlockDelta(event: SseContentBlockDelta): void {
    const block = this.blocks.get(event.index);
    const delta = event.delta;
    if (delta.type === "text_delta") {
      if (block && block.type === "text") block.text += delta.text;
      else this.blocks.set(event.index, { type: "text", text: delta.text });
      this.handlers.onTextDelta(delta.text);
    } else if (delta.type === "thinking_delta") {
      if (block && block.type === "thinking") block.thinking += delta.thinking;
      else this.blocks.set(event.index, { type: "thinking", thinking: delta.thinking });
      this.handlers.onThinkingDelta(delta.thinking);
    } else if (delta.type === "signature_delta") {
      if (block && block.type === "thinking") block.signature = delta.signature;
    } else if (delta.type === "input_json_delta") {
      if (block && block.type === "tool_use") block.partialJson += delta.partial_json;
    }
  }

  private onMessageDelta(event: SseMessageDelta): void {
    if (event.delta?.stop_reason) this.stopReason = event.delta.stop_reason;
    if (event.usage) this.mergeUsage(event.usage);
    this.handlers.onMessageDelta?.({
      stop_reason: this.stopReason,
      usage: this.usage,
    });
  }

  private mergeUsage(u: Partial<AnthropicUsage>): void {
    if (typeof u.input_tokens === "number") this.usage.input_tokens = u.input_tokens;
    if (typeof u.output_tokens === "number") this.usage.output_tokens = u.output_tokens;
    if (typeof u.cache_read_input_tokens === "number")
      this.usage.cache_read_input_tokens = u.cache_read_input_tokens;
    if (typeof u.cache_creation_input_tokens === "number")
      this.usage.cache_creation_input_tokens = u.cache_creation_input_tokens;
  }

  finalize(): AnthropicMessage {
    const content: AnthropicContentBlock[] = [];
    // Emit blocks in ascending index order so the message reads in stream order.
    for (const index of [...this.blocks.keys()].sort((a, b) => a - b)) {
      const block = this.blocks.get(index)!;
      if (block.type === "text") {
        content.push({ type: "text", text: block.text });
      } else if (block.type === "thinking") {
        content.push({
          type: "thinking",
          thinking: block.thinking,
          ...(block.signature ? { signature: block.signature } : {}),
        });
      } else {
        content.push({
          type: "tool_use",
          id: block.id,
          name: block.name,
          input: parseToolInput(block.partialJson),
        });
      }
    }
    return {
      role: "assistant",
      content,
      stop_reason: this.stopReason,
      usage: this.usage,
    };
  }
}

/**
 * Pure helper: fold a sequence of already-parsed SSE events into the final
 * `AnthropicMessage`, optionally firing delta handlers. Exposed for unit tests
 * (text/thinking deltas, tool `input_json_delta` accumulation, message_delta
 * stop_reason/usage) without touching the network. The streaming path uses the
 * same `StreamAssembler` internally.
 */
export function assembleStream(events: SseEvent[], handlers?: Partial<StreamHandlers>): AnthropicMessage {
  const noop = (): void => {};
  const assembler = new StreamAssembler({
    onTextDelta: handlers?.onTextDelta ?? noop,
    onThinkingDelta: handlers?.onThinkingDelta ?? noop,
    onContentBlockStart: handlers?.onContentBlockStart,
    onMessageDelta: handlers?.onMessageDelta,
  });
  for (const event of events) assembler.ingest(event);
  return assembler.finalize();
}

function parseToolInput(partialJson: string): Record<string, unknown> {
  if (!partialJson) return {};
  try {
    const parsed = JSON.parse(partialJson);
    return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

// ─── Mid-stream error events (AC3) ────────────────────────────────────────────
//
// Anthropic can fail a stream AFTER the 200 handshake by emitting an
// `event: error` SSE frame (e.g. overloaded_error mid-generation). Its envelope
// mirrors the HTTP error body: {"type":"error","error":{"type","message"}}.
// Map error.type onto the equivalent HTTP status so mapAnthropicError yields
// the SAME domain error the non-streaming path throws for that failure.
const SSE_ERROR_STATUS: Record<string, number> = {
  invalid_request_error: 400,
  authentication_error: 401,
  permission_error: 403,
  not_found_error: 404,
  request_too_large: 413,
  rate_limit_error: 429,
  api_error: 500,
  overloaded_error: 529,
};

/**
 * Detect a mid-stream `error` SSE event and translate it into a domain error,
 * or return null for every other event. Pure — exposed for unit tests.
 */
export function mapSseErrorEvent(event: SseEvent): VaultGuardError | null {
  if (event.type !== "error") return null;
  const err = (event as { error?: { type?: string } }).error;
  const status = (err?.type && SSE_ERROR_STATUS[err.type]) || 500;
  return mapAnthropicError(status, event);
}

// ─── Lazy Node `https` resolution (mobile-safe) ──────────────────────────────
//
// `https` is resolved at CALL time via a guarded `require`, never as a static
// top-level import — mirroring agent-bridge's `loadNodeHttp()`. A static
// `import ... from "https"` compiles to a top-level `require("https")` that runs
// the instant Obsidian evaluates the bundle, which would touch a Node builtin on
// mobile even though `streamMessages` is desktop-gated by the caller
// (`shouldStream()` → `!Platform.isMobileApp`). Resolving lazily keeps the whole
// module free of any load-time Node dependency, so the plugin bundle never
// requires `https` on mobile.

type HttpsRequestFn = typeof import("https").request;

let cachedHttpsRequest: HttpsRequestFn | null = null;

function loadHttpsRequest(): HttpsRequestFn {
  if (cachedHttpsRequest) return cachedHttpsRequest;
  const maybeWindow =
    typeof window !== "undefined" ? (window as unknown as Record<string, unknown>) : {};
  // Electron's renderer exposes CommonJS `require` as a global, not always on
  // `window`; probe both (and stay unit-testable via a globalThis.require shim).
  const maybeGlobal = globalThis as unknown as Record<string, unknown>;
  const req =
    typeof maybeWindow.require === "function"
      ? maybeWindow.require
      : typeof maybeGlobal.require === "function"
        ? maybeGlobal.require
        : null;
  if (!req) {
    throw new NetworkError(
      "Streaming is available only in desktop Obsidian with Node integration.",
    );
  }
  const https = req("https") as typeof import("https");
  if (!https || typeof https.request !== "function") {
    throw new NetworkError("Could not load Node's https module for streaming.");
  }
  cachedHttpsRequest = https.request;
  return cachedHttpsRequest;
}

// ─── Public streaming entry point ─────────────────────────────────────────────

/**
 * Stream a Messages request over Node's `https` and resolve the fully-assembled
 * `AnthropicMessage` (content blocks incl tool_use, stop_reason, usage) once the
 * stream ends — so the agentic loop is unchanged. Delta handlers fire live as
 * text/thinking tokens arrive. The AbortSignal truly aborts the in-flight
 * request via `req.destroy()`.
 */
export function streamMessages(
  apiKey: string,
  body: object,
  handlers: StreamHandlers,
  signal?: AbortSignal,
): Promise<AnthropicMessage> {
  return new Promise<AnthropicMessage>((resolve, reject) => {
    if (signal?.aborted) {
      reject(new NetworkError("Request aborted before it was sent."));
      return;
    }

    const assembler = new StreamAssembler(handlers);
    const payload = JSON.stringify({ ...body, stream: true });

    let settled = false;
    const finish = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      fn();
    };

    let httpsRequest: HttpsRequestFn;
    try {
      httpsRequest = loadHttpsRequest();
    } catch (err) {
      reject(err instanceof Error ? err : new NetworkError(String(err)));
      return;
    }

    const req = httpsRequest(
      {
        hostname: ANTHROPIC_HOSTNAME,
        path: ANTHROPIC_PATH,
        method: "POST",
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(payload),
          "x-api-key": apiKey,
          "anthropic-version": ANTHROPIC_VERSION,
        },
      },
      (resp) => {
        const status = resp.statusCode ?? 0;
        if (status < 200 || status >= 300) {
          let errBody = "";
          resp.setEncoding("utf8");
          resp.on("data", (c) => (errBody += c));
          resp.on("end", () => finish(() => reject(mapAnthropicError(status, safeJson(errBody)))));
          return;
        }

        let buf = "";
        resp.setEncoding("utf8");
        resp.on("data", (chunk: string) => {
          buf += chunk;
          // SSE framing: events separated by "\n\n".
          let idx: number;
          while ((idx = buf.indexOf("\n\n")) !== -1) {
            const raw = buf.slice(0, idx);
            buf = buf.slice(idx + 2);
            const event = parseSseEvent(raw);
            if (!event) continue;
            // AC3: a mid-stream `error` event means the reply is truncated —
            // reject NOW instead of letting "end" resolve the partial message
            // as if it were complete.
            const streamError = mapSseErrorEvent(event);
            if (streamError) {
              finish(() => reject(streamError));
              resp.destroy();
              return;
            }
            assembler.ingest(event);
          }
        });
        resp.on("end", () => finish(() => resolve(assembler.finalize())));
        resp.on("error", (e: Error) =>
          finish(() => reject(new NetworkError(`Anthropic stream failed: ${e.message}`))),
        );
      },
    );

    req.on("error", (e: Error) => {
      // `req.destroy(...)` on abort surfaces here — distinguish abort from a real
      // transport failure.
      if (signal?.aborted) {
        finish(() => reject(new NetworkError("Request aborted.")));
        return;
      }
      finish(() => reject(new NetworkError(`Could not reach Anthropic: ${e.message}`)));
    });

    if (signal) {
      signal.addEventListener(
        "abort",
        () => {
          req.destroy(new Error("aborted"));
        },
        { once: true },
      );
    }

    req.write(payload);
    req.end();
  });
}
