import { requestUrl, type RequestUrlParam, type RequestUrlResponse } from "obsidian";

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]", "::1"]);
const CONTROL = /[\u0000-\u001f\u007f]/u;
const INPUT_FORBIDDEN = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u;
const MAX_MODEL_CODE_POINTS = 128;
const MAX_INPUTS_PER_REQUEST = 8;
const MAX_CHARACTERS_PER_REQUEST = 32_000;
const MAX_DIMENSIONS = 4_096;
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

export interface SemanticEmbeddingOptions {
  isCancelled?: () => boolean;
}

export interface SemanticEmbeddingProvider {
  readonly origin: string;
  readonly model: string;
  embed(
    inputs: readonly string[],
    options?: SemanticEmbeddingOptions,
  ): Promise<number[][]>;
}

export interface OllamaEmbeddingProviderOptions {
  origin: string;
  model: string;
  request?: (params: RequestUrlParam) => Promise<RequestUrlResponse>;
}

export class SemanticOperationCancelledError extends Error {
  constructor() {
    super("Semantic operation cancelled.");
    this.name = "SemanticOperationCancelledError";
  }
}

export function normalizeOllamaOrigin(value: string): string {
  const raw = typeof value === "string" ? value.trim() : "";
  if (!raw || CONTROL.test(raw)) throw new Error("A valid loopback provider origin is required.");
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error("A valid loopback provider origin is required.");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("The semantic provider must use HTTP or HTTPS.");
  }
  if (!LOOPBACK_HOSTS.has(parsed.hostname.toLocaleLowerCase("en-US"))) {
    throw new Error("The semantic provider must use an exact loopback host.");
  }
  if (
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash ||
    (parsed.pathname !== "" && parsed.pathname !== "/")
  ) {
    throw new Error("The semantic provider must be a plain loopback origin.");
  }
  return parsed.origin;
}

export function validateOllamaModel(value: string): string {
  const model = typeof value === "string" ? value.trim() : "";
  const length = [...model].length;
  if (!model || length > MAX_MODEL_CODE_POINTS || CONTROL.test(model)) {
    throw new Error("The Ollama model must contain 1 to 128 visible characters.");
  }
  return model;
}

function assertNotCancelled(options: SemanticEmbeddingOptions): void {
  if (options.isCancelled?.()) throw new SemanticOperationCancelledError();
}

function characterCount(value: string): number {
  return [...value].length;
}

function normalizeVector(value: unknown, expectedDimensions: number | null): number[] {
  if (!Array.isArray(value)) throw new Error("Ollama returned a malformed embedding vector.");
  if (value.length < 1 || value.length > MAX_DIMENSIONS) {
    throw new Error("Ollama returned an unsupported embedding dimension.");
  }
  if (expectedDimensions !== null && value.length !== expectedDimensions) {
    throw new Error("Ollama returned inconsistent embedding dimensions.");
  }
  const vector = value.map((item) => {
    if (typeof item !== "number" || !Number.isFinite(item)) {
      throw new Error("Ollama returned a non-finite embedding value.");
    }
    return item;
  });
  const magnitude = Math.hypot(...vector);
  if (!Number.isFinite(magnitude) || magnitude <= Number.EPSILON) {
    throw new Error("Ollama returned a zero-magnitude embedding vector.");
  }
  return vector.map((item) => item / magnitude);
}

function buildBatches(inputs: readonly string[]): string[][] {
  if (inputs.length === 0) throw new Error("At least one embedding input is required.");
  const batches: string[][] = [];
  let current: string[] = [];
  let characters = 0;
  for (const raw of inputs) {
    if (typeof raw !== "string" || raw.length === 0 || INPUT_FORBIDDEN.test(raw)) {
      throw new Error("Embedding inputs must be non-empty text without control characters.");
    }
    const size = characterCount(raw);
    if (size > MAX_CHARACTERS_PER_REQUEST) {
      throw new Error("One embedding input exceeds the request character budget.");
    }
    if (
      current.length >= MAX_INPUTS_PER_REQUEST ||
      (current.length > 0 && characters + size > MAX_CHARACTERS_PER_REQUEST)
    ) {
      batches.push(current);
      current = [];
      characters = 0;
    }
    current.push(raw);
    characters += size;
  }
  if (current.length > 0) batches.push(current);
  return batches;
}

export class OllamaEmbeddingProvider implements SemanticEmbeddingProvider {
  readonly origin: string;
  readonly model: string;
  private readonly request: (params: RequestUrlParam) => Promise<RequestUrlResponse>;

  constructor(options: OllamaEmbeddingProviderOptions) {
    this.origin = normalizeOllamaOrigin(options.origin);
    this.model = validateOllamaModel(options.model);
    this.request = options.request ?? requestUrl;
  }

  async embed(
    inputs: readonly string[],
    options: SemanticEmbeddingOptions = {},
  ): Promise<number[][]> {
    const batches = buildBatches(inputs);
    const output: number[][] = [];
    let dimensions: number | null = null;

    for (const batch of batches) {
      assertNotCancelled(options);
      const response = await this.request({
        url: `${this.origin}/api/embed`,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        contentType: "application/json",
        body: JSON.stringify({
          model: this.model,
          input: batch,
          truncate: true,
          keep_alive: "5m",
        }),
        throw: false,
      });
      assertNotCancelled(options);
      if (response.status < 200 || response.status >= 300) {
        throw new Error(`The local Ollama provider returned HTTP ${response.status}.`);
      }
      if (response.arrayBuffer.byteLength > MAX_RESPONSE_BYTES) {
        throw new Error("The local Ollama provider response is too large.");
      }
      const body = response.json as { model?: unknown; embeddings?: unknown } | null;
      if (!body || typeof body !== "object" || !Array.isArray(body.embeddings)) {
        throw new Error("Ollama returned a malformed embedding response.");
      }
      if (typeof body.model === "string" && body.model !== this.model) {
        throw new Error("Ollama returned embeddings for a different model.");
      }
      if (body.embeddings.length !== batch.length) {
        throw new Error("Ollama returned a different embedding count than requested.");
      }
      for (const rawVector of body.embeddings) {
        const vector = normalizeVector(rawVector, dimensions);
        dimensions ??= vector.length;
        output.push(vector);
      }
    }
    return output;
  }
}
