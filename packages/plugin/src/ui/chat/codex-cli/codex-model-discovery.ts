// One-shot, metadata-only access to the authenticated Codex model catalog.
// This process receives no VaultGuard lease/MCP config and never starts a thread.

import { Platform } from "obsidian";

import {
  buildCodexBaseChildEnv,
  buildCodexModelDiscoveryArgs,
  loadCodexAppServerDeps,
  type CodexAppServerClientDeps,
} from "./codex-app-server-client";

const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;
const DEFAULT_PAGE_SIZE = 100;
const DEFAULT_MAX_PAGES = 10;
const DEFAULT_MAX_MODELS = 500;
const MAX_CURSOR_LENGTH = 1_000;
const MAX_PENDING_STDOUT_CHARS = 4 * 1024 * 1024;

export interface CodexSubscriptionModelInfo {
  id: string;
  model: string;
  displayName?: string;
  description?: string;
  hidden?: boolean;
  isDefault?: boolean;
  defaultReasoningEffort?: unknown;
  supportedReasoningEfforts?: unknown;
}

export type CodexModelDiscoveryDeps = Pick<
  CodexAppServerClientDeps,
  "spawn" | "mkdtempSync" | "rmSync" | "tmpdir" | "join" | "parentEnv"
>;

export interface CodexModelDiscoveryOptions {
  signal?: AbortSignal;
  deps?: CodexModelDiscoveryDeps;
  requestTimeoutMs?: number;
  pageSize?: number;
  maxPages?: number;
  maxModels?: number;
}

interface PendingRequest {
  resolve(value: unknown): void;
  reject(error: Error): void;
  timer: ReturnType<typeof setTimeout>;
}

interface RpcMessage {
  id?: number;
  result?: unknown;
  error?: unknown;
  method?: string;
}

export async function listCodexSubscriptionModels(
  binaryPath: string,
  options: CodexModelDiscoveryOptions = {},
): Promise<CodexSubscriptionModelInfo[]> {
  if (options.signal?.aborted) throw new Error("Codex model discovery was cancelled.");
  if (Platform.isMobileApp) {
    throw new Error("Codex model discovery needs desktop Obsidian.");
  }
  const deps = options.deps ?? loadCodexAppServerDeps();
  if (!deps) throw new Error("Codex model discovery is unavailable on this device.");

  const requestTimeoutMs = boundedInteger(
    options.requestTimeoutMs,
    DEFAULT_REQUEST_TIMEOUT_MS,
    10,
    60_000,
  );
  const pageSize = boundedInteger(options.pageSize, DEFAULT_PAGE_SIZE, 1, 100);
  const maxPages = boundedInteger(options.maxPages, DEFAULT_MAX_PAGES, 1, 50);
  const maxModels = boundedInteger(options.maxModels, DEFAULT_MAX_MODELS, 1, 2_000);
  const cwd = deps.mkdtempSync(deps.join(deps.tmpdir(), "vaultguard-codex-models-"));
  const pending = new Map<number, PendingRequest>();
  let nextRequestId = 1;
  let stdoutBuffer = "";
  let closing = false;
  let transportError: Error | null = null;
  let child: ReturnType<CodexModelDiscoveryDeps["spawn"]> | null = null;

  const rejectPending = (error: Error): void => {
    for (const request of pending.values()) {
      clearTimeout(request.timer);
      request.reject(error);
    }
    pending.clear();
  };

  const cleanup = (): void => {
    if (closing) return;
    closing = true;
    rejectPending(new Error("Codex model discovery stopped."));
    try {
      child?.stdin?.end();
    } catch {
      // The child may already have closed its input.
    }
    try {
      child?.kill("SIGTERM");
    } catch {
      // The child may already have exited.
    }
    child = null;
    stdoutBuffer = "";
    try {
      deps.rmSync(cwd, { recursive: true, force: true });
    } catch {
      // No credential or vault data is written to this directory.
    }
  };

  // Sticky: a transport failure can land while no request is in flight (between
  // the initialize response and the first model/list write). Rejecting only the
  // pending map would drop it, and the next request would then hang until its
  // own timeout instead of failing on the error that already happened.
  const failTransport = (message: string): void => {
    const error = new Error(message);
    if (!transportError) transportError = error;
    rejectPending(error);
  };

  const handleStdout = (chunk: string): void => {
    stdoutBuffer += chunk;
    const lines = stdoutBuffer.split(/\r?\n/g);
    stdoutBuffer = lines.pop() ?? "";
    // A child that never emits a newline would otherwise grow this without
    // bound. Nothing legitimate approaches the cap: responses are one JSON
    // object per line.
    if (stdoutBuffer.length > MAX_PENDING_STDOUT_CHARS) {
      stdoutBuffer = "";
      failTransport("Codex model discovery received malformed output.");
      return;
    }
    for (const line of lines) {
      if (!line.trim()) continue;
      let message: RpcMessage;
      try {
        message = JSON.parse(line) as RpcMessage;
      } catch {
        failTransport("Codex model discovery received malformed output.");
        return;
      }
      if (typeof message.id !== "number" || message.method) continue;
      const request = pending.get(message.id);
      if (!request) continue;
      clearTimeout(request.timer);
      pending.delete(message.id);
      if (message.error !== undefined) {
        request.reject(new Error("Codex model discovery failed."));
      } else {
        request.resolve(message.result);
      }
    }
  };

  const request = (method: string, params: unknown): Promise<unknown> => {
    const id = nextRequestId++;
    return new Promise((resolve, reject) => {
      if (transportError) {
        reject(transportError);
        return;
      }
      if (!child?.stdin) {
        reject(new Error("Codex model discovery is not running."));
        return;
      }
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new Error(`Codex model discovery timed out during ${method}.`));
      }, requestTimeoutMs);
      pending.set(id, { resolve, reject, timer });
      try {
        child.stdin.write(`${JSON.stringify({ id, method, params })}\n`);
      } catch {
        clearTimeout(timer);
        pending.delete(id);
        reject(new Error("Codex model discovery failed."));
      }
    });
  };

  const notify = (method: string, params: unknown): void => {
    if (!child?.stdin) throw new Error("Codex model discovery is not running.");
    child.stdin.write(`${JSON.stringify({ method, params })}\n`);
  };

  const onAbort = (): void => {
    failTransport(new Error("Codex model discovery was cancelled.").message);
    cleanup();
  };
  options.signal?.addEventListener("abort", onAbort, { once: true });

  try {
    child = deps.spawn(binaryPath, buildCodexModelDiscoveryArgs(), {
      cwd,
      env: buildCodexBaseChildEnv(deps.parentEnv),
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
      shell: /\.(?:cmd|bat)$/i.test(binaryPath),
    });
    if (!child.stdin || !child.stdout) {
      throw new Error("Codex model discovery transport is unavailable.");
    }
    child.stdin.on("error", () => failTransport("Codex model discovery failed."));
    child.stdout.on("data", (chunk) => handleStdout(chunk.toString()));
    child.stderr?.on("data", () => undefined);
    child.on("error", () => failTransport("Codex model discovery failed."));
    child.on("close", () => {
      if (!closing) failTransport("Codex model discovery process exited unexpectedly.");
    });

    await request("initialize", {
      clientInfo: {
        name: "vaultguard_obsidian_model_catalog",
        title: "VaultGuard Obsidian Model Catalog",
        version: "1",
      },
      capabilities: { experimentalApi: true },
    });
    notify("initialized", {});

    const models: CodexSubscriptionModelInfo[] = [];
    const seenCursors = new Set<string>();
    let cursor: string | undefined;
    for (let page = 0; page < maxPages; page++) {
      const params: Record<string, unknown> = { includeHidden: false, limit: pageSize };
      if (cursor !== undefined) params.cursor = cursor;
      const result = await request("model/list", params);
      const parsed = parsePage(result);
      if (models.length + parsed.data.length > maxModels) {
        throw new Error("Codex model discovery returned too many models.");
      }
      models.push(...parsed.data);
      if (parsed.nextCursor === undefined) return models;
      if (
        parsed.nextCursor.length > MAX_CURSOR_LENGTH ||
        seenCursors.has(parsed.nextCursor)
      ) {
        throw new Error("Codex model discovery returned invalid pagination.");
      }
      seenCursors.add(parsed.nextCursor);
      cursor = parsed.nextCursor;
    }
    throw new Error("Codex model discovery exceeded its page limit.");
  } finally {
    options.signal?.removeEventListener("abort", onAbort);
    cleanup();
  }
}

function parsePage(value: unknown): {
  data: CodexSubscriptionModelInfo[];
  nextCursor?: string;
} {
  if (!value || typeof value !== "object" || !Array.isArray((value as { data?: unknown }).data)) {
    throw new Error("Codex model discovery returned malformed data.");
  }
  const raw = value as { data: unknown[]; nextCursor?: unknown };
  const nextCursor = raw.nextCursor;
  if (nextCursor !== undefined && nextCursor !== null && typeof nextCursor !== "string") {
    throw new Error("Codex model discovery returned malformed pagination.");
  }
  return {
    data: raw.data as CodexSubscriptionModelInfo[],
    ...(typeof nextCursor === "string" && nextCursor.length > 0 ? { nextCursor } : {}),
  };
}

function boundedInteger(
  value: number | undefined,
  fallback: number,
  min: number,
  max: number,
): number {
  if (typeof value !== "number" || !Number.isFinite(value)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(value)));
}
