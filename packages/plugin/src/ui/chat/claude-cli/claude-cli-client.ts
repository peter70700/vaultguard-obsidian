// ClaudeCliClient — drives the official `claude` binary as a subprocess and maps
// its newline-delimited stream-json output onto the SAME progress events the chat
// UI already consumes (docs/AI-CHAT-PANEL.md "Auth & providers"). This is the
// "subscription" provider: the user spends their Claude Pro/Max subscription via
// their own logged-in CLI, and the plugin NEVER handles the subscription token.
//
// ENCRYPTION BOUNDARY (non-negotiable): the spawned `claude` reaches vault
// content ONLY through VaultGuard's AgentBridge MCP server (localhost,
// lease-scoped, permission-checked, writeMode-gated). We lock that down
// with:
//   - --strict-mcp-config + a single HTTP MCP entry (no .mcp.json / CLAUDE.md
//     discovery), and we spawn in a FRESH EMPTY temp cwd so there is no project
//     context to discover.
//   - --allowedTools = the mcp__vaultguard__* tools only (incl. the gated
//     import_list / import_read, which stay server-gated — see mcp-config.ts).
//   - --permission-mode dontAsk denies anything unlisted with no interactive
//     prompt. We intentionally do not pass --disallowedTools because built-in
//     tool names vary across CLI versions and can cause false launch failures.
//   - NEVER --bare (which forces ANTHROPIC_API_KEY-only auth and defeats the
//     subscription keychain).
// This file itself touches NO vault files and NO fs beyond creating a throwaway
// temp cwd dir for the child.
//
// Desktop-only: `child_process` does not exist in mobile Obsidian. The caller
// (chat-view) gates on Platform before constructing this client.
//
// The line parser `parseClaudeStreamLine` is pure and unit-tested; no real
// `claude` process is ever spawned in tests.

import { Platform } from "obsidian";

import {
  VAULTGUARD_MCP_TOOL_NAMES,
  buildMcpConfig,
  buildVaultGuardCliSystemPrompt,
  serializeMcpConfig,
} from "./mcp-config";
import type { AiChatPermissionMode } from "../../../types";

const LOG_PREFIX = "[VaultGuard Chat]";

// ─── Progress handler shape (mirrors ChatProgress used by the UI) ─────────────

export interface ClaudeCliHandlers {
  /** A run of assistant text (whole block on result, or live via onTextDelta). */
  onText?(text: string): void;
  /** Live token-by-token assistant text (stream_event text_delta). */
  onTextDelta?(text: string): void;
  /** Live token-by-token thinking summary (stream_event thinking_delta). */
  onThinkingDelta?(text: string): void;
  /** A tool_use started (name + input). */
  onToolCall?(name: string, input: unknown): void;
  /** A tool_result landed. `isError` mirrors the MCP tool error flag. */
  onToolResult?(name: string, result: { content: string; isError: boolean }): void;
  /** Terminal result for the turn: cost (USD) + the session id to resume. */
  onResult?(info: { costUsd?: number; sessionId?: string }): void;
  /** Transport progress/status from the Claude CLI (not assistant transcript). */
  onStatus?(message: string): void;
  /** A fatal error (non-zero exit, error result subtype, or stderr). */
  onError?(message: string): void;
}

// ─── Parsed stream-json line shapes (pure parser output) ──────────────────────

export type ClaudeStreamParsed =
  | { kind: "ignore" }
  | { kind: "init"; sessionId?: string; model?: string }
  | { kind: "text_delta"; text: string }
  | { kind: "thinking_delta"; text: string }
  | { kind: "status"; message: string }
  | { kind: "tool_use"; name: string; input: unknown }
  | { kind: "tool_result"; name: string; content: string; isError: boolean }
  | { kind: "result"; isError: boolean; costUsd?: number; sessionId?: string; text?: string; subtype?: string };

// Loosely-typed view of the JSON line shapes claude 2.1.181 emits. We read only
// the fields we act on and tolerate everything else.
interface RawLine {
  type?: string;
  subtype?: string;
  session_id?: string;
  model?: string;
  is_error?: boolean;
  total_cost_usd?: number;
  result?: string;
  status?: string;
  text?: string;
  // stream_event wrapper
  event?: {
    type?: string;
    content_block?: { type?: string; name?: string; input?: unknown; id?: string };
    delta?: { type?: string; text?: string; thinking?: string };
  };
  // assistant message wrapper (full assembled message)
  message?: { content?: Array<{ type?: string; name?: string; input?: unknown; content?: unknown; is_error?: boolean }> } | string;
  // tool_result lines (when surfaced at top level by some versions)
  tool_use_id?: string;
  content?: unknown;
}

/**
 * Parse ONE newline-delimited stream-json line into a normalized event. Pure:
 * no IO, no spawning. Returns `{ kind: "ignore" }` for lines we don't act on
 * (system status, hooks, rate_limit, message_start/stop, etc.) and for blank /
 * unparseable lines.
 */
export function parseClaudeStreamLine(line: string): ClaudeStreamParsed {
  const trimmed = cleanClaudeCliText(line);
  if (!trimmed) return { kind: "ignore" };

  let raw: RawLine;
  try {
    raw = JSON.parse(trimmed) as RawLine;
  } catch {
    const status = normalizeClaudeStatus(trimmed);
    if (status) return { kind: "status", message: status };
    return { kind: "ignore" };
  }

  switch (raw.type) {
    case "system": {
      if (raw.subtype === "init") {
        return { kind: "init", sessionId: raw.session_id, model: raw.model };
      }
      const status = normalizeClaudeStatus(firstString(raw.status, raw.text, raw.message));
      if (status) return { kind: "status", message: status };
      return { kind: "ignore" };
    }

    case "stream_event": {
      const ev = raw.event;
      if (!ev) return { kind: "ignore" };
      if (ev.type === "content_block_delta") {
        if (ev.delta?.type === "text_delta" && typeof ev.delta.text === "string") {
          const status = normalizeClaudeStatus(ev.delta.text);
          if (status) return { kind: "status", message: status };
          return { kind: "text_delta", text: ev.delta.text };
        }
        if (ev.delta?.type === "thinking_delta" && typeof ev.delta.thinking === "string") {
          return { kind: "thinking_delta", text: ev.delta.thinking };
        }
        return { kind: "ignore" };
      }
      if (ev.type === "content_block_start" && ev.content_block?.type === "tool_use") {
        return {
          kind: "tool_use",
          name: ev.content_block.name ?? "tool",
          input: ev.content_block.input ?? {},
        };
      }
      return { kind: "ignore" };
    }

    case "user": {
      // Tool results come back as a `user` turn carrying tool_result blocks.
      const blocks =
        raw.message && typeof raw.message === "object" ? raw.message.content : undefined;
      if (Array.isArray(blocks)) {
        for (const b of blocks) {
          if (b?.type === "tool_result") {
            return {
              kind: "tool_result",
              name: typeof b.name === "string" ? b.name : "tool",
              content: stringifyToolContent(b.content),
              isError: b.is_error === true,
            };
          }
        }
      }
      return { kind: "ignore" };
    }

    case "result": {
      return {
        kind: "result",
        isError: raw.is_error === true,
        costUsd: typeof raw.total_cost_usd === "number" ? raw.total_cost_usd : undefined,
        sessionId: raw.session_id,
        text: typeof raw.result === "string" ? raw.result : undefined,
        subtype: raw.subtype,
      };
    }

    // assistant / message_start / message_stop / rate_limit_event / etc.
    default:
      return { kind: "ignore" };
  }
}

const ANSI_OSC_RE = /\x1B\][\s\S]*?(?:\x07|\x1B\\)/g;
const ANSI_CSI_RE = /\x1B(?:\[[0-?]*[ -/]*[@-~]|[@-Z\\-_])/g;
const CONTROL_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;

export function cleanClaudeCliText(text: string): string {
  return text
    .replace(ANSI_OSC_RE, "")
    .replace(ANSI_CSI_RE, "")
    .replace(/[\r\n]+/g, " ")
    .replace(CONTROL_RE, "")
    .replace(/\s+/g, " ")
    .trim();
}

function firstString(...values: unknown[]): string {
  for (const value of values) {
    if (typeof value === "string") return value;
  }
  return "";
}

export function normalizeClaudeStatus(text: string): string {
  const cleaned = cleanClaudeCliText(text);
  if (!cleaned) return "";
  const hasSpinnerPrefix = /^[✽✳✶✷✸✹✺✻✼✢*•●○◐◓◑◒⠁-⣿]\s+/.test(cleaned);
  const withoutPrefix = cleaned.replace(/^[✽✳✶✷✸✹✺✻✼✢*•●○◐◓◑◒⠁-⣿]\s+/, "");
  const hasProgressMetrics =
    /\((?=[^)]*(?:tokens?|tok|[↓↑]|\d+\s*(?:h|m|s)))[^)]*\)\s*$/i.test(withoutPrefix);
  const looksLikeCliStatus =
    hasProgressMetrics &&
    (hasSpinnerPrefix ||
      /\b(?:manifesting|thinking|working|pondering|processing|compacting|reading|searching|using|running)\b/i.test(
        withoutPrefix,
      ));
  return looksLikeCliStatus ? withoutPrefix : "";
}

function splitCliFrames(buffer: string): { frames: string[]; remainder: string } {
  const parts = buffer.split(/\r\n|\n|\r/g);
  return {
    frames: parts.slice(0, -1),
    remainder: parts.at(-1) ?? "",
  };
}

function stringifyToolContent(content: unknown): string {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    // MCP tool_result content is often an array of {type:"text", text}.
    return content
      .map((c) =>
        c && typeof c === "object" && "text" in c && typeof (c as { text: unknown }).text === "string"
          ? (c as { text: string }).text
          : JSON.stringify(c),
      )
      .join("\n");
  }
  if (content == null) return "";
  return JSON.stringify(content);
}

// ─── Node module resolution (desktop-only) ────────────────────────────────────

interface SpawnedChild {
  stdout: { on(ev: "data", cb: (chunk: Buffer | string) => void): void } | null;
  stderr: { on(ev: "data", cb: (chunk: Buffer | string) => void): void } | null;
  on(ev: "error", cb: (err: Error) => void): void;
  on(ev: "close", cb: (code: number | null) => void): void;
  kill(signal?: string): void;
}

interface ChildProcessModule {
  spawn(
    command: string,
    args: ReadonlyArray<string>,
    options: {
      cwd?: string;
      env?: NodeJS.ProcessEnv;
      stdio?: ReadonlyArray<"ignore" | "pipe" | "inherit">;
    },
  ): SpawnedChild;
}

interface FsModule {
  mkdtempSync(prefix: string): string;
  rmSync(path: string, options: { recursive: boolean; force: boolean }): void;
}

interface OsPathModule {
  tmpdir(): string;
  join(...parts: string[]): string;
}

interface ClientNodeDeps {
  childProcess: ChildProcessModule;
  fs: FsModule;
  tmpdir(): string;
  join(...parts: string[]): string;
}

function nodeRequire(): NodeRequire | null {
  const maybeWindow =
    typeof window !== "undefined" ? (window as unknown as Record<string, unknown>) : {};
  if (typeof maybeWindow.require === "function") return maybeWindow.require as NodeRequire;
  return null;
}

function loadNodeDeps(): ClientNodeDeps | null {
  const req = nodeRequire();
  if (!req) return null;
  try {
    const os = req("os") as OsPathModule;
    const path = req("path") as OsPathModule;
    return {
      childProcess: req("child_process") as ChildProcessModule,
      fs: req("fs") as FsModule,
      tmpdir: () => os.tmpdir(),
      join: (...p: string[]) => path.join(...p),
    };
  } catch {
    return null;
  }
}

// ─── Client ───────────────────────────────────────────────────────────────────

export interface ClaudeCliClientConfig {
  binaryPath: string;
  mcpUrl: string;
  leaseToken: string;
  model: string;
  permissionMode?: AiChatPermissionMode;
  // Injected for tests; production resolves Node modules itself.
  deps?: ClientNodeDeps;
}

export class ClaudeCliClient {
  private readonly deps: ClientNodeDeps | null;
  // Threaded from the first `result` so follow-up turns keep context.
  private sessionId: string | null = null;
  // ONE stable working directory for the whole client lifetime. Claude Code
  // scopes session history by cwd, so `--resume` only works if every turn runs
  // in the SAME directory. Created lazily on the first turn; removed on reset().
  private cwd: string | null = null;

  constructor(private readonly config: ClaudeCliClientConfig) {
    this.deps = config.deps ?? loadNodeDeps();
  }

  /** True when the client can actually spawn (desktop + Node available). */
  isSupported(): boolean {
    return !Platform.isMobileApp && this.deps !== null;
  }

  /** Reset multi-turn threading + drop the working dir (used by /clear, onClose). */
  reset(): void {
    this.sessionId = null;
    if (this.cwd) {
      this.cleanupCwd(this.cwd);
      this.cwd = null;
    }
  }

  /**
   * Run one turn. Spawns `claude -p <text> ...` in a fresh empty temp cwd,
   * parses stream-json, and fires `handlers`. Aborting the signal kills the
   * child. Resolves when the process closes.
   */
  async runTurn(text: string, handlers: ClaudeCliHandlers, signal?: AbortSignal): Promise<void> {
    if (!this.deps) {
      handlers.onError?.("Claude Code subscription mode needs desktop Obsidian.");
      return;
    }
    if (signal?.aborted) return;

    // Stable cwd for the whole client lifetime (so --resume works across turns).
    const cwd = this.ensureCwd();
    const args = this.buildArgs(text);

    return new Promise<void>((resolve) => {
      let child: SpawnedChild;
      try {
        child = this.deps!.childProcess.spawn(this.config.binaryPath, args, {
          cwd,
          // Inherit PATH/HOME so `claude` finds its keychain + config; we do NOT
          // set any Anthropic token. No --bare, so OAuth/keychain auth is used.
          env: this.buildChildEnv(),
          // No stdin (/dev/null). `claude -p` otherwise waits ~3s for piped
          // stdin and logs a "no stdin data received" warning before proceeding.
          stdio: ["ignore", "pipe", "pipe"],
        });
      } catch (e) {
        handlers.onError?.(`Could not start Claude Code: ${(e as Error).message}`);
        resolve();
        return;
      }

      let settled = false;
      let stderrBuf = "";
      let stdoutRemainder = "";
      let stderrRemainder = "";
      let sawResult = false;
      let resultWasError = false;
      let sawTextDelta = false;

      const finish = () => {
        if (settled) return;
        settled = true;
        // NOTE: do NOT delete `cwd` here — it is reused across turns so
        // `--resume` keeps working. It is removed in reset() / onClose.
        resolve();
      };

      const onAbort = () => {
        try {
          child.kill("SIGTERM");
        } catch {
          /* already gone */
        }
      };
      if (signal) signal.addEventListener("abort", onAbort, { once: true });

      const handleStdoutFrame = (line: string): void => {
        const parsed = parseClaudeStreamLine(line);
        if (parsed.kind === "text_delta") sawTextDelta = true;
        if (parsed.kind === "result" && parsed.text && !sawTextDelta) {
          handlers.onTextDelta?.(parsed.text);
          sawTextDelta = true;
        }
        this.dispatch(parsed, handlers);
        if (parsed.kind === "result") {
          sawResult = true;
          resultWasError = parsed.isError;
        }
      };

      const handleStderrFrame = (line: string): void => {
        const cleaned = cleanClaudeCliText(line);
        if (!cleaned) return;
        const status = normalizeClaudeStatus(cleaned);
        if (status) {
          handlers.onStatus?.(status);
          return;
        }
        stderrBuf += `${stderrBuf ? "\n" : ""}${cleaned}`;
      };

      child.stdout?.on("data", (chunk) => {
        stdoutRemainder += chunk.toString();
        const split = splitCliFrames(stdoutRemainder);
        stdoutRemainder = split.remainder;
        for (const line of split.frames) handleStdoutFrame(line);
      });

      child.stderr?.on("data", (chunk) => {
        stderrRemainder += chunk.toString();
        const split = splitCliFrames(stderrRemainder);
        stderrRemainder = split.remainder;
        for (const line of split.frames) handleStderrFrame(line);
      });

      child.on("error", (err) => {
        handlers.onError?.(`Claude Code failed to launch: ${err.message}`);
        signal?.removeEventListener("abort", onAbort);
        finish();
      });

      child.on("close", (code) => {
        // Flush any trailing buffered line.
        if (stdoutRemainder.trim()) {
          handleStdoutFrame(stdoutRemainder);
        }
        if (stderrRemainder.trim()) {
          handleStderrFrame(stderrRemainder);
        }
        signal?.removeEventListener("abort", onAbort);

        if (signal?.aborted) {
          // User cancelled — not an error.
          finish();
          return;
        }
        if ((code !== 0 && code !== null) || resultWasError || !sawResult) {
          const msg =
            stderrBuf.trim() ||
            (resultWasError
              ? "Claude Code reported an error for this turn."
              : `Claude Code exited with code ${code ?? "unknown"}.`);
          handlers.onError?.(msg);
        }
        finish();
      });
    });
  }

  private dispatch(parsed: ClaudeStreamParsed, handlers: ClaudeCliHandlers): void {
    switch (parsed.kind) {
      case "init":
        if (parsed.sessionId) this.sessionId = parsed.sessionId;
        break;
      case "text_delta":
        handlers.onTextDelta?.(parsed.text);
        break;
      case "thinking_delta":
        handlers.onThinkingDelta?.(parsed.text);
        break;
      case "status":
        handlers.onStatus?.(parsed.message);
        break;
      case "tool_use":
        handlers.onToolCall?.(parsed.name, parsed.input);
        break;
      case "tool_result":
        handlers.onToolResult?.(parsed.name, {
          content: parsed.content,
          isError: parsed.isError,
        });
        break;
      case "result":
        if (parsed.sessionId) this.sessionId = parsed.sessionId;
        // If the deltas never fired (no --include-partial-messages on some
        // versions), runTurn surfaces the final text once before dispatching
        // this result.
        handlers.onResult?.({ costUsd: parsed.costUsd, sessionId: parsed.sessionId });
        break;
      case "ignore":
      default:
        break;
    }
  }

  // Child env: inherit the parent's PATH/HOME so `claude` finds its keychain
  // and config. ask_user returns a paused marker immediately in MCP mode, so
  // approvals no longer depend on MCP_TOOL_TIMEOUT.
  private buildChildEnv(): NodeJS.ProcessEnv | undefined {
    if (typeof process === "undefined") return undefined;
    return { ...process.env };
  }

  // Build the argv. NOTE: NOT --bare (keeps subscription keychain auth).
  private buildArgs(text: string): string[] {
    const mcpJson = serializeMcpConfig(buildMcpConfig(this.config.mcpUrl, this.config.leaseToken));
    const args: string[] = [
      "-p",
      text,
      "--output-format",
      "stream-json",
      "--include-partial-messages",
      "--verbose",
      "--strict-mcp-config",
      "--mcp-config",
      mcpJson,
      // Allow ONLY our mcp__vaultguard__* tools (incl. the gated import_*, which
      // stay server-gated). Combined with --permission-mode dontAsk (deny
      // anything not in the allow-list) this blocks every built-in file/bash/web
      // tool WITHOUT enumerating them — robust across CLI versions (enumerating
      // --disallowedTools broke when a built-in name like "MultiEdit" didn't
      // exist in the installed claude).
      "--allowedTools",
      ...VAULTGUARD_MCP_TOOL_NAMES,
      "--permission-mode",
      "dontAsk",
      // Steer the model to the mcp__vaultguard__* tools and forbid the native
      // Write/Edit/Read/Bash tools it would otherwise reach for (which dontAsk
      // denies, producing the confusing "Write tool denied" reply). See
      // VAULTGUARD_CLI_SYSTEM_PROMPT for the full rationale.
      "--append-system-prompt",
      buildVaultGuardCliSystemPrompt(this.config.permissionMode),
      "--model",
      this.config.model,
    ];
    // Thread the session for multi-turn context.
    if (this.sessionId) {
      args.push("--resume", this.sessionId);
    }
    return args;
  }

  // The ONE empty temp dir for this client. `claude` discovers NO project
  // context there (CLAUDE.md / .mcp.json), and reusing it across turns keeps
  // --resume working (Claude scopes sessions by cwd). Created once, then cached.
  // Best-effort: if temp creation fails we fall back to undefined cwd, still
  // protected by --strict-mcp-config + dontAsk.
  private ensureCwd(): string | undefined {
    if (this.cwd) return this.cwd;
    if (!this.deps) return undefined;
    try {
      this.cwd = this.deps.fs.mkdtempSync(
        this.deps.join(this.deps.tmpdir(), "vaultguard-claude-"),
      );
      return this.cwd;
    } catch (e) {
      console.warn(`${LOG_PREFIX} Could not create neutral temp cwd for Claude Code`, e);
      return undefined;
    }
  }

  private cleanupCwd(cwd: string | undefined): void {
    if (!cwd || !this.deps) return;
    try {
      this.deps.fs.rmSync(cwd, { recursive: true, force: true });
    } catch {
      /* best-effort */
    }
  }
}
