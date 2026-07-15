// Drives the official Codex app-server for VaultGuard's ChatGPT-subscription
// provider. The process owns ChatGPT authentication; VaultGuard owns the only
// MCP server/tool surface. The AgentBridge bearer is child-environment-only.

import { Platform } from "obsidian";

import type { AiChatPermissionMode, OpenAiReasoningEffort } from "../../../types";
import type { ClaudeCliHandlers } from "../claude-cli/claude-cli-client";
import {
  VAULTGUARD_MCP_TOOL_NAMES,
  buildVaultGuardCliSystemPrompt,
} from "../claude-cli/mcp-config";

const TOKEN_ENV_PREFIX = "VAULTGUARD_CODEX_MCP_TOKEN_";
const REMOTE_CONTROL_DISABLED_ENV = "CODEX_INTERNAL_APP_SERVER_REMOTE_CONTROL_DISABLED";
const REQUEST_TIMEOUT_MS = 15_000;
const MAX_STDERR_CHARS = 4_000;

export const CODEX_DISABLED_FEATURES: ReadonlyArray<string> = [
  "shell_tool",
  "unified_exec",
  "shell_snapshot",
  "code_mode",
  "code_mode_host",
  "hooks",
  "multi_agent",
  "apps",
  "tool_suggest",
  "plugins",
  "in_app_browser",
  "browser_use",
  "browser_use_full_cdp_access",
  "browser_use_external",
  "computer_use",
  "remote_plugin",
  "image_generation",
  "skill_mcp_dependency_install",
  "goals",
  "memories",
  "workspace_dependencies",
];

const CODEX_TOOL_NAMES = VAULTGUARD_MCP_TOOL_NAMES.map((name) =>
  name.replace(/^mcp__vaultguard__/, ""),
);

const SAFE_ENV_KEYS = new Set([
  "PATH",
  "Path",
  "PATHEXT",
  "HOME",
  "USER",
  "USERNAME",
  "USERPROFILE",
  "HOMEDRIVE",
  "HOMEPATH",
  "APPDATA",
  "LOCALAPPDATA",
  "PROGRAMDATA",
  "PROGRAMFILES",
  "PROGRAMFILES(X86)",
  "SYSTEMDRIVE",
  "SYSTEMROOT",
  "WINDIR",
  "COMSPEC",
  "TEMP",
  "TMP",
  "TMPDIR",
  "SHELL",
  "TERM",
  "LANG",
  "TZ",
  "CODEX_HOME",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "ALL_PROXY",
  "NO_PROXY",
  "http_proxy",
  "https_proxy",
  "all_proxy",
  "no_proxy",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
  "DBUS_SESSION_BUS_ADDRESS",
  "WSLENV",
  "WSL_DISTRO_NAME",
]);

function toml(value: unknown): string {
  return JSON.stringify(value);
}

function pushOverride(args: string[], key: string, value: unknown): void {
  args.push("-c", `${key}=${toml(value)}`);
}

export function buildCodexAppServerArgs(input: {
  mcpUrl: string;
  tokenEnvName: string;
}): string[] {
  const args: string[] = [];
  for (const feature of CODEX_DISABLED_FEATURES) {
    pushOverride(args, `features.${feature}`, false);
  }
  pushOverride(args, "web_search", "disabled");
  pushOverride(args, "skills.include_instructions", false);
  pushOverride(args, "skills.bundled.enabled", false);
  pushOverride(args, "orchestrator.skills.enabled", false);
  pushOverride(args, "orchestrator.mcp.enabled", false);
  pushOverride(args, "project_doc_max_bytes", 0);
  pushOverride(args, "project_doc_fallback_filenames", []);
  pushOverride(args, "analytics.enabled", false);
  pushOverride(args, "mcp_servers.vaultguard.url", input.mcpUrl);
  pushOverride(
    args,
    "mcp_servers.vaultguard.bearer_token_env_var",
    input.tokenEnvName,
  );
  pushOverride(args, "mcp_servers.vaultguard.enabled_tools", CODEX_TOOL_NAMES);
  pushOverride(args, "mcp_servers.vaultguard.required", true);
  pushOverride(args, "mcp_servers.vaultguard.startup_timeout_sec", 15);
  pushOverride(args, "mcp_servers.vaultguard.tool_timeout_sec", 300);
  args.push("app-server", "--stdio");
  return args;
}

export function buildCodexChildEnv(
  parent: NodeJS.ProcessEnv,
  tokenEnvName: string,
  leaseToken: string,
): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(parent)) {
    if (value === undefined) continue;
    if (SAFE_ENV_KEYS.has(key) || key.startsWith("LC_") || key.startsWith("XDG_")) {
      env[key] = value;
    }
  }
  env[REMOTE_CONTROL_DISABLED_ENV] = "1";
  env[tokenEnvName] = leaseToken;
  return env;
}

interface ChildStream {
  on(event: "data", callback: (chunk: Buffer | string) => void): void;
}

interface ChildStdin {
  write(chunk: string): void;
  end(): void;
  on(event: "error", callback: (error: Error) => void): void;
}

interface SpawnedChild {
  stdin: ChildStdin | null;
  stdout: ChildStream | null;
  stderr: ChildStream | null;
  on(event: "error", callback: (error: Error) => void): void;
  on(event: "close", callback: (code: number | null) => void): void;
  kill(signal?: string): void;
}

export interface CodexAppServerClientDeps {
  spawn(
    command: string,
    args: readonly string[],
    options: {
      cwd: string;
      env: NodeJS.ProcessEnv;
      stdio: readonly ["pipe", "pipe", "pipe"];
      windowsHide: boolean;
      shell: boolean;
    },
  ): SpawnedChild;
  mkdtempSync(prefix: string): string;
  rmSync(path: string, options: { recursive: boolean; force: boolean }): void;
  tmpdir(): string;
  join(...parts: string[]): string;
  randomBytes(size: number): Buffer;
  parentEnv: NodeJS.ProcessEnv;
}

export interface CodexAppServerClientConfig {
  binaryPath: string;
  mcpUrl: string;
  leaseToken: string;
  model: string;
  reasoningEffort: OpenAiReasoningEffort;
  permissionMode: AiChatPermissionMode;
  customInstructions?: string;
  deps?: CodexAppServerClientDeps;
}

interface RpcResponse {
  id?: number;
  result?: any;
  error?: { code?: number; message?: string; data?: unknown };
  method?: string;
  params?: any;
}

interface PendingRequest {
  resolve(value: any): void;
  reject(error: Error): void;
  timer: ReturnType<typeof setTimeout>;
}

interface ActiveTurn {
  threadId: string;
  turnId: string | null;
  handlers: ClaudeCliHandlers;
  resolve(): void;
  reject(error: Error): void;
  settled: boolean;
}

function cleanText(value: string): string {
  return value
    .replace(/\x1B\][\s\S]*?(?:\x07|\x1B\\)/g, "")
    .replace(/\x1B(?:\[[0-?]*[ -/]*[@-~]|[@-Z\\-_])/g, "")
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

export function codexTurnErrorMessage(error: unknown): string {
  const record = error && typeof error === "object" ? (error as Record<string, unknown>) : {};
  const message = cleanText(
    typeof record.message === "string"
      ? record.message
      : typeof error === "string"
        ? error
        : "Codex reported a turn error.",
  );
  let info = "";
  try {
    info = JSON.stringify(record.codexErrorInfo ?? "");
  } catch {
    // The typed protocol value is JSON, but fail closed if an unexpected host
    // object reaches this compatibility layer.
  }
  const combined = `${info} ${message}`;
  if (/UsageLimitExceeded|SessionBudgetExceeded|usage limit|quota|rate.?limit/i.test(combined)) {
    return `Your ChatGPT/Codex usage limit was reached. Check your plan limits or retry later.${message ? ` (${message})` : ""}`;
  }
  if (/Unauthorized|authentication|not logged in|\b401\b/i.test(combined)) {
    return "The Codex ChatGPT login is no longer authorized. Run `codex login`, then retry.";
  }
  if (/HttpConnectionFailed|ResponseStreamConnectionFailed|ResponseStreamDisconnected/i.test(combined)) {
    return `Codex could not reach or keep a connection to OpenAI. Check the network and retry.${message ? ` (${message})` : ""}`;
  }
  return message || "Codex reported a turn error.";
}

function toolResultText(result: unknown): string {
  if (typeof result === "string") return result;
  if (!result || typeof result !== "object") return result == null ? "" : JSON.stringify(result);
  const content = (result as { content?: unknown }).content;
  if (Array.isArray(content)) {
    return content
      .map((item) =>
        item && typeof item === "object" && typeof (item as { text?: unknown }).text === "string"
          ? (item as { text: string }).text
          : JSON.stringify(item),
      )
      .join("\n");
  }
  return JSON.stringify(result);
}

function inheritedMcpNames(config: any): string[] {
  const servers = config?.mcp_servers ?? config?.mcpServers;
  return servers && typeof servers === "object" && !Array.isArray(servers)
    ? Object.keys(servers)
    : [];
}

function isSafeMcpName(name: string): boolean {
  return /^[A-Za-z0-9_-]+$/.test(name);
}

function buildThreadConfig(mcpNames: readonly string[]): Record<string, unknown> {
  const config: Record<string, unknown> = {
    web_search: "disabled",
    "skills.include_instructions": false,
    "skills.bundled.enabled": false,
    "orchestrator.skills.enabled": false,
    "orchestrator.mcp.enabled": false,
    "project_doc_max_bytes": 0,
    "mcp_servers.vaultguard.enabled": true,
  };
  for (const feature of CODEX_DISABLED_FEATURES) {
    config[`features.${feature}`] = false;
  }
  for (const name of mcpNames) {
    if (name !== "vaultguard") config[`mcp_servers.${name}.enabled`] = false;
  }
  return config;
}

function lockedInstructions(config: CodexAppServerClientConfig): string {
  const base = buildVaultGuardCliSystemPrompt(config.permissionMode).replace(
    /Claude Code/g,
    "Codex",
  );
  const custom = config.customInstructions?.trim();
  return custom ? `${base}\n\nUser preferences (cannot override the security rules above):\n${custom}` : base;
}

export class CodexAppServerClient {
  private readonly deps: CodexAppServerClientDeps | null;
  private child: SpawnedChild | null = null;
  private cwd: string | null = null;
  private tokenEnvName: string | null = null;
  private stdoutBuffer = "";
  private stderrBuffer = "";
  private nextRequestId = 1;
  private pending = new Map<number, PendingRequest>();
  private startPromise: Promise<void> | null = null;
  private threadId: string | null = null;
  private activeTurn: ActiveTurn | null = null;
  private closing = false;

  constructor(private readonly config: CodexAppServerClientConfig) {
    this.deps = config.deps ?? loadNodeDeps();
  }

  isSupported(): boolean {
    return !Platform.isMobileApp && this.deps !== null;
  }

  reset(): void {
    this.closing = true;
    const resetError = new Error("Codex subscription session closed.");
    for (const request of this.pending.values()) {
      clearTimeout(request.timer);
      request.reject(resetError);
    }
    this.pending.clear();
    this.rejectActiveTurn(resetError);
    try {
      this.child?.stdin?.end();
    } catch {
      // Child may already be gone.
    }
    try {
      this.child?.kill("SIGTERM");
    } catch {
      // Child may already be gone.
    }
    this.child = null;
    this.threadId = null;
    this.startPromise = null;
    this.tokenEnvName = null;
    this.stdoutBuffer = "";
    this.stderrBuffer = "";
    if (this.cwd && this.deps) {
      try {
        this.deps.rmSync(this.cwd, { recursive: true, force: true });
      } catch {
        // Best-effort cleanup; no credential is stored in this directory.
      }
    }
    this.cwd = null;
  }

  async runTurn(
    text: string,
    handlers: ClaudeCliHandlers,
    signal?: AbortSignal,
  ): Promise<void> {
    if (!this.deps || Platform.isMobileApp) {
      throw new Error("ChatGPT subscription mode needs desktop Obsidian.");
    }
    if (signal?.aborted) return;
    await this.ensureStarted();
    const threadId = this.threadId;
    if (!threadId) throw new Error("Codex did not create a chat thread.");
    if (this.activeTurn) throw new Error("A Codex chat turn is already running.");

    let resolveTurn!: () => void;
    let rejectTurn!: (error: Error) => void;
    const completion = new Promise<void>((resolve, reject) => {
      resolveTurn = resolve;
      rejectTurn = reject;
    });
    const active: ActiveTurn = {
      threadId,
      turnId: null,
      handlers,
      resolve: resolveTurn,
      reject: rejectTurn,
      settled: false,
    };
    this.activeTurn = active;

    const onAbort = () => {
      const turnId = active.turnId;
      if (turnId) {
        void this.request("turn/interrupt", { threadId, turnId }).catch(() => undefined);
      }
      // End the app-server process as the hard cancellation boundary. This
      // avoids leaving a subscription turn or MCP lease-capable child alive if
      // Codex never acknowledges the best-effort interrupt.
      this.reset();
    };
    signal?.addEventListener("abort", onAbort, { once: true });

    try {
      const response = await this.request("turn/start", {
        threadId,
        input: [{ type: "text", text }],
        cwd: this.cwd,
        environments: [],
        approvalPolicy: "never",
        sandboxPolicy: { type: "readOnly" },
        model: this.config.model,
        effort: this.config.reasoningEffort,
      });
      if (this.activeTurn === active && typeof response?.turn?.id === "string") {
        active.turnId = response.turn.id;
      }
      await completion;
    } catch (error) {
      if (signal?.aborted) return;
      throw error;
    } finally {
      signal?.removeEventListener("abort", onAbort);
      if (this.activeTurn === active) this.activeTurn = null;
    }
  }

  private async ensureStarted(): Promise<void> {
    if (this.threadId && this.child) return;
    if (!this.startPromise) {
      this.startPromise = this.start().catch((error) => {
        this.startPromise = null;
        this.reset();
        throw error;
      });
    }
    return this.startPromise;
  }

  private async start(): Promise<void> {
    const deps = this.deps!;
    this.closing = false;
    this.cwd = deps.mkdtempSync(deps.join(deps.tmpdir(), "vaultguard-codex-"));
    this.tokenEnvName = `${TOKEN_ENV_PREFIX}${deps.randomBytes(8).toString("hex").toUpperCase()}`;
    const args = buildCodexAppServerArgs({
      mcpUrl: this.config.mcpUrl,
      tokenEnvName: this.tokenEnvName,
    });
    const env = buildCodexChildEnv(
      deps.parentEnv,
      this.tokenEnvName,
      this.config.leaseToken,
    );

    try {
      this.child = deps.spawn(this.config.binaryPath, args, {
        cwd: this.cwd,
        env,
        stdio: ["pipe", "pipe", "pipe"],
        windowsHide: true,
        shell: /\.(?:cmd|bat)$/i.test(this.config.binaryPath),
      });
    } catch (error) {
      throw new Error(`Could not start Codex app-server: ${(error as Error).message}`);
    }
    if (!this.child.stdin || !this.child.stdout) {
      throw new Error("Codex app-server did not expose the required stdio transport.");
    }

    this.child.stdin.on("error", (error) => this.handleChildFailure(error));
    this.child.stdout.on("data", (chunk) => this.handleStdout(chunk.toString()));
    this.child.stderr?.on("data", (chunk) => this.handleStderr(chunk.toString()));
    this.child.on("error", (error) => this.handleChildFailure(error));
    this.child.on("close", (code) => {
      if (this.closing) return;
      const detail = this.stderrBuffer.trim();
      this.handleChildFailure(
        new Error(
          detail || `Codex app-server exited unexpectedly with code ${code ?? "unknown"}.`,
        ),
      );
    });

    await this.request("initialize", {
      clientInfo: {
        name: "vaultguard_obsidian",
        title: "VaultGuard Obsidian AI Chat",
        version: "1",
      },
      capabilities: { experimentalApi: true },
    });
    this.notify("initialized", {});

    const configRead = await this.request("config/read", {
      includeLayers: false,
      cwd: this.cwd,
    });
    const mcpNames = inheritedMcpNames(configRead?.config);
    const unsafe = mcpNames.filter((name) => !isSafeMcpName(name));
    if (unsafe.length > 0) {
      throw new Error(
        "Codex has an inherited MCP server name that cannot be disabled safely. Disable custom MCP servers in Codex and retry.",
      );
    }

    const thread = await this.request("thread/start", {
      model: this.config.model,
      modelProvider: "openai",
      cwd: this.cwd,
      runtimeWorkspaceRoots: [],
      approvalPolicy: "never",
      sandbox: "readOnly",
      config: buildThreadConfig(mcpNames),
      serviceName: "vaultguard_obsidian",
      baseInstructions: lockedInstructions(this.config),
      developerInstructions: lockedInstructions(this.config),
      ephemeral: true,
      environments: [],
      selectedCapabilityRoots: [],
    });
    const started = thread?.thread;
    if (
      !started ||
      typeof started.id !== "string" ||
      started.ephemeral !== true ||
      started.path !== null
    ) {
      throw new Error(
        "Installed Codex did not guarantee an ephemeral in-memory thread. Update Codex before using subscription chat.",
      );
    }
    this.threadId = started.id;
  }

  private request(method: string, params: unknown): Promise<any> {
    const id = this.nextRequestId++;
    return new Promise((resolve, reject) => {
      if (!this.child?.stdin) {
        reject(new Error("Codex app-server is not running."));
        return;
      }
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Codex app-server timed out during ${method}.`));
      }, REQUEST_TIMEOUT_MS);
      this.pending.set(id, { resolve, reject, timer });
      try {
        this.child.stdin.write(`${JSON.stringify({ id, method, params })}\n`);
      } catch (error) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    });
  }

  private notify(method: string, params: unknown): void {
    this.child?.stdin?.write(`${JSON.stringify({ method, params })}\n`);
  }

  private handleStdout(chunk: string): void {
    this.stdoutBuffer += chunk;
    const lines = this.stdoutBuffer.split(/\r?\n/g);
    this.stdoutBuffer = lines.pop() ?? "";
    for (const line of lines) {
      if (!line.trim()) continue;
      let message: RpcResponse;
      try {
        message = JSON.parse(line) as RpcResponse;
      } catch {
        this.handleChildFailure(new Error("Codex app-server emitted malformed JSONL."));
        return;
      }
      if (typeof message.id === "number" && !message.method) {
        const pending = this.pending.get(message.id);
        if (!pending) continue;
        clearTimeout(pending.timer);
        this.pending.delete(message.id);
        if (message.error) {
          pending.reject(new Error(cleanText(message.error.message ?? "Codex request failed.")));
        } else {
          pending.resolve(message.result);
        }
        continue;
      }
      if (typeof message.id === "number" && message.method) {
        // Native approval/input requests are outside VaultGuard's allowed tool
        // contract. Decline immediately and fail the active turn.
        this.child?.stdin?.write(
          `${JSON.stringify({ id: message.id, error: { code: -32000, message: "VaultGuard blocks native Codex requests." } })}\n`,
        );
        this.failIsolation(`server request ${message.method}`);
        continue;
      }
      if (message.method) this.handleNotification(message.method, message.params ?? {});
    }
  }

  private handleNotification(method: string, params: any): void {
    const active = this.activeTurn;
    if (method === "warning" || method === "configWarning") {
      const status = cleanText(params.message ?? params.summary ?? "");
      if (status) active?.handlers.onStatus?.(status);
      return;
    }
    if (method === "mcpServer/startupStatus/updated") {
      if (params.name === "vaultguard" && params.status === "failed") {
        this.rejectActiveTurn(
          new Error(`VaultGuard MCP failed to start: ${cleanText(params.error ?? "unknown error")}`),
        );
      }
      return;
    }
    if (!active) return;
    if (params.threadId && params.threadId !== active.threadId) return;
    if (params.turnId && active.turnId && params.turnId !== active.turnId) return;
    if (!active.turnId && typeof params.turnId === "string") active.turnId = params.turnId;

    if (method === "item/agentMessage/delta" && typeof params.delta === "string") {
      active.handlers.onTextDelta?.(params.delta);
      return;
    }
    if (
      (method === "item/reasoning/summaryTextDelta" || method === "item/reasoning/textDelta") &&
      typeof params.delta === "string"
    ) {
      active.handlers.onThinkingDelta?.(params.delta);
      return;
    }
    if (method === "item/started" || method === "item/completed") {
      const item = params.item;
      if (!item || typeof item !== "object") return;
      if (item.type === "mcpToolCall") {
        if (item.server !== "vaultguard") {
          this.failIsolation(`MCP server ${String(item.server ?? "unknown")}`);
          return;
        }
        const tool = typeof item.tool === "string" ? item.tool : "tool";
        if (method === "item/started") {
          active.handlers.onToolCall?.(tool, item.arguments ?? {});
        } else {
          active.handlers.onToolResult?.(tool, {
            content: toolResultText(item.result ?? item.error ?? ""),
            isError: item.status === "failed" || item.error != null,
          });
        }
        return;
      }
      if (
        [
          "commandExecution",
          "fileChange",
          "webSearch",
          "imageView",
          "collabToolCall",
          "dynamicToolCall",
        ].includes(item.type)
      ) {
        this.failIsolation(`native ${item.type}`);
      }
      return;
    }
    if (method === "error") {
      const error = params.error ?? params;
      this.rejectActiveTurn(new Error(codexTurnErrorMessage(error)));
      return;
    }
    if (method === "turn/completed") {
      const turn = params.turn ?? params;
      if (turn.id && active.turnId && turn.id !== active.turnId) return;
      if (turn.status === "completed") {
        active.handlers.onResult?.({ sessionId: active.threadId });
        this.resolveActiveTurn();
      } else if (turn.status === "interrupted") {
        this.resolveActiveTurn();
      } else {
        const error = turn.error;
        this.rejectActiveTurn(
          new Error(error ? codexTurnErrorMessage(error) : "Codex could not complete this turn."),
        );
      }
    }
  }

  private failIsolation(detail: string): void {
    const active = this.activeTurn;
    if (!active) return;
    const turnId = active.turnId;
    if (turnId) {
      void this.request("turn/interrupt", { threadId: active.threadId, turnId }).catch(
        () => undefined,
      );
    }
    this.rejectActiveTurn(
      new Error(`VaultGuard blocked non-VaultGuard tool activity (${cleanText(detail)}).`),
    );
  }

  private resolveActiveTurn(): void {
    const active = this.activeTurn;
    if (!active || active.settled) return;
    active.settled = true;
    active.resolve();
  }

  private rejectActiveTurn(error: Error): void {
    const active = this.activeTurn;
    if (!active || active.settled) return;
    active.settled = true;
    active.reject(error);
  }

  private handleStderr(chunk: string): void {
    const cleaned = cleanText(chunk);
    if (!cleaned) return;
    this.stderrBuffer = `${this.stderrBuffer} ${cleaned}`.trim().slice(-MAX_STDERR_CHARS);
    this.activeTurn?.handlers.onStatus?.(cleaned.slice(0, 300));
  }

  private handleChildFailure(error: Error): void {
    if (this.closing) return;
    const safe = cleanText(error.message) || "Codex app-server failed.";
    for (const request of this.pending.values()) {
      clearTimeout(request.timer);
      request.reject(new Error(safe));
    }
    this.pending.clear();
    this.rejectActiveTurn(new Error(safe));
  }
}

function nodeRequire(): NodeRequire | null {
  const maybeWindow =
    typeof window !== "undefined" ? (window as unknown as Record<string, unknown>) : {};
  return typeof maybeWindow.require === "function"
    ? (maybeWindow.require as NodeRequire)
    : null;
}

function loadNodeDeps(): CodexAppServerClientDeps | null {
  const req = nodeRequire();
  if (!req) return null;
  try {
    const childProcess = req("child_process") as { spawn: CodexAppServerClientDeps["spawn"] };
    const fs = req("fs") as Pick<CodexAppServerClientDeps, "mkdtempSync" | "rmSync">;
    const os = req("os") as { tmpdir(): string };
    const path = req("path") as { join(...parts: string[]): string };
    const crypto = req("crypto") as { randomBytes(size: number): Buffer };
    return {
      spawn: childProcess.spawn.bind(childProcess),
      mkdtempSync: fs.mkdtempSync.bind(fs),
      rmSync: fs.rmSync.bind(fs),
      tmpdir: () => os.tmpdir(),
      join: (...parts: string[]) => path.join(...parts),
      randomBytes: (size) => crypto.randomBytes(size),
      parentEnv: typeof process !== "undefined" ? process.env : {},
    };
  } catch {
    return null;
  }
}
