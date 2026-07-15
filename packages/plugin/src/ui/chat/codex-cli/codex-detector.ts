// Official Codex client detection for the desktop ChatGPT-subscription
// provider. VaultGuard runs only `codex --version` and `codex login status`;
// it never reads CODEX_HOME, auth.json, keychain entries, or token output.

import { Platform } from "obsidian";

export type CodexAuthClassification =
  | "logged-in-chatgpt"
  | "logged-in-other"
  | "not-logged-in"
  | "not-installed"
  | "unsupported"
  | "error";

export interface CodexAuthStatus {
  classification: CodexAuthClassification;
  installed: boolean;
  loggedIn: boolean;
  isChatGptSubscription: boolean;
  binaryPath?: string;
  version?: string;
  authMode?: "chatgpt" | "api-key" | "access-token" | "other";
  error?: string;
}

export interface CodexRunResult {
  exitCode: number | null;
  stdout: string;
  stderr: string;
}

export interface CodexDetectorDeps {
  isMobile: boolean;
  env: NodeJS.ProcessEnv;
  candidatePaths(): Promise<string[]>;
  run(
    binaryPath: string,
    args: readonly string[],
    options: { timeoutMs: number; maxBuffer: number; signal?: AbortSignal },
  ): Promise<CodexRunResult>;
}

const CHECK_TIMEOUT_MS = 5_000;
const CHECK_MAX_BUFFER = 64 * 1024;
const CONTROL_RE = /[\u0000-\u001F\u007F]/g;

function cleanDiagnostic(value: string): string {
  return value
    .replace(CONTROL_RE, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 400);
}

function cancelledError(): Error {
  const error = new Error("Codex readiness check cancelled.");
  error.name = "AbortError";
  return error;
}

export function classifyCodexLoginStatus(
  output: string,
  exitCode: number | null,
): Omit<CodexAuthStatus, "installed" | "binaryPath" | "version"> {
  const text = cleanDiagnostic(output);
  if (/logged in using chatgpt/i.test(text)) {
    return {
      classification: "logged-in-chatgpt",
      loggedIn: true,
      isChatGptSubscription: true,
      authMode: "chatgpt",
    };
  }
  if (/logged in using an api key/i.test(text)) {
    return {
      classification: "logged-in-other",
      loggedIn: true,
      isChatGptSubscription: false,
      authMode: "api-key",
    };
  }
  if (/logged in using (?:an )?access token/i.test(text)) {
    return {
      classification: "logged-in-other",
      loggedIn: true,
      isChatGptSubscription: false,
      authMode: "access-token",
    };
  }
  if (/logged in using/i.test(text)) {
    return {
      classification: "logged-in-other",
      loggedIn: true,
      isChatGptSubscription: false,
      authMode: "other",
    };
  }
  if (/not logged in/i.test(text)) {
    return {
      classification: "not-logged-in",
      loggedIn: false,
      isChatGptSubscription: false,
    };
  }
  return {
    classification: "error",
    loggedIn: false,
    isChatGptSubscription: false,
    error:
      exitCode === 0
        ? "Codex returned an unrecognized login status. Update the official Codex client and retry."
        : "Codex could not verify the current login. Run `codex login` and retry.",
  };
}

function parseVersion(output: string): string | undefined {
  const match = cleanDiagnostic(output).match(/(?:codex(?:-cli)?\s+)?v?(\d+\.\d+\.\d+(?:[-+][\w.-]+)?)/i);
  return match?.[1];
}

export async function findCodexBinary(
  deps: CodexDetectorDeps = loadDetectorDeps(),
  signal?: AbortSignal,
): Promise<{ binaryPath: string; version?: string } | null> {
  if (deps.isMobile) return null;
  if (signal?.aborted) throw cancelledError();
  const candidates = await deps.candidatePaths();
  for (const binaryPath of candidates) {
    if (signal?.aborted) throw cancelledError();
    try {
      const result = await deps.run(binaryPath, ["--version"], {
        timeoutMs: CHECK_TIMEOUT_MS,
        maxBuffer: CHECK_MAX_BUFFER,
        signal,
      });
      if (result.exitCode === 0) {
        return {
          binaryPath,
          version: parseVersion(`${result.stdout}\n${result.stderr}`),
        };
      }
    } catch {
      if (signal?.aborted) throw cancelledError();
      // PATH aliases can exist without being executable (notably Windows Store
      // aliases). Continue to the next absolute candidate.
    }
  }
  return null;
}

export async function getCodexAuthStatus(
  deps: CodexDetectorDeps = loadDetectorDeps(),
  signal?: AbortSignal,
): Promise<CodexAuthStatus> {
  if (deps.isMobile) {
    return {
      classification: "unsupported",
      installed: false,
      loggedIn: false,
      isChatGptSubscription: false,
      error: "ChatGPT subscription chat needs desktop Obsidian.",
    };
  }

  const found = await findCodexBinary(deps, signal);
  if (!found) {
    return {
      classification: "not-installed",
      installed: false,
      loggedIn: false,
      isChatGptSubscription: false,
      error: "Official Codex client not found.",
    };
  }

  try {
    const result = await deps.run(found.binaryPath, ["login", "status"], {
      timeoutMs: CHECK_TIMEOUT_MS,
      maxBuffer: CHECK_MAX_BUFFER,
      signal,
    });
    const classified = classifyCodexLoginStatus(
      `${result.stdout}\n${result.stderr}`,
      result.exitCode,
    );
    return {
      ...classified,
      installed: true,
      binaryPath: found.binaryPath,
      version: found.version,
    };
  } catch (error) {
    if (signal?.aborted || (error instanceof Error && error.name === "AbortError")) {
      throw cancelledError();
    }
    const raw = error instanceof Error ? error.message : String(error);
    const timedOut = /timed?\s*out|timeout|ETIMEDOUT/i.test(raw);
    return {
      classification: "error",
      installed: true,
      loggedIn: false,
      isChatGptSubscription: false,
      binaryPath: found.binaryPath,
      version: found.version,
      error: timedOut
        ? "Codex login status timed out. Close other Codex prompts and retry."
        : `Could not check Codex login: ${cleanDiagnostic(raw)}`,
    };
  }
}

function nodeRequire(): NodeRequire | null {
  const maybeWindow =
    typeof window !== "undefined" ? (window as unknown as Record<string, unknown>) : {};
  return typeof maybeWindow.require === "function"
    ? (maybeWindow.require as NodeRequire)
    : null;
}

function loadDetectorDeps(): CodexDetectorDeps {
  const req = nodeRequire();
  if (!req) {
    return {
      isMobile: Platform.isMobileApp,
      env: {},
      candidatePaths: async () => [],
      run: async () => {
        throw new Error("Node child_process is unavailable in this runtime.");
      },
    };
  }

  const childProcess = req("child_process") as {
    execFile(
      file: string,
      args: readonly string[],
      options: {
        timeout: number;
        maxBuffer: number;
        windowsHide: boolean;
        env: NodeJS.ProcessEnv;
        shell?: boolean;
      },
      callback: (error: Error & { code?: number | string }, stdout: string, stderr: string) => void,
    ): { kill(signal?: string): void };
  };
  const path = req("path") as { join(...parts: string[]): string };
  const os = req("os") as { homedir(): string };
  const env = typeof process !== "undefined" ? process.env : {};

  const run: CodexDetectorDeps["run"] = (binaryPath, args, options) =>
    new Promise((resolve, reject) => {
      let settled = false;
      let child: { kill(signal?: string): void } | null = null;
      const finish = (callback: () => void) => {
        if (settled) return;
        settled = true;
        options.signal?.removeEventListener("abort", onAbort);
        callback();
      };
      const onAbort = () => {
        try {
          child?.kill("SIGTERM");
        } catch {
          // The bounded exec may already have exited.
        }
        finish(() => reject(cancelledError()));
      };
      child = childProcess.execFile(
        binaryPath,
        args,
        {
          timeout: options.timeoutMs,
          maxBuffer: options.maxBuffer,
          windowsHide: true,
          env,
          shell: /\.(?:cmd|bat)$/i.test(binaryPath),
        },
        (error, stdout, stderr) => {
          if (error && typeof error.code !== "number") {
            finish(() => reject(error));
            return;
          }
          finish(() =>
            resolve({
              exitCode: error && typeof error.code === "number" ? error.code : 0,
              stdout: stdout ?? "",
              stderr: stderr ?? "",
            }),
          );
        },
      );
      options.signal?.addEventListener("abort", onAbort, { once: true });
      if (options.signal?.aborted) onAbort();
    });

  return {
    isMobile: Platform.isMobileApp,
    env,
    candidatePaths: async () => {
      const candidates: string[] = [];
      const pathLookup = process.platform === "win32" ? "where.exe" : "which";
      try {
        const lookup = await run(pathLookup, process.platform === "win32" ? ["codex"] : ["-a", "codex"], {
          timeoutMs: CHECK_TIMEOUT_MS,
          maxBuffer: CHECK_MAX_BUFFER,
        });
        candidates.push(...`${lookup.stdout}\n${lookup.stderr}`.split(/\r?\n/g));
      } catch {
        // Common absolute paths below remain available as fallbacks.
      }

      const home = os.homedir();
      if (env.APPDATA) {
        candidates.push(path.join(env.APPDATA, "npm", "codex.exe"));
        candidates.push(path.join(env.APPDATA, "npm", "codex.cmd"));
      }
      if (env.LOCALAPPDATA) {
        candidates.push(path.join(env.LOCALAPPDATA, "Microsoft", "WindowsApps", "codex.exe"));
      }
      candidates.push(
        "/usr/local/bin/codex",
        "/opt/homebrew/bin/codex",
        path.join(home, ".local", "bin", "codex"),
        path.join(home, ".npm-global", "bin", "codex"),
      );

      const seen = new Set<string>();
      return candidates
        .map((candidate) => candidate.trim())
        .filter((candidate) => candidate.length > 0)
        .filter((candidate) => {
          const key = process.platform === "win32" ? candidate.toLowerCase() : candidate;
          if (seen.has(key)) return false;
          seen.add(key);
          return true;
        });
    },
    run,
  };
}
