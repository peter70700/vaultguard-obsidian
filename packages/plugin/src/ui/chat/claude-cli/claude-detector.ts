// Claude Code CLI detection (AI Chat "subscription" provider — docs/AI-CHAT-PANEL.md
// "Auth & providers"). This module lets the plugin tell, at a glance, whether the
// official `claude` binary is installed and whether the user is signed in with a
// Claude.ai subscription (Pro/Max) — WITHOUT the plugin ever touching the user's
// OAuth/subscription token.
//
// SECURITY BOUNDARY: the only things this module does are
//   (a) locate the `claude` binary on PATH / common install dirs,
//   (b) run `claude auth status --json` and parse the result, and
//   (c) answer "does a `claude` binary appear to be installed?" WITHOUT running
//       anything (`claudeBinaryLikelyInstalled` — pure fs.existsSync).
// It NEVER reads, stores, logs, or transmits a token; the spawned `claude`
// authenticates itself from its own keychain. No fs access beyond `which`-style
// PATH resolution. Desktop-only — `child_process` does not exist in the mobile
// (web) Obsidian runtime, so on mobile every call returns "unsupported".
//
// (a) and (b) SPAWN, so they are strictly user-triggered (SD-13-F1): sending a
// message, or explicitly opting into the subscription provider. (c) spawns
// nothing, so it is the only probe safe to run as a side effect of opening the
// chat panel — it cannot execute an attacker-planted binary, which was the whole
// exploitation trigger SD-13-F1 closed.
//
// The parse function `parseAuthStatus` is pure and exhaustively unit-tested with
// fake JSON (valid subscription, API-key login, logged-out, malformed, exit-1).

import { Platform } from "obsidian";

const LOG_PREFIX = "[VaultGuard Chat]";

// Short timeout — `claude auth status` is a local keychain read; if it hangs,
// something is wrong and we don't want to block the settings UI.
const AUTH_STATUS_TIMEOUT_MS = 8_000;

// Common locations the `claude` binary lands in when `which` isn't enough
// (e.g. GUI-launched Obsidian inheriting a minimal PATH). Order matters: the
// first existing match wins.
const COMMON_CLAUDE_PATHS: ReadonlyArray<string> = [
  "/opt/homebrew/bin/claude",
  "/usr/local/bin/claude",
  "/usr/bin/claude",
];

// Home-relative install locations used by the native installer and the common
// package managers. Kept separate from COMMON_CLAUDE_PATHS because they need the
// home directory resolved at call time.
const HOME_RELATIVE_CLAUDE_PATHS: ReadonlyArray<string> = [
  ".claude/local/claude",
  ".local/bin/claude",
  ".bun/bin/claude",
  ".npm-global/bin/claude",
];

// ─── Result shapes ───────────────────────────────────────────────────────────

export type ClaudeAuthClassification =
  | "unsupported" // mobile / no child_process
  | "not-installed" // binary not found on PATH or common paths
  | "not-logged-in" // installed, but `claude auth status` says not signed in
  | "logged-in-subscription" // signed in via claude.ai (Pro/Max) — what we want
  | "logged-in-apikey" // signed in, but with an API key, not a subscription
  | "error"; // ran the command but couldn't classify (parse/exec failure)

export interface ClaudeAuthStatus {
  classification: ClaudeAuthClassification;
  installed: boolean;
  loggedIn: boolean;
  isSubscription: boolean;
  /** "max" | "pro" | ... when present in the CLI output. */
  subscriptionType?: string;
  email?: string;
  /** Absolute path the binary was resolved to (when installed). */
  binaryPath?: string;
  /** Human-readable failure reason; only set for the "error" classification. */
  error?: string;
}

// The subset of `claude auth status --json` fields we read. The CLI may add
// more; we tolerate unknown keys.
export interface ClaudeAuthStatusJson {
  loggedIn?: boolean;
  authMethod?: string; // "claude.ai" ⇒ subscription
  apiProvider?: string; // "firstParty" for subscription/Anthropic-direct
  subscriptionType?: string; // "max" | "pro" | ...
  email?: string;
  orgName?: string;
}

// ─── Node child_process resolution (desktop-only) ────────────────────────────

interface ChildProcessModule {
  execFile(
    file: string,
    args: ReadonlyArray<string>,
    options: { timeout?: number; encoding?: "utf8" },
    callback: (
      error: (Error & { code?: number | string }) | null,
      stdout: string,
      stderr: string,
    ) => void,
  ): unknown;
}

interface FsModule {
  existsSync(path: string): boolean;
}

// Resolve Node modules via Electron's require. Returns null on mobile / web
// runtimes (no `require`), which is exactly where subscription mode is
// unsupported. Mirrors the resolution pattern in main.ts getSkillInstallerDeps.
function nodeRequire(): NodeRequire | null {
  const maybeWindow =
    typeof window !== "undefined" ? (window as unknown as Record<string, unknown>) : {};
  if (typeof maybeWindow.require === "function") return maybeWindow.require as NodeRequire;
  return null;
}

interface DetectorDeps {
  childProcess: ChildProcessModule;
  fs: FsModule;
}

function loadDeps(): DetectorDeps | null {
  const req = nodeRequire();
  if (!req) return null;
  try {
    return {
      childProcess: req("child_process") as ChildProcessModule,
      fs: req("fs") as FsModule,
    };
  } catch {
    return null;
  }
}

// ─── Pure parser (unit-tested) ───────────────────────────────────────────────

/**
 * Classify the result of `claude auth status --json` into a ClaudeAuthStatus.
 * Pure: takes the raw exit/stdout/stderr (already captured by the caller) and
 * returns a classification. Never spawns anything, never touches a token.
 *
 * Subscription ⇔ loggedIn && authMethod === "claude.ai" (a subscriptionType
 * is then present). Any logged-in state that is NOT claude.ai is treated as an
 * API-key login (the CLI still works, but it spends per-token credit — not the
 * subscription path this provider exists for).
 */
export function parseAuthStatus(
  exitCode: number | string | null,
  stdout: string,
  stderr: string,
  binaryPath?: string,
): ClaudeAuthStatus {
  const base: Pick<ClaudeAuthStatus, "installed" | "binaryPath"> = {
    installed: true,
    binaryPath,
  };

  // Non-zero exit with no parseable JSON ⇒ either logged out or an error. The
  // CLI exits 0 when logged in; a clean "not logged in" can surface either as
  // exit 0 with {loggedIn:false} or a non-zero exit. Try to parse first.
  let json: ClaudeAuthStatusJson | null = null;
  const trimmed = (stdout ?? "").trim();
  if (trimmed) {
    try {
      json = JSON.parse(trimmed) as ClaudeAuthStatusJson;
    } catch {
      json = null;
    }
  }

  if (!json) {
    // Couldn't parse JSON. A non-zero exit here means "not logged in" in the
    // common numeric-exit case (the CLI prints a human message to stderr).
    // String codes such as ETIMEDOUT are execution failures, not login state.
    if (exitCode !== 0 && exitCode !== null) {
      if (typeof exitCode !== "number") {
        return {
          ...base,
          classification: "error",
          loggedIn: false,
          isSubscription: false,
          error:
            (stderr ?? "").trim() ||
            `Could not run \`claude auth status --json\` (${String(exitCode)}).`,
        };
      }
      return {
        ...base,
        classification: "not-logged-in",
        loggedIn: false,
        isSubscription: false,
      };
    }
    return {
      ...base,
      classification: "error",
      loggedIn: false,
      isSubscription: false,
      error:
        (stderr ?? "").trim() ||
        "Could not parse `claude auth status --json` output.",
    };
  }

  const loggedIn = json.loggedIn === true;
  if (!loggedIn) {
    return {
      ...base,
      classification: "not-logged-in",
      loggedIn: false,
      isSubscription: false,
      email: json.email,
    };
  }

  const isSubscription = json.authMethod === "claude.ai";
  return {
    ...base,
    classification: isSubscription ? "logged-in-subscription" : "logged-in-apikey",
    loggedIn: true,
    isSubscription,
    subscriptionType: json.subscriptionType,
    email: json.email,
  };
}

// ─── Binary resolution + live detection ──────────────────────────────────────

/** Deps for the no-spawn presence probe. `homeDir` is a test seam. */
export interface ClaudePresenceDeps {
  fs: FsModule;
  /** Explicit home directory; omit to resolve from the environment. */
  homeDir?: string | null;
}

function resolveHomeDir(): string | null {
  if (typeof process === "undefined") return null;
  return process.env?.HOME || process.env?.USERPROFILE || null;
}

/**
 * Does a `claude` binary appear to be installed? SPAWNS NOTHING — this is a
 * pure `fs.existsSync` sweep over the known install locations, so it is the one
 * Claude Code probe that is safe to run without a user action (SD-13-F1: the
 * finding was the drive-by *execution* of a PATH-resolved binary, which this
 * cannot do). It deliberately does NOT consult PATH, because resolving PATH
 * means spawning `which`.
 *
 * A `true` result means "Claude Code is probably installed", NOT "signed in" —
 * login state still requires the real, user-triggered `getClaudeAuthStatus()`.
 * A `false` result is a hint, not proof: a PATH-only install (nvm, a custom
 * prefix, Windows) reads as absent, which is why the chat panel also offers an
 * explicit "Use my Claude subscription" action that runs the full detector.
 *
 * Desktop-only — returns false on mobile and when the Node bridge is absent.
 */
export function claudeBinaryLikelyInstalled(deps?: ClaudePresenceDeps): boolean {
  if (Platform.isMobileApp) return false;
  const fs = deps?.fs ?? loadDeps()?.fs;
  if (!fs) return false;

  const homeDir = deps && "homeDir" in deps ? deps.homeDir : resolveHomeDir();
  const homeCandidates = homeDir
    ? HOME_RELATIVE_CLAUDE_PATHS.map((rel) => `${homeDir.replace(/[/\\]+$/, "")}/${rel}`)
    : [];

  for (const candidate of [...COMMON_CLAUDE_PATHS, ...homeCandidates]) {
    try {
      if (fs.existsSync(candidate)) return true;
    } catch {
      // Unreadable path — keep trying the rest.
    }
  }
  return false;
}

/**
 * Locate the `claude` binary. Tries `which claude` (PATH) first, then a small
 * set of common install dirs (GUI-launched apps often inherit a stripped PATH).
 * Returns the absolute path or null. Desktop-only — returns null on mobile.
 */
export function findClaudeBinary(deps?: DetectorDeps): Promise<string | null> {
  if (Platform.isMobileApp) return Promise.resolve(null);
  const d = deps ?? loadDeps();
  if (!d) return Promise.resolve(null);

  return new Promise((resolve) => {
    // `which` on POSIX, `where` on Windows. Obsidian desktop runs on all three;
    // keep it simple and prefer `which`, falling back to common paths.
    const whichCmd = process.platform === "win32" ? "where" : "which";
    d.childProcess.execFile(
      whichCmd,
      ["claude"],
      { timeout: AUTH_STATUS_TIMEOUT_MS, encoding: "utf8" },
      (error, stdout) => {
        const fromWhich = (stdout ?? "").split(/\r?\n/).map((s) => s.trim()).find(Boolean);
        if (!error && fromWhich) {
          resolve(fromWhich);
          return;
        }
        // Fall back to common install locations.
        for (const candidate of COMMON_CLAUDE_PATHS) {
          try {
            if (d.fs.existsSync(candidate)) {
              resolve(candidate);
              return;
            }
          } catch {
            // ignore and keep trying
          }
        }
        resolve(null);
      },
    );
  });
}

/**
 * Run `claude auth status --json` and return a classified status. Locates the
 * binary first (so a not-installed state is distinguishable from a logged-out
 * one). Desktop-only: returns the "unsupported" classification on mobile.
 *
 * NEVER touches a token — only reads the status JSON the CLI prints.
 */
export async function getClaudeAuthStatus(deps?: DetectorDeps): Promise<ClaudeAuthStatus> {
  if (Platform.isMobileApp) {
    return {
      classification: "unsupported",
      installed: false,
      loggedIn: false,
      isSubscription: false,
      error: "Claude Code subscription mode needs desktop Obsidian.",
    };
  }

  const d = deps ?? loadDeps();
  if (!d) {
    return {
      classification: "unsupported",
      installed: false,
      loggedIn: false,
      isSubscription: false,
      error: "Node child_process is unavailable in this runtime.",
    };
  }

  const binaryPath = await findClaudeBinary(d);
  if (!binaryPath) {
    return {
      classification: "not-installed",
      installed: false,
      loggedIn: false,
      isSubscription: false,
    };
  }

  return new Promise<ClaudeAuthStatus>((resolve) => {
    d.childProcess.execFile(
      binaryPath,
      ["auth", "status", "--json"],
      { timeout: AUTH_STATUS_TIMEOUT_MS, encoding: "utf8" },
      (error, stdout, stderr) => {
        const exitCode = error?.code ?? 0;
        try {
          resolve(parseAuthStatus(exitCode, stdout, stderr, binaryPath));
        } catch (e) {
          console.warn(`${LOG_PREFIX} Failed to classify claude auth status`, e);
          resolve({
            classification: "error",
            installed: true,
            binaryPath,
            loggedIn: false,
            isSubscription: false,
            error: (e as Error).message,
          });
        }
      },
    );
  });
}
