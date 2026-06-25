/**
 * SyncDiagnostics — a pure, obsidian-free breadcrumb recorder for the plugin's
 * startup / sync control flow.
 *
 * The class is the unit-testable core: it only depends on `Date` and never
 * imports from "obsidian", never touches the clipboard, console, or the plugin.
 * `src/plugin/main.ts` owns all side effects (clipboard write, console.log,
 * Notice) and is the single gate that decides what state/detail is safe to
 * record — this helper is deliberately dumb and renders only what it is given.
 *
 * Bounded ring buffer: at most SYNC_DIAG_MAX_ENTRIES breadcrumbs are kept; the
 * oldest are dropped first, so a long-running session can never grow memory
 * without bound (DX4-DIAG / T-dx4-04).
 */

/** Max breadcrumbs retained in the ring buffer; oldest dropped first. */
export const SYNC_DIAG_MAX_ENTRIES = 64;

export interface SyncDiagEntry {
  /** ISO timestamp (`new Date().toISOString()`) of when the event was recorded. */
  t: string;
  /** Stable event name passed to record(). */
  event: string;
  /** Optional whitelisted detail payload (booleans / counts / IDs / enum strings). */
  detail?: Record<string, unknown>;
}

export class SyncDiagnostics {
  private entries: SyncDiagEntry[] = [];

  /**
   * Append a breadcrumb. No debugLogging gate inside the class. Never throws —
   * it is a pure data push. If the buffer exceeds the cap, the oldest entries
   * are dropped so it stays bounded.
   *
   * Production no-op (260625-gg7): in a PRODUCTION build the ring buffer is never
   * populated — the only reader (the "Copy sync diagnostics" command in main.ts)
   * is dead-code-eliminated from the shipped bundle, so recording would be wasted
   * work. esbuild substitutes the `process.env.NODE_ENV` literal; vitest
   * (NODE_ENV != "production") and dev builds keep recording so tests still
   * exercise the buffer.
   */
  record(event: string, detail?: Record<string, unknown>): void {
    // Dev-only: never populate the ring buffer in production builds (the
    // copy-diagnostics command is DCE-stripped there). esbuild substitutes the
    // NODE_ENV literal; vitest (NODE_ENV != production) keeps recording so tests
    // still exercise the buffer.
    if (process.env.NODE_ENV === "production") return;

    this.entries.push({
      t: new Date().toISOString(),
      event,
      ...(detail ? { detail } : {}),
    });

    const overflow = this.entries.length - SYNC_DIAG_MAX_ENTRIES;
    if (overflow > 0) {
      this.entries.splice(0, overflow);
    }
  }

  /** Drop all recorded breadcrumbs. */
  clear(): void {
    this.entries = [];
  }

  /** Number of breadcrumbs currently retained (for tests / introspection). */
  get size(): number {
    return this.entries.length;
  }

  /** Read-only copy of the current breadcrumbs (for tests / introspection). */
  snapshot(): SyncDiagEntry[] {
    return this.entries.map((entry) => ({ ...entry }));
  }

  /**
   * Produce a deterministic, copy-pasteable multi-line report:
   *   1. a header line,
   *   2. a "State" section — one `key: value` line per entry in `state`
   *      (insertion order preserved; null/undefined render as `—`),
   *   3. a "Breadcrumbs (N)" section — one line per recorded entry in
   *      chronological order: absolute ISO `t`, a relative-to-first millisecond
   *      delta (first = `+0ms`), the event name, and compact JSON of `detail`
   *      when present.
   *
   * The caller (main.ts) is responsible for passing only secret-free state —
   * this method renders verbatim whatever it receives.
   */
  buildReport(state: Record<string, unknown>): string {
    const lines: string[] = [];

    lines.push("=== VaultGuard sync diagnostics ===");

    lines.push("State");
    for (const [key, value] of Object.entries(state)) {
      lines.push(`  ${key}: ${formatStateValue(value)}`);
    }

    lines.push(`Breadcrumbs (${this.entries.length})`);
    const baseMs = this.entries.length > 0 ? Date.parse(this.entries[0].t) : 0;
    for (const entry of this.entries) {
      const deltaMs = Date.parse(entry.t) - baseMs;
      const detailStr = entry.detail ? ` ${JSON.stringify(entry.detail)}` : "";
      lines.push(`  ${entry.t} (+${deltaMs}ms) ${entry.event}${detailStr}`);
    }

    return lines.join("\n");
  }
}

function formatStateValue(value: unknown): string {
  if (value === null || value === undefined) {
    return "—";
  }
  return String(value);
}
