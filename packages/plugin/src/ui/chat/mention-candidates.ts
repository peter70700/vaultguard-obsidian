import { PermissionLevel } from "../../types";
import type { MentionCandidate } from "./input-controller";

/**
 * Permission-gated candidate resolution for the AI chat `@`-mention picker
 * (SD-13-F5).
 *
 * The picker is an *enumeration* surface: rendering a path in the popup — or
 * inserting it as `[[path]]` into provider-bound conversation context — is
 * itself the disclosure. A later `vaultguard_read` denial cannot retract a
 * filename the user has already seen. Candidates therefore gate on the same
 * per-path predicate the Agent Bridge list/read surface gates on, and an
 * unresolved path simply does not appear.
 *
 * This module is deliberately pure: no Obsidian API, no plugin class, no
 * network. The only value-level import is the `PermissionLevel` enum; the
 * `MentionCandidate` import is type-only and therefore erased at build time.
 * That is what lets a bare node-env vitest drive it with plain object stubs.
 */

/** Hard ceiling on permission evaluations per query (bounded work per keystroke). */
export const MENTION_MAX_PERMISSION_CHECKS = 200;

export interface MentionFileEntry {
  path: string;
  basename: string;
}

export interface MentionAccessContext {
  /** Same value the bridge list/read surface gates on. */
  getPermission(path: string): Promise<PermissionLevel>;
  /** V1–V4: the non-lease part of the bridge's `isPathAgentReadable`. */
  isPathVisible(path: string): boolean;
  /** V5: metadata side-channel guard (narrowing divergence D3). */
  isMetadataSuppressed(path: string): boolean;
}

export interface MentionCandidatesOptions {
  limit: number;
  maxChecks?: number;
}

export interface MentionCandidatesResult {
  candidates: MentionCandidate[];
  /** Number of permission evaluations actually performed. */
  checked: number;
  /** True when `maxChecks` stopped the walk before `limit` was filled. */
  capped: boolean;
  /** First error thrown by `getPermission`, if any (caller logs once). */
  error: unknown;
  /** How many paths were dropped because evaluation threw. */
  errorCount: number;
}

/**
 * Rank the vault's files for `query`, then return the highest-ranked ones the
 * user may actually read.
 *
 * The visibility rule (§3.4 of the SD-13-F5 remediation plan) — a path is shown
 * iff ALL hold:
 *
 *   V1  it normalizes to a non-empty vault-relative path
 *   V2  it contains no `..` segment anywhere
 *   V3  its first segment does not start with `.`
 *   V4  it is not an excluded (local-only) path
 *   V5  it is not metadata-suppressed
 *   V6  its permission is >= READ
 *
 * V1–V4 are supplied by `access.isPathVisible` (the non-lease part of the
 * bridge's `isPathAgentReadable`). V6 comes through `access.getPermission`, the
 * same function object the bridge gates on, so the two surfaces cannot drift.
 *
 * Deliberate divergences from the bridge list — each NARROWS, none widens:
 *   D1/D2  no lease-scope / `allowRead` check: the picker has no lease at
 *          typing time. Lease scopes narrow an agent's reach *below* the
 *          user's own authorization; the picker only ever shows paths the
 *          user may read, so omitting them cannot widen access.
 *   D3     the picker additionally applies V5, which the bridge list does not.
 *          SD-13-F5 is a metadata-disclosure finding and this is the documented
 *          metadata side-channel guard, so honouring it is strictly narrower.
 *   D4     Local Project Memory Mode inherits the bridge's WRITE short circuit
 *          via `resolveAgentPermission`. Skipping it would deny every path in
 *          that mode while the bridge grants WRITE to everything.
 *
 * Fail-closed everywhere: an unknown permission has already collapsed to NONE
 * by the time it reaches here (`permission-store.ts:204-207`), a throwing
 * evaluation excludes only that path, and the tail beyond `maxChecks` is
 * DROPPED rather than emitted unchecked.
 */
export async function resolveMentionCandidates(
  files: MentionFileEntry[],
  query: string,
  access: MentionAccessContext,
  options: MentionCandidatesOptions,
): Promise<MentionCandidatesResult> {
  const result: MentionCandidatesResult = {
    candidates: [],
    checked: 0,
    capped: false,
    error: undefined,
    errorCount: 0,
  };

  const limit = options.limit;
  const maxChecks = options.maxChecks ?? MENTION_MAX_PERMISSION_CHECKS;
  if (limit <= 0 || maxChecks <= 0) return result;

  const q = query.toLowerCase();

  // Ranking preserved verbatim from the pre-fix picker so the ALLOWED set
  // orders exactly as it always has. Do not renumber these ranks or change the
  // tie-break: only the denied entries disappear.
  const ranked = files
    .map((entry) => {
      const name = entry.basename.toLowerCase();
      const path = entry.path.toLowerCase();
      let rank = -1;
      if (!q) rank = 2;
      else if (name.startsWith(q)) rank = 0;
      else if (name.includes(q)) rank = 1;
      else if (path.includes(q)) rank = 2;
      return { entry, rank };
    })
    .filter((e) => e.rank >= 0)
    // Cheap synchronous pre-filter before any await: these cost nothing and
    // shrink the async walk (and the per-keystroke check budget it spends).
    .filter((e) => access.isPathVisible(e.entry.path))
    .filter((e) => !access.isMetadataSuppressed(e.entry.path))
    .sort(
      (a, b) => a.rank - b.rank || a.entry.basename.localeCompare(b.entry.basename),
    );

  for (const { entry } of ranked) {
    if (result.checked >= maxChecks) {
      // Budget exhausted. Everything past this point is UNVERIFIED, so it is
      // dropped rather than emitted — backfilling here would reintroduce the
      // exact disclosure this function exists to prevent.
      result.capped = true;
      break;
    }
    result.checked += 1;

    let level: PermissionLevel;
    try {
      level = await access.getPermission(entry.path);
    } catch (err) {
      // One broken path must never suppress the whole picker; it is excluded
      // and the caller logs once.
      if (result.error === undefined) result.error = err;
      result.errorCount += 1;
      continue;
    }

    if (level < PermissionLevel.READ) continue;

    result.candidates.push({ path: entry.path, name: entry.basename });
    if (result.candidates.length >= limit) break;
  }

  return result;
}
