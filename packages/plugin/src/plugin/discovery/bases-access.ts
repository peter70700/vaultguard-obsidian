import type { PathAccessSummary } from "../../api/client";
import { PermissionLevel } from "../../types";
import type { PermissionDecision } from "../permission-store";
import { normalizeVaultRelativePath } from "./search-model";

export type BasesAccessLevel = "read" | "write" | "admin";
export type BasesAccessProvenance = "verified" | "cached";

export interface BasesAccessRow {
  path: string;
  level: BasesAccessLevel;
  provenance: BasesAccessProvenance;
  generation: number;
}

export interface BasesAccessResult {
  rows: BasesAccessRow[];
  omitted: number;
  unverified: number;
  truncated: boolean;
  cancelled: boolean;
}

export interface BasesAccessContext {
  getBatchPathAccess(paths: string[]): Promise<PathAccessSummary[]>;
  peekPermissionDecision(path: string): PermissionDecision;
  isMetadataSuppressed(path: string): boolean;
  isPathExcluded(path: string): boolean;
  isGenerationCurrent(generation: number): boolean;
  yieldControl(): Promise<void>;
}

export interface ResolveBasesAccessOptions {
  generation: number;
  maxRows: number;
}

const BATCH_LIMIT = 100;

function fromServerLevel(value: unknown): BasesAccessLevel | null {
  switch (value) {
    case "read":
    case "write":
    case "admin":
      return value;
    default:
      return null;
  }
}

function fromPermissionLevel(value: PermissionLevel): BasesAccessLevel | null {
  if (value >= PermissionLevel.ADMIN) return "admin";
  if (value >= PermissionLevel.WRITE) return "write";
  if (value >= PermissionLevel.READ) return "read";
  return null;
}

function normalizeUniquePaths(paths: readonly string[]): {
  paths: string[];
  rejected: number;
} {
  const seen = new Set<string>();
  const normalized: string[] = [];
  let rejected = 0;
  for (const raw of paths) {
    const path = normalizeVaultRelativePath(raw);
    if (!path || seen.has(path)) {
      rejected += 1;
      continue;
    }
    seen.add(path);
    normalized.push(path);
  }
  return { paths: normalized, rejected };
}

function mapVerifiedBatch(
  requested: readonly string[],
  summaries: readonly PathAccessSummary[],
): Map<string, BasesAccessLevel | null> {
  const requestedSet = new Set(requested);
  const mapped = new Map<string, BasesAccessLevel | null>();
  const duplicates = new Set<string>();
  for (const summary of summaries) {
    const path = normalizeVaultRelativePath(summary?.path);
    if (!path || !requestedSet.has(path)) continue;
    if (mapped.has(path)) {
      duplicates.add(path);
      mapped.set(path, null);
      continue;
    }
    mapped.set(path, fromServerLevel(summary.currentUserLevel));
  }
  for (const duplicate of duplicates) mapped.set(duplicate, null);
  return mapped;
}

/**
 * Authorize a Base result without evaluating Base values first. Fresh server
 * decisions use the existing 100-path batch boundary. A failed batch may fall
 * back only to the synchronous cache seam; it never becomes N network calls.
 */
export async function resolveBasesAccess(
  rawPaths: readonly string[],
  ctx: BasesAccessContext,
  options: ResolveBasesAccessOptions,
): Promise<BasesAccessResult> {
  const maxRows = Math.max(1, Math.min(500, Math.trunc(options.maxRows)));
  const normalized = normalizeUniquePaths(rawPaths);
  const eligible: string[] = [];
  let omitted = normalized.rejected;
  for (const path of normalized.paths) {
    if (ctx.isMetadataSuppressed(path) || ctx.isPathExcluded(path)) {
      omitted += 1;
    } else {
      eligible.push(path);
    }
  }

  const result: BasesAccessResult = {
    rows: [],
    omitted,
    unverified: 0,
    truncated: false,
    cancelled: false,
  };

  for (let offset = 0; offset < eligible.length; offset += BATCH_LIMIT) {
    if (!ctx.isGenerationCurrent(options.generation)) {
      return { ...result, rows: [], cancelled: true };
    }
    const batch = eligible.slice(offset, offset + BATCH_LIMIT);
    let decisions: Array<{
      path: string;
      level: BasesAccessLevel | null;
      provenance: BasesAccessProvenance | null;
    }>;
    try {
      const summaries = await ctx.getBatchPathAccess(batch);
      if (!ctx.isGenerationCurrent(options.generation)) {
        return { ...result, rows: [], cancelled: true };
      }
      const mapped = mapVerifiedBatch(batch, Array.isArray(summaries) ? summaries : []);
      decisions = batch.map((path) => {
        if (!mapped.has(path)) return { path, level: null, provenance: null };
        const level = mapped.get(path) ?? null;
        return { path, level, provenance: level ? "verified" : null };
      });
    } catch {
      decisions = batch.map((path) => {
        const decision = ctx.peekPermissionDecision(path);
        if (decision.kind === "unknown") {
          return { path, level: null, provenance: null };
        }
        const level = fromPermissionLevel(decision.level);
        return {
          path,
          level,
          provenance: level ? (decision.kind === "verified" ? "verified" : "cached") : null,
        };
      });
    }

    for (const decision of decisions) {
      if (!decision.level || !decision.provenance) {
        // A server `none` is an intentional omission. Missing/malformed/unknown
        // cannot be distinguished here without leaking path-level state, so the
        // layout reports a single aggregate unverified count.
        result.unverified += 1;
        continue;
      }
      if (result.rows.length >= maxRows) {
        result.truncated = true;
        break;
      }
      result.rows.push({
        path: decision.path,
        level: decision.level,
        provenance: decision.provenance,
        generation: options.generation,
      });
    }

    await ctx.yieldControl();
    if (!ctx.isGenerationCurrent(options.generation)) {
      return { ...result, rows: [], cancelled: true };
    }
    if (result.rows.length >= maxRows) {
      result.truncated = result.truncated || offset + batch.length < eligible.length;
      break;
    }
  }
  return result;
}
