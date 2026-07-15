export const DISCOVERY_BUDGETS = Object.freeze({
  maxVaults: 25,
  metadataPageSize: 200,
  maxMetadataFilesPerVault: 2_000,
  maxMetadataFiles: 10_000,
  maxContentFiles: 50,
  maxContentBytesPerFile: 256 * 1024,
  maxContentBytesTotal: 8 * 1024 * 1024,
  maxRemoteReadConcurrency: 2,
  maxListConcurrency: 3,
  maxResults: 100,
  maxContentMatches: 50,
  maxSnippetCodePoints: 240,
  maxQueryCodePoints: 256,
  metadataDeadlineMs: 10_000,
  contentDeadlineMs: 20_000,
});

export type SecureSearchScope = "current" | "all";
export type SecureSearchMatchKind = "path" | "content" | "semantic";
export type SecureSearchAccess = "list" | "read" | "write" | "admin";

export interface SecureSearchRequestInput {
  query: string;
  scope?: SecureSearchScope;
  includeContent?: boolean;
  semantic?: boolean;
  limit?: number;
}

export interface SecureSearchRequest {
  query: string;
  scope: SecureSearchScope;
  includeContent: boolean;
  semantic: boolean;
  limit: number;
}

export interface SecureSearchResult {
  vaultId: string;
  vaultName: string;
  path: string;
  local: boolean;
  matchKind: SecureSearchMatchKind;
  score: number;
  access: SecureSearchAccess;
  snippet?: string;
}

export type SearchPartialReason =
  | "offline"
  | "limit"
  | "truncated"
  | "vault-failure"
  | "content-failure"
  | "key-unavailable"
  | "timeout"
  | "cancelled"
  | "stale-index";

export interface SearchCoverage {
  complete: boolean;
  vaultsConsidered: number;
  vaultsSearched: number;
  metadataFiles: number;
  contentFiles: number;
  skippedFiles: number;
  failedVaults: number;
  truncatedVaults: number;
  cancelled: boolean;
  reasons: SearchPartialReason[];
}

export interface SecureSearchResponse {
  schemaVersion: 1;
  query: string;
  scope: SecureSearchScope;
  results: SecureSearchResult[];
  coverage: SearchCoverage;
}

const WINDOWS_ABSOLUTE = /^[a-z]:[\\/]/iu;
const CONTROL = /[\u0000-\u001f\u007f]/u;

/**
 * Convert API/Obsidian path variants to one vault-relative form. This is a
 * defense-in-depth filter, not an authorization decision.
 */
export function normalizeVaultRelativePath(input: unknown): string | null {
  if (typeof input !== "string") return null;
  let path = input.trim().replace(/\\/gu, "/");
  if (!path || path === "/" || CONTROL.test(path) || WINDOWS_ABSOLUTE.test(path)) {
    return null;
  }
  path = path.replace(/^\/+/, "").replace(/\/{2,}/gu, "/");
  const segments = path.split("/");
  if (
    segments.some((segment) => !segment || segment === "." || segment === "..") ||
    segments[0]?.startsWith(".") ||
    path.endsWith("/.vaultguard-folder") ||
    path === ".vaultguard-folder"
  ) {
    return null;
  }
  const lower = path.toLocaleLowerCase("en-US");
  if (
    lower === ".obsidian/plugins/vaultguard" ||
    lower.startsWith(".obsidian/plugins/vaultguard/") ||
    lower === ".obsidian/plugins/vaultguard-sync" ||
    lower.startsWith(".obsidian/plugins/vaultguard-sync/")
  ) {
    return null;
  }
  return path;
}

export function validateSecureSearchRequest(
  input: SecureSearchRequestInput,
): SecureSearchRequest {
  const query = typeof input.query === "string" ? input.query.trim() : "";
  const queryLength = [...query].length;
  if (queryLength < 2 || queryLength > DISCOVERY_BUDGETS.maxQueryCodePoints || CONTROL.test(query)) {
    throw new Error("Search query must contain 2 to 256 visible characters.");
  }
  const scope = input.scope ?? "current";
  if (scope !== "current" && scope !== "all") {
    throw new Error("Search scope must be current or all.");
  }
  const semantic = input.semantic === true;
  if (semantic && scope !== "current") {
    throw new Error("Semantic search is limited to the current vault in P2.");
  }
  const rawLimit = typeof input.limit === "number" && Number.isFinite(input.limit)
    ? Math.trunc(input.limit)
    : 50;
  return {
    query,
    scope,
    includeContent: input.includeContent === true,
    semantic,
    limit: Math.max(1, Math.min(DISCOVERY_BUDGETS.maxResults, rawLimit)),
  };
}

export function scorePathMatch(path: string, query: string): number | null {
  const normalizedPath = path.toLocaleLowerCase("en-US");
  const normalizedQuery = query.trim().toLocaleLowerCase("en-US");
  if (!normalizedQuery) return null;
  const basename = normalizedPath.split("/").at(-1) ?? normalizedPath;
  if (basename === normalizedQuery) return 1;
  if (basename.startsWith(normalizedQuery)) return 0.9;
  if (basename.includes(normalizedQuery)) return 0.8;
  if (normalizedPath.includes(normalizedQuery)) return 0.7;
  return null;
}

/** Build a bounded plain-text excerpt around an optional match offset. */
export function sanitizeSnippet(
  source: string,
  matchIndex = 0,
  maxCodePoints = DISCOVERY_BUDGETS.maxSnippetCodePoints,
): string {
  const clean = source
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/gu, " ")
    .replace(/\s+/gu, " ")
    .trim();
  const points = [...clean];
  const limit = Math.max(1, Math.min(DISCOVERY_BUDGETS.maxSnippetCodePoints, maxCodePoints));
  if (points.length <= limit) return clean;
  const safeIndex = Number.isFinite(matchIndex) ? Math.max(0, Math.trunc(matchIndex)) : 0;
  const start = Math.max(0, Math.min(points.length - limit, safeIndex - Math.floor(limit / 3)));
  const body = points.slice(start, start + limit).join("");
  const prefix = start > 0 ? "…" : "";
  const suffix = start + limit < points.length ? "…" : "";
  // Keep the total output inside the advertised cap, including ellipses.
  return [...`${prefix}${body}${suffix}`].slice(0, limit).join("");
}

export function sortSecureSearchResults(
  results: readonly SecureSearchResult[],
): SecureSearchResult[] {
  return [...results].sort((left, right) => {
    const scoreOrder = right.score - left.score;
    if (scoreOrder !== 0) return scoreOrder;
    const vaultOrder = left.vaultName.localeCompare(right.vaultName, undefined, {
      sensitivity: "base",
    });
    if (vaultOrder !== 0) return vaultOrder;
    return left.path.localeCompare(right.path, undefined, { sensitivity: "base" });
  });
}

export function createEmptyCoverage(): SearchCoverage {
  return {
    complete: true,
    vaultsConsidered: 0,
    vaultsSearched: 0,
    metadataFiles: 0,
    contentFiles: 0,
    skippedFiles: 0,
    failedVaults: 0,
    truncatedVaults: 0,
    cancelled: false,
    reasons: [],
  };
}

export function addPartialReason(
  coverage: SearchCoverage,
  reason: SearchPartialReason,
): void {
  coverage.complete = false;
  if (!coverage.reasons.includes(reason)) coverage.reasons.push(reason);
  if (reason === "cancelled") coverage.cancelled = true;
}

/** Cooperative generation token for APIs whose in-flight requests cannot abort. */
export class SearchGeneration {
  private current = 0;

  start(): number {
    this.current += 1;
    return this.current;
  }

  cancel(): void {
    this.current += 1;
  }

  isCurrent(generation: number): boolean {
    return generation > 0 && generation === this.current;
  }
}
