/**
 * Provider-independent, permission-first inspection for Agent Bridge commands.
 *
 * This module deliberately has no Obsidian or filesystem imports. Providers
 * enumerate vault-relative paths, answer policy questions, and expose a small
 * allow-listed fact shape. The service never requests a fact or note body until
 * every path policy (including read permission) has passed.
 */

export const AGENT_INSPECTION_DEFAULT_LIMIT = 50;
export const AGENT_INSPECTION_MAX_LIMIT = 200;
export const AGENT_INSPECTION_MAX_VISIBLE_FILES = 5_000;
export const AGENT_INSPECTION_MAX_TEXT_BYTES = 262_144;

export type AgentInspectionOperation =
  | "file_info"
  | "outline"
  | "tags"
  | "unresolved_links"
  | "dead_ends"
  | "recent"
  | "word_count"
  | "collection";

export type AgentCollectionPrimitive = string | number | boolean | null;
export type AgentCollectionValue =
  | AgentCollectionPrimitive
  | readonly AgentCollectionPrimitive[];

export type AgentCollectionOperator =
  | "eq"
  | "ne"
  | "contains"
  | "starts_with"
  | "gt"
  | "gte"
  | "lt"
  | "lte"
  | "exists";

export interface AgentCollectionFilter {
  field: string;
  op: AgentCollectionOperator;
  value?: AgentCollectionPrimitive;
}

export interface AgentCollectionSort {
  field: string;
  direction?: "asc" | "desc";
}

export interface AgentInspectionQuery {
  op: AgentInspectionOperation;
  path?: string;
  scope?: string;
  limit?: number;
  fields?: readonly string[];
  filters?: readonly AgentCollectionFilter[];
  sort?: AgentCollectionSort;
}

export interface AgentInspectionHeading {
  heading: string;
  level: number;
  line: number;
}

export interface AgentInspectionUnresolvedLink {
  link: string;
  count?: number;
}

/**
 * Closed metadata shape supplied after authorization. Unknown provider fields
 * are structurally discarded and can never reach an agent result.
 */
export interface AgentInspectionFileFact {
  path: string;
  name?: string;
  extension?: string;
  ctime?: number;
  mtime?: number;
  sizeBytes?: number;
  headings?: readonly AgentInspectionHeading[];
  tags?: readonly string[];
  unresolvedLinks?: readonly AgentInspectionUnresolvedLink[];
  resolvedLinks?: readonly string[];
  frontmatter?: Readonly<Record<string, unknown>>;
}

export interface AgentInspectionTextRead {
  content: string;
  /** True when the provider stopped before the complete plaintext note. */
  truncated?: boolean;
}

type MaybePromise<T> = T | Promise<T>;

export interface AgentInspectionProvider {
  /** Path-only enumeration. It MUST NOT perform a metadata-cache read. */
  listPaths(): MaybePromise<readonly string[]>;
  /** Lease/current-vault scope. A query scope is applied in addition to this. */
  isInScope(path: string): MaybePromise<boolean>;
  isExcluded(path: string): MaybePromise<boolean>;
  isMetadataSuppressed(path: string): MaybePromise<boolean>;
  canRead(path: string): MaybePromise<boolean>;
  /** Called only after every visibility and permission gate passes. */
  getFileFact(path: string): MaybePromise<AgentInspectionFileFact | null>;
  /** Called only for an authorized word-count target. */
  readText(path: string, maxBytes: number): MaybePromise<AgentInspectionTextRead>;
}

export type AgentInspectionRecord = Readonly<Record<string, unknown>>;

export interface AgentInspectionResult {
  op: AgentInspectionOperation;
  records: readonly AgentInspectionRecord[];
  truncated: boolean;
}

interface VisibleFactSet {
  facts: SafeFileFact[];
  truncated: boolean;
}

interface SafeFileFact {
  path: string;
  name: string;
  extension: string;
  ctime: number | null;
  mtime: number | null;
  sizeBytes: number | null;
  headings: AgentInspectionHeading[];
  tags: string[];
  unresolvedLinks: Array<{ link: string; count: number }>;
  resolvedLinks: string[];
  frontmatter: Record<string, AgentCollectionValue>;
}

const COLLECTION_FIXED_FIELDS = new Set([
  "path",
  "name",
  "extension",
  "ctime",
  "mtime",
  "sizeBytes",
]);
const DEFAULT_COLLECTION_FIELDS = ["path", "name", "extension", "mtime"] as const;
const COLLECTION_FIELD_PATTERN = /^frontmatter\.([A-Za-z][A-Za-z0-9_-]{0,63})$/;
const FORBIDDEN_PROPERTY_NAMES = new Set(["__proto__", "constructor", "prototype"]);
const VALID_OPERATORS = new Set<AgentCollectionOperator>([
  "eq",
  "ne",
  "contains",
  "starts_with",
  "gt",
  "gte",
  "lt",
  "lte",
  "exists",
]);

function invalid(message: string): never {
  throw new Error(`Invalid inspection query: ${message}`);
}

function normalizeVaultPath(path: string, label = "path"): string {
  if (typeof path !== "string" || path.length === 0 || path.length > 1_024) {
    return invalid(`${label} must be a non-empty vault-relative path.`);
  }
  if (path.trim() !== path || path.includes("\0")) {
    return invalid(`${label} is not a canonical vault-relative path.`);
  }

  const normalized = path.replace(/\\/g, "/");
  if (
    normalized.startsWith("/") ||
    /^[A-Za-z]:\//.test(normalized) ||
    normalized.startsWith("//")
  ) {
    return invalid(`${label} must be vault-relative.`);
  }

  const segments = normalized.split("/");
  if (segments.some((segment) => segment.length === 0 || segment === "." || segment === "..")) {
    return invalid(`${label} contains an unsafe segment.`);
  }
  return normalized;
}

function normalizeOptionalScope(scope: string | undefined): string | undefined {
  return scope === undefined ? undefined : normalizeVaultPath(scope, "scope");
}

function isHiddenPath(path: string): boolean {
  return path.split("/").some((segment) => segment.startsWith("."));
}

function isWithinRequestedScope(path: string, scope: string | undefined): boolean {
  return scope === undefined || path === scope || path.startsWith(`${scope}/`);
}

function validatedLimit(limit: number | undefined): number {
  if (limit === undefined) return AGENT_INSPECTION_DEFAULT_LIMIT;
  if (!Number.isInteger(limit) || limit < 1 || limit > AGENT_INSPECTION_MAX_LIMIT) {
    return invalid(`limit must be an integer from 1 to ${AGENT_INSPECTION_MAX_LIMIT}.`);
  }
  return limit;
}

function finiteNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function boundedString(value: unknown, maxLength: number): string | null {
  if (typeof value !== "string") return null;
  const flattened = value.replace(/[\r\n\u0000]/g, " ").trim();
  if (!flattened) return null;
  return flattened.slice(0, maxLength);
}

function safeCollectionPrimitive(value: unknown): AgentCollectionPrimitive | undefined {
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") return Number.isFinite(value) ? value : undefined;
  if (typeof value === "string") return value.slice(0, 10_000);
  return undefined;
}

function safeCollectionValue(value: unknown): AgentCollectionValue | undefined {
  const primitive = safeCollectionPrimitive(value);
  if (primitive !== undefined || value === null) return primitive;
  if (!Array.isArray(value) || value.length > 100) return undefined;

  const result: AgentCollectionPrimitive[] = [];
  for (const item of value) {
    const safe = safeCollectionPrimitive(item);
    if (safe === undefined && item !== null) return undefined;
    result.push(safe ?? null);
  }
  return result;
}

function safeFrontmatter(value: unknown): Record<string, AgentCollectionValue> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return {};
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) return {};

  const result: Record<string, AgentCollectionValue> = {};
  for (const [key, raw] of Object.entries(value)) {
    if (
      !/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(key) ||
      FORBIDDEN_PROPERTY_NAMES.has(key)
    ) {
      continue;
    }
    const safe = safeCollectionValue(raw);
    if (safe !== undefined || raw === null) result[key] = safe ?? null;
  }
  return result;
}

function pathName(path: string): string {
  return path.slice(path.lastIndexOf("/") + 1);
}

function pathExtension(path: string): string {
  const name = pathName(path);
  const dot = name.lastIndexOf(".");
  return dot > 0 ? name.slice(dot + 1).toLowerCase() : "";
}

function sanitizeFact(requestedPath: string, fact: AgentInspectionFileFact): SafeFileFact | null {
  let factPath: string;
  try {
    factPath = normalizeVaultPath(fact.path);
  } catch {
    return null;
  }
  if (factPath !== requestedPath) return null;

  const headings = (Array.isArray(fact.headings) ? fact.headings : [])
    .slice(0, 2_000)
    .flatMap((heading) => {
      const text = boundedString(heading?.heading, 512);
      if (
        text === null ||
        !Number.isInteger(heading?.level) ||
        heading.level < 1 ||
        heading.level > 6 ||
        !Number.isInteger(heading?.line) ||
        heading.line < 0
      ) {
        return [];
      }
      return [{ heading: text, level: heading.level, line: heading.line }];
    });

  const tags = Array.from(
    new Set(
      (Array.isArray(fact.tags) ? fact.tags : [])
        .slice(0, 2_000)
        .flatMap((tag) => {
          const safe = boundedString(tag, 256)?.replace(/^#+/, "").toLowerCase();
          return safe ? [safe] : [];
        }),
    ),
  ).sort((left, right) => left.localeCompare(right));

  const unresolvedLinks = (Array.isArray(fact.unresolvedLinks) ? fact.unresolvedLinks : [])
    .slice(0, 2_000)
    .flatMap((entry) => {
      const link = boundedString(entry?.link, 1_024);
      if (link === null) return [];
      const count = Number.isInteger(entry?.count) && (entry.count ?? 0) > 0
        ? Math.min(entry.count ?? 1, 1_000_000)
        : 1;
      return [{ link, count }];
    });

  const resolvedLinks = Array.from(
    new Set(
      (Array.isArray(fact.resolvedLinks) ? fact.resolvedLinks : []).flatMap((link) => {
        try {
          return [normalizeVaultPath(link, "resolved link")];
        } catch {
          return [];
        }
      }),
    ),
  );

  const fallbackName = pathName(requestedPath);
  return {
    path: requestedPath,
    name: boundedString(fact.name, 512) ?? fallbackName,
    extension: boundedString(fact.extension, 32)?.toLowerCase() ?? pathExtension(requestedPath),
    ctime: finiteNumber(fact.ctime),
    mtime: finiteNumber(fact.mtime),
    sizeBytes: finiteNumber(fact.sizeBytes),
    headings,
    tags,
    unresolvedLinks,
    resolvedLinks,
    frontmatter: safeFrontmatter(fact.frontmatter),
  };
}

function validateCollectionField(field: string): string {
  if (typeof field !== "string" || field.length === 0 || field.length > 120) {
    return invalid("collection fields must be non-empty strings no longer than 120 characters.");
  }
  if (COLLECTION_FIXED_FIELDS.has(field)) return field;
  const match = COLLECTION_FIELD_PATTERN.exec(field);
  if (!match || FORBIDDEN_PROPERTY_NAMES.has(match[1])) {
    return invalid(`unsupported collection field ${JSON.stringify(field)}.`);
  }
  return field;
}

function validatedCollectionFields(fields: readonly string[] | undefined): string[] {
  if (fields === undefined) return [...DEFAULT_COLLECTION_FIELDS];
  if (!Array.isArray(fields) || fields.length === 0 || fields.length > 32) {
    return invalid("collection fields must contain between 1 and 32 entries.");
  }
  return Array.from(new Set(fields.map(validateCollectionField)));
}

function validatedFilters(filters: readonly AgentCollectionFilter[] | undefined): AgentCollectionFilter[] {
  if (filters === undefined) return [];
  if (!Array.isArray(filters) || filters.length > 16) {
    return invalid("collection filters may contain at most 16 entries.");
  }
  return filters.map((filter) => {
    if (!filter || typeof filter !== "object") return invalid("collection filter is invalid.");
    const field = validateCollectionField(filter.field);
    if (!VALID_OPERATORS.has(filter.op)) return invalid("collection filter operator is unsupported.");
    if (filter.op !== "exists") {
      const value = safeCollectionPrimitive(filter.value);
      if (value === undefined && filter.value !== null) {
        return invalid("collection filter value must be a finite primitive.");
      }
      return { field, op: filter.op, value: value ?? null };
    }
    if (filter.value !== undefined && typeof filter.value !== "boolean") {
      return invalid("an exists filter value, when present, must be boolean.");
    }
    return { field, op: filter.op, value: filter.value };
  });
}

function validatedSort(sort: AgentCollectionSort | undefined): AgentCollectionSort | undefined {
  if (sort === undefined) return undefined;
  if (!sort || typeof sort !== "object") return invalid("collection sort is invalid.");
  const direction = sort.direction ?? "asc";
  if (direction !== "asc" && direction !== "desc") {
    return invalid("collection sort direction must be asc or desc.");
  }
  return { field: validateCollectionField(sort.field), direction };
}

function fieldValue(fact: SafeFileFact, field: string): AgentCollectionValue | undefined {
  switch (field) {
    case "path":
      return fact.path;
    case "name":
      return fact.name;
    case "extension":
      return fact.extension;
    case "ctime":
      return fact.ctime ?? undefined;
    case "mtime":
      return fact.mtime ?? undefined;
    case "sizeBytes":
      return fact.sizeBytes ?? undefined;
    default: {
      const key = COLLECTION_FIELD_PATTERN.exec(field)?.[1];
      return key === undefined ? undefined : fact.frontmatter[key];
    }
  }
}

function scalarEquals(left: AgentCollectionPrimitive, right: AgentCollectionPrimitive): boolean {
  return left === right;
}

function isCollectionArray(
  value: AgentCollectionValue | undefined,
): value is readonly AgentCollectionPrimitive[] {
  return Array.isArray(value);
}

function compareScalars(left: unknown, right: unknown): number | null {
  if (typeof left === "number" && typeof right === "number") return left - right;
  if (typeof left === "string" && typeof right === "string") return left.localeCompare(right);
  if (typeof left === "boolean" && typeof right === "boolean") {
    return Number(left) - Number(right);
  }
  if (left === null && right === null) return 0;
  return null;
}

function matchesFilter(value: AgentCollectionValue | undefined, filter: AgentCollectionFilter): boolean {
  if (filter.op === "exists") {
    const expected = filter.value === undefined ? true : filter.value;
    return (value !== undefined) === expected;
  }

  const expected = filter.value ?? null;
  if (filter.op === "eq") {
    return !isCollectionArray(value) && value !== undefined && scalarEquals(value, expected);
  }
  if (filter.op === "ne") {
    return value === undefined || isCollectionArray(value) || !scalarEquals(value, expected);
  }
  if (filter.op === "contains") {
    if (typeof value === "string" && typeof expected === "string") return value.includes(expected);
    return isCollectionArray(value) && value.some((entry) => scalarEquals(entry, expected));
  }
  if (filter.op === "starts_with") {
    return typeof value === "string" && typeof expected === "string" && value.startsWith(expected);
  }

  const comparison = compareScalars(value, expected);
  if (comparison === null) return false;
  if (filter.op === "gt") return comparison > 0;
  if (filter.op === "gte") return comparison >= 0;
  if (filter.op === "lt") return comparison < 0;
  return comparison <= 0;
}

function compareCollectionValues(
  left: AgentCollectionValue | undefined,
  right: AgentCollectionValue | undefined,
): number {
  if (left === undefined && right === undefined) return 0;
  if (left === undefined) return 1;
  if (right === undefined) return -1;
  if (isCollectionArray(left) || isCollectionArray(right)) {
    return JSON.stringify(left).localeCompare(JSON.stringify(right));
  }
  return compareScalars(left, right) ?? String(left).localeCompare(String(right));
}

function boundedRecords(
  op: AgentInspectionOperation,
  records: AgentInspectionRecord[],
  limit: number,
  sourceTruncated = false,
): AgentInspectionResult {
  return {
    op,
    records: records.slice(0, limit),
    truncated: sourceTruncated || records.length > limit,
  };
}

function truncateUtf8(content: string, maxBytes: number): { content: string; bytes: number; truncated: boolean } {
  const encoded = new TextEncoder().encode(content);
  if (encoded.byteLength <= maxBytes) {
    return { content, bytes: encoded.byteLength, truncated: false };
  }

  let end = maxBytes;
  while (end > 0 && (encoded[end] & 0xc0) === 0x80) end -= 1;
  return {
    content: new TextDecoder().decode(encoded.slice(0, end)),
    bytes: end,
    truncated: true,
  };
}

function countWords(content: string): number {
  return content.match(/[\p{L}\p{N}]+(?:['’_-][\p{L}\p{N}]+)*/gu)?.length ?? 0;
}

export class AgentInspectionService {
  constructor(private readonly provider: AgentInspectionProvider) {}

  private async passesVisibilityPolicy(path: string, queryScope: string | undefined): Promise<boolean> {
    if (isHiddenPath(path) || !isWithinRequestedScope(path, queryScope)) return false;
    if (!(await this.provider.isInScope(path))) return false;
    if (await this.provider.isExcluded(path)) return false;
    if (await this.provider.isMetadataSuppressed(path)) return false;
    return this.provider.canRead(path);
  }

  private async getVisibleFact(path: string, queryScope: string | undefined): Promise<SafeFileFact | null> {
    if (!(await this.passesVisibilityPolicy(path, queryScope))) return null;
    const fact = await this.provider.getFileFact(path);
    return fact === null ? null : sanitizeFact(path, fact);
  }

  private async requireVisibleFact(path: string, queryScope: string | undefined): Promise<SafeFileFact> {
    const fact = await this.getVisibleFact(path, queryScope);
    if (fact === null) throw new Error("Inspection target is unavailable.");
    return fact;
  }

  private async collectVisibleFacts(queryScope: string | undefined): Promise<VisibleFactSet> {
    const normalized = new Set<string>();
    for (const rawPath of await this.provider.listPaths()) {
      try {
        normalized.add(normalizeVaultPath(rawPath));
      } catch {
        // A malformed provider path is never surfaced or dereferenced.
      }
    }

    const facts: SafeFileFact[] = [];
    let truncated = false;
    for (const path of Array.from(normalized).sort((left, right) => left.localeCompare(right))) {
      if (!(await this.passesVisibilityPolicy(path, queryScope))) continue;
      if (facts.length >= AGENT_INSPECTION_MAX_VISIBLE_FILES) {
        // Only an authorized path contributes to this truncation signal.
        truncated = true;
        continue;
      }
      const fact = await this.provider.getFileFact(path);
      const safe = fact === null ? null : sanitizeFact(path, fact);
      if (safe !== null) facts.push(safe);
    }
    return { facts, truncated };
  }

  async inspect(query: AgentInspectionQuery): Promise<AgentInspectionResult> {
    if (!query || typeof query !== "object") return invalid("input must be an object.");
    const limit = validatedLimit(query.limit);
    const scope = normalizeOptionalScope(query.scope);
    const path = query.path === undefined ? undefined : normalizeVaultPath(query.path);

    if (query.op === "file_info" || query.op === "outline" || query.op === "word_count") {
      if (path === undefined) return invalid(`${query.op} requires path.`);
      const fact = await this.requireVisibleFact(path, scope);

      if (query.op === "file_info") {
        return boundedRecords(query.op, [{
          path: fact.path,
          name: fact.name,
          extension: fact.extension,
          ctime: fact.ctime,
          mtime: fact.mtime,
          sizeBytes: fact.sizeBytes,
        }], limit);
      }

      if (query.op === "outline") {
        const rows = fact.headings.map((heading) => ({ path: fact.path, ...heading }));
        return boundedRecords(query.op, rows, limit);
      }

      // Permission and metadata suppression have already passed before this
      // plaintext read. The body is reduced to counts and is never returned.
      const read = await this.provider.readText(path, AGENT_INSPECTION_MAX_TEXT_BYTES);
      if (!read || typeof read.content !== "string") {
        throw new Error("Inspection text provider returned an invalid result.");
      }
      const bounded = truncateUtf8(read.content, AGENT_INSPECTION_MAX_TEXT_BYTES);
      const content = bounded.content;
      const truncated = bounded.truncated || read.truncated === true;
      return {
        op: query.op,
        records: [{
          path: fact.path,
          wordCount: countWords(content),
          characterCount: Array.from(content).length,
          byteCount: bounded.bytes,
          complete: !truncated,
        }],
        truncated,
      };
    }

    const source = path === undefined
      ? await this.collectVisibleFacts(scope)
      : { facts: [await this.requireVisibleFact(path, scope)], truncated: false };

    if (query.op === "tags") {
      if (path !== undefined) {
        return boundedRecords(
          query.op,
          source.facts[0].tags.map((tag) => ({ path, tag })),
          limit,
          source.truncated,
        );
      }

      const counts = new Map<string, number>();
      for (const fact of source.facts) {
        for (const tag of fact.tags) counts.set(tag, (counts.get(tag) ?? 0) + 1);
      }
      const rows = Array.from(counts, ([tag, count]) => ({ tag, count })).sort(
        (left, right) => right.count - left.count || left.tag.localeCompare(right.tag),
      );
      return boundedRecords(query.op, rows, limit, source.truncated);
    }

    if (query.op === "unresolved_links") {
      const rows = source.facts.flatMap((fact) =>
        fact.unresolvedLinks.map((entry) => ({ path: fact.path, ...entry })),
      ).sort((left, right) => left.path.localeCompare(right.path) || left.link.localeCompare(right.link));
      return boundedRecords(query.op, rows, limit, source.truncated);
    }

    if (query.op === "dead_ends") {
      const visiblePaths = new Set(source.facts.map((fact) => fact.path));
      const rows = source.facts
        .filter((fact) => !fact.resolvedLinks.some((destination) => visiblePaths.has(destination)))
        .map((fact) => ({ path: fact.path }));
      return boundedRecords(query.op, rows, limit, source.truncated);
    }

    if (query.op === "recent") {
      const rows = [...source.facts]
        .sort((left, right) => (right.mtime ?? -Infinity) - (left.mtime ?? -Infinity)
          || left.path.localeCompare(right.path))
        .map((fact) => ({ path: fact.path, mtime: fact.mtime }));
      return boundedRecords(query.op, rows, limit, source.truncated);
    }

    if (query.op !== "collection") return invalid("operation is unsupported.");

    const fields = validatedCollectionFields(query.fields);
    const filters = validatedFilters(query.filters);
    const sort = validatedSort(query.sort);
    const matching = source.facts.filter((fact) =>
      filters.every((filter) => matchesFilter(fieldValue(fact, filter.field), filter)),
    );

    if (sort !== undefined) {
      matching.sort((left, right) => {
        const comparison = compareCollectionValues(
          fieldValue(left, sort.field),
          fieldValue(right, sort.field),
        );
        return (sort.direction === "desc" ? -comparison : comparison)
          || left.path.localeCompare(right.path);
      });
    } else {
      matching.sort((left, right) => left.path.localeCompare(right.path));
    }

    const rows = matching.map((fact) => {
      const row: Record<string, AgentCollectionValue> = {};
      for (const field of fields) {
        const value = fieldValue(fact, field);
        if (value !== undefined) row[field] = value;
      }
      return row;
    });
    return boundedRecords(query.op, rows, limit, source.truncated);
  }
}
