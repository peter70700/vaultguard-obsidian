export const AGENT_READ_PREFLIGHT_MAX_BYTES = 8 * 1024 * 1024;
export const AGENT_READ_MAX_SUGGESTION_CANDIDATES = 5_000;
export const AGENT_READ_MAX_SUGGESTIONS = 5;

export type AgentReadClassification =
  | "text"
  | "supported_source"
  | "media"
  | "binary"
  | "oversized_encrypted"
  | "unknown";

export type AgentReadRoute = "read" | "attachment" | "import" | "unsupported";

export interface AgentReadFileInfo {
  sizeBytes: number;
  storage?: "encrypted" | "plaintext" | "unknown";
}

export interface AgentReadPreflight {
  classification: AgentReadClassification;
  route: AgentReadRoute;
  readable: boolean;
  reasonCode:
    | "readable_text"
    | "readable_source"
    | "use_attachment_workflow"
    | "use_import_workflow"
    | "unsupported_file_type"
    | "file_too_large"
    | "oversized_encrypted";
}

export interface AgentReadWindowRequest {
  offsetBytes?: number;
  maxBytes: number;
  maxAllowedBytes?: number;
  classification?: Extract<AgentReadClassification, "text" | "supported_source">;
}

export interface AgentReadWindow {
  content: string;
  offsetBytes: number;
  returnedBytes: number;
  nextOffsetBytes: number | null;
  totalBytes: number;
  complete: boolean;
  classification: Extract<AgentReadClassification, "text" | "supported_source">;
}

export type AgentReadWindowErrorCode =
  | "invalid_offset"
  | "offset_past_eof"
  | "offset_not_utf8_boundary"
  | "invalid_window_size"
  | "window_too_small";

export class AgentReadWindowError extends Error {
  readonly code: AgentReadWindowErrorCode;

  constructor(code: AgentReadWindowErrorCode, message: string) {
    super(message);
    this.name = "AgentReadWindowError";
    this.code = code;
  }
}

const TEXT_EXTENSIONS = new Set([
  ".canvas",
  ".csv",
  ".json",
  ".log",
  ".md",
  ".mdx",
  ".txt",
  ".tsv",
  ".yaml",
  ".yml",
]);

const SOURCE_EXTENSIONS = new Set([
  ".bash",
  ".c",
  ".cc",
  ".cjs",
  ".cpp",
  ".cs",
  ".css",
  ".fish",
  ".gql",
  ".go",
  ".graphql",
  ".h",
  ".hpp",
  ".htm",
  ".html",
  ".ini",
  ".java",
  ".js",
  ".jsx",
  ".kt",
  ".kts",
  ".mjs",
  ".php",
  ".properties",
  ".ps1",
  ".py",
  ".rb",
  ".rs",
  ".scss",
  ".sh",
  ".sql",
  ".svelte",
  ".tf",
  ".toml",
  ".ts",
  ".tsx",
  ".vue",
  ".xml",
  ".zsh",
]);

const SOURCE_BASENAMES = new Set([
  ".editorconfig",
  ".gitattributes",
  ".gitignore",
  ".npmrc",
  "dockerfile",
  "gemfile",
  "makefile",
  "procfile",
]);

const TEXT_BASENAMES = new Set(["authors", "changelog", "copying", "license", "readme"]);

const MEDIA_EXTENSIONS = new Set([
  ".avif",
  ".bmp",
  ".flac",
  ".gif",
  ".heic",
  ".jpeg",
  ".jpg",
  ".m4a",
  ".mov",
  ".mp3",
  ".mp4",
  ".ogg",
  ".pdf",
  ".png",
  ".svg",
  ".wav",
  ".webm",
  ".webp",
]);

const BINARY_EXTENSIONS = new Set([
  ".7z",
  ".bin",
  ".class",
  ".db",
  ".dll",
  ".dmg",
  ".doc",
  ".docx",
  ".exe",
  ".gz",
  ".jar",
  ".lockb",
  ".o",
  ".pdb",
  ".ppt",
  ".pptx",
  ".sqlite",
  ".tar",
  ".tgz",
  ".wasm",
  ".xls",
  ".xlsx",
  ".zip",
]);

function normalizedBasename(path: string): string {
  const normalized = String(path ?? "").trim().replace(/\\/g, "/").toLocaleLowerCase();
  const slash = normalized.lastIndexOf("/");
  return slash === -1 ? normalized : normalized.slice(slash + 1);
}

function extensionOf(path: string): string {
  const basename = normalizedBasename(path);
  if (basename.endsWith(".tf.json")) return ".tf";
  const dot = basename.lastIndexOf(".");
  return dot <= 0 ? "" : basename.slice(dot);
}

export function classifyAgentReadPath(path: string): AgentReadClassification {
  const basename = normalizedBasename(path);
  const extension = extensionOf(path);
  if (TEXT_EXTENSIONS.has(extension) || TEXT_BASENAMES.has(basename)) return "text";
  if (SOURCE_EXTENSIONS.has(extension) || SOURCE_BASENAMES.has(basename)) {
    return "supported_source";
  }
  if (MEDIA_EXTENSIONS.has(extension)) return "media";
  if (BINARY_EXTENSIONS.has(extension)) return "binary";
  return "unknown";
}

export function preflightAgentRead(input: {
  path: string;
  sizeBytes?: number;
  storage?: AgentReadFileInfo["storage"];
  maxPreflightBytes?: number;
}): AgentReadPreflight {
  const classification = classifyAgentReadPath(input.path);
  const maxPreflightBytes = normalizePositiveInteger(
    input.maxPreflightBytes ?? AGENT_READ_PREFLIGHT_MAX_BYTES,
    AGENT_READ_PREFLIGHT_MAX_BYTES,
  );
  const sizeBytes = Number.isFinite(input.sizeBytes) ? Math.max(0, Math.floor(input.sizeBytes ?? 0)) : null;

  if (sizeBytes !== null && sizeBytes > maxPreflightBytes) {
    if (input.storage === "encrypted") {
      return {
        classification: "oversized_encrypted",
        route: "unsupported",
        readable: false,
        reasonCode: "oversized_encrypted",
      };
    }
    return {
      classification,
      route: "unsupported",
      readable: false,
      reasonCode: "file_too_large",
    };
  }

  if (classification === "text") {
    return { classification, route: "read", readable: true, reasonCode: "readable_text" };
  }
  if (classification === "supported_source") {
    return { classification, route: "read", readable: true, reasonCode: "readable_source" };
  }
  if (classification === "media") {
    return {
      classification,
      route: "attachment",
      readable: false,
      reasonCode: "use_attachment_workflow",
    };
  }
  if (classification === "binary") {
    return {
      classification,
      route: "import",
      readable: false,
      reasonCode: "use_import_workflow",
    };
  }
  return {
    classification,
    route: "unsupported",
    readable: false,
    reasonCode: "unsupported_file_type",
  };
}

export function createAgentReadWindow(content: string, request: AgentReadWindowRequest): AgentReadWindow {
  const bytes = new TextEncoder().encode(content);
  const offsetBytes = normalizeNonNegativeInteger(request.offsetBytes ?? 0);
  if (offsetBytes > bytes.byteLength) {
    throw new AgentReadWindowError("offset_past_eof", "Read offset is past the end of the file.");
  }
  if (offsetBytes < bytes.byteLength && isContinuationByte(bytes[offsetBytes])) {
    throw new AgentReadWindowError(
      "offset_not_utf8_boundary",
      "Read offset must point to a UTF-8 character boundary.",
    );
  }

  const maxAllowedBytes = normalizePositiveInteger(
    request.maxAllowedBytes ?? request.maxBytes,
    request.maxBytes,
  );
  const requestedBytes = normalizePositiveInteger(request.maxBytes, maxAllowedBytes);
  const maxBytes = Math.min(requestedBytes, maxAllowedBytes);
  let end = Math.min(bytes.byteLength, offsetBytes + maxBytes);
  while (end > offsetBytes && end < bytes.byteLength && isContinuationByte(bytes[end])) end--;

  if (end === offsetBytes && offsetBytes < bytes.byteLength) {
    throw new AgentReadWindowError(
      "window_too_small",
      "Read window is too small for the next UTF-8 character.",
    );
  }

  const returnedBytes = end - offsetBytes;
  const complete = end >= bytes.byteLength;
  const slice = bytes.slice(offsetBytes, end);
  return {
    content: new TextDecoder("utf-8", { fatal: true }).decode(slice),
    offsetBytes,
    returnedBytes,
    nextOffsetBytes: complete ? null : end,
    totalBytes: bytes.byteLength,
    complete,
    classification: request.classification ?? "text",
  };
}

export function findSafePathSuggestions(input: {
  requestedPath: string;
  candidatePaths: readonly string[];
  isAllowed: (path: string) => boolean;
  maxCandidates?: number;
  maxSuggestions?: number;
}): string[] {
  const maxCandidates = Math.min(
    normalizePositiveInteger(
      input.maxCandidates ?? AGENT_READ_MAX_SUGGESTION_CANDIDATES,
      AGENT_READ_MAX_SUGGESTION_CANDIDATES,
    ),
    AGENT_READ_MAX_SUGGESTION_CANDIDATES,
  );
  const maxSuggestions = Math.min(
    normalizePositiveInteger(input.maxSuggestions ?? 3, AGENT_READ_MAX_SUGGESTIONS),
    AGENT_READ_MAX_SUGGESTIONS,
  );
  const requested = normalizeSuggestionPath(input.requestedPath);
  const allowed = input.candidatePaths
    .slice(0, maxCandidates)
    .filter((candidate): candidate is string => typeof candidate === "string" && input.isAllowed(candidate));

  return [...new Set(allowed)]
    .map((path) => ({ path, score: pathDistance(requested, normalizeSuggestionPath(path)) }))
    .sort((left, right) => left.score - right.score || left.path.localeCompare(right.path))
    .slice(0, maxSuggestions)
    .map(({ path }) => path);
}

function normalizeSuggestionPath(path: string): string {
  return String(path ?? "").trim().replace(/\\/g, "/").toLocaleLowerCase();
}

function pathDistance(left: string, right: string): number {
  const leftName = normalizedBasename(left);
  const rightName = normalizedBasename(right);
  const directoryPenalty = left.slice(0, -leftName.length) === right.slice(0, -rightName.length) ? 0 : 4;
  return boundedLevenshtein(leftName.slice(0, 160), rightName.slice(0, 160)) + directoryPenalty;
}

function boundedLevenshtein(left: string, right: string): number {
  const previous = Array.from({ length: right.length + 1 }, (_, index) => index);
  for (let row = 1; row <= left.length; row++) {
    let diagonal = previous[0];
    previous[0] = row;
    for (let column = 1; column <= right.length; column++) {
      const above = previous[column];
      previous[column] = Math.min(
        previous[column] + 1,
        previous[column - 1] + 1,
        diagonal + (left[row - 1] === right[column - 1] ? 0 : 1),
      );
      diagonal = above;
    }
  }
  return previous[right.length];
}

function normalizeNonNegativeInteger(value: number): number {
  if (!Number.isFinite(value) || value < 0 || !Number.isInteger(value)) {
    throw new AgentReadWindowError("invalid_offset", "Read offset must be a non-negative integer.");
  }
  return value;
}

function normalizePositiveInteger(value: number, fallbackMaximum: number): number {
  if (!Number.isFinite(value) || value < 1 || !Number.isInteger(value)) {
    throw new AgentReadWindowError("invalid_window_size", "Read window size must be a positive integer.");
  }
  return Math.min(value, Math.max(1, Math.floor(fallbackMaximum)));
}

function isContinuationByte(value: number | undefined): boolean {
  return value !== undefined && (value & 0xc0) === 0x80;
}
