/**
 * Shared constants and helpers for encrypted attachment synchronization.
 *
 * This module owns the JSON-path threshold, request timeout, outgoing MIME map,
 * and pull-side binary discriminator. Files above the threshold use the
 * direct-transfer path; the deployment's configured file limit is authoritative.
 * There is no Obsidian import, so the helpers remain pure and unit-testable.
 */

/**
 * Maximum plaintext byte size that may ride the existing JSON
 * `/vaults/{vaultId}/files` path. Larger text and binary files are routed through
 * the encrypted direct-transfer issue/PUT/finalize path instead of being rejected.
 *
 * Ceiling math: API Gateway hard-caps the JSON request body at 10,485,760 bytes.
 * The body is `{"content": base64(N+28 ciphertext bytes), "hash": 64 hex chars,
 * "contentType": ...}` — AES-256-GCM adds a 12-byte nonce + 16-byte tag = 28 bytes
 * to the N plaintext bytes, and base64 inflates by 4*ceil((N+28)/3). Solving
 * 4*ceil((N+28)/3) < 10,485,760 gives N_max ≈ 7,864,000. Picking 7 MiB
 * (7 * 1024 * 1024 = 7,340,032) leaves ~500 KB of headroom for the JSON envelope
 * keys, the hash, and the contentType string.
 *
 * This is a transport-selection threshold, not the supported file-size maximum.
 * The Lambda `MAX_FILE_SIZE` environment value is enforced when a direct upload is
 * issued and finalized.
 */
export const BINARY_SYNC_MAX_BYTES = 7 * 1024 * 1024;

/**
 * Largest encrypted S3 object that can still belong to the JSON transfer lane.
 * Remote file metadata reports ciphertext bytes, so pull-side lane selection must
 * include the fixed AES-256-GCM envelope (12-byte nonce + 16-byte tag). A direct
 * transfer is therefore strictly larger than this value.
 */
export const JSON_SYNC_MAX_ENCRYPTED_BYTES = BINARY_SYNC_MAX_BYTES + 28;

/**
 * Per-request timeout (ms) for binary PUT uploads, threaded through the `apiRequest`
 * `timeoutMs` override to `requestWithTimeout` (L2). The default 30 s apiRequest
 * timeout is too short for ~9.3 MB base64 bodies on slow uplinks: a timed-out PUT is
 * classified as a network error, flips the client offline, and requeues the op —
 * retrying the same body forever. 120 s gives the largest JSON-path attachment room
 * to land on a modest (~0.7 Mbps) uplink. Direct transfers also enforce at least
 * this timeout in the API client.
 */
export const BINARY_PUT_TIMEOUT_MS = 120_000;

/** Fallback content type for unknown / extension-less paths. */
const DEFAULT_CONTENT_TYPE = "application/octet-stream";

/**
 * Extension → MIME map for OUTGOING binary uploads only. This label rides in the
 * PUT body's `contentType` so the pull side (and pre-AR1-artifact healing, L7) can
 * distinguish binary objects from text. It does NOT drive the push text/binary
 * split — that stays CONTENT-based (a strict UTF-8 probe in readTextForSync),
 * never extension-based.
 *
 * `svg` is deliberately ABSENT: an SVG is valid UTF-8, so it passes the UTF-8 probe
 * and rides the existing text pipeline losslessly — it must never be labelled
 * binary. A real `.svg` therefore never reaches contentTypeForPath at all; if one
 * did (extension-less edge), the default `application/octet-stream` is a safe,
 * still-correct fallback.
 */
const EXTENSION_TO_CONTENT_TYPE: Record<string, string> = {
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  gif: "image/gif",
  webp: "image/webp",
  bmp: "image/bmp",
  ico: "image/x-icon",
  pdf: "application/pdf",
  mp3: "audio/mpeg",
  m4a: "audio/mp4",
  wav: "audio/wav",
  ogg: "audio/ogg",
  flac: "audio/flac",
  mp4: "video/mp4",
  webm: "video/webm",
  mov: "video/quicktime",
  zip: "application/zip",
};

/**
 * Derive the outgoing `contentType` label for a vault-relative path by
 * lowercased-extension lookup. Unknown or dot-less paths → `application/octet-stream`.
 * BIN-A: used only to label binary uploads (see EXTENSION_TO_CONTENT_TYPE).
 */
export function contentTypeForPath(path: string): string {
  const lastSlash = path.lastIndexOf("/");
  const basename = lastSlash >= 0 ? path.slice(lastSlash + 1) : path;
  const lastDot = basename.lastIndexOf(".");
  // lastDot <= 0 covers both "no dot" (-1) and a leading-dot dotfile with no
  // further extension (0) — both have no usable extension.
  if (lastDot <= 0) {
    return DEFAULT_CONTENT_TYPE;
  }
  const ext = basename.slice(lastDot + 1).toLowerCase();
  return EXTENSION_TO_CONTENT_TYPE[ext] ?? DEFAULT_CONTENT_TYPE;
}

/**
 * Pull-side binary discriminator. Returns true only when `contentType` is a
 * non-empty string that does NOT start with "text/". `undefined`/empty → false
 * (treat-as-text fail-safe, matching today's behavior for objects with no type).
 *
 * BIN-A: every text object on S3 today carries `text/markdown` (the server PUT
 * default, files/handler.ts:1129, because no existing push site sends a
 * contentType), so `!startsWith("text/")` is a reliable binary signal — and it
 * also makes pre-AR1 lossy artifacts identifiable (they were stored text/markdown;
 * L7 healing).
 */
export function isBinaryContentType(contentType: string | undefined): boolean {
  if (!contentType) return false;
  return !contentType.startsWith("text/");
}

/**
 * Whether `path` has a KNOWN binary attachment extension (png, jpg, pdf, …) —
 * i.e. contentTypeForPath maps it to a concrete binary MIME rather than the
 * application/octet-stream default.
 *
 * BIN-A / L6 (option b): used ONLY by the lease-denied placeholder skip. It is
 * deliberately NOT `isBinaryContentType(contentTypeForPath(path))`, which would
 * misclassify text (.md), unknown, and extension-less paths as binary — because
 * contentTypeForPath returns the octet-stream default for every unmapped/dot-less
 * path and `isBinaryContentType("application/octet-stream")` is true. Those paths
 * must still receive a text placeholder, so this helper returns false for them.
 *
 * The extension heuristic is acceptable HERE (unlike pull-write decisions, L9)
 * because a missed extension-less binary just gets today's empty placeholder —
 * no worse than the status quo.
 */
export function isKnownBinaryExtensionPath(path: string): boolean {
  return contentTypeForPath(path) !== DEFAULT_CONTENT_TYPE;
}
