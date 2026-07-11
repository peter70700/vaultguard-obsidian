// SD-14-F3: defense-in-depth redaction for the always-on local error logger.
//
// `VaultGuardPlugin.logError` writes to the DevTools console UNCONDITIONALLY
// (real errors must surface regardless of debugLogging / NODE_ENV). That makes
// it the one logging path where an accidentally secret-laden error — e.g. a
// caller that stringifies a bearer token, or a network error whose URL carries
// an auth query param — could reach the console verbatim. These helpers strip
// the few secret SHAPES we can recognize with high confidence, WITHOUT touching
// file paths or ordinary text, so errors stay debuggable.
//
// This is local-console defense-in-depth (console.error never leaves the
// device), NOT a guarantee: an unrecognized secret shape can still pass through.
// The primary control remains "don't pass secrets to logError".

const REDACTED = "«redacted»";

// Each pattern targets a high-signal secret shape → low false-positive rate, so
// normal errors (including vault-relative file paths) are left intact.
const SECRET_PATTERNS: ReadonlyArray<readonly [RegExp, string]> = [
  // Authorization bearer tokens: `Bearer <token>`.
  [/\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi, `Bearer ${REDACTED}`],
  // Agent-bridge lease bearers (`agt_...`).
  [/\bagt_[A-Za-z0-9._-]{6,}/g, `agt_${REDACTED}`],
  // At-rest ciphertext: the VG1 magic ("VG1\0") + the rest of that line.
  [/VG1\x00[^\n\r]*/g, `VG1${REDACTED}`],
  // JWTs (id/access tokens) — the `eyJ` header prefix is highly distinctive.
  [/\beyJ[A-Za-z0-9._-]{20,}/g, `${REDACTED}-jwt`],
  // Secret-bearing URL query params, anchored on `?`/`&` so prose like
  // "primary key: 5" is never matched.
  [
    /([?&](?:access_token|id_token|refresh_token|token|api[_-]?key|secret|password|lease)=)[^&\s"']+/gi,
    `$1${REDACTED}`,
  ],
];

/** Redact known secret shapes from a log string. Leaves everything else intact. */
export function redactSecretString(input: string): string {
  let out = input;
  for (const [pattern, replacement] of SECRET_PATTERNS) {
    out = out.replace(pattern, replacement);
  }
  return out;
}

/**
 * Render an arbitrary logged value to a string WITHOUT redaction — the raw form
 * `logError` compares against so it only swaps in the sanitized string when a
 * secret was actually present (preserving the clickable Error object otherwise).
 */
export function stringifyForLog(value: unknown): string {
  if (value instanceof Error) {
    return value.stack ?? `${value.name}: ${value.message}`;
  }
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}
