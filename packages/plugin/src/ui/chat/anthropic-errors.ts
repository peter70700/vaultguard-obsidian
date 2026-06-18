// Maps Anthropic Messages API HTTP error statuses to VaultGuard's existing
// domain error hierarchy (AI-CHAT-PANEL.md §12). Reuses the classes exported
// from src/api/client.ts rather than inventing a parallel hierarchy.
//
// This module NEVER throws — it returns a constructed error instance so the
// caller decides whether to throw, log, or surface it.

import {
  AuthenticationError,
  AuthorizationError,
  RateLimitError,
  ServerError,
  VaultGuardError,
} from "../../api/client";

/**
 * Anthropic's error envelope is shaped like `{ type:"error", error:{ type, message } }`.
 * This pulls out a human-readable message when the body matches, falling back to
 * `undefined` so callers can substitute a generic per-status message.
 */
export function extractAnthropicMessage(body: unknown): string | undefined {
  if (body && typeof body === "object" && "error" in body) {
    const err = (body as { error?: unknown }).error;
    if (err && typeof err === "object" && "message" in err) {
      const message = (err as { message?: unknown }).message;
      if (typeof message === "string" && message.length > 0) {
        return message;
      }
    }
  }
  return undefined;
}

/**
 * Translate an Anthropic HTTP status + response body into a domain error.
 * Returns the error instance — does not throw.
 */
export function mapAnthropicError(status: number, body: unknown): VaultGuardError {
  const upstream = extractAnthropicMessage(body);

  switch (status) {
    case 401:
      return new AuthenticationError(
        upstream ??
          "Anthropic rejected the API key. Re-enter a valid key in VaultGuard chat settings.",
      );
    case 403:
      return new AuthorizationError(
        upstream ??
          "This API key does not have access to the requested model. Try a different model.",
      );
    case 429:
      return new RateLimitError(upstream ?? "Anthropic rate limit reached. Retry shortly.");
    case 413:
      return new VaultGuardError(
        upstream ??
          "The request is too large for the model. Trim the conversation (clear older turns) and retry.",
      );
    case 400:
      // Bad request — almost always a programming bug (bad model id, bad
      // sampling param, malformed messages). Surface the upstream message so
      // it is debuggable.
      return new VaultGuardError(
        upstream ?? "Anthropic rejected the request as malformed (400).",
      );
    case 500:
    case 502:
    case 503:
    case 529:
      return new ServerError(
        upstream ?? "Anthropic is temporarily unavailable. Retry, or switch to a cheaper model.",
      );
    default:
      if (status >= 500) {
        return new ServerError(upstream ?? `Anthropic server error (${status}).`);
      }
      return new VaultGuardError(
        upstream ?? `Unexpected Anthropic response status ${status}.`,
      );
  }
}
