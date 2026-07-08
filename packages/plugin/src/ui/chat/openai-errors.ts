// Maps OpenAI Responses API HTTP errors to VaultGuard's existing domain errors.
// Messages are redacted defensively before surfacing to the chat UI.

import {
  AuthenticationError,
  AuthorizationError,
  RateLimitError,
  ServerError,
  VaultGuardError,
} from "../../api/client";

const SECRET_RE = /\b(sk-[A-Za-z0-9_-]{8,})\b/g;

export function redactOpenAiSecret(text: string): string {
  return text.replace(SECRET_RE, "sk-...redacted");
}

export function extractOpenAiMessage(body: unknown): string | undefined {
  if (!body || typeof body !== "object" || !("error" in body)) return undefined;
  const err = (body as { error?: unknown }).error;
  if (!err || typeof err !== "object" || !("message" in err)) return undefined;
  const message = (err as { message?: unknown }).message;
  return typeof message === "string" && message.length > 0
    ? redactOpenAiSecret(message)
    : undefined;
}

export function mapOpenAiError(status: number, body: unknown): VaultGuardError {
  const upstream = extractOpenAiMessage(body);

  switch (status) {
    case 401:
      return new AuthenticationError(
        upstream ??
          "OpenAI rejected the API key. Re-enter a valid key in VaultGuard chat settings.",
      );
    case 403:
      return new AuthorizationError(
        upstream ??
          "This OpenAI key does not have access to the requested model. Try a different model.",
      );
    case 429:
      return new RateLimitError(upstream ?? "OpenAI rate limit reached. Retry shortly.");
    case 413:
      return new VaultGuardError(
        upstream ??
          "The OpenAI request is too large for the model. Trim the conversation and retry.",
      );
    case 400:
      return new VaultGuardError(
        upstream ?? "OpenAI rejected the request as malformed (400).",
      );
    case 500:
    case 502:
    case 503:
    case 529:
      return new ServerError(
        upstream ?? "OpenAI is temporarily unavailable. Retry, or switch models.",
      );
    default:
      if (status >= 500) {
        return new ServerError(upstream ?? `OpenAI server error (${status}).`);
      }
      return new VaultGuardError(
        upstream ?? `Unexpected OpenAI response status ${status}.`,
      );
  }
}
