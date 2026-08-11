import { requestUrl } from "obsidian";

export interface PluginLoginPermitMetadata {
  attemptId: string;
  permit: string;
  expiresAt: number;
}

interface VerificationAttemptResponse {
  state: "pending";
  attemptId: string;
  expiresAtMs: number;
  completionUrl: string;
  retryAfterMs: number;
}

interface VerificationPollResponse {
  state: "pending" | "verified" | "expired" | "failed";
  retryAfterMs?: number;
  permit?: string;
  expiresAtMs?: number;
}

export interface PluginHumanVerificationInput {
  apiBaseUrl: string;
  organization: string;
  email: string;
  clientId: string;
  generation: number;
  isGenerationCurrent: (generation: number) => boolean;
}

interface JsonResponse {
  status: number;
  json: unknown;
}

export interface PluginHumanVerificationDependencies {
  request?: (url: string, body: Record<string, unknown>) => Promise<JsonResponse>;
  openCompletion?: (url: string) => void;
  sleep?: (delayMs: number) => Promise<void>;
  now?: () => number;
  createVerifier?: () => string;
  hashVerifier?: (verifier: string) => Promise<string>;
  maxPolls?: number;
}

const MIN_POLL_MS = 250;
const MAX_POLL_MS = 5_000;
const DEFAULT_MAX_POLLS = 120;

function randomVerifier(): string {
  const bytes = new Uint8Array(32);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}

async function obsidianRequest(
  url: string,
  body: Record<string, unknown>,
): Promise<JsonResponse> {
  const response = await requestUrl({
    url,
    method: "POST",
    contentType: "application/json",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    throw: false,
  });
  return { status: response.status, json: response.json };
}

function boundedDelay(value: unknown): number {
  const numeric = typeof value === "number" && Number.isFinite(value) ? value : 1_000;
  return Math.min(MAX_POLL_MS, Math.max(MIN_POLL_MS, numeric));
}

function endpoint(apiBaseUrl: string, path: string): string {
  return `${apiBaseUrl.replace(/\/$/, "")}${path}`;
}

function assertCurrent(input: PluginHumanVerificationInput): void {
  if (!input.isGenerationCurrent(input.generation)) {
    throw new Error("Human verification was cancelled because the login context changed.");
  }
}

async function post(
  request: NonNullable<PluginHumanVerificationDependencies["request"]>,
  url: string,
  body: Record<string, unknown>,
): Promise<JsonResponse> {
  try {
    return await request(url, body);
  } catch {
    throw new Error("Human verification is temporarily unavailable. Please try again.");
  }
}

/**
 * Performs a browser handoff without proxying identity credentials. Only the
 * resulting one-time permit metadata is returned to the initial Cognito call.
 * Raw verifier material remains function-local and is never persisted.
 */
export async function completePluginHumanVerification(
  input: PluginHumanVerificationInput,
  dependencies: PluginHumanVerificationDependencies = {},
): Promise<PluginLoginPermitMetadata> {
  const request = dependencies.request ?? obsidianRequest;
  const now = dependencies.now ?? Date.now;
  const sleep = dependencies.sleep ?? (delayMs => new Promise(resolve => setTimeout(resolve, delayMs)));
  const verifier = (dependencies.createVerifier ?? randomVerifier)();
  const verifierHash = await (dependencies.hashVerifier ?? sha256Hex)(verifier);

  assertCurrent(input);
  const created = await post(
    request,
    endpoint(input.apiBaseUrl, "/auth/human-verification/attempts"),
    {
      purpose: "login",
      orgSlug: input.organization.trim().toLowerCase(),
      email: input.email.trim().toLowerCase(),
      clientSurface: "plugin",
      clientId: input.clientId,
      verifierHash,
    },
  );
  if (created.status !== 201 || !created.json || typeof created.json !== "object") {
    throw new Error("Human verification could not be started. Please try again.");
  }
  const attempt = created.json as Partial<VerificationAttemptResponse>;
  if (
    attempt.state !== "pending" ||
    typeof attempt.attemptId !== "string" ||
    typeof attempt.completionUrl !== "string" ||
    typeof attempt.expiresAtMs !== "number" ||
    attempt.expiresAtMs <= now()
  ) {
    throw new Error("Human verification could not be started. Please try again.");
  }

  assertCurrent(input);
  (dependencies.openCompletion ?? (url => window.open(url, "_blank", "noopener,noreferrer")))(
    attempt.completionUrl,
  );

  const maxPolls = dependencies.maxPolls ?? DEFAULT_MAX_POLLS;
  let retryAfterMs = boundedDelay(attempt.retryAfterMs);
  for (let pollCount = 0; pollCount < maxPolls && now() < attempt.expiresAtMs; pollCount += 1) {
    await sleep(retryAfterMs);
    assertCurrent(input);
    const response = await post(
      request,
      endpoint(input.apiBaseUrl, "/auth/human-verification/poll"),
      { attemptId: attempt.attemptId, verifier },
    );
    if (response.status !== 200 || !response.json || typeof response.json !== "object") {
      throw new Error("Human verification could not be completed. Please try again.");
    }
    const polled = response.json as VerificationPollResponse;
    if (polled.state === "pending") {
      retryAfterMs = boundedDelay(polled.retryAfterMs);
      continue;
    }
    if (
      polled.state === "verified" &&
      typeof polled.permit === "string" &&
      typeof polled.expiresAtMs === "number" &&
      polled.expiresAtMs > now()
    ) {
      assertCurrent(input);
      return {
        attemptId: attempt.attemptId,
        permit: polled.permit,
        expiresAt: polled.expiresAtMs,
      };
    }
    throw new Error("Human verification expired. Please start again.");
  }

  throw new Error("Human verification expired. Please start again.");
}
