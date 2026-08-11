import {
  GetSecretValueCommand,
  SecretsManagerClient,
} from '@aws-sdk/client-secrets-manager';

const SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const DEFAULT_MAX_AGE_MS = 5 * 60_000;
const MAX_FUTURE_SKEW_MS = 30_000;

export interface TurnstileSiteverifyResponse {
  success?: boolean;
  challenge_ts?: string;
  hostname?: string;
  action?: string;
  cdata?: string;
  'error-codes'?: string[];
}

export interface TurnstileTransportInput {
  secret: string;
  token: string;
  remoteIp?: string;
}

export type TurnstileTransport = (
  input: TurnstileTransportInput,
) => Promise<TurnstileSiteverifyResponse>;

export type TurnstileFailureCode =
  | 'not_configured'
  | 'provider_rejected'
  | 'provider_unavailable'
  | 'hostname_mismatch'
  | 'action_mismatch'
  | 'cdata_mismatch'
  | 'invalid_timestamp'
  | 'expired';

export type TurnstileVerificationResult =
  | {
      ok: true;
      hostname: string;
      action: string;
      challengeTimestamp: string;
    }
  | { ok: false; code: TurnstileFailureCode };

export interface VerifyTurnstileProofInput {
  token: string;
  secret: string;
  remoteIp?: string;
  expectedHostnames: readonly string[];
  expectedAction: string;
  expectedCdata: string;
  nowMs?: number;
  maxAgeMs?: number;
}

export async function defaultTurnstileTransport(
  input: TurnstileTransportInput,
): Promise<TurnstileSiteverifyResponse> {
  const body = new URLSearchParams({
    secret: input.secret,
    response: input.token,
  });
  if (input.remoteIp) body.set('remoteip', input.remoteIp);

  const response = await fetch(SITEVERIFY_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  });
  if (!response.ok) throw new Error('Turnstile provider unavailable');
  return (await response.json()) as TurnstileSiteverifyResponse;
}

/**
 * Strictly verifies provider output. The returned value is deliberately
 * bounded: provider errors, request tokens, secrets and response bodies never
 * cross this boundary or enter logs through callers.
 */
export async function verifyTurnstileProof(
  input: VerifyTurnstileProofInput,
  deps: { transport?: TurnstileTransport } = {},
): Promise<TurnstileVerificationResult> {
  if (!input.secret) return { ok: false, code: 'not_configured' };
  const transport = deps.transport ?? defaultTurnstileTransport;
  let result: TurnstileSiteverifyResponse;
  try {
    result = await transport({
      secret: input.secret,
      token: input.token,
      remoteIp: input.remoteIp,
    });
  } catch {
    return { ok: false, code: 'provider_unavailable' };
  }

  if (result.success !== true) return { ok: false, code: 'provider_rejected' };
  const hostname = result.hostname ?? '';
  if (!input.expectedHostnames.includes(hostname)) {
    return { ok: false, code: 'hostname_mismatch' };
  }
  if (result.action !== input.expectedAction) {
    return { ok: false, code: 'action_mismatch' };
  }
  if (result.cdata !== input.expectedCdata) {
    return { ok: false, code: 'cdata_mismatch' };
  }

  const challengeMs = Date.parse(result.challenge_ts ?? '');
  if (!Number.isFinite(challengeMs)) return { ok: false, code: 'invalid_timestamp' };
  const nowMs = input.nowMs ?? Date.now();
  const ageMs = nowMs - challengeMs;
  if (ageMs < -MAX_FUTURE_SKEW_MS || ageMs > (input.maxAgeMs ?? DEFAULT_MAX_AGE_MS)) {
    return { ok: false, code: 'expired' };
  }

  return {
    ok: true,
    hostname,
    action: result.action,
    challengeTimestamp: new Date(challengeMs).toISOString(),
  };
}

const secretCache = new Map<string, string>();

/** Loads `{ "secretKey": "..." }` without ever including payloads in errors. */
export async function loadTurnstileSecret(
  secretArn: string,
  deps: { send?: (command: unknown) => Promise<unknown> } = {},
): Promise<string> {
  if (!secretArn) return '';
  const cached = secretCache.get(secretArn);
  if (cached !== undefined) return cached;

  const send = deps.send ?? ((command: unknown) => {
    const client = new SecretsManagerClient({});
    return client.send(command as GetSecretValueCommand);
  });
  const result = (await send(new GetSecretValueCommand({ SecretId: secretArn }))) as {
    SecretString?: string;
  };
  if (!result.SecretString) throw new Error('Turnstile secret payload is unavailable');

  let parsed: { secretKey?: unknown };
  try {
    parsed = JSON.parse(result.SecretString) as { secretKey?: unknown };
  } catch {
    throw new Error('Turnstile secret payload is invalid');
  }
  if (typeof parsed.secretKey !== 'string' || parsed.secretKey.length === 0) {
    throw new Error('Turnstile secret key is unavailable');
  }
  secretCache.set(secretArn, parsed.secretKey);
  return parsed.secretKey;
}

export function clearTurnstileSecretCacheForTests(): void {
  secretCache.clear();
}
