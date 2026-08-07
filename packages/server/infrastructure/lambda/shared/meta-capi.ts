/**
 * VaultGuard — Meta Conversions API (server-side marketing events)
 *
 * Sends CompleteRegistration / StartTrial / Purchase to Meta's Conversions API
 * so paid-acquisition campaigns can attribute conversions that never happen in
 * a browser (trial start and first payment are both Stripe webhooks).
 *
 * HARD RULE: nothing in this module may throw into a caller. Signup and billing
 * must succeed even when Meta is down, throttling, or misconfigured. Every
 * public function swallows its own errors and logs them. A marketing pixel is
 * never allowed to fail a registration or a payment.
 *
 * Configuration (all optional — if either of the first two is unset, every send
 * is a silent no-op, which is the correct posture for Community Edition and for
 * self-hosters who must never phone home):
 *
 *   META_DATASET_ID       — Meta dataset / pixel ID. Public value (it also ships
 *                           in the landing page HTML), so a plain env var.
 *   META_CAPI_SECRET_ARN  — Secrets Manager ARN holding {"accessToken":"..."}.
 *                           A secret, mirroring STRIPE_SECRET_ARN.
 *   META_API_VERSION      — Graph API version. Defaults to v21.0.
 *   META_CAPI_TEST_CODE   — Events Manager "Test events" code. Set ONLY while
 *                           validating; events sent with it are excluded from
 *                           reporting and attribution.
 *
 * See docs/META-CAPI-SETUP.md for the operator runbook.
 */

import { createHash } from 'crypto';
import { request as httpsRequest } from 'https';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';

// ─── Configuration ───────────────────────────────────────────────────────────

const META_DATASET_ID = process.env.META_DATASET_ID || '';
const META_CAPI_SECRET_ARN = process.env.META_CAPI_SECRET_ARN || '';
const META_API_VERSION = process.env.META_API_VERSION || 'v21.0';
const META_CAPI_TEST_CODE = process.env.META_CAPI_TEST_CODE || '';

/**
 * Meta is a best-effort side channel. Cap it tight so a hung endpoint cannot
 * inflate Lambda duration on the signup and billing paths.
 */
const REQUEST_TIMEOUT_MS = 3_000;

const LOG_PREFIX = '[meta-capi]';

const smClient = new SecretsManagerClient({});
let cachedAccessToken: string | null = null;

// ─── Types ───────────────────────────────────────────────────────────────────

/** Standard Meta event names this codebase sends. */
export type MetaEventName = 'CompleteRegistration' | 'StartTrial' | 'Purchase';

/**
 * Raw (unhashed, un-normalized) customer information. Callers pass plain
 * values; this module normalizes and hashes whatever Meta requires hashed.
 */
export interface MetaUserDataInput {
  /** Plain email. Normalized (trim + lowercase) then SHA-256 hashed. */
  email?: string | null;
  /** ISO 3166-1 alpha-2. Normalized to lowercase then SHA-256 hashed. */
  country?: string | null;
  /** Stable opaque org identifier. SHA-256 hashed (Meta recommends it). */
  externalId?: string | null;
  /** `_fbp` cookie value. Never hashed. */
  fbp?: string | null;
  /** `_fbc` cookie value (or synthesized from fbclid). Never hashed. */
  fbc?: string | null;
  /** Client IP at the time of the original browser interaction. Never hashed. */
  clientIp?: string | null;
  /** Client user agent at the time of the original interaction. Never hashed. */
  clientUserAgent?: string | null;
  /** Stripe subscription ID. Never hashed. */
  subscriptionId?: string | null;
}

export interface MetaEventInput {
  eventName: MetaEventName;
  /**
   * Deduplication key. MUST match the browser pixel's `eventID` for the same
   * conversion, or be deterministic (e.g. derived from the Stripe object ID) so
   * webhook retries collapse into one event on Meta's side.
   */
  eventId: string;
  /** Where the conversion originated. Required when action_source is "website". */
  eventSourceUrl: string;
  /** Unix seconds. Defaults to now. Meta rejects anything older than 7 days. */
  eventTime?: number;
  userData: MetaUserDataInput;
  /** Purchase and StartTrial only. Major units (e.g. 49.00, not 4900). */
  value?: number | null;
  /** ISO 4217, e.g. "EUR". Required whenever `value` is set. */
  currency?: string | null;
  /** Purchase only. Stripe invoice ID. */
  orderId?: string | null;
}

/**
 * Attribution captured in the browser at signup and persisted on the org record
 * so the later server-only events (StartTrial, Purchase) still carry match keys
 * long after the browser is gone.
 */
export interface MetaAttribution {
  metaFbp?: string;
  metaFbc?: string;
  metaSignupIp?: string;
  metaSignupUserAgent?: string;
  metaSignupUrl?: string;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * True when both the dataset ID and the token ARN are configured. Callers can
 * check this to skip assembling a payload they would only throw away.
 */
export function isMetaCapiConfigured(): boolean {
  return META_DATASET_ID !== '' && META_CAPI_SECRET_ARN !== '';
}

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

/**
 * `getClientIp` / `getUserAgent` in shared/utils.ts fall back to the literal
 * string 'unknown'. Sending that to Meta would poison the match key, so treat
 * it — and empty values — as absent.
 */
function present(value: string | null | undefined): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (trimmed === '' || trimmed === 'unknown') return null;
  return trimmed;
}

async function getAccessToken(): Promise<string> {
  if (cachedAccessToken) return cachedAccessToken;

  const result = await smClient.send(
    new GetSecretValueCommand({ SecretId: META_CAPI_SECRET_ARN }),
  );
  const parsed = JSON.parse(result.SecretString || '{}') as { accessToken?: string };
  if (!parsed.accessToken) {
    throw new Error('META_CAPI_SECRET_ARN secret has no "accessToken" field');
  }

  cachedAccessToken = parsed.accessToken;
  return cachedAccessToken;
}

/**
 * Normalize + hash per Meta's customer information parameter rules. Keys with
 * no usable value are omitted entirely — Meta counts an empty string as a
 * present-but-unmatchable parameter, which drags down event match quality.
 */
function buildUserData(input: MetaUserDataInput): Record<string, unknown> {
  const userData: Record<string, unknown> = {};

  const email = present(input.email);
  if (email) userData.em = sha256(email.toLowerCase());

  const country = present(input.country);
  if (country) userData.country = sha256(country.toLowerCase());

  const externalId = present(input.externalId);
  if (externalId) userData.external_id = sha256(externalId);

  // Never hashed — Meta matches these verbatim.
  const fbp = present(input.fbp);
  if (fbp) userData.fbp = fbp;

  const fbc = present(input.fbc);
  if (fbc) userData.fbc = fbc;

  const clientIp = present(input.clientIp);
  if (clientIp) userData.client_ip_address = clientIp;

  const clientUserAgent = present(input.clientUserAgent);
  if (clientUserAgent) userData.client_user_agent = clientUserAgent;

  const subscriptionId = present(input.subscriptionId);
  if (subscriptionId) userData.subscription_id = subscriptionId;

  return userData;
}

function postToMeta(body: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const payload = Buffer.from(body, 'utf8');

    const req = httpsRequest(
      {
        hostname: 'graph.facebook.com',
        path: `/${META_API_VERSION}/${encodeURIComponent(META_DATASET_ID)}/events`,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': payload.length,
        },
        timeout: REQUEST_TIMEOUT_MS,
      },
      res => {
        const chunks: Buffer[] = [];
        res.on('data', chunk => chunks.push(chunk as Buffer));
        res.on('end', () => {
          const status = res.statusCode || 0;
          if (status >= 200 && status < 300) {
            resolve();
            return;
          }
          reject(
            new Error(
              `Meta CAPI responded ${status}: ${Buffer.concat(chunks).toString('utf8').slice(0, 500)}`,
            ),
          );
        });
      },
    );

    req.on('timeout', () => {
      req.destroy(new Error(`Meta CAPI timed out after ${REQUEST_TIMEOUT_MS}ms`));
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Send one conversion event. Never throws — failures are logged and swallowed.
 *
 * Meta requires at least one customer information parameter; an event with no
 * usable match key is dropped before the network call rather than being sent
 * and rejected.
 */
export async function sendMetaEvent(input: MetaEventInput): Promise<void> {
  if (!isMetaCapiConfigured()) return;

  try {
    const userData = buildUserData(input.userData);

    if (Object.keys(userData).length === 0) {
      console.warn(
        `${LOG_PREFIX} skipping ${input.eventName} (${input.eventId}) — no usable customer information parameters`,
      );
      return;
    }

    const accessToken = await getAccessToken();

    const customData: Record<string, unknown> = {};
    if (typeof input.value === 'number' && Number.isFinite(input.value)) {
      customData.value = input.value;
      customData.currency = (input.currency || 'EUR').toUpperCase();
    }
    const orderId = present(input.orderId);
    if (orderId) customData.order_id = orderId;

    const payload: Record<string, unknown> = {
      // Meta documents the token as a query parameter or a form field. Sent as a
      // body field instead: same documented mechanism, but it keeps the
      // credential out of the request URL, where it would otherwise reach access
      // logs and error traces. A Bearer header is NOT documented for this
      // endpoint — do not "tidy" this into one.
      access_token: accessToken,
      data: [
        {
          event_name: input.eventName,
          event_time: input.eventTime ?? Math.floor(Date.now() / 1000),
          event_id: input.eventId,
          event_source_url: input.eventSourceUrl,
          action_source: 'website',
          user_data: userData,
          ...(Object.keys(customData).length > 0 ? { custom_data: customData } : {}),
        },
      ],
    };
    if (META_CAPI_TEST_CODE) payload.test_event_code = META_CAPI_TEST_CODE;

    await postToMeta(JSON.stringify(payload));

    console.log(
      `${LOG_PREFIX} sent ${input.eventName} (${input.eventId}) with ${Object.keys(userData).length} match keys`,
    );
  } catch (err) {
    // Deliberately swallowed: never fail signup or billing for a marketing event.
    console.error(`${LOG_PREFIX} failed to send ${input.eventName} (${input.eventId}):`, err);
  }
}

/**
 * Pull the persisted browser attribution off an org record. Returns only the
 * keys that are actually present so callers can spread it straight into a
 * `MetaUserDataInput`.
 */
export function readAttribution(orgRecord: Record<string, unknown> | undefined): {
  fbp: string | null;
  fbc: string | null;
  clientIp: string | null;
  clientUserAgent: string | null;
  sourceUrl: string | null;
} {
  const record = orgRecord || {};
  return {
    fbp: present(record.metaFbp as string),
    fbc: present(record.metaFbc as string),
    clientIp: present(record.metaSignupIp as string),
    clientUserAgent: present(record.metaSignupUserAgent as string),
    sourceUrl: present(record.metaSignupUrl as string),
  };
}
