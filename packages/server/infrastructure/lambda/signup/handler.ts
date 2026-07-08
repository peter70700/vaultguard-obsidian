/**
 * VaultGuard — Signup & Org Provisioning Lambda
 *
 * Handles public signup (no auth required) and org auto-provisioning.
 * Also serves the public org config endpoint for plugin auto-discovery.
 *
 * Endpoints:
 * - POST /signup           — Create org + admin user (public, no auth)
 * - GET  /orgs/{slug}/config — Public config for plugin auto-discovery
 * - GET  /.well-known/vaultguard.json — Public config for single-org self-hosts
 */

import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import {
  CognitoIdentityProviderClient,
  AdminCreateUserCommand,
  AdminSetUserPasswordCommand,
  AdminAddUserToGroupCommand,
  AdminGetUserCommand,
  CreateGroupCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import {
  docClient,
  logAudit,
  formatError,
  formatSuccess,
  parseBody,
  validateRequiredFields,
  getClientIp,
  getUserAgent,
  generateId,
  PutCommand,
  QueryCommand,
  GetCommand,
  ScanCommand,
  ORGANIZATIONS_TABLE,
  VAULTS_TABLE,
  VAULT_MEMBERS_TABLE,
  SUBSCRIPTIONS_TABLE,
  PLAN_LIMITS,
  VaultRecord,
  VaultMemberRecord,
  parseExemptDomains,
  isBillingExemptEmail,
  isReservedGroupName,
} from '../shared/utils';
import { EDITION, FEATURES } from '../shared/edition';
import { sendEmail } from '../email/handler';

// ─── Configuration ───────────────────────────────────────────────────────────

const REGION = process.env.AWS_REGION || 'eu-central-1';
const USER_POOL_ID = process.env.USER_POOL_ID!;
const CLIENT_ID = process.env.CLIENT_ID!;
const TURNSTILE_SECRET_ARN = process.env.TURNSTILE_SECRET_ARN || '';

// Email domains flagged as internal/company accounts. LA6: a domain match is
// NOT proof of mailbox ownership (signup never verifies email), so it no
// longer self-grants `comped` — it only stamps an inert
// `billingExemptDomain: true` marker on the Subscriptions row. An operator
// flips `comped: true` deliberately (superadmin/console) after recognizing
// the org; until then exempt-domain orgs sit in `pending_checkout` like
// everyone else.
const BILLING_EXEMPT_DOMAINS = parseExemptDomains(process.env.BILLING_EXEMPT_DOMAINS);

const cognitoClient = new CognitoIdentityProviderClient({ region: REGION });

// ─── Cloudflare Turnstile (cold-start cache) ────────────────────────────────
// Mirrors the Stripe Secrets Manager pattern in billing/handler.ts:51-73.
// When TURNSTILE_SECRET_ARN is empty (Community Edition / self-host without
// Cloudflare), the secret resolver returns "" and verification is skipped.

const smClient = new SecretsManagerClient({});
let cachedTurnstileSecret: string | null = null;

async function getTurnstileSecret(): Promise<string> {
  if (cachedTurnstileSecret !== null) return cachedTurnstileSecret;
  if (TURNSTILE_SECRET_ARN === '') {
    // CE signal — do NOT cache so a redeploy that sets the ARN takes effect
    // on the next cold start without code changes.
    return '';
  }

  const result = await smClient.send(
    new GetSecretValueCommand({ SecretId: TURNSTILE_SECRET_ARN })
  );
  if (!result.SecretString) {
    throw new Error('Turnstile secret payload is empty');
  }

  let parsed: { secretKey?: string };
  try {
    parsed = JSON.parse(result.SecretString) as { secretKey?: string };
  } catch (err) {
    throw new Error(
      `Failed to parse Turnstile secret JSON: ${(err as Error).message}`
    );
  }
  if (!parsed.secretKey) {
    throw new Error('Turnstile secret JSON is missing "secretKey" field');
  }
  cachedTurnstileSecret = parsed.secretKey;
  return cachedTurnstileSecret;
}

async function verifyTurnstile(
  token: string,
  remoteip: string | undefined
): Promise<boolean> {
  try {
    const secret = await getTurnstileSecret();
    if (!secret) return false;

    const params = new URLSearchParams();
    params.append('secret', secret);
    params.append('response', token);
    if (remoteip) params.append('remoteip', remoteip);

    const response = await fetch(
      'https://challenges.cloudflare.com/turnstile/v0/siteverify',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: params.toString(),
      }
    );
    if (!response.ok) return false;

    const data = (await response.json()) as { success?: boolean };
    return data?.success === true;
  } catch (err) {
    console.error('[signup] Turnstile siteverify call failed', err);
    return false;
  }
}

/**
 * Returns a 400 error response with the `turnstile_failed` marker code so the
 * admin-panel can distinguish CAPTCHA failures from generic validation errors
 * (and reset the widget). Reuses the same response shape as formatError().
 */
function formatTurnstileError(
  message: string,
  requestId: string
): APIGatewayProxyResult {
  const base = formatError(400, message, requestId);
  const body = JSON.parse(base.body);
  body.code = 'turnstile_failed';
  return { ...base, body: JSON.stringify(body) };
}

/** Derive the API base URL from the incoming request context. */
function getApiUrl(event: APIGatewayProxyEvent): string {
  const { requestContext } = event;
  if (requestContext?.domainName && requestContext?.stage) {
    return `https://${requestContext.domainName}/${requestContext.stage}/`;
  }
  return process.env.API_URL || '';
}

// ─── Main Handler ────────────────────────────────────────────────────────────

export async function handler(event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> {
  const requestId = event.requestContext?.requestId || generateId();
  const method = event.httpMethod?.toUpperCase();
  const resource = event.resource || '';

  try {
    switch (true) {
      case method === 'POST' && resource === '/signup':
        return await handleSignup(event, requestId);

      case method === 'GET' && (resource === '/orgs/{slug}/config' || resource === '/orgs/{orgId}/config'):
        return await handleOrgConfig(event, requestId);

      case method === 'GET' && resource === '/.well-known/vaultguard.json':
        return await handleWellKnownConfig(event, requestId);

      default:
        return formatError(404, `Route not found: ${method} ${resource}`, requestId);
    }
  } catch (err: unknown) {
    console.error('[SIGNUP_HANDLER_ERROR]', (err as Error).message);

    if (err && typeof err === 'object' && 'statusCode' in err) {
      const typed = err as { statusCode: number; message: string; code?: string };
      return formatError(typed.statusCode, typed.message, requestId, typed.code);
    }

    return formatError(500, 'Internal server error', requestId);
  }
}

// ─── POST /signup ───────────────────────────────────────────────────────────

/**
 * Public signup: creates an organization and its first admin user.
 *
 * Request body:
 * - orgName: Display name for the organization (e.g., "Acme Corp")
 * - orgSlug: URL-safe identifier (e.g., "acme-corp") — must be unique
 * - email: Admin user email
 * - password: Admin user password (must meet Cognito policy)
 * - displayName: Admin user display name
 *
 * Provisioning steps:
 * 1. Validate slug uniqueness
 * 2. Create org record in DynamoDB
 * 3. Create Cognito group for the org
 * 4. Create Cognito admin user
 * 5. Seed a default vault (owner added as admin)
 */
async function handleSignup(
  event: APIGatewayProxyEvent,
  requestId: string
): Promise<APIGatewayProxyResult> {
  // Community Edition is single-tenant by default: once the first org exists,
  // public signup is locked. Self-hosters can opt back in by setting
  // VAULTGUARD_ALLOW_PUBLIC_SIGNUP=true on the signup lambda. Pro (managed
  // SaaS) keeps public signup open so new customers can sign up unattended.
  if (EDITION === 'community' && process.env.VAULTGUARD_ALLOW_PUBLIC_SIGNUP !== 'true') {
    if (await hasAnyOrg()) {
      return formatError(
        403,
        'Public signup is disabled on this Community Edition deployment. ' +
          'Set VAULTGUARD_ALLOW_PUBLIC_SIGNUP=true on the signup lambda to re-enable.',
        requestId
      );
    }
  }

  const body = parseBody(event);

  // Turnstile CAPTCHA verification.
  //   Pro / managed SaaS: TURNSTILE_SECRET_ARN is set → token required + verified.
  //   Community Edition: TURNSTILE_SECRET_ARN is empty → skip (fail-open). Self-hosters
  //   gate signup with VAULTGUARD_ALLOW_PUBLIC_SIGNUP=true instead (see handler.ts:117-126).
  const turnstileToken = typeof body.turnstileToken === 'string' ? body.turnstileToken : '';
  const turnstileSecret = await getTurnstileSecret();
  if (turnstileSecret === '') {
    console.warn(
      '[signup] Turnstile not configured (TURNSTILE_SECRET_ARN empty) — skipping verification. ' +
        'This is normal for Community Edition; set TURNSTILE_SECRET_ARN to enable CAPTCHA.'
    );
  } else {
    if (!turnstileToken) {
      return formatTurnstileError('CAPTCHA challenge required.', requestId);
    }
    const remoteip = event.requestContext?.identity?.sourceIp;
    const ok = await verifyTurnstile(turnstileToken, remoteip);
    if (!ok) {
      return formatTurnstileError(
        'CAPTCHA verification failed. Please try again.',
        requestId
      );
    }
  }

  validateRequiredFields(body, ['orgName', 'orgSlug', 'email', 'password', 'displayName']);

  const orgName = (body.orgName as string).trim();
  const orgSlug = (body.orgSlug as string).trim().toLowerCase();
  const email = (body.email as string).trim().toLowerCase();
  const password = body.password as string;
  const displayName = (body.displayName as string).trim();

  // Validate slug format: alphanumeric + hyphens, 3-48 chars
  if (!/^[a-z0-9][a-z0-9-]{1,46}[a-z0-9]$/.test(orgSlug)) {
    return formatError(400, 'Org slug must be 3-48 characters, alphanumeric and hyphens only, cannot start/end with hyphen', requestId);
  }

  // Reserved slugs
  const reserved = ['admin', 'api', 'app', 'www', 'auth', 'signup', 'login', 'vaultguard', 'support', 'help', 'docs'];
  if (reserved.includes(orgSlug)) {
    return formatError(400, `Slug "${orgSlug}" is reserved`, requestId);
  }

  // Step 1: Check slug uniqueness
  const existing = await docClient.send(
    new GetCommand({
      TableName: ORGANIZATIONS_TABLE,
      Key: { slug: orgSlug },
    })
  );

  if (existing.Item) {
    return formatError(409, `Organization slug "${orgSlug}" is already taken`, requestId);
  }

  const orgId = generateId();
  const now = new Date().toISOString();
  // SaaS is Pro-only: every new org starts on the Pro plan with a
  // `pending_checkout` subscription (no free tier). The 14-day trial only
  // begins once the user completes Stripe Checkout — until then the
  // subscription gate in shared/utils.ts blocks every non-billing endpoint
  // with HTTP 402 + code:'checkout_required'.
  const tier = 'pro';
  const limits = PLAN_LIMITS[tier];

  // Step 2: Create Cognito user
  // Use email as username so users can sign in with their email address
  const cognitoUsername = email;

  try {
    await cognitoClient.send(
      new AdminCreateUserCommand({
        UserPoolId: USER_POOL_ID,
        Username: cognitoUsername,
        UserAttributes: [
          { Name: 'email', Value: email },
          { Name: 'email_verified', Value: 'true' },
          { Name: 'name', Value: displayName },
          { Name: 'custom:org', Value: orgId },
          { Name: 'custom:orgRole', Value: 'owner' },
          { Name: 'custom:role', Value: 'admin' },
        ],
        TemporaryPassword: password,
        MessageAction: 'SUPPRESS', // Use our own branded emails, not Cognito defaults
      })
    );

    // Set permanent password
    await cognitoClient.send(
      new AdminSetUserPasswordCommand({
        UserPoolId: USER_POOL_ID,
        Username: cognitoUsername,
        Password: password,
        Permanent: true,
      })
    );
  } catch (err: unknown) {
    const errName = (err as { name?: string })?.name;
    if (errName === 'UsernameExistsException') {
      return formatError(409, 'A user with this email already exists', requestId);
    }
    if (errName === 'InvalidPasswordException') {
      return formatError(400, 'Password does not meet requirements: min 12 chars, uppercase, lowercase, digit, symbol', requestId);
    }
    throw err;
  }

  // Step 3: Create Cognito group for the org and add user
  const groupName = `org-${orgSlug}`;
  // Reserved-group guard: request-derived group names must never collide with
  // a privileged platform group (e.g. platform-superadmin).
  if (isReservedGroupName(groupName) || isReservedGroupName(orgSlug)) {
    return formatError(400, 'Requested group name is reserved', requestId);
  }
  try {
    await cognitoClient.send(
      new CreateGroupCommand({
        UserPoolId: USER_POOL_ID,
        GroupName: groupName,
        Description: `Organization: ${orgName}`,
      })
    );
  } catch (err: unknown) {
    // Group may already exist if a previous signup partially failed
    if ((err as { name?: string })?.name !== 'GroupExistsException') {
      throw err;
    }
  }

  // Also create admin group if needed
  try {
    await cognitoClient.send(
      new CreateGroupCommand({
        UserPoolId: USER_POOL_ID,
        GroupName: 'admin',
        Description: 'VaultGuard administrators',
      })
    );
  } catch {
    // Already exists — fine
  }

  await cognitoClient.send(
    new AdminAddUserToGroupCommand({
      UserPoolId: USER_POOL_ID,
      Username: cognitoUsername,
      GroupName: groupName,
    })
  );

  await cognitoClient.send(
    new AdminAddUserToGroupCommand({
      UserPoolId: USER_POOL_ID,
      Username: cognitoUsername,
      GroupName: 'admin',
    })
  );

  // Step 4: Get the userId (Cognito sub)
  const userInfo = await cognitoClient.send(
    new AdminGetUserCommand({
      UserPoolId: USER_POOL_ID,
      Username: cognitoUsername,
    })
  );
  const userId = userInfo.UserAttributes?.find(a => a.Name === 'sub')?.Value || cognitoUsername;

  // Step 5: Create org record
  // Note: omit null Stripe fields — DynamoDB GSI keys cannot be null
  const orgRecord: Record<string, unknown> = {
    slug: orgSlug,
    orgId,
    name: orgName,
    ownerUserId: userId,
    ownerEmail: email,
    tier,
    maxUsers: limits.maxUsers,
    maxStorageBytes: limits.maxStorageBytes,
    currentUsers: 1,
    currentStorageBytes: 0,
    settings: {
      syncMode: 'periodic',
      syncIntervalMinutes: 1,
      enforceEncryption: true,
      // 720h = 30 days — persistent trusted device (Phase 12 change #5). The cap is
      // still enforced by assertSessionAgePolicy; this only raises the new-org default.
      maxSessionDurationHours: 720,
      requireMfa: false,
      allowedDomains: [],
      retentionDays: 365,
      autoLockMinutes: 30,
      // O-1 humane default: brand-new orgs LOCK (evict keys + local-PIN
      // unlock) instead of full logout on idle. Existing orgs have no
      // idleAction key and normalize to 'logout' via normalizeStoredOrgSettings
      // — so shipping this never silently switches a deployed org to lock.
      idleAction: 'lock',
    },
    createdAt: now,
    updatedAt: now,
    status: 'active',
  };

  // LA5: make slug uniqueness atomic. The Step-1 Get check is a TOCTOU — two
  // concurrent signups for the same slug both pass it, then the second Put
  // overwrites the first org's record (orgId/owner/tier), so the first owner's
  // Cognito custom:org points at a row that now belongs to someone else. A
  // conditional write makes the Put itself the uniqueness gate; the Get stays a
  // fast-path.
  try {
    await docClient.send(
      new PutCommand({
        TableName: ORGANIZATIONS_TABLE,
        Item: orgRecord,
        ConditionExpression: 'attribute_not_exists(slug)',
      })
    );
  } catch (err: unknown) {
    if (err && typeof err === 'object' && (err as { name?: string }).name === 'ConditionalCheckFailedException') {
      // Lost the race — another concurrent signup claimed this slug between the
      // Step-1 Get and now. Same response as the Step-1 check.
      return formatError(409, `Organization slug "${orgSlug}" is already taken`, requestId);
    }
    throw err;
  }

  // Step 5b: Write a `pending_checkout` Subscriptions row so the new org is
  // visible to the billing surface (so it can complete checkout) but BLOCKED
  // by `assertSubscriptionAllowsAccess` from every other endpoint. On Stripe
  // checkout success the webhook overwrites this row with the real
  // `trialing`/`active` state. Community Edition deployments skip the gate
  // (`assertSubscriptionAllowsAccess` returns early when EDITION !== 'pro'),
  // so this row is harmless on self-hosts even though SUBSCRIPTIONS_TABLE
  // exists in their schema.
  // LA6: exempt-domain owners are NOT auto-comped — email is never verified
  // at signup, so anyone who learns an internal domain could self-grant a
  // free active org. The domain match only leaves an inert
  // `billingExemptDomain` marker for the operator, who comps the org
  // deliberately; until then it is paywalled like every other signup.
  const billingExempt = isBillingExemptEmail(email, BILLING_EXEMPT_DOMAINS);
  await docClient.send(
    new PutCommand({
      TableName: SUBSCRIPTIONS_TABLE,
      Item: {
        orgId,
        plan: tier,
        status: 'pending_checkout',
        ...(billingExempt ? { billingExemptDomain: true } : {}),
        cancelAtPeriodEnd: false,
        quantity: 1,
        createdAt: now,
        updatedAt: now,
      },
    })
  );

  // Step 6: Seed a default vault. Every org needs at least one vault for the
  // plugin to bind to — without it the user lands in the picker with nothing
  // to pick. We auto-create a `default` vault and add the org owner as its
  // admin. We deliberately do NOT seed a wildcard allow-all permission rule
  // (one matching every user on every path): it would grant all five actions
  // to every member and silently override viewer/editor role limits. Role
  // enforcement instead flows through evaluatePermission's membership-baseline
  // fallback (shared/utils.ts), and member-add / invite flows seed explicit
  // per-user rules.
  const defaultVaultId = generateId();
  const defaultVault: VaultRecord = {
    orgId,
    vaultId: defaultVaultId,
    name: `${orgName} — Default`,
    slug: 'default',
    kind: 'team',
    defaultRole: 'editor',
    createdAt: now,
    createdBy: userId,
    archived: false,
    description: 'Default vault auto-created at signup.',
  };
  await docClient.send(
    new PutCommand({
      TableName: VAULTS_TABLE,
      Item: defaultVault,
    })
  );

  const ownerMembership: VaultMemberRecord = {
    vaultId: defaultVaultId,
    userId,
    role: 'admin',
    joinedAt: now,
    invitedBy: userId,
  };
  await docClient.send(
    new PutCommand({
      TableName: VAULT_MEMBERS_TABLE,
      Item: ownerMembership,
    })
  );

  await logAudit({
    userId,
    userEmail: email,
    orgId,
    action: 'org.created',
    resourcePath: `/orgs/${orgSlug}`,
    outcome: 'success',
    ipAddress: getClientIp(event),
    userAgent: getUserAgent(event),
    metadata: { orgId, orgSlug, orgName, tier, email },
  });

  // Send welcome email to new org admin
  await sendEmail('welcome', {
    email,
    orgName: orgName,
    orgSlug: orgSlug,
    adminName: displayName || email.split('@')[0],
  });

  return formatSuccess(
    201,
    {
      message: 'Organization created successfully',
      org: {
        slug: orgSlug,
        orgId,
        name: orgName,
        tier,
      },
      user: {
        userId,
        email,
        displayName,
        role: 'owner',
        loginUsername: email, // Users log in with email
      },
      vault: {
        vaultId: defaultVaultId,
        name: defaultVault.name,
        slug: defaultVault.slug,
      },
      config: buildOrgConfig(orgSlug, orgId, orgName, getApiUrl(event)),
    },
    requestId
  );
}

// ─── GET /orgs/{slug}/config ────────────────────────────────────────────────

/**
 * Public endpoint: returns the config the Obsidian plugin needs to connect.
 * No authentication required — the config contains no secrets.
 *
 * Returns:
 * - apiEndpoint: The API Gateway URL
 * - cognitoUserPoolId: Cognito pool ID
 * - cognitoClientId: Cognito app client ID
 * - cognitoRegion: AWS region
 * - orgId: Internal org ID
 * - orgName: Display name
 */
async function handleOrgConfig(
  event: APIGatewayProxyEvent,
  requestId: string
): Promise<APIGatewayProxyResult> {
  const slug = event.pathParameters?.slug || event.pathParameters?.orgId || '';

  if (!slug) {
    return formatError(400, 'Organization slug is required', requestId);
  }

  // Look up by slug first
  let org = await getOrgBySlug(slug);

  // If not found by slug, try by orgId
  if (!org) {
    org = await getOrgByOrgId(slug);
  }

  if (!org) {
    return formatError(404, `Organization not found: ${slug}`, requestId);
  }

  if (org.status !== 'active') {
    return formatError(403, 'Organization is suspended or cancelled', requestId);
  }

  return formatSuccess(200, buildOrgConfig(org.slug as string, org.orgId as string, org.name as string, getApiUrl(event)), requestId);
}

// ─── GET /.well-known/vaultguard.json ────────────────────────────────────────

/**
 * Public, unauthenticated endpoint for self-hosted single-tenant deployments.
 * Returns the minimal connection config the plugin needs to bootstrap without
 * the user knowing their org slug.
 *
 * Security posture (per pre-commit review WR-01 / WR-02):
 *
 * - The endpoint is **only** served on Community Edition single-tenant
 *   deployments. On Cloud (multi-tenant) it returns 404 indistinguishable
 *   from the no-org case, so an outsider scanning example.com cannot
 *   fingerprint which edition runs a given installation. Cloud uses
 *   /orgs/{slug}/config for discovery.
 * - Response body intentionally omits `orgId` and `orgName` — neither is
 *   needed before login and `orgName` is admin-set free text that could
 *   contain the legal entity name. The plugin fetches these post-auth.
 * - `Cache-Control: public, max-age=300` lets CloudFront/intermediaries
 *   absorb repeat requests, reducing the per-request DynamoDB Scan cost.
 *
 * The Cognito User Pool ID and App Client ID in the response ARE public by
 * design — Cognito treats them as OAuth client identifiers, not secrets,
 * and any unauthenticated client must present them during sign-in. See the
 * matching note in `src/config/saas-defaults.ts`.
 */
async function handleWellKnownConfig(
  event: APIGatewayProxyEvent,
  requestId: string
): Promise<APIGatewayProxyResult> {
  // Cloud/multi-tenant deployments never serve this endpoint. The single-org
  // discovery semantic doesn't apply there, and a 200/409 response would
  // fingerprint the edition to unauthenticated callers.
  if (EDITION !== 'community') {
    return formatError(404, 'Not found.', requestId);
  }

  const org = await getSingleActiveOrg();
  // Collapse "no org" and "multiple orgs" into the same 404 response so an
  // unauthenticated scanner cannot tell a fresh single-org install apart
  // from a multi-org one.
  if (!org || org === 'multiple') {
    return formatError(404, 'Not found.', requestId);
  }

  const body = buildWellKnownConfig(org.slug as string, getApiUrl(event));
  return {
    statusCode: 200,
    headers: {
      ...wellKnownSecurityHeaders(requestId),
      'Cache-Control': 'public, max-age=300',
    },
    body: JSON.stringify(body),
  };
}

/**
 * Minimal config shape for the unauthenticated /.well-known/vaultguard.json
 * response. Deliberately omits `orgId` and `orgName` (which `buildOrgConfig`
 * includes) — those require an authenticated caller.
 */
function buildWellKnownConfig(
  slug: string,
  apiUrl?: string
): Record<string, unknown> {
  return {
    apiEndpoint: apiUrl || '',
    cognitoUserPoolId: USER_POOL_ID,
    cognitoClientId: CLIENT_ID,
    cognitoRegion: REGION,
    orgSlug: slug,
    edition: EDITION,
    features: FEATURES,
  };
}

/**
 * Same standard security headers as formatSuccess, but expressed as a plain
 * object so the well-known handler can override Cache-Control. Mirrors
 * SECURITY_HEADERS in shared/utils.ts.
 */
function wellKnownSecurityHeaders(requestId: string): Record<string, string> {
  const allowedOrigin = process.env.ALLOWED_CORS_ORIGIN || 'https://admin.example.com';
  return {
    'Content-Type': 'application/json',
    'X-Request-Id': requestId,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Headers': 'Content-Type,Authorization,X-VaultGuard-Session-Id',
  };
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function buildOrgConfig(
  slug: string,
  orgId: string,
  orgName?: string,
  apiUrl?: string
): Record<string, unknown> {
  return {
    apiEndpoint: apiUrl || '',
    cognitoUserPoolId: USER_POOL_ID,
    cognitoClientId: CLIENT_ID,
    cognitoRegion: REGION,
    orgId,
    orgSlug: slug,
    orgName: orgName || slug,
    edition: EDITION,
    features: FEATURES,
  };
}

async function getOrgBySlug(slug: string): Promise<Record<string, unknown> | null> {
  const result = await docClient.send(
    new GetCommand({
      TableName: ORGANIZATIONS_TABLE,
      Key: { slug },
    })
  );
  return result.Item as Record<string, unknown> | null ?? null;
}

/**
 * Returns true if at least one org record exists. Used by the CE single-tenant
 * guard — a 1-item Scan is cheap enough for this admin-control check.
 */
async function hasAnyOrg(): Promise<boolean> {
  const result = await docClient.send(
    new ScanCommand({
      TableName: ORGANIZATIONS_TABLE,
      Limit: 1,
      ProjectionExpression: 'slug',
    })
  );
  return (result.Items?.length ?? 0) > 0;
}

// Module-level cache for the /.well-known/vaultguard.json result. Since the
// endpoint is unauthenticated and public, the underlying DynamoDB Scan is a
// cost-amplification target — caching the (0|1|multiple) verdict for a short
// window absorbs repeat callers without weakening freshness for the legitimate
// "self-hoster just provisioned, plugin polling" path.
//
// 60-second TTL is the right size: orgs are not created frequently, and the
// 5-minute Cache-Control on the well-known response means CloudFront and
// browser caches handle most traffic; only cache misses reach Lambda.
let cachedSingleActiveOrg: {
  value: Record<string, unknown> | 'multiple' | null;
  expiresAt: number;
} | null = null;
const SINGLE_ACTIVE_ORG_TTL_MS = 60_000;

async function getSingleActiveOrg(): Promise<Record<string, unknown> | 'multiple' | null> {
  const now = Date.now();
  if (cachedSingleActiveOrg && cachedSingleActiveOrg.expiresAt > now) {
    return cachedSingleActiveOrg.value;
  }

  // Server-side FilterExpression prevents Scan from returning soft-deleted /
  // suspended rows. Combined with the early-exit pagination below, this keeps
  // the Lambda's RCU consumption bounded even on tables with many historical
  // org rows.
  let activeOrg: Record<string, unknown> | null = null;
  let lastEvaluatedKey: Record<string, unknown> | undefined;

  do {
    const result = await docClient.send(
      new ScanCommand({
        TableName: ORGANIZATIONS_TABLE,
        ProjectionExpression: 'slug, orgId, #status',
        FilterExpression: '#status = :active',
        ExpressionAttributeNames: {
          '#status': 'status',
        },
        ExpressionAttributeValues: {
          ':active': 'active',
        },
        ExclusiveStartKey: lastEvaluatedKey,
      })
    );

    for (const item of (result.Items ?? []) as Record<string, unknown>[]) {
      if (!activeOrg) {
        activeOrg = item;
      } else {
        // Two active orgs found — short-circuit, no need to scan further.
        cachedSingleActiveOrg = { value: 'multiple', expiresAt: now + SINGLE_ACTIVE_ORG_TTL_MS };
        return 'multiple';
      }
    }
    lastEvaluatedKey = result.LastEvaluatedKey as Record<string, unknown> | undefined;
  } while (lastEvaluatedKey);

  const value = activeOrg;
  cachedSingleActiveOrg = { value, expiresAt: now + SINGLE_ACTIVE_ORG_TTL_MS };
  return value;
}

async function getOrgByOrgId(orgId: string): Promise<Record<string, unknown> | null> {
  const result = await docClient.send(
    new QueryCommand({
      TableName: ORGANIZATIONS_TABLE,
      IndexName: 'orgId-index',
      KeyConditionExpression: 'orgId = :oid',
      ExpressionAttributeValues: { ':oid': orgId },
    })
  );
  return (result.Items?.[0] as Record<string, unknown>) || null;
}
