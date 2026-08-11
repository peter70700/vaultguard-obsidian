import type { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { GetCommand } from '@aws-sdk/lib-dynamodb';
import {
  ORGANIZATIONS_TABLE,
  SESSIONS_TABLE,
  docClient,
} from '../shared/utils';
import {
  LoginPermitError,
  LoginPermitRateLimitError,
  consumeHumanVerificationAttemptBudget,
  createHumanVerificationAttempt,
  exchangeVerifiedAttempt,
  getHumanVerificationAttempt,
  humanVerificationAttemptVerifierMatches,
  markHumanVerificationAttemptVerified,
  type AuthenticationClientSurface,
  type AuthenticationPurpose,
  type LoginPermitBindingScope,
} from '../shared/login-permit';
import {
  loadTurnstileSecret,
  verifyTurnstileProof,
  type TurnstileTransport,
} from '../shared/turnstile';

export type LoginVerificationMode = 'disabled' | 'observe' | 'enforce';

export interface HumanVerificationHandlerDependencies {
  mode: LoginVerificationMode;
  send: (command: unknown) => Promise<any>;
  sessionsTableName: string;
  organizationsTableName: string;
  bindingSecret: string;
  browserCompletionBaseUrl: string;
  expectedHostnames: readonly string[];
  allowedOrigins?: readonly string[];
  nowMs?: number;
  attemptId?: string;
  permit?: string;
  turnstileTransport?: TurnstileTransport;
}

function parseMode(value: string | undefined): LoginVerificationMode {
  if (value === undefined || value === '' || value === 'disabled') return 'disabled';
  if (value === 'observe' || value === 'enforce') return value;
  throw new Error('Invalid login verification configuration');
}

function response(
  statusCode: number,
  body: Record<string, unknown>,
  requestId: string,
  allowedOrigin?: string,
): APIGatewayProxyResult {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'x-request-id': requestId,
      ...(allowedOrigin ? { 'Access-Control-Allow-Origin': allowedOrigin } : {}),
    },
    body: JSON.stringify(body),
  };
}

function genericError(
  statusCode: number,
  requestId: string,
  allowedOrigin?: string,
): APIGatewayProxyResult {
  return response(statusCode, {
    code: 'verification_unavailable',
    message: 'Human verification could not be completed. Start again.',
    requestId,
  }, requestId, allowedOrigin);
}

function parseBody(event: APIGatewayProxyEvent): Record<string, unknown> {
  if (!event.body) return {};
  try {
    const value = JSON.parse(event.body) as unknown;
    return value && typeof value === 'object' && !Array.isArray(value)
      ? value as Record<string, unknown>
      : {};
  } catch {
    return {};
  }
}

async function runtimeDependencies(): Promise<HumanVerificationHandlerDependencies> {
  const mode = parseMode(process.env.LOGIN_VERIFICATION_MODE);
  const secretArn = process.env.TURNSTILE_SECRET_ARN ?? '';
  // Disabled is the migration-safe default and must not depend on provider
  // availability. Observe/enforce still fail the public exchange generically
  // when the required secret cannot be loaded.
  const bindingSecret = mode === 'disabled' ? '' : await loadTurnstileSecret(secretArn);
  return {
    mode,
    send: (command) => docClient.send(command as never),
    sessionsTableName: SESSIONS_TABLE,
    organizationsTableName: ORGANIZATIONS_TABLE,
    bindingSecret,
    browserCompletionBaseUrl:
      process.env.LOGIN_VERIFICATION_BROWSER_URL ??
      'https://auth.example.com/complete',
    expectedHostnames: (
      process.env.TURNSTILE_EXPECTED_HOSTNAMES ??
      'admin.example.com,auth.example.com'
    )
      .split(',')
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean),
    allowedOrigins: (
      process.env.LOGIN_VERIFICATION_ALLOWED_ORIGINS ??
      'https://admin.example.com,https://auth.example.com'
    )
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean),
  };
}

function validPurpose(value: unknown): value is AuthenticationPurpose {
  return value === 'login' || value === 'signup';
}

function validSurface(value: unknown): value is AuthenticationClientSurface {
  return value === 'plugin' || value === 'web';
}

function expectedHostnameForSurface(
  clientSurface: AuthenticationClientSurface,
  hostnames: readonly string[],
  browserCompletionBaseUrl: string,
): string {
  let completionHostname = '';
  try {
    completionHostname = new URL(browserCompletionBaseUrl).hostname.toLowerCase();
  } catch {
    // Configuration is rejected by the empty result below.
  }
  if (clientSurface === 'plugin' && hostnames.includes(completionHostname)) {
    return completionHostname;
  }
  if (clientSurface === 'web') {
    const inlineHostname = hostnames.find(hostname => hostname !== completionHostname);
    if (inlineHostname) return inlineHostname;
  }
  return hostnames[0] ?? '';
}

/**
 * Public pre-authentication endpoints. Responses are deliberately generic and
 * never include raw account, verifier or provider details.
 */
export async function handleHumanVerificationRequest(
  event: APIGatewayProxyEvent,
  requestId: string,
  suppliedDeps?: HumanVerificationHandlerDependencies,
): Promise<APIGatewayProxyResult> {
  let deps: HumanVerificationHandlerDependencies;
  try {
    deps = suppliedDeps ?? await runtimeDependencies();
  } catch {
    return genericError(503, requestId);
  }

  if (deps.mode === 'disabled') {
    const requestOrigin = event.headers?.origin ?? event.headers?.Origin ?? '';
    const allowedOrigin = deps.allowedOrigins?.includes(requestOrigin) ? requestOrigin : undefined;
    return response(409, {
      code: 'verification_disabled',
      message: 'Human verification is not enabled for this client.',
      requestId,
    }, requestId, allowedOrigin);
  }

  const body = parseBody(event);
  const path = event.resource || event.path;
  const nowMs = deps.nowMs ?? Date.now();
  const requestOrigin = event.headers?.origin ?? event.headers?.Origin ?? '';
  const allowedOrigin = deps.allowedOrigins?.includes(requestOrigin) ? requestOrigin : undefined;
  const reply = (statusCode: number, body: Record<string, unknown>) =>
    response(statusCode, body, requestId, allowedOrigin);
  const fail = (statusCode: number) => genericError(statusCode, requestId, allowedOrigin);
  const storeDeps = {
    send: deps.send,
    tableName: deps.sessionsTableName,
    bindingSecret: deps.bindingSecret,
  };

  try {
    if (event.httpMethod === 'POST' && path === '/auth/human-verification/attempts') {
      const purpose = body.purpose;
      const orgSlug = typeof body.orgSlug === 'string' ? body.orgSlug.trim().toLowerCase() : '';
      const email = typeof body.email === 'string' ? body.email : '';
      const clientId = typeof body.clientId === 'string' ? body.clientId.trim() : '';
      const clientSurface = body.clientSurface;
      const verifierHash = typeof body.verifierHash === 'string' ? body.verifierHash : '';
      if (!validPurpose(purpose) || !validSurface(clientSurface) || !email || !clientId) {
        return fail(400);
      }

      // The admin web login is account-first: Cognito supplies the trusted
      // organization after it validates the credentials. Legacy web clients,
      // plugin logins, and non-login purposes remain organization-bound.
      const bindingScope: LoginPermitBindingScope =
        purpose === 'login' && clientSurface === 'web' && !orgSlug
          ? 'account'
          : 'organization_account';
      let orgId: string | undefined;
      if (bindingScope === 'organization_account') {
        if (!orgSlug) return fail(400);
        const org = await deps.send(new GetCommand({
          TableName: deps.organizationsTableName,
          Key: { slug: orgSlug },
          ProjectionExpression: 'orgId',
        }));
        orgId = typeof org.Item?.orgId === 'string' ? org.Item.orgId : undefined;
      }
      const expectedHostname = validSurface(clientSurface)
        ? expectedHostnameForSurface(
            clientSurface,
            deps.expectedHostnames,
            deps.browserCompletionBaseUrl,
          )
        : '';
      if (
        (bindingScope === 'organization_account' && !orgId) ||
        !expectedHostname ||
        !deps.bindingSecret
      ) {
        return fail(400);
      }

      await consumeHumanVerificationAttemptBudget({
        bindingScope,
        orgId,
        normalizedEmail: email,
        clientId,
        clientSurface,
        nowMs,
      }, storeDeps);

      const created = await createHumanVerificationAttempt({
        purpose,
        bindingScope,
        orgId,
        normalizedEmail: email,
        clientId,
        clientSurface,
        verifierHash,
        expectedHostname,
        nowMs,
        attemptId: deps.attemptId,
      }, storeDeps);
      const completionUrl = new URL(deps.browserCompletionBaseUrl);
      completionUrl.searchParams.set('attempt', created.attemptId);
      return reply(201, {
        state: 'pending',
        attemptId: created.attemptId,
        expiresAtMs: created.expiresAtMs,
        completionUrl: completionUrl.toString(),
        retryAfterMs: 1000,
      });
    }

    if (event.httpMethod === 'POST' && path === '/auth/human-verification/complete') {
      const attemptId = typeof body.attemptId === 'string' ? body.attemptId : '';
      const token = typeof body.turnstileToken === 'string' ? body.turnstileToken : '';
      if (!attemptId || !token || !deps.bindingSecret) return fail(400);
      const attempt = await getHumanVerificationAttempt(attemptId, storeDeps);
      if (attempt.state !== 'pending' || attempt.expiresAtMs <= nowMs) {
        return fail(400);
      }
      const verified = await verifyTurnstileProof({
        token,
        secret: deps.bindingSecret,
        remoteIp: event.requestContext?.identity?.sourceIp,
        expectedHostnames: [attempt.expectedHostname],
        expectedAction: attempt.expectedAction,
        expectedCdata: attempt.expectedCdata,
        nowMs,
      }, { transport: deps.turnstileTransport });
      if (!verified.ok) return fail(400);
      await markHumanVerificationAttemptVerified(attemptId, nowMs, storeDeps);
      return reply(200, { state: 'complete' });
    }

    if (event.httpMethod === 'POST' && path === '/auth/human-verification/poll') {
      const attemptId = typeof body.attemptId === 'string' ? body.attemptId : '';
      const verifier = typeof body.verifier === 'string' ? body.verifier : '';
      if (!attemptId || !verifier) return fail(400);
      const attempt = await getHumanVerificationAttempt(attemptId, storeDeps);
      if (
        attempt.expiresAtMs <= nowMs ||
        !humanVerificationAttemptVerifierMatches(attempt, verifier)
      ) {
        return fail(400);
      }
      if (attempt.state === 'pending') {
        return reply(200, { state: 'pending', retryAfterMs: 1000 });
      }
      if (attempt.state !== 'verified') return fail(400);
      const exchanged = await exchangeVerifiedAttempt({
        attemptId,
        rawVerifier: verifier,
        nowMs,
        permit: deps.permit,
      }, storeDeps);
      return reply(200, {
        state: 'verified',
        permit: exchanged.permit,
        expiresAtMs: exchanged.expiresAtMs,
      });
    }

    return fail(404);
  } catch (error) {
    if (error instanceof LoginPermitRateLimitError) return fail(429);
    if (error instanceof LoginPermitError) return fail(400);
    return fail(503);
  }
}
