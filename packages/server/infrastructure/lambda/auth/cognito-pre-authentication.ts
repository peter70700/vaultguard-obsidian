import { docClient, SESSIONS_TABLE } from '../shared/utils';
import { consumeLoginPermit } from '../shared/login-permit';
import { loadTurnstileSecret } from '../shared/turnstile';
import type { LoginVerificationMode } from './human-verification';

interface CognitoPreAuthenticationEvent {
  callerContext?: { clientId?: string };
  request?: {
    userAttributes?: Record<string, string | undefined>;
    clientMetadata?: Record<string, string | undefined>;
  };
  response?: Record<string, unknown>;
  [key: string]: unknown;
}

interface PreAuthenticationDependencies {
  mode: LoginVerificationMode;
  managedClientIds: readonly string[];
  send: (command: unknown) => Promise<any>;
  tableName: string;
  bindingSecret: string;
  nowMs?: number;
  logger?: Pick<Console, 'info'>;
}

function parseMode(value: string | undefined): LoginVerificationMode {
  if (value === undefined || value === '' || value === 'disabled') return 'disabled';
  if (value === 'observe' || value === 'enforce') return value;
  throw new Error('Invalid login verification configuration');
}

async function runtimeDependencies(): Promise<PreAuthenticationDependencies> {
  const mode = parseMode(process.env.LOGIN_VERIFICATION_MODE);
  let bindingSecret = '';
  if (mode !== 'disabled') {
    try {
      bindingSecret = await loadTurnstileSecret(process.env.TURNSTILE_SECRET_ARN ?? '');
    } catch {
      // `observe` must never become enforcement because provider
      // configuration is unavailable. A blank binding fails validation and
      // emits the same bounded rejected outcome below; `enforce` then rejects.
      bindingSecret = '';
    }
  }
  return {
    mode,
    managedClientIds: (process.env.LOGIN_VERIFICATION_CLIENT_IDS ?? '')
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean),
    send: (command) => docClient.send(command as never),
    tableName: SESSIONS_TABLE,
    bindingSecret,
  };
}

function reject(): never {
  throw new Error('Sign-in verification failed. Start again.');
}

/**
 * Cognito Pre Authentication trigger. It sees credentials only inside Cognito;
 * this function receives trusted identity attributes plus opaque client
 * metadata and atomically consumes one server-side permit.
 */
export async function cognitoPreAuthenticationHandler<T extends CognitoPreAuthenticationEvent>(
  event: T,
  suppliedDeps?: PreAuthenticationDependencies,
): Promise<T> {
  let deps: PreAuthenticationDependencies;
  try {
    deps = suppliedDeps ?? await runtimeDependencies();
  } catch {
    reject();
  }
  if (deps.mode === 'disabled') return event;

  const clientId = event.callerContext?.clientId ?? '';
  if (!clientId || deps.managedClientIds.length === 0) {
    (deps.logger ?? console).info('[LOGIN_PERMIT]', {
      mode: deps.mode,
      outcome: 'rejected',
      reason: 'configuration_invalid',
    });
    if (deps.mode === 'enforce') reject();
    return event;
  }
  if (!deps.managedClientIds.includes(clientId)) return event;

  const metadata = event.request?.clientMetadata ?? {};
  const attributes = event.request?.userAttributes ?? {};
  const attemptId = metadata.vaultguardAttemptId ?? '';
  const permit = metadata.vaultguardLoginPermit ?? '';
  const clientSurface = metadata.vaultguardClientSurface;
  const boundClientSurface = clientSurface === 'plugin' || clientSurface === 'web'
    ? clientSurface
    : null;
  const email = attributes.email ?? '';
  const orgId = attributes['custom:org'] ?? '';

  // ClientMetadata is caller-supplied, so surface is a confusion-resistant
  // consistency binding rather than an independent trust signal. The trusted
  // Cognito callerContext client ID and account/org attributes remain the
  // authoritative boundaries. Requiring the stored surface still prevents a
  // permit issued for one managed flow from being accidentally consumed by the
  // other flow.
  let valid = Boolean(
    attemptId &&
    permit &&
    boundClientSurface &&
    email &&
    orgId &&
    deps.bindingSecret,
  );
  if (valid && boundClientSurface) {
    try {
      await consumeLoginPermit({
        permit,
        attemptId,
        purpose: 'login',
        bindingPolicy: boundClientSurface === 'web'
          ? 'allow_account'
          : 'require_organization',
        orgId,
        normalizedEmail: email,
        clientId,
        clientSurface: boundClientSurface,
        nowMs: deps.nowMs,
      }, {
        send: deps.send,
        tableName: deps.tableName,
        bindingSecret: deps.bindingSecret,
      });
    } catch {
      valid = false;
    }
  }

  (deps.logger ?? console).info('[LOGIN_PERMIT]', {
    mode: deps.mode,
    outcome: valid ? 'accepted' : 'rejected',
    reason: valid ? 'permit_consumed' : 'invalid_permit',
  });
  if (!valid && deps.mode === 'enforce') reject();
  return event;
}
