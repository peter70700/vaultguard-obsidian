import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from 'crypto';
import {
  GetCommand,
  PutCommand,
  TransactWriteCommand,
  UpdateCommand,
} from '@aws-sdk/lib-dynamodb';

const ATTEMPT_TTL_MS = 5 * 60_000;
const PERMIT_TTL_MS = 90_000;
const ATTEMPT_RATE_WINDOW_MS = 5 * 60_000;
const ATTEMPT_RATE_LIMIT = 5;
const HASH_PATTERN = /^[a-f0-9]{64}$/;

export type AuthenticationPurpose = 'login' | 'signup';
export type AuthenticationClientSurface = 'plugin' | 'web';
export type LoginPermitBindingScope = 'account' | 'organization_account';
export type LoginPermitBindingPolicy = 'require_organization' | 'allow_account';

export class LoginPermitError extends Error {
  readonly code = 'verification_unavailable';

  constructor() {
    super('Human verification could not be completed. Start again.');
    this.name = 'LoginPermitError';
  }
}

export class LoginPermitRateLimitError extends LoginPermitError {
  constructor() {
    super();
    this.name = 'LoginPermitRateLimitError';
  }
}

export interface LoginPermitDependencies {
  send: (command: unknown) => Promise<any>;
  tableName: string;
  bindingSecret: string;
}

export interface HumanVerificationAttemptRecord {
  sessionId: string;
  recordType: 'human_verification_attempt';
  attemptId: string;
  purpose: AuthenticationPurpose;
  /** Missing on legacy records, which are always treated as organization-bound. */
  bindingScope?: LoginPermitBindingScope;
  orgId?: string;
  accountBinding: string;
  clientId: string;
  clientSurface: AuthenticationClientSurface;
  verifierHash: string;
  expectedHostname: string;
  expectedAction: string;
  expectedCdata: string;
  state: 'pending' | 'verified' | 'exchanged' | 'failed';
  issuedAtMs: number;
  expiresAtMs: number;
  expiresAtTtl: number;
}

export function humanVerificationAttemptVerifierMatches(
  record: Pick<HumanVerificationAttemptRecord, 'verifierHash'>,
  rawVerifier: string,
): boolean {
  return safeHashEqual(record.verifierHash, hashOpaqueValue(rawVerifier));
}

export function normalizeAuthenticationEmail(email: string): string {
  return email.trim().toLowerCase();
}

export function hashOpaqueValue(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

export function accountBindingForEmail(email: string, bindingSecret: string): string {
  return createHmac('sha256', bindingSecret)
    .update('vaultguard-auth-account-v1\0', 'utf8')
    .update(normalizeAuthenticationEmail(email), 'utf8')
    .digest('hex');
}

function safeHashEqual(expected: string, actual: string): boolean {
  if (!HASH_PATTERN.test(expected) || !HASH_PATTERN.test(actual)) return false;
  return timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(actual, 'hex'));
}

function attemptKey(attemptId: string): string {
  return `human-verification-attempt#${attemptId}`;
}

function permitKey(permitHash: string): string {
  return `login-permit#${permitHash}`;
}

function attemptRateKey(
  bindingScope: LoginPermitBindingScope,
  orgId: string | undefined,
  accountBinding: string,
  clientId: string,
  clientSurface: AuthenticationClientSurface,
  windowStartMs: number,
): string {
  const bucket = hashOpaqueValue([
    bindingScope,
    orgId ?? '',
    accountBinding,
    clientId,
    clientSurface,
    String(windowStartMs),
  ].join('\0'));
  return `human-verification-rate#${bucket}`;
}

function actionForPurpose(purpose: AuthenticationPurpose): string {
  return purpose === 'login' ? 'vaultguard_login' : 'vaultguard_signup';
}

/** Atomically caps create-attempt amplification for one account/client bucket. */
export async function consumeHumanVerificationAttemptBudget(
  input: {
    bindingScope: LoginPermitBindingScope;
    orgId?: string;
    normalizedEmail: string;
    clientId: string;
    clientSurface: AuthenticationClientSurface;
    nowMs?: number;
  },
  deps: LoginPermitDependencies,
): Promise<void> {
  if (input.bindingScope === 'organization_account' && !input.orgId) {
    throw new LoginPermitError();
  }
  const nowMs = input.nowMs ?? Date.now();
  const windowStartMs = Math.floor(nowMs / ATTEMPT_RATE_WINDOW_MS) * ATTEMPT_RATE_WINDOW_MS;
  const accountBinding = accountBindingForEmail(input.normalizedEmail, deps.bindingSecret);
  const expiresAtMs = windowStartMs + ATTEMPT_RATE_WINDOW_MS * 2;
  try {
    await deps.send(new UpdateCommand({
      TableName: deps.tableName,
      Key: {
        sessionId: attemptRateKey(
          input.bindingScope,
          input.orgId,
          accountBinding,
          input.clientId,
          input.clientSurface,
          windowStartMs,
        ),
      },
      UpdateExpression:
        'SET recordType = if_not_exists(recordType, :recordType), ' +
        'windowStartMs = if_not_exists(windowStartMs, :windowStartMs), ' +
        'expiresAtMs = :expiresAtMs, expiresAtTtl = :expiresAtTtl ' +
        'ADD attemptCount :one',
      ConditionExpression: 'attribute_not_exists(attemptCount) OR attemptCount < :limit',
      ExpressionAttributeValues: {
        ':recordType': 'human_verification_rate',
        ':windowStartMs': windowStartMs,
        ':expiresAtMs': expiresAtMs,
        ':expiresAtTtl': Math.ceil(expiresAtMs / 1000),
        ':one': 1,
        ':limit': ATTEMPT_RATE_LIMIT,
      },
    }));
  } catch {
    throw new LoginPermitRateLimitError();
  }
}

export async function createHumanVerificationAttempt(
  input: {
    purpose: AuthenticationPurpose;
    bindingScope: LoginPermitBindingScope;
    orgId?: string;
    normalizedEmail: string;
    clientId: string;
    clientSurface: AuthenticationClientSurface;
    verifierHash: string;
    expectedHostname: string;
    nowMs?: number;
    attemptId?: string;
  },
  deps: LoginPermitDependencies,
): Promise<{
  attemptId: string;
  expiresAtMs: number;
  expectedAction: string;
  expectedCdata: string;
}> {
  if (!HASH_PATTERN.test(input.verifierHash)) throw new LoginPermitError();
  if (input.bindingScope === 'organization_account' && !input.orgId) {
    throw new LoginPermitError();
  }
  const nowMs = input.nowMs ?? Date.now();
  const attemptId = input.attemptId ?? randomUUID();
  const expectedAction = actionForPurpose(input.purpose);
  const expectedCdata = `${input.purpose}:${attemptId}`;
  const expiresAtMs = nowMs + ATTEMPT_TTL_MS;
  const record: HumanVerificationAttemptRecord = {
    sessionId: attemptKey(attemptId),
    recordType: 'human_verification_attempt',
    attemptId,
    purpose: input.purpose,
    bindingScope: input.bindingScope,
    ...(input.orgId ? { orgId: input.orgId } : {}),
    accountBinding: accountBindingForEmail(input.normalizedEmail, deps.bindingSecret),
    clientId: input.clientId,
    clientSurface: input.clientSurface,
    verifierHash: input.verifierHash,
    expectedHostname: input.expectedHostname,
    expectedAction,
    expectedCdata,
    state: 'pending',
    issuedAtMs: nowMs,
    expiresAtMs,
    expiresAtTtl: Math.ceil(expiresAtMs / 1000),
  };

  try {
    await deps.send(new PutCommand({
      TableName: deps.tableName,
      Item: record,
      ConditionExpression: 'attribute_not_exists(sessionId)',
    }));
  } catch {
    throw new LoginPermitError();
  }
  return { attemptId, expiresAtMs, expectedAction, expectedCdata };
}

export async function getHumanVerificationAttempt(
  attemptId: string,
  deps: LoginPermitDependencies,
): Promise<HumanVerificationAttemptRecord> {
  const result = await deps.send(new GetCommand({
    TableName: deps.tableName,
    Key: { sessionId: attemptKey(attemptId) },
    ConsistentRead: true,
  }));
  const item = result.Item as HumanVerificationAttemptRecord | undefined;
  if (!item || item.recordType !== 'human_verification_attempt') throw new LoginPermitError();
  return item;
}

export async function markHumanVerificationAttemptVerified(
  attemptId: string,
  nowMs: number,
  deps: LoginPermitDependencies,
): Promise<void> {
  try {
    await deps.send(new UpdateCommand({
      TableName: deps.tableName,
      Key: { sessionId: attemptKey(attemptId) },
      UpdateExpression: 'SET #state = :verified, verifiedAtMs = :now',
      ConditionExpression:
        'recordType = :recordType AND #state = :pending AND expiresAtMs > :now',
      ExpressionAttributeNames: { '#state': 'state' },
      ExpressionAttributeValues: {
        ':recordType': 'human_verification_attempt',
        ':pending': 'pending',
        ':verified': 'verified',
        ':now': nowMs,
      },
    }));
  } catch {
    throw new LoginPermitError();
  }
}

export async function exchangeVerifiedAttempt(
  input: {
    attemptId: string;
    rawVerifier: string;
    nowMs?: number;
    permit?: string;
  },
  deps: LoginPermitDependencies,
): Promise<{ permit: string; expiresAtMs: number }> {
  const nowMs = input.nowMs ?? Date.now();
  const record = await getHumanVerificationAttempt(input.attemptId, deps);
  if (
    record.state !== 'verified' ||
    record.expiresAtMs <= nowMs ||
    !humanVerificationAttemptVerifierMatches(record, input.rawVerifier)
  ) {
    throw new LoginPermitError();
  }

  const permit = input.permit ?? randomBytes(32).toString('base64url');
  const permitHash = hashOpaqueValue(permit);
  const expiresAtMs = Math.min(record.expiresAtMs, nowMs + PERMIT_TTL_MS);
  const permitRecord = {
    sessionId: permitKey(permitHash),
    recordType: 'login_permit',
    permitHash,
    attemptId: record.attemptId,
    purpose: record.purpose,
    bindingScope: record.bindingScope ?? 'organization_account',
    ...(record.orgId ? { orgId: record.orgId } : {}),
    accountBinding: record.accountBinding,
    clientId: record.clientId,
    clientSurface: record.clientSurface,
    state: 'issued',
    issuedAtMs: nowMs,
    expiresAtMs,
    expiresAtTtl: Math.ceil(expiresAtMs / 1000),
  };

  try {
    await deps.send(new TransactWriteCommand({
      TransactItems: [
        {
          Update: {
            TableName: deps.tableName,
            Key: { sessionId: attemptKey(record.attemptId) },
            UpdateExpression: 'SET #state = :exchanged, exchangedAtMs = :now',
            ConditionExpression:
              '#state = :verified AND expiresAtMs > :now AND verifierHash = :verifierHash',
            ExpressionAttributeNames: { '#state': 'state' },
            ExpressionAttributeValues: {
              ':verified': 'verified',
              ':exchanged': 'exchanged',
              ':now': nowMs,
              ':verifierHash': record.verifierHash,
            },
          },
        },
        {
          Put: {
            TableName: deps.tableName,
            Item: permitRecord,
            ConditionExpression: 'attribute_not_exists(sessionId)',
          },
        },
      ],
    }));
  } catch {
    throw new LoginPermitError();
  }
  return { permit, expiresAtMs };
}

export async function consumeLoginPermit(
  input: {
    permit: string;
    attemptId: string;
    purpose: AuthenticationPurpose;
    bindingPolicy: LoginPermitBindingPolicy;
    orgId: string;
    normalizedEmail: string;
    clientId: string;
    clientSurface: AuthenticationClientSurface;
    nowMs?: number;
  },
  deps: LoginPermitDependencies,
): Promise<{ consumed: true }> {
  const nowMs = input.nowMs ?? Date.now();
  const permitHash = hashOpaqueValue(input.permit);
  const bindingCondition = input.bindingPolicy === 'allow_account'
    ? '(#bindingScope = :account OR ' +
      '((#bindingScope = :organizationAccount OR attribute_not_exists(#bindingScope)) ' +
      'AND orgId = :orgId))'
    : '(#bindingScope = :organizationAccount OR attribute_not_exists(#bindingScope)) ' +
      'AND orgId = :orgId';
  try {
    await deps.send(new UpdateCommand({
      TableName: deps.tableName,
      Key: { sessionId: permitKey(permitHash) },
      UpdateExpression: 'SET #state = :consumed, consumedAtMs = :now',
      ConditionExpression: [
        'recordType = :recordType',
        '#state = :issued',
        'expiresAtMs > :now',
        'attemptId = :attemptId',
        'purpose = :purpose',
        bindingCondition,
        'clientId = :clientId',
        'clientSurface = :clientSurface',
        'accountBinding = :accountBinding',
      ].join(' AND '),
      ExpressionAttributeNames: {
        '#state': 'state',
        '#bindingScope': 'bindingScope',
      },
      ExpressionAttributeValues: {
        ':recordType': 'login_permit',
        ':issued': 'issued',
        ':consumed': 'consumed',
        ':now': nowMs,
        ':attemptId': input.attemptId,
        ':purpose': input.purpose,
        ...(input.bindingPolicy === 'allow_account' ? { ':account': 'account' } : {}),
        ':organizationAccount': 'organization_account',
        ':orgId': input.orgId,
        ':clientId': input.clientId,
        ':clientSurface': input.clientSurface,
        ':accountBinding': accountBindingForEmail(input.normalizedEmail, deps.bindingSecret),
      },
      ReturnValues: 'ALL_NEW',
    }));
  } catch {
    throw new LoginPermitError();
  }
  return { consumed: true };
}
