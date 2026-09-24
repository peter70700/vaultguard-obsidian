import {
  AdminGetUserCommand,
  AdminListGroupsForUserCommand,
  ListUsersCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import { randomUUID } from 'node:crypto';
import { DeleteCommand, GetCommand, UpdateCommand, type TransactWriteCommandInput } from '@aws-sdk/lib-dynamodb';
import type { UserContext } from './utils';

export class CurrentHumanDirectoryUnavailable extends Error {
  constructor() {
    super('Current human authority is unavailable');
    this.name = 'CurrentHumanDirectoryUnavailable';
  }
}

export class HumanMutationBusy extends Error {
  constructor() {
    super('Human authority is changing. Retry shortly.');
    this.name = 'HumanMutationBusy';
  }
}

export interface HumanMutationLease { key: string; owner: string }

/** Serializes privileged human mutations in one organization. Lambda's
 * configured 30-second timeout is shorter than this 60-second lease; a timed
 * out writer cannot resume after the next writer acquires it. */
export async function acquireHumanMutationLease(options: {
  orgId: string; tableName: string; send(command: unknown): Promise<unknown>; now?: () => number;
}): Promise<HumanMutationLease> {
  if (!identifier(options.orgId)) throw new HumanMutationBusy();
  const now = options.now?.() ?? Date.now();
  const lease = { key: `human-mutation#${options.orgId}`, owner: randomUUID() };
  try {
    await options.send(new UpdateCommand({ TableName: options.tableName, Key: { sessionId: lease.key },
      UpdateExpression: 'SET mutationOwner = :owner, mutationExpiresAt = :expires, expiresAtTtl = :ttl',
      ConditionExpression: 'attribute_not_exists(mutationOwner) OR mutationExpiresAt <= :now',
      ExpressionAttributeValues: { ':owner': lease.owner, ':expires': now + 60_000, ':ttl': Math.floor(now / 1000) + 86_400, ':now': now } }));
    return lease;
  } catch (error) {
    if ((error as { name?: string } | null)?.name === 'ConditionalCheckFailedException') throw new HumanMutationBusy();
    throw new CurrentHumanDirectoryUnavailable();
  }
}

export async function releaseHumanMutationLease(lease: HumanMutationLease, options: {
  tableName: string; send(command: unknown): Promise<unknown>;
}): Promise<void> {
  await options.send(new DeleteCommand({ TableName: options.tableName, Key: { sessionId: lease.key },
    ConditionExpression: 'mutationOwner = :owner', ExpressionAttributeValues: { ':owner': lease.owner } }));
}

/** A role writer advances the already enforced token logout cutoff BEFORE
 * changing Cognito groups. It never lowers a prior cutoff, including when two
 * role writers or a password reset race. */
export async function advanceHumanRoleCutoff(userId: string, options: {
  tableName: string; send(command: unknown): Promise<unknown>; now?: () => number;
}): Promise<number> {
  if (!identifier(userId)) throw new CurrentHumanDirectoryUnavailable();
  const key = { sessionId: `logout-cutoff#${userId}` };
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const read = await options.send(new GetCommand({ TableName: options.tableName, Key: key, ConsistentRead: true })) as { Item?: { logoutAt?: unknown } };
    const prior = read?.Item?.logoutAt;
    if (prior !== undefined && (!Number.isSafeInteger(prior) || (prior as number) < 0)) throw new CurrentHumanDirectoryUnavailable();
    const now = options.now?.() ?? Date.now();
    // JWT issuance has second precision. Move at least one millisecond beyond
    // this instant so a token minted earlier in the same second is fenced.
    const next = Math.max(now + 1, (prior as number | undefined ?? 0) + 1);
    try {
      await options.send(new UpdateCommand({ TableName: options.tableName, Key: key,
        UpdateExpression: 'SET userId = :user, logoutAt = :next, expiresAtTtl = :ttl',
        ConditionExpression: prior === undefined ? 'attribute_not_exists(logoutAt)' : 'logoutAt = :prior',
        ExpressionAttributeValues: { ':user': userId, ':next': next, ':ttl': Math.floor(next / 1000) + 86_400,
          ...(prior === undefined ? {} : { ':prior': prior }) } }));
      return next;
    } catch (error) {
      if ((error as { name?: string } | null)?.name !== 'ConditionalCheckFailedException') throw error;
    }
  }
  throw new HumanMutationBusy();
}

/** Commit-time guard for a human token admitted before a role mutation. The
 * role writer's cutoff row makes this condition fail in the same transaction. */
export function humanRoleCutoffCondition(tableName: string, user: Pick<UserContext, 'userId' | 'iat'>) {
  if (!identifier(user.userId) || !Number.isSafeInteger(user.iat) || user.iat! <= 0) throw new CurrentHumanDirectoryUnavailable();
  const condition: NonNullable<NonNullable<TransactWriteCommandInput['TransactItems']>[number]['ConditionCheck']> = {
    TableName: tableName, Key: { sessionId: `logout-cutoff#${user.userId}` },
    ConditionExpression: 'attribute_not_exists(sessionId) OR logoutAt < :issued',
    ExpressionAttributeValues: { ':issued': user.iat! * 1000 },
  };
  return condition;
}

const identifier = (value: unknown): value is string =>
  typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u.test(value);

/** Resolves the signed subject to its current directory row and current role
 * groups. A JWT role or mutable custom role attribute never repairs an absent,
 * ambiguous or unreadable directory result. Users administration and the
 * protected workspace web host use this owner at human admission. */
export async function currentHumanDirectory(user: Pick<UserContext, 'userId' | 'orgId'>, options: {
  userPoolId: string;
  send(command: unknown): Promise<unknown>;
}): Promise<{ username: string; roles: string[] }> {
  if (!identifier(user.userId) || !identifier(user.orgId) || !options.userPoolId) throw new CurrentHumanDirectoryUnavailable();
  try {
    const listed = await options.send(new ListUsersCommand({ UserPoolId: options.userPoolId,
      Filter: `sub = "${user.userId}"`, Limit: 2 })) as { Users?: unknown; PaginationToken?: unknown };
    if (!Array.isArray(listed?.Users) || listed.Users.length !== 1 || listed.PaginationToken) throw new Error();
    const match = listed.Users[0] as Record<string, unknown>;
    const username = match?.Username;
    if (!identifier(username) || match.Enabled !== true || match.UserStatus !== 'CONFIRMED' || !Array.isArray(match.Attributes) ||
      match.Attributes.filter((attribute: { Name?: string; Value?: string }) => attribute?.Name === 'sub' && attribute.Value === user.userId).length !== 1) throw new Error();
    const current = await options.send(new AdminGetUserCommand({ UserPoolId: options.userPoolId, Username: username })) as {
      Username?: unknown; Enabled?: unknown; UserStatus?: unknown; UserAttributes?: unknown;
    };
    if (current?.Username !== username || current.Enabled !== true || current.UserStatus !== 'CONFIRMED' || !Array.isArray(current.UserAttributes)) throw new Error();
    const attributes = current.UserAttributes as { Name?: unknown; Value?: unknown }[];
    if (attributes.filter(attribute => attribute?.Name === 'sub' && attribute.Value === user.userId).length !== 1 ||
      attributes.filter(attribute => attribute?.Name === 'custom:org' && attribute.Value === user.orgId).length !== 1) throw new Error();
    const roles: string[] = [], seen = new Set<string>();
    let cursor: string | undefined;
    for (let page = 0; page < 10; page += 1) {
      const response = await options.send(new AdminListGroupsForUserCommand({ UserPoolId: options.userPoolId,
        Username: username, Limit: 60, ...(cursor ? { NextToken: cursor } : {}) })) as { Groups?: unknown; NextToken?: unknown };
      if (!Array.isArray(response?.Groups) || response.Groups.length > 60) throw new Error();
      for (const item of response.Groups) {
        const name = (item as { GroupName?: unknown } | null)?.GroupName;
        if (typeof name !== 'string' || !name || name.length > 128 || /[\u0000-\u001f\u007f]/u.test(name) || seen.has(name)) throw new Error();
        seen.add(name); roles.push(name);
      }
      if (response.NextToken === undefined) return { username, roles };
      if (typeof response.NextToken !== 'string' || !response.NextToken || response.NextToken.length > 2048 ||
        /[\u0000-\u001f\u007f]/u.test(response.NextToken) || response.NextToken === cursor) throw new Error();
      cursor = response.NextToken;
    }
    throw new Error();
  } catch {
    throw new CurrentHumanDirectoryUnavailable();
  }
}
