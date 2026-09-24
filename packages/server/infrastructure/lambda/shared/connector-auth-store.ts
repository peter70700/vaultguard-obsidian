import { observeWorkspaceOperation } from '../workspace-observability/telemetry';
import { createHash } from 'node:crypto';
import {
  GetCommand,
  PutCommand,
  QueryCommand,
  TransactWriteCommand,
  UpdateCommand,
  type TransactWriteCommandInput,
} from "@aws-sdk/lib-dynamodb";
import {
  connectorProfileScopes,
  type ConnectorScopeProfile,
  type ConnectorAgentSession,
  type ConnectorAuthorizationStore,
  type ConnectorClientRegistration,
  type ConnectorGrant,
  type ConnectorSubjectCutoffCondition,
} from "./connector-auth";
import type { OrganizationConnectorPolicy, OrganizationConnectorPolicyReader } from "./organization-connector-policy";

type Kind = "client" | "grant" | "session";
type RecordValue =
  | ConnectorClientRegistration
  | ConnectorGrant
  | ConnectorAgentSession;
type Item = {
  pk: string;
  sk: "STATE";
  schemaVersion: 1;
  kind: Kind;
  record: RecordValue;
};
type Row = Record<string, unknown>;

/** VAULTGUARD-129: what one `endSubjectConnections` run did. Counts only; no path, scope or credential. */
export interface SubjectConnectionTeardown {
  /** The cutoff in force after the run (epoch seconds). */
  cutoffAt: number;
  grantsRevoked: number;
  sessionsRevoked: number;
  grantsAlreadyRevoked: number;
  sessionsAlreadyRevoked: number;
  /** Owner references whose grant or session row does not exist. */
  referencesWithoutRecord: number;
  /** Connections older than the owner directory are refused by the cutoff but not listed. */
  coverage: "recorded-directory-only";
}

/** 25 references a page: up to 10 000 connections per user before a run refuses. */
const MAX_SUBJECT_TEARDOWN_PAGES = 400;
/** A refresh racing the revocation moves a grant's revision; re-read and retry this often. */
const MAX_SUBJECT_REVOKE_ATTEMPTS = 5;

export class ConnectorStoreError extends Error {
  constructor(
    readonly code:
      | "INVALID_STATE"
      | "UNAVAILABLE"
      | "CONFLICT"
      | "OUTCOME_UNKNOWN",
  ) {
    super(code);
    this.name = "ConnectorStoreError";
  }
}

export interface DynamoConnectorAuthorizationStoreOptions {
  tableName: string;
  /** Explicit production-only vocabulary. Omission keeps the G0 store frozen. */
  scopeProfile?: ConnectorScopeProfile;
  /** Supply a document client with automatic retries disabled (maxAttempts: 1). */
  send(command: unknown): Promise<unknown>;
  /** Read the existing live organization policy owner; never duplicate it here. */
  getPolicyRevision(orgId: string): Promise<number | null>;
  now?: () => number;
  /**
   * VAULTGUARD-91: the organization connector admission owner. Supplied, the
   * store exposes it as `getOrganizationConnectorPolicy`, and every owner that
   * honours an existing grant through this store (authentication, issuance,
   * delegated-chain rechecks, handoffs) refuses a connector its organization
   * blocks or has switched off. It never changes what this store reads or writes.
   */
  organizationConnectorPolicy?: OrganizationConnectorPolicyReader;
  /**
   * VAULTGUARD-129: the user-revocation marker owner (`REVOKED_KEYS_TABLE`,
   * `isUserAccessRevoked` in `shared/utils.ts`), answering whether the user is
   * revoked now. Supplied, the store exposes `admitsGrantSubject`, which refuses
   * while the marker exists and, after it is gone, any grant created at or
   * before the user's connector cutoff. Omitted (the frozen G0 edge, the probe
   * and synthetic stores), no subject check exists.
   */
  userRevoked?(userId: string, orgId: string): Promise<boolean>;
  /** Strong current tenant MFA policy; null/unavailable refuses a proofless grant. */
  getMfaRequirement?(orgId: string): Promise<boolean | null>;
  /** Trusted human host: audit/receipt and current-session guards share the exact revoke CAS. */
  revocation?: {
    prepare(kind: 'client' | 'grant' | 'session', id: string, expectedRevision: number): Promise<NonNullable<TransactWriteCommandInput['TransactItems']>>;
    confirmed(kind: 'client' | 'grant' | 'session', id: string, expectedRevision: number): Promise<boolean>;
  };
}

function object(value: unknown): value is Row {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function exact(value: unknown, fields: string[]): value is Row {
  return (
    object(value) &&
    Object.keys(value).length === fields.length &&
    fields.every((field) => Object.keys(value).includes(field))
  );
}
function identifier(value: unknown): value is string {
  return (
    typeof value === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u.test(value)
  );
}
function revision(value: unknown): value is number {
  return (
    Number.isSafeInteger(value) &&
    (value as number) >= 1 &&
    (value as number) < Number.MAX_SAFE_INTEGER
  );
}
function https(value: unknown, resource = false): boolean {
  if (
    typeof value !== "string" ||
    value.length > 2048 ||
    /\s/u.test(value) ||
    [...value].some(
      (character) =>
        character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
    )
  )
    return false;
  try {
    const url = new URL(value);
    return (
      url.protocol === "https:" &&
      !url.username &&
      !url.password &&
      !url.hash &&
      (!resource || (!url.search && url.pathname.endsWith("/mcp")))
    );
  } catch {
    return false;
  }
}
function list(
  value: unknown,
  validate: (entry: unknown) => boolean,
  maximum: number,
): value is string[] {
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.length <= maximum &&
    value.every(validate) &&
    new Set(value).size === value.length
  );
}
function scopes(value: unknown, allowed: readonly string[]): value is string[] {
  return list(
    value,
    (scope) =>
      allowed.includes(scope as string),
    allowed.length,
  );
}
const GRANT_FIELDS = [
  "grantId",
  "clientId",
  "userId",
  "orgId",
  "resource",
  "scopes",
  "status",
  "revision",
  "expiresAt",
];
function valid(kind: Kind, value: unknown, allowed: readonly string[]): value is RecordValue {
  if (kind === "client")
    return (
      exact(value, [
        "clientId",
        "hostKind",
        "redirectUris",
        "allowedResources",
        "allowedScopes",
        "pkceRequired",
        "status",
        "configRevision",
      ]) &&
      identifier(value.clientId) &&
      ["chatgpt", "claude", "custom-mcp"].includes(value.hostKind as string) &&
      list(value.redirectUris, (uri) => https(uri), 20) &&
      list(value.allowedResources, (uri) => https(uri, true), 10) &&
      scopes(value.allowedScopes, allowed) &&
      value.pkceRequired === true &&
      ["active", "suspended", "revoked"].includes(value.status as string) &&
      revision(value.configRevision)
    );
  const common =
    object(value) &&
    identifier(value.userId) &&
    identifier(value.orgId) &&
    identifier(value.grantId) &&
    revision(value.revision) &&
    Number.isSafeInteger(value.expiresAt) &&
    (value.expiresAt as number) > 0;
  if (!common) return false;
  if (kind === "grant")
    return (
      // `authorityRevision` (VAULTGUARD-123) is present on every grant written
      // since it existed and absent on older rows, which stay valid: their
      // authority revision is their rotation revision.
      exact(value, [...GRANT_FIELDS,
        ...(value.authorityRevision === undefined ? [] : ['authorityRevision']),
        ...(value.mfaVerifiedAt === undefined ? [] : ['mfaVerifiedAt'])]) &&
      (value.authorityRevision === undefined || revision(value.authorityRevision)) &&
      (value.mfaVerifiedAt === undefined || (Number.isSafeInteger(value.mfaVerifiedAt) && (value.mfaVerifiedAt as number) > 0)) &&
      identifier(value.clientId) &&
      https(value.resource, true) &&
      scopes(value.scopes, allowed) &&
      ["active", "expired", "suspended", "revoked"].includes(
        value.status as string,
      )
    );
  return (
    exact(value, [
      "sessionId",
      "grantId",
      "userId",
      "orgId",
      "status",
      "revision",
      "expiresAt",
      ...(value.mfaVerifiedAt === undefined ? [] : ['mfaVerifiedAt']),
    ]) &&
    (value.mfaVerifiedAt === undefined || (Number.isSafeInteger(value.mfaVerifiedAt) && (value.mfaVerifiedAt as number) > 0)) &&
    identifier(value.sessionId) &&
    ["active", "ended", "expired", "revoked"].includes(value.status as string)
  );
}
function idOf(kind: Kind, record: RecordValue): string {
  return kind === "client"
    ? (record as ConnectorClientRegistration).clientId
    : kind === "grant"
      ? (record as ConnectorGrant).grantId
      : (record as ConnectorAgentSession).sessionId;
}
function key(kind: Kind, id: string) {
  if (!identifier(id)) throw new ConnectorStoreError("INVALID_STATE");
  return {
    pk: `CONNECTOR#${kind.toUpperCase()}#${Buffer.from(id, "utf8").toString("base64url")}`,
    sk: "STATE" as const,
  };
}
function row(kind: Kind, record: RecordValue, allowed: readonly string[]): Item {
  if (!valid(kind, record, allowed)) throw new ConnectorStoreError("INVALID_STATE");
  return {
    ...key(kind, idOf(kind, record)),
    schemaVersion: 1,
    kind,
    record: structuredClone(record),
  };
}
function conflict(error: unknown): boolean {
  if (!object(error)) return false;
  return (
    error.name === "ConditionalCheckFailedException" ||
    (error.name === "TransactionCanceledException" &&
      Array.isArray(error.CancellationReasons) &&
      error.CancellationReasons.some(
        (reason) => object(reason) && reason.Code === "ConditionalCheckFailed",
      ))
  );
}

/**
 * Durable authority state for the authorized MCP handler. No credentials or
 * refresh tokens are stored here. Issuance callers still own user consent,
 * membership, token signatures, refresh-family handling and trusted time.
 * Retain revoked rows: deleting/TTL-expiring them would permit identifier reuse.
 * Methods are an internal persistence boundary, not public authorization APIs.
 */
export class DynamoConnectorAuthorizationStore
  implements ConnectorAuthorizationStore
{
  /** VAULTGUARD-91: present only when the composition supplied the owner. */
  readonly getOrganizationConnectorPolicy?: (orgId: string) => Promise<OrganizationConnectorPolicy | null>;
  /** VAULTGUARD-129: present only when the composition supplied `userRevoked`. */
  readonly admitsGrantSubject?: (grant: ConnectorGrant) => Promise<boolean>;

  constructor(
    private readonly options: DynamoConnectorAuthorizationStoreOptions,
  ) {
    if (options.organizationConnectorPolicy) {
      const read = options.organizationConnectorPolicy;
      this.getOrganizationConnectorPolicy = (orgId) => read(orgId);
    }
    if (options.userRevoked || options.getMfaRequirement)
      this.admitsGrantSubject = (grant) => this.admitsSubject(grant, options.userRevoked);
    if (
      !/^[A-Za-z0-9_.-]{3,255}$/u.test(options.tableName) ||
      typeof options.send !== "function" ||
      typeof options.getPolicyRevision !== "function"
    ) {
      throw new ConnectorStoreError("INVALID_STATE");
    }
  }

  private now(): number {
    const now = this.options.now?.() ?? Math.floor(Date.now() / 1000);
    if (!Number.isSafeInteger(now) || now < 0)
      throw new ConnectorStoreError("INVALID_STATE");
    return now;
  }

  private allowedScopes(): readonly string[] { return connectorProfileScopes(this.options.scopeProfile); }
  private async read(kind: Kind, id: string): Promise<RecordValue | null> {
    const Key = key(kind, id);
    let result: unknown;
    try {
      result = await this.options.send(
        new GetCommand({
          TableName: this.options.tableName,
          Key,
          ConsistentRead: true,
        }),
      );
    } catch {
      throw new ConnectorStoreError("UNAVAILABLE");
    }
    if (!object(result)) throw new ConnectorStoreError("INVALID_STATE");
    if (result.Item === undefined) return null;
    const item = result.Item;
    if (
      !exact(item, ["pk", "sk", "schemaVersion", "kind", "record"]) ||
      item.pk !== Key.pk ||
      item.sk !== Key.sk ||
      item.schemaVersion !== 1 ||
      item.kind !== kind ||
      !valid(kind, item.record, this.allowedScopes()) ||
      idOf(kind, item.record) !== id
    ) {
      throw new ConnectorStoreError("INVALID_STATE");
    }
    return structuredClone(item.record);
  }

  getClient(id: string): Promise<ConnectorClientRegistration | null> {
    return this.read(
      "client",
      id,
    ) as Promise<ConnectorClientRegistration | null>;
  }
  getGrant(id: string): Promise<ConnectorGrant | null> {
    return this.read("grant", id) as Promise<ConnectorGrant | null>;
  }
  getSession(id: string): Promise<ConnectorAgentSession | null> {
    return this.read("session", id) as Promise<ConnectorAgentSession | null>;
  }

  async getPolicyRevision(orgId: string): Promise<number | null> {
    if (!identifier(orgId)) throw new ConnectorStoreError("INVALID_STATE");
    let value: number | null;
    try {
      value = await this.options.getPolicyRevision(orgId);
    } catch {
      throw new ConnectorStoreError("UNAVAILABLE");
    }
    if (value !== null && (!Number.isSafeInteger(value) || value < 0))
      throw new ConnectorStoreError("INVALID_STATE");
    return value;
  }

  private async write(
    command: TransactWriteCommand | UpdateCommand,
  ): Promise<void> {
    try {
      await this.options.send(command);
    } catch (error) {
      throw new ConnectorStoreError(
        conflict(error) ? "CONFLICT" : "OUTCOME_UNKNOWN",
      );
    }
  }

  private insert(kind: Kind, record: RecordValue) {
    return {
      Put: {
        TableName: this.options.tableName,
        Item: row(kind, record, this.allowedScopes()),
        ConditionExpression:
          "attribute_not_exists(pk) AND attribute_not_exists(sk)",
      },
    };
  }

  private activeCondition(
    kind: "client" | "grant",
    record: ConnectorClientRegistration | ConnectorGrant,
    now: number,
  ) {
    const isClient = kind === "client";
    return {
      ConditionCheck: {
        TableName: this.options.tableName,
        Key: key(kind, idOf(kind, record)),
        ConditionExpression: `#r.#v = :revision AND #r.#s = :active${isClient ? "" : " AND #r.#e > :now"}`,
        ExpressionAttributeNames: {
          "#r": "record",
          "#v": isClient ? "configRevision" : "revision",
          "#s": "status",
          ...(isClient ? {} : { "#e": "expiresAt" }),
        },
        ExpressionAttributeValues: {
          ":revision": isClient
            ? (record as ConnectorClientRegistration).configRevision
            : (record as ConnectorGrant).revision,
          ":active": "active",
          ...(isClient ? {} : { ":now": now }),
        },
      },
    };
  }

  async createClient(client: ConnectorClientRegistration): Promise<void> {
    const item = this.insert("client", client);
    if (client.configRevision !== 1 || client.status !== "active")
      throw new ConnectorStoreError("INVALID_STATE");
    await this.write(new TransactWriteCommand({ TransactItems: [item] }));
  }

  private ownerPartition(orgId: string, userId: string) {
    return `CONNECTOR-OWNER#${createHash('sha256').update(JSON.stringify([orgId, userId])).digest('hex')}`;
  }
  private directory(kind: 'grant' | 'session', record: ConnectorGrant | ConnectorAgentSession) {
    const id = kind === 'grant' ? (record as ConnectorGrant).grantId : (record as ConnectorAgentSession).sessionId;
    // `createdAt` (epoch seconds, VAULTGUARD-91) lives on the reference, never on
    // the frozen authority record, so existing grant/session rows and every
    // reader of them are unchanged. References written before it carry none.
    return { Put: { TableName: this.options.tableName, Item: { pk: this.ownerPartition(record.orgId, record.userId), sk: `${kind.toUpperCase()}#${Buffer.from(id).toString('base64url')}`, schemaVersion: 1, kind: 'connector-owner-reference', entityKind: kind, id, orgId: record.orgId, userId: record.userId, createdAt: this.now() }, ConditionExpression: 'attribute_not_exists(pk) AND attribute_not_exists(sk)' } };
  }
  private organizationPartition(orgId: string) {
    return `CONNECTOR-ORG#${createHash('sha256').update(JSON.stringify([orgId])).digest('hex')}`;
  }
  /**
   * VAULTGUARD-91: the organization directory, written in the same transaction
   * as the owner reference. It holds references only (kind, id, owner, created
   * instant) so an organization administrator can find another member's
   * connections; every listed id is still read from, and checked against, its
   * authority record before anything about it is shown.
   */
  private organizationDirectory(kind: 'grant' | 'session', record: ConnectorGrant | ConnectorAgentSession) {
    const id = kind === 'grant' ? (record as ConnectorGrant).grantId : (record as ConnectorAgentSession).sessionId;
    return { Put: { TableName: this.options.tableName, Item: { pk: this.organizationPartition(record.orgId), sk: `${kind.toUpperCase()}#${Buffer.from(id).toString('base64url')}`, schemaVersion: 1, kind: 'connector-organization-reference', entityKind: kind, id, orgId: record.orgId, userId: record.userId, createdAt: this.now() }, ConditionExpression: 'attribute_not_exists(pk) AND attribute_not_exists(sk)' } };
  }
  /** One page of the organization directory (VAULTGUARD-91). Like the owner
   * directory, connections created before it existed are not listed, and an
   * empty page is never evidence that the organization has no connections. */
  async listOrganization(orgId: string, cursor?: string) {
    if (!identifier(orgId) || (cursor !== undefined && !/^(GRANT|SESSION)#[A-Za-z0-9_-]{1,342}$/.test(cursor))) throw new ConnectorStoreError('INVALID_STATE');
    const pk = this.organizationPartition(orgId);
    const response = await this.options.send(new QueryCommand({ TableName: this.options.tableName, ConsistentRead: true, KeyConditionExpression: 'pk = :org', ExpressionAttributeValues: { ':org': pk }, Limit: 25,
      ...(cursor ? { ExclusiveStartKey: { pk, sk: cursor } } : {}) })) as { Items?: Record<string, unknown>[]; LastEvaluatedKey?: { pk: string; sk: string } };
    const entries = (response.Items ?? []).map(row => {
      if (row.pk !== pk || row.orgId !== orgId || row.schemaVersion !== 1 || row.kind !== 'connector-organization-reference' || !['grant', 'session'].includes(String(row.entityKind)) || !identifier(row.id) || !identifier(row.userId) ||
        row.sk !== `${String(row.entityKind).toUpperCase()}#${Buffer.from(String(row.id)).toString('base64url')}` || !Number.isSafeInteger(row.createdAt) || (row.createdAt as number) < 0) throw new ConnectorStoreError('INVALID_STATE');
      return { kind: row.entityKind as 'grant' | 'session', id: row.id as string, userId: row.userId as string, createdAt: row.createdAt as number };
    });
    if (response.LastEvaluatedKey && response.LastEvaluatedKey.pk !== pk) throw new ConnectorStoreError('INVALID_STATE');
    return { entries, nextCursor: response.LastEvaluatedKey?.sk ?? null };
  }
  /** Strong owner directory contains references only. Legacy authority rows need
   * explicit migration; a missing directory is never evidence of no connections. */
  async listOwned(orgId: string, userId: string, cursor?: string) {
    if (!identifier(orgId) || !identifier(userId) || (cursor !== undefined && !/^(GRANT|SESSION)#[A-Za-z0-9_-]{1,342}$/.test(cursor))) throw new ConnectorStoreError('INVALID_STATE');
    const pk = this.ownerPartition(orgId, userId);
    const response = await this.options.send(new QueryCommand({ TableName: this.options.tableName, ConsistentRead: true, KeyConditionExpression: 'pk = :owner', ExpressionAttributeValues: { ':owner': pk }, Limit: 25,
      ...(cursor ? { ExclusiveStartKey: { pk, sk: cursor } } : {}) })) as { Items?: Record<string, unknown>[]; LastEvaluatedKey?: { pk: string; sk: string } };
    const entries = (response.Items ?? []).map(row => {
      if (row.pk !== pk || row.orgId !== orgId || row.userId !== userId || row.schemaVersion !== 1 || row.kind !== 'connector-owner-reference' || !['grant','session'].includes(String(row.entityKind)) || !identifier(row.id) || row.sk !== `${String(row.entityKind).toUpperCase()}#${Buffer.from(String(row.id)).toString('base64url')}` ||
        (row.createdAt !== undefined && (!Number.isSafeInteger(row.createdAt) || (row.createdAt as number) < 0))) throw new ConnectorStoreError('INVALID_STATE');
      return { kind: row.entityKind as 'grant' | 'session', id: row.id as string, createdAt: row.createdAt === undefined ? null : (row.createdAt as number) };
    });
    if (response.LastEvaluatedKey && response.LastEvaluatedKey.pk !== pk) throw new ConnectorStoreError('INVALID_STATE');
    return { entries, nextCursor: response.LastEvaluatedKey?.sk ?? null };
  }

  /**
   * VAULTGUARD-129 — the user connector cutoff. One row per (organization,
   * user), holding only epoch seconds: every grant whose owner reference was
   * created at or before it is refused for good (`admitsSubject`). It only ever
   * moves forward. Like revoked grant rows it is retained, never TTL-expired:
   * deleting it would let a pre-revocation grant the directory could not find
   * authenticate again.
   */
  private subjectCutoffKey(orgId: string, userId: string) {
    if (!identifier(orgId) || !identifier(userId)) throw new ConnectorStoreError("INVALID_STATE");
    return { pk: `CONNECTOR-SUBJECT-CUTOFF#${createHash('sha256').update(JSON.stringify([orgId, userId])).digest('hex')}`, sk: "STATE" as const };
  }

  /** The user's connector cutoff (epoch seconds), or null when they were never revoked. */
  async getSubjectCutoff(orgId: string, userId: string): Promise<number | null> {
    const Key = this.subjectCutoffKey(orgId, userId);
    let result: unknown;
    try {
      result = await this.options.send(new GetCommand({ TableName: this.options.tableName, Key, ConsistentRead: true }));
    } catch {
      throw new ConnectorStoreError("UNAVAILABLE");
    }
    if (!object(result)) throw new ConnectorStoreError("INVALID_STATE");
    if (result.Item === undefined) return null;
    const item = result.Item;
    if (
      !exact(item, ["pk", "sk", "schemaVersion", "kind", "orgId", "userId", "cutoffAt"]) ||
      item.pk !== Key.pk || item.sk !== Key.sk || item.schemaVersion !== 1 || item.kind !== "connector-subject-cutoff" ||
      item.orgId !== orgId || item.userId !== userId || !Number.isSafeInteger(item.cutoffAt) || (item.cutoffAt as number) < 0
    )
      throw new ConnectorStoreError("INVALID_STATE");
    return item.cutoffAt as number;
  }

  /**
   * Moves the user's cutoff forward to `cutoffAt`, never back, and returns the
   * cutoff in force. Idempotent: a repeat, or a later cutoff already stored,
   * changes nothing.
   */
  async raiseSubjectCutoff(orgId: string, userId: string, cutoffAt: number): Promise<number> {
    if (!Number.isSafeInteger(cutoffAt) || cutoffAt < 0) throw new ConnectorStoreError("INVALID_STATE");
    const Key = this.subjectCutoffKey(orgId, userId);
    try {
      await this.options.send(new PutCommand({
        TableName: this.options.tableName,
        Item: { ...Key, schemaVersion: 1, kind: "connector-subject-cutoff", orgId, userId, cutoffAt },
        ConditionExpression: "attribute_not_exists(pk) OR #cutoff < :cutoff",
        ExpressionAttributeNames: { "#cutoff": "cutoffAt" },
        ExpressionAttributeValues: { ":cutoff": cutoffAt },
      }));
    } catch (error) {
      if (!conflict(error)) throw new ConnectorStoreError("OUTCOME_UNKNOWN");
    }
    const stored = await this.getSubjectCutoff(orgId, userId);
    if (stored === null || stored < cutoffAt) throw new ConnectorStoreError("OUTCOME_UNKNOWN");
    return stored;
  }

  /**
   * VAULTGUARD-129: whether the grant's user may still use it. Refuses while
   * the user is revoked; after that, admits a grant only when its owner
   * reference was created strictly after the user's cutoff. A grant with no
   * owner reference, or a reference without a creation instant, cannot prove
   * that, so it refuses once a cutoff exists. Any unreadable input refuses.
   */
  private async admitsSubject(grant: ConnectorGrant, revoked?: DynamoConnectorAuthorizationStoreOptions["userRevoked"]): Promise<boolean> {
    if (!identifier(grant.orgId) || !identifier(grant.userId) || !identifier(grant.grantId)) return false;
    if (revoked && (await revoked(grant.userId, grant.orgId)) !== false) return false;
    if (this.options.getMfaRequirement) {
      const required = await this.options.getMfaRequirement(grant.orgId);
      if (required === null || (required && (!Number.isSafeInteger(grant.mfaVerifiedAt) || grant.mfaVerifiedAt! <= 0))) return false;
    }
    return this.grantPostdatesSubjectCutoff(grant);
  }

  /**
   * VAULTGUARD-129: the cutoff check alone (see `admitsSubject`). Always
   * available, so every owner that revalidates a stored delegated chain through
   * this store refuses a grant from before its user's last revocation.
   */
  async grantPostdatesSubjectCutoff(grant: ConnectorGrant): Promise<boolean> {
    return (await this.captureGrantSubjectCutoff(grant)) !== null;
  }

  async captureGrantSubjectCutoff(grant: ConnectorGrant): Promise<ConnectorSubjectCutoffCondition | null> {
    if (!identifier(grant.orgId) || !identifier(grant.userId) || !identifier(grant.grantId)) return null;
    const cutoff = await this.getSubjectCutoff(grant.orgId, grant.userId);
    const condition: ConnectorSubjectCutoffCondition = {
      TableName: this.options.tableName,
      Key: this.subjectCutoffKey(grant.orgId, grant.userId),
      ConditionExpression: cutoff === null ? 'attribute_not_exists(pk)' : '#cutoff = :cutoff',
      ...(cutoff === null ? {} : {
        ExpressionAttributeNames: { '#cutoff': 'cutoffAt' },
        ExpressionAttributeValues: { ':cutoff': cutoff },
      }),
    };
    if (cutoff === null) return condition;
    const Key = { pk: this.ownerPartition(grant.orgId, grant.userId), sk: `GRANT#${Buffer.from(grant.grantId).toString('base64url')}` };
    let result: unknown;
    try {
      result = await this.options.send(new GetCommand({ TableName: this.options.tableName, Key, ConsistentRead: true }));
    } catch {
      throw new ConnectorStoreError("UNAVAILABLE");
    }
    const reference = object(result) && object(result.Item) ? result.Item : null;
    const admitted = !!reference && reference.pk === Key.pk && reference.sk === Key.sk && reference.schemaVersion === 1 &&
      reference.kind === "connector-owner-reference" && reference.entityKind === "grant" && reference.id === grant.grantId &&
      reference.orgId === grant.orgId && reference.userId === grant.userId &&
      Number.isSafeInteger(reference.createdAt) && (reference.createdAt as number) > cutoff;
    return admitted ? condition : null;
  }

  /**
   * VAULTGUARD-129 — ends every connector grant and agent session a user holds
   * in an organization. Called by user revocation and again by reactivation
   * (`shared/connector-subject-revocation.ts`); idempotent, so any repeat is a
   * safe retry of an incomplete run.
   *
   * ORDER: the cutoff is raised FIRST, so from that write on no grant the user
   * already holds can authenticate or be issued a token again, whatever this run
   * manages next. Then every grant and session in the user's owner directory is
   * revoked through `revoke`, whose `revocation` hook (when the composition
   * supplies one) commits an audit row in the same transaction. A revision moved
   * by a concurrent refresh is re-read and retried a bounded number of times.
   *
   * Coverage is the owner directory only: a connection written before the
   * directory existed is not found or marked revoked, but the cutoff refuses it.
   * A reference whose authority row is missing is counted, never trusted. A
   * reference or record naming another user or organization fails closed.
   */
  async endSubjectConnections(orgId: string, userId: string, cutoffAt: number): Promise<SubjectConnectionTeardown> {
    const cutoff = await this.raiseSubjectCutoff(orgId, userId, cutoffAt);
    const outcome: SubjectConnectionTeardown = {
      cutoffAt: cutoff, grantsRevoked: 0, sessionsRevoked: 0, grantsAlreadyRevoked: 0, sessionsAlreadyRevoked: 0,
      referencesWithoutRecord: 0, coverage: "recorded-directory-only",
    };
    let cursor: string | undefined;
    for (let page = 0; ; page += 1) {
      if (page >= MAX_SUBJECT_TEARDOWN_PAGES) throw new ConnectorStoreError("INVALID_STATE");
      const listed = await this.listOwned(orgId, userId, cursor);
      for (const entry of listed.entries) {
        const result = await this.revokeOwned(entry.kind, entry.id, orgId, userId);
        if (result === "missing") outcome.referencesWithoutRecord += 1;
        else if (entry.kind === "grant") outcome[result === "revoked" ? "grantsRevoked" : "grantsAlreadyRevoked"] += 1;
        else outcome[result === "revoked" ? "sessionsRevoked" : "sessionsAlreadyRevoked"] += 1;
      }
      if (!listed.nextCursor) break;
      cursor = listed.nextCursor;
    }
    return outcome;
  }

  private async revokeOwned(kind: "grant" | "session", id: string, orgId: string, userId: string): Promise<"revoked" | "already" | "missing"> {
    for (let attempt = 0; attempt < MAX_SUBJECT_REVOKE_ATTEMPTS; attempt += 1) {
      const current = (await this.read(kind, id)) as ConnectorGrant | ConnectorAgentSession | null;
      if (!current) return "missing";
      if (current.orgId !== orgId || current.userId !== userId) throw new ConnectorStoreError("INVALID_STATE");
      if (current.status === "revoked") return "already";
      try {
        await this.revoke(kind, id, current.revision);
        return "revoked";
      } catch (error) {
        if (!(error instanceof ConnectorStoreError) || error.code !== "CONFLICT") throw error;
      }
    }
    throw new ConnectorStoreError("CONFLICT");
  }

  async createGrant(input: ConnectorGrant): Promise<void> {
    const item = this.insert("grant", input);
    const grant = item.Put.Item.record as ConnectorGrant;
    const now = this.now();
    if (
      grant.revision !== 1 ||
      (grant.authorityRevision !== undefined && grant.authorityRevision !== 1) ||
      grant.status !== "active" ||
      grant.expiresAt <= now
    )
      throw new ConnectorStoreError("INVALID_STATE");
    const client = await this.getClient(grant.clientId);
    if (
      client?.status !== "active" ||
      !client.allowedResources.includes(grant.resource) ||
      !grant.scopes.every((scope) => client.allowedScopes.includes(scope))
    )
      throw new ConnectorStoreError("CONFLICT");
    await this.write(
      new TransactWriteCommand({
        TransactItems: [this.activeCondition("client", client, now), item, this.directory("grant", grant), this.organizationDirectory("grant", grant)],
      }),
    );
  }

  async createSession(input: ConnectorAgentSession): Promise<void> {
    const item = this.insert("session", input);
    const session = item.Put.Item.record as ConnectorAgentSession;
    const now = this.now();
    if (
      session.revision !== 1 ||
      session.status !== "active" ||
      session.expiresAt <= now
    )
      throw new ConnectorStoreError("INVALID_STATE");
    const grant = await this.getGrant(session.grantId);
    if (
      grant?.status !== "active" ||
      grant.userId !== session.userId ||
      grant.orgId !== session.orgId ||
      session.expiresAt > grant.expiresAt
      || session.mfaVerifiedAt !== grant.mfaVerifiedAt
    )
      throw new ConnectorStoreError("CONFLICT");
    const client = await this.getClient(grant.clientId);
    if (
      client?.status !== "active" ||
      !client.allowedResources.includes(grant.resource) ||
      !grant.scopes.every((scope) => client.allowedScopes.includes(scope))
    )
      throw new ConnectorStoreError("CONFLICT");
    await this.write(
      new TransactWriteCommand({
        TransactItems: [
          this.activeCondition("client", client, now),
          this.activeCondition("grant", grant, now),
          item,
          this.directory("session", session),
          this.organizationDirectory("session", session),
        ],
      }),
    );
  }

  /**
   * Narrows what a grant authorizes (VAULTGUARD-123, D-016). The authority
   * revision moves, so every durable delegated binding captured before — an
   * agent session's proposals, approvals and apply subjects — fails closed on
   * its next capture and its next commit condition. The rotation revision does
   * NOT move: an access token whose scopes are still inside the narrowed grant
   * stays usable, and one that carries a removed scope is refused by the live
   * scope ceiling on its next call. The refresh family survives: the issuer
   * issues a refresh of it with only the scopes the narrowed grant still holds
   * (`GateOAuthIssuer.exchange`), so the connection continues narrowed rather
   * than having to reconnect.
   *
   * No route calls this yet. It writes no audit row of its own (unlike
   * `revoke`, whose `revocation.prepare` hook commits one with it): the caller
   * that wires a human or governance scope-narrowing control MUST record who
   * narrowed which grant, from which scopes to which, in the same transaction
   * or before acknowledging it (VG123-SEC-2).
   *
   * It can only narrow. The new scopes must be a non-empty strict subset of the
   * live grant's, and the write is conditioned on the exact status, rotation
   * revision, authority revision and scopes it read, so a concurrent revoke,
   * refresh or second narrowing refuses rather than being overwritten. A
   * revoked, suspended or expired grant is never narrowed back into use.
   * Returns the new authority revision.
   */
  async narrowGrantScopes(id: string, expectedAuthorityRevision: number, scopes: string[]): Promise<number> {
    if (!revision(expectedAuthorityRevision) || !revision(expectedAuthorityRevision + 1))
      throw new ConnectorStoreError("INVALID_STATE");
    const now = this.now();
    const current = (await this.read("grant", id)) as ConnectorGrant | null;
    if (
      !current ||
      current.status !== "active" ||
      current.expiresAt <= now ||
      (current.authorityRevision ?? current.revision) !== expectedAuthorityRevision
    )
      throw new ConnectorStoreError("CONFLICT");
    if (
      !list(scopes, (scope) => current.scopes.includes(scope as string), current.scopes.length) ||
      scopes.length >= current.scopes.length
    )
      throw new ConnectorStoreError("INVALID_STATE");
    const next = expectedAuthorityRevision + 1;
    await this.write(
      new UpdateCommand({
        TableName: this.options.tableName,
        Key: key("grant", id),
        ConditionExpression: `#r.#s = :active AND #r.#v = :rotation AND #r.#e > :now AND #r.#scopes = :scopes AND ${
          current.authorityRevision === undefined ? "attribute_not_exists(#r.#a)" : "#r.#a = :authority"
        }`,
        UpdateExpression: "SET #r.#scopes = :narrowed, #r.#a = :next",
        ExpressionAttributeNames: {
          "#r": "record",
          "#s": "status",
          "#v": "revision",
          "#e": "expiresAt",
          "#scopes": "scopes",
          "#a": "authorityRevision",
        },
        ExpressionAttributeValues: {
          ":active": "active",
          ":rotation": current.revision,
          ":now": now,
          ":scopes": current.scopes,
          ...(current.authorityRevision === undefined ? {} : { ":authority": current.authorityRevision }),
          ":narrowed": [...scopes],
          ":next": next,
        },
      }),
    );
    return next;
  }

  /** Client changes use a new registration ID; revoke the old one permanently. */
  revokeClient(id: string, expectedRevision: number): Promise<number> {
    return this.revoke("client", id, expectedRevision);
  }
  revokeGrant(id: string, expectedRevision: number): Promise<number> {
    return this.revoke("grant", id, expectedRevision);
  }
  revokeSession(id: string, expectedRevision: number): Promise<number> {
    return this.revoke("session", id, expectedRevision);
  }

  private revoke(
    kind: Kind,
    id: string,
    expectedRevision: number,
  ): Promise<number> {
    return observeWorkspaceOperation('revocation', async (): Promise<number> => {
    if (!revision(expectedRevision) || !revision(expectedRevision + 1))
      throw new ConnectorStoreError("INVALID_STATE");
    const current = await this.read(kind, id);
    const field = kind === "client" ? "configRevision" : "revision";
    const currentRevision =
      current &&
      (kind === "client"
        ? (current as ConnectorClientRegistration).configRevision
        : (current as ConnectorGrant).revision);
    if (
      current?.status === "revoked" &&
      currentRevision === expectedRevision + 1
    )
      { if (this.options.revocation && !await this.options.revocation.confirmed(kind, id, expectedRevision)) throw new ConnectorStoreError('OUTCOME_UNKNOWN'); return expectedRevision + 1; }
    if (
      !current ||
      currentRevision !== expectedRevision ||
      current.status === "revoked"
    )
      throw new ConnectorStoreError("CONFLICT");
    // Revoking a grant is an authority change (VAULTGUARD-123, D-016): its
    // authority revision moves with it, conditioned on the value read, so a
    // durable binding can never match a revoked grant's authority generation.
    // A legacy grant has none and keeps deriving it from `revision`.
    const authority =
      kind === "grant" && (current as ConnectorGrant).authorityRevision !== undefined
        ? (current as ConnectorGrant).authorityRevision!
        : null;
    const update = new UpdateCommand({
        TableName: this.options.tableName,
        Key: key(kind, id),
        ConditionExpression: `#r.#v = :expected AND #r.#s <> :revoked${authority === null ? "" : " AND #r.#a = :authority"}`,
        UpdateExpression: `SET #r.#s = :revoked, #r.#v = :next${authority === null ? "" : ", #r.#a = :nextAuthority"}`,
        ExpressionAttributeNames: {
          "#r": "record",
          "#s": "status",
          "#v": field,
          ...(authority === null ? {} : { "#a": "authorityRevision" }),
        },
        ExpressionAttributeValues: {
          ":expected": expectedRevision,
          ":next": expectedRevision + 1,
          ":revoked": "revoked",
          ...(authority === null ? {} : { ":authority": authority, ":nextAuthority": authority + 1 }),
        },
      });
    const audit = await this.options.revocation?.prepare(kind, id, expectedRevision);
    try { await this.write(audit ? new TransactWriteCommand({ TransactItems: [{ Update: { ...update.input, UpdateExpression: update.input.UpdateExpression!, Key: update.input.Key } }, ...audit] }) : update); }
    catch (error) {
      if (!this.options.revocation || !await this.options.revocation.confirmed(kind, id, expectedRevision)) throw error;
      const after = await this.read(kind, id);
      if (after?.status !== 'revoked' || (after as ConnectorGrant).revision !== expectedRevision + 1) throw error;
    }
    return expectedRevision + 1;
      });
  }
}
