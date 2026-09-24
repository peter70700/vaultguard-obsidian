import { observeWorkspaceOperation } from '../workspace-observability/telemetry';
/**
 * Provider-neutral delegated OAuth authorization boundary for remote connectors.
 *
 * Token signature verification is injected so the same policy can be exercised
 * with an ephemeral local issuer and, later, a Cognito/JWKS verifier. Every
 * accepted request is also checked against the live client registration and
 * grant. JWT validity by itself is deliberately insufficient: disconnect and
 * refresh-family replay must invalidate already-minted access credentials.
 */

import {
  assertOrganizationConnectorAdmitted,
  type OrganizationConnectorPolicy,
} from "./organization-connector-policy";

export const CONNECTOR_OAUTH_SCOPES = [
  "workspace:read",
  "files:list",
  "files:read",
  "connector:read",
] as const;

/** Production read admission. Semantic vocabulary requires separate organization
 * consent and a configured provider; adding vocabulary never adds it to a grant.
 * The frozen G0 scope constants above remain unchanged. */
export const WORKSPACE_READ_OAUTH_SCOPES = [
  ...CONNECTOR_OAUTH_SCOPES,
  "files:search", "history:read", "graph:read", "context:read", "semantic:read",
  "coordination:read", "access:read", "permissions:read", "members:read", "shares:read", "audit:read",
] as const;

/** Internal proposal/approval record revalidation profile. No issuer or resource
 * admission selects this profile by default. Read transport remains read-only.
 * `history:restore` and `context:propose` are admitted here because a restore
 * and a Context Pack proposal are changes to the same workspace, and the §8.5
 * and §8.6 tools that carry them (VAULTGUARD-108, VAULTGUARD-110) have no other
 * profile. Admitting a scope is not granting it: a grant, a client
 * registration and a delegation row must each name it, and every tool still
 * re-checks membership, path permission and organization policy. */
export const WORKSPACE_PROPOSAL_OAUTH_SCOPES = [...WORKSPACE_READ_OAUTH_SCOPES, 'changes:read', 'changes:propose', 'changes:apply', 'history:restore', 'context:propose'] as const;

/** Internal access-chain reader only. No issuer or deployed transport admits this profile. */
export const WORKSPACE_ACCESS_OAUTH_SCOPES = [...WORKSPACE_PROPOSAL_OAUTH_SCOPES, 'access:propose', 'access:apply', 'shares:write'] as const;

/** Internal transfer/human-handoff reads only; no issuer or resource enables it by default.
 * `coordination:read` is already in the read profile, so it is not repeated: a
 * repeated entry inflates every "at most one of each admitted scope" bound that
 * validates a stored grant against this vocabulary. */
export const WORKSPACE_TRANSFER_OAUTH_SCOPES = [...WORKSPACE_ACCESS_OAUTH_SCOPES, 'transfers:prepare', 'coordination:write'] as const;

/**
 * The admission profiles, in one place.
 *
 * A profile is the OUTER BOUND of what a grant, a client registration, a
 * delegation row and an issued token may carry on one deployment. Every profile
 * except `workspace-read-v1` is opt-in and disabled by default: no issuer,
 * resource metadata or host selects one unless a deployment configures it
 * explicitly (`connector-oauth/handler.ts`), and the production read host pins
 * `workspace-read-v1` in source. Widening a profile never widens a caller's
 * authority: every tool still re-checks the live grant, membership, path
 * permission and organization policy.
 */
export const CONNECTOR_SCOPE_PROFILES = {
  "workspace-read-v1": WORKSPACE_READ_OAUTH_SCOPES,
  "workspace-proposal-v1": WORKSPACE_PROPOSAL_OAUTH_SCOPES,
  "workspace-access-v1": WORKSPACE_ACCESS_OAUTH_SCOPES,
  "workspace-transfer-v1": WORKSPACE_TRANSFER_OAUTH_SCOPES,
} as const;

export type ConnectorScopeProfile = keyof typeof CONNECTOR_SCOPE_PROFILES;

/** The profiles that admit a write or transfer scope. Opt-in, never a default. */
export const CONNECTOR_WRITE_SCOPE_PROFILES = [
  "workspace-proposal-v1",
  "workspace-access-v1",
  "workspace-transfer-v1",
] as const;

export type ConnectorWriteScopeProfile = (typeof CONNECTOR_WRITE_SCOPE_PROFILES)[number];

export function isConnectorScopeProfile(value: unknown): value is ConnectorScopeProfile {
  return typeof value === "string" && value in CONNECTOR_SCOPE_PROFILES;
}

export function isConnectorWriteScopeProfile(value: unknown): value is ConnectorWriteScopeProfile {
  return (CONNECTOR_WRITE_SCOPE_PROFILES as readonly string[]).includes(value as string);
}

/** The admitted vocabulary for a profile, de-duplicated. Omitting the profile
 * keeps the frozen G0 four. */
export function connectorProfileScopes(profile?: ConnectorScopeProfile): readonly string[] {
  return [...new Set<string>(profile ? CONNECTOR_SCOPE_PROFILES[profile] : CONNECTOR_OAUTH_SCOPES)];
}

export type ConnectorOAuthScope = (typeof CONNECTOR_OAUTH_SCOPES)[number];

/**
 * `offline_access` is an authorization-server capability, not a resource
 * permission. It asks for a refresh token, which this issuer already returns
 * unconditionally for the authorization-code grant.
 *
 * It is kept OUT of CONNECTOR_OAUTH_SCOPES deliberately. That constant is the
 * set of scopes that carry authorization: they are stored on the grant and
 * copied into the access token's `scope` claim, where anything present reads as
 * a permission. `offline_access` is therefore accepted at the request boundary
 * and stripped before it can reach either.
 *
 * Why accept it at all: OpenAI instructs ChatGPT connector builders to request
 * `offline_access` and to verify the provider advertises it in
 * `scopes_supported`, warning that a provider which does not may lose access at
 * expiry and that a late fix requires recreating the app. Before this was split
 * out, the issuer advertised only the four resource scopes while the request
 * validator was a strict allow-list capped at four entries, so a client that
 * followed that instruction was rejected outright with `invalid_scope`.
 * See VAULTGUARD-48 and finding PPM-5 in
 * reports/evidence/workspace-gates/provider-plan-matrix-2026-09-07/matrix.json.
 */
export const CONNECTOR_OAUTH_OFFLINE_SCOPE = "offline_access";

/** Everything a client may legally send in a `scope` parameter. */
export const CONNECTOR_OAUTH_REQUEST_SCOPES = [
  ...CONNECTOR_OAUTH_SCOPES,
  CONNECTOR_OAUTH_OFFLINE_SCOPE,
] as const;

export type ConnectorClientStatus = "active" | "suspended" | "revoked";
export type ConnectorGrantStatus = "active" | "expired" | "suspended" | "revoked";
export type ConnectorAgentSessionStatus = "active" | "ended" | "expired" | "revoked";

export interface ConnectorClientRegistration {
  clientId: string;
  hostKind: "chatgpt" | "claude" | "custom-mcp";
  redirectUris: string[];
  allowedResources: string[];
  allowedScopes: string[];
  pkceRequired: true;
  status: ConnectorClientStatus;
  configRevision: number;
}

export interface ConnectorGrant {
  grantId: string;
  clientId: string;
  userId: string;
  orgId: string;
  resource: string;
  scopes: string[];
  status: ConnectorGrantStatus;
  /**
   * The ROTATION revision. Every refresh-token exchange moves it, so an access
   * token (whose `grant_revision` claim must equal it exactly) dies the moment
   * its family rotates. Nothing durable may bind to it (VAULTGUARD-123, D-016).
   */
  revision: number;
  /**
   * The AUTHORITY revision (VAULTGUARD-123, D-016). It moves only when what
   * this grant authorizes changes — revocation or a scope change — and never on
   * refresh, so a delegated proposal, approval or session binds to it and
   * survives token rotation while any authority change fails closed at once.
   * Organization policy changes move the organization's own `policyRevision`,
   * which every such binding pins exactly beside this one.
   *
   * Optional only for rows written before it existed: such a grant's authority
   * revision is its rotation revision (`connectorGrantAuthorityRevision`), so a
   * legacy grant keeps the old, stricter behaviour instead of gaining a longer
   * lifetime nobody consented to.
   */
  authorityRevision?: number;
  /** Cognito-verified TOTP at the original browser consent; never inferred from enrollment or refresh. */
  mfaVerifiedAt?: number;
  expiresAt: number;
}

/** The authority generation a durable delegated binding pins (see
 * `ConnectorGrant.authorityRevision`). A legacy grant falls back to its
 * rotation revision, which is strictly more restrictive. */
export function connectorGrantAuthorityRevision(grant: Pick<ConnectorGrant, "revision" | "authorityRevision">): number {
  return grant.authorityRevision ?? grant.revision;
}

/**
 * The grant as a durable binding may observe it: every field EXCEPT the
 * rotation revision, plus the authority revision. Fingerprints and commit
 * conditions over a grant use this view, so a refresh changes neither while a
 * revocation, scope change, expiry or identity change still does.
 */
export function connectorGrantAuthorityView(grant: ConnectorGrant) {
  return {
    grantId: grant.grantId,
    clientId: grant.clientId,
    userId: grant.userId,
    orgId: grant.orgId,
    resource: grant.resource,
    scopes: [...grant.scopes],
    status: grant.status,
    authorityRevision: connectorGrantAuthorityRevision(grant),
    mfaVerifiedAt: grant.mfaVerifiedAt ?? null,
    expiresAt: grant.expiresAt,
  };
}

/**
 * The commit condition a durable delegated binding places on a grant row: every
 * field of `connectorGrantAuthorityView` must still be exactly what was
 * captured. A refresh (which moves only `revision`) passes it; a revocation,
 * scope change, expiry change or identity change fails it. A legacy grant
 * without `authorityRevision` is pinned on its rotation revision instead, and
 * must still have no authority revision, so it keeps the stricter behaviour.
 */
export function connectorGrantAuthorityCondition(tableName: string, grant: ConnectorGrant) {
  const view = connectorGrantAuthorityView(grant);
  const legacy = grant.authorityRevision === undefined;
  return {
    TableName: tableName,
    Key: {
      pk: `CONNECTOR#GRANT#${Buffer.from(grant.grantId).toString("base64url")}`,
      sk: "STATE",
    },
    ConditionExpression: [
      "#rec.#grantId = :grantId",
      "#rec.#clientId = :clientId",
      "#rec.#userId = :userId",
      "#rec.#orgId = :orgId",
      "#rec.#resource = :resource",
      "#rec.#scopes = :scopes",
      "#rec.#status = :status",
      "#rec.#expiresAt = :expiresAt",
      grant.mfaVerifiedAt === undefined ? "attribute_not_exists(#rec.#mfaVerifiedAt)" : "#rec.#mfaVerifiedAt = :mfaVerifiedAt",
      legacy ? "#rec.#rotation = :authority AND attribute_not_exists(#rec.#authority)" : "#rec.#authority = :authority",
    ].join(" AND "),
    ExpressionAttributeNames: {
      "#rec": "record",
      "#grantId": "grantId",
      "#clientId": "clientId",
      "#userId": "userId",
      "#orgId": "orgId",
      "#resource": "resource",
      "#scopes": "scopes",
      "#status": "status",
      "#expiresAt": "expiresAt",
      "#mfaVerifiedAt": "mfaVerifiedAt",
      "#authority": "authorityRevision",
      ...(legacy ? { "#rotation": "revision" } : {}),
    },
    ExpressionAttributeValues: {
      ":grantId": view.grantId,
      ":clientId": view.clientId,
      ":userId": view.userId,
      ":orgId": view.orgId,
      ":resource": view.resource,
      ":scopes": view.scopes,
      ":status": view.status,
      ":expiresAt": view.expiresAt,
      ...(grant.mfaVerifiedAt === undefined ? {} : { ":mfaVerifiedAt": grant.mfaVerifiedAt }),
      ":authority": view.authorityRevision,
    },
  };
}

export interface ConnectorAgentSession {
  sessionId: string;
  grantId: string;
  userId: string;
  orgId: string;
  status: ConnectorAgentSessionStatus;
  revision: number;
  expiresAt: number;
  /** Bound to the verified consent grant, never generated by refresh. */
  mfaVerifiedAt?: number;
}

export interface ConnectorAccessTokenClaims {
  iss: string;
  aud: string | string[];
  resource?: string;
  client_id: string;
  sub: string;
  org_id: string;
  grant_id: string;
  scope: string;
  token_use: "access";
  grant_revision: number;
  client_config_revision: number;
  policy_revision?: number;
  session_id?: string;
  session_revision?: number;
  iat: number;
  nbf?: number;
  exp: number;
  jti: string;
}

export interface ConnectorTokenVerifier {
  verify(credential: string): Promise<unknown> | unknown;
}

export interface ConnectorSubjectCutoffCondition {
  TableName: string;
  Key: { pk: string; sk: string };
  ConditionExpression: string;
  ExpressionAttributeNames?: Record<string, string>;
  ExpressionAttributeValues?: Record<string, number>;
}

export interface ConnectorAuthorizationStore {
  getClient(clientId: string): Promise<ConnectorClientRegistration | null> | ConnectorClientRegistration | null;
  getGrant(grantId: string): Promise<ConnectorGrant | null> | ConnectorGrant | null;
  getPolicyRevision?(orgId: string): Promise<number | null> | number | null;
  getSession?(sessionId: string): Promise<ConnectorAgentSession | null> | ConnectorAgentSession | null;
  /**
   * VAULTGUARD-91: the organization's live connector admission policy (client
   * and host-kind deny-list, kill switch; `shared/organization-connector-policy.ts`).
   * `null`, or a throw, is an unreadable policy and refuses. Present, it is
   * enforced on every authentication after the client and grant are verified;
   * omitted (the frozen G0 edge and synthetic stores), no organization
   * connector policy applies. Every production composition supplies it.
   */
  getOrganizationConnectorPolicy?(orgId: string): Promise<OrganizationConnectorPolicy | null>;
  /**
   * VAULTGUARD-129: whether the grant's USER may still use it. `false`, or a
   * throw, refuses. It refuses while the user's revocation marker exists (from
   * the first write of a user revocation until reactivation completes) and,
   * after that, any grant created at or before the user's connector cutoff, so
   * a revoked user's connections never revive on reactivation and reconnecting
   * goes back through consent (`DynamoConnectorAuthorizationStore`,
   * `shared/connector-subject-revocation.ts`). Omitted (the frozen G0 edge and
   * synthetic stores), no subject check applies; every production composition
   * that honours a grant for a remote MCP request or issuance supplies it.
   */
  admitsGrantSubject?(grant: ConnectorGrant): Promise<boolean>;
  /**
   * VAULTGUARD-129: the cutoff half of `admitsGrantSubject`, without the
   * revocation-marker read, for owners that read and condition on the marker
   * themselves (`CurrentApprovalPrincipals`). `false`, or a throw, refuses: the
   * grant was created at or before its user's last revocation and never
   * returns to use. `DynamoConnectorAuthorizationStore` always provides it.
   */
  grantPostdatesSubjectCutoff?(grant: ConnectorGrant): Promise<boolean>;
  /** The same check plus a commit fence; null refuses. A revoke/reactivate cycle
   * cannot resurrect a previously captured, directory-less delegated write. */
  captureGrantSubjectCutoff?(grant: ConnectorGrant): Promise<ConnectorSubjectCutoffCondition | null>;
}

export type ConnectorAuthErrorCode =
  | "AUDIENCE_MISMATCH"
  | "CLIENT_INACTIVE"
  | "CLIENT_MISMATCH"
  | "GRANT_INACTIVE"
  | "INVALID_CREDENTIAL"
  | "ISSUER_MISMATCH"
  | "ORGANIZATION_REFUSED"
  | "POLICY_INACTIVE"
  | "RESOURCE_MISMATCH"
  | "SESSION_INACTIVE"
  | "SCOPE_DENIED"
  | "SUBJECT_REVOKED"
  | "TOKEN_EXPIRED"
  | "TOKEN_NOT_ACTIVE";

/** Internal reason codes are safe for tests/audit classification, not callers. */
export class ConnectorAuthError extends Error {
  readonly publicMessage = "Unauthorized";

  constructor(readonly code: ConnectorAuthErrorCode) {
    super(code);
    this.name = "ConnectorAuthError";
  }
}

/**
 * VAULTGUARD-113 (MCPS-GAP-2): a credential that is valid in every respect -- its
 * signature, client, grant, policy revision and agent session all verified -- but
 * that does not carry a scope this request requires. The caller is answered
 * exactly as for any other `SCOPE_DENIED`; the verified context travels with the
 * refusal only so the edge can attribute a content-free audit record to it.
 */
export class ConnectorScopeDeniedError extends ConnectorAuthError {
  constructor(readonly context: ConnectorAuthorizationContext) {
    super("SCOPE_DENIED");
  }
}

export interface ConnectorAuthorizationContext {
  clientId: string;
  clientConfigRevision: number;
  grantId: string;
  /** The rotation revision this access token was minted at (exactly the live one). */
  grantRevision: number;
  /**
   * The live grant's AUTHORITY revision (VAULTGUARD-123, D-016). Durable
   * delegated bindings pin this, never `grantRevision`, so they survive refresh.
   */
  grantAuthorityRevision: number;
  /** Epoch seconds, from the live grant record this request was checked against. */
  grantExpiresAt: number;
  hostKind: ConnectorClientRegistration["hostKind"];
  orgId: string;
  policyRevision: number | null;
  resource: string;
  scopes: string[];
  subject: string;
  tokenExpiresAt: number;
  tokenId: string;
  sessionId: string | null;
  sessionRevision: number | null;
  sessionExpiresAt: number | null;
}

export interface AuthenticateConnectorCredentialInput {
  credential: string;
  expectedIssuer: string;
  expectedAudience: string;
  expectedResource: string;
  requiredScopes?: string[];
  allowedClientIds?: string[];
  clockSkewSeconds?: number;
  requirePolicyRevision?: boolean;
  requireSession?: boolean;
}

export interface ConnectorAuthServiceOptions {
  store: ConnectorAuthorizationStore;
  tokenVerifier: ConnectorTokenVerifier;
  now?: () => number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function requireString(record: Record<string, unknown>, key: string): string {
  const value = record[key];
  if (typeof value !== "string" || value.length === 0) {
    throw new ConnectorAuthError("INVALID_CREDENTIAL");
  }
  return value;
}

function requireFiniteNumber(record: Record<string, unknown>, key: string): number {
  const value = record[key];
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new ConnectorAuthError("INVALID_CREDENTIAL");
  }
  return value;
}

function requireRevision(record: Record<string, unknown>, key: string): number {
  const value = requireFiniteNumber(record, key);
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new ConnectorAuthError("INVALID_CREDENTIAL");
  }
  return value;
}

function parseClaims(value: unknown): ConnectorAccessTokenClaims {
  if (!isRecord(value)) {
    throw new ConnectorAuthError("INVALID_CREDENTIAL");
  }

  const audience = value.aud;
  if (
    !(typeof audience === "string" && audience.length > 0) &&
    !(
      Array.isArray(audience) &&
      audience.length > 0 &&
      audience.every((item) => typeof item === "string" && item.length > 0)
    )
  ) {
    throw new ConnectorAuthError("INVALID_CREDENTIAL");
  }

  const tokenUse = requireString(value, "token_use");
  if (tokenUse !== "access") {
    throw new ConnectorAuthError("INVALID_CREDENTIAL");
  }

  const resource = value.resource;
  if (resource !== undefined && (typeof resource !== "string" || resource.length === 0)) {
    throw new ConnectorAuthError("INVALID_CREDENTIAL");
  }

  const notBefore = value.nbf;
  if (notBefore !== undefined && (typeof notBefore !== "number" || !Number.isFinite(notBefore))) {
    throw new ConnectorAuthError("INVALID_CREDENTIAL");
  }

  const sessionId = value.session_id;
  const sessionRevision = value.session_revision;
  const policyRevision = value.policy_revision;
  if ((sessionId === undefined) !== (sessionRevision === undefined)) {
    throw new ConnectorAuthError("INVALID_CREDENTIAL");
  }
  if (sessionId !== undefined && (typeof sessionId !== "string" || sessionId.length === 0)) {
    throw new ConnectorAuthError("INVALID_CREDENTIAL");
  }
  if (
    sessionRevision !== undefined &&
    (typeof sessionRevision !== "number" || !Number.isSafeInteger(sessionRevision) || sessionRevision < 0)
  ) {
    throw new ConnectorAuthError("INVALID_CREDENTIAL");
  }
  if (
    policyRevision !== undefined &&
    (typeof policyRevision !== "number" || !Number.isSafeInteger(policyRevision) || policyRevision < 0)
  ) {
    throw new ConnectorAuthError("INVALID_CREDENTIAL");
  }

  return {
    iss: requireString(value, "iss"),
    aud: audience as string | string[],
    resource: resource as string | undefined,
    client_id: requireString(value, "client_id"),
    sub: requireString(value, "sub"),
    org_id: requireString(value, "org_id"),
    grant_id: requireString(value, "grant_id"),
    scope: requireString(value, "scope"),
    token_use: "access",
    grant_revision: requireRevision(value, "grant_revision"),
    client_config_revision: requireRevision(value, "client_config_revision"),
    policy_revision: policyRevision as number | undefined,
    session_id: sessionId as string | undefined,
    session_revision: sessionRevision as number | undefined,
    iat: requireFiniteNumber(value, "iat"),
    nbf: notBefore as number | undefined,
    exp: requireFiniteNumber(value, "exp"),
    jti: requireString(value, "jti"),
  };
}

function audienceMatchesExactly(audience: string | string[], expected: string): boolean {
  return typeof audience === "string"
    ? audience === expected
    : audience.length === 1 && audience[0] === expected;
}

function parseScopes(scopeClaim: string): string[] {
  const scopes = scopeClaim.split(/\s+/u).filter(Boolean);
  if (scopes.length === 0 || new Set(scopes).size !== scopes.length) {
    throw new ConnectorAuthError("INVALID_CREDENTIAL");
  }
  return scopes;
}

function sameSetOrSubset(values: string[], ceiling: string[]): boolean {
  const allowed = new Set(ceiling);
  return values.every((value) => allowed.has(value));
}

export class ConnectorAuthService {
  private readonly now: () => number;

  constructor(private readonly options: ConnectorAuthServiceOptions) {
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
  }

  authenticate(input: AuthenticateConnectorCredentialInput): Promise<ConnectorAuthorizationContext> {
    return observeWorkspaceOperation('auth', async (): Promise<ConnectorAuthorizationContext> => {
    let decoded: unknown;
    try {
      decoded = await this.options.tokenVerifier.verify(input.credential);
    } catch {
      throw new ConnectorAuthError("INVALID_CREDENTIAL");
    }

    const claims = parseClaims(decoded);
    const now = this.now();
    const skew = Math.max(0, input.clockSkewSeconds ?? 0);

    if (claims.iss !== input.expectedIssuer) {
      throw new ConnectorAuthError("ISSUER_MISMATCH");
    }
    if (!audienceMatchesExactly(claims.aud, input.expectedAudience)) {
      throw new ConnectorAuthError("AUDIENCE_MISMATCH");
    }
    // Cognito binds the RFC 8707 resource to `aud`. A custom issuer may also
    // emit the explicit resource claim; when present it must agree exactly.
    if (claims.resource !== undefined && claims.resource !== input.expectedResource) {
      throw new ConnectorAuthError("RESOURCE_MISMATCH");
    }
    if (claims.resource === undefined && input.expectedAudience !== input.expectedResource) {
      throw new ConnectorAuthError("RESOURCE_MISMATCH");
    }
    if (claims.nbf !== undefined && claims.nbf > now + skew) {
      throw new ConnectorAuthError("TOKEN_NOT_ACTIVE");
    }
    if (claims.iat > now + skew) {
      throw new ConnectorAuthError("TOKEN_NOT_ACTIVE");
    }
    if (claims.exp <= now - skew) {
      throw new ConnectorAuthError("TOKEN_EXPIRED");
    }
    if (input.allowedClientIds && !input.allowedClientIds.includes(claims.client_id)) {
      throw new ConnectorAuthError("CLIENT_MISMATCH");
    }
    if (input.requireSession && !claims.session_id) {
      throw new ConnectorAuthError("SESSION_INACTIVE");
    }
    if (input.requirePolicyRevision && claims.policy_revision === undefined) {
      throw new ConnectorAuthError("POLICY_INACTIVE");
    }

    const [client, grant] = await Promise.all([
      this.options.store.getClient(claims.client_id),
      this.options.store.getGrant(claims.grant_id),
    ]);

    if (client?.status !== "active") {
      throw new ConnectorAuthError("CLIENT_INACTIVE");
    }
    if (
      client.configRevision !== claims.client_config_revision ||
      !client.allowedResources.includes(input.expectedResource)
    ) {
      throw new ConnectorAuthError("CLIENT_MISMATCH");
    }
    if (grant?.status !== "active" || grant.expiresAt <= now) {
      throw new ConnectorAuthError("GRANT_INACTIVE");
    }
    const grantAuthorityRevision = connectorGrantAuthorityRevision(grant);
    if (!Number.isSafeInteger(grantAuthorityRevision) || grantAuthorityRevision < 1) {
      throw new ConnectorAuthError("GRANT_INACTIVE");
    }
    if (
      grant.clientId !== claims.client_id ||
      grant.userId !== claims.sub ||
      grant.orgId !== claims.org_id ||
      grant.resource !== input.expectedResource ||
      grant.revision !== claims.grant_revision
    ) {
      throw new ConnectorAuthError("GRANT_INACTIVE");
    }

    // VAULTGUARD-129: a revoked user's grant refuses from the first write of the
    // revocation, and a grant from before the user's last revocation never
    // authenticates again, whatever its own status. Read live on every request
    // (and again at egress, which re-authenticates); unreadable refuses.
    if (this.options.store.admitsGrantSubject) {
      let admitted = false;
      try {
        admitted = (await this.options.store.admitsGrantSubject(grant)) === true;
      } catch {
        admitted = false;
      }
      if (!admitted) throw new ConnectorAuthError("SUBJECT_REVOKED");
    }

    // VAULTGUARD-91: the organization's connector admission, from the live
    // settings on every request (and again at egress, which re-authenticates).
    // A blocked client or host kind, an engaged kill switch and an unreadable
    // policy all refuse here, before any tool -- `get_capabilities` included --
    // is reachable. Nothing is revoked: releasing the block ends the refusal.
    if (this.options.store.getOrganizationConnectorPolicy) {
      try {
        await assertOrganizationConnectorAdmitted(
          (orgId) => this.options.store.getOrganizationConnectorPolicy!(orgId),
          { orgId: grant.orgId, clientId: client.clientId, hostKind: client.hostKind },
        );
      } catch {
        throw new ConnectorAuthError("ORGANIZATION_REFUSED");
      }
    }

    const scopes = parseScopes(claims.scope);
    if (!sameSetOrSubset(scopes, client.allowedScopes) || !sameSetOrSubset(scopes, grant.scopes)) {
      throw new ConnectorAuthError("SCOPE_DENIED");
    }

    let policyRevision: number | null = null;
    if (claims.policy_revision !== undefined) {
      if (!this.options.store.getPolicyRevision) {
        throw new ConnectorAuthError("POLICY_INACTIVE");
      }
      policyRevision = await this.options.store.getPolicyRevision(claims.org_id);
      if (policyRevision !== claims.policy_revision) {
        throw new ConnectorAuthError("POLICY_INACTIVE");
      }
    }

    let session: ConnectorAgentSession | null = null;
    if (claims.session_id) {
      if (!this.options.store.getSession) {
        throw new ConnectorAuthError("SESSION_INACTIVE");
      }
      session = await this.options.store.getSession(claims.session_id);
      if (
        session?.status !== "active" ||
        session.expiresAt <= now ||
        session.sessionId !== claims.session_id ||
        session.grantId !== claims.grant_id ||
        session.userId !== claims.sub ||
        session.orgId !== claims.org_id ||
        session.revision !== claims.session_revision ||
        session.expiresAt > grant.expiresAt ||
        session.mfaVerifiedAt !== grant.mfaVerifiedAt
      ) {
        throw new ConnectorAuthError("SESSION_INACTIVE");
      }
    }

    const context: ConnectorAuthorizationContext = {
      clientId: claims.client_id,
      clientConfigRevision: claims.client_config_revision,
      grantId: claims.grant_id,
      grantRevision: claims.grant_revision,
      grantAuthorityRevision,
      grantExpiresAt: grant.expiresAt,
      hostKind: client.hostKind,
      orgId: claims.org_id,
      policyRevision,
      resource: input.expectedResource,
      scopes,
      subject: claims.sub,
      tokenExpiresAt: claims.exp,
      tokenId: claims.jti,
      sessionId: session?.sessionId ?? null,
      sessionRevision: session?.revision ?? null,
      sessionExpiresAt: session?.expiresAt ?? null,
    };
    // The request's own scope requirement is decided last, once every other
    // property of the credential is verified, so a refusal here is attributable
    // to a verified principal. Nothing is reachable with it: it is still thrown.
    if (!sameSetOrSubset(input.requiredScopes ?? [], scopes)) {
      throw new ConnectorScopeDeniedError(context);
    }
    return context;
      });
  }
}
