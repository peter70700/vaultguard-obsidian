/**
 * The organization's connector admission policy (VAULTGUARD-91; decided by
 * Peter Sedmak on 2026-09-17, recorded on the ticket).
 *
 * Three stored `OrgSettings` fields, next to the D-014 family policy
 * (`disabledRemoteMcpFeatures`):
 *
 * - `blockedConnectorClientIds`: connector client registrations this
 *   organization refuses.
 * - `blockedConnectorHostKinds`: host kinds (`chatgpt`, `claude`, `custom-mcp`)
 *   this organization refuses.
 * - `remoteMcpKillSwitch`: the organization kill switch. Engaged, every remote
 *   MCP family is disabled (on top of D-014) AND every connector grant and
 *   session in the organization is refused at the authorization boundary,
 *   `get_capabilities` included.
 *
 * A refusal never deletes, revokes or rewrites a grant, session, client or
 * delegation record: it is evaluated from the live settings on every token
 * issuance and every authorized request, so releasing the switch or removing a
 * block ends the refusal. An update that changes only these fields leaves the
 * organization's `policyRevision` unchanged (`settingsUpdateMovesPolicyRevision`),
 * so the existing credentials and delegation rows work again once it is
 * released; any other settings change still moves it.
 *
 * Fail closed: a policy that cannot be read (a store error, no active
 * organization record, or a stored value that is not the documented shape)
 * refuses every connector exactly as the kill switch does. A malformed list is
 * never trimmed to its recognisable entries, because dropping an entry an
 * administrator meant as "blocked" would admit that connector.
 *
 * This module is pure data with no storage or environment access, so the
 * settings owner (`shared/utils.ts`, `users/handler.ts`), the OAuth issuer, the
 * MCP hosts and the web consumers share one vocabulary and one decision.
 */

import { connectorAuthorizationDays } from './connector-authorization-policy';

export const CONNECTOR_HOST_KINDS = Object.freeze(['chatgpt', 'claude', 'custom-mcp'] as const);
export type ConnectorHostKind = (typeof CONNECTOR_HOST_KINDS)[number];

/** Bound on a stored client deny-list; a larger list is refused, never truncated. */
export const MAX_BLOCKED_CONNECTOR_CLIENT_IDS = 100;

const CLIENT_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$/u;

export function isConnectorHostKind(value: unknown): value is ConnectorHostKind {
  return typeof value === 'string' && (CONNECTOR_HOST_KINDS as readonly string[]).includes(value);
}

export function isConnectorClientId(value: unknown): value is string {
  return typeof value === 'string' && CLIENT_ID.test(value);
}

/** One organization's admission decision inputs. */
export interface OrganizationConnectorPolicy {
  readonly blockedClientIds: readonly string[];
  readonly blockedHostKinds: readonly ConnectorHostKind[];
  readonly killSwitch: boolean;
}

export const DEFAULT_ORGANIZATION_CONNECTOR_POLICY: OrganizationConnectorPolicy = Object.freeze({
  blockedClientIds: Object.freeze([]) as readonly string[],
  blockedHostKinds: Object.freeze([]) as readonly ConnectorHostKind[],
  killSwitch: false,
});

/** The stored `OrgSettings` field names this policy owns. */
export const ORGANIZATION_CONNECTOR_POLICY_FIELDS = Object.freeze([
  'blockedConnectorClientIds',
  'blockedConnectorHostKinds',
  'remoteMcpKillSwitch',
] as const);

/** What a stored settings object says about connector admission. */
export type StoredOrganizationConnectorPolicy =
  | { readonly state: 'readable'; readonly policy: OrganizationConnectorPolicy }
  | { readonly state: 'malformed' };

function uniqueList<T extends string>(value: unknown, check: (entry: unknown) => entry is T, max: number): T[] | null {
  if (!Array.isArray(value) || value.length > max || !value.every(check)) return null;
  return [...new Set(value as T[])];
}

/**
 * Classifies the connector admission fields of a STORED settings object.
 *
 * Each field that is absent takes its default (nothing blocked, switch
 * released). Any field that is present but not exactly the documented shape
 * makes the whole policy malformed: a non-list, a DynamoDB set, an unknown host
 * kind, an identifier outside the connector id vocabulary, a list longer than
 * the bound, or a switch that is not a boolean. Duplicates are tolerated and
 * removed; host kinds are returned in vocabulary order.
 */
export function readStoredOrganizationConnectorPolicy(settings: unknown): StoredOrganizationConnectorPolicy {
  if (settings === undefined || settings === null) {
    return { state: 'readable', policy: DEFAULT_ORGANIZATION_CONNECTOR_POLICY };
  }
  if (typeof settings !== 'object' || Array.isArray(settings)) return { state: 'malformed' };
  const raw = settings as Record<string, unknown>;
  try { connectorAuthorizationDays(raw.connectorAuthorizationDays); } catch { return { state: 'malformed' }; }
  let blockedClientIds: readonly string[] = [];
  let blockedHostKinds: readonly ConnectorHostKind[] = [];
  let killSwitch = false;
  if (raw.blockedConnectorClientIds !== undefined) {
    const list = uniqueList(raw.blockedConnectorClientIds, isConnectorClientId, MAX_BLOCKED_CONNECTOR_CLIENT_IDS);
    if (!list) return { state: 'malformed' };
    blockedClientIds = list;
  }
  if (raw.blockedConnectorHostKinds !== undefined) {
    const list = uniqueList(raw.blockedConnectorHostKinds, isConnectorHostKind, CONNECTOR_HOST_KINDS.length * 4);
    if (!list) return { state: 'malformed' };
    blockedHostKinds = CONNECTOR_HOST_KINDS.filter((kind) => list.includes(kind));
  }
  if (raw.remoteMcpKillSwitch !== undefined) {
    if (typeof raw.remoteMcpKillSwitch !== 'boolean') return { state: 'malformed' };
    killSwitch = raw.remoteMcpKillSwitch;
  }
  return { state: 'readable', policy: { blockedClientIds, blockedHostKinds, killSwitch } };
}

/**
 * The policy an ACTIVE organization record carries, or `null` when there is no
 * readable decision: no record, an organization that is not active, or a
 * malformed stored value. `null` always refuses.
 */
export function organizationConnectorPolicyOf(active: {
  allowed: boolean;
  org?: { settings?: unknown } | null;
}): OrganizationConnectorPolicy | null {
  if (!active.allowed || !active.org) return null;
  const stored = readStoredOrganizationConnectorPolicy(active.org.settings);
  return stored.state === 'readable' ? stored.policy : null;
}

export type OrganizationConnectorRefusal = 'kill_switch' | 'client_blocked' | 'host_kind_blocked' | 'policy_unreadable';

/** The admission decision for one connector under one organization's policy. */
export function organizationConnectorRefusal(
  policy: OrganizationConnectorPolicy | null,
  connector: { clientId: string; hostKind: string },
): OrganizationConnectorRefusal | null {
  if (!policy) return 'policy_unreadable';
  if (policy.killSwitch) return 'kill_switch';
  if (policy.blockedClientIds.includes(connector.clientId)) return 'client_blocked';
  // A host kind outside the vocabulary has no admission decision and is refused.
  if (!isConnectorHostKind(connector.hostKind) || policy.blockedHostKinds.includes(connector.hostKind)) {
    return 'host_kind_blocked';
  }
  return null;
}

/** Reads one organization's live connector policy. `null` (or a throw) refuses. */
export type OrganizationConnectorPolicyReader = (orgId: string) => Promise<OrganizationConnectorPolicy | null>;

export class OrganizationConnectorRefusedError extends Error {
  constructor(readonly refusal: OrganizationConnectorRefusal) {
    super('ORGANIZATION_CONNECTOR_REFUSED');
    this.name = 'OrganizationConnectorRefusedError';
  }
}

/**
 * Refuses a connector the organization does not currently admit. A reader that
 * throws is an unreadable policy, never an admission.
 */
export async function assertOrganizationConnectorAdmitted(
  reader: OrganizationConnectorPolicyReader,
  connector: { orgId: string; clientId: string; hostKind: string },
): Promise<void> {
  let policy: OrganizationConnectorPolicy | null;
  try {
    policy = await reader(connector.orgId);
  } catch {
    policy = null;
  }
  const refusal = organizationConnectorRefusal(policy, connector);
  if (refusal) throw new OrganizationConnectorRefusedError(refusal);
}

/**
 * A SUBMITTED settings update's connector admission fields: the problems that
 * make the route refuse it (never silently dropping an entry an administrator
 * believed was blocked), and the normalized values to store.
 */
export function validateSubmittedOrganizationConnectorPolicy(
  body: Record<string, unknown>,
  current: OrganizationConnectorPolicy,
): { errors: string[]; policy: OrganizationConnectorPolicy } {
  const errors: string[] = [];
  let blockedClientIds = current.blockedClientIds;
  let blockedHostKinds = current.blockedHostKinds;
  let killSwitch = current.killSwitch;
  if (body.blockedConnectorClientIds !== undefined) {
    const value = body.blockedConnectorClientIds;
    if (!Array.isArray(value)) {
      errors.push('blockedConnectorClientIds must be a list of connector client IDs.');
    } else if (value.length > MAX_BLOCKED_CONNECTOR_CLIENT_IDS) {
      errors.push(`blockedConnectorClientIds may name at most ${MAX_BLOCKED_CONNECTOR_CLIENT_IDS} clients.`);
    } else if (!value.every(isConnectorClientId)) {
      errors.push('blockedConnectorClientIds contains a value that is not a connector client ID.');
    } else {
      blockedClientIds = [...new Set(value as string[])];
    }
  }
  if (body.blockedConnectorHostKinds !== undefined) {
    const value = body.blockedConnectorHostKinds;
    if (!Array.isArray(value) || !value.every(isConnectorHostKind)) {
      errors.push(`blockedConnectorHostKinds must be a list drawn from: ${CONNECTOR_HOST_KINDS.join(', ')}.`);
    } else {
      blockedHostKinds = CONNECTOR_HOST_KINDS.filter((kind) => (value as string[]).includes(kind));
    }
  }
  if (body.remoteMcpKillSwitch !== undefined) {
    if (typeof body.remoteMcpKillSwitch !== 'boolean') {
      errors.push('remoteMcpKillSwitch must be true or false.');
    } else {
      killSwitch = body.remoteMcpKillSwitch;
    }
  }
  return { errors, policy: { blockedClientIds, blockedHostKinds, killSwitch } };
}

/**
 * Whether a settings update moves the organization's `policyRevision`
 * (VAULTGUARD-91 review finding F1, D-020).
 *
 * `policyRevision` pins every access token, refresh-token family and delegated
 * binding minted under it, so moving it ends those credentials for good. A
 * connector admission change must not do that: Peter Sedmak's decisions make a
 * block and the kill switch a REVERSIBLE refusal that keeps every record, and
 * both are enforced live, from the stored policy, at consent, at issuance, on
 * every authenticated request and on every delegated recheck. So an update
 * whose only change is to the three connector admission fields leaves the
 * revision where it is, and releasing the switch or removing a block lets the
 * existing connections work again.
 *
 * Every other update moves it exactly as before: any change to another
 * persisted field (including a D-014 family or the organization name), and an
 * update that changes nothing at all.
 */
export function settingsUpdateMovesPolicyRevision(
  before: Readonly<Record<string, unknown>>,
  after: Readonly<Record<string, unknown>>,
): boolean {
  const connectorFields = new Set<string>(ORGANIZATION_CONNECTOR_POLICY_FIELDS);
  const same = (key: string) => JSON.stringify(before[key] ?? null) === JSON.stringify(after[key] ?? null);
  const keys = new Set([...Object.keys(before), ...Object.keys(after)]);
  const otherChanged = [...keys].some((key) => !connectorFields.has(key) && !same(key));
  const connectorChanged = ORGANIZATION_CONNECTOR_POLICY_FIELDS.some((key) => !same(key));
  return otherChanged || !connectorChanged;
}

/**
 * The content-free audit summary of a connector policy change: identifiers
 * and closed-vocabulary values only. `null` when nothing changed, so an
 * unrelated settings update records no connector policy fields.
 */
export function organizationConnectorPolicyChange(
  before: OrganizationConnectorPolicy,
  after: OrganizationConnectorPolicy,
): Record<string, unknown> | null {
  const added = <T>(from: readonly T[], to: readonly T[]) => to.filter((entry) => !from.includes(entry));
  const change: Record<string, unknown> = {};
  const clientsBlocked = added(before.blockedClientIds, after.blockedClientIds);
  const clientsUnblocked = added(after.blockedClientIds, before.blockedClientIds);
  const hostKindsBlocked = added(before.blockedHostKinds, after.blockedHostKinds);
  const hostKindsUnblocked = added(after.blockedHostKinds, before.blockedHostKinds);
  if (clientsBlocked.length) change.connectorClientsBlocked = clientsBlocked;
  if (clientsUnblocked.length) change.connectorClientsUnblocked = clientsUnblocked;
  if (hostKindsBlocked.length) change.connectorHostKindsBlocked = hostKindsBlocked;
  if (hostKindsUnblocked.length) change.connectorHostKindsUnblocked = hostKindsUnblocked;
  if (before.killSwitch !== after.killSwitch) change.remoteMcpKillSwitch = after.killSwitch ? 'engaged' : 'released';
  return Object.keys(change).length ? change : null;
}
