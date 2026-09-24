/**
 * The organization's remote MCP feature policy (contract §5 "∩ organization
 * policy"; D-014, decided by Peter Sedmak on 2026-09-16 for VAULTGUARD-114).
 *
 * `OrgSettings.disabledRemoteMcpFeatures` is the one owner of that decision.
 * Every remote MCP tool descriptor advertises one of the feature ids below as
 * its `policyFeature`, and both discovery and `tools/call` refuse a tool whose
 * feature the organization has not enabled.
 *
 * Defaults, when an organization has never stored the setting:
 *
 * - A family that serves only read tools (and the web-ceremony handoffs, which
 *   complete only through a human in the web workspace) is ENABLED.
 * - A family that serves any `propose`, `apply` or `admin` tool is DISABLED
 *   until an organization administrator explicitly enables it by storing a
 *   list that omits it (`PUT /orgs/{orgId}/settings`).
 *
 * An unreadable policy (a store error, no organization record, or a stored
 * value that is not a list of known feature ids) is not a decision: the MCP
 * hosts fail closed and report every policy-gated family
 * `temporarily_unavailable` (`infrastructure/lambda/mcp/authorized-handler.ts`).
 * Only an ABSENT stored value means "never decided" and resolves to the
 * defaults; a malformed one is never trimmed down to its recognisable entries,
 * because dropping an entry an operator meant as "disabled" would enable that
 * family (`readStoredRemoteMcpFeaturePolicy`).
 *
 * This module is pure data with no storage or environment access, so the
 * settings owner (`shared/utils.ts`) and the MCP hosts share one vocabulary.
 * `tests/mcp-organization-feature-policy.test.ts` derives each family's default
 * from the risk classes of the tools that advertise it, so a descriptor that
 * moves a family across that line, or a new feature id, fails the build.
 *
 * Adding a propose/apply/admin family later: an organization that already
 * stored an explicit list has not decided about the new id, and would see it
 * enabled. Such a change must also add the new id to every stored list (or
 * introduce an explicit enable record) in the same change. Retiring an id is
 * the mirror case: a stored list that still names it becomes malformed and
 * fails closed until it is migrated.
 */

export const REMOTE_MCP_POLICY_FEATURE_DEFAULTS = Object.freeze({
  remote_mcp: 'enabled',
  remote_mcp_files: 'enabled',
  remote_mcp_transfers: 'enabled',
  remote_mcp_graph: 'enabled',
  remote_mcp_knowledge: 'enabled',
  semantic_discovery: 'enabled',
  remote_mcp_changes: 'disabled',
  remote_mcp_access: 'disabled',
  remote_mcp_context: 'disabled',
  remote_mcp_coordination: 'disabled',
} as const satisfies Record<string, 'enabled' | 'disabled'>);

export type RemoteMcpPolicyFeature = keyof typeof REMOTE_MCP_POLICY_FEATURE_DEFAULTS;

export const REMOTE_MCP_POLICY_FEATURES: readonly RemoteMcpPolicyFeature[] = Object.freeze(
  Object.keys(REMOTE_MCP_POLICY_FEATURE_DEFAULTS) as RemoteMcpPolicyFeature[],
);

/** What an organization that never stored the setting has disabled. */
export const DEFAULT_DISABLED_REMOTE_MCP_FEATURES: readonly RemoteMcpPolicyFeature[] = Object.freeze(
  REMOTE_MCP_POLICY_FEATURES.filter((feature) => REMOTE_MCP_POLICY_FEATURE_DEFAULTS[feature] === 'disabled'),
);

const FEATURE_SET: ReadonlySet<string> = new Set(REMOTE_MCP_POLICY_FEATURES);

export function isRemoteMcpPolicyFeature(value: unknown): value is RemoteMcpPolicyFeature {
  return typeof value === 'string' && FEATURE_SET.has(value);
}

/** What a stored `disabledRemoteMcpFeatures` value means. */
export type StoredRemoteMcpFeaturePolicy =
  /** Never stored: the D-014 defaults apply. */
  | { readonly state: 'default' }
  /** A list of known feature ids: the organization's decision. */
  | { readonly state: 'explicit'; readonly disabled: RemoteMcpPolicyFeature[] }
  /** Present but not a list of known ids: no readable decision. */
  | { readonly state: 'malformed' };

/**
 * Classifies a STORED `disabledRemoteMcpFeatures` value.
 *
 * Only an absent value (`undefined`) is "never decided". A list of known
 * feature ids (duplicates allowed) is an explicit decision, returned in
 * vocabulary order and deduplicated. Anything else — a non-list, `null`, a
 * DynamoDB set, or a list carrying a non-string, an unknown or a retired id —
 * is malformed. It is deliberately NOT reduced to its recognisable entries:
 * `["remote_mcp_Changes", "remote_mcp_access"]` meant to disable changes, and
 * dropping the typo would enable them.
 */
export function readStoredRemoteMcpFeaturePolicy(value: unknown): StoredRemoteMcpFeaturePolicy {
  if (value === undefined) return { state: 'default' };
  if (!Array.isArray(value) || !value.every(isRemoteMcpPolicyFeature)) return { state: 'malformed' };
  const present = new Set<string>(value);
  return { state: 'explicit', disabled: REMOTE_MCP_POLICY_FEATURES.filter((feature) => present.has(feature)) };
}

/**
 * A SUBMITTED `disabledRemoteMcpFeatures` value that the settings route has
 * already validated, reduced to the known vocabulary in vocabulary order and
 * deduplicated. Returns `fallback` when the value is not an array, so an
 * omitted field keeps the stored decision. Stored values go through
 * `readStoredRemoteMcpFeaturePolicy`, never through this.
 */
export function normalizeDisabledRemoteMcpFeatures(
  value: unknown,
  fallback: RemoteMcpPolicyFeature[] | undefined,
): RemoteMcpPolicyFeature[] | undefined {
  if (!Array.isArray(value)) return fallback;
  const present = new Set(value.filter(isRemoteMcpPolicyFeature));
  return REMOTE_MCP_POLICY_FEATURES.filter((feature) => present.has(feature));
}

/**
 * The feature ids in a submitted list that are not in the vocabulary. The
 * settings route refuses such a request rather than silently dropping an id an
 * administrator believed they had disabled.
 */
export function unknownRemoteMcpFeatures(value: readonly unknown[]): string[] {
  return value.filter((entry) => !isRemoteMcpPolicyFeature(entry)).map((entry) => String(entry).slice(0, 64));
}

/**
 * The organization's decision on one advertised feature id, given the
 * disabled list it stores. A feature id outside the vocabulary has no
 * decision and is never enabled.
 */
export function remoteMcpFeatureEnabled(disabled: readonly string[], feature: string): boolean {
  return isRemoteMcpPolicyFeature(feature) && !disabled.includes(feature);
}

/**
 * The content-free audit summary of a policy change: the families it enabled
 * and the families it disabled, each drawn from the closed vocabulary and in
 * vocabulary order. `null` when the change enables and disables nothing, so an
 * unrelated settings update records no policy fields.
 */
export function remoteMcpFeaturePolicyChange(
  before: readonly string[],
  after: readonly string[],
): { remoteMcpFeaturesEnabled: RemoteMcpPolicyFeature[]; remoteMcpFeaturesDisabled: RemoteMcpPolicyFeature[] } | null {
  const was = new Set(before);
  const now = new Set(after);
  const remoteMcpFeaturesEnabled = REMOTE_MCP_POLICY_FEATURES.filter((feature) => was.has(feature) && !now.has(feature));
  const remoteMcpFeaturesDisabled = REMOTE_MCP_POLICY_FEATURES.filter((feature) => !was.has(feature) && now.has(feature));
  return remoteMcpFeaturesEnabled.length === 0 && remoteMcpFeaturesDisabled.length === 0
    ? null
    : { remoteMcpFeaturesEnabled, remoteMcpFeaturesDisabled };
}
