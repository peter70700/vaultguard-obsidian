/**
 * permission-explain.ts — PURE, client-side permission-EXPLAIN trace.
 *
 * This is a faithful port of the backend `evaluatePermission` precedence
 * (infrastructure/lambda/shared/utils.ts:537) run over the `PermissionRule[]`
 * that the plugin has already fetched via `getPermissions` /
 * `getUserPermissions`. It is NARRATION ONLY — the server stays the sole
 * source of truth (every datum the graph shows was fetched as the signed-in
 * user; the explain panel never widens what the user can see). When an
 * authoritative server level is supplied and disagrees with the locally
 * computed level, the trace flags `serverDrift` and still reports the server
 * level as truth.
 *
 * ZERO imports from obsidian / the API client / the network. Fully unit-
 * testable. Mirrors these backend functions exactly so the narration matches
 * the real decision:
 *   - pathMatchesPattern   (utils.ts:1004) — glob + parent-folder inheritance
 *   - getPathSpecificity   (utils.ts:1047) — specificity scoring
 *   - ruleLevelRank        (utils.ts:648)  — actions+effect → ordered level
 *   - rolesIncludeOrgAdmin (utils.ts:1510) — admin/owner/vault-admin bypass
 *   - vaultRoleAllowsAction(utils.ts:2387) — membership role baseline
 *   - evaluatePermission   (utils.ts:537)  — the overall precedence order
 */

/** Actions a rule can grant or deny. Mirrors backend `PermissionAction`. */
export type ExplainAction = "read" | "write" | "delete" | "admin" | "list";

/** Allow/deny effect of a rule. */
export type ExplainEffect = "allow" | "deny";

/** Effective access level, same vocabulary as the server's PermissionAccessLevel. */
export type ExplainLevel = "none" | "read" | "write" | "admin";

/** Vault membership role (distinct from org-level roles). */
export type ExplainVaultRole = "viewer" | "editor" | "admin";

/**
 * The subset of a `PermissionRule` (src/api/client.ts:52) that the trace needs.
 * Accepting a structural subset (rather than the full record) keeps this module
 * decoupled from the API client and trivially testable with plain objects.
 */
export interface ExplainRule {
  id: string;
  /** User ID, '*' for wildcard, or a role name when `role` is set. */
  userId?: string;
  /** Role name for role-based rules, or null/undefined for user-specific. */
  role?: string | null;
  pathPattern: string;
  actions: ExplainAction[];
  effect: ExplainEffect;
  priority: number;
  /** Optional ISO timestamp after which the rule is ignored. */
  expiresAt?: string;
}

/** Why the trace arrived at its `effectiveLevel`. */
export type ExplainDecidedBy = "adminBypass" | "rule" | "roleBaseline";

export interface ExplainAccessInput {
  /** The principal whose access is being explained. */
  userId: string;
  /** The principal's role inside THIS vault (drives the baseline fallthrough). */
  role: ExplainVaultRole;
  /**
   * Org-level roles, if known. An org admin / owner / vault-admin short-circuits
   * to full access (mirrors rolesIncludeOrgAdmin). The vault membership role
   * 'admin' is handled separately by the role baseline — it is NOT an org role.
   */
  orgRoles?: string[];
  /** Target path (vault-relative; leading slash is normalized away). */
  path: string;
  /** The action being evaluated. Defaults to "read". */
  action?: ExplainAction;
  /** Candidate rules already fetched for this (user, path). */
  rules: ExplainRule[];
  /**
   * Optional authoritative per-principal level from the server's
   * PathAccessSummary. When present, the trace compares it to the computed
   * level and sets `serverDrift` — the server value is always reported as truth.
   */
  serverLevel?: ExplainLevel;
  /** Injectable "now" (ISO) for deterministic expiry tests. Defaults to Date.now(). */
  now?: string;
}

export interface ExplainTrace {
  /** The computed effective level after the full precedence chain. */
  effectiveLevel: ExplainLevel;
  /** What decided the outcome. */
  decidedBy: ExplainDecidedBy;
  /** The winning rule's id, or null for adminBypass / roleBaseline. */
  winningRuleId: string | null;
  /** Ids of matching rules that lost to the winner (e.g. an allow beaten by a deny). */
  overriddenRuleIds: string[];
  /** The winning rule's expiry, if it is time-bound. */
  expiresAt: string | null;
  /** The server's authoritative level, echoed back when supplied. */
  serverLevel?: ExplainLevel;
  /** True when a supplied serverLevel disagrees with the computed level. */
  serverDrift: boolean;
  /** Human-readable narration lines, in evaluation order. */
  steps: string[];
}

// ─── Backend-mirrored helpers ────────────────────────────────────────────────

/** Port of rolesIncludeOrgAdmin (utils.ts:1510). */
function rolesIncludeOrgAdmin(roles: string[] | undefined): boolean {
  if (!roles) return false;
  return roles.includes("admin") || roles.includes("vault-admin") || roles.includes("owner");
}

/**
 * Port of pathMatchesPattern (utils.ts:1004): glob ('*' = one segment,
 * '**' = any number of segments, '?' = single char), exact match, and
 * parent-folder inheritance.
 */
export function pathMatchesPattern(filePath: string, pattern: string): boolean {
  const normalizedPath = filePath.replace(/\/+/g, "/").replace(/\/$/, "");
  const normalizedPattern = pattern.replace(/\/+/g, "/").replace(/\/$/, "");

  if (normalizedPath === normalizedPattern) {
    return true;
  }

  const regexStr = normalizedPattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&") // Escape regex specials (not * or ?)
    .replace(/\*\*/g, "{{GLOBSTAR}}")
    .replace(/\*/g, "[^/]+")
    .replace(/\?/g, "[^/]")
    .replace(/{{GLOBSTAR}}/g, ".*");

  const regex = new RegExp(`^${regexStr}$`);

  if (regex.test(normalizedPath)) {
    return true;
  }

  // Inheritance: any parent folder of filePath matching the pattern counts.
  const pathSegments = normalizedPath.split("/");
  for (let i = pathSegments.length - 1; i >= 1; i--) {
    const parentPath = pathSegments.slice(0, i).join("/");
    if (regex.test(parentPath)) {
      return true;
    }
  }

  return false;
}

/** Port of getPathSpecificity (utils.ts:1047): more segments, fewer wildcards = higher. */
export function getPathSpecificity(pattern: string): number {
  const segments = pattern.split("/").filter(Boolean);
  let score = segments.length * 10;
  for (const segment of segments) {
    if (segment === "**") score -= 8;
    else if (segment === "*") score -= 5;
    else if (segment.includes("*") || segment.includes("?")) score -= 3;
  }
  return score;
}

/** Port of ruleLevelRank (utils.ts:648): actions+effect → ordered numeric rank. */
export function ruleLevelRank(actions: ExplainAction[], effect: ExplainEffect): number {
  if (effect === "deny") return 0; // a deny rule grants nothing
  if (!actions.includes("read")) return 0; // no read ⇒ effectively none
  if (actions.includes("admin")) return 3; // admin
  if (actions.includes("write") || actions.includes("delete")) return 2; // write
  return 1; // read
}

/** Maps an ordered rank back to the level vocabulary. */
function rankToLevel(rank: number): ExplainLevel {
  switch (rank) {
    case 3:
      return "admin";
    case 2:
      return "write";
    case 1:
      return "read";
    default:
      return "none";
  }
}

/**
 * Port of VAULT_ROLE_DEFAULT_ACTIONS + vaultRoleAllowsAction (utils.ts:2381).
 * The baseline level a membership role grants on a path with no covering rule.
 */
const VAULT_ROLE_DEFAULT_ACTIONS: Record<ExplainVaultRole, ExplainAction[]> = {
  admin: ["read", "write", "delete", "admin", "list"],
  editor: ["read", "write", "delete", "list"],
  viewer: ["read", "list"],
};

function vaultRoleAllowsAction(role: ExplainVaultRole, action: ExplainAction): boolean {
  return VAULT_ROLE_DEFAULT_ACTIONS[role].includes(action);
}

/** The level a membership role grants by default (its full action set's rank). */
function roleBaselineLevel(role: ExplainVaultRole): ExplainLevel {
  return rankToLevel(ruleLevelRank(VAULT_ROLE_DEFAULT_ACTIONS[role], "allow"));
}

// ─── The trace ───────────────────────────────────────────────────────────────

/**
 * Reconstructs the backend permission decision for a (principal, path, action)
 * from already-fetched rules, returning a structured, narratable trace.
 *
 * Precedence (exactly evaluatePermission, utils.ts:537):
 *   1. org admin / owner / vault-admin role ⇒ full access (no rule consulted)
 *   2. drop expired rules (expiresAt <= now)
 *   3. keep rules where pathMatchesPattern(path, pattern) && actions.includes(action)
 *   4. sort: specificity desc, then deny-over-allow, then priority desc
 *   5. winner decides allow/deny (and the level via ruleLevelRank)
 *   6. no matching rule ⇒ membership role baseline
 */
export function explainAccess(input: ExplainAccessInput): ExplainTrace {
  const action: ExplainAction = input.action ?? "read";
  const now = input.now ?? new Date().toISOString();
  const steps: string[] = [];

  const finalize = (
    partial: Omit<ExplainTrace, "serverLevel" | "serverDrift" | "steps">,
  ): ExplainTrace => {
    const serverLevel = input.serverLevel;
    const serverDrift = serverLevel !== undefined && serverLevel !== partial.effectiveLevel;
    if (serverLevel !== undefined) {
      if (serverDrift) {
        steps.push(
          `Server reports "${serverLevel}" for this path — client narration computed "${partial.effectiveLevel}". The server is authoritative; this drift is flagged.`,
        );
      } else {
        steps.push(`Server confirms "${serverLevel}" — client narration agrees.`);
      }
    }
    return { ...partial, serverLevel, serverDrift, steps };
  };

  // 1. Admin bypass — org admins / owners / vault-admins have full access in
  //    every vault in their org, regardless of any deny rule on the path.
  if (rolesIncludeOrgAdmin(input.orgRoles)) {
    steps.push(
      `${describePrincipal(input)} holds an org admin/owner role → full access via admin bypass (no per-file rule is consulted).`,
    );
    return finalize({
      effectiveLevel: "admin",
      decidedBy: "adminBypass",
      winningRuleId: null,
      overriddenRuleIds: [],
      expiresAt: null,
    });
  }

  steps.push(`Evaluating ${action} on "${input.path}" for ${describePrincipal(input)}.`);

  // 2. Drop expired time-bound rules.
  const liveRules = input.rules.filter((rule) => !rule.expiresAt || rule.expiresAt > now);
  const expiredCount = input.rules.length - liveRules.length;
  if (expiredCount > 0) {
    steps.push(`Dropped ${expiredCount} expired rule(s) (expiresAt ≤ now).`);
  }

  // 3. Keep rules whose pattern matches the path AND grant/deny this action.
  const matchingRules = liveRules.filter(
    (rule) => pathMatchesPattern(input.path, rule.pathPattern) && rule.actions.includes(action),
  );

  // 6. No matching rule ⇒ membership role baseline.
  if (matchingRules.length === 0) {
    const allowed = vaultRoleAllowsAction(input.role, action);
    const level: ExplainLevel = allowed ? roleBaselineLevel(input.role) : "none";
    steps.push(
      allowed
        ? `No rule matches; fall through to the "${input.role}" membership baseline → ${level}.`
        : `No rule matches and the "${input.role}" membership baseline does not grant ${action} → none.`,
    );
    return finalize({
      effectiveLevel: level,
      decidedBy: "roleBaseline",
      winningRuleId: null,
      overriddenRuleIds: [],
      expiresAt: null,
    });
  }

  steps.push(
    `${matchingRules.length} rule(s) match the path and action: ${matchingRules
      .map((r) => `#${r.id} (${r.effect} on ${r.pathPattern}, priority ${r.priority})`)
      .join(", ")}.`,
  );

  // 4. Sort: specificity desc, then deny-over-allow, then priority desc.
  const sorted = [...matchingRules].sort((a, b) => {
    const specificityDiff = getPathSpecificity(b.pathPattern) - getPathSpecificity(a.pathPattern);
    if (specificityDiff !== 0) return specificityDiff;
    if (a.effect === "deny" && b.effect === "allow") return -1;
    if (a.effect === "allow" && b.effect === "deny") return 1;
    return b.priority - a.priority;
  });

  // 5. Winner decides.
  const winningRule = sorted[0];
  const overriddenRuleIds = sorted.slice(1).map((rule) => rule.id);
  const level: ExplainLevel =
    winningRule.effect === "allow" ? rankToLevel(ruleLevelRank(winningRule.actions, "allow")) : "none";

  steps.push(
    `Winner: rule #${winningRule.id} — ${winningRule.effect} on "${winningRule.pathPattern}" ` +
      `(specificity ${getPathSpecificity(winningRule.pathPattern)}, priority ${winningRule.priority}) ⇒ ${level}.`,
  );
  if (overriddenRuleIds.length > 0) {
    steps.push(
      `Overridden by the winner: ${overriddenRuleIds.map((id) => `#${id}`).join(", ")} ` +
        `(lower specificity, lost the deny-over-allow tiebreak, or lower priority).`,
    );
  }
  if (winningRule.expiresAt) {
    steps.push(describeExpiry(winningRule.expiresAt, now));
  }

  return finalize({
    effectiveLevel: level,
    decidedBy: "rule",
    winningRuleId: winningRule.id,
    overriddenRuleIds,
    expiresAt: winningRule.expiresAt ?? null,
  });
}

// ─── Narration helpers ───────────────────────────────────────────────────────

function describePrincipal(input: ExplainAccessInput): string {
  return `user ${input.userId} (vault role: ${input.role})`;
}

/** Human-readable "expires in N days/hours" line for a time-bound winning rule. */
function describeExpiry(expiresAt: string, now: string): string {
  const expiryMs = Date.parse(expiresAt);
  const nowMs = Date.parse(now);
  if (Number.isNaN(expiryMs) || Number.isNaN(nowMs)) {
    return `This grant is time-bound (expires ${expiresAt}).`;
  }
  const deltaMs = expiryMs - nowMs;
  if (deltaMs <= 0) return `This grant expired at ${expiresAt}.`;
  const days = Math.floor(deltaMs / 86_400_000);
  if (days >= 1) {
    return `This grant expires in ${days} day${days === 1 ? "" : "s"} (${expiresAt}).`;
  }
  const hours = Math.max(1, Math.floor(deltaMs / 3_600_000));
  return `This grant expires in ${hours} hour${hours === 1 ? "" : "s"} (${expiresAt}).`;
}
