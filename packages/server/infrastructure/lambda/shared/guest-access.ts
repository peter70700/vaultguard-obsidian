export const MIN_GUEST_ACCESS_DAYS = 1;
export const MAX_GUEST_ACCESS_DAYS = 90;
export const DEFAULT_GUEST_ACCESS_DAYS = 30;
export const MAX_GUEST_VAULTS_PER_INVITE = 50;

export function normalizeGuestVaultIds(value: unknown): string[] {
  if (!Array.isArray(value)) {
    throw new RangeError("Select at least one vault for guest access.");
  }
  const ids: string[] = [];
  const seen = new Set<string>();
  for (const candidate of value) {
    if (typeof candidate !== "string" || !candidate.trim()) {
      throw new RangeError("Every guest vault ID must be a non-empty string.");
    }
    const vaultId = candidate.trim();
    if (!seen.has(vaultId)) {
      seen.add(vaultId);
      ids.push(vaultId);
    }
  }
  if (ids.length === 0 || ids.length > MAX_GUEST_VAULTS_PER_INVITE) {
    throw new RangeError(
      `Select between 1 and ${MAX_GUEST_VAULTS_PER_INVITE} vaults for guest access.`,
    );
  }
  return ids;
}

export function isIdenticalGuestMembership(
  value: Record<string, unknown> | null | undefined,
  expected: { vaultId: string; userId: string; expiresAt: string },
): boolean {
  return !!value &&
    value.vaultId === expected.vaultId &&
    value.userId === expected.userId &&
    value.role === "viewer" &&
    value.accessKind === "guest" &&
    value.expiresAt === expected.expiresAt;
}

export function isIdenticalGuestPermissionRule(
  value: Record<string, unknown> | null | undefined,
  expected: { vaultId: string; userId: string; expiresAt: string },
): boolean {
  return !!value &&
    value.vaultId === expected.vaultId &&
    value.userId === expected.userId &&
    value.pathPattern === "/**" &&
    value.effect === "allow" &&
    value.expiresAt === expected.expiresAt &&
    Array.isArray(value.actions) &&
    value.actions.length === 2 &&
    value.actions.includes("read") &&
    value.actions.includes("list");
}

export function guestAccessExpiresAt(days: number, nowMs = Date.now()): string {
  if (!Number.isInteger(days) || days < MIN_GUEST_ACCESS_DAYS || days > MAX_GUEST_ACCESS_DAYS) {
    throw new RangeError(
      `Guest access duration must be a whole number from ${MIN_GUEST_ACCESS_DAYS} to ${MAX_GUEST_ACCESS_DAYS} days.`,
    );
  }
  return new Date(nowMs + days * 24 * 60 * 60 * 1000).toISOString();
}

/** Missing expiry means permanent access; malformed or elapsed expiry fails closed. */
export function isExpiringAccessActive(
  expiresAt: string | undefined,
  nowMs = Date.now(),
): boolean {
  if (!expiresAt) return true;
  const expiresAtMs = Date.parse(expiresAt);
  return Number.isFinite(expiresAtMs) && expiresAtMs > nowMs;
}

/** Keep an offline-capable lease inside the guest membership boundary. */
export function clampLeaseExpiration(
  nowMs: number,
  durationSeconds: number,
  accessExpiresAt?: string,
): string {
  const normalExpiryMs = nowMs + durationSeconds * 1000;
  if (!accessExpiresAt) return new Date(normalExpiryMs).toISOString();
  const accessExpiryMs = Date.parse(accessExpiresAt);
  if (!Number.isFinite(accessExpiryMs) || accessExpiryMs <= nowMs) {
    throw new RangeError("Guest access has expired.");
  }
  return new Date(Math.min(normalExpiryMs, accessExpiryMs)).toISOString();
}

/**
 * Guest rows belonging to an identity that a guest invite CREATED. Absence of `guestOrigin`
 * on a stored row means this, deliberately and provably: no code path can write an attached
 * row until the DR-7 invite path lands, so every guest row written to date is invite-origin
 * by construction.
 */
export const GUEST_ORIGIN_INVITE = "invite";

/**
 * Guest rows ATTACHED to an identity that already existed (CONTEXT.md DR-7). The invite path
 * writes this value and `summarizeGuestAccess` reads it; both sides reference this constant
 * rather than the literal, so a rename fails the typecheck instead of silently un-protecting
 * every attached identity. It is the explicit, opt-in value — everything else is owned.
 */
export const GUEST_ORIGIN_ATTACHED = "attached";

export type GuestOrigin = typeof GUEST_ORIGIN_INVITE | typeof GUEST_ORIGIN_ATTACHED;

/**
 * Structural shape of the VaultMembers rows this rule reasons about. Declared here rather
 * than imported from `shared/utils`, which already imports this module — a value import back
 * would close a circular pair. A `VaultMemberRecord[]` satisfies this structurally, and
 * `guestOrigin` passes straight through at runtime without editing that interface.
 */
export interface GuestMembershipRow {
  vaultId: string;
  userId: string;
  /** Absent on rows written before the guest feature; those count as permanent. */
  accessKind?: string;
  /** ISO boundary enforced by membership checks, permission rules, and leases. */
  expiresAt?: string;
  /** One of GUEST_ORIGIN_*. Absent counts as invite-origin. */
  guestOrigin?: string;
}

export interface GuestAccessSummary {
  /** Badge predicate: no permanent membership anywhere in the org, and >=1 guest row. */
  isGuest: boolean;
  /** LATEST guest expiry — the moment access actually ends. Undefined when !isGuest. */
  expiresAt?: string;
  /** Sweeper predicate: isGuest, zero active guest rows, and >=1 invite-origin guest row. */
  fullyExpired: boolean;
  /** Guest rows past their boundary — always safe to delete, even when !fullyExpired. */
  expiredRows: GuestMembershipRow[];
}

/**
 * The single rule answering "is this user a guest, when does their access end, and is it
 * fully over". `handleListUsers` renders the guest badge from it (DR-1) and the reconciler's
 * guest sweeper decides teardown from it (DR-5), so changing this function changes both —
 * which is the point: the badge and the sweeper cannot drift apart.
 *
 * `fullyExpired` — and ONLY `fullyExpired` — is origin-aware. `isGuest` and `expiresAt` stay
 * purely row-shaped, so the badge keeps showing an attached guest's temporary access and its
 * end date, which is exactly what an admin needs to see. The origin fact changes who gets
 * torn down, not who gets badged.
 *
 * Pass ORG-SCOPED rows for ONE user.
 */
export function summarizeGuestAccess(
  memberships: GuestMembershipRow[],
  nowMs = Date.now(),
): GuestAccessSummary {
  const guests = memberships.filter((row) => row.accessKind === "guest");
  // Never `=== "member"`: rows written before the guest feature carry no accessKind at all
  // and must count as permanent.
  const permanent = memberships.filter((row) => row.accessKind !== "guest");
  const activeGuests = guests.filter((row) => isExpiringAccessActive(row.expiresAt, nowMs));
  // The complement of activeGuests, returned unconditionally — even when !isGuest — because
  // a lapsed guest row grants nothing (every enforcement site already fails closed on it),
  // so deleting it is always safe. This is what lets the sweeper's restraint branch clean up
  // WITHOUT tearing an account down.
  const expiredRows = guests.filter((row) => !isExpiringAccessActive(row.expiresAt, nowMs));
  // Rows on an identity that a guest invite CREATED, as opposed to rows attached to an
  // identity that already existed. Anything not explicitly attached counts as owned.
  const ownedGuests = guests.filter((row) => row.guestOrigin !== GUEST_ORIGIN_ATTACHED);

  // `guests.length > 0` is load-bearing: an org admin holds ZERO membership rows thanks to
  // requireVaultMember's full-org bypass, and must never be badged or swept.
  const isGuest = permanent.length === 0 && guests.length > 0;
  // Lexicographic max is the true latest only because guestAccessExpiresAt always emits
  // toISOString(). Do not relax that.
  const latestExpiry = guests
    .map((row) => row.expiresAt)
    .filter((value): value is string => !!value)
    .sort()
    .pop();

  return {
    isGuest,
    expiresAt: isGuest ? latestExpiry : undefined,
    // `ownedGuests.length > 0` is the DR-7 guard. Without it, an identity that existed BEFORE
    // the guest grant — an org admin, or any editor/viewer holding zero permanent rows —
    // becomes fullyExpired when its temporary grant lapses, and the sweeper disables the
    // account, releases the seat and writes a revocation marker. With it, that identity falls
    // into the sweeper's restraint branch instead: lapsed rows deleted, nothing else.
    // Note the asymmetry — `permanent.length === 0` above protects a target that HOLDS a
    // permanent row; this clause protects one that holds none. Neither substitutes for the
    // other, and a DR-7 attach target is not guaranteed to be covered by the first.
    fullyExpired: isGuest && activeGuests.length === 0 && ownedGuests.length > 0,
    expiredRows,
  };
}
