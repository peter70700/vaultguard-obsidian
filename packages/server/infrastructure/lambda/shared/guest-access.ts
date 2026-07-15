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
