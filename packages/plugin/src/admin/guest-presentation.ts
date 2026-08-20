import type { UserListEntry } from "../api/client";

/**
 * Display-only derivation of the guest badge and the guest expiry line.
 *
 * This module renders a fact the server already computed. It makes no access
 * decision: the rule lives in `summarizeGuestAccess` and the enforcement test
 * in `isExpiringAccessActive` (`infrastructure/lambda/shared/guest-access.ts`,
 * lines 67-75). Nothing here may be read as granting or withholding access.
 *
 * Deliberately free of Obsidian, of the DOM and of locale lookups, so the same
 * decision is callable from a `node`-environment test. The admin panel keeps a
 * mirror at `admin-panel/src/lib/guest-presentation.ts`;
 * `tests/guest-presentation-parity.test.ts` is what stops the two from drifting.
 */

/** The only two fields the decision needs. Both are server-written. */
export type GuestPresentationInput = Pick<UserListEntry, "accessKind" | "expiresAt">;

/** The renderer's instructions: which keys to translate, which raw date to format. */
export interface GuestPresentation {
  /** Always true when a presentation is returned; a non-guest yields `null`. */
  showBadge: true;
  /** True when the expiry is malformed or already elapsed — fails closed. */
  expired: boolean;
  /** Locale key for the expiry meta line. The caller translates it. */
  labelKey: "guest.expiresAt" | "guest.expiredAt";
  /** Locale key for the badge text. The caller translates it. */
  badgeKey: "guest.badge";
  /** Raw ISO expiry, unformatted. `undefined` means: render no meta line. */
  date: string | undefined;
}

/**
 * Returns the badge decision for a guest, or `null` for everyone else.
 *
 * Mirrors the server's fail-closed expiry test: a missing expiry means no
 * boundary, while a malformed value — or one landing exactly on `nowMs` —
 * counts as expired.
 */
export function deriveGuestPresentation(
  entry: GuestPresentationInput,
  nowMs = Date.now(),
): GuestPresentation | null {
  if (entry.accessKind !== "guest") return null;

  const expiresAt = entry.expiresAt;
  if (!expiresAt) {
    return {
      showBadge: true,
      expired: false,
      labelKey: "guest.expiresAt",
      badgeKey: "guest.badge",
      date: undefined,
    };
  }

  const expiresAtMs = Date.parse(expiresAt);
  const expired = !Number.isFinite(expiresAtMs) || expiresAtMs <= nowMs;

  return {
    showBadge: true,
    expired,
    labelKey: expired ? "guest.expiredAt" : "guest.expiresAt",
    badgeKey: "guest.badge",
    date: expiresAt,
  };
}
