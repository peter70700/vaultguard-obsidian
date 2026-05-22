import { UserListEntry } from "../api/client";

const USER_STATUS_RANK: Record<UserListEntry["status"], number> = {
  active: 0,
  pending: 1,
  suspended: 2,
  revoked: 3,
};

const USER_ROLE_RANK: Record<UserListEntry["role"], number> = {
  admin: 0,
  editor: 1,
  viewer: 2,
  custom: 3,
};

type AccessUserIdentity = Pick<UserListEntry, "id" | "email" | "displayName" | "name">;

/**
 * Returns the best human-readable label for a user.
 * Prefers displayName > name > email > id.
 */
export function getAccessUserDisplayName(user: AccessUserIdentity): string {
  if (user.displayName?.trim()) return user.displayName.trim();
  if (user.name?.trim()) return user.name.trim();
  if (user.email?.trim()) return user.email.trim();
  return user.id;
}

/**
 * Returns true if the user has a real name set (not just email/id).
 */
export function hasRealName(user: AccessUserIdentity): boolean {
  return Boolean(user.displayName?.trim() || user.name?.trim());
}

/**
 * Returns initials derived from a user's actual name fields.
 * Falls back to the first letter of email username if no name is set.
 * Always returns 1-2 uppercase letters.
 *
 * Examples:
 *   { displayName: "Jane Smith" }       → "JS"
 *   { name: "John Doe" }                → "JD"
 *   { email: "alice@example.com" }      → "A"
 *   { id: "abc-123" }                   → "A"
 */
export function getAccessUserNameInitials(user: AccessUserIdentity): string {
  // Prefer displayName, then name
  const realName = user.displayName?.trim() || user.name?.trim();
  if (realName) {
    const parts = realName.split(/\s+/).filter(Boolean);
    return parts
      .slice(0, 2)
      .map((p) => p[0]?.toUpperCase() ?? "")
      .join("");
  }

  // Fallback: use the part before @ in email
  if (user.email?.trim()) {
    const localPart = user.email.split("@")[0];
    const parts = localPart.split(/[._-]+/).filter(Boolean);
    return parts
      .slice(0, 2)
      .map((p) => p[0]?.toUpperCase() ?? "")
      .join("");
  }

  // Last resort: first character of ID
  return (user.id[0] ?? "?").toUpperCase();
}

/**
 * Generic initials from any string value (used when no user object is available).
 */
export function getAccessUserInitials(value: string): string {
  const parts = value.split(/[\s@._-]+/).filter(Boolean);
  return parts
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() ?? "")
    .join("");
}

export function sortAccessUsers(users: UserListEntry[]): UserListEntry[] {
  return [...users].sort((left, right) => {
    const statusDiff = USER_STATUS_RANK[left.status] - USER_STATUS_RANK[right.status];
    if (statusDiff !== 0) return statusDiff;

    const roleDiff = USER_ROLE_RANK[left.role] - USER_ROLE_RANK[right.role];
    if (roleDiff !== 0) return roleDiff;

    const nameDiff = getAccessUserDisplayName(left).localeCompare(getAccessUserDisplayName(right));
    if (nameDiff !== 0) return nameDiff;

    const emailDiff = left.email.localeCompare(right.email);
    if (emailDiff !== 0) return emailDiff;

    return left.id.localeCompare(right.id);
  });
}

export function buildAccessUserMap(users: UserListEntry[]): Map<string, UserListEntry> {
  const map = new Map<string, UserListEntry>();
  for (const user of users) {
    map.set(user.id, user);
    const email = user.email.trim();
    if (email) {
      map.set(email, user);
      map.set(email.toLowerCase(), user);
    }
  }
  return map;
}

export function matchesAccessUserQuery(user: UserListEntry, query: string): boolean {
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) return true;

  const haystack = [
    user.id,
    user.email,
    user.displayName,
    user.name,
    getAccessUserDisplayName(user),
    user.role,
    user.status,
  ];

  return haystack.some((value) => value.toLowerCase().includes(normalizedQuery));
}

export function findExactAccessUserMatch(users: UserListEntry[], value: string): UserListEntry | null {
  const normalizedValue = value.trim().toLowerCase();
  if (!normalizedValue) return null;

  const exactIdMatch = users.find((user) => user.id.toLowerCase() === normalizedValue);
  if (exactIdMatch) return exactIdMatch;

  const exactEmailMatch = users.find((user) => user.email.trim().toLowerCase() === normalizedValue);
  if (exactEmailMatch) return exactEmailMatch;

  const namedMatches = users.filter((user) => {
    return (
      getAccessUserDisplayName(user).toLowerCase() === normalizedValue ||
      user.name.toLowerCase() === normalizedValue
    );
  });

  return namedMatches.length === 1 ? namedMatches[0] : null;
}

export function resolveAccessUserId(users: UserListEntry[], value: string): string {
  return findExactAccessUserMatch(users, value)?.id ?? value.trim();
}

export function formatAccessUserRole(role: UserListEntry["role"]): string {
  switch (role) {
    case "admin":
      return "Admin";
    case "editor":
      return "Editor";
    case "viewer":
      return "Viewer";
    default:
      return "Custom";
  }
}

export function formatAccessUserStatus(status: UserListEntry["status"]): string {
  switch (status) {
    case "active":
      return "Active";
    case "pending":
      return "Pending";
    case "suspended":
      return "Suspended";
    default:
      return "Revoked";
  }
}

export function getAccessUserMeta(user: UserListEntry): string {
  const parts: string[] = [];
  if (user.email) {
    parts.push(user.email);
  } else if (user.id) {
    parts.push(user.id);
  }

  if (user.status !== "active") {
    parts.push(formatAccessUserStatus(user.status));
  }

  parts.push(formatAccessUserRole(user.role));
  return parts.join(" · ");
}

export function getAccessUserPickerValue(user: UserListEntry): string {
  const label = getAccessUserDisplayName(user);
  return label.trim().length > 0 ? label : user.id;
}
