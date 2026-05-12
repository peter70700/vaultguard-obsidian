import { describe, expect, it } from "vitest";

import {
  findExactAccessUserMatch,
  getAccessUserDisplayName,
  resolveAccessUserId,
  sortAccessUsers,
} from "../src/ui/access-user-utils";
import type { UserListEntry } from "../src/api/client";

const USERS: UserListEntry[] = [
  {
    id: "viewer-1",
    email: "viewer@example.com",
    displayName: "Viewer Person",
    name: "Viewer Person",
    role: "viewer",
    status: "active",
    lastActive: "",
    createdAt: "",
    mfaEnabled: false,
    deviceCount: 0,
    type: "user",
  },
  {
    id: "admin-1",
    email: "admin@example.com",
    displayName: "Admin Person",
    name: "Admin Person",
    role: "admin",
    status: "active",
    lastActive: "",
    createdAt: "",
    mfaEnabled: true,
    deviceCount: 1,
    type: "user",
  },
  {
    id: "pending-1",
    email: "invitee@example.com",
    displayName: "Pending Invitee",
    name: "Pending Invitee",
    role: "editor",
    status: "pending",
    lastActive: "",
    createdAt: "",
    mfaEnabled: false,
    deviceCount: 0,
    type: "user",
  },
];

describe("access-user-utils", () => {
  it("prefers readable display labels", () => {
    expect(getAccessUserDisplayName(USERS[0])).toBe("Viewer Person");
    expect(
      getAccessUserDisplayName({
        id: "user-2",
        email: "fallback@example.com",
        displayName: "",
        name: "",
      })
    ).toBe("fallback@example.com");
  });

  it("resolves exact email and id matches back to the canonical user id", () => {
    expect(resolveAccessUserId(USERS, "admin@example.com")).toBe("admin-1");
    expect(resolveAccessUserId(USERS, "viewer-1")).toBe("viewer-1");
    expect(findExactAccessUserMatch(USERS, "Pending Invitee")?.id).toBe("pending-1");
  });

  it("sorts active admins ahead of other statuses and roles", () => {
    expect(sortAccessUsers(USERS).map((user) => user.id)).toEqual([
      "admin-1",
      "viewer-1",
      "pending-1",
    ]);
  });
});
