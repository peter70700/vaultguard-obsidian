import {
  App,
  Modal,
  Setting,
  ButtonComponent,
  Notice,
  setIcon,
} from "obsidian";
import { VaultGuardApiClient } from "../api/client";
import type { UserListEntry, VaultMemberRecord } from "../api/client";
import { getAccessUserNameInitials } from "../ui/access-user-utils";
import { createI18n } from "../i18n";
import { deriveGuestPresentation } from "./guest-presentation";

export type UserStatus = "active" | "suspended" | "revoked" | "pending";
export type UserRole = "admin" | "editor" | "viewer" | "custom";

export interface VaultGuardUser {
  id: string;
  email: string;
  displayName: string;
  role: UserRole;
  status: UserStatus;
  lastActive: string; // ISO date
  createdAt: string;
  mfaEnabled: boolean;
  deviceCount: number;
  accessKind?: "member" | "guest";
  expiresAt?: string;
}

export interface UserActivity {
  timestamp: string;
  action: string;
  resourcePath: string;
  deviceInfo: string;
}

/**
 * Reconciles the org-wide guest state on a `GET /users` entry with the member
 * row for the one vault the plugin currently has open.
 *
 * THE SERVER WINS. `entry.accessKind` is computed across every vault in the org
 * (DR-1); a membership is a single vault's fact. Letting the membership
 * overwrite the server value would erase the badge of a guest scoped to a vault
 * this admin does not currently have open — silently presenting a temporary
 * guest as a permanent viewer.
 *
 * The current-vault fallback is kept on purpose rather than deleted: against a
 * server not yet redeployed with the `GET /users` change, `entry.accessKind` is
 * absent and the membership is the only guest state that exists.
 *
 * A pure field-presence decision with no clock. Every expiry comparison in this
 * file goes through `deriveGuestPresentation`, which reads guest state and
 * never re-derives it.
 */
export function mergeGuestState(entry: UserListEntry, membership: VaultMemberRecord | undefined): UserListEntry {
  if (entry.accessKind !== undefined) return entry;
  if (membership?.accessKind === undefined) return entry;
  return {
    ...entry,
    accessKind: membership.accessKind,
    expiresAt: membership.expiresAt,
  };
}

/**
 * The narrow client surface the grant-guest-access sequence needs, injected so
 * the sequence is callable from a `node` test without Obsidian or a network.
 *
 * `revokeUser` is here so the sequence can be OBSERVED not calling it.
 */
export interface GuestAccessGrantClient {
  reactivateUser(userId: string): Promise<void>;
  inviteUser(invite: {
    email: string;
    role: string;
    sendWelcomeEmail: boolean;
    accessKind?: "member" | "guest";
    vaultIds?: string[];
    expiresInDays?: number;
  }): Promise<unknown>;
  revokeUser(userId: string): Promise<unknown>;
}

export type GrantGuestAccessOutcome =
  | { status: "granted" }
  | { status: "reactivate-failed"; message: string }
  | { status: "invite-failed-after-reactivate"; message: string };

function errorMessageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Re-enables a disabled identity and grants it NEW temporary vault access.
 *
 * This is the recovery for a guest the expiry sweeper has already torn down.
 * Such a guest has NO membership row left anywhere — the teardown deletes every
 * one — so they appear in no vault-member list, there is no boundary to move,
 * and the vault-scoped extend answers 404 for precisely that state. What
 * survived a sweep is the IDENTITY, not the grant, so the grant has to be made
 * afresh. This path deliberately makes no claim about what the user held
 * before: the client does not know, and for a revoked permanent member there
 * was never any temporary access at all.
 *
 * THE ORDER IS FORCED BY THE SERVER, not a preference. The invite's
 * attach-to-existing-identity branch answers 409 for an identity that is still
 * disabled or still carries a revocation marker, precisely so an invite can
 * never quietly undo an admin's revoke. Reactivate therefore runs first.
 *
 * The invite carries the user's EXISTING organization role: the attach branch
 * issues no group change, so the role field must not be used to move anyone
 * between roles. `sendWelcomeEmail: false` matches the attach branch already
 * suppressing that template — asking for it would only add a contradictory
 * signal, and a password-reset-shaped email to an existing user is confusing.
 */
export async function grantGuestAccessToRevokedUser(
  client: GuestAccessGrantClient,
  input: {
    userId: string;
    email: string;
    role: string;
    vaultIds: string[];
    expiresInDays: number;
  },
): Promise<GrantGuestAccessOutcome> {
  try {
    await client.reactivateUser(input.userId);
  } catch (error) {
    // Nothing changed, so nothing needs undoing — and the invite is NOT
    // attempted, because against a still-disabled identity it would 409.
    return { status: "reactivate-failed", message: errorMessageOf(error) };
  }

  try {
    await client.inviteUser({
      email: input.email,
      role: input.role,
      sendWelcomeEmail: false,
      accessKind: "guest",
      vaultIds: input.vaultIds,
      expiresInDays: input.expiresInDays,
    });
  } catch (error) {
    // The reactivate above has ALREADY re-taken the seat, so the organization
    // is now paying for an enabled account that got no vault access. State all
    // three facts and name the lever.
    //
    // `revokeUser` is deliberately NOT called as a silent rollback: revoking is
    // an org-wide, audited, account-disabling action, and firing it unattended
    // out of a failed sequence is worse than telling the operator.
    return {
      status: "invite-failed-after-reactivate",
      message:
        "The account was re-enabled and a seat was consumed, but guest access was NOT granted: " +
        `${errorMessageOf(error)} Use Revoke access if the account should not stay enabled.`,
    };
  }

  return { status: "granted" };
}

export class UserManager {
  private app: App;
  private apiClient: VaultGuardApiClient;
  private currentVaultId?: string;
  private readonly i18n = createI18n();

  constructor(app: App, apiClient: VaultGuardApiClient, currentVaultId?: string) {
    this.app = app;
    this.apiClient = apiClient;
    this.currentVaultId = currentVaultId;
  }

  /**
   * Renders the user list into the given container.
   */
  async renderUserList(container: HTMLElement): Promise<void> {
    this.i18n.applyToRoot(container);
    container.empty();
    container.setAttribute("aria-busy", "true");
    const loadingEl = container.createDiv({ cls: "vaultguard-loading" });
    loadingEl.setAttribute("role", "status");
    loadingEl.setAttribute("aria-live", "polite");
    loadingEl.createSpan({ text: this.i18n.t("common.loading") });

    try {
      const [users, memberships] = await Promise.all([
        this.apiClient.listUsers(),
        this.currentVaultId
          ? this.apiClient.listVaultMembers(this.currentVaultId).catch(() => [])
          : Promise.resolve([] as VaultMemberRecord[]),
      ]);
      if (container.isConnected === false) return;
      const membershipByUser = new Map(memberships.map((membership) => [
        membership.userId,
        membership,
      ]));
      container.empty();
      container.setAttribute("aria-busy", "false");

      if (!users || users.length === 0) {
        container.createDiv({
          cls: "vaultguard-empty-state",
          text: "No users found. Click 'Invite User' to add team members.",
        });
        return;
      }

      // Reconcile guest state once, before anything reads it, so the summary
      // bar and the rows below can never disagree about who is a guest.
      const mergedUsers = users.map((user) => mergeGuestState(user, membershipByUser.get(user.id)));
      const nowMs = Date.now();

      // Summary bar
      const summary = container.createDiv({ cls: "vaultguard-user-summary" });
      const activeCount = mergedUsers.filter((u: UserListEntry) => u.status === "active").length;
      const suspendedCount = mergedUsers.filter((u: UserListEntry) => u.status === "suspended").length;
      const pendingCount = mergedUsers.filter((u: UserListEntry) => u.status === "pending").length;
      const guestCount = mergedUsers.filter((u: UserListEntry) => deriveGuestPresentation(u, nowMs) !== null).length;
      summary.createSpan({ text: `${mergedUsers.length} total`, cls: "vaultguard-summary-stat" });
      summary.createSpan({ text: `${activeCount} active`, cls: "vaultguard-summary-stat vaultguard-stat-active" });
      if (suspendedCount > 0) {
        summary.createSpan({ text: `${suspendedCount} suspended`, cls: "vaultguard-summary-stat vaultguard-stat-suspended" });
      }
      if (pendingCount > 0) {
        summary.createSpan({ text: `${pendingCount} pending`, cls: "vaultguard-summary-stat vaultguard-stat-pending" });
      }
      if (guestCount > 0) {
        summary.createSpan({ text: `${guestCount} guest${guestCount !== 1 ? "s" : ""}`, cls: "vaultguard-summary-stat vaultguard-stat-guest" });
      }

      // User items
      for (const user of mergedUsers) {
        this.renderUserItem(container, user);
      }
    } catch (error) {
      if (container.isConnected === false) return;
      container.empty();
      container.setAttribute("aria-busy", "false");
      const errorEl = container.createDiv({
        cls: "vaultguard-error",
        text: `Failed to load users: ${(error as Error).message}`,
      });
      errorEl.setAttribute("role", "alert");
      errorEl.setAttribute("aria-live", "assertive");
    }
  }

  /**
   * Renders a single user row with actions.
   */
  private renderUserItem(container: HTMLElement, user: VaultGuardUser): void {
    // One clock reading per row: the badge and the expiry line must agree.
    const guest = deriveGuestPresentation(user, Date.now());

    const itemEl = container.createDiv({ cls: "vaultguard-user-item" });
    itemEl.setAttribute("data-username", user.displayName);
    itemEl.setAttribute("data-email", user.email);

    // User info section
    const infoEl = itemEl.createDiv({ cls: "vaultguard-user-info" });

    // Fallback avatar with initials
    const avatarEl = infoEl.createDiv({ cls: "vaultguard-user-avatar" });
    const initials = getAccessUserNameInitials({
      id: user.id,
      email: user.email,
      displayName: user.displayName,
      name: "",
    });
    avatarEl.createSpan({ text: initials });

    // Name and email
    const detailEl = infoEl.createDiv({ cls: "vaultguard-user-details" });
    detailEl.createDiv({ text: user.displayName, cls: "vaultguard-user-name" });
    detailEl.createDiv({ text: user.email, cls: "vaultguard-user-email" });

    // Status and role badges
    const badgesEl = itemEl.createDiv({ cls: "vaultguard-user-badges" });

    const statusBadge = badgesEl.createSpan({ cls: "vaultguard-status-badge" });
    statusBadge.setText(user.status);
    statusBadge.addClass(`vaultguard-status-${user.status}`);

    const roleBadge = badgesEl.createSpan({ cls: "vaultguard-role-badge" });
    roleBadge.setText(user.role);
    roleBadge.addClass(`vaultguard-role-${user.role}`);

    if (guest) {
      const guestBadge = badgesEl.createSpan({
        cls: "vaultguard-role-badge vaultguard-role-guest",
        text: this.i18n.t(guest.badgeKey),
      });
      if (guest.expired) {
        guestBadge.addClass("vaultguard-status-revoked");
      }
    }

    if (user.mfaEnabled) {
      const mfaBadge = badgesEl.createSpan({ cls: "vaultguard-mfa-badge" });
      const mfaIcon = mfaBadge.createSpan();
      setIcon(mfaIcon, "shield");
      mfaBadge.createSpan({ text: "MFA" });
    }

    // Last active
    const metaEl = itemEl.createDiv({ cls: "vaultguard-user-meta" });
    metaEl.createDiv({
      text: `Last active: ${this.formatRelativeTime(user.lastActive)}`,
      cls: "vaultguard-user-last-active",
    });
    metaEl.createDiv({
      text: `${user.deviceCount} device${user.deviceCount !== 1 ? "s" : ""}`,
      cls: "vaultguard-user-devices",
    });
    if (guest?.date) {
      metaEl.createDiv({
        text: this.i18n.t(guest.labelKey, {
          date: new Date(guest.date).toLocaleString(),
        }),
        cls: "vaultguard-user-last-active",
      });
    }

    // Action buttons
    const actionsEl = itemEl.createDiv({ cls: "vaultguard-user-actions" });

    // View permissions button
    const viewPermsBtn = actionsEl.createEl("button", { cls: "vaultguard-icon-btn", attr: { title: "View permissions", "aria-label": "View permissions", type: "button" } });
    setIcon(viewPermsBtn, "key");
    viewPermsBtn.addEventListener("click", () => { void this.showUserPermissions(user); });

    // View activity button
    const viewActivityBtn = actionsEl.createEl("button", { cls: "vaultguard-icon-btn", attr: { title: "View activity", "aria-label": "View activity", type: "button" } });
    setIcon(viewActivityBtn, "activity");
    viewActivityBtn.addEventListener("click", () => { void this.showUserActivity(user); });

    // Edit role button
    if (user.accessKind !== "guest") {
      const editRoleBtn = actionsEl.createEl("button", { cls: "vaultguard-icon-btn", attr: { title: "Change role", "aria-label": "Change role", type: "button" } });
      setIcon(editRoleBtn, "user-cog");
      editRoleBtn.addEventListener("click", () => { void this.showRoleEditor(user, container); });
    }

    // Lifecycle actions.
    if (user.status === "active") {
      const revokeBtn = actionsEl.createEl("button", {
        cls: "vaultguard-icon-btn vaultguard-danger",
        attr: { title: "Revoke access", "aria-label": "Revoke access", type: "button" },
      });
      setIcon(revokeBtn, "x-circle");
      revokeBtn.addEventListener("click", () => { void this.confirmRevokeAccess(user, container); });
    } else if (user.status === "pending") {
      const resendBtn = actionsEl.createEl("button", {
        cls: "vaultguard-icon-btn",
        attr: { title: "Resend invitation", "aria-label": "Resend invitation", type: "button" },
      });
      setIcon(resendBtn, "send");
      resendBtn.addEventListener("click", () => { void this.resendInvitation(user); });
    } else if (user.status === "suspended" || user.status === "revoked") {
      const reactivateBtn = actionsEl.createEl("button", {
        cls: "vaultguard-icon-btn vaultguard-success",
        attr: { title: "Reactivate user", "aria-label": "Reactivate user", type: "button" },
      });
      setIcon(reactivateBtn, "check-circle");
      reactivateBtn.addEventListener("click", () => { void this.reactivateUser(user, container); });

      // Rendered ALONGSIDE Reactivate user, on the same gate, on purpose: they
      // are different outcomes. Reactivate user re-enables the account with no
      // vault access; this re-enables it AND attaches temporary vault access.
      //
      // The control is NAMED FOR WHAT ITS GATE ACTUALLY MATCHES. That gate
      // catches every revoked identity, not only a guest the sweeper swept:
      // the teardown deletes every guest row, and `GET /users` never exposes
      // why an account was revoked, so a swept guest and an admin-revoked
      // editor are indistinguishable here. Rather than narrow the gate — which
      // would need a per-user marker read on the heaviest route in the API —
      // the label names the real capability, which is a correct and useful
      // action for any revoked identity.
      if (!guest) {
        const grantGuestBtn = actionsEl.createEl("button", {
          cls: "vaultguard-icon-btn",
          attr: { title: "Grant guest access", "aria-label": "Grant guest access", type: "button" },
        });
        setIcon(grantGuestBtn, "user-plus");
        grantGuestBtn.addEventListener("click", () => {
          void this.showGrantGuestAccessDialog(user, container);
        });
      }
    }
  }

  /**
   * Opens the guest-invite form pre-targeted at an existing, disabled identity.
   *
   * Reuses `InviteUserModal` rather than building a second duration and vault
   * picker, so this file has exactly one of each.
   */
  private async showGrantGuestAccessDialog(
    user: VaultGuardUser,
    container: HTMLElement,
  ): Promise<void> {
    const modal = new InviteUserModal(
      this.app,
      this.apiClient,
      this.currentVaultId,
      async () => {
        await this.renderUserList(container);
      },
      { id: user.id, email: user.email, displayName: user.displayName, role: user.role },
    );
    modal.open();
  }

  /**
   * Shows the invite user dialog.
   */
  async showInviteDialog(parentContainer: HTMLElement): Promise<void> {
    const modal = new InviteUserModal(this.app, this.apiClient, this.currentVaultId, async () => {
      await this.renderUserList(parentContainer.querySelector(".vaultguard-user-list")!);
    });
    modal.open();
  }

  /**
   * Shows a modal with the user's current permissions.
   */
  private async showUserPermissions(user: VaultGuardUser): Promise<void> {
    const modal = new UserPermissionsModal(this.app, this.apiClient, user);
    modal.open();
  }

  /**
   * Shows recent activity for a user.
   */
  private async showUserActivity(user: VaultGuardUser): Promise<void> {
    const modal = new UserActivityModal(this.app, this.apiClient, user);
    modal.open();
  }

  /**
   * Opens the role editor for a user.
   */
  private async showRoleEditor(user: VaultGuardUser, container: HTMLElement): Promise<void> {
    const modal = new RoleEditorModal(this.app, this.apiClient, user, async () => {
      await this.renderUserList(container);
    });
    modal.open();
  }

  /**
   * Confirms and executes access revocation.
   */
  private async confirmRevokeAccess(user: VaultGuardUser, container: HTMLElement): Promise<void> {
    const modal = new RevokeAccessModal(this.app, this.apiClient, user, async () => {
      await this.renderUserList(container);
    });
    modal.open();
  }

  /**
   * Reactivates a suspended user.
   */
  private async reactivateUser(user: VaultGuardUser, container: HTMLElement): Promise<void> {
    try {
      await this.apiClient.reactivateUser(user.id);
      new Notice(`${user.displayName} has been reactivated.`);
      await this.renderUserList(container);
    } catch (error) {
      new Notice(`Failed to reactivate: ${(error as Error).message}`);
    }
  }

  private async resendInvitation(user: VaultGuardUser): Promise<void> {
    try {
      await this.apiClient.resendInvitation(user.id);
      new Notice(`Invitation resent to ${user.email}.`);
    } catch (error) {
      new Notice(`Failed to resend invitation: ${(error as Error).message}`);
    }
  }

  /**
   * Formats a date string into a human-readable relative time.
   */
  private formatRelativeTime(isoDate: string): string {
    const date = new Date(isoDate);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffMins < 1) return "just now";
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    return date.toLocaleDateString();
  }
}

// ─── Invite User Modal ──────────────────────────────────────────────────────

/**
 * An existing, disabled identity this form is granting fresh guest access to,
 * rather than inviting someone new.
 */
interface GuestAccessGrantTarget {
  id: string;
  email: string;
  displayName: string;
  role: UserRole;
}

class InviteUserModal extends Modal {
  private apiClient: VaultGuardApiClient;
  private onInvited: () => Promise<void>;
  private currentVaultId?: string;
  private email: string = "";
  private role: UserRole = "viewer";
  private accessKind: "member" | "guest" = "member";
  private selectedVaultIds = new Set<string>();
  private expiresInDays = 30;
  private sendWelcomeEmail: boolean = true;
  private inviteButton: ButtonComponent | null = null;
  private readonly i18n = createI18n();
  private active = false;
  private readonly grantTarget?: GuestAccessGrantTarget;

  constructor(
    app: App,
    apiClient: VaultGuardApiClient,
    currentVaultId: string | undefined,
    onInvited: () => Promise<void>,
    grantTarget?: GuestAccessGrantTarget,
  ) {
    super(app);
    this.apiClient = apiClient;
    this.currentVaultId = currentVaultId;
    this.onInvited = onInvited;
    this.grantTarget = grantTarget;
    if (grantTarget) {
      // Everything the form would otherwise ask for is already decided: the
      // identity, its existing organization role (which this path must not
      // change), that the access is temporary, and that no invitation email is
      // wanted. What remains to collect is the vaults and the duration.
      this.email = grantTarget.email;
      this.role = grantTarget.role;
      this.accessKind = "guest";
      this.sendWelcomeEmail = false;
    }
  }

  async onOpen(): Promise<void> {
    this.active = true;
    const { contentEl } = this;
    contentEl.empty();
    this.modalEl.addClass("vaultguard-dialog-modal");
    contentEl.addClass("vaultguard-dialog-content");
    this.i18n.applyToRoot(contentEl);
    const title = contentEl.createEl("h3", {
      text: this.grantTarget ? "Grant guest access" : this.i18n.t("guest.title"),
      attr: { id: "vaultguard-invite-user-title" },
    });
    this.modalEl.setAttribute("aria-labelledby", title.id);

    if (this.grantTarget) {
      // Stated plainly and up front, because every one of these is a real
      // consequence the operator is about to cause. Deliberately worded as
      // granting NEW access: nothing about what this user held before is known
      // here, and for a revoked permanent member there was no guest access.
      new Setting(contentEl)
        .setName(`${this.grantTarget.displayName} (${this.grantTarget.email})`)
        .setDesc(
          "This will re-enable their organization account as a viewer, consuming a seat, " +
          "and grant NEW temporary guest access to the vaults you select below for the " +
          "number of days you choose. They will have to sign in again. " +
          "To re-enable the account without granting any vault access, use Reactivate user instead."
        );
    } else {
      new Setting(contentEl)
        .setName(this.i18n.t("guest.email.name"))
        .setDesc(this.i18n.t("guest.email.description"))
        .addText((text) =>
          text
            .setPlaceholder(this.i18n.t("guest.email.placeholder"))
            .onChange((value) => {
              this.email = value;
            })
        );
    }

    const accessDetails = contentEl.createDiv({ cls: "vaultguard-invite-access-details" });
    let renderVersion = 0;
    const renderAccessDetails = async (): Promise<void> => {
      const version = ++renderVersion;
      accessDetails.empty();
      accessDetails.setAttribute("aria-busy", "false");
      if (this.accessKind === "member") {
        new Setting(accessDetails)
          .setName(this.i18n.t("guest.role.name"))
          .setDesc(this.i18n.t("guest.role.description"))
          .addDropdown((dropdown) =>
            dropdown
              .addOption("viewer", this.i18n.t("guest.viewer"))
              .addOption("editor", this.i18n.t("guest.editor"))
              .addOption("admin", this.i18n.t("guest.admin"))
              .setValue(this.role)
              .onChange((value) => {
                this.role = value as UserRole;
              })
          );
        return;
      }

      new Setting(accessDetails)
        .setName(this.i18n.t("guest.permissions.name"))
        .setDesc(this.i18n.t("guest.permissions.description"));

      new Setting(accessDetails)
        .setName(this.i18n.t("guest.duration.name"))
        .setDesc(this.i18n.t("guest.duration.description"))
        .addText((text) => {
          text.setValue(String(this.expiresInDays));
          text.inputEl.type = "number";
          text.inputEl.min = "1";
          text.inputEl.max = "90";
          text.inputEl.step = "1";
          text.inputEl.setAttribute("aria-label", this.i18n.t("guest.duration.name"));
          text.onChange((value) => {
            const parsed = Number(value);
            if (Number.isInteger(parsed)) this.expiresInDays = parsed;
          });
        });

      accessDetails.setAttribute("aria-busy", "true");
      let vaults;
      try {
        vaults = (await this.apiClient.listVaults()).filter((vault) => !vault.archived);
      } catch (error) {
        if (!this.active || version !== renderVersion || this.accessKind !== "guest") return;
        const errorEl = accessDetails.createDiv({
          cls: "vaultguard-error",
          text: this.i18n.t("guest.vaultLoadFailed", {
            message: error instanceof Error ? error.message : String(error),
          }),
        });
        errorEl.setAttribute("role", "alert");
        errorEl.setAttribute("aria-live", "assertive");
        accessDetails.setAttribute("aria-busy", "false");
        return;
      }
      if (!this.active || version !== renderVersion || this.accessKind !== "guest") return;
      accessDetails.setAttribute("aria-busy", "false");
      const validVaultIds = new Set(vaults.map((vault) => vault.vaultId));
      for (const selectedVaultId of this.selectedVaultIds) {
        if (!validVaultIds.has(selectedVaultId)) this.selectedVaultIds.delete(selectedVaultId);
      }
      if (
        this.selectedVaultIds.size === 0 &&
        this.currentVaultId &&
        vaults.some((vault) => vault.vaultId === this.currentVaultId)
      ) {
        this.selectedVaultIds.add(this.currentVaultId);
      }
      if (vaults.length === 0) {
        accessDetails.createDiv({
          cls: "vaultguard-empty-state",
          text: this.i18n.t("guest.noVaults"),
        });
        return;
      }
      new Setting(accessDetails).setName(this.i18n.t("guest.vaults")).setHeading();
      for (const vault of vaults) {
        new Setting(accessDetails)
          .setName(vault.name)
          .setDesc(
            this.i18n.t(
              vault.vaultId === this.currentVaultId ? "guest.currentVault" : "guest.viewerAccess",
            ),
          )
          .addToggle((toggle) => {
            toggle
              .setValue(this.selectedVaultIds.has(vault.vaultId))
              .onChange((selected) => {
                if (selected) this.selectedVaultIds.add(vault.vaultId);
                else this.selectedVaultIds.delete(vault.vaultId);
              });
          });
      }
    };

    // No access-type choice on the grant path: the whole point of the control
    // is temporary access, and offering "permanent member" here would let one
    // gesture hand a revoked identity a standing seat by accident.
    if (!this.grantTarget) {
      new Setting(contentEl)
        .setName(this.i18n.t("guest.accessType.name"))
        .setDesc(this.i18n.t("guest.accessType.description"))
        .addDropdown((dropdown) =>
          dropdown
            .addOption("member", this.i18n.t("guest.member"))
            .addOption("guest", this.i18n.t("guest.guest"))
            .setValue(this.accessKind)
            .onChange((value) => {
              this.accessKind = value === "guest" ? "guest" : "member";
              void renderAccessDetails();
            })
        );
    }
    contentEl.appendChild(accessDetails);
    await renderAccessDetails();
    if (!this.active) return;

    // No welcome-email toggle on the grant path: the server already suppresses
    // that template when attaching to an existing identity, so offering the
    // choice would promise something that cannot happen.
    if (!this.grantTarget) {
      new Setting(contentEl)
        .setName(this.i18n.t("guest.welcome.name"))
        .setDesc(this.i18n.t("guest.welcome.description"))
        .addToggle((toggle) =>
          toggle.setValue(this.sendWelcomeEmail).onChange((value) => {
            this.sendWelcomeEmail = value;
          })
        );
    }

    const actionRow = contentEl.createDiv({ cls: "vaultguard-modal-actions" });
    new ButtonComponent(actionRow)
      .setButtonText(this.i18n.t("common.cancel"))
      .onClick(() => this.close());
    this.inviteButton = new ButtonComponent(actionRow)
      .setButtonText(this.grantTarget ? "Grant guest access" : this.i18n.t("guest.send"))
      .setCta()
      .onClick(() => this.handleInvite());
  }

  onClose(): void {
    this.active = false;
    this.modalEl.removeClass("vaultguard-dialog-modal");
    this.contentEl.removeClass("vaultguard-dialog-content");
    this.inviteButton = null;
    this.contentEl.empty();
  }

  private async handleInvite(): Promise<void> {
    if (!this.email || !this.email.includes("@")) {
      new Notice(this.i18n.t("guest.invalidEmail"));
      return;
    }
    if (this.accessKind === "guest") {
      if (
        !Number.isInteger(this.expiresInDays) ||
        this.expiresInDays < 1 ||
        this.expiresInDays > 90
      ) {
        new Notice(this.i18n.t("guest.invalidDuration"));
        return;
      }
      if (this.selectedVaultIds.size === 0) {
        new Notice(this.i18n.t("guest.selectVault"));
        return;
      }
    }

    if (this.grantTarget) {
      await this.handleGrantGuestAccess(this.grantTarget);
      return;
    }

    this.inviteButton?.setDisabled(true).setButtonText(this.i18n.t("common.loading"));
    this.contentEl.setAttribute("aria-busy", "true");
    try {
      const result = await this.apiClient.inviteUser({
        email: this.email,
        role: this.accessKind === "guest" ? "viewer" : this.role,
        accessKind: this.accessKind,
        ...(this.accessKind === "guest"
          ? {
              vaultIds: [...this.selectedVaultIds],
              expiresInDays: this.expiresInDays,
            }
          : {}),
        sendWelcomeEmail: this.sendWelcomeEmail,
      });
      if (!this.active) return;
      if (result?.provisioningStatus === "partial") {
        new Notice(this.i18n.t("guest.provisioningPartial", {
          failures: result.vaultProvisioningFailures ?? 0,
        }), 10_000);
      } else if (result?.provisioningStatus === "failed") {
        new Notice(this.i18n.t("guest.provisioningFailed"), 10_000);
      } else {
        new Notice(this.i18n.t("guest.sent", { email: this.email }));
      }
      await this.onInvited();
      if (!this.active) return;
      this.close();
    } catch (error) {
      if (!this.active) return;
      new Notice(this.i18n.t("guest.failed", {
        message: error instanceof Error ? error.message : String(error),
      }));
    } finally {
      if (this.active && this.contentEl.isConnected) {
        this.contentEl.setAttribute("aria-busy", "false");
        this.inviteButton?.setDisabled(false).setButtonText(this.i18n.t("guest.send"));
      }
    }
  }

  /**
   * Runs the reactivate-then-guest-invite sequence and reports the outcome.
   *
   * The sequence itself lives in `grantGuestAccessToRevokedUser` so it is
   * testable; this method only collects the form's values and turns the result
   * into notices.
   */
  private async handleGrantGuestAccess(target: GuestAccessGrantTarget): Promise<void> {
    this.inviteButton?.setDisabled(true).setButtonText(this.i18n.t("common.loading"));
    this.contentEl.setAttribute("aria-busy", "true");

    const outcome = await grantGuestAccessToRevokedUser(this.apiClient, {
      userId: target.id,
      email: target.email,
      role: target.role,
      vaultIds: [...this.selectedVaultIds],
      expiresInDays: this.expiresInDays,
    });

    if (!this.active) return;

    if (outcome.status === "granted") {
      new Notice(
        `${target.displayName} has been re-enabled and granted guest access for ${this.expiresInDays} days.`
      );
      await this.onInvited();
      if (!this.active) return;
      this.close();
      return;
    }

    if (outcome.status === "reactivate-failed") {
      // Nothing changed, so the message must not imply otherwise.
      new Notice(`Could not re-enable ${target.displayName}, so no access was granted: ${outcome.message}`);
    } else {
      // The three-fact compensation warning. Held on screen: it describes a
      // billable state the operator has to act on.
      new Notice(`${target.displayName}: ${outcome.message}`, 15_000);
      await this.onInvited();
    }

    if (this.active && this.contentEl.isConnected) {
      this.contentEl.setAttribute("aria-busy", "false");
      this.inviteButton?.setDisabled(false).setButtonText("Grant guest access");
    }
  }
}

// ─── User Permissions Modal ─────────────────────────────────────────────────

class UserPermissionsModal extends Modal {
  private apiClient: VaultGuardApiClient;
  private user: VaultGuardUser;
  private active = false;

  constructor(app: App, apiClient: VaultGuardApiClient, user: VaultGuardUser) {
    super(app);
    this.apiClient = apiClient;
    this.user = user;
  }

  async onOpen(): Promise<void> {
    this.active = true;
    const { contentEl } = this;
    contentEl.empty();
    this.modalEl.addClass("vaultguard-dialog-modal");
    contentEl.addClass("vaultguard-dialog-content");
    contentEl.createEl("h3", { text: `Permissions: ${this.user.displayName}` });

    const loadingEl = contentEl.createDiv({ cls: "vaultguard-loading" });
    loadingEl.createSpan({ text: "Loading permissions..." });

    try {
      const permissions = await this.apiClient.getUserPermissions(this.user.id);
      if (!this.active) return;
      contentEl.empty();
      contentEl.createEl("h3", { text: `Permissions: ${this.user.displayName}` });

      if (!permissions || permissions.length === 0) {
        contentEl.createDiv({
          cls: "vaultguard-empty-state",
          text: "No specific permissions assigned. User has default role-based access only.",
        });
        return;
      }

      const table = contentEl.createEl("table", { cls: "vaultguard-permissions-table" });
      const thead = table.createEl("thead");
      const headerRow = thead.createEl("tr");
      ["Path Pattern", "Effect", "Actions", "Principal"].forEach((h) => headerRow.createEl("th", { text: h }));

      const tbody = table.createEl("tbody");
      for (const perm of permissions) {
        const row = tbody.createEl("tr");
        row.createEl("td", { text: perm.pathPattern, cls: "vaultguard-monospace" });

        const effectCell = row.createEl("td");
        const badge = effectCell.createSpan({ cls: "vaultguard-permission-badge" });
        badge.setText(perm.effect);
        badge.addClass(perm.effect === "deny" ? "vaultguard-level-none" : "vaultguard-level-read");

        row.createEl("td", { text: perm.actions.join(", ") });
        row.createEl("td", { text: perm.role ? `role:${perm.role}` : `user:${perm.userId}` });
      }
    } catch (error) {
      if (!this.active) return;
      contentEl.empty();
      contentEl.createDiv({
        cls: "vaultguard-error",
        text: `Failed to load permissions: ${(error as Error).message}`,
      });
    }
  }

  onClose(): void {
    this.active = false;
    this.modalEl.removeClass("vaultguard-dialog-modal");
    this.contentEl.removeClass("vaultguard-dialog-content");
    this.contentEl.empty();
  }
}

// ─── User Activity Modal ────────────────────────────────────────────────────

class UserActivityModal extends Modal {
  private apiClient: VaultGuardApiClient;
  private user: VaultGuardUser;
  private active = false;

  constructor(app: App, apiClient: VaultGuardApiClient, user: VaultGuardUser) {
    super(app);
    this.apiClient = apiClient;
    this.user = user;
  }

  async onOpen(): Promise<void> {
    this.active = true;
    const { contentEl } = this;
    contentEl.empty();
    this.modalEl.addClass("vaultguard-dialog-modal");
    contentEl.addClass("vaultguard-dialog-content");
    contentEl.createEl("h3", { text: `Recent Activity: ${this.user.displayName}` });

    const loadingEl = contentEl.createDiv({ cls: "vaultguard-loading" });
    loadingEl.createSpan({ text: "Loading activity..." });

    try {
      const activities = await this.apiClient.getUserActivity(this.user.id);
      if (!this.active) return;
      contentEl.empty();
      contentEl.createEl("h3", { text: `Recent Activity: ${this.user.displayName}` });

      if (!activities || activities.length === 0) {
        contentEl.createDiv({
          cls: "vaultguard-empty-state",
          text: "No recent activity recorded for this user.",
        });
        return;
      }

      const table = contentEl.createEl("table", { cls: "vaultguard-activity-table" });
      const thead = table.createEl("thead");
      const headerRow = thead.createEl("tr");
      ["Time", "Action", "Resource", "Device"].forEach((h) => headerRow.createEl("th", { text: h }));

      const tbody = table.createEl("tbody");
      for (const activity of activities as UserActivity[]) {
        const row = tbody.createEl("tr");
        row.createEl("td", { text: new Date(activity.timestamp).toLocaleString() });

        const actionCell = row.createEl("td");
        const badge = actionCell.createSpan({ cls: "vaultguard-action-badge" });
        badge.setText(activity.action);
        badge.addClass(`vaultguard-action-${activity.action}`);

        row.createEl("td", { text: activity.resourcePath, cls: "vaultguard-monospace" });
        row.createEl("td", { text: activity.deviceInfo });
      }
    } catch (error) {
      if (!this.active) return;
      contentEl.empty();
      contentEl.createDiv({
        cls: "vaultguard-error",
        text: `Failed to load activity: ${(error as Error).message}`,
      });
    }
  }

  onClose(): void {
    this.active = false;
    this.modalEl.removeClass("vaultguard-dialog-modal");
    this.contentEl.removeClass("vaultguard-dialog-content");
    this.contentEl.empty();
  }
}

// ─── Role Editor Modal ──────────────────────────────────────────────────────

class RoleEditorModal extends Modal {
  private apiClient: VaultGuardApiClient;
  private user: VaultGuardUser;
  private onUpdated: () => Promise<void>;
  private selectedRole: UserRole;
  private active = false;

  constructor(app: App, apiClient: VaultGuardApiClient, user: VaultGuardUser, onUpdated: () => Promise<void>) {
    super(app);
    this.apiClient = apiClient;
    this.user = user;
    this.onUpdated = onUpdated;
    this.selectedRole = user.role;
  }

  onOpen(): void {
    this.active = true;
    const { contentEl } = this;
    contentEl.empty();
    this.modalEl.addClass("vaultguard-dialog-modal");
    contentEl.addClass("vaultguard-dialog-content");
    contentEl.createEl("h3", { text: `Change Role: ${this.user.displayName}` });

    contentEl.createEl("p", {
      text: `Current role: ${this.user.role}`,
      cls: "vaultguard-current-role",
    });

    new Setting(contentEl)
      .setName("New role")
      .setDesc("Changing a role immediately updates the user's effective permissions")
      .addDropdown((dropdown) =>
        dropdown
          .addOption("viewer", "Viewer (read-only access)")
          .addOption("editor", "Editor (read + write access)")
          .addOption("admin", "Admin (full access + user management)")
          .setValue(this.selectedRole)
          .onChange((value) => {
            this.selectedRole = value as UserRole;
          })
      );

    const actionRow = contentEl.createDiv({ cls: "vaultguard-modal-actions" });
    new ButtonComponent(actionRow).setButtonText("Cancel").onClick(() => this.close());
    new ButtonComponent(actionRow)
      .setButtonText("Update role")
      .setCta()
      .onClick(() => this.handleUpdate());
  }

  onClose(): void {
    this.active = false;
    this.modalEl.removeClass("vaultguard-dialog-modal");
    this.contentEl.removeClass("vaultguard-dialog-content");
    this.contentEl.empty();
  }

  private async handleUpdate(): Promise<void> {
    if (this.selectedRole === this.user.role) {
      new Notice("Role is unchanged.");
      this.close();
      return;
    }

    try {
      await this.apiClient.updateUserRole(this.user.id, this.selectedRole);
      if (!this.active) return;
      new Notice(`${this.user.displayName}'s role updated to ${this.selectedRole}.`);
      await this.onUpdated();
      if (!this.active) return;
      this.close();
    } catch (error) {
      if (!this.active) return;
      new Notice(`Failed to update role: ${(error as Error).message}`);
    }
  }
}

// ─── Revoke Access Modal ────────────────────────────────────────────────────

class RevokeAccessModal extends Modal {
  private apiClient: VaultGuardApiClient;
  private user: VaultGuardUser;
  private onRevoked: () => Promise<void>;
  private active = false;

  constructor(app: App, apiClient: VaultGuardApiClient, user: VaultGuardUser, onRevoked: () => Promise<void>) {
    super(app);
    this.apiClient = apiClient;
    this.user = user;
    this.onRevoked = onRevoked;
  }

  onOpen(): void {
    this.active = true;
    const { contentEl } = this;
    contentEl.empty();
    this.modalEl.addClass("vaultguard-revoke-modal");
    contentEl.addClass("vaultguard-dialog-content");

    contentEl.createEl("h3", { text: "Revoke access", cls: "vaultguard-danger-title" });

    contentEl.createEl("p", {
      text: `You are about to revoke all access for ${this.user.displayName} (${this.user.email}).`,
    });

    contentEl.createEl("h4", { text: "What will happen:" });
    const consequences = contentEl.createEl("ul", { cls: "vaultguard-revoke-consequences" });
    consequences.createEl("li", { text: "All active sessions will be immediately invalidated" });
    consequences.createEl("li", { text: "Cognito tokens will be revoked (no new API calls possible)" });
    consequences.createEl("li", { text: "Encryption keys will be rotated (user cannot decrypt future content)" });
    consequences.createEl("li", {
      text: "Local cache self-destruct signal will be sent (clears cached vault data on next sync attempt)",
    });
    consequences.createEl("li", { text: "User will be locked out within 30 seconds on all devices" });
    consequences.createEl("li", { text: "All pending offline changes from this user will be rejected" });

    contentEl.createEl("p", {
      text: "This action is irreversible. To restore access, you must re-invite the user.",
      cls: "vaultguard-warning-text",
    });

    // Confirmation input
    const confirmSetting = new Setting(contentEl)
      .setName("Type the user's email to confirm")
      .setDesc(this.user.email);

    let confirmValue = "";
    confirmSetting.addText((text) =>
      text.setPlaceholder(this.user.email).onChange((value) => {
        confirmValue = value;
      })
    );

    const actionRow = contentEl.createDiv({ cls: "vaultguard-modal-actions" });
    new ButtonComponent(actionRow).setButtonText("Cancel").onClick(() => this.close());
    new ButtonComponent(actionRow)
      .setButtonText("Revoke access")
      .setWarning()
      .onClick(async () => {
        if (confirmValue !== this.user.email) {
          new Notice("Email does not match. Please type the exact email to confirm.");
          return;
        }
        await this.handleRevoke();
      });
  }

  onClose(): void {
    this.active = false;
    this.modalEl.removeClass("vaultguard-revoke-modal");
    this.contentEl.removeClass("vaultguard-dialog-content");
    this.contentEl.empty();
  }

  private async handleRevoke(): Promise<void> {
    try {
      const result = await this.apiClient.revokeUser(this.user.id);
      if (!this.active) return;
      if (result?.reEncryptionJobId === null) {
        new Notice(
          `Access revoked for ${this.user.displayName}, but vault-key rotation could not start. Trigger re-encryption manually.`,
          10_000,
        );
      } else {
        new Notice(
          `Access revoked for ${this.user.displayName}. All sessions terminated${result?.reEncryptionJobId ? "; vault-key rotation started" : ""}.`,
        );
      }
      await this.onRevoked();
      if (!this.active) return;
      this.close();
    } catch (error) {
      if (!this.active) return;
      new Notice(`Failed to revoke access: ${(error as Error).message}`);
    }
  }
}
