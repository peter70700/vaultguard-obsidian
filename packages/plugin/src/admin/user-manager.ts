import {
  App,
  Modal,
  Setting,
  ButtonComponent,
  Notice,
  setIcon,
} from "obsidian";
import { VaultGuardApiClient } from "../api/client";
import type { VaultMemberRecord } from "../api/client";
import { getAccessUserNameInitials } from "../ui/access-user-utils";
import { createI18n } from "../i18n";

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

      // Summary bar
      const summary = container.createDiv({ cls: "vaultguard-user-summary" });
      const activeCount = users.filter((u: VaultGuardUser) => u.status === "active").length;
      const suspendedCount = users.filter((u: VaultGuardUser) => u.status === "suspended").length;
      const pendingCount = users.filter((u: VaultGuardUser) => u.status === "pending").length;
      summary.createSpan({ text: `${users.length} total`, cls: "vaultguard-summary-stat" });
      summary.createSpan({ text: `${activeCount} active`, cls: "vaultguard-summary-stat vaultguard-stat-active" });
      if (suspendedCount > 0) {
        summary.createSpan({ text: `${suspendedCount} suspended`, cls: "vaultguard-summary-stat vaultguard-stat-suspended" });
      }
      if (pendingCount > 0) {
        summary.createSpan({ text: `${pendingCount} pending`, cls: "vaultguard-summary-stat vaultguard-stat-pending" });
      }

      // User items
      for (const user of users as VaultGuardUser[]) {
        const membership = membershipByUser.get(user.id);
        this.renderUserItem(container, {
          ...user,
          accessKind: membership?.accessKind,
          expiresAt: membership?.expiresAt,
        });
      }
    } catch (error) {
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

    if (user.accessKind === "guest") {
      const guestBadge = badgesEl.createSpan({
        cls: "vaultguard-role-badge vaultguard-role-guest",
        text: this.i18n.t("guest.badge"),
      });
      if (user.expiresAt && Date.parse(user.expiresAt) <= Date.now()) {
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
    if (user.accessKind === "guest" && user.expiresAt) {
      const isActive = Date.parse(user.expiresAt) > Date.now();
      metaEl.createDiv({
        text: this.i18n.t(isActive ? "guest.expiresAt" : "guest.expiredAt", {
          date: new Date(user.expiresAt).toLocaleString(),
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
    }
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

  constructor(
    app: App,
    apiClient: VaultGuardApiClient,
    currentVaultId: string | undefined,
    onInvited: () => Promise<void>,
  ) {
    super(app);
    this.apiClient = apiClient;
    this.currentVaultId = currentVaultId;
    this.onInvited = onInvited;
  }

  async onOpen(): Promise<void> {
    const { contentEl } = this;
    contentEl.empty();
    this.modalEl.addClass("vaultguard-dialog-modal");
    contentEl.addClass("vaultguard-dialog-content");
    this.i18n.applyToRoot(contentEl);
    const title = contentEl.createEl("h3", {
      text: this.i18n.t("guest.title"),
      attr: { id: "vaultguard-invite-user-title" },
    });
    this.modalEl.setAttribute("aria-labelledby", title.id);

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
        if (version !== renderVersion || this.accessKind !== "guest") return;
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
      if (version !== renderVersion || this.accessKind !== "guest") return;
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
    contentEl.appendChild(accessDetails);
    await renderAccessDetails();

    new Setting(contentEl)
      .setName(this.i18n.t("guest.welcome.name"))
      .setDesc(this.i18n.t("guest.welcome.description"))
      .addToggle((toggle) =>
        toggle.setValue(this.sendWelcomeEmail).onChange((value) => {
          this.sendWelcomeEmail = value;
        })
      );

    const actionRow = contentEl.createDiv({ cls: "vaultguard-modal-actions" });
    new ButtonComponent(actionRow)
      .setButtonText(this.i18n.t("common.cancel"))
      .onClick(() => this.close());
    this.inviteButton = new ButtonComponent(actionRow)
      .setButtonText(this.i18n.t("guest.send"))
      .setCta()
      .onClick(() => this.handleInvite());
  }

  onClose(): void {
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
      this.close();
    } catch (error) {
      new Notice(this.i18n.t("guest.failed", {
        message: error instanceof Error ? error.message : String(error),
      }));
    } finally {
      this.contentEl.setAttribute("aria-busy", "false");
      this.inviteButton?.setDisabled(false).setButtonText(this.i18n.t("guest.send"));
    }
  }
}

// ─── User Permissions Modal ─────────────────────────────────────────────────

class UserPermissionsModal extends Modal {
  private apiClient: VaultGuardApiClient;
  private user: VaultGuardUser;

  constructor(app: App, apiClient: VaultGuardApiClient, user: VaultGuardUser) {
    super(app);
    this.apiClient = apiClient;
    this.user = user;
  }

  async onOpen(): Promise<void> {
    const { contentEl } = this;
    contentEl.empty();
    this.modalEl.addClass("vaultguard-dialog-modal");
    contentEl.addClass("vaultguard-dialog-content");
    contentEl.createEl("h3", { text: `Permissions: ${this.user.displayName}` });

    const loadingEl = contentEl.createDiv({ cls: "vaultguard-loading" });
    loadingEl.createSpan({ text: "Loading permissions..." });

    try {
      const permissions = await this.apiClient.getUserPermissions(this.user.id);
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
      contentEl.empty();
      contentEl.createDiv({
        cls: "vaultguard-error",
        text: `Failed to load permissions: ${(error as Error).message}`,
      });
    }
  }

  onClose(): void {
    this.modalEl.removeClass("vaultguard-dialog-modal");
    this.contentEl.removeClass("vaultguard-dialog-content");
    this.contentEl.empty();
  }
}

// ─── User Activity Modal ────────────────────────────────────────────────────

class UserActivityModal extends Modal {
  private apiClient: VaultGuardApiClient;
  private user: VaultGuardUser;

  constructor(app: App, apiClient: VaultGuardApiClient, user: VaultGuardUser) {
    super(app);
    this.apiClient = apiClient;
    this.user = user;
  }

  async onOpen(): Promise<void> {
    const { contentEl } = this;
    contentEl.empty();
    this.modalEl.addClass("vaultguard-dialog-modal");
    contentEl.addClass("vaultguard-dialog-content");
    contentEl.createEl("h3", { text: `Recent Activity: ${this.user.displayName}` });

    const loadingEl = contentEl.createDiv({ cls: "vaultguard-loading" });
    loadingEl.createSpan({ text: "Loading activity..." });

    try {
      const activities = await this.apiClient.getUserActivity(this.user.id);
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
      contentEl.empty();
      contentEl.createDiv({
        cls: "vaultguard-error",
        text: `Failed to load activity: ${(error as Error).message}`,
      });
    }
  }

  onClose(): void {
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

  constructor(app: App, apiClient: VaultGuardApiClient, user: VaultGuardUser, onUpdated: () => Promise<void>) {
    super(app);
    this.apiClient = apiClient;
    this.user = user;
    this.onUpdated = onUpdated;
    this.selectedRole = user.role;
  }

  onOpen(): void {
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
      new Notice(`${this.user.displayName}'s role updated to ${this.selectedRole}.`);
      await this.onUpdated();
      this.close();
    } catch (error) {
      new Notice(`Failed to update role: ${(error as Error).message}`);
    }
  }
}

// ─── Revoke Access Modal ────────────────────────────────────────────────────

class RevokeAccessModal extends Modal {
  private apiClient: VaultGuardApiClient;
  private user: VaultGuardUser;
  private onRevoked: () => Promise<void>;

  constructor(app: App, apiClient: VaultGuardApiClient, user: VaultGuardUser, onRevoked: () => Promise<void>) {
    super(app);
    this.apiClient = apiClient;
    this.user = user;
    this.onRevoked = onRevoked;
  }

  onOpen(): void {
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
    this.modalEl.removeClass("vaultguard-revoke-modal");
    this.contentEl.removeClass("vaultguard-dialog-content");
    this.contentEl.empty();
  }

  private async handleRevoke(): Promise<void> {
    try {
      await this.apiClient.revokeUser(this.user.id);
      new Notice(`Access revoked for ${this.user.displayName}. All sessions terminated.`);
      await this.onRevoked();
      this.close();
    } catch (error) {
      new Notice(`Failed to revoke access: ${(error as Error).message}`);
    }
  }
}
