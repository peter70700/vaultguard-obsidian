import {
  App,
  Modal,
  Setting,
  ButtonComponent,
  Notice,
  setIcon,
} from "obsidian";
import { VaultGuardApiClient } from "../api/client";
import { getAccessUserNameInitials } from "../ui/access-user-utils";

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

  constructor(app: App, apiClient: VaultGuardApiClient) {
    this.app = app;
    this.apiClient = apiClient;
  }

  /**
   * Renders the user list into the given container.
   */
  async renderUserList(container: HTMLElement): Promise<void> {
    container.empty();
    const loadingEl = container.createDiv({ cls: "vaultguard-loading" });
    loadingEl.createSpan({ text: "Loading users..." });

    try {
      const users = await this.apiClient.listUsers();
      container.empty();

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
        this.renderUserItem(container, user);
      }
    } catch (error) {
      container.empty();
      container.createDiv({
        cls: "vaultguard-error",
        text: `Failed to load users: ${(error as Error).message}`,
      });
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

    // Action buttons
    const actionsEl = itemEl.createDiv({ cls: "vaultguard-user-actions" });

    // View permissions button
    const viewPermsBtn = actionsEl.createEl("button", { cls: "vaultguard-icon-btn", attr: { title: "View permissions" } });
    setIcon(viewPermsBtn, "key");
    viewPermsBtn.addEventListener("click", () => this.showUserPermissions(user));

    // View activity button
    const viewActivityBtn = actionsEl.createEl("button", { cls: "vaultguard-icon-btn", attr: { title: "View activity" } });
    setIcon(viewActivityBtn, "activity");
    viewActivityBtn.addEventListener("click", () => this.showUserActivity(user));

    // Edit role button
    const editRoleBtn = actionsEl.createEl("button", { cls: "vaultguard-icon-btn", attr: { title: "Change role" } });
    setIcon(editRoleBtn, "user-cog");
    editRoleBtn.addEventListener("click", () => this.showRoleEditor(user, container));

    // Lifecycle actions.
    if (user.status === "active") {
      const revokeBtn = actionsEl.createEl("button", {
        cls: "vaultguard-icon-btn vaultguard-danger",
        attr: { title: "Revoke access" },
      });
      setIcon(revokeBtn, "x-circle");
      revokeBtn.addEventListener("click", () => this.confirmRevokeAccess(user, container));
    } else if (user.status === "pending") {
      const resendBtn = actionsEl.createEl("button", {
        cls: "vaultguard-icon-btn",
        attr: { title: "Resend invitation" },
      });
      setIcon(resendBtn, "send");
      resendBtn.addEventListener("click", () => this.resendInvitation(user));
    } else if (user.status === "suspended" || user.status === "revoked") {
      const reactivateBtn = actionsEl.createEl("button", {
        cls: "vaultguard-icon-btn vaultguard-success",
        attr: { title: "Reactivate user" },
      });
      setIcon(reactivateBtn, "check-circle");
      reactivateBtn.addEventListener("click", () => this.reactivateUser(user, container));
    }
  }

  /**
   * Shows the invite user dialog.
   */
  async showInviteDialog(parentContainer: HTMLElement): Promise<void> {
    const modal = new InviteUserModal(this.app, this.apiClient, async () => {
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
  private email: string = "";
  private role: UserRole = "viewer";
  private sendWelcomeEmail: boolean = true;

  constructor(app: App, apiClient: VaultGuardApiClient, onInvited: () => Promise<void>) {
    super(app);
    this.apiClient = apiClient;
    this.onInvited = onInvited;
  }

  onOpen(): void {
    const { contentEl } = this;
    contentEl.empty();
    this.modalEl.addClass("vaultguard-dialog-modal");
    contentEl.addClass("vaultguard-dialog-content");
    contentEl.createEl("h3", { text: "Invite User" });

    new Setting(contentEl)
      .setName("Email Address")
      .setDesc("An invitation will be sent via AWS Cognito")
      .addText((text) =>
        text
          .setPlaceholder("user@company.com")
          .onChange((value) => {
            this.email = value;
          })
      );

    new Setting(contentEl)
      .setName("Role")
      .setDesc("Initial role assignment (can be changed later)")
      .addDropdown((dropdown) =>
        dropdown
          .addOption("viewer", "Viewer (read-only)")
          .addOption("editor", "Editor (read + write)")
          .addOption("admin", "Admin (full access)")
          .setValue(this.role)
          .onChange((value) => {
            this.role = value as UserRole;
          })
      );

    new Setting(contentEl)
      .setName("Send Welcome Email")
      .setDesc("Send an email with setup instructions and invite link")
      .addToggle((toggle) =>
        toggle.setValue(this.sendWelcomeEmail).onChange((value) => {
          this.sendWelcomeEmail = value;
        })
      );

    const actionRow = contentEl.createDiv({ cls: "vaultguard-modal-actions" });
    new ButtonComponent(actionRow).setButtonText("Cancel").onClick(() => this.close());
    new ButtonComponent(actionRow)
      .setButtonText("Send Invite")
      .setCta()
      .onClick(() => this.handleInvite());
  }

  onClose(): void {
    this.modalEl.removeClass("vaultguard-dialog-modal");
    this.contentEl.removeClass("vaultguard-dialog-content");
    this.contentEl.empty();
  }

  private async handleInvite(): Promise<void> {
    if (!this.email || !this.email.includes("@")) {
      new Notice("Please enter a valid email address.");
      return;
    }

    try {
      await this.apiClient.inviteUser({
        email: this.email,
        role: this.role,
        sendWelcomeEmail: this.sendWelcomeEmail,
      });
      new Notice(`Invitation sent to ${this.email}`);
      await this.onInvited();
      this.close();
    } catch (error) {
      new Notice(`Failed to invite: ${(error as Error).message}`);
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
      .setName("New Role")
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
      .setButtonText("Update Role")
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

    contentEl.createEl("h3", { text: "Revoke Access", cls: "vaultguard-danger-title" });

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
      .setButtonText("Revoke Access")
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
