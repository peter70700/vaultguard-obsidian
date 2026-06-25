import {
  App,
  Modal,
  Setting,
  DropdownComponent,
  TextComponent,
  ButtonComponent,
  Notice,
  setIcon,
} from "obsidian";
import {
  VaultGuardApiClient,
  AuditLogEntry,
  OrgSettingsResponse,
  PermissionRule,
  UserListEntry,
  VaultMemberRecord,
  VaultMemberRole,
  VaultRecord,
} from "../api/client";
import { PermissionEditor } from "./permission-editor";
import { PermissionRulesView } from "../ui/permission-rules-view";
import { buildFallbackOrgSettings, shouldUseFallbackOrgSettings } from "./settings-support";
import { UserManager } from "./user-manager";
import { getAccessUserDisplayName } from "../ui/access-user-utils";
import { ProUpsellModal } from "../ui/pro-upsell-modal";
import type { ServerFeatures } from "../types";

type TabId = "users" | "permissions" | "audit" | "settings" | "recovery";
type OrgSettings = OrgSettingsResponse;
type AdminModalContext = {
  orgId?: string;
  orgSlug?: string;
  currentUser?: {
    id: string;
    displayName?: string;
    email?: string;
    orgRole?: string;
    roles?: string[];
    vaultRole?: VaultMemberRole | null;
  };
  /**
   * Capability flags advertised by the backend. The modal uses these to hide
   * Pro-only audit-event filter options when connected to a Community Edition
   * server. Optional — if absent, all options are shown (historic behavior).
   */
  features?: ServerFeatures;
  /** Called after a vault-access rule changes so the plugin can refresh the
   *  file header, file-explorer decorations, and sidebar. */
  onPermissionsChanged?: () => void;
  /** Optional initial filter for the Vault access rules overview. */
  permissionsInitialSearch?: string;
};
type PermissionAccessSummary = {
  pathLabel: string;
  badgeText: string;
  badgeClass: string;
  description: string;
};

const AUDIT_ACTION_OPTIONS: Array<{ value: string; label: string }> = [
  { value: "all", label: "All Actions" },
  { value: "admin.access.denied", label: "Admin Access Denied" },
  { value: "admin.list_users", label: "Admin List Users" },
  { value: "admin.role_changed", label: "Admin Role Changed" },
  { value: "admin.settings_reset", label: "Admin Settings Reset" },
  { value: "admin.settings_updated", label: "Admin Settings Updated" },
  { value: "admin.user_invited", label: "Admin User Invited" },
  { value: "admin.user_reactivated", label: "Admin User Reactivated" },
  { value: "admin.user_removed", label: "Admin User Removed" },
  { value: "audit.access.denied", label: "Audit Access Denied" },
  { value: "audit.export", label: "Audit Export" },
  { value: "auth.key-lease.denied", label: "Key Lease Denied" },
  { value: "auth.key-lease.issued", label: "Key Lease Issued" },
  { value: "auth.key-lease.scoped", label: "Scoped Key Lease" },
  { value: "auth.login", label: "Login" },
  { value: "auth.logout", label: "Logout" },
  { value: "auth.recover", label: "Recover Access" },
  { value: "auth.recover.denied", label: "Recover Access Denied" },
  { value: "auth.refresh", label: "Refresh Session" },
  { value: "auth.revoke", label: "Revoke Access" },
  { value: "auth.revoke.denied", label: "Revoke Access Denied" },
  { value: "auth.setup-zk", label: "Setup Zero-Knowledge" },
  { value: "billing.checkout_completed", label: "Billing Checkout Completed" },
  { value: "billing.checkout_started", label: "Billing Checkout Started" },
  { value: "billing.payment_failed", label: "Billing Payment Failed" },
  { value: "billing.payment_succeeded", label: "Billing Payment Succeeded" },
  { value: "billing.subscription_canceled", label: "Billing Subscription Canceled" },
  { value: "billing.subscription_updated", label: "Billing Subscription Updated" },
  { value: "files.delete", label: "File Delete" },
  { value: "files.delete.denied", label: "File Delete Denied" },
  { value: "files.history", label: "File History" },
  { value: "files.history.denied", label: "File History Denied" },
  { value: "files.list", label: "File List" },
  { value: "files.read", label: "File Read" },
  { value: "files.read.denied", label: "File Read Denied" },
  { value: "files.sync", label: "File Sync" },
  { value: "files.write", label: "File Write" },
  { value: "files.write.denied", label: "File Write Denied" },
  { value: "org.created", label: "Organization Created" },
  { value: "permissions.check", label: "Permission Check" },
  { value: "permissions.create", label: "Permission Created" },
  { value: "permissions.create.denied", label: "Permission Create Denied" },
  { value: "permissions.delete", label: "Permission Deleted" },
  { value: "permissions.delete.denied", label: "Permission Delete Denied" },
  { value: "permissions.list", label: "Permission List" },
  { value: "permissions.list.denied", label: "Permission List Denied" },
  { value: "permissions.update", label: "Permission Updated" },
  { value: "permissions.update.denied", label: "Permission Update Denied" },
  { value: "permissions.user.denied", label: "Permission User View Denied" },
  { value: "permissions.user.view", label: "Permission User View" },
  { value: "reencryption.completed", label: "Re-encryption Completed" },
];

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export class AdminModal extends Modal {
  private activeTab: TabId;
  private apiClient: VaultGuardApiClient;
  private permissionsUserId: string | null;
  private tabContainer!: HTMLElement;
  private contentContainer!: HTMLElement;
  private statusEl!: HTMLElement;
  private userManager: UserManager;
  private permissionEditor: PermissionEditor;
  private unsubscribeConnection: (() => void) | null = null;
  private auditCursor: string | null = null;
  private auditHasMore: boolean = false;
  private auditFilters: { search?: string; action?: string; dateFrom?: string; dateTo?: string } = {};
  private userEmailMap: Map<string, string> = new Map();
  private userLabelMap: Map<string, string> = new Map();
  private vaultRoleMap: Map<string, VaultMemberRole> = new Map();
  private principalDirectoryLoaded = false;
  private principalDirectoryPromise: Promise<void> | null = null;
  private auditUserEmailsLoaded = false;
  private readonly context: AdminModalContext;

  constructor(
    app: App,
    apiClient: VaultGuardApiClient,
    initialTab: TabId = "users",
    permissionsUserId: string | null = null,
    context: AdminModalContext = {}
  ) {
    super(app);
    this.activeTab = initialTab;
    this.apiClient = apiClient;
    this.permissionsUserId = permissionsUserId;
    this.context = context;
    this.userManager = new UserManager(app, apiClient);
    this.permissionEditor = new PermissionEditor(app, apiClient);
    this.seedCurrentUserIdentity();
  }

  onOpen(): void {
    const contentEl = this.contentEl;
    contentEl.replaceChildren();
    this.modalEl.classList.add("vaultguard-admin-modal");
    contentEl.classList.add("vaultguard-admin-modal-content");

    // Modal header
    const header = this.createDivElement(contentEl, "vaultguard-admin-header");
    const title = contentEl.ownerDocument.createElement("h2");
    title.textContent = this.permissionsUserId
      ? "VaultGuard - My Vault Access"
      : "VaultGuard - Organization Admin";
    header.appendChild(title);

    // Connection status indicator (updates reactively)
    this.statusEl = this.createDivElement(header, "vaultguard-connection-status");
    this.renderConnectionStatus(this.statusEl);
    this.unsubscribeConnection = this.apiClient.onConnectionStatusChange(() => {
      this.renderConnectionStatus(this.statusEl);
    });

    // Tab navigation
    this.tabContainer = this.createDivElement(contentEl, "vaultguard-tab-nav");
    this.renderTabs();

    // Content area
    this.contentContainer = this.createDivElement(contentEl, "vaultguard-tab-content");
    this.renderActiveTab();
  }

  onClose(): void {
    if (this.unsubscribeConnection) {
      this.unsubscribeConnection();
      this.unsubscribeConnection = null;
    }
    this.modalEl.classList.remove("vaultguard-admin-modal");
    this.contentEl.classList.remove("vaultguard-admin-modal-content");
    this.contentEl.replaceChildren();
  }

  private createDivElement(parent: HTMLElement, className: string): HTMLDivElement {
    const div = parent.ownerDocument.createElement("div");
    div.className = className;
    parent.appendChild(div);
    return div;
  }

  private renderConnectionStatus(container: HTMLElement): void {
    container.empty();
    const isAuth = this.apiClient.isAuthenticated();
    const dot = container.createSpan({ cls: "vaultguard-status-dot" });
    dot.addClass(isAuth ? "vaultguard-status-online" : "vaultguard-status-offline");
    container.createSpan({
      text: isAuth ? "Authenticated" : "Not authenticated",
      cls: "vaultguard-status-text",
    });
  }

  private renderTabs(): void {
    this.tabContainer.empty();

    const tabs: { id: TabId; label: string; icon: string }[] = this.permissionsUserId
      ? [{ id: "permissions", label: "My vault access", icon: "shield" }]
      : [
          { id: "users", label: "Users", icon: "users" },
          { id: "permissions", label: "Vault access", icon: "shield" },
          { id: "audit", label: "Audit Log", icon: "file-text" },
          { id: "recovery", label: "Recovery", icon: "key" },
          { id: "settings", label: "Org settings", icon: "settings" },
        ];

    if (!tabs.some((tab) => tab.id === this.activeTab)) {
      this.activeTab = this.permissionsUserId ? "permissions" : "users";
    }

    for (const tab of tabs) {
      const tabEl = this.tabContainer.createDiv({
        cls: `vaultguard-tab ${this.activeTab === tab.id ? "vaultguard-tab-active" : ""}`,
      });
      const iconSpan = tabEl.createSpan({ cls: "vaultguard-tab-icon" });
      setIcon(iconSpan, tab.icon);
      tabEl.createSpan({ text: tab.label });
      tabEl.addEventListener("click", () => {
        this.activeTab = tab.id;
        this.renderTabs();
        this.renderActiveTab();
      });
    }
  }

  private renderActiveTab(): void {
    this.contentContainer.replaceChildren();

    switch (this.activeTab) {
      case "users":
        void this.renderUsersTab().catch((error: unknown) => this.renderTabError(error));
        break;
      case "permissions":
        void this.renderPermissionsTab().catch((error: unknown) => this.renderTabError(error));
        break;
      case "audit":
        void this.renderAuditTab().catch((error: unknown) => this.renderTabError(error));
        break;
      case "recovery":
        void this.renderRecoveryTab().catch((error: unknown) => this.renderTabError(error));
        break;
      case "settings":
        void this.renderSettingsTab().catch((error: unknown) => this.renderTabError(error));
        break;
    }
  }

  private renderTabError(error: unknown): void {
    this.contentContainer.replaceChildren();
    const errorEl = this.createDivElement(this.contentContainer, "vaultguard-error");
    errorEl.textContent = `Failed to render ${this.activeTab}: ${errorMessage(error)}`;
  }

  // ─── Users Tab ───────────────────────────────────────────────────────

  private async renderUsersTab(): Promise<void> {
    const container = this.createDivElement(this.contentContainer, "vaultguard-users-tab");

    // Toolbar
    const toolbar = this.createDivElement(container, "vaultguard-toolbar");
    new ButtonComponent(toolbar)
      .setButtonText("Invite User")
      .setCta()
      .onClick(() => this.userManager.showInviteDialog(container));

    const searchInput = new TextComponent(toolbar)
      .setPlaceholder("Search users...")
      .onChange((value) => this.filterUsers(value, userList));
    searchInput.inputEl.addClass("vaultguard-search-input");

    // User list
    const userList = this.createDivElement(container, "vaultguard-user-list");
    await this.userManager.renderUserList(userList);
  }

  private filterUsers(query: string, container: HTMLElement): void {
    const items = container.querySelectorAll(".vaultguard-user-item");
    const lowerQuery = query.toLowerCase();
    items.forEach((item) => {
      const name = item.getAttribute("data-username") || "";
      const email = item.getAttribute("data-email") || "";
      const visible =
        name.toLowerCase().includes(lowerQuery) ||
        email.toLowerCase().includes(lowerQuery);
      (item as HTMLElement).toggle(visible);
    });
  }

  // ─── Permissions Tab ─────────────────────────────────────────────────

  private async renderPermissionsTab(): Promise<void> {
    const container = this.contentContainer.createDiv({ cls: "vaultguard-permissions-tab" });

    // Admin "Vault access": the full rules table (search, add / edit / delete,
    // principal dropdowns, level, priority, expiry) — same as the web admin
    // panel. The per-user "My vault access" view keeps the read-only tree.
    if (!this.permissionsUserId) {
      const view = new PermissionRulesView(this.apiClient, container, {
        app: this.app,
        currentUser: {
          id: this.context.currentUser?.id,
          orgRole: this.context.currentUser?.orgRole,
          roles: this.context.currentUser?.roles,
          vaultRole: this.context.currentUser?.vaultRole,
        },
        onChanged: this.context.onPermissionsChanged,
        initialSearch: this.context.permissionsInitialSearch,
      });
      view.mount();
      return;
    }

    container.createEl("h3", { text: "My vault access" });
    container.createDiv({
      cls: "setting-item-description vaultguard-admin-tab-description",
      text:
        "Your vault role plus any direct rules returned for your account in the currently bound server vault.",
    });

    const toolbar = container.createDiv({ cls: "vaultguard-toolbar" });
    const treeContainer = container.createDiv({ cls: "vaultguard-permission-tree" });
    container.addEventListener("vaultguard-refresh-permissions", async () => {
      await this.renderPermissionTree(treeContainer);
    });
    toolbar.createSpan({
      text: "Your currently assigned rule set.",
      cls: "vaultguard-status-text",
    });

    // Rule list grouped visually by path pattern
    await this.renderPermissionTree(treeContainer);
  }

  private async renderPermissionTree(container: HTMLElement): Promise<void> {
    container.empty();
    const loadingEl = container.createDiv({ cls: "vaultguard-loading" });
    loadingEl.createSpan({ text: "Loading permissions..." });

    try {
      const permissionsPromise = this.permissionsUserId
        ? this.apiClient.getUserPermissions(this.permissionsUserId)
        : this.apiClient.getPermissions();
      const [permissions] = await Promise.all([
        permissionsPromise,
        this.hydratePrincipalDirectory(),
      ]);
      container.empty();
      const renderedSummary = this.renderPermissionsUserAccessSummary(container);

      if (!permissions || permissions.length === 0) {
        container.createDiv({
          cls: "vaultguard-empty-state",
          text: renderedSummary
            ? "No additional direct permission rules are assigned."
            : this.permissionsUserId
              ? "No direct permission rules were returned for your account."
              : "No permission rules configured. Click 'Add Rule' to get started.",
        });
        return;
      }

      const sortedRules = [...permissions].sort((a, b) =>
        a.pathPattern.localeCompare(b.pathPattern) ||
        this.formatPrincipalLabel(a).localeCompare(this.formatPrincipalLabel(b))
      );

      for (const rule of sortedRules) {
        const nodeEl = container.createDiv({ cls: "vaultguard-tree-node" });
        const headerEl = nodeEl.createDiv({ cls: "vaultguard-tree-node-header" });

        // Folder icon and path
        const iconSpan = headerEl.createSpan({ cls: "vaultguard-tree-icon" });
        setIcon(iconSpan, rule.pathPattern.endsWith("/") ? "folder" : "file");
        const pathEl = headerEl.createSpan({ text: rule.pathPattern, cls: "vaultguard-tree-path" });
        pathEl.setAttribute("title", rule.pathPattern);

        // Rule badges
        const badgesEl = headerEl.createDiv({ cls: "vaultguard-tree-badges" });
        const principalBadge = badgesEl.createSpan({ cls: "vaultguard-permission-badge" });
        principalBadge.setText(this.formatPrincipalLabel(rule));
        principalBadge.addClass(rule.effect === "deny" ? "vaultguard-level-none" : "vaultguard-level-read");

        const actionBadge = badgesEl.createSpan({ cls: "vaultguard-permission-badge" });
        actionBadge.setText(`${rule.effect} ${rule.actions.join(", ")}`);
        actionBadge.addClass(rule.effect === "deny" ? "vaultguard-level-none" : this.getRuleLevelClass(rule));

        // Edit/Delete actions
        if (!this.permissionsUserId) {
          const actionsEl = headerEl.createDiv({ cls: "vaultguard-tree-actions" });
          const editBtn = actionsEl.createEl("button", { cls: "vaultguard-icon-btn" });
          setIcon(editBtn, "pencil");
          editBtn.addEventListener("click", (e) => {
            e.stopPropagation();
            this.permissionEditor.showEditRuleDialog(container, rule);
          });

          const deleteBtn = actionsEl.createEl("button", { cls: "vaultguard-icon-btn vaultguard-danger" });
          setIcon(deleteBtn, "trash");
          deleteBtn.addEventListener("click", (e) => {
            e.stopPropagation();
            this.confirmDeletePermission(rule, container);
          });
        }
      }
    } catch (error) {
      container.empty();
      container.createDiv({
        cls: "vaultguard-error",
        text: `Failed to load permissions: ${errorMessage(error)}`,
      });
    }
  }

  private formatPrincipalLabel(rule: PermissionRule): string {
    if (rule.role) {
      return `role:${rule.role}`;
    }
    return rule.userId === "*" ? "all users" : this.formatUserLabel(rule.userId);
  }

  private renderPermissionsUserAccessSummary(container: HTMLElement): boolean {
    const summary = this.getPermissionsUserAccessSummary();
    if (!summary) return false;

    const nodeEl = container.createDiv({ cls: "vaultguard-tree-node" });
    const headerEl = nodeEl.createDiv({ cls: "vaultguard-tree-node-header" });

    const iconSpan = headerEl.createSpan({ cls: "vaultguard-tree-icon" });
    setIcon(iconSpan, "shield-check");
    headerEl.createSpan({ text: summary.pathLabel, cls: "vaultguard-tree-path" });

    const badgesEl = headerEl.createDiv({ cls: "vaultguard-tree-badges" });
    const principalBadge = badgesEl.createSpan({ cls: "vaultguard-permission-badge" });
    principalBadge.setText(this.formatUserLabel(this.permissionsUserId ?? ""));
    principalBadge.addClass(summary.badgeClass);

    const accessBadge = badgesEl.createSpan({ cls: "vaultguard-permission-badge" });
    accessBadge.setText(summary.badgeText);
    accessBadge.addClass(summary.badgeClass);

    nodeEl.createDiv({
      cls: "setting-item-description vaultguard-admin-tab-description",
      text: summary.description,
    });
    return true;
  }

  private getPermissionsUserAccessSummary(): PermissionAccessSummary | null {
    if (!this.permissionsUserId) return null;

    const currentUser = this.context.currentUser;
    const isCurrentUser = currentUser?.id === this.permissionsUserId;
    const currentUserRoles = [
      currentUser?.orgRole,
      ...(currentUser?.roles ?? []),
    ].filter((role): role is string => Boolean(role));

    if (isCurrentUser && this.rolesIncludeOrgAdmin(currentUserRoles)) {
      return {
        pathLabel: "Entire vault",
        badgeText: "Full access",
        badgeClass: "vaultguard-level-admin",
        description:
          "Your organization admin role grants read, write, delete, list, and permission management access in this vault.",
      };
    }

    const vaultRole =
      (isCurrentUser ? currentUser?.vaultRole : null)
      ?? this.vaultRoleMap.get(this.permissionsUserId)
      ?? null;

    switch (vaultRole) {
      case "admin":
        return {
          pathLabel: "Entire vault",
          badgeText: "Full access",
          badgeClass: "vaultguard-level-admin",
          description:
            "Your vault admin role grants read, write, delete, list, and permission management access in this vault.",
        };
      case "editor":
        return {
          pathLabel: "Vault defaults",
          badgeText: "Read + write",
          badgeClass: "vaultguard-level-write",
          description:
            "Your editor role grants read, list, and write access by default. Direct rules below can narrow or extend that access for specific paths.",
        };
      case "viewer":
        return {
          pathLabel: "Vault defaults",
          badgeText: "Read only",
          badgeClass: "vaultguard-level-read",
          description:
            "Your viewer role grants read and list access by default. Direct rules below can narrow or extend that access for specific paths.",
        };
      default:
        return null;
    }
  }

  private async hydratePrincipalDirectory(): Promise<void> {
    this.seedCurrentUserIdentity();
    if (this.principalDirectoryLoaded) return;
    if (this.principalDirectoryPromise) {
      await this.principalDirectoryPromise;
      return;
    }

    this.principalDirectoryPromise = this.loadPrincipalDirectory();
    try {
      await this.principalDirectoryPromise;
      this.principalDirectoryLoaded = true;
    } finally {
      this.principalDirectoryPromise = null;
    }
  }

  private async loadPrincipalDirectory(): Promise<void> {
    const tasks: Array<Promise<void>> = [];
    const vaultId = this.apiClient.getVaultId();
    const currentUserRoles = [
      this.context.currentUser?.orgRole,
      ...(this.context.currentUser?.roles ?? []),
    ].filter((role): role is string => Boolean(role));
    const canLoadAdminUsers =
      !this.permissionsUserId || this.rolesIncludeOrgAdmin(currentUserRoles);

    if (vaultId) {
      tasks.push(
        this.apiClient
          .listVaultMembers(vaultId)
          .then((members) => this.mergeVaultMembersIntoPrincipalDirectory(members))
          .catch(() => {
            // Non-critical: explicit rules can still render with the current user's session label.
          })
      );
    }

    if (canLoadAdminUsers) {
      tasks.push(
        this.apiClient
          .listUsers()
          .then((users) => {
            this.mergeUsersIntoPrincipalDirectory(users);
            this.auditUserEmailsLoaded = true;
          })
          .catch(() => {
            // Non-critical: vault members and the current session still cover
            // the "my permissions" view if /users is unavailable.
          })
      );
    }

    await Promise.all(tasks);
  }

  private mergeUsersIntoPrincipalDirectory(users: UserListEntry[]): void {
    for (const user of users) {
      this.registerUserIdentity({
        id: user.id,
        email: user.email,
        displayName: user.displayName,
        name: user.name,
      });
    }
  }

  private mergeVaultMembersIntoPrincipalDirectory(members: VaultMemberRecord[]): void {
    for (const member of members) {
      this.vaultRoleMap.set(member.userId, member.role);
      this.registerUserIdentity({
        id: member.userId,
        email: member.email ?? "",
        displayName: member.displayName ?? "",
        name: member.displayName ?? "",
      });
    }
  }

  private seedCurrentUserIdentity(): void {
    const currentUser = this.context.currentUser;
    if (!currentUser?.id) return;

    this.registerUserIdentity({
      id: currentUser.id,
      email: currentUser.email ?? "",
      displayName: currentUser.displayName ?? "",
      name: currentUser.displayName ?? "",
    });
    if (currentUser.vaultRole) {
      this.vaultRoleMap.set(currentUser.id, currentUser.vaultRole);
    }
  }

  private registerUserIdentity(user: {
    id: string;
    email?: string;
    displayName?: string;
    name?: string;
  }): void {
    if (!user.id) return;

    const label = getAccessUserDisplayName({
      id: user.id,
      email: user.email ?? "",
      displayName: user.displayName ?? "",
      name: user.name ?? "",
    });
    const existing = this.userLabelMap.get(user.id);
    if (!existing || existing === user.id || label !== user.id) {
      this.userLabelMap.set(user.id, label);
    }

    if (user.email?.trim()) {
      this.userEmailMap.set(user.id, user.email.trim());
    }
  }

  private formatUserLabel(userId: string): string {
    if (!userId) return "Current user";
    return this.userLabelMap.get(userId) ?? this.userEmailMap.get(userId) ?? userId;
  }

  private rolesIncludeOrgAdmin(roles: string[]): boolean {
    return roles.includes("admin") || roles.includes("owner") || roles.includes("vault-admin");
  }

  private getRuleLevelClass(rule: PermissionRule): string {
    if (rule.actions.includes("admin")) {
      return "vaultguard-level-admin";
    }
    if (rule.actions.includes("write") || rule.actions.includes("delete")) {
      return "vaultguard-level-write";
    }
    return "vaultguard-level-read";
  }

  /**
   * Guards against self-lockout: deleting a rule that grants the current user
   * their own `admin` (permission-management) access would leave them unable to
   * manage permissions here. Org admins bypass all rules, so they can never
   * lock themselves out and are exempt.
   */
  private wouldDeleteOwnAdminRule(rule: PermissionRule): boolean {
    const cu = this.context.currentUser;
    if (!cu?.id) return false;
    const roles = [cu.orgRole, ...(cu.roles ?? [])].filter(
      (role): role is string => Boolean(role)
    );
    if (this.rolesIncludeOrgAdmin(roles)) return false;
    if (rule.effect !== "allow" || !rule.actions.includes("admin")) return false;
    const appliesToSelf =
      rule.userId === cu.id ||
      (!!rule.role && (roles.includes(rule.role) || cu.vaultRole === rule.role));
    return appliesToSelf;
  }

  private async confirmDeletePermission(rule: PermissionRule, container: HTMLElement): Promise<void> {
    if (this.wouldDeleteOwnAdminRule(rule)) {
      new Notice(
        "You can't delete a rule that grants your own admin access — ask another admin to do it."
      );
      return;
    }
    const confirmed = await this.showConfirmDialog(
      "Delete Permission Rule",
      `Delete the ${this.formatPrincipalLabel(rule)} rule on "${rule.pathPattern}"? This cannot be undone.`
    );
    if (confirmed) {
      try {
        await this.apiClient.deletePermission(rule.id);
        new Notice("Permission rule deleted.");
        await this.renderPermissionTree(container);
      } catch (error) {
        new Notice(`Failed to delete: ${errorMessage(error)}`);
      }
    }
  }

  // ─── Audit Log Tab ───────────────────────────────────────────────────

  private async renderAuditTab(): Promise<void> {
    if (this.permissionsUserId) {
      this.contentContainer.createDiv({
        cls: "vaultguard-empty-state",
        text: "Audit logs are available only in the admin panel.",
      });
      return;
    }

    // Pre-load user email map for audit display
    if (!this.auditUserEmailsLoaded) {
      try {
        const userList = await this.apiClient.listUsers();
        this.mergeUsersIntoPrincipalDirectory(userList);
        this.auditUserEmailsLoaded = true;
      } catch {
        // Non-critical — fall back to showing userId
      }
    }

    const container = this.contentContainer.createDiv({ cls: "vaultguard-audit-tab" });
    const auditVault = await this.loadAuditVaultRecord();
    this.renderAuditVaultContext(container, auditVault);

    // Filters toolbar
    const toolbar = container.createDiv({ cls: "vaultguard-toolbar vaultguard-audit-filters" });

    // Search input
    const searchInput = new TextComponent(toolbar)
      .setPlaceholder("Search by user, path, IP, or action...");
    searchInput.inputEl.addClass("vaultguard-search-input");
    searchInput.setValue(this.auditFilters.search || "");

    // Action filter dropdown. Drop billing.* options when the backend doesn't
    // expose the billing surface (Community Edition).
    const actionFilter = new DropdownComponent(toolbar);
    const billingEnabled = this.context.features?.billing ?? true;
    for (const option of AUDIT_ACTION_OPTIONS) {
      if (!billingEnabled && option.value.startsWith("billing.")) continue;
      actionFilter.addOption(option.value, option.label);
    }
    actionFilter.setValue(this.auditFilters.action || "all");

    // Date range filter
    const dateFromInput = new TextComponent(toolbar)
      .setPlaceholder("From (YYYY-MM-DD)");
    dateFromInput.inputEl.type = "date";
    dateFromInput.inputEl.addClass("vaultguard-date-input");
    dateFromInput.setValue(this.auditFilters.dateFrom || "");

    const dateToInput = new TextComponent(toolbar)
      .setPlaceholder("To (YYYY-MM-DD)");
    dateToInput.inputEl.type = "date";
    dateToInput.inputEl.addClass("vaultguard-date-input");
    dateToInput.setValue(this.auditFilters.dateTo || "");

    // Apply filters button
    new ButtonComponent(toolbar)
      .setButtonText("Apply Filters")
      .onClick(async () => {
        this.auditFilters = {
          search: searchInput.getValue(),
          action: actionFilter.getValue(),
          dateFrom: dateFromInput.getValue(),
          dateTo: dateToInput.getValue(),
        };
        await this.fetchAndRenderAuditLog(logContainer, this.auditFilters, false, auditVault);
      });

    // Export CSV — Pro-only ("advanced" audit). On Community Edition the
    // button is still visible but opens a Pro-upsell modal on click so users
    // see the value of upgrading.
    const advancedAuditEnabled = this.context.features?.advancedAudit ?? true;
    new ButtonComponent(toolbar)
      .setButtonText("Export CSV")
      .onClick(() => {
        if (!advancedAuditEnabled) {
          new ProUpsellModal(this.app, "advancedAudit").open();
          return;
        }
        void this.exportAuditLog();
      });

    // Log entries container
    const logContainer = container.createDiv({ cls: "vaultguard-audit-log" });
    await this.fetchAndRenderAuditLog(logContainer, this.auditFilters, false, auditVault);
  }

  private readonly auditPageSize: number = 50;

  private async fetchAndRenderAuditLog(
    container: HTMLElement,
    filters: { search?: string; action?: string; dateFrom?: string; dateTo?: string },
    append: boolean = false,
    vaultRecord: VaultRecord | null = null
  ): Promise<void> {
    if (!append) {
      container.empty();
      this.auditCursor = null;
      this.auditHasMore = false;
      const loadingEl = container.createDiv({ cls: "vaultguard-loading" });
      loadingEl.createSpan({ text: "Loading audit log..." });
    }

    try {
      const response = await this.apiClient.getAuditLogPage({
        ...filters,
        cursor: append ? this.auditCursor : null,
        limit: this.auditPageSize,
      });
      const entries = response.entries ?? [];
      this.auditCursor = response.nextCursor ?? null;
      this.auditHasMore = Boolean(this.auditCursor);

      if (!append) {
        container.empty();
      } else {
        // Remove old pagination controls before appending
        container.querySelector(".vaultguard-pagination")?.remove();
      }

      if (!entries || entries.length === 0) {
        if (!append) {
          container.createDiv({
            cls: "vaultguard-empty-state",
            text: "No audit log entries match your filters.",
          });
        }
        return;
      }

      let list: HTMLElement;
      if (!append) {
        list = container.createDiv({ cls: "vaultguard-audit-entry-list" });
      } else {
        list = container.querySelector(".vaultguard-audit-entry-list") as HTMLElement;
        if (!list) {
          list = container.createDiv({ cls: "vaultguard-audit-entry-list" });
        }
      }

      for (const entry of entries) {
        this.renderAuditEntry(list, entry, vaultRecord);
      }

      if (this.auditHasMore) {
        const pagination = container.createDiv({ cls: "vaultguard-pagination" });
        const loadMoreBtn = new ButtonComponent(pagination);
        loadMoreBtn.setButtonText("Load More").onClick(async () => {
          loadMoreBtn.setDisabled(true);
          loadMoreBtn.setButtonText("Loading...");
          await this.fetchAndRenderAuditLog(container, filters, true, vaultRecord);
        });
      }
    } catch (error) {
      if (!append) {
        container.empty();
      }
      container.createDiv({
        cls: "vaultguard-error",
        text: `Failed to load audit log: ${errorMessage(error)}`,
      });
    }
  }

  private formatTimestamp(iso: string): string {
    const date = new Date(iso);
    return date.toLocaleString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  }

  private async loadAuditVaultRecord(): Promise<VaultRecord | null> {
    const vaultId = this.apiClient.getVaultId();
    if (!vaultId) {
      return null;
    }

    try {
      return await this.apiClient.getVaultRecord(vaultId);
    } catch {
      return null;
    }
  }

  private renderAuditVaultContext(container: HTMLElement, vaultRecord: VaultRecord | null): void {
    const vaultId = this.apiClient.getVaultId();
    if (!vaultId && !vaultRecord) {
      return;
    }

    const contextEl = container.createDiv({ cls: "vaultguard-audit-vault-context" });
    contextEl.createDiv({
      cls: "vaultguard-audit-vault-title",
      text: vaultRecord?.name ?? "Bound vault",
    });

    const details = [
      vaultRecord?.kind,
      vaultRecord?.slug,
      vaultRecord?.archived ? "archived" : vaultRecord ? "active" : null,
      vaultId,
    ].filter((value): value is string => Boolean(value));

    contextEl.createDiv({
      cls: "vaultguard-audit-vault-meta vaultguard-monospace",
      text: details.join(" | "),
    });
  }

  private renderAuditEntry(container: HTMLElement, entry: AuditLogEntry, vaultRecord: VaultRecord | null): void {
    const entryEl = container.createDiv({ cls: "vaultguard-audit-entry" });
    const header = entryEl.createDiv({ cls: "vaultguard-audit-entry-header" });
    const headerMain = header.createDiv({ cls: "vaultguard-audit-entry-main" });

    const actionBadge = headerMain.createSpan({ cls: "vaultguard-action-badge" });
    actionBadge.setText(entry.action);
    actionBadge.addClass(`vaultguard-action-${entry.action.replace(/[^a-z0-9]+/gi, "_")}`);

    const outcomeBadge = headerMain.createSpan({
      cls: `vaultguard-audit-outcome vaultguard-audit-outcome-${entry.outcome}`,
      text: entry.outcome,
    });
    outcomeBadge.setAttr("aria-label", `Outcome: ${entry.outcome}`);

    header.createDiv({
      cls: "vaultguard-audit-entry-time",
      text: this.formatTimestamp(entry.timestamp),
    });

    const detailsGrid = entryEl.createDiv({ cls: "vaultguard-audit-detail-grid" });
    this.addAuditDetail(detailsGrid, "Vault", this.formatAuditVault(entry, vaultRecord), true);
    this.addAuditDetail(detailsGrid, "User", entry.userEmail ?? this.userEmailMap.get(entry.userId) ?? entry.userId);
    this.addAuditDetail(detailsGrid, "User ID", entry.userId, true);
    this.addAuditDetail(detailsGrid, "Resource", entry.resourcePath || "-", true);
    this.addAuditDetail(detailsGrid, "IP Address", entry.ipAddress || "-");
    this.addAuditDetail(detailsGrid, "Device", entry.userAgent || "-");

    if (entry.orgId) {
      this.addAuditDetail(detailsGrid, "Organization", entry.orgId, true);
    }
    if (entry.id) {
      this.addAuditDetail(detailsGrid, "Event ID", entry.id, true);
    }

    if (entry.metadata && Object.keys(entry.metadata).length > 0) {
      const metadataEl = entryEl.createDiv({ cls: "vaultguard-audit-metadata" });
      metadataEl.createDiv({ cls: "vaultguard-audit-metadata-label", text: "Metadata" });
      metadataEl.createEl("pre", {
        cls: "vaultguard-audit-json",
        text: this.formatAuditJson(entry.metadata),
      });
    }

    const rawDetails = entryEl.createEl("details", { cls: "vaultguard-audit-raw" });
    rawDetails.createEl("summary", { text: "Raw event data" });
    rawDetails.createEl("pre", {
      cls: "vaultguard-audit-json",
      text: this.formatAuditJson(entry),
    });
  }

  private addAuditDetail(container: HTMLElement, label: string, value: unknown, monospace: boolean = false): void {
    const item = container.createDiv({ cls: "vaultguard-audit-detail" });
    item.createDiv({ cls: "vaultguard-audit-detail-label", text: label });
    const valueEl = item.createDiv({ cls: "vaultguard-audit-detail-value" });
    if (monospace) {
      valueEl.addClass("vaultguard-monospace");
    }
    valueEl.setText(this.formatAuditValue(value));
  }

  private formatAuditVault(entry: AuditLogEntry, vaultRecord: VaultRecord | null): string {
    const vaultId = entry.vaultId ?? this.apiClient.getVaultId();
    if (!vaultId) {
      return "-";
    }
    if (vaultRecord && vaultRecord.vaultId === vaultId) {
      return `${vaultRecord.name} (${vaultRecord.slug}) | ${vaultId}`;
    }
    return vaultId;
  }

  private formatAuditValue(value: unknown): string {
    if (value === null || value === undefined || value === "") {
      return "-";
    }
    if (typeof value === "string") {
      return value;
    }
    if (typeof value === "number" || typeof value === "boolean") {
      return String(value);
    }
    return this.formatAuditJson(value);
  }

  private formatAuditJson(value: unknown): string {
    try {
      const serialized = JSON.stringify(value, null, 2);
      return typeof serialized === "string" ? serialized : String(value);
    } catch {
      return String(value);
    }
  }

  private async exportAuditLog(): Promise<void> {
    try {
      const csvBlob = await this.apiClient.exportAuditLogCsv(this.auditFilters);
      const url = URL.createObjectURL(csvBlob);
      const doc = typeof activeDocument === "undefined" ? this.contentEl.ownerDocument : activeDocument;
      const a = doc.createElement("a");
      a.href = url;
      a.download = `vaultguard-audit-log-${new Date().toISOString().split("T")[0]}.csv`;
      a.click();
      URL.revokeObjectURL(url);
      new Notice("Audit log exported.");
    } catch (error) {
      new Notice(`Export failed: ${errorMessage(error)}`);
    }
  }

  // ─── Settings Tab ────────────────────────────────────────────────────

  // ─── Recovery Tab ──────────────────────────────────────────────────

  private async renderRecoveryTab(): Promise<void> {
    const container = this.contentContainer.createDiv({ cls: "vaultguard-recovery-tab" });

    container.createEl("h3", { text: "Key Recovery & Re-encryption" });
    container.createEl("p", {
      text: "Manage encryption key recovery for offboarded users and trigger re-encryption of affected files.",
      cls: "setting-item-description",
    });

    // ── Re-encryption trigger ─────────────────────────────
    container.createEl("h4", { text: "Re-encrypt Files After Offboarding" });
    container.createEl("p", {
      text: "After revoking a user, re-encrypt all files they had access to with new keys. " +
        "This ensures the revoked user's old key material cannot decrypt any retained copies. " +
        "Re-encryption runs automatically on revocation, but you can trigger it manually here.",
      cls: "setting-item-description",
    });

    let targetUserId = "";
    new Setting(container)
      .setName("Target User ID")
      .setDesc("The user ID of the revoked user whose files need re-encryption")
      .addText((text) => {
        text
          .setPlaceholder("user-id-here")
          .onChange((value) => {
            targetUserId = value;
          });
      });

    new Setting(container)
      .setName("Start Re-encryption")
      .setDesc("This will decrypt and re-encrypt all files the user had access to. May take several minutes for large vaults.")
      .addButton((btn) =>
        btn
          .setButtonText("Trigger Re-encryption")
          .setWarning()
          .onClick(async () => {
            const userId = targetUserId.trim();
            if (!userId) {
              new Notice("Please enter a target user ID.");
              return;
            }

            const confirmed = await this.showConfirmDialog(
              "Confirm Re-encryption",
              `This will re-encrypt all files that user "${userId}" had access to. ` +
              `The process cannot be interrupted once started. Proceed?`
            );

            if (!confirmed) return;

            try {
              btn.setDisabled(true);
              btn.setButtonText("Starting...");
              const data = await this.apiClient.triggerReEncryption(userId);
              new Notice(`Re-encryption job started: ${data.jobId || "unknown"}`);

              // Show job status section
              if (data.jobId) {
                await this.renderJobStatus(container, data.jobId);
              }
            } catch (error) {
              new Notice(`Failed to start re-encryption: ${errorMessage(error)}`);
            } finally {
              btn.setDisabled(false);
              btn.setButtonText("Trigger Re-encryption");
            }
          })
      );

    // ── Job status check ─────────────────────────────────
    container.createEl("h4", { text: "Check Job Status" });

    let jobIdValue = "";
    new Setting(container)
      .setName("Job ID")
      .setDesc("Enter a re-encryption job ID to check its progress")
      .addText((text) => {
        text
          .setPlaceholder("job-id-here")
          .onChange((value) => {
            jobIdValue = value;
          });
      })
      .addButton((btn) =>
        btn.setButtonText("Check Status").onClick(async () => {
          const jobId = jobIdValue.trim();
          if (!jobId) {
            new Notice("Please enter a job ID.");
            return;
          }
          await this.renderJobStatus(container, jobId);
        })
      );

    // ── Key Recovery (ZK mode) ───────────────────────────
    container.createEl("h4", { text: "Emergency Key Recovery" });
    container.createEl("p", {
      text: "For organizations using end-to-end encryption (hybrid ZK mode): recover a user's " +
        "encrypted master key using the organization recovery key. This is a sensitive operation " +
        "and is fully audit-logged.",
      cls: "setting-item-description",
    });

    const zkWarning = container.createDiv({ cls: "vaultguard-zk-warning" });
    zkWarning.createEl("strong", { text: "When to use this:" });
    zkWarning.appendText(
      " Only when a user has lost their encryption passphrase and cannot access their vault. " +
        "The recovered key allows you to re-encrypt the user's files so they can set a new passphrase. " +
        "This action is logged and visible in the audit trail."
    );

    let recoveryUserId = "";
    new Setting(container)
      .setName("Recover User's Key")
      .setDesc("Enter the user ID to recover their wrapped master key")
      .addText((text) => {
        text
          .setPlaceholder("user-id-here")
          .onChange((value) => {
            recoveryUserId = value;
          });
      })
      .addButton((btn) =>
        btn
          .setButtonText("Initiate Recovery")
          .setWarning()
          .onClick(async () => {
            const userId = recoveryUserId.trim();
            if (!userId) {
              new Notice("Please enter a user ID.");
              return;
            }

            const confirmed = await this.showConfirmDialog(
              "Confirm Key Recovery",
              `You are about to recover the encryption master key for user "${userId}". ` +
              `This action is irreversible, fully audit-logged, and should only be performed ` +
              `when the user has lost their passphrase. Continue?`
            );

            if (!confirmed) return;

            try {
              const data = await this.apiClient.recoverUserKey(userId);

              if (data.wrappedUMK_org) {
                const wrappedKey = data.wrappedUMK_org;
                new Notice("Recovery key retrieved.");
                const resultEl = container.createDiv({ cls: "vaultguard-recovery-result" });
                resultEl.createEl("h4", { text: "Recovery Result" });
                resultEl.createEl("p", {
                  text: data.message || "Unwrap this key with the organization recovery private key.",
                });
                const keyOutput = resultEl.createEl("textarea", {
                  cls: "vaultguard-recovery-key-output",
                  attr: {
                    readonly: "true",
                    "aria-label": "Wrapped user master key",
                  },
                });
                keyOutput.value = wrappedKey;
                keyOutput.rows = 4;
                const actionsEl = resultEl.createDiv({ cls: "vaultguard-recovery-actions" });
                new ButtonComponent(actionsEl)
                  .setButtonText("Copy wrapped key")
                  .onClick(async () => {
                    try {
                      await navigator.clipboard.writeText(wrappedKey);
                      new Notice("Wrapped key copied.");
                    } catch {
                      keyOutput.select();
                      new Notice("Select and copy the wrapped key manually.");
                    }
                  });
                resultEl.createEl("p", {
                  text: "Handle this wrapped key as sensitive recovery material. This action is audit-logged.",
                  cls: "setting-item-description",
                });
              }
            } catch (error) {
              new Notice(`Recovery failed: ${errorMessage(error)}`);
            }
          })
      );
  }

  private async renderJobStatus(container: HTMLElement, jobId: string): Promise<void> {
    // Remove any existing status display
    const existing = container.querySelector(".vaultguard-job-status");
    if (existing) existing.remove();

    const statusEl = container.createDiv({ cls: "vaultguard-job-status" });
    statusEl.createEl("h4", { text: `Job: ${jobId}` });

    try {
      const data = await this.apiClient.getReEncryptionJobStatus(jobId);
      const job = data.job;

      if (!job) {
        statusEl.createEl("p", { text: "Job not found.", cls: "vaultguard-error" });
        return;
      }

      const status = job.status;
      const processed = job.processedFiles ?? 0;
      const total = job.totalFiles ?? 0;
      const failed = job.failedFiles ?? 0;

      statusEl.createSpan({
        text: status.toUpperCase(),
        cls: `vaultguard-badge vaultguard-badge-${status === "completed" ? "success" : status === "failed" ? "error" : "warning"}`,
      });

      statusEl.createEl("p", {
        text: `Progress: ${processed} / ${total} files re-encrypted${failed > 0 ? ` (${failed} failed)` : ""}`,
      });

      if (job.startedAt) {
        statusEl.createEl("p", {
          text: `Started: ${new Date(job.startedAt).toLocaleString()}`,
          cls: "setting-item-description",
        });
      }
      if (job.completedAt) {
        statusEl.createEl("p", {
          text: `Completed: ${new Date(job.completedAt).toLocaleString()}`,
          cls: "setting-item-description",
        });
      }

      const errors = job.errors ?? [];
      if (errors.length > 0) {
        const errSection = statusEl.createDiv({ cls: "vaultguard-job-errors" });
        errSection.createEl("strong", { text: `Errors (${errors.length}):` });
        for (const err of errors.slice(0, 5)) {
          errSection.createEl("p", { text: err, cls: "vaultguard-error-line" });
        }
        if (errors.length > 5) {
          errSection.createEl("p", {
            text: `...and ${errors.length - 5} more`,
            cls: "setting-item-description",
          });
        }
      }
    } catch (error) {
      statusEl.createEl("p", {
        text: `Failed to fetch status: ${errorMessage(error)}`,
        cls: "vaultguard-error",
      });
    }
  }

  private async renderSettingsTab(): Promise<void> {
    const container = this.contentContainer.createDiv({ cls: "vaultguard-settings-tab" });

    const loadingEl = container.createDiv({ cls: "vaultguard-loading" });
    loadingEl.createSpan({ text: "Loading settings..." });

    try {
      const settings = await this.apiClient.getOrgSettings();
      container.empty();

      this.renderOrgSettings(container, settings as OrgSettings);
    } catch (error) {
      container.empty();
      if (shouldUseFallbackOrgSettings(error)) {
        container.createDiv({
          cls: "vaultguard-warning",
          text:
            "This backend cannot serve organization settings right now. Showing VaultGuard default settings in read-only mode.",
        });
        this.renderOrgSettings(
          container,
          buildFallbackOrgSettings(
            this.context.orgId ?? "",
            this.context.orgSlug
          ),
          { readOnly: true }
        );
        return;
      }

      container.createDiv({
        cls: "vaultguard-error",
        text: `Failed to load settings: ${errorMessage(error)}`,
      });
    }
  }

  private renderOrgSettings(
    container: HTMLElement,
    settings: OrgSettings,
    options: { readOnly?: boolean } = {}
  ): void {
    const readOnly = options.readOnly ?? false;
    const draft: OrgSettings = {
      ...settings,
      allowedDomains: [...(settings.allowedDomains ?? [])],
      enforceEncryption: true,
    };
    let orgNameValue = settings.orgName;
    let syncIntervalValue = String(settings.syncIntervalMinutes);
    let maxSessionValue = String(settings.maxSessionDurationHours);
    let autoLockValue = String(settings.autoLockMinutes);
    let allowedDomainsValue = (settings.allowedDomains ?? []).join("\n");
    let retentionValue = String(settings.retentionDays);

    const parsePositiveInteger = (label: string, value: string): number => {
      const parsed = Number.parseInt(value, 10);
      if (!Number.isInteger(parsed) || parsed <= 0) {
        throw new Error(`${label} must be a whole number greater than 0.`);
      }
      return parsed;
    };

    const parseNonNegativeInteger = (label: string, value: string): number => {
      const parsed = Number.parseInt(value, 10);
      if (!Number.isInteger(parsed) || parsed < 0) {
        throw new Error(`${label} must be a whole number 0 or greater.`);
      }
      return parsed;
    };

    const normalizeDomains = (value: string): string[] => {
      return Array.from(
        new Set(
          value
            .split(/[\n,]/)
            .map((domain) => domain.trim().toLowerCase())
            .filter((domain) => domain.length > 0)
        )
      );
    };

    const buildPayload = (): OrgSettings => {
      const orgName = orgNameValue.trim();
      if (!orgName) {
        throw new Error("Organization name is required.");
      }

      return {
        ...draft,
        orgName,
        syncIntervalMinutes: parsePositiveInteger("Sync interval", syncIntervalValue),
        enforceEncryption: true,
        maxSessionDurationHours: parsePositiveInteger("Max session duration", maxSessionValue),
        allowedDomains: normalizeDomains(allowedDomainsValue),
        retentionDays: parsePositiveInteger("Audit log retention", retentionValue),
        autoLockMinutes: parseNonNegativeInteger("Auto-lock", autoLockValue),
      };
    };

    container.createDiv({
      cls: "vaultguard-info-callout",
      text:
        "These are organization policies served by the VaultGuard backend. Password policy, key-lease duration, billing, and infrastructure remain deployment-managed.",
    });

    // Organization section
    container.createEl("h3", { text: "Organization" });

    new Setting(container)
      .setName("Organization Name")
      .setDesc("Display name for your organization")
      .addText((text) =>
        text
          .setValue(settings.orgName)
          .setDisabled(readOnly)
          .onChange((value) => {
            orgNameValue = value;
          })
      );

    new Setting(container)
      .setName("Organization ID")
      .setDesc("Unique identifier (read-only)")
      .addText((text) => text.setValue(settings.orgId).setDisabled(true));

    // Sync configuration section
    container.createEl("h3", { text: "Sync Configuration" });

    new Setting(container)
      .setName("Sync Mode")
      .setDesc("How vault data is synchronized with the backend")
      .addDropdown((dropdown) =>
        dropdown
          .addOption("realtime", "Real-time")
          .addOption("periodic", "Periodic")
          .addOption("manual", "Manual")
          .setValue(settings.syncMode)
          .setDisabled(readOnly)
          .onChange((value) => {
            draft.syncMode = value as OrgSettings["syncMode"];
          })
      );

    const syncIntervalSetting = new Setting(container)
      .setName("Sync Interval (minutes)")
      .setDesc("How often to sync (only applies to periodic mode)")
      .addText((text) => {
        text.inputEl.type = "number";
        text.inputEl.min = "1";
        text.inputEl.step = "1";
        text
          .setValue(String(settings.syncIntervalMinutes))
          .setPlaceholder("15")
          .setDisabled(readOnly)
          .onChange((value) => {
            syncIntervalValue = value;
          });
      });
    syncIntervalSetting.settingEl.addClass("vaultguard-number-setting");

    // Security policies section
    container.createEl("h3", { text: "Security Policies" });

    new Setting(container)
      .setName("Enforce Encryption")
      .setDesc("VaultGuard always encrypts vault data at rest. This policy is always enabled.")
      .addToggle((toggle) =>
        toggle
          .setValue(settings.enforceEncryption)
          .setDisabled(true)
          .onChange((value) => {
            draft.enforceEncryption = value;
          })
      );

    new Setting(container)
      .setName("Require MFA")
      .setDesc("Require multi-factor authentication for all users")
      .addToggle((toggle) =>
        toggle
          .setValue(settings.requireMfa)
          .setDisabled(readOnly)
          .onChange((value) => {
            draft.requireMfa = value;
          })
      );

    const maxSessionSetting = new Setting(container)
      .setName("Max Session Duration (hours)")
      .setDesc("Force re-authentication after this many hours")
      .addText((text) => {
        text.inputEl.type = "number";
        text.inputEl.min = "1";
        text.inputEl.step = "1";
        text
          .setValue(String(settings.maxSessionDurationHours))
          .setDisabled(readOnly)
          .onChange((value) => {
            maxSessionValue = value;
          });
      });
    maxSessionSetting.settingEl.addClass("vaultguard-number-setting");

    const autoLockSetting = new Setting(container)
      .setName("Auto-Lock (minutes)")
      .setDesc("Lock vault after this many minutes of inactivity (0 = disabled)")
      .addText((text) => {
        text.inputEl.type = "number";
        text.inputEl.min = "0";
        text.inputEl.step = "1";
        text
          .setValue(String(settings.autoLockMinutes))
          .setDisabled(readOnly)
          .onChange((value) => {
            autoLockValue = value;
          });
      });
    autoLockSetting.settingEl.addClass("vaultguard-number-setting");

    const allowedDomainsSetting = new Setting(container)
      .setName("Allowed Email Domains")
      .setDesc("Domains allowed for user invites. Leave blank to allow any domain.")
      .addTextArea((text) => {
        text.inputEl.rows = 3;
        text
          .setValue(allowedDomainsValue)
          .setPlaceholder("company.com\nsubsidiary.com")
          .setDisabled(readOnly)
          .onChange((value) => {
            allowedDomainsValue = value;
          });
      });
    allowedDomainsSetting.settingEl.addClass("vaultguard-admin-textarea-setting");

    const retentionSetting = new Setting(container)
      .setName("Audit Log Retention (days)")
      .setDesc("How long to retain audit log entries")
      .addText((text) => {
        text.inputEl.type = "number";
        text.inputEl.min = "1";
        text.inputEl.step = "1";
        text
          .setValue(String(settings.retentionDays))
          .setDisabled(readOnly)
          .onChange((value) => {
            retentionValue = value;
          });
      });
    retentionSetting.settingEl.addClass("vaultguard-number-setting");

    container.createEl("h3", { text: "Deployment-managed controls" });
    new Setting(container)
      .setName("Password policy")
      .setDesc("Managed by the Cognito user-pool configuration for this deployment.");
    new Setting(container)
      .setName("Key lease duration")
      .setDesc("Managed by backend deployment configuration and refreshed through key-lease APIs.");
    new Setting(container)
      .setName("Infrastructure and billing")
      .setDesc("Managed outside the plugin. Hosted SaaS billing belongs in the web admin panel.");

    if (readOnly) {
      new Setting(container).addButton((btn) =>
        btn.setButtonText("Retry Load").onClick(() => {
          this.renderActiveTab();
        })
      );
      return;
    }

    // Save button
    container.createDiv({ cls: "vaultguard-settings-actions" });
    new Setting(container)
      .addButton((btn) => {
        btn
          .setButtonText("Save Settings")
          .setCta()
          .onClick(async () => {
            try {
              const payload = buildPayload();
              btn.setDisabled(true);
              btn.setButtonText("Saving...");
              await this.apiClient.updateOrgSettings(payload);
              new Notice("Organization settings saved.");
              this.renderActiveTab();
            } catch (error) {
              new Notice(`Failed to save: ${errorMessage(error)}`);
            } finally {
              btn.setDisabled(false);
              btn.setButtonText("Save Settings");
            }
          });
      })
      .addButton((btn) => {
        btn.setButtonText("Reset to Defaults").onClick(async () => {
          const confirmed = await this.showConfirmDialog(
            "Reset Settings",
            "Are you sure you want to reset all settings to their defaults? This cannot be undone."
          );
          if (confirmed) {
            try {
              btn.setDisabled(true);
              btn.setButtonText("Resetting...");
              await this.apiClient.resetOrgSettings();
              new Notice("Settings reset to defaults.");
              this.renderActiveTab();
            } catch (error) {
              new Notice(`Failed to reset: ${errorMessage(error)}`);
            } finally {
              btn.setDisabled(false);
              btn.setButtonText("Reset to Defaults");
            }
          }
        });
      });
  }

  // ─── Utilities ───────────────────────────────────────────────────────

  private showConfirmDialog(title: string, message: string): Promise<boolean> {
    return new Promise((resolve) => {
      const modal = new ConfirmModal(this.app, title, message, resolve);
      modal.open();
    });
  }
}

/**
 * Simple confirmation modal using Obsidian's native Modal class.
 */
class ConfirmModal extends Modal {
  private title: string;
  private message: string;
  private resolvePromise: (value: boolean) => void;
  private resolved: boolean = false;

  constructor(app: App, title: string, message: string, resolve: (value: boolean) => void) {
    super(app);
    this.title = title;
    this.message = message;
    this.resolvePromise = resolve;
  }

  onOpen(): void {
    const { contentEl } = this;
    contentEl.empty();
    this.modalEl.addClass("vaultguard-dialog-modal");
    contentEl.addClass("vaultguard-dialog-content");
    contentEl.createEl("h3", { text: this.title });
    contentEl.createEl("p", { text: this.message });

    const buttonRow = contentEl.createDiv({ cls: "vaultguard-confirm-buttons" });
    new ButtonComponent(buttonRow)
      .setButtonText("Cancel")
      .onClick(() => {
        this.finish(false);
      });
    new ButtonComponent(buttonRow)
      .setButtonText("Confirm")
      .setCta()
      .setWarning()
      .onClick(() => {
        this.finish(true);
      });
  }

  onClose(): void {
    this.modalEl.removeClass("vaultguard-dialog-modal");
    this.contentEl.removeClass("vaultguard-dialog-content");
    this.contentEl.empty();
    if (!this.resolved) {
      this.resolved = true;
      this.resolvePromise(false);
    }
  }

  private finish(value: boolean): void {
    if (this.resolved) return;
    this.resolved = true;
    this.resolvePromise(value);
    this.close();
  }
}
