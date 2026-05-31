/**
 * File Permission Panel — dropdown panel anchored below the file header
 * for viewing and managing per-file permissions (ClickUp-style).
 *
 * Admin users see full CRUD controls; non-admins see a read-only summary.
 */

import { App, TFile, Notice, setIcon } from "obsidian";
import {
  VaultGuardApiClient,
  PermissionRule,
  PermissionMutationInput,
  UserListEntry,
} from "../api/client";
import { setButtonLoading, setControlBusy } from "./loading-button";
import {
  buildAccessUserMap,
  findExactAccessUserMatch,
  formatAccessUserRole,
  formatAccessUserStatus,
  getAccessUserDisplayName,
  getAccessUserInitials,
  getAccessUserNameInitials,
  getAccessUserMeta,
  getAccessUserPickerValue,
  matchesAccessUserQuery,
  resolveAccessUserId,
  sortAccessUsers,
} from "./access-user-utils";

export interface FilePermissionPanelConfig {
  app: App;
  apiClient: VaultGuardApiClient;
  file: TFile;
  rules: PermissionRule[];
  effectivePrincipals?: EffectiveAccessPrincipal[];
  effectiveAccessAvailable?: boolean;
  canManageAccess?: boolean;
  isAdmin: boolean;
  currentUserId: string;
  currentUserEmail?: string;
  /** See FilePermissionHeader.HeaderContext.allowAdminPerFileRestrictions. */
  allowAdminPerFileRestrictions?: boolean;
  anchorEl: HTMLElement;
  initialUsers?: UserListEntry[];
  onRulesChanged: () => Promise<void>;
  onClose: () => void;
}

const PANEL_CLS = "vaultguard-fp-panel";

export interface EffectiveAccessPrincipal {
  id: string;
  email?: string;
  label: string;
  level: "unknown" | "none" | "read" | "write" | "admin";
  type: "user" | "role";
  /**
   * The principal's vault membership role, when known. Used to hide the
   * level dropdown for vault admins/owners — their access is governed by
   * their vault role and bypasses per-file rules server-side, so editing a
   * per-file level for them is a no-op that confuses the user. The backend
   * also rejects such requests with a 400; this field lets the UI avoid
   * even attempting them.
   */
  vaultRole?: "admin" | "editor" | "viewer";
}

export class FilePermissionPanel {
  private cfg: FilePermissionPanelConfig;
  private panelEl: HTMLElement;
  private backdropEl: HTMLElement;
  private rules: PermissionRule[];
  private effectivePrincipals: EffectiveAccessPrincipal[] = [];
  private effectiveAccessAvailable = false;
  private users: UserListEntry[] = [];
  private userMap: Map<string, UserListEntry> = new Map();
  private usersLoading = false;
  private usersLoadError: string | null = null;
  private draftPrincipalType: "user" | "role" = "user";
  private draftPrincipalValue = "";
  private draftSelectedUserId: string | null = null;
  private draftLevel = "write";
  private isDestroyed = false;
  private readonly handleViewportChange = () => this.positionPanel();
  private readonly handleKeyDown = (event: KeyboardEvent) => {
    if (event.key === "Escape") {
      this.destroy();
    }
  };

  constructor(cfg: FilePermissionPanelConfig) {
    this.cfg = cfg;
    this.rules = [...cfg.rules];
    this.users = sortAccessUsers(cfg.initialUsers ?? []);
    this.userMap = buildAccessUserMap(this.users);
    this.effectivePrincipals = this.normalizeEffectivePrincipals(cfg.effectivePrincipals ?? []);
    this.effectiveAccessAvailable = cfg.effectiveAccessAvailable === true;
    this.mergeEffectivePrincipalsIntoDirectory();
    this.usersLoading = cfg.isAdmin;

    // Floating backdrop keeps outside-click handling simple while the panel
    // itself is rendered above it in the document body.
    this.backdropEl = document.body.createDiv({ cls: "vaultguard-fp-backdrop" });
    this.backdropEl.addEventListener("click", () => this.destroy());

    // Render the panel into the body so it is not trapped inside the header's
    // stacking context. This keeps the menu clickable.
    this.panelEl = document.body.createDiv({ cls: PANEL_CLS });
    this.render();
    this.positionPanel();

    window.addEventListener("resize", this.handleViewportChange);
    window.addEventListener("scroll", this.handleViewportChange, true);
    document.addEventListener("keydown", this.handleKeyDown);

    if (this.cfg.isAdmin) {
      void this.loadUsers();
    }
  }

  destroy(): void {
    if (this.isDestroyed) return;
    this.isDestroyed = true;

    window.removeEventListener("resize", this.handleViewportChange);
    window.removeEventListener("scroll", this.handleViewportChange, true);
    document.removeEventListener("keydown", this.handleKeyDown);

    this.panelEl.remove();
    this.backdropEl.remove();
    this.cfg.onClose();
  }

  setRules(rules: PermissionRule[]): void {
    this.setData(rules);
  }

  setData(
    rules: PermissionRule[],
    effectivePrincipals = this.effectivePrincipals,
    effectiveAccessAvailable = this.effectiveAccessAvailable
  ): void {
    this.rules = [...rules];
    this.effectivePrincipals = this.normalizeEffectivePrincipals(effectivePrincipals);
    this.effectiveAccessAvailable = effectiveAccessAvailable;
    this.mergeEffectivePrincipalsIntoDirectory();
    // Post-write read consistency — see reconcilePendingLevelPatches() for
    // the GSI-lag rationale. Without this, a refresh that lands while the
    // server's read view is still stale would overwrite the chip with the
    // pre-write level.
    this.reconcilePendingLevelPatches();
    this.render();
    this.positionPanel();
  }

  // ─── Rendering ─────────────────────────────────────────────────────

  private render(): void {
    this.panelEl.empty();

    // Panel header
    const header = this.panelEl.createDiv({ cls: "vaultguard-fp-header" });
    header.createEl("h4", {
      text: this.canManageAccess() ? "Manage Access" : "Who Has Access",
    });
    const closeBtn = header.createEl("button", {
      cls: "vaultguard-icon-btn",
      attr: { type: "button" },
    });
    setIcon(closeBtn, "x");
    closeBtn.addEventListener("click", () => this.destroy());

    // File path context
    this.panelEl.createDiv({
      cls: "vaultguard-fp-filepath",
      text: this.cfg.file.path,
    });

    // Divider
    this.panelEl.createEl("hr", { cls: "vaultguard-fp-divider" });

    // Rules list
    const listEl = this.panelEl.createDiv({ cls: "vaultguard-fp-list" });
    this.renderRuleList(listEl);

    if (this.canManageAccess()) {
      this.panelEl.createEl("hr", { cls: "vaultguard-fp-divider" });
      this.renderAddRuleSection(this.panelEl);
    }
  }

  private renderRuleList(container: HTMLElement): void {
    if (this.effectiveAccessAvailable) {
      this.renderEffectiveAccessList(container);
      return;
    }

    if (this.rules.length === 0) {
      container.createDiv({
        cls: "vaultguard-fp-empty",
        text: "No permission rules for this file. Access is based on default role permissions.",
      });
      return;
    }

    // Sort: admins first, then by principal
    const sorted = this.rawRulesForDisplay().sort((a, b) => {
      const la = this.ruleLevelRank(a);
      const lb = this.ruleLevelRank(b);
      if (la !== lb) return lb - la;
      return this.principalLabel(a).localeCompare(this.principalLabel(b));
    });

    for (const rule of sorted) {
      this.renderRuleRow(container, rule);
    }
  }

  private renderEffectiveAccessList(container: HTMLElement): void {
    if (this.effectivePrincipals.length === 0) {
      container.createDiv({
        cls: "vaultguard-fp-empty",
        text: "No visible access for this file.",
      });
      return;
    }

    for (const principal of this.effectivePrincipals) {
      this.renderEffectiveAccessRow(container, principal);
    }
  }

  private renderEffectiveAccessRow(container: HTMLElement, principal: EffectiveAccessPrincipal): void {
    const row = container.createDiv({ cls: "vaultguard-fp-row vaultguard-fp-row-effective" });

    const avatarEl = row.createDiv({ cls: "vaultguard-fp-row-avatar" });
    if (principal.type === "role") {
      setIcon(avatarEl, "users");
    } else if (principal.id === "*") {
      setIcon(avatarEl, "globe");
    } else {
      avatarEl.createSpan({
        cls: "vaultguard-fp-row-initials",
        text: this.effectivePrincipalInitials(principal),
      });
    }

    const infoEl = row.createDiv({ cls: "vaultguard-fp-row-info" });
    infoEl.createDiv({
      cls: "vaultguard-fp-row-name",
      text: principal.label,
    });

    infoEl.createDiv({
      cls: "vaultguard-fp-row-meta",
      text: principal.email || "Effective access",
    });

    const levelEl = row.createDiv({ cls: "vaultguard-fp-row-level" });
    if (this.canEditEffectivePrincipal(principal)) {
      const select = levelEl.createEl("select", { cls: "vaultguard-fp-level-select" });
      const options: { value: string; label: string }[] = [
        { value: "admin", label: "Admin" },
        { value: "write", label: "Write" },
        { value: "read", label: "Read" },
        { value: "none", label: "No Access" },
      ];
      for (const opt of options) {
        const optEl = select.createEl("option", { text: opt.label, attr: { value: opt.value } });
        if (opt.value === principal.level) {
          optEl.selected = true;
        }
      }
      select.addEventListener("change", async () => {
        setControlBusy(select, true);
        try {
          await this.handleEffectivePrincipalLevelChange(principal, select.value);
        } finally {
          if (!this.isDestroyed) setControlBusy(select, false);
        }
      });
      return;
    }

    const badge = levelEl.createSpan({
      cls: `vaultguard-fh-badge vaultguard-fh-badge-${principal.level}`,
    });
    badge.setText(this.formatLevel(principal.level));
  }

  private renderRuleRow(container: HTMLElement, rule: PermissionRule): void {
    const row = container.createDiv({ cls: "vaultguard-fp-row" });

    // Avatar / icon
    const avatarEl = row.createDiv({ cls: "vaultguard-fp-row-avatar" });
    if (rule.role) {
      setIcon(avatarEl, "users");
    } else if (rule.userId === "*") {
      setIcon(avatarEl, "globe");
    } else {
      avatarEl.createSpan({
        cls: "vaultguard-fp-row-initials",
        text: this.userInitials(rule.userId),
      });
    }

    // Name + info
    const infoEl = row.createDiv({ cls: "vaultguard-fp-row-info" });
    infoEl.createDiv({
      cls: "vaultguard-fp-row-name",
      text: this.principalLabel(rule),
    });

    const meta: string[] = [];
    if (rule.effect === "deny") meta.push("Denied");
    meta.push(rule.pathPattern);
    infoEl.createDiv({
      cls: "vaultguard-fp-row-meta",
      text: meta.join(" - "),
    });

    // Level badge or dropdown
    const levelEl = row.createDiv({ cls: "vaultguard-fp-row-level" });

    if (this.canManageAccess()) {
      const select = levelEl.createEl("select", { cls: "vaultguard-fp-level-select" });
      const options: { value: string; label: string }[] = [
        { value: "admin", label: "Admin" },
        { value: "write", label: "Write" },
        { value: "read", label: "Read" },
        { value: "none", label: "No Access" },
      ];
      for (const opt of options) {
        const optEl = select.createEl("option", { text: opt.label, attr: { value: opt.value } });
        if (opt.value === this.displayLevelForRule(rule)) {
          optEl.selected = true;
        }
      }
      select.addEventListener("change", async () => {
        setControlBusy(select, true);
        try {
          await this.handleLevelChange(rule, select.value);
        } finally {
          if (!this.isDestroyed) setControlBusy(select, false);
        }
      });

      // Delete button
      const deleteBtn = levelEl.createEl("button", {
        cls: "vaultguard-icon-btn vaultguard-danger",
        attr: { "aria-label": "Remove rule", type: "button" },
      });
      setIcon(deleteBtn, "trash-2");
      deleteBtn.addEventListener("click", async () => {
        setButtonLoading(deleteBtn, true);
        try {
          await this.handleDeleteRule(rule);
        } finally {
          if (!this.isDestroyed && deleteBtn.isConnected) {
            setButtonLoading(deleteBtn, false);
          }
        }
      });
    } else {
      const level = this.displayLevelForRule(rule);
      const badge = levelEl.createSpan({
        cls: `vaultguard-fh-badge vaultguard-fh-badge-${level}`,
      });
      badge.setText(this.formatLevel(level));
    }
  }

  // ─── Add Rule ──────────────────────────────────────────────────────

  private renderAddRuleSection(container: HTMLElement): void {
    this.syncSelectedUserFromDraft();

    const section = container.createDiv({ cls: "vaultguard-fp-add" });
    section.createDiv({ cls: "vaultguard-fp-add-title", text: "Add access" });

    const form = section.createDiv({ cls: "vaultguard-fp-add-form" });

    // Type selector
    const typeSelect = form.createEl("select", { cls: "vaultguard-fp-add-input" });
    typeSelect.createEl("option", { text: "User", attr: { value: "user" } });
    typeSelect.createEl("option", { text: "Role", attr: { value: "role" } });
    typeSelect.value = this.draftPrincipalType;

    // Principal input
    const principalInput = form.createEl("input", {
      cls: "vaultguard-fp-add-input vaultguard-fp-add-principal",
      attr: {
        type: "text",
        placeholder: this.draftPrincipalType === "user"
          ? "Search teammates or enter a user ID"
          : "Role name",
      },
    }) as HTMLInputElement;
    principalInput.value = this.draftPrincipalValue;

    // Level selector
    const levelSelect = form.createEl("select", { cls: "vaultguard-fp-add-input" });
    levelSelect.createEl("option", { text: "Read", attr: { value: "read" } });
    levelSelect.createEl("option", { text: "Write", attr: { value: "write" } });
    levelSelect.createEl("option", { text: "Admin", attr: { value: "admin" } });
    // "No Access" creates a deny rule so admins can revoke inherited access
    // for one principal without removing them from the vault. Mirrors the
    // option already available in the existing-rule dropdown.
    levelSelect.createEl("option", { text: "No Access", attr: { value: "none" } });
    levelSelect.value = this.draftLevel;

    // Add button
    const addBtn = form.createEl("button", {
      cls: "vaultguard-fp-add-btn",
      attr: { type: "button" },
    });
    setIcon(addBtn, "plus");

    const quickListEl = section.createDiv({ cls: "vaultguard-access-picker" });

    const updateQuickList = (): void => {
      this.draftPrincipalType = typeSelect.value as "user" | "role";
      this.draftPrincipalValue = principalInput.value;
      this.draftLevel = levelSelect.value;
      this.syncSelectedUserFromDraft();
      principalInput.placeholder = this.draftPrincipalType === "user"
        ? "Search teammates or enter a user ID"
        : "Role name";

      quickListEl.empty();

      if (this.draftPrincipalType !== "user") {
        quickListEl.createDiv({
          cls: "vaultguard-access-picker-note",
          text: "Role rules apply to everyone assigned to that role.",
        });
        return;
      }

      quickListEl.createDiv({
        cls: "vaultguard-access-picker-note",
        text: "Quick add from your team directory",
      });

      if (this.usersLoading) {
        quickListEl.createDiv({
          cls: "vaultguard-access-picker-state",
          text: "Loading teammates...",
        });
        return;
      }

      if (this.usersLoadError) {
        quickListEl.createDiv({
          cls: "vaultguard-access-picker-state",
          text: "Team directory unavailable right now. You can still type a user ID.",
        });
        return;
      }

      const directoryUsers = this.users.filter((user) => user.status !== "revoked");
      if (directoryUsers.length === 0) {
        quickListEl.createDiv({
          cls: "vaultguard-access-picker-state",
          text: "No teammates found yet. Invite someone from the Users tab first.",
        });
        return;
      }

      const filteredUsers = directoryUsers
        .filter((user) => matchesAccessUserQuery(user, principalInput.value))
        .slice(0, 8);

      if (filteredUsers.length === 0) {
        quickListEl.createDiv({
          cls: "vaultguard-access-picker-state",
          text: "No matching teammates.",
        });
        return;
      }

      const existingLevels = this.existingExactDirectUserLevels();
      const listEl = quickListEl.createDiv({ cls: "vaultguard-access-picker-list" });

      for (const user of filteredUsers) {
        const existingLevel = existingLevels.get(user.id);
        const userBtn = listEl.createEl("button", {
          cls: "vaultguard-access-picker-item",
          attr: { type: "button" },
        });

        userBtn.classList.toggle("is-selected", this.draftSelectedUserId === user.id);
        userBtn.classList.toggle("is-disabled", Boolean(existingLevel));
        userBtn.disabled = Boolean(existingLevel);

        const avatarEl = userBtn.createDiv({ cls: "vaultguard-access-picker-avatar" });
        avatarEl.createSpan({ text: getAccessUserNameInitials(user) });

        const bodyEl = userBtn.createDiv({ cls: "vaultguard-access-picker-body" });
        bodyEl.createDiv({
          cls: "vaultguard-access-picker-name",
          text: getAccessUserDisplayName(user),
        });
        bodyEl.createDiv({
          cls: "vaultguard-access-picker-meta",
          text: getAccessUserMeta(user),
        });

        const pillEl = userBtn.createSpan({ cls: "vaultguard-access-picker-pill" });
        if (existingLevel) {
          pillEl.classList.add(`vaultguard-access-picker-pill-level-${existingLevel}`);
          pillEl.setText(`Has ${this.formatLevel(existingLevel)}`);
        } else if (user.status !== "active") {
          pillEl.setText(formatAccessUserStatus(user.status));
        } else {
          pillEl.setText(formatAccessUserRole(user.role));
        }

        if (!existingLevel) {
          userBtn.addEventListener("click", () => {
            this.draftSelectedUserId = user.id;
            this.draftPrincipalValue = getAccessUserPickerValue(user);
            principalInput.value = this.draftPrincipalValue;
            principalInput.focus();
            updateQuickList();
          });
        }
      }
    };

    const submitAddRule = async (): Promise<void> => {
      const principalType = typeSelect.value as "user" | "role";
      const rawPrincipalValue = principalInput.value.trim();
      const level = levelSelect.value;

      this.draftPrincipalType = principalType;
      this.draftPrincipalValue = principalInput.value;
      this.draftLevel = level;
      this.syncSelectedUserFromDraft();

      const principalId = principalType === "user"
        ? this.resolveDraftUserId(rawPrincipalValue)
        : rawPrincipalValue;

      if (!principalId) {
        new Notice("Please enter a user ID or role name.");
        return;
      }

      if (principalType === "user") {
        const existingLevel = this.existingExactDirectUserLevels().get(principalId);
        if (existingLevel) {
          new Notice(`${this.userLabel(principalId)} already has a direct rule for this file.`);
          return;
        }
      }

      setButtonLoading(addBtn, true);

      try {
        const filePath = this.cfg.file.path;
        const pathPattern = filePath.startsWith("/") ? filePath : `/${filePath}`;
        const principalLabel = principalType === "user" ? this.userLabel(principalId) : principalId;

        // Use the server set-level endpoint so we land the principal at
        // exactly `level` regardless of their inherited baseline. The Add
        // form previously hand-built a rule shape (allow/deny) which is the
        // same class of bug as the dropdown flows — see the matrix test for
        // the failure modes.
        const canonicalUserId = principalType === "user" ? principalId : "*";
        const response = await this.cfg.apiClient.setPermissionLevel({
          userId: canonicalUserId,
          role: principalType === "role" ? principalId : null,
          pathPattern,
          level: level as "none" | "read" | "write" | "admin",
        });
        new Notice(
          level === "none"
            ? `Access blocked for ${principalLabel}.`
            : `Access granted to ${principalLabel}.`
        );
        this.draftPrincipalValue = "";
        this.draftSelectedUserId = null;
        // Optimistic patch — appends the principal to the effective list
        // (or updates an existing row) so the user sees the new row
        // immediately. onRulesChanged() reconciles right after.
        if (response?.level && principalType === "user") {
          this.patchEffectivePrincipalLevel(canonicalUserId, response.level);
          this.optimisticRender();
        }
        await this.cfg.onRulesChanged();
      } catch (error) {
        new Notice(`Failed to add: ${(error as Error).message}`);
      } finally {
        if (!this.isDestroyed && addBtn.isConnected) {
          setButtonLoading(addBtn, false);
        }
      }
    };

    typeSelect.addEventListener("change", () => {
      const nextType = typeSelect.value as "user" | "role";
      if (nextType !== this.draftPrincipalType) {
        this.draftPrincipalValue = "";
        principalInput.value = "";
      }
      if (nextType !== "user") {
        this.draftSelectedUserId = null;
      }
      updateQuickList();
    });

    principalInput.addEventListener("input", () => {
      updateQuickList();
    });

    principalInput.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        event.preventDefault();
        void submitAddRule();
      }
    });

    levelSelect.addEventListener("change", () => {
      this.draftLevel = levelSelect.value;
    });

    addBtn.addEventListener("click", () => {
      void submitAddRule();
    });

    updateQuickList();
  }

  // ─── Handlers ──────────────────────────────────────────────────────

  private async handleLevelChange(rule: PermissionRule, newLevel: string): Promise<void> {
    try {
      // Delegate to the server set-level endpoint — see file-permission-header
      // for the architectural rationale. The server picks the right rule
      // shape from (target, inherited), so the UI never has to compute a
      // mutation that yields the desired effective level.
      const canonicalUserId = rule.role ? "*" : this.resolveCanonicalUserId(rule.userId);
      const response = await this.cfg.apiClient.setPermissionLevel({
        userId: canonicalUserId,
        role: rule.role ?? null,
        pathPattern: this.targetRulePath(),
        level: newLevel as "none" | "read" | "write" | "admin",
      });
      // Optimistic patch: use the server's authoritative new level so the
      // row updates immediately. The parent's onRulesChanged() refresh
      // reconciles the rest of the principals against the server.
      if (response?.level && !rule.role) {
        this.patchEffectivePrincipalLevel(canonicalUserId, response.level);
        this.optimisticRender();
      }
      new Notice("Permission updated.");
      await this.cfg.onRulesChanged();
    } catch (error) {
      new Notice(`Failed to update: ${(error as Error).message}`);
    }
  }

  private async handleEffectivePrincipalLevelChange(
    principal: EffectiveAccessPrincipal,
    newLevel: string
  ): Promise<void> {
    if (principal.type !== "user") return;

    try {
      const canonicalUserId = this.resolveCanonicalUserId(principal.id);
      const response = await this.cfg.apiClient.setPermissionLevel({
        userId: canonicalUserId,
        role: null,
        pathPattern: this.targetRulePath(),
        level: newLevel as "none" | "read" | "write" | "admin",
      });
      // See handleLevelChange — same optimistic-patch-then-reconcile pattern.
      if (response?.level) {
        this.patchEffectivePrincipalLevel(canonicalUserId, response.level);
        this.optimisticRender();
      }
      new Notice("Permission updated.");
      await this.cfg.onRulesChanged();
    } catch (error) {
      new Notice(`Failed to update: ${(error as Error).message}`);
    }
  }

  /**
   * Best-effort re-render after an optimistic patch. No-op when the panel is
   * not mounted (tests using Object.create skip the constructor; legacy
   * call sites may invoke handler before render bootstrap). The authoritative
   * render still fires through onRulesChanged() right after, so a skipped
   * optimistic render only loses the instant-flip, not correctness.
   */
  private optimisticRender(): void {
    if (this.isDestroyed) return;
    if (!this.panelEl?.isConnected) return;
    this.render();
  }

  /**
   * Records a set-level write and reflects it in the local effective-access
   * list so the row updates immediately. The same value is parked in
   * `pendingLevelPatches` and re-applied in `setData()` (called by the
   * parent's refresh) until the server's view catches up — this prevents a
   * stale GSI read from flipping the row back to its prior level
   * immediately after a write.
   */
  private patchEffectivePrincipalLevel(
    canonicalUserId: string,
    level: "none" | "read" | "write" | "admin"
  ): void {
    if (!this.pendingLevelPatches) this.pendingLevelPatches = new Map();
    this.pendingLevelPatches.set(canonicalUserId, level);
    this.reconcilePendingLevelPatches();
  }

  /**
   * Pending set-level patches awaiting confirmation by a subsequent
   * effective-access fetch. See the matching note in
   * path-permissions-modal.ts for the post-write-read-consistency rationale.
   */
  private pendingLevelPatches = new Map<string, "none" | "read" | "write" | "admin">();

  private reconcilePendingLevelPatches(): void {
    if (!this.pendingLevelPatches) this.pendingLevelPatches = new Map();
    // Drop patches the server has caught up to.
    for (const [userId, level] of [...this.pendingLevelPatches]) {
      const principal = this.effectivePrincipals.find(
        (p) => p.type === "user" && this.resolveCanonicalUserId(p.id) === userId
      );
      if (principal && principal.level === level) {
        this.pendingLevelPatches.delete(userId);
      }
    }

    if (this.pendingLevelPatches.size === 0) return;

    this.effectivePrincipals = this.effectivePrincipals.map((principal) => {
      if (principal.type !== "user") return principal;
      const patched = this.pendingLevelPatches.get(this.resolveCanonicalUserId(principal.id));
      return patched ? { ...principal, level: patched } : principal;
    });

    for (const [userId, level] of this.pendingLevelPatches) {
      if (level === "none") continue;
      const exists = this.effectivePrincipals.some(
        (p) => p.type === "user" && this.resolveCanonicalUserId(p.id) === userId
      );
      if (!exists) {
        this.effectivePrincipals.push({
          id: userId,
          label: this.userLabel(userId),
          level,
          type: "user",
        });
      }
    }
  }

  private async handleDeleteRule(rule: PermissionRule): Promise<void> {
    try {
      await this.cfg.apiClient.deletePermission(rule.id);
      new Notice("Permission rule removed.");
      await this.cfg.onRulesChanged();
    } catch (error) {
      new Notice(`Failed to delete: ${(error as Error).message}`);
    }
  }

  private async loadUsers(): Promise<void> {
    try {
      const users = await this.cfg.apiClient.listUsers();
      if (this.isDestroyed) return;

      this.users = sortAccessUsers(users);
      this.userMap = buildAccessUserMap(this.users);
      this.usersLoadError = null;
    } catch (error) {
      if (this.isDestroyed) return;
      this.usersLoadError = (error as Error).message;
    } finally {
      this.usersLoading = false;
      if (!this.isDestroyed) {
        this.render();
        this.positionPanel();
      }
    }
  }

  // ─── Helpers ───────────────────────────────────────────────────────

  private principalLabel(rule: PermissionRule): string {
    if (rule.role) return `Role: ${rule.role}`;
    if (rule.userId === "*") return "Everyone";
    return this.userLabel(rule.userId);
  }

  private currentLevel(rule: PermissionRule): string {
    if (rule.effect === "deny") return this.deniedActionsCapLevel(rule.actions);
    if (rule.actions.includes("admin")) return "admin";
    if (rule.actions.includes("write") || rule.actions.includes("delete")) return "write";
    if (rule.actions.includes("read")) return "read";
    return "none";
  }

  /**
   * Backend-computed effective level for this rule's principal on the panel's
   * current path. Returns null when no effective access summary is available
   * (e.g. legacy admin view without the access endpoint) or when the rule
   * targets a role/wildcard that the effective list does not enumerate. The
   * level here is what the user/role ACTUALLY ends up at, which is the only
   * basis for a correct downgrade-vs-upgrade decision.
   */
  private effectiveLevelForRulePrincipal(rule: PermissionRule): string | null {
    if (this.effectivePrincipals.length === 0) return null;
    if (rule.role || rule.userId === "*") return null;

    const canonicalUserId = this.resolveCanonicalUserId(rule.userId);
    const principal = this.effectivePrincipals.find((entry) => {
      if (entry.type !== "user") return false;
      return this.resolveCanonicalUserId(entry.id) === canonicalUserId;
    });
    return principal ? principal.level : null;
  }

  private displayLevelForRule(rule: PermissionRule): string {
    let level = this.currentLevel(rule);
    if (rule.effect === "deny" || rule.role || rule.userId === "*" || !this.ruleTargetsCurrentPath(rule)) {
      return level;
    }

    const canonicalUserId = this.resolveCanonicalUserId(rule.userId);
    for (const candidate of this.rules) {
      if (candidate === rule || candidate.role || candidate.userId === "*") continue;
      if (this.ruleTargetsCurrentPath(candidate)) continue;
      if (this.resolveCanonicalUserId(candidate.userId) !== canonicalUserId) continue;

      const candidateLevel = this.currentLevel(candidate);
      if (this.levelRank(candidateLevel) > this.levelRank(level)) {
        level = candidateLevel;
      }
    }

    return level;
  }

  private formatLevel(level: string): string {
    switch (level) {
      case "admin": return "Admin";
      case "write": return "Write";
      case "read": return "Read";
      default: return "No Access";
    }
  }

  private levelToActions(level: string): PermissionMutationInput["actions"] {
    switch (level) {
      case "admin": return ["read", "write", "delete", "admin", "list"];
      case "write": return ["read", "write", "delete", "list"];
      case "read": return ["read", "list"];
      default: return ["read", "list"];
    }
  }

  /**
   * Single source of truth for the (actions, effect) tuple that brings the
   * user from `previousLevel` to `level` on the target path. See the matching
   * helper in file-permission-header.ts for the full rationale; this
   * implementation is intentionally identical to keep the three UI surfaces
   * (header, panel, modal) writing the same rule shape for the same
   * transition.
   *
   * The downgrade branch covers ALL downgrades (admin→write, admin→read,
   * write→read, write→none-via-deny, …) not just write→read, so an
   * effectively-write user who was incorrectly stuck on a stale `allow [read]`
   * rule gets reduced via deny-cap whenever the dropdown is touched.
   */
  private buildLevelMutation(
    level: string,
    previousLevel: string = "none"
  ): Pick<PermissionMutationInput, "actions" | "effect"> {
    if (level === "none") {
      return {
        actions: ["read", "write", "delete", "admin", "list"],
        effect: "deny",
      };
    }

    const targetRank = this.levelRank(level);
    const previousRank = this.levelRank(previousLevel);

    if (targetRank < previousRank) {
      // See file-permission-header.ts for the ordering rationale.
      const denyActions: PermissionMutationInput["actions"] = [];
      if (targetRank < 1) denyActions.push("read", "list");
      if (targetRank < 2) denyActions.push("write", "delete");
      if (targetRank < 3) denyActions.push("admin");
      return { actions: denyActions, effect: "deny" };
    }

    return {
      actions: this.levelToActions(level),
      effect: "allow",
    };
  }

  private ruleLevelRank(rule: PermissionRule): number {
    if (rule.effect === "deny") return this.levelRank(this.deniedActionsCapLevel(rule.actions));
    if (rule.actions.includes("admin")) return 3;
    if (rule.actions.includes("write")) return 2;
    if (rule.actions.includes("read")) return 1;
    return 0;
  }

  private userLabel(userId: string): string {
    const user = this.userMap.get(userId);
    return user ? getAccessUserDisplayName(user) : userId;
  }

  private existingExactDirectUserLevels(): Map<string, string> {
    const levels = new Map<string, string>();

    for (const rule of this.rules) {
      if (rule.role || rule.userId === "*") continue;
      if (!this.ruleTargetsCurrentPath(rule)) continue;

      const level = this.currentLevel(rule);
      const existingLevel = levels.get(rule.userId);

      if (!existingLevel || this.levelRank(level) >= this.levelRank(existingLevel)) {
        levels.set(rule.userId, level);
      }
    }

    return levels;
  }

  private targetRulePath(): string {
    return this.cfg.file.path.startsWith("/") ? this.cfg.file.path : `/${this.cfg.file.path}`;
  }

  private ruleTargetsCurrentPath(rule: PermissionRule): boolean {
    return this.normalizeRulePath(rule.pathPattern) === this.normalizeRulePath(this.targetRulePath());
  }

  private findExactRuleForPrincipal(sourceRule: PermissionRule): PermissionRule | null {
    return this.rules.find((rule) => {
      if (!this.ruleTargetsCurrentPath(rule)) return false;
      if (sourceRule.role) return rule.role === sourceRule.role;
      return !rule.role &&
        this.resolveCanonicalUserId(rule.userId) === this.resolveCanonicalUserId(sourceRule.userId);
    }) ?? null;
  }

  private normalizeRulePath(path: string): string {
    return path.replace(/^\/+/, "").replace(/\/+$/, "");
  }

  private resolveCanonicalUserId(userId: string): string {
    return resolveAccessUserId(this.users, userId);
  }

  private findExactUserRuleForCurrentPath(userId: string): PermissionRule | null {
    const canonicalUserId = this.resolveCanonicalUserId(userId);
    return this.rules.find((rule) =>
      !rule.role &&
      this.resolveCanonicalUserId(rule.userId) === canonicalUserId &&
      this.ruleTargetsCurrentPath(rule)
    ) ?? null;
  }

  private rawRulesForDisplay(): PermissionRule[] {
    const exactDirectUsers = new Set<string>();
    for (const rule of this.rules) {
      if (rule.role || rule.userId === "*" || !this.ruleTargetsCurrentPath(rule)) continue;
      exactDirectUsers.add(this.resolveCanonicalUserId(rule.userId));
    }

    if (exactDirectUsers.size === 0) return [...this.rules];

    return this.rules.filter((rule) => {
      if (rule.role || rule.userId === "*") return true;
      if (this.ruleTargetsCurrentPath(rule)) return true;
      return !exactDirectUsers.has(this.resolveCanonicalUserId(rule.userId));
    });
  }

  private syncSelectedUserFromDraft(): void {
    if (this.draftPrincipalType !== "user") {
      this.draftSelectedUserId = null;
      return;
    }

    const selectedUser = this.draftSelectedUserId
      ? this.userMap.get(this.draftSelectedUserId) ?? null
      : null;

    if (
      selectedUser &&
      this.normalizeValue(this.draftPrincipalValue) ===
        this.normalizeValue(getAccessUserPickerValue(selectedUser))
    ) {
      return;
    }

    this.draftSelectedUserId = findExactAccessUserMatch(this.users, this.draftPrincipalValue)?.id ?? null;
  }

  private resolveDraftUserId(rawValue: string): string {
    const selectedUser = this.draftSelectedUserId
      ? this.userMap.get(this.draftSelectedUserId) ?? null
      : null;

    if (
      selectedUser &&
      this.normalizeValue(rawValue) === this.normalizeValue(getAccessUserPickerValue(selectedUser))
    ) {
      return selectedUser.id;
    }

    return resolveAccessUserId(this.users, rawValue);
  }

  private normalizeValue(value: string): string {
    return value.trim().toLowerCase();
  }

  private levelRank(level: string): number {
    switch (level) {
      case "admin": return 3;
      case "write": return 2;
      case "read": return 1;
      default: return 0;
    }
  }

  private deniedActionsCapLevel(actions: PermissionRule["actions"]): string {
    if (actions.includes("read") || actions.includes("list")) return "none";
    if (actions.includes("write") || actions.includes("delete")) return "read";
    if (actions.includes("admin")) return "write";
    return "none";
  }

  private initials(name: string): string {
    if (name === "*") return "*";
    return getAccessUserInitials(name);
  }

  private userInitials(userId: string): string {
    if (userId === "*") return "*";
    const user = this.userMap.get(userId);
    return user ? getAccessUserNameInitials(user) : this.initials(userId);
  }

  private normalizeEffectivePrincipals(principals: EffectiveAccessPrincipal[]): EffectiveAccessPrincipal[] {
    const byKey = new Map<string, EffectiveAccessPrincipal>();

    for (const principal of principals) {
      const canonicalId = principal.type === "user"
        ? this.resolveCanonicalUserId(principal.id)
        : principal.id;
      const email = principal.email?.trim().toLowerCase();
      const key = principal.type === "user"
        ? `user:${email || canonicalId}`
        : `role:${canonicalId}`;
      const normalized: EffectiveAccessPrincipal = {
        ...principal,
        id: canonicalId,
      };
      const existing = byKey.get(key);
      if (!existing || this.levelRank(normalized.level) > this.levelRank(existing.level)) {
        byKey.set(key, normalized);
      }
    }

    return [...byKey.values()].sort((a, b) => {
      const levelDiff = this.levelRank(b.level) - this.levelRank(a.level);
      if (levelDiff !== 0) return levelDiff;
      return a.label.localeCompare(b.label);
    });
  }

  private mergeEffectivePrincipalsIntoDirectory(): void {
    const knownIds = new Set(this.users.map((user) => user.id));
    const additions: UserListEntry[] = [];

    for (const principal of this.effectivePrincipals) {
      if (principal.type !== "user" || principal.id === "*" || knownIds.has(principal.id)) continue;
      if (!principal.label && !principal.email) continue;

      additions.push({
        id: principal.id,
        email: principal.email ?? "",
        displayName: principal.label,
        name: principal.label,
        role: "viewer",
        status: "active",
        lastActive: "",
        createdAt: "",
        mfaEnabled: false,
        deviceCount: 0,
        type: "user",
      });
      knownIds.add(principal.id);
    }

    if (additions.length === 0) return;
    this.users = sortAccessUsers([...this.users, ...additions]);
    this.userMap = buildAccessUserMap(this.users);
  }

  private effectivePrincipalInitials(principal: EffectiveAccessPrincipal): string {
    if (principal.id === "*") return "*";
    const user = this.userMap.get(principal.id) ||
      (principal.email ? this.userMap.get(principal.email) ?? this.userMap.get(principal.email.toLowerCase()) : undefined);
    if (user) return getAccessUserNameInitials(user);
    return this.initials(principal.label || principal.email || principal.id);
  }

  private canManageAccess(): boolean {
    return this.cfg.canManageAccess ?? this.cfg.isAdmin;
  }

  private canEditEffectivePrincipal(principal: EffectiveAccessPrincipal): boolean {
    if (!this.canManageAccess()) return false;
    if (principal.type !== "user") return false;
    if (this.isCurrentUserPrincipal(principal)) return false;
    // See PathPermissionsModal.canEditAccessPrincipal — vault admins
    // bypass per-file deny rules server-side, so editing their level is a
    // no-op that flips back on the next refresh UNLESS the org enabled
    // allowAdminPerFileRestrictions (then the bypass is opt-out and the
    // deny rule actually takes effect).
    if (
      !this.cfg.allowAdminPerFileRestrictions
      && principal.vaultRole === "admin"
    ) {
      return false;
    }
    return true;
  }

  private isCurrentUserPrincipal(principal: EffectiveAccessPrincipal): boolean {
    if (principal.type !== "user") return false;
    const currentId = this.resolveCanonicalUserId(this.cfg.currentUserId);
    const principalId = this.resolveCanonicalUserId(principal.id);
    const currentEmail = this.cfg.currentUserEmail?.trim().toLowerCase() ?? "";
    const principalEmail = principal.email?.trim().toLowerCase() ?? "";
    return principal.id === this.cfg.currentUserId ||
      principalId === currentId ||
      (currentEmail.length > 0 && principalEmail === currentEmail);
  }

  private positionPanel(): void {
    if (!this.cfg.anchorEl.isConnected) {
      this.destroy();
      return;
    }

    const viewportMargin = 12;
    const gap = 8;
    const anchorRect = this.cfg.anchorEl.getBoundingClientRect();
    const availableWidth = Math.max(280, window.innerWidth - viewportMargin * 2);
    const panelWidth = Math.min(380, availableWidth);

    this.panelEl.style.width = `${panelWidth}px`;

    // Measure after width is applied so we can decide whether to place it
    // above or below the anchor based on available space.
    const panelHeight = this.panelEl.offsetHeight || 420;
    const preferredTop = anchorRect.bottom + gap;
    const availableBelow = window.innerHeight - preferredTop - viewportMargin;

    let top = preferredTop;
    if (availableBelow < Math.min(panelHeight, 220)) {
      top = Math.max(viewportMargin, anchorRect.top - panelHeight - gap);
    }

    const left = Math.max(
      viewportMargin,
      Math.min(anchorRect.right - panelWidth, window.innerWidth - panelWidth - viewportMargin)
    );
    const maxHeight = Math.max(220, window.innerHeight - top - viewportMargin);

    this.panelEl.style.top = `${top}px`;
    this.panelEl.style.left = `${left}px`;
    this.panelEl.style.maxHeight = `${maxHeight}px`;
  }
}
