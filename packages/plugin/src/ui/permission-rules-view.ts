import { Notice, Setting } from "obsidian";
import {
  PermissionMutationInput,
  PermissionRule,
  UserListEntry,
  VaultGuardApiClient,
} from "../api/client";

/**
 * Vault-wide permission-rules manager, rendered INTO a container (e.g. the
 * Organization Admin modal's "Vault access" tab). Lists every rule for the
 * bound vault and lets an admin add / edit / delete rules (principal
 * dropdowns, level, priority, expiry), mirroring the web admin panel's
 * Permissions table.
 *
 * The add/edit form renders INLINE in the same container (never a stacked
 * child Modal — that breaks Obsidian's focus trap). The search box re-renders
 * only the table rows, never itself, so typing keeps focus.
 *
 * Separate from the per-file controls in the editor header / sidebar.
 */

type Level = "none" | "read" | "write" | "admin";

export interface PermissionRulesCurrentUser {
  id?: string;
  orgRole?: string;
  roles?: string[];
  vaultRole?: string | null;
}

export interface PermissionRulesViewOptions {
  currentUser?: PermissionRulesCurrentUser;
  /** Called after a rule is created / edited / deleted so the host can refresh
   *  other permission surfaces (file header, decorations, sidebar). */
  onChanged?: () => void;
}

const ROLE_OPTIONS: { value: string; label: string }[] = [
  { value: "viewer", label: "Viewer" },
  { value: "editor", label: "Editor" },
  { value: "admin", label: "Admin" },
];

const LEVEL_OPTIONS: { value: Level; label: string }[] = [
  { value: "none", label: "None (Deny)" },
  { value: "read", label: "Read" },
  { value: "write", label: "Write" },
  { value: "admin", label: "Admin" },
];

function actionsForLevel(level: Level): PermissionMutationInput["actions"] {
  switch (level) {
    case "admin":
      return ["read", "write", "delete", "admin", "list"];
    case "write":
      return ["read", "write", "delete", "list"];
    case "read":
      return ["read", "list"];
    case "none":
      return ["read", "write", "delete", "admin", "list"];
  }
}

function levelFromRule(rule: PermissionRule): Level {
  if (rule.effect === "deny") return "none";
  if (rule.actions.includes("admin")) return "admin";
  if (rule.actions.includes("write") || rule.actions.includes("delete")) return "write";
  return "read";
}

/** ISO timestamp → value accepted by <input type="datetime-local"> (local time). */
function toDatetimeLocal(iso?: string): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function rolesIncludeOrgAdmin(roles: string[]): boolean {
  return roles.includes("admin") || roles.includes("owner") || roles.includes("vault-admin");
}

interface FormState {
  rule: PermissionRule | null; // null = add
  path: string;
  principalType: "user" | "role";
  userId: string;
  roleId: string;
  level: Level;
  priority: string;
  expiresAt: string;
}

export class PermissionRulesView {
  private apiClient: VaultGuardApiClient;
  private container: HTMLElement;
  private currentUser: PermissionRulesCurrentUser;
  private onChanged: () => void;

  private rules: PermissionRule[] = [];
  private users: UserListEntry[] = [];
  private usersById: Map<string, UserListEntry> = new Map();
  private search = "";
  private loadError: string | null = null;
  private loading = true;

  private mode: "table" | "form" = "table";
  private form: FormState | null = null;
  private rowsContainer: HTMLElement | null = null;

  constructor(
    apiClient: VaultGuardApiClient,
    container: HTMLElement,
    options: PermissionRulesViewOptions = {}
  ) {
    this.apiClient = apiClient;
    this.container = container;
    this.currentUser = options.currentUser ?? {};
    this.onChanged = options.onChanged ?? (() => {});
  }

  /** Renders the view and kicks off the data load. */
  mount(): void {
    this.container.addClass("vaultguard-rules-view");
    void this.load();
  }

  private async load(): Promise<void> {
    this.loading = true;
    this.loadError = null;
    this.render();
    try {
      const [rules, users] = await Promise.all([
        this.apiClient.getPermissions(),
        this.apiClient.listUsers().catch(() => [] as UserListEntry[]),
      ]);
      this.rules = rules;
      this.users = users;
      this.usersById = new Map(users.map((u) => [u.id, u]));
    } catch (err) {
      this.loadError = err instanceof Error ? err.message : String(err);
    } finally {
      this.loading = false;
    }
    this.render();
  }

  private render(): void {
    this.container.empty();
    if (this.mode === "form" && this.form) {
      this.renderForm(this.form);
    } else {
      this.renderTable();
    }
  }

  // ─── Table view ────────────────────────────────────────────────────────

  private renderTable(): void {
    const root = this.container;
    root.createEl("p", {
      cls: "setting-item-description",
      text:
        "All permission rules for the server vault bound to this folder. Path patterns match by glob — more specific paths override broader ones, and deny overrides allow at the same specificity. Org admins bypass all rules. This is separate from the per-file controls in the editor header.",
    });

    const toolbar = root.createDiv({ cls: "vaultguard-rules-toolbar" });
    const searchInput = toolbar.createEl("input", {
      cls: "vaultguard-search-input",
      attr: { type: "text", placeholder: "Search by path, user, or role…" },
    });
    searchInput.value = this.search;
    searchInput.addEventListener("input", () => {
      this.search = searchInput.value.toLowerCase();
      this.renderRows();
    });
    const addBtn = toolbar.createEl("button", { cls: "mod-cta", text: "Add Rule" });
    addBtn.addEventListener("click", () => this.openForm(null));

    this.rowsContainer = root.createDiv({ cls: "vaultguard-rules-table-wrap" });
    this.renderRows();
  }

  private renderRows(): void {
    const c = this.rowsContainer;
    if (!c) return;
    c.empty();

    if (this.loadError) {
      c.createDiv({ cls: "vaultguard-error-text", text: `Failed to load permissions: ${this.loadError}` });
      return;
    }
    if (this.loading) {
      c.createDiv({ cls: "vaultguard-empty-state", text: "Loading permissions…" });
      return;
    }

    const rules = this.filteredRules();
    if (rules.length === 0) {
      c.createDiv({
        cls: "vaultguard-empty-state",
        text: this.search ? "No rules match your search." : "No permission rules in this vault yet.",
      });
      return;
    }

    const table = c.createEl("table", { cls: "vaultguard-rules-table" });
    const headRow = table.createEl("thead").createEl("tr");
    for (const h of ["Path pattern", "Principal", "Effect", "Actions", "Priority", "Expires", ""]) {
      headRow.createEl("th", { text: h });
    }
    const tbody = table.createEl("tbody");
    for (const rule of rules) {
      const tr = tbody.createEl("tr");
      tr.createEl("td").createEl("code", { text: rule.pathPattern });
      tr.createEl("td", { text: this.principalLabel(rule) });
      tr.createEl("td").createSpan({
        cls: `vaultguard-effect-badge vaultguard-effect-${rule.effect}`,
        text: rule.effect,
      });
      tr.createEl("td", { cls: "vaultguard-rules-muted", text: rule.actions.join(", ") });
      tr.createEl("td", { cls: "vaultguard-rules-muted", text: String(rule.priority) });
      tr.createEl("td", {
        cls: "vaultguard-rules-muted",
        text: rule.expiresAt ? new Date(rule.expiresAt).toLocaleString() : "—",
      });
      const actionsTd = tr.createEl("td", { cls: "vaultguard-rules-row-actions" });
      actionsTd.createEl("button", { text: "Edit" }).addEventListener("click", () => this.openForm(rule));
      actionsTd
        .createEl("button", { cls: "mod-warning", text: "Delete" })
        .addEventListener("click", () => void this.handleDelete(rule));
    }
  }

  private filteredRules(): PermissionRule[] {
    const q = this.search.trim();
    const matches = q
      ? this.rules.filter((r) => {
          const u = this.usersById.get(r.userId);
          return (
            r.pathPattern.toLowerCase().includes(q) ||
            (r.role || "").toLowerCase().includes(q) ||
            r.userId.toLowerCase().includes(q) ||
            (u?.email || "").toLowerCase().includes(q) ||
            (u?.displayName || "").toLowerCase().includes(q)
          );
        })
      : [...this.rules];
    return matches.sort(
      (a, b) => a.pathPattern.localeCompare(b.pathPattern) || a.effect.localeCompare(b.effect)
    );
  }

  private principalLabel(rule: PermissionRule): string {
    if (rule.role) return `role: ${rule.role}`;
    if (rule.userId === "*") return "all users";
    const u = this.usersById.get(rule.userId);
    return u ? u.displayName || u.email : rule.userId;
  }

  private wouldDeleteOwnAdminRule(rule: PermissionRule): boolean {
    const cu = this.currentUser;
    if (!cu?.id) return false;
    const roles = [cu.orgRole, ...(cu.roles ?? [])].filter((r): r is string => Boolean(r));
    if (rolesIncludeOrgAdmin(roles)) return false;
    if (rule.effect !== "allow" || !rule.actions.includes("admin")) return false;
    return (
      rule.userId === cu.id ||
      (!!rule.role && (roles.includes(rule.role) || cu.vaultRole === rule.role))
    );
  }

  private async handleDelete(rule: PermissionRule): Promise<void> {
    if (this.wouldDeleteOwnAdminRule(rule)) {
      new Notice("You can't delete a rule that grants your own admin access — ask another admin.");
      return;
    }
    const ok = window.confirm(
      `Delete the ${this.principalLabel(rule)} rule on "${rule.pathPattern}"? This cannot be undone.`
    );
    if (!ok) return;
    try {
      await this.apiClient.deletePermission(rule.id);
      new Notice("Permission rule deleted.");
      this.onChanged();
      await this.load();
    } catch (err) {
      new Notice(`Failed to delete: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  // ─── Inline add / edit form ──────────────────────────────────────────────

  private openForm(rule: PermissionRule | null): void {
    this.form = {
      rule,
      path: rule?.pathPattern ?? "",
      principalType: rule?.role ? "role" : "user",
      userId: rule && !rule.role ? rule.userId : "*",
      roleId: rule?.role ?? ROLE_OPTIONS[0].value,
      level: rule ? levelFromRule(rule) : "read",
      priority: rule ? String(rule.priority) : "",
      expiresAt: toDatetimeLocal(rule?.expiresAt),
    };
    this.mode = "form";
    this.render();
  }

  private closeForm(): void {
    this.mode = "table";
    this.form = null;
    this.render();
  }

  private renderForm(form: FormState): void {
    const root = this.container;
    root.createEl("h3", { text: form.rule ? "Edit permission rule" : "Add permission rule" });

    new Setting(root)
      .setName("Path pattern")
      .setDesc("Use * for one segment, ** for recursive. Applies inside this vault.")
      .addText((t) =>
        t
          .setPlaceholder("/engineering/** or /docs/spec.md")
          .setValue(form.path)
          .onChange((v) => (form.path = v))
      );

    new Setting(root).setName("Principal type").addDropdown((d) =>
      d
        .addOption("user", "User")
        .addOption("role", "Role")
        .setValue(form.principalType)
        .onChange((v) => {
          form.principalType = v as "user" | "role";
          applyPrincipalVisibility();
        })
    );

    const userSetting = new Setting(root).setName("User").addDropdown((d) => {
      d.addOption("*", "All users");
      const sorted = [...this.users].sort((a, b) =>
        (a.displayName || a.email).localeCompare(b.displayName || b.email)
      );
      for (const u of sorted) d.addOption(u.id, `${u.displayName || u.email} (${u.email})`);
      if (form.userId !== "*" && !this.users.some((u) => u.id === form.userId)) {
        d.addOption(form.userId, form.userId);
      }
      d.setValue(form.userId).onChange((v) => (form.userId = v));
    });

    const roleSetting = new Setting(root).setName("Role").addDropdown((d) => {
      for (const r of ROLE_OPTIONS) d.addOption(r.value, r.label);
      if (!ROLE_OPTIONS.some((r) => r.value === form.roleId)) d.addOption(form.roleId, form.roleId);
      d.setValue(form.roleId).onChange((v) => (form.roleId = v));
    });

    const applyPrincipalVisibility = () => {
      userSetting.settingEl.toggle(form.principalType === "user");
      roleSetting.settingEl.toggle(form.principalType === "role");
    };
    applyPrincipalVisibility();

    new Setting(root)
      .setName("Permission level")
      .setDesc("None = explicit deny; Read = view; Write = view + edit; Admin = full control.")
      .addDropdown((d) => {
        for (const o of LEVEL_OPTIONS) d.addOption(o.value, o.label);
        d.setValue(form.level).onChange((v) => (form.level = v as Level));
      });

    new Setting(root)
      .setName("Priority")
      .setDesc("Higher wins on conflicts. Blank = auto from path specificity.")
      .addText((t) => {
        t.setPlaceholder("auto").setValue(form.priority).onChange((v) => (form.priority = v));
        t.inputEl.type = "number";
        t.inputEl.min = "0";
        t.inputEl.step = "1";
      });

    new Setting(root)
      .setName("Expires (optional)")
      .setDesc("For time-bound access. Leave blank for never.")
      .addText((t) => {
        t.inputEl.type = "datetime-local";
        t.setValue(form.expiresAt);
        t.onChange((v) => (form.expiresAt = v));
      });

    const actions = root.createDiv({ cls: "vaultguard-rule-actions" });
    actions.createEl("button", { text: "Cancel" }).addEventListener("click", () => this.closeForm());
    const saveBtn = actions.createEl("button", {
      cls: "mod-cta",
      text: form.rule ? "Save changes" : "Create rule",
    });
    saveBtn.addEventListener("click", () => void this.handleSave(form, saveBtn));
  }

  private async handleSave(form: FormState, saveBtn: HTMLButtonElement): Promise<void> {
    const path = form.path.trim();
    if (!path) {
      new Notice("Path is required.");
      return;
    }

    let priority: number | undefined;
    if (form.priority.trim()) {
      priority = Number.parseInt(form.priority, 10);
      if (!Number.isInteger(priority) || priority < 0) {
        new Notice("Priority must be a whole number 0 or greater.");
        return;
      }
    }

    let expiresIso: string | null = null;
    if (form.expiresAt) {
      const d = new Date(form.expiresAt);
      if (Number.isNaN(d.getTime())) {
        new Notice("Invalid expiry date.");
        return;
      }
      expiresIso = d.toISOString();
    }

    const pathPattern = path.startsWith("/") ? path : `/${path}`;
    const payload: PermissionMutationInput = {
      pathPattern,
      actions: actionsForLevel(form.level),
      effect: form.level === "none" ? "deny" : "allow",
      userId: form.principalType === "user" ? form.userId : "*",
      role: form.principalType === "role" ? form.roleId : null,
      expiresAt: expiresIso,
      ...(priority !== undefined ? { priority } : {}),
    };

    saveBtn.disabled = true;
    saveBtn.textContent = "Saving…";
    try {
      if (form.rule) {
        await this.apiClient.updatePermission(form.rule.id, payload);
        new Notice("Permission rule updated.");
      } else {
        await this.apiClient.createPermission({ ...payload, upsert: true });
        new Notice("Permission rule created.");
      }
      this.onChanged();
      this.closeForm();
      await this.load();
    } catch (err) {
      new Notice(`Failed to save: ${err instanceof Error ? err.message : String(err)}`);
      saveBtn.disabled = false;
      saveBtn.textContent = form.rule ? "Save changes" : "Create rule";
    }
  }
}
