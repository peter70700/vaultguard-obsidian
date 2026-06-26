import { App, ButtonComponent, Modal, Notice, Setting } from "obsidian";
import {
  PathAccessPrincipal,
  PathAccessSummary,
  PermissionAccessLevel,
  PermissionMutationInput,
  PermissionRule,
  UserListEntry,
  VaultMemberRecord,
  VaultGuardApiClient,
} from "../api/client";
import {
  explainAccess,
  getPathSpecificity,
  pathMatchesPattern,
  type ExplainAction,
  type ExplainRule,
  type ExplainTrace,
  type ExplainVaultRole,
} from "./graph/permission-explain";

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

interface RuleDisplay {
  label: string;
  levelClass: string;
  mechanism: string;
  rawTitle: string;
}

export interface PermissionRulesCurrentUser {
  id?: string;
  orgRole?: string;
  roles?: string[];
  vaultRole?: string | null;
}

export interface PermissionRulesViewOptions {
  app: App;
  currentUser?: PermissionRulesCurrentUser;
  /** Optional search text to prefill when opening the rules overview. */
  initialSearch?: string;
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
  { value: "none", label: "No access" },
  { value: "read", label: "Read only" },
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

class PermissionRuleConfirmModal extends Modal {
  private resolved = false;

  constructor(
    app: App,
    private message: string,
    private resolvePromise: (value: boolean) => void
  ) {
    super(app);
  }

  onOpen(): void {
    const { contentEl } = this;
    contentEl.empty();
    contentEl.createEl("h3", { text: "Delete permission rule" });
    contentEl.createEl("p", { text: this.message });

    const buttons = contentEl.createDiv({ cls: "vaultguard-confirm-buttons" });
    new ButtonComponent(buttons)
      .setButtonText("Cancel")
      .onClick(() => this.finish(false));
    new ButtonComponent(buttons)
      .setButtonText("Delete")
      .setWarning()
      .onClick(() => this.finish(true));
  }

  onClose(): void {
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

function levelFromRule(rule: PermissionRule): Level {
  if (rule.effect === "deny") return deniedActionsCapLevel(rule.actions);
  if (rule.actions.includes("admin")) return "admin";
  if (rule.actions.includes("write") || rule.actions.includes("delete")) return "write";
  return "read";
}

function deniedActionsCapLevel(actions: PermissionRule["actions"]): Level {
  if (actions.includes("read") || actions.includes("list")) return "none";
  if (actions.includes("write") || actions.includes("delete")) return "read";
  if (actions.includes("admin")) return "write";
  return "none";
}

function formatLevelLabel(level: Level): string {
  switch (level) {
    case "none": return "No access";
    case "read": return "Read only";
    case "write": return "Write";
    case "admin": return "Admin";
  }
}

function actionList(actions: PermissionRule["actions"]): string {
  return actions.join(", ");
}

function describeRule(rule: PermissionRule): RuleDisplay {
  const rawTitle = `${rule.effect}: ${actionList(rule.actions)}`;

  if (rule.effect === "deny") {
    const level = deniedActionsCapLevel(rule.actions);
    if (level === "none") {
      return {
        label: "No access",
        levelClass: "vaultguard-level-none",
        mechanism: "Denies read/list plus editing actions.",
        rawTitle,
      };
    }
    if (level === "read") {
      return {
        label: "Read only",
        levelClass: "vaultguard-level-read",
        mechanism: "Denies write/delete/admin; read can remain.",
        rawTitle,
      };
    }
    return {
      label: "Write max",
      levelClass: "vaultguard-level-write",
      mechanism: "Denies admin; write/read can remain.",
      rawTitle,
    };
  }

  const level = levelFromRule(rule);
  if (level === "read") {
    return {
      label: "Read grant",
      levelClass: "vaultguard-level-read",
      mechanism: "Allows read/list only; inherited write may still apply.",
      rawTitle,
    };
  }

  return {
    label: formatLevelLabel(level),
    levelClass: `vaultguard-level-${level}`,
    mechanism: `Allows ${actionList(rule.actions)}.`,
    rawTitle,
  };
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

interface ExplanationState {
  path: string;
  loading: boolean;
  error: string | null;
  access: PathAccessSummary | null;
}

interface PrincipalReason {
  headline: string;
  steps: string[];
}

export class PermissionRulesView {
  private app: App;
  private apiClient: VaultGuardApiClient;
  private container: HTMLElement;
  private currentUser: PermissionRulesCurrentUser;
  private onChanged: () => void;

  private rules: PermissionRule[] = [];
  private users: UserListEntry[] = [];
  private members: VaultMemberRecord[] = [];
  private usersById: Map<string, UserListEntry> = new Map();
  private membersById: Map<string, VaultMemberRecord> = new Map();
  private search = "";
  private loadError: string | null = null;
  private loading = true;

  private mode: "table" | "form" = "table";
  private form: FormState | null = null;
  private rowsContainer: HTMLElement | null = null;
  private explanationContainer: HTMLElement | null = null;
  private explanation: ExplanationState | null = null;

  constructor(
    apiClient: VaultGuardApiClient,
    container: HTMLElement,
    options: PermissionRulesViewOptions
  ) {
    this.app = options.app;
    this.apiClient = apiClient;
    this.container = container;
    this.currentUser = options.currentUser ?? {};
    this.search = options.initialSearch ?? "";
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
      const vaultId = this.apiClient.getVaultId();
      const [rules, users, members] = await Promise.all([
        this.apiClient.getPermissions(),
        this.apiClient.listUsers().catch(() => [] as UserListEntry[]),
        vaultId ? this.apiClient.listVaultMembers(vaultId).catch(() => [] as VaultMemberRecord[]) : [],
      ]);
      this.rules = rules;
      this.users = users;
      this.members = members;
      this.usersById = new Map(users.map((u) => [u.id, u]));
      this.membersById = new Map(members.map((m) => [m.userId, m]));
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
        "Rules set access for matching vault members. No access blocks reading; Read only removes write/delete/admin; Write allows editing; Admin allows permission management. More specific child rules can override broader folder rules. Org admins bypass rules unless admin restrictions are enabled.",
    });

    const toolbar = root.createDiv({ cls: "vaultguard-rules-toolbar" });
    const searchInput = toolbar.createEl("input", {
      cls: "vaultguard-search-input",
      attr: { type: "text", placeholder: "Search by path, user, or role…" },
    });
    searchInput.value = this.search;
    searchInput.addEventListener("input", () => {
      this.search = searchInput.value;
      this.renderRows();
    });
    const addBtn = toolbar.createEl("button", { cls: "mod-cta", text: "Add rule" });
    addBtn.addEventListener("click", () => this.openForm(null));

    this.rowsContainer = root.createDiv({ cls: "vaultguard-rules-table-wrap" });
    this.renderRows();
    this.explanationContainer = root.createDiv({ cls: "vaultguard-rules-explain" });
    this.renderExplanation();
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
    for (const h of ["Path pattern", "Applies to", "Access", "Enforced by", "Priority", "Expires", ""]) {
      headRow.createEl("th", { text: h });
    }
    const tbody = table.createEl("tbody");
    for (const rule of rules) {
      const display = describeRule(rule);
      const tr = tbody.createEl("tr");
      tr.createEl("td").createEl("code", { text: rule.pathPattern });
      tr.createEl("td", { text: this.principalLabel(rule) });
      tr.createEl("td").createSpan({
        cls: `vaultguard-permission-badge ${display.levelClass}`,
        text: display.label,
        attr: { title: display.rawTitle },
      });
      tr.createEl("td", {
        cls: "vaultguard-rules-mechanism",
        text: display.mechanism,
        attr: { title: display.rawTitle },
      });
      tr.createEl("td", { cls: "vaultguard-rules-muted", text: String(rule.priority) });
      tr.createEl("td", {
        cls: "vaultguard-rules-muted",
        text: rule.expiresAt ? new Date(rule.expiresAt).toLocaleString() : "—",
      });
      const actionsTd = tr.createEl("td", { cls: "vaultguard-rules-row-actions" });
      actionsTd
        .createEl("button", { text: "Explain" })
        .addEventListener("click", () => void this.showExplanation(rule.pathPattern));
      actionsTd.createEl("button", { text: "Edit" }).addEventListener("click", () => this.openForm(rule));
      actionsTd
        .createEl("button", { cls: "mod-warning", text: "Delete" })
        .addEventListener("click", () => void this.handleDelete(rule));
    }
  }

  private async showExplanation(pathPattern: string): Promise<void> {
    const path = this.normalizeExplainPath(pathPattern);
    this.explanation = { path, loading: true, error: null, access: null };
    this.renderExplanation();
    try {
      const access = await this.apiClient.getPathAccess(path);
      this.explanation = { path, loading: false, error: null, access };
    } catch (err) {
      this.explanation = {
        path,
        loading: false,
        error: err instanceof Error ? err.message : String(err),
        access: null,
      };
    }
    this.renderExplanation();
  }

  private renderExplanation(): void {
    const c = this.explanationContainer;
    if (!c) return;
    c.empty();

    if (!this.explanation) {
      c.createDiv({
        cls: "vaultguard-rules-explain-empty",
        text: "Click Explain on a rule to see the backend's effective access for that path and why each user ends up with that level.",
      });
      return;
    }

    const { path, loading, error, access } = this.explanation;
    const header = c.createDiv({ cls: "vaultguard-rules-explain-header" });
    const title = header.createDiv();
    title.createEl("h4", { text: "Effective access explanation" });
    title.createEl("code", { text: path });
    header
      .createEl("button", { text: "Close" })
      .addEventListener("click", () => {
        this.explanation = null;
        this.renderExplanation();
      });

    c.createDiv({
      cls: "setting-item-description",
      text:
        "This is the server's current answer for the path. Rules are checked by path specificity first, then deny beats allow at the same path, then priority breaks remaining ties. If no rule decides an action, the user's vault role supplies the baseline.",
    });

    this.renderMatchingRules(c, path);

    if (loading) {
      c.createDiv({ cls: "vaultguard-empty-state", text: "Loading effective access..." });
      return;
    }
    if (error) {
      c.createDiv({ cls: "vaultguard-error-text", text: `Failed to explain path: ${error}` });
      return;
    }
    if (!access) return;

    this.renderEffectiveAccess(c, access);
  }

  private renderMatchingRules(container: HTMLElement, path: string): void {
    const matches = this.matchingRulesForPath(path);
    const hasReadGrant = matches.some((rule) => {
      const display = describeRule(rule);
      return display.label === "Read grant";
    });

    if (hasReadGrant) {
      container.createDiv({
        cls: "vaultguard-rules-explain-warning",
        text:
          "This path has a Read grant. A read grant is additive: it allows read/list, but it does not remove write from editors or admins. To make something read-only, the stored rule must show as Read only and deny write/delete/admin.",
      });
    }

    container.createEl("h5", { text: "Matching rules, highest precedence first" });
    if (matches.length === 0) {
      container.createDiv({
        cls: "vaultguard-rules-explain-empty",
        text: "No rule matches this path. Access comes from vault membership roles only.",
      });
      return;
    }

    const table = container.createEl("table", { cls: "vaultguard-rules-table vaultguard-rules-explain-rules" });
    const headRow = table.createEl("thead").createEl("tr");
    for (const h of ["Rule", "Applies to", "Access", "Precedence"]) {
      headRow.createEl("th", { text: h });
    }
    const tbody = table.createEl("tbody");
    for (const rule of matches) {
      const display = describeRule(rule);
      const tr = tbody.createEl("tr");
      tr.createEl("td").createEl("code", { text: rule.pathPattern });
      tr.createEl("td", { text: this.principalLabel(rule) });
      tr.createEl("td").createSpan({
        cls: `vaultguard-permission-badge ${display.levelClass}`,
        text: display.label,
        attr: { title: display.rawTitle },
      });
      tr.createEl("td", {
        cls: "vaultguard-rules-muted",
        text: `specificity ${getPathSpecificity(rule.pathPattern)}, priority ${rule.priority}, ${rule.effect}`,
      });
    }
  }

  private renderEffectiveAccess(container: HTMLElement, access: PathAccessSummary): void {
    container.createEl("h5", { text: "Effective access by user" });
    if (access.principals.length === 0) {
      container.createDiv({
        cls: "vaultguard-rules-explain-empty",
        text: "The server did not return a user list because the current account cannot read this path.",
      });
      return;
    }

    const table = container.createEl("table", { cls: "vaultguard-rules-table vaultguard-rules-explain-users" });
    const headRow = table.createEl("thead").createEl("tr");
    for (const h of ["User", "Vault role", "Effective", "Why"]) {
      headRow.createEl("th", { text: h });
    }
    const tbody = table.createEl("tbody");
    const principals = [...access.principals].sort(
      (a, b) => this.levelRank(b.level) - this.levelRank(a.level) || this.principalName(a).localeCompare(this.principalName(b))
    );
    for (const principal of principals) {
      const reason = this.explainPrincipal(access.path || this.explanation?.path || "", principal);
      const tr = tbody.createEl("tr");
      tr.createEl("td", { text: this.principalName(principal) });
      tr.createEl("td", { cls: "vaultguard-rules-muted", text: this.roleForPrincipal(principal) });
      tr.createEl("td").createSpan({
        cls: `vaultguard-permission-badge vaultguard-level-${principal.level}`,
        text: formatLevelLabel(principal.level),
      });
      const why = tr.createEl("td", { cls: "vaultguard-rules-explain-why" });
      why.createDiv({ text: reason.headline });
      const details = why.createEl("details", { cls: "vaultguard-rules-trace" });
      details.createEl("summary", { text: "Trace" });
      const list = details.createEl("ul");
      for (const step of reason.steps) list.createEl("li", { text: step });
    }
  }

  private explainPrincipal(path: string, principal: PathAccessPrincipal): PrincipalReason {
    const role = this.roleForPrincipal(principal);
    const action = this.actionToExplain(principal.level);
    const rules = this.rulesForPrincipal(principal.userId, role);
    const trace = explainAccess({
      userId: principal.userId,
      role,
      orgRoles: this.orgRolesForPrincipal(principal.userId),
      path,
      action,
      rules,
    });

    return {
      headline: this.summarizeTrace(trace, principal.level, action, principal),
      steps: trace.steps,
    };
  }

  private summarizeTrace(
    trace: ExplainTrace,
    serverLevel: PermissionAccessLevel,
    action: ExplainAction,
    principal: PathAccessPrincipal
  ): string {
    if (trace.decidedBy === "adminBypass") {
      return "Admin bypass grants full access before path rules are consulted.";
    }

    const role = this.roleForPrincipal(principal);
    const actionLabel = this.actionLabel(action);
    if (serverLevel === "read") {
      if (trace.decidedBy === "rule" && trace.winningRuleId) {
        const rule = this.rules.find((r) => r.id === trace.winningRuleId);
        return rule
          ? `Read only because editing is blocked by the ${describeRule(rule).label} rule on ${rule.pathPattern}.`
          : "Read only because a matching rule blocks editing.";
      }
      return `Read only because no matching rule grants editing beyond the ${role} vault role.`;
    }

    if (trace.decidedBy === "roleBaseline") {
      if (serverLevel === "none") {
        return `No access because no matching rule or ${role} vault role grants read.`;
      }
      return `${formatLevelLabel(serverLevel)} comes from the ${role} vault role; no matching ${actionLabel} rule changed it.`;
    }

    const rule = trace.winningRuleId ? this.rules.find((r) => r.id === trace.winningRuleId) : null;
    if (rule) {
      const display = describeRule(rule);
      const verb = rule.effect === "deny" ? "blocks" : "grants";
      return `${formatLevelLabel(serverLevel)} because ${display.label} on ${rule.pathPattern} ${verb} ${actionLabel}.`;
    }

    return `${formatLevelLabel(serverLevel)} according to the backend effective-access check.`;
  }

  private matchingRulesForPath(path: string): PermissionRule[] {
    return this.rules
      .filter((rule) => pathMatchesPattern(path, rule.pathPattern) && !this.isRuleExpired(rule))
      .sort((a, b) => {
        const specificityDiff = getPathSpecificity(b.pathPattern) - getPathSpecificity(a.pathPattern);
        if (specificityDiff !== 0) return specificityDiff;
        if (a.effect === "deny" && b.effect === "allow") return -1;
        if (a.effect === "allow" && b.effect === "deny") return 1;
        return b.priority - a.priority;
      });
  }

  private isRuleExpired(rule: PermissionRule): boolean {
    if (!rule.expiresAt) return false;
    const expiresMs = Date.parse(rule.expiresAt);
    return Number.isFinite(expiresMs) && expiresMs <= Date.now();
  }

  private rulesForPrincipal(userId: string, role: ExplainVaultRole): ExplainRule[] {
    return this.rules
      .filter((rule) => rule.userId === userId || rule.userId === "*" || rule.role === role)
      .map((rule) => ({
        id: rule.id,
        userId: rule.userId,
        role: rule.role,
        pathPattern: rule.pathPattern,
        actions: rule.actions,
        effect: rule.effect,
        priority: rule.priority,
        expiresAt: rule.expiresAt,
      }));
  }

  private normalizeExplainPath(pathPattern: string): string {
    const trimmed = pathPattern.trim() || "/";
    return trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
  }

  private principalName(principal: PathAccessPrincipal): string {
    const user = this.usersById.get(principal.userId);
    return principal.displayName || user?.displayName || principal.email || user?.email || principal.userId;
  }

  private roleForPrincipal(principal: PathAccessPrincipal): ExplainVaultRole {
    const raw = principal.role ?? this.membersById.get(principal.userId)?.role ?? (
      principal.userId === this.currentUser.id ? this.currentUser.vaultRole : null
    );
    return raw === "admin" || raw === "editor" || raw === "viewer" ? raw : "viewer";
  }

  private orgRolesForPrincipal(userId: string): string[] {
    const user = this.usersById.get(userId);
    const roles: string[] = [];
    if (user?.role) roles.push(user.role);
    if (userId === this.currentUser.id) {
      if (this.currentUser.orgRole) roles.push(this.currentUser.orgRole);
      roles.push(...(this.currentUser.roles ?? []));
    }
    return roles;
  }

  private actionToExplain(level: PermissionAccessLevel): ExplainAction {
    switch (level) {
      case "admin": return "admin";
      case "write": return "write";
      case "read": return "write";
      case "none": return "read";
    }
  }

  private actionLabel(action: ExplainAction): string {
    switch (action) {
      case "admin": return "permission-management";
      case "write": return "editing";
      case "delete": return "delete";
      case "list": return "list";
      case "read": return "read";
    }
  }

  private levelRank(level: PermissionAccessLevel): number {
    switch (level) {
      case "admin": return 3;
      case "write": return 2;
      case "read": return 1;
      default: return 0;
    }
  }

  private filteredRules(): PermissionRule[] {
    const q = this.search.trim().toLowerCase();
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
    const ok = await this.confirmDelete(
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

  private confirmDelete(message: string): Promise<boolean> {
    return new Promise((resolve) => {
      new PermissionRuleConfirmModal(this.app, message, resolve).open();
    });
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
      .setDesc("Folder paths like /team/ apply to children. Use * for one segment and ** for recursive globs.")
      .addText((t) =>
        t
          .setPlaceholder("/engineering/** or /docs/spec.md")
          .setValue(form.path)
          .onChange((v) => (form.path = v))
      );

    new Setting(root)
      .setName("Principal type")
      .setDesc("Choose one user, all users, or a vault role.")
      .addDropdown((d) =>
      d
        .addOption("user", "User")
        .addOption("role", "Role")
        .setValue(form.principalType)
        .onChange((v) => {
          form.principalType = v as "user" | "role";
          applyPrincipalVisibility();
        })
    );

    const userSetting = new Setting(root).setName("User / all users").addDropdown((d) => {
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
      .setDesc("No access blocks reading. Read only blocks editing. More specific child rules and admin bypass can still affect the final result.")
      .addDropdown((d) => {
        for (const o of LEVEL_OPTIONS) d.addOption(o.value, o.label);
        d.setValue(form.level).onChange((v) => (form.level = v as Level));
      });

    new Setting(root)
      .setName("Priority")
      .setDesc("Advanced conflict breaker for rules on the same path. Leave blank for normal folder/file behavior.")
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
    const userId = form.principalType === "user" ? form.userId : "*";
    const role = form.principalType === "role" ? form.roleId : null;
    const payload: PermissionMutationInput = {
      pathPattern,
      actions: actionsForLevel(form.level),
      effect: form.level === "none" ? "deny" : "allow",
      userId,
      role,
      expiresAt: expiresIso,
      ...(priority !== undefined ? { priority } : {}),
    };
    const existingTargetUnchanged = !form.rule || (
      form.rule.pathPattern === pathPattern &&
      (form.rule.role ? form.principalType === "role" && form.rule.role === form.roleId : form.principalType === "user" && form.rule.userId === form.userId)
    );
    const priorityChanged = form.rule
      ? priority !== undefined && priority !== form.rule.priority
      : priority !== undefined;
    const expiryInvolved = Boolean(form.expiresAt || form.rule?.expiresAt);
    const shouldSetExactLevel = existingTargetUnchanged && !priorityChanged && !expiryInvolved;

    saveBtn.disabled = true;
    saveBtn.textContent = "Saving…";
    try {
      if (shouldSetExactLevel) {
        await this.apiClient.setPermissionLevel({
          userId,
          role,
          pathPattern,
          level: form.level,
        });
        new Notice(form.rule ? "Permission level updated." : "Permission level set.");
      } else if (form.rule) {
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
