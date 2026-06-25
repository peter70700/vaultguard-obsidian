// PermissionsGraphView — the desktop "VaultGuard Permissions" ItemView.
//
// Renders an interactive cytoscape graph of users ↔ files/folders ↔ permissions
// for the connected vault, SCOPED TO THE VIEWER'S OWN PERMISSIONS. It never shows
// a file the viewer cannot read: the file set comes from getBatchPathAccess,
// whose backend returns empty principals when the caller can't read a path, and
// the pure data builder (permissions-graph-data.ts) omits any such path. A
// headline permission-EXPLAIN panel narrates the evaluatePermission precedence
// (permission-explain.ts) on node/edge tap.
//
// SECURITY / NETWORKING (CLAUDE.md):
//   - Zero client-side authorization: every datum is fetched as the signed-in
//     user via the authenticated VaultGuardApiClient (requestUrl underneath),
//     delegated through a plugin-provided PermissionsGraphDataSource. The backend
//     is the sole authority; the explain panel is narration only.
//   - NO raw fetch / EventSource / XMLHttpRequest anywhere (telemetry-policy).
//   - NO telemetry / phone-home. Works in BOTH editions (membership + permissions
//     are core, not Pro-gated).
//   - Online session required: with no session / offline, the view renders a
//     connect empty state and makes ZERO network calls.
//   - Desktop-only v1 (gated by the ribbon/command in main.ts).
//   - ALL chrome is built via Obsidian DOM helpers + CSS classes; there are NO
//     static element.style assignments (Obsidian-review rule). Cytoscape's own
//     canvas is styled through its selector stylesheet, not element.style.

import cytoscape from "cytoscape";
import {
  ItemView,
  Notice,
  WorkspaceLeaf,
  setIcon,
} from "obsidian";

import type VaultGuardPlugin from "../../plugin/main";
import type { PermissionRule } from "../../api/client";
import {
  ancestorFolders,
  buildGraphElements,
  colorForUser,
  type GraphAccessLevel,
  type GraphElement,
  type GraphMember,
  type GraphPathSummary,
  type GraphPrincipal,
} from "./permissions-graph-data";
import {
  explainAccess,
  type ExplainRule,
  type ExplainTrace,
  type ExplainVaultRole,
} from "./permission-explain";

export const VAULTGUARD_GRAPH_VIEW_TYPE = "vaultguard-permissions-graph";

// ─── Data source contract (provided by the plugin; see main.ts) ───────────────
//
// Each method delegates to the authenticated apiClient and fails closed if the
// client is null. The view never constructs an HTTP request itself.
export interface PermissionsGraphDataSource {
  listVaultMembers(vaultId: string): Promise<GraphMember[]>;
  getPermissions(): Promise<PermissionRule[]>;
  getUserPermissions(userId: string): Promise<PermissionRule[]>;
  getBatchPathAccess(paths: string[]): Promise<GraphPathSummary[]>;
  /** All vault-relative file paths visible to the plugin (sweep source). */
  getAllFilePaths(): string[];
}

// The raw fetched dataset for one vault — cached on the plugin (in-memory only,
// never written to disk) so reopening the panel renders instantly instead of
// re-sweeping every file's access over the network.
export interface PermissionsGraphDataset {
  members: GraphMember[];
  rules: PermissionRule[];
  summaries: GraphPathSummary[];
  /** Per-folder access summaries (access evaluated at each folder path). */
  folderSummaries: GraphPathSummary[];
  /** Files actually scanned (≤ SWEEP_CAP) and the vault's total file count. */
  scanned: number;
  total: number;
  truncated: boolean;
}

// ─── CSS class names (mirrors the `*_CLS` convention) ─────────────────────────
const ROOT_CLS = "vaultguard-permissions-graph";
const TOOLBAR_CLS = "vaultguard-pg-toolbar";
const LEGEND_CLS = "vaultguard-pg-legend";
const LEGEND_CHIP_CLS = "vaultguard-pg-legend-chip";
const LEGEND_CHIP_OFF_CLS = "is-off";
const LEGEND_SWATCH_CLS = "vaultguard-pg-legend-swatch";
const DEPTH_ROW_CLS = "vaultguard-pg-depth";
const DEPTH_LABEL_CLS = "vaultguard-pg-depth-label";
const BODY_CLS = "vaultguard-pg-body";
const CANVAS_CLS = "vaultguard-pg-canvas";
const EXPLAIN_CLS = "vaultguard-pg-explain";
const EXPLAIN_TITLE_CLS = "vaultguard-pg-explain-title";
const EXPLAIN_SUBTITLE_CLS = "vaultguard-pg-explain-subtitle";
const EXPLAIN_SECTION_CLS = "vaultguard-pg-explain-section";
const EXPLAIN_ROWS_CLS = "vaultguard-pg-explain-rows";
const EXPLAIN_ROW_CLS = "vaultguard-pg-explain-row";
const EXPLAIN_ROW_DOT_CLS = "vaultguard-pg-explain-row-dot";
const EXPLAIN_ROW_LABEL_CLS = "vaultguard-pg-explain-row-label";
const EXPLAIN_BACK_CLS = "vaultguard-pg-explain-back";
const EXPLAIN_BADGES_CLS = "vaultguard-pg-explain-badges";
const EXPLAIN_BADGE_CLS = "vaultguard-pg-explain-badge";
const EXPLAIN_STEPS_CLS = "vaultguard-pg-explain-steps";
const EXPLAIN_EMPTY_CLS = "vaultguard-pg-explain-empty";
const SEARCH_CLS = "vaultguard-pg-search";
const SEARCH_SCOPE_CLS = "vaultguard-pg-search-scope";
const SEARCH_COUNT_CLS = "vaultguard-pg-search-count";
const EMPTY_CLS = "vaultguard-pg-empty";
const EMPTY_ICON_CLS = "vaultguard-pg-empty-icon";
const NOTE_CLS = "vaultguard-pg-note";
const STATUS_CLS = "vaultguard-pg-status";

// Sweep bounds — mirror the chat access-sweep (agent-bridge.ts:295) so very
// large vaults render a bounded set with a "showing N files" note.
const SWEEP_CAP = 1000;
const BATCH_SIZE = 100; // server cap for POST /permissions/access/batch
// How many 100-path batches resolve concurrently. The old sequential sweep made
// ⌈N/100⌉ round-trips back-to-back (the dominant first-load cost); a small
// in-flight window cuts wall-clock without hammering the backend.
const SWEEP_CONCURRENCY = 6;

// Legend toggles map a label to the cytoscape class it filters. The access
// levels (read/write/admin) double as a colour key for the user→file edges.
const LEGEND_ITEMS: Array<{ key: string; label: string; swatch: "user" | "file" | "folder" | "read" | "write" | "admin" }> = [
  { key: "user", label: "Users", swatch: "user" },
  { key: "file", label: "Files", swatch: "file" },
  { key: "folder", label: "Folders", swatch: "folder" },
  { key: "read", label: "Read", swatch: "read" },
  { key: "write", label: "Write", swatch: "write" },
  { key: "admin", label: "Admin", swatch: "admin" },
];

const DEFAULT_DEPTH = 1;
const MAX_DEPTH = 4;

interface ViewerContext {
  userId: string;
  role: ExplainVaultRole;
  orgRoles: string[];
}

// Free-text search scope: "all" matches any node kind; the others narrow the
// match to a single kind (mirrors the node `data("kind")` values).
type SearchScope = "all" | "user" | "file" | "folder";

export class PermissionsGraphView extends ItemView {
  private cy: cytoscape.Core | null = null;
  private bodyEl: HTMLElement | null = null;
  private canvasEl: HTMLElement | null = null;
  private explainEl: HTMLElement | null = null;
  private statusEl: HTMLElement | null = null;
  private noteEl: HTMLElement | null = null;

  // Legend filter state: class → enabled.
  private readonly legendState = new Map<string, boolean>(
    LEGEND_ITEMS.map((item) => [item.key, true]),
  );
  private depth = DEFAULT_DEPTH;
  private focusedNodeId: string | null = null;
  // Free-text node filter (matches user/file/folder labels + paths).
  private searchQuery = "";
  // Which node kind the free-text filter is restricted to ("all" = any kind).
  private searchScope: SearchScope = "all";
  // The live result-count badge element + the last match count it reflects.
  private searchCountEl: HTMLElement | null = null;
  private lastSearchMatchCount: number | null = null;
  // Layout: "radial" = files/folders on inner rings, users around the outside
  // (the default); "force" = the organic force-directed spread.
  private layoutMode: "radial" | "force" = "radial";
  // Lets the per-permission trace offer a "← back" to the node list it came from.
  private lastExplainContext: { kind: "path" | "user"; key: string } | null = null;

  // Cached fetched data for click→explain narration.
  private rules: PermissionRule[] = [];
  private summaryByPath = new Map<string, GraphPathSummary>();
  // Paths that are folders (so the explain panel labels/handles them as such).
  private folderPathSet = new Set<string>();
  private memberById = new Map<string, GraphMember>();
  private viewer: ViewerContext | null = null;

  constructor(leaf: WorkspaceLeaf, private readonly plugin: VaultGuardPlugin) {
    super(leaf);
  }

  getViewType(): string {
    return VAULTGUARD_GRAPH_VIEW_TYPE;
  }

  getDisplayText(): string {
    return "VaultGuard Permissions";
  }

  getIcon(): string {
    // Stock lucide icon — pre-registered by Obsidian, renders everywhere.
    return "git-fork";
  }

  async onOpen(): Promise<void> {
    await this.render();
  }

  /**
   * Re-render the view from scratch. The plugin calls this whenever the backend
   * connection comes online (main.ts → setConnectionStatus). On launch the
   * "online" flip is deferred until the first sync, so a panel opened early
   * would otherwise stay pinned on the connect empty state forever; this lets it
   * populate itself the moment connectivity lands, with no user action.
   */
  async refresh(): Promise<void> {
    await this.render();
  }

  private async render(): Promise<void> {
    const container = (this.contentEl ??
      (this.containerEl.children[1] as HTMLElement)) as HTMLElement;
    // Tear down any prior render (cytoscape instance + cached state) so a
    // refresh doesn't leak the canvas or stack chrome on top of itself.
    this.teardown();
    container.empty();
    container.addClass(ROOT_CLS);

    // GATE: online session required. Each branch renders an empty state and
    // makes ZERO network calls — distinguishing "signed out" (sign in) from
    // "signed in but offline" (just waiting on the connection) so the panel
    // never tells an authenticated user to sign in.
    const session = this.plugin.getSession();
    const vaultId = this.plugin.settings.serverVaultId;
    if (!session) {
      this.renderEmptyState(container, "signed-out");
      return;
    }
    if (!vaultId) {
      this.renderEmptyState(container, "no-vault");
      return;
    }
    if (!this.plugin.isConnectedOnline()) {
      this.renderEmptyState(container, "offline");
      return;
    }

    this.viewer = {
      userId: session.userId,
      role: this.resolveViewerRole(),
      orgRoles: Array.isArray(session.roles) ? session.roles : [],
    };

    try {
      this.buildChrome(container);
      await this.loadAndRender(vaultId);
    } catch (err) {
      this.renderError(container, err);
    }
  }

  async onClose(): Promise<void> {
    this.teardown();
  }

  /** Destroy the cytoscape instance and drop all cached render state. */
  private teardown(): void {
    if (this.cy) {
      this.cy.destroy();
      this.cy = null;
    }
    this.bodyEl = null;
    this.canvasEl = null;
    this.explainEl = null;
    this.statusEl = null;
    this.noteEl = null;
    this.rules = [];
    this.summaryByPath.clear();
    this.folderPathSet.clear();
    this.memberById.clear();
    this.focusedNodeId = null;
    this.searchQuery = "";
    this.searchScope = "all";
    this.searchCountEl = null;
    this.lastSearchMatchCount = null;
    this.layoutMode = "radial";
    this.lastExplainContext = null;
    this.viewer = null;
  }

  // ─── Viewer role resolution ─────────────────────────────────────────────────

  private resolveViewerRole(): ExplainVaultRole {
    const session = this.plugin.getSession();
    const vaultRole = session?.vaultMemberRole;
    if (vaultRole === "admin" || vaultRole === "editor" || vaultRole === "viewer") {
      return vaultRole;
    }
    // Fall back to the org role mapped onto the vault role vocabulary.
    switch (session?.role) {
      case "admin":
      case "owner":
        return "admin";
      case "editor":
        return "editor";
      default:
        return "viewer";
    }
  }

  // ─── Empty / error states ───────────────────────────────────────────────────

  private renderEmptyState(
    container: HTMLElement,
    reason: "signed-out" | "offline" | "no-vault",
  ): void {
    const empty = container.createDiv({ cls: EMPTY_CLS });
    const icon = empty.createDiv({ cls: EMPTY_ICON_CLS });

    if (reason === "offline") {
      // The user IS signed in — don't tell them to sign in. The panel
      // re-renders itself automatically once the connection is restored.
      setIcon(icon, "cloud-off");
      empty.createEl("p", {
        text: "VaultGuard is offline — the permissions map needs a connection.",
      });
      empty.createEl("p", {
        cls: NOTE_CLS,
        text:
          "You're signed in. This panel will populate automatically once the " +
          "connection comes back. Until then it stays offline and makes no network calls.",
      });
      return;
    }

    if (reason === "no-vault") {
      setIcon(icon, "git-fork");
      empty.createEl("p", { text: "Select a VaultGuard vault to map its permissions." });
      empty.createEl("p", {
        cls: NOTE_CLS,
        text: "Choose a vault in VaultGuard settings, then reopen this panel.",
      });
      return;
    }

    setIcon(icon, "git-fork");
    empty.createEl("p", { text: "Connect VaultGuard to map your vault's permissions." });
    empty.createEl("p", {
      cls: NOTE_CLS,
      text:
        "Sign in and go online to see who can access which files. " +
        "Until then, this panel stays fully offline and makes no network calls.",
    });
  }

  private renderError(container: HTMLElement, err: unknown): void {
    container.empty();
    container.addClass(ROOT_CLS);
    const errEl = container.createDiv({ cls: EMPTY_CLS });
    const icon = errEl.createDiv({ cls: EMPTY_ICON_CLS });
    setIcon(icon, "alert-triangle");
    errEl.createEl("p", {
      text: `VaultGuard Permissions failed to load: ${(err as Error)?.message ?? String(err)}`,
    });
  }

  // ─── Chrome ─────────────────────────────────────────────────────────────────

  private buildChrome(container: HTMLElement): void {
    // Toolbar: legend (doubles as a type/effect filter) + depth control.
    const toolbar = container.createDiv({ cls: TOOLBAR_CLS });

    const legend = toolbar.createDiv({ cls: LEGEND_CLS });
    for (const item of LEGEND_ITEMS) {
      const chip = legend.createDiv({
        cls: LEGEND_CHIP_CLS,
        attr: { role: "button", tabindex: "0", "aria-label": `Toggle ${item.label}` },
      });
      chip.dataset.key = item.key;
      const swatch = chip.createSpan({ cls: `${LEGEND_SWATCH_CLS} is-${item.swatch}` });
      // Glyph for node types; edges use a colored bar (CSS).
      if (item.swatch === "user") setIcon(swatch, "user");
      else if (item.swatch === "file") setIcon(swatch, "file-text");
      else if (item.swatch === "folder") setIcon(swatch, "folder");
      chip.createSpan({ text: item.label });
      chip.addEventListener("click", () => this.toggleLegend(item.key, chip));
      chip.addEventListener("keydown", (evt) => {
        if (evt.key === "Enter" || evt.key === " ") {
          evt.preventDefault();
          this.toggleLegend(item.key, chip);
        }
      });
    }

    // Free-text filter: isolates users/files whose name (or path) matches.
    const search = toolbar.createDiv({ cls: SEARCH_CLS });
    const searchIcon = search.createSpan({ cls: "vaultguard-pg-search-icon" });
    setIcon(searchIcon, "search");

    // Scope selector: narrows the free-text match to a single node kind.
    // Sits before the input so it reads as "search [in People] for …".
    const scopeSelect = search.createEl("select", {
      cls: SEARCH_SCOPE_CLS,
      attr: { "aria-label": "Search scope" },
    });
    const scopeOptions: Array<{ value: SearchScope; text: string }> = [
      { value: "all", text: "All" },
      { value: "user", text: "People" },
      { value: "file", text: "Files" },
      { value: "folder", text: "Folders" },
    ];
    for (const opt of scopeOptions) {
      scopeSelect.createEl("option", { value: opt.value, text: opt.text });
    }
    scopeSelect.value = this.searchScope;

    // Placeholder mirrors the active scope so it's obvious the search is
    // narrowed to that kind (and that scoping works at all).
    const placeholderFor = (scope: SearchScope): string =>
      scope === "user"
        ? "Filter people…"
        : scope === "file"
          ? "Filter files…"
          : scope === "folder"
            ? "Filter folders…"
            : "Filter people, files, folders…";

    const searchInput = search.createEl("input", {
      attr: {
        type: "search",
        placeholder: placeholderFor(this.searchScope),
        "aria-label": "Filter graph",
      },
    });
    searchInput.addEventListener("input", () => {
      this.searchQuery = searchInput.value.trim().toLowerCase();
      this.applyFilters();
      // The layout is computed once and is static, so filtering alone just
      // leaves the matched nodes wherever they were — frequently off-screen on
      // a large vault, which reads as "search does nothing". Pan/zoom to the
      // surviving nodes so the match is actually brought into view. When the
      // query is cleared, this fits the whole graph back into frame.
      this.fitToVisible();
    });

    scopeSelect.addEventListener("change", () => {
      this.searchScope = scopeSelect.value as SearchScope;
      searchInput.placeholder = placeholderFor(this.searchScope);
      this.applyFilters();
      this.fitToVisible();
    });

    // Live result-count badge: applyFilters() drives its text/visibility.
    this.searchCountEl = search.createSpan({ cls: SEARCH_COUNT_CLS });
    this.updateSearchFeedback();

    const depthRow = toolbar.createDiv({ cls: DEPTH_ROW_CLS });
    depthRow.createSpan({ cls: DEPTH_LABEL_CLS, text: "Focus depth" });
    const slider = depthRow.createEl("input", {
      attr: {
        type: "range",
        min: "1",
        max: String(MAX_DEPTH),
        value: String(this.depth),
        "aria-label": "Focus depth",
      },
    });
    const depthValue = depthRow.createSpan({ cls: DEPTH_LABEL_CLS, text: String(this.depth) });
    slider.addEventListener("input", () => {
      this.depth = Number(slider.value) || DEFAULT_DEPTH;
      depthValue.setText(String(this.depth));
      this.applyFocus();
    });

    const resetBtn = depthRow.createSpan({
      cls: "clickable-icon",
      attr: { "aria-label": "Reset focus", title: "Reset focus" },
    });
    setIcon(resetBtn, "expand");
    resetBtn.addEventListener("click", () => {
      this.focusedNodeId = null;
      this.applyFilters();
      this.cy?.fit(undefined, 24);
    });

    // Refresh: drop the cache and re-fetch from the server (the graph is cached
    // in memory, so reopening is instant; this is the manual "get latest" path).
    const refreshBtn = depthRow.createSpan({
      cls: "clickable-icon",
      attr: { "aria-label": "Refresh permissions", title: "Refresh permissions" },
    });
    setIcon(refreshBtn, "refresh-cw");
    refreshBtn.addEventListener("click", () => void this.forceReload());

    // Layout toggle: radial (files inside, users around the outside) ⇄ force.
    const layoutBtn = depthRow.createSpan({
      cls: "clickable-icon",
      attr: { "aria-label": "Toggle layout", title: "Toggle layout: radial / force" },
    });
    const syncLayoutIcon = (): void =>
      setIcon(layoutBtn, this.layoutMode === "radial" ? "target" : "git-fork");
    syncLayoutIcon();
    layoutBtn.addEventListener("click", () => {
      this.layoutMode = this.layoutMode === "radial" ? "force" : "radial";
      syncLayoutIcon();
      this.runLayout();
    });

    // Body: cytoscape canvas + explain side panel.
    this.bodyEl = container.createDiv({ cls: BODY_CLS });
    this.canvasEl = this.bodyEl.createDiv({ cls: CANVAS_CLS });
    this.explainEl = this.bodyEl.createDiv({ cls: EXPLAIN_CLS });
    this.renderExplainEmpty();

    // Status / "showing N files" note line.
    this.noteEl = container.createDiv({ cls: NOTE_CLS });
    this.statusEl = container.createDiv({ cls: STATUS_CLS });
  }

  // ─── Data load + render ─────────────────────────────────────────────────────

  private async loadAndRender(vaultId: string, force = false): Promise<void> {
    // Use the plugin's cache (memory, then the encrypted on-disk envelope) so
    // reopening — even after a restart — is instant; only hit the network on
    // first load, after the TTL, or on an explicit refresh.
    const cached = force ? null : await this.plugin.loadPersistedPermissionsGraphCache(vaultId);
    const dataset = cached ?? (await this.fetchDataset(vaultId));
    if (!cached) void this.plugin.setPermissionsGraphCache(vaultId, dataset);

    this.rules = dataset.rules;
    this.memberById = new Map(dataset.members.map((m) => [m.userId, m]));
    const folderSummaries = dataset.folderSummaries ?? [];
    // Files + folders share one lookup (paths never collide); the folder set
    // lets the explain panel label folders as folders.
    this.summaryByPath = new Map(
      [...dataset.summaries, ...folderSummaries].map((s) => [normalizePath(s.path), s]),
    );
    this.folderPathSet = new Set(folderSummaries.map((s) => normalizePath(s.path)));

    const elements = buildGraphElements({
      vaultId,
      members: dataset.members,
      summaries: dataset.summaries,
      folderSummaries,
      rules: dataset.rules as ExplainRule[],
    });

    this.renderGraph(elements);

    // Visible-file count note (and truncation warning for large vaults).
    const readableCount = dataset.summaries.filter((s) => s.principals && s.principals.length > 0).length;
    const cacheSuffix = cached ? " · cached" : "";
    this.setNote(
      dataset.truncated
        ? `Showing ${readableCount} readable file(s) of the first ${dataset.scanned} scanned (vault has ${dataset.total}; capped for performance).${cacheSuffix}`
        : `Showing ${readableCount} readable file(s).${cacheSuffix}`,
    );
    this.setStatus("");
  }

  /** Fetch the raw dataset: members + rules + a parallel access sweep of files AND folders. */
  private async fetchDataset(vaultId: string): Promise<PermissionsGraphDataset> {
    const source = this.plugin.getPermissionsGraphDataSource();
    this.setStatus("Loading members and permissions…");

    // Members + rules (rules drive the expiring/dashed determination + explain).
    const [members, rules] = await Promise.all([
      source.listVaultMembers(vaultId),
      source.getPermissions().catch(() => [] as PermissionRule[]),
    ]);

    // Sweep the viewer's visible files, bounded by the cap.
    const allPaths = source.getAllFilePaths();
    const capped = allPaths.slice(0, SWEEP_CAP);
    const truncated = allPaths.length > capped.length;

    this.setStatus(`Resolving access for ${capped.length} file(s)…`);
    const summaries = await this.sweepAccess(source, capped, "file");

    // Folders: evaluate access at each ancestor folder of a readable file, so
    // folder-level grants show up as user→folder edges just like files.
    const readable = summaries.filter((s) => s.principals && s.principals.length > 0);
    const folderPaths = Array.from(
      new Set(readable.flatMap((s) => ancestorFolders(normalizePath(s.path)))),
    ).slice(0, SWEEP_CAP);

    let folderSummaries: GraphPathSummary[] = [];
    if (folderPaths.length > 0) {
      this.setStatus(`Resolving access for ${folderPaths.length} folder(s)…`);
      folderSummaries = await this.sweepAccess(source, folderPaths, "folder");
    }

    return {
      members,
      rules,
      summaries,
      folderSummaries,
      scanned: capped.length,
      total: allPaths.length,
      truncated,
    };
  }

  /** Resolve access for a set of paths in bounded-concurrency batches of 100. */
  private async sweepAccess(
    source: PermissionsGraphDataSource,
    paths: string[],
    noun: string,
  ): Promise<GraphPathSummary[]> {
    const chunks: string[][] = [];
    for (let i = 0; i < paths.length; i += BATCH_SIZE) {
      chunks.push(paths.slice(i, i + BATCH_SIZE));
    }
    const summaries: GraphPathSummary[] = [];
    for (let i = 0; i < chunks.length; i += SWEEP_CONCURRENCY) {
      const group = chunks.slice(i, i + SWEEP_CONCURRENCY);
      const results = await Promise.all(group.map((c) => source.getBatchPathAccess(c)));
      for (const r of results) summaries.push(...r);
      const done = Math.min((i + SWEEP_CONCURRENCY) * BATCH_SIZE, paths.length);
      this.setStatus(`Resolving access for ${done} of ${paths.length} ${noun}(s)…`);
    }
    return summaries;
  }

  /** Force-refresh: drop the cache for this vault and re-fetch from the server. */
  private async forceReload(): Promise<void> {
    const vaultId = this.plugin.settings.serverVaultId;
    if (!vaultId) return;
    this.plugin.invalidatePermissionsGraphCache(vaultId);
    try {
      await this.loadAndRender(vaultId, true);
    } catch (err) {
      this.setStatus("");
      new Notice(`VaultGuard: couldn't refresh the permissions graph: ${(err as Error)?.message ?? String(err)}`);
    }
  }

  // Layout options for the current mode. Radial = a concentric arrangement with
  // folders at the centre, their files in the middle ring, and users spread
  // around the outer ring (so people sit "outside the circle of files", on all
  // sides). Force = the organic cose spread.
  private buildLayout(): cytoscape.LayoutOptions {
    if (this.layoutMode === "force") {
      return {
        name: "cose",
        animate: true,
        animationDuration: 700,
        padding: 30,
        nodeDimensionsIncludeLabels: true,
        randomize: true,
        fit: true,
        componentSpacing: 80,
        gravity: 0.25,
        numIter: 1200,
        nodeRepulsion: () => 9000,
        idealEdgeLength: () => 90,
        edgeElasticity: () => 80,
      } as cytoscape.LayoutOptions;
    }

    return {
      name: "concentric",
      animate: true,
      animationDuration: 600,
      padding: 36,
      fit: true,
      avoidOverlap: true,
      minNodeSpacing: 22,
      startAngle: (3 / 2) * Math.PI, // start at top
      // Higher value = closer to the centre: folders (3) → files (2) → users (1).
      concentric: (node: cytoscape.NodeSingular) => {
        const kind = node.data("kind") as string | undefined;
        if (kind === "folder") return 3;
        if (kind === "file") return 2;
        return 1; // users (and anything else) form the outer ring
      },
      levelWidth: () => 1, // each distinct value is its own ring
    } as unknown as cytoscape.LayoutOptions;
  }

  /** Re-run the layout in place (after a mode toggle) without rebuilding cytoscape. */
  private runLayout(): void {
    if (!this.cy) return;
    this.cy.layout(this.buildLayout()).run();
  }

  private renderGraph(elements: GraphElement[]): void {
    if (!this.canvasEl) return;
    if (this.cy) {
      this.cy.destroy();
      this.cy = null;
    }

    this.cy = cytoscape({
      container: this.canvasEl,
      elements: elements as cytoscape.ElementDefinition[],
      style: this.buildStylesheet(),
      layout: this.buildLayout(),
      wheelSensitivity: 0.2,
      minZoom: 0.1,
      maxZoom: 3,
    });

    // Tap a node or edge → narrate the precedence into the explain panel and
    // focus the graph on that node.
    this.cy.on("tap", "node", (evt: cytoscape.EventObjectNode) => {
      const node = evt.target;
      this.focusedNodeId = node.id();
      this.applyFocus();
      this.explainForNode(node);
    });
    this.cy.on("tap", "edge", (evt: cytoscape.EventObjectEdge) => {
      this.explainForEdge(evt.target);
    });
    // Tap the background → clear focus.
    this.cy.on("tap", (evt: cytoscape.EventObject) => {
      if (evt.target === this.cy) {
        this.focusedNodeId = null;
        this.applyFilters();
      }
    });

    // Hover-highlight neighbors — native graph's signature interaction. On
    // pointer-over, fade everything outside the hovered node's closed
    // neighborhood and emphasise the rest; restore on pointer-out. Kept on a
    // separate class from the click→focus dim so the two never clobber.
    this.cy.on("mouseover", "node", (evt: cytoscape.EventObjectNode) => {
      this.hoverHighlight(evt.target);
    });
    this.cy.on("mouseout", "node", () => this.clearHover());

    this.applyFilters();
  }

  // ─── Hover highlight ──────────────────────────────────────────────────────
  private hoverHighlight(node: cytoscape.NodeSingular): void {
    if (!this.cy) return;
    const cy = this.cy;
    const neighborhood = node.closedNeighborhood();
    cy.batch(() => {
      cy.elements().difference(neighborhood).addClass("vg-faded");
      neighborhood.addClass("vg-hl");
    });
  }

  private clearHover(): void {
    if (!this.cy) return;
    const cy = this.cy;
    cy.batch(() => {
      cy.elements().removeClass("vg-faded");
      cy.elements().removeClass("vg-hl");
    });
  }

  // ─── Selector stylesheet (cytoscape canvas styling — NOT element.style) ──────
  //
  // Colors read from Obsidian CSS variables via getComputedStyle so the graph
  // themes with light/dark. Only allow=green / deny=red are semantic hardcodes.
  private buildStylesheet(): cytoscape.StylesheetJson {
    const cssVar = (name: string, fallback: string): string => {
      try {
        const v = getComputedStyle(document.body).getPropertyValue(name).trim();
        return v || fallback;
      } catch {
        return fallback;
      }
    };

    const textColor = cssVar("--text-normal", "#dcdde1");
    const mutedColor = cssVar("--text-muted", "#888");
    const accent = cssVar("--interactive-accent", "#7b6cd9");
    const bgSecondary = cssVar("--background-secondary", "#2a2a2a");
    const fileColor = cssVar("--color-blue", "#4a8fe7");
    const folderColor = cssVar("--background-modifier-border", "#444");
    // Access-level edge colours: read → green, write → amber, admin → purple.
    // Each user→file line is coloured to the exact level that user has.
    const readColor = cssVar("--color-green", "#3aa757");
    const writeColor = cssVar("--color-yellow", "#e0a526");
    const adminColor = cssVar("--color-purple", "#a371e0");
    const denyColor = cssVar("--color-red", "#d64545");

    return [
      // Base node: a circular dot with its label BELOW it (native-graph style),
      // fading the label out when zoomed far out so the canvas stays legible.
      {
        selector: "node",
        style: {
          shape: "ellipse",
          width: 16,
          height: 16,
          "background-color": fileColor,
          "border-width": 0,
          label: "data(label)",
          color: textColor,
          "font-size": 10,
          "text-valign": "bottom",
          "text-halign": "center",
          "text-margin-y": 4,
          "text-wrap": "ellipsis",
          "text-max-width": "110px",
          "min-zoomed-font-size": 7,
        },
      } as cytoscape.StylesheetStyle,
      {
        selector: "node.vault",
        style: {
          "background-color": accent,
          width: 38,
          height: 38,
          "border-width": 2,
          "border-color": accent,
          "border-opacity": 0.4,
          color: textColor,
          "font-size": 12,
          "font-weight": "bold",
        },
      } as cytoscape.StylesheetStyle,
      {
        selector: "node.folder",
        style: {
          // Rounded SQUARE (not a dot) + muted fill so folders are obviously
          // structural containers, never mistaken for the circular file/user dots.
          shape: "round-rectangle",
          "background-color": folderColor,
          "background-opacity": 0.85,
          "border-width": 1,
          "border-color": mutedColor,
          width: 20,
          height: 20,
          color: mutedColor,
        },
      } as cytoscape.StylesheetStyle,
      {
        selector: "node.user",
        style: {
          // Each user gets a distinct, deterministic colour (data(color) from
          // the builder) so users are tellable apart at a glance. Size scales
          // with how many files they touch (degree) — busier users read bigger.
          "background-color": "data(color)",
          width: (ele: cytoscape.NodeSingular) => 22 + Math.min(ele.degree(true), 14) * 1.6,
          height: (ele: cytoscape.NodeSingular) => 22 + Math.min(ele.degree(true), 14) * 1.6,
          "font-weight": "bold",
        },
      } as unknown as cytoscape.StylesheetStyle,
      {
        selector: "node.file",
        style: {
          "background-color": fileColor,
          // Size scales with how many users can reach the file.
          width: (ele: cytoscape.NodeSingular) => 13 + Math.min(ele.degree(true), 12) * 1.2,
          height: (ele: cytoscape.NodeSingular) => 13 + Math.min(ele.degree(true), 12) * 1.2,
        },
      } as unknown as cytoscape.StylesheetStyle,
      {
        selector: "edge",
        style: {
          width: 1.5,
          "curve-style": "bezier",
          "line-color": mutedColor,
          "target-arrow-color": mutedColor,
          "target-arrow-shape": "triangle",
          "arrow-scale": 0.8,
        },
      } as cytoscape.StylesheetStyle,
      // Label mapping is scoped to edges that actually carry a `label` (permission
      // edges = the access level). Containment edges have no `label` data field;
      // applying `data(label)` to them makes cytoscape warn "no mapping for
      // property `label`", so the `[label]` selector limits it to labelled edges.
      {
        selector: "edge[label]",
        style: {
          label: "data(label)",
          "font-size": 9,
          color: mutedColor,
          "text-rotation": "autorotate",
          "text-background-color": bgSecondary,
          "text-background-opacity": 0.8,
          "text-background-padding": "2px",
          "min-zoomed-font-size": 8,
        },
      } as cytoscape.StylesheetStyle,
      // Containment edges (folder→folder→file): faint, arrow-less hierarchy
      // links — they recede so the user→file permission edges read first.
      {
        selector: "edge.containment",
        style: {
          width: 1,
          "line-color": folderColor,
          "line-opacity": 0.45,
          "target-arrow-shape": "none",
        },
      } as cytoscape.StylesheetStyle,
      // Permission edges, coloured by the resolved access level so every line
      // from a user matches exactly what they can do to that file.
      {
        selector: "edge.level-read",
        style: {
          "line-color": readColor,
          "target-arrow-color": readColor,
        },
      } as cytoscape.StylesheetStyle,
      {
        selector: "edge.level-write",
        style: {
          "line-color": writeColor,
          "target-arrow-color": writeColor,
          width: 2,
        },
      } as cytoscape.StylesheetStyle,
      {
        selector: "edge.level-admin",
        style: {
          "line-color": adminColor,
          "target-arrow-color": adminColor,
          width: 2.5,
        },
      } as cytoscape.StylesheetStyle,
      // Forward-compat: an explicit-deny edge, should the server ever surface one.
      {
        selector: "edge.deny",
        style: {
          "line-color": denyColor,
          "target-arrow-color": denyColor,
        },
      } as cytoscape.StylesheetStyle,
      {
        selector: "edge.expiring",
        style: {
          "line-style": "dashed",
        },
      } as cytoscape.StylesheetStyle,
      // Hover highlight: emphasise the hovered neighborhood, fade the rest.
      {
        selector: "node.vg-hl",
        style: {
          "border-width": 3,
          "border-color": accent,
          "border-opacity": 0.9,
        },
      } as cytoscape.StylesheetStyle,
      {
        selector: "edge.vg-hl",
        style: {
          width: 2.5,
        },
      } as cytoscape.StylesheetStyle,
      {
        selector: ".vg-faded",
        style: {
          opacity: 0.1,
        },
      } as cytoscape.StylesheetStyle,
      {
        selector: ".vg-dimmed",
        style: {
          opacity: 0.12,
        },
      } as cytoscape.StylesheetStyle,
      {
        selector: ".vg-hidden",
        style: {
          display: "none",
        },
      } as cytoscape.StylesheetStyle,
    ];
  }

  // ─── Legend filter ──────────────────────────────────────────────────────────

  private toggleLegend(key: string, chip: HTMLElement): void {
    const next = !(this.legendState.get(key) ?? true);
    this.legendState.set(key, next);
    chip.toggleClass(LEGEND_CHIP_OFF_CLS, !next);
    this.applyFilters();
  }

  /** Apply legend visibility, then the depth focus (focus narrows the visible set). */
  private applyFilters(): void {
    if (!this.cy) return;
    const showUsers = this.legendState.get("user") ?? true;
    const showFiles = this.legendState.get("file") ?? true;
    const showFolders = this.legendState.get("folder") ?? true;
    const showRead = this.legendState.get("read") ?? true;
    const showWrite = this.legendState.get("write") ?? true;
    const showAdmin = this.legendState.get("admin") ?? true;

    this.cy.batch(() => {
      this.cy?.elements().removeClass("vg-hidden");

      if (!showUsers) this.cy?.nodes(".user").addClass("vg-hidden");
      if (!showFiles) this.cy?.nodes(".file").addClass("vg-hidden");
      if (!showFolders) this.cy?.nodes(".folder").addClass("vg-hidden");
      if (!showRead) this.cy?.edges(".level-read").addClass("vg-hidden");
      if (!showWrite) this.cy?.edges(".level-write").addClass("vg-hidden");
      if (!showAdmin) this.cy?.edges(".level-admin").addClass("vg-hidden");

      // Free-text filter: keep nodes whose label/path matches the query AND
      // their direct connections — so searching a file keeps the users who can
      // reach it, and searching a user keeps the files they can access.
      const q = this.searchQuery;
      if (q && this.cy) {
        const cy = this.cy;
        const matches = cy.nodes().filter((node) => {
          // Scope gate: when not "all", only nodes of the chosen kind qualify.
          const kind = String(node.data("kind") ?? "");
          if (this.searchScope !== "all" && kind !== this.searchScope) return false;
          const label = String(node.data("label") ?? "").toLowerCase();
          const path = String(node.data("path") ?? "").toLowerCase();
          return label.includes(q) || path.includes(q);
        });
        this.lastSearchMatchCount = matches.length;
        const keep = matches.closedNeighborhood().nodes();
        cy.nodes().difference(keep).addClass("vg-hidden");
      } else {
        this.lastSearchMatchCount = null;
      }

      // Hide any edge (permission, containment) whose endpoints are hidden, so
      // dangling edges don't float free.
      this.cy?.edges().forEach((edge) => {
        const src = edge.source();
        const tgt = edge.target();
        if (src.hasClass("vg-hidden") || tgt.hasClass("vg-hidden")) {
          edge.addClass("vg-hidden");
        }
      });
    });

    this.applyFocus();
    this.updateSearchFeedback();
  }

  /**
   * Reflect the live search result count in the badge. Hidden when no query is
   * active; "No matches" (error-tinted) on zero; "N match(es)" otherwise.
   */
  private updateSearchFeedback(): void {
    if (!this.searchCountEl) return;
    if (!this.searchQuery) {
      this.searchCountEl.setText("");
      this.searchCountEl.toggleClass("is-visible", false);
      this.searchCountEl.toggleClass("is-empty", false);
      return;
    }
    const n = this.lastSearchMatchCount ?? 0;
    this.searchCountEl.setText(n === 0 ? "No matches" : `${n} match${n === 1 ? "" : "es"}`);
    this.searchCountEl.toggleClass("is-visible", true);
    this.searchCountEl.toggleClass("is-empty", n === 0);
  }

  /**
   * Pan/zoom so the currently-visible (non-hidden) nodes fill the viewport.
   * Called after a search so the matched subset is actually brought on-screen
   * instead of staying lost in the static layout. No-op when nothing is visible
   * (e.g. a query that matches nothing) so we don't fit to an empty collection.
   */
  private fitToVisible(): void {
    if (!this.cy) return;
    const visible = this.cy.nodes().not(".vg-hidden");
    if (visible.empty()) return;
    this.cy.fit(visible, 40);
  }

  // ─── Depth focus ────────────────────────────────────────────────────────────
  //
  // Mirrors Obsidian's local graph: when a node is focused, dim everything
  // outside its BFS neighborhood to the chosen depth.
  private applyFocus(): void {
    if (!this.cy) return;
    const cy = this.cy;

    cy.batch(() => {
      cy.elements().removeClass("vg-dimmed");
      if (!this.focusedNodeId) return;
      const focus = cy.getElementById(this.focusedNodeId);
      if (focus.empty()) return;

      // BFS outward from the focused node to `this.depth` hops.
      let frontier = focus;
      let neighborhood = focus;
      for (let i = 0; i < this.depth; i++) {
        const next = frontier.closedNeighborhood();
        neighborhood = neighborhood.union(next);
        frontier = next;
      }
      cy.elements().difference(neighborhood).addClass("vg-dimmed");
    });
  }

  // ─── Explain panel ──────────────────────────────────────────────────────────

  private renderExplainEmpty(): void {
    if (!this.explainEl) return;
    this.explainEl.empty();
    this.explainEl.createDiv({
      cls: EXPLAIN_EMPTY_CLS,
      text: "Select a file to see everyone who can access it, or a user to see every file they can reach. Click any row for the full why.",
    });
  }

  private explainForNode(node: cytoscape.NodeSingular): void {
    const kind = node.data("kind") as string | undefined;
    if (kind === "user") {
      this.explainForUser(node.data("userId") as string, node.data("label") as string);
      return;
    }
    if (kind === "file" || kind === "folder") {
      this.explainForPath(node.data("path") as string, node.data("label") as string);
      return;
    }
    this.renderExplainMessage(String(node.data("label") ?? "Node"), []);
  }

  // File OR folder node → every user who can reach that path, with their level.
  // Folders resolve access exactly like files (evaluated at the folder path), so
  // this is the headline interaction for both. Each row drills into the trace.
  private explainForPath(path: string, label?: string): void {
    if (!this.explainEl) return;
    const norm = normalizePath(path);
    const isFolder = this.folderPathSet.has(norm);
    const noun = isFolder ? "folder" : "file";
    this.lastExplainContext = { kind: "path", key: path };
    this.explainEl.empty();

    const base = path.split("/").filter(Boolean).pop() || path;
    const name = label || (isFolder ? `${base}/` : base);
    this.explainEl.createDiv({ cls: EXPLAIN_TITLE_CLS, text: name });
    this.explainEl.createDiv({ cls: EXPLAIN_SUBTITLE_CLS, text: path });

    const summary = this.summaryByPath.get(norm);
    const principals = (summary?.principals ?? [])
      .filter((p) => p.level && p.level !== "none")
      .sort((a, b) => this.levelRank(a.level) - this.levelRank(b.level) ||
        this.principalLabel(a).localeCompare(this.principalLabel(b)));

    if (principals.length === 0) {
      this.explainEl.createDiv({ cls: EXPLAIN_EMPTY_CLS, text: `No users can access this ${noun}.` });
      return;
    }

    this.explainEl.createDiv({ cls: EXPLAIN_SECTION_CLS, text: `Who can access · ${principals.length}` });
    const rows = this.explainEl.createDiv({ cls: EXPLAIN_ROWS_CLS });
    for (const p of principals) {
      this.renderAccessRow(rows, {
        dotColor: colorForUser(p.userId),
        label: this.principalLabel(p),
        level: p.level,
        onClick: () => this.explainPermission(p.userId, path),
      });
    }
  }

  // User node → every file AND folder this user can reach, with their level.
  private explainForUser(uid: string, label?: string): void {
    if (!this.explainEl) return;
    this.lastExplainContext = { kind: "user", key: uid };
    this.explainEl.empty();

    const name = label || this.labelForUser(uid);
    this.explainEl.createDiv({ cls: EXPLAIN_TITLE_CLS, text: name });

    const badges = this.explainEl.createDiv({ cls: EXPLAIN_BADGES_CLS });
    this.addBadge(badges, this.roleForUser(uid).toUpperCase(), "is-neutral");

    const access: Array<{ path: string; level: GraphAccessLevel }> = [];
    this.summaryByPath.forEach((summary, path) => {
      const principal = summary.principals.find((p) => p.userId === uid && p.level && p.level !== "none");
      if (principal) access.push({ path, level: principal.level });
    });
    access.sort((a, b) => this.levelRank(a.level) - this.levelRank(b.level) || a.path.localeCompare(b.path));

    if (access.length === 0) {
      this.explainEl.createDiv({ cls: EXPLAIN_EMPTY_CLS, text: "This user can't access any readable file or folder." });
      return;
    }

    this.explainEl.createDiv({ cls: EXPLAIN_SECTION_CLS, text: `Can access · ${access.length}` });
    const rows = this.explainEl.createDiv({ cls: EXPLAIN_ROWS_CLS });
    for (const a of access) {
      const isFolder = this.folderPathSet.has(normalizePath(a.path));
      const base = a.path.split("/").filter(Boolean).pop() || a.path;
      this.renderAccessRow(rows, {
        dotColor: null,
        label: isFolder ? `${base}/` : base,
        sublabel: a.path,
        level: a.level,
        onClick: () => this.explainPermission(uid, a.path),
      });
    }
  }

  private explainForEdge(edge: cytoscape.EdgeSingular): void {
    const kind = edge.data("kind") as string | undefined;
    if (kind === "containment") {
      this.renderExplainMessage("Folder structure", ["This link shows where the file lives. Click a user or file node to see permissions."]);
      return;
    }
    const uid = edge.data("userId") as string | undefined;
    const path = edge.data("path") as string | undefined;
    if (!uid || !path) {
      this.renderExplainMessage("Permission", []);
      return;
    }
    this.explainPermission(uid, path);
  }

  // The full precedence trace for one (user, path) — reached from a row click or
  // an edge tap. Offers a "← back" to whichever node list led here.
  private explainPermission(uid: string, path: string): void {
    if (!this.explainEl || !this.viewer) return;

    const principalRules = this.rulesForPrincipal(uid);
    const role = this.roleForUser(uid);
    const serverLevel = this.serverLevelFor(uid, path);

    const trace = explainAccess({
      userId: uid,
      role,
      orgRoles: uid === this.viewer.userId ? this.viewer.orgRoles : [],
      path,
      action: "read",
      rules: principalRules,
      serverLevel,
    });

    this.renderExplainTrace(uid, path, trace);
  }

  private renderExplainMessage(title: string, lines: string[]): void {
    if (!this.explainEl) return;
    this.explainEl.empty();
    this.explainEl.createDiv({ cls: EXPLAIN_TITLE_CLS, text: title });
    const list = this.explainEl.createEl("ul", { cls: EXPLAIN_STEPS_CLS });
    for (const line of lines) {
      list.createEl("li", { text: line });
    }
  }

  private renderExplainTrace(uid: string, path: string, trace: ExplainTrace): void {
    if (!this.explainEl) return;
    this.explainEl.empty();

    // "← back" to the file/user list this trace was opened from.
    const ctx = this.lastExplainContext;
    if (ctx) {
      const back = this.explainEl.createDiv({
        cls: EXPLAIN_BACK_CLS,
        attr: { role: "button", tabindex: "0" },
      });
      setIcon(back, "arrow-left");
      const backText = ctx.kind === "user"
        ? "Back to user"
        : this.folderPathSet.has(normalizePath(ctx.key)) ? "Back to folder" : "Back to file";
      back.createSpan({ text: backText });
      const go = (): void => {
        if (ctx.kind === "path") this.explainForPath(ctx.key);
        else this.explainForUser(ctx.key);
      };
      back.addEventListener("click", go);
      back.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); go(); }
      });
    }

    const label = this.labelForUser(uid);
    const name = path.split("/").filter(Boolean).pop() || path;
    this.explainEl.createDiv({ cls: EXPLAIN_TITLE_CLS, text: `${label} → ${name}` });
    this.explainEl.createDiv({ cls: EXPLAIN_SUBTITLE_CLS, text: path });

    const badges = this.explainEl.createDiv({ cls: EXPLAIN_BADGES_CLS });
    this.addBadge(badges, trace.effectiveLevel.toUpperCase(), this.levelBadgeClass(trace.effectiveLevel));
    this.addBadge(badges, `via ${trace.decidedBy}`, "is-neutral");
    if (trace.expiresAt) {
      this.addBadge(badges, "expiring", "is-expiring");
    }
    if (trace.serverDrift) {
      this.addBadge(badges, "server drift", "is-deny");
    }

    const list = this.explainEl.createEl("ul", { cls: EXPLAIN_STEPS_CLS });
    for (const step of trace.steps) {
      list.createEl("li", { text: step });
    }
  }

  // One clickable row: colour dot (users) + label (+ optional sublabel) + level badge.
  private renderAccessRow(
    parent: HTMLElement,
    opts: { dotColor: string | null; label: string; sublabel?: string; level: GraphAccessLevel; onClick: () => void },
  ): void {
    const row = parent.createDiv({ cls: EXPLAIN_ROW_CLS, attr: { role: "button", tabindex: "0" } });
    if (opts.dotColor) {
      const dot = row.createSpan({ cls: EXPLAIN_ROW_DOT_CLS });
      dot.setCssStyles({ backgroundColor: opts.dotColor });
    }
    const labelWrap = row.createDiv({ cls: EXPLAIN_ROW_LABEL_CLS });
    labelWrap.createSpan({ text: opts.label });
    if (opts.sublabel) labelWrap.createDiv({ cls: EXPLAIN_SUBTITLE_CLS, text: opts.sublabel });
    this.addBadge(row, opts.level.toUpperCase(), `is-level-${opts.level}`);
    row.addEventListener("click", opts.onClick);
    row.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); opts.onClick(); }
    });
  }

  private addBadge(parent: HTMLElement, text: string, variant: string): void {
    const badge = parent.createSpan({ cls: `${EXPLAIN_BADGE_CLS} ${variant}` });
    badge.setText(text);
  }

  private levelBadgeClass(level: GraphAccessLevel): string {
    return level === "none" ? "is-deny" : `is-level-${level}`;
  }

  private levelRank(level: GraphAccessLevel): number {
    return level === "admin" ? 0 : level === "write" ? 1 : level === "read" ? 2 : 3;
  }

  private labelForUser(uid: string): string {
    const m = this.memberById.get(uid);
    return m?.displayName || m?.email || uid;
  }

  private principalLabel(p: GraphPrincipal): string {
    return p.displayName?.trim() || p.email?.trim() || this.memberById.get(p.userId)?.displayName || p.userId;
  }

  // ─── Explain data helpers ───────────────────────────────────────────────────

  /** Rules that could apply to a principal (their id, the wildcard, or their role). */
  private rulesForPrincipal(uid: string): ExplainRule[] {
    const role = this.roleForUser(uid).toLowerCase();
    return (this.rules as ExplainRule[]).filter((rule) => {
      const ruleUser = (rule.userId ?? "").toLowerCase();
      const ruleRole = (rule.role ?? "").toLowerCase();
      return ruleUser === uid.toLowerCase() || rule.userId === "*" || (!!ruleRole && ruleRole === role);
    });
  }

  private roleForUser(uid: string): ExplainVaultRole {
    const role = this.memberById.get(uid)?.role;
    return role === "admin" || role === "editor" || role === "viewer" ? role : "viewer";
  }

  private serverLevelFor(uid: string, path: string): GraphAccessLevel | undefined {
    const summary = this.summaryByPath.get(normalizePath(path));
    const principal = summary?.principals.find((p) => p.userId === uid);
    return principal?.level;
  }

  // ─── Small DOM/status helpers ───────────────────────────────────────────────

  private setStatus(text: string): void {
    if (!this.statusEl) return;
    this.statusEl.setText(text);
    this.statusEl.toggleClass("is-hidden", text.length === 0);
  }

  private setNote(text: string): void {
    if (!this.noteEl) return;
    this.noteEl.setText(text);
    this.noteEl.toggleClass("is-hidden", text.length === 0);
  }
}

/** Local path normalizer matching the data builder (leading slash, no trailing). */
function normalizePath(path: string): string {
  const p = path.replace(/\/+/g, "/").replace(/\/$/, "");
  return p.startsWith("/") ? p : `/${p}`;
}
