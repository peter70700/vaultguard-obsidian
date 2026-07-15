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
  applyGraphStudioPresentation,
  buildGraphStudioPresentation,
  getGraphStudioPreset,
  type GraphStudioPosition,
  type GraphStudioPresetId,
} from "./permissions-graph-customization";
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
import {
  DEFAULT_GRAPH_BUDGETS,
  DEFAULT_GRAPH_OPTIONS,
  buildAggregatedGraphElements,
  buildGraphDebugReadoutModel,
  capExplainRows,
  decideGraphRender,
  estimateDetailedGraphComplexity,
  filterGraphDataset,
  graphOptionsToSavedState,
  normalizeGraphOptions,
  normalizeOptionalGraphPath,
  removeGraphVaultState,
  resetGraphStudioAppearance,
  resetGraphStudioArrangement,
  resetGraphStudioOptions,
  upsertGraphVaultState,
  type FilteredGraphDataset,
  type GraphActualMode,
  type GraphComplexityEstimate,
  type GraphDebugReadoutModel,
  type GraphRenderDecision,
  type GraphRuntimeOptions,
} from "./permissions-graph-scale";

export { VAULTGUARD_GRAPH_VIEW_TYPE } from "../view-types";
import { VAULTGUARD_GRAPH_VIEW_TYPE } from "../view-types";

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
  /** Files actually scanned (bounded by graph max files) and the vault's total file count. */
  scanned: number;
  total: number;
  truncated: boolean;
}

// ─── CSS class names (mirrors the `*_CLS` convention) ─────────────────────────
const ROOT_CLS = "vaultguard-permissions-graph";
const HEADER_CLS = "vaultguard-pg-header";
const TITLE_CLS = "vaultguard-pg-title";
const TOOLBAR_CLS = "vaultguard-pg-toolbar";
const OPTIONS_CLS = "vaultguard-pg-options";
const OPTIONS_SUMMARY_CLS = "vaultguard-pg-options-summary";
const OPTIONS_GRID_CLS = "vaultguard-pg-options-grid";
const OPTION_FIELD_CLS = "vaultguard-pg-option-field";
const OPTION_TOGGLE_CLS = "vaultguard-pg-option-toggle";
const STUDIO_CLS = "vaultguard-pg-studio";
const STUDIO_INTRO_CLS = "vaultguard-pg-studio-intro";
const STUDIO_BODY_CLS = "vaultguard-pg-studio-body";
const STUDIO_PRESETS_CLS = "vaultguard-pg-studio-presets";
const STUDIO_PRESET_CLS = "vaultguard-pg-studio-preset";
const STUDIO_GROUP_CLS = "vaultguard-pg-studio-group";
const STUDIO_GRID_CLS = "vaultguard-pg-studio-grid";
const STUDIO_RANGE_CLS = "vaultguard-pg-studio-range";
const STUDIO_RANGE_VALUE_CLS = "vaultguard-pg-studio-range-value";
const STUDIO_PALETTE_CLS = "vaultguard-pg-studio-palette";
const STUDIO_RESETS_CLS = "vaultguard-pg-studio-resets";
const STUDIO_STATUS_CLS = "vaultguard-pg-studio-status";
const STUDIO_CUSTOM_PALETTE_CLS = "has-studio-custom-palette";
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
const EMPTY_ACTION_CLS = "vaultguard-pg-empty-action";
const EMPTY_ACTION_ICON_CLS = "vaultguard-pg-empty-action-icon";
const NOTICE_CLS = "vaultguard-pg-large-notice";
const DEBUG_CLS = "vaultguard-pg-debug";
const DEBUG_SUMMARY_CLS = "vaultguard-pg-debug-summary";
const DEBUG_GRID_CLS = "vaultguard-pg-debug-grid";
const SHOW_MORE_CLS = "vaultguard-pg-show-more";
const NOTE_CLS = "vaultguard-pg-note";
const STATUS_CLS = "vaultguard-pg-status";

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
  private noticeEl: HTMLElement | null = null;
  private debugEl: HTMLElement | null = null;
  private userFilterSelectEl: HTMLSelectElement | null = null;
  private optionRenderTimer: ReturnType<typeof setTimeout> | null = null;
  private studioPersistTimer: ReturnType<typeof setTimeout> | null = null;
  private activeLayout: cytoscape.Layouts | null = null;
  /** requestAnimationFrame handle for the throttled zoom -> font-size refresh. */
  private zoomFontRaf: number | null = null;
  private studioBodyEl: HTMLElement | null = null;
  private studioStatusEl: HTMLElement | null = null;
  private readonly studioPresetButtons = new Map<GraphStudioPresetId, HTMLButtonElement>();
  private currentBaseElements: GraphElement[] = [];

  // Legend filter state: class → enabled.
  private readonly legendState = new Map<string, boolean>(
    LEGEND_ITEMS.map((item) => [item.key, true]),
  );
  private graphOptions: GraphRuntimeOptions = normalizeGraphOptions();
  private renderDecision: GraphRenderDecision | null = null;
  private lastEstimate: GraphComplexityEstimate | null = null;
  private actualMode: GraphActualMode = "detailed";
  private hoverHighlightEnabled = true;
  private focusedNodeId: string | null = null;
  // The live result-count badge element + the last match count it reflects.
  private searchCountEl: HTMLElement | null = null;
  private lastSearchMatchCount: number | null = null;
  // Lets the per-permission trace offer a "← back" to the node list it came from.
  private lastExplainContext: { kind: "path" | "user"; key: string } | null = null;
  private currentVaultId: string | null = null;

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
    this.registerEvent(
      this.app.workspace.on("css-change", () => {
        this.applyGraphStageAppearance();
        this.cy?.style(this.buildStylesheet());
      }),
    );
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

    this.currentVaultId = vaultId;
    this.loadGraphOptions(vaultId);
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
    this.activeLayout?.stop();
    this.activeLayout = null;
    if (this.zoomFontRaf != null) {
      if (typeof cancelAnimationFrame === "function") cancelAnimationFrame(this.zoomFontRaf);
      this.zoomFontRaf = null;
    }
    if (this.cy) {
      this.cy.destroy();
      this.cy = null;
    }
    if (this.optionRenderTimer) {
      clearTimeout(this.optionRenderTimer);
      this.optionRenderTimer = null;
    }
    if (this.studioPersistTimer) {
      clearTimeout(this.studioPersistTimer);
      this.studioPersistTimer = null;
      this.persistGraphOptions();
    }
    this.bodyEl = null;
    this.canvasEl = null;
    this.explainEl = null;
    this.statusEl = null;
    this.noteEl = null;
    this.noticeEl = null;
    this.debugEl = null;
    this.userFilterSelectEl = null;
    this.studioBodyEl = null;
    this.studioStatusEl = null;
    this.studioPresetButtons.clear();
    this.currentBaseElements = [];
    this.renderDecision = null;
    this.lastEstimate = null;
    this.actualMode = "detailed";
    this.hoverHighlightEnabled = true;
    this.rules = [];
    this.summaryByPath.clear();
    this.folderPathSet.clear();
    this.memberById.clear();
    this.focusedNodeId = null;
    this.searchCountEl = null;
    this.lastSearchMatchCount = null;
    this.lastExplainContext = null;
    this.viewer = null;
    this.currentVaultId = null;
  }

  private loadGraphOptions(vaultId: string): void {
    this.graphOptions = normalizeGraphOptions(
      this.plugin.settings.permissionsGraphDefaults,
      this.plugin.settings.permissionsGraphVaultStates?.[vaultId],
      DEFAULT_GRAPH_BUDGETS,
    );
    this.syncLegendStateFromOptions();
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
      // re-renders itself automatically once the connection is restored, and
      // the Retry button forces a reconnect probe now.
      setIcon(icon, "cloud-off");
      empty.createEl("p", {
        text: "VaultGuard is offline — the permissions map needs a connection.",
      });
      empty.createEl("p", {
        cls: NOTE_CLS,
        text:
          "You're signed in. This panel populates automatically once the " +
          "connection comes back — or retry now. Until then it stays offline " +
          "and makes no network calls.",
      });
      this.addEmptyStateAction(empty, "Retry connection", "refresh-cw", async () => {
        await this.plugin.reconnectNow();
        await this.refresh();
      });
      return;
    }

    if (reason === "no-vault") {
      setIcon(icon, "git-fork");
      empty.createEl("p", { text: "Select a VaultGuard vault to map its permissions." });
      empty.createEl("p", {
        cls: NOTE_CLS,
        text: "Choose a vault to bind this folder — the map loads automatically.",
      });
      this.addEmptyStateAction(empty, "Choose vault", "git-fork", async () => {
        await this.plugin.switchServerVault();
        await this.refresh();
      });
      return;
    }

    setIcon(icon, "git-fork");
    empty.createEl("p", { text: "Connect VaultGuard to map your vault's permissions." });
    empty.createEl("p", {
      cls: NOTE_CLS,
      text:
        "Sign in to see who can access which files. The map loads automatically " +
        "once you're signed in — until then this panel stays fully offline and " +
        "makes no network calls.",
    });
    this.addEmptyStateAction(empty, "Sign in", "log-in", () => {
      // Opens the login modal. Login completion re-renders this panel via the
      // plugin (main.ts refreshPermissionsGraph), so no manual refresh here —
      // the modal flow is async and outlives this click handler.
      this.plugin.openLoginModal();
    });
  }

  /**
   * Append a single primary CTA button to an empty state. The handler may be
   * sync or async; while an async handler runs the button disables itself so a
   * second click can't stack login modals / reconnect probes. Built entirely
   * with Obsidian DOM helpers + the stock `mod-cta` class — no inline
   * element.style (Obsidian-review rule).
   */
  private addEmptyStateAction(
    empty: HTMLElement,
    label: string,
    iconName: string,
    handler: () => void | Promise<void>,
  ): void {
    const btn = empty.createEl("button", { cls: `${EMPTY_ACTION_CLS} mod-cta` });
    setIcon(btn.createSpan({ cls: EMPTY_ACTION_ICON_CLS }), iconName);
    btn.createSpan({ text: label });
    btn.addEventListener("click", () => {
      btn.disabled = true;
      void Promise.resolve(handler()).finally(() => {
        // The view may have re-rendered mid-flight (button detached); only
        // re-enable if it's still in the DOM.
        if (btn.isConnected) btn.disabled = false;
      });
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
    const header = container.createDiv({ cls: HEADER_CLS });
    header.createDiv({ cls: TITLE_CLS, text: "Permissions graph" });

    // Toolbar: render options, legend filters, search, and focus controls.
    const toolbar = container.createDiv({ cls: TOOLBAR_CLS });
    this.renderGraphStudioPanel(toolbar);
    this.renderOptionsPanel(toolbar);

    const legend = toolbar.createDiv({ cls: LEGEND_CLS });
    for (const item of LEGEND_ITEMS) {
      const chip = legend.createDiv({
        cls: LEGEND_CHIP_CLS,
        attr: { role: "button", tabindex: "0", "aria-label": `Toggle ${item.label}` },
      });
      chip.dataset.key = item.key;
      chip.toggleClass(LEGEND_CHIP_OFF_CLS, !(this.legendState.get(item.key) ?? true));
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
    scopeSelect.value = this.graphOptions.searchScope;

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
        placeholder: placeholderFor(this.graphOptions.searchScope),
        "aria-label": "Filter graph",
      },
    });
    searchInput.value = this.graphOptions.searchQuery;
    searchInput.addEventListener("input", () => {
      this.updateGraphOptions({ searchQuery: searchInput.value.trim() }, true);
    });

    scopeSelect.addEventListener("change", () => {
      const nextScope = scopeSelect.value as SearchScope;
      searchInput.placeholder = placeholderFor(nextScope);
      this.updateGraphOptions({ searchScope: nextScope });
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
        max: "8",
        value: String(this.graphOptions.depth),
        "aria-label": "Focus depth",
      },
    });
    const depthValue = depthRow.createSpan({ cls: DEPTH_LABEL_CLS, text: String(this.graphOptions.depth) });
    slider.addEventListener("input", () => {
      const nextDepth = Number(slider.value) || DEFAULT_DEPTH;
      depthValue.setText(String(nextDepth));
      this.updateGraphOptions({ depth: nextDepth }, true);
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

    // Compact layout cycle mirrors the Graph Studio layout control.
    const layoutBtn = depthRow.createSpan({
      cls: "clickable-icon",
      attr: { "aria-label": "Cycle layout", title: "Cycle layout" },
    });
    const syncLayoutIcon = (): void => {
      const layout = this.graphOptions.layoutMode;
      setIcon(
        layoutBtn,
        layout === "force"
          ? "git-fork"
          : layout === "grid" || layout === "sections"
            ? "grid-2x2"
            : layout === "folder"
              ? "folder-tree"
              : "target",
      );
    };
    syncLayoutIcon();
    layoutBtn.addEventListener("click", () => {
      const order: GraphRuntimeOptions["layoutMode"][] = ["auto", "radial", "force", "grid", "folder", "sections"];
      const idx = order.indexOf(this.graphOptions.layoutMode);
      this.updateGraphStudioOptions({ layoutMode: order[(idx + 1) % order.length] }, true);
      this.renderGraphStudioControls();
      syncLayoutIcon();
    });

    this.noticeEl = container.createDiv({ cls: NOTICE_CLS });

    // Body: cytoscape canvas + explain side panel.
    this.bodyEl = container.createDiv({ cls: BODY_CLS });
    this.canvasEl = this.bodyEl.createDiv({ cls: CANVAS_CLS });
    this.explainEl = this.bodyEl.createDiv({ cls: EXPLAIN_CLS });
    this.renderExplainEmpty();

    // Status / "showing N files" note line.
    this.noteEl = container.createDiv({ cls: NOTE_CLS });
    this.statusEl = container.createDiv({ cls: STATUS_CLS });
    this.debugEl = container.createDiv({ cls: DEBUG_CLS });
    this.applyGraphStageAppearance();
  }

  private renderGraphStudioPanel(toolbar: HTMLElement): void {
    const details = toolbar.createEl("details", { cls: `${OPTIONS_CLS} ${STUDIO_CLS}` });
    const summary = details.createEl("summary", { cls: OPTIONS_SUMMARY_CLS });
    setIcon(summary.createSpan(), "palette");
    summary.createSpan({ text: "Graph Studio" });
    summary.createSpan({ cls: STUDIO_INTRO_CLS, text: "Optional" });
    this.studioBodyEl = details.createDiv({ cls: STUDIO_BODY_CLS });
    this.renderGraphStudioControls();
  }

  private renderGraphStudioControls(): void {
    const body = this.studioBodyEl;
    if (!body) return;
    body.empty();
    this.studioPresetButtons.clear();
    body.createDiv({
      cls: STUDIO_INTRO_CLS,
      text: "Tune structure and appearance without changing permissions, safety limits, or the familiar default.",
    });

    const presetGroup = body.createEl("fieldset", { cls: STUDIO_GROUP_CLS });
    presetGroup.createEl("legend", { text: "Quick presets" });
    const presetRow = presetGroup.createDiv({ cls: STUDIO_PRESETS_CLS });
    const presets: Array<{ id: GraphStudioPresetId; label: string; title: string }> = [
      { id: "default", label: "Default", title: "Current graph defaults" },
      { id: "folder-map", label: "Folder map", title: "Hierarchy, folder colors, and connection sizing" },
      { id: "access-audit", label: "Access audit", title: "Access sections, labels, and access emphasis" },
      { id: "minimal", label: "Minimal", title: "Quiet grid with uniform nodes and no labels" },
    ];
    for (const preset of presets) {
      const button = presetRow.createEl("button", {
        cls: STUDIO_PRESET_CLS,
        text: preset.label,
        attr: { type: "button", title: preset.title, "aria-label": `${preset.label}: ${preset.title}` },
      });
      button.dataset.preset = preset.id;
      button.addEventListener("click", () => this.applyGraphStudioPreset(preset.id));
      this.studioPresetButtons.set(preset.id, button);
    }

    const arrangement = body.createEl("fieldset", { cls: STUDIO_GROUP_CLS });
    arrangement.createEl("legend", { text: "Arrangement" });
    const arrangementGrid = arrangement.createDiv({ cls: STUDIO_GRID_CLS });
    this.addStudioSelect(
      arrangementGrid,
      "Layout",
      this.graphOptions.layoutMode,
      [
        ["auto", "Auto"],
        ["radial", "Radial"],
        ["force", "Force"],
        ["grid", "Grid"],
        ["folder", "Folder hierarchy"],
        ["sections", "Sections"],
      ],
      (value) => this.updateGraphStudioOptions({ layoutMode: value as GraphRuntimeOptions["layoutMode"] }, true),
    );
    this.addStudioSelect(
      arrangementGrid,
      "Labels",
      this.graphOptions.labelsMode,
      [
        ["auto", "Auto"],
        ["on", "On"],
        ["off", "Off"],
      ],
      (value) => this.updateGraphStudioOptions({ labelsMode: value as GraphRuntimeOptions["labelsMode"] }, false),
    );
    this.addStudioSelect(
      arrangementGrid,
      "Section by",
      this.graphOptions.arrangement.sectionBy,
      [
        ["folder", "Top folder"],
        ["type", "Node type"],
        ["access", "Access profile"],
        ["connections", "Connectivity"],
      ],
      (value) =>
        this.updateGraphStudioOptions(
          { arrangement: { ...this.graphOptions.arrangement, sectionBy: value as GraphRuntimeOptions["arrangement"]["sectionBy"] } },
          true,
        ),
    );
    this.addStudioSelect(
      arrangementGrid,
      "Sort by",
      this.graphOptions.arrangement.sortBy,
      [
        ["name", "Name"],
        ["path", "Full path"],
        ["access", "Access"],
        ["connections", "Connections"],
      ],
      (value) =>
        this.updateGraphStudioOptions(
          { arrangement: { ...this.graphOptions.arrangement, sortBy: value as GraphRuntimeOptions["arrangement"]["sortBy"] } },
          true,
        ),
    );
    this.addStudioSelect(
      arrangementGrid,
      "Direction",
      this.graphOptions.arrangement.sortDirection,
      [
        ["asc", "Ascending"],
        ["desc", "Descending"],
      ],
      (value) =>
        this.updateGraphStudioOptions(
          {
            arrangement: {
              ...this.graphOptions.arrangement,
              sortDirection: value as GraphRuntimeOptions["arrangement"]["sortDirection"],
            },
          },
          true,
        ),
    );

    const appearance = body.createEl("fieldset", { cls: STUDIO_GROUP_CLS });
    appearance.createEl("legend", { text: "Appearance" });
    const appearanceGrid = appearance.createDiv({ cls: STUDIO_GRID_CLS });
    this.addStudioSelect(
      appearanceGrid,
      "Background",
      this.graphOptions.appearance.backgroundMode,
      [
        ["theme", "Theme"],
        ["solid", "Solid"],
        ["gradient", "Gradient"],
      ],
      (value) =>
        this.updateGraphStudioOptions({
          appearance: {
            ...this.graphOptions.appearance,
            backgroundMode: value as GraphRuntimeOptions["appearance"]["backgroundMode"],
          },
        }, false),
    );
    this.addStudioSelect(
      appearanceGrid,
      "Pattern",
      this.graphOptions.appearance.backgroundPattern,
      [
        ["none", "None"],
        ["grid", "Grid"],
        ["dots", "Dots"],
      ],
      (value) =>
        this.updateGraphStudioOptions({
          appearance: {
            ...this.graphOptions.appearance,
            backgroundPattern: value as GraphRuntimeOptions["appearance"]["backgroundPattern"],
          },
        }, false),
    );
    this.addStudioColor(appearanceGrid, "Background color", this.graphOptions.appearance.backgroundPrimary, (value, debounce) =>
      this.updateGraphStudioOptions({
        appearance: { ...this.graphOptions.appearance, backgroundPrimary: value },
      }, false, debounce),
    );
    this.addStudioColor(appearanceGrid, "Gradient end", this.graphOptions.appearance.backgroundSecondary, (value, debounce) =>
      this.updateGraphStudioOptions({
        appearance: { ...this.graphOptions.appearance, backgroundSecondary: value },
      }, false, debounce),
    );
    this.addStudioSelect(
      appearanceGrid,
      "Color by",
      this.graphOptions.appearance.colorMode,
      [
        ["current", "Current"],
        ["type", "Node type"],
        ["folder", "Top folder"],
        ["access", "Access"],
        ["connections", "Connections"],
      ],
      (value) =>
        this.updateGraphStudioOptions({
          appearance: {
            ...this.graphOptions.appearance,
            colorMode: value as GraphRuntimeOptions["appearance"]["colorMode"],
          },
        }, false),
    );
    this.addStudioSelect(
      appearanceGrid,
      "Size by",
      this.graphOptions.appearance.sizeMode,
      [
        ["standard", "Standard"],
        ["uniform", "Uniform"],
        ["connections", "Connections"],
        ["access", "Access"],
      ],
      (value) =>
        this.updateGraphStudioOptions({
          appearance: {
            ...this.graphOptions.appearance,
            sizeMode: value as GraphRuntimeOptions["appearance"]["sizeMode"],
          },
        }, false),
    );
    this.addStudioRange(appearanceGrid, "Node scale", this.graphOptions.appearance.nodeScale, 0.75, 1.75, 0.05, (value, debounce) =>
      this.updateGraphStudioOptions({ appearance: { ...this.graphOptions.appearance, nodeScale: value } }, false, debounce),
    );
    this.addStudioRange(appearanceGrid, "Edge scale", this.graphOptions.appearance.edgeScale, 0.5, 2, 0.1, (value, debounce) =>
      this.updateGraphStudioOptions({ appearance: { ...this.graphOptions.appearance, edgeScale: value } }, false, debounce),
    );
    this.addStudioRange(appearanceGrid, "Text size", this.graphOptions.appearance.labelScale, 0.75, 2.5, 0.05, (value, debounce) =>
      this.updateGraphStudioOptions({ appearance: { ...this.graphOptions.appearance, labelScale: value } }, false, debounce),
    );

    const paletteGroup = body.createEl("fieldset", { cls: `${STUDIO_GROUP_CLS} ${STUDIO_PALETTE_CLS}` });
    paletteGroup.createEl("legend", { text: "Semantic colors" });
    const paletteInputs: HTMLInputElement[] = [];
    this.addStudioToggle(paletteGroup, "Use custom semantic colors", this.graphOptions.appearance.customPalette, (checked) => {
      this.updateGraphStudioOptions({
        appearance: { ...this.graphOptions.appearance, customPalette: checked },
      }, false);
      for (const input of paletteInputs) input.disabled = !checked;
    });
    const paletteGrid = paletteGroup.createDiv({ cls: STUDIO_GRID_CLS });
    const paletteLabels: Array<[keyof GraphRuntimeOptions["appearance"]["palette"], string]> = [
      ["user", "User"],
      ["file", "File"],
      ["folder", "Folder"],
      ["read", "Read"],
      ["write", "Write"],
      ["admin", "Admin"],
      ["low", "Low connections"],
      ["medium", "Medium connections"],
      ["high", "High connections"],
    ];
    for (const [key, label] of paletteLabels) {
      const input = this.addStudioColor(paletteGrid, label, this.graphOptions.appearance.palette[key], (value, debounce) =>
        this.updateGraphStudioOptions({
          appearance: {
            ...this.graphOptions.appearance,
            palette: { ...this.graphOptions.appearance.palette, [key]: value },
          },
        }, false, debounce),
      );
      input.disabled = !this.graphOptions.appearance.customPalette;
      paletteInputs.push(input);
    }

    const resets = body.createDiv({ cls: STUDIO_RESETS_CLS });
    const resetAppearance = resets.createEl("button", { text: "Reset appearance", attr: { type: "button" } });
    resetAppearance.addEventListener("click", () => {
      const next = resetGraphStudioAppearance(this.graphOptions);
      this.updateGraphStudioOptions({ appearance: next.appearance }, false);
      this.renderGraphStudioControls();
      this.setStudioStatus("Appearance reset. Arrangement and filters were kept.");
    });
    const resetArrangement = resets.createEl("button", { text: "Reset arrangement", attr: { type: "button" } });
    resetArrangement.addEventListener("click", () => {
      const next = resetGraphStudioArrangement(this.graphOptions);
      this.updateGraphStudioOptions(
        { layoutMode: next.layoutMode, labelsMode: next.labelsMode, arrangement: next.arrangement },
        true,
      );
      this.renderGraphStudioControls();
      this.setStudioStatus("Arrangement reset. Appearance and filters were kept.");
    });
    const resetAll = resets.createEl("button", { text: "Reset Studio", cls: "mod-cta", attr: { type: "button" } });
    resetAll.addEventListener("click", () => {
      const next = resetGraphStudioOptions(this.graphOptions);
      this.updateGraphStudioOptions(
        {
          layoutMode: next.layoutMode,
          labelsMode: next.labelsMode,
          appearance: next.appearance,
          arrangement: next.arrangement,
        },
        true,
      );
      this.renderGraphStudioControls();
      this.setStudioStatus("Graph Studio reset. Permission data and filters were kept.");
    });

    this.studioStatusEl = body.createDiv({
      cls: STUDIO_STATUS_CLS,
      text: "Live preview uses only the current viewer-authorized graph.",
      attr: { role: "status", "aria-live": "polite", "aria-atomic": "true" },
    });
    this.syncStudioPresetButtons();
  }

  private addStudioSelect(
    parent: HTMLElement,
    label: string,
    value: string,
    options: Array<[string, string]>,
    onChange: (value: string) => void,
  ): HTMLSelectElement {
    const field = parent.createEl("label", { cls: OPTION_FIELD_CLS });
    field.createSpan({ text: label });
    const select = field.createEl("select", { attr: { "aria-label": label } });
    for (const [optionValue, text] of options) select.createEl("option", { value: optionValue, text });
    select.value = value;
    select.addEventListener("change", () => onChange(select.value));
    return select;
  }

  private addStudioColor(
    parent: HTMLElement,
    label: string,
    value: string,
    onChange: (value: string, debounce: boolean) => void,
  ): HTMLInputElement {
    const field = parent.createEl("label", { cls: OPTION_FIELD_CLS });
    field.createSpan({ text: label });
    const input = field.createEl("input", {
      attr: { type: "color", value, "aria-label": label },
    });
    input.addEventListener("input", () => onChange(input.value, true));
    input.addEventListener("change", () => onChange(input.value, false));
    return input;
  }

  private addStudioRange(
    parent: HTMLElement,
    label: string,
    value: number,
    min: number,
    max: number,
    step: number,
    onChange: (value: number, debounce: boolean) => void,
  ): HTMLInputElement {
    const field = parent.createEl("label", { cls: `${OPTION_FIELD_CLS} ${STUDIO_RANGE_CLS}` });
    const heading = field.createSpan();
    heading.createSpan({ text: label });
    const output = heading.createSpan({ cls: STUDIO_RANGE_VALUE_CLS, text: String(value) });
    const input = field.createEl("input", {
      attr: {
        type: "range",
        min: String(min),
        max: String(max),
        step: String(step),
        value: String(value),
        "aria-label": label,
      },
    });
    const update = (debounce: boolean): void => {
      const next = Number(input.value);
      output.setText(String(next));
      onChange(next, debounce);
    };
    input.addEventListener("input", () => update(true));
    input.addEventListener("change", () => update(false));
    return input;
  }

  private addStudioToggle(
    parent: HTMLElement,
    label: string,
    checked: boolean,
    onChange: (checked: boolean) => void,
  ): HTMLInputElement {
    const field = parent.createEl("label", { cls: OPTION_TOGGLE_CLS });
    const input = field.createEl("input", { attr: { type: "checkbox", "aria-label": label } });
    input.checked = checked;
    field.createSpan({ text: label });
    input.addEventListener("change", () => onChange(input.checked));
    return input;
  }

  private renderOptionsPanel(toolbar: HTMLElement): void {
    const details = toolbar.createEl("details", { cls: OPTIONS_CLS });
    const summary = details.createEl("summary", { cls: OPTIONS_SUMMARY_CLS });
    setIcon(summary.createSpan(), "sliders-horizontal");
    summary.createSpan({ text: "Filters & safety" });

    const grid = details.createDiv({ cls: OPTIONS_GRID_CLS });
    this.addSelectOption(grid, "Mode", this.graphOptions.renderMode, [
      ["auto", "Auto"],
      ["aggregated", "Aggregated"],
      ["detailed", "Detailed"],
    ], (value) => this.updateGraphOptions({ renderMode: value as GraphRuntimeOptions["renderMode"] }));
    this.addNumberOption(grid, "Max files", this.graphOptions.maxFiles, 1, DEFAULT_GRAPH_BUDGETS.maxInitialFiles, (value) =>
      this.updateGraphOptions({ maxFiles: value }, true),
    );
    this.addNumberOption(grid, "Max edges", this.graphOptions.maxEdges, 0, DEFAULT_GRAPH_BUDGETS.maxRenderedEdges, (value) =>
      this.updateGraphOptions({ maxEdges: value }, true),
    );
    this.addNumberOption(grid, "Depth", this.graphOptions.depth, 1, 8, (value) =>
      this.updateGraphOptions({ depth: value }, true),
    );

    const prefixField = grid.createEl("label", { cls: OPTION_FIELD_CLS });
    prefixField.createSpan({ text: "Folder" });
    const prefixInput = prefixField.createEl("input", {
      attr: { type: "search", "aria-label": "Folder prefix" },
    });
    prefixInput.value = this.graphOptions.pathPrefix;
    prefixInput.addEventListener("input", () =>
      this.updateGraphOptions({ pathPrefix: normalizeOptionalGraphPath(prefixInput.value) }, true),
    );

    const userField = grid.createEl("label", { cls: OPTION_FIELD_CLS });
    userField.createSpan({ text: "User" });
    this.userFilterSelectEl = userField.createEl("select", { attr: { "aria-label": "User filter" } });
    this.userFilterSelectEl.addEventListener("change", () => {
      const value = this.userFilterSelectEl?.value ?? "";
      this.updateGraphOptions({ selectedUsers: value ? [value] : [] });
    });

    this.addToggleOption(grid, "Users", this.graphOptions.nodeTypes.users, (checked) =>
      this.updateGraphOptions({ nodeTypes: { ...this.graphOptions.nodeTypes, users: checked } }),
    );
    this.addToggleOption(grid, "Files", this.graphOptions.nodeTypes.files, (checked) =>
      this.updateGraphOptions({ nodeTypes: { ...this.graphOptions.nodeTypes, files: checked } }),
    );
    this.addToggleOption(grid, "Folders", this.graphOptions.nodeTypes.folders, (checked) =>
      this.updateGraphOptions({ nodeTypes: { ...this.graphOptions.nodeTypes, folders: checked } }),
    );
    this.addToggleOption(grid, "Read", this.graphOptions.accessLevels.read, (checked) =>
      this.updateGraphOptions({ accessLevels: { ...this.graphOptions.accessLevels, read: checked } }),
    );
    this.addToggleOption(grid, "Write", this.graphOptions.accessLevels.write, (checked) =>
      this.updateGraphOptions({ accessLevels: { ...this.graphOptions.accessLevels, write: checked } }),
    );
    this.addToggleOption(grid, "Admin", this.graphOptions.accessLevels.admin, (checked) =>
      this.updateGraphOptions({ accessLevels: { ...this.graphOptions.accessLevels, admin: checked } }),
    );
    this.addToggleOption(grid, "Expiring", this.graphOptions.expiringOnly, (checked) =>
      this.updateGraphOptions({ expiringOnly: checked }),
    );
    this.addToggleOption(grid, "Writable/admin", this.graphOptions.writableAdminOnly, (checked) =>
      this.updateGraphOptions({ writableAdminOnly: checked }),
    );
    this.addToggleOption(grid, "Explicit", this.graphOptions.explicitRulesOnly, (checked) =>
      this.updateGraphOptions({ explicitRulesOnly: checked }),
    );

    const resetCurrent = grid.createEl("button", { text: "Reset vault", cls: "mod-cta" });
    resetCurrent.addEventListener("click", () => void this.resetCurrentVaultGraphOptions());
    const resetDefaults = grid.createEl("button", { text: "Reset defaults" });
    resetDefaults.addEventListener("click", () => void this.resetGlobalGraphDefaults());
  }

  private addSelectOption(
    parent: HTMLElement,
    label: string,
    value: string,
    options: Array<[string, string]>,
    onChange: (value: string) => void,
  ): void {
    const field = parent.createEl("label", { cls: OPTION_FIELD_CLS });
    field.createSpan({ text: label });
    const select = field.createEl("select");
    for (const [optionValue, text] of options) {
      select.createEl("option", { value: optionValue, text });
    }
    select.value = value;
    select.addEventListener("change", () => onChange(select.value));
  }

  private addNumberOption(
    parent: HTMLElement,
    label: string,
    value: number,
    min: number,
    max: number,
    onChange: (value: number) => void,
  ): void {
    const field = parent.createEl("label", { cls: OPTION_FIELD_CLS });
    field.createSpan({ text: label });
    const input = field.createEl("input", {
      attr: { type: "number", min: String(min), max: String(max), value: String(value) },
    });
    input.addEventListener("input", () => onChange(Number(input.value) || min));
  }

  private addToggleOption(
    parent: HTMLElement,
    label: string,
    checked: boolean,
    onChange: (checked: boolean) => void,
  ): void {
    const field = parent.createEl("label", { cls: OPTION_TOGGLE_CLS });
    const input = field.createEl("input", { attr: { type: "checkbox" } });
    input.checked = checked;
    field.createSpan({ text: label });
    input.addEventListener("change", () => onChange(input.checked));
  }

  private updateGraphOptions(patch: Partial<GraphRuntimeOptions>, debounce = false): void {
    const merged: GraphRuntimeOptions = {
      ...this.graphOptions,
      ...patch,
      accessLevels: { ...this.graphOptions.accessLevels, ...patch.accessLevels },
      nodeTypes: { ...this.graphOptions.nodeTypes, ...patch.nodeTypes },
      appearance: {
        ...this.graphOptions.appearance,
        ...patch.appearance,
        palette: { ...this.graphOptions.appearance.palette, ...patch.appearance?.palette },
      },
      arrangement: { ...this.graphOptions.arrangement, ...patch.arrangement },
      selectedUsers: patch.selectedUsers ?? this.graphOptions.selectedUsers,
    };
    this.graphOptions = normalizeGraphOptions(undefined, graphOptionsToSavedState(merged), DEFAULT_GRAPH_BUDGETS);
    this.syncLegendStateFromOptions();
    this.persistGraphOptions();
    this.queueGraphRender(debounce);
  }

  private updateGraphStudioOptions(
    patch: Partial<GraphRuntimeOptions>,
    arrangementChanged: boolean,
    debouncePersistence = false,
  ): void {
    const merged: GraphRuntimeOptions = {
      ...this.graphOptions,
      ...patch,
      accessLevels: { ...this.graphOptions.accessLevels, ...patch.accessLevels },
      nodeTypes: { ...this.graphOptions.nodeTypes, ...patch.nodeTypes },
      appearance: {
        ...this.graphOptions.appearance,
        ...patch.appearance,
        palette: { ...this.graphOptions.appearance.palette, ...patch.appearance?.palette },
      },
      arrangement: { ...this.graphOptions.arrangement, ...patch.arrangement },
      selectedUsers: patch.selectedUsers ?? this.graphOptions.selectedUsers,
    };
    this.graphOptions = normalizeGraphOptions(undefined, graphOptionsToSavedState(merged), DEFAULT_GRAPH_BUDGETS);
    if (this.lastEstimate) {
      this.renderDecision = decideGraphRender(this.lastEstimate, this.graphOptions, DEFAULT_GRAPH_BUDGETS);
    }
    const shouldRunLayout =
      arrangementChanged &&
      (patch.layoutMode !== undefined ||
        this.graphOptions.layoutMode === "folder" ||
        this.graphOptions.layoutMode === "sections");
    this.applyStudioPresentation(shouldRunLayout, !debouncePersistence);
    this.queueStudioPersistence(debouncePersistence);
    this.syncStudioPresetButtons();
  }

  private applyGraphStudioPreset(id: GraphStudioPresetId): void {
    const preset = getGraphStudioPreset(id);
    this.updateGraphStudioOptions(preset, true);
    this.renderGraphStudioControls();
    this.studioPresetButtons.get(id)?.focus();
    this.setStudioStatus(`${this.studioPresetLabel(id)} preset applied locally.`);
  }

  private studioPresetLabel(id: GraphStudioPresetId): string {
    if (id === "folder-map") return "Folder map";
    if (id === "access-audit") return "Access audit";
    if (id === "minimal") return "Minimal";
    return "Default";
  }

  private syncStudioPresetButtons(): void {
    for (const [id, button] of this.studioPresetButtons) {
      const preset = getGraphStudioPreset(id);
      const active =
        this.graphOptions.layoutMode === preset.layoutMode &&
        this.graphOptions.labelsMode === preset.labelsMode &&
        JSON.stringify(this.graphOptions.appearance) === JSON.stringify(preset.appearance) &&
        JSON.stringify(this.graphOptions.arrangement) === JSON.stringify(preset.arrangement);
      button.setAttribute("aria-pressed", active ? "true" : "false");
      button.toggleClass("is-active", active);
    }
  }

  private queueStudioPersistence(debounce: boolean): void {
    if (this.studioPersistTimer) {
      clearTimeout(this.studioPersistTimer);
      this.studioPersistTimer = null;
    }
    if (!debounce) {
      this.persistGraphOptions();
      return;
    }
    this.studioPersistTimer = setTimeout(() => {
      this.studioPersistTimer = null;
      this.persistGraphOptions();
    }, 250);
  }

  private applyStudioPresentation(runArrangement: boolean, announce = true): void {
    this.applyGraphStageAppearance();
    if (!this.cy || this.currentBaseElements.length === 0) {
      if (announce) this.setStudioStatus("Preview saved. It will apply when the graph can render.");
      return;
    }
    const presentation = buildGraphStudioPresentation(this.currentBaseElements, this.graphOptions);
    applyGraphStudioPresentation(this.cy, presentation);
    this.cy.style(this.buildStylesheet());
    // Re-apply zoom compensation after a restyle (e.g. Text size change) so the
    // new base font is held at the readable on-screen size at the current zoom.
    this.updateLabelFonts();
    if (runArrangement) {
      this.activeLayout?.stop();
      this.activeLayout = this.cy.layout(this.buildLayout(false, presentation.positions));
      this.activeLayout.run();
    }
    this.applyFilters();
    if (this.renderDecision && this.lastEstimate) {
      this.renderDebugReadout(
        buildGraphDebugReadoutModel(
          this.renderDecision,
          this.lastEstimate,
          this.cy.nodes().length,
          this.cy.edges().length,
          this.graphOptions,
        ),
      );
    }
    const sectionNote = presentation.sectionKeys.length > 0 ? ` · ${presentation.sectionKeys.length} section(s)` : "";
    if (announce) this.setStudioStatus(`Preview updated locally${sectionNote}. No permission reload.`);
  }

  private applyGraphStageAppearance(): void {
    const canvas = this.canvasEl;
    if (!canvas) return;
    const appearance = this.graphOptions.appearance;
    for (const mode of ["theme", "solid", "gradient"]) canvas.removeClass(`is-studio-bg-${mode}`);
    for (const pattern of ["none", "grid", "dots"]) canvas.removeClass(`is-studio-pattern-${pattern}`);
    canvas.addClass(`is-studio-bg-${appearance.backgroundMode}`);
    canvas.addClass(`is-studio-pattern-${appearance.backgroundPattern}`);
    const root = canvas.closest(`.${ROOT_CLS}`) as HTMLElement | null;
    root?.toggleClass(STUDIO_CUSTOM_PALETTE_CLS, appearance.customPalette);
    root?.setCssProps({
      "--vaultguard-pg-bg-primary": appearance.backgroundPrimary,
      "--vaultguard-pg-bg-secondary": appearance.backgroundSecondary,
      "--vaultguard-pg-studio-user": appearance.palette.user,
      "--vaultguard-pg-studio-file": appearance.palette.file,
      "--vaultguard-pg-studio-folder": appearance.palette.folder,
      "--vaultguard-pg-studio-read": appearance.palette.read,
      "--vaultguard-pg-studio-write": appearance.palette.write,
      "--vaultguard-pg-studio-admin": appearance.palette.admin,
      "--vaultguard-pg-studio-low": appearance.palette.low,
      "--vaultguard-pg-studio-medium": appearance.palette.medium,
      "--vaultguard-pg-studio-high": appearance.palette.high,
    });
  }

  private setStudioStatus(text: string): void {
    this.studioStatusEl?.setText(text);
  }

  private persistGraphOptions(): void {
    if (!this.currentVaultId) return;
    this.plugin.settings.permissionsGraphVaultStates = upsertGraphVaultState(
      this.plugin.settings.permissionsGraphVaultStates,
      this.currentVaultId,
      graphOptionsToSavedState(this.graphOptions),
    );
    void this.plugin.saveSettings();
  }

  private queueGraphRender(debounce = false): void {
    const vaultId = this.currentVaultId;
    if (!vaultId) return;
    if (this.optionRenderTimer) {
      clearTimeout(this.optionRenderTimer);
      this.optionRenderTimer = null;
    }
    const run = (): void => {
      this.optionRenderTimer = null;
      void this.loadAndRender(vaultId).catch((err) => {
        this.setStatus(`Could not update graph: ${(err as Error)?.message ?? String(err)}`);
      });
    };
    if (debounce) {
      this.optionRenderTimer = setTimeout(run, 250);
      return;
    }
    run();
  }

  private async resetCurrentVaultGraphOptions(): Promise<void> {
    if (!this.currentVaultId) return;
    this.plugin.settings.permissionsGraphVaultStates = removeGraphVaultState(
      this.plugin.settings.permissionsGraphVaultStates,
      this.currentVaultId,
    );
    await this.plugin.saveSettings();
    await this.render();
  }

  private async resetGlobalGraphDefaults(): Promise<void> {
    this.plugin.settings.permissionsGraphDefaults = graphOptionsToSavedState(DEFAULT_GRAPH_OPTIONS);
    if (this.currentVaultId) {
      this.plugin.settings.permissionsGraphVaultStates = removeGraphVaultState(
        this.plugin.settings.permissionsGraphVaultStates,
        this.currentVaultId,
      );
    }
    await this.plugin.saveSettings();
    await this.render();
  }

  private syncLegendStateFromOptions(): void {
    this.legendState.set("user", this.graphOptions.nodeTypes.users);
    this.legendState.set("file", this.graphOptions.nodeTypes.files);
    this.legendState.set("folder", this.graphOptions.nodeTypes.folders);
    this.legendState.set("read", this.graphOptions.accessLevels.read);
    this.legendState.set("write", this.graphOptions.accessLevels.write);
    this.legendState.set("admin", this.graphOptions.accessLevels.admin);
  }

  private refreshUserFilterOptions(): void {
    if (!this.userFilterSelectEl) return;
    const selected = this.graphOptions.selectedUsers[0] ?? "";
    this.userFilterSelectEl.empty();
    this.userFilterSelectEl.createEl("option", { value: "", text: "All users" });
    const members = Array.from(this.memberById.values()).sort((a, b) =>
      this.labelForUser(a.userId).localeCompare(this.labelForUser(b.userId)),
    );
    for (const member of members) {
      this.userFilterSelectEl.createEl("option", {
        value: member.userId,
        text: this.labelForUser(member.userId),
      });
    }
    this.userFilterSelectEl.value = selected;
  }

  // ─── Data load + render ─────────────────────────────────────────────────────

  private async loadAndRender(vaultId: string, force = false): Promise<void> {
    // Use the plugin's cache (memory, then the encrypted on-disk envelope) so
    // reopening — even after a restart — is instant; only hit the network on
    // first load, after the TTL, or on an explicit refresh.
    const scopedFetch = this.graphOptions.pathPrefix.length > 0;
    const desiredFiles = Math.min(this.graphOptions.maxFiles, DEFAULT_GRAPH_BUDGETS.maxInitialFiles);
    let cached = force || scopedFetch ? null : await this.plugin.loadPersistedPermissionsGraphCache(vaultId);
    if (cached && cached.scanned < Math.min(desiredFiles, cached.total)) cached = null;
    const dataset = cached ?? (await this.fetchDataset(vaultId, scopedFetch));
    if (!cached && !scopedFetch) void this.plugin.setPermissionsGraphCache(vaultId, dataset);

    this.rules = dataset.rules;
    this.memberById = new Map(dataset.members.map((m) => [m.userId, m]));
    this.refreshUserFilterOptions();
    const folderSummaries = dataset.folderSummaries ?? [];
    // Files + folders share one lookup (paths never collide); the folder set
    // lets the explain panel label folders as folders.
    this.summaryByPath = new Map(
      [...dataset.summaries, ...folderSummaries].map((s) => [normalizePath(s.path), s]),
    );
    this.folderPathSet = new Set(folderSummaries.map((s) => normalizePath(s.path)));

    const filtered = filterGraphDataset({
      vaultId,
      members: dataset.members,
      summaries: dataset.summaries,
      folderSummaries,
      rules: dataset.rules as ExplainRule[],
    }, this.graphOptions, DEFAULT_GRAPH_BUDGETS);
    this.summaryByPath = new Map(
      [...filtered.summaries, ...filtered.folderSummaries].map((s) => [normalizePath(s.path), s]),
    );
    this.folderPathSet = new Set(filtered.folderSummaries.map((s) => normalizePath(s.path)));
    const estimate = estimateDetailedGraphComplexity(filtered, this.graphOptions);
    const decision = decideGraphRender(estimate, this.graphOptions, DEFAULT_GRAPH_BUDGETS);
    this.renderDecision = decision;
    this.lastEstimate = estimate;
    this.actualMode = decision.actualMode;
    this.hoverHighlightEnabled = decision.hoverEnabled;

    if (decision.actualMode === "refused") {
      this.renderUnsafeDetailedGraph(decision, estimate);
      this.renderLargeGraphNotice(decision, filtered);
      this.renderDebugReadout(buildGraphDebugReadoutModel(decision, estimate, 0, 0, this.graphOptions));
    } else {
      const elements = decision.actualMode === "aggregated"
        ? buildAggregatedGraphElements(filtered, this.graphOptions, DEFAULT_GRAPH_BUDGETS).elements
        : buildGraphElements({
            vaultId,
            members: filtered.members,
            summaries: filtered.summaries,
            folderSummaries: filtered.folderSummaries,
            rules: dataset.rules as ExplainRule[],
            includeUsers: this.graphOptions.nodeTypes.users,
            includeFiles: this.graphOptions.nodeTypes.files,
            includeFolders: this.graphOptions.nodeTypes.folders,
          });

      this.renderGraph(elements);
      this.renderLargeGraphNotice(decision, filtered);
      this.renderDebugReadout(
        buildGraphDebugReadoutModel(
          decision,
          estimate,
          elements.filter((el) => !el.data.source && !el.data.target).length,
          elements.filter((el) => !!el.data.source && !!el.data.target).length,
          this.graphOptions,
        ),
      );
    }

    // Visible-file count note (and truncation warning for large vaults).
    const readableCount = filtered.readableFileCount;
    const cacheSuffix = cached ? " · cached" : "";
    this.setNote(
      dataset.truncated
        ? `Showing ${readableCount} readable file(s) of the first ${dataset.scanned} scanned (vault has ${dataset.total}; capped for performance).${cacheSuffix}`
        : `Showing ${readableCount} readable file(s).${cacheSuffix}`,
    );
    this.setStatus("");
  }

  /** Fetch the raw dataset: members + rules + a parallel access sweep of files AND folders. */
  private async fetchDataset(vaultId: string, scopedFetch = false): Promise<PermissionsGraphDataset> {
    const source = this.plugin.getPermissionsGraphDataSource();
    this.setStatus("Loading members and permissions…");

    // Members + rules (rules drive the expiring/dashed determination + explain).
    const [members, rules] = await Promise.all([
      source.listVaultMembers(vaultId),
      source.getPermissions().catch(() => [] as PermissionRule[]),
    ]);

    // Sweep the viewer's visible files, bounded by the cap.
    const allPaths = source.getAllFilePaths();
    const scopedPaths = scopedFetch
      ? allPaths.filter((path) => pathStartsWithPrefix(path, this.graphOptions.pathPrefix))
      : allPaths;
    const cap = Math.min(this.graphOptions.maxFiles, DEFAULT_GRAPH_BUDGETS.maxInitialFiles);
    const capped = scopedPaths.slice(0, cap);
    const truncated = scopedPaths.length > capped.length;

    this.setStatus(`Resolving access for ${capped.length} file(s)…`);
    const summaries = await this.sweepAccess(source, capped, "file");

    // Folders: evaluate access at each ancestor folder of a readable file, so
    // folder-level grants show up as user→folder edges just like files.
    const readable = summaries.filter((s) => s.principals && s.principals.length > 0);
    const folderPaths = Array.from(
      new Set(readable.flatMap((s) => ancestorFolders(normalizePath(s.path)))),
    ).slice(0, DEFAULT_GRAPH_BUDGETS.maxInitialFiles);

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
      total: scopedPaths.length,
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

  private renderUnsafeDetailedGraph(
    decision: GraphRenderDecision,
    estimate: GraphComplexityEstimate,
  ): void {
    this.activeLayout?.stop();
    this.activeLayout = null;
    this.currentBaseElements = [];
    if (this.cy) {
      this.cy.destroy();
      this.cy = null;
    }
    this.canvasEl?.empty();
    this.renderExplainMessage("Detailed graph paused", [
      `This graph is estimated at ${estimate.nodeCount} node(s) and ${estimate.edgeCount} edge(s).`,
      `Budget exceeded: ${decision.exceeded.join(", ") || "large graph threshold"}.`,
      "Use folder, search, user, access-level, depth, max-file, or max-edge filters before rendering Detailed mode.",
    ]);
  }

  private renderLargeGraphNotice(
    decision: GraphRenderDecision,
    filtered: FilteredGraphDataset,
  ): void {
    if (!this.noticeEl) return;
    this.noticeEl.empty();
    const shouldShow = decision.large || filtered.omittedByMaxFiles > 0 || filtered.omittedByMaxEdges > 0 || filtered.omittedByFilters > 0;
    this.noticeEl.toggleClass("is-hidden", !shouldShow);
    if (!shouldShow) return;

    const title = decision.actualMode === "aggregated"
      ? "Large graph shown in aggregate mode"
      : decision.actualMode === "refused"
        ? "Detailed graph needs narrower filters"
        : "Graph safety limits applied";
    this.noticeEl.createDiv({ cls: EXPLAIN_TITLE_CLS, text: title });
    const parts: string[] = [];
    if (decision.exceeded.length > 0) parts.push(`Exceeded: ${decision.exceeded.join(", ")}`);
    if (filtered.omittedByMaxFiles > 0) parts.push(`${filtered.omittedByMaxFiles} file(s) skipped by max files`);
    if (filtered.omittedByMaxEdges > 0) parts.push(`${filtered.omittedByMaxEdges} edge(s) skipped by max edges`);
    if (filtered.omittedByFilters > 0) parts.push(`${filtered.omittedByFilters} item(s) removed by filters`);
    parts.push("Narrow by folder, search, user, access level, depth, max files, or max edges.");
    for (const part of parts) {
      this.noticeEl.createDiv({ cls: NOTE_CLS, text: part });
    }
  }

  private renderDebugReadout(model: GraphDebugReadoutModel): void {
    if (!this.debugEl) return;
    this.debugEl.empty();
    const details = this.debugEl.createEl("details");
    details.open = this.graphOptions.debugExpanded || model.actualMode !== "detailed";
    details.addEventListener("toggle", () => {
      this.graphOptions = { ...this.graphOptions, debugExpanded: details.open };
      this.persistGraphOptions();
    });
    const summary = details.createEl("summary", { cls: DEBUG_SUMMARY_CLS });
    setIcon(summary.createSpan(), "activity");
    summary.createSpan({ text: "Performance" });

    const grid = details.createDiv({ cls: DEBUG_GRID_CLS });
    const rows: Array<[string, string]> = [
      ["Requested", model.requestedMode],
      ["Actual", model.actualMode],
      ["Visible nodes", String(model.nodeCount)],
      ["Visible edges", String(model.edgeCount)],
      ["Estimated nodes", String(model.estimatedNodeCount)],
      ["Estimated edges", String(model.estimatedEdgeCount)],
      ["Layout", model.selectedLayout],
      ["Labels", model.labelMode],
      ["Depth", String(model.activeDepth)],
      ["Max files", String(model.maxFiles)],
      ["Max edges", String(model.maxEdges)],
      ["Exceeded", model.exceeded.length > 0 ? model.exceeded.join(", ") : "none"],
      ["Disabled", model.disabled.length > 0 ? model.disabled.join(", ") : "none"],
    ];
    for (const [label, value] of rows) {
      grid.createDiv({ text: label });
      grid.createDiv({ text: value });
    }
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
  private buildLayout(
    fit = true,
    positions: Record<string, GraphStudioPosition> = {},
  ): cytoscape.LayoutOptions {
    const layoutMode = this.renderDecision?.layoutModeUsed ?? "radial";
    const animate = this.renderDecision?.animationEnabled ?? true;
    if (layoutMode === "folder" || layoutMode === "sections") {
      return {
        name: "preset",
        positions,
        animate,
        animationDuration: animate ? 250 : 0,
        padding: 36,
        fit,
      } as cytoscape.LayoutOptions;
    }
    if (layoutMode === "grid") {
      return {
        name: "grid",
        animate: false,
        padding: 32,
        fit,
        // Space cells by each node's footprint so the degree-based sizes don't
        // collide or read as uneven on the lattice.
        avoidOverlap: true,
        avoidOverlapPadding: 12,
        spacingFactor: 1.15,
        condense: false,
        nodeDimensionsIncludeLabels: true,
      } as cytoscape.LayoutOptions;
    }
    if (layoutMode === "force") {
      return {
        name: "cose",
        animate,
        animationDuration: animate ? 350 : 0,
        padding: 30,
        nodeDimensionsIncludeLabels: true,
        randomize: true,
        fit,
        componentSpacing: 80,
        gravity: 0.25,
        numIter: 350,
        nodeRepulsion: () => 9000,
        idealEdgeLength: () => 90,
        edgeElasticity: () => 80,
      } as cytoscape.LayoutOptions;
    }

    return {
      name: "concentric",
      animate,
      animationDuration: animate ? 250 : 0,
      padding: 36,
      fit,
      avoidOverlap: true,
      nodeDimensionsIncludeLabels: true, // keep labels from overlapping the rings
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
    this.activeLayout?.stop();
    const presentation = buildGraphStudioPresentation(this.currentBaseElements, this.graphOptions);
    this.activeLayout = this.cy.layout(this.buildLayout(false, presentation.positions));
    this.activeLayout.run();
  }

  /**
   * Keep labels readable when zoomed out. Cytoscape renders font-size in graph
   * (model) units, so on-screen label size = modelFont × zoom — a label shrinks
   * as you zoom out. Below 1:1 we counter that by inflating the model font by
   * 1/zoom so the label holds a ~constant on-screen size, but we CAP the
   * inflation at CAP×. Past the cap (zoom < 1/CAP ≈ 0.4) the model font is
   * pinned, so labels resume shrinking with further zoom-out and a large graph
   * collapses into a clean overview instead of a constant-size wall of text —
   * the exact failure that got the un-capped f0604ce version reverted (db3492d).
   * At/above 1:1 we drop the override so labels still enlarge naturally on zoom-in.
   */
  private updateLabelFonts(): void {
    if (!this.cy) return;
    const cy = this.cy;
    const scale = this.graphOptions.appearance.labelScale ?? 1;
    const zoom = cy.zoom() || 1;
    if (zoom >= 1) {
      cy.batch(() => {
        cy.nodes().removeStyle("font-size");
        cy.edges().removeStyle("font-size");
      });
      return;
    }
    // Hold labels readable down to ~1/CAP zoom, then let the overview shrink.
    const CAP = 2.5;
    const inflate = Math.min(1 / Math.max(zoom, 0.05), CAP);
    // Bases mirror the per-selector font-size in buildStylesheet() (node 13,
    // vault 15, edge label 11); labelScale is folded in so the Text size control
    // and the zoom compensation compose instead of fighting.
    const fontFor = (base: number): number => Math.max(1, Math.round(base * scale * inflate));
    cy.batch(() => {
      cy.nodes().style("font-size", fontFor(13));
      cy.$("node.vault").style("font-size", fontFor(15));
      cy.$("edge[label]").style("font-size", fontFor(11));
    });
  }

  /** Coalesce rapid zoom events into one font refresh per animation frame. */
  private scheduleLabelFontUpdate(): void {
    if (this.zoomFontRaf != null) return;
    if (typeof requestAnimationFrame !== "function") {
      this.updateLabelFonts();
      return;
    }
    this.zoomFontRaf = requestAnimationFrame(() => {
      this.zoomFontRaf = null;
      this.updateLabelFonts();
    });
  }

  private renderGraph(elements: GraphElement[]): void {
    if (!this.canvasEl) return;
    this.activeLayout?.stop();
    this.activeLayout = null;
    if (this.cy) {
      this.cy.destroy();
      this.cy = null;
    }

    this.currentBaseElements = elements.slice();
    const presentation = buildGraphStudioPresentation(this.currentBaseElements, this.graphOptions);
    this.cy = cytoscape({
      container: this.canvasEl,
      elements: elements as cytoscape.ElementDefinition[],
      style: this.buildStylesheet(),
      layout: this.buildLayout(true, presentation.positions),
      wheelSensitivity: 0.2,
      minZoom: 0.1,
      maxZoom: 3,
    });
    applyGraphStudioPresentation(this.cy, presentation);
    this.cy.style(this.buildStylesheet());
    // Keep labels legible at any zoom: cytoscape scales font with zoom, so for
    // zoomed-out views we inflate the model font (capped) to hold on-screen size.
    this.cy.on("zoom", () => this.scheduleLabelFontUpdate());
    this.updateLabelFonts();

    // Tap a node or edge → narrate the precedence into the explain panel and
    // focus the graph on that node.
    this.cy.on("tap", "node", (evt: cytoscape.EventObjectNode) => {
      const node = evt.target;
      const kind = node.data("kind") as string | undefined;
      if (this.actualMode === "aggregated" && kind === "folder") {
        const path = node.data("path") as string | undefined;
        if (path) this.updateGraphOptions({ pathPrefix: path, renderMode: "auto" });
        return;
      }
      if (this.actualMode === "aggregated" && kind === "user") {
        const userId = node.data("userId") as string | undefined;
        if (userId) this.updateGraphOptions({ selectedUsers: [userId], renderMode: "auto" });
        return;
      }
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
    if (this.hoverHighlightEnabled) {
      this.cy.on("mouseover", "node", (evt: cytoscape.EventObjectNode) => {
        this.hoverHighlight(evt.target);
      });
      this.cy.on("mouseout", "node", () => this.clearHover());
    }

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
        const ownerDocument = this.canvasEl?.ownerDocument;
        const target = ownerDocument?.body;
        const v = target ? ownerDocument.defaultView?.getComputedStyle(target).getPropertyValue(name).trim() : "";
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
    const labelsOn = (this.renderDecision?.labelModeUsed ?? "on") === "on";
    // User-adjustable text size (Graph Studio → Text size). Multiplies every label
    // font size so the graph stays readable at the default fit-to-view zoom.
    const labelScale = this.graphOptions.appearance.labelScale ?? 1;
    const fontPx = (base: number): number => Math.max(1, Math.round(base * labelScale));

    return [
      // Base node: a circular dot with its label BELOW it (native-graph style),
      // fading the label out when zoomed far out so the canvas stays legible.
      {
        selector: "node",
        style: {
          shape: "ellipse",
          width: 18,
          height: 18,
          "background-color": fileColor,
          "border-width": 0,
          label: labelsOn ? "data(label)" : "",
          color: textColor,
          "font-size": fontPx(13),
          "text-valign": "bottom",
          "text-halign": "center",
          "text-margin-y": 4,
          // Show the FULL name — wrap long labels onto multiple lines instead of
          // truncating with an ellipsis. Wrap width scales with the text size.
          "text-wrap": "wrap",
          "text-max-width": `${Math.round(200 * labelScale)}px`,
          "min-zoomed-font-size": 6,
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
          "font-size": fontPx(15),
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
          width: (ele: cytoscape.NodeSingular) => 24 + Math.min(ele.degree(true), 14) * 1.6,
          height: (ele: cytoscape.NodeSingular) => 24 + Math.min(ele.degree(true), 14) * 1.6,
          "font-weight": "bold",
        },
      } as unknown as cytoscape.StylesheetStyle,
      {
        selector: "node.file",
        style: {
          "background-color": fileColor,
          // Size scales with how many users can reach the file. Floor kept large
          // enough that a low-degree file is still a clearly visible, tappable dot.
          width: (ele: cytoscape.NodeSingular) => 18 + Math.min(ele.degree(true), 12) * 1.4,
          height: (ele: cytoscape.NodeSingular) => 18 + Math.min(ele.degree(true), 12) * 1.4,
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
          label: labelsOn ? "data(label)" : "",
          "font-size": fontPx(11),
          color: mutedColor,
          "text-rotation": "autorotate",
          "text-background-color": bgSecondary,
          "text-background-opacity": 0.8,
          "text-background-padding": "2px",
          "min-zoomed-font-size": 7,
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
      // Graph Studio data mappings are sparse and last in the semantic cascade.
      // With untouched defaults these selectors match nothing, preserving the
      // current theme-derived graph exactly.
      {
        selector: "node[studioColor]",
        style: {
          "background-color": "data(studioColor)",
        },
      } as cytoscape.StylesheetStyle,
      {
        selector: "node[studioSize]",
        style: {
          width: "data(studioSize)",
          height: "data(studioSize)",
        },
      } as cytoscape.StylesheetStyle,
      {
        selector: "edge[studioColor]",
        style: {
          "line-color": "data(studioColor)",
          "target-arrow-color": "data(studioColor)",
        },
      } as cytoscape.StylesheetStyle,
      {
        selector: "edge[studioWidth]",
        style: {
          width: "data(studioWidth)",
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
    if (key === "user") this.updateGraphOptions({ nodeTypes: { ...this.graphOptions.nodeTypes, users: next } });
    else if (key === "file") this.updateGraphOptions({ nodeTypes: { ...this.graphOptions.nodeTypes, files: next } });
    else if (key === "folder") this.updateGraphOptions({ nodeTypes: { ...this.graphOptions.nodeTypes, folders: next } });
    else if (key === "read") this.updateGraphOptions({ accessLevels: { ...this.graphOptions.accessLevels, read: next } });
    else if (key === "write") this.updateGraphOptions({ accessLevels: { ...this.graphOptions.accessLevels, write: next } });
    else if (key === "admin") this.updateGraphOptions({ accessLevels: { ...this.graphOptions.accessLevels, admin: next } });
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
      const q = this.graphOptions.searchQuery.trim().toLowerCase();
      if (q && this.cy) {
        const cy = this.cy;
        const matches = cy.nodes().filter((node) => {
          // Scope gate: when not "all", only nodes of the chosen kind qualify.
          const kind = String(node.data("kind") ?? "");
          if (this.graphOptions.searchScope !== "all" && kind !== this.graphOptions.searchScope) return false;
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
    if (!this.graphOptions.searchQuery) {
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

      // BFS outward from the focused node to the configured focus depth.
      let frontier = focus;
      let neighborhood = focus;
      for (let i = 0; i < this.graphOptions.depth; i++) {
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
    const capped = capExplainRows(principals, DEFAULT_GRAPH_BUDGETS.maxExplainRows);
    const renderPrincipal = (p: GraphPrincipal): void => {
      this.renderAccessRow(rows, {
        dotColor: colorForUser(p.userId),
        label: this.principalLabel(p),
        level: p.level,
        onClick: () => this.explainPermission(p.userId, path),
      });
    };
    for (const p of capped.visible) {
      renderPrincipal(p);
    }
    if (capped.hiddenCount > 0) {
      this.addShowMore(rows, capped.hiddenCount, () => {
        for (const p of principals.slice(capped.visible.length)) renderPrincipal(p);
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
    const capped = capExplainRows(access, DEFAULT_GRAPH_BUDGETS.maxExplainRows);
    const renderPathAccess = (a: { path: string; level: GraphAccessLevel }): void => {
      const isFolder = this.folderPathSet.has(normalizePath(a.path));
      const base = a.path.split("/").filter(Boolean).pop() || a.path;
      this.renderAccessRow(rows, {
        dotColor: null,
        label: isFolder ? `${base}/` : base,
        sublabel: a.path,
        level: a.level,
        onClick: () => this.explainPermission(uid, a.path),
      });
    };
    for (const a of capped.visible) {
      renderPathAccess(a);
    }
    if (capped.hiddenCount > 0) {
      this.addShowMore(rows, capped.hiddenCount, () => {
        for (const a of access.slice(capped.visible.length)) renderPathAccess(a);
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
    const capped = capExplainRows(trace.steps, DEFAULT_GRAPH_BUDGETS.maxExplainRows);
    for (const step of capped.visible) {
      list.createEl("li", { text: step });
    }
    if (capped.hiddenCount > 0) {
      this.addShowMore(this.explainEl, capped.hiddenCount, () => {
        for (const step of trace.steps.slice(capped.visible.length)) {
          list.createEl("li", { text: step });
        }
      });
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

  private addShowMore(parent: HTMLElement, hiddenCount: number, onClick: () => void): void {
    const button = parent.createEl("button", {
      cls: SHOW_MORE_CLS,
      text: `Show ${hiddenCount} more`,
    });
    button.addEventListener("click", () => {
      button.remove();
      onClick();
    });
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

function pathStartsWithPrefix(path: string, prefix: string): boolean {
  const normalizedPath = normalizePath(path);
  const normalizedPrefix = normalizePath(prefix);
  return normalizedPath === normalizedPrefix || normalizedPath.startsWith(`${normalizedPrefix}/`);
}
