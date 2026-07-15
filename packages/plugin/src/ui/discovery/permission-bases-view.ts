import {
  BasesView,
  type BasesViewRegistration,
  type QueryController,
  type TFile,
} from "obsidian";
import type { PathAccessSummary } from "../../api/client";
import type { PermissionDecision } from "../../plugin/permission-store";
import {
  resolveBasesAccess,
  type BasesAccessContext,
  type BasesAccessRow,
} from "../../plugin/discovery/bases-access";
import { normalizeVaultRelativePath } from "../../plugin/discovery/search-model";

export const VAULTGUARD_BASES_VIEW_ID = "vaultguard-access";

export interface PermissionBasesViewContext {
  isEnabled(): boolean;
  getBatchPathAccess(paths: string[]): Promise<PathAccessSummary[]>;
  peekPermissionDecision(path: string): PermissionDecision;
  isMetadataSuppressed(path: string): boolean;
  isPathExcluded(path: string): boolean;
  isCurrentLocalPath(path: string): boolean;
  openPath(path: string): Promise<void>;
  subscribePermissionChanges(handler: () => void): () => void;
  subscribeModuleChanges(handler: () => void): () => void;
  yieldControl(): Promise<void>;
  labels: {
    off: string;
    verifying: string;
    prefix: string;
    readable(count: number): string;
    showing(count: number): string;
    unavailable(count: number): string;
    verified: string;
    cached: string;
  };
}

function coerceMaxRows(value: unknown): 100 | 250 | 500 {
  const parsed = typeof value === "number" ? value : Number(value);
  if (parsed === 100 || parsed === 500) return parsed;
  return 250;
}

function safeLabel(path: string): string {
  return path.split("/").at(-1) ?? path;
}

function capitalize(value: string): string {
  return value.length > 0 ? `${value[0]?.toUpperCase()}${value.slice(1)}` : value;
}

/**
 * This class lives in its own dynamically imported module because Obsidian
 * 1.8.x does not expose BasesView. Never import it from the startup graph.
 */
export class VaultGuardPermissionBasesView extends BasesView {
  type = VAULTGUARD_BASES_VIEW_ID;
  private readonly rootEl: HTMLElement;
  private generation = 0;
  private refreshTimer: number | null = null;

  constructor(
    controller: QueryController,
    containerEl: HTMLElement,
    private readonly ctx: PermissionBasesViewContext,
  ) {
    super(controller);
    this.rootEl = containerEl;
    this.rootEl.classList.add("vaultguard-bases-access");
  }

  onload(): void {
    this.register(this.ctx.subscribePermissionChanges(() => this.scheduleRefresh()));
    this.register(this.ctx.subscribeModuleChanges(() => {
      this.generation += 1;
      if (!this.ctx.isEnabled()) this.renderOffState();
      else this.scheduleRefresh();
    }));
    this.onDataUpdated();
  }

  onunload(): void {
    this.generation += 1;
    if (this.refreshTimer !== null) window.clearTimeout(this.refreshTimer);
    this.refreshTimer = null;
    this.rootEl.replaceChildren();
  }

  onDataUpdated(): void {
    this.scheduleRefresh();
  }

  private scheduleRefresh(): void {
    this.generation += 1;
    const scheduledGeneration = this.generation;
    if (this.refreshTimer !== null) window.clearTimeout(this.refreshTimer);
    this.refreshTimer = window.setTimeout(() => {
      this.refreshTimer = null;
      void this.refresh(scheduledGeneration);
    }, 50);
  }

  private renderOffState(): void {
    this.rootEl.replaceChildren();
    const status = this.rootEl.ownerDocument.createElement("p");
    status.className = "vaultguard-discovery-status";
    status.setAttribute("role", "status");
    status.setAttribute("aria-live", "polite");
    status.textContent = this.ctx.labels.off;
    this.rootEl.append(status);
  }

  private snapshotPaths(): string[] {
    const data = this.data?.data ?? [];
    const paths: string[] = [];
    for (const entry of data) {
      // Do not call entry.getValue here: even evaluating frontmatter/formulas
      // must wait until the path has passed VaultGuard authorization.
      const path = normalizeVaultRelativePath((entry.file as TFile | undefined)?.path);
      if (path) paths.push(path);
    }
    return paths;
  }

  private accessContext(generation: number): BasesAccessContext {
    return {
      getBatchPathAccess: (paths) => this.ctx.getBatchPathAccess(paths),
      peekPermissionDecision: (path) => this.ctx.peekPermissionDecision(path),
      isMetadataSuppressed: (path) => this.ctx.isMetadataSuppressed(path),
      isPathExcluded: (path) => this.ctx.isPathExcluded(path),
      isGenerationCurrent: (candidate) =>
        candidate === generation && candidate === this.generation && this.ctx.isEnabled(),
      yieldControl: () => this.ctx.yieldControl(),
    };
  }

  private async refresh(generation: number): Promise<void> {
    if (!this.ctx.isEnabled()) {
      this.renderOffState();
      return;
    }
    const doc = this.rootEl.ownerDocument;
    const loading = doc.createElement("p");
    loading.className = "vaultguard-discovery-status";
    loading.setAttribute("role", "status");
    loading.setAttribute("aria-live", "polite");
    loading.setAttribute("aria-atomic", "true");
    loading.textContent = this.ctx.labels.verifying;
    this.rootEl.replaceChildren(loading);

    const maxRows = coerceMaxRows(this.config?.get("maxRows"));
    const result = await resolveBasesAccess(this.snapshotPaths(), this.accessContext(generation), {
      generation,
      maxRows,
    });
    if (result.cancelled || generation !== this.generation || !this.ctx.isEnabled()) return;

    const fragment = doc.createDocumentFragment();
    const status = doc.createElement("p");
    status.className = "vaultguard-discovery-status";
    status.setAttribute("role", "status");
    status.setAttribute("aria-live", "polite");
    status.setAttribute("aria-atomic", "true");
    const qualifiers = [
      result.truncated
        ? this.ctx.labels.showing(result.rows.length)
        : this.ctx.labels.readable(result.rows.length),
      result.unverified > 0 ? this.ctx.labels.unavailable(result.unverified) : "",
    ].filter(Boolean);
    status.textContent = `${this.ctx.labels.prefix}: ${qualifiers.join(", ")}.`;
    fragment.append(status);

    const list = doc.createElement("ul");
    list.className = "vaultguard-bases-access-list";
    const showProvenance = this.config?.get("showProvenance") === true;
    for (const row of result.rows) list.append(this.renderRow(doc, row, showProvenance));
    fragment.append(list);
    if (generation === this.generation && this.ctx.isEnabled()) {
      this.rootEl.replaceChildren(fragment);
    }
  }

  private renderRow(
    doc: Document,
    row: BasesAccessRow,
    showProvenance: boolean,
  ): HTMLLIElement {
    const item = doc.createElement("li");
    item.className = "vaultguard-bases-access-row";
    const link = doc.createElement("a");
    link.href = "#";
    link.textContent = safeLabel(row.path);
    link.setAttribute("aria-label", `${safeLabel(row.path)}, ${row.path}`);
    link.addEventListener("click", (event) => {
      event.preventDefault();
      void this.openIfStillAuthorized(row.path);
    });
    item.append(link);

    const badge = doc.createElement("span");
    badge.className = `vaultguard-bases-access-badge is-${row.level}`;
    badge.textContent = capitalize(row.level);
    item.append(badge);
    if (showProvenance) {
      const provenance = doc.createElement("span");
      provenance.className = "vaultguard-bases-access-provenance";
      provenance.textContent =
        row.provenance === "verified" ? this.ctx.labels.verified : this.ctx.labels.cached;
      item.append(provenance);
    }
    return item;
  }

  private async openIfStillAuthorized(path: string): Promise<void> {
    if (!this.ctx.isEnabled() || !this.ctx.isCurrentLocalPath(path)) return;
    const generation = this.generation;
    const check = await resolveBasesAccess([path], this.accessContext(generation), {
      generation,
      maxRows: 1,
    });
    if (
      !check.cancelled &&
      check.rows.length === 1 &&
      this.ctx.isCurrentLocalPath(path) &&
      this.ctx.isEnabled()
    ) {
      await this.ctx.openPath(path);
    }
  }
}

export function createPermissionBasesRegistration(
  ctx: PermissionBasesViewContext,
): BasesViewRegistration {
  return {
    name: "VaultGuard access",
    icon: "shield-check",
    factory: (controller, containerEl) =>
      new VaultGuardPermissionBasesView(controller, containerEl, ctx),
    options: () => [
      {
        key: "maxRows",
        type: "dropdown",
        displayName: "Maximum rows",
        default: "250",
        options: { "100": "100", "250": "250", "500": "500" },
      },
      {
        key: "showProvenance",
        type: "toggle",
        displayName: "Show verification source",
        default: false,
      },
    ],
  };
}
