import { ItemView, WorkspaceLeaf } from "obsidian";
import { createI18n } from "../../i18n";
import {
  validateSecureSearchRequest,
  type SearchCoverage,
  type SearchPartialReason,
  type SecureSearchRequest,
  type SecureSearchResponse,
  type SecureSearchResult,
  type SecureSearchScope,
} from "../../plugin/discovery/search-model";
import { VAULTGUARD_DISCOVERY_VIEW_TYPE } from "../view-types";
import type { SemanticRuntimeStatus } from "../../plugin/discovery/semantic-search-runtime";

export interface SecureSearchViewContext {
  isEnabled(): boolean;
  isReady(): boolean;
  search(request: SecureSearchRequest): Promise<SecureSearchResponse>;
  cancel(): void;
  openLocalPath(path: string): Promise<void>;
  subscribeLifecycle(listener: () => void): () => void;
  isSemanticSupported(): boolean;
  isSemanticEnabled(): boolean;
  getSemanticPreferences(): { origin: string; model: string };
  getSemanticStatus(): SemanticRuntimeStatus;
  subscribeSemanticStatus(listener: (status: SemanticRuntimeStatus) => void): () => void;
  setSemanticEnabled(enabled: boolean): Promise<void>;
  updateSemanticPreferences(origin: string, model: string): Promise<void>;
  testSemanticProvider(): Promise<number>;
  buildSemanticIndex(): Promise<SemanticRuntimeStatus>;
  cancelSemanticWork(): void;
  purgeSemanticIndex(): Promise<void>;
}

const ROOT_CLS = "vaultguard-secure-search";

const REASON_KEYS: Record<SearchPartialReason, string> = {
  offline: "discovery.search.reason.offline",
  limit: "discovery.search.reason.limit",
  truncated: "discovery.search.reason.truncated",
  "vault-failure": "discovery.search.reason.vaultFailure",
  "content-failure": "discovery.search.reason.contentFailure",
  "key-unavailable": "discovery.search.reason.keyUnavailable",
  timeout: "discovery.search.reason.timeout",
  cancelled: "discovery.search.reason.cancelled",
  "stale-index": "discovery.search.reason.staleIndex",
};

export class SecureSearchView extends ItemView {
  private readonly i18n = createI18n();
  private unsubscribeLifecycle: (() => void) | null = null;
  private unsubscribeSemanticStatus: (() => void) | null = null;
  private queryEl: HTMLInputElement | null = null;
  private scopeEl: HTMLSelectElement | null = null;
  private contentToggleEl: HTMLInputElement | null = null;
  private semanticQueryToggleEl: HTMLInputElement | null = null;
  private semanticConsentEl: HTMLInputElement | null = null;
  private semanticOriginEl: HTMLInputElement | null = null;
  private semanticModelEl: HTMLInputElement | null = null;
  private semanticStatusEl: HTMLElement | null = null;
  private submitEl: HTMLButtonElement | null = null;
  private cancelEl: HTMLButtonElement | null = null;
  private statusEl: HTMLElement | null = null;
  private resultsEl: HTMLElement | null = null;
  private requestGeneration = 0;
  private searching = false;

  constructor(leaf: WorkspaceLeaf, private readonly context: SecureSearchViewContext) {
    super(leaf);
  }

  getViewType(): string {
    return VAULTGUARD_DISCOVERY_VIEW_TYPE;
  }

  getDisplayText(): string {
    return this.i18n.t("discovery.search.title");
  }

  getIcon(): string {
    return "search-check";
  }

  async onOpen(): Promise<void> {
    this.renderShell();
    this.unsubscribeLifecycle = this.context.subscribeLifecycle(() => {
      this.context.cancel();
      this.requestGeneration += 1;
      this.searching = false;
      this.syncControls();
      this.renderReadiness();
      this.syncSemanticControls();
    });
    this.unsubscribeSemanticStatus = this.context.subscribeSemanticStatus((status) =>
      this.renderSemanticStatus(status),
    );
  }

  async onClose(): Promise<void> {
    this.context.cancel();
    this.requestGeneration += 1;
    this.unsubscribeLifecycle?.();
    this.unsubscribeLifecycle = null;
    this.unsubscribeSemanticStatus?.();
    this.unsubscribeSemanticStatus = null;
    this.queryEl = null;
    this.scopeEl = null;
    this.contentToggleEl = null;
    this.semanticQueryToggleEl = null;
    this.semanticConsentEl = null;
    this.semanticOriginEl = null;
    this.semanticModelEl = null;
    this.semanticStatusEl = null;
    this.submitEl = null;
    this.cancelEl = null;
    this.statusEl = null;
    this.resultsEl = null;
  }

  focusQuery(): void {
    this.queryEl?.focus();
  }

  private renderShell(): void {
    const root = this.containerEl.children[1] as HTMLElement;
    root.empty();
    root.addClass(ROOT_CLS);
    this.i18n.applyToRoot(root);

    const header = root.createDiv({ cls: `${ROOT_CLS}__header` });
    header.createEl("h2", { text: this.i18n.t("discovery.search.title") });
    header.createEl("p", {
      cls: `${ROOT_CLS}__intro`,
      text: this.i18n.t("discovery.search.intro"),
    });

    const form = root.createEl("form", { cls: `${ROOT_CLS}__form` });
    const queryId = `vaultguard-secure-search-${Math.random().toString(36).slice(2)}`;
    form.createEl("label", {
      attr: { for: queryId },
      text: this.i18n.t("discovery.search.queryLabel"),
    });
    this.queryEl = form.createEl("input", {
      type: "search",
      cls: `${ROOT_CLS}__query`,
      attr: {
        id: queryId,
        autocomplete: "off",
        maxlength: "256",
        placeholder: this.i18n.t("discovery.search.queryPlaceholder"),
      },
    });

    const options = form.createDiv({ cls: `${ROOT_CLS}__options` });
    const scopeLabel = options.createEl("label", {
      cls: `${ROOT_CLS}__field`,
      text: this.i18n.t("discovery.search.scopeLabel"),
    });
    this.scopeEl = scopeLabel.createEl("select");
    this.scopeEl.createEl("option", {
      value: "current",
      text: this.i18n.t("discovery.search.scopeCurrent"),
    });
    this.scopeEl.createEl("option", {
      value: "all",
      text: this.i18n.t("discovery.search.scopeAll"),
    });
    this.scopeEl.addEventListener("change", () => this.syncSemanticControls());

    const contentLabel = options.createEl("label", { cls: `${ROOT_CLS}__check` });
    this.contentToggleEl = contentLabel.createEl("input", { type: "checkbox" });
    contentLabel.createSpan({ text: this.i18n.t("discovery.search.includeContent") });
    options.createEl("p", {
      cls: `${ROOT_CLS}__consent`,
      text: this.i18n.t("discovery.search.contentConsent"),
    });

    const semanticQueryLabel = options.createEl("label", { cls: `${ROOT_CLS}__check` });
    this.semanticQueryToggleEl = semanticQueryLabel.createEl("input", { type: "checkbox" });
    semanticQueryLabel.createSpan({ text: this.i18n.t("discovery.semantic.useForQuery") });
    options.createEl("p", {
      cls: `${ROOT_CLS}__consent`,
      text: this.i18n.t("discovery.semantic.currentScopeOnly"),
    });

    const actions = form.createDiv({ cls: `${ROOT_CLS}__actions` });
    this.submitEl = actions.createEl("button", {
      type: "submit",
      cls: "mod-cta",
      text: this.i18n.t("discovery.search.submit"),
    });
    this.cancelEl = actions.createEl("button", {
      type: "button",
      text: this.i18n.t("common.cancel"),
    });
    this.cancelEl.addEventListener("click", () => {
      if (!this.searching) return;
      this.context.cancel();
      this.setStatus(this.i18n.t("discovery.search.cancelling"), "status");
    });
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      void this.runSearch();
    });

    this.renderSemanticPanel(root);

    this.statusEl = root.createDiv({ cls: `${ROOT_CLS}__status` });
    this.statusEl.setAttribute("role", "status");
    this.statusEl.setAttribute("aria-live", "polite");
    this.resultsEl = root.createDiv({ cls: `${ROOT_CLS}__results` });
    this.syncSemanticControls();
    this.renderReadiness();
  }

  private renderSemanticPanel(root: HTMLElement): void {
    const panel = root.createEl("section", { cls: `${ROOT_CLS}__semantic` });
    panel.createEl("h3", { text: this.i18n.t("discovery.semantic.heading") });
    panel.createEl("p", {
      cls: `${ROOT_CLS}__semantic-trust`,
      text: this.i18n.t("discovery.semantic.trust"),
    });

    if (!this.context.isSemanticSupported()) {
      panel.createEl("p", {
        cls: `${ROOT_CLS}__semantic-status`,
        text: this.i18n.t("discovery.semantic.desktopOnly"),
      });
      return;
    }

    const consentLabel = panel.createEl("label", { cls: `${ROOT_CLS}__check` });
    this.semanticConsentEl = consentLabel.createEl("input", { type: "checkbox" });
    this.semanticConsentEl.checked = this.context.isSemanticEnabled();
    consentLabel.createSpan({ text: this.i18n.t("discovery.semantic.consent") });
    this.semanticConsentEl.addEventListener("change", () => {
      const enabled = this.semanticConsentEl?.checked === true;
      if (this.semanticConsentEl) this.semanticConsentEl.disabled = true;
      void this.context.setSemanticEnabled(enabled)
        .then(() => {
          this.setSemanticMessage(
            this.i18n.t(enabled ? "discovery.semantic.enabled" : "discovery.semantic.disabled"),
            "status",
          );
          if (!enabled && this.semanticQueryToggleEl) this.semanticQueryToggleEl.checked = false;
          this.syncSemanticControls();
        })
        .catch((error) => {
          if (this.semanticConsentEl) {
            this.semanticConsentEl.checked = this.context.isSemanticEnabled();
          }
          this.setSemanticMessage(this.formatSemanticError(error), "alert");
        })
        .finally(() => {
          if (this.semanticConsentEl) this.semanticConsentEl.disabled = false;
        });
    });

    const preferences = this.context.getSemanticPreferences();
    const fields = panel.createDiv({ cls: `${ROOT_CLS}__semantic-fields` });
    const originId = `vaultguard-semantic-origin-${Math.random().toString(36).slice(2)}`;
    const originLabel = fields.createEl("label", {
      attr: { for: originId },
      text: this.i18n.t("discovery.semantic.origin"),
    });
    this.semanticOriginEl = originLabel.createEl("input", {
      type: "url",
      attr: { id: originId, autocomplete: "off", spellcheck: "false" },
      value: preferences.origin,
    });
    const modelId = `vaultguard-semantic-model-${Math.random().toString(36).slice(2)}`;
    const modelLabel = fields.createEl("label", {
      attr: { for: modelId },
      text: this.i18n.t("discovery.semantic.model"),
    });
    this.semanticModelEl = modelLabel.createEl("input", {
      type: "text",
      attr: { id: modelId, autocomplete: "off", spellcheck: "false" },
      value: preferences.model,
    });

    const actions = panel.createDiv({ cls: `${ROOT_CLS}__semantic-actions` });
    const addAction = (label: string, action: () => Promise<void> | void): HTMLButtonElement => {
      const button = actions.createEl("button", { type: "button", text: label });
      button.addEventListener("click", () => {
        button.disabled = true;
        Promise.resolve(action())
          .catch((error) => this.setSemanticMessage(this.formatSemanticError(error), "alert"))
          .finally(() => {
            button.disabled = false;
            this.syncSemanticControls();
          });
      });
      return button;
    };
    addAction(this.i18n.t("discovery.semantic.save"), async () => {
      await this.context.updateSemanticPreferences(
        this.semanticOriginEl?.value ?? "",
        this.semanticModelEl?.value ?? "",
      );
      const saved = this.context.getSemanticPreferences();
      if (this.semanticOriginEl) this.semanticOriginEl.value = saved.origin;
      if (this.semanticModelEl) this.semanticModelEl.value = saved.model;
      this.setSemanticMessage(this.i18n.t("discovery.semantic.saved"), "status");
    });
    addAction(this.i18n.t("discovery.semantic.test"), async () => {
      const dimensions = await this.context.testSemanticProvider();
      this.setSemanticMessage(
        this.i18n.t("discovery.semantic.testPassed", { dimensions }),
        "status",
      );
    });
    addAction(this.i18n.t("discovery.semantic.build"), async () => {
      this.setSemanticMessage(this.i18n.t("discovery.semantic.building"), "status");
      await this.context.buildSemanticIndex();
    });
    addAction(this.i18n.t("discovery.semantic.cancel"), () => {
      this.context.cancelSemanticWork();
      this.setSemanticMessage(this.i18n.t("discovery.semantic.cancelling"), "status");
    });
    addAction(this.i18n.t("discovery.semantic.purge"), async () => {
      await this.context.purgeSemanticIndex();
      this.setSemanticMessage(this.i18n.t("discovery.semantic.purged"), "status");
    });

    this.semanticStatusEl = panel.createDiv({ cls: `${ROOT_CLS}__semantic-status` });
    this.semanticStatusEl.setAttribute("role", "status");
    this.semanticStatusEl.setAttribute("aria-live", "polite");
    this.renderSemanticStatus(this.context.getSemanticStatus());
  }

  private renderReadiness(): void {
    this.resultsEl?.empty();
    if (!this.context.isEnabled()) {
      this.setStatus(this.i18n.t("discovery.search.disabled"), "status");
      return;
    }
    if (!this.context.isReady()) {
      this.setStatus(this.i18n.t("discovery.search.notReady"), "status");
      return;
    }
    this.setStatus(this.i18n.t("discovery.search.ready"), "status");
  }

  private async runSearch(): Promise<void> {
    if (!this.queryEl || !this.scopeEl || !this.contentToggleEl) return;
    let request: SecureSearchRequest;
    try {
      request = validateSecureSearchRequest({
        query: this.queryEl.value,
        scope: this.scopeEl.value as SecureSearchScope,
        includeContent: this.contentToggleEl.checked,
        semantic: this.semanticQueryToggleEl?.checked === true,
      });
    } catch {
      this.setStatus(this.i18n.t("discovery.search.invalidQuery"), "alert");
      return;
    }
    if (!this.context.isEnabled() || !this.context.isReady()) {
      this.renderReadiness();
      return;
    }

    const generation = ++this.requestGeneration;
    this.searching = true;
    this.syncControls();
    this.resultsEl?.empty();
    this.setStatus(this.i18n.t("discovery.search.searching"), "status");
    try {
      const response = await this.context.search(request);
      if (generation !== this.requestGeneration) return;
      this.renderResponse(response);
    } catch {
      if (generation !== this.requestGeneration) return;
      this.setStatus(this.i18n.t("discovery.search.failed"), "alert");
    } finally {
      if (generation === this.requestGeneration) {
        this.searching = false;
        this.syncControls();
      }
    }
  }

  private syncControls(): void {
    if (this.submitEl) this.submitEl.disabled = this.searching;
    if (this.cancelEl) this.cancelEl.disabled = !this.searching;
    if (this.queryEl) this.queryEl.disabled = this.searching;
    if (this.scopeEl) this.scopeEl.disabled = this.searching;
    if (this.contentToggleEl) this.contentToggleEl.disabled = this.searching;
    this.syncSemanticControls();
    const form = this.submitEl?.closest("form");
    form?.setAttribute("aria-busy", this.searching ? "true" : "false");
  }

  private renderResponse(response: SecureSearchResponse): void {
    if (!this.resultsEl) return;
    this.resultsEl.empty();
    this.renderCoverage(response.coverage, response.results.length);
    if (response.results.length === 0) {
      this.resultsEl.createEl("p", {
        cls: `${ROOT_CLS}__empty`,
        text: this.i18n.t("discovery.search.noResults"),
      });
      return;
    }

    const list = this.resultsEl.createEl("ol", { cls: `${ROOT_CLS}__list` });
    for (const result of response.results) this.renderResult(list, result);
  }

  private renderCoverage(coverage: SearchCoverage, resultCount: number): void {
    const summary = this.i18n.t("discovery.search.coverage", {
      results: resultCount,
      searched: coverage.vaultsSearched,
      considered: coverage.vaultsConsidered,
      files: coverage.metadataFiles,
    });
    if (coverage.complete) {
      this.setStatus(`${this.i18n.t("discovery.search.complete")} ${summary}`, "status");
      return;
    }
    const reasons = coverage.reasons
      .map((reason) => this.i18n.t(REASON_KEYS[reason]))
      .join(" ");
    this.setStatus(
      `${this.i18n.t("discovery.search.partial")} ${summary} ${reasons}`.trim(),
      "status",
    );
  }

  private renderResult(list: HTMLOListElement, result: SecureSearchResult): void {
    const row = list.createEl("li", { cls: `${ROOT_CLS}__result` });
    const heading = row.createDiv({ cls: `${ROOT_CLS}__result-heading` });
    if (result.local) {
      const open = heading.createEl("button", {
        type: "button",
        cls: `${ROOT_CLS}__path`,
        text: result.path,
        attr: { title: this.i18n.t("discovery.search.openLocal") },
      });
      open.addEventListener("click", () => {
        void this.context.openLocalPath(result.path).catch(() => {
          this.setStatus(this.i18n.t("discovery.search.openFailed"), "alert");
        });
      });
    } else {
      heading.createSpan({ cls: `${ROOT_CLS}__path`, text: result.path });
    }
    heading.createSpan({
      cls: `${ROOT_CLS}__vault`,
      text: result.local
        ? this.i18n.t("discovery.search.localResult", { vault: result.vaultName })
        : this.i18n.t("discovery.search.remoteResult", { vault: result.vaultName }),
    });
    row.createEl("p", {
      cls: `${ROOT_CLS}__semantics`,
      text: this.i18n.t("discovery.search.resultSemantics", {
        match: result.matchKind,
        access: result.access,
      }),
    });
    if (result.snippet) {
      row.createEl("p", { cls: `${ROOT_CLS}__snippet`, text: result.snippet });
    }
  }

  private setStatus(message: string, role: "status" | "alert"): void {
    if (!this.statusEl) return;
    this.statusEl.setText(message);
    this.statusEl.setAttribute("role", role);
    this.statusEl.toggleClass("is-error", role === "alert");
  }

  private syncSemanticControls(): void {
    const supported = this.context.isSemanticSupported();
    const consented = supported && this.context.isSemanticEnabled();
    const currentScope = this.scopeEl?.value !== "all";
    if (!currentScope && this.semanticQueryToggleEl) this.semanticQueryToggleEl.checked = false;
    if (this.semanticQueryToggleEl) {
      this.semanticQueryToggleEl.disabled = this.searching || !consented || !currentScope;
    }
    if (this.semanticConsentEl) this.semanticConsentEl.checked = consented;
    if (this.semanticOriginEl) this.semanticOriginEl.disabled = !supported;
    if (this.semanticModelEl) this.semanticModelEl.disabled = !supported;
  }

  private renderSemanticStatus(status: SemanticRuntimeStatus): void {
    const key = `discovery.semantic.status.${status.state}`;
    let message = this.i18n.t(key, {
      files: status.indexedFiles,
      chunks: status.indexedChunks,
    });
    if (status.totalFiles !== undefined) {
      message += ` ${this.i18n.t("discovery.semantic.status.coverage", {
        processed: status.processedFiles ?? 0,
        total: status.totalFiles,
        skipped: status.skippedFiles ?? 0,
        failed: status.failedFiles ?? 0,
        limited: status.limitedFiles ?? 0,
      })}`;
    }
    this.setSemanticMessage(status.error ? `${message} ${status.error}` : message, status.error ? "alert" : "status");
  }

  private setSemanticMessage(message: string, role: "status" | "alert"): void {
    if (!this.semanticStatusEl) return;
    this.semanticStatusEl.setText(message);
    this.semanticStatusEl.setAttribute("role", role);
    this.semanticStatusEl.toggleClass("is-error", role === "alert");
  }

  private formatSemanticError(error: unknown): string {
    return this.i18n.t("discovery.semantic.error", {
      message: error instanceof Error ? error.message : String(error),
    });
  }
}

export { VAULTGUARD_DISCOVERY_VIEW_TYPE } from "../view-types";
