import cytoscape from "cytoscape";
import { App, Modal, Notice } from "obsidian";

import { runPermissionsGraphVirtualQaPipeline } from "./permissions-graph-qa-session";
import { createPermissionsGraphActiveSliceRendererForQa } from "./permissions-graph-renderer";

interface DestroyableCore {
  destroy(): void;
}

/** Small independently testable owner for abort and Cytoscape teardown. */
export class PermissionsGraphVirtualQaOwnedResources {
  private controller: AbortController | null = null;
  private core: DestroyableCore | null = null;

  get hasCore(): boolean {
    return this.core !== null;
  }

  get hasActiveRun(): boolean {
    return this.controller !== null;
  }

  beginRun(): AbortController {
    this.teardown();
    this.controller = new AbortController();
    return this.controller;
  }

  finishRun(controller: AbortController): void {
    if (this.controller === controller) this.controller = null;
  }

  cancelRun(): void {
    this.controller?.abort();
  }

  replaceCore(core: DestroyableCore): void {
    this.core?.destroy();
    this.core = core;
  }

  teardown(): void {
    this.controller?.abort();
    this.controller = null;
    this.core?.destroy();
    this.core = null;
  }
}

export interface PermissionsGraphVirtualQaModalOptions {
  readonly onClosed?: (modal: PermissionsGraphVirtualQaModal) => void;
}

/** Transient development-only UI. This module is loaded only through a dev-gated import. */
export class PermissionsGraphVirtualQaModal extends Modal {
  private readonly resources = new PermissionsGraphVirtualQaOwnedResources();
  private readonly disposers: Array<() => void> = [];
  private evidenceText = "";

  constructor(app: App, private readonly options: PermissionsGraphVirtualQaModalOptions = {}) {
    super(app);
  }

  onOpen(): void {
    this.contentEl.empty();
    this.contentEl.addClass("vaultguard-permissions-graph-qa-modal");
    this.titleEl.setText("Virtual permissions graph synthetic QA");

    const warning = this.contentEl.createEl("div");
    warning.createEl("strong", { text: "Use a disposable vault for synthetic QA only." });
    warning.createEl("p", {
      text:
        "This development-only fixture does not validate real vault behavior and is not production activation proof by itself.",
    });
    warning.createEl("p", {
      text:
        "It reads no vault data, calls no network/API, writes no cache or graph state, and may briefly consume CPU and memory.",
    });

    const gates = this.contentEl.createEl("ul");
    for (const text of [
      "Development build: passed",
      "Desktop only: passed",
      "Debug logging enabled: passed",
      "Synthetic data only: enforced",
    ]) {
      gates.createEl("li", { text });
    }

    const confirmationLabel = this.contentEl.createEl("label");
    const confirmation = confirmationLabel.createEl("input");
    confirmation.type = "checkbox";
    confirmationLabel.appendText(
      " I confirm that I am using a disposable vault and understand this synthetic-only warning.",
    );

    const controls = this.contentEl.createDiv();
    const runButton = controls.createEl("button", { text: "Run synthetic QA" });
    const cancelButton = controls.createEl("button", { text: "Cancel" });
    const copyButton = controls.createEl("button", { text: "Copy synthetic QA evidence" });
    runButton.disabled = true;
    cancelButton.disabled = true;
    copyButton.disabled = true;

    const statusEl = this.contentEl.createEl("p", { text: "Awaiting disposable-vault confirmation." });
    statusEl.setAttr("aria-live", "polite");
    const graphContainer = this.contentEl.createDiv({
      cls: "vaultguard-permissions-graph-qa-canvas",
    });
    graphContainer.setAttr("role", "img");
    graphContainer.setAttr(
      "aria-label",
      "Synthetic virtual permissions graph preview. Evidence details follow below.",
    );
    const evidenceEl = this.contentEl.createEl("pre", {
      text: "No synthetic QA evidence yet.",
      cls: "vaultguard-permissions-graph-qa-evidence",
    });

    this.listen(confirmation, "change", () => {
      runButton.disabled = !confirmation.checked || this.resources.hasActiveRun;
      statusEl.setText(
        confirmation.checked
          ? "Disposable-vault confirmation recorded. Ready to run synthetic QA."
          : "Awaiting disposable-vault confirmation.",
      );
    });

    this.listen(runButton, "click", () => {
      if (!confirmation.checked) return;
      void this.runSyntheticQa({
        graphContainer,
        runButton,
        cancelButton,
        copyButton,
        statusEl,
        evidenceEl,
        isConfirmed: () => confirmation.checked,
      });
    });
    this.listen(cancelButton, "click", () => {
      this.resources.cancelRun();
      statusEl.setText("Cancelling synthetic QA safely...");
    });
    this.listen(copyButton, "click", () => {
      void this.copyEvidence();
    });
  }

  onClose(): void {
    this.resources.teardown();
    for (const dispose of this.disposers.splice(0)) dispose();
    this.evidenceText = "";
    this.contentEl.empty();
    this.options.onClosed?.(this);
  }

  private async runSyntheticQa(elements: {
    readonly graphContainer: HTMLElement;
    readonly runButton: HTMLButtonElement;
    readonly cancelButton: HTMLButtonElement;
    readonly copyButton: HTMLButtonElement;
    readonly statusEl: HTMLElement;
    readonly evidenceEl: HTMLElement;
    readonly isConfirmed: () => boolean;
  }): Promise<void> {
    const controller = this.resources.beginRun();
    elements.graphContainer.empty();
    elements.runButton.disabled = true;
    elements.cancelButton.disabled = false;
    elements.copyButton.disabled = true;
    elements.statusEl.setText("Starting fixed synthetic QA fixture...");

    try {
      const result = await runPermissionsGraphVirtualQaPipeline({
        disposableVaultConfirmed: true,
        signal: controller.signal,
        onStage: (stage) => elements.statusEl.setText(`Synthetic QA stage: ${stage}`),
      });
      this.evidenceText = JSON.stringify(result.evidence, null, 2);
      elements.evidenceEl.setText(this.evidenceText);
      elements.copyButton.disabled = false;

      if (result.evidence.status === "cancelled" || !result.resources || controller.signal.aborted) {
        elements.statusEl.setText("Synthetic QA cancelled; no graph slice was published.");
        return;
      }

      const cy = cytoscape({
        container: elements.graphContainer,
        elements: [],
        layout: { name: "preset" },
        minZoom: 0.05,
        maxZoom: 4,
        style: qaStylesheet(
          resolvePermissionsGraphQaPalette(
            elements.graphContainer.ownerDocument?.defaultView?.getComputedStyle(
              elements.graphContainer,
            ),
          ),
        ),
      });
      this.resources.replaceCore(cy);
      const renderer = createPermissionsGraphActiveSliceRendererForQa(cy);
      renderer.render(result.resources.activeSlice, {
        preserveSelection: false,
        preserveViewport: false,
      });
      cy.fit(cy.elements(), 24);
      elements.statusEl.setText(
        `Synthetic QA complete: ${result.evidence.materializedNodeCount} nodes and ${result.evidence.materializedEdgeCount} edges rendered.`,
      );
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown synthetic QA error";
      elements.statusEl.setText(`Synthetic QA failed safely: ${message}`);
      this.evidenceText = JSON.stringify({
        schemaVersion: 1,
        status: "failed",
        disposableVaultConfirmed: true,
        diagnostics: [message],
        safety: {
          syntheticOnly: true,
          noVaultAccess: true,
          noNetworkAccess: true,
          noCacheAccess: true,
          noPersistence: true,
        },
      }, null, 2);
      elements.evidenceEl.setText(this.evidenceText);
      elements.copyButton.disabled = false;
    } finally {
      this.resources.finishRun(controller);
      elements.cancelButton.disabled = true;
      elements.runButton.disabled = !elements.isConfirmed();
    }
  }

  private async copyEvidence(): Promise<void> {
    if (!this.evidenceText) return;
    try {
      await navigator.clipboard.writeText(this.evidenceText);
      new Notice("VaultGuard synthetic graph QA evidence copied.", 4000);
    } catch {
      new Notice("VaultGuard synthetic graph QA evidence is visible in the modal but could not be copied.", 6000);
    }
  }

  private listen<K extends keyof HTMLElementEventMap>(
    element: HTMLElement,
    event: K,
    listener: (event: HTMLElementEventMap[K]) => void,
  ): void {
    element.addEventListener(event, listener as EventListener);
    this.disposers.push(() => element.removeEventListener(event, listener as EventListener));
  }
}

export interface PermissionsGraphQaPalette {
  readonly node: string;
  readonly text: string;
  readonly outline: string;
  readonly user: string;
  readonly folder: string;
  readonly edge: string;
  readonly write: string;
  readonly admin: string;
  readonly selected: string;
}

interface PermissionsGraphQaThemeStyle {
  getPropertyValue(property: string): string;
}

/** Resolve canvas-safe colors from the active Obsidian theme at render time. */
export function resolvePermissionsGraphQaPalette(
  styles?: PermissionsGraphQaThemeStyle | null,
): PermissionsGraphQaPalette {
  const color = (properties: readonly string[], fallback: string): string => {
    for (const property of properties) {
      const value = styles?.getPropertyValue(property).trim();
      if (value) return value;
    }
    return fallback;
  };

  return Object.freeze({
    node: color(["--interactive-accent", "--color-blue"], "#2563eb"),
    text: color(["--text-normal"], "#111827"),
    outline: color(["--background-primary"], "#ffffff"),
    user: color(["--color-purple", "--interactive-accent"], "#7c3aed"),
    folder: color(["--color-orange", "--color-yellow"], "#b45309"),
    edge: color(["--text-muted", "--text-normal"], "#4b5563"),
    write: color(["--color-green", "--interactive-success"], "#15803d"),
    admin: color(["--color-red", "--text-error"], "#b91c1c"),
    selected: color(["--color-cyan", "--interactive-accent-hover"], "#0891b2"),
  });
}

function qaStylesheet(palette: PermissionsGraphQaPalette): cytoscape.StylesheetJson {
  return [
    {
      selector: "node",
      style: {
        "background-color": palette.node,
        color: palette.text,
        label: "data(label)",
        "font-size": 8,
        "text-outline-color": palette.outline,
        "text-outline-width": 2,
        width: 14,
        height: 14,
      },
    },
    { selector: "node.user", style: { "background-color": palette.user, width: 22, height: 22 } },
    { selector: "node.folder", style: { "background-color": palette.folder, shape: "round-rectangle" } },
    {
      selector: "edge",
      style: {
        width: 1,
        "line-color": palette.edge,
        "target-arrow-color": palette.edge,
        "target-arrow-shape": "triangle",
        "curve-style": "bezier",
        opacity: 0.8,
      },
    },
    { selector: "edge.level-write", style: { "line-color": palette.write, "target-arrow-color": palette.write } },
    { selector: "edge.level-admin", style: { "line-color": palette.admin, "target-arrow-color": palette.admin } },
    { selector: ":selected", style: { "border-width": 3, "border-color": palette.selected } },
  ];
}
