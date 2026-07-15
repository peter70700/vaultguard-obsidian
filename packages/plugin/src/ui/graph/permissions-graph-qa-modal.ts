import cytoscape from "cytoscape";
import {
  App,
  type KeymapContext,
  type KeymapEventHandler,
  Modal,
  Notice,
  type Scope,
} from "obsidian";

import { createPermissionsGraphCameraState } from "./permissions-graph-camera";
import type { PermissionsGraphIndex } from "./permissions-graph-model";
import type { PermissionsGraphOverviewBuffers } from "./permissions-graph-overview-buffers";
import {
  createPermissionsGraphOverviewRenderer,
  type PermissionsGraphOverviewRenderer,
} from "./permissions-graph-overview-renderer";
import type { PermissionsGraphOverviewTheme } from "./permissions-graph-overview-palette";
import {
  buildPermissionsGraphOverviewEdges,
  type PermissionsGraphOverviewEdgeSnapshot,
} from "./permissions-graph-overview-edges";
import {
  PermissionsGraphQaVirtualInteractionController,
  type PermissionsGraphQaSelectedNodeSummary,
  type PermissionsGraphQaVirtualInteractionEvidence,
} from "./permissions-graph-qa-interaction";
import { runPermissionsGraphVirtualQaPipeline } from "./permissions-graph-qa-session";
import {
  createPermissionsGraphActiveSliceRendererForQa,
  type PermissionsGraphActiveSlice,
} from "./permissions-graph-renderer";
import {
  PERMISSIONS_GRAPH_COMMITTED_TRANSITION_PHASE_F_MARKER,
  createPermissionsGraphCommittedTransition,
  type PermissionsGraphCommittedTransition,
  type PermissionsGraphCommittedTransitionFrame,
} from "./permissions-graph-transition";

interface DestroyableCore {
  destroy(): void;
}

interface DestroyableInteraction {
  clearTransientState(): void;
  destroy(): void;
}

interface CancellableTransition {
  cancel(): unknown;
}

/** Small independently testable owner for abort and Cytoscape teardown. */
export class PermissionsGraphVirtualQaOwnedResources {
  private controller: AbortController | null = null;
  private core: DestroyableCore | null = null;
  private overview: PermissionsGraphOverviewRenderer | null = null;
  private interaction: DestroyableInteraction | null = null;
  private transition: CancellableTransition | null = null;
  private readonly disposers: Array<() => void> = [];
  private cancelFrame: (() => void) | null = null;
  private cancelTransitionFrame: (() => void) | null = null;

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
    this.cancelTransitionFrame?.();
    this.cancelTransitionFrame = null;
    this.transition?.cancel();
  }

  clearTransientInteraction(): boolean {
    if (!this.interaction) return false;
    this.interaction.clearTransientState();
    return true;
  }

  replaceCore(core: DestroyableCore): void {
    this.core?.destroy();
    this.core = core;
  }

  replaceOverview(overview: PermissionsGraphOverviewRenderer): void {
    this.overview?.destroy();
    this.overview = overview;
  }

  replaceInteraction(interaction: DestroyableInteraction): void {
    this.interaction?.destroy();
    this.interaction = interaction;
  }

  replaceTransition(transition: CancellableTransition): void {
    this.transition?.cancel();
    this.transition = transition;
  }

  replaceTransitionFrame(cancel: (() => void) | null): void {
    this.cancelTransitionFrame?.();
    this.cancelTransitionFrame = cancel;
  }

  finishTransition(transition: CancellableTransition): void {
    if (this.transition === transition) this.transition = null;
    this.cancelTransitionFrame = null;
  }

  addDisposer(dispose: () => void): void {
    this.disposers.push(dispose);
  }

  replaceScheduledFrame(cancel: (() => void) | null): void {
    this.cancelFrame?.();
    this.cancelFrame = cancel;
  }

  teardown(): void {
    this.controller?.abort();
    this.controller = null;
    this.cancelFrame?.();
    this.cancelFrame = null;
    this.cancelTransitionFrame?.();
    this.cancelTransitionFrame = null;
    this.transition?.cancel();
    this.transition = null;
    for (const dispose of this.disposers.splice(0)) dispose();
    this.interaction?.destroy();
    this.interaction = null;
    this.overview?.destroy();
    this.overview = null;
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

  close(): void {
    // Obsidian detaches modal DOM before invoking onClose(). Tear down while
    // the graph stage is still connected so its pointerout reaches the host
    // tooltip manager and dismisses any visible accessibility tooltip.
    this.resources.teardown();
    super.close();
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
    this.installGraphEscapeHandler(graphContainer);
    const selectedSummaryEl = this.contentEl.createDiv({
      cls: "vaultguard-permissions-graph-qa-selected-summary",
    });
    selectedSummaryEl.setAttr("role", "status");
    selectedSummaryEl.setAttr("aria-live", "polite");
    selectedSummaryEl.setText("No synthetic graph node selected.");
    const edgeStatusEl = this.contentEl.createDiv({
      cls: "vaultguard-permissions-graph-qa-edge-status",
    });
    edgeStatusEl.setAttr("role", "status");
    edgeStatusEl.setAttr("aria-live", "polite");
    edgeStatusEl.setText("Synthetic overview edges have not been generated yet.");
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
        selectedSummaryEl,
        edgeStatusEl,
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
    readonly selectedSummaryEl: HTMLElement;
    readonly edgeStatusEl: HTMLElement;
    readonly evidenceEl: HTMLElement;
    readonly isConfirmed: () => boolean;
  }): Promise<void> {
    const restoreGraphFocus = elements.graphContainer.ownerDocument.activeElement === elements.graphContainer;
    const controller = this.resources.beginRun();
    elements.graphContainer.empty();
    elements.runButton.disabled = true;
    elements.cancelButton.disabled = false;
    elements.copyButton.disabled = true;
    elements.statusEl.setText("Starting fixed synthetic QA fixture...");
    elements.selectedSummaryEl.setText("No synthetic graph node selected.");
    elements.edgeStatusEl.setText("Generating bounded synthetic overview edges...");

    try {
      const result = await runPermissionsGraphVirtualQaPipeline({
        disposableVaultConfirmed: true,
        signal: controller.signal,
        onStage: (stage) => elements.statusEl.setText(`Synthetic QA stage: ${stage}`),
      });
      if (result.evidence.status === "cancelled" || !result.resources || controller.signal.aborted) {
        this.publishEvidence(result.evidence, elements.evidenceEl);
        elements.copyButton.disabled = false;
        elements.statusEl.setText("Synthetic QA cancelled; no graph slice was published.");
        return;
      }
      const resources = result.resources;

      const overviewCanvas = elements.graphContainer.createEl("canvas", {
        cls: "vaultguard-permissions-graph-qa-overview",
      });
      overviewCanvas.setAttr("aria-hidden", "true");
      const detailContainer = elements.graphContainer.createDiv({
        cls: "vaultguard-permissions-graph-qa-detail",
      });

      const cy = cytoscape({
        container: detailContainer,
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
      const initialDetailSlice = resources.refinement?.beforeSlice ?? resources.activeSlice;
      renderer.render(initialDetailSlice, {
        preserveSelection: false,
        preserveViewport: false,
      });
      cy.fit(cy.elements(), 24);

      const createCanvas = (): HTMLCanvasElement => {
        const canvas = elements.graphContainer.ownerDocument.createElement("canvas");
        canvas.addClass("vaultguard-permissions-graph-qa-overview");
        canvas.setAttr("aria-hidden", "true");
        return canvas;
      };
      const overview = createPermissionsGraphOverviewRenderer({
        canvas: overviewCanvas,
        createReplacementCanvas: createCanvas,
        replaceCanvas: (previous, replacement) => previous.replaceWith(replacement),
      });
      this.resources.replaceOverview(overview);

      let cameraRevision = 0;
      let scheduled = false;
      let overviewBuffers = resources.overviewBuffers;
      let overviewEdges: PermissionsGraphOverviewEdgeSnapshot = resources.overviewEdges;
      let edgePresentationFingerprint = resources.overviewBuffers.bufferFingerprint;
      let interactionEvidence: PermissionsGraphQaVirtualInteractionEvidence | null = null;
      let overviewRenderEvidence: Record<string, unknown> | null = null;
      let transitionEvidence: Record<string, unknown> | null = null;
      const activeWindow = elements.graphContainer.ownerDocument.defaultView ?? window;
      const theme = (): PermissionsGraphOverviewTheme =>
        elements.graphContainer.ownerDocument.body.classList.contains("theme-dark") ? "dark" : "light";
      const currentCamera = () => {
        const pan = cy.pan();
        return createPermissionsGraphCameraState({
          panX: pan.x,
          panY: pan.y,
          zoom: cy.zoom(),
          revision: cameraRevision,
        });
      };
      const publishCombinedEvidence = () => this.publishEvidence({
        ...result.evidence,
        ...(overviewRenderEvidence ? { overviewRender: overviewRenderEvidence } : {}),
        ...(interactionEvidence ? { virtualInteraction: interactionEvidence } : {}),
        ...(transitionEvidence ? { transition: transitionEvidence } : {}),
      }, elements.evidenceEl);
      const redraw = () => {
        scheduled = false;
        if (controller.signal.aborted) return;
        const camera = currentCamera();
        if (
          overviewEdges.cameraRevision !== camera.revision ||
          overviewEdges.layoutGeneration !== overviewBuffers.layoutGeneration ||
          overviewEdges.coordinateRevision !== overviewBuffers.coordinateRevision ||
          overviewEdges.topologyFingerprint !== overviewBuffers.topologyFingerprint ||
          edgePresentationFingerprint !== overviewBuffers.bufferFingerprint
        ) {
          overviewEdges = buildPermissionsGraphOverviewEdges({
            model: resources.model,
            index: resources.index,
            layout: resources.layout,
            projectedMedianSpacing: 6 * camera.zoom,
            cameraRevision: camera.revision,
            presentationPositions: overviewBuffers.positions,
            signal: controller.signal,
          });
          edgePresentationFingerprint = overviewBuffers.bufferFingerprint;
        }
        const bounds = elements.graphContainer.getBoundingClientRect();
        const renderResult = overview.render({
          buffers: overviewBuffers,
          edges: overviewEdges,
          camera,
          width: Math.max(0, bounds.width),
          height: Math.max(0, bounds.height),
          pixelRatio: activeWindow.devicePixelRatio || 1,
          theme: theme(),
        });
        overviewRenderEvidence = {
          backend: renderResult.backend,
          drawablePointCount: renderResult.drawablePointCount,
          overviewEdgeSegmentCount: renderResult.overviewEdgeSegmentCount,
          drawableEdgeSegmentCount: renderResult.drawableEdgeSegmentCount,
          uploadedBytes: renderResult.uploadedBytes,
          cameraRevision: camera.revision,
          zoom: camera.zoom,
          pan: { x: camera.panX, y: camera.panY },
          logicalViewport: { width: renderResult.viewport.width, height: renderResult.viewport.height },
          backingViewport: {
            width: renderResult.viewport.backingWidth,
            height: renderResult.viewport.backingHeight,
          },
          pixelRatio: renderResult.viewport.pixelRatio,
          theme: theme(),
          ...overview.getDiagnostics(),
        };
        elements.edgeStatusEl.setText(formatPermissionsGraphOverviewEdgeStatus(overviewEdges));
        publishCombinedEvidence();
      };
      const schedule = (cameraChanged = true) => {
        if (cameraChanged) cameraRevision = cameraRevision === 0xffff_ffff ? 0 : cameraRevision + 1;
        if (scheduled) return;
        scheduled = true;
        const frame = activeWindow.requestAnimationFrame(redraw);
        this.resources.replaceScheduledFrame(() => activeWindow.cancelAnimationFrame(frame));
      };
      const viewportListener = () => schedule();
      cy.on("pan zoom resize", viewportListener);
      this.resources.addDisposer(() => cy.off("pan zoom resize", viewportListener));

      const resizeObserver = typeof ResizeObserver === "undefined"
        ? null
        : new ResizeObserver(() => {
            cy.resize();
            schedule();
          });
      resizeObserver?.observe(elements.graphContainer);
      if (resizeObserver) this.resources.addDisposer(() => resizeObserver.disconnect());

      const themeObserver = typeof MutationObserver === "undefined"
        ? null
        : new MutationObserver(() => overview.updateTheme(theme()));
      themeObserver?.observe(elements.graphContainer.ownerDocument.body, {
        attributes: true,
        attributeFilter: ["class"],
      });
      if (themeObserver) this.resources.addDisposer(() => themeObserver.disconnect());

      const activateInteraction = () => {
        const interaction = new PermissionsGraphQaVirtualInteractionController({
          stage: elements.graphContainer,
          cy,
          model: resources.model,
          index: resources.index,
          layout: resources.layout,
          spatial: resources.spatial,
          overviewBuffers,
          renderer,
          initialSlice: resources.activeSlice,
          budget: { maxNodes: 900, maxEdges: 1_600 },
          getCamera: currentCamera,
          requestFrame: (callback) => activeWindow.requestAnimationFrame(callback),
          cancelFrame: (handle) => activeWindow.cancelAnimationFrame(handle),
          onOverviewBuffersChanged: (buffers) => {
            overviewBuffers = buffers;
            schedule(false);
          },
          onCoordinatesCommitted: () => schedule(false),
          onStatus: (text) => elements.statusEl.setText(text),
          onSelectedSummary: (summary) => {
            elements.selectedSummaryEl.setText(formatSelectedSummary(summary));
          },
          onEvidence: (evidence) => {
            interactionEvidence = evidence;
            publishCombinedEvidence();
          },
        });
        this.resources.replaceInteraction(interaction);
        if (restoreGraphFocus) elements.graphContainer.focus({ preventScroll: true });
      };

      const sourceById = new Map(
        initialDetailSlice.nodes.map((node) => [node.data.id, node.position] as const),
      );
      const transitionEntries = resources.activeSlice.nodes
        .map((node) => {
          const ordinal = resources.index.getNodeOrdinal(node.data.id);
          if (ordinal === undefined) return null;
          return { ordinal, source: sourceById.get(node.data.id) ?? node.position };
        })
        .filter((entry): entry is NonNullable<typeof entry> => entry !== null)
        .sort((left, right) => left.ordinal - right.ordinal);
      const sourceCoordinates = new Float32Array(transitionEntries.length * 2);
      for (let index = 0; index < transitionEntries.length; index += 1) {
        sourceCoordinates[index * 2] = transitionEntries[index]!.source.x;
        sourceCoordinates[index * 2 + 1] = transitionEntries[index]!.source.y;
      }
      const transitionStartedAt = activeWindow.performance.now();
      const transition = createPermissionsGraphCommittedTransition({
        layout: resources.layout,
        topologyFingerprint: resources.model.topologyFingerprint,
        layoutGeneration: resources.layout.layoutGeneration,
        coordinateRevision: resources.layout.coordinateRevision,
        ordinals: transitionEntries.map((entry) => entry.ordinal),
        sourceCoordinates,
        startedAtMs: transitionStartedAt,
        durationMs: 300,
        reducedMotion: prefersPermissionsGraphReducedMotion(activeWindow),
        signal: controller.signal,
      });
      this.resources.replaceTransition(transition);
      elements.statusEl.setText(
        transition.mode === "immediate"
          ? "Synchronizing the committed synthetic graph target immediately."
          : "Animating one bounded committed synthetic graph transition.",
      );

      await new Promise<void>((resolve) => {
        let settled = false;
        let previousPreparationMs = 0;
        const finish = (frame: PermissionsGraphCommittedTransitionFrame) => {
          if (settled) return;
          settled = true;
          controller.signal.removeEventListener("abort", onAbort);
          transitionEvidence = transitionFrameEvidence(transition, frame);
          overviewBuffers = resources.overviewBuffers;
          renderer.render(resources.activeSlice, {
            preserveSelection: true,
            preserveViewport: true,
          });
          this.resources.finishTransition(transition);
          resolve();
        };
        const present = (frame: PermissionsGraphCommittedTransitionFrame) => {
          const presentation = applyPermissionsGraphTransitionFrame({
            buffers: resources.overviewBuffers,
            slice: resources.activeSlice,
            index: resources.index,
            frame,
          });
          overviewBuffers = presentation.buffers;
          renderer.render(presentation.slice, {
            preserveSelection: true,
            preserveViewport: true,
          });
          transitionEvidence = transitionFrameEvidence(transition, frame);
          redraw();
        };
        const onAbort = () => {
          const frame = transition.cancel();
          present(frame);
          finish(frame);
        };
        const step = (timestamp: number) => {
          if (settled) return;
          const preparationStartedAt = activeWindow.performance.now();
          const frame = transition.sample(timestamp, previousPreparationMs);
          present(frame);
          previousPreparationMs = activeWindow.performance.now() - preparationStartedAt;
          if (frame.status !== "active") {
            finish(frame);
            return;
          }
          const handle = activeWindow.requestAnimationFrame(step);
          this.resources.replaceTransitionFrame(() => activeWindow.cancelAnimationFrame(handle));
        };
        controller.signal.addEventListener("abort", onAbort, { once: true });
        step(transitionStartedAt);
      });

      if (controller.signal.aborted) {
        publishCombinedEvidence();
        elements.copyButton.disabled = false;
        elements.statusEl.setText("Synthetic QA transition cancelled at the committed target.");
        return;
      }
      activateInteraction();
      redraw();
      elements.copyButton.disabled = false;
      elements.statusEl.setText(
        `Synthetic QA complete: ${result.evidence.overview.nodeCount} overview points, ${result.evidence.overview.edges.emittedSegmentCount} bounded edge segments, and ${result.evidence.materializedNodeCount} bounded detail nodes.`,
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

  private installGraphEscapeHandler(graphContainer: HTMLElement): void {
    type RuntimeKeymapEventHandler = KeymapEventHandler & {
      func(event: KeyboardEvent, context: KeymapContext): false | unknown;
    };
    const runtimeScope = this.scope as Scope & { keys?: RuntimeKeymapEventHandler[] };
    const modalEscapeHandler = runtimeScope.keys?.find((handler) => handler.key === "Escape");
    if (!modalEscapeHandler) return;

    this.scope.unregister(modalEscapeHandler);
    const graphEscapeHandler = this.scope.register([], "Escape", (event, context) => {
      if (
        graphContainer.ownerDocument.activeElement === graphContainer &&
        this.resources.clearTransientInteraction()
      ) {
        event.preventDefault();
        event.stopPropagation();
        return false;
      }
      return modalEscapeHandler.func(event, context);
    });
    this.disposers.push(() => this.scope.unregister(graphEscapeHandler));
  }

  private publishEvidence(evidence: unknown, evidenceEl: HTMLElement): void {
    this.evidenceText = JSON.stringify(evidence, null, 2);
    evidenceEl.setText(this.evidenceText);
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

interface PermissionsGraphReducedMotionView {
  matchMedia(query: string): { readonly matches: boolean };
}

export function prefersPermissionsGraphReducedMotion(
  view: PermissionsGraphReducedMotionView | null | undefined,
): boolean {
  if (!view) return false;
  try {
    return view.matchMedia("(prefers-reduced-motion: reduce)").matches;
  } catch {
    return false;
  }
}

export function applyPermissionsGraphTransitionFrame(input: {
  readonly buffers: PermissionsGraphOverviewBuffers;
  readonly slice: PermissionsGraphActiveSlice;
  readonly index: PermissionsGraphIndex;
  readonly frame: PermissionsGraphCommittedTransitionFrame;
}): { readonly buffers: PermissionsGraphOverviewBuffers; readonly slice: PermissionsGraphActiveSlice } {
  const { buffers, frame } = input;
  if (
    buffers.topologyFingerprint !== input.slice.sourceTopologyFingerprint ||
    buffers.layoutGeneration !== frame.layoutGeneration ||
    buffers.coordinateRevision !== frame.coordinateRevision ||
    frame.coordinates.length !== frame.ordinals.length * 2
  ) throw new Error("Permissions graph transition frame does not match the committed overview target.");

  const positions = buffers.positions.slice();
  const coordinateIndexByOrdinal = new Map<number, number>();
  for (let index = 0; index < frame.ordinals.length; index += 1) {
    const ordinal = frame.ordinals[index] as number;
    const x = frame.coordinates[index * 2];
    const y = frame.coordinates[index * 2 + 1];
    if (ordinal >= buffers.nodeCount || !Number.isFinite(x) || !Number.isFinite(y)) {
      throw new Error("Permissions graph transition frame contains an invalid numeric coordinate.");
    }
    positions[ordinal * 2] = x as number;
    positions[ordinal * 2 + 1] = y as number;
    coordinateIndexByOrdinal.set(ordinal, index);
  }
  const ranges = coalesceTransitionOrdinals(Array.from(frame.ordinals).sort((a, b) => a - b));
  const presentationBuffers: PermissionsGraphOverviewBuffers = Object.freeze({
    ...buffers,
    positions,
    invalidationKey: `${buffers.invalidationKey}:transition`,
    bufferFingerprint: `${buffers.bufferFingerprint}:transition:${frame.status}:${frame.progress.toFixed(6)}`,
    update: Object.freeze({ kind: "coordinates" as const, ranges }),
  });
  const nodes = input.slice.nodes.map((node) => {
    const ordinal = input.index.getNodeOrdinal(node.data.id);
    const coordinateIndex = ordinal === undefined ? undefined : coordinateIndexByOrdinal.get(ordinal);
    if (coordinateIndex === undefined) return node;
    return Object.freeze({
      ...node,
      position: Object.freeze({
        x: frame.coordinates[coordinateIndex * 2] as number,
        y: frame.coordinates[coordinateIndex * 2 + 1] as number,
      }),
    });
  });
  const slice: PermissionsGraphActiveSlice = Object.freeze({
    ...input.slice,
    nodes: Object.freeze(nodes),
    elements: Object.freeze([...nodes, ...input.slice.edges]),
  });
  return Object.freeze({ buffers: presentationBuffers, slice });
}

function coalesceTransitionOrdinals(
  ordinals: readonly number[],
): readonly { readonly startOrdinal: number; readonly endOrdinalExclusive: number }[] {
  if (ordinals.length === 0) return Object.freeze([]);
  const ranges: Array<{ readonly startOrdinal: number; readonly endOrdinalExclusive: number }> = [];
  let start = ordinals[0] as number;
  let end = start + 1;
  for (let index = 1; index < ordinals.length; index += 1) {
    const ordinal = ordinals[index] as number;
    if (ordinal === end) {
      end += 1;
      continue;
    }
    ranges.push(Object.freeze({ startOrdinal: start, endOrdinalExclusive: end }));
    start = ordinal;
    end = ordinal + 1;
  }
  ranges.push(Object.freeze({ startOrdinal: start, endOrdinalExclusive: end }));
  return Object.freeze(ranges);
}

function transitionFrameEvidence(
  transition: PermissionsGraphCommittedTransition,
  frame: PermissionsGraphCommittedTransitionFrame,
): Readonly<Record<string, unknown>> {
  const metrics = transition.getMetrics();
  return Object.freeze({
    marker: PERMISSIONS_GRAPH_COMMITTED_TRANSITION_PHASE_F_MARKER,
    mode: metrics.mode,
    status: frame.status,
    progress: frame.progress,
    durationMs: metrics.durationMs,
    nodeCount: metrics.ordinalCount,
    sourceBytes: metrics.sourceBufferBytes,
    targetBytes: metrics.targetBufferBytes,
    immediateReason: metrics.immediateReason,
    frameCount: metrics.frameCount,
    droppedFrameCount: metrics.droppedFrameCount,
    skippedFrameCount: metrics.skippedFrameCount,
    maximumFrameDurationMs: metrics.maximumFrameDurationMs,
    layoutGeneration: frame.layoutGeneration,
    coordinateRevision: frame.coordinateRevision,
  });
}

export function formatPermissionsGraphOverviewEdgeStatus(
  snapshot: PermissionsGraphOverviewEdgeSnapshot,
): string {
  const mode = snapshot.exact ? "exact" : snapshot.mode;
  return [
    `Synthetic overview edges: ${mode}.`,
    `Sampled: ${snapshot.ordinarySampleSegmentCount}.`,
    `Bundled: ${snapshot.bundledEdgeCount} edges in ${snapshot.bundleSegmentCount} segments.`,
    `Density summaries: ${snapshot.densitySegmentCount}.`,
    `Omitted: ${snapshot.omittedEdgeCount}.`,
  ].join(" ");
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

function formatSelectedSummary(summary: PermissionsGraphQaSelectedNodeSummary): string {
  if (!summary.id) return "No synthetic graph node selected.";
  if (!summary.available) {
    return `Synthetic node ${summary.id}: explain metadata unavailable${summary.diagnostic ? ` (${summary.diagnostic})` : ""}.`;
  }
  const access = summary.accessLevels.length > 0 ? summary.accessLevels.join(", ") : "none";
  return [
    `Selected synthetic node: ${summary.label ?? summary.id}`,
    `ID: ${summary.id}`,
    `Kind: ${summary.kind ?? "unknown"}`,
    `Path: ${summary.path ?? "not applicable"}`,
    `Access: ${access}`,
    `Degree: ${summary.degree}`,
    `Aggregate count: ${summary.aggregateCount}`,
    `Materialized: ${summary.materialized ? "yes" : "no"}`,
    `Selection source: ${summary.selectionSource}`,
  ].join(" | ");
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
