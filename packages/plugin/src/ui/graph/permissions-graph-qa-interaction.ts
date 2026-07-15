import type cytoscape from "cytoscape";

import { createPermissionsGraphCameraState } from "./permissions-graph-camera";
import type { PermissionsGraphLayoutStore } from "./permissions-graph-layout";
import {
  lookupPermissionsGraphExplainMetadata,
  type PermissionsGraphMaterializationBudget,
} from "./permissions-graph-materialization";
import type { PermissionsGraphIndex, PermissionsGraphModel } from "./permissions-graph-model";
import {
  buildPermissionsGraphOverviewBuffers,
  patchPermissionsGraphOverviewCoordinates,
  type PermissionsGraphOverviewBuffers,
} from "./permissions-graph-overview-buffers";
import {
  buildPermissionsGraphActiveSlice,
  type PermissionsGraphActiveSlice,
  type PermissionsGraphActiveSliceRendererForQa,
} from "./permissions-graph-renderer";
import type {
  PermissionsGraphSpatialIndex,
  PermissionsGraphSpatialMovedNodeUpdateResult,
} from "./permissions-graph-spatial";
import {
  DEFAULT_PERMISSIONS_GRAPH_VIRTUAL_HOVER_DELAY_MS,
  DEFAULT_PERMISSIONS_GRAPH_VIRTUAL_HYSTERESIS_RADIUS,
  PERMISSIONS_GRAPH_VIRTUAL_INTERACTION_PHASE_D_MARKER,
  capturePermissionsGraphInteractionIdentity,
  clearPermissionsGraphVirtualTransientState,
  clientToPermissionsGraphStageRenderedPoint,
  createPermissionsGraphVirtualActivationToken,
  createPermissionsGraphVirtualInteractionState,
  hitTestPermissionsGraphVirtualNode,
  navigatePermissionsGraphVirtualOrdinal,
  patchPermissionsGraphOverviewDynamicFlags,
  planPermissionsGraphVirtualPriorityMaterialization,
  updatePermissionsGraphVirtualInteractionState,
  validatePermissionsGraphNoJumpHandoff,
  validatePermissionsGraphVirtualActivationToken,
  type PermissionsGraphInteractionIdentity,
  type PermissionsGraphPointerKind,
  type PermissionsGraphVirtualActivationToken,
  type PermissionsGraphVirtualInteractionState,
  type PermissionsGraphVirtualSelectionSource,
} from "./permissions-graph-virtual-interaction";

export interface PermissionsGraphQaSelectedNodeSummary {
  readonly available: boolean;
  readonly id: string | null;
  readonly kind: string | null;
  readonly label: string | null;
  readonly path: string | null;
  readonly accessLevels: readonly string[];
  readonly degree: number;
  readonly aggregateCount: number;
  readonly materialized: boolean;
  readonly selectionSource: PermissionsGraphVirtualSelectionSource;
  readonly diagnostic: string | null;
}

export interface PermissionsGraphQaVirtualInteractionEvidence {
  readonly marker: typeof PERMISSIONS_GRAPH_VIRTUAL_INTERACTION_PHASE_D_MARKER;
  readonly virtualInteractionEnabled: true;
  readonly pointerConversionStatus: "ready" | "failed";
  readonly topologyFingerprint: string;
  readonly layoutGeneration: number;
  readonly coordinateRevision: number;
  readonly spatialIndexRevision: string;
  readonly cameraRevision: number;
  readonly activeMaterializationRevision: number;
  readonly currentHoverNodeId: string | null;
  readonly currentSelectedNodeId: string | null;
  readonly currentKeyboardTargetNodeId: string | null;
  readonly hitCount: number;
  readonly missCount: number;
  readonly staleQueryRejectionCount: number;
  readonly hoverMaterializationCount: number;
  readonly clickMaterializationCount: number;
  readonly keyboardMaterializationCount: number;
  readonly materializationNodeCount: number;
  readonly materializationEdgeCount: number;
  readonly evictedNodeCount: number;
  readonly evictedEdgeCount: number;
  readonly noJumpMaximumObservedDelta: number;
  readonly dragCommitCount: number;
  readonly dragRejectedCount: number;
  readonly lastSpatialUpdateMode: PermissionsGraphSpatialMovedNodeUpdateResult["mode"] | "not-run";
  readonly selectionSynchronizationStatus: "ready" | "updating" | "destroyed";
  readonly explainLookupStatus: "idle" | "ready" | "unavailable";
  readonly diagnostics: readonly string[];
  readonly teardownStatus: "active" | "destroyed";
}

export interface PermissionsGraphQaVirtualInteractionControllerOptions {
  readonly stage: HTMLElement;
  readonly cy: cytoscape.Core;
  readonly model: PermissionsGraphModel;
  readonly index: PermissionsGraphIndex;
  readonly layout: PermissionsGraphLayoutStore;
  readonly spatial: PermissionsGraphSpatialIndex;
  readonly overviewBuffers: PermissionsGraphOverviewBuffers;
  readonly renderer: PermissionsGraphActiveSliceRendererForQa;
  readonly initialSlice: PermissionsGraphActiveSlice;
  readonly budget: PermissionsGraphMaterializationBudget;
  readonly hoverDelayMs?: number;
  readonly onOverviewBuffersChanged: (buffers: PermissionsGraphOverviewBuffers) => void;
  readonly onCoordinatesCommitted?: (commit: PermissionsGraphQaCoordinateCommitEvidence) => void;
  readonly onStatus: (text: string) => void;
  readonly onSelectedSummary: (summary: PermissionsGraphQaSelectedNodeSummary) => void;
  readonly onEvidence: (evidence: PermissionsGraphQaVirtualInteractionEvidence) => void;
  readonly getCamera?: () => ReturnType<typeof createPermissionsGraphCameraState>;
  readonly requestFrame?: (callback: FrameRequestCallback) => number;
  readonly cancelFrame?: (handle: number) => void;
}

export interface PermissionsGraphQaCoordinateCommitEvidence {
  readonly movedNodeCount: number;
  readonly coordinateRangeCount: number;
  readonly previousCoordinateRevision: number;
  readonly coordinateRevision: number;
  readonly spatialUpdateMode: PermissionsGraphSpatialMovedNodeUpdateResult["mode"];
}

interface PendingActivation {
  readonly nodeId: string;
  readonly source: "hover" | "click" | "keyboard";
  readonly identity: PermissionsGraphInteractionIdentity;
}

interface MutableEvidenceCounters {
  pointerConversionStatus: "ready" | "failed";
  hitCount: number;
  missCount: number;
  staleQueryRejectionCount: number;
  hoverMaterializationCount: number;
  clickMaterializationCount: number;
  keyboardMaterializationCount: number;
  evictedNodeCount: number;
  evictedEdgeCount: number;
  noJumpMaximumObservedDelta: number;
  dragCommitCount: number;
  dragRejectedCount: number;
  lastSpatialUpdateMode: PermissionsGraphSpatialMovedNodeUpdateResult["mode"] | "not-run";
  explainLookupStatus: "idle" | "ready" | "unavailable";
}

export class PermissionsGraphQaVirtualInteractionController {
  private state: PermissionsGraphVirtualInteractionState;
  private overviewBuffers: PermissionsGraphOverviewBuffers;
  private currentSlice: PermissionsGraphActiveSlice;
  private materializationRevision = 0;
  private hoverTimer: ReturnType<typeof setTimeout> | null = null;
  private hoverAnchor: { readonly x: number; readonly y: number } | null = null;
  private pointerDownToken: PermissionsGraphVirtualActivationToken | null = null;
  private pendingActivation: PendingActivation | null = null;
  private queuedFrame: number | null = null;
  private syncingSelection = false;
  private destroyed = false;
  private dynamicRevision = 0;
  private draggingNodeId: string | null = null;
  private readonly diagnostics = new Set<string>();
  private readonly counters: MutableEvidenceCounters = {
    pointerConversionStatus: "ready",
    hitCount: 0,
    missCount: 0,
    staleQueryRejectionCount: 0,
    hoverMaterializationCount: 0,
    clickMaterializationCount: 0,
    keyboardMaterializationCount: 0,
    evictedNodeCount: 0,
    evictedEdgeCount: 0,
    noJumpMaximumObservedDelta: 0,
    dragCommitCount: 0,
    dragRejectedCount: 0,
    lastSpatialUpdateMode: "not-run",
    explainLookupStatus: "idle",
  };
  private readonly requestFrame: (callback: FrameRequestCallback) => number;
  private readonly cancelFrame: (handle: number) => void;

  private readonly pointerLeaveListener = () => this.clearHover();
  private readonly keydownListener = (event: Event) => this.onKeyDown(event as KeyboardEvent);
  private readonly cyMouseMoveListener = (event: cytoscape.EventObject) => this.onCyMouseMove(event);
  private readonly cyMouseDownListener = (event: cytoscape.EventObject) => this.onCyMouseDown(event);
  private readonly cyTapListener = (event: cytoscape.EventObject) => this.onCyTap(event);
  private readonly cySelectListener = (event: cytoscape.EventObject) => this.onCySelection(event, true);
  private readonly cyUnselectListener = (event: cytoscape.EventObject) => this.onCySelection(event, false);
  private readonly cyGrabListener = (event: cytoscape.EventObject) => this.onCyGrab(event);
  private readonly cyDragFreeListener = (event: cytoscape.EventObject) => this.onCyDragFree(event);

  constructor(private readonly options: PermissionsGraphQaVirtualInteractionControllerOptions) {
    this.overviewBuffers = options.overviewBuffers;
    this.currentSlice = options.initialSlice;
    this.state = createPermissionsGraphVirtualInteractionState({
      materializedNodeIds: options.initialSlice.materializedNodeIds,
    });
    const activeWindow = options.stage.ownerDocument.defaultView;
    this.requestFrame = options.requestFrame ?? ((callback) =>
      (activeWindow?.requestAnimationFrame ?? requestAnimationFrame)(callback));
    this.cancelFrame = options.cancelFrame ?? ((handle) =>
      (activeWindow?.cancelAnimationFrame ?? cancelAnimationFrame)(handle));

    this.ensureFinalRevisionCompatibility();
    options.stage.tabIndex = 0;
    options.stage.setAttribute("role", "application");
    options.stage.setAttribute(
      "aria-label",
      "Synthetic permissions graph interaction surface. Use arrow keys to move the bounded target, Enter or Space to select, and Escape to clear transient focus.",
    );
    options.stage.setAttribute("data-phase-d-marker", PERMISSIONS_GRAPH_VIRTUAL_INTERACTION_PHASE_D_MARKER);
    options.stage.addEventListener("pointerleave", this.pointerLeaveListener);
    options.stage.addEventListener("keydown", this.keydownListener);
    options.cy.on("mousemove", this.cyMouseMoveListener);
    options.cy.on("mousedown", this.cyMouseDownListener);
    options.cy.on("tap", this.cyTapListener);
    options.cy.on("select", "node", this.cySelectListener);
    options.cy.on("unselect", "node", this.cyUnselectListener);
    options.cy.on("grab", "node", this.cyGrabListener);
    options.cy.on("dragfree", "node", this.cyDragFreeListener);
    this.patchOverview();
    this.publishEvidence();
  }

  getState(): PermissionsGraphVirtualInteractionState {
    return this.state;
  }

  getOverviewBuffers(): PermissionsGraphOverviewBuffers {
    return this.overviewBuffers;
  }

  clearTransientState(): void {
    if (this.destroyed) return;
    this.state = clearPermissionsGraphVirtualTransientState(this.state);
    this.clearHoverTimer();
    this.patchOverview();
    this.options.onStatus("Transient virtual hover and keyboard target cleared.");
  }

  getEvidence(): PermissionsGraphQaVirtualInteractionEvidence {
    const camera = this.camera();
    return Object.freeze({
      marker: PERMISSIONS_GRAPH_VIRTUAL_INTERACTION_PHASE_D_MARKER,
      virtualInteractionEnabled: true,
      pointerConversionStatus: this.counters.pointerConversionStatus,
      topologyFingerprint: this.options.model.topologyFingerprint,
      layoutGeneration: this.options.layout.layoutGeneration,
      coordinateRevision: this.options.layout.coordinateRevision,
      spatialIndexRevision: `${this.options.spatial.layoutGeneration}:${this.options.spatial.coordinateRevision}`,
      cameraRevision: camera.revision,
      activeMaterializationRevision: this.materializationRevision,
      currentHoverNodeId: this.state.hoveredNodeId,
      currentSelectedNodeId: this.state.selectedNodeId,
      currentKeyboardTargetNodeId: this.state.keyboardTargetNodeId,
      hitCount: this.counters.hitCount,
      missCount: this.counters.missCount,
      staleQueryRejectionCount: this.counters.staleQueryRejectionCount,
      hoverMaterializationCount: this.counters.hoverMaterializationCount,
      clickMaterializationCount: this.counters.clickMaterializationCount,
      keyboardMaterializationCount: this.counters.keyboardMaterializationCount,
      materializationNodeCount: this.currentSlice.materializedNodeIds.length,
      materializationEdgeCount: this.currentSlice.materializedEdgeIds.length,
      evictedNodeCount: this.counters.evictedNodeCount,
      evictedEdgeCount: this.counters.evictedEdgeCount,
      noJumpMaximumObservedDelta: this.counters.noJumpMaximumObservedDelta,
      dragCommitCount: this.counters.dragCommitCount,
      dragRejectedCount: this.counters.dragRejectedCount,
      lastSpatialUpdateMode: this.counters.lastSpatialUpdateMode,
      selectionSynchronizationStatus: this.destroyed
        ? "destroyed"
        : this.syncingSelection ? "updating" : "ready",
      explainLookupStatus: this.counters.explainLookupStatus,
      diagnostics: Object.freeze(Array.from(this.diagnostics).sort(compareStrings)),
      teardownStatus: this.destroyed ? "destroyed" : "active",
    });
  }

  destroy(): void {
    if (this.destroyed) return;
    this.dismissStageHoverAndFocus();
    this.destroyed = true;
    this.clearHoverTimer();
    if (this.queuedFrame !== null) this.cancelFrame(this.queuedFrame);
    this.queuedFrame = null;
    this.pendingActivation = null;
    this.pointerDownToken = null;
    this.draggingNodeId = null;
    this.syncingSelection = false;
    this.options.stage.removeEventListener("pointerleave", this.pointerLeaveListener);
    this.options.stage.removeEventListener("keydown", this.keydownListener);
    this.options.cy.off("mousemove", this.cyMouseMoveListener);
    this.options.cy.off("mousedown", this.cyMouseDownListener);
    this.options.cy.off("tap", this.cyTapListener);
    this.options.cy.off("select", "node", this.cySelectListener);
    this.options.cy.off("unselect", "node", this.cyUnselectListener);
    this.options.cy.off("grab", "node", this.cyGrabListener);
    this.options.cy.off("dragfree", "node", this.cyDragFreeListener);
    this.options.stage.tabIndex = -1;
    this.options.stage.removeAttribute("role");
    this.options.stage.removeAttribute("aria-label");
    this.options.stage.removeAttribute("data-phase-d-marker");
    this.publishEvidence();
  }

  private dismissStageHoverAndFocus(): void {
    const stage = this.options.stage;
    const activeWindow = stage.ownerDocument.defaultView;
    const eventTypes = [
      ["pointerleave", false],
      ["pointerout", true],
      ["mouseleave", false],
      ["mouseout", true],
    ] as const;
    for (const [type, bubbles] of eventTypes) {
      const event = activeWindow?.MouseEvent
        ? new activeWindow.MouseEvent(type, {
          bubbles,
          relatedTarget: stage.ownerDocument.body,
        })
        : new Event(type, { bubbles });
      stage.dispatchEvent(event);
    }
    stage.blur();
  }

  private onCyMouseMove(event: cytoscape.EventObject): void {
    if (this.destroyed || event.target !== this.options.cy) {
      this.clearHover();
      return;
    }
    const original = event.originalEvent as PointerEvent | MouseEvent | undefined;
    if (!original || !Number.isFinite(original.clientX) || !Number.isFinite(original.clientY)) return;
    const pointerType = "pointerType" in original ? original.pointerType : "mouse";
    this.onBackgroundPointerMove(original.clientX, original.clientY, pointerKind(pointerType));
  }

  private onBackgroundPointerMove(
    clientX: number,
    clientY: number,
    pointerType: PermissionsGraphPointerKind,
  ): void {
    if (this.destroyed) return;
    const hit = this.hitFromClient(clientX, clientY, pointerType);
    if (!hit) {
      this.clearHover();
      return;
    }
    const rendered = clientToPermissionsGraphStageRenderedPoint(
      { x: clientX, y: clientY },
      numericBounds(this.options.stage.getBoundingClientRect()),
    ).renderedPoint;
    if (
      hit === this.state.hoveredNodeId && rendered && this.hoverAnchor &&
      Math.hypot(rendered.x - this.hoverAnchor.x, rendered.y - this.hoverAnchor.y) <=
        DEFAULT_PERMISSIONS_GRAPH_VIRTUAL_HYSTERESIS_RADIUS
    ) return;

    this.clearHoverTimer();
    this.hoverAnchor = rendered;
    this.state = updatePermissionsGraphVirtualInteractionState(this.state, { hoveredNodeId: hit });
    this.patchOverview();
    const delay = Number.isFinite(this.options.hoverDelayMs)
      ? Math.max(0, this.options.hoverDelayMs ?? DEFAULT_PERMISSIONS_GRAPH_VIRTUAL_HOVER_DELAY_MS)
      : DEFAULT_PERMISSIONS_GRAPH_VIRTUAL_HOVER_DELAY_MS;
    this.hoverTimer = setTimeout(() => {
      this.hoverTimer = null;
      if (this.destroyed || this.state.hoveredNodeId !== hit) return;
      this.queueActivation(hit, "hover", this.identity());
    }, delay);
  }

  private onCyMouseDown(event: cytoscape.EventObject): void {
    if (this.destroyed || event.target !== this.options.cy) {
      this.pointerDownToken = null;
      return;
    }
    const hit = this.hitFromCyEvent(event);
    this.pointerDownToken = hit?.token ?? null;
  }

  private onCyTap(event: cytoscape.EventObject): void {
    if (this.destroyed || event.target !== this.options.cy) return;
    this.clearHoverTimer();
    const currentIdentity = this.identity();
    if (this.pointerDownToken) {
      const stale = validatePermissionsGraphVirtualActivationToken({
        token: this.pointerDownToken,
        currentIdentity,
      });
      if (stale) {
        this.rejectStale(stale.code);
        this.pointerDownToken = null;
        return;
      }
      const nodeId = this.pointerDownToken.nodeId;
      this.pointerDownToken = null;
      this.queueActivation(nodeId, "click", currentIdentity);
      return;
    }
    const hit = this.hitFromCyEvent(event);
    if (hit?.nodeId) this.queueActivation(hit.nodeId, "click", hit.identity);
    else this.emptyBackgroundPolicy();
  }

  private onCySelection(event: cytoscape.EventObject, selected: boolean): void {
    if (this.destroyed || this.syncingSelection || event.target === this.options.cy) return;
    const node = event.target as cytoscape.NodeSingular;
    const nodeId = node.id();
    if (selected) {
      this.state = updatePermissionsGraphVirtualInteractionState(this.state, {
        selectedNodeId: nodeId,
        keyboardTargetNodeId: nodeId,
        selectionSource: "cytoscape",
      });
      this.updateExplain(nodeId, "cytoscape");
    } else if (this.state.selectedNodeId === nodeId && this.options.cy.nodes(":selected").length === 0) {
      this.state = updatePermissionsGraphVirtualInteractionState(this.state, {
        selectedNodeId: null,
        selectionSource: "none",
      });
      this.updateExplain(null, "none");
    }
    this.patchOverview();
  }

  private onCyGrab(event: cytoscape.EventObject): void {
    if (this.destroyed || event.target === this.options.cy) return;
    const node = event.target as cytoscape.NodeSingular;
    if (!this.options.index.getNode(node.id())) return;
    this.draggingNodeId = node.id();
    this.patchOverview();
    this.options.onStatus("Synthetic graph drag active; overview duplicate suppressed.");
  }

  private onCyDragFree(event: cytoscape.EventObject): void {
    if (this.destroyed || event.target === this.options.cy) return;
    const node = event.target as cytoscape.NodeSingular;
    const nodeId = node.id();
    if (this.draggingNodeId !== nodeId) return;
    this.draggingNodeId = null;
    const position = node.position();
    const ordinal = this.options.index.getNodeOrdinal(nodeId);
    if (ordinal === undefined || !Number.isFinite(position.x) || !Number.isFinite(position.y)) {
      this.counters.dragRejectedCount += 1;
      this.diagnostics.add("DRAG_COORDINATE_REJECTED");
      const committed = this.options.layout.getPosition(nodeId);
      if (committed) node.position(committed);
      this.patchOverview();
      this.options.onStatus("Synthetic graph drag rejected: coordinate was invalid.");
      return;
    }

    const previousCoordinateRevision = this.options.layout.coordinateRevision;
    if (!this.options.layout.setManualPosition(nodeId, position.x, position.y)) {
      this.patchOverview();
      this.options.onStatus("Synthetic graph drag ended without a coordinate change.");
      return;
    }

    let spatialUpdate: PermissionsGraphSpatialMovedNodeUpdateResult;
    let coordinateRangeCount = 0;
    try {
      const patched = patchPermissionsGraphOverviewCoordinates({
        buffers: this.overviewBuffers,
        layout: this.options.layout,
        previousCoordinateRevision,
        movedOrdinals: [ordinal],
      });
      this.overviewBuffers = patched.buffers;
      coordinateRangeCount = patched.buffers.update.ranges.length;
      spatialUpdate = this.options.spatial.updateMovedNodes({
        topologyFingerprint: this.options.model.topologyFingerprint,
        layoutGeneration: this.options.layout.layoutGeneration,
        previousCoordinateRevision,
        movedOrdinals: [ordinal],
      });
    } catch {
      this.diagnostics.add("DRAG_INCREMENTAL_FALLBACK");
      this.options.spatial.rebuild();
      this.overviewBuffers = buildPermissionsGraphOverviewBuffers({
        model: this.options.model,
        index: this.options.index,
        layout: this.options.layout,
        state: {
          revision: this.dynamicRevision,
          selectedNodeIds: this.state.selectedNodeId ? [this.state.selectedNodeId] : [],
          focusedNodeIds: this.state.keyboardTargetNodeId ? [this.state.keyboardTargetNodeId] : [],
          hoveredNodeIds: this.state.hoveredNodeId ? [this.state.hoveredNodeId] : [],
          materializedNodeIds: this.state.materializedNodeIds,
        },
      });
      spatialUpdate = Object.freeze({
        mode: "full-rebuild" as const,
        reason: "revision-mismatch" as const,
        movedNodeCount: 1,
        touchedCellKeys: Object.freeze([] as string[]),
        previousCoordinateRevision,
        coordinateRevision: this.options.layout.coordinateRevision,
      });
    }

    const next = buildPermissionsGraphActiveSlice({
      model: this.options.model,
      index: this.options.index,
      layout: this.options.layout,
      source: {
        kind: "model-slice",
        nodeIds: this.currentSlice.materializedNodeIds,
        edgeIds: this.currentSlice.materializedEdgeIds,
        budget: this.options.budget,
      },
      selection: { nodeIds: this.state.selectedNodeId ? [this.state.selectedNodeId] : [] },
    });
    this.options.renderer.render(next, { preserveSelection: true, preserveViewport: true });
    this.currentSlice = next;
    this.counters.dragCommitCount += 1;
    this.counters.lastSpatialUpdateMode = spatialUpdate.mode;
    this.patchOverview();
    this.options.onCoordinatesCommitted?.(Object.freeze({
      movedNodeCount: 1,
      coordinateRangeCount,
      previousCoordinateRevision,
      coordinateRevision: this.options.layout.coordinateRevision,
      spatialUpdateMode: spatialUpdate.mode,
    }));
    this.options.onStatus("Synthetic graph manual position committed to overview, detail, edges, and spatial state.");
  }

  private onKeyDown(event: KeyboardEvent): void {
    if (this.destroyed) return;
    if (event.key === "Escape") {
      event.preventDefault();
      event.stopPropagation();
      this.clearTransientState();
      return;
    }
    if (["ArrowRight", "ArrowDown", "ArrowLeft", "ArrowUp"].includes(event.key)) {
      event.preventDefault();
      const direction = event.key === "ArrowRight" || event.key === "ArrowDown" ? "next" : "previous";
      const target = navigatePermissionsGraphVirtualOrdinal({
        model: this.options.model,
        index: this.options.index,
        currentNodeId: this.state.keyboardTargetNodeId ?? this.state.selectedNodeId,
        direction,
      });
      this.state = updatePermissionsGraphVirtualInteractionState(this.state, {
        keyboardTargetNodeId: target,
      });
      this.patchOverview();
      this.options.onStatus(target ? `Keyboard target: ${target}` : "No keyboard target available.");
      return;
    }
    if (event.key !== "Enter" && event.key !== " ") return;
    event.preventDefault();
    const target = this.state.keyboardTargetNodeId ?? this.state.selectedNodeId ??
      this.currentSlice.materializedNodeIds[0] ?? this.options.model.nodes[0]?.id ?? null;
    if (target) this.queueActivation(target, "keyboard", this.identity());
  }

  private queueActivation(
    nodeId: string,
    source: PendingActivation["source"],
    identity: PermissionsGraphInteractionIdentity,
  ): void {
    if (this.destroyed) return;
    this.pendingActivation = Object.freeze({ nodeId, source, identity });
    if (this.queuedFrame !== null) return;
    this.queuedFrame = this.requestFrame(() => {
      this.queuedFrame = null;
      const pending = this.pendingActivation;
      this.pendingActivation = null;
      if (pending && !this.destroyed) this.applyActivation(pending);
    });
  }

  private applyActivation(pending: PendingActivation): void {
    const stale = validatePermissionsGraphVirtualActivationToken({
      token: { nodeId: pending.nodeId, worldPoint: { x: 0, y: 0 }, identity: pending.identity },
      currentIdentity: this.identity(),
    });
    if (stale) {
      this.rejectStale(stale.code);
      return;
    }
    if (!this.options.index.getNode(pending.nodeId)) {
      this.diagnostics.add("UNKNOWN_NODE");
      this.publishEvidence();
      return;
    }
    const previous = this.currentSlice;
    const activationSelects = pending.source !== "hover";
    const selectedNodeId = activationSelects ? pending.nodeId : this.state.selectedNodeId;
    const plan = planPermissionsGraphVirtualPriorityMaterialization({
      model: this.options.model,
      index: this.options.index,
      layout: this.options.layout,
      request: {
        selectedNodeId,
        keyboardTargetNodeId: this.state.keyboardTargetNodeId,
        hoveredNodeId: this.state.hoveredNodeId,
        pinnedNodeIds: [
          ...this.options.layout.getManualPositions().map((entry) => entry.nodeId),
          ...(this.draggingNodeId ? [this.draggingNodeId] : []),
        ],
        previous: {
          nodeIds: previous.materializedNodeIds,
          edgeIds: previous.materializedEdgeIds,
        },
        maxNeighbors: 12,
        budget: this.options.budget,
      },
    });
    if (!plan.selectedNodeIncluded || !plan.includedNodeIds.includes(pending.nodeId)) {
      this.diagnostics.add("NODE_BUDGET_ZERO");
      this.publishEvidence();
      return;
    }
    const next = buildPermissionsGraphActiveSlice({
      model: this.options.model,
      index: this.options.index,
      layout: this.options.layout,
      source: plan.source,
      selection: { nodeIds: selectedNodeId ? [selectedNodeId] : [] },
    });
    const node = next.nodes.find((entry) => entry.data.id === pending.nodeId);
    if (!node) return;
    const cameraBefore = this.camera();
    const noJump = validatePermissionsGraphNoJumpHandoff({
      nodeId: pending.nodeId,
      index: this.options.index,
      layout: this.options.layout,
      overviewBuffers: this.overviewBuffers,
      camera: cameraBefore,
      presetPosition: node.position,
    });
    this.counters.noJumpMaximumObservedDelta = Math.max(
      this.counters.noJumpMaximumObservedDelta,
      Number.isFinite(noJump.maximumDelta) ? noJump.maximumDelta : 0,
    );
    if (!noJump.ok) {
      this.diagnostics.add(noJump.diagnostic?.code ?? "NO_JUMP_MISMATCH");
      this.publishEvidence();
      return;
    }

    this.syncingSelection = true;
    const renderResult = this.options.renderer.render(next, {
      preserveSelection: !activationSelects,
      preserveViewport: true,
    });
    const cameraAfter = this.camera(cameraBefore.revision);
    const materialized = this.options.cy.getElementById(pending.nodeId);
    const position = materialized.position();
    const cameraStable = cameraBefore.zoom === cameraAfter.zoom &&
      cameraBefore.panX === cameraAfter.panX && cameraBefore.panY === cameraAfter.panY;
    const positionStable = Math.hypot(position.x - node.position.x, position.y - node.position.y) <= 0.01;
    if (!cameraStable || !positionStable) {
      this.diagnostics.add("NO_JUMP_POST_APPLY_MISMATCH");
    }
    if (activationSelects) materialized.select();
    this.syncingSelection = false;

    this.currentSlice = next;
    this.materializationRevision = incrementRevision(this.materializationRevision);
    this.counters.evictedNodeCount += renderResult.diff.removeNodes.length;
    this.counters.evictedEdgeCount += renderResult.diff.removeEdges.length;
    if (pending.source === "keyboard") this.counters.keyboardMaterializationCount += 1;
    else if (pending.source === "hover") this.counters.hoverMaterializationCount += 1;
    else this.counters.clickMaterializationCount += 1;
    this.state = updatePermissionsGraphVirtualInteractionState(this.state, {
      selectedNodeId,
      keyboardTargetNodeId: pending.source === "keyboard"
        ? pending.nodeId
        : this.state.keyboardTargetNodeId,
      materializedNodeIds: next.materializedNodeIds,
      selectionSource: activationSelects
        ? pending.source === "keyboard" ? "keyboard" : "pointer"
        : this.state.selectionSource,
    });
    this.patchOverview();
    if (activationSelects) {
      this.updateExplain(pending.nodeId, this.state.selectionSource);
      this.options.onStatus(`Synthetic virtual node selected: ${pending.nodeId}`);
    } else {
      this.options.onStatus(`Synthetic virtual node materialized on hover: ${pending.nodeId}`);
    }
  }

  private hitFromClient(clientX: number, clientY: number, kind: PermissionsGraphPointerKind): string | null {
    this.ensureSpatialCurrent();
    const conversion = clientToPermissionsGraphStageRenderedPoint(
      { x: clientX, y: clientY },
      numericBounds(this.options.stage.getBoundingClientRect()),
    );
    if (!conversion.ok || !conversion.renderedPoint) {
      this.counters.pointerConversionStatus = "failed";
      this.counters.missCount += 1;
      this.publishEvidence();
      return null;
    }
    this.counters.pointerConversionStatus = "ready";
    const result = hitTestPermissionsGraphVirtualNode({
      model: this.options.model,
      index: this.options.index,
      layout: this.options.layout,
      spatial: this.options.spatial,
      overviewBuffers: this.overviewBuffers,
      camera: this.camera(),
      activeMaterializationRevision: this.materializationRevision,
      renderedPoint: conversion.renderedPoint,
      options: { pointerKind: kind, includePointSize: true },
    });
    if (!result.ok) {
      if (result.diagnostic?.code.startsWith("STALE_")) this.rejectStale(result.diagnostic.code);
      else this.counters.missCount += 1;
      this.publishEvidence();
      return null;
    }
    if (!result.hit) {
      this.counters.missCount += 1;
      this.publishEvidence();
      return null;
    }
    this.counters.hitCount += 1;
    this.publishEvidence();
    return result.hit.nodeId;
  }

  private hitFromCyEvent(event: cytoscape.EventObject): {
    readonly nodeId: string;
    readonly token: PermissionsGraphVirtualActivationToken | null;
    readonly identity: PermissionsGraphInteractionIdentity;
  } | null {
    this.ensureSpatialCurrent();
    const rendered = event.renderedPosition;
    if (!rendered) return null;
    const result = hitTestPermissionsGraphVirtualNode({
      model: this.options.model,
      index: this.options.index,
      layout: this.options.layout,
      spatial: this.options.spatial,
      overviewBuffers: this.overviewBuffers,
      camera: this.camera(),
      activeMaterializationRevision: this.materializationRevision,
      renderedPoint: rendered,
    });
    if (!result.ok || !result.hit) {
      this.counters.missCount += 1;
      if (result.diagnostic?.code.startsWith("STALE_")) this.rejectStale(result.diagnostic.code);
      this.publishEvidence();
      return null;
    }
    this.counters.hitCount += 1;
    this.publishEvidence();
    return Object.freeze({
      nodeId: result.hit.nodeId,
      token: createPermissionsGraphVirtualActivationToken(result),
      identity: result.identity,
    });
  }

  private emptyBackgroundPolicy(): void {
    this.clearHover();
    this.state = updatePermissionsGraphVirtualInteractionState(this.state, {
      selectedNodeId: null,
      selectionSource: "none",
    });
    this.syncingSelection = true;
    this.options.cy.elements().unselect();
    this.syncingSelection = false;
    this.patchOverview();
    this.updateExplain(null, "none");
    this.options.onStatus("Empty background selected; active detail slice retained.");
  }

  private clearHover(): void {
    this.clearHoverTimer();
    this.hoverAnchor = null;
    if (this.state.hoveredNodeId === null) return;
    this.state = updatePermissionsGraphVirtualInteractionState(this.state, { hoveredNodeId: null });
    this.patchOverview();
  }

  private clearHoverTimer(): void {
    if (this.hoverTimer !== null) clearTimeout(this.hoverTimer);
    this.hoverTimer = null;
  }

  private patchOverview(): void {
    this.dynamicRevision = incrementRevision(this.dynamicRevision);
    const patched = patchPermissionsGraphOverviewDynamicFlags({
      buffers: this.overviewBuffers,
      index: this.options.index,
      revision: this.dynamicRevision,
      state: {
        selectedNodeId: this.state.selectedNodeId,
        keyboardTargetNodeId: this.state.keyboardTargetNodeId,
        hoveredNodeId: this.state.hoveredNodeId,
        materializedNodeIds: this.state.materializedNodeIds,
        suppressedNodeIds: this.draggingNodeId ? [this.draggingNodeId] : [],
      },
    });
    if (patched.unknownNodeIds.length > 0) this.diagnostics.add("UNKNOWN_DYNAMIC_STATE_ID");
    this.overviewBuffers = patched.buffers;
    if (patched.changed) this.options.onOverviewBuffersChanged(this.overviewBuffers);
    this.publishEvidence();
  }

  private updateExplain(nodeId: string | null, source: PermissionsGraphVirtualSelectionSource): void {
    if (!nodeId) {
      this.counters.explainLookupStatus = "idle";
      this.options.onSelectedSummary(emptySummary());
      this.publishEvidence();
      return;
    }
    const result = lookupPermissionsGraphExplainMetadata(
      this.options.model,
      this.options.index,
      nodeId,
      { materializedNodeIds: this.currentSlice.materializedNodeIds },
    );
    if (!result.found || result.entityType !== "node") {
      this.counters.explainLookupStatus = "unavailable";
      this.options.onSelectedSummary(Object.freeze({
        ...emptySummary(),
        id: nodeId,
        diagnostic: "Synthetic model metadata unavailable.",
      }));
      this.publishEvidence();
      return;
    }
    const safePath = result.path?.startsWith("/synthetic/qa/") ? result.path : null;
    const pathRejected = result.path !== null && safePath === null;
    if (pathRejected) this.diagnostics.add("NON_SYNTHETIC_PATH_REJECTED");
    this.counters.explainLookupStatus = pathRejected ? "unavailable" : "ready";
    const node = this.options.index.getNode(nodeId);
    this.options.onSelectedSummary(Object.freeze({
      available: !pathRejected,
      id: nodeId,
      kind: result.nodeKind,
      label: result.label,
      path: safePath,
      accessLevels: result.accessLevels,
      degree: this.options.index.getDegree(nodeId).total,
      aggregateCount: node?.aggregateCounts?.readableFiles ?? 0,
      materialized: result.materialization === "materialized",
      selectionSource: source,
      diagnostic: pathRejected ? "Non-synthetic path rejected." : null,
    }));
    this.publishEvidence();
  }

  private ensureFinalRevisionCompatibility(): void {
    this.ensureSpatialCurrent();
    if (
      this.overviewBuffers.topologyFingerprint !== this.options.model.topologyFingerprint ||
      this.overviewBuffers.layoutGeneration !== this.options.layout.layoutGeneration ||
      this.overviewBuffers.coordinateRevision !== this.options.layout.coordinateRevision
    ) throw new Error("Phase D interaction requires final-revision overview buffers.");
  }

  private ensureSpatialCurrent(): void {
    if (this.options.spatial.isStale) {
      this.options.spatial.rebuildIfNeeded();
      this.diagnostics.add("SPATIAL_INDEX_REBUILT");
    }
  }

  private identity(): PermissionsGraphInteractionIdentity {
    return capturePermissionsGraphInteractionIdentity({
      model: this.options.model,
      layout: this.options.layout,
      spatial: this.options.spatial,
      overviewBuffers: this.overviewBuffers,
      camera: this.camera(),
      activeMaterializationRevision: this.materializationRevision,
    });
  }

  private camera(revision = this.options.cy.scratch("phaseDCameraRevision") ?? 0) {
    if (this.options.getCamera) return this.options.getCamera();
    const pan = this.options.cy.pan();
    const camera = createPermissionsGraphCameraState({
      panX: pan.x,
      panY: pan.y,
      zoom: this.options.cy.zoom(),
      revision: Number.isInteger(revision) ? revision : 0,
    });
    this.options.cy.scratch("phaseDCameraRevision", camera.revision);
    return camera;
  }

  private rejectStale(code: string): void {
    this.counters.staleQueryRejectionCount += 1;
    this.diagnostics.add(code);
    this.clearHoverTimer();
    this.options.onStatus("Stale virtual interaction rejected safely; move or activate again.");
  }

  private publishEvidence(): void {
    this.options.onEvidence(this.getEvidence());
  }
}

function numericBounds(rect: DOMRect): { left: number; top: number; width: number; height: number } {
  return { left: rect.left, top: rect.top, width: rect.width, height: rect.height };
}

function pointerKind(value: string): PermissionsGraphPointerKind {
  return value === "touch" || value === "pen" ? value : "mouse";
}

function emptySummary(): PermissionsGraphQaSelectedNodeSummary {
  return Object.freeze({
    available: false,
    id: null,
    kind: null,
    label: null,
    path: null,
    accessLevels: Object.freeze([] as string[]),
    degree: 0,
    aggregateCount: 0,
    materialized: false,
    selectionSource: "none",
    diagnostic: null,
  });
}

function incrementRevision(value: number): number {
  return value === 0xffff_ffff ? 0 : value + 1;
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
