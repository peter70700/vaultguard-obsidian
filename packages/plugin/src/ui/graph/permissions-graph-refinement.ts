/**
 * QA-only active-slice refinement for the inert virtual permissions graph.
 *
 * This module is renderer-independent except for the pure transition-frame
 * adapter at the bottom. It is not imported by PermissionsGraphView or plugin
 * runtime wiring. The mandatory executor is chunked on the main thread; worker
 * use remains deferred until the repository has an explicit worker bundle.
 */

import { yieldToEventLoop } from "../../plugin/long-operation";
import {
  PermissionsGraphLayoutStateError,
  type PermissionsGraphCancellationSignal,
  type PermissionsGraphCoordinate,
  type PermissionsGraphLayoutStore,
} from "./permissions-graph-layout";
import type { PermissionsGraphMaterializationPlan } from "./permissions-graph-materialization";
import type {
  PermissionsGraphEdgeRecord,
  PermissionsGraphIndex,
  PermissionsGraphModel,
} from "./permissions-graph-model";
import type {
  PermissionsGraphActiveNodeElement,
  PermissionsGraphActiveSlice,
} from "./permissions-graph-renderer";

export const MAX_PERMISSIONS_GRAPH_REFINEMENT_EDGES = 350;

const DEFAULT_ITERATIONS = 24;
const MAX_ITERATIONS = 200;
const DEFAULT_EDGE_LENGTH = 120;
const DEFAULT_EDGE_ATTRACTION = 0.035;
const DEFAULT_SEPARATION_RADIUS = 72;
const DEFAULT_SEPARATION_STRENGTH = 0.12;
const DEFAULT_DAMPING = 0.72;
const DEFAULT_MAX_MOVEMENT_PER_TICK = 18;
const DEFAULT_BOUNDS_PADDING = 240;
const DEFAULT_PRIORITY_MULTIPLIER = 1.35;
const DEFAULT_PROGRESS_INTERVAL = 1;
const DEFAULT_YIELD_INTERVAL = 4;
const DEFAULT_MAX_SEPARATION_NEIGHBORS = 32;
const DEFAULT_CONVERGENCE_THRESHOLD = 0.001;

export type PermissionsGraphRefinementDiagnosticCode =
  | "INDEX_MODEL_MISMATCH"
  | "LAYOUT_MODEL_MISMATCH"
  | "PLAN_TOPOLOGY_MISMATCH"
  | "UNKNOWN_ACTIVE_NODE"
  | "UNKNOWN_ACTIVE_EDGE"
  | "DANGLING_ACTIVE_EDGE"
  | "EDGE_CAP_EXCEEDED"
  | "NON_FINITE_INITIAL_COORDINATE"
  | "IGNORED_PRIORITY_NODE"
  | "IGNORED_PINNED_NODE"
  | "WORKER_DEFERRED"
  | "CANCELLED"
  | "EXECUTION_FAILED"
  | "UNKNOWN_TRANSITION_NODE"
  | "MISSING_PREVIOUS_COORDINATE"
  | "NON_FINITE_TRANSITION_COORDINATE";

export interface PermissionsGraphRefinementDiagnostic {
  readonly code: PermissionsGraphRefinementDiagnosticCode;
  readonly message: string;
  readonly id?: string;
}

export interface PermissionsGraphRefinementOptions {
  readonly iterations?: number;
  readonly edgeLength?: number;
  readonly edgeAttraction?: number;
  readonly separationRadius?: number;
  readonly separationStrength?: number;
  readonly damping?: number;
  readonly maxMovementPerTick?: number;
  readonly boundsPadding?: number;
  readonly priorityMultiplier?: number;
  readonly progressInterval?: number;
  readonly yieldInterval?: number;
  readonly maxSeparationNeighbors?: number;
  readonly convergenceThreshold?: number;
  readonly yieldFn?: () => Promise<void>;
  /** Records a safe fallback decision; no worker is constructed in this phase. */
  readonly preferWorker?: boolean;
}

interface NormalizedRefinementOptions {
  readonly iterations: number;
  readonly edgeLength: number;
  readonly edgeAttraction: number;
  readonly separationRadius: number;
  readonly separationStrength: number;
  readonly damping: number;
  readonly maxMovementPerTick: number;
  readonly boundsPadding: number;
  readonly priorityMultiplier: number;
  readonly progressInterval: number;
  readonly yieldInterval: number;
  readonly maxSeparationNeighbors: number;
  readonly convergenceThreshold: number;
  readonly yieldFn: () => Promise<void>;
  readonly preferWorker: boolean;
}

export interface PermissionsGraphRefinementProgress {
  readonly phase: "refining" | "completed" | "cancelled" | "rejected" | "failed";
  readonly completedIterations: number;
  readonly totalIterations: number;
  readonly nodeCount: number;
  readonly edgeCount: number;
}

export interface PermissionsGraphRefinementInput {
  readonly model: PermissionsGraphModel;
  readonly index: PermissionsGraphIndex;
  readonly layout: PermissionsGraphLayoutStore;
  readonly materializationPlan?: PermissionsGraphMaterializationPlan;
  /** Explicit IDs take precedence over the materialization plan when supplied. */
  readonly includedNodeIds?: readonly string[];
  readonly includedEdgeIds?: readonly string[];
  readonly selectedNodeIds?: readonly string[];
  readonly focusedNodeIds?: readonly string[];
  readonly pinnedNodeIds?: readonly string[];
  readonly options?: PermissionsGraphRefinementOptions;
  readonly signal?: PermissionsGraphCancellationSignal;
  readonly onProgress?: (progress: PermissionsGraphRefinementProgress) => void;
}

export type PermissionsGraphRefinementPlanStatus = "ready" | "skipped" | "rejected";

export interface PermissionsGraphRefinementPlan {
  readonly status: PermissionsGraphRefinementPlanStatus;
  readonly reason: string | null;
  readonly sourceTopologyFingerprint: string;
  readonly sourceLayoutGeneration: number;
  readonly sourceCoordinateRevision: number;
  readonly nodeIds: readonly string[];
  readonly edgeIds: readonly string[];
  readonly pinnedNodeIds: readonly string[];
  readonly priorityNodeIds: readonly string[];
  readonly diagnostics: readonly PermissionsGraphRefinementDiagnostic[];
  readonly options: NormalizedRefinementOptions;
}

export type PermissionsGraphRefinementStatus =
  | "completed"
  | "skipped"
  | "cancelled"
  | "rejected"
  | "failed";

export interface PermissionsGraphRefinedCoordinate extends PermissionsGraphCoordinate {
  readonly nodeId: string;
  readonly pinned: boolean;
  readonly priority: boolean;
  readonly moved: boolean;
}

export interface PermissionsGraphRefinementExecution {
  readonly mode: "chunked-main-thread";
  readonly workerRequested: boolean;
  readonly workerUsed: false;
  readonly fallbackUsed: true;
  readonly workerReason: "not-requested" | "worker-bundle-unavailable";
}

export interface PermissionsGraphRefinementResult {
  readonly status: PermissionsGraphRefinementStatus;
  readonly reason: string | null;
  readonly sourceTopologyFingerprint: string;
  readonly sourceLayoutGeneration: number;
  readonly sourceCoordinateRevision: number;
  readonly nodeCount: number;
  readonly edgeCount: number;
  readonly iterationsCompleted: number;
  readonly totalIterations: number;
  readonly pinnedNodeIds: readonly string[];
  readonly priorityNodeIds: readonly string[];
  readonly coordinates: readonly PermissionsGraphRefinedCoordinate[];
  readonly diagnostics: readonly PermissionsGraphRefinementDiagnostic[];
  readonly progressEvents: readonly PermissionsGraphRefinementProgress[];
  readonly execution: PermissionsGraphRefinementExecution;
}

export type PermissionsGraphRefinementWriteBackStatus = "committed" | "skipped" | "rejected";

export interface PermissionsGraphRefinementWriteBackResult {
  readonly status: PermissionsGraphRefinementWriteBackStatus;
  readonly reason: string | null;
  readonly changedNodeIds: readonly string[];
  readonly skippedManualNodeIds: readonly string[];
  readonly coordinateRevisionBefore: number;
  readonly coordinateRevisionAfter: number;
  readonly layoutGenerationBefore: number;
  readonly layoutGenerationAfter: number;
}

export interface PermissionsGraphTransitionCoordinate extends PermissionsGraphCoordinate {
  readonly nodeId: string;
}

export interface PermissionsGraphCoordinateTransitionOptions {
  readonly durationMs?: number;
  readonly steps?: number;
  readonly frameDurationMs?: number;
  readonly maxMovementPerStep?: number;
}

export interface PermissionsGraphCoordinateDelta {
  readonly nodeId: string;
  readonly from: PermissionsGraphCoordinate;
  readonly to: PermissionsGraphCoordinate;
  readonly dx: number;
  readonly dy: number;
  readonly distance: number;
  readonly pinned: boolean;
}

export interface PermissionsGraphCoordinateTransitionFrame {
  readonly step: number;
  readonly progress: number;
  readonly coordinates: readonly PermissionsGraphTransitionCoordinate[];
}

export interface PermissionsGraphCoordinateTransition {
  readonly immediate: boolean;
  readonly stepCount: number;
  readonly deltas: readonly PermissionsGraphCoordinateDelta[];
  readonly frames: readonly PermissionsGraphCoordinateTransitionFrame[];
  readonly diagnostics: readonly PermissionsGraphRefinementDiagnostic[];
}

export interface PermissionsGraphCoordinateTransitionInput {
  readonly previous: readonly PermissionsGraphTransitionCoordinate[];
  readonly next: readonly PermissionsGraphTransitionCoordinate[];
  readonly knownNodeIds?: readonly string[];
  readonly pinnedNodeIds?: readonly string[];
  readonly options?: PermissionsGraphCoordinateTransitionOptions;
}

class PermissionsGraphRefinementCancelledError extends Error {
  constructor() {
    super("Permissions graph refinement was cancelled.");
    this.name = "AbortError";
  }
}

/** Validate and normalize one explicit active-slice refinement request. */
export function planPermissionsGraphActiveSliceRefinement(
  input: PermissionsGraphRefinementInput,
): PermissionsGraphRefinementPlan {
  const diagnostics: PermissionsGraphRefinementDiagnostic[] = [];
  const options = normalizeRefinementOptions(input.options);
  if (!indexMatchesModel(input.model, input.index)) {
    diagnostics.push(diagnostic(
      "INDEX_MODEL_MISMATCH",
      "The PermissionsGraphIndex does not match the refinement model.",
    ));
    return freezePlan(input, options, [], [], [], [], "rejected", "index-model-mismatch", diagnostics);
  }
  if (
    input.layout.model !== input.model ||
    input.layout.index !== input.index ||
    input.layout.topologyFingerprint !== input.model.topologyFingerprint
  ) {
    diagnostics.push(diagnostic(
      "LAYOUT_MODEL_MISMATCH",
      "The PermissionsGraphLayoutStore does not match the refinement model/index.",
    ));
    return freezePlan(input, options, [], [], [], [], "rejected", "layout-model-mismatch", diagnostics);
  }
  if (
    input.materializationPlan &&
    input.materializationPlan.sourceTopologyFingerprint !== input.model.topologyFingerprint
  ) {
    diagnostics.push(diagnostic(
      "PLAN_TOPOLOGY_MISMATCH",
      "The Phase 5 materialization plan does not match the refinement topology.",
    ));
    return freezePlan(input, options, [], [], [], [], "rejected", "plan-topology-mismatch", diagnostics);
  }

  const nodeIds = uniqueSorted(
    input.includedNodeIds ?? input.materializationPlan?.includedNodeIds ?? [],
  );
  const edgeIds = uniqueSorted(
    input.includedEdgeIds ?? input.materializationPlan?.includedEdgeIds ?? [],
  );
  if (edgeIds.length > MAX_PERMISSIONS_GRAPH_REFINEMENT_EDGES) {
    diagnostics.push(diagnostic(
      "EDGE_CAP_EXCEEDED",
      `Active-slice refinement allows at most ${MAX_PERMISSIONS_GRAPH_REFINEMENT_EDGES} edges; received ${edgeIds.length}.`,
    ));
    return freezePlan(
      input,
      options,
      nodeIds,
      edgeIds,
      [],
      [],
      "rejected",
      "edge-cap-exceeded",
      diagnostics,
    );
  }

  const activeNodeIds = new Set(nodeIds);
  let invalid = false;
  for (const nodeId of nodeIds) {
    const position = input.layout.getPosition(nodeId);
    if (!input.index.getNode(nodeId)) {
      diagnostics.push(diagnostic("UNKNOWN_ACTIVE_NODE", `Unknown active node ${nodeId}.`, nodeId));
      invalid = true;
    } else if (!position || !finiteCoordinate(position)) {
      diagnostics.push(diagnostic(
        "NON_FINITE_INITIAL_COORDINATE",
        `Active node ${nodeId} does not have a finite layout coordinate.`,
        nodeId,
      ));
      invalid = true;
    }
  }
  for (const edgeId of edgeIds) {
    const edge = input.index.getEdge(edgeId);
    if (!edge) {
      diagnostics.push(diagnostic("UNKNOWN_ACTIVE_EDGE", `Unknown active edge ${edgeId}.`, edgeId));
      invalid = true;
      continue;
    }
    if (!activeNodeIds.has(edge.sourceId) || !activeNodeIds.has(edge.targetId)) {
      diagnostics.push(diagnostic(
        "DANGLING_ACTIVE_EDGE",
        `Active edge ${edgeId} has an endpoint outside the active slice.`,
        edgeId,
      ));
      invalid = true;
    }
  }

  const priorityNodeIds = filterActiveIds(
    [...(input.selectedNodeIds ?? []), ...(input.focusedNodeIds ?? [])],
    activeNodeIds,
    diagnostics,
    "IGNORED_PRIORITY_NODE",
  );
  const explicitPinnedNodeIds = filterActiveIds(
    input.pinnedNodeIds ?? [],
    activeNodeIds,
    diagnostics,
    "IGNORED_PINNED_NODE",
  );
  const pinnedNodeIds = uniqueSorted([
    ...explicitPinnedNodeIds,
    ...nodeIds.filter((nodeId) => input.layout.isManuallyPositioned(nodeId)),
  ]);
  if (options.preferWorker) {
    diagnostics.push(diagnostic(
      "WORKER_DEFERRED",
      "Worker refinement is deferred because this repository has no worker bundle; using the chunked main-thread fallback.",
    ));
  }

  if (invalid) {
    return freezePlan(
      input,
      options,
      nodeIds,
      edgeIds,
      pinnedNodeIds,
      priorityNodeIds,
      "rejected",
      "invalid-active-slice",
      diagnostics,
    );
  }
  if (nodeIds.length === 0) {
    return freezePlan(
      input,
      options,
      nodeIds,
      edgeIds,
      pinnedNodeIds,
      priorityNodeIds,
      "skipped",
      "empty-active-slice",
      diagnostics,
    );
  }
  if (nodeIds.length === 1) {
    return freezePlan(
      input,
      options,
      nodeIds,
      edgeIds,
      pinnedNodeIds,
      priorityNodeIds,
      "skipped",
      "single-node-stable",
      diagnostics,
    );
  }
  if (options.iterations === 0) {
    return freezePlan(
      input,
      options,
      nodeIds,
      edgeIds,
      pinnedNodeIds,
      priorityNodeIds,
      "skipped",
      "zero-iterations",
      diagnostics,
    );
  }
  return freezePlan(
    input,
    options,
    nodeIds,
    edgeIds,
    pinnedNodeIds,
    priorityNodeIds,
    "ready",
    null,
    diagnostics,
  );
}

/** Run deterministic bounded relaxation off to the side; never mutates layout. */
export async function refinePermissionsGraphActiveSlice(
  input: PermissionsGraphRefinementInput,
): Promise<PermissionsGraphRefinementResult> {
  const plan = planPermissionsGraphActiveSliceRefinement(input);
  const progressEvents: PermissionsGraphRefinementProgress[] = [];
  const emit = (
    phase: PermissionsGraphRefinementProgress["phase"],
    completedIterations: number,
  ): void => {
    const event = Object.freeze({
      phase,
      completedIterations,
      totalIterations: plan.options.iterations,
      nodeCount: plan.nodeIds.length,
      edgeCount: plan.edgeIds.length,
    });
    progressEvents.push(event);
    input.onProgress?.(event);
  };
  const execution = executionFor(plan.options.preferWorker);
  const initialCoordinates = coordinatesFromLayout(input.layout, plan, null, null);

  try {
    throwIfCancelled(input.signal);
  } catch (error) {
    emit("cancelled", 0);
    return freezeResult(plan, "cancelled", "cancelled-before-start", 0, initialCoordinates, [
      ...plan.diagnostics,
      diagnostic("CANCELLED", cancellationMessage(error)),
    ], progressEvents, execution);
  }

  if (plan.status === "rejected") {
    emit("rejected", 0);
    return freezeResult(
      plan,
      "rejected",
      plan.reason,
      0,
      initialCoordinates,
      plan.diagnostics,
      progressEvents,
      execution,
    );
  }
  if (plan.status === "skipped") {
    return freezeResult(
      plan,
      "skipped",
      plan.reason,
      0,
      initialCoordinates,
      plan.diagnostics,
      progressEvents,
      execution,
    );
  }

  const nodeOrdinal = new Map(plan.nodeIds.map((nodeId, ordinal) => [nodeId, ordinal]));
  const edgePairs = plan.edgeIds.map((edgeId) => {
    const edge = input.index.getEdge(edgeId) as PermissionsGraphEdgeRecord;
    return {
      edge,
      source: nodeOrdinal.get(edge.sourceId) as number,
      target: nodeOrdinal.get(edge.targetId) as number,
    };
  });
  const nodeCount = plan.nodeIds.length;
  const x = new Float64Array(nodeCount);
  const y = new Float64Array(nodeCount);
  const initialX = new Float64Array(nodeCount);
  const initialY = new Float64Array(nodeCount);
  const vx = new Float64Array(nodeCount);
  const vy = new Float64Array(nodeCount);
  const fx = new Float64Array(nodeCount);
  const fy = new Float64Array(nodeCount);
  const pinned = new Set(plan.pinnedNodeIds);
  const priority = new Set(plan.priorityNodeIds);
  for (let ordinal = 0; ordinal < nodeCount; ordinal += 1) {
    const position = input.layout.getPosition(plan.nodeIds[ordinal]) as PermissionsGraphCoordinate;
    x[ordinal] = position.x;
    y[ordinal] = position.y;
    initialX[ordinal] = position.x;
    initialY[ordinal] = position.y;
  }
  const layoutBounds = input.layout.coordinateBounds;
  const bounds = {
    minX: layoutBounds.minX - plan.options.boundsPadding,
    minY: layoutBounds.minY - plan.options.boundsPadding,
    maxX: layoutBounds.maxX + plan.options.boundsPadding,
    maxY: layoutBounds.maxY + plan.options.boundsPadding,
  };

  let iterationsCompleted = 0;
  emit("refining", 0);
  try {
    for (let iteration = 1; iteration <= plan.options.iterations; iteration += 1) {
      throwIfCancelled(input.signal);
      fx.fill(0);
      fy.fill(0);
      applyEdgeAttraction(edgePairs, x, y, fx, fy, plan, priority, input.layout.seed);
      applyBoundedSeparation(x, y, fx, fy, plan, input.layout.seed);

      let totalMovement = 0;
      for (let ordinal = 0; ordinal < nodeCount; ordinal += 1) {
        const nodeId = plan.nodeIds[ordinal];
        if (pinned.has(nodeId)) {
          vx[ordinal] = 0;
          vy[ordinal] = 0;
          continue;
        }
        const priorityScale = priority.has(nodeId) ? plan.options.priorityMultiplier : 1;
        vx[ordinal] = (vx[ordinal] + fx[ordinal] * priorityScale) * plan.options.damping;
        vy[ordinal] = (vy[ordinal] + fy[ordinal] * priorityScale) * plan.options.damping;
        const velocityLength = Math.hypot(vx[ordinal], vy[ordinal]);
        if (velocityLength > plan.options.maxMovementPerTick && velocityLength > 0) {
          const scale = plan.options.maxMovementPerTick / velocityLength;
          vx[ordinal] *= scale;
          vy[ordinal] *= scale;
        }
        const nextX = clamp(x[ordinal] + vx[ordinal], bounds.minX, bounds.maxX);
        const nextY = clamp(y[ordinal] + vy[ordinal], bounds.minY, bounds.maxY);
        if (!Number.isFinite(nextX) || !Number.isFinite(nextY)) {
          throw new Error(`Non-finite refinement coordinate for ${nodeId}.`);
        }
        totalMovement += Math.hypot(nextX - x[ordinal], nextY - y[ordinal]);
        x[ordinal] = nextX;
        y[ordinal] = nextY;
      }

      iterationsCompleted = iteration;
      if (
        iteration % plan.options.progressInterval === 0 ||
        iteration === plan.options.iterations
      ) {
        emit("refining", iteration);
      }
      if (plan.options.yieldInterval > 0 && iteration % plan.options.yieldInterval === 0) {
        await cooperativeRefinementCheckpoint(input.signal, plan.options.yieldFn);
      }
      if (totalMovement <= plan.options.convergenceThreshold) break;
    }
    throwIfCancelled(input.signal);
    emit("completed", iterationsCompleted);
    return freezeResult(
      plan,
      "completed",
      null,
      iterationsCompleted,
      coordinatesFromLayout(input.layout, plan, x, y, initialX, initialY),
      plan.diagnostics,
      progressEvents,
      execution,
    );
  } catch (error) {
    if (isCancellation(error, input.signal)) {
      emit("cancelled", iterationsCompleted);
      return freezeResult(
        plan,
        "cancelled",
        "cancelled-during-refinement",
        iterationsCompleted,
        initialCoordinates,
        [...plan.diagnostics, diagnostic("CANCELLED", cancellationMessage(error))],
        progressEvents,
        execution,
      );
    }
    emit("failed", iterationsCompleted);
    return freezeResult(
      plan,
      "failed",
      "refinement-failed",
      iterationsCompleted,
      initialCoordinates,
      [...plan.diagnostics, diagnostic(
        "EXECUTION_FAILED",
        error instanceof Error ? error.message : String(error),
      )],
      progressEvents,
      execution,
    );
  }
}

/** Commit only a completed, current-generation result to its matching store. */
export function applyPermissionsGraphRefinementToLayoutStore(input: {
  readonly model: PermissionsGraphModel;
  readonly index: PermissionsGraphIndex;
  readonly layout: PermissionsGraphLayoutStore;
  readonly result: PermissionsGraphRefinementResult;
  readonly allowManualOverwrite?: boolean;
}): PermissionsGraphRefinementWriteBackResult {
  const coordinateRevisionBefore = input.layout.coordinateRevision;
  const layoutGenerationBefore = input.layout.layoutGeneration;
  const rejected = (reason: string): PermissionsGraphRefinementWriteBackResult => Object.freeze({
    status: "rejected",
    reason,
    changedNodeIds: Object.freeze([] as string[]),
    skippedManualNodeIds: Object.freeze([] as string[]),
    coordinateRevisionBefore,
    coordinateRevisionAfter: input.layout.coordinateRevision,
    layoutGenerationBefore,
    layoutGenerationAfter: input.layout.layoutGeneration,
  });
  const skipped = (reason: string): PermissionsGraphRefinementWriteBackResult => Object.freeze({
    status: "skipped",
    reason,
    changedNodeIds: Object.freeze([] as string[]),
    skippedManualNodeIds: Object.freeze([] as string[]),
    coordinateRevisionBefore,
    coordinateRevisionAfter: input.layout.coordinateRevision,
    layoutGenerationBefore,
    layoutGenerationAfter: input.layout.layoutGeneration,
  });

  if (input.result.status !== "completed") return skipped("refinement-not-completed");
  if (
    input.layout.model !== input.model ||
    input.layout.index !== input.index ||
    !indexMatchesModel(input.model, input.index)
  ) return rejected("layout-model-mismatch");
  if (
    input.result.sourceTopologyFingerprint !== input.model.topologyFingerprint ||
    input.layout.topologyFingerprint !== input.model.topologyFingerprint
  ) return rejected("topology-mismatch");
  if (
    input.result.sourceLayoutGeneration !== input.layout.layoutGeneration ||
    input.result.sourceCoordinateRevision !== input.layout.coordinateRevision
  ) return rejected("stale-layout-state");

  const seen = new Set<string>();
  for (const coordinate of input.result.coordinates) {
    if (seen.has(coordinate.nodeId)) return rejected("duplicate-coordinate-id");
    seen.add(coordinate.nodeId);
    if (!input.index.getNode(coordinate.nodeId)) return rejected("unknown-node-id");
    if (!finiteCoordinate(coordinate)) return rejected("non-finite-coordinate");
  }

  try {
    const committed = input.layout.commitCoordinateUpdates(
      input.result.coordinates.map((coordinate) => ({
        nodeId: coordinate.nodeId,
        x: coordinate.x,
        y: coordinate.y,
      })),
      {
        topologyFingerprint: input.result.sourceTopologyFingerprint,
        preserveManualPositions: input.allowManualOverwrite !== true,
      },
    );
    return Object.freeze({
      status: committed.changedNodeIds.length > 0 ? "committed" : "skipped",
      reason: committed.changedNodeIds.length > 0 ? null : "no-coordinate-changes",
      changedNodeIds: committed.changedNodeIds,
      skippedManualNodeIds: committed.skippedManualNodeIds,
      coordinateRevisionBefore,
      coordinateRevisionAfter: committed.coordinateRevision,
      layoutGenerationBefore,
      layoutGenerationAfter: committed.layoutGeneration,
    });
  } catch (error) {
    if (error instanceof PermissionsGraphLayoutStateError) {
      if (error.code === "UNKNOWN_NODE_ID") return rejected("unknown-node-id");
      if (error.code === "NON_FINITE_COORDINATE") return rejected("non-finite-coordinate");
      if (error.code === "TOPOLOGY_MISMATCH") return rejected("topology-mismatch");
    }
    return rejected("coordinate-commit-failed");
  }
}

/** Build deterministic previous-to-next coordinate frames. */
export function buildPermissionsGraphCoordinateTransition(
  input: PermissionsGraphCoordinateTransitionInput,
): PermissionsGraphCoordinateTransition {
  const diagnostics: PermissionsGraphRefinementDiagnostic[] = [];
  const known = input.knownNodeIds ? new Set(input.knownNodeIds) : null;
  const pinned = new Set(input.pinnedNodeIds ?? []);
  const previous = new Map<string, PermissionsGraphTransitionCoordinate>();
  for (const coordinate of input.previous) {
    if (!finiteCoordinate(coordinate)) {
      diagnostics.push(diagnostic(
        "NON_FINITE_TRANSITION_COORDINATE",
        `Ignored non-finite previous coordinate for ${coordinate.nodeId}.`,
        coordinate.nodeId,
      ));
      continue;
    }
    previous.set(coordinate.nodeId, coordinate);
  }
  const next = new Map<string, PermissionsGraphTransitionCoordinate>();
  for (const coordinate of input.next) {
    if (known && !known.has(coordinate.nodeId)) {
      diagnostics.push(diagnostic(
        "UNKNOWN_TRANSITION_NODE",
        `Ignored unknown transition node ${coordinate.nodeId}.`,
        coordinate.nodeId,
      ));
      continue;
    }
    if (!finiteCoordinate(coordinate)) {
      diagnostics.push(diagnostic(
        "NON_FINITE_TRANSITION_COORDINATE",
        `Ignored non-finite next coordinate for ${coordinate.nodeId}.`,
        coordinate.nodeId,
      ));
      continue;
    }
    next.set(coordinate.nodeId, coordinate);
  }

  const deltas: PermissionsGraphCoordinateDelta[] = [];
  for (const nodeId of Array.from(next.keys()).sort(compareStrings)) {
    const nextCoordinate = next.get(nodeId) as PermissionsGraphTransitionCoordinate;
    const previousCoordinate = previous.get(nodeId);
    if (!previousCoordinate) {
      diagnostics.push(diagnostic(
        "MISSING_PREVIOUS_COORDINATE",
        `Transition node ${nodeId} has no previous coordinate; it starts at its next coordinate.`,
        nodeId,
      ));
    }
    const from = previousCoordinate ?? nextCoordinate;
    const to = pinned.has(nodeId) ? from : nextCoordinate;
    const dx = to.x - from.x;
    const dy = to.y - from.y;
    deltas.push(Object.freeze({
      nodeId,
      from: Object.freeze({ x: from.x, y: from.y }),
      to: Object.freeze({ x: to.x, y: to.y }),
      dx,
      dy,
      distance: Math.hypot(dx, dy),
      pinned: pinned.has(nodeId),
    }));
  }

  const options = input.options ?? {};
  const immediate = options.durationMs === 0;
  const frameDurationMs = positiveFinite(options.frameDurationMs, 1000 / 60);
  const requestedSteps = immediate
    ? 1
    : options.steps !== undefined
      ? normalizeInteger(options.steps, 1, 1, Number.MAX_SAFE_INTEGER)
      : options.durationMs !== undefined && Number.isFinite(options.durationMs) && options.durationMs > 0
        ? Math.max(1, Math.ceil(options.durationMs / frameDurationMs))
        : 6;
  const maxMovementPerStep = positiveFinite(
    options.maxMovementPerStep,
    Number.POSITIVE_INFINITY,
  );
  const requiredSteps = immediate || maxMovementPerStep === Number.POSITIVE_INFINITY
    ? 1
    : deltas.reduce(
        (maximum, delta) => Math.max(maximum, Math.ceil(delta.distance / maxMovementPerStep)),
        1,
      );
  const stepCount = immediate ? 1 : Math.max(requestedSteps, requiredSteps);
  const frames: PermissionsGraphCoordinateTransitionFrame[] = [];
  for (let step = 1; step <= stepCount; step += 1) {
    const progress = step / stepCount;
    const coordinates = deltas.map((delta) => Object.freeze({
      nodeId: delta.nodeId,
      x: delta.from.x + delta.dx * progress,
      y: delta.from.y + delta.dy * progress,
    }));
    frames.push(Object.freeze({
      step,
      progress,
      coordinates: Object.freeze(coordinates),
    }));
  }

  return Object.freeze({
    immediate,
    stepCount,
    deltas: Object.freeze(deltas),
    frames: Object.freeze(frames),
    diagnostics: freezeDiagnostics(diagnostics),
  });
}

/** Convert one pure transition frame into a valid Phase 4 renderer slice. */
export function applyPermissionsGraphTransitionFrameToActiveSlice(
  slice: PermissionsGraphActiveSlice,
  frame: PermissionsGraphCoordinateTransitionFrame,
): PermissionsGraphActiveSlice {
  const coordinateById = new Map(
    frame.coordinates
      .filter(finiteCoordinate)
      .map((coordinate) => [coordinate.nodeId, coordinate]),
  );
  const nodes = slice.nodes.map((node): PermissionsGraphActiveNodeElement => {
    const coordinate = coordinateById.get(node.data.id);
    if (!coordinate) return node;
    return Object.freeze({
      ...node,
      position: Object.freeze({ x: coordinate.x, y: coordinate.y }),
    });
  });
  return Object.freeze({
    ...slice,
    nodes: Object.freeze(nodes),
    elements: Object.freeze([...nodes, ...slice.edges]),
  });
}

function applyEdgeAttraction(
  edges: ReadonlyArray<{ readonly edge: PermissionsGraphEdgeRecord; readonly source: number; readonly target: number }>,
  x: Float64Array,
  y: Float64Array,
  fx: Float64Array,
  fy: Float64Array,
  plan: PermissionsGraphRefinementPlan,
  priority: ReadonlySet<string>,
  seed: number,
): void {
  for (const { edge, source, target } of edges) {
    let dx = x[target] - x[source];
    let dy = y[target] - y[source];
    let distance = Math.hypot(dx, dy);
    if (distance < 1e-6) {
      const direction = deterministicDirection(`${seed}:${edge.id}`);
      dx = direction.x;
      dy = direction.y;
      distance = 1;
    }
    const priorityScale = priority.has(edge.sourceId) || priority.has(edge.targetId)
      ? plan.options.priorityMultiplier
      : 1;
    const magnitude = (distance - plan.options.edgeLength) *
      plan.options.edgeAttraction * priorityScale;
    const forceX = (dx / distance) * magnitude;
    const forceY = (dy / distance) * magnitude;
    fx[source] += forceX;
    fy[source] += forceY;
    fx[target] -= forceX;
    fy[target] -= forceY;
  }
}

function applyBoundedSeparation(
  x: Float64Array,
  y: Float64Array,
  fx: Float64Array,
  fy: Float64Array,
  plan: PermissionsGraphRefinementPlan,
  seed: number,
): void {
  if (plan.options.separationStrength <= 0 || plan.options.separationRadius <= 0) return;
  const cellSize = plan.options.separationRadius;
  const cells = new Map<string, number[]>();
  for (let ordinal = 0; ordinal < x.length; ordinal += 1) {
    const cellX = Math.floor(x[ordinal] / cellSize);
    const cellY = Math.floor(y[ordinal] / cellSize);
    const key = `${cellX},${cellY}`;
    const values = cells.get(key);
    if (values) values.push(ordinal);
    else cells.set(key, [ordinal]);
  }

  for (let left = 0; left < x.length; left += 1) {
    const cellX = Math.floor(x[left] / cellSize);
    const cellY = Math.floor(y[left] / cellSize);
    let considered = 0;
    outer: for (let offsetY = -1; offsetY <= 1; offsetY += 1) {
      for (let offsetX = -1; offsetX <= 1; offsetX += 1) {
        const candidates = cells.get(`${cellX + offsetX},${cellY + offsetY}`) ?? [];
        for (const right of candidates) {
          if (right <= left) continue;
          let dx = x[right] - x[left];
          let dy = y[right] - y[left];
          let distance = Math.hypot(dx, dy);
          if (distance >= plan.options.separationRadius) continue;
          if (distance < 1e-6) {
            const direction = deterministicDirection(
              `${seed}:${plan.nodeIds[left]}:${plan.nodeIds[right]}`,
            );
            dx = direction.x;
            dy = direction.y;
            distance = 1;
          }
          const magnitude = (plan.options.separationRadius - distance) *
            plan.options.separationStrength;
          const forceX = (dx / distance) * magnitude;
          const forceY = (dy / distance) * magnitude;
          fx[left] -= forceX;
          fy[left] -= forceY;
          fx[right] += forceX;
          fy[right] += forceY;
          considered += 1;
          if (considered >= plan.options.maxSeparationNeighbors) break outer;
        }
      }
    }
  }
}

function coordinatesFromLayout(
  layout: PermissionsGraphLayoutStore,
  plan: PermissionsGraphRefinementPlan,
  x: Float64Array | null,
  y: Float64Array | null,
  initialX?: Float64Array,
  initialY?: Float64Array,
): readonly PermissionsGraphRefinedCoordinate[] {
  const pinned = new Set(plan.pinnedNodeIds);
  const priority = new Set(plan.priorityNodeIds);
  return Object.freeze(plan.nodeIds.map((nodeId, ordinal) => {
    const stored = layout.getPosition(nodeId) ?? { x: 0, y: 0 };
    const nextX = finiteFloat32(x?.[ordinal] ?? stored.x);
    const nextY = finiteFloat32(y?.[ordinal] ?? stored.y);
    const originalX = finiteFloat32(initialX?.[ordinal] ?? stored.x);
    const originalY = finiteFloat32(initialY?.[ordinal] ?? stored.y);
    return Object.freeze({
      nodeId,
      x: nextX,
      y: nextY,
      pinned: pinned.has(nodeId),
      priority: priority.has(nodeId),
      moved: !pinned.has(nodeId) &&
        (!Object.is(nextX, originalX) || !Object.is(nextY, originalY)),
    });
  }));
}

function freezeResult(
  plan: PermissionsGraphRefinementPlan,
  status: PermissionsGraphRefinementStatus,
  reason: string | null,
  iterationsCompleted: number,
  coordinates: readonly PermissionsGraphRefinedCoordinate[],
  diagnostics: readonly PermissionsGraphRefinementDiagnostic[],
  progressEvents: readonly PermissionsGraphRefinementProgress[],
  execution: PermissionsGraphRefinementExecution,
): PermissionsGraphRefinementResult {
  return Object.freeze({
    status,
    reason,
    sourceTopologyFingerprint: plan.sourceTopologyFingerprint,
    sourceLayoutGeneration: plan.sourceLayoutGeneration,
    sourceCoordinateRevision: plan.sourceCoordinateRevision,
    nodeCount: plan.nodeIds.length,
    edgeCount: plan.edgeIds.length,
    iterationsCompleted,
    totalIterations: plan.options.iterations,
    pinnedNodeIds: plan.pinnedNodeIds,
    priorityNodeIds: plan.priorityNodeIds,
    coordinates,
    diagnostics: freezeDiagnostics(diagnostics),
    progressEvents: Object.freeze([...progressEvents]),
    execution,
  });
}

function freezePlan(
  input: PermissionsGraphRefinementInput,
  options: NormalizedRefinementOptions,
  nodeIds: readonly string[],
  edgeIds: readonly string[],
  pinnedNodeIds: readonly string[],
  priorityNodeIds: readonly string[],
  status: PermissionsGraphRefinementPlanStatus,
  reason: string | null,
  diagnostics: readonly PermissionsGraphRefinementDiagnostic[],
): PermissionsGraphRefinementPlan {
  return Object.freeze({
    status,
    reason,
    sourceTopologyFingerprint: input.model.topologyFingerprint,
    sourceLayoutGeneration: input.layout.layoutGeneration,
    sourceCoordinateRevision: input.layout.coordinateRevision,
    nodeIds: Object.freeze([...nodeIds]),
    edgeIds: Object.freeze([...edgeIds]),
    pinnedNodeIds: Object.freeze([...pinnedNodeIds]),
    priorityNodeIds: Object.freeze([...priorityNodeIds]),
    diagnostics: freezeDiagnostics(diagnostics),
    options,
  });
}

function normalizeRefinementOptions(
  options: PermissionsGraphRefinementOptions = {},
): NormalizedRefinementOptions {
  return Object.freeze({
    iterations: normalizeInteger(options.iterations, DEFAULT_ITERATIONS, 0, MAX_ITERATIONS),
    edgeLength: nonNegativeFinite(options.edgeLength, DEFAULT_EDGE_LENGTH),
    edgeAttraction: nonNegativeFinite(options.edgeAttraction, DEFAULT_EDGE_ATTRACTION),
    separationRadius: nonNegativeFinite(options.separationRadius, DEFAULT_SEPARATION_RADIUS),
    separationStrength: nonNegativeFinite(
      options.separationStrength,
      DEFAULT_SEPARATION_STRENGTH,
    ),
    damping: clamp(finiteOr(options.damping, DEFAULT_DAMPING), 0, 1),
    maxMovementPerTick: positiveFinite(
      options.maxMovementPerTick,
      DEFAULT_MAX_MOVEMENT_PER_TICK,
    ),
    boundsPadding: nonNegativeFinite(options.boundsPadding, DEFAULT_BOUNDS_PADDING),
    priorityMultiplier: Math.max(1, finiteOr(
      options.priorityMultiplier,
      DEFAULT_PRIORITY_MULTIPLIER,
    )),
    progressInterval: normalizeInteger(
      options.progressInterval,
      DEFAULT_PROGRESS_INTERVAL,
      1,
      MAX_ITERATIONS,
    ),
    yieldInterval: normalizeInteger(
      options.yieldInterval,
      DEFAULT_YIELD_INTERVAL,
      0,
      MAX_ITERATIONS,
    ),
    maxSeparationNeighbors: normalizeInteger(
      options.maxSeparationNeighbors,
      DEFAULT_MAX_SEPARATION_NEIGHBORS,
      1,
      512,
    ),
    convergenceThreshold: nonNegativeFinite(
      options.convergenceThreshold,
      DEFAULT_CONVERGENCE_THRESHOLD,
    ),
    yieldFn: options.yieldFn ?? yieldToEventLoop,
    preferWorker: options.preferWorker === true,
  });
}

function executionFor(workerRequested: boolean): PermissionsGraphRefinementExecution {
  return Object.freeze({
    mode: "chunked-main-thread",
    workerRequested,
    workerUsed: false,
    fallbackUsed: true,
    workerReason: workerRequested ? "worker-bundle-unavailable" : "not-requested",
  });
}

function filterActiveIds(
  ids: readonly string[],
  activeNodeIds: ReadonlySet<string>,
  diagnostics: PermissionsGraphRefinementDiagnostic[],
  code: "IGNORED_PRIORITY_NODE" | "IGNORED_PINNED_NODE",
): readonly string[] {
  const included: string[] = [];
  for (const id of uniqueSorted(ids)) {
    if (activeNodeIds.has(id)) included.push(id);
    else diagnostics.push(diagnostic(code, `Ignored node ${id} because it is outside the active slice.`, id));
  }
  return Object.freeze(included);
}

function indexMatchesModel(model: PermissionsGraphModel, index: PermissionsGraphIndex): boolean {
  return model.nodes.every((node) => index.getNode(node.id) === node) &&
    model.edges.every((edge) => index.getEdge(edge.id) === edge);
}

function diagnostic(
  code: PermissionsGraphRefinementDiagnosticCode,
  message: string,
  id?: string,
): PermissionsGraphRefinementDiagnostic {
  return Object.freeze(id === undefined ? { code, message } : { code, message, id });
}

function freezeDiagnostics(
  values: readonly PermissionsGraphRefinementDiagnostic[],
): readonly PermissionsGraphRefinementDiagnostic[] {
  const unique = new Map<string, PermissionsGraphRefinementDiagnostic>();
  for (const value of values) {
    const key = `${value.code}\u0000${value.id ?? ""}\u0000${value.message}`;
    if (!unique.has(key)) unique.set(key, value);
  }
  return Object.freeze(Array.from(unique.values()).sort((left, right) =>
    compareStrings(left.code, right.code) ||
    compareStrings(left.id ?? "", right.id ?? "") ||
    compareStrings(left.message, right.message)
  ));
}

function throwIfCancelled(signal: PermissionsGraphCancellationSignal | undefined): void {
  if (!signal) return;
  if ("aborted" in signal && signal.aborted) throw new PermissionsGraphRefinementCancelledError();
  if ("throwIfCancellationRequested" in signal && !("aborted" in signal)) {
    signal.throwIfCancellationRequested();
  }
}

async function cooperativeRefinementCheckpoint(
  signal: PermissionsGraphCancellationSignal | undefined,
  yieldFn: () => Promise<void>,
): Promise<void> {
  throwIfCancelled(signal);
  if (signal && "checkpoint" in signal && signal.checkpoint) await signal.checkpoint();
  await yieldFn();
  throwIfCancelled(signal);
}

function isCancellation(
  error: unknown,
  signal: PermissionsGraphCancellationSignal | undefined,
): boolean {
  if (error instanceof PermissionsGraphRefinementCancelledError) return true;
  if (error instanceof Error && (error.name === "AbortError" || error.name === "LongOperationCancelledError")) {
    return true;
  }
  if (signal && "aborted" in signal && signal.aborted) return true;
  return !!signal && "isCancelRequested" in signal && signal.isCancelRequested === true;
}

function cancellationMessage(error: unknown): string {
  return error instanceof Error ? error.message : "Permissions graph refinement was cancelled.";
}

function deterministicDirection(value: string): PermissionsGraphCoordinate {
  const angle = (hashString(value) / 0xffff_ffff) * Math.PI * 2;
  return { x: Math.cos(angle), y: Math.sin(angle) };
}

function hashString(value: string): number {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

function finiteCoordinate(value: { readonly x: number; readonly y: number }): boolean {
  return Number.isFinite(value.x) && Number.isFinite(value.y);
}

function finiteFloat32(value: number): number {
  const converted = new Float32Array([value])[0];
  if (!Number.isFinite(converted)) throw new Error("Coordinate exceeds the finite Float32 range.");
  return converted;
}

function normalizeInteger(
  value: number | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  if (!Number.isFinite(value)) return fallback;
  return Math.max(minimum, Math.min(maximum, Math.floor(value as number)));
}

function finiteOr(value: number | undefined, fallback: number): number {
  return Number.isFinite(value) ? (value as number) : fallback;
}

function nonNegativeFinite(value: number | undefined, fallback: number): number {
  return Math.max(0, finiteOr(value, fallback));
}

function positiveFinite(value: number | undefined, fallback: number): number {
  if (value === Number.POSITIVE_INFINITY) return Number.POSITIVE_INFINITY;
  const normalized = finiteOr(value, fallback);
  return normalized > 0 ? normalized : fallback;
}

function clamp(value: number, minimum: number, maximum: number): number {
  return Math.max(minimum, Math.min(maximum, value));
}

function uniqueSorted(values: Iterable<string>): readonly string[] {
  return Object.freeze(Array.from(new Set(values)).sort(compareStrings));
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
