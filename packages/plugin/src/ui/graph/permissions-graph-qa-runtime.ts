/**
 * Explicit QA/dev-only Phase 5 -> Phase 6 -> Phase 4 bridge.
 *
 * Production graph views and plugin wiring must not import this module. Calling
 * this function is the only way to combine virtual materialization, bounded
 * refinement, coordinate write-back, transitions, and the active renderer.
 */

import type {
  PermissionsGraphCancellationSignal,
  PermissionsGraphLayoutStore,
} from "./permissions-graph-layout";
import {
  permissionsGraphMaterializationPlanToActiveSliceInput,
  type PermissionsGraphMaterializationPlan,
} from "./permissions-graph-materialization";
import type { PermissionsGraphIndex, PermissionsGraphModel } from "./permissions-graph-model";
import {
  applyPermissionsGraphRefinementToLayoutStore,
  applyPermissionsGraphTransitionFrameToActiveSlice,
  buildPermissionsGraphCoordinateTransition,
  refinePermissionsGraphActiveSlice,
  type PermissionsGraphCoordinateTransition,
  type PermissionsGraphCoordinateTransitionOptions,
  type PermissionsGraphRefinementOptions,
  type PermissionsGraphRefinementProgress,
  type PermissionsGraphRefinementResult,
  type PermissionsGraphRefinementWriteBackResult,
} from "./permissions-graph-refinement";
import {
  buildPermissionsGraphActiveSlice,
  type PermissionsGraphActiveSlice,
  type PermissionsGraphSelectionRequest,
} from "./permissions-graph-renderer";

export interface PermissionsGraphQaRefinementInput {
  readonly model: PermissionsGraphModel;
  readonly index: PermissionsGraphIndex;
  readonly layout: PermissionsGraphLayoutStore;
  readonly plan: PermissionsGraphMaterializationPlan;
  readonly selection?: PermissionsGraphSelectionRequest;
  readonly focusedNodeIds?: readonly string[];
  readonly pinnedNodeIds?: readonly string[];
  readonly refinementOptions?: PermissionsGraphRefinementOptions;
  readonly transitionOptions?: PermissionsGraphCoordinateTransitionOptions;
  readonly signal?: PermissionsGraphCancellationSignal;
  readonly onProgress?: (progress: PermissionsGraphRefinementProgress) => void;
  readonly allowManualOverwrite?: boolean;
}

export interface PermissionsGraphQaRefinementResult {
  readonly refinement: PermissionsGraphRefinementResult;
  readonly writeBack: PermissionsGraphRefinementWriteBackResult;
  readonly beforeSlice: PermissionsGraphActiveSlice;
  readonly afterSlice: PermissionsGraphActiveSlice;
  readonly transition: PermissionsGraphCoordinateTransition;
  readonly transitionSlices: readonly PermissionsGraphActiveSlice[];
}

/**
 * Refine one already-materialized Phase 5 plan and return slices accepted by
 * the Phase 4 renderer. The production view has no call site for this bridge.
 */
export async function refinePermissionsGraphMaterializationPlanForQa(
  input: PermissionsGraphQaRefinementInput,
): Promise<PermissionsGraphQaRefinementResult> {
  const activeInput = permissionsGraphMaterializationPlanToActiveSliceInput({
    model: input.model,
    index: input.index,
    layout: input.layout,
    plan: input.plan,
    selection: input.selection,
  });
  const beforeSlice = buildPermissionsGraphActiveSlice(activeInput);
  const inferredFocusNodeIds = input.focusedNodeIds ?? focusNodeIdsFromPlan(input.plan);
  const refinement = await refinePermissionsGraphActiveSlice({
    model: input.model,
    index: input.index,
    layout: input.layout,
    materializationPlan: input.plan,
    selectedNodeIds: input.selection?.nodeIds,
    focusedNodeIds: inferredFocusNodeIds,
    pinnedNodeIds: input.pinnedNodeIds,
    options: input.refinementOptions,
    signal: input.signal,
    onProgress: input.onProgress,
  });
  const writeBack = applyPermissionsGraphRefinementToLayoutStore({
    model: input.model,
    index: input.index,
    layout: input.layout,
    result: refinement,
    allowManualOverwrite: input.allowManualOverwrite,
  });
  const afterSlice = refinement.status === "completed" && writeBack.status !== "rejected"
    ? buildPermissionsGraphActiveSlice(activeInput)
    : beforeSlice;
  const pinnedNodeIds = Array.from(new Set([
    ...(input.pinnedNodeIds ?? []),
    ...beforeSlice.materializedNodeIds.filter((nodeId) => input.layout.isManuallyPositioned(nodeId)),
  ])).sort(compareStrings);
  const transition = buildPermissionsGraphCoordinateTransition({
    previous: beforeSlice.nodes.map((node) => ({ nodeId: node.data.id, ...node.position })),
    next: afterSlice.nodes.map((node) => ({ nodeId: node.data.id, ...node.position })),
    knownNodeIds: input.model.nodes.map((node) => node.id),
    pinnedNodeIds,
    options: input.transitionOptions,
  });
  const transitionSlices = Object.freeze(
    transition.frames.map((frame) =>
      applyPermissionsGraphTransitionFrameToActiveSlice(afterSlice, frame)
    ),
  );

  return Object.freeze({
    refinement,
    writeBack,
    beforeSlice,
    afterSlice,
    transition,
    transitionSlices,
  });
}

function focusNodeIdsFromPlan(plan: PermissionsGraphMaterializationPlan): readonly string[] {
  if (plan.kind !== "focus" || !("focusNodeId" in plan)) return Object.freeze([] as string[]);
  const focusNodeId = (plan as { readonly focusNodeId?: unknown }).focusNodeId;
  return typeof focusNodeId === "string" && focusNodeId.length > 0
    ? Object.freeze([focusNodeId])
    : Object.freeze([] as string[]);
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
