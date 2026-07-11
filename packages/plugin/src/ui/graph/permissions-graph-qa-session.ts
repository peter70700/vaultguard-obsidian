import { buildPermissionsGraphAggregatePlan } from "./permissions-graph-budget";
import {
  buildPermissionsGraphSeedLayout,
  PermissionsGraphLayoutCancelledError,
  type PermissionsGraphLayoutMemoryEstimate,
  type PermissionsGraphLayoutStore,
} from "./permissions-graph-layout";
import {
  PermissionsGraphSearchIndex,
  permissionsGraphMaterializationPlanToActiveSliceInput,
  planPermissionsGraphFocusMaterialization,
  planPermissionsGraphHoverMaterialization,
  planPermissionsGraphSearchMaterialization,
  planPermissionsGraphViewportMaterialization,
} from "./permissions-graph-materialization";
import {
  buildPermissionsGraphModelFromElements,
  type PermissionsGraphIndex,
  type PermissionsGraphModel,
} from "./permissions-graph-model";
import {
  createPermissionsGraphVirtualQaFixture,
  validatePermissionsGraphVirtualQaFixture,
  type PermissionsGraphVirtualQaFixture,
} from "./permissions-graph-qa-fixture";
import {
  refinePermissionsGraphMaterializationPlanForQa,
  type PermissionsGraphQaRefinementResult,
} from "./permissions-graph-qa-runtime";
import {
  buildPermissionsGraphActiveSlice,
  type PermissionsGraphActiveSlice,
} from "./permissions-graph-renderer";
import { MAX_PERMISSIONS_GRAPH_REFINEMENT_EDGES } from "./permissions-graph-refinement";
import { PermissionsGraphSpatialIndex } from "./permissions-graph-spatial";

const ACTIVE_NODE_CAP = 900;
const ACTIVE_EDGE_CAP = 1_600;

export type PermissionsGraphVirtualQaRunStatus = "completed" | "cancelled";

export interface PermissionsGraphVirtualQaEvidence {
  readonly schemaVersion: 1;
  readonly status: PermissionsGraphVirtualQaRunStatus;
  readonly disposableVaultConfirmed: true;
  readonly syntheticNodeCount: number;
  readonly syntheticEdgeCount: number;
  readonly syntheticPermissionEdgeCount: number;
  readonly materializedNodeCount: number;
  readonly materializedEdgeCount: number;
  readonly omittedNodeCount: number;
  readonly omittedEdgeCount: number;
  readonly hiddenNodeCount: number;
  readonly hiddenEdgeCount: number;
  readonly layoutMemory: Pick<
    PermissionsGraphLayoutMemoryEstimate,
    "typedArrayBytes" | "idMetadataBytes" | "manualMetadataBytes" | "totalEstimatedBytes" | "perNodeEstimatedBytes"
  >;
  readonly planStatus: {
    readonly viewport: "ready" | "not-run";
    readonly hover: "ready" | "not-run";
    readonly search: "ready" | "not-run";
    readonly focus: "ready" | "not-run";
    readonly viewportNodes: number;
    readonly hoverHit: boolean;
    readonly searchMatches: number;
    readonly focusNodes: number;
  };
  readonly refinement: {
    readonly status: string;
    readonly writeBackStatus: string;
    readonly edgeCount: number;
    readonly cap: 350;
  };
  readonly cancellation: {
    readonly requested: boolean;
    readonly status: "not-cancelled" | "cancelled";
  };
  readonly diagnostics: readonly string[];
  readonly timingsMs: Readonly<Record<string, number>> & { readonly total: number };
  readonly safety: {
    readonly syntheticOnly: true;
    readonly noVaultAccess: true;
    readonly noNetworkAccess: true;
    readonly noCacheAccess: true;
    readonly noPersistence: true;
  };
}

export interface PermissionsGraphVirtualQaResources {
  readonly fixture: PermissionsGraphVirtualQaFixture;
  readonly model: PermissionsGraphModel;
  readonly index: PermissionsGraphIndex;
  readonly layout: PermissionsGraphLayoutStore;
  readonly spatial: PermissionsGraphSpatialIndex;
  readonly activeSlice: PermissionsGraphActiveSlice;
  readonly refinement: PermissionsGraphQaRefinementResult | null;
}

export interface PermissionsGraphVirtualQaRunResult {
  readonly evidence: PermissionsGraphVirtualQaEvidence;
  readonly resources: PermissionsGraphVirtualQaResources | null;
}

export interface PermissionsGraphVirtualQaRunOptions {
  readonly disposableVaultConfirmed: boolean;
  readonly signal?: AbortSignal;
  readonly onStage?: (stage: string) => void;
}

export class PermissionsGraphVirtualQaConfirmationError extends Error {
  constructor() {
    super("Disposable-vault confirmation is required before synthetic graph QA can run.");
    this.name = "PermissionsGraphVirtualQaConfirmationError";
  }
}

class PermissionsGraphVirtualQaCancelledError extends Error {}

/** Compose the inert Phase 1-6 path using only the fixed source-local fixture. */
export async function runPermissionsGraphVirtualQaPipeline(
  options: PermissionsGraphVirtualQaRunOptions,
): Promise<PermissionsGraphVirtualQaRunResult> {
  if (!options.disposableVaultConfirmed) {
    throw new PermissionsGraphVirtualQaConfirmationError();
  }

  const startedAt = now();
  const timings: Record<string, number> = {};
  const diagnostics = new Set<string>();
  let fixture: PermissionsGraphVirtualQaFixture | null = null;
  let memory: PermissionsGraphLayoutMemoryEstimate | null = null;

  try {
    checkCancellation(options.signal);
    fixture = await measure("fixture", timings, options, () =>
      createPermissionsGraphVirtualQaFixture()
    );
    const validation = validatePermissionsGraphVirtualQaFixture(fixture);
    if (!validation.valid) {
      throw new Error("The fixed synthetic QA fixture failed its topology/path invariants.");
    }
    checkCancellation(options.signal);

    const modelResult = await measure("modelIndex", timings, options, () =>
      buildPermissionsGraphModelFromElements(fixture?.elements ?? [], {
        vaultId: "synthetic-qa-vault",
      })
    );
    const { model, index } = modelResult;
    checkCancellation(options.signal);

    const aggregatePlan = await measure("budgetPlanner", timings, options, () =>
      buildPermissionsGraphAggregatePlan(model, index, {
        maxRenderedNodes: ACTIVE_NODE_CAP,
        maxRenderedEdges: ACTIVE_EDGE_CAP,
        maxAggregateNodes: 675,
        maxEdgesPerAggregate: 64,
        showUserNodes: true,
        accessLevels: { read: true, write: true, admin: true },
        includeFileSummaries: true,
        includeFolderSummaries: true,
        tieBreak: "stable-id",
      })
    );
    for (const diagnostic of aggregatePlan.diagnostics) diagnostics.add(diagnostic.code);
    checkCancellation(options.signal);

    const layout = await measure("layout", timings, options, () =>
      buildPermissionsGraphSeedLayout(model, index, {
        seed: fixture?.seed,
        signal: options.signal,
        yieldInterval: 256,
      })
    );
    memory = layout.getMemoryEstimate();
    checkCancellation(options.signal);

    const spatial = await measure("spatial", timings, options, () =>
      new PermissionsGraphSpatialIndex(layout)
    );
    for (const diagnostic of spatial.getDiagnostics()) diagnostics.add(diagnostic.code);

    const anchorId = fixture.userIds[0] ?? fixture.fileIds[0] ?? fixture.folderIds[0];
    const anchor = anchorId ? layout.getPosition(anchorId) : null;
    const bounds = layout.coordinateBounds;
    const viewport = anchor
      ? {
          x1: anchor.x - 512,
          y1: anchor.y - 512,
          x2: anchor.x + 512,
          y2: anchor.y + 512,
        }
      : {
          x1: bounds.minX - 1,
          y1: bounds.minY - 1,
          x2: bounds.maxX + 1,
          y2: bounds.maxY + 1,
        };

    const viewportPlan = await measure("viewportPlan", timings, options, () =>
      planPermissionsGraphViewportMaterialization(model, index, layout, spatial, {
        viewport,
        overscanMargin: 128,
        hysteresisMargin: 256,
        includeNeighbors: true,
        maxNeighborsPerNode: 1,
        budget: { maxNodes: ACTIVE_NODE_CAP, maxEdges: ACTIVE_EDGE_CAP },
      })
    );
    for (const diagnostic of viewportPlan.diagnostics) diagnostics.add(diagnostic);
    checkCancellation(options.signal);

    const hoverPlan = await measure("hoverPlan", timings, options, () =>
      planPermissionsGraphHoverMaterialization(model, index, layout, spatial, {
        x: anchor?.x ?? 0,
        y: anchor?.y ?? 0,
        hitRadius: anchor ? 1 : 0,
        maxNeighbors: 12,
        budget: { maxNodes: ACTIVE_NODE_CAP, maxEdges: ACTIVE_EDGE_CAP },
      })
    );
    for (const diagnostic of hoverPlan.diagnostics) diagnostics.add(diagnostic);

    const searchIndex = new PermissionsGraphSearchIndex(model, index);
    const firstFile = fixture.fileIds[0] ? index.getNode(fixture.fileIds[0]) : undefined;
    const searchPlan = await measure("searchPlan", timings, options, () =>
      planPermissionsGraphSearchMaterialization(model, index, layout, searchIndex, {
        query: firstFile?.label ?? "Synthetic QA File",
        maxResults: 100,
        includeNeighbors: true,
        maxNeighborsPerResult: 1,
        includeEdges: true,
        budget: { maxNodes: ACTIVE_NODE_CAP, maxEdges: ACTIVE_EDGE_CAP },
      })
    );
    for (const diagnostic of searchPlan.diagnostics) diagnostics.add(diagnostic);

    const focusNodeId = fixture.userIds[0] ?? "synthetic-qa-missing";
    const focusPlan = await measure("focusPlan", timings, options, () =>
      planPermissionsGraphFocusMaterialization(model, index, layout, {
        focusNodeId,
        depth: 1,
        includeEdges: true,
        budget: {
          maxNodes: ACTIVE_NODE_CAP,
          maxEdges: MAX_PERMISSIONS_GRAPH_REFINEMENT_EDGES,
        },
      })
    );
    for (const diagnostic of focusPlan.diagnostics) diagnostics.add(diagnostic);
    checkCancellation(options.signal);

    const beforeSlice = await measure("rendererInput", timings, options, () =>
      buildPermissionsGraphActiveSlice(
        permissionsGraphMaterializationPlanToActiveSliceInput({
          model,
          index,
          layout,
          plan: focusPlan,
        }),
      )
    );

    let refinement: PermissionsGraphQaRefinementResult | null = null;
    let activeSlice = beforeSlice;
    let refinementStatus = "skipped";
    let writeBackStatus = "skipped";
    if (beforeSlice.edges.length <= MAX_PERMISSIONS_GRAPH_REFINEMENT_EDGES) {
      refinement = await measure("refinement", timings, options, () =>
        refinePermissionsGraphMaterializationPlanForQa({
          model,
          index,
          layout,
          plan: focusPlan,
          focusedNodeIds: [focusNodeId],
          signal: options.signal,
          refinementOptions: {
            iterations: 4,
            yieldInterval: 1,
            convergenceThreshold: 0,
          },
          transitionOptions: { durationMs: 0 },
        })
      );
      refinementStatus = refinement.refinement.status;
      writeBackStatus = refinement.writeBack.status;
      for (const diagnostic of refinement.refinement.diagnostics) diagnostics.add(diagnostic.code);
      if (refinement.refinement.status === "cancelled") {
        return cancelledResult(startedAt, timings, fixture, memory, diagnostics);
      }
      activeSlice = refinement.afterSlice;
    }
    checkCancellation(options.signal);

    timings.total = round(now() - startedAt);
    const evidence = freezeEvidence({
      status: "completed",
      fixture,
      memory,
      materializedNodeCount: activeSlice.nodes.length,
      materializedEdgeCount: activeSlice.edges.length,
      omittedNodeCount: focusPlan.omittedNodes.length,
      omittedEdgeCount: focusPlan.omittedEdges.length,
      hiddenNodeCount: aggregatePlan.hiddenNodeCount,
      hiddenEdgeCount: aggregatePlan.hiddenEdgeCount,
      viewportNodes: viewportPlan.includedNodeIds.length,
      hoverHit: hoverPlan.hit !== null,
      searchMatches: searchPlan.totalMatchCount,
      focusNodes: focusPlan.includedNodeIds.length,
      refinementStatus,
      writeBackStatus,
      refinementEdgeCount: beforeSlice.edges.length,
      cancellationRequested: false,
      diagnostics,
      timings,
    });
    return Object.freeze({
      evidence,
      resources: Object.freeze({ fixture, model, index, layout, spatial, activeSlice, refinement }),
    });
  } catch (error) {
    if (
      options.signal?.aborted ||
      error instanceof PermissionsGraphVirtualQaCancelledError ||
      error instanceof PermissionsGraphLayoutCancelledError
    ) {
      return cancelledResult(startedAt, timings, fixture, memory, diagnostics);
    }
    throw error;
  }
}

function cancelledResult(
  startedAt: number,
  timings: Record<string, number>,
  fixture: PermissionsGraphVirtualQaFixture | null,
  memory: PermissionsGraphLayoutMemoryEstimate | null,
  diagnostics: Set<string>,
): PermissionsGraphVirtualQaRunResult {
  diagnostics.add("cancelled-before-publish");
  timings.total = round(now() - startedAt);
  return Object.freeze({
    evidence: freezeEvidence({
      status: "cancelled",
      fixture,
      memory,
      materializedNodeCount: 0,
      materializedEdgeCount: 0,
      omittedNodeCount: 0,
      omittedEdgeCount: 0,
      hiddenNodeCount: 0,
      hiddenEdgeCount: 0,
      viewportNodes: 0,
      hoverHit: false,
      searchMatches: 0,
      focusNodes: 0,
      refinementStatus: "cancelled",
      writeBackStatus: "skipped",
      refinementEdgeCount: 0,
      cancellationRequested: true,
      diagnostics,
      timings,
    }),
    resources: null,
  });
}

interface EvidenceInput {
  readonly status: PermissionsGraphVirtualQaRunStatus;
  readonly fixture: PermissionsGraphVirtualQaFixture | null;
  readonly memory: PermissionsGraphLayoutMemoryEstimate | null;
  readonly materializedNodeCount: number;
  readonly materializedEdgeCount: number;
  readonly omittedNodeCount: number;
  readonly omittedEdgeCount: number;
  readonly hiddenNodeCount: number;
  readonly hiddenEdgeCount: number;
  readonly viewportNodes: number;
  readonly hoverHit: boolean;
  readonly searchMatches: number;
  readonly focusNodes: number;
  readonly refinementStatus: string;
  readonly writeBackStatus: string;
  readonly refinementEdgeCount: number;
  readonly cancellationRequested: boolean;
  readonly diagnostics: Set<string>;
  readonly timings: Record<string, number>;
}

function freezeEvidence(input: EvidenceInput): PermissionsGraphVirtualQaEvidence {
  const emptyMemory = {
    typedArrayBytes: 0,
    idMetadataBytes: 0,
    manualMetadataBytes: 0,
    totalEstimatedBytes: 0,
    perNodeEstimatedBytes: 0,
  };
  const memory = input.memory ?? emptyMemory;
  const timingsMs = Object.freeze({
    ...input.timings,
    total: input.timings.total ?? 0,
  });
  return Object.freeze({
    schemaVersion: 1,
    status: input.status,
    disposableVaultConfirmed: true,
    syntheticNodeCount: input.fixture?.counts.nodes ?? 0,
    syntheticEdgeCount: input.fixture?.counts.edges ?? 0,
    syntheticPermissionEdgeCount: input.fixture?.counts.permissionEdges ?? 0,
    materializedNodeCount: input.materializedNodeCount,
    materializedEdgeCount: input.materializedEdgeCount,
    omittedNodeCount: input.omittedNodeCount,
    omittedEdgeCount: input.omittedEdgeCount,
    hiddenNodeCount: input.hiddenNodeCount,
    hiddenEdgeCount: input.hiddenEdgeCount,
    layoutMemory: Object.freeze({
      typedArrayBytes: memory.typedArrayBytes,
      idMetadataBytes: memory.idMetadataBytes,
      manualMetadataBytes: memory.manualMetadataBytes,
      totalEstimatedBytes: memory.totalEstimatedBytes,
      perNodeEstimatedBytes: memory.perNodeEstimatedBytes,
    }),
    planStatus: Object.freeze({
      viewport: input.status === "completed" ? "ready" : "not-run",
      hover: input.status === "completed" ? "ready" : "not-run",
      search: input.status === "completed" ? "ready" : "not-run",
      focus: input.status === "completed" ? "ready" : "not-run",
      viewportNodes: input.viewportNodes,
      hoverHit: input.hoverHit,
      searchMatches: input.searchMatches,
      focusNodes: input.focusNodes,
    }),
    refinement: Object.freeze({
      status: input.refinementStatus,
      writeBackStatus: input.writeBackStatus,
      edgeCount: input.refinementEdgeCount,
      cap: MAX_PERMISSIONS_GRAPH_REFINEMENT_EDGES,
    }),
    cancellation: Object.freeze({
      requested: input.cancellationRequested,
      status: input.cancellationRequested ? "cancelled" : "not-cancelled",
    }),
    diagnostics: Object.freeze(Array.from(input.diagnostics).sort(compareStrings)),
    timingsMs,
    safety: Object.freeze({
      syntheticOnly: true,
      noVaultAccess: true,
      noNetworkAccess: true,
      noCacheAccess: true,
      noPersistence: true,
    }),
  });
}

async function measure<T>(
  stage: string,
  timings: Record<string, number>,
  options: PermissionsGraphVirtualQaRunOptions,
  action: () => T | Promise<T>,
): Promise<T> {
  checkCancellation(options.signal);
  options.onStage?.(stage);
  const startedAt = now();
  const result = await action();
  timings[stage] = round(now() - startedAt);
  checkCancellation(options.signal);
  return result;
}

function checkCancellation(signal?: AbortSignal): void {
  if (signal?.aborted) throw new PermissionsGraphVirtualQaCancelledError();
}

function now(): number {
  return typeof performance !== "undefined" ? performance.now() : Date.now();
}

function round(value: number): number {
  return Math.round(value * 1_000) / 1_000;
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
