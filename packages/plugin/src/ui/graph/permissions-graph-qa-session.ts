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
  buildPermissionsGraphOverviewBuffers,
  type PermissionsGraphOverviewBuffers,
} from "./permissions-graph-overview-buffers";
import {
  buildPermissionsGraphOverviewEdges,
  type PermissionsGraphOverviewEdgeMode,
  type PermissionsGraphOverviewEdgeSnapshot,
} from "./permissions-graph-overview-edges";
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
export const PERMISSIONS_GRAPH_STRESS_EVIDENCE_PHASE_G_MARKER =
  "vg-permissions-graph-stress-evidence-phase-g-v1";

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
  readonly overview: {
    readonly enabled: true;
    readonly nodeCount: number;
    readonly bufferBytes: number;
    readonly edges: {
      readonly enabled: boolean;
      readonly mode: PermissionsGraphOverviewEdgeMode | "not-run";
      readonly eligibleEdgeCount: number;
      readonly representedEdgeCount: number;
      readonly emittedSegmentCount: number;
      readonly prioritySegmentCount: number;
      readonly ordinarySampleSegmentCount: number;
      readonly bundleSegmentCount: number;
      readonly densitySegmentCount: number;
      readonly bundledEdgeCount: number;
      readonly omittedEdgeCount: number;
      readonly exact: boolean;
      readonly bufferBytes: number;
      readonly expectedGpuMirrorBytes: number;
      readonly bufferFingerprint: string | null;
      readonly diagnostics: readonly string[];
    };
  };
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
  readonly phaseG: {
    readonly marker: typeof PERMISSIONS_GRAPH_STRESS_EVIDENCE_PHASE_G_MARKER;
    readonly edge: {
      readonly mode: PermissionsGraphOverviewEdgeMode | "not-run";
      readonly eligibleEdgeCount: number;
      readonly emittedSegmentCount: number;
      readonly omittedEdgeCount: number;
    };
    readonly transition: {
      readonly status: "completed" | "not-run";
      readonly mode: "animated" | "immediate" | "not-run";
      readonly progress: number;
      readonly movedNodeCount: number;
      readonly frameCount: number;
      readonly droppedFrameCount: 0;
      readonly skippedFrameCount: number;
    };
    readonly spatial: {
      readonly indexedNodeCount: number;
      readonly skippedNodeCount: number;
      readonly rebuildCount: number;
      readonly incrementalUpdateCount: number;
      readonly stale: boolean;
    };
    readonly fallback: {
      readonly revisionSyncRebuilt: boolean;
    };
    readonly lifecycle: {
      readonly resourcesPublished: boolean;
      readonly cancellationSafe: true;
    };
    readonly privacy: {
      readonly allowlisted: true;
      readonly forbiddenValueCount: 0;
    };
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
  readonly overviewBuffers: PermissionsGraphOverviewBuffers;
  readonly overviewEdges: PermissionsGraphOverviewEdgeSnapshot;
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
  let overviewBuffers: PermissionsGraphOverviewBuffers | null = null;
  let overviewEdges: PermissionsGraphOverviewEdgeSnapshot | null = null;

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

    overviewBuffers = await measure("overviewBuffers", timings, options, () =>
      buildPermissionsGraphOverviewBuffers({ model, index, layout })
    );
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

    // Phase 6 may publish a new coordinate revision. Phase D must never pair
    // the final active slice with pre-refinement overview/spatial coordinates.
    await measure("interactionRevisionSync", timings, options, () => {
      spatial.rebuildIfNeeded();
      overviewBuffers = buildPermissionsGraphOverviewBuffers({
        model,
        index,
        layout,
        state: {
          revision: 0,
          materializedNodeIds: activeSlice.materializedNodeIds,
        },
      });
    });
    checkCancellation(options.signal);

    overviewEdges = await measure("overviewEdges", timings, options, () =>
      buildPermissionsGraphOverviewEdges({
        model,
        index,
        layout,
        projectedMedianSpacing: 6,
        cameraRevision: 0,
        signal: options.signal,
      })
    );
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
      overviewBuffers,
      overviewEdges,
      spatial,
      refinementResult: refinement,
      diagnostics,
      timings,
    });
    return Object.freeze({
      evidence,
      resources: Object.freeze({
        fixture,
        model,
        index,
        layout,
        overviewBuffers,
        overviewEdges,
        spatial,
        activeSlice,
        refinement,
      }),
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
      overviewBuffers: null,
      overviewEdges: null,
      spatial: null,
      refinementResult: null,
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
  readonly overviewBuffers: PermissionsGraphOverviewBuffers | null;
  readonly overviewEdges: PermissionsGraphOverviewEdgeSnapshot | null;
  readonly spatial: PermissionsGraphSpatialIndex | null;
  readonly refinementResult: PermissionsGraphQaRefinementResult | null;
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
    overview: Object.freeze({
      enabled: true,
      nodeCount: input.overviewBuffers?.nodeCount ?? 0,
      bufferBytes: input.overviewBuffers?.memory.totalOwnedBytes ?? 0,
      edges: freezeOverviewEdgeEvidence(input.overviewEdges),
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
    phaseG: freezePhaseGEvidence(input),
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

function freezePhaseGEvidence(
  input: EvidenceInput,
): PermissionsGraphVirtualQaEvidence["phaseG"] {
  const transition = input.refinementResult?.transition ?? null;
  const frameCount = transition?.frames.length ?? 0;
  const finalProgress = transition?.frames.at(-1)?.progress ?? (transition ? 1 : 0);
  return Object.freeze({
    marker: PERMISSIONS_GRAPH_STRESS_EVIDENCE_PHASE_G_MARKER,
    edge: Object.freeze({
      mode: input.overviewEdges?.mode ?? "not-run",
      eligibleEdgeCount: input.overviewEdges?.eligibleEdgeCount ?? 0,
      emittedSegmentCount: input.overviewEdges?.emittedSegmentCount ?? 0,
      omittedEdgeCount: input.overviewEdges?.omittedEdgeCount ?? 0,
    }),
    transition: Object.freeze({
      status: transition ? "completed" as const : "not-run" as const,
      mode: transition ? transition.immediate ? "immediate" as const : "animated" as const : "not-run" as const,
      progress: finalProgress,
      movedNodeCount: transition?.deltas.length ?? 0,
      frameCount,
      droppedFrameCount: 0 as const,
      skippedFrameCount: transition?.immediate ? Math.max(0, 1 - frameCount) : 0,
    }),
    spatial: Object.freeze({
      indexedNodeCount: input.spatial?.indexedNodeCount ?? 0,
      skippedNodeCount: input.spatial?.skippedNodeCount ?? 0,
      rebuildCount: input.spatial?.rebuildCount ?? 0,
      incrementalUpdateCount: input.spatial?.incrementalUpdateCount ?? 0,
      stale: input.spatial
        ? input.spatial.coordinateRevision !== input.overviewBuffers?.coordinateRevision
        : false,
    }),
    fallback: Object.freeze({
      revisionSyncRebuilt: (input.spatial?.rebuildCount ?? 0) > 1,
    }),
    lifecycle: Object.freeze({
      resourcesPublished: input.status === "completed" && input.overviewBuffers !== null,
      cancellationSafe: true as const,
    }),
    privacy: Object.freeze({
      allowlisted: true as const,
      forbiddenValueCount: 0 as const,
    }),
  });
}

function freezeOverviewEdgeEvidence(
  snapshot: PermissionsGraphOverviewEdgeSnapshot | null,
): PermissionsGraphVirtualQaEvidence["overview"]["edges"] {
  return Object.freeze({
    enabled: snapshot !== null,
    mode: snapshot?.mode ?? "not-run",
    eligibleEdgeCount: snapshot?.eligibleEdgeCount ?? 0,
    representedEdgeCount: snapshot?.representedEdgeCount ?? 0,
    emittedSegmentCount: snapshot?.emittedSegmentCount ?? 0,
    prioritySegmentCount: snapshot?.prioritySegmentCount ?? 0,
    ordinarySampleSegmentCount: snapshot?.ordinarySampleSegmentCount ?? 0,
    bundleSegmentCount: snapshot?.bundleSegmentCount ?? 0,
    densitySegmentCount: snapshot?.densitySegmentCount ?? 0,
    bundledEdgeCount: snapshot?.bundledEdgeCount ?? 0,
    omittedEdgeCount: snapshot?.omittedEdgeCount ?? 0,
    exact: snapshot?.exact ?? false,
    bufferBytes: snapshot?.memory.totalOwnedBytes ?? 0,
    expectedGpuMirrorBytes: snapshot?.memory.expectedGpuMirrorBytes ?? 0,
    bufferFingerprint: snapshot?.bufferFingerprint ?? null,
    diagnostics: Object.freeze([...(snapshot?.diagnostics ?? [])]),
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
