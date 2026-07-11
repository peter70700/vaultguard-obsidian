/**
 * Renderer-independent uniform-grid spatial index for Phase 5 planning.
 *
 * This module is intentionally inert. It only reads Phase 3 layout coordinates
 * and is not imported by the live PermissionsGraphView or plugin runtime.
 */

import type {
  PermissionsGraphCoordinate,
  PermissionsGraphLayoutStore,
} from "./permissions-graph-layout";

export const DEFAULT_PERMISSIONS_GRAPH_SPATIAL_CELL_SIZE = 256;

export interface PermissionsGraphSpatialBounds {
  readonly x1: number;
  readonly y1: number;
  readonly x2: number;
  readonly y2: number;
}

export interface PermissionsGraphSpatialIndexOptions {
  readonly cellSize?: number;
}

export interface PermissionsGraphSpatialQueryOptions {
  /** Absolute world-coordinate margin added on every side. */
  readonly overscan?: number;
  readonly maxResults?: number;
}

export interface PermissionsGraphSpatialEntry extends PermissionsGraphCoordinate {
  readonly nodeId: string;
  readonly ordinal: number;
  readonly cellX: number;
  readonly cellY: number;
}

export interface PermissionsGraphNearestNodeResult extends PermissionsGraphCoordinate {
  readonly nodeId: string;
  readonly ordinal: number;
  readonly distance: number;
}

export type PermissionsGraphSpatialDiagnosticCode =
  | "INVALID_CELL_SIZE"
  | "SKIPPED_NON_FINITE_COORDINATE";

export interface PermissionsGraphSpatialDiagnostic {
  readonly code: PermissionsGraphSpatialDiagnosticCode;
  readonly message: string;
  readonly nodeId?: string;
  readonly ordinal?: number;
}

interface MutableSpatialEntry extends PermissionsGraphSpatialEntry {}

const EMPTY_ENTRIES: readonly PermissionsGraphSpatialEntry[] = Object.freeze(
  [] as PermissionsGraphSpatialEntry[],
);

/**
 * Uniform point grid keyed by deterministic integer world-coordinate cells.
 * Queries automatically rebuild after a Phase 3 generation/revision change.
 */
export class PermissionsGraphSpatialIndex {
  readonly cellSize: number;

  private readonly configurationDiagnostics: PermissionsGraphSpatialDiagnostic[];
  private cells = new Map<string, readonly PermissionsGraphSpatialEntry[]>();
  private diagnostics: readonly PermissionsGraphSpatialDiagnostic[] = Object.freeze(
    [] as PermissionsGraphSpatialDiagnostic[],
  );
  private _layoutGeneration = -1;
  private _coordinateRevision = -1;
  private _indexedNodeCount = 0;
  private _skippedNodeCount = 0;
  private _rebuildCount = 0;

  constructor(
    readonly layout: PermissionsGraphLayoutStore,
    options: PermissionsGraphSpatialIndexOptions = {},
  ) {
    const requestedCellSize = options.cellSize ?? DEFAULT_PERMISSIONS_GRAPH_SPATIAL_CELL_SIZE;
    this.configurationDiagnostics = [];
    if (!Number.isFinite(requestedCellSize) || requestedCellSize <= 0) {
      this.cellSize = DEFAULT_PERMISSIONS_GRAPH_SPATIAL_CELL_SIZE;
      this.configurationDiagnostics.push(Object.freeze({
        code: "INVALID_CELL_SIZE",
        message: `Spatial cell size must be finite and positive; using ${DEFAULT_PERMISSIONS_GRAPH_SPATIAL_CELL_SIZE}.`,
      }));
    } else {
      this.cellSize = requestedCellSize;
    }
    this.rebuild();
  }

  get layoutGeneration(): number {
    return this._layoutGeneration;
  }

  get coordinateRevision(): number {
    return this._coordinateRevision;
  }

  get indexedNodeCount(): number {
    return this._indexedNodeCount;
  }

  get skippedNodeCount(): number {
    return this._skippedNodeCount;
  }

  get rebuildCount(): number {
    return this._rebuildCount;
  }

  get isStale(): boolean {
    return this._layoutGeneration !== this.layout.layoutGeneration ||
      this._coordinateRevision !== this.layout.coordinateRevision;
  }

  getDiagnostics(): readonly PermissionsGraphSpatialDiagnostic[] {
    return this.diagnostics;
  }

  /** Rebuild only when the layout generation or coordinate revision changed. */
  rebuildIfNeeded(): boolean {
    if (!this.isStale) return false;
    this.rebuild();
    return true;
  }

  /** Rebuild completely; invalid externally-mutated coordinates are skipped. */
  rebuild(): void {
    const mutableCells = new Map<string, MutableSpatialEntry[]>();
    const rebuildDiagnostics = [...this.configurationDiagnostics];
    let indexedNodeCount = 0;
    let skippedNodeCount = 0;

    for (let ordinal = 0; ordinal < this.layout.coordinateCount; ordinal += 1) {
      const nodeId = this.layout.nodeIds[ordinal] ?? `ordinal:${ordinal}`;
      const x = this.layout.x[ordinal];
      const y = this.layout.y[ordinal];
      if (!Number.isFinite(x) || !Number.isFinite(y)) {
        skippedNodeCount += 1;
        rebuildDiagnostics.push(Object.freeze({
          code: "SKIPPED_NON_FINITE_COORDINATE",
          message: `Skipped ${nodeId}: layout coordinate is not finite.`,
          nodeId,
          ordinal,
        }));
        continue;
      }

      const cellX = Math.floor(x / this.cellSize);
      const cellY = Math.floor(y / this.cellSize);
      const entry = Object.freeze({ nodeId, ordinal, x, y, cellX, cellY });
      const key = cellKey(cellX, cellY);
      const entries = mutableCells.get(key);
      if (entries) entries.push(entry);
      else mutableCells.set(key, [entry]);
      indexedNodeCount += 1;
    }

    const nextCells = new Map<string, readonly PermissionsGraphSpatialEntry[]>();
    for (const [key, entries] of Array.from(mutableCells.entries()).sort((left, right) =>
      compareStrings(left[0], right[0])
    )) {
      entries.sort(compareEntries);
      nextCells.set(key, Object.freeze(entries));
    }

    this.cells = nextCells;
    this._layoutGeneration = this.layout.layoutGeneration;
    this._coordinateRevision = this.layout.coordinateRevision;
    this._indexedNodeCount = indexedNodeCount;
    this._skippedNodeCount = skippedNodeCount;
    this._rebuildCount += 1;
    this.diagnostics = Object.freeze(rebuildDiagnostics);
  }

  query(
    rawBounds: PermissionsGraphSpatialBounds,
    options: PermissionsGraphSpatialQueryOptions = {},
  ): readonly PermissionsGraphSpatialEntry[] {
    this.rebuildIfNeeded();
    const bounds = normalizeBounds(rawBounds, options.overscan ?? 0);
    if (!bounds) return EMPTY_ENTRIES;
    const maxResults = normalizeLimit(options.maxResults, Number.MAX_SAFE_INTEGER);
    if (maxResults === 0 || this.cells.size === 0) return EMPTY_ENTRIES;

    const minCellX = Math.floor(bounds.x1 / this.cellSize);
    const minCellY = Math.floor(bounds.y1 / this.cellSize);
    const maxCellX = Math.floor(bounds.x2 / this.cellSize);
    const maxCellY = Math.floor(bounds.y2 / this.cellSize);
    const spanX = maxCellX - minCellX + 1;
    const spanY = maxCellY - minCellY + 1;
    const requestedCellCount = spanX > 0 && spanY > 0 && spanX <= Number.MAX_SAFE_INTEGER / spanY
      ? spanX * spanY
      : Number.POSITIVE_INFINITY;
    const candidates: PermissionsGraphSpatialEntry[] = [];

    if (requestedCellCount <= this.cells.size * 4 + 1_024) {
      for (let cellY = minCellY; cellY <= maxCellY; cellY += 1) {
        for (let cellX = minCellX; cellX <= maxCellX; cellX += 1) {
          const entries = this.cells.get(cellKey(cellX, cellY));
          if (entries) candidates.push(...entries);
        }
      }
    } else {
      for (const entries of this.cells.values()) candidates.push(...entries);
    }

    const matches = candidates
      .filter((entry) => pointInBounds(entry, bounds))
      .sort(compareEntries)
      .slice(0, maxResults);
    return Object.freeze(matches);
  }

  nearest(
    point: PermissionsGraphCoordinate,
    maxDistance: number,
  ): PermissionsGraphNearestNodeResult | null {
    this.rebuildIfNeeded();
    if (!Number.isFinite(point.x) || !Number.isFinite(point.y)) return null;
    if ((!Number.isFinite(maxDistance) && maxDistance !== Number.POSITIVE_INFINITY) || maxDistance < 0) {
      return null;
    }

    const candidates = maxDistance === Number.POSITIVE_INFINITY
      ? Array.from(this.cells.values()).flat()
      : this.query({
          x1: point.x - maxDistance,
          y1: point.y - maxDistance,
          x2: point.x + maxDistance,
          y2: point.y + maxDistance,
        });
    const maxDistanceSquared = maxDistance === Number.POSITIVE_INFINITY
      ? Number.POSITIVE_INFINITY
      : maxDistance * maxDistance;
    let best: PermissionsGraphSpatialEntry | null = null;
    let bestDistanceSquared = Number.POSITIVE_INFINITY;

    for (const candidate of candidates) {
      const dx = candidate.x - point.x;
      const dy = candidate.y - point.y;
      const distanceSquared = dx * dx + dy * dy;
      if (distanceSquared > maxDistanceSquared) continue;
      if (
        distanceSquared < bestDistanceSquared ||
        (Object.is(distanceSquared, bestDistanceSquared) && best &&
          compareStrings(candidate.nodeId, best.nodeId) < 0)
      ) {
        best = candidate;
        bestDistanceSquared = distanceSquared;
      }
    }

    return best
      ? Object.freeze({
          nodeId: best.nodeId,
          ordinal: best.ordinal,
          x: best.x,
          y: best.y,
          distance: Math.sqrt(bestDistanceSquared),
        })
      : null;
  }
}

export function buildPermissionsGraphSpatialIndex(
  layout: PermissionsGraphLayoutStore,
  options: PermissionsGraphSpatialIndexOptions = {},
): PermissionsGraphSpatialIndex {
  return new PermissionsGraphSpatialIndex(layout, options);
}

export function expandPermissionsGraphSpatialBounds(
  rawBounds: PermissionsGraphSpatialBounds,
  margin: number,
): PermissionsGraphSpatialBounds | null {
  return normalizeBounds(rawBounds, margin);
}

function normalizeBounds(
  raw: PermissionsGraphSpatialBounds,
  rawMargin: number,
): PermissionsGraphSpatialBounds | null {
  const values = [raw.x1, raw.y1, raw.x2, raw.y2];
  if (values.some((value) => !Number.isFinite(value))) return null;
  const margin = Number.isFinite(rawMargin) ? Math.max(0, rawMargin) : 0;
  return Object.freeze({
    x1: Math.min(raw.x1, raw.x2) - margin,
    y1: Math.min(raw.y1, raw.y2) - margin,
    x2: Math.max(raw.x1, raw.x2) + margin,
    y2: Math.max(raw.y1, raw.y2) + margin,
  });
}

function pointInBounds(
  point: PermissionsGraphCoordinate,
  bounds: PermissionsGraphSpatialBounds,
): boolean {
  return point.x >= bounds.x1 && point.x <= bounds.x2 &&
    point.y >= bounds.y1 && point.y <= bounds.y2;
}

function normalizeLimit(value: number | undefined, fallback: number): number {
  if (value === undefined) return fallback;
  if (!Number.isFinite(value)) return value === Number.POSITIVE_INFINITY ? fallback : 0;
  return Math.max(0, Math.floor(value));
}

function cellKey(cellX: number, cellY: number): string {
  return `${cellX},${cellY}`;
}

function compareEntries(
  left: PermissionsGraphSpatialEntry,
  right: PermissionsGraphSpatialEntry,
): number {
  return compareStrings(left.nodeId, right.nodeId) || left.ordinal - right.ordinal;
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
