import { worldToPermissionsGraphRenderedPoint } from "./permissions-graph-camera";
import { PERMISSIONS_GRAPH_OVERVIEW_DYNAMIC_FLAG } from "./permissions-graph-overview-buffers";
import { PERMISSIONS_GRAPH_OVERVIEW_EDGE_STYLE_FLAG } from "./permissions-graph-overview-edges";
import type { PermissionsGraphOverviewPalette } from "./permissions-graph-overview-palette";
import {
  applyPermissionsGraphOverviewCanvasSize,
  type PermissionsGraphOverviewBackendRenderer,
  type PermissionsGraphOverviewRenderInput,
  type PermissionsGraphOverviewRenderResult,
  type PermissionsGraphOverviewResizeInput,
  type PermissionsGraphOverviewNormalizedResize,
  validatePermissionsGraphOverviewRenderInput,
} from "./permissions-graph-overview-renderer";

export interface PermissionsGraphOverviewCanvasRendererOptions {
  readonly canvas: HTMLCanvasElement;
  readonly palette: PermissionsGraphOverviewPalette;
}

export function createPermissionsGraphOverviewCanvasRenderer(
  options: PermissionsGraphOverviewCanvasRendererOptions,
): PermissionsGraphOverviewBackendRenderer {
  const context = options.canvas.getContext("2d");
  if (!context) throw new Error("Canvas 2D overview context is unavailable.");
  return new CanvasPermissionsGraphOverviewRenderer(options.canvas, context, options.palette);
}

class CanvasPermissionsGraphOverviewRenderer implements PermissionsGraphOverviewBackendRenderer {
  readonly backend = "canvas2d" as const;
  private destroyed = false;
  private lastResize: PermissionsGraphOverviewNormalizedResize | null = null;

  constructor(
    readonly canvas: HTMLCanvasElement,
    private context: CanvasRenderingContext2D | null,
    private palette: PermissionsGraphOverviewPalette,
  ) {}

  resize(input: PermissionsGraphOverviewResizeInput): PermissionsGraphOverviewNormalizedResize {
    this.assertLive();
    const normalized = applyPermissionsGraphOverviewCanvasSize(this.canvas, input);
    this.lastResize = normalized;
    return normalized;
  }

  updateTheme(palette: PermissionsGraphOverviewPalette): void {
    this.assertLive();
    this.palette = palette;
  }

  render(input: PermissionsGraphOverviewRenderInput): PermissionsGraphOverviewRenderResult {
    this.assertLive();
    validatePermissionsGraphOverviewRenderInput(input);
    const context = this.context as CanvasRenderingContext2D;
    const viewport = this.resize(input);
    let drawablePointCount = 0;
    let drawableEdgeSegmentCount = 0;
    context.setTransform(viewport.pixelRatio, 0, 0, viewport.pixelRatio, 0, 0);
    if (input.clear !== false) context.clearRect(0, 0, viewport.width, viewport.height);
    if (viewport.width === 0 || viewport.height === 0) {
      return result(input, drawablePointCount, drawableEdgeSegmentCount, viewport);
    }

    if (input.edges) {
      for (let index = 0; index < input.edges.emittedSegmentCount; index += 1) {
        const offset = index * 4;
        const from = worldToPermissionsGraphRenderedPoint({
          x: input.edges.segmentCoordinates[offset] ?? 0,
          y: input.edges.segmentCoordinates[offset + 1] ?? 0,
        }, input.camera);
        const to = worldToPermissionsGraphRenderedPoint({
          x: input.edges.segmentCoordinates[offset + 2] ?? 0,
          y: input.edges.segmentCoordinates[offset + 3] ?? 0,
        }, input.camera);
        if (
          Math.max(from.x, to.x) < 0 || Math.max(from.y, to.y) < 0 ||
          Math.min(from.x, to.x) > viewport.width || Math.min(from.y, to.y) > viewport.height
        ) continue;
        const style = input.edges.segmentStyles[index] ?? 0;
        const weight = input.edges.segmentWeights[index] ?? 1;
        const priority = (style & PERMISSIONS_GRAPH_OVERVIEW_EDGE_STYLE_FLAG.priority) !== 0;
        const bundle = (style & PERMISSIONS_GRAPH_OVERVIEW_EDGE_STYLE_FLAG.bundle) !== 0;
        const density = (style & PERMISSIONS_GRAPH_OVERVIEW_EDGE_STYLE_FLAG.density) !== 0;
        context.strokeStyle = priority
          ? this.palette.selected
          : bundle ? this.palette.aggregate : this.palette.unknown;
        context.globalAlpha = priority ? 0.85 : density ? 0.18 : bundle ? 0.35 : 0.28;
        context.lineWidth = Math.min(3, 1 + Math.log2(Math.max(1, weight)) * 0.25);
        context.beginPath();
        context.moveTo(from.x, from.y);
        context.lineTo(to.x, to.y);
        context.stroke();
        drawableEdgeSegmentCount += 1;
      }
      context.globalAlpha = 1;
      context.lineWidth = 1;
    }

    const dynamicFlags = input.buffers.dynamicFlags;
    for (let ordinal = 0; ordinal < input.buffers.nodeCount; ordinal += 1) {
      const point = worldToPermissionsGraphRenderedPoint({
        x: input.buffers.positions[ordinal * 2] ?? 0,
        y: input.buffers.positions[ordinal * 2 + 1] ?? 0,
      }, input.camera);
      const size = input.buffers.pointSizes[ordinal] ?? 2;
      const radius = size / 2;
      if (
        point.x + radius < 0 || point.y + radius < 0 ||
        point.x - radius > viewport.width || point.y - radius > viewport.height
      ) continue;

      const flags = dynamicFlags?.[ordinal] ?? 0;
      if ((flags & PERMISSIONS_GRAPH_OVERVIEW_DYNAMIC_FLAG.dragSuppressed) !== 0) continue;
      const selected = (flags & PERMISSIONS_GRAPH_OVERVIEW_DYNAMIC_FLAG.selected) !== 0;
      const focused = (flags & PERMISSIONS_GRAPH_OVERVIEW_DYNAMIC_FLAG.focused) !== 0;
      const hovered = (flags & PERMISSIONS_GRAPH_OVERVIEW_DYNAMIC_FLAG.hovered) !== 0;
      const materialized = (flags & PERMISSIONS_GRAPH_OVERVIEW_DYNAMIC_FLAG.materialized) !== 0;
      if (selected || focused || hovered || materialized) {
        drawHalo(
          context,
          point.x,
          point.y,
          radius + (selected || focused || hovered ? 3 : 2),
          selected || focused ? this.palette.selected : this.palette.materialized,
        );
      }
      drawPoint(
        context,
        point.x,
        point.y,
        size,
        input.buffers.visualTokens[ordinal] ?? 0,
        pointColor(input.buffers.visualTokens[ordinal] ?? 0, this.palette),
      );
      drawablePointCount += 1;
    }
    return result(input, drawablePointCount, drawableEdgeSegmentCount, viewport);
  }

  destroy(): void {
    if (this.destroyed) return;
    this.destroyed = true;
    this.context = null;
    this.lastResize = null;
  }

  private assertLive(): void {
    if (this.destroyed || !this.context) throw new Error("Canvas overview renderer is destroyed.");
  }
}

function result(
  input: PermissionsGraphOverviewRenderInput,
  drawablePointCount: number,
  drawableEdgeSegmentCount: number,
  viewport: PermissionsGraphOverviewNormalizedResize,
): PermissionsGraphOverviewRenderResult {
  return Object.freeze({
    backend: "canvas2d",
    overviewNodeCount: input.buffers.nodeCount,
    drawablePointCount,
    overviewEdgeSegmentCount: input.edges?.emittedSegmentCount ?? 0,
    drawableEdgeSegmentCount,
    uploadedBytes: 0,
    viewport,
  });
}

function drawHalo(
  context: CanvasRenderingContext2D,
  x: number,
  y: number,
  radius: number,
  color: string,
): void {
  context.beginPath();
  context.arc(x, y, radius, 0, Math.PI * 2);
  context.fillStyle = color;
  context.fill();
}

function drawPoint(
  context: CanvasRenderingContext2D,
  x: number,
  y: number,
  size: number,
  token: number,
  color: string,
): void {
  const half = size / 2;
  context.fillStyle = color;
  context.beginPath();
  if (token === 3) {
    context.rect(x - half, y - half, size, size);
  } else if (token === 5 || token === 6) {
    context.moveTo(x, y - half);
    context.lineTo(x + half, y);
    context.lineTo(x, y + half);
    context.lineTo(x - half, y);
    context.closePath();
  } else {
    context.arc(x, y, half, 0, Math.PI * 2);
  }
  context.fill();
}

function pointColor(token: number, palette: PermissionsGraphOverviewPalette): string {
  switch (token) {
    case 1: return palette.user;
    case 2: return palette.file;
    case 3: return palette.folder;
    case 4: return palette.vault;
    case 5: return palette.group;
    case 6: return palette.aggregate;
    default: return palette.unknown;
  }
}
