import type { PermissionsGraphCameraState } from "./permissions-graph-camera";
import {
  clampPermissionsGraphPixelRatio,
  createPermissionsGraphViewport,
} from "./permissions-graph-camera";
import type { PermissionsGraphOverviewBuffers } from "./permissions-graph-overview-buffers";
import type { PermissionsGraphOverviewEdgeSnapshot } from "./permissions-graph-overview-edges";
import type {
  PermissionsGraphOverviewPalette,
  PermissionsGraphOverviewTheme,
} from "./permissions-graph-overview-palette";
import { getPermissionsGraphOverviewPalette } from "./permissions-graph-overview-palette";
import { createPermissionsGraphOverviewCanvasRenderer } from "./permissions-graph-overview-canvas";
import { createPermissionsGraphOverviewWebglRenderer } from "./permissions-graph-overview-webgl";

export const PERMISSIONS_GRAPH_OVERVIEW_PHASE_C_MARKER = "vg-permissions-overview-phase-c-v1";
export const PERMISSIONS_GRAPH_OVERVIEW_MAX_BACKING_DIMENSION = 8_192;
export const PERMISSIONS_GRAPH_OVERVIEW_MAX_BACKING_PIXELS = 33_554_432;

export type PermissionsGraphOverviewBackend = "webgl2" | "canvas2d" | "unavailable";

export interface PermissionsGraphOverviewResizeInput {
  readonly width: number;
  readonly height: number;
  readonly pixelRatio: number;
}

export interface PermissionsGraphOverviewNormalizedResize extends PermissionsGraphOverviewResizeInput {
  readonly backingWidth: number;
  readonly backingHeight: number;
}

export interface PermissionsGraphOverviewRenderInput extends PermissionsGraphOverviewResizeInput {
  readonly buffers: PermissionsGraphOverviewBuffers;
  readonly edges?: PermissionsGraphOverviewEdgeSnapshot;
  readonly camera: PermissionsGraphCameraState;
  readonly theme: PermissionsGraphOverviewTheme;
  readonly clear?: boolean;
}

export interface PermissionsGraphOverviewRenderResult {
  readonly backend: PermissionsGraphOverviewBackend;
  readonly overviewNodeCount: number;
  readonly drawablePointCount: number;
  readonly overviewEdgeSegmentCount: number;
  readonly drawableEdgeSegmentCount: number;
  readonly uploadedBytes: number;
  readonly viewport: PermissionsGraphOverviewNormalizedResize;
}

export interface PermissionsGraphOverviewDiagnostics {
  readonly requestedBackendPolicy: "webgl2-then-canvas2d";
  readonly selectedBackend: PermissionsGraphOverviewBackend;
  readonly webglInitializationStatus: "not-attempted" | "ready" | "failed" | "lost";
  readonly canvasFallbackStatus: "not-attempted" | "ready" | "failed";
  readonly contextLossCount: number;
  readonly fallbackReason: string | null;
  readonly diagnostics: readonly string[];
  readonly destroyed: boolean;
}

export interface PermissionsGraphOverviewRenderer {
  readonly backend: PermissionsGraphOverviewBackend;
  readonly canvas: HTMLCanvasElement;
  render(input: PermissionsGraphOverviewRenderInput): PermissionsGraphOverviewRenderResult;
  resize(input: PermissionsGraphOverviewResizeInput): PermissionsGraphOverviewNormalizedResize;
  updateTheme(theme: PermissionsGraphOverviewTheme): void;
  getDiagnostics(): PermissionsGraphOverviewDiagnostics;
  destroy(): void;
}

export interface PermissionsGraphOverviewBackendRenderer {
  readonly backend: "webgl2" | "canvas2d";
  readonly canvas: HTMLCanvasElement;
  render(input: PermissionsGraphOverviewRenderInput): PermissionsGraphOverviewRenderResult;
  resize(input: PermissionsGraphOverviewResizeInput): PermissionsGraphOverviewNormalizedResize;
  updateTheme(palette: PermissionsGraphOverviewPalette): void;
  destroy(): void;
}

export interface PermissionsGraphOverviewRendererFactoryOptions {
  readonly canvas: HTMLCanvasElement;
  readonly createReplacementCanvas?: () => HTMLCanvasElement;
  readonly replaceCanvas?: (previous: HTMLCanvasElement, replacement: HTMLCanvasElement) => void;
  readonly onDiagnostic?: (message: string) => void;
}

export function normalizePermissionsGraphOverviewResize(
  input: PermissionsGraphOverviewResizeInput,
): PermissionsGraphOverviewNormalizedResize {
  const viewport = createPermissionsGraphViewport(input.width, input.height);
  let pixelRatio = clampPermissionsGraphPixelRatio(input.pixelRatio);
  const maxDimensionRatio = Math.min(
    1,
    viewport.width === 0 ? 1 : PERMISSIONS_GRAPH_OVERVIEW_MAX_BACKING_DIMENSION / (viewport.width * pixelRatio),
    viewport.height === 0 ? 1 : PERMISSIONS_GRAPH_OVERVIEW_MAX_BACKING_DIMENSION / (viewport.height * pixelRatio),
  );
  const rawPixels = viewport.width * viewport.height * pixelRatio * pixelRatio;
  const maxPixelRatio = rawPixels === 0
    ? 1
    : Math.min(1, Math.sqrt(PERMISSIONS_GRAPH_OVERVIEW_MAX_BACKING_PIXELS / rawPixels));
  pixelRatio *= Math.min(maxDimensionRatio, maxPixelRatio);
  const backingWidth = Math.max(0, Math.floor(viewport.width * pixelRatio));
  const backingHeight = Math.max(0, Math.floor(viewport.height * pixelRatio));
  return Object.freeze({
    width: viewport.width,
    height: viewport.height,
    pixelRatio,
    backingWidth,
    backingHeight,
  });
}

export function applyPermissionsGraphOverviewCanvasSize(
  canvas: HTMLCanvasElement,
  input: PermissionsGraphOverviewResizeInput,
): PermissionsGraphOverviewNormalizedResize {
  const normalized = normalizePermissionsGraphOverviewResize(input);
  if (canvas.width !== normalized.backingWidth) canvas.width = normalized.backingWidth;
  if (canvas.height !== normalized.backingHeight) canvas.height = normalized.backingHeight;
  return normalized;
}

export function createPermissionsGraphOverviewRenderer(
  options: PermissionsGraphOverviewRendererFactoryOptions,
): PermissionsGraphOverviewRenderer {
  return new SelectablePermissionsGraphOverviewRenderer(options);
}

class SelectablePermissionsGraphOverviewRenderer implements PermissionsGraphOverviewRenderer {
  private active: PermissionsGraphOverviewBackendRenderer | null = null;
  private currentCanvas: HTMLCanvasElement;
  private theme: PermissionsGraphOverviewTheme = "dark";
  private lastInput: PermissionsGraphOverviewRenderInput | null = null;
  private webglStatus: PermissionsGraphOverviewDiagnostics["webglInitializationStatus"] = "not-attempted";
  private canvasStatus: PermissionsGraphOverviewDiagnostics["canvasFallbackStatus"] = "not-attempted";
  private contextLossCount = 0;
  private fallbackReason: string | null = null;
  private readonly messages: string[] = [];
  private destroyed = false;

  constructor(private readonly options: PermissionsGraphOverviewRendererFactoryOptions) {
    this.currentCanvas = options.canvas;
    this.selectInitialBackend();
  }

  get backend(): PermissionsGraphOverviewBackend {
    return this.active?.backend ?? "unavailable";
  }

  get canvas(): HTMLCanvasElement {
    return this.currentCanvas;
  }

  render(input: PermissionsGraphOverviewRenderInput): PermissionsGraphOverviewRenderResult {
    this.assertLive();
    validatePermissionsGraphOverviewRenderInput(input);
    this.lastInput = input;
    this.theme = input.theme;
    if (!this.active) return unavailableResult(input);
    this.active.updateTheme(getPermissionsGraphOverviewPalette(input.theme));
    return this.active.render(input);
  }

  resize(input: PermissionsGraphOverviewResizeInput): PermissionsGraphOverviewNormalizedResize {
    this.assertLive();
    return this.active?.resize(input) ?? applyPermissionsGraphOverviewCanvasSize(this.currentCanvas, input);
  }

  updateTheme(theme: PermissionsGraphOverviewTheme): void {
    this.assertLive();
    this.theme = theme;
    this.active?.updateTheme(getPermissionsGraphOverviewPalette(theme));
    if (this.lastInput) this.render({ ...this.lastInput, theme });
  }

  getDiagnostics(): PermissionsGraphOverviewDiagnostics {
    return Object.freeze({
      requestedBackendPolicy: "webgl2-then-canvas2d",
      selectedBackend: this.backend,
      webglInitializationStatus: this.webglStatus,
      canvasFallbackStatus: this.canvasStatus,
      contextLossCount: this.contextLossCount,
      fallbackReason: this.fallbackReason,
      diagnostics: Object.freeze([...this.messages]),
      destroyed: this.destroyed,
    });
  }

  destroy(): void {
    if (this.destroyed) return;
    this.destroyed = true;
    this.active?.destroy();
    this.active = null;
    this.lastInput = null;
  }

  private selectInitialBackend(): void {
    this.webglStatus = "failed";
    try {
      this.active = createPermissionsGraphOverviewWebglRenderer({
        canvas: this.currentCanvas,
        palette: getPermissionsGraphOverviewPalette(this.theme),
        onContextLost: () => this.handleContextLoss(),
      });
      this.webglStatus = "ready";
      return;
    } catch (error) {
      this.fallbackReason = sanitizedReason(error, "WebGL2 initialization failed");
      this.record(this.fallbackReason);
    }
    this.activateCanvasFallback(this.fallbackReason ?? "WebGL2 unavailable");
  }

  private handleContextLoss(): void {
    if (this.destroyed || this.webglStatus === "lost") return;
    this.contextLossCount += 1;
    this.webglStatus = "lost";
    this.active?.destroy();
    this.active = null;
    this.activateCanvasFallback("WebGL2 context lost; stable Canvas 2D fallback selected");
    if (this.lastInput && this.active) this.render({ ...this.lastInput, theme: this.theme });
  }

  private activateCanvasFallback(reason: string): void {
    this.fallbackReason = reason;
    this.canvasStatus = "failed";
    const previous = this.currentCanvas;
    const replacement = this.options.createReplacementCanvas?.() ?? previous;
    try {
      const next = createPermissionsGraphOverviewCanvasRenderer({
        canvas: replacement,
        palette: getPermissionsGraphOverviewPalette(this.theme),
      });
      if (replacement !== previous) this.options.replaceCanvas?.(previous, replacement);
      this.currentCanvas = replacement;
      this.active = next;
      this.canvasStatus = "ready";
    } catch (error) {
      const message = sanitizedReason(error, "Canvas 2D initialization failed");
      this.record(message);
      this.active = null;
    }
  }

  private record(message: string): void {
    if (!this.messages.includes(message)) this.messages.push(message);
    this.options.onDiagnostic?.(message);
  }

  private assertLive(): void {
    if (this.destroyed) throw new Error("Permissions graph overview renderer is destroyed.");
  }
}

function unavailableResult(input: PermissionsGraphOverviewRenderInput): PermissionsGraphOverviewRenderResult {
  return Object.freeze({
    backend: "unavailable",
    overviewNodeCount: input.buffers.nodeCount,
    drawablePointCount: 0,
    overviewEdgeSegmentCount: input.edges?.emittedSegmentCount ?? 0,
    drawableEdgeSegmentCount: 0,
    uploadedBytes: 0,
    viewport: normalizePermissionsGraphOverviewResize(input),
  });
}

export function validatePermissionsGraphOverviewRenderInput(
  input: PermissionsGraphOverviewRenderInput,
): void {
  const edges = input.edges;
  if (!edges) return;
  if (
    edges.topologyFingerprint !== input.buffers.topologyFingerprint ||
    edges.layoutGeneration !== input.buffers.layoutGeneration ||
    edges.coordinateRevision !== input.buffers.coordinateRevision ||
    edges.cameraRevision !== input.camera.revision
  ) {
    throw new Error("Permissions graph overview edge snapshot identity does not match the render frame.");
  }
  if (
    edges.segmentCoordinates.length !== edges.emittedSegmentCount * 4 ||
    edges.segmentStyles.length !== edges.emittedSegmentCount ||
    edges.segmentWeights.length !== edges.emittedSegmentCount
  ) {
    throw new Error("Permissions graph overview edge snapshot array lengths are invalid.");
  }
  if (
    !Array.from(edges.segmentCoordinates).every(Number.isFinite) ||
    !Array.from(edges.segmentWeights).every((value) => Number.isFinite(value) && value > 0)
  ) {
    throw new Error("Permissions graph overview edge snapshot contains invalid numeric data.");
  }
}

function sanitizedReason(error: unknown, fallback: string): string {
  if (!(error instanceof Error)) return fallback;
  const normalized = error.message.replace(/[\r\n\t]+/g, " ").replace(/[^\x20-\x7e]/g, "?").slice(0, 160);
  return normalized || fallback;
}
