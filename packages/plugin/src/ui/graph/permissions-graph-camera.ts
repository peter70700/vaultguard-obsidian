/**
 * Renderer-independent camera math for the Permissions Graph.
 *
 * Camera pan is a rendered-space translation in logical (CSS) pixels:
 *
 *   rendered = world * zoom + pan
 *   world = (rendered - pan) / zoom
 *
 * Device-pixel scaling is deliberately separate and requires an explicit
 * numeric pixel ratio. This module has no renderer, browser, or runtime state.
 */

export const PERMISSIONS_GRAPH_CAMERA_TRANSFORM_VERSION = 1;

export const PERMISSIONS_GRAPH_CAMERA_MIN_ZOOM = 0.000_001;
export const PERMISSIONS_GRAPH_CAMERA_MAX_ZOOM = 1_000_000;
export const DEFAULT_PERMISSIONS_GRAPH_CAMERA_MIN_ZOOM = 0.1;
export const DEFAULT_PERMISSIONS_GRAPH_CAMERA_MAX_ZOOM = 3;
export const PERMISSIONS_GRAPH_CAMERA_MAX_COORDINATE_MAGNITUDE = 1_000_000_000_000;
export const PERMISSIONS_GRAPH_CAMERA_MAX_VIEWPORT_DIMENSION = 1_000_000;
export const PERMISSIONS_GRAPH_CAMERA_MAX_PIXEL_RATIO = 16;
export const DEFAULT_PERMISSIONS_GRAPH_CAMERA_MAX_PIXEL_RATIO = 4;
export const PERMISSIONS_GRAPH_CAMERA_MAX_REVISION = 0xffff_ffff;

export interface PermissionsGraphPoint {
  readonly x: number;
  readonly y: number;
}

export interface PermissionsGraphCameraState {
  /** Rendered-space x translation in logical pixels. */
  readonly panX: number;
  /** Rendered-space y translation in logical pixels. */
  readonly panY: number;
  /** Rendered logical pixels per world-coordinate unit. */
  readonly zoom: number;
  /** Unsigned 32-bit invalidation revision. */
  readonly revision: number;
}

export interface PermissionsGraphViewport {
  /** Logical rendered width. Zero is valid during lifecycle transitions. */
  readonly width: number;
  /** Logical rendered height. Zero is valid during lifecycle transitions. */
  readonly height: number;
}

export interface PermissionsGraphZoomLimits {
  readonly minZoom: number;
  readonly maxZoom: number;
}

export interface PermissionsGraphWorldBoundsInput {
  readonly minX: number;
  readonly minY: number;
  readonly maxX: number;
  readonly maxY: number;
}

export interface PermissionsGraphWorldBounds extends PermissionsGraphWorldBoundsInput {
  readonly width: number;
  readonly height: number;
}

/** Structural match for the Phase 5 spatial viewport contract. */
export interface PermissionsGraphCameraSpatialBounds {
  readonly x1: number;
  readonly y1: number;
  readonly x2: number;
  readonly y2: number;
}

export type PermissionsGraphCameraErrorCode =
  | "INVALID_BOUNDS"
  | "INVALID_CAMERA"
  | "INVALID_COORDINATE"
  | "INVALID_OVERSCAN"
  | "INVALID_PIXEL_RATIO"
  | "INVALID_VIEWPORT"
  | "INVALID_ZOOM"
  | "INVALID_ZOOM_LIMITS"
  | "NUMERIC_OVERFLOW";

export class PermissionsGraphCameraError extends Error {
  constructor(
    readonly code: PermissionsGraphCameraErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "PermissionsGraphCameraError";
  }
}

const DEFAULT_ZOOM_LIMITS: PermissionsGraphZoomLimits = Object.freeze({
  minZoom: DEFAULT_PERMISSIONS_GRAPH_CAMERA_MIN_ZOOM,
  maxZoom: DEFAULT_PERMISSIONS_GRAPH_CAMERA_MAX_ZOOM,
});

export function createPermissionsGraphCameraState(
  input: Partial<PermissionsGraphCameraState> = {},
): PermissionsGraphCameraState {
  const state = {
    panX: normalizeZero(input.panX ?? 0),
    panY: normalizeZero(input.panY ?? 0),
    zoom: normalizeZero(input.zoom ?? 1),
    revision: input.revision ?? 0,
  };
  assertCameraState(state);
  return Object.freeze(state);
}

export function createPermissionsGraphViewport(
  width: number,
  height: number,
): PermissionsGraphViewport {
  const viewport = { width: normalizeZero(width), height: normalizeZero(height) };
  assertViewport(viewport);
  return Object.freeze(viewport);
}

export function clampPermissionsGraphZoom(
  requestedZoom: number,
  limits: PermissionsGraphZoomLimits = DEFAULT_ZOOM_LIMITS,
): number {
  assertRequestedZoom(requestedZoom);
  assertZoomLimits(limits);
  return Math.min(limits.maxZoom, Math.max(limits.minZoom, requestedZoom));
}

export function worldToPermissionsGraphRenderedPoint(
  point: PermissionsGraphPoint,
  camera: PermissionsGraphCameraState,
): PermissionsGraphPoint {
  assertPoint(point, "world point");
  assertCameraState(camera);
  return pointResult(
    checkedResult(point.x * camera.zoom + camera.panX, "rendered x"),
    checkedResult(point.y * camera.zoom + camera.panY, "rendered y"),
  );
}

export function renderedToPermissionsGraphWorldPoint(
  point: PermissionsGraphPoint,
  camera: PermissionsGraphCameraState,
): PermissionsGraphPoint {
  assertPoint(point, "rendered point");
  assertCameraState(camera);
  return pointResult(
    checkedResult((point.x - camera.panX) / camera.zoom, "world x"),
    checkedResult((point.y - camera.panY) / camera.zoom, "world y"),
  );
}

/** Move rendered content by a logical-pixel delta. */
export function panPermissionsGraphCameraByRenderedDelta(
  camera: PermissionsGraphCameraState,
  renderedDelta: PermissionsGraphPoint,
): PermissionsGraphCameraState {
  assertCameraState(camera);
  assertPoint(renderedDelta, "rendered pan delta");
  return updateCamera(
    camera,
    checkedResult(camera.panX + renderedDelta.x, "pan x"),
    checkedResult(camera.panY + renderedDelta.y, "pan y"),
    camera.zoom,
  );
}

/**
 * Move the viewport through world space. A positive x delta reveals world
 * coordinates to the right, so the rendered-space pan translation decreases.
 */
export function movePermissionsGraphViewportByWorldDelta(
  camera: PermissionsGraphCameraState,
  worldDelta: PermissionsGraphPoint,
): PermissionsGraphCameraState {
  assertCameraState(camera);
  assertPoint(worldDelta, "world viewport delta");
  return updateCamera(
    camera,
    checkedResult(camera.panX - worldDelta.x * camera.zoom, "pan x"),
    checkedResult(camera.panY - worldDelta.y * camera.zoom, "pan y"),
    camera.zoom,
  );
}

export function setPermissionsGraphCameraRenderedPan(
  camera: PermissionsGraphCameraState,
  renderedPan: PermissionsGraphPoint,
): PermissionsGraphCameraState {
  assertCameraState(camera);
  assertPoint(renderedPan, "rendered pan");
  return updateCamera(camera, renderedPan.x, renderedPan.y, camera.zoom);
}

export function zoomPermissionsGraphCameraAtRenderedAnchor(
  camera: PermissionsGraphCameraState,
  requestedZoom: number,
  renderedAnchor: PermissionsGraphPoint,
  limits: PermissionsGraphZoomLimits = DEFAULT_ZOOM_LIMITS,
): PermissionsGraphCameraState {
  assertCameraState(camera);
  assertPoint(renderedAnchor, "rendered zoom anchor");
  const nextZoom = clampPermissionsGraphZoom(requestedZoom, limits);
  if (nextZoom === camera.zoom) return camera;

  const worldAnchor = renderedToPermissionsGraphWorldPoint(renderedAnchor, camera);
  return updateCamera(
    camera,
    checkedResult(renderedAnchor.x - worldAnchor.x * nextZoom, "zoomed pan x"),
    checkedResult(renderedAnchor.y - worldAnchor.y * nextZoom, "zoomed pan y"),
    nextZoom,
  );
}

export function zoomPermissionsGraphCameraAtViewportCenter(
  camera: PermissionsGraphCameraState,
  requestedZoom: number,
  viewport: PermissionsGraphViewport,
  limits: PermissionsGraphZoomLimits = DEFAULT_ZOOM_LIMITS,
): PermissionsGraphCameraState {
  assertViewport(viewport);
  return zoomPermissionsGraphCameraAtRenderedAnchor(
    camera,
    requestedZoom,
    { x: viewport.width / 2, y: viewport.height / 2 },
    limits,
  );
}

export function normalizePermissionsGraphWorldBounds(
  input: PermissionsGraphWorldBoundsInput,
): PermissionsGraphWorldBounds {
  assertBoundsInput(input);
  const minX = Math.min(input.minX, input.maxX);
  const minY = Math.min(input.minY, input.maxY);
  const maxX = Math.max(input.minX, input.maxX);
  const maxY = Math.max(input.minY, input.maxY);
  return boundsResult(minX, minY, maxX, maxY);
}

export function calculatePermissionsGraphViewportWorldBounds(
  camera: PermissionsGraphCameraState,
  viewport: PermissionsGraphViewport,
): PermissionsGraphWorldBounds {
  assertCameraState(camera);
  assertViewport(viewport);
  const first = renderedToPermissionsGraphWorldPoint({ x: 0, y: 0 }, camera);
  const second = renderedToPermissionsGraphWorldPoint(
    { x: viewport.width, y: viewport.height },
    camera,
  );
  return normalizePermissionsGraphWorldBounds({
    minX: first.x,
    minY: first.y,
    maxX: second.x,
    maxY: second.y,
  });
}

export function overscanPermissionsGraphWorldBoundsByRenderedPixels(
  bounds: PermissionsGraphWorldBoundsInput,
  camera: PermissionsGraphCameraState,
  renderedPixelOverscan: number,
): PermissionsGraphWorldBounds {
  assertCameraState(camera);
  assertNonNegativeFinite(renderedPixelOverscan, "rendered-pixel overscan", "INVALID_OVERSCAN");
  const normalized = normalizePermissionsGraphWorldBounds(bounds);
  const worldMargin = renderedPixelOverscan / camera.zoom;
  return expandPermissionsGraphWorldBoundsByWorldUnits(normalized, worldMargin);
}

export function expandPermissionsGraphWorldBoundsByWorldUnits(
  bounds: PermissionsGraphWorldBoundsInput,
  worldUnitOverscan: number,
): PermissionsGraphWorldBounds {
  assertNonNegativeFinite(worldUnitOverscan, "world-unit overscan", "INVALID_OVERSCAN");
  const normalized = normalizePermissionsGraphWorldBounds(bounds);
  return boundsResult(
    checkedResult(normalized.minX - worldUnitOverscan, "overscan minimum x"),
    checkedResult(normalized.minY - worldUnitOverscan, "overscan minimum y"),
    checkedResult(normalized.maxX + worldUnitOverscan, "overscan maximum x"),
    checkedResult(normalized.maxY + worldUnitOverscan, "overscan maximum y"),
  );
}

export function toPermissionsGraphCameraSpatialBounds(
  bounds: PermissionsGraphWorldBoundsInput,
): PermissionsGraphCameraSpatialBounds {
  const normalized = normalizePermissionsGraphWorldBounds(bounds);
  return Object.freeze({
    x1: normalized.minX,
    y1: normalized.minY,
    x2: normalized.maxX,
    y2: normalized.maxY,
  });
}

export function clampPermissionsGraphPixelRatio(
  requestedPixelRatio: number,
  maximumPixelRatio = DEFAULT_PERMISSIONS_GRAPH_CAMERA_MAX_PIXEL_RATIO,
): number {
  assertPixelRatio(requestedPixelRatio, "requested pixel ratio");
  assertPixelRatio(maximumPixelRatio, "maximum pixel ratio");
  return Math.min(requestedPixelRatio, maximumPixelRatio);
}

export function permissionsGraphRenderedPointToDevicePixels(
  renderedPoint: PermissionsGraphPoint,
  pixelRatio: number,
): PermissionsGraphPoint {
  assertPoint(renderedPoint, "rendered point");
  assertPixelRatio(pixelRatio, "pixel ratio");
  return pointResult(
    checkedResult(renderedPoint.x * pixelRatio, "device x"),
    checkedResult(renderedPoint.y * pixelRatio, "device y"),
  );
}

export function permissionsGraphDevicePointToRenderedPixels(
  devicePoint: PermissionsGraphPoint,
  pixelRatio: number,
): PermissionsGraphPoint {
  assertPoint(devicePoint, "device point");
  assertPixelRatio(pixelRatio, "pixel ratio");
  return pointResult(
    checkedResult(devicePoint.x / pixelRatio, "rendered x"),
    checkedResult(devicePoint.y / pixelRatio, "rendered y"),
  );
}

/**
 * Deterministic redraw/recalculation identity. Including a viewport makes the
 * key suitable for world-bounds and materialization replanning; omitting it is
 * suitable for camera-only overview invalidation.
 */
export function createPermissionsGraphCameraInvalidationKey(
  camera: PermissionsGraphCameraState,
  viewport?: PermissionsGraphViewport,
): string {
  assertCameraState(camera);
  if (viewport) assertViewport(viewport);
  const viewportPart = viewport
    ? `|v:${canonicalNumber(viewport.width)},${canonicalNumber(viewport.height)}`
    : "";
  return `pg-camera-v${PERMISSIONS_GRAPH_CAMERA_TRANSFORM_VERSION}|r:${camera.revision}|p:${canonicalNumber(camera.panX)},${canonicalNumber(camera.panY)}|z:${canonicalNumber(camera.zoom)}${viewportPart}`;
}

function updateCamera(
  camera: PermissionsGraphCameraState,
  rawPanX: number,
  rawPanY: number,
  rawZoom: number,
): PermissionsGraphCameraState {
  const panX = normalizeZero(rawPanX);
  const panY = normalizeZero(rawPanY);
  const zoom = normalizeZero(rawZoom);
  assertCoordinate(panX, "camera pan x");
  assertCoordinate(panY, "camera pan y");
  assertCameraZoom(zoom);
  if (panX === camera.panX && panY === camera.panY && zoom === camera.zoom) return camera;
  return Object.freeze({
    panX,
    panY,
    zoom,
    revision: incrementRevision(camera.revision),
  });
}

function assertCameraState(camera: PermissionsGraphCameraState): void {
  if (!camera || typeof camera !== "object") {
    throw cameraError("INVALID_CAMERA", "Permissions graph camera state is required.");
  }
  assertCoordinate(camera.panX, "camera pan x", "INVALID_CAMERA");
  assertCoordinate(camera.panY, "camera pan y", "INVALID_CAMERA");
  assertCameraZoom(camera.zoom);
  if (
    !Number.isInteger(camera.revision)
    || camera.revision < 0
    || camera.revision > PERMISSIONS_GRAPH_CAMERA_MAX_REVISION
  ) {
    throw cameraError("INVALID_CAMERA", "Permissions graph camera revision must be a Uint32 value.");
  }
}

function assertCameraZoom(zoom: number): void {
  if (
    !Number.isFinite(zoom)
    || zoom < PERMISSIONS_GRAPH_CAMERA_MIN_ZOOM
    || zoom > PERMISSIONS_GRAPH_CAMERA_MAX_ZOOM
  ) {
    throw cameraError(
      "INVALID_ZOOM",
      `Permissions graph camera zoom must be between ${PERMISSIONS_GRAPH_CAMERA_MIN_ZOOM} and ${PERMISSIONS_GRAPH_CAMERA_MAX_ZOOM}.`,
    );
  }
}

function assertRequestedZoom(zoom: number): void {
  if (!Number.isFinite(zoom) || zoom <= 0) {
    throw cameraError("INVALID_ZOOM", "Requested permissions graph zoom must be finite and positive.");
  }
}

function assertZoomLimits(limits: PermissionsGraphZoomLimits): void {
  if (
    !limits
    || !Number.isFinite(limits.minZoom)
    || !Number.isFinite(limits.maxZoom)
    || limits.minZoom < PERMISSIONS_GRAPH_CAMERA_MIN_ZOOM
    || limits.maxZoom > PERMISSIONS_GRAPH_CAMERA_MAX_ZOOM
    || limits.minZoom > limits.maxZoom
  ) {
    throw cameraError("INVALID_ZOOM_LIMITS", "Permissions graph zoom limits are invalid.");
  }
}

function assertViewport(viewport: PermissionsGraphViewport): void {
  if (
    !viewport
    || !Number.isFinite(viewport.width)
    || !Number.isFinite(viewport.height)
    || viewport.width < 0
    || viewport.height < 0
    || viewport.width > PERMISSIONS_GRAPH_CAMERA_MAX_VIEWPORT_DIMENSION
    || viewport.height > PERMISSIONS_GRAPH_CAMERA_MAX_VIEWPORT_DIMENSION
  ) {
    throw cameraError(
      "INVALID_VIEWPORT",
      "Permissions graph viewport dimensions must be finite, non-negative, and within the supported limit.",
    );
  }
}

function assertPoint(point: PermissionsGraphPoint, label: string): void {
  if (!point || typeof point !== "object") {
    throw cameraError("INVALID_COORDINATE", `${label} is required.`);
  }
  assertCoordinate(point.x, `${label} x`);
  assertCoordinate(point.y, `${label} y`);
}

function assertCoordinate(
  value: number,
  label: string,
  code: PermissionsGraphCameraErrorCode = "INVALID_COORDINATE",
): void {
  if (
    !Number.isFinite(value)
    || Math.abs(value) > PERMISSIONS_GRAPH_CAMERA_MAX_COORDINATE_MAGNITUDE
  ) {
    throw cameraError(code, `${label} is outside the supported finite coordinate range.`);
  }
}

function assertBoundsInput(input: PermissionsGraphWorldBoundsInput): void {
  if (!input || typeof input !== "object") {
    throw cameraError("INVALID_BOUNDS", "Permissions graph world bounds are required.");
  }
  for (const [label, value] of [
    ["minimum x", input.minX],
    ["minimum y", input.minY],
    ["maximum x", input.maxX],
    ["maximum y", input.maxY],
  ] as const) {
    assertCoordinate(value, `bounds ${label}`, "INVALID_BOUNDS");
  }
}

function assertNonNegativeFinite(
  value: number,
  label: string,
  code: PermissionsGraphCameraErrorCode,
): void {
  if (!Number.isFinite(value) || value < 0) {
    throw cameraError(code, `${label} must be finite and non-negative.`);
  }
}

function assertPixelRatio(value: number, label: string): void {
  if (!Number.isFinite(value) || value <= 0 || value > PERMISSIONS_GRAPH_CAMERA_MAX_PIXEL_RATIO) {
    throw cameraError(
      "INVALID_PIXEL_RATIO",
      `${label} must be positive and at most ${PERMISSIONS_GRAPH_CAMERA_MAX_PIXEL_RATIO}.`,
    );
  }
}

function checkedResult(value: number, label: string): number {
  if (
    !Number.isFinite(value)
    || Math.abs(value) > PERMISSIONS_GRAPH_CAMERA_MAX_COORDINATE_MAGNITUDE
  ) {
    throw cameraError("NUMERIC_OVERFLOW", `${label} exceeded the supported numeric range.`);
  }
  return normalizeZero(value);
}

function pointResult(x: number, y: number): PermissionsGraphPoint {
  return Object.freeze({ x: normalizeZero(x), y: normalizeZero(y) });
}

function boundsResult(
  minX: number,
  minY: number,
  maxX: number,
  maxY: number,
): PermissionsGraphWorldBounds {
  const width = checkedResult(maxX - minX, "bounds width");
  const height = checkedResult(maxY - minY, "bounds height");
  return Object.freeze({ minX, minY, maxX, maxY, width, height });
}

function incrementRevision(revision: number): number {
  return revision === PERMISSIONS_GRAPH_CAMERA_MAX_REVISION ? 0 : revision + 1;
}

function normalizeZero(value: number): number {
  return Object.is(value, -0) ? 0 : value;
}

function canonicalNumber(value: number): string {
  return String(normalizeZero(value));
}

function cameraError(
  code: PermissionsGraphCameraErrorCode,
  message: string,
): PermissionsGraphCameraError {
  return new PermissionsGraphCameraError(code, message);
}
