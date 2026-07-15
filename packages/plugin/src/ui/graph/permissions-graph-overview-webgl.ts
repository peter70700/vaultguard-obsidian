import type { PermissionsGraphOverviewPalette } from "./permissions-graph-overview-palette";
import {
  applyPermissionsGraphOverviewCanvasSize,
  PERMISSIONS_GRAPH_OVERVIEW_PHASE_C_MARKER,
  type PermissionsGraphOverviewBackendRenderer,
  type PermissionsGraphOverviewNormalizedResize,
  type PermissionsGraphOverviewRenderInput,
  type PermissionsGraphOverviewRenderResult,
  type PermissionsGraphOverviewResizeInput,
  validatePermissionsGraphOverviewRenderInput,
} from "./permissions-graph-overview-renderer";

export const PERMISSIONS_GRAPH_OVERVIEW_VERTEX_SHADER = `#version 300 es
// VG_PG_OVERVIEW_PHASE_C_VERTEX_V1
precision highp float;
in vec2 a_position;
in float a_pointSize;
in float a_visualToken;
in float a_dynamicFlags;
uniform vec2 u_pan;
uniform float u_zoom;
uniform vec2 u_viewport;
uniform float u_pixelRatio;
out float v_visualToken;
out float v_dynamicFlags;
void main() {
  vec2 rendered = a_position * u_zoom + u_pan;
  vec2 clip = vec2((rendered.x / u_viewport.x) * 2.0 - 1.0, 1.0 - (rendered.y / u_viewport.y) * 2.0);
  gl_Position = vec4(clip, 0.0, 1.0);
  int flags = int(a_dynamicFlags + 0.5);
  bool highlighted = (flags & 7) != 0;
  bool suppressed = (flags & 64) != 0;
  gl_PointSize = suppressed ? 1.0 : max(1.0, (a_pointSize + (highlighted ? 3.0 : 0.0)) * u_pixelRatio);
  v_visualToken = a_visualToken;
  v_dynamicFlags = a_dynamicFlags;
}`;

export const PERMISSIONS_GRAPH_OVERVIEW_FRAGMENT_SHADER = `#version 300 es
// VG_PG_OVERVIEW_PHASE_C_FRAGMENT_V1
precision highp float;
in float v_visualToken;
in float v_dynamicFlags;
uniform vec4 u_colors[9];
out vec4 outColor;
void main() {
  vec2 centered = gl_PointCoord - vec2(0.5);
  if (dot(centered, centered) > 0.25) discard;
  int token = int(v_visualToken + 0.5);
  int flags = int(v_dynamicFlags + 0.5);
  if ((flags & 64) != 0) discard;
  bool selected = (flags & 1) != 0;
  bool focused = (flags & 2) != 0;
  bool hovered = (flags & 4) != 0;
  bool materialized = (flags & 16) != 0;
  bool emphasized = selected || focused || hovered || materialized;
  int colorIndex = token >= 0 && token <= 6 ? token : 0;
  float edge = length(centered);
  int emphasisColor = selected || focused ? 8 : 7;
  outColor = emphasized && edge > 0.34 ? u_colors[emphasisColor] : u_colors[colorIndex];
}`;

export const PERMISSIONS_GRAPH_OVERVIEW_EDGE_VERTEX_SHADER = `#version 300 es
// VG_PG_OVERVIEW_PHASE_E_EDGE_VERTEX_V1
precision highp float;
in vec2 a_edgePosition;
in float a_edgeStyle;
uniform vec2 u_edgePan;
uniform float u_edgeZoom;
uniform vec2 u_edgeViewport;
out float v_edgeStyle;
void main() {
  vec2 rendered = a_edgePosition * u_edgeZoom + u_edgePan;
  vec2 clip = vec2((rendered.x / u_edgeViewport.x) * 2.0 - 1.0, 1.0 - (rendered.y / u_edgeViewport.y) * 2.0);
  gl_Position = vec4(clip, 0.0, 1.0);
  v_edgeStyle = a_edgeStyle;
}`;

export const PERMISSIONS_GRAPH_OVERVIEW_EDGE_FRAGMENT_SHADER = `#version 300 es
// VG_PG_OVERVIEW_PHASE_E_EDGE_FRAGMENT_V1
precision highp float;
in float v_edgeStyle;
uniform vec4 u_edgeColors[3];
out vec4 outColor;
void main() {
  int style = int(v_edgeStyle + 0.5);
  bool priority = (style & 128) != 0;
  bool bundle = (style & 256) != 0;
  outColor = priority ? u_edgeColors[1] : bundle ? u_edgeColors[2] : u_edgeColors[0];
}`;

export interface PermissionsGraphOverviewWebglRendererOptions {
  readonly canvas: HTMLCanvasElement;
  readonly palette: PermissionsGraphOverviewPalette;
  readonly onContextLost: () => void;
}

interface GlResources {
  readonly program: WebGLProgram;
  readonly vertexShader: WebGLShader;
  readonly fragmentShader: WebGLShader;
  readonly positions: WebGLBuffer;
  readonly pointSizes: WebGLBuffer;
  readonly visualTokens: WebGLBuffer;
  readonly dynamicFlags: WebGLBuffer;
  readonly edgeProgram: WebGLProgram;
  readonly edgeVertexShader: WebGLShader;
  readonly edgeFragmentShader: WebGLShader;
  readonly edgePositions: WebGLBuffer;
  readonly edgeStyles: WebGLBuffer;
  readonly locations: {
    readonly position: number;
    readonly pointSize: number;
    readonly visualToken: number;
    readonly dynamicFlags: number;
    readonly pan: WebGLUniformLocation;
    readonly zoom: WebGLUniformLocation;
    readonly viewport: WebGLUniformLocation;
    readonly pixelRatio: WebGLUniformLocation;
    readonly colors: WebGLUniformLocation;
  };
  readonly edgeLocations: {
    readonly position: number;
    readonly style: number;
    readonly pan: WebGLUniformLocation;
    readonly zoom: WebGLUniformLocation;
    readonly viewport: WebGLUniformLocation;
    readonly colors: WebGLUniformLocation;
  };
}

export function createPermissionsGraphOverviewWebglRenderer(
  options: PermissionsGraphOverviewWebglRendererOptions,
): PermissionsGraphOverviewBackendRenderer {
  const gl = options.canvas.getContext("webgl2", { alpha: true, antialias: false });
  if (!gl) throw new Error("WebGL2 overview context is unavailable.");
  return new WebglPermissionsGraphOverviewRenderer(options.canvas, gl, options.palette, options.onContextLost);
}

class WebglPermissionsGraphOverviewRenderer implements PermissionsGraphOverviewBackendRenderer {
  readonly backend = "webgl2" as const;
  private resources: GlResources | null = null;
  private destroyed = false;
  private contextLost = false;
  private uploadedFingerprint: string | null = null;
  private uploadedEdgeFingerprint: string | null = null;
  private uploadedStaticBuffers: {
    readonly positions: Float32Array;
    readonly pointSizes: Float32Array;
    readonly visualTokens: Uint8Array;
    readonly dynamicFlags: Uint8Array | undefined;
    readonly nodeCount: number;
  } | null = null;
  private uploadedBytes = 0;
  private readonly lostListener: EventListener;
  private readonly restoredListener: EventListener;

  constructor(
    readonly canvas: HTMLCanvasElement,
    private gl: WebGL2RenderingContext | null,
    private palette: PermissionsGraphOverviewPalette,
    onContextLost: () => void,
  ) {
    this.lostListener = (event) => {
      event.preventDefault();
      if (this.contextLost || this.destroyed) return;
      this.contextLost = true;
      this.resources = null;
      this.uploadedFingerprint = null;
      this.uploadedStaticBuffers = null;
      onContextLost();
    };
    this.restoredListener = () => {
      // Stable Canvas fallback remains authoritative after a loss.
    };
    canvas.addEventListener("webglcontextlost", this.lostListener);
    canvas.addEventListener("webglcontextrestored", this.restoredListener);
    try {
      this.resources = createResources(gl as WebGL2RenderingContext);
      this.uploadPalette();
    } catch (error) {
      this.releaseResources();
      canvas.removeEventListener("webglcontextlost", this.lostListener);
      canvas.removeEventListener("webglcontextrestored", this.restoredListener);
      this.gl = null;
      throw error;
    }
  }

  resize(input: PermissionsGraphOverviewResizeInput): PermissionsGraphOverviewNormalizedResize {
    this.assertLive();
    const normalized = applyPermissionsGraphOverviewCanvasSize(this.canvas, input);
    this.gl?.viewport(0, 0, normalized.backingWidth, normalized.backingHeight);
    return normalized;
  }

  updateTheme(palette: PermissionsGraphOverviewPalette): void {
    this.assertLive();
    this.palette = palette;
    this.uploadPalette();
  }

  render(input: PermissionsGraphOverviewRenderInput): PermissionsGraphOverviewRenderResult {
    this.assertLive();
    validatePermissionsGraphOverviewRenderInput(input);
    const gl = this.gl as WebGL2RenderingContext;
    const resources = this.resources as GlResources;
    const viewport = this.resize(input);
    if (viewport.width === 0 || viewport.height === 0) {
      return renderResult(input, 0, 0, this.uploadedBytes, viewport);
    }
    if (
      this.uploadedFingerprint !== input.buffers.bufferFingerprint ||
      this.uploadedEdgeFingerprint !== (input.edges?.bufferFingerprint ?? null)
    ) this.upload(input);

    if (input.clear !== false) {
      gl.clearColor(0, 0, 0, 0);
      gl.clear(gl.COLOR_BUFFER_BIT);
    }
    if (input.edges && input.edges.emittedSegmentCount > 0) {
      gl.useProgram(resources.edgeProgram);
      bindEdgeAttributes(gl, resources);
      gl.uniform2f(resources.edgeLocations.pan, input.camera.panX, input.camera.panY);
      gl.uniform1f(resources.edgeLocations.zoom, input.camera.zoom);
      gl.uniform2f(resources.edgeLocations.viewport, viewport.width, viewport.height);
      gl.drawArrays(gl.LINES, 0, input.edges.emittedSegmentCount * 2);
    }
    gl.useProgram(resources.program);
    bindPointAttributes(gl, resources);
    gl.uniform2f(resources.locations.pan, input.camera.panX, input.camera.panY);
    gl.uniform1f(resources.locations.zoom, input.camera.zoom);
    gl.uniform2f(resources.locations.viewport, viewport.width, viewport.height);
    gl.uniform1f(resources.locations.pixelRatio, viewport.pixelRatio);
    gl.drawArrays(gl.POINTS, 0, input.buffers.nodeCount);
    return renderResult(
      input,
      input.buffers.nodeCount,
      input.edges?.emittedSegmentCount ?? 0,
      this.uploadedBytes,
      viewport,
    );
  }

  destroy(): void {
    if (this.destroyed) return;
    this.destroyed = true;
    this.canvas.removeEventListener("webglcontextlost", this.lostListener);
    this.canvas.removeEventListener("webglcontextrestored", this.restoredListener);
    this.releaseResources();
    this.uploadedStaticBuffers = null;
    this.uploadedEdgeFingerprint = null;
    this.gl = null;
  }

  private upload(input: PermissionsGraphOverviewRenderInput): void {
    const gl = this.gl as WebGL2RenderingContext;
    const resources = this.resources as GlResources;
    const flags = input.buffers.dynamicFlags ?? new Uint8Array(input.buffers.nodeCount);
    const semanticBuffersMatch = this.uploadedStaticBuffers !== null &&
      this.uploadedStaticBuffers.pointSizes === input.buffers.pointSizes &&
      this.uploadedStaticBuffers.visualTokens === input.buffers.visualTokens &&
      this.uploadedStaticBuffers.nodeCount === input.buffers.nodeCount;
    const positionsMatch = this.uploadedStaticBuffers?.positions === input.buffers.positions;
    const dynamicFlagsMatch =
      this.uploadedStaticBuffers?.dynamicFlags === input.buffers.dynamicFlags;
    const canPatchCoordinates = semanticBuffersMatch &&
      input.buffers.update.kind === "coordinates";
    if (!semanticBuffersMatch || (!positionsMatch && !canPatchCoordinates)) {
      uploadAttribute(gl, resources.positions, resources.locations.position, 2, gl.FLOAT, input.buffers.positions);
      uploadAttribute(gl, resources.pointSizes, resources.locations.pointSize, 1, gl.FLOAT, input.buffers.pointSizes);
      uploadAttribute(gl, resources.visualTokens, resources.locations.visualToken, 1, gl.UNSIGNED_BYTE, input.buffers.visualTokens);
      uploadAttribute(gl, resources.dynamicFlags, resources.locations.dynamicFlags, 1, gl.UNSIGNED_BYTE, flags);
    } else {
      if (!positionsMatch) {
        uploadCoordinateRanges(
          gl,
          resources.positions,
          input.buffers.positions,
          input.buffers.update.ranges,
        );
      }
      if (!dynamicFlagsMatch) {
        if (input.buffers.update.kind === "dynamic" || input.buffers.update.kind === "coordinates") {
          uploadDynamicRanges(gl, resources.dynamicFlags, flags, input.buffers.update.ranges);
        } else {
          uploadAttribute(gl, resources.dynamicFlags, resources.locations.dynamicFlags, 1, gl.UNSIGNED_BYTE, flags);
        }
      }
    }
    this.uploadedStaticBuffers = {
      positions: input.buffers.positions,
      pointSizes: input.buffers.pointSizes,
      visualTokens: input.buffers.visualTokens,
      dynamicFlags: input.buffers.dynamicFlags,
      nodeCount: input.buffers.nodeCount,
    };
    this.uploadedBytes = input.buffers.positions.byteLength + input.buffers.pointSizes.byteLength +
      input.buffers.visualTokens.byteLength + flags.byteLength;
    this.uploadedFingerprint = input.buffers.bufferFingerprint;
    if (input.edges) {
      const expandedStyles = new Float32Array(input.edges.emittedSegmentCount * 2);
      for (let index = 0; index < input.edges.emittedSegmentCount; index += 1) {
        const style = input.edges.segmentStyles[index] ?? 0;
        expandedStyles[index * 2] = style;
        expandedStyles[index * 2 + 1] = style;
      }
      uploadAttribute(
        gl,
        resources.edgePositions,
        resources.edgeLocations.position,
        2,
        gl.FLOAT,
        input.edges.segmentCoordinates,
      );
      uploadAttribute(
        gl,
        resources.edgeStyles,
        resources.edgeLocations.style,
        1,
        gl.FLOAT,
        expandedStyles,
      );
      this.uploadedBytes += input.edges.segmentCoordinates.byteLength + expandedStyles.byteLength;
      this.uploadedEdgeFingerprint = input.edges.bufferFingerprint;
    } else {
      this.uploadedEdgeFingerprint = null;
    }
  }

  private uploadPalette(): void {
    if (!this.gl || !this.resources) return;
    const colors = [
      this.palette.unknown, this.palette.user, this.palette.file, this.palette.folder,
      this.palette.vault, this.palette.group, this.palette.aggregate,
      this.palette.materialized, this.palette.selected,
    ].flatMap(hexToRgba);
    this.gl.useProgram(this.resources.program);
    this.gl.uniform4fv(this.resources.locations.colors, new Float32Array(colors));
    const edgeColors = [
      [...hexToRgba(this.palette.unknown).slice(0, 3), 0.28],
      [...hexToRgba(this.palette.selected).slice(0, 3), 0.85],
      [...hexToRgba(this.palette.aggregate).slice(0, 3), 0.35],
    ].flat();
    this.gl.useProgram(this.resources.edgeProgram);
    this.gl.uniform4fv(this.resources.edgeLocations.colors, new Float32Array(edgeColors));
  }

  private releaseResources(): void {
    if (!this.gl || !this.resources) return;
    const {
      program, vertexShader, fragmentShader, positions, pointSizes, visualTokens, dynamicFlags,
      edgeProgram, edgeVertexShader, edgeFragmentShader, edgePositions, edgeStyles,
    } = this.resources;
    for (const buffer of [positions, pointSizes, visualTokens, dynamicFlags, edgePositions, edgeStyles]) {
      this.gl.deleteBuffer(buffer);
    }
    this.gl.deleteProgram(program);
    this.gl.deleteProgram(edgeProgram);
    this.gl.deleteShader(vertexShader);
    this.gl.deleteShader(fragmentShader);
    this.gl.deleteShader(edgeVertexShader);
    this.gl.deleteShader(edgeFragmentShader);
    this.resources = null;
  }

  private assertLive(): void {
    if (this.destroyed || this.contextLost || !this.gl || !this.resources) {
      throw new Error("WebGL2 overview renderer is unavailable.");
    }
  }
}

function createResources(gl: WebGL2RenderingContext): GlResources {
  let vertexShader: WebGLShader | null = null;
  let fragmentShader: WebGLShader | null = null;
  let edgeVertexShader: WebGLShader | null = null;
  let edgeFragmentShader: WebGLShader | null = null;
  let program: WebGLProgram | null = null;
  let edgeProgram: WebGLProgram | null = null;
  const buffers: WebGLBuffer[] = [];
  try {
    vertexShader = compileShader(gl, gl.VERTEX_SHADER, PERMISSIONS_GRAPH_OVERVIEW_VERTEX_SHADER);
    fragmentShader = compileShader(gl, gl.FRAGMENT_SHADER, PERMISSIONS_GRAPH_OVERVIEW_FRAGMENT_SHADER);
    edgeVertexShader = compileShader(gl, gl.VERTEX_SHADER, PERMISSIONS_GRAPH_OVERVIEW_EDGE_VERTEX_SHADER);
    edgeFragmentShader = compileShader(gl, gl.FRAGMENT_SHADER, PERMISSIONS_GRAPH_OVERVIEW_EDGE_FRAGMENT_SHADER);
    program = createProgram(gl, vertexShader, fragmentShader);
    edgeProgram = createProgram(gl, edgeVertexShader, edgeFragmentShader);
    const position = requiredAttribute(gl, program, "a_position");
    const pointSize = requiredAttribute(gl, program, "a_pointSize");
    const visualToken = requiredAttribute(gl, program, "a_visualToken");
    const dynamicFlags = requiredAttribute(gl, program, "a_dynamicFlags");
    const edgePosition = requiredAttribute(gl, edgeProgram, "a_edgePosition");
    const edgeStyle = requiredAttribute(gl, edgeProgram, "a_edgeStyle");
    const created = Array.from({ length: 6 }, () => {
      const buffer = gl.createBuffer();
      if (!buffer) throw new Error("WebGL2 overview buffer allocation failed.");
      buffers.push(buffer);
      return buffer;
    });
    return {
      program, vertexShader, fragmentShader,
      positions: created[0] as WebGLBuffer,
      pointSizes: created[1] as WebGLBuffer,
      visualTokens: created[2] as WebGLBuffer,
      dynamicFlags: created[3] as WebGLBuffer,
      edgeProgram,
      edgeVertexShader,
      edgeFragmentShader,
      edgePositions: created[4] as WebGLBuffer,
      edgeStyles: created[5] as WebGLBuffer,
      locations: {
        position, pointSize, visualToken, dynamicFlags,
        pan: requiredUniform(gl, program, "u_pan"),
        zoom: requiredUniform(gl, program, "u_zoom"),
        viewport: requiredUniform(gl, program, "u_viewport"),
        pixelRatio: requiredUniform(gl, program, "u_pixelRatio"),
        colors: requiredUniform(gl, program, "u_colors[0]"),
      },
      edgeLocations: {
        position: edgePosition,
        style: edgeStyle,
        pan: requiredUniform(gl, edgeProgram, "u_edgePan"),
        zoom: requiredUniform(gl, edgeProgram, "u_edgeZoom"),
        viewport: requiredUniform(gl, edgeProgram, "u_edgeViewport"),
        colors: requiredUniform(gl, edgeProgram, "u_edgeColors[0]"),
      },
    };
  } catch (error) {
    for (const buffer of buffers) gl.deleteBuffer(buffer);
    if (program) gl.deleteProgram(program);
    if (edgeProgram) gl.deleteProgram(edgeProgram);
    if (vertexShader) gl.deleteShader(vertexShader);
    if (fragmentShader) gl.deleteShader(fragmentShader);
    if (edgeVertexShader) gl.deleteShader(edgeVertexShader);
    if (edgeFragmentShader) gl.deleteShader(edgeFragmentShader);
    throw error;
  }
}

function createProgram(
  gl: WebGL2RenderingContext,
  vertexShader: WebGLShader,
  fragmentShader: WebGLShader,
): WebGLProgram {
  const program = gl.createProgram();
  if (!program) throw new Error("WebGL2 overview program allocation failed.");
  gl.attachShader(program, vertexShader);
  gl.attachShader(program, fragmentShader);
  gl.linkProgram(program);
  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
    gl.deleteProgram(program);
    throw new Error("WebGL2 overview program link failed.");
  }
  return program;
}

function compileShader(gl: WebGL2RenderingContext, type: number, source: string): WebGLShader {
  const shader = gl.createShader(type);
  if (!shader) throw new Error("WebGL2 overview shader allocation failed.");
  gl.shaderSource(shader, `${source}\n// ${PERMISSIONS_GRAPH_OVERVIEW_PHASE_C_MARKER}`);
  gl.compileShader(shader);
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
    gl.deleteShader(shader);
    throw new Error("WebGL2 overview shader compilation failed.");
  }
  return shader;
}

function requiredAttribute(gl: WebGL2RenderingContext, program: WebGLProgram, name: string): number {
  const location = gl.getAttribLocation(program, name);
  if (location < 0) throw new Error("WebGL2 overview attribute lookup failed.");
  return location;
}

function requiredUniform(gl: WebGL2RenderingContext, program: WebGLProgram, name: string): WebGLUniformLocation {
  const location = gl.getUniformLocation(program, name);
  if (!location) throw new Error("WebGL2 overview uniform lookup failed.");
  return location;
}

function uploadAttribute(
  gl: WebGL2RenderingContext,
  buffer: WebGLBuffer,
  location: number,
  size: number,
  type: number,
  data: ArrayBufferView,
): void {
  gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
  gl.bufferData(gl.ARRAY_BUFFER, data, gl.STATIC_DRAW);
  gl.enableVertexAttribArray(location);
  gl.vertexAttribPointer(location, size, type, false, 0, 0);
}

function uploadDynamicRanges(
  gl: WebGL2RenderingContext,
  buffer: WebGLBuffer,
  flags: Uint8Array,
  ranges: readonly { readonly startOrdinal: number; readonly endOrdinalExclusive: number }[],
): void {
  gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
  for (const range of ranges) {
    gl.bufferSubData(
      gl.ARRAY_BUFFER,
      range.startOrdinal,
      flags.subarray(range.startOrdinal, range.endOrdinalExclusive),
    );
  }
}

function uploadCoordinateRanges(
  gl: WebGL2RenderingContext,
  buffer: WebGLBuffer,
  positions: Float32Array,
  ranges: readonly { readonly startOrdinal: number; readonly endOrdinalExclusive: number }[],
): void {
  gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
  for (const range of ranges) {
    const start = range.startOrdinal * 2;
    const end = range.endOrdinalExclusive * 2;
    gl.bufferSubData(
      gl.ARRAY_BUFFER,
      start * Float32Array.BYTES_PER_ELEMENT,
      positions.subarray(start, end),
    );
  }
}

function bindPointAttributes(gl: WebGL2RenderingContext, resources: GlResources): void {
  bindAttribute(gl, resources.positions, resources.locations.position, 2, gl.FLOAT);
  bindAttribute(gl, resources.pointSizes, resources.locations.pointSize, 1, gl.FLOAT);
  bindAttribute(gl, resources.visualTokens, resources.locations.visualToken, 1, gl.UNSIGNED_BYTE);
  bindAttribute(gl, resources.dynamicFlags, resources.locations.dynamicFlags, 1, gl.UNSIGNED_BYTE);
}

function bindEdgeAttributes(gl: WebGL2RenderingContext, resources: GlResources): void {
  bindAttribute(gl, resources.edgePositions, resources.edgeLocations.position, 2, gl.FLOAT);
  bindAttribute(gl, resources.edgeStyles, resources.edgeLocations.style, 1, gl.FLOAT);
}

function bindAttribute(
  gl: WebGL2RenderingContext,
  buffer: WebGLBuffer,
  location: number,
  size: number,
  type: number,
): void {
  gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
  gl.enableVertexAttribArray(location);
  gl.vertexAttribPointer(location, size, type, false, 0, 0);
}

function renderResult(
  input: PermissionsGraphOverviewRenderInput,
  drawablePointCount: number,
  drawableEdgeSegmentCount: number,
  uploadedBytes: number,
  viewport: PermissionsGraphOverviewNormalizedResize,
): PermissionsGraphOverviewRenderResult {
  return Object.freeze({
    backend: "webgl2",
    overviewNodeCount: input.buffers.nodeCount,
    drawablePointCount,
    overviewEdgeSegmentCount: input.edges?.emittedSegmentCount ?? 0,
    drawableEdgeSegmentCount,
    uploadedBytes,
    viewport,
  });
}

function hexToRgba(value: string): number[] {
  const component = (offset: number) => Number.parseInt(value.slice(offset, offset + 2), 16) / 255;
  return [component(1), component(3), component(5), 1];
}
