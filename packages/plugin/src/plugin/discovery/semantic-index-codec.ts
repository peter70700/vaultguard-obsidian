import { normalizeVaultRelativePath } from "./search-model";

const MAGIC = new Uint8Array([0x56, 0x47, 0x53, 0x49]); // VGSI
const SCHEMA_VERSION = 1;
const MAX_ENCODED_BYTES = 128 * 1024 * 1024;
const MAX_NOTES = 1_000;
const MAX_ENTRIES = 25_000;
const MAX_DIMENSIONS = 4_096;
const MAX_PATH_BYTES = 4_096;
const MAX_IDENTITY_BYTES = 1_024;
const MAX_FINGERPRINT_BYTES = 256;
const MAX_HEADING_CODE_POINTS = 160;
const CONTROL = /[\u0000-\u001f\u007f]/u;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export interface SemanticIndexIdentity {
  schemaVersion: 1;
  userId: string;
  localVaultId: string;
  vaultId: string;
  provider: string;
  providerOrigin: string;
  model: string;
  chunkerVersion: string;
  dimensions: number;
}

export type SemanticIndexExpectedIdentity = Omit<SemanticIndexIdentity, "dimensions"> & {
  dimensions?: number;
};

export interface SemanticIndexEntry {
  path: string;
  fingerprint: string;
  chunkIndex: number;
  start: number;
  end: number;
  heading?: string;
  vector: number[];
  indexedAt: number;
}

export interface SemanticIndexEnvelope extends SemanticIndexIdentity {
  generatedAt: number;
  entries: SemanticIndexEntry[];
}

function requireBoundedString(value: unknown, field: string, maxBytes: number): string {
  if (typeof value !== "string" || !value || CONTROL.test(value)) {
    throw new Error(`Semantic index ${field} is invalid.`);
  }
  if (encoder.encode(value).byteLength > maxBytes) {
    throw new Error(`Semantic index ${field} exceeds its bound.`);
  }
  return value;
}

function validateIdentity(identity: SemanticIndexExpectedIdentity | SemanticIndexIdentity): void {
  if (identity.schemaVersion !== 1) throw new Error("Unsupported semantic index schema.");
  requireBoundedString(identity.userId, "userId", MAX_IDENTITY_BYTES);
  requireBoundedString(identity.localVaultId, "localVaultId", MAX_IDENTITY_BYTES);
  requireBoundedString(identity.vaultId, "vaultId", MAX_IDENTITY_BYTES);
  requireBoundedString(identity.provider, "provider", MAX_IDENTITY_BYTES);
  requireBoundedString(identity.providerOrigin, "providerOrigin", MAX_IDENTITY_BYTES);
  requireBoundedString(identity.model, "model", MAX_IDENTITY_BYTES);
  requireBoundedString(identity.chunkerVersion, "chunkerVersion", MAX_IDENTITY_BYTES);
  if (
    identity.dimensions !== undefined &&
    (!Number.isInteger(identity.dimensions) || identity.dimensions < 1 || identity.dimensions > MAX_DIMENSIONS)
  ) {
    throw new Error("Semantic index dimensions are invalid.");
  }
}

function validateEnvelope(envelope: SemanticIndexEnvelope): SemanticIndexEntry[] {
  validateIdentity(envelope);
  if (!Number.isFinite(envelope.generatedAt) || envelope.generatedAt < 0) {
    throw new Error("Semantic index generation timestamp is invalid.");
  }
  if (!Array.isArray(envelope.entries) || envelope.entries.length > MAX_ENTRIES) {
    throw new Error("Semantic index entry count exceeds its bound.");
  }

  const notes = new Set<string>();
  const chunks = new Set<string>();
  const entries = envelope.entries.map((entry) => {
    const path = normalizeVaultRelativePath(entry.path);
    if (!path || path !== entry.path || !path.toLocaleLowerCase("en-US").endsWith(".md")) {
      throw new Error("Semantic index entry path is invalid.");
    }
    requireBoundedString(path, "path", MAX_PATH_BYTES);
    notes.add(path);
    if (notes.size > MAX_NOTES) throw new Error("Semantic index note count exceeds its bound.");
    const fingerprint = requireBoundedString(
      entry.fingerprint,
      "fingerprint",
      MAX_FINGERPRINT_BYTES,
    );
    if (!Number.isInteger(entry.chunkIndex) || entry.chunkIndex < 0 || entry.chunkIndex > 31) {
      throw new Error("Semantic index chunk index is invalid.");
    }
    const chunkKey = `${path}\u0000${entry.chunkIndex}`;
    if (chunks.has(chunkKey)) throw new Error("Semantic index contains a duplicate chunk.");
    chunks.add(chunkKey);
    if (
      !Number.isInteger(entry.start) ||
      !Number.isInteger(entry.end) ||
      entry.start < 0 ||
      entry.end <= entry.start ||
      entry.end > 0xffff_ffff
    ) {
      throw new Error("Semantic index chunk offsets are invalid.");
    }
    let heading: string | undefined;
    if (entry.heading !== undefined) {
      heading = requireBoundedString(entry.heading, "heading", MAX_IDENTITY_BYTES);
      if ([...heading].length > MAX_HEADING_CODE_POINTS || heading.includes("\n")) {
        throw new Error("Semantic index heading exceeds its bound.");
      }
    }
    if (!Number.isFinite(entry.indexedAt) || entry.indexedAt < 0) {
      throw new Error("Semantic index entry timestamp is invalid.");
    }
    if (!Array.isArray(entry.vector) || entry.vector.length !== envelope.dimensions) {
      throw new Error("Semantic index vector dimension is inconsistent.");
    }
    let squared = 0;
    const vector = entry.vector.map((value) => {
      if (typeof value !== "number" || !Number.isFinite(value)) {
        throw new Error("Semantic index vector contains a non-finite value.");
      }
      squared += value * value;
      return value;
    });
    const magnitude = Math.sqrt(squared);
    if (!Number.isFinite(magnitude) || Math.abs(magnitude - 1) > 0.001) {
      throw new Error("Semantic index vector is not normalized.");
    }
    return {
      path,
      fingerprint,
      chunkIndex: entry.chunkIndex,
      start: entry.start,
      end: entry.end,
      ...(heading ? { heading } : {}),
      vector,
      indexedAt: entry.indexedAt,
    };
  });
  return entries.sort((left, right) =>
    left.path.localeCompare(right.path, undefined, { sensitivity: "base" }) ||
    left.chunkIndex - right.chunkIndex,
  );
}

class BinaryWriter {
  private readonly chunks: Uint8Array[] = [];
  private length = 0;

  private push(bytes: Uint8Array): void {
    if (this.length + bytes.byteLength > MAX_ENCODED_BYTES) {
      throw new Error("Semantic index payload exceeds 128 MiB.");
    }
    this.chunks.push(bytes);
    this.length += bytes.byteLength;
  }

  bytes(value: Uint8Array): void { this.push(value); }

  uint8(value: number): void { this.push(Uint8Array.of(value)); }

  uint16(value: number): void {
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(0, value, true);
    this.push(bytes);
  }

  uint32(value: number): void {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);
    this.push(bytes);
  }

  float32(value: number): void {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setFloat32(0, value, true);
    this.push(bytes);
  }

  float64(value: number): void {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setFloat64(0, value, true);
    this.push(bytes);
  }

  string(value: string): void {
    const bytes = encoder.encode(value);
    this.uint32(bytes.byteLength);
    this.push(bytes);
  }

  finish(): Uint8Array {
    const output = new Uint8Array(this.length);
    let offset = 0;
    for (const chunk of this.chunks) {
      output.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return output;
  }
}

class BinaryReader {
  private offset = 0;
  private readonly view: DataView;

  constructor(private readonly bytes: Uint8Array) {
    if (bytes.byteLength > MAX_ENCODED_BYTES) throw new Error("Semantic index payload exceeds 128 MiB.");
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  private take(length: number): Uint8Array {
    if (!Number.isInteger(length) || length < 0 || this.offset + length > this.bytes.byteLength) {
      throw new Error("Semantic index payload is truncated.");
    }
    const value = this.bytes.slice(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  uint8(): number { return this.take(1)[0]!; }

  uint16(): number {
    const value = this.view.getUint16(this.offset, true);
    this.take(2);
    return value;
  }

  uint32(): number {
    const value = this.view.getUint32(this.offset, true);
    this.take(4);
    return value;
  }

  float32(): number {
    const value = this.view.getFloat32(this.offset, true);
    this.take(4);
    return value;
  }

  float64(): number {
    const value = this.view.getFloat64(this.offset, true);
    this.take(8);
    return value;
  }

  string(maxBytes: number): string {
    const length = this.uint32();
    if (length > maxBytes) throw new Error("Semantic index string exceeds its bound.");
    return decoder.decode(this.take(length));
  }

  done(): boolean { return this.offset === this.bytes.byteLength; }
}

export function encodeSemanticIndex(envelope: SemanticIndexEnvelope): Uint8Array {
  const entries = validateEnvelope(envelope);
  const writer = new BinaryWriter();
  writer.bytes(MAGIC);
  writer.uint16(SCHEMA_VERSION);
  writer.uint16(0);
  writer.string(envelope.userId);
  writer.string(envelope.localVaultId);
  writer.string(envelope.vaultId);
  writer.string(envelope.provider);
  writer.string(envelope.providerOrigin);
  writer.string(envelope.model);
  writer.string(envelope.chunkerVersion);
  writer.uint16(envelope.dimensions);
  writer.float64(envelope.generatedAt);
  writer.uint32(entries.length);
  for (const entry of entries) {
    writer.string(entry.path);
    writer.string(entry.fingerprint);
    writer.uint8(entry.chunkIndex);
    writer.uint8(entry.heading ? 1 : 0);
    writer.uint16(0);
    writer.uint32(entry.start);
    writer.uint32(entry.end);
    writer.float64(entry.indexedAt);
    if (entry.heading) writer.string(entry.heading);
    for (const value of entry.vector) writer.float32(value);
  }
  return writer.finish();
}

export function decodeSemanticIndex(
  input: ArrayBuffer | Uint8Array,
  expected: SemanticIndexExpectedIdentity,
): SemanticIndexEnvelope {
  validateIdentity(expected);
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  const reader = new BinaryReader(bytes);
  const magic = Uint8Array.from({ length: MAGIC.length }, () => reader.uint8());
  if (!magic.every((value, index) => value === MAGIC[index])) {
    throw new Error("Semantic index magic is invalid.");
  }
  const schemaVersion = reader.uint16();
  if (schemaVersion !== SCHEMA_VERSION || reader.uint16() !== 0) {
    throw new Error("Unsupported semantic index schema.");
  }
  const identity: SemanticIndexIdentity = {
    schemaVersion: 1,
    userId: reader.string(MAX_IDENTITY_BYTES),
    localVaultId: reader.string(MAX_IDENTITY_BYTES),
    vaultId: reader.string(MAX_IDENTITY_BYTES),
    provider: reader.string(MAX_IDENTITY_BYTES),
    providerOrigin: reader.string(MAX_IDENTITY_BYTES),
    model: reader.string(MAX_IDENTITY_BYTES),
    chunkerVersion: reader.string(MAX_IDENTITY_BYTES),
    dimensions: reader.uint16(),
  };
  validateIdentity(identity);
  for (const field of [
    "schemaVersion",
    "userId",
    "localVaultId",
    "vaultId",
    "provider",
    "providerOrigin",
    "model",
    "chunkerVersion",
  ] as const) {
    if (identity[field] !== expected[field]) {
      throw new Error(`Semantic index identity mismatch: ${field}.`);
    }
  }
  if (expected.dimensions !== undefined && identity.dimensions !== expected.dimensions) {
    throw new Error("Semantic index identity mismatch: dimensions.");
  }
  const generatedAt = reader.float64();
  const count = reader.uint32();
  if (count > MAX_ENTRIES) throw new Error("Semantic index entry count exceeds its bound.");
  const entries: SemanticIndexEntry[] = [];
  for (let index = 0; index < count; index += 1) {
    const path = reader.string(MAX_PATH_BYTES);
    const fingerprint = reader.string(MAX_FINGERPRINT_BYTES);
    const chunkIndex = reader.uint8();
    const hasHeading = reader.uint8();
    if (hasHeading !== 0 && hasHeading !== 1) throw new Error("Semantic index heading flag is invalid.");
    if (reader.uint16() !== 0) throw new Error("Semantic index reserved bytes are invalid.");
    const start = reader.uint32();
    const end = reader.uint32();
    const indexedAt = reader.float64();
    const heading = hasHeading === 1 ? reader.string(MAX_IDENTITY_BYTES) : undefined;
    const vector = Array.from({ length: identity.dimensions }, () => reader.float32());
    entries.push({
      path,
      fingerprint,
      chunkIndex,
      start,
      end,
      ...(heading ? { heading } : {}),
      vector,
      indexedAt,
    });
  }
  if (!reader.done()) throw new Error("Semantic index payload has trailing data.");
  const envelope: SemanticIndexEnvelope = { ...identity, generatedAt, entries };
  envelope.entries = validateEnvelope(envelope);
  return envelope;
}
