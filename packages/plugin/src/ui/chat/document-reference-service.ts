import { Platform } from "obsidian";

import {
  AttachmentValidationError,
  MAX_DOCUMENT_BYTES,
  MAX_DOCUMENT_PINS,
  type AttachmentCapabilities,
  type DocumentFormat,
  type DocumentPin,
  type PreparedDocument,
  sanitizeAttachmentName,
} from "./attachment-model";
import { classifyExtension, dispatchConvert } from "../import/converters/dispatch";

const READ_CHUNK_BYTES = 64 * 1024;
const TEXT_DECODER = new TextDecoder("utf-8", { fatal: true });
const DOCX_MEDIA_TYPE =
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

export interface StableFileStat {
  size: number;
  mtimeMs: number;
  dev?: number;
  ino?: number;
  isFile: boolean;
}

export interface StableFileHandle {
  stat(): Promise<StableFileStat>;
  read(
    target: Uint8Array,
    offset: number,
    length: number,
    position: number,
  ): Promise<{ bytesRead: number }>;
  close(): Promise<void>;
}

export interface DocumentReferenceServiceDeps {
  pickFiles(): Promise<string[]>;
  realpath(path: string): Promise<string>;
  openReadOnly(path: string): Promise<StableFileHandle>;
  basename(path: string): string;
  /** Lower-cased extension without the dot. */
  extname(path: string): string;
  randomId(): string;
  now(): number;
}

export class DocumentReferenceService {
  private readonly deps: DocumentReferenceServiceDeps | null;

  constructor(deps?: DocumentReferenceServiceDeps | null) {
    this.deps = deps === undefined ? loadProductionDeps() : deps;
  }

  isAvailable(): boolean {
    return !Platform.isMobileApp && this.deps !== null;
  }

  async pickDocumentPins(existingCount = 0): Promise<DocumentPin[]> {
    const deps = this.requireDeps();
    const paths = await deps.pickFiles();
    if (existingCount + paths.length > MAX_DOCUMENT_PINS) {
      throw new AttachmentValidationError(
        "too-many-files",
        `A conversation can pin up to ${MAX_DOCUMENT_PINS} documents.`,
      );
    }

    const pins: DocumentPin[] = [];
    for (const sourcePath of paths) {
      let handle: StableFileHandle | null = null;
      try {
        const canonicalPath = await deps.realpath(sourcePath);
        handle = await deps.openReadOnly(canonicalPath);
        const stat = await handle.stat();
        validateRegularDocument(stat);
        const ext = deps.extname(canonicalPath).replace(/^\.+/, "").toLowerCase();
        const format = documentFormat(ext);
        pins.push({
          id: deps.randomId(),
          displayName: sanitizeAttachmentName(deps.basename(canonicalPath), "document"),
          format,
          mediaType: documentMediaType(format),
          byteLength: stat.size,
          sourcePath,
          canonicalPath,
          addedAt: deps.now(),
          state: "ready",
        });
      } catch (error) {
        throw safeDocumentError(error);
      } finally {
        await handle?.close().catch(() => undefined);
      }
    }
    return pins;
  }

  async preparePins(
    pins: ReadonlyArray<DocumentPin>,
    capabilities: AttachmentCapabilities,
    signal?: AbortSignal,
  ): Promise<PreparedDocument[]> {
    if (pins.length > MAX_DOCUMENT_PINS) {
      throw new AttachmentValidationError(
        "too-many-files",
        `A conversation can pin up to ${MAX_DOCUMENT_PINS} documents.`,
      );
    }
    const prepared: PreparedDocument[] = [];
    for (const pin of pins) {
      throwIfAborted(signal);
      if (pin.format === "pdf" && !capabilities.pdfDocumentInput) {
        throw new AttachmentValidationError(
          "unsupported-provider",
          "PDF pins are not supported by the selected AI provider.",
        );
      }
      if (pin.format !== "pdf" && !capabilities.textDocumentInput) {
        throw new AttachmentValidationError(
          "unsupported-provider",
          "Document pins are not supported by the selected AI provider.",
        );
      }
      const bytes = await this.stableRead(pin, signal);
      prepared.push(await prepareDocument(pin, bytes));
    }
    return prepared;
  }

  private async stableRead(pin: DocumentPin, signal?: AbortSignal): Promise<Uint8Array> {
    const deps = this.requireDeps();
    let handle: StableFileHandle | null = null;
    try {
      throwIfAborted(signal);
      const beforeCanonical = await deps.realpath(pin.sourcePath);
      if (beforeCanonical !== pin.canonicalPath) {
        throw new AttachmentValidationError(
          "file-changed",
          `Pinned document "${pin.displayName}" now points to a different file.`,
        );
      }

      handle = await deps.openReadOnly(beforeCanonical);
      const before = await handle.stat();
      validateRegularDocument(before);
      const bytes = new Uint8Array(before.size);
      let position = 0;
      while (position < before.size) {
        throwIfAborted(signal);
        const length = Math.min(READ_CHUNK_BYTES, before.size - position);
        const { bytesRead } = await handle.read(bytes, position, length, position);
        if (bytesRead <= 0) {
          throw new AttachmentValidationError(
            "file-changed",
            `Pinned document "${pin.displayName}" changed while it was being read.`,
          );
        }
        position += bytesRead;
      }

      const after = await handle.stat();
      if (!sameFileStat(before, after)) {
        throw new AttachmentValidationError(
          "file-changed",
          `Pinned document "${pin.displayName}" changed while it was being read.`,
        );
      }
      await handle.close();
      handle = null;
      const afterCanonical = await deps.realpath(pin.sourcePath);
      if (afterCanonical !== beforeCanonical) {
        throw new AttachmentValidationError(
          "file-changed",
          `Pinned document "${pin.displayName}" changed while it was being read.`,
        );
      }
      return bytes;
    } catch (error) {
      throw safeDocumentError(error, pin.displayName);
    } finally {
      await handle?.close().catch(() => undefined);
    }
  }

  private requireDeps(): DocumentReferenceServiceDeps {
    if (!this.deps || Platform.isMobileApp) {
      throw new AttachmentValidationError(
        "unsupported-platform",
        "Document pins are available in desktop Obsidian only.",
      );
    }
    return this.deps;
  }
}

function validateRegularDocument(stat: StableFileStat): void {
  if (!stat.isFile) {
    throw new AttachmentValidationError("unsupported-type", "Select a regular document file.");
  }
  if (!Number.isSafeInteger(stat.size) || stat.size < 0 || stat.size > MAX_DOCUMENT_BYTES) {
    throw new AttachmentValidationError(
      "file-too-large",
      "Documents must be 20 MB or smaller.",
    );
  }
}

function sameFileStat(before: StableFileStat, after: StableFileStat): boolean {
  if (before.size !== after.size || before.mtimeMs !== after.mtimeMs) return false;
  if (before.dev && after.dev && before.dev !== after.dev) return false;
  if (before.ino && after.ino && before.ino !== after.ino) return false;
  return before.isFile && after.isFile;
}

function documentFormat(ext: string): DocumentFormat {
  const route = classifyExtension(ext);
  if (route === "passthrough" || route === "code") return "text";
  if (route === "pdf-skip") return "pdf";
  if (route === "convert") {
    if (ext === "docx") return "docx";
    if (ext === "html" || ext === "htm") return "html";
    if (ext === "csv" || ext === "tsv") return "csv";
  }
  throw new AttachmentValidationError(
    "unsupported-type",
    "That document type is not supported. Use text, Markdown, CSV/TSV, JSON, source code, HTML, DOCX, or PDF.",
  );
}

function documentMediaType(format: DocumentFormat): string {
  if (format === "pdf") return "application/pdf";
  if (format === "docx") return DOCX_MEDIA_TYPE;
  if (format === "html") return "text/html";
  if (format === "csv") return "text/csv";
  return "text/plain";
}

async function prepareDocument(pin: DocumentPin, bytes: Uint8Array): Promise<PreparedDocument> {
  if (pin.format === "pdf") {
    if (!hasPrefix(bytes, [0x25, 0x50, 0x44, 0x46, 0x2d])) {
      throw new AttachmentValidationError(
        "invalid-signature",
        `Pinned document "${pin.displayName}" is not a valid PDF.`,
      );
    }
    if (containsAsciiToken(bytes, "/Encrypt")) {
      throw new AttachmentValidationError(
        "encrypted-document",
        "The pinned PDF is encrypted and cannot be read safely.",
      );
    }
    const data = bytesToBase64(bytes);
    return {
      kind: "pdf",
      pinId: pin.id,
      displayName: pin.displayName,
      mediaType: "application/pdf",
      data,
      payloadBytes: new TextEncoder().encode(data).byteLength,
    };
  }

  if (pin.format === "docx") {
    if (!hasPrefix(bytes, [0x50, 0x4b])) {
      throw new AttachmentValidationError(
        "invalid-signature",
        `Pinned document "${pin.displayName}" is not a valid DOCX file.`,
      );
    }
  } else {
    try {
      TEXT_DECODER.decode(bytes);
    } catch {
      throw new AttachmentValidationError(
        "invalid-encoding",
        `Pinned document "${pin.displayName}" is not valid UTF-8 text.`,
      );
    }
  }

  const ext = extensionForFormat(pin);
  const converted = await dispatchConvert({
    bytes,
    ext,
    baseName: pin.displayName.replace(/\.[^.]+$/, ""),
  });
  if (converted.kind === "skipped") {
    throw new AttachmentValidationError(
      "unsupported-type",
      `Pinned document "${pin.displayName}" could not be read as a supported document.`,
    );
  }
  const text = converted.markdown;
  if (typeof text !== "string") {
    throw new AttachmentValidationError(
      "unsupported-type",
      "The document converter did not return readable text.",
    );
  }
  return {
    kind: "text",
    pinId: pin.id,
    displayName: pin.displayName,
    mediaType: "text/plain",
    text,
    payloadBytes: new TextEncoder().encode(text).byteLength,
  };
}

function extensionForFormat(pin: DocumentPin): string {
  const match = /\.([A-Za-z0-9]+)$/.exec(pin.displayName);
  if (match) return match[1].toLowerCase();
  if (pin.format === "html") return "html";
  if (pin.format === "csv") return "csv";
  if (pin.format === "docx") return "docx";
  return "txt";
}

function containsAsciiToken(bytes: Uint8Array, token: string): boolean {
  const needle = new TextEncoder().encode(token);
  outer: for (let offset = 0; offset <= bytes.length - needle.length; offset++) {
    for (let index = 0; index < needle.length; index++) {
      if (bytes[offset + index] !== needle[index]) continue outer;
    }
    return true;
  }
  return false;
}
function hasPrefix(bytes: Uint8Array, prefix: ReadonlyArray<number>): boolean {
  return prefix.every((value, index) => bytes[index] === value);
}

function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") return Buffer.from(bytes).toString("base64");
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) {
    throw new AttachmentValidationError("cancelled", "Attachment preparation was cancelled.");
  }
}

function safeDocumentError(error: unknown, displayName?: string): AttachmentValidationError {
  if (error instanceof AttachmentValidationError) return error;
  const label = displayName ? ` "${sanitizeAttachmentName(displayName, "document")}"` : "";
  return new AttachmentValidationError(
    "file-unavailable",
    `Pinned document${label} is unavailable or unreadable.`,
  );
}

interface ElectronDialogLike {
  showOpenDialog(options: {
    title: string;
    properties: string[];
    filters: Array<{ name: string; extensions: string[] }>;
  }): Promise<{ canceled: boolean; filePaths: string[] }>;
}

function electronRequire(): ((id: string) => unknown) | null {
  const maybeWindow =
    typeof window !== "undefined" ? (window as unknown as { require?: unknown }) : undefined;
  if (typeof maybeWindow?.require === "function") {
    return maybeWindow.require as (id: string) => unknown;
  }
  try {
    return typeof require === "function" ? (require as (id: string) => unknown) : null;
  } catch {
    return null;
  }
}

function loadProductionDeps(): DocumentReferenceServiceDeps | null {
  if (Platform.isMobileApp) return null;
  const req = electronRequire();
  if (!req) return null;
  try {
    const fs = req("fs") as {
      promises: {
        realpath(path: string): Promise<string>;
        open(path: string, flags: "r"): Promise<{
          stat(): Promise<{
            size: number;
            mtimeMs: number;
            dev?: number;
            ino?: number;
            isFile(): boolean;
          }>;
          read(
            target: Uint8Array,
            offset: number,
            length: number,
            position: number,
          ): Promise<{ bytesRead: number }>;
          close(): Promise<void>;
        }>;
      };
    };
    const path = req("path") as {
      basename(path: string): string;
      extname(path: string): string;
    };
    let dialog: ElectronDialogLike | undefined;
    try {
      dialog = (req("@electron/remote") as { dialog?: ElectronDialogLike }).dialog;
    } catch {
      const electron = req("electron") as {
        dialog?: ElectronDialogLike;
        remote?: { dialog?: ElectronDialogLike };
      };
      dialog = electron.remote?.dialog ?? electron.dialog;
    }
    if (!dialog) return null;

    return {
      async pickFiles() {
        const result = await dialog!.showOpenDialog({
          title: "Pin original documents to this chat",
          properties: ["openFile", "multiSelections"],
          filters: [
            {
              name: "Supported documents",
              extensions: [
                "txt", "text", "md", "markdown", "json", "jsonc", "csv", "tsv",
                "html", "htm", "docx", "pdf", "ts", "tsx", "js", "jsx", "py",
                "rb", "go", "rs", "java", "kt", "swift", "c", "h", "cpp", "cc",
                "hpp", "cs", "php", "sh", "bash", "zsh", "ps1", "sql", "yaml",
                "yml", "toml", "ini", "xml", "css", "scss", "less",
              ],
            },
          ],
        });
        return result.canceled ? [] : result.filePaths;
      },
      realpath: (value) => fs.promises.realpath(value),
      openReadOnly: async (value) => {
        const handle = await fs.promises.open(value, "r");
        return {
          stat: async () => {
            const stat = await handle.stat();
            return {
              size: stat.size,
              mtimeMs: stat.mtimeMs,
              dev: stat.dev,
              ino: stat.ino,
              isFile: stat.isFile(),
            };
          },
          read: (target, offset, length, position) =>
            handle.read(target, offset, length, position),
          close: () => handle.close(),
        };
      },
      basename: (value) => path.basename(value),
      extname: (value) => path.extname(value).replace(/^\.+/, "").toLowerCase(),
      randomId: () =>
        typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
          ? crypto.randomUUID()
          : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`,
      now: () => Date.now(),
    };
  } catch {
    return null;
  }
}
