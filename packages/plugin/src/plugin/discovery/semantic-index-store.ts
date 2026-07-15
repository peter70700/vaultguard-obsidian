import {
  decodeSemanticIndex,
  encodeSemanticIndex,
  type SemanticIndexEnvelope,
  type SemanticIndexExpectedIdentity,
} from "./semantic-index-codec";

export interface SemanticIndexCipher {
  isReady(): boolean;
  encryptBinary(plaintext: ArrayBuffer | Uint8Array): Promise<ArrayBuffer>;
  decryptBinary(ciphertext: ArrayBuffer | Uint8Array): Promise<ArrayBuffer>;
}

export interface SemanticIndexStorage {
  exists(path: string): Promise<boolean>;
  readBinary(path: string): Promise<ArrayBuffer>;
  writeBinary(path: string, bytes: ArrayBuffer): Promise<void>;
  remove(path: string): Promise<void>;
  rename(from: string, to: string): Promise<void>;
}

export interface SemanticIndexStoreContext {
  path: string;
  getCipher(): SemanticIndexCipher | null;
  getStorage(): SemanticIndexStorage | null;
  ensureParent(path: string): Promise<void>;
}

function wipeBinary(value: ArrayBuffer | Uint8Array): void {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  bytes.fill(0);
}

export class SemanticIndexStore {
  private readonly tempPath: string;
  private readonly backupPath: string;

  constructor(private readonly context: SemanticIndexStoreContext) {
    this.tempPath = `${context.path}.tmp`;
    this.backupPath = `${context.path}.bak`;
  }

  async load(expected: SemanticIndexExpectedIdentity): Promise<SemanticIndexEnvelope | null> {
    const cipher = this.context.getCipher();
    const storage = this.context.getStorage();
    if (!cipher?.isReady() || !storage) return null;
    if (!(await storage.exists(this.context.path))) return null;
    const ciphertext = await storage.readBinary(this.context.path);
    const plaintext = await cipher.decryptBinary(ciphertext);
    try {
      return decodeSemanticIndex(plaintext, expected);
    } finally {
      wipeBinary(plaintext);
    }
  }

  async save(envelope: SemanticIndexEnvelope): Promise<void> {
    const cipher = this.context.getCipher();
    const storage = this.context.getStorage();
    if (!cipher?.isReady() || !storage) {
      throw new Error("The local at-rest cipher and raw binary adapter are required.");
    }
    const encoded = encodeSemanticIndex(envelope);
    try {
      const ciphertext = await cipher.encryptBinary(encoded);
      try {
        await this.context.ensureParent(this.context.path);
        await this.removeIfPresent(storage, this.tempPath);
        await storage.writeBinary(this.tempPath, ciphertext);

        // Read back from the raw adapter, decrypt, and validate the complete
        // identity before the old envelope is touched.
        const tempCiphertext = await storage.readBinary(this.tempPath);
        const tempPlaintext = await cipher.decryptBinary(tempCiphertext);
        try {
          decodeSemanticIndex(tempPlaintext, envelope);
        } finally {
          wipeBinary(tempPlaintext);
        }

        const hadFinal = await storage.exists(this.context.path);
        if (hadFinal) {
          await this.removeIfPresent(storage, this.backupPath);
          await storage.rename(this.context.path, this.backupPath);
        }
        try {
          await storage.rename(this.tempPath, this.context.path);
        } catch (error) {
          if (hadFinal && await storage.exists(this.backupPath)) {
            await this.removeIfPresent(storage, this.context.path);
            await storage.rename(this.backupPath, this.context.path);
          }
          throw error;
        }
        await this.removeIfPresent(storage, this.backupPath);
      } catch (error) {
        await this.removeIfPresent(storage, this.tempPath).catch(() => {});
        throw error;
      }
    } finally {
      encoded.fill(0);
    }
  }

  async purge(): Promise<void> {
    const storage = this.context.getStorage();
    if (!storage) {
      throw new Error("The raw binary adapter is required to purge the semantic index.");
    }
    await this.removeIfPresent(storage, this.tempPath);
    await this.removeIfPresent(storage, this.backupPath);
    await this.removeIfPresent(storage, this.context.path);
  }

  private async removeIfPresent(storage: SemanticIndexStorage, path: string): Promise<void> {
    if (await storage.exists(path)) await storage.remove(path);
  }
}
