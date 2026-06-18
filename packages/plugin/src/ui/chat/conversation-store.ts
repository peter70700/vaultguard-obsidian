// LAK-encrypted conversation persistence (AI-CHAT-PANEL.md §10).
//
// ENCRYPTION BOUNDARY: conversations are persisted under the plugin's own
// config dir (`.obsidian/plugins/<id>/chat/<id>.json.envelope`), which is
// `isPathExcluded` — the plugin's own data, exactly like the agent-leases
// envelope. Each file is LAK-encrypted via AtRestCipher (encryptString → bytes
// → write; read → decryptString). Conversation PLAINTEXT is NEVER written to
// disk and NEVER touches actual vault content.
//
// If the LAK is unavailable the store fails soft: persistence is skipped with a
// one-time debug log and chat continues uninterrupted.

import type { AnthropicConversationMessage } from "./anthropic-client";

const LOG_PREFIX = "[VaultGuard Chat]";
const ENVELOPE_SUFFIX = ".json.envelope";

// The cipher surface the store needs — a structural subset of AtRestCipher so
// tests can inject a fake.
export interface ConversationCipher {
  isReady(): boolean;
  encryptString(plaintext: string): Promise<ArrayBuffer>;
  decryptString(encrypted: ArrayBuffer | Uint8Array): Promise<string>;
}

// Filesystem surface, scoped to the plugin's chat config dir. The plugin
// implements this over the excluded-path adapter (binary read/write) so the
// store never imports Obsidian directly and stays unit-testable.
export interface ConversationStorageAdapter {
  /** True if `<dir>/<name>` exists. */
  exists(name: string): Promise<boolean>;
  /** Read the raw envelope bytes for `<dir>/<name>`. */
  readBinary(name: string): Promise<ArrayBuffer>;
  /** Write raw envelope bytes to `<dir>/<name>`, creating the dir if needed. */
  writeBinary(name: string, bytes: ArrayBuffer): Promise<void>;
  /** Remove `<dir>/<name>` if present. */
  remove(name: string): Promise<void>;
  /** List file names directly under the chat dir (no path prefix). */
  list(): Promise<string[]>;
}

export interface Conversation {
  id: string;
  title: string;
  model: string;
  createdAt: number;
  updatedAt: number;
  messages: AnthropicConversationMessage[];
}

export interface ConversationMeta {
  id: string;
  title: string;
  model: string;
  updatedAt: number;
}

export interface ConversationStoreDeps {
  cipher: ConversationCipher;
  adapter: ConversationStorageAdapter;
}

export class ConversationStore {
  private readonly cipher: ConversationCipher;
  private readonly adapter: ConversationStorageAdapter;
  private softFailLogged = false;

  constructor(deps: ConversationStoreDeps) {
    this.cipher = deps.cipher;
    this.adapter = deps.adapter;
  }

  /**
   * Persist a conversation, encrypted at rest. No-op (fail soft) when the LAK
   * is not ready. Returns true if the conversation was written.
   */
  async save(convo: Conversation): Promise<boolean> {
    if (!this.cipher.isReady()) {
      this.logSoftFail("save");
      return false;
    }
    try {
      const plaintext = JSON.stringify(convo);
      const cipherBytes = await this.cipher.encryptString(plaintext);
      await this.adapter.writeBinary(this.fileName(convo.id), cipherBytes);
      return true;
    } catch (err) {
      console.warn(`${LOG_PREFIX} Failed to persist conversation ${convo.id}:`, err);
      return false;
    }
  }

  /** Load a conversation by id, or null if absent / undecryptable / locked. */
  async load(id: string): Promise<Conversation | null> {
    if (!this.cipher.isReady()) {
      this.logSoftFail("load");
      return null;
    }
    const name = this.fileName(id);
    try {
      if (!(await this.adapter.exists(name))) return null;
      const bytes = await this.adapter.readBinary(name);
      const plaintext = await this.cipher.decryptString(bytes);
      const parsed = JSON.parse(plaintext) as Conversation;
      if (!parsed || typeof parsed.id !== "string") return null;
      return parsed;
    } catch (err) {
      console.warn(`${LOG_PREFIX} Failed to load conversation ${id}:`, err);
      return null;
    }
  }

  /**
   * List conversation metadata, newest first. Decrypts each envelope to read
   * its title/model/updatedAt. Skips any file that can't be decrypted or
   * parsed rather than failing the whole list.
   */
  async list(): Promise<ConversationMeta[]> {
    if (!this.cipher.isReady()) {
      this.logSoftFail("list");
      return [];
    }
    let names: string[];
    try {
      names = await this.adapter.list();
    } catch (err) {
      console.warn(`${LOG_PREFIX} Failed to list conversations:`, err);
      return [];
    }

    const metas: ConversationMeta[] = [];
    for (const name of names) {
      if (!name.endsWith(ENVELOPE_SUFFIX)) continue;
      try {
        const bytes = await this.adapter.readBinary(name);
        const plaintext = await this.cipher.decryptString(bytes);
        const convo = JSON.parse(plaintext) as Conversation;
        if (!convo || typeof convo.id !== "string") continue;
        metas.push({
          id: convo.id,
          title: convo.title,
          model: convo.model,
          updatedAt: convo.updatedAt,
        });
      } catch {
        // Skip undecryptable / corrupt envelopes silently — one bad file must
        // not break the history picker.
      }
    }
    metas.sort((a, b) => b.updatedAt - a.updatedAt);
    return metas;
  }

  /** Delete a conversation envelope. Idempotent; fail soft. */
  async delete(id: string): Promise<void> {
    try {
      await this.adapter.remove(this.fileName(id));
    } catch (err) {
      console.warn(`${LOG_PREFIX} Failed to delete conversation ${id}:`, err);
    }
  }

  /** Load the most-recently-updated conversation, or null if none. */
  async loadMostRecent(): Promise<Conversation | null> {
    const metas = await this.list();
    if (metas.length === 0) return null;
    return this.load(metas[0].id);
  }

  private fileName(id: string): string {
    // Defensive: ids are generated locally (see newConversationId) but never
    // let a stray separator escape the chat dir.
    const safe = id.replace(/[^a-zA-Z0-9_-]/g, "");
    return `${safe}${ENVELOPE_SUFFIX}`;
  }

  private logSoftFail(op: string): void {
    if (this.softFailLogged) return;
    this.softFailLogged = true;
    console.debug(
      `${LOG_PREFIX} At-rest key not ready — skipping conversation ${op} ` +
        "(chat continues; history won't persist until the LAK is unlocked).",
    );
  }
}

/** Generate a fresh, filesystem-safe conversation id. */
export function newConversationId(): string {
  const rand =
    typeof crypto !== "undefined" && typeof crypto.randomUUID === "function"
      ? crypto.randomUUID().replace(/-/g, "")
      : Math.random().toString(36).slice(2);
  return `${Date.now().toString(36)}-${rand.slice(0, 12)}`;
}

/** Default title for a not-yet-titled conversation. */
export function defaultTitle(firstUserText: string): string {
  const words = firstUserText.trim().split(/\s+/).slice(0, 6).join(" ");
  return words.length > 0 ? words : "New chat";
}

// ─── Per-leaf chat-tab state (multi-tab support) ─────────────────────────────
//
// A VaultGuardChatView leaf persists which conversation it is showing in its
// Obsidian view state (workspace.json) so multiple chat tabs each restore their
// OWN conversation. Only the non-secret conversation id travels here; the
// conversation CONTENT stays LAK-encrypted in ConversationStore.

export interface ChatLeafState {
  /** The conversation this leaf is bound to (null/absent → not yet chosen). */
  conversationId?: string | null;
  /** Set when the leaf was opened explicitly as a brand-new chat tab. */
  fresh?: boolean;
}

export type InitialConversation =
  | { mode: "load"; id: string }
  | { mode: "fresh" }
  | { mode: "recent" };

/**
 * Decide which conversation a freshly-opened chat leaf should show, from its
 * persisted view state. Pure (no Obsidian) so it is unit-testable:
 *   - a non-empty conversationId → load that specific conversation (a restored
 *     tab; takes precedence over `fresh` so a re-opened tab keeps its chat);
 *   - else `fresh === true` → start blank (user opened a new chat tab);
 *   - else → restore the most-recent conversation (legacy single-panel open,
 *     and the upgrade path for a pre-existing tab with no persisted id).
 */
export function pickInitialConversation(
  state: ChatLeafState | null | undefined,
): InitialConversation {
  const id = state?.conversationId;
  if (typeof id === "string" && id.length > 0) return { mode: "load", id };
  if (state?.fresh === true) return { mode: "fresh" };
  return { mode: "recent" };
}

export { ENVELOPE_SUFFIX };
