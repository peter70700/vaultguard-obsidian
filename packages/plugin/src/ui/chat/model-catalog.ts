import type { AnthropicModelInfo } from "./anthropic-client";
import { AnthropicClient } from "./anthropic-client";
import type { OpenAiModelInfo } from "./openai-client";
import { OpenAiResponsesClient } from "./openai-client";
import {
  listCodexSubscriptionModels,
  type CodexSubscriptionModelInfo,
} from "./codex-cli/codex-model-discovery";
import {
  AI_CHAT_MODELS,
  OPENAI_CHAT_MODELS,
  humanizeModelId,
  type ChatModelOption,
} from "./models";

export type ProviderModelCatalogProvider = "anthropic" | "openai" | "codex";
export type ModelCatalogSource = "live" | "cache" | "fallback";

export const MODEL_CATALOG_CACHE_TTL_MS = 5 * 60 * 1000;
const MAX_CATALOG_MODELS = 100;
const MAX_MODEL_ID_LENGTH = 200;

export interface ResolveModelCatalogInput {
  provider: ProviderModelCatalogProvider;
  apiKey: string | null;
  codexBinaryPath?: string | null;
  selectedModel: string;
  preferNewest?: boolean;
  forceRefresh?: boolean;
  signal?: AbortSignal;
}

export interface ResolvedModelCatalog {
  provider: ProviderModelCatalogProvider;
  options: ReadonlyArray<ChatModelOption>;
  selectedModel: string;
  source: ModelCatalogSource;
  fetchedAt?: number;
  warning?: string;
}

export interface ProviderModelCatalogLoaders {
  loadAnthropic(apiKey: string): Promise<AnthropicModelInfo[]>;
  loadOpenAi(apiKey: string): Promise<OpenAiModelInfo[]>;
  loadCodex(binaryPath: string, signal?: AbortSignal): Promise<CodexSubscriptionModelInfo[]>;
}

interface CatalogCacheEntry {
  options: ReadonlyArray<ChatModelOption>;
  defaultModel?: string;
  fetchedAt: number;
  generation: number;
}

interface InFlightCatalog {
  generation: number;
  promise: Promise<LoadedCatalog | null>;
}

interface LoadedCatalog {
  options: ReadonlyArray<ChatModelOption>;
  defaultModel?: string;
}

const DEFAULT_LOADERS: ProviderModelCatalogLoaders = {
  loadAnthropic: (apiKey) =>
    new AnthropicClient({ apiKey, model: AI_CHAT_MODELS[0]?.id ?? "" }).listModels(),
  loadOpenAi: (apiKey) =>
    new OpenAiResponsesClient({ apiKey, model: OPENAI_CHAT_MODELS[0]?.id ?? "" }).listModels(),
  loadCodex: (binaryPath, signal) =>
    listCodexSubscriptionModels(binaryPath, { signal }),
};

export class ProviderModelCatalogService {
  private readonly cache = new Map<ProviderModelCatalogProvider, CatalogCacheEntry>();
  private readonly inFlight = new Map<ProviderModelCatalogProvider, InFlightCatalog>();
  private readonly generations: Record<ProviderModelCatalogProvider, number> = {
    anthropic: 0,
    openai: 0,
    codex: 0,
  };
  private readonly loaders: ProviderModelCatalogLoaders;

  constructor(
    loaders: Partial<ProviderModelCatalogLoaders> = DEFAULT_LOADERS,
    private readonly now: () => number = Date.now,
  ) {
    this.loaders = { ...DEFAULT_LOADERS, ...loaders };
  }

  invalidate(provider: ProviderModelCatalogProvider): void {
    this.generations[provider]++;
    this.cache.delete(provider);
    this.inFlight.delete(provider);
  }

  async resolve(input: ResolveModelCatalogInput): Promise<ResolvedModelCatalog> {
    const selectedModel = normalizeModelId(input.selectedModel);
    const fallback = () => mergeSelected(selectedModel, fallbackOptions(input.provider));
    const cached = this.cache.get(input.provider);
    const credential =
      input.provider === "codex" ? input.codexBinaryPath?.trim() : input.apiKey?.trim();

    if (!credential) {
      return {
        provider: input.provider,
        options: fallback(),
        selectedModel,
        source: "fallback",
      };
    }

    if (
      !input.forceRefresh &&
      cached &&
      cached.generation === this.generations[input.provider] &&
      this.now() - cached.fetchedAt < MODEL_CATALOG_CACHE_TTL_MS
    ) {
      return {
        provider: input.provider,
        ...resolveSelection(selectedModel, cached, input.preferNewest === true),
        source: "cache",
        fetchedAt: cached.fetchedAt,
      };
    }

    const generation = this.generations[input.provider];
    let request = this.inFlight.get(input.provider);
    if (!request || request.generation !== generation) {
      const promise = this.load(input.provider, credential, input.signal)
        .then((catalog) => {
          if (this.generations[input.provider] !== generation) return null;
          const fetchedAt = this.now();
          this.cache.set(input.provider, { ...catalog, fetchedAt, generation });
          return catalog;
        })
        .finally(() => {
          const current = this.inFlight.get(input.provider);
          if (current?.generation === generation) this.inFlight.delete(input.provider);
        });
      request = { generation, promise };
      this.inFlight.set(input.provider, request);
    }

    try {
      const options = await request.promise;
      if (!options) {
        return {
          provider: input.provider,
          options: fallback(),
          selectedModel,
          source: "fallback",
          warning: discoveryWarning(input.provider),
        };
      }
      return {
        provider: input.provider,
        ...resolveSelection(selectedModel, options, input.preferNewest === true),
        source: "live",
        fetchedAt: this.cache.get(input.provider)?.fetchedAt,
      };
    } catch {
      const safeCache = this.cache.get(input.provider);
      return {
        provider: input.provider,
        ...(safeCache
          ? resolveSelection(selectedModel, safeCache)
          : { options: fallback(), selectedModel }),
        source: safeCache ? "cache" : "fallback",
        fetchedAt: safeCache?.fetchedAt,
        warning: discoveryWarning(input.provider),
      };
    }
  }

  private async load(
    provider: ProviderModelCatalogProvider,
    credential: string,
    signal?: AbortSignal,
  ): Promise<LoadedCatalog> {
    if (provider === "openai") {
      return { options: normalizeOpenAiModels(await this.loaders.loadOpenAi(credential)) };
    }
    if (provider === "anthropic") {
      return { options: normalizeAnthropicModels(await this.loaders.loadAnthropic(credential)) };
    }
    return normalizeCodexModels(await this.loaders.loadCodex(credential, signal));
  }
}

export const providerModelCatalog = new ProviderModelCatalogService();

export function isOpenAiChatModelId(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const id = normalizeModelId(value).toLowerCase();
  if (!id || id.length > MAX_MODEL_ID_LENGTH) return false;
  const family = /^(?:ft:)?gpt-(\d+)(?:[.-]|$)/.exec(id);
  if (!family || Number(family[1]) < 5) return false;
  return !/(?:^|[-:])(codex|chat|realtime|audio|image|transcribe|tts|search)(?:-|$)/.test(id);
}

export function isAnthropicChatModel(value: unknown): value is AnthropicModelInfo {
  if (!value || typeof value !== "object") return false;
  const model = value as Partial<AnthropicModelInfo>;
  if (model.type !== "model") return false;
  const id = normalizeModelId(model.id);
  if (!id.startsWith("claude-") || id.length > MAX_MODEL_ID_LENGTH) return false;
  const capabilities = model.capabilities;
  if (!capabilities || typeof capabilities !== "object") return true;
  if (capabilities.effort?.supported === false) return false;
  if (capabilities.thinking?.supported === false) return false;
  if (capabilities.thinking?.types?.adaptive?.supported === false) return false;
  return true;
}

function normalizeOpenAiModels(models: ReadonlyArray<OpenAiModelInfo>): ChatModelOption[] {
  const sorted = models
    .filter(isOpenAiModelRecord)
    .sort((a, b) => numericCreated(b.created) - numericCreated(a.created));
  return dedupeOptions(
    sorted
      .filter((model) => isOpenAiChatModelId(model?.id))
      .map((model) => ({ id: normalizeModelId(model.id), label: humanizeModelId(model.id) })),
  );
}

function normalizeAnthropicModels(models: ReadonlyArray<AnthropicModelInfo>): ChatModelOption[] {
  const sorted = [...models].sort(
    (a, b) => Date.parse(b?.created_at ?? "") - Date.parse(a?.created_at ?? ""),
  );
  return dedupeOptions(
    sorted.filter(isAnthropicChatModel).map((model) => ({
      id: normalizeModelId(model.id),
      label:
        typeof model.display_name === "string" && model.display_name.trim()
          ? model.display_name.trim()
          : humanizeModelId(model.id),
    })),
  );
}

function normalizeCodexModels(
  models: ReadonlyArray<CodexSubscriptionModelInfo>,
): LoadedCatalog {
  const valid = models
    .filter(isCodexModelRecord)
    .sort(compareCodexModelRecency);
  const options = dedupeOptions(
    valid.map((model) => ({
      id: normalizeModelId(model.model),
      label:
        typeof model.displayName === "string" && model.displayName.trim()
          ? model.displayName.trim()
          : humanizeModelId(model.model),
    })),
  );
  const defaultModel = options[0]?.id;
  return { options, ...(defaultModel ? { defaultModel } : {}) };
}

function compareCodexModelRecency(
  left: CodexSubscriptionModelInfo,
  right: CodexSubscriptionModelInfo,
): number {
  const leftVersion = parseGptVersion(left.model);
  const rightVersion = parseGptVersion(right.model);
  if (!leftVersion) return rightVersion ? 1 : 0;
  if (!rightVersion) return -1;
  const length = Math.max(leftVersion.length, rightVersion.length);
  for (let index = 0; index < length; index++) {
    const difference = (rightVersion[index] ?? 0) - (leftVersion[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return 0;
}

function parseGptVersion(model: string): number[] | null {
  const match = /^gpt-(\d+(?:\.\d+)*)(?:-|$)/i.exec(model.trim());
  return match ? match[1].split(".").map((part) => Number.parseInt(part, 10)) : null;
}

function isCodexModelRecord(value: unknown): value is CodexSubscriptionModelInfo {
  if (!value || typeof value !== "object") return false;
  const model = value as Partial<CodexSubscriptionModelInfo>;
  const id = normalizeModelId(model.id);
  const requestModel = normalizeModelId(model.model);
  return (
    id.length > 0 &&
    id.length <= MAX_MODEL_ID_LENGTH &&
    requestModel.length > 0 &&
    requestModel.length <= MAX_MODEL_ID_LENGTH &&
    model.hidden !== true
  );
}

function isOpenAiModelRecord(value: unknown): value is OpenAiModelInfo {
  return (
    !!value &&
    typeof value === "object" &&
    (value as Partial<OpenAiModelInfo>).object === "model" &&
    typeof (value as Partial<OpenAiModelInfo>).id === "string"
  );
}

function numericCreated(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function normalizeModelId(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function dedupeOptions(options: ReadonlyArray<ChatModelOption>): ChatModelOption[] {
  const seen = new Set<string>();
  const result: ChatModelOption[] = [];
  for (const option of options) {
    if (!option.id || seen.has(option.id)) continue;
    seen.add(option.id);
    result.push(option);
    if (result.length >= MAX_CATALOG_MODELS) break;
  }
  return result;
}

function mergeSelected(
  selectedModel: string,
  options: ReadonlyArray<ChatModelOption>,
): ReadonlyArray<ChatModelOption> {
  if (!selectedModel || options.some((option) => option.id === selectedModel)) return options;
  return [
    { id: selectedModel, label: `${humanizeModelId(selectedModel)} (current)` },
    ...options,
  ].slice(0, MAX_CATALOG_MODELS);
}

function resolveSelection(
  selectedModel: string,
  catalog: Pick<LoadedCatalog, "options" | "defaultModel">,
  preferNewest = false,
): { options: ReadonlyArray<ChatModelOption>; selectedModel: string } {
  const selectedAvailable = catalog.options.some((option) => option.id === selectedModel);
  const defaultAvailable =
    !!catalog.defaultModel && catalog.options.some((option) => option.id === catalog.defaultModel);
  const newestAvailable = catalog.options[0]?.id;
  const resolved =
    preferNewest && newestAvailable
      ? newestAvailable
      : selectedAvailable
        ? selectedModel
        : defaultAvailable
          ? catalog.defaultModel!
          : selectedModel;
  return { options: mergeSelected(resolved, catalog.options), selectedModel: resolved };
}

function fallbackOptions(provider: ProviderModelCatalogProvider): ReadonlyArray<ChatModelOption> {
  if (provider === "anthropic") return AI_CHAT_MODELS;
  // A ChatGPT subscription catalog is account- and workspace-specific. Never
  // present the API-key provider's bundled choices as if Codex reported them.
  // mergeSelected() still preserves the user's saved value as an explicitly
  // unverified current selection when live discovery is unavailable.
  return provider === "codex" ? [] : OPENAI_CHAT_MODELS;
}

function discoveryWarning(provider: ProviderModelCatalogProvider): string {
  if (provider === "codex") {
    return "Could not refresh ChatGPT subscription models; showing only the saved selection.";
  }
  const label = provider === "openai" ? "OpenAI" : "Anthropic";
  return `Could not refresh ${label} models; using the current and saved fallback choices.`;
}
