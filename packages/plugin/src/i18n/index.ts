import { getLanguage } from "obsidian";
import {
  ARABIC_MESSAGES,
  ENGLISH_MESSAGES,
  SLOVAK_MESSAGES,
  type MessageCatalog,
  type MessageKey,
} from "./locales";

export type SupportedLocale = "en" | "sk" | "ar";
export type TextDirection = "ltr" | "rtl";
export type TranslationParams = Record<string, unknown>;

const CATALOGS: Record<SupportedLocale, MessageCatalog> = {
  en: ENGLISH_MESSAGES,
  sk: SLOVAK_MESSAGES,
  ar: ARABIC_MESSAGES,
};
const RTL_LANGUAGES = new Set(["ar", "dv", "fa", "he", "ku", "ps", "ur", "yi"]);

export function normalizeLanguageTag(language: unknown): string {
  if (typeof language !== "string") return "en";
  const normalized = language.trim().toLowerCase().replace(/_/g, "-");
  return normalized || "en";
}

export function resolveLocale(language: unknown): SupportedLocale {
  const primary = normalizeLanguageTag(language).split("-")[0];
  return primary === "sk" || primary === "ar" ? primary : "en";
}

export function resolveDirection(language: unknown): TextDirection {
  const primary = normalizeLanguageTag(language).split("-")[0];
  return RTL_LANGUAGES.has(primary) ? "rtl" : "ltr";
}

function safeInterpolationValue(value: unknown): string {
  if (typeof value !== "string" && typeof value !== "number" && typeof value !== "boolean") {
    return "";
  }
  return String(value)
    .replace(/[<>]/g, "")
    .replace(/[\u0000-\u001F\u007F]/g, "");
}

export function translate(
  key: MessageKey | string,
  params: TranslationParams = {},
  language: unknown = "en",
): string {
  const locale = resolveLocale(language);
  const english = ENGLISH_MESSAGES[key as MessageKey] ?? ENGLISH_MESSAGES["common.unknown"];
  const template = CATALOGS[locale][key as MessageKey] ?? english;
  return template.replace(/\{([a-zA-Z0-9_]+)\}/g, (_match, name: string) =>
    safeInterpolationValue(params[name])
  );
}

function currentLanguage(): string {
  try {
    return typeof getLanguage === "function" ? getLanguage() : "en";
  } catch {
    return "en";
  }
}

export interface I18nContext {
  locale: SupportedLocale;
  direction: TextDirection;
  t(key: MessageKey | string, params?: TranslationParams): string;
  applyToRoot(root: HTMLElement): void;
}

export function createI18n(language: unknown = currentLanguage()): I18nContext {
  const normalized = normalizeLanguageTag(language);
  const locale = resolveLocale(normalized);
  const direction = resolveDirection(normalized);
  return {
    locale,
    direction,
    t: (key, params) => translate(key, params, normalized),
    applyToRoot(root) {
      const target = root as HTMLElement & {
        setAttr?: (name: string, value: string) => void;
      };
      if (typeof target.setAttribute === "function") {
        target.setAttribute("lang", locale);
        target.setAttribute("dir", direction);
      } else if (typeof target.setAttr === "function") {
        // Obsidian's HTMLElement helpers and lightweight test doubles may expose
        // setAttr without the browser-native method.
        target.setAttr("lang", locale);
        target.setAttr("dir", direction);
      }
      target.classList?.toggle?.("vaultguard-rtl", direction === "rtl");
    },
  };
}

export type { MessageKey } from "./locales";
