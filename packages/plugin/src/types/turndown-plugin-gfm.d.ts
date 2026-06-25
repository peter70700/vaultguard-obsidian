/**
 * Ambient type shim for `turndown-plugin-gfm` (MIT), which ships no type
 * definitions and has no `@types/turndown-plugin-gfm` package. The plugins are
 * Turndown `Plugin` functions applied via `turndownService.use(plugin)`.
 *
 * Added for quick task 260622-sd2 (local file import) — the HTML→Markdown
 * converter uses `gfm` for GFM tables / strikethrough / task lists.
 */
declare module "turndown-plugin-gfm" {
  import type TurndownService from "turndown";

  /** A Turndown plugin: receives the service and registers rules. */
  type Plugin = TurndownService.Plugin;

  /** Bundle of all GFM rules (tables + strikethrough + task list items). */
  export const gfm: Plugin;
  export const tables: Plugin;
  export const strikethrough: Plugin;
  export const taskListItems: Plugin;
  export const highlightedCodeBlock: Plugin;
}
