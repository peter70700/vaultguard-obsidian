import esbuild from "esbuild";
import process from "process";
import { existsSync, mkdirSync } from "fs";
import { builtinModules, createRequire } from "module";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

// Resolve runtime deps wherever they actually live. In a flat install that's
// <root>/node_modules; in the public monorepo's npm workspaces it's hoisted to
// the workspace root. Hardcoding <root>/node_modules/<dep> broke the monorepo
// release build (jszip is hoisted above packages/plugin) — require.resolve walks
// the node_modules chain and finds it in either layout.
const requireFromConfig = createRequire(import.meta.url);

// Node built-ins are available in Electron's CJS runtime — keep them external so
// esbuild doesn't try to bundle/polyfill them. The Tier-2 AI-chat streaming path
// (src/ui/chat/anthropic-stream.ts) imports the `https` builtin (the same Node
// networking layer Obsidian's requestUrl wraps; see CLAUDE.md Streaming
// exception). Cover both bare ("https") and prefixed ("node:https") specifiers.
const nodeBuiltins = [
  ...builtinModules,
  ...builtinModules.map((m) => `node:${m}`),
];

const banner = `/*
  VaultGuard Plugin
  Enterprise vault security with permission-aware encrypted cloud sync.
  THIS IS A GENERATED FILE - DO NOT EDIT DIRECTLY
*/`;

const prod = process.argv[2] === "production";
// One-shot dev build (`node esbuild.config.mjs dev`): builds once and exits 0,
// unlike no-arg `npm run dev` which watches. Resolves NODE_ENV to "development"
// (same as watch), so the dev-only diagnostic commands stay in this output —
// used by `install:plugin:dev` to put a diagnostics-enabled build in the vault.
const devBuild = process.argv[2] === "dev";
const rootDir = dirname(fileURLToPath(import.meta.url));

const safeDependencyAliases = {
  immediate: join(rootDir, "src", "shims", "immediate.cjs"),
  // require.resolve("jszip") → its package "main" (lib/index.js), resolved from
  // wherever jszip is installed (flat OR workspace-hoisted), so the monorepo
  // release build doesn't look under packages/plugin/node_modules.
  jszip: requireFromConfig.resolve("jszip"),
  setimmediate: join(rootDir, "src", "shims", "setimmediate.cjs"),
};

const safeDependencyAliasPlugin = {
  name: "vaultguard-safe-dependency-aliases",
  setup(build) {
    for (const [moduleName, replacement] of Object.entries(safeDependencyAliases)) {
      build.onResolve({ filter: new RegExp(`^${moduleName}(?:/.*)?$`) }, () => ({
        path: replacement,
      }));
    }
  },
};

// Ensure output directory exists
if (!existsSync("./dist")) {
  mkdirSync("./dist", { recursive: true });
}

const context = await esbuild.context({
  banner: {
    js: banner,
  },
  entryPoints: ["src/plugin/main.ts"],
  bundle: true,
  external: [
    "obsidian",
    "electron",
    ...nodeBuiltins,
    "@codemirror/autocomplete",
    "@codemirror/collab",
    "@codemirror/commands",
    "@codemirror/language",
    "@codemirror/lint",
    "@codemirror/search",
    "@codemirror/state",
    "@codemirror/view",
    "@lezer/common",
    "@lezer/highlight",
    "@lezer/lr",
  ],
  format: "cjs",
  target: "es2020",
  loader: {
    ".css": "text",
    ".md": "text",
  },
  logLevel: "info",
  plugins: [safeDependencyAliasPlugin],
  sourcemap: prod ? false : "inline",
  treeShaking: true,
  outfile: "main.js",
  minify: prod,
  define: {
    "process.env.NODE_ENV": prod ? '"production"' : '"development"',
  },
});

if (prod) {
  await context.rebuild();
  process.exit(0);
} else if (devBuild) {
  // One-shot dev build (not a watcher) — exits 0 so install:plugin:dev can chain.
  await context.rebuild();
  process.exit(0);
} else {
  await context.watch();
}
