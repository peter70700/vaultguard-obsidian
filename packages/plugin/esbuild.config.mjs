import esbuild from "esbuild";
import process from "process";
import { existsSync, mkdirSync } from "fs";
import { builtinModules } from "module";

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
} else {
  await context.watch();
}
