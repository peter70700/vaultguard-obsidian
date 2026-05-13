/**
 * Builds all Lambda handlers into self-contained JS bundles.
 * Each Lambda gets its own output directory with a single handler.js
 * that includes all dependencies (AWS SDK v3, shared utils, etc.).
 */

import * as esbuild from "esbuild";
import { mkdirSync, rmSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

const LAMBDAS = [
  { name: "auth", entry: "lambda/auth/handler.ts" },
  { name: "files", entry: "lambda/files/handler.ts" },
  { name: "permissions", entry: "lambda/permissions/handler.ts" },
  { name: "audit", entry: "lambda/audit/handler.ts" },
  { name: "users", entry: "lambda/users/handler.ts" },
  { name: "signup", entry: "lambda/signup/handler.ts" },
  { name: "billing", entry: "lambda/billing/handler.ts" },
  { name: "reencryption", entry: "lambda/reencryption/handler.ts" },
  { name: "reconciler", entry: "lambda/reconciler/handler.ts" },
  { name: "email", entry: "lambda/email/handler.ts" },
  { name: "vaults", entry: "lambda/vaults/handler.ts" },
  { name: "shares", entry: "lambda/shares/handler.ts" },
];

const outBase = resolve(__dirname, "dist");

// Clean previous build
rmSync(outBase, { recursive: true, force: true });

for (const lambda of LAMBDAS) {
  const outdir = resolve(outBase, lambda.name);
  mkdirSync(outdir, { recursive: true });

  await esbuild.build({
    entryPoints: [resolve(__dirname, lambda.entry)],
    bundle: true,
    platform: "node",
    target: "node22",
    format: "cjs",
    outfile: resolve(outdir, "handler.js"),
    sourcemap: true,
    minify: false, // Keep readable for debugging
    external: [
      // These are available in the Lambda runtime, no need to bundle
      // (but we DO bundle @aws-sdk/* since Lambda Node 22 includes v3
      //  but specific sub-packages may differ)
    ],
  });

  console.log(`Built: ${lambda.name} -> dist/${lambda.name}/handler.js`);
}

console.log("\nAll Lambdas built successfully.");
