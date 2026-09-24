/**
 * Builds all Lambda handlers into self-contained JS bundles.
 * Each Lambda gets its own output directory with a single handler.js
 * that includes all dependencies (AWS SDK v3, shared utils, etc.).
 */

import * as esbuild from "esbuild";
import { existsSync, mkdirSync, rmSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { assertNode, checkoutIdentity, recordBuild } from "./lambda-build-provenance.mjs";

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
  { name: "workspace-recovery", entry: "lambda/workspace-recovery/handler.ts" },
  { name: "workspace-projection", entry: "lambda/workspace-projection/handler.ts" },
  { name: "workspace-operator", entry: "lambda/workspace-operator/handler.ts" },
  { name: "workspace-migration", entry: "lambda/workspace-migration/handler.ts" },
  // Reusable P4 domain bundle; no HTTP handler or deployed function is created.
  { name: "workspace-collaboration", entry: "lambda/workspace-collaboration/index.ts" },
  { name: "workspace-access", entry: "lambda/workspace-access/index.ts" },
  { name: "workspace-apply", entry: "lambda/workspace-apply/index.ts" },
  { name: "workspace-publication", entry: "lambda/workspace-publication/index.ts" },
  { name: "workspace-conflicts", entry: "lambda/workspace-conflicts/index.ts" },
  { name: "workspace-approvals", entry: "lambda/workspace-approvals/index.ts" },
  { name: "workspace-proposals", entry: "lambda/workspace-proposals/index.ts" },
  { name: "reconciler", entry: "lambda/reconciler/handler.ts" },
  { name: "detector", entry: "lambda/detector/handler.ts" },
  { name: "email", entry: "lambda/email/handler.ts" },
  { name: "vaults", entry: "lambda/vaults/handler.ts" },
  { name: "shares", entry: "lambda/shares/handler.ts" },
  { name: "superadmin", entry: "lambda/superadmin/handler.ts" },
  // VAULTGUARD-49 / ADR-003: VaultGuard's own connector authorization server.
  // Production stopped naming Cognito because a Cognito discovery document can
  // never advertise `offline_access`, which ChatGPT connectors check for.
  { name: "connector-oauth", entry: "lambda/connector-oauth/handler.ts" },
  { name: "mcp-read", entry: "lambda/mcp-read/handler.ts" },
  { name: "mcp-write", entry: "lambda/mcp-write/handler.ts" },
  { name: "workspace-web", entry: "lambda/workspace-web/handler.ts" },
];

const outBase = resolve(__dirname, "dist");
assertNode(__dirname);
const identity = checkoutIdentity(__dirname);
const contractsSource = resolve(__dirname, "../packages/workspace-contracts/src/index.ts");
const sourceInputs = new Set(["build-lambdas.mjs", "lambda-build-provenance.mjs", "package.json", "package-lock.json", ".nvmrc"].map((file) => resolve(__dirname, file)));

// Clean previous build
rmSync(outBase, { recursive: true, force: true });

for (const lambda of LAMBDAS) {
  const outdir = resolve(outBase, lambda.name);
  mkdirSync(outdir, { recursive: true });

  const result = await esbuild.build({
    entryPoints: [resolve(__dirname, lambda.entry)],
    bundle: true,
    platform: "node",
    target: "node22",
    format: "cjs",
    outfile: resolve(outdir, "handler.js"),
    sourcemap: true,
    metafile: true,
    minify: false, // Keep readable for debugging
    // Bundle tracked source, never a stale ignored workspace dist directory.
    // The Community server does not import or ship this private package.
    alias: existsSync(contractsSource) ? { "@vaultguard/workspace-contracts": contractsSource } : {},
    external: [
      // These are available in the Lambda runtime, no need to bundle
      // (but we DO bundle @aws-sdk/* since Lambda Node 22 includes v3
      //  but specific sub-packages may differ)
    ],
  });
  for (const input of Object.keys(result.metafile.inputs)) {
    if (!input.replaceAll("\\", "/").split("/").includes("node_modules")) sourceInputs.add(resolve(input));
  }

  console.log(`Built: ${lambda.name} -> dist/${lambda.name}/handler.js`);
}

const manifest = recordBuild(__dirname, LAMBDAS.map(({ name }) => name), identity, [...sourceInputs]);
console.log(`\nAll Lambdas built successfully. Source: ${manifest.commit ?? "unrecorded"}; deployable: ${manifest.clean}.`);
