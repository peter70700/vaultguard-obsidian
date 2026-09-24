/** Prepare a retained, clean checkout. Planning requires an explicit --plan. */
import { execFileSync } from "node:child_process";
import { existsSync, realpathSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { assertNode, checkoutIdentity, verifyBuild } from "./lambda-build-provenance.mjs";

const infrastructure = realpathSync(dirname(fileURLToPath(import.meta.url)));
const args = process.argv.slice(2);
const options = {};
try {
  for (let i = 0; i < args.length; i++) {
    const key = args[i];
    if (key === "--plan") options.plan = true;
    else if (["--commit", "--worktree", "--var-file", "--backend-config"].includes(key) && args[i + 1] && !args[i + 1].startsWith("--")) options[key.slice(2)] = args[++i];
    else throw new Error("Usage: node infrastructure/plan-lambdas.mjs --commit <recorded-ref> --worktree <new-absolute-directory> [--plan --var-file <absolute-file> [--backend-config <absolute-file>]]");
  }
  if (!options.commit || !isAbsolute(options.worktree ?? "") || existsSync(options.worktree)) throw new Error("Provide --commit and a new absolute --worktree directory. Existing worktrees are never reused or removed.");
  for (const key of ["var-file", "backend-config"]) if (options[key] && !isAbsolute(options[key])) throw new Error(`--${key} must be an absolute operator-owned file path.`);
  if (options.plan && !options["var-file"]) throw new Error("--plan requires an explicit --var-file; there is no default deployment environment.");
  assertNode(infrastructure);
  if (!checkoutIdentity(infrastructure).clean) throw new Error("Source checkout is dirty or unrecorded. Commit source changes before preparing a deployment.");
  const git = (...argv) => execFileSync("git", ["-C", infrastructure, ...argv], { encoding: "utf8" }).trim();
  const root = git("rev-parse", "--show-toplevel");
  const commit = git("rev-parse", "--verify", "--end-of-options", `${options.commit}^{commit}`);
  git("worktree", "add", "--detach", options.worktree, commit);
  const laneInfrastructure = resolve(options.worktree, relative(root, infrastructure));
  const run = (program, argv, cwd) => execFileSync(program, argv, { cwd, stdio: "inherit" });
  // npm's JavaScript CLI avoids shell interpolation and works with spaces in
  // checkout paths. npm run supplies npm_execpath; direct invocation discovers
  // the standard Node installation layout.
  const npmCli = process.env.npm_execpath ?? resolve(dirname(process.execPath), process.platform === "win32" ? "node_modules/npm/bin/npm-cli.js" : "../lib/node_modules/npm/bin/npm-cli.js");
  if (!existsSync(npmCli)) throw new Error("Run this command through npm run deploy:plan so npm supplies its CLI path.");
  const npm = (argv, cwd) => run(process.execPath, [npmCli, ...argv], cwd);
  // The private build needs the contracts workspace for its TypeScript gate;
  // exported standalone / public-monorepo servers do not contain that package.
  if (existsSync(join(laneInfrastructure, "../packages/workspace-contracts/package.json"))) npm(["ci", "--no-audit", "--no-fund"], dirname(laneInfrastructure));
  npm(["ci", "--no-audit", "--no-fund"], laneInfrastructure);
  assertNode(laneInfrastructure);
  npm(["run", "build"], laneInfrastructure);
  const proof = verifyBuild(laneInfrastructure);
  if (proof.commit !== commit) throw new Error("Prepared checkout no longer matches the requested commit.");
  const terraform = resolve(laneInfrastructure, "../terraform");
  console.log(`Prepared commit ${commit}. Retain this worktree and its .build artifacts until any saved plan is applied or discarded: ${options.worktree}`);
  if (options.plan) {
    const initArgs = ["init", "-input=false"];
    if (options["backend-config"]) initArgs.push(`-backend-config=${options["backend-config"]}`);
    run("terraform", initArgs, terraform);
    // Terraform init can create its provider lockfile. It must already be
    // committed or ignored by the chosen source tree, never silently admitted.
    verifyBuild(laneInfrastructure);
    run("terraform", ["plan", "-input=false", `-var-file=${options["var-file"]}`, "-out=tfplan"], terraform);
  }
} catch (error) {
  console.error(`Clean Lambda planning failed: ${error.message}`);
  process.exitCode = 1;
}
