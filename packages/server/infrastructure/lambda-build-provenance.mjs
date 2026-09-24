/** Local build provenance. No AWS calls, Git contents, or environment inputs. */
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";

export const MANIFEST = "build-manifest.json";
export const BUILD_INFO = "build-info.json";
const hash = (value) => createHash("sha256").update(value).digest("hex");
const git = (cwd, ...args) => execFileSync("git", ["-C", cwd, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();

export function assertNode(infrastructure) {
  const expected = readFileSync(join(infrastructure, ".nvmrc"), "utf8").trim();
  if (process.versions.node !== expected) throw new Error(`Lambda builds require Node ${expected}; found ${process.versions.node}. Run nvm use in infrastructure/.`);
}

export function checkoutIdentity(infrastructure) {
  try {
    infrastructure = realpathSync(infrastructure);
    const root = git(infrastructure, "rev-parse", "--show-toplevel");
    // An ignored export directory inside a private checkout is not the
    // private commit's source. Its own Git checkout must track the build pin.
    git(root, "ls-files", "--error-unmatch", "--", relative(root, join(infrastructure, ".nvmrc")));
    return {
      commit: git(root, "rev-parse", "HEAD"),
      tree: git(root, "rev-parse", "HEAD^{tree}"),
      clean: git(root, "status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none") === "",
    };
  } catch {
    // Export/build smoke checks can run outside Git, but cannot be deployed.
    return { commit: null, tree: null, clean: false };
  }
}

function inventory(directory) {
  const result = {};
  function visit(dir, prefix = "") {
    for (const name of readdirSync(dir).sort()) {
      const path = join(dir, name);
      const key = prefix + name;
      const stat = lstatSync(path);
      if (stat.isSymbolicLink()) throw new Error("Lambda artifact contains a symbolic link; rebuild it.");
      if (stat.isDirectory()) visit(path, `${key}/`);
      else if (stat.isFile()) result[key] = hash(readFileSync(path));
      else throw new Error("Lambda artifact contains a non-regular file; rebuild it.");
    }
  }
  if (!lstatSync(directory).isDirectory() || lstatSync(directory).isSymbolicLink()) throw new Error("Lambda artifact directory must be a real directory.");
  visit(directory);
  return result;
}

function sameFiles(actual, expected) {
  return JSON.stringify(actual) === JSON.stringify(expected);
}

export function recordBuild(infrastructure, names, before, sourceInputs = []) {
  const after = checkoutIdentity(infrastructure);
  let trackedInputs = true;
  try {
    const root = git(infrastructure, "rev-parse", "--show-toplevel");
    for (const input of sourceInputs) {
      git(root, "ls-files", "--error-unmatch", "--", relative(root, realpathSync(input)));
    }
  } catch { trackedInputs = false; }
  const identity = { ...before, clean: trackedInputs && before.clean && after.clean && before.commit === after.commit && before.tree === after.tree };
  const artifacts = {};
  for (const name of [...names].sort()) {
    const dir = join(infrastructure, "dist", name);
    writeFileSync(join(dir, BUILD_INFO), `${JSON.stringify({ schema: 1, ...identity, node: process.versions.node, lambda: name }, null, 2)}\n`);
    artifacts[name] = inventory(dir);
  }
  const manifest = { schema: 1, ...identity, node: process.versions.node, artifacts };
  const digest = hash(JSON.stringify(manifest));
  // Retain old snapshots so a subsequent build cannot replace a saved plan's
  // input. Only the builder writes these content-addressed directories.
  const snapshot = join(infrastructure, ".build", "lambdas", digest);
  for (const name of Object.keys(artifacts)) {
    const target = join(snapshot, name);
    if (!existsSync(target)) {
      mkdirSync(dirname(target), { recursive: true });
      cpSync(join(infrastructure, "dist", name), target, { recursive: true });
    }
    if (!sameFiles(inventory(target), artifacts[name])) throw new Error("Recorded Lambda snapshot was modified; remove that generated snapshot and rebuild.");
  }
  // Publish the complete manifest last: interrupted builds cannot be packaged.
  writeFileSync(join(infrastructure, "dist", MANIFEST), `${JSON.stringify(manifest, null, 2)}\n`);
  return manifest;
}

export function verifyBuild(infrastructure) {
  infrastructure = resolve(infrastructure);
  assertNode(infrastructure);
  const current = checkoutIdentity(infrastructure);
  if (!current.clean) throw new Error("Lambda packaging refused: checkout is dirty or has no recorded Git commit. Commit source changes and rebuild from a clean checkout.");
  const path = join(infrastructure, "dist", MANIFEST);
  if (!existsSync(path)) throw new Error("Lambda packaging refused: build manifest missing. Run npm run build:lambdas in infrastructure/.");
  const manifest = JSON.parse(readFileSync(path, "utf8"));
  if (manifest.schema !== 1 || manifest.clean !== true || manifest.commit !== current.commit || manifest.tree !== current.tree || manifest.node !== process.versions.node) {
    throw new Error("Lambda packaging refused: build is dirty, stale, or from another commit/runtime. Rebuild this clean commit.");
  }
  if (!manifest.artifacts || Object.keys(manifest.artifacts).length === 0) throw new Error("Lambda packaging refused: artifact inventory missing.");
  const digest = hash(JSON.stringify(manifest));
  const snapshot = join(infrastructure, ".build", "lambdas", digest);
  for (const [name, files] of Object.entries(manifest.artifacts)) {
    if (!/^[a-z][a-z0-9-]*$/.test(name) || !files[BUILD_INFO] || !files["handler.js"] || !files["handler.js.map"]) throw new Error("Lambda packaging refused: malformed artifact inventory.");
    for (const base of [join(infrastructure, "dist"), snapshot]) {
      if (!sameFiles(inventory(join(base, name)), files)) throw new Error(`Lambda packaging refused: ${name} artifact was modified or is incomplete. Rebuild it.`);
    }
    const info = JSON.parse(readFileSync(join(snapshot, name, BUILD_INFO), "utf8"));
    if (info.commit !== current.commit || info.tree !== current.tree || info.clean !== true || info.lambda !== name) throw new Error("Lambda packaging refused: embedded provenance mismatch.");
  }
  if (JSON.stringify(checkoutIdentity(infrastructure)) !== JSON.stringify(current)) throw new Error("Lambda packaging refused: checkout changed during verification.");
  return { commit: current.commit, digest, directory: snapshot };
}
