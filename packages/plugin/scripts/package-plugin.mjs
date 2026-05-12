import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync } from "fs";
import { spawnSync } from "child_process";
import { dirname, join, resolve } from "path";
import { fileURLToPath } from "url";

const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const packageJson = readJson("package.json");
const manifest = readJson("manifest.json");
const versions = readJson("versions.json");

const requiredAssets = ["main.js", "manifest.json", "styles.css"];
const outDir = join(rootDir, "dist", manifest.id);
const zipPath = join(rootDir, "dist", `${manifest.id}-${manifest.version}.zip`);

validateReleaseMetadata();
validateAssets();

rmSync(outDir, { recursive: true, force: true });
mkdirSync(outDir, { recursive: true });

for (const asset of requiredAssets) {
  copyFileSync(join(rootDir, asset), join(outDir, asset));
}

rmSync(zipPath, { force: true });

const zip = spawnSync(
  "zip",
  ["-j", "-X", zipPath, ...requiredAssets.map((asset) => join(rootDir, asset))],
  { cwd: rootDir, stdio: "inherit" }
);

if (zip.error) {
  throw new Error(`Failed to run zip: ${zip.error.message}`);
}

if (zip.status !== 0) {
  throw new Error(`zip exited with status ${zip.status}`);
}

console.log(`Packaged ${manifest.name} ${manifest.version}`);
console.log(`Assets: ${outDir}`);
console.log(`Zip: ${zipPath}`);

function readJson(relativePath) {
  return JSON.parse(readFileSync(join(rootDir, relativePath), "utf8"));
}

function validateReleaseMetadata() {
  if (packageJson.version !== manifest.version) {
    throw new Error(
      `package.json version (${packageJson.version}) must match manifest.json version (${manifest.version}).`
    );
  }

  if (versions[manifest.version] !== manifest.minAppVersion) {
    throw new Error(
      `versions.json must map ${manifest.version} to minAppVersion ${manifest.minAppVersion}.`
    );
  }
}

function validateAssets() {
  for (const asset of requiredAssets) {
    if (!existsSync(join(rootDir, asset))) {
      throw new Error(`Missing ${asset}. Run npm run build before packaging.`);
    }
  }
}
