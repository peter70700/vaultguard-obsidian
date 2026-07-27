import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

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

const zip = createZipArchive();

if (zip.error) {
  throw new Error(`Failed to run archive tool: ${zip.error.message}`);
}

if (zip.status !== 0) {
  throw new Error(`Archive tool exited with status ${zip.status}`);
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

function createZipArchive() {
  const assetPaths = requiredAssets.map((asset) => join(rootDir, asset));

  if (process.platform === "win32") {
    const files = assetPaths.map(toPowerShellLiteral).join(", ");
    const command = [
      "$ErrorActionPreference = 'Stop'",
      `$files = @(${files})`,
      `Compress-Archive -LiteralPath $files -DestinationPath ${toPowerShellLiteral(zipPath)} -CompressionLevel Optimal -Force`,
    ].join("; ");

    return spawnSync(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", command],
      { cwd: rootDir, stdio: "inherit", windowsHide: true }
    );
  }

  return spawnSync("zip", ["-j", "-X", zipPath, ...assetPaths], {
    cwd: rootDir,
    stdio: "inherit",
    windowsHide: true,
  });
}

function toPowerShellLiteral(value) {
  return `'${value.replace(/'/g, "''")}'`;
}
