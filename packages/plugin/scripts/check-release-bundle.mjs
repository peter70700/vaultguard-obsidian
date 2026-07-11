import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const rootDir = resolve(fileURLToPath(new URL("..", import.meta.url)));
const bundlePath = join(rootDir, "main.js");
const bundle = readFileSync(bundlePath, "utf8");

const forbiddenPatterns = [
  {
    label: "dynamic script element creation",
    pattern: /createElement\s*\(\s*["']script["']\s*\)/g,
  },
  {
    label: "dynamic script element creation",
    pattern: /createElement\s*\(\s*`script`\s*\)/g,
  },
];

const forbiddenStrings = [
  "vaultguard-debug-permissions-graph-virtual-qa",
  "VaultGuard (debug): Open virtual permissions graph QA",
  "Virtual permissions graph synthetic QA",
  "Use a disposable vault for synthetic QA only.",
];

const hits = [];

for (const { label, pattern } of forbiddenPatterns) {
  let match = pattern.exec(bundle);
  while (match !== null) {
    hits.push({
      label,
      index: match.index,
      snippet: snippetAt(bundle, match.index),
    });
    match = pattern.exec(bundle);
  }
}

for (const forbidden of forbiddenStrings) {
  let index = bundle.indexOf(forbidden);
  while (index >= 0) {
    hits.push({
      label: `development-only string: ${forbidden}`,
      index,
      snippet: snippetAt(bundle, index),
    });
    index = bundle.indexOf(forbidden, index + forbidden.length);
  }
}

if (hits.length > 0) {
  console.error(`Release bundle check failed: found ${hits.length} forbidden pattern(s).`);
  for (const hit of hits) {
    console.error(`- ${hit.label} at byte ${hit.index}: ${hit.snippet}`);
  }
  process.exit(1);
}

console.log("Release bundle check passed.");

function snippetAt(text, index) {
  const start = Math.max(0, index - 90);
  const end = Math.min(text.length, index + 160);
  return text.slice(start, end).replace(/\s+/g, " ");
}
