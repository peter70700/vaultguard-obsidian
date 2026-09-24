/** Terraform external-data protocol: JSON on stdout; failures on stderr. */
import { readFileSync } from "node:fs";
import { verifyBuild } from "./lambda-build-provenance.mjs";

try {
  const { infrastructure } = JSON.parse(readFileSync(0, "utf8"));
  if (typeof infrastructure !== "string" || !infrastructure) throw new Error("Missing infrastructure directory.");
  process.stdout.write(JSON.stringify(verifyBuild(infrastructure)));
} catch (error) {
  console.error(`Lambda build guard: ${error.message}`);
  process.exitCode = 1;
}
