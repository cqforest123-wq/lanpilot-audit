import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const app = readFileSync(join(root, "src", "App.tsx"), "utf8");
const visibleLiteral = app.split("\n")
  .filter((line) => !line.includes("RawDetail") && !line.includes("<pre"))
  .flatMap((line) => line.match(/>[A-Za-z][^<{]*\s+[A-Za-z][^<{]*</g) ?? [])
  .filter((value) => value !== ">LANPilot Audit<");
if (visibleLiteral.length) {
  console.error("Possible visible English literals in App.tsx:");
  visibleLiteral.forEach((value) => console.error(value.trim()));
  process.exit(1);
}
console.log("Strict UI hardcoded-English check passed.");
