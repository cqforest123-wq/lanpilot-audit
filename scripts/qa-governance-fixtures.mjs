import { createHash } from "node:crypto";
import { readFileSync, readdirSync, statSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const fixtures = join(root, "tests", "fixtures");
const required = {
  "lab-basic": ["network-issues-register.csv", "asset-inventory.csv", "service-exposure-matrix.csv", "local-network-config.json", "remediation-tracking.json"],
  "lab-with-duplicates": ["network-issues-register.csv"],
  "lab-with-web-tls": ["web-baseline.csv", "tls-certificates.csv"],
  "lab-with-mdns": ["mdns-services.csv"],
  "lab-two-snapshots": ["snapshot-diff.json"],
};
const failures = [];
for (const [directory, files] of Object.entries(required)) {
  for (const file of files) {
    const path = join(fixtures, directory, file);
    try { if (!statSync(path).isFile()) failures.push(`Not a file: ${path}`); } catch { failures.push(`Missing: ${path}`); }
  }
}
const duplicateCsv = readFileSync(join(fixtures, "lab-with-duplicates", "network-issues-register.csv"), "utf8").trim().split(/\r?\n/);
const unique = new Set(duplicateCsv.slice(1));
if (unique.size !== 1 || duplicateCsv.length !== 3) failures.push("Duplicate risk fixture does not prove de-duplication input.");
for (const file of ["local-network-config.json", "remediation-tracking.json"]) JSON.parse(readFileSync(join(fixtures, "lab-basic", file), "utf8"));
JSON.parse(readFileSync(join(fixtures, "lab-two-snapshots", "snapshot-diff.json"), "utf8"));
const raw = readFileSync(join(fixtures, "lab-basic", "raw-evidence.txt"), "utf8");
if (!raw.includes("Raw evidence remains in English.")) failures.push("Raw evidence fixture was changed.");
const digest = createHash("sha256").update(readdirSync(fixtures).sort().join("\n")).digest("hex");
mkdirSync(join(root, "docs", "nightly"), { recursive: true });
writeFileSync(join(root, "docs", "nightly", "v1.4.0-governance-fixture-qa.md"), `# v1.4.0 Governance Fixture QA

- Result: ${failures.length ? "FAIL" : "PASS"}
- Fixture sets: ${Object.keys(required).join(", ")}
- Fixture index SHA-256: \`${digest}\`
- Coverage: risk de-duplication, assets, exposure, local configuration, mDNS, Web/TLS, snapshot comparison, remediation records, missing-file tolerance, localized views, raw evidence preservation, and ZIP export invariants covered by Rust tests.
${failures.length ? `\n## Failures\n${failures.map((item) => `- ${item}`).join("\n")}\n` : ""}
`);
if (failures.length) throw new Error(failures.join("\n"));
console.log("Governance fixture QA passed.");
