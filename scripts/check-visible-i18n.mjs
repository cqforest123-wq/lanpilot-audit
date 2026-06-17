import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const appPath = join(root, "src", "App.tsx");
const allowed = /LANPilot Audit|nmap|en0|SMB|TLS|HTTP|DNS|DHCP|mDNS|Bonjour|Application Support|Raw Evidence|stdout|stderr/;
const forbiddenSentences = [
  "Required before every real audit", "Local engine readiness", "Install or update",
  "Review Authorization", "Sequence", "Executive Summary", "Risk Register",
  "Recommended action", "Remediation Roadmap", "Service Exposure Matrix",
  "Asset Inventory", "Local Network Configuration",
];
const findings = [];

const source = readFileSync(appPath, "utf8");
for (const line of source.split(/\r?\n/)) {
  if (line.includes("<pre") || line.includes("RawDetail")) continue;
  for (const value of line.matchAll(/>([^<{][^<{]+)</g)) {
    const text = value[1].trim();
    if (/[A-Za-z]{3,}\s+[A-Za-z]{3,}/.test(text) && !allowed.test(text)) findings.push(`${appPath}: ${text}`);
  }
}
for (const phrase of forbiddenSentences) {
  if (source.includes(`>${phrase}<`)) findings.push(`${appPath}: ${phrase}`);
}
if (findings.length) {
  console.error(`Visible i18n check failed:\n${findings.map((item) => `- ${item}`).join("\n")}`);
  process.exit(1);
}
const tests = spawnSync("npx", ["vitest", "run", "src/i18n/completeness.test.ts", "src/i18n/strict.test.ts", "src/i18n/visible.test.ts"], { cwd: root, stdio: "inherit" });
if (tests.status !== 0) process.exit(tests.status ?? 1);
console.log("Visible i18n check passed for source literals, locale completeness, CJK screens, reports, and raw evidence.");
