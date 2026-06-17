import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const version = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;
const app = join(root, "src-tauri", "target", "release", "bundle", "macos", "LANPilot Audit.app");
const dmg = join(root, "src-tauri", "target", "release", "bundle", "dmg", `LANPilot Audit_${version}_aarch64.dmg`);
const report = join(root, "docs", "release", "gatekeeper-check.md");

for (const artifact of [app, dmg]) {
  if (!existsSync(artifact)) throw new Error(`Required release artifact is missing: ${artifact}`);
}

function run(command, args) {
  const result = spawnSync(command, args, { cwd: root, encoding: "utf8" });
  return {
    command: [command, ...args].join(" "),
    status: result.status ?? 1,
    output: `${result.stdout ?? ""}${result.stderr ?? ""}`.trim() || "(no output)",
  };
}

function publicOutput(value) {
  return value
    .split(root).join("<repo>/")
    .replace(/TeamIdentifier=[A-Z0-9]+/g, "TeamIdentifier=<redacted>")
    .replace(/\([A-Z0-9]{10}\)/g, "(<team-id>)");
}

const codesignApp = run("/usr/bin/codesign", ["-dv", "--verbose=4", app]);
const codesignDmg = run("/usr/bin/codesign", ["-dv", "--verbose=4", dmg]);
const spctlApp = run("/usr/sbin/spctl", ["--assess", "--type", "execute", "--verbose=4", app]);
const spctlDmg = run("/usr/sbin/spctl", ["--assess", "--type", "open", "--context", "context:primary-signature", "--verbose=4", dmg]);
const staplerApp = run("/usr/bin/xcrun", ["stapler", "validate", app]);
const staplerDmg = run("/usr/bin/xcrun", ["stapler", "validate", dmg]);
const developerSigned = /Authority=Developer ID Application:/.test(codesignApp.output);
const adHocSigned = /Signature=adhoc/.test(codesignApp.output);
const notarized = staplerApp.status === 0 || staplerDmg.status === 0;
const signature = developerSigned ? "Developer ID signed" : adHocSigned ? "ad-hoc signed" : "unknown signature";

function section(title, result) {
  return `## ${title}

- Exit status: ${result.status}

\`\`\`text
${publicOutput(result.command)}
${publicOutput(result.output)}
\`\`\`
`;
}

mkdirSync(join(root, "docs", "release"), { recursive: true });
writeFileSync(report, `# Gatekeeper Check

- Version: ${version}
- Signature classification: ${signature}
- Developer ID signed: ${developerSigned ? "Yes" : "No"}
- Ad-hoc signed: ${adHocSigned ? "Yes" : "No"}
- Notarized/stapled: ${notarized ? "Yes" : "No"}
- Gatekeeper assessment: ${spctlApp.status === 0 ? "Accepted" : "Not accepted"}

Developer ID signing and notarization are optional for this local readiness check. Their absence is recorded as a distribution limitation, not a product test failure.

${section("codesign - App", codesignApp)}
${section("codesign - DMG", codesignDmg)}
${section("spctl - App", spctlApp)}
${section("spctl - DMG", spctlDmg)}
${section("stapler - App", staplerApp)}
${section("stapler - DMG", staplerDmg)}
`);

console.log(`Gatekeeper report: ${report}`);
console.log(`Signature: ${signature}`);
console.log(`Gatekeeper: ${spctlApp.status === 0 ? "accepted" : "not accepted"}`);
console.log(`Notarized/stapled: ${notarized ? "yes" : "no"}`);
