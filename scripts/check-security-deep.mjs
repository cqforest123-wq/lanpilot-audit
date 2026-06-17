import { readFileSync, readdirSync, mkdirSync, writeFileSync } from "node:fs";
import { extname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const roots = ["src", "src-tauri/src", "bundled-engine/lanpilot-audit", "scripts", ".github/workflows"];
const excludedDirs = new Set([".git", "node_modules", "target", "dist", "release", "tests"]);
const excludedFiles = new Set(["check-security-deep.mjs", "check-security-keywords.mjs"]);
const textExtensions = new Set([".ts", ".tsx", ".js", ".mjs", ".rs", ".sh", ".py", ".yml", ".yaml", ".json", ""]);
const patterns = [
  ["arbitrary shell input", /arbitrary\s+shell\s+input/i],
  ["custom command", /custom\s+command/i],
  ["user command", /user\s+command/i],
  ["eval", /\beval\s*\(/i],
  ["sh -c", /\b(?:sh|bash)\s+-c\b/i],
  ["sudo", /\bsudo\b/i],
  ["rm -rf", /\brm\s+-rf\b/i],
  ["chmod 777", /\bchmod\s+777\b/i],
  ["offensive utility", /\b(?:hydra|metasploit|wfuzz|dirb|gobuster|nikto|sqlmap|masscan|nuclei)\b/i],
  ["credential activity", /\b(?:default-password|smb-enum|enum-shares|password\s+spray|credential\s+stuffing|login\s+attempt)\b/i],
  ["nmap vuln", /\bnmap\b[^\n]*(?:--script\s+vuln|\bvuln\b)/i],
  ["network configuration mutation", /\bnetworksetup\b[^\n]*(?:-set|-create|-delete)|\broute\s+(?:add|delete)\b|\bifconfig\b[^\n]*(?:down|up)\b|\bpfctl\b[^\n]*(?:-e|-d|-f)\b/i],
  ["scp upload", /\bscp\b/i],
  ["curl upload", /\bcurl\b[^\n]*(?:--upload-file|-T\s|-F\s|--data|--data-binary)\b/i],
];
const findings = [];

function walk(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && excludedDirs.has(entry.name)) continue;
    const path = join(directory, entry.name);
    if (entry.isDirectory()) walk(path);
    else if (entry.isFile() && !excludedFiles.has(entry.name) && textExtensions.has(extname(entry.name))) {
      const lines = readFileSync(path, "utf8").split(/\r?\n/);
      lines.forEach((line, index) => {
        for (const [label, pattern] of patterns) if (pattern.test(line)) findings.push(`${relative(root, path)}:${index + 1}: ${label}`);
      });
    }
  }
}
for (const directory of roots) walk(join(root, directory));
mkdirSync(join(root, "docs", "nightly"), { recursive: true });
writeFileSync(join(root, "docs", "nightly", "v1.4.0-security-deep-check.md"), `# v1.4.0 Security Deep Check

- Scope: ${roots.join(", ")}
- Exclusions: generated artifacts, documentation, fixtures, and checker assertions
- Result: ${findings.length ? "FAIL" : "PASS"}
- Boundary: fixed allowlisted observations only; no credential activity, unauthorized login, configuration mutation, arbitrary command input, or cloud upload.
${findings.length ? `\n## Findings\n${findings.map((item) => `- ${item}`).join("\n")}\n` : ""}
`);
if (findings.length) {
  console.error(`Deep security boundary check failed:\n${findings.map((item) => `- ${item}`).join("\n")}`);
  process.exit(1);
}
console.log("Deep security boundary check passed.");
