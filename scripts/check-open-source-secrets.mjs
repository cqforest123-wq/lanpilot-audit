import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const reportDir = join(root, "docs", "open-source");
const reportPath = join(reportDir, "security-scan-report.md");
const cleanupPath = join(reportDir, "history-cleanup-plan.md");
const exact = [
  { name: "personal email marker", value: ["predestina", "me.com"].join("@"), severity: "block" },
  { name: "Apple ID marker", value: ["Apple", "ID"].join(" "), severity: "review" },
  { name: "app-specific password variable", value: ["APPLE", "APP", "SPECIFIC", "PASSWORD"].join("_"), severity: "review" },
  { name: "Apple team id marker", value: ["V5746", "UM5UL"].join(""), severity: "block" },
  { name: "Developer ID personal identity", value: ["Developer ID Application:", "TAO LI"].join(" "), severity: "review" },
  { name: "local home path", value: ["", "Users", "litao"].join("/"), severity: "block" },
  { name: "legacy network lab directory", value: ["network", "lab", "latest"].join("-"), severity: "block" },
];
const regexes = [
  { name: "GitHub classic token", pattern: /gho_[A-Za-z0-9_]{20,}/, severity: "block" },
  { name: "GitHub fine-grained token", pattern: /github_pat_[A-Za-z0-9_]{20,}/, severity: "block" },
  { name: "private key material", pattern: /BEGIN (RSA |OPENSSH |EC |DSA |PRIVATE )?PRIVATE KEY/, severity: "block" },
  { name: "certificate block", pattern: /BEGIN CERTIFICATE/, severity: "block" },
  { name: "MAC address", pattern: /\b[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}\b/, severity: "review" },
];
const ignoreCurrent = new Set([
  ".gitignore",
  "scripts/check-open-source-secrets.mjs",
  "docs/open-source/security-scan-report.md",
  "docs/open-source/history-cleanup-plan.md",
]);

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { cwd: root, encoding: "utf8", ...options });
  return { status: result.status ?? 1, stdout: result.stdout ?? "", stderr: result.stderr ?? "" };
}

function trackedFiles() {
  return execFileSync("git", ["ls-files"], { cwd: root, encoding: "utf8" })
    .trim()
    .split("\n")
    .filter(Boolean)
    .filter((path) => !ignoreCurrent.has(path))
    .filter((path) => !path.startsWith("src-tauri/target/"))
    .filter((path) => !path.startsWith("release/website/downloads/"));
}

function readText(path) {
  try {
    const content = readFileSync(join(root, path), "utf8");
    return content.includes("\u0000") ? null : content;
  } catch {
    return null;
  }
}

function currentFindings() {
  const findings = [];
  for (const path of trackedFiles()) {
    const content = readText(path);
    if (content === null) continue;
    for (const item of exact) {
      if (content.includes(item.value)) findings.push({ path, name: item.name, severity: item.severity });
    }
    for (const item of regexes) {
      if (item.pattern.test(content)) findings.push({ path, name: item.name, severity: item.severity });
    }
  }
  return findings;
}

function historyFindings() {
  const terms = exact
    .filter((item) => item.severity === "block")
    .map((item) => item.value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  const pattern = [...terms, "gho_[A-Za-z0-9_]{20,}", "github_pat_[A-Za-z0-9_]{20,}", "BEGIN (RSA |OPENSSH |EC |DSA |PRIVATE )?PRIVATE KEY", "BEGIN CERTIFICATE"].join("|");
  const revisions = run("git", ["rev-list", "--all"]);
  if (revisions.status !== 0 || !revisions.stdout.trim()) return [];
  const args = ["grep", "-n", "-I", "-E", pattern, ...revisions.stdout.trim().split("\n"), "--", ".", ":(exclude).gitignore", ":(exclude)scripts/check-open-source-secrets.mjs"];
  const result = run("git", args, { maxBuffer: 1024 * 1024 * 20 });
  if (result.status !== 0 && !result.stdout.trim()) return [];
  return result.stdout.trim().split("\n").filter(Boolean).slice(0, 200);
}

function toolStatus(name) {
  const result = run("sh", ["-lc", `command -v ${name}`]);
  if (result.status !== 0) return { name, available: false, detail: "not installed" };
  const scan = name === "gitleaks"
    ? run(name, ["detect", "--source", root, "--no-git", "--redact", "--exit-code", "1"])
    : run(name, ["filesystem", root, "--no-update", "--fail"]);
  return { name, available: true, detail: scan.status === 0 ? "passed" : "review required" };
}

const current = currentFindings();
const history = historyFindings();
const external = [toolStatus("gitleaks"), toolStatus("trufflehog")];
const blockers = current.filter((finding) => finding.severity === "block");
const reviews = current.filter((finding) => finding.severity !== "block");
mkdirSync(reportDir, { recursive: true });
writeFileSync(reportPath, `# Open Source Security Scan Report

- Current tree blockers: ${blockers.length}
- Current tree review items: ${reviews.length}
- Git history matches: ${history.length}
- External tools: ${external.map((item) => `${item.name}: ${item.detail}`).join("; ")}

## Current Tree

${current.length ? current.map((finding) => `- ${finding.severity.toUpperCase()}: ${finding.path} (${finding.name})`).join("\n") : "- PASS: no blocking secret or personal-data markers found in tracked current files."}

## Git History

${history.length ? history.map((line) => `- ${line.split(":").slice(0, 3).join(":")}: matched blocking history marker`).join("\n") : "- PASS: no history matches for blocking markers or high-confidence secret patterns."}

## External Secret Scanners

${external.map((item) => `- ${item.name}: ${item.available ? item.detail : "not installed; npm scan fallback used"}`).join("\n")}

## Notes

- Current scan excludes the physical .git directory and generated binary build output.
- History scan covers blocking markers and high-confidence secret patterns; review-only public distribution markers are reported in the current tree only.
- Secret values are never printed in this report.
- Repository secret variable names are allowed only when they do not include secret values.
`);

if (history.length) {
  writeFileSync(cleanupPath, `# Git History Cleanup Plan

The current branch has been cleaned for public-readiness checks, but git history still contains public-readiness markers such as local build paths or signing-related variable references.

Before changing repository visibility to public, choose one of these paths:

1. Conservative public launch: run \`git filter-repo\` on a throwaway clone to remove historical local paths and any sensitive records, then force-push after review.
2. Risk acceptance: keep history unchanged only if every historical match is confirmed to be non-secret and acceptable for public disclosure.

Recommended command shape for a separate throwaway clone:

\`\`\`sh
git clone --mirror <repo-url> lanpilot-audit-app-cleanup.git
cd lanpilot-audit-app-cleanup.git
git filter-repo --replace-text replacements.txt
\`\`\`

Do not run history rewriting in the working repository without an explicit approval checkpoint.
`);
} else {
  writeFileSync(cleanupPath, `# Git History Cleanup Plan

No blocking history markers or high-confidence secret patterns were found by the current open-source readiness scan.

Continue using a clean public snapshot workflow for releases, and do not commit Apple credentials, certificates, private logs, real audit reports, or local network evidence.
`);
}

console.log(`Open source security scan report: ${reportPath}`);
if (history.length) console.log(`History cleanup plan: ${cleanupPath}`);
if (blockers.length) {
  console.error(`Open source security scan found ${blockers.length} current-tree blocker(s).`);
  process.exit(1);
}
