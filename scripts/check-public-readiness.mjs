import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const results = [];
let failed = false;

function record(status, name, detail) {
  results.push({ status, name, detail });
  if (status === "FAIL") failed = true;
  console.log(`[${status}] ${name}: ${detail}`);
}

function run(name, command, args) {
  const result = spawnSync(command, args, { cwd: root, stdio: "inherit" });
  record(result.status === 0 ? "PASS" : "FAIL", name, `${command} ${args.join(" ")}`);
}

run("Full project checks", npm, ["run", "check"]);
run("Visible i18n check", npm, ["run", "i18n:visible-check"]);
run("Deep security boundary check", npm, ["run", "security:deep-check"]);
run("Governance fixtures", npm, ["run", "qa:governance-fixtures"]);
run("Open-source secret scan", npm, ["run", "secret:scan"]);

const required = [
  "README.md", "LICENSE", "SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md",
  ".github/ISSUE_TEMPLATE/bug_report.yml", ".github/ISSUE_TEMPLATE/feature_request.yml",
  ".github/ISSUE_TEMPLATE/localization.yml", ".github/ISSUE_TEMPLATE/security_boundary.yml",
  ".github/pull_request_template.md", "docs/assets/README.md",
  "docs/open-source/public-repo-checklist.md", "docs/open-source/make-public-steps.md",
  "docs/open-source/github-topics.md", "docs/open-source/security-scan-report.md",
  "docs/launch/launch-post-en.md", "docs/launch/launch-post-zh-CN.md",
  "docs/launch/hacker-news-title-ideas.md", "docs/launch/reddit-post.md",
  "docs/launch/producthunt-draft.md", "docs/launch/x-twitter-posts.md",
];
for (const path of required) {
  record(existsSync(join(root, path)) ? "PASS" : "FAIL", `Required file ${path}`, existsSync(join(root, path)) ? "present" : "missing");
}

const readme = readFileSync(join(root, "README.md"), "utf8");
const imageRefs = [...readme.matchAll(/!\[[^\]]*]\(([^)]+)\)/g)].map((match) => match[1]).filter((target) => !/^https?:/.test(target));
for (const target of imageRefs) {
  record(existsSync(join(root, target)) ? "PASS" : "FAIL", `README image ${target}`, existsSync(join(root, target)) ? "present" : "missing");
}
if (imageRefs.length === 0) record("PASS", "README image assets", "no missing local image references");

console.log("\nPublic readiness summary");
for (const status of ["PASS", "WARN", "FAIL"]) {
  console.log(`${status}: ${results.filter((result) => result.status === status).length}`);
}
if (failed) process.exit(1);
