import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const version = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;
const expectedTag = `v${version}`;
const dmgName = `LANPilot Audit_${version}_aarch64.dmg`;
const portableDmgName = `LANPilot-Audit_${version}_aarch64.dmg`;
const dmg = join(root, "src-tauri", "target", "release", "bundle", "dmg", dmgName);
const checksumFile = join(root, "checksums", "SHA256SUMS.txt");
const website = join(root, "release", "website");
const websiteFiles = ["index.html", "faq.html", "privacy.html", "release-notes.html", "SHA256SUMS.txt"];
const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const results = [];
let failed = false;

function record(status, name, detail) {
  results.push({ status, name, detail });
  if (status === "FAIL") failed = true;
  console.log(`[${status}] ${name}: ${detail}`);
}

function output(command, args) {
  return execFileSync(command, args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

function fileCheck(name, path) {
  if (existsSync(path)) record("PASS", name, path);
  else record("FAIL", name, `Missing: ${path}`);
}

console.log(`LANPilot Audit ${version} release-readiness verification\n`);

const exactTags = output("git", ["tag", "--points-at", "HEAD"]).split("\n").filter(Boolean);
if (exactTags.includes(expectedTag)) {
  record("PASS", "Git tag/version", `${expectedTag} points at HEAD`);
} else if (exactTags.length > 0) {
  record("FAIL", "Git tag/version", `HEAD tags ${exactTags.join(", ")} do not include ${expectedTag}`);
} else {
  const expectedExists = spawnSync("git", ["rev-parse", "-q", "--verify", `refs/tags/${expectedTag}`], { cwd: root });
  if (expectedExists.status === 0) record("FAIL", "Git tag/version", `${expectedTag} exists but does not point at HEAD`);
  else record("WARN", "Git tag/version", `${expectedTag} is pending; create it after readiness checks pass`);
}

const worktree = output("git", ["status", "--porcelain"]);
const generatedInCi = new Set(["release-notes-local.md"]);
const dirtyPaths = worktree.split("\n").filter(Boolean).map((line) => line.replace(/^[ MARCUD?!]{1,2}\s+/, ""));
const unexpectedDirty = process.env.GITHUB_ACTIONS === "true"
  ? dirtyPaths.filter((path) => !generatedInCi.has(path) && !path.startsWith("release/website/"))
  : dirtyPaths;
if (unexpectedDirty.length) record("FAIL", "Git worktree", `Unexpected uncommitted changes: ${unexpectedDirty.join(", ")}`);
else if (dirtyPaths.length) record("PASS", "Git worktree", "Only deterministic release outputs changed in CI");
else record("PASS", "Git worktree", "Clean");

const check = spawnSync(npm, ["run", "check"], { cwd: root, stdio: "inherit" });
if (check.status === 0) record("PASS", "Automated checks", "npm run check passed");
else record("FAIL", "Automated checks", `npm run check exited with status ${check.status}`);

const artifacts = spawnSync(npm, ["run", "release:artifacts:verify"], { cwd: root, stdio: "inherit" });
if (artifacts.status === 0) record("PASS", "Release artifact integrity", "App, DMG, checksum, and bundled engine verified");
else record("FAIL", "Release artifact integrity", `Artifact verification exited with status ${artifacts.status}`);

fileCheck("DMG", dmg);
fileCheck("SHA256SUMS", checksumFile);
fileCheck("Release website", website);
for (const name of websiteFiles) fileCheck(`Release website ${name}`, join(website, name));

if (existsSync(dmg) && existsSync(checksumFile)) {
  const digest = createHash("sha256").update(readFileSync(dmg)).digest("hex");
  const expected = `${digest}  ${dmgName}\n`;
  if (readFileSync(checksumFile, "utf8") === expected) record("PASS", "DMG SHA-256", digest);
  else record("FAIL", "DMG SHA-256", "checksums/SHA256SUMS.txt does not match the DMG");
}

const release = spawnSync(
  "gh",
  ["release", "view", expectedTag, "--json", "url,assets"],
  { cwd: root, encoding: "utf8" },
);
if (release.status === 0) {
  const data = JSON.parse(release.stdout);
  const assets = data.assets.map((asset) => asset.name);
  if (assets.includes(portableDmgName) && assets.includes("SHA256SUMS.txt")) {
    record("PASS", "GitHub release assets", data.url);
  } else {
    record("FAIL", "GitHub release assets", `Missing expected assets in ${data.url}`);
  }
} else if (exactTags.includes(expectedTag)) {
  record("FAIL", "GitHub release assets", `${expectedTag} exists locally but its GitHub Release is unavailable`);
} else {
  record("WARN", "GitHub release assets", `${expectedTag} release is pending until the tag is pushed`);
}

if (process.platform === "darwin") {
  const identities = spawnSync("security", ["find-identity", "-v", "-p", "codesigning"], { encoding: "utf8" });
  if (/Developer ID Application:/.test(identities.stdout)) {
    record("PASS", "Developer ID Application", "Certificate identity found");
  } else {
    record("WARN", "Developer ID Application", "Certificate identity not found; local readiness remains valid");
  }
} else {
  record("WARN", "Developer ID Application", "Certificate lookup is only available on macOS");
}

const baseVariables = ["APPLE_TEAM_ID", "DEVELOPER_ID_APPLICATION"];
const apiVariables = ["ASC_KEY_ID", "ASC_ISSUER_ID", "ASC_KEY_PATH"];
const missingBase = baseVariables.filter((name) => !process.env[name]);
const hasApiAuth = apiVariables.every((name) => process.env[name]);
if (missingBase.length === 0 && hasApiAuth) {
  record("PASS", "Notarization environment", "Required signing and notary variables are available");
} else {
  const detail = [
    ...missingBase,
    ...(!hasApiAuth ? ["ASC notary authentication set"] : []),
  ].join(", ");
  record("WARN", "Notarization environment", `Pending: ${detail}`);
}

console.log("\nRelease-readiness summary");
for (const status of ["PASS", "WARN", "FAIL"]) {
  console.log(`${status}: ${results.filter((result) => result.status === status).length}`);
}
if (failed) process.exit(1);
