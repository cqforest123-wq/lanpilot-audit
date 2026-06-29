import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
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

function run(command, args, cwd = root) {
  const result = spawnSync(command, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  return {
    status: result.status,
    output: `${result.stdout ?? ""}${result.stderr ?? ""}`,
  };
}

function fileCheck(name, path) {
  if (existsSync(path)) record("PASS", name, path);
  else record("FAIL", name, `Missing: ${path}`);
}

function verifyRemoteRelease(exactTags) {
  const release = spawnSync(
    "gh",
    ["release", "view", expectedTag, "--json", "url,assets"],
    { cwd: root, encoding: "utf8" },
  );

  if (release.status !== 0) {
    if (exactTags.includes(expectedTag)) {
      return { status: "fail", detail: `${expectedTag} exists locally but its GitHub Release is unavailable` };
    }

    return { status: "warn", detail: `${expectedTag} GitHub Release is pending` };
  }

  const data = JSON.parse(release.stdout);
  const assets = data.assets.map((asset) => asset.name);

  if (!assets.includes(portableDmgName) || !assets.includes("SHA256SUMS.txt")) {
    return { status: "fail", detail: `Missing expected assets in ${data.url}` };
  }

  const temp = mkdtempSync(join(tmpdir(), "lanpilot-remote-release-"));

  try {
    const downloadDmg = run(
      "gh",
      ["release", "download", expectedTag, "--repo", "cqforest123-wq/lanpilot-audit", "--pattern", portableDmgName, "--clobber"],
      temp,
    );

    if (downloadDmg.status !== 0) {
      return { status: "fail", detail: downloadDmg.output.trim() || "Failed to download remote DMG" };
    }

    const downloadChecksum = run(
      "gh",
      ["release", "download", expectedTag, "--repo", "cqforest123-wq/lanpilot-audit", "--pattern", "SHA256SUMS.txt", "--clobber"],
      temp,
    );

    if (downloadChecksum.status !== 0) {
      return { status: "fail", detail: downloadChecksum.output.trim() || "Failed to download remote SHA256SUMS.txt" };
    }

    const checksum = run("/usr/bin/shasum", ["-a", "256", "-c", "SHA256SUMS.txt"], temp);

    if (checksum.status !== 0) {
      return { status: "fail", detail: checksum.output.trim() || "Remote checksum verification failed" };
    }

    if (process.platform === "darwin") {
      const remoteDmg = join(temp, portableDmgName);
      const gatekeeper = run(
        "/usr/sbin/spctl",
        ["-a", "-t", "open", "--context", "context:primary-signature", "-vv", remoteDmg],
        temp,
      );

      if (gatekeeper.status !== 0) {
        return { status: "fail", detail: gatekeeper.output.trim() || "Remote DMG is not Gatekeeper accepted" };
      }

      if (!/accepted/.test(gatekeeper.output) || !/Notarized Developer ID/.test(gatekeeper.output)) {
        return { status: "fail", detail: `Remote DMG is not accepted as Notarized Developer ID: ${gatekeeper.output.trim()}` };
      }
    }

    return { status: "ok", detail: `${data.url} remote DMG checksum and Gatekeeper verification passed` };
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
}

console.log(`LANPilot Audit ${version} release-readiness verification\n`);

const exactTags = output("git", ["tag", "--points-at", "HEAD"]).split("\n").filter(Boolean);

if (exactTags.includes(expectedTag)) {
  record("PASS", "Git tag/version", `${expectedTag} points at HEAD`);
} else if (exactTags.length > 0) {
  record("FAIL", "Git tag/version", `HEAD tags ${exactTags.join(", ")} do not include ${expectedTag}`);
} else {
  const expectedExists = spawnSync("git", ["rev-parse", "-q", "--verify", `refs/tags/${expectedTag}`], { cwd: root });

  if (expectedExists.status === 0) {
    record("FAIL", "Git tag/version", `${expectedTag} exists but does not point at HEAD`);
  } else {
    record("WARN", "Git tag/version", `${expectedTag} is pending; create it after readiness checks pass`);
  }
}

const worktree = output("git", ["status", "--porcelain"]);
const generatedInCi = new Set(["release-notes-local.md"]);
const dirtyPaths = worktree.split("\n").filter(Boolean).map((line) => line.replace(/^[ MARCUD?!]{1,2}\s+/, ""));
const unexpectedDirty = process.env.GITHUB_ACTIONS === "true"
  ? dirtyPaths.filter((path) => !generatedInCi.has(path) && !path.startsWith("release/website/"))
  : dirtyPaths;

if (unexpectedDirty.length) {
  record("FAIL", "Git worktree", `Unexpected uncommitted changes: ${unexpectedDirty.join(", ")}`);
} else if (dirtyPaths.length) {
  record("PASS", "Git worktree", "Only deterministic release outputs changed in CI");
} else {
  record("PASS", "Git worktree", "Clean");
}

const check = spawnSync(npm, ["run", "check"], { cwd: root, stdio: "inherit" });

if (check.status === 0) {
  record("PASS", "Automated checks", "npm run check passed");
} else {
  record("FAIL", "Automated checks", `npm run check exited with status ${check.status}`);
}

const artifacts = spawnSync(npm, ["run", "release:artifacts:verify"], { cwd: root, stdio: "inherit" });

if (artifacts.status === 0) {
  record("PASS", "Release artifact integrity", "App, DMG, checksum, signing, notarization, Gatekeeper, and bundled engine verified");
} else {
  record("FAIL", "Release artifact integrity", `Artifact verification exited with status ${artifacts.status}`);
}

fileCheck("DMG", dmg);
fileCheck("SHA256SUMS", checksumFile);
fileCheck("Release website", website);

for (const name of websiteFiles) {
  fileCheck(`Release website ${name}`, join(website, name));
}

if (existsSync(dmg) && existsSync(checksumFile)) {
  const digest = createHash("sha256").update(readFileSync(dmg)).digest("hex");
  const expected = `${digest}  ${dmgName}\n`;

  if (readFileSync(checksumFile, "utf8") === expected) {
    record("PASS", "DMG SHA-256", digest);
  } else {
    record("FAIL", "DMG SHA-256", "checksums/SHA256SUMS.txt does not match the DMG");
  }
}

const remote = verifyRemoteRelease(exactTags);

if (remote.status === "ok") {
  record("PASS", "GitHub release assets", remote.detail);
} else if (remote.status === "fail") {
  record("FAIL", "GitHub release assets", remote.detail);
} else {
  record("WARN", "GitHub release assets", remote.detail);
}

if (process.platform === "darwin") {
  const identities = spawnSync("security", ["find-identity", "-v", "-p", "codesigning"], { encoding: "utf8" });

  if (/Developer ID Application:/.test(identities.stdout)) {
    record("PASS", "Developer ID Application", "Certificate identity found");
  } else {
    record("WARN", "Developer ID Application", "Certificate identity not found; local readiness remains valid");
  }

  const profile = process.env.NOTARY_PROFILE || process.env.APPLE_NOTARY_PROFILE || "lanpilot-notary";
  const hasKeychainProfile = spawnSync("/usr/bin/xcrun", ["notarytool", "history", "--keychain-profile", profile], { encoding: "utf8" }).status === 0;
  const hasApiAuth = Boolean(process.env.APPLE_TEAM_ID && process.env.ASC_KEY_ID && process.env.ASC_ISSUER_ID && process.env.ASC_KEY_PATH);

  if (hasApiAuth) {
    record("PASS", "Notarization environment", "ASC notary authentication is available");
  } else if (hasKeychainProfile) {
    record("PASS", "Notarization environment", `Keychain profile '${profile}' is available`);
  } else {
    record("WARN", "Notarization environment", `Pending: ASC notary authentication or keychain profile '${profile}'`);
  }
} else {
  record("WARN", "Developer ID Application", "Certificate lookup is only available on macOS");
  record("WARN", "Notarization environment", "Notarization check is only available on macOS");
}

console.log("\nRelease-readiness summary");

for (const status of ["PASS", "WARN", "FAIL"]) {
  console.log(`${status}: ${results.filter((result) => result.status === status).length}`);
}

if (failed) process.exit(1);
