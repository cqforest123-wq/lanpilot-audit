import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { cp, symlink } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const version = JSON.parse(await import("node:fs/promises").then(({ readFile }) => readFile(join(root, "package.json"), "utf8"))).version;
const app = join(root, "src-tauri", "target", "release", "bundle", "macos", "LANPilot Audit.app");
const mainBinary = join(app, "Contents", "MacOS", "lanpilot-audit-app");
const dmg = join(root, "src-tauri", "target", "release", "bundle", "dmg", `LANPilot Audit_${version}_aarch64.dmg`);
const checkOnly = process.argv.includes("--check");
const profile = process.env.NOTARY_PROFILE || process.env.APPLE_NOTARY_PROFILE || "lanpilot-notary";

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    stdio: options.inherit ? "inherit" : ["ignore", "pipe", "pipe"],
  });
  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
  if (result.status !== 0) {
    if (!options.inherit && output.trim()) process.stderr.write(output);
    throw new Error(`${command} ${args.join(" ")} failed with status ${result.status}`);
  }
  return output;
}

function optional(command, args) {
  return spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function resolveIdentity() {
  if (process.env.DEVELOPER_ID_APPLICATION) return process.env.DEVELOPER_ID_APPLICATION;
  if (process.platform !== "darwin") throw new Error("Developer ID signing requires macOS.");
  const identities = run("/usr/bin/security", ["find-identity", "-v", "-p", "codesigning"]);
  const match = identities.match(/"([^"]*Developer ID Application:[^"]*)"/);
  if (!match) throw new Error("Developer ID Application identity was not found.");
  return match[1];
}

function hasKeychainProfile() {
  if (process.platform !== "darwin") return false;
  const result = optional("/usr/bin/xcrun", ["notarytool", "history", "--keychain-profile", profile]);
  return result.status === 0;
}

function hasApiAuth() {
  return Boolean(process.env.APPLE_TEAM_ID && process.env.ASC_KEY_ID && process.env.ASC_ISSUER_ID && process.env.ASC_KEY_PATH);
}

function assertSignatureDetails(target, label, requireRuntime) {
  const details = run("/usr/bin/codesign", ["-dv", "--verbose=4", target]);
  if (!/Authority=Developer ID Application:/.test(details)) throw new Error(`${label} is not Developer ID signed.`);
  if (!/Timestamp=/.test(details)) throw new Error(`${label} signature has no secure timestamp.`);
  if (requireRuntime && !/Runtime Version=/.test(details)) throw new Error(`${label} does not have hardened runtime enabled.`);
}

function notarizeArgs() {
  if (hasApiAuth()) {
    return [
      "notarytool",
      "submit",
      dmg,
      "--wait",
      "--team-id",
      process.env.APPLE_TEAM_ID,
      "--key-id",
      process.env.ASC_KEY_ID,
      "--issuer",
      process.env.ASC_ISSUER_ID,
      "--key",
      process.env.ASC_KEY_PATH,
    ];
  }
  if (hasKeychainProfile()) {
    return ["notarytool", "submit", dmg, "--keychain-profile", profile, "--wait"];
  }
  throw new Error(`No valid notary authentication found. Set ASC env vars or create keychain profile '${profile}'.`);
}

const identity = resolveIdentity();

console.log(`Developer ID identity: ${identity}`);
console.log(`Notary profile: ${profile}`);
console.log(`ASC API auth: ${hasApiAuth() ? "available" : "not set"}`);
console.log(`Keychain notary profile: ${hasKeychainProfile() ? "available" : "not available"}`);

if (checkOnly) {
  if (!hasApiAuth() && !hasKeychainProfile()) {
    throw new Error("Signing/notarization credentials are incomplete.");
  }
  console.log("Signing/notarization environment is ready.");
  process.exit(0);
}

if (!existsSync(app) || !existsSync(mainBinary)) {
  throw new Error("Release app bundle is missing. Run npm run app:build first.");
}

run("/usr/bin/xattr", ["-cr", app], { inherit: true });

optional("/usr/bin/codesign", ["--remove-signature", mainBinary]);
optional("/usr/bin/codesign", ["--remove-signature", app]);

run("/usr/bin/codesign", [
  "--force",
  "--timestamp",
  "--options",
  "runtime",
  "--sign",
  identity,
  mainBinary,
], { inherit: true });

run("/usr/bin/codesign", [
  "--force",
  "--deep",
  "--timestamp",
  "--options",
  "runtime",
  "--sign",
  identity,
  app,
], { inherit: true });

run("/usr/bin/codesign", ["--verify", "--deep", "--strict", "--verbose=4", app], { inherit: true });
assertSignatureDetails(mainBinary, "Main executable", true);
assertSignatureDetails(app, "App bundle", true);

rmSync(dmg, { force: true });

const staging = mkdtempSync(join(tmpdir(), "lanpilot-dmg-"));
await cp(app, join(staging, "LANPilot Audit.app"), { recursive: true });
await symlink("/Applications", join(staging, "Applications"));

run("/usr/bin/hdiutil", [
  "create",
  "-volname",
  "LANPilot Audit",
  "-srcfolder",
  staging,
  "-ov",
  "-format",
  "UDZO",
  dmg,
], { inherit: true });

rmSync(staging, { recursive: true, force: true });

run("/usr/bin/codesign", [
  "--force",
  "--timestamp",
  "--sign",
  identity,
  dmg,
], { inherit: true });

run("/usr/bin/codesign", ["--verify", "--strict", "--verbose=4", dmg], { inherit: true });
assertSignatureDetails(dmg, "DMG", false);

run("/usr/bin/xcrun", notarizeArgs(), { inherit: true });
run("/usr/bin/xcrun", ["stapler", "staple", dmg], { inherit: true });
run("/usr/bin/xcrun", ["stapler", "validate", dmg], { inherit: true });

const gatekeeper = run("/usr/sbin/spctl", [
  "-a",
  "-t",
  "open",
  "--context",
  "context:primary-signature",
  "-vv",
  dmg,
]);
process.stdout.write(gatekeeper);
if (!/accepted/.test(gatekeeper) || !/Notarized Developer ID/.test(gatekeeper)) {
  throw new Error("DMG is not Gatekeeper accepted as Notarized Developer ID.");
}

console.log("Signing, notarization, stapling, and Gatekeeper validation completed.");
