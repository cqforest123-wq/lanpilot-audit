import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const version = JSON.parse(await import("node:fs/promises").then(({ readFile }) => readFile(join(root, "package.json"), "utf8"))).version;
const app = join(root, "src-tauri", "target", "release", "bundle", "macos", "LANPilot Audit.app");
const dmg = join(root, "src-tauri", "target", "release", "bundle", "dmg", `LANPilot Audit_${version}_aarch64.dmg`);
const required = ["APPLE_TEAM_ID", "DEVELOPER_ID_APPLICATION"];
const apiAuth = ["ASC_KEY_ID", "ASC_ISSUER_ID", "ASC_KEY_PATH"];
const missingBase = required.filter((name) => !process.env[name]);
const hasApiAuth = apiAuth.every((name) => process.env[name]);
const checkOnly = process.argv.includes("--check");

console.log(`Required identity variables: ${required.join(", ")}`);
console.log(`Notary authentication: ${apiAuth.join(", ")}`);
if (missingBase.length || !hasApiAuth) {
  console.error(`Signing/notarization credentials are incomplete. Missing: ${[...missingBase, ...(!hasApiAuth ? ["ASC notary authentication set"] : [])].join(", ")}`);
  process.exit(1);
}
if (checkOnly) {
  console.log("Signing/notarization environment is ready.");
  process.exit(0);
}
if (!existsSync(app) || !existsSync(dmg)) throw new Error("Release app or DMG is missing. Run npm run app:build first.");

execFileSync("/usr/bin/codesign", ["--force", "--deep", "--options", "runtime", "--timestamp", "--sign", process.env.DEVELOPER_ID_APPLICATION, app], { stdio: "inherit" });
execFileSync("/usr/bin/codesign", ["--verify", "--deep", "--strict", app], { stdio: "inherit" });
execFileSync("/usr/bin/hdiutil", ["create", "-volname", "LANPilot Audit", "-srcfolder", app, "-ov", "-format", "UDZO", dmg], { stdio: "inherit" });
execFileSync("/usr/bin/codesign", ["--force", "--timestamp", "--sign", process.env.DEVELOPER_ID_APPLICATION, dmg], { stdio: "inherit" });
execFileSync("/usr/bin/codesign", ["--verify", "--strict", dmg], { stdio: "inherit" });
const args = ["notarytool", "submit", dmg, "--wait", "--team-id", process.env.APPLE_TEAM_ID];
args.push("--key-id", process.env.ASC_KEY_ID, "--issuer", process.env.ASC_ISSUER_ID, "--key", process.env.ASC_KEY_PATH);
execFileSync("/usr/bin/xcrun", args, { stdio: "inherit" });
execFileSync("/usr/bin/xcrun", ["stapler", "staple", dmg], { stdio: "inherit" });
execFileSync("/usr/bin/xcrun", ["stapler", "validate", dmg], { stdio: "inherit" });
console.log("Signing and notarization completed.");
