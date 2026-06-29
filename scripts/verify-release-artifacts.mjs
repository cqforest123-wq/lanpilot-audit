import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const version = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;
const app = join(root, "src-tauri", "target", "release", "bundle", "macos", "LANPilot Audit.app");
const mainBinary = join(app, "Contents", "MacOS", "lanpilot-audit-app");
const dmgName = `LANPilot Audit_${version}_aarch64.dmg`;
const dmg = join(root, "src-tauri", "target", "release", "bundle", "dmg", dmgName);
const checksumFile = join(root, "checksums", "SHA256SUMS.txt");
const engine = join(app, "Contents", "Resources", "bundled-engine", "lanpilot-audit");
const infoPlist = join(app, "Contents", "Info.plist");

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  const output = `${result.stdout ?? ""}${result.stderr ?? ""}`;
  if (result.status !== 0) {
    if (output.trim()) process.stderr.write(output);
    throw new Error(`${command} ${args.join(" ")} failed with status ${result.status}`);
  }
  return output;
}

function requireMatch(output, pattern, message) {
  if (!pattern.test(output)) throw new Error(message);
}

for (const path of [app, mainBinary, dmg, checksumFile, engine]) {
  if (!existsSync(path)) throw new Error(`Required release artifact is missing: ${path}`);
}

const bundleVersion = run("/usr/bin/plutil", [
  "-extract",
  "CFBundleShortVersionString",
  "raw",
  "-o",
  "-",
  infoPlist,
]).trim();

if (bundleVersion !== version) {
  throw new Error(`Release app bundle is version ${bundleVersion}; expected ${version}.`);
}

const sha256 = (path) => createHash("sha256").update(readFileSync(path)).digest("hex");
const expectedChecksum = `${sha256(dmg)}  ${dmgName}\n`;

if (readFileSync(checksumFile, "utf8") !== expectedChecksum) {
  throw new Error("Release checksum file does not exactly match the current DMG.");
}

const represented = new Set();

for (const line of readFileSync(join(engine, "ENGINE_SHA256SUMS.txt"), "utf8").trim().split("\n")) {
  const [expected, file] = line.split("  ");

  if (!expected || !file || file.startsWith("/") || file.split("/").includes("..") || represented.has(file)) {
    throw new Error(`Invalid bundled engine manifest line: ${line}`);
  }

  const path = join(engine, file);

  if (!existsSync(path) || lstatSync(path).isSymbolicLink() || sha256(path) !== expected) {
    throw new Error(`Bundled app engine integrity check failed: ${file}`);
  }

  represented.add(file);
}

function collect(directory, files = []) {
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    const metadata = lstatSync(path);

    if (metadata.isSymbolicLink()) {
      throw new Error(`Bundled app engine contains a symbolic link: ${path}`);
    }

    if (metadata.isDirectory()) collect(path, files);
    else if (entry !== "ENGINE_SHA256SUMS.txt") files.push(relative(engine, path));
  }

  return files;
}

const actual = collect(engine);

if (actual.length !== represented.size || actual.some((file) => !represented.has(file))) {
  throw new Error("Bundled app engine contains unlisted files.");
}

if (process.platform === "darwin") {
  run("/usr/bin/codesign", ["--verify", "--deep", "--strict", "--verbose=4", app]);
  run("/usr/bin/codesign", ["--verify", "--strict", "--verbose=4", dmg]);

  const mainSignature = run("/usr/bin/codesign", ["-dv", "--verbose=4", mainBinary]);
  const appSignature = run("/usr/bin/codesign", ["-dv", "--verbose=4", app]);
  const dmgSignature = run("/usr/bin/codesign", ["-dv", "--verbose=4", dmg]);

  requireMatch(mainSignature, /Authority=Developer ID Application:/, "Main executable is not Developer ID signed.");
  requireMatch(mainSignature, /Timestamp=/, "Main executable signature has no secure timestamp.");
  requireMatch(mainSignature, /Runtime Version=/, "Main executable does not have hardened runtime enabled.");

  requireMatch(appSignature, /Authority=Developer ID Application:/, "App bundle is not Developer ID signed.");
  requireMatch(appSignature, /Timestamp=/, "App bundle signature has no secure timestamp.");
  requireMatch(appSignature, /Runtime Version=/, "App bundle does not have hardened runtime enabled.");

  requireMatch(dmgSignature, /Authority=Developer ID Application:/, "DMG is not Developer ID signed.");
  requireMatch(dmgSignature, /Timestamp=/, "DMG signature has no secure timestamp.");

  run("/usr/bin/hdiutil", ["verify", dmg]);
  run("/usr/bin/xcrun", ["stapler", "validate", dmg]);

  const gatekeeper = run("/usr/sbin/spctl", [
    "-a",
    "-t",
    "open",
    "--context",
    "context:primary-signature",
    "-vv",
    dmg,
  ]);

  requireMatch(gatekeeper, /accepted/, "DMG is not Gatekeeper accepted.");
  requireMatch(gatekeeper, /Notarized Developer ID/, "DMG is not accepted as Notarized Developer ID.");
}

console.log(`Release artifacts verified for LANPilot Audit ${version}.`);
