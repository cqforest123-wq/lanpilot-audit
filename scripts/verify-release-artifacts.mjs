import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const version = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;
const app = join(root, "src-tauri", "target", "release", "bundle", "macos", "LANPilot Audit.app");
const dmgName = `LANPilot Audit_${version}_aarch64.dmg`;
const dmg = join(root, "src-tauri", "target", "release", "bundle", "dmg", dmgName);
const checksumFile = join(root, "checksums", "SHA256SUMS.txt");
const engine = join(app, "Contents", "Resources", "bundled-engine", "lanpilot-audit");
const infoPlist = join(app, "Contents", "Info.plist");

for (const path of [app, dmg, checksumFile, engine]) {
  if (!existsSync(path)) throw new Error(`Required release artifact is missing: ${path}`);
}
const bundleVersion = execFileSync(
  "/usr/bin/plutil",
  ["-extract", "CFBundleShortVersionString", "raw", "-o", "-", infoPlist],
  { encoding: "utf8" },
).trim();
if (bundleVersion !== version) throw new Error(`Release app bundle is version ${bundleVersion}; expected ${version}.`);

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
    if (metadata.isSymbolicLink()) throw new Error(`Bundled app engine contains a symbolic link: ${path}`);
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
  execFileSync("/usr/bin/codesign", ["--verify", "--deep", "--strict", app], { stdio: "inherit" });
  execFileSync("/usr/bin/hdiutil", ["verify", dmg], { stdio: "inherit" });
}

console.log(`Release artifacts verified for LANPilot Audit ${version}.`);
