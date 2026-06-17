import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";

const root = new URL("../", import.meta.url).pathname;
const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const packageJson = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));

function run(args) {
  execFileSync(npm, args, { cwd: root, stdio: "inherit" });
}

function findArtifacts(directory, suffixes) {
  if (!statSync(directory, { throwIfNoEntry: false })) return [];
  const results = [];
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    const stats = statSync(path);
    if (stats.isDirectory() && entry.endsWith(".app")) {
      if (suffixes.includes(".app")) results.push(path);
      continue;
    }
    if (stats.isDirectory()) results.push(...findArtifacts(path, suffixes));
    else if (suffixes.some((suffix) => entry.endsWith(suffix))) results.push(path);
  }
  return results;
}

run(["run", "check"]);
run(["run", "app:build"]);

const bundleRoot = join(root, "src-tauri", "target", "release", "bundle");
const appPaths = findArtifacts(bundleRoot, [".app"]);
const dmgPaths = findArtifacts(bundleRoot, [".dmg"]);

if (process.platform === "darwin") {
  for (const appPath of appPaths) {
    execFileSync("/usr/bin/codesign", ["--force", "--deep", "--sign", "-", appPath], { stdio: "inherit" });
    execFileSync("/usr/bin/codesign", ["--verify", "--deep", "--strict", appPath], { stdio: "inherit" });
  }
  if (appPaths.length === 1 && dmgPaths.length === 1) {
    execFileSync("/usr/bin/hdiutil", ["create", "-volname", "LANPilot Audit", "-srcfolder", appPaths[0], "-ov", "-format", "UDZO", dmgPaths[0]], { stdio: "inherit" });
  }
}

run(["run", "checksums"]);
const generatedAt = new Date().toISOString();
const notes = `# LANPilot Audit Local Release

- Version: ${packageJson.version}
- Generated: ${generatedAt}
- Validation: \`npm run check\` passed
- Local signing: ad-hoc signed and strictly verified

## App
${appPaths.map((path) => `- ${path}`).join("\n") || "- Not generated"}

## DMG
${dmgPaths.map((path) => `- ${path}`).join("\n") || "- Not generated"}

## Checksums
- ${join(root, "checksums", "SHA256SUMS.txt")}

## Distribution Note
This is a local build. Developer ID signing, notarization, and App Store submission are separate distribution steps.
`;
writeFileSync(join(root, "release-notes-local.md"), notes);

console.log("\nLocal release artifacts:");
appPaths.forEach((path) => console.log(`APP: ${relative(root, path)}`));
dmgPaths.forEach((path) => console.log(`DMG: ${relative(root, path)}`));
console.log("Release notes: release-notes-local.md");
