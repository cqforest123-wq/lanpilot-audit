import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { extname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const version = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;
const app = join(root, "src-tauri", "target", "release", "bundle", "macos", "LANPilot Audit.app");
const dmg = join(root, "src-tauri", "target", "release", "bundle", "dmg", `LANPilot Audit_${version}_aarch64.dmg`);
const plist = join(app, "Contents", "Info.plist");
const report = join(root, "docs", "nightly", "v1.4.0-installed-app-qa.md");
const failures = [];
const warnings = [];
const rows = [];
const check = (name, pass, detail) => { rows.push([pass ? "PASS" : "FAIL", name, detail]); if (!pass) failures.push(`${name}: ${detail}`); };
for (const [name, path] of [["App", app], ["DMG", dmg], ["Info.plist", plist]]) check(name, existsSync(path), path);

function plistValue(key) {
  return execFileSync("/usr/bin/plutil", ["-extract", key, "raw", "-o", "-", plist], { encoding: "utf8" }).trim();
}
if (existsSync(plist)) {
  for (const key of ["CFBundleName", "CFBundleDisplayName", "CFBundleIdentifier", "CFBundleShortVersionString", "CFBundleVersion"]) {
    const value = plistValue(key);
    check(`Info.plist ${key}`, Boolean(value), value);
  }
  check("Bundle version", plistValue("CFBundleShortVersionString") === version, plistValue("CFBundleShortVersionString"));
}
const engine = join(app, "Contents", "Resources", "bundled-engine", "lanpilot-audit");
check("Bundled engine", existsSync(join(engine, "ENGINE_SHA256SUMS.txt")), engine);
const forbidden = [];
const absoluteLeaks = [];
function walk(directory) {
  if (!existsSync(directory)) return;
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    const rel = relative(app, path);
    if (entry.name === ".git" || entry.name === "node_modules") forbidden.push(rel);
    if (entry.isDirectory()) walk(path);
    else if (entry.isFile() && [".html", ".js", ".json", ".md", ".txt"].includes(extname(entry.name))) {
      let content = "";
      try { content = readFileSync(path, "utf8"); } catch { /* binary or unreadable file */ }
      if (content.includes(`${process.env.HOME}/`)) absoluteLeaks.push(rel);
    }
  }
}
walk(app);
check("No .git or node_modules", forbidden.length === 0, forbidden.join(", ") || "none");
check("No local absolute-path leak", absoluteLeaks.length === 0, absoluteLeaks.join(", ") || "none");
if (existsSync(app)) {
  const bytes = Number(execFileSync("/usr/bin/du", ["-sk", app], { encoding: "utf8" }).trim().split(/\s+/)[0]) * 1024;
  rows.push(["PASS", "App bundle size", `${bytes} bytes`]);
  if (bytes > 100 * 1024 * 1024) warnings.push("App bundle exceeds 100 MB.");
}
if (existsSync(dmg)) rows.push(["PASS", "DMG SHA-256", createHash("sha256").update(readFileSync(dmg)).digest("hex")]);
const codesign = spawnSync("/usr/bin/codesign", ["-dv", "--verbose=4", app], { encoding: "utf8" });
const signatureOutput = `${codesign.stdout ?? ""}${codesign.stderr ?? ""}`;
const signature = /Developer ID Application:/.test(signatureOutput) ? "Developer ID signed" : /Signature=adhoc/.test(signatureOutput) ? "ad-hoc signed" : "unknown";
const stapler = spawnSync("/usr/bin/xcrun", ["stapler", "validate", dmg], { encoding: "utf8" });
warnings.push(`Signature: ${signature}; notarized/stapled: ${stapler.status === 0 ? "yes" : "no"}.`);
mkdirSync(join(root, "docs", "nightly"), { recursive: true });
writeFileSync(report, `# v1.4.0 Installed App QA

- Version: ${version}
- Result: ${failures.length ? "FAIL" : "PASS"}
- Apple credential absence is a warning, not a product QA failure.

| Result | Check | Detail |
|---|---|---|
${rows.map((row) => `| ${row[0]} | ${row[1]} | ${String(row[2]).replaceAll("|", "\\|")} |`).join("\n")}

## Warnings
${warnings.map((item) => `- ${item}`).join("\n")}
`);
if (failures.length) throw new Error(failures.join("\n"));
console.log(`Installed app QA passed. ${warnings.join(" ")}`);
