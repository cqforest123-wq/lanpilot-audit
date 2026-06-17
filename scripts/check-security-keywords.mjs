import { readFile, readdir } from "node:fs/promises";
import { extname, join, relative } from "node:path";

const root = new URL("../", import.meta.url).pathname;
const excludedDirectories = new Set([".git", "node_modules", "target", "dist", "gen", "release"]);
const excludedExtensions = new Set([".md", ".lock", ".png", ".ico", ".icns"]);
const prohibited = [
  ["ex", "ploit"],
  ["br", "ute"],
  ["hy", "dra"],
  ["meta", "sploit"],
  ["default", "-password"],
  ["smb", "-enum"],
  ["enum", "-shares"],
  ["rm", " -rf"],
  ["su", "do"],
  ["chmod", " 777"],
  ["vu", "ln"],
  ["custom", " command"],
  ["user", " command"],
  ["sh", " -c"],
  ["ev", "al("],
].map((parts) => parts.join(""));
const reviewedSafetyStatements = [
  /^\s*-\s*exploit\s*$/i,
  /NSE vuln/i,
  /does not include exploit activity/i,
  /does not require exploit code/i,
  /custom_command/,
  /no arbitrary command input/i,
  /no remediation command is executed/i,
];

async function scanDirectory(directory) {
  const findings = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    if (entry.isDirectory() && excludedDirectories.has(entry.name)) continue;
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      findings.push(...await scanDirectory(path));
      continue;
    }
    if (!entry.isFile() || excludedExtensions.has(extname(entry.name).toLowerCase())) continue;
    if (["scripts/check-security-keywords.mjs", "scripts/check-security-deep.mjs"].includes(relative(root, path))) continue;
    const content = await readFile(path, "utf8").catch(() => "");
    for (const [index, line] of content.split(/\r?\n/).entries()) {
      if (reviewedSafetyStatements.some((pattern) => pattern.test(line))) continue;
      const lower = line.toLowerCase();
      for (const keyword of prohibited) {
        if (lower.includes(keyword)) findings.push(`${relative(root, path)}:${index + 1}: ${keyword}`);
      }
    }
  }
  return findings;
}

const findings = await scanDirectory(root);
if (findings.length > 0) {
  console.error("Security keyword check failed:");
  findings.forEach((finding) => console.error(`- ${finding}`));
  process.exit(1);
}
console.log("Security keyword check passed.");
