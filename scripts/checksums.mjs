import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";

const root = new URL("../", import.meta.url).pathname;
const bundleRoot = join(root, "src-tauri", "target", "release", "bundle");
const checksumDirectory = join(root, "checksums");
const checksumPath = join(checksumDirectory, "SHA256SUMS.txt");

function findDmgs(directory) {
  if (!statSync(directory, { throwIfNoEntry: false })) return [];
  return readdirSync(directory).flatMap((entry) => {
    const path = join(directory, entry);
    return statSync(path).isDirectory() ? findDmgs(path) : entry.endsWith(".dmg") ? [path] : [];
  });
}

const dmgs = findDmgs(bundleRoot);
if (dmgs.length === 0) throw new Error("No release DMG found. Run npm run app:build first.");
mkdirSync(checksumDirectory, { recursive: true });
const lines = dmgs.map((path) => `${createHash("sha256").update(readFileSync(path)).digest("hex")}  ${basename(path)}`);
writeFileSync(checksumPath, `${lines.join("\n")}\n`);
console.log(`Checksums: ${checksumPath}`);
