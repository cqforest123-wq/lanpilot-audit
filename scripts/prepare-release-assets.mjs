import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const version = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;

const dmgName = `LANPilot Audit_${version}_aarch64.dmg`;
const portableDmgName = `LANPilot-Audit_${version}_aarch64.dmg`;

const dmg = join(root, "src-tauri", "target", "release", "bundle", "dmg", dmgName);
const releaseRoot = join(root, "release-assets");
const versionedRelease = join(releaseRoot, `v${version}`);
const checksums = join(root, "checksums");

if (!existsSync(dmg)) {
  throw new Error(`DMG is missing: ${dmg}`);
}

const digest = createHash("sha256").update(readFileSync(dmg)).digest("hex");

mkdirSync(releaseRoot, { recursive: true });
mkdirSync(versionedRelease, { recursive: true });
mkdirSync(checksums, { recursive: true });

copyFileSync(dmg, join(versionedRelease, portableDmgName));
writeFileSync(join(versionedRelease, "SHA256SUMS.txt"), `${digest}  ${portableDmgName}\n`);

copyFileSync(dmg, join(releaseRoot, portableDmgName));
writeFileSync(join(releaseRoot, "SHA256SUMS.txt"), `${digest}  ${portableDmgName}\n`);

writeFileSync(join(checksums, "SHA256SUMS.txt"), `${digest}  ${dmgName}\n`);

console.log(`Prepared release assets for LANPilot Audit ${version}.`);
console.log(`${digest}  ${portableDmgName}`);
