import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const version = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;
const source = join(root, "src-tauri", "target", "release", "bundle", "dmg", `LANPilot Audit_${version}_aarch64.dmg`);
const outputDirectory = join(root, "release-assets");
const outputName = `LANPilot-Audit_${version}_aarch64.dmg`;
const output = join(outputDirectory, outputName);

rmSync(outputDirectory, { recursive: true, force: true });
mkdirSync(outputDirectory, { recursive: true });
copyFileSync(source, output);
const checksum = createHash("sha256").update(readFileSync(output)).digest("hex");
writeFileSync(join(outputDirectory, "SHA256SUMS.txt"), `${checksum}  ${outputName}\n`);
console.log(`Release assets prepared for LANPilot Audit ${version}.`);
