import { createHash } from "node:crypto";
import { cpSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const source = resolve(process.env.LANPILOT_ENGINE_SOURCE || join(root, "..", "lanpilot-audit"));
const destination = join(root, "bundled-engine", "lanpilot-audit");
const checkOnly = process.argv.includes("--check");
const files = [
  "01-init-lab.sh", "02-baseline.sh", "03-passive-assets.sh", "04-client-isolation.sh",
  "05-common-services.sh", "06-smb-posture.sh", "07-gateway-posture.sh", "08-build-report.sh",
  "09-local-network-config.sh", "10-mdns-observation.sh", "11-web-tls-baseline.sh",
  "12-build-enhanced-governance-report.py", "13-build-formats.py",
  "README.md", "VERSION", "lib/common.sh", "run-audit.sh",
];

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function collectBundledFiles(directory, collected = []) {
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    const metadata = lstatSync(path);
    if (metadata.isSymbolicLink()) throw new Error(`Bundled engine contains a symbolic link: ${relative(destination, path)}`);
    if (metadata.isDirectory()) collectBundledFiles(path, collected);
    else if (metadata.isFile() && entry !== "ENGINE_SHA256SUMS.txt") collected.push(relative(destination, path));
  }
  return collected;
}

function verifyBundledManifest() {
  const manifestPath = join(destination, "ENGINE_SHA256SUMS.txt");
  if (!existsSync(manifestPath)) throw new Error("Bundled engine integrity manifest is missing.");
  const manifestLines = readFileSync(manifestPath, "utf8").trim().split("\n");
  const represented = new Set();
  for (const line of manifestLines) {
    const [expected, file] = line.split("  ");
    if (!expected || !file || !files.includes(file)) throw new Error(`Invalid bundled engine manifest line: ${line}`);
    const bundled = join(destination, file);
    if (!existsSync(bundled) || sha256(bundled) !== expected) throw new Error(`Bundled engine integrity check failed: ${file}`);
    represented.add(file);
  }
  if (represented.size !== files.length) throw new Error("Bundled engine manifest does not represent every required file.");
  const actual = collectBundledFiles(destination);
  if (actual.length !== represented.size || actual.some((file) => !represented.has(file))) {
    throw new Error("Bundled engine contains files not represented by its integrity manifest.");
  }
  console.log(`Bundled engine integrity manifest is valid for ${readFileSync(join(destination, "VERSION"), "utf8").trim()}.`);
}

if (!existsSync(source)) {
  if (checkOnly) {
    verifyBundledManifest();
    process.exit(0);
  }
  throw new Error(`LANPilot engine source not found: ${source}`);
}
const sourceVersion = readFileSync(join(source, "VERSION"), "utf8").trim();
const manifest = files.map((file) => {
  const sourceFile = join(source, file);
  if (!existsSync(sourceFile)) throw new Error(`Required engine file is missing: ${sourceFile}`);
  return `${sha256(sourceFile)}  ${file}`;
}).join("\n") + "\n";

if (checkOnly) {
  const mismatches = [];
  for (const file of files) {
    const bundled = join(destination, file);
    if (!existsSync(bundled) || sha256(join(source, file)) !== sha256(bundled)) mismatches.push(file);
  }
  const bundledManifest = join(destination, "ENGINE_SHA256SUMS.txt");
  if (!existsSync(bundledManifest) || readFileSync(bundledManifest, "utf8") !== manifest) mismatches.push("ENGINE_SHA256SUMS.txt");
  if (mismatches.length) throw new Error(`Bundled engine differs from source ${sourceVersion}: ${mismatches.join(", ")}`);
  console.log(`Bundled engine matches source version ${sourceVersion}.`);
  process.exit(0);
}

rmSync(destination, { recursive: true, force: true });
for (const file of files) {
  const target = join(destination, file);
  mkdirSync(dirname(target), { recursive: true });
  cpSync(join(source, file), target);
}
writeFileSync(join(destination, "ENGINE_SHA256SUMS.txt"), manifest);
console.log(`Synced LANPilot engine ${sourceVersion} from ${relative(root, source) || source}.`);
