import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const read = (path) => readFileSync(join(root, path), "utf8");
const packageVersion = JSON.parse(read("package.json")).version;
const packageLock = JSON.parse(read("package-lock.json"));
const lockVersion = packageLock.version;
const lockRootVersion = packageLock.packages?.[""]?.version;
const tauriVersion = JSON.parse(read("src-tauri/tauri.conf.json")).version;
const cargoVersion = read("src-tauri/Cargo.toml").match(/^version = "([^"]+)"/m)?.[1];
const engineVersion = read("bundled-engine/lanpilot-audit/VERSION").trim();
const rustEngineVersion = read("src-tauri/src/lib.rs").match(/const BUNDLED_ENGINE_VERSION: &str = "([^"]+)"/)?.[1];

const cargoLockVersion = read("src-tauri/Cargo.lock").match(
  /name = "lanpilot-audit-app"\nversion = "([^"]+)"/,
)?.[1];
const appVersions = { packageVersion, lockVersion, lockRootVersion, tauriVersion, cargoVersion, cargoLockVersion };
for (const [name, version] of Object.entries(appVersions)) {
  if (version !== packageVersion) throw new Error(`${name} is ${version}; expected app version ${packageVersion}.`);
}
if (rustEngineVersion !== engineVersion) {
  throw new Error(`Rust bundled engine version is ${rustEngineVersion}; bundled engine is ${engineVersion}.`);
}
if (process.env.GITHUB_REF_TYPE === "tag" && process.env.GITHUB_REF_NAME !== `v${packageVersion}`) {
  throw new Error(`Release tag ${process.env.GITHUB_REF_NAME} does not match app version v${packageVersion}.`);
}

console.log(`Version consistency passed: app ${packageVersion}, engine ${engineVersion}.`);
