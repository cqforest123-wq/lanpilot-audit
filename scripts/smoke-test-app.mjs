import { execFileSync, spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const version = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;
const binary = join(
  root,
  "src-tauri",
  "target",
  "release",
  "bundle",
  "macos",
  "LANPilot Audit.app",
  "Contents",
  "MacOS",
  "lanpilot-audit-app",
);
const infoPlist = join(root, "src-tauri", "target", "release", "bundle", "macos", "LANPilot Audit.app", "Contents", "Info.plist");

if (process.platform !== "darwin") {
  console.log("App launch smoke test is skipped outside macOS.");
  process.exit(0);
}
if (!existsSync(binary)) throw new Error("Release app binary is missing. Run npm run app:build first.");
const bundleVersion = execFileSync(
  "/usr/bin/plutil",
  ["-extract", "CFBundleShortVersionString", "raw", "-o", "-", infoPlist],
  { encoding: "utf8" },
).trim();
if (bundleVersion !== version) throw new Error(`Release app bundle is version ${bundleVersion}; expected ${version}.`);

const app = spawn(binary, [], { stdio: ["ignore", "pipe", "pipe"] });
let stdout = "";
let stderr = "";
app.stdout.on("data", (chunk) => { stdout += chunk; });
app.stderr.on("data", (chunk) => { stderr += chunk; });

const result = await new Promise((resolve) => {
  const timer = setTimeout(() => resolve({ alive: app.exitCode === null }), 5000);
  app.once("exit", (code, signal) => {
    clearTimeout(timer);
    resolve({ alive: false, code, signal });
  });
});

if (!result.alive) {
  throw new Error(`Release app exited during smoke test: ${JSON.stringify(result)}\nstdout: ${stdout}\nstderr: ${stderr}`);
}
app.kill("SIGTERM");
await new Promise((resolve) => setTimeout(resolve, 500));
if (app.exitCode === null) app.kill("SIGKILL");
console.log(`Release app launch smoke test passed for LANPilot Audit ${version}.`);
