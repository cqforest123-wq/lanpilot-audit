#!/usr/bin/env node
/**
 * Proves that Quick Check still works under App Sandbox.
 *
 * The whole App Store plan rests on unprivileged ICMP, UDP, and the local
 * lookups working inside the sandbox. That is an empirical question, not a
 * design decision, so it is checked rather than assumed. It also pins the
 * network.server requirement: without it the ICMP socket still *opens* and
 * only send fails, so a shallower check would pass and ship a broken app.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync, mkdirSync, copyFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ENTITLEMENTS = "src-tauri/entitlements/appstore.entitlements";
const EXAMPLE = "sandbox_probe";

function run(command, args, options = {}) {
  return spawnSync(command, args, { encoding: "utf8", ...options });
}

console.log("Building the sandbox probe…");
const build = run("cargo", ["build", "--manifest-path", "src-tauri/Cargo.toml", "--example", EXAMPLE]);
if (build.status !== 0) {
  console.error(build.stderr);
  process.exit(1);
}

const work = mkdtempSync(join(tmpdir(), "lanpilot-sandbox-"));
const app = join(work, "SandboxProbe.app");
mkdirSync(join(app, "Contents", "MacOS"), { recursive: true });
copyFileSync(`src-tauri/target/debug/examples/${EXAMPLE}`, join(app, "Contents", "MacOS", "SandboxProbe"));
writeFileSync(join(app, "Contents", "Info.plist"), `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>SandboxProbe</string>
<key>CFBundleIdentifier</key><string>com.litao.lanpilotaudit.sandboxprobe</string>
<key>CFBundleName</key><string>SandboxProbe</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>CFBundleVersion</key><string>1</string>
</dict></plist>
`);

// Ad-hoc signing is enough: the sandbox activates from the entitlement, and the
// probe reports whether HOME was redirected into a container to confirm it.
execFileSync("codesign", ["--force", "--deep", "--sign", "-", "--entitlements", ENTITLEMENTS, app]);

const probe = run(join(app, "Contents", "MacOS", "SandboxProbe"), [], { timeout: 60_000 });
const output = probe.stdout || "";
console.log(output);
rmSync(work, { recursive: true, force: true });

if (!output.includes("Sandbox enforcing : yes")) {
  console.error("Sandbox did not engage; this run proves nothing.");
  process.exit(1);
}
const failures = output.split("\n").filter((line) => line.includes("[FAIL]"));
if (failures.length > 0) {
  console.error(`Sandbox verification failed:\n${failures.join("\n")}`);
  process.exit(1);
}
console.log("Sandbox verification passed: every Quick Check capability works sandboxed.");
