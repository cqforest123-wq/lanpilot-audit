#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, lstatSync, readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const version = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;
const app = join(root, "src-tauri", "target", "release", "bundle", "macos", "LANPilot Audit.app");
const infoPlist = join(app, "Contents", "Info.plist");
const resources = join(app, "Contents", "Resources");
const supportedLocales = readFileSync(join(root, "src", "i18n", "types.ts"), "utf8")
  .match(/supportedLocales\s*=\s*\[([^\]]+)\]/s)?.[1]
  ?.match(/"([^"]+)"/g)
  ?.map((value) => value.replaceAll("\"", "")) ?? [];

const lprojByLocale = {
  en: "en.lproj",
  "zh-CN": "zh-Hans.lproj",
  "zh-TW": "zh-Hant.lproj",
  ja: "ja.lproj",
  ko: "ko.lproj",
  de: "de.lproj",
  fr: "fr.lproj",
  es: "es.lproj",
  "pt-BR": "pt-BR.lproj",
  it: "it.lproj",
  nl: "nl.lproj",
};

const passes = [];
const warnings = [];
const failures = [];

function pass(name, detail) {
  passes.push({ name, detail });
  console.log(`[PASS] ${name}: ${detail}`);
}

function warn(name, detail) {
  warnings.push({ name, detail });
  console.warn(`[WARN] ${name}: ${detail}`);
}

function fail(name, detail) {
  failures.push({ name, detail });
  console.error(`[FAIL] ${name}: ${detail}`);
}

function run(command, args) {
  const result = spawnSync(command, args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  return { status: result.status, output: `${result.stdout ?? ""}${result.stderr ?? ""}` };
}

function plistValue(key) {
  const result = run("/usr/bin/plutil", ["-extract", key, "raw", "-o", "-", infoPlist]);

  if (result.status !== 0) return null;
  return result.output.trim();
}

function collect(directory, files = []) {
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    const metadata = lstatSync(path);

    if (metadata.isDirectory()) collect(path, files);
    else files.push(relative(app, path));
  }

  return files;
}

console.log(`LANPilot Audit ${version} App Store bundle verification\n`);

if (!existsSync(app)) {
  fail("App bundle", `Missing: ${app}`);
} else {
  pass("App bundle", app);
}

if (!existsSync(infoPlist)) {
  fail("Info.plist", `Missing: ${infoPlist}`);
} else {
  const bundleVersion = plistValue("CFBundleShortVersionString");
  const identifier = plistValue("CFBundleIdentifier");
  const localNetworkUsage = plistValue("NSLocalNetworkUsageDescription");

  if (bundleVersion === version) pass("Bundle version", bundleVersion);
  else fail("Bundle version", `${bundleVersion ?? "missing"}; expected ${version}`);

  if (identifier === "com.litao.lanpilotaudit") pass("Bundle identifier", identifier);
  else fail("Bundle identifier", `${identifier ?? "missing"}; expected com.litao.lanpilotaudit`);

  if (localNetworkUsage?.includes("local network") && localNetworkUsage.includes("authorized")) {
    pass("Local network purpose string", localNetworkUsage);
  } else {
    fail("Local network purpose string", localNetworkUsage || "missing");
  }
}

if (!existsSync(resources)) {
  fail("Resources", `Missing: ${resources}`);
} else {
  const files = collect(resources);
  const forbidden = files.filter((file) =>
    /bundled-engine|\/nmap$|\.sh$|\.py$|\.command$|\.tool$/i.test(file),
  );

  if (forbidden.length === 0) pass("Sandbox resources", "No bundled engine, nmap, shell scripts, Python scripts, or command tools found");
  else fail("Sandbox resources", `Forbidden files found: ${forbidden.join(", ")}`);

  for (const locale of supportedLocales) {
    const lproj = lprojByLocale[locale];
    const path = join(resources, lproj, "InfoPlist.strings");

    if (!existsSync(path)) {
      fail("Localized purpose string", `Missing ${lproj}/InfoPlist.strings for ${locale}`);
      continue;
    }

    const content = readFileSync(path, "utf8");

    if (content.includes("NSLocalNetworkUsageDescription")) {
      pass(`Localized purpose string ${locale}`, lproj);
    } else {
      fail("Localized purpose string", `${lproj}/InfoPlist.strings is missing NSLocalNetworkUsageDescription`);
    }
  }
}

const entitlements = run("/usr/bin/codesign", ["-d", "--entitlements", ":-", app]);

if (entitlements.status !== 0) {
  fail("Entitlements", entitlements.output.trim() || "Unable to read entitlements");
} else {
  for (const key of [
    "com.apple.security.app-sandbox",
    "com.apple.security.network.client",
    "com.apple.security.network.server",
  ]) {
    if (entitlements.output.includes(key)) pass(`Entitlement ${key}`, "present");
    else fail(`Entitlement ${key}`, "missing");
  }
}

const signature = run("/usr/bin/codesign", ["-dv", "--verbose=4", app]);

if (signature.status !== 0) {
  fail("Code signature", signature.output.trim() || "Unable to inspect signature");
} else if (/Authority=Apple Distribution:|Authority=Mac App Distribution:|Authority=3rd Party Mac Developer Application:/.test(signature.output)) {
  pass("Code signature", "Mac App Store distribution signed");
} else if (/Signature=adhoc/.test(signature.output)) {
  warn("Code signature", "Ad-hoc signed; valid for local sandbox verification, not for App Store upload");
} else {
  warn("Code signature", "Signed, but not recognized as Mac App Store distribution identity");
}

console.log("\nApp Store bundle verification summary");
console.log(`PASS: ${passes.length}`);
console.log(`WARN: ${warnings.length}`);
console.log(`FAIL: ${failures.length}`);

if (failures.length) process.exit(1);
