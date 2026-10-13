#!/usr/bin/env node
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../", import.meta.url));
const read = (path) => readFileSync(join(root, path), "utf8");
const packageVersion = JSON.parse(read("package.json")).version;
const config = JSON.parse(read("src-tauri/tauri.appstore.conf.json"));
const entitlements = read("src-tauri/entitlements/appstore.entitlements");
const infoPlist = read("src-tauri/Info.plist");
const supportedLocales = read("src/i18n/types.ts")
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

const failures = [];
const warnings = [];
const resources = config.bundle?.resources ?? {};
const macFiles = config.bundle?.macOS?.files ?? {};

function fail(message) {
  failures.push(message);
}

function warn(message) {
  warnings.push(message);
}

if (config.version !== packageVersion) {
  fail(`App Store config version is ${config.version}; expected ${packageVersion}.`);
}

if (config.bundle?.resources !== null) {
  fail("App Store config must set bundle.resources to null so the full audit engine is not merged into the sandboxed store bundle.");
}

if (!config.bundle?.macOS?.entitlements?.endsWith("appstore.entitlements")) {
  fail("App Store config must use the App Store sandbox entitlements file.");
}

if (config.bundle?.macOS?.infoPlist !== "Info.plist") {
  fail("App Store config must merge src-tauri/Info.plist.");
}

if (!entitlements.includes("com.apple.security.app-sandbox")) {
  fail("App Store entitlements must enable App Sandbox.");
}

for (const key of ["com.apple.security.network.client", "com.apple.security.network.server"]) {
  if (!entitlements.includes(key)) fail(`App Store entitlements are missing ${key}.`);
}

if (!infoPlist.includes("NSLocalNetworkUsageDescription")) {
  fail("Info.plist is missing NSLocalNetworkUsageDescription.");
}

if (!infoPlist.includes("LSApplicationCategoryType") || !infoPlist.includes("public.app-category.utilities")) {
  fail("Info.plist must set LSApplicationCategoryType to public.app-category.utilities for Mac App Store submission.");
}

if (!infoPlist.includes("LSMinimumSystemVersion") || !infoPlist.includes("<string>12.0</string>")) {
  fail("Info.plist must set LSMinimumSystemVersion to 12.0 or higher for the arm64-only Mac App Store build.");
}

if (/bundled-engine|nmap|shell|script/i.test(JSON.stringify({ resources, macFiles }))) {
  fail("App Store bundle inputs must not include the bundled audit engine, nmap, shell, or script resources.");
}

for (const locale of supportedLocales) {
  const lproj = lprojByLocale[locale];

  if (!lproj) {
    fail(`No App Store lproj mapping for supported locale ${locale}.`);
    continue;
  }

  const source = `appstore-localization/${lproj}/InfoPlist.strings`;
  const target = `${lproj}/InfoPlist.strings`;
  const path = join(root, "src-tauri", source);

  if (!existsSync(path)) {
    fail(`Missing localized local-network purpose string: src-tauri/${source}`);
    continue;
  }

  const content = read(`src-tauri/${source}`);

  if (!content.includes("NSLocalNetworkUsageDescription")) {
    fail(`Missing NSLocalNetworkUsageDescription key in src-tauri/${source}`);
  }

  if (!Object.entries(macFiles).some(([to, from]) => from === source && to === `Resources/${target}`)) {
    fail(`App Store config does not bundle Resources/${target} <- ${source}.`);
  }
}

if (process.platform === "darwin") {
  const { spawnSync } = await import("node:child_process");
  const identities = spawnSync("security", ["find-identity", "-v", "-p", "codesigning"], { encoding: "utf8" });

  if (!/Apple Distribution:|Mac App Distribution:|3rd Party Mac Developer Application:/.test(identities.stdout)) {
    warn("Mac App Store distribution signing identity was not found locally. This is required before upload, but not for source readiness.");
  }
}

for (const message of warnings) console.warn(`[WARN] ${message}`);

if (failures.length) {
  for (const message of failures) console.error(`[FAIL] ${message}`);
  process.exit(1);
}

console.log(`App Store readiness metadata passed for LANPilot Audit ${packageVersion}.`);
