import { describe, expect, it } from "vitest";
import { messages } from "./index";
import { supportedLocales } from "./types";

const criticalPrefixes = ["nav", "toolbox.", "step.local", "step.mdns", "step.webTls", "step.enhanced"];
const networkReliabilityKeys = [
  "navNetworkReliability",
  "reliability.title",
  "reliability.description",
  "reliability.run",
  "reliability.currentPath",
  "reliability.faultPoint",
  "reliability.impact",
  "reliability.keyEvidence",
  "reliability.advice",
  "reliability.retest",
  "reliability.physicalLan",
  "reliability.externalInternet",
  "reliability.confirmNoChanges",
];

describe("strict multilingual UI coverage", () => {
  it("provides every English key with a non-empty value in every locale", () => {
    for (const locale of supportedLocales) {
      for (const key of Object.keys(messages.en)) expect(messages[locale][key]?.trim(), `${locale}:${key}`).toBeTruthy();
    }
  });

  it("does not reuse English for critical CJK governance UI", () => {
    for (const locale of ["ja", "ko", "zh-CN", "zh-TW"] as const) {
      for (const key of Object.keys(messages.en).filter((item) => criticalPrefixes.some((prefix) => item.startsWith(prefix)))) {
        expect(messages[locale][key], `${locale}:${key}`).not.toBe(messages.en[key]);
      }
    }
  });

  it("uses locale-specific Network Reliability labels across all non-English languages", () => {
    for (const locale of supportedLocales.filter((item) => item !== "en")) {
      for (const key of networkReliabilityKeys) {
        expect(messages[locale][key], `${locale}:${key}`).toBeTruthy();
        expect(messages[locale][key], `${locale}:${key}`).not.toBe(messages.en[key]);
      }
    }
  });

  it("keeps raw evidence content outside the translation catalog", () => {
    expect(Object.keys(messages.en).some((key) => key.includes("rawEvidenceContent"))).toBe(false);
  });
});
