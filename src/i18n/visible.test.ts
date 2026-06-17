import { describe, expect, it } from "vitest";
import { messages } from "./index";
import { reportCopy } from "../report-localization";

const cjk = ["zh-CN", "zh-TW", "ja", "ko"] as const;
const criticalKeys = [
  "navRun", "authorization.title", "engine.title", "interface.title", "run.title",
  "toolbox.assets", "toolbox.exposure", "step.localNetworkConfig", "step.mdnsObservation",
  "step.webTlsBaseline", "toolbox.compare", "toolbox.remediation", "report", "export", "settings.title",
  "remediation.title", "remediation.generate", "remediation.retest", "remediation.safety",
];

describe("visible CJK localization", () => {
  it.each(cjk)("%s has no English fallback on major workflow and governance screens", (locale) => {
    for (const key of criticalKeys) {
      expect(messages[locale][key], `${locale}:${key}`).toBeTruthy();
      expect(messages[locale][key], `${locale}:${key}`).not.toBe(messages.en[key]);
    }
  });

  it.each(cjk)("%s report view does not fall back to English headings", (locale) => {
    const localized = reportCopy(locale);
    const english = reportCopy("en");
    for (const key of ["executiveSummary", "riskRegister", "recommendedAction", "remediationRoadmap", "unknown"] as const) {
      expect(localized[key], `${locale}:${key}`).not.toBe(english[key]);
    }
  });

  it("preserves raw evidence outside translated report copy", () => {
    expect(reportCopy("ja").rawEvidence).not.toBe("Raw evidence remains in English.");
    expect("Raw evidence remains in English.").toContain("English");
  });
});
