import { describe, expect, it } from "vitest";
import { messages, supportedLocales } from ".";

type MessageTree = Record<string, unknown>;

function missingPaths(reference: MessageTree, candidate: MessageTree, prefix = ""): string[] {
  return Object.entries(reference).flatMap(([key, referenceValue]) => {
    const path = prefix ? `${prefix}.${key}` : key;
    if (!Object.prototype.hasOwnProperty.call(candidate, key)) return [path];

    if (referenceValue && typeof referenceValue === "object" && !Array.isArray(referenceValue)) {
      const candidateValue = candidate[key];
      if (!candidateValue || typeof candidateValue !== "object" || Array.isArray(candidateValue)) return [path];
      return missingPaths(referenceValue as MessageTree, candidateValue as MessageTree, path);
    }

    return [];
  });
}

describe("i18n completeness", () => {
  it.each(supportedLocales)("%s contains every English message key, including nested keys", (locale) => {
    expect(missingPaths(messages.en, messages[locale]), `Missing ${locale} translation keys`).toEqual([]);
  });
});
