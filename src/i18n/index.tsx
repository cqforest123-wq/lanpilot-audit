import { createContext, useContext, useMemo, useState, type ReactNode } from "react";
import { de } from "./locales/de"; import { en } from "./locales/en"; import { es } from "./locales/es";
import { fr } from "./locales/fr"; import { it } from "./locales/it"; import { ja } from "./locales/ja";
import { ko } from "./locales/ko"; import { nl } from "./locales/nl"; import { ptBR } from "./locales/pt-BR";
import { zhCN } from "./locales/zh-CN"; import { zhTW } from "./locales/zh-TW";
import { supportedLocales, type Locale, type Messages } from "./types";
import { workflowMessages } from "./workflow";
import { toolboxMessages } from "./toolbox";
import { remediationMessages } from "./remediation";

const localeMessages: Record<Locale, Messages> = { en, "zh-CN": zhCN, "zh-TW": zhTW, ja, ko, de, fr, es, "pt-BR": ptBR, it, nl };
export const messages = Object.fromEntries(supportedLocales.map((locale) => [locale, { ...localeMessages[locale], ...workflowMessages[locale], ...toolboxMessages[locale], ...remediationMessages[locale] }])) as Record<Locale, Messages>;
export function resolveLocale(value?: string | null): Locale {
  const raw = (value || "").replace("_", "-");
  if (/^zh($|-Hans|-CN)/i.test(raw)) return "zh-CN";
  if (/^zh-(Hant|TW|HK|MO)/i.test(raw)) return "zh-TW";
  if (/^pt($|-BR)/i.test(raw)) return "pt-BR";
  const match = supportedLocales.find((locale) => raw.toLowerCase() === locale.toLowerCase() || raw.toLowerCase().startsWith(`${locale.toLowerCase()}-`));
  return match || "en";
}
const Context = createContext({ locale: "en" as Locale, setLocale: (_locale: Locale) => {}, t: (key: string) => messages.en[key] || key });
export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, updateLocale] = useState<Locale>(() => resolveLocale(localStorage.getItem("lanpilot.locale") || navigator.language));
  const value = useMemo(() => ({
    locale,
    setLocale: (next: Locale) => { localStorage.setItem("lanpilot.locale", next); updateLocale(next); },
    t: (key: string) => {
      const translated = messages[locale][key];
      if (!translated && import.meta.env.DEV && locale !== "en") console.warn(`Missing ${locale} translation: ${key}`);
      return translated || en[key] || key;
    },
  }), [locale]);
  return <Context.Provider value={value}>{children}</Context.Provider>;
}
export const useI18n = () => useContext(Context);
export { supportedLocales };
