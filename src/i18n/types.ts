export const supportedLocales = ["en", "zh-CN", "zh-TW", "ja", "ko", "de", "fr", "es", "pt-BR", "it", "nl"] as const;
export type Locale = typeof supportedLocales[number];
export type Messages = Record<string, string>;
