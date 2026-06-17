# Localization

`npm run i18n:strict-check` verifies complete, non-empty message keys, critical
CJK governance translations, and obvious visible English literals. Raw evidence,
stdout, stderr, paths, addresses, protocol names, and original CSV/Markdown
remain intentionally untranslated.

LANPilot Audit supports English, Simplified Chinese, Traditional Chinese,
Japanese, Korean, German, French, Spanish, Brazilian Portuguese, Italian, and
Dutch.

The UI language is stored in `localStorage`. If no preference exists, the app
maps `navigator.language`, including Chinese script/region handling, and falls
back to English. Missing keys fall back to English and warn in development.

Only UI labels are translated. Original stdout, stderr, evidence files,
Markdown reports, and CSV content remain unchanged.
