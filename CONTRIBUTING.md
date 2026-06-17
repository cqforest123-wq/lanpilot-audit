# Contributing

Thanks for helping LANPilot Audit stay useful, boring in the right places, and safe by design.

## Setup

```sh
npm install
npm run engine:sync
npm run check
```

## Development Commands

```sh
npm run dev
npm run tauri -- dev
npm run app:build
```

## Test Commands

```sh
npm run check
npm run i18n:visible-check
npm run security:deep-check
npm run qa:governance-fixtures
npm run public:check
```

## Internationalization

- Add visible UI copy through the i18n message files.
- Keep CJK screens free of English fallback for major workflows.
- Preserve Raw Evidence in its original generated language.

## Safety Boundary Rules

Do not add:

- Exploit modules.
- Credential testing.
- Brute force.
- Default-password testing.
- Unauthorized login.
- Arbitrary shell command input.
- Automatic configuration changes.
- Lateral movement.
- Cloud upload of audit evidence.

## Adding A Governance Check

1. Keep the check low-intensity and authorized-governance only.
2. Add it to the fixed allowlisted engine surface.
3. Write structured output with stable CSV/JSON headers.
4. Add report localization and raw evidence preservation.
5. Add safety and fixture tests.

## Adding Report Fields

1. Prefer structured source files over parsing rendered prose.
2. Keep field names stable.
3. Include missing-file tolerance in the app.
4. Extend export and ZIP coverage when the field affects report artifacts.

## Pull Request Checklist

- [ ] `npm run check` passes.
- [ ] `npm run public:check` passes or documented warnings are acceptable.
- [ ] No new offensive security capability.
- [ ] No secrets, local audit outputs, private screenshots, or personal data.
- [ ] i18n impact is handled.
- [ ] Data privacy impact is documented.
