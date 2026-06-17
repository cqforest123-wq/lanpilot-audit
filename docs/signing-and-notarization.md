# Signing and Notarization

Local builds do not require Apple credentials. Public website distribution
requires a Developer ID Application identity and notarization.

## Environment

Required:

- `APPLE_TEAM_ID`
- `DEVELOPER_ID_APPLICATION`

Notarization uses App Store Connect API credentials:

- `ASC_KEY_ID`
- `ASC_ISSUER_ID`
- `ASC_KEY_PATH`

The scripts print variable names only and never print secret values.

```sh
npm run notarize:check
npm run release:public
```

The automation uses fixed `codesign`, `hdiutil`, `xcrun notarytool submit`,
and `xcrun stapler` argument templates. It signs the app, rebuilds and signs
the DMG, submits it for notarization, staples the ticket, and validates the
result. Credentials are never committed.

## GitHub Public Release

The `Public Notarized Release` workflow promotes an existing local-build
prerelease after signing and notarization. Configure these repository secrets:

- `APPLE_CERTIFICATE_P12_BASE64`
- `APPLE_CERTIFICATE_PASSWORD`
- `APPLE_KEYCHAIN_PASSWORD`
- `APPLE_TEAM_ID`
- `DEVELOPER_ID_APPLICATION`
- `ASC_KEY_ID`
- `ASC_ISSUER_ID`
- `ASC_KEY_PATH`

Then run the workflow with an existing version tag such as `v1.4.0`.
