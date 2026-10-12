# App Store Submission Readiness

## Current Status

LANPilot Audit has a sandbox-clean App Store build path for the Lite experience.
This build is separate from the full Developer ID DMG release on GitHub.

Verified locally:

- App Sandbox entitlement is enabled.
- Network client and network server entitlements are present.
- The full bundled audit engine is excluded from the App Store bundle.
- `NSLocalNetworkUsageDescription` is present.
- Local network purpose strings are localized for every supported UI locale.
- Quick Check sandbox capabilities are measured with `npm run sandbox:verify`.

## Verification Commands

```sh
npm run appstore:check
npm run sandbox:verify
npm run app:build:appstore
npm run appstore:bundle:verify
```

Or run the combined check:

```sh
npm run appstore:verify
```

## Upload Blocker

The local machine currently has Developer ID signing for direct distribution,
but Mac App Store upload still requires App Store distribution signing assets.

Required before upload:

- Apple Distribution, Mac App Distribution, or 3rd Party Mac Developer
  Application signing identity.
- App Store Connect app record.
- Store screenshots and metadata.
- Transporter or App Store Connect upload workflow.

## Distribution Boundary

- GitHub Release DMG: full local audit engine, Developer ID signed and
  notarized.
- Mac App Store build: sandboxed Lite build, no bundled engine, no subprocess
  audit workflow, no `nmap`.

Both builds retain the safety boundary: no exploit activity, no credential
testing, no brute force, no unauthorized login, no cloud upload, and no
automatic network configuration changes.
