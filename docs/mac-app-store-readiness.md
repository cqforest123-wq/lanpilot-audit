# Mac App Store Readiness

## Current Review Risks

- App Sandbox restrictions around local script execution.
- The separately installed `nmap` dependency.
- Explaining an authorized network-governance product during review.

## Suggested Store Variant

A possible **LANPilot Audit Lite** variant should emphasize report viewing,
authorization governance, and low-intensity checks. It must not provide
arbitrary commands, install `nmap`, or bypass authorization.

## Review Notes Draft

App is an authorized LAN governance audit assistant. It only runs fixed local
audit steps after explicit user confirmation. It does not perform exploit
activity, credential testing, brute force, unauthorized login, or
configuration changes. Audit evidence remains on the user's Mac.

## Checklists

- Entitlements: sandbox, network client/server justification, file access.
- Privacy: local storage, no cloud upload, user-controlled export.
- Screenshots: authorization, engine setup, run status, report, export.
- Metadata: restrained governance language, supported languages, limitations.
