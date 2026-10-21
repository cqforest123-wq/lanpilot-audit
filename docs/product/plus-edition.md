# LANPilot Audit Plus

## Product direction

Keep LANPilot Audit useful as a free local network governance tool. Offer Plus as an optional one-time purchase for users who need deeper analysis and ongoing governance workflows. Do not make core safety, authorization, privacy, or basic reporting depend on payment.

The macOS 1.8.1 build is currently in App Review. This document is a forward-looking product decision only; it does not change that submitted build, its metadata, or its review notes.

## Free edition

The free edition should remain useful on its own:

- Quick Check and a basic authorized local network assessment.
- A dedicated Wi-Fi section with a free, user-initiated scan of devices visible on the current local network.
- Essential asset and service visibility within the approved scope.
- A readable summary of findings and basic remediation guidance.
- Local-first processing, local report access, and explicit authorization.
- The published safety boundary: no exploit activity, credential testing, brute force, unauthorized login, lateral movement, or automatic network configuration changes.

## Plus candidates

Consider these as the paid value, subject to implementation and App Review:

- Network Doctor deep diagnosis with evidence-linked root-cause candidates and retest plans.
- Deeper passive Wi-Fi security and signal-quality assessment, limited to information available through supported macOS APIs and permissions.
- Historical snapshots, baseline comparison, and change timeline across multiple runs.
- Remediation tracking, ownership, acceptance records, and repeatable verification plans.
- Enhanced governance reports and redacted support bundles.
- Additional report export formats and team-ready workflow artifacts, generated locally.

Keep one basic diagnosis, current-run findings, and a useful report available for free. The paid tier should extend depth and continuity rather than withhold the result needed to understand a current safety issue.

## Wi-Fi section and navigation

Add one top-level Wi-Fi entry to the app navigation. Keep the sidebar compact by placing Wi-Fi workflows inside that section as tabs or subnavigation:

- **Devices (free):** scan devices visible on the current local network. Explain that results depend on current network conditions, permissions, and what devices expose; do not promise discovery of every connected device.
- **Security (Plus):** deeper passive checks of the current connection and supported, user-provided router details. No login attempts, password guessing, or configuration changes.
- **Signal (Plus):** assess the current connection's signal and channel information where macOS exposes it. Do not promise a spectrum analyzer or background scanning of nearby networks unless platform and App Store validation proves it is available.
- **History (Plus):** compare locally saved Wi-Fi observations over time. Keep the history on-device and provide a clear delete/export path.

The Wi-Fi overview and basic device scan remain usable without Plus. Mark paid tabs clearly and explain the included capability before opening purchase. Do not add separate sidebar items for every Wi-Fi workflow.

Implementation status: the `feat/wifi-workspace-foundation` branch adds the dedicated navigation entry and free device-discovery page using the existing scoped sweep and consent flow. The paid Wi-Fi workflows remain product candidates and are not hidden or dormant in the current App Store submission.

## Speed testing

Do not build a speed-test feature. Reliable speed tests for users in many countries require geographically suitable test infrastructure, consistent endpoints, and careful interpretation of ISP routing, VPNs, proxies, and congestion. A local diagnostic tool should not imply a universal internet-speed result without those dependencies. Keep diagnosis focused on path, DNS, gateway, reachability, and observable link quality.

## Purchase model

Preferred first model: a non-consumable, one-time Plus unlock for the Mac App Store edition. The app must use StoreKit In-App Purchase to unlock digital functionality sold inside the app. Do not add an external checkout link or an account/license bypass to the App Store build without confirming the applicable Apple entitlement and storefront rules.

Do not introduce an auto-renewable subscription unless LANPilot later provides clear ongoing value that justifies recurring billing. A local-only feature bundle by itself is a poor subscription fit.

The Developer ID direct-download edition is a separate distribution channel. Decide whether it shares the App Store purchase, uses a separately documented license, or remains fully featured only after reviewing the public license, support burden, and Apple rules. Do not silently make the open-source repository imply that a payment unlocks rights granted by its software license.

## Review and implementation gates

Before building the paywall or gating code:

1. Let the current 1.8.1 review finish without changing its binary or review metadata.
2. Confirm the free/Plus feature list, one-time price, supported storefronts, and refund/support language.
3. Create the non-consumable In-App Purchase in App Store Connect and configure its review screenshot and notes.
4. Implement StoreKit purchase, restore, entitlement refresh, offline behavior, and purchase-state tests.
5. Keep review access to Plus available through Apple's sandbox purchase flow and explain it in review notes.
6. Update privacy disclosures, listing copy, screenshots, and the digital-goods questionnaire to match the actual purchase flow.
7. Verify the app remains useful when StoreKit is unavailable and never blocks basic safety information or user-owned local data.

Apple's current App Review Guidelines require In-App Purchase when an app unlocks digital features or functionality. Auto-renewable subscriptions must provide ongoing value. Check the current guidelines again when implementation begins because storefront rules can change.

## Explicit exclusions

- No cloud upload or remote processing as a prerequisite for Plus.
- No default-password checks, brute force, exploit checks, unauthorized logins, or configuration changes.
- No paywall around authorization, safety disclosures, privacy controls, or access to existing local reports.
- No recurring subscription until the product offers meaningful ongoing value.
- No speed-test feature or dependence on third-party speed-test endpoints.
- No changes to the submitted 1.8.1 build while it is under review.
