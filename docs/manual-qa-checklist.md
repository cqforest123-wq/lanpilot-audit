# Manual QA Checklist

## Remediation Assistant

- [ ] Generate a remediation pack from the latest report and confirm all five fixed artifacts exist.
- [ ] Edit owner, due date, status, justification, and notes; save and reopen the page.
- [ ] Confirm the exported audit ZIP includes the remediation artifacts.
- [ ] Confirm Enter Authorized Retest opens a fresh authorization confirmation.
- [ ] Confirm there is no arbitrary command field or automatic configuration-change action.
- [ ] Confirm common report asset labels and remediation guidance are localized while Raw Evidence remains original.

## Installation And Startup

- [ ] Mount the generated DMG and verify its displayed version.
- [ ] Drag LANPilot Audit into Applications.
- [ ] Launch the app for the first time and record any macOS security warning.
- [ ] Confirm Settings displays version 1.7.0 and the actual bundled engine version.

## Overnight Full Acceptance

- [ ] Download the DMG, verify SHA-256, open it, and install the App.
- [ ] Confirm first launch behavior and document the expected macOS warning for the ad-hoc signed, not-notarized build.
- [ ] Switch among English, Simplified Chinese, Japanese, and Korean; verify major pages and localized report views contain no ordinary English fallback.
- [ ] Confirm Raw Evidence preserves original text.
- [ ] Confirm project name and authorization checkbox are required before real checks can run.
- [ ] Install/update the bundled engine; validate nmap ready, missing, and limited modes.
- [ ] Run approved steps 01-08 and governance steps 09-12; confirm fixed sequence and stop-on-failure behavior.
- [ ] Verify localized report, Raw Evidence, finding de-duplication, Asset Inventory, Service Exposure Matrix, Local Network Config, mDNS, Web/TLS, Snapshot Compare, and Remediation Tracking.
- [ ] Verify Export ZIP plus HTML, Markdown, CSV, JSON, and spreadsheet outputs.
- [ ] Confirm Settings version and engine version.
- [ ] Confirm there is no arbitrary shell input, custom command, automatic network configuration repair, credential activity, or unauthorized login.
- [ ] Close and reopen the App; confirm local data remains available.
- [ ] Remove the App's Application Support engine in a test profile; confirm first-start engine installation can restore it.

## Language And Authorization

- [ ] Switch through every supported language and confirm the interface remains usable.
- [ ] Confirm the authorization statement must be accepted before a real audit can start.
- [ ] Confirm authorization is consumed once and cannot be bypassed.
- [ ] Confirm no arbitrary shell input or custom-command field is present.

## Engine And Dependencies

- [ ] Install or update the bundled engine through Engine Setup.
- [ ] Confirm a modified bundled-engine manifest is rejected.
- [ ] Confirm limited mode remains clear and usable when `nmap` is missing.

## Audit And Reports

- [ ] Run a real audit on an explicitly authorized network.
- [ ] Confirm the fixed audit steps run in order and stop clearly on failure.
- [ ] Confirm localized report labels use the selected language.
- [ ] Confirm Raw Evidence preserves original evidence text.
- [ ] Confirm the report describes point-in-time limitations.

## Export And Safety Boundary

- [ ] Export a report ZIP and verify expected files open successfully.
- [ ] Confirm symbolic links are excluded from ZIP export.
- [ ] Confirm the app provides no credential-testing or unauthorized-login workflow.
- [ ] Confirm the app provides no network-device configuration changes.
- [ ] Confirm the app provides no arbitrary shell input.
- [ ] Confirm Assets, Service Exposure, Compare, and Remediation pages load.
- [ ] Confirm remediation metadata persists locally without executing a change.
- [ ] Confirm ZIP export includes enhanced governance outputs.
