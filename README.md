# LANPilot Audit

LANPilot Audit -- Local-first LAN governance audit assistant for macOS. Open-source snapshot with notarized DMG distribution handled separately.

[![Release](https://img.shields.io/github/v/release/cqforest123-wq/lanpilot-audit?include_prereleases)](https://github.com/cqforest123-wq/lanpilot-audit/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/cqforest123-wq/lanpilot-audit/ci.yml?branch=main&label=CI)](https://github.com/cqforest123-wq/lanpilot-audit/actions)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
![macOS](https://img.shields.io/badge/macOS-Apple%20Silicon-lightgrey)
![Tauri](https://img.shields.io/badge/Tauri-2.x-24c8db)
![Rust](https://img.shields.io/badge/Rust-backend-orange)
![React](https://img.shields.io/badge/React-UI-61dafb)
![Local First](https://img.shields.io/badge/local--first-no%20cloud%20upload-brightgreen)
![Notarized DMG](https://img.shields.io/badge/DMG-signed%20%2B%20notarized-success)

LANPilot Audit helps small teams understand LAN exposure without turning an audit tool into an offensive scanner. It runs a fixed, authorized, low-intensity local workflow and turns observations into assets, risk registers, remediation plans, evidence, and retest records.

## Visual Preview

Screenshots and demo assets are planned in [docs/assets](docs/assets/README.md). The README intentionally avoids broken image links until final public screenshots are captured.

| Preview slot | Planned asset |
| --- | --- |
| Authorization workflow | Main interface with explicit scope confirmation |
| Localized report | Chinese report view with governance language |
| Remediation workflow | Remediation Assistant and service exposure matrix |

## Quick Start

```sh
git clone https://github.com/cqforest123-wq/lanpilot-audit.git
cd lanpilot-audit
npm install
npm run check
npm run tauri -- dev
```

You can also use `npm run app:dev` for the local Tauri development run.

## Why

Small networks often expose SMB, remote admin, web panels, gateway services, and client-to-client access without a clear owner or remediation path. LANPilot turns low-intensity observations into risk registers, remediation plans, and retest workflows that are useful for small-business governance.

## Safety Boundary

**LANPilot Audit is for networks you own or are explicitly authorized to assess.**

- No exploit modules.
- No credential testing.
- No brute force.
- No default-password testing.
- No unauthorized login.
- No configuration changes.
- No lateral movement.
- No cloud upload of audit evidence.

## Features

- Authorized audit workflow with explicit scope confirmation.
- Local-first engine and local report storage.
- Asset inventory and service exposure matrix.
- Local network configuration observation.
- Bonjour / mDNS observation.
- Web/TLS baseline for already-discovered web services.
- Snapshot comparison across local audit runs.
- Remediation Assistant with fixed local artifacts and authorized retest entry.
- Multilingual UI for 11 locales.
- Raw Evidence preservation for audit traceability.
- Export ZIP, HTML, Markdown, CSV, and JSON outputs.
- Developer ID signed and Apple notarized DMG release path.

## Download

The public repository publishes source snapshots, starting with [LANPilot Audit v1.5.1 Open Source Snapshot](https://github.com/cqforest123-wq/lanpilot-audit/releases/tag/v1.5.1).

Developer ID notarized DMG distribution is handled separately from this open-source snapshot repository so signing, notarization, and release operations stay isolated from public source history.

When a notarized DMG is provided through the distribution channel, verify the SHA-256 checksum before opening it:

```sh
shasum -a 256 "LANPilot-Audit_1.5.0_aarch64.dmg"
cat SHA256SUMS.txt
```

The signed release path supports Developer ID signing, Apple notarization, stapling, and Gatekeeper verification. Internal readiness builds may be marked pre-release when they are not intended for broad distribution.

## Build From Source

```sh
npm install
npm run check
npm run app:build
npm run tauri -- dev
```

Useful release and readiness commands:

```sh
npm run public:check
npm run release:verify
npm run gatekeeper:check
```

## Architecture

- Tauri desktop shell.
- React and TypeScript frontend.
- Rust backend commands with fixed inputs.
- Bundled local audit engine with deterministic SHA-256 manifest.
- Fixed, allowlisted audit steps.
- No arbitrary shell command input.

## Roadmap

- Public docs site.
- Signed auto-update research.
- Mac App Store Lite research.
- Policy templates for common small-business findings.
- Team workflow for assignment, acceptance, and retest.

## Contributing

Safe contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and the pull request template before proposing changes.

Contributions that add offensive modules, credential testing, arbitrary shell command execution, unauthorized login, or automatic configuration changes are out of scope.

If LANPilot Audit helps your network governance workflow, please consider starring the project.
