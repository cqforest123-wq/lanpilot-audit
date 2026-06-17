# App Review Notes

## Remediation Assistant

The Remediation Assistant creates local governance records and manual guidance from observed findings. It does not automatically apply changes, access service credentials, or bypass the existing authorization confirmation. All generated data remains local unless the user explicitly exports it.

LANPilot Audit is an authorized network-governance assistant for small-business
LANs. A reviewer can inspect reports and the interface without starting a real
audit. A real audit requires explicit authorization and executes only a fixed,
allowlisted sequence of local engine steps.

The app has no arbitrary command input. It performs no credential testing,
unauthorized login, configuration changes, or lateral movement. Evidence stays
on the Mac unless the user explicitly creates a local ZIP export.

Version 1.5.0 adds the Remediation Assistant's structured local guidance,
tracking, fixed-file export, and authorized retest entry point while preserving
the existing read-only governance and authorization boundaries.

The current direct-distribution build depends on separately installed `nmap`.
See `sandbox-risk-notes.md` for the App Sandbox implications.
