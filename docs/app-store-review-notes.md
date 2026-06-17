# App Store Review Notes

LANPilot Audit is an authorized network governance audit assistant for macOS.

- The app does not provide arbitrary shell input.
- The app does not provide user-defined commands.
- The app does not provide vulnerability exploitation.
- The app does not perform brute-force or default-password testing.
- The app does not perform unauthorized login.
- The app does not modify network configuration.
- The app does not provide lateral-movement capability.
- The app only invokes thirteen fixed, local, allowlisted scripts from the user's
  `~/lanpilot-audit`.
- The user selects one locally enumerated IPv4 interface. The backend validates
  that interface before passing it as the fixed `LANPILOT_INTERFACE` value.
- The user must complete all authorization confirmations and explicitly click
  **Run Full Audit** before any real audit begins.
- Execution stops immediately when a step fails.
- ZIP export is implemented inside the app and does not invoke a shell.

The generated findings are point-in-time observations intended to help an
authorized operator document network governance posture and remediation work.
