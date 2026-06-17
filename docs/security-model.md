# Security Model

## Remediation Assistant

The Remediation Assistant writes structured guidance only to fixed files under the latest local audit workspace. It cannot accept an output path or command, apply a configuration change, log in to a service, or start a retest without the existing authorization flow. See [remediation-assistant.md](remediation-assistant.md).

- Real audit execution requires a fresh, one-time authorization token.
- The backend accepts only fixed audit step enum values.
- The engine path is fixed under Application Support; development fallback is
  fixed and cannot be supplied by the user.
- All thirteen engine scripts are allowlisted and symbolic links are rejected.
- Governance observations use fixed commands, fixed paths, and bounded durations.
- Snapshot comparison and remediation tracking operate only on local files.
- Bundled and installed engine files must match the deterministic SHA-256
  integrity manifest before installation or audit execution.
- Integrity manifests reject absolute paths, parent-directory traversal,
  duplicate paths, missing files, modified files, symbolic links, and
  unlisted extra files.
- Script environments are cleared before execution.
- User-entered project, site, and note fields never enter command arguments or
  script environments.
- External app runtime commands are limited to allowlisted scripts and the
  fixed macOS folder-opening action.
- The app does not modify firewall, routing, DNS, VLAN, or Wi-Fi settings.
- The app does not upload audit data.
