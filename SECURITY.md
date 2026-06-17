# Security Policy

## Supported Versions

Security fixes are accepted for the current minor release and the latest public release tag.

## Responsible Disclosure

Please report vulnerabilities through GitHub Security Advisories. A public security contact can be added before the repository visibility is changed.

Do not submit offensive modules, credential testing features, unauthorized-login flows, arbitrary shell command features, or automatic configuration-change features.

## In Scope

- App security issues.
- Unsafe command execution.
- Path traversal.
- Symlink handling.
- Export leaks.
- Signing and release integrity.
- Authorization bypass in real audit workflows.

## Out Of Scope

- Requests for offensive scanning.
- Unauthorized network use.
- Credential testing or default-password testing requests.
- Automatic device or endpoint configuration changes.
- Findings that depend on using LANPilot Audit outside an authorized environment.

## Safety Boundary

LANPilot Audit is a local-first governance tool. It is not a vulnerability exploitation framework and does not perform credential testing, brute force, unauthorized login, lateral movement, or configuration changes.
