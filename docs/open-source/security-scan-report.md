# Open Source Security Scan Report

- Current tree blockers: 0
- Current tree review items: 2
- Git history matches: 2
- External tools: gitleaks: not installed; trufflehog: not installed

## Current Tree

- REVIEW: docs/release/gatekeeper-check.md (Developer ID personal identity)
- REVIEW: src-tauri/src/lib.rs (MAC address)

## Git History

- 886bec88bd0898f0580ca2488f093b680dbd7bea:docs/release/gatekeeper-check.md:37: matched public-readiness marker
- 886bec88bd0898f0580ca2488f093b680dbd7bea:docs/release/gatekeeper-check.md:68: matched public-readiness marker

## External Secret Scanners

- gitleaks: not installed; npm scan fallback used
- trufflehog: not installed; npm scan fallback used

## Notes

- Current scan excludes the physical .git directory and generated binary build output.
- Secret values are never printed in this report.
- Repository secret variable names are allowed only when they do not include secret values.
