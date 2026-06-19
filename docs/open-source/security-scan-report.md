# Open Source Security Scan Report

- Current tree blockers: 0
- Current tree review items: 2
- Git history matches: 0
- External tools: gitleaks: not installed; trufflehog: not installed

## Current Tree

- REVIEW: docs/release/gatekeeper-check.md (Developer ID personal identity)
- REVIEW: src-tauri/src/lib.rs (MAC address)

## Git History

- PASS: no history matches for blocking markers or high-confidence secret patterns.

## External Secret Scanners

- gitleaks: not installed; npm scan fallback used
- trufflehog: not installed; npm scan fallback used

## Notes

- Current scan excludes the physical .git directory and generated binary build output.
- History scan covers blocking markers and high-confidence secret patterns; review-only public distribution markers are reported in the current tree only.
- Secret values are never printed in this report.
- Repository secret variable names are allowed only when they do not include secret values.
