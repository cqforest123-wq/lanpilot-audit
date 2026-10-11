# Open Source Security Scan Report

- Current tree blockers: 0
- Current tree review items: 4
- Git history matches: 31
- External tools: gitleaks: not installed; trufflehog: not installed

## Current Tree

- REVIEW: docs/release/gatekeeper-check.md (Developer ID personal identity)
- REVIEW: src-tauri/src/lib.rs (MAC address)
- REVIEW: src-tauri/src/quick_check/neighbours.rs (MAC address)
- REVIEW: src-tauri/src/quick_check/oui.rs (MAC address)

## Git History

- ccb0077b508c7f365b8a38f19801c63a47796ef7:tests/run-tests.sh:51: matched blocking history marker
- ccb0077b508c7f365b8a38f19801c63a47796ef7:tests/run-tests.sh:52: matched blocking history marker
- f62141215646b14dd795fa58792296f1bd0126a9:tests/run-tests.sh:51: matched blocking history marker
- f62141215646b14dd795fa58792296f1bd0126a9:tests/run-tests.sh:52: matched blocking history marker
- 2e7a0151b6a7a5c54417d95a20cb0e04ec7a1b41:tests/run-tests.sh:51: matched blocking history marker
- 2e7a0151b6a7a5c54417d95a20cb0e04ec7a1b41:tests/run-tests.sh:52: matched blocking history marker
- f540ef04b7c6b2711e852122cda358fda1b1d585:tests/run-tests.sh:39: matched blocking history marker
- f540ef04b7c6b2711e852122cda358fda1b1d585:tests/run-tests.sh:40: matched blocking history marker
- 77132ba1cc3b3a7a7e16c81d3aa19f2e03b92be9:tests/run-tests.sh:39: matched blocking history marker
- 77132ba1cc3b3a7a7e16c81d3aa19f2e03b92be9:tests/run-tests.sh:40: matched blocking history marker
- 3140a86fe98a05246134e13f13e1cb1f3f4018d3:tests/run-tests.sh:39: matched blocking history marker
- 3140a86fe98a05246134e13f13e1cb1f3f4018d3:tests/run-tests.sh:40: matched blocking history marker
- 8e73303f39071220779ab75ad85838e308278844:tests/run-tests.sh:39: matched blocking history marker
- 8e73303f39071220779ab75ad85838e308278844:tests/run-tests.sh:40: matched blocking history marker
- af85ca5b9709403ac0351bb95344e609651db706:tests/run-tests.sh:39: matched blocking history marker
- af85ca5b9709403ac0351bb95344e609651db706:tests/run-tests.sh:40: matched blocking history marker
- 07c743d600917d22bffb9a7008d6dc38d8e095f1:tests/run-tests.sh:39: matched blocking history marker
- 07c743d600917d22bffb9a7008d6dc38d8e095f1:tests/run-tests.sh:40: matched blocking history marker
- c0406f8781d76ed83e31d3ad1ca50502354b9f10:tests/run-tests.sh:39: matched blocking history marker
- c0406f8781d76ed83e31d3ad1ca50502354b9f10:tests/run-tests.sh:40: matched blocking history marker
- 1a4a073903f621d0d9a88549506352906c1823d1:01-init-lab.sh:117: matched blocking history marker
- 1a4a073903f621d0d9a88549506352906c1823d1:01-init-lab.sh:121: matched blocking history marker
- 77664acfc9a63641d451d700bf7deffc8fe2d597:01-init-lab.sh:116: matched blocking history marker
- 77664acfc9a63641d451d700bf7deffc8fe2d597:01-init-lab.sh:119: matched blocking history marker
- 77664acfc9a63641d451d700bf7deffc8fe2d597:lib/common.sh:6: matched blocking history marker
- 33e606e00b1fa3de0b3321d0c47cbf1b24e37494:01-init-lab.sh:115: matched blocking history marker
- 33e606e00b1fa3de0b3321d0c47cbf1b24e37494:01-init-lab.sh:118: matched blocking history marker
- 33e606e00b1fa3de0b3321d0c47cbf1b24e37494:lib/common.sh:6: matched blocking history marker
- 4b4e1b690a173e6a8048ad70ac61bf5847341dba:01-init-lab.sh:115: matched blocking history marker
- 4b4e1b690a173e6a8048ad70ac61bf5847341dba:01-init-lab.sh:118: matched blocking history marker
- 4b4e1b690a173e6a8048ad70ac61bf5847341dba:lib/common.sh:6: matched blocking history marker

## External Secret Scanners

- gitleaks: not installed; npm scan fallback used
- trufflehog: not installed; npm scan fallback used

## Notes

- Current scan excludes the physical .git directory and generated binary build output.
- History scan covers blocking markers and high-confidence secret patterns; review-only public distribution markers are reported in the current tree only.
- Secret values are never printed in this report.
- Repository secret variable names are allowed only when they do not include secret values.
