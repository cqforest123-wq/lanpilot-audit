# Git History Cleanup Plan

The current branch has been cleaned for public-readiness checks, but git history still contains public-readiness markers such as local build paths or signing-related variable references.

Before changing repository visibility to public, choose one of these paths:

1. Conservative public launch: run `git filter-repo` on a throwaway clone to remove historical local paths and any sensitive records, then force-push after review.
2. Risk acceptance: keep history unchanged only if every historical match is confirmed to be non-secret and acceptable for public disclosure.

Recommended command shape for a separate throwaway clone:

```sh
git clone --mirror <repo-url> lanpilot-audit-app-cleanup.git
cd lanpilot-audit-app-cleanup.git
git filter-repo --replace-text replacements.txt
```

Do not run history rewriting in the working repository without an explicit approval checkpoint.
