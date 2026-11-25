# actionlint baseline: every inherited finding, classified

**Status:** built 2026-11-13 (lane actionlint-pair, KDEC-058). ENFORCED by `tests/check_actionlint.py`, run in the
self-test `actionlint` job; the enforcement itself is proven by `tests/prove_actionlint_baseline.py`.

Verified with actionlint: 1.7.7, 1.7.12

## What this is

`actionlint -no-color .github/workflows/*.yml` reports **102** findings with actionlint 1.7.7 and **100** with the
pinned 1.7.12 (`.github/tool-pins.json`; the Windows build was fetched and its sha256 matched the pin). The same
89 occur on the earlier trunk 644d90d; the other 13 are the deploy-safety lanes' new `$/` calls (rows AL-050 to AL-056, integration 2026-11-13; AL-057, lane deploy-bounds 2026-11-13) and the scanner-obligations composite's (AL-058, KDEC-069, found by the first hosted run on 2026-11-25). Until 2026-11-13 `tests/check_actionlint.py` hid them by
dropping every line that CONTAINED one of two strings. A reviewer asked that they be classified, not
grandfathered. Every finding is now a row below, and the check compares EXACTLY:

| Outcome | When | Result |
|---|---|---|
| UNCLASSIFIED | a finding no row covers, or more occurrences than a row says | FAIL |
| STALE | a row for the running version that occurs fewer times than it says, or not at all | FAIL |
| DEFECT_BASELINED | any class-2 row (a defect is fixed, never baselined) | FAIL |
| ACTIONLINT_VERSION_UNCLASSIFIED | an actionlint version not in "Verified with actionlint" | UNKNOWN (exit 2) |
| NOTE | a row's lines moved but its count holds; a row's workflow is withheld from this tree | printed, not a failure |

The match key is (file, rule kind, exact message, count, versions). Lines are recorded as observed at c33c1f6 and
are only NOTED when they drift, because every edit above a finding moves it.

Not read: shellcheck findings (`-shellcheck=` disables the integration; the raw command above ran without a
shellcheck on PATH, so the 89 contain none). Overlay workflows (`overlays/*/workflows/*.yml`) are read by the check
and report nothing.

## Classes

| Class | Meaning | Rows | Findings (1.7.7 / 1.7.12) |
|---|---|---|---|
| 1 | actionlint does not model a pattern GitHub accepts (parser limitation) | 57 | 101 / 99 |
| 2 | genuine defect | 0 | 0 |
| 3 | style, no runtime effect | 0 | 0 |

No finding is a genuine defect, so nothing was fixed and nothing is handed off. The deploy workflows
(`reusable-deploy-*.yml`, `live-deploy-acceptance.yml`, the deploy-safety lane's files) carry only class-1 rows;
when that lane adds or removes a `$/` call there, the check prints the exact row to change.

## Reasons

**R1. The `$/` self-repository action reference (every version; 100 of the findings on 1.7.12).** Each finding reads
`specifying action "$/.github/actions/NAME" in invalid format because ref is missing`. actionlint parses `$/...`
as a remote `owner/repo` reference without `@ref`. GitHub defines `$/` as the workflow's OWN repository at the
exact commit that is running, with no checkout and no ref: "resolves to your workflow's own repository at the
exact commit that is running", requiring runner 2.336.0 or newer, available on github.com
([GitHub changelog, "Reference same-repository actions with self-repository syntax"](https://github.blog/changelog/2026-07-01-reference-same-repository-actions-with-self-repository-syntax/)).
GitHub Enterprise Server does not offer it (the kit states this as a consumer precondition in
`docs/architecture/04_DEPLOYMENT_VIEW.md`). The kit's own hosted runs resolved it across repositories: consumer-path
run 38811950471 and Level 2 runs 38434823833 and 38468728084 (`docs/assurance/COMPLETION_LEDGER.md` rows S-02 and
L64). Leaving the ref out is the design (the ref is the caller's pinned commit), so adding `@ref` would be the
defect. Class 1.

**R2. More than 10 `workflow_dispatch` inputs (2 findings, actionlint 1.7.7 only).** actionlint 1.7.7 enforces an
old limit of 10. GitHub's workflow syntax reference now reads: "The maximum number of top-level properties for
`inputs` is 25" ([Workflow syntax for GitHub Actions, `on.workflow_dispatch.inputs`](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax)).
`verify-azure-oidc.yml` declares 16 and `live-deploy-acceptance.yml` 18 (its `timeout_minutes`, KREQ-717), both within 25; the pinned 1.7.12 no
longer reports either. Class 1, recorded for 1.7.7 only, so on 1.7.12 the rows are not compared and on 1.7.7 they
must still occur.

## Changing this file

- A new `$/` call (or one removed) changes a row's count: the check names the row and the new count.
- A new kind of finding needs a new row with a class, a reason here and, for class 1 or 3, a citation. A class-2
  finding is fixed instead (test-first), never added.
- A new actionlint pin: run it, classify every finding it reports, and add its version to "Verified with
  actionlint". Until then the check is UNKNOWN on that version.

## Rows

Rows AL-050 to AL-056 were added at integration (2026-11-13) for the deploy-safety lane's new `$/` calls (`deploy-interruption`, `live-target-authorisation`); their "Lines" are at the integration head, not c33c1f6. AL-057 (lane deploy-bounds, 2026-11-13, KDEC-061 M2): the build reusable's time-bound check and registry-push state record; lines at that lane's head.

| Id | Class | Reason | File | Kind | Count | Versions | Lines at c33c1f6 | Message |
|---|---|---|---|---|---|---|---|---|
| AL-001 | 1 | R2 | `.github/workflows/live-deploy-acceptance.yml` | events | 1 | 1.7.7 | 30 | `maximum number of inputs for "workflow_dispatch" event is 10 but 18 inputs are provided. see https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#providing-inputs` |
| AL-002 | 1 | R1 | `.github/workflows/reusable-build-docker.yml` | action | 1 | 1.7.7, 1.7.12 | 402 | `specifying action "$/.github/actions/feed-mirror" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-003 | 1 | R1 | `.github/workflows/reusable-build-docker.yml` | action | 1 | 1.7.7, 1.7.12 | 296 | `specifying action "$/.github/actions/org-settings" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-004 | 1 | R1 | `.github/workflows/reusable-deploy-appservice.yml` | action | 1 | 1.7.7, 1.7.12 | 6606 | `specifying action "$/.github/actions/feed-mirror" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-005 | 1 | R1 | `.github/workflows/reusable-deploy-appservice.yml` | action | 1 | 1.7.7, 1.7.12 | 6627 | `specifying action "$/.github/actions/known-exploited" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-006 | 1 | R1 | `.github/workflows/reusable-deploy-appservice.yml` | action | 1 | 1.7.7, 1.7.12 | 6098 | `specifying action "$/.github/actions/org-settings" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-007 | 1 | R1 | `.github/workflows/reusable-deploy-appservice.yml` | action | 1 | 1.7.7, 1.7.12 | 7440 | `specifying action "$/.github/actions/plain-errors" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-008 | 1 | R1 | `.github/workflows/reusable-deploy-appservice.yml` | action | 3 | 1.7.7, 1.7.12 | 6194, 6673, 7418 | `specifying action "$/.github/actions/reviewer-signals" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-009 | 1 | R1 | `.github/workflows/reusable-deploy-appservice.yml` | action | 7 | 1.7.7, 1.7.12 | 6696, 6738, 6765, 6790, 6815, 6851, 6903 | `specifying action "$/.github/actions/target-lease" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-010 | 1 | R1 | `.github/workflows/reusable-deploy-containerapp.yml` | action | 1 | 1.7.7, 1.7.12 | 6557 | `specifying action "$/.github/actions/feed-mirror" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-011 | 1 | R1 | `.github/workflows/reusable-deploy-containerapp.yml` | action | 1 | 1.7.7, 1.7.12 | 6578 | `specifying action "$/.github/actions/known-exploited" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-012 | 1 | R1 | `.github/workflows/reusable-deploy-containerapp.yml` | action | 1 | 1.7.7, 1.7.12 | 6070 | `specifying action "$/.github/actions/org-settings" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-013 | 1 | R1 | `.github/workflows/reusable-deploy-containerapp.yml` | action | 1 | 1.7.7, 1.7.12 | 7368 | `specifying action "$/.github/actions/plain-errors" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-014 | 1 | R1 | `.github/workflows/reusable-deploy-containerapp.yml` | action | 3 | 1.7.7, 1.7.12 | 6166, 6624, 7346 | `specifying action "$/.github/actions/reviewer-signals" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-015 | 1 | R1 | `.github/workflows/reusable-deploy-containerapp.yml` | action | 7 | 1.7.7, 1.7.12 | 6647, 6690, 6724, 6746, 6771, 6804, 6840 | `specifying action "$/.github/actions/target-lease" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-016 | 1 | R1 | `.github/workflows/reusable-deploy-staticwebapp.yml` | action | 1 | 1.7.7, 1.7.12 | 6954 | `specifying action "$/.github/actions/feed-mirror" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-017 | 1 | R1 | `.github/workflows/reusable-deploy-staticwebapp.yml` | action | 1 | 1.7.7, 1.7.12 | 6975 | `specifying action "$/.github/actions/known-exploited" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-018 | 1 | R1 | `.github/workflows/reusable-deploy-staticwebapp.yml` | action | 1 | 1.7.7, 1.7.12 | 6534 | `specifying action "$/.github/actions/org-settings" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-019 | 1 | R1 | `.github/workflows/reusable-deploy-staticwebapp.yml` | action | 1 | 1.7.7, 1.7.12 | 7708 | `specifying action "$/.github/actions/plain-errors" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-020 | 1 | R1 | `.github/workflows/reusable-deploy-staticwebapp.yml` | action | 3 | 1.7.7, 1.7.12 | 6630, 7021, 7686 | `specifying action "$/.github/actions/reviewer-signals" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-021 | 1 | R1 | `.github/workflows/reusable-deploy-staticwebapp.yml` | action | 7 | 1.7.7, 1.7.12 | 7044, 7079, 7112, 7134, 7157, 7182, 7218 | `specifying action "$/.github/actions/target-lease" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-022 | 1 | R1 | `.github/workflows/reusable-deployed-scan.yml` | action | 3 | 1.7.7, 1.7.12 | 117, 137, 175 | `specifying action "$/.github/actions/deployed-scan" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-023 | 1 | R1 | `.github/workflows/reusable-deployed-scan.yml` | action | 1 | 1.7.7, 1.7.12 | 108 | `specifying action "$/.github/actions/feed-mirror" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-024 | 1 | R1 | `.github/workflows/reusable-deployed-scan.yml` | action | 1 | 1.7.7, 1.7.12 | 128 | `specifying action "$/.github/actions/known-exploited" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-025 | 1 | R1 | `.github/workflows/reusable-feed-mirror-refresh.yml` | action | 2 | 1.7.7, 1.7.12 | 148, 176 | `specifying action "$/.github/actions/feed-mirror-refresh" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-026 | 1 | R1 | `.github/workflows/reusable-kit-api.yml` | action | 7 | 1.7.7, 1.7.12 | 199, 240, 257, 286, 341, 432, 492 | `specifying action "$/.github/actions/kit-api" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-027 | 1 | R1 | `.github/workflows/reusable-kit-api.yml` | action | 4 | 1.7.7, 1.7.12 | 268, 296, 443, 507 | `specifying action "$/.github/actions/plain-errors" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-028 | 1 | R1 | `.github/workflows/reusable-nvd-cve.yml` | action | 3 | 1.7.7, 1.7.12 | 373, 587, 832 | `specifying action "$/.github/actions/feed-mirror" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-029 | 1 | R1 | `.github/workflows/reusable-nvd-cve.yml` | action | 1 | 1.7.7, 1.7.12 | 878 | `specifying action "$/.github/actions/known-exploited" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-030 | 1 | R1 | `.github/workflows/reusable-propose-ledger.yml` | action | 1 | 1.7.7, 1.7.12 | 127 | `specifying action "$/.github/actions/propose-ledger" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-031 | 1 | R1 | `.github/workflows/reusable-security.yml` | action | 1 | 1.7.7, 1.7.12 | 5532 | `specifying action "$/.github/actions/capability-floor" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-032 | 1 | R1 | `.github/workflows/reusable-security.yml` | action | 1 | 1.7.7, 1.7.12 | 3307 | `specifying action "$/.github/actions/deps-scan" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-033 | 1 | R1 | `.github/workflows/reusable-security.yml` | action | 2 | 1.7.7, 1.7.12 | 1967, 1980 | `specifying action "$/.github/actions/discover" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-034 | 1 | R1 | `.github/workflows/reusable-security.yml` | action | 2 | 1.7.7, 1.7.12 | 4129, 4445 | `specifying action "$/.github/actions/feed-mirror" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-035 | 1 | R1 | `.github/workflows/reusable-security.yml` | action | 1 | 1.7.7, 1.7.12 | 3372 | `specifying action "$/.github/actions/iac-scan" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-036 | 1 | R1 | `.github/workflows/reusable-security.yml` | action | 1 | 1.7.7, 1.7.12 | 5572 | `specifying action "$/.github/actions/known-exploited" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-037 | 1 | R1 | `.github/workflows/reusable-security.yml` | action | 1 | 1.7.7, 1.7.12 | 7163 | `specifying action "$/.github/actions/plain-errors" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-038 | 1 | R1 | `.github/workflows/reusable-security.yml` | action | 1 | 1.7.7, 1.7.12 | 2054 | `specifying action "$/.github/actions/resolve" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-039 | 1 | R1 | `.github/workflows/reusable-security.yml` | action | 1 | 1.7.7, 1.7.12 | 5558 | `specifying action "$/.github/actions/resolve-policy" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-040 | 1 | R1 | `.github/workflows/reusable-security.yml` | action | 1 | 1.7.7, 1.7.12 | 7131 | `specifying action "$/.github/actions/reviewer-signals" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-041 | 1 | R1 | `.github/workflows/reusable-security.yml` | action | 1 | 1.7.7, 1.7.12 | 7109 | `specifying action "$/.github/actions/run-record" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-042 | 1 | R1 | `.github/workflows/reusable-security.yml` | action | 1 | 1.7.7, 1.7.12 | 4019 | `specifying action "$/.github/actions/sast-cpp" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-043 | 1 | R1 | `.github/workflows/reusable-security.yml` | action | 1 | 1.7.7, 1.7.12 | 3433 | `specifying action "$/.github/actions/sast-dotnet" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-044 | 1 | R1 | `.github/workflows/reusable-security.yml` | action | 1 | 1.7.7, 1.7.12 | 3486 | `specifying action "$/.github/actions/sast-java" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-045 | 1 | R1 | `.github/workflows/reusable-security.yml` | action | 1 | 1.7.7, 1.7.12 | 3529 | `specifying action "$/.github/actions/sast-mobile" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-046 | 1 | R1 | `.github/workflows/reusable-security.yml` | action | 1 | 1.7.7, 1.7.12 | 5470 | `specifying action "$/.github/actions/scan-report" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-047 | 1 | R1 | `.github/workflows/reusable-security.yml` | action | 1 | 1.7.7, 1.7.12 | 2134 | `specifying action "$/.github/actions/secret-scan" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-048 | 1 | R1 | `.github/workflows/verify-azure-oidc.yml` | action | 1 | 1.7.7, 1.7.12 | 1169 | `specifying action "$/.github/actions/plain-errors" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-049 | 1 | R2 | `.github/workflows/verify-azure-oidc.yml` | events | 1 | 1.7.7 | 55 | `maximum number of inputs for "workflow_dispatch" event is 10 but 16 inputs are provided. see https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#providing-inputs` |
| AL-050 | 1 | R1 | `.github/workflows/reusable-deploy-appservice.yml` | action | 2 | 1.7.7, 1.7.12 | 6725, 7537 | `specifying action "$/.github/actions/deploy-interruption" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-051 | 1 | R1 | `.github/workflows/reusable-deploy-appservice.yml` | action | 1 | 1.7.7, 1.7.12 | 6966 | `specifying action "$/.github/actions/live-target-authorisation" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-052 | 1 | R1 | `.github/workflows/reusable-deploy-containerapp.yml` | action | 2 | 1.7.7, 1.7.12 | 6676, 7465 | `specifying action "$/.github/actions/deploy-interruption" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-053 | 1 | R1 | `.github/workflows/reusable-deploy-containerapp.yml` | action | 1 | 1.7.7, 1.7.12 | 6903 | `specifying action "$/.github/actions/live-target-authorisation" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-054 | 1 | R1 | `.github/workflows/reusable-deploy-staticwebapp.yml` | action | 2 | 1.7.7, 1.7.12 | 7030, 7762 | `specifying action "$/.github/actions/deploy-interruption" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-055 | 1 | R1 | `.github/workflows/reusable-deploy-staticwebapp.yml` | action | 1 | 1.7.7, 1.7.12 | 7238 | `specifying action "$/.github/actions/live-target-authorisation" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-056 | 1 | R1 | `.github/workflows/reusable-deployed-scan.yml` | action | 1 | 1.7.7, 1.7.12 | 81 | `specifying action "$/.github/actions/live-target-authorisation" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-057 | 1 | R1 | `.github/workflows/reusable-build-docker.yml` | action | 2 | 1.7.7, 1.7.12 | 256, 728 | `specifying action "$/.github/actions/deploy-interruption" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
| AL-058 | 1 | R1 | `.github/workflows/reusable-security.yml` | action | 1 | 1.7.7, 1.7.12 | 5562 | `specifying action "$/.github/actions/scanner-obligations" in invalid format because ref is missing. available formats are "{owner}/{repo}@{ref}" or "{owner}/{repo}/{path}@{ref}"` |
