# Code walkthrough: developer-safety/

```
Kept:      generated 2026-11-07 against the trunk; the file list is mechanical (git ls-files), the
           descriptions were written by reading each file. tests/check_code_walkthrough_coverage.py
           fails when a tracked file has no row here, or a row names a file that is gone.
Columns:   "called by" = files that run, import, inline or `uses:` it; "proved by" = tests that name it.
           Both are computed by text search, so they can over-count a mention as a use.
```

[Back to the walkthrough index](README.md)

14 files.

| file | what it does | called by | inputs and outputs | proved by |
|---|---|---|---|---|
| `developer-safety/README.md` | What the developer safety rails are, and how to install each one. | - | - | - |
| `developer-safety/branch-protection/PROFILES.md` | The branch-protection profiles (solo, small team, critical service) and the invariant every profile keeps. | - | - | `tests/check_branch_protection_profiles.py` |
| `developer-safety/branch-protection/apply-push-ruleset.sh` | Applies the kit's push ruleset (blocks secret-file paths server-side) to one repository through the API. | - | - | `tests/prove_push_ruleset_secret_files.py` |
| `developer-safety/branch-protection/critical-service.json` | The branch-protection settings for a critical service: the security, policy and NVD checks required, two reviewers, code-owner review. | - | keys: `required_status_checks`, `enforce_admins`, `required_pull_request_reviews`, `restrictions`, `required_linear_history` +4 | - |
| `developer-safety/branch-protection/push-ruleset-secret-files.json` | A push ruleset that refuses pushes of secret-file paths and extensions, letting `.env.example` through. | `.github/workflows/reusable-security.yml`, `assurance-taxonomy.yaml`, `developer-safety/branch-protection/apply-push-ruleset.sh` | keys: `name`, `target`, `enforcement`, `bypass_actors`, `rules` | `tests/prove_leak_gate_posture.py`, `tests/prove_push_ruleset_secret_files.py` |
| `developer-safety/branch-protection/small-team.json` | The branch-protection settings for a small team: the security and policy checks required, one reviewer. | - | keys: `required_status_checks`, `enforce_admins`, `required_pull_request_reviews`, `restrictions`, `required_linear_history` +4 | - |
| `developer-safety/branch-protection/solo.json` | The branch-protection settings for a solo developer: the security and policy checks required, no reviewer count that cannot be met. | - | keys: `required_status_checks`, `enforce_admins`, `required_pull_request_reviews`, `restrictions`, `required_linear_history` +4 | - |
| `developer-safety/codeowners/CODEOWNERS.example` | An example CODEOWNERS file to copy and adapt, with a note for solo teams. | - | - | - |
| `developer-safety/codeowners/CODEOWNERS.zone-readiness` | CODEOWNERS lines that make AppSec the only approver of the zone readiness attestation. | - | - | `tests/prove_reviewer_signals.py` |
| `developer-safety/gitignore/baseline.gitignore` | The baseline `.gitignore`: secret files, keys and local state that must never be committed. | `assurance-taxonomy.yaml`, `developer-safety/gitignore/merge-baseline.sh` | - | `tests/prove_baseline_gitignore.py` |
| `developer-safety/gitignore/merge-baseline.sh` | Merges the baseline `.gitignore` into a repository's own, never replacing it. | - | - | `tests/prove_baseline_gitignore.py` |
| `developer-safety/hooks/.pre-commit-config.yaml` | The baseline pre-commit hooks (gitleaks and friends): early feedback only, since hooks can be bypassed. | `.github/actions/discover/action.yml` | keys: `repos` | `tests/prove_leak_gate_posture.py` |
| `developer-safety/hooks/gitleaks-azure.toml` | Gitleaks rules for Azure and Entra credential classes the default rules miss. | `.github/actions/secret-scan/action.yml`, `.github/workflows/validate-scanners.yml`, `developer-safety/hooks/.pre-commit-config.yaml` | - | `tests/prove_secret_denominator.py`, `tests/prove_test_only_seeds_add_only.py` |
| `developer-safety/pr-templates/PULL_REQUEST_TEMPLATE.md` | A pull-request template asking for purpose, scope, risk and the tests run. | - | - | - |
