# Developer safety rails

The delivery control surface starts long before CI:

```
workstation → commit → push → PR → CI → merge → deploy
```

Securing only CI misses four earlier, cheaper chances to stop a mistake. This directory covers them.

| Directory | Purpose |
|---|---|
| `gitignore/` | Baseline ignore rules for secret, state, and artifact classes. Templates stay trackable via negations. |
| `hooks/` | `pre-commit` config — early feedback on the developer's machine |
| `pr-templates/` | PR body requiring evidence, risk, rollback, and independence disclosure |
| `codeowners/` | CODEOWNERS example — routes review and documents the consequential surface |
| `branch-protection/` | Profiles for solo / small-team / critical-service, plus applier JSON |

## Two rules

**1. Defaults are safe; organizations extend, never remove.** The baseline denylist covers common
secret and state classes. A local repo adds to it. Entries are not deleted because something is
"probably fine."

**2. Hooks are feedback; CI is enforcement.** Hooks are bypassable with `--no-verify` and are not
evidence of anything. Treating a green hook as a satisfied control recreates `configured ≠ enforced`
at the developer's desk.

## Setup

```bash
cp developer-safety/gitignore/baseline.gitignore .gitignore     # or append
cp developer-safety/hooks/.pre-commit-config.yaml .
cp developer-safety/pr-templates/PULL_REQUEST_TEMPLATE.md .github/

pip install pre-commit detect-secrets
detect-secrets scan > .secrets.baseline
pre-commit install && pre-commit install --hook-type pre-push
pre-commit run --all-files      # expect noise on first run; triage, don't blanket-ignore
```

Then pick a branch-protection profile — see `branch-protection/PROFILES.md`. **The invariant is the
same at every team size; only the mechanism for achieving independence changes.**
