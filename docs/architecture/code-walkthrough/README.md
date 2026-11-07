# 11 · Code walkthrough: every file, in plain words

```
Kept:      2026-11-07, against the trunk. One page per area; one row per tracked file.
Audience:  the owner, learning every drop of code; a reviewer who wants to know what a file is for.
Rule:      tests/check_code_walkthrough_coverage.py fails when a tracked file has no row, a row names a
           file that is gone, a row has no sentence, or a file has two rows. The file list is
           mechanical (git ls-files); the "what it does" sentences were written by reading each file.
```

## How to read a page

Each row has five columns:

| Column | Means |
|---|---|
| file | the path, from the repository root |
| what it does (for a test: what it proves or checks) | one or two plain sentences |
| called by (for a test: run by) | the files that run, import, inline or `uses:` it (for a test, the workflow that runs it) |
| inputs and outputs (for a test: exercises) | workflow and action inputs and outputs, script arguments, or data keys (for a test, the kit files it names) |
| proved by (for a test: inputs) | the tests that name the file (for a test, its own arguments) |

"Called by" and "proved by" are found by text search over the tree, so a file that only *mentions*
another can appear as a caller. When in doubt, the file itself is the authority.

## The pages, in the order to read them

| Page | Area | Start with |
|---|---|---|
| [root-and-config.md](root-and-config.md) | the repository root: README, CODEOWNERS, the registries (`scanner-registry.yaml`, `capability-floor.json`, `assurance-taxonomy.yaml`) and small areas | `scanner-registry.yaml`, `assurance-taxonomy.yaml` |
| [templates.md](templates.md) | the starter templates a consumer copies | `templates/build-deploy.yml` |
| [github-workflows.md](github-workflows.md) | the reusable workflows and the kit-host workflows | `.github/workflows/reusable-security.yml` |
| [github-actions.md](github-actions.md) | the composite actions | `.github/actions/discover/action.yml` |
| [scripts-1.md](scripts-1.md) | scripts, a to k | `scripts/deploy_contract.py`, `scripts/kit_api.py` |
| [scripts-2.md](scripts-2.md) | scripts, l to z | `scripts/scan_report.py`, `scripts/reconcile_tickets.py`, `scripts/policy_registration.py` |
| [api.md](api.md) | the kit API contract, `api/v1/` | `api/v1/request.schema.json` |
| [schemas-profiles-infra.md](schemas-profiles-infra.md) | the JSON schemas, pipeline profiles, feed-mirror Terraform | `schemas/assurance-result.schema.json` |
| [developer-safety.md](developer-safety.md) | branch protection, hooks, gitignore baseline, CODEOWNERS examples | `developer-safety/README.md` |
| [tools.md](tools.md) | the local battery | `tools/battery.py` |
| [tests-checks.md](tests-checks.md) | the static checks and linters the self-test runs | `tests/check_gate.py` |
| [tests-proofs-1.md](tests-proofs-1.md) to [tests-proofs-4.md](tests-proofs-4.md) | every `tests/prove_*.py`, alphabetically | the proof named in the component you are reading |
| [tests-support.md](tests-support.md) | stand-ins, harnesses and corpora (not tests themselves) | `tests/_step_harness.py` |
| [tests-fixtures.md](tests-fixtures.md) | fixtures: deliberately vulnerable or deliberately broken files | `tests/consumer-fixture/README.md` |
| [overlays.md](overlays.md) | where each overlay's own walkthrough lives | - |

## What is not here, and why

- **Documents** (`docs/**`, `.context/**`) are not code. The architecture documents are indexed by
  [../INDEX.md](../INDEX.md), the rest by `docs/START-HERE.md` and each folder's README.
- **Overlay files** and **export profiles** are withheld from the neutral export. Their rows live in a
  `CODE_WALKTHROUGH.md` inside that directory, so the neutral core never names whose they are
  ([overlays.md](overlays.md)).

## How a walkthrough page is kept current

1. A lane adds a file. `tests/check_code_walkthrough_coverage.py` fails (W1) and names the page to add it to.
2. The lane writes one row: the path in backticks, then a sentence saying what the file does.
3. A file is deleted: the check fails (W2) until its row goes.
