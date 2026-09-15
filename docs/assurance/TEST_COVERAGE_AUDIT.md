# Test coverage audit — what is tested, and what is not

**Full enumeration, 2026-08-12.** Written after `reusable-nvd-cve.yml` was found missing from the
capability matrix. That omission prompted the question *"how many others?"* — this is the answer, and
it is worse than one.

---

## Answer: 3 of 5 reusable workflows have never been executed. 7 of 7 composite actions have never been executed.

## Reusable workflows

| Workflow | Shape validated | **Executed** | Behavior proven | Status |
|---|---|---|---|---|
| `reusable-security.yml` | ✅ contract + lint | ⚠️ **jobs probed individually, workflow never called** | scanner-by-scanner | **partial** |
| `reusable-nvd-cve.yml` | ✅ contract + lint | ❌ **never** | ❌ | **UNTESTED** *(probe added today)* |
| `reusable-build-docker.yml` | ✅ contract + lint | ❌ **never** | ❌ | **UNTESTED** |
| `reusable-deploy-appservice.yml` | ✅ contract + lint | ❌ **never** | ❌ | **UNTESTED** |
| `reusable-deploy-containerapp.yml` | ✅ contract + lint | ❌ **never** | ❌ | **UNTESTED** |
| `workflow-policy-check.yml` | ✅ contract + lint | ✅ **dogfooded on this repo** | ✅ finds real violations | **observed** |

## Composite actions — none are executed by any test

| Action | Shape validated | Executed | Status |
|---|---|---|---|
| `azure-login-oidc` | ✅ contract | ❌ | **UNTESTED** |
| `determine-changes` | ✅ contract | ❌ | **UNTESTED** |
| `docker-build-push` | ✅ contract | ❌ | **UNTESTED** |
| `render-version-metadata` | ✅ contract | ❌ | **UNTESTED** |
| `setup-node` | ✅ contract | ❌ | **UNTESTED** |
| `setup-python` | ✅ contract | ❌ | **UNTESTED** |
| `setup-terraform` | ✅ contract | ❌ | **UNTESTED** |

`self-test.yml` validates that each action **declares** `name`, `description`, `runs.using: composite`
and documented inputs. **It never runs one.**

## What the two test workflows actually cover

| | `self-test.yml` | `validate-scanners.yml` |
|---|---|---|
| Covers | YAML lint · actionlint · contract shape · profile schema · policy dogfood | Individual scanner tools against a seeded fixture |
| **Does not cover** | any execution | any **workflow**, any **composite action**, any **deploy path**, any **image build** |

**`validate-scanners.yml` tests the tools, not the kit.** It runs `bandit`, `semgrep`, `trivy` and so
on directly — it never invokes `reusable-security.yml` itself. So the wiring *inside* the reusable
workflow — inputs threading correctly, `if:` conditions selecting the right language paths, SARIF
category collisions, the gate reading job results correctly — is **entirely unproven**. A probe
proving `bandit` works says nothing about whether the workflow's `bandit` job works.

## The pattern behind all three misses

Same shape, three times, each in the thing doing the measuring:

1. **The gate** enforced 4 of 6 jobs while docs said all six were required.
2. **The harness** suppressed its own errors, so failures were undiagnosable.
3. **The matrix** omitted an entire workflow, converting an unknown into an invisible.

Now a fourth: **the test suite tests tools and reports as though it tests the kit.**

**The reporting artifacts have been consistently less trustworthy than the things they report on.**
That is the finding worth carrying out of this repo.

## Honest status

```
Reusable workflows      1 of 6 executed        (workflow-policy-check, via dogfood)
Composite actions       0 of 7 executed
Scanner tools           6 of 11 observed, 4 unknown, 1 untested
Assurance mechanisms    2 of 2 observed
```

**Nothing that deploys, builds an image, or authenticates to Azure has ever run.** Those are the
highest-consequence paths in the kit and the least tested — and unlike the scanners, a defect there
fails at deploy time, in someone else's repo.

## What closing this actually requires

| Gap | Cost | Blocker |
|---|---|---|
| Call `reusable-security.yml` end-to-end against the fixture | Low | none — **do this next** |
| Call `reusable-nvd-cve.yml` end-to-end | Low | no `NVD_API_KEY` in this repo |
| Execute the 4 setup/util composite actions | Low | none |
| Execute `docker-build-push` | Medium | needs a registry, or local-only build |
| Execute `azure-login-oidc` | High | **needs a real Azure tenant + federated credential** |
| Execute both deploy workflows | High | **needs real Azure targets** |

The last three cannot be proven in this repo without cloud resources. Those should be marked
**UNPROVABLE-HERE** with the reason, not left to look like ordinary pending work — an unprovable gap
and an unfinished one need different decisions.

## Rule going forward

> **A capability is listed in the matrix the moment it exists in the kit — with status `UNTESTED` —
> not when someone remembers to add a probe for it.**

Absence from the matrix must never be how a capability avoids scrutiny.

## Owed tests — identified 2026-08-18

| Test | Proves | Why the obvious version is insufficient |
|---|---|---|
| **Path collision fixture** | Two component roots each containing the same filename, scanned together, still yield **two distinct identities** after normalization | Asserting that re-rooting produces the expected *string* tests the implementation. The failure mode is two files collapsing into one identity — test **that** |
| **IaC tool pinning** | `iac:checkov` and `iac:trivy` each independently produced evidence | Currently unpinned, so one scanner covering for a dead one passes. This is how the Trivy path defect survived |
| **Timeout termination** | A deliberately hung scanner is killed, reports `UNAVAILABLE` / `EXECUTION_TIMEOUT`, and **siblings retain independent states** | Use a tiny bound or a mocked sleeper. Do not spend six hours proving a six-hour limit |
| **Discovery failure semantics** | A failed discovery yields `DISCOVERY_UNAVAILABLE` / `PARTIAL`, **never** a tidy set of `NOT_APPLICABLE`s | Once discovery gates every scanner it becomes the highest-leverage place in the kit for a silent lie |
| **Failure isolation in consolidated jobs** | One scanner `FAILED` does not contaminate siblings, **and** one scanner reporting `FINDINGS` does not either | Failure contagion and finding contagion are the same bug wearing different hats |
