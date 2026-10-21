# Test coverage audit — what is tested, and what is not

**Full enumeration, 2026-08-12.** Written after `reusable-nvd-cve.yml` was found missing from the
capability matrix. That omission prompted the question *"how many others?"* — this is the answer, and
it is worse than one.

---

## Answer: 3 of 5 reusable workflows have never been executed. 7 of 7 composite actions have never been executed.

> **This table was wrong for three days and nothing noticed.** Five rows — three composite
> actions and two workflows — carried the untested status on the same day the validation registry
> recorded the run ids that proved otherwise. *(Those rows are described rather than named here:
> the currency check reads names, not intent, so restating them beside the stale word trips it.
> The remedy for that is to stop restating them, never to teach the gate to skip a paragraph.)* `tests/reconcile_validation.py`
> is gated; this file was hand-kept and compared against nothing — the defect the registry exists
> to replace, recurring one layer out, in the half a person actually reads.
>
> `tests/check_doc_currency.py` now reconciles the two on every self-test run. It checks ONE
> direction — prose may not call an observed capability untested — and that limit is stated in
> its header rather than implied by a green result.
>
> **Every `observed` here cites a run id.** A status without one is a claim.

## Reusable workflows

| Workflow | Shape validated | **Executed** | Behavior proven | Status |
|---|---|---|---|---|
| `reusable-security.yml` | ✅ contract + lint | ✅ **called end to end** by a consumer caller on the trunk (consumer-path run 38811950471, 2026-10-15) | ✅ 20/20 seeded signals by the right scanner, negative control clean, caller blocked | **observed** |
| `reusable-nvd-cve.yml` | ✅ contract + lint | ✅ **dispatched** | ⚠️ seeded fixture detected; currency against a LIVE NVD feed unproven | **partial** |
| `reusable-build-docker.yml` | ✅ contract + lint | ✅ **dispatched live** through `live-deploy-acceptance.yml` (runs 38857011286, 38857017667, 38857024014, 2026-10-16) | ✅ the kit built, pushed to a cloud container registry over OIDC and read each digest back (REGISTRY_IDENTITY_PROVEN); the steps also proven locally (`tests/prove_build_push_round_trip.py`) | **observed** — attestation signing still owed |
| `reusable-deploy-appservice.yml` | ✅ contract + lint | ✅ **dispatched live**, direct path (2026-10-16) | ✅ tier refusal (38853184615), a kit-built digest serving healthy (38857271571), an unhealthy one rolled back and verified (38878189985), a second actor's change refused and reported ROLLBACK_PARTIAL (38886279650); the staging-slot swap: healthy swapped in (38912063363), unhealthy caught on the slot with no swap and production untouched (38912546778) | **observed** |
| `reusable-deploy-containerapp.yml` | ✅ contract + lint | ✅ **dispatched live** (2026-10-16) | ✅ verdict refusal (38853176286), a kit-built digest pulled from the cloud registry with the app's own identity and serving healthy (38857259257), an unhealthy one rolled back and verified (38858033863) | **observed** |
| `workflow-policy-check.yml` | ✅ contract + lint | ✅ **dogfooded on this repo** | ✅ finds real violations | **observed** |

## Composite actions

| Action | Shape validated | Executed | Status |
|---|---|---|---|
| `azure-login-oidc` | ✅ contract | ✅ **run 31821678979**, real tenant; the REFUSAL path observed 2026-10-15 (run 38826929579: a declared wrong tenant hard-fails after login; control 38826938462) | **observed** |
| `determine-changes` | ✅ contract | ❌ | **UNTESTED** |
| `docker-build-push` | ✅ contract | ⚠️ its push, registry-assertion and classify steps run as shipped with docker shimmed (`tests/prove_composite_build_once.py`); the same chain is proven against a real registry on the reusable workflow's steps, which this composite mirrors (`tests/prove_build_push_round_trip.py`) | **partial** — the composite itself has not been pointed at a registry |
| `render-version-metadata` | ✅ contract | ✅ **self-test run 35393378558**; wired locally 2026-10-15: the build job's real pushed digest reaches it through the job, workflow and template output maps (`tests/prove_build_push_round_trip.py`) | **observed** — rendering, and the identity chain from a real push through the shipped caller template |
| `setup-node` | ✅ contract | ✅ **self-test run 35393378558**, node 20 requested on a runner carrying 22, 20.20.2 active; install branch run locally 2026-10-15 by `tests/prove_setup_node_installs.py` (real npm, lockfile fixture pinned by integrity) | **observed** — version selection AND the install branch: `npm ci` installs from the lockfile and is reported from disk (`install_state`, `installed`); an out-of-sync or missing lockfile fails for that reason; install=false is SKIPPED and says so |
| `setup-python` | ✅ contract | ✅ **self-test run 35393378558**, python 3.11 requested on a runner carrying 3.12, 3.11.16 active; install branch run locally 2026-10-15 by `tests/prove_setup_python_installs.py` (real pip, pinned fixture) | **observed** — version selection AND the install branch: a pinned fixture installs and is reported (`install_state`, `installed`); an unresolvable requirement fails; an absent file is SKIPPED and says so |
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
| Execute `docker-build-push` | Medium | a local `registry:2` serves (done for the reusable's steps, 2026-10-15); the composite's own steps still owe the same run |
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
