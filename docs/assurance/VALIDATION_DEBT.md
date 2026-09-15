# Validation debt

What has been **verified**, what is merely **authored**, and what is **blocked** — with the blocking
reason and the downstream claims that inherit the uncertainty.

The rule this file enforces: *a blocked node is not a blocked project.* Work that does not genuinely
depend on an unavailable step continues; only claims that depend on it carry the uncertainty. Nothing
unvalidated is ever reported as passing.

## How debt is held — red must mean "act now"

**A permanently red check is not a control. It is training.** People learn that red means "known
backlog", stop reading it, and then a real regression arrives wearing the same colour as the noise.
That failure is worse than having no check, because it also consumes the attention a working check
would have earned.

So `tests/reconcile_validation.py` produces exactly two outcomes:

| Outcome | Meaning | CI |
|---|---|---|
| **BLOCKING** | Something is unaccounted for, or a deferral expired. **Act now.** | ❌ fails |
| **ACCEPTED DEBT** | A deliberate deferral that is dated, owned, and not yet expired. | ✅ passes, reported loudly |

### What keeps a deferral honest

Every capability that is not `observed` **must** have a `DEFERRALS` entry. No entry is BLOCKING —
which preserves the original property that **absence is an error state, not a way to avoid
scrutiny**. Each entry carries four fields, and each one closes a specific way deferrals rot:

| Field | Stops |
|---|---|
| `reason` | "we forgot" |
| `owner` | orphaning at handoff — a **role**, never a person, so the kit stays portable |
| `proves` | a deferral quietly becoming a wish |
| `expires` | "temporary" becoming permanent |

Five more rules do the rest:

1. **Expiry is the mechanism.** An expired deferral goes BLOCKING, forcing a fresh decision.
   *Silence must never renew a deferral.* Re-dating is legitimate; re-dating without looking is not,
   which is why moving the date means rewriting the reason.
2. **Approaching expiry warns** (14 days) so it is never a surprise.
3. **Unregistered artifacts can never be deferred.** A new workflow or action nobody registered is
   drift, and drift is always BLOCKING.
4. **"Needs infrastructure" is a reason to defer, never an exemption.** The
   `requires-integration-environment` capabilities are deferrals with dates like everything else.
   They were previously exempt, which meant they could sit unproven forever without ever appearing
   as debt.
5. **Ratchet.** Accepted debt may shrink, never grow. New debt must displace old debt, or
   `MAX_ACCEPTED_DEBT` must be raised deliberately in a reviewable diff.

### The gate is itself under test

`self-test.yml` runs a **negative control**: it forces every deferral past its expiry and requires a
non-zero exit through the BLOCKING path. If the gate ever returns success with everything expired,
the accepted-debt path has swallowed the blocking path, coverage reporting has become unfalsifiable,
and the negative control fails loudly.

This is the same standard the scanners are held to. A check that cannot be shown to fail is
decoration — and a decoration in the position of a control is worse than an empty position, because
it is trusted.

## Verified — actually executed

| # | Check | How | Result |
|---|---|---|---|
| V1 | All 16 YAML files parse (workflows, actions, templates, profiles) | `yaml.safe_load` locally | ✅ pass |
| V2 | `profiles/profile.schema.json` is valid JSON Schema | `json.load` | ✅ pass |
| V3 | All 3 profiles validate against the schema | `jsonschema.validate` locally | ✅ pass |
| V4 | Reusable-workflow + composite-action contracts well-formed | `self-test.yml` contract script, run locally | ✅ pass — **found 4 real defects** (undescribed inputs in `reusable-build-docker.yml`), since fixed |
| V5 | Policy gate runs and is self-consistent | policy script extracted and run locally against the kit | ✅ pass — **found 3 real defects** in its own rules (R7 self-match, R7 false positive on provenance-stamp steps, R6 false positive on dispatch-gated jobs), since fixed |
| V6 | Policy gate in strict mode reports exactly the known pinning gap | `REQUIRE_SHA=true` locally | ✅ 7 findings, all expected — matches [PINNING.md](PINNING.md) |
| V7 | Consumer templates pass the gate they ship with | gate run against `templates/` | ✅ 0 findings |
| V8 | **All of the above re-run on a real GitHub runner** | `self-test.yml`, run `31427774873`, 2026-08-10 | ✅ **5/5 jobs pass** — YAML lint · actionlint · Contract shape · Profile schema · Policy gate (dogfood) |

V4 and V5 are the point of the self-test harness: it found defects in the kit before any consumer did.

## Unvalidated — authored, never executed in CI

| # | Node | Why unvalidated | What it needs | Claims that depend on it |
|---|---|---|---|---|
| U1 | `reusable-security.yml` scanner invocations | No GitHub runner available in the authoring environment | One pilot repo run | "the scan set works"; Checkov's SARIF output path and the Semgrep flag combination are the two most likely breakages |
| U2 | `reusable-build-docker.yml` | No runner, no registry, no cloud identity | Pilot run with a real ACR | "Trivy gates before push"; "SBOM is produced"; the `docker/build-push-action` digest output contract |
| U3 | `reusable-deploy-containerapp.yml` | No Azure subscription or Container App to target | Pilot deploy | "auto-rollback works"; `az containerapp revision` query shapes are the likely breakage |
| U4 | `reusable-deploy-appservice.yml` | Same, plus no sovereign-partition tenant | Pilot deploy in each partition | "dual-partition parity holds"; slot-swap behaviour |
| U6 | `scripts/pin-actions.sh` | Requires live GitHub API access and a token | One dry run | "tags resolve to SHAs correctly" |

**U5 DISCHARGED (2026-08-10).** `actionlint` and `yamllint` now pass on a real runner — a stronger
check than the local YAML parse, because it validates against the Actions schema rather than just
YAML syntax. Moved to V8.

**None of the remaining rows may be described as passing.** U1–U4 are first-run-shakeout risks, not
design doubts — the patterns are standard, the version-specific details break. Note what `self-test`
does *not* exercise: no scanner is invoked, no image is built, no cloud is touched. A green
self-test proves the kit is well-formed, **not** that the security suite finds anything or that the
deploys work.

## Blocked

| # | Node | Blocking reason | Artifact needed to unblock | Genuinely dependent work |
|---|---|---|---|---|
| B1 | SHA-pinning the 5 third-party actions | Real commit SHAs must be resolved against live upstream repos. They cannot be authored from memory, and a fabricated SHA fails closed while looking like a typo | Run `scripts/pin-actions.sh --apply` with a token | The `v1` tag, and flipping `self-test.yml` to enforcing. **Nothing else.** |
| B2 | Mapping any specific named supply-chain campaign to controls | The name in circulation post-dates what can be verified from here | Read the current advisory | Nothing. [POLICY.md](../architecture/POLICY.md) is written against the durable control class, which is the more useful framing anyway |

Neither blocker gates Phase 1–4 authoring, the USR rebuild, or the Landing Zone rebuild. B1 gates
exactly one thing: the `v1` tag.

## Provider independence

Every control in this kit is a deterministic asset — policy-as-code, a contract checker, a JSON
Schema, a shell resolver, and gate definitions. All of it runs on a GitHub runner with Python and
`curl`, with no model in the loop. An AI assistant can accelerate authoring and interpretation of
these files; none of them requires one to execute, and the evidence path survives any provider
disappearing.

The one thing a model must never do is mark a row in the Unvalidated table as passing without a run
that produced the evidence.

## reusable-nvd-cve.yml (added 2026-08-12)

**Written, YAML-valid, NOT yet executed on a runner.** Do not present as validated.

| Item | State |
|---|---|
| YAML parse + workflow_call shape | ✅ verified locally |
| Trivy SARIF upload | ⚠ unvalidated |
| Dependency-Check SARIF format flag (`--format SARIF`) | ⚠ unvalidated — confirm the 9.0.9 release emits it and confirm the report filename |
| NVD cache key/restore behavior | ⚠ unvalidated |
| Cold-cache runtime | ⚠ unknown; expect 20–40 min without an API key |
| `fail_on_cvss` gating | ⚠ unvalidated |
| Dockerfile config scan | ⚠ unvalidated |

**First validation run should be `workflow_dispatch` on a throwaway repo with a real `NVD_API_KEY`,
not a production repo.**

### Deliberate behavior changes from the original this was abstracted from

- **NVD update failure is no longer silent.** The original used `|| true`; a failed update meant
  scanning against a stale or empty DB while the job stayed green. Now it emits a warning, sets
  `NVD_UPDATE_FAILED`, and the step summary states explicitly that an empty result does not
  establish "no known vulnerabilities."
- **Reporting and gating are separate steps.** The original mixed `continue-on-error` with `|| true`
  so it was not determinable from the file whether anything could fail the build. Now the reporting
  pass runs with `exit-code: 0` and the gate is an explicit, separately configured step.
- **SARIF upload added.** The original emitted JSON/HTML/table only, so findings never reached code
  scanning.
- **NVD data is cached** across runs with a warm restore key. The original re-downloaded.


## Coverage correction (2026-08-12) — gate vs. documentation mismatch

The `security-gate` job enforced only 4 of the 6 jobs that existed: `sast-bandit` and `iac-scan`
ran but **could not fail the gate**. Documentation listed them as required checks. That is
`configured != enforced` inside the kit that defines the phrase.

Fixed: the gate now enumerates **all 12** jobs. A job skipped because its language or toggle is off
counts as acceptable; a failure or cancellation does not. Skipped is printed as skipped in the run
summary rather than folded into "passed", so coverage stays visible instead of silently shrinking.

### Language coverage added

`python | node` only → **`python · node · dotnet · java · go · cpp · multi`**.

| Job | Tools |
|---|---|
| `sast-dotnet` | `dotnet list package --vulnerable --include-transitive` + `--deprecated`, Semgrep `p/csharp` |
| `sast-java` | Semgrep `p/java` + `p/secrets` |
| `sast-go` | `gosec` (SARIF) + `govulncheck` |
| `sast-cpp` | `cppcheck` + `flawfinder` (SARIF) |

### Malicious-package detection added — this is a different question from CVEs

`malicious-deps` runs **OSV-Scanner** and fails on **`MAL-` advisories** (OpenSSF Malicious Packages).

**CVE scanning finds packages that are *vulnerable*. This finds packages that are *compromised*** —
typosquats, hijacked maintainer accounts, backdoored releases. `npm audit` and Trivy will not tell
you that a package you depend on was taken over last week; CVE feeds do not carry that class.

Notably: when OSV produces no output the job **warns and treats the result as UNKNOWN**, not clean.
The success message says so explicitly — absence of a match is not proof of a clean supply chain.

### SBOM added

`sbom` job generates CycloneDX **and** SPDX via Syft, retained 90 days.

### Contract violations fixed

Two inputs on `reusable-nvd-cve.yml` shipped without descriptions and broke the kit's own contract
gate — a workflow added to the kit that violated the kit's own policy. Also fixed: **9 undocumented
secrets** across `reusable-build-docker`, `reusable-deploy-appservice` and
`reusable-deploy-containerapp` that the CI contract check does **not currently catch** because it
validates inputs but not secrets.

**Follow-up:** tighten `contract.py` in `self-test.yml` to validate secret descriptions too. Until
then the local reproduction in this repo is stricter than CI, which is its own small
`configured != enforced`.

### Still not validated

**None of the new jobs has run on a runner.** YAML parses, the contract check passes locally,
yamllint is clean. Highest-risk assumptions: OSV-Scanner release URL and JSON shape, Syft installer,
`flawfinder --sarif` support, and whether `dotnet list package` output matching is reliable across
SDK versions.

---

## Added 2026-08-18

### Execution bounds
All non-mutating jobs now carry `timeout-minutes` (29 bounds), sized from observed healthy durations.
**`reusable-nvd-cve` is the exception and the caveat:** it has **never executed**, so it had no
observed duration to size from. Its own documentation says a cold-cache update takes **20–40 minutes**
without an `NVD_API_KEY`. It carries **60 minutes, derived from documentation, not evidence** —
re-size it from a real run. A bound sized from data that does not exist is a guess wearing evidence's
clothes.

| Item | State |
|---|---|
| Timeout semantics | ⚠ **unvalidated and incomplete.** A timeout currently surfaces as a plain job failure. It should classify as `UNAVAILABLE` / `EXECUTION_TIMEOUT` with the last completed phase recorded |
| Timeout termination behaviour | ⚠ **never exercised.** No test proves a hung scanner is killed, nor that its siblings retain independent states |
| Bounded dependency acquisition | ⚠ **absent.** No connect/read timeouts or retry-with-backoff on tool downloads; the outer job bound is the only protection |
| Mutating-workflow bounds | ⏸ **deliberately absent** pending rollback-contract design — see `ROLLBACK_CONTRACT.md` |

### Scanner path identity
| Item | State |
|---|---|
| gosec repo-relative URIs | ✅ fixed `02b67f6`; re-rooting verified against real SARIF, idempotent |
| **Trivy scope-relative URIs** | ❗ **LIVE DEFECT.** Trivy reports `infra/main.tf` where Checkov and Semgrep report `tests/consumer-fixture/full/infra/main.tf`. One file, two identities, inside one repo |
| IaC signal tool-pinning | ⚠ **absent.** `iac:checkov` and `iac:dockerfile` are not tool-pinned, which is why the Trivy defect survived. Any scanner covering for another passes |
| Collision regression fixture | ⚠ **owed.** Two component roots containing the same filename, scanned together, asserting **two distinct identities survive normalization**. Tests the failure mode rather than the implementation that prevents it |

### Environment-scoped secrets in reusable workflows (2026-08-18)

A reusable-workflow **call** is a job-level substitution: the calling job never touches a runner, so
it cannot declare `environment:` — and `secrets: inherit` does **not** carry environment secrets.
Per GitHub's own documentation, the environment must be declared on a job *inside* the called
workflow, and the environment secret then takes precedence over anything the caller passed.

**Consequence, and it is a contract rule, not a workaround:** any reusable workflow that needs an
environment-scoped secret must expose a `github_environment` input.

| Workflow | Declares secrets | `github_environment` | State |
|---|---|---|---|
| `reusable-build-docker` | Azure | ✅ | correct |
| `reusable-deploy-appservice` | Azure | ✅ | correct |
| `reusable-deploy-containerapp` | Azure | ✅ | correct |
| `reusable-nvd-cve` | `NVD_API_KEY` | ✅ | **fixed 2026-08-18** — the key was provisioned in both environments and structurally unreachable, so the workflow would have silently taken its un-keyed path |
| `reusable-security` | `SEMGREP_APP_TOKEN` (**optional**) | ❌ | ⏸ **Latent, affects nothing today.** **No token is required and none is configured.** Semgrep runs on the public OSS rulesets and is the highest-yield scanner in the contract suite without one — the token only adds Semgrep's managed rules and dashboard. The wiring gap would only bite a consumer who *chooses* to use the optional token *and* stores it as an environment secret. Same class as the NVD defect, but conditional rather than active. Fix alongside the capture-boundary work, which touches those 13 jobs anyway |

### NVD workflow — first evidence, 2026-08-18/19

Three runs. Each one found something the previous could not, because nothing had ever executed.

| Run | Outcome |
|---|---|
| 1 | **Publication killed detection.** An unavailable Security tab failed the SARIF upload, which skipped the NVD update, Dependency-Check and the Dockerfile scan. Fixed |
| 2 | **NVD returned 403/404.** Pinned Dependency-Check `9.0.9` predates NIST retiring the legacy data feeds. The API key was independently verified as working — a valid key against a retired endpoint still 404s. Bumped to `12.1.0` |
| 3 | **Database update SUCCEEDED** (~50 min cold), Dockerfile scan ran despite the Dependency-Check failure (contagion fix held), all publication guards behaved. Dependency-Check exited 14 |

**Established:** the `github_environment` wiring resolves `NVD_API_KEY` · the version bump fixes the
NVD API · publication no longer gates detection · an unrelated scanner is no longer suppressed by a
sibling's failure · a cold database build fits inside the 60-minute bound.

**Open — `ASSURANCE_PREREQUISITE_GAP`, not a scanner defect:**

| Gap | Detail |
|---|---|
| Go analyzer | Needs a working Go toolchain; the job installs none. `Error parsing output from 'go list -json -m all'` → **exit 14, fatal**. Either provide the toolchain, disable that analyzer explicitly, or report `PARTIAL` — but **never silently** |
| Node analyzer | Wants `node_modules`; warns only. Dependency claims for Node are therefore **not established** by this workflow |
| Fatal escalation | One analyzer's prerequisite failure kills the whole scan **after** the expensive database build. Analyzer-level failure should degrade coverage, not discard a completed database pass |
| Self-scan scope | Fixed: the kit was scanning `tests/consumer-fixture/`, which is deliberately vulnerable and malformed. A detection fixture is **input to the test suite, never a subject of the kit's own posture** |
| Cache/timeout interaction | Run 3 completed, so the feared cold-start deadlock did **not** materialise. Watch it: a cold build that exceeded the bound could never populate the cache that would let it finish |

### Toolchain acquisition — what is proven and what is not (2026-08-21)

**Presence is not fitness, and an install that "succeeded" is not a tool that runs.** Three separate
claims, historically conflated:

| Claim | How it is established |
|---|---|
| the tool is **present** | `command -v` |
| the tool is **fit** | version meets the minimum (Java ≥ 11 for Dependency-Check 12.x) |
| the tool **runs** | it actually executes after whichever acquisition path was taken |

| Site | Bounded | Skip-if-present | Usability proved | Proven **in CI** |
|---|---|---|---|---|
| `reusable-nvd-cve` — openjdk, unzip | ✅ | ✅ | ✅ | **skip path only** |
| `reusable-security` — cppcheck, flawfinder | ✅ | ✅ | ✅ | ❌ **not yet** |
| `validate-scanners` probes ×2 | ✅ | ❌ | ❌ | ❌ |

**Unproven and honest about it:**
- The **fitness check itself has never run in CI.** It was added after the successful NVD run, so
  what CI proved was the *older* skip-only logic.
- The **apt fallback has never been exercised** — every successful run took the skip path.
- The **dpkg-lock bound has never fired.** It is the fix for a hang that cost ~386 minutes, and it
  remains theoretically correct rather than demonstrated.
- **flawfinder SARIF capability** is now recorded up front rather than discovered by failure, but the
  CSV fallback path is likewise unexercised.

**How to prove them without waiting for a real outage:** force each branch — a fixture that removes
the tool from PATH, one that presents an old version, and one that holds the dpkg lock. Testing the
failure branch is the only way to know the safety net is attached, and this kit has already learned
that an assertion which has never failed is decoration.

### The class discovery exposed — audited, not assumed (2026-08-21)

Building discovery surfaced two defects **in the discovery job itself**. Treating those as bugs in
one job would have been the mistake; the owner caught that and asked whether the same failures
existed elsewhere. They did.

**Pattern 1 — "found nothing" and "could not look" collapsed into one answer.**
`[ -z "$(find ... | head -1)" ]` reads a *failed* find as *no files present*, skips the job, and
reports green over code nobody scanned. Found in discovery, then in **four more applicability
guards** — Python, .NET, Java and C/C++.

**Pattern 2 — a parse failure reported as zero findings.**
`n=$(jq '...' report.sarif 2>/dev/null || echo 0)` yields `n=0` when the report is missing,
truncated or malformed. The gate reads zero as clean. Found in **13 sites**, including **gitleaks**
— the scanner that is supposed to hard-block unconditionally — and **semgrep**, the highest-yield
detector in the suite.

The taxonomy already contained the word for this, registered days earlier:

> `COLLECTION_FAILED` — *an empty but well-formed result is indistinguishable from a clean scan.*

The vocabulary was right and the code did the opposite in seventeen places. **Registering a term is
not implementing it.**

**Fixed:** every consumer-path site now distinguishes absent, unparseable and empty, and emits
`COLLECTION_FAILED` rather than a zero.

**Still open:** five sites in `validate-scanners` probe internals use `grep -c ... || echo 0` for
probe bookkeeping. Lower blast radius — they measure probe output rather than consumer posture — but
test scaffolding must not be weaker in the exact property it validates. Owed.
