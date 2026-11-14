# 10a · Design: discovery, resolve, scanners, report and the gate

```
Kept:      2026-11-07, against the trunk at c1420ea. Components: 03a_COMPONENTS_GATE.md.
Code:      .github/workflows/reusable-security.yml and its composites; scripts/scan_report.py,
           scripts/policy_registration.py, scripts/rung_ladder.py, scripts/enforcement_axes.py,
           scripts/capability_floor.py, scripts/known_exploited.py, scripts/run_record.py.
Deeper:    PIPELINE_ORDERING_AND_SCAN_VALIDITY.md, ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md,
           RUNG_DERIVATION_TABLE.md, SCANNER_SUBJECT_MODEL.md, POLICY.md.
```

## 1 · Purpose

Answer one question per commit, honestly: **may this change proceed?** One job decides (the gate). Every
scanner reports what it found and whether it could look; none decides on its own.

## 2 · Inputs and outputs

| Kind | What | Notes |
|---|---|---|
| input | the consumer's commit | checked out after the kit scripts are written and digested |
| input | workflow inputs (28): `language`, `paths`, `iac_mode`, `image_ref`, `fail_on_severity`, `advisory_mode`, `soft_fail_sast`, the five `weakening_*` fields, `environment`, `target_environment`, `test_only_seed_artifact`, and the toolchain versions | the defaults ARE the baseline (KDEC-008); changing one is a weakening |
| input | `SEMGREP_APP_TOKEN` (optional secret) | managed Semgrep rules |
| input | the policy register, central (at the kit pin) and repository (on the protected default branch) | never the PR's tree |
| input | the CISA KEV catalog; the Trivy DB; OSV data | the organisation mirror first when configured (KDEC-032) |
| output | `routing_result`, `advisory_causes`, `controls_*`, `weakening_*`, `deploy_approval`, `max_exception_renewals`, `security_record`, `run_record` and 30 more (47 in all) | read by the template's `verdict` job and every deploy |
| output | artifacts `security-report-ATTEMPT` (with `findings.json`), `kit-security-record-ATTEMPT`, `sarif-*-ATTEMPT`, `sbom` | 06 section 4 for retention |

## 3 · How it works, in order

1. **Plan** (one job, three parts): write and digest the kit scripts before checkout; **survey** what is in
   scope and **probe** the platform; **resolve** which carried scanner can read each target and at which
   version (KDEC-010), and plan the CodeQL legs.
2. **Scan**: each scanner job runs only where the plan says it applies. Each writes SARIF, redacts it,
   keeps it as an artifact, publishes it where code scanning is available, and reports `findings_state`.
3. **Report**: collect every SARIF; build per-scanner state; render the five sections and `findings.json`.
   A scanner that did not look is NOT ESTABLISHED, never zero.
4. **Floor**: every identity in the protected capability floor has a state file, or the floor is BREACHED.
5. **Policy**: resolve the rung, the per-control minimums, the tier and the team pattern from the register.
6. **KEV**: check every CVE found against the catalog.
7. **Enforce**: compute every control's route; take the precedence maximum; secrets, known-exploited and
   known-malicious block in every mode.
8. **Record**: control posture, leak-gate posture, the run record (schema-validated), reviewer signals.
9. **Say it plainly**, then exit on the verdict.

## 4 · States, in plain words

From `docs/errors/errors.json` (the full catalogue is `docs/errors/ERRORS.md`).

| State (`routing_result`) | In plain words |
|---|---|
| `PROCEED` | The scan passed; nothing to act on. (Not a failure, so it has no catalogue entry.) |
| `PROCEED_WITH_ADVISORY` | The security scan passed with notes: it found things worth knowing that do not stop this change. |
| `DECISION_REQUIRED` | A person has to make a decision before this can deploy: a control was weakened without a recorded reason and owner, or an exception has expired. |
| `EVIDENCE_UNTRUSTED` | The security scan could not finish properly, so its result cannot be trusted either way. |
| `BLOCKED` | The security scan stopped this change: a check found something that must be fixed first (for example a committed secret or a known-exploited vulnerability). |

| Other state | In plain words |
|---|---|
| `advisory_cause.VERSION_GAP` | No scanner the kit carries can read the language or framework version this code targets, so part of the code was not checked. |
| `advisory_cause.COVERAGE_PARTIAL` | A scanner checked most of the code but could not read some files. |
| `advisory_cause.KEV_UNAVAILABLE` | The list of known-exploited vulnerabilities could not be read on this run, so that check did not happen. |
| `advisory_cause.WEAKENING_NOT_APPROVED` | A control is weakened, but the record approving it is missing a field (reason, owner, approver, reference or expiry). |
| `scanner_state.COLLECTION_FAILED` | A scanner ran, but its results could not be collected (the report was empty or unreadable). |
| `scanner_state.UNAVAILABLE` | A scanner never ran on this run. |
| `discovery_state.COVERAGE_GAP` | Code is present that needs a check, and no scanner looked at it. |
| `capability_floor_state.BREACHED` | A scanner that every run must include produced no result, or was removed without a recorded decision. |
| `known_exploited.FINDING_KNOWN_EXPLOITED` | A dependency or image contains a vulnerability that attackers are actively exploiting (it is on the CISA KEV list). |
| `publication_state.PUBLICATION_DEGRADED` | A place results are shown (such as the Security tab) was not available, so results were not published there. |

## 5 · Failure modes, and what the design does about each

| Failure | What happens | Proof |
|---|---|---|
| the kit-scripts part fails | every scanner that needs the scripts is skipped; the gate reads the part's result and reports UNDETERMINED, never NOT_APPLICABLE | `tests/prove_bootstrap_failure.py`, `tests/prove_plan_job.py` |
| a scanner cannot fetch its tool | `DEPENDENCY_ACQUISITION_UNAVAILABLE`; never clean | `tests/prove_hollow_scan.py` |
| a scanner crashes or writes malformed SARIF | one UNPARSEABLE row; other scanners unaffected | `tests/prove_malformed_sarif_isolated.py` |
| a scanner's job fails on findings | it does not: scanners report, the gate decides | `tests/prove_scanners_survive_enforce.py` |
| the register cannot be read | `REGISTRATION_UNAVAILABLE`, `EVIDENCE_UNTRUSTED`; never the default | `tests/prove_policy_registration.py` |
| the KEV catalog cannot be read | `KEV_UNAVAILABLE`, advisory, never PROCEED | `tests/prove_known_exploited.py` |
| the workflow grows past GitHub's start limit | a self-test check fails first | `tests/check_workflow_size.py` |
| an expression in a script grows past GitHub's limit | every value arrives through `env:` | `tests/check_expression_length.py` |
| a PR edits the registry to drop a scanner | the capability floor still expects it | `tests/prove_capability_floor.py` |

## 6 · Decisions

| Decision | What it settled |
|---|---|
| KDEC-008 | the defaults are the baseline (`soft_fail_sast: false`, and the rest) |
| KDEC-010 | capability selects the scanner; PARTIAL only when no configured scanner can read it |
| KDEC-011 | end-to-end secret seeds arrive through a test-only, add-files-only input |
| KDEC-014 | a version gap is advisory at dev/test; uat and prod need an attributed exception |
| KDEC-017, KDEC-018, KDEC-020 | crawl is the floor; the top authority's rung binds everyone; unmapped orgs run at the enterprise floor; the malicious-package scan is in the crawl floor |
| KDEC-022 | known-exploited blocks at every rung; exception history from git |
| KDEC-025, KDEC-026 | every coverage gap closed cost-beneficially; mobile, C/C++ and .NET solutions scanned |
| KDEC-031 | leak gates recorded on every run |
| KDEC-033 | the cost redesign: one plan job, dynamic CodeQL, the registry under a protected capability floor, skipped is never green |
| KDEC-036 | what a reviewer could not see is recorded (weakening authority, verdict provenance, watermark) |

Decisions are in `.context/products/secure-cicd-kit/decisions.md` (the kit's decision register).
