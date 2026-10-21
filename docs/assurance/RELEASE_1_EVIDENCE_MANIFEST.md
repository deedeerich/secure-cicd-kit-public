# Release 1 evidence manifest, part 1 of 3

```
Phase:              1
Parts:              this file: truth state, legend, 1A scan and gate (rows 1-30), 1B NVD, policy,
                    provenance, composites (rows 31-40).
                    `RELEASE_1_EVIDENCE_MANIFEST_PART2.md`: 1C identity, build, deploy (rows 41-64),
                    1D ticketing (rows 65-68), the row counts for all 68 rows.
                    `RELEASE_1_EVIDENCE_MANIFEST_PART3.md`: the consumer interface and its gaps, what
                    the trunk has added since main, where the next proof is owed.
                    Each part is under 20 KB and stands alone.
Truth State:        tied to `main` = ef4b15d (Release 1, PR #3, merged 2026-10-16; self-test run
                    38926152571 on ef4b15d: success, VERIFIED by `gh run view`). Trunk deltas were
                    marked against fix/normalization-and-discovery at 3830edb, and brought to the
                    trunk at 078ef90 on 2026-10-21 (lane L-G2: proofs run there, no new run ids).
Audience:           a consumer deciding what to rely on; the owner; whoever closes the next lane
Decision Supported: which capability is proven, how, at what scope -- and which outputs a consumer
                    can read, and which it cannot
Authority:          tests/reconcile_validation.py (machine-checked) and the workflows at the SHAs
                    above. Where this file and they disagree, they win and this file is wrong.
Written:            2026-10-16, lane L-G. Every run id below was read back with `gh run view`
                    (conclusion, head SHA, workflow) unless the row says READ.
```

## How to read a row

| state | means |
|---|---|
| **PROVEN-LIVE** | exercised against a real external system (Azure, a cloud registry, a real tracker); run id or transcript cited |
| **PROVEN-HOSTED** | exercised on a GitHub runner as a consumer calls it; run id cited |
| **PROVEN-LOCAL** | the shipped step or script run with the real tool on seeded input; the proof is named |
| **PROVEN-STUB** | proven against a stubbed external API (a fake `az`, a replayed tracker) |
| **DESIGNED** | specified, not delivered (unbuilt, or built and not doing what the design says) |
| **DEFERRED** | a dated, owned deferral in `tests/reconcile_validation.py` (or a dated weakening) |
| **BLOCKED** | waits on a named owner decision (`COMPLETION_LEDGER.md` section 6) |

These are column values of this document, not taxonomy terms, so they are written with hyphens:
capitals joined by underscores are reserved for terms registered in `assurance-taxonomy.yaml`
(`scripts/reconcile_taxonomy.py` enforces it).

**A job that ran is not proof its control was effective.** The "asserted" column says what the run
or proof actually established; nothing beyond it is claimed. A run whose conclusion is `failure` is
cited where the failure WAS the assertion (a refusal, a blocked caller) — the column says so.

Labels: **VERIFIED** (code or run read for this file), **READ** (a registry comment or document says
so and was not re-derived), **INFERRED** (reasoned).

## 1 · Capabilities

### 1A · Scan and gate (`reusable-security.yml`)

| # | capability | state | evidence | asserted | scope / limit | label |
|---|---|---|---|---|---|---|
| 1 | Scan → report → gate end to end, as a consumer calls it | PROVEN-HOSTED | **on main `ef4b15d`**: `consumer-path-test.yml` run 38934329462 (success), negative 38934348351 (failure, as designed); self-test 38926152571. Earlier on trunk `13f1518`: 38811950471, 38811969419, self-test 38811959160 | 20/20 seeded signals detected, each by the scanner pinned for it; negative control clean; the seeded findings blocked the caller | main `ef4b15d`; not yet on the trunk (`078ef90` adds KDEC-014 gate bytes, `--strict`, the depth bound) | VERIFIED runs (conclusion, SHA), READ assertions (coordinator relay; registry for 38811950471) |
| 2 | Discovery (presence, could-not-look ≠ absent, coverage gaps) | PROVEN-HOSTED | run 38811950471; `tests/test_discovery.py` | multi-language roots discovered, including second Go roots | as row 1. Trunk `11db350`: beyond the 8-level bound a language is UNDETERMINED and runs, never NOT_APPLICABLE (`prove_discovery_depth.py`, local) | VERIFIED run, READ |
| 3 | Secret detection (gitleaks, detect-secrets, kit rules for cloud credential classes) | PROVEN-HOSTED | run 38811950471 (three Azure/Entra secret classes, via the test-only seed input, KDEC-011) | each seeded class detected by gitleaks | detect-secrets' report row stays NOT ESTABLISHED (ledger L14) | READ |
| 4 | Secrets block in every mode, including advisory | PROVEN-LOCAL | `tests/prove_secrets_always_block.py`, `tests/prove_secret_denominator.py` | the shipped Enforce step exits non-zero on a finding with `advisory_mode` on; an empty scope is COLLECTION_FAILED | the gate's `secret_fail` is inferred from job conclusions (fail-safe), not a typed output | VERIFIED |
| 5 | SAST detection: Semgrep, Bandit, Java (Semgrep), gosec, .NET (NuGet audit + Semgrep C#), C/C++ (cppcheck, flawfinder) | PROVEN-HOSTED | run 38811950471 | a seeded flaw per language detected by its scanner | per-signal breakdown in the run, not re-read here | READ |
| 6 | SAST count/enforce paths never read no-evidence as zero | PROVEN-LOCAL | `prove_bandit_enforces`, `prove_gosec_modules`, `prove_cppcheck_collects`, `prove_nuget_audit`, `prove_sast_java_detects`, `prove_sast_dotnet_detects`, `prove_sarif_effective_level`, `prove_semgrep_rulesets` | absent/unparseable/empty → COLLECTION_FAILED; Semgrep/Checkov counted by effective SARIF level | trunk: the report and runner agree on a hollow scan (L01, `fa19c02`, `prove_hollow_scan`); every `semgrep scan` runs `--strict`, exit 3 → COLLECTION_FAILED (`1542c05`, `prove_semgrep_strict`; measured on 1.178.0, the 1.90.0 container owes a hosted run) | VERIFIED names, READ content |
| 7 | CodeQL (six language legs, per-language rows) | PROVEN-HOSTED | Level 2 consumer (a separate private consumer repository), runs 38817782084, 38820564939 (failure: seeded flaws) | 5 Python + 4 JavaScript results under the expected SARIF categories; the gate's rows read them (APPLICABLE/COMPLETE/RETAINED); four absent languages NOT_APPLICABLE; publication refused, analysis ran | `resolve` still caps CodeQL on the platform pre-flight (D-10). Trunk `1542c05`: an autobuild that did not succeed reads PARTIAL in the summary, not the verdict (`prove_codeql_build_outcome`) | VERIFIED run, READ assertions |
| 8 | Dependency scan (Trivy fs) threshold separate from evidence | PROVEN-LOCAL | `prove_trivy_threshold.py`; tool probe `scanners/trivy` | every severity kept in SARIF; blocks only at `fail_on_severity` | — | READ |
| 9 | IaC scan (Checkov, Trivy config) | PROVEN-HOSTED | run 38811950471 (Terraform and Dockerfile seeds) | seeded misconfigurations detected | every IaC root is a VERSION_GAP by construction until D-VF-4 corpora exist (ledger V-02) | READ |
| 10 | Known-malicious packages block in every mode | PROVEN-LOCAL | `prove_malicious_deps_enforces.py` (real osv-scanner) | a MAL- advisory fails in advisory mode too | malware published only under a GHSA id is not seen | READ |
| 11 | SBOM (Syft CycloneDX) and licence denial reaching the gate | PROVEN-LOCAL | `prove_sbom_licence_verdict.py`; tool probe `scanners/syft` | a denied licence reaches the gate | — | READ |
| 12 | Image scan: CVEs (advisory softens) and baked-in secrets (every mode) | PROVEN-LOCAL | `prove_image_scan_enforces`, `prove_image_scan_retains`, `prove_image_secret_row` | real Trivy on built images; a credential fails in every mode; both SARIFs retained | no hosted run with `image_ref` | READ |
| 13 | Code quality (ruff, mypy, ESLint) | PROVEN-LOCAL | `prove_code_quality_enforces.py` | seeded violations fail with `enforce_lint` on, report with it off | — | READ |
| 14 | Version discovery, capability selection, substitution, PARTIAL-never-PASS (KDEC-010) | PROVEN-LOCAL | `test_resolve.py`, `prove_capability_selection.py`, `prove_gate_routing.py` | a scanner unable to read the target's version never yields PASS; a substitute is labelled | no hosted run with a seeded VERSION_GAP or SUBSTITUTION | VERIFIED names |
| 15 | Gate verdict `routing_result` (five values, precedence) | PROVEN-LOCAL | `prove_gate_routing.py` (21 scenarios at 078ef90), `prove_gate_reads_findings`, `prove_bootstrap_failure` | each scenario routes as specified; bootstrap/discovery/report failure never green | hosted: only the BLOCKED path (row 1). No rung ladder (Release 2) | VERIFIED |
| 16 | `advisory_causes` output and the KDEC-014 deploy rule | PROVEN-STUB | `prove_version_gap_production.py` (fails 110 ways on 53d2962) | causes emitted; at uat/prod a proven VERSION_GAP refused without a named, dated acceptance; UNVERIFIED gap proceeds, recorded; causeless advisory refused. Trunk `078ef90`: exactly one `version_gap_ruling` on every verdict path (`VERSION_GAP_NOT_ENGAGED` new); an empty ruling routes the deploy EVIDENCE_UNTRUSTED | **trunk only (1c20a0b, 078ef90) — not on main.** No live run | VERIFIED (commit), READ (proof content) |
| 17 | Control-posture record (`weakenings`, attribution, controls_*) | PROVEN-LOCAL | `check_weakening_record.py` (shape, every reusable RECORDED except `verify-azure-oidc.yml`, exempt to 2026-10-31); `prove_gate_routing.py` (values) | every input classified; unattributed/expired → DECISION_REQUIRED | values on a real run: only as row 1 | VERIFIED |
| 18 | Redaction before every publication | PROVEN-LOCAL | `prove_redaction_chain.py`, `check_redaction_parity.py` | every upload preceded by a redaction step | — | READ |
| 19 | Evidence validity before upload | PROVEN-LOCAL | `prove_validity_before_upload.py` | 14 count sites check validity rows 1–6 before upload | sidecar rows 8–10 not built (L03) | READ |
| 20 | Kit-scripts bootstrap integrity | PROVEN-HOSTED | run 38811950471; `prove_kit_script_digests.py`, `prove_bootstrap_failure.py` (local) | scripts delivered as a run artifact with a pinned digest manifest; a bootstrap failure blocks in every mode (local) | — | READ |
| 21 | Report: 25 scanner rows, findings counts, `findings.json` | PROVEN-LOCAL | `prove_report_runs_as_shipped`, `prove_report_emits_findings`, `prove_report_counts_findings`, `prove_evidence_artifact_named` | the reporter runs from the kit via `$/`; one identity record per finding; the named artifact is the uploaded one | hosted: the report ran in row 1 | VERIFIED names |
| 22 | Durable identity, anchored correlation, matching cascade | PROVEN-LOCAL | `prove_identity_durability`, `prove_subject_covers_roster`, `prove_anchored_correlation`, `prove_baseline_cascade`, `prove_report_wires_identity` | identity survives moves and upgrades; refuse, never degrade | `prove_identity_durability` runs in no workflow (G-03); the gate does not read the cascade | READ |
| 23 | Baseline ledger read from the protected branch only | PROVEN-LOCAL | `prove_ledger_read_authority.py` | a PR's own ledger edits are never read | — | READ |
| 24 | Establishing a baseline ledger through `reusable-propose-ledger.yml` | PROVEN-LOCAL (trunk) | trunk `a636f5e` (F-01): input `establish-approver-role`; `prove_propose_ledger_establishment.py` runs the reusable's shipped steps against a throwaway remote | no ledger and no role refuses with the reason as outputs `status`/`why`; a role without CODEOWNERS over the ledger path refuses; with CODEOWNERS an ESTABLISH pull request opens, naming the role, asserting no age | **on main `ef4b15d` it cannot establish** (no role input). No hosted run; no template caller | VERIFIED (proof run at 078ef90) |
| 25 | Ledger proposal against an existing ledger | PROVEN-LOCAL | `prove_propose_ledger.py`, `prove_propose_ledger_job_scope.py` | refuses PR events and non-default refs; never re-dates `first_seen` | no hosted proposal. Trunk: one move record as a lineage event (`b036f5c`); unreconciled scanner generations held (`417c6ae`, `prove_propose_ledger_generation`); ticket ledger in the same PR (`c1c3dae`) | READ |
| 26 | Dispositions on the durable key (legacy window to 2026-11-13) | PROVEN-LOCAL | `prove_disposition_schema_and_key.py` | approved, unexpired, exact match only | — | READ |
| 27 | Run record `assurance-result.json` (`schemas/assurance-result.schema.json`) | DESIGNED | schema present; emitted nowhere (ledger L36) | — | — | VERIFIED |
| 28 | Rung ladder, policy registration, tier floors in the gate | DESIGNED | libraries proven locally (`prove_rung_ladder`, `prove_policy_registration`, `prove_enforcement_axes`); `wiring/gate-rung.patch.md` unapplied; `prove_gate_reads_rung` fails | — | Release 2 | READ |
| 29 | Severity, fix availability, SLA in the gate and ledger | BLOCKED | O-06 (numbers and weights); library `prove_remediation_sla` | — | Release 2 | READ |
| 30 | Execution plan enforcement | BLOCKED | EP-1..EP-4 (O-21); the plan is an advisory `resolve` output nothing enforces | — | — | READ |

### 1B · NVD, policy, provenance, composites

| # | capability | state | evidence | asserted | scope / limit | label |
|---|---|---|---|---|---|---|
| 31 | NVD Trivy and Dockerfile paths | PROVEN-LOCAL | `prove_nvd_trivy_detects.py`, `prove_nvd_dockerfile_detects.py` | seeded CVEs reach the SARIF and the armed gate fails; clean passes; Dockerfile skip is explicit | — | READ |
| 32 | NVD Dependency-Check detection | PROVEN-LOCAL | tool probe `scanners/depcheck`; `prove_nvd_workflow_honest.py` | detection on a seeded fixture | **currency against the live NVD feed unproven** (no keyed run); `fail_on_cvss` 11 never blocks (BLOCKED, O-12) | READ |
| 33 | Workflow policy gate (R1–R9) | PROVEN-HOSTED | self-test dogfood, e.g. run 38926152571 on ef4b15d | the gate runs against the kit's own workflows and records its posture | dogfood runs `require_sha_pinning: false`, `soft_fail: true` (attributed, expires 2026-10-31); no seeded fixture per rule (L83) | VERIFIED run, READ scope |
| 34 | SHA pinning of the kit's own third-party actions | DEFERRED | dated weakening in `self-test.yml` (expires 2026-10-31); `scripts/pin-actions.sh` | — | ~1 of ~171 remote `uses:` pinned by SHA (ledger L82) | READ |
| 35 | `setup-python` / `setup-node` version selection | PROVEN-HOSTED | self-test toolchain probes (registry `toolchain-*-version`) | the requested version is the one on PATH | — | READ |
| 36 | `setup-python` / `setup-node` installs | PROVEN-LOCAL | `prove_setup_python_installs.py`, `prove_setup_node_installs.py` | installs from a lockfile/requirements and reports what it installed; a drifted lockfile fails | — | READ |
| 37 | `render-version-metadata` stamp; wiring from build outputs | PROVEN-HOSTED (render) / PROVEN-LOCAL (wiring) | self-test provenance probe; `prove_build_push_round_trip.py`, `prove_stamp_consistency.py` | an unproven identity reaches the stamp as IDENTITY_UNVERIFIED, never PROVEN | called by the template only | READ |
| 38 | `setup-terraform` | DEFERRED | `toolchain-terraform`, expires 2026-12-31 (IMPLEMENTATION_HELD) | — | no consumer until the Terraform assurance model exists | VERIFIED |
| 39 | `determine-changes` | DEFERRED | `change-detection`, expires 2026-12-31 (IMPLEMENTATION_HELD) | — | produces SOURCE_DELTA, whose consumer is unbuilt | VERIFIED |
| 40 | Export safety (neutral core names no organisation, estate or person) | PROVEN-LOCAL | `check_export_safety.py` + `scripts/export-deny.txt` | the tree passes the deny list | trunk: the hyphenated overlay slug is denied (`3500e23`, L106); every pattern carries samples it must match (`b352729`, `prove_deny_samples`); the check reads never-lift patterns as the export gate does (`c82b34f`); an export with no deny list refuses (`bc98cc5`) | VERIFIED (checks run at 078ef90) |

Continued in `RELEASE_1_EVIDENCE_MANIFEST_PART2.md` (1C identity, build, deploy; 1D ticketing; the
row counts) and `RELEASE_1_EVIDENCE_MANIFEST_PART3.md` (the consumer interface and its gaps; what
the trunk has added since main; where the next proof is owed).
