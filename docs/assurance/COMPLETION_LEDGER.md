# Completion ledger: what the kit still lacks to be complete, correct, as designed and tested end to end

```
Phase:              1
Truth State:        audit at commit 53d2962 (trunk fix/normalization-and-discovery, as branched to
                    lane/completion-audit). Every row carries a label: VERIFIED (code or a run read at
                    53d2962), READ (a document or registry comment says so), INFERRED (reasoned, not observed).
Audience:           the owner, and whoever plans the lanes that finish the kit
Decision Supported: what "done" still costs, in what order, which owner decisions block it, and which
                    facts feed the next question (landing-zone deploys vs kit deploys)
Deferred Depth:     per-job YAML; the comparison of deployment methods itself (section 7 lists its inputs only)
Written:            2026-10-16, read-only audit; this document is the only file changed
```

> **The one-paragraph answer.** The kit's Release 1 path is real and mostly proven. Scan and gate run
> end to end on GitHub (20 of 20 seeded signals). CodeQL is proven on a separate consumer repository. Both
> deploy adapters deploy a kit-built digest live, roll it back and refuse to overwrite a second actor.
> Jira ticketing is proven live.
>
> It is **not complete as designed**, for four kinds of reason:
>
> 1. **Wiring.** Proven libraries are not connected to the path that decides anything:
>    - the rung ladder, SLA and severity are not in the gate;
>    - the baseline does not affect blocking;
>    - the execution plan is not enforced;
>    - no consumer template runs the ticketing or ledger jobs;
>    - nothing writes lineage.
> 2. **New owner rules with no build yet.** Neither KDEC-014 (prod refuses a version-gap-only advisory)
>    nor KDEC-015 (the kit releases internal tools too) appears anywhere in the tree.
> 3. **Defects the audit found.** These are real, cheap and test-first:
>    - Jira and Azure DevOps ticket updates erase the human-written description;
>    - no consumer can establish a baseline through the shipped ledger workflow;
>    - the report and the runner disagree about what a hollow scan is;
>    - the template hard-codes `prod` and passes the wrong verdict.
> 4. **Evidence that is real but not current.** The flagship's end-to-end run is on `13f1518`, many
>    commits ago. About 1 of 171 action references is pinned by SHA. A long tail of documents
>    contradicts the validation registry.
>
> None of this is a redesign. Most rows are S or M.

---

## 0 · Method, sources and what was read

- **Base:** `git remote get-url origin` ends `<owner>/secure-cicd-kit.git` (the private source repository); `53d2962` is a commit;
  branch `lane/completion-audit` created from it. `lane/kdec-014` exists and points at `53d2962` with no
  commits of its own (VERIFIED), so every KDEC-014 judgement below is on the base.
- **Gates at base, run by this audit (VERIFIED):** `reconcile_validation` 0 BLOCKING, 3/3 accepted
  (`change-detection`, `toolchain-terraform`, `attestation-verify`, all expiring 2026-12-31).
  `check_doc_currency`, `check_export_safety` and `reconcile_taxonomy` all pass. The flagship is
  453,297 B (LF) / 450.2 KB as GitHub reads it.
- **Five parallel read-only audits** each read their documents in full and checked code at `53d2962`.
  The coordinator read the rest in full and re-verified the load-bearing claims against code: the
  ticket body erasure, ledger establishment, the L01 split, the deploy verdict set, the template tier
  and verdict, the App Service serving read, D-10, pinning counts, the plan not being enforced, and
  `fail_on_cvss`.

| read in full | lines |
|---|---|
| docs/architecture/PIPELINE_ORDERING_AND_SCAN_VALIDITY.md | 1617/1617 |
| docs/architecture/ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md | 1301/1301 |
| docs/architecture/DEPLOYMENT_CONTRACT_RECONCILIATION.md | 1251/1251 |
| docs/architecture/TICKETING_CONTRACT.md | 1492/1492 |
| docs/architecture/SINGLE_PIPELINE_TARGET.md | 1209/1209 |
| docs/architecture/SECURITY_WORKFLOW_DECOMPOSITION_PLAN.md | 1115/1115 |
| docs/architecture/PROVENANCE_AND_ATTESTATION.md | 772/772 |
| docs/architecture/JOB_TOPOLOGY_AND_BUDGET.md | 709/709 |
| docs/architecture/EXECUTION_PLANNING.md | 377/377 |
| docs/architecture/WHY_THESE_KEEP_HAPPENING.md | 366/366 |
| docs/architecture/ROLLBACK_CONTRACT.md | 278/278 |
| docs/architecture/THREAT_MODEL.md | 274/274 |
| docs/architecture/TICKETING_BACKENDS.md | 265/265 |
| docs/architecture/ASSURANCE_MODEL_CANDIDATES.md | 251/251 |
| docs/architecture/CAPABILITY_INVENTORY.md | 197/197 |
| docs/architecture/AXES_AND_PHASES.md | 190/190 |
| docs/architecture/RUNG_DERIVATION_TABLE.md | 164/164 |
| docs/architecture/SCANNER_SUBJECT_MODEL.md, NVD_ABSTRACTION_ACCOUNTING.md | 116/116, 115/115 |
| docs/architecture/LZ_KIT_HANDOFF_CONTRACT.md, PRIOR_CORRELATION_WORK.md, POLICY.md, WORK_ITEM_HIERARCHY.md | 84/84, 79/79, 63/63, 72/72 |
| docs/architecture/generated/PIPELINE_OVERLAYS.md, prototypes/README.md | 211/211, 54/54 |
| docs/assurance/CAPABILITY_MATRIX.md, KNOWN_GAPS.md, TEST_COVERAGE_AUDIT.md, PINNING.md, VALIDATION_DEBT.md | all in full |
| docs/KNOWN_DEFECTS.md, docs/roadmap/FUTURE_WORK.md, docs/PIPELINE_STATE_AND_DIRECTION.md, docs/START-HERE.md, docs/PROOF_RULE.md | all in full |
| docs/explainer/07, 09, 11 | in full |
| wiring/gate-rung.patch.md | 375/375 |
| .context/products/secure-cicd-kit/{current-state, decisions, risks, active-lane, continuation}.md | all in full |
| tests/reconcile_validation.py | 953/953 |
| the prior 110-row ledger (outside the repository, 2026-10-12) | 576/576; every row L01–L110 re-checked below |

**UNREAD:**

- **Prototypes:** `docs/architecture/prototypes/{reusable-security-grouped.yml, build_grouped.py, scan_step_state.sh}`.
  These are frozen prototypes that nothing calls. Their purpose was noted only.
- **The rest of `docs/explainer/` (00–06, 08, 10), `docs/adoption/*` and `docs/operations/*`.**
  `USAGE.md` was searched for advisory mode only.
- **Code read in part, not in full:**
  - the flagship (by region);
  - the deploy reusables' generated inline script copies (they are checked in sync by
    `inline_deploy_scripts.py --check`);
  - `scripts/reconcile_tickets.py` 2441–2809 and 2871–3456;
  - most of `scripts/ticket_model.py`;
  - `scripts/derive_reversal_disposition.py` (body);
  - `tests/_fake_az.py`;
  - most of `reusable-build-docker.yml` and `reusable-nvd-cve.yml`.

  Rows that depend on code that was not read are labelled READ or INFERRED, not VERIFIED.

**State vocabulary used in this document only.** These are column values in this ledger, not taxonomy
terms:

| state | meaning |
|---|---|
| DONE-PROVEN-LIVE | built, and observed on a real runner, tenant or tracker; the run is cited |
| DONE-PROVEN-LOCAL | built, and proven by running the shipped step or script locally, or against a stateful stand-in |
| BUILT-UNPROVEN | built; no proof that exercises it |
| PARTIAL | part of the designed clause is built, or it is built and not on the path that decides |
| NOT BUILT | nothing, or design only; "deferred by design" is noted where a document chose that |
| BLOCKED-ON-OWNER | cannot close without a named decision (section 6) |

"Proven how" cites a proof only if it exists in `tests/`, and a run id only if it appears in the tree.
`reconcile_validation.py` line numbers are given where a run id is cited from it.

---

## 1 · Owner rulings recorded here as owed

Neither ruling below is in `.context/products/secure-cicd-kit/decisions.md` or anywhere else in the tree
(`git grep KDEC-01[345]` returns nothing). VERIFIED.

- **KDEC-014 (relayed 2026-10-16).** A version-gap-only `PROCEED_WITH_ADVISORY` is DEV/TEST ONLY. UAT
  and prod refuse it until the scanner gap is closed, or a named person accepts it as an attributed
  exception. It is being built in a separate lane, which has no commits yet.
  - **Today:**
    - the gate is tier-blind and routes a version-gap-only PARTIAL to `PROCEED_WITH_ADVISORY`
      (`reusable-security.yml:7615-7648`);
    - both deploy reusables admit `PROCEED_WITH_ADVISORY` at every tier
      (`reusable-deploy-containerapp.yml:1934`, `reusable-deploy-appservice.yml:1952`);
    - `tests/prove_deploy_gate.py:59` asserts that admission.

  VERIFIED.
- **KDEC-015 (relayed 2026-10-16).** KDEC-009 covers ALL tools. Internal tools are released by the kit
  into targets the landing zone vends, with per-tool deploy identities.
  - **Owed:**
    - the decision record itself;
    - `LZ_KIT_HANDOFF_CONTRACT.md` gaining "per tool";
    - a statement of which hosting types the kit can release (App Service and Container Apps only,
      VERIFIED).

---

## 2 · The ledger

Columns: **id** · **designed** (doc §) · **built?** (file:line) · **proven how** · **state** ·
**what closes it** · **size** · **label**.

Abbreviations:

| abbreviation | file |
|---|---|
| FW | `.github/workflows/reusable-security.yml` |
| RES | `.github/actions/resolve/action.yml` |
| SR | `scripts/scan_report.py` |
| DC | `scripts/deploy_contract.py` |
| APP / CA | the App Service / Container Apps deploy reusables |
| TPL | `templates/build-deploy.yml` |
| RT | `scripts/reconcile_tickets.py` |
| RV | `tests/reconcile_validation.py` |
| REG | `scanner-registry.yaml` |

**`FW` means two things, and the column says which (clarified 2026-10-22, lane L-FWA).** `FW:line`, anywhere,
is a line of the flagship workflow. `FW §N`, `FW-§N` or `FW Dn` in the **designed** column is section N, or
subsection Dn, of `docs/roadmap/FUTURE_WORK.md`. `tests/check_future_work_traceability.py` reads only the
designed column and fails when a roadmap section is cited by no row; the map is
`docs/assurance/FUTURE_WORK_TRACEABILITY.md`.

### 2A · Stages of the fifteen-stage target (SINGLE_PIPELINE_TARGET §4)

The stage register (`tests/check_stage_phase.py`) is itself stale and is not run in CI. See G-07.

| id | designed | built? | proven how | state | what closes it | size | label |
|---|---|---|---|---|---|---|---|
| S-01 policy resolution | SPT §4 row 1, §8.2–8.3; ETFB §1–4, §10; RUNG §1–8 | **Lane L-A (2026-10-22):** the rung patch is applied, adapted to the owner's multi-scope requirement: `.github/actions/resolve-policy/` resolves the policy register (`schema_version 2`; central copy in the kit, the repository's own file on its protected default branch; precedence kit default < org < team < product < team+product < repository, tier-qualified above) as the gate's first step; `target_environment` input; the posture folds the resolution; a `verdict` step exits on it. No register = the kit default, crawl (B-09 closed; O-03 superseded by the owner's crawl requirement) | `prove_policy_registration`, `prove_gate_reads_rung` (wired), `prove_gate_policy_enforcement` | DONE-PROVEN-LOCAL (gate half; enforcement whole since lane L-S) | ~~crawl findings end their scanner job red~~ closed by lane L-S (2026-10-22): the gate is the single enforcement point -- scanner jobs hand findings over as `findings_state` and fail only when they could not scan (`prove_gate_policy_enforcement` `sep_*`). Still owed: `resolve` consuming the policy for depth/scope (EP-1/S-05); one hosted run | M | VERIFIED |
| S-02 discovery | SPT §4 row 2 | `discover` composite through `$/` (FW:1641) | `test_discovery.py`; consumer-path run 38811950471 (RV:425) | DONE-PROVEN-LIVE | Record the run id in the stage register | S | VERIFIED |
| S-03 version discovery | SPT §4 row 3; PO §2.1–2.3; FW D6 | RES:792–1130: seven classes, per root, with evidence strength | `test_resolve.py` | DONE-PROVEN-LOCAL | Hosted run on a fixture with a declared version above a ceiling | S | VERIFIED |
| S-04 capability selection | SPT §4 row 4; PO §2.4; KDEC-010 | RES:1290–1500; gate caps PASS to PARTIAL (FW:6958–6964); REG has 23 rows, 11 READ and 12 UNVERIFIED | `prove_capability_selection`, `test_resolve`, `prove_gate_routing` | DONE-PROVEN-LOCAL | Hosted run with a seeded SUBSTITUTION and a VERSION_GAP. "Consumption in each scanner job" (KDEC-010 owed) is not built: see V-01 | S | VERIFIED |
| S-05 execution planning | EP §3–§5 | The plan is a `resolve` output marked `advisory: true`, "enforced_by nothing". No `fromJSON(needs.resolve.outputs.plan)` anywhere. Not a `workflow_call` output | `test_resolve.py` (shape and refusals) | BLOCKED-ON-OWNER (EP-1..EP-4) | EP-1, then the scanner `if:` change (EP §5). Also fix its failure shape: an empty `jobs[]` violates refusal 3 | M | VERIFIED |
| S-06 scanning | SPT §4 row 6 | 16 scanner jobs; the report roster has 25 verdicts | Consumer-path 38811950471, 20/20 tool-pinned (RV:425). CodeQL 38817782084 and 38820564939 (RV:230–251) | DONE-PROVEN-LIVE | Re-run on the current trunk (the cited run is on `13f1518`) | S | VERIFIED |
| S-07 evidence validity | SPT §4 row 7; PO §4.4–4.6 | `sarif_validity.py` runs before each of 14 count sites (FW:2246…6040) | `prove_validity_before_upload`; `prove_hollow_scan` (not in any workflow) | PARTIAL | L01 (one profile), L03 (sidecars), L14; wire `prove_hollow_scan` | M | VERIFIED |
| S-08 normalisation and redaction | SPT §4 row 8 | `normalize_sarif.py`; a redact step before every upload | `prove_redaction_chain`, `check_redaction_parity` (both wired) | DONE-PROVEN-LOCAL | — | — | READ |
| S-09 baseline and classification | SPT §4 row 9, §6.1; ETFB §5 | identity, cascade and ledger read are wired in the report (SR:1798–1822). **The gate does not read `identity_routing` or `baseline_state`** (gate `env:` FW:6779–6820) | `prove_baseline_cascade`, `prove_ledger_read_authority`, `prove_report_wires_identity` | PARTIAL | F-01 (establishment), F-03 (the gate acts on NEW vs PRE-EXISTING, through the rung patch) | M | VERIFIED |
| S-10 severity and disposition | SPT §4 row 10; ETFB §6–8 | Dispositions are schema-true on the durable key. The 30-day dual-key window closes **2026-11-13** (SR:1129–1141). Severity and SLA are library only; blocking uses scanner severity (SR:1234–1240) | `prove_disposition_schema_and_key`, `prove_remediation_sla` | PARTIAL | L47 (Release 2) | L | VERIFIED |
| S-11 correlation | SPT §4 row 11; ETFB §9 | `finding_correlation` wired in the report (SR:1824–1835) | `prove_anchored_correlation` | DONE-PROVEN-LOCAL | Cluster confirm and split records (L48) | M | VERIFIED |
| S-12 gate and verdict | SPT §5.2 | `routing_result` plus posture (FW:320–346, 7448–7701). **The gate computes the verdict itself** (security-gate is about 65 KB), the opposite of SPT §5.1's read-and-exit. No rung | `prove_gate_routing`, `prove_gate_reads_findings`, `prove_secrets_always_block`, `prove_bootstrap_failure`; live block in 38811950471 | PARTIAL | S-01; KDEC-014 cause output (K-01); section 5, B-04 | M | VERIFIED |
| S-13 ticket reconciliation | SPT §6.1; TC; TB | `reusable-ticket-reconcile.yml`; reconciler live on Jira. **No consumer template calls the workflow**; self-test calls it only as a PR negative control | Jira live, run by `tests/live_ticketing_run.py` (RV:376–392). Transcripts are outside the repository | PARTIAL | Section 2E | M | VERIFIED |
| S-14 reporting | SPT §4 row 14 | The `report` job plus the `scan-report` composite; findings JSON | Live through consumer-path | PARTIAL | No context label (PR, merge, nightly) reaches `scan_report.py`; the run record (L36) is not emitted | S | VERIFIED |
| FW-§4 presentation tiers (added 2026-10-22, L-FWA) | FW §4 (tiers 1–3 and the engineer's view) | **Nothing built.** No HTML dashboard artifact, no trend projection, no Pages surface: a case-insensitive search for `dashboard` over the workflows and scripts finds only the Semgrep token input's description (FW:357). The report publishes findings JSON and a step summary (S-14, L52) | — | NOT BUILT | Tier 1: one self-contained HTML dashboard as a workflow artifact, built from the findings JSON (scanner status, safe paths, severity and confidence, prerequisite gaps, corroboration, remediation, what was not scanned and why), with redaction proven on the HTML. Tier 2: trend JSON on an orphan branch, labelled a projection, never findings state. Tier 3: Pages off by default and aggregate-only, with a check that refuses paths, rule detail, snippets or raw SARIF. Lane: a new presentation lane after L-W | M | VERIFIED (absence) |
| S-15 deploy and verify | SPT §6.2; DCR; RC | Both adapters; verdict and tier gates; digest-bound; rollback | Live (section 2F) | PARTIAL | Section 2F; a scan → verdict → build → deploy chain in ONE hosted run (live-deploy-acceptance types the verdict in); break-glass and release-object store not built | M | VERIFIED |
| S-§2.4 same-run post-scan phase (L67) | SPT §2.4, §5.1, §5.3 | Pieces exist: report → gate → `reusable-propose-ledger.yml` → `reusable-ticket-reconcile.yml`, each guarded against PR context. No template composes them | none hosted | PARTIAL | Add ledger and ticket jobs to `templates/security.yml` behind `github.event_name != 'pull_request'`; one hosted merge run | M | VERIFIED |
| S-§4.1 unsafe defaults | SPT §4.1 | `soft_fail_sast` now false and `language: auto` (OD-7 done). **`fail_on_cvss` still defaults to 11** (`reusable-nvd-cve.yml:69`), so the NVD workflow never blocks | — | PARTIAL | Rung-derived, or 9.0 (section 6, O-12) | S | VERIFIED |
| S-§7 retirement register (L68) | SPT §7.2–7.5 | none | none | NOT BUILT | A register, a deletion-coupled check and its negative fixture (needed when legacy workflows retire) | M | VERIFIED |

### 2B · Scan validity and version fitness (PIPELINE_ORDERING_AND_SCAN_VALIDITY, SCANNER_SUBJECT_MODEL, NVD accounting)

| id | designed | built? | proven how | state | what closes it | size | label |
|---|---|---|---|---|---|---|---|
| L01 examination axis | KD D-1; PO §4.4; OD-2 | **Split contract.** The runner honours the per-tool profile (`sarif_validity.py:48–62`, `rules_witness=False`). The report's `examination_of` still counts a present-and-empty `rules[]` as hollow (SR:349–355) and reads only `toolExecutionNotifications` (SR:339). A clean bandit run reads EXAMINED_NOTHING in the report | `scan_report` self-test asserts the old behaviour (SR:2012–2015) | PARTIAL | `examination_of` imports `sarif_validity.PROFILES`; flip the self-test case test-first | S | VERIFIED |
| L02 validity before upload | PO §4.5 rows 1–6, §4.6 | 14 count sites | `prove_validity_before_upload` | DONE-PROVEN-LOCAL | A hosted negative (one hollow SARIF) | S | VERIFIED |
| L03 sidecar channels (rows 8–10) | PO §4.4.1, §3.4–3.6 | **Semgrep, built.** `--strict` at every `semgrep scan` (`1542c05`); `--json-output` read for `paths.scanned`, the PHP witness (lane L-PHP); **one Semgrep version** (lane L-SG): the `sast-semgrep` container is the 1.178.0 image pinned by digest (was the 1.90.0 tag), the release the C# and Java jobs and self-test pip-install, and validate-scanners and the corpus probe run the same digest. **Not built:** Checkov `soft_fail: true`, no parse-error fail; Trivy `num=0`, cppcheck `checkersReport` and flawfinder line counts are not read | `prove_semgrep_strict` (P4: the release run locally is the job's), `prove_semgrep_php` (S6), `prove_validate_scanners_matrix` (M2, M7), `prove_php_corpus` (P8, P9); each failed first on `7fe3d54` | PARTIAL | Hosted: self-test, validate-scanners, the corpus probe, a consumer-path run on the 1.178.0 image. Then the Checkov, Trivy, cppcheck and flawfinder channels | M | VERIFIED |
| L04 secret denominator | PO §5.4 | gitleaks enumerates its scope and refuses an empty one; detect-secrets `--all-files` with `ds_count` (FW:2184–2215, 2384–2412) | `prove_secret_denominator` (UNKNOWN where gitleaks is absent); populated path live in 38811950471 | DONE-PROVEN-LOCAL | A hosted empty-scope negative | S | VERIFIED |
| L05 per-job summary zero | `scan_status.sh` | `scan_status.sh:39–60` | `prove_scan_status_zero` | DONE-PROVEN-LOCAL | — | — | VERIFIED |
| L06 malformed SARIF | KD D-5 | SR:397–414, 1718–1729 | `prove_malformed_sarif_isolated` | DONE-PROVEN-LOCAL | KNOWN_DEFECTS D-5 still says NOT FIXED (D-01) | S | VERIFIED |
| L07 redact before publication | SPT §8.3; TM T-11 | CodeQL `upload: never` then redact then upload (FW:3195); other jobs per proof headers | `prove_redaction_chain`, `check_redaction_parity` | DONE-PROVEN-LOCAL | — | — | READ |
| L08 absent, unparseable or empty never reads as zero | VD; PO §4.1 | bandit, gosec, cppcheck, NuGet, OSV now counted | `prove_bandit_enforces`, `prove_gosec_modules`, `prove_cppcheck_collects`, `prove_nuget_audit`, `prove_malicious_deps_enforces` | DONE-PROVEN-LOCAL | — | — | VERIFIED |
| L09 acquisition failure typed | PSD §2.1 | gosec and cppcheck (FW:5087–5092) | flagship: none (`prove_nvd_workflow_honest` covers the NVD path only) | BUILT-UNPROVEN | A local forced-failure proof | S | VERIFIED |
| L10 timeout semantics | FW §10; VD | none; `cancelled` maps to UNAVAILABLE (FW:6955) | none | NOT BUILT | Step-level timeout wrapper giving EXECUTION_TIMEOUT with last phase, plus a mocked-sleeper test | M | VERIFIED |
| L11 bounded acquisition | FW §10 | curl `--retry 3 --connect-timeout 20` for OSV and syft (FW:5887, 6170); apt lock bound. pip and docker pulls are unbounded | none | PARTIAL | Wrappers on the remaining acquisitions | S | VERIFIED |
| L12 image findings retained | KG §1 | FW:6598–6599 | `prove_image_scan_retains`, `prove_image_secret_row` | DONE-PROVEN-LOCAL | KG §1 text is stale (D-01) | S | VERIFIED |
| L13 ESLint on Node-only repositories | KG §2 | built | `prove_code_quality_enforces` | DONE-PROVEN-LOCAL | — | — | READ |
| L14 no-SARIF scanners honest | KG §3 | The detect-secrets row reads `detect-secrets.sarif` (FW:6535), which is never written, so it stays NOT ESTABLISHED although `ds_count` exists. ruff, mypy, eslint, NuGet and sbom are log-only (FW:7245) | — | PARTIAL | Feed `ds_count` to the report; machine output per tool | M | VERIFIED |
| L15 OSV malware | VD | gate FW:6873–6878, 6941–6944 | `prove_malicious_deps_enforces` (real osv-scanner) | DONE-PROVEN-LOCAL | — | — | VERIFIED |
| L16 licence denial reaches the gate | `sbom_licenses` | FW:6946 | `prove_sbom_licence_verdict` | DONE-PROVEN-LOCAL | — | — | VERIFIED |
| L17 threshold separate from evidence | deps-scan | built | `prove_trivy_threshold` | DONE-PROVEN-LOCAL | — | — | READ |
| L18 real-output SARIF corpus | KD "first thing to check" | Proofs run real tools, but no corpus is stored | — | PARTIAL | One real clean and one real hollow SARIF per tool, stored (this would have caught L01) | S-M | VERIFIED |
| L19 version discovery | PO §2.1–2.3 | = S-03 | `test_resolve` | DONE-PROVEN-LOCAL | Hosted | S | VERIFIED |
| L20 per-tool ranges | PO §2.4; FW D6 | REG:89–303; VERSION_UNSUPPORTED becomes a warning plus a gate row (FW:7175–7191) | `test_resolve` | DONE-PROVEN-LOCAL | Hosted | S | VERIFIED |
| L21 / PO §1.3 positions R1–R7 | PO §1.3, §1.6 | `resolve` exists, but **every scanner `needs: [discover, kit-scripts]`, not `resolve`**, so resolve runs in parallel with the scans. The gap is declared independently, not before in time | `test_resolve` | PARTIAL | Either scanners need and consume `resolve` (with EP-1), or record "parallel by design" (section 5, B-07) | M | VERIFIED |
| V-01 KDEC-010 consumption in each scanner job | KDEC-010 "owed" | Not built: a SUBSTITUTION is labelled, but the substitute scanner is not re-routed in the scanner jobs | none | NOT BUILT | Scanner jobs read `selection` for their roots | M | VERIFIED |
| V-02 D-VF-4 seeded corpora | KDEC-010 owed | (Since: checkov and trivy-config READ, lane L-C1; sast-semgrep/php READ 5.6..7.2, lane L-PHP.) Still UNVERIFIED: semgrep ×7 legs, eslint, gosec, cppcheck, checkov, trivy-config. An UNVERIFIED row is never selected (REG:323–328), so every IaC root is a VERSION_GAP by construction | none | NOT BUILT | One seeded-corpus probe per tool above its ceiling, writing a measured READ range (validate-scanners shape) | L | VERIFIED |
| PHP-1 PHP a supported ecosystem (lane L-PHP, owner 2026-10-21) | owner: "I need php and we need it now" | discovery `php`; resolve PHP version sources; `php-sast` = sast-semgrep with a `p/php` floor and a hollow-PHP witness (`paths.scanned` from `--json-output`: the first sidecar channel read, L03); Composer through deps-scan; lock-less `composer.json` a named gap; fixture 24 signals; a PHP-only negative | `test_discovery`, `test_resolve`, `prove_semgrep_php`, `prove_deps_scan_composer` (each failed first on 75d935c) | DONE-PROVEN-LOCAL | Hosted: consumer path (24/24), the scope=php negative, self-test, the corpus probe | M | VERIFIED |
| PHP-2 the shipped Semgrep reads PHP 8.x (KDEC-016; was: only to 7.2) | D-VF-4 (PHP corpus); KDEC-016 | Lane L-SG moved `sast-semgrep` to the Semgrep 1.178.0 image, pinned by digest, and re-measured `version_support` sast-semgrep/php on it: **READ 5.6..8.4** (`tests/corpora/php_corpus.py`, locally in that image, 2026-10-21; the families were `php -l`-checked by lane L-PHP). In the same image, every corpus family under `--strict` with `p/php` is exit 0, and an unparseable file exit 3. validate-scanners' container probe and a new `semgrep-php` probe, and the corpus probe, run the same digest. Before: READ 5.6..7.2 on the 1.90.0 container, 7.3+ syntax exit 3 = COLLECTION_FAILED. **PHP 8.5 is in the corpus and MEASURED unread** (family `php -l`-checked under 8.5.12 and 8.4.27): the `(void)` cast and `final` promoted properties draw PartialParsing on 1.178.0 and on 1.182.0, the newest release (2026-10-21); the pipe operator parses. **PHP 8.5, owner 2026-10-22 (KDEC-016 amended, replacing the per-app exception): scan what parses, flag the rest** (lane L-P85). `sast-semgrep` reads Semgrep's JSON: exit 3 whose errors are ONLY parse errors on `.php` files (`errors[].type` `["PartialParsing", [spans]]`, level `warn`) keeps the run -- findings kept, files and lines named, `scan_state` PARTIAL (`PARSE_PARTIAL_PHP_SYNTAX`); any other error stays COLLECTION_FAILED. The gate reads it as PARTIAL -> PROCEED_WITH_ADVISORY / COVERAGE_PARTIAL. The row's measured `parse_evidence_max` 8.5 makes an 8.5 target SERVED, not a VERSION_GAP (9.0 still a proven gap). The PHP-only negative carries `php/php85.php` and still blocks on its seeds | `prove_php_corpus` (P8, P9; P10 failed first on `5569274`; P11), `prove_validate_scanners_matrix` (M7), each failed first on `7fe3d54`; `prove_semgrep_php` S7-S10, `test_resolve` (PHP 8.5), `prove_version_gap_production` (php85 gate chain, resolve 8.5/9.0), each failed first on `2cd078e` | PARTIAL (8.5, by design: flagged per file) | Hosted: the corpus probe and validate-scanners on the digest, the consumer path (24/24) and the scope=php negative (now with the 8.5 file: Semgrep job FAILED on findings, its scan PARTIAL). PHP 8.5 fully read: a Semgrep release that parses it (none as of 1.182.0) | S | VERIFIED |
| V-03 PO §1.4 toolchain chosen from the target | PO §1.4 | Toolchain versions are still caller inputs; resolve only compares against them (`max_from_input`) | none | NOT BUILT | resolve emits a recommended runner version per class, and setup uses it or refuses a lower input loudly (section 5, B-03) | M | VERIFIED |
| V-04 row 5 vs a declared gap | PO §2.4 ("still runs; silence is not coverage") | A bandit parse-skip trips row 5, the job exits 1 (FW:2991–2995), and the gate maps it to EVIDENCE_UNTRUSTED (FW:6951–6996), even where resolve already declared that root VERSION_UNSUPPORTED | none | PARTIAL | Owner decision O-07, then test-first | S | INFERRED |
| V-05 version inputs as control surfaces | PO §7 | FW:7535–7539 and `reusable-nvd-cve.yml:975` still classify them as NOT_A_CONTROL_SURFACE, while REG:78–79 says `max_from_input` makes them one | none | NOT BUILT | Reclassify; update `check_weakening_record` | S | VERIFIED |
| D-10 CodeQL withdrawn on a platform pre-flight | KD D-10 | RES:1373 still withdraws `codeql` when code scanning is UNAVAILABLE or NOT_CONFIGURED. Run 38817782084 showed the analysis runs anyway | KD D-10 | NOT BUILT | Withdraw from publication only; read `cq_state`; fix the `test_resolve` platform rows | S | VERIFIED |
| L34 CodeQL per-language states | AX; PO §6.3; KG §4 | Report rows per language (FW:6601–6650). The gate still projects `codeql: skipped` to UNAVAILABLE at job level (FW:6936). `cq_build` (FW:3177) is read nowhere | `prove_codeql_rows_read_sarif`; live 38817782084, 38820564939 (RV:230–251) | PARTIAL | The gate reads per-leg state; autobuild failure becomes PARTIAL or COLLECTION_FAILED | S | VERIFIED |
| L35 no idle CodeQL legs | JT §5.2, §9.4 depth 1 | Not built (the gate's own known-gaps row, FW:7246; six legs gated at step level) | none | NOT BUILT | Conditioned legs, or a `fromJSON` matrix from discovery with an empty-list guard (section 5, B-06) | S | VERIFIED |
| L24 class-and-count coverage | PO §5.3 | RES:1508–1577 | `test_resolve` | DONE-PROVEN-LOCAL | Hosted | S | VERIFIED |
| PO §5.5 file-level skip reasons | PO §5.5 | Class level only | none | NOT BUILT | Follows L24 | M | INFERRED |
| PO §4.6 / §8 platform experiments | PO §4.6, §8 | Five experiments not run (error-level notification on upload; CodeQL above its ceiling; cppcheck checkersReport; gosec type-check-only; CodeQL CLI licence on private repositories) | none | NOT BUILT (deferred by design: PO §8) | One hosted experiment each | S | READ |
| PO §4.7 versionControlProvenance | PO §4.7 | none | none | NOT BUILT | A profile field | S | VERIFIED |
| L25 platform probe consumed | PO §6.1–6.4 | RES:1716–1840 emits owner roles, Dependabot alerts (**first page only, ≤100**, RES:1803) and a dataflow COVERAGE_GAP. FW exposes them (1804–1817); **neither the gate nor the report consumes them** | `test_resolve` platform rows | PARTIAL | A Dependabot row; pagination; the gate reads `dataflow_capability` (D-10 contradicts the dataflow answer) | M | VERIFIED |
| L108a subject on registration | SSM | Mapping in `finding_subject.BY_SCANNER`, not a REG field | `prove_subject_covers_roster` | PARTIAL | Move to REG, or cross-check the two | S | VERIFIED |
| L108b parse-ceiling scanners are PARTIAL by construction | SSM | none | none | NOT BUILT | REG `parse_ceiling` field capping at PARTIAL | S | VERIFIED |
| L109 live-target authorisation record | SSM 48–71 | none (the consumer overlay's DAST runs without one) | none | NOT BUILT | Record schema, PREREQUISITE_UNAVAILABLE path, expiry | S-M | VERIFIED |
| L110-1 workflow security lint | SSM gate 1 | `lint_injection` (self-test), the `pull_request_target` rule, `check_caller_permissions` | self-test | PARTIAL | Artifact-poisoning and over-broad-permission checks | S | VERIFIED |
| L84 non-`uses:` installs pinned | FW §11 | OSV, syft (checksummed), bandit, semgrep 1.178.0 pinned. `pip install detect-secrets` (FW:2383) and `ruff mypy` (FW:2652) unpinned. `check_pinned_installs` covers three jobs only | `check_pinned_installs` | PARTIAL | Pin, and widen the checker's scope | S | VERIFIED |
| L23 pin resolution and toolchain currency (FW D7) | FW D7, §11 | `check_pinned_artifacts` is wired (self-test:305) and the v-tag proof exists (unwired). No currency inventory | `prove_pin_check_sees_v_tags_and_action_refs` | PARTIAL | D7 inventory, warn-not-fail, scheduled (R-02 item 1) | M | VERIFIED |
| NVD-§4.1 Dependency-Check disable flags | NVD §4.1 | only `--disableOssIndex` | — | BLOCKED-ON-OWNER (O-13) | A recorded decision | S | VERIFIED |
| NVD-§4.4 non-Dockerfile misconfiguration | NVD §4.4 | `trivy config .`, table only, no SARIF or gate (`reusable-nvd-cve.yml:719`) | — | PARTIAL | SARIF plus gate, or declare it owned by iac-scan | S | VERIFIED |
| NVD-§5 posture in the evidence artifact | NVD §5; KG §6 | Posture is written after the upload (nvd:723) | — | PARTIAL | Write posture before upload | S | VERIFIED |
| NVD-§6 live NVD currency | NVD §6; VD | The registry blocker says unproven; Go and Node analyzer prerequisites unestablished | tool-level only | PARTIAL | A cited keyed run | S | VERIFIED |
| FW-§5 coverage gaps | FW §5; CI A5/A6/B3/B4/C2 | No shellcheck, hadolint, tflint, pip-audit or npm audit; no Swift, Kotlin/Android, build-aware C/C++, shell or workflow scanner; no real .NET consumer | — | BLOCKED-ON-OWNER (O-14, scope) | Classify each as owed, overlay or retired | M | VERIFIED |
| FW-§1 Trivy scope-relative URIs | FW §1; VD | Not established at 53d2962 (not re-traced) | — | UNKNOWN (not re-checked) | Re-trace; collision regression fixture (VD "owed") | S | INFERRED |

### 2C · Gate, enforcement, identity, baseline (ENFORCEMENT_TIERS, RUNG, AXES, POLICY)

| id | designed | built? | proven how | state | what closes it | size | label |
|---|---|---|---|---|---|---|---|
| L26 secrets block in every mode | ETFB §5.7 | The gate sets `secret_fail` from the secret-scan, image-secret and malicious-deps jobs before the advisory branch (FW:6997–7016, 7312–7377). Inferred from job conclusions (fail-safe), not a typed output | `prove_secrets_always_block`, `prove_gate_reads_findings`; live on `13f1518` | DONE-PROVEN-LOCAL | Re-dispatch the consumer path on the current trunk | S | VERIFIED |
| L27 states from evidence | JT §8.1 | `blocking_findings` and `jobs_with_findings` give FINDINGS (FW:6866–6927) | `prove_gate_reads_findings` | DONE-PROVEN-LOCAL | — | — | VERIFIED |
| L28 discovery failure is EVIDENCE_UNTRUSTED | ETFB §3 | FW:7087–7111, 7273–7298 | `prove_bootstrap_failure` (discover_failed) | DONE-PROVEN-LOCAL | — | — | VERIFIED |
| L29 bootstrap failure is never green | DECOMP §6.3 | FW:7063–7079 | `prove_bootstrap_failure`; hosted step 7 never run | DONE-PROVEN-LOCAL | One hosted forced failure (optional) | S | VERIFIED |
| L30 gate emits a verdict | SPT §5.2 | FW:7629–7652; output FW:320–322 | `prove_gate_routing`; deploy refusal live 38853176286 (RV:319) | DONE-PROVEN-LOCAL | Hosted flagship run on the current trunk | S | VERIFIED |
| L31 posture record | ETFB §2.2 | FW:7448–7701; the exemption is closed (`check_weakening_record.py:164`). Stale comment at FW:7565–7567 (OD-7 "undecided") | `prove_gate_routing`, `check_weakening_record` | DONE-PROVEN-LOCAL | Comment fixed (lane L-A: defaults are the baseline, KDEC-008 OD-7) | S | VERIFIED |
| L32 rung ladder | ETFB §1–4; RUNG | = S-01. **Lane L-A (2026-10-22):** the gate obeys the registered rung through the policy register (findings route by the rung's floor and registered minimums). Promotion evidence (ETFB §4.3) is not read: the attributed decision is the authority, `rung_effective` = `rung_declared` | as S-01 | DONE-PROVEN-LOCAL (gate half) | A visible Release-2 register (section 5, B-10); per-finding classes need L44; one hosted run | M | VERIFIED |
| L33 tier and team pattern | AX; ETFB §3, §8.6 | **Lane L-A:** tier and `team_pattern` resolve per register scope; the gate emits `environment_tier`, `team_pattern`, `unvalidated_human_workflow_paths`. No tier floors beyond O-24 (O-04 recommendation kept) | `prove_policy_registration`, `prove_gate_reads_rung` | DONE-PROVEN-LOCAL | Settings derived from `team_pattern` (AX-TEAM); one hosted run | M | VERIFIED |
| ETFB-§3 untrusted evidence by tier | ETFB §3 | **Lane L-A:** the gate job ends on a `verdict` step. Owner ruling O-24 (2026-10-22): EVIDENCE_UNTRUSTED stops the gate at EVERY tier, crawl included (the kit unable to run or trust its scan blocks); a coverage gap stays advisory | `prove_gate_policy_enforcement` | DONE-PROVEN-LOCAL | One hosted run | S | VERIFIED |
| ETFB-§2.2 rung, minimum and divergences emitted | ETFB §2.2 | **Lane L-A:** `rung_declared`, `rung_effective`, `policy_mode`, `effective_minimum`, `policy_divergences`, `policy_resolution`, `policy_source`, `policy_chain` are gate and workflow outputs and in the summary | `prove_gate_reads_rung` (0 failures, wired) | DONE-PROVEN-LOCAL | One hosted run | S | VERIFIED |
| ETFB-§4.3 promotion evidence verified | ETFB §4.3 | The library checks that evidence references exist (`rung_ladder.py:116, 282`); it never verifies them | `prove_rung_ladder` | BUILT-UNPROVEN | A verifier per reference type | M | VERIFIED |
| L36 run record and `evidence_artifact` | `schemas/assurance-result.schema.json` | `evidence_artifact` fixed (FW:7262). **Lane L-A (2026-10-22):** the gate's `record` step (`run-record` composite, `scripts/run_record.py`) builds the record from the gate's own outputs, validates it against the schema and emits it as `assurance_result` (job and workflow output); an invalid record is named and not emitted. An UNAVAILABLE scanner carries `INFRASTRUCTURE_UNKNOWN`; findings are the blocking count only | `prove_evidence_artifact_named`, `prove_gate_run_record` | DONE-PROVEN-LOCAL | Upload `assurance-result.json` as an artifact (a new `uses:` line, after lane L-H's pinning); the schema has no routing_result or policy fields (a schema_version 2 is owed); one hosted run | S-M | VERIFIED |
| L37 history scan | AX depth | `'0'` string form, FW:1900 | no dedicated proof | BUILT-UNPROVEN | A proof | S | READ |
| L38 caller inputs via `env:` | SPT §6.2 | the lint blocks it in every reusable | `lint_injection` | DONE-PROVEN-LOCAL | — | — | VERIFIED |
| L39 re-run reads its own attempt | RSR#13 | `kit-scripts-${run_attempt}` unchanged (FW:1609) | none | BUILT-UNPROVEN | Observe one partial re-run | S | INFERRED |
| L40 durable identity | ETFB §5.1–5.6 | String-aware stripping fixed (`finding_identity.py:428–530`); `symbol_path` optional in WHERE, required for a CWE-only WHAT | `prove_identity_durability` (constructed SARIF; not in self-test) | BLOCKED-ON-OWNER (O-05, `symbol_path`) | Ruling; wire the proof; real corpus (L18) | S | VERIFIED |
| L41 identity reachable at runtime | KDEC-002 | the report runs from the kit through `$/` (FW:6661) | `prove_report_runs_as_shipped` | DONE-PROVEN-LOCAL | Hosted on the current trunk | S | VERIFIED |
| L42 every roster scanner maps | KD D-3 | built | `prove_subject_covers_roster` | DONE-PROVEN-LOCAL | — | — | VERIFIED |
| L43 identity before redaction | KD D-8 | not built; secrets refuse outright (SR:1055–1075). Redacted SAST constructs still refuse CONTENT_UNDERIVABLE in production (KD D-8 standing) | — | NOT BUILT | Build it (carry component hashes in the per-job state), or rule it out of scope with the consequence stated | S-M | INFERRED |
| L44 matching cascade | ETFB §5.3 | `finding_match` wired in the report (SR:1798–1822); outputs FW:6331–6332; **not read by the gate** | `prove_baseline_cascade`, `prove_report_wires_identity` | PARTIAL | Acting half via the rung patch §11 (Release 2) | M | VERIFIED |
| F-01 / L45 ledger | ETFB §5.4 | Reader wired. Writer: `reusable-propose-ledger.yml` plus composite. **Lane L-F:** the reusable now declares `establish-approver-role` (optional, no default) and hands it to the composite, and publishes `status` / `why` as workflow outputs. Establishment is only ever an ESTABLISH pull request, refused unless CODEOWNERS at the default tip covers the ledger path (ETFB §5.4/§10 "under CODEOWNERS"); a role given when a ledger exists is ignored and said so. The guard is the default-branch condition plus CODEOWNERS, not environment reviewers (a conditional `environment:` cannot be expressed on this job). No template ledger job (L-W) | `prove_propose_ledger_establishment` (runs the reusable's shipped steps against a throwaway remote with a `gh` shim; failed first on the missing input and outputs), `prove_propose_ledger`, `prove_propose_ledger_job_scope`, `prove_ledger_read_authority`; no positive hosted proposal | DONE-PROVEN-LOCAL (reusable) | Template job (L-W); one hosted establish-then-propose run on the Level 2 consumer (needs a CODEOWNERS rule over `.security/` there) | S | VERIFIED |
| L46 rule-family upgrade | ETFB §5.5 | `rule_family.resolve` in the report. **Lane L-F:** the write path runs `generation_check` per observed (scanner, version) against the alias table at the default tip: a finding first reported by an unpinned-and-unreconciled generation is HELD (never NEW); the proposal opens ONE `reconciliation_report` per (scanner, from, to) under `.security/reconciliations/` (window from an owner placeholder, 30 days, O-06); an open report is never re-opened; once a reviewed change adds an acceptance (role, date, inside the window, `validate_acceptance`), exactly its listed findings enter as `detection_change`, age not established. A pinned scanner with no version is held as EVIDENCE_UNTRUSTED; no table or an unpinned scanner admits as before. Nothing writes `scanner_generations` in the ledger header, and the gate (read side) still does not consult the generation (L-A) | `prove_propose_ledger_generation` (failed first: the upgrade's finding was admitted NEW, no report), `prove_rule_family_upgrade` | DONE-PROVEN-LOCAL (write path) | The acceptance and pin update are manual reviewed edits (no tool writes them); `disappeared` is not computable per scanner (the ledger has no scanner attribution) and the report says so; gate-side enforcement with the rung patch (L-A); one hosted run with a real version bump | M | VERIFIED |
| L47 severity, fix availability, SLA, breach staging | ETFB §6–8 | `remediation_sla.py` library; ledger fields allowlisted (`baseline_ledger.py:97–100`) but never written; **no data source for fix availability** | `prove_remediation_sla` | BLOCKED-ON-OWNER (O-06, numbers and weights; Release 2) | Write the fields in propose-ledger; the gate reads deadlines; establish fix availability | L | VERIFIED |
| L48 correlation tiers | ETFB §9 | core wired; confirm and split records not built; **the ticket cluster key is computed separately** (`RT:287` vs `finding_correlation.py:72,148`) | `prove_anchored_correlation` | PARTIAL | Event record; one key function | M | VERIFIED |
| FW-§3a correlation confidence used, disagreement escalated (added 2026-10-22, L-FWA) | FW §3 (D1–D4: "confidence without calibration is theatre"; "disagreement should escalate, never average away"; never destructive dedupe) | `finding_correlation.py` clusters on an anchored key and keeps source observations. It carries no confidence value, calibration, independence assumption or disagreement semantics: the module contains no `confidence`, `disagree` or `escalat` (searched 2026-10-22) | `prove_anchored_correlation` (clustering only) | NOT BUILT | The correlation record carries normalisation basis (rule ID → CWE), independence assumptions, provenance, and agreement and disagreement; a disagreement routes to a person (DECISION_REQUIRED), never an average; the design states what confidence changes (a gate input or an escalation), or records that it changes nothing. Lane L-A (the gate reads it), after L48 | M | VERIFIED |
| FW-§3b correlation-triage skill (added 2026-10-22, L-FWA) | FW §3 ("There is no correlation `SKILL.md` anywhere") | none: the tree has no `skills/` directory (2026-10-22) | — | NOT BUILT | Write the tool-tier skill from the reference doctrine FW §3 names, or record it out of scope. Lane L-G | S | VERIFIED |
| AX-TEAM team pattern drives the repository's settings (added 2026-10-22, L-FWA) | AX "enforcement by team pattern"; owner 2026-10-22 (team-type-driven settings: solo dev, pair, team) | Library only: `enforcement_axes.py` maps four patterns to human-control availability and disposition deciders, and the registration schema requires `team_pattern`; neither is on the gate path (L33). `developer-safety/branch-protection/` ships three static profiles (solo, small team, critical service) that do not match the four patterns (no pair profile) and are applied by hand. Nothing derives required approvals, CODEOWNERS routing, environment reviewers, separation of duties or auto-merge eligibility from `team_pattern`, and no run reports the unvalidated human-workflow paths | `prove_enforcement_axes` (library); `check_branch_protection_profiles` (check names only); since lane L-A `prove_policy_registration`, `prove_deploy_environment_protection` | PARTIAL (lane L-A: `team_pattern` resolves per register scope and the gate reports the unvalidated human-workflow paths; deploy approval -- approver groups, self-review prevented, AI review advisory only -- is expressed per scope and read back from the GitHub environment by both deploys, refusing at uat/prod) | Still owed: one mapping from `team_pattern` to settings (profile JSON, approvals, environment reviewers, auto-merge eligibility for lane L-DB's FW §6 path), a pair profile, and the posture record lists the unvalidated human-workflow paths. Lane L-A with L33 | M | VERIFIED |
| AX-CRAWL crawl blocks only secrets (added 2026-10-22, L-FWA) | RUNG; ETFB §1.1; owner 2026-10-22 ("crawl phase where only secrets block") | `rung_ladder.FLOOR` at crawl: secrets BLOCKED, every finding class PROCEED_WITH_ADVISORY (`rung_ladder.py:87–93`). Not wired (S-01). Unresolved against the owner's words: the gate also stops on untrusted evidence and bootstrap failure in every mode (L28, L29), and KDEC-014 refuses a proven version gap at uat/prod | `prove_rung_ladder` (library); lane L-A `prove_gate_policy_enforcement` | DONE-PROVEN-LOCAL (lane L-A, owner ruling O-24 2026-10-22: crawl blocks on a found secret and on the kit being unable to run or trust its own scan -- crash, COLLECTION_FAILED, hollow or unreadable scan, bootstrap failure -- EVIDENCE_UNTRUSTED at every tier; findings and COVERAGE_PARTIAL advisory with registered causes; one hosted run owed) | Was: record the ruling (recommended: at crawl only secret FINDINGS block; a scan that did not run still stops, because it is not a finding). Then the rung patch (S-01) with a crawl registration, and a proof that a crawl run with a seeded high finding proceeds and one with a seeded secret blocks. Lane L-A | M | VERIFIED code, INFERRED owner meaning |
| POL-SCOPE policy per organisation, team, product and environment (added 2026-10-22, L-FWA) | owner 2026-10-22 (finer per-org/team/product/environment policy, lane L-A); ETFB §4, §10 | `policy-registration.schema.json`: one registration per repository, with cells per environment only. No organisation, team or product level, and no precedence between levels (schema read 2026-10-22) | `prove_policy_registration` (since lane L-A: the multi-scope register) | DONE-PROVEN-LOCAL (lane L-A: register schema_version 2; precedence kit default < org < org+team < org+product < org+team+product < repository, tier-qualified above untiered; central copy in the kit, repository file on its protected branch, tighten-only; conflicts, unattributed and expired decisions refused by name. Departs from the recommendation: a more specific scope may SOFTEN what it inherits as an attributed decision (owner 2026-10-22); one hosted run owed. **Reversed by KDEC-018 (lane L-FX):** the recommendation now holds -- an enterprise scope above org, and every narrower scope may only tighten (FX-FLOOR)) | Was: design the precedence (organisation floor → team → product → environment; a lower level may only strengthen, as cherry-picks do), where each level's record lives (read from a protected ref, never the PR), and the refusals; then build it in L-A beside the rung patch | M | VERIFIED |
| FX-FLOOR the authority's rung is the floor (added 2026-10-22, lane L-FX) | KDEC-018 items 1-3 | Enterprise scope (`orgs` map); a narrower entry leaving anything weaker than what is registered above it is `POLICY_BELOW_AUTHORITY_FLOOR` (BLOCKED), decision or not; only the authority softens the kit default deploy approval; `--validate` names every below-floor entry; per-finding exceptions unaffected | `prove_authority_floor` (failed first: 34 FAIL), `prove_policy_registration`, `prove_gate_policy_enforcement` (`softening` failed first: PROCEED_WITH_ADVISORY) | DONE-PROVEN-LOCAL | One hosted run (the owner's call on unmapped orgs was made: KDEC-020, correcting KDEC-019 item 1, row RB-ORG) | M | VERIFIED |
| FX-CRAWL crawl is the absolute floor (added 2026-10-22, lane L-FX) | KDEC-018 item 1 | Every weakening input, attributed, still blocks a secret and a crashed scan at dev and prod; the one path below crawl -- `paths` narrowing the secret scan -- closed: the secret scan always covers the repository root | `prove_crawl_floor` (failed first: K1, K2), `prove_composite_move_equivalence` (re-pinned) | DONE-PROVEN-LOCAL | Hosted self-test. (The owner's call on `enable_malicious_pkg_scan: false` was made: below crawl, refused -- KDEC-020, row UO-MAL) | S | VERIFIED |
| FX-HISTORY exception history and renewal cap (added 2026-10-22, lane L-FX) | KDEC-018 item 4 | `renews` on secret exceptions, register decisions, the deploy's version-gap exception (`weakening_renews`); shown in the gate summary, run record (`policy_exceptions` new), deploy summary and `outcome.json`; `numbers.max_exception_renewals` (central, default 2, 0..5); `EXCEPTION_RENEWAL_LIMIT` | `prove_exception_lifecycle` (failed first: 40+ FAIL), `prove_version_gap_production`, `prove_gate_run_record` | DONE-PROVEN-LOCAL | Hosted runs (gate, deploy). History is declared in the register (CODEOWNERS-reviewed), not derived from git | M | VERIFIED |
| FX-RESURFACE exceptions resurface when due (added 2026-10-22, lane L-FX) | KDEC-018 item 4; KDEC-017 item 5 (Jira only) | `scripts/exception_due.py`, `reusable-exception-due.yml` (credential-free list job; resurface job in the protected environment, schedule/dispatch on the default branch), `templates/exception-due.yml` (weekly) | `prove_exception_due` (fake Jira; list step run as shipped; failed first: not built) | DONE-PROVEN-LOCAL (tool) | A hosted scheduled run; a run against a personal Jira (never employer) | M | VERIFIED |
| RB-ORG unmapped orgs run at the enterprise floor (added 2026-10-22, lane L-RB; corrected 2026-10-23, lane L-UO) | KDEC-020 (supersedes KDEC-019 item 1) | **Corrected:** L-RB built the opposite of the owner's meaning (`26ca9e8`, a refusal `ORG_NOT_UNDER_ENTERPRISE`). Now an org the central `orgs` map does not name RUNS at the enterprise floor -- the one enterprise, or with several the strictest at each tier, never the lower -- and its own entries may only tighten (below it: `POLICY_BELOW_AUTHORITY_FLOOR`). Never silent: notice `ORG_UNMAPPED_RAN_AT_ENTERPRISE_FLOOR` (org, enterprise, rung, "add it to the orgs map") in `notices`/`notes`, `policy_notices`, a workflow warning and the gate's policy summary (`policy_notice` namespace). `--validate` no longer refuses unmapped orgs. No map or an empty one changes nothing. `ORG_NOT_UNDER_ENTERPRISE` retired (registered only for history) | `prove_authority_floor` A1, A11 (failed first: 29 FAIL -- unmapped orgs refused, no notice, `--validate` refused, the refusal still in the resolver) | DONE-PROVEN-LOCAL | One hosted run | S | VERIFIED |
| UO-MAL the malicious-package scan is part of the crawl floor (added 2026-10-23, lane L-UO) | KDEC-020 | A run that receives `enable_malicious_pkg_scan` false is refused by the resolver, `CHERRY_PICK_BELOW_FLOOR` (BLOCKED, the input named), at every tier and on pull requests; a register softening of `malicious-deps` already was. No kit workflow passes it false (`consumer-path-test.yml` `multi` now expects the job to run; `consumer-path-negative.yml` `seeded-php` keeps the default). How a confirmed `MAL-` finding routes at crawl is unchanged | `prove_crawl_floor` K6, K7 (failed first: 27 FAIL -- the input resolved POLICY_RESOLVED; two kit workflows passed it false) | DONE-PROVEN-LOCAL | Hosted self-test and consumer-path run; owner question: does a confirmed `MAL-` hit block at crawl? (KDEC-020) | S | VERIFIED |
| L49 disposition contract | schema; ETFB §8.1 | built | `prove_disposition_schema_and_key` | DONE-PROVEN-LOCAL | — | — | VERIFIED |
| L50 / OD-6 durable key, 30-day window | KDEC-008 OD-6 | built; the window closes 2026-11-13 (a code constant) | `prove_disposition_schema_and_key` | DONE-PROVEN-LOCAL | Remove the legacy path after 2026-11-13, test-first | S | VERIFIED |
| L51 lineage | KD; `finding_lineage` | integrity fixed. **Lane L-F (B-08 taken):** propose-ledger records each move ONCE, as a SUPERSEDES / PATH_MOVED lineage event appended by `finding_lineage.append_event` to the tip's `.security/finding-lineage.jsonl` (plus head anchor) and carried in the same pull request; it no longer writes `move_history`, and the ledger reader refuses that field by name. A tampered or unparseable lineage at the tip refuses the proposal; a move already recorded (another environment's entry) is not appended twice. The push step stages only files under `.security/` | `prove_propose_ledger` (failed first: `move_history` written, no lineage file, reader accepted the field), `prove_propose_ledger_establishment` (move through the shipped steps), `prove_propose_ledger_job_scope` (path guard, 10 mutants), `prove_lineage_integrity`, `prove_lineage_durability` | DONE-PROVEN-LOCAL | Hosted: one move proposed on the Level 2 consumer. Nothing READS lineage on the gate path yet (dispositions carried by lineage are library-only); KNOWN_DEFECTS "nothing writes a lineage event" is now stale (L-G) | M | VERIFIED |
| L52 findings JSON | TC §3 | SR:1553–1581 | `prove_report_emits_findings` | DONE-PROVEN-LOCAL | — | — | VERIFIED |
| ETFB-§5.6 declared reformat event | ETFB §5.6 | none; threshold is a placeholder | — | BLOCKED-ON-OWNER (O-06) | Measure, then build | M | VERIFIED |
| ETFB-§8.1 grandfather track ref and SLA expiry | ETFB §8.1 | schema built; track ref and expiry not | — | PARTIAL (Release 2) | With L47 | M | READ |
| ETFB-§8.8 rule 4 per-environment pre-existence | ETFB §8.8 | Environment is a free caller string over a default-branch scan. **Lane L-F:** the ledger header gains `environment_presence` {env: evidence (a registered `scan_depth` value), assumption, declared_on, run_id}; propose-ledger declares it (merge, or nightly on a schedule; assumption true) the first time an environment's entries are proposed, and says so in the body; the reader refuses a malformed block, an unregistered depth, or a non-`revalidate` claim without an assumption, and notes (does not refuse) an environment with entries but no declaration (ledgers written before this) | `prove_propose_ledger` (failed first: no declaration; the field was an unknown header key) | DONE-PROVEN-LOCAL | A `revalidate` (deployed-artefact) evidence path is not built: nothing proposes from a scan of the running digest (P-03 / V3) | S | VERIFIED |
| ETFB-§10 governance records | ETFB §10 | ledger header, disposition and posture built; severity-formula, cluster confirm/split and rung-in-run records not | — | PARTIAL | — | M | VERIFIED |
| ETFB-§12 vocabulary | ETFB §12 | registered except the correlation confidence namespace (the code uses lowercase `anchored`) | `reconcile_taxonomy` | PARTIAL | Register or rename | S | VERIFIED |
| AX-DEPTH depth by trigger context | AX; EP | advisory plan only; CodeQL queries flat | `test_resolve` | BLOCKED-ON-OWNER (EP-1..EP-4) | — | M | VERIFIED |
| AX-REVAL revalidation contract | AX 157–165 | the NVD reusable takes `sbom_path` / `image_ref`; contract fields and schedule not built | — | NOT BUILT (with PROV V3) | P-06 | M | READ |
| L82 SHA pinning | POLICY R2; PINNING; SSM gate 2 | **1 of about 171 remote `uses:` references is pinned by a 40-character SHA** (coordinator count: `grep` over `.github` and `templates`). The audits counted 0 of 149–150 under narrower definitions. Self-test dogfood runs `require_sha_pinning: false`, `soft_fail: true`, **attributed weakening expiring 2026-10-31** (self-test.yml:1569–1580). The template pins the kit `@v1` (TPL:26…189) while `templates/security.yml` pins a SHA | `check_action_pins` (P1–P5, `--online` in self-test); `prove_workflow_policy_rules` TREE + DOGFOOD | DONE-PROVEN-LOCAL | **Lane L-H, 2026-10-22:** 161 of 161 remote `uses:` (workflows, job-level calls, composites) pinned to the commit SHA their tag named, `# vX.Y.Z` exact release, resolved and peeled through the GitHub API; templates keep the fail-closed `YOUR_ORG`/forty-zero placeholder; dogfood flipped to `require_sha_pinning: true`, `soft_fail: false`, weakening record removed (O-23); Dependabot reads `/.github/actions/*`. Follow-up: the overlay's 5 refs pinned the same way (checked; Dependabot deliberately not pointed at overlays); `pin-actions.sh` writes the exact release and exempts no owner by default (`prove_pin_actions_names_release`). Owed: a hosted self-test on the pinned tree | M | VERIFIED |
| L83 policy gate R1–R9 | POLICY | Job-level `uses:` and container/service images unchecked (`workflow-policy-check.yml:227–242`); R9 excludes `inputs.*` (175–180); zero files exits 0; no seeded fixtures per rule | dogfood only | PARTIAL | Extend the rules; seeded fixtures | S-M | VERIFIED |
| AMC C-1, C-2 | ASSURANCE_MODEL_CANDIDATES | candidates; nothing built | — | NOT BUILT (deferred by design: AMC header; `toolchain-terraform` held to 2026-12-31) | Terraform assurance model specified | L | VERIFIED |

### 2D · Decomposition, topology, self-assurance

| id | designed | built? | proven how | state | what closes it | size | label |
|---|---|---|---|---|---|---|---|
| L60 Candidate D bootstrap | DECOMP §5 Phase 1 | `kit-scripts` (FW:385) | step 6 hosted (38811950471); step 7 local (`prove_bootstrap_failure`) | DONE-PROVEN-LIVE | — | — | VERIFIED |
| L61 import closure | DECOMP §1.5 | No AST closure check; the four bundled `.py` files import only the standard library today | — | PARTIAL | Closure check in `inline_normalizer --check` | S | VERIFIED |
| L62 pin tooling covers composites | DECOMP step 9 | `pin-actions.sh` scans `.github`; `check_pinned_artifacts.py:61` covers actions | the v-tag proof | DONE-PROVEN-LOCAL | — | — | VERIFIED |
| L63 registry as denominator | DECOMP §E.3 | `check_scanner_registry`: 19 rows = 19 jobs, 8 seeded defects caught | wired | DONE-PROVEN-LOCAL | — | — | VERIFIED |
| L64 Phase 2 composites | DECOMP steps 11–13; KDEC-002 | `$/` for discover ×2, resolve, scan-report, propose-ledger. Per-scanner composites not built; `kit-scripts` retained; redact, status and fetch blocks still inline. **FW:375–379 says `$/` "is not used" while FW:1700, 1829, 2661 use it** | Level 2 `$/` runs 38434823833, 38468728084 (decomposition plan header) | PARTIAL | One scanner per commit (sast-cpp and secret-scan first); then delete `kit-scripts` (section 5, B-01) | L | VERIFIED |
| L65 cost packing | DECOMP Phase 3; JT §9.4 | not built; the remote `perf/consolidate-subminute-jobs` is stale (2026-08-17) | — | BLOCKED-ON-OWNER (OD-3; Release 2) | Re-measure, then decide the endpoint | L | VERIFIED |
| FW-§2 cost acceptance per consumer class (added 2026-10-22, L-FWA) | FW §2 (acceptance criterion: identical semantics, "before/after billed minutes per class"; changed-path intelligence; developer vs assurance mode) | Packing not built (L65). The `determine-changes` composite exists, held by the deferral `change-detection` (RV:589, expires 2026-12-31). Depth by trigger is the advisory plan (AX-DEPTH). No billed-minute measurement exists in the tree for a small, a monorepo or an IaC-heavy consumer | — | NOT BUILT | Measure billed minutes per class on the current trunk (before); after each of L65, change-detection and AX-DEPTH, measure again with scanner, evidence and gate semantics unchanged (consumer path 24/24, negative as designed). Lane L-R | M | VERIFIED (code), READ (no measurement) |
| L66 size gate scope | `check_workflow_size` | `.github/workflows/*.yml` only; composites (resolve is 99 KB) and overlay workflows unmeasured; measures on-disk bytes (CRLF inflates on Windows) | wired | PARTIAL | Widen the glob; measure LF | S | VERIFIED |
| G-01 / L69 debt register | VD | 0 BLOCKING, 3/3. **Orphan deferral:** `version-metadata` (RV:586–592) expired 2026-09-30 and maps to no capability, so it is silently ignored; stale keys are not flagged | RV, plus the forced-expiry negative control in self-test | PARTIAL | Delete the orphan; fail on a deferral key with no capability | S | VERIFIED |
| G-02 registry level overclaim | VD | **Closed in lane L-T** (coordinate the merge with L-E, which owns RV): `ticket-reconciliation` is now `level: "tool"`; the comment beside it says the probe never ran the workflow, and that the L-T changes (T-02, T-08, T-13) are NOT covered by the cited live runs, which predate them. RV:41–44 now agrees: observed at tool level, armed workflow owed (T-19) | `reconcile_validation` 0 BLOCKING after the change; `check_doc_currency` passes | DONE-PROVEN-LOCAL | The armed workflow path stays T-19 (hosted run, O-18) | S | VERIFIED |
| L70 needs-infrastructure is not an exemption | VD rule 4 | `check_selftest_coverage.py:134–135` still counts requires-integration-environment as accounted (latent: the dict is empty) | — | PARTIAL | Require a dated deferral | S | VERIFIED |
| L71 four-case gate harness | PROOF_RULE | `prove_gate_routing`, `prove_gate_reads_findings`, `prove_bootstrap_failure`, `prove_secrets_always_block` | wired | DONE-PROVEN-LOCAL | — | — | INFERRED |
| G-03 / L72 proofs wired into CI | KD; TM | **Not invoked by any workflow:** `check_stage_phase`, `build_pipeline_overlays --check`, `prove_hollow_scan`, `prove_identity_durability`, `check_context_current`, `check_shell_continuations`, `prove_pin_check_sees_v_tags_and_action_refs`, `capability_inventory`, `prove_gate_reads_rung` (expected-fail) | — | PARTIAL | Add the eight runnable ones to self-test; the ninth after S-01 | S | VERIFIED |
| L73 tests leave the machine and tree intact | — | `mkdtemp`; ticket idempotency mutates copies | `prove_tests_leave_tree_clean` | DONE-PROVEN-LOCAL | — | — | VERIFIED |
| L74 consumer contract | FW §12 | negative asserts exact job and conclusion; 20/20 tool-pinned | 38811950471 (RV:425) | DONE-PROVEN-LIVE | — | — | VERIFIED |
| FW-§12 consumer contract invocations (added 2026-10-22, L-FWA) | FW §12 ("Owed: decide whether the negative control should be (a) … (b) … (c)", and whether `clean` and `multi` share one invocation) | Undecided. `consumer-path-negative.yml` keeps `workflow_dispatch` (:17), so it can still run with nothing asserting on it. `consumer-path-test.yml` invokes the flagship twice (:43, :123) and dispatches the negative twice (:286, and :425 with `scope=php`). L74 tracks the assertions, not this decision | — | BLOCKED-ON-OWNER (O-26) | Choose (a), (b) or (c), and whether the two legs share one invocation, weakening no assertion; billed minutes before and after (FW-§2). Lane L-E | S-M | VERIFIED |
| L75 Level 2 consumer | DECOMP step 8 | separate private repository calling by SHA | 38817782084, 38820564939 (RV:230–251) | DONE-PROVEN-LIVE | — | — | VERIFIED |
| L76 validate-scanners | FW §9 | **Still broken:** the negative control has `continue-on-error: true` (validate-scanners:549) and `2>/dev/null` with `\|\| echo 0` (539–542); the matrix renderer swallows bad JSON (596) | — | PARTIAL | Remove continue-on-error; a parse failure is UNKNOWN; roster denominator | S | VERIFIED |
| L77 vocabulary gate | operations doc on taxonomy drift | exits 0 | `reconcile_taxonomy` | PARTIAL (the one-way-drift sub-items were not re-checked) | — | M | INFERRED |
| G-07 / L78 stage register | TM §0 | Guardrails are strings; not run in CI; **stale both ways**: stage 13 says "no workflow calls this script", stage 15 says DESIGNED and ENFORCED is 0 despite live refusals; stages 2 and 6 carry no run id | — | PARTIAL | Wire it; tie guardrails to tests; update phases from the runs the registry cites | M | VERIFIED |
| L79 kit linters | the recurring-defects analysis | not re-checked at 53d2962 | — | UNKNOWN | Re-check | M | — |
| L80 first ENFORCED state (T-03) | TM §5 | No hosted run of a job refused a write outside its permission. Live refusals exist for the boundary (T-09) and the verdict gate; TM still says 0 ENFORCED | — | NOT BUILT | One hosted run, then refresh the TM states | S | VERIFIED |
| L81 doc currency | `check_doc_currency` | One direction only; did not catch any of the stale prose listed in D-01 | wired | PARTIAL | A claims list with code predicates (section 5, B-11) | S-M | VERIFIED |
| L104 branch-protection profiles | developer-safety | still require `lint`, `test`, `sast`, `sca`, `policy`, `provenance`, which no job emits; the real check is `<caller job> / Security gate` | — | PARTIAL | Real check names, derived from workflows by a check | S | VERIFIED |
| L105 profiles wired into resolve | SPT §8.2 | inert; vocabulary drift (`enable_iac`, `language: none`) | — | NOT BUILT | After S-01 | M | VERIFIED |
| L106 export cannot leak | FW §13 | Personal-product slug fixed (`53d2962`). **Sibling:** the consumer-overlay pattern (`scripts/export-deny.txt` line 51) uses `\s*` and misses the hyphenated overlay slug; SPT:931 on the trunk still carries it; the release candidate neutralised it by hand | `check_export_safety` passes because the pattern misses | PARTIAL | Separator-tolerant pattern for line 51, test-first | S | VERIFIED |
| L107 custody across overlays | FW §13 | iterates every overlay, tolerates none | `prove_custody_overlays` | DONE-PROVEN-LOCAL | — | — | VERIFIED |
| FW-§8a organisation and Enterprise migration (added 2026-10-22, L-FWA) | FW §8 ("OIDC subjects contain the owner name"; AADSTS700213; `access_level`, environments, secrets, branch policies, every `uses:` reference) | none: no migration runbook, inventory or pre-move check in the tree | — | NOT BUILT | A pre-move check that lists every owner-named federated subject, environment, secret, branch policy and `uses:` reference, plus a migration checklist; one rehearsal into an organisation. Lane L-E (check), owner (rehearsal) | M | INFERRED (no file found) |
| FW-§8b export cannot carry history (added 2026-10-22, L-FWA) | FW §8 ("It cannot cover history") | Built by construction: `export_for_adoption.py` writes a fresh tree with no history (:884) and prints that it did (:708, :962). FW §8's sentence is stale | No proof asserts it: `prove_export_scope` checks what is exported, not that no `.git` or commit object is | BUILT-UNPROVEN | A proof case (the export holds no `.git` and no commit object), then L-G updates FW §8. Lane L-E | S | VERIFIED (code) |
| FW-§8c promotion path personal → portable → organisation (added 2026-10-22, L-FWA) | FW §8 (no tenant IDs, OIDC subjects, environment names, repository IDs, GHAS assumptions or owner permissions survive the boundary) | First hop built: `check_export_safety`, the deny list and the public mirror (`v0.2.0`). Second hop (portable → organisation) has no check and no rehearsal | `check_export_safety`, `prove_export_scope` (first hop) | PARTIAL | One deny class per named item, and one organisation-side rehearsal with FW-§8a | M | VERIFIED (first hop), INFERRED (second) |
| FW-§6b reference-estate census items not tracked elsewhere (added 2026-10-22, L-FWA) | FW §6 ("What the reference estate has that this kit does not"). **Auto-merge (FW §6 proper) is not this row: lane L-DB adds it** | Of the ten census workflows, eight map to rows: dedupe to S-11 and L48; issues from scans to S-13; ingestion to F-01; dashboard to FW-§4; shell and Actions lint to FW-§5 and L110-1; the orchestrator to S-05; the GHAS-conditional pattern superseded by the platform probe (L25). **Two map to nothing:** `update-roadmap-from-scans.yml` (scan output feeding planning) and `azure-security-ingestion.yml` (cloud posture into the same pipeline) | — | BLOCKED-ON-OWNER (O-14, scope) | Classify both as owed, overlay or retired in O-14's one recorded decision | S | VERIFIED |
| OVL-A consumer scanning overlay | FW §13; KDEC-003, KDEC-008 OD-10 | Calls the core cross-repo by SHA (placeholder). `secrets: inherit`; external quality and DAST actions tag-pinned; the verdict reads `needs.neutral.result`, not the core's `routing_result`; its tests run in no workflow; never dispatched | — | PARTIAL | Pin; explicit secrets; read `routing_result`; wire its tests; the authorisation record (L109); one dispatch | M | VERIFIED |
| OVL-B reference-estate fixture overlay | runbook Steps 25–27 | The ticketing-twice property is proven live on Jira (synthetic findings). The scan against the fixture repositories and the asserted disagreements are not built; teardown harness is stub-only | — | NOT BUILT | After L-E and L-F; one cloud sandbox run | L | VERIFIED |
| OVL-C storefront templating overlay | profile doc | design only | — | NOT BUILT | Release 2 (09-STATUS) | L | VERIFIED |
| G-04 PR #1 to main | KDEC-003 | `release/main-candidate` (`62fb360`) carries no `overlays/`; the trunk does; `main` is older | — | BLOCKED-ON-OWNER (O-15) | Merge from the candidate, never the trunk | S | VERIFIED |

### 2E · Ticketing (TICKETING_CONTRACT, TICKETING_BACKENDS, WORK_ITEM_HIERARCHY)

Backends: **J** is Jira (authoritative, KDEC-004), **A** is Azure DevOps (second), **G** is GitHub Issues
(supported, not extended). The live evidence is `tests/live_ticketing_run.py` on the owner's personal
Jira. The transcripts are kept outside this repository, and the tree records them only in RV:376–392,
commits `4360aeb`, `a992811` and the change log. No GitHub run id exists for any ticketing run.

| id | designed | built? | proven how | state | what closes it | size | label |
|---|---|---|---|---|---|---|---|
| T-01 / L53 cascade, create only on BINDING_ABSENT | TC §3.1–3.4 | `RT:1628–1697`; the old defects are fixed (membership-stable key `rebind` 1595–1625; no self-validation `ticket_model.py:847–884`; garbage dates read as an unknown term, 702–759) | stub T-1..T-6 (J, A); J live T-1/T-2 | DONE-PROVEN-LIVE (J) | A live; G has no T-matrix case | S | VERIFIED |
| **T-02 human text preserved** | TC §5.4 | **Fixed in lane L-T.** The members-added update now reads the description in full first (`read_description`: J `GET issue?fields=description` as ADF, A `GET workitems?fields=System.Description` as HTML plus `rev`, G the issue body), replaces only the delimited block (`adf_splice`, `html_splice`, `splice_text`) and writes every other node or byte back as read (`write_description`; A adds a JSON Patch `test /rev`, so a person saving between read and write is never overwritten). A description that cannot be read is **not written**: the run carries a `BINDING_UNESTABLISHED` obligation, the ledger records the members as `update_owed` for the next run, and the claim is `EVIDENCE_UNTRUSTED`. Missing delimiters re-append and are reported. Was: the J and A sweeps return `'body': ''`, and the update rendered the block against it, erasing human text. Residual: Jira's issue edit takes no precondition, so a save in the seconds between read and write is not detected (named in code) | `prove_ticket_backends` case "T-02 human text outside the block survives" (J and A, ledger carried and absent, ADF marks/mentions/lists and HTML around the block, unreadable description). **Failed first** on the base: 16 failures, every one the human text before or after the block erased, or an unreadable description written anyway. `reconcile_tickets --self-test` 12c; three new mutants in `prove_ticket_idempotency` (sweep copy trusted, unreadable written, whole-body splice), all killed; `prove_live_runner_offline` asserts the live runner's new T-02 check HELD | DONE-PROVEN-LOCAL (live J re-run owed: `live_ticketing_run.py --phase r2` now writes a person's note around the block before "T-2 joined" and reads it back) | Live R-2 on the personal Jira (T-2 with human text, the runner's new T-02 check) | S | VERIFIED |
| T-03 / L54 calibration probe | TC §4.5 | J 781–804, A 1123–1134, G 619–640 | stub J-3; live J (the probe must pass for T-1 to create) | DONE-PROVEN-LIVE (J) | A live | S | INFERRED (live) |
| T-04 dangling, redirect, positive deletion | TC §4.5 | `resolve()` exists and is never called; a dangling reference always goes to a person; no redirect or archived handling | — | PARTIAL (fails safe) | Owner decision O-17 | M | VERIFIED |
| T-05 / L55 failed lookup | TC §4.1 | `finish_claim` 1746–1781; exit 3; `owed` written to the ledger; retry ceiling defaults to 0 | stub T-5, J-4, T-11, C-2; live J R-1 (4/4 named, 0 writes) | DONE-PROVEN-LIVE (J) | A live; owner sets the retry ceiling (O-16) | S | VERIFIED |
| T-06 degraded-run escalation | TC §4.1, §8 | **Built in lane L-T.** `carry_owed` writes `owed` = {outcome, cause, `attempts`, `first_degraded_at`} for every carried obligation (lookup unestablished, create failed, update unreadable or failed); a run that establishes the binding clears it, so `attempts` counts consecutive runs. Past `TICKET_DEGRADED_RUN_THRESHOLD` (owner-set; 0 = count, never escalate) the run lists it under `degraded_escalations` and the summary routes it `DECISION_REQUIRED` at the cell's next promotion review | `reconcile_tickets --self-test` 18 (three degraded runs, escalation at the threshold, streak restarts after a bound run). **Failed first:** `owed` held only {outcome, cause}, no escalation. Mutants "streak not counted", "bound lookup does not end the streak" killed | DONE-PROVEN-LOCAL | Owner sets the threshold (O-16) | S | VERIFIED |
| T-07 reopen and successor | TC §4.2 | `closure_backing` 1536–1561; branch 2132–2176 | self-test T-7 and T-8; live J T-7 and T-8 | DONE-PROVEN-LIVE (J) | A live; a live "backed closure stays closed" case | S | VERIFIED |
| T-08 REOPENED_BY_LAPSE label | TC §4.2; FW D5 | **Built in lane L-T.** `reopen_classification` names every reopen by TC 4.2's table: the registered `REOPENED_BY_LAPSE` (an approved disposition expired), `falsified` (an approved REMEDIATED still reproduced) or `unbacked` (nothing approved). It is recorded in the run record, in the ledger's append-only `reopens` history, and as one comment on the ticket (`reopen_comment`, "re-decide with a named approver and a new expiry"). A successor's block states why its predecessor needed reopening | `reconcile_tickets --self-test` 4b-iv; `prove_ticket_backends` J reopen (one ADF comment naming the class; successor block) and A reopen (one comment). **Failed first:** 12 self-test failures, reopen recorded with no classification, no comment and no ledger history. Mutants "a reopen does not say why", "an expired disposition reads as unbacked" killed | DONE-PROVEN-LOCAL | Live J T-7 re-run reads the comment | S | VERIFIED |
| T-09 cluster closure on verified clearance | TC §4.3 | The model has ALL_CHILDREN_RESOLVED; the reconciler never closes a ticket; departed members are not marked POTENTIALLY_ABSENT in the block | model self-test | BLOCKED-ON-OWNER (O-17) | Human-only closure plus a reported signal, or wire it | M | VERIFIED |
| T-10 ambiguity (T-6) | TC §4.4 | 1645–1660, 2178–2181 | stub J and A; live J T-6 | DONE-PROVEN-LIVE (J) | A live | S | VERIFIED |
| T-11 unstamped security-shaped tickets report | TC §4.4 | none | — | NOT BUILT | Owner: wanted or not (TC §11.4 doubts it) | M | VERIFIED |
| T-12 one backend, refused by name | TC §4.6 | `choose_backend` 2299–2308; the workflow unsets the other backend; no migration path | stub C-2, T-11 | DONE-PROVEN-LOCAL | Migration when needed | S | VERIFIED |
| T-13 delta updates | TC §5.1 | **Partly built in lane L-T.** The bound path now computes a delta over the facts the kit has data for: members added; effective severity (worst of the members OBSERVED this run); contributing scanners, where a stopped scanner is named "no longer contributing", not omitted; members not observed, listed `POTENTIALLY_ABSENT`. The delta source is the ledger's `rendered` record, written at create and after each write, so an unchanged run with the ledger carried costs no read and no write (TC 6.1). Without it (no persisted ledger, T-20; or older tickets) the run reads the description, compares the block (`block_facts`), and writes only on a difference. Last-seen goes to the ledger every run and to the ticket only with another write. **Not built, no data source:** fix availability and SLA (L47/T-27, Release 2), movement (locus is in the cluster key), the stamp repair and the disposition rendering | `reconcile_tickets --self-test` 19 (writes per run exactly [0,0,1,0,1,0] with and without the ledger; zero reads on an unchanged carried run; a same-scanner join is one write). `prove_ticket_backends` T-02 case: an unchanged third run makes no PUT or PATCH on J and A. **Failed first:** 9 self-test failures, no write on a severity or scanner change, no last-seen. Mutants "unchanged run reads anyway", "stopped scanner omitted", "a member joining is not a delta" killed | PARTIAL (5.1 facts with a source: DONE-PROVEN-LOCAL) | Fix availability and SLA with L47; movement once identity across a move is established | M | VERIFIED |
| T-14 never-list (no disposition, approver, expiry or SLA write) | TC §5.2 | static and dynamic check | stub T-12 (J, A) | DONE-PROVEN-LOCAL | — | — | VERIFIED |
| T-15 rendering divergence | TC §5.3 | none | — | NOT BUILT | Render plus divergence, or drop the clause | M | VERIFIED |
| T-16 mutation classes | TC §5.5 | `ticket_model.py:264–425` | `prove_ticket_idempotency` | DONE-PROVEN-LOCAL | — | — | READ |
| T-17 / L59 deferral clock | TC §5.6; FW D5 | `sweep` and `resolve` CLIs; workflow `mode: sweep`. **No schedule exists anywhere** | `prove_ticket_reconcile_workflow` (sweep mode) | PARTIAL | A template caller with `schedule:` plus `mode: sweep`, and one hosted run | S | VERIFIED |
| T-18 call budget | TC §6 | calls and 429s recorded; creation ceiling required for J and A; severity order | stub J-4; live R-2 | DONE-PROVEN-LIVE (J) | Nearest-SLA order; bulk create; a dangling-resolution ceiling | M | VERIFIED |
| T-19 / L56 where it runs | TC §7.1–7.3 | the workflow exists (guard 111–148; job 150–163); only the self-test PR negative calls it; **no template caller** | local extraction proof; no hosted run id | BUILT-UNPROVEN | Template caller (push to the default branch plus schedule); one armed hosted run on the personal tracker (O-18) | M | VERIFIED |
| **T-20 ticket ledger persistence** | TC §7, §5.4 | The workflow uploads `ticket-ledger-proposal.json` (261, 408–417). **Lane L-F (B-15 taken):** `reusable-propose-ledger.yml` gains `ticket-ledger-artifact`; when named, the proposal is downloaded and `propose_ledger.py` carries a changed one, canonical, at `.security/ticket-ledger.json` in the SAME pull request (also when no baseline exists, saying why); an unchanged one adds nothing; a malformed one refuses. The caller must run ticketing BEFORE propose-ledger and name the artifact; no template does yet (L-W) | `prove_propose_ledger_ticket_ledger` (runs the shipped steps; failed first: no input, no download, unchanged/refused instead of persisted) | DONE-PROVEN-LOCAL (reusable) | L-W: template orders ticket-reconcile before propose-ledger and passes `ticket-reconcile-${{ github.run_attempt }}`; one hosted run showing a successor persisted and the next run binding it | M | VERIFIED code, INFERRED consequence |
| T-21 sweep-mode least privilege | TC §7.2 | **Built in lane L-T.** `reusable-ticket-reconcile.yml` has a `sweep` job (mode `sweep` only) with no environment, no secret, `contents: read` and a timeout; the credentialed `reconcile` job no longer runs for mode `sweep`. The workflow outputs read either job. Found on the way: under the runner's `bash -e` the reconcile step's non-zero exit ended the step before `rc` was written, so a decision owed (1) reached the posture step as no verdict (EVIDENCE_UNTRUSTED); the exit is now captured (`rc=0; ... \|\| rc=$?`) | `prove_ticket_reconcile_workflow`: sweep job shape, the extracted sweep step (elapsed deferral → exit 1, DECISION_REQUIRED; no ledger → exit 3, EVIDENCE_UNTRUSTED), and `rc=3` written under `bash -e`. **Failed first:** no sweep job, reconcile job armed for mode sweep; then `rc` absent under `bash -e` | DONE-PROVEN-LOCAL | One hosted scheduled run (with T-17 / L-W) | S | VERIFIED |
| T-22 injection and redaction | TC §7.4 | ADF text nodes; HTML-escaped A; env-only | stub T-9, T-10 | DONE-PROVEN-LOCAL | — | — | VERIFIED |
| T-23 per-cell policy record | TC §8 | environment variables, not a protected-branch policy file; no discovery date | — | BLOCKED-ON-OWNER (O-16) | Accept the variables as the record, or add the file | S | VERIFIED |
| T-24 R-1 missing-transition break | TB §6 | **Built in lane L-T.** R-1 breaks a fifth setting: J `JIRA_TRANSITION_REOPEN` (tried on the calibration ticket, reads only, every write blocked, since Jira offers transitions per issue), A `AZDO_STATE_REOPEN` (refused at run start). Every Jira reopen refusal now names `JIRA_TRANSITION_REOPEN` | `prove_live_runner_offline` asserts all five J breaks REFUSED (named), zero writes. **Failed first:** the transition break did not exist | DONE-PROVEN-LOCAL (offline); live 4/4 | Live R-1 re-run on the personal Jira (5/5) | S | VERIFIED |
| T-25 tier −1 instances | TB §2; J-8 | threshold defaults to 0 | stub J-8 | BLOCKED-ON-OWNER (O-16) | Threshold, then live | S | VERIFIED |
| T-26 three tiers | WIH | Epic is the parent of tier 0 | stub J-2, A-1; live J create | DONE-PROVEN-LIVE (J) | — | — | VERIFIED |
| T-27 SLA in ticketing | WIH "SLA clock on the instance" | `remediation_sla.py` has no runtime consumer; the reconciler has no deadline or breach logic | `prove_remediation_sla` (library) | NOT BUILT | With L47 (Release 2) | M | VERIFIED |
| T-28 Azure DevOps live | KDEC-004 | backend built; stubs only (RV:389–390) | stubs | BLOCKED-ON-OWNER (O-19) | The owner moves the personal project to the inherited process; then R-1 and R-2 | S | VERIFIED |
| T-29 GitHub Issues stamp in an issue field; L58 experiment | TC §3.2, §11.3 | body stamp only; experiment not run | — | NOT BUILT (frozen by KDEC-004) | Only if G is extended | S | VERIFIED |
| K-03 KDEC-013 the work-item reference gate is core, with no default range (added 2026-10-22, L-FWA) | KDEC-013; FW §13 ("must ship with enforcement OFF and no default range") | `reusable-ticket-reference.yml`: `min_digits` and `max_digits` optional, both or neither (:61, :106), no range by default; a consumer's range lives only in its overlay caller | `prove_ticket_reference_gate` (run by self-test:999, on the shipped step) | DONE-PROVEN-LOCAL | A hosted pull-request run on the Level 2 consumer with a range, and one without | S | VERIFIED |
| TKT-WORK Jira only at work; Azure DevOps out of scope for work (added 2026-10-22, L-FWA) | owner 2026-10-22 (relayed by the coordinator); KDEC-004 | KDEC-004 still names Azure DevOps the second backend for the same contract. Backend A is built and stub-proven (T-28). Nothing in the tree records that the work instantiation uses Jira only | — | BLOCKED-ON-OWNER (O-25) | Record the ruling as a KDEC entry (lane L-G). For the work instantiation the tracker is Jira only, and the overlay configures only J. Then decide whether A stays a neutral-kit backend proven on the personal organisation (T-28 becomes optional, not a release blocker) or is frozen like G | S | READ |

### 2F · Build, provenance, deploy, rollback, landing-zone hand-off

| id | designed | built? | proven how | state | what closes it | size | label |
|---|---|---|---|---|---|---|---|
| L85 build once | PROV §2.1 | `reusable-build-docker.yml:326–611`; the composite builds once; a Trivy failure routes BLOCKED | `prove_build_routing`, `prove_build_push_round_trip`; live 38857011286, 38857017667, 38857024014 (RV:299–313) | DONE-PROVEN-LIVE | — | — | VERIFIED |
| L86 build inputs | PROV §9 step 1 | build-docker 393–463 | `prove_build_inputs_recorded` | DONE-PROVEN-LOCAL | Hosted build record | S | VERIFIED |
| P-01 / L87 template stamp and branching | PROV §9 steps 2–3 | TPL:88–177. **TPL:195 hard-codes `environment_tier: prod`; TPL:196 passes the SECURITY verdict, not the combined `needs.verdict` verdict; TPL reads un-prefixed resource-group, container-app and registry variables, not the contract's `KIT_*` names; one environment ("production") for build and deploy; the kit is pinned `@v1`** | `prove_template_branches_on_verdict` | PARTIAL (defect) | Pass `needs.verdict.outputs.routing_result`; `vars.KIT_ENVIRONMENT_TIER`; contract names; separate build and deploy identities and environments; pin by SHA; one hosted TPL run | S | VERIFIED |
| L88 attest job | PROV §8.2 | build-docker 908–957, job-level `attestations: write`; signs only a REGISTRY_IDENTITY_PROVEN digest | `prove_attest_job_isolated`; never signed | BLOCKED-ON-OWNER (O-20, plan) | A hosted run on a public repository or Enterprise Cloud | S | VERIFIED |
| P-02 / L89 V1 verify | PROV §6.1–6.4 | `verify-attestation` (5 outcomes; the plan-held outcome gives PROCEED_WITH_ADVISORY). **Called only from TPL:106–116, not inside the deploy reusables**, so a direct caller bypasses it | `prove_attestation_verify`; deferral `attestation-verify` (RV:575–585) | BLOCKED-ON-OWNER (O-20) | Move V1 into both deploy reusables before login (section 5, B-05); live on a public repository | S-M | VERIFIED |
| P-03 / L90 V3 revalidation | PROV §6.1 V3, §9 step 6 | none; NVD rescans a caller-supplied SBOM or image, never the running digest; `nvd-cve.yml` deliberately unscheduled | — | NOT BUILT (design owed) | Design V3: read the running revision or start record, compare to the release digest, re-verify | M | VERIFIED |
| L91 NVD honesty | NVD | fixed (`OUTDIR` defined) | `prove_nvd_workflow_honest` | DONE-PROVEN-LOCAL | Hosted keyed run | S | VERIFIED |
| L92 stamp | PROV §2.2 | `render-version-metadata`, called by TPL:169–177 | `prove_stamp_consistency`; `version-metadata-wired` observed (tool) | DONE-PROVEN-LOCAL | Hosted TPL run | S | VERIFIED |
| L93 deploy reads the verdict | SPT §5.2 | APP:1932–1972, CA:1914–1954; PROCEED and PROCEED_WITH_ADVISORY pass; everything else refuses before login | `prove_deploy_gate`; live 38853176286 (RV:319). **The live verdict was a typed dispatch input, not a gate output** | DONE-PROVEN-LIVE (deploy side) | A hosted gate → deploy chain (S-15) | S | VERIFIED |
| K-01 KDEC-014 | owner ruling | **Lane L-A (2026-10-22):** the gate half is proven by cause (`prove_gate_routing` cause_* scenarios: VERSION_GAP, VERSION_GAP_UNVERIFIED, COVERAGE_PARTIAL, all causes sorted, none on PROCEED), and the environment-reviewer half of the exception is now READ BACK by both deploys (`prove_deploy_environment_protection`). Earlier text: Not built (section 1). The deploy has a tier input (APP:56–62; DC:300–336) used only for direct-to-production and rollback capability; the gate emits no advisory cause | — | NOT BUILT (separate lane, empty) | The gate emits the cause(s) of an advisory; deploy refuses a version-gap-only advisory at uat/prod unless an attributed, unexpired exception reference is supplied (reusing the weakening fields: reason, authority, exception ref, expiry); extend `prove_deploy_gate` test-first. Ship it with V-02 for checkov and trivy-config, or every IaC repository needs an exception on day one (O-01) | M | VERIFIED |
| K-02 KDEC-015 | owner ruling | not recorded; the contract says "per application" | — | NOT BUILT | Record it; contract "per tool"; list the supported hosting types | S | VERIFIED |
| L97 previous state (3 values) | DCR §3.2 | DC:227–296 | EXISTING_DEPLOYMENT live; UNKNOWN and EMPTY stub (`prove_deploy_outcome` gap4) | DONE-PROVEN-LOCAL (UNKNOWN, EMPTY); live (EXISTING) | Induce UNKNOWN and EMPTY live | S | VERIFIED |
| DCR-9 rollback capability before the point of no return | DCR §3.5, §5.9 | DC:303–342 (UNAVAILABLE at uat/prod refuses); `policy_mode` not consumed | gap9 stub; computed in every live run, never refused live | DONE-PROVEN-LOCAL | One live prod-tier run against a single-revision app | S | VERIFIED |
| DCR-1 direct-to-production | DCR §5.1 | APP:1974–1993, 2095–2109; DC:1081–1108 | `prove_deploy_direct_to_production`; live 38853184615, 38878189985 | DONE-PROVEN-LIVE | — | — | VERIFIED |
| DCR-2 ATTEMPTED vs NOW SERVING | DCR §3.4 | DC:159–223, 1249–1312. **App Service judges NOW SERVING by the CONFIGURED image** (`appservice_slot_image('production')`, DC:701; also DC:1148–1149, 1054, 1005–1020); the platform start record is reported beside it and decides nothing (RV:371–372); after a swap production's start is never re-read | live (defect 95bd5cc from 38879879589) | PARTIAL (design caveat) | Section 5, B-02 | S-M | VERIFIED |
| DCR-3 provenance after health | DCR §5.3 | APP:2083–2093; DC:1038–1078 | gap3 stub; live-deploy-acceptance never passes `version_metadata`, so the stamp step never ran live | DONE-PROVEN-LOCAL | One live run with `version_metadata` | S | VERIFIED |
| DCR-4 read failure is not "empty" | DCR §5.4 | DC:227–237 | gap4 stub | DONE-PROVEN-LOCAL | Live UNKNOWN (deny Reader temporarily) | S | VERIFIED |
| DCR-5 rollback to empty | DCR §5.5 | DC:928, 864–868, 905–906 | gap5 stub | DONE-PROVEN-LOCAL | Live first deploy into a vended empty target, made unhealthy | S | VERIFIED |
| DCR-6 snapshot and manifest | DCR §5.6; RC §1–2 | DC:367–482, written before the mutation | every live run | DONE-PROVEN-LIVE | — | — | VERIFIED |
| DCR-7 reversal verified against live state | DCR §5.7 | DC:917–1020 | 38855747496, 38858033863, 38878189985; partial 38886279650, 38855929525 (RV:319–374) | DONE-PROVEN-LIVE | — | — | VERIFIED |
| DCR-8 PARTIAL_APPLY / STATUS_UNTRUSTED (matrix B, D) | DCR §5.8 | DC:1112–1157 | gap8 stub; "B and D not induced live" (RV:340–341) | DONE-PROVEN-LOCAL | Cancel mid-mutation, and revoke a read after the mutation, live | S | VERIFIED |
| DCR-10 push as the point of no return | DCR §5.10 | reusable build-docker 493–611; **the docker-build-push composite has no push-capability step** | `prove_push_capability`; live build runs | PARTIAL (composite) | Add the step to the composite, or retire it | S | VERIFIED |
| DCR-11 promotion distinct from deploy | DCR §5.11, §7.7 | DC:1165–1187: the report can never read "verified" (three conditions have no source; artefact identity is never credited, although the build proves it) | gap11 stub | BLOCKED-ON-OWNER (O-11) | Owner defines functional, operational and dependency evidence per tier; pass `artifact_identity` into deploy | M-L | VERIFIED |
| L96 six-question report and escalation | DCR §3.4, §8.4 | DC:1190–1245, 1270–1305; channel and service level are placeholders | live shape | BLOCKED-ON-OWNER (O-11, routing) | Owner, channel and service-level policy | S | VERIFIED |
| L98 P1–P6 per-object dispositions | DCR §8; RC | `derive_reversal_disposition.py` and DC:723–914. **App Service declares P3, P5 and P6 empty (DC:890–894) because "the concurrency group serialises"**, which holds only within one repository | `prove_reversal_disposition`; live P4 38886279650, P6 38855929525 | PARTIAL | Read P3 live from the stamp, or a platform-side lease (section 5, B-12); release graph for P5 (DCR §8.7) | L | VERIFIED |
| DCR-OWN ownership stamp | DCR §8.3 | CA: a revision environment variable set by the update; AS: a resource tag set before the image. Tags do not move with a swap; the reversal reads the target slot's stamp | live via the second-actor runs | PARTIAL (App Service swap) | Stamp production at swap time | S | VERIFIED code, INFERRED swap |
| DCR-PART ROLLBACK_PARTIAL and second-actor refusal | DCR §8.2, §8.5 | DC:944–958 | 38886279650, 38855929525 | DONE-PROVEN-LIVE | — | — | VERIFIED |
| RB-SEQ sequential rollback, e2e tests between steps (added 2026-10-22, lane L-RB) | KDEC-019 item 4; RC "Sequential rollback" | `scripts/rollback_sequence.py`, `reusable-rollback-sequence.yml`, `templates/rollback-sequence.yml`, `schemas/rollback-sequence.schema.json`: deploy runs reversed newest first; per step a fresh-read eligibility (`ELIGIBLE_UNTOUCHED`; `ELIGIBLE_OWNED_PART_SEPARABLE` on Container Apps only), the deploy contract's own reversal (only `ROLLBACK_VERIFIED` counts), the health probe, the caller's `e2e_test_command` (bounded, without the deploy identity's session); halts by name; no e2e command refused before login; registered `rollback_sequence`, `rollback_sequence_step`, `rollback_step_eligibility` | `prove_rollback_sequence` S1..S12 against the stub cloud with evidence from the shipped deploy reusables (failed first: the engine did not exist); KDEC-021 (2026-10-23, lane L-RB2): a test period after every step (`e2e_test_period_minutes`, default 15, 0 refused `ROLLBACK_SEQUENCE_REFUSED_NO_TEST_PERIOD`), App Service slots restored to the requested `target_version` and read back live (slot `prior_stamp` restored by the deploy contract), one shared concurrency group per target across the deploy and rollback reusables, a kit deploy landing mid-sequence rolled back first -- S13..S19 (failed first: unknown flags, separate groups, stacked App Service stopped on the slot stamp) | DONE-PROVEN-LOCAL | A live run on the sandbox (deferral `rollback-sequence-live`, 2026-12-31); App Service shared-slot separability (its reversal verifies every captured slot); the shared group is proven by expression resolution, not a hosted queue; one target's lock per sequence | L | VERIFIED |
| L94 RC promotion gate (8 boxes) | RC:210–249; FW §7 item 1 | 7 of 8 hold. Unticked: ROLLBACK_REQUIRES_HUMAN_DECISION is never emitted (it is replaced by refusing before the mutation plus STATUS_UNTRUSTED). The RC header (:4–6) "not proven live" is stale | live for 6; harness local | BLOCKED-ON-OWNER (O-10) | Accept the substitution with a note, or emit it as well | S | VERIFIED |
| DCR-GATE2 "DCR closes gate 2" | RC:186–208; DCR:13; FW §7 item 2 | DCR claims closure; RC:190–193 says "not yet recovered" | — | BLOCKED-ON-OWNER (O-09) | Ruling, then align the RC text | S | READ |
| DCR-MATRIX acceptance A–E | DCR §7.8 | — | A live (38855599716, 38857259257, 38857271571, 38912063363); C live (38855747496, 38858033863, 38878189985, 38912546778); B and D stub; E not built | PARTIAL | B, D and EMPTY live; E needs a release graph | M (E: L) | VERIFIED |
| DCR-§2.2 security posture after reversal | DCR §2.2 | the snapshot excludes settings, ingress and identity | — | NOT BUILT (by scope) | Assert it, or rule it out while the run changes none of it | M | VERIFIED |
| DCR-§2.4 plan preview, blast radius, layered readiness | DCR §2.4, §3.1 | none | — | NOT BUILT | what-if per adapter; per-mutation gates | L | VERIFIED |
| L99 serialised per target, never cancelled | RC:119–137 | APP:208–210, CA:191–193, keyed on the app | `prove_deploy_concurrency` | DONE-PROVEN-LOCAL (per repository only; see L98) | — | S | VERIFIED |
| FW-§10-M a bound for mutating jobs, designed against the rollback contract (added 2026-10-22, L-FWA) | FW §10 ("Mutating pipelines need their own semantics") | Neither deploy reusable sets `timeout-minutes`, so they run to GitHub's 6-hour job limit; `reusable-build-docker.yml` bounds one job (:915, 10 min). A cancelled mutation is handled (DCR-8: STATUS_UNTRUSTED); a kill at the job limit mid-mutation has no designed outcome | DCR-8 stub only | NOT BUILT (deferred by design: FW §10) | Design the bound against RC first (the change manifest at the moment of the kill, and what may be reversed from it), then one bound per mutating job routed to that outcome, with a mocked-sleeper proof. Lane L-D | M | VERIFIED |
| L100 digest-only, input via env | PROV §7 | APP:1995–2002, 231–252 | `prove_deploy_inputs_via_env`; live | DONE-PROVEN-LIVE | — | — | VERIFIED |
| L101 health establishes the intended artefact | DCR §3.1 | CA reads the revision back (DC:578–589); AS reads the start log before the probe (DC:530–634); after a swap, AS reads the configured image only | live (6ee04c3 from 38857408542; 6e40dad from 38867771912) | PARTIAL (after swap) | Section 5, B-02 | S-M | VERIFIED |
| L102 harness teardown | RC:167–184 | `tests/harness/teardown_scope.py`, in no reusable (correct) | `prove_harness_teardown` (stub); the sandbox slot was deleted by hand (RV:370) | DONE-PROVEN-LOCAL | One live zero-before and zero-after run on the sandbox group | S | VERIFIED |
| L103 boundary proven by denial | TM T-09; LZ:61–64 | `verify-azure-oidc.yml`. **An UNAVAILABLE calibration probe leaves the verdict PASS** (:717–735, :808); the subscription scope is printed in the assertions output (:774) | live 38832628162, 38832634828, 38850408850 (RV:142–163) | PARTIAL | Fail on calibration UNAVAILABLE; hash the scope | S | VERIFIED code, INFERRED output drop |
| LZ-1 what the kit consumes vs the contract | LZ:21–39 | Reusables take `AZURE_*` as `secrets:`; TPL diverges (P-01); `KIT_ENVIRONMENT_TIER` and `KIT_CLOUD` are not consumed by the template | none | PARTIAL | Align TPL to the contract | S | VERIFIED |
| LZ-2 deploy identity minimum roles | LZ:44–64; KDEC-009 owed | Roles are stated, not run. The roles the live test identity held are recorded nowhere in the tree. The Kudu log read (DC:546) and `az tag update` (DC:442, 1070) may need more than Website Contributor | none | BLOCKED-ON-OWNER (O-08) | One live matrix run under exactly the contract roles, plus the boundary probe for that identity | S | READ, INFERRED |
| LZ-3 open items 1–4 | LZ:75–84 | — | — | BLOCKED-ON-OWNER (O-08) | Section 6 | S | READ |
| C-01 smart Dependabot auto-merge | FUTURE_WORK §6; owner 2026-10-22 | **Built in lane L-DB.** `.github/workflows/reusable-dependabot-triage.yml` (pull_request_target caller, nothing checked out, `permissions: {}` and per-job scopes; fetch-metadata pinned by SHA) and `templates/dependabot-triage.yml`. Auto-merge is `gh pr merge --auto --squash` only when every §6 criterion the kit can establish holds; otherwise label + comment + review request, or close for an excluded path. Criterion map: `docs/adoption/DEPENDABOT_TRIAGE.md` §1. **Not enforced:** provenance/signature of the new version (recorded `not_established`). **Delegated** to the security gate as a REQUIRED check named in `required_checks`: no new critical/high, no malicious package | `prove_dependabot_triage` (D1..D8: 42 decisions through the shipped evidence and decision steps, the action steps against a gh shim, injection). **Failed first:** no workflow, then no template. Wired in self-test. No hosted run | PARTIAL (decision DONE-PROVEN-LOCAL; provenance NOT BUILT; GitHub half owed) | The hosted plan in DEPENDABOT_TRIAGE.md §6 on the owner's public test repository (closes deferral `dependabot-merge-hosted`); a provenance step that reads registry signatures without executing the package | M | VERIFIED (local), INFERRED (check-name format) |
| TM T-07, T-08, T-13, T-14 | TM §2 | The TM says DESIGNED; the code is built and live for T-07, T-13 and T-14; T-08 attest is built and unsigned | rows above | PARTIAL (document stale) | Refresh the TM states (D-01) | S | VERIFIED |

### 2G · Document currency (stale truth), one row

| id | designed | built? | proven how | state | what closes it | size | label |
|---|---|---|---|---|---|---|---|
| D-01 the documents agree with the registry | `check_doc_currency` | **Stale against the code or the registry at 53d2962** (VERIFIED unless marked READ): START-HERE:23 ("advisory suppresses the secret gate", fixed at `09f073e`) and :55 ("deploy never executed"); `adoption/USAGE.md:97` (advisory covers secret scanning); PSD (2026-10-05: deploy never ran, version discovery absent); KNOWN_DEFECTS D-5 (fixed) and D-6 (closed); KNOWN_GAPS §1 and §5; CAPABILITY_MATRIX status block and authorization-boundary "unknown"; TEST_COVERAGE_AUDIT "honest status"; FUTURE_WORK §1, §5, §7; VALIDATION_DEBT U1–U4, nvd section; RC header and gate-2 text; DCR §8.7; PROV header ("nothing built"); TM state table; ETFB header and §5.8; RUNG header; AXES "no tier concept"; POLICY.md:50 (points to a missing note); PO §8 ("landing zone in neither repository"); TC:21–24 and TB "today's code" lines; `RT:119–128` environment list omits Azure DevOps; explainer 07 ("never dispatched against Azure") and 11 §6 ("stub cloud only", "live ticketing pending"); `.context` risks R-04 and continuation open-decision list; FW:7565–7567 comment. WIH:32, 70 and one `.context` line name a real tracker project key (a neutrality defect, READ) | `check_doc_currency` passes (it checks one direction only) | PARTIAL | One documentation lane (L-G); then section 5, B-11 so it cannot recur | M | VERIFIED |

---

## 3 · Counts

There are 205 rows above, one per designed capability or clause. The counts were made by a script that
reads the state column. When a row has a mixed state, it is counted under its first state.
(Recounted 2026-10-22 by lane L-DB when it added C-01; the previous table, 202 rows, had not followed
the rows and states later lanes changed.)

| state | rows |
|---|---|
| DONE-PROVEN-LIVE | 19 |
| DONE-PROVEN-LOCAL | 62 |
| BUILT-UNPROVEN | 5 |
| PARTIAL | 64 |
| NOT BUILT | 31 |
| BLOCKED-ON-OWNER | 22 |
| UNKNOWN (not re-checked) | 2 |

A row marked DONE-PROVEN-LIVE (J) counts as live for Jira only. Azure DevOps is blocked on the owner
(T-28). INFERRED counts are not separated out; the label column carries them.

So 81 of 205 rows (40%) are done and proven: 19 live and 62 locally. 124 rows are not.

**Rows added after this audit (2026-10-22, lane L-FWA, from `docs/assurance/FUTURE_WORK_TRACEABILITY.md`).**
The counts above are the audit's at `53d2962` and do not include them. Fifteen rows were added:
FW-§4, FW-§3a, FW-§3b, AX-TEAM, AX-CRAWL, POL-SCOPE, FW-§2, FW-§12, FW-§8a, FW-§8b, FW-§8c, FW-§6b,
K-03, TKT-WORK and FW-§10-M. One is DONE-PROVEN-LOCAL (K-03), one BUILT-UNPROVEN (FW-§8b), two
PARTIAL (AX-TEAM, FW-§8c), seven NOT BUILT, and four BLOCKED-ON-OWNER (three new decisions, O-24 to
O-26, and O-14). Lane L-DB adds the FW §6 auto-merge row separately.

**What "complete" means here.** Every row is DONE-PROVEN-LIVE or DONE-PROVEN-LOCAL, or carries an owner
ruling that makes it out of scope. Proof is required at the strongest level the design asks for: hosted
where the design names a platform behaviour, live where it names a cloud or tracker. The flagship is
re-proven end to end on the commit that closes the last lane. That is the requirements-ledger rule: not
"ready" until every hard requirement is built.

---

## 4 · Build order: lanes to completion

**Collision rules.**

- **Owner files.** Each lane owns the files listed for it. Two files are shared, and changes to them merge
  through one coordinator in the order shown: the flagship `reusable-security.yml` and
  `templates/security.yml`.
- **Flagship budget.** At 453,297 B the flagship has 33,103 B to the 486,400 B fail line. The lanes that
  add bytes are L-A (rung patch, about 7 KB) and L-C (sidecars). L-B (composites) removes bytes first.
- **Size gate.** Measure with `check_workflow_size.py` before each merge.
- **Method (unchanged).**
  1. Write a test that FAILS on the old code for the named reason.
  2. Fix.
  3. The same test PASSES.
  4. Wire it into self-test.
  5. Run the CP-018 battery before any push.

**Wave 1 — independent; run in parallel now.**

| lane | owns (files) | closes | closing proof |
|---|---|---|---|
| **L-T ticketing correctness** | `scripts/reconcile_tickets.py`, `scripts/ticket_model.py`, `.github/workflows/reusable-ticket-reconcile.yml`, `tests/prove_ticket_*.py`, `tests/live_ticketing_run.py` | **T-02 (description erasure, first)**, T-08, T-21, T-24, T-06, T-13 (delta), G-02 (registry level, coordinated with L-G) | A new proof where human text outside the block survives a members-added update, failing today, on stub J and A; then a live re-run on the personal Jira of T-2 with human text present |
| **L-D deploy, release, template, hand-off** (merges after lane/kdec-014's deploy half, or absorbs it) | `reusable-deploy-appservice.yml`, `reusable-deploy-containerapp.yml`, `scripts/deploy_contract.py`, `scripts/derive_reversal_disposition.py`, `scripts/inline_deploy_scripts.py`, `templates/build-deploy.yml`, `.github/actions/verify-attestation/`, `.github/actions/docker-build-push/`, `live-deploy-acceptance.yml`, `tests/prove_deploy_*.py` | **K-01 deploy half** (refuse a version-gap-only advisory at uat/prod without an attributed exception), P-01 (template verdict, tier, names, identities, SHA pin), P-02 (V1 inside the deploy reusables), DCR-2 / L101 (NOW SERVING from the running artefact, B-02), DCR-OWN (stamp at swap), DCR-10 composite, L94 (O-10), DCR-3, 4, 5, 8 and 9 live, DCR-MATRIX B, D, EMPTY | `prove_deploy_gate` extended (fails today on advisory at prod); live runs on the sandbox for B, D, EMPTY, UNKNOWN, a prod-tier capability refusal and a stamped provenance write; one hosted TPL run (scan → verdict → build → deploy) |
| **L-F ledger and lineage** | `.github/workflows/reusable-propose-ledger.yml`, `.github/actions/propose-ledger/`, `scripts/propose_ledger.py`, `scripts/finding_lineage.py`, `scripts/rule_family.py`, `scripts/baseline_ledger.py`, `tests/prove_propose_ledger*.py`, `tests/prove_lineage_*.py` | **F-01 establishment path**, L51 (one move record), L46 (generation-check job), T-20 (accept the ticket-ledger proposal into the same PR), ETFB-§8.8 rule 4 header | A proof that the shipped reusable establishes a ledger when the approver role is given and refuses without it (fails today); one hosted establish-then-propose run on the Level 2 consumer |
| **L-E self-assurance hygiene** | `tests/reconcile_validation.py` (orphan, levels), `tests/check_selftest_coverage.py`, `tests/check_stage_phase.py`, `tests/check_workflow_size.py`, `tests/check_doc_currency.py`, `.github/workflows/self-test.yml` (proof wiring only), `.github/workflows/validate-scanners.yml`, `.github/workflows/workflow-policy-check.yml`, `developer-safety/`, `scripts/export-deny.txt`, `scripts/inline_normalizer.py` | G-01, G-02 (with L-T), G-03 / L72 (wire eight proofs), G-07 / L78, L66, L70, L76, L83, L104, L106 (line 51), L61, L81 / B-11 | Each checker gets a seeded failing case first; self-test green on the trunk |

**Wave 2 — the flagship.** These lanes are serialised through the coordinator. Each touches
`reusable-security.yml` in a distinct region.

| lane | owns | closes | closing proof |
|---|---|---|---|
| **L-B decomposition first (frees bytes)** | `.github/actions/<scanner>/` composites; flagship scanner job bodies; `scripts/inline_normalizer.py` (after L-E) | L64 (sast-cpp and secret-scan first; then retire `kit-scripts`, OD-8), the FW:375–379 contradiction | `check_scanner_registry`, the consumer path 20/20 on the lane's merge commit |
| **L-C scan validity and version fitness** | `.github/actions/resolve/`, `scanner-registry.yaml`, `scripts/sarif_validity.py`, `scripts/scan_report.py` (`examination_of` only), flagship scanner jobs (after L-B), `tests/test_resolve.py`, a new corpus probe workflow | **L01**, D-10, L34, L35, L03 (semgrep single version plus `--strict` first), V-01, **V-02 D-VF-4 corpora (checkov and trivy-config first, because K-01 needs them)**, V-03, V-04 (O-07), V-05, L14, L25, L09, L10, L11, L84, L18 | `scan_report` self-test flipped (fails today); `test_resolve` platform rows; a corpus probe writing READ ranges; a hosted run showing a VERSION_GAP and a SUBSTITUTION |
| **L-A gate and policy** (status 2026-10-22 in the block below the table) | flagship `security-gate` and posture region, `.github/actions/resolve-policy/` (new), `scripts/rung_ladder.py`, `scripts/policy_registration.py`, `scripts/enforcement_axes.py`, `templates/policy-registration.example.json`, `tests/prove_gate_*.py` | **K-01 gate half** (emit the advisory causes), S-01 / L32 / L33 / ETFB-§2.2 / ETFB-§3 (apply `wiring/gate-rung.patch.md` with a shipped registration), L44 acting half, L36 run record, L31 comment, S-05 once EP-1 is decided | `prove_gate_reads_rung` 0 failures (it fails today); `prove_gate_routing` extended with version-gap causes |

**Lane L-A status (2026-10-22, local proof only; Actions minutes blocked).** The rows lane L-FWA
added (`7b4fea1`) are updated in place since the trunk merge; in summary:
**AX-CRAWL** DONE-PROVEN-LOCAL: owner ruling O-24 recorded and built (crawl blocks on a found secret
and on the kit being unable to run or trust its own scan -- EVIDENCE_UNTRUSTED at every tier;
findings and coverage gaps advisory with registered causes; `prove_gate_policy_enforcement`).
**POL-SCOPE** DONE-PROVEN-LOCAL: the policy register (org, team, product, repository, tier; stated
precedence; conflicts, unattributed and expired decisions refused by name; strict schema with a
version field; `prove_policy_registration`). It departs from the row's recommendation in one place:
a more specific scope MAY soften what it inherits, as an attributed decision (owner 2026-10-22),
except the repository's own file, which may only tighten. **AX-TEAM** PARTIAL: `team_pattern`
resolves per scope and the gate reports the unvalidated human-workflow paths; deploy approval
(approver groups, self-review prevented, AI review advisory) is expressed per scope and read back by
the deploy; nothing yet derives branch-protection profiles or auto-merge eligibility from the
pattern. **FW-§3a** NOT BUILT (untouched by L-A; needs L48 first).
L36 DONE-PROVEN-LOCAL (row above; artifact upload owed). Lane L-P85 follow-ups (merged into L-A):
the posture summary words a PARTIAL by its cause (a version gap, or a scanner that read the version
but not every file), and a softened finding beside a PHP parse gap carries both
FINDINGS_NOT_BLOCKED and COVERAGE_PARTIAL (`prove_gate_policy_enforcement` crawl_parse_partial_*). Not done by L-A: L44 acting half (the gate reads a job's findings at
`new_critical_high`, the strictest non-secret class, so the missing per-finding class can only make
it stricter), S-05 (EP-1 undecided), the scanner half of the derived policy.

**Wave 3 — after waves 1–2 merge.**

| lane | owns | closes | closing proof |
|---|---|---|---|
| **L-W wiring the post-scan phase** | `templates/security.yml`, `templates/build-deploy.yml` (after L-D) | S-§2.4 / L67, T-17 (schedule), T-19 (template caller), F-01 template job | One hosted merge run on the Level 2 consumer: scan → gate → propose-ledger → ticket-reconcile (armed, personal Jira), each with a run id in the registry |
| **L-R Release 2** (dated per KDEC-007, made visible first: B-10) | `scripts/remediation_sla.py`, ledger severity and SLA fields, the reconciler's SLA read, the packing workflow, the V3 design | L47, T-27, ETFB-§5.6, ETFB-§8.1, L65 (OD-3), P-03 (V3), D7 currency (L23), L105, OVL-C | Per design: `prove_remediation_sla` wired; a measured before/after for packing |
| **L-G documentation** (may run any time; final pass last) | `docs/**` (not this file), `.context/products/secure-cicd-kit/*` | D-01, K-02 record (with owner), the neutrality defect in WIH | `check_doc_currency` with the claims list from L-E; `check_export_safety` |
| **L-H pinning sweep** (last: it touches every workflow) | every `uses:` line | L82 (flip dogfood before the 2026-10-31 expiry of its weakening), L84 remainder | `pin-actions.sh --apply` with a token; self-test with `require_sha_pinning: true`, `soft_fail: false` |
| **L-Z hosted closure** | none (dispatches only) | S-06 / L26 / L30 / L41 on the current trunk; OVL-A one dispatch; L80 (T-03 refusal); L39 re-run observation; PO §4.6/§8 experiments; T-28 Azure DevOps live (after O-19); L88/P-02 live on a public repository (after O-20) | Run ids written into `tests/reconcile_validation.py` and the stage register |

---

## 5 · Better-design candidates (proposals only — no code)

| # | current design | proposal | trade-off | label |
|---|---|---|---|---|
| B-01 | **The flagship size line.** A byte fail line (486,400 B) on one file. The file is 453,297 B; comment-only lines are about 183.7 KB (40%); `kit-scripts` carries about 53 KB of generated copies. GitHub also refuses an expression template over 21,000 characters, a second limit the byte line does not see | Keep the byte gate as a backstop, and add a **structural rule** checked beside `check_scanner_registry`: the flagship holds orchestration only (job shells, `if:`, `needs:`, permissions, outputs); any `run:` body over N lines lives in a `$/` composite. Finish E(b) and delete `kit-scripts` (`$/` already delivers the whole repository; runs 38434823833, 38468728084) | More indirection when reading; more pin surface (covered by L62); the composite size limit is undocumented, so widen the size gate to composites (L66). Gives up GHES (OD-8), which `$/` has already done in practice | VERIFIED (sizes), INFERRED (benefit) |
| B-02 | **"NOW SERVING" reads the configured image** on App Service (DC:701; RV:371–372). The container start record is shown but decides nothing, and after a swap production's start is never re-read. Container Apps reads the immutable revision plus traffic, but not replica running or health state | Make the platform start record (when readable) the App Service NOW SERVING verdict, including after a swap; or require an app digest/version endpoint and compare it. For Container Apps add `runningState`/`healthState` | Start-log parsing is fragile and needs SCM read in the deploy identity (interacts with LZ-2 roles); an app endpoint needs app cooperation and can be spoofed by the app | VERIFIED |
| B-03 | **Capability ranges are UNVERIFIED by construction**, and an UNVERIFIED row is never selected (REG:323–328). So every IaC root is a VERSION_GAP, node-quality always is, and go-sast is whenever CodeQL is withdrawn. Under KDEC-014 that makes uat/prod refuse almost every real repository: the "permanently amber" failure PO §4.4.1 warns about, rebuilt one layer up | Treat D-VF-4 as a **prerequisite of KDEC-014**: a scheduled corpus probe per tool above its ceiling writes a READ range with measured version and date. Separate "tool range unknown" from "target version unknown" in the outcome. Also derive the runner toolchain from the discovered target (PO §1.4), which removes most bandit, mypy and dotnet gaps at the source | Corpus maintenance per tool upgrade (it is also D7's regression corpus, so the cost is shared); the caller loses an implicit version pin, which becomes a recorded override | VERIFIED |
| B-04 | **The verdict is a bare token.** `PROCEED_WITH_ADVISORY` cannot say why, so any deployer (kit or landing zone) needs tier logic plus a summary parser to enforce KDEC-014 | The gate emits a typed list of advisory causes beside `routing_result` (VERSION_GAP, an attributed weakening, advisory findings); deploy applies the tier rule to the causes. Long-term, the gate's verdict computation moves to the report/adjudicate position and the gate becomes read-and-exit (SPT §5.1) | One more output on the public interface (a versioned change); moving the computation re-plumbs one output | VERIFIED |
| B-05 | **V1 attestation verification runs only in the template** (TPL:106–116). A direct caller of a deploy reusable — a landing-zone pipeline or a mixed method — bypasses it | Move V1 into both deploy reusables, before login (as PROV §6.1 specifies), keeping the plan-held state advisory | The deploy job needs `attestations: read` and `gh` | VERIFIED |
| B-06 | **Idle CodeQL legs**; six legs gated at step level | `matrix: ${{ fromJSON(discover.outputs.codeql_languages) }}` with an empty-list guard; verdicts stay per-language SARIF, so this is not the rejected matrix-output design | An empty matrix is a hard error and needs its own guard | VERIFIED |
| B-07 | **resolve runs in parallel with the scanners**, so "declared before the scan" holds logically, not in time | Either scanners `needs: resolve` and consume `plan` and `selection` (enables V-01 and EP enforcement), or write "computed independently of the scan's result" into the design | Serial resolve adds one job's latency to every scanner | VERIFIED |
| B-08 | **Two move records**: the ledger's `move_history` and the `finding_lineage` hash chain | One record: propose-ledger appends lineage events (with operator confirmation), or lineage retires for moves | Lineage's integrity guarantees cost a write path in propose-ledger | VERIFIED |
| B-09 | **The rung patch has an adoption cliff**: a missing registration routes to REGISTRATION_UNAVAILABLE, which stops at every tier | Ship a registration in the template and onboarding in the same release; a missing file in a consumer that has never registered reads a documented crawl default for dev and test only | A default is a policy choice the owner must make (O-03) | VERIFIED |
| B-10 | **Release 2 deferrals cannot be registered**: the ratchet (3/3) counts capabilities, not stages, so the rung ladder, SLA, packing, V3 and D7 are dated only in prose | A separate dated Release-2 register (stage, owner role, expiry), printed in the gate's known-gaps table and checked like `DEFERRALS` | One more register to keep honest; it must not become a place where debt hides from the ratchet | VERIFIED |
| B-11 | **Doc currency is checked in one direction** (a document calling an observed capability untested). It missed every stale "never ran" or "nothing built" line in D-01 | A claims list: each stage, deferral and live capability has a predicate in code, and the checker fails on any document line asserting the opposite of a predicate | Maintenance of the claims list; false positives on quoted history unless dated sections are exempt | VERIFIED |
| B-12 | **Serialisation and ownership assume one repository** (`concurrency` is per repository; App Service declares P3, P5 and P6 empty on that basis). Under KDEC-015 and any landing-zone/kit mix, two repositories or deployers can write one target | A platform-side lease (a compare-and-set tag or ETag) per target, and P3 read live from the stamp | Extra calls per deploy; the lease needs a role the deploy identity must hold | VERIFIED |
| B-13 | **Tier is a caller string** (TPL hard-codes `prod`), not bound to the GitHub environment the identity is federated to | The deploy job reads the tier from its own environment's variable and refuses a mismatch with the input | Relies on GitHub environment-variable resolution inside the called workflow | INFERRED |
| B-14 | **Ticket updates use cheap sweeps that omit the body** (the cause of T-02) | GET the description on the update path only, or post a comment rather than rewrite | One extra read per changed ticket (inside the U term of the call budget) | VERIFIED |
| B-15 | **The ticket ledger proposal is orphaned** (T-20) | Feed it into the propose-ledger pull request (one write path). Alternative: treat the tracker's stamp plus predecessor fields as the binding record | The alternative makes the tracker an authority, against TC §3's "the ledger is authoritative" | VERIFIED |
| B-16 | **`test_only_seed_artifact` is on the production interface** (FW:247–260), guarded but present | A kit-internal wrapper workflow carries it | The consumer path would no longer test the shipped interface verbatim | VERIFIED |
| B-17 | **The runner and the report hold two copies of the validity profile** (L01) | One source: the report imports `sarif_validity.PROFILES` | None worth naming | VERIFIED |

---

## 6 · Owner decisions blocking completion

Each decision has a recommended default and the reason for it. The defaults follow the design wherever
the design has one.

| # | decision | blocks | recommended default | why |
|---|---|---|---|---|
| O-01 | KDEC-014 rollout order, and what "a named person accepts it" means mechanically | K-01 | Ship the deploy refusal **together with** D-VF-4 corpora for checkov and trivy-config. The exception is the existing attributed-weakening fields (reason, authority, exception ref, expiry), plus required reviewers on the uat/prod GitHub environment | Without corpora every IaC repository needs an exception on day one, which teaches people to rubber-stamp. The kit cannot verify a person from a string; environment reviewers can |
| O-02 | Record KDEC-015, and its scope | K-02, LZ contract | Record it now; the contract says "per tool"; the kit lists App Service and Container Apps as the release adapters it has, and a tool on any other hosting type is a named gap | Other hosting types have no adapter; silence would imply coverage |
| O-03 | Missing policy registration behaviour when the rung patch lands | S-01, B-09 | Dev and test fall back to a documented crawl default; uat and prod refuse | Avoids blocking every consumer at once while keeping production strict |
| O-04 | Rung table items: tier floors, the non-monotone `pre_existing_on_track` row, crawl cherry-picks, walk → adoption | L32, L33 | Keep the named non-monotone exemption; no tier floors beyond the untrusted-evidence rule; cherry-picks strengthen only; keep walk → adoption | Matches the built library and RUNG doc; floors as written make crawl unregisterable at test |
| O-05 | `symbol_path` in identity | L40 | As built: optional in WHERE, required for a CWE-only WHAT | Removing it collapses CWE-only findings into one identity |
| O-06 | Every placeholder number, and the severity weights | L47, ETFB-§5.6 | SLA 7/30/180/365 days; grace 0/7/14/14; stall 90; no-fix re-check min(30, SLA); promotion 5 clean runs; `severity-formula/1`, provisional; reformat threshold measured before it is set | The day forms of the owner's 1/6/12-month intent; all are configuration, never constants |
| O-07 | A parse-skip by a tool resolve already declared unable to read that root | V-04 | Cap at PARTIAL when the gap was declared for that root; otherwise COLLECTION_FAILED | Otherwise a declared gap escalates to EVIDENCE_UNTRUSTED, against PO §2.4 |
| O-08 | Landing-zone contract open items 1–4, and the deploy identity's roles | LZ-2, LZ-3 | One identity per application (or tool) per environment; the vending also creates the build identity (AcrPush on that repository path); prove roles with one live matrix run under exactly the contract roles plus the boundary probe; infrastructure-like app config lives in the vending | A test identity can never reach prod. Roles are read, not run, and two operations may exceed Website Contributor |
| O-09 | Does DCR close rollback gate 2? | DCR-GATE2 | Yes for the comparison; promotion (DCR-11) stays open under gate 1; fix the RC text | DCR did the difference-by-difference comparison; what remains is implementation |
| O-10 | ROLLBACK_REQUIRES_HUMAN_DECISION never emitted | L94 | Accept the substitution (refuse before mutation; STATUS_UNTRUSTED after) and tick the box with a note | Same safety, different vocabulary |
| O-11 | Promotion evidence (functional, operational, dependencies) and escalation routing | DCR-11, L96 | Define the minimum per tier; for dev and test, artefact identity plus health suffices | Without a source, promotion can never read verified |
| O-12 | `fail_on_cvss` default (11) | S-§4.1 | 9.0 until the rung derives it | An 11 can never block; it is a decorative default at an assurance boundary |
| O-13 | Dependency-Check disable list | NVD-§4.1 | Leave everything enabled, recorded as a decision | Do not restore flags by reflex |
| O-14 | Scope of missing coverage (shellcheck, hadolint, tflint, pip-audit, npm audit, Swift, Kotlin/Android, build-aware C/C++, a workflow scanner) | FW-§5 | Classify each as owed (Release 2), overlay or retired, in one recorded decision | An unclassified gap reads as an oversight |
| O-15 | Merge to `main` (PR #1) | G-04 | From `release/main-candidate` after L-G and L-E; never from the trunk | KDEC-003: the trunk carries overlays and a consumer slug (SPT:931) |
| O-16 | Ticketing numbers: retry ceiling, tier −1 instance threshold, creation ceiling, staleness, degraded-run threshold; whether environment variables are the per-cell record | T-05, T-06, T-23, T-25 | Retry 3; instance threshold 25; creation ceiling 25; accept environment variables as the record | With the shipped 0, the first 429 fails and no instances are itemised |
| O-17 | Tracker closure and dangling references | T-04, T-09 | Closure stays human-only, plus a reported "all members cleared" signal; a calibrated not-found never licenses creation | Fail-safe and simpler; matches what is built |
| O-18 | An armed hosted run of `reusable-ticket-reconcile.yml` on the personal Jira (protected environment, branch policy, variables and secrets) | T-19 | Yes: `apply: false` first, then `apply: true` | It is the only way to prove TC §7 with a run id |
| O-19 | Move the personal Azure DevOps project to the inherited process with the stamp field | T-28 | Do it now | The only blocker to the second backend (KDEC-004) |
| O-20 | Attestation signing and V1 live | L88, P-02 | Arm on the existing public test repository; private repositories stay held to 2026-12-31 | Free on public repositories; closes L88 and V1 with no plan change |
| O-21 | Execution planning EP-1..EP-4 and packing OD-3 | S-05, L65 | EP-1 advisory until one hosted run shows the plan equals what ran, then enforce; EP-2 nightly on the protected branch; OD-3 depth 3 (CodeQL job conditions, report and gate, SCA) | The designs' own defaults; about 57% of the saving with no attribution loss (JT §9.4) |
| O-22 | OD-8 GHES / runner version; OD-9 private unlicensed repositories | L64, L25 | github.com only, runner ≥ 2.336.0, stated as a consumer precondition; the dataflow gap is tolerable as declared, under KDEC-014-style tier rules | `$/` is already load-bearing; a licence requirement would exclude most private repositories |
| O-23 | The dogfood pinning weakening expires 2026-10-31 | L82 | Run the pin sweep (L-H) before then rather than re-date it | Re-dating without a reason is the specific thing the ratchet exists to stop |
| O-24 (added 2026-10-22; DECIDED by the owner 2026-10-22, built by lane L-A) | What "crawl: only secrets block" means: secret findings only, or nothing but secrets at all | AX-CRAWL | RULING: at crawl the gate blocks on a found secret and on the kit being unable to run or trust its own scan (crash, COLLECTION_FAILED, hollow or unreadable scan, bootstrap failure); everything else is advisory with registered causes, and COVERAGE_PARTIAL is advisory, not untrusted. Recommendation was: only secret FINDINGS block at crawl; untrusted evidence, bootstrap failure and KDEC-014's uat/prod refusal still stop the run | A scan that did not run is not a finding; letting it through at crawl would make crawl report a green it never earned |
| O-25 (added 2026-10-22) | Jira only at work; the place of Azure DevOps | TKT-WORK, T-28 | Record it: the work instantiation configures Jira only; Azure DevOps stays a neutral backend, proven on the personal organisation when convenient, and is not a release blocker | Matches the owner's words without discarding a built and stub-proven backend |
| O-26 (added 2026-10-22) | The negative control's shape, and whether the two contract legs share one invocation (FW §12) | FW-§12 | (b): keep it a separate workflow, not independently dispatchable; share an invocation only where every assertion survives | Removes the run-with-no-reader path at no loss of evidence |

---

## 7 · Inputs to the deployment-method comparison (facts only, not the comparison)

The owner wants to compare three methods next: landing zone deploys, kit deploys, and a mix. These are
the facts this ledger establishes that bear on that comparison.

**What the kit's deploy proves today, live.** These runs were on the owner's personal test subscription,
sandbox group, from the trunk, through `live-deploy-acceptance.yml` (RV:299–375). VERIFIED.

- Refusal before login on a non-proceed verdict (38853176286), and refusal of an irreversible deploy at
  prod (38853184615).
- Deploy of the exact digest the kit built and proved in the registry (build 38857011286–38857024014 →
  deploy 38857259257, 38857271571, 38858033863).
- Pre-change capture and a manifest written before the mutation; an unverified revision never takes
  traffic; on App Service the new container's start is observed before health; the slot is health-checked
  before a swap (38912063363 swapped, 38912546778 refused the swap).
- Verified rollback on both adapters (38855747496, 38858033863, 38878189985), and a second actor's change
  refused or deferred, reported ROLLBACK_PARTIAL (38886279650, 38855929525).
- The authorization boundary: own scope reached; sibling and opposite-tier scopes refused;
  subscription-scope write refused (38832628162, 38832634828, 38850408850). Context integrity: a wrong
  tenant refused after a real login (38826929579).

**What it does not yet prove.** VERIFIED.

- A real gate verdict flowing into deploy in one run. Every live deploy got a typed verdict.
- Provenance tags written live.
- EMPTY and UNKNOWN previous state; PARTIAL_APPLY / STATUS_UNTRUSTED live; the capability refusal live.
- Attestation signing and V1; V3 revalidation; harness teardown live.
- That the deploy identity's roles equal the contract's (the live identity's roles are not recorded).
- Any hosting type other than App Service and Container Apps.

**What the landing-zone contract assumes** (`LZ_KIT_HANDOFF_CONTRACT.md`, a draft; READ). Per
application and environment, the vending writes the following into the repository's GitHub environment:

- variables for tenant, subscription and client ids, and for resource group, app, registry, image
  repository, tier and cloud;
- protection rules on uat and prod;
- a federated subject pinned to repository and environment;
- an empty vended target, with AcrPull for the app's own managed identity;
- a deploy identity with Website Contributor or Container Apps Contributor on the app, plus Reader on the
  group, and no registry role;
- a build identity with AcrPush only.

The landing zone never deploys application code; the kit never creates platform objects.

**Where the kit diverges from that contract today.** VERIFIED.

- The template reads different variable names.
- It uses one environment and identity for build and deploy.
- It hard-codes the tier and pins the kit `@v1` (P-01).
- `KIT_ENVIRONMENT_TIER` and `KIT_CLOUD` are not consumed by the template.

**What a landing-zone-side deployer would have to rebuild** to keep the guarantees the kit's release
carries. VERIFIED from the code:

- the verdict gate before login (and, for KDEC-014, the advisory cause — B-04);
- deploy by a registry-proven digest, and the build-once chain;
- V1 attestation verification (today template-only — B-05);
- three-value previous-state capture and capability-before-mutation by tier;
- the change manifest and ownership stamp;
- pre-traffic verification;
- P1–P6 reversal with second-actor refusal;
- the six-question outcome report and escalation contract;
- provenance after health;
- the posture record and evidence artifacts.

The landing zone's plan → approve → apply flow carries none of these for releases. READ from KDEC-009,
VERIFIED in code.

**What a mix changes.** VERIFIED in code; impact INFERRED.

- Serialisation is per repository, and App Service declares P3, P5 and P6 empty on that basis (DC:890–894).
- If two deployers write one target, the kit's reversal reads the other's writes as an external actor
  and refuses (P4), which is safe but turns every such reversal into ROLLBACK_PARTIAL.
- A shared target would need a platform-side lease (B-12).

**KDEC-015 implications** (per tool). VERIFIED for the adapter list; INFERRED for the rest.

- One GitHub environment, federated credential and deploy identity per tool per environment.
- The boundary probe is run per identity.
- A vended empty target and AcrPull per tool.
- A kit adapter per hosting type.
- Shared hosts across tools need the lease.

**Facts that are equal under any method.**

- GitHub has no dynamic secret resolution (SPT §8.4), so per-product × environment identities are
  enumerated at the call site whoever deploys.
- KDEC-014 must be enforced at whichever deploy gate exists, and today no gate emits the cause it needs.
