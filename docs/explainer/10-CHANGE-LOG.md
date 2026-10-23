# 10 · Change log

Newest first. On every later delivery, read this file first: it says which parts changed and why.
Commit ids are on the build trunk `fix/normalization-and-discovery`. Versions 1.10 and earlier are in
`10b-CHANGE-LOG-EARLIER.md`. A reader whose last copy was v1.10 (`a907dc8`) reads
`12-CHANGES-SINCE-A907DC8.md` first: it groups every change since by what an integrator must do.

## Unreleased — rollback test period, requested version, per-target freeze (lane L-RB2, 2026-10-23)

KDEC-021 (owner, 2026-10-23; `a0c93c4`). Proven against the stub cloud (`prove_rollback_sequence.py`
S13..S19, failed first on `19b5e1d`); no hosted or live run. Corrects the L-RB entry below, where the
e2e command ran once per step.

| change | parts affected |
|---|---|
| **A test period after every step, the last included**: `e2e_test_period_minutes` (default 15, 0 < m ≤ 240; 0 → `ROLLBACK_SEQUENCE_REFUSED_NO_TEST_PERIOD`; under 15 a recorded weakening), checks at start, every `e2e_check_interval_minutes`, and end; any failure halts | 07, 09 |
| **App Service back to the requested version**: `target_version` required for App Service steps, checked first; every affected slot read back live after each reversal, swaps included; a non-kit slot change halts for a human | 07 |
| **Deploys frozen per target**: deploys and rollback share `kit-target-<env>-<rg>-<app>`; one target per rollback run; a kit deploy landing mid-sequence is prepended and rolled back first with its own period (more than five halts). Record v2 adds `test_period`, `restored`, `inserted`, `lock`, `final_version` | 07, 09 |

## Unreleased — unmapped orgs run at the enterprise floor; malicious-package scan in the floor (lane L-UO, 2026-10-23)

KDEC-020 (owner, 2026-10-23; `c8b3fc2`, merged `5c1b090`), superseding KDEC-019 item 1, which lane
L-RB built backwards (the L-RB entry below). Proven locally (`prove_authority_floor.py` A1/A11,
`prove_crawl_floor.py` K6/K7, each failed first); no hosted run.

| change | parts affected |
|---|---|
| **An unmapped org runs at the enterprise floor** (the strictest enterprise at each tier when several; tighten-only, `POLICY_BELOW_AUTHORITY_FLOOR` below it), with the notice `ORG_UNMAPPED_RAN_AT_ENTERPRISE_FLOOR` (`policy_notice`; `policy_notices` output, a warning, the gate summary). `ORG_NOT_UNDER_ENTERPRISE` retired, no longer emitted | 03, 05 |
| **`enable_malicious_pkg_scan: false` is refused** below crawl, `CHERRY_PICK_BELOW_FLOOR` (`BLOCKED`), every tier and on pull requests; no longer a recordable weakening | 02, 04, 05 |

## Unreleased — explainer made current at source (lane L-DOC, 2026-10-23)

Every part re-read against the code at `19b5e1d` and KDEC-017..019, then brought to KDEC-020/021 above.
Cost: `validate-scanners.yml` runs on a push only to `main` (M12, failed first on `19b5e1d`).

| change | parts affected |
|---|---|
| secrets: a ticketed one-finding exception is the only way past a found secret; `secret_gate` `EXCEPTED`; cause `SECRET_EXCEPTION_ATTRIBUTED` listed; "nothing below crawl" a principle; the gate, not an enforce step, decides | 00, 01, 03, 04, 06, 09, 11 |
| the rung and register are wired (stage 1, built), not Release 2; deploy refusal follows the rung | 07, 09, 11 |
| actions are SHA-pinned (L82), not by tag; `fail_on_cvss` ships 9.0 (O-12), not 11; counts at `19b5e1d`: 27 inputs, 26 routing and 64 policy scenarios, 12 recorded workflows, 5 deferrals (ratchet 5/5), OIDC exemption to 2026-12-31; `check_stage_phase` runs in self-test | 03, 04, 05, 08, 09 |
| exception resurfacing described in the ticketing part; new proofs listed; KDEC range 001..019 | 06, 08, 11 |
| V1 attestation verification runs inside both deploy reusables (P-02, `ae04403`), not template-only; five outcomes, not four | 07, 09, 11 |
| v1.9 and v1.10 moved to `10b` (size) | 00, 10, 10b |

## Unreleased — unmapped orgs refused; sequential rollback (lane L-RB, 2026-10-22)

KDEC-019 items 1 and 4 (owner, 2026-10-22). Proven locally, each proof failed first; no hosted run.

| change | parts affected |
|---|---|
| **No run outside the enterprise floor**: once the central `orgs` map defines an enterprise, a run in an org it does not name is `ORG_NOT_UNDER_ENTERPRISE` (`BLOCKED`, the org named), at every tier and on pull requests, even if it ran before; no map, nothing changes; `--validate` names every org the register mentions that the map leaves out | 03, 05 |
| **Sequential rollback, tested end to end between steps**: `reusable-rollback-sequence.yml` + `scripts/rollback_sequence.py` + `templates/rollback-sequence.yml` reverse several deploy runs newest first; each step must be eligible from a fresh live read (`ELIGIBLE_UNTOUCHED`, or `ELIGIBLE_OWNED_PART_SEPARABLE` on a shared Container App), `ROLLBACK_VERIFIED` by the deploy contract, healthy, and pass the caller's `e2e_test_command`; anything else stops or halts by name (`ROLLBACK_SEQUENCE_HALTED_E2E_FAILED`, ...) before later steps are touched; no e2e command is `ROLLBACK_SEQUENCE_REFUSED_NO_E2E`; record `schemas/rollback-sequence.schema.json`. Stub cloud only | 07 |

## Unreleased — crawl is the floor; the authority binds; exceptions resurface (lane L-FX, 2026-10-22)

KDEC-018 (owner, 2026-10-22). Proven locally, each proof failed first; no hosted run.

| change | parts affected |
|---|---|
| **Enterprise scope and the authority floor**: the central `orgs` map places each org in an enterprise; precedence kit default < enterprise < org < ... < repository. A narrower entry (org under its enterprise, team, product, repository, a tier beneath its tier-less entry) that leaves anything weaker is `POLICY_BELOW_AUTHORITY_FLOOR` (`BLOCKED`), decision or not; only the authority may soften the kit default deploy approval. Per-finding exceptions are unaffected | 03, 05 |
| **Crawl is absolute**: the secret scan always covers the repository root (`paths` narrowed it below crawl); every weakening input, attributed, still blocks a secret and a scan the kit could not run or trust (`tests/prove_crawl_floor.py`) | 02, 05 |
| **Exception history and the renewal cap**: `renews` (prior grants) on secret exceptions, register decisions and the deploy's version-gap exception (`weakening_renews`); shown as "first exception" or "previously excepted N time(s) since ..." in the gate summary, the run record (`policy_exceptions` new), the deploy summary and `outcome.json`; over `numbers.max_exception_renewals` (central only, default 2, 0..5) → `EXCEPTION_RENEWAL_LIMIT`. New outputs/inputs: security `max_exception_renewals` → deploy `max_exception_renewals` | 03, 05, 07 |
| **Resurfacing**: `scripts/exception_due.py` + `reusable-exception-due.yml` + `templates/exception-due.yml` (weekly): every exception due within 14 days or expired is listed with its history, and raised on its Jira ticket (reopen, comment, or one new issue), saying it was excepted before and is now due; `NOT_CONFIGURED` without Jira credentials; an unreadable register is never "nothing due" | 05, 06 |
| **Ticket keys end where their number ends**: `ticket_reference.py` refuses `WORK-123abc`, `WORK-1234_`, `WORK-0123` (after lane L-W's G10), so a malformed key never excepts a secret | 06 |

## Unreleased — the gate is the single enforcement point (lane `lane/L-S`, 2026-10-22)

Owner ruling O-24 ("only secrets block at this time"). Proven locally; the proof failed first on
`7515088` (every scanner job failed on an ordinary finding at crawl, so the workflow was red and a
caller's `needs: security` skipped build and deploy); no hosted run (Actions minutes blocked).

| change | parts affected |
|---|---|
| **Scanner jobs report, the gate enforces**: each non-secret scanner job hands findings over its threshold to the gate as the job output `findings_state=FINDINGS` and fails only when it could not scan or trust its count; the gate enforces by the resolved policy, so the workflow concludes as its verdict. The secret scan hands its secrets over too (the gate blocks them at every tier unless excepted, below); an image's secrets step and a known-malicious package still fail their own job | 02, 03, 04 |
| **Secret exceptions, one finding each** (owner ruling 2026-10-22: "requested and logged with tickets that have explanations"): a register entry's `secret_exceptions` item names the finding's fingerprint, a `<PROJECT>-<digits>` ticket, an explanation, a named approver, an expiry, and reviewers at uat/prod; anything missing is refused by name (`SECRET_EXCEPTION_NOT_FINDING_SCOPED`, `_UNTICKETED`, `_UNATTRIBUTED`, `_EXPIRED`) and the secret blocks; a class-wide softening stays `CHERRY_PICK_BELOW_FLOOR`. Every secret covered → `PROCEED_WITH_ADVISORY` (`SECRET_EXCEPTION_ATTRIBUTED`), `secret_gate` `EXCEPTED`, logged in the summary and the run record (`secret_exceptions`); the report publishes `secret_findings`; both deploys accept the new cause | 02, 03, 05 |
| **A non-secret job that fails beside findings on record is untrusted** (`EVIDENCE_UNTRUSTED`), no longer "the control fired"; `advisory_mode` no longer softens a crash in the gate step, nor Checkov's `COLLECTION_FAILED` (it passed under advisory_mode at `7515088`) | 03 |
| **ESLint under `bash -e`**: a lint finding no longer ends the step, enforce_lint on or off | 04 |
| **Consumer path**: the full negative asserts the secret scan and the gate fail while Semgrep and Trivy succeed; the PHP-only leg asserts the verdict it records (crawl: `PROCEED_WITH_ADVISORY`, green; above crawl: `BLOCKED`) | 08 |

## Unreleased — the policy register and crawl (lane `lane/L-A`, 2026-10-22)

Owner requirements 2026-10-22 (relayed by the coordinator) and ruling O-24. Proven locally, each
proof failed first on `2cd078e`; no hosted run (Actions minutes blocked).

| change | parts affected |
|---|---|
| **The policy register** (`schema_version 2`): per org, team, product, repository and environment tier, signed off, every entry an attributed decision; precedence kit default < org < team < product < team+product < repository; conflicts, unattributed and expired decisions refused by name; the repository's own file only tightens. `docs/adoption/POLICY_REGISTER.md` | 03, 05, 11 |
| **The gate resolves it first** (`resolve-policy`, rung patch applied): no register = crawl, only secrets block, other findings `PROCEED_WITH_ADVISORY` (`FINDINGS_NOT_BLOCKED`); walk owes a decision, run blocks; new outputs (`policy_resolution`, `rung_*`, `effective_minimum`, `deploy_approval`, ...); input `target_environment`; a `verdict` step | 03, 05 |
| **O-24**: the kit unable to run or trust its own scan blocks at every tier, crawl included; a coverage gap stays advisory | 03 |
| **Deploy reads the environment's reviewers back**: at uat/prod both deploys refuse before login unless required reviewers exist with self-review prevented (and from the named groups); new input `deploy_approval`, output `environment_protection` | 03, 07 |

## Unreleased — Release 3 (next): PHP (lane `lane/L-PHP`, 2026-10-21)

Owner: "I need php and we need it now". Proven locally (each proof failed first on `75d935c`);
hosted runs owed: the consumer path at 24 seeded signals, its `scope=php` negative, self-test, the
corpus probe.

| commit | change | parts affected |
|---|---|---|
| `f880b80` | **PHP a supported ecosystem**: discovery `php` (`*.php`, `composer.json`, `composer.lock`); a `composer.json` without its lock is the named gap `PHPDependenciesUnlocked` (Trivy reads only the lock); PHP target versions in resolve; `p/php` a floor in `sast-semgrep` with a hollow-PHP witness (Semgrep's own `paths.scanned`); a vulnerable Composer lock blocks `deps-scan`; fixture 20 → 24 signals and a PHP-only negative | 02, 04, 08, 09 |
| lane L-PHP, corpus commit | **the PHP range Semgrep reads, MEASURED** on the job's own image by a seeded corpus whose families are `php -l`-checked: 1.90.0 reads 5.6–7.2 (7.3+ syntax is exit 3 under `--strict`); 1.178.0 read 5.6–8.4. Registry row READ 5.6–7.2; weekly probe job | 04, 09 |
| lane L-SG | **one Semgrep release, pinned by digest** (ledger L03; KDEC-016, PHP 8.x required): `sast-semgrep` runs the Semgrep 1.178.0 image by digest, not the 1.90.0 tag; the PHP row re-measured on it, READ 5.6–8.4; validate-scanners probes the same digest and gains a `semgrep-php` probe; self-test pins Semgrep 1.178.0, and the local Semgrep proofs fail if their release is not the job's. A push no longer cancels a dispatched or scheduled run of validate-scanners or the corpus probe. A PHP 8.5 corpus family, MEASURED unread on 1.178.0 and 1.182.0 (`(void)` cast, `final` promotion): the row stays READ 5.6–8.4 and an 8.5 target is a proven VERSION_GAP. Proven locally, each proof failed first on `7fe3d54`; hosted runs owed | 04, 09 |

## Version 1.12 — 2026-10-21 (trunk `078ef90`, lane `lane/L-G2`)

`main` is still `ef4b15d`. The trunk's changes below are proven locally; the trunk owes the consumer-path run.

| commit / run | change | parts affected |
|---|---|---|
| `078ef90` | **KDEC-014, the verdict step always answers**: both deploy reusables write exactly one `version_gap_ruling` on every path their verdict step reaches, the new `VERSION_GAP_NOT_ENGAGED` where no gap rule applied; an EMPTY ruling (the step never answered) routes the deploy's posture `EVIDENCE_UNTRUSTED` (a BLOCKED stands) and the summary reads "not reported", not "not engaged". Stub-proven (`prove_version_gap_production.py`) | 03, 05, 07, 09, 11 |
| `71a3d63` | **the assurance tracer reads `env:` and `needs.*`** (31 → 120 hand-offs traced) and the ten real defects it found are fixed: in both deploy reusables a rollback-capability step that wrote no verdict read as reversal available, now UNAVAILABLE (→ `EVIDENCE_UNTRUSTED`); the OIDC verifier counted a baseline step that never answered as a baseline taken, now UNAVAILABLE; the NVD summary's unavailable list is read only when it wrote its state; ticket-reconcile's absent exit code has its own case arm | 05, 07, 08, 11 |
| `fa19c02` | **hollow scan per tool (KDEC-008 OD-2)**: the report now agrees with the runner that a clean Bandit run is not hollow (its rows had read NOT ESTABLISHED), and reads error notifications from both SARIF arrays; `prove_hollow_scan.py` wired into self-test (completion ledger L01) | 02, 04, 08, 09 |
| `1542c05` | **scan validity**: every `semgrep scan` runs `--strict`, exit 3 (a file it could not parse) is COLLECTION_FAILED; a CodeQL autobuild that did not succeed reads PARTIAL (summary and annotation; the gate does not read it) | 02, 04, 08, 09 |
| `11db350` | **discovery depth**: beyond the 8-level search bound a language is UNDETERMINED and its scanner runs, never NOT_APPLICABLE, with a `BeyondSearchDepth` coverage gap; the Node/.NET/Go root enumerations search 8 levels, not 6 | 02, 08, 09 |
| `655a2e5`, run 39618320185 | **weekly tool probe** probes the shipped Semgrep 1.178.0 and gosec 2.24.6 container; its negative control installs Trivy and can fail. Hosted run on `078ef90` green | 04, 08 |
| `3500e23`, `bc98cc5`, `b352729`, `fdd0a0c`, `c82b34f`, `c7309f1` | **export and neutrality**: `.context/` never exported; no deny list (or an empty one) refuses the export; the profile is bound to the destination's watermark; the kit's own consumer-path harness is no longer exported; every deny pattern carries samples it must match (`prove_deny_samples.py`); three more name forms denied; `check_export_safety` reads the deny list by the gate's own rules and refuses if they disagree; the watermark keeps the commit and drops the branch | 08 |
| `5fde1e4` | the consumer census writes outside the kit (system temp or `CONSUMER_COVERAGE_OUT`) and refuses a destination inside it | 08 |
| `bb7ef0d` | two self-descriptions corrected (taxonomy `version_applicability`; the tracer's undelivered ORPHAN check) | — |
| v1.11 correction | **v1.11 missed three merges that landed before it**: lane L-F (`a0e8b16`: F-01 fixed — a ledger is established by an approved ESTABLISH pull request under CODEOWNERS; one move record; scanner-generation hold; environment presence; ticket ledger in the same PR), lane L-T (`85bd33d`: T-02 fixed — updates never erase human text; delta-only updates; reopen classes; sweep without credentials; degraded streak) and `9b18e49` (KDEC-013's reference gate now on the trunk). Parts 06, 09 and 11 said F-01 and T-02 were open | 06, 09, 11 |
| docs | part 02 said 24 report rows (25); `RELEASE_1_EVIDENCE_MANIFEST.md` split into three standalone parts under 20 KB (the original name keeps part 1; `_PART2.md` holds identity, build, deploy and ticketing; `_PART3.md` the consumer interface and the trunk's additions) and brought to `078ef90`; this log split (`10b`); new part 12; part 00 separates VERIFIED (run) from READ | 00, 09, 10, 11, 12 |

Deferrals: 3, none blocking — unchanged. Hosted on `078ef90`: Validate scanners 39618320185 green;
self-test 39618329392 failed in the export-scope proof (a downloaded scanner archive in the
runner's working tree tripped the deny list during the proof's own export). The exporter excluded
only gitignored files, so the download would also have shipped. **`904bc7a`**: whatever git does not
track is neither scanned nor exported (proof E8, failed first); self-test 39622321744 green on it.

## Version 1.11 — 2026-10-16 (trunk `3830edb`, lane `lane/L-G`)

`main` is at Release 1: `ef4b15d` (PR #3, neutral, no overlays, Jira ticketing in core).

| commit / run | change | parts affected |
|---|---|---|
| `1c20a0b` | **KDEC-014**: the gate emits `advisory_causes`; at uat/prod both deploy reusables refuse a `PROCEED_WITH_ADVISORY` caused by a proven `VERSION_GAP` unless the weakening record names an accepter, a reason and an unexpired date; an UNVERIFIED-range gap proceeds, recorded; an advisory with no cause is refused. Stub-proven (`prove_version_gap_production.py`); no live run. KDEC-015 recorded: internal tools are released by the kit too | 03, 05, 07, 11 |
| lane L-G | **documents made true to the code**: advisory mode never covered secrets (START-HERE said it did); the deploy workflows are proven live (START-HERE, USAGE, SETUP, the rollback contract and parts 07/11 said never executed or stub-only); examples no longer set the dead `enable_iac` or narrow `language`; caller permissions stated per reusable; the deploy reusables do not check `artifact_identity` (the template does); report rows 25, routing scenarios 21; the run record and deploy outcome are not workflow outputs. New: `docs/assurance/RELEASE_1_EVIDENCE_MANIFEST.md`. `check_doc_currency.py` now reads the consumer documents and refuses those three classes | 02–09, 11 |

Deferrals: 3, none blocking — attestation-verify, change-detection, toolchain-terraform (all 2026-12-31).

Versions 1.10 and earlier: `10b-CHANGE-LOG-EARLIER.md`.
