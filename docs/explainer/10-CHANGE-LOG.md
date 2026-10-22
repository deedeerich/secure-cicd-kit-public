# 10 · Change log

Newest first. On every later delivery, read this file first: it says which parts changed and why.
Commit ids are on the build trunk `fix/normalization-and-discovery`. Versions 1.8 and earlier are in
`10b-CHANGE-LOG-EARLIER.md`. A reader whose last copy was v1.10 (`a907dc8`) reads
`12-CHANGES-SINCE-A907DC8.md` first: it groups every change since by what an integrator must do.

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

## Version 1.10 — 2026-10-16 (trunk `af8672c`)

| commit / run | change | parts affected |
|---|---|---|
| `4360aeb` | **live ticketing proven on a real Jira**: every broken setting refused by name with zero writes; a repeat run creates nothing; a closed ticket with no reopen setting gets a successor that references it; with the reopen transition named, the closed ticket is reopened; two tickets carrying the same stamp are reported AMBIGUOUS and neither is written. Azure DevOps live is not yet run | 06, 09 |
| runs 38912063363, 38912546778 | **App Service staging-slot swap proven live**: a healthy release is deployed to the slot, checked there and swapped in; an unhealthy one is caught on the slot, never swapped, production untouched, the slot restored and verified | 07, 09 |

Deferrals: 3, none blocking — attestation signing (needs a public repository; being wired) and two
capabilities not yet in use.

## Version 1.9 — 2026-10-16 (trunk `c140fe6`)

Live on the owner's personal Azure test subscription (KDEC-012), from the trunk branch the `test`
environment admits, through `live-deploy-acceptance.yml` calling the deploy workflows as a consumer does.

| commit / run | change | parts affected |
|---|---|---|
| runs 38832628162, 38832634828, 38850408850 | **authorization boundary proven on the real tenant**: the kit's own and shared groups reachable; a sibling product's group, an empty opposite-tier group and the subscription REFUSED with their AuthorizationFailed bodies printed; a reachable scope placed in a refused position fails the run | 07 |
| runs 38857011286–38857024014 | **build once, push to a cloud registry**: the kit's own build pushed three images over OIDC and read each digest back (REGISTRY_IDENTITY_PROVEN); those exact digests were deployed | 05, 07 |
| runs 38857259257, 38858033863, 38855929525 | **Container Apps deploy proven live**: a kit-built digest pulled with the app's own identity and served healthy; an unhealthy one never received traffic and was rolled back and verified; a later release created mid-run made the reversal defer rather than reverse out of order | 07 |
| runs 38878189985, 38886279650 | **App Service deploy proven live** (direct path): an unhealthy image rolled back and verified; a second person's change during the health check was detected and NOT overwritten — the run reports ROLLBACK_PARTIAL naming what it refused. The staging-slot swap path is not yet live (needs a Standard tier slot the owner creates) | 07, 09 |
| `ece9d00`, `fe606ae`, `6ee04c3`, `6e40dad`, `95bd5cc` | **five deploy defects found only by running live, each fixed test-first**: a Container App moved all traffic to an unverified revision; the reversal missed inactive revisions; App Service read a 200 from the PREVIOUS container as the new one's health; an idle free-tier site never started until requested; a refused reversal was summarised as verified | 07 |
| `72102ad` | eleven places where a caller's input reached a shell script directly now pass through `env:`, and the lint blocks that pattern in every shared workflow | 05 |
| `e509d6c` | self-test had been intermittently red; a proof crashed when a test registry dropped its connection on Linux. Fixed test-first; self-test green since | 08 |

Deferrals: 4, none blocking. Owed: live ticketing's person-only steps (expires 2026-10-23),
attestation signing (public repository or Enterprise Cloud), two capabilities not yet in use.

Versions 1.8 and earlier: `10b-CHANGE-LOG-EARLIER.md`.
