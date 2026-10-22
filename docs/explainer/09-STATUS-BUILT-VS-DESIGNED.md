# 09 · Status: built vs designed

Source: `docs/assurance/COMPLETION_LEDGER.md` (202 rows, audited at `53d2962`) and
`docs/assurance/RELEASE_1_EVIDENCE_MANIFEST.md` with `_PART2.md` and `_PART3.md` (one row per
capability, each with its run or proof),
updated to trunk `078ef90`. Completion-ledger rows closed after its audit are stated here from the
fixing commit and its proof. **Release 1** is what the owner decided must be complete and proven end
to end now (KDEC-007); **Release 2** is the rest, dated.

"Proven locally" means the shipped step or script was run with the real tool (or, for cloud and tracker
calls, against a stateful stand-in that replays the documented API shapes) and failed before its fix and
passed after. "Live" means a real external system (Azure, a registry, a tracker), with a run id or a
cited transcript. "Hosted" means a GitHub runner run id.

## By stage

| stage | what it is | state | release |
|---|---|---|---|
| 1 policy resolution | rung per (repo, environment), registration file, derived `policy_mode` | BUILT as libraries, proven; gate wiring is a written patch, not applied | 2 |
| 2 discovery | presence probes, could-not-look ≠ not-present, coverage gaps; beyond the 8-level bound is UNDETERMINED, never NOT_APPLICABLE (`11db350`); `php` an ecosystem since lane L-PHP, a lock-less `composer.json` a named gap | BUILT, proven hosted (consumer path, before the bound fix); the bound and PHP proven locally | 1 (PHP: 3) |
| 3 version discovery | the version each root targets | BUILT, proven locally | 2 |
| 4 capability selection | the capability picks the scanner; a substitute is labelled; no capable scanner = PARTIAL, never PASS (KDEC-010) | BUILT, proven locally; many ranges UNVERIFIED until seeded test sets exist, so those read PARTIAL | 2 |
| 5 execution planning | the job set as data before anything runs | DESIGNED (owner review, EP-1..EP-4) + an advisory plan output nothing enforces | 2 |
| 6 scanning | 14 scanner jobs | BUILT, proven hosted (20/20 seeded signals on `main` `ef4b15d`, run 38934329462); every count site refuses no-evidence-as-zero; malware and secrets block in every mode | 1 |
| 7 evidence validity | a report that read nothing is never clean | BUILT at every count site; the report and the runner now agree on a hollow scan (ledger L01, `fa19c02`); Semgrep `--strict` and the CodeQL autobuild outcome read (`1542c05`); sidecar rows 8–10 not built | 1 |
| 8 normalisation + redaction | redaction before every publication | BUILT, proven locally | 1 |
| 9 identity + baseline | durable identity, ledger read, cascade, propose-ledger job | BUILT and wired into the report; a ledger is established only by an approved ESTABLISH pull request under CODEOWNERS (F-01 fixed, `a636f5e`), proven locally, no hosted run; one move record, scanner-generation hold; the gate does not read the baseline yet | 1 |
| 10 severity + disposition | schema-true dispositions on the durable key | BUILT, proven (legacy key honoured until 2026-11-13); severity/SLA libraries Release 2 | 1 |
| 11 correlation | anchored clusters only | BUILT, wired, proven locally | 1 |
| 12 gate + verdict | `routing_result`, `advisory_causes`, posture record | BUILT, proven locally (21 routing scenarios) and live in the consumer path (caller blocked); rung floor Release 2 | 1 |
| 13 ticketing | Jira first, Azure DevOps second | BUILT; the reconciler proven LIVE on a personal Jira; Azure DevOps against stand-ins only; the armed workflow has no hosted run and no template calls it; updates keep human text (T-02 fixed, `795d13c`) and write only on a delta | 1 |
| 14 reporting | 25 rows, findings counts, findings JSON, evidence artifact | BUILT, proven; the run record `assurance-result.json` its schema describes is emitted nowhere (L36) | 1 |
| 15 deploy + verification | verdict-gated, digest-bound, reversible | BUILT, proven LIVE on Azure for Container Apps and App Service: refusal, healthy deploy, verified rollback, a second actor refused, the slot swap. KDEC-014 (prod refuses a proven version gap without a named acceptance) built, stub-proven; since `078ef90` an absent ruling is EVIDENCE_UNTRUSTED | 1 |

## Hosted and live status (trunk `078ef90`)

**The trunk owes the consumer-path run.** Everything below was proven on `main` `ef4b15d` or on earlier
trunk commits; the trunk's changes since (KDEC-014, the L-F/L-T lanes, the `078ef90` fixes) are proven
locally. On `078ef90` the weekly tool probe ran green (39618320185) and self-test failed
(39618329392): its export-scope proof (E1) found the neutral export refused, because a scanner archive
an earlier step downloaded into the runner's working tree matched a deny pattern. The defect was the
exporter's: it excluded only gitignored files, so an untracked download was scanned and would have
shipped. **Fixed in `904bc7a`**: whatever git does not track is neither scanned nor exported (proof
E8, failed first). Self-test 39622321744 is green on `904bc7a` (VERIFIED).

**The scan-and-gate path is proven end to end on GitHub, on `main` itself.** On `ef4b15d` the
consumer-path test (run 38934329462) detected 20 of 20 seeded signals, each by the scanner that should
detect it, kept the negative control clean and blocked the caller; its negative run (38934348351)
failed as designed; self-test 38926152571 was green on the same commit. (First shown on trunk
`13f1518`, run 38811950471.) **CodeQL is proven on the Level 2 consumer** (a separate
private repository calling the kit by `owner/repo@sha`, runs 38817782084 and 38820564939). **The
Azure identity is proven on the real tenant**: a wrong expected tenant hard-fails after a real login
(38826929579) and the matching case passes (38826938462); the authorization boundary refuses sibling,
opposite-tier and subscription scopes (38832628162, 38832634828, 38850408850). **Build and push are
proven live** to a cloud registry over OIDC (38857011286, 38857017667, 38857024014). **Both deploy
adapters are proven live** on a sandbox subscription, including the App Service staging-slot swap
(run ids in part 07). **The ticket reconciler is proven live on a real Jira**, including the
person-only cases (duplicate, close, reopen). `main` is at Release 1 (`ef4b15d`, PR #3, self-test
38926152571).

## What you can rely on today

- The verdict (`routing_result`) and its routing, including unreadable expiries and the shipped defaults
  (a caller who changes nothing gets `PROCEED` on a clean run), and `advisory_causes` naming why an
  advisory is advisory.
- Secrets block in every mode — source, history, image — and **known-malicious packages block in every
  mode**. A secret scan that read nothing is `COLLECTION_FAILED`.
- No scanner turns a missing, empty or unparseable report into zero; Semgrep and Checkov count by the
  effective SARIF level; Trivy keeps every severity in the evidence and blocks only at `fail_on_severity`.
- No caller input reaches any script except as data (`env:`), and a lint refuses otherwise.
- Deploy refuses before login unless the verdict permits, labels what it ATTEMPTED vs what is NOW
  SERVING, refuses an irreversible deploy at uat/prod, and reverses only what the run changed — on
  real Azure for the healthy, unhealthy and second-actor cases.
- The report publishes durable finding identities and matches them against a baseline ledger read from
  the protected branch; only a separate post-merge job may propose ledger changes, as a pull request.

## What you must NOT rely on yet

- **A real gate verdict carried into a deploy in one pipeline**: every live deploy received a typed
  verdict. The starter template that composes them has not run on a runner.
- **Attestation signing and verification (V1)**: built; held until a public repository or Enterprise
  Cloud. V1 runs only in the starter template, not inside the deploy reusables.
- **A baseline ledger established on a runner**: the shipped path (an approved ESTABLISH pull request,
  F-01) is proven locally only, and no starter template calls it; until one is merged nothing is
  grandfathered.
- **Live ticketing on Azure DevOps**, and an armed hosted run of `reusable-ticket-reconcile.yml`.
- **EMPTY or UNKNOWN prior state, PARTIAL_APPLY / STATUS_UNTRUSTED, provenance tags, a prod-tier
  capability refusal, KDEC-014** on a live target: stub-proven only.
- **The rung ladder, SLA and severity derivation in the gate** — Release 2. Version fitness is consumed
  (KDEC-010): a scanner that cannot read the code at its version never carries a PASS.
- **PHP 8.x on a runner**: lane L-SG moved the `sast-semgrep` job to the Semgrep 1.178.0 image,
  pinned by digest, which reads PHP 5.6–8.4 (measured locally in that image). No hosted run of the
  job on that image exists yet.
- **PHP 8.5 on a runner**: Semgrep cannot fully parse the `(void)` cast or `final` promoted
  properties (1.178.0 and the newest, 1.182.0). Since lane L-P85 (owner, 2026-10-22: scan what
  parses, flag the rest) such a file makes the Semgrep scan `PARTIAL` with the file named and every
  other finding kept, routed `COVERAGE_PARTIAL` -- proven locally, including in the job's image; no
  hosted run yet.
- **The NVD workflow blocking anything**: `fail_on_cvss` defaults to 11.
- **SHA-pinned actions**: the kit's own third-party actions are referenced by tag.
- **The kit as a landing-zone deploy engine** — there is no plan/apply/destroy/vend pipeline.

## Release 2 (dated, owned; see completion ledger section 4)

Seeded corpora for the UNVERIFIED scanner ranges (semgrep, gosec, checkov, trivy-config, cppcheck,
eslint — D-VF-4; until then those scanners are never *selected* and the capabilities only they serve go
PARTIAL), rung-ladder gate wiring, severity/SLA in the gate and ledger, execution-plan enforcement, cost
packing, scheduled revalidation (PROV V3), the retirement register, overlays B and C beyond their docs.

## Release 3 (next)

**PHP, a supported ecosystem** (owner, 2026-10-21: "I need php and we need it now"; lane L-PHP).
BUILT and PROVEN LOCALLY, hosted runs owed (consumer path at 24 seeded signals, the PHP-only
negative, self-test, validate-scanners, the corpus probe):

| piece | state |
|---|---|
| discovery `php` (`*.php`, `composer.json`, `composer.lock`), the same could-not-look and depth rules | PROVEN LOCALLY (`test_discovery.py`) |
| PHP target versions (`.php-version`, `config.platform.php`, `require.php`, the lock, `FROM php:`) | PROVEN LOCALLY (`test_resolve.py`) |
| SAST: `p/php` a floor in `sast-semgrep`; SQL injection, XSS, command injection detected; a hollow PHP scan is `COLLECTION_FAILED` | PROVEN LOCALLY (`prove_semgrep_php.py`) |
| dependencies: a vulnerable `composer.lock` blocks `deps-scan`; a lock-less `composer.json` is a named gap | PROVEN LOCALLY (`prove_deps_scan_composer.py`) |
| the PHP range Semgrep reads, MEASURED on the job's image | **READ 5.6–8.4** on the job's 1.178.0 image, pinned by digest (lane L-SG; re-measured locally in that image 2026-10-21; `prove_php_corpus.py`). The weekly corpus probe and the validate-scanners `semgrep-php` probe run the same digest; their hosted runs are owed. **8.5 measured not fully read** on 1.178.0 and 1.182.0, and measured as parse evidence (`parse_evidence_max` 8.5, lane L-P85): an 8.5 target is not a `VERSION_GAP` -- the job's parse evidence decides. Before L-SG: READ 5.6–7.2 on the 1.90.0 container |
| PHP 8.5: scan what parses, flag the rest (owner, 2026-10-22; KDEC-016 amended) | PROVEN LOCALLY (`prove_semgrep_php.py` S7-S10, `prove_version_gap_production.py`, `test_resolve.py`, `prove_php_corpus.py` P11): an 8.5 file Semgrep partly parses is `PARTIAL` (`PARSE_PARTIAL_PHP_SYNTAX`), named, every other finding kept; the gate routes `PROCEED_WITH_ADVISORY` / `COVERAGE_PARTIAL`; a non-PHP parse failure is still `COLLECTION_FAILED`. Hosted owed |
| one Semgrep release (ledger L03) | the job's image, the C# and Java jobs and self-test all at 1.178.0; the local Semgrep proofs fail if the release they run is not the job's | PROVEN LOCALLY (`prove_semgrep_strict.py` P4, `prove_semgrep_php.py` S6) |

## Open owner decisions

The full list with recommended defaults is completion ledger section 6 (O-01..O-23). Among them:
OD-3 (packing endpoint), OD-8 (runner version), OD-9 (private unlicensed repositories), `symbol_path`
in identity, the rung table, every placeholder number, whether DCR closes rollback gate 2, the
`fail_on_cvss` default, the landing-zone contract's open items, attestation on a public repository,
and moving the personal Azure DevOps project to its inherited process.
