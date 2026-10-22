# 04 · The scanner jobs

Every job follows the shape in part 02: run the tool without letting its exit code decide, COUNT
(absent or unparseable = `COLLECTION_FAILED`), ENFORCE separately, redact, keep, publish, and say so
when publication degraded. Columns:

- **Runs when** — the discovery output (or input) that starts it.
- **Blocks on** — what the job hands the security gate as `findings_state=FINDINGS` when its
  threshold fires unsoftened; the gate blocks on it by the resolved policy (at crawl it is advisory).
  Since lane L-S the job itself fails only when it could not scan or trust its count — the secret
  scan included, whose secrets the gate blocks at every tier unless each one is excepted in the
  register — except an image secret and a known-malicious package, which still fail their own job.
- **Mode rule** — how `soft_fail_sast` / `advisory_mode` apply.
- **Proof** — the local proof that runs the shipped step with the real tool (part 08), or the
  tool-level probe in `validate-scanners.yml`.

State at trunk `078ef90`: every row's count and enforce path is proven locally with the real tool, and every job ran on GitHub in the consumer-path run 38934329462 on `main` (`ef4b15d`), where 20/20 seeded signals were detected by the scanner that should detect each (first shown on trunk `13f1518`, run 38811950471); CodeQL is proven on a separate consumer repository. The trunk's later commits (including `--strict` and the depth bound below) owe the same run.

| job | tool(s) | runs when | blocks on | mode rule | proof / state |
|---|---|---|---|---|---|
| `secret-scan` | gitleaks 8.21.2 (pinned, kit rules for cloud/identity credential classes), detect-secrets | always | any gitleaks finding; an empty scope or zero commits scanned (`COLLECTION_FAILED`); a detect-secrets report that cannot be read | **never softened** | `prove_secrets_always_block.py`, `prove_secret_denominator.py` (VERIFIED) |
| `code-quality` | ruff + mypy (python), ESLint (node) | discovery found python **or** node | ruff / ESLint violations, only with `enforce_lint: true` | lint is not a security control; off by default; advisory never blocks | `prove_code_quality_enforces.py` (VERIFIED) |
| `sast-semgrep` | Semgrep, rulesets from `semgrep_config`, run with `--strict`; **plus `p/php` whenever discovery finds PHP** (a floor the caller's rulesets cannot narrow away) | always | ERROR-level findings by **effective** SARIF level; a file it cannot parse (exit 3 under `--strict`) is `COLLECTION_FAILED`; PHP in scope that Semgrep examined none of (its own `paths.scanned`), or with no PHP rule loaded, is `COLLECTION_FAILED` | softened by `soft_fail_sast` / advisory | `prove_sarif_effective_level.py`, `prove_semgrep_rulesets.py`, `prove_semgrep_strict.py`, `prove_semgrep_php.py` (VERIFIED). The job runs the Semgrep **1.178.0 image, pinned by digest** (lane L-SG), the release the C# and Java jobs install; the local proofs fail if the Semgrep they run is not that release. Exit 3 under `--strict` measured on 1.178.0, in this image too (locally, 2026-10-21); a hosted run of the job is owed |
| `sast-bandit` | Bandit | python found | findings; an unparseable file is COLLECTION_FAILED | softened | `prove_bandit_enforces.py` (VERIFIED) |
| `sast-java` | Semgrep `p/java` + `p/security-audit`, `--strict` | java found | findings; exit 3 is COLLECTION_FAILED | softened | `prove_sast_java_detects.py` (VERIFIED, seeded SQL injection) |
| `sast-go` | gosec | go found | findings; no module dropped silently | softened | `prove_gosec_modules.py` (VERIFIED) |
| `sast-dotnet` | `dotnet list package --vulnerable` (run per project), Semgrep C# (`--strict`) | dotnet found | findings; Semgrep exit 3 is COLLECTION_FAILED | softened | `prove_sast_dotnet_detects.py`, `prove_nuget_audit.py` (VERIFIED) |
| `sast-cpp` | cppcheck, flawfinder | cpp found | findings; a converter failure is COLLECTION_FAILED | softened | `prove_cppcheck_collects.py`, `prove_sast_cpp_runs.py` (VERIFIED) |
| `codeql` | GitHub CodeQL, `codeql_queries` suite (default `security-extended`), up to six language legs | a CodeQL language found | findings | softened | **proven at Level 2** (a separate private repository calling by `owner/repo@sha`, runs 38817782084, 38820564939: 5 Python and 4 JavaScript results read by the gate; absent languages NOT_APPLICABLE). On a private unlicensed repository the analysis runs and only publication is refused; `resolve` still caps the job PARTIAL on the platform pre-flight (KNOWN_DEFECTS D-10). An autobuild that did not succeed now reads `PARTIAL`, not `COMPLETE` (`prove_codeql_build_outcome.py`, VERIFIED) — in the summary and an annotation only: the gate reads the job's result, so it does not reach the verdict |
| `deps-scan` | Trivy filesystem (dependencies) | always | findings at `fail_on_severity` (default CRITICAL,HIGH); every severity stays in the SARIF | softened by advisory | `prove_trivy_threshold.py`, `prove_deps_scan_composer.py` (VERIFIED; a vulnerable Composer lock blocks) |
| `iac-scan` | Checkov, Trivy IaC | IaC found (`iac_mode: auto`), or `required` | ERROR-level by effective level | softened | `prove_sarif_effective_level.py` covers the count (VERIFIED) |
| `malicious-deps` | OSV-Scanner (pinned, checksum-verified) | `enable_malicious_pkg_scan` (default true) | known-malicious `MAL-` advisories (ids and aliases), **in every mode**, like secrets | never softened | `prove_malicious_deps_enforces.py` (VERIFIED). Malware published only under a GHSA id is not seen by the MAL- rule |
| `sbom` | Syft (CycloneDX), licence check | `enable_sbom` (default true) | a denied licence (token match, counted once); no SBOM = failure | — | `prove_sbom_licence_verdict.py` (VERIFIED) |
| `image-scan` | Trivy image: **two steps** — vulnerabilities, then secrets | `image_ref` supplied | CVEs at `fail_on_severity` (advisory softens); **any secret in the image, every mode** | secrets never softened | `prove_image_scan_enforces.py`, `prove_image_scan_retains.py` (VERIFIED; both SARIFs redacted and retained) |

## PHP (lane L-PHP, Release 3 next)

PHP is scanned by two existing jobs, each proven on seeds (measured 2026-10-21, VERIFIED):

| what | how | state |
|---|---|---|
| PHP source (SAST) | `sast-semgrep` adds `p/php`; seeded SQL injection, XSS and command injection reported at ERROR on Semgrep 1.90.0 and 1.178.0 (the job's image since lane L-SG, measured in it), even under a narrowed `semgrep_config` | PROVEN LOCALLY (`prove_semgrep_php.py`); the weekly `semgrep-php` probe runs the job's image over the seeds; hosted owed |
| PHP dependencies | `deps-scan` (Trivy) reads `composer.lock`: phpmailer/phpmailer v5.2.18 gives CVE-2016-10045 CRITICAL and blocks | PROVEN LOCALLY (`prove_deps_scan_composer.py`); hosted owed |
| a `composer.json` with no lock | read by no scanner (Trivy produced no result) | declared `COVERAGE_GAP` `PHPDependenciesUnlocked` |
| PHP 8.5 Semgrep cannot fully parse | **scan what parses, flag the rest** (owner, 2026-10-22; KDEC-016 amended). `sast-semgrep` reads Semgrep's own JSON: when every error is a parse error (`errors[].type` `["PartialParsing", [spans]]`, level `warn`) on a `.php` file, the exit 3 is not discarded -- findings kept (and block as usual), the files and lines named, `scan_state` `PARTIAL` (`PARSE_PARTIAL_PHP_SYNTAX`). The gate reads it as `PARTIAL`, routing `PROCEED_WITH_ADVISORY` / `COVERAGE_PARTIAL`. Any other error (a non-PHP parse failure, a rule load failure, nothing examined) stays `COLLECTION_FAILED` | PROVEN LOCALLY (`prove_semgrep_php.py` S7-S10, in the job's image too); hosted owed |
| PHP release Semgrep can read | `version_support` sast-semgrep/php, MEASURED by `tests/corpora/php_corpus.py` on the job's own image | **READ 5.6–8.4** on the job's 1.178.0 image (lane L-SG re-measured it there, 2026-10-21, locally; the weekly corpus probe repeats it on the same digest). **PHP 8.5 is measured and NOT fully read**: its `(void)` cast and `final` promoted properties draw PartialParsing on 1.178.0 and on 1.182.0, the newest Semgrep; the pipe operator parses. The row's measured `parse_evidence_max: "8.5"` says Semgrep NAMES each such file, so an 8.5 target is not a `VERSION_GAP` (above 8.5 it still is). Before L-SG the job's 1.90.0 container read only 5.6–7.2: 7.3+ syntax was exit 3 under `--strict` (`COLLECTION_FAILED`) |

## The report's 25 rows

The report renders one verdict per **scanner**, not per job, so two tools in one job cannot hide behind
each other: gitleaks, detect-secrets, code-quality, eslint, semgrep, bandit, java-sast, gosec,
dotnet-vuln, semgrep-csharp, cppcheck, flawfinder, trivy, trivy-iac, checkov, malicious-deps, sbom,
trivy-image, trivy-image-secret, and CodeQL's six languages (the `expect` list of the report step). A tool that writes no SARIF (detect-secrets, ruff/mypy, ESLint,
the NuGet audit, the SBOM licence list) has a row that is honestly **NOT ESTABLISHED** for want of
machine-readable evidence — never CLEAN.

A hollow scan (a SARIF that shows the tool examined nothing) is judged per tool (KDEC-008 OD-2). Since
`fa19c02` the report and the runner agree: a **clean Bandit run reads clean**, because Bandit lists only
the rules that fired, while a Bandit run that could not parse a file (an error in either SARIF
notification array) reads NOT ESTABLISHED (`prove_hollow_scan.py`, VERIFIED, now wired into self-test).
Still open: the report lets a result outrank an error notification (the runner fails such a run
first), and the gate does not count NOT ESTABLISHED rows.

## Per-scanner traps the kit already paid for (do not reintroduce)

- **Semgrep skips `test/` and `fixture/` by default.** The kit writes its own `.semgrepignore` so the
  caller's scope decides what is scanned.
- **Semgrep `--config` must be repeated per ruleset**; one flag with two values loads one and treats the
  other as a path.
- **Semgrep writes no `level` on results**; severity is the rule's `defaultConfiguration.level`. Count by
  the SARIF effective level, never `.level // "warning"`.
- **Gitleaks prints no byte count with `--no-git`**; the kit enumerates the scope itself.
- **detect-secrets exits 0 always and scopes to git-tracked files**; the kit scans `--all-files`.
- **checkov-action's `output_file_path` is a directory**; the report is `checkov.sarif/results_sarif.sarif`.
- **trivy-action drops `severity:` for SARIF output entirely**, so it cannot be the block threshold; a separate count step applies `fail_on_severity`.
- **A tool installed but never run, publishing a report nothing wrote**, was green for weeks.
  `check_published_sarif_has_producer.py` now refuses it.

## The weekly tool probe (`validate-scanners.yml`)

Since `655a2e5` it probes the versions the flagship actually runs — Semgrep 1.178.0 (as the C# and
Java jobs pin) and the gosec 2.24.6 container without `-no-fail` — and its negative control can fail:
it installs the pinned Trivy, runs a positive control, and requires a non-zero exit and no
empty-but-well-formed report for a path that does not exist (`prove_validate_scanners.py`, VERIFIED;
hosted run 39618320185 on `078ef90` succeeded). Since L76 the probe matrix is not
`continue-on-error`, the capability matrix fails on an absent, unparseable or undetecting probe, and a
`semgrep-container` probe runs the `sast-semgrep` job's own image (`prove_validate_scanners_matrix.py`,
VERIFIED locally). Since lane L-SG that image is the 1.178.0 digest, and a `semgrep-php` probe runs it
with `p/php` over the three seeded PHP files, detected only when all three are reported at ERROR
(measured locally on that image; the hosted run is owed). A push no longer cancels a dispatched or
scheduled run of this workflow or of the corpus probe: pushes cancelled dispatch runs 39681385412 and
39688249062, so the concurrency group now splits by event and only push runs supersede each other
(M8, VERIFIED locally).

## Pinning

Every tool is installed at a pinned version, and where a release publishes checksums the install
verifies them. `releases/latest` and `install.sh` from a moving branch are refused (L84, in progress for
the remaining installs). The Semgrep container is pinned by image digest, with its release named
beside it (lane L-SG). Actions are referenced by tag today; resolving them to commit SHAs needs a token
and the live API (L82, part 09).
