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
| `secret-scan` | gitleaks 8.21.2 (pinned, kit rules for cloud/identity credential classes), detect-secrets | always | any gitleaks finding; an empty scope or zero commits scanned (`COLLECTION_FAILED`); a detect-secrets report that cannot be read | **never softened**; one found secret passes only under a ticketed exception for that finding (part 05) | `prove_secrets_always_block.py`, `prove_secret_denominator.py` (VERIFIED) |
| `code-quality` | ruff + mypy (python), ESLint (node) | discovery found python **or** node | ruff / ESLint violations, only with `enforce_lint: true` | lint is not a security control; off by default; advisory never blocks | `prove_code_quality_enforces.py` (VERIFIED) |
| `sast-semgrep` | Semgrep, rulesets from `semgrep_config`, run with `--strict`; **plus `p/php` whenever discovery finds PHP, and `p/kotlin` whenever it finds Kotlin** (floors the caller's rulesets cannot narrow away) | always | ERROR-level findings by **effective** SARIF level; a file it cannot parse (exit 3 under `--strict`) is `COLLECTION_FAILED`; PHP in scope that Semgrep examined none of (its own `paths.scanned`), or with no PHP rule loaded, is `COLLECTION_FAILED`; the same witness for Kotlin (KDEC-026) | softened by `soft_fail_sast` / advisory | `prove_sarif_effective_level.py`, `prove_semgrep_rulesets.py`, `prove_semgrep_strict.py`, `prove_semgrep_php.py`, `prove_semgrep_kotlin.py` (VERIFIED). The job runs the Semgrep **1.178.0 image, pinned by digest** (lane L-SG), the release the C# and Java jobs install; the local proofs fail if the Semgrep they run is not that release. Exit 3 under `--strict` measured on 1.178.0, in this image too (locally, 2026-10-21); a hosted run of the job is owed |
| `sast-bandit` | Bandit | python found | findings; an unparseable file is COLLECTION_FAILED | softened | `prove_bandit_enforces.py` (VERIFIED) |
| `sast-java` | Semgrep `p/java` + `p/security-audit`, `--strict` | java found | findings; exit 3 is COLLECTION_FAILED | softened | `prove_sast_java_detects.py` (VERIFIED, seeded SQL injection) |
| `sast-go` | gosec | go found | findings; no module dropped silently | softened | `prove_gosec_modules.py` (VERIFIED) |
| `sast-dotnet` | `dotnet list package --vulnerable` (run per project, each result filed against the project dotnet reports), Semgrep C# (`--strict`) | dotnet found | findings; Semgrep exit 3 is COLLECTION_FAILED | softened | `prove_sast_dotnet_detects.py`, `prove_nuget_audit.py`, `prove_dotnet_solution_detects.py` (VERIFIED; a multi-project solution, KDEC-026) |
| `sast-cpp` | cppcheck (through a compilation database when the build can be read: committed, CMake configure-only, or bear over `make`), flawfinder | cpp found | findings; a converter failure is COLLECTION_FAILED; any source with no build metadata makes the scan `PARTIAL` (`CPP_ANALYSIS_PARTIAL`) | softened | `prove_cppcheck_collects.py`, `prove_sast_cpp_runs.py`, `prove_cpp_build_aware.py` (VERIFIED) |
| `sast-mobile` | mobsfscan 1.0.1 (Semgrep 1.172.0 inside; both by sha256), kit rules `mobile-config.semgrep.yml` | mobile found (AndroidManifest.xml, Info.plist, `.swift`, `.m`, `.mm`) | ERROR-level results of either; a positive control (planted manifest + planted Kotlin MD5) not detected is COLLECTION_FAILED | softened | `prove_sast_mobile_detects.py` (VERIFIED, in a Linux container) |
| `codeql` | GitHub CodeQL, `codeql_queries` suite (default `security-extended`), up to six language legs | a CodeQL language found (the `java-kotlin` leg on Java **or** Kotlin) | findings | softened | **proven at Level 2** (a separate private repository calling by `owner/repo@sha`, runs 38817782084, 38820564939: 5 Python and 4 JavaScript results read by the gate; absent languages NOT_APPLICABLE). On a private unlicensed repository the analysis runs and only publication is refused; `resolve` still caps the job PARTIAL on the platform pre-flight (KNOWN_DEFECTS D-10). Each leg names its build mode: `none` (buildless, every source file, no build system needed) for Python, JavaScript/TypeScript, C#, Java and C/C++; `autobuild` for Go and for a Kotlin leg. Each leg files its own state and its row reads it, not the shared job result: an autobuild that did not succeed is `PARTIAL` in the row and the verdict (`COVERAGE_PARTIAL`), and a leg that initialised and could not analyse fails its job (`COLLECTION_FAILED`, read by the gate as untrusted evidence) — `prove_codeql_build_outcome.py`, `prove_codeql_rows_read_sarif.py`, `prove_codeql_dynamic_matrix.py` (integrate/r8; before it, the monorepo cost fixture's C/C++, C# and Java legs found no build system, wrote no SARIF and stayed green) |
| `deps-scan` | Trivy filesystem (dependencies); **pipeline lint** (below): actionlint + zizmor, shellcheck, PSScriptAnalyzer | always; each linter only where discovery's `workflows` / `shell` / `powershell` is true | findings at `fail_on_severity` (default CRITICAL,HIGH); every severity stays in the SARIF; lint: ERROR-level by effective level | softened by advisory | `prove_trivy_threshold.py`, `prove_deps_scan_composer.py` (VERIFIED; a vulnerable Composer lock blocks); lint: `prove_pipeline_lint.py` (VERIFIED locally in a Linux container) |
| `iac-scan` | Checkov, Trivy IaC; **hadolint** where discovery's `dockerfile` is true | IaC found (`iac_mode: auto`), or `required` | ERROR-level by effective level | softened | `prove_sarif_effective_level.py` covers the count (VERIFIED); hadolint: `prove_pipeline_lint.py` |
| `malicious-deps` | OSV-Scanner (pinned, checksum-verified) | always: part of the crawl floor; `enable_malicious_pkg_scan` cannot be false (refused, `CHERRY_PICK_BELOW_FLOOR`, KDEC-020) | known-malicious `MAL-` advisories (ids and aliases): routed with the secret class at the gate, **blocking in every mode** | never softened | `prove_malicious_deps_enforces.py` (VERIFIED). Malware published only under a GHSA id is not seen by the MAL- rule |
| `sbom` | Syft (CycloneDX), licence check | `enable_sbom` (default true) | a denied licence (token match, counted once); no SBOM = failure | — | `prove_sbom_licence_verdict.py` (VERIFIED) |
| `image-scan` | Trivy image: **two steps** — vulnerabilities, then secrets | `image_ref` supplied | CVEs at `fail_on_severity` (advisory softens); **any secret in the image, every mode** | secrets never softened | `prove_image_scan_enforces.py`, `prove_image_scan_retains.py` (VERIFIED; both SARIFs redacted and retained) |

**Exploited in the wild blocks at every rung** (KDEC-022 item 3; VERIFIED locally with a fixture feed,
`prove_known_exploited.py`; no hosted run). The report publishes every `deps-scan` / `image-scan`
CVE (`cve_findings`, every severity); the gate's `kev` step reads the CISA KEV catalog once per run
(date-keyed cache; catalogVersion, dateReleased and sha256 in the summary) and a catalogued CVE is
`FINDING_KNOWN_EXPLOITED`, `BLOCKED`, crawl and `advisory_mode` included, unless one register
`known_exploited_exceptions` item excepts that finding. An unreadable catalog is
`kev_state UNAVAILABLE` (advisory, never a pass). `reusable-nvd-cve.yml` runs the same check on its
own SARIF, with no exceptions.

## PHP (lane L-PHP, Release 3 next)

PHP is scanned by two existing jobs, each proven on seeds (measured 2026-10-21, VERIFIED):

| what | how | state |
|---|---|---|
| PHP source (SAST) | `sast-semgrep` adds `p/php`; seeded SQL injection, XSS and command injection reported at ERROR on Semgrep 1.90.0 and 1.178.0 (the job's image since lane L-SG, measured in it), even under a narrowed `semgrep_config` | PROVEN LOCALLY (`prove_semgrep_php.py`); the weekly `semgrep-php` probe runs the job's image over the seeds; hosted owed |
| PHP dependencies | `deps-scan` (Trivy) reads `composer.lock`: phpmailer/phpmailer v5.2.18 gives CVE-2016-10045 CRITICAL and blocks | PROVEN LOCALLY (`prove_deps_scan_composer.py`); hosted owed |
| a `composer.json` with no lock | read by no scanner (Trivy produced no result) | declared `COVERAGE_GAP` `PHPDependenciesUnlocked` |
| PHP 8.5 Semgrep cannot fully parse | **scan what parses, flag the rest** (owner, 2026-10-22; KDEC-016 amended). `sast-semgrep` reads Semgrep's own JSON: when every error is a parse error (`errors[].type` `["PartialParsing", [spans]]`, level `warn`) on a `.php` file, the exit 3 is not discarded -- findings kept (and block as usual), the files and lines named, `scan_state` `PARTIAL` (`PARSE_PARTIAL_PHP_SYNTAX`). The gate reads it as `PARTIAL`, routing `PROCEED_WITH_ADVISORY` / `COVERAGE_PARTIAL`. Any other error (a non-PHP parse failure, a rule load failure, nothing examined) stays `COLLECTION_FAILED` | PROVEN LOCALLY (`prove_semgrep_php.py` S7-S10, in the job's image too); hosted owed |
| PHP release Semgrep can read | `version_support` sast-semgrep/php, MEASURED by `tests/corpora/php_corpus.py` on the job's own image | **READ 5.6–8.4** on the job's 1.178.0 image (lane L-SG re-measured it there, 2026-10-21, locally; the weekly corpus probe repeats it on the same digest). **PHP 8.5 is measured and NOT fully read**: its `(void)` cast and `final` promoted properties draw PartialParsing on 1.178.0 and on 1.182.0, the newest Semgrep; the pipe operator parses. The row's measured `parse_evidence_max: "8.5"` says Semgrep NAMES each such file, so an 8.5 target is not a `VERSION_GAP` (above 8.5 it still is). Before L-SG the job's 1.90.0 container read only 5.6–7.2: 7.3+ syntax was exit 3 under `--strict` (`COLLECTION_FAILED`) |

## Pipeline lint (lane L-SCAN-A, KDEC-025)

Workflows, shell, PowerShell and Dockerfiles were `COVERAGE_GAP` rows. Each now has a linter **inside a
job that already runs**, so a consumer pays no new job minute: nearly every repository has a workflow,
and a job of its own would bill a minimum minute on every run. Discovery decides per class; a class
that is absent is skipped inside the step at no cost (nothing fetched). Every tool is fetched by exact
version and sha256 written in the step.

| class | tool (job) | refuses, as a named `VERSION_GAP` |
|---|---|---|
| `.github/workflows/*.yml` | actionlint 1.7.12 (shellchecks every `run:`), zizmor 1.30.1 offline, `--no-config` (`deps-scan`) | — (a workflow zizmor cannot load is `COLLECTION_FAILED`) |
| `*.sh` / `*.bash` | shellcheck 0.11.0 (`deps-scan`) | a shebang outside sh/bash/dash/ksh/busybox (zsh, fish); no shebang: `.sh` read as POSIX sh, stated |
| `*.ps1` / `*.psm1` / `*.psd1` | PSScriptAnalyzer 1.25.0 on the runner's pwsh (`deps-scan`) | `#Requires -Version` newer than that pwsh (measured: the tool returns nothing for it) |
| `Dockerfile*`, `Containerfile` | hadolint 2.15.1 (`iac-scan`) | a file it cannot parse (DL1000), left out of the count |

SARIF carries repository-relative paths and a fingerprint over tool, rule, path and snippet (never a
line). ERROR-level findings hand `findings_state=FINDINGS` to the gate; the job fails only when a
linter that should have run established nothing. A row whose linter named an unread file is
`PARTIAL`, never `PASS`. Not added, by measurement (KDEC-025): pip-audit and npm audit (every advisory
they reported on pinned or locked dependencies was in OSV-Scanner's report, which already runs; an
unpinned requirement neither reads is a declared `PythonDependenciesUnpinned` gap) and tflint (none of
three seeded misconfigurations, where Trivy config found two among eight, beside Checkov). Hosted runs are owed.
## Android, iOS, Kotlin, build-aware C/C++ and a real .NET solution (lane L-SCAN-B, KDEC-026)

Measured 2026-10-23 on planted trees (`tests/_platform_fixtures.py`, graded by `PLATFORM_SIGNALS.json`):

| what | how | state |
|---|---|---|
| Kotlin | discovery `kotlin` (`.kt`/`.kts`); `sast-semgrep` adds `p/kotlin` (MD5 and ECB found under a narrowed config); CodeQL's `java-kotlin` leg starts on Kotlin too | PROVEN LOCALLY; hosted owed (`semgrep-kotlin` probe) |
| Android | mobsfscan: manifest (debuggable, allowBackup, cleartext, minSdk), network_security_config (cleartext, user CAs), Kotlin (ECB, MD5, WebView). Kit rules for what it does not read: exported components without a permission, hard-coded Gradle signing passwords, Gradle minSdk below 26, debuggable release builds | PROVEN LOCALLY in a container; hosted owed (`mobile` probe) |
| iOS | discovery `mobile` now probes `.m`/`.mm` (Objective-C was never asked about) and `swift`; mobsfscan: ATS arbitrary loads, insecure-HTTP and weak-TLS exceptions, `kSecAttrAccessibleAlways`, UIWebView, Objective-C MD5 and `strcpy`. **No macOS runner**: CodeQL for Swift needs one at 10x the minute rate, a deliberate cost decision | PROVEN LOCALLY; hosted owed |
| Build-aware C/C++ | a source-only scan of the planted tree is silent; through CMake's database cppcheck reports the out-of-bounds write. No build system is ever written; a source without build metadata is `PARTIAL` (`CPP_ANALYSIS_PARTIAL`, read by the gate as `COVERAGE_PARTIAL`) | PROVEN LOCALLY (Ubuntu container); hosted owed (`cppcheck-build` probe) |
| .NET solution | `.sln` + web, data and test projects; both planted NuGet advisories reported at their declaring project lines (the first run found them filed against the `.sln`, fixed), and the controller SQL injection | PROVEN LOCALLY (host SDK); hosted owed (`dotnet-solution` probe) |

Version ranges (`scanner-registry.yaml`): CodeQL Kotlin 1.8.0–2.4.20 (READ); Semgrep Kotlin/Swift and
mobsfscan Swift UNVERIFIED, so a target there is `VERSION_SUPPORT_UNDETERMINED`, never assumed.

## The report's 32 rows

The report renders one verdict per **scanner**, not per job, so two tools in one job cannot hide behind
each other: gitleaks, detect-secrets, code-quality, eslint, semgrep, bandit, java-sast, gosec,
dotnet-vuln, semgrep-csharp, cppcheck, flawfinder, mobsfscan, mobile-config, trivy, trivy-iac, checkov, actionlint,
zizmor, shellcheck, psscriptanalyzer, hadolint, malicious-deps, sbom,
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
(M8, VERIFIED locally). A push runs it only on `main` (lane L-DOC, M12): this private repository pays
for every Actions minute, so a branch is validated by the free public mirror's run on the release
candidate, or here by dispatch; the weekly schedule is unchanged. Lane L-SCAN-A added five legs —
`actionlint`, `zizmor`, `shellcheck`, `psscriptanalyzer`, `hadolint` — each running the pinned release
over `tests/corpora/pipeline_lint_corpus.py` and detecting only when every seeded rule is reported
(measured locally in a Linux container; the hosted run is owed).
Lane L-SCAN-B added four legs -- `mobile`, `semgrep-kotlin`, `cppcheck-build`, `dotnet-solution` -- each
detected only when every planted row of `PLATFORM_SIGNALS.json` for its tool is reported on its file
(three run locally, 2026-10-23).

## Pinning

Every tool is installed at a pinned version, and where a release publishes checksums the install
verifies them. `releases/latest` and `install.sh` from a moving branch are refused (L84, in progress for
the remaining installs). The Semgrep container is pinned by image digest, with its release named
beside it (lane L-SG). Every remote action is referenced by a full commit SHA with its release named
beside it (L82, `4dfd858`; VERIFIED at `19b5e1d`: `tests/check_action_pins.py`, 182 references, 0
refused). Two pip installs (detect-secrets, ruff/mypy) are still unpinned (L84).
