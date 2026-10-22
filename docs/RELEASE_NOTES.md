# Release notes

Each release of `main` is built from a release-candidate branch, never directly from the development
trunk: the candidate merges the trunk and keeps every consumer overlay off `main`, so the neutral kit,
and the public export generated from it, carry no consumer-specific material. Each entry names the
trunk commit that brought the change.

## Release 3

Built on `release/main-candidate-3` from Release 2 (`b634cff`) and the trunk through `883f328`
(first cut at `09a22a8`, re-cut at `2cd078e` to carry the NVD fix, re-cut again at `883f328` to
carry the policy register, crawl, SHA pinning, Dependabot triage and PHP 8.5 partial scanning).
`overlays/` stays removed, as in Releases 1 and 2; the third merge's only conflict was a file under
`overlays/` that the trunk had changed, resolved by keeping it removed. The release tree equals the
trunk at `883f328` apart from `overlays/` and this file.

### Policy per scope, and crawl (KDEC-017)

- **A policy register per org, team, product and environment tier.** A central register
  (`policy/policy-registration.json`) and a repository's own file (`.security/policy-registration.json`,
  read from the protected branch) set the enforcement rung; precedence runs kit default < org <
  org+team < org+product < org+team+product < repository, with the environment tier above. The gate
  resolves the register first; an unreadable register fails closed. (`20ba090`, merged in `7515088`)
- **Crawl is the default everywhere** (owner ruling O-24): only a secret, or the kit being unable to
  run or trust its own scan, blocks; every other finding is advisory and routes
  `PROCEED_WITH_ADVISORY`. (`20ba090`)
- **The gate is the single enforcement point.** Scanner jobs now report their findings to the gate
  and fail only when they could not scan or cannot trust the result (a crash, `COLLECTION_FAILED`, no
  count); so at crawl an ordinary finding leaves every job green and `templates/build-deploy.yml`
  builds, while at `run` and above the same finding turns the gate red. A non-secret job that failed
  is now read as untrusted evidence, never as "the control fired", and `advisory_mode` no longer
  keeps a crashed job green. Image secrets and malicious dependencies still fail their own jobs.
  (`5b06ccb`, merged in `883f328`)
- **A secret may be excepted, one finding at a time, only by ticket.** A `secret_exceptions` item in
  the register names the finding's report fingerprint, a ticket reference (validated by the ticket
  reference gate), an explanation, a named approver, an unexpired date and, at uat and prod, the
  environment's reviewers. A missing element is refused by name (`SECRET_EXCEPTION_UNTICKETED`,
  `_UNATTRIBUTED`, `_EXPIRED`, `_NOT_FINDING_SCOPED`) and the secret still blocks; an expired
  exception blocks again; a class-wide softening of secrets stays `CHERRY_PICK_BELOW_FLOOR`. Only when
  every secret found is covered does the gate route `PROCEED_WITH_ADVISORY` with cause
  `SECRET_EXCEPTION_ATTRIBUTED`, and each applied exception is written to the gate summary and the
  run record. (`e4b0810`)
- **Deploy approval never falls below the default.** At uat and prod the deploy reads the
  environment's required reviewers and "prevent self-review" back and refuses without them, so a
  single-developer repository deploys on a non-self approver. (`20ba090`)
- **The gate emits the run record**, schema-valid, and refuses an invalid one (ledger L36).
  (`0cd48de`)

### Supply chain

- **Every remote action is pinned by commit SHA** with an exact-release comment (166 references);
  `tests/check_action_pins.py` refuses any `uses:` that is not `owner/repo@<40 hex> # vX.Y.Z`. The
  kit's own dogfood now requires pinning and the self-use weakening is removed (O-23). Dependabot
  reads the composite actions. (`4dfd858`, `db404f7`, merged in `8bf4913`)
- **Dependabot triage** (FUTURE_WORK §6): an update is auto-merged, through branch protection, only
  when the evidence shows it cannot change behaviour; anything material (a major version, a runtime
  or security-critical package, an action) goes to a human. (`4435750`, `c260892`, merged in
  `517eb79`)
- **Every FUTURE_WORK section traces to a completion-ledger row**, and
  `tests/check_future_work_traceability.py` fails when one does not. (`0b505d8`, merged in `7b4fea1`)

### PHP, a supported ecosystem (KDEC-016)

- **PHP moves from a declared coverage gap to a supported ecosystem.** Discovery finds `*.php`,
  `composer.json` and `composer.lock` under the same could-not-look-is-not-found-nothing and depth-8
  rules as the other ecosystems; a `composer.json` with no `composer.lock` beside it is a named,
  counted coverage gap (`PHPDependenciesUnlocked`), because the dependency scanner reads only the
  lock. The target PHP version is resolved from `.php-version`, then `config.platform.php`, then
  `require.php` (a constraint, never rounded), then the lock's platform entries, then a Dockerfile
  `FROM php:<v>`. (`f880b80`, merged in `7fe3d54`)
- **PHP SAST.** `sast-semgrep` adds `p/php` as a floor whenever discovery found PHP or could not
  say, beside the caller's own Semgrep configuration; it reports seeded SQL injection, cross-site
  scripting and command injection at ERROR. A PHP scan that examined no PHP file, or loaded no PHP
  rule, is `COLLECTION_FAILED`, never clean. (`f880b80`)
- **Composer dependencies through Trivy.** A `composer.lock` pinning a vulnerable package fails
  `deps-scan`; a clean lock passes. Dependabot's composer entry excludes the deliberately vulnerable
  fixtures. (`f880b80`)
- **The consumer path carries PHP.** The full fixture has 24 seeded signals (was 20), four of them
  PHP; a new PHP-only run (`consumer-path-negative.yml` with `scope=php`) asserts the gate's
  verdict on the PHP findings. The test repository registers no policy, so it runs at crawl: the
  verdict must be `PROCEED_WITH_ADVISORY` and green; above crawl, `BLOCKED` and red. (`f880b80`,
  verdict assertion `5b06ccb`)
- **The PHP range Semgrep reads is measured, not assumed.** A seeded PHP corpus holds one family per
  PHP release that added syntax (5.6, 7.0 to 7.4, 8.0 to 8.5), each checked with `php -l` under that
  release's official image and the release before, and an unparseable control.
  `tests/corpora/probe_php_corpus.py` reads Semgrep's result for each family, and a weekly hosted
  corpus job measures the job's own image. Shipped row: **READ 5.6 to 8.4**. (`8c4854b`, `a928010`)
- **PHP 8.5: scan what parses, flag the rest** (KDEC-016 as amended). Semgrep 1.178.0 and the
  newest release measured, 1.182.0, both fail to parse 8.5's `(void)` cast and `final` promoted
  properties (the pipe operator parses). Instead of refusing an 8.5 target, the kit keeps every
  finding from the files that parsed, names each file that did not
  (`PARSE_PARTIAL_PHP_SYNTAX`), and routes `COVERAGE_PARTIAL`, which is advisory. 8.5 is served by
  parse evidence (`parse_evidence_max`); a PHP release beyond it is still a proven version gap.
  (`e082419`, merged in `4831258`; `099e6cf`)

### One Semgrep release

- **Every Semgrep in the kit is 1.178.0.** The `sast-semgrep` job's container moves from the
  `1.90.0` tag (which read PHP only to 7.2, so 7.3+ syntax was exit 3 under `--strict` and failed the
  whole job) to the 1.178.0 image **pinned by digest**; the C# and Java jobs and self-test
  pip-install `semgrep==1.178.0`; validate-scanners' container probe, a new `semgrep-php` probe and
  the corpus probe run the same digest. The local Semgrep proofs fail if the release they run is not
  the job's. (`5569274`, merged in `f0fba61`)
- **A push no longer cancels a dispatched or scheduled run** of validate-scanners or the corpus
  probe; only push and pull-request runs cancel one another. (`5569274`)

### A slimmer flagship workflow

- **Six scanner jobs move into composite actions** reached through `$/`: `secret-scan`, `sast-cpp`,
  `iac-scan`, `deps-scan`, `sast-dotnet` and `sast-java`. The flagship `reusable-security.yml` goes
  from 460,924 to 338,021 bytes (about 461 KB to 338 KB; 342,047 bytes at this release with PHP
  added), well under GitHub's limit. Each move is pinned by
  `tests/prove_composite_move_equivalence.py`: the composite, expanded back into its job, has the
  same canonical digest as the job before the move. (`6ceaa63`, `aa9eea1`, `600995a`, `6501b41`,
  `3ee2948`, `208fb2c`, merged in `80d8eaf`)
- **No reader went blind on the move.** The dataflow tracer, the capability inventory, the
  kit-script digest count, the custody check and every step reader now read jobs through one
  composite-expansion rule; the tracer's output was byte-identical before and after, and
  validate-scanners also triggers on `.github/actions/**`, where scanner pins now live. (`6ceaa63`,
  `3ee2948`)

### Dependency-Check and the NVD database

- **The NVD database is built from the Dependency-Check project's NVD mirror by default**, in both
  the real NVD scan (`reusable-nvd-cve.yml`) and the validate-scanners probe. Cause, measured: the
  NVD API itself trickles (about 40 kB/s per 2,000-record page, about 207 pages for a cold build),
  so a cold build could not finish inside the job's limit with any version or key; the mirror
  builds the same database cold in about 1.5 minutes. A new input, `nvd_datafeed_url`, names the
  source; setting it to `""` restores the keyed NVD API. (`ef1458c`, merged in `71c8f6b`)
- **Dependency-Check 12.2.2, signature-verified, from the canonical repository.** The kit had
  downloaded from a separate repository whose releases stop at 12.1.0; it now fetches from
  `dependency-check/DependencyCheck`, pinned to the digest Maven Central publishes for the
  PGP-signed asset. 12.1.0 silently dropped CVE-2026-6785 and CVE-2026-6786 ("Value too long");
  12.2.2 fixes that and adds a read timeout. The probe and the real scan run the same version, digest,
  repository and datafeed (`tests/prove_validate_scanners_matrix.py` M9). (`ef1458c`)
- **A stalled update leaves evidence.** The probe's update step no longer dies silently under
  `bash -e`; an incomplete update records its last progress line, retried requests and HTTP
  statuses (M10). (`ef1458c`)
- Proven hosted on the trunk at `2cd078e`: validate-scanners 39743589679 built the database cold
  from the mirror in 2 minutes and the scan ran.
- **The probe's update sequence matches the real scan's**: it installs, restores a cached
  database from its own version-scoped namespace (complete, then partial), updates in the
  background under a budget with a heartbeat every 60 seconds, saves a complete or partial cache
  (keyed by run attempt), then scans warm with the real scan's arguments. (`bcc6978`, merged in
  `b463c7d`; the namespace re-keyed to 12.2.2 in `ef1458c`)
- **Earlier probe defects fixed on the way**: the leg had failed on every run because Dependency-Check refuses an
  `--out` with no parent directory, hidden by a usage dump (`778ce1c`, `144bb98`); the key now
  travels as one argument and only its shape is printed (`09a2986`); detection now means a SARIF
  file holding at least one result, not merely a file (`7e5ef03`); an unknown cache-restore outcome
  is reported as `UNKNOWN`, not as a cold start (`b463c7d`). The real NVD workflow's comment that it
  had "never run" was false and now cites both measured runs (`bcc6978`).

### Export and neutrality

- **Untracked files are never exported** (E8, carried from Release 2 and now proven with E9 beside
  it). **Generated files are regenerated from the copy** (E9): the exporter rebuilds each generated
  file inside the exported tree, from that tree, in full and incremental exports, and refuses if
  regeneration fails, so a generated file can no longer name something the export withholds; the
  exported copy passes its own proof census. (`1cf0422`)
- **Source-only controls say so in an exported copy** (E9): the export-safety check, the deny-sample
  proof and the export-scope proof guard the source and need the deny list, which an export never
  carries. In a copy recognised by its watermark and the list's absence, each prints
  `SOURCE-ONLY CONTROL` and exits 0, stating that nothing was checked there; in the kit each runs
  exactly as before. (`8c3f037`)

### Self-test and hygiene

- Release 2's `main` passed its own self-test on GitHub (run 39664610236 on `b634cff`).
- The self-test's "Normalizer drift" limit is 30 minutes (was 15), from three measured runs.
  (`17b243f`)
- A shell variable read as an unregistered vocabulary word is renamed to mixed case, as the
  taxonomy check prescribes. (`8478400`)
- Hosted on the trunk at `f0fba61` (the tree of `09a22a8` apart from one decision record): self-test
  39701219662 green; the corpus probe 39701219513 green, including the PHP corpus on the 1.178.0
  image; validate-scanners 39701219505 green on the `semgrep-php` and `semgrep-container` probes.
- The continuity check counts work commits only: merges and commits that change only these release
  notes no longer count against the context's reconciliation limit, so a release candidate is not
  read as unreconciled work; real work beyond the limit is still refused. (`2cd078e`)
- Hosted on the trunk at `2cd078e`: self-test 39743586463 and validate-scanners 39743589679 green.

### Known limits

- **PHP 8.5 is partially scanned** (above): a file using the `(void)` cast or `final` promoted
  properties is named, not scanned, until a Semgrep release reads it.
- **Not yet run on GitHub** (Actions minutes for the private repository ran out): the self-test,
  validate-scanners and the consumer path on the trunk from `4a787c7` on; a crawl run with an
  ordinary finding that builds; a run with a register secret exception; a uat/prod deploy against
  protected and unprotected environments; the first Dependabot github-actions update. Every lane
  passed its own failing-first proofs and the full local sweep.
- **Dependency-Check does not read a bare `pom.xml`.** The database now builds (cold, from the
  mirror, in 2 minutes on a hosted runner) and the scan runs, but the Dependency-Check CLI reads no
  dependencies declared only in a standalone `pom.xml` with no JAR, so the probe's seeded Maven
  dependency is not detected by it (a JAR carrying the same coordinates is). Trivy's dependency
  scan covers Maven source manifests. The probe's detection stays under its dated acceptance until
  2026-11-30.
- **The consumer path on this release is owed**: the full run at 24 signals, the default negative
  and the `scope=php` negative have not yet run on GitHub for Release 3's head.
- **The sidecar channels of Checkov, Trivy, cppcheck and flawfinder are not read** (Semgrep's
  is): Checkov parse errors, Trivy's empty result count, cppcheck's checkers report and
  flawfinder's line counts (completion ledger L03).
- **Seeded corpora exist only for PHP, Checkov and Trivy-config**; the other scanner version ranges
  stay `UNVERIFIED` and are never selected (ledger V-02).
- Unchanged from Release 2: a real gate verdict feeding a deploy in one pipeline, a hosted
  establish-then-propose ledger run, Azure DevOps ticketing live, the rung ladder in the gate, and
  container images still referenced by tag (gosec, gitleaks), and the dated deferrals for attestation
  signing, change detection and the Terraform toolchain (2026-12-31).
- **Documentation lag**: a few documents still describe the NVD workflow's CVSS threshold as it was
  before Release 2; the shipped default is 9.0. `tests/check_doc_currency.py` lists each such line
  as known-stale until 2026-11-15.

## Release 2

Built on `release/main-candidate-2` from Release 1 (`ef4b15d`) and the trunk through `25f14d3`.
`overlays/` stays removed, as in Release 1; a consumer's own ticket-number range for the Jira
reference gate stays in that consumer's overlay, and the core gate ships with no range.

### Deploy and release

- **The starter template hands deploy the combined verdict** (security and policy together) instead
  of the security verdict alone; the deploy binds to the GitHub environment's `KIT_*` values and
  refuses a mismatched target; attestation verification runs inside both deploy reusables; NOW SERVING
  is read from production's own start record; a staging-slot swap stamps which run owns it; live
  acceptance enablers. Proven on a sandbox subscription: a healthy Container Apps deploy with
  provenance tags, a production deploy refused before any change when rollback was disabled, and a
  healthy direct App Service deploy. (`11d1d56`, live runs recorded in `25f14d3`)
- **Version gaps at uat and prod (KDEC-014).** The security gate names the cause of every advisory
  (`advisory_causes`). At uat and prod a deploy refuses an advisory caused by a proven version gap,
  unless a named person accepts it through the existing weakening record (authority, reason, an
  unexpired date) and the environment's required reviewers approve. The deploy's verdict step always
  writes one ruling, and an absent ruling routes the deploy `EVIDENCE_UNTRUSTED`. (`3830edb`,
  `078ef90`)
- **Version-gap enforcement is on for infrastructure as code.** Seeded Terraform corpora establish
  the ranges Checkov and Trivy-config can read; a gap counts as proven only when every candidate's
  established range answers that it cannot read the version. A hosted corpus probe re-measures on
  change, and the registry cites its run. (`272fe71`, `37e4e77`, `939cfc3`)

### Findings, ledger and ticketing

- **A finding baseline is established only by an approved pull request** under code ownership; one
  move record; the ticket ledger persists; a scanner-generation check; per-environment presence.
  (`a0e8b16`)
- **Ticket updates never erase human-written text**; reopen classes; least-privilege sweep; a
  degraded-streak signal; delta updates. Proven against a personal Jira site. (`85bd33d`)

### Scan validity

- **Hollow-scan handling follows per-tool profiles**: a clean Bandit run is not hollow. Semgrep runs
  with `--strict`, and its exit 3 is `COLLECTION_FAILED`. The CodeQL autobuild outcome is read and
  reported. Discovery searches to depth 8 and names what lies beyond it. (`a279f5a`)
- **The assurance dataflow trace reads `env:` and `needs`** (31 to 120 hand-offs traced); ten real
  defects it then found are fixed, including a silent rollback-capability step that both deploy
  reusables read as "rollback available" (now `UNAVAILABLE`). (`a279f5a`)
- **Scanner registry hygiene; NVD `fail_on_cvss` defaults to 9.0** with the decimal comparison
  fixed; the proof census and stage register are checked; size and bundle gates measure what GitHub
  actually loads; validate-scanners fails on a missing probe and runs as a matrix; workflow policy
  checks job-level `uses:` and images; branch-protection profiles require the gate and policy checks.
  (`58dce0d`)
- **Real SARIF fixtures**; Dependabot paging; toolchain advice. (`272fe71`) Dependabot no longer
  touches the deliberately vulnerable test fixtures. (`754f80d`)

### Export and neutrality

- **The export gate and the safety check agree**; every deny pattern carries its own positive and
  negative samples (`tests/prove_deny_samples.py`); the export profile is bound to its destination;
  the export watermark keeps the commit and drops the branch name; the proof census runs outside the
  kit. (`a279f5a`)
- **Untracked files are never scanned or exported**, ignored or not. (`904bc7a`)

### Documentation

- `docs/assurance/COMPLETION_LEDGER.md`: the designed-versus-built map, 202 rows. (`d107fe9`)
- `docs/assurance/RELEASE_1_EVIDENCE_MANIFEST.md` and its two further parts: what Release 1 proved,
  with run ids. Consumer documents made true to the code. (`f01ef04`)
- The builder explainer to v1.12, in parts each under 20 KB, with part 12 listing every change since
  v1.10. (`f01ef04`, `6feaf82`, `8ca6bb0`)

### Still owed

Unchanged by this release and carried as dated deferrals: attestation signing, change detection and
the Terraform toolchain (2026-12-31). Not yet run: a real gate verdict feeding a deploy in one
pipeline, a hosted establish-then-propose ledger run, Azure DevOps ticketing live, and SHA-pinned
actions (the self-use weakening expires 2026-10-31). The rung ladder is not yet wired into the gate
(`wiring/gate-rung.patch.md` unapplied; `tests/prove_gate_reads_rung.py` still fails by design and
is accounted for in `tests/check_selftest_coverage.py`); nor are the SLA and cost-packing work that
KDEC-007 also scheduled after Release 1.

## Release 1

`ef4b15d` (pull request #3): a correct scan, gate and verdict; finding identity and the ledger; Jira
and Azure DevOps ticketing with the Jira reference gate in the core; provenance; and deploy with
rollback, proven end to end. No consumer overlay.
