# Release notes

Each release of `main` is built from a release-candidate branch, never directly from the development
trunk: the candidate merges the trunk and keeps every consumer overlay off `main`, so the neutral kit,
and the public export generated from it, carry no consumer-specific material. Each entry names the
trunk commit that brought the change.

## Release 5

Built on `release/main-candidate-5` from Release 4.1 and its Dependabot merges (`62cae61`) and the
development branch, merged with `--no-ff` through **`d0a8ba4`**. Two content conflicts
(`self-test.yml`, where the trunk's KDEC-038 wiring sits beside the triage-permissions line, and the
continuity record) were resolved to the development branch's text; the two modify/delete conflicts
under `overlays/` were resolved by keeping those files removed, and every overlay file the branch
carries was removed again. `git diff d0a8ba4 HEAD -- . ':(exclude)overlays'` shows this file and
`main`'s own Dependabot bumps (#12 the deploy-probe base image, #14 the action pins) that the trunk
did not yet carry.

### What is in it

- **KDEC-038: SAST and secret findings are ticketed.** bandit, semgrep and CodeQL findings get a
  deterministic key (a rule-family alias table, a code location read from the checked-out commit, never
  the line number); one ticket per issue across tools; a secret is an urgent ROTATE ticket keyed on a
  non-reversible fingerprint and never closed by its absence; an unknown rule is refused by name
  (`tests/prove_sast_secret_tickets.py`). (`e24354f`..`311b7bd`)
- **KDEC-039: `evidence.export`.** A kit API read that produces the kit's half of the per-app evidence
  bundle; the security record carries the KEV verdict, the SBOM digest and the commit author
  (`tests/prove_evidence_export.py`). **A kit-api caller must grant `deployments: read`** before it
  bumps its pin past this release, or every call fails at startup. (`0142e1b`, `463ea98`)
- **KDEC-040: the consumer experience.** The local battery in the repository (`tools/battery.py`);
  positive controls beside negative ones (`docs/assurance/POSITIVE_NEGATIVE_MATRIX.md`); Dependabot
  keep-current and a configuration check; SonarQube and Aikido findings pulled read-only into the
  intake, submitted only behind the `external-findings-review` environment; one id normaliser; unknown
  ids logged and routed to a person; every register entry carries suggested mitigations; a
  dispatched run is paired by its correlation id (the consumer path test's race is fixed);
  `verify-azure-oidc` signs in to Government. (`cec8438`..`e03b1a4`)
- **KDEC-041: adoption.** `kit init` (`scripts/kit_init.py`, `templates/kit-init.yml`) wires a
  repository in one pull request; every refusal is said in plain English first
  (`docs/errors/ERRORS.md`); the rollout plan, the pilot friction log and the 1-hour guide.
  (`f306ae1`, `54de048`)
- **`JIRA_HOST` in either form.** The bare host or `https://<site>`: the reference check drops the
  scheme, the ticket jobs add it, so one value serves both (`prove_ticket_reference_gate.py` G11,
  `prove_jira_host_secret.py` H7). (`10e19d7`)
- **Three hosted-only test defects** found by the candidate's first public self-test (42317591967) and the
  local copy battery: `prove_dispatch_correlation.py`, `prove_register_mitigations.py` and
  `scripts/check_register_mitigations.py` are SOURCE-ONLY by name in an exported copy (the withheld
  consumer-path workflow; no `.context/`), held by `prove_export_scope.py` E9. (`fd02f2d`, `d0a8ba4`)
- Architecture diagrams ARCH-01..07, instruction fixes, the triage-permissions fix restated on the
  trunk. (`ca5a205`, `1b4229a`, `2d3031c`)

### Caller migration

- `kit-api.yml` callers: add `deployments: read` to the jobs that call `reusable-kit-api.yml`.
- Deploy callers (`deploy`, `deploy-dev`, `deploy-test`, `promote`): `deployments: write` and
  `pull-requests: read` (unchanged since Release 4).
- `templates/kit-init.yml` needs the repository secret `KIT_INIT_TOKEN` only to open its PR itself.

### Where Release 5 is proven

The hosted runs of this tree's neutral export (public mirror, branch `release-5-candidate`) and of
this release PR are listed in the PR's description; no run on a GHE.com host exists yet.

### Owner decisions owed

O-38a..O-38e, O-39a..O-39c, O-40a..O-40c, O-41a..O-41d (the continuity record's decisions file);
R-23 (Dependabot and the Actions bot) and R-24 (the vendor fields) are UNVERIFIED until the first
real runs.

## Release 4

Built on `release/main-candidate-4` from Release 3 (`45b620f`) and the development branch, merged
twice with `--no-ff`: first through `cbf49f1` (`acce433` plus the three hosted-only test fixes
below), then through **`9ba5ab7`** (the additions in "Second cut" below), with `main`'s Dependabot merge
(`f57615d`) brought in and its fixture bump reverted. Seven
content conflicts came from Release 3's own NVD wording on `main`, and each was resolved to the
development branch's text. The three modify/delete conflicts under `overlays/` were resolved by
keeping those files removed, and every overlay file the branch added was removed again.
`git diff 9ba5ab7 HEAD -- . ':(exclude)overlays'` shows only this file.

### Second cut (`cbf49f1..9ba5ab7`)

- **E12 is SOURCE-ONLY on a release tree.** `main` keeps `overlays/` out, so the consumer-am export
  cannot be built there; E12 now says so by name instead of failing every release PR (private
  self-test 41901549538 on PR #11). (`c7b1977`)
- **The Jira host may be a secret.** `reusable-ticket-reconcile`, `reusable-kit-api` and
  `reusable-exception-due` read `secrets.JIRA_HOST || vars.JIRA_HOST`, declare JIRA_HOST as an optional
  secret, and every template passes it; no message carries the host's value
  (`tests/prove_jira_host_secret.py`). (`0c233b5`)
- **Azure Government sign-in asks for `api://AzureADTokenExchangeUSGov`** at every Gov-capable
  `azure/login` (nine sites and the `azure-login-oidc` composite), overridable for gov only by
  `vars.KIT_AZURE_OIDC_AUDIENCE`; commercial unchanged (`tests/prove_azure_gov_audience.py`,
  SETUP.md section 4.2). UNVERIFIED: a live Government sign-in. (`022f343`, `70dece3`)
- **Dependabot**: the owner's triage strategy runs on the kit itself, Dependabot bumps pass Normalizer
  drift, and every push to `main` runs the whole self-test. (`59a0949`..`6311134`, the Dependabot lane)
- **A dependency finding is keyed when its manifest names the registry.** Found running the Release 4
  end-to-end: Trivy's SARIF carries no purl, so every dependency finding was refused and nothing was
  ticketed. The purl is now built from the labelled package and version and the ecosystem the
  manifest's file name fixes (a fixed table); an unknown manifest still refuses
  (`tests/prove_dependency_purl_from_manifest.py`). For the owner to confirm: this widens which
  dependency findings are ticketed. (`22c7e66`)
- The capability inventory regenerated. (`fd7cf43`)
- **The fixtures' vulnerable pins are held.** Dependabot PR #10 bumped phpmailer 5.2.18 -> 6.5.0 in
  `tests/consumer-fixture/full/php` and was merged to `main`, removing the seed of `deps:php-cve`.
  `tests/check_fixture_seed_pins.py` (Normalizer drift, required) now holds every fixture manifest
  to `tests/consumer-fixture/SEED_PINS.json`; this release restores 5.2.18. (`9ba5ab7`, `a19564d`)

### Where Release 4 is proven

- **Hosted, at the second cut**: the neutral export of `fd7cf43` (public `3f2d88e`): self-test
  **41956214131: success**. The export of `70dece3` (public `42ffdd4`): self-test 41945242125: success.
- **The end-to-end ticket flow on the public mirror** (environment `ticketing-e2e-r4`, the owner's
  personal Jira, the host held as a secret and masked in every log): see the lane report. The
  kit's scans filed TEST tickets (scan 41956255071, ten tickets, the creation ceiling holding four);
  a second scan bound to the same tickets, creating none (41957417989); the fixer's resolve went to
  pending verification through the kit API (41957819417). Closure by rescan and "fix observed" need
  the ticket ledger, which only the default branch persists, so they were not run on the mirror;
  the duplicate sub-task, trust and confidence, and the verify by someone other than the fixer ran
  on the personal Jira with a STAND-IN second identity (`live_ticketing_run.py --phase r5`, HELD).
- **Hosted, on the public mirror**: the neutral export of `cbf49f1`, with no profile and no overlays,
  sits on `release-4-candidate` (draft PR #12). Every workflow it triggered was green: self-test **41897567200** (success: 13 jobs green, 10 skipped by design on a pull request -- the inner jobs of the hosted negative controls) and Automatic Dependency Submission **41897547314** (success), on public commit `38a590d`. The first candidate (`83f566d`, the export of `acce433`) failed self-test 41885418827, which found the three fixes below.
  These runs cover:
  - the kit API's hosted refusal control;
  - the ticket intake v1 and v2 proofs (stand-ins and offline);
  - the reviewer-gaps signals (`prove_reviewer_signals.py` on Linux);
  - the GHE.com host proofs (`prove_ghe_host.py`, `prove_job_token_named.py`);
  - the docs-markup proof (`prove_docs_no_tool_markup.py`);
  - the consumer-path pre-flight's verifier half.
- **Not proven hosted:** the pre-flight's workflow half (C1, C2 and C4). A neutral export withholds
  `consumer-path-test.yml`, so in the copy those checks say SOURCE-ONLY by name. They passed on the
  source at `cbf49f1` locally.
- **Locally**: the kit battery at `cbf49f1`:
  - actionlint 1.7.7;
  - `check_expression_length`, `check_workflow_size`, `check_export_safety`, `check_context_current`
    and `check_selftest_coverage`;
  - the full clean-tree sweep: passes (`prove_tests_leave_tree_clean.py`): 204 tests clean with exit 0, 11 UNKNOWN (exit 2: a scanner or tool this Windows host lacks; they run hosted), 3 skipped as runtime tools, none failed.
- **Live (personal trackers only), from the lanes**:
  - the ticket templates' R-4 on the owner's personal Jira;
  - v2's R-5 on Jira and GitHub Issues.
  The live end-to-end ticket flow on the public mirror is prepared but not yet run, because it needs
  secrets that only the owner sets.

### The kit's API (KDEC-035, proposed)

- Another program calls the kit by dispatching a repository's `kit-api.yml` with a v1 request
  (`api/v1/`). The answer comes back in the check run `kit-api/<correlation id>`.
- Tickets are written, read and searched through the kit's own reconciler, so there is one ticket per
  finding across the API and the pipeline.
- Findings are read from a run's evidence. KEV is never false.
- A scan can be requested.
- A release is the repository's own `build-deploy.yml`, called (it gained `workflow_call`), with
  every gate and a human approver.
- Client: `scripts/kit_api.py`. Run side: `reusable-kit-api.yml` and the `kit-api` composite.
  Docs: `docs/api/`.

### What a security reviewer could not see (KDEC-036, proposed)

- **A weakening is approved only with all five fields**:
  - an evidence reference;
  - a reason;
  - a named owner;
  - an expiry within the ceiling (default 90 days);
  - an approver on a registered list who is not the requester (`weakening_approver`, a new input).

  If any field is missing, the result is `WEAKENING_NOT_APPROVED`, naming the field. At crawl the run
  proceeds, but every deploy refuses it. If the requester, the actor or the release's author is the
  owner or approver, the result is `WEAKENING_SELF_APPROVED`, which blocks everywhere. This also
  tightens KDEC-014's version-gap exception and KDEC-029's break-glass at uat and prod.
- The deploy reads its gate's `kit-security-record`. The possible results are `VERDICT_FROM_GATE`,
  `MANUAL_REVIEW_VERDICT`, `TYPED_VERDICT` and `VERDICT_CONTRADICTED`.
- Each release gets a durable GitHub deployment record when the lease is off.
- Evidence retention is floored at 90 days.
- The kit copy's watermark is read at run time.
- The run records the tier's source and reality.
- Readiness comes from the landing zone or AppSec's `.kit/zone-readiness.json`, and is never self-set.
- `NO_KIT_ADAPTER` is named.
- Functions run as a container through the App Service reusable.

### Ticket intake (KDEC-037, versions 1 and 2)

- External findings come in through templates, and only after a finalized, human-concurred review.
  Every ticket is searched before a create, manual tickets included.
- Separation of duties: the approver is from a list or a GitHub team, and the review is `AGREE` or
  `DISAGREE` with an alternative.
- Closure has three steps:
  - resolve: pending verification;
  - verify: by someone other than the fixer, or by the kit's rescan on the branch mapped to the
    ticket's environment; a clean scan on any other branch records "fix observed";
  - reject.
- Dedupe v2:
  - an exact match becomes a closed duplicate sub-task under the original;
  - a regression reopens the original;
  - a near match is created in triage;
  - a search that did not complete marks the ticket dedupe-pending;
  - a durable outbox keeps every item, so none disappears.
- Trust is shown beside confidence.
- **The exception taxonomy** is exception, exemption, accepted-risk and compliance-exception. The
  reconciler's exception mapping was fixed.
- Also: extensions and the no-fix clock; Azure DevOps and GitHub Issues intake adapters; 14 proposed
  ticket types, disabled; the branch-scan proposal.

### Change-review security docs

- `docs/security-review/` holds the reviewer's checklists and the procedure for one change request.
  It covers app and cloud checks as guided conversations (Azure, AWS, GitHub), escalation and
  adoption review.
- Stray authoring-tool markup was stripped from the docs. `tests/prove_docs_no_tool_markup.py` holds
  that in place.

### Also since Release 3 (in this release)

- KDEC-029: build once and promote the same digest.
- KDEC-030: release targets are shared by field with the landing zone, with one cross-repository
  lease per target.
- KDEC-031: leak gates are recorded on every run.
- KDEC-032: organisation-hosted feed mirrors, off unless configured.
- KDEC-033: the cost redesign: dynamic CodeQL, plan and report jobs, the protected capability floor,
  and the "Self-test required" check.
- KDEC-034: the landing zone's stronger release steps.

### Migration impact

- **Deploy callers must grant `deployments: write` and `pull-requests: read`.** These are for the
  durable release record and the readiness attestation's approving review. Without them, GitHub
  refuses the run at startup.
- **Weakenings now need all five fields.** Any record without an expiry, an evidence reference or a
  listed approver who is not the requester is `WEAKENING_NOT_APPROVED`. Uat and prod deploys refuse
  it. Register an approver list (`approver_lists`) in the central register before relying on an
  exception.
- **The exception taxonomy has changed**: exception, exemption, accepted-risk and
  compliance-exception. Check any tooling that read the reconciler's old exception mapping.

### Fixes found on the hosted runners (`cbf49f1`)

- `prove_job_token_named.py` T9 and `prove_consumer_path_preflight.py` C1 to C4 read
  `consumer-path-test.yml`, which a neutral export withholds. In such a copy they now say SOURCE-ONLY
  by name. `prove_export_scope.py` E9 runs both inside the exported copy, and failed first.
- `prove_reviewer_signals.py` named `github_api_url` and `github_sha` in lower case. Windows reads
  environment names without case, but Linux does not, so the runner's own values won there. The
  harness now uses the runner's spelling. The test was red under Linux first.

## Release 3

Built on `release/main-candidate-3` from Release 2 (`b634cff`) and the trunk through `4060290`
(first cut at `09a22a8`, re-cut at `2cd078e` to carry the NVD fix, at `883f328` to carry the policy
register, crawl, SHA pinning, Dependabot triage and PHP 8.5 partial scanning, at `c7e1ea9` to carry
the crawl floor and exception resurfacing, the enterprise floor for unmapped orgs, the sequential
rollback and the fixes found running the candidate on the public mirror, and again at `4060290` to
carry KDEC-022 to KDEC-028 and the two hosted-only fixes; `4060290` is the export under test at work).
`overlays/` stays removed, as in Releases 1 and 2; the fifth merge's only conflicts were four files
under `overlays/` that the trunk had changed, resolved by keeping them removed, and the overlay files
the trunk added were removed again. The release tree equals the trunk at `4060290` apart from
`overlays/` and this file.

### Where Release 3 at `4060290` is proven

- **Locally**: the full kit battery on this tree passes every check that does not read an overlay
  (34 of 36); the two that fail are the overlay's own proofs (`prove_overlay_crawl.py`,
  `run_jira_step.py`), absent here by design, as at `c7e1ea9`. The guard check and proof the last
  trunk commit changed (`check_action_manifest_flow_scalars.py`, `prove_known_exploited.py`) pass.
  The clean-tree sweep (`prove_tests_leave_tree_clean.py`) passes: 182 tests clean, 3 skipped as
  runtime tools, none failed.
- **On the private repository**: pull request #8's checks for this head. The cross-edited rollback,
  exception resurfacing and the Jira cross-check, the strictest-org floor and test-versus-real
  ticketing have no live run on this branch yet.
- The fetch-depth fix this candidate carried alone at `0339aa4` reached the trunk as `afa0bcf`; the
  two are identical, so the self-test here is the trunk's.

### Strictest org, exception history, exploited in the wild (KDEC-022)

- **No enterprise entry: an unknown org runs at the strictest registered org**, tier by tier, never
  below it and never below crawl; notice `ORG_UNMAPPED_RAN_AT_STRICTEST_ORG`. This answers KDEC-020's
  open question. (`9bca02d`)
- **Exception renewal history is derived from git** (`git log --follow` of the protected register):
  a `renews` list shorter than git shows is `EXCEPTION_HISTORY_TAMPERED`; a history git cannot show
  is `EXCEPTION_HISTORY_UNVERIFIED`, never zero. The weekly `exception_due.py --cross-check` holds
  each exception's Jira ticket to the register (option D). (`e76413c`)
- **A CVE on the CISA KEV catalog blocks at every rung**, crawl and advisory mode included
  (`FINDING_KNOWN_EXPLOITED`), exceptable only by a register `known_exploited_exceptions` item; the
  catalog is read once per run and pinned in the evidence. Known-malicious (`MAL-`) packages keep
  blocking in every mode, which answers KDEC-020's other question. (`9ba89fb`, `6b47542`)

### Cross-edited rollback (KDEC-023)

- **Every resource a rollback touches has a class** (`rollback-resource-classes.yaml`): on a shared
  multi-config resource only the product's own entries move; a stable resource changed by something
  else halts for a human. A dependency review and graph go with every rollback, and an incoming
  deploy after a rollback of its target is dependency-checked. (`66f60ee` red, `a125328`)

### Ticketing matured (KDEC-024)

- Findings reach the reconciler; the clock runs on a schedule; a ticket closes only on positive
  clearance evidence and comes back as `RECURRED`; one ticket per finding identity across scanners;
  disagreement and SLA by severity escalate; every run is idempotent and bounded. Auto-close names
  the fix (commit range, UTC time, run, verifying scanner versions, finding). The live R-3 phase ran
  on the personal Jira. (`074bc6d`, `0f907e7`, `c2d2457`, `cd10e8b`, `9bb5bce`)

### Scanner coverage (KDEC-025, KDEC-026)

- **Consumer workflows, shell, PowerShell and Dockerfiles are linted** (actionlint, zizmor,
  shellcheck, PSScriptAnalyzer, hadolint) inside jobs that already run, every tool pinned by version
  and sha256; pip-audit, npm audit and tflint are closed by existing scanners, with measurements.
  (`9838776`, `7e189a3`)
- **Kotlin/Android, Swift/Objective-C, build-aware C/C++ and a real .NET solution are scanned**
  (mobsfscan plus kit rules, a compilation database only when the consumer has one, no macOS
  runners); Semgrep exit 3 maps to `COLLECTION_FAILED`. (`126afb2`, `58bb318`, `89d7a93`)

### GitHub Enterprise Cloud with data residency (KDEC-027)

- **`<tenant>.ghe.com` is a supported host.** Action refs resolve by git with no token; a run's token
  goes only to the API host that issued it; `pin-actions.sh` reads public actions from github.com
  without a ghe.com token; Trivy is a pinned binary, not trivy-action; GHAS-dependent steps degrade
  visibly; every `$GITHUB_OUTPUT`/`$GITHUB_ENV` write of external text is single-line.
  (`686431b`, `8f5ecf4`, `8b64f97`, `3fdb59f`, `466f83a`, `bd59985`)

### Jira bearer, ticket routing, test ticketing (KDEC-028)

- **External evidence intake is neutral**: an overlay scanner that runs before the core leaves
  evidence the core report, gate and tickets read. The overlay itself (Sonar, ZAP, WordPress and the
  consumer template) stays off this branch.
- **`JIRA_AUTH_MODE=bearer`** sends the token alone, with no personal binding.
- **`ticket_routing`** on any register entry routes by class, scanner, category, severity and
  repository; routing a secret, KEV or malicious class to `"none"` is `TICKET_ROUTING_BELOW_FLOOR`.
- **Test ticketing is chosen by the branch**, with no switch: the default branch tickets the real
  project, other branches a sandbox; a test run aimed at a real project is
  `TICKETING_TEST_TARGETS_REAL_PROJECT`. (`6db6dbe`, `c7bd52a`, `274ae4d`)

### Fixes found on the hosted runners

- **The known-exploited action loads on GitHub again**: two flow-mapping descriptions holding a
  colon are quoted (PyYAML read them, GitHub's manifest parser refused the action, so every
  consumer's gate failed to load it); the new `tests/check_action_manifest_flow_scalars.py`, wired
  into the self-test, fails on the unfixed manifest. (`4060290`)
- **`prove_known_exploited.py` builds its scratch path from `dirname(cache)`**, which resolves on
  Linux before the cache exists. (`4060290`)
- **The normalizer-drift job checks out full history** (`afa0bcf`, as this branch's `0339aa4`).
- Docs: non-human identities in Entra and Azure (`edd9057`); KDEC-022 brought into the policy register
  guide and explainers (`6b47542`); `.context` restated at `5ccf1a8`.

### Where Release 3 at `c7e1ea9` was proven

- **Locally**: the full kit battery on this tree passes every check that does not read an overlay
  (34 of 36); the two that fail are the overlay's own proofs (`prove_overlay_crawl.py`,
  `run_jira_step.py`), absent here by design. On the trunk at `c7e1ea9`, with the overlay, all 36 pass.
- **On the free public mirror** (`secure-cicd-kit-public`, branch `release-3-candidate` at `f0b138d`):
  9 checks pass, 0 fail; validate-scanners run 39959026371 is green, 17 of 17 jobs.
- **As a consumer**: hello-world pull request #7 calling the kit: 28 checks pass, and the Security
  gate fails only on the secret planted in it, as designed.
- **Owed on the private repository**: the hosted self-test and the consumer path for this head; no
  live run of the sequential rollback, of exception resurfacing to Jira, or of an unmapped org under
  an enterprise register. validate-scanners now runs on push only on `main` (below), so on this
  candidate it runs on the public mirror or by dispatch.

### Crawl is the floor; the authority's rung binds (KDEC-018)

- **Nothing runs below crawl, and the highest authority's rung is the floor beneath it.** A new
  enterprise scope sits above org; an org entry binds every team, product, repository and tier in it.
  Narrower scopes may only tighten: an entry below the authority's rung is refused,
  `POLICY_BELOW_AUTHORITY_FLOOR`. The secret scan always covers the repository root. (`5641257`,
  merged in `0386d7f`)
- **Exceptions show their history and renewals are capped.** A renewed exception names what it
  `renews`, so when, by whom, on which tickets and how many times it was excepted is shown;
  `numbers.max_exception_renewals` (default 2, adjustable 0 to 5) caps renewals,
  `EXCEPTION_RENEWAL_LIMIT`. (`d0aa66f`, merged in `0386d7f`)
- **Exceptions resurface when they come due.** `scripts/exception_due.py`, run by
  `reusable-exception-due.yml` on a schedule (starter `templates/exception-due.yml`), raises every
  exception coming due or expired back onto its Jira ticket. (`c7f8725`, merged in `0386d7f`)
- **A ticket key ends where its number ends.** The ticket reference gate had read `WORK-123abc`,
  `WORK-1234X`, `WORK-1234_` and `WORK-0123` as references; a run-on word character or a leading zero
  is now a malformed key, named and refused. (`c106ca9`, merged in `a328ebb`; `6be79e0`)

### Unmapped orgs and the malicious-package scan (KDEC-020)

- **An org the central `orgs` map does not name runs at the enterprise floor** (the strictest
  enterprise level when there are several), never refused and never silent: the run carries the
  notice `ORG_UNMAPPED_RAN_AT_ENTERPRISE_FLOOR`, naming the enterprise and level. This corrects
  KDEC-019 item 1, which was recorded and briefly built backwards as a refusal
  (`ORG_NOT_UNDER_ENTERPRISE`, `26ca9e8`, merged in `e9ba7ba`); that refusal is retired. (`5c1b090`)
- **The malicious-package scan is part of the crawl floor.** Turning `enable_malicious_pkg_scan`
  off, or softening `malicious-deps` in the register, is refused as below crawl,
  `CHERRY_PICK_BELOW_FLOOR`; the consumer-path workflows no longer pass it false. Whether a confirmed
  `MAL-` hit blocks at crawl is an open owner question; it blocks today, as built. (`5c1b090`)

### Sequential rollback (KDEC-019 item 4, KDEC-021)

- **Several deployments roll back in reverse order, tested between every step.**
  `scripts/rollback_sequence.py`, `reusable-rollback-sequence.yml` and
  `templates/rollback-sequence.yml` reverse each eligible step and run the health probe and the
  application's end-to-end tests after it; any failure halts for a human on the last state reached.
  A sequence with no e2e command is refused, `ROLLBACK_SEQUENCE_REFUSED_NO_E2E`. (`e9ba7ba`)
- **A test period after every step** (KDEC-021): the probe and e2e tests run at its start, at each
  interval if set, and at its end; default 15 minutes, bounded 0 < m <= 240, a period of 0 refused
  (`ROLLBACK_SEQUENCE_REFUSED_NO_TEST_PERIOD`), under 15 a recorded weakening. (`a0c93c4`, merged in
  `6cc1a0f`)
- **App Service slots return to the requested version** (`target_version`), read back live; a slot's
  prior stamp is recorded and restored, so stacked slot-and-swap releases reverse. (`a0c93c4`)
- **Deploys to a target are frozen while it rolls back**: one shared concurrency group per target
  (`kit-target-<env>-<rg>-<name>`) across both deploy reusables and the rollback; a kit deployment
  that lands anyway is rolled back first with its own test period; a non-kit change halts for a
  human. Proven locally against the stub cloud only. (`a0c93c4`)

### Fixes found running the candidate on the public mirror

- **The secret scan counts only the consumer's files again.** Since `5641257` the kit's own rules
  file, history log, report and staged binary were written into the scanned root, so an empty
  repository read as "1 file scanned, 0 secrets"; they now live in `RUNNER_TEMP`, the root
  `gitleaks.sarif` is excluded by identity, and an empty repository is `COLLECTION_FAILED` again
  (ledger L04). (`118904f`, merged in `0a066d4`)
- **yamllint padding fixed**, and the local battery runs the self-test's own yamllint config.
  (`acbe461`, merged in `a31c0a6`)
- **A comment naming a file is not reach.** The stage register's negative control had passed because
  a comment cited the design note; comments are now ignored, and the sweep fails a test that exits 1.
  (`5c9b8d7`, merged in `a31c0a6`)
- **The Semgrep container probe legs pull with retry and keep their evidence**, after a refused pull
  read as `COLLECTION_FAILED` on the public mirror. (`76ef449`, merged in `a31c0a6`)
- **`check_context_current.py` is a source-only control in an exported copy** (E9): an export ships no
  `.context`. (`2d0a34d`)
- **validate-scanners runs on push only on `main`**: the private repository pays for every minute;
  branches validate on the free public mirror or by dispatch (M12). (`a87f8e4`, merged in `3a6233d`)

### Documentation current at source

- The explainer, roadmap, capability inventory and validation debt are made current against
  KDEC-017 to KDEC-021 (F-21). (`424a9a3`, `15a6d13`, `b8a4a67`, merged in `3a6233d`)
- The remaining explainer and wiring-guide lags are fixed at source: ticket backends, the KDEC range,
  deploy and rollback grants, IaC ranges, crawl blockers, `policy_notices`, wiring refusals and export.
  (`e1f878e`, merged in `c7e1ea9`)

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

- **The NVD database is built from the Dependency-Check project's public datafeed by default**
  (`https://dependency-check.github.io/DependencyCheck_Builder/nvd_cache/`), in both
  the real NVD scan (`reusable-nvd-cve.yml`) and the validate-scanners probe. **This is not an
  organisation-hosted mirror, and NVD is not covered beyond it**: the datafeed is a third-party
  host, the runner needs egress to it, and the database is only as current and as available as that
  feed. An organisation mirror is planned for Release 4. Cause, measured: the NVD API itself
  trickles (about 40 kB/s per 2,000-record page, about 207 pages for a cold build), so a cold build
  could not finish inside the job's limit with any version or key; the datafeed builds the same
  database cold in about 1.5 minutes. A new input, `nvd_datafeed_url`, names the source; setting it
  to `""` restores the keyed NVD API, and only then is `NVD_API_KEY` used. (`ef1458c`, merged in
  `71c8f6b`)
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
  from the public datafeed in 2 minutes and the scan ran.
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
- **Not yet run on the private repository's own Actions** for this head: the self-test and the
  consumer path. The public mirror and hello-world runs above stand in for them; a uat/prod deploy
  against protected and unprotected environments, the first Dependabot github-actions update, and
  live runs of the sequential rollback and of exception resurfacing are still owed. Every lane passed
  its own failing-first proofs and the full local sweep.
- **KDEC-020's open owner questions are answered** (KDEC-022): a `MAL-` hit and a KEV CVE block at
  every rung, and an unmapped org with no enterprise entry runs at the strictest registered org.
- **NVD data is not organisation-hosted.** Dependency-Check's NVD database comes by default from
  the Dependency-Check project's public datafeed
  (`https://dependency-check.github.io/DependencyCheck_Builder/nvd_cache/`). There is no
  organisation-hosted mirror: the runner needs egress to that third-party host, and the data is
  only as current and as available as that feed. `NVD_API_KEY` is used only if `nvd_datafeed_url`
  is emptied. The CISA KEV catalog and Trivy's database are likewise fetched from their public
  publishers. An organisation mirror is planned for Release 4.
- **Dependency-Check does not read a bare `pom.xml`.** The database now builds (cold, from the
  Dependency-Check project's public datafeed, in 2 minutes on a hosted runner) and the scan runs,
  but the Dependency-Check CLI reads no dependencies declared only in a standalone `pom.xml` with
  no JAR, so the probe's seeded Maven dependency is not detected by it (a JAR carrying the same coordinates is). Trivy's dependency
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
