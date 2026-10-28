# Using the kit

## What's in it

**Reusable workflows** (`workflow_call` — reference them from a calling repo). The "caller grants"
column is what the CALLING job (or its workflow) must grant: GitHub caps a called workflow at the
caller's permissions and refuses the whole run before any job starts (`startup_failure`, no log)
when a called job asks for more. `tests/check_caller_permissions.py` holds the kit's own callers and
templates to this rule.

| Workflow | Purpose | Cloud deps | Caller grants |
|---|---|---|---|
| `reusable-security.yml` | Discovery → secret · code-quality · SAST · CodeQL · dependency · IaC · malware · SBOM · image scans → report → gate → `routing_result` | none | `contents: read`, `security-events: write`, `actions: read` |
| `reusable-nvd-cve.yml` | Trivy + OWASP Dependency-Check; NVD data from the Dependency-Check project's public datafeed by default (a third-party host the runner must reach; no organisation-hosted mirror unless the optional Release 4 organisation mirror is configured -- KDEC-032, proven locally only); re-scan of an SBOM or image | none (`NVD_API_KEY` only if `nvd_datafeed_url` is emptied) | `contents: read`, `security-events: write` |
| `workflow-policy-check.yml` | Governance gate over the calling repo's own workflows | none | `contents: read` |
| `reusable-build-docker.yml` | Build once → Trivy gate **before** push → Syft SPDX SBOM → push those bytes → digest read back → attest | OIDC | `contents: read`, `id-token: write`, `attestations: write` |
| `reusable-deploy-containerapp.yml` | Container Apps deploy by digest, verdict-gated, revision probed before traffic, reversible | OIDC | `contents: read`, `id-token: write` |
| `reusable-deploy-appservice.yml` | App Service deploy by digest, verdict-gated, slot-staged (or direct below uat), reversible | OIDC | `contents: read`, `id-token: write` |
| `reusable-propose-ledger.yml` | Proposes baseline-ledger changes as a pull request (protected default branch only) | none | `contents: write`, `pull-requests: write` |
| `reusable-ticket-reconcile.yml` | Findings → Jira or Azure DevOps tickets, post-merge or scheduled | tracker | `contents: read` |
| `reusable-dependabot-triage.yml` | Dependabot PRs: `--auto --squash` only when nothing can change behaviour (FUTURE_WORK §6); otherwise label, comment why and ask a human; excluded fixture paths closed. Call from `pull_request_target` ([DEPENDABOT_TRIAGE.md](DEPENDABOT_TRIAGE.md)) | none (optional `METADATA_TOKEN`) | `contents: write`, `pull-requests: write`, `issues: write` |
| `verify-azure-oidc.yml` | Zero-resource check of the OIDC subject, the session context and the authorization boundary | OIDC | `contents: read`, `id-token: write` |

**Composite actions** (`.github/actions/*` — for repos that build inside their own workflows):
`setup-python`, `setup-node`, `setup-terraform`, `azure-login-oidc`, `docker-build-push`,
`render-version-metadata`, `determine-changes`, `verify-attestation`. The flagship's own
`discover`, `resolve`, `scan-report` and `propose-ledger` composites are called by the kit, not by
consumers.

The flagship reaches its own composites with `uses: $/.github/actions/<name>`, which resolves to
the **kit's** repository at the commit the caller pinned (requires a current github.com runner).
A plain relative `uses: ./…` would resolve against the *caller's* checkout and break silently
cross-repo, which is why nothing in a reusable workflow uses that form.

`reusable-security.yml` does not inline each script at every call site. One bootstrap job,
`kit-scripts`, writes the canonical scripts once and publishes them as a **run-scoped artifact**
with a pinned SHA-256 manifest that every other job downloads and verifies; an artifact belongs to
the run rather than to a repository, so a cross-repo consumer's runner receives exactly what the
kit's own runner receives. Per-call-site inlining is what took that file to 608.8 KB, past GitHub's
size ceiling, after which it did not fail — it never started.

**Templates** (`templates/`): `security.yml`, `policy.yml`, `build-deploy.yml`, `nvd-cve.yml`,
`dependabot-triage.yml` — copy into `.github/workflows/`, replace the org, pin the kit by SHA.
Policy: [`POLICY_REGISTER.md`](POLICY_REGISTER.md).

**Profiles** (`profiles/`): declarative statements of what a class of repo gets. They are intent
records validated by `profiles/profile.schema.json` — the reusable workflows are the implementation.
Nothing reads a profile at runtime yet, and their vocabulary predates `iac_mode` (they still say
`enable_iac`); wiring them up is a deliberate follow-on.

## Adoption sequence

1. **Install the leak gates in the repository first** ([`LEAK_GATES.md`](LEAK_GATES.md)):
   - merge `developer-safety/gitignore/baseline.gitignore` into its `.gitignore` (`merge-baseline.sh`; never replace it);
   - install the gitleaks pre-commit hook;
   - apply the push ruleset (`apply-push-ruleset.sh`);
   - enable push protection where it is licensed.

   Tines GitSync and other server-side pushes run no local hook. Only the push ruleset, push
   protection and CI stand in front of them.
2. Host the kit in a repository your organisation owns and let it be consumed (SETUP.md §1.5).
3. Pick a kit **commit SHA** to consume. Branches and tags move; a verdict is only as trustworthy as
   the code that produced it.
4. In a **pilot repo**: copy `templates/security.yml`, point it at that SHA, and let it run. The first
   run will find things — that is the system working ([`FINDING_CLASSIFICATION.md`](../operations/FINDING_CLASSIFICATION.md)).
5. Add `templates/policy.yml` with `soft_fail: true` (an attributed weakening), fix what it reports,
   then flip it to blocking.
6. Only then wire build + deploy (`templates/build-deploy.yml`), and add the checks to branch
   protection. The required check is the caller job's `Security gate`, e.g. `security / Security gate`.
   **`templates/build-deploy.yml` REPLACES `templates/security.yml`**: delete `security.yml` in the
   same change (one security caller per repository, KDEC-033). Its `security` job runs on the same
   push, pull_request and dispatch triggers under the same job id, so the required check keeps its
   name; with both installed the full suite ran twice per event. The one deliberate difference: a
   *promotion* dispatch scans nothing, because the promoted record carries its verdict.
   `tests/prove_security_caller_triggers.py` proves the replacement from the templates; confirm it on
   your pilot repo (the required check reports from the new workflow) before deleting the old file.

## Cloud identity

Nothing environment-specific is baked in. Every deploy input arrives from the caller:

- **Secrets** — `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `AZURE_CLIENT_ID`, passed explicitly to
  the build and deploy reusables (OIDC federation only; no client secret exists anywhere in this kit).
  They are identifiers, so a landing zone may hold them as environment **variables** and pass them in
  the `secrets:` block (LZ_KIT_HANDOFF_CONTRACT.md).
- **Vars** — registry login server, image repository, resource group, app name, environment tier.
- **Partition** — the `cloud` input (`commercial` | `gov`) selects the Azure environment. The same
  pipeline shape serves both; there is no forked sovereign pipeline to drift out of sync. Defaults
  differ: `commercial` for Container Apps and the build, `gov` for App Service — set it explicitly.

Grant `permissions` on the *calling job* as in the table above — a reusable workflow cannot grant
itself more than the caller has. The kit's policy gate rejects workflow-level `id-token: write`.

## Deploy contract

Build emits `image_digest`, `image_config_digest`, `artifact_identity` and `sbom_sha256`. Deploy takes
`image_digest` and refuses anything that isn't a full `sha256:` value. Deploy is only safe to treat as
deployment provenance when `artifact_identity` is `REGISTRY_IDENTITY_PROVEN`: the artifact that was
scanned is provably the artifact that ships. `templates/build-deploy.yml` checks it in its `verdict`
job; since KDEC-029 the deploy reusables also take `artifact_identity` as an input, and a deploy whose
build did not prove it can never be `verified-for-promotion`.

The deploy reusables read the security verdict: `routing_result` is a **required** input, and anything
but `PROCEED` or `PROCEED_WITH_ADVISORY` is refused **before login**, naming the value. At `uat` and
`prod` a `PROCEED_WITH_ADVISORY` caused by a proven `VERSION_GAP` is refused unless a named person
accepts it through the weakening record (KDEC-014) — pass `advisory_causes` beside `routing_result`.
After health and a fresh live read of what serves, the deploy writes provenance **tags** on the
serving object (`deploy_provenance_digest`, `deploy_provenance_metadata_sha256`,
`deploy_provenance_run`) from the `render-version-metadata` stamp the template passes as
`version_metadata`.

Deploys are gated by a GitHub Environment. A merge to `main` deploys **dev and test** (the build of
that merge, in parallel); everything else is a `workflow_dispatch`.
Health checks run **before** traffic moves: Container Apps probes the new revision on its own name
before any traffic shifts and reverses only what the run changed; App Service health-checks the slot
and never swaps an unhealthy one (a direct deploy with `slot: ''` is refused at `uat`/`prod`).

## Build once, promote the same digest (KDEC-029)

A merge to `main` passes the full gate, builds **once**, signs, and produces its SBOM and provenance.
That exact digest is what moves through the environments; nothing is rebuilt per environment.

```
merge to main ─▶ security + policy ─▶ build (sign, SBOM) ─▶ verdict ─┬─▶ deploy-dev   (parallel)
                                                                     └─▶ deploy-test  (parallel)
dispatch promote_from_run_id=<run> promote_from_environment=test ─▶ promote ─▶ uat or prod
```

- **dev and test deploy in parallel** from the same build (`deploy-dev`, `deploy-test` in
  `templates/build-deploy.yml`). Each writes its own **promotion record**, published as the artifact
  `kit-promotion-record-<environment>` (`schemas/promotion-record.schema.json`).
- **uat and prod are promoted**, never deployed from a build: a dispatch with `promote_from_run_id`
  runs no gate and no build. A uat/prod deploy that names no source is refused
  `PROMOTION_REFUSED_NO_PREDECESSOR` before login.
- **The predecessor is product policy**: `vars.KIT_PROMOTION_PREDECESSOR` (`test` or `uat`, default
  `test`) for prod; uat's predecessor is always `test`. A dev success never satisfies it.
- **"Tested"** — the record reads `verified-for-promotion` only when health passed, the end-to-end
  test period passed (`vars.KIT_E2E_TEST_COMMAND`, `e2e_test_period_minutes`, KDEC-021), DAST where
  configured shows no blocking finding (`vars.KIT_DAST_COMMAND`), the security-settings posture read
  back from the live target holds, the build proved `artifact_identity` and V1 verified the
  signature, the release verdict was PROCEED-class, and the digest was built from the default branch.
  No e2e command means the deploy can never be verified for promotion.
- **DAST is a neutral hook**: `dast_command` runs against `PROMOTION_APP_URL` and writes SARIF to
  `PROMOTION_DAST_SARIF`; an unsuppressed `error`-level result blocks. An overlay supplies ZAP
  baseline through it (for example: run the pinned ZAP image with `zap-baseline.py -t
  "$PROMOTION_APP_URL"` and convert its JSON report to SARIF). It is **refused at prod**
  (`DAST_REFUSED_PRODUCTION_TARGET`): prod gets passive checks only (health, posture).

**The promotion gate** runs in the deploy reusable, before login, and refuses with the reason named:

| Code | Why |
|---|---|
| `PROMOTION_REFUSED_SOURCE_UNREADABLE` | run Y published no readable record for environment Y |
| `PROMOTION_REFUSED_DIGEST_MISMATCH` | the digest to deploy is not the one the record verified |
| `PROMOTION_REFUSED_WRONG_PREDECESSOR` | not the required predecessor (or a dev/sandbox record) |
| `PROMOTION_REFUSED_NOT_VERIFIED` | the record is not `verified-for-promotion`; the missing conditions are named |
| `PROMOTION_REFUSED_NOT_FROM_MAIN` | not built from the default branch |
| `PROMOTION_REFUSED_SIGNATURE` | V1 in this deploy did not read `ATTESTATION_VERIFIED` |
| `PROMOTION_REFUSED_REVOKED` | a revocation (digest, signer, approval, test evidence) or a new critical / known-exploited finding |
| `PROMOTION_REFUSED_NEW_FINDING` | the SBOM re-scan finds a HIGH finding the build gate did not have |
| `PROMOTION_REFUSED_RECHECK_INCOMPLETE` | the SBOM re-scan, KEV, history or revocation register could not be read |
| `PROMOTION_REFUSED_STALE` | verified more than 14 days ago |
| `PROMOTION_REFUSED_SUPERSEDED` | a newer build was verified in the same predecessor since |

14 days is a **maximum**. Revoke at once by committing an entry to
`.security/promotion-revocations.json` on the default branch (CODEOWNERS-protected):
`{"revocations": [{"kind": "digest|signer|approval|test-evidence", "match": "...", "reason": "...",
"revoked_by": "...", "revoked_at": "YYYY-MM-DD"}]}`. At promotion time the gate re-scans the build's
SBOM (sha256 checked against the record) with the pinned Trivy and re-checks KEV; it never rebuilds.
Prod keeps its environment approvals and self-review prevention.

**Hotfix** is the same path compressed: `release_path: hotfix` with a shorter `e2e_test_period_minutes`
(recorded), then promote. A **named rollback or hotfix decision** (`release_path: rollback|hotfix`
with the weakening record: reason, authority, exception reference, unexpired expiry) may promote an
older build that is not superseded. **Break-glass** (`release_path: break-glass`) needs an attributed
exception expiring within 7 days; the deploy proceeds past the testing refusals (never past a
substitution, a non-default branch, an unverified signature or a revocation), records
`BREAK_GLASS`, and the template immediately runs the deployed scan, which tickets the testing owed
until a verified record of that digest exists in the predecessor.

**Daily deployed scan** (`templates/deployed-scan.yml`, `reusable-deployed-scan.yml`): per
environment it reconciles what actually serves (revisions and their traffic weights, or slots, and
their image digests), reports **artifact drift** (not the last promoted digest) and **security
drift** (the serving digest re-scanned from its build SBOM plus KEV) separately, checks the security
settings, and flags break-glass testing still owed. One report job feeds the existing ticket
reconcile path. It never rolls a healthy production system back.

## Branching model — what runs where

```
scanners      →  all branches  ·  no environment  ·  no Azure credential at all
build only    →  all branches  ·  github_environment: ""  ·  push: false
build + push  →  main only     ·  github_environment: <env>  ·  push: true
deploy        →  main only     ·  dev + test from the merge build; uat/prod by promotion
promote       →  dispatch      ·  no build  ·  environment + approval  ·  promotion gate
```

**Restrict branches with the Environment's deployment branch policy, never with the federated
credential subject.** The branch policy refuses the job before it starts; a `Branch`-form credential
lets the job run, do its work, and then fail on `AADSTS700213` — turning a policy decision into what
looks like an auth bug. Setup and verification for both: `docs/adoption/SETUP.md` §1.2 and §4.

`reusable-security.yml` needs **no Azure identity**, so the entire scanner surface is unaffected by
any of this and runs anywhere.

## Adopting this on a repository that has never been scanned

```yaml
with:
  advisory_mode: true      # everything runs, everything reports; only the block is withheld
  weakening_reason: "first adoption on an inherited backlog"
  weakening_authority: "security lead"
  weakening_expires: "2026-12-31"
```

`advisory_mode` withholds the block on SAST, lint, dependency and IaC findings. **It never withholds
it on secrets**: a secret in source, in history or baked into an image, and a known-malicious
package, block in every mode (`tests/prove_secrets_always_block.py`, `tests/prove_image_scan_enforces.py`,
`tests/prove_malicious_deps_enforces.py`). A toolchain, discovery or report failure also blocks in
every mode. (`soft_fail_sast` governs SAST only.)

Nothing is disabled, scoped away or hidden by it. Every scanner still runs, every finding is still
produced, published and persisted. **Only the block is withheld.** Detection is never what gets
turned off.

Advisory mode is a **recorded weakening** (`GATE_SOFTENED`): without `weakening_reason` and
`weakening_authority` the verdict is `DECISION_REQUIRED`, and after `weakening_expires` it is
`DECISION_REQUIRED` again until someone re-decides. Attributed, a clean or advisory run routes
`PROCEED_WITH_ADVISORY`.

Why it exists: dropping a hard gate onto an unknown backlog freezes development and gets the control
bypassed wholesale, which costs far more coverage than the gate was going to buy. Learn the inherited
baseline, classify it (see [`FINDING_CLASSIFICATION.md`](../operations/FINDING_CLASSIFICATION.md)), then enforce.

> **Advisory mode is a baseline tool, not a resting state.** It announces itself on every enforcement
> point and the gate reports `enforcement_state: ADVISORY`, because a silent permanent advisory mode
> is indistinguishable from having no gate at all.

`enforce_lint` (default **false**) is separate: `ruff` and ESLint findings are advisory because **lint
style is not a security control**, and hard-failing on it blocked adoption of a security workflow on
day one. Turn it on when your team chooses to.

## What each scanner needs in order to see anything

A scanner that runs against a project it cannot parse exits **zero**. It does not warn you that it
analysed nothing. These are the preconditions — every one of them was found the hard way, by a
seeded fixture that a green job failed to detect.

| Capability | Requires | If missing |
|---|---|---|
| **npm dependency + malicious-package scan** | **`package-lock.json`, `npm-shrinkwrap.json` or `yarn.lock`.** Trivy **cannot** resolve npm dependencies from `package.json` alone | Node deps are **not scanned at all**. The workflow emits a `warning`, because this is where supply-chain attacks currently land |
| Go SAST (gosec) | `go.mod` — discovered anywhere under `paths`, not just the repo root | job reports "no Go module", skips, and says so |
| .NET SCA | `.csproj` / `.sln` so `dotnet restore` can resolve | dependency audit finds nothing |
| .NET / Java SAST | `.cs` / `.java` sources under `paths` | job reports "no sources", skips, and says so |
| Python SAST | `.py` sources under `paths` | skipped with a notice |
| **PHP dependency scan** (since Release 3, next) | **`composer.lock`** beside each `composer.json`. Trivy reads only the lock: a `composer.json` alone produced no result at all (measured, trivy 0.71.2) | each `composer.json` without its lock is a named, counted `COVERAGE_GAP` (`PHPDependenciesUnlocked`) — never a dependency scan that passed |
| PHP SAST (Semgrep; since Release 3, next) | `.php` sources under `paths`. `p/php` is added to your `semgrep_config` automatically whenever discovery finds PHP, so narrowing the rulesets cannot drop it | a PHP scan that examined no PHP file, or loaded no PHP rule, is `COLLECTION_FAILED`. **The shipped Semgrep container (1.178.0, pinned by digest) reads PHP 5.6–8.4** (measured in that image). **PHP 8.5: scan what parses, flag the rest** (owner, 2026-10-22): Semgrep (1.178.0, 1.182.0) cannot parse the `(void)` cast or `final` promoted properties. Every other file is still scanned and its findings kept (they block as usual); the files it could not fully parse are **named** in the summaries, and the scan is `PARTIAL` (`PARSE_PARTIAL_PHP_SYNTAX`), never `PASS`: `PROCEED_WITH_ADVISORY`, cause `COVERAGE_PARTIAL`, not refused at uat/prod (not a version gap). Any other Semgrep error stays `COLLECTION_FAILED`. Above 8.5 is still a `VERSION_GAP`. Kit versions before lane L-SG ran Semgrep 1.90.0, which read PHP only to 7.2 |
| PHP target version | `.php-version`, or `config.platform.php` / `require.php` in `composer.json` (a constraint such as `^8.1` is recorded as a constraint, never a version) | no version declared: the PHP capability is `VERSION_GAP` (recorded, not enforced), so Semgrep's PASS reads `PARTIAL` |
| IaC | Terraform, Bicep, ARM, Kubernetes, Helm or a Dockerfile under `paths`; `iac_mode` (default `auto`) not `disabled` | `NOT_APPLICABLE` with the path searched. `iac_mode: required` makes absence a finding; `disabled` is a recorded weakening. (`enable_iac` is deprecated and ignored — the run says so) |
| Container image | `image_ref` (prefer a digest) | `NOT_APPLICABLE`, never a clean result |
| Everything Semgrep | Your code must not sit under a path Semgrep ignores by default (`tests/`, `fixtures/`, …) | **the kit overrides this** with its own `.semgrepignore`, because the default caused silent empty results |

**Absence of a language is always reported, never inferred from a green job.** A skipped scanner
prints a `notice` naming the path it searched. If you see neither findings nor a skip notice, treat
that as a defect in the kit and open an issue — silence is the one outcome that is never correct.

### What `language:` actually selects

The default is **`auto`**: scan every ecosystem discovery finds. **Applicability is decided by
discovery, against the content under `paths`** — a selector can only narrow it.

| `language:` | Meaning |
|---|---|
| **`auto`** (default), `multi` | Consider every family. Each still runs only if discovery finds something for it to analyze. `multi` is a synonym |
| a list of `python`, `node`, `dotnet`, `java`, `go`, `cpp`, `php`, `iac` (aliases `js`/`ts`, `py`, `c#`, `c++`, `tf`) | **Exclude** every discovered ecosystem not listed. It can never add one discovery did not find, and the narrowing is recorded as a weakening (`SCOPE_NARROWED`) — attribute it or the verdict is `DECISION_REQUIRED` |

So the default on a repository containing Python and Terraform runs the Python and IaC paths and
**skips** Go, Java, .NET and C/C++. That is the correct outcome, not a coverage gap. Running a Go
analyzer against a repository with no Go produces no assurance — only cost, runtime, and a green job
that means nothing. A language that is present but that no kit scanner can read is reported as
`COVERAGE_GAP`, so a green result is never read as full coverage.

**The union is the failure case, not the default.** When discovery *cannot establish* what is
present — an unreadable tree, a permission denial, a survey that did not complete — the safe move is
to scan broadly and report `DISCOVERY_UNAVAILABLE`. **What must never happen is a quiet skip**, because
a skip and an unexamined ecosystem are indistinguishable from the outside.

> **Why this is written down.** The consumer contract previously asserted that `multi` made *every*
> language analyzer run. That assertion passed for months — because four analyzers were ignoring their
> `paths` scope entirely and walking the whole checkout, so they always found something. Fixing the
> scoping made the test fail, and the failure was the contract, not the code. A semantic that only
> exists in an assertion is a semantic nobody can consume correctly. (Decided 2026-09-02.) Until
> KDEC-008 OD-7 the default was `python`, which made every caller that changed nothing a weakened run.

### Manifests are discovered, not assumed at the root

`paths` is the scope, and project roots are located *within* it. A monorepo consumer scanning
`services/checkout` gets `services/checkout` scanned — not the repository root, and not every commit
in history. Two real defects came from assuming otherwise: `setup-node` hard-failed when
`package-lock.json` was not at the root, and `gosec` scanned `./...` from the root regardless of
`paths`.

## Never trust ambient cloud context

**A cloud CLI's default context is not an authorization decision.** Developer machines accumulate
sessions — old tenants, former clients, multiple subscriptions, stale profiles that outlive the
engagement. "Whichever subscription happens to be default" is not a safe target for anything that
mutates state.

Every job that authenticates to a cloud must **declare the intended authority domain, then verify it
against what it actually got, before doing anything consequential**:

```
expected tenant        == observed tenant
expected subscription  == observed subscription
expected identity      == observed identity (the workload principal, not a human)
expected environment   == requested environment
```

A mismatch is a **hard fail before mutation**, not a warning. `verify-azure-oidc.yml` implements
this assertion (`expect_tenant_id`, `expect_subscription_id`, `expect_client_id`) and is the
reference for the deploy adapters; its refusal is proven on a real tenant (run 38826929579).

> This is not hypothetical. A three-year-old profile from a *former client* was found as the default
> Azure CLI context on a workstation actively used for unrelated personal cloud work. No live token
> remained, so nothing was reachable — but automation that trusted the ambient context would have
> aimed at the wrong estate without a single error.

## Proven state — read `docs/assurance/RELEASE_1_EVIDENCE_MANIFEST.md` for the evidence

Do not read this section as marketing. Each row is a distinct claim with distinct evidence; the
manifest gives the run id or proof, what it asserted, and its scope.

| Surface | State |
|---|---|
| **`reusable-security.yml` end-to-end as a consumer calls it** | **proven on GitHub**: input threading, discovery, every scanner job, report and gate from a consumer-style caller — 20/20 seeded signals detected by the right scanner, negative control clean, caller blocked (run 38934329462 on `main` `ef4b15d`, negative 38934348351 failed as designed; earlier 38811950471 on trunk `13f1518`) |
| **CodeQL** | **proven on a separate consumer repository** calling by `owner/repo@sha` (runs 38817782084, 38820564939) |
| **Azure OIDC, context integrity, authorization boundary** | **proven on a real tenant**, zero resources created (runs 38826929579, 38832628162, 38832634828, 38850408850) |
| **Environment branch policy** | **observed** — non-`main` refused in ~2s, 0 steps, no token minted |
| **Build and push** | **proven live** to a cloud registry, digest read back (runs 38857011286, 38857017667, 38857024014) |
| **Deploy and rollback, both adapters** | **proven live** on a sandbox subscription — refusal, healthy deploy, verified rollback, second actor refused, App Service slot swap. Not live: empty/unknown prior state, partial apply, provenance tags written, a scan → deploy chain in one run |
| **Composite actions** | `setup-python`/`setup-node` installs and `render-version-metadata` proven (self-test probes and local proofs); `determine-changes` and `setup-terraform` held (no consumer yet); `verify-attestation` held by plan |
| **Ticketing** | reconciler proven live on a personal Jira; the armed workflow has no hosted run; Azure DevOps against stubs only |

**Validate on one repo before rolling out**, on the kit commit you pinned.
