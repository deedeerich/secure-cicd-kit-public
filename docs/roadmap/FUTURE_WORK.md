# Future work — what was deliberately not finished

Everything here was **consciously deferred**, not overlooked. The distinction matters: a kit that
quietly omits things teaches you to distrust it, and "not tonight" becomes "forgotten forever"
unless it is written down with a reason.

Items with an **expiry** are enforced by `tests/reconcile_validation.py` — they turn the build red on
their own when the date passes. Everything else lives here because a date would be theatre.

---

## 1 · Blocked only on execution

*Updated 2026-08-18 — the outage cleared, the runs happened, and they found a real defect.*

| Item | State |
|---|---|
| `validate-scanners` on `main` | ✅ **GREEN at `8b8eb94`**, run `32151286413` |
| Full consumer contract on `main` | ⚠️ **19/20 at `8b8eb94`**, run `32151289784`. The miss was real: gosec reported module-relative paths, so two files shared one identity and semgrep covered for it. **Fixed at `02b67f6`** — needs re-running |
| Re-verify at current `main` | ✅ **Done (2026-10-16).** The consumer path on `main` `ef4b15d` (Release 1) detected 20/20 seeded signals, each by the scanner that should detect it (run 38934329462). The trunk's later commits owe the same run |
| Reconcile `sast-java` | ✅ **Resolved from run evidence.** The consumer path detected `sast:java-semgrep` at `java/Vuln.java`. Observed at contract level; no longer under-claimed |
| `code-quality` detection assertion | ⏸ **Still correctly deferred.** The job runs, but no expected signal asserts it detects anything. Stands until the fixture carries a seeded lint violation |
| Trivy path normalization | ✅ **Built.** The `iac-scan` composite re-roots Trivy's scope-relative URIs to repo-relative with the kit's SARIF normaliser before counting (`.github/actions/iac-scan/action.yml`, the normalise step), and refuses the run if the normaliser is absent. **Still owed:** the collision regression fixture (two roots, one filename, two identities must survive; `docs/assurance/VALIDATION_DEBT.md`, "Scanner path identity") |

---

## 2 · Cost — a control too expensive to leave on is not a control

GitHub bills **every job rounded up to a whole minute**. Measured on the smallest consumer:
**13 jobs, 415s of real work, ~12 billed minutes.** Four jobs did **19 seconds** between them and
cost **4 minutes**.

That is an adoption risk, not an accounting detail. A budget-tight team disables what it cannot
afford — the same assurance failure as a permanently red gate, arriving through the finance door.

| Item | Notes |
|---|---|
**Acceptance criterion — not "fewer jobs":**

> Preserve **identical** scanner, evidence and gate semantics while reducing billed Actions minutes
> for three representative consumer classes: a **small** repo, a **monorepo**, and an
> **IaC-heavy** repo. Report **before/after billed minutes per class.**

Cost is an architectural quality attribute here, not an optimisation footnote — a security control
too expensive to leave enabled eventually becomes a disabled security control.

| **Consolidate sub-minute jobs + re-gate** | Built on `perf/consolidate-subminute-jobs` + `stash@{0}`; **incomplete** (2 lint errors, `needs[]` didn't rewrite). Scanner identity must survive: per-scanner outputs, gate still enumerating each one. **Success = same detection/evidence/gating, fewer billed minutes — with a before/after measurement.** Not "we refactored CI and it still looked green" |
| Changed-path intelligence | Skipped jobs are free. Route by what actually changed |
| Developer mode vs assurance mode | Not every commit needs the full fan-out. Cheap continuous + scheduled comprehensive |

---

## 3 · Findings management (D1–D4) — the next real capability

Eleven working detectors produce signal. Without disposition that is just a new way to manufacture
backlog.

> ### State at trunk `19b5e1d` (2026-10-23)
>
> Built locally, wired into the report: durable identity (`scripts/finding_identity.py`), the
> matching cascade (`finding_match.py`), anchored correlation (`finding_correlation.py`), the
> hash-chained lineage (`finding_lineage.py`), and tickets from findings (`scripts/reconcile_tickets.py`,
> proven live on a personal Jira). **Not built:** confidence and disagreement semantics (below), and
> D4 (findings feeding a roadmap). **D5 is partial:** no starter template calls
> `reusable-ticket-reconcile.yml`, nothing schedules its sweep, and closure on positive clearance is not
> built. **D6 is built locally** (version discovery and capability selection, KDEC-010). The text
> below is the design as it stood, kept.

**Doctrine already exists — use it, do not reinvent it:** the reference estate `ADR-013-correlation-engine.md`,
`backend/app/appsec/correlation.py`, `docs/specialist-pack/04-correlation-and-identity.md`.

> **Independent agreement raises CONFIDENCE. Source observations stay intact.**
> Never destructive deduplication — corroboration is the strongest evidence you have.

### D5 · Raise tracked work for findings that are NEW, RECURRED, or REOPENED BY LAPSE

**Requested 2026-09-17. Three triggers, and they are not variations of one thing.**

| trigger | what changed | what it means |
|---|---|---|
| `NEW` | a fingerprint never seen before | nobody has decided about this yet |
| `RECURRED` | a fingerprint previously `REMEDIATED` is detected again | **a fix did not hold.** Someone already decided about this once and the decision was undone — by a revert, a merge, a dependency bump, or a fix that never worked |
| `REOPENED_BY_LAPSE` | nothing in the code changed; the **disposition expired** | an `ACCEPTED_RISK` or `FALSE_POSITIVE` aged out. The risk was never removed; permission to carry it ran out |

**TWO OF THESE COME FROM THE SCAN. THE THIRD COMES FROM THE CALENDAR.**

That is the load-bearing distinction. A pipeline that reacts only to scanner output can raise `NEW`
and `RECURRED`, and is **structurally incapable** of raising `REOPENED_BY_LAPSE` — because on the
day an acceptance expires, the scan is byte-identical to yesterday's. Nothing appears, nothing
disappears, no diff fires. The finding was suppressed by a decision and the decision quietly stopped
being valid.

So D5 needs a **clock**, not a diff. It must run on a schedule as well as on scan completion, and
compare `disposition.expires` against the run date independently of whether anything was scanned.
The kit already proves this class of defect is real: five of its own deferrals lapsed on 2026-09-15
and only `tests/reconcile_validation.py`'s date check noticed. Nothing in any scan could have.

**What already exists — build the consumer, do not reinvent the model:**

- `schemas/disposition.schema.json` — `fingerprint`, `disposition_type`
  (`FALSE_POSITIVE` · `ACCEPTED_RISK` · `MITIGATED` · `REMEDIATED`), `approver_role`, `created`,
  `expires`, and a `state` enum that already contains `expired`. The vocabulary is done.
- `scripts/scan_report.py::fingerprint()` — stable identity across runs, deliberately excluding the
  line number so a finding that shifts three lines is still the same finding. **That is what makes
  `RECURRED` distinguishable from `NEW` at all**, and why it must never be "improved" to include
  position.
- `schemas/disposition-request.schema.json` — the proposal side.

**The traps, each of which has already bitten this kit in another form:**

**Idempotence.** Re-running must not create a second issue for the same fingerprint. Key the issue
on the fingerprint, search before creating, and reopen-with-a-comment rather than open-a-duplicate.
A capability that manufactures backlog is worse than one that manufactures none.

**An issue must never auto-close because a scanner did not run.** A finding absent from this run is
`POTENTIALLY_ABSENT`, not `REMEDIATED` — the same rule `compare_snapshots.py` applies to a resource
missing from a partial collection, and the same rule `COVERAGE_GAP` applies to a language nothing
scanned. Closing requires positive evidence that the scanner ran, covered the path, and did not find
it. Absence of a finding is not evidence of a fix.

**`RECURRED` must not be silently re-dispositioned.** When a fix does not hold, the old
`REMEDIATED` disposition is not evidence about the new occurrence — it is evidence that a previous
judgement was wrong or was undone. The issue should carry the prior decision and its approver role
as **context**, never as an inherited suppression.

**The issue is a projection, not the record.** The disposition store is authoritative. An issue
closed by hand must not mean a risk is accepted; that requires a disposition with an approver role
and an expiry. Otherwise the tracker becomes a second source of truth and the two drift — which is
the defect this kit has found in five other places.

**Custody.** GitHub Issues is the neutral implementation. Any other tracker is an **extension
point**, and which tracker an organisation uses is not something the neutral core may know.

**Depends on:** D1–D4 (correlation and dedupe must settle what "the same finding" means before
anything raises work from it). **Blocked by nothing else.**

### D6 · Discovery must establish VERSIONS, and a scanner must refuse a version it cannot support

**Requested 2026-09-17.** Discovery currently answers *is this ecosystem present*. It does not
answer *at what version*, and nothing asks whether the scanner pointed at it actually supports that
version.

That leaves a silent failure between `ARTIFACT_PRESENT` and `CLEAN`:

```
Python 3.13 in the repo
  -> discovery says python=true
  -> bandit runs
  -> bandit's AST parser does not know a 3.13 construct
  -> it skips the file, or parses it wrong
  -> zero findings
  -> green
```

Nothing lied. The scanner ran, exited 0, and reported nothing — and "nothing" is
indistinguishable from "clean" unless the version question was asked first.

**The contract extension.** Discovery already reports per artifact class; it must also report the
version it found and what the scanner does with it:

```
ARTIFACT_PRESENT        python
VERSION_DISCOVERED      3.13.1          from .python-version / pyproject / setup-python input
SCANNER_SUPPORTS        bandit <= 3.12  declared by the kit, per scanner
=> VERSION_UNSUPPORTED  a COVERAGE_GAP, not a clean result
```

`VERSION_UNSUPPORTED` is a member of the same family as `COVERAGE_GAP` and must never collapse into
`NOT_APPLICABLE` or `CLEAN`. The code is here, a control is owed, the control ran, and it could not
see. That is a fourth state and it is the one a green run hides best.

**Why this is not the toolchain composites' job.** `setup-python` pins what the RUNNER installs.
This is a different question: what the REPOSITORY targets, and whether the scanner can read it. A
repo can pin 3.13 in `pyproject.toml` while the workflow sets up 3.11 — and then the scanners are
reading code written for a language version they were never handed.

**Each scanner must declare its own supported range.** Not a global table: bandit, semgrep, CodeQL,
gosec and trivy each have their own. A single kit-wide "supported versions" list would be a
convenient fiction, and the first scanner to fall outside it would be wrong in whichever direction
the list happened to be set.

**The honest default when support is unknown** is `VERSION_SUPPORT_UNDETERMINED`, treated as a gap
rather than as support. Same rule as a failed discovery probe: could-not-establish is not
established-absent, and it is certainly not established-present.

**Depends on:** the `COVERAGE_GAP` machinery in discovery, which exists. **Blocked by nothing.**

### D7 · Toolchain version and support assurance — is what we are running still the right version?

**Requested 2026-09-17.** D6 asks *can this scanner understand the code in front of it*. D7 asks
*is this scanner itself current, supported, and safe to keep running*. Same word, two questions, and
they must not share a register:

```
D6   repository target version  ->  scanner supported range     a COVERAGE question
D7   installed tool version     ->  latest / supported release  a MAINTENANCE question
```

A pipeline can be perfectly version-compatible with the code and running a scanner whose rule pack
was abandoned eighteen months ago. Nothing in the run would say so.

**What it inventories.** Not just scanners — everything whose version changes what the pipeline
detects: GitHub Actions versions and pinned SHAs · scanner binaries · the language runtimes the
pipeline itself uses · Terraform CLI and provider/plugin versions · container base images · and the
kit's own reusable-workflow tags, since a consumer pinned to `@v0.1.0` is running last week's
detection whatever the source says.

**Per entry:** tool · installed version · where that version is configured · latest available ·
support status · security-advisory status · breaking-change risk · update class · last checked.

**"Newer exists" is not "upgrade now", and the state vocabulary has to carry that:**

```
CURRENT                       running a supported, reasonably recent version
UPDATE_AVAILABLE              newer exists; no forcing reason
SECURITY_UPDATE_REQUIRED      the gap itself is the vulnerability
DEPRECATED                    still runs, no longer maintained
UNSUPPORTED                   past end of support
VERSION_UNKNOWN               could not establish -- a gap, never a pass
UPDATE_BLOCKED_BY_COMPATIBILITY  newer version breaks something named
```

**AN UPGRADE IS A CHANGE TO DETECTION, NOT A MAINTENANCE CHORE.** A major checkov, trivy, semgrep or
CodeQL bump can change rule behaviour, output schema, severity mapping and finding counts. So an
update must not promote until the seeded acceptance corpus proves the new version still detects what
the old one did — and any deliberate change in findings is surfaced as a change, not absorbed as
noise. Upgrading a scanner and assuming the assurance state survives is the same mistake as assuming
a green run means the controls executed.

The lifecycle mirrors the capability ladder already in use:

```
version discovered -> support evaluated -> update classified -> regression-tested against the
seeded corpus -> published as a new kit version -> detection and enforcement REVALIDATED
```

That last rung is `REVALIDATED` in `capability_maturity`, reached for a reason that has nothing to
do with the code changing — which is exactly the case the revalidation model was built for.

**This is also what the toolchain composites should eventually feed.** `setup-python`, `setup-node`
and `setup-terraform` currently prove nothing; their first probe is *"I installed what was
requested"*, and their second job is to report what was ACTUALLY installed into this inventory. A
composite that pins a version and never says what it got is the same class of silence as a scanner
that runs and reports nothing.

**Depends on:** the seeded acceptance corpus (exists, public, proven). **Blocked by nothing.**

Already demonstrable on real data: OSV and Trivy independently flagged the **same** lockfile.

Carry all of it, not just the multiplier maths: normalisation basis (rule ID → CWE), independence
assumptions, provenance, agreement **and disagreement** semantics, calibration, and — from the
extraction manifest's own warning — **what confidence actually changes operationally**:

> *"Confidence without calibration is theatre… confidence is captured but not used to gate actions or
> trigger escalation."*

Disagreement should **escalate**, never average away.

**There is no correlation `SKILL.md` anywhere.** `SKILL_TAXONOMY.md` names `correlation-triage`
as a tool-tier skill and `SESSION-ONBOARDING.md` points at `skills/tools/{tool}/`, but that directory
does not exist. Specified, never written — a genuine extraction gap.

---

## 4 · Presentation — GHAS is one surface, never the engine

```
scanners → normalized observations → correlation → durable findings state → safe projection
```

| Tier | What | Safe where |
|---|---|---|
| **1** | Self-contained HTML dashboard as a **workflow artifact** | everywhere — private by definition |
| **2** | Trend JSON on an orphan branch. **A trend projection, not authoritative findings state** — D1–D4 owns dedupe/disposition/history | inherits repo visibility |
| **3** | GitHub Pages — **off by default** | ⚠️ **Pages is PUBLIC even from a private repo** (unless GHEC). Aggregate posture only. No paths, rule detail, snippets, or raw SARIF. Otherwise it is a free reconnaissance portal |

Engineers need scanner status, findings, safe paths, severity/confidence, prerequisite gaps,
corroboration, remediation, **what was not scanned and why**, and trend — with secrets redacted and
sensitive findings kept out of logs.

---

## 5 · Coverage gaps — stated, never implied

| Gap | Why it is not "nearly done" |
|---|---|
| **Swift / Objective-C** | No scanner at all. Needs real iOS tooling, not a generic C scanner wearing a moustache. Swift is a declared `COVERAGE_GAP`; **Objective-C is not even probed** (no `.m` in discovery's unsupported-language sweep), so an ObjC-only repository reports no gap at all |
| **Kotlin / Android** | **Java coverage does not imply Android.** Gradle, manifests, exported components, permissions, signing/config, mobile-specific rules. No real repo exists — build a purpose-made consumer. A **Kotlin-only** repository gets no scanner: `.kt` is a declared `COVERAGE_GAP`, and `sast-java` reads Java only |
| **.NET real-repo consumer** | None exists in any accessible account. Only the synthetic fixture |
| **Build-aware C/C++** | Source-only analysis is proven. Compilation database, resolved includes/macros, linked dependency graph are **not**. Report `CPP_ANALYSIS_PARTIAL` when source exists without build metadata — and **never synthesise a build system to make a scanner happy**. **`CPP_ANALYSIS_PARTIAL` is never emitted** today (only allow-listed in `scripts/reconcile_taxonomy.py`, not a taxonomy term): a source-only C/C++ scan reads like a complete one |
| **Shell / bash** | the reference estate has `shell-scanning.yml`; this kit has **no shell scanner** (no shellcheck), while shipping shell inside its own workflows. Discovery declares `.sh` (`Shell`) and `.ps1` (`PowerShell`) as `COVERAGE_GAP` (`.github/actions/discover/action.yml`, the unsupported-language sweep), so the gap is reported, not hidden |
| **GitHub Actions workflows themselves** | The workflows are a scanned surface. the reference estate has `github-actions-lint.yml`; this kit has `workflow-policy-check.yml` for policy, not lint. **actionlint runs only in the kit's own self-test**; a consumer's workflows get no actionlint or zizmor pass (discovery declares them a `GitHubActionsWorkflow` coverage gap) |
| Composite actions | All observed except `determine-changes` and `setup-terraform` (no consumer yet) and `verify-attestation` (held by plan); each carries a dated deferral to 2026-12-31 in `tests/reconcile_validation.py` |
| `reusable-nvd-cve.yml` | Has run on a runner (2026-08-18/19, three runs), and its scanners are observed on seeded fixtures. Remaining gap is the WARM path: cache key/restore behaviour has no evidence yet, and the only measured cold updates are 32 min 03 s and 9 min 17 s (runs 32190300370, 32382255986, read by the tool probe). Capture the warm duration from a real run |
| `context-integrity` negative fixture | ✅ **Refusal observed on the real tenant**: a wrong expected tenant hard-failed after a real login (run 38826929579), the matching case passed (38826938462) |
| `image-build` / `image-push` | ~~Need a registry. Expire 2026-10-31~~ **closed by proof 2026-10-15** against a real local `registry:2` (`tests/prove_build_push_round_trip.py`): digest, SBOM with the fixture component, retrieval by digest, identity round trip. Remaining gap is an ACR behind Azure identity, and a hosted dispatch of the workflow -- neither is a registry gap |

---

## 6 · Capability recovery — smart Dependabot auto-merge

> ### Search scope corrected 2026-09-10
>
> The claim below — *searched and not found* — searched an archived copy of that estate, which is a **zip extract**.
> The live repository was never looked at: the live reference estate, remote
> `the reference estate`, **30 workflows**.
>
> It contains `dependabot-security-check.yml`, and eight further workflows this kit does not have.
> A real search with the wrong denominator, recorded as an absence — the same shape as every other
> defect this week.

> ### Built 2026-10-22 (lane L-DB), proven locally, not yet on GitHub
>
> `.github/workflows/reusable-dependabot-triage.yml` + `templates/dependabot-triage.yml`, to the
> criteria below. Each criterion is mapped to the rule that enforces it, and the ones not
> enforceable yet are named, in [`docs/adoption/DEPENDABOT_TRIAGE.md`](../adoption/DEPENDABOT_TRIAGE.md)
> section 1. Not enforced: provenance/signature of the new version. Delegated to the security gate
> as a required check: no new critical/high, no malicious package. Proof:
> `tests/prove_dependabot_triage.py`; the hosted run is owed (registry `dependabot-merge-hosted`).
> The text below is the design as it stood, kept.

**Auto-merge itself is still genuinely absent.** No `gh pr merge`, `automerge` or auto-approve step
exists in any workflow in any local repository. What the reference estate has is the *gate* half — an
alert check, not the merge decision — and it is worth reading before rebuilding, because it already
implements the conditional pattern this kit needs:

```
GITHUB_ADVANCED_SECURITY_ENABLED secret -> step output -> if: steps.x.outputs.enabled == 'true'
```

Secrets cannot be used directly in an `if:`, so it projects the secret into a step output first.
That is the mechanical shape required for a GHAS-conditional step.

**SUPERSEDED — and deliberately not copied.** The `discover` job now establishes platform
applicability by PROBING the repository (`security_and_analysis`, plus a behavioural check against
the code-scanning endpoint, plus visibility), and publishes `ghas_available`, `code_scanning`,
`secret_scanning`, `push_protection`, `dependabot_alerts` and `dependabot_updates` for every
downstream job to consume.

A secret someone sets by hand is a DECLARATION. It is correct on the day it is written and silently
wrong from the day licensing changes, because nothing makes anyone update it — and it fails in the
direction that matters: a stale `true` means CodeQL is expected and quietly absent, a stale `false`
means it is switched off for a repository that is entitled to it. Neither produces an error.

The probe can also answer UNKNOWN, which a secret cannot. A read-scoped token genuinely cannot see
`security_and_analysis`, and saying so is different from saying "not available".

### What the reference estate has that this kit does not

Found by reverse census 2026-09-10 (`tests/capability_inventory.py` runs against any repo):

| Workflow | Lines | Why it matters here |
|---|---|---|
| `deduplicate-vulnerabilities.yml` | 100 | **Findings dedupe — section 3 of this document calls this "the next real capability"** |
| `create-issues-from-scans.yml` | 87 | findings → tracked work, the ownership half of section 3 |
| `ingest-scan-results.yml` | 70 | findings out of the run and into somewhere durable |
| `ingest-scan-results-to-dashboard.yml` | 87 | the presentation surface section 4 says GHAS must not be the only one |
| `update-roadmap-from-scans.yml` | 392 | scan output feeding planning |
| `azure-security-ingestion.yml` | 55 | cloud posture into the same pipeline |
| `dependabot-security-check.yml` | — | the GHAS-conditional pattern described above |
| `shell-scanning.yml` | 75 | **shell is a coverage gap here and is not listed in section 5** |
| `github-actions-lint.yml` | 89 | the workflows themselves as a scanned surface |
| `00-orchestrator.yml` | 293 | sequencing across 30 workflows, with a design document beside it |

**Sections 3 and 4 of this roadmap describe as future work things that already run in
the reference estate.** They need reading and porting, not designing.

the reference estate capability census: **9 of 16** — bandit, checkov, **codeql**, dependency-check,
gitleaks, semgrep, syft, trivy, sarif-upload. Absent there: detect-secrets, dotnet-vuln, flawfinder,
gosec, osv-scanner, sonarcloud, zap.

CodeQL ran in the reference estate and in a second consumer repository while this kit — the one whose matrix
*documented* CodeQL — never invoked it. **Since corrected:** the flagship's `codeql` job runs up to six
language legs, proven at Level 2 from a separate consumer repository (runs 38817782084, 38820564939).

The policy is **not** "robots skip review". It is:

> Low-consequence, machine-verifiable dependency updates may follow an automated assurance path
> instead of consuming scarce human review capacity.

Risk-tiered. Auto-merge only when **all** hold: patch/minor · dependency not in a protected class ·
all tests and scans pass · no breaking-change signal · no infra/schema/auth/network impact ·
provenance/signature checks pass · no new critical/high vulnerability · no malicious-package signal ·
lockfile diff consistent with the intended change · nothing outside dependency metadata · trivial
revert · full evidence retained.

**Escalate to a human:** major versions, security-sensitive libraries, platform/runtime upgrades,
auth/crypto/network packages, anything changing service behaviour.

---

## 7 · Deployment — two independent gates, both open

1. **`ROLLBACK_CONTRACT.md`** — state-aware, change-scoped rollback. Reversible ≠ safe to reverse.
2. **Landing Zone reconciliation** — these patterns came from a **devkit**, not the Landing Zone.
   That governance material has not been recovered and compared.

Shipping a deployment pattern that contradicts doctrine you already wrote is worse than shipping
none: the consumer inherits the contradiction and cannot know it exists. **Candidate implementations,
not recommendations.**

---

## 8 · Distribution and IP

| Item | Notes |
|---|---|
| Organisation + Enterprise migration | 50,000 Actions minutes vs 3,000. **`OIDC subjects contain the owner name`** — every federated credential breaks on transfer, presenting as `AADSTS700213`, which blames authentication and never mentions the move. Also `access_level`, environments, secrets, branch policies, and every `uses:` reference |
| Export gate maturation | `scripts/export_for_adoption.py` writes a **fresh tree with no history** (not a clone), so history never crosses the boundary; whatever git does not track is neither scanned nor exported (`904bc7a`, `tests/prove_export_scope.py`). What remains is maturation of the deny list, not history |
| Promotion path testing | personal → portable → organisation, with **no** tenant IDs, OIDC subjects, environment names, repo IDs, GHAS assumptions or owner-specific permissions surviving the boundary |

---

## 9 · The assurance model this work earned

Four distinct layers, each independently capable of lying. **Every one of these happened here:**

| Layer | Observed failure |
|---|---|
| **Tool** | scanner works, **action reference invalid** (`trivy-action@0.28.0` never existed) |
| **Workflow** | probe works, **workflow never invokes it** (14 Azure rules; three SAST jobs ran no scanner at all) |
| **Output** | scanner runs, **output discarded** (cppcheck findings consumed by nothing) |
| **Validity** | output produced, **malformed** (flawfinder crash text captured as its own report) |
| **Fixture** | synthetic passes, **real input breaks it** (non-UTF-8 source; single-root vs monorepo) |
| **Publication** | everything executes, **publication unavailable** (no GHAS) |

> **Tool validation ≠ workflow validation ≠ consumer validation ≠ publication.**

Six manifestations of one failure class in two days is architecture talking. This belongs in a formal
assurance model, not just a war story.

---

## 10 · Execution bounds — cost is a safety property, and semantics are still missing

Added 2026-08-18 after two C/C++ jobs stalled in dependency acquisition and ran for three hours.
Estimated **~386 billed minutes from one incident** — more than every useful validation run of the
preceding two days combined. Nothing in the kit bounded them; `reusable-security.yml` has 13 jobs, so
a single bad invocation could bill **13 × 360 = 4,680 minutes** in a *consumer's* account.

**Done:** 29 `timeout-minutes` bounds across the seven non-mutating workflows, sized from observed
healthy durations plus explicit headroom, with the rationale recorded per class.

### Still owed

- **A timeout must not read as a scanner failure.** It currently surfaces as a plain job failure. The
  correct shape is `scanner execution = incomplete` · `assurance state = UNAVAILABLE` ·
  `reason = EXECUTION_TIMEOUT` · `last completed phase = <known>` · `findings conclusion = cannot be
  determined`. Cost is bounded; **semantics are not.** Until this lands, a timeout is
  indistinguishable from a defect — the exact conflation the six-state vocabulary exists to prevent.
- **Bounded dependency acquisition.** The outer job bound stops the bleeding; a download that retries
  forever is still bad behaviour. Where the tooling supports it, set connect/read timeouts and a
  small retry/backoff: retry transient 429/5xx a few times, then classify **dependency acquisition
  unavailable** and exit cleanly *with evidence* — rather than waiting out the job limit on infinite
  optimism.
- **A test that proves it.** Terminate a deliberately hung scanner and assert its state is
  `UNAVAILABLE` **while sibling scanners retain independent states**. Use a tiny timeout or a mocked
  sleeper path — do **not** spend six hours proving a six-hour limit.
- **Re-size `reusable-nvd-cve` from evidence.** Its 60-minute bound was derived from documentation
  before the workflow ran (see LM-011). It has run since, and the cold database update is measured
  (32 min 03 s worst, run 32190300370); the bound has not yet been re-sized from those numbers.
- **Mutating pipelines need their own semantics — deliberately excluded here.**
  `reusable-build-docker`, `reusable-deploy-appservice` and `reusable-deploy-containerapp` are
  unbounded on purpose. For a scan, killing a hung run is safe. For a build or deploy, timing out
  mid-change creates ambiguous state and must flow into the rollback contract as a
  `ROLLBACK_REQUIRES_HUMAN_DECISION`, exactly as a cancelled mutation already does. **Do not
  mechanically apply scanner timeout semantics to deployment jobs because `timeout-minutes` is a
  convenient YAML property.** Design the bound against `ROLLBACK_CONTRACT.md` first: what is the
  change manifest at the moment of the kill, and what can safely be reversed from it?

### The reusable lesson

**Unbounded execution converts a dependency failure into uncontrolled cost.** This is not FinOps
commentary — validation that becomes too expensive to leave enabled becomes disabled validation, and
that is a control failure arriving as a billing decision.

---

## 11 · Version drift is a silent capability loss

Audited 2026-08-19 after a three-major drift in Dependency-Check turned into a hard failure against
a retired NVD endpoint.

| Tool | Was | Now | Note |
|---|---|---|---|
| Dependency-Check | `9.0.9` | `12.1.0` | was calling a decommissioned API |
| Dependency-Check | `12.1.0` | **`12.2.2`** | 2026-10-21, lane L-NV. `12.1.0` was "latest" only because the URL named `jeremylong/DependencyCheck`, a separate repository whose releases stop there; the project is `dependency-check/DependencyCheck`. Probe and real scan held to one version and its published digest (`tests/prove_validate_scanners_matrix.py` M9) |
| gosec | `2.21.4` | **`2.24.6`** | see the correction below |
| trivy-action | `v0.36.0` | — | current |
| syft · osv-scanner · gitleaks | via action | **unpinned** | never stale, but not reproducible |

### Correction — 2026-09-02: this table caused a defect

**This row previously named `2.28.0` as the gosec target. That version does not exist.** Upstream
stops at `2.24.x`. The pin was applied from this document, every `docker run` failed at manifest
lookup, `|| true` swallowed the failure, and **"the scanner could not be acquired" was recorded as
"the scanner found nothing."** The job went green with no SARIF while a seeded G401/G204 fixture sat
unscanned. It was found only because a separate assertion pinned that signal to gosec specifically.

Three things this establishes, all of which outlive the version number:

1. **A currency fix reached forward past the end of the shelf.** Chasing "current" is not free —
   verify the artifact resolves before changing a pin. An unresolvable pin is worse than a stale one,
   because a stale scanner still runs.
2. **Acquisition needed its own failure path.** Only *execution* had one. `DEPENDENCY_ACQUISITION_UNAVAILABLE`
   already existed in the taxonomy and was enforced for cppcheck; gosec was exempt by omission, which
   is how exemptions usually happen.
3. **A roadmap is an instruction.** This table told the next person what to do, and it was wrong for
   two weeks. Documentation is not commentary on the system; it is part of it.

**Nothing in this kit checks for drift.** That is why Dependency-Check sat three majors behind until
it broke, and a stale scanner does not announce itself — it silently stops detecting whatever was
added since. **Owed:** a check that compares every pinned tool against upstream and reports the gap —
and, per the above, one that **verifies each pinned artifact actually resolves**, since this document
demonstrated that an unresolvable pin can be authored and survive.
Warn rather than fail, since "newest" is not automatically "correct", but *state* it. Also decide
deliberately on the unpinned tools: floating means never stale and never reproducible, and the kit
should say which trade it is making rather than having one by accident.

---

## 12 · The consumer contract runs the full suite three times

`consumer-path-test` invokes `reusable-security` for the `clean` leg and the `multi` leg, then
dispatches `consumer-path-negative`, which invokes it a third time. Roughly **28 + 23 billed
minutes** to answer questions that overlap substantially.

The negative control is a separate workflow for a real reason — a job *expected to fail* inside a
passing workflow requires `continue-on-error` gymnastics that undermine the assertion. But
**"separate workflow" and "independently dispatchable full suite" are different requirements**, and
conflating them has a cost:

- It is dispatchable on its own, so it can run with **nothing asserting on the result** — a test
  executing for no reader.

> **To be precise about what happened, because the imprecise version sends someone hunting a bug
> that does not exist:** on 2026-08-18 this workflow ran twice on the same SHA, seven seconds apart,
> costing a full duplicate invocation. **No workflow in this kit is duplicated, and nothing triggers
> twice by design.** An operator dispatched `consumer-path-negative` directly while also dispatching
> `consumer-path-test`, which dispatches it as part of its own contract. That was operator error.
>
> The architectural point is not that runs duplicate — it is that the design **permits** an
> expensive suite to be launched with no assertion attached to it. Permitting a foot-gun is a
> weaker claim than firing one, and the record should say which occurred.
- Three full invocations is a large share of a metered budget for a suite that is run often.

**Owed:** decide whether the negative control should be (a) a job inside the contract workflow with
inverted assertion, (b) still separate but not independently dispatchable, or (c) explicitly
labelled diagnostic-only. And whether the `clean` and `multi` legs can share one invocation. **Do not
collapse them by weakening what is asserted** — the point is fewer invocations, identical evidence.

---

## 13 · Custody — this kit is employer-neutral, and that is load-bearing

```
Truth State: recorded 2026-09-14 from a live custody decision
Authority:   DEC-2026-09-14-001 (personal workspace decision ledger)
```

This kit is **employer-neutral and owner-retained**. It is built off-duty, on the owner's
equipment, in the owner's repository, with contemporaneous dated commits. That provenance is
not incidental — it is the entire custody argument, and it only exists because the commits were
made as the work happened. Retroactive dating is worthless and worse than nothing.

**What that means for contributors and for future sessions:**

| | |
|---|---|
| the kit itself | neutral, owner-retained |
| the app-dev tool list that was checked against it | a coverage QUESTION asked of the kit, not a customisation of it |
| `the ticket-reference gate` | **NOT neutral.** Employer the work-item system, employer change-control policy, employer digit range. **Moved to `overlays/<name>/workflows/` on 2026-09-14.** |
| SonarCloud, OWASP ZAP | **NOT neutral.** Entered from the employer's declared app-dev ecosystem. **Moved to the overlay 2026-09-14.** |
| any employer-specific adaptation | belongs to that employer |

**Direction of travel is one-way: canonical → instantiation.** Never "clean up" an employer
artifact into a neutral one. Extraction after the fact is the scenario with no defence, and it
is the reason the neutral version gets built first even when the motivation for building it is
an employer constraint. Motivation is not custody; build location, timing and resources are.

**Practical rule for anyone adding to this kit:** if a change encodes an employer's policy,
naming, ticket scheme, tenant, or estate, it is an instantiation — put it in the overlay, not
behind a comment. Generic capability stays; employer specifics do not leak in.

### The overlay, as of 2026-09-14

```
.github/workflows/          neutral core — 16 jobs, independently runnable
overlays/<name>/
  workflows/
    security-<name>.yml     CALLS the core, adds Sonar + ZAP, gates only its own additions
    the ticket-reference gate
```

**One-way dependency, and it is checked.** `tests/check_custody.py` fails if an employer-custody
capability appears in the core, if the core references an overlay, or if the overlay stops calling
`reusable-security.yml` (which would mean it had become a fork rather than a composition). Both
negative cases verified.

The overlay's jobs depend on `neutral`, not on `discover` — a job inside the called workflow is not
addressable from outside it, which is the boundary working. Applicability is still established once,
in discovery, and consumed through the core's `discovery_state` output. Stated cost: the overlay
waits for the whole core rather than just discovery.

**Ticketing is not the work-item system.** The generic capability — a PR must carry a well-formed reference to a
change record — is neutral and tracker-agnostic; the work-item system is one adapter. Azure Boards or ServiceNow
would be others. The **3–4 digit range is employer policy**, and when the generic capability is
extracted it must ship with enforcement OFF and no default range. A neutral kit that defaults to
one employer's numbers has quietly adopted their policy.

**If the kit should later support DAST or an external quality platform**, specify the neutral
requirement independently and build an adapter from it. Do not cherry-pick the overlay
implementations back into the core. Lessons out, artifacts stay.
