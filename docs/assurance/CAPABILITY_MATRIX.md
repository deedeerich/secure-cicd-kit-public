# Capability matrix — what is actually proven

**Generated from real runs, not from the presence of files.** Read this instead of prose to know the
kit's trust state.

Last validated: **2026-08-14**. Evidence runs in the reference implementation
(run IDs are from the kit's own repository — substitute your own once you adopt it):

| Evidence | Run |
|---|---|
| Scanner baseline — 15/15 jobs green | `31799471359` |
| Azure OIDC against a real tenant | `31821678979` |
| Environment branch policy refusing a non-`main` branch | `31821992932` |

## Validation contract

A capability is not `observed` because a process exited 0. Every rung needs its own evidence:

```
Installed → Executes → Expected behavior on seeded input → Artifact valid → Gate behaves
```

## Detection & generation capabilities

> ### Re-evaluated 2026-09-02 — a claim is only as strong as the contract its evidence was gathered under
>
> The `19/19` result this matrix cited was **union-satisfied**: the assertion asked only whether a
> seeded signal had been flagged *by anything*. Commit `0d5983a` — *"pin signals to scanners, because
> overlap was hiding dead scanners"* — changed the contract to require the **specific** analyzer.
> Under the stronger contract, **gosec and flawfinder immediately failed**: flawfinder had never been
> installed, and gosec was pinned to a container tag that does not exist. Semgrep, running unscoped
> because of a separate defect, had been covering for both.
>
> **This matrix did not lie.** It recorded evidence faithfully against a contract too weak to detect
> the failure. That is the lesson worth keeping: *when the contract is strengthened, prior claims must
> be re-derived, not assumed to carry forward.* Rows below are re-evaluated against current evidence
> (**20/20 pinned attribution, 1/1 clean negative control**), not downgraded to punish the old record.

| Capability | Function | Status |
|---|---|---|
| **Semgrep** | Multi-language pattern/rule SAST | **observed** — pinned attribution |
| **Bandit** | **Python security static analysis** — insecure-code-pattern detection | **observed** — pinned attribution |
| **gosec** | Go security static analysis | **observed** — *re-earned 2026-09-02.* Prior status was union-satisfied; acquires `2.24.6`, discovers all module roots, findings attributed to gosec |
| **flawfinder** | C/C++ insecure-function detection | **observed** — *re-earned 2026-09-02.* Prior status was union-satisfied; installs, executes, emits SARIF, attributed to flawfinder |
| **`dotnet list package --vulnerable`** | .NET SCA | **observed** |
| **OSV-Scanner** | SCA **+ malicious-package intelligence** (`MAL-` advisories) | **observed** |
| **Trivy fs** | Dependency vuln + config signal | **observed** |
| **Checkov** | IaC policy & security | **observed** |
| **Azure gitleaks rules** | Secret detection — 14 custom Azure/Entra classes | **observed** |
| **Syft** | SBOM generation (supply-chain evidence source) | **observed** |
| **OWASP Dependency-Check** | NVD CPE matching — the capability unique to `reusable-nvd-cve.yml` | **observed** ¹ |

**11 of 11 detection/generation capabilities observed.**

¹ Dependency-Check detects against the **seeded fixture**. Currency against a *live* NVD feed is a
separate claim and remains unproven — it needs a sustained `NVD_API_KEY` run. Proven ≠ proven-current.

> ### ⚠️ Matrix omission, corrected 2026-08-12
> The first version of this table **omitted `reusable-nvd-cve.yml` entirely** — the whole workflow,
> not just a row. It has never run on a runner, and `validate-scanners.yml` did not probe it.
>
> **A matrix that claims to show trust state while silently omitting a capability is worse than no
> matrix**, because it converts an unknown into an invisible. That is the same failure class the kit
> exists to prevent, committed in the artifact that reports on it. A probe has been added.

## Assurance mechanisms (not scanners — do not fold into the count above)

| Mechanism | Function | Status |
|---|---|---|
| Negative control | Proves a failed collection ≠ a clean result | **observed** |
| Gate enumeration | Proves every job can actually fail the gate | **observed** |

## Why overlap is not waste

**Semgrep and Bandit are not two implementations of one checkbox.** Semgrep is a broad cross-language
rule engine. Bandit carries a Python-specific *security* corpus — insecure subprocess and shell
invocation, hardcoded credentials, weak crypto and insecure hashes, TLS misuse, unsafe
deserialization (`pickle`), risky temp-file handling, insecure permissions, SQL construction, `eval`
/`exec` hazards, unsafe XML, with severity **and confidence** classification.

Same for Trivy config vs Checkov on IaC. **Overlap is detection diversity and corroboration, not
redundancy.** Collapsing tools by shallow category name is how coverage quietly develops holes while
the inventory looks tidy.

## Known blockers — RESOLVED 2026-08-14 (run `31799471359`)

| # | Capability | Cause | Fix | Outcome |
|---|---|---|---|---|
| 1 | Azure secret rules | gitleaks install → **HTTP 503** from the release CDN. URL and asset name verified correct; the *delivery path* is unreliable. | Extract the binary from the vendor container image — no release-asset dependency | **observed** |
| 3 | OWASP Dependency-Check | ~~No `NVD_API_KEY` secret exists in this repo.~~ **SUPERSEDED 2026-08-18/19.** The key was provisioned, was structurally unreachable so the workflow silently took its un-keyed path, and that wiring was fixed. The key itself was then **independently verified as working** — run 2's 403/404 came from Dependency-Check `9.0.9` predating NIST's retirement of the legacy feeds, not from the key. | Bumped to `12.1.0`; `github_environment` wiring resolves the secret | **Run 3: database update SUCCEEDED (~50 min cold).** Live-NVD currency is **established for the DB build**. Detection for **Go and Node dependencies is still not established** — an analyzer prerequisite gap, not a key problem: the Go analyzer needs a toolchain the job does not install (exit 14, fatal) and the Node analyzer wants `node_modules` |
| 2 | Bandit · Checkov · Syft | **Cause undeterminable** — probe steps suppressed output with `>/dev/null`. **The harness was not self-diagnosing, which is its own defect.** | `exec 2>&1`, print tool versions, `ls -l` the output file | **all three observed** |

**The harness is part of the security control surface.** If it suppresses errors, misparses YAML, or
fails for reasons unrelated to the thing under test, it manufactures false assurance exactly like a
silent scanner does. It is held to the same rules: observable failure, typed unknown, reproducible
test, no silent fallback.

## Stopping condition — MET 2026-08-14

**Scanner expansion is frozen.** Every capability in the chosen baseline is `observed` or carries an
explicit, documented blocker. Nothing is left as "probably fine".

The four capabilities that were UNKNOWN are now proven. They were never optional — each is pivotal,
which is why the matrix refused to freeze without them:

- **Bandit** — Python is certain to appear in scripts, tooling and automation
- **Checkov** — non-negotiable for a cloud/IaC kit; without it "shift left" is unproven
- **Azure secret rules** — most consequential to leave unproven in an Azure estate; they exist
  *because* generic hook coverage had a hole. Until positives and near-misses both run, we do not
  know whether 14 regexes protect developers or decorate a TOML file
- **Syft** — SBOM feeds license policy, component inventory, vuln correlation, provenance and
  "what exactly did we ship?"

Each reached `observed` on seeded input. An overlapping scanner passing is **not** evidence that a
different scanner works — every one was proven independently.

> **What this validation pass actually bought.** Not "11 scanners work" — that was expected. The
> value was that the harness found defects in the **assurance machinery itself**: the gate enforced
> 4 of 6 jobs while the docs claimed six; probe steps suppressed their own diagnostics with
> `>/dev/null`; the matrix omitted an entire workflow; and the secret-scanner allowlist exempted
> `.md`/`.txt`/`.rst` wholesale, making any credential in a runbook invisible. Only a fixture with
> seeded positives could find that last one, and it would have shipped as a silent hole in a
> security control.

### Per-capability success criteria

| Capability | "Expected behavior" means |
|---|---|
| Bandit | Seeded vulnerable Python produces the expected security findings |
| OWASP Dependency-Check | Installs, executes, and emits `dependency-check-report.sarif` under the expected filename. **Detection against a current NVD database is NOT provable here** — see the key constraint below |
| Checkov | Known-bad IaC produces the expected finding class; known-good is not mistaken for equivalent failure |
| Azure secret rules | Every supported synthetic credential class matches; representative near-misses do **not**; no real credentials ever used |
| Syft | SBOM is syntactically valid **and contains known expected components** from the fixture |

> ## ⚠️ PENDING RE-VERIFICATION — updated 2026-08-18
>
> **The outage is over and the two runs happened.** What they found is recorded below; what they
> have not yet covered is stated plainly.
>
> **Settled at `8b8eb94` (2026-08-18):**
> - `validate-scanners` — **GREEN**, run `32151286413`. First trustworthy green on current `main`.
> - `consumer-path-test` — run `32151289784`: **19/20 seeded signals, 1/1 negative control clean.**
>   The single failure was **not** a test defect:
>   `WRONG-TOOL sast:go-gosec gosec go/vuln.go [got semgrep,semgrep-csharp,semgrep-java]`.
>   gosec ran and found real issues, but reported **module-relative** paths, so `go/vuln.go` and
>   `services/worker/vuln.go` both arrived as `vuln.go` — two files, one identity. The amendment
>   caught it on its **first real run**; the old 19/19 contract would have reported green while
>   semgrep silently covered for gosec. Fixed at `02b67f6`.
> - `sast-java` — **resolved from evidence, no longer under-claimed.** The consumer run detected
>   `sast:java-semgrep` at `java/Vuln.java`. Observed at contract level.
> - `code-quality` — **still correctly deferred.** The job runs; no expected signal asserts it
>   detects anything. Deferral stands until the fixture carries a seeded lint violation.
>
> **NOT yet settled.** `main` has moved twice since that evidence — `02b67f6` (gosec identity fix)
> and `1452aa0` (29 job timeout bounds). Neither has been run against the signal contract.
> **The evidence below describes the commits it names, not current `main`.**
>
> **Known live defect, same class, not yet fixed:** Trivy reports **scope-relative** URIs
> (`infra/main.tf`) where Checkov and Semgrep report **repo-relative**
> (`tests/consumer-fixture/full/infra/main.tf`). One file, two identities, inside a single repo. It
> survives because `iac:checkov` and `iac:dockerfile` are **not tool-pinned** — the same blind spot
> the Go pin exposed, one layer over. Batched with the discovery work rather than churning another
> baseline.

## Consumer-path & external validation — proven 2026-08-14/16

**Tool-level evidence says nothing about what a consumer gets.** Three coverage illusions shipped
here and survived a fully green `validate-scanners`: a `trivy-action` tag that never existed, 14
Azure secret rules the reusable workflow never loaded, and three SAST jobs that ran **no scanner at
all**. All three were invisible until the contract itself was tested.

### Level 1 — consumer-path contract (internal caller)

| Evidence | Result |
|---|---|
| `consumer-path-test.yml` run `31851461339` | **19/19 seeded signals DETECTED**, 1/1 negative control clean, seeded findings **blocked the caller** |
| Coverage | Python · Node · .NET/C# · Java · Go · C/C++ · Terraform · Dockerfile · 3 Azure/Entra secret classes |
| Monorepo | **2 Node roots · 2 Go modules** — proves all-roots discovery, not first-match-wins |

Compared **expected vs observed** via `tests/verify_expected_signals.py`. Counting green jobs cannot
detect a scanner pointed at the wrong path, handed the wrong config, or writing an empty report.

### Level 2 — external repositories (cross-repo consumption)

Real repositories, **discovery mode** (`advisory_mode: true`), classified per
[`FINDING_CLASSIFICATION.md`](../operations/FINDING_CLASSIFICATION.md).

Consumer repositories are described by **shape, not name**, and finding counts are omitted.
Naming a private repository alongside its vulnerability count publishes a reconnaissance summary
of that repository — the assessed party's posture is theirs to disclose, not the kit's.

| Consumer shape | Scale | What it proved |
|---|---|---|
| **Split frontend/backend web app** | nested manifests, no root lockfile | cross-repo resolution works; **advisory-mode A/B — identical findings, 4 failing jobs → 0** |
| **Infrastructure-as-code repository** | 40+ Terraform modules | the **IaC surface exercised against real infrastructure**, not a fixture |
| **Legacy C++ project** | 2019 IDE workspace, no package metadata, **non-UTF-8 source** | the awkward case — **two defects surfaced here and nowhere else** |

**What the awkward repository caught that nothing else did.** First run: **1 finding**. After the
fixes: **167**.

- **flawfinder was crashing, silently.** It is a Python tool and aborts on the first undecodable
  byte — one Latin-1 character in one 2019 file. It wrote that error to **stdout**, so the redirect
  captured the error message *as the report*: a non-empty file that is not JSON. The guard checked
  only that the file existed, which a crash satisfies. Reports are now parsed to prove they are
  valid, and non-UTF-8 sources are transcoded into a **temporary copy** — the consumer's repository
  is never modified.
- **cppcheck's findings were produced and discarded.** XML written, never converted, never
  published, never gated. 159 real defects invisible to everything downstream. A scanner whose
  output nothing consumes is not a control.

> **A true positive is a successful test of the kit and a failed security assessment of the
> consumer.** None of these findings were "fixed" by changing scanner configuration. Two genuine
> `KIT_DEFECT`s came out of the first external consumer — `ruff` hard-failing on lint style, and
> the absence of any real advisory mode — and only those were fixed.

### Not covered — stated, not implied

| Gap | Why |
|---|---|
| **Swift / Objective-C** | no scanner in the kit; `language` accepts python/node/dotnet/java/go/cpp/multi |
| **Kotlin / Android** | no real repository available; Java coverage does **not** imply Android coverage |
| Cross-**organisation** consumption of a private kit | impossible by GitHub design — each org hosts its own instance |

## Cloud identity & deployment gating — proven 2026-08-14

| Capability | Evidence | Status |
|---|---|---|
| `azure-oidc-auth` | `verify-azure-oidc.yml`, environment-scoped subject, `az account show` returned, **0 resources created** | **observed** |
| Environment deployment branch policy | non-`main` branch dispatched at an environment restricted to `main` → **refused in ~2s with 0 steps executed**, no OIDC token minted | **observed** |

The second is the more interesting result. It proves the authorization boundary sits **before** token
issuance: the branch is refused by GitHub, not by Azure. Enforcing the same rule through a
`Branch`-form federated credential would move the failure *after* the build, and disguise a policy
decision as an authentication error. See `SETUP.md` §1.2 and §4.

## Deploy workflows — blocked on a design requirement, not only on environment

`deploy-appservice`, `deploy-containerapp` and `image-push` are **not** merely waiting for an Azure
tenant. They are blocked on **[`ROLLBACK_CONTRACT.md`](../architecture/ROLLBACK_CONTRACT.md)**.

Rollback must be **state-aware and change-scoped**: remove only what this run created, restore what
this run modified, and verify live state afterward. Full deletion is permitted only for resources
positively identified as created by the current run, or in an explicitly ephemeral test scope proven
empty beforehand. **A rollback command exiting 0 is not proof of restored service.**

Shipping "cleanup = delete the resource group" as a reusable production behavior would be a defect
with a much larger blast radius than anything else in this kit.

## CodeQL — added 2026-09-09, and not yet proven

`github/codeql-action` appeared **twelve times** in `reusable-security.yml`. Every one was
`upload-sarif` — the transport that publishes *other* scanners' SARIF to the Security tab.
`codeql-action/init`, `/autobuild` and `/analyze` appeared **zero** times.

So the graceful-degradation wrapper existed around an upload, and the analysis engine it was named
after was never wired in. Reading the vendor name twelve times in your own workflow and concluding
the capability was present is this kit's own failure class, committed inside the kit.

**Now present:** a `codeql` job, discovery-gated like every other scanner, matrixed across the six
supported ecosystems. It attempts real analysis and declares its own outcome:

| Outcome | State | Meaning |
|---|---|---|
| initialise fails | `UNAVAILABLE` | almost always GHAS not enabled on a private repo. Build not failed; scope **unestablished** |
| analysis fails | `COLLECTION_FAILED` | initialised then did not complete. Not zero findings |
| analysis completes | `COMPLETE` | results in the Security tab and in the `sarif-codeql-<lang>` artifact |

`UNAVAILABLE` and `COLLECTION_FAILED` both feed `undetermined`, so a consumer cannot read a passing
gate as *"CodeQL found nothing"* when CodeQL never ran.

**Assurance state: DECLARED.** The job exists and the YAML parses. It has **not** been observed
running — not against a GHAS-enabled repository, and not against one without it. Until both paths
have been seen, this row is a claim about configuration, not about detection. Do not cite it as
coverage.

## What is missing — by layer, not one junk drawer

| Capability | Layer |
|---|---|
| Dependabot **alerts/security updates** | org / platform configuration — `.github/dependabot.yml` proposes updates, it cannot enable the feature |
| Push protection | org / platform configuration — not YAML |
| Container **image** scanning | build / release (distinct from Trivy's filesystem scan) |
| Signing / provenance attestation | supply chain / release |
| License policy | SBOM governance — SBOM generated, no policy applied |
| DAST | environment-aware; needs a deployed target |
| Findings dedupe / ownership / disposition | **findings-management layer, not this kit** |

## Status

```
designed    ✅
configured  ✅
observed    ⚠️  6 of 10 detection capabilities; 2 of 2 assurance mechanisms
effective   ❌  unmeasured
```

**Not ready to hand over.** Once the four reach `observed`, freeze scanner expansion and move to
findings management — at that point the bottleneck stops being *signal production* and becomes
*more findings than a thin team can triage, correlate, own, remediate and close*.
