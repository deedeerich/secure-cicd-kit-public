# Capability inventory — source pipeline families

Classification of 77 source workflows (~15,900 lines) into **capability families**, so abstraction
proceeds by family rather than by file size. Abstracting file-by-file would preserve duplication as
architecture.

**Line count is not a coverage metric.** A 20-line reusable can replace 2,000 duplicated lines. The
metric below is **capability coverage**.

---

## Headline

**77 files ≈ 27 distinct capabilities.** Nine families are duplicated 2–3× across repos — several as
literal copies (`reusable-code-quality-scan` is 90 lines in all three repos; `reusable-secret-scan` is
105/108/108).

**The duplication is the story.** `comprehensive-code-scan` exists three times at 1055/1150/1083 lines
with an identical 14-tool set. That is one canonical workflow plus drift, not three pipelines.

---

## Duplication map

| Family | Copies | Lines | Assessment |
|---|---|---|---|
| `comprehensive-code-scan` | agent · infra · ui | 1055 / 1150 / 1083 | Identical toolset (bandit, checkov, codeql, eslint, gitleaks, hadolint, mypy, npm audit, pylint, safety, shellcheck, terrascan, tflint, trivy). **One canonical + drift.** 3,288 lines → one parameterized reusable. |
| `infrastructure-scans` | agent · infra · ui | 493 / 497 / 412 | Identical toolset. Same conclusion. |
| `security-scanning` | agent · infra · ui | 271 / 388 / 385 | Near-identical; ui/infra add codeql. |
| `semgrep-security-scan` | agent · infra · ui | 144 / 235 / 235 | agent variant diverged. |
| `code-quality-scans` | agent · infra | 636 / 641 | Effectively identical. |
| `reusable-code-quality-scan` | agent · infra · ui | 90 / 90 / 90 | **Literal copies.** Already reusable — just never centralized. |
| `reusable-secret-scan` | agent · infra · ui | 105 / 108 / 108 | Near-literal copies. |
| `create-issues-from-scans` | agent · infra · ui | 87 / 121 / 86 | Variant drift. |
| `deduplicate-vulnerabilities` | agent · infra · ui | 100 / 93 / 106 | Variant drift. |
| `workflow-policy-check` | agent · infra · ui | 60 / 60 / 149 | ui diverged substantially. |
| `github-actions-lint` | agent · infra | 89 / 90 | Copies. |

**Roughly 7,000 of 15,900 lines are duplication.**

---

## Capability families vs. `secure-cicd-kit` coverage

### A · Static security analysis

| # | Capability | Source | Kit |
|---|---|---|---|
| A1 | Secret scanning (gitleaks, detect-secrets) | `reusable-secret-scan` ×3 | ✅ |
| A2 | SAST — Python (bandit) | embedded widely | ✅ |
| A3 | SAST — generic (semgrep) | `semgrep-security-scan` ×3, `_reusable-security-semgrep` | ✅ |
| A4 | SAST — CodeQL | `codeql-analysis`, `codeql`, `_reusable-security-codeql` | ✅ the flagship's `codeql` job, up to six languages; proven at Level 2 (runs 38817782084, 38820564939) |
| A5 | Shell (shellcheck) | `shell-scanning` | ✅ CLOSED 2026-10-23 (KDEC-025): shellcheck 0.11.0 (and PSScriptAnalyzer 1.25.0 for PowerShell) in `deps-scan`, discovery-gated; `tests/prove_pipeline_lint.py`; no hosted run yet |
| A6 | Dockerfile (hadolint) | embedded in comprehensive/infra scans | ✅ CLOSED 2026-10-23 (KDEC-025): hadolint 2.15.1 in `iac-scan`, discovery-gated; `tests/prove_pipeline_lint.py`; no hosted run yet |

Coverage the reference estate does not have (FUTURE_WORK section 5; lane L-SCAN-B, KDEC-026, 2026-10-23
-- outside the 27 counted below, so the summary counts are unchanged by it):

| # | Capability | Kit | Evidence |
|---|---|---|---|
| A7 | Kotlin SAST | ✅ CLOSED: `sast-semgrep` `p/kotlin` floor + witness; CodeQL `java-kotlin` starts on Kotlin | `prove_semgrep_kotlin.py`, `prove_platform_discovery.py` (local); hosted `semgrep-kotlin` probe owed |
| A8 | Android configuration + Kotlin/Java mobile rules | ✅ CLOSED: `sast-mobile` (mobsfscan 1.0.1 by digest + kit rules) | `prove_sast_mobile_detects.py` (Linux container); hosted `mobile` probe owed |
| A9 | Swift / Objective-C / iOS configuration | ✅ CLOSED from source on ubuntu (`.m`/`.mm` now probed); CodeQL Swift left out -- macOS runners cost 10x, a recorded decision | `prove_sast_mobile_detects.py`; hosted `mobile` probe owed |
| A10 | Build-aware C/C++ | ✅ CLOSED: compilation database from the build the repo has; `CPP_ANALYSIS_PARTIAL` otherwise | `prove_cpp_build_aware.py` (Ubuntu container); hosted `cppcheck-build` probe owed |
| A11 | .NET on a real-shaped solution | ✅ CLOSED: multi-project fixture; per-project attribution fixed | `prove_dotnet_solution_detects.py` (host SDK); hosted `dotnet-solution` probe owed |

### B · Dependency & supply chain

| # | Capability | Source | Kit |
|---|---|---|---|
| B1 | Dependency CVE (trivy fs) | many | ✅ |
| B2 | NVD deep scan (Dependency-Check) | `nvd-cve-scanning` ×2 | ✅ observed on seeded fixtures; live-feed currency unproven |
| B3 | Python deps (safety, pip-audit) | `code-quality-scans`, `security-scanning` | ✅ CLOSED-BY-EXISTING (KDEC-025, measured 2026-10-23): OSV-Scanner + Trivy reported all 57 of pip-audit's advisories on pinned requirements; an unpinned requirement neither reads is a named `PythonDependenciesUnpinned` gap |
| B4 | Node deps (npm audit) | `frontend-security-scanning`, `json-validation` | ✅ CLOSED-BY-EXISTING (KDEC-025, measured 2026-10-23): all 8 of npm audit's GHSA ids on a lockfile were in OSV-Scanner's report (7 in Trivy's) |
| B5 | Dependabot integration | `dependabot-security-check`, `dependency-review` | ⚠️ partial: `reusable-dependabot-triage.yml` built locally, no hosted run |
| B6 | SBOM generation (syft) | the image build workflow | ✅ the flagship's `sbom` job (Syft, CycloneDX, licence verdict) and the build |

### C · Infrastructure & config

| # | Capability | Source | Kit |
|---|---|---|---|
| C1 | IaC security (checkov, terrascan) | `infrastructure-scans` ×3, `scan-pack` | ✅ |
| C2 | Terraform lint (tflint) | same | ✅ CLOSED-BY-EXISTING (KDEC-025, measured 2026-10-23): tflint found none of 3 seeded misconfigurations, Trivy config 2 of them among 8 (Checkov runs beside it); tflint is hygiene, not a security control |
| C3 | Terraform plan/apply | `terraform-plan-apply`, `deploy-infrastructure` | ❌ gap |
| C4 | PR-scoped terraform scan | `terraform-scan-on-pr` | ❌ gap |
| C5 | Teardown | `destroy-shared-services` | ❌ gap |

### D · Findings management ← **the largest and most differentiated gap**

| # | Capability | Source | Lines | Kit |
|---|---|---|---|---|
| D1 | **Vulnerability deduplication** | `deduplicate-vulnerabilities` ×3 | ~300 | ⚠️ partial: durable identity, matching cascade and anchored correlation (`scripts/finding_identity.py`, `finding_match.py`, `finding_correlation.py`) built and wired into the report; confidence and disagreement semantics not built |
| D2 | **Issue creation from scans** | `create-issues-from-scans` ×3 | ~294 | ⚠️ partial: `scripts/reconcile_tickets.py` + `reusable-ticket-reconcile.yml`, proven live on a personal Jira; no starter template calls it, no hosted run |
| D3 | **Scan-result ingestion** | `ingest-scan-results` ×2, `ingest-scan-results-to-dashboard`, `azure-security-ingestion` | ~212 | ⚠️ partial: `findings.json` in the evidence artifact, the baseline ledger and hash-chained lineage (`finding_lineage.py`) on the protected branch; no dashboard |
| D4 | **Roadmap update from findings** | `update-roadmap-from-scans` | 392 | ❌ **gap** |

*Updated 2026-10-23 (trunk `19b5e1d`): D1–D3 are built locally and partly wired; D4 is still a gap.*
When this table was first written the family had zero coverage in the kit. **It is the least
commonly built thing in the whole corpus.** Most organizations run scanners and stop; dedup, issue synthesis, and feeding findings into
a roadmap is the part that turns scan output into managed work. **Highest-value abstraction target
after the duplicate consolidation** — and the part with genuine portfolio value.

### E · Build & release

| # | Capability | Source | Kit |
|---|---|---|---|
| E1 | Docker build + push | `_reusable-build-docker`, `build-push-*` ×2 | ✅ |
| E2 | Deploy App Service | `_reusable-deploy-appservice` | ✅ |
| E3 | Deploy Container App | `_reusable-deploy-containerapp` | ✅ |
| E4 | Gov/prod gated deploy | `gov-prod-deploy-*` ×3 | ❌ gap |
| E5 | Change detection | `_reusable-determine-changes` | ✅ (composite action) |
| E6 | Multi-stage orchestration | `00-orchestrator` (293) | ❌ gap |

### F · Governance & policy

| # | Capability | Source | Kit |
|---|---|---|---|
| F1 | Workflow policy check | `workflow-policy-check` ×3 | ✅ |
| F2 | GitHub Actions lint (actionlint) | `github-actions-lint` ×2, `self-test` | ✅ the kit's own (self-test) and, since 2026-10-23, every consumer's: actionlint + zizmor in `deps-scan` (KDEC-025) |
| F3 | **Invariant gate** | `invariant-gate` (ui, 124) | ❌ **gap — investigate** |
| F4 | ADO mirror push | `push-to-azure-devops` | ❌ gap (org-coupled) |

### G · Quality

| # | Capability | Source | Kit |
|---|---|---|---|
| G1 | Python lint/type (ruff/mypy/pylint) | `reusable-code-quality-scan` ×3 | ✅ |
| G2 | JS/TS lint (eslint) | `frontend-security-scanning` | ✅ |
| G3 | JSON/YAML validation | `json-validation` | ⚠️ partial |

### H · Cost & operations

| # | Capability | Source | Kit |
|---|---|---|---|
| H1 | Resource shutdown / off-hours start | `resource-shutdown`, `off-hours-start-resources` | ❌ gap |

---

## Coverage summary — by capability, not lines

**27 capabilities identified · 14 covered · 8 partial · 5 gaps** (at trunk `19b5e1d`; when first
written: 12 · 4 · 11).

The gaps that matter, ranked:

1. **D1–D4 findings management** — 4 capabilities, ~1,200 lines, and the most differentiated work in
   the corpus. D1–D3 are now partial (built locally; confidence/disagreement, a template caller and a
   dashboard owed); D4 is still a gap.
2. ~~**B6 SBOM**~~ — built (the flagship's `sbom` job).
3. ~~**A4 CodeQL**~~ — built (the flagship's `codeql` job, proven at Level 2).
4. **F3 invariant gate** — 124 lines, unexamined. **Read before classifying.** May be a governance
   mechanism worth more than its size suggests.
5. **E6 orchestration** — 293 lines; determines whether the kit is a set of parts or a pipeline.

---

## Abstraction order (supersedes "next biggest file")

1. **Consolidate the duplicated families** — `comprehensive-code-scan`, `infrastructure-scans`,
   `security-scanning`, `code-quality-scans`. One parameterized reusable each, driven by the existing
   profile mechanism. **~7,000 lines → a few hundred.**
2. **Findings management (D1–D4)** — the differentiated capability, and the one nobody else has built.
3. **SBOM + CodeQL** — small, high assurance value.
4. **Read `invariant-gate`** before deciding where it belongs.
5. **Orchestration last** — it composes everything above and should be designed against the final
   shape, not the current one.

---

## Per-workflow accounting schema (required for every abstraction)

No workflow is abstracted without producing this record. Improvements go in a **separate** candidate
ledger — never folded silently into the neutral version.

```
Source workflow · Purpose/pressure · Trigger model · Inputs/secrets · Tools & actions ·
Security/quality gates · Blocking thresholds · Scan scope · Outputs/artifacts/SARIF ·
Cross-repo assumptions · External dependencies · Known validation behavior ·
Employer-specific bindings · Generic reusable mechanisms · Behavior intentionally preserved ·
Behavior changed during abstraction · Behavior dropped · Behavior unresolved (needs decision) ·
Verification needed after abstraction
```

**Three separate outputs per workflow:**

| Output | Contains |
|---|---|
| **Recovered behavior** | What the original actually did |
| **Neutral abstraction** | Same intent and mechanism, parameterized, employer bindings removed |
| **Improvement candidates** | What we now think should change — **not applied during abstraction** |

`NVD_ABSTRACTION_ACCOUNTING.md` was written before this schema existed and mixes layers 2 and 3. It
documents every change, so nothing is hidden, but its structure is the thing this schema exists to
prevent. Retrofit when that workflow is next touched.

---

## Open historical question — carried, not resolved

`nvd-cve-scanning` disabled thirteen Dependency-Check analyzers, including `--disablePyDist` and
`--disablePyPkg`, on a scan whose target was a Python application. Four hypotheses, none yet
supported by evidence:

1. Trivy handled Python dependency scanning and Dependency-Check served a deliberately narrow role.
2. The flags were inherited from another stack's configuration and never re-tuned.
3. They existed to suppress false positives.
4. They existed to control runtime, and the scan was quietly neutered as a side effect.

**Do not restore or delete by reflex.** This is pressure → mechanism → effect archaeology; the answer
determines whether Dependency-Check belongs in the neutral kit at all.
