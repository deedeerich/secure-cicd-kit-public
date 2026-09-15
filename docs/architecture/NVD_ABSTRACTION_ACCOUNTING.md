# `reusable-nvd-cve.yml` — full accounting of the abstraction

Source: a 253-line single-repo `nvd-cve-scanning.yml`. Read in full before this was written.
This file exists so nothing is silently lost in translation. **Everything dropped is listed.**

---

## 1 · Kept as-is (mechanism carried forward)

| Item | Note |
|---|---|
| NIST compliance disclaimer block | Required by NIST terms of use — must never be stripped |
| Trivy install via official `install.sh` | Used for the Dockerfile config pass |
| Dependency-Check install pattern | apt `openjdk-17-jre-headless` + `unzip` → wget release zip → `/opt/` → chmod → `GITHUB_PATH` |
| `--updateonly --data /tmp/nvd-data --nvdApiKey` | The two-phase update-then-scan pattern |
| Core DC args | `--project` · `--scan` · `--format` · `--out` · `--enableExperimental` · `--data` · `--disableOssIndex` · `--failOnCVSS` |
| `schedule: '0 5 * * *'` | Including the "after NVD publishes" rationale |
| `permissions:` block | `contents: read` + `security-events: write` |
| Dockerfile discovery via `find` | Restructured but the intent is preserved |

## 2 · Abstracted (same behavior, now parameterized)

| Original (hardcoded) | Now |
|---|---|
| the original hardcoded scan paths | `scan_paths` input |
| a hardcoded project name | `project_name` input, defaults to `${{ github.repository }}` |
| a repository-specific secret name | `secrets.NVD_API_KEY` |
| `--failOnCVSS 9` | `fail_on_cvss` input — **default changed to 11 (never fail)**, see §5 |
| Dependency-Check `9.0.9` pinned in URL | `dependency_check_version` input |
| Python `3.11` | `python_version` input, default `3.12` |
| `retention-days: 90` | `artifact_retention_days` input, **default 30** |
| `on: push / pull_request / schedule / dispatch` | `on: workflow_call` — triggers now belong to the consumer template |

## 3 · Added (was not in the original)

- **SARIF output and upload for both scanners.** The original's SARIF step was a **stub that never
  uploaded anything** — it echoed *"Trivy JSON output is not SARIF format. SARIF upload skipped."*
  Findings never reached the Security tab. This closes a gap the original already documented.
- **NVD data caching** (`actions/cache` with a warm restore key). The original re-downloaded every run.
- **Explicit separation of reporting and gating.** Reporting runs `exit-code: 0`; the gate is its own
  configurable step.
- **Loud failure on NVD update.** Sets `NVD_UPDATE_FAILED`, emits a warning, and the summary states
  that an empty result does **not** establish "no known vulnerabilities."
- **Warning when no API key is configured.**
- **Structured step summary** (which scanners ran, paths scanned, staleness warning).

## 4 · DROPPED — recreate if needed

**These are real losses. Nothing here was replaced by an equivalent.**

### 4.1 The Dependency-Check analyzer disable list ⚠ most significant

The original passed **thirteen** `--disable*` flags. Only `--disableOssIndex` was carried forward:

```
--disableAssembly   --disableRetireJS  --disableNodeJS   --disableNPM      --disableNugetconf
--disableNuspec     --disableComposer  --disablePyDist   --disablePyPkg    --disableRubygems
--disableCmake      --disableAutoconf  --disableCocoapods
```

**Impact:** Dependency-Check will now run **all** analyzers — slower, and likely noisier. That flag
list was deliberate tuning and it is gone.

**Open question worth answering before restoring them blindly:** with `--disablePyDist` and
`--disablePyPkg` set, the Python analyzers were **off** — on a scan whose target was a Python app.
Combined with NodeJS/NPM/Composer/Ruby/Nuget/CMake/Autoconf/Cocoapods/RetireJS/Assembly also off,
Dependency-Check had very little left to analyze. Either Trivy was doing the real dependency work and
DC was near-vestigial, or the flags had drifted out of sync with intent. **Worth deciding rather than
restoring by reflex.**

### 4.2 Sibling-repository scanning

The original probed for `../infra-agent` and `../infra-shared-services` and scanned them if present —
one workflow covering multiple checked-out repos. **Not reproduced.** The reusable version scans only
within the calling repo. Restoring this means the consumer checks out siblings and passes them via
`scan_paths`.

### 4.3 Per-component output files

Original produced per-repository named outputs,
`trivy-infra-shared.{json,txt}`, `trivy-repo.{json,txt}`, and `trivy-<Dockerfile>.json` — a separate
report per component. **Now one SARIF plus one artifact directory.** The per-component breakdown is
lost.

### 4.4 `--security-checks vuln,config` on the filesystem scan

The original ran vulnerability **and** misconfiguration checks together across the filesystem. Here,
vuln runs via `trivy-action` and config runs only against Dockerfiles. **Non-Dockerfile
misconfiguration scanning is not in this workflow** — `reusable-security.yml`'s `iac-scan` job covers
Terraform/IaC, but that is a different workflow the consumer must also call.

### 4.5 `--db-repository ghcr.io/aquasecurity/trivy-db`

Explicit Trivy DB registry pin. **Dropped**; the action default is used. Matters for mirrored or
egress-restricted environments — restore as an input if the target org proxies registries.

### 4.6 Human-readable table output in the summary

The original piped raw `trivy-repo.txt` into the step summary. Replaced with a status table. Findings
are now in SARIF/code scanning and the artifact, not inline in the summary.

## 5 · Behavior changes to decide on

| Change | Original | Now | Why |
|---|---|---|---|
| **CVSS gate** | `--failOnCVSS 9` — **did block** at CVSS ≥ 9 | Default `11` = never blocks | A reusable default should not silently start failing other people's builds. **If you want the original posture, set `fail_on_cvss: 9`.** |
| Artifact retention | 90 days | 30 days default | Cost; override per consumer |
| Trivy fail severities | n/a (`\|\| true` everywhere) | `trivy_fail_severities: ""` = report-only | Gate is now explicit and opt-in |

## 6 · Validation state

**Nothing here has run on a runner.** YAML parses; `workflow_call` shape verified locally. Highest-risk
unverified assumption: **that Dependency-Check 9.0.9 supports `--format SARIF` and writes
`dependency-check-report.sarif`.** If it does not, that step fails and the upload finds no file.
Full list in `VALIDATION_DEBT.md`.
