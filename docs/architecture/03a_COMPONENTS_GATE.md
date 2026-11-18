# 03a · Components: the security run and its gate

```
Kept:      2026-11-07, drawn against the trunk at c1420ea. Notation: 00_NOTATION_AND_LEGEND.md.
Container: .github/workflows/reusable-security.yml (called by templates/security.yml,
           templates/build-deploy.yml job `security`, templates/kit-api.yml job `scan`).
Design:    10a_DESIGN_SECURITY_GATE.md. Ordering rules: PIPELINE_ORDERING_AND_SCAN_VALIDITY.md.
```

## 1 · The jobs, in run order

```mermaid
flowchart TB
  TRIG[/"push, pull request, dispatch, or a kit API scan.request"/]:::kit
  subgraph PLAN["job plan  (contents: read, security-events: read)"]
    P1["part 1: write the canonical scripts,<br/>pin their digest, redact, publish kit-scripts<br/>BEFORE the checkout<br/>[T]"]:::ctrl
    P2["checkout the consumer's commit"]:::kit
    P3["discover part survey:<br/>languages, IaC, workflows, deploy targets<br/>[D]"]:::kit
    P4["discover part platform:<br/>GHAS, push protection, rulesets, visibility"]:::kit
    P5["plan the CodeQL legs from discovery"]:::kit
    P6["resolve: versions, capability, coverage,<br/>the plan of which scanner reads what<br/>[D]"]:::kit
  end
  subgraph SCANS["scanner jobs, each only where discovery applies"]
    S1["secret-scan: gitleaks + detect-secrets<br/>[I]"]:::kit
    S2["sast-semgrep, sast-bandit, codeql,<br/>sast-dotnet, sast-java, sast-go,<br/>sast-cpp, sast-mobile, code-quality"]:::kit
    S3["deps-scan: Trivy fs + pipeline lint<br/>(actionlint, zizmor, shellcheck, PSScriptAnalyzer)"]:::kit
    S4["iac-scan: Checkov, Trivy config, hadolint"]:::kit
    S5["image-scan, malicious-deps (OSV), sbom (Syft)"]:::kit
  end
  subgraph GATE["job security-gate  (contents: read)  [T R D]"]
    G1["collect every SARIF; per-scanner state"]:::kit
    G2["render the report: findings.json,<br/>security-report-ATTEMPT (C2)"]:::store
    G3["capability floor:<br/>every expected scanner left a state"]:::ctrl
    G4["clear the workspace"]:::kit
    G5["resolve the policy from the register<br/>on the protected default branch"]:::ctrl
    G6["KEV check of every CVE"]:::ctrl
    G7["enforce required scans:<br/>the routing_result"]:::ctrl
    G8["control posture, leak-gate posture"]:::kit
    G9["run record, reviewer signals,<br/>kit-security-record-ATTEMPT (C2)"]:::store
    G10["plain words, then exit on the verdict"]:::kit
  end
  TRIG --> P1 --> P2 --> P3 --> P4 --> P5 --> P6
  P6 --> S1 & S2 & S3 & S4 & S5
  S1 & S2 & S3 & S4 & S5 -->|"SARIF and findings_state (C2)"| G1
  G1 --> G2 --> G3 --> G4 --> G5 --> G6 --> G7 --> G8 --> G9 --> G10
  G10 --x|"BLOCKED or EVIDENCE_UNTRUSTED: the run fails"| RED(("red"))
  G10 -->|"PROCEED, PROCEED_WITH_ADVISORY, DECISION_REQUIRED"| GREEN(("green, outputs for the deploy"))
  classDef kit fill:#dbeafe,stroke:#1d4ed8,color:#0b1b3f
  classDef store fill:#fef3c7,stroke:#b45309,color:#3b1d02
  classDef ctrl fill:#fee2e2,stroke:#b91c1c,color:#450a0a
```

Cited: the job and step names of `.github/workflows/reusable-security.yml`; `.github/actions/discover/action.yml`,
`.github/actions/resolve/action.yml`, `.github/actions/scan-report/action.yml`,
`.github/actions/capability-floor/action.yml`, `.github/actions/resolve-policy/action.yml`,
`.github/actions/known-exploited/action.yml`, `.github/actions/run-record/action.yml`,
`.github/actions/reviewer-signals/action.yml`, `.github/actions/plain-errors/action.yml`.

## 2 · The components and what each holds

| Component | Code | Holds | Proof |
|---|---|---|---|
| kit-scripts part | `plan` job part 1; `scripts/inline_normalizer.py` | the scripts are the pinned ones; written before consumer content is in the workspace | `tests/prove_plan_job.py`, `tests/prove_kit_script_digests.py` |
| survey | `.github/actions/discover` part `survey` | what is in scope; an unreadable root is named, never "nothing there" | `tests/test_discovery.py`, `tests/prove_discovery_depth.py` |
| platform | `.github/actions/discover` part `platform` | GHAS, push protection, rulesets; `UNKNOWN` is not `false` | `tests/prove_platform_discovery.py` |
| resolve | `.github/actions/resolve` | which carried scanner can read each target (KDEC-010); version gaps | `tests/test_resolve.py`, `tests/prove_capability_selection.py` |
| scanner jobs | `reusable-security.yml` jobs and the scanner composites | each reports `findings_state`; a job fails only when it could not scan | `tests/prove_scanners_survive_enforce.py`, `tests/prove_hollow_scan.py` |
| report | `scripts/scan_report.py` via `.github/actions/scan-report` | five sections; zero only when a scanner looked | `tests/prove_report_and_gate.py`, `tests/prove_report_counts_findings.py` |
| capability floor | `scripts/capability_floor.py`, `capability-floor.json` | a scanner removed from the registry is still expected | `tests/prove_capability_floor.py` |
| policy | `scripts/policy_registration.py` via `resolve-policy` | rung and per-control minimums from the protected default branch, never the PR tree | `tests/prove_gate_reads_rung.py`, `tests/prove_policy_registration.py` |
| KEV | `scripts/known_exploited.py` | a CVE on CISA KEV blocks at every rung; an unreadable catalog is never a pass | `tests/prove_known_exploited.py` |
| enforce | the `gate` step | the precedence maximum of every control's route | `tests/prove_gate_routing.py`, `tests/prove_bootstrap_failure.py`, `tests/prove_secrets_always_block.py` |
| posture | control and leak-gate posture steps | required, executed, unavailable, reduced, skipped, and who decided | `tests/prove_leak_gate_posture.py` |
| run record | `scripts/run_record.py` | the record validates against `schemas/assurance-result.schema.json` or is not emitted | `tests/prove_gate_run_record.py` |
| reviewer signals | `scripts/reviewer_signals.py` | weakening authority, verdict provenance, watermark, the security record | `tests/prove_reviewer_signals.py` |
| plain words | `scripts/plain_errors.py` | every refusal said in a sentence first, the state name after | `tests/prove_plain_errors.py` |

## 3 · The verdict words

The gate emits one `routing_result`, the precedence maximum across controls:

`BLOCKED` > `EVIDENCE_UNTRUSTED` > `DECISION_REQUIRED` > `PROCEED_WITH_ADVISORY` > `PROCEED`

- The rung (crawl, walk, run) sets the weakest result each control may contribute
  (`scripts/rung_ladder.py`; `RUNG_DERIVATION_TABLE.md`).
- Secrets block at every rung. A known-exploited CVE blocks at every rung (KDEC-022). A known-malicious
  package blocks in every mode.
- At a production tier (uat, prod) `EVIDENCE_UNTRUSTED` stops the run; below it warns
  (`scripts/enforcement_axes.py`).
- An absent or unrecognised verdict is `EVIDENCE_UNTRUSTED`, never a pass (the template's `verdict` job).

## 4 · Outputs the rest of the kit reads

The workflow declares 47 outputs. The ones other containers depend on:

| Output | Read by |
|---|---|
| `routing_result`, `advisory_causes`, `controls_unavailable` | the template's `verdict` job; every deploy |
| `deploy_approval`, `max_exception_renewals` | every deploy (approver groups, renewal cap) |
| `evidence_artifact`, `security_record` | the ticket reconciler, the kit API, `evidence.export` |
| `kev_state`, `kev_verdict` | the security record; the promotion re-check |
| `rung_effective`, `policy_source`, `environment_tier` | the reviewer signals; the evidence |

## 5 · Trust and threat notes

- **TB-1** (consumer to kit): caller inputs reach every script as `env:` data, never as script text
  (`tests/lint_injection.py`, `tests/check_expression_length.py`).
- **TB-2** (PR content): on a pull request the policy is read from the protected default branch, so a
  PR cannot choose its own rung (`tests/prove_gate_reads_rung.py`).
- **TB-6** (scanner supply chain): every tool is pinned by version and checksum
  (`tests/check_pinned_installs.py`); the Trivy DB, OSV and KEV come from the organisation mirror only when
  current and intact (`tests/prove_feed_mirror.py`).
- **D (the quiet denial)**: a skipped or crashed scanner is `NOT_ESTABLISHED`, never zero
  (`tests/prove_hollow_scan.py`, `tests/prove_scan_status_zero.py`).
- Threat entries: [09_THREAT_MODEL.md](09_THREAT_MODEL.md) TH-TB1-*, TH-TB2-*, TH-TB6-*.
