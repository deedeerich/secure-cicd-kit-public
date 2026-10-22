# 02 · What happens in one run

The consumer calls one reusable workflow:

```yaml
permissions:                   # everything the kit's jobs request, or GitHub refuses the run
  contents: read
  security-events: write
  actions: read                # the CodeQL job
jobs:
  security:
    uses: <kit-owner>/<kit-repo>/.github/workflows/reusable-security.yml@<commit-sha>
    with:
      environment: prod        # the baseline-ledger environment; empty names none
      # language: auto, iac_mode: auto, paths: ".", soft_fail_sast: false are the defaults AND the
      # baseline -- change nothing to get PROCEED on a clean run (part 05)
    secrets:
      SEMGREP_APP_TOKEN: ${{ secrets.SEMGREP_APP_TOKEN }}   # optional; the only secret it takes
```

Pin the kit by **commit SHA**, never a branch or a moving tag: the verdict is only as trustworthy as
the code that produced it.

## The job graph (VERIFIED against the workflow on trunk)

```
kit-scripts ─┐
             ├─> secret-scan, code-quality, sast-semgrep, sast-bandit, sast-java, sast-go,
discover ────┘   sast-dotnet, sast-cpp, codeql, deps-scan, iac-scan, malicious-deps, sbom,
     │           image-scan                       (14 scanner jobs)
     └─> resolve  (version fitness and capability selection; runs beside the scanners, not before)
                          │
                          v
                       report  (renders 25 scanner rows; counts blocking findings per job;
                                writes findings.json into the evidence artifact)
                          │
                          v
                    security-gate  ── step `gate`    (what happened)
                                   └─ step `posture` (what should happen next: routing_result,
                                                      advisory_causes)
```

### 1. `kit-scripts` — the kit's own scripts, verified

Writes the kit's helper scripts once and publishes them as a **run-scoped artifact** with a pinned
SHA-256 manifest. Every scanner job downloads that artifact and verifies the digest before using it.
A script that arrives unverified is a supply-chain step with no integrity check.

If this job fails, every scanner is skipped — and a skipped scanner is **not** a clean scanner. The
gate treats the toolchain as its own question: a `kit-scripts` failure blocks in every mode, including
advisory.

### 2. `discover` — what is actually here

Eight presence probes (python, node, go, dotnet, java, cpp, php, iac; php since lane L-PHP) plus an unsupported-language sweep
and a platform probe (visibility, code-scanning and secret-scanning availability, Dependabot state).
Each probe distinguishes **found nothing** from **could not look**: a probe that errors does not read
as "not present". If the survey itself cannot run, discovery turns **everything on** and reports
`DISCOVERY_UNAVAILABLE` — over-scanning is recoverable, a silent skip is not.

Languages present that no kit scanner can read are reported as `COVERAGE_GAP` — present, a control is
owed, nothing looked — and the gate repeats them so a green result is never read as full coverage.
PHP is no longer one of them; a `composer.json` without its `composer.lock` is
(`PHPDependenciesUnlocked`), because the dependency scan reads only the lock.

**The search has a depth bound of 8 directory levels** (`11db350`, VERIFIED: `prove_discovery_depth.py`
at `078ef90`). A probe that found nothing while the scope holds entries deeper than 8 levels reports
`UNDETERMINED` and **runs the scanner** ("none within 8 levels; deeper not searched") instead of
`NOT_APPLICABLE`, and any entry beyond the bound adds a `BeyondSearchDepth` coverage gap. The Node,
.NET and Go root enumerations search the same 8 levels and declare deeper entries the same way. Cost:
in a repository with anything deeper than 8 levels, every language discovery cannot see runs its scanner.

The caller's `language` input can only **exclude** ecosystems discovery found (reported as
`EXCLUDED_BY_SELECTOR` and recorded as a narrowing in the posture record).

### 3. The scanner jobs

Each scanner job follows the same shape (part 04 lists every job):

```
install the tool (pinned) → run it, never letting its exit code decide anything
  → COUNT: report present? parseable? how many blocking findings? (absent/unparseable = COLLECTION_FAILED)
  → ENFORCE: separate step; HANDS findings over its threshold to the gate (findings_state=FINDINGS)
             and fails only when the count could not be established
  → redact → keep the SARIF as an artifact → publish to the Security tab where available
  → say plainly if publication degraded (publication never decides pass/fail)
```

**The security gate is the single enforcement point** (lane L-S, owner ruling O-24; VERIFIED locally
by `tests/prove_gate_policy_enforcement.py`, `sep_*` scenarios, which run the shipped enforce steps and
then the gate). A scanner job **reports**: it succeeds with findings and publishes them as the job
output `findings_state=FINDINGS`; it **fails only when it could not scan or could not trust its own
result** — a tool crash, `COLLECTION_FAILED`, a hollow or unparseable report, a bootstrap failure. The
gate then enforces by the resolved policy, so the workflow's conclusion **is** the verdict: at crawl an
ordinary finding leaves every job green and routes `PROCEED_WITH_ADVISORY`; a broken scan is red
(`EVIDENCE_UNTRUSTED`); at `run` the same finding is red at the gate (`BLOCKED`) while the scanner job
stays green. **Secrets go to the gate as well** (owner ruling 2026-10-22): the secret scan hands its
secrets over with their count, and the gate **blocks them at every tier** unless the policy register
excepts each one — one finding by its fingerprint, a ticket, an explanation, a named approver, an
expiry, and a renewal history under the cap (part 03; `docs/adoption/POLICY_REGISTER.md`). The secret
scan always covers the **repository root**: `paths` narrows the other scanners, never it (KDEC-018,
crawl is the floor). A separate weekly workflow, `reusable-exception-due.yml`, raises every exception
coming due on its Jira ticket (part 05). Only the gate holds the policy, so only the gate
can honour an exception. An image's secrets step and a known-malicious package, which no register
excepts, still fail their own job. `advisory_mode` and
`soft_fail_sast` still soften what a job hands over — recorded as weakenings in the posture record —
but they are no longer what keeps a scanner job green. A non-secret scanner job that **fails beside
findings on record** could not finish its scan, and the gate reads it as untrusted, not as findings.

A run that skipped part of its input is not a clean run: every `semgrep scan` runs with `--strict`, so
a file Semgrep cannot parse is exit 3 and `COLLECTION_FAILED`, not a warning and a zero; a CodeQL
autobuild that did not succeed makes that language's state `PARTIAL` in the summary (`1542c05`; the
gate does not read it yet, part 04).

**Detection is separated from enforcement**, and **redaction precedes every publication** in the job,
including the last upload (VERIFIED: 29 uploads, each preceded by a redaction, checked by
`tests/check_redaction_parity.py`).

### 4. `report` — evidence assembled, findings counted

Runs from the kit's own repository via a composite action (`$/` reference), so it executes beside the
modules it imports. It renders one row per **scanner** (25 rows, not one per job — two scanners in one
job each get their own verdict), applies approved dispositions read from the **protected default
branch**, computes durable finding identity where it can, and publishes per job the count of
**blocking findings** that remain. That count — not the job's conclusion — is what tells the gate
whether findings exist. It uploads the evidence artifact `security-report-<run_attempt>`.

A row reads **NOT ESTABLISHED** when the tool's evidence shows it examined nothing. What counts as
"examined nothing" is per tool (KDEC-008 OD-2): since `fa19c02` the report agrees with the runner's
validity check that a **clean Bandit run is not hollow** (Bandit lists only rules that fired, so an
empty rule list is normal), and it reads error notifications from both SARIF notification arrays.

### 5. `security-gate` — two questions, then a verdict

Step `gate` answers two separate questions and never collapses them:

| output | question |
|---|---|
| `assurance_state` | what did this run ESTABLISH? `PASS`, `FINDINGS`, `PARTIAL`, `UNDETERMINED` |
| `enforcement_state` | what did the gate DO? `BLOCKED`, `ADVISORY`, `ALLOWED` |

Then step `posture` (runs even when the gate blocked) enumerates every input, records each weakening
and who decided it, and emits the **verdict**: `routing_result`. Deploy reads that. The job ends on a
`verdict` step that fails it on `BLOCKED` and `EVIDENCE_UNTRUSTED`, so a caller's `needs: security`
skips on exactly those (`templates/build-deploy.yml` then refuses any deploy below
`PROCEED_WITH_ADVISORY` from `routing_result`). Part 03 has the exact rules.

## What crosses the run boundary

Only the merge commit and retained artifacts. Nothing computed in one run is re-classified in another;
a later automation may retrieve and render a verdict computed in the run, never compute one after the
fact (SINGLE_PIPELINE_TARGET §2.4, §3.1).

## Triggers (DESIGNED; the flagship runs on whatever event the consumer wires)

| context | what it arms |
|---|---|
| pull request | detection, identity matching (read-only), gate, verdict. Never writes the ledger or tickets |
| merge to the protected branch | the above, plus ledger proposals and ticket reconciliation (separate privileged job) |
| nightly / scheduled | deeper depth (history scan), revalidation of what is deployed, deferral sweeps |

## Where the long-term shape is going (DESIGNED, partly built)

The workflow is being decomposed so each scanner's logic lives in its own composite action called via
`$/` from the kit repository (step 8 of the decomposition plan proved this works across repositories;
the report is the first composite). Target: the main workflow around 42 KB, and a scanner registry
(`scanner-registry.yaml`, already enforced by `tests/check_scanner_registry.py`) as the authoritative
list the gate must read.
