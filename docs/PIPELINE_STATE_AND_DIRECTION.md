# The delivery pipeline — current state, what is missing, what is in flight

```
Phase:              1
Truth State:        confirmed where marked VERIFIED; see the label on each claim
Audience:           security leadership and anyone writing a finding about delivery security
Decision Supported: how to characterise pipeline security posture honestly, and what to prioritise
Deferred Depth:     per-job YAML, scanner contracts, the fifteen-stage target architecture
Written:            2026-10-05
```

> **This document does not sugar-coat.** A finding that says "pipelines are broken" is wrong, and a
> finding that says "pipelines are fine" is also wrong. The accurate statement is narrower and more
> useful: **a substantial security pipeline exists and runs; several of its assurance claims are not
> yet established; two defects are already fixed and awaiting a paid test run; and the roadmap that
> closes the rest is written rather than imagined.**
>
> An untested patch in the wings is not an embarrassment. It is a known defect with a known fix and a
> known cost to verify, which is a materially better position than an unknown defect — and it tells
> you exactly where the priority is.

---

## 1 · What exists and runs today `VERIFIED 2026-10-05`

A reusable GitHub Actions security library that calling repositories reference by `workflow_call`
rather than copy-pasting pipeline logic. **18 jobs, 12,097 lines of workflow, 7 composite actions.**

```
kit-scripts ──┐
              ├─> discover ──> 13 scanners in parallel ──> report ──> security-gate
```

Implemented and running: secret scanning, SAST across Python, Go, Java, .NET, C/C++ and multi-language
rules, dependency scanning, IaC scanning, container image scanning, malicious-package detection, SBOM
generation, code quality, and CodeQL.

**Design principles actually enforced in the code**, not merely stated:

- Security gates run before deploy; deploys cannot proceed without them
- OIDC-only cloud authentication — no long-lived credentials
- No deploy-on-push; deploys are dispatched and gated
- Supply-chain integrity via SBOM, image-digest pinning and provenance metadata
- Everything environment-specific arrives as an input or secret from the caller

**It requires no GitHub Advanced Security.** Every engine is open source; GHAS only ever supplied the
Security tab and triage. Findings persist as build artifacts regardless, and when publication is
unavailable the run reports `PUBLICATION=DEGRADED` — never a failed scan.

### Three rules the kit holds itself to

1. **Silence is never a correct outcome.** Every scanner emits findings, an explicit "nothing to scan,
   and here is the path I searched", or a loud failure. Anything else is a defect.
2. **Never change scanner configuration to make a real run green.** Classify first.
3. **Detection immediately, enforcement deliberately.**

---

## 2 · What is genuinely wrong, stated plainly

### 2.1 A scanner was acquiring nothing and reporting success `VERIFIED 2026-10-05`

The published pipeline pulls a Go security scanner by a **container tag that has never existed**. The
pull fails, the scanner never runs, it produces no findings — and the job reports **success**. A
different scanner's rules caught the seeded test signal, so coverage looked intact.

This was detected on **2026-09-30** by a tool-pinned assertion that requires the *named* scanner to
find its own seeded signal. Nothing else in the system noticed: every scanner job and both security
gates reported success.

**Fixed in local work** — acquisition now pins a real version and emits an explicit
`DEPENDENCY_ACQUISITION_UNAVAILABLE` state when it fails, so an unacquired scanner can never again be
silent. **The fix is written and not yet verified by a run.**

> This is the single most important thing in this document, and not because of the one scanner. It
> is the proof that **a tool exiting zero establishes nothing about what it examined.** That is the
> defect class, and it is why the assurance work below is not bureaucracy.

### 2.2 Assurance debt is overdue and the build is red `VERIFIED 2026-10-05`

The kit enforces a ratchet on its own claims: every capability not independently proven must carry a
dated, owned, expiring deferral, and an expired deferral **fails the build**. Six decisions expired on
2026-09-30 and have not been answered. The build is correctly red.

The largest is structural: **twelve capabilities are proven at tool level only.** The scanners are
installed and execute; the workflow that orchestrates them has not been run end to end against the
current code, so input threading, language selectors, result categories and gate wiring are unproven.

**The probe for this already exists** and calls the pipeline at two levels. It has not been run
against the commit containing the fixes — see §4.

### 2.3 Deploy and rollback have never executed `READ`

Both deployment workflows are provisional and have never run. Their assurance deferrals expire
**2026-10-31**. A rollback contract is written and specifies the hard parts correctly — ownership
stamps, refusal when a later change or a new dependent would be disturbed, and explicit
`ROLLBACK_REQUIRES_HUMAN_DECISION` / `ROLLBACK_PROHIBITED` outcomes rather than forcing a reversal.
**Written, not exercised.**

### 2.4 No scanner or language version-fitness gate `VERIFIED 2026-10-05`

Nothing checks whether a pinned scanner still understands the language, framework, lockfile format or
provider schema it is handed. Discovery reports *presence* — "is Go here?" — not *version*, so a
scanner that can no longer parse what it is given reports **CLEAN** rather than a coverage gap.

That is §2.1 generalised: a pipeline without this gate can scan last year's technology faithfully and
hand today's code a green tick. **The design exists** — including an experiment that demonstrates the
defect rather than asserting it — and is not implemented.

---

## 3 · What is designed and in flight

A fifteen-stage target architecture is written, with each stage recording what exists today, what the
target is, and what it takes to get there. The stages that are absent or partial, in priority order:

| stage | state | what it means in practice |
|---|---|---|
| version discovery | absent | §2.4 — a scanner's fitness is never checked |
| capability selection | partial | tools are chosen by language presence, not by whether they can read the version found |
| evidence validity | partial | a zero-finding, zero-artifact report should be PARTIAL, never clean. **Weakest link in what already ships.** |
| baseline and classification | partial, and wrongly | finding identity is computed from scanner name and rule id, so a scanner upgrade resets every finding's history. Must be replaced, not extended. |
| correlation | a count, not a cluster | the pipeline reports how many findings more than one tool saw; it cannot say *which* are the same issue |
| ticket reconciliation | absent | findings do not yet become tracked, dispositioned work |
| execution planning | neither design nor build | the one stage with nothing |

**Prior work already solves part of this and is recorded rather than re-derived**: a weighted
confidence score instead of boolean matching, a line-drift window that keeps signal a naive
fingerprint throws away, and a measured observation that 60% of platform-native alerts carry no CWE —
which is why CWE-only correlation produces false matches.

---

## 4 · Why it has not been run, and what that costs

The fixes above sit in **20 commits that have not been published**, so no runner can execute them. That
is a deliberate decision, not an oversight.

**The reason:** the pipeline's process shape is known to be wrong in the ways listed in §3. Paying for
pipeline minutes to prove that a known-incomplete shape is green buys a green tick over stages that
are missing by design. The work in flight makes the process correct *first*; the paid verification run
happens when there is something worth verifying.

**What that costs:** every capability claim stays at tool level until a run happens, and §2.1 remains
fixed-but-unverified. **That is the honest state and it should be reported as such** — not as a risk
being ignored, but as a sequencing decision with a named trigger.

---

## 5 · How to characterise this in a finding

**Accurate:**

> A reusable security pipeline is implemented and running across thirteen scanner classes with gates
> before deploy and OIDC-only authentication. Its own assurance controls have detected that one
> scanner was acquiring nothing while reporting success — a defect now fixed and awaiting
> verification — and that twelve capabilities are proven at tool level but not end to end.
> Deployment and rollback paths are written and have never executed. A version-fitness gate, finding
> identity, correlation and ticket lifecycle are designed and not implemented. Remediation is
> sequenced and in progress.

**Not accurate, in either direction:** "the pipeline is broken" — it runs, gates, and caught its own
dead scanner. "Pipeline security is in place" — a third of the assurance chain is unproven and
deployment has never run.

**The sentence worth keeping:** a pipeline that detects its own blind scanner is in better condition
than one that reports green because nothing is checking. The defect was found **by the kit's own
controls**, not by an auditor, and that is the capability worth reporting.

---

## 6 · Priorities, in order

1. **Make the process correct** — the stages in §3, highest value first: evidence validity, then
   finding identity, then version fitness.
2. **Answer the six expired decisions** by proof or a fresh dated decision. Never by moving a date.
3. **Then publish and run the probe**, confirming §2.1 and converting twelve tool-level capabilities
   to pipeline-level.
4. **Then the deployment and rollback paths**, before 2026-10-31.

**Vulnerability findings — the near-term operational need:** the scanning that produces them runs
today and its output persists as artifacts. What is missing is not detection but **lifecycle** —
durable finding identity, correlation across tools, and reconciliation into tracked work. Findings can
be produced now; they cannot yet be *tracked* across runs without the identity work in §3.
