# When it goes red — classify before you change anything

**Workflow correctness and security posture are different questions, and collapsing them is how a
truthful security system gets quietly dismantled.**

A run that correctly discovers real vulnerabilities is a **successful test of the pipeline** and a
**failed security assessment of the repository**. Those are not the same event, and only one of them
is a reason to touch the kit.

If your first run on a real repository goes green, be suspicious. Inherited codebases have inherited
debt; a scanner that finds none of it has usually found nothing at all.

## The four outcomes

| Machinery | Result | Meaning |
|---|---|---|
| worked | clean / below threshold | ✅ system works, repo passes |
| **worked** | **real blocking findings** | ✅ **system works, repo fails security. A true positive is a pipeline SUCCESS.** |
| worked | evidence incomplete | ⚠️ assurance incomplete — see `ASSURANCE_PREREQUISITE_GAP` |
| **failed** | cannot determine | ❌ **this** is a kit/integration failure |
| **never ran** | cannot determine | ❌ **`EXECUTION_UNAVAILABLE`** — billing, infrastructure, policy or timeout. Not a finding, not clean, not a scanner defect |

## The six classifications

Every red result gets one **before** anything is modified.

### `KIT_DEFECT`
The machinery is wrong. The scanner looked at the wrong directory, an action ref was invalid, a
report vanished, a job installed a tool and never ran it, or a missing publication channel was
reported as a missing finding.

**→ Fix the kit.** This is the *only* class that justifies changing the workflow.

### `REPO_TRUE_FINDING`
The scanner is right. There is a real vulnerability, secret, or misconfiguration.

**→ Preserve it.** Correlate it, evaluate consequence, remediate the repository on its own schedule.
Never tune the scanner to make it disappear. If a true finding is being accepted for now, that is a
*disposition with provenance*, not a scanner configuration change.

### `ASSURANCE_PREREQUISITE_GAP`
Not a vulnerability — a condition preventing a security **claim** from being established. A Node
project with `package.json` and no lockfile: source SAST ran, dependency analysis could not.

**→ Report it explicitly** (`NODE_SCA_PARTIAL`), then decide which of three cases applies:
the project genuinely should have the artifact (add it) · a scanner-specific prerequisite (adapt the
scanner or use another) · a legacy layout where the artifact makes no sense (scan what can be
scanned and **state the coverage boundary**).

**The workflow will never generate the artifact for you.** Doing so converts *"we cannot establish
this"* into *"we quietly changed the project until we could."*

### `FALSE_POSITIVE` / `APPLICABILITY`
The finding is technically produced but does not mean what it appears to. Real examples from the
first external run: gitleaks flagging 118 high-entropy strings inside cached *security-finding
payload* JSON; Bandit's `B101` firing on every `assert` across a test suite.

**→ Validate, document, and tune NARROWLY — with provenance.** Never "make the scanner shut up"
globally. A global suppression takes the next *real* occurrence with it, and nobody will remember
why. A disposition names the path, the rule, the reason and the date.

### `EXECUTION_UNAVAILABLE`
**Added 2026-08-18 from three days of hard evidence.** The machinery never got to run, or was killed
before it finished. **This is not a scanner failure and never a finding** — it means *the security
posture cannot be determined from this run at all*.

The remediation differs completely per reason, so the reason is part of the classification:

| `reason` | Signature you will actually meet |
|---|---|
| `BILLING_EXECUTION_REFUSED` | job has **0 steps**; annotation says payments failed or the spending limit needs raising |
| `ACTION_ACQUISITION_FAILURE` | job has **1 step**; `Set up job` fails downloading an action archive — **429 / 502 / 503** |
| `POLICY_REFUSED` | job has **0 steps**, ~2s, no token minted — environment protection refused the branch |
| `EXECUTION_TIMEOUT` | job hit its `timeout-minutes` bound; record the **last completed phase** |
| `INFRASTRUCTURE_UNKNOWN` | none of the above, and the scanner still never executed |

**All of them are distinguishable only by the annotation — never by the logs.** Check the annotation.

Contrast, and keep these five apart at all costs:

| | Did the control run? | What it means |
|---|---|---|
| `EXECUTION_UNAVAILABLE` | **no** | posture cannot be determined |
| `FAILED` | yes | the control **malfunctioned** |
| `FINDINGS` | yes | the control **worked and found something** |
| `PARTIAL` | partly | a prerequisite was missing; the claim is **not established** |
| `PASS` | yes | the control worked and found nothing |

Collapsing these into one red is how a dashboard becomes an attractive lie. Three separate causes
already presented identically here in a single week, and a fourth — a three-hour hang — presented as
"still running."

> **An unrecognised state fails.** An unknown must never resolve to clean.

### `UNKNOWN`
Not yet established. **Never assume clean.** An unknown that resolves toward "probably fine" is the
failure mode this entire kit exists to prevent.

## Adoption sequencing

> **Detection immediately. Enforcement deliberately.**

Run `advisory_mode: true` on a repository that has never been scanned this way. Every scanner runs,
every finding is reported and persisted, and non-secret findings do not block. Learn the inherited
baseline, classify it,
*then* enforce.

This is not softened security. Nothing is disabled, scoped away, or hidden. Dropping a hard gate onto
an unknown backlog freezes development and gets the control bypassed wholesale, which costs far more
coverage than the gate was ever going to buy.

**Advisory mode is a baseline tool, not a resting state.** It announces itself loudly on every
enforcement point and in the gate summary, because a silent permanent advisory mode is
indistinguishable from having no gate at all.

## Corroboration is not duplication

When two independent scanners flag the same artifact, that is **higher confidence**, not a duplicate
to delete. The first external run showed it immediately: OSV reported 14 findings and Trivy 7 in the
*same* `frontend/package-lock.json`.

Findings management must **preserve source observations** and record agreement as a confidence
signal, never collapse them. Destructive deduplication throws away the strongest evidence you have —
that two detectors, with different rules and different data, arrived at the same place.

Disagreement matters equally: when detectors conflict, that surfaces for a human rather than
averaging away.

> Carried forward from the reference estate `ADR-013`. And its own warning applies: **confidence without calibration
> or action thresholds is theater.** A confidence score must change what happens — gate, escalate,
> or defer — or it is decoration wearing a number.

## The rule that protects all of this

**Never modify scanner configuration merely to make a real consumer run green.**

Building scanners that finally tell the truth and then sanding off the edges because the truth is red
would waste the entire exercise — and leave behind something worse than no scanner, because it would
be trusted.

## Secrets are outside advisory mode — intent, and the current gap

**Decided policy:** a leaked credential is live exposure, not inherited technical debt. The fix is
unambiguous and immediate — rotate it. **Secret findings block from day one, and `advisory_mode`
must never suppress them.** Everything else crawls while a team works down its baseline; secrets run
at full enforcement immediately.

> ⚠️ **The code does not do this yet.** `advisory_mode` was built as a blanket switch: when it is
> true the gate exits zero for **every** failing scanner, secrets included. That directly contradicts
> the policy above and is a known defect scheduled on the policy branch.
>
> **Until it is fixed, do not use `advisory_mode` on a repository where an unrotated leaked
> credential would matter.** This note exists rather than a confident sentence about secrets always
> blocking, because a document that describes intended behaviour as though it were current behaviour
> is the same defect class as a green job that never ran a scanner.

The companion the fix needs: a **governed disposition path** for legacy repositories. Hard-blocking
secrets on day one against an inherited estate can wall a team behind a false-positive population
they did not create. One real consumer produced several hundred secret findings, the large majority
of them high-entropy strings inside cached tool-output payloads — noise generated by a previous
system, not credentials anyone leaked. Without a way to accept known false
positives *by name, with a reason and an expiry*, the predictable outcome is someone disabling the
scanner entirely, which is strictly worse than an advisory mode.
