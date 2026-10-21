# 01 · Purpose and principles

## Why the kit exists

Security pipelines fail quietly far more often than they fail loudly. The common shapes, each of
which this kit has itself shipped at least once and then fixed:

- a job that installs a scanner, never runs it, and publishes a report nothing wrote — green on every run;
- a scanner whose exit code means "found something", silenced with `|| true`, so a crash reads as clean;
- a report that is missing or unparseable, counted as zero findings;
- a softened control (`soft_fail`, advisory mode, a narrowed path) that leaves no trace, so a weakened
  run is reported identically to an honest pass;
- a gate that reads job conclusions, so findings in a job told not to fail read as PASS;
- a verdict a deploy step cannot read, so deployment keys on "the workflow was green".

The kit's purpose is to make the result of a security run **mean what it says**: when it reports
clean, something actually looked, at the scope that mattered, with controls at the strength the
organisation chose — and when any of that is not true, the result says which part is not.

## The principles every part obeys

**1. Configured is not effective.** A control that exists in YAML is not a control that ran. Every
claim is backed by evidence the run produced (a report, a count, an observed refusal) or it is not
claimed.

**2. Four states of "nothing", never collapsed.** *Nothing found* (looked, clean), *nothing exists*
(established not applicable, with evidence), *nothing was looked at* (`COLLECTION_FAILED`,
`UNAVAILABLE`), *the control is off* (a recorded weakening). A query that cannot hold the thing
returns empty with no error; that empty is never trusted until the surface is proven able to hold it.

**3. Detection immediately, enforcement deliberately.** Every scanner always runs and always reports.
Modes and rungs change what BLOCKS, never what is SEEN. Advisory mode exists so a team can see an
inherited backlog without being frozen by it; it is reported loudly on every run, because a permanent
advisory mode is indistinguishable from no gate.

**4. Secrets are outside advisory mode.** A leaked credential is live exposure, not debt. It blocks at
every rung and in every mode: source, history, or inside a container image.

**5. Discovered, not declared.** What runs is decided by what discovery finds in the repository, not by
what a caller says the repository is. A caller's selector may only narrow, and narrowing is recorded.

**6. Redaction before every publication.** Scanner output can contain the secret it found. Every SARIF
upload, artifact and ticket is preceded by redaction in the same job. A redactor after the upload
protects nothing while looking exactly like protection.

**7. A weakening is a governed exception, not a boolean preference.** Every input that can soften a
control is enumerated in an emitted record, with who decided, why, where it is recorded, and when it
lapses. Silence never renews an exception.

**8. Partial is not total ignorance.** When one scanner fails, what the others established stays
established, and what became unknown is named. Degradation may reduce a claim's scope or confidence;
it must never increase its authority.

**9. The verdict is data, and deploy reads it.** The gate emits `routing_result` with five values.
Deploy proceeds only on `PROCEED` or `PROCEED_WITH_ADVISORY`.

**10. The authority is never where the automation can write.** Dispositions, approvals and expiries
live on the protected default branch under CODEOWNERS. A pull request cannot exempt the finding it
introduces; a ticketing bot cannot clear a finding by editing a ticket.

**11. Proof, not presence.** A test that passes when both sides are empty proves nothing; a check that
greps for a capability's name finds the word, not the capability. The kit's own tests run the
shipped step against seeded inputs and assert the reason, not merely the exit code (part 08).

**12. Neutral core, consumer overlays.** The core names no organisation, tenant or person and an export
check enforces it. Consumer-specific behaviour lives in overlays that compose the core and never merge
into the neutral core's main branch.

## The three structural remedies the kit keeps reusing

1. **A declared registry, the actual usage, and a check that fails on divergence** — the scanner
   registry vs the workflow's jobs, the validation registry vs the capabilities, the weakening record vs
   the declared inputs, the taxonomy vs the words the code branches on.
2. **Separate detection from enforcement** — the scanner never fails its own job; a separate count step
   produces a number (or `COLLECTION_FAILED`), and a separate enforce step decides.
3. **Dated exceptions** — every deferral, exemption and weakening carries an owner and an expiry; an
   expired one turns red and cannot be renewed by moving the date.

## What the kit deliberately does NOT do

- It does not decide which licences, severities or SLAs an organisation accepts. Those are policy, read
  from configuration, never constants in code.
- It does not auto-merge, auto-dispose or auto-close. A human merges dispositions.
- It does not tear down infrastructure in a deployment path. Full teardown is a test-harness behaviour.
- It does not treat a tool's exit code as a verdict. Exit codes are evidence, interpreted per tool.
