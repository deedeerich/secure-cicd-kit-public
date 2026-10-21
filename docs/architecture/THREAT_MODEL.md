# Threat model — the core kit

**What an adversary does to a pipeline whose job is to catch adversaries. Each threat names its
entry point, its consequence, the control, whether that control exists, the test that would prove
it, and what is left over.**

```
Phase:              1
Truth State:        control states VERIFIED 2026-10-06 against the tree; residual risk is judgement
Audience:           anyone changing the kit, and anyone signing off on a release that uses it
Decision Supported: whether a change needs a threat review before it ships
Deferred Depth:     consumer-specific flows and assets — those belong in an overlay, see §6
```

---

## 0 · What this is, and the one thing it must not become

This is the **core kit's** threat model: the pipeline itself as the asset and the attack surface.
Consumer architecture — a particular deployment shape, a particular data classification, a
particular connectivity path — belongs in an **overlay** (§6), never here. An overlay adds context
and tests; it never changes a rule in this file, and it never brings an organization's name into
the neutral core.

**Having this file is not a control.** A threat model that is written once and never revisited is
another appearance-of-control, exactly like a pipeline file that proves a security step *appears*.
§7 says what change obliges a review, and `tests/check_stage_phase.py` is where that becomes a gate
rather than an intention.

**Control states use the stage ladder**, and nothing is inherited: `ABSENT` · `DESIGNED` · `BUILT`
· `EXERCISED` · `PROVEN` · `ENFORCED`. Across this entire file, **nothing is ENFORCED** — no
control here has yet refused a real prohibited operation. That is the honest headline and it is the
same zero the stage gate reports.

---

## 1 · Trust boundaries

| | boundary | what crosses it |
|---|---|---|
| **B1** | caller repository → kit | source, config, workflow inputs, PR content from forks |
| **B2** | kit → runner | the runner is ephemeral but not isolated from the token it holds |
| **B3** | kit → scanner supply chain | container images, actions, rule sets, advisory data |
| **B4** | build → scan → registry → deploy | the artifact's identity must survive every hop |
| **B5** | kit → cloud | federated identity, scoped to an environment or not |
| **B6** | run → evidence | SARIF, artifacts, summaries, publication surfaces |
| **B7** | kit → deployment target | shared resources with other owners and other releases |
| **B8** | findings → approval | dispositions, exemptions, reviewers |

---

## 2 · The threats

### B1 · Caller repository

**T-01 · Untrusted pull request executes with repository privilege**
*Entry:* a fork PR against a workflow triggered by `pull_request_target` or an equivalent that
checks out PR head while holding the base repo's token.
*Consequence:* arbitrary code with read access to secrets and write access to the Security tab.
*Control:* triggers restricted so PR content is never executed with privileged context.
*State:* `BUILT` — `workflow-policy-check.yml` exists and `tests/lint_injection.py` passes.
*Test:* a fixture PR from a fork proving the privileged path does not execute its content.
*Residual:* the test has never run. `BUILT` is not `PROVEN`, and this is the threat where that
difference is most expensive.

**T-02 · Input injection into a shell step**
*Entry:* a branch, title, or caller-supplied input interpolated into `run:`.
*Consequence:* command execution on the runner with the job's token.
*Control:* inputs via environment, never interpolation; enforced statically.
*State:* `BUILT` — `tests/lint_injection.py`, `tests/check_shell_continuations.py` pass.
*Residual:* static analysis of shell text. A novel construction it does not model would pass.

### B2 · Runner

**T-03 · Token scope exceeds the job's need**
*Entry:* workflow-level `permissions` inherited by every job.
*Consequence:* a discovery job holding `security-events: write` widens blast radius for any step
that is compromised.
*Control:* least privilege declared per job rather than inherited.
*State:* `BUILT` — the `discover` job declares its own block for exactly this reason.
*Test:* a job attempting a write outside its declared permission and being refused.
*Residual:* **this is a candidate for the first real enforcement test.** Nothing has attempted it.

### B3 · Scanner supply chain

**T-04 · A scanner silently acquires nothing and the job reports success**
*Entry:* a pinned image tag, action version, or package that cannot be fetched.
*Consequence:* **a coverage gap presenting as a clean result.** Observed on `main` on 2026-09-30:
a Go scanner pinned to a container tag that has never existed, producing no findings, with the job
green and another scanner's rules covering the seeded signal.
*Control:* acquisition failure is a named state (`DEPENDENCY_ACQUISITION_UNAVAILABLE`), and seeded
signals are **tool-pinned** so one scanner cannot satisfy another's assertion.
*State:* `BUILT`, fix unpublished. Tool pinning is `PROVEN`.
*Test:* the existing consumer-path probe, run against the commit holding the fix.
*Residual:* **the highest-value open item in the kit.** Until that run exists, every coverage claim
rests on scanners that may or may not have acquired.

**T-05 · A scanner runs but cannot parse what it was given**
*Entry:* a language, framework, lockfile format or provider schema outside the pinned tool's range.
*Consequence:* zero findings, reported as `CLEAN` rather than as a coverage gap. A pipeline scanning
last year's technology and passing today's code.
*Control:* a pre-scan capability check — version discovered, tool range declared per tool,
`VERSION_UNSUPPORTED` declared **before** the scan so a zero never has to be interpreted afterwards.
*State:* `DESIGNED` — specified in `PIPELINE_ORDERING_AND_SCAN_VALIDITY.md` §2, demonstrated
experimentally in §3, implemented nowhere.
*Residual:* unmitigated. This is T-04 generalised and it is wider.

**T-06 · Rule-set or advisory drift**
*Entry:* a pinned scanner ages; new rule classes and advisories never arrive.
*Consequence:* silent decay. Coverage shrinks while every run stays green, and it gets *more* likely
the longer the kit is stable, because stability is what keeps pins unexamined.
*Control:* currency review on a schedule, against authoritative sources.
*State:* `ABSENT`.
*Residual:* unmitigated, and invisible without a review cadence.

### B4 · Artifact identity

**T-07 · Artifact substitution between scan and deploy**
*Entry:* a second build between scanning and pushing, or a mutable tag resolved twice.
*Consequence:* the bytes scanned are not the bytes deployed. The SBOM and scan describe something
that was never shipped.
*Control:* build once, scan those bytes, push those bytes, deploy by digest. Chain specified in
`PROVENANCE_AND_ATTESTATION.md` §3.
*State:* `DESIGNED`. **A double build on the published build path is reported and not yet verified
against the local tree** — recorded as an open assumption, not a finding.
*Test:* a release in which the scanned digest and the deployed digest are compared and a mismatch
fails the gate.
*Residual:* until that comparison exists, "we scanned it" and "we deployed it" are two claims about
possibly different objects.

**T-08 · Provenance asserted rather than verified**
*Entry:* a run stamping metadata about itself.
*Consequence:* a signature nobody checks is decoration. `PROVENANCE_AND_ATTESTATION.md` §1 is
explicit that stamped, attested and verified are three different claims.
*Control:* attestation produced *and* verified at the consuming end.
*State:* `DESIGNED`; the stamp degrades on the shipped path.
*Residual:* provenance currently supports an audit story, not an enforcement one.

### B5 · Cloud identity

**T-09 · Federated identity usable from outside its intended scope**
*Entry:* a federated credential whose subject claim is wider than intended — a wildcard, a branch
pattern, or `pull_request` where an environment was meant.
*Consequence:* any workflow matching the subject assumes the identity. A standing path to the cloud
that appears in no RBAC export.
*Control:* subject pinned to environment or protected ref; authorization boundary isolation probe.
*State:* `BUILT`, deferral expiring 2026-10-31.
*Test:* a dispatched run where one scope returns `REFUSED` and a run seeded with a scope the
identity *can* reach **fails** — an assertion that has never failed is decoration.
*Residual:* the test is specified and has not run.

### B6 · Evidence path

**T-10 · Publication failure rewriting the detection verdict**
*Entry:* the Security tab, artifact upload, or summary surface unavailable.
*Consequence:* a failed publication read as a failed or passed scan.
*Control:* `PUBLICATION=DEGRADED` is a distinct state; findings persist as artifacts regardless.
*State:* `BUILT`.
*Residual:* low. This one is genuinely well handled.

**T-11 · Sensitive content leaving in the evidence**
*Entry:* SARIF, logs or receipts carrying matched secret values, response bodies, or customer data.
*Consequence:* the artifact meant to prove security becomes the disclosure.
*Control:* redaction before any publication, ordering guaranteed; tools report pattern **class and
location**, never the matched value.
*State:* `BUILT` — `tests/check_redaction_parity.py` and `tests/prove_redaction_chain.py` pass.
*Residual:* **this class recurs.** It was reintroduced twice in one week in adjacent tooling, both
times by a fallback that reached for stdout when an error string was empty. Redaction holds; the
discipline around *new* writers does not hold itself.

**T-12 · Telemetry or evidence tampering**
*Entry:* a writable artifact path, or a disposition file read from an unprotected ref.
*Consequence:* findings suppressed by editing the evidence rather than fixing the code.
*Control:* dispositions consumed **only** from the protected branch; artifact digests recorded.
*State:* `DESIGNED` — the protected-branch rule is specified and not enforced at runtime.
*Residual:* a disposition file supplied by a caller is currently trusted.

### B7 · Deployment target

**T-13 · Shared-resource mutation beyond the release's ownership**
*Entry:* a deployment writing a resource another release or another consumer also owns.
*Consequence:* one release silently reconfigures another's dependency.
*Control:* field-level change manifest; only this run's owned, separable change is written.
*State:* `DESIGNED` — `ROLLBACK_CONTRACT.md`.
*Residual:* no deployment has executed, so ownership stamping is untested.

**T-14 · Unsafe rollback**
*Entry:* a failed release triggering reversal against state that moved after the snapshot.
*Consequence:* reversing out from under a later change or a new dependent — a recovery action that
causes the larger outage.
*Control:* preconditions evaluated against **live** state before any removal; ownership, concurrent
modification, later-introduced dependents, reverse-ancestry order; explicit
`ROLLBACK_REQUIRES_HUMAN_DECISION` and `ROLLBACK_PROHIBITED` outcomes.
*State:* `DESIGNED`, and the design is strong.
*Residual:* unexercised. **A rollback command exiting zero is not evidence of restored service**,
and nothing has yet proved the kit knows that in practice.

### B8 · Approval

**T-15 · Approval bypass through the gate's own vocabulary**
*Entry:* a skipped, cancelled or unavailable job projecting to a non-blocking state.
*Consequence:* `NOT_APPLICABLE` over code nobody scanned. A green gate over an empty run.
*Control:* the gate reads `kit-scripts` explicitly rather than inferring it; bootstrap failure is
`BLOCKED` and `undetermined`, not applicable.
*State:* `PROVEN` locally — `tests/prove_bootstrap_failure.py` passes, including the control case.
*Residual:* proven against the gate logic, not against GitHub's actual job results.

**T-16 · Disposition inherited by the wrong finding**
*Entry:* an approval keyed to an identity that changes when a scanner is upgraded.
*Consequence:* an approval granted for one thing silently suppressing another.
*Control:* durable finding identity excluding scanner name and rule id; inheritance requires a
matched identity and a rationale.
*State:* `BUILT, and wrongly` — the current fingerprint contains two components it forbids, so a
scanner upgrade resets every finding's history.
*Residual:* **active defect.** Dispositions do not survive a scanner upgrade today.

---

## 3 · What this adds up to

| state | threats |
|---|---|
| `PROVEN` | 1 |
| `BUILT` | 7 (one of them wrongly) |
| `DESIGNED` | 6 |
| `ABSENT` | 1 |
| **`ENFORCED`** | **0** |

Six threats have a named test that has never been run. One (T-16) has a control that is built and
incorrect, which is worse than absent because it reads as present.

---

## 4 · The two threats to fix first

**T-04**, because it is the only one observed happening, the fix is written, and the test exists.
**T-16**, because a wrong control is more dangerous than a missing one and it silently weakens every
disposition already granted.

---

## 5 · The first enforcement test

Nothing here is `ENFORCED`. **T-03** is the cheapest honest candidate: a job attempting a write
outside its declared permission, and the refusal recorded. It needs no deployment target, no
consumer, and no production resource — and it would be the first `Enforced` state this programme has
ever produced.

---

## 6 · Overlays

An overlay covers what the core cannot know: a specific deployment shape and its slots or revisions,
shared landing-zone resources and who else owns them, hybrid connectivity, regulated data
classification, and the tests those imply.

**Rules.** An overlay adds threats, assets, flows and tests. It **never** relaxes a core rule, and it
**never** introduces an organization, client or product name into the neutral core — overlay content
stays in `overlays/`, which is excluded from export. A core threat an overlay cannot satisfy is
recorded as residual risk in the overlay, not as a weakened control here.

## 7 · When a review is obliged

Not "annually". A threat review is required when any of these changes:

- the architecture or deployment shape of a consumer
- an exposed endpoint, or the reachability of an existing one
- an identity, its scope, or its federation subject
- the dependency graph, or a scanner's acquisition path or declared capability
- the deployment target, or the recovery design
- a trust boundary in §1 moving, appearing, or disappearing

The obligation is only real if something checks it. That belongs in the stage gate, which already
refuses a stage claiming more maturity than its evidence carries.
