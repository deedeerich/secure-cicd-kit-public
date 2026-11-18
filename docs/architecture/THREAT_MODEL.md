# Threat model — the core kit

**What an adversary does to a pipeline whose job is to catch adversaries. Each threat names its
entry point, its consequence, the control, whether that control exists, the test that would prove
it, and what is left over.**

```
Phase:              1
Truth State:        control states VERIFIED 2026-10-06; RE-READ 2026-11-07 against the trunk (c1420ea)
                    and corrected where the code moved (each correction says so). Residual risk is
                    judgement. The full STRIDE model per element and per boundary is now
                    09_THREAT_MODEL.md and 09b_THREATS_BY_BOUNDARY.md; this file keeps T-01..T-16.
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
· `EXERCISED` · `PROVEN` · `ENFORCED`. When this file was written (2026-10-06) no control here had
refused a real prohibited operation. Since then the stage register records one stage at `ENFORCED`:
deployment and verification (stage 15, `tests/check_stage_phase.py`), with live refusals -- a deploy
on a BLOCKED verdict refused before login (run 38853176286), an irreversible prod deploy refused
(38853184615), a second actor's change not overwritten (38886279650). Every other control here is
still below `ENFORCED`.

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
*State:* `BUILT` — `workflow-policy-check.yml` exists and `tests/lint_injection.py` passes. *Re-read
2026-11-07:* rule R4 (a `pull_request_target` head checkout) refuses its seeded violation
(`tests/prove_workflow_policy_rules.py`), and the Dependabot triage reads a PR as data with nothing
checked out (`tests/prove_dependabot_triage.py`).
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
*State:* `BUILT`; *re-read 2026-11-07:* the fix is published, `DEPENDENCY_ACQUISITION_UNAVAILABLE` is
emitted by the scanner composites and the gate, and a scanner that read nothing is never zero
(`tests/prove_hollow_scan.py`). Tool pinning is `PROVEN`.
*Test:* the existing consumer-path probe, run against the commit holding the fix.
*Residual:* **the highest-value open item in the kit.** Until that run exists, every coverage claim
rests on scanners that may or may not have acquired.

**T-05 · A scanner runs but cannot parse what it was given**
*Entry:* a language, framework, lockfile format or provider schema outside the pinned tool's range.
*Consequence:* zero findings, reported as `CLEAN` rather than as a coverage gap. A pipeline scanning
last year's technology and passing today's code.
*Control:* a pre-scan capability check — version discovered, tool range declared per tool,
`VERSION_UNSUPPORTED` declared **before** the scan so a zero never has to be interpreted afterwards.
*State:* `BUILT` (re-read 2026-11-07; it was `DESIGNED` here) — the resolve composite discovers
versions and declares `VERSION_UNSUPPORTED` / `VERSION_GAP` per tool before the scan, and a job
pointed at a gap has its PASS capped at PARTIAL (KDEC-010, KDEC-014; `tests/test_resolve.py`,
`tests/prove_capability_selection.py`, `tests/prove_version_gap_production.py`).
*Residual:* only as good as each tool's declared range; a range not yet proven by a seeded corpus is
recorded UNVERIFIED and does not refuse at uat/prod.

**T-06 · Rule-set or advisory drift**
*Entry:* a pinned scanner ages; new rule classes and advisories never arrive.
*Consequence:* silent decay. Coverage shrinks while every run stays green, and it gets *more* likely
the longer the kit is stable, because stability is what keeps pins unexamined.
*Control:* currency review on a schedule, against authoritative sources.
*State:* `ABSENT` for tool binaries and rule sets pinned inside steps; *re-read 2026-11-07:* pinned
actions are kept current by Dependabot and its triage (`templates/dependabot-triage.yml`,
`tests/prove_dependabot_bump_mergeable.py`).
*Residual:* unmitigated for in-step tools, and invisible without a review cadence.

### B4 · Artifact identity

**T-07 · Artifact substitution between scan and deploy**
*Entry:* a second build between scanning and pushing, or a mutable tag resolved twice.
*Consequence:* the bytes scanned are not the bytes deployed. The SBOM and scan describe something
that was never shipped.
*Control:* build once, scan those bytes, push those bytes, deploy by digest. Chain specified in
`PROVENANCE_AND_ATTESTATION.md` §3.
*State:* `BUILT` (re-read 2026-11-07; it was `DESIGNED` here) — the build pushes the scanned bytes and
asserts the registry holds them (`REGISTRY_IDENTITY_PROVEN`), the composite builds once, and the deploy
refuses anything but a digest (`tests/check_artifact_identity.py`, `tests/prove_composite_build_once.py`,
`tests/prove_build_push_round_trip.py`); promotion moves the same digest (KDEC-029).
*Test:* a release in which the scanned digest and the deployed digest are compared and a mismatch
fails the gate.
*Residual:* until that comparison exists, "we scanned it" and "we deployed it" are two claims about
possibly different objects.

**T-08 · Provenance asserted rather than verified**
*Entry:* a run stamping metadata about itself.
*Consequence:* a signature nobody checks is decoration. `PROVENANCE_AND_ATTESTATION.md` §1 is
explicit that stamped, attested and verified are three different claims.
*Control:* attestation produced *and* verified at the consuming end.
*State:* `BUILT` (re-read 2026-11-07) — the attest job signs only a proven digest, and V1 verifies it
before login in the template's verdict job and inside every deploy (`tests/prove_attest_job_isolated.py`,
`tests/prove_attestation_verify.py`, `tests/prove_deploy_attestation.py`). On a private repository whose
plan offers no attestations V1 is `IMPLEMENTATION_HELD`.
*Residual:* where V1 is held, provenance supports an audit story, not an enforcement one.

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
*State:* `BUILT` (re-read 2026-11-07) — the policy register, the baseline ledger and the ticket ledger
are read from the protected default branch, never the PR tree, and the ledger changes only through a
pull request (`tests/prove_gate_reads_rung.py`, `tests/prove_ledger_read_authority.py`,
`tests/prove_propose_ledger_job_scope.py`).
*Residual:* artifacts carry no signature of their own; a reader trusts GitHub's artifact store.

### B7 · Deployment target

**T-13 · Shared-resource mutation beyond the release's ownership**
*Entry:* a deployment writing a resource another release or another consumer also owns.
*Consequence:* one release silently reconfigures another's dependency.
*Control:* field-level change manifest; only this run's owned, separable change is written.
*State:* `BUILT` (re-read 2026-11-07) — field ownership at the seam and the ownership stamp are
built (`tests/prove_seam_setting_ownership.py`, `tests/prove_deploy_ownership_stamp.py`), and a second
actor's change was not overwritten in a live run (38886279650).
*Residual:* the seam and the cross-repository lease are opt-in until KDEC-030 is ruled on.

**T-14 · Unsafe rollback**
*Entry:* a failed release triggering reversal against state that moved after the snapshot.
*Consequence:* reversing out from under a later change or a new dependent — a recovery action that
causes the larger outage.
*Control:* preconditions evaluated against **live** state before any removal; ownership, concurrent
modification, later-introduced dependents, reverse-ancestry order; explicit
`ROLLBACK_REQUIRES_HUMAN_DECISION` and `ROLLBACK_PROHIBITED` outcomes.
*State:* `ENFORCED` for a run's own failed change (stage 15: seeded unhealthy digests reversed and
verified live, runs 38878189985 and 38855747496); `BUILT` for a sequence of several releases
(`tests/prove_rollback_sequence.py`, `tests/prove_rollback_dependencies.py`).
*Residual:* a sequential rollback has not been exercised live. **A rollback command exiting zero is not
evidence of restored service**; the kit reads the target back after every reversal.

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
*State:* `BUILT` (re-read 2026-11-07; it was `BUILT, and wrongly` here) — the durable identity and the
rule-family alias table keep a finding's identity across a scanner upgrade
(`tests/prove_identity_durability.py`, `tests/prove_rule_family_upgrade.py`, KDEC-038).
*Residual:* a rule the alias table does not know yet is a new identity until a person maps it.

---

## 3 · What this adds up to

Re-counted 2026-11-07 against the trunk (c1420ea). The 2026-10-06 count was PROVEN 1, BUILT 7 (one
wrongly), DESIGNED 6, ABSENT 1, ENFORCED 0.

| state | threats |
|---|---|
| `ENFORCED` | 1 (T-14, for a run's own failed change) |
| `PROVEN` | 1 (T-15) |
| `BUILT` | 13 |
| `DESIGNED` | 0 |
| `ABSENT` | 1 (T-06, for tools and rule sets pinned inside steps) |

T-16's wrong control is fixed. The named tests still owed are the fork-PR fixture (T-01), an attempted
write outside a job's permission (T-03), the seeded identity-scope run (T-09) and a live sequential
rollback (T-14).

---

## 4 · The two threats to fix first

Re-read 2026-11-07: the two named here on 2026-10-06 (T-04, T-16) are both built. The two now first:
**T-06**, because in-step tool and rule-set drift is the one class still `ABSENT`; and **T-01**,
because the privileged path has never met a real fork PR.

---

## 5 · The next enforcement test

**T-03** is still the cheapest honest candidate: a job attempting a write outside its declared
permission, and the refusal recorded. It needs no deployment target, no consumer and no production
resource. The full list of suggested mitigations is in `09b_THREATS_BY_BOUNDARY.md`.

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
