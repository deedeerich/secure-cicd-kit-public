# 03 · Vocabulary and the verdict contract

Every state the kit emits is a registered term in `assurance-taxonomy.yaml`. A word the code branches
on that is not registered fails `scripts/reconcile_taxonomy.py`. Integrate against these words; do not
invent synonyms (`risk-accepted` is not `ACCEPTED_RISK`, and a near-miss reads as blank).

## Per-scanner state (`scanner_state`, in the gate's `scanner_states` JSON)

| value | means |
|---|---|
| `PASS` | ran, established, no blocking findings |
| `FINDINGS` | ran, established, findings exist (blocked, or softened and still recorded) |
| `PARTIAL` | ran, but established only part of its scope |
| `NOT_APPLICABLE` | established not to apply (discovery found nothing for it), with evidence |
| `UNAVAILABLE` | could not run or could not be acquired — NOT clean |
| `COLLECTION_FAILED` | ran, but its evidence is absent or unparseable — NOT zero findings |
| `FAILED` | the job failed for a reason that is not findings |

`skipped` because a dependency failed is never `NOT_APPLICABLE`; that is the toolchain question below.

## Run-level outputs of the flagship (`workflow_call` outputs)

| output | values | read it as |
|---|---|---|
| `assurance_state` | `PASS` · `FINDINGS` · `PARTIAL` · `UNDETERMINED` | what was established. `UNDETERMINED` = discovery failed, so what should have run is unknown |
| `enforcement_state` | `BLOCKED` · `ADVISORY` · `ALLOWED` | what the gate did |
| `gate_decision` | `FAIL` · `ADVISORY` · `PASS` | legacy summary of the above |
| `secret_gate` | `FAIL` · `PASS` | whether a secret was found anywhere (source, history, image) |
| `undetermined` | `true` · `false` | "did not block" must not be read as "safe" while true |
| `scanner_states` | JSON object | per-scanner state |
| `established` / `unestablished` | names with states | what was and was not established, never merged |
| `discovery_state` | `COMPLETE` · `DISCOVERY_PARTIAL` · `DISCOVERY_UNAVAILABLE` | whether applicability could be established at all |
| `evidence_artifact` | `security-report-<attempt>` | the artifact the report actually uploaded; it holds the per-scanner state files, the redacted SARIF they name, and `findings.json` |
| **`routing_result`** | five values below | **the verdict. Deploy reads this.** |
| `advisory_causes` | comma list of `VERSION_GAP` · `VERSION_GAP_UNVERIFIED` · `COVERAGE_PARTIAL` · `WEAKENING_ATTRIBUTED` · `FINDINGS_NOT_BLOCKED` | set only when `routing_result` is `PROCEED_WITH_ADVISORY`: WHY it is advisory. Pass it to the deploy beside `routing_result` (KDEC-014) |
| `controls_required`, `controls_executed`, `controls_unavailable`, `controls_reduced`, `controls_skipped` | comma lists | the control posture |
| `weakenings` | JSON array | every input that governs a control, with class, baseline, value, state |
| `weakening_attribution` | `WEAKENING_AT_BASELINE` · `WEAKENING_ATTRIBUTED` · `WEAKENING_UNATTRIBUTED` · `WEAKENING_EXCEPTION_EXPIRED` | whether a person stands behind a weakening |
| `weakening_record` | JSON object | reason, authority, exception reference, expiry |
| `policy_resolution`, `policy_source`, `policy_chain` | `POLICY_RESOLVED` or a refusal by name · `KIT_DEFAULT` / `REGISTER` · entry ids | the policy the verdict was reached under (lane L-A; `docs/adoption/POLICY_REGISTER.md`) |
| `rung_declared`, `rung_effective`, `policy_mode` | `crawl` · `walk` · `run`; `adoption` · `strict` (derived) | the rung the gate obeyed; no input can set either |
| `effective_minimum`, `policy_divergences` | JSON | each control's weakest permitted route, and where it differs from the rung's floor |
| `environment_tier`, `team_pattern`, `unvalidated_human_workflow_paths` | tier · pattern · comma list | where the run was evaluated and which human controls the team cannot demonstrate |
| `assurance_result`, `run_record` | compact JSON · `valid` / `invalid` | the run record, valid against `schemas/assurance-result.schema.json` (L36); empty when it did not validate |
| `deploy_approval` | JSON per tier | what a uat/prod deploy verifies on its GitHub environment — pass it to the deploy |

## The verdict: `routing_result` (VERIFIED: `tests/prove_gate_routing.py`, 21 scenarios at `078ef90`)

Five values, with a fixed precedence — the most severe applicable value wins:

```
BLOCKED  >  EVIDENCE_UNTRUSTED  >  DECISION_REQUIRED  >  PROCEED_WITH_ADVISORY  >  PROCEED
```

| value | when | deploy |
|---|---|---|
| `BLOCKED` | an **observed refusal**: a secret anywhere, or established findings the gate enforced | refuse |
| `EVIDENCE_UNTRUSTED` | evidence is missing: assurance `PARTIAL` (other than a version gap) or `UNDETERMINED`, the gate emitted nothing, or a block caused by a toolchain/report/discovery failure rather than findings | refuse |
| `DECISION_REQUIRED` | a control is weakened and nobody is recorded as deciding it (`WEAKENING_UNATTRIBUTED`), or the recorded decision has expired | refuse |
| `PROCEED_WITH_ADVISORY` | a weakening is in force and attributed, findings were recorded under advisory/softened enforcement, or a scanner was capped `PARTIAL` because no carried scanner can read the target's version (KDEC-010). `advisory_causes` says which | proceed (at uat/prod, subject to KDEC-014), and surface the advisory |
| `PROCEED` | clean run, every control at baseline | proceed |

**Why BLOCKED is reserved for observed refusals.** A block because evidence is missing and a block
because something was found need different human responses — fix the pipeline vs fix the code. Both
stop deployment; the value tells the person which problem they have.

**The shipped defaults are the baseline (KDEC-008, OD-7).** `soft_fail_sast: false` and `language:
auto`, so a caller who changes nothing gets `PROCEED` on a clean run. Softening either one makes it a
weakening: attribute it (`weakening_reason` + `weakening_authority`, ideally `weakening_expires`) for
`PROCEED_WITH_ADVISORY`, or it routes `DECISION_REQUIRED`.

**The policy decides which findings block (lane L-A, owner requirement 2026-10-22; VERIFIED locally:
`tests/prove_gate_policy_enforcement.py`, 19 scenarios).** Before it reads any result the gate
resolves the policy register (part 05). With nothing registered the run is at the kit default,
**crawl: only secrets block** — a non-secret finding routes `PROCEED_WITH_ADVISORY` with cause
`FINDINGS_NOT_BLOCKED`, never `PROCEED`. **Owner ruling O-24:** at crawl the gate still blocks when
the kit could not run or trust its own scan (a crash, `COLLECTION_FAILED`, a hollow or unreadable
scan, a bootstrap failure) — `EVIDENCE_UNTRUSTED` at every tier — while a coverage gap stays
advisory (`VERSION_GAP` / `COVERAGE_PARTIAL`). At `walk` findings route `DECISION_REQUIRED`; at `run`, or
where a registered control is `BLOCKED`, they route `BLOCKED`. The policy can only raise the route.
A refused policy is folded in by the same precedence: a defect (conflict, unattributed decision,
supplied `policy_mode`, a narrower scope below the authority's floor — `POLICY_BELOW_AUTHORITY_FLOOR`,
KDEC-018) `BLOCKED`, an unreadable register `EVIDENCE_UNTRUSTED`, an expired decision or a softening
renewed past its cap (`EXCEPTION_RENEWAL_LIMIT`) `DECISION_REQUIRED`. A secret exception renewed past
the cap is refused by the same name and the secret blocks (part 05). The gate job then exits on the verdict: `BLOCKED` and `EVIDENCE_UNTRUSTED`
fail it at every tier; the rest pass the gate and the deploy refuses `DECISION_REQUIRED`. With no policy step at all the gate is strict, never crawl.

**The gate is the single enforcement point (lane L-S, owner ruling O-24; VERIFIED locally:
`tests/prove_gate_policy_enforcement.py`, `sep_*` scenarios, which run each scanner job's shipped
enforce steps and then the gate).** "Deploy reads the verdict, not the job result" now holds for the
whole run: a scanner job never fails because it found something. It hands its findings to the gate
as `findings_state=FINDINGS` and fails only when it could not scan or could not trust its own result.
So the security workflow concludes as its verdict, and a caller's `needs:` chain behaves:

| situation | scanner job | gate job | `routing_result` |
|---|---|---|---|
| crawl, ordinary finding | success | success | `PROCEED_WITH_ADVISORY` (`FINDINGS_NOT_BLOCKED`) |
| `run` (or a control registered `BLOCKED`), same finding | success | **failure** | `BLOCKED` |
| a secret, any rung | success (handed over) | **failure** | `BLOCKED` |
| a secret excepted by the register (one finding, ticket, approver, expiry) | success | success | `PROCEED_WITH_ADVISORY` (`SECRET_EXCEPTION_ATTRIBUTED`); `secret_gate` `EXCEPTED`, never `PASS` |
| crash / `COLLECTION_FAILED` / hollow scan, any rung | **failure** | **failure** | `EVIDENCE_UNTRUSTED` |
| a non-secret job failed beside findings on record | **failure** | **failure** | `EVIDENCE_UNTRUSTED` (it could not finish) |

`advisory_mode` and `soft_fail_sast` still soften what a job hands over and are recorded as
weakenings (part 05); they are no longer what keeps a scanner job green, and neither one softens a
scan that did not happen (Checkov's `COLLECTION_FAILED` under `advisory_mode` used to pass — VERIFIED
at `7515088`, fixed by lane L-S).

## The deploy-side contract (SINGLE_PIPELINE_TARGET §5.2; BUILT in both deploy reusables — part 07)

```
deploy proceeds   only if routing_result ∈ {PROCEED, PROCEED_WITH_ADVISORY}
deploy refuses    on BLOCKED, EVIDENCE_UNTRUSTED, DECISION_REQUIRED, empty, or any unrecognised value
                  -- before it logs in to anything, naming the value it refused
at uat and prod   PROCEED_WITH_ADVISORY whose advisory_causes include VERSION_GAP is refused unless the
                  weakening record names an accepter, a reason and an unexpired date (KDEC-014);
                  VERSION_GAP_UNVERIFIED proceeds, recorded; an advisory with no or an unregistered
                  cause is refused
deploy rules      exactly ONE version_gap_ruling on every path its verdict step reaches, refused or
                  not (KDEC-014, 078ef90): VERSION_GAP_NOT_ENGAGED · VERSION_GAP_RECORDED ·
                  VERSION_GAP_UNVERIFIED_RECORDED · VERSION_GAP_EXCEPTION_ACCEPTED ·
                  VERSION_GAP_REFUSED · ADVISORY_CAUSE_UNKNOWN
an EMPTY ruling   is never "not engaged": it means the verdict step never ran or never finished, so
                  the deploy's own posture routes EVIDENCE_UNTRUSTED (a BLOCKED it already reached
                  stands) and its summary reads "not reported"
deploy records    controls_unavailable, the causes and the ruling in its outcome report
at uat and prod   before the verdict and login, the deploy reads its GitHub environment's protection
                  rules back and refuses unless required reviewers exist, self-review is prevented,
                  and (when the policy names approver groups) every reviewer is one of them;
                  unreadable is refused too (environment_protection; lane L-A, owner 2026-10-22)
```

`VERSION_GAP_NOT_ENGAGED` is written when no version-gap rule applied: the verdict was `PROCEED`, a
refusal on another verdict, or an advisory with no version-gap cause to rule on at that tier. It routes
nothing by itself; it exists so that silence can never be read as "not engaged".

Proven: the refusal before login is observed live (run 38853176286, a typed `BLOCKED`); the
KDEC-014 rule, including one ruling on every path and the empty-ruling route, is proven against a
stub cloud only (`tests/prove_version_gap_production.py`, VERIFIED at `078ef90`). No live run has yet
carried a real gate verdict into a deploy in one pipeline: every live deploy received a typed verdict.

## Words for "nothing", kept apart

| situation | state |
|---|---|
| looked, found nothing | `PASS` with a positive denominator (files or commits scanned) |
| established it does not apply | `NOT_APPLICABLE` (with discovery evidence) |
| present, but no kit scanner can read it | `COVERAGE_GAP` |
| looked, but the report is missing/unparseable/the scope was empty | `COLLECTION_FAILED` |
| the tool could not be acquired or run | `UNAVAILABLE` |
| a caller turned the control off or softened it | a weakening in the posture record (part 05) |
| a request exists for an exception | still nothing changes; only a merged disposition does (part 06) |
