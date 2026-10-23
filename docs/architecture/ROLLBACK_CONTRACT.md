# Rollback contract — blocking requirement for the deploy workflows

```
Status (2026-10-16, trunk 3830edb): IMPLEMENTED in both deploy reusables and PROVEN LIVE on a
sandbox Azure subscription, through live-deploy-acceptance.yml calling them as a consumer does
(tests/reconcile_validation.py, `deploy-containerapp` and `deploy-appservice`, both `observed`):
  verified rollback   Container Apps 38855747496, 38858033863; App Service 38878189985;
                      App Service slot 38912546778 (no swap, production untouched)
  second actor        Container Apps 38855929525 (deferred to the later release, ROLLBACK_PARTIAL);
                      App Service 38886279650 (REVERSAL_REFUSED_CONFLICT, ROLLBACK_PARTIAL)
  refusal / healthy   38853176286 (BLOCKED verdict, no login); 38853184615 (prod, no slot, refused);
                      38855599716, 38857259257, 38857271571, 38912063363 (healthy; slot swapped)
NOT live (stub-proven only, tests/prove_deploy_outcome.py): EMPTY and UNKNOWN previous state,
PARTIAL_APPLY / STATUS_UNTRUSTED (matrix B and D), a capability refusal at a production tier,
provenance tags written, a post-swap production failure. `requires-integration-environment` is
empty: the three surfaces left it on the runs above.
SEQUENTIAL ROLLBACK (2026-10-22, lane L-RB, KDEC-019 item 4): several deployments reversed newest
first with the application's end-to-end tests between steps -- built and proven against the stub
cloud only (tests/prove_rollback_sequence.py); never run live. Section "Sequential rollback" below.
KDEC-021 (2026-10-23, lane L-RB2): a TEST PERIOD after every step, App Service slots restored to the
requested version, deploys frozen per target during a rollback and a kit deploy that lands anyway
rolled back first -- stub-proven (S13..S19), never run live.
```

## The rule

> **Roll back to the last known-good state of only what this run changed.**
> Created something that did not previously exist → remove **only that**.
> Modified something that already existed → **restore its prior state**.
> Then **independently verify live state** before declaring recovery successful.

That is materially different from *"cleanup = delete the resource group."*

**Full teardown is a test-harness behavior, not a deployment behavior.** It is safe only where the
precondition is *proven* — a deliberately empty scope, verified empty before the run. It must never
live inside a reusable production deploy workflow, where "deployment failed, delete prod" would be a
memorable Thursday.

## Three separate artifacts

### 1 · Pre-change snapshot — the mutation surface only

Before mutating, capture what recovery will need. **Not "snapshot the universe"** — only what this
workflow plans to change:

resource IDs · active revision or deployment slot · image digest/version · relevant app settings and
configuration · traffic weights · deployment metadata · anything else in the declared mutation surface.

### 2 · Change manifest — what *this run* did

Record exactly what this run **created**, **updated**, **deleted**, or **redirected**.

This is what scopes rollback to the current run instead of swinging a chainsaw at a resource group.
Without it, rollback cannot distinguish *"I made this"* from *"this was already here."*

### 3 · Validated rollback

On validation failure:

| Condition | Action |
|---|---|
| Created by this run | Remove |
| Pre-existing and modified | Restore captured prior state |
| Traffic redirected | Restore previous routing |
| Prior revision/slot existed | Reactivate or swap back |

Then **query actual live state and compare against the pre-change snapshot.** Only then:

```
ROLLBACK_VERIFIED = TRUE
```

> **A rollback command exiting 0 is not proof of restored service.** Same rung problem as everywhere
> else in this kit — `executed` is not `effective`.

## Do-no-harm rule

> **Never perform destructive rollback when the pre-change state is unknown.**

If the workflow cannot establish whether a resource existed beforehand, it must **not** decide
"guess we delete it." That state is:

```
ROLLBACK_REQUIRES_HUMAN_DECISION
```

An unknown must not resolve toward destruction because destruction is the easier branch to code.
This is typed absence applied where it costs the most.

**This rule is stated about the RUN, and it also holds PER OBJECT.** A run can have a perfectly
established previous state and still meet, inside its own change manifest, an object whose current
ownership or version it cannot read — because something else modified that object between the
deployment and the reversal. *"I created this"* is a true statement about the past and is not
sufficient authority to delete in the present. The per-object precondition model, its disposition
table and the ownership-stamp mechanism are in
`docs/architecture/DEPLOYMENT_CONTRACT_RECONCILIATION.md` §8, with the vocabulary registered in
`assurance-taxonomy.yaml` under `release_ownership`, `reversal_conflict` and
`reversal_disposition`.

## Reversible ≠ safe to reverse

**Two different claims.** A change can be technically reversible and still unsafe to reverse
automatically — and sometimes the old state is the thing that was dangerous.

| Change | Reversible? | Safe to auto-reverse? |
|---|---|---|
| App Service slot swap | strongly | usually yes |
| Container Apps traffic weights | yes | usually yes |
| Terraform resource setting | maybe | depends on drift and dependents |
| Schema migration | often **not** | no |
| Database data mutation | depends entirely | rarely |
| Certificate / key rotation | technically | **old state may already be revoked or invalid** |
| RBAC change | yes | **restoring prior state can reintroduce a compromised privilege** |
| Emergency security mitigation | yes | **rollback reopens the vulnerability that triggered the change** |

Each adapter therefore answers **two** questions, not one:

1. *Can this class of change be automatically rolled back?*
2. *Is automatic rollback safe **under this specific failure mode**?*

### Dispositions

```
AUTO_ROLLBACK_ALLOWED           reversible and safe — proceed, then verify
ROLLBACK_REQUIRES_VALIDATION    reverse, but prove the restored state is correct before declaring success
ROLLBACK_REQUIRES_HUMAN_DECISION  prior state unknown, or reversal has consequences a machine should not weigh
ROLLBACK_PROHIBITED             forward-fix only — reversal is worse than the failure
```

`ROLLBACK_PROHIBITED` exists because "put it back how it was" is not always the safe outcome.
Reverting an emergency mitigation restores a known-exploitable state; reverting an RBAC removal can
hand back access that was deliberately taken away. **In those cases the correct recovery is forward,
and a workflow that silently reverses has made a security decision nobody authorized.**

## Cancellation is a failure mode this contract must survive

A run that is **cancelled** between making a change and verifying it is the worst state this
contract can be in: the mutation happened, the change manifest was never completed, and no rollback
can know what the run owned. Every recovery path is then forced to guess ownership — which is how a
failed deployment becomes an incident.

That makes workflow concurrency a **safety** setting, not a cost setting, and the correct semantics
are **opposite** for the two kinds of workflow:

| Workflow kind | Setting | Why |
|---|---|---|
| Validation / scanners / self-test | `cancel-in-progress: **true**` | The superseded answer is stale. Killing it costs nothing and saves metered minutes. |
| **Deploy · build+push · any mutation** | `cancel-in-progress: **false**`, serialized per target | Cancelling mid-mutation strands a half-applied change with no manifest. Never cancel a run that has already mutated something. |

Concurrency groups for change workflows key on **environment + target resource**, so two runs cannot
mutate the same target simultaneously while unrelated targets still proceed in parallel. GitHub keeps
at most one run *pending* per group and discards older pending ones — safe, because a pending run has
mutated nothing.

> **Corollary:** a `ROLLBACK_REQUIRES_HUMAN_DECISION` outcome is the *expected* result of a cancelled
> mutation, not an edge case. Unknown prior state must never resolve toward destructive action.

**Cost note.** Validation has a cost envelope, and it is a governance concern rather than a separate
FinOps one. A harness that spawns duplicate runs makes assurance more expensive to sustain, and
assurance that becomes too expensive gets switched off — which is a control failure arriving by way
of a billing decision.

## Rollback is capability-specific

One generic script pretending every Azure resource has equivalent reversibility is a bug. These have
genuinely different semantics:

| Surface | Reversal mechanism |
|---|---|
| App Service | slot swap back |
| Container Apps | revision reactivation + traffic weights |
| Terraform-managed | state-aware; `destroy` is *not* rollback |
| Databases | schema/data migration — often **not** reversible |
| DNS | propagation delay; reversal is not instant |
| RBAC | assignment restore, with its own blast radius |

**The framework defines the contract; each adapter implements the mechanism:**

```
capture → mutate → validate → restore-on-failure → verify-restoration
```

## Sequential rollback — several deployments, tested end to end between steps

KDEC-019 item 4 (owner, 2026-10-22, relaying a colleague): when more than one deployment must be
rolled back, *"and can be done because nothing else touched the resource and/or because the
resource was shared but still able to be rolled back for that particular application or deployment
… intelligently then we should do end to end tests to make sure that between each rollback things
still work."* Built by lane L-RB: `scripts/rollback_sequence.py`, `.github/workflows/reusable-rollback-sequence.yml`,
`templates/rollback-sequence.yml`, record schema `schemas/rollback-sequence.schema.json`.

Everything above is about **one run** reversing **its own** change. A sequence reverses **several
standing deployments** — several runs' manifests, or several resources of one release — and adds
nothing to the per-run rules: each step is the same manifest-scoped, precondition-checked,
live-verified reversal the deploys already perform (`deploy_contract.py reverse`, the same code).
What the sequence adds is **order**, **eligibility before each step**, and **tests between steps**.

**Order.** Steps are listed oldest first and executed **newest first**, because a later release may
stand on an earlier one (DCR §8.1 P6). A sequence listed in the wrong order does not reverse out of
order: the first step it reaches has later releases standing on it, and it stops before touching
anything.

**Eligibility, from a fresh live read just before each step.** Two bases, the two the owner named:

| basis | means | adapters |
|---|---|---|
| `ELIGIBLE_UNTOUCHED` | every object the run's manifest names holds what the run left (P1 stamp, P2 version), no later release stands on it (P6), nothing labels it (P5), and nothing else on the resource moved | both |
| `ELIGIBLE_OWNED_PART_SEPARABLE` | the resource is shared and something else on it moved (another actor's inactive revision, a newer latest revision that takes no traffic), but **this deployment's part** — its revision and its traffic — is intact and is reversed on its own (DCR §8.1, "the unit of conflict is the mutation") | Container Apps |

Anything else stops the sequence **before** the step, and nothing of that step or any later one is
touched: `ROLLBACK_REQUIRES_HUMAN_DECISION` (touched by someone else, unreadable, a later release
outside the sequence standing on it, no valid mechanism, a deployment that is not standing), or
`ROLLBACK_PROHIBITED` for a step the caller declares forward-fix only (`forward_fix_only`, with the
reason: the emergency mitigation and RBAC rows of the table above). Revisions created by steps this
sequence has already reversed are its own, not another actor's. **App Service is eligible only
untouched:** its reversal is verified by comparing every slot it captured, so a slot another actor
moved would make the reversal unverifiable; the step stops before it rather than run to a certain
`ROLLBACK_PARTIAL`.

**A step is complete only when all four hold, in order:**

1. eligible (above);
2. reversed and **`ROLLBACK_VERIFIED`** by the deploy contract — `ROLLBACK_PARTIAL` or
   `STATUS_UNTRUSTED` halts the sequence (`ROLLBACK_SEQUENCE_HALTED_ROLLBACK_UNVERIFIED`); a partial
   rollback is never verified;
3. **healthy**: the deploy's own health probe answers 200 on the consumer-facing name
   (`ROLLBACK_SEQUENCE_HALTED_HEALTH_FAILED` otherwise; the tests are not run on an unhealthy state);
4. **the application's end-to-end tests pass, over a test period**: the caller's `e2e_test_command`,
   run in the caller's checkout by `/bin/sh` at the **start** and the **end** of a test period after
   **each** step (and every `e2e_check_interval_minutes` inside it, when set), with the step named in
   its environment (`$ROLLBACK_STEP`, `$ROLLBACK_STEPS_TOTAL`, `$ROLLBACK_DEPLOYMENT`,
   `$ROLLBACK_ADAPTER`, `$ROLLBACK_APP_URL`, `$ROLLBACK_SEQUENCE_ID`, `$ROLLBACK_CHECK_PHASE`),
   **without** the deploy identity's Azure session (its Azure configuration directory is a fresh
   empty one), and bounded by `e2e_timeout_minutes`. The health probe runs before the tests at every
   check. A failure **or a timeout** at **any** check halts the sequence,
   `ROLLBACK_SEQUENCE_HALTED_E2E_FAILED` (or `_HEALTH_FAILED`), for a human decision, on the state it
   reached. It never continues on a broken intermediate state, and the final step gets its period
   too: nothing is reported verified before it ends.

### The test period, the requested version, and deploys mid-rollback (KDEC-021, owner, 2026-10-23)

The owner's three rulings, as built by lane L-RB2:

- *"There needs to be an end to end test period."* — `e2e_test_period_minutes` on the reusable and
  the template, **default 15**, bounded **0 < m ≤ 240**. **0 is refused**,
  `ROLLBACK_SEQUENCE_REFUSED_NO_TEST_PERIOD`, the same family as `ROLLBACK_SEQUENCE_REFUSED_NO_E2E`
  (one instant is not a period); past 240 is `ROLLBACK_SEQUENCE_REFUSED_INPUT`. A period shorter than
  the baseline 15 is recorded as a reduced control (`e2e-test-period`, `CONTROL_RECONFIGURED`) in the
  control posture and needs an attributed weakening. Each check's phase (`start` | `interval` |
  `end`), time, offset from the start of the period and results are in the step's `test_period`.
- App Service slots *"should rollback to the previous code that is being requested."* — the sequence
  names `target_version` (the image `registry/repo@sha256:…` or digest production ran before the
  oldest deployment being reversed; **required** when any step is App Service). It is checked
  **before anything is touched** against what the oldest deployment's snapshot recorded — a version
  the target never held is refused, because returning to it would be a deploy, not a rollback. After
  every verified reversal each slot the step affected (production, the deploy slot, and the slot a
  swap moved images through) is **read back live** against the version it held before that
  deployment (`restored`), and after the last step production is read back against
  `target_version` (`final_version`). Stacked slot+swap deployments now reverse cleanly: each
  reversal hands the slot's ownership stamp back to the release that held it before
  (`deploy_contract.py` records the slot's `prior_stamp` on `MODIFIED` and restores it, as it
  already did for production on a swap). A slot changed by an actor **other than the kit** (no kit
  stamp, or a kit-stamped slot holding an image the kit did not leave) still stops the sequence for a
  human, and the reason says so.
- *"A deployment rolling mid rollback means the deployment has to be rolled back."* — (a) **Frozen**:
  the deploy reusables and the rollback reusable share **one concurrency group per target**,
  `kit-target-<environment>-<resource group>-<name>` (the adapter prefix was dropped from the deploy
  groups so the rollback can name the same lock from `target_resource_group` + `target_name`),
  never cancelled in progress; a deploy queues behind a rollback of its target. A sequence holds one
  target's lock, and a step on any other target is refused (`--locked-target`); a release over
  several targets is rolled back as one sequence per target. (b) **Backstop**: the target's kit
  releases are recorded when the sequence starts (`baseline`) and re-read before **every** step; a
  kit-stamped release that is new and not in the sequence landed mid-rollback. It is fetched
  (`gh run download` of its `deploy-evidence-<run>-<attempt>`), put at the **front** of what remains,
  rolled back **first** with its own eligibility, reversal and test period, and listed in `inserted`
  (its step carries `inserted: true` and why). Evidence that cannot be fetched, more than five
  landings, or a change with no kit stamp stops the sequence for a human.

**No end-to-end tests is a refusal, not a pass.** An empty `e2e_test_command` is
`ROLLBACK_SEQUENCE_REFUSED_NO_E2E` before login and before the first step; nothing is touched. The
alternatives were weighed: *run the reversals and record the gap* leaves exactly the untested
intermediate states the rule forbids, and a record after the fact cannot un-break a user path;
*treat the health probe as the test* collapses one request into functional validation, which this
kit refuses for promotion for the same reason. Refusing is the non-destructive branch: each deploy's
own single-run reversal is unaffected, and a caller with no tests can still reverse one deployment at
a time.

**The record** (`rollback-sequence.json`, validated against its schema before it is written; the job
summary and an artifact): the sequence result; each step's deployment, position and execution order,
eligibility basis or disposition with the checks that decided it, rollback result and residue,
health, e2e result and exit code, the test period's checks, the live read-back of what it restored,
whether it was inserted mid-sequence, timestamps; the lock held, the requested and final version,
the baseline of kit releases; and, for anything but a verified sequence, an
escalation contract (owner, next action, artefacts, what an automated actor may and may not do — the
same lists as the deploy outcome). **`ROLLBACK_SEQUENCE_VERIFIED` only when every step is
`ROLLBACK_STEP_VERIFIED`.** Vocabulary: `rollback_sequence`, `rollback_sequence_step`,
`rollback_step_eligibility` in `assurance-taxonomy.yaml`.

**Proven locally, not live.** `tests/prove_rollback_sequence.py` deploys with the shipped deploy
reusables against the stub cloud (three stacked Container App releases; one App Service + Container
App release) and runs the sequence: all good; step 2 of 3 failing its tests (halts, step 3
untouched); an ineligible step (stops before it); a shared app with the app-owned part intact
(eligible); no tests (refused, zero mutating calls); a partial rollback (never verified); forward-fix
only; wrong order; a failed probe; a hung test; evidence of another run; and, for KDEC-021, a test
period with an interval, a failure at the end of a period, a 0-minute and an over-bound period, two
stacked App Service slot+swap releases returned to the requested version (and a never-held or
missing version refused), a slot changed outside the kit (image, and a foreign stamp), a kit deploy
landing mid-sequence (rolled back first; and with no evidence, a human decision), and the shared
concurrency group (S13..S19). **Limits:** never executed against Azure (risks R-04); the concurrency
group is proven by resolving the expressions, not by a hosted queue; GitHub keeps one pending run per
group and discards an older pending one (it mutated nothing, and is re-run by hand); a sequence holds
one target's lock; P5 dependents beyond traffic labels are not readable (DCR §8.7); the e2e command is
the caller's own code and is trusted as such.

## Integration-test harness — separate, and safe for a different reason

Full destroy is permitted in the personal-tenant test **because absence is proven first**, not
because destroy is safe:

```
PRE_TEST_RESOURCE_COUNT  = 0   # asserted for the tagged/prefixed test scope, BEFORE deploying
        ↓ deploy
        ↓ validate
        ↓ cleanup
POST_CLEANUP_RESOURCE_COUNT = 0   # asserted AFTER, and failing loudly if not
```

Both assertions are required. The pre-assert is what makes full destroy defensible; the post-assert
is what stops a failed run leaving an orphan nobody notices for a month. **Teardown that is not
verified is `configured ≠ observed` in the place where it costs real money.**

This lives in the test harness. It is never imported into the reusable deploy path.

## The deployment model is PROVISIONAL — a second gate

The rollback contract is not the only thing holding the deploy workflows back.

**These deployment patterns came from a devkit, not from the Landing Zone.** The Landing Zone work
carried its own governance material — promotion sequencing, environment controls, rollback
expectations, and a body of "here is how to do this better" lessons — which has **not yet been
recovered and compared against what is implemented here**.

So there are two independent gates on the deploy surface:

1. **`ROLLBACK_CONTRACT.md`** — state-aware, change-scoped rollback with the dispositions above.
2. **Landing Zone reconciliation** — the recovered governance doctrine compared, difference by
   difference, against the promotion/environment/rollback model implemented here.

Deploy validation may proceed where it is safe and non-destructive. **The portable deployment model
must not be declared finished until gate 2 is closed**, because shipping a deployment pattern that
contradicts governance doctrine you already wrote — and then forgot you wrote — is a worse outcome
than shipping no deployment pattern at all. The consumer inherits the contradiction and has no way
to know it exists.

Until then, treat every deploy workflow in this kit as a **candidate implementation**, not a
recommendation.

> **Status of gate 2 (2026-10-16).** `DEPLOYMENT_CONTRACT_RECONCILIATION.md` did the
> difference-by-difference comparison (2026-09-18) and says it closes this gate; whether that claim
> stands is an open owner decision (completion ledger O-09, recommended: yes for the comparison,
> with promotion — DCR gap 11 — still open). Gate 1 is implemented and proven live (header).

## Promotion gate

`deploy-appservice`, `deploy-containerapp` and `image-push` were held at
`requires-integration-environment` until the boxes below held. They left it on the live runs in the
header (2026-10-15/16); the registry now records all three `observed`.

A tick below means **proven locally against a stub cloud** (`tests/_fake_az.py`, the whole job
run step by step by `tests/_workflow_runner.py`), in the proof named, and — where the box names it —
observed live. Live coverage per box: the snapshot, the change manifest, manifest-scoped reversal,
live-state verification and second-actor refusal are observed live; EMPTY/UNKNOWN previous state and
PARTIAL_APPLY / STATUS_UNTRUSTED are stub-only (DCR §7.8 matrix B and D).

- [x] Pre-change snapshot captured for the declared mutation surface — `deploy_contract.py
      capture`; `tests/prove_deploy_outcome.py` gap4/gap6. *Limit:* the surface is the image,
      revisions, traffic, mode and tags; app settings, ingress and identity are not captured
      because the run does not change them.
- [x] Change manifest records created / updated / deleted / redirected per run — written
      `planned` before the first mutation; gap6. *No run deletes anything, so no DELETED entry
      exists to record.*
- [x] Rollback scoped to the change manifest — never to a container scope — gap5, gap7.
- [x] Per-object preconditions evaluated against LIVE state before any removal — every entry
      through `scripts/derive_reversal_disposition.py` (`tests/prove_reversal_disposition.py`,
      exhaustive sweep); second-actor dependency withheld in gap5. *Limit:* P3/P5/P6 are adapter
      declarations or narrow live reads (traffic labels, later stamped revisions); no release
      graph exists.
- [ ] `ROLLBACK_REQUIRES_HUMAN_DECISION` emitted when pre-state is unknown — NOT ticked. Unknown
      pre-state now refuses BEFORE any mutation (`previous_state` UNKNOWN -> `DEPLOY_REFUSED`), and
      a mutation that loses visibility reports `STATUS_UNTRUSTED` with an escalation contract; the
      `rollback_state` value itself is not emitted anywhere.
- [x] Live-state verification after rollback, not command exit status — gap7, including an
      apply-then-error case decided by live state. An entry the reversal did not act on (refused,
      withheld, deferred, mechanism not valid) makes the run `ROLLBACK_PARTIAL` whatever live
      state happens to equal — live run 38879879589 reported a REFUSED reversal as verified
      because a second actor's image equalled the prior one (`prove_deploy_outcome.py`
      `live_appservice_refused_reversal_is_not_verified`). *Limit:* on App Service the comparison
      reads the CONFIGURED image; the running container is reported separately, from the
      platform's container start record, and is not part of the verdict.
- [x] Capability-specific adapters rather than one generic destroy — Container Apps (traffic,
      revision deactivation, refused in single-revision mode) and App Service (swap back, image
      restore); gap5, gap7, gap9.
- [x] Harness cleanup path kept out of the reusable workflow — `tests/harness/teardown_scope.py`,
      `tests/prove_harness_teardown.py` (structural check included).

`image-push` is outside this list's proof: DCR gap 10 (push as a point of no return) is in
`reusable-build-docker.yml`, which this work did not change. It has since been proven on its own
terms against a real local registry (`tests/prove_build_push_round_trip.py`, 2026-10-15): the
capability step reads a held tag as the rollback point, an unreachable registry refuses before the
push, and the change manifest records the prior digest. The live half followed: an ACR behind the
test identity's OIDC login, runs 38857011286, 38857017667, 38857024014 (build once, gate before
push, `REGISTRY_IDENTITY_PROVEN`, digests confirmed independently and then deployed).

## Timeouts are a cancellation vector — and mutating jobs are deliberately unbounded

Added 2026-08-18, after a stalled scanner billed an estimated ~386 minutes.

Every **non-mutating** job in the kit now carries `timeout-minutes`. **No mutating job does**, and
that omission is a decision, not an oversight.

A timeout is a cancellation the operator did not choose and cannot time. Everything this contract
already says about a cancelled run applies with more force, because nobody is watching when it fires:

- A build-and-push or deploy job killed mid-change strands a half-applied change **with no completed
  change manifest**, so rollback cannot know what it owned.
- That is a `ROLLBACK_REQUIRES_HUMAN_DECISION` — the *expected* outcome, not an error.

**`timeout-minutes` must not be added to a mutating job merely because it is a convenient YAML
property.** Before bounding one, answer: *what is the change manifest at the moment of the kill, and
what can be safely reversed from it?* A bound that produces an unreversible half-state is worse than
an unbounded job, because it manufactures the exact condition this contract exists to avoid.

Cost still has to be bounded somewhere. The answer for mutating work is a bound on the **change
window** with a manifest written before mutation begins — not a wall-clock kill on the job.
