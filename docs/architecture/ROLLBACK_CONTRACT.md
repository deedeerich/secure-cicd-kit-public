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
