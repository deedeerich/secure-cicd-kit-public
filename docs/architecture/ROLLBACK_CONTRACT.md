# Rollback contract — blocking requirement for the deploy workflows

```
Status: REQUIREMENT, not implemented. The deploy workflows MUST NOT be promoted
beyond `requires-integration-environment` until this contract is satisfied.
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

## Promotion gate

`deploy-appservice`, `deploy-containerapp` and `image-push` stay at
`requires-integration-environment` until:

- [ ] Pre-change snapshot captured for the declared mutation surface
- [ ] Change manifest records created / updated / deleted / redirected per run
- [ ] Rollback scoped to the change manifest — never to a container scope
- [ ] `ROLLBACK_REQUIRES_HUMAN_DECISION` emitted when pre-state is unknown
- [ ] Live-state verification after rollback, not command exit status
- [ ] Capability-specific adapters rather than one generic destroy
- [ ] Harness cleanup path kept out of the reusable workflow

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
