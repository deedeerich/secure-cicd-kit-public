# Deployment contract reconciliation — prior control-plane design vs this kit

```
Phase: design  ·  Truth State: reconciled 2026-09-18 against a recovered prior control-plane
                  design corpus and the deploy workflows as they stand in this tree
Audience: anyone about to change a mutating workflow, or to promote one past
          `requires-integration-environment`
Decision Supported: what the deploy surface must do before its outcome report can be trusted
Deferred Depth: docs/architecture/ROLLBACK_CONTRACT.md · docs/architecture/AXES_AND_PHASES.md ·
                assurance-taxonomy.yaml (`rollback_state`, `environment_tier`, `policy_mode`)
```

This closes **gate 2** of `ROLLBACK_CONTRACT.md:186-188` — *"the recovered governance doctrine
compared, difference by difference, against the promotion/environment/rollback model implemented
here."* (Whether that claim stands is open owner decision O-09 in `docs/assurance/COMPLETION_LEDGER.md`.)
When this was written, gate 1 (state-aware, change-scoped rollback) was open and this document was
what the implementation work had to satisfy.

> **Implementation status, 2026-10-16 (trunk `3830edb`).** The gap list in §5 below describes the
> deploy workflows **as they stood on 2026-09-18**; its line references are to that code. Built since
> (`scripts/deploy_contract.py`, both deploy reusables) and proven as follows — live runs through
> `live-deploy-acceptance.yml`, cited in `tests/reconcile_validation.py`:
>
> | gap | state | evidence |
> |---|---|---|
> | 1 `slot: ''` direct to production | built; refused at uat/prod; direct path reversible | live: 38853184615 (prod, no slot, refused before login), 38878189985 (direct path rolled back, verified) |
> | 2 ATTEMPTED vs NOW SERVING | built; **App Service judges NOW SERVING by the configured image**, the platform start record is reported beside it | live (defect 95bd5cc found by 38879879589); design caveat open (ledger DCR-2, B-02) |
> | 3 provenance after health | built (tags after health and a live read) | stub only (`prove_deploy_outcome` gap3); never written live |
> | 4 a read failure is not "empty" | built (`previous_state` UNKNOWN refuses before mutation) | stub only (gap4) |
> | 5 rollback to empty | built | stub only (gap5) |
> | 6 snapshot and change manifest | built, written before the first mutation | every live run |
> | 7 reversal verified against live state; `ROLLBACK_PARTIAL` | built | live: 38855747496, 38858033863, 38878189985, 38912546778; partial 38855929525, 38886279650 |
> | 8 `PARTIAL_APPLY` / `STATUS_UNTRUSTED` | built, registered | stub only (gap8; matrix B and D not induced live) |
> | 9 `rollback_capability` before the point of no return | built; UNAVAILABLE refuses at uat/prod | stub only (gap9); computed on every live run, never refused live |
> | 10 push as the point of no return | built in `reusable-build-docker.yml` | live: 38857011286, 38857017667, 38857024014. The `docker-build-push` composite has no push-capability step |
> | 11 promotion verified | built (KDEC-029, 2026-10-26): every condition has a source; the promotion record and the promotion gate (`scripts/promotion.py`) | stub only (`prove_deploy_outcome` gap11, `prove_promotion`); the hosted promotion is owed |
>
> Gate 1 is therefore implemented and proven live for the reversal cases the acceptance matrix calls
> A and C and for the second-actor refusal (§8); B, D, E and ROLLBACK_TO_EMPTY are not live (§7.8).

## Custody

The rule is a **naming** rule, not a usage ban. The engineering crosses over intact; the identity
does not.

**Carried:** the state model and its vocabulary, the lifecycle and its ordering, schemas and
structures as models, the reasoning, the alternatives that were rejected and why, and the worked
failures that motivated each decision — because a state with its originating failure attached is
worth ten times one lifted from a list.

**Not carried:** any employer, tenant, product codename, personal identity, repository path or
resource name. The source is cited throughout as **"the prior control-plane design."** Where that
design's own examples are used, the names are substituted and the mechanism is kept.

This is the same treatment the kit already gives its own inherited lessons — the ticket-gate
injection defect, the correlation-engine doctrine and the NVD abstraction accounting are all
recorded in full and attributed to *a reference estate* rather than to whoever's estate it was.
Keep the lesson, drop the name.

Where a requirement below matches something the prior design already wrote, the **neutral
requirement is stated first** and the prior design is cited afterwards as *evidence that the
requirement is right* — because that design paid for the evidence with real incidents, and every
one of those incidents is reachable from this kit's current code.

---

## 1 · Where the two already agree

Four things need no reconciliation. One line each, then move on.

| Agreement | Both say |
|---|---|
| **Reversal is scoped to what the run touched** | Prior design: platform-managed dependencies are destroyed with the workload; externally-owned ones **never** are. Kit: `ROLLBACK_CONTRACT.md:10-13`. Same rule, arrived at independently. |
| **A command exiting 0 is not proof of effect** | Prior design's four-state maturity spine ends at *effective*, proven by a negative test. Kit: `ROLLBACK_CONTRACT.md:56-57`. |
| **Unknown must not resolve toward destruction** | Prior design escalates rather than guesses. Kit: `ROLLBACK_CONTRACT.md:59-71`, `assurance-taxonomy.yaml:796-801`. |
| **A cancelled mutation is an expected outcome, not an edge case** | Kit: `ROLLBACK_CONTRACT.md:108-134`, `:212-232`. The prior design has no counter-position; its observed analogue is the half-applied change (row 1.4 below). |

Everything after this point is a delta.

---

## 2 · Three-way reconciliation

Legend: **MEETS** · **PARTIAL** · **MISSES**.

### 2.1 Lifecycle and pre-change state capture

| What the prior control-plane design established | What the kit does today | The neutral requirement | Verdict |
|---|---|---|---|
| A change is a sequence with a **capture step before the mutation step**, and the capture must cover every surface the change will touch, not a single handle. | App Service captures **nothing** before mutating: `reusable-deploy-appservice.yml:127-137` is the first thing that touches the target. Container Apps captures **one string** — the active revision name — at `reusable-deploy-containerapp.yml:125-132`. Not the image reference, not traffic weights, not app settings, not the revision mode. | Before the first mutation the run MUST record a **pre-change snapshot of the declared mutation surface**: every attribute the run intends to change, plus everything reversal will need to restore. A snapshot narrower than the mutation surface is not a snapshot. | **MISSES** (App Service) / **PARTIAL** (Container Apps) |
| The state record must distinguish *"there is no prior state"* from *"we could not read the prior state."* Collapsing them is how an unknown silently becomes an empty. | `reusable-deploy-containerapp.yml:130` ends the query with `2>/dev/null \|\| true`, so a permissions failure, a throttled API and a genuinely first deployment all produce the same empty string. Line 187 then treats empty as "no rollback needed." | `PREVIOUS_STATE` MUST be one of three values, never inferred from an empty string: an existing deployment, a proven-empty target, or unknown. The capture step MUST fail loudly rather than degrade a read error into an absence. | **MISSES** |
| The run must record what **this run** created, updated, deleted or redirected — a change manifest — because that, not the resource container, is the scope of any reversal. | Neither deploy workflow writes a change manifest. Container Apps *infers* its own new revision by taking the newest by creation time (`reusable-deploy-containerapp.yml:143-145`), which is a guess about ownership, not a record of it. | The run MUST emit a change manifest naming each object it created, each object it modified together with the captured prior value, and each traffic redirection. Reversal reads the manifest; it never reads the container. | **MISSES** |
| Infrastructure that mutated but is not reflected in the recorded state is a **distinct, named failure class** that requires out-of-band recovery. The prior design hit it as a partially-applied change whose orphans existed in the cloud but not in state, and which was only recovered by manual deletion. | No such state exists in either workflow or in `assurance-taxonomy.yaml:781-811`. A run that dies between the mutation and the summary simply produces a failed job. | A partial application MUST be representable. When a run terminates after mutation and before reconciliation, the outcome is not "failed" — it is *mutated, extent unknown*, and it MUST say so. | **MISSES** |

### 2.2 Reversal semantics

| What the prior control-plane design established | What the kit does today | The neutral requirement | Verdict |
|---|---|---|---|
| Reversal is **capability-specific**, and the mechanism must be legal for the target's current mode of operation. | `reusable-deploy-containerapp.yml:193-195` sets a 100% traffic weight on the previous revision. That is a traffic-split operation. The workflow never establishes or asserts the target's revision mode, and the operation is not valid in every mode. If it errors, the step fails — after `revision activate` at `:190-192` has already run. | Before performing a reversal the run MUST establish that the reversal mechanism is valid for the target's observed configuration. A reversal that fails halfway is itself a partial reversal and MUST be reported as one. | **PARTIAL** |
| A recovery path must exist for the case where there is no prior state. The prior design treated teardown of a *proven-empty-before* scope as a legitimate, separately-gated operation, not as an error condition and not as the same operation as restoring a prior deployment. | `reusable-deploy-containerapp.yml:187` gates the entire rollback step on `steps.before.outputs.previous != ''`. When there is no previous revision the step is **skipped in silence** — no output, no state, no summary row. The App Service workflow has no rollback step at all. | **Rollback to empty is a first-class recovery path, not an error.** A first deployment has a rollback point: the empty state. "Undo what this run touched" then means *remove what it created and restore what it changed, leaving unrelated platform resources alone.* It does NOT mean destroy the environment. The empty-state path MUST be implemented, reported and verified exactly like the prior-state path. | **MISSES** |
| A workload's security-relevant properties must remain functionally equivalent across any lifecycle transition — promotion, migration, rebuild, reprovision, **recovery**. The prior design learned this from an incident where configuration existed in the source and did not survive the transition, and nothing detected the divergence. | Neither workflow asserts anything about the restored target's identity, ingress, authentication or network posture after a reversal. `reusable-deploy-containerapp.yml:196` prints `Rolled back.` and stops. | Reversal MUST restore security posture, not just the workload artefact. After reversal the run MUST re-establish that the controls it was relying on before the change are present on what is now serving. A reversal that restores the image and loses a control is a security regression wearing a recovery label. | **MISSES** |
| Reversal is frequently **partial** in practice, and the residue matters more than the success. | Nothing in either workflow can express partial reversal. `reusable-deploy-containerapp.yml:149-158` mutates the app template a second time to stamp provenance; the reversal at `:186-196` restores a revision but does not undo that template mutation. So even on the happy path the reversal is partial — and reports as total. | A reversal MUST report **what was reversed, what was NOT, and why.** Intentional retention for forensics is legitimate **when stated**; unstated retention is a lie about the terminal state. | **MISSES** |
| Reversal correctness is established by **querying live state and comparing it against the pre-change snapshot**, never by the reversal command's exit status. Reconciliation verifies the *negative space* too: some of its assertions are that a thing is still absent. | `reusable-deploy-containerapp.yml:196` asserts success from command exit. The kit already has the correct doctrine written down at `ROLLBACK_CONTRACT.md:50-57`; the workflows do not implement it. | The terminal state is **reconciled reality**. The run MUST read live state after reversal and compare it against the pre-change snapshot before asserting that recovery succeeded — including asserting that what should be gone is gone. | **MISSES** (documented, not implemented) |
| **Automated reversal authority scales with severity, it is not granted uniformly.** The prior design classified divergence into three tiers and permitted automated remediation only at the most severe, on the reasoning that auto-reversing benign divergence causes more outages than it prevents — "remediation breaks workload" was one of its own observed incident shapes. | `reusable-deploy-containerapp.yml:187` gates reversal on a single boolean input (`rollback_on_failure`) plus a non-empty string. Any health failure, of any severity, triggers the same full traffic reversal. | Reversal authority MUST be a function of severity, not a single switch. The contract MUST distinguish *report only*, *reverse and verify*, and *reverse immediately* — and `ROLLBACK_CONTRACT.md:96-101` already names the right four dispositions for this. | **MISSES** |

### 2.3 Reporting honesty — the defect that motivated this work

| What the prior control-plane design established | What the kit does today | The neutral requirement | Verdict |
|---|---|---|---|
| **The defect class, stated directly.** In the prior design a status-writing step had no condition on prior success, so it recorded a successful plan even though the plan never executed. Any agent or human reading that status as the machine-readable contract believed something that was not true. The fix was two-part: gate the write on success, **and** expand the status vocabulary so failure modes are distinguishable. *"A status field with only a happy value is not a contract."* | `reusable-deploy-appservice.yml:199-213` and `reusable-deploy-containerapp.yml:198-212` run `if: always()` and print the **digest the run tried to deploy** (`:209` / `:208`) and, for Container Apps, the **revision the run tried to create** (`:209`) immediately beside a `Health` cell that may read `failure`. A reader concludes their change shipped when it was rolled back — or, on the App Service production path, when nothing reversed it at all. | The outcome report MUST distinguish **ATTEMPTED** from **NOW SERVING**. Every identifier in the report MUST be labelled as one or the other, and the *now serving* values MUST be read back from live state, not echoed from inputs. Where the run cannot establish what is serving, the report says so rather than printing the attempt. | **MISSES** |
| A status that the evidence does not support must not be emitted. The prior design's sharpest instance: a deployment reported complete while the field proving the user outcome was absent from the report. The rule adopted was that the absence of that field downgrades the state — the run is not *complete*, it is *incomplete*. | Both summaries are `if: always()` with no coupling between what is printed and what was verified. The App Service workflow additionally cannot report a swap that did not happen on the production path, because there is no swap on that path. | A terminal success state MUST NOT be asserted while a field that proves it is missing. Missing proof downgrades the state; it never defaults to success. | **MISSES** |
| A **degraded or fallback outcome must be named and consented to**, never silently substituted for the requested one. The prior design's instance was a placeholder artefact deployed in place of the requested one while the run reported success — infrastructure correct, user outcome wrong. | Not applicable in the same shape here, but the structural analogue exists: `reusable-deploy-containerapp.yml:186-196` substitutes *previous revision serving* for *requested digest serving* and the summary still prints the requested digest. | Where the run ends in a state other than the one requested, the report MUST name the substitution. The requested identifier may appear only under an ATTEMPTED label. | **MISSES** |
| Provenance is a claim about reality and must be stamped only once reality supports it. | Both workflows stamp provenance **before** the health probe: `reusable-deploy-appservice.yml:139-149` precedes `:169-184`; `reusable-deploy-containerapp.yml:149-158` precedes `:169-184`. On a failed deploy the target therefore carries provenance for a version that never passed health. On Container Apps the reversal does not remove it. | Provenance MUST be stamped only after health **and** live-state reconciliation succeed. Provenance means *this is running and it works*, not *this is what we attempted*. On reversal, provenance MUST be restored to the prior value or explicitly marked untrusted. | **MISSES** |
| The status model must be able to answer six questions truthfully, or downstream automation makes confident, wrong decisions: is it blocked · why · who owns resolution · is a remediation known · may an automated actor proceed unattended · what is the exact next action. | The kit's summaries answer none of these. The job's red/green is the only machine-readable signal, and `assurance-taxonomy.yaml:781-811` describes dispositions but no run outcome. | The outcome report MUST answer all six. A blocking state that cannot say who owns resolution and whether a remediation is known is an invitation to retry loops and invented fixes. | **MISSES** |

### 2.4 Governance placement relative to the point of no return

| What the prior control-plane design established | What the kit does today | The neutral requirement | Verdict |
|---|---|---|---|
| Review happens **before decisions become irreversible** — routing is decided pre-provision, with four outcomes: proceed automatically, proceed with asynchronous notification, block pending review, or reject with the redesign named. Ambiguity fails closed toward review. | The deploy workflows take `github_environment` (`reusable-deploy-appservice.yml:12-14`) and nothing else that bears on consequence. They consume neither `environment_tier` (`assurance-taxonomy.yaml:923-937`) nor `policy_mode` (`:873-885`), so the ENVIRONMENT CONSEQUENCE and ENFORCEMENT axes of `AXES_AND_PHASES.md` are unwired on the one surface where being wrong costs the most. | Before an **irreversible mutation**, `rollback_capability` MUST be established as one of three values, and the environment/enforcement axis MUST decide whether the operation may proceed. **Governance belongs before the point of no return, not after.** A gate that runs after the mutation is a report, not a gate. | **MISSES** |
| Some decisions are cheap to make and expensive or impossible to reverse; those are foundational and must be surfaced explicitly rather than discovered during recovery. | Nothing in the kit classifies a mutation by reversibility before performing it. `ROLLBACK_CONTRACT.md:73-106` classifies change *classes* correctly but nothing consumes that table at run time. | Irreversibility MUST be declared by the adapter and evaluated before the mutation. The four dispositions at `ROLLBACK_CONTRACT.md:96-101` are the right vocabulary; they need a consumer. | **PARTIAL** (documented, not enforced) |
| The plan-review invariant is a **positive assertion list, not an absence of errors** — and one of its standing assertions is *no unexpected destruction outside the intended change*. That assertion is a pre-mutation reversibility screen: you establish what will be destroyed **before** authorising the mutation, because afterwards the question is expensive to answer. | The kit performs no plan or diff stage on either deploy surface. The first thing a run knows about the blast radius of its own change is whatever the cloud does after the mutation is issued. | Where the adapter can produce a change preview, the run MUST assert *no destruction outside the change manifest* before authorising the mutation. Where it cannot, that inability is itself an input to `rollback_capability` and MUST be recorded. | **MISSES** |
| A change that carries a different reversibility profile from its container **must not inherit the container's review path**. The prior design held a small but tenant-scoped edit out of a workload-scoped change on exactly this ground — different blast radius, different review path. | Both deploy workflows treat every mutation in the run as one undifferentiated unit of authority, gated once by the GitHub Environment at `reusable-deploy-appservice.yml:106` / `reusable-deploy-containerapp.yml:103`. | A run MUST NOT bundle mutations whose reversibility or blast radius differ materially under a single gate. Where it must, the gate is the strictest of them, not the most convenient. | **MISSES** |
| Deployment success is **not** trust progression. A change can deploy, function and pass technical validation while remaining ineligible to advance. Conflating the two produces *"it deployed, therefore it is approved."* | The kit has no promotion concept on the deploy surface at all — a successful deploy is the terminal state. | The contract MUST separate *deployed and healthy* from *verified for promotion*. Promotion requires evidence that the controls are effective, not merely that the deployment completed. | **MISSES** |
| A registry push is an irreversible mutation of a shared, retained surface and deserves the same pre-mutation treatment as a deployment. | `reusable-build-docker.yml:154-162` pushes with no rollback-capability assessment and no reversal path. Separately, the artefact scanned at `:139-145` comes from the build at `:131-137` while the artefact pushed at `:154-162` comes from a **second** `docker/build-push-action` invocation. Cache normally makes them identical; nothing proves it, and the digest reported downstream is the pushed one. | Push MUST be treated as a point of no return: `rollback_capability` established beforehand, and the pushed digest MUST be the digest that was scanned — proven, not assumed. | **MISSES** |

---

### 2.5 The state model the prior design arrived at — including what it rejected on the way

The single most transferable structure in the prior control-plane design is not any individual
state. It is **the organising axis**: states are grouped by *who is permitted to act on them*, not
by severity. That axis is worth carrying wholesale, because it is the thing this kit's
`rollback_state` namespace does not have.

| Band | The question it answers | Members as the prior design enumerated them |
|---|---|---|
| Non-blocking | Proceed; this is information | advisory · observed risk · warning |
| Blocking, autonomously resolvable | A remediation is known **and** an automated actor may apply it | fix required · retry required · dependency missing · input blocked · policy remediable |
| Blocking, **not** autonomously resolvable | A human or governance decision is required | security blocked · architecture blocked · governance blocked · manual review required · unsupported pattern |
| **System failure** | The control plane cannot vouch for reality | **pipeline failed · status untrusted · partial apply · rollback required** |

Four things about how it got there, because the path matters more than the list:

- **The fourth band is empirical, not a priori.** It was added after the operators had already
  observed stale outputs, false success and partial applies in production runs. It exists because
  the first three bands all presuppose that the record describes the world, and sometimes it does
  not. A kit whose taxonomy has no fourth band is asserting that its records are always truthful.
- **A single "fix required" state was rejected as overloaded.** It was collapsing two operationally
  opposite realities: *a remediation path exists* and *nobody currently knows how to resolve this
  safely.* The split into a `fix_available` flag plus a separate `autonomous_resolution_allowed`
  flag was the correction. The reasoning generalises: **state overloading is a correctness bug, not
  a naming preference.** If the state model lies, everything downstream is nonsense wrapped in
  structured data.
- **`rollback required` is deliberately a state of the system, not a record of an action.** It
  asserts that a reversal is *owed*. It does not assert that the platform has the authority or the
  capability to perform one. That separation is what lets a run escalate honestly instead of
  attempting a reversal it was never entitled to make — and it is why the proposal in §4 keeps
  `ROLLBACK_REQUIRED` but never lets it be terminal.
- **A blocking non-autonomous state without an escalation contract was treated as a dead end.**
  The stated failure mode if you omit it: automated actors retry endlessly, generate garbage fixes,
  route around policy, or invent remediation paths — described in the source as building a
  distributed outage generator. The contract shape is given in §3.4.

**The four worked failures that produced all of this**, names substituted, because each maps
one-to-one onto something reachable from this kit's current code:

| The failure | What it proved | The kit's exposure |
|---|---|---|
| A status-writing step with no condition on prior success recorded a completed plan for a plan that never executed | A status field with only a happy value is not a contract | Both summaries run `if: always()` and echo inputs |
| A partial apply left objects existing in the cloud and absent from the state record; recovery was manual out-of-band deletion | Mutation without accountability is a distinct failure class needing its own state | No representation for it anywhere |
| Infrastructure verified entirely healthy while the user path returned failures and the direct-to-origin path succeeded | *Provisioned correctly* and *serving* are separate claims, and only one of them is what the user asked for | Health probes the resolved target, not necessarily what the user path reaches |
| A deployment reported complete while the field proving the user outcome was absent from the report | Missing proof downgrades the state; it never defaults to success | No NOW SERVING column exists to be missing |

---

## 3 · The neutral deployment contract

Backend-neutral. Nothing below names a cloud, a runtime, a registry or an IaC language. An adapter
implements the mechanism; the contract defines the obligations.

### 3.1 The lifecycle

```
intent
  → pre-change snapshot        (the declared mutation surface, captured before anything moves)
  → change manifest            (what THIS run will create / update / delete / redirect)
  → mutation
  → health & functional validation
  → live-state reconciliation  (observed reality compared against the manifest and snapshot)
  → provenance commit          (stamped only if the two preceding stages both succeeded)
```

Three rules bind the sequence:

1. **No stage may be skipped on the failure path.** A run that fails at mutation still owes a
   reconciliation and a report. Failure is not an exemption from telling the truth.
2. **The terminal state is reconciled reality, not "rollback ran."** The authority for the final
   outcome is what live state says is serving, compared against what was captured before the
   change. A reversal command's exit status is an input to that comparison, never a substitute
   for it.
3. **Provenance is stamped last.** It is a claim that something is running and works. It must
   never be written before there is evidence for both halves of that claim, and it must be
   restored or marked untrusted when a reversal changes what is serving.

**Reconciliation is layered, not boolean.** The prior control-plane design's readiness model is
worth carrying as a structure: each layer is reported independently and the overall state is
*derived*, never asserted. Its stated purpose was to kill the inference that a successful apply
means the thing works.

```
infrastructure_ready    the objects exist
dependencies_ready      what the target needs is present and reachable
inputs_ready            externally-owned inputs the platform does not provide are present
runtime_deployed        the intended artefact is the one loaded
health_verified         functional validation passed against the live target
serving_verified        the path a consumer actually uses reaches the intended artefact
```

Two consequences the prior design paid for in incidents:

- **A lower layer passing does not imply a higher one.** A provisioned dependency does not mean the
  workload runs. A healthy target does not mean the consumer path reaches it — that one was proven
  by a case where every provisioned object verified healthy while the user-facing path failed and
  the direct-to-origin path succeeded. `health_verified` and `serving_verified` are separate
  assertions and the kit currently has only the first.
- **Reconciliation asserts absences too.** Some of its checks are that something is *still missing*
  — an externally-owned input still declared absent, an object the reversal was supposed to remove
  actually gone. A reconciliation that only looks for presence cannot detect a failed removal.

### 3.2 Previous state, and what rollback means for each

`PREVIOUS_STATE` is established by the capture stage and takes exactly one of three values. It is
never inferred from an empty result.

| Value | Established by | Rollback means | Terminal state on success |
|---|---|---|---|
| **an existing deployment** | Reading the target and observing a prior deployment, with every attribute in the mutation surface captured | Restore the captured prior state for everything this run modified; remove everything this run created; restore prior routing | Prior state reconciled and serving |
| **empty** | Reading the target and observing, *positively*, that nothing was there — the absence is measured, not assumed | **Remove what this run created and restore what it changed, leaving unrelated platform resources alone.** This is a recovery path, not an error, and not a teardown of the environment | Empty state reconciled; the target is back to the measured absence |
| **unknown** | Any read that could not establish either of the above — permission denied, timeout, throttling, cancellation before capture completed, or a capture that never ran | **Nothing destructive.** The run reconciles what it can observe and reports untrusted status with the reason | Untrusted status reported; no destructive action taken |

Three consequences worth stating explicitly:

- **A read failure is not an absence.** An adapter that swallows an error and returns a blank is
  manufacturing a false empty, and a false empty is the input that makes "remove what this run
  created" delete the wrong things or skip the recovery entirely.
- **The empty path must be implemented, not merely permitted.** A gate of the form
  *"roll back only if a previous state exists"* silently skips recovery on every first deployment
  — the exact population where a failed deploy leaves the most orphans.
- **Unknown previous state must not pretend rollback succeeded.** The run reconciles, reports
  untrusted status, and stops. It does not guess, and it does not resolve the ambiguity toward the
  branch that is easier to code.

> **Corrected by §8.** All three rows above are properties of **the run**, and the empty row's
> *"remove what this run created"* has no precondition attached to it. A measured-empty target at
> deployment time says nothing about the target at reversal time. Every object named in a manifest
> — on the empty path as much as any other — is subject to the per-object preconditions in §8.1
> before anything is removed.

### 3.3 Reversal reporting

A reversal produces a report, not a boolean.

- **What was reversed** — each object, with the observed post-reversal value compared against the
  captured prior value.
- **What was NOT reversed** — each object left changed, with the value it now holds.
- **Why** — per item. Three reasons are legitimate: the reversal mechanism was not valid for the
  target's observed configuration; the object is outside the change manifest and therefore outside
  this run's authority; **or the object was retained deliberately for forensics.**
  Intentional retention is legitimate **when stated**. Unstated retention is a false claim about
  the terminal state.
- **Residual risk** — anything left in a state that neither matches the prior snapshot nor the
  intended change.

A reversal that reversed some things and not others is **partial**. Partial is a terminal state in
its own right. It is never reported as verified.

> **Extended by §8.4–8.5.** The three reasons above are not the full set. They have no entry for
> *a later release owns the current state*, *an external actor changed it*, *a dependent exists*
> or *ownership could not be established* — four outcomes an implementation would then have
> nowhere to record. The per-object disposition and conflict vocabulary is in
> `assurance-taxonomy.yaml` under `reversal_disposition` and `reversal_conflict`.

### 3.4 The outcome report

Every identifier in the report carries one of two labels. There is no third, unlabelled category.

| Label | Source | May be echoed from inputs? |
|---|---|---|
| **ATTEMPTED** | The run's inputs and intent | Yes — that is what it is |
| **NOW SERVING** | Read back from live state during reconciliation | **No.** Echoing an input here is the defect |

Rules:

- If the run cannot establish what is now serving, the report says *unknown* in that column. It
  does not fall back to the attempted value.
- A terminal success state MUST NOT be asserted while a field that would prove it is missing.
  Missing proof downgrades the state.
- Where the run ends in a state other than the one requested — a reversal, a fallback, a partial
  application — the report names the substitution explicitly.
- The report answers six questions, or it is not a report:
  1. Is progression blocked?
  2. Why?
  3. Who owns resolution?
  4. Is a remediation known?
  5. May an automated actor proceed unattended?
  6. What is the exact next action?

Questions 4 and 5 are separate on purpose. *"A fix exists"* and *"a machine may apply it"* are
different claims, and collapsing them produces automation that retries forever or invents
remediations for problems it was never authorised to touch.

**A blocking state that no automated actor may resolve MUST carry an escalation contract.** Without
one it is a dead end, and the observed consequence of dead ends is automation that retries
endlessly, fabricates remediations, or routes around the gate. The contract shape, carried from the
prior control-plane design as a model:

| Field | Purpose |
|---|---|
| `resolution_owner` | Who decides. A role or team, never an individual |
| `request_channel` | Where the request goes |
| `request_type` | What kind of decision is being asked for |
| `required_artefacts` | What must accompany the request — the change manifest, the pre-change snapshot, the reconciliation result, the specific finding |
| `service_level` | How long the requester should expect to wait |
| `permitted_agent_action` | The bounded set an automated actor MAY take |

`permitted_agent_action` is the load-bearing field. An automated actor holding a non-autonomous
blocking state may gather evidence, identify the owner, draft the request and propose compensating
controls. It may **not** mutate infrastructure, retry the mutation, suppress the finding, invent an
approval, or proceed to apply. Those two lists must be explicit, because the default behaviour of an
unconstrained actor facing a blocker is to try something.

### 3.5 Before the point of no return

Before any **irreversible** mutation the run MUST establish `rollback_capability`:

| Value | Meaning |
|---|---|
| **available** | A prior state was captured and the adapter has a valid reversal mechanism for the target's observed configuration |
| **unavailable** | Either no usable prior state was captured, or no valid reversal mechanism exists for this change class on this target |
| **no prior state** | The target is measured empty; reversal means removing what this run creates |

The environment/enforcement axis then decides whether the operation may proceed. At low-consequence
tiers an unavailable capability may be an accepted risk that is recorded. At production tiers it
blocks. The decision is taken **before** the mutation, because governance that arrives after the
point of no return is a report, not a gate.

The kit already has both halves of the input: `environment_tier` and `policy_mode` in
`assurance-taxonomy.yaml:873-937`, and the ENVIRONMENT CONSEQUENCE × ENFORCEMENT axes in
`AXES_AND_PHASES.md`. Neither reaches the deploy workflows. Wiring them is the gate.

---

## 4 · Proposed vocabulary for `assurance-taxonomy.yaml`

**This is a proposal. Do not edit `assurance-taxonomy.yaml` from this document.**

The existing `rollback_state` namespace (`assurance-taxonomy.yaml:781-811`) has five values and is
insufficient for one structural reason: **it describes only dispositions — what may be done about a
failed change — and has no vocabulary for outcomes — what actually happened.** A namespace that
can say `AUTO_ROLLBACK_ALLOWED` but cannot say *"we mutated and then lost visibility"* cannot
describe the failure the deploy workflows are most likely to produce.

The prior control-plane design reached the same conclusion from the other direction: as soon as
more than one automated actor consumed the state field, the vocabulary became an API, and an
un-versioned, under-specified API is how one actor's *blocked* becomes another's *pending* three
layers downstream.

Two changes are proposed: **keep `rollback_state` as the disposition namespace, unchanged**, and
add a sibling `deployment_outcome` namespace for what happened — organised on the prior design's
actionability axis from §2.5, because grouping outcomes by *who may act* is what makes the
namespace consumable by anything other than a human reading a summary.

| Band | Proposed members |
|---|---|
| Non-blocking | `DEPLOY_HEALTHY` · `PROMOTION_VERIFIED` |
| Blocking, autonomously resolvable | `DEPLOY_ATTEMPTED` · `ROLLBACK_REQUIRED` |
| Blocking, **not** autonomously resolvable | `ROLLBACK_PARTIAL` · `MANUAL_RECOVERY_REQUIRED` |
| **System failure** | `PARTIAL_APPLY` · `STATUS_UNTRUSTED` |
| Reversal outcomes (band depends on verification) | `ROLLBACK_TO_PRIOR` · `ROLLBACK_TO_EMPTY` → `ROLLBACK_VERIFIED` or `ROLLBACK_PARTIAL` |

```yaml
  # PROPOSED — not yet registered. Sibling to rollback_state, which stays as-is.
  deployment_outcome:
    description: >-
      What a change run actually did, established from reconciled live state rather than from
      step exit codes. Distinct from rollback_state, which says what MAY be done about a failure.
      A run has exactly one outcome and it is asserted only after live-state reconciliation.
    consumers: [deploy workflows, build-and-push, promotion gate, incident response]
    rule: >-
      Every identifier reported alongside an outcome is labelled ATTEMPTED or NOW SERVING.
      NOW SERVING values are read back from live state. Echoing an input there is the defect
      this namespace exists to prevent.
    values:
      DEPLOY_ATTEMPTED:
        definition: >-
          The mutation was issued. Says nothing about whether it took effect or whether the
          result is healthy. This is the ceiling on what a run may claim before validation.
        note: The digest/revision/version associated with this value is ATTEMPTED, never NOW SERVING.
      DEPLOY_HEALTHY:
        definition: >-
          The mutation took effect AND functional validation passed against the live target.
          Not a promotion claim.
      PROMOTION_VERIFIED:
        definition: >-
          DEPLOY_HEALTHY plus evidence that the controls the target depends on are effective on
          what is now serving. The only state from which advancement to a higher tier is legal.
        rule: >-
          Deployment success is not trust progression. Never collapse these two. And: REBUILD,
          NOT RELABEL -- advancing a tier normally means reprovisioning through the higher tier's
          pattern, not mutating a label on the lower tier's deployment. A tier reached by editing
          a field was never verified against that tier's controls, and this is the mechanism that
          stops a long-lived experiment from quietly becoming production.
      ROLLBACK_REQUIRED:
        definition: >-
          Validation failed and the change must be reversed. A decision, not an outcome --
          it is superseded by one of the ROLLBACK_* outcomes below.
      ROLLBACK_TO_PRIOR:
        definition: >-
          Reversal performed against a captured prior state. Not yet proven; see ROLLBACK_VERIFIED.
      ROLLBACK_TO_EMPTY:
        definition: >-
          Reversal performed against a measured-empty prior state -- what this run created was
          removed and what it changed was restored, leaving unrelated resources alone.
        rule: >-
          A FIRST-CLASS RECOVERY PATH, NOT AN ERROR. A first deployment has a rollback point:
          the empty state. This is NOT teardown of the environment, and a workflow that skips
          reversal when no prior deployment exists has skipped recovery on exactly the population
          that orphans the most.
      ROLLBACK_PARTIAL:
        definition: >-
          Some of the change manifest was reversed and some was not, with each item's reason
          recorded. Deliberate retention for forensics is legitimate WHEN STATED.
        rule: >-
          ROLLBACK_PARTIAL IS NOT ROLLBACK_VERIFIED. It never rounds up. A consumer that treats
          partial as verified has broken the taxonomy even though every word it used was valid.
      ROLLBACK_VERIFIED:
        definition: >-
          Reversal complete AND live state reconciled against the pre-change snapshot. Already
          registered under rollback_state; reused here unchanged so the two namespaces agree.
      PARTIAL_APPLY:
        definition: >-
          Infrastructure was mutated and the run cannot account for the full extent. Objects may
          exist that no state record knows about.
        produced_by: >-
          Termination between the first mutation and the completion of the change manifest --
          cancellation, timeout, runner loss, or an adapter error mid-sequence.
        note: Recovery is out-of-band and manual by construction; the manifest that would scope it does not exist.
      STATUS_UNTRUSTED:
        definition: >-
          The run failed AFTER infrastructure mutation but BEFORE status reconciliation. What is
          serving is not known to this run. The correct report is the honest one: mutated,
          unreconciled, untrusted.
        rule: >-
          NOT "failed". Failure implies nothing changed. This state exists because something DID
          change and the run lost the ability to describe it.
      MANUAL_RECOVERY_REQUIRED:
        definition: >-
          No automated path can safely reach a known-good state. Carries an escalation contract:
          owner, required artefacts, and the actions an automated actor may take (gather evidence,
          draft a request) versus may not (mutate, retry, suppress, self-approve).
```

Supporting fields proposed on the same report, as a sibling namespace or as fields on the above:

```yaml
  # PROPOSED — the pre-mutation gate input.
  rollback_capability:
    description: >-
      Established BEFORE an irreversible mutation. The environment/enforcement axis consumes this
      to decide whether the operation may proceed. Governance belongs before the point of no
      return, not after.
    consumers: [deploy workflows, build-and-push, promotion gate]
    values:
      AVAILABLE:
        definition: Prior state captured and a reversal mechanism valid for the target's observed configuration exists.
      UNAVAILABLE:
        definition: >-
          No usable prior state, or no valid reversal mechanism for this change class on this
          target. At production tiers this blocks; at lower tiers it may be a recorded accepted risk.
      NO_PRIOR_STATE:
        definition: >-
          The target is measured empty. Reversal means removing what this run creates. This is a
          capability, not an absence of one.

  # PROPOSED — the three-value capture result. Never inferred from an empty string.
  PREVIOUS_STATE:
    EXISTING_DEPLOYMENT:
      definition: A prior deployment was read and every attribute in the mutation surface was captured.
    EMPTY:
      definition: Absence was MEASURED, not assumed. A read error is never this value.
    UNKNOWN:
      definition: >-
        The capture could not establish either of the above. Resolves toward reconcile-and-report,
        never toward a destructive branch.

  # PROPOSED — label on every identifier in an outcome report.
  serving_claim:
    ATTEMPTED:
      definition: What the run tried to deploy. May be echoed from inputs.
    NOW_SERVING:
      definition: >-
        Read back from live state during reconciliation. Echoing an input here is the defect.
        Where it cannot be established, the value is unknown -- never the attempted value.

  # PROPOSED — the provenance payload becomes a claim about reality, not intent.
  DEPLOY_PROVENANCE:
    stamped_when: After health AND live-state reconciliation both succeed. Never before.
    on_reversal: Restored to the prior value, or marked untrusted. Never left claiming a version that is not serving.
```

Three notes on the refinement, since the candidate list was offered to be improved rather than
adopted:

- `ROLLBACK_REQUIRED` is kept but demoted. It is a **decision**, not an outcome, and it is always
  superseded by one of the `ROLLBACK_*` outcomes. Leaving it as a terminal value is how a run ends
  by announcing an intention.
- `NO_PRIOR_STATE` moved out of the outcome namespace and into `rollback_capability`, where it
  belongs: it describes what reversal *can* do, established before the mutation, not what a run
  *did*.
- `PARTIAL_APPLY` was not in the candidate list and is the most important addition. It is the only
  value that describes mutation without accountability, and it is the state the current workflows
  are most likely to produce under cancellation or timeout.

---

## 5 · Gap list — ordered

Each item names the defect it closes. Ordered by *how badly the current behaviour misleads a
reader*, not by implementation cost.

### 1 · App Service `slot: ''` mutates production with no reversal path, and the reassuring message is gated on the wrong condition

`reusable-deploy-appservice.yml:40-44` documents `slot: ''` as "deploys straight to production."
On that path `:127-137` sets the container image directly on production, `:139-149` stamps
provenance on production, `:151-156` restarts production — and there is **no rollback step anywhere
in the file.** A failed health check at `:169-184` ends at `:215-217` with `exit 1` and production
left running the new digest.

Worse, `:194-197` — the step that prints *"no swap performed. Production is untouched."* — is
gated on `inputs.slot != ''`. **It does not print on the one path where production was touched.**
The workflow reassures precisely when it should not, and stays silent precisely when it should
warn.

Meanwhile `:199-213` prints the digest at `:209` next to `Health: failure` at `:211`, with no row
that could say what production is actually serving.

*Defect closed:* production mutation with no reversal path, plus a safety message whose condition
is inverted relative to the risk.

*The general defect class, worth naming because the kit will hit it again:* **a conditional step
whose condition excludes the case it exists to handle.** The prior control-plane design hit the
same shape from the other direction — a required check bound to a job that got skipped on one
execution path, so the gate became unsatisfiable exactly where it mattered. The rule both cases
produce: **a safety or gating step's identity and firing condition must be invariant across every
execution path the run can take.** If a path can skip the guard, the guard is decoration on the
paths that kept it.

*Minimum fix, in order:* (a) make the `slot: ''` path refuse to run at production-tier environments
until a reversal path exists; (b) correct the condition at `:195` so the unhealthy path always
reports, with different text for slot-staged versus direct-to-production; (c) add pre-change
capture and reversal for the direct path.

### 2 · Summaries print ATTEMPTED values beside failed validation with no NOW SERVING column

`reusable-deploy-appservice.yml:199-213` and `reusable-deploy-containerapp.yml:198-212`.
`if: always()`, digest and revision echoed from inputs and from a pre-reversal capture, health
outcome adjacent, nothing read back from live state. A reader concludes their change shipped when
it was rolled back.

*Defect closed:* the reporting defect that motivated this reconciliation. Same shape as the prior
design's status-that-claimed-success-after-no-execution, and the fix is the same two-part fix:
gate the claim on the evidence, and give the vocabulary somewhere to put failure.

*Minimum fix:* label every identifier ATTEMPTED or NOW SERVING; read NOW SERVING back from the
target during reconciliation; emit *unknown* rather than the attempted value when it cannot be read.

### 3 · Provenance is stamped before validation, and survives reversal

`reusable-deploy-appservice.yml:139-149` and `reusable-deploy-containerapp.yml:149-158` both run
before the health probe at `:169-184`. On Container Apps the reversal at `:186-196` restores a
revision but does not touch the app-level template mutation the provenance stamp performed — so
after a rollback the target advertises provenance for a digest that is not serving.

*Defect closed:* provenance meaning *what we attempted* instead of *this is running and it works*.

*Minimum fix:* move both stamps after health and reconciliation; on reversal, restore the prior
provenance value or mark it untrusted.

### 4 · A read failure is indistinguishable from an empty target

`reusable-deploy-containerapp.yml:130` swallows errors into an empty string, and `:187` treats
empty as *no rollback needed*. A throttled or permission-denied capture therefore produces a silent
skip of the entire recovery path.

*Defect closed:* an unknown resolving toward the branch that is easier to code — the exact failure
`ROLLBACK_CONTRACT.md:59-71` and `assurance-taxonomy.yaml:796-801` already prohibit in prose.

*Minimum fix:* three-value `PREVIOUS_STATE`; fail the capture loudly on read error; never infer
absence from a blank.

### 5 · Rollback to empty is not implemented on any path

`reusable-deploy-containerapp.yml:187` skips reversal entirely when there is no previous revision.
App Service has no reversal at all. So the first deployment — the population that orphans the most
on failure — has no recovery.

*Defect closed:* treating "no prior state" as "nothing to do" instead of as a rollback point.

*Minimum fix:* implement the empty path as a first-class outcome (`ROLLBACK_TO_EMPTY`): remove what
the change manifest says this run created, restore what it says this run changed, touch nothing
else, then reconcile and report.

### 6 · No pre-change snapshot and no change manifest

App Service captures nothing (`:127-137` is the first touch). Container Apps captures one string
(`:125-132`) and then infers its own new revision by newest-created-time (`:143-145`).

*Defect closed:* reversal that cannot distinguish *I made this* from *this was already here* —
`ROLLBACK_CONTRACT.md:32-37`, still unimplemented.

*Minimum fix:* capture the declared mutation surface before the first mutation; record created /
updated / deleted / redirected as the run proceeds; scope every reversal to that record.

### 7 · Reversal asserts success from command exit, and cannot express partial

`reusable-deploy-containerapp.yml:196` prints `Rolled back.` with no live-state read. The traffic
operation at `:193-195` is only valid in one revision mode, which the workflow never establishes —
so a reversal can half-succeed and still be reported as complete. Nothing in the file can express
`ROLLBACK_PARTIAL`.

*Defect closed:* `executed` claimed as `effective`, at the one moment where the difference decides
whether an incident is over.

*Minimum fix:* assert the reversal mechanism is valid for the observed configuration before using
it; read live state after reversal and compare against the snapshot; report what was reversed, what
was not, and why, with deliberate retention allowed only when stated.

### 8 · Partial application and post-mutation loss of visibility have no representation

Neither workflow, nor `assurance-taxonomy.yaml:781-811`, can say *mutated, extent unknown* or
*mutated, then lost the ability to describe it*. A run cancelled or timed out mid-sequence reports
as a plain job failure, which reads as *nothing changed*.

*Defect closed:* the failure class the prior design hit as orphaned resources that existed in the
cloud and not in state, recoverable only by manual out-of-band deletion — and the case this
reconciliation was asked to centre: a run that fails **after infrastructure mutation but before
status reconciliation**.

*Minimum fix:* add `PARTIAL_APPLY` and `STATUS_UNTRUSTED` to the vocabulary and emit them from the
workflows; `ROLLBACK_CONTRACT.md:212-232` already explains why bounding a mutating job with a
wall-clock timeout manufactures this state.

### 9 · `rollback_capability` is not established before irreversible mutation, and the enforcement axis is unwired

Neither deploy workflow takes `environment_tier` or `policy_mode`
(`assurance-taxonomy.yaml:873-937`), so ENVIRONMENT CONSEQUENCE and ENFORCEMENT from
`AXES_AND_PHASES.md` do not reach the deploy surface. The reversibility classification at
`ROLLBACK_CONTRACT.md:73-106` has no run-time consumer.

*Defect closed:* governance arriving after the point of no return, where it can only describe the
damage.

*Minimum fix:* adapters declare the change class; the run establishes `rollback_capability` before
the first irreversible operation; the environment/enforcement axis decides whether to proceed;
production tiers block on `unavailable`.

### 10 · Push is an irreversible mutation with no capability assessment, and the scanned artefact is not proven to be the pushed artefact

`reusable-build-docker.yml:154-162` pushes with no pre-mutation gate. The image scanned at
`:139-145` was produced by the build at `:131-137`; the image pushed at `:154-162` is produced by a
second build invocation. Build cache normally makes them identical. Nothing in the workflow proves
it, and the digest that flows downstream to both deploy workflows is the pushed one.

*Defect closed:* a gate that validated one artefact while a different artefact reached the registry
— and an irreversible mutation performed without asking whether it could be reversed.

*Minimum fix:* build once and push the same built artefact, or compare the two digests and fail on
divergence; establish `rollback_capability` before push; record the push in the change manifest so
downstream reversal can account for it.

> **Partly closed, `d49bd22`.** The artefact-identity half is fixed and structurally guarded: one
> build, the gate and the SBOM pinned to that image, `docker push` of those bytes, and a registry
> round trip that refuses to return a digest the registry does not confirm holds the scanned config.
> `tests/check_artifact_identity.py` refuses the shape's return. **Still open:** `rollback_capability`
> is not established before the push, and the push is not recorded in a change manifest — because
> there is no change manifest yet. See §7.
>
> **Closed 2026-10-15 (ledger L95, gap 10 second half).** The build job now does before the push
> what the deploy contract does before its first mutation, in the same vocabulary: it reads the
> tag's previous state from the registry (`EXISTING_DEPLOYMENT` with the prior manifest digest as
> the rollback point, `EMPTY` measured, or `UNKNOWN` — which refuses, because a read failure is
> not an empty target), decides `rollback_capability` (`AVAILABLE`, `NO_PRIOR_STATE`,
> `UNAVAILABLE` — refused before anything is written), and plans the change manifest; the push
> itself refuses without a planned manifest and marks it applied with the pushed digest. The
> record (`build-evidence/{snapshot,capability,manifest}.json`) is uploaded on every pushing
> path, and the posture record names `push-reversal` as a control. Proven by
> `tests/prove_push_capability.py` against a shimmed registry; the live registry is the hosted
> run that is owed.

### 11 · Promotion has no separate verified state

A successful deploy is terminal. There is no state meaning *the controls this target depends on are
effective on what is now serving*.

*Defect closed:* *it deployed, therefore it is approved* — the conflation the prior design named
explicitly, and the one that lets a technically-valid change advance past a tier it has not earned.

*Minimum fix:* add `PROMOTION_VERIFIED` as distinct from `DEPLOY_HEALTHY`; require evidence of
control effectiveness, not merely deployment completion, for advancement.

---

## 6 · What this document does not settle

- **Which adapter owns which mechanism.** The contract is backend-neutral by construction; the
  per-surface reversal mechanisms at `ROLLBACK_CONTRACT.md:141-149` still need implementations.
- **Whether the outcome report is a file, a job output, or a summary.** The obligations are
  defined; the transport is not. Whatever carries it becomes an interface the moment a second
  consumer reads it, and should be versioned accordingly.
- **The escalation contract's routing.** `MANUAL_RECOVERY_REQUIRED` needs an owner and a set of
  permitted automated actions before it can be emitted usefully. That is a policy question, not an
  architecture one.
- **Gate 1 of `ROLLBACK_CONTRACT.md`.** This document closes the reconciliation gate. The
  state-aware, change-scoped rollback gate stayed open until items 4 through 8 above were
  implemented and proven. *2026-10-16:* all five are implemented; 6 and 7 are proven live, 4, 5 and
  8 against a stub cloud only (status table at the top).

---

## 7 · `RELEASE` — the missing noun, and the four things it must not swallow

Everything in this kit keys on the **workflow run**. That is why *deployed successfully* can only
mean *the job went green*, why rollback can only mean *redeploy something older and hope*, and why
`determine-changes`, `render-version-metadata` and `docker-build-push` have sat unwired for five
weeks: they are inputs to a noun that does not exist.

`RELEASE` is that noun.

### 7.1 The correction that produced this section

The first framing of this said six recorded backlog items *were fragments of one capability* — D5
findings, D6 version discovery, D7 toolchain currency, `determine-changes`, the provenance
composites, the revalidation contract. That collapse is too aggressive and was challenged.

The challenge is correct. Several of those **intersect** the release graph rather than living
inside it, and the difference is not pedantic: an abstraction that absorbs its neighbours stops
being a correlation backbone and becomes the single blob every one of them has to be decoded out of
again. This kit has a whole document on why these keep happening; *a new abstraction quietly
annexing adjacent concepts* belongs in it.

**The release graph is a correlation backbone. It is not the canonical identity of every fact
that touches it.**

```
                         TOOLCHAIN ASSURANCE
                            D6 · D7 · rule-pack and advisory currency
                                     │  triggers revalidation OF releases;
                                     │  is never a property of one
                                     ▼
SOURCE STATE ──▶ BUILD ──▶ ARTIFACT ──▶ RELEASE ──▶ DEPLOYMENT STATE
     │             │          │            │              │
 source diff     SBOM      digest     change plan   observed mutations
     │             │          │            │              │
     └─────────────┴──────────┴───────┬────┴──────────────┘
                                      ▼
                               FINDINGS MODEL
                          (subject_type + subject_identity,
                           release is an OPTIONAL relationship)
                                      ▼
                          ASSURANCE / REVALIDATION
```

### 7.2 D5 — a finding's subject is not always a digest

Container and package findings attach cleanly to an artefact digest and its SBOM. Most findings do
not. A finding may belong to a source commit, an IaC plan, a deployed resource, an identity or RBAC
assignment, a runtime observation, a policy, or to a release as an aggregate. Forcing all of them
onto a digest would either fabricate a subject or drop the finding — and *dropping the ones that do
not fit the model* is the exact failure mode the three-answer rule exists to prevent.

```
FINDING
  subject_type        IMAGE | SOURCE | IAC_PLAN | RESOURCE | IDENTITY_ASSIGNMENT |
                      RUNTIME_OBSERVATION | POLICY | RELEASE
  subject_identity    sha256:… | git:<commit> | <plan-hash> | <cloud-resource-id> | …
  observed_in_release_id?    OPTIONAL relationship, never the identity
```

`observed_in_release_id` is how the dashboard correlates. It is not how the finding is named. A
finding whose subject is a running resource outlives every release that touched it, and a model
that names it by release loses it at the next deploy.

### 7.3 `determine-changes` is one of four change artefacts, not the change manifest

A composite that determines changed source paths cannot be the change manifest. A git diff cannot
tell you that a deployment created a revision, shifted three traffic weights, generated an identity
assignment and partially applied a schema migration. Four distinct artefacts:

| artefact | question | producer |
|---|---|---|
| `SOURCE_DELTA` | what changed in code and config | `determine-changes` |
| `PLANNED_MUTATION_SET` | what the deployment **intends** to alter | plan/what-if, pre-change |
| `OBSERVED_MUTATION_SET` | what **actually** changed | post-change reconciliation |
| `REVERSAL_MANIFEST` | how each observed mutation can be compensated | derived, per mutation |

They diverge, and every divergence is information. `PLANNED` minus `OBSERVED` is work that did not
happen; `OBSERVED` minus `PLANNED` is work nobody asked for — arguably the more alarming of the two,
and currently unrepresentable. Multi-release rollback reads `OBSERVED` and `REVERSAL`, never
`SOURCE_DELTA`.

### 7.4 D7 stays orthogonal

*Is our Trivy current and supported* is a property of the **assurance machinery**, not of a release.
D7 triggers revalidation; a release's SBOM is then one of its consumer targets. Putting currency
inside the release object would give every release its own opinion about the toolchain, and there
is only one toolchain.

### 7.5 The release object — references evidence, does not absorb it

```
release_id · parent_release_id
source_identity · artifact_identity · sbom_identity · build_provenance
environment · promotion_tier
planned_change_manifest · observed_change_manifest
technical_provenance · business_acceptance
deployment_state · functional_state · traffic_state
rollback_target · rollback_capability · rollback_state
created_at · promoted_at · withdrawn_at
```

Every `*_identity` and `*_manifest` field is a **reference**. The moment the release row starts
carrying finding bodies, SBOM contents or scan output, it is a blob, and the next question anyone
asks of it requires parsing rather than joining.

### 7.6 Transitions carry reasons, not just endpoints

`R47 → R46` is not a fact anyone can act on. Two releases can produce that identical arrow for
opposite reasons, and once there is a dashboard the difference is the whole point.

```
transition:
  from · to · action            ROLLBACK | PROMOTE | WITHDRAW | RECOVER
  reason_class                  HEALTH_FAILURE | VALIDATION_FAILURE | BUSINESS_DECISION |
                                SECURITY_FINDING | DEPENDENCY_FAILURE | OPERATOR_DIRECTED
  initiated_by · evidence · started_at · completed_at
```

*R47 was rolled back because health failed* and *R47 passed everything and was withdrawn by the
business* are different histories. Only the second one leaves `technical_provenance: VERIFIED`
standing, which is the point of §7.7.

### 7.7 Production provenance is a conjunction, and withdrawal does not revoke it

`technical_provenance = VERIFIED` requires **all** of:

```
exact artefact identity established        ← the only one of these currently implemented (d49bd22)
expected artefact observed running
intended traffic observed
functional tests passed
operational validation passed
dependencies verified
required reviews and gates passed
state reconciliation complete
```

`business_acceptance = WITHDRAWN` recorded later **does not alter that historical fact**. The
release did work, under traffic, verified. The business chose otherwise. A model that rewrites the
first as failure because of the second is destroying the evidence — and this kit's rule is that a
rollback must never make the record of what happened less true.

### 7.8 The acceptance matrix the sandbox exists to run

The personal Azure subscription is not for proving *rollback works*. It is the **release-state
acceptance environment**, and one happy rollback demo proves nothing:

```
A  healthy deployment
B  partial mutation / execution failure
C  complete deployment, unhealthy workload
D  mutation occurred, reconciliation lost            -> STATUS_UNTRUSTED
E  technically healthy release withdrawn by the business
```

crossed with `single-release` / `multi-release` recovery, and with `prior release` /
`ROLLBACK_TO_EMPTY` as the target.

**And at least one deliberately irreversible or compensate-only mutation.** A matrix of perfectly
reversible toy resources never exercises the sentence the whole design exists to be able to say:

> *I restored everything I could safely restore. This mutation remains and requires explicit
> handling.*

That sentence is more valuable than a green rollback, and it is the one that cannot be faked.

### 7.9 Ordering

Nothing above may claim `artifact_digest = D` until D has been proven end to end —
`build → digest → scan → SBOM → push → retrieve → assert`. That chain closed in `d49bd22` for the
build path. Starting the release abstraction on an unproven artefact identity would be a
particularly poor joke in a kit built to prevent exactly that.

---

## 8 · Reversal preconditions — the change manifest is necessary and is not sufficient

§3 and §7.3 establish that reversal is scoped to the change manifest: reverse only the mutations
attributable to the release being reversed, restore its measured pre-state, disturb nothing else.
That is correct. It is also incomplete, and the gap is the one that turns a recovery into an
incident.

The sentence that produced this section:

> *"You can't assume that the subscription remains empty and that you can have that destroy all
> without possibly destroying the new state for something that got onboarded in between."*

Concretely. Release R1 creates resource X. Between R1's deployment and R1's reversal, another
onboarding process modifies X, or takes a dependency on it. R1's manifest still says *I created X*,
and that sentence is still **true**. It is no longer sufficient **authority** to delete X.

**A change manifest is a record of the past. Reversal acts on the present.** Every entry in a
`REVERSAL_MANIFEST` is therefore a *proposal*, not an instruction, and each proposal is evaluated
against live state at the moment of reversal. The manifest says what may be in scope. Live state
decides what may be touched.

This is the per-object form of a rule the contract already holds at run level.
`ROLLBACK_CONTRACT.md:59-71` and §3.2 both say an unknown previous state must not resolve toward
destruction. Both are stated about **the run**. A run can have a perfectly good `PREVIOUS_STATE`
and still meet, inside its own manifest, an object it cannot vouch for — and nothing in the
contract currently stops that object being deleted.

### 8.1 The preconditions

Six questions, all answered by **reading live state**, none answerable from the manifest.

| | Precondition | Established by reading | Where failure to read resolves |
|---|---|---|---|
| **P1** | Does the object still carry this release's ownership identity? | The `RELEASE_OWNERSHIP_STAMP` on the live object | `OWNERSHIP_UNESTABLISHED` |
| **P2** | Is its current version the post-state this release recorded? | The object's version handle — ETag, generation, resource version, revision name — compared against the `OBSERVED_MUTATION_SET` | `PRECONDITION_UNESTABLISHED` |
| **P3** | Has another release modified it since? | The stamp's release id against this release, and the release graph | `PRECONDITION_UNESTABLISHED` |
| **P4** | Has an external actor modified it since? | P2 differs **and** no release in the graph claims the difference | `PRECONDITION_UNESTABLISHED` |
| **P5** | Does anything introduced later depend on it? | Dependency edges recorded by later releases, plus a live dependency read where the adapter supports one | `PRECONDITION_UNESTABLISHED` |
| **P6** | Is this reversal in correct reverse-ancestry order? | The release graph: no un-reversed descendant of this release | `REVERSE_ORDER_VIOLATED` if a descendant stands; `PRECONDITION_UNESTABLISHED` if the graph could not be traversed |

Three properties of that table are load-bearing:

- **P4 is a difference, not an observation.** No adapter reports "an external actor changed this."
  External modification is what remains after every release in the graph has been asked and none
  of them claims the change. That makes P4 dependent on P3 having *succeeded*, not merely on P3
  having returned nothing.
- **P6 is about the graph, not the object.** A descendant release that never touched this object
  can still depend on the object existing. A precondition set that only asks per-object drift
  questions misses that entirely, which is why `REVERSE_ORDER_VIOLATED` is a separate conflict
  from `SUPERSEDED_BY_LATER_RELEASE`.
- **Every failure-to-read column resolves somewhere non-destructive.** There is no cell in that
  table whose unknown lands on removal. That is the whole design.

#### The unit of conflict is the MUTATION, not the object

P2 and P4 as written ask whether **the object** changed. For a composite resource that is far too
coarse, and it produces the wrong answer in the most ordinary case there is.

A Front Door profile, a firewall policy, a route table, an NSG, an application's settings
collection, a DNS zone — these are single objects holding **many independently owned entries**. A
second actor adding *their* rule changes the object's ETag while leaving *this release's* rule
untouched. Refusing on that basis means:

> *something else touched it, so do not even look*

which withholds a reversal that was perfectly safe, and does so on the majority of shared
surfaces. **A withheld-but-safe reversal is not the harmless direction.** It leaves this release's
mutation in production permanently, and it trains operators to override the check — which is how
the check stops existing.

So the object's version handle is a **trigger to look closer**, never a verdict:

```
object version differs
        │
        ├─ is THIS RELEASE'S ENTRY still byte-identical to what it recorded?
        │       no  → REVERSAL_REFUSED_CONFLICT. Somebody edited our change.
        │       yes ↓
        ├─ does removing THIS ENTRY alter anything another actor owns?
        │       yes → REVERSAL_WITHHELD_DEPENDENCY, naming what it would alter
        │       no  ↓
        └─ can the entry be addressed and removed INDEPENDENTLY on this surface?
                no  → REVERSAL_WITHHELD_UNTRUSTED — granularity unestablished
                yes → REVERSE IT
```

**The second question is the subtle one, and it is where ordering lives.** Rule sets are usually
*ordered* — priority, precedence, longest-prefix, first-match. Removing our rule can change the
effective behaviour of rules we never touched, without modifying a single byte of them. On an
ordered surface, "I only removed my own entry" is not sufficient; the question is whether the
**evaluation outcome** for everyone else's entries is unchanged. An adapter that cannot answer
that for its surface must resolve to `REVERSAL_WITHHELD_UNTRUSTED` rather than assume
independence.

`REVERSAL_ENTRY_SCOPED` carries this outcome: the parent object changed, this release's entry did
not, removal is side-effect-free, and the entry alone is reversed. It is a narrowing of
`REVERSAL_REFUSED_CONFLICT`, which now means *our own change was altered* rather than *the
neighbourhood moved*.

### 8.2 The dispositions

Each manifest entry resolves to exactly one `reversal_disposition`, derived from the preconditions
above. **Exactly one of the six removes anything.**

| Situation established from live state | Disposition | Recovery behaviour | Run-level effect |
|---|---|---|---|
| Created by this release · unchanged since · `OWNED_EXCLUSIVE` | `REVERSAL_REMOVE` | Remove it | Contributes to a complete reversal |
| Modified by this release · current state still equals the recorded post-state | `REVERSAL_RESTORE_PRIOR` | Restore the recorded pre-state | Contributes to a complete reversal |
| `SUPERSEDED_BY_LATER_RELEASE` — a later release wrote the current state | `REVERSAL_DEFERRED_TO_SUCCESSOR` | Reverse the later releases first; this entry is not actioned now | Reversal is **ordered**, not refused |
| `REVERSE_ORDER_VIOLATED` — a descendant release still stands | `REVERSAL_DEFERRED_TO_SUCCESSOR` | Reverse descendants first, whether or not they touched this object | Reversal is **ordered**, not refused |
| `MODIFIED_BY_EXTERNAL_ACTOR` | `REVERSAL_REFUSED_CONFLICT` | Stop automatic reversal for this object; report a conflict with an escalation contract | `ROLLBACK_PARTIAL` at minimum |
| `OWNED_BY_ANOTHER_RELEASE` — the stamp names someone else | `REVERSAL_REFUSED_CONFLICT` | Stop; the manifest and live state disagree about who made this | `ROLLBACK_PARTIAL` at minimum |
| `DEPENDENT_INTRODUCED_LATER`, or the object is now `OWNED_SHARED` | `REVERSAL_WITHHELD_DEPENDENCY` | Preserve it; **name the dependent or co-owner that preserved it** | `ROLLBACK_PARTIAL` |
| `OWNERSHIP_UNESTABLISHED` or `PRECONDITION_UNESTABLISHED` | `REVERSAL_WITHHELD_UNTRUSTED` | **Nothing destructive.** Reconcile what can be observed and report | The run reports the proposed `STATUS_UNTRUSTED` (§4) |

The rule the table exists to enforce, stated once so it cannot be inferred wrongly:

> **The unknown branch and the destructive branch are not the same branch.**
> `REVERSAL_REMOVE` is reachable only from `OWNED_EXCLUSIVE` with every precondition **positively
> established** — not from "no conflict was found," which is also what a failed conflict query
> returns.

Two consequences that contradict what this document said earlier, and are corrections rather than
additions:

- **§3.2's empty-previous-state row was too permissive.** It reads *"remove what this run created
  and restore what it changed"* with no precondition. A measured-empty target at deployment time
  says nothing about the target at *reversal* time, and `ROLLBACK_TO_EMPTY` is exactly the path
  the onboarded-in-between case attacks: the run believes it owns everything in scope because
  scope was empty when it started. Every entry on that path runs the same preconditions as every
  other entry. §5 gap 5 carries the same wording and the same correction applies to it.
- **§3.3's three legitimate reasons for non-reversal are incomplete.** It admits *mechanism not
  valid*, *outside the manifest*, and *retained for forensics*. It has no reason for *a later
  release owns this*, *an external actor changed this*, *a dependent exists*, or *ownership could
  not be established* — so an implementation following §3.3 literally has nowhere to record four
  of the six dispositions above, and the likeliest place they end up is nowhere.

### 8.3 The ownership mechanism

Ownership has to be a property **of the object**, readable at reversal time by a process that may
never have seen the deploying run.

```
RELEASE_OWNERSHIP_STAMP        written into the adapter's native metadata channel
  release_id                   which release claims this object
  parent_release_id            where it sits in the graph, so ancestry is readable from the object
  run_id                       which execution wrote it
  post_state_version           the version handle this run left behind (ETag / generation / revision)
  stamped_at                   when
```

Four rules, each naming the mistake it prevents:

1. **Written with the mutation, not after it.** A stamp applied in a later step is absent from
   every object a cancelled run created before it died — and that population is precisely the one
   a reversal has to reason about. This is the same ordering argument as provenance-after-health
   in §5 gap 3, pointing the opposite way: provenance is a claim about reality and must be late;
   ownership is a fact about authorship and must be simultaneous.
2. **On the object, not only in the run record.** The run record is the thing a cancelled run does
   not finish. An ownership model that lives only in the manifest fails in exactly the case that
   produced `PARTIAL_APPLY`.
3. **`post_state_version` is part of the stamp, not a separate artefact.** P2 asks whether the
   object is still as this release left it. Keeping the answer's two halves — who left it, and in
   what state — in one place means they cannot be read out of sync, and a resource that has been
   re-created carries neither.
4. **The stamp is evidence, not proof.** It is a claim the run makes about itself, in a channel an
   external actor can also write. It establishes ownership against *accident*; it does not
   establish ownership against *intent*. Nothing downstream may treat a stamp as an authorisation
   to delete without P2 through P6 also holding.

**Where the resource class has no metadata channel, ownership is `OWNERSHIP_UNESTABLISHED` by
construction, and removal is permanently unavailable for that class.** That is not a reversal-time
discovery. It is a `rollback_capability` fact, and §3.5 requires it to be established *before* the
mutation — a resource whose ownership can never be read is a resource whose creation is, for
recovery purposes, irreversible. Saying so before the point of no return is a gate. Discovering it
during the reversal is a report.

### 8.3a Shared infrastructure — the normal case, and the authority it does not confer

Earlier drafts of this document, and the advice built on them, treated shared resources as a
compromise: what you accept when budget will not stretch to separation. **That is backwards.** In
any real estate the shared layer is the architecture —

| shared | why it is shared, permanently |
|---|---|
| hub VNet, firewall, ExpressRoute | nobody buys one firewall per application |
| private DNS zones | one authoritative zone per namespace, by definition |
| container registry | the **control plane** is shared. Individual repositories and artefacts are not — see the ABAC note below |
| Log Analytics workspace | cross-workload correlation is the point of it |
| management groups, policy | inheritance is the mechanism |
| the tenant | there is one |

The rule this produces:

> **SHARED INFRASTRUCTURE MAY EXIST ACROSS WORKLOADS. SHARED WRITE AUTHORITY MUST NOT
> AUTOMATICALLY EXIST ACROSS WORKLOAD DEPLOYMENT IDENTITIES.**

Existence and authority are different questions, and collapsing them is how an application
rollback ends up entitled to delete a workspace it once wrote a diagnostic setting to.

`OWNED_SHARED` was too coarse to carry this: it describes two RELEASES claiming one object, and
says nothing about a release's relationship to platform infrastructure it never created. Four
values now do:

| classification | what the release did | reversal |
|---|---|---|
| `OWNED_BINDING` | created a binding *on* something it does not own | remove the **binding**, never the host |
| `SHARED_CONFIGURATION_ENTRY` | added an entry to a shared surface | revert **that entry** — conditionally, see below |
| `REFERENCE_ONLY` | consumed it — joined, emitted, pulled | **never reversible**; consumption left no trace |
| `PLATFORM_OWNED_SHARED` | nothing; the platform owns it | **cannot act**, whatever the manifest says |

**A classification is not an outcome.** An earlier draft of this section said in one breath that
reversal "removes that entry" and that the disposition is `REVERSAL_WITHHELD_DEPENDENCY`. Those are
different outcomes, and writing both as if they were one is exactly the collapse §8.1 exists to
prevent: the classification says what KIND of thing this is; the live-state preconditions decide
what HAPPENS to it. Both are required, and the second runs at reversal time.

For a release-owned entry inside a shared service — a firewall rule, a DNS record, a diagnostic
setting, a registry repository path, a private-endpoint binding:

| live condition at reversal time | outcome |
|---|---|
| entry still equals this release's recorded post-state, no later dependent | `REVERSAL_RESTORE_PRIOR` — reverse the entry |
| a LATER RELEASE modified the entry | `REVERSAL_DEFERRED_TO_SUCCESSOR` — reverse descendants first |
| the PARENT changed but **this release's entry did not**, and removal is side-effect-free | `REVERSAL_ENTRY_SCOPED` — reverse the entry |
| an external actor altered **this release's own entry** | `REVERSAL_REFUSED_CONFLICT` — withhold, report |
| something introduced later depends on it | `REVERSAL_WITHHELD_DEPENDENCY` — preserve, report partial |
| ownership or current state unestablished | `REVERSAL_WITHHELD_UNTRUSTED` — preserve |
| the shared resource ITSELF | never removable by an application rollback, in any condition |

The parent — firewall, zone, workspace, registry — stays platform-owned throughout. **A
release-owned entry inside a shared service is reversible; the service is not.**

That last row is the important one. **The manifest records what a run did; the classification
records what a run was entitled to do, and the second one wins.** A run that exceeded its
authority does not acquire the right to reverse the excess.

**Identity follows the same split.** An application deployment identity gets Contributor on its
own workload resource group and *consumption* rights on the shared layer — repository-scoped
registry write for its own image path, permission to emit telemetry, permission to join an
approved subnet. It does not get Contributor over the shared resource group. Changes to shared
infrastructure belong to a platform identity with its own environments and its own release
history, so that shared mutation is a governed change rather than a side effect of an application
deploy.

*(Registry note: repository-scoped write for an Entra principal is achievable through ABAC
conditions on repository name — it does not require stored-credential tokens. An earlier draft
said otherwise and was wrong. Enabling ABAC on a registry that is already serving traffic
supersedes the legacy registry-wide role assignments, so the equivalent repository roles have to
exist before the switch, not after.)*

**What none of this covers.** These values describe *who owns an object*. They say nothing about
**the regime an object sits under**, and that is a set of axes rather than one field — collapsing
them into a single "placement" flag would repeat the mistake `OWNED_SHARED` just made:

```
network_zone            data_classification      regulatory_scope[]
residency_requirement   egress_policy            identity_trust_zone
recovery_tier
```

A workload is several of these at once — regulated data, an inspected-allowlist egress path, a
life-critical recovery tier — and they are independently true. *(Written as prose, not as state
values: these axes are PROPOSED and undecided, and registering example values would assert the
model had been adopted. The taxonomy gate caught the first draft doing exactly that, which is
remedy 4 working.)*

**And shared does not mean uncontrolled.** A regulated workload and an ordinary one sharing an
egress platform is not automatically wrong; whether it is wrong depends on segmentation,
inspection, policy enforcement, logging, rule ownership and contractual constraint. An earlier
draft of this paragraph implied otherwise, which would have argued for duplicating platform
infrastructure to solve a problem that inspection and segmentation already solve.

What remains true: two workloads can be perfectly RBAC-isolated and still be wrongly placed. RBAC
separation must not be reported as though it answered placement. None of these axes exist in this
kit yet.

### 8.4 Conflict states and what they owe the reader

`REVERSAL_REFUSED_CONFLICT` is a blocking, **not autonomously resolvable** state in the §2.5 band
model. It therefore carries the escalation contract of §3.4 — `resolution_owner`,
`request_channel`, `request_type`, `required_artefacts`, `service_level`, `permitted_agent_action`
— and `required_artefacts` for a reversal conflict is specific:

- the manifest entry, with its recorded pre-state and post-state,
- the object's live state as read at reversal time,
- the version handles either side of the difference,
- the ownership stamp as found, including its absence,
- which precondition failed, and whether it failed as *established-false* or as *unevaluable*.

That last distinction decides whether a human is resolving a conflict or restoring an ability to
observe, and they are different jobs.

`permitted_agent_action` for a reversal conflict, stated positively and negatively because the
default behaviour of an unconstrained actor facing a blocked reversal is to try something:

| MAY | MAY NOT |
|---|---|
| Re-read live state and re-evaluate preconditions | Remove the object |
| Reverse a *different* entry whose preconditions hold | Force, retry, or widen the reversal |
| Reverse descendant releases in order, where those preconditions hold | Overwrite the current state with the recorded pre-state |
| Draft the escalation and name the conflicting actor | Re-stamp the object with this release's ownership |
| Propose compensating changes for a human to approve | Treat a re-stamp as having resolved the conflict |

The re-stamp prohibition is the one worth spelling out. An automated actor that can write ownership
metadata can make any object look `OWNED_EXCLUSIVE`. That is not establishing ownership; it is
manufacturing the precondition for deleting something it does not own.

### 8.5 What the outcome report does when a reversal is refused

A reversal report is **per object** because a disposition is per object. §3.3's shape holds and
gains a column.

| Column | Content |
|---|---|
| object | The manifest entry's identity |
| disposition | One of the six `reversal_disposition` values |
| precondition that decided it | Which of P1–P6, and whether it was established-false or unevaluable |
| observed state | Read back from live state **after** the action — a NOW SERVING claim |
| residual risk | What the object now holds that matches neither the pre-state nor the intended change |

Rules on top of that table:

- **Refusal does not make the run "failed."** Failure implies nothing changed. A reversal that
  removed four objects, deferred one and refused one is `ROLLBACK_PARTIAL` with a named residue,
  and `ROLLBACK_PARTIAL` never rounds up to `ROLLBACK_VERIFIED`.
- **A withheld object omitted from the report is indistinguishable from a removed one.** Silence
  about an object is the specific failure §3.3 already names as unstated retention, and it is more
  dangerous here because the reader has been told a rollback occurred.
- **"Restored" is a NOW SERVING claim.** It is read back from live state, never inferred from the
  restore command's exit status. §3.4's labelling rule applies inside the reversal report, not
  only in the deployment summary.
- **A run in which every entry resolved to `REVERSAL_WITHHELD_UNTRUSTED` has performed no
  reversal at all.** It must not report as a reversal that found nothing to do. It reports the
  proposed `STATUS_UNTRUSTED` and says which preconditions it could not evaluate — because
  "nothing needed reversing" and "I could not tell what needed reversing" are the two states this
  entire document exists to keep apart.

### 8.6 What is structurally checked, and what is not

`tests/check_reversal_preconditions.py` refuses a reversal implementation whose **shape** permits a
deletion without ownership having been established. It reads workflow structure and nothing else.

It can establish that a destructive step is preceded by an ownership read, that the read is not
error-suppressed, that the object's version is read, and that the destructive step is guarded by a
disposition rather than by `always()`. It **cannot** establish that the ownership comparison is
correct, that the stamp names the right release, or that any of P1–P6 is evaluated soundly. Those
need a real target and a real second actor modifying state between deploy and reversal, which is
acceptance-matrix work (§7.8), not static work.

A structural check that claimed otherwise would be the same overstatement it exists to catch.

### 8.7 What this section does not settle

- **How dependency edges are recorded.** P5 assumes later releases record what they depend on.
  Nothing in this kit does that yet, and a live dependency read is adapter-specific and often
  impossible. Until it exists, P5 is unevaluable for most resource classes — which by §8.2 means
  `REVERSAL_WITHHELD_UNTRUSTED`, not `REVERSAL_REMOVE`. That is the correct failure direction and
  it is also an expensive one: a kit that cannot answer P5 cannot automatically remove anything.
  Saying so is the point.
- **Whether the stamp survives adapter-specific operations.** Tag inheritance, policy-driven tag
  stripping, resource re-creation by an unrelated process and metadata size limits all break it in
  ways that differ per surface. Each adapter owes an answer; none has been written.
- **Multi-release ordering mechanics.** §8.2 says descendants are reversed first. The ordering
  algorithm, and what happens when two descendants conflict with each other, is release-graph work
  that does not exist yet.
- **What is proven (2026-10-16).** Reversals have been executed against live targets, with
  preconditions: a second actor's newer revision made the Container Apps reversal defer to it
  (P6, `REVERSAL_DEFERRED_TO_SUCCESSOR`, run 38855929525) and a second actor's App Service change
  was refused (P4, `REVERSAL_REFUSED_CONFLICT`, run 38886279650), each reported `ROLLBACK_PARTIAL`.
  The deferrals for `deploy-appservice` and `deploy-containerapp` closed on exactly this section's
  acceptance requirements and both capabilities are `observed` in `tests/reconcile_validation.py`.
  Still not proven: P3 and P5 (App Service declares P3, P5 and P6 empty on the basis that the
  concurrency group serialises, which holds only within one repository — ledger L98, B-12), and any
  dependency-edge or release-graph case.
