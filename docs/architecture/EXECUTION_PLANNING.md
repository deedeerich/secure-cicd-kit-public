# Execution planning — the job set, depth and ordering of a run, as data, before anything runs

**Stage 5 of the single pipeline. The one stage that had neither a design nor a build. This is
the design. It is a proposal, and it is marked as one.**

```
Phase: design proposal — DESIGNED, owner review. Nothing in this document is enforced.
Truth State: modelled 2026-10-14 from the depth model in AXES_AND_PHASES.md, the grouped
             topology in JOB_TOPOLOGY_AND_BUDGET.md §4, stage 5 of SINGLE_PIPELINE_TARGET.md
             (§4.4: "the one with neither"), the ordering contract in
             PIPELINE_ORDERING_AND_SCAN_VALIDITY.md §1, scanner-registry.yaml as the job
             denominator, and the `resolve` job as it stands in reusable-security.yml at the
             commit this file lands in
Audience: the owner, deciding whether this is the plan object the pipeline should emit; whoever
             later wires scanners and the gate to read it
Decision Supported: what a plan is, where it is computed, what it contains, what it must refuse,
             and what enforcing it would change. Not whether to enforce it.
Deferred Depth: the rung ladder (ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md) · the packing
             decision (JOB_TOPOLOGY §9.4, OD-3) · the registration file (stage 1, ABSENT)
```

> **What is built, exactly, and no more.** The `resolve` job emits an **advisory** plan object
> in the shape §3 describes, as a job output nothing reads and nothing enforces. That is a
> prototype of the data, kept honest by tests/test_resolve.py, so the owner reviews a shape that
> exists rather than a shape described. The stage itself is DESIGNED, and the register in
> tests/check_stage_phase.py says so. **Registering a term is not implementing it, and emitting a
> plan is not executing one.**
>
> **No vocabulary is coined here.** Every enforcement word below is registered in
> `assurance-taxonomy.yaml`. Where the design needs a word the registry lacks, it is written in
> lower case so `scripts/reconcile_taxonomy.py` reads a proposal as a proposal.

---

## 0 · What this settles, and what it deliberately does not

**Settled here:** that a plan is one object, computed once, at the position between discovery
and the scanners, from inputs that all exist before any scanner starts; what the object contains
and in what order its fields are derived; how the two existing models it joins — depth by trigger
context, jobs by grouped topology — map onto one record; the four things a plan must refuse; and
the exact change that would turn the advisory object into the thing the scanners and the gate
read.

**Deliberately not settled:** whether to enforce it (§8, owner's call); the depth of a
`workflow_dispatch` run, which the depth model leaves open (§8); whether the target topology is
JOB_TOPOLOGY's depth 3 or depth 4 (OD-3), which the plan carries as a *label* so that it is
right under either answer; and every number.

**Out of scope, because other documents own them:** what blocks (the rung); what a scanner
establishes (validity, §4 of the ordering document); who approves (team pattern).

---

## 1 · Why a plan, and why here

### 1.1 The gap

`SINGLE_PIPELINE_TARGET.md` §4.4: *"Stage 5, execution planning, has no design and no build. It
is also the stage that makes stages 2, 3 and 4 useful: version discovery and capability
selection produce answers, and without a planning stage there is nowhere to put them."*

That is now literally the situation in the tree. `resolve` establishes, per class and root, the
target version (R2) and each scanner's capability against it (R3), and declares every
`VERSION_UNSUPPORTED` as a `COVERAGE_GAP` before the scan. Nothing consumes those answers. The
scanner jobs still start from `needs.discover.outputs.*` alone, which is R1. The answers exist
and the position that would act on them does not — which is the same shape §1.6 of the ordering
document recorded for R2 and R3 themselves before the `resolve` job existed.

### 1.2 What a plan is

A plan is the **concrete job set, depth and ordering for this run, emitted as data a human can
read before anything runs.** Four properties make it a plan and not a log:

| property | why it is load-bearing |
|---|---|
| **computed before any scanner starts** | after the fact it is a record; the point is that a reader can see what *will* run and why, and that a wrong plan is wrong *loudly* and *early* |
| **one object** | the depth model and the topology are two documents today; a job set that lives in sixteen `if:` expressions is not readable by anyone, including the gate |
| **derived, never supplied** | AXES_AND_PHASES: a question discovery can answer is derived, not an input. A plan a caller could pass would be the orchestrator pattern SPT §3.2 refuses, one layer down |
| **carries its reasons** | every `skip` names the registered state that caused it, because `NOT_APPLICABLE`, `EXCLUDED_BY_SELECTOR`, `DISABLED` and `DEPTH_REDUCED` render identically in the Actions UI and mean opposite things about coverage |

### 1.3 Where it is computed

In `resolve`, last, after R2 and R3. Not a job of its own: SPT §5.1 already decided that stages
1-5 are metadata work in one job, and a plan is a pure function of values that job already holds.
Not in `discover`: discovery decides applicability and must not know the trigger context
(AXES_AND_PHASES, "discovery cannot know the trigger context or the target environment"). The
plan is the first place those two meet, and it must be *after* the version and capability
answers so that a job's row can carry them.

```
discover   R1  applicability           -> D_<class>, coverage_gaps
resolve    R2  version per class/root  -> versions
           R3  capability per tool     -> capability, version_gaps
           R4  THE PLAN                -> plan              <- this document
scan-*     R5  execution               reads the plan (future), today reads R1 only
```

---

## 2 · The inputs, and the order they are joined

Every input exists before the first scanner starts. That is the whole constraint, and it is
what makes the position possible.

| # | input | from | axis (AXES_AND_PHASES) |
|---|---|---|---|
| 1 | the registered job set, with each job's applicability rule | `scanner-registry.yaml` `jobs[].applies` | — (the denominator) |
| 2 | applicability per class | `needs.discover.outputs.<class>`: `true`, `false`, or empty when discovery did not say | APPLICABILITY |
| 3 | the survey state | `needs.discover.outputs.state` | APPLICABILITY |
| 4 | caller toggles that gate a job | `inputs.image_ref`, `inputs.enable_sbom`, `inputs.enable_malicious_pkg_scan` | APPLICABILITY, caller-declared |
| 5 | version and capability answers | `resolve` R2/R3 outputs | APPLICABILITY, version half |
| 6 | the trigger context | `github.event_name` | DEPTH |
| 7 | platform values | `needs.discover.outputs.code_scanning` and the others | platform applicability |

**Not an input, deliberately:** the environment tier, the team pattern, and the rung. Those are
ENFORCEMENT, decided at R7, and a plan that carried them would be two decisions in one knob.
The plan says what runs and how hard; it never says what blocks.

**The join order is the derivation order and it is fixed:**

1. **depth** from the trigger context (input 6), by the depth table in §3.2. Decided first
   because it is independent of everything in the repository.
2. **per job, the decision** from the applicability rule (input 1) evaluated against inputs 2-4,
   by the rules in §3.3.
3. **per job, the capability states** from input 5 for the class the rule names, attached to
   the row — never used to change the decision (§4, refusal 1).
4. **the declared gaps**, copied from discovery's `coverage_gaps` and resolve's `version_gaps`,
   so the plan is the one place both kinds of gap appear beside the jobs that will run.

---

## 3 · The plan object

### 3.1 Shape

One JSON object, a job output of `resolve`, single line. Field names are lower case because
they are data, not states; the *values* of `decision`, `depth` and `capability_states` are
registered vocabulary.

```
plan
  advisory          true                     until the owner decides otherwise (§8)
  enforced_by       "nothing"                the literal word, so no reader infers more
  context
    event           the trigger event name
    depth           pr | merge | nightly | release | revalidate | null
    depth_basis     how depth was derived, or why it could not be
  survey            discovery's state: COMPLETE | DISCOVERY_PARTIAL | DISCOVERY_UNAVAILABLE
  jobs[]            one row per registered job of class scanner
    job             the job name, exactly as the registry spells it
    group           the JOB_TOPOLOGY §4 group this job belongs to (§3.4)
    applies         the registry rule, verbatim: always | discover.<class> | input.<name> | ...
    decision        run | skip | forced
    reason          the registered state behind the decision (§3.3)
    capability_states   the R3 answers for this job's class, as a list of states, or []
  depth_settings    the row of the depth table for this depth (§3.2), or null
  declared_gaps
    coverage_gaps   discovery's class list
    version_gaps    resolve's class@root:job/tool list
```

### 3.2 Depth, from the trigger context

Verbatim from AXES_AND_PHASES, carried as data so the two cannot drift silently:

| event | depth | CodeQL suite | secrets scope | paths | posture |
|---|---|---|---|---|---|
| `pull_request` | `pr` | `default` | diff only | changed paths | advisory on new categories |
| `push` to the protected branch | `merge` | `security-extended` | full tree | whole repo | blocking |
| `schedule` | `nightly` | `security-and-quality` | full git history | whole repo | report only |
| a release trigger | `release` | extended + SBOM + attestation | full | whole repo | hard gate |
| a revalidation trigger | `revalidate` | none | none | image digest + SBOM only | incident path |
| anything else | `null` | — | — | — | — |

Two things the table does not decide and the plan therefore does not pretend to:

- **`push` is `merge` only on the protected default branch.** A push to any other branch is a
  `pr`-shaped event without a pull request. Until stage 1 (policy resolution) names the
  protected branch, the plan records `depth: merge` with `depth_basis` saying it assumed the
  pushed ref is the protected one. That assumption is visible, which is the most that can be
  done without the registration file.
- **`workflow_dispatch` has no depth.** SPT §5.3 puts it under *"`nightly` or `revalidate`"*,
  and the two scan different things. The plan emits `depth: null` with the basis naming this
  section. An owner decision closes it (§8).

**`depth_settings` is a label, not a setting.** Today no scanner reads it. The CodeQL job takes
`inputs.codeql_queries` from the caller; secret scanning takes `inputs.scan_git_history`. The row
records what the depth model *says* this run should do, so a reader can see where the run's
actual configuration disagrees with its depth — which is exactly the flat-input defect
AXES_AND_PHASES opens with, made visible per run.

### 3.3 Decision rules, per job

The rule is the registry's `applies` field; the decision is evaluated by one table, in one place:

| `applies` | inputs | decision | reason (registered state) |
|---|---|---|---|
| `always` | — | `run` | `RUN` |
| `discover.<class>` | class `true` | `run` | `RUN` |
| `discover.<class>` | class `false` | `skip` | `NOT_APPLICABLE` — discovery's own row carries whether it was a search or a selector |
| `discover.<class>` | class empty | `forced` | `UNDETERMINED_PRESENT` — applicability was not established, so the job runs and its result is not coverage |
| `discover.any-codeql-lang` | any class `true` or empty | `run` / `forced` | as above, over the six CodeQL languages |
| `input.image_ref` | non-empty | `run` | `RUN` |
| `input.image_ref` | empty | `skip` | `NOT_APPLICABLE` — the caller declared no image |
| `input.enable_<x>` | `true` | `run` | `RUN` |
| `input.enable_<x>` | `false` | `skip` | `DISABLED` — a caller's explicit exception, reported loudly |
| any | `survey` is `DISCOVERY_UNAVAILABLE` | `forced` | `DISCOVERY_UNAVAILABLE` — everything runs; nothing is coverage |

Three properties of the table carry the design:

- **`forced` is a third decision, not a flavour of `run`.** A job that runs because the question
  was never answered contributes `PARTIAL`, never `PASS`. Collapsing `forced` into `run` is how
  a failed survey becomes a green run, and the plan refuses it by having a third word.
- **The decision never reads the capability answers.** A `VERSION_UNSUPPORTED` scanner still
  runs (PIPELINE_ORDERING §2.4: *"Why `VERSION_UNSUPPORTED` still runs the tool"*). The
  capability states ride on the row so the reader and, later, the gate know what the job's
  silence may mean. §4, refusal 1.
- **`skip` always names which registered state produced it.** `NOT_APPLICABLE` and `DISABLED`
  are different owners; `DEPTH_REDUCED` (§3.5) is a third.

### 3.4 The group label, from the grouped topology

JOB_TOPOLOGY §4 proposes thirteen groups; today the workflow has sixteen scanner-class jobs and
the packing endpoint is OD-3. The plan carries **both** names so it is correct under either
answer and so a migration can be checked against it: every job today maps to exactly one
target group.

| today's job | `group` (JOB_TOPOLOGY §4) |
|---|---|
| `secret-scan` | `secrets` |
| `deps-scan`, `malicious-deps`, `sbom` | `sca` |
| `sast-semgrep` | `sast-multi` — never a language bucket (§4.2) |
| `sast-bandit`, `code-quality` (python half) | `sast-python` |
| `code-quality` (node half) | `sast-node` |
| `sast-go` | `sast-go` |
| `sast-dotnet` | `sast-dotnet` — carries the NuGet audit, the §4.4 axis collision, labelled not resolved |
| `sast-java` | `sast-java` |
| `sast-cpp` | `sast-cpp` |
| `codeql` | the language group of each leg once the matrix becomes six jobs (§4.1); `codeql` until then |
| `iac-scan` | `iac` |
| `image-scan` | `container` |

`code-quality` straddles two groups, which is the ESLint-behind-a-Python-gate defect (§2.2)
expressed as data: a job whose halves belong to different groups is a job whose job-level
condition cannot be the disjunction of its members. The plan carries it as `sast-python` with a
note, because the defect is fixed by dissolving the job (§4.3), not by the plan pretending it is
one thing.

### 3.5 Depth narrowing is a plan decision and must be visible

When `depth` is `pr`, the depth model narrows scope to changed paths and the secret scope to the
diff. **Narrowing is not skipping.** A job that runs over changed paths only is
`scan_depth.DEPTH_REDUCED` over every unchanged file (PIPELINE_ORDERING §5.5), and the plan's
`depth_settings` row is where a reader sees that before the run rather than inferring it from
a smaller finding count afterwards. The plan does not compute the changed-path set — that is
stage 6's checkout — it records that the depth calls for one.

---

## 4 · What a plan must refuse

Each of these is a place where an unknown would become a claim at the boundary between stages
4 and 6, and each is a test in tests/test_resolve.py against the advisory object.

1. **A decision changed by a capability answer.** `VERSION_UNSUPPORTED` and
   `VERSION_SUPPORT_UNDETERMINED` never turn `run` into `skip`. Suppressing a scanner that might
   still find something discards real findings to avoid a gap that was already declared.
2. **A `forced` rendered as `run`.** The third decision exists so that "ran because nobody could
   say" is distinguishable from "ran because it applies".
3. **A registered job missing from the plan.** The registry is the denominator
   (check_scanner_registry.py); a plan that lists fewer jobs than the registry has silently
   dropped a control, which is the retirement-register failure (SPT §7) one stage earlier.
4. **A plan computed after a scanner started.** The position is the control. A plan emitted from
   the report job is a log wearing a plan's name, and order is the whole control here as it is
   for redaction before publication.

And one the plan cannot refuse alone, named so nobody assumes it does: **a scanner that does not
read the plan.** Today none does. Until a scanner's `if:` reads the plan, the plan is advisory
by construction, and this document says so in its first line.

---

## 5 · What enforcing it would change, exactly

Three edits, none of them in this lane, listed so the owner can see the cost before deciding.

**Scanner jobs.** Each job gains `resolve` in `needs:` and its job-level `if:` reads the plan
instead of the raw discover output:

```yaml
    needs: [discover, resolve, kit-scripts]
    if: fromJSON(needs.resolve.outputs.plan).decisions['sast-bandit'] != 'skip'
```

(`decisions` is a flat `{job: decision}` map carried beside `jobs[]` for exactly this
expression, because `fromJSON(...).jobs[?]` is not expressible in a workflow `if:`.) A `forced`
job runs and must emit `PARTIAL`; that is the envelope rule of JOB_TOPOLOGY §8.1 R3 applied to
applicability.

**The gate.** Compares the plan to what happened: every job the plan said `run` or `forced`
has a `scanner_state`; a job the plan said `skip` that nonetheless has a result is a plan
violation; a `forced` job's `PASS` is read as `PARTIAL`. A plan violation routes
`DECISION_REQUIRED` — a human has to look, because the pipeline did not do what it said it
would — never `BLOCKED`, which the registry reserves for an observed refusal.

**The report.** Renders the plan beside the results, so the six questions an outcome report
must answer (SPT stage 14) start with "what did this run set out to do".

**Cost:** nothing additional in billed minutes. `resolve` already runs. Elapsed time gains one
job's duration on the critical path, which JOB_TOPOLOGY §7.4 already accepted for `kit-scripts`
for the same reason: a position that has to exist costs a serialisation point.

---

## 6 · What is emitted today, and what it proves

The `resolve` job emits `plan` in the shape of §3.1 with `advisory: true` and
`enforced_by: "nothing"`, plus the flat `decisions` map §5 needs. tests/test_resolve.py proves,
against fixture trees and forced inputs, that:

- every scanner-class job in scanner-registry.yaml has a row (refusal 3);
- `push` derives `merge`, `pull_request` derives `pr`, `schedule` derives `nightly`, and
  `workflow_dispatch` derives `null` with a basis naming §8;
- a class discovery found runs, a class it did not find skips with `NOT_APPLICABLE`, a class it
  could not establish is `forced` with `UNDETERMINED_PRESENT` (refusal 2);
- a `VERSION_UNSUPPORTED` answer rides on the row and leaves the decision `run` (refusal 1);
- an empty `image_ref` skips the container scan with `NOT_APPLICABLE`; a disabled toggle skips
  with `DISABLED`;
- the object is emitted before any scanner can start, because it is emitted by a job no scanner
  waits on and that waits on no scanner (refusal 4, by position).

What it does not prove: that any of this changes what runs. It does not. That is §8.

---

## 7 · Vocabulary reused, by name

| reused | where |
|---|---|
| `discovery_state` — `RUN`, `NOT_APPLICABLE`, `DISABLED`, `UNDETERMINED_PRESENT`, `DISCOVERY_PARTIAL`, `DISCOVERY_UNAVAILABLE`, `COVERAGE_GAP` | §3.3 decisions and reasons |
| `scan_depth` — `pr`, `merge`, `nightly`, `release`, `revalidate`, `DEPTH_REDUCED` | §3.2, §3.5 |
| `version_applicability` — `SCANNER_SUPPORTS`, `VERSION_UNSUPPORTED`, `VERSION_SUPPORT_UNDETERMINED` | §3.3 capability states on each row |
| `scanner_state.PARTIAL` and its `forbidden` clause | what a `forced` job may contribute |
| `routing_result.DECISION_REQUIRED` | §5, a plan violation |
| invariants `defaults_are_suspicious_at_assurance_boundaries`, `a_node_is_not_a_path` | §1.3, §4 |

**Candidate, not registered, written in lower case:** *plan violation* (a job whose result
contradicts its planned decision) and *forced* as a decision value. If the owner adopts §5,
both go through docs/operations/TAXONOMY_DRIFT.md — `forced` most likely as a value of
`discovery_state` beside `RUN`, since it is a decision about applicability, and *plan
violation* as a reason under `routing_result.DECISION_REQUIRED`. Neither is registered by this
document, because nothing branches on them yet.

---

## 8 · Owner decisions

| # | decision | default this document proposes | why it is the owner's |
|---|---|---|---|
| EP-1 | Enforce the plan (§5), or keep it advisory | advisory until the first hosted run shows the plan agreeing with what ran, then enforce | it changes which jobs start; KDEC-006 makes the private consumer dispatch the place to see it first |
| EP-2 | Depth of a `workflow_dispatch` run | `nightly` when dispatched on the protected branch, otherwise `null` and the run says so | the depth model left it open; both readings are defensible |
| EP-3 | Which topology the `group` label targets | JOB_TOPOLOGY depth 3 ("stop at 3 unless CodeQL grows") | OD-3 is open; the label is correct under either and the owner should know which it is checking |
| EP-4 | Whether `forced` and *plan violation* are registered now or when §5 lands | when §5 lands | registering ahead of a consumer is cheap and the registry already does it for D6/D7, but a value nothing branches on is an orphan the reconciler will report until then |

---

## 9 · What could not be settled

- **The protected branch.** `merge` depth is assumed for every `push` until stage 1 exists.
  The assumption is written into `depth_basis` on every plan so it cannot be mistaken for a
  fact.
- **Whether `fromJSON` on a job output of this size is within expression limits.** The plan is
  a few kilobytes; GitHub documents a 1 MB ceiling on job outputs and no documented ceiling on
  `fromJSON`. UNVERIFIED until a hosted run evaluates one.
- **The changed-path set at `pr` depth.** The plan records that narrowing applies; computing
  the set is stage 6's, and `determine-changes` exists as a composite nothing calls.
- **Every number.** There are none in this document, deliberately.
