# Why these keep happening

Twenty-plus defects in one week, found one at a time. Each was fixed on its own terms. That is the
mistake this document exists to correct: they are not twenty defects. They are **three structural
failures**, and every fix so far has been an instance rather than a cause.

---

## The evidence, compressed

| | |
|---|---|
| `sast-java` uploaded a SARIF nothing created | job green |
| `sast-dotnet` published a report nothing wrote | job green |
| `sast-cpp` never invoked flawfinder | job green |
| Semgrep skipped `tests/` by default, so the *clean control was never clean* | job green |
| `trivy-action@0.28.0` — a tag that never existed | would fail on first consumer use |
| 14 Azure gitleaks rules never loaded for any consumer | matrix claimed the coverage |
| gosec: two files, one identity | contract read 19/19 |
| Trivy: one file, two identities | signals passed on collective coverage |
| Container output root-owned → in-place rewrite → **no report at all** | worse than the bug it fixed |
| `apt` blocking on the dpkg lock, silently, three times | ~412 billed minutes |
| `command -v java` succeeds on Java 8 | present ≠ fit |
| Checking `java` when Dependency-Check picks its own JVM | proxy ≠ tool |
| Cache discarded on job failure, so the expensive build never persisted | self-sustaining cost |
| NVD workflow unreachable by construction — `workflow_call` only, no caller | unvalidatable, not unvalidated |
| A failed SARIF upload cancelled the entire deep scan | publication killed detection |
| Discovery: "found nothing" indistinguishable from "could not look" | in the job that decides what gets scanned |
| Discovery: failure signal set inside `$( )`, discarded at the subshell boundary | detected, then thrown away |
| **17 sites** where a parse failure produced `n=0` → read as clean | including gitleaks and semgrep |
| `advisory_mode` suppressed secrets, contradicting stated policy | policy ≠ code |
| Decisions recorded in two places, the stale one looking authoritative | a decision got re-asked |
| Vocabulary used in 14 files, defined in none | enforcement words with no contract |
| Every internal state died at the workflow boundary | consumers saw only red/green |

---

## Failure 1 — Failure to observe inhabits the same state as a successful negative observation

**The single unifying defect**, and the precise form matters. "Missing information renders as good
news" is the symptom. The architectural defect is that **four different states are compressed into
one**:

| State | What it actually is |
|---|---|
| executed, valid report, zero findings | **evidence** |
| did not execute, no report | **absence of evidence** |
| executed, malformed report | **failed evidence collection** |
| could not inspect scope | **failed applicability determination** |

These are not variations of zero. They carry different provenance, different assurance consequences
and different permissible transitions. Shell, Actions and this implementation repeatedly compressed
all four into `empty` / `false` / `0` / `skipped`. Making that compression difficult is the job.

In every case below, the *absence* of information was rendered as the *presence* of a satisfactory
result.

```
no scanner ran        -> green
no report produced    -> n=0        -> clean
could not search      -> no matches -> NOT_APPLICABLE
signal lost           -> default    -> success
key unreachable       -> un-keyed path -> "it works"
publication failed    -> job failed -> detection cancelled
```

### Why it happens structurally

1. **The substrate's idioms default to success.** `|| true`, `|| echo 0`, `2>/dev/null`,
   `[ -z "$(...)" ]`, a skipped job, an empty file. Every ergonomic path in shell and CI swallows
   errors, because the alternative is verbose. **The easy way to write it is the wrong way.**
2. **Absence has no type.** There is no native way to say *I don't know*. It degrades to `0`,
   `""`, `false`, `skipped` — all of which are indistinguishable from *fine*.
3. **Green is the null hypothesis.** CI is built so that "nothing bad was reported" means pass.
   Therefore **any failure to report becomes a pass.**

### The assumption that is wrong

> **A system reports its own failures.**

It does not. It reports what it managed to produce. Silence is structurally identical to safety, and
nothing in the substrate distinguishes them.

---

## Failure 2 — We measure the nearest observable proxy, not the claim

| We asserted | We actually measured |
|---|---|
| the workflow works | the *tool* works (probe installs the binary) |
| the action reference resolves | the *binary* installs |
| the seeded vulnerability is detected | *something* flagged the file |
| the JVM is adequate | `java` on PATH — not the JVM the tool selects |
| the scanner ran | the *job* completed |
| coverage exists | the *registry says* it exists |

Each proxy was chosen because it was **easier to observe**, and each sat one step to the side of the
claim. The gap between them is exactly where every defect lived.

### The assumption that is wrong

> **If the thing next to it works, it works.**

Tool ≠ workflow ≠ consumer ≠ evidence ≠ publication. Proving any one of them proves nothing about the
next, because *each boundary is where responsibility is assumed to have been handled by the other
side*.

---

## Failure 3 — Declarations drift free of implementations

| Declared | Actual |
|---|---|
| registry says `observed` | nothing observed it |
| taxonomy defines `COLLECTION_FAILED` | 17 sites do the opposite |
| policy: secrets always block | `advisory_mode` suppressed them |
| docs: advisory blocks nothing | intent: secrets always block |
| decisions recorded | recorded **twice**, one stale |
| "starting discovery" | discovery not started |

Declaration is cheap. Implementation is expensive. Nothing forces them to meet, so they separate at
exactly the rate the work gets hard.

### The assumption that is wrong

> **Writing it down makes it so.**

**Registering a term is not implementing it.** Recording a decision is not enforcing it. Stating an
intent is not executing it.

---

## What the *process* got wrong

**Not one of these was found by reading the code.** Every single one was found by
**executing it** or by **someone asking a question**. Careful review found nothing, repeatedly,
including review by the person who had just written the code.

Two consequences:

1. **Unexecuted code is unknown code**, regardless of how carefully written or reviewed. Confidence
   must be a function of execution, not of attention. The validation registry already encodes this
   for capabilities; the principle is broader.
2. **The defects cluster at boundaries** — tool→workflow, workflow→consumer, job→job,
   scanner→evidence, code→docs, decision→record, internal→API. Interfaces are where lying happens,
   because each side assumes the other handled it.

And the uncomfortable one:

3. **The system currently depends on a human asking "did you check?"** Every reconciler that exists
   was born from a question, not from a design. That is not a durable process — it makes the
   quality of the system a function of one person's attention.

---

## What to design, and why each one is mechanical

The fix for each failure is a **control that cannot be satisfied by intention**.

### Against Failure 1 — make absence loud

- **Ban the swallowing idioms mechanically.** A lint that rejects `|| true`, `|| echo 0`,
  `2>/dev/null`, and bare `[ -z "$(...)" ]` on anything whose absence changes a conclusion.
  Allow them only with an explicit annotation naming why absence is safe *here*.
- **`UNKNOWN` must be representable at every layer** — count, state, output, artifact. A measurement
  that cannot express "I could not measure" will eventually claim a value it does not have.
- **Fail closed on missing information.** The gate already does this for unrecognised states.
  It must be the rule, not one instance.

### Against Failure 2 — assert the claim, not its neighbour

- **Attribution is mandatory in assertions.** Every expected signal names *which component* must
  produce the evidence. Generalise the `tool:` pin: any assertion satisfiable by a neighbour is not
  an assertion.
- **Every boundary gets a forced-failure test.** Not "does it work" but "when the far side fails,
  does this side notice?" That is the only test that catches an assumed responsibility.
- **A probe proves a tool. Only a consumer-path test proves a workflow.** Record which level each
  claim was established at, and never let a lower level satisfy a higher claim.

### Against Failure 3 — reconcile declarations against reality

The pattern already works here three times over — **declared registry + actual usage + a check that
fails on divergence**:

| Existing | Reconciles |
|---|---|
| `reconcile_validation.py` | capability claims vs probes |
| `inline_normalizer.py --check` | canonical source vs inlined copies |
| `reconcile_taxonomy.py` | vocabulary declared vs vocabulary used |

**Owed, by the same pattern:**

- **Policy vs code** — assert by *execution* that secrets block under `advisory_mode`, rather than
  trusting the branch order. The policy is a claim; only a run is evidence.
- **Docs vs behaviour** — statements about enforcement, extracted and checked against the gate.
- **Decisions vs implementation** — a settled decision with no implementing artifact is drift, and
  should be visible as such rather than discovered when someone re-asks it.

### Turning findings into controls, without drowning in tests

**Do not convert every question into a bespoke test.** That way lies 247 exquisitely specific
regression tests protecting a property nobody can name.

> **Every newly discovered failure CLASS becomes an INVARIANT. Representative instances become
> tests of that invariant.**

The seventeen sites were never seventeen lessons. They are one invariant:

> **Failure to determine a value MUST NOT be represented as a successfully determined negative
> value.**

Static analysis hunts the syntactic manifestations. Forced-failure contract tests establish the
semantic behaviour. The invariant is the thing being protected; the tests are only samples of it.

### Fail-open vs fail-closed is a declared property, not an outcome

"Closed is good" is too crude, and we already shipped a case where failing closed was *wrong*: a
SARIF publication failure killed an entire deep scan. That is closed execution and terrible
assurance architecture.

> **Fail closed on the assurance CLAIM. Fail isolated on independent evidence COLLECTION.**

Never manufacture `PASS` when required evidence is unavailable. Never destroy evidence you could
still obtain because a sibling failed — independent scanners must not die because one of them had
indigestion. Secrets are the opposite pole: failure to establish the secret result can never become
permission to merge.

Every boundary therefore declares a **failure disposition**: what failed, whether the claim can still
be established, what evidence survived, whether this poisons overall assurance or one capability,
whether collection continues, whether enforcement blocks, what the consumer sees — and, if the
mechanism itself fails, whether that is open, closed, isolated, degraded or undetermined, **on
purpose**.

### Correctness is not local

A perfectly correct producer can still participate in a false assurance result if its consumer
assigns semantics to missing output. That is not a syntax problem and grep will not find it.

> **A fix is not complete when the defective component behaves correctly. It is complete when the
> resulting claim remains correct through every downstream boundary that consumes it.**

So the audit needs a **producer to consumer trace for every assurance-bearing value**: who produces
it, under what conditions it can be absent, who consumes it, what the consumer does when it is
absent or invalid, and what final assurance and enforcement state results. **Defaults at assurance
boundaries are suspicious by construction** — there is no implicit default from unknown to known.

And `always()` needs its own question. It is not wrong; we want cleanup, artifact preservation,
summaries and independent collection to survive failure. The question is narrower:

> **What authority does a step running under `always()` have to make a NEW assurance claim?**
> Preserve evidence: yes. Record failure state: yes. Run an independent scanner: yes.
> Turn missing upstream output into a successful state: never.

Likewise `continue-on-error` is correct only when **the error becomes data**. If execution continues
and nobody captures the outcome, maps it into the taxonomy and propagates its effect, then
`continue-on-error` is `|| true` wearing YAML. And `2>/dev/null` is acceptable when it suppresses
only presentation — not when it destroys the information needed to distinguish failure from absence.
We are after semantics, not a lint cult.

### Degradation must not increase authority

The correction that matters most, and the one with the widest reach:

> **Degradation may reduce the SCOPE or CONFIDENCE of a claim. It must never increase its
> AUTHORITY.**

An earlier version of the gate projected *any* unavailable scanner into a blanket `UNDETERMINED`.
That discards everything genuinely established — as destructive as inventing a `PASS`, merely in the
opposite direction. A failed Bandit does not un-find a Trivy finding; a passing Semgrep does not fill
Bandit's hole.

`PARTIAL` preserves what was established and names what became unknown. `UNDETERMINED` is reserved
for failure of the **aggregate** claim — discovery failed, so we do not know which capabilities
should have run, and therefore cannot know what was never attempted.

This one is not specific to scanners. It applies to agents, identity, continuity and governance
alike: **authority must degrade with certainty, never grow because certainty disappeared.**

### The test harness is inside the assurance boundary

Five sites in `validate-scanners` still read a collection failure as zero. They cannot stay weaker
for being "internal scaffolding":

> **A harness that interprets collection failure as zero, while testing whether production code
> correctly distinguishes collection failure from zero, is a lying lie detector.**

### And the process fix

**Convert every question into a check.** Each of the reconcilers above exists because someone asked
whether the thing was true. Those questions are the specification. When a question finds a defect,
the deliverable is not only the fix — it is the mechanical check that would have asked it for us.

Otherwise the pipeline's assurance is only ever as good as whoever last thought to ask.

> **A defect discovered through HIL questioning is evidence of a missing machine-verifiable
> invariant until demonstrated otherwise.**

The goal is not to remove human judgement — some things genuinely require it. The goal is to stop
spending it rediscovering what the system could have checked itself, so attention goes to *"what
claim have we not considered?"* rather than catching `jq || echo 0` in its seventeenth disguise.

---

## The philosophy underneath all of it

Recorded because it is the actual objective, and every control above is downstream of it.

- **Design for falsification.** Ask what observation would prove the claim wrong, then produce that
  condition deliberately. A hundred green runs establish less than one deliberately broken
  dependency handled correctly.
- **Search for siblings before declaring a fix.** One swallowed `find` failure was not a bug to
  patch — it was evidence of a pattern. The sibling search is part of root-cause analysis, not an
  optional follow-up.
- **Reality outranks architecture.** Doctrine, taxonomy and process are provisional. If operational
  evidence says the model is wrong, the model moves — do not torture reality until it resembles the
  diagram. A settled decision stays authoritative **until later evidence invalidates one of its
  premises**, not forever.
- **Idiot-proofing is respect for a cognitive budget, not an insult.** The engineer shipping a
  service already has an application, dependencies, incidents and deadlines competing for attention.
  They should not also have to become an amateur archaeologist of the security platform.
- **Asymmetric friction.** Low friction for the compliant path; friction proportional to risk for
  bypass. If the secure path needs seventeen remembered caveats and the insecure path is one YAML
  boolean, that is not governance, it is a compliance obstacle course.
- **Human attention is a scarce security resource.** Spend it at judgement boundaries — is this
  genuinely an accepted risk, does this compensating control suffice, does new evidence invalidate
  an earlier decision, is the system claiming something it has not earned — never on whether `jq`
  silently failed.

**The test for any new control:** does it reduce the knowledge and vigilance required from an
ordinary engineer while preserving or increasing assurance? If it requires everyone to learn the
security ontology merely to deploy a Python service, it is theatre.

**The destination:** security and governance are mature when people stop experiencing them as extra
work — not because the controls disappeared, but because they became how the system naturally works.
A paved road with guardrails nobody notices until they try to drive through one.
