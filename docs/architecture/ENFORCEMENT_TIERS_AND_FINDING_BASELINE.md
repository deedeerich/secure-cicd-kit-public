# Enforcement tiers and the finding baseline

**The three-rung ladder, and the NEW-versus-PRE-EXISTING mechanism it cannot be turned on without.**

```
Phase: design — a written contract, not an implementation
Truth State: modelled 2026-09-23 from the owner's enforcement model, against the
             registered vocabulary in secure-cicd-kit/assurance-taxonomy.yaml (v1)
Audience: whoever builds the gate, and whoever has to explain a tier in six months
Decision Supported: what a rung means, what makes a finding NEW, and what the
             grandfather clause costs
Deferred Depth: the taxonomy itself; the ticket system; the remediation track's UI
```

> **Section 5 now has code behind most of it, as LIBRARIES with local proofs, and none of it is
> wired into a pipeline job.** `scripts/finding_identity.py` implements section 5.1's three
> components, section 5.2's exclusions and the per-subject loci. The cascade (section 5.3,
> `scripts/finding_match.py`), the ledger format and its protected-branch reader (section 5.4,
> `scripts/baseline_ledger.py`), the only write authority (`scripts/propose_ledger.py`), the
> alias table and upgrade reconciliation (section 5.5, `scripts/rule_family.py`) and the anchored
> correlation tier (section 9.4, `scripts/finding_correlation.py`) exist and are proven locally.
> **Not built:** the ladder, severity, fix availability, the SLA and the track (sections 6-8), and
> every job that would call the above. See section 5.8 for exactly which sentences have code
> behind them, because a document that says "designed" over a half-built feature is the same
> defect as one that says "built" over a design -- and "built as a library" is not "running".
>
> This document exists so that when it is built it is built once, and so that the words it uses
> already mean something. The kit's own rule applies to this file first:
> **registering a term is not implementing it, and writing it down does not make it so.**
>
> **Nothing here is registered vocabulary.** Section 12 proposes candidates. They are marked
> CANDIDATE because registering them would assert they had been decided, and they have not been.

---

## 0 · What this settles, and what it deliberately does not

**Settled here:** what each rung blocks; why a rung is a floor; who decides a repo's rung and what
promotion evidence looks like; whether the rung is per repo or per environment; what a finding's
durable identity is made of and what it must never contain; where first-seen lives and which branch
it is read from; what a scanner upgrade does to a baseline; what happens when a finding moves; how a
pre-existing finding expires; what the SLA is and when its clock starts; what happens at breach;
where deduplication happens relative to raising a ticket; and how every one of those decisions is
recorded.

**Not settled here, and named as unsettled in Section 13:** whether the rung vocabulary supersedes
the registered `policy_mode`; whether cross-scanner SAST identity is achievable at all; the stability
of content hashing under a repository-wide reformat; whether estates actually have deployed-artifact
evidence; ledger scale; monorepo and vendored-code ownership.

A document that answered all of those about a mechanism nobody has built would be lying.

---

## 1 · The ladder

```
crawl   only SECRETS block. Everything else is reported.
walk    secrets block, PLUS cherry-picked controls block. Everything else
        reported with a disposition required.
run     all HIGH/CRITICAL block -- EXCEPT findings already present in
        production, which are fixed on a remediation track rather than
        blocking new work.
```

That is the owner's model verbatim and it is the thing being specified. Everything below is either a
consequence of it or a prerequisite for it.

### 1.1 The rungs expressed as minimum routing results

A rung does not say "block" or "not block". It sets, per control, the **weakest routing result that
control is permitted to contribute**. The run's result is then the precedence-maximum across
controls, using the precedence order that `routing_result` already declares:

```
BLOCKED > EVIDENCE_UNTRUSTED > DECISION_REQUIRED > PROCEED_WITH_ADVISORY > PROCEED
```

This is reuse, not a new lattice. The aggregation rule and the ordering both already exist.

| control class | crawl | walk | run |
|---|---|---|---|
| **secrets** | `BLOCKED` | `BLOCKED` | `BLOCKED` |
| cherry-picked set | n/a | `BLOCKED` | `BLOCKED` |
| NEW critical/high | `PROCEED_WITH_ADVISORY` | `DECISION_REQUIRED` | `BLOCKED` |
| PRE-EXISTING critical/high, on an unexpired track | `PROCEED_WITH_ADVISORY` | `DECISION_REQUIRED` | `PROCEED_WITH_ADVISORY` |
| PRE-EXISTING critical/high, track lapsed | `PROCEED_WITH_ADVISORY` | `DECISION_REQUIRED` | `BLOCKED` |
| everything else (medium/low, lint) | `PROCEED_WITH_ADVISORY` | `DECISION_REQUIRED` | `DECISION_REQUIRED` |
| any control yielding `EVIDENCE_UNTRUSTED` | see §3 | see §3 | see §3 |

Three readings of that table matter.

**Visibility is constant across rungs.** `policy_mode` already states it: a mode "changes
ENFORCEMENT, never VISIBILITY". `crawl` collects and reports exactly what `run` collects and reports.
A rung that also narrowed scope would be two decisions in one knob, which
`AXES_AND_PHASES.md` already forbids: an input that answers more than one axis is two inputs.

**The ladder is monotone.** For every control, `run` is at least as strong as `walk`, and `walk` at
least as strong as `crawl`. This is why the bottom row of `run` is `DECISION_REQUIRED` rather than
advisory — a `run` repo cannot be weaker than a `walk` repo on medium findings, or "promotion" would
mean losing a control. **A non-monotone ladder is a menu.**

**`run` does not grant amnesty; it grants a schedule.** The "EXCEPT" clause in the owner's model
resolves to `PROCEED_WITH_ADVISORY` *only while a track is unexpired*, and the row directly beneath
it is the whole of Section 8.

---

## 2 · The floor invariant

> **A tier is a FLOOR. Cherry-picks may only STRENGTHEN it, never weaken it.**

Mechanically:

```
effective_minimum(control) = precedence_max( rung_floor(control), cherry_pick(control) )
```

A cherry-pick whose value sits **below** the floor is not "applied and then overridden" and it is not
silently dropped. **It is a policy defect that fails the policy check**, by name, at the point the
policy file is read. A silently-dropped override reads as applied to everyone who wrote it.

`run` with controls picked *off* is `crawl` wearing `run`'s label, and that is the failure this whole
model exists to prevent. The mechanism against it is not good intentions; it is that the downward
direction has no representation. There is no field in which a cherry-pick can express "less than the
rung".

### 2.1 The honest limit of the floor rule

The lattice above works only for controls whose surface has an **establishable strong side**. The
taxonomy already names the case where it does not: `control_weakening.CONTROL_RECONFIGURED` —
"the value differs from baseline on a surface where this record CANNOT establish the direction: a
severity list, a path, a query suite. Different is not provably weaker."

So the floor invariant is total over **enforcement dispositions** and partial over **configuration
surfaces**. A cherry-pick that swaps a CodeQL query suite, narrows a path selector or edits a
severity list is recorded as `CONTROL_RECONFIGURED` and routes to `DECISION_REQUIRED` at the next
promotion review. It is neither asserted as a weakening (an overstatement) nor treated as equivalent
to baseline (the silence `control_weakening` exists to end).

**This is a real hole and it is where a determined team will push.** Naming it is the mitigation
available at design time; the mitigation available at build time is to make the set of
direction-establishable surfaces as large as possible and to treat every remaining
`CONTROL_RECONFIGURED` as owing a decision rather than as configuration.

### 2.2 The label must be emitted, not just held

A run must emit the **registered rung**, the **effective minimum per control**, and **every
divergence between them**. A rung label with no emitted effective set is `soft_fail_sast` again — the
kit has already shipped one input that softened the gate while the run "was reported identically to
one that passed honestly". `control_weakening` exists because of that, and its rule applies here
unchanged: **a weakening that is not in the record did not happen, as far as the evidence is
concerned, and that is indistinguishable from a clean run.**

---

## 3 · A broken scanner must never demote a tier

> The rung is a property of the **registered policy**. Nothing a run observes may change it.

When a control is `UNAVAILABLE`, `COLLECTION_FAILED`, `FAILED`, or when discovery could not establish
applicability, the control contributes `routing_result.EVIDENCE_UNTRUSTED`. It does **not** contribute
`PROCEED`, it does not contribute `DECISION_REQUIRED` ("there is nothing here to decide about yet —
the input to a decision is missing"), and it does not lower the rung.

The reason is an incentive, not a taxonomy preference. If a broken scanner demoted the tier, then
**breaking a scanner would be the cheapest way to weaken the gate**, and the pipeline would have been
built to reward exactly the behaviour it exists to detect.

Three consequences that need stating because each is a plausible shortcut:

**A control whose effective minimum is `BLOCKED` stops the run when its evidence is untrusted, at
every rung and every environment.** Secrets are the standing case. `WHY_THESE_KEEP_HAPPENING.md`
already draws this line: "failure to establish the secret result can never become permission to
merge." A secret scanner that could not run is not a clean secret scan at `crawl` either.

**At non-production environment tiers, `EVIDENCE_UNTRUSTED` on a non-blocking control warns rather
than stops**, per the registered `environment_tier` table. That means a broken scanner genuinely does
let work through at `dev`. That is the declared position, not an oversight — and it is exactly why
`uat` and `prod` are both production tiers where "scanner did not run" blocks.

**Baseline unavailability is itself `EVIDENCE_UNTRUSTED`.** If the ledger cannot be read, the run
cannot tell NEW from PRE-EXISTING. It must not fall back to "treat everything as pre-existing" (a
one-line total bypass of `run`) and must not fall back to "treat everything as new" (which blocks the
world and gets the gate switched off within a week — the founding failure this document exists to
prevent). It emits `EVIDENCE_UNTRUSTED` and says which ledger it could not read. This is the single
most likely implementation shortcut and the most damaging.

---

## 4 · Who decides a rung, and is it per repo or per environment

### 4.0 The rung is the business's declared posture. Everything else derives from it.

**Owner decision, 2026-09-23.** The rung is not a peer of `policy_mode`, `team_pattern` or
`environment_tier`. It sits **above** them. It is the single place a business states the level of
gating it is *comfortable with and prepared for*, and team size, environment tier, and the ordinary
gating rules are read **downstream of that declaration**, never beside it.

This settles §13's first open question. It also fixes the shape of the whole mechanism:

```
business declares rung  (per repo, per environment -- §4.1)
        |
        +--> per-control floor table            (§1.1)
        +--> policy_mode, as a DERIVED value    (see below)
        +--> team_pattern -> HOW a floor is satisfied, never WHETHER
        +--> environment_tier -> may only raise the floor, never lower it
        +--> cherry-picks -> strengthen only    (§2)
```

**`policy_mode` becomes derived, not declared.** It is no longer an independent input a caller
sets; it is computed from the rung and recorded as such. Two spellings of one concept is the drift
the taxonomy exists to catch, and the resolution is not to delete `policy_mode` but to stop anyone
setting it directly. A derived value that a caller can still override is not derived.

**Team size changes the mechanism, never the floor.** `team_pattern.solo_dev` makes a
required-second-reviewer rule *unsatisfiable*, not *waived*. A one-person team at `run` still blocks
on high and critical; what changes is that peer review cannot be the control, so a compensating
control is named and the decision routes to an authority outside the repo. The floor is untouched.
Reading team size as permission to lower a rung is how "we're small" becomes a standing exemption,
and small teams are not the ones who can absorb an incident.

**The declaration names the TARGET. The evidence sets the EFFECTIVE.** "Comfortable with" and
"prepared for" are two different claims, and a business can hold the first without the second. A
declaration of `run` with no baseline, no fingerprint scheme and no remediation track is an
aspiration, and §4.3's promotion evidence exists precisely so that nobody can declare their way up
the ladder. Where the declared and the effective rung differ, **the record carries both and the
gate obeys the effective one** — never the reverse, and never a single number that hides which it
is. A dashboard showing `run` over an estate running at `crawl` is the most expensive artefact in
this document.

**Declaring downward is a weakening event.** Because the rung is now the top of the tree, moving a
business from `run` to `walk` is the largest single control change available in the system and must
be at least as visible as disabling one scanner: a named authority, a stated reason, an expiry, and
`control_weakening.WEAKENING_IN_FORCE` on every affected run. Otherwise the root declaration is the
softest bypass the kit ships, and it would be reached by editing one word.

### 4.1 Both. The rung is registered per (repo, environment) cell.

A repo at `run` deploying to dev and to prod is two different risk positions, so it holds two
registered rungs. The rung that applies to a run is the rung of the **environment being targeted**.

Two constraints on the cells:

**Monotone along the promotion path.** `rung(sandbox) <= rung(dev) <= rung(test) <= rung(uat) =
rung(prod)`. The equality at the end is not a choice: `environment_tier` already declares uat and
prod both production tiers. A cell that violates the ordering is a policy defect.

**A pull request is evaluated at the rung of the highest environment the merged branch can reach
without a further human gate.** Without this rule a repo registered `crawl` for dev and `run` for
prod lets everything into the default branch and discovers it at the promotion gate, which is the
late-discovery failure in a new costume — and the promotion gate is then the place where a release
is blocked by code that merged weeks earlier and belongs to someone who has moved on.

### 4.2 Who decides

| act | proposed by | approved by | recorded where |
|---|---|---|---|
| initial rung registration | repo owner | Security | repo policy file on the protected default branch, under CODEOWNERS |
| promotion (up a rung) | repo owner | Security, against the evidence in §4.3 | same file; the prior value retained, not overwritten in place |
| demotion (down a rung) | either | Security, **with a stated reason and an expiry** | same file |
| cherry-pick | repo owner | Security where it is not a strengthening; automatic where it is | same file |

**A rung is not a workflow input.** If the calling workflow accepts one at all, the run must compare
it against the registered value and record any downward divergence as
`control_weakening.WEAKENING_IN_FORCE`; with no reason and no named authority attached it is
`WEAKENING_UNATTRIBUTED`, which routes to `DECISION_REQUIRED`. A rung that a caller can simply pass
is a governance position expressed as a config flag, and the kit has already been bitten by that.

**Demotion is a governance act with an expiry, never an outcome.** Nothing in a run may demote. A
demotion without an expiry is a permanent quiet retreat, and the same rule the taxonomy applies to
every other exception applies here: silence never renews it.

### 4.3 Promotion needs evidence, and here is which evidence

**crawl → walk:**

1. **The rung's controls have actually executed at baseline strength**, on this repo, on the commit
   that could break them, for a declared number of consecutive runs, with no `EVIDENCE_UNTRUSTED`.
   Configuration is not evidence — `a_node_is_not_a_path` and `selftest_reach.EXERCISED_ON_PUSH` both
   say so, and the kit has already shipped six days of green over a workflow that started zero times.
2. **A baseline ledger exists** for the cell, is populated, and every entry has an owner.
3. **Every entry is classified**, not merely counted — each carries a `finding_classification` value.
   A backlog of a thousand unclassified findings is not a baseline; it is a number.
4. **The human controls the rung assumes are available at this `team_pattern`.** A cherry-picked
   control requiring approval separation is unsatisfiable at `solo_dev` and must be recorded as an
   UNVALIDATED HUMAN-WORKFLOW PATH rather than reported as passing.

**walk → run, additionally:**

5. **The baseline mechanism itself has been demonstrated, by forced failure.** A deliberately
   relocated finding is shown to survive as the same finding; a deliberately introduced one is shown
   to appear as NEW; a deliberately removed one is shown to appear as `POTENTIALLY_ABSENT` rather
   than as fixed. Without this, `run` is blocking on an unproven identity scheme, and
   "unexecuted code is unknown code" applies to the gate's own machinery first.
6. **The remediation track has closed at least one entry, verified by the scanner no longer
   reproducing it.** Evidence that the track is a track and not a car park.
7. **Fix availability has been established for the whole day-one baseline** (§7), because a `run`
   rung whose baseline is full of unestablished fix availability is a schedule over unexamined
   work. That state reuses the registered `NOT_ESTABLISHED`.

   > This line originally coined its own namespaced spelling of *unknown* — a fifth variant of
   > not-established, in a document whose §13 complains that four already exist.
   > `reconcile_taxonomy.py` refused it under **remedy 1**, on the file that was lecturing about
   > remedy 1. Note also that the gate kept refusing while the token merely appeared in the
   > sentence explaining the mistake: **it scans for the word, not for the intent.** That is the
   > correct trade — a scanner that could be talked out of a finding by surrounding prose is a
   > scanner with a natural-language bypass — and the cost is that a term can only be retired by
   > ceasing to write it.

---

## 5 · The prerequisite: what makes a finding the same finding

`run` is unreachable without a defensible answer to "have I seen this before?". Without it, the day
the rung turns on, every pre-existing HIGH blocks every deployment, nobody ships until the backlog
clears, and the gate is switched off within a week.

### 5.1 One finding, three components, carried separately

A fingerprint here is **not one hash**. It is three hashes carried together, because a single hash
forces one answer to three questions that fail in different ways.

| component | what it hashes | fails when |
|---|---|---|
| **WHAT** | the defect's class identity, externally anchored where an anchor exists: CVE / GHSA / OSV id, or PURL for a package finding, or the CWE plus a **rule-family alias** for a finding with no external id | advisories re-alias; CWE is coarse |
| **WHERE** | a subject-scaled locus, never an offset (§5.2) | genuine relocation |
| **CONTENT** | a normalised hash of the matched construct: whitespace collapsed, comments removed, string and numeric literals that are not part of the construct replaced by placeholders | a repository-wide reformat; an identifier rename that is part of the construct |

**WHERE is scaled to `finding_subject`**, reusing the registered subject classes:

| subject | locus |
|---|---|
| `SOURCE` | canonical repo-relative path **plus** the enclosing symbol path (namespace / class / function). The symbol is the strong half; the path is carried and weighted weakly. |
| dependency (SCA) | PURL — ecosystem, package name, version — plus whether it is direct or transitive, plus the manifest role. Never the lockfile line. |
| `IMAGE` | installed package name and version as reported by the image's own package database. **Never the image digest** — it changes on every build. |
| `IAC_PLAN` | the plan's resource address: module path, resource type, resource name. Never the file offset. |
| `RESOURCE` | the cloud resource id. `finding_subject` already warns that a finding whose subject is a running resource outlives every release that touched it. |

### 5.2 What a fingerprint must NOT contain, and why each one is fatal

> **A fingerprint that changes when the finding did not is a fingerprint that manufactures NEW
> findings forever.**

| excluded | what breaks it | what the breakage looks like |
|---|---|---|
| **line and column numbers** | any edit above the finding | one unrelated import added at the top of a file, and every finding in it is NEW |
| **the scanner's rule id** | a scanner upgrade renaming or splitting a rule | the entire baseline resets at the next minor version |
| **scanner name and version** | upgrade; adding a second scanner | corroboration reads as duplication, and the upgrade resets everything |
| **the file path as a strong component** | a rename, a directory move, a monorepo restructure | a refactor produces N new criticals and N silent disappearances |
| **commit sha, run id, build number, timestamp** | every run | nothing ever matches anything |
| **image digest** | every build | every rebuild re-baselines the whole image |
| **severity** | a CVSS re-score, a distro re-rating | a re-score both retires the old finding and creates a new one — two lies in one event |
| **the scanner's own `partialFingerprints`** | scanner-specific by construction; for a secret scanner it can be **a hash of the secret itself** | the kit already strips these before SARIF upload for exactly that reason. A baseline ledger that reintroduced them would commit an offline-crackable oracle for every low-entropy secret to a branch everyone can read. |
| **any matched secret material, snippet, or entropy string** | — | same reason. See §5.7: the baseline has no authority over secrets at all, so it never needs to hold one. |

### 5.3 Matching is a cascade, not an equality test

For a candidate finding against the ledger:

| outcome | condition | treatment |
|---|---|---|
| **exact match** | WHAT, WHERE and CONTENT all agree | the same finding. `first_seen` carried forward untouched. |
| **moved** | WHAT and CONTENT agree, WHERE differs, and exactly one unmatched ledger entry holds that pair | **one finding that moved.** The move is recorded as an event; `first_seen` is carried forward. |
| **ambiguous** | WHAT and CONTENT agree across more than one entry, or across more than one current finding | resolved by **cardinality**, not by guessing — see below |
| **unmatched** | WHAT is new, or CONTENT is new | **NEW** |
| **uncomputable** | a component could not be derived (scanner gave no locus, the file could not be read) | **not a match and not a NEW finding.** `EVIDENCE_UNTRUSTED` for that finding. An identity that could not be computed must never resolve to the permissive side. |

**The cardinality rule, which is the answer to "is that one finding that moved, or one closed and one
new, and how would anybody tell".** For a group of ledger entries and current findings sharing
(WHAT, CONTENT), with `N` in the ledger and `M` currently observed:

- `min(N, M)` are continuations — that many findings demonstrably existed before.
- any surplus `M - N` is **NEW**. A file split that genuinely duplicates a defect adds a finding, and
  the model says so.
- any deficit `N - M` is **`POTENTIALLY_ABSENT`** — the registered term, whose registered rule is
  exactly this case: "present earlier and absent now, where the later observation is NOT shown to
  have covered the scope it lived in… absence of the scope is not absence of the thing". It is not
  closed until coverage over the scope it lived in is demonstrated.

Within the group, *which* current finding corresponds to *which* ledger entry is often genuinely
undecidable. The model does not pretend to know. It records the ambiguity, and enforcement depends
only on the cardinality, which it does know. **Nobody can tell, in the hard cases — so the design
must not require anyone to.**

### 5.4 Where `first_seen` lives, and which branch it is read from

**The baseline ledger** is a set of records committed on the **protected default branch**, keyed by
`(finding identity, environment)`. Each record carries at minimum:

```
the three fingerprint components · subject class · environment · first_seen date ·
first_seen provenance (run id, observed_at, observed_at_source) · age_established flag ·
severity as reported by each scanner · effective_severity and its formula version ·
fix_availability and the date it was established · classification · owner ·
disposition reference · remediation track reference · SLA deadline · move history
```

`first_seen provenance` reuses `provenance_identity`'s field list, including the two time fields that
namespace added because "the envelope had thirteen fields and not one was a time".

**Read from the protected default branch, never from the PR under evaluation.** This is the same rule
`disposition_type` already carries for dispositions, and it is the same rule for the same reason:
otherwise a PR can add its own finding to the baseline in the same PR and grandfather the thing it
just introduced — identical in shape to exempting the secret it introduces. A baseline read from the
PR head is not a weaker baseline; it is a self-signed certificate.

**Written by a separate, reviewed change.** Ledger updates are produced by the post-merge or nightly
run and merged to the protected branch under CODEOWNERS. **A PR run may only read.** The ledger is a
governance artifact, not a scanner output — the scanner's observation set is evidence; the ledger is
the record of decisions about that evidence, and the two must not share a write path.

**Which commit is read:** the merge base for **grandfathering**, the branch tip for **removals**.
Grandfathering from the merge base means nothing can be added underneath a PR while it is open.
Removals taking effect from the tip means a remediation merged by someone else strengthens the gate
immediately. This is the floor rule applied to time: **strengthening takes effect at once; weakening
requires review.** The cost is named in §13.

### 5.5 What a scanner upgrade does

A fingerprint scheme that survives no upgrade is a baseline that resets annually.

**Rule ids are aliased, not embedded.** A `rule_family` alias table lives beside the ledger on the
protected branch, mapping (scanner, version-range, rule id) onto a stable family key. The alias table
is versioned and reviewed like any other governance file. Adding an alias is how an upgrade is
absorbed; *not* adding one is how a baseline silently resets.

**An upgrade is a declared event.** The scanner generation is pinned in the profile. When it changes,
the run emits a **baseline reconciliation report** comparing the identity sets before and after, and
the new generation is not authoritative for enforcement until that report is reviewed and accepted by
a named approver. This is `toolchain_currency`'s existing rule applied to the baseline rather than to
the tool: "an upgrade changes detection, so it may not promote until the seeded corpus proves the new
version still detects what the old one did."

**An upgrade may never, by itself, create a NEW finding.** Findings that appear only because the
scanner got better are real findings and are not the author's doing. They enter the ledger as
pre-existing with an explicit flag saying the baseline did not observe them earlier **because nothing
could** — their age is not established and must not be asserted as the upgrade date. They take a
track, they do not inherit an open-ended grant, and their SLA runs per §8.

**Findings that disappear across an upgrade are `POTENTIALLY_ABSENT`, never fixed**, until the new
generation demonstrates it covered the scope. A scanner that stopped looking and a defect that stopped
existing are the same shape in a report and opposite facts about the world.

**The reconciliation window is bounded.** A generation change grants one dated reconciliation with an
approver. It is not a standing right, and it is not a device for re-baselining a repo by upgrading
something.

### 5.6 The failure modes of this scheme, stated plainly

| failure | effect | what reduces it | residual |
|---|---|---|---|
| repository-wide reformat or formatter rollout | CONTENT changes across thousands of findings at once; mass false NEW | normalise whitespace and comments out of CONTENT; treat a commit touching more than a declared fraction of files as a **declared reformat event** requiring reconciliation, exactly like a scanner upgrade | a partial reformat under the threshold still manufactures NEW findings |
| identifier rename inside the matched construct | CONTENT changes for that finding | placeholder substitution for literals only; symbol path in WHERE is a separate component, so WHAT+WHERE may still match | a rename plus a move in one commit is indistinguishable from a deletion plus an addition |
| advisory re-aliasing (GHSA splits, CVE merges) | WHAT changes | carry all known aliases in the record and match on alias-set intersection, not on equality | alias sets are not transitive in practice, and two ecosystems disagree |
| one finding legitimately becomes two | cardinality rule creates one NEW | intended behaviour | a defensible NEW finding lands on an author who only moved code |
| a scanner reports no locus at all | identity uncomputable | `EVIDENCE_UNTRUSTED` for that finding | the finding cannot be baselined and therefore cannot be grandfathered — which is the safe side, and is also friction |
| very coarse WHAT (CWE only) plus a common CONTENT | two genuinely different findings collide as one | require a symbol-level WHERE for CWE-only findings | collisions in generated or highly repetitive code |

**The scheme's own honest summary:** it is designed to be wrong in the direction of *asking* rather
than in the direction of *assuming*. Every unresolved case above routes to `DECISION_REQUIRED` or
`EVIDENCE_UNTRUSTED`, never to `PROCEED`.

### 5.7 The baseline has no authority over secrets

**Secret findings block at every rung and are never grandfathered.** A leaked credential is live
exposure, not inherited technical debt; the fix is unambiguous and immediate, which is rotation. "It
was already in production" is the *reason to rotate it*, not a reason to schedule it.

This closes the largest loophole in the whole model before it opens, and it also shrinks the
fingerprint problem: nothing in the ledger ever needs to identify a secret, so nothing in the ledger
ever needs to hold secret-derived material.

The known cost, from the kit's own operational record: a legacy estate can produce several hundred
secret findings, the large majority of them high-entropy strings in cached tool output — noise a
previous system generated, not credentials anyone leaked. Those are `FALSE_POSITIVE` dispositions,
per finding, with evidence, narrowly scoped, on the protected branch. That path is deliberately
narrow and deliberately laborious. **"It looks like a secret but probably isn't" does not qualify** —
that sentence is already in `disposition_type.secrets_rule` and it stands.

### 5.8 What is built, what is not, and where it is wired

`scripts/finding_identity.py`, `--selftest` green. **Built:**

| section | built as |
|---|---|
| 5.1 three components carried separately | `identify()` returns `what` / `where` / `content` alongside a composite `identity`. The composite never replaces them, because section 5.3 cannot tell MOVED from NEW without them apart. |
| 5.1 per-subject WHERE | `SPEC`, one entry per registered `finding_subject`, each carrying a `why_stable` argument that `--explain` prints. Five loci are the design's; `RUNTIME_OBSERVATION`, `POLICY` and `IDENTITY_ASSIGNMENT` are **derived here** and flagged as the weakest-defended rows. |
| 5.2 exclusions | structural: every component reads through a per-subject key allowlist, so an excluded field is never read rather than filtered. `--selftest` mutates all 20 and asserts the identity is unchanged. |
| 5.6 symbol required for coarse WHAT | a CWE-only WHAT with no `symbol_path` is refused, not hashed. |
| 5.7 no baseline authority over secrets | `is_secret_finding` is refused outright, so nothing in the ledger ever needs to hold secret-derived material. |
| the refusal discipline | `UNFINGERPRINTABLE` with a named reason and `identity: null`. Never a partial hash. Routes to `EVIDENCE_UNTRUSTED`. |

**Built since, as libraries with local proofs (2026-10-14, lane `identity-ledger`):**

| section | built as | proven by |
|---|---|---|
| 5.3 cascade and cardinality rule | `scripts/finding_match.py` -- a pure function; groups by (subject, WHAT, CONTENT) so nothing moves across subjects; ledger filtered to one environment; an unusable ledger is `BASELINE_UNAVAILABLE` for every finding | `tests/prove_baseline_cascade.py` (the 4.3 item 5 forced-failure demonstration) |
| 5.4 ledger and `first_seen` | `scripts/baseline_ledger.py` -- one JSON document on the protected branch, allowlisted fields, read from git refs only: grandfathering from the merge base, removals from the tip | `tests/prove_ledger_read_authority.py` |
| 5.4 "written by a separate, reviewed change" | `scripts/propose_ledger.py` -- produces a pull-request payload, refuses PR events and non-default refs, never re-dates `first_seen`, never removes an unobserved entry | `tests/prove_propose_ledger.py` |
| 5.5 alias table, declared upgrade, reconciliation report | `scripts/rule_family.py` | `tests/prove_rule_family_upgrade.py` |
| 9.4 anchored tier | `scripts/finding_correlation.py` | `tests/prove_anchored_correlation.py` |

Vocabulary: section 12.1 and 12.2 are registered as `finding_baseline_state` and
`finding_identity_match`, with section 12.6's merge advice taken (no separate generation-change
namespace; no `MOVED` baseline value). 12.3-12.5 remain candidates.

**Still not built, and nothing pretends otherwise:** any job that calls the above (no workflow runs
the cascade, reads the ledger or opens a ledger PR), the three rungs, the remediation track,
severity, fix availability and the SLA. The cascade is library code over identities the reporter
does not yet hand it: `scan_report.py` computes WHAT/WHERE/CONTENT and keeps only the composite.

**One addition the design did not have.** `identity_scope`, two values:
`DURABLE_ACROSS_RUNS_AND_UPGRADES` and `VALID_WITHIN_ONE_RELEASE_ONLY`. Seven subjects are durable.
`RELEASE` is not, and `finding_subject`'s own registered rule is why — *a finding whose subject is a
running resource outlives every release that touched it, and naming it by release loses it at the
next deploy.* A RELEASE fingerprint is perfectly computable and worthless as a ledger key, which is
the worst combination available: it would pass every test and lose every finding at the next deploy.
The scope field makes that visible at the point of use instead.

**Two content policies, not one.** `LITERALS_PLACEHOLDERED` for source constructs, so a constant
tweak or a formatter rollout is not a NEW finding. `VALUES_VERBATIM` for IaC, resources, policy and
RBAC, because there the value **is** the finding: placeholdering it would make
`public_network_access_enabled = false` match the ledger entry for `= true`, so a remediation would
read as still open and — far worse — an introduced finding would match a closed entry and be
grandfathered. That error is in the permissive direction, and this is the one distinction a single
fingerprint shape across eight subjects cannot express.

#### Not wired into the workflow, and that is a decision

`kit-scripts` does not fetch scripts — it **inlines their full text** into `reusable-security.yml`
and uploads the result as a digest-pinned artifact. So adding this to `kit-scripts` is not free:

```
reusable-security.yml now          382,392 bytes   72.9% of GitHub's 512,000-byte limit
if inlined (48,399 + indentation)  439,389 bytes   83.8%
```

`check_workflow_size.py` already warns that this file is *approaching* the limit, and the kit's own
history is that it sat **108 KB over** the limit for six days, starting zero times, while the
self-test stayed green. Spending 11% of the remaining headroom on a component whose consumer — the
cascade and the ledger — does not exist yet buys nothing and costs the thing that already failed
once.

**So the delta to every workflow file in this commit is zero bytes.** The script is canonical,
importable and self-testing, and `inline_normalizer.py --check` still reports exactly six inlined
scripts. It gets inlined when section 5.3 and section 5.4 exist and there is something in the
pipeline that calls it — and by then the decomposition in `SECURITY_WORKFLOW_DECOMPOSITION_PLAN.md`
should have settled whether `reusable-security.yml` is still one file at all.

**Trigger to revisit:** the first commit that implements the matching cascade. **That trigger has
fired** (`scripts/finding_match.py`). The inlining question itself is moot since the report runs
from the kit through a `$/` composite beside the identity modules (owner decision OD-1, commit
6635ca6); what is owed now is the job wiring, not bytes.

---

## 6 · Severity: whose number is it

The SLA in §8 hangs entirely off severity, which makes severity the weakest link in the model. It has
to be specified before the SLA means anything.

**Severity is the organisation's, and it is derived, not copied.** Inputs:

- every scanner's own reported severity — **all of them preserved, none overwritten**;
- the external score where one exists, as a **vector**, not a number (CVSS base is not environmental
  and a bare 7.5 discards the part that matters);
- exploitation and exposure signals — known-exploited status, whether any tool established
  reachability;
- the environmental modifiers of the **cell**: internet-facing versus build-time-only, data class,
  blast radius. A medium on an internet-facing service is not a medium on a build tool.

**A derivation does not mutate evidence.** `disposition_type`'s invariant says it for dispositions and
it holds here: the original scanner severities are preserved forever; `effective_severity` is an
additional field with a recorded **formula version**.

**When two scanners disagree:** take the **highest** as the provisional effective severity, and
**record the disagreement explicitly as a signal for a human**. Never average. `FINDING_CLASSIFICATION.md`
already states the principle for corroboration and it applies identically to conflict: "when
detectors conflict, that surfaces for a human rather than averaging away." Failing toward stringency
is the right default because under-rating is the failure that stays quiet.

**Overrides.** Upward is free — it is a strengthening. Downward is a governance act with a named
authority and an expiry, because it moves the SLA deadline, and a knob that moves a deadline is a
weakening under `control_weakening` whether or not it looks like one.

**Re-scoring is a dated event, and the deadline arithmetic is fixed so it cannot be gamed in either
direction:**

```
new deadline = min( existing deadline , re-score date + period(new severity) )
```

An upward re-score can bring a deadline earlier and can never extend one. A downward re-score can
never extend a deadline at all without a named approval. Neither direction can produce an instant
mass breach larger than one period, and neither can be used to buy time.

**A severity formula change is a declared event with the same reconciliation obligation as a scanner
upgrade.** An unversioned severity formula silently re-dates every finding in the estate the day
somebody edits it.

---

## 7 · Fix availability is its own axis

> **"Fix it instead of blocking" presumes a fix.**

When there is no patch, no upstream release and no available mitigation, putting a finding on a
remediation track is a promise with a date attached that nobody can keep — and the date passing then
looks like negligence rather than like the upstream reality it is. Fix availability must be
**established**, not assumed.

| value | meaning | may take the remediation track? |
|---|---|---|
| `FIX_AVAILABLE` | a patch, version or configuration change exists **and is applicable to this consumer** | **yes** |
| `MITIGATION_AVAILABLE` | no fix, but a compensating control exists and can be put in force here | **yes — on a different track, see below** |
| `NO_FIX_AVAILABLE` | upstream has none; the thing cannot currently be remediated | **no.** Requires a decision, not a schedule |
| *fix availability not established* | nobody has established which of the above is true | **no.** A gap, never a benign default |

### 7.1 Why `MITIGATION_AVAILABLE` takes a track, and what its deliverable is

It takes a track because it has an **achievable, verifiable action with a date** — which is the only
thing a track can honestly hold. But its deliverable is different, and conflating the two is how a
mitigation quietly becomes a fix in the record:

- a `FIX_AVAILABLE` track completes when **the scanner stops reproducing the finding**. The
  disposition that closes it is `REMEDIATED`, which the taxonomy already marks `self_invalidating` —
  "if the finding still reproduces, the disposition is STALE OR WRONG and must not suppress." That
  self-falsification is the entire value of using the registered term.
- a `MITIGATION_AVAILABLE` track completes when **the compensating control is in force and
  evidenced**. The finding remains open and observable. The disposition that results is `MITIGATED` —
  again the registered term, whose registered note already says it is "NOT the same claim as 'the
  scanner is wrong' and NOT the same as 'we accept it as-is'".
- and because a compensating control can lapse silently — a WAF rule removed, a network boundary
  redrawn, a feature flag flipped — **a `MITIGATED` disposition carries its own expiry for
  re-verification**, not a closure. It is the one disposition whose evidence has to be re-established
  rather than merely re-approved.

### 7.2 What `NO_FIX_AVAILABLE` requires instead

Not a schedule. One of:

- `ACCEPTED_RISK` with a named authority, a stated rationale, a stated condition and an expiry; or
- removal of the exposure — drop the dependency, remove the component, isolate the path. This is a
  remediation, so it may take a track; but it is a *different* remediation from the one upstream is
  not providing, and the record must say which one is being done.

### 7.3 Fix availability that has not been established

The kit's convention for a value nobody has established is not silence, and every namespace that
needs one carries its own: `VERSION_UNKNOWN`, `COVERAGE_UNDETERMINED`, `IDENTITY_UNVERIFIED`,
`platform_applicability.UNKNOWN`, `finding_classification.UNKNOWN` ("Not yet established. NEVER
assume clean"). The governing invariant is already registered:
`defaults_are_suspicious_at_assurance_boundaries` — "there is NO implicit default from unknown to
known."

So the candidate namespace in §12 carries its own not-established value, following that convention
rather than inventing a new idea. Its treatment: **a finding whose fix availability is not
established may not take a track and may not be grandfathered.** At `run` it routes to
`DECISION_REQUIRED` until somebody establishes it. Establishing it is cheap; assuming it is how a
track fills up with promises nobody checked.

**Observed while checking:** the kit spells its not-established values four different ways across
namespaces (`UNKNOWN`, `VERSION_UNKNOWN`, `NOT_ESTABLISHED`, `COVERAGE_UNDETERMINED`). That is not a
defect in any one namespace, and it is the shape `TAXONOMY_DRIFT.md` warns about — a near-miss
spelling reads as blank. Worth a maintainer's attention independently of this document.

---

## 8 · The grandfather clause, and its expiry

> "Already in production, fix it instead" with no date is **permanent amnesty**, and it is the
> loophole every team eventually finds.

### 8.1 It is not a new disposition class

Checked first, and the registered vocabulary already holds it. A pre-existing finding authorised to
proceed while it is fixed is exactly `disposition_type.ACCEPTED_RISK`: "the finding is valid and
remains. Authorized to proceed temporarily or conditionally", with `evidence_must_show` = "who
accepted it, under what conditions, until when", and required fields that already include `created`,
`expires`, `approver_role` and `evidence_ref`.

**The grandfather clause is therefore `ACCEPTED_RISK` plus two mandatory additions:** a
**remediation track reference**, and an **expiry computed from the SLA rather than chosen**. No new
disposition type is proposed. The disposition is what makes it non-blocking; the track is what makes
it get fixed; and neither alone is the clause.

### 8.2 The SLA

| effective severity | term |
|---|---|
| CRITICAL | **7 days** |
| HIGH | **1 month** |
| MEDIUM | **6 months** |
| LOW | **12 months** |

These are the owner's numbers and they are **policy, not architecture**. The taxonomy already draws
that line: `capability_origin.OVERLAY_SPECIFIC_POLICY` — "their values, not the capability. A 3-4
digit ticket rule is policy; the ability to enforce a configurable range is not." The mechanism must
accept a configured table. This table is the configured value.

### 8.3 When the clock starts

**From `first_seen` where `first_seen` is known and claimable. Otherwise from baseline
establishment — recorded as an unestablished age, never asserted as an age.**

"Claimable" is not a new idea either. `provenance_identity.observation_time` already tiers the sources
of a time claim and marks which may be claimed:

| tier | source | claimable | use here |
|---|---|---|---|
| 1 | the artefact carries its own collection time — a scanner's `startTimeUtc` | yes | establishes `first_seen` |
| 2 | a sidecar written by the collecting process at the moment it ran | yes | establishes `first_seen` |
| 3 | a date in a filename | **no** | routing only |
| 4 | file mtime | **no** | see below |
| 5 | nothing | no | age not established |

That namespace's warning about tier 4 is precisely the trap here: filesystem time "looks
authoritative and is systematically wrong in the direction that makes stale evidence look fresh."
A baseline that dated its entries from the day the ledger file was written would be doing exactly
that, at estate scale.

So an entry with no claimable earlier observation carries `age_established: false`, and the record
says **"first observed by us on <date>; the finding may be older"** — never "first seen <date>". The
distinction costs one field and is the difference between a record and a story.

### 8.4 A finding older than its SLA is breached on day one

Stated plainly, because this is the part most likely to be got wrong:

> **A critical that has been in production for two years does not get a fresh 7 days because today is
> the day we started measuring.**

Resetting the clock because measurement just began is "silence renews a disposition" wearing a new
coat, and the taxonomy already names that failure: `REOPENED_BY_LAPSE` — "the finding never changed;
its disposition expired… silence must never renew a disposition."

Consequences that follow and must be built in:

**Establishing a baseline must not launder the age of what it baselines.** Where a claimable
`first_seen` exists, the deadline is `first_seen + period`, which may already be in the past. Where it
does not, the deadline is `baseline establishment + period`, and the record simultaneously states that
the age is unestablished and may be older. The second case is weaker than the first and must never be
reported as the first.

**A baseline that produces zero day-one breaches is either a young repository or a laundered
baseline.** On a real legacy estate, day-one breaches are the expected output. If the first run
produces none, that is a finding about the baseline, not a fact about the code.

**But the day-one breach set must not instantly wall the team either** — that is the founding failure
arriving through the SLA instead of through the gate. So:

- The day-one breach set is a **one-time, dated, enumerated cohort decision**, addressed to a named
  authority, with a scheduled burn-down and a per-severity sub-deadline so the cohort does not all
  come due on one morning.
- That decision **does not reset any clock**. It records an **accepted, dated breach**. The record
  says *"breached; accepted until <date>; by <who>; burn-down <schedule>"*. It never says *compliant*.
- The cohort is **closed at establishment**. Only identities present in the ledger at the
  establishment commit may be members. Nothing may join later. Anything else is a per-finding
  decision with a per-finding approver.

Cohort approval exists because per-finding approval of ten thousand inherited findings is not a
control; it is a week of clicking that produces a rubber stamp. Closing the cohort at establishment
is what stops it becoming a permanent intake pipe.

### 8.5 What happens at breach

**Both escalation and blocking, staged — because escalation alone makes the SLA decorative and
immediate blocking alone gets the gate switched off.**

| stage | state | routing | who |
|---|---|---|---|
| deadline passes | breached | `DECISION_REQUIRED`, and the breach is named in the run summary | escalation authority per §8.6 is notified with the finding, its age, its fix availability and its owner |
| grace period, per severity (CRITICAL: none; longer severities: short and configured) | breached, awaiting decision | `DECISION_REQUIRED` | the authority must produce a **new dated decision**: fix landed, re-scoped, risk accepted with a new expiry, or exposure removed |
| grace expires with no decision | **`REOPENED_BY_LAPSE`** | `BLOCKED` at the rung's normal strength | nobody — this is automatic, and that is the point |

`REOPENED_BY_LAPSE` is the registered term and it is exactly right: the finding never changed, its
disposition expired. In enforcement it is now indistinguishable from a NEW finding. In the **record**
it remains distinguishable forever — `first_seen` is preserved, the lapse is dated, and the history
shows a decision that was allowed to expire rather than a defect that was introduced. That
distinction is why the class exists.

**A new decision after a lapse does not restore the original deadline.** It is a new dated decision
with its own expiry, and the lapse stays in the history.

### 8.6 Who decides at breach

A function of severity and of `team_pattern`, reusing the registered patterns:

| `team_pattern` | what is available |
|---|---|
| `full_team` (5+) | a security reviewer distinct from author and approver decides |
| `small_team` (3-4) | CODEOWNERS routing; a reviewer who is not the author |
| `pair_devs` (2) | mutual review; **no separation of duties on an exception** — record it as such |
| `solo_dev` (1) | separation is unavailable. The decision **escalates outside the repository** to an org-level authority, and the repo records an UNVALIDATED HUMAN-WORKFLOW PATH |

`team_pattern`'s registered rule already says a solo repository "cannot prove the human half of the
operating model" and that these paths are "not failures, and not to be reported as passing either". A
solo developer approving their own breached CRITICAL is not a control, and a model that let it look
like one would be worse than having no approval step.

### 8.7 How the SLA interacts with `NO_FIX_AVAILABLE`

**The clock still runs, the breach still happens, and that is a deliberate decision rather than an
accident of the model.**

A 7-day clock on something nobody can fix will breach and keep breaching. The alternative — pausing
the clock when upstream has no fix — reopens permanent amnesty through a different door, because
`NO_FIX_AVAILABLE` is *asserted once* and nobody ever re-checks it. Upstream ships a patch, and the
finding sits behind a stopped clock indefinitely.

So the clock runs, and what breach **demands** differs by fix availability:

| fix availability | what breach demands |
|---|---|
| `FIX_AVAILABLE` | the fix, or a named authority's dated decision |
| `MITIGATION_AVAILABLE` | the compensating control in force and evidenced, or a dated decision |
| `NO_FIX_AVAILABLE` | **re-establishment of fix availability first** (has upstream shipped?), then a re-decision by a named authority — at escalating seniority on each recurrence |

**`NO_FIX_AVAILABLE` carries a re-check cadence tied to the SLA period**, because "no fix exists" is a
claim with a shelf life, and it is the single most attractive thing in this model to assert and then
forget.

**And `NO_FIX_AVAILABLE` does not block on the NEW-versus-PRE-EXISTING axis.** It converts to a
decision: `DECISION_REQUIRED`, resolved into `ACCEPTED_RISK` with a named authority and an expiry.
While that acceptance is unexpired the run proceeds with advisory; when it lapses, `REOPENED_BY_LAPSE`
blocks. **The blocking consequence therefore lands on the decision lapsing, not on upstream's
inability** — which puts the consequence where the agency actually is. A team cannot be permanently
blocked by a vendor's silence, and it also cannot be permanently free of it.

### 8.8 Anti-laundering rules

These are the loopholes teams find, in the order they find them:

1. **A lapsed finding cannot be re-grandfathered by re-baselining.** Ledger entries are append-only
   with respect to `first_seen`. A re-baseline may add entries; it may never reset one. A whole-repo
   re-baseline is itself a governance act with a named approver and an expiry.
2. **Touching the file does not make it new, and moving it does not make it old.** A move is a
   recorded event, not a reset.
3. **Grandfather status attaches to a finding identity, never to a file, a path prefix, a directory
   or a component.** A NEW finding introduced into a file full of grandfathered findings is NEW.
4. **A finding cannot be grandfathered into an environment it was never present in.** The ledger is
   keyed by `(identity, environment)`. "Pre-existing in dev" is not "pre-existing in prod". A
   promotion to a stricter environment with no ledger entry there meets a NEW finding at that gate.
   The evidence for presence in an environment is a scan of the **deployed artefact** — which
   `scan_depth.revalidate` already describes: "deployed artifact ONLY — image digest and SBOM. No
   source scanning: the source did not change, the world did." Where an estate has no such scan, the
   honest fallback is a **declared, dated assumption of inheritance**, recorded as an assumption, and
   never a silent inheritance.
5. **A track with no closures is amnesty with paperwork.** A cell whose track has recorded zero
   verified closures in a period is a `DECISION_REQUIRED` at its next promotion review, regardless of
   how many of its entries are unexpired. An untouched track is indistinguishable from amnesty right
   up until the morning everything expires at once.
6. **A grandfathered finding the scanner stops reporting is `POTENTIALLY_ABSENT`, not closed** —
   §5.3, and the registered rule, unchanged.
7. **Closing a ticket does not clear a finding.** Only the scanner not reproducing it clears it
   (`REMEDIATED` is self-invalidating). Otherwise ticket closure becomes the cheapest suppression
   mechanism in the estate.

---

## 9 · Deduplication, and where it sits relative to raising anything

> Five scanners finding one issue must not raise five tickets, or the team learns the pipeline is
> noise.

### 9.1 Dedupe never collapses observations

The kit has already decided this and the decision holds: **corroboration is not duplication.**
`disposition_type`'s invariant warns about "destructive deduplication wearing governance perfume", and
`FINDING_CLASSIFICATION.md` records the live case — OSV reported 14 findings and Trivy 7 in the same
`package-lock.json`, and collapsing them would have thrown away the strongest evidence available:
that two detectors with different rules and different data arrived at the same place.

So a layer is inserted rather than a merge performed:

```
observations  ->  correlation  ->  cluster  ->  at most one ticket
   (kept            (adds a         (one remediation
    forever)         cluster key)    obligation)
```

**One cluster is one remediation obligation is at most one ticket.** Five scanners produce five
observations, one cluster, one ticket, and `evidence_confidence.observed_corroborated` recorded with
**every contributing scanner named**. The naming is not decoration: `evidence_confidence`'s registered
warning is that dropping tool attribution "is what caught a dead flawfinder covered for by cppcheck".
A cluster that recorded only "corroborated" would let a dead detector hide behind a live one, which is
the same defect this layer exists to avoid, arriving through the correlation door.

### 9.2 Where it happens

**After classification. Before ticketing. Never before enforcement.**

- **Enforcement counts clusters, not observations** — otherwise a well-covered repository is punished
  for having more scanners, which is a direct incentive to remove one.
- **The gate's evidence is the observations** — every one of them, preserved, attributed.
- **Correlation and ticketing happen outside the PR run.** Both need the ledger and the ticket
  system; the PR run must not write to either (§5.4). A PR run consumes cluster identity; it does not
  create it.

### 9.3 Cross-scanner identity is harder than it sounds

It is worth saying why, rather than waving at it, because a design that assumes this is easy will
produce a correlation layer that quietly merges unrelated findings — which is worse than five
tickets, since the merged-away finding leaves no trace.

- **SCA is the only class with a genuine external anchor** (CVE / GHSA / OSV / PURL), and even there:
  one GHSA maps to several CVEs, OSV aliases are not transitive in practice, and ecosystem advisories
  disagree about affected version ranges. Matching on an alias *set* intersection is better than
  matching on an id, and still not exact.
- **SAST findings have no shared identifier at all.** Semgrep's rule and CodeQL's query are different
  claims about overlapping code. "Same CWE, same file, overlapping range" is a **heuristic**, not an
  identity, and treating it as identity is how two different defects in one function become one
  ticket.
- **Container findings are the same package seen through a different package database.** Epoch
  handling, distro backport suffixes and vendor-specific severity re-ratings all differ, and two
  scanners can legitimately disagree about whether a backported fix applies at all. Their
  disagreement is information.
- **Nothing correlates across subject classes.** A SOURCE finding and a RESOURCE finding about "the
  same problem" are two obligations with two owners and two fixes, and `finding_subject` already
  warns that a finding whose subject is a running resource outlives every release that touched it.

### 9.4 Correlation confidence is recorded, and only the strong tier acts

| tier | basis | effect |
|---|---|---|
| **anchored** | a shared external identifier plus matching package coordinates | clustered automatically |
| **proposed** | heuristic agreement — same CWE family, overlapping locus | **proposed only.** Not applied to enforcement. A human confirms or splits. |
| **singleton** | nothing else agrees | its own cluster |

**A proposed cluster must never suppress the observation it clustered away.** If a cluster is later
split, both members return to acting on their own terms, each keeping its own `first_seen`. A split is
a recorded event, like a move.

### 9.5 Ticket hygiene

- **The ticket carries the cluster key, and the pipeline looks up by cluster key before creating
  anything.** Without that, a re-run makes a second ticket for the same cluster, and the team learns
  within a fortnight that the pipeline is noise.
- **Ticket state is not finding state.** See §8.8 rule 7.
- **A cluster with an open ticket still blocks or does not block on its own terms.** Having a ticket
  is not a disposition. A ticket is where the work is tracked; a disposition is where the
  authorisation lives; and letting the first stand in for the second means anyone who can file a
  ticket can authorise an exception.

---

## 10 · How every one of these decisions is recorded

A rung and a cherry-pick are both governance positions somebody will have to explain in six months.
The kit's third structural failure is "declarations drift free of implementations", and its named
remedy is the pattern it has already applied three times: **a declared registry, the actual usage, and
a check that fails on divergence.**

| decision | recorded as | required fields | reconciled against |
|---|---|---|---|
| rung registration per (repo, environment) | repo policy file, protected branch, CODEOWNERS | repo, environment, rung, approver, date, review trigger | the effective minimum the run actually emits |
| cherry-pick | same file | control, direction, reason, authority, expiry or review trigger | the floor — a below-floor pick fails the policy check |
| promotion / demotion | same file, prior value retained | from, to, evidence refs (§4.3), approver, date; demotion additionally requires an expiry | the promotion evidence itself |
| baseline establishment | ledger header on the protected branch | commit, date, scanner generation, severity formula version, cohort decision ref, approver | the ledger's own contents |
| ledger entry | one record per (identity, environment) | as listed in §5.4 | the run's observation set |
| disposition | existing `disposition_type` record | its existing required fields, plus track ref and SLA-derived expiry | the scanner — `REMEDIATED` is self-invalidating |
| SLA breach decision | dated decision record | finding or cohort, breach date, decision, new expiry, named authority, escalation level | the deadline arithmetic in §6 |
| scanner generation change | reconciliation report | before/after identity sets, alias additions, approver, date | the identity sets themselves |
| severity formula change | same shape | formula version, approver, date, affected deadline changes | the recomputed deadlines |
| cluster confirm / split | event record | cluster key, members, confidence tier, who, when | the observation set, which is never mutated |

Three properties are required of all of them:

**On the protected default branch, under CODEOWNERS.** Same rule and same reason as dispositions and
the ledger: a decision readable from the PR that it governs is a self-signed decision.

**Emitted into the run record.** A step summary must show the governance position, not only the
result. A rung held in a file that no run mentions is a declaration with nothing to reconcile against
— and the kit has already watched a weakening exist in configuration while the run "was reported
identically to one that passed honestly".

**Carrying an expiry or a review trigger.** `validation_debt_state.IMPLEMENTATION_HELD` is the shape
to copy: it "carries an activation TRIGGER rather than only a date, because it returns to scope when
the thing it waits on starts. The date remains as a backstop so it cannot be held indefinitely without
anyone looking." A rung registration should return to review when the repo's environment set changes,
its team pattern changes, or its exposure changes — with a date behind it so that none of those
happening is not the same as nobody looking.

---

## 11 · Vocabulary reused, by name

Everything in this column is registered in `secure-cicd-kit/assurance-taxonomy.yaml` v1 and is used
here with its registered meaning. Nothing in this document redefines any of it.

| reused | where and how |
|---|---|
| `routing_result` — `PROCEED`, `PROCEED_WITH_ADVISORY`, `DECISION_REQUIRED`, `BLOCKED`, `EVIDENCE_UNTRUSTED`, and its precedence order | §1.1 as the rung lattice; §3 for broken scanners; §7.3; §8.5 |
| `finding_classification.REOPENED_BY_LAPSE` | §8.4, §8.5 — a lapsed SLA is exactly this class |
| `finding_classification.POTENTIALLY_ABSENT` | §5.3 cardinality deficit; §5.5 upgrade disappearances; §8.8 rule 6 |
| `finding_classification.UNKNOWN` and the "never assume clean" convention | §7.3 |
| `disposition_type` — the protected-branch consumption rule | §5.4, quoted as the reason the baseline obeys the same rule |
| `disposition_type.ACCEPTED_RISK` | §8.1 — the grandfather clause is this, plus a track and an SLA-derived expiry. No new disposition type proposed. |
| `disposition_type.MITIGATED` | §7.1 — what a mitigation track produces, with its own re-verification expiry |
| `disposition_type.REMEDIATED` and `self_invalidating` | §7.1, §8.8 rule 7 — the scanner clears a finding, not a ticket |
| `disposition_type.FALSE_POSITIVE` and `secrets_rule` | §5.7 — the narrow path for inherited secret noise |
| `disposition_type` invariant — a disposition does not mutate evidence | §6 (severity derivation), §9.1 (dedupe) |
| `control_weakening` — `GATE_SOFTENED`, `WEAKENING_IN_FORCE`, `WEAKENING_UNATTRIBUTED`, `WEAKENING_EXCEPTION_EXPIRED`, `CONTROL_RECONFIGURED`, and the attribution rule | §2.1, §2.2, §4.2, §6 |
| `policy_mode` — "changes ENFORCEMENT, never VISIBILITY" | §1.1 |
| `environment_tier` — sandbox / dev / test / uat / prod, uat and prod both production | §3, §4.1 |
| `team_pattern` — solo_dev / pair_devs / small_team / full_team, and UNVALIDATED HUMAN-WORKFLOW PATH | §4.3, §8.6 |
| `scan_depth.revalidate` | §8.8 rule 4 — deployed-artefact evidence for per-environment pre-existence |
| `scan_depth.DEPTH_REDUCED` | §1.1 by implication — a rung must never be allowed to reduce depth |
| `finding_subject` — SOURCE / IMAGE / IAC_PLAN / RESOURCE / and the rest | §5.1 WHERE scaling; §9.3 |
| `provenance_identity` field list, and `observation_time`'s claimable tiers | §5.4, §8.3 |
| `evidence_confidence.observed_corroborated` and its tool-attribution warning | §9.1 |
| `toolchain_currency` — "newer exists is not upgrade now" | §5.5 |
| `capability_origin.OVERLAY_SPECIFIC_POLICY` | §8.2 — the SLA numbers are policy, the mechanism is not |
| `validation_debt_state.IMPLEMENTATION_HELD` — trigger plus date backstop | §10 |
| `discovery_state.COVERAGE_GAP` / `coverage_state.UNSUPPORTED_PRESENT` | §4.3 by implication — unscanned code is a coverage declaration, never a baseline entry and never a finding |
| invariants `authority_never_grows_from_loss`, `absence_is_not_a_negative_observation`, `defaults_are_suspicious_at_assurance_boundaries`, `a_node_is_not_a_path` | throughout; §3 and §7.3 most directly |

---

## 12 · CANDIDATE registrations — proposed, not adopted

> **These are CANDIDATES.** Registering them would assert they had been decided, and they have not
> been. `TAXONOMY_DRIFT.md` is explicit that registration is the **third** remedy, after correcting a
> malformed term and after reusing an existing one, and that a pre-filled block "is a candidate
> registration, not a fix". Each block below therefore states what was checked first and why nothing
> fitted — and each must survive the four questions (semantics, namespace, transitions, consumers)
> before anybody pastes it anywhere.

### 12.1 `finding_baseline_state` — CANDIDATE

**Checked first:** `finding_classification` owns what a RED result *means* (kit defect, true finding,
false positive) and a true finding is NEW or PRE-EXISTING orthogonally to that, so the two cannot
share a namespace without one value carrying two models. `disposition_type` is an *authorised
decision* about one finding — baseline state is an **observation**, established by evidence and
authorised by nobody, and putting it there would let an observation wear an approval.
`discovery_state` and `coverage_state` are about scope, not about a finding's age.

```yaml
  finding_baseline_state:
    description: >-
      Whether this finding existed before the baseline for this (repo, environment) cell, and on
      what evidence. An OBSERVATION, never an authorization.
    consumers: [security-gate at the run rung, remediation track, promotion review]
    rule: >-
      A BASELINE STATE THAT COULD NOT BE COMPUTED IS NOT PRE-EXISTING. Identity failure resolves to
      EVIDENCE_UNTRUSTED, never to the permissive side.
    values:
      NEW:
        definition: No matching identity in the ledger read from the protected default branch.
      PRE_EXISTING_BASELINED:
        definition: Matched an entry whose first_seen predates this evaluation.
      PRE_EXISTING_AGE_NOT_ESTABLISHED:
        definition: >-
          Matched, and no claimable observation time exists for the earliest observation. Older than
          the baseline by at least the baseline's own age; how much older is unknown.
        rule: >-
          MUST NOT be reported as PRE_EXISTING_BASELINED. The SLA clock runs from baseline
          establishment and the record says the age is unestablished.
      PRE_EXISTING_BY_DETECTION_CHANGE:
        definition: >-
          Appeared only because a scanner generation or rule set changed. The code is not new; the
          detection is.
        rule: >-
          Never NEW, and never an open-ended grant. Takes a track like any other pre-existing
          finding.
      MOVED:
        definition: Matched on WHAT and CONTENT at a different locus, resolved unambiguously.
        rule: first_seen is carried forward. A move is an event, never a reset.
      BASELINE_UNAVAILABLE:
        definition: The ledger could not be read, so NEW and PRE-EXISTING cannot be distinguished.
        rule: >-
          Yields routing_result.EVIDENCE_UNTRUSTED. MUST NOT default to either side -- one bypasses
          the rung entirely and the other blocks the estate.
```

**Not registered here:** `REOPENED_BY_LAPSE` and `POTENTIALLY_ABSENT`, which already exist in
`finding_classification` and are cross-referenced rather than respelled.

### 12.2 `finding_identity_match` — CANDIDATE

**Checked first:** `artifact_identity` asks whether the artefact a control inspected is the one that
was published — bytes and a registry, a different question, and its own entry already insists it is
not `release_ownership` for the same reason. `provenance_identity` is the identity that must be
**bound at capture** and lists `finding_fingerprint` as one of its fields — it owns *carrying* an
identity, not *matching* two of them across runs. Nothing owns the match outcome.

```yaml
  finding_identity_match:
    description: >-
      The outcome of matching a current finding against the baseline ledger. Five answers, never a
      boolean, because "could not compute" and "no match" are opposite facts about the evidence.
    consumers: [baseline matcher, remediation track, promotion review]
    rule: >-
      AMBIGUITY IS RESOLVED BY CARDINALITY, NEVER BY GUESSING WHICH ONE MOVED WHERE. The model
      records that it does not know which is which, and enforces on the count, which it does know.
    values:
      IDENTITY_MATCHED_EXACT:   {definition: WHAT, WHERE and CONTENT all agree.}
      IDENTITY_MATCHED_MOVED:   {definition: WHAT and CONTENT agree at a different locus, and exactly one ledger entry is available to match.}
      IDENTITY_AMBIGUOUS:
        definition: A (WHAT, CONTENT) group holds more than one entry or more than one current finding.
        rule: >-
          min(N,M) are continuations, surplus is NEW, deficit is POTENTIALLY_ABSENT. The ambiguity
          about WHICH is recorded and changes no enforcement outcome.
      IDENTITY_UNMATCHED:       {definition: No ledger entry shares WHAT and CONTENT. The finding is NEW.}
      IDENTITY_UNCOMPUTABLE:
        definition: A component could not be derived, so no match was attempted.
        rule: NOT a NEW finding and NOT a match. EVIDENCE_UNTRUSTED for this finding.
```

### 12.3 `fix_availability` — CANDIDATE

**Checked first:** `disposition_type.MITIGATED` is the *decision* that a compensating control is in
force and authorised; `MITIGATION_AVAILABLE` is the *fact* that one exists and could be. Collapsing
them would let the existence of an option read as the option having been taken.
`toolchain_currency.UPDATE_BLOCKED_BY_COMPATIBILITY` is about the kit's own tools, though its rule
transfers exactly — "we cannot upgrade" without a named incompatibility "is a deferral wearing a
technical costume". `validation_debt_state` is about an unproven capability of the kit, not about a
finding's remediability.

```yaml
  fix_availability:
    description: >-
      Whether the thing this finding names can currently be fixed, established rather than assumed.
      A remediation track is a schedule, and a schedule over something nobody can fix is a promise
      with a date attached that nobody can keep.
    consumers: [remediation track admission, SLA breach routing, promotion review]
    rule: >-
      ONLY AN ESTABLISHED VALUE ADMITS A FINDING TO A TRACK. Not-established is a gap, never a
      benign default -- defaults_are_suspicious_at_assurance_boundaries applies unchanged.
    values:
      FIX_AVAILABLE:
        definition: A patch, version or configuration change exists AND is applicable to this consumer.
        rule: Upstream having shipped something is not the same as it being applicable here.
      MITIGATION_AVAILABLE:
        definition: No fix, and a compensating control exists that can be put in force here.
        rule: >-
          Takes a track whose deliverable is the control IN FORCE and EVIDENCED, closing to
          disposition_type.MITIGATED with its own re-verification expiry -- never to REMEDIATED.
          The finding remains open and observable.
      NO_FIX_AVAILABLE:
        definition: Upstream has none; the thing cannot currently be remediated.
        rule: >-
          Requires a DECISION, not a schedule: ACCEPTED_RISK with a named authority and an expiry,
          or removal of the exposure. Carries a re-check cadence tied to the SLA period, because
          "no fix exists" is a claim with a shelf life.
      FIX_AVAILABILITY_NOT_ESTABLISHED:
        definition: Nobody has established which of the above is true.
        rule: >-
          May not take a track and may not be grandfathered. Routes to DECISION_REQUIRED at the run
          rung until established.
```

**Spelling flagged for the maintainer:** the kit currently spells its not-established values four
ways (`UNKNOWN`, `VERSION_UNKNOWN`, `NOT_ESTABLISHED`, `COVERAGE_UNDETERMINED`). This candidate
follows the `NOT_ESTABLISHED` form. Whichever form is adopted, it should be adopted once — a
near-miss spelling reads as blank, which `TAXONOMY_DRIFT.md` calls worse than a wild one.

### 12.4 `remediation_track_state` — CANDIDATE, and the weakest of the four

**Checked first:** `validation_debt_state.ACCEPTED_DEBT` is extremely close — "dated, owned, unexpired
deferral. Passes, reported loudly", with `expires` and the rule that silence never renews it. It is
not reusable only because its subject is explicitly an unproven **capability of the kit**, and its
`BLOCKING` value fails the build, which is not what a remediation track does to a run.
`disposition_type` owns the authorisation; this would own the *progress of the obligation the
authorisation creates*.

```yaml
  remediation_track_state:
    description: >-
      The progress of the obligation created when a pre-existing finding was authorized to proceed.
      The disposition says it may proceed; this says whether anyone is doing anything about it.
    consumers: [remediation track, promotion review, breach escalation]
    rule: >-
      A TRACK WITH NO VERIFIED CLOSURES IS AMNESTY WITH PAPERWORK, and it is indistinguishable from
      a working track until the morning everything expires at once.
    values:
      ON_TRACK:          {definition: Unexpired, owned, and the track has recorded activity.}
      BREACHED_ACCEPTED: {definition: Past its SLA deadline, with a dated decision from a named authority that has not itself expired. The record says BREACHED, never COMPLIANT.}
      BREACHED_UNDECIDED:{definition: Past its deadline with no decision. Routes to DECISION_REQUIRED and, after the severity's grace, to REOPENED_BY_LAPSE.}
      CLOSED_VERIFIED:   {definition: The scanner no longer reproduces it, over a scope shown to cover where it lived.}
      TRACK_STALLED:     {definition: Zero verified closures for this cell in a period, regardless of how many entries are unexpired. A DECISION_REQUIRED at promotion review.}
```

**Alternative, and it may be the better answer:** carry these as **fields on the disposition** rather
than as a namespace. The disposition already has the finding, the owner, the approver and the expiry;
the track adds a deliverable and an activity record. A reviewer should weigh that before registering a
fifth namespace for one mechanism.

### 12.5 `correlation_confidence` — CANDIDATE

**Checked first:** `evidence_confidence` is about how strongly a **capability claim** of the kit is
supported, consumed by the capability matrix and validation debt. `observed_corroborated` is close in
spirit and is about the wrong subject. This is about whether two findings are the same finding.

```yaml
  correlation_confidence:
    description: >-
      How strongly two observations are established to be about the same remediation obligation.
      Clustering decides how many tickets exist; it must never decide how many findings exist.
    consumers: [correlation layer, ticketing, enforcement counting]
    rule: >-
      CORROBORATION IS NOT DUPLICATION. Clustering NEVER removes an observation, and a proposed
      cluster never suppresses what it clustered. Every contributing scanner is named, so a dead
      detector cannot hide behind a live one.
    values:
      CLUSTER_ANCHORED:
        definition: A shared external identifier (CVE/GHSA/OSV alias set intersection) plus matching package coordinates.
        rule: The only tier that clusters automatically and the only one enforcement counts as one obligation.
      CLUSTER_PROPOSED:
        definition: Heuristic agreement only -- same CWE family, overlapping locus.
        rule: >-
          PROPOSED, never applied to enforcement. A human confirms or splits. SAST findings have no
          shared identifier and this tier is where that fact lives.
      CLUSTER_SINGLETON:
        definition: No other observation agrees. Its own obligation.
      CLUSTER_SPLIT:
        definition: A previously clustered group was separated. Each member resumes acting on its own terms, keeping its own first_seen.
```

### 12.6 The candidate count is itself a warning

Five namespaces for one mechanism is a lot, and a reviewer should expect to reject or merge at least
two. In order of what should merge first: **12.4 into `disposition_type` fields**, and the
generation-change event in §5.5 into `finding_baseline_state` rather than becoming a sixth namespace
of its own. **Green-by-taxonomy-inflation is `ignoreFailures: true` wearing reading glasses**, and
that applies to a design document proposing vocabulary just as much as to a pipeline clearing a drift
gate.

---

## 13 · What could not be settled

Named because a document that answered everything about a mechanism nobody has built would be lying.

**~~Whether `enforcement_rung` supersedes `policy_mode`.~~ SETTLED 2026-09-23 — see §4.0.** The rung
is the business's root declaration; `policy_mode` becomes a **derived** value computed from it and
is no longer settable by a caller. `policy_mode.adoption` remains close to `crawl` and
`policy_mode.strict` close to `run` without a baseline — they were never synonyms, and the
resolution is a derivation, not a deletion. What is now owed to the maintainer is narrower and
mechanical: **the derivation table itself**, and the check that fails a run in which `policy_mode`
was supplied rather than computed. Rung vocabulary may be registered once that table exists.

**Whether cross-scanner SAST identity is achievable at all.** §9.3 argues it is not, beyond
CWE-plus-locus heuristics that must stay `CLUSTER_PROPOSED`. That is an argument, not a measurement.
Nobody here has run two SAST engines over one corpus and counted how often the heuristic is right.

**The stability of CONTENT hashing under a repository-wide reformat.** This is the single most likely
mass-false-NEW event and its magnitude is unmeasured. The declared-reformat-event mitigation in §5.6
is a design response to an unquantified risk. The threshold at which a commit counts as a reformat is
a guess until somebody measures it.

**Whether estates actually have deployed-artefact evidence.** §8.8 rule 4 keys pre-existence to the
environment and requires a `revalidate`-depth scan of what is running to prove it. Many estates do not
have that, and the fallback — a declared, dated assumption of inheritance — is materially weaker.
Whether the strong form is reachable in practice is unknown here.

**Ledger scale and review burden.** A large legacy estate produces tens of thousands of entries. It is
not established that a reviewed file on a protected branch is the right storage at that size, nor what
the review of a ledger diff of that size actually consists of, nor whether CODEOWNERS routing survives
it. A ledger nobody can review is a governance artifact in name only.

**Whether the fingerprint should be salted per repository.** Salting improves the privacy of a
committed ledger; a global scheme allows cross-repo correlation and estate-wide dedupe. These conflict
and the trade-off is not made here.

**The merge-base-versus-tip race.** §5.4 reads grandfathering from the merge base and removals from the
tip, which is correct by the floor rule and has a live cost: an author can be blocked by a ledger
removal that somebody else merged, for a finding they did not introduce. Safe, and possibly
intolerable in practice. Not settled.

**Monorepos and vendored code.** A finding in a vendored third-party directory has a different owner
and often no possible fix by the team that holds the repo. Neither the ledger key nor the ownership
model here has an answer, and `capability_origin` does not cover it either.

**Where the cluster-to-ticket boundary lives.** The ticket system is in neither repository. The
idempotency rule in §9.5 assumes a lookup by cluster key exists; whether the chosen tracker supports
one, and who owns that integration, is outside both.

**Every number in this document.** The SLA table is the owner's and is recorded as policy. The
consecutive-run count for promotion, the grace periods after breach, the reformat threshold and the
track-stall period are all placeholders awaiting an owner's decision, and none of them should be
implemented as a constant.

---

## 14 · The one-paragraph version

A rung is a registered governance position per repository and per environment, expressed as a
minimum routing result per control, that cherry-picks may only raise. `run` is unreachable until a
finding has a durable identity — three components, no line numbers, no rule ids, no paths as strong
signals, no severity, no secret material — matched by a cascade that resolves ambiguity by counting
rather than guessing, against a ledger on the protected default branch that a pull request may read
and may never write. Pre-existing findings are not exempt; they hold an `ACCEPTED_RISK` disposition
with a remediation track, admitted only where a fix or a mitigation has been **established** to
exist, expiring on a severity SLA whose clock starts at a **claimable** first-seen and otherwise at
baseline establishment with the age recorded as unestablished — so that something already older than
its SLA is breached on day one and the record says so. At breach it escalates to a named authority and
then, absent a decision, becomes `REOPENED_BY_LAPSE` and blocks. A broken scanner never demotes any of
this; it yields `EVIDENCE_UNTRUSTED`, and so does a ledger that cannot be read.
