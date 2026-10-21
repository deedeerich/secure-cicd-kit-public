# Your pipeline failed on "Taxonomy drift". Here is how to clear it.

**You are not blocked for long.** This is a two-minute fix in almost every case, and the failing
step prints a paste-ready block. This page is the long version, with the reasoning and worked
examples.

---

## What just happened

A job failed with something like:

```
== DRIFT — enforcement words nobody defined ==
   IDENTITY_UNVERIFIED     used in .github/workflows/reusable-build-docker.yml
   SOURCE_DELTA            used in docs/architecture/DEPLOYMENT_CONTRACT_RECONCILIATION.md

::error title=Taxonomy drift::2 term(s) drive behaviour but are not in assurance-taxonomy.yaml.
```

`scripts/reconcile_taxonomy.py` found all-caps tokens that look like **states** — values something
branches on — in files that drive behaviour, and they are not declared in `assurance-taxonomy.yaml`.

**It is not complaining about your code quality.** It is complaining that a word with consequences
has no definition anywhere.

---

## Why this gate exists

A state vocabulary is only useful if every reader agrees what each value means. When a value is
undefined, two things happen and neither announces itself:

- **A near-miss spelling reads as blank.** A consumer looking for `PARTIAL` does not match
  `PARTIAl`, so it treats the cell as empty — and empty renders as *unqualified*, which is the
  strongest reading available. **A near-miss value is worse than a wild one.**
- **Two implementations invent two spellings.** Six weeks apart, in two files, and nothing
  reconciles them until something downstream quietly takes the wrong branch.

That is the failure this gate is placed ahead of: **an undefined enforcement word is how `PARTIAL`
quietly becomes `PASS` three layers downstream.**

---

## Four remedies, in order — registration is the THIRD

### 1 · Correct an accidental or malformed term — fix the code, not the taxonomy

The most common cause, and the easiest one to get wrong by "fixing" it in the wrong direction.

The step output lists every **registered** term. Read that list first. If your token is one
character off something already there, the taxonomy is right and your code is wrong.

```diff
- if state == "Coverage_Gaps":
+ if state == "COVERAGE_GAP":
```

Registering the typo instead would create two spellings of one concept, which is the exact defect
the gate exists to catch, arriving through the gate itself.

### 2 · Reuse an existing canonical term when the concept is equivalent

Two spellings of one concept is the defect this gate exists to catch. If a registered value
already means what you mean, use it — **even if you would have named it differently**. Your
preferred spelling is not worth a second entry that every future reader has to reconcile.

Search `assurance-taxonomy.yaml` for a sibling before concluding nothing fits.

### 3 · Register a genuinely new concept — after reviewing four things

**This is the third remedy, not the first.** The failing step prints a pre-filled block, and that
block is *scaffolding to save you typing the nesting* — it is **a candidate registration, not a
fix**. Pasting it unreviewed converts a red pipeline into a permanently wrong vocabulary, and a
gate that hands you a green button is not a gate. Green-by-taxonomy-inflation is
`ignoreFailures: true` wearing reading glasses.

Before you register anything, establish four things:

| | |
|---|---|
| **Semantics** | What is precisely true when something is in this state — not a restatement of the name |
| **Namespace** | Does an existing namespace already own this concept? Adding a value to one beats inventing a namespace beside it |
| **Transitions** | What may move into and out of it, and what may never |
| **Consumers** | Who branches on it, and what each of them does with it |

If you cannot answer all four, you do not yet know whether the term should exist — and registering
it anyway is how a vocabulary accumulates values nobody can act on.

**An existing namespace already covers the concept.** Add your value to it. Search
`assurance-taxonomy.yaml` for a sibling value — if `artifact_identity` already holds
`REGISTRY_IDENTITY_PROVEN` and `LOCAL_BUILD_ONLY`, a third identity answer belongs there, not in a
new namespace of its own.

**Nothing covers it.** Add a namespace. The failing step prints this skeleton pre-filled with your
terms; paste it under `namespaces:` in `assurance-taxonomy.yaml`:

```yaml
  your_namespace_name:
    description: >-
      What this set of values is ABOUT, in one sentence a stranger can act on.
    consumers: [the file or job that branches on these values]
    rule: >-
      THE INVARIANT THIS VOCABULARY PROTECTS. What must never be collapsed into what.
    values:
      Your_Term:
        definition: What is true when a thing is in this state.
        rule: When this value must NOT be treated as one of its neighbours.
```

`definition` is required. `rule` is optional and is the field that earns its keep — it is where you
write down the distinction a future reader will otherwise collapse.

**Worked example.** The build workflow began emitting three answers about whether a pushed image is
provably the one that was scanned. Registered as:

```yaml
  artifact_identity:
    description: >-
      Whether the artefact a control inspected is provably the artefact that was published.
    consumers: [reusable-build-docker.yml, render-version-metadata]
    rule: >-
      THREE ANSWERS, NEVER A BOOLEAN. Proven, nothing-was-pushed and could-not-establish are
      different facts, and collapsing them is how an unverified digest inherits a verified reading.
    values:
      REGISTRY_IDENTITY_PROVEN:
        definition: The registry confirmed the pushed manifest's config digest is the one scanned.
        rule: The only value that licenses treating the digest as assurance-bearing.
      LOCAL_BUILD_ONLY:
        definition: Nothing was pushed, so there is no registry claim to agree or disagree with.
        rule: Not a weaker proof. A different question, correctly unanswered.
      IDENTITY_UNVERIFIED:
        definition: A push occurred and the link could not be established.
        rule: COULD-NOT-ESTABLISH IS NEVER ESTABLISHED.
```

Note what the `rule:` lines are doing. None of them describe the value; they each name the mistake
someone would otherwise make.

### 4 · Use ordinary prose formatting when the phrase is explanatory

The gate reads all-caps tokens because that is what state values look like in this codebase. If
yours is a constant, an environment variable, a log string or prose that happens to be shouting,
it is a false positive of a deliberately broad reader.

Rename it, or lowercase it, so it stops looking like a state. `Max_Retries` and `Timeout_Seconds`
are settings, not states — if one of those trips this gate, the fix is on your side and it is
cosmetic.

---

## What is not an option

**Deleting the check, adding an exemption, or listing your file as skipped.**

A gate with an exemption clause is a gate with a bypass, and the bypass outlives whatever reason
opened it. This kit has already watched that happen in the other direction: a deny list nobody
read for two weeks reported CLEAN over five real violations, and five patterns in it matched
nothing at all while appearing correct in every editor.

If the gate is genuinely wrong about your token, option 3 is the honest fix. If the gate is wrong
about a whole *class* of token, that is a defect in `reconcile_taxonomy.py` worth reporting —
change the reader, not the policy.

---

## Checking your fix before you push

```bash
python3 scripts/reconcile_taxonomy.py
```

Exit 0 and `taxonomy OK — every vocabulary token in use is registered.` means you are clear. It
runs in under a second and needs no network, so there is no reason to discover this on a runner
twice.

---

## A related line in the same output, which is NOT a failure

```
-- ORPHANS (registered, used nowhere) --
```

Orphans are terms declared in the taxonomy that nothing uses. **They do not fail the build.** They
are either dead vocabulary or an unimplemented promise, and both are worth knowing about — a
namespace registered ahead of the implementation it describes is a deliberate and cheap way to stop
two implementations inventing two spellings later.

If you see your own new terms listed as orphans, that is expected until something branches on them.

---

## This page tripped its own gate, and that is the worked example

The first draft of this document used real-looking tokens in its examples — a deliberately
misspelled state, two settings that are not states — written in the same all-caps shape the scanner
reads. The scanner read them, correctly, as usage. **The page explaining how to clear taxonomy
drift caused taxonomy drift.**

The fix was option 3, applied to this file: the examples are now written in mixed case
(`Coverage_Gaps`, `Max_Retries`) so they stop looking like states, and every lesson survives intact.

The tempting fix was to exclude `docs/` from the scanner, or to exclude this one file. That would
have been a bypass — and the next document to genuinely introduce a state would have introduced it
invisibly. **When a broad reader produces a false positive, change the thing that looks wrong, or
change the reader. Never carve out the place the reader is not allowed to look.**
