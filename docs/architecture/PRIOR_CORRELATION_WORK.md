# Correlation already exists in the reference estate. Read it before building stage 11.

```
Status: RECORDED 2026-09-25. NEUTRALIZED 2026-10-02 — names removed, lessons kept.
Purpose: stop stage 11 being re-derived from scratch when the work is already done.
Truth State: READ — the implementations were read, not run, and not reviewed for correctness.
```

> **Why this file was rewritten rather than deleted.** The original named consumer repositories and
> prior-engagement product names, and the export-safety gate refused it with the right instruction:
> *"Keep the LESSON, remove the NAME. A kit that is employer-neutral by intent and not by
> construction discloses one consumer to the next."* Deleting it would also have deleted the lesson,
> and the lesson is the only reason the file exists. The locations are recorded privately; what
> follows is what a neutral kit is allowed to carry.

## What exists, in the reference estate

| artifact | size | what it does |
|---|---|---|
| a cross-scanner correlator | 443 lines | correlation across scanners with a **weighted confidence score** |
| a pipeline-attribution correlator | 550 lines | finding-to-pipeline attribution, five matching strategies with declared confidence tiers |
| an evidence-graph ontology | — | 12 node types, 14 edge types, and the composite match key |
| a per-run dedupe workflow | — | keys on `cve:pkg` and `test_id:file:line:cwe`, local to a single process |

## What it establishes that this kit's design does not

**A weighted score, not a boolean match.** The cross-scanner correlator scores
`rule_location_hash_match` (0 or 100), `line_drift_window_match` (0–90) and `toolName_match`
(0 or 10), and acts only at **confidence ≥ 85**. This kit's design has a four-level confidence ladder
in prose and no computation anywhere.

**A line-DRIFT WINDOW rather than excluding line numbers.** This kit's fingerprint design excludes
line numbers outright, because they move on every unrelated edit. The reference estate keeps them and
**scores proximity** instead. That retains signal the exclusion throws away, and it is the better
answer where the comparison is between two scanners looking at the same tree at the same moment.

**A measured reason for the composite key, not an assumed one:**

> *"CWE alone is fundamentally insufficient for correlation — **60% of platform-native alerts have no
> CWE**."*

The composite is `CWE + rule_id + file_path + repo + service + code_pattern`, all available fields
evaluated, and a CWE-only match is classified T3 with **no inheritance**. **That 60% is an observation
from a real estate. Nothing in this kit has a number like it.**

**Inheritance has a precondition.** A disposition may only be inherited when the source carries a
mitigation rationale at confidence ≥ medium. Dispositions without rationale cannot propagate — which
is this kit's *"a ticket is not an authorization"* rule, already implemented one layer down.

**A named anti-pattern worth stealing.** *Ontology collapse* — "everything connects to everything.
When a graph has no bounded domains, every query returns noise, every audit is impossible, and every
relationship is meaningless." 12 node types and 14 edge types is stated as the boundary.

## The distinction that must NOT be collapsed when this is adopted

The reference estate's composite key contains `rule_id`. This kit's fingerprint design forbids
`rule_id`. **Both are correct, because they answer different questions:**

| | question | time axis | may it use `rule_id`? |
|---|---|---|---|
| **identity** (this kit, §5) | is this the same finding as last week? | across runs, across upgrades | **no** — a rule rename makes every finding look new |
| **correlation** (reference estate) | are these two findings, from two scanners, the same issue? | one moment, one tree | **yes** — both were produced by the versions in hand |

Merging them produces a key that is either unstable over time or blind across tools. **The two layers
stack:** correlate at a point in time using everything available, then carry the cluster under a
durable identity that survives the next upgrade.

## What was not assessed

Whether any of it is correct, tested, or currently reachable. The per-run dedupe workflow runs in a
workflow whose artifact download resolves to the wrong run, so **it has been processing zero bytes** —
the dedupe logic may be sound and has not been exercised on real input. The two correlators were
**read, not run**.

That last point is itself the lesson this kit already knows under another name: an implementation
that has never processed real input is `authored`, not `observed`.

**Read this before writing stage 11.** The confidence model, the drift window and the 60% figure are
the parts this kit does not have and would otherwise invent worse.
