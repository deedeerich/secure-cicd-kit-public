# Prototypes — FROZEN. Not shipped, not called, not a workflow.

These files are **design experiments**. Nothing here runs, nothing references them, and nothing may.

They live under `docs/` and **not** under `.github/workflows/` deliberately. A `.yml` in the workflows
directory is a workflow whether or not anyone meant it to be: GitHub would parse it, `actionlint` would
lint it, and `tests/check_workflow_size.py` globs `.github/workflows/*.yml` and would measure it. A
prototype sitting in the production directory is the same defect class this kit exists to name —
something present that nobody decided to make present.

## What is here

| file | what it is |
|---|---|
| `reusable-security-grouped.yml` | a 14-job restructure of `reusable-security.yml`, SAST grouped by language |
| `build_grouped.py` | the generator that produced it — every scanner body lifted verbatim by line range from the live file, so any delta is attributable to restructuring rather than transcription |
| `scan_step_state.sh` | the per-STEP state recorder the grouped design needs, replacing per-JOB capture |

## Why it is frozen

Recorded so the next person does not re-derive it:

1. **Grouping does not shrink the file. It grows it.** 349,029 bytes today → 414,733 here, +18.8%.
   Per-step capture costs bytes per-job capture did not, and de-matrixing CodeQL replicates its step
   block six ways. **414,733 is also above the 350 KB warn threshold**, and above this prototype's own
   design projection of 356,281.
2. **Without the `kit-scripts` bootstrap job it is 794,017 bytes** — 282 KB past GitHub's hard limit,
   and worse than the 608.8 KB that stopped the file starting on 2026-09-16. Grouping makes the
   bootstrap *more* load-bearing, not less.
3. **It does not fix the defects it was credited with.** The `image` job here still has no redaction
   step, no SARIF upload and no publish, so the `trivy-image` evidence loss survives intact; and
   gosec's `-no-fail` survives.
4. **The verdict count does not depend on it.** The reason to want this restructure was 14 scanner
   verdicts becoming 24. That split is edits to the `add` rows and the `--expect` roster in the
   existing `report`/`security-gate` jobs. **It needs no regrouping of any job**, and CodeQL's matrix
   legs are already separate jobs at runtime.

Point 4 is the one that matters. **Twenty-four independent scanner verdicts are a correctness
requirement; fourteen jobs are one packaging proposal.** They were conflated, and separating them
removed the entire argument for promoting this.

## What it is still good for

Measured evidence, kept rather than repeated:

- the real byte cost of per-step state capture;
- the permission unions a merge creates — notably that folding CodeQL into six language jobs spreads
  `actions:read` to every linter and every transitive dependency in them;
- a worked implementation of recorded-and-surfaced failure tolerance that is demonstrably not
  `soft_fail_sast` (captured, propagated to the gate, surfaced in an annotation);
- proof that the four states stay apart — turned-off, not-applicable, clean, collection-failed.

Revisit only when real run timings exist. Every duration in the cost model behind it is **assumed**;
there has been no run history since 2026-09-16.
