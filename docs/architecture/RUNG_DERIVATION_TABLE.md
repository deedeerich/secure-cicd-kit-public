# The rung derivation table

**What a registered rung derives, cell by cell, and the one row the source table writes against
its own invariant.**

```
Phase: built as a library with local proofs; NOT wired into the gate (the wiring is a
       separate step: see wiring/gate-rung.patch.md on the lane branch)
Truth State: derived 2026-10-14 from ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md sections
       1-4, 10 and 13, AXES_AND_PHASES.md, SINGLE_PIPELINE_TARGET.md stage 1 and
       section 8.3, against assurance-taxonomy.yaml
Code:  scripts/rung_ladder.py (the table), scripts/enforcement_axes.py (tier and team),
       scripts/policy_registration.py (the file and its reader)
Proof: tests/prove_rung_ladder.py, tests/prove_enforcement_axes.py,
       tests/prove_policy_registration.py
```

ETFB section 13 settled that `policy_mode` is derived from the rung and said what was still owed:
"the derivation table itself, and the check that fails a run in which `policy_mode` was supplied
rather than computed. Rung vocabulary may be registered once that table exists." This is that
table. The vocabulary (`enforcement_rung`, `policy_resolution`, `human_control_availability`) is
registered beside it.

---

## 1 · Rung to per-control floor (ETFB section 1.1, verbatim)

A rung sets, per control class, the **weakest routing result** that control may contribute. The
run's result is the precedence maximum across controls under the registered order
`BLOCKED > EVIDENCE_UNTRUSTED > DECISION_REQUIRED > PROCEED_WITH_ADVISORY > PROCEED`.

| control class | `crawl` | `walk` | `run` |
|---|---|---|---|
| `secrets` | `BLOCKED` | `BLOCKED` | `BLOCKED` |
| `new_critical_high` | `PROCEED_WITH_ADVISORY` | `DECISION_REQUIRED` | `BLOCKED` |
| `pre_existing_on_track` | `PROCEED_WITH_ADVISORY` | `DECISION_REQUIRED` | `PROCEED_WITH_ADVISORY` |
| `pre_existing_track_lapsed` | `PROCEED_WITH_ADVISORY` | `DECISION_REQUIRED` | `BLOCKED` |
| `other_findings` (medium, low, lint) | `PROCEED_WITH_ADVISORY` | `DECISION_REQUIRED` | `DECISION_REQUIRED` |

The source table's "cherry-picked set" row is not a floor of its own; it is the **output** of
section 3 below. Visibility is constant across rungs: nothing here changes what is scanned.

**The row that is not monotone, and is kept.** ETFB section 1.1 states "for every control, `run`
is at least as strong as `walk`" and then writes `pre_existing_on_track` as `DECISION_REQUIRED` at
`walk` and `PROCEED_WITH_ADVISORY` at `run`. That row is the mechanism the document exists for:
"`run` does not grant amnesty; it grants a schedule." The value is kept verbatim; the exemption is
**named** in `rung_ladder.monotone_exempt` and the proof asserts it is exactly that one row, so a
reader meets it rather than a check that was quietly loosened. The reading: at `walk` a
pre-existing finding owes a disposition; at `run` the track **is** the disposition (`ACCEPTED_RISK`
plus a track reference, section 8.1). Whether `walk` should read the same once a track exists is
an owner decision; nothing in the code decides it.

## 2 · Rung to `policy_mode` (derived, never set)

| rung | `policy_mode` | why |
|---|---|---|
| `crawl` | `adoption` | "non-secret findings report without blocking" is `crawl` |
| `walk` | `adoption` | the blocking set is secrets plus cherry-picks; the picks are a mechanism of their own (section 3), and `policy_mode` has no third value |
| `run` | `strict` | "high/critical findings block" |

ETFB section 13: "`policy_mode.adoption` remains close to `crawl` and `policy_mode.strict` close to
`run` without a baseline — they were never synonyms, and the resolution is a derivation, not a
deletion." A run that **receives** `policy_mode` as an input — any spelling, any value, including
the one this table would produce — is `POLICY_MODE_SUPPLIED` and routes `BLOCKED`.

## 3 · Cherry-picks: strengthen only (ETFB section 2)

```
effective_minimum(control) = precedence_max( rung_floor(control), cherry_pick(control) )
```

A pick names a control class from section 1 or a named control (a scanner job; the secret scanner
is the `secrets` class, every other named control is compared against the `other_findings` row,
because a pick on a scanner applies to every finding it reports). Equal to the floor: recorded, no
change. Above: applied, and the divergence is emitted. **Below: `CHERRY_PICK_BELOW_FLOOR`, a
policy defect that fails the policy check by name.** The effective set never contains the
defective value. The downward direction has no representation.

The honest limit (ETFB section 2.1) stands: picks here are **enforcement dispositions**, whose
direction is total. Configuration surfaces — a query suite, a path, a severity list — are not
picks; they stay `control_weakening.CONTROL_RECONFIGURED` in the posture record.

## 4 · Declared versus effective (ETFB sections 4.0, 4.3)

The registration declares the **target**. The promotion evidence sets the **effective** rung, and
the gate obeys the effective one. Evidence items are references, never booleans — configuration
is not evidence:

| to reach | the cell must carry |
|---|---|
| `walk` | `controls_executed_at_baseline` with `consecutive_clean_runs` at least the configured number and an evidence ref · `ledger_populated_and_owned` · `entries_classified` · `human_controls_assessed` |
| `run` | the above, plus `baseline_forced_failure_demonstrated` · `track_closure_verified` · `day_one_fix_availability_established` |

A declared `run` with `walk` evidence resolves `RUNG_EFFECTIVE_BELOW_DECLARED`: not a refusal; the
record carries both. `policy_mode` follows the **effective** rung.

## 5 · Cells, pull requests, demotions (ETFB sections 4.1, 4.2)

- `rung(sandbox) <= rung(dev) <= rung(test) <= rung(uat) = rung(prod)`, and two cells at one tier
  agree. Otherwise `CELLS_NOT_MONOTONE`, a policy defect.
- A pull request resolves at the rung of the **highest environment its merge can reach without a
  further human gate** — the cell's `reachable_from_merge_without_human_gate`, which the file must
  state because it cannot be inferred.
- A rung is not a workflow input. A supplied `rung` **below** the registered one is a
  `GATE_SOFTENED` weakening at `WEAKENING_IN_FORCE`: attributed with a reason, an authority and a
  readable future expiry it routes `PROCEED_WITH_ADVISORY`, otherwise `WEAKENING_UNATTRIBUTED`
  and `DECISION_REQUIRED`. A supplied rung **above** the registered one is ignored: declaring up
  needs section 4 evidence. The registered value governs either way.
- A demotion in the cell's `history` is the same weakening, on every affected run, until its
  expiry; silence never renews it.

## 6 · The two axes read downstream of the rung (L33; AXES_AND_PHASES.md; ETFB sections 3, 8.6)

**`environment_tier`** changes one gate fact: at `uat` and `prod` (both production)
`EVIDENCE_UNTRUSTED` stops the run; at `sandbox`, `dev` and `test` it warns — except on a control
whose effective minimum is `BLOCKED`, which stops when untrusted at every tier (secrets). A tier
may only raise a floor. **Today it raises none**: the AXES_AND_PHASES.md rows that block new
critical/high from `test` upward predate the rung and would make `crawl` unregisterable at `test`;
applying them is an owner decision (lane report). `enforcement_axes.apply_tier` is the only place
a tier may touch a floor, and it cannot lower one.

**`team_pattern`** changes how a floor is satisfied, never whether:

| pattern | second reviewer | approval separation | CODEOWNERS routing | distinct security reviewer | breach authority (8.6) |
|---|---|---|---|---|---|
| `solo_dev` | unvalidated | unvalidated | unvalidated | unvalidated | **escalates outside the repository** |
| `pair_devs` | available | no separation | no separation | unvalidated | mutual review, no separation on an exception |
| `small_team` | available | available | available | unvalidated | CODEOWNERS routing; a reviewer who is not the author |
| `full_team` | available | available | available | available | a security reviewer distinct from author and approver |

"Unvalidated" is `HUMAN_CONTROL_UNVALIDATED`: an UNVALIDATED HUMAN-WORKFLOW PATH, reported and
never rendered as passing. A cherry-pick that `requires_human_control` the pattern cannot provide
is still applied to the floor and its divergence carries that state.

## 7 · Resolution outcomes and where they route

| `policy_resolution` | routes | stops a gate |
|---|---|---|
| `POLICY_RESOLVED` | nothing of its own (findings route under the effective set); a weakening in force routes as attributed | no |
| `POLICY_MODE_SUPPLIED` | `BLOCKED` | yes |
| `CHERRY_PICK_BELOW_FLOOR` | `BLOCKED` | yes |
| `CELLS_NOT_MONOTONE` | `BLOCKED` | yes |
| `CELL_NOT_REGISTERED` | `EVIDENCE_UNTRUSTED` | yes, at every tier: the rung itself is a `BLOCKED`-floor control |
| `REGISTRATION_UNAVAILABLE` | `EVIDENCE_UNTRUSTED` | same |
| `POLICY_NUMBER_NOT_CONFIGURED` | `EVIDENCE_UNTRUSTED` | same |

Nothing resolves to `crawl` because it could not read the file.

## 8 · Every number, and where it lives

All in the registration's `numbers` block, none in code: `promotion_consecutive_clean_runs`,
`sla_period_days` per severity, `breach_grace_days` per severity, `track_stall_period_days`,
`no_fix_recheck_days`, `severity_formula_version`. The shipped example
(`templates/policy-registration.example.json`) carries the owner's section 8.2 table as the
configured value. A missing number is `POLICY_NUMBER_NOT_CONFIGURED`.

## 9 · Not settled here

- the non-monotone row (section 1), and whether `walk` should read `PROCEED_WITH_ADVISORY` once a
  track exists;
- whether the tier table raises floors beyond the untrusted-evidence rule (section 6);
- whether a cherry-pick at `crawl` (the source table says "n/a") is admissible as a strengthening,
  which is how the code treats it;
- every number (section 8).
