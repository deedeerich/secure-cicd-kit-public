# The proof rule

**A guardrail is proven when its counterexample has been run and refused, and its valid
counterpart has been run and allowed. Until both receipts exist, the claim is unproven.**

The operator's words, which this document exists to make binding:

> *"We need to test to fail whatever mechanism our role or guardrail or whatever feature it is and
> disprove it and to also prove it."*

---

## The procedure

1. **State the claim.** One sentence, in terms of what is refused or allowed. "The reconciler is
   safe" is not a claim; "an unapproved risk acceptance cannot reach the tracker" is.
2. **Construct a counterexample.** The input that *should* defeat the claim.
3. **Run it through the real path.** The command line, or the enforcement function the real
   caller reaches — never a helper that merely resembles it.
4. **Show the refusal,** and show that it refused *for the stated reason*. A refusal for an
   unrelated reason is a coincidence, and a coincidence will be refactored away.
5. **Run the valid counterpart.** The input that *should* succeed.
6. **Keep both receipts.** In the test, in the output, and in the file that claims the guardrail.

---

## The four cases

Every guardrail owes all four. Three of them are not optional extras — each one catches a
distinct way a control lies.

| Case | Question | What its absence hides |
|---|---|---|
| **Allowed** | Does valid input complete the intended action? | A control that refuses everything. The pipeline is broken and the suite is green. |
| **Attack** | Can the prohibited action get through? | A control that is decorative. The claim was never tested at all. |
| **Missing-evidence** | Does absent, partial or unreadable evidence refuse a clean verdict? | A verdict manufactured from an absence — the worst failure, because it reads as a pass. |
| **Recovery** | After a refusal, is the state accurate and can work safely resume? | A control that is correct once and then wedges the system. People disable those. |

### The two-sided rule

- If the **counterexample passes**, the control is **disproven**. Say so; do not reword the claim.
- If **both** cases fail, the control is **unusable**. "Everything is refused" is not security, it
  is a broken pipeline, and it will be switched off by the first person it blocks.
- If **either** case was not run, the claim is **unproven**. Not "probably fine". Unproven.

### Why half a control passes a test suite

This rule was written after a real instance. The ticketing path's approval gate had one mutation
test: *the human-in-loop gate is bypassed*. It passed. It would also have passed against a
reconciler that refused **every** creation — and that reconciler is exactly what the gate had
become, because a blanket "every mutation needs a human" invariant had been imported from a prior
engine. The suite could not tell a control from a brick, because it only ever pushed in one
direction.

A gate has two failure modes. Test one and you have tested nothing.

---

## Reaching the real enforcement point

**A helper test cannot earn the claim.** If the claim is about what the command line refuses, the
test runs the command line. If it is about what a function enforces, the test calls the function
the real caller calls — not a private helper, not a reimplementation of the check inside the test.

Two practical consequences:

- **Assert on the reason, not only on the refusal.** Where a property is guarded twice, a test
  that checks only "it was refused" will pass with the guard it names deleted, because the other
  guard answers in its place. `scripts/ticket_model.py` carries a worked example: the ordinary
  transition path cannot reopen a deferral, and the mutation-class table *also* refuses that
  call, so the test requires the refusal to name `reopen_deferred`.
- **A mutant that cannot fail is not evidence.** Where a property is genuinely guarded twice and
  no single change can defeat it, retire the mutant and record *where the property is proven*
  instead of leaving a mutant in the list to be counted.

---

## Scope

This document governs **new and corrected guardrail work**. It is applied in full to the
ticketing guardrails:

| Guardrail | Claim | Where the four cases run |
|---|---|---|
| The mutation-class gate | Routine reconciliation runs unattended; a disposition needs a role and a readable reason; an unclassified mutation refuses. | `scripts/ticket_model.py --self-test` §2, §9 · `scripts/reconcile_tickets.py --self-test` §13 · `tests/prove_ticket_idempotency.py` (mutants + the four-case CLI section) |
| The past-due review obligation | An elapsed deferral becomes `DEFERRAL_PAST_DUE`, stays `DEFERRED`, is visible unasked, and clears only through an approved reopen or an approved renewal to a future date. | `scripts/ticket_model.py --self-test` §13 · `scripts/reconcile_tickets.py --self-test` §17 · `tests/prove_ticket_idempotency.py` (the four-case CLI section) |

It is **not** retrofitted to the rest of the kit. That is a larger job and claiming it here would
be the same overclaim this rule exists to catch. `docs/assurance/TEST_COVERAGE_AUDIT.md` and
`docs/assurance/VALIDATION_DEBT.md` are where the remaining gaps are accounted for.
