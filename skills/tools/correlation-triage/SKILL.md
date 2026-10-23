---
name: correlation-triage
description: >-
  Triage what the kit's correlation layer could not settle on its own -- an alias-chain or
  CWE-plus-file PROPOSAL, a CONTESTED_ANCHORED finding a peer scanner covered and did not report,
  a severity disagreement, a cross-scanner merge, or a BINDING_AMBIGUOUS split -- and record the
  decision through the one path that changes enforcement (a reviewed disposition on the protected
  default branch). Use when a ticket run routes DECISION_REQUIRED for correlation, or a ticket
  carries the disagreement or superseded label.
---

# correlation-triage

A tool-tier skill (FUTURE_WORK.md section 3, FW-§3b; KDEC-024). It is the human half of
`scripts/finding_correlation.py` and the ticket lifecycle in `scripts/reconcile_tickets.py`. The
machine half never guesses; this skill is where a person decides, with the evidence in front of
them, and leaves a record the next run reads.

**Independent agreement raises confidence. Source observations stay intact. Disagreement
escalates; it is never averaged away.** Nothing in this skill deletes an observation, a ticket or
a ledger entry.

## What you are looking at

| tier or state | where it comes from | what the kit already did | what is owed to you |
|---|---|---|---|
| `anchored` | identical durable identity, or one shared advisory identifier common to every member, within one subject and one locus | ONE ticket naming every scanner | nothing, unless it is also contested |
| `proposed` | an alias CHAIN whose ends share nothing, or the same CWE in the same file with no shared identifier | each member ticketed ON ITS OWN; the proposal is listed in the run record (`proposals`) | confirm (they are one finding) or split (they are not) |
| `singleton` | nothing else agrees, or no durable identity | its own ticket, or `IDENTITY_NOT_ESTABLISHED` and none | nothing for correlation; identity gaps go to the identity owner |
| `CONTESTED_ANCHORED` | a peer of the SAME detection class (sca, container, secrets) ran, established its row, covered the file, and did not report it | ticketed anyway, labelled `<stamp>-disagreement`, the peer named in the block, `DECISION_REQUIRED` once | decide which scanner is right |
| severity disagreement | the members' scanners report different severities | the WORST is the effective severity; every value is in the block | nothing unless the worst is wrong -- then a downward override needs a named authority and an expiry (remediation_sla) |
| merged (D4) | two tickets for what now anchors as one finding | the OLDEST ticket survives and names every scanner; the other is closed as superseded, labelled `<stamp>-superseded`, pointing at the survivor | check the merge was a real duplicate |
| `BINDING_AMBIGUOUS` | members bound to obligations another cluster also claims (a split), or one key with several tickets | nothing created, nothing updated, every candidate named | declare the canonical ticket |

SAST and IaC findings are never contested by a silent peer: their rule sets differ, so one tool
saying nothing about another tool's rule observes nothing about it.

## Inputs to open

1. The run record (`ticket-run-record.json` in the `ticket-reconcile-<attempt>` artifact): the
   `proposals`, `disagreements`, `merged`, `needs_decision` and `potentially_absent` lists.
2. `findings.json` and `findings-coverage.json` from the same run's `security-report-<attempt>`
   artifact: what each scanner saw, and what each scanner ESTABLISHED (ran, read, scope).
3. The ticket itself: the machine-owned block names the cluster key, every member identity, every
   scanner and its severity, the confidence and its basis, the run and the commit.
4. `.security/ticket-ledger.json` on the default branch: bindings, `merged_into`, `clearance`,
   `recurrences`, `sla`.

## Procedure

1. **Name the question in one line** -- "is osv-scanner's silence on go.mod a negative for
   CVE-X?", "are A and C the same finding though they share no identifier?". A triage with no
   stated question cannot be checked later.
2. **Read the evidence, not the labels.** For a contest: is the advisory in the peer's database
   at the version scanned; did the peer actually read that manifest (its coverage row's `scope`
   and `parse_state`)? For a proposal: do the members share a package coordinate, a symbol, a
   fix? For a merge: do both tickets describe the same coordinate and the same fix?
3. **Decide, and record it where enforcement reads it** -- never only on the ticket:
   - the finding is real and the peer is wrong: remediate; nothing to record but the fix.
     Optionally open a scanner-defect issue against the peer.
   - the finding is wrong: a `FALSE_POSITIVE` disposition request with the evidence, approved by
     a role distinct from the requester, merged to the protected default branch under CODEOWNERS
     (TICKETING_CONTRACT.md sections 1 and 2). Closing the ticket does not do this.
   - a proposal is one finding: record the confirmation in the ledger proposal pull request; the
     next run binds them to one obligation. A proposal is NEVER applied by the kit.
   - a merge was wrong: reopen the superseded ticket by hand, remove its `merged_into` in the
     ledger pull request, and say why on both tickets.
   - an ambiguity: name the canonical ticket in the ledger pull request; mark the others as
     duplicates by hand. The kit never marks a duplicate (TC 5.2).
4. **Leave the ticket readable**: one comment stating the question, the evidence and the decision,
   and where the decision is recorded. Write OUTSIDE the machine-owned block; inside it is
   overwritten.

## Never

- Never average two severities, and never lower one without a named authority and an expiry.
- Never treat a contested finding as suppressed. The peer's silence is a question, not a pass.
- Never close a ticket to clear a finding. Only the scanner no longer reproducing it clears it --
  and the kit closes the ticket itself, citing the run, when that is verified (T-09).
- Never edit the cluster stamp, an expiry, an approver or a due date on a ticket. The authority is
  the record on the protected branch; the ticket is a rendering of it.
- Never confirm a proposal because the titles look alike. Titles are not identity.

## What confidence changes

`CONTESTED_ANCHORED` changes WHO is asked (a person, once, `DECISION_REQUIRED` on the ticket run)
and what the ticket says. It changes nothing in the security gate: a finding blocks or proceeds on
its rung whatever its confidence, and the ticketing run never feeds the gate (KDEC-024).
