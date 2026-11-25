# Separation of duties for review findings and their tickets

```
Status:    DECIDED by the owner, 2026-11-04 (KDEC-037). Enforced by scripts/separation_of_duties.py,
           scripts/review_finalize.py (rule R5) and scripts/ticket_submit.py; proven by
           tests/prove_ticket_intake_v2.py V1..V3 and tests/prove_ticket_templates.py T2, T5, T6.
Applies:   every tickets.submit (findings, requests, extensions, closures, triage decisions).
```

## 1. The owner's rule

> "The submitter of the review doesn't get to do the triage review, the fix, and then sign off on their
> own work... They can submit the review and identify what needs to be triaged; they could even be
> talked into doing the work; they just can't be the authority that approves their own work, or
> approves their review after they've completed it. They can move the tickets to closed if their task
> is complete, and it's someone else's responsibility to come behind them and double-check."

## 2. The roles, per item

| role | who | may also be |
|---|---|---|
| **submitter** | the person who submitted the review (`submitted_by` in the review record) | triager, fixer |
| **AI run owner** | the engineer an AI review ran for (`run_started_by`) | triager, fixer |
| **triager** | the person who decided merge / separate on a possible duplicate, or picked what needs triage (`triaged_by`) | submitter, fixer |
| **requester** | the person asking for an exception, exemption, accepted risk, extension (`requested_by`) | submitter, fixer |
| **fixer / assignee** | the person who did the fix (`fixed_by`) | submitter, triager |
| **verifier / approver** | a member of the security team who concurs, verifies or approves | NONE of the above for this item |

One person may hold submitter, triager and fixer. **Nobody approves or verifies anything they
authored**: their review, their triage decision, their fix, their exception request, or an AI run
they started. A bot is never an approver. Identities are compared case-insensitively, with a `[bot]`
suffix and an e-mail domain removed (`a@example.com` is `a`).

## 3. Who may approve

The approvers are the **entire security team**, held as either (KDEC-037 O-37b):

- `list:<name>` -- a list in the central register's `approver_lists` (default `list:review-concurrence`): the SAME
  structure as KDEC-036's AppSec list (`approver_lists.appsec`), GitHub logins, inline or in the shared file the
  register's `approver_lists_source` names -- one mechanism, read by one loader; else
  `.security/reviews/approvers.json`. Being on another list (`appsec`) is not being on this one; or
- `team:<org>/<slug>` -- a GitHub team, its members read through the API host with a members:read token
  (`KIT_API_TEAM_READ_TOKEN`). A team that cannot be read is NOT a list: nothing is approved.

Any member except the author of the work may concur -- including on the AI's work that ran for another
engineer. A concurrence is at most 30 days old (`KIT_API_REVIEW_MAX_AGE_DAYS`) and is the member's
APPROVAL of the pull request that merged the review record (the kit reads it back from GitHub).

## 4. Concurrence: AGREE, or DISAGREE with an alternative

The review record (`kit-review-record/2`) carries `decision`:

- `AGREE` -- the items are written.
- `DISAGREE` with an `alternative` (what the reviewer would do instead) -- nothing is written for the
  items; each is `TEMPLATE_SENT_BACK` and the dissent is recorded in `data.dissent[]` (who, the
  alternative, the review id). A DISAGREE with no alternative is not a finalized review.
- `item_decisions` -- the same, for single items: only those go back.

## 5. Closure is two people (or the kit's own rescan)

1. The fixer may **resolve** their ticket: `resolved -- pending verification`
   (`TEMPLATE_PENDING_VERIFICATION`, label `<stamp>-pending-verification`). It is never final. The
   approvers are notified: "ready to close, please verify".
2. It is **Closed-Verified** only by (a) the kit's rescan that covered the finding and no longer
   reports it, on the branch mapped to the ticket's environment (docs/ticketing/
   BRANCH-SCAN-AND-CLOSURE-PROPOSAL.md), or (b) a verifier who is not the fixer.
3. A verifier may **reject**: the ticket is reopened with the reason. The fixer cannot reject (or
   verify) their own fix.
4. Still pending after N days (default 7, `KIT_API_VERIFICATION_REMINDER_DAYS`): a reminder; after 2N:
   escalated (the priority raised one step). Each once per pending cycle; the tracker's labels are the
   record.

## 6. What enforces it, and how it fails

| check | where | outcome |
|---|---|---|
| the review's concurrer is the submitter, AI run owner, triager, caller, `on_behalf_of` or a bot | review_finalize R5 | `API_REVIEW_NOT_FINALIZED` (nothing read or written) |
| the concurrer is not on the list / in the team, or did not approve the merging pull request | review_finalize R4, R7 | `API_REVIEW_NOT_FINALIZED` |
| the approver requested the exception / extension / exemption, or triaged the triage item | ticket_submit, ticket_templates | `API_TEMPLATE_RULE_REFUSED` + `SOD_SELF_APPROVAL` |
| the fixer verifies their own fix | ticket_submit | allowed, but PENDING (`TEMPLATE_PENDING_VERIFICATION`) |
| the fixer rejects their own fix | ticket_submit | `SOD_SELF_APPROVAL` |

**Residuals.** The kit sees identities as GitHub logins and the names in the record; it cannot know
that two logins are one person. An approver list that holds the whole team is the owner's choice
(O-37b); a smaller list is a configuration, not a code change.
