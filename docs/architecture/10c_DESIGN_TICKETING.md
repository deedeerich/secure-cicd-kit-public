# 10c · Design: ticketing (reconciler, trackers, ledger, exceptions coming due)

```
Kept:      2026-11-07, against the trunk at c1420ea. Components: 03c_COMPONENTS_TICKETING.md.
Code:      reusable-ticket-reconcile.yml, reusable-propose-ledger.yml, reusable-exception-due.yml,
           reusable-ticket-reference.yml; scripts/reconcile_tickets.py, scripts/ticket_model.py,
           scripts/ticket_routing.py, scripts/ticket_governance.py, scripts/ticket_intake.py,
           scripts/tracker_freshservice.py, scripts/propose_ledger.py, scripts/exception_due.py,
           scripts/exception_history.py, scripts/ticket_reference.py, scripts/remediation_sla.py.
Deeper:    TICKETING_CONTRACT.md, TICKETING_BACKENDS.md, JIRA_AUTH_AND_ROUTING.md,
           WORK_ITEM_HIERARCHY.md, ARCH_03_TICKETING.md, docs/ticketing/.
```

## 1 · Purpose

Turn every finding the kit established on the protected default branch into **one** ticket in the right
project, keep it current, and close it only on verified clearance, never by the person who fixed it.

## 2 · Inputs and outputs

| Kind | What | Notes |
|---|---|---|
| input | `findings.json` from the same run's security report | a default-branch run only (test runs on other branches) |
| input | `backend` (`jira`, `azdo`, `github`, `freshservice`), `environment`, `test_environment`, `default_branch`, `mode` (`reconcile`, `sweep`, `resurface`), `apply`, `kit_repository`, `kit_ref` | `apply: false` prints the plan and writes nothing |
| input | the tracker credential from the environment (names in 07 section 5) | one job holds it |
| input | the ledger `.security/ticket-ledger.json` and the register's `ticket_routing` | read from the protected branch |
| output | `armed`, `routing_result`, `ticketing_state`, `controls_unavailable` | `ticketing_state` is never a gate input |
| output | artifacts `ticket-reconcile-ATTEMPT` (run record and ledger proposal), `kit-ticket-outbox-ID` | the ledger itself changes only by a merged PR |

## 3 · How it works

1. **Guard**: armed only for push, schedule or dispatch; the default branch is real, any other branch
   (not a schedule) is test, in `ticketing-test`, with `[TEST]` tickets.
2. **Identify**: each finding's full correlation key (KDEC-038 for SAST and secrets).
3. **Route**: the first matching `ticket_routing` rule, most specific scope first; no area is a triage state
   with an owner role and a deadline (KDEC-043).
4. **Look up first**: the ledger binding, then the tracker's stamp, then every ticket, manual ones too.
5. **Write**: update the bound ticket; create one per cluster only after a complete search found none,
   within the creation ceiling; a near match is created flagged possible-duplicate; an unreachable
   tracker goes to the outbox, drained first next time.
6. **Close**: only on verified clearance in a full run, or by a second person; a fixer's close is
   pending verification; a regression reopens.
7. **Propose the ledger** as a pull request; a person merges it.
8. **The clock**: on a schedule, past-due deferrals are swept (no credential) and exceptions coming due
   resurface on their ticket, saying plainly they were excepted before.

## 4 · States, in plain words

| State | In plain words |
|---|---|
| `ticketing_availability.TICKETING_UNAVAILABLE` | The ticket tracker could not be reached, refused the credentials, or a write failed. |
| `ticketing_availability.TICKETING_NOT_CONFIGURED` | No ticket tracker is configured (or two are), so no tickets were created or checked. |
| `ticketing_availability.TICKETING_TEST_TARGETS_REAL_PROJECT` | A test ticketing run was pointed at a real Jira project, so nothing was sent. |
| `ticket_lookup_outcome.BINDING_AMBIGUOUS` | More than one ticket claims the same finding, so the kit updated none of them. |
| `ticket_lookup_outcome.BINDING_UNESTABLISHED` | The ticket search did not finish (rate limit, outage or expired credential). |
| `ticket_lookup_outcome.IDENTITY_NOT_ESTABLISHED` | A finding has no stable identity, so no ticket can be looked up or created for it. |
| `ticket_governance_state.CORRELATION_LABEL_COLLISION` | A ticket carries this finding's label but its full key belongs to a different finding. |
| `ticket_governance_state.PROVENANCE_MISMATCH` | The integration named on the ticket (the via label) is not the identity that actually wrote it. |
| `ticket_governance_state.AREA_UNRESOLVED` | No routing rule gave this finding an owning area, so it waits in triage with an owner role and a deadline. |
| `ticket_governance_state.TAG_PRESERVATION_NOT_ESTABLISHED` | Freshservice replaced the ticket's whole tag list and the kit could not prove nobody else's tag change was lost. |
| `ticket_intake_state.TRACKER_INTAKE_PARTIAL` | The search of existing tickets did not finish. |
| `exception_resurfacing.EXCEPTION_OVERDUE` | An exception has expired, or its expiry date cannot be read. |
| `exception_resurfacing.RESURFACE_FAILED` | Raising a due exception on its ticket failed. |
| `ticket_reference_outcome.NO_CANDIDATE` | The pull request description does not mention a ticket. |
| `remediation_track_state.BREACHED_UNDECIDED` | A known finding is past its fix deadline and nobody has decided what to do. |

## 5 · Failure modes

| Failure | What happens | Proof |
|---|---|---|
| the tracker is down | entries go to the durable outbox; the next run drains it first | `tests/prove_ticket_lifecycle.py` |
| the search is incomplete | nothing is created from it; "not looked at" is not "nothing found" | `tests/prove_ticket_idempotency.py` |
| two tickets claim one finding | none is updated; a person resolves it | `tests/prove_ticket_idempotency.py` |
| a scanner upgrade renames a rule | the rule-family table keeps the identity | `tests/prove_rule_family_upgrade.py` |
| a run on a PR | not armed; no credential requested | `tests/prove_ticket_reconcile_workflow.py` |
| a test branch aimed at a real project | refused, nothing sent | `tests/prove_jira_auth_and_routing.py` |
| a person edits Freshservice tags while the kit writes | notes by default; tag mode re-reads and reconciles | `tests/prove_freshservice_tracker.py` |
| an exception keeps being renewed | the renewal cap refuses; history comes from git | `tests/prove_exception_lifecycle.py`, `tests/prove_exception_history_derived.py` |

## 6 · Decisions

| Decision | What it settled |
|---|---|
| KDEC-004 | Jira is the backend; Azure DevOps second; GitHub Issues not extended (later added to the shared contract) |
| KDEC-013 | the Jira reference gate is core; a consumer's ticket-number range is its only overlay part |
| KDEC-017, KDEC-018 | ticketed exceptions; exceptions resurface with their history |
| KDEC-024 | findings reach tickets; close on verified clearance; RECURRED; one ticket per finding; bounded runs |
| KDEC-028 | Jira without a personal binding; routed by policy; test ticketing chosen by the branch |
| KDEC-037 | every ticket, manual ones included, is searched before one is created |
| KDEC-038 | deterministic keys for SAST and secret findings |
| KDEC-043 | the full correlation key is the only identity; a `via` label is a claim; unrouted is triage; multicloud children; Freshservice is the fourth tracker |
