# Ticket governance: the key, the via claim, unrouted findings, multicloud findings

```
Status:    PROPOSED (KDEC-043, lane tickets, 2026-11-06). Built and proven locally against stand-ins only.
Enforced:  scripts/ticket_governance.py; scripts/ticket_intake.py (match); scripts/ticket_submit.py;
           scripts/reconcile_tickets.py; scripts/tracker_freshservice.py
Proven:    tests/prove_ticket_governance.py G1-G4 (+ mutants M1-M4); tests/prove_freshservice_tracker.py
           F1-F12 (+ mutants M-F1..M-F4); tests/prove_ticket_templates.py T3, T9; tests/prove_ticket_intake_v2.py V11
Applies:   every tracker: Jira, Azure DevOps, GitHub Issues, Freshservice
```

These rules sit beside the owner's ticket rules (docs/ticketing/SEPARATION-OF-DUTIES.md): a submitter can triage
and fix but never approves their own work; an exact duplicate is linked and closed as a duplicate and the original's
confidence is updated; a near match goes to a person and is never merged; a search that fails never loses the ticket
(it is created in triage as dedupe-pending, or held in the outbox); trust and confidence are both shown; closure is
by rescan or by a second person.

## 1. The correlation key is never truncated as identity

| where the key lives | role |
|---|---|
| the tracker's stamp field (`JIRA_STAMP_FIELD`, `AZDO_STAMP_FIELD`, `FRESHSERVICE_STAMP_FIELD`) | **governed**, the identity |
| the stamp line in the kit's machine-owned block: `secure-cicd-kit-cluster: <32 hex>` | **governed**, the identity (GitHub's only one) |
| a link line in the kit's block on a person's ticket: `secure-cicd-kit-correlation-key: <32 hex>` | **governed**, written when a finalized review links the ticket |
| the label `<stamp>-ck-<32 hex>` (on GitHub, a 50-character short form: the head, a dash, 8 hex of its sha256) | **a search aid only** |

A label hit is checked against the governed key before it counts:

- the governed key is this key: **exact**;
- the governed key is ANOTHER key: **`CORRELATION_LABEL_COLLISION`** -- a search ambiguity, shown to a person as a
  candidate, never merged; the full key decides;
- there is no governed key: **`CORRELATION_LABEL_UNVERIFIED`** -- a candidate for a person.

`tickets.search` reports `linked_cluster_keys` only from governed places; keys read from labels are
`label_key_hints`. **Migration:** a person's ticket linked before this change carries the label but no link line,
so it now shows as a candidate once; the reviewer's `link` decision writes the link line and it is exact from then
on. Kit-made tickets always carried the stamp line and are unaffected.

## 2. A `via` label is a claim

`tickets.submit` may name `via` (e.g. `tines`); the kit writes `<stamp>-via-<name>` on each new ticket, at creation.
Provenance is then established from three sides, compared:

1. the identity the kit's credential **authenticated as** (Jira `/myself`; Freshservice `GET /api/v2/agents/me`,
   UNVERIFIED; GitHub `GET /user`, UNVERIFIED for an installation token; Azure DevOps `connectionData`, UNVERIFIED);
2. the tracker's **record of the write** (Jira's creator, GitHub's issue author, `System.CreatedBy`, Freshservice's
   oldest activity);
3. the identity **registered** for the claimed name: `KIT_INTEGRATION_IDENTITIES` (`name=identity,...`, a repository
   or organisation variable; roles and ids only).

All agree: `PROVENANCE_ESTABLISHED`. Any two disagree: `PROVENANCE_MISMATCH` -- `<stamp>-provenance-mismatch`, a
comment naming the sides, an alert in the answer; a person checks. A side unread: `PROVENANCE_NOT_ESTABLISHED`
(with a claim present, `<stamp>-provenance-unverified`). The answer's item carries the record.

## 3. `area-unresolved` is a triage state

When `ticket_routing` is configured and no rule and no default give a finding an area, the ticket is still created
(the kit default project) with `<stamp>-area-unresolved`, `<stamp>-triage`, `<stamp>-area-owner-<role>` and
`<stamp>-area-due-<date>`, and the ledger records `{state, owner_role, since, due}`. The owner role and deadline come
from the register:

```json
"ticket_routing": { "rules": [...], "unresolved": {"owner_role": "security-triage", "deadline_days": 5} }
```

(defaults: `security-triage`, 5 days). Every reconcile run and the scheduled clock list the unresolved areas; past
the deadline each is `AREA_UNRESOLVED_OVERDUE`, a decision owed (exit 1) naming the ticket and the role. It leaves
the state (`AREA_RESOLVED`, with the rule and date, said on the ticket) when a later run's routing gives it an area.
With no routing configured the kit default IS the area, and nothing is unresolved.

## 4. Multicloud findings: one identity, child obligations

A finding item may carry `obligations` (api/v1/tickets/finding.schema.json): at least two, in Azure AND AWS, each
`{id, cloud, owner_role, asset}`. The parent is ONE identity -- the identifier in its environment
(`multicloud:<environment>`) -- created with `<stamp>-obligations-<n>`. Each child is its own ticket under the parent
with `<stamp>-obligation-<id>`, `<stamp>-owner-<role>` and `<stamp>-parent-<ref>`; the parent gains
`<stamp>-child-<id>-<ref>`.

- A child closes like any ticket: its fixer resolves it (pending verification), and the kit's rescan or someone
  other than the fixer verifies it.
- A verification of the parent while any child is open, missing or unreadable is refused
  **`CHILD_OBLIGATION_OPEN`**.
- When the last child is verified, the parent closes itself (`ticket.close.ALL_CHILDREN_RESOLVED`) and says so.

## 5. Freshservice's whole-list tag write

See docs/architecture/TICKETING_BACKENDS.md section 4A: tags at creation; lifecycle markers on existing tickets as
append-only private notes by default; `tags` mode reads, merges, writes, re-reads and verifies under a per-ticket
lock, reconciles a person's simultaneous edit from the activity history, and says
`TAG_PRESERVATION_NOT_ESTABLISHED` (and asks a person) whenever it cannot prove nothing was lost.

## 6. Residuals (registered: R-29 .. R-32)

Freshservice shapes not on the documentation page are UNVERIFIED until a live run on the owner's personal account;
two repositories writing one Freshservice ticket are not serialised by the per-repository concurrency group; the
Jira and Freshservice description writes have a seconds-wide window between re-read and write; a provenance claim
is only as good as the `KIT_INTEGRATION_IDENTITIES` mapping someone maintains.
