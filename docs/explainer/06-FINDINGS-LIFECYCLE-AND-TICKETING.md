# 06 · Findings lifecycle: identity, ledger, dispositions, ticketing

The scan answers "what is there now". This part is about **the same finding over time**: recognising
it across scanner upgrades, file moves and rewordings; recording that it existed before; deciding what
to do about it; and tracking the work — without letting any of that weaken the gate.

## 1. Durable finding identity (BUILT, proven; partly wired)

`scripts/finding_identity.py` computes a three-component identity — **WHAT** (the weakness, e.g. CWE and
rule family), **WHERE** (symbol and path, or a package coordinate, or a resource address — depending on
the finding's subject class), **CONTENT** (a normalised construct, literals placeholdered, comments
stripped string-aware). It deliberately excludes the scanner name, the rule id and the message text:
any of those changes on a tool upgrade and would orphan every approval keyed on it.

- Nine registered subject classes (`finding_subject`): source, source dependency, image, IaC plan,
  resource, identity assignment, runtime observation, policy and release. Every scanner the report runs maps to one (VERIFIED,
  `prove_subject_covers_roster.py`).
- **Refuse, never degrade**: a finding that cannot be identified is `UNFINGERPRINTABLE` with a reason —
  never an empty string that two findings could share (`prove_identity_durability.py`).
- **Secrets are outside the baseline**: they block at every rung and are never grandfathered. The only
  way past one found secret is a ticketed, finding-scoped exception in the policy register (part 05),
  which is a dated decision, not a baseline entry.

## 2. The baseline ledger (BUILT; read and write paths wired; proven locally, no hosted run)

**Establishing a baseline** (completion ledger F-01, fixed in `a636f5e`; VERIFIED at `078ef90`:
`prove_propose_ledger_establishment.py`). `reusable-propose-ledger.yml` takes an optional
`establish-approver-role` (no default, so never automatic). With no ledger and no role it refuses,
and says why in its workflow outputs `status` and `why`. With a role, it opens an **ESTABLISH pull
request** whose header names the role and asserts no age — and only if CODEOWNERS on the default
branch covers the ledger path; otherwise it refuses. A role given when a ledger already exists is
ignored and the pull request says so: the input establishes, it never re-baselines. Until a consumer
merges such a pull request, runs that name an `environment` read `LEDGER_ABSENT` and the identity
claim (`identity_routing`) is `EVIDENCE_UNTRUSTED`; the gate does not read that value, so nothing
about what blocks changes. Still owed: a starter-template job and one hosted establish-then-propose run.

**What a proposal now also carries** (lane L-F, VERIFIED by the proofs named):
- **One move record** (`b036f5c`): a moved finding is re-keyed with `first_seen` kept, and the move is
  recorded once, as a lineage event in `.security/finding-lineage.jsonl` (plus its head anchor) in the
  same pull request; the ledger entry no longer carries `move_history`, and the reader refuses it.
  The composite's output is now `tree` (files under `.security/` only).
- **Scanner generations** (`417c6ae`, `prove_propose_ledger_generation.py`): a finding first reported
  by a pinned scanner's unreconciled new generation is **held**, never admitted as NEW; the proposal
  opens one reconciliation report per (scanner, from, to), with a window set by
  `reconciliation-window-days` (placeholder 30, owner decision O-06). Only an accepted report admits
  exactly the findings it lists.
- **Presence in an environment** (`4329f2b`): the first proposal for an environment writes a declared,
  dated `environment_presence` assumption to the ledger header; it is never re-dated.
- **The ticket ledger** (`c1c3dae`, `prove_propose_ledger_ticket_ledger.py`): given
  `ticket-ledger-artifact`, the ticket reconciler's proposal travels in the same pull request at
  `.security/ticket-ledger.json` — one reviewed write path.

- **Matching cascade** (`finding_match.py`): exact → moved → ambiguous resolved by cardinality →
  unmatched → uncomputable. Ambiguity is resolved by counting, never by guessing. An unreadable ledger
  or an uncomputable identity is `EVIDENCE_UNTRUSTED`.
- **Where the ledger lives**: on the protected default branch. A pull request **only reads** it, and reads
  it from git refs (the merge base and the default-branch tip), so a PR's own edits to the ledger are never
  read (`prove_ledger_read_authority.py`).
- **Who writes it**: only `propose_ledger.py`, which produces a **pull request** on a post-merge or
  scheduled run. It refuses pull-request events and non-default refs, never re-dates `first_seen`, never
  removes an entry (`prove_propose_ledger.py`).
- **Scanner upgrades** (`rule_family.py`): an alias table; an upgrade is a declared, dated event accepted
  once by a named approver; findings that only appear after an upgrade are never reported as NEW.
- **Lineage** (`finding_lineage.py`): append-only, hash-chained, head-anchored so a truncated tail is
  detected; resolution refuses a ledger it cannot verify.
- **Correlation** (`finding_correlation.py`): **anchored** (a shared identifier at the same location) /
  **proposed** / **singleton**. Only anchored clusters act; every contributing scanner is named, so a
  dead detector cannot hide behind a live one.

## 3. Dispositions — the only thing that changes enforcement

A **disposition** is a merged record on the protected default branch, under CODEOWNERS, that says a
specific finding is `FALSE_POSITIVE`, `ACCEPTED_RISK`, `MITIGATED` or `REMEDIATED`, with an approver, a
rationale and an **expiry**. The report applies it only if it is approved, unexpired and exactly matches.

- Read from the protected default branch, never from the pull request under evaluation.
- `REMEDIATED` is self-invalidating: if the scanner still reproduces the finding, the disposition is wrong.
- Expired → `REOPENED_BY_LAPSE`; silence never renews.
- **Key migration (KDEC-008, OD-6)**: dispositions key on the durable identity; the legacy fingerprint
  is also honoured until **2026-11-13** (BUILT; `prove_disposition_schema_and_key.py`).

## 4. Ticketing (BUILT; Jira proven live, Azure DevOps against stand-ins only)

**A ticket is a REQUEST for a disposition, never the disposition.** Closing, editing or approving a ticket
changes nothing the gate reads.

| ticket class | may result in | approved by |
|---|---|---|
| remediation work item | `REMEDIATED` | nobody — the scanner closes it by no longer reproducing the finding |
| false-positive request | `FALSE_POSITIVE` | Security, not the requester |
| accepted-risk request | `ACCEPTED_RISK` | Security + the named accepting authority; expiry required |
| mitigation record | `MITIGATED` | Security, against a control in force; carries a re-verification expiry |
| grandfather track item | `ACCEPTED_RISK` + track + SLA-computed expiry | as accepted risk |

**Backends (KDEC-004)**: **Jira Cloud** is authoritative; **Azure DevOps Boards** is second; GitHub Issues
is supported but not extended. One backend per repository and environment; two configured at once is a
policy defect refused by name. The reconciler is proven **live on a personal Jira** (refusals by name
with zero writes, idempotent re-runs, a successor for a closed ticket, reopen, a duplicate stamp
reported ambiguous) by `tests/live_ticketing_run.py`; **Azure DevOps is proven against stand-ins
only**; and the armed workflow `reusable-ticket-reconcile.yml` has **no hosted run** and no starter
template calls it yet. Moving to a consumer's tracker changes configuration values only (test B-1).

**Exceptions come back onto their tickets** (KDEC-018, lane L-FX; VERIFIED locally:
`prove_exception_due.py`). A ticket reference is required for a secret exception but never authorises
it: only the merged register entry does. A weekly workflow (`reusable-exception-due.yml`, called by
`templates/exception-due.yml`; `scripts/exception_due.py`) lists every exception due within 14 days or
expired, with its history, and raises it on its Jira ticket (reopen, comment, or one new issue),
saying it was excepted before and is now due. Jira only; without its credentials it reports
`NOT_CONFIGURED`, and an unreadable register is never "nothing due".

**Updates never erase human text** (completion ledger T-02, fixed in `795d13c`; VERIFIED at `078ef90`:
`prove_ticket_backends.py`). An update reads the description in full, replaces only the kit's
delimited block and writes the rest back exactly as read. An unreadable description is never
overwritten: nothing is written, the update is owed to the next run and the ticketing claim is
`EVIDENCE_UNTRUSTED`. Azure DevOps writes with a revision precondition; Jira has none (a residual
named in the code). Proven live on the personal Jira after the fix, per the merge record (READ).

**What the bound path updates, and when** (lane L-T, READ from the merge commits): writes happen only
on a change in the facts the kit has data for — members added, effective severity, contributing
scanners (a stopped one is named "no longer contributing") and members not seen this run
(`POTENTIALLY_ABSENT`) — so an unchanged run writes nothing (`c712a41`). Every reopen is classified
(`REOPENED_BY_LAPSE`, falsified, unbacked), recorded and posted once as a comment (`1193914`). The
scheduled deferral sweep runs in its own job with no environment and no secret. An obligation that
stays degraded counts consecutive runs and, past an owner-set threshold, is escalated as
`DECISION_REQUIRED` at the next promotion review.

**Hierarchy** (three tiers, forced by both plans): product (Epic, made once by a human) → cluster
(Jira Story / ADO Issue, stamped with the cluster key) → instance (Jira Subtask / ADO Task).

**Before anything is created**: (1) read the ledger's cluster→ticket binding (free); (2) one paginated
**sweep** of every ticket carrying the umbrella stamp, built into a local map; (3) create **only** if both
positively established absence through a channel proven able to see tickets this credential did not
create — a **calibration probe** resolves a known foreign ticket first. Six lookup outcomes, never a
boolean: `LEDGER_BOUND`, `BACKEND_BOUND`, `BINDING_ABSENT` (the only one that permits creation),
`BINDING_AMBIGUOUS`, `BINDING_DANGLING`, `BINDING_UNESTABLISHED` (the default for anything unclassified).

**May update**: last-seen, effective severity, fix availability, SLA breach (announce, never move), file
moves, contributing scanners, cluster membership. **Never**: the disposition, the approver, any expiry,
the SLA deadline, `first_seen`, the justification, closing a ticket to clear a finding, marking duplicates.

**Where it runs**: a separate reusable workflow, post-merge and scheduled only — never in a pull-request
job — with the tracker credential in a protected environment, `contents: read`, a timeout, and finding
text passed as data (redacted first; no snippets, no secret-derived fingerprints).

**Throttling**: Jira publishes no rate for API tokens, so `Retry-After` is primary and the run reports
calls spent and every 429; Azure DevOps meters in TSTUs (200 per five minutes) and the bridge slows down on
`X-RateLimit-Remaining` before it is delayed. A lookup that cannot complete creates nothing.

Full design: `docs/architecture/TICKETING_CONTRACT.md` and `docs/architecture/TICKETING_BACKENDS.md`.
