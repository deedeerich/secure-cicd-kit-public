# Findings and tickets UI -- a specification to build from (no UI is built here)

```
Status:     SPECIFICATION ONLY (KDEC-035 PROPOSED, 2026-11-03). Nothing in this repository renders it.
For:        whoever builds the UI (at work the owner raises it with the automation platform team).
Reads:      docs/api/README.md (the operations), api/v1/*.schema.json (the shapes),
            api/v1/refusals.json (the remedy text the UI shows for each refusal).
Rule:       the UI is a CLIENT of the kit's API. It decides nothing the kit decides, holds no tracker
            credential, and has no button that approves, closes, excepts or deploys around a gate.
```

## 1. What the UI is for

A vulnerability and findings management view over one or more repositories that run the kit: find
what the kit's scans established, see which findings have tickets and how they stand, raise or
annotate tickets through the kit, ask for a scan, ask for a release and watch it reach its human
approval. Every action is one API call; every state on screen is a word the API returned.

## 2. Rules every screen obeys

1. **Words, not colours.** Show `api_state`, `routing_result`, `deployment_outcome`, `kev` and
   `ticketing_state` as the words they are. `API_COMPLETED` is not "green": a completed scan can be
   `BLOCKED`. A check run's colour is never read (it is `neutral` for every non-completed call).
2. **Unknown is never good.** `kev: UNAVAILABLE` is shown as "not known -- the catalog could not be
   read", never as "not exploited". `not_judged` counts are shown. A `sweep_complete: false` answer is
   labelled "partial -- counts are a floor". `API_RESULT_UNREADABLE`, `API_FAILED` and
   `API_CANCELLED` are failures, shown with their notes.
3. **Received is not done.** After a submit (`API_ACCEPTED`) the UI shows "requested" and polls;
   it never shows success until `status` returns `API_COMPLETED`.
4. **Refusals are named and explained.** Show `refusal.code`, `refusal.detail`, and the remedy from
   `api/v1/refusals.json`. A refused or failed write is resubmitted with a **new** idempotency key
   (the first key is spent once its call was accepted); a retry is safe because a ticket is found by
   its stamp before one is created. A call `API_CANCELLED` before it started is resubmitted with the
   **same** key.
5. **No authority in the UI.** No approve button for a release (approval is a person on GitHub's
   environment review, quoting the digest), no close or transition button for a ticket (closure is
   the scanner's on verified clearance; people move tickets in the tracker), no exception or false
   positive button that writes anything (an exception is a pull request a person approves -- the UI
   may link to where that is done).
6. **Identity.** The UI calls the API with its own identity (a GitHub App installation token per
   repository, or a connector). `on_behalf_of` carries the signed-in person's name as a declared
   hint; the UI says it is unverified. The UI's users sign in with SSO; the UI never relays a user's
   own token.
7. **Minimal data.** Show and keep ids, states, counts, paths, rule ids, severities. No code content
   (the API returns none), no ticket descriptions beyond the kit's block facts, no secrets. Any cache
   is a rebuildable index: deleting it loses nothing.
8. **Bounded polling.** Poll `status` every 10 to 30 seconds while a call is queued or running, and
   back off to minutes for `API_AWAITING_APPROVAL` (a person may take days). Stop at a terminal state.
9. **One repository per call.** Cross-repository views fan out one call per repository, in bounded
   batches; a repository that did not answer is shown as "not read", never as "no findings".

## 3. Screens

### 3.1 Findings search

| element | from | notes |
|---|---|---|
| repository picker | the UI's configuration | one call per repository |
| run picker: "latest" or a run id | `findings.search` `run_id` | show the run's commit and link (`data.run`) |
| filters: severity, scanner, job, rule, CVE, KEV, path prefix, text, established only | `findings.search.filters` | KEV filter shows `data.not_judged` |
| results table: severity, rule, path:line, scanner, CVEs, KEV, ticket, first seen, baseline state | `data.findings[]` | `kev` per section 2.2; `ticket` links to the ticket detail |
| paging | `limit`, `offset`, `next_offset` | at most 200 per page |
| action: "ticket these" (selected rows with an identity) | `tickets.write` with `select.identities`, `dry_run: true` first, then for real | a row whose `identity` is null (e.g. a secret) cannot be ticketed by the API; say why |

### 3.2 Triage queue

| element | from | notes |
|---|---|---|
| open tickets by severity, SLA due, KEV | `tickets.search` `{status: open, severity, kev}` with `findings_run_id: latest` | `data.sweep_complete` false -> "partial" banner |
| columns: key, severity, SLA due, raised as (NEW / RECURRED / REOPENED_BY_LAPSE), confidence, disagreement label | `data.tickets[].ledger`, `labels` | `CONTESTED_ANCHORED` shown as "scanners disagree -- a person settles it" |
| sort: KEV first, then severity, then SLA due | client side | |

### 3.3 Finding detail

`findings.get` (by `finding_id` or `fingerprint`) plus, when bound, `tickets.get` by the finding's
`ticket.ref`. Shows: the finding's facts, its CVEs and KEV, the baseline state, the run and commit,
the ticket's block facts. Actions: **create ticket** (`tickets.write`), **comment** on its ticket
(`tickets.comment`). For "this is a false positive" or "we accept this risk": a link to the
repository's disposition / policy-register pull request path, with the text "a person approves this
on the protected branch; the UI cannot".

### 3.4 Ticket detail

`tickets.get` by `ref` or `cluster_key`: key, tracker link, state and status name, labels, block
facts (severity, contributing scanners, scanners that stopped, members not seen this run, SLA due,
confidence, exceptions), ledger facts (raised as, first and last seen, member identities). Action:
**comment** (`tickets.comment`, text up to 2,000 characters; the kit prefixes who asked). No close,
no transition.

### 3.5 Scan request

Form: repository, branch or tag, reason. Call `scan.request` (the client dispatches at that ref).
Status panel: `API_ACCEPTED` -> polling -> `API_COMPLETED` with `routing_result`,
`assurance_state`, `advisory_causes`; a link "see findings" opens 3.1 with `run_id` = `data.run_id`.
`API_FAILED` shows the notes ("the scan did not run" / "no registered verdict").

### 3.6 Release request and status

Form: repository, mode (promote / build-deploy), environment (only those the repository lists),
for a promotion the predecessor run and environment, release path (normal / hotfix only).
Call `deploy.request` with a fresh idempotency key. Status panel:

| api_state | show |
|---|---|
| `API_ACCEPTED`, `API_QUEUED`, `API_IN_PROGRESS` | "requested -- running the pipeline" with the run link |
| `API_AWAITING_APPROVAL` | "waiting for a person to approve the release to <environments>" and the instruction: the reviewer approves in GitHub and quotes the digest; the requester cannot approve |
| `API_COMPLETED` | `deployment_outcome` (e.g. DEPLOY_HEALTHY), now serving, the promotion record |
| `API_FAILED` | the job result and notes (which gate refused: approval, readiness, release block, promotion) |
| `API_REFUSED` | the refusal and its remedy |

### 3.6a Review finalization and ticket submission (KDEC-037, version 2)

A review's findings (any source) shaped into `tickets.submit` templates. Screen flow: **dry run**
(`dry_run: true`) shows each item's outcome -- planned tickets, exact matches, candidates with their
basis and similarity; the person picks `link` or `new`; the UI computes the evidence-set hash; a
security-team member who authored none of it (not the submitter, the engineer the AI run was for, or
the triager) approves the review record's pull request **in GitHub** -- AGREE, or DISAGREE with an
alternative (the UI has no approve control); then the real submit. Show `API_REVIEW_NOT_FINALIZED` with
every reason, `TEMPLATE_SENT_BACK` with the dissent, `SOD_SELF_APPROVAL` naming the role. A **triage
queue** lists `TEMPLATE_POSSIBLE_DUPLICATE` and `TEMPLATE_DEDUPE_PENDING` tickets with merge / separate
(the `triage` template); a **verification queue** lists `TEMPLATE_PENDING_VERIFICATION` with verify /
reject; an **outbox banner** shows `TEMPLATE_OUTBOX` and `data.alerts` until drained. Show each item's
`confidence` and `trust` WITH their `_basis`, beside its tier, never as a colour or a rank of risk.

### 3.6b Tracker intake (dashboards)

`tickets.search` with `tracker_query`: every ticket in the repository's projects, manual ones
flagged, paged with `next_page_token`; a partial or not-configured intake is "not read", never zero.

### 3.7 Activity

Every call the UI made: correlation id, operation, repository, who asked (declared), submitted at,
current `api_state`, link to the run. Re-check any row with `status.get`.

## 4. The calls each screen makes

| screen | calls |
|---|---|
| 3.1 Findings search | `findings.search`; `tickets.write` (dry run, then real) |
| 3.2 Triage queue | `tickets.search` |
| 3.3 Finding detail | `findings.get`, `tickets.get`, `tickets.write`, `tickets.comment` |
| 3.4 Ticket detail | `tickets.get`, `tickets.comment` |
| 3.5 Scan request | `scan.request`, `status.get`, then `findings.search` |
| 3.6 Release | `deploy.request`, `status.get` |
| 3.7 Activity | `status.get` |

## 5. Acceptance tests for the builder (each a negative as well as a positive)

1. A `kev: UNAVAILABLE` finding never renders as "not exploited"; a KEV filter shows `not_judged`.
2. A submitted write shows "requested", never "done", until `API_COMPLETED`.
3. A release waiting on reviewers shows `API_AWAITING_APPROVAL` and offers no approve control.
4. A refused call shows its code and the remedy from `api/v1/refusals.json`.
5. A completed scan with `routing_result: BLOCKED` is shown as blocked, not as success.
6. A partial ticket sweep shows the "partial -- counts are a floor" banner.
7. A finding with no identity offers no "ticket" action, and says why.
8. Repeating a ticket write after `API_FAILED` (new key) or a cancelled one (same key) never yields
   two tickets for one finding; repeating a completed write with its key answers
   `API_DUPLICATE_REQUEST` naming the first call.
9. No screen shows code content, a ticket description beyond the block facts, or a credential.
10. Signing out and back in never changes what the API was told (`on_behalf_of` stays a declared hint).
