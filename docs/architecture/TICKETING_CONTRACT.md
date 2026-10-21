# The ticketing contract

**A ticket is a REQUEST for a disposition. It is never the disposition itself — and nothing is
created until a lookup has established that nothing is already there.**

```
Phase: design — a written contract, not an implementation
Truth State: modelled 2026-09-23 from the owner's ticketing requirement, against the
             registered vocabulary in secure-cicd-kit/assurance-taxonomy.yaml (v1),
             the request contract already in schemas/disposition-request.schema.json,
             and ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md sections 5, 8 and 9
Audience: whoever builds the ticketing bridge, and whoever has to explain to an auditor
             why an open ticket did not soften a gate
Decision Supported: what each ticket class may result in, who may approve it, what is
             checked before a ticket is created, what automation may touch afterwards,
             and what a run costs in API calls
Deferred Depth: the ledger's storage model (ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md section 13) · the Jira
             field model, which could not be verified here · the tracker's own UI
```

> **Nothing described here is built.** Not the ticket classes, not the stamp, not the lookup
> cascade, not the update path, not the budget. No workflow, script or test was changed to write
> this. The kit's own rule applies to this file first: **registering a term is not implementing it,
> and writing it down does not make it so.**
>
> **Section 9 proposes two CANDIDATE namespaces.** They are marked CANDIDATE because registering
> them would assert they had been decided, and they have not been. Section 10 lists the terms this
> document leans on that are CANDIDATE elsewhere, so that nobody reads a proposal as a registration.
>
> **Every claim about an external API is either cited to primary documentation or marked
> UNVERIFIED.** A claim about a rate limit that nobody sourced is how a cost model becomes a guess
> with a table around it.

---

## 0 · What this settles, and what it deliberately does not

**Settled here:** that a ticket is a request and never an authorization; the five ticket classes the
owner named and the exact `disposition_type` value each may result in; who approves each and what
evidence the approval owes; what an OPEN request does to the gate (nothing) versus an APPROVED one
(nothing, on its own — the merged disposition does it); the order of the idempotency cascade and
what is stamped where for each backend; the required behaviour on a failed lookup, a closed ticket,
a many-to-one cluster, a one-to-many ambiguity, a dangling reference, and both backends configured
at once; the exhaustive list of what an automated run may update and the shorter list it may never
touch; the API-call budget as a function of findings and of changed findings; and the trigger and
permission model.

**Not settled here, and named as unsettled in Section 11:** most of the Jira field model; whether
the owner's estate has a Jira project to target at all; whether the tracker's own approval state can
ever be trusted as a signal; the creation budget's numeric value; and how a ledger-to-tracker
reconciliation is reviewed at estate scale.

A document that answered all of those about a bridge nobody has built would be lying.

---

## 1 · The load-bearing distinction

> **A false-positive REQUEST is not a false-positive DETERMINATION.**

If a ticket were a disposition, then anyone who can open an issue could clear a finding. On GitHub
that is anyone with read access to a public repository; in Jira it is frequently anyone in the
organisation. The gate's authority would then be delegated, silently, to the tracker's weakest
permission.

This is not a new rule and it is not this document's invention. It is already written down twice in
the kit:

- `disposition_type`'s rule: "A finding is exempted ONLY by an exact, unexpired, approved
  disposition. Dispositions are consumed from the PROTECTED DEFAULT BRANCH, never from the PR under
  evaluation — otherwise a PR can exempt the secret it introduces in the same PR."
- `schemas/disposition-request.schema.json`, whose own description says it: "a request is not a
  disposition. Only a MERGED approval on the protected default branch alters enforcement." That
  schema already separates **two lifecycles, deliberately not one enum** — `request_state` (where
  the governance workflow has got to) and `requested_disposition` (what is claimed to be true).

**So the ticketing model reuses that schema rather than respelling it.** A ticket is the *human
surface* of a disposition request. The request record is the machine surface. The disposition is a
third thing, on the protected branch, under CODEOWNERS.

```
ticket  (in GitHub Issues or Jira — discussion, assignment, workload)
   |
   |  carries a reference to, and is reconciled against
   v
disposition request record  (schemas/disposition-request.schema.json)
   |
   |  APPROVED only by a merge to the protected default branch
   v
disposition  (disposition_type — the ONLY thing that changes enforcement)
```

Three properties of that chain matter more than the diagram:

**The arrows only point down.** Editing a ticket cannot change a disposition, because the
disposition does not live in the ticket. This is the whole mechanism (Section 5.3) and it is
structural rather than a rule the bot is asked to respect.

**The ticket is a copy, and a copy that drifts is a defect.** The ticket may render the disposition
for a human to read. It is marked as a rendering, the authority is the merged record, and the run
reconciles the two and reports divergence. That is the kit's third structural remedy applied here
unchanged — "a declared registry, the actual usage, and a check that fails on divergence".

**The tracker's own approval state is a signal, never the authority.** A Jira transition to an
approved status, or a GitHub issue closed by a maintainer, tells you a conversation happened. It
does not tell you that a security approver with the separation `team_pattern` requires has
established that the claimed classification is supported. Those are different facts and only the
second one is allowed to move a gate.

---

## 2 · The ticket classes

### 2.1 The five classes the owner named

| class | what it is for | may result in | approved by | evidence the approval requires | while merely OPEN | once the request is APPROVED and merged |
|---|---|---|---|---|---|---|
| **remediation work item** | the finding is real and is being fixed | `REMEDIATED` | **nobody approves it.** The scanner closes it by no longer reproducing the finding | coverage over the scope the finding lived in, per `POTENTIALLY_ABSENT` | nothing. The finding routes on its own terms | nothing. `REMEDIATED` is `self_invalidating` — if the finding still reproduces, the disposition "is STALE OR WRONG and must not suppress" |
| **false-positive request** | the detector is wrong about this finding | `FALSE_POSITIVE` | Security, distinct from the requester, at the `team_pattern` the cell holds | "why the detector is wrong" — the registered `evidence_must_show`. Narrowly scoped. For a secret, the much narrower `secrets_rule` path | nothing | the finding stops blocking, within the scope the disposition names, until its expiry |
| **accepted-risk request** | the finding is real, cannot or will not be fixed now, and someone is choosing to proceed | `ACCEPTED_RISK` | Security plus the named accepting authority; escalating by severity per ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md section 8.6 | "who accepted it, under what conditions, until when", plus the schema's conditional requirement of `acceptance_ref`, `owner_role` and `expires_at` | nothing | the finding routes `PROCEED_WITH_ADVISORY` while the acceptance is unexpired; `REOPENED_BY_LAPSE` and `BLOCKED` when it is not |
| **mitigation record** | no fix exists; a compensating control has been put in force | `MITIGATED` | Security, against the control being **in force and evidenced** — not merely designed | "which compensating control, and that it is in force". Carries its own re-verification expiry, because a control can lapse silently | nothing | the finding remains open and observable and stops blocking. Re-verification, not renewal, keeps it standing |
| **grandfather track item** | the finding was already present in production; it is scheduled rather than blocking | `ACCEPTED_RISK`, **plus a track reference and an expiry computed from the SLA rather than chosen** | as accepted-risk, or once for the day-one cohort as a dated, enumerated, closed cohort decision | fix availability **established** (not assumed); a claimable first-seen or an explicit record that the age is unestablished; the track reference | nothing | `PROCEED_WITH_ADVISORY` at the `run` rung while the track is unexpired. Track lapsed means `BLOCKED` |

### 2.2 The rows that are easy to get wrong

**The remediation work item is the only class that is not a request for an authorization.** It asks
nobody for anything. It is work, and its terminal state is established by a scanner rather than
granted by a person. That is why `REMEDIATED` is the one disposition the scanner itself can falsify,
and why this class has no approver column worth filling in. Giving it one would invite the failure
ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md section 8.8 rule 7 already names: **closing a ticket does not clear a finding.**

**The grandfather track item is not a sixth disposition class.** It is `ACCEPTED_RISK` with two
mandatory additions. ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md section 8.1 checked that first and found the registered
vocabulary already held it; this document does not re-open the question. What separates it from a
plain accepted-risk request is not the claim but the arithmetic: **its expiry is computed from the
severity SLA, not chosen by the approver**, and a bot that could choose it would be choosing the
deadline.

**The mitigation record's deliverable is the control, not the fix.** ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md section 7.1
is explicit that conflating the two is how a mitigation quietly becomes a fix in the record. A
mitigation record therefore never closes to `REMEDIATED`, and an automated run that saw the scanner
stop reproducing a mitigated finding must not upgrade the disposition — that is a determination, and
Section 5.2 forbids it.

**The accepted-risk request is the answer to no fix being available, and the grandfather item is the
answer to a fix being available and scheduled.** They are not two flavours of the same thing. One
holds a decision, the other holds a schedule. ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md section 7 is the axis that decides
which is admissible, and a finding whose fix availability has not been established is admissible to
neither.

### 2.3 What an OPEN request does to the gate: nothing at all

> **An open request must not soften anything.**

Stated as a prohibition rather than a preference, because the permissive reading is one line of code
away and it is the reading a tired implementation will take. Three forms of the same error, all
forbidden:

- **A ticket existing does not soften a finding.** ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md section 9.5 already says it:
  "Having a ticket is not a disposition. A ticket is where the work is tracked; a disposition is
  where the authorisation lives; and letting the first stand in for the second means anyone who can
  file a ticket can authorise an exception."
- **A request in flight does not soften a finding.** `disposition_type` has a named
  `forbidden_transition`: "proposed -> suppressing (a proposal never buys passage)".
  `control_weakening.WEAKENING_UNATTRIBUTED` states the same rule one namespace over, for controls:
  an unattributed weakening "is not an approved exception. It is a decision nobody has made."
- **A ticket being assigned, in progress, triaged or commented on does not soften a finding.** Those
  are workload facts. They are worth reporting and they establish nothing about risk.

The one thing an open request legitimately changes is **who the run addresses**. A finding with an
open request in `UNDER_REVIEW` routes `DECISION_REQUIRED` to a named reviewer rather than to the
author, and the run summary says which reviewer and since when. That is routing, not enforcement,
and `routing_result` already keeps those apart.

### 2.4 The governance state is the schema's, reused verbatim

The ticket's governance lifecycle is not a new vocabulary. It is `request_state` from
`schemas/disposition-request.schema.json`, whose values are:

```
    REQUESTED         raised; nobody has picked it up. Suppresses nothing.
    UNDER_REVIEW:     Security has it. Suppresses nothing.
    APPROVED          reviewed, with a reviewer, a time and a rationale -- and it STILL
                      suppresses nothing until the disposition record is merged to the
                      protected default branch.
    REJECTED          returns to blocking. The ticket records why.
    CHANGES_REQUESTED: returns to REQUESTED. Not a rejection and not an approval.
```

**APPROVED is the row people misread.** In that schema APPROVED is a property of the *request*, and
the schema's own conditional requirement is only that an approval carry "a reviewer and a rationale
— an approval with neither is a rubber stamp with extra steps". Enforcement changes at the *merge*,
not at the approval, because the merge is the act CODEOWNERS governs and the approval is not. A
bridge that treated APPROVED as suppressing would move the authority from the protected branch into
whatever the tracker's edit permission happens to be.

### 2.5 The classes deliberately not proposed

**No class for a secret.** Secret findings block at every rung and are never grandfathered
(ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md section 5.7). A secret gets a remediation work item whose action is rotation, and
that item carries **no secret material of any kind** — see Section 7.4. The narrow inherited-noise
path is a `FALSE_POSITIVE` request under `secrets_rule`, which is an existing class and not a new
one.

**No class for a finding whose fix availability is not established.** Such a finding routes
`DECISION_REQUIRED` and what it needs is an establishment, not a request. Whether that deserves its
own class or belongs as a state on the remediation work item is genuinely open and is named in
Section 11 rather than guessed at here. ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md section 12.6 already warns that five
namespaces for one mechanism is too many and that a reviewer should expect to merge two; adding a
sixth ticket class on a hunch would be the same mistake in the same week.

---

## 3 · Idempotency — the check before creation

> The team learns within a fortnight whether the pipeline is a tool or a noise generator, and it
> learns it from duplicates.

### 3.1 The cascade, in order of cost

Three steps, and the ordering is by cost because cost is the axis the owner has repeatedly flagged.

```
STEP 1   THE LEDGER.  Read the finding-identity -> ticket-reference mapping out of the
         baseline ledger on the protected default branch.
         COST: zero API calls. The ledger is already in the checkout.

STEP 2   THE BACKEND SWEEP.  One paginated read of every ticket carrying the kit's
         umbrella stamp, keyed on a MACHINE-READABLE stamp, built into a local map.
         COST: a function of TICKETS THAT ALREADY EXIST, not of findings (Section 6).

STEP 3   CREATION.  Only if steps 1 and 2 BOTH established absence, through a channel
         shown to be able to see the thing it is reporting absent.
```

**Step 1 is first because it is free, and it is authoritative about intent rather than about
reality.** The ledger records the decision that a ticket was created. It does not know whether the
ticket still exists, so a ledger hit is a reference to be resolved, not a resolution.

**Step 2 exists because the ledger can be wrong in both directions.** It can hold a reference to a
ticket somebody deleted, and it can be missing a reference to a ticket somebody created by hand with
the stamp applied. Skipping step 2 on a ledger miss would make every hand-made ticket invisible and
duplicate it on the next run.

**Step 3 is reachable from exactly one outcome.** Section 3.4.

### 3.2 What is stamped, and where

> **Never title text.** Title matching both misses and collides: a title is edited by humans,
> truncated by tooling, translated, prefixed with a sprint tag, and two different findings in two
> different files routinely produce byte-identical titles. A lookup that can be defeated by somebody
> tidying a title is not a lookup.

What is stamped is the **cluster key** from ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md section 9 — not the raw finding
fingerprint. The mapping is many findings to one cluster to at most one ticket, so the ticket is
keyed by the obligation it tracks, not by one of the observations that produced it.

**Two parts, always both:**

| part | value | why |
|---|---|---|
| **umbrella stamp** | one fixed marker, identical on every ticket the kit raises | makes step 2 a single bounded sweep rather than one query per finding. This is the whole budget argument |
| **cluster stamp** | the cluster key, in a form the backend can match EXACTLY | makes the lookup a match rather than a search |

#### GitHub Issues

| | value | primary source |
|---|---|---|
| **umbrella stamp** | one repository label, created once by a human, applied in the `labels` array of the **create** call | `POST /repos/{owner}/{repo}/issues` documents `labels` on creation, with the warning that "Only users with push access can set labels for new issues. Labels are silently dropped otherwise" — https://docs.github.com/en/rest/issues/issues?apiVersion=2022-11-28#create-an-issue |
| **cluster stamp, durable** | an organisation-level issue field of type `text`, set with `PUT /repos/{owner}/{repo}/issues/{issue_number}/issue-field-values` | field definitions: https://docs.github.com/en/rest/orgs/issue-fields (types `text, date, single_select, multi_select, number`); per-issue values: https://docs.github.com/en/rest/issues/issue-field-values |
| **cluster stamp, redundant** | the same key inside the delimited machine-owned block in the body | the list endpoint returns each issue's `body`, so this costs nothing to read |
| **the sweep** | `GET /repos/{owner}/{repo}/issues?labels=<umbrella>&state=all&per_page=100`, paginated | https://docs.github.com/en/rest/issues/issues?apiVersion=2022-11-28#list-repository-issues |

**The sweep filters on the umbrella label only, and reads the cluster key out of what came back.** That
is deliberate and it is not the same thing as searching for the key:

- **It does not depend on multi-label AND semantics.** The `labels` parameter is documented as nothing
  more than "A list of comma separated label names" — GitHub documents **no** conjunction semantics for
  it. AND is the observed behaviour and is **UNVERIFIED** as a contract, so the design does not rest on
  it.
- **It does not use the search endpoint.** `GET /search/issues` is limited to 30 requests per minute
  for all authenticated search endpoints
  (https://docs.github.com/en/rest/search/search?apiVersion=2022-11-28), is a text index with its own
  consistency behaviour, and now carries a `search_type` parameter whose semantic and hybrid modes are
  separately limited to 10 requests per minute. A lookup that cannot see a ticket created ninety
  seconds ago is a duplicate generator with an excuse.
- **Parsing a structured value out of a record the API returned is exact and immediate. Asking a text
  index to find it is neither.** That is the whole distinction, and Section 3.3 turns on it.

**Two stamps rather than one, because one of them is documented to be lossy.** Transferring an issue
between repositories retains labels only conditionally: "Labels and milestones are also retained if
they're present in the target repository, with labels matching by name"
(https://docs.github.com/en/issues/tracking-your-work-with-issues/administering-issues/transferring-an-issue-to-another-repository).
A cluster-specific label would therefore be **silently dropped** by a transfer into a repository that
does not already have it. The issue field and the body block survive that; the ledger is the authority
regardless.

**Why not a label per cluster.** It would make the sweep a single filtered query, and it grows the
repository's label namespace without a documented bound: GitHub's repository-limits page documents
size, activity, text, pull-request, diff and commit limits and **nothing about labels**
(https://docs.github.com/en/repositories/creating-and-managing-repositories/repository-limits), and the
maximum label name length, the character set, the maximum labels per issue and the maximum labels per
repository are all **UNVERIFIED** — the commonly cited figures appear in no GitHub document. Building
an index on four unverified limits is how a scheme works for two years and then stops.

**Reopening.** `PATCH /repos/{owner}/{repo}/issues/{issue_number}` with `state: open`. The documented
`state_reason` enum is `completed`, `not_planned`, `duplicate`, `reopened` or null, and it is "Ignored
unless state is changed"
(https://docs.github.com/en/rest/issues/issues?apiVersion=2022-11-28#update-an-issue) — so a reason
cannot be corrected without flipping the state, which is itself a reason to record reasons in the
machine-owned block as well. `duplicate` exists as a reason and Section 5.2 still forbids automation
from applying it.

**Deletion and identity.** There is no REST endpoint to delete an issue; deletion is permanent, the URL
404s afterwards, and issue numbers are not reused
(https://docs.github.com/en/issues/tracking-your-work-with-issues/administering-issues/deleting-an-issue).
A transfer, by contrast, is survivable: "The original URL redirects to the new issue's URL." What
happens to the issue **number** on transfer is **UNVERIFIED** — the transfer page does not say — so the
ledger stores the issue's API URL and node identifier alongside the number, and never the number alone.

#### Jira Cloud

| | value | primary source |
|---|---|---|
| **umbrella stamp** | the project itself, plus a fixed label or a single-select custom field value | — |
| **cluster stamp** | a **single-line** custom field (`textfield`), referenced as `customfield_` plus its numeric id | the create-issue docs are explicit that "`description`, `environment`, and any `textarea` type custom fields (multi-line text fields) take Atlassian Document Format content. Single line custom fields (`textfield`) accept a string" — https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/#api-rest-api-3-issue-post |
| **field id discovery** | `GET /rest/api/3/field`, or `GET /rest/api/3/issue/createmeta` for what is settable on an issue type, resolved at run start and pinned in the policy file | https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issue-fields/#api-rest-api-3-field-get |
| **the sweep** | `POST /rest/api/3/search/jql` with a bounded JQL query, `fields` limited, paged by `nextPageToken` | https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issue-search/ |

**Five Jira-specific constraints, each of which changes the design:**

**Custom field ids are per-site and must be resolved at runtime.** There is no name-based addressing
in the API; a field is `customfield_` plus a numeric id allocated by the site. A pinned id is therefore
a per-instance configuration value, recorded with the date it was discovered and re-resolved when the
credential or project changes. A verbatim Atlassian sentence stating this is **UNVERIFIED** — it is
structurally certain from the absence of name-based addressing, and the canonical page is a knowledge
base article rather than the REST reference.

**Field discovery is not exhaustive.** `GET /rest/api/3/field` documents that "Fields that are not
associated to any used field configurations or screens are not returned." A field that exists but is
not on a screen is invisible to discovery, so "the stamp field was not found" is a
could-not-establish, not an absence — Section 4.5's rule, one layer up.

**The legacy search endpoint is being removed, so the enhanced one is the only one designed against.**
Atlassian's own published OpenAPI description
(https://developer.atlassian.com/cloud/jira/platform/swagger-v3.v3.json) flags both
`GET /rest/api/3/search` and `POST /rest/api/3/search` as deprecated, with the summary "Currently being
removed", pointing at https://developer.atlassian.com/changelog/#CHANGE-2046. The dates circulating for
that removal are **UNVERIFIED** — the changelog is a client-rendered application and the dates appear
only in community threads. What is primary and unambiguous is the word "removing".

**The enhanced search is eventually consistent, and that is a first-class duplicate hazard.** Verbatim:
"Recent updates might not be immediately visible in the returned search results. If you need
read-after-write consistency, you can utilize the `reconcileIssues` parameter." So:

- **Never read after write.** A run that creates a ticket and then searches for it will intermittently
  not find it and will create a second one. The ledger is written in the same run and is what the next
  run reads.
- **`reconcileIssues` is passed for the references the ledger says should exist**, which is exactly the
  set where a false absence would be expensive.
- The query must be **bounded** — documented: "this parameter requires a bounded query... Example of an
  unbounded query: `order by key desc`" — so the sweep always carries a project restriction.

**The issue key is not a stable identifier. The numeric id is.** A move changes the key; redirection
from the old key is described in an Atlassian knowledge base article rather than the REST reference and
has known third-party failure modes, so it is **UNVERIFIED** as a contract. The ledger therefore stores
the **numeric issue id** as the reference and the key only as a human-facing label. This is the Jira
analogue of the transfer problem above and it is worse, because the key is the thing people paste.

**Archived and trashed issues leave the search index while continuing to exist.** Archived issues drop
out of JQL results, and a trashed project's items are documented as not appearing "in basic or advanced
search results" while remaining reachable by direct link for 60 days
(https://support.atlassian.com/jira-cloud-administration/docs/trash-for-jira-cloud-projects/). Whether
either can still be fetched by key or id through the REST API is **UNVERIFIED**. This is the clearest
possible case of Section 4.5's rule: **a sweep miss against a ledger reference is not an absence**, and
treating it as one would file a duplicate for every archived finding in the estate.

**Reopening has no generic form.** There is no `state` field to write. The bridge reads
`GET /rest/api/3/issue/{issueIdOrKey}/transitions` and posts a transition id, and transition ids are
workflow-specific and not portable between projects. The documented failure mode is the important part:
"if a request is made for a transition that does not exist or cannot be performed on the issue, given
its status, the response will return any empty transitions list", and separately "if the user does not
have the Transition issues project permission the response will not list any transitions." **An empty
list is ambiguous between not-permitted and not-applicable** — `DISTINCTION_NOT_OBSERVABLE` again — so
"reopen was refused" must never be recorded as "reopen is impossible here", and the successor path in
Section 4.2 is the required behaviour rather than a fallback.

### 3.3 The body block is a rendering, not the index

The ticket body carries a delimited, machine-owned block holding the cluster key, the member
fingerprints, every contributing scanner named, the current effective severity and its formula
version, and the disposition as rendered from the authority. That block is for humans and for
reconciliation. **It is never the thing the lookup searches**, for two reasons:

- **Full-text search is a different consistency model.** A newly created ticket is not necessarily
  findable by body text immediately, and a lookup that misses a ticket created ninety seconds ago is
  a duplicate generator with an excuse.
- **Full-text search is fuzzy by construction.** It tokenises, stems and scores. An exact-match
  index on a label or a field is the only mechanism whose answer is the same on every run.

**Searching for a value and parsing one out of a record the API already returned are not the same
act, and Section 3.2 does the second.** The sweep asks the backend one bounded question it has an
exact index for — which tickets carry the umbrella stamp — and the backend returns whole records. The
cluster key is then read out of those records by this kit's own parser: exact, immediate, and
answerable offline. Nothing is ever asked of a text index. The distinction matters because the
permissive-sounding shorthand ("we look it up in the body") describes a design that would be wrong,
and the conservative-sounding one ("we never look at the body") describes one that throws away a free
and reliable check.

### 3.4 The one outcome that permits creation

Creation is reachable only from an outcome that **positively established absence** — both the ledger
and the backend sweep completed, and the channel that reported absence was shown to be able to see
tickets this credential did not create (Section 4.5). Everything else routes somewhere other than
creation. `observation_quality` already draws exactly this line and it is reused rather than
restated: `VERIFIED_ABSENT` is "the control observed that the thing is genuinely not there. A real
negative", and it is a different value from every kind of could-not-look.

**The permissive branch and the unknown branch are not the same branch.** `reversal_disposition`
states the general form of this rule for a destructive action — "any implementation in which a
failed precondition can fall through into `REVERSAL_REMOVE` has broken the taxonomy even though
every word it used was valid". Creation is not destructive, but it is the irreversible one here: you
can stop updating a ticket, and you cannot un-notify four hundred people.

---

## 4 · The failure modes, and the required behaviour of each

### 4.1 The lookup itself fails — rate limit, outage, expired credential

Two obvious answers and both are wrong:

- **Create anyway.** This is how an estate gets hundreds of duplicates overnight. It also has the
  exact shape the kit has already shipped and named: a failed observation read as a successful
  negative one. `absence_is_not_a_negative_observation` is a governing invariant, and "did not
  execute, no report" is **absence of evidence**, not zero.
- **Do not create, say nothing.** The finding loses its only tracking surface and the run reports
  identically to one where a ticket was raised. `control_weakening`'s rule covers the shape: what is
  not in the record "did not happen, as far as the evidence is concerned — and that is
  indistinguishable from a clean run, which is the defect."

**The third answer, and it reuses the shape the taxonomy already holds for a publication channel
that could not be reached:**

1. **Create nothing.** Absence was not established.
2. **Clear nothing.** The ledger's existing mapping is untouched; a failed lookup is not evidence
   that a mapping is stale.
3. **Record the obligation as outstanding, in the ledger, with the reason.** The finding is carried
   forward as owing a ticket, with the lookup outcome and its cause, so the next run acts on it
   without re-deriving anything. This is the "error becomes data" requirement:
   `suppression_reason.FAILURE_ISOLATION_WITH_STATE_CAPTURE` is only correct when the failure is
   "captured as explicit state that propagates", and otherwise "it is `|| true` wearing YAML".
4. **Classify the ticketing capability, not the finding.** The ticketing claim for the run is
   `publication_state.PUBLICATION_DEGRADED` — "a presentation channel was unavailable", whose
   registered rule is precisely the two things needed here: it "MUST NOT fail the scan", because "an
   unreachable dashboard cancelled an entire deep scan once"; and "an empty Security tab is
   indistinguishable from a clean codebase — **say which it is.**" A tracker is a presentation
   channel for a finding and inherits that rule unchanged. The run's ticketing claim routes
   `routing_result.EVIDENCE_UNTRUSTED`, which exists for exactly this: a result that "cannot be
   relied on", never `DECISION_REQUIRED` and never clean.
5. **Retry within the run, bounded, and then stop.** A bounded backoff with a hard ceiling, because
   an unbounded retry against a rate limit converts a tracker outage into billed minutes — the kit
   has already paid roughly 412 billed minutes for an unbounded wait on a lock.

**And the rule that matters most:**

> **A ticketing failure does not soften the finding's routing under the rung.**

The routing of a finding is computed from scanner evidence and the ledger, and the baseline
document, section 9.2 already places correlation and ticketing **after** classification and **outside** the
pull-request run. Ticketing is therefore downstream of enforcement by construction, and a downstream
failure that could reach back and change an upstream verdict would be
`authority_never_grows_from_loss` violated in its plainest form. A finding that blocks still blocks
when the tracker is down. A finding that proceeds still proceeds. What changes is that the run says
the finding has no tracking surface yet, and says why.

**Degraded for more than one run is a governance fact.** Ticketing degraded for a configured number
of consecutive runs routes `DECISION_REQUIRED` at the cell's next promotion review, reusing the
shape ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md section 8.8 rule 5 applies to a track with no closures: an untouched
mechanism "is indistinguishable from a working track until the morning everything expires at once".

### 4.2 A ticket exists and is closed — reopen, or create new?

**Reopen by default. Create a successor only when reopening is refused, and never without recording
the predecessor.**

The argument, and it turns on what closure means:

**Closure of a ticket is not closure of a finding.** ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md section 8.8 rule 7 is the
governing sentence: "Closing a ticket does not clear a finding. Only the scanner not reproducing it
clears it." So a closed ticket beside a reproducing finding is not a contradiction to be resolved by
creating something new; it is a ticket whose closure was premature, wrong, or about something else.

**Creating a new ticket destroys the only record of why it was closed.** The triage, the argument,
the person who decided, the evidence they looked at. Worse, it destroys the *pattern*: a finding
closed and reopened five times is a visible governance problem on one ticket and is invisible across
five. The kit's own named hazard is "decisions recorded in two places, one stale, the stale one
looking authoritative" — and N tickets for one obligation is that hazard at N.

**But reopening on every run is equally wrong**, and this is the case a naive implementation gets
backwards:

| the closure is backed by | and the scanner still reproduces the finding | required behaviour |
|---|---|---|
| an **unexpired, approved, exactly-matching `FALSE_POSITIVE`** | expected. A false positive never stopped reproducing; the detector is still wrong in the same way | **the ticket stays closed.** Reopening it every run teaches the team the bridge is broken |
| an **unexpired, approved `ACCEPTED_RISK`** or grandfather track item | expected. The finding is real and authorised to remain | **the ticket stays closed**, or stays open as a track item on its own terms. The run does not toggle it |
| an **unexpired, approved `MITIGATED`** | expected. The finding "remains technically observable" by definition | **the ticket stays closed.** What needs re-establishing is the control, on the mitigation's own re-verification expiry, and that is a human act |
| a **`REMEDIATED` disposition** | **not** expected. `REMEDIATED` is `self_invalidating`: "if the finding still reproduces, the disposition is STALE OR WRONG and must not suppress" | **reopen**, name the run that re-observed it, and record the disposition as falsified by the scanner |
| **nothing** — somebody just closed it | nothing was ever authorised | **reopen**, and name the closure as unbacked. This is the cheapest suppression mechanism in an estate and the one rule 7 exists to close |
| a disposition that has **expired** | the finding never changed; its disposition did | **reopen**, as `REOPENED_BY_LAPSE` — the registered class, whose registered action is "re-decide with a named approver and a new expiry", and whose registered rule is that "silence must never renew a disposition" |

**The case the requirement singles out: closed as a false positive, later overturned.** This is the
one that proves the successor pattern is needed rather than optional.

What overturns a false positive is **not** the scanner reproducing the finding, because it always
did. It is one of: the disposition being revoked, the disposition expiring, or its scope no longer
matching — `disposition_type` names the last two as transitions, `approved -> expired` and
`approved -> invalidated`. Any of those is `REOPENED_BY_LAPSE` or an invalidation, and the required
behaviour is to **reopen the original ticket**, because the overturn is only legible beside the
argument it overturns. A fresh ticket saying "this is a real finding" with no link to the ticket that
said "this is a false positive" loses the single most useful artefact in the sequence: the reason
somebody was wrong.

**When reopening is refused.** It will be, and for ordinary reasons: a Jira workflow with no legal
transition out of a done status; an issue locked; a repository archived and therefore read-only; the
automation's credential lacking the transition. Then:

1. Create a **successor** ticket that references the predecessor by its stamp and its URL.
2. Write the predecessor's reference into the successor's machine-owned block and the successor's
   reference into the ledger, **retaining the predecessor in the ledger's history**. The chain is
   the artefact; losing it is the failure.
3. Record the reason the reopen was refused. "Could not reopen" with no cause is the kind of
   entry that gets read as "chose not to".
4. A cell in which reopening is *structurally* unavailable is a declared limitation of that backend
   configuration, reported once and loudly, not rediscovered per finding.

### 4.3 Many findings to one ticket — what closing it requires

The mapping is **many-to-one by design**: five scanners produce five observations, one cluster, at
most one ticket (ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md section 9.1). So closure is a claim about the cluster, and:

**A cluster's ticket may be closed only when every member is closed on its own terms.** Each member
needs the scanner to no longer reproduce it, over a scope shown to cover where that member lived.
A member that merely stopped appearing is `POTENTIALLY_ABSENT`, whose registered action is
"establish coverage before calling it fixed — absence of the scope is not absence of the thing".

**Partial clearance does not close anything, and it is not silent.** A cluster with three members of
which two no longer reproduce holds a ticket that stays open, and whose machine-owned block records
which members cleared, when, and on what coverage evidence. A partially cleared cluster reported as
open with no detail is indistinguishable from one where nothing happened, which is the distinction
`partial_is_not_total_ignorance` exists to preserve: "preserve everything still established and NAME
what became unknown."

**Every contributing scanner is named, on the ticket, always.** `evidence_confidence`'s registered
warning is the reason: dropping tool attribution "is what caught a dead flawfinder covered for by
cppcheck". A cluster ticket that said only "corroborated" would let a dead detector hide behind a
live one — the same defect the correlation layer exists to avoid, arriving through the ticket.

**A cluster split re-splits the tickets, and it is an event.** ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md section 9.4: when a
cluster is split, "both members return to acting on their own terms, each keeping its own
`first_seen`". The ticket that held the merged cluster keeps one member, the others get tickets whose
machine-owned blocks reference the original, and the split is recorded. Nothing is deleted. A merge
in the other direction never removes a ticket either: the surviving ticket references the ones it
absorbed and those are closed **as superseded, by a human**, never by the bot (Section 5.2).

**And closing the ticket still clears nothing.** Rule 7, one more time, because this is the exact
place an implementer will be tempted to shortcut it: the cluster's members are cleared by the
scanner. Closing the ticket is bookkeeping about work, not a statement about the code.

### 4.4 One finding to many tickets — report the ambiguity, do not pick

Two people file tickets for the same obligation, both carrying the stamp; or the ledger holds one
reference and the sweep finds two more. The required behaviour is the discipline the baseline document,
section 5.3, already applies to finding identity, transplanted intact:

> **Ambiguity is resolved by cardinality, never by guessing which one is canonical.**

1. **Create nothing.** There is no shortage of tickets here.
2. **Update nothing.** Updating one of N arbitrarily *is* picking, and it picks by whatever order the
   API happened to return. That is the worst available outcome: a decision made by pagination.
3. **Name every candidate** — all references, their states, who created them, when — in the run
   summary and in the ledger's record for that cluster.
4. **Route the ticket-hygiene claim to `DECISION_REQUIRED`.** A human declares the canonical ticket;
   the others are marked as duplicates **by a person**, with the canonical one referenced. The ledger
   then holds exactly one canonical reference and the resolution is recorded as an event.
5. **The finding's own routing is unchanged.** An ambiguous ticket mapping is a bookkeeping defect,
   not evidence about code. It does not block and it does not soften.

**The ledger holds exactly one canonical reference, so one-to-many is a defect state and never a
model.** Worth saying plainly, because a schema that permitted a list of ticket references would
make the ambiguity representable and therefore permanent, and something downstream would then pick
the first element.

**The residual, named:** the sweep can only see what carries the stamp. A ticket a human filed
without it is invisible and will be duplicated. Three things reduce that and none eliminate it: the
automation applies the stamp itself so the normal path is stamped; the stamp's meaning and shape are
documented where humans file tickets; and a periodic reconciliation lists tickets in the project that
are security-shaped and unstamped, as a report for a human rather than as an automated match. Any
automated guess at which unstamped ticket "is probably" a given cluster would be exactly the
heuristic ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md section 9.3 refuses for cross-scanner identity, and for the same reason.

### 4.5 Deleted, moved, or the project archived — a dangling reference is not "no ticket"

> A reference that did not resolve is an **unresolved reference**. It is not an absence, and the
> difference decides whether something gets created.

The failure to avoid is mechanical: a permissions change narrows the automation's visibility, every
ledger reference stops resolving, the bridge reads that as "no ticket exists", and the estate gets a
complete duplicate set in one run.

**Why a not-found answer is not an absence, in the taxonomy's own terms.** This is
`observation_quality.DISTINCTION_NOT_OBSERVABLE`: "the control established that its channel
COLLAPSES two outcomes it is required to keep apart", with the registered example of a cloud API that
returns the same refusal for a resource that does not exist and one the caller cannot see, so
"denied and absent arrive identically". Issue trackers behave this way deliberately — hiding the
existence of private resources is a feature, not a defect. Its registered rule is the behaviour
required here: the result "STILL HOLDS, at the reduced strength it actually has", and the value is "a
routing instruction to correlate, not a licence to stop reporting."

**Required handling, by what the backend actually returned:**

| what came back | what it means | required behaviour |
|---|---|---|
| a redirect to a new location | the ticket moved and the backend is telling you where | follow it once, rewrite the ledger reference, **record the move as an event**. Never silently |
| not-found, from a channel **not** shown to be able to see tickets like this one | deleted, or invisible to this credential. Indistinguishable | **create nothing, clear nothing.** Mark the reference unresolved, report it, and route the hygiene claim to `DECISION_REQUIRED`. A human re-points or retires it |
| not-found, from a channel **shown** to be able to see such tickets | a positively established deletion | creation is permitted, and the ledger records that the predecessor was established deleted, by which probe |
| a permission refusal | the ticket may well exist | as the second row. A refusal is not an absence |
| the project or repository is archived or read-only | the tickets exist and cannot be written | reads continue; every write is withheld and **named**. Not an error per finding — a declared limitation of the cell, reported once |
| rate limited, or a server error | nothing was established | Section 4.1 |

**How a channel is shown to be able to see such tickets: a calibration probe.**
`observation_quality.DISTINCTION_OBSERVABLE` is the registered mechanism and its registered rule is
that the distinction must be "proven by a calibration probe whose answer is known in advance rather
than assumed from the channel's documentation". Concretely: before treating any not-found as a
deletion, resolve a **known-present** ticket in the same project with the same credential. If that
succeeds, the channel can see tickets in this project and a not-found is informative. If it does
not, the channel is collapsed and no not-found in that run may license creation. One extra call per
run, at most, and it is the call that prevents the duplicate-storm failure.

### 4.6 Both backends configured at once

**Exactly one backend is authoritative per (repo, environment) cell. Two configured at once is a
policy defect that fails the policy check, by name, when the configuration is read.**

Not "create in both" — that is two tickets for one obligation, two closures, two dispositions
requested, and the kit's own named hazard of one truth in more than one place, which it has already
been bitten by. Not "prefer whichever is listed first" either: a silent precedence rule is a decision
made by field order. ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md section 2 already establishes the shape for a configuration
that cannot be honoured: it "is not 'applied and then overridden' and it is not silently dropped. It
is a policy defect that fails the policy check", because "a silently-dropped override reads as
applied to everyone who wrote it."

**The one legitimate case is a migration, and it is dated.** Moving an estate from one tracker to
another is real work that spans months. Then:

- The **new** backend is authoritative; the old is **read-only**. Writes to the old one are withheld
  and named.
- The ledger carries **both** references, with the predecessor marked as such, so nothing in the
  history becomes unreachable.
- It is a **declared event with a named authority and an expiry**, exactly like the bounded
  reconciliation window a scanner-generation change gets in ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md section 5.5: "one dated
  reconciliation with an approver. It is not a standing right."
- On expiry with the migration incomplete, the configuration is back to being a defect. Silence does
  not renew it — the same mechanism `disposition_type`, `validation_debt_state` and
  `control_weakening` all use for their own exceptions.

---

## 5 · The update path

The owner's requirement is explicit that an existing ticket often "just doesn't need updating", so
the update set is enumerated in both directions. The second list is the one that matters.

### 5.1 What an automated run MAY update

Only inside the machine-owned block, or as a comment, or as a label the kit owns:

| may update | why it is safe | constraint |
|---|---|---|
| **last-seen**: the date and run reference of the most recent observation | an observation, not a decision | written from a **claimable** observation time per `provenance_identity.observation_time`; where none exists, recorded as unestablished, never as a date |
| **current effective severity**, its formula version, and the per-scanner severities | a derivation over preserved evidence, and `disposition_type`'s invariant permits it: "a disposition does not mutate evidence" — the original scanner severities are preserved forever | the run may **not** write the resulting SLA deadline (5.2). Scanner disagreement is recorded explicitly, never averaged |
| **fix availability becoming established, or changing** | upstream shipping a patch is new evidence | an establishment is recorded with its date and source. A downgrade toward "no fix" does not stop any clock (ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md section 8.7) |
| **SLA approaching or breached** | a computation over an existing deadline | the run may **announce** a breach and may **not** move the deadline. A breach is recorded as breached, never as compliant |
| **the finding having moved** | a recorded event, not a reset. ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md section 8.8 rule 2: "touching the file does not make it new, and moving it does not make it old" | `first_seen` carried forward untouched |
| **contributing scanners added or removed** | tool attribution is load-bearing | every contributor named; a detector that stopped contributing is named as stopped, not omitted |
| **cluster membership**: members added, members going `POTENTIALLY_ABSENT`, a split or a merge | the obligation's shape genuinely changed | a split or merge is an event with a record; nothing is deleted |
| **a missing stamp on a ticket the ledger already binds** | self-healing an index, not a decision | recorded as a repair, with the run that made it |
| **the rendered copy of the disposition** | it is a copy of the authority | marked as a rendering; divergence from the merged record is a **defect the run reports**, not something the run resolves in either direction |

### 5.2 What an automated run must NEVER update

> **A bot that can extend an expiry is a bot that can grant amnesty.**

| never | why |
|---|---|
| **the disposition** — `requested_disposition` or the disposition itself | it is a determination. A run that could write `FALSE_POSITIVE` is a run that can clear any finding, which is the entire failure this document opens with |
| **the approver, the reviewer, the reviewed-at, or the rationale** | the schema requires those precisely so an approval cannot be a rubber stamp; a bot filling them in is the rubber stamp |
| **any expiry** — a disposition's, an acceptance's, a mitigation's re-verification date, the cohort decision's | the mechanism *is* the expiry. `validation_debt_state.ACCEPTED_DEBT`: "Expiry is the mechanism. Silence must NEVER renew a deferral." `disposition_type`: `approved -> expired` is "automatic; silence NEVER renews". `control_weakening.WEAKENING_EXCEPTION_EXPIRED`: "Silence NEVER renews a weakening." Three namespaces, one rule, and a bot with write access to an expiry defeats all three at once |
| **the SLA deadline** | it is derived, and the arithmetic in ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md section 6 is `min(existing deadline, re-score date + period)` specifically so nothing can extend one. A bot writing a later date is a weakening whether or not it looks like one |
| **`first_seen`, or the flag that says the age is unestablished** | ledger entries are append-only with respect to `first_seen` (section 8.8 rule 1). Re-dating a finding is re-grandfathering it |
| **the justification or the evidence references** | they are the requester's claim and the reviewer's basis. A bot editing either changes what was approved after it was approved |
| **closing a ticket as a way of clearing a finding** | rule 7. The scanner clears findings |
| **closing a ticket at all, except as the recorded consequence of a verified clearance** | a bot that can close can bury |
| **reopening a ticket whose closure is backed by an unexpired approved disposition** | Section 4.2. Reopening on every run trains people to ignore the bridge, and a control people ignore is worse than none |
| **marking a ticket as a duplicate of another** | that is the cardinality judgement Section 4.4 sends to a human |
| **the cluster stamp, once set** | re-pointing a stamp re-points the history silently. A wrong stamp is repaired by a recorded human act |
| **anything outside the machine-owned block** | the rest of the ticket belongs to people |

### 5.3 The prohibition is structural, not a promise about the bot

A credential with write access to an issue can edit any field on it. So a rule that says "the
automation must not edit the expiry" is, on its own, exactly the kind of declaration the kit's third
structural failure is about: "declarations drift free of implementations", and "writing it down makes
it so" is named there as the assumption that is wrong.

**The mechanism is that the authority is not in the ticket.** The disposition, the approver and the
expiry live in a record on the protected default branch under CODEOWNERS. The gate reads that record.
The ticket holds a **rendering**. Therefore:

- The automation's tracker credential cannot change enforcement, whatever it writes, because nothing
  the gate consumes lives where that credential can reach.
- Changing a disposition requires a merge, which requires a review the tracker's permission model has
  no part in.
- An edit to the ticket's rendered copy is detectable: the run compares the rendering to the
  authority and reports divergence. A tampered rendering is a **defect the run surfaces**, not a
  change it honours.

That is the same pattern the kit already runs three times over — a declared registry, the actual
usage, and a check that fails on divergence — and it is the only form of this rule that survives
somebody rewriting the bridge in six months.

### 5.4 The machine-owned region

Automation writes inside explicit delimiters and nowhere else. Two consequences worth stating:

- **Human edits inside the block are overwritten**, and the delimiters say so in words a person
  reading the ticket will understand. Silently discarding somebody's note is how people learn to
  distrust the ticket.
- **A ticket whose delimiters are missing or damaged is not rewritten from scratch.** It is reported,
  and the block is re-appended rather than the body replaced. A bridge that regenerates a body loses
  every human sentence in it on its first bad parse.

### 5.5 Who approves what — and the defect of gating everything

> **A reconciler that needs a human for every create is a reconciler nobody will run.**

Sections 5.1 and 5.2 draw the line correctly, and the first implementation of this contract drew it
somewhere else. `scripts/ticket_model.py` carried the parent/child model in from a prior
engagement's ticket engine, and with it a numbered invariant: *every creation, closure, transition,
split, reopen, suppression and validation requires explicit human approval.* `scripts/reconcile_tickets.py`
applied it to **creation**. The result was a deterministic, idempotent, evidence-backed reconciler
that could not open a work item for a fingerprinted, anchored finding without somebody signing for
it — which is not a control. It is an off switch, and it would have been switched off.

**The correction, in the operator's words:** a human is consulted
*"for something like an exception, exclusion, risk acceptance, mitigation, false positive, something
that requires budget judgement or would impact the security and governance of the environment and
system."*

So the ticketing path now classifies every mutation into one of exactly two classes, **explicitly,
in a table in the code** — `scripts/ticket_model.py --explain-mutations` prints it, with the reason
each row is on the side it is on.

| class | what it covers | gate |
|---|---|---|
| `ROUTINE_RECONCILIATION` | creation, body re-sync, child linking, ledger binding, the ordinary ticket and task transitions, and closure reached **because every child is evidenced complete** | **runs unattended.** No approval is consulted and none is required |
| `GOVERNANCE_DISPOSITION` | exception · exclusion · false-positive disposition · risk acceptance · deferral and its renewal or ending · a compensating control accepted instead of a fix · closure reached by **judgement** rather than by evidence · anything committing budget · anything moving the security or governance posture | **a role approves it, with a readable reason.** The refusal is reported as its own outcome |

Four properties make that table a mechanism rather than a promise:

1. **`--apply` is still a gate, and it is not an approval.** It is the operator — or the policy that
   scheduled the run — intending writes this run rather than a plan. A schedule can set it. A
   schedule is not an approver, and it never stands in for one.
2. **An unstated class refuses.** A mutation absent from the table yields
   `MUTATION_CLASS_NOT_STATED` and is refused by name. Defaulting to automatic would hand a
   disposition the unattended path; defaulting to approval would rebuild the blanket gate. Neither
   default is safe, so there is none. The same rule catches an unrecognised disposition *request*:
   `risk-accepted` is not `risk_acceptance`, and quietly downgrading it to ordinary remediation work
   would answer "we are asking you to accept this risk" with "somebody please fix this".
3. **Where the routine path is unattended because it is evidenced, the evidence is required.**
   Closure under `ALL_CHILDREN_RESOLVED` refuses when the children are not supplied. Closing on an
   absence is not closing on evidence.
4. **An unattended mutation records itself as unattended.** The audit history names the reconciler,
   not a person and not "the system". The engine this model came from wrote the system into the actor
   field of an automatic reopen, and that is how an unapproved mutation comes to look signed-for six
   months later.

None of this changes section 5.2. **The automation still writes no disposition, no approver, no
expiry and no SLA deadline**, and the authority still lives in a record on the protected default
branch under CODEOWNERS. A disposition *request* reaching a ticket is not a disposition.

### 5.6 An elapsed deferral is a review obligation

> **Past due must be visible in the ordinary output, without anyone asking for it.**

The deferral discipline forbids silent reopening — correctly, and `validation_debt_state`,
`disposition_type` and `control_weakening` all carry the same rule in their own words: *silence must
never renew*. The first implementation stopped there, and that left a past-due deferral with nowhere
to go. In practice it meant one of two things, and both are the failure the rule exists to prevent:

- the deferral **went on suppressing**, because nobody was asked to renew it; or
- it **waited for a trigger nobody fires**, because reopening requires a named trigger and nothing
  in the kit generates one on a date.

So the date passing now produces a **state**, and the state is an obligation on a person:

| state | meaning | behaviour |
|---|---|---|
| `DEFERRAL_WITHIN_TERM` | end date recorded, reference date supplied, not yet elapsed | **not** reported. A signal that fires on deferrals in good standing is noise, and noise gets ignored |
| `DEFERRAL_PAST_DUE` | the end date is earlier than the reference date | reported in **every ordinary run** with no flag enabling it, and the run **exits 1** |
| `DEFERRAL_TERM_UNKNOWN` | no end date, a non-ISO date, an unreadable record, or no reference date supplied | reported **alongside** past due, never filtered out. An absent expiry is not an open-ended one; it is unspecified, and it is the hole this kit already shipped once |

What the run does **not** do:

- **Nothing reopens.** The task stays `DEFERRED`. A deferral that reopens because a date passed is
  an obligation changing state with nobody having decided anything.
- **Nothing goes on quietly suppressing.** The acceptance has lapsed, and the run says so until an
  authorised person acts.
- **The sweep mutates nothing.** Observing an elapsed deferral does not resolve it.

There are exactly **two doors out**, both `GOVERNANCE_DISPOSITION`:
`--resolve-deferral <task> --resolution reopen` ends the acceptance with a named trigger, and
`--resolution extend --until <date>` renews it to a **future** date with a **fresh** reason — the
original is not carried forward, because "still waiting" written once and inherited for three
quarters is renewal through silence. A renewal to a date already past is refused: it would rewrite
the past-due state to look resolved without the review happening.

There is deliberately **no "clear" or "dismiss"**. An obligation marked handled without the
acceptance being ended or renewed is a suppression with a tidier name, and the tidiness is the
danger.

The sweep reads the **whole ledger**, not only the clusters in the current run. A finding that
stopped being reported — fixed, or no longer scanned — still has an acceptance recorded against it,
and that acceptance must not become invisible because the scanner went quiet.

---

## 6 · Budget

GitHub bills every job **rounded up to a whole minute**, which the kit has already measured against
itself: a 13-job consumer did 415 seconds of real work for roughly 12 billed minutes, and four of
those jobs did 19 seconds between them. So the design target is not "fewer API calls" in the
abstract. It is **a call count that does not grow with the size of the estate's backlog, inside one
short job.**

### 6.1 Act on deltas only

**The ledger records what was true last run. That is the delta source, and it is free to read.**

```
for each cluster observed this run:
    prior = ledger entry for this cluster        (no API call)
    if prior.ticket_reference resolves in the sweep map AND
       nothing in the updatable set (5.1) changed since prior:
            DO NOTHING.  No read, no write, no comment.
    else:
            one write, or one creation, or one reported ambiguity.
```

**A finding that did not change costs zero calls and zero bytes.** This is the whole cost model, and
it also happens to be the correct behaviour for a different reason: a bridge that comments on every
ticket every run is a bridge whose notifications get filtered, after which the update path exists and
reaches nobody. `a_node_is_not_a_path` applies — a producer whose output nobody reads is a node, not
a path.

**What counts as changed is exactly the Section 5.1 set**, and nothing else. Notably a run in which a
finding was observed again with identical severity, identical fix availability, identical locus and
identical cluster membership is **not** a change, even though the last-seen date moved. Last-seen is
recorded in the **ledger** on every run, which costs nothing, and written to the **ticket** only when
something else is already being written or when a configured staleness interval has elapsed. Writing
a "still here" comment per finding per run is the single most expensive habit available.

### 6.2 Batch the lookups

The naive shape is one search per finding. For a legacy estate that is thousands of calls, most of
them against the most rate-limited endpoint a tracker has.

**The shape used instead is one sweep per backend per run:** read every ticket carrying the umbrella
stamp, in pages, and build the cluster-key-to-ticket map locally. Then every cluster's lookup is a
dictionary hit.

Three properties of that:

- **Cost is a function of tickets that exist, not findings observed.** A run over ten thousand
  findings and two hundred tickets does the same number of lookup calls as a run over one finding and
  two hundred tickets.
- **The map is built once and reused for every cluster**, so the many-to-one and one-to-many
  detections in Sections 4.3 and 4.4 are free rather than extra queries.
- **It is the only shape that can detect ambiguity at all.** A per-finding lookup that returns the
  first match cannot know a second exists.

### 6.3 The call count

Let:

```
F  findings observed this run
K  clusters this run                    (K <= F, and K << F on a well-covered repo)
T  tickets already carrying the umbrella stamp
C  clusters needing a NEW ticket
U  clusters with something in the 5.1 set changed
P  page size of the sweep
```

| phase | calls | grows with |
|---|---|---|
| ledger read | **0** | nothing. It is in the checkout |
| calibration probe (Section 4.5) | **1** | nothing |
| umbrella sweep | **ceil(T / P)** | **T** — tickets that exist |
| per-cluster lookup | **0** | nothing. Dictionary hits against the sweep map |
| updates | **U** (one call each; batched into one comment or one field write per ticket, never one per changed attribute) | **changed** clusters |
| creations | **C** | **new** clusters |
| resolving a dangling reference | **1 per unresolved reference**, bounded by a per-run ceiling | defects, and it is reported when the ceiling is hit |

```
total  =  1  +  ceil(T / P)  +  U  +  C  +  (bounded dangling resolutions)
```

**`F` does not appear.** That is the point of the design. A steady-state run on a mature repository
is `1 + ceil(T/P)` calls and nothing else — a handful.

### 6.4 The rate limits this budget was checked against

**GitHub — primary limits.** All from
https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api?apiVersion=2022-11-28:

| caller | documented limit |
|---|---|
| the Actions token, which is what a post-merge job holds by default | **1,000 requests per hour per repository**; "For requests to resources that belong to a GitHub Enterprise Cloud account, the limit is 15,000 requests per hour per repository" |
| a personal access token | **5,000 requests per hour** |
| a GitHub App installation token | **5,000 per hour** base, "another 50 requests per hour for each repository" above 20 repositories and the same per user above 20 users, capped: "The rate limit cannot increase beyond 12,500 requests per hour" |
| unauthenticated | 60 per hour |
| checking the budget | `GET /rate_limit`, and "Accessing this endpoint does not count against your REST API rate limit" (https://docs.github.com/en/rest/rate-limit/rate-limit?apiVersion=2022-11-28) |

**GitHub — the secondary limit that actually binds this workload.** Verbatim from the same page:

> "no more than 80 content-generating requests per minute and no more than 500 content-generating
> requests per hour are allowed."

Also documented there: no more than 100 concurrent requests; no more than 900 points per minute per
REST endpoint; no more than 90 seconds of CPU time per 60 seconds of real time.

**That 500 per hour is the ceiling the creation budget is set against, not the 1,000 or the 5,000.**
Three consequences, and the first is free money:

- **Set labels in the create call, not after it.** Creating the issue and then applying the label are
  two content-generating requests; the create call accepts `labels` directly. Folding them halves the
  cost of every new ticket against the binding limit. The same is true of the issue type.
- **The issue-field write is a separate call**, so a created and stamped ticket costs two against the
  500 rather than one. A day-one cohort of 3,000 clusters is therefore at least 6,000
  content-generating requests, which is **at least twelve hours of the documented hourly allowance** —
  Section 6.5, and not a number anybody should discover at run time.
- **Sweep calls are not content-generating**, so the read half of the budget is governed only by the
  primary limit. At 100 per page, a 10,000-ticket estate sweeps in 100 calls: 10% of an Actions token's
  hourly allowance, once per run.

**GitHub — search, avoided for this reason.** "For authenticated requests, you can make up to 30
requests per minute for all search endpoints except for the Search code endpoint"
(https://docs.github.com/en/rest/search/search?apiVersion=2022-11-28). A per-finding search design is
capped at 30 findings per minute before anything is written. The sweep design does not touch it.

**GitHub — GraphQL, mentioned only to be ruled out.** 5,000 points per hour per user, and "1,000 points
per hour per repository" in Actions, with the same 80-per-minute content rule
(https://docs.github.com/en/graphql/overview/rate-limits-and-node-limits-for-the-graphql-api). It buys
nothing here: the endpoints this design needs are all REST, and adding a second protocol adds a second
failure mode.

**Jira — there is no number to budget against, and that is the documented position.** From
https://developer.atlassian.com/cloud/jira/platform/rate-limiting/, the published cost-based quotas
apply only to apps: "The new rate limits will apply to all Forge, Connect, and OAuth 2.0 (3LO) apps."
And verbatim, for the case this bridge would actually be:

> "API token-based traffic is not affected by this change, and will continue to be governed by existing
> burst rate limits."

Those existing burst limits are **not defined numerically anywhere on that page**. What is documented is
the failure contract: "When any limit is exceeded, Jira returns an HTTP `429 Too Many Requests`
response", and "Your app should handle this gracefully by respecting the `Retry-After` header", with
`X-RateLimit-Limit`, `X-RateLimit-Remaining` and `X-RateLimit-Reset` available. Atlassian also states
that "these limits and the policies governing them are subject to change."

**So the Jira half of this budget is unbudgetable, and the design says so rather than inventing a
figure.** Consequences:

- **`Retry-After` is the primary mechanism, not a fallback**, and exhausting the retry ceiling is
  `BINDING_UNESTABLISHED` per Section 4.1 — never a create.
- **Bulk endpoints are used where they exist**, because they convert many requests into one:
  `POST /rest/api/3/issue/bulk` documents "Creates upto 50 issues", and there are bulk edit, move,
  transition and fetch equivalents
  (https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issues/).
- **The sweep asks for as few fields as possible**, because page size is field-dependent: the enhanced
  search documents "The maximum number of items to return per page... The greatest number of items
  returned per page is achieved when requesting `id` or `key` only. It returns max 5000 issues", with a
  default of 50. So the sweep requests the id, the key and the stamp field, and nothing else — and one
  page can cover an entire estate's worth of tickets.
- **Because the numbers are unpublished, the Jira path carries an observed-throughput record rather than
  a modelled one.** The run reports calls spent and any 429 encountered, so the budget becomes a
  measurement instead of an assumption. The kit's own standing rule applies: a hundred green runs
  establish less than one deliberately broken dependency handled correctly.

**Worked figures, for the two backends, steady state on a mature repository** (`T` = 400 stamped
tickets, `U` = 6 changed obligations, `C` = 1 new):

| | GitHub | Jira |
|---|---|---|
| calibration probe | 1 | 1 |
| sweep | 4 (`ceil(400/100)`) | 1 (one page, id and key and stamp only) |
| lookups | 0 | 0 |
| updates | 6 | 6 |
| creations | 2 (create-with-label, then the field write) | 1 (fields set in the create call) |
| **total** | **13** | **9** |

Against 1,000 primary requests per hour and 500 content-generating per hour on GitHub, that is
noise — which is the point. The cost problem is never the steady state; it is the first run, and that
is Section 6.5.

### 6.5 The creation budget per run, and why the day-one cohort needs one

A day-one baseline on a legacy estate produces a large `C`. ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md section 8.4 says so
plainly: "on a real legacy estate, day-one breaches are the expected output."

**So creation is budgeted per run, the budget is configured, and the remainder is carried, not
dropped.** Three requirements:

1. **The per-run creation ceiling is a declared number**, chosen against the backend's
   content-creation limits rather than guessed. Every number in this document is a placeholder
   awaiting an owner's decision, exactly as ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md section 13 says of its own.
2. **Clusters not ticketed this run are recorded as owing a ticket, with their position in the
   queue**, and the run says how many are outstanding. A truncated batch reported as a completed one
   is the same lie as a truncated scan reported as a clean one.
3. **The ordering is by consequence, not by discovery order** — highest effective severity and
   nearest SLA deadline first, so a ceiling delays the cheapest work rather than the most urgent.

**And the budget must never gate enforcement.** A finding with no ticket yet still routes exactly as
the rung says. If a creation ceiling could soften a finding, the cheapest way to weaken the gate
would be to file a lot of findings — which is section 3 of the baseline document in a new costume.

---

## 7 · Where this runs

### 7.1 Not in a pull-request job, and not because of the credential alone

> Ticketing must not run in a job that an untrusted fork can cause to execute while holding write
> credentials to an external tracker.

Two separate reasons, and the second is the one that settles it:

**The security reason.** A workflow triggered by a fork's pull request that nonetheless holds write
credentials is the shape that lets an outsider mint tickets, or worse, execute with the job's token.
The kit has already shipped and fixed exactly this class in its own ticket-reference gate: a pull
request body was interpolated into a `run:` block, so "anyone who can open a PR can run code", and
the registered class for it is
`untrusted_input_transport.UNTRUSTED_CONTEXT_INTERPOLATION`, severity critical.

**The architectural reason, which is stronger.** Ticketing does not belong in a pull-request run at
all, and this was already decided. ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md section 9.2: "Correlation and ticketing happen
outside the PR run. Both need the ledger and the ticket system; the PR run must not write to either.
A PR run consumes cluster identity; it does not create it." And section 5.4: ledger updates "are
produced by the post-merge or nightly run and merged to the protected branch under CODEOWNERS. **A PR
run may only read.**"

So there is no design in which ticketing wants pull-request credentials, and the safe answer is not
a hardened pull-request job — it is **no pull-request job**.

### 7.2 The trigger and permission model, reusing what the kit already does

**The pattern already exists and is named: privileged work happens after the merge or on a
schedule.** `scan_depth` registers `merge`, `nightly` and `revalidate` as trigger contexts, and
`selftest_reach` registers what each class of trigger does and does not catch. Ticketing rides that
rather than inventing a second pattern.

| | value | why |
|---|---|---|
| **trigger** | push to the protected default branch, plus a schedule | the merge is the governed act. The schedule catches what changed in the world rather than in the code — which is what `revalidate` is for, and is the case where a new advisory creates an obligation with no commit behind it |
| **rejected trigger** | anything fork-reachable that carries write credentials | it is the class above. A pattern that needs a paragraph of caveats to be safe will be unsafe the first time somebody copies it |
| **rejected trigger** | a run chained off a pull-request workflow's completion | it executes privileged logic on the default branch in response to something a fork caused. Cheaper to not have the pattern than to reason about it every time the bridge is edited |
| **permissions, declared per job** | `contents: read`. Write to the tracker only in the one job that needs it, and nowhere else in the file | the kit already does this: its script-materialising job declares `contents: read` explicitly rather than inheriting the workflow's `security-events: write`, on the stated grounds that inherited scope "is a larger blast radius than its purpose justifies and is invisible when reading it" |
| **credentials** | held in a protected deployment environment gated by the protected branch, so a run on any other ref cannot mint them | the kit's existing pattern for privileged targets, and `execution_unavailable_reason.POLICY_REFUSED` is already the registered state for an environment refusing a ref |
| **ledger writes** | a separate reviewed change, merged under CODEOWNERS | section 5.4's rule, unchanged. The ledger "is a governance artifact, not a scanner output", and the two must not share a write path |
| **bound** | `timeout-minutes` on the job | an unbounded job converts a tracker outage into billed minutes. The kit has the receipt: roughly 412 billed minutes for a silent blocking wait |

**The consequence to state out loud:** a ticket for a finding introduced in a pull request appears
**after the merge**, not on the pull request. That is deliberate. The pull request already gets the
finding, the routing and the summary; what it does not get is a write to a governance surface.

### 7.3 What the credential may reach

Least privilege, and written as a list because "least privilege" on its own has never constrained
anybody:

- **Create and comment on tickets in one configured project or repository.** Not the organisation.
- **Transition and reopen within that project only**, and only into states the configuration names.
- **No delete.** Nothing in this design deletes a ticket, so the reach should not exist.
- **No permission to administer** labels, fields, workflows or the project. The umbrella stamp and
  any needed field are provisioned **once, by a human**, as a prerequisite; a bridge that can create
  its own index can also fragment it.
- **No read outside the configured project**, so a leaked credential cannot enumerate the estate.

### 7.4 Injection and redaction — a tracker is a publication channel

**Finding text reaches the tracker as data, never as code.** Paths, messages, rule names and
snippets are all attacker-influenceable in a repository the kit scans. Every one arrives through
`env:` and is serialised by a program, never interpolated into a shell or script body. The registered
rule is unambiguous: "Any value GitHub does not constrain must arrive through `env:`, never through
`${{ }}` inside `run:` or a github-script body. In env: it is DATA. In the script it is CODE." The
correct state is `SAFE_ENV_TRANSPORT`, which the taxonomy notes "is the FIX and is never reported".

**Redaction runs before the ticket, not after it.** `credential_redaction`'s registered rule is
"Redaction runs BEFORE every publication step — artifact and Security tab both. A redactor after the
upload protects nothing while looking exactly like protection." A ticket is another publication step
and inherits it. Concretely: a ticket body carries rule id, severity, file, line and a short
identifying prefix; it carries no snippet, no context region, no code-flow snippet and no
scanner-supplied partial fingerprint — the last of which, for a secret scanner, "can be a hash OF the
secret". ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md section 5.2 makes the same point about the ledger, and a ticket is more
widely readable than a ledger.

**The stamp is derived from the cluster key and the cluster key contains no secret material**, by
construction, because the ledger holds none (section 5.7). A stamp that embedded a hash of matched
content would publish an offline-crackable oracle to whoever can read the project.

---

## 8 · How these decisions are recorded

Same three properties as every other governance position in the kit, and the same reasons.

| decision | recorded as | required fields | reconciled against |
|---|---|---|---|
| which backend is authoritative for a cell | repo policy file, protected branch, CODEOWNERS | repo, environment, backend, project identifier, stamp shape, approver, date | the configuration the run actually read. Two backends fails the policy check |
| the field or label the stamp lives in | same file, as a pinned identifier | backend, identifier, the date it was discovered, who provisioned it | resolved at run start; an identifier that no longer resolves is reported, never guessed at |
| cluster to ticket binding | the ledger entry for that cluster | cluster key, backend, reference, bound-at, bound-by run, predecessor references retained | the sweep. A binding that does not resolve is unresolved, not absent |
| a binding that could not be established | the same entry | outcome, cause, attempts, first-degraded-at | the next run, which acts on it without re-deriving |
| an ambiguity | the same entry | every candidate reference and its state, detected-at | a human's canonical declaration, recorded as an event |
| reopen, successor, split, merge, move | event record | references before and after, reason, run, date, and who, where a human acted | the ledger's history, which is append-only |
| a backend migration | repo policy file | from, to, authority, reason, expiry | the expiry. Silence does not renew it |
| the per-run creation ceiling and the staleness interval | profile or policy file | value, approver, date | the run's own report of how many clusters were carried |

**On the protected default branch, under CODEOWNERS** — a decision readable from the pull request it
governs is a self-signed decision.

**Emitted into the run record** — the run summary states the backend, the lookup outcome distribution,
how many tickets were created, updated, carried and reported ambiguous, and the calls spent. A bridge
that reported only "done" would be the weakening-that-nobody-emitted failure in a new place.

**Carrying an expiry or a review trigger** — `validation_debt_state.IMPLEMENTATION_HELD` is the shape:
"an activation TRIGGER rather than only a date... The date remains as a backstop so it cannot be held
indefinitely without anyone looking." The backend registration returns to review when the project
changes, the stamp identifier changes, or the credential is rotated.

---

## 9 · CANDIDATE registrations — proposed, not adopted

> **These are CANDIDATES.** Registration is the **third** remedy in `docs/operations/TAXONOMY_DRIFT.md`,
> after correcting a malformed term and after reusing an existing one, and a pre-filled block "is a
> candidate registration, not a fix". Each block states what was checked first. Each must survive the
> four questions — semantics, namespace, transitions, consumers — before anybody pastes it anywhere.
>
> **Two, deliberately.** ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md section 12.6 already warns that five namespaces for one
> mechanism is too many and that a reviewer should expect to reject or merge two. Adding five more
> here would be the same mistake in the same week. Everything else in this document reuses registered
> vocabulary or the existing request schema.

### 9.1 `ticket_class` — CANDIDATE

**Checked first.** `disposition_type` owns the *authorized determination* about one finding, matched
by fingerprint — a ticket class is the *kind of request* that could result in one, and putting them
in one namespace is precisely the collapse this document opens by refusing: it would let a request
wear a determination's authority. `schemas/disposition-request.schema.json` owns two axes already and
neither is this one: `requested_disposition` is the security claim (and its enum is the four
registered `disposition_type` values, reused unchanged) and `request_state` is the governance state.
A class is a third fact — *what the ticket is for* — and it decides the approver, the evidence owed,
the expiry rule and whether an expiry is chosen or computed. `finding_classification` is what a red
result *means*, assigned before anything is changed, which is upstream of any ticket.
`capability_origin.OVERLAY_SPECIFIC_POLICY` correctly says a tracker's local rules are policy rather
than capability, and that governs the *values* of things like an id format, not this namespace.

```yaml
  ticket_class:
    description: >-
      What a tracker item is FOR, and therefore which disposition it may result in, who may approve
      it, and what its expiry is derived from. A ticket is a REQUEST for a disposition and never the
      disposition itself.
    consumers: [the ticketing bridge, promotion review, audit, security-gate for routing only]
    rule: >-
      A CLASS NEVER SUPPRESSES ANYTHING. Suppression requires an exact, unexpired, approved
      disposition merged to the protected default branch. A class decides who is asked and what
      evidence is owed; it decides nothing about enforcement.
    values:
      REMEDIATION_WORK_ITEM:
        definition: The finding is valid and is being fixed. Requests no authorization from anyone.
        results_in: REMEDIATED
        rule: >-
          Closed by the scanner no longer reproducing the finding over a scope shown to cover where
          it lived -- never by the ticket being closed. REMEDIATED is self_invalidating, so a closed
          item beside a reproducing finding is a falsified disposition and not a cleared finding.
      FALSE_POSITIVE_REQUEST:
        definition: A claim that the detector is wrong about this finding. A request, not a finding.
        results_in: FALSE_POSITIVE
        rule: >-
          Approved by Security, distinct from the requester where team_pattern permits it. For a
          secret finding the much narrower secrets_rule path applies and "it looks like a secret but
          probably isn't" does not qualify.
      ACCEPTED_RISK_REQUEST:
        definition: >-
          A request to proceed with a valid finding that will not be fixed now, with a CHOSEN expiry
          and a named accepting authority.
        results_in: ACCEPTED_RISK
        rule: >-
          Spelled to match the registered disposition. Spelled to match the registered disposition rather than the reversed word order that
          disposition_type.rejected_synonyms already refused. A near-miss spelling reads as blank to
          a consumer, which is worse than a wild one.
      MITIGATED_REQUEST:
        definition: >-
          The owner's "mitigation record". A request backed by a named compensating control that is
          IN FORCE and evidenced. The finding remains open and observable.
        results_in: MITIGATED
        rule: >-
          Carries its OWN re-verification expiry rather than a closure, because a compensating
          control can lapse silently. Never upgrades to REMEDIATED, not even when the scanner stops
          reproducing the finding -- that is a determination, and automation may not make one.
      GRANDFATHER_TRACK_ITEM:
        definition: >-
          A finding established as already present in the target environment, scheduled on a
          remediation track rather than blocking new work.
        results_in: ACCEPTED_RISK
        rule: >-
          ACCEPTED_RISK plus a track reference plus an expiry COMPUTED from the severity SLA rather
          than chosen. Admissible only where fix availability has been established. Not a new
          disposition class -- ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md section 8.1 checked and the
          registered vocabulary already held it.
```

**Open, and better decided by a reviewer than by this document:** whether a finding whose fix
availability has not been established needs a sixth class, or is a state on
`REMEDIATION_WORK_ITEM`. The second is probably right and is not obviously right.

### 9.2 `ticket_lookup_outcome` — CANDIDATE

**Checked first.** `observation_quality` is the closest fit and cannot carry it: it has
`VERIFIED_ABSENT` for an established absence and `DISTINCTION_NOT_OBSERVABLE` for a collapsed
channel — both of which are **reused inside** the values below rather than respelled — but it has no
value for *cardinality* (more than one candidate) and none for a *reference that did not resolve*,
and those are the two outcomes that decide whether anything is created. The CANDIDATE
`finding_identity_match` in ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md section 12.2 has deliberately the same five-answer
shape and a different subject: it matches a finding against the **ledger**, this matches an
obligation against a **tracker**, and one namespace covering both would be two models in one word.
`authorization_probe_outcome` is about what a deliberate access attempt established about an
**authorization boundary** — its not-found value means a named scope did not resolve and "PROVES
NOTHING ABOUT AUTHORIZATION, in either direction" — so borrowing it would make an existence question
wear an authorization answer. `artifact_identity` asks whether inspected bytes are published bytes.
`publication_state` owns whether evidence reached a channel and its `PUBLICATION_DEGRADED` is reused
for the degraded case, but it cannot express a binding.

```yaml
  ticket_lookup_outcome:
    description: >-
      What the pre-creation cascade established about whether an obligation already has a tracker
      item. Six answers, never a boolean, because "nothing is there" and "I could not look" decide
      opposite things about whether to create.
    consumers: [the ticketing bridge, the ledger, promotion review, cost reporting]
    rule: >-
      EXACTLY ONE OUTCOME PERMITS CREATION, and it requires absence to have been POSITIVELY
      ESTABLISHED through a channel shown to be able to see items it does not own. A failed lookup
      resolving toward creation is how an estate gets hundreds of duplicates overnight;
      absence_is_not_a_negative_observation applies unchanged.
    values:
      LEDGER_BOUND:
        definition: The ledger held a reference for this obligation and it resolved in the sweep.
        rule: The zero-cost path and the expected steady state. Creates nothing.
      BACKEND_BOUND:
        definition: >-
          The ledger held no reference and exactly one stamped item was found. The item exists and
          the ledger was out of date.
        rule: >-
          Creates nothing AND owes a ledger repair. Distinct from LEDGER_BOUND because a ledger that
          silently disagrees with the tracker is a governance artifact drifting from reality.
      BINDING_ABSENT:
        definition: >-
          The ledger held no reference, the sweep found none, and the channel was shown able to see
          items of this kind. observation_quality.VERIFIED_ABSENT, for a tracker.
        rule: THE ONLY OUTCOME FROM WHICH CREATION IS AVAILABLE.
      BINDING_AMBIGUOUS:
        definition: More than one stamped item claims this obligation.
        rule: >-
          Creates nothing and UPDATES NOTHING -- updating one of several is picking, by whatever
          order the API returned. Every candidate is named and a human declares the canonical one.
          Cardinality, never guessing.
      BINDING_DANGLING:
        definition: >-
          A reference existed and did not resolve: not found, refused, or moved without a
          redirect.
        rule: >-
          NOT AN ABSENCE. Where the backend returns the same answer for an item that was deleted and
          one this credential cannot see, that is observation_quality.DISTINCTION_NOT_OBSERVABLE and
          the result holds at the reduced strength it actually has. Creation requires a calibration
          probe establishing DISTINCTION_OBSERVABLE first.
      BINDING_UNESTABLISHED:
        definition: >-
          The lookup did not complete -- rate limited, unavailable, unauthenticated, or an error
          nobody classified.
        rule: >-
          THE UNCLASSIFIED CASE DEFAULTS HERE, never to BINDING_ABSENT. Projects to
          publication_state.PUBLICATION_DEGRADED for the ticketing claim and
          routing_result.EVIDENCE_UNTRUSTED for the run's ticketing result -- and NEVER changes the
          finding's own routing under the rung.
```

**Not registered here:** ticket STATE. GitHub and Jira each own a state model, Jira's is per-project
and configurable, and minting a third spelling of "open" would be the drift `reconcile_taxonomy.py`
exists to catch. The bridge **reads** the backend's state, **records** it verbatim alongside the
backend's name, and **projects** it only where a decision needs it — and the projection is recorded,
per `projection`'s rule that the integrity violation is "a lossy projection masquerading as the
richer state it came from".

---

## 10 · Terms this document leans on that are CANDIDATE elsewhere

Named so nobody reads a proposal as a registration. All five were proposed in
`ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md` section 12 and none is registered in
`assurance-taxonomy.yaml` v1.

| namespace | proposed in | what this document uses it for |
|---|---|---|
| `finding_baseline_state` | section 12.1 | which findings are eligible for a grandfather track item at all |
| `finding_identity_match` | section 12.2 | the cluster identity the stamp is derived from, and the shape Section 9.2 deliberately mirrors |
| `fix_availability` | section 12.3 | admission to a track, and the one attribute in Section 5.1 whose change is new evidence rather than a decision |
| `remediation_track_state` | section 12.4 | what a grandfather track item's progress is, and the source of the stalled-mechanism shape reused in Section 4.1 |
| `correlation_confidence` | section 12.5 | why the stamp is keyed on a cluster rather than an observation, and why an automatically clustered obligation and a heuristically proposed one are not the same thing |

**Reused, and registered:** `disposition_type` and its four values and its invariant;
`finding_classification.REOPENED_BY_LAPSE`, `POTENTIALLY_ABSENT` and `UNKNOWN`; `routing_result` and
its precedence; `observation_quality.VERIFIED_ABSENT`, `DISTINCTION_OBSERVABLE` and
`DISTINCTION_NOT_OBSERVABLE`; `publication_state.PUBLICATION_DEGRADED`;
`suppression_reason.FAILURE_ISOLATION_WITH_STATE_CAPTURE`;
`untrusted_input_transport.UNTRUSTED_CONTEXT_INTERPOLATION` and `SAFE_ENV_TRANSPORT`;
`credential_redaction` and its `SECRET_PATTERNS`; `control_weakening.WEAKENING_UNATTRIBUTED` and
`WEAKENING_EXCEPTION_EXPIRED`; `validation_debt_state.ACCEPTED_DEBT` and `IMPLEMENTATION_HELD`;
`provenance_identity` and its `observation_time` tiers; `evidence_confidence`'s tool-attribution
warning; `team_pattern`; `environment_tier`; `scan_depth`; `capability_origin.OVERLAY_SPECIFIC_POLICY`;
`execution_unavailable_reason.POLICY_REFUSED`; and the invariants
`absence_is_not_a_negative_observation`, `authority_never_grows_from_loss`,
`partial_is_not_total_ignorance`, `a_node_is_not_a_path` and
`defaults_are_suspicious_at_assurance_boundaries`.

**Reused verbatim, and not vocabulary:** `request_state` and `requested_disposition` from
`schemas/disposition-request.schema.json`. That schema already separates the request from the
determination, which is this document's central claim, and it was written before this document.

---

## 11 · What could not be settled

Named plainly, because a document that answered everything about a bridge nobody has built would be
lying.

### 11.1 Whether the owner's estate has a Jira project to target at all

**Not established, and nothing in either repository establishes it.**

What exists is an overlay gate, a consumer overlay's `workflows/validate-jira-reference.yml`, which
requires two repository variables — a Jira host and a project key — and whose own not-configured path
prints "Nothing was checked. This is unestablished scope, not a clean result." That file is evidence
that somebody expected a Jira project. It is not evidence that one exists. Its own assurance block is
explicit about the boundary: "reference supplied != URL well-formed != key syntactically valid != the
issue exists", and it states that establishing existence "needs a Jira API call and is left as a
declared gap rather than implied".

So the following are all unknown here, and every one of them is a prerequisite for the Jira half of
this document to be implementable:

- whether a project exists, and whether the kit's automation would be permitted to write to it;
- its issue types, and which fields are on their screens — which decides what the create call may set;
- whether a single-line custom field can be **provisioned** for the stamp, and by whom. The bridge is
  deliberately not permitted to create one (Section 7.3), so this is a human prerequisite with an owner
  who has not been named;
- its workflow, and therefore whether any transition back out of a done status exists — which decides
  whether Section 4.2's reopen path or its successor path is the normal case;
- who administers it, and whether an archived-project or trashed-project regime is in force.

The overlay's own 3-to-4-digit issue-number policy hints at a project with fewer than ten thousand
issues, and the overlay itself warns that this is "THIS employer's ticketing rule" and that encoding
today's volume as permanent policy "starts rejecting legitimate work the day the project crosses the
ceiling". A hint is not an establishment.

> **SUPERSEDED 2026-10-14 (KDEC-004).** The owner established Jira as the system of record, with a
> personal site to prove against. The sequencing below is replaced by
> `TICKETING_BACKENDS.md`: Jira first, Azure DevOps second, and GitHub Issues kept but not extended.
> The unknowns listed above become configuration the bridge validates at run start.

**Consequence for sequencing (as written 2026-09-23, superseded):** GitHub Issues is the backend that can be built against verified
documentation today. Jira is the backend that needs an estate survey first. Building both at once
would mean building one of them against assumptions.

### 11.2 What could not be verified about the Jira API

Each of these is a real gap rather than a detail, because each one changes a behaviour above:

| unverified | why it matters | what was found instead |
|---|---|---|
| Jira label constraints — the no-spaces rule and the 255-character limit | decides whether a label is usable as a fallback stamp | both appear only in Atlassian error strings and issue trackers, not the REST reference; and https://jira.atlassian.com/browse/JRACLOUD-82154 reports that Jira Cloud allows a label containing a space, so the rule is not reliably enforced. **Validate client-side; do not rely on the backend to refuse a malformed stamp** |
| the removal schedule behind CHANGE-2046 | decides how long the legacy search endpoint keeps working during a build | the changelog is client-rendered and could not be read; dates circulate only in community threads. The OpenAPI's "Currently being removed" is the only primary signal |
| whether an archived or trashed issue can be fetched by key or id through REST | decides whether a dangling reference can ever be positively resolved after archival | documented only that such items leave the search index and remain reachable "through direct links" |
| a verbatim statement that custom field ids are per-instance | decides how confidently the pinned-id design can be described | structurally certain from the absence of name-based addressing; the canonical page is a knowledge base article |
| whether the old key redirects after an API-initiated bulk move | decides whether a stored key can ever be trusted | a knowledge base article describes the mechanism and its third-party failure modes. The design avoids the question by storing the numeric id |
| the per-site burst rate limits for token authentication | decides the Jira creation budget | explicitly out of scope of Atlassian's published quotas, with no figure given |

### 11.3 What could not be verified about the GitHub API

| unverified | why it matters |
|---|---|
| maximum label name length, permitted characters, maximum labels per issue, maximum labels per repository | four unverified limits, which is why a label per cluster was rejected in Section 3.2 |
| whether the `labels` list parameter conjoins or disjoins multiple names | the sweep is designed not to need it, which is the only safe response to not knowing |
| whether issue-field values are returned by, or filterable on, the issues list endpoint | if they are, the body block becomes redundant and the sweep gets simpler. If they are not, a field-only design costs one call per issue and is unaffordable. **This is the single most valuable thing to establish by experiment before building** |
| whether organisation issue fields survive an issue transfer between repositories | labels are documented as conditionally retained; fields are not addressed |
| the maximum number of issue fields per organisation | a figure appears in a GitHub guide page rather than the API reference, and it was not captured verbatim. If the cap is small, the stamp competes with everything else the organisation wants fields for |
| what happens to the issue number on transfer | the design stores the API URL and node identifier as well, which makes the answer not matter |
| whether a not-found response distinguishes a deleted issue from one this credential cannot see | this is the premise of the calibration probe in Section 4.5. The probe is required **because** the answer is unverified, not because the collapse is documented |
| the reported September 2025 change of default behaviour for `GET /search/issues` | the endpoint is not flagged deprecated in GitHub's current OpenAPI description and no GitHub page carries the date. The design does not use the endpoint, so it does not depend on the answer |

### 11.4 Design questions this document deliberately did not decide

**Whether the tracker's own approval state can ever be a trusted signal.** Section 1 rules it out as an
authority. Whether it can be read as *evidence* that a review happened — shortening the path for a
reviewer who has already argued the case in the ticket — is a real usability question and the answer
depends on whether the tracker's permission model can be established at all. Recording it as a signal
and never as an authority is probably right and is not obviously sufficient.

**Every number.** The per-run creation ceiling, the staleness interval at which a still-here update is
worth a call, the consecutive-degraded-run threshold that escalates to a promotion review, and the
per-run ceiling on dangling-reference resolutions are all placeholders. The baseline document says the
same of its own and the sentence transfers: none of them should be implemented as a constant.

**Whether the day-one cohort should produce one ticket or thousands.** Section 6.5 budgets for
thousands. But the baseline document's cohort decision is "a one-time, dated, enumerated cohort
decision, addressed to a named authority, with a scheduled burn-down", which is *one* governance object
— and a single tracker item holding an enumerated cohort with a burn-down schedule may be both cheaper
and more honest than three thousand items nobody will read. The argument against it is that a cohort
ticket cannot be assigned, and work that cannot be assigned does not get done. Genuinely open, and worth
deciding before the first run rather than after it.

**Whether a cluster should be a parent item with children rather than one item.** Both backends support
a hierarchy — GitHub sub-issues (https://docs.github.com/en/rest/issues/sub-issues?apiVersion=2022-11-28)
and Jira subtasks — and that would model the many-to-one relationship in Section 4.3 natively instead of
in a body block. It was not explored: GitHub documents no nesting-depth or count limit for sub-issues
and does warn that "Creating content too quickly using this endpoint may result in secondary rate
limiting", which means a hierarchy multiplies the write cost by cluster size against the tightest limit
in the system. Cheaper is not the same as better and this was not measured.

**Whether unstamped hand-made tickets can be reconciled at all.** Section 4.4 proposes a periodic report
for a human and refuses to guess. Whether such a report is actionable on a legacy estate, or is simply a
long list nobody reads, is unknown — and a report nobody reads is `a_node_is_not_a_path` with a cron
schedule.

**Whether the bridge should hold an App identity rather than the Actions token.** An App installation
gets a higher and separately-scoped primary allowance and a reviewable permission set; the Actions token
gets 1,000 requests per hour per repository and is already present. The kit ships no App, and
introducing one is a custody and secret-management decision rather than a rate-limit calculation.

**How a ledger-to-tracker reconciliation is reviewed at estate scale.** This inherits the baseline
document's open question about ledger scale directly: if a reviewed file on a protected branch is the
wrong storage for tens of thousands of entries, it is also the wrong storage for tens of thousands of
ticket bindings, and the diff of a bridge run is exactly the artefact "a ledger nobody can review"
describes.

---

## 12 · The one-paragraph version

A tracker item is a REQUEST for a disposition and never the disposition itself, because otherwise
anyone who can open an issue can clear a finding; the five classes the owner named map onto the four
registered `disposition_type` values with the grandfather track item being `ACCEPTED_RISK` plus a
track and an SLA-computed expiry, and an item that is merely open softens nothing at any rung. Before
anything is created the bridge reads the ledger's obligation-to-item mapping for free, then does one
paginated sweep of every item carrying a machine-readable stamp — a label or a custom field, never
title text — and creates only where both established absence through a channel proven able to see
items it does not own. A lookup that failed creates nothing and clears nothing: it records the
obligation as outstanding with its cause, reports the ticketing claim as a degraded publication
channel routing `EVIDENCE_UNTRUSTED`, and leaves the finding's routing under the rung exactly where
the evidence put it. A closed item is reopened when its closure is unbacked, expired or a falsified
`REMEDIATED`, and left alone while an unexpired approved disposition stands; more than one candidate
item is an ambiguity reported by cardinality rather than resolved by guessing; a reference that did
not resolve is unresolved and never an absence; and two backends configured at once is a policy
defect, not a precedence puzzle. Automation may update last-seen, severity, fix availability, breach
status, movement and cluster membership, and may never touch the disposition, the approver or any
expiry — enforced not by asking the bot nicely but by keeping the authority on the protected branch
where the bot's credential does not reach. The whole thing runs after the merge and on a schedule,
never in a fork-reachable job with tracker write credentials, and costs one calibration call plus one
paginated sweep plus one write per genuinely changed obligation, which is a cost that grows with the
backlog that exists rather than with the findings observed.
