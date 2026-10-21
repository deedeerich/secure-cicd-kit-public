# Ticketing backends: Jira first, Azure DevOps second

```
Phase:              design, decided 2026-10-14. The build follows this file.
Truth State:        DECIDED by the owner (KDEC-004). API facts are cited, or marked UNVERIFIED.
Audience:           whoever builds or tests the ticketing bridge
Decision Supported: which tracker the kit writes to, what it writes, how it finds what it wrote,
                    and what "proven" means before a consumer's tracker is pointed at
Deferred Depth:     four-tier hierarchy (WORK_ITEM_HIERARCHY.md); GitHub Issues, kept, not built further
Supersedes:         TICKETING_CONTRACT.md section 11.1's sequencing ("GitHub Issues first; Jira only
                    after an estate survey"). Everything else in TICKETING_CONTRACT.md stands.
```

> **TICKETING_CONTRACT.md is still the contract.** A ticket is a request, never a disposition. The
> six lookup outcomes, the calibration probe, the update and never-update lists, the delta-only
> budget, and post-merge-only execution are all unchanged. This file decides only which backends
> carry it, in what order, and how each one is shaped.

---

## 1 · The decision

| | |
|---|---|
| **Authoritative backend** | **Jira Cloud.** This is the tracker the work is actually done in. |
| **Second backend** | **Azure DevOps Boards.** The same contract and the same hierarchy depth; a rename, not a redesign (WORK_ITEM_HIERARCHY.md). |
| **GitHub Issues** | Already built. Kept as a supported backend, and not extended until someone needs it. |
| **One backend per cell** | Unchanged (TICKETING_CONTRACT.md section 4.6). Configuring two at once is a policy defect, refused by name. |
| **Where it is proven** | **The owner's personal Jira site and personal Azure DevOps organisation**, never a consumer's tracker. |
| **Moving to a consumer's tracker** | Changes **configuration values only**: the host, project and credential. No code, no workflow file and no stamp format changes. A test proves this (section 6, test B-1). |

**Why the survey precondition is gone.** Section 11.1 deferred Jira because nobody had established
that a project existed to write to. The owner has now established it: Jira is the system of record,
and a personal site exists to prove against. The unknowns 11.1 listed (issue types, fields,
workflow, transitions) are no longer survey questions. They are **configuration the bridge validates
at run start** (section 4), so a wrong guess becomes a refusal by name, not a silent mis-write.

---

## 2 · The hierarchy, per backend

Three tiers (WORK_ITEM_HIERARCHY.md, decided 2026-09-24, forced by both plans):

| tier | meaning | Jira (team-managed) | Azure DevOps (Basic, inherited) | who creates it |
|---|---|---|---|---|
| 1 | product | `Epic` | `Epic` | **a human, once.** Referenced by id in configuration. The bridge never creates a tier-1 item |
| 0 | vulnerability or class: one correlation cluster | `Story` | `Issue` | the bridge (`ROUTINE_RECONCILIATION`) |
| −1 | instance: one observation at one locus | `Subtask` | `Task` | the bridge, up to a per-class threshold; above it the class carries a count and an evidence artifact (WORK_ITEM_HIERARCHY.md, "Volume") |

**The stamp lives on the tier-0 item only.** The tier-0 item is the unit that check-before-create
looks up. Instances are found through their parent, never by a sweep of their own.

**Closure is one-way.** A tier-0 item closes only when every instance under it has closed on
scanner evidence (TICKETING_CONTRACT.md section 4.3). An instance never closes because its parent
did. Both trackers will cascade closure downward if asked, so the bridge never asks.

---

## 3 · Jira Cloud

### 3.1 Configuration: every value that differs between a personal site and a consumer's

| variable | meaning | validated at run start by |
|---|---|---|
| `TICKET_BACKEND=jira` | selects this backend | `choose_backend`: exactly one backend, or refuse |
| `JIRA_HOST` | `https://<site>.atlassian.net` | well-formed https URL, no path, no credentials in it |
| `JIRA_EMAIL`, `JIRA_TOKEN` | basic auth is `email:token` (the token alone returns 401) | the probe (3.4). Never logged, never echoed, held only in a protected environment |
| `JIRA_PROJECT` | project key | `GET /rest/api/3/project/{key}` resolves |
| `JIRA_STAMP_FIELD` | `customfield_<id>`, a **single-line text** field provisioned once by a human | createmeta (3.2) lists it as settable on the tier-0 type, with schema `string` |
| `JIRA_TYPE_CLUSTER`, `JIRA_TYPE_INSTANCE` | default `Story`, `Subtask` | createmeta lists both in the project |
| `JIRA_EPIC_ID` | numeric id of the product's tier-1 item | resolves, and is in the project |
| `JIRA_CALIBRATION_ISSUE` | numeric id of a **known-present ticket this credential did not create**, made once by a human | the calibration probe (3.4) |
| `JIRA_TRANSITION_REOPEN`, `JIRA_TRANSITION_DONE` | transition **names**, mapped to ids at runtime | read from `/transitions` per issue. An absent name means the successor path (TICKETING_CONTRACT.md 4.2), never a guess |
| `TICKET_STAMP_LABEL` | umbrella label, default `secure-cicd-kit` | must contain no spaces; validated client-side (TICKETING_CONTRACT.md 11.2) |
| `TICKET_CREATE_CEILING` | per-run creation ceiling | a positive integer from the policy file. No default constant in code (TICKETING_CONTRACT.md 11.4) |

**A missing or invalid value is a refusal with the value's name**, and the ticketing claim routes
`EVIDENCE_UNTRUSTED` / `PUBLICATION_DEGRADED`. The control being off (`TICKET_BACKEND` unset) is
reported as *off*, never as *nothing to ticket*.

### 3.2 Run start: establish the shape once, then act

1. `GET /rest/api/3/project/{key}`: the project is readable.
2. `GET /rest/api/3/issue/createmeta/{projectIdOrKey}/issuetypes`, then the tier-0 type's fields:
   the stamp field is present and settable, and both issue types exist. TICKETING_CONTRACT.md 3.2
   applies: "field not found" is **could-not-establish**, never absence, because discovery omits
   fields that aren't on a screen.
3. The calibration probe (3.4).

If any step fails, **nothing is created and nothing is updated** this run. The obligations are
carried in the ledger with the cause (TICKETING_CONTRACT.md 4.1).

### 3.3 Sweep, create, update

- **Sweep.** `POST /rest/api/3/search/jql` with
  `project = "<key>" AND labels = "<umbrella>" AND issuetype = "<cluster type>"`, bounded by project
  as the endpoint requires. `fields` = `[stamp field, status, labels]` only. Page by `nextPageToken`;
  `maxResults` is the largest the endpoint honours for those fields. Ledger-referenced ids are passed
  as `reconcileIssues` (read-after-write consistency for exactly the set where a false absence costs
  most). Hitting the page safety cap marks the sweep **PARTIAL**: every count is a floor and no miss
  licenses creation. *Today's code sweeps the whole project without the umbrella label; that is a
  defect to fix (section 7).*
- **Create.** One `POST /rest/api/3/issue` per new cluster, in consequence order (highest effective
  severity and nearest SLA first, TICKETING_CONTRACT.md 6.5). It sets these fields in the **same**
  call:
  - `issuetype`, `summary`;
  - `labels: [umbrella, family]` (`sca`, `sast`, `secrets`, `iac` or `container`; the rollup
    WORK_ITEM_HIERARCHY.md moved to a label);
  - `parent: {id: JIRA_EPIC_ID}`;
  - the stamp field;
  - `description` in **Atlassian Document Format** carrying the delimited machine-owned block
    (TICKETING_CONTRACT.md 3.3, 5.4).

  Instances are created as subtasks with `parent: {id: <tier-0 id>}`. When `C` exceeds a batch
  threshold, use bulk create (`POST /rest/api/3/issue/bulk`, up to 50 per call, cited in
  TICKETING_CONTRACT.md 6.4). **Never read after write.** The ledger records the new numeric id in
  the same run. *Today's code creates `Task` with no description, no parent and no labels; that is a
  defect to fix.*
- **Update.** Only the TICKETING_CONTRACT.md 5.1 set, as one comment (ADF) or one write to the
  machine-owned block per changed ticket. Nothing in the 5.2 never-list. Last-seen goes to the
  ledger every run, and to the ticket only on another write or after the staleness interval.
- **Reopen.** `GET /rest/api/3/issue/{id}/transitions`, then post the id whose name equals
  `JIRA_TRANSITION_REOPEN`. An empty list is ambiguous between *not permitted* and *not applicable*
  (DISTINCTION_NOT_OBSERVABLE). Then the successor path: a new tier-0 item referencing the
  predecessor, both recorded in the ledger history, with the reason. *Not built today.*
- **Throttling.** On `429` or `503`, wait for `Retry-After` (seconds or HTTP-date). If the header is
  absent, use bounded exponential backoff with jitter, under a per-run ceiling. Exhausting the ceiling
  is `BINDING_UNESTABLISHED`, **never a create**. Each run reports calls spent and every 429 seen.
  The Jira budget is a measurement, because Atlassian publishes no number for token traffic
  (TICKETING_CONTRACT.md 6.4). *Not built today.*

### 3.4 The calibration probe

`GET /rest/api/3/issue/{JIRA_CALIBRATION_ISSUE}` must resolve. If it does, a not-found on another
reference in this run is informative (DISTINCTION_OBSERVABLE). If it does not, or the variable is
unset, **no not-found this run may license creation**. *Today's probe reads only the project, which
proves reach, not visibility of foreign tickets (ledger row L54); to fix.*

---

## 4 · Azure DevOps Boards

### 4.1 Configuration

| variable | meaning | validated at run start by |
|---|---|---|
| `TICKET_BACKEND=azdo` | selects this backend | as Jira |
| `AZDO_ORG_URL` | `https://dev.azure.com/<org>` | well-formed https URL |
| `AZDO_PROJECT` | project name | `GET {org}/_apis/projects/{project}` resolves |
| `AZDO_PAT` | PAT, Work Items read & write, **one organisation**, shortest practical expiry | the probe. Basic auth with an empty user name |
| `AZDO_STAMP_FIELD` | reference name of a custom **single-line text** field (e.g. `Custom.KitClusterKey`), added once by a human to the tier-0 type in an **inherited** process | the work item type's field list contains it. Custom fields need an inherited process; the Basic system process cannot hold them |
| `AZDO_TYPE_CLUSTER`, `AZDO_TYPE_INSTANCE` | default `Issue`, `Task` | the project's work item types include both |
| `AZDO_EPIC_ID` | the tier-1 work item id | resolves |
| `AZDO_CALIBRATION_ITEM` | a known-present work item this PAT did not create | the probe |
| `AZDO_STATE_REOPEN`, `AZDO_STATE_DONE` | state names (Basic: `To Do` / `Doing` / `Done`) | the type's states include them |
| `TICKET_STAMP_LABEL`, `TICKET_CREATE_CEILING` | as Jira. The umbrella stamp is a **tag** | as Jira |

### 4.2 Sweep, create, update

- **Sweep.** Two steps, because WIQL returns only ids
  ([WIQL syntax reference](https://learn.microsoft.com/azure/devops/boards/queries/wiql-syntax)):
  1. `POST {org}/{project}/_apis/wit/wiql` with
     `SELECT [System.Id] FROM WorkItems WHERE [System.TeamProject] = @project AND [System.WorkItemType] = '<cluster type>' AND [System.Tags] CONTAINS '<umbrella>'`.
  2. `POST {org}/{project}/_apis/wit/workitemsbatch` in chunks of **at most 200 ids** (the
     documented batch maximum,
     [getWorkItemsBatch](https://learn.microsoft.com/javascript/api/azure-devops-extension-api/workitemtrackingrestclient)),
     requesting only `System.Id`, `System.State`, `System.Tags` and the stamp field.

  **The WIQL result cap.** A single query is limited to 20,000 results. That figure is documented in
  a Microsoft Q&A answer; the REST reference page itself is UNVERIFIED. The sweep therefore pages by
  `[System.Id] > <last id>` ordered by id, and treats a result count at the cap as **PARTIAL**,
  never complete.
- **Create.** `POST {org}/{project}/_apis/wit/workitems/${type}` with a JSON Patch body. It sets
  `System.Title`, `System.Tags` (umbrella and family), the stamp field, `System.Description` (HTML,
  carrying the machine-owned block), and the parent relation
  (`System.LinkTypes.Hierarchy-Reverse` to `AZDO_EPIC_ID`, or to the tier-0 item for an instance),
  all in **one** call.
- **Update.** One comment (`_apis/wit/workItems/{id}/comments`) or one block rewrite per changed
  item. The 5.2 never-list is unchanged.
- **Reopen.** A state write to `AZDO_STATE_REOPEN`. A refusal by a process rule is the successor
  path, as in Jira.
- **Throttling.** Azure DevOps meters load in TSTUs: 200 per sliding five-minute window per
  identity. It sends `Retry-After` and `X-RateLimit-*` headers before it starts delaying
  ([Rate and usage limits](https://learn.microsoft.com/azure/devops/integrate/concepts/rate-limits)).
  The bridge honours `Retry-After`, and reads `X-RateLimit-Remaining` to slow down **before** it is
  delayed. A delayed or blocked request past the retry ceiling is `BINDING_UNESTABLISHED`.

### 4.3 The calibration probe

`GET {org}/{project}/_apis/wit/workitems/{AZDO_CALIBRATION_ITEM}` must resolve. The rule is the same
as Jira: no foreign visibility means no creation from a not-found.

---

## 5 · Where it runs (TICKETING_CONTRACT.md section 7, applied)

- **A separate reusable workflow**, `reusable-ticket-reconcile.yml`. Its triggers are push to the
  protected default branch and a schedule, **never** a pull request and never a run chained off one.
- **One job** holds the tracker credential, from a **protected environment** gated to the default
  branch. `permissions: contents: read`. It has `timeout-minutes`.
- **Inputs** are the findings JSON emitted by the report (ledger row L52) and the ledger read from
  the protected branch. **Ledger changes go out as a reviewed PR** via `propose-ledger`; this job
  never pushes them.
- **Finding text reaches the tracker as data**: through `env:` and a program, never `${{ }}` in
  `run:`. **Redaction runs before the ticket body is rendered.** No snippet, no context region, and
  no scanner-supplied partial fingerprint is ever written.
- **The run summary states:** the backend; the lookup-outcome distribution; how many tickets were
  created, updated, carried and found ambiguous; calls spent; and every 429 seen.

---

## 6 · What "proven" means: the tests

Each test runs against the **RecordingBackend** first, locally and offline. The R-tests then repeat
it against the **owner's personal Jira and personal Azure DevOps**. Credentials come from the owner
at test time, are stored only as GitHub secrets or environment variables, and never reach a file.

| id | proves | backends |
|---|---|---|
| T-1 | two runs over the same findings create the same tickets: second run, zero creates | all |
| T-2 | a narrowed cluster membership creates no duplicate | all |
| T-3 | probe fails, so every not-found refuses to create | all |
| T-4 | sweep PARTIAL (page cap, WIQL cap, mid-sweep error), so no creation from a miss | all |
| T-5 | 429 with `Retry-After` is waited out; past the ceiling the result is `BINDING_UNESTABLISHED`, exit non-zero, nothing created | all |
| T-6 | two stamped tickets for one cluster: `BINDING_AMBIGUOUS`, nothing created or updated, all candidates named | all |
| T-7 | closed with no backing disposition: reopened. Closed with an unexpired approved disposition: left alone | all |
| T-8 | reopen refused (no transition / rule refuses): successor created, predecessor kept in the ledger, reason recorded | Jira, AzDO |
| T-9 | injection: a finding path or message containing `$(...)`, backticks, quotes, ADF/HTML markup and a 10 KB string arrives verbatim as text, executes nothing and breaks no JSON | all |
| T-10 | a secret finding's ticket carries no secret material: no snippet, no fingerprint of matched content | all |
| T-11 | the control is off, both backends are configured, or a config value is missing: refused by name, exit non-zero, never 0 | all |
| T-12 | the bot never writes a disposition, approver, expiry or SLA date: a static check over the write calls | all |
| R-1 | live: wrong host, bad token, missing project, missing stamp field, missing transition: each refused by name, nothing written | personal Jira + AzDO |
| R-2 | live: T-1, T-2, T-6, T-7, T-8 against real tickets, then cleanup **by a human** (the bridge has no delete) | personal Jira + AzDO |
| B-1 | **portability:** the personal-instance run and a consumer-instance dry plan differ only in configuration values. A diff of the effective config is the only difference; code, workflow and stamp format are byte-identical | — |

**A live R-test is evidence only with its run id or a recorded transcript.** "Worked on my site" with
no record is not a result.

---

## 7 · Build list: today's code against this design

| # | gap | file |
|---|---|---|
| J-1 | sweep JQL lacks the umbrella label and issue type; requests no status | `scripts/reconcile_tickets.py` `Jira.sweep` |
| J-2 | create sets `Task`, no description/block, no labels, no parent | `Jira.create` |
| J-3 | calibration probe reads the project only (L54) | `Jira.probe` |
| J-4 | no `Retry-After` / backoff / ceiling; no 429 reporting | `Jira._req` |
| J-5 | no `reconcileIssues` for ledger-referenced ids | `Jira.sweep` |
| J-6 | no reopen / transition / successor path | new |
| J-7 | no run-start shape validation (createmeta, types, epic) | new |
| J-8 | subtask instances under the tier-0 item, with the per-class threshold | new |
| A-1 | Azure DevOps backend: all of section 4 | new `AzureDevOps(TicketBackend)` |
| C-1 | `check_env.py` requires both Jira and ADO credentials (a policy defect, TICKETING_CONTRACT.md 4.6) | `scripts/check_env.py` |
| C-2 | `choose_backend` accepts `azdo`, and refuses two backends at once | `choose_backend` |
| W-1 | `reusable-ticket-reconcile.yml` per section 5 | new |
| X-1 | tests T-1 to T-12 and B-1 in self-test; R-1/R-2 as a dispatch-only workflow against the personal instances | `tests/`, new workflow |

## 8 · Still open, and who settles it

| question | default until settled |
|---|---|
| day-one cohort: one cohort ticket, or thousands (TICKETING_CONTRACT.md 11.4) | **per-cluster tickets, under the creation ceiling, carried in consequence order.** The cohort decision itself is a separate governance object, recorded once by the owner |
| the per-run creation ceiling, the staleness interval and the retry ceiling | **owner sets them in the policy file.** The first runs on the personal instances measure what is reasonable |
| a four-tier hierarchy | take it when both backends can carry it (WORK_ITEM_HIERARCHY.md) |
