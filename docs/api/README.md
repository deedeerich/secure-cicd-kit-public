# The kit's API, v1

```
Status:        PROPOSED (KDEC-035, 2026-11-03). Built and proven locally; no hosted or live call yet.
Audience:      a builder wiring another program (a Tines 3B automation or agent first; anything that
               holds a GitHub credential) to the secure CI/CD kit.
Contract:      api/v1/request.schema.json, api/v1/params/<operation>.schema.json,
               api/v1/result.schema.json, api/v1/refusals.json. The schemas win over this page.
Client:        scripts/kit_api.py (one file, standard library only).
Run side:      templates/kit-api.yml -> .github/workflows/reusable-kit-api.yml ->
               .github/actions/kit-api -> scripts/kit_api_server.py.
Proofs:        tests/prove_kit_api_client.py (K1..K9), prove_kit_api_server.py (S1..S8),
               prove_kit_api_workflow.py (W1..W8), prove_ticket_templates.py (T1..T10, KDEC-037), prove_ticket_intake_v2.py (V1..V11);
               self-test job kit-api-refuses-by-name.
```

## 1. What it is, in one paragraph

Another program asks a repository's copy of the kit to do one of its things by **dispatching that
repository's `kit-api.yml` workflow** with a JSON request. The run that answers is an ordinary
GitHub Actions run named `kit-api <correlation id>`; it validates the request, refuses by name or
carries the call out **through the kit's own machinery** (the ticket reconciler, a security run's
evidence, the repository's own release pipeline), and writes a JSON result to a **check run** named
`kit-api/<correlation id>`, the run summary and an artifact. There is **no server to host or
secure**: GitHub is the transport, the queue, the access control and the audit trail. A caller
reads its answer through the same API host it dispatched to.

## 2. Quick start

```bash
# The host is NEVER assumed. Name the one your token was issued by:
export GH_HOST=<tenant>.ghe.com          # or GITHUB_API_URL=https://api.<tenant>.ghe.com
export GH_TOKEN=<fine-grained token: Actions read+write, Checks read, this repository only>

# Submit, then read the answer later (a dispatch reply is "received", never "done"):
python3 scripts/kit_api.py submit --repo <owner>/<repo> --operation findings.search \
    --params '{"run_id": "latest", "filters": {"severity": ["critical", "high"]}}'
python3 scripts/kit_api.py status --repo <owner>/<repo> --correlation-id kapi-20261103T101500Z-0123456789ab

# Or submit and wait, bounded (default 300 s, at most 3600 s):
python3 scripts/kit_api.py call --repo <owner>/<repo> --operation tickets.search \
    --params '{"filters": {"status": "open"}}' --wait-seconds 120
```

Every command prints one JSON result (`api/v1/result.schema.json`). Exit codes: `0` completed (or
accepted, for `submit`), `1` refused by name, `2` usage, `3` no completed answer yet or not one that
can be trusted (queued, running, awaiting approval, not found, failed, cancelled, unreadable).

## 3. Turning it on in a repository

1. Copy `templates/kit-api.yml` to `.github/workflows/kit-api.yml`, set `YOUR_ORG` and pin the kit
   SHA (the same SHA as `build-deploy.yml`).
2. Ticket operations use the **same** `ticketing` environment, variables and secrets as the
   pipeline's ticket reconciliation (`docs/architecture/TICKETING_CONTRACT.md` section 13.1). Nothing
   new is provisioned for tickets.
3. Reads and `scan.request` are served by default. **Writes are off** until the repository names
   them: `vars.KIT_API_OPERATIONS`, e.g.
   `tickets.write,tickets.comment,tickets.get,tickets.search,findings.get,findings.search,scan.request,deploy.request`.
4. Releases: `vars.KIT_API_DEPLOY_ENVIRONMENTS` lists the environments a release may be requested
   for (empty permits none), and each must demand a **human approver with self-review prevented**
   (GitHub environment protection, read back at intake).
5. Optional: `vars.KIT_API_TICKET_BACKEND` (`jira` by default; `azdo`, `github`).
6. `tickets.submit` (KDEC-037): keep finalized review records in `.security/reviews/` on the default
   branch under CODEOWNERS. The approvers are the whole security team: `vars.KIT_API_REVIEW_APPROVER_SOURCE`
   is `list:<name>` (the register's `approver_lists[<name>]` -- the same structure, and the same shared
   `approver_lists_source` file, as KDEC-036's `approver_lists.appsec` -- or `.security/reviews/approvers.json`;
   default `list:review-concurrence`) or `team:<org>/<slug>` (a GitHub team's members, read with
   `secrets.KIT_API_TEAM_READ_TOKEN`, members:read only). `vars.KIT_API_BRANCH_ENVIRONMENTS`
   (`main=prod,release/*=prod,develop=dev`; default: the default branch is prod) maps a branch's rescan
   to the environment whose ticket it may close; `vars.KIT_API_APPROVED_TOOLS` and
   `vars.KIT_API_EVIDENCE_STORES` (comma lists) feed the trust score. The owner's numbers are variables
   with defaults: `KIT_API_EXTENSION_DEFAULT_DAYS` (30), `KIT_API_EXTENSION_MAX` (2, with a fix
   available), `KIT_API_EXTENSION_CEILING_DAYS` (90), `KIT_API_VENDOR_ADVISORY_EXTENSIONS` (2),
   `KIT_API_VENDOR_ADVISORY_DAYS` (180), `KIT_API_NOFIX_EXEMPTION_DAYS` (30),
   `KIT_API_NOFIX_EXEMPTION_CEILING_DAYS` (90), `KIT_API_NOFIX_RECHECK_DAYS` (30, unless the register's
   `numbers.no_fix_recheck_days`), `KIT_API_NOFIX_REVIEW_DAYS` (90), `KIT_API_EXCEPTION_MAX_DAYS` (90),
   `KIT_API_REVIEW_MAX_AGE_DAYS` (30), `KIT_API_VERIFICATION_REMINDER_DAYS` (7),
   `KIT_API_FUZZY_TITLE_PERCENT` (85). The caller grants `pull-requests: read` (templates/kit-api.yml does).

## 4. Authentication and least privilege

| caller | credential | permissions, this repository only |
|---|---|---|
| any program (recommended transport: `workflow_dispatch`) | fine-grained token or GitHub App installation token | **Actions: read and write** (dispatch; read runs, pending deployments, artifacts), **Checks: read** (the answer), Metadata: read |
| `repository_dispatch` (supported, not recommended) | as above **plus Contents: write** | the dispatch endpoint needs Contents write; refused outright for `deploy.request` |
| a Tines 3B step | a connector whose URL pattern is the API host only; `KIT_API_AUTH=proxy` | as the first row; the step's code never sees the token |

What the **run** holds is the run's own `GITHUB_TOKEN` (`contents: read`, `actions: read`,
`checks: write`) and, in the `tickets` job only, the tracker credential from the protected
`ticketing` environment. The API run holds **no deploy identity**: a release is the repository's own
`build-deploy.yml`, whose jobs bind their own environments' identities as they always do.

**The token stays on its host (KDEC-027).** The client sends the token only to the API host it
resolved. GitHub answers an artifact download with a redirect to blob storage; the client never
lets the HTTP library follow a redirect and follows that one itself without the Authorization
header. Nothing named is `API_HOST_NOT_NAMED` -- never github.com.

## 5. The envelope

```json
{
  "api_version": "v1",
  "operation": "tickets.search",
  "correlation_id": "kapi-20261103T101500Z-0123456789ab",
  "idempotency_key": "vuln-triage:wf-12:item-88",
  "on_behalf_of": "analyst@example.invalid",
  "client": {"name": "tines-3b-step", "version": "1.0.0"},
  "dry_run": false,
  "params": {"filters": {"status": "open"}}
}
```

- `correlation_id`: made by the caller (the client makes it), unique per call. It is the run's
  name, the check run's name and the result's key.
- `idempotency_key`: **required for every write** (`tickets.write`, `tickets.comment`,
  `deploy.request`). The same key twice is `API_DUPLICATE_REQUEST` naming the first call, and
  nothing is done again (a 90-day window: the marker artifact's retention). Calls with one key never
  overlap: the template's concurrency group serialises them. Never a secret: it appears in run names.
- `on_behalf_of`: what the caller **declares**; recorded and shown, never verified, never used to
  authorise (`actor.on_behalf_of_verified` is always `false`).
- The dispatch carries the envelope as the `request` input (at most 60,000 characters) and repeats
  `correlation_id` and `idempotency_key` as inputs; the run refuses a mismatch.

## 6. The result

```json
{
  "api_version": "v1", "correlation_id": "kapi-...", "operation": "tickets.write",
  "api_state": "API_COMPLETED", "refusal": null, "routing_result": "PROCEED",
  "repository": "<owner>/<repo>", "transport": "workflow_dispatch",
  "run": {"id": 40890000001, "attempt": 1, "url": "https://<host>/<owner>/<repo>/actions/runs/40890000001"},
  "actor": {"actor": "<app>[bot]", "triggering_actor": "<app>[bot]",
            "on_behalf_of": "analyst@example.invalid", "on_behalf_of_verified": false},
  "idempotency_key_sha256": "...", "request_sha256": "...",
  "received_at": "2026-11-03T10:15:02Z", "finished_at": "2026-11-03T10:15:41Z",
  "data": { "...": "the operation's answer, below" },
  "notes": ["..."], "truncated": false, "next_offset": null
}
```

**`api_state`** (assurance-taxonomy.yaml `kit_api_state`):

| state | means | caller does |
|---|---|---|
| `API_ACCEPTED` | the dispatch was received (submit's answer) -- **never done** | poll `status` |
| `API_NOT_FOUND` | no run carries the id yet (a dispatch takes seconds to appear) | poll again |
| `API_QUEUED`, `API_IN_PROGRESS` | the run exists and has not finished | poll again |
| `API_AWAITING_APPROVAL` | a release waits on an environment's required reviewers (`data.awaiting_environments`) | tell a person; the API never approves |
| `API_COMPLETED` | the call did what it was asked; `data` carries the kit's own words | read `data`; **completed is not clean** |
| `API_REFUSED` | refused by name before anything was done (`refusal.code`, `refusal.detail`) | fix and resubmit with a new key |
| `API_FAILED` | accepted and could not be carried out (tracker down, release reported nothing) | read `notes`; never a success. Retry with a NEW key (the first is spent); a ticket retry cannot duplicate (lookup by stamp) |
| `API_CANCELLED` | cancelled before it wrote a result (a newer pending call with the same key replaced it) | resubmit with the same key |
| `API_RESULT_UNREADABLE` | the run finished and no valid result naming this call could be read | treat as failed; read the run |

`routing_result` is the kit's verdict word **for the operation's own claim** (a scan's verdict; a
ticket run's ticketing claim), never a gate input. A check run's conclusion is `success` only for
`API_COMPLETED` and `neutral` otherwise, so an API call never turns a commit red; read `api_state`,
never the colour.

**Size.** The check run holds at most 60,000 characters of result. A larger answer is cut (`truncated:
true`, a note) and the artifact `kit-api-result-<correlation id>` holds the whole of it; searches page
with `limit` (at most 200) and `offset`, and `next_offset` says where the next page starts.

## 7. The operations

### 7.1 `tickets.write` -- create or update finding tickets, through the reconciler

```json
{"source": {"run_id": 40812345678}, "select": {"identities": ["3f9c2a7d1e5b4c60a1b2c3d4e5f60718"]}}
```

- `source.run_id`: a **completed run of the default branch** that kept its security evidence
  (`security-report-*`), by id or `"latest"`. Anything else is `API_EVIDENCE_UNAVAILABLE`.
- `select`: `identities`, `cluster_keys` and/or `fingerprints` of findings **that run established**
  (1 to 100 in all). A name the run did not establish is `API_FINDING_NOT_KIT_ESTABLISHED`: the API
  tickets only what the kit's own scan found, under the gate's rules. No inline findings.
- **One ticket per finding across the API and the pipeline.** The write runs
  `scripts/reconcile_tickets.py`'s own `reconcile()` with the repository's backend, ledger,
  register routing, stamp field and umbrella label, in the `ticketing` environment and in the same
  concurrency group as the pipeline's reconciliation. The pipeline later finds the API's ticket by
  its stamp (`BACKEND_BOUND`) and creates nothing; the API finds the pipeline's ticket the same way.
- **It closes nothing.** Closure is the reconciler's, on verified clearance, in a full run
  (KDEC-024); a write of some findings is not a run of all of them. It may reopen a closed ticket
  beside a finding that still reproduces, by the reconciler's own rule (TC 4.2).
- **No disposition.** `requested_disposition` is `API_DISPOSITION_NOT_VIA_API`: an exception, a
  false positive or a risk acceptance is a pull request to the protected branch that a person
  approves.
- `dry_run: true` plans and writes nothing. The ledger is not written by the API: the run keeps
  `ticket-ledger-proposal.json` in its artifact, and the pipeline's next reconciliation repairs the
  ledger from the stamp.

`data`: `backend`, `ticketing_state` (`TICKETING_AVAILABLE` | `TICKETING_UNAVAILABLE` |
`TICKETING_NOT_CONFIGURED`), `source_run`, `selected`, `outcomes` (the lookup outcomes:
`BINDING_ABSENT`, `LEDGER_BOUND`, `BACKEND_BOUND`, ...), `created` (`cluster_key`, `ref`, `key`,
`title`, `trigger`, `planned`), `updated`, `reopened`, `successors`, `merged`, `escalations`,
`needs_decision`, `withheld_no_identity`, `obligations`, `closed` (always empty), `calls`.
`API_FAILED` when the ticketing claim is `EVIDENCE_UNTRUSTED` (the tracker could not be read or
written; the obligations are listed).

### 7.2 `tickets.comment`

```json
{"ref": "SEC-1042", "text": "Owner team confirmed; fix targeted for the next sprint."}
```

One comment on a ticket that carries the kit's cluster stamp, prefixed with the correlation id, the
requesting identity and the declared `on_behalf_of`. It changes no state. A ticket without the stamp
is `API_TICKET_NOT_KIT_STAMPED`. **There is no transition operation**: closing is the scanner's (on
verified clearance) and reopening the reconciler's (on reproduction); a person moves tickets in the
tracker directly.

### 7.3 `tickets.get`

`{"ref": "SEC-1042"}` or `{"cluster_key": "<32 hex>"}`. `data.ticket`: `cluster_key`, `ref`, `key`,
`url`, `state` (`open` | `closed`), `status_name`, `labels`, `block` (what the ticket's
machine-owned block states: `severity`, `scanners`, `stopped`, `absent`, `sla_due`, `confidence`,
`exceptions`) and `ledger` (severity, SLA, raised_as, first/last seen, member identities,
fingerprints). A ref the sweep does not show stamped is `API_TICKET_NOT_KIT_STAMPED`; a partial sweep
is `API_FAILED` (absence was not established).

### 7.4 `tickets.search`

```json
{"filters": {"severity": ["critical", "high"], "status": "open", "kev": true},
 "findings_run_id": "latest", "limit": 50, "offset": 0}
```

Filters: `fingerprint`, `finding_id`, `cluster_key`, `repo` (must be this repository, else
`API_REPOSITORY_NOT_SERVED`), `severity`, `status`, `cve`, `kev`, `text`. `cve`, `kev` and `text`
read the findings of `findings_run_id` (required for them: `API_FILTER_NEEDS_FINDINGS_RUN`).
`data`: `total`, `tickets` (as `tickets.get` without `block`), `not_judged` (tickets a `kev` filter
could not judge because the catalog was unreadable -- **never counted as not exploited**),
`kev_state`, `sweep_complete` (false: every count is a floor).

**Tracker intake (KDEC-037).** With `tracker_query` (`api/v1/tickets/intake.schema.json`: `projects`,
`labels`, `jql`, `page_token`, `max_results` up to 100, `adapter`), `tickets.search` reads EVERY ticket
in the repository's ticket projects -- manually created ones included -- one page at a time with the
tracker's own cursor (`data.next_page_token`). Each ticket: `ref`, `key`, `summary`, `labels`, `state`,
`status_name`, `stamp`, `manual` (true when the kit did not stamp it) and `linked_cluster_keys` (joined to
the findings of `findings_run_id` when given). No description is returned. A project outside the
repository's routing and ledger projects, or JQL carrying `ORDER BY`, is `API_TRACKER_QUERY_REFUSED`.
Jira, Azure DevOps (WIQL inside the project, paged by id, then `workitemsbatch`; `labels` are tags) and
GitHub Issues (the issues list, paged; text by the search API inside the one repository) are built to
the same contract; `jql` is Jira-only. `adapter: freshservice` is the seam and answers
`TRACKER_INTAKE_NOT_CONFIGURED` (`API_FAILED`, never "no tickets").

### 7.5 `findings.search` and `findings.get`

```json
{"run_id": "latest", "filters": {"cve": "CVE-2021-44228", "established_only": true}, "limit": 50}
{"run_id": 40812345678, "finding_id": "3f9c2a7d1e5b4c60a1b2c3d4e5f60718"}
```

The normalised findings one security run established (its `findings.json`, redacted at source).
Filters: `fingerprint`, `finding_id`, `cluster_key`, `severity`, `scanner`, `job`, `rule`, `cve`,
`kev`, `path` (prefix), `text`, `established_only`. Each finding: `identity`, `fingerprint`,
`cluster_key`, `scanner`, `tool`, `scanner_version`, `job`, `rule_id`, `severity`, `path`, `line`,
`subject`, `cwe`, `identity_state`, `reason`, `row_established`, `baseline_state`, `first_seen`,
`correlation_tier`, `cves`, `kev` (`true` | `false` | `UNAVAILABLE` | `null` when it names no CVE)
and `ticket` (`ref`, `key` from the ticket ledger, or `null`). **No code content** is returned.
`data.kev_state`: `AVAILABLE`, `UNAVAILABLE` (the CISA catalog or the organisation mirror could not
be read -- KDEC-032's rule) or `NOT_NEEDED` (nothing named a CVE).

### 7.6 `deploy.request`

```json
{"mode": "promote", "environment": "prod", "promote_from_run_id": 40812345678,
 "promote_from_environment": "test", "release_path": "normal"}
{"mode": "build-deploy", "environment": "dev"}
```

- The release is **the repository's own `build-deploy.yml`, called as a reusable workflow** by the
  API run with intake's validated values. Every gate in it applies: the verdict, artifact identity,
  attestation (V1), the release block (K-3), zone readiness (K-2), the approval bound to the digest
  with no self-approval (K-1), the lease, promotion (KDEC-029), the rollback dependency check.
  Because it is called (not re-dispatched), **the API's caller is the release's requester**, so the
  caller can never be the approver.
- Intake refuses: by `repository_dispatch` (`API_TRANSPORT_NOT_PERMITTED`); `rollback` or
  `break-glass` (`API_RELEASE_PATH_NOT_PERMITTED`: a person dispatches those with the exception
  record); an environment not listed, or `build-deploy` aimed outside dev/test
  (`API_ENVIRONMENT_NOT_PERMITTED`); a promotion without its source
  (`API_PROMOTION_SOURCE_REQUIRED`); an environment that does not demand a human approver with
  self-review prevented (`API_DEPLOY_NEEDS_HUMAN_APPROVAL`) -- **an agent's release always waits for a
  person**, at every tier.
- While the run waits for the reviewers, `status` answers `API_AWAITING_APPROVAL`.
- `data`: `job_result`, `environment`, `mode`, `deployment_outcome` (the deploy's own word from its
  `outcome.json`, e.g. `DEPLOY_HEALTHY`; `NOT_REPORTED` when the run holds none), `now_serving`,
  `gate`, `promotion_record`. `API_COMPLETED` only when the release job succeeded **and** its outcome
  was read; otherwise `API_FAILED` -- never "deployed" without the deploy's evidence.

### 7.7 `scan.request`

`{"ref": "main", "reason": "nightly re-check"}`. The client dispatches the API run **at that ref**
(a branch or tag; a commit SHA cannot be dispatched); the run calls the kit's security workflow.
`data`: `routing_result`, `assurance_state`, `advisory_causes`, `evidence_artifact`, `run_id`.
`API_COMPLETED` whenever the scan produced a registered verdict -- including `BLOCKED`; a scan that
did not run or reported no verdict is `API_FAILED`. `findings.search` with `run_id` = `data.run_id`
reads what it found.

### 7.8 `status.get`

Answered by the client (`kit_api.py status`), **nothing is dispatched**: it finds the run named
`kit-api <correlation id>`, reads `pending_deployments` while it runs and the check run's result once
it finished.

### 7.9 `tickets.submit` -- tickets from a finalized review, through templates (KDEC-037)

```json
{"template": "finding", "template_version": 2, "review_id": "USR-2026-11-04-001",
 "items": [{"source_type": "usr", "source_tool": "usr-review", "environment": "azure-government-prod",
            "asset": {"scheme": "azure-resource", "cloud": "azure-government", "tenant_id": "<uuid>",
                      "subscription_id": "<uuid>", "resource_id": "/subscriptions/<uuid>/resourceGroups/rg/..."},
            "identifier": "AZURE-STORAGE-TLS-1-0", "severity": "high", "fix_status": "FIX_AVAILABLE",
            "evidence": {"ref": "usr-reviews/.../item-1.json", "sha256": "<64 hex>", "verified": true},
            "title": "Storage account allows TLS 1.0"}],
 "link_decisions": [{"correlation_key": "<32 hex>", "decision": "link", "ref": "SEC-1042"}]}
```

The owner's flow: an automation runs a review, a person concurs with its findings and evidence, the
review is finalized, and only then are its tickets written -- after looking at EVERY ticket the tracker
holds, manual ones included. Version 2 (2026-11-04) carries the owner's answers to O-37b/c/d/f/g/h.

- **Templates** (`api/v1/tickets/<template>.schema.json`, `template_version` 2; 1 is superseded):
  `finding`; the requests `false-positive` (no expiry; re-checked when the rule, tool version or code
  changes), `exception` (at most 90 days, a specific scope, compensating controls), `exemption` (there
  to stay; a review cadence), `accepted-risk` (owner, review date, risk-register link),
  `compliance-exception` (framework, control, requirement text, named authority), `mitigation` -- each
  opens a request-class ticket, never a disposition; `extension`; `nofix-recheck`; `closure`
  (`resolve`, `verify`, `reject`); `triage` (`merge`, `separate`). Fourteen PROPOSED types are stubs,
  disabled (`TEMPLATE_NOT_ENABLED`; docs/ticketing/TICKET-TYPES.md).
- **The asset identity scheme**: `repo-path`, `azure-resource` (the id must name the subscription),
  `aws-resource` (the ARN must name the account), `github-repo`, `engagement`. The identity is the asset
  and the identifier, nothing about the source: two tools on the same thing are ONE ticket naming both.
- **The finalize gate and separation of duties** (docs/ticketing/SEPARATION-OF-DUTIES.md). The record
  (`kit-review-record/2`) is FINALIZED, bound to this call's `evidence_set_sha256`
  (`python3 scripts/kit_api.py evidence-hash --params p.json`), concurred by a member of the security
  team's list or GitHub team, at most 30 days ago, who APPROVED the pull request that merged it and is
  NOT the submitter, the engineer who started the AI run, the triager, the caller, `on_behalf_of` or a
  bot. Item level: the requester of an exception, extension or exemption, the triager of a triage, the
  fixer of a rejected fix may not approve it (`SOD_SELF_APPROVAL`). The concurrence is `AGREE`, or
  `DISAGREE` with an `alternative` -- whole or per item (`item_decisions`) -- which writes nothing for
  those items: `TEMPLATE_SENT_BACK` with `data.dissent[]`. Anything else is `API_REVIEW_NOT_FINALIZED`
  with every reason, and nothing is read from or written to the tracker. A fixer's `resolve` and a
  rescan `verify` need no review.
- **Dedupe against every ticket; no item ever disappears.** Exact (the kit's stamp, or a
  correlation-key label or stamp line on any ticket): a new contribution is recorded as a sub-task
  closed as a duplicate (`TEMPLATE_CLOSED_DUPLICATE`), and the original is commented with what it added
  -- a new source ("confidence increased X -> Y" with the derivation), new evidence, the asset, a
  severity change, recurrence; the same contribution again is `TEMPLATE_TICKET_BOUND` /
  `TEMPLATE_LINKED_EXACT`; a closed original newly observed is reopened, `TEMPLATE_REGRESSION`. Near
  (the same asset and identifier, or the identifier and a close title): the ticket is CREATED, flagged
  `<stamp>-possible-duplicate` and `<stamp>-triage`, commented with its candidates
  (`TEMPLATE_POSSIBLE_DUPLICATE`); a person decides with the `triage` template, or in the review with
  `link_decisions` (`link` records a closed duplicate, `new` creates unflagged). A search that did not
  complete creates the ticket in triage with `<stamp>-dedupe-pending` (`TEMPLATE_DEDUPE_PENDING`); the
  next run re-runs the dedupe on it (`data.dedupe_rechecked`). A tracker that could not be reached keeps
  every item in the durable outbox -- `outbox.json`, kept as the `kit-ticket-outbox-<correlation id>`
  artifact (90 days) -- alerts a person (`data.alerts`, a run error), and is retried first by the next
  submit (`data.outbox_drained`); `TEMPLATE_OUTBOX`.
- **Closure.** The fixer resolves: `TEMPLATE_PENDING_VERIFICATION`, labelled
  `<stamp>-pending-verification`, the approvers notified ("ready to close, please verify";
  `data.notifications`), reminded after 7 days and escalated after 14. Closed-Verified only by a
  reviewer who is not the fixer, or by the kit's rescan that covered the finding and no longer reports
  it ON THE BRANCH MAPPED TO THE TICKET'S ENVIRONMENT; a clean scan on another branch records "fix
  observed on <branch>" (`TEMPLATE_FIX_OBSERVED`). A `reject` reopens (`TEMPLATE_VERIFICATION_REJECTED`).
  Only a ticket the kit stamped or linked is closed or extended (`TICKET_NOT_KIT_LINKED`).
- **Extensions**: 30 days by default; with a fix available at most 2, each at most 90 days
  (`EXTENSION_LIMIT_REACHED`, `EXTENSION_CEILING_EXCEEDED`); `waiting_on: vendor` continues, and at the
  second extension or 180 days the ticket gets the advisory "no fix after 6 months, consider an
  alternative". Counted from the ticket's own `<stamp>-extension-<n>` labels.
- **No-fix**: a 30-day exemption (ceiling 90; a ticket-level SLA pause, never a gate exception), a vendor
  re-check every 30 days, a review every 90, and the advisory "something like a permanent risk
  acceptance; look for an alternative" at 180 days -- 90 and escalated for critical/high, none for low
  (`numbers.no_fix_advisory_days` overrides). `FIX_AVAILABLE` later reopens it as remediation.
- `dry_run: true` shows exactly what would be written and writes nothing.

`data`: `template`, `template_version`, `evidence_set_sha256`, `review`, `dissent`, `items[]` (`item`,
`correlation_key`, `outcome` -- `ticket_template_outcome`, `ref`, `key`, `basis`, `candidates`,
`confidence`, `confidence_basis`, `trust`, `trust_basis`, `detail`), `notifications`, `alerts`,
`outbox`, `outbox_drained`, `dedupe_rechecked`, `reconcile`, `intake_adapter`, `sweep`.
Two numbers, both on the ticket and in the answer, neither replacing the tier: the **confidence**
(0..100, `finding_correlation.corroboration_score`: how likely the finding is real -- anchored 40 /
singleton 20, +15 per independent source beyond the first, +10 exact identifier, +10 evidence hash, +10
the kit's own scan, -20 contested) and the **trust** (0..100, `ticket_templates.trust_score`: how much
we trust the source and its custody -- source class kit scan 40 > approved integrated tool 30 >
contracted pentest/audit 25 > internal reviewer 20 > manual 5; +10 evidence hash, +10 evidence verified,
+5 a receipt, +10 the submitter's identity verified, +20 a finalized concurrence, +5 the chain of
custody in an approved evidence store). Each carries its derivation.

## 8. The refusals

Registered in `assurance-taxonomy.yaml :: kit_api_refusal`; `api/v1/refusals.json` carries each
remedy. **A refusal is made before anything it guards is done.** The API never removes a gate the
kit already has: a refusal can only add a "no".

| code | where | means |
|---|---|---|
| `API_HOST_NOT_NAMED` | client | no API host named; never github.com by default |
| `API_HOST_INSECURE` | client | not https (http only to loopback) |
| `API_CREDENTIAL_ABSENT` | client | no token and not proxy mode |
| `API_REQUEST_UNPARSEABLE` | intake | not a JSON object |
| `API_REQUEST_TOO_LARGE` | client, intake | over 60,000 characters |
| `API_VERSION_UNSUPPORTED` | client, intake | not v1 |
| `API_OPERATION_UNKNOWN` | client, intake | not in the contract |
| `API_OPERATION_NOT_ENABLED` | intake | the repository does not serve it (writes are opt-in) |
| `API_SCHEMA_VIOLATION` | client, intake | `field` names the field |
| `API_CORRELATION_MISMATCH` | intake | the run and the request name different calls |
| `API_IDEMPOTENCY_KEY_REQUIRED` | client, intake | a write without a key, or two keys |
| `API_DUPLICATE_REQUEST` | intake | the key was used; the first call is named |
| `API_IDEMPOTENCY_UNVERIFIED` | intake | the key's history could not be read; a write is never risked |
| `API_REF_NOT_DEFAULT_BRANCH` | intake | a ticket or release call off the default branch |
| `API_TRANSPORT_NOT_PERMITTED` | intake | a release by repository_dispatch |
| `API_REPOSITORY_NOT_SERVED` | intake | a filter named another repository |
| `API_EVIDENCE_UNAVAILABLE` | operation | no completed default-branch run with evidence |
| `API_FINDING_NOT_KIT_ESTABLISHED` | operation | the run did not establish that finding |
| `API_DISPOSITION_NOT_VIA_API` | intake | dispositions are pull requests a person approves |
| `API_TICKET_NOT_KIT_STAMPED` | operation | the ticket is not the kit's |
| `API_FILTER_NEEDS_FINDINGS_RUN` | intake | cve/kev/text need `findings_run_id` |
| `API_RELEASE_PATH_NOT_PERMITTED` | intake | rollback and break-glass are a person's |
| `API_ENVIRONMENT_NOT_PERMITTED` | intake | not listed, or build-deploy outside dev/test |
| `API_PROMOTION_SOURCE_REQUIRED` | intake | a promotion names its predecessor |
| `API_DEPLOY_NEEDS_HUMAN_APPROVAL` | intake | the environment does not demand a human approver |
| `API_TEMPLATE_INVALID` | intake | a `tickets.submit` item breaks its template (`data.template_refusal`) |
| `API_REVIEW_NOT_FINALIZED` | operation | no finalized, human-concurred review bound to this evidence set |
| `API_TEMPLATE_RULE_REFUSED` | operation | a rule on the tracker's state: self-approval, a count, a limit, an unverified closure, a ticket the kit does not own |
| `API_TRACKER_QUERY_REFUSED` | intake, operation | a project outside the repository's, or JQL with `ORDER BY` |

## 9. Versioning and deprecation

- The version is in the request (`api_version`) and in the path of every schema (`api/v1/`).
- **Within v1**, only additive, optional changes: a new optional parameter or filter, a new field
  in `data`, a new operation, a new refusal code (a caller must treat an unknown code as a refusal).
  Nothing a caller relies on is removed or changes meaning within v1.
- **A breaking change is v2**, in `api/v2/`, served beside v1. v1 then stays served for at least
  **two kit releases and 90 days**, whichever is longer; a v1 request in that window answers as before
  with a deprecation note in `notes`; after it, `API_VERSION_UNSUPPORTED`. The window and its end date
  are recorded in `.context/products/secure-cicd-kit/decisions.md` and the explainer change log.
- A repository pins the kit by SHA, so it changes API version only when it moves its pin.

## 10. What is proven, and what is owed

| claim | evidence |
|---|---|
| the contract validates and refuses by name; the host is never assumed; the token stays on its host; only a readable result is a result | `tests/prove_kit_api_client.py` K1..K9 (a simulated GHE.com API host; K9 the shipped opener against a loopback 302) |
| every run-side refusal named and readable by the caller; one ticket per finding across the API and the pipeline on Jira and Azure DevOps, both orders; a subset closes nothing; KEV never false; a release meets every gate | `tests/prove_kit_api_server.py` S1..S8 (documented-shape tracker stand-ins) |
| the release is the repository's own pipeline, called; the gates run before Azure login; the API holds no deploy identity; one ticket writer at a time; every value read is set; the shipped step answers | `tests/prove_kit_api_workflow.py` W1..W8 |
| the reusable workflow starts on GitHub and refuses by name | self-test `kit-api-refuses-by-name` (on every self-test run once pushed) |
| every template checked and refused by name; nothing written without a finalized, human-concurred review bound to the evidence set; every ticket (manual ones too) searched before a create, a candidate never merged; closure verified and never self-verified; extensions counted and capped; the no-fix re-check; tracker intake paging; the corroboration score | `tests/prove_ticket_templates.py` T1..T10, T5b (failed 70 checks first; ten mutants killed) |

**Owed:** a hosted armed call per operation on the owner's personal test repository; a live
`tickets.write` / `tickets.search` / `tickets.comment` round trip on the owner's **personal** Jira
and **personal** Azure DevOps (`tests/live_ticketing_run.py`'s targets; never an employer's); a
`tickets.submit` with a real review record merged by a real approving reviewer on a personal test
repository (KDEC-037: the GitHub half; the tracker half -- v1 HELD live on the owner's personal Jira on
2026-11-04 (`--phase r4`), v2 in `--phase r5`, see docs/decisions.md KDEC-037); a
`deploy.request` on the personal sandbox showing `API_AWAITING_APPROVAL`, then a human approval, then
`API_COMPLETED` with `DEPLOY_HEALTHY`; that a GHE.com tenant's runs are found by `display_title` and
that `$/` resolves inside the API's reusable workflow there.
