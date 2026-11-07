# The kit's API, for a Tines 3B builder

```
Status:   PROPOSED (kit KDEC-035, 2026-11-03), amended by the owner (kit KDEC-037: templates and
          tickets from a finalized review); extended 2026-11-06 (kit KDEC-038: SAST and secret findings
          keyed and ticketed; kit KDEC-039: evidence.export). Built and proven locally in the kit; no
          hosted call yet.
Reads:    this file alone. The full contract is the kit's docs/api/README.md and api/v1/*.schema.json.
Platform: Tines 3B only -- workflows, steps, spaces, connectors, routes, webpages, volumes, cron,
          GitSync. Nothing here uses any other Tines construct.
Pack:     HELD. NOT part of the Tines pack yet. It reaches the pack only in the owner's one final delivery.
```

## 1. What changed for Tines, in one paragraph

A 3B workflow can now ask the secure CI/CD kit to **write, read and search finding tickets, read and
search findings, write tickets from a finalized review (section 5a), request a scan and request a release** -- by calling one GitHub API endpoint through
a connector. Tines still holds **no tracker credential** for finding tickets and **no cloud
identity**: the kit's own reconciler writes the ticket (CORE C-04's rule, now reachable from a
workflow), and the repository's own pipeline deploys (C-01), with every gate and a human approval.
Tines asks; the kit decides and does.

## 2. How a call works

1. A step sends `POST /repos/<org>/<repo>/actions/workflows/kit-api.yml/dispatches` with
   `{"ref": "<default branch>", "inputs": {"correlation_id", "idempotency_key", "request"}}`.
   GitHub answers 204: **received, not done** (checklist item 16).
2. GitHub runs `kit-api <correlation id>` in that repository. It validates the request, refuses by
   name or carries the call out, and writes the answer to a **check run named
   `kit-api/<correlation id>`** on the API host.
3. A later step (or a cron workflow) reads the answer: find the run by its name, read its check run's
   `output.text` -- a JSON result. Everything is on the one API host the connector allows.

The kit's client does all three: `scripts/kit_api.py` (one Python file, standard library only).
Copy it, and `api/v1/` (the schemas), into the step directory from a **pinned kit release** through
GitSync -- never edited in place.

## 3. The connector

| item | value |
|---|---|
| name (proposed) | `T-KAPI-<product>` -- one per product space (C-20: credential ids are per product) |
| credential | a **GitHub App** installation token (JWT method), installed "only select repositories". Interim: the existing GitHub token, if the owner approves its use here (C-03, C-13) |
| permissions | **Actions: read and write**, **Checks: read**, Metadata: read -- on the product's application repositories only. **Never Contents: write.** |
| URL pattern | `https://api.<tenant>.ghe.com/repos/<org>/<repo>/*` for each listed repository -- nothing else (item 7) |
| who creates it | a tenant admin or "Create connectors" holder, never the builder (item 6) |
| approval | **stop and ask** first: a new connector and grant exist only as a named row the owner approved (C-02, OD-3B-2) |

The step code never sees the token: it runs with `KIT_API_AUTH=proxy` and the credential proxy adds
the header (F6). The API host is a **value** in `config.toml`: `KIT_API_URL =
"https://api.<tenant>.ghe.com"` -- the client never assumes github.com and refuses when no host is
named. No uncredentialed egress is needed: answers come from the check run, never from artifact
storage (Q-3B-18 default holds).

## 4. A step, end to end

`config.toml` (values only, no secrets):

```toml
KIT_API_URL = "https://api.<tenant>.ghe.com"
KIT_API_AUTH = "proxy"
KIT_API_SCHEMAS = "./api/v1"
REPO = "<org>/<repo>"
```

`script.py` (the shape; the builder adds the product's own halt read and evidence record):

```python
import json, os, sys
import kit_api                       # copied beside this script from the pinned kit release

halt = json.load(open('halt.json'))  # C-15: the step's byte-copy of ops/halt.json, read first
if halt.get('halted') is not False:
    print(json.dumps({'status': 'not_attempted', 'why': 'halted: %s' % halt.get('reason')}))
    sys.exit(0)

client, refusal = kit_api.client_from_env(os.environ)   # KIT_API_URL + KIT_API_AUTH=proxy
if client is None:
    print(json.dumps({'status': 'not_attempted', 'refusal': refusal}))
    sys.exit(0)
item = json.load(sys.stdin)                            # e.g. a finding id from the previous step
res = kit_api.submit(client, os.environ['REPO'], 'tickets.write',
                     {'source': {'run_id': 'latest'}, 'select': {'identities': [item['finding_id']]}},
                     idempotency_key='vuln-flow:%s' % item['id'])    # from the workflow's id ledger
print(json.dumps({'correlation_id': res['correlation_id'], 'api_state': res['api_state'],
                  'refusal': res.get('refusal')}))
```

A second step (or a `cron` workflow on `main`, item 13) calls `kit_api.status(client, REPO,
correlation_id)` and stores only the id, the state and a timestamp in the volume (an index, C-18).
Use `kit_api.call(..., wait_seconds=...)` only with a wait shorter than the step's time cap; prefer
submit-then-poll. Copy status words verbatim; never turn a state into "done".

## 5. The operations, as a 3B workflow uses them

| need | operation | params (example) | what comes back in `data` |
|---|---|---|---|
| open or update a finding ticket | `tickets.write` (key required) | `{"source": {"run_id": "latest"}, "select": {"identities": ["<id>"]}}` | `created`, `updated`, `outcomes`, `ticketing_state` |
| note on a kit ticket | `tickets.comment` (key required) | `{"ref": "SEC-1042", "text": "..."}` | `commented`, `ref` |
| one ticket | `tickets.get` | `{"ref": "SEC-1042"}` | `ticket` (state, labels, block facts, SLA) |
| ticket search (dashboards) | `tickets.search` | `{"filters": {"status": "open", "severity": ["critical"]}, "findings_run_id": "latest"}` | `tickets`, `total`, `not_judged` |
| findings (vuln management) | `findings.search` | `{"run_id": "latest", "filters": {"kev": true}}` | `findings` (CVEs, KEV, ticket), `total` |
| one finding | `findings.get` | `{"run_id": 123, "finding_id": "<id>"}` | `finding` |
| a scan of a branch | `scan.request` | `{"ref": "main"}` (dispatched AT that ref) | `routing_result`, `run_id` |
| a release | `deploy.request` (key required) | `{"mode": "promote", "environment": "prod", "promote_from_run_id": 123, "promote_from_environment": "test"}` | `deployment_outcome` |
| the answer to any call | `status` (client only) | the correlation id | the result |
| tickets from a finalized review | `tickets.submit` (key required) | `{"template": "finding", "template_version": 1, "review_id": "<id>", "items": [...]}` | `items[]` (outcome, ref, candidates, score), `review` |
| every ticket, manual too (dashboards) | `tickets.search` | `{"tracker_query": {"labels": ["security"], "max_results": 100}}` | `tickets` (manual, state, linked keys), `next_page_token` |
| the kit's half of an app's evidence bundle (CAB, adoption review) | `evidence.export` (a read) | `{"commit": "<40 hex>"}` or `{"release": <deployment id>}` | `export` (ten sections, each ESTABLISHED or NOT ESTABLISHED with why), `export_sha256`, `artifact` |

Writes (`tickets.write`, `tickets.submit`, `tickets.comment`, `deploy.request`) work only where the repository has
turned them on (`vars.KIT_API_OPERATIONS`); otherwise the call is refused
`API_OPERATION_NOT_ENABLED`. The idempotency key is the workflow's own stable id for the item
(`<workflow>:<item id>`), so a re-run of a 3B step can never write twice: the same key is
`API_DUPLICATE_REQUEST`, naming the first call.

## 5a. Writing tickets from a finalized review (KDEC-037; version 2, the owner's answers 2026-11-04)

Tines runs a review (USR, a cloud tool, a pentest, an audit), a member of the security team concurs,
the review is finalized, and only then are tickets written -- after the kit has searched EVERY ticket,
manual ones included. Operation `tickets.submit` (key required). Tines holds no tracker credential.

1. **Shape items with the templates** (`api/v1/tickets/<template>.schema.json`, `template_version` 2,
   copied from the pinned release): `finding`; the requests `false-positive`, `exception` (at most 90
   days, a scope), `exemption`, `accepted-risk`, `compliance-exception`, `mitigation`; `extension`
   (`waiting_on` fix or vendor); `nofix-recheck`; `closure` (`resolve` / `verify` / `reject`); `triage`
   (`merge` / `separate`). Proposed types answer `TEMPLATE_NOT_ENABLED`.
2. **Dry run first** (`dry_run: true`, `review_id` set): exact matches, candidates, planned tickets.
3. **Concurrence.** Tines opens the kit-gated GitSync PR adding `.security/reviews/<review_id>.json`
   (`kit-review-record/2`: `decision` AGREE, or DISAGREE with `alternative`; per-item `item_decisions`;
   `submitted_by`, `run_started_by` -- the engineer the AI run was for --, `triaged_by`,
   `evidence_set_sha256` of the FINAL params). ANY security-team member (the list or GitHub team) who is
   none of those people approves THAT pull request in GitHub. Tines never approves.
4. **Submit** with the same params and a new key. Read `data.items[].outcome`:
   `TEMPLATE_TICKET_CREATED`, `TEMPLATE_TICKET_BOUND`, `TEMPLATE_LINKED_EXACT`,
   `TEMPLATE_CLOSED_DUPLICATE` (the original updated with the new source, evidence and confidence
   change), `TEMPLATE_REGRESSION`, `TEMPLATE_POSSIBLE_DUPLICATE` (created, in triage: route to a
   person), `TEMPLATE_DEDUPE_PENDING` (created; the next run re-checks), `TEMPLATE_OUTBOX` (the tracker
   was away: kept and retried first next call -- raise `data.alerts` to a person), `TEMPLATE_SENT_BACK`
   (the dissent in `data.dissent`), `TEMPLATE_PENDING_VERIFICATION` (send `data.notifications` to the
   approvers: "ready to close, please verify"), `TEMPLATE_FIX_OBSERVED`,
   `TEMPLATE_VERIFICATION_REJECTED`, `TEMPLATE_TICKET_CLOSED`, `TEMPLATE_TICKET_UPDATED`,
   `TEMPLATE_REOPENED_AS_REMEDIATION`. Show `confidence` and `trust` with their `_basis`, beside the
   tier, never instead.
5. **Closing.** The fixer submits `closure` `resolve` (no review needed). A verifier who is not the
   fixer submits `verify` (reviewer) under a review, or the kit's rescan verifies on the branch mapped
   to the ticket's environment. `reject` reopens. The kit reminds after 7 days and escalates after 14.

**Dashboards and intake.** `tickets.search` with `tracker_query` pages through EVERY ticket in Jira,
Azure DevOps or GitHub Issues -- manual ones included -- with `manual`, `state`, `labels` and linked
finding keys. Store ids and states in the volume; follow `next_page_token` in bounded batches.
FreshService answers `TRACKER_INTAKE_NOT_CONFIGURED`. The labels are a baseline for an
environment-specific scheme (`docs/ticketing/TAGGING-STRATEGY-PROPOSAL.md`).

## 5b. SAST and secret findings, and the evidence export (KDEC-038, KDEC-039)

**SAST and secrets.** Bandit, semgrep and CodeQL findings now carry `rule_family` and a canonical `cwe`; the same
weakness on the same line from two tools is ONE finding and one ticket naming both (corroboration raises the
confidence). A rule the kit's table does not know is `RULE_FAMILY_UNKNOWN` -- record it as "not keyed", never guess a
family in the workflow. A secret finding is ticketed by the kit's own reconciliation as URGENT (critical, the top
priority, an `-urgent` label) with ROTATE instructions, and never closes because the scanner stopped seeing it: a
person confirms the rotation. A 3B dashboard shows "rotate" for these rows; no step, volume or log ever holds a
secret's value or its fingerprint. `ticket_routing` rules may now match `rule_family` and `cwe` (a register change,
merged by a person).

**Evidence export.** One `evidence.export` call per repository and commit (or release) returns the kit's half of the
per-app evidence bundle: security record, review signals, promotion and release records (the durable ones), findings,
ticket outbox, ticket links, KEV, SBOM digest and the commit author as a pseudonym. Record each section's state WORD
verbatim: `NOT ESTABLISHED` is "not established, because <why>", never blank, zero or clean; a `kev` section NOT
ESTABLISHED is "not known", never "not on KEV". The answer is read from the check run as for every call. When
`data.export.abridged` is true the check run holds each section's state and count only, and the whole export is in
the run's artifact `kit-evidence-export-<correlation id>`; Tines does not read artifact storage (section 7, item 8),
so the step records the artifact name and the reviewer downloads it. The calling repository's `kit-api.yml` must
grant `deployments: read` before its kit pin moves past KDEC-039, or every call fails at startup.

## 6. States, and what a workflow does with each

| `api_state` | the 3B step records | then |
|---|---|---|
| `API_ACCEPTED` | `received` | poll |
| `API_NOT_FOUND`, `API_QUEUED`, `API_IN_PROGRESS` | `pending` | poll (bounded batches; unreached = `not_attempted`) |
| `API_AWAITING_APPROVAL` | `awaiting approval` | message the approver group with the run link; a person approves in GitHub, quoting the digest; never Tines |
| `API_COMPLETED` | the `data` words verbatim (`routing_result`, `deployment_outcome`, `ticketing_state`) | done -- completed is not clean: a scan can be `BLOCKED` |
| `API_REFUSED` | `refused: <refusal.code>` | report; fix and resubmit with a new key |
| `API_FAILED`, `API_RESULT_UNREADABLE` | `not read` / `failed` with the notes | report; retry with a new key (a ticket retry cannot duplicate) |
| `API_CANCELLED` | `cancelled` | resubmit with the same key |

`kev: "UNAVAILABLE"` is "not known", never "not exploited". A connector refusal (401/403), a
timeout or a 5xx is "not read (HTTP <code>)", never 0 or "none".

## 7. What Tines may NEVER do through or around the API

1. Hold or use a tracker credential to create, edit, transition or close a **finding** ticket. The
   kit's reconciler does that (C-04). There is no transition or close operation, by design.
2. Approve, or appear to approve, a release. A release requested through the API is the
   repository's own pipeline, called by the API run, so **the connector's identity is the requester**
   and is refused as an approver; the environment must demand a human approver with self-review
   prevented, or the API refuses (`API_DEPLOY_NEEDS_HUMAN_APPROVAL`).
3. Request `rollback` or `break-glass` (`API_RELEASE_PATH_NOT_PERMITTED`): a person does, with the
   exception record.
4. Grant a disposition -- an exception, a false positive, a risk acceptance
   (`API_DISPOSITION_NOT_VIA_API`). A compliance template (section 5a) opens a REQUEST ticket; the
   disposition itself is a pull request to the protected branch that a named approver merges.
5. Write any ticket without a finalized review she concurred with (`API_REVIEW_NOT_FINALIZED`), approve
   or author her concurrence, close a ticket without a verified closure, or extend one past its count.
   `tickets.write` still tickets only the kit's own findings (`API_FINDING_NOT_KIT_ESTABLISHED`);
   external findings go through `tickets.submit`.
6. Treat `on_behalf_of` as authority. It is recorded as declared, never verified (Q-3B-17).
7. Dispatch `build-deploy.yml` (or any other workflow) directly to get around the API's refusals, or
   use `repository_dispatch` for a release (it needs Contents write; refused).
8. Read artifacts from blob storage, or widen the connector's URL pattern to reach them.
9. Store a token, a ticket description or code content in a volume, a log or step output (C-07,
   item 15). The API returns no code content.
10. Change the kit, its workflows or a repository's `kit-api.yml` other than by the kit-gated GitSync
    pull request a named approver who did not prompt it merges (C-16).

## 8. Agents and the UI

- An agent (AI) step in a 3B workflow is governed by ACP (C-22) and, until the owner allows AI steps
  in product workflows (Q-3B-14), stays in the build chat. Where allowed, an agent may call the
  **read** operations freely and **propose** writes; a write it makes is still the kit's write under
  the kit's rules, and a release it requests still waits for a person.
- The findings and tickets UI (the kit's `docs/api/UI-SPEC.md`) is a 3B **webpage** route with
  `route_auth = SSO` to named IdP groups (item 11). It calls the API with the space's connector,
  passes the signed-in person as `on_behalf_of` (a hint), and has no approve, close or exception
  control. Dashboards (Jira security tickets) read `tickets.search`.

## 9. Testing in 3B before live

- Step tests replay recorded API answers (item 17): `API_ACCEPTED`, each state of section 6, three
  refusals (`API_OPERATION_NOT_ENABLED`, `API_DUPLICATE_REQUEST`, `API_DEPLOY_NEEDS_HUMAN_APPROVAL`)
  and a 401. Each must record the right word and never "done" before `API_COMPLETED`.
- First live calls go to the owner's **personal** test repository with the owner's **personal**
  Jira / Azure DevOps behind it -- never a work tracker -- until the owner moves them.
- The kit side is proven by its own tests (`prove_kit_api_client.py`, `_server.py`, `_workflow.py`).

## 10. Owner decisions this needs (defaults the build uses until answered)

| ID | decision | default |
|---|---|---|
| K-API-1 | Accept KDEC-035 (the kit's API) | proposed, not accepted: build only against a test repository |
| K-API-2 | Amend C-04: Tines asks the kit's reconciler through the API (Tines still holds no tracker credential for finding tickets) | **answered by the owner 2026-11-03 (KDEC-037):** Tines may write tickets through the API only after her recorded concurrence with the finalized review (section 5a) |
| K-API-5 | The approvers, extensions, no-fix clock, taxonomy, tagging, intake adapters (KDEC-037 O-37b..O-37h) | **answered by the owner 2026-11-04** (section 5a); still open: which proposed types to enable (O-37k, default none), the branch mapping (O-37m, default main=prod) |
| K-API-3 | The connector's credential: a GitHub App per product, or the interim GitHub token | stop and ask; nothing is created |
| K-API-4 | Which repositories turn on writes and which environments allow API releases | none: reads only |
| K-API-6 | Who may call `evidence.export` (KDEC-039 O-39a) | any caller of the repository's kit-api (a read, on by default) |
| K-API-7 | The SAST alias table, secret urgency and fingerprint (KDEC-038 O-38a..O-38e) | as built; unknown rules refuse; secrets never auto-close |
