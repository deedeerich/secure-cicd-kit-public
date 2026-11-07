# 10e · Design: the kit API

```
Kept:      2026-11-07, against the trunk at c1420ea. Status: PROPOSED (KDEC-035).
Components: 03e_COMPONENTS_KIT_API.md. Contract: docs/api/README.md and api/v1/ (the schemas win).
Code:      templates/kit-api.yml, reusable-kit-api.yml, .github/actions/kit-api, scripts/kit_api.py,
           scripts/kit_api_server.py, scripts/ticket_submit.py, scripts/ticket_templates.py,
           scripts/review_finalize.py, scripts/separation_of_duties.py, scripts/evidence_export.py.
```

## 1 · Purpose

Let another program (an automation or an agent with a GitHub credential) ask a repository's copy of the
kit to do one of its things, through GitHub alone, without removing any gate and without a server.

## 2 · Inputs and outputs

| Kind | What | Notes |
|---|---|---|
| input | a dispatch of `kit-api.yml` with `correlation_id`, `idempotency_key`, `request` (a v1 envelope) | or a `repository_dispatch` of event type `kit-api` (never for a release) |
| input | `vars.KIT_API_OPERATIONS` (writes to enable), `vars.KIT_API_DEPLOY_ENVIRONMENTS`, the review and SLA numbers (`KIT_API_*`) | writes are off unless named |
| input | tracker credentials in the `ticketing` environment; optional `KIT_API_TEAM_READ_TOKEN` | the tickets job only |
| output | `result.json` (`api/v1/result.schema.json`): `api_state`, `refusal`, `routing_result`, `data` | written three ways: artifact, run summary, check run `kit-api/CORRELATION-ID` |
| output | a ticket ledger proposal artifact; the outbox; for `evidence.export` the `kit-evidence-export-*` artifact | never a write to the ledger itself |

## 3 · How it works

1. The client (`scripts/kit_api.py`) builds and validates the request, names the host (never assumed),
   and dispatches on the default branch. GitHub answers 204: received, never done.
2. The run is named `kit-api CORRELATION-ID`. **Intake** validates the envelope, refuses by name, records
   the idempotency key, opens the check run, and serves the read operations. It holds no tracker credential.
3. **Tickets** runs the ticket operations through the same reconciler as the pipeline, in the `ticketing`
   environment. `tickets.submit` first requires a finalized, concurred review and applies separation of
   duties per item.
4. **Scan** and **deploy** run as the caller workflow's own jobs: the kit's security workflow, or the
   repository's own `build-deploy.yml` called as a reusable workflow, so the API caller is the release's
   requester and can never approve it.
5. **Finish** writes the result. The client reads it by finding the run by name and reading the check run.

## 4 · States, in plain words

| State | In plain words |
|---|---|
| `kit_api_state.API_REFUSED` | The API call was refused by name before anything was done. |
| `kit_api_state.API_AWAITING_APPROVAL` | The API call is waiting for a person to approve a release in its environment. |
| `kit_api_state.API_FAILED` | The API call was accepted but could not be carried out. |
| `kit_api_state.API_RESULT_UNREADABLE` | The API run finished, but no valid result for this call could be read. |
| `kit_api_refusal.API_HOST_NOT_NAMED` | The API client was not told which GitHub host to call. |
| `kit_api_refusal.API_OPERATION_NOT_ENABLED` | This repository has not turned on the requested API operation. |
| `kit_api_refusal.API_SCHEMA_VIOLATION` | A field in the API request is invalid. |
| `kit_api_refusal.API_IDEMPOTENCY_KEY_REQUIRED` | A write request came without an idempotency key (or with two different ones). |
| `kit_api_refusal.API_DUPLICATE_REQUEST` | This idempotency key was already used; nothing was done again. |
| `kit_api_refusal.API_REF_NOT_DEFAULT_BRANCH` | A ticket or deploy call was dispatched on a branch other than the default branch. |
| `kit_api_refusal.API_REPOSITORY_NOT_SERVED` | The request names another repository; each API instance serves only its own. |
| `kit_api_refusal.API_DISPOSITION_NOT_VIA_API` | An exception, false positive or risk acceptance was requested through the API. |
| `kit_api_refusal.API_RELEASE_PATH_NOT_PERMITTED` | Rollback and break-glass cannot be requested through the API. |
| `kit_api_refusal.API_DEPLOY_NEEDS_HUMAN_APPROVAL` | The target environment does not require a human approver with self-review prevented. |
| `kit_api_refusal.API_REVIEW_NOT_FINALIZED` | The review behind the tickets is not finalized with a recorded second-person approval. |
| `ticket_template_outcome.TEMPLATE_OUTBOX` | The tracker could not be written, so the item was kept in the outbox for the next run. |
| `ticket_template_outcome.TEMPLATE_SENT_BACK` | The concurring reviewer disagreed with this item, so nothing was written for it. |

All 29 refusals are in `api/v1/refusals.json` and `docs/errors/ERRORS.md`.

## 5 · Failure modes

| Failure | What happens | Proof |
|---|---|---|
| the caller's host is not named | refused locally, nothing sent | `tests/prove_kit_api_client.py` K3 |
| an artifact download redirects to blob storage | the token is not forwarded | `tests/prove_kit_api_client.py` K9 |
| the same write is sent twice | `API_DUPLICATE_REQUEST`; nothing done again | `tests/prove_kit_api_server.py` |
| the key cannot be checked | `API_IDEMPOTENCY_UNVERIFIED`; no write risked | `tests/prove_kit_api_server.py` |
| a release environment has no human approver | `API_DEPLOY_NEEDS_HUMAN_APPROVAL` | `tests/prove_kit_api_workflow.py` |
| the caller waits too long | the bounded wait returns the last state, exit 3 | `tests/prove_kit_api_client.py` K8 |
| a refused call on every hosted self-test | refused by name, asserted | self-test jobs `kit-api-refuses-by-name`, `kit-api-refusal-asserted` |

## 6 · Decisions

| Decision | What it settled |
|---|---|
| KDEC-035 | a versioned, schema-defined contract through GitHub dispatches; no new server |
| KDEC-037 | external findings through templates; tickets only after a recorded human concurrence; every ticket searched first |
| KDEC-039 | `evidence.export`; the caller grants `deployments: read` |
| KDEC-027 | a run's token goes only to the API host that issued it |
