# ARCH-04 · The kit API surface

```
Truth State:  drawn 2026-11-06 from the files cited below, on the trunk. Release 4 (main 10ffcea)
              serves every operation here EXCEPT evidence.export (KDEC-039, trunk only).
Status:       PROPOSED (KDEC-035). Built and proven locally; no hosted or live armed call yet.
Contract:     docs/api/README.md and api/v1/ (the schemas win over any page, this one included)
```

## 1 · One call, end to end

```mermaid
sequenceDiagram
  participant C as Caller (a program or a Tines step)
  participant H as GitHub host API (the caller's own host)
  participant W as kit-api.yml in the repository
  participant I as Intake job
  participant J as Tickets / findings / scan / deploy job
  participant X as Check run kit-api/correlation-id
  C->>H: workflow_dispatch kit-api.yml (request, correlation_id, idempotency_key)
  H-->>C: 204 received, never done
  H->>W: a run named kit-api correlation-id
  W->>I: validate the envelope, refuse by name, record the key
  alt refused
    I->>X: API_REFUSED with refusal.code
  else accepted
    I->>J: the operation, through the kit's own machinery
    J->>X: API_COMPLETED or API_FAILED, data in the kit's own words
  end
  C->>H: status (find the run by its name, read the check run)
  H-->>C: result JSON (api_state, refusal, routing_result, data)
```

Cited: `scripts/kit_api.py` (client, `OPERATIONS`), `templates/kit-api.yml` (the caller in a
repository), `.github/workflows/reusable-kit-api.yml` (jobs `intake`, `tickets`, `finish`),
`.github/actions/kit-api`, `scripts/kit_api_server.py`, `api/v1/request.schema.json`,
`api/v1/result.schema.json`, `api/v1/refusals.json`.

## 2 · The operations and what each reaches

```mermaid
flowchart LR
  subgraph READS["Reads (served by default)"]
    TG["tickets.get"]
    TS["tickets.search<br/>(+ tracker intake paging)"]
    FG["findings.get"]
    FS["findings.search"]
    EX["evidence.export<br/>(trunk, KDEC-039)"]
    SR["scan.request"]
    ST["status.get<br/>(client only, nothing sent)"]
  end
  subgraph WRITES["Writes (opt-in: vars.KIT_API_OPERATIONS; idempotency key required)"]
    TW["tickets.write"]
    TC["tickets.comment"]
    TSU["tickets.submit<br/>(finalized review only)"]
    DR["deploy.request"]
  end
  TG --> RECON["Ticket reconciler<br/>ticketing environment"]
  TS --> RECON
  TW --> RECON
  TC --> RECON
  TSU --> RECON
  FG --> EVID["A default-branch security run's<br/>findings.json (redacted)"]
  FS --> EVID
  EX --> REL["Security record, release records,<br/>promotion records, outbox, ledger"]
  SR --> SECRUN["reusable-security.yml<br/>at the requested ref"]
  DR --> BD["The repository's own build-deploy.yml<br/>every gate, a human approver"]
```

Cited: `scripts/kit_api.py` `OPERATIONS` (write flags and jobs), `api/v1/params/*.schema.json`
(one schema per operation), `templates/kit-api.yml` (jobs `api`, `scan`, `deploy`, `finish`).

- **No server to host.** GitHub is the transport, queue, access control and audit trail.
- **The API never removes a gate.** A release is the repository's own `build-deploy.yml`, called;
  an agent's release always waits for a person (`API_DEPLOY_NEEDS_HUMAN_APPROVAL`); rollback and
  break-glass are refused (`API_RELEASE_PATH_NOT_PERMITTED`).
- **Least privilege for the caller**: Actions read and write, Checks read, this repository only.
  The run holds its own job token (`contents: read`, `actions: read`, `checks: write`,
  `pull-requests: read`, and on the trunk `deployments: read` for `evidence.export`) and, only in
  the tickets job, the tracker credential from the protected environment.
- **Migration**: a repository that moves its kit pin past KDEC-039 must add `deployments: read`
  to its `kit-api.yml` first, or every call fails at startup (`docs/api/README.md` section 3 item 7).

## 3 · What is proven

`tests/prove_kit_api_client.py` (K1..K9), `tests/prove_kit_api_server.py` (S1..S8),
`tests/prove_kit_api_workflow.py` (W1..W8), `tests/prove_ticket_templates.py`,
`tests/prove_ticket_intake_v2.py`, on the trunk `tests/prove_evidence_export.py`; the self-test job
`kit-api-refuses-by-name` on every hosted self-test. Owed: a hosted armed call per operation.
