# Evidence copy-out (KDEC-068)

`.github/workflows/evidence-copyout.yml` is the kit's one writer into the governed evidence store. It runs
on a schedule (and by dispatch) in the kit's evidence repository, reads the finished runs of the
repositories it is told about, and copies their evidence artifacts in, put-once.

**Application repositories hold no storage identity.** They keep uploading artifacts as they do today;
nothing in an application repository changes.

## What goes where

| Artifact (name pattern) | Container | Layer |
|---|---|---|
| `sarif-*`, `sbom`, `sbom-*`, `security-report-<n>`, `deployed-findings-<run>-<n>`, `external-findings-*`, `ai-artifact-inventory-<n>` | `cicd-kit-scans` | `reported/` |
| `kit-security-record-<n>`, `deploy-evidence-<run>-<n>`, `rollback-sequence-<run>-<n>`, `build-evidence-<run>-<n>`, `kit-evidence-export-*` | `cicd-kit-gates` | `evaluated/` |
| `kit-promotion-record-*` (it carries the approval record) | `cicd-kit-gates` | `approved/` |
| everything else (cross-run state such as `kit-deploy-state-*`, `kit-rollback-marker-*`, `kit-api-idem-*`, ticket outboxes, script bundles, fixtures) | not copied | SKIPPED by name |

Blob path: `<layer>/<owner>/<repo>/runs/<run-id>-<attempt>/<artifact>/<file>`, a receipt beside every
file and a manifest per artifact (the evidence-store client, vendored at `tools/evidence-store-client`,
tree hash `43852cb4c3678488a12144fcd223a86a0b337bed79e3317e3893b7f888859c4c`, re-vendored 2026-11-25 from
evidence-store-client `e7aa774`). The release record is a
GitHub deployment, not an artifact, and is not copied by this job (it would need Deployments: read).

## Transport: the kit's own evidence API app (owner decisions 2026-11-24)

The push step hands the client `EVIDENCE_API_URL` = `vars.EVIDENCE_KIT_API_URL` and
`EVIDENCE_API_AUDIENCE` = `vars.EVIDENCE_KIT_API_AUDIENCE` (the landing-zone root output
`evidence_api.tool_endpoints.kit`; identifiers, not secrets), the same pattern as the
evidence-store-client's integration templates. The client gets an Entra token for that audience from
the `azure/login` session and writes through the **kit API app** over HTTPS. The **direct** library
write is the fallback only: `vars.EVIDENCE_DIRECT_WRITE = true` while the API is off. With neither,
the push refuses before any upload (`NO_API`, exit 5); an API URL without its audience is refused the
same way. Objects over 32 MiB (or an artifact over 32 MiB / 500 files) are written directly by the
client automatically; each result row records `transport` (`api` or `direct`).

## The publication gate (cicd-kit-gates is read by Tines)

`cicd-kit-gates` is one of the six result containers Tines reads. Before any upload, every staged file
routed there must pass the client's publication gate (evidence-store-client `docs/PROTOCOL.md`
section 4.2): JSON with a registered schema id that validates (the kit's own ids, such as
`kit-promotion-record/1`, `kit-security-record/1`, `kit-release-record/1`, `kit-evidence-export/1`,
`kit-deploy-state/1`, the rollback sequence's `schema_version` 3; the kit files that carry no id are
declared by name in the client's policy), no secret shape and no PHI/CUI marker. One refused file
refuses the whole push (exit 5); the message names the reason and the class matched, never the text.
`cicd-kit-scans` (raw: SARIF, SBOMs, findings) is not gated. A new kit record type needs its id
registered in the client's policy (a reviewed client change and re-pin) before the copy-out can carry it.

## Setup (the owner, once)

1. **A read-only GitHub App** installed on the application repositories: Contents read, Actions read,
   Metadata read, nothing else. Variable `KIT_COPYOUT_APP_CLIENT_ID`, secret `KIT_COPYOUT_APP_PRIVATE_KEY`
   on the environment `kit-evidence-copyout`, which admits only the default branch.
2. Variable `KIT_COPYOUT_REPOSITORIES`: `owner/repo` names, one owner per run (one App installation).
3. **The kit writer** `id-kit-evidence-writer-<class>` from the landing zone's governed-storage root, with
   the OIDC subject `repo:<org>/<kit-evidence-repo>:environment:kit-evidence-copyout`; variables
   `KIT_EVIDENCE_WRITER_CLIENT_ID`, `KIT_EVIDENCE_TENANT_ID` (identifiers, not secrets).
4. `.github/evidence-store/store_contract.json` in the evidence repository: the reviewed
   `terraform output -raw store_contract`. Without it every push is REFUSED (exit 5).
5. `KIT_EVIDENCE_RUNNER`: a self-hosted runner label that reaches the store's private endpoint.
6. `EVIDENCE_KIT_API_URL` and `EVIDENCE_KIT_API_AUDIENCE` on the environment (from the landing-zone root
   output `evidence_api.tool_endpoints.kit`); `EVIDENCE_DIRECT_WRITE = true` only while the API is off.

Until the App exists every run ends `COPYOUT_NOT_RUN` (red, by name, never a pass).

## Retention of the source artifacts

The copy-out looks back 36 hours each night. The kit's evidence artifacts keep their current retention:
SARIF 30 days; the SBOM, security report, security record, promotion record and deploy evidence at the
evidence floor of 90 days (KDEC-036 G6, owner decision O-36c, `scripts/reviewer_signals.py`
`AUDIT_FLOOR_DAYS`). They were **not** shortened to 30 days: that is below the owner's recorded floor,
and several of them are read back by later runs. Owner decision (2026-11-24): keep it exactly so, the
90-day floor and SARIF 30 days.

## Proof

`tests/prove_evidence_copyout.py` (offline, against the landing zone's real store contract fixture):
routing, contract, unsafe zip names, the gate, the client pin, exit codes, staging layout, the
transport (C9: API by default, direct only with the flag, NO_API otherwise), the publication gate before
any upload (C10), the workflow's shape and its API wiring (W1, W2), five mutants. Not proven: a hosted
run, the kit API app (it has never run in Azure; loopback-tested only in the client), the App's token
on GHE.com, the OIDC exchange, the private endpoint from the runner.
