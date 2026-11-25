# 10f · Design: evidence export

```
Kept:      2026-11-07, against the trunk at c1420ea. Components: 03f_COMPONENTS_EVIDENCE_EXPORT.md.
Code:      scripts/evidence_export.py (export, unpack); scripts/kit_api_server.py; reusable-kit-api.yml.
Contract:  api/v1/evidence-export.schema.json (kit-evidence-export/1); api/v1/params/evidence.export.schema.json.
Into the harness: ARCH_06_EVIDENCE_TO_THE_HARNESS.md.
```

## 1 · Purpose

Produce the kit's half of the per-app evidence bundle a security reviewer builds for a CAB change or an
adoption review, so nobody has to find and download a pile of artifacts before they expire, and so three
facts no kit record used to carry (KEV, the SBOM digest, the commit author) are carried.

## 2 · Inputs and outputs

| Kind | What |
|---|---|
| input | exactly one of a commit or a release (a `kit-release-record` deployment) of the API's own repository |
| input | the run's own token: `actions: read` (artifacts), `deployments: read` (release records), `contents: read` (the ledger) |
| output | `evidence-export.json`: ten sections, each ESTABLISHED with its sources or NOT ESTABLISHED with why; `data.export_sha256` |
| output | the unpacked folder the harness reads as `--kit-evidence`, kept as `kit-evidence-export-CORRELATION-ID` |

## 3 · How it works

1. Intake validates the request; another repository is refused.
2. For the commit (or the release's commit) it reads the newest security record, the security report's
   findings, the live promotion records, the durable release records, the ticket outbox and the ledger,
   and the commit's author and verification.
3. Each record is copied through an **allowlist** of its schema's fields. Free text, messages, snippets,
   weakening reasons and outbox params are never copied; a credential-shaped value is withheld by name.
4. The author becomes `person:<10 hex>`, the harness's own pseudonym scheme. No email.
5. No clock is read and every list is sorted on stable keys: the same reads give the same bytes.
6. `unpack` writes the records as the files the harness already reads.

## 4 · States, in plain words

| State | In plain words |
|---|---|
| a section `NOT ESTABLISHED` | the record could not be read, and the reason is given; never an empty list |
| `kit_api_refusal.API_SCHEMA_VIOLATION` | A field in the API request is invalid (for example both a commit and a release). |
| `kit_api_refusal.API_REPOSITORY_NOT_SERVED` | The request names another repository; each API instance serves only its own. |
| `kit_api_refusal.API_EVIDENCE_UNAVAILABLE` | The named security run is not a completed default-branch run, or its evidence has expired. |
| `evidence_retention.EVIDENCE_RETENTION_RAISED_TO_FLOOR` | KIT_EVIDENCE_RETENTION_DAYS was below the audit minimum (or not a number), so the minimum was used. |
| `evidence_retention.EVIDENCE_RETENTION_CAPPED` | KIT_EVIDENCE_RETENTION_DAYS was above GitHub's 400-day maximum, so 400 was used. |

## 5 · Failure modes

| Failure | What happens | Proof |
|---|---|---|
| an artifact has expired | its section is NOT ESTABLISHED; the durable release record still answers | `tests/prove_evidence_export.py` E1..E5 |
| a record names another repository | counted in `excluded_other_repository`, not copied | the same file N1..N4 |
| a record carries a secret-shaped value or an email | withheld by name | the same file M1..M4 |
| the harness cannot read the export | the proof builds a bundle with the harness's own entry point | the same file |

## 6 · Decisions

| Decision | What it settled |
|---|---|
| KDEC-039 | the kit produces its half of the bundle, read-only, one repository; the security record carries the KEV verdict, the SBOM digest and the commit author |
| KDEC-035 | the API contract it rides on |
| KDEC-036 G6 | durable release records; retention floored at 90 days |
