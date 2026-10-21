# Release 1 evidence manifest, part 2 of 3

```
Covers:             rows 41-68 and the counts
Parts:              1 `RELEASE_1_EVIDENCE_MANIFEST.md`: truth state, legend, 1A scan and gate
                    (rows 1-30), 1B NVD, policy, provenance, composites (rows 31-40).
                    2 this file: 1C identity, build, deploy (rows 41-64), 1D ticketing (rows
                    65-68), the row counts for all 68 rows.
                    3 `RELEASE_1_EVIDENCE_MANIFEST_PART3.md`: the consumer interface and its gaps,
                    what the trunk has added since main, where the next proof is owed.
                    Each part is under 20 KB and stands alone.
Truth State:        tied to `main` = ef4b15d (Release 1; self-test 38926152571 success).
                    Trunk deltas marked against fix/normalization-and-discovery at 078ef90.
Authority:          tests/reconcile_validation.py and the workflows at the SHAs above. Where
                    this file and they disagree, they win and this file is wrong.
Written:            2026-10-16, lane L-G; split in three and brought to 078ef90 on
                    2026-10-21, lane L-G2.
```

## How to read a row

| state | means |
|---|---|
| **PROVEN-LIVE** | exercised against a real external system (Azure, a cloud registry, a real tracker); run id or transcript cited |
| **PROVEN-HOSTED** | exercised on a GitHub runner as a consumer calls it; run id cited |
| **PROVEN-LOCAL** | the shipped step or script run with the real tool on seeded input; the proof is named |
| **PROVEN-STUB** | proven against a stubbed external API (a fake `az`, a replayed tracker) |
| **DESIGNED** | specified, not delivered (unbuilt, or built and not doing what the design says) |
| **DEFERRED** | a dated, owned deferral in `tests/reconcile_validation.py` (or a dated weakening) |
| **BLOCKED** | waits on a named owner decision (`COMPLETION_LEDGER.md` section 6) |

These are column values of this document, not taxonomy terms, so they are written with hyphens:
capitals joined by underscores are reserved for terms registered in `assurance-taxonomy.yaml`
(`scripts/reconcile_taxonomy.py` enforces it).

**A job that ran is not proof its control was effective.** The "asserted" column says what the run
or proof actually established; nothing beyond it is claimed. A run whose conclusion is `failure` is
cited where the failure WAS the assertion (a refusal, a blocked caller) — the column says so.

Labels: **VERIFIED** (code or run read for this file), **READ** (a registry comment or document says
so and was not re-derived), **INFERRED** (reasoned).

## 1 · Capabilities (continued from part 1)

### 1C · Identity, build, deploy (Azure; `live-deploy-acceptance.yml` calls the reusables as a consumer does)

| # | capability | state | evidence | asserted | scope / limit | label |
|---|---|---|---|---|---|---|
| 41 | Azure OIDC login with an environment-scoped subject (plain and ID-qualified forms) | PROVEN-LIVE | `verify-azure-oidc.yml` runs 38832628162, 38850408850 (success) | a federated login with no secret; the subject form recorded | personal test subscription (KDEC-012) | VERIFIED run, READ |
| 42 | Context integrity (declared tenant/subscription/client vs the session) | PROVEN-LIVE | 38826929579 (the assert step failed on a declared wrong tenant); 38826938462 (the assert step passed with nothing declared; the run failed later on the boundary, closed afterwards) | a real login, then a hard refusal on mismatch | — | VERIFIED (step conclusions) |
| 43 | Authorization boundary | PROVEN-LIVE | 38832628162 (success), 38832634828 (failure: a reachable scope seeded in a refused position), 38850408850 (AuthorizationFailed bodies printed) | own and shared groups reached; sibling, opposite-tier and subscription-scope write refused | an UNAVAILABLE calibration probe still leaves PASS (L103) | VERIFIED run, READ |
| 44 | Build once, Trivy gate before push, SBOM, push to a cloud registry, digest read back | PROVEN-LIVE | 38857011286, 38857017667, 38857024014 (success); local `prove_build_push_round_trip.py` | REGISTRY_IDENTITY_PROVEN; digests confirmed by `az acr repository show` and then deployed | sandbox ACR; build inputs record proven locally only (`prove_build_inputs_recorded`) | VERIFIED run, READ |
| 45 | Push as the point of no return (capability + manifest before push) | PROVEN-LIVE (path ran) / PROVEN-LOCAL (refusal) | rows 44 runs; `prove_push_capability.py` | the capability step ran before each push; an unreachable/UNKNOWN registry refuses before writing (local) | the `docker-build-push` composite lacks the step (DCR-10) | READ |
| 46 | Attestation signing (attest job) and V1 verification | DEFERRED | `attestation-verify`, expires 2026-12-31 (held by plan; O-20); `prove_attestation_verify.py`, `prove_attest_job_isolated.py` (local) | five-outcome classification against recorded `gh` answers (local) | never signed; V1 runs in the template only, not the deploy reusables | VERIFIED |
| 47 | Deploy refuses before login on a non-proceed verdict | PROVEN-LIVE | 38853176286 (failure at "Gate verdict (refuse before login)", expected) | a typed `BLOCKED` refused; Azure login never ran | the verdict was a typed input, not a gate output | VERIFIED |
| 48 | Irreversible deploy refused at prod (App Service, no slot) | PROVEN-LIVE | 38853184615 (failure, expected) | refused before login | — | VERIFIED run, READ |
| 49 | Healthy deploy of a kit-built digest | PROVEN-LIVE | Container Apps 38855599716, 38857259257; App Service 38857271571 (success) | the revision probed on its own name before traffic (CA); DEPLOY_HEALTHY | — | VERIFIED run, READ |
| 50 | Unhealthy deploy rolled back and verified against live state | PROVEN-LIVE | Container Apps 38855747496, 38858033863; App Service direct 38878189985 (failure: the deploy failed, as seeded) | traffic never moved / prior image restored; ROLLBACK_VERIFIED from a fresh live read | App Service judges NOW SERVING by the configured image (DCR-2) | VERIFIED run, READ |
| 51 | App Service staging slot: health on the slot, swap only when healthy | PROVEN-LIVE | 38912063363 (success, swapped); 38912546778 (failure: no swap, staging restored and verified) | production untouched on the unhealthy path | post-swap production failure stub-only | VERIFIED run, READ |
| 52 | Second actor: reversal defers or refuses, reported ROLLBACK_PARTIAL | PROVEN-LIVE | Container Apps 38855929525 (REVERSAL_DEFERRED_TO_SUCCESSOR, P6); App Service 38886279650 (REVERSAL_REFUSED_CONFLICT, P4) | nothing reversed out of order; the refusal named | App Service declares P3/P5/P6 empty (single-repository assumption, L98) | VERIFIED run, READ |
| 53 | Container Apps traffic-following-latest pinned before update | PROVEN-LIVE | 38856714492 (failure at "Reconcile and report outcome": residue later fixed in fe606ae) | public /health 200 on all 16 samples during the run; ROLLBACK_VERIFIED | the withheld residue the run showed is fixed by stub proof, not re-run live | VERIFIED run, READ |
| 54 | Snapshot and change manifest before the first mutation | PROVEN-LIVE | every live deploy run above | written `planned` before mutation | — | READ |
| 55 | EMPTY / UNKNOWN previous state; rollback to empty | PROVEN-STUB | `prove_deploy_outcome.py` gap4, gap5 | UNKNOWN refuses before mutation; empty target reversed to empty | — | READ |
| 56 | PARTIAL_APPLY / STATUS_UNTRUSTED (matrix B, D) | PROVEN-STUB | `prove_deploy_outcome.py` gap8 | — | not induced live | READ |
| 57 | Rollback capability established before the point of no return; refusal at uat/prod | PROVEN-STUB | gap9 | UNAVAILABLE refuses at uat/prod | computed on every live run, never refused live. Trunk `71a3d63`: a capability step that wrote no verdict reads UNAVAILABLE (was: available), so the posture routes EVIDENCE_UNTRUSTED | READ |
| 58 | Provenance tags written after health | PROVEN-STUB | gap3 | tags only after a live read shows the intended artefact | `live-deploy-acceptance.yml` never passes `version_metadata` | READ |
| 59 | Deploy posture record; serialised per target | PROVEN-LOCAL | `prove_deploy_posture.py`, `prove_deploy_concurrency.py` | — | per repository only. Trunk `078ef90`: an empty KDEC-014 ruling routes EVIDENCE_UNTRUSTED (`prove_version_gap_production`) | VERIFIED (proofs run at 078ef90) |
| 60 | Starter template: identity + verdict branching, stamp, deploy | PROVEN-LOCAL | `prove_template_branches_on_verdict.py` (the `decide` step) | an unproven identity or non-proceed verdict refuses a requested deploy | **never run on a runner**; passes the security verdict, not the combined one, and hard-codes `prod` (ledger P-01) | READ |
| 61 | Scan → verdict → build → deploy in one run | DESIGNED | — | — | every live deploy used a typed verdict | VERIFIED (ledger S-15) |
| 62 | Promotion verified as its own outcome (DCR-11) | BLOCKED | O-11 | — | the report can never read "verified" | READ |
| 63 | Harness teardown (zero before, zero after) | PROVEN-STUB | `prove_harness_teardown.py` | — | no live run | READ |
| 64 | Scheduled revalidation of what is running (PROV V3) | DESIGNED | — | — | NVD rescans a caller-supplied SBOM/image only | READ |

### 1D · Ticketing

| # | capability | state | evidence | asserted | scope / limit | label |
|---|---|---|---|---|---|---|
| 65 | Ticket reconciler on Jira (create once, idempotent, successor, reopen, ambiguity, refusals by name) | PROVEN-LIVE | `tests/live_ticketing_run.py` R-1, R-2 (T-1, T-2), T-6, T-7, T-8 on a personal Jira; transcripts outside the repository | 4/4 broken settings refused by name, 0 writes; second identical run creates nothing; BINDING_AMBIGUOUS writes nothing | **no GitHub run id**: a local runner against the tracker. Description erasure on update (T-02) is on main; fixed on the trunk (`795d13c`, `prove_ticket_backends` run at 078ef90), with a live re-run on the personal Jira recorded by the L-T merge (`85bd33d`: R-1 5/5 refused, T-02 held) | READ |
| 66 | Azure DevOps backend | PROVEN-STUB / BLOCKED (live) | `prove_ticket_backends.py` and stubs T-1..T-12; live waits on O-19 | — | — | READ |
| 67 | Armed `reusable-ticket-reconcile.yml` on a protected branch | PROVEN-LOCAL / BLOCKED (hosted) | `prove_ticket_reconcile_workflow.py`; self-test PR negative control; hosted armed run waits on O-18 | the guard refuses non-default refs | no template caller; sweep never scheduled | READ |
| 68 | Pull-request Jira reference gate (KDEC-013, `reusable-ticket-reference.yml`) | PROVEN-LOCAL | `tests/prove_ticket_reference_gate.py` (G1..G9) on **main** | no default range; PR body inert; a non-PR event NOT ASSESSED | on main, and on the trunk since `9b18e49` (the trunk at 3830edb lacked it) | VERIFIED presence; proof run at 078ef90 |

### Counts

| state | rows |
|---|---|
| PROVEN-LIVE | 14 |
| PROVEN-HOSTED | 10 |
| PROVEN-LOCAL | 28 |
| PROVEN-STUB | 7 |
| DESIGNED | 4 |
| DEFERRED | 4 |
| BLOCKED | 5 |
| **total** | **72 states over 68 rows (parts 1 and 2)** |

Rows with a split state (37, 45, 66, 67) count once under each of their two states. Row 24 moved
from DESIGNED to PROVEN-LOCAL with the trunk's F-01 fix (`a636f5e`); on main it is still DESIGNED.
Validation debt (`tests/reconcile_validation.py`, 3830edb and again at 078ef90): **0 BLOCKING, 3
deferrals, ratchet 3/3** — rows 38, 39 and 46. Row 34 is a dated weakening, not a registry deferral.
