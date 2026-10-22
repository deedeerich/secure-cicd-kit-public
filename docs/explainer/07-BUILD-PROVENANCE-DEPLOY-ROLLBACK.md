# 07 · Build, provenance, deploy and rollback

This is where the design is deepest. Read the status column literally.

## Build once, scan those bytes, ship those bytes (BUILT in `reusable-build-docker.yml`; proven live)

The image is built **once**; the scan reads that image; the push sends those bytes; the registry is read
back to prove it holds what was scanned (`REGISTRY_IDENTITY_PROVEN`). The composite now builds once too, and a
Trivy refusal in the build routes `BLOCKED` (L85). Proven live against a cloud registry over OIDC
(runs 38857011286, 38857017667, 38857024014); those exact digests were then deployed.

## Provenance (DESIGNED in `PROVENANCE_AND_ATTESTATION.md`; partly built)

| step (PROV §9 order) | state |
|---|---|
| 1 capture build inputs: base image digest, lockfile hash, toolchain versions | BUILT, proven (L86) |
| 2 the template passes `version_metadata` | BUILT, proven (L87) |
| 3 the template branches on `artifact_identity` and on the security verdict | BUILT, proven (L87) |
| 4 a separate attest job holding `attestations: write` at job level only | BUILT; signing itself needs a hosted run (L88) |
| 5 verify at deploy (V1), four outcomes routed by rung; held as dated debt on private plans without attestation | BUILT against recorded answers; live lookup held by plan (L89) |
| 6 scheduled revalidation of what is running (V3) | design owed |

The version stamp (`render-version-metadata`) defaults to the weakest claim: `technical_provenance:
NOT_ESTABLISHED` until something proves otherwise (BUILT).

## Deploy (designed in `DEPLOYMENT_CONTRACT_RECONCILIATION.md` and `ROLLBACK_CONTRACT.md`; BUILT; proven live)

**The deploy stage reads the verdict, not a job result.** It proceeds only when:

```
routing_result ∈ {PROCEED, PROCEED_WITH_ADVISORY}          -- checked by the deploy reusables
AND artifact identity is REGISTRY_IDENTITY_PROVEN          -- checked by the starter template's
    (the digest that was scanned is the digest deployed)       `verdict` job, NOT by the reusables
```

…and the deploy reusables refuse, **before logging in to anything**, on any other value, an empty value,
or an unrecognised one — naming what it refused. At `uat` and `prod`, a `PROCEED_WITH_ADVISORY` caused by
a proven version gap is refused unless a named person accepts it (KDEC-014, part 03); the rung ladder
that would refuse more is Release 2. A caller that invokes a deploy reusable directly, without the
template's `verdict` job, must check `artifact_identity` itself.

The verdict step writes exactly one KDEC-014 `version_gap_ruling` on every path it reaches,
`VERSION_GAP_NOT_ENGAGED` included; an empty ruling means it never answered, and the deploy's posture
then routes `EVIDENCE_UNTRUSTED` and its summary says "not reported" (`078ef90`, part 03).

**Today (live runs as cited; the trunk is now at `078ef90`)**: both deploy reusables are proven **live** on a sandbox Azure
subscription, called as a consumer calls them (`live-deploy-acceptance.yml`): a `BLOCKED` verdict refused
before login (38853176286); an irreversible deploy at prod refused (38853184615); healthy deploys of
kit-built digests (38855599716, 38857259257, 38857271571); unhealthy ones rolled back and verified against
live state (Container Apps 38855747496, 38858033863; App Service 38878189985); a second actor's change
deferred to or refused, reported `ROLLBACK_PARTIAL` (38855929525, 38886279650); the App Service staging
slot health-checked and swapped (38912063363) or not swapped (38912546778). Still stub-only: EMPTY and
UNKNOWN prior state, `PARTIAL_APPLY` / `STATUS_UNTRUSTED`, a capability refusal at a production tier,
provenance tags written, the KDEC-014 rule, and the two silence rules in the rollback section below
(`71a3d63`, `078ef90`). Every live deploy received a **typed** verdict: no run yet carries a real gate
verdict into a deploy in one pipeline. The live runs predate KDEC-014 (`1c20a0b`) and the silence
rules; those are proven against the stub cloud only.
**The kit is not a landing-zone deploy engine**: it has no plan/apply/destroy/vend pipeline (KDEC-009:
the landing zone vends, the kit releases).

### The deployment lifecycle (the fixes go in this order, DCR §5)

```
intent → pre-change snapshot → change manifest → mutation (the point of no return is the push/swap)
       → health and functional validation → live-state reconciliation → provenance written LAST
```

1. App Service `slot: ''` handling · 2. **ATTEMPTED vs NOW SERVING** are different facts · 3. provenance
after health · 4. a read failure is not "empty" · 5. rollback to empty · 6. snapshot + manifest ·
7. live-state verification · 8. `PARTIAL_APPLY` / `STATUS_UNTRUSTED` · 9. rollback capability established
**before** the point of no return · 10. the push as the point of no return · 11. promotion verified as its own
outcome, distinct from `DEPLOY_HEALTHY` (proposed in DCR §4; no deploy reusable emits it yet, so it is not
yet registered — `deployment_outcome` registers values as they are emitted, never ahead).

Readiness is reported in layers that never imply each other: infrastructure ready, dependencies ready,
inputs ready, runtime deployed, health verified, serving verified. "The health endpoint returned 200" can
come from the old revision; serving is proven by reading back the running digest.

## Rollback (BUILT; proven live for the cases above)

> **Roll back to the last known-good state of only what this run changed.** If this run created it,
> remove only that. If it modified something that already existed, restore the prior state. Then check
> live state independently before declaring recovery.

- Three artifacts: the **pre-change snapshot** (only what this run will change: resource ids, active
  revision or slot, image digest, settings, traffic weights), the **change manifest** (what was created,
  updated, deleted, redirected), and the **validated rollback** (compared with the snapshot).
- `previous_state` has three values (`EXISTING_DEPLOYMENT`, `EMPTY`, `UNKNOWN`); failing to read it fails
  loudly instead of reading as "nothing there".
- **Exactly one destructive disposition per object**, derived from live state with an ownership stamp
  written with the mutation. If a second actor modified, or took a dependency on, an object this run
  created, the reversal **refuses** to remove it and reports the refusal.
- **Silence is not capability.** With reversal required (`rollback_on_failure: true`, the default), a
  rollback-capability step that succeeded but wrote no verdict reads as reversal **UNAVAILABLE**,
  never as available (`71a3d63`, found by the strengthened assurance tracer): the deploy's posture
  lists `reversal` in `controls_unavailable` and routes `EVIDENCE_UNTRUSTED`. Likewise an empty
  KDEC-014 ruling routes `EVIDENCE_UNTRUSTED` (`078ef90`). VERIFIED locally at `078ef90`.
- Mutating workflows are never cancelled in flight and are serialised per target.
- **Full teardown is a test-harness behaviour, never a deployment behaviour**, and only with
  before/after zero-count assertions.

Built: the derivation (`derive_reversal_disposition.py`), the snapshot/manifest, the reversal and the
six-question outcome report (`scripts/deploy_contract.py`), proven locally against stubbed live state
(acceptance matrix A–E) and live on the owner's sandbox for matrix A and C and the second-actor case
(KDEC-012). Matrix B, D and E and rollback-to-empty are not live. One known caveat: App Service judges
NOW SERVING by the configured image, with the platform's container start record reported beside it
(completion ledger DCR-2, B-02).

**What a consumer reads back.** The deploy reusables output `routing_result`, the posture rows and
`app_url` (Container Apps also `revision`). The deploy outcome itself — `deployment_outcome`, ATTEMPTED
vs NOW SERVING, the reversal and the KDEC-014 ruling — is **not** a workflow output: it is in the job
summary and in the `deploy-evidence-<run_id>-<attempt>` artifact (`outcome.json`, `snapshot.json`,
`manifest.json`, `capability.json`, `verification.json`, `reversal.json`, and `provenance.json` when
a stamp was written). Their shape is defined in code (`scripts/deploy_contract.py`), not by a schema.

## Sequential rollback (BUILT, lane L-RB; proven locally against the stub cloud, NOT live)

KDEC-019 item 4: when several deployments must be rolled back, they are reversed **newest first**,
and the application's **end-to-end tests run after each step** (`reusable-rollback-sequence.yml`,
`scripts/rollback_sequence.py`, `templates/rollback-sequence.yml`; `ROLLBACK_CONTRACT.md`
"Sequential rollback"). The caller names the deploy runs, oldest first; each run's
`deploy-evidence-<run_id>-<attempt>` artifact is its manifest.

- **Each step, in order:** eligible from a fresh live read (`ELIGIBLE_UNTOUCHED` — nothing else
  touched the resource; or `ELIGIBLE_OWNED_PART_SEPARABLE` — a shared Container App whose revision
  and traffic from this run are intact); reversed and `ROLLBACK_VERIFIED` by the same deploy-contract
  code the deploys run; healthy; and the caller's `e2e_test_command` passes (bounded, without the
  deploy identity's Azure session).
- **Anything else stops or halts the sequence, by name**, before anything later is touched: an
  ineligible step (`ROLLBACK_REQUIRES_HUMAN_DECISION`, or `ROLLBACK_PROHIBITED` for a step declared
  forward-fix only), a partial reversal, a failed probe, a failed or hung test
  (`ROLLBACK_SEQUENCE_HALTED_E2E_FAILED`).
- **No end-to-end tests is a refusal** (`ROLLBACK_SEQUENCE_REFUSED_NO_E2E`), before login: running the
  reversals untested is the broken intermediate state the rule forbids.
- The record (`schemas/rollback-sequence.schema.json`) lists every step — deployment, eligibility
  basis, rollback, health, e2e, timestamps — and reads `ROLLBACK_SEQUENCE_VERIFIED` only when every
  step is verified. App Service is eligible only untouched. Never run against Azure (risks R-04).
