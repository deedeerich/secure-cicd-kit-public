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
| 5 verify at deploy (V1), five outcomes routed by rung, inside both deploy reusables before login (P-02, `ae04403`) and in the starter template; a plan that offers no attestations is held (`PROCEED_WITH_ADVISORY`) | BUILT against recorded answers (`prove_deploy_attestation.py`); live lookup held by plan (L89) |
| 6 scheduled revalidation of what is running (V3) | BUILT (KDEC-029 decision 8: `reusable-deployed-scan.yml`, daily; reconciles what serves, re-scans its SBOM and KEV, reports artifact and security drift); proven locally against the stub cloud, hosted run owed |

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
a proven version gap is refused unless a named person accepts it (KDEC-014, part 03). The rung refuses
more upstream: the gate resolves the policy register first, so at `walk` a finding routes
`DECISION_REQUIRED` and at `run` `BLOCKED`, and the deploy refuses both (part 03). A caller that invokes a deploy reusable directly, without the
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

## Promotion: build once, promote the same digest (KDEC-029; BUILT; proven locally, NOT live)

The owner closed O-11 on 2026-10-26. Deployment success is still not trust progression, but every
condition of the conjunction now has a source, so a deploy record can read `verified-for-promotion`:

| condition | source |
|---|---|
| exact artefact identity | the build's `artifact_identity` (`REGISTRY_IDENTITY_PROVEN`) AND V1 in this deploy (`ATTESTATION_VERIFIED`) |
| running, traffic, reconciliation | the deploy contract's live read-back |
| end-to-end test period | the caller's e2e command at start, intervals and end (KDEC-021's period) |
| DAST, where configured | the caller's DAST command's SARIF: no unsuppressed `error` result (an overlay supplies ZAP baseline) |
| security-settings posture | the live target read back (HTTPS-only, TLS 1.2+, no plain FTP, no remote debugging; no insecure ingress) |
| gates | the release verdict was PROCEED-class |
| source | built from the default branch |

**Shape.** A merge to main builds once and deploys dev and test **in parallel**; each writes its own
record (`kit-promotion-record-<environment>`). uat and prod are **promoted** from the prior environment
(prod's predecessor is test or uat, per product; default test) by a dispatch that builds nothing. The
promotion gate, before login, refuses with a named code: source unreadable, digest mismatch, wrong
predecessor (a dev success never counts), not verified, not from main, signature, revoked, new
finding, re-check incomplete, stale (14 days is a maximum), superseded. Prod runs passive checks only
and refuses active DAST. Hotfix compresses the path; break-glass proceeds on an attributed exception
of at most 7 days, records `BREAK_GLASS`, and the deployed scan tickets the testing owed.

**What is not proven.** Everything above runs against the stub cloud and a recorded GitHub API
(`tests/prove_promotion.py`). A hosted promotion on the owner's personal tenant -- real `gh
attestation verify`, a real artifact listing, a real Trivy SBOM re-scan, real environment approvals
-- is owed.

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

## Sequential rollback (BUILT, lanes L-RB, L-RB2 and L-RB3; proven locally against the stub cloud, NOT live)

KDEC-019 item 4 and KDEC-021: when several deployments must be rolled back, they are reversed
**newest first**, and the application's **end-to-end tests run over a test period after each step**,
the last included (`reusable-rollback-sequence.yml`,
`scripts/rollback_sequence.py`, `templates/rollback-sequence.yml`; `ROLLBACK_CONTRACT.md`
"Sequential rollback"). The caller names the deploy runs, oldest first; each run's
`deploy-evidence-<run_id>-<attempt>` artifact is its manifest.

- **Each step, in order:** eligible from a fresh live read (`ELIGIBLE_UNTOUCHED` — nothing else
  touched the resource; or `ELIGIBLE_OWNED_PART_SEPARABLE` — a shared Container App whose revision
  and traffic from this run are intact); reversed and `ROLLBACK_VERIFIED` by the same deploy-contract
  code the deploys run; healthy; and the caller's `e2e_test_command` passes at every check of the
  step's **test period** (bounded, without the deploy identity's Azure session).
- **The test period** (KDEC-021): `e2e_test_period_minutes`, default 15, `0 < m ≤ 240`; the health
  probe and the tests run at its start, every `e2e_check_interval_minutes` inside it when set, and at
  its end. A failure or timeout at any check halts. `0` is refused (`ROLLBACK_SEQUENCE_REFUSED_NO_TEST_PERIOD`:
  one instant is not a period), over 240 is refused, and under 15 is recorded as a reduced control
  that needs an attributed weakening.
- **App Service returns to the requested version**: `target_version` (required when any step is App
  Service) is checked before anything is touched — a version the target never held is refused — and
  after each reversal every slot it affected is read back live against the version it held before,
  swaps included; after the last step production is read back against `target_version`. A slot
  changed by an actor other than the kit stops the sequence for a human.
- **Deploys are frozen per target**: both deploy reusables and the rollback share one concurrency
  group, `kit-target-<environment>-<resource group>-<name>`, never cancelled in progress, so a deploy
  queues behind a rollback of its target. One rollback run holds one target; a step on another target
  is refused. A kit deploy that lands mid-sequence anyway is fetched, put first, and rolled back with
  its own test period (`inserted`); unfetchable evidence, more than five landings, or an unstamped
  change halts for a human.
- **Anything else stops or halts the sequence, by name**, before anything later is touched: an
  ineligible step (`ROLLBACK_REQUIRES_HUMAN_DECISION`, or `ROLLBACK_PROHIBITED` for a step declared
  forward-fix only), a partial reversal, a failed probe, a failed or hung test
  (`ROLLBACK_SEQUENCE_HALTED_E2E_FAILED`).
- **No end-to-end tests is a refusal** (`ROLLBACK_SEQUENCE_REFUSED_NO_E2E`), before login: running the
  reversals untested is the broken intermediate state the rule forbids.
- **Cross-edited resources (KDEC-023, lane L-RB3; stub-proven, NOT live).** Every resource a rollback
  touches has a class (`rollback-resource-classes.yaml`). **`SHARED_MULTI_CONFIG`** (Front Door, NSG,
  firewall, Application Gateway / WAF, route tables, DNS, API Management): only the product's own
  entries are rolled back, and every other entry is read back byte-identical before and after
  (`ROLLBACK_SCOPED_TO_PRODUCT_CONFIG`). **`STABLE`** (App Service, Container App, database, storage,
  Key Vault, VM…) changed by another actor — or a cross-edit of one of the product's own shared
  entries — gets a **dependency review**: a graph of who depends on what, each node marked unchanged /
  changed by this release / changed by other; the **full rollback is refused**, and either the parts
  independent of the foreign change are rolled back (`ROLLBACK_PARTIAL_DEPENDENCY_CONFLICT`) or
  nothing is (`ROLLBACK_REFUSED_DEPENDENCY_CONFLICT`), each node with its reason, the graph as JSON and
  Mermaid in the record, the evidence and the run summary, and **`ROLLBACK_REQUIRES_HUMAN_DECISION`**
  emitted. The ARM path reads a deployer's `resources.json`; the kit's own deploy adapters do not
  write one yet.
- **A deploy after a rollback is dependency-checked (KDEC-023, the owner's decision).** The rollback
  leaves a marker for its target; both deploy reusables check, **before login**, any deploy built
  before the rollback finished: built on a rolled-back commit, shipping a rolled-back image, or
  declaring (`declared_dependencies`) something the rollback removed or changed →
  **`DEPLOY_REFUSED_ROLLBACK_DEPENDENCY`**, with a report of the rollback and each dependency (old →
  new, or no longer exists); the team corrects the deploy — there is no override. No dependency →
  it deploys, with a note. A check that cannot be completed refuses. The deploys now need
  `actions: read`.
- The record (`schemas/rollback-sequence.schema.json`, v3) lists every step — deployment, eligibility
  basis, rollback, health, e2e, the test period's checks, what it `restored`, whether it was
  `inserted`, timestamps — plus the `lock` held and the requested and `final_version`, and reads
  `ROLLBACK_SEQUENCE_VERIFIED` only when every step is verified (`tests/prove_rollback_sequence.py`
  S1..S19, `tests/prove_rollback_dependencies.py` D1..D8). Never run against Azure (risks R-04); the shared concurrency group is proven by resolving
  its expressions, not by a hosted queue.
