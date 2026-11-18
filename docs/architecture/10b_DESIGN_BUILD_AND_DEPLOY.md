# 10b · Design: build, verdict, deploy, promotion, rollback and the deployed scan

```
Kept:      2026-11-07, against the trunk at c1420ea. Components: 03b_COMPONENTS_DEPLOY.md.
Code:      templates/build-deploy.yml, templates/build-deploy-static.yml, reusable-build-docker.yml,
           the three deploy reusables, reusable-deployed-scan.yml, reusable-rollback-sequence.yml;
           scripts/deploy_contract.py, scripts/promotion.py, scripts/release_gates.py,
           scripts/environment_protection.py, scripts/reviewer_signals.py, scripts/target_lease.py,
           scripts/static_site_contract.py, scripts/rollback_sequence.py, scripts/rollback_hold.py.
Deeper:    PROVENANCE_AND_ATTESTATION.md, ROLLBACK_CONTRACT.md, DEPLOYMENT_CONTRACT_RECONCILIATION.md,
           LZ_KIT_HANDOFF_CONTRACT.md, LZ_KIT_SEAM_CONTRACT.md, ARCH_01_PIPELINE_END_TO_END.md.
```

## 1 · Purpose

Release exactly the bytes that were scanned, into the environment the landing zone vended, only after
every check that can refuse has refused or passed, and keep a record that outlives the run.

## 2 · Inputs and outputs

| Kind | What | Notes |
|---|---|---|
| input | the verdict from the template's `verdict` job: `deploy_routing_result`, `advisory_causes`, `controls_unavailable`, `deploy_approval` | the deploy re-reads the security record to check where the verdict came from (KDEC-036 G8) |
| input | `image_digest` (or a static site's tree digest), `version_metadata`, `artifact_identity` | a digest only; a tag is refused |
| input | `github_environment` (required, no default) and the environment's vended `KIT_*` values | the bind step fills empty inputs and refuses a mismatch |
| input | for a promotion: `promote_from_run_id`, `promote_from_environment`, `promotion_predecessor` | the same digest, never rebuilt |
| input | for break-glass or rollback: the five weakening fields | at most 7 days for break-glass |
| input | `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `AZURE_CLIENT_ID` (identifiers, in `secrets:` slots) | federated, no key |
| output | `routing_result`, `release_approval`, `release_approval_by`, `zone_readiness`, `release_block`, `verdict_provenance`, `tier_source`, `readiness_source`, `release_record`, `lease_state`, `review_signals` and more | 31 outputs on each deploy reusable |
| output | artifacts `deploy-evidence-RUN-ATTEMPT`, `kit-promotion-record-ENV`; a GitHub deployment with task `kit-release-record` | 06 section 4 |

## 3 · How it works

1. **Build once** (push to main): scan the loaded image before push, SBOM, record build inputs, push the
   scanned bytes, assert the registry holds them, attest.
2. **Decide** in the template's `verdict` job: identity proven and a PROCEED-class verdict, or no deploy.
3. **Deploy dev and test in parallel** from that one build (KDEC-029); each writes its own promotion record.
4. **Promote** to uat or prod when a person dispatches it: read the predecessor's record, and deploy the
   same digest through the promotion gate and the release approval.
5. **Inside each deploy**, before login: bind, readiness source, stop and readiness, protection read-back,
   verdict, digest, V1, rollback marker, promotion gate, release approval, reviewer signals.
6. **After login**: lease (opt-in), capture, establish rollback, seam (opt-in), deploy, verify healthy,
   move traffic, verify the consumer path, reverse when unhealthy, stamp, purge the edge, test period,
   DAST (never prod), posture, records.
7. **Every day**: the deployed scan reconciles what serves and reports drift. **On request**: a sequential
   rollback reverses several deployments with a test period after each.

## 4 · States, in plain words

| State | In plain words |
|---|---|
| `deployment_outcome.DEPLOY_REFUSED` | The deploy was refused before it changed anything; the reason is the first refusal listed below it. |
| `deployment_outcome.ROLLBACK_TO_PRIOR` | The new version failed its checks and the deploy put the previous version back. |
| `deployment_outcome.MANUAL_RECOVERY_REQUIRED` | The deploy failed its checks and could not undo itself automatically; the failed version is still live. |
| `artifact_identity.IDENTITY_UNVERIFIED` | The image was pushed, but the kit could not prove the pushed image is the one it scanned. |
| `attestation_verification.ATTESTATION_ABSENT` | No signed build record (attestation) exists for this image. |
| `attestation_verification.ATTESTATION_HELD_BY_PLAN` | This private repository's GitHub plan does not offer attestations, so the signature check was skipped. |
| `environment_protection.ENVIRONMENT_REVIEWERS_ABSENT` | The uat or prod environment has no required reviewers, so anyone who can run the workflow could deploy. |
| `environment_protection.ENVIRONMENT_SELF_REVIEW_ALLOWED` | The environment lets the person who started the deploy approve it themselves. |
| `environment_protection.ENVIRONMENT_APPROVERS_ALL_APP_TEAM` | Every reviewer of the uat or prod environment is on the app team that wrote the change. |
| `release_approval.SELF_DEPLOYMENT_APPROVAL` | The person who approved this release is the one who requested it, or the author of the change. |
| `release_approval.RELEASE_APPROVAL_NOT_BOUND_TO_DIGEST` | The approval did not quote the image digest being released, so it is not shown to be for these exact bytes. |
| `release_block.RELEASE_BLOCKED_BY_PLATFORM` | The landing zone has paused releases to this workload (halted, expired, or over budget). |
| `zone_readiness.NOT_READY` | The landing zone for this environment failed a readiness check. |
| `readiness_source.READINESS_SOURCE_SELF_SET_REFUSED` | KIT_ZONE_READINESS was set by the deploying team itself, with no landing-zone marker and no AppSec attestation. |
| `verdict_provenance.VERDICT_CONTRADICTED` | The verdict handed to the deploy is more permissive than what the security scan actually decided. |
| `promotion_gate.PROMOTION_REFUSED_DIGEST_MISMATCH` | The image you are promoting is not the one the earlier environment verified. |
| `promotion_gate.PROMOTION_REFUSED_STALE` | The build was verified more than 14 days ago. |
| `promotion_gate.DAST_REFUSED_PRODUCTION_TARGET` | Active DAST (attack testing) was configured against prod. |
| `promotion_gate.BREAK_GLASS_REFUSED_TOO_LONG` | The break-glass exception expires more than 7 days out. |
| `promotion_revocation.NEW_KNOWN_EXPLOITED` | A package in this build is now on the known-exploited vulnerability list. |
| `target_lease.LEASE_HELD` | Another pipeline (the landing zone or another run) is changing this target right now. |
| `target_lease.STALE_LEASE_HOLDER` | This run's hold on the target was taken over or broken, so its change was not sent. |
| `rollback_state.ROLLBACK_REQUIRES_HUMAN_DECISION` | Undoing this change needs a person to decide: the previous state is unknown or reversal has consequences. |
| `rollback_sequence.ROLLBACK_SEQUENCE_HALTED_E2E_FAILED` | After a step was rolled back, the end-to-end tests failed, so the sequence stopped. |
| `tier_source.TIER_SELF_DECLARED` | The environment's tier (dev, test, uat, prod) was set by the team, not by the landing zone. |
| `edge_purge.EDGE_PURGE_FAILED` | Clearing the edge cache failed after a good release. |

## 5 · Failure modes

| Failure | What happens | Proof |
|---|---|---|
| a refusal is reached | it happens before the cloud login; the identity is never used | `tests/prove_deploy_gate.py` (ENFORCED, stage 15) |
| the new revision is unhealthy | this run's changes are reversed and the target read back | `tests/prove_deploy_outcome.py` |
| the run cannot tell what serves | NOW SERVING is `unknown`, never the attempted value | `tests/prove_deploy_now_serving.py` |
| two deploys of one app at once | they queue in one concurrency group, never cancel | `tests/prove_deploy_concurrency.py` |
| the landing zone and the kit write the same target | the lease and the seam refuse the second writer (opt-in) | `tests/prove_target_lease_crossrepo.py` |
| an App Service deploy straight to production with no slot | refused at a production tier | `tests/prove_deploy_direct_to_production.py` |
| a rollback step breaks the app | the sequence halts at that step | `tests/prove_rollback_sequence.py` |
| the artifact expired before an audit | the deployment record survives it | `tests/prove_release_record_store.py` |

## 6 · Decisions

| Decision | What it settled |
|---|---|
| KDEC-009, KDEC-015 | the landing zone vends; the kit deploys, for all tools |
| KDEC-014 | a version gap at uat/prod needs an attributed exception |
| KDEC-019, KDEC-021, KDEC-023 | sequential rollback with a test period per step; cross-edited rollback by resource class; an incoming deploy after a rollback is dependency-checked |
| KDEC-029 | build once, promote the same digest; "tested" defined; 14 days at most; revocable at once; the daily scan of what serves |
| KDEC-030 | the landing zone and the kit share targets by field, with one cross-repository lease (opt-in until ruled) |
| KDEC-034 | the landing zone's stronger release steps adopted: stop, readiness, bound approval, one approver list, durable records, the edge purge |
| KDEC-036 | verdict provenance, weakening authority, readiness source, the durable release record |
| KDEC-042 | never a uat or prod deployment without a human approval from outside the app team |
