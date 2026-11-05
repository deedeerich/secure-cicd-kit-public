# MOD-PROD-DEPLOY — a release to uat or prod

```
Truth State: Authored, not field-tested (2026-11-03; stated by intent 2026-11-04). One page. Tick only
             from evidence you saw; otherwise label the line Stated or Not established (../SIGN-OFF.md).
```

- [ ] The deploy reads `needs.security.outputs.routing_result` and `advisory_causes` (S8), and the
      build's `artifact_identity` `REGISTRY_IDENTITY_PROVEN` is checked; `verdict_provenance`
      `VERDICT_FROM_GATE`, or `MANUAL_REVIEW_VERDICT` with the manual review attached (the deploy refuses a
      typed or contradicted verdict at uat/prod).
- [ ] `KIT_ENVIRONMENT_TIER` is `uat` or `prod` on every environment serving real users (S6);
      `tier_source` `TIER_VENDED` where a landing zone vends; no `TIER_MISMATCH_SUSPECTED` below uat.
- [ ] `environment_protection` `ENVIRONMENT_PROTECTION_VERIFIED`: required reviewers, self-review
      prevented, reviewers from the approver list.
- [ ] `release_approval` `RELEASE_APPROVAL_VERIFIED`: the approver is neither requester nor author, and
      the approval comment quotes the digest.
- [ ] `release_block` `RELEASE_NOT_BLOCKED` (`RELEASE_BLOCK_NOT_VENDED` outside a landing zone).
- [ ] `zone_readiness` `READY` or `READY_WITH_EXCEPTIONS`, and the **issuer** is known: the landing
      zone when connected (`readiness_source` `READINESS_SOURCE_LZ_HANDOFF`), otherwise AppSec's attestation
      (`READINESS_SOURCE_APPSEC_ATTESTATION`; `.kit/zone-readiness.json` and its approving pull request
      attached). Never the app or deploy team: self-set is refused (S7).
- [ ] Promoted from a verified predecessor (`PROMOTION_ALLOWED`); the record is not `BREAK_GLASS`.
- [ ] `version_gap_ruling` reported; a `VERSION_GAP` accepted only with `weakening_authority`,
      `weakening_reason` and an unexpired `weakening_expires`.
- [ ] Rollback: `rollback_on_failure` `true`; the reversal shown available; an e2e test command set
      (`KIT_E2E_TEST_COMMAND`), or the deploy can never be verified for promotion.
- [ ] Lease: `KIT_TARGET_LEASE_ACCOUNT` set, or `SEAM_OWNERSHIP_NOT_IN_FORCE` recorded as a condition
      (S14, E1).
- [ ] Evidence downloaded: `deploy-evidence-<run_id>-<attempt>` (with `review-signals.json`) and
      `kit-promotion-record-<environment>`; `release_record` kept (`RELEASE_RECORD_KEPT_DEPLOYMENT`
      with its id, or `RELEASE_RECORD_KEPT` with the lease).

**Cloud-neutral.** Every line here reads the kit's own run, the source-control platform or the
people involved; none depends on which cloud the app runs on. Cloud facts the change touches are
read through `../CLOUD-CHECKS.md` by intent, on whichever cloud it is.
