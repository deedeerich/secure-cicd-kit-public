# Reading the run summary — what each kit word means for a reviewer

```
Truth State:  Authored, not field-tested (2026-11-03). Definitions are condensed from
              assurance-taxonomy.yaml, which wins if this sheet disagrees.
```

## The verdict — `routing_result` (most severe wins)

| Word | Means | For you |
|---|---|---|
| `BLOCKED` | a control refused: a secret not excepted, a known-malicious package, a KEV-listed CVE, enforced findings, or a refused policy | fix the code or the policy; deploy refuses |
| `EVIDENCE_UNTRUSTED` | evidence is missing: a scan crashed, `COLLECTION_FAILED`, discovery failed, the gate emitted nothing | the pipeline is broken, not the code; nothing here is clean |
| `DECISION_REQUIRED` | a weakening with no named authority, or an expired decision | a person owes a decision; deploy refuses |
| `PROCEED_WITH_ADVISORY` | proceeds, with a recorded reason in `advisory_causes` | read every cause |
| `PROCEED` | clean, every control at baseline | the only fully clean value |

`advisory_causes`: `FINDINGS_NOT_BLOCKED` (findings recorded, not blocked at this rung),
`WEAKENING_ATTRIBUTED`, `SECRET_EXCEPTION_ATTRIBUTED`, `KNOWN_EXPLOITED_EXCEPTION_ATTRIBUTED`,
`KEV_UNAVAILABLE`, `COVERAGE_PARTIAL`, `VERSION_GAP` (refused at uat/prod without a named
acceptance), `VERSION_GAP_UNVERIFIED`, `WEAKENING_NOT_APPROVED` (refused by a uat/prod deploy, KDEC-036).

## What was established vs what was done

| Output | Values | Read as |
|---|---|---|
| `assurance_state` | `PASS` · `FINDINGS` · `PARTIAL` · `UNDETERMINED` | what the run established. `UNDETERMINED`: what should have run is unknown |
| `enforcement_state` | `BLOCKED` · `ADVISORY` · `ALLOWED` | what the gate did. `ADVISORY` is not clean |
| `secret_gate` | `PASS` · `EXCEPTED` · `FAIL` | `EXCEPTED` = found, and every one excepted. Never clean |
| `kev_state` / `kev_verdict` | `AVAILABLE` / `UNAVAILABLE`; `CLEAR` · `EXCEPTED` · `FINDING_KNOWN_EXPLOITED` | catalog unreadable is never `CLEAR` |
| `undetermined` | `true` · `false` | while `true`, "did not block" is not "safe" |

## One scanner — `scanner_states`

| Word | Means |
|---|---|
| `PASS` | ran, established, nothing blocking |
| `FINDINGS` | ran and found something: the control worked |
| `PARTIAL` | ran on only part of its scope (a version gap, a file it could not parse, a build it could not read). Not clean |
| `NOT_APPLICABLE` | discovery searched and found nothing of its kind. Needs the search as evidence |
| `UNAVAILABLE` | never ran, or the tool could not be acquired. Not clean |
| `COLLECTION_FAILED` | ran, but its report is missing, empty-in-scope or unparseable. Not zero |
| `FAILED` | malfunctioned |

Report rows can also read **NOT ESTABLISHED**: the tool left no machine-readable evidence.

## Discovery and coverage

`EXCLUDED_BY_SELECTOR` (present, narrowed away by `language`) · `COVERAGE_GAP` (code present that no
kit scanner reads; named, e.g. `PHPDependenciesUnlocked`, `BeyondSearchDepth`) · `UNDETERMINED`
(a probe failed or the search depth was reached, so the scanner runs anyway) ·
`DISCOVERY_PARTIAL` / `DISCOVERY_UNAVAILABLE` (everything runs; applicability not established).

## The platform and the token

| Word | Means | Owner |
|---|---|---|
| `ENABLED` | available and on | — |
| `NOT_CONFIGURED` | available and switched off | the platform (a decision made, or never made) |
| `UNAVAILABLE` | not licensed or not available here | the platform |
| `UNKNOWN` / unknown | this run's token could not see it. Run anyway, say so | whoever has admin can read it |
| `TOKEN_ACCEPTED` | the job's own token was accepted | — |
| `JOB_TOKEN_REJECTED`, `ORG_IP_ALLOW_LIST_BLOCKS_RUNNER`, `ORG_SSO_BLOCKS_TOKEN` | GitHub refused the job's token | organisation owner (then workflow maintainer) |
| `RATE_LIMITED` · `API_UNREACHABLE` · `TOKEN_PREFLIGHT_UNCLASSIFIED` | a limit, no answer, anything else | workflow maintainer · runner administrator · workflow maintainer |

## Leak gates — `leak_gates`

`ON` (read and in force) · `OFF` (every source read, none showed it; a recorded weakening) ·
`UNKNOWN` (could not be read; never `ON`, never `OFF`) · `NO_LEAK_GATE_SHOWN` (only the CI scan stands
before the default branch). At crawl none of these change `routing_result`.

## Weakenings, policy, floor

| Output | Values |
|---|---|
| `weakening_attribution` | `WEAKENING_AT_BASELINE` · `WEAKENING_ATTRIBUTED` (approved: an evidence reference, a reason, a named owner, an expiry within the ceiling, an approver on a registered list who is not the requester) · `WEAKENING_NOT_APPROVED` (a field missing, named; recorded at crawl, refused by a uat/prod deploy) · `WEAKENING_SELF_APPROVED` (the requester, actor or release author as owner or approver: BLOCKED everywhere) · `WEAKENING_UNATTRIBUTED` · `WEAKENING_EXCEPTION_EXPIRED` (passed or unreadable date) |
| weakening classes | `GATE_SOFTENED` (runs, block withheld) · `CONTROL_DISABLED` (does not run) · `SCOPE_NARROWED` / `SEVERITY_RAISED` / `DEPTH_REDUCED` (runs differently) · `TARGET_NOT_SUPPLIED` (nothing to examine; skipped, not a weakening) · `CONTROL_SURFACE_DEAD` (an input nothing reads) |
| `policy_source` | `KIT_DEFAULT` (crawl; nobody registered anything) · `REGISTER` |
| `rung_effective` | `crawl` (only secrets-class and untrusted scans block) · `walk` (findings owe a decision) · `run` (findings block) |
| capability floor (gate summary; output `capability_floor`) | `HELD` · `GAP_DECIDED` (a required scanner removed under a dated decision; not a pass of coverage) · `BREACHED` (the gate fails; an unanswered floor reads `BREACHED` in the record) |
| `no_kit_adapter` (deploy coverage) | empty · `NO_KIT_ADAPTER:aks` · `NO_KIT_ADAPTER:vm` · `NO_KIT_ADAPTER:function_app_code` · `NO_KIT_ADAPTER:UNDETERMINED` (the survey could not run) -- the kit scans that code and does not release it |
| kit host copy (`kit_watermark`) | `WATERMARK_BOUND` (with `source_commit`) · `WATERMARK_DIRTY` · `WATERMARK_ABSENT` · `WATERMARK_UNREADABLE` |
| `evidence_retention` (record) | `EVIDENCE_RETENTION_DEFAULT` · `EVIDENCE_RETENTION_SET` · `EVIDENCE_RETENTION_RAISED_TO_FLOOR` · `EVIDENCE_RETENTION_CAPPED` -- days in `retention_days`, never below 90 |

## Deploy side (deploy job summary and outputs)

| Check | Clean at uat/prod | Other values |
|---|---|---|
| `release_block` | `RELEASE_NOT_BLOCKED` | `RELEASE_BLOCK_NOT_VENDED` (no landing zone writes it; recorded) · `RELEASE_BLOCKED_BY_PLATFORM` (refused) |
| `zone_readiness` | `READY`, `READY_WITH_EXCEPTIONS` (gate `ZONE_READINESS_PERMITTED`) | `NOT_READY` · `UNKNOWN` (unset included) → `RELEASE_REFUSED_ZONE_NOT_READY`. Below uat: `ZONE_READINESS_NOT_REQUIRED`. The value does not say who set it: `readiness_source` says what was declared |
| `readiness_source` (zone step) | `READINESS_SOURCE_LZ_HANDOFF` · `READINESS_SOURCE_APPSEC_ATTESTATION` | `READINESS_ATTESTATION_REFUSED` · `READINESS_SOURCE_SELF_SET_REFUSED` (refused at uat/prod) · `READINESS_SOURCE_TEST_FIXTURE` (a labelled fixture: never on an environment serving users, S7) · `READINESS_NOT_SET` |
| `verdict_provenance` | `VERDICT_FROM_GATE` · `MANUAL_REVIEW_VERDICT` (typed, with an AppSec reviewer on the AppSec list, a reference and a date: a manual review, never a scan) | `TYPED_VERDICT` (refused at uat/prod) · `VERDICT_RECORD_UNREADABLE` (refused at uat/prod) · `VERDICT_CONTRADICTED` (refused at every tier) |
| `tier_source` / `tier_reality` | `TIER_VENDED` / `TIER_CONSISTENT` | `TIER_SELF_DECLARED` · `TIER_MISMATCH_SUSPECTED` (warn only) · `TIER_REALITY_UNREAD` |
| `weakening_check` (the deploy's own record) | `WEAKENING_ATTRIBUTED` or empty | `WEAKENING_NOT_APPROVED` (refused at uat/prod) · `WEAKENING_SELF_APPROVED` (refused at every tier) |
| `hosting_kind` | the adapter's kind | `NO_KIT_ADAPTER:<kind>` (a vended `KIT_HOSTING_KIND` this adapter does not release: refused) |
| `release_record` | `RELEASE_RECORD_KEPT_DEPLOYMENT` (lease off; `release_record_ref` is the deployment id) · `RELEASE_RECORD_KEPT` (lease on) | `RELEASE_RECORD_NOT_KEPT` (the job fails) |
| `environment_protection` | `ENVIRONMENT_PROTECTION_VERIFIED` | `ENVIRONMENT_REVIEWERS_ABSENT` · `ENVIRONMENT_SELF_REVIEW_ALLOWED` · `ENVIRONMENT_APPROVER_GROUP_MISSING` · `ENVIRONMENT_PROTECTION_NOT_ESTABLISHED` |
| `release_approval` | `RELEASE_APPROVAL_VERIFIED` | `RELEASE_APPROVAL_ABSENT` (admin bypass) · `SELF_DEPLOYMENT_APPROVAL` · `RELEASE_APPROVAL_NOT_BOUND_TO_DIGEST` · `RELEASE_APPROVAL_NOT_ESTABLISHED` · below uat `RELEASE_APPROVAL_NOT_REQUIRED` |
| `artifact_identity` (build) | `REGISTRY_IDENTITY_PROVEN` (static site: `CONTENT_DIGEST_PROVEN`) | `IDENTITY_UNVERIFIED` · `LOCAL_BUILD_ONLY` · `NOT_ESTABLISHED` |
| attestation (V1) | `ATTESTATION_VERIFIED` | `ATTESTATION_ABSENT` · `ATTESTATION_CONTRADICTED` (blocks) · `ATTESTATION_NOT_ESTABLISHABLE` · `ATTESTATION_HELD_BY_PLAN` |
| `version_gap_ruling` | `VERSION_GAP_NOT_ENGAGED` | `VERSION_GAP_RECORDED` · `VERSION_GAP_UNVERIFIED_RECORDED` · `VERSION_GAP_EXCEPTION_ACCEPTED` · `VERSION_GAP_REFUSED` · `ADVISORY_CAUSE_UNKNOWN`; "not reported" = a pipeline fault |
| seam / lease (`seam_state`, `lease_state`) | `SEAM_OWNERSHIP_HELD`, `LEASE_ACQUIRED`, `MUTATED_UNDER_LEASE` | `SEAM_OWNERSHIP_NOT_IN_FORCE` / `LEASE_NOT_IN_FORCE` (lease off) · `LEASE_HELD` · `MUTATED_WITHOUT_LEASE` (a human decides) |
| outcome (`outcome.json`) | `DEPLOY_HEALTHY`; reversal `ROLLBACK_VERIFIED` | `DEPLOY_REFUSED` (nothing changed) · `ROLLBACK_PARTIAL` · `PARTIAL_APPLY` · `STATUS_UNTRUSTED` · `MANUAL_RECOVERY_REQUIRED` |
| promotion | `PROMOTION_ALLOWED` | a `PROMOTION_REFUSED_*` code naming its reason; `BREAK_GLASS` in the record is never verified |
