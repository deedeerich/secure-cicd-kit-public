# Stop and ask — pause on this item and ask the app team

```
Truth State:  Authored, not field-tested (2026-11-03; cloud-neutral wording 2026-11-04).
Use when:     a signal below appears in the evidence. Pause on that item, ask the question, record
              the answer. The rest of the review can continue unless the row says "pause".
Not this:     if the answer belongs to someone other than the app team, use ESCALATE-BROADER.md.
```

| # | Signal (where you see it) | Ask the app team exactly this |
|---|---|---|
| S1 | An `UNKNOWN` row: a leak gate in `leak_gates`, a platform capability, a pin check | "This layer reads `UNKNOWN` because the run's token could not see it. Who can read it with admin rights, and what does it say? Please send a screenshot or API answer." |
| S2 | A skipped or narrowed scanner: a name in `controls_skipped`, `EXCLUDED_BY_SELECTOR`, `language` or `paths` narrowed, `iac_mode: disabled`, `enable_sbom: false`, `image_ref` empty while the app ships an image | "Scanner X did not run on all of the code. Why was it narrowed or skipped, who decided, and until when?" |
| S3 | A row that is not clean: `UNAVAILABLE`, `COLLECTION_FAILED`, `PARTIAL`, `FAILED`, `COVERAGE_GAP`, `UNDETERMINED`; a `controls_unavailable` entry | "This control did not establish its result. Is there a later run where it did? If not, what is being done to make it run, and by when?" |
| S4 | `WEAKENING_SELF_APPROVED` (the requester, actor or release author named as owner or approver: the gate blocked), `WEAKENING_NOT_APPROVED` with the approver or owner missing or on no list, an owner that is a team member, the team itself, or a role nobody can name; or `WEAKENING_UNATTRIBUTED` | "Who outside the team approved this, on which approver list, and where is that decision recorded (`weakening_exception_ref`)?" |
| S5 | `WEAKENING_NOT_APPROVED` for want of an expiry or an evidence reference (no `weakening_expires`, or one past the ceiling, default 90 days), "previously excepted N time(s)" near the cap, or `MIRROR_FALLBACK_UPSTREAM` | "When does this exception end, what removes the need for it, and why was it renewed?" |
| S6 | A self-approved release: an approver who is also the requester or author; `RELEASE_APPROVAL_NOT_REQUIRED` or `ENVIRONMENT_PROTECTION_NOT_REQUIRED` on an environment that serves real users; a `KIT_ENVIRONMENT_TIER` below `uat` there; `tier_reality` `TIER_MISMATCH_SUSPECTED`; `tier_source` `TIER_SELF_DECLARED` on an environment a landing zone should vend | "This environment serves real users but is tiered below uat, so the approval gates did not apply. Who approved this release, and why is the tier set this way?" |
| S7 | `readiness_source` `READINESS_SOURCE_TEST_FIXTURE` on an environment serving real users, `READINESS_ATTESTATION_REFUSED`, an attestation whose approver you cannot place on the AppSec list, or no one can say who set `KIT_ZONE_READINESS` | "Who issued this readiness value? It must come from the landing zone when the app is in a connected one, or from AppSec's attestation (`.kit/zone-readiness.json`) otherwise. Please show the record and its pull request." |
| S8 | `verdict_provenance` other than `VERDICT_FROM_GATE` (`MANUAL_REVIEW_VERDICT`: read the manual review; `TYPED_VERDICT` below uat, where it is only warned); the deploy called with a typed `routing_result` instead of `needs.security.outputs.routing_result`; no `advisory_causes`; `artifact_identity` not checked | "The deploy does not read the security verdict from this run. Why, and which run's verdict, or which manual review, does this release rest on?" — **pause the deploy part of the review** |
| S9 | A kit `uses:` on a branch or tag, mixed SHAs, `kit_watermark` `WATERMARK_ABSENT`, `WATERMARK_DIRTY` or `WATERMARK_UNREADABLE` (no watermark, `source_dirty: true`, or `unresolved_conflicts` not empty) | "Which kit commit is this app actually running, and who chose it?" |
| S10 | Capability floor `GAP_DECIDED` | "A required scanner was removed under a gap decision. What replaces it, and when does the decision expire?" |
| S11 | `policy_source` `KIT_DEFAULT` on an app whose data or exposure calls for more than crawl; an `ORG_UNMAPPED_RAN_AT_*` notice | "Nobody registered a policy for this app, so only secrets, malware, known-exploited CVEs and broken scans block. Is that the level the owner chose?" |
| S12 | `test_only_seed_artifact` set in a non-test caller | "Why does a production caller carry the test-only seed input?" — **pause** |
| S13 | `secret_gate` `EXCEPTED`, or `kev_verdict` `EXCEPTED` | "For each excepted finding: is the secret rotated or the CVE mitigated, and what is the ticket's status?" |
| S14 | `SEAM_OWNERSHIP_NOT_IN_FORCE` / `LEASE_NOT_IN_FORCE` (no lease), `RELEASE_BLOCK_NOT_VENDED`, a `NO_KIT_ADAPTER:<kind>` in `no_kit_adapter`, or a deploy that does not go through the kit's deploy reusables | "What stops another pipeline or a person from changing this target during or after your release?" |
| S15 | `ATTESTATION_ABSENT`, or no `attestation_url` from the build | "How do we know the image deployed is the one your build produced and scanned?" |
| S16 | The run's evidence artifacts have expired (and no durable deployment record, `release_record_ref`, covers the release), `RELEASE_RECORD_NOT_KEPT`, or the newest run is older than the change under review | "Please re-run the security caller on the commit under review, and send the run id." |
| S17 | Job token preflight not `TOKEN_ACCEPTED` (`JOB_TOKEN_REJECTED`, `RATE_LIMITED`, `API_UNREACHABLE`, ...) | "Every API-derived value in this run is unknown. Has the owner role named in the summary fixed it, and is there a clean re-run?" |
| S18 | The change is on a cloud, partition or service the cloud checks do not name, or you cannot map a check's intent to it (`CLOUD-CHECKS.md`, the "other cloud" column) | "Please show me, read-only, where this platform keeps the equivalent: who holds access, who may assume it, what is reachable, where its audit log is. Which of these does the platform not have?" A missing equivalent is a gap to record, not a pass |

## Rules for the pause

- **Ask once, in writing**, quoting the signal and the run id. Keep the answer with the review.
- **An answer is evidence only if it points at something you can read** (a run, a file on the
  default branch, a ticket, a setting). "It's fine" is recorded as *stated by the app team*.
- **No answer by the agreed date** is not consent. The item stays open and sign-off may not cover it.
- **If the honest answer is "someone else decides this"**, it is an escalation: use
  `ESCALATE-BROADER.md`.
- For a CAB change or an adoption approval, an open stop-and-ask item blocks sign-off unless the
  approver records it as a condition with an owner and a date
  ([`CAB-AND-ADOPTION-REVIEW.md`](CAB-AND-ADOPTION-REVIEW.md), step 5; modules by app kind and
  environment: [`APPROVAL-MATRIX.md`](APPROVAL-MATRIX.md)).
