# Sign-off — what "reviewed" may and may not claim

```
Truth State:  Authored, not field-tested (2026-11-03).
Use:          when writing the review result. For a CAB change or an adoption approval, also use
              CAB-AND-ADOPTION-REVIEW.md step 5.
```

## Label every claim

Use the same discipline as the kit's own explainer (VERIFIED / READ / DESIGNED). In a review
record, each line carries one of these labels, written in plain words:

| Label | Use when | Example |
|---|---|---|
| **Observed** | you saw it in a run's output, summary or artifact, with the run id | "`routing_result` `PROCEED_WITH_ADVISORY`, cause `FINDINGS_NOT_BLOCKED` (run 123..., commit abc...)" |
| **Read** | you read it in a file, setting or register, but no run showed it working | "`.security/policy-registration.json` carries two secret exceptions, both expiring 2026-12-31" |
| **Stated** | the app team told you and you could not check | "the team states no agent writes to this repository" |
| **Not established** | you looked and the evidence was missing, unreadable or `UNKNOWN` | "push protection: `UNKNOWN` in `leak_gates`; no admin answer" |
| **Handed off** | it went to another role (`ESCALATE-BROADER.md`) | "identity scope escalated to the identity architecture owner, 2026-11-03" |
| **Out of scope** | deliberately not reviewed, with the reason | "the Functions component has no kit adapter and was not reviewed" |

Never upgrade a label in a summary: a list of "Stated" items is not "reviewed".

## What a review MAY claim

- "The security caller ran at kit commit `<sha>` on app commit `<sha>` and its verdict was
  `<routing_result>`, with these causes, these weakenings and these exceptions." (Observed)
- "These controls executed; these were unavailable, reduced or skipped." (Observed, from the
  posture outputs)
- "Secrets, known-malicious packages and KEV-listed CVEs blocked or were excepted as listed."
- "These items were raised with the app team and answered / not answered."
- "These items were handed off to these roles."

## What a review may NOT claim

- **Deployment governance**, unless the deploy controls were live for this app and observed in a
  deploy run at the tier claimed: the app deploys through a kit deploy reusable; the verdict came
  from `needs.security.outputs.routing_result`; at uat/prod `environment_protection`
  `ENVIRONMENT_PROTECTION_VERIFIED`, `release_approval` `RELEASE_APPROVAL_VERIFIED`,
  `zone_readiness` permitted with a known, legitimate issuer (`readiness_source`, and for a manual
  one AppSec's attestation), `verdict_provenance` `VERDICT_FROM_GATE`, and a promotion from a
  verified predecessor. Without all of these, write "deployment governance not established".
  Note the kit's own state too: no live run has yet carried a real gate verdict into a deploy in one
  pipeline (`docs/explainer/09-STATUS-BUILT-VS-DESIGNED.md`).
- **Cross-pipeline protection of the target**, unless the lease was on (`KIT_TARGET_LEASE_ACCOUNT`)
  and the landing zone honours field ownership. The lease and the seam are proven against an
  emulator, not real Azure Storage.
- **"Clean"** for any row that read `UNKNOWN`, `UNAVAILABLE`, `COLLECTION_FAILED`, `PARTIAL`,
  `COVERAGE_GAP` or NOT ESTABLISHED.
- **"Provenance verified"** when attestation was `ATTESTATION_HELD_BY_PLAN`, `ATTESTATION_ABSENT` or
  not checked.
- **Coverage of code no kit scanner reads** (a `COVERAGE_GAP`), of hosting types the kit has no
  adapter for, or of anything a third party runs.
- **Anything about the future.** A review is of the commits and runs named. A new data class, new
  exposure, new identity, new third party, new environment or a removed control means a new review
  (`CAB-AND-ADOPTION-REVIEW.md`, step 3).

## The sign-off block

```
App:            <name>, repository <owner/repo>
Reviewed:       app commit <sha>; kit commit <sha> (watermark source_commit <sha>, kit_watermark <state>)
Runs:           security <run id>; build <run id>; deploy <tier>: <run id>
Verdict:        routing_result <value>; advisory_causes <list>
Exceptions:     <finding / ticket / approver / expiry>, ...
Readiness:      KIT_ZONE_READINESS <value> at <tier>, readiness_source <state>, issued by <landing zone | AppSec attestation ref>
Verdict source: verdict_provenance <state>; tier_source <state>; tier_reality <state>
Records:        kit-security-record-<attempt>; release_record <state> <deployment id>
Obtained:       <OBTAIN-SEPARATELY rows, each Read / Stated / Not established>
Open asks:      S<n>: <question> -- owner <role>, due <date>
Handed off:     E<n>: <role>, <date>
Not established / out of scope: <list>
Claims:         <may-claim lines, each labelled>
Reviewer:       <role>, <date>     Valid for: the commits and runs above only
```
