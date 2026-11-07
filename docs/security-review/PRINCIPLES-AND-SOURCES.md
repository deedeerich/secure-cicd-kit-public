# Principles and sources — why each check in the security review of a CAB change is asked

```
Truth State:  Authored, not field-tested (2026-11-03). Source titles and control identifiers are as
              published by each body; section numbers of benchmarks move between versions, so cite
              the version your organisation adopted and map by the control's title.
Use:          when a requester asks "why are you asking this?", or when an approver wants the basis of
              a stop. Check ids are those of CAB-CHANGE-SAFETY-STEPS.md (step.check), the boundary
              rows (DB, SB, AB, XB) and the cloud sheets (Z = Azure, W = AWS, H = GitHub).
```

## 1 · The principles, each mapped to the checks that use it

| Principle | What it means for one change | Checks that use it | Sources |
|---|---|---|---|
| **Least privilege** | an identity gets only the actions it needs, on only the resources it touches, for only as long as it needs them | AB-1, AB-2, AB-4; Z1, Z5, Z9, Z10; W1, W6, W8; H3, H4, H6; 3.12 | NIST SP 800-53 AC-6 (and AC-6(5) privileged accounts); MCSB PA-7, IM-3; AWS Well-Architected SEC 3; CIS Azure and AWS Foundations (identity sections); OWASP Top 10 A01 |
| **Defence in depth** | one control failing must not expose the asset: network, identity, encryption, monitoring each hold on their own | SB-1..SB-5; Z2, Z3, Z4, Z6; W3, W4, W5, W7; 3.7 (leak gates are layered) | NIST SP 800-53 SC-7; MCSB NS-1, NS-2; AWS Well-Architected design principle "apply security at all layers", SEC 5; OWASP ASVS V1 |
| **Secure by default** | the change keeps the platform's secure defaults (private, encrypted, logged, authenticated) unless a named decision says otherwise | XB-1; Z4, Z13; W4, W8, W10; H3 (`read` default token); 3.2 (`PROCEED` needs every control at baseline) | NIST SSDF PW.9; NIST SP 800-53 CM-6, CM-7; OWASP Top 10 A05; CIS Benchmarks (each control's recommended default) |
| **Separation of duties** | the requester never approves: not the release, not an exception, not a weakening, not a readiness value | 1.8 stop; 3.4, 3.5, 3.10; 5.2; H2 (`prevent_self_review`), H3 (Actions may not approve); EARLY-REVIEW-REQUESTS section 2 | NIST SP 800-53 AC-5, CM-3; ITIL 4 change enablement (the change authority is not the requester); OWASP Top 10 CI/CD CICD-SEC-1 (insufficient flow control); kit: `SELF_DEPLOYMENT_APPROVAL`, K-1 |
| **Fail closed** | missing, unreadable or unknown evidence counts against the change, never for it | 2 (unknown = yes); 3.1, 3.2 (`EVIDENCE_UNTRUSTED` stops), 3.3, 3.7 (`UNKNOWN` is never `ON`); step 7 ("I could not check it" is never safe); H intro (403 is UNKNOWN) | NIST SP 800-53 SC-24 (fail in known state); kit principle 2 (four states of "nothing") and principle 9 (the verdict is data) |
| **Evidence over assertion** | every claim in the ticket points at a run, a report, a plan or a read the reviewer can repeat | 3.1, 3.3, 5.3, 5.5; every cloud check (a command, not a description); a tick counts only with its source (checklist); claim labels in `SIGN-OFF.md` | NIST SP 800-53 CM-4(2) (verify controls after change), CA-2; NIST SSDF PO.4 (criteria for security checks), PS.3 (archive each release); kit principle 1 (configured is not effective) |
| **Understand before you attest** | a reviewer signs only what they understood; not knowing is a valid, routed outcome, never a silent tick | step 1 (the understanding gate: blank is not valid); step 7 "Not reviewed — outside my knowledge" and "Paused"; the checklist's rubber-stamping box; the sign-off wording | NIST SP 800-53 CM-4 (impact analysis needs the change understood), CM-3(4) (security representatives on the change board are there to judge, not to initial); ITIL 4 change enablement (assessment before authorisation) |
| **Change traceability** | the change is one artefact, linked both ways to its ticket, and every platform change can be tied to it | 1.7; 4.0 (no unexpected diff); 5.4; 3.10 (approval bound to the digest); step 8 "valid for" | NIST SP 800-53 CM-3, CM-5, AU-2, AU-12; NIST SSDF PS.2 (verify release integrity); ITIL 4 change enablement (change record, change schedule); SLSA build provenance; AWS Well-Architected "maintain traceability" |

## 2 · The sources, and where each one bites

| Source | What this procedure takes from it | Checks |
|---|---|---|
| **OWASP ASVS** (4.0.3 chapter names; ASVS 5.0 reorganises them, map by title) | V1 architecture (trust boundaries), V2 authentication, V4 access control, V6 stored cryptography, V7 logging, V8 data protection, V9 communications, V13 API, V14 configuration — the application questions the kit does not test | AB-7, DB-1..DB-4, SB-3; 3 (app questions labelled Read or Stated); Z13; W10 |
| **OWASP Top 10** (2021 edition; map by name if your organisation uses a later one) | A01 broken access control, A02 cryptographic failures, A05 security misconfiguration, A06 vulnerable and outdated components, A07 identification and authentication failures, A08 software and data integrity failures, A09 logging and monitoring failures | 3.6 (A06), 3.8 and 3.10 (A08), SB-5 and Z6/W7 (A09), Z4/W4 (A05), AB-7 (A01, A07) |
| **OWASP Top 10 CI/CD Security Risks** (also used) | CICD-SEC-1 flow control, -2 identity and access, -4 poisoned pipeline execution, -6 credential hygiene, -7 insecure system configuration, -8 ungoverned third-party services, -9 artefact integrity, -10 logging | 5.1 (-4), 5.2 (-1), H1..H6, 3.12 (-9), XB-3 (-8) |
| **NIST SP 800-53 Rev. 5** | **CM-3** configuration change control (and CM-3(4): security representatives on the change board — the reason this role is on the CAB ticket); **CM-4** impact analyses (CM-4(1) separate test environments; CM-4(2) verification of controls); CM-5 access restrictions for change; CM-6 configuration settings; **AC-6** least privilege; AC-5 separation of duties; **AU-2, AU-6, AU-9, AU-11, AU-12** event logging, review, protection, retention, generation; SC-7 boundary protection; SC-8, SC-28 encryption in transit and at rest; SC-12 key management; IA-2(1) MFA; IA-5 authenticators; SA-9 external services | CM-3: steps 1, 5.4, 8; CM-4: steps 2, 4 ("read after in a lower environment"), 6; AC-6: AB rows, Z1, W1; AU: SB-5, Z6, W7, H8, 4.0; SC: SB rows; IA: AB-5, AB-6; SA-9: XB-3 |
| **NIST SSDF (SP 800-218)** | PO.4 criteria for security checks; PO.5 secure environments; PS.1 protect code; PS.2 verify release integrity; PS.3 archive each release; PW.7, PW.8 review and test; PW.9 secure defaults; RV.1 identify vulnerabilities | 3.2, 3.3 (PO.4); 5.1, H1 (PS.1); 1.7, 3.10, 3.12 (PS.2); 5.5 (PS.3); 3.6 (RV.1) |
| **CIS Benchmarks** — Microsoft Azure Foundations, AWS Foundations, GitHub (with the CIS Software Supply Chain Security Guide) | per-setting secure defaults: storage public access, NSG management ports, Key Vault purge protection, diagnostic settings; IAM wildcard policies, S3 Block Public Access, CloudTrail and Config on, security groups from 0.0.0.0/0; branch protection, required reviews, token default permissions, deploy keys | Z2, Z4, Z5, Z6; W1, W3, W4, W7; H1, H3, H5 |
| **Microsoft cloud security benchmark** (MCSB) | NS-1, NS-2 network segmentation and private access; IM-3 managed identities; IM-7 conditional access; IM-8 restrict exposure of credentials and secrets; PA-1, PA-7 privileged access and just enough administration; DP-3, DP-4, DP-6 encryption and key management; LT-3, LT-4 logging; DS (DevOps security) | Z1..Z14 |
| **AWS Well-Architected Framework, security pillar** | design principles (strong identity foundation, traceability, security at all layers, protect data in transit and at rest, keep people away from data); SEC 2 identities, SEC 3 permissions, SEC 4 detection, SEC 5 network, SEC 7 data classification, SEC 8 and SEC 9 data protection | W1..W12 |
| **ITIL 4 change enablement** (how the security verdict fits the organisation's existing CAB; nothing here redefines it) | assessment before authorisation; emergency changes authorised fast and reviewed after; the change record as the one place the decision lives | steps 7, 8; emergency section; EARLY-REVIEW-REQUESTS section 3 (nothing decided off-ticket) |
| **SLSA** (also used) | build provenance binding an artefact to its source and build | 1.7, 3.8, 3.10, 3.12 (the kit's `artifact_identity`, attestation and digest-bound approval) |

## 3 · Common gotchas, and the check that catches each

| # | Gotcha | What it looks like on the ticket | Caught by |
|---|---|---|---|
| G1 | **"Temporary" public access never reverted** | "open the port / allow public access for the migration, we'll close it after" | XB-1, SB-1; 6.4 (rollback must close it); Z2, Z4, W3, W4; the emergency retrospective |
| G2 | **A wildcard IAM action** | a policy with `"Action": "*"`, `s3:*` or `iam:PassRole` on `"*"` "to unblock the deploy" | AB-2; W1 (`validate-policy`); Z1 (a custom role with `"*"`) |
| G3 | **A managed identity at subscription scope** | "gave the app's identity Contributor so it can read the vault" | AB-2; Z9; Z1 |
| G4 | **Logging disabled to cut cost** | "reduce diagnostic settings / data events to lower the bill" | SB-5; Z6; W7; H8 |
| G5 | **A secret in app settings or environment variables** | a connection string with a key pasted into configuration "until Key Vault is set up" | AB-6; Z12; W9; 3.7 for the repository side |
| G6 | **A self-approved exception** | the requester's name in `approver` of a register exception, or as `weakening_authority` | 3.4, 3.5; 5.2; `WEAKENING_SELF_APPROVED` (gate BLOCKED; `weakening_attribution`, `weakening_check`) |
| G7 | **An exception with no expiry** | `expires` missing, far out, or renewed past the cap | 3.5; `WEAKENING_NOT_APPROVED` naming `expiry` (`weakening_attribution`, `weakening_check`), `EXCEPTION_RENEWAL_LIMIT`; Z8 (a policy exemption with no end) |
| G8 | **A Lambda function URL with auth `NONE`** | "added a function URL for the webhook" | XB-1, AB-7; W8 |
| G9 | **A typed verdict in the deploy call** | the workflow passes `routing_result: PROCEED` instead of the security job's output | 3.11 (S8; `verdict_provenance` `TYPED_VERDICT` or `VERDICT_CONTRADICTED`); 5.1 |
| G10 | **The required check renamed or removed** | a workflow rename, after which `Security gate` no longer reports and is no longer required | 5.1; H1 |
| G11 | **A dangling DNS record** | a record pointing at an app or bucket being deleted in the same change | XB-2; Z14; W12 |
| G12 | **An OIDC trust with a wildcard subject** | a federated credential or IAM trust on `repo:<owner>/*` or a branch form for an environment job | AB-3; Z10; W2 |
| G13 | **`pull_request_target` checking out the pull request** | a workflow that runs pull-request code with a write token and secrets | 5.1; H3 |
| G14 | **An approval that is not for these bytes** | approved "the release" in the environment, no digest in the comment; a rebuild after approval | 3.10 (`RELEASE_APPROVAL_NOT_BOUND_TO_DIGEST`); 1.7 |
| G15 | **Rollback that reverts the code but not the grant** | the back-out plan redeploys the old image; the new role, rule or consent stays | 6.4 |
| G16 | **Production labelled dev** | an environment serving real users tiered `dev` or `test`, so the uat/prod gates never apply | 1.3; H2; S6 (`tier_reality` `TIER_MISMATCH_SUSPECTED`, `tier_source` `TIER_SELF_DECLARED`) |
| G17 | **`UNKNOWN` read as on** | "push protection is on" when the run says the layer could not be read | 3.7 (S1); H intro |
| G18 | **CORS `*` with credentials** | "allow all origins so the new front end works" | AB-7; Z13 |
| G19 | **Admin bypass of the environment** | the release went out with no approval because an admin bypassed it | 3.9 (`RELEASE_APPROVAL_ABSENT`); H2 (`can_admins_bypass`) |
| G20 | **The scan narrowed in the same change** | a `paths` or `language` narrowing, `advisory_mode`, or a register softening beside the code it would have caught | SB-6; 3.3, 3.4; 5.1 |
| G21 | **A private endpoint replaced by public access** | "the private endpoint was flaky, switched to public with an IP rule" | SB-1, XB-1; Z3, Z4 |
| G22 | **Consent granted to a third-party app** | an admin consent to a multi-tenant app for "a quick integration" | XB-3, AB-2; Z10 (E5) |
| G23 | **Decided off-ticket** | "security said it was fine on the call" with nothing on the CAB record | EARLY-REVIEW-REQUESTS.md section 3; step 8 |
| G24 | **Reviewing what you don't understand** | ticks with no source; the understanding lines blank or copied from the requester; "LGTM" on the ticket | step 1 gate; the checklist's rubber-stamping box; step 8 (a bare "security reviewed" is not a sign-off) |
