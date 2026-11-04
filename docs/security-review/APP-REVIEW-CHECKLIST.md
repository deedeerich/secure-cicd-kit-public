# App review checklist — in the order a review actually runs

```
Truth State:  Authored, not field-tested (2026-11-03).
Use with:     READING-THE-RUN-SUMMARY.md open beside it. S-numbers point to STOP-AND-ASK.md,
              E-numbers to ESCALATE-BROADER.md.
Evidence:     one recent run of the app's security caller, and (if it deploys) one recent deploy run
              per tier you are reviewing. Kit evidence artifacts are kept
              KIT_EVIDENCE_RETENTION_DAYS days, never below 90 (`evidence_retention` in the
              record): a run older than that may have no artifacts left (S16), but with the lease
              off each release keeps a durable GitHub deployment record (`release_record_ref`).
```

Tick each box only from evidence you saw. "The team said so" is a different label (see `SIGN-OFF.md`).

---

## 1 · Scope and context

- [ ] **What the app is**: name, repository (or repositories), hosting type. The kit releases Azure
      App Service (Linux container), Azure Container Apps, Azure Static Web Apps and Azure Functions
      hosted as a Linux custom container on a Premium or Dedicated plan (the App Service reusable with
      `site_kind: functionapp`). Code-packaged Functions, AKS and VMs have no kit adapter: the gate
      names them `NO_KIT_ADAPTER:<kind>` (output `no_kit_adapter`, summary row "deploy coverage"), and
      their deploy is outside the kit (`MOD-OUTSIDE-KIT`).
- [ ] **Its data**: what classes of data it stores, processes or passes on, and to whom. A flow to
      another team's system is E4; a new kind of regulated data is E6.
- [ ] **Its exposure**: public, internal, partner-facing; which endpoints; does it sit behind a
      shared edge (Front Door, a gateway). Shared edge entries are the landing zone's (E1).
- [ ] **Its owners**: the app owner role, who approves releases at uat and prod, who can change the
      repository's workflows and environments. If one person is all of these, note it
      (`team_pattern`, `unvalidated_human_workflow_paths` in the gate's outputs).
- [ ] **Its third parties**: SaaS, external APIs, vendor actions or images it adds (E5 if new).
- [ ] **AI agents**: does any agent hold a token that writes to this repository, its tracker or its
      cloud target? If yes, E9.

## 2 · Is the kit actually wired, and at which pinned version?

- [ ] Open the app's workflow files. Find every `uses:` that names the kit, for example
      `<kit-owner>/<kit-repo>/.github/workflows/reusable-security.yml@<ref>`.
- [ ] Each `<ref>` is a **full 40-hex commit SHA**, never a branch or a tag (S9). The verdict is
      only as trustworthy as the code that produced it.
- [ ] All kit calls in the app use the **same** SHA, or the difference is explained.
- [ ] Open the organisation's copy of the kit (the repository those `uses:` lines name) and read
      `.neutral-export-watermark.json` at its root, if present:
  - `source_commit` — the kit source commit this copy received;
  - `profile` — which export profile the copy was taken under;
  - `exported_at_utc` — when;
  - `source_dirty` — must be `false`; `true` means the copy was exported from uncommitted changes;
  - `unresolved_conflicts` — must be empty; anything listed is a kit file the copy did not take.
  No watermark means you cannot tie the copy to a kit source commit: S9.
  **The run reads it too (KDEC-036 G9):** the gate's and every deploy's summary row "kit host copy"
  and the `kit_watermark` output give `WATERMARK_BOUND`, `WATERMARK_DIRTY`, `WATERMARK_ABSENT` or
  `WATERMARK_UNREADABLE`, the `source_commit`, and the kit repository and ref the reusable was called at:
  the pinned SHA is tied to the source commit in the run's own record.
- [ ] One security caller per repository: `templates/build-deploy.yml` **replaces**
      `templates/security.yml` (two callers run the suite twice and can disagree).
- [ ] The required check on the default branch is the caller job's `Security gate`
      (for example `security / Security gate`). The run's leak-gate record says whether that branch
      gate could be read (step 3).
- [ ] The app's own workflows pass `workflow-policy-check.yml` (rules R1–R9 in
      `docs/architecture/POLICY.md`) with `soft_fail: false` and `require_sha_pinning: true`.
      `trusted_orgs` (default `actions,github,azure,docker,hashicorp`) may use tags, not SHAs:
      note any owner added to that list.
- [ ] `test_only_seed_artifact` is empty in every non-test caller (S12).

## 3 · What the run summary says

Read the **security-gate** job's summary and outputs, and the **discover** job's summary.

- [ ] **The verdict**: `routing_result` is one of `PROCEED`, `PROCEED_WITH_ADVISORY`,
      `DECISION_REQUIRED`, `EVIDENCE_UNTRUSTED`, `BLOCKED`. If advisory, read `advisory_causes`.
- [ ] **Control posture**: `controls_required`, `controls_executed`, `controls_unavailable`,
      `controls_reduced`, `controls_skipped`. Every required control is either executed or named
      in one of the other lists. Any name in `controls_unavailable` or `controls_skipped`: S2/S3.
- [ ] **Weakenings**: `weakenings`, `weakening_attribution`, `weakening_record`. At baseline is
      `WEAKENING_AT_BASELINE`. Anything else: who is `weakening_authority`, is there a
      `weakening_exception_ref`, does `weakening_expires` exist and lie in the future (S4, S5).
      The kit now decides approval (KDEC-036, owner rulings 2026-11-03): `WEAKENING_ATTRIBUTED` only with an
      evidence reference, a reason, a named owner, an expiry within the ceiling (default 90 days) and an
      approver (`weakening_approver`) on a registered approver list who is not the requester;
      `WEAKENING_NOT_APPROVED` names the missing field (recorded at crawl, refused by a uat/prod deploy);
      `WEAKENING_SELF_APPROVED` (the requester, actor or release author as owner or approver) blocks
      everywhere. Team membership is not resolved by the kit (`OBTAIN-SEPARATELY.md`).
- [ ] **Leak gates**: `leak_gates` (each layer `ON`, `OFF` or `UNKNOWN`) and
      `leak_gate_weakenings`; the louder warning `NO_LEAK_GATE_SHOWN` in the summary. `UNKNOWN` is
      never `ON` (S1). Push protection off for want of a licence is E2.
- [ ] **Job token preflight** (discover summary, "Job token preflight" row; output
      `token_preflight`): `TOKEN_ACCEPTED` is the only clean answer. Any other word names its owner
      role (S17).
- [ ] **Platform capability** (discover summary): code scanning, secret scanning, Dependabot each
      `ENABLED`, `NOT_CONFIGURED`, `UNAVAILABLE` or unknown. `NOT_CONFIGURED` and `UNAVAILABLE` are
      platform actions, not developer actions (E2 if the cause is licensing).
- [ ] **Capability floor** (gate summary row "capability floor"; output `capability_floor`): `HELD`.
      `GAP_DECIDED` means a
      required scanner was removed under a dated decision (S10). `BREACHED` fails the gate.
- [ ] **Policy**: `policy_source` (`KIT_DEFAULT` = nobody registered anything: crawl, where only
      secrets, known-malicious packages, KEV-listed CVEs and untrusted scans block), `policy_resolution`
      (`POLICY_RESOLVED` or a refusal by name), `rung_declared` / `rung_effective`, `policy_chain`.
      A policy warning `ORG_UNMAPPED_RAN_AT_ENTERPRISE_FLOOR` or `ORG_UNMAPPED_RAN_AT_STRICTEST_ORG`
      means the org is not in the register's map (S11); the output `policy_notices` lists them.
- [ ] **Deploy coverage**: `no_kit_adapter` empty, or each `NO_KIT_ADAPTER:<kind>` reviewed under
      `MOD-OUTSIDE-KIT` (`aks`, `vm`, `function_app_code`; the evidence paths are in the record's
      `deploy_coverage`).

## 4 · Findings

- [ ] **The gate verdict**: `assurance_state` (what was established) and `enforcement_state`
      (`BLOCKED`, `ADVISORY`, `ALLOWED`) read together with `routing_result`.
- [ ] **Advisory vs blocking**: at crawl an ordinary finding routes `PROCEED_WITH_ADVISORY` with cause
      `FINDINGS_NOT_BLOCKED`. It is recorded, not cleared. Read the findings in `findings.json` inside
      the `evidence_artifact` (`security-report-<attempt>`), not only the Security tab, which may be
      unavailable without GHAS.
- [ ] **Secrets**: `secret_gate` is `PASS`, `EXCEPTED` or `FAIL`. `EXCEPTED` is never clean: each
      exception names one finding, a ticket, an approver and an expiry in the policy register
      (S13). A secret that reached the remote is compromised whatever the gate later does: rotation
      is owed; evidence of use is E7.
- [ ] **KEV**: `kev_state` `AVAILABLE` and `kev_verdict` `CLEAR`. `FINDING_KNOWN_EXPLOITED` blocks
      at every rung. `UNAVAILABLE` routes advisory (`KEV_UNAVAILABLE`), never a pass.
      `EXCEPTED` is an exception to read (S13).
- [ ] **Exceptions and their expiry**: open `.security/policy-registration.json` on the app's
      default branch (and the central `policy/policy-registration.json` in the kit copy). Every
      `secret_exceptions` and `known_exploited_exceptions` item has `finding`, `ticket`,
      `explanation`, `approver`, `expires`; renewals in `renews`. The gate summary says
      "first exception" or "previously excepted N time(s)". Near the cap
      (`max_exception_renewals`, default 2) is S5; raising the cap is E8.
- [ ] **Dispositions**: `.security/dispositions.json` on the protected default branch, under
      CODEOWNERS. A ticket closed in the tracker clears nothing; only a merged disposition does.
- [ ] The weekly `reusable-exception-due.yml` is wired, or nobody is raised when an exception comes
      due (it reports `NOT_CONFIGURED` without Jira credentials).

## 5 · Secrets and identities

- [ ] **OIDC only**: no client secret, no `azure/login` with `creds:` (rule R5). The `AZURE_*`
      values are identifiers held as environment variables or secrets, not credentials.
- [ ] **No long-lived keys** in the repository's secrets for cloud access. Optional ones the kit
      names: `SEMGREP_APP_TOKEN`, `NVD_API_KEY` (only if the datafeed is emptied), the tracker
      credential in a protected environment.
- [ ] **One federated credential per environment**, subject
      `repo:<owner>/<repo>:environment:<env>` (or the id-qualified form). `verify-azure-oidc.yml`
      run on this identity shows `verdict` `PASS` and sibling scopes `REFUSED`.
- [ ] **Least privilege**: the deploy identity holds `Website Contributor` (App Service) or
      `Container Apps Contributor` (Container Apps) on that app, `Reader` on its resource group, and
      nothing at subscription scope, nothing on another app, never `Owner` or
      `User Access Administrator`. The build identity holds `AcrPush` only. The app's own managed
      identity, not the deploy identity, holds `AcrPull`. Anything wider: E3.
- [ ] **Workflow permissions**: per job, `id-token: write` only where a job logs in; no
      workflow-level `id-token: write` (R3); `secrets: inherit` flagged (R8).

## 6 · Deploy path

Skip this section only if the app does not deploy through the kit, and say so at sign-off.

- [ ] The deploy is called with `routing_result: ${{ needs.security.outputs.routing_result }}` and
      `advisory_causes` from the same job, never a typed value (S8). The deploy now checks this
      itself (KDEC-036 G8): `VERDICT_FROM_GATE` is the clean answer; `MANUAL_REVIEW_VERDICT` is a manual
      AppSec review (read the reviewer, reference and date: it is not a scan); `TYPED_VERDICT` (no gate
      record, no valid manual review) and `VERDICT_RECORD_UNREADABLE` are refused at
      uat/prod and warned below; `VERDICT_CONTRADICTED` is refused at every tier. The build's
      `artifact_identity` is `REGISTRY_IDENTITY_PROVEN` (the starter template's `verdict` job checks
      it; a direct caller must).
- [ ] **Tier**: `KIT_ENVIRONMENT_TIER` on each environment matches reality. An environment serving
      real users labelled `dev` or `test` skips every uat/prod gate below (S6). The deploy records
      where the tier came from (`tier_source`: `TIER_VENDED` through the landing zone's hand-off, or
      `TIER_SELF_DECLARED`) and a reality signal (`tier_reality` `TIER_MISMATCH_SUSPECTED`: a custom
      domain, or public ingress at production-like scale, under dev/test; a warning, never a refusal).
- [ ] **Release gates before login** (deploy summary and outputs):
  - `release_block`: `RELEASE_NOT_BLOCKED` or `RELEASE_BLOCK_NOT_VENDED` (no landing zone writes one);
  - `environment_protection`: `ENVIRONMENT_PROTECTION_VERIFIED` at uat/prod;
  - `release_approval`: `RELEASE_APPROVAL_VERIFIED` at uat/prod — the approver is neither the
    requester nor the commit's author, and the approval comment quotes the digest. Below uat
    `RELEASE_APPROVAL_NOT_REQUIRED` is recorded, not a control (S6);
  - `promotion_gate` / `promotion_state`: uat and prod are promoted from a verified predecessor,
    never deployed from a fresh build.
- [ ] **Zone readiness and who issued it**: `zone_readiness` is `READY` or `READY_WITH_EXCEPTIONS`
      at uat/prod (`ZONE_READINESS_PERMITTED`). Owner ruling 2026-11-03: `KIT_ZONE_READINESS` is
      issued by the landing zone when the app is in a connected landing zone; otherwise AppSec
      issues it manually as a recorded attestation. **The app or deploy team never sets it for
      itself.** The zone step records `readiness_source`: `READINESS_SOURCE_LZ_HANDOFF`,
      `READINESS_SOURCE_APPSEC_ATTESTATION` (`.kit/zone-readiness.json`, merged through a pull request an
      AppSec approver who is not its author approved; `docs/adoption/ZONE_READINESS_ATTESTATION.md`), or
      a refusal at uat/prod (`READINESS_ATTESTATION_REFUSED`, `READINESS_SOURCE_SELF_SET_REFUSED`).
      `READINESS_SOURCE_TEST_FIXTURE` on an environment serving users is S7. Read the attestation file and
      its pull request; who wrote a variable is in the audit log (`OBTAIN-SEPARATELY.md`).
- [ ] **Lease and field ownership**: `KIT_TARGET_LEASE_ACCOUNT` set on the environment turns on the
      cross-repository lease, the `seam` step and the durable release record. Off, the deploy
      summary shows `SEAM_OWNERSHIP_NOT_IN_FORCE`: nothing stops a later platform apply from
      writing the release's image back, and nothing serialises the platform and the kit (S14, and
      E1 for the platform side). Outputs `lease_state` (`LEASE_NOT_IN_FORCE` when off) and
      `seam_state`; `release_approval_by` names the approvers the deploy read before login.
- [ ] **The durable release record**: `release_record` `RELEASE_RECORD_KEPT_DEPLOYMENT` (lease off: a
      GitHub deployment, id `release_record_ref`) or `RELEASE_RECORD_KEPT` (lease on: the lease store).
      `RELEASE_RECORD_NOT_KEPT` fails the deploy job: ask why (S16).
- [ ] **Rollback**: `rollback_on_failure` is `true` (the default); the deploy evidence artifact
      `deploy-evidence-<run_id>-<attempt>` holds `outcome.json`, `snapshot.json`, `manifest.json`,
      `capability.json`, `verification.json`, `reversal.json`. A reversal shown unavailable routes
      `EVIDENCE_UNTRUSTED`. `deployment_outcome` is not a workflow output; read it there.
- [ ] **The version-gap ruling**: one `version_gap_ruling` on every deploy. "not reported" in the
      summary is a pipeline fault, not "no gap".

## 7 · Supply chain

- [ ] **Pins**: the kit by SHA (step 2); the app's own third-party actions by SHA unless their
      owner is in `trusted_orgs`; deploys by `@sha256:` digest (R7).
- [ ] **SBOM**: the security run's `sbom` artifact (CycloneDX and SPDX, plus `licences.json`) and
      the build's `sbom_sha256`. `enable_sbom: false` is a weakening (S2). `license_deny` empty
      means inventory only: the licence policy is the app's to set.
- [ ] **Attestation**: the build's `attestation_url`; at deploy, V1 verification
      (`ATTESTATION_VERIFIED`). `ATTESTATION_HELD_BY_PLAN` on a private repository without the plan
      for it is a licensing fact (E2); `ATTESTATION_ABSENT` is a gap (S15);
      `ATTESTATION_CONTRADICTED` blocks and is E7 until explained.
- [ ] **Feeds**: if the organisation runs the feed mirrors, the summary shows `MIRROR_CURRENT`.
      `MIRROR_INTEGRITY_FAILED` is treated as an incident (E7). `MIRROR_FALLBACK_UPSTREAM` is an
      exception to the private-only rule and needs a recorded decision (S5).
- [ ] **Malicious packages**: the malicious-deps scan always runs; `enable_malicious_pkg_scan: false`
      is refused (`CHERRY_PICK_BELOW_FLOOR`).

## 8 · Evidence to keep

The kit's artifacts expire (30 days; the SBOM 90). Download what you relied on into the review record:

- [ ] the security run id and commit, and its `security-report-<attempt>` artifact (`findings.json`,
      per-scanner state files, redacted SARIF) and `kit-security-record-<attempt>` (every signal above,
      machine-readable);
- [ ] the gate job summary (verdict, posture, leak gates, capability floor, policy) and the
      `run_record` output;
- [ ] the discover job summary (job token preflight, platform capability, discovery rows);
- [ ] each deploy run id with its `deploy-evidence-<run_id>-<attempt>` (with `review-signals.json`) and
      `kit-promotion-record-<environment>` artifacts, and the durable deployment record's id;
- [ ] the kit copy's watermark and the app's `uses:` lines as read;
- [ ] the policy register files and the exceptions in force, with their tickets;
- [ ] the zone readiness issuer and attestation record (step 6);
- [ ] every stop-and-ask question with its answer, and every escalation with its hand-off note;
- [ ] what you obtained separately (`OBTAIN-SEPARATELY.md`), labelled Read or Stated.

Then write the sign-off: [`SIGN-OFF.md`](SIGN-OFF.md).
