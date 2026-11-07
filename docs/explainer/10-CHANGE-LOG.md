# 10 · Change log

Newest first. On every later delivery, read this file first: it says which parts changed and why.
Commit ids are on the build trunk `fix/normalization-and-discovery`. Versions 1.12 to the 2026-10-28
entries are in `10a-CHANGE-LOG-OCTOBER.md`; 1.11 and earlier in `10b-CHANGE-LOG-EARLIER.md`. A reader whose last copy was v1.10 (`a907dc8`) reads
`12-CHANGES-SINCE-A907DC8.md` first: it groups every change since by what an integrator must do.

## Unreleased — adoption without "a million hoops" (KDEC-041 PROPOSED, 2026-11-06)

Proven locally (`prove_kit_init.py`, `prove_plain_errors.py`, `prove_friction_summary.py`, `prove_adoption_guides.py` R1/N4; 13 mutants killed). No hosted run yet.

| change | parts affected |
|---|---|
| `kit init` (`scripts/kit_init.py`; the button `templates/kit-init.yml` + `.github/actions/kit-init`): detects the stacks and deploy shape, writes the pinned callers with exact permissions, `dependabot.yml`, a CODEOWNERS block, the environments spec and a settings stub, opens one PR whose body is the person-only checklist; never guesses, never writes a secret, keeps a person's edits | 11 |
| `templates/build-deploy-static.yml`: the static-site caller (package by content digest, attest, dev/test on merge, promote to uat/prod) | 07, 11 |
| The plain-English error layer: `docs/errors/ERRORS.md` (from `errors.json`), every refusal in the taxonomy said in plain words with the fix; the gate, deploys, ticketing, triage, API and OIDC preflight annotate each refusal with the plain sentence first; `kit_init_state` registered | 03, 06, 07, 11 |
| `docs/adoption/GETTING_STARTED_1_HOUR.md`, `ROLLOUT_PLAN.md` (waves, report-only weeks, same-day approver SLA with a backup, never auto-approval), the pilot friction log and `scripts/friction_summary.py` | 11 |

## Unreleased — the consumer experience (KDEC-040 PROPOSED, 2026-11-06)

Local battery `tools/battery.sh`/`.ps1` (08); positive controls and their matrix (08); keep-current
rebases behind Dependabot PRs, `dependabot_config.py` and its PR check, auto-merge risks and rulesets (11);
SonarQube/Aikido intake and ONE id normaliser, `finding_ids.py` (06, 11); `verify-azure-oidc` gov and
directory checks (07); Release 4 in the consumer path, runs paired by correlation id (08, 11); suggested
mitigations in every register (09). Details: `.context/products/secure-cicd-kit/current-state.md`.

## Unreleased — instructions audit; architecture diagrams (2026-11-06)

Documents only: no gate, output or state word changed.

| change | parts affected |
|---|---|
| New `docs/architecture/README.md` and the ARCH-01 to ARCH-07 documents: the pipeline end to end, identities and trust, ticketing, the kit API, the Dependabot triage, the evidence into the harness's per-app bundle, commercial vs Government, as Mermaid, each citing the files it draws | 07, 11 |
| The caller-permission table gains the kit API and the Dependabot triage | 11 |
| `docs/adoption/SETUP.md`: the Jira host as a secret (and the variable the reference check still needs), the GHE.com OIDC issuer, the deploy and kit-api caller permissions, the build's required inputs; `USAGE.md`'s table lists every reusable | 11 |

## Unreleased — SAST and secret tickets; evidence.export (KDEC-038, KDEC-039, 2026-11-06)

Proven locally (`prove_sast_secret_tickets.py`, `prove_evidence_export.py`; each failed first, 11 mutants killed).

| change | parts affected |
|---|---|
| bandit, semgrep and CodeQL findings keyed: a curated rule-family table (`RULE_FAMILY_UNKNOWN` by name, never a guess) and a code location read from the checked-out commit (symbol, normalised line + ordinal; D-8 closed in code); one ticket per issue across tools | 04, 06 |
| Secrets ticketed on a non-reversible fingerprint taken before redaction: urgent, ROTATE, never closed on absence; routing matches `rule_family`, `cwe` | 06, 11 |
| `evidence.export`: the kit's half of the per-app evidence bundle, each section or NOT ESTABLISHED; **API callers grant `deployments: read`** | 11 |
| The security record carries the KEV verdict, the SBOM digest, the commit author (pseudonym + verification) | 03, 11 |

## Unreleased — the security review sheets made cloud-agnostic (2026-11-04)

Owner, 2026-11-04: the cloud checklists must work in Azure or AWS, cloud-agnostic, as the security review
was meant to be. Documents only: no gate, output or state word changed.

| change | parts affected |
|---|---|
| New `docs/security-review/CLOUD-CHECKS.md`: C0..C20, each check stated once by intent (safe / ask / stop), an implementation table (Azure, AWS, GitHub, other cloud: how to find the equivalent) and every command unchanged; every old id Z1..Z14, W1..W12, H1..H8 kept as an alias; the three platform sheets are now pointers | 11 |
| `CAB-CHANGE-SAFETY-STEPS.md` step 4 and the checklist's block D by intent with per-platform tables; the Azure Government line replaced by a generic sovereign or government cloud note; modules, APP-REVIEW-CHECKLIST, QUESTIONS-FOR-APP-TEAMS, STOP-AND-ASK (new S18: a cloud the sheets do not name) and ESCALATE-BROADER worded for any cloud; the kit's Azure-only deploy stated as such (`MOD-OUTSIDE-KIT`) | 11 |

## Unreleased — ticket intake version 2: the owner's rulings (KDEC-037 amended, 2026-11-04)

Proven locally (`prove_ticket_intake_v2.py` V1..V11, failed first; 20 mutants killed) and live on the
owner's personal Jira and GitHub Issues (Azure DevOps owed: the local token is rejected). `template_version`
1 is refused as superseded.

| change | parts affected |
|---|---|
| **Separation of duties**: no author role concurs or verifies; AGREE or DISAGREE with an alternative (`kit-review-record/2`); `SOD_SELF_APPROVAL` | 06, 11 |
| **Approvers**: the whole security team, `list:<name>` in the same `approver_lists` as KDEC-036's AppSec list, or `team:<org>/<slug>` (optional secret `KIT_API_TEAM_READ_TOKEN`) | 11 |
| **Closure**: resolve (pending verification, approvers notified, reminded at 7 days, escalated at 14), verify (not the fixer, or the rescan on the mapped branch; else "fix observed"), reject; `KIT_API_BRANCH_ENVIRONMENTS` | 06, 11 |
| **Dedupe**: closed duplicate under the original, regression, possible duplicate in triage, dedupe pending, durable outbox (`kit-ticket-outbox-<id>` artifact) | 06, 11 |
| **Trust score** beside the confidence, on the ticket and in the API | 06, 11 |
| **Taxonomy**: `exception` (≤ 90 days, scoped), `exemption`, `accepted-risk`, `compliance-exception`; the reconciler's exception mapping fixed; extensions and the no-fix clock per the owner | 06, 11 |
| **Intake**: Azure DevOps and GitHub Issues adapters; 14 proposed ticket types, disabled (`docs/ticketing/TICKET-TYPES.md`) | 11 |

## Unreleased — what a reviewer could not see, recorded; typed verdicts refused (KDEC-036 PROPOSED, 2026-11-03)

The security-review lane's gaps (`docs/security-review/`): signals a reviewer needs that the kit did not
compute or kept only in a job summary. Proven locally, each proof failed first
(`prove_reviewer_signals.py` R1..R8, 72 failures on `4a181ff`); no hosted run yet. No new job and no new
required check name.

| change | parts affected |
|---|---|
| **Weakening records approved or not (G2, G3; owner rulings 2026-11-03).** Approved (`WEAKENING_ATTRIBUTED`) only with an evidence reference, a reason, a named owner, an expiry within the ceiling (default 90 days) and an approver (new input `weakening_approver`) on a register approver list who is not the requester; a missing field is `WEAKENING_NOT_APPROVED`, named (proceeds at crawl, the control still counted weakened; refused at uat/prod); the requester, actor or release author as owner or approver is `WEAKENING_SELF_APPROVED`, BLOCKED everywhere. No exception without an expiry (KNOWN_DEFECTS D-14) | 03, 05, 07 |
| **The verdict's provenance (G8).** A deploy reads the `kit-security-record` of the run its verdict came from (this run, the promotion source, or the new input `security_run_id`): `VERDICT_FROM_GATE`; `TYPED_VERDICT` (refused at uat/prod); `VERDICT_CONTRADICTED` (more permissive, a dropped cause, another commit: refused at every tier); `VERDICT_RECORD_UNREADABLE` | 03, 07, 11 |
| **Signals as outputs and a machine-readable record (G5).** Security outputs `capability_floor`, `token_preflight`, `leak_gate_alarm`, `policy_notices`, `no_kit_adapter`, `kit_watermark`, `security_record`, and the artifact `kit-security-record-<attempt>`; each deploy outputs `release_approval_by`, `verdict_provenance`, `tier_source`, `readiness_source`, `tier_reality`, `release_record`, `lease_state`, `seam_state`, `review_signals` and keeps `review-pre.json` / `review-signals.json` in its evidence | 03, 07, 11 |
| **Durable release record without the lease (G6).** A GitHub deployment (`task: kit-release-record`, the record as payload) and its status; **every deploy caller must now grant `deployments: write`**. Evidence retention is `KIT_EVIDENCE_RETENTION_DAYS`, never below the 90-day audit floor | 07, 11 |
| **The kit copy's watermark read at run time (G9)**: `source_commit`, profile, dirty, conflicts, beside the called kit ref, in every gate and deploy summary and record | 02, 11 |
| **Tier source (G4) and readiness (G1, owner ruling 2026-11-03).** `TIER_VENDED` / `TIER_SELF_DECLARED` (the landing zone's new hand-off marker `KIT_HANDOFF_ISSUER`); `TIER_MISMATCH_SUSPECTED` (warn only). Readiness comes from the landing zone, or from AppSec's attestation `.kit/zone-readiness.json` approved through a pull request by the AppSec list (`READINESS_SOURCE_APPSEC_ATTESTATION`); self-set is refused at uat/prod unless labelled a test fixture. **Deploy callers now also grant `pull-requests: read`** | 07, 11 |
| **Manual review verdicts (G8, owner ruling).** A typed `routing_result` with `manual_review_by` (AppSec list, not the requester or author), `manual_review_ref` and `manual_review_date` is `MANUAL_REVIEW_VERDICT`, recorded distinctly; any other typed verdict is `TYPED_VERDICT` | 07, 11 |
| **Deploy coverage and Functions (G10).** Discovery names `NO_KIT_ADAPTER:aks`, `:vm`, `:function_app_code`; a vended `KIT_HOSTING_KIND` the adapter does not serve is refused. The App Service reusable releases a containerised Functions app with `site_kind: functionapp` (`az functionapp`); a code-packaged one is refused before any change. AKS, VM and Functions-zip adapters are sized in `KNOWN_DEFECTS.md` D-13 | 07, 09, 11 |
| `docs/security-review/`: every sheet names the new signal where a gap closed; new `OBTAIN-SEPARATELY.md` (G7 admin-only settings, G11 automation runtime: what to obtain, from which role) | 11 |
| Change log split: v1.11 to the 2026-10-23 entries moved to `10a-CHANGE-LOG-OCTOBER.md` (this file was over 20 KB) | 00, 10 |

## Unreleased — the security review of a CAB change to cloud or apps: steps and checklist (2026-11-03)

Owner, 2026-11-03: CAB already exists, is well run and has its own tickets and process; what is needed
is the security review a reviewer performs on a change going to CAB (cloud and apps), with a checklist,
"to stop people from saying work security reviewed when they don't understand what they are reviewing
and when to ask questions and when to stop for a larger conversation". Documents only: no gate or
enforcement changed; nothing here defines CAB. Authored, not field-tested.

| change | parts affected |
|---|---|
| New `docs/security-review/CAB-CHANGE-SAFETY-STEPS.md`: six valid outcomes (approve, with conditions, reject, needs more info, "not reviewed — outside my knowledge, routed to <role>", "paused — broader conversation opened"); eight steps (the understanding gate; boundary triage over data, security, auth and exposure rows deciding full or delta review; app checks from the run summary; cloud checks; pipeline and evidence; rollback; decide by written criteria; the security verdict written onto the existing CAB ticket), the app and cloud checks written as guided conversations (the question in plain words, why we ask, what a good answer sounds like, what to worry about, where to then check it in the run summary, Azure, AWS or GitHub), with inline stop-and-ask and broader-conversation triggers; a tick counts only with its source; the emergency retrospective within 5 working days (OWNER DECISION, default) | 11 |
| New `CAB-CHANGE-REVIEW-CHECKLIST.md` (one per change, mirrors the steps; header fields, understanding gate, triage box, app / Azure / AWS / GitHub / pipeline / rollback blocks with sources, triggers, "signs you're rubber-stamping", outcome and conditions with owner and expiry, a sign-off attesting understanding by role, AppSec as the required reviewer, the paste block for the CAB ticket; a bare "security reviewed" or "LGTM" is not a sign-off) | 11 |
| New read-only cloud sheets `CLOUD-CHECKS-AZURE.md` (Z1..Z14: portal path, `az` and Graph), `CLOUD-CHECKS-AWS.md` (W1..W12: console path, `aws`), `CLOUD-CHECKS-GITHUB.md` (H1..H8: `gh api`) | 11 |
| New `EARLY-REVIEW-REQUESTS.md` (pulled in before the CAB presentation: what the reviewer asks for, early guidance only, the note recorded on the ticket, when to stop for a broader conversation) and `PRINCIPLES-AND-SOURCES.md` (eight principles mapped to the checks; OWASP ASVS and Top 10, NIST SP 800-53 CM-3/CM-4/AC-6/AU, NIST SSDF, CIS, MCSB, AWS Well-Architected, ITIL 4; 24 common gotchas with the check that catches each) | 11 |
| `CAB-AND-ADOPTION-REVIEW.md` kept as the adoption path, its step 3 now the boundary triage; README, APPROVAL-MATRIX, MOD-EMERGENCY-CHANGE, MOD-IAC, MOD-DATA, MOD-API, MOD-WEB, MOD-THIRD-PARTY and USAGE point to the review; `scripts/reconcile_taxonomy.py` classifies three AWS enum values the AWS sheet quotes as somebody else's identifiers | 08, 11 |

## Unreleased — ticket templates and external findings, behind a finalized human review (KDEC-037, 2026-11-03)

Owner, 2026-11-03, amending KDEC-035: external findings are accepted through templates (O-35f), and
Tines writes tickets through the API only after her recorded concurrence with the finalized review
(O-35g); every ticket, manual ones included, is looked at before one is created. Proven locally
(`prove_ticket_templates.py` T1..T10, T5b: 70 checks failed first; ten mutants killed); no hosted or
live call yet.

| change | parts affected |
|---|---|
| **`tickets.submit`**: versioned templates (`api/v1/tickets/`) -- finding, four compliance REQUESTS, extension, no-fix re-check, closure -- each with required fields and named refusals (`ticket_template_refusal`); routed by template, source type and environment | 06, 11 |
| **The finalize gate** (`scripts/review_finalize.py`): a FINALIZED record on the default branch, bound to the call's evidence-set hash, concurred by an approver who is not the automation and who APPROVED the record's pull request (read back) -- else `API_REVIEW_NOT_FINALIZED`, nothing touched | 06, 11 |
| **External findings** normalised with provenance and an asset identity scheme (repo path, Azure tenant/subscription/resource, AWS account/region/ARN, GitHub org/repo, engagement); two tools on one asset and identifier are one ticket | 06 |
| **Dedupe against every ticket** (`scripts/ticket_intake.py`): stamp or correlation-key label is exact; asset + identifier or a close title is a candidate for a person, never merged; a partial search creates nothing. **Tracker intake**: `tickets.search` `tracker_query` pages manual and kit tickets (Jira; FreshService a seam) | 06, 11 |
| **Closure** only verified (kit scan or the approved reviewer), never by the requester or fixer; **extensions** counted from the ticket's labels and capped; the **no-fix re-check** reopens as remediation when a fix ships, and the clock raises a due re-check once | 06 |
| **Corroboration score** (`finding_correlation.corroboration_score`), deterministic 0..100 with its derivation, beside the tier | 03, 06 |
| Tagging proposal for the owner: `docs/ticketing/TAGGING-STRATEGY-PROPOSAL.md` | 06 |

## Unreleased — security review sheets for reviewers, CAB and adoption (2026-11-03)

Owner requests 2026-11-03 (a checklist and small helper sheets for a security team reviewing an app;
the approval path for CAB changes and adoption of internally built apps) and the owner ruling
refining O-34a. Documents only: no code, no gate, no enforcement changed. Authored, not field-tested.

| change | parts affected |
|---|---|
| New `docs/security-review/`: README, the app review checklist (scope, kit pin and watermark, run summary, findings, identities, deploy path, supply chain, evidence), stop-and-ask (S1..S17), escalate (E1..E10, by role), reading the run summary, questions for app teams, sign-off with claim labels; the CAB and adoption selector, the approval matrix and fourteen one-page modules under `modules/`. Pointer from `docs/adoption/USAGE.md` | 11 |
| `KIT_ZONE_READINESS` is issued by the landing zone when connected, otherwise by AppSec as a recorded attestation; never set by the app or deploy team. USAGE, SETUP and the hand-off contract keep `fb3f0a1`'s TEST FIXTURE ONLY label and now name the issuer in place of "owner decision, still open". The kit still records only the value, not its issuer (a stated gap) | 07, 11 |
| `tests/check_doc_currency.py` reads `docs/security-review/**` as consumer documents | 08 |

## Unreleased — the kit's API, v1 (KDEC-035 PROPOSED, 2026-11-03)

Owner: an API "for other products/programs to use secure cicd kit ... so tines can use it to deploy
products and write tickets from its workflows on 3B". Proven locally, each proof failed first
(`prove_kit_api_client.py` K1..K9, `prove_kit_api_server.py` S1..S8, `prove_kit_api_workflow.py`
W1..W8); no hosted or live call yet. The contract and every operation: `docs/api/README.md`.

| change | parts affected |
|---|---|
| **A call is a dispatch of the repository's `kit-api.yml`** (`templates/kit-api.yml`) with a v1 request (`api/v1/`); the answer is the check run `kit-api/<correlation id>`, the summary and an artifact. States `kit_api_state`, 25 named refusals `kit_api_refusal`. Client `scripts/kit_api.py`; never assumes a host; the token stays on it | 11 |
| **Tickets through the reconciler**: write, comment, get, search -- one ticket per finding across the API and the pipeline (shared stamp, ledger and a shared concurrency group with `reusable-ticket-reconcile.yml`'s reconcile and resurface jobs); only findings a default-branch run established; closes nothing; no disposition or transition | 06, 11 |
| **Findings read and search** from a run's `findings.json`, with KEV (`UNAVAILABLE`, never false) and the ticket binding | 06, 11 |
| **A release is the repository's own `build-deploy.yml`, called** (it gains `workflow_call`): every gate applies and the caller is the requester; the API also refuses an environment without a human approver, rollback and break-glass | 07, 11 |
| `tests/check_caller_permissions.py` resolves a template's `./.github/workflows/<f>` to the starter beside it | 08 |

## Unreleased — a rejected job token is named once; the host is always written (D-11, 2026-11-02)

From the owner's GHE.com work copy: every API call answered 401 "Bad credentials" and five steps said
so five ways, none naming the cause (the runs were a pre-KDEC-027 revision). Proven locally, each
failed first (`prove_job_token_named.py` T1..T8, `prove_ghe_host.py` H8/H9, `check_action_pins.py`
P7); no hosted run yet.

| change | parts affected |
|---|---|
| Job token preflight in the discover job: `token_preflight` = `JOB_TOKEN_REJECTED`, `ORG_IP_ALLOW_LIST_BLOCKS_RUNNER`, `ORG_SSO_BLOCKS_TOKEN`, `RATE_LIMITED`, `API_UNREACHABLE` or `TOKEN_ACCEPTED`, with owner role and checklist in the summary; resolve, the consumer path and the pin checkers report the same word | 02, 03 |
| `GH_REPO` and `-R`/`--repo` always `HOST/OWNER/REPO`; attestation verify passes `--hostname` | 07, 11 |
| Dependabot entries only where a manifest is (no more `dependency_file_not_found` at `/`) | 08 |
| The self-test tools install Trivy as the pinned, sha256-verified binary (not `install.sh`) | 08 |

