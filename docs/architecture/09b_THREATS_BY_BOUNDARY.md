# 09b · Threats by boundary (STRIDE)

```
Kept:      2026-11-07, against the trunk at c1420ea. Method, element matrix and summary: 09_THREAT_MODEL.md.
Columns:   id | STRIDE letters | threat | control | proof (a file in tests/ that exists) | state |
           residual | suggested mitigation. Every suggested mitigation is PROPOSED: a suggestion for the
           owner, never treated as done. "-" means no residual worth a mitigation was found.
States:    the ladder in 00_NOTATION_AND_LEGEND.md section 7. PL = PROVEN-LOCAL, B = BUILT, EN = ENFORCED.
```

## TB-1 · Consumer repository to the kit repository

| id | STRIDE | threat | control | proof | state | residual | suggested mitigation (PROPOSED) |
|---|---|---|---|---|---|---|---|
| TH-TB1-01 | T | a consumer pins the kit by branch or tag, so kit code changes under it | starters and kit init pin a 40-hex SHA; policy rule R1 refuses a moving ref; every branch-protection profile requires `policy / Workflow policy` | `tests/prove_workflow_policy_rules.py`, `tests/prove_kit_init.py`, `tests/check_branch_protection_profiles.py` | PL | a repository that applies no profile can merge an edited caller | the leak-gate posture, which already reads the branch's required checks, also records whether `policy / Workflow policy` is required |
| TH-TB1-02 | E | a caller grants a kit job more than it needs | each kit job declares its own permissions; kit templates grant exactly the union | `tests/check_caller_permissions.py` | PL | the check holds the kit's own templates, not a consumer's edited caller | a policy-check rule that compares a consumer's grants with the called workflow's requests |
| TH-TB1-03 | T E | caller input injected into a shell step | inputs reach scripts only as `env:` data; no expression in a deploy `run:` | `tests/lint_injection.py`, `tests/prove_deploy_inputs_via_env.py`, `tests/check_expression_length.py` | PL | static reading of shell text; a novel construct could pass | a proof that feeds quote, backtick and `$()` payloads into every reusable input through the step harness |
| TH-TB1-04 | E | `KIT_INIT_TOKEN` is wider or longer-lived than its job | the run's own token is `contents: read`; the checklist names the exact scopes | `tests/prove_kit_init.py` | PL | the kit cannot read a fine-grained token's scope | recommend a GitHub App installed on the one repository, or a token that expires within 7 days, in the checklist |
| TH-TB1-05 | T | an inlined kit script is swapped or drifts inside a run | the digest is pinned in `plan` and checked in every job; `inline_normalizer.py --check` | `tests/prove_kit_script_digests.py`, `tests/prove_plan_job.py` | PL | - | - |

## TB-2 · Pull-request content to a privileged context

| id | STRIDE | threat | control | proof | state | residual | suggested mitigation (PROPOSED) |
|---|---|---|---|---|---|---|---|
| TH-TB2-01 | E | fork PR code runs with a privileged token (the original threat model, T-01) | policy rule R4 refuses a `pull_request_target` head checkout; triage checks out nothing | `tests/prove_workflow_policy_rules.py`, `tests/prove_dependabot_triage.py` | PL | a real fork PR against the privileged path has not been run | a hosted fixture: a fork PR against a `pull_request_target` workflow in the test consumer, asserted not to execute |
| TH-TB2-02 | T | a PR chooses its own rung, ledger or dispositions | all read from the protected default branch | `tests/prove_gate_reads_rung.py`, `tests/prove_ledger_read_authority.py` | PL | - | - |
| TH-TB2-03 | S T | a PR that looks like Dependabot's is auto-merged | the PR author must be `dependabot[bot]`; every criterion; the scan gate must be required | `tests/prove_dependabot_triage.py`, `tests/prove_triage_job_permissions.py` | PL | the new version's provenance is `not_established` | check registry provenance (npm, PyPI attestations) where the ecosystem publishes it, and route a missing one to a person |
| TH-TB2-04 | I E | ticketing on a PR puts the tracker credential in reach | the guard refuses every PR event before the environment is requested | `tests/prove_ticket_reconcile_workflow.py`; hosted job `ticket-reconcile-refuses-pr` | PL, hosted | - | - |
| TH-TB2-05 | T | a test-only seed changes the scanned tree to hide a finding | seeds can only add files, staged outside the tree first | `tests/prove_test_only_seeds_add_only.py` | PL | - | - |

## TB-3 · Runner to cloud (OIDC)

| id | STRIDE | threat | control | proof | state | residual | suggested mitigation (PROPOSED) |
|---|---|---|---|---|---|---|---|
| TH-TB3-01 | S | a wider subject (branch, `pull_request`, wildcard) lets another workflow assume the identity | environment subject only; the verifier checks the token's own claims | `tests/prove_oidc_subject_forms.py`, `tests/prove_oidc_directory_checks.py` | PL | the kit sees only the identity it is asked to verify | a harness-side sweep of every federated credential in each tenant, with the tenant reader |
| TH-TB3-02 | E | the deploy identity holds roles beyond its app or its subscription | landing-zone contract; the verifier checks "one subscription" and no client secret | `tests/prove_oidc_directory_checks.py`, `tests/prove_context_integrity_refuses.py` | PL | checked only when someone dispatches the verifier | call `verify-azure-oidc.yml` on a schedule per environment |
| TH-TB3-03 | T | a call names a target or cloud other than the environment's | the bind step refuses before login | `tests/prove_deploy_environment_binding.py` | PL | - | - |
| TH-TB3-04 | E | a refusal comes after the identity was used | every refusal sits before the login step | `tests/prove_deploy_gate.py`, `tests/check_deploy_environment_declared.py` | EN (stage 15) | - | - |
| TH-TB3-05 | S D | the Government audience is wrong and sign-in fails or uses the wrong credential | the audience is chosen per cloud; an override for a global-audience credential | `tests/prove_azure_gov_audience.py` | PL | no live Government sign-in | one run on a Government sandbox, recorded in the evidence manifest |

## TB-4 · Runner to the GitHub API

| id | STRIDE | threat | control | proof | state | residual | suggested mitigation (PROPOSED) |
|---|---|---|---|---|---|---|---|
| TH-TB4-01 | I | the job token is sent to `api.github.com` from a GHE.com run | every call to `GITHUB_API_URL` (KDEC-027) | `tests/prove_github_token_stays_on_its_host.py`, `tests/prove_ghe_host.py` | PL | - | - |
| TH-TB4-02 | T | external text written into `$GITHUB_OUTPUT` or `$GITHUB_ENV` forges an output | sanitised writes only | `tests/check_output_writes.py` | PL | - | - |
| TH-TB4-03 | E | a job token wider than the job needs (the original threat model, T-03) | per-job permissions everywhere | `tests/check_caller_permissions.py`, `tests/prove_triage_job_permissions.py` | B | nothing has attempted a write outside a declared permission | a self-test job that attempts a write with a read-only token and asserts the refusal (the first ENFORCED test on this boundary) |
| TH-TB4-04 | D | a rejected token makes later steps skip silently | `JOB_TOKEN_REJECTED` named once, early, with an owner role | `tests/prove_job_token_named.py` | PL | - | - |

## TB-5 · Runner to tracker

| id | STRIDE | threat | control | proof | state | residual | suggested mitigation (PROPOSED) |
|---|---|---|---|---|---|---|---|
| TH-TB5-01 | I | the tracker credential is in reach of jobs that need none | one job per workflow holds it, from a protected environment | `tests/prove_ticket_reconcile_workflow.py`, `tests/prove_kit_api_workflow.py` | PL | - | - |
| TH-TB5-02 | T | a test run writes into a real project | the branch chooses; `JIRA_REAL_PROJECTS` refuses | `tests/prove_jira_auth_and_routing.py` | PL | - | - |
| TH-TB5-03 | T D | duplicate tickets flood a board | lookup before create; creation ceiling; idempotency | `tests/prove_ticket_idempotency.py`, `tests/prove_ticket_lifecycle.py` | PL; Jira live | - | - |
| TH-TB5-04 | S R | a forged stamp or `via` label claims a ticket | the full key is verified; provenance is the authenticated identity | `tests/prove_ticket_governance.py` | PL | - | - |
| TH-TB5-05 | T | a person's tags are lost to a concurrent kit write | Freshservice markers are notes; tag mode locks, re-reads and reconciles | `tests/prove_freshservice_tracker.py` | PL | - | - |
| TH-TB5-06 | I | a ticket shows more than the repository's readers may see | findings redacted; secrets as a fingerprint | `tests/prove_redaction_chain.py`, `tests/prove_sast_secret_tickets.py` | PL | a tracker project may be readable by more people than the repository | route `class: secret` to a restricted project in the example register |
| TH-TB5-07 | E | a fixer closes their own ticket | closure by another person or a rescan | `tests/prove_ticket_lifecycle.py` | PL | closure by rescan not yet run on a default branch that keeps the ledger | include it in the next hosted ticketing run |

## TB-6 · Scanner supply chain and data feeds

| id | STRIDE | threat | control | proof | state | residual | suggested mitigation (PROPOSED) |
|---|---|---|---|---|---|---|---|
| TH-TB6-01 | T | a tampered tool binary | exact versions; `sha256sum -c` on downloads | `tests/check_pinned_installs.py` | PL | its declared scope excludes the secret-scan (detect-secrets) and code-quality (ruff, mypy) installs | pin those versions and bring the jobs into scope |
| TH-TB6-02 | D | a scanner that acquired nothing reports clean (T-04) | `DEPENDENCY_ACQUISITION_UNAVAILABLE`; never zero | `tests/prove_hollow_scan.py`, `tests/prove_scan_status_zero.py` | PL | - | - |
| TH-TB6-03 | T D | a stale or altered mirror | used only when current and every file matches the manifest | `tests/prove_feed_mirror.py`, `tests/prove_feed_mirror_gaps.py` | PL | the mirror has not run live | a live refresh and read on the personal sandbox |
| TH-TB6-04 | D | an unreadable KEV catalog reads as clear | `KEV_UNAVAILABLE` routes advisory, never PROCEED | `tests/prove_known_exploited.py` | PL | - | - |
| TH-TB6-05 | T | a PR deletes a scanner's registry row and the gate stops expecting it | the capability floor, kit-owned, shrinks only by tombstone | `tests/prove_capability_floor.py` | PL | - | - |
| TH-TB6-06 | D | in-step tools and rule sets age silently (T-06) | Dependabot keeps pinned actions current | `tests/prove_dependabot_bump_mergeable.py` | partial | tool binaries and rule sets in steps have no currency check | a scheduled currency inventory: each pinned tool against its latest release, warn not fail |
| TH-TB6-07 | D | a scanner cannot read the stack's version (T-05) | version gaps declared before the scan; PASS capped | `tests/test_resolve.py`, `tests/prove_version_gap_production.py` | PL | an UNVERIFIED range does not refuse at uat/prod | seed a corpus per declared range so each range becomes READ |

## TB-7 · Environment approval gate

| id | STRIDE | threat | control | proof | state | residual | suggested mitigation (PROPOSED) |
|---|---|---|---|---|---|---|---|
| TH-TB7-01 | E | a person approves their own uat/prod release | not the requester, not the author | `tests/prove_release_gates.py`, `tests/prove_uat_prod_gating.py` | PL | - | - |
| TH-TB7-02 | E | an environment with no reviewers or allowing self-review | protection read back before login | `tests/prove_deploy_environment_protection.py` | PL | - | - |
| TH-TB7-03 | E | the app team approves its own release | pools and app-team checks | `tests/prove_uat_prod_gating.py` | PL | membership the kit cannot read is NOT_ESTABLISHED; the decision rests on the rules | give the deploy a members:read token (as the API has `KIT_API_TEAM_READ_TOKEN`) |
| TH-TB7-04 | T | the approval is not bound to what is released | the comment must quote the digest | `tests/prove_release_gates.py` | PL | - | - |
| TH-TB7-05 | E | an administrator bypass releases with no approval | `RELEASE_APPROVAL_ABSENT` | `tests/prove_release_gates.py` | PL | - | - |
| TH-TB7-06 | E | an environment renamed or unclassed to dodge the gate | the strongest of tier, class and name; `ENVIRONMENT_UNCLASSED` refused | `tests/prove_uat_prod_gating.py` | PL | - | - |

## TB-8 · Artifact identity

| id | STRIDE | threat | control | proof | state | residual | suggested mitigation (PROPOSED) |
|---|---|---|---|---|---|---|---|
| TH-TB8-01 | T | the bytes deployed are not the bytes scanned (T-07) | build once; identity proven; digest only | `tests/check_artifact_identity.py`, `tests/prove_composite_build_once.py`, `tests/prove_build_push_round_trip.py` | PL; deploy EN | - | - |
| TH-TB8-02 | S | an artifact not signed by the kit's build | V1 before login | `tests/prove_attestation_verify.py`, `tests/prove_deploy_attestation.py` | PL | V1 is HELD on a private plan without attestations | sign to the registry where GitHub attestations are unavailable, and verify that at V1 |
| TH-TB8-03 | T | a revoked or expired digest is promoted | the promotion gate: predecessor, 14 days, revocations, re-scan | `tests/prove_promotion.py` | PL | - | - |
| TH-TB8-04 | T R | a typed verdict replaces the gate's | verdict provenance; manual review attributed | `tests/prove_reviewer_signals.py` | PL | - | - |

## TB-9 · Public mirror

| id | STRIDE | threat | control | proof | state | residual | suggested mitigation (PROPOSED) |
|---|---|---|---|---|---|---|---|
| TH-TB9-01 | I | a name reaches the public copy | the deny list, each pattern with a sample; checked every self-test | `tests/check_export_safety.py`, `tests/prove_deny_samples.py` | PL | the list is only as good as its last update | `tests/check_custody.py` requires a deny pattern for every overlay directory's name |
| TH-TB9-02 | I | git history carries what a file no longer does | a fresh tree with no history | `tests/prove_export_scope.py` | PL | - | - |
| TH-TB9-03 | T | an invisible control byte makes a pattern match nothing | source hygiene; samples prove each pattern | `tests/check_source_hygiene.py`, `tests/prove_deny_samples.py` | PL | - | - |

## TB-10 · Overlay, central register and consumer settings

| id | STRIDE | threat | control | proof | state | residual | suggested mitigation (PROPOSED) |
|---|---|---|---|---|---|---|---|
| TH-TB10-01 | E T | a repository softens below its authority's floor | the top authority's rung is the floor; crawl is absolute | `tests/prove_authority_floor.py`, `tests/prove_crawl_floor.py` | PL | - | - |
| TH-TB10-02 | T D | an unreadable register is taken as the default | `REGISTRATION_UNAVAILABLE`, `EVIDENCE_UNTRUSTED` | `tests/prove_policy_registration.py` | PL | - | - |
| TH-TB10-03 | R E | a weakening approved by its requester | five fields; `WEAKENING_SELF_APPROVED` blocks | `tests/prove_reviewer_signals.py`, `tests/check_weakening_record.py` | PL | - | - |
| TH-TB10-04 | T | an overlay relaxes a core rule | the one-way custody rule | `tests/check_custody.py` | PL | "adds, never relaxes" is not checked for an overlay's pipeline | a proof per overlay that its template calls the core gate with no weakening input |
| TH-TB10-05 | R | exceptions renewed without end | resurfacing with history; a renewal cap | `tests/prove_exception_due.py`, `tests/prove_exception_lifecycle.py` | PL | - | - |

## TB-11 · Evidence harness

| id | STRIDE | threat | control | proof | state | residual | suggested mitigation (PROPOSED) |
|---|---|---|---|---|---|---|---|
| TH-TB11-01 | I | the export carries free text, a secret or an email | allowlist copy; pseudonyms | `tests/prove_evidence_export.py` | PL | - | - |
| TH-TB11-02 | T | the folder is altered between download and the harness | `export_sha256` binds the answer | `tests/prove_evidence_export.py` | PL | the transfer is by hand; the harness must check the hash | the harness verifies `export_sha256` and refuses a mismatch (harness-side) |
| TH-TB11-03 | R | evidence expires before an audit asks for it | 90-day floor on the report and deploy records; durable release records | `tests/prove_release_record_store.py` | PL | SARIF, build evidence and ticketing run records are kept 30 days | set those uploads to `KIT_EVIDENCE_RETENTION_DAYS` |

## TB-12 · Outside caller to the kit API

| id | STRIDE | threat | control | proof | state | residual | suggested mitigation (PROPOSED) |
|---|---|---|---|---|---|---|---|
| TH-TB12-01 | S E | anyone with Actions write on the repository calls a write | writes off unless named; idempotency key | `tests/prove_kit_api_server.py` | PL; refusals hosted | any holder of Actions write may call an enabled write | an allowlist of caller identities checked at intake |
| TH-TB12-02 | E | the caller approves its own release | the caller is the run's actor; the approval refuses the requester | `tests/prove_kit_api_workflow.py`, `tests/prove_release_gates.py` | PL | - | - |
| TH-TB12-03 | T | a write is replayed | the idempotency key is recorded | `tests/prove_kit_api_server.py` | PL | - | - |
| TH-TB12-04 | S | the caller reads another call's result | the run and check run are named by the correlation id | `tests/prove_dispatch_correlation.py` | PL | - | - |

## TB-13 · External finding sources

| id | STRIDE | threat | control | proof | state | residual | suggested mitigation (PROPOSED) |
|---|---|---|---|---|---|---|---|
| TH-TB13-01 | T S | poisoned external findings create tickets | template validation; a finalized, concurred review; SoD | `tests/prove_external_findings_pull.py`, `tests/prove_ticket_templates.py` | PL | - | - |
| TH-TB13-02 | I E | a vendor token that can write | the pull never writes to the vendor | `tests/prove_external_findings_workflow.py` | PL | the kit cannot see the vendor token's scope | the pull records the scope where the vendor's API reports it, and the checklist asks for a read-only token |

## TB-14 · Shared deploy target

| id | STRIDE | threat | control | proof | state | residual | suggested mitigation (PROPOSED) |
|---|---|---|---|---|---|---|---|
| TH-TB14-01 | T | the kit overwrites a landing-zone-owned setting | field ownership at the seam | `tests/prove_seam_setting_ownership.py` | PL; opt-in | off until KDEC-030 is ruled on | rule on KDEC-030 O-1 |
| TH-TB14-02 | T D | two writers mutate one target at once | the lease's fencing token; deploys queue | `tests/prove_target_lease_crossrepo.py`, `tests/prove_deploy_concurrency.py` | PL | not run against real Azure Storage | a live lease run on the personal sandbox |
| TH-TB14-03 | D | a rollback causes the larger outage | preconditions on live state; human decision | `tests/prove_reversal_disposition.py`, `tests/check_reversal_preconditions.py`, `tests/prove_rollback_sequence.py` | own change EN; sequence PL | a sequence not yet run live | one live two-step sequential rollback on the sandbox |
