# 08 · How the kit proves itself

## The proof rule

A control is proven only when four cases have been run **at the real enforcement point**: the allowed
case passes, the attack case is refused **for the stated reason**, missing evidence is refused, and
recovery works (`docs/PROOF_RULE.md`). "It compiles" is not proof; "a test exists" is not proof; a test
that passes when both sides are empty is not proof (landmine CP-013).

## How every fix is made

1. Write a proving test that **runs the shipped step** — the step's script is extracted from the workflow
   as shipped, its `${{ }}` inputs (and `env:`) substituted from the scenario, and run under bash with the
   **real tool** against seeded and clean fixtures.
2. Run it on the old code and watch it **FAIL for the named reason**.
3. Fix. Watch the same test PASS.
4. Wire it into `.github/workflows/self-test.yml` so CI runs it on every change.
5. One defect per commit, prefixed with its id.

**Measure the tool before designing against a description of it.** Two design assumptions turned out
false on measurement: gitleaks prints no byte count in the mode the kit uses, and Semgrep writes no
`level` on results. Both had shipped as code that could never fire.

## The proofs that exist (VERIFIED: all exit 0 at the change-log commit)

| area | proofs |
|---|---|
| gate and verdict | `prove_gate_routing.py` (21 scenarios), `prove_version_gap_production.py` (KDEC-014, both deploy adapters), `prove_deploy_gate.py`, `prove_bootstrap_failure.py` (toolchain/discovery/report failure blocks in every mode; image secrets block), `prove_gate_reads_findings.py`, `prove_report_counts_findings.py`, `prove_evidence_artifact_named.py` |
| secrets | `prove_secrets_always_block.py`, `prove_secret_denominator.py` |
| scanners | `prove_code_quality_enforces.py`, `prove_sast_java_detects.py`, `prove_image_scan_enforces.py`, `prove_sarif_effective_level.py`, `prove_hollow_scan.py` (wired into self-test since `fa19c02`), `prove_semgrep_strict.py`, `prove_codeql_build_outcome.py`, `prove_discovery_depth.py`, `prove_validate_scanners.py`; PHP (lane L-PHP): `prove_semgrep_php.py`, `prove_deps_scan_composer.py`, `prove_php_corpus.py` |
| report and redaction | `prove_report_runs_as_shipped.py`, `prove_redaction_chain.py`, `check_redaction_parity.py` |
| identity and ledger | `prove_identity_durability.py`, `prove_subject_covers_roster.py`, `prove_baseline_cascade.py`, `prove_ledger_read_authority.py`, `prove_propose_ledger.py`, `prove_propose_ledger_establishment.py`, `prove_propose_ledger_generation.py`, `prove_propose_ledger_ticket_ledger.py`, `prove_rule_family_upgrade.py`, `prove_lineage_durability.py`, `prove_lineage_integrity.py`, `prove_anchored_correlation.py` |
| supply chain | `prove_kit_script_digests.py`, `prove_pin_scope_covers_composites.py`, `check_pinned_artifacts.py` |
| ticketing | `prove_ticket_idempotency.py`, `prove_ticket_backends.py`, `prove_ticket_reconcile_workflow.py`; live: `live_ticketing_run.py` (personal Jira) |
| build and deploy | `prove_build_push_round_trip.py` (real local registry), `prove_push_capability.py`, `prove_deploy_outcome.py` (stub cloud, matrix A–E), `prove_deploy_posture.py`, `prove_reversal_disposition.py`, `prove_deploy_direct_to_production.py` |
| neutrality and export | `check_export_safety.py`, `prove_deny_samples.py` (every deny pattern has a sample it must match), `prove_export_scope.py`, `prove_census_outside_kit.py` |
| the assurance tracer | `scripts/trace_assurance_flow.py` (every producer-to-consumer hand-off guarded), `prove_trace_reads_env.py` |
| documents | `check_doc_currency.py` (prose may not call an observed capability untested; consumer documents may not set a dead input or claim secrets are softened in advisory mode) |
| the tests themselves | `prove_tests_leave_tree_clean.py` (every test in a throwaway clone; none may change a tracked file), `prove_digest_proof_spares_tmp.py` |

## The registries that refuse drift

| registry | checker | fails when |
|---|---|---|
| `assurance-taxonomy.yaml` | `scripts/reconcile_taxonomy.py` | code branches on an unregistered state word |
| `scanner-registry.yaml` | `check_scanner_registry.py` | a scanner job exists that the gate does not read, or vice versa |
| validation registry + deferrals | `reconcile_validation.py` | a capability has no proof and no dated deferral, or a deferral expired |
| weakening record | `check_weakening_record.py` | an input is unclassified or laundered as inert |
| stage maturity | `check_stage_phase.py` | a stage claims more maturity than its evidence — **not run by any workflow yet, and its register is stale** (completion ledger G-03, G-07) |
| neutrality | `check_export_safety.py` + `scripts/export-deny.txt` | the neutral core names an organisation, estate or person; since `c82b34f` it reads the deny list by the export gate's own rules (never-lift patterns were invisible to it) and refuses if the two pattern sets disagree; since `b352729` every pattern carries samples it must and must not match (`prove_deny_samples.py`) |
| assurance dataflow | `scripts/trace_assurance_flow.py` | a value is consumed with no producer (PHANTOM) or read with no absence check (UNGUARDED). Since `71a3d63` it reads `env:` mappings and `needs.*.outputs`, which took it from 31 to 120 traced hand-offs and found ten real defects, all fixed; composite actions' outputs and an ORPHAN check are declared limits |
| continuity | `check_context_current.py` | the kit's continuity record falls more than 10 commits behind — run locally before a push, not by any workflow yet (G-03) |

## Validation debt and deferrals

Every capability is either **observed** (proven on seeded input) or carries a **deferral** with four fields:
reason, owner (a role), what evidence closes it, and an expiry. An expired deferral is **BLOCKING** and is
answered by proof or a fresh dated decision — never by moving the date. The number of open deferrals is
capped by a **ratchet**, so new debt must retire old debt; the limit follows the debt down.

At trunk `078ef90` (VERIFIED, `reconcile_validation.py`): **0 BLOCKING, 3 deferrals, ratchet 3/3**, all expiring 2026-12-31 and all held on
something other than a probe: `attestation-verify` (the owner's plan offers no attestations on private
repositories), `change-detection` and `toolchain-terraform` (no consumer until the change-manifest and
Terraform assurance models are specified). Everything else is `observed`, including both deploy
adapters, the authorization boundary, context integrity, CodeQL and live Jira ticketing.

## Hosted runs (KDEC-006)

Local proof covers the step logic. What only a runner can show — that the workflow starts, that real job
results thread through, CodeQL, cross-repository `$/` resolution, attestation, deploy against a real
target — is proven by dispatching the trunk from the owner's **private consumer repository** after each
merged milestone. A cited run id, not a sentence, is the evidence.
