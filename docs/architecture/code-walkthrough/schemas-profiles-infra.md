# Code walkthrough: schemas/, profiles/, infra/

```
Kept:      generated 2026-11-07 against the trunk; the file list is mechanical (git ls-files), the
           descriptions were written by reading each file. tests/check_code_walkthrough_coverage.py
           fails when a tracked file has no row here, or a row names a file that is gone.
Columns:   "called by" = files that run, import, inline or `uses:` it; "proved by" = tests that name it.
           Both are computed by text search, so they can over-count a mention as a use.
```

[Back to the walkthrough index](README.md)

18 files.

| file | what it does | called by | inputs and outputs | proved by |
|---|---|---|---|---|
| `infra/feed-mirrors/.terraform.lock.hcl` | The committed provider lock for the feed mirror (azurerm, hashes for linux_amd64, windows_amd64 and darwin_arm64); CI initialises with `-lockfile=readonly`, so only a provider this file names can run (KDEC-071). | `.github/workflows/self-test.yml` | - | - |
| `infra/feed-mirrors/main.tf` | Terraform for the feed mirror: one storage account whose static website holds the feeds, reachable only through private endpoints. | - | - | - |
| `infra/feed-mirrors/outputs.tf` | The Terraform outputs the refresh template and every consuming repository need: the mirror URL and account. | - | - | - |
| `infra/feed-mirrors/tests/feed_mirrors.tftest.hcl` | The mocked Terraform test of the feed mirror's security posture (mock_provider azurerm, no Azure): storage and registry public access off, private endpoints and DNS links, the refresh identity's federated credential and its two scoped grants, the blob audit setting, every output. | `.github/workflows/self-test.yml` | runs: `plan_security_posture`, `apply_mocked_wiring` | - |
| `infra/feed-mirrors/variables.tf` | The Terraform inputs for the feed mirror: resource group, location, private endpoint subnet and DNS, the refresh identity's repository, environment and OIDC issuer, and tags. | - | - | - |
| `infra/feed-mirrors/versions.tf` | The Terraform and provider version pins for the feed mirror (azurerm `~> 5.14`; no resource provider is registered by the provider, so the subscription must have them registered first). | - | - | `tests/prove_kit_dependabot_triage_caller.py` |
| `profiles/node-service-sovereign.yml` | An example profile: a containerised Node service deploying to App Service in the sovereign (Government) cloud. | - | keys: `profile`, `description`, `language`, `security`, `supply_chain` +1 | - |
| `profiles/profile.schema.json` | The JSON schema of a pipeline profile: the shape of a repository type the kit serves. | `.github/workflows/self-test.yml` | keys: `$schema`, `$id`, `title`, `description`, `type` +3 | - |
| `profiles/python-service.yml` | An example profile: a containerised Python service deploying to Container Apps in the commercial cloud. | - | keys: `profile`, `description`, `language`, `security`, `supply_chain` +1 | - |
| `profiles/terraform-stack.yml` | An example profile: an infrastructure-as-code repository with no container build; the gates are IaC-shaped. | - | keys: `profile`, `description`, `language`, `security`, `supply_chain` +1 | - |
| `schemas/assurance-result.schema.json` | The JSON schema of the run record a security run emits (`scripts/run_record.py` validates against it). | `.github/actions/run-record/action.yml`, `.github/workflows/reusable-security.yml`, `assurance-taxonomy.yaml` +1 more | keys: `$schema`, `$id`, `title`, `description`, `type` +3 | `tests/prove_exception_lifecycle.py`, `tests/prove_gate_run_record.py` |
| `schemas/disposition-request.schema.json` | The JSON schema of a request to disposition a finding (accept, defer, mark false positive). | `CODEOWNERS`, `scripts/lint_suppressions.py` | keys: `$schema`, `$id`, `title`, `description`, `type` +4 | - |
| `schemas/disposition.schema.json` | The JSON schema of an approved disposition: who decided, why, and until when. | `CODEOWNERS`, `scripts/lint_suppressions.py`, `scripts/scan_report.py` | keys: `$schema`, `$id`, `title`, `description`, `type` +5 | `tests/prove_disposition_schema_and_key.py` |
| `schemas/expected-signal.schema.json` | The JSON schema of an expected signal: a seeded condition a scanner must detect in a fixture. | - | keys: `$schema`, `$id`, `title`, `description`, `type` +1 | - |
| `schemas/policy-registration.schema.json` | The JSON schema of the policy register (central and repository copies): rungs, controls, approver lists, routing, exceptions. | `scripts/policy_registration.py` | keys: `$schema`, `$id`, `title`, `description`, `type` +4 | `tests/prove_approver_list_source.py`, `tests/prove_policy_registration.py` |
| `schemas/promotion-record.schema.json` | The JSON schema of the promotion record a deploy writes and a later promotion reads. | `.github/workflows/reusable-deploy-appservice.yml`, `.github/workflows/reusable-deploy-containerapp.yml`, `.github/workflows/reusable-deploy-staticwebapp.yml` +2 more | keys: `$schema`, `$id`, `title`, `description`, `type` +3 | `tests/prove_promotion.py` |
| `schemas/live-target-authorisation.schema.json` | The JSON schema of the live-target authorisation record: who authorised which scan of which target, and until when. | `scripts/live_target_authorisation.py` | keys: `$schema`, `$id`, `title`, `description`, `type` +3 | `tests/prove_live_target_authorisation.py` |
| `schemas/rollback-sequence.schema.json` | The JSON schema of a sequential-rollback request: the deployments, in order, and their test periods. | `.github/workflows/reusable-rollback-sequence.yml`, `assurance-taxonomy.yaml`, `scripts/rollback_sequence.py` | keys: `$schema`, `$id`, `title`, `description`, `type` +3 | `tests/prove_rollback_dependencies.py` |
