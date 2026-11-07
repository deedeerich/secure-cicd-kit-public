# Code walkthrough: Root files, registries and small areas

```
Kept:      generated 2026-11-07 against the trunk; the file list is mechanical (git ls-files), the
           descriptions were written by reading each file. tests/check_code_walkthrough_coverage.py
           fails when a tracked file has no row here, or a row names a file that is gone.
Columns:   "called by" = files that run, import, inline or `uses:` it; "proved by" = tests that name it.
           Both are computed by text search, so they can over-count a mention as a use.
```

[Back to the walkthrough index](README.md)

14 files.

| file | what it does | called by | inputs and outputs | proved by |
|---|---|---|---|---|
| `.custody.json` | Declares this repository NEUTRAL custody: it ships to consumers, may receive only neutral material, and is enforced by the export-safety check. Overlays are the named exception. | - | keys: `class`, `enforced_by`, `deny_list`, `may_receive_from`, `rationale` +2 | - |
| `.env.example` | A template for a local `.env` holding tracker and cloud settings for local runs. Nothing in CI reads it; `scripts/check_env.py` names any missing field. | `.github/workflows/self-test.yml`, `.gitignore`, `developer-safety/branch-protection/push-ruleset-secret-files.json` +3 more | - | `tests/prove_baseline_gitignore.py`, `tests/prove_leak_gate_posture.py`, `tests/prove_push_ruleset_secret_files.py` +1 more |
| `.github/dependabot.yml` | The kit repository's own Dependabot configuration: weekly updates for its pinned actions (root and every composite), the feed-mirror Terraform and its Docker images; the test fixtures' manifests are held still, even against security updates. | `.github/actions/discover/action.yml`, `.github/actions/kit-init/action.yml`, `.github/actions/resolve/action.yml` +8 more | keys: `version`, `updates` | `tests/capability_inventory.py`, `tests/check_action_pins.py`, `tests/check_fixture_seed_pins.py` +5 more |
| `.gitignore` | Keeps generated evidence, caches and local secrets out of the repository. | `.github/actions/discover/action.yml`, `.github/workflows/reusable-security.yml`, `.github/workflows/self-test.yml` +4 more | - | `tests/check_source_hygiene.py`, `tests/prove_baseline_gitignore.py`, `tests/prove_census_outside_kit.py` +2 more |
| `CODEOWNERS` | Says who must approve which paths, so the three questions (is the pipeline right, is the security policy right, is the kit itself right) have different approvers. | `.github/actions/kit-init/action.yml`, `.github/workflows/reusable-dependabot-triage.yml`, `.github/workflows/reusable-kit-survey.yml` +22 more | - | `tests/check_fixture_seed_pins.py`, `tests/check_weakening_record.py`, `tests/prove_capability_floor.py` +6 more |
| `CONTRIBUTING.md` | How to change the kit: test first, one defect per commit, run the battery before every push. | `tools/battery.ps1`, `tools/battery.py`, `tools/battery.sh` | - | `tests/prove_battery_mirrors_selftest.py` |
| `README.md` | The front page: what the kit is, what each reusable workflow does, and what is proven. | `.github/actions/kit-api/action.yml`, `.github/workflows/reusable-kit-api.yml`, `api/v1/refusals.json` +8 more | - | `tests/check_doc_currency.py`, `tests/check_pinned_artifacts.py`, `tests/make_fixture.py` +15 more |
| `assurance-taxonomy.yaml` | The controlled vocabulary: every state word the kit may emit (PROCEED, BLOCKED, NOT_ESTABLISHED and hundreds more), grouped by namespace, with what each means. | `.github/actions/capability-floor/action.yml`, `.github/actions/target-lease/action.yml`, `.github/workflows/reusable-build-docker.yml` +50 more and 1 in a withheld directory | keys: `meta`, `invariants`, `namespaces` | `tests/check_reversal_preconditions.py`, `tests/check_weakening_record.py`, `tests/prove_authority_floor.py` +14 more |
| `capability-floor.json` | The protected capability floor: the scanner identities the gate must expect whatever the registry says. It can shrink only through a recorded tombstone. | `.github/actions/capability-floor/action.yml`, `.github/workflows/reusable-security.yml`, `.github/workflows/self-test.yml` +4 more | keys: `_what`, `_shrink`, `version`, `floor`, `tombstones` | `tests/prove_capability_floor.py` |
| `id-mappings.json` | Mappings a person made for finding identifiers the kit could not read, each a reviewed change with author, date and reason. | `CODEOWNERS`, `assurance-taxonomy.yaml`, `scripts/code_finding_key.py` +3 more | keys: `schema`, `_about`, `mappings` | - |
| `rollback-resource-classes.yaml` | Which Azure resource types a rollback may reverse entry by entry, and which it must treat as one whole thing. | `assurance-taxonomy.yaml`, `scripts/rollback_dependencies.py`, `scripts/rollback_sequence.py` | keys: `schema_version`, `classes`, `read_only_fields`, `types` | `tests/prove_rollback_dependencies.py`, `tests/prove_seam_app_rollback_refuses_shared_entry.py` |
| `scanner-registry.yaml` | The list of every scanner job, the identities it reports, its capability and its declared version range: the denominator the gate and the report check against. | `.github/actions/capability-floor/action.yml`, `.github/actions/resolve/action.yml`, `.github/workflows/probe-scanner-corpora.yml` +8 more | keys: `jobs`, `version_support`, `capability_selection` | `tests/_composite_expand.py`, `tests/capability_inventory.py`, `tests/check_gate.py` +16 more |
| `skills/tools/correlation-triage/SKILL.md` | An agent skill describing how to triage finding-correlation proposals by hand. | - | - | `tests/prove_ticket_lifecycle.py` |
| `wiring/gate-rung.patch.md` | A record of how the rung was wired into the gate: the exact change, its proof, and what it means for the posture record. | `.github/workflows/reusable-security.yml`, `.github/workflows/self-test.yml` | - | `tests/check_stage_phase.py`, `tests/prove_gate_policy_enforcement.py`, `tests/prove_gate_reads_rung.py` |
