# 10d · Design: Dependabot triage, keep-current and the configuration check

```
Kept:      2026-11-07, against the trunk at c1420ea. Components: 03d_COMPONENTS_DEPENDABOT.md.
Code:      reusable-dependabot-triage.yml, reusable-dependabot-keep-current.yml,
           reusable-dependabot-config-check.yml; scripts/dependabot_config.py,
           scripts/inline_dependabot_config.py.
Guide:     docs/adoption/DEPENDABOT_TRIAGE.md. Picture: ARCH_05_DEPENDABOT_TRIAGE.md.
```

## 1 · Purpose

Let a bot merge, on its own, only the dependency updates that cannot change behaviour; send every other
update to a person with one comment saying why; keep open updates current so nobody babysits them; and
make sure no manifest is left without updates.

## 2 · Inputs and outputs

| Workflow | Inputs | Outputs |
|---|---|---|
| triage | `critical_packages`, `critical_ecosystems`, `auto_merge_update_types` (default patch, minor), `lockfile_line_threshold` (ceiling 400), `excluded_paths`, `required_checks`, `min_compatibility_score`, `review_team`, `review_label`, `urgent_label`; optional `METADATA_TOKEN` | `action` (`auto_merge`, `human_review`, `close`), `rule`; `decision.json` |
| keep-current | `base_branch`, `excluded_paths`, `max_pull_requests`; optional `COMMAND_TOKEN` | `asked_rebase`, `asked_recreate`, `closed` |
| config check | none | `state`; a corrected `dependabot.yml` when one is needed |

## 3 · How it works

1. On `pull_request_target`, only when the PR **author** is `dependabot[bot]`, classify reads the
   metadata, the files and diffs as data, and the base branch protection. Nothing is checked out.
2. Every criterion must hold for `auto_merge`; the first that fails names the rule. Anything unreadable
   goes to a person (fail closed).
3. `auto_merge` arms `gh pr merge --auto --squash`; GitHub merges only when every required check passes.
4. Keep-current, on push, schedule or dispatch, asks each behind Dependabot PR to rebase once per base
   commit, a conflicting one to recreate, closes a fixture PR, and never touches a human PR.
5. The config check compares every manifest with the `dependabot.yml` entries.

## 4 · States, in plain words (`dependabot_triage_rule`, a sample)

| Rule | In plain words |
|---|---|
| `excluded_path` | This update touches a path excluded from updates (for example test fixtures), so it was closed. |
| `critical_package` | The package is on the protected list (runtime-critical). |
| `triage_chain` | The update changes the triage workflow or the kit pin itself. |
| `major_update` | This is a major version update. |
| `actions_pin_not_sha` | A GitHub Actions update is not pinned to a full commit SHA. |
| `non_dependency_change` | The update changes something other than a dependency version. |
| `breaking_change_signal` | The release notes mention a breaking change. |
| `lockfile_churn` | The lockfile changes more lines than this repository auto-merges. |
| `lockfile_unrelated_moves` | The lockfile also changes packages this update does not name. |
| `no_required_checks` | The base branch requires no status checks, so an auto-merge would merge untested code. |
| `scan_gate_not_required` | A check the triage relies on is not required on the base branch. |
| `policy_misconfigured` | The triage settings in the caller workflow are invalid, so every update goes to a person. |

All 26 rules are in `docs/errors/ERRORS.md`.

## 5 · Failure modes

| Failure | What happens | Proof |
|---|---|---|
| a human pushes to a Dependabot PR | the author check still reads Dependabot, but the files and diffs change, so the criteria re-run on what is there | `tests/prove_dependabot_triage.py` |
| a PR bumps the triage workflow or the kit pin | `triage_chain`: a person decides | `tests/prove_dependabot_triage.py` |
| "Allow auto-merge" is off | the auto-merge job comments; nothing merges | `tests/prove_dependabot_triage.py` |
| the scan gate is not required | every PR goes to a person | `tests/prove_dependabot_triage.py` |
| Dependabot ignores the run's own token for commands | `COMMAND_TOKEN` may post the comment | `tests/prove_dependabot_keep_current.py` |
| a manifest has no Dependabot entry | the config check fails and offers a corrected file | `tests/prove_dependabot_config.py` |

## 6 · Decisions

| Decision | What it settled |
|---|---|
| owner merge strategy (2026-10-22, recorded in the triage workflow's header) | auto-merge only what cannot change behaviour; a human for the rest |
| KDEC-040 | Dependabot with no babysitting (keep-current); manifests checked (the config check) |
| KDEC-033 | the kit host's required check is `Self-test required`, never green by skipping |
