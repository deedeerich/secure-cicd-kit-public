# Branch protection: the rulesets to turn on, per repository type

Status: recommended settings for the owner (decision O-40c, KDEC-040). **Nothing here has been applied**
by any workflow or lane; every command is the owner's to run. The check names are the ones the kit's
workflows emit (`tests/check_branch_protection_profiles.py` derives them from the shipped templates),
so a required check never waits for a name nothing produces.

Use **repository rulesets** (Settings > Rules > Rulesets, or the `rulesets` API). They work the same on
github.com and on GHE.com, can be read back, and can be set for many repositories at once at the
organisation level. The older "branch protection rules" still work; `developer-safety/branch-protection/*.json`
holds those profiles.

## What each setting does, and the tradeoffs

| setting | why | tradeoff |
|---|---|---|
| **Require a pull request** | nothing reaches `main` without review and checks | none worth having |
| **Required status checks** (exact names below) | the kit's gate decides every merge | a name no job emits blocks every PR forever; use only the names below |
| **Require branches to be up to date** ("strict") | the checks ran on what will be merged | every merge makes other PRs stale, so they re-run checks and need a rebase. The kit's keep-current job asks Dependabot to rebase its own PRs once per base commit (`DEPENDABOT_TRIAGE.md` 3b); people click "Update branch". A merge queue (`merge_group`, KDEC-033) removes the churn where it is available |
| **Require review from code owners** | the owners of a path approve changes to it | **it holds auto-merge**: GitHub merges an armed PR only after every required review. A Dependabot PR that touches a code-owned manifest waits for that owner. Choose: code-own the manifests (a person approves each update, auto-merge only saves the click), or leave manifests un-owned in repositories that use auto-merge |
| **Required approvals** | a second person | in a repository that auto-merges, any required approval means a person approves each Dependabot PR; set 0 only with the compensating controls of the solo profile |
| **Dismiss stale approvals, require approval of the last push** | an approval covers what merges | a person re-approves after a push |
| **Block force pushes and deletions** | history and the branch cannot be rewritten or removed | none |
| **Linear history** (optional) | one line of history, easy reverts | merge commits are refused; squash or rebase only |
| **Signed commits** (optional) | every commit is verified | every contributor sets up signing. GitHub signs the commits it makes (web merges, squash merges, Dependabot), so auto-merge keeps working |
| **Bypass list** | who may skip the rules | **none**. If you need break-glass, one team, "pull requests only", and every use reviewed |
| **Environments `uat` and `prod`** | a person approves each release | required reviewers with self-review prevented; deployment branches limited to `main` |

## GHE.com (data residency) specifics

- Every `gh` command needs the host: `export GH_HOST=<tenant>.ghe.com` (or `--hostname <tenant>.ghe.com`).
  The API is `https://api.<tenant>.ghe.com`; a call to `api.github.com` with a GHE.com token fails (KDEC-027).
- Rulesets, required status checks, CODEOWNERS and environments behave as on github.com. A required check
  may name the app that must report it (`integration_id`); the GitHub Actions app's id on a GHE.com tenant
  is **UNVERIFIED** here, so the JSON below names checks by context only. To pin the app, read
  `app.id` from one of the repository's own check runs and add it.
- Merge queue availability on your plan and visibility: **UNVERIFIED**; read Settings > Rules first.
- GitHub Advanced Security being off changes nothing below: no rule here requires code scanning results.

Apply a ruleset (one file per repository type, below):

```bash
export GH_HOST=<tenant>.ghe.com          # GHE.com only; omit on github.com
gh api -X POST repos/<org>/<repo>/rulesets --input ruleset.json
gh api repos/<org>/<repo>/rulesets        # read it back: the id, then
gh api repos/<org>/<repo>/rulesets/<id>   # the rules as GitHub stored them
```

To change one later: `gh api -X PUT repos/<org>/<repo>/rulesets/<id> --input ruleset.json`.

## 1. The kit repository (private)

The one required check is `Self-test required` (KDEC-033: never green by skipping, never pending by a path
filter). `Dependabot configuration matches the manifests` is cheap and never skips by path.

```json
{
  "name": "main: kit",
  "target": "branch",
  "enforcement": "active",
  "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
  "bypass_actors": [],
  "rules": [
    {"type": "deletion"},
    {"type": "non_fast_forward"},
    {"type": "required_linear_history"},
    {"type": "pull_request", "parameters": {
      "required_approving_review_count": 0,
      "dismiss_stale_reviews_on_push": true,
      "require_code_owner_review": false,
      "require_last_push_approval": false,
      "required_review_thread_resolution": true,
      "allowed_merge_methods": ["squash"]}},
    {"type": "required_status_checks", "parameters": {
      "strict_required_status_checks_policy": true,
      "do_not_enforce_on_create": false,
      "required_status_checks": [
        {"context": "Self-test required"},
        {"context": "dependabot-config / Dependabot configuration matches the manifests"}]}}
  ]
}
```

Approvals 0 and no code-owner review: the owner works solo (the solo profile's compensating controls
apply), and the kit's own Dependabot updates auto-merge. With a second maintainer, set approvals to 1 and
`require_code_owner_review` to true; auto-merge then waits for that approval.

## 2. The public mirror

The release self-tests run there (owner, 2026-10-27). Same rules, plus signed commits; no auto-merge
until two weeks of the kit's own decisions have been reviewed (`AUTOMERGE_RISKS_AND_ROLLOUT.md`).

```json
{
  "name": "main: public mirror",
  "target": "branch",
  "enforcement": "active",
  "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
  "bypass_actors": [],
  "rules": [
    {"type": "deletion"},
    {"type": "non_fast_forward"},
    {"type": "required_linear_history"},
    {"type": "required_signatures"},
    {"type": "pull_request", "parameters": {
      "required_approving_review_count": 1,
      "dismiss_stale_reviews_on_push": true,
      "require_code_owner_review": true,
      "require_last_push_approval": true,
      "required_review_thread_resolution": true,
      "allowed_merge_methods": ["squash"]}},
    {"type": "required_status_checks", "parameters": {
      "strict_required_status_checks_policy": true,
      "do_not_enforce_on_create": false,
      "required_status_checks": [{"context": "Self-test required"}]}}
  ]
}
```

## 3. A consumer application repository

Calls the kit through `templates/build-deploy.yml` (job `security`, check `security / Security gate`) and
the workflow policy (`policy / Workflow policy`). Add `cve / NVD CVE scan` for a critical service.

```json
{
  "name": "main: application",
  "target": "branch",
  "enforcement": "active",
  "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
  "bypass_actors": [],
  "rules": [
    {"type": "deletion"},
    {"type": "non_fast_forward"},
    {"type": "pull_request", "parameters": {
      "required_approving_review_count": 1,
      "dismiss_stale_reviews_on_push": true,
      "require_code_owner_review": true,
      "require_last_push_approval": true,
      "required_review_thread_resolution": true,
      "allowed_merge_methods": ["squash", "merge"]}},
    {"type": "required_status_checks", "parameters": {
      "strict_required_status_checks_policy": true,
      "do_not_enforce_on_create": false,
      "required_status_checks": [
        {"context": "security / Security gate"},
        {"context": "policy / Workflow policy"},
        {"context": "dependabot-config / Dependabot configuration matches the manifests"}]}}
  ]
}
```

With `require_code_owner_review` true, a Dependabot PR touching an owned manifest waits for its owner
even when the triage armed auto-merge. That is the recommended default (`AUTOMERGE_RISKS_AND_ROLLOUT.md`).

## 4. An infrastructure / landing-zone repository

Infrastructure changes are high blast radius: two approvals, code owners, signed commits, linear history.
`security / Security gate` runs the kit's IaC scanners (`iac_mode`). Add your plan job's check by its exact
name (`<plan job> / <plan step job name>`), read from a pull request's checks list.

```json
{
  "name": "main: infrastructure",
  "target": "branch",
  "enforcement": "active",
  "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
  "bypass_actors": [],
  "rules": [
    {"type": "deletion"},
    {"type": "non_fast_forward"},
    {"type": "required_linear_history"},
    {"type": "required_signatures"},
    {"type": "pull_request", "parameters": {
      "required_approving_review_count": 2,
      "dismiss_stale_reviews_on_push": true,
      "require_code_owner_review": true,
      "require_last_push_approval": true,
      "required_review_thread_resolution": true,
      "allowed_merge_methods": ["squash"]}},
    {"type": "required_status_checks", "parameters": {
      "strict_required_status_checks_policy": true,
      "do_not_enforce_on_create": false,
      "required_status_checks": [
        {"context": "security / Security gate"},
        {"context": "policy / Workflow policy"}]}}
  ]
}
```

No auto-merge in this repository type.

## Environments `uat` and `prod` (every repository that deploys)

```bash
cat > env.json <<'JSON'
{
  "wait_timer": 0,
  "prevent_self_review": true,
  "reviewers": [{"type": "Team", "id": <release-approvers team id>}],
  "deployment_branch_policy": {"protected_branches": true, "custom_branch_policies": false}
}
JSON
gh api -X PUT repos/<org>/<repo>/environments/prod --input env.json
gh api -X PUT repos/<org>/<repo>/environments/uat  --input env.json
gh api orgs/<org>/teams/<team-slug> --jq .id     # the team id for "reviewers"
```

The kit's deploy reusables read this protection back and refuse a uat/prod release before login when it
falls short of the policy register's `deploy_approval` (`docs/adoption/SETUP.md` section 1).

Who the reviewers are, and how fast they answer ([ROLLOUT_PLAN.md](ROLLOUT_PLAN.md) section 3, KDEC-041):
name a **primary and a backup** reviewer (two entries, e.g. the platform team and the security team); for a
**small team** they come from platform or security, outside the team; the approver SLA is the **same
business day**, and a missed SLA is escalated (backup, then the platform lead), **never auto-approved** and
never answered by loosening the environment. `kit init` writes this as `.kit/environments.json` and puts the
exact commands in the repository's checklist (deployment branches limited to `main`). Require
`security / Security gate` only **after** the repository's first green run: a required check that has never
passed blocks every pull request at once.

## Break-glass, if you must have one

One team, bypass mode "pull requests only" (it can merge a reviewed PR past a failing check, never push
directly), and every use recorded as a weakening with all five fields (KDEC-036):

```json
"bypass_actors": [{"actor_id": <break-glass team id>, "actor_type": "Team", "bypass_mode": "pull_request"}]
```
