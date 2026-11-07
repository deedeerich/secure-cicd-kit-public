# Auto-merge of Dependabot updates: where to turn it on, and the risks

Status: guidance for the owner's decision O-40b (KDEC-040, PROPOSED). Every mitigation below is
**PROPOSED** until someone records the evidence and an approver (`scripts/check_register_mitigations.py`
holds the registers to that; risk R-22 in `.context/products/secure-cicd-kit/risks.md` points here).

## The short answers

**Which repositories should have auto-merge on?** Start with the kit's own repositories, then low-risk
internal repositories at the crawl rung. Never a repository whose push to `main` deploys to
production without an environment approval gate. The criteria per repository are in the
[decision table](#decision-criteria-per-repository).

**Is auto-merge on for every repository that uses the kit?** No. It is opt-in, per repository.
Nothing happens until that repository adds the triage caller (`templates/dependabot-triage.yml`),
turns on Settings > General > "Allow auto-merge", and requires the kit's gate check on `main`.
Without all three, every Dependabot pull request goes to a person (`scan_gate_not_required`,
`scan_gate_unnamed`).

**What does the kit already limit?** Only patch and minor updates can merge on their own; a major
never does. The triage sends these to a person: protected packages (authentication, cryptography,
network, web frameworks, database drivers, payment, the triage chain itself), protected ecosystems
(Docker, Compose, Helm, Terraform, devcontainers), anything outside dependency metadata, breaking-change
and maintainer-change signals, lockfile churn over 400 lines or moving packages the PR does not name,
and an Actions update that is not pinned to a commit SHA. The merge is `gh pr merge --auto --squash`,
so GitHub merges only when branch protection and every required check allow it.
`docs/adoption/DEPENDABOT_TRIAGE.md` has the rules.

## The risks, each with suggested mitigations

### 1. A compromised patch or minor release (a malicious maintainer or a taken-over account)

A new version within a minor can carry malicious code and still pass tests.
**Suggested mitigations** (PROPOSED):
- Keep the kit's malicious-package scan (osv-scanner) and known-exploited blocking in the required gate, so a published malicious version blocks the merge.
- Add a cooldown: merge only updates whose release is at least N days old (Dependabot's `cooldown` setting or a triage rule), so most takeovers are caught upstream first.
- Keep `maintainer_changed` and provenance signals sending the update to a person; add registry provenance checks where the ecosystem offers them (npm provenance, PyPI attestations).
- Add your own critical packages to `critical_packages`.

### 2. Semver-violating breaking changes

A "patch" that changes behaviour.
**Suggested mitigations** (PROPOSED):
- Turn auto-merge on only where the required checks include real tests of the changed behaviour.
- Keep `breaking_change_signal` routing to a person; read release notes for the protected packages.
- Squash merges revert with one `git revert`; keep that the documented rollback.

### 3. Thin test coverage lets a break through

A green check over few tests proves little.
**Suggested mitigations** (PROPOSED):
- Set a coverage floor (or a list of required test jobs) before a repository is eligible.
- Use `auto_merge_update_types: patch` (narrower) on repositories below the floor.
- Review a monthly sample of auto-merged updates against incidents.

### 4. Merge to `main` deploys to production without CAB or change approval (the biggest one)

If a push to `main` triggers a production deploy with no human gate, auto-merge becomes auto-deploy.

**Now enforced by the kit (KDEC-042, 2026-11-06), not only advised.** Every kit deploy job runs in its
GitHub environment (`environment:` from a required input, never conditional on the trigger;
`tests/check_deploy_environment_declared.py`), so a push or an auto-merge to `main` that reaches uat or
prod waits on that environment's required reviewers. Before any cloud login the deploy also refuses a uat
or prod environment that does not exist, has no reviewers, allows self-review, has no platform or security
pool reviewer, or can be approved only by the app team, and refuses an environment it cannot class
(`ENVIRONMENT_UNCLASSED`) at every tier (`tests/prove_uat_prod_gating.py`). What stays a person's: the
reviewers themselves (a repository admin sets them), and CAB where your change process requires it; the
residual risks are R-27 and R-28 in the risk register.

**Suggested mitigations** (PROPOSED):
- Tie every production deploy to a GitHub environment with **required reviewers** and self-review prevented; the kit's deploy reusables already read the environment's protection back and refuse at uat/prod when it falls short (`deploy_approval`).
- Route production releases through CAB (`docs/security-review/CAB-CHANGE-REVIEW-CHECKLIST.md`); keep promotion of the same digest (KDEC-029) so prod deploys a build a person approved.
- Never enable auto-merge in a repository whose `main` deploys to prod without that gate (the decision table).

### 5. The `pull_request_target` token can write

The triage workflow runs with a token that can merge and label.
**Suggested mitigations** (PROPOSED):
- Keep the kit's design: the caller and the reusable come from the default branch, nothing checks out PR code, every PR value is data (`tests/prove_dependabot_triage.py` D1, D8).
- Protect `.github/workflows/` with CODEOWNERS so the caller cannot change without review.
- Keep the job permissions per job (classify reads; only auto-merge may merge).

### 6. Review fatigue and rubber-stamping

People approve what a bot sends without reading.
**Suggested mitigations** (PROPOSED):
- Keep each PR's triage comment saying exactly why it needs a person; group minor and patch updates to cut volume.
- Limit open Dependabot PRs per ecosystem (`open-pull-requests-limit`).
- Spot-check a sample of human-approved updates each month.

### 7. Audit trail and separation of duties (the bot approving itself)

An auto-merge has no human approver on record.
**Suggested mitigations** (PROPOSED):
- Never let the bot approve: the kit's triage arms auto-merge, it does not submit an approving review; a required CODEOWNERS review blocks auto-merge on paths that need a person.
- Keep each decision as `decision.json` (90 days) and the merge in the audit log; export both to the evidence store.
- Record in the policy register which repositories allow auto-merge, approved by a named role.

### 8. A grouped update hides a risky one

One PR moves several packages.
**Suggested mitigations** (PROPOSED):
- The triage evaluates every dependency in a group; one protected package sends the whole group to a person.
- Keep groups to minor and patch only, per ecosystem.

### 9. Transitive dependencies

A small direct bump pulls in many indirect changes.
**Suggested mitigations** (PROPOSED):
- Keep the lockfile checks: churn over the threshold, or a package the PR does not name, goes to a person.
- Keep the dependency and malicious-package scans over the whole lockfile in the gate.

### 10. Licence changes

A new version changes its licence.
**Suggested mitigations** (PROPOSED):
- Keep the SBOM licence verdict in the gate (`scripts/sbom_licenses.py`); a denied licence blocks.
- Add a triage rule: a licence change between versions goes to a person.

### 11. Volume and noise

Many small PRs and comments.
**Suggested mitigations** (PROPOSED):
- Group minor and patch updates; weekly schedule; per-ecosystem PR limits (`scripts/dependabot_config.py generate` does all three).
- The keep-current job asks for a rebase once per base commit, never more.

## Rollout recommendation

1. **The kit's repositories first** (the kit, then its public mirror): the gate is "Self-test
   required", the caller is already in place (`.github/workflows/dependabot-triage.yml`). Watch two
   weeks of decisions.
2. **Low-risk internal repositories at crawl**, one at a time: internal tools, libraries without a
   production deploy, repositories with good tests. Patch only for the first month.
3. **Everything else stays manual** until it meets every criterion below.
4. **Never**: a repository whose `main` deploys to production without an environment approval gate.

How this sits in the kit's adoption waves ([ROLLOUT_PLAN.md](ROLLOUT_PLAN.md), KDEC-041): auto-merge is off in
every wave by default. `kit init --automerge` (or the kit-init workflow's `automerge` box) only adds the
"Allow auto-merge" step and this guide to the repository's checklist; a person decides. A repository in its
report-only weeks is a fair candidate for step 2 once its gate check is required; a legacy repository whose
backlog is not yet triaged is not.

## Decision criteria per repository

| criterion | needed for auto-merge |
|---|---|
| the kit's gate check (`security / Security gate` or the repository's equivalent) is a required status check on `main` | yes |
| production deploys go through an environment with required reviewers (and CAB where it applies) | yes, or the repository never deploys to production |
| required tests exercise the code the dependencies serve (a coverage floor or named test jobs) | yes |
| CODEOWNERS covers `.github/workflows/` and the dependency manifests | yes |
| the repository handles regulated data or authentication for others | no auto-merge; or `patch` only with protected packages listed |
| "Allow auto-merge" is on in Settings > General | yes |
| the policy register records the repository as auto-merge-enabled, approved by a named role | yes |

Owner commands (not run by this lane), per repository once it qualifies:

```bash
gh api -X PATCH repos/<org>/<repo> -F allow_auto_merge=true
```

The required checks and environments are in `docs/adoption/BRANCH_PROTECTION_SETTINGS.md`.
