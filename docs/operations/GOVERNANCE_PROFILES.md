# Governance profiles: personal and employer

Owner decision KDEC-052 item 11 (2026-11-13), built under KDEC-059. KE-02 (the checks run from a trusted
base-side source and read the pull request as data) is part of the same build.

> "Solo personal means solo there isn't another entity to approve changes period. Solo at work is
> different. Might be solo in the development space but we have team members allotted for PR
> pushes/reviews to main because those deploy to prod. But think of the changes like the dependabot
> merger. Only holds for human review if failures or it changes security or critical operational
> boundaries and code." (owner, 2026-11-13)

## 1. What the gate decides

`.github/workflows/governance-gate.yml` runs `scripts/governance_gate.py` from the DEFAULT branch and
publishes one of four decisions as the commit status `kit/governance-gate` on the pull request's head:

| decision | when | what happens |
|---|---|---|
| `merge_eligible` | no protected path changed, the trusted check passed from its trusted workflow, the base-side checks hold | auto-merge is armed (`gh pr merge --auto --squash --match-head-commit`); the ruleset still decides |
| `authorized` | a protected path changed, the profile's authorizer recorded consent on THIS head, every check above holds | auto-merge is armed |
| `hold` | anything else, each reason a named rule (docs/errors/ERRORS.md, `governance_gate_rule`) | auto-merge is disarmed; the status is `failure` |
| `delegated` | a verified Dependabot pull request that touches no governance machinery | the Dependabot triage decides (docs/adoption/DEPENDABOT_TRIAGE.md) |

A failed, missing or inconclusive check holds (in progress, skipped, neutral and cancelled are not
green). A change to security controls, critical operational boundaries, protected code, or to the
classifier, validator, scanner floor, policies or merge logic holds for the authorizer.

**Classification is by impact, not "contains code".** A path is protected when it matches a class in
`governance-profile.json` (merge_logic, scanner_floor, validator, policy, security_control,
operational_boundary) or the gate's own MACHINERY floor, which the profile cannot lower (the gate, its
profile and workflow, the checkers it imports, the files that decide "Self-test required", the floor,
the protected change log, CODEOWNERS, everything under `.github/`). Executable boundaries anywhere
(`action.yml`, `Dockerfile`, `*.tf`, `.gitattributes`, `.gitmodules`) are protected too. Renames are
read as a delete plus an add, so moving a protected file to a routine path is protected. Everything
else (for this repository: `docs/` outside `docs/assurance/`, README files) is routine. An adopting
repository lists its own security and operational paths (auth, IaC, deploy configuration) in `classes`.

## 2. The two profiles

`governance-profile.json` `profile` selects one. The gate reads the file from the BASE commit only: a
pull request that switches employer to personal is judged as employer and holds for the employer's
reviewers (tests/prove_governance_profiles.py A-5e). Any change to the file is protected.

**personal** -- genuinely solo; the owner is the authorizer; a second human is never required.
A protected change needs the owner's recorded authorization -- a pull request comment by `owner_login`
whose first line is `/kit-authorize <40-hex head sha>`, unedited -- plus independent technical
validation: the trusted check from its trusted workflow and the base-side floor and change-record checks.
A push after the authorization moves the head, so the authorization never carries to new code. The
placeholder `replace-me-owner-login` authorizes nothing.

**employer** -- development may be solo, but pull requests to the default branch deploy to production.
A protected change needs `required_approvals` (at least 1) approvals on the CURRENT head commit from the
assigned reviewers (`reviewer_teams` members, or `reviewer_logins`); the author and anyone who authored
or committed a commit on the pull request never count (separation of duties); any reviewer's latest
"changes requested" holds. Team membership needs `read:org`, which the run's token does not have: the
optional repository secret below supplies it; without it only `reviewer_logins` count, and with neither
a protected change holds (`reviewers_unknown`).

```yaml
GOVERNANCE_READ_ORG_TOKEN: a fine-grained token, organization "Members: read" only (optional)
```

## 3. Why the pull request cannot influence the checker (KE-02)

- Every trigger (`pull_request_target`, `workflow_run` of Self-test, `issue_comment`, `workflow_dispatch`)
  runs the default branch's workflow file; there is no `pull_request` trigger.
- The only checkout is the default branch, `persist-credentials: false`. The pull request's commits are
  fetched as git objects (`refs/pull/N/head`) and read by `git diff --no-renames` and `git show` in the
  base checker. Nothing from the pull request is checked out, installed, sourced or executed; the step
  that runs the checker holds no token.
- The profile, the classifier, the floor checker (`capability_floor`) and the change-record checker
  (`protected_paths`) are the base's copies. The floor is compared head-against-base by the base's code,
  so a pull request that rewrites `capability_floor.py` is still judged by the old one.
- A check is trusted by SOURCE, not name: a "Self-test required" check run counts only from the GitHub
  Actions app in a run of `.github/workflows/self-test.yml`. The same name from any other workflow or app
  is `impostor_check` and holds, even beside a real green one. A pull request that edits self-test.yml
  or `selftest_required.py` is protected (and recorded as `self_defined_checks`).

## 4. Repository settings the owner applies (this lane changed none)

Both profiles, the `main` ruleset (Settings > Rules > Rulesets), target the default branch, enforcement
**Active**, **bypass list empty** (administrators included; approver teams are never bypass actors,
KDEC-044):

| rule | personal | employer |
|---|---|---|
| Restrict deletions | on | on |
| Block force pushes | on | on |
| Require a pull request before merging | on | on |
| Required approvals | **0** (never a second human) | **0** for routine paths; code-owner review below covers protected ones. Raise it if the organization requires review of everything. |
| Dismiss stale approvals when new commits are pushed | on | on |
| Require review from Code Owners | **off** (the owner cannot approve her own pull request; her `/kit-authorize` is the consent) | **on** (CODEOWNERS' protected owner = the assigned reviewers' team) |
| Require approval of the most recent reviewable push | off | **on** (the last pusher never approves) |
| Require conversation resolution | optional | on |
| Require status checks to pass | on, "Require branches to be up to date" on | on, up to date on |
| Required checks | `Self-test required` and `kit/governance-gate`, source GitHub Actions | the same |
| Allowed merge methods | squash | squash |

Settings > General: **Allow auto-merge** on (until then the auto-merge job fails and says so). Settings >
Actions > General: fork pull request workflows **require approval for all outside collaborators**;
**Allow GitHub Actions to create and approve pull requests** off; workflow permissions **read**.
`governance-profile.json`: set `profile`, and `owner_login` (personal) or `reviewer_teams` /
`reviewer_logins` (employer), and merge that change by hand once -- the gate cannot authorize the change
that names its first authorizer. In the employer profile replace `@YOUR_ORG/replace-me-kit-control-owners`
in CODEOWNERS with the assigned reviewers' team (KDEC-050).

Employer note (INFERRED, verify with one test pull request): with 0 required approvals and "Require
review from Code Owners" on, GitHub requires a code owner's approval only when a code-owned file
changes. Check that a docs-only pull request merges without review and a `scripts/` one does not.

## 5. Residual risk, stated plainly

1. **The status can be written by another workflow.** `kit/governance-gate` is posted with the run's
   token, and a same-repository branch's own `pull_request` workflow with `statuses: write` could post the
   same context. Adding or editing such a workflow is itself a protected (`.github/`) change: in the
   employer profile GitHub's code-owner review blocks its merge natively; fork pull requests get a
   read-only token. Closing it fully: a dedicated GitHub App posts the status, and the ruleset's required
   check names that App as its source (the owner creates the App; PROPOSED in KDEC-059).
2. **Auto-merge can be armed by anyone with write access.** The gate disarms it on every hold, but a
   later arm by someone else is still bounded only by the required checks (risk 1).
3. **The owner's credential is the personal authorizer.** Anything holding her token -- an agent
   included -- can comment `/kit-authorize`. Agents should run under their own account or a token that
   is not hers.
4. **Re-decision triggers.** The gate re-decides on pushes, when Self-test completes, on `/kit-` comments
   and on dispatch. An employer review does not trigger it (the `pull_request_review` event runs the pull
   request's workflow): after approving, comment `/kit-recheck`.
5. **A replacement proof added in the same pull request** is looked up in the base tree, so the floor
   check holds it (conservative); land the proof first.
6. **Fixture proofs only.** tests/prove_governance_profiles.py proves the decision logic, the workflow's
   shape and end-to-end git reading. No hosted run has exercised the workflow; acceptance on a personal
   test repository is owed (routine docs PR, protected PR, fake-check workflow PR, profile switch).

## 6. Proof

`python3 tests/prove_governance_profiles.py` (in the self-test contract job): in BOTH profiles a routine
green change is `merge_eligible`; red, missing and inconclusive checks hold; the PR editing the
classifier, protected_paths/CHANGE_GUARDED, the floor, the merge logic, the profile, adding a fake
"Self-test required" workflow, editing self-test.yml, editing only the change log, or renaming a
protected file -- each holds; forged authorizations hold; an authorized floor shrink without a tombstone
holds by the base-side check; fourteen named mutants are each killed.
