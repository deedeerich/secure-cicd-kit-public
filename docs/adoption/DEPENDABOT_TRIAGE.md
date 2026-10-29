# Dependabot triage: auto-merge what cannot change behaviour, ask a human for the rest

`.github/workflows/reusable-dependabot-triage.yml`, called from `templates/dependabot-triage.yml`.
It recovers the capability designed in [`docs/roadmap/FUTURE_WORK.md` section 6](../roadmap/FUTURE_WORK.md)
and meets the owner's requirement of 2026-10-22: a human reviews a Dependabot pull request only when
it "materially changes something that could change functionality or is critically important to
runtime".

**Status.** Proven locally by running the workflow's own steps (`tests/prove_dependabot_triage.py`,
42 decisions plus the action steps, wired into `self-test.yml`). It has **not** run on GitHub. A hosted
run is owed (section 6 below; registry deferral `dependabot-merge-hosted`).

---

## 1 · What it does

For every Dependabot pull request it makes ONE decision, records it, and acts:

| decision | what happens |
|---|---|
| `auto_merge` | `gh pr merge --auto --squash`. GitHub merges **only when branch protection and every required check allow it**. The workflow never merges past them and never uses `--admin`. A squash is one commit, so the update reverts with one `git revert`. |
| `human_review` | the review label (default `needs-human-review`), plus `urgent-security-review` for a security update to a protected package; a review request to `review_team` if set; one comment, updated in place, saying **why** in plain words; an auto-merge armed by an earlier run is switched back off. |
| `close` | the PR touches an excluded path (default `tests/consumer-fixture/**`, whose packages are deliberately vulnerable): closed with the reason. |

Every decision (package, from -> to, update type, dependency type, ecosystem, security linkage,
every rule matched, the action) is written to the run's step summary and to the
`dependabot-triage-<pr>-<attempt>` artifact (`decision.json`, kept 90 days).

### The rules (FUTURE_WORK section 6, criterion by criterion)

Auto-merge needs **every** criterion to hold. The first rule that fails names the decision; all
that fail are recorded.

| FW section 6 criterion | enforced by | rule id(s) | proof case(s) |
|---|---|---|---|
| patch or minor | the per-dependency update type, inside `auto_merge_update_types` (ceiling `patch,minor`) | `major_update`, `update_type_unknown`, `update_type_not_allowed`, `policy_misconfigured` | D3 major, D4 grouped major, unknown type, patch-only policy, major-in-policy refused |
| not in a protected class | the kit's built-in list (auth/identity, crypto/TLS, network/HTTP, web frameworks and runtime, DB drivers/ORMs/migrations, payment) plus `critical_packages`; infra/runtime ecosystems docker, docker-compose, helm, terraform, devcontainers plus `critical_ecosystems` | `critical_package`, `critical_ecosystem`, `security_critical` | D3 critical minor, security-critical (+urgent), caller glob; D4 network package, docker, terraform |
| all tests and scans pass | the merge is `--auto`: GitHub waits for every required check. The workflow refuses to arm it unless the base branch REQUIRES status checks and every name in `required_checks` (the scan gate) is one of them | `no_required_checks`, `required_checks_unknown`, `scan_gate_unnamed`, `scan_gate_not_required` | D4 no checks, protection unreadable, ruleset checks count, no gate named, gate not required |
| no breaking-change signal | the PR body (Dependabot's release notes and commits): "breaking change", `BREAKING`, "backwards incompatible", a conventional `feat!:`; "no breaking changes" and "non-breaking" are not signals | `breaking_change_signal` | D4 feat!, BREAKING, the negative control |
| no infra/schema/auth/network impact | the protected classes above (schema = ORMs and migration tools; infra = the protected ecosystems), plus scope: nothing but dependency metadata may change | `critical_package`, `critical_ecosystem`, `non_dependency_file` | as above; D4 source file changed |
| provenance/signature checks pass | **NOT ENFORCED.** No registry signature or provenance check exists in the kit for dependencies. Every decision records `provenance: not_established`. The one provenance property checked: a github-actions update must land on a full 40-hex commit SHA | `actions_pin_not_sha` (actions only) | D4 action moved onto a tag |
| no new critical/high vulnerability | delegated to the kit's security gate as a REQUIRED check (`required_checks`); auto-merge waits for it. The triage itself reads no scan result | `scan_gate_unnamed`, `scan_gate_not_required` | D4 gate cases. The gate's own behaviour: the security proofs |
| no malicious-package signal | the same: `reusable-security.yml`'s malicious-deps check blocks the gate in every mode; required, it holds the merge. Also `maintainer_changed` (fetch-metadata's maintainer-change signal) goes to a human | `maintainer_changed` (+ the gate) | D4 maintainers changed |
| lockfile diff consistent with the intended change | the lockfile diff is read package by package (npm package-lock, yarn.lock, poetry/uv/Cargo, composer.lock, go.sum, Gemfile.lock); any package it moves that the PR does not name goes to a human; a lockfile whose diff GitHub does not return, or a format not read (pnpm-lock, Pipfile.lock), goes to a human; production churn above `lockfile_line_threshold` (ceiling 400) goes to a human | `lockfile_unrelated_moves`, `lockfile_unparsed`, `lockfile_churn` | D3 churn and its dev-only control; D4 unrelated move, no diff |
| nothing outside dependency metadata | every changed file must be a manifest or lockfile; in a workflow or `action.yml`, every changed line must be a `uses:` pin; the PR may not edit the workflow that runs this triage; an update to `dependabot/fetch-metadata` itself goes to a human | `non_dependency_file`, `non_dependency_change`, `triage_chain` | D4 source file, workflow line, caller edited, the triage action |
| trivial revert | squash merge (one commit) and the scope rules above | — | D1 (`--auto --squash` asserted), D7 |
| full evidence retained | step summary, `decision.json` artifact (90 days), the PR comment | — | D6 on every case |

**Escalate to a human** (section 6): majors, security-sensitive libraries, platform/runtime upgrades,
auth/crypto/network packages, anything changing service behaviour -- every one is a rule above.
"Anything changing service behaviour" is not machine-decidable in general; the kit approximates it
with the protected classes, the breaking-change signal and the scope rules, and errs towards a human.

**Fail closed, always.** fetch-metadata refusing (a commit on the branch that is not Dependabot's),
the PR's files or the base branch's protection being unreadable, an update type it cannot read, a
github-actions version it cannot parse: each is `human_review` with the reason, never a merge.

### The reference estate's `dependabot-security-check.yml` (FUTURE_WORK section 6)

Section 6 records that the reference estate gates on a hand-set `GITHUB_ADVANCED_SECURITY_ENABLED`
secret projected into a step output, and that this kit deliberately does **not** copy it: a secret
someone sets is a declaration that goes stale silently. The triage follows that ruling. Nothing here
is switched by a declared "GHAS enabled" flag. The only secret is `METADATA_TOKEN`, a credential for
fetch-metadata's alert and compatibility lookups, and its absence is recorded as a fact about the
EVIDENCE (`security.linkage: not_established`), never read as "no advisory". A supplied token whose
lookup finds nothing is `none_found`; an advisory linked is `established`.

---

## 2 · Why `pull_request_target` is the safe trigger here

GitHub documents two patterns and they differ on exactly the point that matters.

- Under **`pull_request`**, "Workflow runs triggered by Dependabot pull requests run as if they are
  from a forked repository, and therefore use a read-only `GITHUB_TOKEN`. These workflow runs cannot
  access any secrets." ([workflow syntax: permissions for workflow runs triggered by Dependabot](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax)).
  GitHub's own Dependabot page shows an auto-merge example on `pull_request` with a `permissions:`
  block ([Automating Dependabot with GitHub Actions](https://docs.github.com/en/code-security/dependabot/working-with-dependabot/automating-dependabot-with-github-actions)),
  and the troubleshooting page says the `permissions` key can raise the token ([Troubleshooting Dependabot on GitHub Actions](https://docs.github.com/en/code-security/dependabot/troubleshooting-dependabot/troubleshooting-dependabot-on-github-actions)).
  The pages disagree; a design should not depend on which one is current.
- More importantly, under `pull_request` **the workflow file is the PR's own copy**. Dependabot's
  github-actions updates rewrite `.github/workflows/*`, including the caller of this triage and its
  pin of the kit. That run would execute the PROPOSED action SHAs and the PROPOSED kit version, with
  a write token, while deciding whether to merge itself.
- Under **`pull_request_target`** the workflow runs "in the context of the default branch of the base
  repository", and since 2025-12-08 the workflow file is always taken from the default branch
  ([GitHub changelog, 2025-11-07](https://github.blog/changelog/2025-11-07-actions-pull_request_target-and-environment-branch-protections-changes/)).
  The PR cannot alter the code that judges it. fetch-metadata's own documentation uses
  `pull_request_target` for auto-merge for this reason (write token, `contents` and `pull-requests`
  write) ([dependabot/fetch-metadata README at v3.1.0](https://github.com/dependabot/fetch-metadata/tree/25dd0e34f4fe68f24cc83900b1fe3fe149efef98)).
- GitHub's warning for `pull_request_target` is about RUNNING PR CODE: "Running untrusted code on the
  `pull_request_target` trigger may lead to security vulnerabilities ... Avoid using this event if
  you need to build or run code from the pull request" ([events that trigger workflows](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows)).
  **This workflow checks out nothing.** It reads the PR through the API, as data (file list and
  diffs, the body, fetch-metadata's parse of Dependabot's commit), and every PR-derived value reaches
  a script through `env:` or a file, never an expression in `run:` (`tests/lint_injection.py`; proof D8).
  It uses no cache.

Further guards:

- The job runs only when the **PR author** is `dependabot[bot]`; `github.actor` changes on a re-run
  or a human push and is not used. fetch-metadata's default verification (left on, proof D1) refuses
  a PR whose commits are not all Dependabot's, and that refusal is a `human_review`, not a merge.
- `permissions: {}` at the top. `classify` holds `contents: read, pull-requests: read`; only
  `auto-merge` holds `contents: write` (enabling auto-merge requires it); `human-review` holds
  `pull-requests: write, issues: write` (labels); `close` holds `pull-requests: write`. No job runs
  third-party code with a write token: fetch-metadata (pinned by full SHA, `# v3.1.0`) runs in the
  read-only job.
- A caller that uses `pull_request` is refused loudly (`wrong_trigger`, the job fails; proof D5).

---

## 3 · Enabling it in a repository

1. **Allow auto-merge.** Settings > General > Pull Requests > "Allow auto-merge". CLI:
   `gh api -X PATCH repos/OWNER/REPO -F allow_auto_merge=true`. Without it the auto-merge job fails
   and comments on the PR saying so (proof D7); nothing merges.
2. **Protect the default branch with required status checks** (classic protection or a ruleset):
   require the tests and the job that fails on the kit's security verdict. Without required checks
   every PR goes to a human (`no_required_checks`). Name those checks in the caller's
   `required_checks` exactly as a PR shows them (for a reusable call: `<caller job> / <job name>`,
   for example `security / Security gate` -- INFERRED from GitHub's naming of called jobs; read the
   names off a real PR's checks list).
3. **Enable Dependabot** alerts and security updates (Settings > Code security), and commit a
   `.github/dependabot.yml` (the kit's own is an example; keep fixture paths in `exclude-paths`).
4. **Copy `templates/dependabot-triage.yml`** to `.github/workflows/dependabot-triage.yml`, pin the
   kit by full commit SHA, set `required_checks`, and add your own runtime-critical packages (and the
   kit repository itself) to `critical_packages`.
5. **Optional:** a fine-grained token or GitHub App token with "Dependabot alerts: read" as a
   repository secret (`DEPENDABOT_METADATA_TOKEN`), so security updates are linked to their advisory
   and a protected package's security fix gets the urgent label. Without it, protected packages still
   go to a human, but not marked urgent.
6. **Reviews.** If branch protection requires an approving review, an auto-merge waits for one: the
   kit deliberately does not approve on anyone's behalf. Use CODEOWNERS for the review routing;
   `review_team` is a convenience, and a request the token cannot make is reported, not hidden.
7. **Merge queue.** GitHub's docs note `GITHUB_TOKEN` cannot add a PR to a merge queue; on a queued
   branch, auto-merge needs a different token. Not supported by this workflow yet.

### Inputs (all policy is caller data; every input can only send MORE to a human)

| input | default | meaning |
|---|---|---|
| `required_checks` | `""` | checks that must be required on the base branch; empty sends everything to a human |
| `critical_packages` | `""` | globs ADDED to the built-in protected list |
| `critical_ecosystems` | `""` | ecosystems ADDED to docker, docker-compose, helm, terraform, devcontainers |
| `auto_merge_update_types` | `patch,minor` | `patch`, or empty for none; anything above the ceiling is refused |
| `lockfile_line_threshold` | `400` | lower only; above 400 is refused |
| `excluded_paths` | `tests/consumer-fixture/**` | globs ADDED to the default; matching PRs are closed |
| `min_compatibility_score` | `""` | optional 1-100 floor; needs the token |
| `review_team`, `review_label`, `urgent_label` | `""`, `needs-human-review`, `urgent-security-review` | names only |
| secret `METADATA_TOKEN` | none | Dependabot alerts read, for the lookups |

Outputs: `action` (`auto_merge`, `human_review`, `close`, `none`) and `rule`.

---

## 4 · What is NOT established

- **Provenance/signature of the new package version** (section 6 criterion): no check exists; recorded
  as `not_established` in every decision. Closing it means a registry-signature step (for npm,
  `npm audit signatures` over the PR's lockfile) run WITHOUT installing or executing the package --
  which under `pull_request_target` must be designed carefully, and is not done here.
- **Security linkage without a token**: a Dependabot security update for a non-protected package is
  merged like any other passing update; for a protected one it goes to a human but is not urgent.
- **The vulnerability and malicious-package criteria are delegated**, not computed: they hold only
  if the consumer makes the kit's security gate a required check and names it.
- **pnpm-lock.yaml and Pipfile.lock** are not read package by package; such updates go to a human.
- **"Changes service behaviour"** is approximated, not decided (section 1).
- **Nothing here has run on GitHub** (section 6).

---

## 5 · Proof

`python3 tests/prove_dependabot_triage.py` (in `self-test.yml`). It extracts the workflow's evidence,
decision and action steps as shipped and runs them under bash with a `gh` shim answering from
fixtures. D1 structure and least privilege; D2 the template; D3 the owner's eight cases and controls;
D4 every fail-closed path; D5 the trigger and author; D6 the record; D7 the exact `gh` commands;
D8 PR text stays data. It failed first: with no workflow, then with no template.

---

## 6 · Hosted test plan (for the coordinator, on the owner's public `hello-world`)

Read 2026-10-22 through the API (VERIFIED): `<test-owner>/hello-world` is public, default branch
`master`, **unprotected**, `allow_auto_merge: false`; it consumes the kit from the public mirror
`<test-owner>/<public-mirror>` by SHA; two open Dependabot PRs exist (#4 `web/`, #5 `app/`), both
on its deliberately vulnerable fixture paths. **Ask the owner before steps 1, 2 and 4**: they change
the repository's settings and would close #4 and #5.

0. Export this lane to the public mirror and note the commit SHA (`<KIT_SHA>`).
1. Settings: allow auto-merge (`gh api -X PATCH repos/<test-owner>/hello-world -F allow_auto_merge=true`).
2. Add `.github/workflows/triage-probe-check.yml`: `on: pull_request`, one job `probe`
   (`runs-on: ubuntu-latest`, `steps: - run: sleep 90`). Protect `master` requiring the status check
   `probe` (no review requirement, so an armed auto-merge is decided by the check alone). Do not
   require the fixture's security gate: its findings are planted.
3. Add probe manifests and a dependabot entry for each:
   - `triage-probe/npm/package.json`: `devDependencies: {"ms": "2.1.2", "chalk": "4.1.2"}` and
     `dependencies: {"express": "4.18.2"}` (exact pins; no lockfile).
   - `triage-probe/fixture/package.json`: `devDependencies: {"ms": "2.1.1"}`.
   - `.github/workflows/triage-probe-actions.yml` (`on: workflow_dispatch`) with
     `uses: actions/checkout@<full SHA of v4.1.0> # v4.1.0`.
   - `.github/dependabot.yml`: npm for `/triage-probe/npm` and `/triage-probe/fixture`
     (`groups` off, so each dependency gets its own PR); github-actions for `/` with
     `ignore: [{dependency-name: "actions/checkout", update-types: ["version-update:semver-major"]}]`
     so the bump stays inside v4.
4. Add `.github/workflows/dependabot-triage.yml` from the template, `uses:
   <test-owner>/<public-mirror>/.github/workflows/reusable-dependabot-triage.yml@<KIT_SHA>`,
   `required_checks: "probe"`, `excluded_paths: "triage-probe/fixture/**,app/**,web/**"` (hello-world
   is itself a scanner fixture). Commit to `master`, then trigger Dependabot (Insights > Dependency
   graph > Dependabot > "Check for updates", or wait for the schedule).
5. Expect, and record each run id:

   | PR | expected `action` / `rule` | what to observe |
   |---|---|---|
   | ms 2.1.2 -> 2.1.3 (dev, patch) | `auto_merge` / `all_conditions_met` | auto-merge armed at once; the PR stays OPEN until `probe` passes (about 90 s), then squash-merged |
   | chalk 4.1.2 -> 5.x | `human_review` / `major_update` | labelled `needs-human-review`, one comment saying it is a major, auto-merge not armed |
   | express 4.18.2 -> 4.x | `human_review` / `critical_package` | label and comment; not merged |
   | actions/checkout v4.1.0 -> v4.x (SHA) | `auto_merge` (or `human_review` / `triage_chain` if Dependabot groups it with the caller workflow) | the new pin is a full SHA |
   | ms 2.1.1 in `triage-probe/fixture` | `close` / `excluded_path` | closed, with the comment |
   | #4, #5 on their next event | `close` / `excluded_path` | closed, with the comment |

6. Negative controls: (a) push an empty commit to the ms PR's branch as a human: fetch-metadata
   refuses, expect `human_review` / `metadata_unverified`, and the earlier auto-merge switched off;
   (b) temporarily change the caller's trigger to `pull_request` and re-run: expect the classify job
   to fail with `wrong_trigger`; (c) remove the `probe` requirement and re-run a patch PR: expect
   `human_review` / `no_required_checks`.
7. Record the run ids in `tests/reconcile_validation.py` (`dependabot-merge-hosted`) and close the
   deferral; lower `MAX_ACCEPTED_DEBT` back to 3.
