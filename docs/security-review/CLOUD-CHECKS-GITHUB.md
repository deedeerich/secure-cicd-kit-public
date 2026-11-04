# Cloud checks — GitHub (read-only)

```
Truth State:  Authored, not field-tested (2026-11-03). Endpoints are GitHub REST API v3 as documented;
              on a GHE.com tenant add --hostname <tenant>.ghe.com to every gh call (KDEC-027: the
              token goes only to the host that issued it).
Use with:     CAB-CHANGE-SAFETY-STEPS.md steps 4 and 5. GitHub is where the kit's own gates live:
              a change to these settings is a change to the gate (step 5.1).
Read-only:    every call is a GET. Several answers are admin-only (classic branch protection,
              push protection on a private repository, the audit log); a non-admin token gets 403 or
              404, which is UNKNOWN, never "off". Ask the repository or organisation admin role for
              the answer instead of taking admin to review.
Placeholders: <owner>/<repo>, <org>, <env>, <branch> (the default branch), <id>.
```

**What changed, and who:** the organisation audit log (organisation owners; Enterprise Cloud for the
API) — `gh api "orgs/<org>/audit-log?phrase=repo:<owner>/<repo>"`; otherwise the repository's
**Settings** pages show current state only, so read them before the change and after it.

---

## H1 · Rulesets and branch protection

```sh
gh api repos/<owner>/<repo>/rulesets --jq '.[] | {id, name, target, enforcement}'
gh api repos/<owner>/<repo>/rulesets/<id> --jq '{enforcement, bypass_actors, conditions, rules: [.rules[].type]}'
gh api repos/<owner>/<repo>/rules/branches/<branch> --jq '.[] | {type, parameters}'     # the rules that actually apply
gh api orgs/<org>/rulesets --jq '.[] | {id, name, target, enforcement}'
gh api repos/<owner>/<repo>/branches/<branch>/protection                                # classic protection; admin only
```

UI: the repository → **Settings** → **Rules** → **Rulesets**; **Branches** for classic protection.

- **Safe:** the default branch requires a pull request and the `Security gate` check (for example
  `security / Security gate`); `enforcement` `active`; bypass actors limited to a named admin role;
  the push ruleset refusing secret-file paths is `active` (`docs/adoption/LEAK_GATES.md`).
- **Ask:** a new bypass actor; a required review count lowered.
- **Stop:** a ruleset moved to `evaluate` or `disabled`; the `Security gate` requirement removed or
  renamed so nothing reports it (a required check naming no job blocks forever; one renamed away
  silently stops being required); a bypass for the requester. In the same change as code, this is the
  change editing its own gate (step 5.1).

## H2 · Environments: reviewers, self-review, branch policy, readiness

```sh
gh api repos/<owner>/<repo>/environments/<env> \
  --jq '{protection_rules, deployment_branch_policy, can_admins_bypass}'
gh api repos/<owner>/<repo>/environments/<env>/deployment-branch-policies --jq '.branch_policies[] | {name, type}'
gh api repos/<owner>/<repo>/environments/<env>/variables --jq '.variables[] | {name, value}'   # KIT_ENVIRONMENT_TIER, KIT_ZONE_READINESS, ...
gh api repos/<owner>/<repo>/environments/<env>/secrets --jq '.secrets[] | {name, updated_at}' # names only
```

UI: **Settings** → **Environments** → the environment.

- **Safe:** at uat and prod, required reviewers from the approver list, `prevent_self_review` true,
  deployment branches limited to the default branch; `KIT_ENVIRONMENT_TIER` matches reality;
  `KIT_ZONE_READINESS` issued by the landing zone or by AppSec as a recorded attestation (S7).
- **Ask:** `can_admins_bypass` true (an admin bypass leaves no approval: `RELEASE_APPROVAL_ABSENT`).
- **Stop:** reviewers removed, self-review allowed, or the branch policy opened (`404` on the policies
  call means no custom policy: every branch may deploy); `KIT_ZONE_READINESS` set to `READY` by the app
  or deploy team (a test fixture only); a production environment re-tiered below uat (S6).

## H3 · Actions permissions

```sh
gh api repos/<owner>/<repo>/actions/permissions                       # enabled, allowed_actions
gh api repos/<owner>/<repo>/actions/permissions/selected-actions      # when allowed_actions is "selected"
gh api repos/<owner>/<repo>/actions/permissions/workflow              # default_workflow_permissions, can_approve_pull_request_reviews
gh api orgs/<org>/actions/permissions
```

UI: **Settings** → **Actions** → **General**.

- **Safe:** `default_workflow_permissions` `read`; `can_approve_pull_request_reviews` false; allowed
  actions limited (selected, or the organisation's list), and the kit's own pins are full SHAs.
- **Stop:** the default token switched to `write`; Actions allowed to approve pull requests (a
  workflow could then approve its own change: separation of duties).

In the workflow diff of this change, also stop on: `permissions: write-all` or a new `contents: write`
/ `id-token: write` at workflow level (rule R3); `pull_request_target` that checks out the pull request
head; a new `secrets: inherit` (R8); a `uses:` on a branch or tag outside `trusted_orgs`; a kit pin moved
with no reason (S9).

## H4 · Secrets: names, scope, visibility

```sh
gh api repos/<owner>/<repo>/actions/secrets --jq '.secrets[] | {name, updated_at}'
gh api orgs/<org>/actions/secrets --jq '.secrets[] | {name, visibility, updated_at}'
gh api orgs/<org>/actions/secrets/<name>/repositories --jq '.repositories[].full_name'    # who can read a "selected" org secret
gh api repos/<owner>/<repo>/dependabot/secrets --jq '.secrets[].name'
```

- **Safe:** cloud access is OIDC (no client secret, no long-lived key); a credential that grants access
  to an environment lives in that environment's secrets, behind its reviewers (`docs/adoption/SETUP.md`
  section 2.1).
- **Ask:** a new organisation secret with `visibility` `all` (every workflow in every repository can read it).
- **Stop:** a new long-lived cloud key or a personal access token added as a secret for a workload; a
  deploy credential moved from environment scope to repository or organisation scope.

## H5 · Deploy keys

```sh
gh api repos/<owner>/<repo>/keys --jq '.[] | {id, title, read_only, created_at}'
```

- **Safe:** none, or read-only keys with a named owner.
- **Stop:** a new key with `read_only` false (it can push, around pull requests unless a ruleset
  stops it) that the ticket does not name.

## H6 · GitHub Apps and webhooks

```sh
gh api orgs/<org>/installations --jq '.installations[] | {app_slug, repository_selection, permissions}'   # organisation owners
gh api repos/<owner>/<repo>/hooks --jq '.[] | {id, active, url: .config.url, events}'                      # repository admin
gh api repos/<owner>/<repo>/collaborators --jq '.[] | select(.permissions.admin) | .login'
```

- **Safe:** the app's permissions match its stated job; `repository_selection` `selected`.
- **Ask:** a new app with `contents: write`, `administration`, `workflows` or `secrets` permission.
- **Stop:** a third party with write access nobody cleared (E5); an AI agent's app that can approve,
  merge or change environments (E9; `ai_review` is advisory only); a webhook to an external URL that
  receives repository content.

## H7 · Organisation 2FA and SSO

```sh
gh api orgs/<org> --jq '{two_factor_requirement_enabled}'       # organisation owners
```

UI: the organisation → **Settings** → **Authentication security** (2FA; SAML SSO on Enterprise Cloud).

- **Stop:** the 2FA requirement turned off, or SSO enforcement removed, as part of an app change: that
  is an organisation change for the organisation owner (E2, E3), not this ticket.

## H8 · Audit log streaming and security features

```sh
gh api repos/<owner>/<repo> --jq '.security_and_analysis'
```

UI: the enterprise → **Settings** → **Audit log** → **Log streaming** (Enterprise Cloud).

- **Safe:** secret scanning and push protection unchanged where licensed; the push ruleset `active`
  where they are not (`leak_gates` in the run shows each layer).
- **Stop:** secret scanning, push protection or audit-log streaming switched off by the change (SB-5,
  SB-6).
