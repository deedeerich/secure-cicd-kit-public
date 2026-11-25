# Obtain separately — what the kit cannot see, and whom to ask

```
Truth State:  Authored, not field-tested (2026-11-03). KDEC-036 G7 and G11: no build; the kit
              cannot read these with the run's own token, so this sheet says where they come from.
Use:          before sign-off, for every row the app's review depends on. Ask by ROLE, in writing,
              and record the answer as Read (you saw the setting or the log) or Stated
              (SIGN-OFF.md). A row nobody answered is "Not established", never clean.
```

The run's token is the job's own `GITHUB_TOKEN`: it reads the repository, not the organisation, and
not settings only an administrator can read. Where the kit reads such a setting and cannot, it says
`UNKNOWN` (never `ON`); where it cannot read it at all, it says nothing, and this sheet is the reminder.

## G7 — settings only an administrator can read

| What | Where the kit shows it | Why it can be UNKNOWN or absent | Obtain from (role) | Ask for |
|---|---|---|---|---|
| Branch protection on the default branch (required checks, required reviews, who may bypass, force-push) | `leak_gates.branch_gate`; the summary row "Branch gate" | the protection endpoint needs repository admin; rulesets are read, classic protection may not be | repository administrator | a screenshot or `GET /repos/{o}/{r}/branches/{b}/protection` answer, and the ruleset list with bypass actors |
| Push protection and secret scanning | `leak_gates.push_protection`, `leak_gates.secret_scanning`; the platform capability rows | the security-and-analysis object is admin-only; licensing is the organisation's | repository administrator (licence: organisation owner) | the repository's Code security settings page |
| Push rulesets and their bypass list | `leak_gates.push_ruleset` | a ruleset's bypass actors are not shown to a read token | repository administrator | the ruleset JSON, bypass list included |
| Environment protection: who may bypass, deployment branch policy, admin bypass allowed | `environment_protection` (required reviewers and self-review are read) | "allow administrators to bypass" and custom protection rules are not in the read answer | repository administrator | the environment's settings page for uat and prod |
| Who wrote `KIT_ZONE_READINESS`, `KIT_ENVIRONMENT_TIER`, `KIT_HANDOFF_ISSUER`, `KIT_HOSTING_KIND` | `readiness_source`, `tier_source` (the declared marker only) | a variable's API answer has no author | organisation owner or audit-log reader (the security team where delegated) | the audit-log entries `environment.update_actions_variable` / `repo.update_actions_variable` for those names |
| Team membership of an approver list group, and of the requester | `weakening_check` (the list name or group is matched, the people are not) | resolving members needs organisation read access | organisation owner, or the team's maintainer | the members of the group named in `weakening_authority` on the date of the run |
| Organisation SSO enforcement, IP allow list, token policies | `token_preflight` (a refusal is named; a policy that allowed the token is not) | organisation settings | organisation owner | the organisation's authentication and IP allow-list settings |
| Actions settings: allowed actions, artifact and log retention maximum, fork pull-request approval, default token permissions | the evidence retention requested (`evidence_retention`) | organisation and repository Actions settings are admin-only | organisation owner, repository administrator | the Actions settings pages; the artifact retention maximum caps `KIT_EVIDENCE_RETENTION_DAYS` |
| Runner groups and which repositories may use self-hosted or private-network runners | `runner_label` as passed | runner groups are organisation settings | organisation owner (the platform team where delegated) | the runner group and its repository access |
| Deletions of the durable release record | `release_record`, `release_record_ref` | a token with `deployments: write` can mark a deployment inactive and delete it | organisation owner or audit-log reader | the audit-log entries for deployment deletion on the repository |
| Who can change the kit copy (CODEOWNERS, branch protection on the kit host repository) | `kit_watermark` (what the copy received) | the kit host repository's settings | the kit host repository's administrator | its CODEOWNERS, branch protection and recent merges |

## G11 — an automation's runtime (Tines 3B, or another automation platform)

The kit scans what an automation keeps in a repository (for example through GitSync) and records the
token a kit API call came from. It does not see the automation running.

| What | Obtain from (role) | Ask for |
|---|---|---|
| The automation's run history: what it changed, when, on whose behalf | the automation platform's owner | the platform's audit log or run log for the review period |
| The credentials it holds, their scope and where they are stored | the automation platform's owner, with the identity owner (E3) | the credential list with scopes; proof none is in the synced code (`secret_gate` `PASS`) |
| Every system it calls or changes | the automation's owner | the list, with the data each receives (E4, E5) |
| Whether it acts without a person approving each action | the automation's owner; the AI agent governance owner (E9) | the approval design; `MOD-AGENT` applies if not |
| Changes made to it outside the synced repository (in the platform's editor) | the automation platform's owner | the platform's change history against the repository's |
| The token it dispatches the kit's API with | the automation's owner, with the repository administrator | the token's scope; it is the requester of every release it asks for and may not approve one (S6) |

## Rules

- **Read beats Stated.** A screenshot, an API answer or a log entry is Read; "it's on" is Stated.
- **An unanswered row is Not established.** Sign-off lists it; it never becomes clean by silence.
- **The person who changed the setting cannot be its only witness.** Ask the role that can read the
  audit log, not the app team, for who wrote a value.
