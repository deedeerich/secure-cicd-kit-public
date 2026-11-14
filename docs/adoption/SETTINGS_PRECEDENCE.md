# Settings precedence: which level each kit setting belongs at, what wins, and what the kit does when it is shadowed

Status: owner rulings of 2026-11-07, built (KDEC-044 records the approver-group standard, PROPOSED). Every
GitHub fact below is quoted from GitHub's documentation with its address and the date it was read. Nothing
here changes a setting; every command is a person's to run.

## 1. The rule GitHub applies (read 2026-11-07)

**Variables.** "If a variable with the same name exists at multiple levels, the variable at the lowest level
takes precedence. For example, if an organization-level variable has the same name as a repository-level
variable, then the repository-level variable takes precedence. Similarly, if an organization, repository, and
environment all have a variable with the same name, the environment-level variable takes precedence."
(<https://docs.github.com/en/actions/reference/workflows-and-actions/variables>, retrieved 2026-11-07)

**Secrets.** "If a secret with the same name exists at multiple levels, the secret at the lowest level takes
precedence", the repository's over the organisation's, and "the environment-level secret takes precedence"
over both. Secret names "must be unique to the repository, organization, or enterprise where they are created"
and "are case insensitive when referenced."
(<https://docs.github.com/en/actions/reference/security/secrets>, retrieved 2026-11-07)

So the order is **environment beats repository beats organisation**: the most specific level wins. The
reference names the enterprise as a place a secret can be created but its precedence sentences cover the
organisation, repository and environment only; **the kit puts no setting at enterprise level.**

**What follows for the kit.** A repository can *shadow* an organisation value just by defining the same name,
and a running job cannot tell which level a value came from (GitHub gives the job the winning value, not its
origin). A setting that decides who may approve a production release, or which cloud a deploy signs in to,
therefore cannot be trusted from a variable alone.

## 2. Governed settings come from the org overlay, and a repository may only tighten them

The settings below are **governed**. They live in the org overlay inside the organisation's own copy of the
kit, `overlays/<org>/kit-org-settings.json` (copy `templates/kit-org-settings.example.json`; validate with
`python3 scripts/org_settings.py validate overlays/<org>/kit-org-settings.json`). The deploys read it from the
kit copy they run from (the composite `.github/actions/org-settings`, delivered by `$/` at the commit the
caller pins; the rollback reads it from its own kit checkout), so a pull request in an application repository
cannot change it. A change reaches a repository when the repository moves its kit pin.

| governed setting | overlay key | read by | a consumer value that LOOSENS it is refused as |
|---|---|---|---|
| approver pools (who may approve uat/prod) | `approver_pools` | the deploys' and the rollback's protection step | `ENVIRONMENT_GOVERNED_SETTING_LOOSENED` (a pool the overlay does not name, in `KIT_APPROVER_POOLS` or `.kit/settings.json`); naming a subset is a tightening and is honoured |
| the app team, its size, and small-team self-approval | `app_teams.<owner/repo>` | the protection and approval steps | `ENVIRONMENT_GOVERNED_SETTING_LOOSENED` (another team in `KIT_APP_TEAM`; any `KIT_SMALL_TEAM_SELF_APPROVAL` or `small_team_self_approval` in the repository) |
| default adoption level and the crawl clock | `adoption`, `repositories.<owner/repo>.adoption_level` | kit init | `KIT_INIT_GOVERNED_SETTING_LOOSENED` (a level below the overlay's) |
| environment classes | `environment_classes` | the protection step | a class never lowers a production name, wherever it comes from (owner O-42a) |
| the Azure cloud of each environment | `azure_clouds` | the deploys, the build and the rollback before sign-in | `AZURE_CLOUD_CONFLICTS_WITH_ORG`; with two clouds declared and the environment unmapped, `AZURE_CLOUD_UNSET_FOR_ENVIRONMENT` |
| ticket routing and tags | `ticket_routing` | kit init (written into `.kit/settings.json` and the checklist) | the central policy register's `ticket_routing` keeps deciding at run time (`docs/architecture/JIRA_AUTH_AND_ROUTING.md`) |
| CODEOWNERS of the kit-governed paths | `codeowners` | kit init | a person's edit outside the kit-init block is theirs; the block itself is kit init's |

With **no overlay** for the organisation (`ORG_OVERLAY_ABSENT`) the kit behaves exactly as before: the
variables and `.kit/settings.json` decide, a variable over the file. An overlay that cannot be read
(`ORG_OVERLAY_INVALID`) or two naming one organisation (`ORG_OVERLAY_AMBIGUOUS`) are refused at uat and prod,
never read as absent.

## 3. CODEOWNERS and rulesets: what layers and what does not

- **CODEOWNERS exists only per repository.** GitHub reads one file per repository, from "the `.github/`,
  root, or `docs/` directory of the repository", searching "in that order" and using "the first one it
  finds"; "each CODEOWNERS file assigns the code owners for a single branch in the repository", and "the
  CODEOWNERS file must be on the base branch of the pull request"
  (<https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners>,
  retrieved 2026-11-07). The page describes no organisation- or enterprise-level CODEOWNERS file, and there is
  none. **So the org's approver teams own the kit-governed paths by a block kit init writes into each
  repository's own CODEOWNERS** (`/.github/workflows/`, `/.kit/`, `/id-mappings.json`; KDEC-044), and a
  ruleset requires code-owner review.
- **Rulesets layer, and all of them apply.** "A ruleset does not have a priority. Instead, if multiple rulesets
  target the same branch or tag in a repository, the rules in each of these rulesets are aggregated. If the
  same rule is defined in different ways across the aggregated rulesets, the most restrictive version of the
  rule applies. As well as layering with each other, rulesets also layer with protection rules targeting the
  same branch or tag." The page's example aggregates an organisation's ruleset with a repository's: "The rules
  from each source are aggregated, and all rules apply."
  (<https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets>,
  retrieved 2026-11-07). Enterprise rulesets target organisations, repositories and branches
  (<https://docs.github.com/en/enterprise-cloud@latest/admin/enforcing-policies/enforcing-policies-for-your-enterprise/enforcing-policies-for-code-governance>);
  the pages read do not state the enterprise-to-organisation layering in words, so the kit's statement that an
  enterprise ruleset layers the same way is **by the aggregation rule above, not by a separate sentence**.
  The result for the kit: an organisation or enterprise ruleset that requires `security / Security gate` and
  code-owner review cannot be loosened by a repository's own ruleset. The approver teams are **never** a
  ruleset bypass actor (KDEC-044).

## 4. Self-approval of a deployment, and why it is not self-approval of a pull request

- **Deployments.** An environment's required reviewers hold a job until "one of the required reviewers" approves.
  With **Prevent self-review** on, "users who initiate a deployment cannot approve the deployment job", "even if
  they are a required reviewer"
  (<https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments>, retrieved
  2026-11-07); the review page says the same: "you will not be able to approve a deployment from a workflow run
  you initiated" when the environment prevents self-approvals
  (<https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/review-deployments>).
  **With it off, the pages do not say in words that the initiator may approve**; they describe the setting only
  as what stops the initiator, which is how the kit reads it. The same pages hold on GHE.com: the data-residency
  feature overview lists no limitation of environments or deployment protection rules
  (<https://docs.github.com/en/enterprise-cloud@latest/admin/data-residency/feature-overview-for-github-enterprise-cloud-with-data-residency>,
  retrieved 2026-11-07). **UNVERIFIED by a hosted run** on either host: the first small-team deploy is that test.
- **Plans.** "If you are on a GitHub Free, GitHub Pro, or GitHub Team plan, required reviewers are only
  available for public repositories" (the deployments page above). A personal **private** repository on those
  plans cannot have required reviewers at all, so a uat/prod deploy there is refused
  (`ENVIRONMENT_REVIEWERS_ABSENT`); test the gating on a public repository, or on an organisation with
  GitHub Enterprise.
- **Pull requests.** "Pull request authors cannot approve their own pull requests"
  (<https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/reviewing-changes-in-pull-requests/approving-a-pull-request-with-required-reviews>,
  retrieved 2026-11-07). So the small-team mode applies to **deployments only**; a small team that requires an
  approving review on `main` needs a second person or a review count of 0 with the solo profile's compensating
  controls (`BRANCH_PROTECTION_SETTINGS.md`).

**Only pool reviewers on uat and prod (external review 2026-11-07, R09).** GitHub waits for ONE approval from ANY listed reviewer. A list that holds the security team and one app developer lets that developer approve production alone. So when approver pools are named, every reviewer of a uat or prod environment must be a pool team or member; anyone else is refused before sign-in as `ENVIRONMENT_REVIEWER_OUTSIDE_POOL`. Then whoever approves is from the pool, because GitHub accepts approvals only from listed reviewers. (The small-team mode, for known solo developers only, is the declared exception.)

**"Prevent self-review" is a GitHub *environment* protection setting.** It governs only the approval of deployment jobs that target that environment. It does not change branch protection, rulesets or pull request review rules, and the kit never sets it: kit init only prints the command, and the deploy only reads it back and checks it.

**Only for KNOWN solo developers (owner ruling, 2026-11-07).** Self-approval is never inferred from a team
size. The org overlay names the GitHub accounts or orgs whose developers are known to work alone, and those
developers' logins, in `known_solo_developers` (for example `{"<your-personal-account>": ["<your-login>"]}`).
The app team must list `members`, and every member must be a listed login of the repository's owner. Anything
else is refused as `SMALL_TEAM_SELF_APPROVAL_NOT_KNOWN_SOLO_DEVELOPER`. A repository cannot add itself: the list
lives only in the org overlay.

**The small-team mode (owner 2026-11-07).** For a team of two or fewer with no external approver group: the
uat/prod environments keep their required-reviewers rule with a non-empty list (the wait happens, even for the
person who pushed), but Prevent self-review may be off so the developer approves their own deployment. It is a
**declared weakening**, declared only in the org overlay, with the five fields `approved_by`, `ref`, `date`,
`reason`, `expires`, time-boxed by `review_days` (default 90). It is refused when the declared team is larger
than two or when the overlay names approver pools. In force, the run summary and the release record say
**SMALL_TEAM_SELF_APPROVAL** in plain words, and the release approval still has to quote the digest
(`RELEASE_APPROVAL_SMALL_TEAM_SELF_APPROVAL`).

```json
"app_teams": {"<org>/<repo>": {"team": "@<org>/<devs>", "size": 2,
  "small_team_self_approval": {"approved_by": "<role that approved the weakening>", "ref": "<decision or ticket>",
    "date": "2026-11-07", "reason": "two developers, no external approver group", "expires": "2027-02-05",
    "review_days": 90, "external_approver_group_available": false}}}
```

## 5. KIT_CLOUD: Azure only, per environment

`KIT_CLOUD` (`commercial` or `gov`) names an **Azure** cloud. No AWS job reads it
(`tests/check_kit_cloud_scope.py`; the kit has no AWS sign-in job today). Because an organisation-wide value
would classify every tenant alike, and a job cannot see which level a variable came from:

- with an overlay that declares **two** Azure clouds, each environment's cloud comes from
  `azure_clouds.environments` (`<owner>/<repo>:<env>` first, then `<env>`); an unmapped environment is refused
  before sign-in (`AZURE_CLOUD_UNSET_FOR_ENVIRONMENT`), and a call or a `KIT_CLOUD` that disagrees is refused
  (`AZURE_CLOUD_CONFLICTS_WITH_ORG`);
- with **one** declared cloud, it is every environment's (`AZURE_CLOUD_ORG_SINGLE`);
- with **no overlay**, the environment's `KIT_CLOUD` decides (set it **in each deploy environment**, never at
  organisation level), else the call's input, else commercial.

The deploys, the build and the rollback sign in to the cloud this decided (`steps.org_settings.outputs.azure_cloud`).
The name stays `KIT_CLOUD`. An alias `KIT_AZURE_CLOUD` was considered and **not** added: two names for one
setting can disagree, and the binding proof holds one name exactly.

## 6. Every kit variable and secret: where it belongs, what wins, what the kit does when it is shadowed

**Level** is where the kit expects the value. **Wins** is GitHub's rule applied to that name. **Shadowed** is
what happens when a more specific level defines the same name. "Org overlay" means the value is governed in
section 2 and the variable is at most a tightening.

| name | kind | level | wins | if shadowed |
|---|---|---|---|---|
| `KIT_APPROVER_POOLS` | variable | **org overlay** `approver_pools`; the variable only narrows | the overlay | a wider set is `ENVIRONMENT_GOVERNED_SETTING_LOOSENED` |
| `KIT_APP_TEAM` | variable | **org overlay** `app_teams`; the variable only names the same team | the overlay | another team is `ENVIRONMENT_GOVERNED_SETTING_LOOSENED` |
| `KIT_SMALL_TEAM_SELF_APPROVAL` | variable | **never set it**: only the org overlay declares the mode | n/a | any value is `ENVIRONMENT_GOVERNED_SETTING_LOOSENED` |
| `KIT_CLOUD` | variable | **each deploy environment**, or the org overlay's map | environment > repo > org | with two clouds declared the overlay decides; disagreement is refused (section 5) |
| `KIT_AZURE_OIDC_AUDIENCE` | variable | repository (Government only) | environment > repo > org | a repository value replaces the organisation's; gov sign-ins only |
| `KIT_ENVIRONMENT_TIER`, `KIT_RESOURCE_GROUP`, `KIT_APP_NAME`, `KIT_ACR_LOGIN_SERVER`, `KIT_IMAGE_REPOSITORY` | variable | each deploy environment, written by the landing zone | environment | a call that disagrees with the environment is refused by the bind step |
| `KIT_HANDOFF_ISSUER`, `KIT_HOSTING_KIND`, `KIT_RELEASE_BLOCK`, `KIT_ZONE_READINESS`, `KIT_SETTING_KEYS`, `KIT_TARGET_LEASE_ACCOUNT`, `KIT_EDGE_ENDPOINT` | variable | each environment, written by the landing zone only | environment | a repository-level value reaches every environment that has none: the deploy records the source (`readiness_source` refuses a self-set readiness at uat/prod) |
| `KIT_ZONE_READINESS_TEST_FIXTURE` | variable | a test environment only | environment | never on an environment serving users |
| `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` | variable (secret accepted) | each environment (one identity per environment; `build` for the build) | environment; a secret of the same name wins over the variable | a repository or organisation value would give every environment one identity: never set them there |
| `KIT_E2E_TEST_COMMAND`, `KIT_DAST_COMMAND`, `KIT_PROMOTION_PREDECESSOR`, `KIT_STATIC_BUILD_COMMAND` | variable | repository | repo > org | the repository's value is used; an organisation value is a default |
| `KIT_EVIDENCE_RETENTION_DAYS` | variable | organisation (or repository) | repo > org | floored at 90, capped at 400 whatever the level |
| `ATTESTATIONS_AVAILABLE` | variable | organisation | repo > org | a repository `true` on a plan without attestations is refused at promotion (no signed provenance) |
| `KIT_FEED_MIRROR_URL`, `KIT_FEED_MIRROR_RUNNER`, `KIT_FEED_MIRROR_ACCOUNT`, `KIT_FEED_MIRROR_MAX_AGE_HOURS`, `KIT_FEED_MIRROR_FALLBACK`, `KIT_SCANNER_IMAGE_REGISTRY` | variable | organisation | repo > org | a stale or tampered mirror is refused by name whatever the level (`FEED_MIRRORS.md`) |
| `KIT_CONSUMER_PATH_ON_PUSH`, `KIT_CONSUMER_PATH_SCHEDULE` | variable | the kit repository only | repo | n/a |
| `KIT_INTEGRATION_IDENTITIES` | variable | organisation | repo > org | a repository value changes which identities a `via` label is checked against: keep it at organisation level (KDEC-043) |
| `JIRA_HOST` | variable (and optional secret) | organisation variable; the secret in `ticketing`/`ticketing-test` | secret first, then variable; environment > repo > org | either form works (KDEC-040); a repository value points that repository's tickets elsewhere |
| `JIRA_PROJECT` | variable | organisation; `ticketing-test` for the sandbox | environment > repo > org | the test environment's sandbox key wins in test runs, by design |
| `JIRA_MIN_DIGITS`, `JIRA_MAX_DIGITS`, `JIRA_REAL_PROJECTS` | variable | organisation | repo > org | a repository may narrow; test runs refuse a real project (`TICKETING_TEST_TARGETS_REAL_PROJECT`) |
| `JIRA_AUTH_MODE`, `JIRA_CLOUD_ID`, `JIRA_STAMP_FIELD`, `JIRA_EPIC_ID`, `JIRA_CALIBRATION_ISSUE`, `JIRA_TYPE_CLUSTER`, `JIRA_TYPE_INSTANCE`, `JIRA_TRANSITION_DONE`, `JIRA_TRANSITION_REOPEN`, `JIRA_PRIORITY_LADDER` | variable | each ticketing environment | environment | each environment names its own project's fields |
| `TICKET_CREATE_CEILING`, `TICKET_CALL_BUDGET`, `TICKET_RETRY_CEILING`, `TICKET_INSTANCE_THRESHOLD`, `TICKET_DEGRADED_RUN_THRESHOLD`, `TICKET_STAMP_LABEL`, `TICKET_REPO`, `TICKET_CALIBRATION_REF` | variable | each ticketing environment | environment | bounded by the reconciler whatever the level |
| `AZDO_ORG_URL`, `AZDO_PROJECT`, `AZDO_STAMP_FIELD`, `AZDO_EPIC_ID`, `AZDO_CALIBRATION_ITEM`, `AZDO_TYPE_CLUSTER`, `AZDO_TYPE_INSTANCE`, `AZDO_STATE_DONE`, `AZDO_STATE_REOPEN` | variable | each ticketing environment (Azure DevOps backend) | environment | as Jira |
| `FRESHSERVICE_HOST`, `FRESHSERVICE_WORKSPACE_ID`, `FRESHSERVICE_REQUESTER_ID`, `FRESHSERVICE_STAMP_FIELD`, `FRESHSERVICE_CALIBRATION_TICKET`, `FRESHSERVICE_MARK_MODE`, `FRESHSERVICE_TAG_RETRIES` | variable | each ticketing environment (Freshservice backend, KDEC-043) | environment | as Jira |
| `KIT_API_OPERATIONS`, `KIT_API_DEPLOY_ENVIRONMENTS`, `KIT_API_TICKET_BACKEND`, `KIT_API_BRANCH_ENVIRONMENTS`, `KIT_API_APPROVED_TOOLS`, `KIT_API_EVIDENCE_STORES`, `KIT_API_REVIEW_APPROVER_SOURCE`, `KIT_API_REVIEW_APPROVER_LIST` and the numbers `KIT_API_EXTENSION_*`, `KIT_API_VENDOR_ADVISORY_*`, `KIT_API_NOFIX_*`, `KIT_API_EXCEPTION_MAX_DAYS`, `KIT_API_REVIEW_MAX_AGE_DAYS`, `KIT_API_VERIFICATION_REMINDER_DAYS`, `KIT_API_FUZZY_TITLE_PERCENT` | variable | repository (the API serves one repository) | repo > org | writes stay off until a repository names them; numbers are bounded by the API |
| `ZAP_TARGET` | variable | repository | repo > org | the test site only; never set it at organisation level |
| `JIRA_TOKEN`, `JIRA_EMAIL`, `AZDO_PAT`, `GH_TICKET_TOKEN`, `FRESHSERVICE_API_KEY` | secret | the protected ticketing environment | environment | an organisation or repository copy is outside the environment's protection: keep them in the environment only |
| `SONAR_TOKEN`, `SONAR_HOST_URL`, `AIKIDO_CLIENT_ID`, `AIKIDO_CLIENT_SECRET`, `WPSCAN_API_TOKEN`, `WORDFENCE_API_KEY`, `SEMGREP_APP_TOKEN`, `NVD_API_KEY` | secret | organisation, visible to the repositories that use them | repo > org | a repository copy replaces the organisation's for that repository; rotate in one place |
| `KIT_SURVEY_TOKEN` | secret | the one repository that runs the org survey (`.github/workflows/kit-survey.yml`) | repo | read-only across the organisation; behind a protected environment; never organisation-wide (risk R-36) |
| `KIT_INIT_TOKEN`, `DEPENDABOT_COMMAND_TOKEN`, `DEPENDABOT_METADATA_TOKEN`, `KIT_API_TEAM_READ_TOKEN` | secret | the one repository that uses it | repo | scoped to that repository; never organisation-wide |
| `GOVERNANCE_READ_ORG_TOKEN` | secret (optional) | the kit repository that runs `governance-gate.yml` | repo | organisation "Members: read" only, to resolve the employer profile's reviewer team; without it only the named `reviewer_logins` count, and with neither a protected change holds (KDEC-059, `docs/operations/GOVERNANCE_PROFILES.md`) |
| `KIT_HARNESS_REPOSITORY` | variable | the kit repository | repo | names the harness repository the pair test reads; with it unset the pair test reports HARNESS_LEG_NOT_RUN, never a pass (KDEC-058) |
| `KIT_HARNESS_APP_CLIENT_ID`, `KIT_HARNESS_APP_PRIVATE_KEY` | variable, secret | the `kit-harness-pair` environment only | environment | a GitHub App with Contents read on the harness repository alone; a repository or organisation copy is outside the environment's protection (KDEC-058, `docs/operations/HARNESS_PAIR_HOSTED.md`) |
| `COMMAND_TOKEN`, `METADATA_TOKEN` | reusable-workflow secret inputs | passed by the caller (`DEPENDABOT_COMMAND_TOKEN`, `DEPENDABOT_METADATA_TOKEN`) | the caller | n/a |

`tests/check_settings_precedence.py` holds this table to the tree: every `vars.*` and `secrets.*` name the
kit's workflows, templates and the work overlay read appears in it.

## 7. Where to look next

- The overlay's every key: `scripts/org_settings.py` (docstring) and `templates/kit-org-settings.example.json`.
- The approver groups standard (PROPOSED): KDEC-044 in the continuity record; `BRANCH_PROTECTION_SETTINGS.md`.
- What the deploy refuses, with the plain words: `docs/errors/ERRORS.md` (`environment_protection`,
  `small_team_self_approval`, `azure_cloud`, `org_settings`).
