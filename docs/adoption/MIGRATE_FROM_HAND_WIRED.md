# Before you run kit init on a repository that was wired by hand earlier

For a repository wired to the kit by copying files by hand (the earlier work packages' "test repository setup"
pages, from the first package through Release 5's candidate), before its first `kit init`. Nothing here changes
a setting; every step is yours to run. **Do not delete anything a person customised**: when in doubt, keep it, and
kit init will list it rather than overwrite it.

## 1. How kit init treats what is already there (the lock file)

`kit init` keeps `.kit/kit-init.lock.json`: the SHA-256 of every file (a CODEOWNERS only when kit init wrote the whole file) it wrote last
time. On every run:

| what kit init finds at a path it manages | what it does |
|---|---|
| nothing | writes it (`created`) |
| exactly what it would write | leaves it (`unchanged`) |
| a file whose hash equals the lock's record (kit init wrote it, nobody edited it) | replaces it with the new version (`updated`) |
| **a file the lock does not record** (copied by hand, or there before kit init), or one edited since | **keeps it byte for byte and lists it** (`KIT_INIT_HUMAN_EDIT_PRESERVED`); to take the kit's version, delete the file and run kit init again |
| `.github/workflows/security.yml` that kit init did not write, while kit init writes `build-deploy.yml` (a deploying repository) | keeps it and names a conflict to resolve: two security callers would run the whole suite twice (KDEC-033); you delete one |
| **any CODEOWNERS** (`.github/CODEOWNERS`, the root `CODEOWNERS` or `docs/CODEOWNERS`; GitHub uses the first it finds) | **never changed** (owner, 2026-11-07). kit init proposes its lines in `.kit/CODEOWNERS.proposed` and flags, by line, every existing rule that would decide a kit path instead (the LAST matching rule wins, so the kit lines go at the end). With no CODEOWNERS anywhere it writes a complete default from your organisation's approver teams, or, with `--codeowners customise`, a draft for you to finish |
| `.kit/zone-readiness.json` | never written by kit init (it is AppSec's); left alone |

So a leftover hand-copied file is never lost: the worst case is that kit init keeps your copy and tells you.

## 2. Every file the earlier pages told you to add by hand, and what to do with it

| file in the repository | added by | keep or delete before kit init | why |
|---|---|---|---|
| `.github/workflows/security.yml` copied from the **work overlay's** pipeline template | every earlier test-repository page (step 2) | **keep** in a repository that uses the work overlay | kit init writes the neutral caller; the overlay's caller adds the overlay's own gate (its Sonar, ZAP and WordPress steps). kit init lists it as kept. In a repository that will NOT use the overlay, delete it and let kit init write the neutral one |
| `.github/workflows/security-<org>.yml` copied from the overlay's workflow | every earlier page (step 2) | **keep** with the file above | kit init does not manage it; the overlay caller calls it |
| `.github/workflows/build-deploy.yml` copied from `templates/build-deploy.yml` | the deploy steps ("later", section 5 of those pages) | **delete** unless you edited it (an edited one: keep, and compare it with what kit init writes on a scratch branch) | kit init writes it with exactly the permissions the pinned kit requests (Release 4 added `deployments: write` and `pull-requests: read`) |
| `.github/workflows/kit-api.yml` copied from `templates/kit-api.yml` | the kit API section | **delete** unless edited | the Release 5 kit API needs `deployments: read`; a copy from Release 4.1 fails at startup. `kit init --with-api` writes the right one |
| `.github/workflows/dependabot-triage.yml` copied from `templates/dependabot-triage.yml` | the Dependabot section | **keep** if you set `required_checks` or `critical_packages`; otherwise delete | `kit init --with-triage` writes the template as shipped; your settings would be lost if you deleted an edited copy |
| `.github/dependabot.yml` written by hand | the Dependabot section | **keep** | kit init keeps a pre-existing one and runs the configuration check on it, naming every fix |
| `.github/workflows/kit-init.yml` copied for the button | the Release 5 candidate page (test repository B) | delete if it is unchanged from the template; kit init writes its own | either way works; kit init keeps an edited copy |
| the files a `kit init --dry-run` wrote on test repository B (`.github/...`, `.kit/environments.json`, `.kit/settings.json`, `.kit/ADOPTION_CHECKLIST.md`, `.kit/kit-init.lock.json`) | the Release 5 candidate page, section 6 | **delete them all together, the lock included**, or keep them all together | the lock and the files belong together: files without their lock are treated as a person's (kept), a lock without its files is simply rewritten |
| your CODEOWNERS (with the lines from `developer-safety/codeowners/CODEOWNERS.zone-readiness`, or a block an earlier kit init appended) | the readiness attestation step; the Release 5 candidate's kit init | **keep** | kit init never changes it: copy the proposed lines from `.kit/CODEOWNERS.proposed` to its **end** yourself, and replace an earlier kit-init block with them (the checklist names it) |
| `.kit/zone-readiness.json` | AppSec, outside a landing zone | **keep** | AppSec's attestation; kit init never writes it |
| `.security/policy-registration.json` | the policy register page | **keep** | the repository's own tightening; kit init never writes it |

## 3. Settings set by hand (not files), and whether they still fit

kit init never changes a setting; these are yours to keep, move or remove.

| setting | set by | what to do now |
|---|---|---|
| `JIRA_HOST`, `JIRA_PROJECT` as **repository** variables | step 3 of every earlier page | keep while testing; for good, set them at organisation level and delete the repository copies (a repository value shadows the organisation's: [SETTINGS_PRECEDENCE.md](SETTINGS_PRECEDENCE.md)) |
| `KIT_APPROVER_POOLS`, `KIT_APP_TEAM` repository variables | the Release 5 candidate's kit init checklist | **delete** once the organisation has an org overlay: the overlay governs them and a wider value is refused (`ENVIRONMENT_GOVERNED_SETTING_LOOSENED`); a value that only narrows the pools may stay |
| `KIT_CLOUD` as a **repository or organisation** variable | the Government steps | move it to **each deploy environment**, or leave it unset when the org overlay maps the clouds; a value that disagrees with the overlay is refused before sign-in (`AZURE_CLOUD_CONFLICTS_WITH_ORG`) |
| the environments `dev`, `test`, `uat`, `prod`, `build`, `ticketing`, `ticketing-test` and their secrets | the deploy and ticket steps | keep; compare uat and prod with `.kit/environments.json` after kit init (reviewers, Prevent self-review, deployment branch) |
| a ruleset on the default branch requiring the three check names | step "Required checks" | keep; add code-owner review once the approver teams own the governed paths ([BRANCH_PROTECTION_SETTINGS.md](BRANCH_PROTECTION_SETTINGS.md)) |
| the push ruleset from `apply-push-ruleset.sh` | the leak-gate step | keep |

## 4. Every connector by name: keep, rename, remove or new

"Connectors" are everything a repository has wired for the kit: secrets, variables, environments and files (mostly
the caller workflows). Names only; never put a value anywhere but the setting itself. kit init's checklist
inventories the ones it can see (the files always; environment, secret and variable names with `--inventory-api`
and a token that may list them, otherwise it says so) and says what each is for.

| name | kind | keep / rename / remove / new | note |
|---|---|---|---|
| `.github/workflows/security.yml` (the overlay's pipeline) | file | keep (overlay repositories) / remove (neutral ones) | section 2 |
| `.github/workflows/security-<org>.yml` | file | keep | the overlay pipeline calls it |
| `.github/workflows/build-deploy.yml`, `kit-api.yml` | file | remove unless edited; kit init writes them | section 2 |
| `.github/workflows/dependabot-triage.yml`, `.github/dependabot.yml` | file | keep when customised | section 2 |
| `.github/workflows/dependabot-config-check.yml`, `kit-init.yml` | file | **new** (kit init writes them) | |
| `.kit/environments.json`, `.kit/settings.json`, `.kit/ADOPTION_CHECKLIST.md`, `.kit/kit-init.lock.json`, `.kit/CODEOWNERS.proposed` | file | **new** (kit init's own) | a dry run's copies: keep all or remove all |
| `.kit/zone-readiness.json`, `.security/policy-registration.json` | file | keep | AppSec's / the repository's tightening |
| `CODEOWNERS` (any of the three places) | file | keep; add the proposed lines at the end | never changed by kit init |
| `dev`, `test`, `uat`, `prod`, `build` | environment | keep; compare with `.kit/environments.json` | uat/prod: a non-empty reviewers rule, Prevent self-review on (unless the org's small-team mode applies) |
| `ticketing`, `ticketing-test`, `external-findings-review` | environment | keep | |
| any other environment name | environment | keep and class it in `.kit/environments.json`, or remove if nothing deploys there | an unclassed name is refused at every tier |
| `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` | variable (or secret) | keep **in each environment**; remove repository or organisation copies | one identity per environment |
| `KIT_RESOURCE_GROUP`, `KIT_APP_NAME`, `KIT_ENVIRONMENT_TIER`, `KIT_ACR_LOGIN_SERVER`, `KIT_IMAGE_REPOSITORY` | variable | keep (vended per environment; the registry and image at repository level) | |
| `KIT_CLOUD` | variable | keep **in each deploy environment**; remove a repository or organisation copy when the org overlay maps the clouds | a value that disagrees with the overlay is refused |
| `KIT_APPROVER_POOLS`, `KIT_APP_TEAM` | variable | remove once the org overlay names them (a narrowing value may stay) | governed by the overlay |
| `KIT_SMALL_TEAM_SELF_APPROVAL` | variable | **remove** | never a repository setting: only the org overlay declares small-team mode |
| `KIT_ZONE_READINESS`, `KIT_HANDOFF_ISSUER` and the other `KIT_*` values the landing zone vends | variable | keep (the landing zone's); never set them yourself at uat/prod | |
| `JIRA_HOST`, `JIRA_PROJECT` | variable | keep; move to organisation level for good | either form of `JIRA_HOST` works |
| `JIRA_TOKEN`, `JIRA_EMAIL`, a `JIRA_HOST` secret | secret | keep, in `ticketing` / `ticketing-test` only | |
| `SONAR_TOKEN`, `SONAR_HOST_URL`, `WPSCAN_API_TOKEN`, `WORDFENCE_API_KEY`, `SEMGREP_APP_TOKEN` | secret | keep at organisation level | |
| `KIT_INIT_TOKEN` | secret | **new**, optional | lets the kit-init button open its PR |
| `DEPENDABOT_COMMAND_TOKEN`, `DEPENDABOT_METADATA_TOKEN` | secret | new, only if needed | |
| a name the kit does not read (kit init says "not a kit name") | any | keep if something else uses it; otherwise remove | |
| `overlays/<org>/kit-org-settings.json` | file, in the **kit** repository | **new** (the organisation, once) | the governed settings; [SETTINGS_PRECEDENCE.md](SETTINGS_PRECEDENCE.md) |

No connector is **renamed** by this release: `KIT_CLOUD` keeps its name (no alias), and `JIRA_HOST` accepts either form.

## 5. The order

1. On a branch: delete only the files sections 2 and 4 say to remove, and commit that by itself; remove the settings
   section 4 marks **remove** in Settings (a person's step; kit init never changes a setting).
2. Run `kit init --dry-run` (or the button with no token) and read its output: every `kept` line is a file of yours
   it did not overwrite; every `RESOLVE` line is a conflict you settle in this branch.
3. Read `.kit/ADOPTION_CHECKLIST.md`; do what applies; open the pull request.
4. After the merge, run kit init again: it should say `KIT_INIT_UNCHANGED`.
