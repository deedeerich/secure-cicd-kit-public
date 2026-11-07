# Survey the organisation first, then set it up once

Owner, 2026-11-07: *"A scanner of what's already running in the org first, so it can identify if there's something
that's being done better or needs to be adopted, and we adopt it through the overlays."* And a one-time org setup
that *"sets up what it can and then instructs people on what they need to fill out, how to do it, and why it's
important."* KDEC-045 (PROPOSED).

Two read-only tools and one dispatch-only workflow:

| tool | what it answers | output |
|---|---|---|
| `scripts/kit_survey.py` | What already runs in every repository; how it compares with the kit; how much of the estate the kit supports and secures; where a repository turned the kit off and why | `KIT_SURVEY.csv`, `KIT_SURVEY.md`, `KIT_SURVEY_COMPARISON.md`, `KIT_ADOPTION_INVENTORY.md`, `kit-survey.json` |
| `scripts/kit_org_init.py` | Is the organisation set up for the kit? Per item PASS / ACTION_NEEDED / NOT_ESTABLISHED, with WHAT, HOW and WHY, and a dry-run plan | `ORG_INIT_CHECKLIST.md`, `org-init.json` |
| `.github/workflows/reusable-kit-survey.yml` + `templates/kit-survey.yml` | Both, from the organisation's kit repository, when a person presses Run | the `kit-survey` artifact (14 days) |

**Neither changes anything.** Their client sends GET and has no other method; the proofs run them against a
stand-in that answers any other method 405 and records it. Neither reads a secret value (GitHub never returns
one) and both drop a variable's value the moment it is read: only NAMES reach the reports.

**The reports name private repositories.** The tools refuse to write them inside the kit repository
(`SURVEY_OUT_IN_KIT`); the workflow keeps them as an artifact, never a commit.

## 1. The token

The run's own `GITHUB_TOKEN` sees one repository. The survey needs a **read-only** token across the
organisation, saved as the secret `KIT_SURVEY_TOKEN` in the repository that runs the workflow:

| permission (fine-grained token or GitHub App) | read | what it unlocks | without it |
|---|---|---|---|
| Metadata | read | the repository list | `SURVEY_AUTH_REFUSED` |
| Contents | read | workflow files, CODEOWNERS, Dependabot config, the policy registration, history | `workflows` NOT_ESTABLISHED; adoption NOT_ESTABLISHED |
| Actions | read | workflow state (disabled in the UI) | `workflow_state` NOT_ESTABLISHED |
| Administration | read | branch protection, rulesets, environments, Actions access level and permissions | those columns NOT_ESTABLISHED |
| Secrets, Variables | read | NAMES only | `secret_names` / `variable_names` NOT_ESTABLISHED |
| Organization: Members, Administration | read | approver teams, org variables, Actions policy, workflow token default | org check items NOT_ESTABLISHED |

A permission it lacks shows as **NOT_ESTABLISHED in that column, never as "none"**. That is the rule the whole kit
follows: never "nothing there" when it could not look.

## 2. Run it

**In the organisation (recommended):** copy `templates/kit-survey.yml` to the org's kit repository at
`.github/workflows/kit-survey.yml`, replace `YOUR_ORG`, pin the kit by commit SHA (and `kit_ref` to the same
commit), fill `platform_team` and `appsec_team`, add the `KIT_SURVEY_TOKEN` secret, then
**Actions -> Kit survey -> Run workflow**. Download the `kit-survey` artifact when it finishes.

**By hand from a laptop** (no Claude Code needed; Python 3 and PyYAML):

```bash
export GH_TOKEN=<a read-only token>          # or: export GH_TOKEN=$(gh auth token)
python3 scripts/kit_survey.py   --owner YOUR_ORG --host github.com --out ~/kit-survey     # or --host <tenant>.ghe.com
python3 scripts/kit_org_init.py --owner YOUR_ORG --host github.com --out ~/kit-survey \
    --platform-team platform --appsec-team appsec
```

The host is never assumed (KDEC-027): `--host` names it, or `GITHUB_API_URL` / `GH_HOST`. An API URL that is not
the named host's, a repository answered for on another host, or a next-page link to another host stops the survey
with `SURVEY_HOST_MISMATCH` and the token goes nowhere else.

## 3. Reading the survey

**`KIT_SURVEY.md` / `.csv`** — one row per repository: workflows (and which are disabled through the API), the
actions they use and which are not pinned by SHA, the scanners already running (by action name or command:
CodeQL, Semgrep, gitleaks, TruffleHog, Trivy, OSV-Scanner, dependency review, Grype, Checkov, tfsec, KICS,
hadolint, Bandit, gosec, ESLint, Ruff, actionlint, zizmor, SBOM, attestation, cosign, SonarQube, Snyk, Aikido,
Scorecard, harden-runner, ZAP), branch protection and rulesets, environments with their reviewers, self-review
rule and wait timer, CODEOWNERS, Dependabot config, secret and variable names, the kit callers and the kit commit
they pin, and the deploy targets the workflows imply (azure / aws / gcp / other).

**`KIT_SURVEY_COMPARISON.md`** — per capability in the kit's inventory (the scanners of `capability-floor.json`,
plus pinning, protection, environment approval, CODEOWNERS, Dependabot, OIDC login, workflow linting, provenance,
and the things the kit does not run: signing, DAST, runner hardening, Scorecard, SonarQube, Aikido, Snyk). The
org's practice is read **from its own workflows and settings, never from a kit caller**:

| verdict | meaning |
|---|---|
| `KIT_BETTER` | the org does it but lacks something the kit holds (pinned, on the pull request, blocking, a review rule) |
| `ORG_BETTER` | the org does it with something the kit lacks — credited by repository (a schedule, broader CodeQL queries, signed commits, two approvals, a production wait timer, a Dependabot cooldown) |
| `EQUIVALENT` | the same attributes |
| `ORG_ONLY` | the org does something the kit does not do at all |
| `KIT_ONLY` | only the kit does it |
| `GAP` | neither, and it is on the kit's expected baseline (signing, DAST, runner hardening): **a kit gap to build** |
| `NOT_ESTABLISHED` | no repository's setting could be read |

For every `ORG_BETTER` and `ORG_ONLY` row it writes **"Adopt via overlay"** — where it goes — and **"How to do it
by hand"**, numbered steps a person follows in the browser and a terminal. The rule for where: **proprietary or
vendor practice goes into `overlays/<org>/` only**; the neutral kit takes a change only when it is neutral or
GitHub/Microsoft-native, and only through a KDEC. Credit stays with the team that did it first
(`overlays/<org>/docs/ADOPTED_FROM_ORG.md`).

**`KIT_ADOPTION_INVENTORY.md`** — per repository:

| state | evidence |
|---|---|
| `ADOPTED` (rung) | an active kit security or deploy caller, SHA-pinned, on pull requests, no weakening; the rung from `.security/policy-registration.json` (crawl when none) |
| `PARTIAL` | a caller, but a moving kit ref, no pull-request trigger, a declared weakening (its reason kept), or only non-security kit workflows |
| `TURNED_OFF` | a commit that removed the caller, a job `if: false`, or the workflow disabled through the API — the commit or state is the evidence |
| `NEVER` | no caller now or anywhere in the workflow history, **read in full** |
| `NOT_ESTABLISHED` | the workflows or their history could not be read in full (raise `--history`) |
| `KIT_HOST` | the kit itself |

For a turn-off it keeps the **stated reason** — the commit message (unless it is a UI default such as
"Update security.yml"), the pull request's title and body, or the weakening record — else `REASON_NOT_RECORDED`,
and a **pain point** by keyword (too slow, cost, noise / false positives, blocks delivery, broken / failing,
permissions / setup, replaced by another tool). The pain point is a keyword match, a pointer for a conversation,
not a diagnosis.

The percentages state their **denominator**: repositories that are not archived, not forks and not the kit
(each exclusion counted and named). "Supported" is ADOPTED or PARTIAL; "secured" is ADOPTED. The same two numbers
are given for deploying repositories, with their own denominator. A NOT_ESTABLISHED repository stays in the
denominator and counts neither way.

## 4. The one-time org setup (`ORG_INIT_CHECKLIST.md`)

| id | checks | why it matters |
|---|---|---|
| O1 | the kit repository exists, private or internal | consumers pin it; the public mirror is for hosted self-tests only |
| O2 | its Actions access level lets the org's repositories call it | otherwise the caller says "workflow not found", which reads as a typo (SETUP.md 1.5) |
| O3 | `overlays/<name>/` exists | the org's own practice has a home a kit upgrade never overwrites |
| O4 | the platform and AppSec approver teams exist | uat/prod reviewers from outside the app team (KDEC-042) |
| O5 | `KIT_APPROVER_POOLS` is an org variable; no per-repository variable (KIT_APP_TEAM, AZURE_CLIENT_ID ...) sits at org level | one OIDC identity per deployment per subscription, never one for the org |
| O6 | Actions permissions allow GitHub-owned actions and every action owner the kit pins | a refused action fails the job before any scan |
| O7 | the default workflow token is read-only and cannot approve pull requests | the kit grants per job; a token that approves PRs defeats a review rule |
| O8 | the OIDC issuer for this host, and the org's subject-claim template | a GHE.com tenant has its own issuer; a custom template breaks every federated credential |
| O9 | kit init and its template are in the kit copy | it writes each repository's environments spec and checklist |
| O10 | Dependabot alerts and security updates on for new repositories | free on every plan |
| O11 | GHAS and GitHub secret scanning state | the kit does not need GHAS (below) |

Each ACTION_NEEDED item gives WHAT, HOW (the exact `gh` command, with `GH_HOST` on a GHE.com host, and the browser
path) and WHY. The **dry-run plan** at the end lists every command in order. **Nothing was run**: read each
command, then run it yourself. On a user account the organisation-only items are NOT_ESTABLISHED by name.

**With GHAS off** the kit still runs in full: its gitleaks secret scan blocks in every mode, its gate reads the
scanners' SARIF itself (no Security tab needed), and Dependabot alerts and updates are free. Not available without
it on private repositories: GitHub's own secret scanning and push protection (Secret Protection) and the
code-scanning Security tab (Code Security).

## 5. Limits (UNVERIFIED or not read, said plainly)

- Workflows are read **on the default branch**; a caller only on another branch is not seen.
- Scanners are recognised by action name or command; a scanner wrapped in a script the survey cannot read is not
  seen (it shows as KIT_ONLY for that capability). Add its name to `TOOLS` in `scripts/kit_survey.py`.
- Organisation-level secrets are not listed by the survey (repository level only); the org check reads org
  variable names.
- `dependabot_*_enabled_for_new_repositories` and `secret_scanning_enabled_for_new_repositories` are older fields
  GitHub is replacing with code security configurations; when absent the item is NOT_ESTABLISHED. UNVERIFIED on
  a GHE.com tenant.
- The OIDC subject-claim template endpoint answering 404 is read as "the default". UNVERIFIED for every plan.
- A free-plan private repository answers branch protection with 403: that is NOT_ESTABLISHED, not "none".

## 6. Proofs

`tests/prove_kit_survey.py` (P1-P7, N1-N7, 8 mutants) and `tests/prove_kit_org_init.py` (P1-P5, N1-N6, 6 mutants),
both against `tests/_survey_api_standin.py` on 127.0.0.1 in the github.com and GHE.com shapes; rows in
`docs/assurance/POSITIVE_NEGATIVE_MATRIX.md`; run by self-test.
