# Getting started in 1 hour

For a developer wiring a repository to the secure CI/CD kit for the first time. You need no security
background. At the end of the hour your repository runs the kit's security gate on every pull request, at
the **crawl** level: it reports what it finds, and blocks only the few things that must never ship (a
committed secret, a vulnerability attackers are actively exploiting, a known-malicious package).

If something here does not work, write it down in your team's friction log
([PILOT_FRICTION_LOG_TEMPLATE.md](PILOT_FRICTION_LOG_TEMPLATE.md)): every stuck point is a fix we owe.

## Minutes 0-10: run `kit init`

`kit init` looks at your repository, works out what it is (Python, Node, .NET, Java, PHP, Go, a static site,
a container, Terraform, Bicep, or several at once) and writes everything the kit needs, pinned to one exact
version of the kit. It opens **one pull request**. It never writes a secret and never changes a setting.

**Option A: the button (no tools on your machine).** Copy the kit's `templates/kit-init.yml` to
`.github/workflows/kit-init.yml` in your repository, replace `YOUR_ORG` and the `0000...` with the kit
repository and the commit SHA your platform team gives you, and merge it. Then **Actions > Kit init > Run
workflow**. Pick the deploy shape (or leave `auto`), and name your AppSec and platform teams
(`@your-org/team`) if you know them.

- With the repository secret `KIT_INIT_TOKEN` set (a token for this repository only, with Contents, Pull
  requests and Workflows read and write), the run opens the pull request itself.
- Without it, the run uploads the files as the artifact `kit-init-files`: download it, unzip it at the root of
  a new branch, commit, and open a pull request with `.kit/ADOPTION_CHECKLIST.md` as its description. (A
  workflow's own token can never push a change to `.github/workflows/`, which is why the token is needed for
  the automatic pull request.)

**Option B: the command line.** From a clone of the kit at the commit you want to pin:

```bash
python3 -m pip install PyYAML
python3 scripts/kit_init.py --target ../my-app --kit-repo YOUR_ORG/secure-cicd-kit \
    --appsec-team @your-org/appsec --platform-team @your-org/platform
# add --dry-run to write the files without a branch or pull request
# on a <tenant>.ghe.com host, gh needs GH_HOST=<tenant>.ghe.com (kit init sets it for its own calls)
```

**The host is detected** (owner, 2026-11-07): `github.com` (a personal repository, default branch `main`) and
`<tenant>.ghe.com` (work) both work. kit init reads the host from `--host`, from the repository's own workflow
(`GITHUB_SERVER_URL`, `GITHUB_API_URL`), from the `origin` remote and from your organisation's overlay, and derives
the API address (`api.github.com` or `api.<tenant>.ghe.com`) and the sign-in issuer from it. Another host is
refused by name (`KIT_INIT_HOST_UNSUPPORTED`); two sources that disagree are refused too (`KIT_INIT_HOST_MISMATCH`).

**Your organisation's overlay is applied on day one.** If your organisation keeps an overlay in its kit repository
(`overlays/<org>/kit-org-settings.json`), kit init takes from it the approver teams (uat/prod reviewers and the
CODEOWNERS of `.github/workflows/`, `.kit/` and `id-mappings.json`), the adoption level, the Azure cloud of each
environment and where tickets go. You may make these stricter, never looser
([SETTINGS_PRECEDENCE.md](SETTINGS_PRECEDENCE.md)). Wired a repository by hand before? Read
[MIGRATE_FROM_HAND_WIRED.md](MIGRATE_FROM_HAND_WIRED.md) first.

If kit init refuses, it says why in one sentence with the fix, e.g. "kit init did not recognise any language
or deploy type in this repository, so it wrote nothing. [KIT_INIT_STACK_UNKNOWN]". Every refusal is in
[ERRORS.md](../errors/ERRORS.md#kit_init_state).

**What the pull request adds:**

| file | what it is |
|---|---|
| `.github/workflows/security.yml`, or `build-deploy.yml` (a container), or `build-deploy-static.yml` (a static site) | the kit's gate (and for a deploy, the build and the deploys), pinned by SHA, each job granting exactly the permissions it needs |
| `.github/workflows/dependabot-config-check.yml` and `.github/dependabot.yml` | every manifest kept up to date; a pull request that adds a manifest nobody updates fails with the fix |
| `.github/workflows/kit-init.yml` | re-running kit init later is a button |
| `.github/workflows/dependabot-triage.yml`, `kit-api.yml` | only if you asked for them |
| `.github/CODEOWNERS` (only when you have none) | a complete default: the approver teams own the workflows, `.kit/` and `id-mappings.json`, AppSec and platform the Dockerfiles and infrastructure code. **An existing CODEOWNERS is never changed**: kit init proposes its lines in `.kit/CODEOWNERS.proposed` and names any of your rules that would override them. `--codeowners customise` gives you a draft instead |
| `.kit/environments.json`, `.kit/settings.json`, `.kit/ADOPTION_CHECKLIST.md` | the environments to create (a spec, not applied), your answers, and the checklist |

Re-running kit init is safe: it updates its own files and **keeps any file you edited** (it lists them).

## Minutes 10-25: the checklist (some of it needs an admin)

The pull request's description is the checklist of things only a person can do. Every item says **what** to
do, **how** (the exact command) and **why it matters**. Typically:

1. **Create the environments and their reviewers** (dev, test, uat, prod; `gh api` commands included). uat
   and prod always name a reviewer, and the deploy waits until that person says yes, even for a push straight
   to main. The reviewer comes from platform or security and is not you; with no approver pools at all (a team
   of one), the environment still names a person who is not the deployer. Ask a repository admin if you are not
   one. Without an org overlay, set the variables the checklist names (`KIT_APPROVER_POOLS`, and `KIT_APP_TEAM` if
   you gave `--app-team`); with one, leave them unset. An environment with a name other than dev, test, uat or
   prod needs a `class` in `.kit/environments.json`, or the deploy refuses it (`ENVIRONMENT_UNCLASSED`).
   **A team of two or fewer with no approver group** may approve its own deployments only when the organisation
   declares it in its overlay, as a recorded, time-boxed exception; the run then says
   **SMALL_TEAM_SELF_APPROVAL** ([SETTINGS_PRECEDENCE.md](SETTINGS_PRECEDENCE.md) section 4). **"Prevent self-review" is a GitHub *environment* protection setting.** It governs only the approval of deployment jobs that target that environment. It does not change branch protection, rulesets or pull request review rules, and the kit never sets it: kit init only prints the command, and the deploy only reads it back and checks it.
2. **Add the OIDC federated credentials** (`az ad app federated-credential create ...`, one per
   environment). There is no client secret anywhere; the deploy signs in with a short-lived token. On a
   `<tenant>.ghe.com` host the issuer is `https://token.actions.<tenant>.ghe.com`; the checklist already
   says so.
3. **Readiness attestation** if you deploy outside a landing zone: AppSec writes `.kit/zone-readiness.json`.
4. **Set the variables and secrets** it lists (names only: you set the values in Settings > Secrets and
   variables > Actions; never in a file).

None of these block your first crawl run of the security gate: you can merge and continue, and finish the
deploy steps before your first deploy.

## Minutes 25-40: the first crawl run

Merge the pull request. The gate runs on the push to `main` (and from now on, on every pull request). Open
**Actions > the run**. A first run takes a few minutes; scanners for every language it found run in parallel.

- **Green with notes** (`PROCEED_WITH_ADVISORY`) is the normal first result at crawl: it found things worth
  fixing that do not block.
- **Red** at crawl means one of the few blocking classes, or that the kit could not finish a scan. Read the
  next section.

## Minutes 40-50: reading the result

At the **top of the run page**, each problem has an annotation whose title is a plain sentence, followed by
the fix and the state name in brackets. In each job's summary, **"What happened, in plain words"** says the
same with why it matters and a link. For example:

> The security scan stopped this change: a check found something that must be fixed first (for example a
> committed secret or a known-exploited vulnerability). **[BLOCKED]**
> Fix: Open the run summary, find the blocking finding (file and line), fix it in your branch and push. A
> committed secret must also be revoked and rotated, not just deleted.

The whole catalogue, for every refusal the kit can show: [docs/errors/ERRORS.md](../errors/ERRORS.md).
Search it for the word in brackets. If the plain sentence did not help, tell the platform team and log it:
that entry gets rewritten.

Below the plain words, the summary lists every finding (file, line, rule) and every scanner's state. A
scanner that could not run says so; it is never shown as clean.

## Minutes 50-60: next steps

1. **Require the gate:** once the first run is green, ask an admin to require `security / Security gate` on
   `main` ([BRANCH_PROTECTION_SETTINGS.md](BRANCH_PROTECTION_SETTINGS.md)). Not before: a required check that
   has never passed blocks every pull request.
2. **Fix or ticket the notes** from your first run while they are cheap.
3. **Your first deploy** (container or static site): finish checklist items 1-4, then merge a change; it deploys
   to dev and test. uat and prod are promoted from test by a dispatch with the test run's id, and a reviewer
   from platform or security approves it the same business day ([ROLLOUT_PLAN.md](ROLLOUT_PLAN.md)).
4. **Log your time**: add the `first_green` row (minutes from starting kit init to the green run) and any
   `stuck` rows to the friction log.

## How long you stay at crawl

Every repository **starts at crawl** unless your organisation's overlay sets a stricter level (owner, 2026-11-07).
The optimal crawl is **4 weeks**; the summary flags it after **8 weeks** (prefer no more than two months); **six
months** (26 weeks) is the hard maximum, where it is escalated to the platform lead. Nothing moves you to walk, or
keeps you at crawl longer, by itself: a person changes the policy register. kit init writes the dates into the
checklist.

## FAQ

**Do I have to write a positive and a negative test for every change I make to my application?**
No. The positive/negative proof pairing is required **only for changes to the kit itself (and to the evidence
harness)**: a new or changed kit control must prove both that it passes the normal path and that it refuses the
bad one (`tests/check_positive_negative_pairing.py`, `docs/assurance/POSITIVE_NEGATIVE_MATRIX.md`). That check
runs only in the kit's own self-test (`.github/workflows/self-test.yml`); none of the reusable workflows your
repository calls runs it, or any of the kit's `tests/` scripts. **Your application code goes through the
scanners and the gate only**: the security workflow scans it, and the gate decides at your adoption level. Your
own tests are yours to choose (a deploy promotes only what passes your `KIT_E2E_TEST_COMMAND`).

**Can I approve my own pull request?** No. GitHub does not let a pull request's author approve it. The small-team
mode is about **deployments** only.

**Why does the kit refuse a variable I set in my repository?** A repository value shadows the organisation's
(GitHub uses the most specific level). For the few settings that decide who approves production and which cloud a
deploy signs in to, the organisation's overlay decides and your value may only make it stricter
([SETTINGS_PRECEDENCE.md](SETTINGS_PRECEDENCE.md)).

## Where to go next

- [ROLLOUT_PLAN.md](ROLLOUT_PLAN.md): the waves, the report-only weeks, who approves releases and how fast.
- [USAGE.md](USAGE.md): every reusable workflow and input. [SETUP.md](SETUP.md): identities and OIDC in depth.
- [DEPENDABOT_IN_YOUR_REPO.md](DEPENDABOT_IN_YOUR_REPO.md) and, if you turn it on,
  [AUTOMERGE_RISKS_AND_ROLLOUT.md](AUTOMERGE_RISKS_AND_ROLLOUT.md).
