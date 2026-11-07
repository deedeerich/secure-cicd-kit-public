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
| a block in `CODEOWNERS` | AppSec and platform review changes to the kit's settings, the workflows, Dockerfiles and infrastructure code |
| `.kit/environments.json`, `.kit/settings.json`, `.kit/ADOPTION_CHECKLIST.md` | the environments to create (a spec, not applied), your answers, and the checklist |

Re-running kit init is safe: it updates its own files and **keeps any file you edited** (it lists them).

## Minutes 10-25: the checklist (some of it needs an admin)

The pull request's description is the checklist of things only a person can do, each with the exact
command. Typically:

1. **Create the environments and their reviewers** (dev, test, uat, prod; `gh api` commands included). uat
   and prod need a reviewer from platform or security who is not you: the kit refuses a production deploy
   nobody else approved. Ask a repository admin if you are not one.
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

## Where to go next

- [ROLLOUT_PLAN.md](ROLLOUT_PLAN.md): the waves, the report-only weeks, who approves releases and how fast.
- [USAGE.md](USAGE.md): every reusable workflow and input. [SETUP.md](SETUP.md): identities and OIDC in depth.
- [DEPENDABOT_IN_YOUR_REPO.md](DEPENDABOT_IN_YOUR_REPO.md) and, if you turn it on,
  [AUTOMERGE_RISKS_AND_ROLLOUT.md](AUTOMERGE_RISKS_AND_ROLLOUT.md).
