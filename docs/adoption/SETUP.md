# Setup — secrets and Azure OIDC

**Every step has both a Portal (GUI) path and a CLI path.** Written for someone who has not set up
workload identity federation before.

## 0 · Fill these in once

Every command and every field below uses these. Substitute your own values — nothing in this document
is specific to any one organization, repository, or tenant.

| Placeholder | Meaning | Example |
|---|---|---|
| `<ORG>` | GitHub organization or username | `contoso` |
| `<REPO>` | Repository consuming the kit | `payments-api` |
| `<ENVIRONMENT>` | GitHub Environment holding the secrets — **omit entirely if using repo-scope secrets** | `prod`, `dev`, `sandbox` |
| `<APP_NAME>` | Entra app registration display name | `gh-payments-api-deploy` |
| `<TEST_RESOURCE_GROUP>` | Throwaway RG for integration testing | `rg-cicdkit-test` |
| `<SUBSCRIPTION_ID>` | Target Azure subscription | from `az account show` |

Shell blocks assume:

```bash
ORG=<your-github-org-or-username>
REPO=<your-repo>
ENVIRONMENT=<your-github-environment>   # omit if using repo-scope secrets
APP_NAME="gh-${REPO}-deploy"
```

---

## 1 · GitHub Environments — create these before anything else

Skip this section entirely if you are using **repo-scope secrets**. If you are using Environments —
and you should, because they are what carries per-environment subscription context — the environment
must exist before you can put secrets in it or point a federated credential at it.

**An Environment gives you three things a repo secret cannot:**

| | |
|---|---|
| **Isolated secret scope** | `dev` holds its own `AZURE_SUBSCRIPTION_ID`. It never sees prod's. That is physical isolation, not a naming convention. |
| **Deployment branch policy** | Which branches may deploy here — enforced by GitHub *before the job starts* |
| **Required reviewers** | Human approval gate before the job runs |

### 1.1 · Create the environment

**GUI:** repo → **Settings → Environments → New environment** → name it → **Configure environment**

**CLI:**
```bash
gh api -X PUT "repos/$ORG/$REPO/environments/$ENVIRONMENT"
```

Then add its secrets (§2):
```bash
gh secret set AZURE_CLIENT_ID --repo "$ORG/$REPO" --env "$ENVIRONMENT"
```

> **Environment secrets do not inherit from repo secrets and do not cross between environments.**
> Every environment needs its own full set. Creating `prod` after `dev` copies nothing.

### 1.2 · Deployment branch policy — "deploy only from main"

This is the correct place to restrict deployments. **Do not** try to enforce it with the federated
credential subject — see the comparison in §4.

**GUI:** **Settings → Environments → `<ENVIRONMENT>` → Deployment branches and tags** → change the
dropdown from *No restriction* to **Selected branches and tags** → **Add deployment branch or tag
rule** → enter `main` → **Add rule**

The dropdown has three states, and two of them are mutually exclusive in the API:

| Dropdown | API |
|---|---|
| No restriction | `deployment_branch_policy: null` |
| **Protected branches only** | `protected_branches: true`, `custom_branch_policies: false` |
| **Selected branches and tags** | `protected_branches: false`, `custom_branch_policies: true` |

> `protected_branches` and `custom_branch_policies` **cannot both be true.** Pick one shape.

**CLI:**
```bash
# enable custom branch policies on the environment
gh api -X PUT "repos/$ORG/$REPO/environments/$ENVIRONMENT" --input - <<'JSON'
{ "deployment_branch_policy": { "protected_branches": false, "custom_branch_policies": true } }
JSON

# allow only main
gh api -X POST "repos/$ORG/$REPO/environments/$ENVIRONMENT/deployment-branch-policies"   -f name='main' -f type='branch'
```

**Verify it stored:**
```bash
gh api "repos/$ORG/$REPO/environments"   --jq '.environments[] | {name, policy: .deployment_branch_policy}'
gh api "repos/$ORG/$REPO/environments/$ENVIRONMENT/deployment-branch-policies"   --jq '.branch_policies[] | {name, type}'
```

A `404` on the second command means **no custom policy is configured** — the environment is open to
every branch. That is a silent default, so check it rather than assuming.

### 1.3 · What enforcement actually looks like

Verified behaviour, not a description. A job declaring `environment: prod` dispatched from a
non-`main` branch, with the policy above in place:

```
Branch "policy-control-test" is not allowed to deploy to prod
due to environment protection rules.
```

- the job runs **0 steps** and lives ~2 seconds
- **no OIDC token is minted**, so Azure is never contacted
- the refusal is visible in the Actions UI, attributed to the protection rule

**If you instead restricted deployments via the credential subject**, the job would start, resolve
secrets, do its work, and *then* fail on `AADSTS700213` — later, more expensively, and with an error
that blames authentication rather than policy.

> A job that fails with **zero steps** has been refused by a protection rule. It is not a broken
> workflow — do not go debugging the YAML.

### 1.4 · Required reviewers (optional)

**GUI:** same page → tick **Required reviewers** → add up to 6 users/teams → **Save protection rules**

**CLI:**
```bash
MY_ID=$(gh api user --jq .id)
gh api -X PUT "repos/$ORG/$REPO/environments/$ENVIRONMENT" --input - <<JSON
{ "wait_timer": 0, "reviewers": [ { "type": "User", "id": $MY_ID } ] }
JSON
```

The run pauses as *Waiting* until approved. Note that **you cannot approve your own deployment** in
organization-owned repos, though you can in a personal one.

---

## 1.5 · Let other repositories consume the kit

**Do this before the first consumer, or nothing works and the error will not tell you why.**

A reusable workflow in a **private** repository is invisible to every other repository until the
*providing* repo opts in. Set it once, on the kit repo — not on each consumer.

The failure mode is the reason this section exists: the caller reports that the **workflow could not
be found**, which reads as a typo in the `uses:` path or a bad ref. Nothing mentions settings, so the
time goes into re-checking the path that was correct all along.

**GUI:** kit repo → **Settings → Actions → General → Access** → choose
*Accessible from repositories owned by the user/organization* → **Save**

**CLI:**
```bash
gh api -X PUT "repos/<ORG>/secure-cicd-kit/actions/permissions/access" -f access_level='organization'
gh api "repos/<ORG>/secure-cicd-kit/actions/permissions/access"      # verify
```

| `access_level` | Who may call it |
|---|---|
| `none` | **nobody** — the default for a private repo |
| `user` | repos owned by the same **personal account** |
| `organization` | repos owned by the same **organization** |
| `enterprise` | other orgs in the same enterprise *(GHEC only)* |

### There is no cross-organization sharing of a private kit

This is a GitHub boundary, not a limitation of the kit. A private repository's reusable workflows
**cannot** be consumed from outside its owning account or organization at all. Two consequences:

- **Each organization hosts its own instance.** Fork or import the kit into `<ORG>/secure-cicd-kit`,
  set `access_level: organization`, and point every repo in that org at *that* copy. This is why
  every environment-specific value is an input — the kit is designed to be instantiated, not
  centrally hosted.
- **Public is the only way to share it beyond one org.** That is a licensing and IP decision, not a
  technical one. Making it public also makes Actions minutes free, which is a real but separate
  consideration.

> A **public** consumer *can* call a **private** kit within the same account, but not the reverse:
> the constraint is on where the *workflow* lives, not the caller.

---

## 2 · Secret inventory

| Secret | Needed by | Required? | What it is |
|---|---|---|---|
| `AZURE_CLIENT_ID` | deploy + build, `azure-login-oidc` | Yes for Azure | App registration (client) ID. An identifier, not a credential — stored as a secret to keep it out of logs. |
| `AZURE_TENANT_ID` | same | Yes | Entra tenant ID |
| `AZURE_SUBSCRIPTION_ID` | same | Yes | Target subscription |
| `NVD_API_KEY` | `reusable-nvd-cve.yml` | Strongly recommended | Free NIST key. Without it the DB update is rate-limited and may take 30+ min. |
| `SEMGREP_APP_TOKEN` | `reusable-security.yml` | Optional | Managed rules / dashboard only. Everything works without it. |

**No client secret exists anywhere in this kit, by design.** If you are creating one for Azure auth,
stop — you are on the wrong path.

### 2.1 · Which SCOPE to store each secret in — and why it is not a style choice

GitHub has three places to put a secret, and for a **reusable** workflow they do not behave alike.

| Scope | How it reaches a reusable workflow | Protection rules | Rotation |
|---|---|---|---|
| **Organization** | `secrets: inherit`, or explicit pass | none | **one place, propagates to every repo** |
| **Repository** | `secrets: inherit`, or explicit pass | none | one place *per repo* — N repos means N rotations |
| **Environment** | **only** if a job **inside the called workflow** declares `environment:` | ✅ approvals, branch policies, wait timers | one place per environment |

**The constraint that surprises people:** a job that calls a reusable workflow (`uses:`) is a
job-level substitution — it never touches a runner. So it **cannot declare `environment:`**, and
`secrets: inherit` does **not** carry environment secrets. Per GitHub's documentation, the
environment must be declared on a job *inside* the called workflow, and the environment secret then
takes precedence over anything the caller passed. That precedence is a security property: a reusable
workflow cannot be handed a credential from a weaker scope than the environment it is running in.

**Consequence — a contract rule for this kit, not a workaround:**

> Any reusable workflow that needs an environment-scoped secret **must expose a `github_environment`
> input** and set `environment: ${{ inputs.github_environment }}` on its job.

`reusable-build-docker`, `reusable-deploy-appservice`, `reusable-deploy-containerapp` and
`reusable-nvd-cve` follow this. `reusable-security` does not, which is why its **optional**
`SEMGREP_APP_TOKEN` must be stored at repository or organization scope rather than environment scope.

#### Choosing the scope

- **Environment** — when the secret needs *gating* or is *bound to a target*. Azure credentials are
  the non-negotiable case: the OIDC federated credential subject literally contains the environment
  name (`repo:<ORG>/<REPO>:environment:prod`). Here the environment is not storage, it is **identity**.
- **Organization** — for a shared credential used by several repositories. This is the right answer
  to secret sprawl: one copy, **rotate once and it touches everything**, scoped to selected repos,
  and no per-repo duplication to drift out of sync.
- **Repository** — single-repo credentials with no gating. Treat as a last resort: it is the scope
  that quietly recreates the same secret in N places and turns rotation into an archaeology exercise.

**Do not scatter credentials at repository scope for convenience.** A secret duplicated across
repositories is a secret nobody can rotate confidently, and "we rotated it everywhere" becomes a
claim rather than a fact.

> ⚠️ Organization secrets require an **organization**. A personal account cannot create them, so on a
> personal account **environment scope is the best consolidation mechanism available**. This is a
> real argument for the organization migration independent of Actions minutes — see
> `ORG_MIGRATION_CHECKLIST`.

### 2.2 · Changing scope later — the cutover

**You are not locked in.** The kit contracts on `github_environment` being *optional*, so the same
workflows run unchanged whether a secret lives at environment, repository or organization scope. The
change-over is configuration, not a rewrite.

#### What moves, and what must not

| Secret | Personal account (today) | After you have an organization |
|---|---|---|
| `NVD_API_KEY` | **Environment** — the only consolidation available | **Organization** — one copy, rotate once, scoped to selected repos |
| `SEMGREP_APP_TOKEN` (optional) | Repository | **Organization** |
| `AZURE_CLIENT_ID` · `AZURE_TENANT_ID` · `AZURE_SUBSCRIPTION_ID` | **Environment** | **Environment — STAYS.** Not a storage choice: the OIDC federated credential subject *contains* the environment name (`repo:<ORG>/<REPO>:environment:prod`). Here the environment is identity, and moving it breaks authentication |

The rule underneath: **move what is merely shared. Keep what is bound to a target or needs gating.**

#### The cutover, in order

**Add the new scope first. Verify. Only then remove the old one.** Never swap in place — the same
discipline that federated credentials demand, and for the same reason: an edit that replaces leaves
you with nothing while you are still assuming you have something.

1. **Create the organization secret**, scoped to the repositories that need it.
2. **Leave the environment secret in place.** Both can exist; the environment secret takes precedence
   inside a job that declares an environment, so behaviour does not change yet.
3. **Stop passing `github_environment`** for that workflow — for a non-gated credential like
   `NVD_API_KEY`, pass an empty value. The called job then has no environment, so the organization
   secret resolves through `secrets: inherit`.
4. **Run it and verify from evidence, not assumption.** For `NVD_API_KEY` the tell is specific: the
   *"no NVD API key is configured"* warning must **not** fire, and the database update must succeed.
   A silent fall-through to the un-keyed path looks like success and takes 20–40 minutes.
5. **Only now delete the environment secret**, and confirm the next run still passes.
6. **Record the change.** Which secrets moved, when, and who owns rotation.

#### What you gain, and the one thing to watch

Rotation becomes a single action that propagates everywhere, instead of a per-repository sweep that
is only ever *believed* to be complete. That is the whole point.

The thing to watch: an organization secret is readable by **every workflow in every repository you
scope it to**. That is the correct trade for a rate-limit API key and the wrong trade for anything
that grants access to an environment. If a secret would be dangerous in the hands of any workflow in
scope, it belongs in an Environment behind protection rules — not at organization scope for
convenience.

> **Secrets, not Variables.** Variables are plaintext and **are not masked in workflow logs**.

**GUI:** repo → **Settings → Secrets and variables → Actions**
· repo-wide → **Secrets** tab → *New repository secret*
· scoped to an environment → **Environments** → pick it → *Add secret*

**CLI:**
```bash
gh secret set AZURE_CLIENT_ID --repo "$ORG/$REPO"                      # repo scope
gh secret set AZURE_CLIENT_ID --repo "$ORG/$REPO" --env "$ENVIRONMENT"  # environment scope
```

---

## 3 · App registration

**GUI:** **Entra ID → App registrations → New registration** → name it (e.g.
`gh-<REPO>-deploy`) → *Accounts in this organizational directory only* → **Register**.
Copy **Application (client) ID** and **Directory (tenant) ID** from the Overview blade.

> Registering an app creates the service principal automatically in the portal. Via CLI it does not —
> see below.

**CLI:**
```bash
APP_NAME="gh-${REPO}-deploy"      # any descriptive name
az ad app create --display-name "$APP_NAME"
APP_ID=$(az ad app list --display-name "$APP_NAME" --query "[0].appId" -o tsv)
az ad sp create --id "$APP_ID"          # REQUIRED — az ad app create does not do this
echo "AZURE_CLIENT_ID       = $APP_ID"
echo "AZURE_TENANT_ID       = $(az account show --query tenantId -o tsv)"
echo "AZURE_SUBSCRIPTION_ID = $(az account show --query id -o tsv)"
```

---

## 4 · Federated credential — the step people get wrong

The **subject** must match the token GitHub actually sends. A mismatch produces `AADSTS700213` /
*no matching federated identity record found*, which reads like a permissions problem and is not.


### 4.0 · Finding the values you need

The form asks for things you have to go look up. Here is where each comes from.

**GitHub side — org, repo, environment:**

```bash
gh repo view --json nameWithOwner,owner,name --jq '.'
gh api repos/<ORG>/<REPO>/environments --jq '.environments[].name'   # exact env names, case-sensitive
```

Or in the browser: the org/repo are in the URL. Environments are under
**Settings → Environments**. **Copy the environment name exactly** — it is case-sensitive and a
trailing space will silently break the match.

**Azure side — app, tenant, subscription:**

```bash
az ad app list --display-name "<APP_NAME>" --query "[0].{appId:appId,objectId:id}" -o table
az account show --query "{tenantId:tenantId,subscriptionId:id}" -o table
```

Portal: **Entra ID → App registrations → [your app] → Overview** has *Application (client) ID* and
*Directory (tenant) ID*. Subscription ID is on the **Subscriptions** blade.

**Numeric Organization ID and Repository ID ARE required by the current portal form.** It has
dedicated fields for both, and it generates a subject in the ID-decorated form:

```
repo:<ORG>@<ORG_ID>/<REPO>@<REPO_ID>:environment:<ENVIRONMENT>
```

That is **legitimate and correct** — not an error rendering. Both subject shapes exist in the wild:

| Form | Where it comes from |
|---|---|
| `repo:<ORG>/<REPO>:environment:<ENV>` | Older portal forms, and hand-written CLI credentials |
| `repo:<ORG>@<ORG_ID>/<REPO>@<REPO_ID>:environment:<ENV>` | Current portal form with the ID fields |

**Do not "fix" the ID form by stripping the IDs.** Match whatever the workflow actually presents —
`verify-azure-oidc.yml` prints it, and the `AADSTS700213` error text quotes it verbatim.

Get the IDs with:

```bash
gh api repos/<ORG>/<REPO> --jq '{owner_id:.owner.id, repo_id:.id}'
```

### 4.1 · Verify what is actually stored

Before assuming the subject is right, read it back:

```bash
APP_ID=$(az ad app list --display-name "<APP_NAME>" --query "[0].appId" -o tsv)
az ad app federated-credential list --id "$APP_ID"   --query "[].{name:name,subject:subject,issuer:issuer,audiences:audiences}" -o json
```

Compare **character for character** against what the workflow prints. Common mismatches that look
identical at a glance:

| Stored | Presented | Why it fails |
|---|---|---|
| `...:ref:refs/heads/main` | `...:environment:prod` | Branch form configured for an environment-scoped job |
| `...:environment:Prod` | `...:environment:prod` | **Case-sensitive** |
| `...:environment:prod ` | `...:environment:prod` | Trailing whitespace pasted in |
| configured on app **A** | token for app **B** | `AZURE_CLIENT_ID` points at a different app registration |
| `audiences: ["api://AzureADTokenExchange"]` missing | — | Audience must match exactly |

**`AADSTS70025`** = zero credentials on the app. **`AADSTS700213`** = a credential exists but no
subject matches. Different problems, different fixes.

### Which entity type?

| Where your secrets live | Workflow declares | Entity type | Subject |
|---|---|---|---|
| **A GitHub Environment** | `environment: <name>` | **Environment** | `repo:O/R:environment:<name>` |
| Repo secrets | nothing | **Branch** | `repo:O/R:ref:refs/heads/<branch>` |
| Repo secrets, tag build | nothing | **Tag** | `repo:O/R:ref:refs/tags/<tag>` |
| Repo secrets, PR | nothing | **Pull request** | `repo:O/R:pull_request` |

> **A job declaring `environment:` sends the environment subject — even though the run is on a
> branch.** Using the branch form for an environment-scoped job is the most common failure, and the
> error does not say so.

**GUI:** **Entra ID → App registrations → [your app] → Certificates & secrets → Federated
credentials → Add credential**

1. Scenario: **GitHub Actions deploying Azure resources**
2. Organization: `<ORG>`
3. Repository: `<REPO>`
4. **Entity type:** ← the field that matters (table above)
5. Environment / Branch / Tag name — exact, case-sensitive
6. Name: anything descriptive
7. Audience: leave `api://AzureADTokenExchange`

Verify the generated subject reads exactly `repo:<ORG>/<REPO>:environment:<ENVIRONMENT>`.

**CLI:**
```bash
ORG=<your-github-org-or-username>
REPO=<your-repo>
ENVIRONMENT=<your-github-environment>   # omit if using repo-scope secrets
az ad app federated-credential create --id "$APP_ID" --parameters "{
  \"name\": \"gh-${REPO}-${ENVIRONMENT}\",
  \"issuer\": \"https://token.actions.githubusercontent.com\",
  \"subject\": \"repo:${ORG}/${REPO}:environment:${ENVIRONMENT}\",
  \"audiences\": [\"api://AzureADTokenExchange\"]
}"
```

**One credential per subject.** Deploying from both `main` and a `prod` environment needs two. Max 20
per app.

> ⚠️ **Editing a credential replaces it — it does not add one.** Changing an existing credential's
> environment from `dev` to `prod` leaves you with a working `prod` and a **broken `dev`**, which then
> fails `AADSTS700213` the next time anything runs against it. Verified the hard way. Use *Add
> credential* for each environment; confirm the count with the `list` command in §4.1.

### Do not use the credential subject to restrict branches

Both of these can express "only `main` deploys to prod". They are not equivalent.

| | Credential subject = `Branch:main` | **Environment deployment branch policy** |
|---|---|---|
| Where enforced | Entra, at token exchange | **GitHub, before the job starts** |
| Feature branch behaviour | job starts, secrets resolve, work runs, **then** auth fails | **job never starts — 0 steps** |
| Error the developer sees | `AADSTS700213` — looks like broken auth | *"Branch X is not allowed to deploy to prod due to environment protection rules"* |
| Cost of the failure | full job runtime | ~2 seconds |
| Side effect | **loses environment-scoped secrets entirely** | none |
| Who can change it | Entra admin | repo admin, in the UI |

Use the **branch policy** (§1.2). Keep every credential in the **Environment** form. *Which branches
may deploy* is a repository policy question, not an identity question.

---

## 5 · RBAC

**Auth verification needs NO role at all.** Login succeeds with zero assignments. Add roles only for
what you actually intend to do.

| To do this | Role | Scope |
|---|---|---|
| Enumerate resources | **Reader** | subscription or RG |
| Deploy to an existing App Service | **Website Contributor** | the app or its RG |
| Deploy to an existing Container App | **ContainerApp Contributor** | the app or its RG |
| **Push images to ACR** | **AcrPush** | **the registry** |
| **Create** the test resources | **Contributor** | **a dedicated test RG only** |

> There is no "Web App Contributor" — the role is **Website Contributor**. Common trip-up.

**GUI:** **Subscription** (or better, a **Resource group**) → **Access control (IAM)** → **Add → Add
role assignment** → pick role → **Members** → *User, group, or service principal* → **+ Select
members** → search the **app registration display name** → **Review + assign**.

> ⚠️ It will not appear if you search by the *application* object ID. Search by **display name**.

**CLI:**
```bash
SUB=$(az account show --query id -o tsv); RG=<TEST_RESOURCE_GROUP>
az role assignment create --assignee "$APP_ID" --role "Website Contributor" \
  --scope "/subscriptions/$SUB/resourceGroups/$RG"
```

---

## 6 · Workflow permissions

Any job using OIDC **must** declare, per job:

```yaml
permissions:
  id-token: write      # mint the OIDC token — without this, login fails
  contents: read
```

The kit's policy gate rejects workflow-level `id-token: write`. Grant it per job, only where needed.

---

## 7 · Verify — creates nothing, costs nothing

**Actions → Verify Azure OIDC → Run workflow.** It prints the subject your run presents, asserts the
secrets are reachable, then logs in. Run this before anything that deploys.

---

## 8 · What you additionally need to test the DEPLOY workflows

**Reader + Website Contributor + ContainerApp Contributor lets you deploy *to* things. It does not
let you *create* anything — and the deploy workflows require targets that already exist.**

Required inputs, all of which name pre-existing resources:

| Workflow | Requires |
|---|---|
| `reusable-deploy-appservice` | `resource_group` · `webapp_name` · `acr_login_server` · `image_repository` · `image_digest` |
| `reusable-deploy-containerapp` | `resource_group` · `containerapp_name` · `acr_login_server` · `image_repository` · `image_digest` |
| `reusable-build-docker` | `acr_login_server` · `image_repository` |

So from a **zero-resource** subscription you still need:

| # | Thing | Why | Missing role |
|---|---|---|---|
| 1 | A **resource group** | everything lands in one | **Contributor** on it (or create in portal) |
| 2 | An **Azure Container Registry** | `acr_login_server` is required by all three | **AcrPush** to push · **Contributor** to create |
| 3 | A **Linux App Service** (container-based) | `webapp_name` target | Website Contributor covers *deploy*, not *create* |
| 4 | A **Container Apps environment + app** | `containerapp_name` target | ContainerApp Contributor covers *deploy*, not *create* |
| 5 | **Pull rights from ACR to the apps** | otherwise deploy succeeds and the app fails to start | app's managed identity needs **AcrPull** on the registry |
| 6 | `image_digest` | deploy input | produced by running `reusable-build-docker` first |

**#5 is the one that bites.** Deploy reports success, the revision never becomes healthy, and the
cause is an image pull failure — not a deploy failure.

### Two ways forward

**A — grant `Contributor` on one dedicated RG** and let the harness create and destroy everything.
Smallest standing privilege, cleanest teardown, matches the
[rollback contract](../architecture/ROLLBACK_CONTRACT.md) precondition (`PRE_TEST_RESOURCE_COUNT = 0`).

**B — create the RG, ACR, App Service and Container App by hand in the portal**, keep your current
narrow roles, and test deploy only. Less privilege granted; you own cleanup manually.

Given you are deliberately at zero resources and want to stay there, **A is the better fit** —
scoped to one throwaway RG, with the harness asserting empty before and empty after.

**Do not do this yet.** The deploy workflows are blocked on
[`ROLLBACK_CONTRACT.md`](../architecture/ROLLBACK_CONTRACT.md) regardless of tenant access — that is a design gate,
not an access gate.

---

## 9 · NVD API key

Free: **https://nvd.nist.gov/developers/request-an-api-key**

A missing key does **not** fail the workflow — it degrades to unauthenticated and rate-limited with a
warning. *"The scan ran"* and *"the scan had current data"* are different claims.

---

## 10 · Troubleshooting

| Symptom | Cause |
|---|---|
| `AADSTS700213` | Subject mismatch — **environment vs branch** is the usual culprit |
| `Unable to get ACTIONS_ID_TOKEN_REQUEST_URL` | Job missing `permissions: id-token: write` |
| Login works, deploy denied | No RBAC, or wrong scope |
| Deploy succeeds, app never healthy | **ACR pull rights missing** (§8 #5) |
| App registration not in member picker | Searching by object ID — search by **display name** |
| Secret set but empty at runtime | Set as a **Variable**, or at the wrong scope (repo vs environment) |
| NVD job runs 30+ min | No `NVD_API_KEY` |

## 11 · Minimum setup

Not using Azure? **You need nothing.** `reusable-security.yml` requires no secrets —
`SEMGREP_APP_TOKEN` is optional and everything else runs unauthenticated.
