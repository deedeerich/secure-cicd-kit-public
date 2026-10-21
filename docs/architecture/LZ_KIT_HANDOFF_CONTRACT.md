# Landing zone → kit: the hand-off contract

```
Phase:              1
Truth State:        DECIDED by the owner (KDEC-009, 2026-10-15; KDEC-014 and KDEC-015, 2026-10-16); this
                    contract is a DRAFT for owner review.
                    Role names are READ from platform documentation. The kit's deploys HAVE run live
                    (2026-10-15/16, a sandbox subscription, a test identity), but the roles that
                    identity held were not recorded, so the table below is still unverified
                    (completion ledger LZ-2). Nothing here has run against a real landing zone yet.
Audience:           whoever builds the landing-zone vending, and whoever wires a repository to the kit
Decision Supported: what the vending must emit per application, and what the kit consumes, so neither
                    side deploys the other's objects
```

## The split (KDEC-009)

| | landing-zone vending | secure CI/CD kit |
|---|---|---|
| owns | the platform and each application's **empty target**, plus the **deploy identity** | every **application release** |
| changes by | plan → human approval → apply (infrastructure as code) | the kit's run: scan → verdict → build once → deploy by digest → verify → reverse |
| never | deploys application code or images | creates or deletes platform infrastructure |

**All tools, internal ones included (KDEC-015).** An internal tool is a workload like any
application: the vending gives it its own empty target and its own per-tool deploy identity, and the
kit releases it. Everywhere below, "application" means application or tool. No identity deploys more
than one tool, and being internal never moves a tool's release out of the kit.

**Hosting types the kit can release today: Azure App Service (Linux container) and Azure Container
Apps** — the two deploy adapters it has (VERIFIED: `reusable-deploy-appservice.yml`,
`reusable-deploy-containerapp.yml`). A tool on any other hosting type (Functions, AKS, a VM, static
hosting) has no kit adapter; that is a named gap, not implied coverage.

## What the vending emits, per application and environment

All of it is written into the **application repository's GitHub environment** (one environment per
deployment environment, e.g. `dev`, `test`, `prod`). Identifiers are **variables**; nothing below is a
secret, because the identity is federated (OIDC) and holds no key.

| GitHub environment item | type | consumed by the kit as | notes |
|---|---|---|---|
| `AZURE_TENANT_ID` | variable (passed as the `secrets:` value the reusables declare) | `AZURE_TENANT_ID` | |
| `AZURE_SUBSCRIPTION_ID` | variable | `AZURE_SUBSCRIPTION_ID` | the application's subscription |
| `AZURE_CLIENT_ID` | variable | `AZURE_CLIENT_ID` | the **deploy identity** (below); never a secret, never a key |
| `KIT_RESOURCE_GROUP` | variable | input `resource_group` | the application's resource group |
| `KIT_APP_NAME` | variable | input `webapp_name` or `containerapp_name` | the vended, empty target |
| `KIT_ACR_LOGIN_SERVER` | variable | input `acr_login_server` | the registry the build pushes to |
| `KIT_IMAGE_REPOSITORY` | variable | input `image_repository` | |
| `KIT_ENVIRONMENT_TIER` | variable | input `environment_tier` | `dev` / `test` / `uat` / `prod`. At uat and prod the kit refuses an irreversible deploy |
| `KIT_CLOUD` | variable | input `cloud` | `commercial` or `gov` |
| environment protection rules | GitHub setting | — | **REQUIRED on uat/prod:** required reviewers and a branch policy (the protected default branch only). The reviewers are the approval half of a version-gap exception (KDEC-014); the kit cannot set or read them, so the vending must, and the deploy records which environment it ran in |
| the federated credential subject | Entra setting | — | `repo:<owner>/<repo>:environment:<env>` — so only a job running in **that** environment of **that** repository can mint the token |

The vending also records, in its own output for the platform team (not in the repository): the
application's owner role, its cost centre, and the guardrails in force.

## The deploy identity — least privilege, per application

One identity per application per environment (or per application with one federated credential per
environment). Scoped to **that application's resources only**:

| target | role at the application's scope | why |
|---|---|---|
| App Service | `Website Contributor` on the web app (and its slots) | set the container image, restart, swap slots, read back state, write the provenance tags |
| Container Apps | `Container Apps Contributor` (or the documented equivalent) on the container app | create revisions, set traffic, read back state, write tags |
| both | `Reader` on the resource group | read live state for snapshot, reconciliation and reversal |
| both | **none** on the registry for the deploy identity | the deploy reads by digest; the web app's or container app's **own managed identity** gets `AcrPull`, vended by the landing zone |

The **build** identity (the kit's build workflow) is separate: `AcrPush` on the application's
repository in the registry, nothing else.

**What the deploy identity must NOT hold:** any role at subscription or management-group scope, any
role on another application's resources, `User Access Administrator` or `Owner` anywhere, or any
permission to create resource groups or networks. The kit's authorization-boundary probe
(`verify-azure-oidc.yml`) proves this by attempting reads and a subscription-scope write it must be
**refused**: reachable scopes REACHED, sibling and opposite-tier scopes REFUSED, subscription write
REFUSED.

## What the kit guarantees back to the platform

- A deploy runs only on `routing_result` ∈ {PROCEED, PROCEED_WITH_ADVISORY}, refusing before login
  otherwise, and only by a full `sha256:` digest (part 03 and 07 of `docs/explainer/`). That the digest
  is the one that was scanned and built (`artifact_identity` = `REGISTRY_IDENTITY_PROVEN`) is checked
  by the starter template's `verdict` job, **not** by the deploy reusables: a pipeline that calls a
  deploy reusable directly must make that check itself.
- At `uat` and `prod` (KDEC-014) a `PROCEED_WITH_ADVISORY` caused, wholly or partly, by a version gap
  that READ scanner ranges establish (`advisory_causes` contains `VERSION_GAP`) is refused before
  login unless a named person accepts it as an attributed exception. The exception is the kit's
  existing weakening record — `weakening_authority` (the named accepter), `weakening_reason` and an
  unexpired `weakening_expires` (YYYY-MM-DD) — AND the deploy job runs in the GitHub environment
  whose required reviewers approve it (the setting above). The acceptance and the environment are
  recorded in the posture record and `outcome.json`.
- A gap that rests on an UNVERIFIED scanner range (`VERSION_GAP_UNVERIFIED`) proceeds at `uat` and
  `prod`, recorded prominently in the summary, the posture record and `outcome.json`. Enforcement is
  data-driven: it turns on for a capability when a seeded corpus makes every candidate's range READ
  in `scanner-registry.yaml` (Checkov and Trivy-config, for IaC, first). There is no caller toggle.
- An advisory with no cause, or an unregistered one, is refused at `uat` and `prod`. Below `uat` a
  gap is recorded and the deploy proceeds. The exception is set per release by the application
  repository's owner, never by the vending: the vending emits no exception.
- It changes only the vended target, records a change manifest, and reverses only what that run
  changed. Anything another actor touched is refused for removal and reported.
- It writes provenance as tags on the serving object after health, never before.
- It never creates, deletes or re-scopes platform objects; a deploy that would need to is refused.

## Open items for the owner

1. One identity per application per environment, or one per application with several federated
   credentials? (Recommended: one per environment; a test identity can never reach prod.)
2. Does the vending also create the **build** identity and its registry scope, or is that a second,
   one-time onboarding step?
3. Role names to verify on the first live deploy (the table above is read, not run).
4. Where application-level configuration that is infrastructure (scale, plan size, app settings that
   are not secrets) lives: in the vending (plan → apply), or as kit-managed settings. Recommended: the
   vending, so the kit never changes what the platform team approved.
