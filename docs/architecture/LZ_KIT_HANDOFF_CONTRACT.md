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

**Hosting types the kit can release today: Azure App Service (Linux container), Azure Container
Apps and Azure Static Web Apps** — the three deploy adapters it has (VERIFIED: `reusable-deploy-appservice.yml`,
`reusable-deploy-containerapp.yml`; and, since OF-5 K-8 (KDEC-034 PROPOSED, 2026-10-28),
`reusable-deploy-staticwebapp.yml`, observed against the stub cloud by tests/prove_deploy_staticwebapp.py,
its run on a real site the dated deferral deploy-staticwebapp-live). The landing
zone's no-kit-adapter report for `static_web_app` therefore no longer applies: it hands a Static Web App
off like the other two (`KIT_APP_NAME` is the site's name; `KIT_ACR_*` do not apply), and the deploy
identity needs, at the one site's scope, the right to read its deployment token and environments, delete
a preview environment and write tags. The site must not be linked to a repository (its generated workflow
would deploy around the kit; the posture check fails it). A tool on any other hosting type (Functions,
AKS, a VM) has no kit adapter; that is a named gap, not implied coverage.

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
| environment protection rules | GitHub setting | — | **REQUIRED on uat/prod:** required reviewers and a branch policy (the protected default branch only). The reviewers are the approval half of a version-gap exception (KDEC-014) and, at uat/prod, a control in their own right: **prevent self-review ON**. The kit cannot set them, so the vending must; the deploy reads them back before login and refuses at uat/prod when they are absent, allow self-review, or (when the policy names approver groups) include anyone outside the groups (lane L-A, `environment_protection`) |
| the federated credential subject | Entra setting | — | `repo:<owner>/<repo>:environment:<env>` — so only a job running in **that** environment of **that** repository can mint the token |


### The extended hand-off set (OF-5, 2026-10-28; KDEC-034 PROPOSED)

The LZ-vs-kit deployment review (the landing zone's `LZ-VS-KIT-DEPLOYMENT-REVIEW.md`, P4-P7, P17)
took the landing zone's stop, its zone readiness and its one approver list into the kit's releases,
and gave the kit the durable record and the edge purge the landing zone reads and grants. The vending
(its hand-off write) writes these beside the nine identifiers, read back the same way; each is a
**variable**, never a secret, and the deploy records which of the environment ones it found
(`handoff_vended`, names only, in the posture record).

| Item | Where | Value | The kit's use (refused before login unless stated) |
|---|---|---|---|
| `KIT_RELEASE_BLOCK` | each environment | `none` \| `platform_halted` \| `ttl_expired` \| `budget_cap_reached`; rewritten on every halt and `apply_block` change, and when a halt clears (while halted, the halt runbook's platform admin sets `platform_halted`) | anything but `none` refuses at **every** tier: `RELEASE_BLOCKED_BY_PLATFORM` (K-3). Unset: recorded `RELEASE_BLOCK_NOT_VENDED`, proceeds |
| `KIT_ZONE_READINESS` | each environment | `READY` \| `READY_WITH_EXCEPTIONS` \| `NOT_READY` \| `UNKNOWN`, from the zone's readiness register | at `uat`/`prod` only `READY` or `READY_WITH_EXCEPTIONS` releases; `NOT_READY`, `UNKNOWN` or **unset** refuses: `RELEASE_REFUSED_ZONE_NOT_READY` (K-2). Below `uat` it is recorded. **A repository outside a landing zone sets `KIT_ZONE_READINESS: READY` on its uat/prod environments itself** -- the kit cannot know a zone is ready, and unknown is never a pass |
| `KIT_SETTING_KEYS` | each environment | the app-setting / env keys assigned to the kit, comma- or space-separated; **empty by default** (every key is the landing zone's) | with the seam on: a key the deploy would write outside these and `release_ownership_stamp`, or one of these the landing zone also claims (slot-sticky, secret-backed -- on a static site, a Key Vault reference), refuses before the first mutation: `SEAM_SETTING_OWNERSHIP_CONFLICT`; an App Service swap that would carry a non-sticky landing-zone setting into production: `SEAM_SWAP_MOVES_LZ_SETTING` (K-6) |
| `KIT_EDGE_ENDPOINT` | each environment of a user-facing app | the app's **own** Front Door endpoint, as its resource id (`.../Microsoft.Cdn/profiles/<profile>/afdEndpoints/<endpoint>`); one endpoint per user-facing app | after a verified release the kit purges that endpoint's cache, and no other (D-4; all three deploy adapters, the static site's since integrate/r8): `EDGE_PURGED`; unset: `EDGE_PURGE_NOT_APPLICABLE` (recorded, never a pass); a value that is not an endpoint id: `EDGE_PURGE_REFUSED`; a failed purge: `EDGE_PURGE_FAILED`, an advisory -- never a failed release |
| `KIT_TARGET_LEASE_ACCOUNT` | each environment | the lease store's storage account (the container is derived from the target's resource id) | **only after the owner rules on KDEC-030 (the landing zone's G09)**; until then unset, and every lease and seam step on both sides stays off. On: the lease (KDEC-030), the `seam` step (K-6), the rollback's entry ownership (K-5) and the durable release record (K-4) |
| `KIT_ACR_LOGIN_SERVER`, `KIT_IMAGE_REPOSITORY` | **also as repository variables** | as the environment values | the build reusable binds no environment, so the starter template reads them from the repository |
| `KIT_PROMOTION_PREDECESSOR` | repository variable | `test` (default) or `uat`, per product | the predecessor whose verified record a `prod` promotion requires (KDEC-029) |
| the approver groups in the `uat`/`prod` protection rules | GitHub setting | the kit policy register's `deploy_approval.approver_groups` -- or the named list it points at (`approver_groups_from` in `approver_lists`, optionally kept in the shared file `approver_lists_source`); the landing zone **reads** that list and never keeps a second one (its `HANDOFF_APPROVER_LIST_MISMATCH` refuses a worksheet that disagrees) | the deploy checks the environment's reviewers against the same list (`environment_protection`); one list, so the two cannot drift (K-9) |

**Release approval at uat/prod (K-1).** On top of the protection rules above, the deploy reads its
own run's approvals before login: an approval of this environment must exist (an administrator
bypass leaves none: `RELEASE_APPROVAL_ABSENT`), no approver may be the requester or the released
commit's author (`SELF_DEPLOYMENT_APPROVAL`, the landing zone's own name), and an independent
approval's **comment must quote the digest** being released -- the full `sha256:` value or at least its
first 12 hex characters (`RELEASE_APPROVAL_NOT_BOUND_TO_DIGEST`). The reviewer who quotes it is the
confirmer: approver/confirmer, requester and author are distinct people. The vending need write
nothing for this; reviewers need to know to quote the digest the run summary shows.

**The durable release record (K-4).** With the lease on, every deploy that took the lease writes its
release record, create-only, as `releases/<environment>/<UTC>-<run>-<attempt>.json` in the target's
lease container: digest, `now_serving`, run, `routing_result`, validity, target, and the full
promotion record -- what the landing zone's seam detector, destroy evidence and `status.json` read.
The kit never overwrites or deletes one. **Retention is the landing zone's**: it sets a time-based
immutability policy on the lease container at least as long as its Git evidence (SOC 2); the kit
reads the container's properties and records `retention_policy` (`present` | `absent` |
`unreadable`), warning when no policy is in force.

The deploy identity additionally receives, from the vend: `Storage Blob Data Contributor` on **its
target's lease container only** (only after G09), and a custom role holding only
`Microsoft.Cdn/profiles/afdendpoints/Purge/action` at **its own** `afdEndpoints/<name>` scope
(D-4; whether the purge's status poll needs a read action is the seam contract's U8).
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
