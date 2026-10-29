# Landing zone ↔ kit: the deployment seam contract

```
Phase:              1
Truth State:        KDEC-030 DRAFT -- PROPOSED as a whole, for owner approval. The owner DECIDED four of its
                    points on 2026-10-26 (private-only endpoints, the identity design from the start, the
                    lease store's network and co-location, the kit's own edge purge: "Decided 2026-10-26"
                    below); "Contributor only when required" is RECOMMENDED, FOR DISCUSSION until she
                    confirms it. Revised 2026-10-27 (lane L-SEAM2, reviewer finding): the shared
                    concurrency group is REMOVED as a control; the cross-repository lock is the
                    per-target blob lease alone; one owner per field with a drift rule; the lease
                    has a live REST adapter, a composite both sides call, and OPT-IN wiring in both
                    deploy reusables (off unless KIT_TARGET_LEASE_ACCOUNT is set). Proven against a
                    local HTTP emulation of the Blob service with two independent callers
                    (tests/prove_target_lease_crossrepo.py) and as a model
                    (tests/prove_target_lease.py). Nothing here has run against real Azure Storage
                    or a real landing zone; integrated LZ + kit testing is CLOSED (see the gate).
Audience:           the owner; whoever builds the landing-zone (LZ) vending and its IaC; whoever wires
                    the kit's deploy and rollback reusables to the lease (after lane L-PROMO merges)
Decision Supported: which side owns each field of a release target; how each side detects and answers the
                    other's change; the one lock both take before mutating a target; what a kit rollback
                    may never reverse
Extends:            LZ_KIT_HANDOFF_CONTRACT.md (KDEC-009, KDEC-015). That contract splits OBJECTS
                    (platform vs release); this one splits FIELDS of the shared objects, and the TIME
                    each side may write them.
```

## Why this is a release blocker

A seam review (2026-10-26) read both sides and found the split of KDEC-009 holds for *objects* and fails
for *fields* and *time*. Three hazards, each confirmed against the sources named at the end:

1. **The LZ IaC can overwrite what a release changed.** The LZ apply creates the target and its
   configuration -- ingress, auth, app settings (LZ brief item 84), tags. The kit then changes the same
   resource's image, revision, traffic weights, slot contents, tags and one environment variable
   (`deploy_contract.py` `cmd_mutate`, `cmd_swap`, `cmd_provenance`). Neither the LZ brief nor its product
   files contain any rule that keeps the kit's fields out of the IaC (searched: no `ignore_changes`, no
   lifecycle rule). The next LZ apply can silently revert a release; the kit's next reversal then sees
   "another actor" and refuses. The LZ's daily drift plan (brief §6.9, WX-DRIFT) reports every release as
   IaC drift. **And the LZ's own negative test AT-N121 ("refused by role") is not true as written**: the
   LZ apply identity L5 holds `Contributor` on the workload resource group (brief W0 step 2), which
   includes writing the container app's image. Only design review stops it.
2. **The two sides use different locks.** The kit serialises deploys and rollback sequences on the
   concurrency group `kit-target-<env>-<rg>-<name>` (`reusable-deploy-appservice.yml` line 298-300,
   `reusable-deploy-containerapp.yml` 281-283, `reusable-rollback-sequence.yml` 191-193). The LZ's mutating
   jobs use "concurrency keyed on environment and target" with no shared name (WORKFLOWS-03
   `mutating_job_rules`; AT-N129). An earlier draft proposed that the LZ jobs join the kit's group as a
   shared lock. **That cannot work, and the shared group is removed as a control.** GitHub documents a
   concurrency group as evaluated against runs *in the repository*. **VERIFIED (doc), re-read
   2026-10-27:** *Control the concurrency of workflows and jobs*
   (<https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency>):
   a queued job or workflow waits "if another job or workflow using the same concurrency group in the
   repository is in progress"; and "If you have multiple workflows in the same repository, concurrency
   group names must be unique across workflows to avoid canceling in-progress jobs or runs from other
   workflows." *Workflow syntax for GitHub Actions* § `concurrency`
   (<https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax>) carries the same
   "in the repository" sentence and names no organisation-wide or cross-repository scope. The LZ apply
   runs in the platform repository and the kit's deploy in the application repository, so identical
   group names in two repositories are two locks. What is verified is the documented wording; the docs
   do not say "cannot span repositories" in those words, and no hosted two-repository run was made (a
   reusable workflow's run belongs to its caller's repository, so the kit's group lives in each
   application repository). The cross-repository lock is the per-target lease (*The lease*, below).
3. **The kit's generic ARM rollback could reverse LZ-owned shared entries.** `reusable-rollback-sequence.yml`
   with `adapter: arm` reverses `SHARED_MULTI_CONFIG` entries -- Front Door routes, NSG rules, firewall rule
   collections, WAF rules, DNS records -- from any deployer's `resources.json` (ROLLBACK_CONTRACT.md,
   "Cross-edited resources"; `rollback_sequence.py` `ADAPTERS`). The LZ creates exactly those entries for
   each workload (brief W7 step 3: "edge route, origin group, DNS record, firewall or policy exemption
   entry") and owns their reversal (§3.7 Recovery, entry-level, three-way compare). Nothing forbids
   feeding an LZ apply's evidence to the kit's `arm` rollback; two systems would reverse the same entries.

A fourth fact makes 1 sharper: the LZ deliberately allows **privileged interactive change inside a
workload boundary** under time-limited elevation (brief D12; §6.9 "subject to drift detection").
So "someone else" is not hypothetical: the IaC, a person under elevation, and the kit can all write the
target. Whatever the IaC is told to ignore, it stops seeing -- from every one of them.

## The rules (owner-level; each row of the table below follows from them)

| # | Rule |
|---|---|
| R1 | The **LZ owns existence, networking, identity and platform security settings** of every target: create, delete, network integration, ingress posture, access restrictions, TLS, auth, managed identity, registry-pull identity, plan/scale, diagnostic settings, platform tags. |
| R2 | The **kit owns the release fields**: the image digest, the revision (and its suffix), the traffic split between revisions, which slot holds which release and the swap, and the kit's own stamps and provenance tags. |
| R3 | **App configuration is assigned per key or per namespace**, never per resource. Every key has exactly one owner. A key claimed by both sides, or written by a side that does not own it, is **refused** -- by the LZ plan and by the kit's deploy, before either writes (`SEAM_SETTING_OWNERSHIP_CONFLICT`). An unassigned key belongs to the LZ (item 84's default), so the kit writes no app setting unless the hand-off assigns it the key. |
| R4 | **Shared entries** (Front Door route / origin group / rule, DNS record, WAF rule, NSG rule, firewall rule collection, route, gateway listener) are **LZ-owned at entry level** and are **never reversed by an application rollback**. Their only reverser is the LZ's own recovery (§3.7, W7). |
| R5 | The **kit owns release provenance** (who released which digest, when, with what verdict and promotion record); the **LZ consumes it** -- in its drift detector, its destroy precondition and its status -- and never writes it. |
| R6 | **No side reverts the other's fields.** Drift on a field the other side owns is *detected and reported to its owner*, never silently reconciled. |
| R7 | **One lease per target**, keyed by the target's ARM resource id, acquired by every pipeline -- the LZ apply and the kit deploy alike -- before it mutates the target, re-checked (fenced) before every mutation. **GitHub concurrency is not a seam control**: the kit's existing group still queues two runs inside one application repository, and that is all it does. Fencing stops a stale holder before its next call; it cannot recall an Azure mutation already sent. |
| R8 | **Public endpoints only where a private link or private endpoint is technically impossible** (the owner, 2026-10-26). A service that supports a private endpoint is reached privately; a client that cannot reach it privately is the thing to change, not the endpoint. An exception is time-boxed, recorded and reviewed. Applies to every resource on both sides of the seam, the lease store first. |

## One owner per field (the summary both sides build from)

**Why ownership, and not the lock, closes hazard 1.** The lease serialises the LZ apply and the kit
deploy; it does not stop a *later* LZ apply, run after the kit released the lease, from writing the
release's image back to whatever the IaC declares. Only field ownership does that: every field has
exactly one owner, and the non-owner's tool is configured never to write it. The lease and the ownership
rules are both required; neither replaces the other.

| Field (App Service `Microsoft.Web/sites` / Container Apps `Microsoft.App/containerApps`) | Owner | What the LZ does when it is not the owner | What the kit does when it is not the owner |
|---|---|---|---|
| Existence, region, App Service plan / SKU, managed environment, workload profile | LZ | -- | never writes; a missing target fails the kit's snapshot and the deploy refuses |
| Scaling: plan instance count and autoscale; `template.scale` (min/max replicas, rules) | LZ | -- | never writes (no deploy path changes scale) |
| Networking: public network access, VNet integration, private endpoints, access restrictions, ingress except `traffic` (`external`, `targetPort`, `transport`, `allowInsecure`) | LZ | -- | never writes |
| Identity: system/user-assigned identities, `keyVaultReferenceIdentity`, registry-pull identity, `configuration.registries` | LZ | -- | never writes |
| TLS and security: `httpsOnly`, `minTlsVersion`, `ftpsState`, certificates and custom-domain bindings, `authsettingsV2`, basic publishing credentials off | LZ | -- | never writes; its posture check only reads them |
| Diagnostic settings on the target (`Microsoft.Insights/diagnosticSettings`) and platform logging | LZ | -- | never writes |
| Platform runtime: `alwaysOn`, `healthCheckPath`, `http20Enabled`, container `resources` and `probes`, `activeRevisionsMode` | LZ | -- | never writes; a change between its snapshot and its mutate makes it refuse |
| Secrets (`configuration.secrets`, Key Vault references) | LZ | -- | never writes |
| App settings, connection strings and container env -- every key **not** assigned to the kit (default: all keys) | LZ | -- | never writes; a write outside its assigned keys is refused `SEAM_SETTING_OWNERSHIP_CONFLICT` (built 2026-10-28, OF-5 K-6, opt-in with the lease) |
| App settings / env keys assigned to the kit (the hand-off's kit setting keys; empty today) and the env key `release_ownership_stamp` | kit | `ignore_changes` on each key by index (`app_settings["<k>"]`); the Container Apps env list is ignored whole **only together with** the seam detector (the block-list problem) | -- |
| Slot configuration: sticky settings (`slotConfigNames`) | LZ | -- | never writes; refuses a swap that would move a non-sticky LZ key `SEAM_SWAP_MOVES_LZ_SETTING` (built 2026-10-28, OF-5 K-6) |
| Deployment slots: existence and each slot's networking, identity, security and settings | LZ | -- | never writes; a missing slot fails the snapshot |
| Slot contents (the image in a slot) and the swap | kit | `ignore_changes` on each slot resource's image attribute | -- |
| Configured image: `linuxFxVersion` / `application_stack` image; `template.containers[].image` | kit | `ignore_changes` on exactly that attribute | -- |
| Revision suffix, the revision set, `configuration.ingress.traffic` (weights, labels) | kit | `ignore_changes` on `template[0].revision_suffix` and `ingress[0].traffic_weight` | -- |
| Tags `release_ownership_stamp`, `deploy_provenance_digest`, `deploy_provenance_metadata_sha256`, `deploy_provenance_run` | kit | `ignore_changes` on each tag by key (`tags["<k>"]`), never the whole map | -- |
| Every other tag | LZ | -- | never writes |
| Shared entries: Front Door routes/origins/rules, DNS records, WAF rules, NSG and firewall rules | LZ | -- | never writes; its rollback refuses them `ROLLBACK_REFUSED_PLATFORM_OWNED` (built 2026-10-28, OF-5 K-5, opt-in with the lease) |
| Edge cache purge of the app's own Front Door endpoint (an action, not a field) | kit | not a field; nothing to ignore | -- |

A Terraform illustration of the LZ's side (attribute paths are U5: illustrative until checked against
the LZ's provider version; the rule is the field):

```hcl
resource "azurerm_container_app" "app" {
  # ... everything the LZ owns is declared normally and planned normally ...
  lifecycle {
    ignore_changes = [
      template[0].container[0].image,        # kit: the release
      template[0].revision_suffix,           # kit
      ingress[0].traffic_weight,             # kit
      template[0].container[0].env,          # ONLY with the seam detector (the block-list problem)
      tags["release_ownership_stamp"],
      tags["deploy_provenance_digest"],
      tags["deploy_provenance_metadata_sha256"],
      tags["deploy_provenance_run"],
    ]
  }
}
```

**Drift rule (D).** A side that detects a change to a field it does **not** own **reports it to the owner
and does not revert it**: the LZ through its seam detector (`seam_field_drift`, never through the plan,
which no longer shows kit fields), the kit through its snapshot, its posture check and the daily scan of
what serves. Only the owner reconciles, through its own pipeline and under the lease. This is R6 made
operational; it applies equally to a change made by a person under elevation.

## The field-level authority table

Legend. **Owner**: who may write the field in steady state. **Detect**: how the *other* side notices a
change it did not expect. **Response**: what happens then. **Reconciles**: the only party that may put the
field back. "Ledger" means the kit's release record for the target (the KDEC-029 promotion record, plus the
durable copy proposed under *The lease*); "plan" means the LZ's read-only IaC plan (WX-DRIFT); "seam
detector" is the new LZ check specified under *Instead: narrow ignores plus a detector*.

### App Service (`Microsoft.Web/sites`, Linux container)

| Object / field | Owner | Detect (by the other side) | Response | Reconciles |
|---|---|---|---|---|
| The site: existence, plan (`serverFarmId`), SKU/scale, region | LZ | kit: snapshot before mutate (`cmd_capture`) reads the app; missing → refuses | kit refuses to mutate (no established pre-change snapshot) | LZ |
| Networking: `publicNetworkAccess`, VNet integration, private endpoint, `ipSecurityRestrictions`, `scmIpSecurityRestrictions` | LZ | LZ plan | LZ drift class per §3.7 (exposure → critical) | LZ |
| Identity: `identity`, `keyVaultReferenceIdentity`, `acrUseManagedIdentityCreds` | LZ | LZ plan | LZ drift (identity dimension) | LZ |
| Security settings: `httpsOnly`, `minTlsVersion`, `ftpsState`, basic-auth publishing off, `authsettingsV2` | LZ | LZ plan | LZ drift (security-control / authentication) | LZ |
| Platform runtime settings: `alwaysOn`, `healthCheckPath`, `http20Enabled`, logging | LZ | LZ plan | LZ drift | LZ |
| **Configured image**: `siteConfig.linuxFxVersion` of the production site | **kit** | LZ: seam detector compares live value with the ledger's NOW SERVING for production | match → nothing; differs and the ledger names a newer kit run → `KIT_FIELD_RELEASED` (info); differs with no kit run → `KIT_FIELD_UNAUTHORISED_CHANGE`, routed to the app owner and the kit (rollback or forward fix by a kit run); **never reverted by the LZ** | kit (a release or a rollback run) |
| Slot: existence of the staging slot, its networking, identity and security settings (as the rows above) | LZ | kit: the deploy refuses `slot: ''` at uat/prod; a missing slot fails the snapshot | kit refuses; LZ vends the slot | LZ |
| Slot: `linuxFxVersion` of a non-production slot | **kit** | LZ: seam detector vs the ledger's slot entry | as the production image row | kit |
| Slot swap state (which release is in which slot; the swap itself) | **kit** | LZ: seam detector (production image vs ledger) | as the production image row | kit |
| Slot-sticky configuration (`slotConfigNames`) | LZ | kit: reads it in the snapshot; a non-sticky LZ-owned key that differs between slots would move with a swap → kit refuses the swap (`SEAM_SWAP_MOVES_LZ_SETTING`) | LZ makes every LZ-owned key sticky or equal across slots | LZ |
| App settings / connection strings, keys assigned to the LZ (default: all; item 84) | LZ | LZ plan (per key, never the whole map ignored) | LZ drift | LZ |
| App settings, keys assigned to the kit (listed in a new hand-off variable, the kit's setting keys; empty today -- see UNVERIFIED U4 for `DOCKER_*`) | **kit** | LZ: seam detector vs ledger | as the production image row | kit |
| Tags `release_ownership_stamp`, `deploy_provenance_digest`, `deploy_provenance_metadata_sha256`, `deploy_provenance_run` | **kit** | LZ: seam detector (stamp's run id must resolve to a kit run of this target) | unresolvable stamp → `KIT_FIELD_UNAUTHORISED_CHANGE` | kit |
| Every other tag (cost centre, owner, lifecycle, classification ...) | LZ | LZ plan (per tag key) | LZ drift (benign) | LZ |

### Container Apps (`Microsoft.App/containerApps`)

| Object / field | Owner | Detect (by the other side) | Response | Reconciles |
|---|---|---|---|---|
| The app: existence, `managedEnvironmentId`, `workloadProfileName` | LZ | kit: snapshot | kit refuses | LZ |
| `configuration.ingress` except `traffic`: `external`, `targetPort`, `transport`, `allowInsecure`, `ipSecurityRestrictions`, custom domains | LZ | LZ plan | LZ drift (network exposure) | LZ |
| `configuration.activeRevisionsMode` | LZ (kit reads it; its mutate path depends on it) | kit: snapshot | a change between snapshot and mutate → kit refuses the release (it no longer matches the snapshot) | LZ, under the lease |
| `configuration.ingress.traffic` (weights, labels, `latestRevision`) | **kit** | LZ: seam detector vs ledger | as the App Service image row | kit |
| `configuration.secrets`, `configuration.registries` (identity-based pull) | LZ | LZ plan | LZ drift | LZ |
| `identity` | LZ | LZ plan | LZ drift | LZ |
| `template.containers[].image` | **kit** | LZ: seam detector vs ledger (`now_serving`) | as the App Service image row | kit |
| `template.revisionSuffix`, the revision set and which revisions are active | **kit** | LZ: seam detector | as above | kit |
| `template.containers[].env`, key `release_ownership_stamp` | **kit** | LZ: seam detector | as above | kit |
| `template.containers[].env`, every other key (secret refs included) | LZ (per key) | LZ: seam detector per key (see *the block-list problem*) | LZ drift | LZ, **under the lease** (any template change creates a revision) |
| `template.containers[].resources`, `probes`, `template.scale` | LZ | LZ plan | LZ drift | LZ, under the lease |
| Tags (as the App Service tag rows) | kit for its four keys; LZ for the rest | as above | as above | as above |

**A Container Apps template change is a revision.** Any LZ apply that changes an env value, resources,
probes or scale creates a new revision running whatever image the template then holds. That is a
release-shaped event the kit did not make. So an LZ template change is allowed only (a) under the lease,
(b) with the image left as live (the IaC ignores it, so Terraform sends the refreshed value), and (c)
recorded in the seam ledger as a platform revision, so the kit's next ownership check sees a known actor
rather than an unknown one.

### Shared entries (LZ-owned at entry level; never reversed by an app rollback)

| Object | Owner | Detect | Response | Reconciles |
|---|---|---|---|---|
| Front Door / CDN profile; its endpoints, routes, origin groups, origins, rule sets, rules, security policies, custom domains | LZ (the profile is platform; each workload's entries are the LZ's, created by the vend) | kit: never writes them; the rollback refuses them (below). LZ: §3.7 three-way compare | kit: `ROLLBACK_REFUSED_PLATFORM_OWNED`; LZ: entry-level recovery | LZ only |
| DNS zones and record sets (public and private) | LZ | as above | as above | LZ only |
| WAF policies (Front Door, Application Gateway) and their custom rules | LZ | as above | as above | LZ only |
| NSGs and security rules; route tables and routes; firewall policies, rule collection groups, classic firewall collections; load balancers; Application Gateways; VNets and subnets; API Management | LZ | as above | as above | LZ only |
| Edge cache purge after a release | **kit**, for the app's **own** Front Door endpoint only (decided 2026-10-26; *The kit purges its own routes*) | LZ: the Activity Log shows each purge by the kit deploy identity | none -- a purge changes no configuration | -- (nothing to reconcile) |

### Provenance and ownership stamps

| Object | Owner | Consumed by the LZ as |
|---|---|---|
| The release record (KDEC-029 promotion record: digest, environment, `target_resource_id`, `now_serving`, run, validity) | kit | the seam detector's expected value; the destroy evidence packet; `status.json`'s release citation (run id + `routing_result`, read, never derived) |
| `release_ownership_stamp` (tag on App Service, env var on the Container App revision) | kit | "which kit release last claimed this target" -- **not** a lock. The seam review found the LZ destroy's "ownership stamp" read (AT-N125) has two possible meanings; under this contract the LZ destroy decides on the **lease**, and reads the stamp only to name the serving release in its evidence |
| The lease blob's metadata (holder, generation, state) | whoever holds the lease | both sides: the lock, and the "mid-mutation" flag a destroy must respect |

## No blanket `ignore_changes`

The tempting fix for hazard 1 is a Terraform `lifecycle { ignore_changes = all }` on the target, or
`ignore_changes = [site_config, app_settings, tags, template]`. It is refused:

- **It hides every writer, not just the kit.** `ignore_changes` removes the attribute from the plan's
  comparison. A person under elevation (D12) who changes `ipSecurityRestrictions`, turns
  `publicNetworkAccess` on, or sets an app setting is then invisible to the daily plan -- the same plan
  §6.9 relies on to make that elevation "honest". Terraform's own docs: with `all`, "Terraform can create
  and destroy the remote object but will never propose updates to it" (*The lifecycle meta-argument*,
  read 2026-10-26). An ignored field is a field nobody watches.
- **It ignores the LZ's own fields too.** `app_settings` is one map, `tags` one map, `template` one block;
  ignoring the container ignores the LZ-owned keys inside it, so an LZ change to them never applies --
  silent config drift in the platform's own declared state.
- **It turns a release-reverting bug into an unauthorised-change blind spot.** The hazard was "the LZ
  reverts the kit". Blanket ignore swaps it for "nobody notices when anyone else changes the release",
  including a hand-edited image that bypassed the kit's scan and verdict entirely.

**Instead: narrow ignores plus a detector.**

1. The LZ IaC ignores **only kit-owned fields**, by index where Terraform allows it ("You can reference map
   and list elements using index notation, such as `tags["Name"]` and `list[0]`", same page):
   - App Service (`azurerm_linux_web_app`, and each `azurerm_linux_web_app_slot`):
     `site_config[0].application_stack[0].docker_image_name` (and the registry URL attribute if the
     adapter writes it -- U4), `tags["release_ownership_stamp"]`, `tags["deploy_provenance_digest"]`,
     `tags["deploy_provenance_metadata_sha256"]`, `tags["deploy_provenance_run"]`, and
     `app_settings["<k>"]` for each key the hand-off assigns the kit (none today).
   - Container Apps (`azurerm_container_app`): `template[0].container[0].image`,
     `template[0].revision_suffix`, `ingress[0].traffic_weight`, and the four tags.
   - **The block-list problem.** `template[0].container[0].env` is a list of blocks; Terraform cannot
     ignore one element by its `name`. The LZ therefore ignores the env list **and** the seam detector
     compares every env entry by key: LZ-owned keys against the IaC's declared values, the kit's
     `release_ownership_stamp` against the ledger. This is the one place an ignore is wider than the kit's
     field, and the detector is what keeps it from hiding anything. (The alternative -- the kit moving its
     stamp out of the env -- was rejected when the stamp was put there: on Container Apps the revision has
     no tags, and the stamp must travel with the mutation, `cmd_mutate`.) If the LZ's IaC tool is not
     Terraform, the same rule applies in that tool's terms.
2. The LZ runs a **seam detector** -- a read-only job beside WX-DRIFT, same identity (L5p), same schedule
   (at least daily) plus after every LZ apply -- that reads each kit-owned field **live** (not through the
   plan, which no longer shows it) and compares it with the kit's release record for the target:

   | Live vs the kit's record | Outcome | Class (§3.7) | Response |
   |---|---|---|---|
   | equal | `KIT_FIELD_MATCHES_RECORD` | -- | none |
   | differs; a newer kit run for this target explains it (record fetched, run resolved) | `KIT_FIELD_RELEASED` | -- | refresh the cached record |
   | differs; no kit run explains it, or the stamp names a run that is not a kit deploy of this target | `KIT_FIELD_UNAUTHORISED_CHANGE` | operational; **critical** when the image is not a digest the kit verified | `drift.detected` with dimension `release`; notify the app owner and the platform admins; open the kit's path (rollback sequence or forward fix). **The LZ never reverts it** (R6) |
   | the record could not be read, or the field could not be read | `KIT_FIELD_NOT_ATTEMPTED` | -- | `not_attempted`, never "no drift" (the brief's own rule) |
   | an LZ-owned env key differs from the IaC | ordinary IaC drift | per §3.7 | as WX-DRIFT today |

   The Activity Log's caller for the last write on the resource corroborates (kit deploy identity vs
   anyone else) but does not decide: it names the operation, not the field.

## The lease: one lock across both repositories

### What it must do

Both the LZ pipeline (vend, apply, destroy, any template-changing reconcile) and the kit (deploy, single
reversal, rollback sequence) acquire **the same lease for the target** before their first mutation, and
prove they still hold it before each further mutation. A holder that lost it must be refused before it
writes (fencing), and a loss during a write must be reported, not hidden.

### Options compared

| | **A. Azure Storage blob lease per target + generation (fencing token)** | **B. A tag or lock on the target, compare-and-swap with `If-Match`** | C. ARM management lock |
|---|---|---|---|
| Mutual exclusion | Service-enforced: one active lease id per blob; a second acquire is `409` (Lease Blob) | Only if the endpoint honours `If-Match` on the ETag; ARM support is per resource provider and for the tags API is **UNVERIFIED** (U2) | `ReadOnly` blocks the holder too; `CanNotDelete` blocks nothing a deploy does |
| Fencing a stale holder | Lease id + generation in metadata; a read conditional on the lease id fails `409/412` once it is lost (proven as a model) | ETag changes on every write of the resource, including the holder's own deploy, so the token must be re-read after each step -- an ABA race with any other writer | none |
| Expiry and crash recovery | Fixed 15-60 s or infinite; logical expiry in metadata (below); break needs no lease id | none built in; a timestamp in a tag value, trusted by convention | none |
| Survives hazard 1 | Yes: the lock is not on the target, so no IaC rule can overwrite it | **No**: the lock tag lives on the very resource the LZ IaC manages and any `Contributor` (L5, an elevated person) can rewrite | n/a |
| Identity needed | data-plane `Storage Blob Data Contributor` on one container | the target's own write role (already held) | `Microsoft.Authorization/locks/*` -- Owner or User Access Administrator: refused by the hand-off contract's least privilege |
| Network | **data plane**: the runner must reach the storage endpoint -- privately (R8; *The lease store's network*) | control plane only (already reachable) | control plane |
| Cost | one storage account per environment, transactions only | none | none |

**Chosen: A.** It is the only option whose exclusion the service enforces, whose token a stale holder
cannot keep using, and whose lock lives outside the object the IaC manages. B is rejected because the lock
would sit on the field set hazard 1 is about and its compare-and-swap is not established for the tags API.
C is rejected on privilege. **GitHub concurrency is not one of the options and not a control here**: it
is evaluated inside one repository (VERIFIED (doc), hazard 2). The kit's existing group is left as it is
-- it still queues two runs of one target inside one application repository without an Azure call, with
`cancel-in-progress: false` -- but nothing in this contract relies on it, and the LZ must not count a
same-named group as coordination with the kit.

### The other way: one central mutating orchestrator (owner decision O-6)

Instead of a lock both pipelines take, **one system makes every mutation** of a release target: the LZ
apply and the kit deploy become *requests* to it, and it runs them one at a time per target. If that
system is a single GitHub repository, a concurrency group there *would* serialise both, because every run
would then belong to one repository.

| | **Lease taken by both pipelines (option A, built here)** | **Central mutating orchestrator** |
|---|---|---|
| Who can write a target | each side's own least-privilege identity (per app per environment for the kit; L5 for the LZ) | one identity able to write every target -- the widest grant in the estate |
| A mutator that skips the protocol (a person under elevation, a hand-written script) | not stopped; the seam detector finds it afterwards | stopped *if* the orchestrator holds the only write identity -- its strongest argument |
| Failure mode | the lease store down: both sides fail closed, per environment | the orchestrator down: nothing deploys or applies anywhere; a new single point of failure and a high-value target |
| What it changes | adds steps to the existing pipelines (built, opt-in, for the kit) | rebuilds both deploy paths as requests to a third system; the kit's per-application deploy identity and environment approvals move into it |
| Cost | one storage account per environment (transactions only); the private runner network already decided (D-2) | a service to build, run, patch and approve; its own private network path to every target |
| Recalling a mutation already sent | no | no -- serialising does not recall a call either |
| Field ownership (one owner per field) | still required | still required: an orchestrator that applies the LZ's IaC after a release still reverts it without the narrow ignores |

**Recommendation: the lease (A), with ownership rules and the seam detector.** It keeps the
least-privilege, per-repository identity design the owner decided (D-3), it fails closed per target
instead of everywhere, it costs one storage account per environment, and it is built and proven against
an emulator now. Choose the orchestrator instead if the owner wants exactly one identity able to write
release targets (so that skipping the protocol is impossible, not merely detected), or if more than two
pipelines will mutate the same targets. **The choice is the owner's: O-6, recorded in KDEC-030.**

### The protocol (A)

Storage: one storage account per environment, an LZ platform object, shared-key access disabled,
Entra-only, **public network access disabled, reached through a private endpoint** (R8), co-located with
the LZ's IaC state backend (*The lease store's network*, below). **One container per target, keyed by
the target's ARM resource id**: named `t-` + the first 40 hex of `sha256(<resource id, lower-cased>)`
(container names are 3-63 lowercase characters; ARM ids are case-insensitive, so both sides lower-case
before hashing; the resource id is the one name both repositories already know, and unlike
`<env>/<resource-group>/<app>` it cannot collide across subscriptions). For App Service the target is the
**site**, not a slot: a swap changes both. The container holds the blob `lease` and the folder
`releases/` (the kit's durable copy of each release record for the target -- the ledger the seam
detector reads; GitHub artifacts expire). The vend creates the container; a pipeline that finds none is
refused `LEASE_TARGET_NOT_VENDED` (it never creates one: its grant is the container, not the account).

| Step | Rule |
|---|---|
| **Acquire** | `Lease Blob acquire`, duration **-1 (infinite)**, a fresh lease id. Then, holding it, write metadata: `generation` = previous + 1, `holder` (`lz-apply:<run>` / `kit-deploy:<run>-<attempt>` / `kit-rollback:<run>`), `expires_at` = now + heartbeat TTL, `state = clean`, a bounded history. Why infinite: an LZ apply takes 4-27 minutes (brief W4 timing), a kit rollback sequence up to 240; a 15-60 s lease needs a renewer that can die silently between steps. The *logical* expiry carries the liveness instead. |
| **Held** | `409` on acquire → read metadata. Live holder (`now ≤ expires_at`) → the pipeline stops before its first capture or mutation (after login: the storage token needs it) with `LEASE_HELD`, naming the holder, and is re-run (the LZ's event-driven design re-queues it; the kit run fails visibly and is re-dispatched). No waiting loop inside a mutating job. |
| **Renewal (heartbeat)** | The holder re-writes `expires_at` (a metadata write needs its lease id, so only the holder can) before each mutation and at least every TTL/3. TTL default 10 minutes. |
| **Fence** | Immediately before every mutating call: read properties **conditional on the lease id** (fails `409`/`412` once the lease is gone), compare `generation` and `holder` with the token, and check `expires_at`. Any miss: `STALE_LEASE_HOLDER` or `LEASE_EXPIRED_HOLDER`, and the call is not made. |
| **Mutate** | fence → `state = mutating` (+ what) → the call → fence again → `state = clean`. A failed after-fence is `MUTATED_WITHOUT_LEASE` and `ROLLBACK_REQUIRES_HUMAN_DECISION` -- the existing outcome for a mutation whose ownership cannot be established. |
| **Expiry, crash recovery** | A holder past `expires_at` whose `state` is `clean` (it crashed between mutations) is broken and taken over automatically by the next acquirer, generation + 1, `took_over` recorded. A holder that expired with `state = mutating` (it died mid-change) is **not** taken over: `LEASE_ABANDONED_MID_MUTATION`, and a human decides -- the same rule as the kit's "a cancelled or timed-out mutating run ends ROLLBACK_REQUIRES_HUMAN_DECISION" and the LZ's item 89. |
| **Release** | After the last mutation and its verification; refused while `state = mutating` (`RELEASE_MID_MUTATION`). A run that ends without releasing simply expires (crash path). |
| **Break authority** | The platform admins (under privileged activation) and nobody else, through a runbook that records who and why in the metadata and bumps the generation, so every former holder is fenced. **Azure cannot enforce this split**: "Any authorized request can break the lease" (Lease Blob), and break is the same `blobs/write` action the pipelines need. So pipelines never call break; the authority is enforced by code review of the pipelines, by the recorded reason, and by the storage account's diagnostic logs (whether they show the lease action is U3). |
| **Store unreachable** | Fail closed: no mutation, `LEASE_STORE_UNREACHABLE`. A lease that cannot be read is not a lease that is free. |
| **Destroy** | The LZ destroy acquires the lease like any mutation; it is refused while a kit run holds it or while the metadata says `mutating` (this replaces the stamp-based meaning of AT-N125). |

**What the fence does not close.** **Fencing stops a stale holder before its next call; it cannot recall
an Azure mutation already sent.** The Azure target does not check the token. A call already sent when
the lease is broken still lands; the after-fence reports it (`MUTATED_WITHOUT_LEASE`, a human decision).
The kit fences before **every mutating `az` call**, not only before each step (*The kit's wiring*), so
the window is one call. And a writer that does not follow the protocol -- a person in the portal -- is
not fenced at all; the seam detector is what finds that.

### The kit's wiring (built 2026-10-27, OPT-IN)

| Piece | What it is |
|---|---|
| `scripts/target_lease.py` | the model (unchanged), plus `AzureBlobLeaseStore` -- the same five calls sent to the Blob REST API with an Entra bearer token (`az account get-access-token --resource https://storage.azure.com/`; never a shared key) -- and a command line, one subcommand per pipeline step: `acquire` (by `--resource-id`, or `--adapter --subscription --resource-group --name`), `begin`, `fence` (fence + heartbeat), `end` (the after-fence), `release`, `status`, `break`, and **`hold`**. Exit 0 done, 1 refused by name, 2 could not check (fail closed). The fencing token travels between steps in a token file under `$RUNNER_TEMP` (`kit-target-lease/token.json`), never uploaded. |
| `hold` (heartbeat through a long step) | runs the step's command as a child and renews the lease every 180 s (below a third of the 10-minute expiry). **A failed renewal stops the child at once and ends `LEASE_LOST`, exit 1**, and the loss is written beside the token, so every later fence in the run -- including the per-call fence below -- refuses `LEASE_LOST` without asking the store again: no further mutation. `--mark-mutating` marks the lease `mutating` for the whole child run and clean only when it exits 0. |
| The per-call fence (`deploy_contract.az`) | every kit mutation goes through `deploy_contract.az` (the deploy steps; the reversal; the rollback sequence, which runs `deploy_contract.py reverse`; the generic ARM rollback in `rollback_dependencies.py`). When the lease is on, each **mutating** call (`az_is_mutating`: a mutating verb among the command words -- update, set, swap, activate, deactivate, create, delete, restart and the rest -- or `az rest` with any method but get/head/options) is fenced immediately before it is sent; a refused fence returns the call as failed with the code (`STALE_LEASE_HOLDER`, `LEASE_EXPIRED_HOLDER`, `LEASE_LOST`, `LEASE_NOT_HELD`) and the call is **not sent**. Reads are not fenced. Off: the function is unchanged. This replaces "fence before each step" for the steps that send several calls (`mutate` tags then sets the image; `swap`; `reverse` restores several entries; `provenance` tags). |
| `.github/actions/target-lease` | the composite **both sides call** (the LZ from its platform repository, the kit from its deploy reusables); inputs reach the script as environment data. |
| `reusable-deploy-containerapp.yml`, `reusable-deploy-appservice.yml` | after Azure login and before the first capture: `acquire` (holder `kit-deploy:<repo>/<run>-<attempt>`, the site or container app's resource id); `begin` before the first mutation; step fences before the traffic move / swap, the reversal and the provenance stamp (the reversal runs only if its fence passed); `end` after the provenance stamp; the **e2e test period runs under `hold`**; `release` after the test period. A failed mutate or reversal skips `end`, so the lease stays `mutating` and `release` refuses: a human decides. `target_lease.py` is materialised beside the deploy contract (`scripts/inline_deploy_scripts.py`). |
| `reusable-rollback-sequence.yml` | `acquire` **once** for the whole sequence after Azure login (holder `kit-rollback:<repo>/<run>-<attempt>`; the target from the steps' adapter, or for a generic `arm` sequence one live read of the named resource -- an ambiguous name refuses); the sequence runs under `hold --mark-mutating`, so every step's reversal and every test period is covered by the heartbeat and every mutating call by the per-call fence; `release` after (refused while a halted sequence left it `mutating`). |
| The runner | input **`runner_label`** on all three reusables (default `ubuntu-latest`, so no caller changes). A job that takes the lease needs a runner that reaches the store's private endpoint (D-2): a larger GitHub-hosted runner with Azure private networking, or a self-hosted runner in the network. On a runner that cannot reach it, the lease fails closed (`LEASE_STORE_UNREACHABLE`). Recorded in each posture record as not a control surface. |
| The opt-in | each job reads `vars.KIT_TARGET_LEASE_ACCOUNT` from its GitHub environment (the LZ vends it with the other hand-off variables). **Empty: every lease step is skipped, `hold` is not used and the per-call fence is inert: the jobs run exactly as before.** |

**What the wiring still does not cover (stated, not hidden):**

- **DAST and the posture check** run after `release`: neither mutates the target, and the lease exists to
  serialise mutations and the period that tests them. An LZ apply could land during a kit DAST run.
- **Before login.** The contract's "refused before login" is not met: a storage token needs the login,
  so `LEASE_HELD` refuses after login and before the first capture -- still before any mutation.
- **The call already sent.** The per-call fence narrows the window to one call; it cannot recall it.
- **Live.** No call has reached real Azure Storage, and no hosted run has used `runner_label` with a
  private-network runner. Header names and status codes follow Microsoft Learn's Lease Blob, Set Blob
  Metadata, Get Blob Properties and Put Blob pages; U6, U7, U10, U11.

### The LZ side: the same lease from the platform repository

The LZ calls the same composite, pinned to a kit commit, around every job that mutates a release target.
Plan **and** apply run inside one lease hold, so a plan cannot be computed against a state the kit then
changes. One lease per target; an apply that touches several targets takes them in sorted resource-id
order (no two jobs can deadlock) and releases them in reverse.

```yaml
# platform repository: the apply job for one workload target (illustrative; pin every uses: to a SHA)
jobs:
  apply:
    runs-on: [lz-private-network]          # a runner that reaches the lease store's private endpoint (D-2)
    environment: prod                      # required reviewers; L5's federated credential trusts only this
    permissions: { id-token: write, contents: read }
    env:
      LEASE_ACCOUNT: ${{ vars.KIT_TARGET_LEASE_ACCOUNT }}
      TARGET_ID: ${{ vars.TARGET_RESOURCE_ID }}   # the ARM resource id the vend created
    steps:
      - uses: actions/checkout@<sha>
      - uses: azure/login@<sha>
        with: { client-id: "${{ vars.AZURE_CLIENT_ID }}", tenant-id: "${{ vars.AZURE_TENANT_ID }}",
                subscription-id: "${{ vars.AZURE_SUBSCRIPTION_ID }}" }
      - name: Target lease -- acquire (refused LEASE_HELD while a kit deploy holds it)
        uses: <org>/secure-cicd-kit/.github/actions/target-lease@<kit-sha>
        with:
          op: acquire
          account: ${{ env.LEASE_ACCOUNT }}
          resource-id: ${{ env.TARGET_ID }}
          holder: lz-apply:${{ github.repository }}/${{ github.run_id }}-${{ github.run_attempt }}
      - run: terraform plan -input=false -out=tfplan
      - name: Target lease -- fence and mark the mutation
        uses: <org>/secure-cicd-kit/.github/actions/target-lease@<kit-sha>
        with: { op: begin, what: "terraform apply" }
      - run: terraform apply -input=false tfplan
      - name: Target lease -- end (MUTATED_WITHOUT_LEASE if it was lost in flight)
        uses: <org>/secure-cicd-kit/.github/actions/target-lease@<kit-sha>
        with: { op: end }
      - name: Target lease -- release (refused while still mutating)
        if: "!cancelled()"
        uses: <org>/secure-cicd-kit/.github/actions/target-lease@<kit-sha>
        with: { op: release }
```

Outside GitHub Actions (a wrapper around `terraform apply` on another runner) the same calls are
`python3 scripts/target_lease.py acquire --account <acct> --resource-id <id> --holder lz-apply:<run>
--token-file <f>`, then `begin --what ...`, the apply, `end`, `release`, each stopping the wrapper on a
non-zero exit. A long apply calls `fence` (the heartbeat) at least every TTL/3.

### The lease store's network (decided 2026-10-26)

Azure Storage supports private endpoints, so under R8 the lease store is private: public network access
off, one private endpoint for the `blob` sub-resource, the private DNS zone `privatelink.blob.core.windows.net`
linked to the network the runners use. Storage is not where the constraint lies; the runner is.
GitHub-hosted standard runners cannot reach a private endpoint. In the owner's order of preference:

| Order | Runner | What it needs | Notes |
|---|---|---|---|
| **(a) preferred** | **GitHub-hosted runners with Azure private networking** (the runner's network interface is placed in the organisation's Azure VNet) | GitHub Team or GitHub Enterprise Cloud: "Enterprises and organizations on GitHub Enterprise Cloud or GitHub Team plans can configure Azure private networking" (GitHub Docs, *Private networking with GitHub-hosted runners*). **Larger runners only**: "Azure VNET private networking is only available for larger runners" (GitHub Docs, *About Azure private networking for GitHub-hosted runners in your enterprise*), billed per minute at the larger-runner rate. A subnet delegated to GitHub's network settings resource, in a supported region | **GHE.com data residency: supported**, with its own region list (*Network details for GHE.com*: EU francecentral, northeurope, germanywestcentral, swedencentral; Australia australiaeast, australiacentral; US centralus, eastus2, westus3; read 2026-10-26). The runner reaches the private endpoint through the VNet; no public endpoint, no inbound port. The kit's required-reviewer gates already assume an Enterprise plan on private repositories |
| (b) | Self-hosted or Actions Runner Controller (ARC) runners in the VNet | runner hosts the organisation patches and hardens; ephemeral runners only (one job per runner) | the kit's hosted-runner assumptions (tool versions, `ubuntu-latest` images) must be re-proven on them |
| (c) last | A **documented, time-boxed exception to R8**: the account's public endpoint with Entra-only auth and shared key off | only if neither (a) nor (b) is available; recorded under the LZ's exception process with an expiry and an owner | never silently renewed; the exit is (a) or (b) |

**Co-location.** The lease store sits **with the LZ's Terraform state backend, under the same network
design**: the same resource group (the LZ's state resource group), the same private-endpoint subnet and
private DNS zone, the same runner network. Neither the LZ identities nor its state backend are built yet
at the building organisation, so this is **design-time guidance, not a retrofit**: build both together.
Recommended: a **sibling storage account** in that resource group rather than a container in the state
account itself. State files hold secrets; a container-scoped grant to every kit deploy identity on the
state account would put account-level operations (network rules, keys, diagnostics) one misconfiguration
away from state. Same network, separate account, separate grants.

**Workflow consequence (owed, after L-PROMO merges).** Every job that takes the lease -- the kit's deploy
and rollback jobs, the LZ apply and destroy -- runs on the private-network runner group. The kit's
reusables gain a runner-label input for those jobs; the scan and build jobs stay on standard runners.

### Identities: the design to build from the start (decided 2026-10-26)

**No LZ identity exists yet** at the building organisation. The table below is the design to create, not
a change to existing grants. The names (L5, L5p, L5v) are the LZ builder brief's.

| Identity | Kind | Federated subject (one per identity) | Azure control-plane roles | Lease-store data-plane role |
|---|---|---|---|---|
| **Kit deploy identity**, one per application per environment | app registration or user-assigned managed identity | `repo:<org>/<app-repo>:environment:<env>` (in the form the repository presents) | `Website Contributor` (App Service, on the app and its slots) or `Container Apps Contributor` (on the container app); `Reader` on the app's resource group; the **edge purge role** on the app's own Front Door endpoint, where it has one | `Storage Blob Data Contributor` on **its target's container only** |
| **LZ vend** (L5v) | as above | `repo:<org>/<platform-repo>:environment:<env>-vend` | resource-group and tag write by custom role; conditioned role-assignment rights (brief W0) | creates the target's container (control plane) and its container-scoped grant |
| **LZ apply / destroy** (L5) | as above | `repo:<org>/<platform-repo>:environment:<env>` -- an environment **with required reviewers** for prod and every destroy | see *Contributor only when required* (recommended, for discussion) | `Storage Blob Data Contributor` on the lease account |
| **LZ plan / drift** (L5p) | as above | `repo:<org>/<platform-repo>:environment:<env>-plan` | `Reader` on the workload resource groups; **separate from L5** | `Storage Blob Data Reader` on the lease account |
| Kit build identity | as above | the build job's environment | `AcrPush` on the app's registry repository | none |
| Humans (break-glass, maintenance) | users | -- | PIM-eligible only (below) | eligible `Storage Blob Data Contributor`, for the break-lease runbook |

Federated credentials are subject-scoped to one environment of one repository ("For Jobs tied to an
environment: `repo:< Organization/Repository >:environment:< Name >`", Microsoft Learn, *Configure an app
to trust an external identity provider*), so a credential is usable only by a job running in that
environment, which the environment's reviewers and branch policy gate.

**The AT-N121 correction stands** as a correction to the LZ brief: as written, L5 holds `Contributor` on
the workload resource group, which can write an image; "refused by role" holds only once L5's rights on the
application target are narrowed (next section).

### Contributor only when required (RECOMMENDED, FOR DISCUSSION)

**Workload identities cannot use PIM.** Microsoft Learn: "you can't create eligible role assignments for
applications, service principals, or managed identities because they can't perform the activation steps"
(*Eligible and time-bound role assignments in Azure RBAC*), and "You can't assign service principals as
eligible to Microsoft Entra roles, Azure roles, and PIM for Groups but you can grant a time-limited active
assignment to all three" (*Plan a Privileged Identity Management deployment*). So for automation "only
when required" has to mean something else:

| Option | What it is | Assessment |
|---|---|---|
| 1. Standing `Contributor` on the subscription | -- | refused: the brief's own §5.19 lesson |
| 2. Standing `Contributor` on each workload resource group (the brief today) | broad, always usable | usable by any run that can mint the token; the image-write gap behind AT-N121 |
| **3. Usable only in an approved run, narrowest role** (recommended) | (i) L5's federated credential trusts only `environment:<env>` with **required reviewers** (and `dev-gated` where the brief uses it), so a token exists only inside an approved run; (ii) **custom roles** where the actions separate cleanly (network, identity, diagnostics, tags), `Contributor` at the **narrowest scope** (one workload resource group) only where they do not; (iii) on application targets, the target's release-field write actions **excluded** from L5's custom role once the vend's needed actions are observed, so AT-N121 holds by role; (iv) L5p stays a separate, read-only identity | the closest automation gets to just-in-time: the credential is inert outside an approved run |
| 4. A time-limited active assignment granted per run | a broker grants L5 an active, time-bound assignment before each apply and removes it after | needs a second, more privileged identity to grant it -- moves the standing privilege, does not remove it |

**Break-glass and maintenance outside the pipelines are done by humans**, never by a pipeline identity:

- **PIM-eligible `Contributor` on the specific resource group**, through **PIM for Groups** (just-in-time
  membership of a group that holds the assignment; Microsoft Learn, *Plan a Privileged Identity Management
  deployment*, "PIM for Groups").
- Activation requires **approval, a justification and a ticket reference**; **short activation** (for
  example 4 hours); **activation alerts** to the platform admins and the security function.
- **Two cloud-only emergency access accounts** for when Entra ID or PIM itself is impaired, following
  Microsoft Learn *Manage emergency access accounts in Microsoft Entra ID*: at least two; cloud-only
  (`.onmicrosoft.com`); phishing-resistant authentication; excluded only from Conditional Access policies
  that block or restrict sign-in ("Report-only policies don't require an exclusion"); every sign-in
  alerted; validated "at least every 90 days".

**Afterwards.** Any manual change to a seam field is caught -- a kit-owned field by the seam detector and
the kit's release record, an LZ-owned field by the LZ plan -- and must be **reconciled**: codified (an IaC
change, or a kit release) or reverted, **through the owning side** (R6).

**Two different break-glasses.** The kit's own pipeline break-glass (KDEC-029: a release through the
deploy identity under an exception record, its testing owed) is a **pipeline** path, recorded in the
kit's promotion record. The human break-glass above is **PIM or an emergency account**, outside every
pipeline. Neither substitutes for the other, and a human break-glass change is never recorded as a kit
release.

## The kit purges its own routes (decided 2026-10-26)

After a **verified** release (NOW SERVING read back, health passed), the kit purges the edge cache of
**only the app's own Front Door endpoint and routes**: the endpoint and domains the hand-off names for the
target, paths limited to the app's own route patterns. Apps without Front Door: not applicable, and the
step records `not applicable`, never a pass.

- **Role:** a custom role holding the purge action only, `Microsoft.Cdn/profiles/afdendpoints/Purge/action`
  (Azure resource provider operations, Networking, `Microsoft.Cdn`: the Front Door Standard/Premium
  endpoint purge; read 2026-10-26), assigned to the kit deploy identity **at the app's own
  `afdEndpoints/<name>` scope**. Whether the long-running purge's status poll also needs a read action
  (under `Microsoft.Cdn/operationresults/profileresults/afdendpointresults/`) is U8.
- **Scope limit.** RBAC scopes the purge to an endpoint, not to a route or path. If several apps shared one
  endpoint, the request body's domains and paths would be the only limit, and RBAC does not enforce them;
  so the LZ vends **one endpoint per user-facing app** and names it in the hand-off, and the kit refuses to
  purge an endpoint the hand-off does not name as the app's own.
- **Fewer purges:** recommend **versioned (content-hashed) asset names** in each app's build, so a release
  needs a purge only for unversioned entry documents (`/`, `index.html`), not every asset.
- This closes the seam review's cache-purge GAP; the LZ's W4 step 8 purge stays for the first release only.

## Rollback: what the generic ARM rollback must refuse

Today `rollback-resource-classes.yaml` classes a type `SHARED_MULTI_CONFIG` (reverse the product's
entries) or `STABLE` (reverse the whole resource if nothing else changed it). Both classes describe *how*
a resource can be reversed; neither says *who may*. KDEC-030 adds the owner:

| Change | Detail |
|---|---|
| New per-type key `entry_owner` | `"landing-zone"` on every `SHARED_MULTI_CONFIG` type (Front Door / CDN profiles, classic Front Door, both WAF policy types, firewall policies, Azure Firewall, Application Gateway, route tables, NSGs, load balancers, VNets, DNS and private DNS zones, API Management) and on the platform `STABLE` types (`serverfarms`, `managedEnvironments`, `privateEndpoints`, `userAssignedIdentities`, `roleAssignments`, Key Vault, storage, registries, databases). `"kit-release-fields"` on `Microsoft.Web/sites` and `Microsoft.App/containerApps` only: the kit may reverse **its own fields** there, which is what the deploy contract's own reversal already does. |
| New dependency-review mark | A node whose type's `entry_owner` is `landing-zone` is **blocked** with the reason platform-owned, whatever its mark, before any other rule. Existing rules then block everything that depends on it or is evaluated together with it (unchanged). |
| New outcome | `ROLLBACK_REFUSED_PLATFORM_OWNED` (`rollback_dependency_outcome`), routed `ROLLBACK_REQUIRES_HUMAN_DECISION` and naming the LZ's recovery (W7, §3.7) as the reverser. The graph still shows the node, so the human sees what the release touched. |
| New input check | A step's `resources.json` whose `release_id` is not a kit deploy run of the locked target (for example an LZ apply's evidence) is refused before anything is read live: `ROLLBACK_REFUSED_FOREIGN_EVIDENCE`. |
| The `arm` adapter's scope | Narrowed to resources an application release itself created inside its own resource group and that are not platform types. A release that needs a shared entry changed asks the LZ (a manifest change), so the kit never holds a reversal for it. |
| Unchanged | The SHARED/STABLE mechanics, the byte-identical read-back of other entries, the graph. They remain correct for any non-LZ deployer that uses the kit's rollback on its own entries. |

Files: `rollback-resource-classes.yaml` (the key), `scripts/rollback_dependencies.py` (the mark and the
outcome), `scripts/rollback_sequence.py` (the evidence check), `assurance-taxonomy.yaml` (two outcomes),
`ROLLBACK_CONTRACT.md` (the cross-edited section), proven by new cases in
`tests/prove_rollback_dependencies.py` and `tests/prove_rollback_sequence.py`.

## What each side must change

**The landing zone** (for a later delta to the LZ builder brief; the brief is not edited here):

1. Adopt the authority table above as the target's field ownership; record it in the vend output per target.
2. IaC: narrow `ignore_changes` on exactly the kit-owned fields listed under *Instead*; **never**
   `ignore_changes = all` or a whole `site_config`, `app_settings`, `tags` or `template`. The env-list
   exception goes with the seam detector, or not at all.
3. Build the seam detector beside WX-DRIFT (outcomes and responses above); add `release` as a drift
   dimension; auto-remediation (Phase 3) must never touch a kit-owned field.
4. Vend the lease storage account per environment beside the IaC state backend (same resource group,
   same private network), private endpoint only, shared-key access off; one container per target; build
   the identities of the identity design from the start, with the grants in its table.
5. Every apply, destroy and template-changing job acquires the target's lease first (the kit's
   `target-lease` composite, keyed by the resource id; *The LZ side*), plans and applies inside it, fences
   before each mutating step, releases after verification. Replace "concurrency keyed on environment and
   target" (item 89, AT-N129) with the lease; any concurrency group the LZ keeps queues its own runs only
   and is not coordination with the kit. Vend `KIT_TARGET_LEASE_ACCOUNT` into each kit environment.
6. Destroy: decide on the lease (refuse while held or `mutating`), not on the kit's stamp (AT-N125).
7. Container Apps: any template change runs under the lease, keeps the live image, and is recorded in the
   target's `releases/` as a platform revision.
8. App Service: every LZ-owned app setting is slot-sticky or equal across slots.
9. Emit the kit's setting keys as a new hand-off variable (empty by default) and refuse an IaC key that is in it.
10. Correct AT-N121's "refused by role": as written, L5's `Contributor` can write an image; under the
    recommended identity design the target's release-field writes leave L5's custom role and it holds by role.
11. Shared entries: the LZ is their sole reverser; never pass an LZ apply's evidence to the kit's rollback.
12. Provide private-network runners for the apply, destroy and lease jobs (order (a), (b), (c) above).
13. Vend one Front Door endpoint per user-facing app, name it in the hand-off, and grant the purge role.
14. Human break-glass: PIM for Groups, approval + justification + ticket, short activation, alerts; two
    emergency access accounts per Microsoft's guidance.

**The kit** (L-PROMO has merged; items 2-6 and 8 built 2026-10-28 on lane `lane/lz-strengths`, the
LZ-vs-kit review OF-5, KDEC-034 PROPOSED -- every one opt-in with the lease, as item 1):

1. **Built 2026-10-27, opt-in** (*The kit's wiring*): the live adapter, the composite, both deploy
   reusables (the test period held with a heartbeat) and the rollback sequence (one lease for the
   sequence, held through every step and test period), with a fence before every mutating `az` call.
2. **Built (K-4):** each release record written create-only into the target's `releases/`
   (`target_lease.py record`, `RELEASE_RECORD_KEPT`); the GitHub artifact stays too. Retention is the
   LZ's immutability policy on the container, read and recorded. `tests/prove_release_record_store.py`.
3. **Built (K-6):** the `seam` step refuses an app-setting or env write outside the kit's assigned keys,
   or a kit key the LZ also claims (`SEAM_SETTING_OWNERSHIP_CONFLICT`), and a swap that would move a
   non-sticky LZ-owned key (`SEAM_SWAP_MOVES_LZ_SETTING`), before the first mutation.
   `tests/prove_seam_setting_ownership.py`.
4. **Built (K-5):** the rollback changes in the table above (`entry_owner`, `--seam-ownership`).
   `tests/prove_seam_app_rollback_refuses_shared_entry.py`.
5. **Built (K-7):** `LZ_KIT_HANDOFF_CONTRACT.md` "The extended hand-off set": `KIT_TARGET_LEASE_ACCOUNT`,
   `KIT_SETTING_KEYS`, `KIT_RELEASE_BLOCK`, `KIT_ZONE_READINESS`, `KIT_EDGE_ENDPOINT`, `KIT_ACR_*` as
   repository variables, the lease data-plane role and the purge-only role. `tests/prove_handoff_extended.py`.
6. **Built:** the outcomes registered in `assurance-taxonomy.yaml` (no longer CANDIDATES, except
   `seam_field_drift`, whose emitter is the LZ's seam detector).
7. **Built 2026-10-27:** the `runner_label` input on both deploy reusables and the rollback sequence
   (default `ubuntu-latest`); a private-network runner is the consumer's to supply (D-2).
8. **Built (K-7, D-4):** the post-deploy purge of the app's own endpoint (`EDGE_PURGED`;
   `EDGE_PURGE_NOT_APPLICABLE` without one, never a pass; a failed purge is an advisory).

## Negative tests to build after L-PROMO merges

Each runs the shipped job against the stub cloud plus an emulated blob service; the live versions are owed
to the owner's personal tenant.

| Name | Setup | Expected |
|---|---|---|
| `prove_seam_concurrent_lz_apply_and_kit_deploy` | LZ apply holds the target's lease; a kit deploy of the same target starts | kit refuses `LEASE_HELD` before its first mutation, naming the LZ run; reverse order the same; a different target proceeds in parallel (control) |
| `prove_seam_deploy_during_rollback` | a kit rollback sequence holds the lease mid-test-period; a deploy of the target is dispatched (from another repository, so concurrency cannot queue it) | the deploy refuses `LEASE_HELD`; nothing mutated; the sequence's after-fence still passes |
| `prove_seam_lz_destroy_during_deploy` | a kit deploy holds the lease with `state = mutating`; the LZ destroy starts | destroy refused before its first step; after the deploy's holder expires mid-mutation, still refused (`LEASE_ABANDONED_MID_MUTATION`) until the break authority acts |
| `prove_seam_expired_holder_fenced` | a kit deploy's lease is broken by the authority and the LZ acquires; the kit job reaches its next mutating step | the step is refused `STALE_LEASE_HOLDER`, no `az` mutating call is made, the run ends `ROLLBACK_REQUIRES_HUMAN_DECISION` |
| `prove_seam_lz_drift_on_kit_field` | after a verified release, the stub cloud's image is changed by "someone else" (no kit run); the LZ plan and the seam detector run | the plan proposes **no** change to the image (narrow ignore); the detector reports `KIT_FIELD_UNAUTHORISED_CHANGE`; nothing reverts it; an LZ-owned key changed the same way is ordinary IaC drift (control) |
| `prove_seam_app_rollback_refuses_shared_entry` | an `arm` rollback step whose `resources.json` names a Front Door route, a DNS record and a WAF rule, plus one non-platform node | the three are `ROLLBACK_REFUSED_PLATFORM_OWNED`, nothing of them is read-for-reversal or written; the free node is reversed only if nothing depends on the refused ones; LZ-apply evidence is `ROLLBACK_REFUSED_FOREIGN_EVIDENCE` |

## Stub-level proofs now

`tests/prove_target_lease.py` (run in self-test) proves the lease protocol over an in-memory emulation of
the Lease Blob semantics in `scripts/target_lease.py`: the emulation's own states and status codes (B1-B5);
`LEASE_HELD` naming the holder; **fencing refuses a stale holder** after a break and re-acquire, after a
break with nobody re-acquiring, past its own expiry, with a stale generation, and with the right generation
but the wrong lease id; generations strictly increase; expired-clean takeover; no takeover mid-mutation;
break authority; a lease lost during a mutation reported `MUTATED_WITHOUT_LEASE`; no release mid-mutation;
and a control where the rightful holder is never refused. Written test-first (the proof ran `UNKNOWN`, exit
2, before the module existed), and each fence check was removed in turn to confirm a case fails without it.

`tests/prove_target_lease_crossrepo.py` (2026-10-27, run in self-test) proves it **across two independent
callers**: separate processes with separate working directories ("repo-lz", "repo-app") and token files,
each running the shipped CLI through the live REST adapter against a local HTTP emulation of the Blob
service (the emulation's lease semantics are the model's `BlobLeaseStore`). X1-X11: the second caller is
refused `LEASE_HELD` naming the first (also for the resource id in another case); another target
proceeds; the break authority; the broken holder's next fence **and** its next `begin` refused
`STALE_LEASE_HOLDER`; renewal keeps the target past the original expiry; a silent clean holder is taken
over and then fenced; an expired mid-mutation holder is not taken over and cannot release; a lease lost in
flight is `MUTATED_WITHOUT_LEASE`; the full control path; fail closed (`LEASE_STORE_UNREACHABLE`,
`LEASE_TARGET_NOT_VENDED`, plain http to a non-loopback host refused). W1-W6 check the wiring statically:
the composite, acquire after login and before the capture, a fence before every mutating step, the
guarded reversal, end and release after the last mutation, every lease step off unless opted in. Written
first: before the adapter, CLI, composite and wiring existed, 30 of its 31 cases failed (the 31st, X8c,
is a "nothing happened" check that passes vacuously). Removing the fence's lease-id and generation checks
fails X5b, X5c and X7b; removing one deploy fence fails W4. Second pass (same day, also written first: 16
of its 20 new cases failed before the code): H1-H4 `hold` -- a 3-second lease renewed every second
outlives itself while a contender is refused; a break mid-period stops the held step at once,
`LEASE_LOST`, and the loss is sticky; `--mark-mutating` leaves a halted sequence `mutating` -- A1-A5 the
per-call fence through the shipped `deploy_contract.az` against an `az` stand-in (a broken lease: the
mutating calls are not sent, reads still are; no token: `LEASE_NOT_HELD`; lease off: unchanged; the
classifier), W7-W10 the runner input, the held test period, the rollback sequence and the materialised
script. Removing the per-call fence fails A2 and A3; removing the renewal fails H1 and H2.

**The integrated gate.** Integrated testing of an LZ apply together with a kit deploy against the same
target **stays closed** until (1) both sides use the **live** lease (a real storage account, the private
path, the real identities) and (2) the field-ownership rules are in force in that test: the LZ IaC carries
the narrow `ignore_changes` above and the seam detector runs. A stub or emulator result does not open it.

Vocabulary: `assurance-taxonomy.yaml` registers `target_lease` (emitted by the model and the CLI),
`seam_ownership_refusal` and `seam_ownership_check` (the deploy's `seam` step, OF-5 K-6), the two
`rollback_dependency_outcome` values (the ARM rollback, K-5), `release_record` (K-4) and `edge_purge`
(D-4). `seam_field_drift` stays a CANDIDATE: the LZ's seam detector emits it.

## Decided 2026-10-26, and what stays open

| # | Point | Status |
|---|---|---|
| D-1 | Public endpoints only where a private link or endpoint is technically impossible (R8) | **decided 2026-10-26** |
| D-2 | The lease store is private; runners in the order (a) Azure private networking, (b) self-hosted/ARC in the VNet, (c) a time-boxed exception; co-located with the IaC state backend under the same network design | **decided 2026-10-26** |
| D-3 | No LZ identity exists yet: the identity table is the design to build from the start; the AT-N121 correction stands | **decided 2026-10-26** |
| D-4 | The kit purges its own Front Door endpoint after a verified release, with a purge-only custom role; versioned asset names recommended; not applicable without Front Door | **decided 2026-10-26** |
| O-1 | Approve KDEC-030 as a whole (rules R1-R8, the table, lease option A) | open; recommended: approve |
| O-3 | Contributor only when required: option 3, with human break-glass through PIM for Groups and two emergency access accounts | **recommended, for discussion** until the owner confirms |
| O-5 | Heartbeat TTL (default 10 minutes) | open; recommended: keep |
| O-6 | The cross-repository lock: the lease taken by both pipelines (A), or one central mutating orchestrator | **open, owner decision**; recommended: the lease (*The other way*, above) |
| O-7 | The integrated gate: LZ apply + kit deploy testing stays closed until both sides use the live lease and the field-ownership rules in a test | proposed by the lane; the owner may tighten, not loosen |

## UNVERIFIED

- **U1** *Narrowed 2026-10-27:* the documented wording is VERIFIED (doc) (hazard 2: "in the repository",
  both pages, URLs given). Still not run: no hosted test with two repositories sharing a group name.
- **U2** ARM `If-Match` support for the tags API and for `Microsoft.Web`/`Microsoft.App` writes (option B).
- **U3** Whether Storage diagnostic logs record the lease action (acquire vs break) of a `LeaseBlob` call.
- **U4** Whether `az webapp config container set --container-image-name` writes any `DOCKER_*` app setting
  besides `linuxFxVersion`; if it does, those keys join the kit's setting keys and the LZ ignore list.
- **U5** The exact Terraform attribute paths above (`azurerm` 3.x/4.x names); the rule is the field, the path
  is illustrative until checked against the LZ's provider version.
- **U6** The lease protocol is a model; no live blob, identity or network path has been exercised.
- **U7** Azure private networking for hosted runners: plan eligibility and the GHE.com region list are READ
  from GitHub Docs (2026-10-26), not configured or run; whether the building organisation's plan and region
  qualify is unknown.
- **U8** Whether the Front Door purge's status poll needs a read action beyond
  `Microsoft.Cdn/profiles/afdendpoints/Purge/action`, and that an `afdEndpoints` child scope takes the
  custom-role assignment as expected. Read, not run.
- **U9** Option 3's custom-role split for L5 depends on the actions the vend's IaC actually uses, which
  cannot be observed until it runs.
- **U10** That `az account get-access-token --resource https://storage.azure.com/` yields a token the
  Blob service accepts in the US Government cloud as well as the public one (the adapter uses the same
  resource for both; only the endpoint suffix differs).
- **U11** The live adapter's REST details against the real service: the `x-ms-version` used
  (`2021-12-02`), the 404 error codes `ContainerNotFound`/`BlobNotFound`, a `HEAD` conditional on
  `x-ms-lease-id` returning 409/412 on a lost lease, and whether a container-scoped
  `Storage Blob Data Contributor` may create the `lease` blob. Read from Microsoft Learn; exercised only
  against the emulator.

## Sources read for this contract

Kit (`fix/normalization-and-discovery` 4060290): `LZ_KIT_HANDOFF_CONTRACT.md`; `rollback-resource-classes.yaml`;
`deploy_contract.py` header, `cmd_mutate`, `cmd_swap`, `resource_id`, `cmd_provenance`; the concurrency blocks
of both deploy reusables and the rollback-sequence reusable with its header and inputs; `rollback_sequence.py`
header and input loading; `rollback_dependencies.py` header; `ROLLBACK_CONTRACT.md` "Cross-edited resources";
KDEC-029's promotion-record schema on `lane/promotion` (read only). LZ (builder brief, newest branch, read
only): §0.5 W0-W8 in full, §0.7 with the kit preconditions, §0.10 items 73-90, §0.T.4, §0.T.6 with the
deployment policy, §3.4, §3.7 readiness through drift taxonomy (Recovery in full), §6.8, §6.9, §6.13,
D7-D16, acceptance rows AT-P26-P28, AT-N67, AT-N121, AT-N125-N129, AT-N132-N134; the product files
`DEPLOYMENT.yaml`, `WORKFLOWS-03.yaml` (W4, whole), `WORKFLOWS-04.yaml` (W7, W8, WX-ASSESS, WX-DRIFT), the
shared deployment-authority file (paths, defaults, LZ rows). `landing-zone-platform`: README (an
unimplemented founding note; no IaC exists in either LZ location). The seam review itself. External: GitHub
Docs (concurrency; workflow syntax; private networking for GitHub-hosted runners; network details for
GHE.com), Microsoft Learn (Lease Blob; eligible role assignments in Azure RBAC; PIM deployment plan and PIM
for Groups; emergency access accounts; workload identity federation trust; resource provider operations for
`Microsoft.Cdn`), HashiCorp (`lifecycle`), all read 2026-10-26. **Not read:** the rest of the LZ brief (about 80%), the LZ schemas and negative-test files.
