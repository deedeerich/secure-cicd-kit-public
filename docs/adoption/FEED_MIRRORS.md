# Feed mirrors — the organisation hosts the scanners' data feeds (Release 4)

```
Truth State:   KDEC-032 PROPOSED (lane L-MIRROR, 2026-10-27). BUILT AND PROVEN LOCALLY ONLY.
               Nothing here has run against a real storage account, private endpoint, registry or
               runner. tests/prove_feed_mirror.py (M1-M14) proves the logic on file:// fixtures and
               runs the consumer composites' steps as shipped; infra/feed-mirrors passes
               `terraform validate` (azurerm 4.81.0), tflint and Trivy's own misconfiguration scan.
               The first live run is the "Verify" section below.
Audience:      the owner, at work; the platform team that deploys into the security platform
               subscription; whoever adopts the kit in an application repository
Decision:      KDEC-032 (.context/products/secure-cicd-kit/decisions.md)
```

Owner, 2026-10-27: *"release 4 could have the mirrors yes? I could have it in the security platform
azure subscription"*.

## What it is, in one paragraph

Every scan reads public feeds: the **NVD datafeed** Dependency-Check builds its database from, the
**CISA KEV catalog** (known exploited vulnerabilities, which blocks at every rung), the **Trivy
vulnerability database** (with its Java index), **Trivy's misconfiguration checks bundle** (`trivy config`)
and the **OSV database** (the malicious-package scan). Across hundreds of repositories each pulls them itself,
cold, from third-party hosts, and `actions/cache` cannot be shared between repositories. With the
mirrors, **one scheduled job** refreshes all five into a **private storage account** in the security
platform subscription, and every scan reads them from there. Optionally it also copies the **scanner
images** (Semgrep, gosec, gitleaks) **by digest** into a private registry. Each refresh writes a **manifest** per feed:
source, upstream version and timestamp, sha256 and size of every file, `refreshed_at`. A scan uses a
mirror only when it is **current (refreshed within 48 hours) and intact (every byte it reads matches the
manifest)**. Otherwise it **refuses by name**. It never falls back to "clean", and never to the public
feed unless you configured that and the run records it.

## The pieces

| Piece | Where | What it does |
|---|---|---|
| Azure side | `infra/feed-mirrors/` (Terraform) | Storage account with the static website (`$web`), public network access **off**, shared key **off**; private endpoints `web` (read) and `blob` (write) with their private DNS zones; the refresh identity (a user-assigned managed identity, federated to one GitHub environment) with **Storage Blob Data Contributor on the `$web` container only**; optional Premium registry (anonymous pull, public access **off**, private endpoint) with **AcrPush on that registry only**; blob write/delete audit to Log Analytics |
| The refresh | `.github/workflows/reusable-feed-mirror-refresh.yml` + `.github/actions/feed-mirror-refresh` | Per feed: fetch → verify upstream → new generation → upload → manifest **last** → read back through the consumer path → prune. Images: copy by digest, prove it resolves at the same digest |
| The starter | `templates/feed-mirror-refresh.yml` | Daily at 04:17 UTC + manual dispatch, one concurrency group, installed **once** in the repository that owns the mirror |
| The consumer | `.github/actions/feed-mirror`, `.github/actions/known-exploited`, `scripts/feed_mirror.py` (`consume`), `scripts/feed_mirror_step.sh` | Reads the manifest, checks age and integrity, delivers the feed or refuses by name |
| Wired into | `reusable-nvd-cve.yml` (NVD, Trivy, the checks bundle for its Dockerfile scan, KEV); `reusable-security.yml` (deps-scan, image-scan, iac-scan's checks bundle, malicious-deps' OSV database, security-gate's KEV, and the sast-semgrep, sast-go and secret-scan images); `reusable-build-docker.yml`; `reusable-deploy-appservice.yml` / `-containerapp.yml` (promotion re-scan, KEV); `reusable-deployed-scan.yml`; the `deps-scan`, `iac-scan`, `secret-scan` and `docker-build-push` composites | Each reads the mirror variables below. With none set, nothing changes |

## Design choices, and why

1. **A static website, read anonymously over a private endpoint.** Dependency-Check reads its datafeed
   itself over HTTP(S) and accepts no bearer token (only basic credentials), so a datafeed behind Entra
   auth is not readable by it. A static website serves `$web` anonymously ("Disabling anonymous access
   on a storage account ... doesn't affect static websites", Microsoft Learn), and with public network
   access off and a private `web` endpoint, **the network is the access control**: only the private
   network can read, and what it reads is public data whose integrity the manifest's sha256 carries.
   Consequence: **scan jobs need no Azure role and no login at all**. Only the refresh writes, with Entra.
2. **Trivy's database as files, not as an OCI artifact.** Trivy supports both: a `--db-repository` OCI
   registry, or the air-gapped layout (the database placed in the cache, `--skip-db-update`). Files give
   **one** storage plane, **one** access model (the same anonymous private read), and a sha256 the kit
   checks itself before Trivy sees a byte. An OCI repository would need the registry's anonymous pull
   for every scan and would put integrity in a tag the kit does not verify.
3. **The NVD source is the Dependency-Check project's own datafeed, not the NVD API.** It is the source
   every scan already reads today (`nvd_datafeed_url`'s default), so the mirror changes **where** the
   data is read, not **what**. It is published by the project whose code runs the scan. And the NVD API
   was measured (lane L-NV, 2026-10-21) at ~10-40 kB/s per response; keyed cold builds sat at
   10,000-20,000 of ~413,000 records after 35 minutes, while the project's datafeed built the same
   database in 91-95 s. The refresh does not trust it blindly: every year's `.json.gz` is checked
   against its own `.meta` (sha256 of the uncompressed bytes, size, gzip size), and the datafeed's
   `lastModifiedDate` must be within 48 hours. Building from the NVD API with `NVD_API_KEY` remains
   possible (`nvd_upstream_url` can name another datafeed) but is not the default.
4. **Generations and a manifest written last.** Each refresh writes `<feed>/g/<generation>/...` once and
   never edits it; `<feed>/manifest.json` is switched by one blob write after every file it names is in
   place. A reader never sees a half-written feed. The previous 3 generations are kept, so a scan that
   started on yesterday's manifest still finds its files.
5. **The 48-hour policy is a ceiling.** One missed daily run is tolerated, two are not. A caller may
   **tighten** it (`KIT_FEED_MIRROR_MAX_AGE_HOURS=24`); a larger value is clamped to 48 and the run says
   so. No repository variable can make a stale mirror current. The number lives in one place:
   `MAX_AGE_HOURS_CEILING` in `scripts/feed_mirror.py`.
6. **Fail closed, in the vocabulary each consumer already has.** No new routing outcome was needed:

   | Mirror refused (`MIRROR_STALE`, `MIRROR_UNREACHABLE`, `MIRROR_INTEGRITY_FAILED`) | What the scan reports |
   |---|---|
   | KEV | `kev_state UNAVAILABLE`, `kev_why` naming the cause → `PROCEED_WITH_ADVISORY` (`KEV_UNAVAILABLE`); never `CLEAR` |
   | NVD (Dependency-Check) | the database is not updated and Dependency-Check does not run → `nvd-dependency-check` in `controls_unavailable`, `nvd_database_state STALE`, `EVIDENCE_UNTRUSTED` |
   | Trivy (every job) | the cache is **emptied** and the update stays **off**, so every Trivy call refuses ("--skip-db-update cannot be specified on the first run") → that scanner's job reports its report missing (deps-scan, image-scan: unavailable; build: the image gate fails) |
   | Trivy checks bundle (iac-scan, the NVD path's Dockerfile scan) | the bundle is removed and `TRIVY_CONFIG_CHECK` points at a path that does not exist, so `trivy config` is **fatal**. Without that Trivy would not refuse: with the update off and no bundle it "Falls back to embedded checks" (measured, 0.71.2), an older rule set that reads as a current scan |
   | OSV (malicious-deps) | the scan runs **offline against an empty database**; osv-scanner exits 127 ("no offline version of the OSV database is available", measured 2.6.0) and the job's count step says `COLLECTION_FAILED`, which the gate never reads as clean. An ecosystem the repository needs that the mirror lacks is refused the same way, by name |
   | Scanner images (Semgrep, gosec, gitleaks) | the job cannot pull its image → `sast-semgrep` fails; gosec is `DEPENDENCY_ACQUISITION_UNAVAILABLE` / `COLLECTION_FAILED`; gitleaks cannot install and the secret scan fails -- none is a pass |

7. **Falling back to the public feed only when configured, and recorded.** `KIT_FEED_MIRROR_FALLBACK=
   upstream` makes a refused mirror read the public feed instead, as `MIRROR_FALLBACK_UPSTREAM` with
   `mirror_cause`, in the step summary and the evidence file. It is an exception to the private-only
   rule (R8) and should be recorded and time-boxed like one. Unset (the default) means refuse.
8. **One storage account for the mirrors, separate from the lease store (KDEC-030).** Recommended:
   separate accounts on the same private network. The lease store holds release records and lease
   state that must never be anonymously readable; this account is anonymous-readable on its network by
   design. One account would put an anonymous `web` endpoint next to the release ledger, and the
   account-level settings (network, static website, diagnostics) would serve two owners and two sets of
   grants. A second account costs only its transactions.

## Set it up at work (the platform team and the owner)

### 1. Deploy the Azure side (platform team, security platform subscription)

Prerequisites: a resource group; the **private-endpoint subnet** of the network the runners use (or a
network peered with it); either the hub's central private DNS zones (pass their ids) or this module
creates them and links them to the runners' network.

```hcl
# feed-mirrors.tfvars
resource_group_name        = "rg-security-platform-mirrors"
location                   = "<region of the runners' network>"
name_prefix                = "secplat"            # -> secplatfeedmirror, secplatscanmirror
private_endpoint_subnet_id = "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Network/virtualNetworks/<vnet>/subnets/<pe-subnet>"
dns_zone_ids = {                                  # leave out any the module should create
  web      = "<id of privatelink.web.core.windows.net>"
  blob     = "<id of privatelink.blob.core.windows.net>"
  registry = "<id of privatelink.azurecr.io>"
}
dns_link_vnet_ids          = []                   # only for zones the module creates
github_repository          = "<org>/<repository that runs the refresh>"
github_environment         = "feed-mirror"
oidc_issuer                = "https://token.actions.githubusercontent.com"   # a GHE.com tenant has its own
log_analytics_workspace_id = "<workspace id>"
```

```sh
terraform -chdir=infra/feed-mirrors init      # with the platform's state backend
terraform -chdir=infra/feed-mirrors plan  -var-file=feed-mirrors.tfvars -out=mirrors.plan
terraform -chdir=infra/feed-mirrors apply mirrors.plan
terraform -chdir=infra/feed-mirrors output
```

The apply itself must run where the `blob` private endpoint is reachable (the static website is a
data-plane setting, applied with Entra because shared key is off), i.e. on the platform's
private-network runner, as every other platform apply.

Keep the outputs: `storage_account_name`, `mirror_url`, `registry_login_server`,
`refresh_identity_client_id`, `refresh_identity_tenant_id`.

### 2. Make sure the runners can reach it (same requirement as the lease store)

GitHub-hosted **standard** runners cannot reach a private endpoint. Use, in the owner's order
(LZ_KIT_SEAM_CONTRACT.md, "The lease store's network"): **(a)** GitHub-hosted larger runners with Azure
private networking in the runners' network; **(b)** self-hosted or ARC runners in that network
(ephemeral); **(c)** only as a recorded, time-boxed exception, a public endpoint. The runner must
**resolve** the `privatelink.web.core.windows.net`, `privatelink.blob.core.windows.net` and (for images)
`privatelink.azurecr.io` zones to the private addresses, and needs outbound access to the upstreams
(the Dependency-Check datafeed on GitHub Pages, cisa.gov, Trivy's database registry, Docker Hub) for
the **refresh only**. Scan jobs need only the mirror.

### 3. The refresh identity and its environment (owner)

Terraform created the identity, its federated credential (`repo:<org>/<repo>:environment:feed-mirror`)
and its two grants. In the repository that runs the refresh:

1. Create the environment **`feed-mirror`**; deployment branches: the default branch only. Required
   reviewers: none (it runs unattended daily; the federated credential is usable only inside this
   environment, which the branch policy gates).
2. Environment **variables** (identifiers, not secrets): `AZURE_CLIENT_ID` =
   `refresh_identity_client_id`, `AZURE_TENANT_ID` = `refresh_identity_tenant_id`,
   `AZURE_SUBSCRIPTION_ID` = the security platform subscription's id.
3. Repository **variables**: `KIT_FEED_MIRROR_ACCOUNT` = `storage_account_name`, `KIT_FEED_MIRROR_URL` =
   `mirror_url`, `KIT_FEED_MIRROR_RUNNER` = the private runner's label, and `KIT_SCANNER_IMAGE_REGISTRY`
   = `registry_login_server` to mirror images.

No key, SAS or connection string is created or stored anywhere.

### 4. Install the refresh (owner)

Copy `templates/feed-mirror-refresh.yml` to `.github/workflows/feed-mirror-refresh.yml` in that
repository, replace `YOUR_ORG`, and pin the kit by its 40-hex commit SHA.

### 5. Verify the first refresh (owner) — this is the live proof that is still owed

1. **Actions → Feed mirror refresh → Run workflow.**
2. Expect six jobs: `Refresh nvd`, `Refresh kev`, `Refresh trivy`, `Refresh trivy-checks`, `Refresh osv`
   and `Mirror scanner images by
   digest`. Each feed job's summary ends with a *Feed mirror* table reading **`MIRROR_CURRENT`** (its
   own read-back) and the log line `MIRROR_PUBLISHED: feed <f> read back MIRROR_CURRENT`. The image job
   logs `mirrored semgrep/semgrep@sha256:32e4... -> <registry>/semgrep/semgrep@sha256:32e4...`.
3. From a job on the private runner (or a VM in that network), read a manifest:
   `curl -s <mirror_url>kev/manifest.json` → `"feed": "kev"`, a `refreshed_at` of a few minutes ago,
   `upstream_version` = CISA's `catalogVersion`. From outside the network the same URL must **fail**
   (public network access is off): that is the second half of the proof.
4. In the platform's Log Analytics: `StorageBlobLogs | where OperationName == "PutBlob"`, every caller the
   refresh identity.

### 6. Point the scans at it (owner, for each organisation that adopts)

Set **organisation** variables (one place for every repository; a repository variable overrides):

| Variable | Value | Effect |
|---|---|---|
| `KIT_FEED_MIRROR_URL` | `mirror_url` | every NVD, KEV and Trivy read goes to the mirror |
| `KIT_FEED_MIRROR_RUNNER` | the private runner's label | the jobs that read it run there: `nvd-cve-scan`, `deps-scan`, `iac-scan`, `image-scan`, `malicious-deps`, `sast-semgrep`, `sast-go`, `secret-scan`, `security-gate`, the build job, the deployed scan. The deploy job runs on its caller's `runner_label` input (KDEC-030), which must be the same private runner |
| `KIT_SCANNER_IMAGE_REGISTRY` | `registry_login_server` | `sast-semgrep` pulls the **same digest** from the mirror registry |
| `KIT_FEED_MIRROR_MAX_AGE_HOURS` | optional, at most 48 | tighter only |
| `KIT_FEED_MIRROR_FALLBACK` | leave **unset** | `upstream` only as a recorded exception |

The kit reads these through the `vars` context inside its reusable workflows, the same convention as
the landing-zone hand-off's `vars.KIT_*` (repository and organisation variables). **UNVERIFIED live:** that a called workflow sees the
caller's organisation variables (GitHub's reusable-workflow page does not say; the hand-off contract
relies on the same behaviour).

Then run any scan and read its step summary: a *Feed mirror: kev / nvd / trivy* table reading
`MIRROR_CURRENT`, and in the KEV row `kev_source mirror`.

### 7. What failure looks like

| You see | It means | Do |
|---|---|---|
| `MIRROR_STALE` in a scan's summary; KEV `UNAVAILABLE`; `nvd-dependency-check` unavailable; Trivy "--skip-db-update cannot be specified on the first run" | the refresh has not published for 48 h | open the refresh workflow's last runs; the refusal is named there |
| `MIRROR_UNREACHABLE` | this job cannot reach the private endpoint (wrong runner, DNS, endpoint down) | check `KIT_FEED_MIRROR_RUNNER` and the runner's DNS for `privatelink.web.core.windows.net` |
| `MIRROR_INTEGRITY_FAILED` | the bytes do not match the manifest, or the manifest is malformed or from the future | treat as an incident: only the refresh identity can write; check the audit log |
| refresh `MIRROR_UPSTREAM_STALE` | the upstream itself stopped (datafeed or Trivy DB older than 48 h) | nothing to fix here; the previous generation keeps serving until it ages out |
| refresh `MIRROR_UPSTREAM_INTEGRITY_FAILED` | an upstream file does not match its own checksum, or KEV does not parse | nothing was published; re-run later, report upstream if it persists |
| refresh `MIRROR_PUBLISH_UNVERIFIED` | uploaded, but the read-back did not return `MIRROR_CURRENT` (or an image did not resolve at its digest) | check the `web` private endpoint and its DNS from the runner |

**Turning it off:** unset `KIT_FEED_MIRROR_URL` (and `KIT_SCANNER_IMAGE_REGISTRY`). Every scan returns to
the public feeds exactly as before (`NOT_CONFIGURED`), with no other change.

## The three gaps of the first cut, closed (coordinator, 2026-10-27)

- **gosec and gitleaks are pinned by digest** -- `securego/gosec:2.24.6@sha256:2cf71ea7...9be5` and
  `zricethezav/gitleaks:v8.21.2@sha256:0e99e882...7f46` (the multi-platform index digests Docker Hub
  served on 2026-10-27). The tag stays in the reference so the pin readers keep resolving and comparing
  it; the digest is what is pulled. With `KIT_SCANNER_IMAGE_REGISTRY` set they come from
  `<registry>/securego/gosec@<digest>` and `<registry>/zricethezav/gitleaks@<digest>`, and the refresh
  copies all three images by default. `feed_mirror.py image-target` refuses a source that is not pinned
  by digest.
- **Trivy's checks bundle** is a feed, `trivy-checks`: the refresh packs Trivy's own download
  (`<cache>/policy`, its `metadata.json` digest as the upstream version) into `checks.tar.gz`; consumers
  unpack it over the cache with `TRIVY_SKIP_CHECK_UPDATE`. No upstream age limit: the bundle changes when
  Aqua publishes rules, not daily.
- **OSV** is a feed, `osv`: one `all.zip` per ecosystem from the OSV bucket (PyPI, npm, Go, NuGet, Maven,
  Packagist, SwiftURL, crates.io, RubyGems, Pub, Hex; npm is ~220 MB of the ~330 MB), each checked to be
  a zip of OSV records. The malicious-deps job asks for the ecosystems discovery found plus the small
  ones, places them where **osv-scanner 2.6 reads them -- `<dir>/osv-scalibr/<Ecosystem>/all.zip`,
  measured; its offline-mode page says `osv-scanner/`, which 2.6 does not read** -- and adds
  `--offline-vulnerabilities`. No upstream age limit: an ecosystem with no new advisories is not
  regenerated (Pub's `all.zip` was 12 days old on 2026-10-27); the mirror's own 48 h policy still holds.
  **Still public in offline mode:** `--offline-vulnerabilities` takes the advisories offline but not
  osv-scanner's transitive resolution of a manifest without a lockfile (a bare `pom.xml`), which still
  asks its registries; a private runner without that egress records it as an extraction error
  (`COLLECTION_FAILED`), not as clean.

## Unproven live (owed)

- The whole Azure path: the static website over a private `web` endpoint, Entra uploads over the `blob`
  endpoint, the container-scoped grant being sufficient for upload, list and delete, the registry's
  anonymous pull over its private endpoint, the token exchange for AcrPush, and
  `docker buildx imagetools create` keeping the source digest.
- That the azurerm provider can set the static website with shared key off (`storage_use_azuread`).
- That a called workflow reads the caller's organisation variables.
- That Dependency-Check 12.2.2 builds its database from the mirror URL as it does from the project's
  datafeed (the files are byte-identical; the path differs).
- That Trivy 0.71.2 accepts the unpacked database with `--skip-db-update` exactly as it does its own
  download (it is its own download, tarred and untarred). Measured locally instead: the checks bundle
  unpacked into a cache is used under `--skip-check-update`, a missing one falls back to embedded checks,
  and a missing custom-check path is fatal; osv-scanner 2.6.0 scans offline from a placed `all.zip`
  and exits 127 without one.
- Registered as `feed-mirror-live` (tests/reconcile_validation.py), expiring 2026-12-31.
