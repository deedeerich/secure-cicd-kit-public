# secure-cicd-kit

**Employer-neutral, reusable CI/CD + security library for GitHub Actions.** Clean-room rebuild of the reusable-workflow
pattern: enforced security gates, supply-chain integrity (SBOM + container/dep scanning), OIDC-only cloud auth, and
deploy-by-digest — all as `workflow_call` reusables and composite actions that any repository references instead of
copy-pasting inline pipeline logic.

```
Provenance & IP: this is a CLEAN-ROOM reconstruction of the reusable-CI PATTERN (studied, then rebuilt fresh) —
employer-neutral reserved IP. It contains NO organization names, registry hosts, resource groups, tenant/subscription/
client IDs, or product codenames. Every environment-specific value is a workflow INPUT or SECRET supplied by the caller.
Portable to any org (drop it into an <org>/secure-cicd-kit repo and reference it). Sibling to landing-zone-platform.
```

## Design principles (carried forward, neutralized)
- **Security gates before deploy** — SAST + secret + dependency + IaC scans run as required checks; deploys can't proceed without them.
- **Supply-chain integrity** — SBOM (Syft, SPDX JSON), container scan (Trivy), image-digest pinning, provenance metadata.
- **OIDC-only** — no long-lived cloud credentials; federated identity only.
- **No deploy-on-push** — deploys are dispatch/gated, never automatic on push.
- **Dual-partition parity** — the same pipeline shape works for commercial and sovereign/government clouds via inputs (no hardcoded endpoints).
- **Caller supplies identity** — org, registry, resource group, tenant/subscription/client all arrive as inputs/secrets.

## Setup first

**[`docs/adoption/SETUP.md`](docs/adoption/SETUP.md)** (GUI + CLI for every step) · **[`docs/operations/GOTCHAS.md`](docs/operations/GOTCHAS.md)** — secret inventory, Azure OIDC federated-credential setup
(including the subject-claim formats people most often get wrong), least-privilege RBAC, the NVD key,
and a zero-cost verification job that creates no resources.

**Not using Azure? You need no secrets at all** — `reusable-security.yml` runs unauthenticated.

## Start here → **[`docs/START-HERE.md`](docs/START-HERE.md)**

Three doors. Pick one; you don't need the rest.

| | |
|---|---|
| 🚪 **I want to use this** | five steps to a first run, in order |
| 🚪 **Something failed** | symptom → document. **Your first run will find things; that is the system working** |
| 🚪 **I need to understand or change it** | what's proven, what's provisional, what was deliberately left undone |

### Three rules everything else follows from

1. **Silence is never a correct outcome** — findings, an explicit "nothing to scan and here is the path I searched", or a loud failure. Never quiet success.
2. **Never change scanner configuration to make a real run green** — classify first.
3. **Detection immediately, enforcement deliberately** — start in `advisory_mode`.

### No GitHub Advanced Security required

Every engine is open source. GHAS only ever supplied the Security tab, PR annotations and triage —
findings always persist as build artifacts regardless, and unavailable publication is reported as a
warning ("NOT published to the Security tab … ANALYSIS=COMPLETE") rather than a failed scan.

## How to consume
From a calling repo, reference a reusable workflow by `workflow_call`. The defaults are the
baseline — `language: auto` (scan every ecosystem discovery finds) and `iac_mode: auto` (scan any
Terraform, Bicep, ARM, Kubernetes, Helm or Dockerfile found) — so the smallest correct caller sets
almost nothing:
```yaml
permissions:            # the caller must grant everything the kit's jobs request, or GitHub
  contents: read        # refuses the whole run before any job starts (startup_failure)
  security-events: write
  actions: read         # the CodeQL job
jobs:
  security:
    uses: YOUR_ORG/secure-cicd-kit/.github/workflows/reusable-security.yml@<40-hex commit sha>
    with:
      environment: prod     # the baseline-ledger environment this run is for (empty = none named)
    secrets:
      SEMGREP_APP_TOKEN: ${{ secrets.SEMGREP_APP_TOKEN }}   # optional
```
Copy a starter from `templates/` (`templates/security.yml` is this shape) and wire the jobs you need.
**Pin the kit by commit SHA**, never `@main` or a moving tag: the verdict is only as trustworthy as
the code that produced it. `enable_iac` is deprecated and ignored — use `iac_mode`. Read the verdict
from the `routing_result` output, never from the job's colour.

## Status
| Surface | State |
|---|---|
| `reusable-security.yml` (scan → report → gate → `routing_result`) | **Proven end to end on GitHub** from a consumer-style caller: 20/20 seeded signals detected by the right scanner, negative control clean, caller blocked — on `main` itself (`ef4b15d`, run 38934329462; negative 38934348351 failed as designed). CodeQL proven on a separate consumer repository (runs 38817782084, 38820564939) |
| `reusable-build-docker.yml` | **Proven live**: build once, Trivy gate before push, SBOM, push to a cloud registry over OIDC, digest read back (`REGISTRY_IDENTITY_PROVEN`) (runs 38857011286, 38857017667, 38857024014) |
| `reusable-deploy-containerapp.yml`, `reusable-deploy-appservice.yml` | **Proven live** on a sandbox subscription: verdict refusal before login, healthy deploy of a kit-built digest, verified rollback, a second actor's change refused, App Service slot swap |
| `reusable-ticket-reconcile.yml` | reconciler proven live on a personal Jira; the armed workflow itself has no hosted run; Azure DevOps against stubs only |
| `reusable-nvd-cve.yml` | Trivy and Dependency-Check detection proven locally with the real tools; a keyed hosted run against the live NVD feed is owed. `fail_on_cvss` defaults to 11 (never blocks) |
| attestation signing and verification | built; held — needs a public repository or Enterprise Cloud |
| SHA-pinning of the kit's own third-party actions | **not done** — the dogfood policy check runs with `require_sha_pinning: false` under a weakening that expires 2026-10-31 ([docs/assurance/PINNING.md](docs/assurance/PINNING.md)) |

Every row, its run or proof and its scope: [docs/assurance/RELEASE_1_EVIDENCE_MANIFEST.md](docs/assurance/RELEASE_1_EVIDENCE_MANIFEST.md).
What the kit still lacks: [docs/assurance/COMPLETION_LEDGER.md](docs/assurance/COMPLETION_LEDGER.md).
Adoption sequence in [docs/adoption/USAGE.md](docs/adoption/USAGE.md).

**Provider independence:** every control here is a deterministic asset — policy-as-code, a contract
checker, a JSON Schema, a shell resolver. All of it runs on a GitHub runner with Python and `curl`,
with no model in the loop. No essential security capability of this kit requires a particular AI
provider to execute or validate it.

## Layout
```
.github/workflows/     reusable (workflow_call): reusable-security · reusable-nvd-cve ·
                       reusable-build-docker · reusable-deploy-containerapp ·
                       reusable-deploy-appservice · reusable-propose-ledger ·
                       reusable-ticket-reconcile · workflow-policy-check · verify-azure-oidc
                       kit-internal: self-test · consumer-path-test/-negative ·
                       live-deploy-acceptance · validate-scanners · nvd-cve
.github/actions/       composites: setup-python/node/terraform, azure-login-oidc, docker-build-push,
                       render-version-metadata, determine-changes, verify-attestation, and the
                       flagship's own discover, resolve, scan-report, propose-ledger (called via $/)
templates/             consumer starters: security.yml · policy.yml · build-deploy.yml · nvd-cve.yml
                       · policy-registration.example.json
profiles/              repo-class intent records + profile.schema.json (inert: nothing reads them yet)
schemas/               JSON schemas (dispositions, policy registration, expected signals, run record)
assurance-taxonomy.yaml  every state word the workflows emit
docs/                  START-HERE · adoption/ · explainer/ · architecture/ · assurance/ · operations/
scripts/               the kit's canonical scripts; pin-actions.sh (tag -> commit SHA resolver)
```

## Governance gate
`workflow-policy-check.yml` lints a consuming repo's own pipelines against the CI supply-chain threat
model — mutable action refs, ambient token authority, fork-controlled code holding secrets,
long-lived cloud credentials, deploy-on-push, tag-based deploys, and shell injection via
attacker-controlled expressions. Nine rules, rationale, and the adoption path are in
[docs/architecture/POLICY.md](docs/architecture/POLICY.md). This is the piece the source devkit documented but never promoted
out of inline pipeline logic.

## About the cited run ids
Documents and commit messages in this kit cite workflow run ids (for example "run 38817782084") as
evidence for what was observed. Those runs belong to the private repository the kit is developed
in, so they are not viewable from a public copy. They are kept as citations, not links: each one
names a specific observation that can be produced on request.

## What "better" adds vs the original
The source devkit shipped CodeQL + Semgrep + build + deploy as reusables, but left **secret-scan, code-quality, IaC-scan,
and dependency-scan as repo-local duplicates** (copied across three repos) and the **policy-check gate inline**. This kit
**promotes all of those into shared reusables** and folds the scanners into one callable `reusable-security.yml` umbrella,
so a repo gets "all the security scans" from a single `uses:` line — the thing that was missing.

## Required secrets (by phase)
| Secret | Phase | Purpose |
|---|---|---|
| `SEMGREP_APP_TOKEN` | 1 (optional) | Semgrep managed rules/dashboard |
| `NVD_API_KEY` | 1b (recommended) | `reusable-nvd-cve.yml`; without it the NVD update is rate-limited |
| `AZURE_TENANT_ID` / `AZURE_SUBSCRIPTION_ID` / `AZURE_CLIENT_ID` | 2–3 | OIDC federated login, passed explicitly to the build and deploy reusables (identifiers, not credentials; the partition is the `cloud` input, `commercial` or `gov`) |
| `JIRA_EMAIL` + `JIRA_TOKEN`, or `AZDO_PAT` | ticketing | `reusable-ticket-reconcile.yml`, one backend per run |
