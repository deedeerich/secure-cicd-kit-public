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
findings always persist as build artifacts regardless, and unavailable publication reports
`PUBLICATION=DEGRADED` rather than a failed scan.

## How to consume
From a calling repo, reference a reusable workflow by `workflow_call`:
```yaml
jobs:
  security:
    uses: YOUR_ORG/secure-cicd-kit/.github/workflows/reusable-security.yml@v1
    with:
      language: python          # python | node | multi
      enable_iac: true          # scan Terraform/IaC too
    secrets:
      SEMGREP_APP_TOKEN: ${{ secrets.SEMGREP_APP_TOKEN }}   # optional
```
Copy a starter from `templates/` and wire the jobs you need. Pin to a tag (`@v1`), not `@main`, in real repos.

## Build roadmap (tranches)
| Phase | Contents | Status |
|---|---|---|
| **1b — NVD CVE** | `reusable-nvd-cve.yml` (Trivy + OWASP Dependency-Check against the public NIST NVD) + consumer template | ✅ written, ⚠ unvalidated |
| **1 — Security suite** | `reusable-security.yml` umbrella (secret · code-quality · SAST · deps · IaC) + consumer template | ✅ written |
| **2 — Build & supply chain** | composite actions (`setup-python/node/terraform`, `azure-login-oidc`, `docker-build-push`, `render-version-metadata`, `determine-changes`) + `reusable-build-docker.yml` (Trivy gate before push + Syft SBOM) | ✅ written |
| **3 — Deploy** | `reusable-deploy-containerapp.yml` (commercial, auto-rollback) + `reusable-deploy-appservice.yml` (sovereign, slot-then-swap), deploy-by-digest + health check | ✅ written |
| **4 — Governance & self-test** | `workflow-policy-check.yml` gate (promoted from inline) · `self-test.yml` (yamllint · actionlint · contract · profile schema · policy dogfood) · `profiles/` + JSON schema · `docs/` · `scripts/pin-actions.sh` | ✅ written |
| **v1 tag** | SHA-pin third-party actions, flip `self-test.yml` to enforcing, validate on a pilot repo | ⏳ open — see [docs/assurance/PINNING.md](docs/assurance/PINNING.md) |

**Status honesty:** "written" means authored to correct Actions patterns and statically verified —
YAML parse, schema validation, contract check, and the policy gate run against the kit itself, all
green. It does **not** mean executed in CI. Expect first-run shakeout (Checkov SARIF path, Semgrep
flag combo, `az containerapp revision` query shapes, exact action tags). Every claim is tracked as
verified / unvalidated / blocked in [docs/assurance/VALIDATION_DEBT.md](docs/assurance/VALIDATION_DEBT.md) — nothing is
called green until it has run green. Adoption sequence in [docs/adoption/USAGE.md](docs/adoption/USAGE.md).

**Provider independence:** every control here is a deterministic asset — policy-as-code, a contract
checker, a JSON Schema, a shell resolver. All of it runs on a GitHub runner with Python and `curl`,
with no model in the loop. No essential security capability of this kit requires a particular AI
provider to execute or validate it.

## Layout
```
.github/workflows/     reusable-security · workflow-policy-check · reusable-build-docker
                       reusable-deploy-containerapp · reusable-deploy-appservice · self-test
.github/actions/       7 composite actions (setup-*, azure-login-oidc, docker-build-push,
                       render-version-metadata, determine-changes)
templates/             consumer starters: security.yml · policy.yml · build-deploy.yml
profiles/              repo-class intent records + profile.schema.json
docs/                  USAGE.md · POLICY.md · PINNING.md
scripts/               pin-actions.sh (tag -> commit SHA resolver)
```

## Governance gate
`workflow-policy-check.yml` lints a consuming repo's own pipelines against the CI supply-chain threat
model — mutable action refs, ambient token authority, fork-controlled code holding secrets,
long-lived cloud credentials, deploy-on-push, tag-based deploys, and shell injection via
attacker-controlled expressions. Nine rules, rationale, and the adoption path are in
[docs/architecture/POLICY.md](docs/architecture/POLICY.md). This is the piece the source devkit documented but never promoted
out of inline pipeline logic.

## What "better" adds vs the original
The source devkit shipped CodeQL + Semgrep + build + deploy as reusables, but left **secret-scan, code-quality, IaC-scan,
and dependency-scan as repo-local duplicates** (copied across three repos) and the **policy-check gate inline**. This kit
**promotes all of those into shared reusables** and folds the scanners into one callable `reusable-security.yml` umbrella,
so a repo gets "all the security scans" from a single `uses:` line — the thing that was missing.

## Required secrets (by phase)
| Secret | Phase | Purpose |
|---|---|---|
| `SEMGREP_APP_TOKEN` | 1 (optional) | Semgrep managed rules/dashboard |
| `AZURE_TENANT_ID` / `AZURE_SUBSCRIPTION_ID` / `AZURE_CLIENT_ID` | 2–3 | OIDC federated login (per partition; add `_GOV` variants for sovereign) |
