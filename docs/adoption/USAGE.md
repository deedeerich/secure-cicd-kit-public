# Using the kit

## What's in it

**Reusable workflows** (`workflow_call` — reference them from a calling repo):

| Workflow | Purpose | Cloud deps |
|---|---|---|
| `reusable-security.yml` | Secret · code-quality · SAST · dependency · IaC scans + enforcing gate | none |
| `workflow-policy-check.yml` | Governance gate over the calling repo's own workflows | none |
| `reusable-build-docker.yml` | Buildx build → Trivy gate **before** push → Syft SPDX SBOM → digest-pinned push | OIDC |
| `reusable-deploy-containerapp.yml` | Container Apps deploy by digest, gated, health-checked, auto-rollback | OIDC |
| `reusable-deploy-appservice.yml` | App Service deploy by digest, slot-staged, swap only when healthy | OIDC |

**Composite actions** (`.github/actions/*` — for repos that build inside their own workflows):
`setup-python`, `setup-node`, `setup-terraform`, `azure-login-oidc`, `docker-build-push`,
`render-version-metadata`, `determine-changes`.

The reusable workflows **inline** their logic rather than calling `uses: ./…`. Relative action
references resolve against the *caller's* checkout, not the kit's, so they break silently
cross-repo. The composite actions ship separately for direct use; the duplication is deliberate.

**Templates** (`templates/`): `security.yml`, `policy.yml`, `build-deploy.yml` — copy into a calling
repo's `.github/workflows/` and fill in the org and inputs.

**Profiles** (`profiles/`): declarative statements of what a class of repo gets. They are intent
records validated by `profiles/profile.schema.json` — the reusable workflows are the implementation.
Nothing reads a profile at runtime yet; wiring that up is a deliberate follow-on.

## Adoption sequence

1. Extract `secure-cicd-kit/` to its own repository under your org.
2. Run `scripts/pin-actions.sh --apply` (see [PINNING.md](../assurance/PINNING.md)) and commit the SHAs.
3. Flip `self-test.yml` to `require_sha_pinning: true`, `soft_fail: false`. Let it go green.
4. Tag `v1`.
5. In a **pilot repo**: copy `templates/security.yml`, point it at `@v1`, and let it run. Expect a
   first-run shakeout — see the caveat below.
6. Add `templates/policy.yml` with `soft_fail: true`, fix what it reports, then flip it to blocking.
7. Only then wire build + deploy, and add the checks to branch protection.

## Cloud identity

Nothing environment-specific is baked in. Every deploy input arrives from the caller:

- **Secrets** — `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `AZURE_CLIENT_ID` (OIDC federation only;
  no client secret exists anywhere in this kit).
- **Vars** — registry login server, image repository, resource group, app name.
- **Partition** — the `cloud` input (`commercial` | `gov`) selects the Azure environment. The same
  pipeline shape serves both; there is no forked sovereign pipeline to drift out of sync.

Grant `permissions: { id-token: write, contents: read }` on the *calling job* — a reusable workflow
cannot grant itself more than the caller has.

## Deploy contract

Build emits `image_digest` and `sbom_sha256`. Deploy takes `image_digest` and refuses anything that
isn't a full `sha256:` value. That is the whole reproducibility story: the artifact that was scanned
is provably the artifact that ships, and `render-version-metadata` stamps the digest, SBOM hash, git
SHA, and run ID onto the running app as `DEPLOY_PROVENANCE`.

Deploys are gated by a GitHub Environment and reached by `workflow_dispatch`, never by a bare push.
Health checks run **before** traffic moves — Container Apps rolls back to the previous revision,
App Service simply never swaps the slot.

## Branching model — what runs where

```
scanners      →  all branches  ·  no environment  ·  no Azure credential at all
build only    →  all branches  ·  github_environment: ""  ·  push: false
build + push  →  main only     ·  github_environment: <env>  ·  push: true
deploy        →  main only     ·  environment + approval
```

**Restrict branches with the Environment's deployment branch policy, never with the federated
credential subject.** The branch policy refuses the job before it starts; a `Branch`-form credential
lets the job run, do its work, and then fail on `AADSTS700213` — turning a policy decision into what
looks like an auth bug. Setup and verification for both: `docs/adoption/SETUP.md` §1.2 and §4.

`reusable-security.yml` needs **no Azure identity**, so the entire scanner surface is unaffected by
any of this and runs anywhere.

## Adopting this on a repository that has never been scanned

```yaml
with:
  advisory_mode: true      # everything runs, everything reports, NOTHING blocks
```

`advisory_mode` covers **every** enforcement point — SAST, lint, dependency scanning and secret
scanning. (`soft_fail_sast` governs SAST only, which is why "run it non-blocking to learn the
baseline" was not previously achievable.)

Nothing is disabled, scoped away or hidden by it. Every scanner still runs, every finding is still
produced, published and persisted. **Only the block is withheld.** Detection is never what gets
turned off.

Why it exists: dropping a hard gate onto an unknown backlog freezes development and gets the control
bypassed wholesale, which costs far more coverage than the gate was going to buy. Learn the inherited
baseline, classify it (see [`FINDING_CLASSIFICATION.md`](../operations/FINDING_CLASSIFICATION.md)), then enforce.

> **Advisory mode is a baseline tool, not a resting state.** It announces itself on every enforcement
> point and reports `GATE=ADVISORY`, because a silent permanent advisory mode is indistinguishable
> from having no gate at all.

`enforce_lint` (default **false**) is separate: `ruff` findings are advisory because **lint style is
not a security control**, and hard-failing on it blocked adoption of a security workflow on day one.
Turn it on when your team chooses to.

## What each scanner needs in order to see anything

A scanner that runs against a project it cannot parse exits **zero**. It does not warn you that it
analysed nothing. These are the preconditions — every one of them was found the hard way, by a
seeded fixture that a green job failed to detect.

| Capability | Requires | If missing |
|---|---|---|
| **npm dependency + malicious-package scan** | **`package-lock.json`, `npm-shrinkwrap.json` or `yarn.lock`.** Trivy **cannot** resolve npm dependencies from `package.json` alone | Node deps are **not scanned at all**. The workflow emits a `warning`, because this is where supply-chain attacks currently land |
| Go SAST (gosec) | `go.mod` — discovered anywhere under `paths`, not just the repo root | job reports "no Go module", skips, and says so |
| .NET SCA | `.csproj` / `.sln` so `dotnet restore` can resolve | dependency audit finds nothing |
| .NET / Java SAST | `.cs` / `.java` sources under `paths` | job reports "no sources", skips, and says so |
| Python SAST | `.py` sources under `paths` | skipped with a notice |
| IaC | `enable_iac: true` **and** Terraform/Dockerfile under `paths` | job skips — `enable_iac` defaults **false** |
| Everything Semgrep | Your code must not sit under a path Semgrep ignores by default (`tests/`, `fixtures/`, …) | **the kit overrides this** with its own `.semgrepignore`, because the default caused silent empty results |

**Absence of a language is always reported, never inferred from a green job.** A skipped scanner
prints a `notice` naming the path it searched. If you see neither findings nor a skip notice, treat
that as a defect in the kit and open an issue — silence is the one outcome that is never correct.

### What `language:` actually selects

`language` chooses which analyzer families are **considered**. It does not force any of them to run.
**Applicability is decided by discovery, against the content under `paths`.**

| `language:` | Meaning |
|---|---|
| `python`, `node`, `dotnet`, `java`, `go`, `cpp` | Consider that family's analyzers, plus the ones that always run |
| **`multi`** | **Consider every family.** Each still runs only if discovery finds something for it to analyze |

So `language: multi` on a repository containing Python and Terraform runs the Python and IaC paths
and **skips** Go, Java, .NET and C/C++. That is the correct outcome, not a coverage gap. Running a Go
analyzer against a repository with no Go produces no assurance — only cost, runtime, and a green job
that means nothing.

**The union is the failure case, not the default.** When discovery *cannot establish* what is
present — an unreadable tree, a permission denial, a survey that did not complete — the safe move is
to scan broadly or emit `COLLECTION_FAILED`. **What must never happen is a quiet skip**, because a
skip and an unexamined ecosystem are indistinguishable from the outside.

> **Why this is written down.** The consumer contract previously asserted that `multi` made *every*
> language analyzer run. That assertion passed for months — because four analyzers were ignoring their
> `paths` scope entirely and walking the whole checkout, so they always found something. Fixing the
> scoping made the test fail, and the failure was the contract, not the code. A semantic that only
> exists in an assertion is a semantic nobody can consume correctly. (Decided 2026-09-02.)

### Manifests are discovered, not assumed at the root

`paths` is the scope, and project roots are located *within* it. A monorepo consumer scanning
`services/checkout` gets `services/checkout` scanned — not the repository root, and not every commit
in history. Two real defects came from assuming otherwise: `setup-node` hard-failed when
`package-lock.json` was not at the root, and `gosec` scanned `./...` from the root regardless of
`paths`.

## Never trust ambient cloud context

**A cloud CLI's default context is not an authorization decision.** Developer machines accumulate
sessions — old tenants, former clients, multiple subscriptions, stale profiles that outlive the
engagement. "Whichever subscription happens to be default" is not a safe target for anything that
mutates state.

Every job that authenticates to a cloud must **declare the intended authority domain, then verify it
against what it actually got, before doing anything consequential**:

```
expected tenant        == observed tenant
expected subscription  == observed subscription
expected identity      == observed identity (the workload principal, not a human)
expected environment   == requested environment
```

A mismatch is a **hard fail before mutation**, not a warning. `verify-azure-oidc.yml` implements
this assertion and is the reference for the deploy adapters.

> This is not hypothetical. A three-year-old profile from a *former client* was found as the default
> Azure CLI context on a workstation actively used for unrelated personal cloud work. No live token
> remained, so nothing was reachable — but automation that trusted the ambient context would have
> aimed at the wrong estate without a single error.

## Proven state — read `docs/assurance/CAPABILITY_MATRIX.md` for the evidence

Do not read this section as marketing. Each row is a distinct claim with distinct evidence.

| Surface | State |
|---|---|
| **Scanner tools** (11 detectors) | **observed** — executed *and* detected seeded conditions |
| **Assurance mechanisms** (negative control, gate enumeration) | **observed** |
| **Azure OIDC auth** | **observed** against a real tenant, zero resources created |
| **Environment branch policy** | **observed** — non-`main` refused in ~2s, 0 steps, no token minted |
| **`reusable-security.yml` end-to-end as a consumer calls it** | **NOT PROVEN** — the 11 probes test the *tools*, not the reusable contract: input threading, language selectors, SARIF categories, skip semantics, gate wiring and failure propagation are all unproven |
| **Composite actions** | **NOT PROVEN** — no probes yet |
| **Build / push / deploy workflows** | **NEVER EXECUTED.** Blocked on [`ROLLBACK_CONTRACT.md`](../architecture/ROLLBACK_CONTRACT.md), which is a *design* gate — having tenant access does not unblock it |

**Validate on one repo before rolling out.** Expect first-run shakeout on version-specific details in
the unproven rows: Checkov's SARIF output path, the Semgrep flag combination, `az containerapp
revision` query shapes, and exact action tags.
