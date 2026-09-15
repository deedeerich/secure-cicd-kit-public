# Gotchas

Things that cost time, with the reason attached. Every one of these was hit for real in this repo.

## OIDC / Azure

**`AADSTS70025` — "no configured federated identity credentials"**
The app registration has **zero** federated credentials. Not a wrong one — none. Creating the app
registration does **not** create a credential; that is a separate step.

**`AADSTS700213` — "no matching federated identity record found"**
Subject mismatch. **Check `Entity type` FIRST** — a `Branch` credential can never match a job that
declares `environment:`, no matter how correct every other field is.

**The portal's Organization ID / Repository ID fields are real and required.** The generated subject
`repo:<ORG>@<ORG_ID>/<REPO>@<REPO_ID>:environment:<ENVIRONMENT>` is correct, not a rendering artifact. Both the
ID form and the name-only form exist depending on how the credential was created — **match what the
workflow presents**, do not strip the IDs to make it look tidier. **A job declaring `environment:` sends the environment subject even though the run
is on a branch.** Configuring the branch form for an environment-scoped job is the most common cause,
and the error text does not hint at it.

**`az ad app create` does not create the service principal.** The portal does it for you; the CLI does
not. You must also run `az ad sp create --id "$APP_ID"` or role assignment will fail.

**The app won't appear in the IAM member picker** if you search by *application* object ID. Search by
**display name**.

**There is no "Web App Contributor" role.** It is **Website Contributor**.

**Auth verification needs no RBAC at all.** Login succeeds with zero role assignments. If you are
debugging login by adding roles, you are debugging the wrong thing.

**Deploy succeeds, app never becomes healthy** → the app's managed identity lacks **`AcrPull`** on the
registry. It is an image-pull failure presenting as a deploy success.

**Secrets vs Variables.** GitHub's settings page is titled *"Secrets and variables"*, which invites
the mistake. **Variables are plaintext and are not masked in logs.** A secret set as a variable
resolves to empty in `secrets.*` and the workflow degrades silently.

**Environment-scoped secrets require the job to declare `environment:`.** Otherwise `secrets.*` is
empty and nothing says why.

**Never trust the cloud CLI's ambient context.** `az account show` reports whatever profile is cached
locally — which may belong to a former client, a different tenant, or an engagement that ended years
ago. Cached *metadata* survives independently of whether any token is still valid, so the CLI can
name a subscription it cannot actually reach. Before any mutating operation, assert observed tenant /
subscription / identity against explicitly declared expected values. `az account clear` removes stale
profiles; `az account show` does **not** authenticate and proves nothing about entitlement.

**Editing a federated credential REPLACES it.** Repointing an existing credential from one
environment to another silently breaks the first one. You need **one credential per environment** —
`az ad app federated-credential list` should show as many entries as you have environments.

**Environment secrets do not inherit, and do not copy between environments.** Creating `prod` after
`dev` gives you an environment with **zero** secrets. `secrets.AZURE_CLIENT_ID` resolves empty and the
Azure login failure looks like a credential problem.

**A job that fails with ZERO steps was refused by a protection rule** — a deployment branch policy or
a pending reviewer. Nothing in the YAML is wrong. Read the run's annotation, not the logs; there are
no logs, because nothing ran.

**No deployment branch policy is the silent default.** A brand-new environment accepts deploys from
*every* branch. `gh api repos/O/R/environments/<env>/deployment-branch-policies` returning **404**
means unrestricted — not "misconfigured". Assume nothing; check.

**`protected_branches` and `custom_branch_policies` cannot both be true.** The API rejects it. The
GUI's three-state dropdown maps to one or the other, never both.

## Scanners

**A missing `NVD_API_KEY` does not fail the NVD workflow** — it degrades to unauthenticated and
rate-limited. *"The scan ran"* and *"the scan had current data"* are different claims.

**gitleaks release downloads return HTTP 503 intermittently.** The URL is fine; the CDN is not. Pull
the binary from the vendor container image instead.

**Never allowlist `.md` / `.txt` / `.rst` wholesale in a secret scanner.** Shipped here once — three
of four rules silently stopped detecting, because their fixture files ended in `.txt`. Secrets land
in runbooks, notes and READMEs constantly. Narrow the allowlist to specific paths.

**`bandit` exits non-zero when it finds things.** That is success, not failure. Wrap accordingly or
the job reports broken when it is working.

**Suppressing scanner output with `>/dev/null` makes failures undiagnosable.** Cost two full debug
cycles here. A harness that cannot be diagnosed from its own logs manufactures false assurance
exactly like a silent scanner.

## Workflow authoring

**`yaml.safe_load` parses `on:` as the boolean `True`**, not the string `"on"`. Any script inspecting
workflows must handle `doc.get("on", doc.get(True))`.

**Inline Python heredocs inside `run: |` blocks break** on YAML block-scalar processing. Put the
script in a file and call it — it is also then runnable locally.

**A job that runs but is absent from the gate's `needs:` cannot fail the build.** It reports; it does
not gate. Shipped here with 4 of 6 jobs wired in while docs claimed all six.

**`skipped` is not `passed`.** A gate treating them identically hides shrinking coverage. Print
skipped as skipped.

**A scanner probe passing does not prove the workflow's job works.** Different thing entirely — the
probe tests the tool, the workflow tests input threading, `if:` conditions, SARIF categories and gate
wiring.

## Cost and execution bounds

- **An unbounded job runs for six hours.** GitHub's default `timeout-minutes` is **360**. Two stalled
  C/C++ jobs billed an estimated **~386 minutes** on 2026-08-18 — more than every useful validation
  run of the preceding two days combined. Every non-mutating job in this kit is now bounded. **If you
  add a job, bound it.**
- **Sizing a bound from "similar jobs" is a guess when the job has never run.** `reusable-nvd-cve`
  would have inherited 20 minutes while its own documentation says a cold-cache update takes
  **20–40 minutes** without an `NVD_API_KEY`. It carries 60, explicitly sized from documentation and
  flagged for re-sizing after its first real execution.
- **Caller jobs cannot carry `timeout-minutes`.** A job that `uses:` a reusable workflow rejects it.
  They are bounded transitively by the callee — which is the better place, because the bound then
  reaches consumers who configured nothing.
- **Do not bound mutating jobs the same way.** Killing a hung *scan* is safe. Killing a *build or
  deploy* mid-change strands a half-applied change with no completed manifest — a
  `ROLLBACK_REQUIRES_HUMAN_DECISION`. Design that bound against `ROLLBACK_CONTRACT.md` first.
- **A long run is not necessarily a slow run.** Check `started_at` on the job that is still
  `in_progress`; everything else finishing while one job sits there is the signature of a hang.

## Scanner path rooting — findings that point at the wrong file

- **A scanner reports paths relative to whatever scope it was handed.** gosec runs per Go module with
  the module as its working directory, so `go/vuln.go` and `services/worker/vuln.go` both arrived as
  `vuln.go`. **Two files, one identity.** Fixed by re-rooting at the point of capture.
- **Re-root while the component root is still known.** It cannot be recovered afterwards — merged
  filenames use `tr '/' '_'` and that mapping is lossy.
- **Trivy still does this** (`infra/main.tf`) while Checkov and Semgrep report repo-relative
  (`tests/consumer-fixture/full/infra/main.tf`). One file, two identities, inside one repo.
- **Why it matters beyond a failing assertion:** annotations point at paths that do not exist at repo
  root, finding history cannot separate components across runs, one scanner silently covers for
  another in a tool-pinned assertion, and correlation later merges findings from different components
  as the same finding.
- **The invariant:** *normalize only after source identity is bound. Never merge first and
  reconstruct provenance later.*
