# 11 · Integrating a product with the kit — what a builder must do, and must not assume

This part is for a builder who is wiring OTHER products (a landing-zone vending, an application, a
tool) to the kit. It is the practical summary of parts 03, 05 and 07 plus the hand-off contract
(`docs/architecture/LZ_KIT_HANDOFF_CONTRACT.md`).

## 1. Who does what (owner decision KDEC-009)

| | the landing-zone vending | the secure CI/CD kit |
|---|---|---|
| builds and changes | the platform; each application's **empty** target; the per-application **deploy identity** | every **release** of the application |
| how | infrastructure as code: plan → human approval → apply | the kit's run: scan → verdict → build once → deploy by digest → verify → reverse |
| never | deploys application code or images | creates or deletes platform infrastructure |

A builder that makes the vending deploy an application, or makes the kit create infrastructure, has
broken this split.

**Internal tools are workloads too (KDEC-015).** The split covers every tool, not only applications:
the vending gives each internal tool its own empty target and its own per-tool deploy identity, and
the kit releases it exactly as it releases an application. One identity never deploys several tools.

## 2. What the vending must hand over, per application and environment

Written into the application repository's **GitHub environment** (`dev`, `test`, `uat`, `prod`), as
**variables** (nothing is a secret; the identity is federated OIDC and holds no key):

`AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `AZURE_CLIENT_ID` (the deploy identity), `KIT_RESOURCE_GROUP`,
`KIT_APP_NAME`, `KIT_ACR_LOGIN_SERVER`, `KIT_IMAGE_REPOSITORY`, `KIT_ENVIRONMENT_TIER`, `KIT_CLOUD`.

Plus: environment protection (required reviewers, protected-branch-only) on uat and prod, and the
federated credential subject `repo:<owner>/<repo>:environment:<env>`. The required reviewers on
uat and prod are **required**, not optional: they are the approval half of a version-gap exception
(KDEC-014, section 4). The kit cannot set or read them; the deploy records which environment it ran in.

**Deploy identity — least privilege, that application only:** App Service → `Website Contributor` on the
web app; Container Apps → `Container Apps Contributor` on the container app; `Reader` on the resource
group. No registry role (the app's own managed identity gets `AcrPull`). Nothing at subscription scope,
nothing on another application, never `Owner` or `User Access Administrator`. Role names are to be
verified on the first live deploy. A separate **build** identity holds `AcrPush` only.

## 3. The application repository's workflow (shape)

```yaml
jobs:
  security:
    uses: <kit-owner>/<kit-repo>/.github/workflows/reusable-security.yml@<kit-commit-sha>
    with:
      environment: prod            # names the baseline-ledger environment
      # defaults ARE the baseline: soft_fail_sast false, language auto. Change nothing to get PROCEED
      # on a clean run. Any softening must be attributed (part 05) or it routes DECISION_REQUIRED.
  build:
    needs: security
    uses: <kit-owner>/<kit-repo>/.github/workflows/reusable-build-docker.yml@<kit-commit-sha>
    with:
      github_environment: prod     # REQUIRED when push is true (the default): OIDC + registry
      acr_login_server: ${{ vars.KIT_ACR_LOGIN_SERVER }}
      image_repository: ${{ vars.KIT_IMAGE_REPOSITORY }}
    # secrets: the build identity's AZURE_* (AcrPush only), as for deploy below
    # builds once, scans those bytes, pushes those bytes; emits image_digest and artifact_identity
  # (add here: refuse unless needs.build.outputs.artifact_identity == 'REGISTRY_IDENTITY_PROVEN';
  #  templates/build-deploy.yml does it in its `verdict` job)
  deploy:
    needs: [security, build]
    uses: <kit-owner>/<kit-repo>/.github/workflows/reusable-deploy-appservice.yml@<kit-commit-sha>
    with:
      github_environment: prod
      routing_result: ${{ needs.security.outputs.routing_result }}       # REQUIRED
      advisory_causes: ${{ needs.security.outputs.advisory_causes }}     # needed at uat/prod
      controls_unavailable: ${{ needs.security.outputs.controls_unavailable }}
      # Only to accept a proven version gap at uat/prod (KDEC-014): the weakening record, named
      # and dated, in an environment whose required reviewers approve this job.
      # weakening_authority: <a named person>
      # weakening_reason: <why>
      # weakening_expires: <YYYY-MM-DD>
      environment_tier: ${{ vars.KIT_ENVIRONMENT_TIER }}
      resource_group: ${{ vars.KIT_RESOURCE_GROUP }}
      webapp_name: ${{ vars.KIT_APP_NAME }}
      acr_login_server: ${{ vars.KIT_ACR_LOGIN_SERVER }}
      image_repository: ${{ vars.KIT_IMAGE_REPOSITORY }}
      image_digest: ${{ needs.build.outputs.image_digest }}
    secrets:
      AZURE_TENANT_ID: ${{ vars.AZURE_TENANT_ID }}
      AZURE_SUBSCRIPTION_ID: ${{ vars.AZURE_SUBSCRIPTION_ID }}
      AZURE_CLIENT_ID: ${{ vars.AZURE_CLIENT_ID }}
```

**Permissions the caller must grant** (GitHub refuses the whole run -- `startup_failure`, no log --
when a called job asks for more than the caller grants; `tests/check_caller_permissions.py` holds the
kit's own callers and templates to this):

| calling | grant |
|---|---|
| the security workflow | `contents: read`, `security-events: write`, `actions: read` |
| the build workflow | `contents: read`, `id-token: write`, `attestations: write` |
| a deploy workflow | `contents: read`, `id-token: write` |
| the ledger proposal (`reusable-propose-ledger.yml`) | `contents: write`, `pull-requests: write` -- and call it only on the protected default branch, never on a pull request, after the security job. Inputs: `environment`; `establish-approver-role` only to establish a first ledger (needs CODEOWNERS over the ledger path; opens an ESTABLISH pull request); `ticket-ledger-artifact` to carry the ticket ledger in the same pull request. Outputs `status` and `why` |
| the NVD workflow (`reusable-nvd-cve.yml`) | `contents: read`, `security-events: write` |
| ticket reconciliation (`reusable-ticket-reconcile.yml`) | `contents: read` |
| the policy gate (`workflow-policy-check.yml`) | `contents: read` |
| the OIDC / boundary probe (`verify-azure-oidc.yml`) | `contents: read`, `id-token: write` |

The ledger proposal is a **separate** reusable workflow so the security scan never needs a write scope.

The kit's starter template (`templates/build-deploy.yml`) is the maintained version of this shape; it
also gates deploy on artifact identity and the security verdict through a `verdict` job.

**Pin the kit by commit SHA.** A branch or moving tag means the verdict came from code nobody chose.

## 4. Reading the result

- **Deploy proceeds** only on `routing_result` ∈ {`PROCEED`, `PROCEED_WITH_ADVISORY`}. Everything
  else — `BLOCKED`, `EVIDENCE_UNTRUSTED`, `DECISION_REQUIRED`, empty, unrecognised — refuses before
  login and names the value. **The deploy reusables do not read `artifact_identity`**: the starter
  template's `verdict` job refuses unless the build reported `REGISTRY_IDENTITY_PROVEN`, and the
  shape in section 3 (which has no `verdict` job) must add that check before calling a deploy.
- **A version gap is dev/test only (KDEC-014).** `PROCEED_WITH_ADVISORY` has several causes, and the
  security gate names them in `advisory_causes` (`VERSION_GAP`, `VERSION_GAP_UNVERIFIED`,
  `COVERAGE_PARTIAL`, `WEAKENING_ATTRIBUTED`, `FINDINGS_NOT_BLOCKED`).
  - `VERSION_GAP`: no carried scanner can read the target version, and every candidate's range is
    READ (cited or corpus-proven), so the gap is established. At `uat` and `prod` it refuses before
    login unless a named person accepts it through the existing weakening record —
    `weakening_authority` (the accepter), `weakening_reason`, and a `weakening_expires` date that has
    not passed — in a GitHub environment whose required reviewers approve the job.
  - `VERSION_GAP_UNVERIFIED`: the same gap, resting on an UNVERIFIED range. At `uat` and `prod` it
    proceeds, recorded loudly in the summary, the posture record and `outcome.json`. Enforcement is
    data-driven: it turns on when a seeded corpus makes the range READ in `scanner-registry.yaml`
    (Checkov and Trivy-config first). There is no switch to set.
  - Without `advisory_causes` the deploy cannot tell, so at those tiers an advisory with no cause is
    refused: pass it. Below `uat` any gap is recorded and the deploy proceeds. The other causes are
    unchanged.
  - The deploy's verdict step records exactly one ruling on every path (`VERSION_GAP_NOT_ENGAGED`
    when no gap rule applied). If the deploy's summary shows the ruling as "not reported", the
    verdict step never answered and the deploy's own `routing_result` is `EVIDENCE_UNTRUSTED`:
    treat it as a pipeline fault, not as "no gap" (`078ef90`).
- **A deploy whose reversal could not be shown available** (the capability step said nothing) lists
  `reversal` in its `controls_unavailable` and routes `EVIDENCE_UNTRUSTED` (`71a3d63`).
- `EVIDENCE_UNTRUSTED` means fix the pipeline (a tool, the report, discovery), not the code.
  `BLOCKED` means fix the code (a secret, malware, enforced findings). `DECISION_REQUIRED` means a person
  must attribute or revert a weakening.
- The deploy writes an **outcome report** (six questions: what was attempted, what is now serving,
  whether health and serving were verified, whether it was reversed, what needs a human) and provenance
  **tags on the serving object after health**. The report is the job summary plus `outcome.json` in
  the `deploy-evidence-<run_id>-<attempt>` artifact; `deployment_outcome` is **not** a workflow
  output, so a calling pipeline that must branch on it has to download that artifact (see the
  consumer-interface gaps in `docs/assurance/RELEASE_1_EVIDENCE_MANIFEST_PART3.md`, section 2C).

## 5. Ticketing from the kit

Findings become tickets in **Jira** (authoritative) or **Azure DevOps** (second), from a separate
post-merge/scheduled workflow (`reusable-ticket-reconcile.yml`), never from a pull request. It reads
the report's `findings.json` from a same-run artifact named by its `findings_artifact` input, and
`apply: false` (the default) only prints the plan. No starter template wires it yet. One backend per
repository and environment. A ticket is a request; closing it clears nothing. Configuration (host,
project, stamp field id, epic id, calibration item) is per tracker; moving trackers changes values only.

On **pull requests**, `reusable-ticket-reference.yml` requires the description to carry a well-formed Jira
reference (`https://<host>/browse/<KEY>-<number>`), from `tracker_host` and `project_key`. It is core
(KDEC-013) and applies **no issue-number range** unless the caller passes `min_digits` and `max_digits`
(both or neither); a consumer that limits its ticket numbers sets them in its own caller. It checks the
format only: never that the issue exists, and a ticket is never an authorization.

## 6. What a builder may and must NOT assume (trunk `078ef90`)

Proven, with run ids in `docs/assurance/RELEASE_1_EVIDENCE_MANIFEST.md` (and its `_PART2.md`, `_PART3.md`): the scan-and-gate path end to
end on GitHub (20/20 seeded signals, caller blocked — on `main` `ef4b15d`, run 38934329462; owed again on the
trunk); CodeQL from a separate consumer repository; the OIDC identity, context integrity and
authorization boundary on a real tenant; build and push to a cloud registry; both deploy adapters on
real Azure (refusal, healthy deploy, verified rollback, second actor refused, slot swap); the ticket
reconciler on a real Jira.

Do NOT assume yet:

- That a **real gate verdict has flowed into a deploy in one run**: every live deploy received a typed
  verdict, and the section-3 shape and the starter template have not run on a runner.
- That **the deploy identity's roles in section 2 are verified**: the live runs used a test identity
  whose roles were not recorded (LZ_KIT_HANDOFF_CONTRACT open item 3).
- That **Azure DevOps ticketing**, or an armed hosted run of `reusable-ticket-reconcile.yml`, works:
  Jira is proven live; Azure DevOps against stand-ins; the workflow has no hosted run.
- That **a baseline ledger has been established on a runner**: `reusable-propose-ledger.yml` can now
  do it (an approved ESTABLISH pull request, F-01 fixed in `a636f5e`), proven locally only; no hosted
  establish-then-propose run yet, and no starter template calls it.
- That **attestation signing or V1 verification** has run: held by plan; V1 is template-only.
- That the kit is a **landing-zone deploy engine**: it is not (section 1).
- That the rung ladder and SLA are enforced: not yet. Version fitness is consumed (KDEC-010): a scanner
  that cannot read the code at its version never carries a PASS; expect `PARTIAL` rows and a
  `PROCEED_WITH_ADVISORY` route until the registry's UNVERIFIED ranges are established (D-VF-4) —
  and while those ranges are UNVERIFIED, uat/prod proceed with the gap recorded; once a corpus makes
  them READ, uat/prod refuse it without a named acceptance (KDEC-014, section 4). The version-gap
  rule is proven against stubs only; no live run has exercised it yet.

## 7. Where the authority lives

The kit's design documents (`docs/architecture/`) and its code win over this explainer and over any brief.
Owner decisions are in `.context/products/secure-cicd-kit/decisions.md` (KDEC-001..015).
