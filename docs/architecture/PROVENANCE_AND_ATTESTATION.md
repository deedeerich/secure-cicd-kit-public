# Provenance and attestation

**The difference between stamping metadata about yourself, signing a statement somebody else can
check, and actually checking it — and which of the three this kit does.**

```
Phase: design — a written contract, not an implementation
Truth State: read 2026-09-24 from secure-cicd-kit at 53fa27b, from
             the reference estate service repository and the reference estate infrastructure repository (read-only),
             and from GitHub primary documentation cited inline
Audience: whoever wires attestation into the build path, and whoever has to explain
             to an auditor why a green pipeline proves what it proves
Decision Supported: whether to adopt actions/attest, where verification lives, what a
             verification failure costs at each rung, and what the plan gate forbids
Deferred Depth: the release object; the admission-control story for Kubernetes targets;
             key management for any non-GitHub signing path
```

> **Nothing described here is built.** No attestation is produced anywhere in this kit or in the
> reference estate. No attestation is verified anywhere. This document exists so that when it is
> built it is built once, and so that the difference between the three words in its title is
> settled before anybody writes a step that blurs them. The kit's own rule applies to this file
> first: **registering a term is not implementing it, and writing it down does not make it so.**
>
> **Nothing here is registered vocabulary.** Section 10 proposes candidates. They are written in
> lowercase-with-hyphens, deliberately, so that `scripts/reconcile_taxonomy.py` does not read a
> proposal as an adopted term — that checker matches the literal token, not the intent, and
> spelling a candidate in capitals would quietly register it by making the gate green.

---

## 0 · What this settles, and what it deliberately does not

**Settled here:** what separates a stamp from an attestation from a verification; where each link of
the source-to-runtime chain currently stands in this kit and in the reference estate; what
`actions/attest` signs, costs and requires; whether it is available on the owner's plan; where
verification must happen and what each failure mode must resolve to at each rung; whether the kit's
deploy path is digest-bound; and which job may hold `attestations: write`.

**Not settled here:** whether to sign with anything other than GitHub's own Sigstore federation;
what an admission control looks like for a Kubernetes target this kit does not currently deploy to;
how attestations are retained beyond the run; and how a verification result joins the release object
sketched in `DEPLOYMENT_CONTRACT_RECONCILIATION.md` section 7.5.

---

## 1 · Stamped, attested, verified — three claims, not three words for one

The whole gap is here, so it goes first.

**Stamped.** A value the producing system writes about itself, into a channel it controls. It is a
*report*. Its trustworthiness is exactly the trustworthiness of the process that wrote it, and there
is no way for a later reader to establish that independently — the reader can only re-read the same
claim. A stamp has no signature, no verifier and therefore no failure mode: nothing can ever
*disagree* with it.

**Attested.** A signed statement, made by an identity that is not the artefact, binding a named
subject (here, an image digest) to a predicate (here, how it was built). The signature is what makes
it checkable by somebody who was not present and does not trust the builder's word. An attestation
introduces the possibility of disagreement, which is the only thing that makes it evidence.

**Verified.** Somebody checked the signature, checked *which identity* made it, checked that the
subject in the statement is the artefact in front of them — and a failure of that check changed what
happened next. Verification is not a read; it is a refusal that did not have to fire.

The compression to one sentence:

> **A stamp is a write. An attestation is a signature. A verification is a refusal. Only the third
> one is a control.**

Applied through the ladder this kit already uses everywhere else — mentioned, specified, configured,
invoked, completed, surfaced, consumed, enforced, effective — a self-generated stamp that nothing
reads back is **configured** at best. It is present in the workflow, it renders correctly, and no
consumer branches on it. The registered `capability_maturity` namespace says the same thing in the
kit's own vocabulary: a step that exists and would run is `IMPLEMENTED`, and "the ceiling of static
analysis. Everything above requires a runner." Provenance in this kit has not reached `EXECUTED` on
any shipped path (section 2.3), let alone `ENFORCEMENT_PROVEN`, and `REVALIDATED` is not even
modelled.

### 1.1 A correction the brief needs, because the namespaces matter

The task framing put `OWNED_BINDING` and `REFERENCE_ONLY` in `artifact_identity`. They are not
there. They are values of **`release_ownership`**, and `assurance-taxonomy.yaml` goes out of its way
to forbid exactly that conflation:

> *"NOT artifact_identity. That namespace asks whether the artefact a control inspected is the
> artefact that was published — a question about bytes and a registry. This asks whether a DEPLOYED
> OBJECT is still owned by one release — a question about a live resource and a release graph."*

`artifact_identity` has four registered values and no others: `REGISTRY_IDENTITY_PROVEN`,
`LOCAL_BUILD_ONLY`, `IDENTITY_UNVERIFIED`, `NOT_ESTABLISHED`.

So the real question — *where does a self-generated stamp sit in `artifact_identity`* — has a
sharper answer than the framing allowed: **it does not sit anywhere in that namespace, because a
stamp is not an identity claim at all.** It is a *serialization of* an identity claim. The
distinction is the point of this document, and section 2.2 is where it bites.

---

## 2 · The honest current state

### 2.1 What the kit actually has, and it is more than "nothing"

The strongest link in either repository is real, and it is not a stamp.
`.github/workflows/reusable-build-docker.yml` builds exactly once, scans those bytes, pushes those
bytes, and then **asks the registry what it is holding**:

```
Assert artifact identity — the registry is holding the image that was scanned
  docker buildx imagetools inspect --raw "$REPO@$DIGEST"
  compare .config.digest against the config digest that was scanned
  mismatch  -> exit 1
  no config -> exit 1 (an index or attestation manifest, not a plain image manifest)
```

That is a **second party being asked and agreeing**. The registry is not the build job, it can
disagree, and a disagreement costs the run. By the three-way distinction in section 1 this is
closer to *verification* than to *stamping* — it is a check whose failure changes what happens next.
It is the one place the kit already does the right shape of thing.

What it is *not* is an attestation. Nothing is signed. The claim is produced and consumed inside one
workflow run, and it survives that run only as a string.

### 2.2 Where the stamp actually is, and why it degrades

`.github/actions/render-version-metadata/action.yml` renders a compact JSON object with schema
`deploy-provenance/2` carrying `image_digest`, `scanned_config_digest`, `artifact_identity`,
`sbom_sha256`, `git_sha`, `git_ref`, `run_id`, `built_at` — and, honestly,
`technical_provenance: "NOT_ESTABLISHED"` hardcoded, because
`DEPLOYMENT_CONTRACT_RECONCILIATION.md` section 7.7 makes production provenance a conjunction of
eight conditions and the composite can see one of them.

That composite is genuinely well built. It refuses an unrecognised identity class, it shape-checks
every hash (after a real incident where YAML typed an all-digit hash as a float), it defaults to the
weakest value so a forgetful caller under-claims, and it warns when the identity is not proven.

And then the value is written to `DEPLOY_PROVENANCE`, an App Service application setting or a
Container App revision label, by `az`. At that moment:

> The registry round trip was evidence. Its verdict, copied into a JSON blob by the same job that
> produced it and written into a field that job controls, is **hearsay**. Nothing downstream can
> re-derive it, contradict it, or tell it apart from a value somebody typed.

This is the precise sense in which the kit *stamps* rather than *attests*. It is not that the
underlying claim is weak. It is that serializing a strong claim into a self-controlled field
destroys its checkability, and the resulting field reads to every later human as proof.

### 2.3 And on the shipped path the stamp is not even written

`version_metadata` defaults to `''` in both deploy workflows, and the "Stamp provenance" step is
guarded `if: inputs.version_metadata != ''`. The shipped caller template,
`templates/build-deploy.yml`, passes `image_digest` and does **not** pass `version_metadata`. The
only caller of `render-version-metadata` anywhere in the repository is `.github/workflows/self-test.yml`,
as a probe.

So, in the ladder's terms: the stamp is **configured** and **not invoked** on every path a consumer
would actually adopt. A capability whose sole caller is its own self-test has not been consumed by
anything.

> **Update (L87).** `templates/build-deploy.yml` now has a `verdict` job between build and deploy:
> it renders the stamp from the build's own outputs and passes it as `version_metadata`, and it
> branches on `artifact_identity` and on the precedence-maximum of the security and build
> `routing_result` -- a requested deploy that is refused fails the run. Proven locally by
> `tests/prove_template_branches_on_verdict.py` with the security verdict stubbed (the flagship's
> own `routing_result` output, L30/L31, is proven separately by `tests/prove_gate_routing.py`); an
> absent verdict refuses the deploy as `EVIDENCE_UNTRUSTED`. Not yet on a runner.

### 2.4 What the reference estate has — ahead, and not in the way it looks

`reference estate service repo, workflow gov-prod-deploy-<service>-api.yml` is genuinely ahead in
three respects, and behind in the one the word "attestation" implies.

Ahead:

- **Richer build inputs are captured.** Lines 105 and 117-118 record a lockfile hash
  (`sha256sum apps/<service>/requirements.txt`) and the SBOM hash alongside the image digest. The kit
  captures neither of the first two into any provenance record.
- **A versioned envelope.** Line 109 declares a `"schema"` field naming a versioned
  provenance-attestation envelope, version 1. The kit's equivalent is `deploy-provenance/2`. Both
  version their shape; only one of them names itself after attestation.
- **The build is gated on security jobs.** Line 75, `needs: [codeql, semgrep]`, with the header
  comment "All security lanes are REQUIRED (no soft fails)". The kit's template does the same
  through `needs: [security, policy]`.
- **The reference estate's production deploy workflow** (in the reference estate infrastructure repository, not the reference estate service repository) does plan then artifact then
  apply, with **both** the `plan` and `apply` jobs bound to `environment: gov-prod`, and `apply`
  additionally requiring `workflow_dispatch` plus a typed break-glass string.

Behind, and this is the finding:

> **the reference estate does not attest either.** The job is named `provenance` and the schema is named after
> attestation, but what it produces is a `cat > provenance-a reference estate service.json` heredoc, minified with
> `python3`, hashed with `sha256sum`, and uploaded with `actions/upload-artifact@v4` at
> `retention-days: 90`. There is no signature, no signing identity, no verifier and no expiry-proof
> storage. It is a **stamp with a better vocabulary**.

Two further observations that matter for the design:

- The `deploy` job declares `needs: [build, provenance]` but reads **only** `needs.build.outputs`.
  The provenance job is an ordering dependency, not a gate. If it produced a contradiction, nothing
  would notice.
- The `provenance_sha256` output is computed and exported and **consumed by nothing** in that file.

A grep for `attest-build-provenance`, `attestations:` as a permission, `in-toto`, `slsa-framework`,
`cosign` and `sigstore` across both `D:/Dev/secure-cicd-kit` and `D:/Dev/consumer-estate` returns
nothing. The only occurrences of the word in the kit are the string "attestation manifest" in the
build workflow's own error message, a "Signing / provenance attestation" row in
`docs/assurance/CAPABILITY_MATRIX.md` and `.github/workflows/validate-scanners.yml` — which already
says, in one line, the whole content of this document:

> *"Signing / provenance attestation — SBOM produced, nothing attests to it"*

That line has been correct since it was written. Nothing has changed it.

---

## 3 · The chain, link by link

`has` means implemented on a path a consumer would actually run. `probe` means implemented but
reachable only from a self-test. `—` means absent.

| # | link | kit | the reference estate | notes |
|---|---|---|---|---|
| 1 | source commit identity | has | has | `github.sha` in both. Neither verifies a commit *signature*; the identity is the platform's word. |
| 2 | base image digest | has (L86) | — | Neither resolves or records the `FROM` digest. A floating base tag makes every downstream claim about "the same build inputs" unfalsifiable. **The largest single gap in the chain.** *Update (L86):* the build job's `build_inputs` step now resolves every external `FROM` to a digest and records it; an unresolvable one is recorded empty with `all_base_images_resolved: false`. Proven locally by `tests/prove_build_inputs_recorded.py`; not yet on a runner. |
| 3 | lockfile hash | has (L86) | **has** | the reference estate hashes `requirements.txt` into its record. *Update (L86):* the kit now hashes every recognised lockfile in the build context into `build_inputs`, and `render-version-metadata` carries it (`deploy-provenance/3`). |
| 4 | toolchain versions | has (L86) | — | *Update (L86):* docker engine, buildx, syft and trivy versions are recorded in `build_inputs`; an empty value means not observed. (`provenance_identity.fields` carries `scanner_version` — that is *finding* provenance, a different envelope.) |
| 5 | single build | **has** | delegated | The kit enforces one build and documents why at length. the reference estate calls a devkit reusable this repository cannot read. |
| 6 | artefact digest, proven | **has** | delegated | Registry round trip, `artifact_identity` emitted as a four-value output. The strongest link in either repo. |
| 7 | SBOM | has | has | Syft SPDX in the kit, named by evidence class so an unverified SBOM cannot be cited as a verified one. `sbom_sha256` in both. |
| 8 | **attestation** | written, not run (L88) | — | **Neither.** Nothing signs anything. Section 2.4. *Update (L88):* `reusable-build-docker.yml` has an `attest` job, the only holder of `attestations: write` (job level), signing only a `REGISTRY_IDENTITY_PROVEN` digest via `actions/attest@v4`, skipped on a private repository unless `attestations_available` is set. Permission topology and the subject guard are proven locally (`tests/prove_attest_job_isolated.py`); **the signature itself is owed to a hosted run**, as is the `artifact-metadata: write` question (section 4.4). |
| 9 | attestation in the registry | — | — | Neither pushes a referrer, signature or SBOM attachment to ACR. The registry holds the image and nothing about it. |
| 10 | deployment by digest | **has** | has | The kit refuses tags with a regex guard before it even logs in. Section 7. |
| 11 | provenance stamped at deploy | probe | has | Kit: step exists, shipped template never passes it. the reference estate: uploads a run artifact with a 90-day retention. |
| 12 | verification at deploy | written, held (L89) | — | **Neither.** Nothing reads a provenance record back and refuses on it. *Update (L89):* `.github/actions/verify-attestation` implements V1 with the five outcomes now registered as `attestation_verification` (section 10's four candidates plus `ATTESTATION_HELD_BY_PLAN`, answering its open question as a value), routed per section 6.3; `templates/build-deploy.yml` runs it before the deploy decision. Classification and routing proven locally against recorded `gh` answers (`tests/prove_attestation_verify.py`); the live lookup is `IMPLEMENTATION_HELD` with the plan as trigger (`tests/reconcile_validation.py`, `attestation-verify`). Not yet called from inside the deploy workflows themselves. |
| 13 | runtime revalidation of identity | — | — | Neither re-reads the running image reference and compares it to what was deployed. Both have a health probe; a 200 from a stale container is indistinguishable from a 200 from the new one. `capability_maturity.REVALIDATED` is registered and unreached here. |

Read down column "kit": the chain is strong from link 5 to link 7, closed at link 10, and open at
both ends. Links 2 and 4 mean the kit cannot say *what went into* the build; links 8, 9, 12 and 13
mean nothing outside the producing run can check *anything* it said.

---

## 4 · What `actions/attest-build-provenance` provides, and what it costs

Every claim in this section carries a primary citation. Where two primary sources disagree, that is
recorded rather than resolved.

### 4.1 What it is now

As of v4, `actions/attest-build-provenance` is *"simply a wrapper on top of `actions/attest`"*
([actions/attest-build-provenance](https://github.com/actions/attest-build-provenance)). The
GitHub documentation page for establishing build provenance uses `actions/attest@v4` in every
example
([Using artifact attestations to establish provenance for builds](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds)).
Adopting the wrapper means adopting `actions/attest`; the design below names both.

### 4.2 What it signs and produces

It generates *"signed build provenance attestations for workflow artifacts"* using the SLSA build
provenance predicate in the in-toto attestation format, and the attestations are *"uploaded to the
GH attestations API and associated with the repository from which the workflow was initiated"*
([actions/attest-build-provenance](https://github.com/actions/attest-build-provenance)).

The content is *"a link to the workflow associated with the artifact; the repository, organization,
environment, commit SHA, and triggering event for the artifact; other information from the OIDC
token used to establish provenance"*
([Artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations)).

Subject selection is by `subject-path` (a file or glob) or by `subject-digest` in
`sha256:<hex>` form, which **requires** `subject-name` alongside it
([actions/attest](https://github.com/actions/attest)). The digest path is the relevant one here:
the kit already has the digest as a job output and does not need the image locally to attest it.

Outputs are `bundle-path` (*"absolute path to the file containing the generated attestation"*),
`attestation-url` and `attestation-id` (same source). `bundle-path` is what makes offline
verification possible later.

### 4.3 Where it is stored, and the transparency difference

> **Public repository:** *"A copy of the generated Sigstore bundle is stored with GitHub and is also
> written to an immutable transparency log that is publicly readable on the internet."*
>
> **Private or internal repository:** *"GitHub's Sigstore instance uses the same codebase as the
> Sigstore Public Good Instance, but it does not have a transparency log and only federates with
> GitHub Actions."*
>
> ([Artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations))

That difference is not cosmetic. On a public repository an attestation is checkable against a log
nobody controls. On a private one it is checkable against GitHub. The second is still far stronger
than a stamp — it is signed, it binds a digest, and it can disagree — but the trust root is the same
vendor that ran the build. Worth stating in any claim made to an auditor.

### 4.4 Permissions — and the sources conflict

GitHub's how-to page gives two blocks verbatim
([Use artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)):

```yaml
# binaries
permissions:
  id-token: write
  contents: read
  attestations: write
```

```yaml
# container images
permissions:
  id-token: write
  contents: read
  attestations: write
  packages: write
```

`packages: write` in the second block is for publishing to **GitHub Packages / ghcr.io**. The kit
publishes to Azure Container Registry with an OIDC-federated Azure identity, so that permission
buys nothing here — and granting a write permission that nothing uses is the exact habit this kit
argues against.

The `actions/attest` repository's own usage block lists a **third** permission not present on
either documentation page:

```yaml
permissions:
  id-token: write
  attestations: write
  artifact-metadata: write
```

([actions/attest](https://github.com/actions/attest)). The how-to page mentions
`artifact-metadata: write` only in connection with `push-to-registry` creating storage records on
the linked-artifacts page. **The two primary sources do not agree on whether it is always
required.** Recorded in section 11 as unestablished; the implementation must determine it by
observation, not by picking the more convenient page.

### 4.5 How a consumer verifies

```
gh attestation verify [<file-path> | oci://<image-uri>] [--owner | --repo] [flags]
```

*"Verifies the integrity and provenance of an artifact using its associated cryptographically signed
attestations."* At least one of `--owner <org>` or `--repo <owner/repo>` is required. By default it
*"enforces the `https://slsa.dev/provenance/v1` predicate type"*, validates the identity of the
workflow that created the attestation, and fetches attestations via the GitHub API — so it needs
network access unless `--bundle` supplies a local bundle
([gh attestation verify](https://cli.github.com/manual/gh_attestation_verify)).

The flags that make it a control rather than a smoke test:

| flag | why it matters |
|---|---|
| `--repo <OWNER>/<REPO>` | Scopes the lookup. Without a scope, "an attestation exists" is not the same claim as "an attestation from *our* repository exists". |
| `--signer-workflow <...>` | Enforces **which workflow** signed it. This is the difference between "GitHub signed something" and "our build workflow signed this digest". Omitting it is the single most likely way to ship a verification that verifies nothing meaningful. |
| `--deny-self-hosted-runners` | Refuses attestations produced on a self-hosted runner. |
| `--predicate-type <...>` | Needed for non-provenance predicates; the SBOM example uses `https://spdx.dev/Document/v2.3`. |
| `--format json` | The only output shape a gate can branch on. |

Documented examples, with GitHub's all-caps placeholders rewritten in angle brackets so this file
does not hand `scripts/reconcile_taxonomy.py` a placeholder to read as a state
([Use artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations)):

```bash
gh attestation verify <PATH>/<TO>/<ARTIFACT> -R <ORG>/<REPO>
docker login ghcr.io
gh attestation verify oci://ghcr.io/<ORG>/<IMAGE>:test -R <ORG>/<REPO>
```

Note the registry in the container example. It is ghcr.io in every documented case. Section 11.

---

## 5 · Availability — and this is the finding that reshapes the design

> *"Artifact attestations are available in public repositories for all current GitHub plans."*
>
> *"If you are on a GitHub Free, GitHub Pro, or GitHub Team plan, artifact attestations are only
> available for public repositories. To use artifact attestations in private or internal
> repositories, you must be on a GitHub Enterprise Cloud plan."*
>
> ([actions/attest-build-provenance](https://github.com/actions/attest-build-provenance);
> the same wording appears in
> [GitHub Enterprise Cloud: Artifact attestations](https://docs.github.com/en/enterprise-cloud@latest/actions/concepts/security/artifact-attestations))

Artifact attestations are additionally **not supported on GitHub Enterprise Server** (same source).

**So the gate is real, and it has the same shape as the one already tabled in
`PIPELINE_ORDERING_AND_SCAN_VALIDITY.md` for code scanning and SARIF upload:** free and unrestricted
on a public repository, licence-gated on a private one. That table now has a sibling row:

| capability | public repository | private repository, Free / Pro / Team | source |
|---|---|---|---|
| artifact attestations (generate and verify) | free | **refused — requires GitHub Enterprise Cloud** | as cited above |

The consequence for the design is not "adopt it anyway". It is:

> **On a GitHub Pro account, every private consumer of this kit would sit permanently at
> `EVIDENCE_UNTRUSTED` if attestation verification were wired as a live gate.** The registered
> `validation_debt_state` namespace already forbids that outcome: *"A permanently red check is not a
> control, it is training: people learn red means 'known backlog', stop reading it, and a real
> regression arrives wearing the same colour."*

That is the difference between this and every other control in the kit, and section 6.4 is where it
is handled rather than wished away.

---

## 6 · The verification half, which is the half that matters

Producing an attestation nobody checks is `soft_fail_sast` in a new costume: it looks exactly like
assurance and enforces nothing. Worse than the SAST case, in fact — a soft-failed scan at least
prints findings. An unverified attestation prints a green check mark.

### 6.1 Three verification points, and only two of them exist

**V1 — at deploy, before any mutation.** The deploy workflow verifies the attestation for
`inputs.image_digest` *before* `az webapp config container set` or `az containerapp update` runs.
This is the one that matters most, because it is the last point at which refusing costs nothing: no
resource has changed, no traffic has moved, `ROLLBACK_CONTRACT.md` has nothing to honour. It sits
immediately after the existing "Validate digest (refuse mutable tags)" step, which is already the
first step in both deploy workflows and already the right place for a precondition.

**V2 — at admission.** *Not available for this kit's targets.* The kit deploys to Azure App Service
and Azure Container Apps. Neither exposes an admission-control hook into which a signature policy
could be installed; that pattern belongs to Kubernetes. ACR itself supports OCI 1.1 referrers —
*"The OCI Referrers API is supported by most of the ACR features except the CMK-encrypted registry"*
([Manage OCI Artifacts and Supply Chain Artifacts with ORAS](https://learn.microsoft.com/azure/container-registry/container-registry-manage-artifact))
— so attestations *can* be stored beside the image, but storage is not admission. **V2 is absent by
platform, not by omission, and must be recorded as such rather than left looking unfinished.**

**V3 — at revalidation.** A scheduled job reads the image reference the platform is *actually*
running (`az webapp config container show`, `az containerapp revision list`), compares that digest
to the one the release recorded, and re-verifies the attestation. This is the rung the kit has
registered and never reached: `capability_maturity.REVALIDATED` — *"Same artifact, same SBOM, new
intelligence. The assurance state changed without the software changing."* V3 is also the only thing
that would catch an out-of-band `az` change to a running app, which no build-time control can see.

### 6.2 Four outcomes, and they must not be three

The mistake to avoid is a boolean. Verification has four distinguishable results and collapsing any
two of them reproduces the failure family this kit exists to prevent.

| outcome | what happened | what it is |
|---|---|---|
| **verified** | Signature valid; subject digest equals the digest being deployed; signer workflow matches the expected workflow; predicate type is the expected one. | Evidence. |
| **absent** | Lookup succeeded and returned no attestation for this digest. | A **gap in production**. The producing side never ran, or ran without the permission. |
| **contradicted** | An attestation exists and does **not** check out: bad signature, subject mismatch, unexpected signer, wrong predicate type. | An **active contradiction**. Something signed a different artefact, or something substituted this one. |
| **not-establishable** | The check could not be performed: API unreachable, CLI absent, token lacks read access, or **the plan does not offer attestations at all**. | The control could not be acquired. |

`absent` and `contradicted` are the pair a tired implementation collapses, and they need opposite
treatment. `absent` is a hole; `contradicted` is an alarm. `absent` and `not-establishable` are the
second pair, and the kit already has a precedent for keeping them apart — `artifact_identity`
separates `IDENTITY_UNVERIFIED` (asked and failed) from `NOT_ESTABLISHED` (never reached).

### 6.3 What each outcome resolves to, per rung

Using the minimum-routing-result mechanism from
`docs/architecture/ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md` section 1.1 — a rung sets the weakest
result a control may contribute; the run's result is the precedence-maximum across controls, with
`BLOCKED > EVIDENCE_UNTRUSTED > DECISION_REQUIRED > PROCEED_WITH_ADVISORY > PROCEED`.

| outcome | crawl | walk | run |
|---|---|---|---|
| verified | `PROCEED` | `PROCEED` | `PROCEED` |
| absent | `PROCEED_WITH_ADVISORY` | `DECISION_REQUIRED` | `DECISION_REQUIRED` |
| **contradicted** | `BLOCKED` | `BLOCKED` | `BLOCKED` |
| not-establishable | `EVIDENCE_UNTRUSTED` | `EVIDENCE_UNTRUSTED` | `EVIDENCE_UNTRUSTED` |

Four readings of that table are load-bearing.

**`contradicted` blocks at `crawl`.** It is the second row in the whole enforcement model to do so,
alongside secrets, and for the same reason. A signature that does not verify against the digest
being deployed is not a severity-tunable finding — it says the artefact in front of the deploy is
not the artefact the build signed. There is no rung at which that is an advisory. Section 3 of
`ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md` already makes the equivalent argument for secrets:
"failure to establish the secret result can never become permission to merge."

**`absent` never reaches `BLOCKED`, even at `run`.** Because `absent` is overwhelmingly caused by
the *producing* side — a build that predates the attest job, a repository that has not adopted it, a
plan that forbids it. Blocking on it makes every pre-existing image undeployable on the day the
control is switched on, which is the founding failure the tier ladder exists to prevent.
`DECISION_REQUIRED` is the correct state: *"NOT a failure and NOT a pass. It is the state a kit
should be in when someone has weakened a control and nobody has said why."*

**`not-establishable` is `EVIDENCE_UNTRUSTED` at every rung and never anything else.** This is the
registered rule, not a preference: *"NEVER DECISION_REQUIRED and never clean. There is nothing here
to decide about yet — the input to a decision is missing."* And per `environment_tier`, that means it
warns at `sandbox` and `dev`, and **stops at `uat` and `prod`**, both of which are production tiers
where "scanner did not run" blocks.

**A missing or unverifiable attestation must never resolve to a pass.** Neither `absent` nor
`not-establishable` appears anywhere in the `PROCEED` column above `crawl`. That is the one
invariant this whole section exists to hold.

### 6.4 The plan gate must be registered as debt, not wired as a permanently failing gate

Section 5 establishes that on GitHub Pro, a private repository **cannot** produce or verify an
attestation. Wired naively, V1 would then emit `not-establishable` on every run of every private
consumer forever, which at `uat` and `prod` means a permanent stop — a gate that gets switched off
within a week.

The resolution uses vocabulary the kit already has. `validation_debt_state.IMPLEMENTATION_HELD` is
defined as *"a component exists whose blocker is an UNBUILT CAPABILITY, not an unwritten probe"* and
*"carries an activation TRIGGER rather than only a date, because it returns to scope when the thing
it waits on starts."* A plan-level refusal is precisely an unbuilt capability from the consumer's
side. So:

- **The verification step is written, and it is not armed by default on private repositories.**
- **Plan unavailability is recorded once, at discovery, and is spelled differently from a missing
  attestation.** If "this plan does not offer attestations" and "this image has no attestation"
  render the same, then on the day the plan changes nobody will notice that the second one has
  become a real finding. One of those two causes is fixable by the owner and one is not, and a
  control that cannot tell them apart is reporting the wrong thing to the only person who could act.
- **The activation trigger is the plan, not a date.** The debt returns to scope when the account
  moves to Enterprise Cloud, or when a repository the kit builds is public.
- **On a public repository, it arms immediately**, because there the capability is free on all
  current plans and there is nothing to defer.

---

## 7 · Deploy-by-digest — the verdict

A tag is mutable. An attestation bound to a digest means nothing if the deployment resolves a tag at
deploy time, because the attested digest and the deployed digest are then two different facts joined
by a name that anyone with push access can move.

**Verdict: the kit's deploy path is digest-bound, and this link is not where the chain is broken.**

Both `reusable-deploy-appservice.yml` and `reusable-deploy-containerapp.yml` open with the same
step, before Azure login, before anything:

```
- name: Validate digest (refuse mutable tags)
    if ! echo "$d" | grep -Eq '^sha256:[a-f0-9]{64}$'; then
      echo "::error::image_digest must be a full sha256 digest (got '$d').
            Tag-based deploys are not permitted."
      exit 1
```

and both then set the image by `@${{ inputs.image_digest }}`, never by tag. The App Service workflow
is even titled "Deploy App Service (by digest, sovereign-capable)". This is stronger than what can be
read in the reference estate, which passes a digest to a devkit reusable in a repository outside this scope — the
digest is right, but whether a guard enforces it is not establishable from here.

Three qualifications, because "digest-bound" is doing less work than it sounds like:

**The digest is bound; the *evidence about* the digest is not carried.** Section 2.3: the shipped
template passes `image_digest` and not `version_metadata`, so the deploy knows *which* artefact and
nothing about what was established about it. Deploying the right bytes with no record of why they
were the right bytes is a correct deployment with no provenance.

**The guard against a bad identity is a job failure, not a branch.** `templates/build-deploy.yml`
declares `needs: [build]` and does not read `artifact_identity` at all. In practice a mismatch still
stops the deploy, because `assert_identity` exits 1 and the build job fails — `needs` does the work.
But that safety comes from a side effect. A caller who adds `continue-on-error` to the build job, or
who consumes outputs from a failed job, loses it silently and the template gives no sign. The kit
went to considerable trouble to emit a four-value `artifact_identity` output specifically so a
consumer could branch on it, and its own template does not.

**Nothing confirms what is running after the deploy.** `az webapp config container set` is issued,
the app is restarted, and a health probe polls for HTTP 200. A 200 from a container that did not
actually roll is identical to a 200 from the one that did. The kit has the right vocabulary for this
already — `DEPLOYMENT_CONTRACT_RECONCILIATION.md` section 7.7 lists "expected artefact observed
running" as a separate condition from "exact artefact identity established", and marks only the
second as implemented. Link 13 of section 3.

---

## 8 · What it costs

### 8.1 Jobs and minutes

Attestation needs the digest and an OIDC token. Both exist after the build job. Two shapes:

| shape | cost | permission consequence |
|---|---|---|
| attest **inside** the build job | no extra runner start; a few seconds of step time | `attestations: write` is held by the job that also builds, scans, logs into Azure and pushes. **Rejected.** |
| attest in a **separate job**, `needs: [build]`, consuming `image_digest` and `image_repository` as inputs | one extra runner start (tens of seconds of wall clock, billed as a fresh job minute) plus a few seconds of step time; **no artefact transfer**, because `subject-digest` + `subject-name` do not require the image locally | `attestations: write` is held by a job that does nothing else. **Preferred.** |

Verification at V1 adds one `gh attestation verify --format json` call to the deploy job: seconds,
no new job, no artefact download for an `oci://` subject. V3 is a new scheduled workflow and is
costed separately when it is designed.

Against a Trivy scan and a Syft SBOM this is not a material minute cost. The cost that matters is
the permission.

### 8.2 The permission, and why it must not spread

**Exactly one job may hold `attestations: write`: the attest job.** Not the build job, not the deploy
job, not the security workflow.

The mechanism that makes this a real risk rather than a style preference: in a reusable workflow, the
`permissions:` block at file level is the **ceiling for every job in that file**, and a job-level
block narrows from there. Adding `attestations: write` at file level in `reusable-build-docker.yml`
would grant it to the build job as well — a job that already holds `id-token: write`, authenticates
to Azure, and runs a caller-supplied Dockerfile. That is a token with the authority to sign
statements *about* artefacts, handed to the process that produces them from untrusted input. Signing
authority belongs to the narrowest possible job.

So, concretely:

```yaml
# reusable-build-docker.yml — UNCHANGED at file level
permissions:
  contents: read
  id-token: write

jobs:
  build:
    # unchanged

  attest:
    needs: [build]
    permissions:          # JOB level. Never promoted to file level.
      contents: read
      id-token: write
      attestations: write
    # no Azure login, no registry login, no Dockerfile, no caller-supplied script
```

Three further rules:

- **`packages: write` is not added.** It appears in GitHub's container-image example because that
  example publishes to ghcr.io. This kit publishes to ACR with a federated Azure identity. A write
  permission granted for a registry the kit does not use is a permission surface with no
  corresponding capability.
- **`artifact-metadata: write` is added only if observation shows it is required** (section 4.4 —
  the primary sources disagree), and only on the attest job.
- **Verification needs no new write permission anywhere.** `gh attestation verify` reads. The deploy
  job needs a token with read access to the repository's attestations and, for an `oci://` subject,
  registry read — which it already has through its Azure identity.

The relevant recent lesson is that permission unions across merged jobs produce regressions that are
invisible until something uses the extra authority. A signing permission is the worst possible
candidate for a union.

---

## 9 · What adopting this would actually change, in order

Stated as a sequence because each step is useless without the one before it, and because doing them
out of order produces exactly the false assurance this document argues against.

1. **Capture the missing build inputs** — base image digest, lockfile hash, toolchain versions
   (links 2, 3, 4). This costs nothing, needs no permission, and works on every plan. Without it an
   attestation signs a statement whose interesting fields are empty. **Do this first even if
   attestation is never adopted**, because it is the half of the gap that has no plan gate.
2. **Pass `version_metadata` from the shipped template** so the stamp that already exists is at
   least invoked on a real path (section 2.3). Also free, also plan-independent.
3. **Branch the template on `artifact_identity`** rather than relying on the build job's failure as
   an implicit gate (section 7).
4. **Add the attest job**, job-scoped permission, digest subject (section 8).
5. **Add V1 verification at deploy**, with `--signer-workflow`, `--format json`, and the four-outcome
   mapping of section 6.3, registered as held debt on plan-gated repositories (section 6.4).
6. **Design V3 revalidation.** Separate document; it is the only thing that catches an out-of-band
   change, and nothing in either repository addresses it today.

Steps 1 to 3 close real gaps on the current plan. Steps 4 and 5 are the ones section 5 constrains.

---

## 10 · Candidate vocabulary

Four outcome names are needed for section 6.2 and none of them exist in
`assurance-taxonomy.yaml`. They are written here in lowercase-with-hyphens **on purpose**:
`scripts/reconcile_taxonomy.py` matches the literal uppercase token, so spelling a proposal in
capitals would register it by making the gate green — the "green-by-taxonomy-inflation" failure that
script explicitly names.

What was checked first, in the order that script prescribes:

- **Reuse before invention.** `artifact_identity` was checked and rejected: it asks whether the
  artefact a control *inspected* is the one *published* — a question about two byte-streams and a
  registry, answered inside one run. Attestation verification asks whether a *signed third-party
  statement* about a digest checks out, at a point far downstream of the run that made it. Same
  subject, different question, different failure modes.
- `routing_result` was checked and is **reused, not extended**. The four outcomes *map onto* it; they
  do not replace it. `contradicted` contributes `BLOCKED`, `not-establishable` contributes
  `EVIDENCE_UNTRUSTED`. No new routing value is proposed and none is needed.
- `evidence_confidence`, `publication_state` and `observation_quality` were checked. All three model
  how strongly something was *observed*; none models whether a signature *checked out*.
- `capability_maturity` was checked and is reused as-is for the ladder in section 1.

| candidate | proposed meaning | why not an existing term |
|---|---|---|
| `attestation-verified` | Signature valid, subject digest matches, signer workflow matches, predicate type matches. | Nothing registered means "a signature checked out". |
| `attestation-absent` | Lookup succeeded, no attestation exists for this subject. | Distinct from `IDENTITY_UNVERIFIED`, which is about a registry round trip inside the build. |
| `attestation-contradicted` | An attestation exists and fails to check out. | The one outcome with no analogue anywhere in the registry: an active disagreement rather than a gap. |
| `attestation-not-establishable` | The check could not be performed — unreachable, unauthorised, or unavailable on this plan. | Closest neighbour is `NOT_ESTABLISHED` in `artifact_identity`, which is scoped to that namespace's question. |

**These are proposals. None should be registered until the mechanism exists**, because registering
them would assert they had been decided, and section 6 is a design, not an implementation. A fifth
name may also be needed to keep "unavailable on this plan" apart from "unreachable right now"
(section 6.4) — deliberately not proposed here, because whether that is a fifth value or a reason
field on the fourth is a question the implementation should answer.

---

## 11 · What could not be established

Named plainly, because a confident guess in this section is worse than an admission.

1. **Whether `actions/attest` `push-to-registry` works against Azure Container Registry.** ACR
   documents OCI 1.1 referrers support with a named exception for CMK-encrypted registries
   ([Manage OCI Artifacts with ORAS](https://learn.microsoft.com/azure/container-registry/container-registry-manage-artifact)),
   and the action documents `push-to-registry` generally. **No primary source tests the
   combination.** Every documented container example in GitHub's material uses ghcr.io. Unverified.

2. **Whether `gh attestation verify oci://<acr-host>/...` resolves.** The verification path fetches
   from GitHub's attestations API by subject digest. Whether that lookup succeeds for an image in a
   registry GitHub never saw is not stated anywhere in the cited documentation. Unverified, and it
   is the single question that most determines whether V1 is implementable as designed.

3. **Whether `artifact-metadata: write` is always required.** Section 4.4 — the `actions/attest`
   README's permissions block and GitHub's how-to pages disagree. Not resolved here. Must be
   established by observation.

4. **The owner's actual GitHub plan.** The brief states Pro; this document did not query the
   account. Section 5's conclusion is conditional on that being correct — and it is worth confirming
   before any of section 9 steps 4 to 6 is scheduled, because the answer changes the whole shape.

5. **The visibility of the consumer repositories.** the reference estate service repository and the reference estate infrastructure repository were read from
   local clones, which carry no visibility state. If any repository the kit builds is **public**,
   attestation is available there today on any plan, and the debt of section 6.4 does not apply to
   it.

6. **What the devkit reusables do.** the reference estate calls
   `a former employer/deepanalysis-devkit/.github/workflows/_reusable-build-docker.yml@main` and
   `_reusable-deploy-appservice.yml@main`. That repository was not available locally and is outside
   the read scope of this task. **Whether those workflows attest, verify, or guard the digest is
   unknown.** Every claim in this document about the reference estate is a claim about the caller file only. This
   is the largest blind spot in section 3's the reference estate column.

7. **Whether App Service or Container Apps offer any admission-time verification hook.** None was
   found. Not searched exhaustively enough to call it proven absent. Section 6.1 records V2 as
   absent by platform on that basis and should be revisited if a hook exists.

8. **Actual minute cost.** Section 8.1 reasons from job structure, not from measurement. No run was
   executed.

9. **Whether the registry round trip of section 2.1 would survive attestation being pushed to the
   registry.** The build workflow's identity assertion explicitly fails when a digest resolves to
   *"an index or attestation manifest rather than a plain image manifest"*. Attaching referrers to
   an image should not change what the image digest itself resolves to — but this kit's own error
   message shows somebody already met that shape once, and the interaction has not been tested.

---

## 12 · The sentence this document exists to make unavailable

> *"We have provenance."*

The kit has a registry round trip that is genuinely evidence, a build discipline that makes the
scanned and pushed artefact the same bytes, a digest-bound deploy that refuses mutable tags, and an
honest stamp that says `NOT_ESTABLISHED` where it cannot claim more. That is more than most
pipelines have and it was clearly hard-won.

It has no signature, no verifier, and no failure mode on the provenance path. Nothing outside the
run that produced a claim can check it. Until something can, the correct sentence is:

> *"We establish artefact identity inside the build and we deploy by digest. We do not attest, and
> nothing verifies."*

---

> **Neutralisation note.** This document originally named a consumer estate's repositories and
> products. Those names are denied from the neutral core by `scripts/export-deny.txt`, and the
> remedy is substitution rather than deletion: the meaning is preserved and the identity is not.
> Where a specific repository mattered to an argument, it now reads as **the reference estate** --
> the estate this kit is qualified against, whose own assessment lives in
> a consumer overlay's `docs/` folder. Nothing about the findings changed.
