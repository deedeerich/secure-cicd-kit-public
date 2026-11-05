# MOD-CONTAINER — an image built once and deployed by digest (the kit's container targets, or any registry and container runtime)

```
Truth State: Authored, not field-tested (2026-11-03; stated by intent 2026-11-04). One page. Tick only
             from evidence you saw; otherwise label the line Stated or Not established (../SIGN-OFF.md).
```

- [ ] The image is built by `reusable-build-docker.yml`: Trivy gate before push, SBOM, push, digest
      read back; `artifact_identity` `REGISTRY_IDENTITY_PROVEN`.
- [ ] The build's `image_digest` is the digest deployed (`@sha256:`, rule R7).
- [ ] The image's secret scan found nothing (an image secret is never excepted).
- [ ] `sbom_sha256` recorded and the `sbom` artifact kept (90 days).
- [ ] `hadolint` ran on the Dockerfile (`iac-scan`); the base image is pinned by digest
      (`build_inputs` records it).
- [ ] **Registry rights are split three ways:** the build identity can push to its own image
      repository and nothing else; the deploy identity holds no registry role; the running app pulls
      with its own identity. Where to read it (`../CLOUD-CHECKS.md` C1, C10):

      | Azure | AWS | GitHub | Other cloud: how to find the equivalent |
      |---|---|---|---|
      | build `AcrPush` (registry-wide), or `Container Registry Repository Writer` with a repository condition in an ABAC-mode registry; app's managed identity `AcrPull` (or `Container Registry Repository Reader`) | the build role's `ecr:PutImage` and layer-upload actions on one repository ARN; the task or function role's pull actions; the repository policy | a package's access settings and the workflow token's `packages` permission, when GitHub Packages is the registry | the registry's per-repository push and pull grants, and which identity the runtime pulls with |

- [ ] Attestation: `attestation_url` from the build; at deploy `ATTESTATION_VERIFIED`, or the reason
      it is not (`ATTESTATION_HELD_BY_PLAN`: E2; `ATTESTATION_ABSENT`: S15).
- [ ] The daily deployed scan (`reusable-deployed-scan.yml`) is wired: it reports artifact drift and
      security drift of what actually serves.
- [ ] The kit releases containers to Azure App Service, Container Apps and Functions as a container.
      A container runtime elsewhere (on AWS, or any other cloud) is scanned by the kit but deployed
      outside it: also `MOD-OUTSIDE-KIT`.
