# MOD-CONTAINER — an image built once and deployed by digest (App Service, Container Apps, Functions as a container)

```
Truth State: Authored, not field-tested (2026-11-03). One page. Tick only from evidence you saw;
             otherwise label the line Stated or Not established (../SIGN-OFF.md).
```

- [ ] The image is built by `reusable-build-docker.yml`: Trivy gate before push, SBOM, push, digest
      read back; `artifact_identity` `REGISTRY_IDENTITY_PROVEN`.
- [ ] The build's `image_digest` is the digest deployed (`@sha256:`, rule R7).
- [ ] The image's secret scan found nothing (an image secret is never excepted).
- [ ] `sbom_sha256` recorded and the `sbom` artifact kept (90 days).
- [ ] `hadolint` ran on the Dockerfile (`iac-scan`); the base image is pinned by digest
      (`build_inputs` records it).
- [ ] The build identity holds `AcrPush` only; the deploy identity holds no registry role; the app's
      own managed identity holds `AcrPull`.
- [ ] Attestation: `attestation_url` from the build; at deploy `ATTESTATION_VERIFIED`, or the reason
      it is not (`ATTESTATION_HELD_BY_PLAN`: E2; `ATTESTATION_ABSENT`: S15).
- [ ] The daily deployed scan (`reusable-deployed-scan.yml`) is wired: it reports artifact drift and
      security drift of what actually serves.
