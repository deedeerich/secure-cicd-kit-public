# MOD-STATIC-SITE — a static site (the kit releases Azure Static Web Apps; elsewhere see the table)

```
Truth State: Authored, not field-tested (2026-11-03; stated by intent 2026-11-04). One page. Tick only
             from evidence you saw; otherwise label the line Stated or Not established (../SIGN-OFF.md).
```

**Where the kit releases it.** A static site is released by the kit only as an Azure Static Web Apps
site. The intent of every line below holds on any platform; where the kit does not release the site,
it is also `MOD-OUTSIDE-KIT`.

| Azure | AWS | GitHub | Other cloud: how to find the equivalent |
|---|---|---|---|
| Static Web Apps: released by the kit (`reusable-deploy-staticwebapp.yml`) | S3 with CloudFront, or Amplify Hosting: outside the kit (`MOD-OUTSIDE-KIT`) | Pages: outside the kit | the provider's static hosting: outside the kit |

- [ ] **The content released is the content packaged.** Kit: packaged by
      `.github/actions/static-site-package` (the `kit-release.json` marker and `site_digest`) and
      deployed by `reusable-deploy-staticwebapp.yml`: identity `CONTENT_DIGEST_PROVEN` before login;
      `SITE_DIGEST_MISMATCH` refuses. Elsewhere: ask how the uploaded files are tied to the scanned
      build (a digest, a signed manifest).
- [ ] **Staged before it serves users.** Kit: a preview environment first; `preview_environment: ''`
      is refused at uat/prod. Elsewhere: a staging bucket, branch or environment, and who promotes it.
- [ ] **Nothing deploys around the release path.** Kit: the site is **not linked to a repository** (its
      own generated workflow could deploy around the kit, and the posture check fails it), and is not
      on the Free plan. Elsewhere: no second pipeline, sync job or console upload can publish to it.
- [ ] **It can be put back.** Kit: the artefact's `retention-days` is at least as long as a release may
      stand: an expired one makes rollback `UNAVAILABLE`, refused at uat/prod. Elsewhere: versioning on
      the bucket or the previous build kept, and a tested way back.
- [ ] The kit's static-site adapter is proven against the stub cloud only; a live run is owed. Label
      deploy claims accordingly.
