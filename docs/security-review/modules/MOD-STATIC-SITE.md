# MOD-STATIC-SITE — an Azure Static Web Apps site

```
Truth State: Authored, not field-tested (2026-11-03). One page. Tick only from evidence you saw;
             otherwise label the line Stated or Not established (../SIGN-OFF.md).
```

- [ ] Packaged by `.github/actions/static-site-package`: the `kit-release.json` marker and `site_digest`.
- [ ] Deployed by `reusable-deploy-staticwebapp.yml`: identity `CONTENT_DIGEST_PROVEN` before login;
      `SITE_DIGEST_MISMATCH` refuses.
- [ ] Staged in a preview environment first; `preview_environment: ''` is refused at uat/prod.
- [ ] The site is **not linked to a repository** (its own generated workflow could deploy around the
      kit, and the posture check fails it), and is not on the Free plan.
- [ ] The artefact's `retention-days` is at least as long as a release may stand: an expired one makes
      rollback `UNAVAILABLE`, refused at uat/prod.
- [ ] This adapter is proven against the stub cloud only; a live run is owed. Label deploy claims
      accordingly.
