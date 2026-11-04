# MOD-THIRD-PARTY — a new third party

```
Truth State: Authored, not field-tested (2026-11-03). One page. Tick only from evidence you saw;
             otherwise label the line Stated or Not established (../SIGN-OFF.md).
```

- [ ] What it is: a SaaS, an external API, a vendor GitHub action, a container image, a feed.
- [ ] **Escalated (E5)** to third-party / vendor risk; the third party stays out of the sign-off until
      cleared.
- [ ] What data it sees and what it can change (E4 and E3 as they apply).
- [ ] A vendor action is pinned to a 40-hex SHA unless its owner is in `trusted_orgs` (note the list).
- [ ] A vendor image is pinned by digest and scanned (`image_ref` for the security run, or the build's
      Trivy gate).
- [ ] The app's credential for it: scope, rotation, where it is stored (never the repository).
- [ ] What happens when it is down: the app fails closed or degrades visibly (Stated unless tested).
- [ ] For a CAB change it is row XB-3, a full review: consent or app installation read (Z10 in
      `../CLOUD-CHECKS-AZURE.md`, W2 in `../CLOUD-CHECKS-AWS.md`, H6 in `../CLOUD-CHECKS-GITHUB.md`).
