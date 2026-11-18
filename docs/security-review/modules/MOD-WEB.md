# MOD-WEB — a browser-facing app

```
Truth State: Authored, not field-tested (2026-11-03; stated by intent 2026-11-04). One page. Tick only
             from evidence you saw; otherwise label the line Stated or Not established (../SIGN-OFF.md).
```

- [ ] Exposure recorded: internet-facing or internal, and behind which edge (a front door or CDN such
      as Front Door or CloudFront, a gateway). Edge routes, WAF rules and DNS records are the landing
      zone's (E1).
- [ ] SAST ran on every language present (`sast-semgrep`, with `p/php` or `p/kotlin` where found; the
      `codeql` legs; the language jobs); no row `PARTIAL` without an answer.
- [ ] `deps-scan` read a lockfile for every Node and PHP root: no open `PHPDependenciesUnlocked` or
      missing Node lockfile.
- [ ] `malicious-deps` ran (it always does; switching it off is refused).
- [ ] At promotion, the security-settings posture read back from the live target holds (HTTPS-only,
      TLS 1.2+, no plain FTP, no remote debugging): `POSTURE_PASSED`, never `POSTURE_UNREADABLE`.
- [ ] DAST where configured (`KIT_DAST_COMMAND`): `DAST_PASSED`; `DAST_INCOMPLETE` is not a pass.
      Active DAST is refused at prod (`DAST_REFUSED_PRODUCTION_TARGET`) and runs in the predecessor.
- [ ] Who signs users in (platform auth, the app, a third party: `MOD-THIRD-PARTY` if new). The kit
      does not test authentication or sessions: label these Read or Stated.
- [ ] With `KIT_EDGE_ENDPOINT` vended, a verified release purges only the app's own endpoint
      (`EDGE_PURGED`); `EDGE_PURGE_FAILED` is an advisory to note.
- [ ] For a CAB change: a new public endpoint, DNS record or ingress is an exposure boundary (rows
      XB-1, XB-2 of `../CAB-CHANGE-SAFETY-STEPS.md` step 2): public access (C4), caller checks (C14) and
      DNS (C15) in `../CLOUD-CHECKS.md`:

      | Azure | AWS | GitHub | Other cloud: how to find the equivalent |
      |---|---|---|---|
      | C4 (was Z4), C14 (was Z13), C15 (was Z14) | C4 (was W4), C14 (was W8, W10), C15 (was W12) | Pages custom domains, if used (C15) | the public-access switch, the built-in authentication and the DNS zone of whatever serves the site |
