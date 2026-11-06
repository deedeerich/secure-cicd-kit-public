# MOD-DATA — confidential or regulated data, or a cross-team data flow

```
Truth State: Authored, not field-tested (2026-11-03; stated by intent 2026-11-04). One page. Tick only
             from evidence you saw; otherwise label the line Stated or Not established (../SIGN-OFF.md).
```

- [ ] The data classes are listed, with where they are stored and where they go.
- [ ] Each flow to or from another team's system has that system's data owner's agreement (E4).
- [ ] Regulated data, a new jurisdiction or a new audit scope is E6, which pauses sign-off.
- [ ] Data-store secrets are references to the platform's secret store, or the store is reached by
      the app's own platform identity (a managed identity, an IAM role, or the equivalent) owned by the
      landing zone; none in the repository (`secret_gate` `PASS`).
- [ ] The app's identity reaches only its own data stores (E3 if wider).
- [ ] A database change says whether it can be rolled back or is forward-fix only
      (`ROLLBACK_PROHIBITED`); the CAB record carries the answer.
- [ ] Logs do not carry the sensitive data. The kit does not test this: label it Read or Stated.
- [ ] For a CAB change: the data boundary rows DB-1..DB-6 of `../CAB-CHANGE-SAFETY-STEPS.md` step 2
      answered (a new class, store, flow, recipient, retention or residency is a full review), and
      the store's settings read: public access, region and retention (C4), encryption key (C5), log
      retention (C7) in `../CLOUD-CHECKS.md`:

      | Azure | AWS | GitHub | Other cloud: how to find the equivalent |
      |---|---|---|---|
      | C4 (was Z4), C7 (was Z6) | C4 (was W4), C5 (was W5) | usually N/A | the store's public-access setting, region, lifecycle rules, encryption key and log export |
