# MOD-SELF-HOSTED-RUNNER — jobs on self-hosted or private-network runners

```
Truth State: Authored, not field-tested (2026-11-03; stated by intent 2026-11-04). One page. Tick only
             from evidence you saw; otherwise label the line Stated or Not established (../SIGN-OFF.md).
```

- [ ] Which jobs run there (`runner_label` on the deploy reusables; `KIT_FEED_MIRROR_RUNNER` for the
      scan jobs that read the feed mirror) and why.
- [ ] Runners are ephemeral (one job per runner), patched, and not shared with untrusted repositories.
- [ ] A platform-hosted runner joined to a private network is preferred over a self-hosted one; a
      public endpoint instead is only a recorded, time-boxed exception
      (`docs/architecture/LZ_KIT_SEAM_CONTRACT.md`, "The lease store's network"):

      | Azure | AWS | GitHub | Other cloud: how to find the equivalent |
      |---|---|---|---|
      | a GitHub-hosted larger runner with Azure private networking | a runner inside the account's VPC (self-hosted or a managed fleet), reaching AWS APIs through VPC endpoints | the organisation's runner groups and which repositories may use them | the CI provider's private-network runners, or runners on the cloud's own network with private service endpoints |
- [ ] The runner's network reaches only what it needs (the lease store, the feed mirror, the target).
- [ ] A green security run on this runner exists: the kit's hosted-runner assumptions (tool versions,
      images) must be re-proven there.
- [ ] Who administers the runners (the platform: E1), and who can read their logs.
