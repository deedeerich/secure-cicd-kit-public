# MOD-SELF-HOSTED-RUNNER — jobs on self-hosted or private-network runners

```
Truth State: Authored, not field-tested (2026-11-03). One page. Tick only from evidence you saw;
             otherwise label the line Stated or Not established (../SIGN-OFF.md).
```

- [ ] Which jobs run there (`runner_label` on the deploy reusables; `KIT_FEED_MIRROR_RUNNER` for the
      scan jobs that read the feed mirror) and why.
- [ ] Runners are ephemeral (one job per runner), patched, and not shared with untrusted repositories.
- [ ] A GitHub-hosted larger runner with Azure private networking is preferred over a self-hosted one;
      a public endpoint instead is only a recorded, time-boxed exception
      (`docs/architecture/LZ_KIT_SEAM_CONTRACT.md`, "The lease store's network").
- [ ] The runner's network reaches only what it needs (the lease store, the feed mirror, the target).
- [ ] A green security run on this runner exists: the kit's hosted-runner assumptions (tool versions,
      images) must be re-proven there.
- [ ] Who administers the runners (the platform: E1), and who can read their logs.
