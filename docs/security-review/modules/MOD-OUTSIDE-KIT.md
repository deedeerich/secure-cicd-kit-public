# MOD-OUTSIDE-KIT — hosting with no kit deploy adapter (code-packaged Functions, AKS, VMs, other)

```
Truth State: Authored, not field-tested (2026-11-03). One page. Tick only from evidence you saw;
             otherwise label the line Stated or Not established (../SIGN-OFF.md).
```

- [ ] The repository still runs the kit's security caller (`MOD-BASE`): the scan covers the code, and
      the gate names the gap (`no_kit_adapter`: `NO_KIT_ADAPTER:aks`, `:vm`, `:function_app_code`).
      A Functions app hosted as a container is NOT outside the kit: `MOD-CONTAINER`.
- [ ] The deploy is **outside the kit**: none of the kit's deploy gates (verdict before login, digest
      binding, approval bound to digest, readiness, rollback) apply. The sign-off says deployment
      governance is not established by the kit.
- [ ] How the deploy reads the security verdict, if at all (S8).
- [ ] Who approves production releases, and whether the author can approve their own (S6).
- [ ] The deploy identity's scope (E3 if wider than the one workload).
- [ ] What artefact is deployed, and how it is tied to what was scanned (a digest, a signature).
- [ ] How a bad release is reversed, and whether that has been done.
- [ ] The missing adapter is recorded as a named gap for the kit maintainers (E10), not as coverage;
      the adapter plan and its size are `docs/KNOWN_DEFECTS.md` D-13.
