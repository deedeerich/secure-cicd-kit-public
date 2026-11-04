# MOD-API — an API, an integration or connector, or an app other services call

```
Truth State: Authored, not field-tested (2026-11-03). One page. Tick only from evidence you saw;
             otherwise label the line Stated or Not established (../SIGN-OFF.md).
```

- [ ] Every caller is recorded: users, internal services, partners, the internet.
- [ ] How callers authenticate (tokens, managed identity, keys). A shared or long-lived key is E3.
- [ ] What it can change downstream: only its own data, or other teams' systems (E4 for a data flow,
      E3 for privilege beyond its own target).
- [ ] The same scanner evidence as `MOD-WEB`: SAST per language, `deps-scan`, `malicious-deps`.
- [ ] Keys and connection strings it needs live in configuration the landing zone owns, or as Key
      Vault references, never in the repository (`secret_gate` `PASS`).
- [ ] An integration or connector: the other system's owner knows and agrees (E4), and the
      connector's own credentials are listed with their scope.
- [ ] Rate limits, input validation and per-operation authorisation are not tested by the kit: label
      them Read or Stated, and say so in the sign-off.
- [ ] For a CAB change that adds or changes a route or its authentication (row AB-7): every new route
      has an authorizer or is named public on the ticket (Z13 in `../CLOUD-CHECKS-AZURE.md`; W8, W10
      in `../CLOUD-CHECKS-AWS.md`).
