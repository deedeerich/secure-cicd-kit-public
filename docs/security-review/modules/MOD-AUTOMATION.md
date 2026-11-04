# MOD-AUTOMATION — an automation built in Tines 3B, or on another automation platform

```
Truth State: Authored, not field-tested (2026-11-03). One page. Tick only from evidence you saw;
             otherwise label the line Stated or Not established (../SIGN-OFF.md).
```

- [ ] Where its code lives. If it is synced to a repository (for example by GitSync), that repository
      runs the kit's security caller (`MOD-BASE`).
- [ ] Server-side pushes run no local hook, so the repository carries the push ruleset
      (`developer-safety/branch-protection/push-ruleset-secret-files.json`) and push protection where
      licensed (`docs/adoption/LEAK_GATES.md`): `leak_gates` shows the push ruleset `ON`.
- [ ] Its credentials live in the platform's credential store, never in the synced code
      (`secret_gate` `PASS`). Each credential is listed with its scope (E3 if wider than needed).
- [ ] Each system it calls or changes is listed (E4 for data flows, E5 for a new third party).
- [ ] If it creates, changes or deletes on its own without a person approving each action, it is also
      `MOD-AGENT`, and E9.
- [ ] The kit does not see the automation's runtime or run history: those claims are Stated unless the
      platform's own audit log shows them. What to obtain, and from which role: `../OBTAIN-SEPARATELY.md`
      (G11).
- [ ] If it calls the kit's API (a dispatch of the repository's `kit-api.yml`; `docs/api/README.md`),
      the token it dispatches with is the requester of every release and ticket it asks for: list
      that token's scope, and check it cannot also approve the release (S6).
- [ ] A change to the automation takes the same CAB class as any app change
      (`../CAB-AND-ADOPTION-REVIEW.md` step 3).
