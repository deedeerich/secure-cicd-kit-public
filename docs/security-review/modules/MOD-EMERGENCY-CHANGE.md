# MOD-EMERGENCY-CHANGE — a CAB emergency change

```
Truth State: Authored, not field-tested (2026-11-03; stated by intent 2026-11-04). One page. Tick only
             from evidence you saw; otherwise label the line Stated or Not established (../SIGN-OFF.md).
```

- [ ] What is broken or exposed, and why the normal path cannot wait. An incident goes to incident
      response first (E7); this module covers the change, not the incident.
- [ ] A security run on the emergency commit exists and its `routing_result` is recorded, even if the
      change proceeds. A secret or a known-malicious package still blocks.
- [ ] Released past the promotion gate only as `release_path: break-glass` with an attributed exception
      (reason, authority, exception reference, an expiry within 7 days); the record reads
      `BREAK_GLASS`; the deployed scan tickets the testing owed. Break-glass never passes a
      substitution, a non-default branch, an unverified signature or a revocation.
- [ ] A hotfix (`release_path: hotfix`) records its shorter test period.
- [ ] The approver is recorded, and is not the author.
- [ ] **Retrospective review** booked within **5 working days** (OWNER DECISION: the number; 5 is the
      default until the owner sets it): the security review of `../CAB-CHANGE-SAFETY-STEPS.md` (steps 1 to 8) on the
      released commit and digest, with step 4.0 reading the platform's change history from the
      emergency window, and every "temporary" opening checked closed (gotcha G1 in
      `../PRINCIPLES-AND-SOURCES.md`); an owner role and a date in the follow-up record.

**Cloud-neutral.** Every line here reads the kit's own run, the source-control platform or the
people involved; none depends on which cloud the app runs on. Cloud facts the change touches are
read through `../CLOUD-CHECKS.md` by intent, on whichever cloud it is.
