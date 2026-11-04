# MOD-AGENT — AI or code acting on systems on its own

```
Truth State: Authored, not field-tested (2026-11-03). One page. Tick only from evidence you saw;
             otherwise label the line Stated or Not established (../SIGN-OFF.md).
```

- [ ] **Escalated first (E9)** to the AI agent governance owner. The agent governance harness, not
      this review, decides what the agent may do.
- [ ] Every system the agent can write to (repositories, trackers, cloud, chat, other apps) is listed,
      with the token or identity it uses for each and its scope.
- [ ] No agent approves or merges its own change, or approves a release. `ai_review` in
      `deploy_approval` is advisory only: never a gate, never an approval.
- [ ] No agent holds a token that can change branch protection, environments, the policy register,
      `KIT_ZONE_READINESS` or `KIT_ENVIRONMENT_TIER`.
- [ ] Every action the agent takes is logged where a person can read it, with the agent named.
- [ ] A human owner role is accountable for the agent and can switch it off.
- [ ] The kit scans the agent's code like any app (`MOD-BASE`); it does not observe what the agent does
      at runtime. Runtime claims are Stated unless the governance harness shows them.
