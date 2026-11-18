# Escalate — this is a different or broader conversation, not an app review

```
Truth State:  Authored, not field-tested (2026-11-03; cloud-neutral wording 2026-11-04).
Use when:     the answer belongs to someone other than the app team, or the issue is bigger than
              this one app. Hand it over by ROLE (never by a person's name), record the hand-off, and
              continue or pause as the row says.
```

## How to hand over

1. Write a short hand-off note: the app, the run id(s), the signal, what you saw, what you need
   decided, and by when. Attach the evidence (or its links).
2. Send it to the role in the table. If you do not know who holds the role, ask the app owner and
   the security lead; do not guess.
3. In the app review record, write: "Escalated to <role> on <date>: <one line>. Review
   continues / pauses on <item>." Sign-off later lists it as **handed off**, never as reviewed.

| # | Signal | Goes to (role) | Hand over | Review |
|---|---|---|---|---|
| E1 | **Platform or landing-zone ownership** (on any cloud): who vends the target, its network or its identity; a new subscription, account, project or tenant; `KIT_RELEASE_BLOCK`, `KIT_ZONE_READINESS`, `KIT_HANDOFF_ISSUER` or `KIT_TARGET_LEASE_ACCOUNT` not vended (`tier_source` `TIER_SELF_DECLARED`, `readiness_source` other than `READINESS_SOURCE_LZ_HANDOFF` where a landing zone should vend); shared edge entries (an edge or CDN front door, DNS, WAF, network security rules, firewall); `SEAM_OWNERSHIP_NOT_IN_FORCE` where the platform owns the fix | the platform / landing-zone owner | the hand-off variables found and missing, the deploy summary, `docs/architecture/LZ_KIT_SEAM_CONTRACT.md` | continues; the deploy-governance claim waits |
| E2 | **Organisation licensing or plan**: code scanning or secret scanning `UNAVAILABLE`, push protection off for want of a licence, push rulesets refused (422), `ATTESTATION_HELD_BY_PLAN`, no private-network runners | the GitHub organisation owner, with the budget owner | the platform capability rows, `leak_gates`, the attestation outcome | continues; record the gap as a platform limit |
| E3 | **Identity architecture**: a deploy identity wider than one app; anything at subscription, account or project scope (on Azure `Contributor`, `Owner` or `User Access Administrator`; on AWS an administrator or `iam:*` policy; the equivalent elsewhere); a long-lived secret or cloud key; standing human privilege; a shared identity across tools; a trust across tenants or accounts | the identity / access architecture owner | the role assignments or policies seen, the federation subjects or trust policies, the boundary probe output where one exists (`verify-azure-oidc.yml` on Azure) | **pauses** on section 5 and the deploy path |
| E4 | **A cross-team data flow**: the app sends or receives data from another team's system or store | the data owner(s) of both sides, with privacy / data protection | the data classes, the direction, the interface | continues on the rest |
| E5 | **A new third party**: a SaaS, external API, new feed host, vendor action or image not used before | third-party / vendor risk | what it is, what data it sees, what it can change | continues; the third party is excluded from sign-off until cleared |
| E6 | **A regulatory scope change**: new regulated data, a new jurisdiction, or an app newly in an audit scope | compliance / GRC | what changed and since when | **pauses** sign-off |
| E7 | **An incident or suspected compromise**: a secret that reached the remote with any sign of use; `MIRROR_INTEGRITY_FAILED`; `ATTESTATION_CONTRADICTED`; `EXCEPTION_HISTORY_TAMPERED`; a serving digest no kit run explains; `MUTATED_WITHOUT_LEASE` | **incident response**, not review | everything you have, unedited, at once. Do not wait to finish the review | **pauses**. Resume only when incident response says so |
| E8 | **A policy exception beyond your authority**: raising `max_exception_renewals`, softening deploy approval, anything below crawl (refused by the kit: `CHERRY_PICK_BELOW_FLOOR`), a register change at org or enterprise scope, a break-glass release | the policy register's authority (the security policy owner, or the delegate the register names) | the request, its reason, the register entry it would change | pauses on that item |
| E9 | **AI agents acting on systems**: an agent with a token that writes to the repository, tracker, cloud or another system; an agent approving or merging. (`ai_review` in `deploy_approval` is advisory only: never a gate or an approval) | the AI agent governance owner (the agent governance harness, for example an agent control plane) | which agent, which tokens, which actions, who is accountable | continues on the app; the agent part is out of scope until governed |
| E10 | **A kit defect**: the run says something the code cannot mean, a silence where the kit should speak, a word not in `assurance-taxonomy.yaml`, a `NO_KIT_ADAPTER:<kind>` the app needs an adapter for (KNOWN_DEFECTS D-13) | the kit maintainers | the run id and the exact line | continues; mark the affected item not established |

## Rules

- **An incident is never reviewed.** E7 goes to incident response the moment you see it.
- **Escalating is not failing the app.** It names the right owner. The app review states what it
  could and could not cover.
- **Do not trade.** An escalated item is not closed by the app team agreeing to something; it is
  closed by the role it went to.
- For a CAB change or an adoption approval, an open E-item blocks sign-off unless the role it went
  to has answered, or the approver records it as a condition
  ([`CAB-AND-ADOPTION-REVIEW.md`](CAB-AND-ADOPTION-REVIEW.md), step 5). An open E6 or E7 blocks it
  outright. Which modules an app needs: [`APPROVAL-MATRIX.md`](APPROVAL-MATRIX.md).
- An emergency change still gets a retrospective review within 5 working days (OWNER DECISION: the
  number; 5 is the default until set). See `modules/MOD-EMERGENCY-CHANGE.md`.
