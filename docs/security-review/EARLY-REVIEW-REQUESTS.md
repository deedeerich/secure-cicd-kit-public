# Pulled in before the CAB presentation: what the security reviewer asks for

```
Truth State:  Authored, not field-tested (2026-11-03).
The problem:  a security reviewer is brought in early, by chat, a meeting or a hallway question,
              before the change has a CAB presentation. The conversation shapes the change, and later
              it is quoted as "security already looked at this" with nothing behind it.
This sheet:   what the reviewer asks the requester for before engaging, what the reviewer may say at
              that stage, how the reviewer records it on the CAB ticket, and when to stop for a
              broader conversation. It is the reviewer's own practice. It does not define CAB intake
              or any CAB step; the review itself is CAB-CHANGE-SAFETY-STEPS.md.
```

## 1 · What to ask for before engaging

Ask for these, in writing. They are the inputs the security review needs; until they exist you can
listen, but there is nothing yet to review.

| # | Ask for | Enough when |
|---|---|---|
| 1 | **What changes**, in two or three sentences | you could write the understanding lines 1.1 and 1.2 of the review from it |
| 2 | **Why, and why now** | the urgency is stated, not implied |
| 3 | **The boundaries touched**: data, security, auth, exposure (the triage rows of step 2), each yes, no or unknown | every row answered; unknown is allowed and counts as yes |
| 4 | **Where it runs**: platform and environments, and which serve real users | named, not "all" |
| 5 | **The rollback**: how it is backed out, by whom, and what cannot be undone | a trigger, an owner role, the irreversible parts |
| 6 | **The evidence links**: the pull request or design, the CAB ticket if one exists, a security run if code exists, the IaC plan if infrastructure changes | links, not descriptions; "none yet" is an honest answer |

Copy-paste for the requester:

```
For the security review
1 What changes:
2 Why, and why now:
3 Boundaries (yes / no / unknown):
  data: new class / store / flow / recipient / retention / residency
  security: network exposure / firewall-SG-NSG-WAF / encryption / keys / logging reduced / scanner or gate weakened
  auth: new identity / role or permission / trust policy / cross-account or tenant / MFA-CA / secret / API auth
  exposure: public endpoint / DNS record / new third party
4 Platform and environments:
5 Rollback (trigger, owner, what cannot be undone):
6 Links (PR or design, CAB ticket, security run, IaC plan):
```

## 2 · What the reviewer may say at this stage

**Early guidance only. Never approval.** There is no commit, digest, run or plan to review yet;
anything said is about a design.

You may say: which boundary rows the design touches and so whether it will be a full or delta review;
the evidence the security review will need, so the team produces it once; the stop conditions the
design already hits ("a function URL with auth `NONE` will be a stop", "a managed identity at
subscription scope will be a stop", "the requester cannot approve their own exception") and the usual
way around each; and which other roles must be involved (`ESCALATE-BROADER.md`).

You may not say, or let be recorded as said: "security approves", "no security concerns",
"security reviewed" — about a change that does not exist yet as an artefact; an exception, weakening
or readiness value granted in conversation (those exist only in the policy register, the weakening
record or an AppSec attestation, approved by someone other than the requester); or a decision that
belongs to another role.

## 3 · Record it on the CAB ticket

Nothing you said early should exist only in a chat. Post a note on the CAB ticket the same day; if
there is no ticket yet, send the note to the requester in writing, keep your own copy, and add it to
the ticket when it appears, with its original date. The later review starts from it, and any
difference between the note and the actual diff is called out in the security verdict.

```
Early security guidance — <date> — reviewer: <role>
Status:      EARLY GUIDANCE ONLY. Not a security review, not an approval. No artefact was reviewed.
Asked by:    <requester role>, via <chat | meeting | email> on <date>
As described: <one or two sentences>
Received:    1 <y/n> 2 <y/n> 3 <y/n> 4 <y/n> 5 <y/n> 6 <y/n>
Boundaries:  <rows yes or unknown> -> expected review depth <full | delta>
Guidance:    <each point, one line>
Stops already visible: <list | none>
The review will need: <security run on the commit; plan; cloud checks <ids>; rollback with trigger and owner; ...>
Other roles: <E-number and role | none>
```

## 4 · When to stop for a broader conversation

| Situation | Say | Then |
|---|---|---|
| Nothing to review yet after one ask | "Send the six items and I'll look." | note it, with what is missing |
| A decision is wanted now ("can we just open the port", "can I approve it myself this once") | "That needs the security review on evidence, not a yes in conversation." | note the request and the answer |
| A boundary only the platform, identity, data or vendor owner can answer | "This is a broader conversation first: it needs <role>." | the E-row: E1 platform, E3 identity, E4 data flow, E5 third party, E6 regulatory |
| Signs of an incident (a leaked secret, unexplained access, a resource nobody owns) | "This goes to incident response now." | E7, at once |
| An AI agent or automation acting on systems on its own | "The agent governance owner needs to see this first." | E9, `modules/MOD-AGENT.md` |
| A control lowered below the policy register, or a cap raised | "Only the register's authority can decide that." | E8 |
| A new platform, tenant or architecture, not one change | "This is bigger than one change review." | the security lead role; each resulting change still gets its own security review |
| You don't know what the component is | "I'm not the right reviewer for this part; <role> is." | route it; that is a correct answer, not a failure |
