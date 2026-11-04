# Security review checklist — one CAB change to cloud or apps

```
Authored, not field-tested (2026-11-03). One per change. Mirrors CAB-CHANGE-SAFETY-STEPS.md line by
line: each line cites its step. Required reviewer: AppSec (the application security role). This is the
security review of the change, not CAB process.
"Security reviewed" or "LGTM" on its own is NOT an accepted security sign-off. The CAB ticket gets the
paste block at the end: outcome, understanding, evidence, open questions.
A tick counts only with its source: a run link, a file@commit, a portal/console view, a command
output, a ticket, or "asked <role>: <answer>".
```

**CAB ticket:** ________  **Change type:** ☐ app ☐ cloud ☐ both  **Environment:** ☐ dev ☐ test ☐ uat ☐ prod
**Platform:** ☐ Azure commercial ☐ Azure Gov ☐ AWS ☐ GitHub  **App type:** ________  **Data class:** ☐ public ☐ internal ☐ confidential ☐ regulated
**Artefact (1.7):** repo ________ commit ________ digest ________
**Requester / author / release approver (1.8):** ________ / ________ / ________ (three different people)

## A · Understanding gate — in your own words, before any tick (step 1)

Blank, or "N/A" without a reason, makes this review **not valid**. Can't fill a line? Stop and ask
(S-row below); still can't? Outcome "Not reviewed — outside my knowledge".

| | Line | Your words (1–2 lines) |
|---|---|---|
| 1.1 | What is changing | |
| 1.2 | What the app or system does | |
| 1.3 | Where it runs (platform, environment) | |
| 1.4 | What data it touches | |
| 1.5 | Who and what can reach it (auth, exposure) | |
| 1.6 | What breaks if it goes wrong | |

## B · The four opening questions (step 2) — any yes or unknown = FULL review; all no = DELTA

Each line: the answer, and where you confirmed it. The conversation guide is in the steps doc.

☐ **Data** — asked "what data does this touch, and is any of it new, stored, sent or kept somewhere new?" (DB-1..6) Answer + confirmed in: ________
☐ **Security controls** — asked "does this change network, encryption, keys or logging, or switch any check off?" (SB-1..6) Answer + confirmed in: ________
☐ **Who and what can act** — asked "does this add an identity or role, widen access, add a trust or a secret?" (AB-1..7) Answer + confirmed in: ________
☐ **Exposure** — asked "who can reach this after the change; anything newly public, a new DNS name, a new third party?" (XB-1..3) Answer + confirmed in: ________
Depth: ☐ full ☐ delta   Rows yes/unknown: ________

## C · App checks (step 3) — confirmed in the kit run summary

☐ **3A** Asked which commit and which run — run link, commit matches, evidence not expired; kit pinned by SHA (3.1, 3.12): ________
☐ **3B** Asked what the scan said — `routing_result` ____, every advisory cause explained, nothing unavailable/partial unanswered, floor `HELD` (3.2, 3.3): ________
☐ **3C** Asked what's switched off or excepted, who decided, who owns it, when it ends — **the requester did not approve their own exception** (3.4, 3.5): ________
☐ **3D** Asked about known-exploited CVEs, malicious packages, secrets and rotation — KEV `CLEAR`, `secret_gate` `PASS`, SBOM kept (3.6, 3.7, 3.8): ________
☐ **3E** Asked who approves the release and whether the approval quotes the digest — approver ≠ requester ≠ author; deploy reads the gate's verdict (3.9, 3.10, 3.11): ________
☐ **3F** Asked how the app checks callers and what goes in logs — labelled Read / Stated / routed: ________

Stop and ask if: you didn't open the run summary yourself; a word means nothing to you (S2, S3, S8, S16). Broader conversation if: an exception has no owner (E8); the run says something the code can't mean (E10).

## D · Cloud checks (step 4) — per conversation, the platforms it touches; N/A needs a reason

☐ **4.0** Asked "did anything else change on these resources?" — change history matches the ticket: ________
☐ **4A Who can reach it** — Azure Z2/Z3/Z4 ____ · AWS W3/W4 ____ · GitHub H1/H3 ____
☐ **4B Who gets access, how much** — Azure Z1/Z9/Z10/Z11 ____ · AWS W1/W2 ____ · GitHub H2/H5/H6/H7 ____
☐ **4C Secrets and keys** — Azure Z12/Z5/Z4 ____ · AWS W9/W6/W5 ____ · GitHub H4 ____
☐ **4D Where the data goes** — Azure Z4/Z6 ____ · AWS W4/W5 ____ · GitHub H6 ____
☐ **4E Will we still see it** — Azure Z6/Z7/Z8 ____ · AWS W7/W11 ____ · GitHub H8 ____
☐ **4F Does the app check callers** — Azure Z13 ____ · AWS W8/W10 ____
☐ **4G New names or outside parties** — Azure Z14/Z10 ____ · AWS W12/W2 ____ · GitHub H6 ____
Platforms not touched: Azure ☐ N/A because ____ · AWS ☐ N/A because ____ · GitHub ☐ N/A because ____

Stop and ask if: you can't run or read a check — ask the platform team to show you (S1). Broader conversation if: a new identity or trust (E3); new internet exposure (E1); a new platform, subscription, account or tenant (E1); a shared edge entry (E1); regulated data moves (E6).

## E · Pipeline and evidence (step 5)

☐ 5.1 the change doesn't edit its own gate ☐ 5.2 requester approves nothing ☐ 5.3 every claim has a link ☐ 5.4 ticket ↔ PR ↔ runs linked ☐ 5.5 evidence attached — sources: ________
Stop and ask if: the only evidence is "it's the same as before". Broader conversation if: an agent or automation acts on systems on its own (E9).

## F · Rollback (step 6)

☐ 6.1 trigger + owner role ☐ 6.2 reversal available, e2e set ☐ 6.3 irreversible parts named and accepted ☐ 6.4 platform change reverted too ☐ 6.5 shared entries left to the platform — sources: ________

## G · Triggers met — record any that fired

Stop and ask (`STOP-AND-ASK.md`): ☐ an understanding line blank ☐ S____ : ________
Broader conversation (`ESCALATE-BROADER.md`): ☐ new data class (E4/E6) ☐ new identity or trust (E3) ☐ new internet exposure (E1) ☐ new platform or tenant (E1) ☐ architecture change (security lead) ☐ unowned exception (E8) ☐ "I don't know what this component is" (route it) ☐ incident signs (E7, at once) ☐ E____ : ________

**Signs you're rubber-stamping** — if any is true, stop and fix it before choosing an outcome:
☐ you didn't open the run summary ☐ you can't name the data ☐ you're relying on "it's the same as before" ☐ the requester answered the questions for you ☐ time pressure is the reason to approve ☐ you ticked a box with no source ☐ you don't know what a component in the diff is

## H · Outcome (step 7) — choose one; the typed outcome is the verdict

☐ Approve ☐ Approve with conditions ☐ Reject ☐ Needs more info
☐ **Not reviewed — outside my knowledge, routed to** ________ ☐ **Paused — broader conversation opened (E____)**
The last two are correct, respectable outcomes, not failures.

| Condition | Owner (role) | Expiry / due | Evidence that closes it |
|---|---|---|---|
| | | | |

Open questions: ____________________________________________

**Sign-off:** I understood what this change does, I looked at the evidence listed, and the open questions are listed above.
Reviewer role: ________ (AppSec)  Date: ________  Valid for: the commit and digest above only.

---

## Paste into the CAB ticket comment

```
SECURITY REVIEW — <CAB ticket> — <date> — reviewer: <role, AppSec>
Outcome:        <Approve | Approve with conditions | Reject | Needs more info |
                 Not reviewed — outside my knowledge, routed to <role> | Paused — broader conversation opened (E<n>)>
Understanding:  changing <1.1>; the system <1.2>; runs on <1.3>; data <1.4>; reachable by <1.5>; if it fails <1.6>
Scope:          <repo>@<sha>, <digest>; <environments>; review depth <full | delta>; boundaries <rows | none>
Evidence:       security run <link>; build run <link>; deploy run <link | at release>; plan <link>;
                cloud checks <ids with source>; asked <role>: <answer>
Verdict data:   routing_result <value>; advisory_causes <list>; exceptions <finding/owner/approver/expiry | none>
Conditions:     <condition — owner role — expiry — closing evidence> | none
Open questions: <list> | none
Rollback:       trigger <...>; owner <role>; irreversible <list | none>
Valid for:      the commit and digest above only. "Security reviewed" without this block is not a security sign-off.
```
