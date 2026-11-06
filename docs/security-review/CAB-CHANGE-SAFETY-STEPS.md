# Security review of a CAB change to cloud or apps — the reviewer's steps

```
Truth State:  Authored, not field-tested (2026-11-03). Written from the kit's documents and code on the
              trunk and from the sources in PRINCIPLES-AND-SOURCES.md; no reviewer has yet run a real
              change through these steps.
What this is: the SECURITY REVIEW a security reviewer performs on one change that is going to CAB: a
              change to an app, or to the cloud it runs on (any cloud: Azure, AWS or another), or to
              GitHub. It answers one question: is this change safe, and on what evidence?
What it is not: CAB. The organisation's CAB already exists, is well run, and has its own tickets,
              classes, meetings and process. Nothing here defines or changes any of that. The only
              place this review touches CAB is the end: the security verdict is written onto the
              existing CAB ticket (step 8).
Why it exists: so that "security reviewed it" is never said by someone who did not understand what
              they were reviewing, and so the reviewer knows when to ask a question and when to stop
              for a larger conversation.
Fill in:      CAB-CHANGE-REVIEW-CHECKLIST.md (one per change; it mirrors these steps line by line).
Pulled in early, before the CAB presentation exists?  EARLY-REVIEW-REQUESTS.md.
Why each check exists:  PRINCIPLES-AND-SOURCES.md (principle, source, the gotcha it catches).
Cloud commands:  CLOUD-CHECKS.md, keyed by what each check is for, with Azure, AWS, GitHub and
              "other cloud" columns (old Z/W/H ids kept as aliases). Every one is a read-only
              command or click path.
Owner decisions marked: OWNER DECISION, with the default these sheets use until decided.
```

This is written for a reviewer who may be new to a platform. The app and cloud checks (steps 2 to 4)
are **conversations**: for each one you get the question to ask in plain words, **why we ask**, what
**a good answer sounds like**, what to **worry about if you hear**, where to **then check** it yourself
(the kit's run summary, the cloud's console or CLI, GitHub's settings), and when
to **stop and ask** or open a **broader conversation**. The other steps say what to open, what to
check, and what safe, ask and stop look like. "Ask" means the requester can
answer with evidence (`STOP-AND-ASK.md`, S-numbers). "Stop" means you cannot recommend approval until
it is fixed, or a role other than the requester decides it (`ESCALATE-BROADER.md`, E-numbers).

**Evidence per tick.** Every check you mark done names what you actually looked at: a run summary
link, a file at a commit, a portal or console view, a command's output, a ticket, or the person you
asked and their answer. A tick without a source does not count. Label each answer Observed, Read,
Stated, Not established or Handed off (`SIGN-OFF.md`).

## The valid outcomes of a review

| Outcome | Means |
|---|---|
| **Approve** | the decision criteria of step 7 hold, on evidence you looked at |
| **Approve with conditions** | no stop holds; each remaining gap has an owner role, a due date and the evidence that closes it |
| **Reject** | a stop holds; the reason and what would change the answer are written down |
| **Needs more info** | an ask is open; the review resumes when the evidence arrives |
| **Not reviewed — outside my knowledge, routed to `<role>`** | you do not understand a component well enough to judge it, and you said so and named who can |
| **Paused — broader conversation opened (E`<n>`)** | the change is bigger than one change review, and it is with the right role |

**The last two are correct, respectable outcomes, not failures.** A reviewer who says "I don't know
what this component is, routed to the platform owner" has protected the organisation. A reviewer who
ticks it anyway has not. **A bare "security reviewed", "LGTM" or a thumbs-up on the CAB ticket is not a
security sign-off.** The ticket gets the outcome, the understanding, the evidence and the open
questions (step 8).

---

## Step 1 · Understand the change — before any check

**Open** the CAB ticket (summary, description, systems, environments, links), the linked pull
request(s) or commit(s), and the IaC plan if there is one.

**Write, in your own words, one or two lines each** (the checklist's understanding gate):

1.1 **What is changing.** One sentence you could explain to someone else.
1.2 **What the app or system does**, and for whom.
1.3 **Where it runs**: the platform (which cloud, and which of its partitions: commercial, or a
    sovereign or government cloud; and GitHub), the environment(s), and which serve real users.
1.4 **What data it touches**: the classes, and whether any is confidential or regulated.
1.5 **Who and what can reach it**: its authentication, and its exposure (internet, internal,
    partner, other services).
1.6 **What breaks if the change goes wrong**, and for whom.

Then the artefact and the people:

1.7 **The exact artefact**: repository, commit SHA(s), and for a release the image digest
    (`sha256:...`) or static-site `site_digest`. "Latest", a branch or a tag is not an artefact.
1.8 **The requester, the commit author(s), the release approver.** Write all three down; step 5
    checks they differ.

| Safe | Ask | Stop |
|---|---|---|
| every line written in your words; one commit and one digest; named environments; three distinct people | a line you cannot fill from what you were given: ask the requester for it (S-row in the checklist) | the requester is also the release approver or the exception approver |

**Triggers.** *Stop and ask if* you cannot write any of 1.1 to 1.6: a blank, or "N/A" with no reason,
makes the review **not valid**. *Stop — broader conversation if* the honest answer to 1.2 or 1.3 is "I
don't know what this component is" (route it: outcome "Not reviewed — outside my knowledge"), or the
change is a new platform, a new tenant or an architecture change rather than a change to an existing
one (E1, E3; security lead).

**Write down:** the six understanding lines, the artefact, the three names (by role on the ticket).

---

## Step 2 · Boundary triage — the four opening questions (full review or delta review)

**Open** the pull request diff (application code, `.github/workflows/`, IaC, configuration,
`.security/`) and the ticket's description of impact. Then have this conversation with the requester.
Four questions, one per boundary. You are listening for whether anything **new** crosses a line.

**Q1 — Data.** "What data does this touch, and is any of it new to this system? Does it get stored
somewhere new, sent somewhere new, kept longer, or moved to another region?"
- *Why we ask:* most serious incidents are about data ending up somewhere nobody planned for.
- *A good answer sounds like:* "Same customer table as today, no new fields, nothing leaves the app."
- *Worry if you hear:* "it's just logs" (logs often hold payloads), "the vendor only sees IDs" (check
  that), "we'll sort retention out later".

**Q2 — Security controls.** "Does this open, close or change anything on the network, encryption,
keys or logging? Does it switch any scanner or check off, even for a while?"
- *Why we ask:* controls are layered; quietly removing one layer is how the others end up carrying
  more than they were built for.
- *A good answer sounds like:* "No network or logging change; the pipeline is untouched."
- *Worry if you hear:* "it's just a quick firewall tweak", "we turned logging down to save money",
  "the scan was noisy so we narrowed it".

**Q3 — Who and what can act.** "Does this add a person, a service account, an app identity or a role,
or give an existing one more access? Does anything trust anything new: another account, another
tenant, a new pipeline? Any new secret?"
- *Why we ask:* access is where a small change becomes a big blast radius. A broad role given "to
  unblock the deploy" tends to stay forever.
- *A good answer sounds like:* "One new role assignment, read-only, on this one storage container."
- *Worry if you hear:* "we gave it Contributor so it would stop failing", "we'll tighten it later",
  "it uses the same account as the other app".

**Q4 — Exposure.** "Walk me through who can reach this after the change. Is anything newly open to the
internet, a new DNS name, a new third party?"
- *Why we ask:* something reachable from the internet is tested by strangers within hours, not months.
- *A good answer sounds like:* "Still internal only, behind the same gateway; no new hostname."
- *Worry if you hear:* "we'll add auth later", "it's only temporary", "nobody knows the URL".

Mark the rows behind each answer: yes, no, or unknown. **Unknown counts as yes** until the requester
shows otherwise. You will confirm the answers yourself in steps 3 and 4: an answer is a lead, not
evidence.

| # | Boundary | It changes when the change adds, removes or alters any of |
|---|---|---|
| DB-1 | data | a new data class, or data moving to a higher sensitivity |
| DB-2 | data | a new data store (database, bucket, storage account, queue, cache, a log sink holding payloads) |
| DB-3 | data | a new data flow between systems, or a changed direction |
| DB-4 | data | a new external recipient: another team, a vendor, a partner, an export |
| DB-5 | data | retention: kept longer or shorter, deletion or backup changed |
| DB-6 | data | residency: a new region, jurisdiction or tenant holds or processes it |
| SB-1 | security | network exposure: a port, listener, ingress, peering, route or private endpoint |
| SB-2 | security | a firewall rule, security group or network ACL (on Azure an NSG), a WAF rule or an access restriction |
| SB-3 | security | encryption in transit or at rest: TLS settings, a cipher, a store's encryption |
| SB-4 | security | a key: a new key, a key policy, rotation, who may use or administer it |
| SB-5 | security | logging or monitoring turned off, reduced, sampled, or its retention shortened |
| SB-6 | security | a scanner or gate weakened: anything in `weakenings`, a new exception, a narrowed `paths` or `language`, `advisory_mode`, a removed required check, a ruleset in `evaluate` |
| AB-1 | auth | a new identity: user, group, service principal, managed identity, IAM role or user, GitHub App, bot |
| AB-2 | auth | a new role or permission, or a wider scope for an existing one |
| AB-3 | auth | a trust policy, federated credential subject, or who may assume what |
| AB-4 | auth | cross-account, cross-subscription or cross-tenant access |
| AB-5 | auth | an MFA or Conditional Access change, an exclusion added, a sign-in method |
| AB-6 | auth | a secret: new, moved, rotated, or its scope changed (repository, environment, org, vault) |
| AB-7 | auth | API authentication or authorisation: an authorizer, a key requirement, a route left open, CORS |
| XB-1 | exposure | a public endpoint: a public IP, a function URL, a public bucket or container, a public-network-access switch turned on |
| XB-2 | exposure | a DNS record (new, changed target, a dangling one left behind) |
| XB-3 | exposure | a new third party: SaaS, external API, vendor action, image, feed, webhook target |

**Decide the depth**

- **Any row yes or unknown: a full review.** Steps 3 to 7 in full, every module the app needs
  (`APPROVAL-MATRIX.md`), and the cloud check for every row that is yes.
- **Every row no: a delta review.** Step 3, the step 4 "no unexpected diff" check (4.0), steps 5, 6
  and 7.

The kit catches SB-6 for the pipeline (`weakenings`, `weakening_attribution`, `controls_skipped`, the
capability floor, the policy register). IaC rows (SB-1..SB-4, AB-1..AB-4, XB-1, XB-2) need `MOD-IAC`
and the cloud reads. Nothing in the kit catches DB-1..DB-6, AB-5 or XB-3 by itself: they come from
the diff, the requester and the cloud.

**Triggers.** *Stop — broader conversation if* DB-1 or DB-6 is yes for confidential or regulated data
(E4, E6); AB-1, AB-3 or AB-4 adds a new identity or trust across a boundary (E3); XB-1 is new internet
exposure for something that was internal (E1); XB-3 is a third party nobody has cleared (E5). These
are not reasons to reject: they are reasons the decision is not yours alone.

**Write down:** the rows that are yes or unknown, and the depth.

---

## Step 3 · App checks — a conversation, then the run summary

Each check below is a short conversation. Ask the question in plain words, listen, then **confirm it
yourself** where it says "Then check". The kit's run summary is your main source here: open the
security run on the commit under review (the caller's `security` job: the gate summary and outputs,
the discover summary, the `security-report-<attempt>` artifact) and keep
`READING-THE-RUN-SUMMARY.md` open beside it for any word you don't know. Write down the answer and
where you confirmed it.

### 3A · "Is the evidence for this exact change?"

**Ask:** "Which commit is going out, and which security run was on that commit? Send me the run link."
- *Why we ask:* a clean scan of last week's code says nothing about today's. Reviews go wrong most often
  by looking at the wrong run.
- *A good answer sounds like:* a link to a run whose commit matches the pull request, from the last
  few days.
- *Worry if you hear:* "it passed last time", "the scan is basically the same", "we'll run it after".
- **Then check (kit run summary):** **3.1** the run's commit is the commit in 1.7 and its artifacts
  have not expired (30 days; the SBOM 90). **3.12** every kit `uses:` in the workflows is pinned to one
  40-hex SHA and the kit copy's watermark is bound (S9).
- **Stop and ask if** there is no run for this commit, or it is too old to have evidence (S16).

### 3B · "What did the security scan actually say?"

**Ask:** "What was the verdict on that run, and is anything in it marked advisory, partial or
unavailable? Can you tell me why?"
- *Why we ask:* a green tick can still carry findings, a scanner that didn't run, or missing evidence.
  The verdict word tells you which.
- *A good answer sounds like:* "`PROCEED`", or "`PROCEED_WITH_ADVISORY` because of two findings below
  the bar; here they are and here's the ticket."
- *Worry if you hear:* "it's green, so it's fine", "that scanner always fails, ignore it".
- **Then check (kit run summary):** **3.2** `routing_result`: `PROCEED`, or `PROCEED_WITH_ADVISORY`
  with every `advisory_causes` entry read; `BLOCKED`, `EVIDENCE_UNTRUSTED` and `DECISION_REQUIRED` are
  stops. **3.3** `controls_unavailable`, `controls_reduced`, `controls_skipped` empty or explained;
  no `scanner_states` row `UNAVAILABLE`, `PARTIAL` or `COLLECTION_FAILED` without an answer; every
  `COVERAGE_GAP` named; the capability floor `HELD` (`BREACHED` is a stop).
- **Stop and ask if** a scanner didn't run or ran on part of the code (S2, S3), or a required scanner
  was removed under a gap decision (S10).

### 3C · "Did anything get switched off, softened or excepted?"

**Ask:** "Is any check turned down, narrowed or excepted for this change? Who decided, where is that
written, and when does it end? Who owns it?"
- *Why we ask:* exceptions are normal, but an exception nobody owns, with no end date, or approved by the
  person who wanted it, is just a control that stopped existing.
- *A good answer sounds like:* "One secret exception for a test credential: ticket SEC-123, approved by
  the security lead, rotated, expires end of next month."
- *Worry if you hear:* "I approved it myself, it's low risk", "it doesn't expire", "it's been like that
  for ages", "we'll remove it later".
- **Then check (kit run summary and the repository):** **3.4** `weakening_attribution`
  `WEAKENING_AT_BASELINE`, or `WEAKENING_ATTRIBUTED` (KDEC-036: approved -- an evidence reference, a
  reason, an owner, an expiry within the ceiling and an approver on a registered list who is not the
  requester). `WEAKENING_NOT_APPROVED` (a field missing, named) and `WEAKENING_SELF_APPROVED` (the
  requester, actor or release author as owner or approver; the gate blocks) are stops; the deploy's
  own record reads in `weakening_check`. **3.5** every
  `secret_exceptions` and `known_exploited_exceptions` item in `.security/policy-registration.json` on
  the default branch names one finding, a ticket, an explanation with its evidence, an owner, an
  approver who is not the requester, and an expiry; the gate summary says "first exception" or a
  renewal count under the cap.
- **The rule: the requester never approves their own exception.** If they did, it is a stop, however
  small the exception.
- **Stop and ask if** the authority is the team itself or nobody can be named (S4), or there is no
  expiry or it is renewed again and again (S5). **Broader conversation if** nobody will own the
  exception (E8).

### 3D · "Anything known-bad in what it's built from?"

**Ask:** "Did the scan find any known-exploited vulnerability, malicious package or secret? If a secret
was found, has it been rotated?"
- *Why we ask:* these three block at every level in the kit because they are the ones attackers use
  first. A secret that reached the repository is exposed, whatever happens to the code afterwards.
- *A good answer sounds like:* "KEV clear, no malicious packages, no secrets."
- *Worry if you hear:* "the secret was only there for a minute", "it's a test key" (with no ticket),
  "the vulnerability isn't reachable" (with no evidence).
- **Then check (kit run summary):** **3.6** `kev_state` `AVAILABLE` and `kev_verdict` `CLEAR`; the
  `deps-scan` and `malicious-deps` rows established (`FINDING_KNOWN_EXPLOITED` or a malicious package is
  a stop). **3.7** `secret_gate` `PASS` (`EXCEPTED` means asked and rotated, S13; `FAIL` is a stop);
  `leak_gates` read, and `UNKNOWN` is never "on" (S1). **3.8** the `sbom` artifact is there and the
  build's `sbom_sha256` matches this digest.
- **Broader conversation if** there is any sign a leaked secret was used: incident response, now (E7).

### 3E · "Who signs off the release, and does it name these exact bytes?"

**Ask:** "Who approves the release to this environment? Is that someone other than you and the person
who wrote the code? Will the approval quote the image digest?"
- *Why we ask:* the person who wants a change should never be the one who lets it out, and an approval
  that doesn't name the bytes can be reused for different bytes.
- *A good answer sounds like:* "The release approver group; I can't approve my own run, and we paste the
  digest into the approval comment."
- *Worry if you hear:* "I usually approve my own, it's quicker", "an admin pushes it through",
  "we just approve the environment".
- **Then check (kit deploy summary, at the target tier):** **3.9** `release_block`,
  `environment_protection` `ENVIRONMENT_PROTECTION_VERIFIED`, `release_approval`, `zone_readiness`
  permitted with a known issuer (the landing zone, or AppSec's recorded attestation), `promotion_state`,
  `version_gap_ruling` reported. **3.10** `RELEASE_APPROVAL_VERIFIED` naming this digest
  (`SELF_DEPLOYMENT_APPROVAL` and `RELEASE_APPROVAL_NOT_BOUND_TO_DIGEST` are stops). **3.11** the deploy
  reads `needs.security.outputs.routing_result`, never a typed value: `verdict_provenance`
  `VERDICT_FROM_GATE`, or `MANUAL_REVIEW_VERDICT` with the AppSec manual review read (`TYPED_VERDICT` and
  `VERDICT_CONTRADICTED` are refused at uat/prod; contradicted at every tier).
- **Stop and ask if** nobody can say who set the readiness value (S7), the environment serving real
  users is labelled dev or test (S6), or the verdict is typed into the deploy (S8).

### 3F · What the kit can't tell you

**Ask:** "How does the app check who the caller is and what they're allowed to do? What goes into the
logs?" The kit does not test authentication, sessions, input validation, per-operation authorisation
or log contents. Read the code or design and label the answer **Read** or **Stated** (`MOD-WEB`,
`MOD-API`, `MOD-DATA`). If you can't judge the answer, that part is "Not reviewed — outside my
knowledge, routed to <role>", and that is fine.

**Triggers for the whole step.** *Stop and ask if* you did not open the run summary yourself, or a
state word still means nothing to you after `READING-THE-RUN-SUMMARY.md`. *Broader conversation if* the
run says something the code cannot mean (E10).

**Write down:** for each conversation, the answer you got and where you confirmed it (run id and job).

---

## Step 4 · Cloud checks — a conversation, then the platform

Same pattern: ask, listen, then confirm it in the platform yourself. Each conversation below is stated
once, by what it is for, in words that hold on any cloud. Under it, an **implementation table** says
where to confirm it on Azure, on AWS and on GitHub, and, for any other cloud, how to find the
equivalent. **Only the platforms the change touches apply**; for the others write "N/A" and why ("no
AWS resource in the diff or the plan"). The exact commands and click paths are in `CLOUD-CHECKS.md`
(C-numbers, keyed by intent; the old Z-, W- and H-numbers stay as aliases). All of them only read.

**A sovereign or government cloud** (a provider's separate partition for a government or a
jurisdiction) uses the same checks: point the CLI at that cloud's endpoints and sign-in first, use
its own API host, and record a feature that cloud does not offer as a gap, never as "off" or clean
(`CLOUD-CHECKS.md`, the note at the top).

**Read before and after.** Look at the state before the change (production now, or the plan's
"before") and after it (a lower environment where it already ran, or the plan's "after"). Reading only
"after" in production is reviewing a change that has already happened.

**New to a platform?** That's expected. Use the click path first, the command second, and if an output
doesn't make sense, ask the platform team to walk you through it. Asking is part of the review, and
"Not reviewed — outside my knowledge, routed to <role>" is a valid outcome for a part you can't judge.

### 4.0 · "Is what changed what the ticket says changed?" (every review)

**Ask:** "Apart from what's in the ticket, did anything else change on these resources since the last
release: by hand, by another pipeline, during testing?"
- *Why we ask:* the risky change is often the one next to the one being reviewed.
- *Worry if you hear:* "I fixed a couple of other things while I was in there".
- **Then check** the change history (C0); it should match the ticket:

  | Azure | AWS | GitHub | Other cloud: how to find the equivalent |
  |---|---|---|---|
  | the resource's **Activity log** | **CloudTrail → Event history**; **Config → Resource timeline** | the organisation audit log, or the settings pages before and after | the provider's control-plane audit log and its resource configuration history |

- **Stop if** a resource the ticket does not name changed in a boundary that matters.

### 4A · "Who can reach it after the change?" (rows SB-1, SB-2, XB-1)

**Ask:** "Walk me through who can reach this after the change. Is anything newly open to the internet,
or to a wider network than before? Is a private connection being replaced with a public one?"
- *Why we ask:* every new opening is a new way in. "Temporary" openings are the ones most often
  forgotten.
- *A good answer sounds like:* "Only the app gateway's subnet can reach it, same as now, port 443."
- *Worry if you hear:* "it's just a quick firewall tweak", "we opened it for the migration, we'll close
  it after", "the private endpoint was flaky so we switched to public".
- **Then check:** no source of "anywhere" to a management or database port (C3); private connections
  still approved and public network access still off (C4); transport settings unchanged (C4); at the
  source-control platform, who can push to the default branch and what CI may do (C16, C18).

  | Azure | AWS | GitHub | Other cloud: how to find the equivalent |
  |---|---|---|---|
  | C3 (Z2) NSG and firewall rules: no `Internet`/`*` source to a management or database port; C4 (Z3) private endpoints still approved; C4 (Z4) `publicNetworkAccess`, TLS and HTTPS | C3 (W3) security groups and network ACLs: no `0.0.0.0/0` to SSH, RDP or a database port; C4 (W4) S3 Block Public Access still on, the bucket not public | C16 (H1) rulesets; C18 (H3) Actions permissions | the resource's firewall or security-group rules and its subnet ACL; its private-connectivity attachments; its public-access switch and TLS minimum |

- **Broader conversation if** something internal becomes internet-facing, or a shared edge entry
  (an edge or CDN front door, WAF, DNS, firewall) changes (E1).

### 4B · "Who and what gets access, and how much?" (rows AB-1..AB-5)

**Ask:** "Which identities does this add or change: people, service accounts, app identities, roles?
What can each one do, and on what? Does anything new get to assume or trust anything?"
- *Why we ask:* a broad role given to get past an error is the most common way a small change gets a
  big blast radius.
- *A good answer sounds like:* "The app's own identity gets read on its own storage; nothing at
  subscription or account level."
- *Worry if you hear:* "we gave it Contributor/Admin so it would stop failing", "it needs `*` for now",
  "it's the same identity the other app uses", "the trust is for our whole org".
- **Then check:** the permission diff, before and after, with nothing full-control, grant-others or
  wildcard at a wide scope for a workload (C1); who may assume or federate into each identity (C2); the
  runtime identity's reach (C10); directory or API permissions, consent and credentials (C11);
  sign-in protections and their exclusions (C12); deployment approvals and the integrations that can
  act on the code (C17, C19, C20).

  | Azure | AWS | GitHub | Other cloud: how to find the equivalent |
  |---|---|---|---|
  | C1 (Z1) role assignments: no `Owner`, `User Access Administrator` or `Contributor` at subscription scope for a workload; C10 (Z9) the managed identity's scope; C11 (Z10) Entra app permissions, admin consent, federated credentials and client secrets; C12 (Z11) Conditional Access and MFA exclusions | C1 (W1) the IAM policy versions side by side (no `"Action": "*"`, no `iam:PassRole` on `*`; run Access Analyzer's validate-policy); C2 (W2) the role's trust policy (no `"Principal": "*"`, GitHub OIDC pinned to one repository and environment) | C17 (H2) environment reviewers and self-review; C19 (H5) deploy keys; C20 (H6) GitHub Apps and their permissions; C12 (H7) organisation 2FA and SSO | the role bindings on the resource and its parents; each identity's trust or federation configuration; the identity provider's app permissions and sign-in policies |

- **Broader conversation if** it is a new identity design, cross-tenant or cross-account trust, or an MFA
  or Conditional Access change (E3).

### 4C · "Where do the secrets and keys live?" (rows AB-6, SB-3, SB-4)

**Ask:** "Does this add or move a password, key, token or certificate? Where is it stored, who can read
it, and how is it rotated? Does any encryption setting change?"
- *Why we ask:* a secret in plain configuration is readable by everyone who can read the configuration,
  and that is usually more people than you think.
- *A good answer sounds like:* "It's a reference to the secret store; only the app's identity can read it."
- *Worry if you hear:* "it's in the app settings for now", "it's in an environment variable", "we'll
  move it to the vault later".
- **Then check:** credentials are references to the secret store, not literals (C13: look at names
  first; never paste values into the ticket); who can use and administer the keys, and deletion
  protection (C6); encryption at rest names the right key (C5); transport minimums (C4).

  | Azure | AWS | GitHub | Other cloud: how to find the equivalent |
  |---|---|---|---|
  | C13 (Z12) app settings are Key Vault references; C6 (Z5) Key Vault access and purge protection; C4 (Z4) TLS minimums | C13 (W9) Lambda and task-definition variables reference Secrets Manager or Parameter Store; C6 (W6) the KMS key policy and rotation; C5 (W5) S3 encryption | C13 (H4) secrets: names, scope and who can read an organisation secret | the compute service's settings and environment variables; the provider's secret manager and key service access model; the store's encryption-at-rest key |

- **Stop if** a literal secret is in configuration: it needs rotating, not just moving.

### 4D · "Where does the data go, and how long does it stay?" (rows DB-2, DB-5, DB-6)

**Ask:** "Which store does this write to? Is it new? Which region is it in? How long is the data kept,
and does that change?"
- *Why we ask:* data in a new store, region or retention period can change who must be told and what
  rules apply.
- *A good answer sounds like:* "Same database, same region, same retention."
- *Worry if you hear:* "it's just a temporary copy", "the new bucket is in another region but it's only
  for a while".
- **Then check:** the store's network and public-access settings, region and retention rules (C4);
  its encryption (C5); its log retention (C7).

  | Azure | AWS | GitHub | Other cloud: how to find the equivalent |
  |---|---|---|---|
  | C4 (Z4) the store's network and public-access settings and its region; C7 (Z6) diagnostic retention | C4 (W4) the bucket's region, policy and lifecycle rules; C5 (W5) encryption | usually N/A; C20 (H6) if an app or webhook receives repository data | the store's region, resource policy, public-access setting and lifecycle or retention rules |

- **Broader conversation if** regulated data moves, or data goes to another team's system (E6, E4).

### 4E · "Will we still see what happens?" (rows SB-5, SB-6)

**Ask:** "Does this change any logging, monitoring or alerting, or any security tool's coverage? Is
anything being turned down to save cost or noise?"
- *Why we ask:* logs are the evidence for every later investigation. Turning them down is invisible
  until the day you need them.
- *A good answer sounds like:* "No logging change; the cloud's security service is unchanged."
- *Worry if you hear:* "we reduced diagnostics to cut the bill", "we paused the trail during the
  change", "that recommendation is just noise".
- **Then check:** log export settings before and after, and the account-wide audit trail (C7); the
  posture and threat findings for the resource (C8); policy compliance and any new exemption (C9).

  | Azure | AWS | GitHub | Other cloud: how to find the equivalent |
  |---|---|---|---|
  | C7 (Z6) diagnostic settings before and after; C8 (Z7) Defender for Cloud recommendations for the resource; C9 (Z8) Azure Policy compliance and any new exemption | C7 (W7) CloudTrail logging and Config recording still on; C8 (W11) Security Hub and GuardDuty findings for the resource | C7 (H8) secret scanning and push protection, and audit-log streaming where licensed | the provider's log export settings and API audit trail; its posture-management and threat-detection findings; its policy engine's compliance and exemptions |

- **Broader conversation if** the platform's threat detection shows signs of active misuse: incident
  response (E7).

### 4F · "Does the app check who's calling?" (row AB-7)

**Ask:** "For each new route or endpoint: who is allowed to call it, and what checks that? Is anything
deliberately public?"
- *Why we ask:* an endpoint without authentication is open to anyone who finds it, and they will.
- *A good answer sounds like:* "Every new route sits behind the same sign-in as the rest; the health
  check is the only public one."
- *Worry if you hear:* "we'll add auth later", "nobody knows the URL", "CORS is `*` for now".
- **Then check:** the app's or gateway's authentication on every new route, ingress and CORS (C14).

  | Azure | AWS | GitHub | Other cloud: how to find the equivalent |
  |---|---|---|---|
  | C14 (Z13) App Service or Container Apps authentication and ingress, and CORS | C14 (W8) the Lambda function URL (auth type `NONE` is a stop unless the ticket says public) and resource policy; C14 (W10) API Gateway authorizers on every new route | N/A | the compute service's built-in authentication, the gateway's per-route authorizers, CORS and invoke policies |

### 4G · "Any new names or new outside parties?" (rows XB-2, XB-3)

**Ask:** "Does this add or change a DNS name? Does it bring in a new vendor, SaaS, API, action or image,
or give one access it didn't have?"
- *Why we ask:* a DNS name left pointing at something deleted can be taken over; a new third party sees
  your data on its own terms.
- *A good answer sounds like:* "No DNS change; no new vendor."
- *Worry if you hear:* "we'll clean up the old record later", "it's a free tool, no contract needed".
- **Then check:** every new name points at something we own (C15); a third party's consent, trust or
  installation (C11, C2, C20).

  | Azure | AWS | GitHub | Other cloud: how to find the equivalent |
  |---|---|---|---|
  | C15 (Z14) DNS records; C11 (Z10) admin consent to a third-party app | C15 (W12) Route 53 records; C2 (W2) a third-party account in a trust policy (with an external ID) | C20 (H6) a new app installation or webhook | the provider's DNS zones and each CNAME or alias target; third-party consents, trusts and installed integrations |

- **Broader conversation if** a third party nobody has cleared is involved (E5).

**Triggers for the whole step.** *Stop and ask if* you cannot read a check or don't understand its
output: ask the platform team to run it and walk you through it; never take a write role to review
(S1). *Broader conversation if* the change creates a new subscription, account, project, tenant or
landing zone (E1), or is an identity design rather than one grant (E3).

**Write down:** for each conversation, the answer and where you confirmed it (the C-number, or its old
Z/W/H alias, and what it showed), and "N/A — reason" for platforms not touched.

---

## Step 5 · Pipeline and evidence checks

**Open** the change's diff of `.github/workflows/`, the environment settings, and the ticket's links.

| # | Check | Safe | Ask | Stop |
|---|---|---|---|---|
| 5.1 | **The change does not edit its own gate**: the security caller, the required check, the policy register, CODEOWNERS, rulesets and environment protection are unchanged in the same change as the code they gate | none changed, or changed in a separate, already reviewed change | a governance file changed beside the code, with a reason | the change weakens the gate that judges it (`pull_request_target` checking out the head, a removed `Security gate` requirement, `permissions: write-all`, a new `secrets: inherit`) |
| 5.2 | **Separation of duties**: requester, author, code reviewer, release approver, exception approver | the requester approves nothing; author and release approver differ | two roles held by one person in a small team, recorded (`team_pattern`) | the requester approved the release, an exception or a weakening |
| 5.3 | **Evidence over assertion**: each "tested", "scanned", "no impact" points at a run, a report or a plan | each claim has a link | a claim with no link: ask once | a claim the evidence contradicts |
| 5.4 | **Traceability**: the ticket links the pull request, the security run and the build run (and the deploy run after release); the pull request links the ticket | all links | links missing: ask for them | the commit to be released is not the commit reviewed |
| 5.5 | **Evidence kept**: the run's artifacts expire (30 days; SBOM 90); what you relied on is attached to your review record (`APP-REVIEW-CHECKLIST.md` section 8) | attached | — | the evidence you relied on is gone and cannot be re-run |

**Triggers.** *Stop and ask if* the only evidence for a claim is "it's the same as before". *Stop —
broader conversation if* an AI agent or automation would act on systems on its own (E9).

**Write down:** what changed in the gate files, the roles, the links.

---

## Step 6 · The rollback check

**Open** the ticket's back-out section and, for a kit release, the deploy evidence of the last release
to the same target (`deploy-evidence-<run_id>-<attempt>`: `capability.json`, `reversal.json`).

| # | Check | Safe | Ask | Stop |
|---|---|---|---|---|
| 6.1 | **A plan with a trigger**: what signal means "back out", who decides (role), within what time | trigger, owner role and time named | no trigger or no owner | no plan for a change touching a boundary row |
| 6.2 | **Mechanical for a kit release**: `rollback_on_failure` `true`; the reversal shown available; an e2e test command set; the previous digest still in the registry | all four | no e2e command (the deploy can never be verified for promotion) | reversal `UNAVAILABLE` at uat or prod |
| 6.3 | **What cannot be rolled back is named**: a data migration, a deleted store, a destroyed key, an external send, a cached DNS record, a permission already used | each named with its forward-fix and who accepts it | "it can be rolled back" for a schema change, with no evidence | an irreversible boundary change with no named acceptance |
| 6.4 | **Rollback restores the boundary too**: reverting the code does not revert an IAM grant, a firewall rule, a consent or a DNS record made outside it | the plan reverts the platform change too, or says why it stays | the plan covers only the app | a "temporary" opening with no step that closes it |
| 6.5 | **Shared entries** (an edge or CDN front door, DNS, WAF, network security rules, firewall) belong to the platform; an app rollback never reverses them (`ROLLBACK_REFUSED_PLATFORM_OWNED`) | the platform owner has its own back-out | — | the app team plans to revert a shared entry itself (E1) |

**Write down:** the trigger, the owner role, the irreversible parts and who accepts them.

---

## Step 7 · Decide

Apply in order; the first that matches is the outcome. "I could not check it" is never safe.

**Not reviewed — outside my knowledge**, when any understanding line of step 1 is still blank, or
you cannot judge a component the change depends on. Route it to the role who can.

**Paused — broader conversation opened**, when a step's broader-conversation trigger fired and the
role has not answered. An open E6 (regulatory) or E7 (incident) always pauses.

**Reject** when any of these holds:

1. `routing_result` `BLOCKED`, `EVIDENCE_UNTRUSTED` or `DECISION_REQUIRED` on the commit to be released.
2. A stop outcome in any check of steps 1 to 6.
3. The requester approved the release, an exception or a weakening for this change.
4. An exception with no owner, no expiry, past its expiry, or past its renewal cap.
5. A boundary row is yes and its cloud check was not done, or was done only after the change reached prod.
6. A full review with no rollback plan, or an irreversible boundary change with no named acceptance.

**Needs more info** when no reject rule holds but an ask is open that the requester can answer.

**Approve with conditions** when no rule above holds and every remaining item is a bounded gap with
an owner role, a due date and the evidence that closes it: an escalation still with its role (other
than E6, E7), `ATTESTATION_HELD_BY_PLAN`, `SEAM_OWNERSHIP_NOT_IN_FORCE`, an approval that must quote the
digest at release, a `COVERAGE_GAP` the team is closing.

**Approve** when all of these hold:

1. The understanding gate is complete in your words.
2. The artefact is one commit and one digest, and the evidence is for that commit.
3. `routing_result` is `PROCEED`, or `PROCEED_WITH_ADVISORY` with every cause read and acceptable.
4. No boundary change, or every boundary row that is yes has its cloud check safe.
5. No new exception or weakening, or each one has evidence, notes, an owner who is not the requester,
   an approver who is not the requester, and an expiry.
6. Requester, author and release approver are three people, and the release approval will quote the digest.
7. No unexpected diff (4.0).
8. A rollback plan with a trigger and an owner, which reverts the platform changes too.

---

## Step 8 · Write the security verdict onto the CAB ticket

The reviewer records the security outcome, the understanding, the evidence, the conditions and the
open questions as a comment on the **existing** CAB ticket, where the organisation already puts the
security answer. This does not change how CAB runs: it is what CAB reads from security. The paste
block is in `CAB-CHANGE-REVIEW-CHECKLIST.md`; the full notes behind it go in your review record
(`SIGN-OFF.md`).

- State **one outcome** from the table at the top, in words. A typed outcome is the verdict: there is
  no tool that decides it for you.
- Include the understanding summary (step 1), the evidence list (what you looked at), the conditions
  (each with an owner role and an expiry or due date), and the open questions.
- Sign by **role**, never by a person's name.
- "Security reviewed" or "LGTM" alone is not a security sign-off, and CAB should not read it as one.
- The verdict is valid for the commit and digest named only. A new commit, digest or boundary is a
  new review. A condition past its date reopens it: silence never renews it.

---

## Emergency changes

CAB's emergency path decides when a change may skip the normal one. The security review's part:

- **At the time:** step 1, step 2, and checks 3.2, 3.6 and 3.7 at least. A found secret or a
  known-malicious package still blocks; an emergency does not change that. A kit release past the
  promotion gate is `release_path: break-glass` with an attributed exception expiring within 7 days,
  never a typed verdict (`modules/MOD-EMERGENCY-CHANGE.md`). An incident goes to incident response
  first (E7).
- **Afterwards: the retrospective security review within 5 working days of the change** (OWNER
  DECISION: the number; 5 working days is the default until the owner sets it). Steps 1 to 8 in full
  on the commit and digest that were released, with 4.0 reading the platform's change history from the
  emergency window. Any "temporary" access, rule, exception or bypass opened for the emergency is
  checked closed (gotcha G1 in `PRINCIPLES-AND-SOURCES.md`). The verdict goes on the same CAB ticket,
  marked "Retrospective".
