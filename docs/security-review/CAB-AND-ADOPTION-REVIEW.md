# CAB and adoption review — the adoption path for an internally built app

```
Truth State:  Authored, not field-tested (2026-11-03).
Use when:     security is asked to approve the ADOPTION of a new internally built app: which
              checklist modules apply, and what the approver signs. The modules are in modules/, and
              APPROVAL-MATRIX.md is the one-page lookup.
CAB changes:  CAB, its tickets and its process are the organisation's and are not defined here. The
              security review of one change going to CAB (cloud or app) is CAB-CHANGE-SAFETY-STEPS.md,
              recorded on CAB-CHANGE-REVIEW-CHECKLIST.md; pulled in before the CAB presentation:
              EARLY-REVIEW-REQUESTS.md. Steps 1, 2 and 4 below still select the modules a full review
              needs; step 3 now points to the boundary triage.
Owner decisions marked: OWNER DECISION, with the default this sheet uses until decided.
```

## Step 1 · Classify the app

Pick every kind that applies. Most apps are two (for example a web app that also calls an API).

| Axis | Values | Notes |
|---|---|---|
| **Kind** | web app / API · internal tool · batch or data pipeline · automation or agent (AI or code acting on systems) · integration / connector · infrastructure / IaC · static site | an internal tool is a workload like any app (KDEC-015): its own target, its own deploy identity |
| **Data sensitivity** | public · internal · confidential · regulated | the highest class it stores, processes or passes on |
| **Exposure** | internet-facing · internal network only · no inbound network | include partner access and anything behind a shared edge |
| **Identity and privilege** | what it can change: its own target only · other apps' resources · platform or identity objects · other organisations' systems | anything beyond its own target is E3 |
| **Third parties** | none · existing approved · new | new is E5 |

An **automation or agent that acts on systems** (writes to repositories, tickets, cloud resources or
another system on its own) is always also under the agent governance harness: E9 in
`ESCALATE-BROADER.md`, and module `MOD-AGENT`.

## Step 2 · The environment it runs on

| Runs on | Kit coverage | Modules it adds |
|---|---|---|
| Azure App Service (Linux container) | scan, build once, deploy by digest, slot swap, verified rollback | `MOD-CONTAINER`, and `MOD-PROD-DEPLOY` at uat/prod |
| Azure Container Apps | scan, build once, deploy by digest, revision traffic, verified rollback | `MOD-CONTAINER`, and `MOD-PROD-DEPLOY` at uat/prod |
| Azure Static Web Apps | scan, content digest, preview then production, reversal to the prior artefact (stub-proven only) | `MOD-STATIC-SITE`, and `MOD-PROD-DEPLOY` at uat/prod |
| Azure Functions as a Linux custom container (Premium or Dedicated plan) | scan, build once, deploy by digest through the App Service reusable (`site_kind: functionapp`), slot swap, verified rollback (stub-proven only) | `MOD-CONTAINER`, and `MOD-PROD-DEPLOY` at uat/prod |
| Code-packaged Functions, AKS, VMs, anything else | **scan only**: the kit has no deploy adapter (`NO_KIT_ADAPTER:<kind>` in the gate's `no_kit_adapter`); the deploy is outside the kit | `MOD-OUTSIDE-KIT` |
| Inside a connected landing zone | the zone vends the target, the identity and the hand-off variables (`KIT_ZONE_READINESS`, `KIT_RELEASE_BLOCK`, ...) | — (the platform's part is E1) |
| Outside a landing zone | nobody vends readiness or the platform stop; AppSec issues `KIT_ZONE_READINESS` as a recorded attestation | `MOD-PROD-DEPLOY` covers the attestation |
| dev / test | gates record but do not refuse (approval, readiness) | none extra |
| uat / prod | approval bound to digest, environment protection, readiness, promotion all refuse | `MOD-PROD-DEPLOY` |
| Self-hosted or private-network runner | the runner is part of the trust boundary | `MOD-SELF-HOSTED-RUNNER` |
| GitHub-hosted standard runner | cannot reach private endpoints (lease store, feed mirrors) | none extra |
| An automation built in Tines 3B (code-first) | the kit scans what reaches the repository (for example through GitSync); it does not see the automation's runtime credentials or what it calls | `MOD-AUTOMATION` (and `MOD-AGENT` if it acts on systems on its own) |

## Step 3 · The size of the change (CAB only)

| CAB class | When | Evidence it needs |
|---|---|---|
| **Standard** | a pre-approved, repeatable change of a kind already reviewed (a dependency patch through the kit's Dependabot triage, a content change), same scope | the security run on the commit: `routing_result` `PROCEED` or `PROCEED_WITH_ADVISORY` with every cause read; no new exception |
| **Normal** | everything else that is not an emergency | a **delta review** or a **full re-review** (below), with the modules' evidence |
| **Emergency** | a fix that cannot wait for the normal path | `MOD-EMERGENCY-CHANGE`; a retrospective review afterwards |

**Full review or delta review** is decided by the boundary-change triage in
[`CAB-CHANGE-SAFETY-STEPS.md`](CAB-CHANGE-SAFETY-STEPS.md), step 2: a change to a data, security,
auth or exposure boundary (rows DB-1..DB-6, SB-1..SB-6, AB-1..AB-7, XB-1..XB-3; unknown counts as yes)
is a **full review** — every module for the app's kind and environment, from step 1, plus the cloud
checks for each boundary touched. Also a full review, whatever the triage says: a new runtime, hosting
type or environment (including a first uat/prod release), and an AI agent or automation newly acting
on systems (E9).

**Delta review** — every triage row is no; only code changes; the kit pin unchanged or moved forward
with its watermark read; the security run on the change `PROCEED` or `PROCEED_WITH_ADVISORY` with every
cause read; no new exception; the capability floor `HELD`. A delta review is `MOD-BASE` plus
`MOD-PROD-DEPLOY` if the change goes to uat/prod, and steps 3, 4.0, 5, 6 and 7 of the procedure.

**Emergency changes still get a retrospective review**, within **5 working days** of the change
(OWNER DECISION: the number; 5 working days is this sheet's default until the owner sets it). The
retrospective is the security review, steps 1 to 8, on the commit and digest that were released
(`CAB-CHANGE-SAFETY-STEPS.md`, "Emergency changes").

## Step 4 · The checklist modules

Always `MOD-BASE`. Then each module the app's kind, environment and change select
(`APPROVAL-MATRIX.md`). Each module is one page.

| Module | Covers |
|---|---|
| [`MOD-BASE`](modules/MOD-BASE.md) | pin, verdict, posture, findings, exceptions, leak gates — every review |
| [`MOD-WEB`](modules/MOD-WEB.md) | a browser-facing app |
| [`MOD-API`](modules/MOD-API.md) | an API, or an app other services call |
| [`MOD-CONTAINER`](modules/MOD-CONTAINER.md) | an image built once and deployed by digest |
| [`MOD-STATIC-SITE`](modules/MOD-STATIC-SITE.md) | a Static Web Apps site |
| [`MOD-IAC`](modules/MOD-IAC.md) | infrastructure code in the repository |
| [`MOD-DATA`](modules/MOD-DATA.md) | confidential or regulated data, or a cross-team data flow |
| [`MOD-AGENT`](modules/MOD-AGENT.md) | AI or code acting on systems on its own |
| [`MOD-AUTOMATION`](modules/MOD-AUTOMATION.md) | an automation built in Tines 3B, or another automation platform |
| [`MOD-THIRD-PARTY`](modules/MOD-THIRD-PARTY.md) | a new third party |
| [`MOD-PROD-DEPLOY`](modules/MOD-PROD-DEPLOY.md) | a release to uat or prod |
| [`MOD-OUTSIDE-KIT`](modules/MOD-OUTSIDE-KIT.md) | hosting with no kit deploy adapter |
| [`MOD-SELF-HOSTED-RUNNER`](modules/MOD-SELF-HOSTED-RUNNER.md) | jobs on self-hosted or private-network runners |
| [`MOD-EMERGENCY-CHANGE`](modules/MOD-EMERGENCY-CHANGE.md) | a CAB emergency change |

## Step 5 · Sign-off

**What the approver signs.**

- **CAB**: "This change, at app commit `<sha>` and image or site digest `<digest>`, may be released
  to `<environment>`, on this evidence, with these conditions." It covers the change, not the whole
  app.
- **Adoption**: "This app, at commit `<sha>`, in these environments, may be run and released through
  the kit, on this evidence, with these conditions, until `<review date>`." It covers the app's
  current scope; a material change (step 3) ends it.

**Attach**: the run links (security, build, deploy per tier); the digest; the gate verdict
(`routing_result`, `advisory_causes`); every exception with its ticket, approver and expiry; the
readiness value and its issuer (landing zone, or AppSec attestation reference); the completed
modules; open stop-and-ask items; escalations and their answers. Use the block in `SIGN-OFF.md`.

**Blocks sign-off** (no approval, with or without conditions):

- `routing_result` `BLOCKED`, `EVIDENCE_UNTRUSTED` or `DECISION_REQUIRED` on the commit released;
- an open E7 (incident) or E6 (regulatory) escalation;
- at uat/prod: `release_approval` not `RELEASE_APPROVAL_VERIFIED`, `environment_protection` not
  `ENVIRONMENT_PROTECTION_VERIFIED`, or a readiness value with no legitimate issuer (S7);
- a typed verdict in the deploy call (S8; `verdict_provenance` not `VERDICT_FROM_GATE`), or a kit pin
  that is not a SHA (S9);
- a capability floor `BREACHED`; a secret not rotated; an exception past its expiry;
- for adoption: no run of the security caller on the commit under review.

**Approve with conditions** when everything above holds and what remains is a bounded, owned gap:
an open stop-and-ask item, an escalation still with its role (other than E6/E7), an
`ATTESTATION_HELD_BY_PLAN`, a lease not yet on, a `COVERAGE_GAP` the team is closing. Each
condition has an owner role, a due date and the evidence that closes it.

**The follow-up record**: one entry per condition in the review record and in the tracker the
organisation uses for security work, linked from the CAB record. A condition past its date reopens
the approval: silence never renews it, the same rule the kit holds for its own exceptions.
