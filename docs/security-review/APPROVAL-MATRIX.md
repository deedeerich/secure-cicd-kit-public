# Approval matrix — which modules a review needs

```
Truth State:  Authored, not field-tested (2026-11-03). One page. The selector behind it is
              CAB-AND-ADOPTION-REVIEW.md; the modules are in modules/.
How to read:  find the app's kind (row) and where it runs (column). Every review also takes MOD-BASE.
              Then add every line of "Add when" that applies.
```

| App kind ↓ / runs on → | App Service, Container Apps, or Functions as a container | Static Web Apps | Code-packaged Functions, AKS, VM, other (no kit adapter: `NO_KIT_ADAPTER:<kind>`) | Automation platform (Tines 3B or other) |
|---|---|---|---|---|
| Web app | WEB, CONTAINER | WEB, STATIC-SITE | WEB, OUTSIDE-KIT | — |
| API | API, CONTAINER | — | API, OUTSIDE-KIT | API, AUTOMATION |
| Internal tool | WEB or API, CONTAINER | STATIC-SITE | OUTSIDE-KIT | AUTOMATION |
| Batch or data pipeline | DATA, CONTAINER | — | DATA, OUTSIDE-KIT | DATA, AUTOMATION |
| Automation or agent acting on systems | AGENT, CONTAINER | — | AGENT, OUTSIDE-KIT | AGENT, AUTOMATION |
| Integration or connector | API, CONTAINER | — | API, OUTSIDE-KIT | API, AUTOMATION |
| Infrastructure / IaC | IAC (the platform applies it: E1) | IAC | IAC | IAC |
| Static site | — | STATIC-SITE | OUTSIDE-KIT | — |

Module names drop the `MOD-` prefix in the table (`WEB` = `MOD-WEB`).

## Add when

| Condition | Add |
|---|---|
| any release to **uat or prod** through a kit deploy reusable | `MOD-PROD-DEPLOY` |
| data is **confidential or regulated**, or flows to another team | `MOD-DATA` |
| a **new third party** | `MOD-THIRD-PARTY` |
| jobs run on **self-hosted or private-network runners** | `MOD-SELF-HOSTED-RUNNER` |
| the repository holds **IaC** beside the app | `MOD-IAC` |
| the app or a part of it **acts on systems on its own** | `MOD-AGENT` (and E9) |
| a CAB **emergency** change | `MOD-EMERGENCY-CHANGE` (retrospective review within 5 working days: OWNER DECISION, default) |

## Which depth

| Review | Modules |
|---|---|
| Adoption of a new app | every module the table and "Add when" select |
| Security review of a CAB change, **full** (the boundary triage of [`CAB-CHANGE-SAFETY-STEPS.md`](CAB-CHANGE-SAFETY-STEPS.md) step 2 finds a data, security, auth or exposure boundary changed, or unknown; or a new runtime or environment) | every module selected, plus the cloud checks for each boundary touched; recorded on [`CAB-CHANGE-REVIEW-CHECKLIST.md`](CAB-CHANGE-REVIEW-CHECKLIST.md) |
| Security review of a CAB change, **delta** (every triage row no; code only; gate `PROCEED` or `PROCEED_WITH_ADVISORY` with every cause read, floor `HELD`, no new exception) | `MOD-BASE`, plus `MOD-PROD-DEPLOY` if it goes to uat/prod; the procedure's steps 3, 4.0, 5, 6, 7 |
| CAB standard change | `MOD-BASE` evidence on the commit: verdict read, no new exception; standard only while every triage row is no |
| CAB emergency change | `MOD-EMERGENCY-CHANGE` now; the retrospective security review within 5 working days (OWNER DECISION, default), steps 1 to 8 |
| Pulled in before the CAB presentation exists | no module yet: [`EARLY-REVIEW-REQUESTS.md`](EARLY-REVIEW-REQUESTS.md) (what to ask for; early guidance only, recorded on the ticket) |

Inside or outside a landing zone does not change the modules; it changes who issues
`KIT_ZONE_READINESS` (the landing zone when connected, otherwise AppSec as a recorded attestation)
and who owns the platform items (E1).
