# Ticket types -- the enabled templates, and the PROPOSED ones the owner picks from

```
Status:    KDEC-037 (2026-11-04). ENABLED types are built and proven (tests/prove_ticket_templates.py,
           tests/prove_ticket_intake_v2.py). PROPOSED types are draft schema stubs, DISABLED: a
           submission is refused TEMPLATE_NOT_ENABLED until the owner enables the type.
Schemas:   api/v1/tickets/<type>.schema.json (enabled), api/v1/tickets/proposed/<type>.schema.json (proposed).
```

## Enabled (template_version 2)

| type | what it is (the owner's words where she gave them) | opens |
|---|---|---|
| `finding` | a finding the kit's scan did not produce: USR reviews, cloud tools (any Azure cloud, Azure Government, AWS), pentests, audits, reviews, other tools | a remediation ticket |
| `false-positive` | "this is not a thing, the scanner is wrong": evidence required, a reviewer confirms, NO expiry, re-checked when the rule, tool version or code changes | `FALSE_POSITIVE_REQUEST` |
| `exception` | ALWAYS time-limited (at most 90 days) with a SPECIFIC scope -- "this WAF rule blocks us because this traffic triggers it, but it's parameterized and not harmful; from this specific endpoint to this specific endpoint"; justification and compensating controls | `EXCEPTION_REQUEST` |
| `exemption` | the accepted-risk family, "there to stay"; may have a ticket time limit; a review cadence | `EXEMPTION_REQUEST` |
| `accepted-risk` | its own type, not necessarily an exemption -- legacy hardware awaiting migration or funding; inherent operational risk ("pilots have to fly in the rain"); owner, rationale, review date, risk-register link; no control exemption requested | `ACCEPTED_RISK_REQUEST` |
| `compliance-exception` | the stricter standard: framework, control id, requirement text, scope, compensating controls, expiry, a named approving authority | `COMPLIANCE_EXCEPTION_REQUEST` |
| `mitigation` | a compensating control in force instead of a fix | `MITIGATED_REQUEST` |
| `extension` | a new expiry on an existing ticket: 30 days by default; while a fix is available at most 2, each at most 90 days; while waiting on the vendor it continues, with the advisory "no fix after 6 months, consider an alternative" at the second extension or 180 days | an update |
| `nofix-recheck` | NO_FIX_AVAILABLE: a 30-day exemption (ceiling 90), a vendor re-check every 30 days, a review every 90, the advisory at 180 days ("something like a permanent risk acceptance; look for an alternative") -- earlier and escalated for critical/high, none for low | a no-fix ticket |
| `closure` | resolve (the fixer: pending verification), verify (a rescan on the mapped branch, or a reviewer who is not the fixer), reject (reopens) | an update |
| `triage` | a person's merge / separate on a possible duplicate | an update |

A request is never a disposition: nothing stops blocking until an exact, unexpired, approved
disposition is merged to the protected default branch.

## PROPOSED (disabled by default; the owner picks which to enable)

Each has a draft stub at `api/v1/tickets/proposed/<type>.schema.json` (`x-enabled: false`). Enabling one
means: a full schema with its required fields, its rules, its ticket class, its routing facts, and a
proof -- the same as every enabled type.

| type | what it would carry | why it may deserve its own type |
|---|---|---|
| `vendor-dependency` | a remediation that waits on a vendor (release, patch, contract): vendor, product, the vendor's ticket, the expected date | its clock is the vendor's, not the team's; it pairs with the vendor-extension rule |
| `remediation-subtask` | one piece of a larger remediation, under its parent | progress on a large fix without splitting the finding |
| `review-finding` | a finding from a USR or CISO review, beside its review record | the review's own lifecycle and sign-off |
| `pentest-finding` | a finding from a contracted penetration test: engagement id, tester, retest window | a retest by the tester is its verification |
| `audit-finding` | a finding from an internal or external audit: audit id, control, auditor | audit closure needs the auditor's acceptance |
| `cloud-misconfiguration` | a cloud misconfiguration or configuration drift on a resource | drift reverts; the fix is a policy or IaC change |
| `exposed-secret` | an exposed credential: rotate, remove, prove the old one dead | rotation comes first, before any review (the kit never grandfathers a secret) |
| `licence` | a licence obligation or conflict in a dependency | legal, not security, owns the decision |
| `end-of-life` | an end-of-life or unsupported technology to replace | no fix will ever come; a migration plan is the remedy |
| `architecture-risk` | an architecture or design risk without a single code location | no scanner verifies it; an architect does |
| `access-review-finding` | excess, stale or orphaned access from an access review | the identity owner remediates; evidence is the access list |
| `incident-follow-up` | a follow-up action from an incident review | tied to the incident record and its deadline |
| `policy-deviation` | a deviation from an internal policy (not a framework control) | the policy owner decides, not the control owner |
| `control-gap` | a control the framework requires and the estate does not implement | a compliance gap, not a defect in one asset |

**Owner decision owed (O-37k):** which proposed types to enable. Default: none.
