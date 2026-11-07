# Ticket tagging strategy -- a PROPOSAL for discussion, not a decision

> **Baseline for an environment-specific scheme to be designed at the adopting organisation**
> (the owner, 2026-11-04, KDEC-037 O-37g). Kept as written; not elaborated here.

```
Status:     PROPOSAL (KDEC-037, 2026-11-03). The labels below are what the kit writes TODAY as its
            default; every one of them is open for the owner to change. Nothing here is final.
Audience:   the owner, whoever runs the Jira projects, and the Tines 3B builder (dashboards).
Decision:   how findings from every source are tagged in the tracker so that they can be tracked,
            processed, governed, worked and managed -- and found again.
Built:      scripts/ticket_templates.py tag_labels(); the routing facts in scripts/ticket_routing.py.
```

## 1. Why this needs a scheme

The owner, 2026-11-03: "there will be vulns from apps, projects, subscriptions, resources, pentests
and findings from reviews, audits, etc and it all must be tracked and processed and governed and
worked on and managed ... we need to come up with tagging strategies too."

Three consumers read the tags, and each needs different things:

| consumer | needs |
|---|---|
| the kit itself | to find its own tickets again (the stamp), and to find a finding's ticket when a person filed it by hand (the correlation key) |
| the people working the tickets | to filter by where it came from, which environment, how bad, whether it is known-exploited, and what is being asked |
| dashboards (Jira security tickets, Freshservice later) | stable, low-cardinality dimensions to group by |

## 2. The dimensions, and what the kit writes today

Every kit label starts with the umbrella stamp (`TICKET_STAMP_LABEL`, default `secure-cicd-kit`), so
a person can see whose label it is and the kit never collides with a team's own labels. In the table,
`<p>` is that prefix.

| dimension | label the kit writes (default) | values | cardinality |
|---|---|---|---|
| ownership (the umbrella) | `<p>` | one | 1 |
| **source type** | `<p>-src-<type>` | `scan-app`, `project`, `subscription`, `account`, `resource`, `pentest`, `review`, `audit`, `usr`, `cloud-tool`, `other-tool` (the kit's own scan findings carry the scanner family label instead: `sca`, `sast`, `iac`, `container`) | 11 |
| **environment / tenant / account** | `<p>-env-<label>` | the submitter's environment label, slugged (e.g. `azure-commercial-prod`, `azure-government-prod`, `aws-prod`) | one per environment |
| **asset class** | `<p>-asset-<scheme>` | `repo-path`, `azure-resource`, `aws-resource`, `github-repo`, `engagement` | 5 |
| **finding class** | the floor class is routed, not labelled, today (`class` in routing: `secret`, `kev`, `malicious`, `finding`); KEV is labelled (below) | 4 | |
| **severity** | `<p>-sev-<severity>` | `critical`, `high`, `medium`, `low`, `info` | 5 |
| **KEV** | `<p>-kev` | present or absent | 2 |
| **disposition / request** | `<p>-tpl-<template>` names what is asked (`false-positive`, `accepted-risk`, `mitigation`, `exemption`); the ticket CLASS is in the machine-owned block (`FALSE_POSITIVE_REQUEST`, ...); a granted disposition lives on the protected branch, never in a label | 8 templates | |
| **SLA** | `<p>-sla-overdue` (only when breached; KDEC-024). The due date is in the block, never in the tracker's due-date field | 1 | |
| **correlation key** | `<p>-ck-<32 hex>` (on GitHub a 50-character hashed short form) | one per finding | high -- a SEARCH AID only: the full key in the stamp field or the block decides (KDEC-043, docs/ticketing/TICKET-GOVERNANCE.md) |
| **review id** | `<p>-review-<review id>` | one per review | medium |
| **template type** | `<p>-tpl-<template>` | `finding`, `false-positive`, `accepted-risk`, `mitigation`, `exemption`, `extension`, `nofix-recheck`, `closure` | 8 |
| lifecycle markers | `<p>-linked`, `<p>-nofix`, `<p>-recheck-due`, `<p>-fix-available`, `<p>-extension-<n>`, `<p>-remediated`, `<p>-superseded`, `<p>-disagreement` | | small |

The stamp FIELD (`JIRA_STAMP_FIELD`, a custom field) stays the kit's authoritative identity for
tickets it created; the `-ck-` label is what lets a ticket the kit did NOT create be linked and found
again without anyone editing a custom field.

## 3. Labels, components or custom fields -- the trade-offs

| mechanism | good for | bad for | the kit's use today |
|---|---|---|---|
| **labels** | anything, no admin needed; one token each; searchable by JQL; survive a move between projects | free text: typos make new values; no allowed-value list; hard to report on high-cardinality ones | every dimension above (because no Jira admin action is needed to start) |
| **components** | a small, curated set per project (teams, product areas); allowed values enforced; default assignee per component | per PROJECT: a value must exist in every project a ticket can be routed to; an admin creates them | only where a routing rule names them (`ticket_routing` `components`) |
| **custom fields** (select lists) | a governed dimension with an allowed-value list, reportable in dashboards, one value per ticket | an admin creates and maintains them; per-site ids (`customfield_<n>`); must be on the screen to be settable | the stamp field only |

A reasonable end state (for the owner to decide): **custom select fields** for the four low-cardinality
dimensions dashboards group by (source type, environment, severity, template type); **labels** for
the identifiers and the lifecycle markers (correlation key, review id, linked, nofix, extension-n);
**components** for the owning team, set by routing. Until a Jira admin creates the fields, labels carry
everything, which is what the kit does today.

## 4. Manually created tickets -- the migration note

A ticket a person made carries none of the above. The kit still finds it: before every create, the
search reads every ticket in the repository's ticket projects and surfaces any that names the same
asset AND identifier, or the identifier and a close title, as a **candidate** (never merged). Once a
person confirms the link in a finalized review, the kit adds `<p>-ck-<key>` and `<p>-linked` and a
comment; from then on it is an exact match.

To bring an existing backlog in without waiting for the next finding:

1. Run `tickets.search` with a `tracker_query` over the project (paged with `page_token`) and export
   the result: each ticket shows `manual: true` and its `linked_cluster_keys` (empty for unlinked ones).
2. For each manual ticket that tracks a finding, submit that finding (`tickets.submit`, template
   `finding`) in a review; the dry run shows the manual ticket as a candidate; the reviewer records
   `link` decisions; the real run labels them (and records each as a closed duplicate under it).
3. Tickets that track nothing the kit knows stay as they are: the kit never edits a ticket it neither
   created nor was told to link.

Nothing is renamed, re-typed or moved; only labels and one comment are added.

## 5. Decisions the owner must make (each with the default the kit uses until then)

| id | decision | default |
|---|---|---|
| T-1 | the umbrella prefix for every kit label | `secure-cicd-kit` (`TICKET_STAMP_LABEL`) |
| T-2 | labels vs custom fields for source type, environment, severity and template type | labels until a Jira admin creates select fields |
| T-3 | the source-type list (add or merge values) | the eleven above |
| T-4 | the environment labels (one per tenant / subscription family / account, or per environment tier) | whatever the submitter sends, slugged; no list enforced |
| T-5 | whether the floor class (secret / KEV / malicious) gets its own label beside routing | KEV only (`<p>-kev`) |
| T-6 | whether the review id label is kept after closure (audit trail vs label clutter) | kept |
| T-7 | components: which team owns which source type or environment | none set unless a routing rule names one |
| T-8 | Freshservice: the same dimensions as Freshservice tags/custom fields | the same names; the adapter is built (KDEC-043): tags are set at creation and lifecycle markers go in private notes unless FRESHSERVICE_MARK_MODE=tags (docs/architecture/TICKETING_BACKENDS.md 4A) |
| T-9 | the Jira projects per source (routing): e.g. cloud findings to the cloud team's board, pentests to the security board, requests to GRC | everything to `JIRA_PROJECT` until a `ticket_routing` rule says otherwise |
