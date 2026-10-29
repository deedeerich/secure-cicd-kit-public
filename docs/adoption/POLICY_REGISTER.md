# The policy register: who decided how hard each control bites

> For an administrator registering policy per **enterprise, org, team (dev group), product,
> repository and environment tier**, and for a tool that proposes registrations. Code:
> `scripts/policy_registration.py`. Schema: `schemas/policy-registration.schema.json`
> (`schema_version: 2`). Proofs: `tests/prove_policy_registration.py`,
> `tests/prove_authority_floor.py`, `tests/prove_crawl_floor.py`,
> `tests/prove_gate_policy_enforcement.py`, `tests/prove_gate_reads_rung.py`,
> `tests/prove_deploy_environment_protection.py`.

## The default: crawl — only secrets block

With **no registration anywhere**, every run is at the kit default (`policy_source: KIT_DEFAULT`):

| control | what it contributes to `routing_result` |
|---|---|
| secrets (`secret-scan`, a secret in an image, a known-malicious package) | `BLOCKED`, at every tier — unless that ONE secret-scan finding is excepted, ticketed and attributed ([Secret exceptions](#secret-exceptions-one-finding-ticketed-logged)) |
| every other scanner's findings | `PROCEED_WITH_ADVISORY`, cause `FINDINGS_NOT_BLOCKED` — recorded, never `PROCEED` |
| the kit could not run or trust its own scan (a crash, `COLLECTION_FAILED`, a hollow or unreadable scan, a bootstrap failure) | `EVIDENCE_UNTRUSTED` — the gate **stops at every tier** (owner ruling O-24: a pipeline that silently did not scan cannot count as "scanned, advisory") |
| a coverage gap (a version no carried scanner reads, e.g. PHP 8.5) | `PROCEED_WITH_ADVISORY` (`VERSION_GAP` / `COVERAGE_PARTIAL`) — not untrusted evidence; KDEC-014 still applies at uat/prod deploys |
| uat / prod deploy | one required reviewer on the GitHub environment, self-review prevented |

Anything **stronger** than that (walk, run, a control that blocks) is a decision a named person makes
in the register. **Nothing is ever weaker than crawl** (KDEC-018: *"You can't drop below crawl ever …
Only up."*): no rung sits below it, secrets never soften, and no run input — `advisory_mode`,
`soft_fail_sast`, `paths`, `language`, … — lets a secret or a scan the kit could not run or trust
through (`tests/prove_crawl_floor.py` drives every weakening input, attributed, through the gate).
`paths` narrows every scanner **except the secret scan**, which always covers the repository root.
**The malicious-package scan is part of the crawl floor** (KDEC-020; owner: these *"should be on if
needed yes?"*): a run that receives `enable_malicious_pkg_scan: false` is refused by the resolver,
`CHERRY_PICK_BELOW_FLOOR` (`BLOCKED`), naming the input, and a register entry softening
`malicious-deps` is refused the same way (`tests/prove_crawl_floor.py` K6/K7). This decides only
that the scan RUNS; whether a confirmed `MAL-` finding should block at crawl is an open owner
question (KDEC-020) — the gate's handling of that finding is unchanged.

## Where the register lives

One format, two places. A pull request can write neither.

| copy | path | holds | read from |
|---|---|---|---|
| **central** | `policy/policy-registration.json` in **your copy of the kit** | every enterprise, org, team, product and repository scope, the org → enterprise map (`orgs`) and the repository → team/product map | the kit delivered by `$/`, at the kit commit the caller pins — a change reaches a repository when it moves its pin |
| **repository** | `.security/policy-registration.json` in the calling repository (put it under CODEOWNERS) | that repository's own entries; scopes name only `environment_tier` | the repository's **protected default branch**, fetched by ref — never the run's checkout |

The repository file may only **tighten** what the central register gives it
(`REPOSITORY_FILE_SOFTENING` otherwise). The neutral kit ships no central register; a single
repository uses only its own file. Unreadable, unparseable or schema-violating is
`REGISTRATION_UNAVAILABLE` (`EVIDENCE_UNTRUSTED`) — **never** the default.

## Precedence (most specific wins)

```
kit default  <  enterprise  <  org  <  org+team  <  org+product  <  org+team+product  <  repository
```

At each level a scope **with** `environment_tier` ranks above the same scope without one. Every
matching entry is applied in that order on top of what the run inherited. Two entries with the same
scope are a conflict, refused by name (`POLICY_REGISTER_CONFLICT`), never resolved by file order.
The org is the repository's owner (case-insensitive); team and product come from the central
`repositories` map — an unmapped repository gets its org's entries only. The **enterprise** is the
org's value in the central `orgs` map (`{"org-a": "my-enterprise", "org-b": "my-enterprise"}`); an
enterprise scope names only `enterprise` (and optionally `environment_tier`) and binds every
repository of every org mapped to it.

**Once the `orgs` map defines an enterprise, an org it does not name still runs — at the enterprise
floor** (KDEC-020, which supersedes KDEC-019 item 1; owner 2026-10-23: *"I thought we agreed unmapped
orgs would be rolled in at whatever level the enterprise or other orgs are at"*). With one enterprise
defined the org gets that enterprise's entries; with several it gets, at each tier, the **strictest**
of them (higher rung, then stronger controls, then stronger deploy approval — never the lower). Its
own org, team, product and repository entries may tighten above that floor; one that goes below it is
`POLICY_BELOW_AUTHORITY_FLOOR` (`BLOCKED`). It is never a refusal and never silent: the run carries
the notice **`ORG_UNMAPPED_RAN_AT_ENTERPRISE_FLOOR`** — naming the org, the enterprise and rung used,
and saying "add it to the orgs map" — in the resolution's `notices` and `notes`, the `policy_notices`
output, a workflow warning and the gate's policy summary. (`ORG_NOT_UNDER_ENTERPRISE`, the refusal
briefly built for KDEC-019 item 1, is retired and no longer emitted.)

**With no enterprise ENTRY, an org the register does not know runs at the strictest registered org**
(KDEC-022 item 1; owner 2026-10-23: *"Yes you should get the strictest from the orgs."*). When the
register has an `orgs` map or org entries but no enterprise entry, an org that is not in the map,
named by no entry and owns no registered repository runs, at each tier, at the strictest registered
org's org-level entries — the same comparison as above. Its own repository file may tighten above
that, never go below it (`REPOSITORY_FILE_SOFTENING`); the floor org's per-finding exceptions never
travel. Notice: **`ORG_UNMAPPED_RAN_AT_STRICTEST_ORG`** (the org, the floor org, the rung, the tier).
With no register at all nothing changes (the kit default, crawl). Proven:
`tests/prove_authority_floor.py` A12.

## The authority floor: narrower scopes only tighten

KDEC-018 (owner, 2026-10-22): *"whatever is allocated at the org or enterprise (if there is a higher
authority) must be the level we run at across the entire enterprise. So if they say walk everyone is
at walk."*

- The rung and every control's routing set by the **highest authority** that applies (the enterprise
  entry when there is one, else the org's) is the **floor** for everything beneath it.
- An entry that leaves the rung, a control, or a deploy approval a registered entry set **weaker**
  than what it inherited is refused: **`POLICY_BELOW_AUTHORITY_FLOOR`** (`BLOCKED`) — with an
  unexpired decision or without one. That covers an org under its enterprise; every team, product,
  team+product and repository entry; and a tier-qualified entry beneath the tier-less entry of its
  own scope (an org at `walk` cannot put `dev` at `crawl` — register `crawl` tier-less and raise the
  higher tiers instead). Its tightening, if any, is applied, so the floor holds in the record.
- Raising the rung is a tightening even where the ladder routes one class differently (at `run`,
  pre-existing findings on a tracked SLA are advisory).
- The rung and the controls cannot be softer than crawl at all, so the **only softening left** is of
  the kit default's uat/prod deploy approval, and only the authority (an enterprise or org scope) may
  make it, with its decision — recorded as a weakening and never honoured by the deploy (below).
- Teams still differ where it is not a rung: team size (`team_pattern`), deploy approval
  (tightening), which controls they raise.
- **Per-finding exceptions are unaffected**: a `secret_exceptions` item makes ONE finding advisory and
  is not a rung change, so any scope may carry one (below). `--validate` names every below-floor
  entry for every repository and org it would reach.

The tiers must stay ordered for every repository: `sandbox ≤ dev ≤ test ≤ uat = prod`
(`CELLS_NOT_MONOTONE` otherwise) — register uat and prod together.

## An entry

```json
{
  "id": "org-a-payments-prod-walk",
  "scope": {"org": "example-org-a", "team": "payments", "environment_tier": "prod"},
  "rung": "walk",
  "controls": {"deps-scan": "BLOCKED"},
  "team_pattern": "small_team",
  "deploy_approval": {"approver_groups": ["security", "platform"], "approvers_required": 1,
                      "self_review_prevented": "required", "ai_review": "advisory"},
  "decision": {"authority": "Named Person", "approver_role": "security-lead",
               "reason": "why", "decided_on": "2026-10-22", "expires": "2027-01-31",
               "exception_ref": "SEC-123", "environment_reviewers": ["payments-release-approvers"]}
}
```

| field | meaning |
|---|---|
| `rung` | `crawl` (only secrets block) · `walk` (findings owe a decision: `DECISION_REQUIRED`) · `run` (findings block). The gate reads a job's findings at `new_critical_high` until per-finding classes reach it (ledger L44) |
| `controls` | per control class or scanner job, the weakest route it may contribute. `secrets`, `secret-scan`, `malicious-deps` accept only `BLOCKED`; nothing may be `PROCEED` (`CHERRY_PICK_BELOW_FLOOR`) |
| `secret_exceptions` | one secret finding each, ticketed and attributed (section below); never a class |
| `known_exploited_exceptions` | one finding whose CVE is on the CISA KEV catalog each, by fingerprint and CVE, on the same rules (KDEC-022) |
| `merge_reaches_tier` | the tier a merge reaches without a human gate (tier-less entries only). Pull requests and unnamed runs are evaluated there; **prod when none is declared** |
| `deploy_approval` | what the deploy verifies on its GitHub environment (below). `ai_review` is `advisory` or `none`: an AI review comments on pull requests and is **never** a gate or an approval |
| `decision` | **required on every entry**: `authority` (a named person), `reason`, `decided_on`, `expires`. An entry that changes enforcement at uat or prod (a uat/prod tier, or no tier) must also name `environment_reviewers` |

**Tightening** (walk, run, a control raised) is an attributed decision. A **softening** below the
floor is refused (above); the authority's softening of the kit default deploy approval in force is an
attributed weakening row in the posture record and routes `PROCEED_WITH_ADVISORY` (cause
`WEAKENING_ATTRIBUTED`). An **expired** decision
never softens anything: its tightening stays in force, its softening reverts, and the run routes
`DECISION_REQUIRED` (`POLICY_DECISION_EXPIRED`) until someone re-decides it. A missing field is
`POLICY_DECISION_UNATTRIBUTED` (`BLOCKED`).

## Secret exceptions: one finding, ticketed, logged

Owner ruling 2026-10-22: *"There must be the possibility of exceptions … but they must be requested
and logged with tickets that have explanations."* A secret still blocks at every tier, and softening
secrets as a class or a scanner (`controls: {"secret-scan": "PROCEED_WITH_ADVISORY"}`) is still
refused, `CHERRY_PICK_BELOW_FLOOR`. What an entry may carry is a list of exceptions, each for **one
finding**:

```json
"secret_exceptions": [
  {"finding": "a1b2c3d4e5f6", "ticket": "SEC-1234",
   "explanation": "test credential in a fixture; rotated, removal tracked on the ticket",
   "approver": "Named Person", "expires": "2026-12-31",
   "environment_reviewers": ["platform-approvers"]}
]
```

| field | rule (refused by name when broken — the exception is then never in force and the secret BLOCKS) |
|---|---|
| `finding` | the finding's fingerprint as the security report computes it (`fp`, 12 lowercase hex; the report prints it as "Legacy fingerprint" under each blocking finding, and the `secret_findings` report output lists them). Secret findings carry no durable identity by design, so this is the key; a scanner or rule change orphans it and the secret blocks again (fail-safe). Anything else — `secrets`, a scanner, a wildcard — is `SECRET_EXCEPTION_NOT_FINDING_SCOPED` |
| `ticket` | a work-item key `<PROJECT>-<digits>` (`scripts/ticket_reference.py`, KDEC-013), within `numbers.ticket_min_digits`..`ticket_max_digits` when the register sets them (the work overlay's range goes there). Missing or malformed: `SECRET_EXCEPTION_UNTICKETED` |
| `explanation`, `approver` | why, and the named person who approved it. Missing: `SECRET_EXCEPTION_UNATTRIBUTED` |
| `expires` | `YYYY-MM-DD`; unreadable is `SECRET_EXCEPTION_UNATTRIBUTED`, past is `SECRET_EXCEPTION_EXPIRED` (so is an expired entry decision). Silence never renews it |
| `environment_reviewers` | here or on the entry's `decision`, required when the entry applies at uat/prod (a uat/prod tier, or no tier): `SECRET_EXCEPTION_UNATTRIBUTED` otherwise |

It lives only in the register — the central copy, or the repository's own file on its protected
default branch (the one softening a repository file may carry) — never in a run input. The gate
excepts the secret scan's findings only when **every** secret it found is named by an exception in
force, one exception per finding, and the report's fingerprints account for exactly the scan's count;
a second secret, the same fingerprint twice, or a count the report cannot account for, and the run is
`BLOCKED`. Excepted, the run routes `PROCEED_WITH_ADVISORY` with cause `SECRET_EXCEPTION_ATTRIBUTED`,
`secret_gate` is `EXCEPTED` (never `PASS`), and each exception — fingerprint, ticket, approver, expiry,
entry — is written to the gate summary and the run record (`secret_exceptions`); refused exceptions
are listed in the summary with their refusal. An image secret and a known-malicious package are not
exceptable. `--validate` reports every refused exception. Proven locally:
`tests/prove_gate_policy_enforcement.py` (`sx_*`), `tests/prove_gate_run_record.py`,
`tests/prove_report_counts_findings.py`.

## Exploited in the wild: a CVE on the CISA KEV catalog blocks at every rung

KDEC-022 item 3 (owner, 2026-10-23: *"confirmed malicious packages should block if we know there is
an exploit in the wild right?"*). Known-malicious packages (OSV `MAL-`) already block in every mode.
Now a dependency or image CVE on the **CISA Known Exploited Vulnerabilities** catalog blocks too, at
every rung — crawl and `advisory_mode` included: **`FINDING_KNOWN_EXPLOITED`**, `BLOCKED`. The report
publishes every dependency/image finding's CVE (`cve_findings`, every severity, before dispositions);
the gate's `kev` step (`.github/actions/known-exploited`, `scripts/known_exploited.py`) reads the
catalog once per run (a date-keyed cache), pins it in the evidence (catalogVersion, dateReleased,
sha256) and matches; the gate enforces. An unreadable catalog is `kev_state UNAVAILABLE`: in the
summary and outputs, routed `PROCEED_WITH_ADVISORY` (cause `KEV_UNAVAILABLE`) — never a pass. The NVD
path runs the same check on its own SARIF and, resolving no policy, honours no exception.

One such finding may be excepted, on the secret-exception rules above plus its CVE:

```json
"known_exploited_exceptions": [
  {"finding": "0123456789ab", "cve": "CVE-2021-44228", "ticket": "SEC-4400",
   "explanation": "vendor appliance pins it; the lookup is disabled; upgrade tracked on the ticket",
   "approver": "Named Person", "expires": "2026-12-31", "environment_reviewers": ["platform-approvers"]}
]
```

Refused by name (`KEV_EXCEPTION_NOT_FINDING_SCOPED` — no fingerprint or no CVE, `_UNTICKETED`,
`_UNATTRIBUTED`, `_EXPIRED`, and the history refusals below) the finding blocks. Excepted, the run
routes `PROCEED_WITH_ADVISORY` (cause `KNOWN_EXPLOITED_EXCEPTION_ATTRIBUTED`), `kev_verdict` is
`EXCEPTED`, never clear. Proven locally: `tests/prove_known_exploited.py`.

## Exception history and the renewal cap

KDEC-018 item 4 (owner, 2026-10-22): *"when they resurface it needs to be clear they were exempted
previously and shown. Because endless exemptions/exceptions are not a thing."* Every dated exception
the kit honours may carry **`renews`** — its PRIOR grants, one object each:

```json
"renews": [{"ticket": "SEC-1200", "approver": "Named Person", "from": "2026-01-10", "expires": "2026-04-10"},
           {"ticket": "SEC-1311", "approver": "Other Person", "from": "2026-04-10", "expires": "2026-07-10"}]
```

| exception | where `renews` goes |
|---|---|
| a secret exception | the `secret_exceptions` item |
| a register softening (the authority's softening of the kit default deploy approval — the only one left) | the entry's `decision` |
| the deploy's version-gap exception at uat/prod (KDEC-014) | the deploy input `weakening_renews` (JSON), beside `weakening_expires` |

- **Shown wherever it applies**: the gate summary, the gate's `secret_exceptions_applied`, the
  posture summary, the run record (`secret_exceptions[].history`, `policy_exceptions[]`), the
  deploy summary and `outcome.json` — *"previously excepted 2 time(s) since 2026-01-10, tickets
  SEC-1200, SEC-1311, approvers Named Person, Other Person"*, or *"first exception"*.
- **Capped**: `numbers.max_exception_renewals` in the **central** register (the authority's; a
  repository file may not set it), kit default **2**, an integer **0–5** — never unlimited (0 = no
  renewal; 5 bounds one exception at six grants, about eighteen months at quarterly expiries; past
  that a recurring exception is a standing policy, or for a secret, a secret to remove). More prior
  grants than the cap: **`EXCEPTION_RENEWAL_LIMIT`** — the secret BLOCKS, the softening reverts
  (`DECISION_REQUIRED`), the version-gap deploy is `VERSION_GAP_REFUSED`. The deploy takes the
  gate's `max_exception_renewals` output and holds the stronger of it and the kit default.
- A history the kit cannot read is not "no history": the exception is refused as unattributed.
- **The count comes from git, not from the register's say-so** (KDEC-022 item 2, option D, "B plus
  C"). The resolver walks `git log --follow` of the protected register file on the default branch
  and collects every distinct (ticket, expiry) each exception ever had — secret and known-exploited
  exceptions by finding, softening decisions by entry. The declared `renews` must list every prior
  grant git shows; fewer (the history was erased) is **`EXCEPTION_HISTORY_TAMPERED`** (`BLOCKED`).
  The cap binds the derived count. A history git cannot show — a shallow clone, a register in no git
  history, a central copy that is not its newest commit — is **`EXCEPTION_HISTORY_UNVERIFIED`**,
  refused like an unreadable one, never zero renewals. `resolve-policy` clones the default branch
  blob-less with its history for this (measured on this kit: 1.0 MB plus 2.4 MB fetched by the walk,
  against 2.8 MB at depth 1), and clones the kit's own history for the central register when GitHub
  names the action's repository and ref (not yet run hosted; without it central exceptions are
  UNVERIFIED and refused).
- **And Jira is checked weekly (C)**: `exception_due.py --cross-check` (the resurface job runs it)
  holds each exception's ticket to the register — it exists, names the same approver, and its links,
  text or comments show each renewal. A disagreement is **`EXCEPTION_TICKET_MISMATCH`**, in the run
  summary and (applied) a comment on the ticket. The gate never reads Jira.
- `scripts/exception_due.py` (below) resurfaces every exception as it comes due.

Proven locally: `tests/prove_exception_lifecycle.py`, `tests/prove_exception_history_derived.py`.

### Resurfacing: exceptions come back onto their ticket when they come due

`scripts/exception_due.py` lists every exception due within N days (default 14) and every expired
one — register secret exceptions, register decisions (central and the repository's file), and the
literal `weakening_expires` records in the caller's workflows (the deploy's version-gap exception) —
each with its full history, renewal count and cap: deterministic JSON plus a human summary. An
unreadable register or workflow exits 3 (`REGISTRATION_UNAVAILABLE`), never "nothing due".

`.github/workflows/reusable-exception-due.yml`, called weekly by `templates/exception-due.yml`:

- the **list** job (no credential, `contents: read`) writes the list to the job summary and an
  artifact, and fails on an unreadable source;
- the **resurface** job, armed only on a schedule or dispatch on the default branch and only when
  something is due, takes the Jira credential from the protected environment (**Jira only**, KDEC-017
  item 5; the same settings as the ticket reconciler) and, with `apply: true`, reopens a closed
  ticket and comments on it — or creates ONE issue for an unticketed exception, found by its stamp
  next time. Every comment says plainly that it was excepted before (history, count, approvers,
  expiry) or that it is a first exception, and that it is now due. No Jira credential:
  `NOT_CONFIGURED`, and the list job's summary and artifact stand.

A `weakening_expires` written as an expression cannot be read from the file and is named in the
summary, not guessed. Proven locally with a recording fake Jira: `tests/prove_exception_due.py`.
Owed: a hosted scheduled run, and a run against a personal Jira.

## The register document

```json
{"schema_version": 2, "register_id": "...",
 "sign_off": {"by": "Named Person", "role": "security-lead", "date": "2026-10-22", "reference": "REG-1"},
 "proposed_by": "optional: the tool and run that proposed it",
 "environment_names": {"production": "prod", "staging": "uat"},
 "orgs": {"org-a": "my-enterprise", "org-b": "my-enterprise"},
 "repositories": {"org-a/payments-api": {"team": "payments", "product": "ledger"}},
 "policies": [ ...entries... ]}
```

`sign_off` is required: a register nobody signed off is a proposal (`POLICY_DECISION_UNATTRIBUTED`).
A harness that analyses team types **proposes** a document in exactly this format and sets
`proposed_by`; a person reviews it and adds `sign_off`. Unknown fields anywhere are refused (the
reader is an allowlist), and so is `schema_version: 1` (the retired per-repository cell format).

Validate before merging — wire this into the register's own pull-request check:

```
python3 scripts/policy_registration.py --validate policy/policy-registration.json --origin central
python3 scripts/policy_registration.py --validate .security/policy-registration.json --origin repository
```

It refuses everything resolution would refuse anywhere: schema, conflicts, attribution, expired
decisions and non-monotone tiers for every mapped repository and every org — an org the `orgs` map
leaves out is checked against the enterprise floor it will run at (KDEC-020), not refused.

## Deploy approval: read back from the environment

At uat and prod both deploy reusables read the GitHub environment they run in
(`GET /repos/{owner}/{repo}/environments/{name}`, read-only) before login and refuse unless its
required reviewers satisfy the demand: at least one reviewer, **self-review prevented**, and — when
`approver_groups` is set — every reviewer one of those teams (so the approver is from the group and
is not the deploying developer). Outcomes: `environment_protection` in `assurance-taxonomy.yaml`.
Pass the security gate's `deploy_approval` output to the deploy's `deploy_approval` input
(`templates/build-deploy.yml` does). The deploy holds the **stronger** of that value and the kit
default, because it cannot tell a value the gate emitted from one a caller typed: a register
softening of deploy approval below the uat/prod default is recorded by the gate and **not** honoured
by the deploy. If the API cannot be read, uat/prod refuse (`ENVIRONMENT_PROTECTION_NOT_ESTABLISHED`).

### One approver list, shared with the landing zone (OF-5 K-9, K-1)

The landing zone writes each uat/prod environment's reviewers; the deploy checks them against this
register. Two lists drift, and every release is then refused -- so there is **one** list. Name it once
in the central register and point every tier's `deploy_approval` at it:

```json
"approver_lists": {"deployment-approvers": ["architects", "security", "platform"]},
...
"deploy_approval": {"approver_groups_from": "deployment-approvers", "approvers_required": 1,
                    "self_review_prevented": "required"}
```

Or keep the list in its own file -- the **configurable source** -- beside the central register, the
same file the landing zone's hand-off write reads (`"approver_lists_source": "approver-lists.json"`,
holding `{"approver_lists": {...}}`). Resolution and `--validate` read it; its sha256 is in the
resolution notes; it cannot be read -> `REGISTRATION_UNAVAILABLE`, never the default. Refused by name:
`approver_groups` and `approver_groups_from` in one entry, or `approver_lists` and
`approver_lists_source` together (`POLICY_REGISTER_CONFLICT`); a name no list defines, or a
repository file naming a list -- the list is the central register's (`REGISTRATION_UNAVAILABLE`). The
resolved `deploy_approval` output carries the groups and the list's name. The landing zone reads that
list and refuses a worksheet that disagrees (its `HANDOFF_APPROVER_LIST_MISMATCH`). Proof:
`tests/prove_approver_list_source.py`.

**The approval itself (K-1).** At uat and prod the deploy also reads its own run's approvals before
login: an approval of the environment must exist, its reviewer may be neither the requester nor the
released commit's author (`SELF_DEPLOYMENT_APPROVAL`), and an independent approval's comment must
quote the digest being released, in full or by at least its first 12 hex characters
(`RELEASE_APPROVAL_NOT_BOUND_TO_DIGEST`). `deploy_approval.confirm_digest: required` demands the same
below uat; nothing relaxes it at uat/prod. Outcomes: `release_approval`.

## What a work administrator creates

1. In the private kit repository: `policy/policy-registration.json` (copy
   `templates/policy-register.central.example.json`), with the `orgs` map placing both orgs in
   the enterprise, the enterprise entry (the floor for both), each team and product, the
   `repositories` map (from the harness proposal), and CODEOWNERS on `policy/`.
2. A pull-request check on the kit repository running `--validate` on it.
3. For each repository that needs its own tightening: `.security/policy-registration.json` on its
   default branch (copy `templates/policy-registration.example.json`), under CODEOWNERS.
4. On every uat and prod GitHub environment: required reviewers (the approver teams), **prevent
   self-review** on. The deploy refuses without them.
5. Callers pass `target_environment` to the security workflow when a run is for a named
   environment, and `deploy_approval` from the security workflow to the deploy.

## What the gate emits

`policy_resolution`, `policy_source`, `policy_chain` (entry ids applied), `rung_declared`,
`rung_effective`, `policy_mode` (derived; no `policy_mode` or `rung` input exists, and a supplied
one is `POLICY_MODE_SUPPLIED`, `BLOCKED`), `effective_minimum`, `policy_divergences`,
`environment_tier`, `team_pattern`, `unvalidated_human_workflow_paths`, `deploy_approval` — beside
`routing_result` and `advisory_causes`. The security-gate job ends on a `verdict` step: `BLOCKED`
and `EVIDENCE_UNTRUSTED` fail it at every tier (O-24); `DECISION_REQUIRED` and the advisories pass the gate and are refused by the deploy.

**The gate is the single enforcement point** (lane L-S, 2026-10-22; VERIFIED locally by
`tests/prove_gate_policy_enforcement.py`, `sep_*`). Scanner jobs report: each hands findings over its
own threshold to the gate as the job output `findings_state=FINDINGS` and fails only when it could not
scan or trust its result (a crash, `COLLECTION_FAILED`, a hollow or unparseable report). The secret
scan hands its secrets over too, and the gate blocks them at every tier unless each is excepted
(below); an image's secrets step and a known-malicious package still fail their own job. The workflow therefore
concludes as its verdict: at crawl an ordinary finding is green with `PROCEED_WITH_ADVISORY`, and a
caller's `needs: security` (as in `templates/build-deploy.yml`) builds; a secret or a broken scan is
red. `advisory_mode` and `soft_fail_sast` still soften what a job hands over, as recorded weakenings;
they no longer keep a scanner job green, because nothing turns it red on a finding.

## Not yet

- ~~Scanner jobs still read `advisory_mode` / `soft_fail_sast`, not the derived policy: under crawl a
  scanner job with findings still ends red.~~ **Closed by lane L-S (2026-10-22):** scanner jobs no
  longer fail on findings; the gate enforces the resolved policy alone (above). Still open: the scanner
  half proper (`resolve` consuming the policy to choose depth and scope; EP-1) — enforcement no longer
  depends on it.
- Per-finding classes (new vs pre-existing on a track) are not in the gate (ledger L44): a job's
  findings are read at `new_critical_high`, the strictest non-secret class.
- Hosted runs: none of this has run on GitHub yet (Actions minutes are blocked); every proof is local.
