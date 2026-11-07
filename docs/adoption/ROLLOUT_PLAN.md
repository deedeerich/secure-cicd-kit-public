# Rolling the kit out without "a million hoops"

Status: PROPOSED (KDEC-041). The owner asked how painful adoption will be. The honest answer: **heavy in
week one without help, light afterwards if it is rolled out well.** This plan is the "rolled out well" part.
Three things carry the weight: `kit init` does the wiring in one command
([GETTING_STARTED_1_HOUR.md](GETTING_STARTED_1_HOUR.md)), every refusal says what to do in plain words
([../errors/ERRORS.md](../errors/ERRORS.md)), and the pilot friction log measures where the time really goes
([PILOT_FRICTION_LOG_TEMPLATE.md](PILOT_FRICTION_LOG_TEMPLATE.md)). Nothing here changes a setting by itself;
each wave is the owner's decision.

## 1. The waves, in order

| wave | which repositories | how they are wired | enforcement | moves on when |
|---|---|---|---|---|
| **1. Greenfield and landing-zone-vended** | new repositories, and every repository the landing zone vends | pre-wired: the vending runs `kit init` (or the repository starts from its pull request), so the first push already runs the gate | crawl from day one (only secrets, known-exploited and malicious packages block) | the friction summary shows at least 80% of wave-1 repositories green within the hour, and no error state that cost more than 30 minutes is without a fixed entry |
| **2. Existing repositories, at crawl** | active repositories with a team that owns them | the team runs `kit init` (the Actions button, or the CLI) and works the checklist | **report-only for N weeks** (N = 4 proposed): crawl, nothing new blocks but secrets, known-exploited and malicious packages; findings are read and ticketed | the team has triaged its backlog (every pre-existing finding is baselined, fixed or ticketed) and the friction summary for the team is green |
| **3. Walk, then run** | wave-2 repositories whose backlog is triaged | the policy register raises the rung per repository and tier ([POLICY_REGISTER.md](POLICY_REGISTER.md)) | walk: findings owe a decision; run: new criticals and highs block | the owner signs the register change |
| **Legacy** | repositories with a large inherited backlog or no active owner | wired at crawl like wave 2 | **never gated at walk until their backlog is triaged**: a gate that blocks every change on findings nobody can fix in a week is a gate people route around | the backlog triage is recorded; then wave 3 |

The rung never drops below crawl, at any wave (KDEC-018). "Report-only" means crawl, not "off": a
committed secret still blocks in week one.

## 2. Why this order

- **Greenfield first** costs least: no backlog, and kit init (or the vend) wires it before the first line of
  code, so the team never sees the kit as a hoop added later.
- **Existing repositories at crawl** learn the vocabulary on their own code without being blocked by
  findings older than the team. Their backlog is triaged before anything blocks on it.
- **Walk only after the backlog is triaged**, because walk makes every finding owe a decision; on an
  untriaged backlog that is hundreds of decisions on day one.

## 3. Who approves uat and prod, and how fast

The kit refuses a uat or prod deploy that nobody approved, that its own requester approved, or whose
environment lacks required reviewers (`ENVIRONMENT_REVIEWERS_ABSENT`, `SELF_DEPLOYMENT_APPROVAL`). So every
deploying team needs approvers who are available:

- **The approver SLA is the same business day.** A release request made by 14:00 local time is approved or
  answered (with the reason) the same business day.
- **Every uat and prod environment names a primary approver and a backup approver**, as two reviewer
  entries on the environment (kit init's environments spec names the platform team and the security team,
  either of which may approve). One named person alone is not enough: holidays happen.
- **Small teams** (one to four developers): the approvers come from **platform or security, outside the
  team**. A teammate approving a teammate's release is not separation of duties when the team is the whole
  chain (`HUMAN_CONTROL_UNVALIDATED`, `HUMAN_CONTROL_NO_SEPARATION`).
- **When the SLA is missed**, the requester escalates: (1) the backup approver, (2) at the next business day's
  start, the platform lead, (3) for a production incident, the break-glass path with its five-field exception
  record (KDEC-036). **A missed SLA never auto-approves anything**, and nobody lowers the environment's
  protection to get a release out: the deploy would refuse it anyway, and the refusal is the record that the
  SLA, not the control, needs fixing.
- The friction log records every wait on an approver as a `stuck` row at the step `approval`, so a slow
  approver pool shows up in the weekly summary before it becomes a workaround.

## 4. Week-one support (the "with help" part)

- A platform engineer pairs with each wave-1 and wave-2 team for its first repository: kit init, the checklist
  (the environment and OIDC commands need an admin), the first crawl run, reading the result.
- A shared channel where a developer pastes the plain sentence and the state name; every answer that was not
  already in [ERRORS.md](../errors/ERRORS.md) becomes an edit to it.
- The weekly friction summary (`python3 scripts/friction_summary.py`) is read in the platform team's weekly
  meeting; its worst step is next week's fix.

## 5. How this fits the other two guides

- **Auto-merge** stays off in every wave until a repository meets the criteria in
  [AUTOMERGE_RISKS_AND_ROLLOUT.md](AUTOMERGE_RISKS_AND_ROLLOUT.md): the kit's repositories first, then
  low-risk repositories at crawl, never one whose `main` deploys to production without an environment approval
  gate. kit init's `--automerge` only adds the "Allow auto-merge" step to the checklist; a person decides.
- **Branch protection** comes after the first green run, not before it: requiring `security / Security gate`
  on a repository whose first run has not passed blocks every pull request at once. The rulesets per
  repository type, and the environment reviewers this section describes, are in
  [BRANCH_PROTECTION_SETTINGS.md](BRANCH_PROTECTION_SETTINGS.md).

## 6. What would make this plan wrong

- If wave-1 teams routinely miss the hour, kit init is not doing enough: the summary's worst steps say what.
- If approvers miss the same-day SLA more than occasionally, the approver pool is too small: add a backup
  team rather than relaxing the environment.
- If report-only weeks end with an untriaged backlog, N was too short for that team: extend it for that
  team; never move it to walk on an untriaged backlog.

**Suggested mitigations** (PROPOSED; risk R-25 in `.context/products/secure-cicd-kit/risks.md`):
- M1 PROPOSED: run wave 1 on two pilot teams first and read their friction logs before inviting more.
- M2 PROPOSED: name the primary and backup approver pools before the first uat environment exists.
