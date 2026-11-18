# ARCH-05 · The Dependabot triage

```
Truth State:  drawn 2026-11-06 from the files cited below. The same on the trunk and in
              Release 4 (main 10ffcea).
Audience:     whoever turns on auto-merge for Dependabot, and whoever reviews what merged unseen
Guide:        docs/adoption/DEPENDABOT_TRIAGE.md (the rules, criterion by criterion)
```

## 1 · One decision per Dependabot pull request

```mermaid
flowchart TD
  PR["Dependabot opens or updates a PR"] --> TRIG["pull_request_target<br/>caller AND reusable read from the DEFAULT branch<br/>nothing from the PR is checked out"]
  TRIG --> AUTH{"PR author is dependabot[bot]?"}
  AUTH -->|"no"| NONE["No job runs"]
  AUTH -->|"yes"| CLS["classify (contents: read, pull-requests: read)<br/>fetch-metadata, files, diffs, branch protection"]
  CLS --> EXC{"Touches an excluded path?<br/>tests/consumer-fixture/** by default"}
  EXC -->|"yes"| CLOSE["close<br/>(pull-requests: write)"]
  EXC -->|"no"| RULES{"Every criterion holds?<br/>patch/minor, not protected, no breaking signal,<br/>only dependency metadata changed, lockfile consistent,<br/>actions pinned by SHA, base branch REQUIRES the scan gate"}
  RULES -->|"no, or anything unreadable"| HUMAN["human-review: label, one comment saying why,<br/>an earlier auto-merge switched off"]
  RULES -->|"yes"| AM["auto-merge: gh pr merge --auto --squash<br/>(contents: write)"]
  AM --> WAIT["GitHub merges only when every required check passes<br/>(never --admin)"]
  CLS --> REC["decision.json artifact (90 days) + step summary"]
```

Cited: `.github/workflows/reusable-dependabot-triage.yml` (jobs `classify`, `auto-merge`,
`human-review`, `close`), `templates/dependabot-triage.yml` (the consumer's caller),
`.github/workflows/dependabot-triage.yml` (the kit host's own caller, `required_checks:
"Self-test required"`), `.github/dependabot.yml`.

## 2 · What has to be true in the repository settings

```mermaid
flowchart LR
  S1["Settings: Allow auto-merge ON"] --> OK["An armed auto-merge can complete"]
  S2["Ruleset on main requires the scan gate<br/>(kit host: Self-test required)"] --> OK
  S3["Dependabot alerts and security updates ON<br/>.github/dependabot.yml committed"] --> OK
  S4["Optional DEPENDABOT_METADATA_TOKEN<br/>(Dependabot alerts: read)"] --> URG["Security updates linked to their advisory;<br/>a protected package's fix marked urgent"]
```

- Without "Allow auto-merge" the auto-merge job comments on the PR and nothing merges.
- Without the scan gate as a **required** check every PR is `human_review` / `scan_gate_not_required`
  (fail closed).
- The vulnerability and malicious-package criteria are **delegated to the security gate**; they hold
  only because the gate is a required check.
- **Not established**: the provenance or signature of the new package version
  (`provenance: not_established` on every decision). Not yet run on GitHub (the hosted plan is in the
  guide, section 6).

Proof: `tests/prove_dependabot_triage.py` (D1..D8), `tests/prove_kit_dependabot_triage_caller.py`
(K1..K3), `tests/prove_dependabot_bump_mergeable.py`, `tests/check_action_pins.py` P6..P8.
