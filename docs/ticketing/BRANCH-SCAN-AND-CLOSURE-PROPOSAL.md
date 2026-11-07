# Branch scanning and rescan-driven closure -- a PROPOSAL, with discovery and adoption

```
Status:    PROPOSAL (the owner's, 2026-11-04; KDEC-037). The closure half is BUILT: a clean kit rescan
           on a branch not mapped to the ticket's environment records "fix observed on <branch>"; one on
           the mapped branch closes (scripts/ticket_submit.py; tests/prove_ticket_intake_v2.py V4).
           Scanning every branch is the adopting team's configuration (templates/security.yml).
Config:    KIT_API_BRANCH_ENVIRONMENTS, e.g. main=prod,release/*=prod,test=test,develop=dev
           (unset: the default branch is prod, nothing else maps).
```

## 1. The proposal

The owner: scanners run on ALL branches, including feature branches, triggered by a pull-request push.
A clean scan on a feature branch records "fix observed on <branch>". The ticket closes only when the
fix reaches the branch mapped to the ticket's environment; the branch-to-environment mapping is
configuration (main/prod, dev, test).

1. **Scan where the work is.** `templates/security.yml` and `build-deploy.yml` already scan on
   `pull_request` to the default branch. Adopting teams widen `branches:` to every long-lived branch and
   add `pull_request` for every target branch (the cost: one scan per push).
2. **Observe, then close.** A `closure` item with `verification.kind: scan` names a run of the kit's
   security workflow. The kit reads that run's evidence on ANY branch (the default-branch rule is
   relaxed only for closure verification), and checks the finding is gone and the run's scanners
   covered where it lived.
   - The run's branch maps to the ticket's environment (the ticket's `<stamp>-env-<environment>`
     label; or, with none, the default branch): the ticket is **Closed-Verified** by the rescan.
   - It does not: **"fix observed on <branch>"** is commented and labelled
     (`<stamp>-fix-observed-<branch>`, `TEMPLATE_FIX_OBSERVED`); the ticket stays open, waiting for the
     fix to reach the mapped branch.
3. **Mapping is data.** `KIT_API_BRANCH_ENVIRONMENTS` maps branch names (a trailing `*` matches a
   prefix) to environment names -- the same names findings carry in `environment`, compared after the
   same slugging as the ticket's label (`Azure Government Prod` is `azure-government-prod`); the first
   match wins; an unmapped branch closes nothing. A ticket with no environment label closes only on the
   mapped default branch.
4. **Nothing else changes.** A person may still verify (not the fixer); a fixer's resolve is still
   pending; the gate's dispositions are untouched (a ticket closing never clears a finding).

## 2. Current-state discovery checklist (what teams do today)

Ask each team, and record the answer before changing anything:

- [ ] Which branches exist and live long: `main`, `develop`, `release/*`, `hotfix/*`, environment
      branches (`dev`, `test`, `prod`)? Trunk-based or GitFlow?
- [ ] Which branch deploys to which environment, and how (a GitHub Environment, a pipeline variable,
      a person)? Is that written down anywhere the kit could read?
- [ ] Which workflows scan today, on which events (`push`, `pull_request`, schedule) and which branches?
      Which scanners run on pull requests and which only on the default branch?
- [ ] How long does a scan take, and what does a scan per push cost them (minutes, runners)?
- [ ] How do they close security tickets today: by hand, on merge, on deploy, never? Who closes them?
- [ ] Do tickets name an environment? A component? A branch?
- [ ] Do feature branches live long enough for "fix observed" to matter (days vs hours)?
- [ ] Who verifies a fix today, and is it ever the person who wrote it?
- [ ] Which repositories were vended by the landing zone (their workflows and environments are
      already the kit's shape) and which were not?
- [ ] Are there branch protections and required checks on the mapped branches?

## 3. Phased adoption -- easing teams in without a harsh drift from their process

The owner: "the landing zones are a good start."

| phase | who | what changes | what does not |
|---|---|---|---|
| **0. Observe** | everyone | Run the discovery checklist; set `KIT_API_BRANCH_ENVIRONMENTS` to the default only. Closure by a verifier who is not the fixer (already the rule). | Branch triggers; how teams close tickets. |
| **1. Landing-zone repositories** | repositories vended by the landing zone | Their environments are already GitHub Environments: map `main=prod` (and `develop=dev` where it exists). Widen `pull_request` to every target branch. Clean feature-branch scans record "fix observed"; the mapped branch closes. | Teams outside the landing zone. |
| **2. Opt-in teams** | teams that ask, or whose discovery shows GitFlow / environment branches | Add their mapping and branch triggers; one review of the first ten closures with the team. | Everyone else. |
| **3. Default** | all kit-adopting repositories | `security.yml` ships with every long-lived branch in `branches:`; the mapping is part of onboarding (the landing zone's vending fills it). | Verification by a person stays available everywhere. |
| **4. Measure** | security | Report closures by kind (rescan on mapped branch, verifier), time from fix-observed to closed, tickets reopened after a rescan closure. | -- |

Each phase is reversible: an empty mapping returns to "the default branch is prod", and a person can
always verify.

## 4. Open questions (with the kit's defaults)

- **O-37m** Which environments the landing zone's vending should write into the mapping. Default: only
  `main=prod`.
- **O-37n** Whether "fix observed" should move the ticket to an "in progress" status in the tracker.
  Default: no -- a comment and a label only.
