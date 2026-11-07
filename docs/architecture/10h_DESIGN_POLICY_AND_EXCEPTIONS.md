# 10h · Design: the policy register, rungs, weakenings and exceptions

```
Kept:      2026-11-07, against the trunk at c1420ea. Boundary: TB-10 in 05_TRUST_BOUNDARIES.md.
Code:      scripts/policy_registration.py, scripts/rung_ladder.py, scripts/enforcement_axes.py,
           scripts/reviewer_signals.py, scripts/exception_history.py, scripts/exception_due.py,
           scripts/known_exploited.py, .github/actions/resolve-policy; schemas/policy-registration.schema.json;
           templates/policy-register.central.example.json, templates/policy-registration.example.json.
Deeper:    POLICY.md, AXES_AND_PHASES.md, ENFORCEMENT_TIERS_AND_FINDING_BASELINE.md, RUNG_DERIVATION_TABLE.md,
           docs/adoption/POLICY_REGISTER.md.
```

## 1 · Purpose

Say, per organisation, team, product, repository and environment tier, **how hard each control bites**,
who decided it and until when, and make sure nobody below can soften what an authority above decided.

## 2 · Where policy lives (two copies of one format)

| Copy | Where | Read from | May |
|---|---|---|---|
| central | `policy/policy-registration.json` inside the organisation's kit copy, delivered by `$/` at the caller's pin (the neutral kit ships none) | the kit pin | hold every org, team, product, repository map and number |
| repository | `.security/policy-registration.json` on the repository's protected default branch | a git ref, never the working tree | only tighten |
| neither | the kit default | - | crawl at every tier: only secrets block |

An unreadable file is never the default: it is `REGISTRATION_UNAVAILABLE` and `EVIDENCE_UNTRUSTED`.

## 3 · The rung and the floor

| Control class | crawl | walk | run |
|---|---|---|---|
| secrets | BLOCKED | BLOCKED | BLOCKED |
| new critical/high | PROCEED_WITH_ADVISORY | DECISION_REQUIRED | BLOCKED |
| pre-existing, on track | PROCEED_WITH_ADVISORY | DECISION_REQUIRED | PROCEED_WITH_ADVISORY |
| pre-existing, track lapsed | PROCEED_WITH_ADVISORY | DECISION_REQUIRED | BLOCKED |
| other findings (medium/low) | PROCEED_WITH_ADVISORY | DECISION_REQUIRED | DECISION_REQUIRED |

From `scripts/rung_ladder.py` (the table in `RUNG_DERIVATION_TABLE.md`). Rules on top of it:

- **The top authority's rung is the floor** for everything beneath it (KDEC-018); narrower scopes only
  tighten (`POLICY_BELOW_AUTHORITY_FLOOR`).
- **Crawl is the absolute floor**; a known-exploited CVE and a known-malicious package block at every rung
  (KDEC-020, KDEC-022).
- **The tier may only raise a floor**: at uat and prod `EVIDENCE_UNTRUSTED` stops the run
  (`scripts/enforcement_axes.py`).
- **The team pattern changes how a floor is met, never whether**: a solo repository's second reviewer is
  unsatisfiable, reported as an unvalidated human-workflow path, never as passing.
- **`policy_mode` is derived**, never received (`POLICY_MODE_SUPPLIED`).

## 4 · Weakenings and exceptions

| Kind | Needs | Refused as |
|---|---|---|
| a weakening (a softened workflow input) | `weakening_reason`, `weakening_authority` (the owner), `weakening_approver` (on a registered list, not the requester), `weakening_exception_ref`, `weakening_expires` within the ceiling (default 90 days) | `WEAKENING_NOT_APPROVED` (a missing field), `WEAKENING_SELF_APPROVED` (blocks), `WEAKENING_EXCEPTION_EXPIRED` |
| a secret exception | exactly one finding by fingerprint, a ticket, an explanation, an approver, an expiry; reviewers at uat/prod | `SECRET_EXCEPTION_*` |
| a known-exploited exception | the same, by fingerprint and CVE | `known_exploited_exception_refusal` |
| a version-gap exception at uat/prod | the five weakening fields, and the environment's reviewers | KDEC-014 |
| renewals | at most `max_exception_renewals`; history from git, cross-checked on the ticket | `EXCEPTION_RENEWAL_LIMIT`, `EXCEPTION_HISTORY_TAMPERED` |

Exceptions coming due resurface on their ticket, saying they were excepted before (`scripts/exception_due.py`).

## 5 · States, in plain words

| State | In plain words |
|---|---|
| `policy_resolution.REGISTRATION_UNAVAILABLE` | The policy file could not be read (invalid JSON, wrong schema, or the protected branch could not be reached). |
| `policy_resolution.REPOSITORY_FILE_SOFTENING` | This repository's own policy file tries to make a check weaker than the organisation's policy allows. |
| `policy_resolution.POLICY_BELOW_AUTHORITY_FLOOR` | A policy entry for a narrower scope (team, product, repository) tries to go below what a broader scope set. |
| `policy_resolution.POLICY_DECISION_EXPIRED` | A policy entry that applies to this run has passed its expiry date. |
| `policy_resolution.CHERRY_PICK_BELOW_FLOOR` | The policy (or a workflow input) asks for less than the kit's minimum: a secret check below blocking, or a required scan switched off. |
| `policy_resolution.TICKET_ROUTING_BELOW_FLOOR` | A policy entry routes secrets, known-exploited or malicious-package findings to "no ticket". |
| `policy_resolution.CELLS_NOT_MONOTONE` | The policy makes a lower environment stricter than a higher one (for example dev stricter than prod). |
| `policy_resolution.EXCEPTION_RENEWAL_LIMIT` | An exception has been renewed more times than the policy allows. |
| `control_weakening.GATE_SOFTENED` | A workflow input lets a scanner report without blocking (for example soft_fail_sast: true). |
| `control_weakening.CONTROL_SURFACE_DEAD` | A workflow input you set is not read by anything, so setting it has no effect. |
| `control_weakening.WEAKENING_SELF_APPROVED` | The person named as approver of a weakening is the person who asked for it (or the author of the change). |
| `secret_exception_refusal.SECRET_EXCEPTION_NOT_FINDING_SCOPED` | A secret exception does not name exactly one finding (its 12-character fingerprint). |

## 6 · Failure modes

| Failure | What happens | Proof |
|---|---|---|
| a PR edits the repository register | read from the default branch, so the PR's edit has no effect on its own run | `tests/prove_gate_reads_rung.py` |
| a narrower scope softens | refused, the floor holds | `tests/prove_authority_floor.py` |
| every weakening input at once | a secret still blocks | `tests/prove_crawl_floor.py` |
| a register number is missing | `POLICY_NUMBER_NOT_CONFIGURED`, refused | `tests/prove_rung_ladder.py` |
| the approver list lives in two places | one list, read by both the kit and the landing zone | `tests/prove_approver_list_source.py` |

## 7 · Decisions

KDEC-014 (version gaps), KDEC-017 (crawl rollout, scoped policy, deploy approval, ticketed exceptions),
KDEC-018 (the top authority binds; exceptions resurface), KDEC-019 and KDEC-020 (unmapped orgs at the
enterprise floor), KDEC-022 (strictest org; history from git; KEV blocks), KDEC-028 (ticket routing by
policy), KDEC-036 (weakening authority and expiry).
