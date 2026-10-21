# A scanner declares what it looked at, not what language the repository is

```
Status: DESIGN. Nothing built.
Scope: the neutral core only. Consumer-specific scanner sets live in overlays/,
       which are excluded from every exported copy by construction.
```

## The finding

Two consumer ecosystems were proposed as new *profiles*. Working through them surfaced something
larger: **profiles are the wrong unit, and the vocabulary already knew.**

`assurance-taxonomy.yaml` registers `finding_subject` with eight values:

```
IMAGE · SOURCE · IAC_PLAN · RESOURCE · IDENTITY_ASSIGNMENT · RUNTIME_OBSERVATION · POLICY · RELEASE
```

`RUNTIME_OBSERVATION` is the live-target class. It has been registered the whole time and
**no profile has ever emitted it.**

> A profile answers *what language is this repository.*
> A scanner answers *what kind of thing did I look at.*
>
> Those are different axes, and this kit has been treating the first as though it settled the
> second.

Every repository-shaped profile can only ever describe repository-shaped things. A hosted
property, a deployed resource, a running service — none of them fit, and the absence shows up as
a missing profile when it is actually a missing field.

## What changes

**Add `finding_subject` to the scanner registration schema.** One field, and the special cases
stop being special:

| consequence | follows from the subject, not the profile |
|---|---|
| authorization required before execution | only where the subject is a live target; source analysis needs no permission |
| a finding cannot be closed by a pull request | the subject is a deployment, so remediation is a deploy |
| the SLA clock attaches to a deployed thing | consistent with the anti-laundering rule that pre-existing in one environment is not pre-existing in another |
| rate limiting and blast radius apply | an active scan is traffic against something real |
| `scan_depth` shifts to `revalidate` | the source did not change, the world did |

None of that needs a new namespace. It needs the field populated.

## The authorization gate is a record, not an input

A boolean input is worth nothing here. It is set by the same person who wants the scan to run, it
never expires, and it records nobody.

An active scan against a live property is a deliberate act against a real system, and in several
jurisdictions performing one without permission is a criminal matter rather than a policy breach.
So the gate carries what a permission actually carries:

```
authorizing party   a named human, not a repository setting
scope               the exact hosts and paths in scope, and what is explicitly OUT
window              a start and an EXPIRY -- one that never expires is a standing authorization
intensity           passive enumeration / authenticated read / active probing / full DAST
recorded where      the protected default branch, under CODEOWNERS
```

Absent or expired resolves to `PREREQUISITE_UNAVAILABLE` and **the scan does not run** — never to
a pass, and never to a scan that proceeds with a warning attached. Same shape as every other
precondition here: the unknown side is non-destructive, and for a live target non-destructive
means *do not touch it*.

**The authorization expires on its own.** `REOPENED_BY_LAPSE` already exists for a disposition
whose expiry passed; a permission to scan is no different.

## The ceiling mechanism, stated generally

One proposed ruleset targets a templating language with no analyser support, leaving pattern
matching without a parse tree as the only option. That produces a class of scanner this kit has
not had to describe before:

> **A scanner that cannot parse its target is `PARTIAL` by construction and may never report
> `CLEAN`.** A run that finds nothing means *these patterns did not match*, not *this target is
> sound*.

This is the same defect family as a scanner exiting zero having parsed nothing, with one
difference that matters: **it is known in advance.** So the ceiling is a property of the
registration rather than a discovery made later, and the registry needs somewhere to record it.

## Three gates that belong here and should not wait

Surfaced while reviewing consumer-specific sets, but repository-shaped and owed to every consumer:

1. **Workflow security linting** beyond syntax — privileged-trigger misuse, expression injection
   into `run:` blocks, over-broad `permissions`, artifact poisoning. `actionlint` does not cover
   this class.
2. **An assert-no-mutable-action-refs gate.** Thirty-nine references were pinned to commit SHAs by
   hand. A gate is what stops the fortieth from regressing, and hand-pinning does not survive
   contact with a dependency bot.
3. **A self-test proving each gate actually blocks.** The argument is this kit's own history: a
   self-test was green because its denominator was wrong, not because a check was missing. A gate
   that has never failed is decoration, and a new scanner without a negative fixture is an
   unexercised claim.

## Where consumer-specific sets live

Scanner sets belonging to one consumer's estate go in `overlays/<consumer>/docs/`, marked
`capability_origin: OVERLAY_ECOSYSTEM_DECLARED` — the registered term for a technology present in
one estate and declared by them, rather than a capability the neutral kit owes everybody.

That term was **orphaned** until now: registered, defined, used nowhere. So were
`OVERLAY_REQUESTED_CAPABILITY` and `GENERIC_TEAM_PATTERN`. The overlay split is their first real
consumer, and it is the second time in two days that the answer to a structural question turned
out to be already in the taxonomy and unwired.

`scripts/export_for_adoption.py` excludes `overlays/` from every exported copy by construction —
`EXCLUDE_TREES`, not a deny-list pattern — so a set written for one estate cannot reach another
even if nobody has written a deny rule for it yet. **The neutral core must therefore never name a
consumer's ecosystem, product or property.** If it does, the capability has escaped its overlay.
