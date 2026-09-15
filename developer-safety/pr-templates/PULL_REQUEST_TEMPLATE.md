## Purpose
<!-- What problem does this solve? One or two sentences. -->

## Scope
<!-- What changes. Link a diff summary if large. -->

## Risk / blast radius
<!-- What could go wrong, and how far does it reach if it does? -->

## Rollback
<!-- Specific steps. "Revert the PR" is not a rollback plan for anything with state. -->

## Testing done
- [ ] Unit tests added / updated
- [ ] Integration tests where practical
- [ ] Local checks pass
- [ ] Required CI checks expected green

## Evidence
<!-- What establishes that this works? Link runs, output, screenshots.
     "It should work" is not evidence. -->

## Invariant-adjacent?
- [ ] Touches schemas, auth/RBAC, data model, audit logging, aggregation/derivation, or deploy authority
- [ ] If checked: independent review recorded below

Independent review: <!-- reviewer, or the review pass performed, or "deferred — logged in register" -->

## Independence disclosure (solo / constrained profile only)
- [ ] No second human reviewer was available for this change
- [ ] An independent review pass was performed and is recorded above

## Checklist
- [ ] No secrets, keys, or real credentials in the diff
- [ ] No hardcoded subscription/tenant IDs or environment-specific values
- [ ] Branch name follows `feat/ | fix/ | chore/ | docs/`
- [ ] Docs updated where relevant
