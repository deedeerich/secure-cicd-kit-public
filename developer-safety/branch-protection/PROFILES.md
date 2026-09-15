# Branch protection profiles

## The invariant — independent of team size

> **No consequential change advances without independent evidence and challenge appropriate to its
> risk.**

**Organizational scale is not part of the security invariant.** How independence is achieved varies
with staffing; *that* independence is required does not. A policy demanding two human approvers in a
one-engineer environment does not produce safety — it produces "never ship anything," which is
followed by "ship around the process," which is worse than having no policy.

## Where independence can come from

Independence is a property of the *evidence*, not necessarily of the *headcount*:

- required CI checks that the author cannot alter in the same PR
- required security scanning / code scanning results
- deterministic policy checks (schema, provenance, signature, segregation rules)
- an independent architecture/security review pass by a separate agent context
- PR template requiring evidence, risk, and rollback notes
- protected deployment environments with their own approval
- explicit self-approval disclosure, recorded rather than hidden
- deferred peer review for selected high-risk changes when a qualified reviewer becomes available
- stricter requirements for irreversible or high-blast-radius change classes

## Profile: solo / constrained

For one engineer, or a team too small for meaningful peer review.

| Setting | Value |
|---|---|
| Require PR before merge | ✅ |
| Required approvals | **0** — with compensating controls below |
| Require conversation resolution | ✅ |
| Required status checks | `lint` · `test` · `secret-scan` · `sast` · `sca` · `policy` |
| Require branches up to date | ✅ |
| Require signed commits | ✅ |
| Block force push / deletion | ✅ |
| Admins exempt | ❌ **never** |
| Production environment | Separate protection + explicit approval, even if self-approved |

**Compensating controls, all required:**

1. PR body completed — purpose, risk, blast radius, rollback, testing done, evidence.
2. An independent review pass recorded in the PR (separate agent context, or a checklist run against
   the diff — not the author's own summary of it).
3. `invariant-adjacent` label on anything touching schemas, auth, data model, audit, or deployment
   authority — those get a **deferred human review** entry in a register rather than being waived.
4. Self-merge is **disclosed**, not hidden: a PR comment stating no second human was available.

The last point matters. A self-approved merge that says so is auditable. One that quietly satisfies a
policy by having the same person wear two hats is not.

## Profile: small team (2–5)

| Setting | Value |
|---|---|
| Required approvals | **1**, and **not the author** |
| Dismiss stale approvals on new commits | ✅ |
| Required status checks | as above |
| Signed commits · no force push · admins not exempt | ✅ |
| `invariant-adjacent` changes | 1 approval + named architect sign-off |

## Profile: mature team

| Setting | Value |
|---|---|
| Required approvals | 1–2 |
| CODEOWNERS review required | ✅ |
| Domain-specific approvals (security, data, infra) | ✅ |
| Environment approvals for prod | Distinct approver group; no self-approval |
| High-risk change classes | Segregation of duties enforced |

## Applying a profile

```bash
# Solo profile — adjust checks to those the repo actually runs
gh api -X PUT repos/:owner/:repo/branches/main/protection \
  --input developer-safety/branch-protection/solo.json
```

Profiles are JSON alongside this file. **Verify after applying** — a protection rule that was rejected
by the API and never checked is `configured ≠ enforced` in miniature:

```bash
gh api repos/:owner/:repo/branches/main/protection | jq '{
  checks: .required_status_checks.contexts,
  approvals: .required_pull_request_reviews.required_approving_review_count,
  admins: .enforce_admins.enabled,
  signed: .required_signatures.enabled
}'
```

## Hooks are not enforcement

`developer-safety/hooks/` gives early feedback on the developer's machine. It can be bypassed with
`--no-verify`, and it is not evidence of anything.

| Layer | Role |
|---|---|
| **Hook** | Early feedback — cheap, fast, bypassable |
| **CI** | Enforceable evidence — the authoritative gate |

Never treat a green hook as a satisfied control. Securing only CI, however, misses three earlier
chances to stop a mistake cheaply: **workstation → commit → push → PR → CI → merge → deploy.** The
first four are where a secret gets committed; CI is where you find out it already happened.
