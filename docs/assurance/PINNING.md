# Action pinning

## The rule

Third-party actions are referenced by **full 40-character commit SHA**, with the human-readable
version in a trailing comment:

```yaml
- uses: aquasecurity/trivy-action@<40-char-sha>   # v0.28.0
```

The comment is not decoration — it is what makes the pin reviewable and upgradeable. A bare SHA with
no version comment is unmaintainable by the next person, so the gate emits a NOTE when it sees one.

## Current state of this kit — read before tagging v1

The kit's own workflows currently reference third-party actions **by tag**, not by SHA:

| Action | Current ref | Owner trusted by default? |
|---|---|---|
| `gitleaks/gitleaks-action` | `@v3` | no — must be SHA-pinned |
| `aquasecurity/trivy-action` | `@v0.36.0` | no — must be SHA-pinned |
| `bridgecrewio/checkov-action` | `@v12` | no — must be SHA-pinned |
| `dorny/paths-filter` | `@v4` | no — must be SHA-pinned |
| `semgrep/semgrep` (container image) | `:1.90.0` | pin by image digest |
| `actions/*`, `github/*`, `azure/*`, `docker/*`, `hashicorp/*` | tags | yes — exempt by configuration |

### A tag you cannot resolve is worse than a tag you have not reviewed

`aquasecurity/trivy-action` was pinned to **`@0.28.0`**, which **does not exist** — upstream tags are
`v`-prefixed (`v0.28.0`). Six references across `reusable-security.yml`, `reusable-nvd-cve.yml`,
`reusable-build-docker.yml` and `action:docker-build-push` would have failed with *"Unable to resolve
action"* for the first consumer who ran them.

`validate-scanners.yml` did not catch it because the probes install the Trivy **binary** directly.
They prove the *tool*; they say nothing about the *action reference* in the reusable workflow. This
is the "never invoked end-to-end" gap producing a real shipped defect rather than a theoretical one,
and it is the strongest argument for the consumer-path test.

**Rule:** every `uses:` ref must be resolved against upstream, never written from memory — the same
rule this document already states for SHAs. It applies to tags too.

### Runtime currency — Node 20 removal, 2026-09-16

GitHub flipped the runner default to Node 24 on **2026-06-02** and **removes Node 20 from hosted
runners entirely on 2026-09-16**, after which `node20` actions stop working regardless of any
opt-out flag. On 2026-08-14 this kit had **16 actions on `node20`**; all were moved to majors that
declare `node24`.

Resolve-don't-guess applies here as well. Check any action's runtime with:

```bash
gh api "repos/<owner>/<repo>/contents/action.yml?ref=<tag>" --jq .content   | base64 -d | grep -E "using:"     # some actions use action.yaml — try both
```

A pinned SHA freezes the runtime too, so **SHA pinning does not exempt you from this** — it makes
runtime drift invisible until the action stops running. Re-check on every upgrade.

This is a **known open item, not an oversight**. Real commit SHAs must be resolved against the live
upstream repositories at adoption time; they cannot be authored from memory, and a fabricated SHA is
worse than an honest tag because it fails closed in a way that looks like a typo. `self-test.yml`
therefore dogfoods the policy gate with `require_sha_pinning: false` and `soft_fail: true`.

**Before tagging `v1`:** run the resolver below, commit the SHAs, then flip `self-test.yml` to
`require_sha_pinning: true` / `soft_fail: false`. That flip is the definition of done for Phase 4.

## Resolving tags to SHAs

`scripts/pin-actions.sh` reads every `uses:` in the repository, resolves each tag to its commit SHA
via the GitHub API, and rewrites the reference in place with a version comment.

```bash
export GITHUB_TOKEN=<a token with public repo read>
./scripts/pin-actions.sh                 # dry run — prints the rewrites it would make
./scripts/pin-actions.sh --apply         # rewrite in place
```

Review the diff before committing. The script deliberately does not touch `./`-relative references or
owners listed in `TRUSTED_ORGS`.

## Upgrading a pinned action

1. Read the upstream release notes and the diff between your pinned SHA and the new tag.
2. Re-run the resolver for that one action.
3. Commit the SHA **and** update the trailing version comment in the same change.

Never "upgrade" by moving to a tag temporarily. That reintroduces exactly the mutable pointer the pin
exists to remove.

## The exemption list is a decision, not a default

`trusted_orgs` exists because pinning every `actions/checkout` in a large estate is friction with a
poor return — those repositories are GitHub-operated and heavily watched. That is a *risk
acceptance*, and it should be recorded as one. Environments with a stricter threat model (sovereign,
regulated, or air-gapped-adjacent) should set `trusted_orgs: ""` and pin everything.
