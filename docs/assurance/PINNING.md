# Action pinning

## The rule

Third-party actions are referenced by **full 40-character commit SHA**, with the human-readable
version in a trailing comment:

```yaml
- uses: aquasecurity/trivy-action@<40-char-sha>   # v0.28.0
```

The comment is not decoration — it is what makes the pin reviewable and upgradeable. A bare SHA with
no version comment is unmaintainable by the next person, so the gate emits a NOTE when it sees one.

## Current state of this kit

**Every remote `uses:` is SHA-pinned** (lane L-H, 2026-10-22, ledger L82, owner decision O-23).
Until then the kit's own tree carried 161 remote references by tag, and the self-test ran this gate
against itself with `require_sha_pinning: false` / `soft_fail: true` under a weakening dated to
expire 2026-10-31. The sweep pinned all 161 — the GitHub-operated owners included, because the
`trusted_orgs` exemption is a consumer's risk acceptance, not this kit's — and the dogfood job now
runs at baseline with no weakening record. It was removed, not re-dated.

| Action | Pinned commit | Release |
|---|---|---|
| `actions/attest` | `1e69f48acb82d1966a394da916b4c1698aa569d6` | v4.2.2 |
| `actions/cache` (`save`, `restore`) | `55cc8345863c7cc4c66a329aec7e433d2d1c52a9` | v6.1.0 |
| `actions/checkout` | `3d3c42e5aac5ba805825da76410c181273ba90b1` | v7.0.1 |
| `actions/download-artifact` | `9000827ccba6bdab643e8b6fd33ac0654aef8333` | v8.0.2 |
| `actions/setup-dotnet` | `a98b56852c35b8e3190ac28c8c2271da59106c68` | v6.0.0 |
| `actions/setup-go` | `b7ad1dad31e06c5925ef5d2fc7ad053ef454303e` | v7.0.0 |
| `actions/setup-java` | `b6effb05e454b25005698d916606bdc6ffcbf961` | v5.7.0 (release branch) |
| `actions/setup-node` | `949feb2413d6458794dcd2491c4babbbce0c15c1` | v7.1.0 |
| `actions/setup-python` | `6d4fd22b20465ccc0f7354476588e8df7c9ca0e0` | v7.1.0 |
| `actions/upload-artifact` | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` | v7.0.2 |
| `aquasecurity/trivy-action` | `ed142fd0673e97e23eac54620cfb913e5ce36c25` | v0.36.0 |
| `azure/login` | `a641126d1b8aa4d1fa005f4f92df94a3a4c4c906` | v3.1.0 (release branch) |
| `bridgecrewio/checkov-action` | `c3e106d5f8f4253a6de5110efb41a080f83db294` | v12.3135.0 |
| `docker/build-push-action` | `c3c9e263c25d99ce0380d002d59b67737d91b0dc` | v7.4.0 |
| `docker/setup-buildx-action` | `f87e5991a6d7451dcb8d9637bfbc97413f497069` | v4.4.1 |
| `dorny/paths-filter` | `ceb8a2b8f2d89434be7ff52d3de7ec3738c5cc9d` | v4.0.3 |
| `github/codeql-action` (`init`, `autobuild`, `analyze`, `upload-sarif`) | `9b3254085494b55a0f7c4c2b3d2d52cc712ce370` | v4.39.1 |
| `hashicorp/setup-terraform` | `dfe3c3f87815947d99a8997f908cb6525fc44e9e` | v4.0.1 |
| `SonarSource/sonarqube-scan-action` (overlay only) | `fd88b7d7ccbaefd23d8f36f73b59db7a3d246602` | v6.0.0 |
| `zaproxy/action-baseline` (overlay only) | `7c4deb10e6261301961c86d65d54a516394f9aed` | v0.14.0 |
| `semgrep/semgrep` (container image) | `@sha256:32e45996…` (1.178.0; lane L-SG) | pinned by image digest |

Each SHA is the commit the tag named on 2026-10-22, resolved through the GitHub REST API with
annotated tags peeled, and confirmed on the action's default-branch history or as a release tag's
target (the two marked *release branch* are cut from one). The comment is the exact release at that
commit, never the moving major. `templates/` keep `YOUR_ORG/secure-cicd-kit/...@` forty zeros: a
consumer pins its own fork's commit, and an unedited copy fails closed.

**Overlays are pinned too.** An overlay's workflows ship into that consumer's own copy through the
consumer export profile, with that consumer's secrets, so its 5 remote references were pinned the
same way (the two overlay-only actions are in the table). Its kit call keeps the
`KIT_OWNER/KIT_REPO/...@` forty-zero placeholder that `tests/check_custody.py` governs. Dependabot
here deliberately does **not** read `overlays/`: an overlay is maintained with its consumer, whose
own Dependabot keeps those pins current in their copy.

**What holds it.** `tests/check_action_pins.py` (workflows, job-level calls, composites and
templates; no owner exempt; the comment must be an exact release, spot-checked against a recorded
table offline and against the API with `--online` in the self-test; Dependabot must read every
composite). `tests/prove_workflow_policy_rules.py` (the shipped gate over this tree with
`trusted_orgs` empty finds zero unpinned; the dogfood job carries no weakening).
**What keeps it current.** Dependabot's `github-actions` ecosystem, which moves a SHA and its version
comment together, reads `/` and `/.github/actions/*` (`.github/dependabot.yml`).

The historical record below is kept because the lessons in it still apply.

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

Real commit SHAs must be resolved against the live upstream repositories; they cannot be authored
from memory, and a fabricated SHA is worse than an honest tag because it fails closed in a way that
looks like a typo. Until 2026-10-22 that was why `self-test.yml` dogfooded the policy gate with
`require_sha_pinning: false` and `soft_fail: true`; the flip to `true` / `false` — the definition of
done for Phase 4 — was made by the L-H sweep (above).

## Resolving tags to SHAs

`scripts/pin-actions.sh` reads every `uses:` in the repository, resolves each tag to its commit SHA
via the GitHub API, and rewrites the reference in place with a version comment.

```bash
export GITHUB_TOKEN=<a token with public repo read>
./scripts/pin-actions.sh                 # dry run — prints the rewrites it would make
./scripts/pin-actions.sh --apply         # rewrite in place
```

Review the diff before committing. The script deliberately does not touch `./`-relative or `$/`
references, or owners listed in `TRUSTED_ORGS` — which is **empty by default** since 2026-10-22: the
kit pins every owner, and an exemption is something you set. `SEARCH_PATHS` widens the walk
(e.g. `SEARCH_PATHS=".github overlays"`).

The comment it writes is the **exact release** at the resolved commit (`# v7.0.1`), found among the
repository's tags across every page — not the moving major it resolved (`@v7`). A commit with no
`vX.Y.Z` tag is refused and its line left alone. Its output passes `tests/check_action_pins.py`;
`tests/prove_pin_actions_names_release.py` holds that offline against a local API stand-in. (Before
2026-10-22 it wrote `# v7`, so the L-H sweep resolved exact releases separately.)

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
