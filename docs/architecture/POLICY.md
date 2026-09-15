# Pipeline policy — what the gate enforces and why

`workflow-policy-check.yml` is the kit's governance gate. It lints a repository's **own** workflow
definitions, not its application code. Everything below is enforced mechanically; nothing depends on
a reviewer noticing it.

## Threat model

CI is a high-value target because a runner briefly holds more authority than any human in the
pipeline: repository secrets, a live cloud OIDC token, and write access to the artifact that
production will run. The dominant attack class is **third-party Action compromise** — an action a
repository trusts is either backdoored at source or has its *tag repointed* at malicious code, and
executes inside that authority. The `tj-actions/changed-files` incident is the canonical worked
example: a mutable tag was moved, and every workflow referencing it started dumping runner memory
(including secrets) into build logs on the next run.

Two properties make that class devastating and both are structural, not behavioural:

1. **Mutable references.** `@v4` and `@main` are pointers. Whoever controls the pointer controls what
   your CI executes, retroactively, without a commit in your repository.
2. **Ambient authority.** A compromised step inherits whatever the *job* was granted — so a broad
   `permissions:` block or a workflow-wide `id-token: write` converts one bad action into cloud access.

The controls below are chosen because they hold regardless of which specific action gets compromised
next, and regardless of what the campaign ends up being called.

> Scope note: this document describes the control class, not any single named campaign. Where a
> current incident name is in circulation, map it to the rules below rather than adding a bespoke
> check for it.

## Rules

| # | Rule | Severity | Why |
|---|---|---|---|
| R1 | Every `uses:` carries an explicit ref | ERROR | An unpinned action is whatever the default branch says today. |
| R2 | Untrusted-owner actions pinned to a full 40-char commit SHA; no `@main`/`@master` ever | ERROR | Removes the mutable pointer. A SHA cannot be repointed. Trusted owners (`actions`, `github`, `azure`, …) are exempt by configuration, not by principle — see [PINNING.md](../assurance/PINNING.md). |
| R3 | Every workflow declares `permissions:`; `id-token: write` is scoped to the deploying job | ERROR / WARN | Caps the blast radius of a compromised step. A workflow-wide OIDC grant hands every job a usable cloud token. |
| R4 | `pull_request_target` must never check out the PR head | ERROR | That combination executes fork-authored code with full secret access. It is the single most common way secrets leave a repository. |
| R5 | Cloud auth is OIDC only — `azure/login` with `creds:` is rejected | ERROR | A long-lived service-principal secret survives its own leak. A federated token expires in minutes and is bound to the repo and ref. |
| R6 | No deploy-on-push — deploy-shaped jobs need a gating `environment:` or a dispatch trigger | ERROR | Makes "who approved this" answerable, and stops a merge from becoming a production change. |
| R7 | Deploys reference `@sha256:` digests, never tags | ERROR | A tag can point somewhere else between scan and deploy. The digest is the artifact you actually scanned. |
| R8 | `secrets: inherit` is flagged | WARN | Hands a called workflow every secret in the repository, not the ones it needs. |
| R9 | Attacker-controlled expressions never interpolate into `run:` | ERROR | A PR title containing shell metacharacters becomes code. Pass through `env:` and reference `"$VAR"`. |

## Adoption path

The gate is deliberately noisy on first run against an existing repository. Adopt in three steps:

1. Run with `soft_fail: true` and read the job summary. Non-secret findings do not block.
   **Secrets are intended to block regardless of mode** — see the defect note below.
2. Fix ERRORs, starting with R4, R5, and R9 — those are live secret-exposure paths, not hygiene.
3. Flip `soft_fail: false` and add the check to branch protection.

R2 is usually the largest batch of findings and the most mechanical to fix; `scripts/pin-actions.sh`
resolves the tags you already use into SHAs so the change is a rewrite, not a research project.

## What the gate does *not* do

It reads workflow definitions statically. It cannot see what a composite action does internally, what
a `run:` script fetches at execution time, or whether a pinned SHA was already malicious when you
pinned it. Pinning defeats *repointing*, not a compromised release. Pair this gate with dependency
review on the actions you consume and with egress-restricted runners where the threat model warrants
it.
