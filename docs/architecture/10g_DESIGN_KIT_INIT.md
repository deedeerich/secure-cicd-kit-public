# 10g · Design: kit init

```
Kept:      2026-11-07, against the trunk at c1420ea. Components: 03g_COMPONENTS_KIT_INIT.md.
Code:      scripts/kit_init.py, .github/actions/kit-init, templates/kit-init.yml,
           scripts/consumer_surface_check.py, scripts/dependabot_config.py.
Guide:     docs/adoption/GETTING_STARTED_1_HOUR.md. Decision: KDEC-041.
```

## 1 · Purpose

Wire a repository to the kit in one command, correctly the first time, and write down, with the exact
commands, everything only a person can do. Developers are new to this way of working; adoption must not be
"a million hoops".

## 2 · Inputs and outputs

| Kind | What |
|---|---|
| input | `--target` (the repository), `--kit-repo`, `--kit-sha` (40 hex), `--deploy auto, container, static, none`, `--dockerfile`, `--site-dir`, `--with-triage`, `--with-api`, `--automerge`, `--outside-landing-zone`, `--appsec-team`, `--platform-team`, `--repo`, `--host`, `--dry-run`, `--json` |
| input | the workflow's dispatch inputs map to those; `KIT_INIT_TOKEN` (optional) opens the PR |
| output | the caller workflows, `.github/dependabot.yml`, a CODEOWNERS block, `.kit/environments.json`, `.kit/settings.json`, `.kit/ADOPTION_CHECKLIST.md`, `.kit/kit-init.lock.json` |
| output | one branch and one pull request, or the artifact `kit-init-files` |
| output | `state` (`kit_init_state`) |

## 3 · How it works

1. **Detect** the stacks and the deploy shape. Never guess: nothing recognised is a named refusal.
2. **Generate** from the kit's own starter templates at the pinned commit, pinned to that SHA, each job
   granting exactly the union of what its callee's jobs request.
3. **Verify** before writing a byte: exact permissions, every reference on the one SHA, no placeholder, one
   security caller, no secret value, actionlint clean (in self-test).
4. **Write** idempotently: a file kit init wrote and nobody changed is updated; a file a person edited is
   preserved and listed.
5. **Open one PR** whose body is the checklist: environments and reviewers (`gh api` commands), the OIDC
   federated credential per environment with this host's issuer, the readiness attestation outside a
   landing zone, the secret and variable names to set, auto-merge if opted in.

## 4 · States, in plain words

| State | In plain words |
|---|---|
| `KIT_INIT_STACK_UNKNOWN` | kit init did not recognise any language or deploy type in this repository, so it wrote nothing. |
| `KIT_INIT_MULTIPLE_IMAGES` | This repository has more than one Dockerfile and kit init will not pick which one deploys. |
| `KIT_INIT_PIN_MISSING` | kit init was not told which kit repository and commit to pin. |
| `KIT_INIT_PIN_NOT_CHECKOUT` | The commit you asked kit init to pin is not the kit commit it is running from. |
| `KIT_INIT_HOST_UNSUPPORTED` | The repository's host is neither github.com nor a TENANT.ghe.com host. |
| `KIT_INIT_API_NEEDS_CONTAINER` | The kit API caller was requested, but this repository is not a container deploy. |
| `KIT_INIT_SECRET_REFUSED` | kit init found a secret-looking value in what it was about to write, so it wrote nothing. |
| `KIT_INIT_GENERATED_INVALID` | kit init's own check of the files it generated failed, so it wrote nothing. |
| `KIT_INIT_DIRTY_TREE` | The repository has uncommitted changes, so kit init did not open its pull request. |
| `KIT_INIT_PR_NOT_OPENED` | kit init wrote the files but git or gh refused to push the branch or open the pull request. |
| `KIT_INIT_HUMAN_EDIT_PRESERVED` | kit init kept a file (or the CODEOWNERS block) exactly as a person left it, instead of updating it. |

## 5 · Failure modes

| Failure | What happens | Proof |
|---|---|---|
| the generated callers would fail GitHub's permission check | `KIT_INIT_GENERATED_INVALID`, nothing written | `tests/prove_kit_init.py` |
| a re-run would overwrite a person's edit | the edit is kept and listed | `tests/prove_kit_init.py` |
| no token can push workflows | the files go to an artifact with commit instructions | `tests/prove_kit_init.py` |
| a stack kit init does not know sits beside one it does | named in the checklist as not covered | `tests/prove_kit_init.py` |

## 6 · Decisions

| Decision | What it settled |
|---|---|
| KDEC-041 | adoption in one command; every refusal said in plain words first; pilots measure their friction (`scripts/friction_summary.py`) |
| KDEC-042 | `.kit/environments.json` classes each environment; uat/prod gated by people outside the app team |
| KDEC-027 | the issuer and API host are this host's (github.com or TENANT.ghe.com) |
