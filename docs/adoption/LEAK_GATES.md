# Leak gates — keeping a committed secret off the default branch

A GitHub PAT leaked when a `.env` file was committed to a repository with none of these layers in
place. Tines GitSync pushes do not run local hooks. GitHub secret scanning and push protection may
not be licensed on private repositories. So the kit gives the strongest protection it can without
them, and every run says which layers are missing (lane L-LEAK, **KDEC-031 PROPOSED**).

## The gates, in order

| # | Gate | Where it runs | Licence | What the kit ships |
|---|---|---|---|---|
| 1 | `.gitignore` + the gitleaks pre-commit hook | the developer's machine | none | `developer-safety/gitignore/baseline.gitignore` + `merge-baseline.sh`, `developer-safety/hooks/.pre-commit-config.yaml` |
| 2a | Secret scanning **push protection** | GitHub, before the push lands | GitHub Secret Protection on private/internal repositories | nothing to ship; turn it on where licensed |
| 2b | **Push ruleset** refusing secret-file paths and extensions | GitHub, before the push lands | none: it matches paths, not content | `developer-safety/branch-protection/push-ruleset-secret-files.json` + `apply-push-ruleset.sh` |
| 3 | The kit's CI secret scan | the `secret-scan` job | none | blocks in **every** mode and rung |
| 4 | Branch gate: a PR **and** the `Security gate` check required | GitHub, at merge | none | `developer-safety/branch-protection/*.json` profiles |

Gates 1 and 2 stop the secret before it is in the remote. Gate 3 finds it after the push. Gate 4
stops a secret on a branch from ever merging. **A secret that reached the remote is compromised:
rotate it, whatever gate 3 or 4 later does.**

### Tines GitSync and other server-side pushers

Local hooks do not run for Tines GitSync pushes (nor for the web editor, or any bot or CI job that
pushes). For those only **2a, 2b and 3** apply, plus 4 at merge. A repository Tines writes to
should therefore carry the push ruleset (2b) even where push protection (2a) is licensed.

## Adoption step 1: install the rails

Do this first, before wiring the workflows.

1. **Merge the baseline `.gitignore`** into the repository's own (never replace it):
   `bash developer-safety/gitignore/merge-baseline.sh <repo-dir>`. It appends only the missing
   patterns, after the repository's own lines, and appends nothing the second time.
   `<repo-dir>` must exist and be inside a git work tree. After writing, the script re-reads the
   file and requires every baseline pattern in it. It never reports a success it has not checked
   (exit codes below).
   It covers:
   - `.env` and `.env.*`, except `.env.example` (and `.env.template` / `.env.sample`);
   - keys and certificates: `*.pem`, `*.key`, `*.pfx`, `*.p12`, `*.jks`, `id_rsa*`, `id_ed25519*`, `id_ecdsa*`;
   - `*.tfstate` and its backups;
   - `*.har` captures;
   - credentials JSON;
   - cloud CLI caches: `.aws/`, `.azure/`, `.config/gcloud/`, `.kube/config`, `.docker/config.json`, `.oci/`;
   - `.npmrc`, `.netrc`, `.pypirc`, `.git-credentials`.

   `tests/prove_baseline_gitignore.py` proves each pattern with `git check-ignore`. A repository
   that must commit a token-free `.npmrc` negates it locally (`!.npmrc`) after review.
2. **Install the pre-commit hook:** copy `developer-safety/hooks/.pre-commit-config.yaml`, then
   run `pre-commit install`. The hook is feedback, not evidence: `--no-verify` skips it.
3. **Apply the push ruleset** (needs repository administration):
   `bash developer-safety/branch-protection/apply-push-ruleset.sh <owner>/<repo>`. On a
   `<tenant>.ghe.com` estate, add `--host <tenant>.ghe.com`. The token goes only to that host
   (KDEC-027). The script is idempotent and `--dry-run` shows what it would do.
   The dry run is a real check, not a printout. It needs bash, `gh` and `jq`, a `gh` logged in to
   the host, and the repository readable through the API. If any of these fails, it exits non-zero
   with a named reason before printing a plan. `existing_id` is printed only after a ruleset
   lookup that succeeded. Before this fix, a dry run with `gh` missing or logged out printed
   `existing_id=none` and exited 0.
4. **Enable push protection where licensed:** Settings, Advanced Security, Secret Protection,
   Push protection. Where it is not licensed, the run records that (below). It is not a failure.
5. Then require a PR and the `Security gate` check on the default branch (`branch-protection/PROFILES.md`).

### Exit codes of the two scripts

Each failure prints its reason name on stderr. A wrapper can branch on the code. A person reads
the name. The names are registered in `assurance-taxonomy.yaml`: `PREREQUISITE_UNAVAILABLE` and
`FITNESS_FAILED` under `prerequisite_readiness` (the same words the scanner jobs use for a missing
or unfit tool), the rest under `leak_gate_setup_refusal`. Several prerequisites share
`PREREQUISITE_UNAVAILABLE`; the code tells them apart and the message names the one that failed.

`apply-push-ruleset.sh OWNER/REPO [--host HOST] [--dry-run]`. The dry run and the real run check
the same prerequisites, in this order:

| Code | Reason | Meaning |
|---|---|---|
| 0 | | Applied. With `--dry-run`: every prerequisite held and the plan (`existing_id`, PUT or POST) is printed |
| 1 | `NOT_APPLIED` | GitHub refused the PUT or POST (403: no administration; 422: personal-account repository, public repository, or a plan without push rulesets) |
| 2 | `USAGE` | Bad or missing argument |
| 10 | `PREREQUISITE_UNAVAILABLE` | bash: run by a shell that is not bash (`sh apply-push-ruleset.sh`) |
| 11 | `PREREQUISITE_UNAVAILABLE` | `gh` is not on PATH |
| 12 | `PREREQUISITE_UNAVAILABLE` | `jq` is not on PATH |
| 13 | `PREREQUISITE_UNAVAILABLE` | A `gh` login to the host: `gh auth status --hostname HOST` failed. Run `gh auth login --hostname HOST`, or set `GH_TOKEN` |
| 14 | `REPO_NOT_READABLE` | `GET repos/OWNER/REPO` failed: no such repository, no access, or the wrong host |
| 15 | `RULESET_LOOKUP_FAILED` | `GET repos/OWNER/REPO/rulesets` failed or answered nonsense, so whether the ruleset exists is unknown |
| 16 | `TEMPLATE_UNREADABLE` | `push-ruleset-secret-files.json` is missing, is not JSON, or has no name |

`merge-baseline.sh [REPO_DIR]`:

| Code | Reason | Meaning |
|---|---|---|
| 0 | | Merged, or it already carried every pattern. Either way, verified by re-reading the file |
| 2 | `USAGE` | More than one argument, or an unknown option |
| 10 | `PREREQUISITE_UNAVAILABLE` | bash: run by a shell that is not bash |
| 11 | `PREREQUISITE_UNAVAILABLE` | `grep` or `tail` is not on PATH |
| 12 | `BASELINE_UNREADABLE` | `baseline.gitignore` is missing, unreadable, or holds no pattern. Before this fix, an empty baseline reported "already carries every baseline pattern" |
| 13 | `REPO_DIR_MISSING` | `REPO_DIR` does not exist. Nothing is created |
| 14 | `NOT_A_GIT_REPO` | `REPO_DIR` is not inside a git work tree. Before this fix, it wrote a `.gitignore` into any directory |
| 15 | `TARGET_NOT_WRITABLE` | `REPO_DIR/.gitignore` is not a readable, writable file |
| 16 | `MERGE_NOT_VERIFIED` | After the merge, the file does not carry every baseline pattern |
| 17 | `FITNESS_FAILED` | `grep -Fxq` fails its self-test. Before this fix, a grep that never matched made every run append every pattern again and exit 0 |

`tests/prove_push_ruleset_secret_files.py` R6 and `tests/prove_baseline_gitignore.py` G4 prove
each refusal. They run against stub tools on a controlled PATH.

## What every run records

Discover's platform step reads each layer with the run's own token. It is a few GETs in a job that
already runs, with no new job and no new check name. The `security-gate` job's **Leak-gate
posture** step then records:

- `leak_gates`: a JSON object, each layer `ON`, `OFF` or `UNKNOWN`;
- `leak_gate_weakenings`: one `control_weakening` row per `OFF` layer (`CONTROL_DISABLED`,
  `WEAKENING_IN_FORCE`, `WEAKENING_UNATTRIBUTED`), the vocabulary of a disabled control;
- a warning per missing layer, and a table in the run summary.

**UNKNOWN is never ON.** A 403, a token without the scope, or an unreadable answer is UNKNOWN.
`GITHUB_TOKEN` cannot read push protection on a private repository, nor a classic protection's PR
requirement (both are admin-only), so those are often UNKNOWN. Rulesets can be read with read
access.

**The louder warning (`NO_LEAK_GATE_SHOWN`)** fires when none of push protection, a push ruleset or
the local rails can be shown ON. Only the CI scan stands in front of the default branch then.

**At crawl nothing here blocks or changes `routing_result`.** Deploys refuse an advisory cause they
do not know. KDEC-031 records how the owner makes a missing gate route or block later.

## Verified facts, with sources

| Claim | Status | Source |
|---|---|---|
| Push rulesets block pushes "to a private or internal repository and that repository's entire fork network" | VERIFIED (docs) | [About rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets) |
| Push rulesets on **public** repositories | Not documented: treat as unavailable | same |
| Push rulesets need an **organisation-owned** repository | VERIFIED LIVE (2026-10-26): a private repository owned by a personal account is refused with HTTP 422 "Source only org-owned repos can have push rules", whatever the plan | live API call |
| Rulesets are documented for "GitHub Team and GitHub Enterprise plans" | VERIFIED (docs); push rulesets on a **Free organisation's** private repository are **UNVERIFIED** | same |
| Push rulesets need no GitHub Advanced Security or secret-scanning licence | The docs state no licence requirement. The rules match file paths, extensions, path length and size, not content. **UNVERIFIED** as an explicit statement | [Available rules](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets) |
| Repository push protection "requires GitHub Secret Protection" and is off by default | VERIFIED (docs) | [About push protection](https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection) |
| API: `POST /repos/{owner}/{repo}/rulesets`, with `target: "push"`, `enforcement: "active"`, rules `file_path_restriction` (`restricted_file_paths`) and `file_extension_restriction` (`restricted_file_extensions`) | VERIFIED (REST reference) | [Repository rules API](https://docs.github.com/en/rest/repos/rules?apiVersion=2022-11-28#create-a-repository-ruleset) |
| Each `restricted_file_extensions` entry is written `*.ext` | VERIFIED LIVE (2026-10-26): a bare `.pem` is refused with HTTP 422 "File extension must start with *." The first template shipped the bare form; it is corrected and the test now requires `*.ext` | live API call |
| Limit: 200 entries of at most 200 characters per rule; `fnmatch` syntax | VERIFIED (docs) | Available rules |
| `*` does not match `/`; character sets work, complement with `^` does not; no extglob | VERIFIED (docs) | [Creating rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/creating-rulesets-for-a-repository#using-fnmatch-syntax) |
| The UI's "Allowed exceptions" for file paths | VERIFIED (UI docs); **no API parameter documented**, so the template does not use one | Creating rulesets; REST reference |
| Fine-grained token permission for creating rulesets (Administration: write) and for reading them (Metadata: read) | **UNVERIFIED** | not found in the pages above |

**How `.env.example` passes without an exception.** The API documents no exception list, and
complemented sets (`[^e]`) are unsupported. So the template blocks `.env.*` with **positive**
character sets that spell out every name except `example`:

- `.env.[a-df-zA-Z0-9._-]*` (the first letter is not `e`);
- `.env.e[a-wy-zA-Z0-9._-]*`, and so on, one per letter;
- each exact truncation (`.env.exa`);
- `.env.example?*`.

The ruleset blocks `.env.template` and `.env.sample`, which the `.gitignore` allows. Rename such a
file to `.env.example`.

Every pattern is shipped three ways: at the root, under `**/`, and under one dot-directory
(`**/.*/**/`), because `**/` does not descend into `.`-directories. A name that starts with a
character outside `a-zA-Z0-9._-` (for example `.env.~x`) is not blocked by the ruleset. The
`.gitignore` and the CI scan still cover it.

**Proof and its limit.** `tests/prove_push_ruleset_secret_files.py` checks the JSON against the
documented shape and limits. It then evaluates every pattern under emulated
`Ruby File.fnmatch with the pathname flag`: every named secret path is blocked, and `.env.example` is allowed at
any depth.

That GitHub's matcher behaves exactly like the emulation is **UNVERIFIED** until someone:

1. applies the ruleset to a real **organisation-owned** private repository;
2. tries to push a `.env` (refused) and a `.env.example` (accepted).

A personal account's repository cannot take a push ruleset at all (verified live 2026-10-26), so the
proof needs a repository in an organisation, such as a free test organisation, or the work
organisation's test repository.

## Scanning long-lived branches

`templates/security.yml` triggers on pushes and PRs to `main`. A secret pushed to `dev` or a
release branch is scanned only when a PR from it targets `main`. **Recommended:** add every
long-lived branch to both triggers (`branches: [main, dev]`). That costs one more full scan per push
to those branches. The template's default is unchanged; the line is there, commented.
