# START HERE: the secure CI/CD kit, in this copy

This file travels inside every copy of the kit (the repository and every export of it), so a copy explains itself.
Read it top to bottom once. Every step names the exact file to read next; nothing here changes a setting.

## 1. What this is

The secure CI/CD kit is a set of **reusable GitHub Actions workflows** and the scripts they run. An application
repository calls them, pinned to one exact kit commit, and gets: the security scanners and one gate that decides
every pull request at the repository's adoption level (crawl, walk, run); build, deploy and rollback to Azure with
a human approval before uat and prod; tickets for findings; and plain-English explanations of every refusal
(`docs/errors/ERRORS.md`). Your organisation hosts **its own copy** of the kit (this one), and its repositories call
that copy.

| folder | what it holds |
|---|---|
| `.github/workflows/reusable-*.yml` | the workflows your repositories call |
| `templates/` | the starter callers (kit init writes them for you) |
| `scripts/`, `.github/actions/` | what the workflows run |
| `docs/adoption/` | the guides named below |
| `overlays/<org>/` | your organisation's own material, when this copy was exported for you |
| `tests/`, `tools/battery.py` | the kit's own proofs (they run in the kit's self-test, not in your applications) |

## 2. Bring this copy into your organisation's kit repository (once per release)

- **A new kit repository:** create an empty private repository in your organisation, put the unzipped files in it,
  commit once, and push (`EXPORT_MANIFEST.md` in an exported copy says the same).
- **An existing kit repository:** never copy the files over it by hand. Import plan-first with the import tool and
  the step-by-step page that come **beside** this zip in its package (`tools/plan_import.py`, `IMPORT_<commit>.md`):
  make a plan, review it, apply exactly the reviewed plan, stage only what it wrote, then hand-merge the protected
  files it lists. A file you edited is never overwritten, and an untracked file is never replaced.
- Then run the kit's own checks in the repository: `python tools/battery.py --fast` (UNKNOWN for a tool your
  machine lacks, never a failure), and open the import pull request: the self-test must be green, with
  `Self-test required` green.

## 3. The organisation's one-time setup (an organisation owner and the platform team)

1. **Let repositories call the kit:** kit repository, Settings > Actions > General > Access: "Accessible from
   repositories in the organisation" (`docs/adoption/SETUP.md` section 1.5).
2. **Create the org overlay**, the governed settings no repository can override: copy
   `templates/kit-org-settings.example.json` to `overlays/<your org>/kit-org-settings.json`, fill every `<...>`, and
   validate it: `python3 scripts/org_settings.py validate overlays/<your org>/kit-org-settings.json`. It names the
   approver teams, the adoption level, the Azure cloud of each environment, ticket routing, and (for a team of two
   or fewer with no approver group) the small-team self-approval. Why it lives here and not in a variable:
   `docs/adoption/SETTINGS_PRECEDENCE.md`.
3. **The approver teams** (KDEC-044, proposed): two GitHub teams, for example platform approvers and security
   approvers, named in the overlay; they become the uat/prod reviewers and the CODEOWNERS of `.github/workflows/`,
   `.kit/` and `id-mappings.json` in every repository, and they are never ruleset bypass actors
   (`docs/adoption/BRANCH_PROTECTION_SETTINGS.md`).
4. **Organisation variables** that are shared, not governed (`JIRA_HOST`, `JIRA_PROJECT`, the feed mirror), at the
   level `docs/adoption/SETTINGS_PRECEDENCE.md` gives for each.
5. **The kit repository's own rulesets:** require `Self-test required` (`docs/adoption/BRANCH_PROTECTION_SETTINGS.md`
   section 1).

## 4. Each application repository: `kit init`

Run `kit init` once per repository: it detects the stack and the host (github.com or `<tenant>.ghe.com`), applies
your org overlay, writes the callers pinned to this kit's commit, and opens one pull request whose description is
the checklist of what only a person can do (each item: what, how, why).

```bash
python3 -m pip install PyYAML
python3 scripts/kit_init.py --target ../my-app --kit-repo <your-org>/<kit-repo> --dry-run   # look first
python3 scripts/kit_init.py --target ../my-app --kit-repo <your-org>/<kit-repo>             # one branch, one PR
```

Or the button: copy `templates/kit-init.yml` into the repository, pin it, and run **Actions > Kit init**. The guide:
`docs/adoption/GETTING_STARTED_1_HOUR.md`.

**A repository someone wired by hand before** (copied templates, overlay pipelines): read
`docs/adoption/MIGRATE_FROM_HAND_WIRED.md` first. kit init never overwrites a file it did not write; it lists it.

## 5. The three pages to keep open

| page | when |
|---|---|
| `docs/adoption/GETTING_STARTED_1_HOUR.md` | the first hour in any repository, and the FAQ |
| `docs/adoption/SETTINGS_PRECEDENCE.md` | where each variable and secret goes, what wins, and what the kit refuses |
| `docs/adoption/MIGRATE_FROM_HAND_WIRED.md` | before kit init on a repository wired by hand |

Also: `docs/adoption/ROLLOUT_PLAN.md` (waves, crawl lasts 4 weeks optimally, 2 months preferred, 6 months at most),
`docs/errors/ERRORS.md` (every refusal in plain words), `docs/adoption/BRANCH_PROTECTION_SETTINGS.md` (the rulesets
and the uat/prod environments).
