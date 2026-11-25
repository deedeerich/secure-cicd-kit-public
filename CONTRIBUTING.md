# Contributing to the secure CI/CD kit

The kit is changed test-first: a proof that fails on the old code for the named reason, the fix,
the same proof passing, wired into `.github/workflows/self-test.yml`. Every capability has a
positive control (the normal user's path works end to end) and its negative controls (what must be
refused), recorded in `docs/assurance/POSITIVE_NEGATIVE_MATRIX.md`.

## Before every push: the local battery

The battery runs, on your machine, the checks the hosted `Self-test required` check depends on.
It holds no list of its own: `tools/battery.py` reads `.github/workflows/self-test.yml`, takes
the jobs the `required` job needs, and runs what their steps run, so it cannot drift from the
hosted run.

```bash
tools/battery.sh --fast          # Git Bash, Linux, macOS: every check except the tree-clean sweep
tools/battery.sh                 # the same plus the sweep (every test in a throwaway clone; slow)
tools/battery.sh --list          # the plan: each check, and each step that runs only on GitHub
tools/battery.sh --only ticket   # only the checks whose command matches a regular expression
tools/battery.sh --strict        # an UNKNOWN check fails the battery too
```

```powershell
tools\battery.ps1 --fast         # Windows PowerShell; puts Git for Windows' bash ahead of the WSL stub
```

Each check prints its rc and time; the summary names every failure with the tail of its output.

| rc | verdict | meaning |
|---|---|---|
| 0 | PASS | the check ran and held |
| 2 | UNKNOWN | the check could not run here: a tool or credential this machine lacks (the log says which) |
| anything else, or a timeout | FAIL | the check ran and refused, or hung |

The battery exits 1 when any check FAILED. UNKNOWN does not fail it unless `--strict` is given,
because a laptop rarely has every scanner; the hosted run has them all and an UNKNOWN there is red.

What the battery does not run, and says so in `--list`: the reusable-workflow calls (hosted
negative controls GitHub runs), runner probes whose outputs feed later `uses:` steps, and the
inline `yamllint` step, whose local twin `tests/check_yamllint.py` reads that step's own config.

### Setting up a machine for it

- Python 3.9 or later with `PyYAML` and `jsonschema` (`python -m pip install PyYAML jsonschema yamllint`).
- Git for Windows on Windows (its bash, not WSL's, runs the step bodies).
- For fewer UNKNOWN rows: `actionlint` 1.7.7 on PATH (or `ACTIONLINT=/path/to/actionlint`), Docker,
  and the scanner versions `.github/actions/selftest-tools/action.yml` pins (Semgrep, Trivy,
  osv-scanner, bandit, gosec).

### Local scanner tools: `KIT_LOCAL_TOOLS`

A laptop proves less than the hosted runner when a scanner is missing: its checks answer UNKNOWN.
To prove as much locally, place the pinned releases yourself and point the battery at them:

```bash
KIT_LOCAL_TOOLS=/d/tools tools/battery.sh --fast
```

```powershell
$env:KIT_LOCAL_TOOLS = 'D:\tools'; tools\battery.ps1 --fast
```

- **Layout.** `<dir>/<tool>-<version>/` holding the executable (`gitleaks-8.21.2/gitleaks.exe`), or a
  `bin/` under it (`go-1.22.12/bin/go.exe`). For this run only, the battery puts `<dir>`, each child
  and each child's `bin/` ahead of `PATH` (children named `_…` or `.…`, e.g. a `_downloads` folder,
  are skipped). Your shell profile is not touched.
- **The battery never downloads anything.** You fetch each tool from its vendor's release, into a
  new empty directory, and verify it against the vendor's published checksum file before use. The
  versions are the ones `.github/actions/selftest-tools/action.yml` downloads (osv-scanner, gosec,
  syft, gitleaks, Trivy) and the one `self-test.yml` downloads itself (actionlint); cppcheck and flawfinder are the runner's distribution packages, unpinned.
  gosec's proof also needs Go (`inputs.go_version` 1.22).
- **Preflight.** Before any check runs, every tool those files pin is resolved on that `PATH`
  and asked its version: `OK` (the pin), `ABSENT` (its checks stay UNKNOWN, as before) or
  `VERSION_MISMATCH` (another release, or no version printed). **A VERSION_MISMATCH fails the
  battery (rc 1) even when every check passed**: a pass on another release is not the hosted proof.
- Unset or empty, nothing changes. A value that is not a directory is UNKNOWN (rc 2), nothing run.
- Checks that need Linux itself (`tests/prove_pipeline_lint.py` P3–P6) still answer UNKNOWN on
  Windows; run that proof inside a WSL distribution with Linux tools in their own `KIT_LOCAL_TOOLS`.

`tests/prove_battery_mirrors_selftest.py` T1–T6 hold the battery to this.

### The rest of the pre-push checklist

1. `tools/battery.sh` (with the sweep) on the committed tree is green.
2. Rebase on the trunk before pushing; another lane may have moved it.
3. Never force-push and never `--no-verify`. If a hook, guard or permission check blocks you, stop and
   ask the repository owner; never change repository settings yourself.
4. After the push, watch the hosted self-test: the local battery is not the Linux runner.

`tests/prove_battery_mirrors_selftest.py` holds the battery to this description: it plans every
script self-test runs, fails and names a failing check, keeps running after one, treats exit 2 as
UNKNOWN, fails a check that hangs or whose script is gone, and refuses an empty plan.
