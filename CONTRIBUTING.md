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

### The rest of the pre-push checklist

1. `tools/battery.sh` (with the sweep) on the committed tree is green.
2. Rebase on the trunk before pushing; another lane may have moved it.
3. Never force-push and never `--no-verify`. If a hook, guard or permission check blocks you, stop and
   ask the repository owner; never change repository settings yourself.
4. After the push, watch the hosted self-test: the local battery is not the Linux runner.

`tests/prove_battery_mirrors_selftest.py` holds the battery to this description: it plans every
script self-test runs, fails and names a failing check, keeps running after one, treats exit 2 as
UNKNOWN, fails a check that hangs or whose script is gone, and refuses an empty plan.
