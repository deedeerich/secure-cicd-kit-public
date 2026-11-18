# Code walkthrough: tools/

```
Kept:      generated 2026-11-07 against the trunk; the file list is mechanical (git ls-files), the
           descriptions were written by reading each file. tests/check_code_walkthrough_coverage.py
           fails when a tracked file has no row here, or a row names a file that is gone.
Columns:   "called by" = files that run, import, inline or `uses:` it; "proved by" = tests that name it.
           Both are computed by text search, so they can over-count a mention as a use.
```

[Back to the walkthrough index](README.md)

3 files.

| file | what it does | called by | inputs and outputs | proved by |
|---|---|---|---|---|
| `tools/battery.ps1` | The PowerShell twin of the battery: finds bash and Python and calls `tools/battery.py`. | `tools/battery.py` | - | `tests/prove_battery_mirrors_selftest.py` |
| `tools/battery.py` | The local battery: reads `.github/workflows/self-test.yml`, runs what its required jobs run, and reports PASS, FAIL or UNKNOWN per check. `KIT_LOCAL_TOOLS` puts locally placed scanners on PATH, and a placed tool whose version is not the pinned one fails. | `tests/prove_battery_mirrors_selftest.py` | args: `--workflow`, `--root`, `--fast`, `--list`, `--only`, `--strict` +3 | `tests/prove_battery_mirrors_selftest.py` |
| `tools/battery.sh` | The bash twin of the battery: finds Python and calls `tools/battery.py`. | `tests/prove_battery_mirrors_selftest.py` | - | `tests/prove_battery_mirrors_selftest.py` |
