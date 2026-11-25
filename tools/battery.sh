#!/usr/bin/env bash
# The local battery (CP-018): the checks self-test's required jobs run, run here with an rc per
# check and a summary. All logic is in tools/battery.py, which reads .github/workflows/self-test.yml,
# so this list cannot drift from the hosted one. Arguments pass through (--fast, --list, --only,
# --strict, --json). See CONTRIBUTING.md.
# KIT_LOCAL_TOOLS=<dir> (scanners you placed, checksum-verified, as <dir>/<tool>-<version>/) passes
# through in the environment; tools/battery.py puts it on PATH and checks each pinned version.
# Neither this twin nor the battery downloads anything.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(dirname "$here")"
py="${BATTERY_PYTHON:-}"
if [ -z "$py" ]; then
  for c in python3 python; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
      py="$c"; break
    fi
  done
fi
if [ -z "$py" ]; then
  echo "UNKNOWN: no Python 3.9+ found (set BATTERY_PYTHON)." >&2
  exit 2
fi
cd "$root" || exit 2
exec "$py" tools/battery.py "$@"
