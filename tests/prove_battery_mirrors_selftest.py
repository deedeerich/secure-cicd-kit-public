#!/usr/bin/env python3
"""The local battery runs what self-test's required jobs run, with an rc per check (owner, 2026-11-06).

WHY THIS EXISTS
    The pre-push battery lived in a session scratchpad and was lost. tools/battery.py replaces it by
    READING .github/workflows/self-test.yml instead of carrying a list. This proves both halves:

    POSITIVE
      P1  every tests/ or scripts/ file self-test's required jobs invoke is in the battery's plan
          (as its own check or inside a whole-step check), or the step is named hosted-only.
      P2  a clean workflow: every check PASSES, the battery exits 0, the summary counts them.
      P3  a step added to the workflow is in the plan with no edit to the battery (no drift).
      P4  the shell twins exist and hand every argument to tools/battery.py.
    NEGATIVE
      N1  a failing check (exit 1) fails the battery (rc 1), is NAMED, and the checks after it still run.
      N2  exit 2 is UNKNOWN, not PASS: rc 0 by default, rc 2 under --strict.
      N3  a whole-step negative control (`if python ...; then exit 1`) that cannot fail is a FAIL.
      N4  a line nested in `if` and the lines of a heredoc are not split out as checks.
      N5  a job the required check does not need is not run.
      N6  a check that hangs is a FAIL (timeout), not a pass.
      N7  no workflow, or no `required` job: UNKNOWN (rc 2), never an empty green.
      N8  a check whose script is missing is a FAIL (python's own exit 2 would read UNKNOWN).
      N9  a check that leaves a file in the working tree is a FAIL, and the file is named.

EXIT 0 proven   1 a claim failed   2 could not run (PyYAML missing)
"""
import io
import os
import re
import subprocess
import sys
import tempfile
import shutil
import contextlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'tools'))

try:
    import yaml  # noqa: F401
except ImportError:
    print('UNKNOWN: PyYAML is required')
    sys.exit(2)
import battery  # noqa: E402

FAILS = []


def claim(ok, name, detail=''):
    print('  %s  %s%s' % ('ok  ' if ok else 'FAIL', name, (' -- ' + detail) if detail and not ok else ''))
    if not ok:
        FAILS.append(name)


def run_battery(argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = battery.main(argv)
    return rc, buf.getvalue()


WF = """name: t
on: [push]
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@0000000000000000000000000000000000000000 # v1
      - name: two checks
        run: |
          set -euo pipefail
          python3 tests/ok1.py
          python3 tests/ok2.py --flag
          if [ -n "x" ]; then
            python3 tests/nested.py
          fi
      - name: inline negative control
        run: |
          if python3 tests/mustfail.py; then
            echo "cannot fail"; exit 1
          fi
          python - <<'PYEOF'
          print("heredoc ran")
          PYEOF
%(extra)s
  b:
    uses: ./.github/workflows/other.yml
  notneeded:
    runs-on: ubuntu-latest
    steps:
      - name: never
        run: python3 tests/never.py
  required:
    needs: [a, b]
    if: always()
    runs-on: ubuntu-latest
    steps:
      - run: echo verdict
"""

SCRIPTS = {
    'ok1.py': 'import sys; sys.exit(0)',
    'ok2.py': 'import sys; sys.exit(0 if "--flag" in sys.argv else 1)',
    'nested.py': 'import sys; sys.exit(1)',
    'mustfail.py': 'import sys; sys.exit(1)',
    'never.py': 'import sys; sys.exit(1)',
    'bad.py': 'import sys; print("seeded failure"); sys.exit(1)',
    'unknown.py': 'import sys; print("UNKNOWN: no tool"); sys.exit(2)',
    'hang.py': 'import time; time.sleep(30)',
    'canpass.py': 'import sys; sys.exit(0)',
}


def sandbox(extra=''):
    d = tempfile.mkdtemp(prefix='battery-proof-')
    os.makedirs(os.path.join(d, 'tests'))
    for n, body in SCRIPTS.items():
        with open(os.path.join(d, 'tests', n), 'w', encoding='utf-8') as fh:
            fh.write(body + '\n')
    wf = os.path.join(d, 'wf.yml')
    with open(wf, 'w', encoding='utf-8') as fh:
        fh.write(WF % {'extra': extra})
    return d, wf


def step(name, line):
    return '      - name: %s\n        run: |\n          %s\n' % (name, line)


def main():
    print('Battery mirrors self-test (tools/battery.py):')
    # ---- P1: the real self-test, every invoked script is planned or named hosted-only ----------
    checks, hosted, err = battery.plan()
    claim(err is None and len(checks) > 100, 'P1 the real self-test plans (%d checks)' % len(checks), err or '')
    doc = yaml.safe_load(open(battery.SELF_TEST, encoding='utf-8'))
    jobs = doc['jobs']
    needed = jobs['required']['needs']
    planned_text = '\n'.join(c['cmd'] for c in checks)
    hosted_steps = {(j, s) for j, s, _ in hosted}
    missing = []
    for j in needed:
        for st in (jobs[j].get('steps') or []):
            body = str(st.get('run') or '')
            for ref in sorted(set(re.findall(r'python3?\s+((?:tests|scripts)/[\w./-]+\.py)', body))):
                if ref not in planned_text and (j, st.get('name') or st.get('uses') or '(unnamed)') not in hosted_steps:
                    # a reference nested under a PR-only branch is covered when the same script runs elsewhere
                    missing.append('%s :: %s' % (j, ref))
    claim(not missing, 'P1 every script the required jobs invoke is a battery check or a named hosted-only step',
          '; '.join(missing[:8]))

    # ---- P2/N3/N4/N5: a clean fake workflow -----------------------------------------------------
    d, wf = sandbox()
    try:
        rc, out = run_battery(['--workflow', wf, '--root', d, '--timeout', '20'])
        names = [c['name'] for c in battery.plan(wf)[0] if c['job'] != '(extra)']
        claim(rc == 0, 'P2 a clean workflow passes (rc 0)', out[-400:])
        claim('python3 tests/ok1.py' in names and 'python3 tests/ok2.py --flag' in names,
              'P2 each top-level check line is its own check')
        claim('== battery summary' in out and 'PASS' in out, 'P2 a summary is printed')
        claim(not any('nested.py' == n.split('/')[-1] for n in names) and
              not any(n.endswith('tests/nested.py') for n in names),
              'N4 a line nested in `if` is not split out as its own check')
        claim(not any('heredoc ran' in n for n in names), 'N4 heredoc lines are not checks')
        claim(not any('never.py' in n for n in names), 'N5 a job the required check does not need is not run')
        claim(any(j == 'b' for j, _, _ in battery.plan(wf)[1]), 'P2 a reusable-workflow call is named hosted-only')
        claim(any(n.startswith('step: inline negative control') for n in names),
              'P2 a step with a negative control runs whole')
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # ---- P3: a new step is planned with no battery edit ----------------------------------------
    d, wf = sandbox(step('added later', 'python3 tests/canpass.py'))
    try:
        names = [c['name'] for c in battery.plan(wf)[0]]
        claim('python3 tests/canpass.py' in names, 'P3 a step added to the workflow is planned (no drift)')
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # ---- N1: a failing check fails the battery, is named, and later checks still run ------------
    d, wf = sandbox(step('seeded fail', 'python3 tests/bad.py') + step('after it', 'python3 tests/canpass.py'))
    try:
        rc, out = run_battery(['--workflow', wf, '--root', d, '--timeout', '20', '--only', 'tests/'])
        claim(rc == 1, 'N1 a failing check fails the battery (rc 1)', 'rc=%s' % rc)
        claim(re.search(r'FAIL\s+rc=1\s+python3 tests/bad\.py', out) is not None, 'N1 the failing check is named')
        claim('seeded failure' in out, 'N1 its output tail is shown')
        claim(re.search(r'PASS\s+rc=0\s+\S+\s+python3 tests/canpass\.py', out) is not None,
              'N1 the checks after a failure still run')
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # ---- N2: exit 2 is UNKNOWN; --strict fails on it ------------------------------------------
    d, wf = sandbox(step('a tool this host lacks', 'python3 tests/unknown.py'))
    try:
        rc, out = run_battery(['--workflow', wf, '--root', d, '--timeout', '20', '--only', 'unknown'])
        claim(rc == 0 and 'UNKNOWN rc=2' in out, 'N2 exit 2 is reported UNKNOWN, not PASS', out[-300:])
        rc, out = run_battery(['--workflow', wf, '--root', d, '--timeout', '20', '--only', 'unknown', '--strict'])
        claim(rc == 2, 'N2 --strict fails the battery on UNKNOWN (rc 2)', 'rc=%s' % rc)
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # ---- N3: a negative control that cannot fail is a FAIL -------------------------------------
    d, wf = sandbox()
    try:
        with open(os.path.join(d, 'tests', 'mustfail.py'), 'w', encoding='utf-8') as fh:
            fh.write('import sys; sys.exit(0)\n')  # the mutant: the gate can no longer fail
        rc, out = run_battery(['--workflow', wf, '--root', d, '--timeout', '20', '--only', 'negative'])
        claim(rc == 1 and 'FAIL' in out, 'N3 a negative control that cannot fail fails the battery', out[-300:])
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # ---- N6: a hanging check is a FAIL -----------------------------------------------------------
    d, wf = sandbox(step('hangs', 'python3 tests/hang.py'))
    try:
        rc, out = run_battery(['--workflow', wf, '--root', d, '--timeout', '2', '--only', 'hang'])
        claim(rc == 1 and 'rc=timeout' in out, 'N6 a check that hangs is a FAIL (timeout)', out[-300:])
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # ---- N8: a check whose script is gone is a FAIL, not python's exit-2 UNKNOWN ----------------
    d, wf = sandbox(step('gone', 'python3 tests/deleted_check.py'))
    try:
        rc, out = run_battery(['--workflow', wf, '--root', d, '--timeout', '20', '--only', 'deleted'])
        claim(rc == 1 and 'does not exist' in out, 'N8 a check whose script is missing is a FAIL', out[-300:])
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # ---- N9: a check that leaves a file in the working tree is a FAIL ---------------------------
    d, wf = sandbox(step('litters', 'python3 tests/litter.py'))
    try:
        with open(os.path.join(d, 'tests', 'litter.py'), 'w', encoding='utf-8') as fh:
            fh.write('open("left-behind.txt", "w").write("x")\n')
        subprocess.run(['git', 'init', '-q', d], capture_output=True)
        subprocess.run(['git', '-C', d, 'add', '-A'], capture_output=True)
        subprocess.run(['git', '-C', d, '-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qm', 'x'],
                       capture_output=True)
        rc, out = run_battery(['--workflow', wf, '--root', d, '--timeout', '20', '--only', 'litter'])
        claim(rc == 1 and 'left-behind.txt' in out, 'N9 a check that leaves a file in the tree is a FAIL, named',
              out[-300:])
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # ---- N7: no workflow / no required job is UNKNOWN -----------------------------------------
    d = tempfile.mkdtemp(prefix='battery-proof-')
    try:
        rc, out = run_battery(['--workflow', os.path.join(d, 'absent.yml'), '--root', d])
        claim(rc == 2 and 'UNKNOWN' in out, 'N7 an absent workflow is UNKNOWN (rc 2)')
        p = os.path.join(d, 'noreq.yml')
        with open(p, 'w', encoding='utf-8') as fh:
            fh.write('on: [push]\njobs:\n  a:\n    runs-on: x\n    steps:\n      - run: python3 tests/x.py\n')
        rc, out = run_battery(['--workflow', p, '--root', d])
        claim(rc == 2 and 'required' in out, 'N7 a workflow with no required job is UNKNOWN (rc 2)')
    finally:
        shutil.rmtree(d, ignore_errors=True)

    # ---- P4: the shell twins call the Python core with every argument ----------------------------
    sh = open(os.path.join(ROOT, 'tools', 'battery.sh'), encoding='utf-8').read()
    ps = open(os.path.join(ROOT, 'tools', 'battery.ps1'), encoding='utf-8').read()
    claim('tools/battery.py "$@"' in sh, 'P4 battery.sh passes every argument to tools/battery.py')
    claim('tools/battery.py @args' in ps, 'P4 battery.ps1 passes every argument to tools/battery.py')
    claim('Git\\bin' in ps and 'BATTERY_BASH' in ps, 'P4 battery.ps1 puts Git bash ahead of the WSL stub')
    contrib = os.path.join(ROOT, 'CONTRIBUTING.md')
    claim(os.path.exists(contrib) and 'tools/battery' in open(contrib, encoding='utf-8').read(),
          'P4 CONTRIBUTING.md documents the battery')

    if FAILS:
        print('FAIL: %d claim(s): %s' % (len(FAILS), ', '.join(FAILS)))
        return 1
    print('PASS: the battery reads self-test, runs each check with its rc, and fails, names and times out honestly.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
