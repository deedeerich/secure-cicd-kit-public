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

    KIT_LOCAL_TOOLS (owner, 2026-11-07: local runs should prove as much as hosted ones)
      T1  POSITIVE  a pinned tool placed in <dir>/<tool>-<version>/ is found by a check, which
                    then PASSES where it was UNKNOWN; the preflight names it at the kit's pin.
      T2  NEGATIVE  KIT_LOCAL_TOOLS unset, or set to the empty string, changes nothing: the same
                    verdicts, the same PATH handed to every check, no preflight.
      T3  NEGATIVE  a tool whose version differs from the pin (including a near miss, 1.2.30 for
                    1.2.3) is VERSION_MISMATCH and fails the battery (rc 1), never a silent pass.
      T4  NEGATIVE  KIT_LOCAL_TOOLS naming a directory that does not exist is UNKNOWN (rc 2) before
                    anything runs; an existing empty directory changes no verdict.
      T5  NEGATIVE  the battery downloads nothing: no network call in it or in its shell twins.
      T6  the pins are read from .github/actions/selftest-tools/action.yml and the release downloads
          self-test.yml makes itself (actionlint), never from a second list.

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


FAKE_PINS = """name: fake pinned tools
runs:
  using: composite
  steps:
    - name: a pinned release
      shell: bash
      run: |
        v=1.2.3; t=kitfaketool_${v}_linux_amd64.tar.gz
        curl -sSfLO "https://github.com/example/kitfaketool/releases/download/v${v}/${t}"
"""
NEEDTOOL = ('import os, shutil, sys\n'
            'print("PATH=" + os.environ.get("PATH", ""))\n'
            'sys.exit(0 if shutil.which("kitfaketool") else 2)\n')


@contextlib.contextmanager
def local_tools(value):
    """KIT_LOCAL_TOOLS set to `value` (None = unset) for the block, restored after."""
    old = os.environ.get('KIT_LOCAL_TOOLS')
    if value is None:
        os.environ.pop('KIT_LOCAL_TOOLS', None)
    else:
        os.environ['KIT_LOCAL_TOOLS'] = value
    try:
        yield
    finally:
        if old is None:
            os.environ.pop('KIT_LOCAL_TOOLS', None)
        else:
            os.environ['KIT_LOCAL_TOOLS'] = old


def fake_tool(tools_dir, version):
    """A `kitfaketool` that prints `version`, at <tools_dir>/kitfaketool-<version>/."""
    d = os.path.join(tools_dir, 'kitfaketool-' + version)
    os.makedirs(d)
    if os.name == 'nt':
        with open(os.path.join(d, 'kitfaketool.cmd'), 'w', encoding='utf-8', newline='\r\n') as fh:
            fh.write('@echo off\necho kitfaketool version %s\n' % version)
    else:
        p = os.path.join(d, 'kitfaketool')
        with open(p, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write('#!/bin/sh\necho "kitfaketool version %s"\n' % version)
        os.chmod(p, 0o755)


def battery_json(argv, value):
    """Run the battery with KIT_LOCAL_TOOLS=value; -> (rc, stdout, {check: (verdict, PATH seen)})."""
    fd, jp = tempfile.mkstemp(suffix='.json')
    os.close(fd)
    try:
        with local_tools(value):
            rc, out = run_battery(argv + ['--json', jp])
        res = {}
        if os.path.getsize(jp):
            import json
            for r in json.load(open(jp, encoding='utf-8'))['results']:
                seen = [ln for ln in r['tail'] if ln.startswith('PATH=')]
                res[r['check']] = (r['verdict'], seen[0] if seen else None)
        return rc, out, res
    finally:
        os.remove(jp)


def local_tools_claims(sh, ps, contrib):
    d, wf = sandbox(step('needs a pinned tool', 'python3 tests/needtool.py'))
    tools = tempfile.mkdtemp(prefix='battery-tools-')
    empty = tempfile.mkdtemp(prefix='battery-tools-empty-')
    try:
        with open(os.path.join(d, 'tests', 'needtool.py'), 'w', encoding='utf-8') as fh:
            fh.write(NEEDTOOL)
        pins = os.path.join(d, 'pins.yml')
        with open(pins, 'w', encoding='utf-8') as fh:
            fh.write(FAKE_PINS)
        argv = ['--workflow', wf, '--root', d, '--timeout', '20', '--only', 'needtool', '--pins', pins]
        key = 'python3 tests/needtool.py'

        # T6: the pins come from the selftest-tools composite, not a second list.
        real = battery.tool_pins() if hasattr(battery, 'tool_pins') else {}
        claim(real.get('gitleaks') == '8.21.2' and real.get('osv-scanner') == '2.6.0' and
              real.get('gosec') == '2.24.6' and real.get('syft') == '1.52.0' and real.get('trivy') == '0.71.2' and
              real.get('actionlint') == '1.7.7',
              'T6 the pins are read from the selftest-tools composite and self-test.yml', repr(real))
        claim(battery.tool_pins(pins) == {'kitfaketool': '1.2.3'} if hasattr(battery, 'tool_pins') else False,
              'T6 a pin is the release a composite downloads (v/t variables substituted)')

        # T2: unset and empty are the baseline, identical to each other.
        rc0, out0, base = battery_json(argv, None)
        rc1, out1, empty_val = battery_json(argv, '')
        claim(rc0 == 0 and base.get(key, (None,))[0] == 'UNKNOWN', 'T2 baseline: the tool is absent, UNKNOWN',
              '%s %r' % (rc0, base))
        claim(empty_val == base and rc1 == rc0, 'T2 KIT_LOCAL_TOOLS="" gives the same verdicts and PATH as unset',
              '%r vs %r' % (empty_val, base))
        claim('VERSION_MISMATCH' not in out0 + out1 and 'local tools' not in (out0 + out1).lower(),
              'T2 unset or empty: no preflight is printed')

        # T4: an absent directory refuses before running; an empty one changes no verdict.
        rc, out, res = battery_json(argv, os.path.join(tools, 'no-such-dir'))
        claim(rc == 2 and 'UNKNOWN' in out and not res, 'T4 a KIT_LOCAL_TOOLS that is not a directory is rc 2, nothing run',
              'rc=%s %s' % (rc, out[-300:]))
        rc, out, res = battery_json(argv, empty)
        claim(rc == 0 and res.get(key, (None,))[0] == 'UNKNOWN',
              'T4 an empty tools directory changes no verdict', 'rc=%s %r' % (rc, res))

        # T1: the pinned tool in <dir>/<tool>-<version>/ is found and the check passes.
        fake_tool(tools, '1.2.3')
        rc, out, res = battery_json(argv, tools)
        claim(rc == 0 and res.get(key, (None,))[0] == 'PASS',
              'T1 a pinned tool in KIT_LOCAL_TOOLS turns the UNKNOWN check into a PASS', 'rc=%s %s' % (rc, out[-500:]))
        claim(re.search(r'kitfaketool\s+OK\s+1\.2\.3', out) is not None,
              'T1 the preflight names the tool at the kit pin', out[-500:])
        seen = (res.get(key) or (None, ''))[1] or ''
        claim('kitfaketool-1.2.3' in seen, 'T1 the tool directory is on the PATH the check is handed', seen[:200])

        # T3: a version that differs from the pin is VERSION_MISMATCH and fails the battery.
        for wrong in ('9.9.9', '1.2.30'):
            mt = tempfile.mkdtemp(prefix='battery-tools-mm-')
            try:
                fake_tool(mt, wrong)
                rc, out, res = battery_json(argv, mt)
                claim(rc == 1 and re.search(r'VERSION_MISMATCH\s+kitfaketool', out) is not None,
                      'T3 kitfaketool %s (pin 1.2.3) is VERSION_MISMATCH and fails the battery' % wrong,
                      'rc=%s %s' % (rc, out[-500:]))
            finally:
                shutil.rmtree(mt, ignore_errors=True)
    finally:
        for p in (d, tools, empty):
            shutil.rmtree(p, ignore_errors=True)

    # T5: nothing downloads.
    src = open(os.path.join(ROOT, 'tools', 'battery.py'), encoding='utf-8').read()
    net = re.compile(r'urllib|urlopen|requests\b|http\.client|\bcurl\b|\bwget\b|Invoke-WebRequest|Invoke-RestMethod|'
                     r'Start-BitsTransfer|https?://')
    claim(not net.search(src) and not net.search(sh) and not net.search(ps),
          'T5 the battery and its twins contain no download or network call')
    claim('KIT_LOCAL_TOOLS' in src and 'KIT_LOCAL_TOOLS' in sh and 'KIT_LOCAL_TOOLS' in ps and
          os.path.exists(contrib) and 'KIT_LOCAL_TOOLS' in open(contrib, encoding='utf-8').read(),
          'T5 KIT_LOCAL_TOOLS is documented in the battery, both twins and CONTRIBUTING.md')


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

    local_tools_claims(sh, ps, contrib)

    if FAILS:
        print('FAIL: %d claim(s): %s' % (len(FAILS), ', '.join(FAILS)))
        return 1
    print('PASS: the battery reads self-test, runs each check with its rc, and fails, names and times out honestly.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
