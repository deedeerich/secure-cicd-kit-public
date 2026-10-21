#!/usr/bin/env python3
"""The consumer census is never written inside the kit (W4K-114).

WHY THIS EXISTS
    scripts/inventory_consumers.py writes a record listing the absolute path of every directory
    under the roots it surveys -- the operator's private estate. It wrote that record into the
    kit's own root, where only a .gitignore line kept it out of a commit; a fresh clone without
    that line, or a `git add -f`, would have committed the estate map.

WHAT IT PROVES
    K1  run over a throwaway root, the census writes nothing inside the kit's tree
    K2  CONTROL: it does write its record -- to CONSUMER_COVERAGE_OUT when set, outside the kit
    K3  pointed INSIDE the kit by CONSUMER_COVERAGE_OUT, it refuses (exit non-zero, no file)

EXIT  0 all hold, 1 any does not
"""
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, 'scripts', 'inventory_consumers.py')
IN_KIT = os.path.join(ROOT, 'consumer-coverage.json')


def run(root, out):
    env = dict(os.environ, PYTHONIOENCODING='utf-8')
    if out:
        env['CONSUMER_COVERAGE_OUT'] = out
    else:
        env.pop('CONSUMER_COVERAGE_OUT', None)
    return subprocess.run([sys.executable, SCRIPT, root], capture_output=True, text=True,
                          encoding='utf-8', errors='replace', env=env, cwd=root)


def main():
    if os.path.exists(IN_KIT):
        print('UNKNOWN: %s already exists, so a write there cannot be told apart.' % IN_KIT)
        return 2
    work = tempfile.mkdtemp(prefix='census-')
    bad = []
    try:
        proj = os.path.join(work, 'estate', 'proj-a')
        os.makedirs(proj)
        open(os.path.join(proj, 'main.py'), 'w').write('x = 1\n')
        out = os.path.join(work, 'census.json')
        p = run(os.path.join(work, 'estate'), out)
        if os.path.exists(IN_KIT):
            bad.append('K1 the census wrote %s' % IN_KIT)
            os.remove(IN_KIT)
        if p.returncode != 0 or not os.path.isfile(out):
            bad.append('K2 CONTROL: no record at CONSUMER_COVERAGE_OUT (rc %d): %s'
                       % (p.returncode, (p.stdout + p.stderr)[-400:]))
        p = run(os.path.join(work, 'estate'), IN_KIT)
        if p.returncode == 0 or os.path.exists(IN_KIT):
            bad.append('K3 pointed inside the kit, the census did not refuse')
            if os.path.exists(IN_KIT):
                os.remove(IN_KIT)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    for b in bad:
        print('FAIL ' + b)
    if bad:
        return 1
    print('PASS: the census writes outside the kit, and refuses a destination inside it.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
