#!/usr/bin/env python3
"""Prove the pinning tools see composite actions, and treat `$/` as pinned by construction.

WHY THIS EXISTS

    Decomposition plan §7 step 9: before any scanner moves into a composite action, the two pinning
    tools must cover `.github/actions/**`. Otherwise Phase 2 moves every pinned image and every
    third-party `uses:` out of the only place they are checked, and the move itself is the regression.

    Two gaps, each proved here against a sandbox tree:

      1  check_pinned_artifacts.py scanned `.github/workflows/*.yml` only. An image pinned inside a
         composite was invisible to it.
      2  pin-actions.sh walked `.github` but read a `$/...` reference as "has no ref at all -- pin it
         manually" and exited 1. A `$/` reference resolves to this repository AT THE COMMIT THE
         CALLER PINNED (step 8, run 38434823833). It is pinned by construction and must be skipped
         like `./`, not reported as a failure that trains an operator to ignore the tool.

    No network: the sandbox holds no third-party reference, so pin-actions.sh never calls the API.

EXIT
    0  both tools cover composites and accept `$/`
    1  a gap remains
    2  could not be checked (bash missing) -- UNKNOWN, never PASS
"""
import io
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

COMPOSITE = """name: sandbox composite
runs:
  using: composite
  steps:
    - uses: $/.github/actions/other
    - shell: bash
      run: docker run --rm securego/gosec:2.24.6 -version
"""


def main():
    import check_pinned_artifacts as cpa
    bash = shutil.which('bash')
    if not bash:
        print('UNKNOWN: bash is required to run pin-actions.sh.')
        return 2

    failures = []
    work = tempfile.mkdtemp(prefix='pin-scope-')
    cwd = os.getcwd()
    try:
        d = os.path.join(work, '.github', 'actions', 'scan-x')
        os.makedirs(d)
        os.makedirs(os.path.join(work, '.github', 'workflows'))
        io.open(os.path.join(d, 'action.yml'), 'w', encoding='utf-8', newline='\n').write(COMPOSITE)

        os.chdir(work)
        found = cpa.find_images(cpa.CODE_PATTERNS) if hasattr(cpa, 'CODE_PATTERNS') \
            else cpa.find_images([cpa.WORKFLOWS])
        if ('securego/gosec', '2.24.6') not in found:
            failures.append('check_pinned_artifacts does not see an image pinned in a composite')

        env = dict(os.environ, GITHUB_TOKEN=os.environ.get('GITHUB_TOKEN') or 'unused-no-network')
        p = subprocess.run([bash, os.path.join(ROOT, 'scripts', 'pin-actions.sh')],
                           capture_output=True, text=True, env=env, cwd=work)
        print(p.stdout.strip())
        if p.returncode != 0:
            failures.append('pin-actions.sh exits %d on a tree whose only reference is $/'
                            % p.returncode)
    finally:
        os.chdir(cwd)
        shutil.rmtree(work, ignore_errors=True)

    for f in failures:
        print('FAIL: %s.' % f)
    if failures:
        return 1
    print('PASS: composites are in scope for both pinning tools, and $/ is accepted as pinned.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
