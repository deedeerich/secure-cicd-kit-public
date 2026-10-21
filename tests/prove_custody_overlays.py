#!/usr/bin/env python3
"""Run tests/check_custody.py against constructed trees and prove it handles NO overlay, EVERY
overlay, and the cross-repository call shape (ledger L107; KDEC-008 OD-10).

WHY THIS EXISTS
    check_custody.py read `MANIFESTS[0]` and `OVERLAY_DIRS[0]`:
      * with no overlay at all it crashed (`os.path.exists(None)`) -- the neutral kit, the one
        tree that must always pass, could not run its own custody check;
      * it checked only the FIRST overlay (alphabetically), so a second overlay that copied the
        pipeline instead of calling the core, or a second ledger, was never looked at.
    And KDEC-008 OD-10: an overlay calls the kit cross-repository by
    `owner/repo/.github/workflows/reusable-security.yml@<sha>` -- a `./` path resolves against
    the CALLER's checkout and works only inside the kit repository.

SCENARIOS (a throwaway tree each, the checker run with --root)
    no_overlay           neutral core only                         -> exit 0
    pinned_overlay       overlay calls owner/repo/...@<40-hex>     -> exit 0
    local_path_overlay   overlay calls ./.github/workflows/...     -> exit 1 (OD-10)
    unpinned_overlay     overlay calls owner/repo/...@main         -> exit 1 (OD-10)
    second_overlay_fork  first overlay fine, second copies, not calls -> exit 1
    second_ledger_drift  second overlay's ledger declares an absent capability -> exit 1

EXIT
    0  every scenario decided as it must
    1  a scenario decided wrongly
    2  could not be checked -- UNKNOWN, never PASS
"""
import io
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CHECK = os.path.join(HERE, 'check_custody.py')
SHA = '0123456789abcdef0123456789abcdef01234567'
CORE = ('name: core\non:\n  workflow_call:\njobs:\n  scan:\n    runs-on: ubuntu-latest\n'
        '    steps:\n      - run: gitleaks detect --source .\n')
# Origin values are capability_origin terms (assurance-taxonomy.yaml), as the shipped ledgers use.
LEDGER = ('Capability,Origin,Custody,Implemented before AM,Completed during AM\n'
          'gitleaks,PREEXISTING_NEUTRAL_IMPLEMENTATION,neutral,yes,no\n')


def overlay_wf(uses):
    return ('name: overlay\non:\n  workflow_call:\njobs:\n  neutral:\n    uses: %s\n'
            '    secrets: inherit\n' % uses)


def tree(root, overlays):
    os.makedirs(os.path.join(root, '.github', 'workflows'))
    io.open(os.path.join(root, '.github', 'workflows', 'reusable-security.yml'), 'w').write(CORE)
    for name, wf, ledger in overlays:
        d = os.path.join(root, 'overlays', name)
        os.makedirs(os.path.join(d, 'docs'))
        if wf is not None:
            os.makedirs(os.path.join(d, 'workflows'))
            io.open(os.path.join(d, 'workflows', 'security-overlay.yml'), 'w').write(wf)
        io.open(os.path.join(d, 'docs', 'CAPABILITY_CUSTODY.csv'), 'w').write(
            ledger.replace('neutral', 'neutral') if ledger else LEDGER)


GOOD = overlay_wf('KIT_OWNER/KIT_REPO/.github/workflows/reusable-security.yml@%s' % SHA)
SCENARIOS = [
    ('no_overlay', [], 0),
    ('pinned_overlay', [('alpha', GOOD, None)], 0),
    ('local_path_overlay', [('alpha', overlay_wf('./.github/workflows/reusable-security.yml'),
                             None)], 1),
    ('unpinned_overlay', [('alpha', overlay_wf(
        'KIT_OWNER/KIT_REPO/.github/workflows/reusable-security.yml@main'), None)], 1),
    ('second_overlay_fork', [('alpha', GOOD, None),
                             ('beta', 'name: fork\non: push\njobs:\n  copy:\n    runs-on: x\n'
                                      '    steps:\n      - run: gitleaks detect --source .\n',
                              None)], 1),
    ('second_ledger_drift', [('alpha', GOOD, None),
                             ('beta', None,
                              LEDGER + 'OWASP ZAP,OVERLAY_REQUESTED_CAPABILITY,beta,yes,no\n')],
     1),
]


def main():
    bad = []
    for name, overlays, want in SCENARIOS:
        root = tempfile.mkdtemp(prefix='custody-')
        try:
            tree(root, overlays)
            p = subprocess.run([sys.executable, CHECK, '--root', root], capture_output=True,
                               text=True, encoding='utf-8', errors='replace',
                               env=dict(os.environ, PYTHONUTF8='1'))
            out = (p.stdout or '') + (p.stderr or '')
            print('  %-22s exit=%d (want %d)' % (name, p.returncode, want))
            if p.returncode != want:
                bad.append('%s: exit %d, expected %d\n%s' % (name, p.returncode, want, out[-700:]))
        finally:
            shutil.rmtree(root, ignore_errors=True)
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: check_custody passes a tree with no overlay, checks every overlay and every '
          'ledger, and requires an overlay to call the kit cross-repository, pinned to a SHA.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
