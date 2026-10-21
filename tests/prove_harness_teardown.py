#!/usr/bin/env python3
"""Full teardown is a TEST-HARNESS behaviour, safe only where absence was proven first.

WHY THIS EXISTS (L102; ROLLBACK_CONTRACT.md "Integration-test harness")

    "Full destroy is permitted in the personal-tenant test because absence is proven first, not
    because destroy is safe":

        PRE_TEST_RESOURCE_COUNT  = 0   asserted for the tagged test scope, BEFORE deploying
        POST_CLEANUP_RESOURCE_COUNT = 0   asserted AFTER, failing loudly if not

    The kit had this only as a manual runbook. tests/harness/teardown_scope.py implements it, and
    this file proves it through its command line against the stub cloud (tests/_fake_az.py).

THE CASES (docs/PROOF_RULE.md)
    allowed    pre-count 0 -> deploy creates tagged resources -> teardown removes them -> post 0
    attack     teardown with no PRE receipt for the scope -> refused, nothing deleted
    attack     a non-empty scope at PRE -> refused; the harness may not run there
    attack     a resource onboarded in between WITHOUT the scope tag survives the teardown
    missing    the list read fails -> UNKNOWN (exit 2), never a zero count
    recovery   a delete that fails leaves POST > 0 -> exit 1, loud, naming what remains
    structure  no reusable workflow references the harness script -- it is never in the
               reusable deploy path

EXIT  0 proven   1 a case decided wrongly   2 could not be checked (UNKNOWN, never PASS)
"""
import glob
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _workflow_runner as W  # noqa: E402

SCRIPT = os.path.join(HERE, 'harness', 'teardown_scope.py')
TAG = 'kit-test-scope=run-7'


def world(resources, **faults):
    s = {'resources': resources}
    s.update(faults)
    return s


def run(work, state, *args):
    """Run the harness CLI with the stub az first on PATH. -> (rc, out, final_state)."""
    sp = os.path.join(work, 'state.json')
    io.open(sp, 'w', encoding='utf-8').write(json.dumps(state))
    lp = os.path.join(work, 'calls.jsonl')
    io.open(lp, 'a').close()
    bin_dir = W.stub_bin(sp, lp)
    try:
        env = dict(os.environ, fake_az_state=sp, fake_az_log=lp,
                   AZURE_CONFIG_DIR=os.path.join(work, 'no-azure-config'),
                   PATH=bin_dir + os.pathsep + os.environ.get('PATH', ''))
        p = subprocess.run([sys.executable, SCRIPT] + list(args), capture_output=True, text=True,
                           env=env, cwd=work)
        return p.returncode, p.stdout + p.stderr, json.load(io.open(sp, encoding='utf-8'))
    finally:
        shutil.rmtree(bin_dir, ignore_errors=True)


def tagged(i):
    return {'id': '/rg/test-rg/r%d' % i, 'resource_group': 'test-rg',
            'tags': {'kit-test-scope': 'run-7'}}


def main():
    if not os.path.isfile(SCRIPT):
        print('FAIL: %s does not exist; the harness teardown is a manual runbook only.'
              % os.path.relpath(SCRIPT, os.path.dirname(HERE)))
        return 1
    fails = []
    work = tempfile.mkdtemp(prefix='teardown-proof-')
    try:
        receipt = os.path.join(work, 'pre.json')
        common = ['--resource-group', 'test-rg', '--scope-tag', TAG]

        rc, out, _ = run(work, world([]), 'pre', *common, '--receipt', receipt)
        print('  allowed  pre on an empty scope            exit=%d' % rc)
        if rc != 0 or not os.path.isfile(receipt):
            fails.append('allowed: PRE on an empty scope did not pass and write a receipt:\n' + out)
        stranger = {'id': '/rg/test-rg/onboarded', 'resource_group': 'test-rg', 'tags': {}}
        rc, out, final = run(work, world([tagged(1), tagged(2), stranger]), 'teardown', *common,
                             '--receipt', receipt)
        left = [r['id'] for r in final['resources']]
        print('  allowed  teardown, stranger in between    exit=%d left=%s' % (rc, left))
        if rc != 0 or left != ['/rg/test-rg/onboarded']:
            fails.append('allowed/attack: teardown did not remove exactly the tagged scope and '
                         'leave the untagged resource onboarded in between (left %s):\n%s'
                         % (left, out))

        rc, out, final = run(work, world([tagged(1)]), 'teardown', *common,
                             '--receipt', os.path.join(work, 'missing.json'))
        print('  attack   teardown with no PRE receipt     exit=%d left=%d' % (rc, len(final['resources'])))
        if rc == 0 or len(final['resources']) != 1:
            fails.append('attack: teardown ran without a PRE receipt proving the scope was empty.')

        rc, out, _ = run(work, world([tagged(9)]), 'pre', *common,
                         '--receipt', os.path.join(work, 'pre2.json'))
        print('  attack   pre on a non-empty scope         exit=%d' % rc)
        if rc != 1 or os.path.isfile(os.path.join(work, 'pre2.json')):
            fails.append('attack: PRE on a non-empty scope did not refuse (exit %d).' % rc)

        rc, out, _ = run(work, world([], fail=['resource list']), 'pre', *common,
                         '--receipt', os.path.join(work, 'pre3.json'))
        print('  missing  pre with the list read failing   exit=%d' % rc)
        if rc != 2 or os.path.isfile(os.path.join(work, 'pre3.json')):
            fails.append('missing: a failed read was not UNKNOWN (exit %d); a read failure '
                         'reported as zero would license the teardown.' % rc)

        rc, out, final = run(work, world([tagged(1)], delete_fails=['resource delete']),
                             'teardown', *common, '--receipt', receipt)
        print('  recovery delete fails, POST > 0          exit=%d' % rc)
        if rc != 1 or 'POST_CLEANUP_RESOURCE_COUNT' not in out or '/rg/test-rg/r1' not in out:
            fails.append('recovery: a teardown that left a resource behind did not fail loudly '
                         'naming it:\n' + out)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    root = os.path.dirname(HERE)
    for wf in glob.glob(os.path.join(root, '.github', 'workflows', 'reusable-*.yml')):
        if 'teardown_scope' in io.open(wf, encoding='utf-8').read():
            fails.append('%s references the harness teardown. It must never be in the reusable '
                         'deploy path.' % os.path.basename(wf))

    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: teardown runs only behind a PRE zero-count receipt for its scope, removes only')
    print('      tagged resources, reports a failed read as UNKNOWN and a non-zero POST loudly,')
    print('      and no reusable workflow references it. STUBBED: the live run is owed.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
