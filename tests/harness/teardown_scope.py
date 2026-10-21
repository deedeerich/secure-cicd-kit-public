#!/usr/bin/env python3
"""Integration-test harness teardown: PRE zero-count, then teardown, then POST zero-count.

TEST HARNESS ONLY. NEVER CALLED FROM A REUSABLE WORKFLOW (tests/prove_harness_teardown.py fails
if one references it). ROLLBACK_CONTRACT.md: full teardown is safe in the test harness "because
absence is proven first, not because destroy is safe", and it "is never imported into the
reusable deploy path" -- where "deployment failed, delete prod" would be a memorable Thursday.

    pre       list the tagged scope in the resource group; PRE_TEST_RESOURCE_COUNT must be 0.
              Writes a receipt naming the scope. A read failure is UNKNOWN (exit 2), never 0.
    teardown  refuses without a PRE receipt for the SAME scope; deletes only resources carrying
              the scope tag (a resource onboarded in between without the tag is not ours and is
              left alone); then POST_CLEANUP_RESOURCE_COUNT must be 0, failing loudly with what
              remains.

USAGE
    teardown_scope.py pre      --resource-group RG --scope-tag key=value --receipt FILE
    teardown_scope.py teardown --resource-group RG --scope-tag key=value --receipt FILE

EXIT  0 asserted   1 refused / count not zero   2 could not read the scope (UNKNOWN)
"""
import argparse
import io
import json
import shutil
import subprocess
import sys


def az(*args):
    exe = shutil.which('az')
    if not exe:
        return False, None, 'az CLI not found'
    p = subprocess.run([exe] + list(args) + ['-o', 'json'], capture_output=True, text=True)
    if p.returncode != 0:
        return False, None, (p.stderr or '').strip()[:300]
    try:
        return True, json.loads(p.stdout or 'null'), ''
    except ValueError:
        return False, None, 'unparseable az output'


def scope(rg, tag):
    ok, items, err = az('resource', 'list', '--resource-group', rg, '--tag', tag)
    if not ok or not isinstance(items, list):
        return None, err
    return [i.get('id') for i in items], ''


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument('mode', choices=('pre', 'teardown'))
    ap.add_argument('--resource-group', required=True)
    ap.add_argument('--scope-tag', required=True)
    ap.add_argument('--receipt', required=True)
    a = ap.parse_args(argv)
    if '=' not in a.scope_tag:
        print('scope tag must be key=value')
        return 1
    if a.mode == 'pre':
        ids, err = scope(a.resource_group, a.scope_tag)
        if ids is None:
            print('UNKNOWN: the scope could not be read (%s). A failed read is not a zero count.' % err)
            return 2
        print('PRE_TEST_RESOURCE_COUNT = %d' % len(ids))
        if ids:
            print('REFUSED: the test scope is not empty (%s). Full teardown is defensible only '
                  'where absence was proven first.' % ', '.join(ids))
            return 1
        io.open(a.receipt, 'w', encoding='utf-8').write(json.dumps(
            {'resource_group': a.resource_group, 'scope_tag': a.scope_tag, 'pre_count': 0}))
        return 0
    try:
        rec = json.load(io.open(a.receipt, encoding='utf-8'))
    except (OSError, ValueError):
        print('REFUSED: no PRE receipt. Teardown without a proven-empty starting scope is the '
              'chainsaw the rollback contract exists to forbid.')
        return 1
    if rec.get('resource_group') != a.resource_group or rec.get('scope_tag') != a.scope_tag \
            or rec.get('pre_count') != 0:
        print('REFUSED: the PRE receipt is for a different scope.')
        return 1
    ids, err = scope(a.resource_group, a.scope_tag)
    if ids is None:
        print('UNKNOWN: the scope could not be read (%s); nothing deleted.' % err)
        return 2
    for rid in ids:
        ok, _, err = az('resource', 'delete', '--ids', rid)
        print('  delete %s -> %s' % (rid, 'ok' if ok else 'FAILED: %s' % err))
    left, err = scope(a.resource_group, a.scope_tag)
    if left is None:
        print('UNKNOWN: POST count could not be read (%s). Teardown that is not verified is '
              'configured, not observed.' % err)
        return 2
    print('POST_CLEANUP_RESOURCE_COUNT = %d' % len(left))
    if left:
        print('FAILED LOUDLY: resources remain after teardown: %s' % ', '.join(left))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
