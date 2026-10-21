#!/usr/bin/env python3
"""Exactly one disposition removes anything, and no unknown can reach it.

WHY THIS EXISTS (L98; DEPLOYMENT_CONTRACT_RECONCILIATION.md section 8)

    A change manifest is a record of the past; a reversal acts on the present. Release R1
    creates X, something else later modifies X or takes a dependency on it, and R1's manifest
    still truthfully says "I created X" -- which is no longer authority to delete X. Section 8
    turns every manifest entry into a PROPOSAL evaluated against live state: P1 ownership stamp,
    P2 version against the recorded post-state, P3 later releases, P4 external modification,
    P5 later dependents, P6 reverse-ancestry order.

    The reference fixture in tests/check_reversal_preconditions.py has called
    `scripts/derive_reversal_disposition.py` since it was written. The script did not exist.
    The structural check proved the SHAPE of a reversal that derives a disposition before it
    deletes; nothing proved the derivation.

WHAT THIS RUNS -- the script's command line, the real enforcement point (PROOF_RULE.md)
    table      every row of section 8.2 and the entry-scoped tree of section 8.1
    allowed    an entry this release created, still stamped by it, unchanged, nothing depending
               on it, no descendant standing -> REVERSAL_REMOVE (a derivation that never removes
               is a brick, not a control)
    attack     a SECOND ACTOR modified the object this run created -> REVERSAL_REFUSED_CONFLICT
               naming P4; a second actor took a DEPENDENCY on it -> REVERSAL_WITHHELD_DEPENDENCY
               naming the dependent
    missing    every precondition made unknown in turn, and then EVERY combination of known and
               unknown inputs swept: REVERSAL_REMOVE appears only where all six are positively
               established. "No conflict found" is also what a failed conflict query returns.
    recovery   the same entry, re-read once the evidence is available, derives REMOVE again;
               and the reference fixture's exact invocation runs and emits a key=value line
               its `if:` can read.

EXIT  0 proven   1 a case decided wrongly   2 could not be checked (UNKNOWN, never PASS)
"""
import io
import itertools
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPT = os.path.join(ROOT, 'scripts', 'derive_reversal_disposition.py')

R = 'rel-42'
STAMP = 'release_id=%s;parent=rel-41;run=900;post=v2' % R


def cli(args):
    p = subprocess.run([sys.executable, SCRIPT] + args, capture_output=True, text=True)
    out = {}
    for line in p.stdout.splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            out[k] = v
    return p.returncode, out, p.stdout + p.stderr


def entry(**over):
    """A fully-established CREATED entry. Each case changes one thing."""
    e = {'object': 'revision/app--r7', 'action': 'CREATED', 'stamp': STAMP,
         'current_version': 'v2', 'recorded_post_version': 'v2', 'later_releases': [],
         'descendants': [], 'dependents': [], 'other_claims': [], 'classification': 'EXCLUSIVE'}
    e.update(over)
    return e


def batch(entries):
    tmp = tempfile.mkdtemp(prefix='disposition-')
    try:
        f = os.path.join(tmp, 'entries.json')
        io.open(f, 'w', encoding='utf-8').write(json.dumps(entries))
        p = subprocess.run([sys.executable, SCRIPT, '--release', R, '--entries', f],
                           capture_output=True, text=True)
        if p.returncode != 0:
            return None, p.stdout + p.stderr
        return json.loads(p.stdout), ''
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# (case, entry, expected disposition, expected deciding precondition or None, phrase in reason)
TABLE = [
    ('8.2 created, owned exclusive, unchanged', entry(), 'REVERSAL_REMOVE', None, None),
    ('8.2 modified, still the recorded post-state', entry(action='MODIFIED'),
     'REVERSAL_RESTORE_PRIOR', None, None),
    ('8.2 traffic redirected, unchanged since', entry(action='REDIRECTED'),
     'REVERSAL_RESTORE_PRIOR', None, None),
    ('8.2 superseded by a later release', entry(stamp='release_id=rel-43;post=v3',
                                                 current_version='v3', later_releases=['rel-43']),
     'REVERSAL_DEFERRED_TO_SUCCESSOR', 'P3', None),
    ('8.2 descendant still standing', entry(descendants=['rel-44']),
     'REVERSAL_DEFERRED_TO_SUCCESSOR', 'P6', None),
    ('8.2 ATTACK: second actor modified what this run created', entry(current_version='v9'),
     'REVERSAL_REFUSED_CONFLICT', 'P4', 'MODIFIED_BY_EXTERNAL_ACTOR'),
    ('8.2 stamp names another release', entry(stamp='release_id=rel-99;post=v2'),
     'REVERSAL_REFUSED_CONFLICT', 'P1', 'OWNED_BY_ANOTHER_RELEASE'),
    ('8.2 ATTACK: second actor took a dependency', entry(dependents=['traffic:canary-label']),
     'REVERSAL_WITHHELD_DEPENDENCY', 'P5', 'traffic:canary-label'),
    ('8.2 co-owned', entry(other_claims=['rel-50']),
     'REVERSAL_WITHHELD_DEPENDENCY', 'P1', 'rel-50'),
    ('8.2 stamp unreadable', entry(stamp=None), 'REVERSAL_WITHHELD_UNTRUSTED', 'P1', None),
    ('8.2 no stamp on the object', entry(stamp=''), 'REVERSAL_WITHHELD_UNTRUSTED', 'P1', None),
    ('8.2 version unreadable', entry(current_version=None),
     'REVERSAL_WITHHELD_UNTRUSTED', 'P2', None),
    ('8.2 no recorded post-state', entry(recorded_post_version=None),
     'REVERSAL_WITHHELD_UNTRUSTED', 'P2', None),
    ('8.2 release graph not traversable', entry(later_releases=None),
     'REVERSAL_WITHHELD_UNTRUSTED', 'P3', None),
    ('8.2 dependency read failed', entry(dependents=None),
     'REVERSAL_WITHHELD_UNTRUSTED', 'P5', None),
    ('8.2 descendants unknown', entry(descendants=None),
     'REVERSAL_WITHHELD_UNTRUSTED', 'P6', None),
    ('8.1 parent moved, our entry intact, removal side-effect-free',
     entry(action='ENTRY', current_version='v5', entry_unchanged=True,
           entry_side_effect_free=True, entry_independent=True),
     'REVERSAL_ENTRY_SCOPED', None, None),
    ('8.1 our own entry edited by someone else',
     entry(action='ENTRY', current_version='v5', entry_unchanged=False),
     'REVERSAL_REFUSED_CONFLICT', 'P4', None),
    ('8.1 removing our entry alters an ordered neighbour',
     entry(action='ENTRY', current_version='v5', entry_unchanged=True,
           entry_side_effect_free=False),
     'REVERSAL_WITHHELD_DEPENDENCY', 'P5', None),
    ('8.1 granularity unestablished',
     entry(action='ENTRY', current_version='v5', entry_unchanged=True,
           entry_side_effect_free=True, entry_independent=None),
     'REVERSAL_WITHHELD_UNTRUSTED', 'P4', None),
    ('8.3a platform-owned shared resource', entry(classification='PLATFORM_OWNED_SHARED'),
     'REVERSAL_WITHHELD_DEPENDENCY', None, 'platform'),
]

DISPOSITIONS = {'REVERSAL_REMOVE', 'REVERSAL_RESTORE_PRIOR', 'REVERSAL_DEFERRED_TO_SUCCESSOR',
                'REVERSAL_ENTRY_SCOPED', 'REVERSAL_REFUSED_CONFLICT',
                'REVERSAL_WITHHELD_DEPENDENCY', 'REVERSAL_WITHHELD_UNTRUSTED'}


def sweep_entries():
    """Every combination of each precondition input being: established-good, unknown, bad."""
    axes = {
        'stamp': [STAMP, None, '', 'release_id=rel-99'],
        'current_version': ['v2', None, 'v9'],
        'recorded_post_version': ['v2', None],
        'later_releases': [[], None, ['rel-43']],
        'descendants': [[], None, ['rel-44']],
        'dependents': [[], None, ['x']],
        'other_claims': [[], None, ['rel-50']],
        'action': ['CREATED', 'MODIFIED'],
    }
    keys = list(axes)
    for combo in itertools.product(*(axes[k] for k in keys)):
        yield dict(zip(keys, combo))


def main():
    if not os.path.isfile(SCRIPT):
        print('FAIL: %s does not exist. The reference fixture in tests/check_reversal_'
              'preconditions.py calls it; the derivation it names has never been built.'
              % os.path.relpath(SCRIPT, ROOT))
        return 1
    fails = []

    rc, out, log = cli(['--self-test'])
    if rc != 0:
        fails.append('the script\'s own self-test failed:\n' + log[-600:])

    got, err = batch([e for _c, e, _d, _p, _r in TABLE])
    if got is None:
        print('FAIL: batch mode refused the table: %s' % err[-400:])
        return 1
    for (case, _e, want, prec, phrase), g in zip(TABLE, got):
        d = g.get('reversal_disposition')
        ok = d == want and (prec is None or g.get('deciding_precondition') == prec) and \
            (phrase is None or phrase in json.dumps(g))
        print('  %-62s %s' % (case, d))
        if not ok:
            fails.append('%s: got %s / %s, wanted %s / %s%s' % (
                case, d, g.get('deciding_precondition'), want, prec,
                (' naming %r' % phrase) if phrase else ''))

    # Missing evidence, exhaustively. REMOVE only where every precondition is established-good.
    sweep = list(sweep_entries())
    res, err = batch([entry(**s) for s in sweep])
    if res is None:
        fails.append('batch mode refused the sweep: %s' % err[-300:])
        res = []
    removes, bad_removes, unknown_dispositions = 0, [], set()
    for s, g in zip(sweep, res):
        d = g.get('reversal_disposition')
        if d not in DISPOSITIONS:
            unknown_dispositions.add(d)
        if d == 'REVERSAL_REMOVE':
            removes += 1
            good = (s['stamp'] == STAMP and s['current_version'] == 'v2' and
                    s['recorded_post_version'] == 'v2' and s['later_releases'] == [] and
                    s['descendants'] == [] and s['dependents'] == [] and
                    s['other_claims'] == [] and s['action'] == 'CREATED')
            if not good:
                bad_removes.append(s)
    print('  sweep: %d combinations, %d derive REVERSAL_REMOVE' % (len(sweep), removes))
    if unknown_dispositions:
        fails.append('unregistered dispositions emitted: %s' % sorted(unknown_dispositions))
    if bad_removes:
        fails.append('%d combination(s) reached REVERSAL_REMOVE without every precondition '
                     'positively established, e.g. %r' % (len(bad_removes), bad_removes[0]))
    if removes != 1:
        fails.append('expected exactly one REMOVE combination in the sweep, got %d' % removes)

    # Recovery: the attack entry, re-read after the evidence is restored, removes again.
    rec, _ = batch([entry(current_version='v9'), entry()])
    if not rec or [g.get('reversal_disposition') for g in rec] != [
            'REVERSAL_REFUSED_CONFLICT', 'REVERSAL_REMOVE']:
        fails.append('recovery: a re-read with the evidence restored did not derive REMOVE '
                     '(got %r)' % [g.get('reversal_disposition') for g in (rec or [])])

    # The reference fixture's exact command line: --stamp, --current-version, --release only.
    rc, out, log = cli(['--stamp', STAMP, '--current-version', 'v2', '--release', R])
    if rc != 0 or out.get('reversal_disposition') not in DISPOSITIONS:
        fails.append('the reference fixture\'s invocation did not emit a readable disposition '
                     '(exit %d):\n%s' % (rc, log[-300:]))
    elif out['reversal_disposition'] == 'REVERSAL_REMOVE':
        fails.append('the fixture\'s three-argument call derived REMOVE although P2-P6 were '
                     'never supplied -- an unasked question answered as "no conflict".')
    else:
        print('  fixture invocation -> %s (P2-P6 not supplied, so not removable)'
              % out['reversal_disposition'])

    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: every section 8.2 row derives its disposition for the named precondition; the')
    print('      second-actor modification refuses and the second-actor dependency withholds;')
    print('      across %d combinations REMOVE appears once, where all six are established.'
          % len(sweep))
    print('      DERIVATION ONLY. That a live adapter reads P1-P6 truthfully needs a real target')
    print('      and a real second actor -- the hosted acceptance matrix, DCR 7.8.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
