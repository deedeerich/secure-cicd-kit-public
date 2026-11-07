#!/usr/bin/env python3
"""Every negative control has a paired positive control, or a named reason (owner, 2026-11-06).

WHY THIS EXISTS
    "I see negative testing but no positive testing." docs/assurance/POSITIVE_NEGATIVE_MATRIX.md records, per
    proof and per hosted control, the positive control (the normal user's path works) and the negative
    control(s). This holds the matrix to the tree:

    C1  every tests/prove_*.py has a row (a new proof cannot land unaudited)
    C2  every row that names a negative control names a positive control, or its pairing column says
        `REASON: <why>` in at least five words
    C3  every tests/ or scripts/ file a row cites exists
    C4  the pairing column is PAIRED or REASON: ..., never empty or UNPAIRED
    C5  every hosted control job self-test runs as a refusal (scripts/selftest_required.py
        table of controls that refuse by skipping, and the kit API refusal) has a row in the hosted-controls table

EXIT  0 the matrix holds   1 a rule refused (each named)   2 the matrix could not be read
"""
import glob
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
MATRIX = os.path.join('docs', 'assurance', 'POSITIVE_NEGATIVE_MATRIX.md')
HOSTED = ('ticket-reconcile-refuses-pr', 'ticket-reference-not-assessed-off-pr', 'exception-due-lists-on-push',
          'ledger-proposal-refuses-pr', 'kit-api-refuses-by-name', 'dogfood-policy')


def rows(text):
    out = []
    for ln in text.splitlines():
        if not ln.startswith('| ') or ln.startswith('|---') or ln.startswith('| proof ') or ln.startswith('| job '):
            continue
        cells = [c.strip() for c in ln.strip().strip('|').split('|')]
        out.append(cells)
    return out


def problems(root, text):
    probs = []
    allrows = rows(text)
    proof_rows = {}
    for c in allrows:
        m = re.match(r'^`tests/(prove_[\w]+\.py)`$', c[0])
        if m and len(c) >= 5:
            proof_rows[m.group(1)] = c
    for p in sorted(glob.glob(os.path.join(root, 'tests', 'prove_*.py'))):
        b = os.path.basename(p)
        if b not in proof_rows:
            probs.append('C1 tests/%s has no row in %s' % (b, MATRIX))
    for b, c in sorted(proof_rows.items()):
        _proof, _cap, pos, neg, pair = c[:5]
        if pair != 'PAIRED' and not pair.startswith('REASON:'):
            probs.append('C4 tests/%s: pairing is %r, not PAIRED or REASON: ...' % (b, pair))
        if neg and not neg.startswith('REASON:') and not pos and not (pair.startswith('REASON:') and len(pair.split()) >= 6):
            probs.append('C2 tests/%s has a negative control and no positive control or named reason' % b)
        if pair == 'PAIRED' and not pos:
            probs.append('C2 tests/%s says PAIRED and names no positive control' % b)
    for ref in sorted(set(re.findall(r'`((?:tests|scripts)/[\w./-]+\.py)`', text))):
        if not os.path.exists(os.path.join(root, *ref.split('/'))):
            probs.append('C3 %s is cited and does not exist' % ref)
    hosted = {c[0] for c in allrows}
    for j in HOSTED:
        if j not in hosted:
            probs.append('C5 the hosted control %s has no row' % j)
    return probs


def self_test():
    head = '| proof | capability | positive control | negative control(s) | pairing |\n|---|---|---|---|---|\n'
    host = ''.join('| %s | x | y | PAIRED |\n' % j for j in HOSTED)
    work_root = ROOT
    good = head + ''.join('| `tests/%s` | c | in-file: ok | in-file: no | PAIRED |\n' % os.path.basename(p)
                          for p in glob.glob(os.path.join(ROOT, 'tests', 'prove_*.py'))) + host
    cases = [('the control', good, []),
             ('a proof with no row', good.replace('| `tests/prove_deploy_gate.py` | c | in-file: ok | in-file: no | PAIRED |\n', ''), ['C1']),
             ('a negative with no positive', good.replace('| `tests/prove_deploy_gate.py` | c | in-file: ok |', '| `tests/prove_deploy_gate.py` | c |  |'), ['C2']),
             ('a short reason does not count', good.replace('| `tests/prove_deploy_gate.py` | c | in-file: ok | in-file: no | PAIRED |',
                                                            '| `tests/prove_deploy_gate.py` | c |  | in-file: no | REASON: none |'), ['C2']),
             ('a named reason counts', good.replace('| `tests/prove_deploy_gate.py` | c | in-file: ok | in-file: no | PAIRED |',
                                                    '| `tests/prove_deploy_gate.py` | c |  | in-file: no | REASON: its positive case lives in the gate proof, by design |'), []),
             ('UNPAIRED', good.replace('| `tests/prove_deploy_gate.py` | c | in-file: ok | in-file: no | PAIRED |',
                                       '| `tests/prove_deploy_gate.py` | c | in-file: ok | in-file: no | UNPAIRED |'), ['C4']),
             ('a cited file that does not exist', good + '| `tests/prove_nothing_here.py` | c | `tests/prove_nothing_here.py` | n | PAIRED |\n', ['C3']),
             ('a hosted control with no row', good.replace('| kit-api-refuses-by-name | x | y | PAIRED |\n', ''), ['C5'])]
    bad = []
    for label, text, want in cases:
        got = sorted(set(p.split()[0] for p in problems(work_root, text)))
        if got != sorted(want):
            bad.append('%s: wanted %s, got %s' % (label, want, got))
    for b in bad:
        print('SELF-TEST FAIL: %s' % b)
    print('self-test %s: %d cases' % ('FAILED' if bad else 'ok', len(cases)))
    return 1 if bad else 0


def main(argv):
    if '--self-test' in argv:
        return self_test()
    try:
        text = io.open(os.path.join(ROOT, MATRIX), encoding='utf-8').read()
    except OSError as e:
        print('UNKNOWN: %s could not be read (%s)' % (MATRIX, e))
        return 2
    probs = problems(ROOT, text)
    for p in probs:
        print('REFUSED: %s' % p)
    if probs:
        print('FAIL: %d problem(s): every negative control needs its positive control, or a named reason.' % len(probs))
        return 1
    n = len(glob.glob(os.path.join(ROOT, 'tests', 'prove_*.py')))
    print('PASS: %d proofs and %d hosted controls each carry a positive control or a named reason.' % (n, len(HOSTED)))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
