#!/usr/bin/env python3
"""The actionlint baseline is ENFORCED: an unclassified finding fails, a stale row fails, a defect cannot be baselined. NO NETWORK.

WHY (KDEC-058, 2026-11-13)
    tests/check_actionlint.py used to drop every finding CONTAINING two strings, so 89 inherited findings were
    invisible and any new finding of the same shape would have been too. It now compares actionlint's output
    with docs/assurance/ACTIONLINT_BASELINE.md exactly. This proves that comparison can fail in each way it
    claims, by driving check_actionlint.evaluate() with findings built from the real baseline rows (no
    actionlint binary is needed; the actionlint job also runs the check itself over the real tree).

WHAT IT PROVES
    B1  POSITIVE   the real baseline parses (57 rows, every class 1, two versions) and findings equal to its
                   rows PASS on 1.7.12 and on 1.7.7 (the 1.7.7-only rows are compared only on 1.7.7)
    B2  POSITIVE   lines that moved with the count unchanged are a NOTE, not a failure
    B3  POSITIVE   a row whose workflow is absent from the tree (withheld by a profile) is NOTED, not stale
    N1  NEGATIVE   a new finding no row covers                          -> UNCLASSIFIED
    N2  NEGATIVE   one more `$/` occurrence than a row records           -> UNCLASSIFIED
    N3  NEGATIVE   a row that no longer occurs                           -> STALE
    N4  NEGATIVE   a row that occurs fewer times than it records         -> STALE
    N5  NEGATIVE   a 1.7.7-only row (R2) still required on 1.7.7         -> STALE when it stops occurring there
    N6  NEGATIVE   a class-2 row                                         -> DEFECT_BASELINED
    N7  NEGATIVE   an actionlint version the baseline was not verified with -> ACTIONLINT_VERSION_UNCLASSIFIED
    N8  NEGATIVE   a malformed row, a duplicate id, a missing "Verified with" line -> BaselineError (UNKNOWN)
    MUTANTS (each a weakened evaluate(); the same fixtures must expose it)
        substring_exclusion   the pre-2026-11-13 behaviour: drop any line containing `specifying action "$/`
                              -> N2 and the new-`$/`-file case pass under it, so it is caught
        no_stale_check        rows that no longer occur are ignored -> N3 passes under it, caught
        count_ignored         presence only, counts ignored -> N2 and N4 pass under it, caught
        defect_allowed        class-2 rows accepted -> N6 passes under it, caught

EXIT  0 all hold   1 any does not   2 could not be checked
"""
import io
import os
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check_actionlint as ca  # noqa: E402

FAILS = []


def check(cond, msg):
    print('  %s %s' % ('ok  ' if cond else 'FAIL', msg))
    if not cond:
        FAILS.append(msg)
    return bool(cond)


def findings_from(rows, version):
    out = {}
    for r in rows:
        if version in r['versions']:
            out[(r['file'], r['kind'], r['message'])] = list(r['lines'])
    return out


def has(problems, code):
    return any(p.startswith(code) for p in problems)


def run(evaluate, f, rows, version, verified, present):
    return evaluate(f, rows, version, verified, present)[0]


# ── mutants: each is the real evaluate() with one guard removed ─────────────────────────────────────────────
def m_substring_exclusion(findings, rows, version, verified, present):
    kept = dict((k, v) for k, v in findings.items() if 'specifying action "$/' not in k[2]
                and 'maximum number of inputs for "workflow_dispatch" event is 10' not in k[2])
    return ([('UNCLASSIFIED: %s' % (k,)) for k in kept], [], {})


def m_no_stale_check(findings, rows, version, verified, present):
    p, n, c = ca.evaluate(findings, rows, version, verified, present)
    return [x for x in p if not x.startswith('STALE')], n, c


def m_count_ignored(findings, rows, version, verified, present):
    p, n, c = ca.evaluate(findings, rows, version, verified, present)
    return [x for x in p if ' expects ' not in x], n, c


def m_defect_allowed(findings, rows, version, verified, present):
    p, n, c = ca.evaluate(findings, rows, version, verified, present)
    return [x for x in p if not x.startswith('DEFECT_BASELINED')], n, c


def main():
    verified, rows = ca.read_baseline()
    present = set(r['file'] for r in rows)
    v12, v77 = '1.7.12', '1.7.7'
    print('B positives')
    check(len(rows) == 57 and set(r['class'] for r in rows) == {'1'} and verified == [v77, v12],
          'B1 the real baseline: 57 rows, every one class 1, verified with %s' % verified)
    check(sum(r['count'] for r in rows if v12 in r['versions']) == 99
          and sum(r['count'] for r in rows if v77 in r['versions']) == 101,
          'B1 the rows account for 99 findings on 1.7.12 and 101 on 1.7.7')
    for v in (v12, v77):
        p = run(ca.evaluate, findings_from(rows, v), rows, v, verified, present)
        check(not p, 'B1 findings equal to the rows PASS on %s %s' % (v, p[:1]))
    moved = findings_from(rows, v12)
    k0 = sorted(moved)[0]
    moved[k0] = [x + 3 for x in moved[k0]]
    p, notes, _ = ca.evaluate(moved, rows, v12, verified, present)
    check(not p and any('moved' in n for n in notes), 'B2 moved lines are a NOTE, the count holds')
    gone = next(r['file'] for r in rows if v12 in r['versions'])
    withheld = set(present) - {gone}
    f = dict((k, v) for k, v in findings_from(rows, v12).items() if k[0] != gone)
    p, notes, c = ca.evaluate(f, rows, v12, verified, withheld)
    check(not p and c['withheld'] >= 1 and any('not in this tree' in n for n in notes),
          'B3 a withheld workflow\'s rows are NOTED, not stale')

    print('N negatives (and which mutant each exposes)')
    dollar = next(r for r in rows if r['message'].startswith('specifying action "$/') and v12 in r['versions'])
    r2 = next(r for r in rows if r['reason'] == 'R2')
    fx = {}
    f = findings_from(rows, v12)
    f[('.github/workflows/self-test.yml', 'expression', 'property "nope" is not defined in object type {}')] = [9]
    fx['N1'] = (f, rows, v12, 'UNCLASSIFIED')
    f = findings_from(rows, v12)
    f[(dollar['file'], dollar['kind'], dollar['message'])] = dollar['lines'] + [99999]
    fx['N2'] = (f, rows, v12, 'UNCLASSIFIED')
    f = findings_from(rows, v12)
    f[('.github/workflows/brand-new.yml', 'action', dollar['message'])] = [5]
    fx['N2b'] = (f, rows, v12, 'UNCLASSIFIED')
    f = findings_from(rows, v12)
    del f[(dollar['file'], dollar['kind'], dollar['message'])]
    fx['N3'] = (f, rows, v12, 'STALE')
    multi = next(r for r in rows if r['count'] > 1)
    f = findings_from(rows, v12)
    f[(multi['file'], multi['kind'], multi['message'])] = multi['lines'][1:]
    fx['N4'] = (f, rows, v12, 'STALE')
    f = findings_from(rows, v77)
    del f[(r2['file'], r2['kind'], r2['message'])]
    fx['N5'] = (f, rows, v77, 'STALE')
    bad = [dict(r) for r in rows]
    bad[0]['class'] = '2'
    fx['N6'] = (findings_from(rows, v12), bad, v12, 'DEFECT_BASELINED')
    fx['N7'] = (findings_from(rows, v12), rows, '1.7.99', 'ACTIONLINT_VERSION_UNCLASSIFIED')
    for name in sorted(fx):
        f, rr, v, code = fx[name]
        p = run(ca.evaluate, f, rr, v, verified, present)
        check(has(p, code), '%s fails %s: %s' % (name, code, (p[:1] or ['nothing'])[0][:110]))
    # N8: a malformed baseline is UNKNOWN, never an empty pass
    text = io.open(ca.BASELINE, encoding='utf-8').read()
    first_row = next(l for l in text.splitlines() if l.startswith('| AL-'))
    cases = {'malformed row': text.replace(first_row, first_row.replace('| 1 |', '| one |', 1), 1),
             'duplicate id': text.replace(first_row, first_row + '\n' + first_row, 1),
             'no verified line': re.sub(r'(?m)^Verified with actionlint:.*$', '', text),
             'no rows': '\n'.join(l for l in text.splitlines() if not l.startswith('| AL-'))}
    for label, body in sorted(cases.items()):
        fd, path = tempfile.mkstemp(suffix='.md')
        os.close(fd)
        io.open(path, 'w', encoding='utf-8').write(body)
        try:
            ca.read_baseline(path)
            check(False, 'N8 %s raises BaselineError' % label)
        except ca.BaselineError as e:
            check(True, 'N8 %s raises BaselineError: %s' % (label, str(e)[:70]))
        finally:
            os.remove(path)

    print('MUTANTS (each must let a negative through, so the real check is what catches it)')
    for mname, mut, exposes in (('substring_exclusion', m_substring_exclusion, ('N2', 'N2b')),
                                ('no_stale_check', m_no_stale_check, ('N3',)),
                                ('count_ignored', m_count_ignored, ('N2', 'N4')),
                                ('defect_allowed', m_defect_allowed, ('N6',))):
        let_through = []
        for name in exposes:
            f, rr, v, code = fx[name]
            if not has(run(mut, f, rr, v, verified, present), code):
                let_through.append(name)
        check(len(let_through) == len(exposes),
              'mutant %s caught: it passes %s, which the real check fails' % (mname, ', '.join(exposes)))
    print('PASS' if not FAILS else 'FAIL: %d check(s) failed' % len(FAILS))
    return 1 if FAILS else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, StopIteration, ca.BaselineError) as e:
        print('could not be checked: %s' % e)
        sys.exit(2)
