#!/usr/bin/env python3
"""A proof no workflow runs is refused by name (completion ledger G-03 / L72).

WHY THIS EXISTS

    check_selftest_coverage.py counted WORKFLOWS and nothing else. Nine proofs existed that no
    workflow ran -- among them the stage register, the identity-durability proof and the pin
    checker's own scope proof -- and the census was green over all of them. A proof that is never
    run is a string: green the day it was written, and nobody would see it turn red.

WHAT IT PROVES (against constructed trees, never the real one)
    P1  a tests/ proof that no workflow runs is refused, by name
    P2  a proof named only in a workflow COMMENT is still refused (a mention is not a run)
    P3  a scripts/ file with a --self-test mode whose mode no workflow runs is refused
    P4  an UNWIRED entry accounts for an unrun proof until it expires; expired, it is refused
    P5  an UNWIRED entry for a proof a workflow now runs is refused as stale
    P6  CONTROL: a tree where every proof is run, and a runtime tool is declared, passes
    P7  the real repository: every proof is run, declared a runtime tool, or under an unexpired
        UNWIRED entry

EXIT  0 all hold   1 any does not   2 could not be checked
"""
import datetime
import importlib
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

TODAY = datetime.date(2026, 10, 21)
WF_HEAD = ('name: t\non:\n  push:\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n'
           '      - run: |\n')


def tree(work, name, proofs, lines, scripts=()):
    root = os.path.join(work, name)
    os.makedirs(os.path.join(root, '.github', 'workflows'))
    os.makedirs(os.path.join(root, 'tests'))
    os.makedirs(os.path.join(root, 'scripts'))
    for p in proofs:
        open(os.path.join(root, 'tests', p), 'w').write('print(1)\n')
    for s in scripts:
        open(os.path.join(root, 'scripts', s), 'w').write("import sys\nif '--self-test' in sys.argv: pass\n")
    body = WF_HEAD + ''.join('          %s\n' % ln for ln in lines)
    open(os.path.join(root, '.github', 'workflows', 'self-test.yml'), 'w').write(body)
    return root


def main():
    try:
        C = importlib.import_module('check_selftest_coverage')
    except Exception as e:  # noqa: BLE001
        print('UNKNOWN: could not import check_selftest_coverage (%s)' % e)
        return 2
    census = getattr(C, 'proof_census', None)
    bad = []
    if census is None:
        bad.append('check_selftest_coverage has NO proof census: a proof no workflow runs is '
                   'invisible to it, and it reports green over every one')
        for b in bad:
            print('FAIL ' + b)
        return 1
    work = tempfile.mkdtemp(prefix='proof-census-')
    try:
        unw = {'prove_held.py': {'reason': 'seeded', 'owner': 'kit-maintainer', 'closes': 'seeded',
                                 'expires': '2099-01-01'}}
        cases = [
            ('P1 unrun proof', tree(work, 'p1', ['prove_a.py', 'prove_b.py'],
                                    ['python3 tests/prove_a.py']), {}, {}, ['prove_b.py']),
            ('P2 comment is not a run', tree(work, 'p2', ['prove_a.py'],
                                             ['# python3 tests/prove_a.py', 'echo hi']),
             {}, {}, ['prove_a.py']),
            ('P3 unrun --self-test', tree(work, 'p3', [], ['python3 scripts/lib.py'],
                                          scripts=['lib.py']), {}, {}, ['lib.py']),
            ('P4 unexpired UNWIRED accounts', tree(work, 'p4', ['prove_held.py'], ['echo hi']),
             {}, unw, []),
            ('P4 expired UNWIRED refused', tree(work, 'p4x', ['prove_held.py'], ['echo hi']),
             {}, {'prove_held.py': dict(unw['prove_held.py'], expires='2026-01-01')},
             ['prove_held.py']),
            ('P5 stale UNWIRED refused', tree(work, 'p5', ['prove_held.py'],
                                              ['python3 tests/prove_held.py']), {}, unw,
             ['prove_held.py']),
            ('P6 CONTROL all run', tree(work, 'p6', ['prove_a.py', 'live_tool.py'],
                                        ['python3 tests/prove_a.py',
                                         'python3 scripts/lib.py --self-test'],
                                        scripts=['lib.py']),
             {'live_tool.py': 'needs a live target'}, {}, []),
        ]
        for label, root, runtime, unwired, want in cases:
            problems, _ = census(root, TODAY, runtime=runtime, unwired=unwired)
            named = [w for w in want if any(w in p for p in problems)]
            ok = (len(problems) == 0) if not want else (len(named) == len(want))
            print('  %-32s problems=%d %s' % (label, len(problems), 'ok' if ok else 'WRONG'))
            if not ok:
                bad.append('%s: want %s named, got %s' % (label, want or 'none', problems))
        problems, counts = census(ROOT, datetime.date.today())
        print('  %-32s problems=%d run=%d runtime=%d unwired=%d'
              % ('P7 the real repository', len(problems), counts['run'], counts['runtime'],
                 counts['unwired']))
        bad.extend('P7 ' + p for p in problems)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    for b in bad:
        print('FAIL ' + b)
    if bad:
        return 1
    print('PASS: an unrun proof, a proof only mentioned in a comment and an unrun --self-test are each')
    print('      refused by name; a dated UNWIRED entry accounts until it expires, and is refused once')
    print('      a workflow runs the proof; every proof in this repository is run or accounted for.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
