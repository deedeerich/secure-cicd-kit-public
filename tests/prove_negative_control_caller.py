#!/usr/bin/env python3
"""KREQ-632 (FW section 12, option (b), accepted 2026-11-13 in KDEC-052): the negative control runs only for a reader.
NO NETWORK.

WHY
    consumer-path-negative.yml (the suite that must end red) could be started by hand with nothing reading
    its result. Option (b): a separate workflow, not independently runnable. Its first job `caller` runs
    scripts/negative_control_caller.py; every other job needs it, so a run with no reader stops there.

WHAT IT PROVES
  STRUCTURE (the shipped workflow, parsed)
    S1  `caller` exists, runs scripts/negative_control_caller.py with the dispatch inputs, and every other job
        needs it directly or through `seed`; `php-verdict` (always()) also requires needs.caller.result success
    S2  the dispatch inputs the readers send (correlation_id, scope) are still declared, so both readers keep
        working (consumer-path-test.yml's `gh workflow run`, scripts/measure_cost.py dispatch)
  POSITIVE (scripts/negative_control_caller.judge, the production function)
    P1  <run>-<attempt>-full-<epoch> naming an in-progress consumer-path-test.yml run of this repository proceeds
    P2  the PHP leg's id (scope php) proceeds the same way
    P3  cost-monorepo-before-1-<epoch> proceeds at scope full; cost-iac-heavy-after-2-<epoch> at scope iac
    P4  the command line exits 0 for a confirmed reader and 1 for a refusal, printing NOT_ESTABLISHED
  NEGATIVE (each refused NOT_ESTABLISHED, with the guard's own reason)
    N1  empty id (a hand dispatch)             "no correlation id"
    N2  the id's run is another workflow       "not .github/workflows/consumer-path-test.yml"
    N3  the id's run has completed             "has completed"
    N4  the id's run is in another repository  "belongs to"
    N5  the id was made for another scope      "was made for scope"
    N6  the run could not be read              "could not be read"
    N7  a cost class used with the wrong scope "measures scope"
  MUTANTS (a modified copy; the original is untouched)
    empty_id_proceeds -> N1   reader_path_unchecked -> N2   completed_run_accepted -> N3
    repository_unchecked -> N4   unread_run_trusted -> N6   seeded_php_without_caller -> S1
    php_verdict_ignores_caller -> S1

EXIT  0 proven   1 a case failed (named)   2 could not be checked (PyYAML absent)
"""
import io
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPT = os.path.join(ROOT, 'scripts', 'negative_control_caller.py')
WORKFLOW = os.path.join(ROOT, '.github', 'workflows', 'consumer-path-negative.yml')
REPO = 'owner/kit'
CPT = '.github/workflows/consumer-path-test.yml'


def load(replace=None):
    text = io.open(SCRIPT, encoding='utf-8').read()
    if replace:
        old, new = replace
        if text.count(old) != 1:
            raise AssertionError('mutant anchor occurs %d times: %r' % (text.count(old), old[:70]))
        text = text.replace(old, new)
    mod = types.ModuleType('negative_control_caller_under_test')
    mod.__file__ = SCRIPT
    exec(compile(text, SCRIPT, 'exec'), mod.__dict__)  # noqa: S102 -- the kit's own source
    return mod


def runs(path=CPT, status='in_progress', repo=REPO, raise_=False):
    def fetch(run_id):
        if raise_:
            raise IOError('HTTP 404')
        return {'id': int(run_id), 'path': path, 'status': status, 'repository': {'full_name': repo}}
    return fetch


def behaviour(m):
    """-> {case: (ok, detail)} for the judge function of module m."""
    out = {}

    def case(name, cid, scope, fetch, want_ok, want_text):
        ok, why = m.judge(cid, scope, REPO, fetch)
        good = (ok is want_ok) and (want_text in why) and (want_ok or why.startswith('NOT_ESTABLISHED'))
        out[name] = (good, '%s -> %s %s' % (cid, ok, why))
    case('P1', '9001-1-full-1763000000', 'full', runs(), True, 'consumer-path-test.yml run 9001')
    case('P2', '9001-1-php-1763000000', 'php', runs(), True, 'in progress')
    ok_a, _ = m.judge('cost-monorepo-before-1-1763000000', 'full', REPO, runs(raise_=True))
    ok_b, _ = m.judge('cost-iac-heavy-after-2-1763000000', 'iac', REPO, runs(raise_=True))
    out['P3'] = (ok_a is True and ok_b is True, 'cost ids: %s %s' % (ok_a, ok_b))
    case('N1', '', 'full', runs(), False, 'no correlation id')
    case('N2', '9001-1-full-1763000000', 'full', runs(path='.github/workflows/self-test.yml'), False,
         'not .github/workflows/consumer-path-test.yml')
    case('N3', '9001-1-full-1763000000', 'full', runs(status='completed'), False, 'has completed')
    case('N4', '9001-1-full-1763000000', 'full', runs(repo='someone/else'), False, 'belongs to')
    case('N5', '9001-1-php-1763000000', 'full', runs(), False, 'was made for scope php')
    case('N6', '9001-1-full-1763000000', 'full', runs(raise_=True), False, 'could not be read')
    case('N7', 'cost-iac-heavy-before-1-1763000000', 'full', runs(), False, 'measures scope iac')
    return out


def structure(text):
    import yaml
    wf = yaml.safe_load(text)
    on = wf.get('on', wf.get(True)) or {}
    inputs = (on.get('workflow_dispatch') or {}).get('inputs') or {}
    jobs = wf.get('jobs') or {}

    def needs(j):
        n = (jobs.get(j) or {}).get('needs') or []
        return [n] if isinstance(n, str) else list(n)

    def reaches(j, seen=()):
        return any(n == 'caller' or (n not in seen and reaches(n, seen + (j,))) for n in needs(j))
    step = ' '.join(str(s.get('run', '')) for s in (jobs.get('caller') or {}).get('steps') or [])
    gated = [j for j in jobs if j != 'caller' and not reaches(j)]
    php_if = str((jobs.get('php-verdict') or {}).get('if', ''))
    s1 = ('caller' in jobs and 'scripts/negative_control_caller.py' in step and '--correlation-id' in step and
          not gated and "needs.caller.result == 'success'" in php_if)
    s2 = 'correlation_id' in inputs and 'scope' in inputs
    return {'S1': (s1, 'jobs not gated by caller: %s; php-verdict if: %r' % (gated, php_if)),
            'S2': (s2, 'inputs %s' % sorted(inputs))}


def cli(m):
    m.api_fetch = lambda repo: runs()
    rc_ok = m.main(['--correlation-id', '9001-1-full-1763000000', '--scope', 'full', '--repo', REPO])
    rc_no = m.main(['--correlation-id', '', '--scope', 'full', '--repo', REPO])
    return rc_ok == 0 and rc_no == 1, 'exit codes %s %s' % (rc_ok, rc_no)


SCRIPT_MUTANTS = (
    ('empty_id_proceeds', ("    if not cid:\n        return False,", "    if not cid:\n        return True,"), 'N1'),
    ('reader_path_unchecked', ('    if path != reader_workflow:', '    if False:'), 'N2'),
    ('completed_run_accepted', ("    if doc.get('status') == 'completed':", '    if False:'), 'N3'),
    ('repository_unchecked', ("    if owner != (repo or '').lower():", '    if False:'), 'N4'),
    ('unread_run_trusted', ("        return False, 'NOT_ESTABLISHED: run %s could not be read",
                            "        return True, 'NOT_ESTABLISHED: run %s could not be read"), 'N6'),
)
WORKFLOW_MUTANTS = (
    ('seeded_php_without_caller', ("    name: Seeded PHP MUST block the caller\n    needs: caller\n",
                                   "    name: Seeded PHP MUST block the caller\n"), 'S1'),
    ('php_verdict_ignores_caller', (" && needs.caller.result == 'success'", ''), 'S1'),
)


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('NOT CHECKED: PyYAML unavailable')
        return 2
    text = io.open(WORKFLOW, encoding='utf-8').read().replace('\r\n', '\n')
    m = load()
    results = dict(structure(text))
    results.update(behaviour(m))
    results['P4'] = cli(load())
    fails = 0
    for name in ('S1', 'S2', 'P1', 'P2', 'P3', 'P4', 'N1', 'N2', 'N3', 'N4', 'N5', 'N6', 'N7'):
        ok, detail = results[name]
        print('  %s %s' % ('PASS' if ok else 'FAIL', name))
        if not ok:
            print('      ' + detail[:400])
            fails += 1
    for label, rep, case in SCRIPT_MUTANTS:
        try:
            ok = not behaviour(load(rep))[case][0]
            why = 'caught by %s' % case if ok else 'NOT caught by %s' % case
        except AssertionError as exc:
            ok, why = False, 'anchor problem: %s' % exc
        print('  %s mutant %s: %s' % ('PASS' if ok else 'FAIL', label, why))
        fails += 0 if ok else 1
    for label, (old, new), case in WORKFLOW_MUTANTS:
        if text.count(old) != 1:
            ok, why = False, 'anchor occurs %d times' % text.count(old)
        else:
            ok = not structure(text.replace(old, new))[case][0]
            why = 'caught by %s' % case if ok else 'NOT caught by %s' % case
        print('  %s mutant %s: %s' % ('PASS' if ok else 'FAIL', label, why))
        fails += 0 if ok else 1
    if fails:
        print('FAIL: %d case(s) of KREQ-632 failed: the negative control could run with no reader' % fails)
        return 1
    print('PASS: KREQ-632 the negative control runs only for a reader (consumer-path-test.yml in progress, or the '
          'cost tool); a hand dispatch stops at the first job (13 cases, %d named mutants caught)'
          % (len(SCRIPT_MUTANTS) + len(WORKFLOW_MUTANTS)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
