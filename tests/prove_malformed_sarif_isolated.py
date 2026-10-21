#!/usr/bin/env python3
"""A malformed SARIF is one UNPARSEABLE row, and it takes no other scanner's row with it (L06).

WHY THIS EXISTS

    parse_sarif documented three states -- COMPLETE, ABSENT, UNPARSEABLE -- and a fourth existed
    undeclared: valid JSON whose SARIF structure is wrong (`runs: ["a-string"]`, a result whose
    `locations` is not a list) RAISED out of the parser instead of returning UNPARSEABLE.
    tests/prove_identity_durability.py found it and reported it by name rather than inheriting
    it. In batch mode the consequence is worse than one wrong row: the exception escapes batch(),
    the report is never rendered, no counts and no findings file are published, and fifteen
    scanners' evidence disappears because one scanner wrote a broken file -- the gate then reads
    `report: failure` and the whole run is UNDETERMINED over scope that was measured.

WHAT IT PROVES

    parser         each malformed document returns parse_state UNPARSEABLE with a witness naming
                   the defect; it never raises; a well-formed document beside it still parses
    isolation      in batch() over three scanners -- two malformed, one sound -- the sound
                   scanner's row is ESTABLISHED and counted, each malformed scanner's row is
                   exactly one NOT ESTABLISHED row with `SARIF | INVALID`, the reporter exits 0,
                   and the findings file carries the sound scanner's finding
    never zero     neither malformed row reads 0 findings

EXIT  0 proven   1 a case failed (named)   2 could not be checked (UNKNOWN, never PASS)
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
REPORTER = os.path.join(ROOT, 'scripts', 'scan_report.py')

GOOD = {'version': '2.1.0', 'runs': [{
    'tool': {'driver': {'name': 'bandit', 'rules': [{'id': 'B602'}]}},
    'invocations': [{'executionSuccessful': True}],
    'results': [{'ruleId': 'B602', 'level': 'error', 'message': {'text': 'shell=True'},
                 'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'app/run.py'},
                                                     'region': {'startLine': 12}}}]}]}]}

MALFORMED = {
    'runs-not-objects': {'version': '2.1.0', 'runs': ['a-string-not-an-object']},
    'result-fields-wrong-types': {'version': '2.1.0', 'runs': [{
        'tool': 'not-an-object',
        'results': [{'ruleId': 5, 'message': 'not-an-object', 'locations': 'nope'}]}]},
    'top-level-list': [1, 2, 3],
}


def state(scanner, sarif):
    return {'scanner': scanner, 'applicability': 'APPLICABLE', 'execution': 'COMPLETE',
            'scope': 'x', 'sarif': sarif, 'artifact': 'RETAINED', 'upload': 'COMPLETE',
            'gate': 'PASS', 'job': 'job-' + scanner}


def main():
    try:
        import scan_report as sr
    except ImportError as exc:
        print('UNKNOWN: %s' % exc)
        return 2
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    work = tempfile.mkdtemp(prefix='malformed-sarif-')
    try:
        # ── parser ───────────────────────────────────────────────────────────────────────
        for name, doc in MALFORMED.items():
            p = os.path.join(work, name + '.sarif')
            io.open(p, 'w', encoding='utf-8').write(json.dumps(doc))
            try:
                findings, ps, (es, witnesses) = sr.parse_sarif(p, name)
            except Exception as exc:  # noqa: BLE001
                fails.append('parser: %s RAISED %s: %s -- the fourth state is still undeclared'
                             % (name, type(exc).__name__, exc))
                continue
            check(ps == 'UNPARSEABLE', 'parser: %s returned parse_state %r, expected UNPARSEABLE' % (name, ps))
            check(not findings, 'parser: %s produced %d finding(s) from a document it could not read'
                  % (name, len(findings)))
            check(bool(witnesses) and any('SARIF' in w or 'shape' in w.lower() for w in witnesses),
                  'parser: %s refused with no witness naming the defect (%r)' % (name, witnesses))
        gp = os.path.join(work, 'bandit.sarif')
        io.open(gp, 'w', encoding='utf-8').write(json.dumps(GOOD))
        findings, ps, _ = sr.parse_sarif(gp, 'bandit')
        check(ps == 'COMPLETE' and len(findings) == 1, 'control: the sound document did not parse')

        # ── isolation, through the reporter as the job runs it ───────────────────────────
        names = ['bandit', 'runs-not-objects', 'result-fields-wrong-types']
        for n in names:
            io.open(os.path.join(work, 'state-%s.json' % n), 'w', encoding='utf-8').write(
                json.dumps(state(n, n + '.sarif')))
        out = os.path.join(work, 'gh_output')
        io.open(out, 'w').close()
        env = dict(os.environ, GITHUB_OUTPUT=out, GITHUB_STEP_SUMMARY='')
        p = subprocess.run([sys.executable, '-E', '-s', REPORTER, '--batch', work, '--max-detail', '5'],
                           capture_output=True, text=True, env=env)
        text = (p.stdout or '') + (p.stderr or '')
        check(p.returncode == 0, 'isolation: the reporter exited %d over one broken scanner; '
                                 'every other scanner\'s evidence went with it: %s'
              % (p.returncode, text[-500:]))
        got = dict(l.rstrip('\n').split('=', 1) for l in io.open(out, encoding='utf-8') if '=' in l)
        check(got.get('blocking_findings') == '1' and got.get('jobs_with_findings') == 'job-bandit',
              'isolation: the sound scanner was not counted (%r / %r)'
              % (got.get('blocking_findings'), got.get('jobs_with_findings')))
        rows = dict((l.split('|')[1].strip(), l) for l in text.splitlines()
                    if l.startswith('| ') and l.count('|') >= 8)
        for n in names[1:]:
            row = rows.get(n, '')
            check(row != '', 'isolation: no summary row for %s' % n)
            check('NOT ESTABLISHED' in row, 'isolation: %s row is not NOT ESTABLISHED: %s' % (n, row))
            check(' | 0 | ' not in row, 'isolation: %s row reads a zero count: %s' % (n, row))
            block = text.split('### %s' % n)[-1].split('### ')[0] if '### %s' % n in text else ''
            check('| SARIF | INVALID |' in block, 'isolation: %s block does not say the SARIF is INVALID' % n)
            check('could not be parsed' in block or 'not SARIF-shaped' in block,
                  'isolation: %s block does not say why nothing is established' % n)
        check('| bandit |' in text and ' | 1 | 1 | ' in rows.get('bandit', ''),
              'isolation: the sound scanner\'s row is wrong: %s' % rows.get('bandit'))
        fpath = got.get('findings') or ''
        recs = json.load(io.open(fpath, encoding='utf-8')) if os.path.isfile(fpath) else None
        check(recs is not None and [r['scanner'] for r in recs] == ['bandit'],
              'isolation: the findings file does not carry exactly the sound scanner\'s finding (%r)'
              % (recs and [r['scanner'] for r in recs]))
    finally:
        shutil.rmtree(work, ignore_errors=True)

    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: a malformed SARIF is one UNPARSEABLE row with a witness, never a traceback, never '
          'a zero, and the scanners beside it are counted as if it were not there.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
