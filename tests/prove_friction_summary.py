#!/usr/bin/env python3
"""The pilot friction logs summarise across teams honestly: nothing dropped, the hour measured (owner, 2026-11-06).

WHY THIS EXISTS
    The rollout plan's wave gates (docs/adoption/ROLLOUT_PLAN.md) read the friction summary: time to first
    green at crawl against the one-hour target, where the minutes went, and which error states cost most.
    A summary that drops a row it cannot read reports less friction than there was; one that cannot join a
    state to its plain-English entry hides a catalogue gap.

WHAT IT PROVES
  POSITIVE
    P1  the shipped template CSV (docs/adoption/pilot-friction-log.template.csv) reads with no refused row
        and its example team met the target
    P2  two teams, three repositories: met / missed / not green yet per repository, minutes lost per team,
        error states worst first, each joined to its plain sentence, the steps and who fixed them, the
        satisfaction average, a team at 2 or lower flagged
    P3 a folder of logs is read whole (every *.csv)
  NEGATIVE
    N1  a row with an unknown kind, no team, a bad date, zero or negative minutes, a stuck row with no
        step, or satisfaction outside 1-5 is REFUSED by name with its file and line, the rest still counted,
        exit 1
    N2  an error state with no plain-English entry is reported as a catalogue gap, never as a blank
    N3  no log at all, or a log missing the required columns: exit 2 / the file refused, never an empty "all clear"
  MUTANT
    M1  a summariser that silently drops invalid rows (validate() always passes them over) is caught: the
        refused count this proof expects disappears

EXIT 0 all hold   1 any does not
"""
import csv
import io
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
import friction_summary as FS  # noqa: E402

SCRIPT = os.path.join(ROOT, 'scripts', 'friction_summary.py')
FAILS = []


def check(cond, label, detail=''):
    print('  %s %s%s' % ('ok  ' if cond else 'FAIL', label, ('  -- ' + str(detail)[:400]) if detail and not cond else ''))
    if not cond:
        FAILS.append(label)


def write(path, rows):
    with io.open(path, 'w', encoding='utf-8', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(FS.COLUMNS)
        for r in rows:
            w.writerow([r.get(c, '') for c in FS.COLUMNS])


def run(*args):
    p = subprocess.run([sys.executable, SCRIPT] + list(args), capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def main():
    base = tempfile.mkdtemp(prefix='friction-proof-')
    try:
        print('POSITIVE')
        rc, out = run(os.path.join(ROOT, 'docs', 'adoption', 'pilot-friction-log.template.csv'))
        check(rc == 0 and 'Rows NOT counted' not in out and '| team-example | 1 | example-app 55 | example-app |' in out,
              'P1 the shipped template reads cleanly and its example met the hour', out[-400:])
        a = os.path.join(base, 'logs', 'team-a.csv')
        b = os.path.join(base, 'logs', 'team-b.csv')
        os.makedirs(os.path.dirname(a))
        day = '2026-11-10'
        write(a, [
            {'kind': 'first_green', 'team': 'a', 'repository': 'svc1', 'date': day, 'minutes': '50'},
            {'kind': 'first_green', 'team': 'a', 'repository': 'svc2', 'date': day, 'minutes': '95'},
            {'kind': 'stuck', 'team': 'a', 'repository': 'svc2', 'date': day, 'step': 'environments',
             'error_state': 'environment_protection.ENVIRONMENT_REVIEWERS_ABSENT', 'minutes': '30', 'fixed_by': 'platform'},
            {'kind': 'stuck', 'team': 'a', 'repository': 'svc2', 'date': day, 'step': 'first crawl run',
             'error_state': 'api_token_preflight.JOB_TOKEN_REJECTED', 'minutes': '10', 'fixed_by': 'self'},
            {'kind': 'satisfaction', 'team': 'a', 'repository': 'svc1', 'date': day, 'satisfaction': '4'}])
        write(b, [
            {'kind': 'stuck', 'team': 'b', 'repository': 'web', 'date': day, 'step': 'environments',
             'error_state': 'environment_protection.ENVIRONMENT_REVIEWERS_ABSENT', 'minutes': '25', 'fixed_by': 'docs'},
            {'kind': 'satisfaction', 'team': 'b', 'repository': 'web', 'date': day, 'satisfaction': '2'}])
        rows, refused, files = FS.read_rows([a, b])
        s = FS.summarise(rows, refused)
        ta = next(t for t in s['teams'] if t['team'] == 'a')
        tb = next(t for t in s['teams'] if t['team'] == 'b')
        check(ta['met_target'] == ['svc1'] and ta['missed_target'] == ['svc2'] and tb['not_green_yet'] == ['web'],
              'P2 met / missed / not green yet, per repository', (ta, tb))
        check(ta['minutes_lost'] == 40 and tb['minutes_lost'] == 25 and s['overall']['minutes_lost'] == 65,
              'P2 minutes lost per team and overall')
        top = s['error_states'][0]
        check(top['state'] == 'environment_protection.ENVIRONMENT_REVIEWERS_ABSENT' and top['minutes'] == 55 and
              top['times'] == 2 and top['plain'] and 'required reviewers' in top['plain'],
              'P2 error states worst first, joined to their plain sentence', top)
        check(dict(s['steps'])['environments'] == 55 and dict(s['fixed_by'])['platform'] == 30,
              'P2 by step and by who fixed it')
        check(ta['satisfaction'] == 4.0 and tb['low_satisfaction'] and not ta['low_satisfaction'],
              'P2 satisfaction averaged; a team at 2 or lower flagged')
        rc, out = run(os.path.dirname(a))
        check(rc == 0 and '| a | 2 |' in out and '| b | 1 |' in out, 'P3 a folder of logs is read whole', out[-300:])
        print('NEGATIVE')
        c = os.path.join(base, 'bad.csv')
        write(c, [
            {'kind': 'first_green', 'team': 'c', 'repository': 'r', 'date': day, 'minutes': '30'},
            {'kind': 'oops', 'team': 'c', 'repository': 'r', 'date': day, 'minutes': '5'},
            {'kind': 'stuck', 'team': '', 'repository': 'r', 'date': day, 'step': 'x', 'minutes': '5'},
            {'kind': 'stuck', 'team': 'c', 'repository': 'r', 'date': '10/11/2026', 'step': 'x', 'minutes': '5'},
            {'kind': 'stuck', 'team': 'c', 'repository': 'r', 'date': day, 'step': 'x', 'minutes': '0'},
            {'kind': 'stuck', 'team': 'c', 'repository': 'r', 'date': day, 'step': '', 'minutes': '5'},
            {'kind': 'satisfaction', 'team': 'c', 'repository': 'r', 'date': day, 'satisfaction': '7'},
            {'kind': 'stuck', 'team': 'c', 'repository': 'r', 'date': day, 'step': 'x', 'minutes': '9',
             'error_state': 'routing_result.NOT_A_REAL_STATE'}])
        rows, refused, _ = FS.read_rows([c])
        reasons = ' | '.join(w for _f, _l, w in refused)
        check(len(refused) == 6 and len(rows) == 2 and all(ln >= 2 for _f, ln, _w in refused) and
              'kind' in reasons and 'no team' in reasons and 'YYYY-MM-DD' in reasons and 'above 0' in reasons and
              'step' in reasons and '1 to 5' in reasons, 'N1 six bad rows refused by name and line; two counted', reasons)
        rc, out = run(c)
        check(rc == 1 and 'Rows NOT counted' in out, 'N1 exit 1 and the refused rows listed', out[-300:])
        s = FS.summarise(rows, refused)
        gap = [e for e in s['error_states'] if e['state'] == 'routing_result.NOT_A_REAL_STATE']
        check(gap and gap[0]['catalogue_gap'] and 'catalogue gap' in FS.render(s), 'N2 a state with no entry is a named catalogue gap')
        rc, out = run()
        check(rc == 2, 'N3 no log at all: exit 2, never "all clear"')
        d = os.path.join(base, 'nohdr.csv')
        io.open(d, 'w', encoding='utf-8').write('who,when\nx,y\n')
        rows, refused, _ = FS.read_rows([d])
        check(not rows and refused and 'header lacks' in refused[0][2], 'N3 a log without the columns is refused, not read as empty')
        print('MUTANT')
        saved = FS.validate
        try:
            FS.validate = lambda row: ''   # the drop-or-accept-anything mutant
            rows_m, refused_m, _ = FS.read_rows([c])
        finally:
            FS.validate = saved
        check(len(refused_m) != 6, 'M1 a summariser that refuses nothing is caught by N1\'s count (mutant killed)')
        rc, out = run('--self-test')
        check(rc == 0, 'the script\'s own self-test passes', out)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    if FAILS:
        print('FAIL: %d check(s): %s' % (len(FAILS), '; '.join(FAILS)))
        return 1
    print('PASS: friction logs summarise across teams, measure the hour, and drop nothing.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
