#!/usr/bin/env python3
"""Prove the reporter publishes the findings evidence the gate reads, and never invents a zero (C3).

The gate's assurance_state now follows `blocking_findings` and `jobs_with_findings`, which the
reporter writes to $GITHUB_OUTPUT in batch mode. This runs the real reporter over a sandboxed state
directory in three shapes:

    findings     one established row whose SARIF carries an error-level result -> 1, that job
    not_run      the same SARIF, but the job did not run                        -> 0, no job
                 (a row that established nothing contributes nothing; it is not a clean zero)
    two_jobs     findings in two jobs                                           -> 2, both jobs

EXIT  0 counts are right   1 wrong   2 could not be checked
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
REPORTER = os.path.join(ROOT, 'scripts', 'scan_report.py')

SARIF = {
    'version': '2.1.0',
    'runs': [{
        'tool': {'driver': {'name': 'bandit', 'rules': [{'id': 'B602'}]}},
        'results': [{
            'ruleId': 'B602', 'level': 'error',
            'message': {'text': 'subprocess call with shell=True'},
            'locations': [{'physicalLocation': {
                'artifactLocation': {'uri': 'app/run.py'},
                'region': {'startLine': 12}}}],
        }],
    }],
}


def state(scanner, job, execution, sarif):
    return {'scanner': scanner, 'applicability': 'APPLICABLE', 'execution': execution,
            'scope': 'python', 'sarif': sarif, 'artifact': 'RETAINED', 'upload': 'COMPLETE',
            'gate': 'PASS', 'job': job}


def run_case(states):
    work = tempfile.mkdtemp(prefix='report-counts-')
    try:
        for name, st in states:
            io.open(os.path.join(work, st['sarif']), 'w', encoding='utf-8').write(json.dumps(SARIF))
            io.open(os.path.join(work, 'state-%s.json' % name), 'w', encoding='utf-8').write(
                json.dumps(st))
        out = os.path.join(work, 'gh_output')
        io.open(out, 'w').close()
        env = dict(os.environ, GITHUB_OUTPUT=out, GITHUB_STEP_SUMMARY='')
        p = subprocess.run([sys.executable, '-E', '-s', REPORTER, '--batch', work,
                            '--max-detail', '1'], capture_output=True, text=True, env=env)
        got = {}
        for line in io.open(out, encoding='utf-8'):
            if '=' in line:
                k, v = line.rstrip('\n').split('=', 1)
                got[k] = v
        # Resolved while the sandbox still exists: the path is only meaningful here.
        got['findings_written'] = bool(got.get('findings')) and os.path.isfile(got['findings'])
        return p.returncode, got, (p.stdout or '')[-600:] + (p.stderr or '')[-600:]
    finally:
        shutil.rmtree(work, ignore_errors=True)


CASES = [
    ('findings', [('bandit', state('bandit', 'sast-bandit', 'COMPLETE', 'bandit.sarif'))],
     '1', 'sast-bandit'),
    ('not_run', [('bandit', state('bandit', 'sast-bandit', 'NOT_RUN', 'bandit.sarif'))],
     '0', ''),
    ('two_jobs', [('bandit', state('bandit', 'sast-bandit', 'COMPLETE', 'bandit.sarif')),
                  ('semgrep', state('semgrep', 'sast-semgrep', 'COMPLETE', 'semgrep.sarif'))],
     '2', 'sast-bandit sast-semgrep'),
]


def main():
    bad = []
    for name, states, want_n, want_jobs in CASES:
        rc, got, log = run_case(states)
        n, jobs = got.get('blocking_findings'), got.get('jobs_with_findings')
        print('  %-10s exit=%d blocking_findings=%r jobs_with_findings=%r' % (name, rc, n, jobs))
        if n is None:
            bad.append('%s: no blocking_findings written to GITHUB_OUTPUT' % name)
            print(log)
            continue
        if n != want_n or (jobs or '') != want_jobs:
            bad.append('%s: got (%s, %r), expected (%s, %r)' % (name, n, jobs, want_n, want_jobs))
        # L52: the findings file is published on EVERY shape, including the one that established
        # nothing -- an empty list there is "nothing fingerprintable arrived", and its absence
        # would be "the reporter never got this far". Both are facts a consumer needs apart.
        if not got.get('findings_written'):
            bad.append('%s: no findings file was published beside the counts' % name)
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: the reporter counts blocking findings over established rows only, per job.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
