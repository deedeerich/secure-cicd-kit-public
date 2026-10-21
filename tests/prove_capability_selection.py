#!/usr/bin/env python3
"""Prove the report never renders PASS for a scanner the capability selection capped (KDEC-010).

WHY THIS EXISTS

    "It's supposed to change scanners if there is one that has the capabilities, not just
    partial, and if there is not one then it annotates and goes to partial." resolve selects the
    scanner per (capability, root) and publishes two lists: jobs pointed at a VERSION_GAP (no
    carried scanner can read the target) and jobs NOT SELECTED for a target another scanner
    serves. The gate honours them (tests/prove_bootstrap_failure.py). The report is the other
    place a PASS is rendered -- per scanner row, and in the index a reviewer reads first -- and
    scanner_state.PARTIAL "MUST NOT be projected, summarised or rounded into PASS by any
    downstream consumer". A row that still said PASS would be exactly that.

    This runs the real reporter (scripts/scan_report.py --batch) over a sandboxed state
    directory the way the report job does, with the selection handed to it the way the
    scan-report composite hands it, and reads the rendered text and the published counts.

SCENARIOS
    control            a clean checkov row, no selection            -> Gate state PASS
    capped             the same, iac-scan capped (VERSION_GAP)      -> PARTIAL, the gap and the
                                                                       registry row named, no PASS
                                                                       anywhere in the row
    capped_findings    a capped bandit row WITH a finding           -> PARTIAL, and the finding is
                                                                       still counted (findings are
                                                                       findings; only PASS is capped)
    not_selected       a clean bandit row, sast-bandit not selected -> PARTIAL, labelled as a
                                                                       SUBSTITUTION to codeql/codeql,
                                                                       not equivalence
    untouched          a semgrep row beside a capped checkov row    -> semgrep stays PASS

EXIT  0 every scenario rendered as it must   1 a wrong rendering   2 could not be checked
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

GAP_NOTE = ('iac-scan: VERSION_GAP iac@infra (iac-scan/checkov VERSION_SUPPORT_UNDETERMINED) -- '
            'PARTIAL, never PASS; closes: scanner-registry.yaml version_support iac-scan/checkov '
            '(UNVERIFIED): a READ range from a seeded corpus at 1.6.0 (D-VF-4)')
SUB_NOTE = ('sast-bandit: not selected for python-sast@. (sast-bandit/bandit VERSION_UNSUPPORTED); '
            'served by codeql/codeql (SUBSTITUTION, not equivalence)')


def clean_sarif(tool):
    """A run that declares it succeeded, loaded a rule and found nothing: EXAMINED, clean."""
    return {'version': '2.1.0', 'runs': [{
        'tool': {'driver': {'name': tool, 'rules': [{'id': tool.upper() + '_1'}]}},
        'invocations': [{'executionSuccessful': True}],
        'results': []}]}


def finding_sarif(tool):
    return {'version': '2.1.0', 'runs': [{
        'tool': {'driver': {'name': tool, 'rules': [{'id': 'B602'}]}},
        'results': [{'ruleId': 'B602', 'level': 'error',
                     'message': {'text': 'subprocess call with shell=True'},
                     'locations': [{'physicalLocation': {
                         'artifactLocation': {'uri': 'app/run.py'},
                         'region': {'startLine': 12}}}]}]}]}


def state(scanner, job, sarif):
    """What the report job's state builder writes for a scanner whose job succeeded with a report:
    the row the builder marks `gate: PASS`, and the only row the selection may cap."""
    return {'scanner': scanner, 'applicability': 'APPLICABLE', 'execution': 'COMPLETE',
            'scope': 'x', 'sarif': sarif, 'artifact': 'RETAINED', 'upload': 'COMPLETE',
            'gate': 'PASS', 'job': job}


def run_case(rows, extra):
    """rows: [(scanner, job, sarif doc)]. extra: further reporter arguments."""
    work = tempfile.mkdtemp(prefix='cap-sel-')
    try:
        names = []
        for scanner, job, doc in rows:
            sarif = scanner + '.sarif'
            io.open(os.path.join(work, sarif), 'w', encoding='utf-8').write(json.dumps(doc))
            io.open(os.path.join(work, 'state-%s.json' % scanner), 'w', encoding='utf-8').write(
                json.dumps(state(scanner, job, sarif)))
            names.append(scanner)
        out = os.path.join(work, 'gh_output')
        io.open(out, 'w').close()
        env = dict(os.environ, GITHUB_OUTPUT=out, GITHUB_STEP_SUMMARY='')
        p = subprocess.run([sys.executable, '-E', '-s', REPORTER, '--batch', work,
                            '--expect', ','.join(names), '--max-detail', '2'] + extra,
                           capture_output=True, text=True, encoding='utf-8', errors='replace',
                           env=env)
        got = {}
        for line in io.open(out, encoding='utf-8'):
            if '=' in line:
                k, v = line.rstrip('\n').split('=', 1)
                got[k] = v
        return p.returncode, (p.stdout or ''), (p.stderr or ''), got
    finally:
        shutil.rmtree(work, ignore_errors=True)


def block(text, scanner):
    """The rendered section for one scanner."""
    marker = '### %s' % scanner
    if marker not in text:
        return ''
    rest = text.split(marker, 1)[1]
    return rest.split('\n### ', 1)[0]


def index_row(text, scanner):
    for line in text.splitlines():
        if line.startswith('| %s |' % scanner):
            return line
    return ''


def main():
    bad = []

    def expect(name, cond, why):
        print('  %-18s %s' % (name, 'ok' if cond else 'FAIL'))
        if not cond:
            bad.append('%s: %s' % (name, why))

    # ── control: the reporter accepts the selection arguments, and a clean row is PASS ──────
    rc, text, err, got = run_case([('checkov', 'iac-scan', clean_sarif('checkov'))], [])
    expect('control', rc == 0 and '| Gate state | PASS |' in block(text, 'checkov')
           and index_row(text, 'checkov').rstrip().endswith('| PASS |'),
           'exit=%d; a clean, established, applicable row did not render PASS:\n%s'
           % (rc, (block(text, 'checkov') or err)[-600:]))

    # ── capped: PARTIAL, never PASS, with the gap and the closing row named ────────────────
    rc, text, err, got = run_case([('checkov', 'iac-scan', clean_sarif('checkov'))],
                                  ['--capped-jobs', 'iac-scan', '--fitness-notes', GAP_NOTE])
    b = block(text, 'checkov')
    expect('capped', rc == 0 and '| Gate state | PARTIAL |' in b,
           'exit=%d; the capped row does not render Gate state PARTIAL (%s):\n%s'
           % (rc, err.strip().splitlines()[-1:] or 'no stderr', b[-600:]))
    expect('capped_no_pass', b and 'PASS' not in b.replace('never PASS', ''),
           'the capped row still carries PASS somewhere:\n%s' % b[-900:])
    expect('capped_annotated', 'VERSION_GAP' in b and 'iac@infra' in b
           and 'scanner-registry.yaml' in b and 'iac-scan/checkov' in b,
           'the capped row does not name the gap and the registry row that closes it:\n%s' % b[-900:])
    expect('capped_index', index_row(text, 'checkov').rstrip().endswith('| PARTIAL |'),
           'the index row a reviewer reads first still says %r' % index_row(text, 'checkov'))

    # ── capped with a finding: findings are findings; only PASS is capped ─────────────────
    rc, text, err, got = run_case([('bandit', 'sast-bandit', finding_sarif('bandit'))],
                                  ['--capped-jobs', 'sast-bandit', '--fitness-notes',
                                   'sast-bandit: VERSION_GAP python-sast@. -- PARTIAL, never PASS'])
    b = block(text, 'bandit')
    expect('capped_findings', rc == 0 and '| Gate state | PARTIAL |' in b
           and got.get('blocking_findings') == '1' and got.get('jobs_with_findings') == 'sast-bandit',
           'a capped row with a finding: gate=%s blocking_findings=%r jobs=%r -- a cap on PASS '
           'must not erase a finding' % ('PARTIAL' in b, got.get('blocking_findings'),
                                          got.get('jobs_with_findings')))

    # ── not selected: PARTIAL for that target, labelled as a substitution, not equivalence ─
    rc, text, err, got = run_case([('bandit', 'sast-bandit', clean_sarif('bandit'))],
                                  ['--not-selected-jobs', 'sast-bandit', '--fitness-notes', SUB_NOTE])
    b = block(text, 'bandit')
    expect('not_selected', rc == 0 and '| Gate state | PARTIAL |' in b
           and 'SUBSTITUTION' in b and 'codeql/codeql' in b and 'not equivalence' in b
           and 'PASS' not in b.replace('never PASS', ''),
           'a scanner not selected for a target it cannot read: PARTIAL=%s substitution named=%s '
           'PASS absent=%s:\n%s' % ('| Gate state | PARTIAL |' in b, 'SUBSTITUTION' in b,
                                    'PASS' not in b.replace('never PASS', ''), b[-900:]))

    # ── untouched: a scanner in neither list keeps its PASS beside a capped one ───────────
    rc, text, err, got = run_case([('checkov', 'iac-scan', clean_sarif('checkov')),
                                   ('semgrep', 'sast-semgrep', clean_sarif('semgrep'))],
                                  ['--capped-jobs', 'iac-scan', '--fitness-notes', GAP_NOTE])
    expect('untouched', rc == 0 and '| Gate state | PASS |' in block(text, 'semgrep')
           and '| Gate state | PARTIAL |' in block(text, 'checkov'),
           'the cap leaked (semgrep=%s checkov=%s)'
           % ('PASS' in block(text, 'semgrep'), 'PARTIAL' in block(text, 'checkov')))

    print()
    if bad:
        for m in bad:
            print('FAIL: %s' % m)
        print('')
        print('A PARTIAL RENDERED AS PASS IS THE ROUNDING THE TAXONOMY FORBIDS.')
        return 1
    print('PASS: the report caps a scanner the capability selection capped at PARTIAL, names the')
    print('      gap and the row that closes it, labels a substitution as one, keeps findings')
    print('      counted, and leaves every other row alone.')
    print('      THIS RUNS THE REPORTER, NOT THE REPORT JOB. That the job hands it the lists is')
    print('      read from the workflow by tests/test_resolve.py and the composite contract.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
