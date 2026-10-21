#!/usr/bin/env python3
"""The report must emit a machine-readable findings file beside the rendered report (L52).

WHY THIS EXISTS

    The rendered report is prose for a person. Everything downstream of it -- the baseline cascade
    (scripts/finding_match.py), correlation (scripts/finding_correlation.py), the only write
    authority over the ledger (scripts/propose_ledger.py) and ticket reconciliation -- consumes
    identify() results, and until this row nothing published them. The identity was computed on
    every finding and then rendered as a hex string in a markdown bullet, which no program reads.
    Libraries proven in isolation and fed by nothing are a design, not a pipeline.

WHAT IT PROVES, by running the real reporter in batch mode over three scanners

    published        GITHUB_OUTPUT carries `findings=<path>` and the file exists
    complete         every record carries scanner, identity_scope, what_aliases, cwe,
                     canonical_path, finding_subject and the identify() result: state, identity and
                     ALL THREE components (what, where, content). A fingerprinted record's identity
                     re-derives from its three components, so nothing was hand-assembled
    refusal kept     a secret finding is listed with state UNFINGERPRINTABLE and its reason -- never
                     dropped and never given a hash
    no material      no record carries message, construct, snippet or partial fingerprints. The
                     file is an artifact readable by anyone with repository read access
    consumable       finding_match.match over the list against an empty ledger yields NEW for the
                     fingerprinted records and IDENTITY_UNCOMPUTABLE for the refused one;
                     finding_correlation.correlate accepts the list and keeps every index
    before faults    the file is written even when a roster fault fails the job (exit 3), like the
                     gate's counts: a fault in the pipeline must not erase the evidence

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

REQUIRED_KEYS = ('scanner', 'identity_scope', 'what_aliases', 'cwe', 'canonical_path',
                 'finding_subject', 'state', 'identity', 'what', 'where', 'content')
MATCHED_MATERIAL = ('message', 'construct', 'snippet', 'partial_fingerprints',
                    'partialFingerprints')


def sast_sarif():
    return {'version': '2.1.0', 'runs': [{
        'tool': {'driver': {'name': 'Semgrep', 'semanticVersion': '1.92.3', 'rules': [{
            'id': 'python.lang.security.audit.sqli.sql-injection',
            'properties': {'tags': ['external/cwe/cwe-089'], 'security-severity': '8.5'}}]}},
        'invocations': [{'executionSuccessful': True}],
        'results': [{
            'ruleId': 'python.lang.security.audit.sqli.sql-injection', 'level': 'error',
            'message': {'text': 'SQL built by concatenation'},
            'locations': [{
                'physicalLocation': {'artifactLocation': {'uri': 'app/db/queries.py'},
                                     'region': {'startLine': 42, 'snippet': {
                                         'text': 'cursor.execute("SELECT 1" + user_id)'}}},
                'logicalLocations': [{'fullyQualifiedName': 'app.db.queries.fetch_user'}]}]}]}]}


def dep_sarif():
    return {'version': '2.1.0', 'runs': [{
        'tool': {'driver': {'name': 'Trivy', 'version': '0.56.1',
                            'rules': [{'id': 'CVE-2018-18074',
                                       'properties': {'security-severity': '9.1'}}]}},
        'invocations': [{'executionSuccessful': True}],
        'results': [{
            'ruleId': 'CVE-2018-18074', 'level': 'error',
            'message': {'text': 'requests 2.19.1: header leak'},
            'properties': {'purl': 'pkg:pypi/requests@2.19.1', 'package': 'requests',
                           'fixed_version': '2.31.0'},
            'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'requirements.txt'},
                                                'region': {'startLine': 7}}}]}]}]}


def secret_sarif():
    return {'version': '2.1.0', 'runs': [{
        'tool': {'driver': {'name': 'gitleaks', 'rules': [{'id': 'aws-access-key-id'}]}},
        'invocations': [{'executionSuccessful': True}],
        'results': [{
            'ruleId': 'aws-access-key-id', 'level': 'error',
            'message': {'text': 'AWS key AKIAIOSFODNN7EXAMPLE in infra/main.tf'},
            'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'infra/main.tf'},
                                                'region': {'startLine': 3}}}]}]}]}


def state(scanner, job, sarif):
    return {'scanner': scanner, 'applicability': 'APPLICABLE', 'execution': 'COMPLETE',
            'scope': 'x', 'sarif': sarif, 'artifact': 'RETAINED', 'upload': 'COMPLETE',
            'gate': 'FAIL', 'job': job}


def run_reporter(work, expect):
    out = os.path.join(work, 'gh_output')
    io.open(out, 'w').close()
    env = dict(os.environ, GITHUB_OUTPUT=out, GITHUB_STEP_SUMMARY='')
    p = subprocess.run([sys.executable, '-E', '-s', REPORTER, '--batch', work,
                        '--max-detail', '5', '--expect', expect],
                       capture_output=True, text=True, env=env)
    got = {}
    for line in io.open(out, encoding='utf-8'):
        if '=' in line:
            k, v = line.rstrip('\n').split('=', 1)
            got[k] = v
    return p.returncode, got, ((p.stdout or '')[-800:] + (p.stderr or '')[-800:])


def main():
    try:
        import finding_match as fm
        import finding_correlation as fc
        from baseline_ledger import composite_identity
    except ImportError as exc:
        print('UNKNOWN: %s' % exc)
        return 2
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    work = tempfile.mkdtemp(prefix='report-findings-')
    try:
        for name, doc in (('semgrep', sast_sarif()), ('trivy', dep_sarif()),
                          ('gitleaks', secret_sarif())):
            io.open(os.path.join(work, name + '.sarif'), 'w', encoding='utf-8').write(json.dumps(doc))
            io.open(os.path.join(work, 'state-%s.json' % name), 'w', encoding='utf-8').write(
                json.dumps(state(name, 'job-' + name, name + '.sarif')))

        # codeql-python is expected and wrote nothing: a roster fault, exit 3. The file must still
        # be written, exactly as blocking_findings is published before the fault exit.
        rc, got, log = run_reporter(work, 'semgrep,trivy,gitleaks,codeql-python')
        print('  reporter exit=%d outputs=%s' % (rc, sorted(got)))
        check(rc == 3, 'control: a missing roster entry did not fail the reporter (exit %d)' % rc)
        path = got.get('findings')
        if not path:
            print('FAIL: no `findings=<path>` in GITHUB_OUTPUT. The identify() results are rendered '
                  'as prose and published to no program.')
            print(log)
            return 1
        check(os.path.isfile(path), 'findings path %r does not exist' % path)
        if not os.path.isfile(path):
            raise SystemExit(_report(fails))
        records = json.load(io.open(path, encoding='utf-8'))
        check(isinstance(records, list) and len(records) == 3,
              'expected a list of 3 records, got %r' % (type(records).__name__,))
        if not isinstance(records, list):
            raise SystemExit(_report(fails))

        by_scanner = dict((r.get('scanner'), r) for r in records if isinstance(r, dict))
        for r in records:
            missing = [k for k in REQUIRED_KEYS if k not in r]
            check(not missing, '%s: record lacks %s' % (r.get('scanner'), ', '.join(missing)))
            leaked = [k for k in MATCHED_MATERIAL if k in r]
            check(not leaked, '%s: record carries matched material %s -- this file is an artifact '
                              'readable by anyone with read access' % (r.get('scanner'), leaked))
            text = json.dumps(r)
            check('AKIAIOSFODNN7EXAMPLE' not in text, '%s: a credential reached the findings file'
                  % r.get('scanner'))

        for name in ('semgrep', 'trivy'):
            r = by_scanner.get(name) or {}
            check(r.get('state') == 'FINGERPRINTED',
                  '%s: state %r, expected FINGERPRINTED (%s)' % (name, r.get('state'),
                                                                   r.get('reason') or r.get('identity_reason')))
            for k in ('what', 'where', 'content', 'identity'):
                check(bool(r.get(k)), '%s: %s is empty' % (name, k))
            if all(r.get(k) for k in ('what', 'where', 'content', 'identity')):
                check(composite_identity(r['finding_subject'], r['what'], r['where'], r['content'])
                      == r['identity'],
                      '%s: identity does not re-derive from its three components' % name)
            check(r.get('identity_scope') == 'DURABLE_ACROSS_RUNS_AND_UPGRADES',
                  '%s: identity_scope %r' % (name, r.get('identity_scope')))
        sem = by_scanner.get('semgrep') or {}
        check(sem.get('cwe') == 'CWE-89' or sem.get('cwe') == 'CWE-089',
              'semgrep: cwe %r was not lifted from the rule tags' % sem.get('cwe'))
        check(sem.get('canonical_path') == 'app/db/queries.py',
              'semgrep: canonical_path %r' % sem.get('canonical_path'))
        tri = by_scanner.get('trivy') or {}
        check('CVE-2018-18074' in (tri.get('what_aliases') or []),
              'trivy: what_aliases %r lacks the CVE' % tri.get('what_aliases'))

        sec = by_scanner.get('gitleaks') or {}
        check(sec.get('state') == 'UNFINGERPRINTABLE' and not sec.get('identity'),
              'gitleaks: a secret finding was given an identity (%r)' % sec.get('state'))
        check(sec.get('reason') == 'SECRET_SUBJECT_NOT_BASELINEABLE',
              'gitleaks: refusal reason %r' % sec.get('reason'))

        # Consumable by the cascade and by correlation, exactly as written.
        r = fm.match(records, [], fm.LEDGER_EMPTY, 'prod')
        states = dict((records[f['index']]['scanner'], f['match']) for f in r['findings'])
        check(states.get('semgrep') == fm.IDENTITY_UNMATCHED and states.get('trivy') == fm.IDENTITY_UNMATCHED,
              'cascade: fingerprinted records were not NEW against an empty ledger: %r' % states)
        check(states.get('gitleaks') == fm.IDENTITY_UNCOMPUTABLE,
              'cascade: the refused record was not IDENTITY_UNCOMPUTABLE: %r' % states)
        c = fc.correlate(records)
        check(sorted(i for cl in c['clusters'] for i in cl['members']) == list(range(len(records))),
              'correlation dropped or duplicated an observation')
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return _report(fails)


def _report(fails):
    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: the reporter publishes findings.json with every identify() part, refusals kept, '
          'no matched material, consumable by the cascade and correlation, and written before a '
          'roster fault exits the job.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
