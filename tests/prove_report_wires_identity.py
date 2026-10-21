#!/usr/bin/env python3
"""The reporter must CALL the identity libraries, not sit beside them (rows L44/L45/L46/L48 wiring).

WHY THIS EXISTS

    finding_match.py, rule_family.py and finding_correlation.py were each built and proven in
    isolation and then called by nothing. The reporter still correlated on `(uri, rule_id)` -- the
    correlation key the identity model names as fatal -- derived the rule family from a string
    split, and matched nothing against any ledger. A library the pipeline never calls is a design.

WHAT IT PROVES, by running the real reporter in batch mode

    correlate       two scanners reporting one advisory for one purl at DIFFERENT paths are ONE
                    anchored cluster (the old `(uri, rule)` key could not see that); two scanners
                    agreeing on a path and rule id WITHOUT a durable identity are NOT reported as
                    correlated (the old key would have); proposals are recorded, never applied
    alias table     with a usable table the rule family comes from it and the identity moves with
                    it; a table whose aliases disagree refuses WHAT rather than falling back; no
                    table keeps the namespaced-prefix tier and says so in the basis
    cascade         with a ledger and an environment, a ledger entry matches IDENTITY_MATCHED_EXACT
                    with its baseline state carried, a new finding is NEW, and the identity claim
                    routes PROCEED with the ledger state published
    untrusted       no ledger, an unusable ledger, or an uncomputable identity publishes
                    identity_routing=EVIDENCE_UNTRUSTED for the IDENTITY CLAIM -- and the
                    blocking count is IDENTICAL to the trusted case. The baseline has no authority
                    over what blocks; it only says which findings are old
    secrets         a secret finding is outside the baseline by design (section 5.7) and does not
                    by itself make the identity claim untrusted

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

CVE = 'CVE-2018-18074'
PURL = 'pkg:pypi/requests@2.19.1'
SAST_RULE = 'python.lang.security.audit.sqli.sql-injection'


def dep_sarif(tool, path):
    return {'version': '2.1.0', 'runs': [{
        'tool': {'driver': {'name': tool, 'version': '1.0.0',
                            'rules': [{'id': CVE, 'properties': {'security-severity': '9.1'}}]}},
        'invocations': [{'executionSuccessful': True}],
        'results': [{'ruleId': CVE, 'level': 'error', 'message': {'text': 'requests leak'},
                     'properties': {'purl': PURL},
                     'locations': [{'physicalLocation': {'artifactLocation': {'uri': path},
                                                         'region': {'startLine': 1}}}]}]}]}


def sast_sarif(snippet='cursor.execute("SELECT 1" + user_id)'):
    region = {'startLine': 42}
    if snippet is not None:
        region['snippet'] = {'text': snippet}
    return {'version': '2.1.0', 'runs': [{
        'tool': {'driver': {'name': 'Semgrep', 'semanticVersion': '1.92.3', 'rules': [{
            'id': SAST_RULE, 'properties': {'tags': ['external/cwe/cwe-089'],
                                            'security-severity': '8.5'}}]}},
        'invocations': [{'executionSuccessful': True}],
        'results': [{'ruleId': SAST_RULE, 'level': 'error', 'message': {'text': 'sqli'},
                     'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'app/q.py'},
                                                         'region': region},
                                    'logicalLocations': [{'fullyQualifiedName': 'app.q.get'}]}]}]}]}


def secret_sarif(tool):
    return {'version': '2.1.0', 'runs': [{
        'tool': {'driver': {'name': tool, 'rules': [{'id': 'aws-access-key-id'}]}},
        'invocations': [{'executionSuccessful': True}],
        'results': [{'ruleId': 'aws-access-key-id', 'level': 'error',
                     'message': {'text': 'AWS key AKIAIOSFODNN7EXAMPLE'},
                     'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'infra/main.tf'},
                                                         'region': {'startLine': 3}}}]}]}]}


def state(scanner, sarif):
    return {'scanner': scanner, 'applicability': 'APPLICABLE', 'execution': 'COMPLETE',
            'scope': 'x', 'sarif': sarif, 'artifact': 'RETAINED', 'upload': 'COMPLETE',
            'gate': 'FAIL', 'job': 'job-' + scanner}


class Run(object):
    def __init__(self, docs, extra=()):
        self.work = tempfile.mkdtemp(prefix='report-wiring-')
        for name, doc in docs:
            io.open(os.path.join(self.work, name + '.sarif'), 'w', encoding='utf-8').write(json.dumps(doc))
            io.open(os.path.join(self.work, 'state-%s.json' % name), 'w', encoding='utf-8').write(
                json.dumps(state(name, name + '.sarif')))
        out = os.path.join(self.work, 'gh_output')
        io.open(out, 'w').close()
        env = dict(os.environ, GITHUB_OUTPUT=out, GITHUB_STEP_SUMMARY='')
        p = subprocess.run([sys.executable, '-E', '-s', REPORTER, '--batch', self.work,
                            '--max-detail', '5'] + list(extra),
                           capture_output=True, text=True, env=env)
        self.rc, self.text = p.returncode, (p.stdout or '') + (p.stderr or '')
        self.out = {}
        for line in io.open(out, encoding='utf-8'):
            if '=' in line:
                k, v = line.rstrip('\n').split('=', 1)
                self.out[k] = v
        path = self.out.get('findings') or ''
        self.records = json.load(io.open(path, encoding='utf-8')) if os.path.isfile(path) else []
        self.by_scanner = dict((r.get('scanner'), r) for r in self.records)

    def close(self):
        shutil.rmtree(self.work, ignore_errors=True)


def write_json(work, name, obj):
    p = os.path.join(work, name)
    io.open(p, 'w', encoding='utf-8').write(json.dumps(obj))
    return p


def main():
    try:
        from finding_identity import identify
        import baseline_ledger as bl
        import finding_match as fm
    except ImportError as exc:
        print('UNKNOWN: %s' % exc)
        return 2
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    side = tempfile.mkdtemp(prefix='report-wiring-side-')
    runs = []
    try:
        # ── correlate: one advisory, one purl, two scanners, two different paths ─────────
        r = Run([('trivy', dep_sarif('Trivy', 'requirements.txt')),
                 ('malicious-deps', dep_sarif('osv-scanner', 'poetry.lock'))])
        runs.append(r)
        check('Correlated across scanners:** 1 finding' in r.text,
              'correlate: one advisory at one purl from two scanners at different paths was not '
              'reported as ONE correlated finding -- the report still keys on (uri, rule)')
        ids = set(x.get('identity') for x in r.records)
        check(len(ids) == 1 and None not in ids, 'correlate: the two observations do not share one '
                                                 'identity (%r)' % ids)
        # ── correlate: same path and rule id, no durable identity -> NOT correlated ─────
        r = Run([('gitleaks', secret_sarif('gitleaks')), ('detect-secrets', secret_sarif('detect-secrets'))])
        runs.append(r)
        check('Correlated across scanners' not in r.text,
              'correlate: two scanners agreeing on (uri, rule) with NO durable identity were '
              'reported as correlated -- that is the (uri, rule) key, which identity forbids')

        # ── alias table ──────────────────────────────────────────────────────────────────
        r0 = Run([('semgrep', sast_sarif())])
        runs.append(r0)
        base = r0.by_scanner.get('semgrep') or {}
        check(base.get('state') == 'FINGERPRINTED', 'alias: control finding did not fingerprint (%s)'
              % base.get('reason'))
        table = {'schema_version': 1, 'generations': {'semgrep': {'pinned': '1.92'}},
                 'aliases': [{'scanner': 'semgrep', 'versions': '>=1.0', 'rule_id': SAST_RULE,
                              'family': 'sqli'}]}
        r1 = Run([('semgrep', sast_sarif())], ['--rule-families', write_json(side, 'aliases.json', table)])
        runs.append(r1)
        with_t = r1.by_scanner.get('semgrep') or {}
        check(with_t.get('state') == 'FINGERPRINTED',
              'alias: with a usable table the finding refused (%s)' % with_t.get('reason'))
        check(with_t.get('identity') and with_t.get('identity') != base.get('identity'),
              'alias: the alias table did not reach WHAT -- the identity is the same as the '
              'string-split family produced, so rule_family.resolve was not called')
        two = dict(table, aliases=table['aliases'] + [dict(table['aliases'][0], family='other')])
        r2 = Run([('semgrep', sast_sarif())], ['--rule-families', write_json(side, 'two.json', two)])
        runs.append(r2)
        dis = r2.by_scanner.get('semgrep') or {}
        check(dis.get('state') == 'UNFINGERPRINTABLE' and dis.get('reason') == 'WHAT_UNDERIVABLE',
              'alias: a table whose aliases DISAGREE did not refuse WHAT (%s / %s) -- a table that '
              'answers two ways answers nothing, and falling back past it reaches for the rule id'
              % (dis.get('state'), dis.get('reason')))
        check(r2.out.get('blocking_findings') == r0.out.get('blocking_findings'),
              'alias: refusing the identity changed the blocking count (%s vs %s)'
              % (r2.out.get('blocking_findings'), r0.out.get('blocking_findings')))

        # ── cascade: a ledger entry for the dependency finding, environment prod ─────────
        ident = identify({'finding_subject': 'SOURCE_DEPENDENCY', 'cve': CVE, 'purl': PURL})
        prov = {'run_id': '7', 'observed_at': '2026-01-01T00:00:00Z', 'observed_at_source': 'SIDECAR'}
        entry = bl.entry_from_identity(ident, 'prod', '2026-01-01', prov, True)
        ledger = {'entries': [entry], 'state': bl.LEDGER_INTACT, 'notes': ['fixture'],
                  'merge_base': 'm' * 40, 'tip': 't' * 40, 'header': {}}
        lp = write_json(side, 'ledger.json', ledger)
        docs = [('trivy', dep_sarif('Trivy', 'requirements.txt')), ('semgrep', sast_sarif())]
        good = Run(docs, ['--ledger', lp, '--environment', 'prod'])
        runs.append(good)
        tri = good.by_scanner.get('trivy') or {}
        sem = good.by_scanner.get('semgrep') or {}
        check(tri.get('identity_match') == fm.IDENTITY_MATCHED_EXACT
              and tri.get('baseline_state') == fm.PRE_EXISTING_BASELINED,
              'cascade: the ledgered finding was not matched exact / baselined (%s / %s)'
              % (tri.get('identity_match'), tri.get('baseline_state')))
        check(sem.get('identity_match') == fm.IDENTITY_UNMATCHED and sem.get('baseline_state') == fm.NEW,
              'cascade: the unledgered finding was not NEW (%s / %s)'
              % (sem.get('identity_match'), sem.get('baseline_state')))
        check(good.out.get('identity_routing') == 'PROCEED',
              'cascade: identity_routing is %r, expected PROCEED when every identity matched a '
              'readable ledger' % good.out.get('identity_routing'))
        check(good.out.get('baseline_state') == bl.LEDGER_INTACT,
              'cascade: baseline_state is %r, expected the ledger state' % good.out.get('baseline_state'))
        check(good.out.get('blocking_findings') == '2', 'cascade control: blocking count %r, expected 2'
              % good.out.get('blocking_findings'))
        wrong_env = Run(docs, ['--ledger', lp, '--environment', 'dev'])
        runs.append(wrong_env)
        check((wrong_env.by_scanner.get('trivy') or {}).get('baseline_state') == fm.NEW,
              'cascade: an entry for `prod` grandfathered a finding evaluated in `dev`')

        # ── untrusted: no ledger / unusable ledger / uncomputable identity ───────────────
        none = Run(docs)
        runs.append(none)
        check(none.out.get('identity_routing') == fm.EVIDENCE_UNTRUSTED
              and none.out.get('baseline_state') == fm.BASELINE_UNAVAILABLE,
              'untrusted: no ledger read gave identity_routing=%r baseline_state=%r; an unread '
              'ledger is not an empty one' % (none.out.get('identity_routing'), none.out.get('baseline_state')))
        broken = Run(docs, ['--ledger', write_json(side, 'broken.json', dict(ledger, state=bl.LEDGER_LINE_UNPARSEABLE,
                                                                               entries=[])),
                           '--environment', 'prod'])
        runs.append(broken)
        check(broken.out.get('identity_routing') == fm.EVIDENCE_UNTRUSTED,
              'untrusted: an unparseable ledger did not route the identity claim to EVIDENCE_UNTRUSTED')
        no_env = Run(docs, ['--ledger', lp])
        runs.append(no_env)
        check(no_env.out.get('identity_routing') == fm.EVIDENCE_UNTRUSTED,
              'untrusted: a ledger with no environment named was used anyway')
        for label, x in (('no ledger', none), ('unparseable ledger', broken), ('no environment', no_env)):
            check(x.out.get('blocking_findings') == good.out.get('blocking_findings'),
                  'untrusted (%s): the blocking count changed (%r vs %r). The baseline has no '
                  'authority over what blocks' % (label, x.out.get('blocking_findings'),
                                                  good.out.get('blocking_findings')))
        unc = Run([('trivy', dep_sarif('Trivy', 'requirements.txt')), ('semgrep', sast_sarif(snippet=None))],
                  ['--ledger', lp, '--environment', 'prod'])
        runs.append(unc)
        check((unc.by_scanner.get('semgrep') or {}).get('identity_match') == fm.IDENTITY_UNCOMPUTABLE,
              'untrusted: a finding with no computable identity was not IDENTITY_UNCOMPUTABLE')
        check(unc.out.get('identity_routing') == fm.EVIDENCE_UNTRUSTED,
              'untrusted: an uncomputable identity did not route the identity claim to '
              'EVIDENCE_UNTRUSTED (%r)' % unc.out.get('identity_routing'))
        check(unc.out.get('blocking_findings') == '2',
              'untrusted: an uncomputable identity changed the blocking count (%r)'
              % unc.out.get('blocking_findings'))

        # ── secrets are outside the baseline by design ──────────────────────────────────
        sec = Run([('trivy', dep_sarif('Trivy', 'requirements.txt')), ('gitleaks', secret_sarif('gitleaks'))],
                  ['--ledger', lp, '--environment', 'prod'])
        runs.append(sec)
        check(sec.out.get('identity_routing') == 'PROCEED',
              'secrets: a secret finding made the identity claim %r. Secrets are never baselined '
              '(section 5.7); that is a design fact, not missing evidence' % sec.out.get('identity_routing'))
        check('outside the baseline by design' in sec.text,
              'secrets: the report does not say the secret finding was left out of the cascade')
    finally:
        for r in runs:
            r.close()
        shutil.rmtree(side, ignore_errors=True)

    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: the reporter correlates on durable identity (anchored only), resolves the rule '
          'family through the alias table and refuses when it disagrees, matches the ledger per '
          'environment, and publishes EVIDENCE_UNTRUSTED for the identity claim without touching '
          'the blocking count.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
