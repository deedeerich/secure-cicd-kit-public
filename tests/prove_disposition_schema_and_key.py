#!/usr/bin/env python3
"""Dispositions suppress only when written to the schema, and on the durable key (L49, KDEC-008 OD-6).

WHY THIS EXISTS

    L49: the reporter and the suppression linter read `state` as the CLAIM -- `state: ACCEPTED_RISK`
    suppressed. schemas/disposition.schema.json puts the claim in `disposition_type` and reserves
    `state` for the lifecycle, of which only `approved` suppresses ("a proposal never buys
    passage"). So a record written exactly to the schema suppressed nothing, a record written to
    neither suppressed, and a record with no `expires` -- which the schema REQUIRES -- suppressed
    forever. Two readers, one schema, zero agreement.

    OD-6 (KDEC-008): approvals were keyed on the legacy fingerprint, built from scanner, rule id,
    path and message -- the four fields a vendor change moves. Dispositions move to the durable
    identity, with a 30-day window in which the legacy key is also honoured; after it the legacy
    key stops suppressing, and the run says so.

WHAT IT PROVES, through the real batch() over a state directory and a disposition register

    schema         an approved, complete record suppresses; the same record with state proposed,
                   under_review or absent does not; without `expires` does not; without
                   rationale/approver_role does not; MITIGATED without compensating_control does
                   not; ACCEPTED_RISK without evidence_ref does not; the claim written into
                   `state` (the legacy shape) does not, and the reason names the migration;
                   RISK_ACCEPTED / RISK_ACCEPTANCE do not
    key            keyed on the durable identity: suppresses, basis durable. Keyed on the legacy
                   fingerprint inside the window: suppresses, basis legacy, report says until when.
                   After the window: does NOT suppress, and the report names the orphaned key and
                   the identity to re-key to. Both keys present: the durable one is the basis
    linter         scripts/lint_suppressions.py accepts the schema shape, reports the legacy
                   shape as a defect naming disposition_type, and skips a proposed record

EXIT  0 proven   1 a case failed (named)   2 could not be checked (UNKNOWN, never PASS)
"""
import datetime
import io
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

CVE = 'CVE-2018-18074'
PURL = 'pkg:pypi/requests@2.19.1'


def dep_sarif():
    return {'version': '2.1.0', 'runs': [{
        'tool': {'driver': {'name': 'Trivy', 'version': '0.56.1',
                            'rules': [{'id': CVE, 'properties': {'security-severity': '9.1'}}]}},
        'invocations': [{'executionSuccessful': True}],
        'results': [{'ruleId': CVE, 'level': 'error', 'message': {'text': 'requests leak'},
                     'properties': {'purl': PURL},
                     'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'requirements.txt'},
                                                         'region': {'startLine': 7}}}]}]}]}


def record(key, claim='ACCEPTED_RISK', **over):
    d = {'schema_version': 1, 'fingerprint': key, 'scanner': 'trivy', 'rule': CVE,
         'scope_path': 'requirements.txt', 'disposition_type': claim,
         'rationale': 'Upstream has no patch; the service is not internet facing and the '
                      'compensating network rule is recorded in the change ticket.',
         'evidence_ref': 'change-record-17', 'approver_role': 'security-lead',
         'created': '2026-01-01', 'expires': '2099-01-01', 'state': 'approved'}
    d.update(over)
    for k in [k for k, v in d.items() if v is None]:
        del d[k]
    return d


def main():
    try:
        import scan_report as sr
        import lint_suppressions as ls
    except ImportError as exc:
        print('UNKNOWN: %s' % exc)
        return 2
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    work = tempfile.mkdtemp(prefix='disposition-')
    try:
        io.open(os.path.join(work, 'trivy.sarif'), 'w', encoding='utf-8').write(json.dumps(dep_sarif()))
        io.open(os.path.join(work, 'state-trivy.json'), 'w', encoding='utf-8').write(json.dumps(
            {'scanner': 'trivy', 'applicability': 'APPLICABLE', 'execution': 'COMPLETE', 'scope': 'x',
             'sarif': 'trivy.sarif', 'artifact': 'RETAINED', 'upload': 'COMPLETE', 'gate': 'FAIL',
             'job': 'deps-scan'}))
        findings, _ps, _ex = sr.parse_sarif(os.path.join(work, 'trivy.sarif'), 'trivy')
        if len(findings) != 1 or not findings[0]['identity']:
            print('UNKNOWN: the fixture did not fingerprint (%r)' % (findings and findings[0].get('identity_reason')))
            return 2
        identity, legacy = findings[0]['identity'], findings[0]['fp']
        check(identity != legacy and len(identity) > len(legacy), 'control: the two keys are not distinct')

        def run(register, today=None, label=''):
            p = os.path.join(work, 'dispositions.json')
            io.open(p, 'w', encoding='utf-8').write(json.dumps({'dispositions': register}))
            summary = {}
            text, _f = sr.batch(work, p, 5, '', [], summary, today=today)
            return summary.get('blocking_findings'), text

        # ── schema ────────────────────────────────────────────────────────────────────
        n, text = run({identity: record(identity)})
        check(n == 0, 'schema: an approved, complete record did not suppress (blocking=%r)' % n)
        check('honoured' in text, 'schema: the honoured disposition is not rendered as honoured')
        for label, rec in (
                ('state proposed', record(identity, state='proposed')),
                ('state under_review', record(identity, state='under_review')),
                ('state absent (schema default proposed)', record(identity, state=None)),
                ('no expires', record(identity, expires=None)),
                ('no rationale', record(identity, rationale=None)),
                ('thin rationale', record(identity, rationale='fp')),
                ('no approver_role', record(identity, approver_role=None)),
                ('MITIGATED without compensating_control', record(identity, claim='MITIGATED')),
                ('ACCEPTED_RISK without evidence_ref', record(identity, evidence_ref=None)),
                ('claim in state (legacy shape)', {'state': 'ACCEPTED_RISK', 'approved_by': 'x',
                                                   'expires': '2099-01-01'}),
                ('RISK_ACCEPTED', record(identity, claim='RISK_ACCEPTED')),
                ('RISK_ACCEPTANCE', record(identity, claim='RISK_ACCEPTANCE')),
                ('expired', record(identity, expires='2020-01-01'))):
            n, text = run({identity: rec})
            check(n == 1, 'schema: %s suppressed the finding (blocking=%r)' % (label, n))
        n, text = run({identity: {'state': 'ACCEPTED_RISK', 'approved_by': 'x', 'expires': '2099-01-01'}})
        check('disposition_type' in text, 'schema: the legacy-shape refusal does not name '
                                          'disposition_type, so nobody knows what to migrate to')
        ok = record(identity, claim='MITIGATED', compensating_control='egress policy on the subnet')
        n, text = run({identity: ok})
        check(n == 0, 'schema: MITIGATED with its compensating control did not suppress')

        # ── key ───────────────────────────────────────────────────────────────────────
        opened = datetime.date(*[int(x) for x in sr.legacy_key_window_opened.split('-')])
        inside = opened + datetime.timedelta(days=1)
        after = opened + datetime.timedelta(days=sr.legacy_key_window_days + 1)
        n, text = run({identity: record(identity)}, today=after)
        check(n == 0, 'key: the durable key stopped suppressing after the window (blocking=%r)' % n)
        n, text = run({legacy: record(legacy)}, today=inside)
        check(n == 0, 'key: the legacy key did not suppress inside the window (blocking=%r)' % n)
        check('legacy' in text.lower() and sr.legacy_key_window_closes in text,
              'key: inside the window the report does not say the legacy key is honoured and until when')
        n, text = run({legacy: record(legacy)}, today=after)
        check(n == 1, 'key: the legacy key STILL suppressed after the window closed (blocking=%r)' % n)
        check(legacy in text and identity in text and 'window' in text.lower(),
              'key: after the window the run does not say which legacy key stopped suppressing and '
              'which durable identity to re-key it to')
        n, text = run({legacy: record(legacy), identity: record(identity)}, today=after)
        check(n == 0, 'key: with both keys present the durable one was not honoured')
        n, text = run({legacy: record(legacy, state='proposed'), identity: record(identity)}, today=inside)
        check(n == 0, 'key: a proposed legacy record masked an approved durable one')

        # ── linter ────────────────────────────────────────────────────────────────────
        today = datetime.date(2026, 10, 14)
        rp = os.path.join(work, 'reg.json')
        io.open(rp, 'w', encoding='utf-8').write(json.dumps({identity: record(identity)}))
        rows, state = ls.lint_exceptions(rp, today)
        check(state == 'LOADED' and not [r for r in rows if r[1] == 'ERROR'],
              'linter: a schema-shaped approved record was reported defective: %r' % rows)
        io.open(rp, 'w', encoding='utf-8').write(json.dumps(
            {identity: {'state': 'ACCEPTED_RISK', 'owner_role': 'x', 'expires': '2099-01-01',
                        'rationale': 'Upstream has no patch; recorded in the change ticket.'}}))
        rows, _s = ls.lint_exceptions(rp, today)
        check(any(r[1] == 'ERROR' and 'disposition_type' in r[3] for r in rows),
              'linter: the legacy shape (claim in `state`) was not reported as a defect naming '
              'disposition_type: %r' % rows)
        io.open(rp, 'w', encoding='utf-8').write(json.dumps({identity: record(identity, state='proposed')}))
        rows, _s = ls.lint_exceptions(rp, today)
        check(not rows, 'linter: a proposed record was linted as a live exception: %r' % rows)
    finally:
        shutil.rmtree(work, ignore_errors=True)

    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: only an approved, complete, unexpired record written to the schema suppresses; '
          'the claim belongs in disposition_type and only state=approved buys passage; the durable '
          'identity is the key, the legacy fingerprint is honoured inside the %d-day window and '
          'refused after it with the run naming the key to migrate; the linter reads the same '
          'schema.' % sr.legacy_key_window_days)
    return 0


if __name__ == '__main__':
    sys.exit(main())
