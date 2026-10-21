#!/usr/bin/env python3
"""Secrets found in the container image get a report row of their own (docs/assurance/KNOWN_GAPS.md
section 1 remainder).

WHY THIS EXISTS

    image-scan writes trivy-image-secret.sarif, redacts it, keeps it and publishes it (ledger L12),
    and the consolidated report never read it: the only row for the image was `trivy-image`, built
    from the VULNERABILITY report. A credential baked into the image blocked through the gate's
    secret_fail and appeared in no report row, so the report's roster -- the thing a reader counts
    on to be total -- was one scanner short, and "one row absent reads as nothing to report" is the
    failure family this report exists to end.

WHAT IS RUN
    The report job's "Build per-scanner state" step, extracted as shipped, in a workspace holding
    what the artifact download would have delivered; then the reporter itself (scripts/scan_report.py
    batch, the function the scan-report composite runs) over the states it wrote, with the roster the
    workflow passes as `expect:`.

CASES (docs/PROOF_RULE.md)
    allowed           an image is named and both image reports arrived -> the trivy-image-secret
                      row is APPLICABLE, COMPLETE and established, carrying the secret finding
    attack            an image is named and the secret report is MISSING -> the row is APPLICABLE
                      and NOT ESTABLISHED (machine output ABSENT, gate UNDETERMINED) -- never NONE
    missing-evidence  the roster omits the row -> the reporter raises a roster fault (control: the
                      roster is what makes an absent row visible)
    recovery          no image is named -> NOT_APPLICABLE, like trivy-image
    static            the roster (`expect:`) names trivy-image-secret; the subject map answers IMAGE
                      for it (tests/prove_subject_covers_roster.py holds the roster/map agreement)

EXIT 0 every case decided as it must; 1 a case decided wrongly; 2 could not be checked (UNKNOWN).
"""
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
import _scan_step_harness as h  # noqa: E402
import prove_bootstrap_failure as pbf  # noqa: E402

ROW = 'trivy-image-secret'
SARIF = 'trivy-image-secret.sarif'
IMAGE = 'registry.example/app:1.0'


def secret_sarif():
    return json.dumps({'version': '2.1.0', 'runs': [{
        'tool': {'driver': {'name': 'Trivy', 'rules': [
            {'id': 'github-pat', 'shortDescription': {'text': 'GitHub token'},
             'properties': {'tags': ['secret', 'security', 'HIGH'],
                            'security-severity': '8.0'}}]}},
        'results': [{'ruleId': 'github-pat', 'level': 'error',
                     'message': {'text': 'Artifact: app/settings.env'},
                     'locations': [{'physicalLocation': {
                         'artifactLocation': {'uri': 'app/settings.env'},
                         'region': {'startLine': 1}}}]}]}]})


def vuln_sarif():
    return json.dumps({'version': '2.1.0', 'runs': [{
        'tool': {'driver': {'name': 'Trivy', 'rules': []}}, 'results': []}]})


def roster(text):
    m = re.search(r'^\s*expect:\s*([A-Za-z0-9_,.-]+)\s*$', text, re.M)
    return [n.strip() for n in m.group(1).split(',')] if m else []


def block(txt, name):
    parts = txt.split('### %s\n' % name)
    return parts[1].split('\n### ')[0] if len(parts) > 1 else ''


def index_row(txt, name):
    for line in txt.splitlines():
        if line.startswith('| %s |' % name) or line.startswith('| `%s` |' % name):
            return line
    return ''


def main():
    try:
        import yaml  # noqa: F401
        import scan_report
    except ImportError as exc:
        print('UNKNOWN: %s' % exc)
        return 2
    bash, why = pbf.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s).' % why)
        return 2
    text = io.open(h.WF, encoding='utf-8').read()
    bad = []
    names = roster(text)
    if not names:
        print('UNKNOWN: the report roster (expect:) was not found.')
        return 2
    if ROW not in names:
        bad.append('static: %r is not on the report roster (expect:) -- the row cannot be owed' % ROW)
    step = h.steps_by_name('report').get('Build per-scanner state')
    if step is None:
        print('UNKNOWN: the report job has no "Build per-scanner state" step.')
        return 2
    if not re.search(r'^\s*add\s+"%s"' % re.escape(ROW), str(step.get('run') or ''), re.M):
        bad.append('static: the state builder writes no state for %r' % ROW)
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1

    sb = h.Sandbox('image-secret-row-')
    try:
        def states_for(name, image, files):
            vals = {'needs.image-scan.result': 'success', 'inputs.image_ref': image,
                    'needs.discover.outputs.state': 'COMPLETE'}
            ws = sb.workspace(name, dict({'_sarif/.keep': ''}, **files))
            rc, log, _o, _u = sb.run(bash, step, vals, ws)
            if rc != 0:
                bad.append('%s: the state builder exited %d\n%s' % (name, rc, log[-400:]))
            return os.path.join(ws, '_states')

        def report(states, expect):
            txt, faults = scan_report.batch(states, '', 20, '', expect)
            return txt, faults

        # allowed: both reports arrived; the secret row carries its finding.
        st = states_for('allowed', IMAGE, {'_sarif/trivy-image.sarif': vuln_sarif(),
                                            '_sarif/%s' % SARIF: secret_sarif()})
        txt, faults = report(st, names)
        blk, row = block(txt, ROW), index_row(txt, ROW)
        print('  allowed          index: %s' % row)
        if 'Applicability | APPLICABLE' not in blk or 'Execution | COMPLETE' not in blk:
            bad.append('allowed: the row is not APPLICABLE / COMPLETE:\n%s' % blk[:600])
        if 'NOT ESTABLISHED' in blk or '| **Total** | **1** |' not in blk:
            bad.append('allowed: the secret finding is not counted on its own row:\n%s' % blk[:900])
        if any(ROW in f for f in faults):
            bad.append('allowed: roster fault for %r: %s' % (ROW, faults))

        # attack: the secret report is missing -- not zero, not absent from the table.
        st = states_for('attack-missing', IMAGE, {'_sarif/trivy-image.sarif': vuln_sarif()})
        txt, faults = report(st, names)
        blk, row = block(txt, ROW), index_row(txt, ROW)
        print('  attack-missing   index: %s' % row)
        if 'Applicability | APPLICABLE' not in blk or 'NOT ESTABLISHED' not in blk \
                or 'Machine output | ABSENT' not in blk or 'Gate state | UNDETERMINED' not in blk:
            bad.append('attack-missing: a named image with no secret report must render APPLICABLE '
                       'and NOT ESTABLISHED (machine output ABSENT, gate UNDETERMINED):\n%s' % blk[:900])

        # recovery: no image named -> NOT_APPLICABLE, like the vulnerability row.
        st = states_for('recovery-noimage', '', {})
        txt, faults = report(st, names)
        blk = block(txt, ROW)
        print('  recovery-noimage index: %s' % index_row(txt, ROW))
        if 'Applicability | NOT_APPLICABLE' not in blk:
            bad.append('recovery-noimage: with no image named the row must be NOT_APPLICABLE:\n%s'
                       % blk[:400])

        # missing-evidence (control): a roster that omits the row is a roster fault, so the
        # mechanism that makes an absent row visible is itself exercised.
        st = states_for('control', IMAGE, {'_sarif/trivy-image.sarif': vuln_sarif()})
        os.remove(os.path.join(st, 'state-%s.json' % ROW))
        _txt, faults = report(st, names)
        if not any(("no result for '%s'" % ROW) in f for f in faults):
            bad.append('control: a state missing for %r raised no roster fault: %s' % (ROW, faults))
    finally:
        sb.close()
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: image secrets have their own report row -- established with its finding when the '
          'report arrived, NOT ESTABLISHED when it is missing, NOT_APPLICABLE when no image is named, '
          'and a roster fault when the state is absent.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
