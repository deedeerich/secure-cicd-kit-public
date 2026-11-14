#!/usr/bin/env python3
"""KREQ-558: no DAST and no deployed scan without a live-target authorisation record in force.

WHY THIS EXISTS

    A dynamic scan sends attack traffic at a running system, and a deployed scan reads a live target
    with a cloud identity. Both act on something the pipeline does not own outright: the target's
    owner, and whoever answers its alerts, have to have agreed to it. The kit ran either one whenever
    a command or an environment was configured -- configuration standing in for authorisation.

THE RECORD (`.kit/live-target-authorisation.json` on the repository's DEFAULT branch, read through
the contents API so a branch under review cannot authorise itself; schema
schemas/live-target-authorisation.schema.json)

    {"schema_version": 1,
     "authorisations": [{"id": "LTA-001", "environment": "dev", "targets": ["app-name"],
                         "scans": ["dast", "deployed-scan"], "authorised_by": "<role>",
                         "authorised_on": "YYYY-MM-DD", "expires_on": "YYYY-MM-DD",
                         "reference": "<change or ticket>"}]}

    An entry is in force for (scan, environment, target) when all three are named exactly (no
    wildcard), authorised_on <= today <= expires_on, and the window is at most 366 days.

OUTCOMES (assurance-taxonomy.yaml :: live_target_authorisation)
    LIVE_TARGET_AUTHORISED     an entry is in force; the scan may run
    PREREQUISITE_UNAVAILABLE   absent, unreadable, malformed, expired, not yet valid, over-long, or
                               out of scope (environment, target or scan) -- the scan is NOT run, and
                               the reason is recorded. Never a pass: for DAST the deploy's dast.json
                               says PREREQUISITE_UNAVAILABLE, so the release is not verified for
                               promotion.

EXIT  0 authorised   1 not authorised   2 usage.   Proof: tests/prove_live_target_authorisation.py.
"""
import argparse
import base64
import datetime
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rollback_hold as RH  # noqa: E402  (the GitHub API reader)

AUTHORISED = 'LIVE_TARGET_AUTHORISED'
UNAVAILABLE = 'PREREQUISITE_UNAVAILABLE'
RECORD_PATH = '.kit/live-target-authorisation.json'
SCANS = ('dast', 'deployed-scan')
MAX_WINDOW_DAYS = 366
REQUIRED = ('id', 'environment', 'targets', 'scans', 'authorised_by', 'authorised_on', 'expires_on',
            'reference')


def _date(v):
    return datetime.datetime.strptime(str(v), '%Y-%m-%d').date()


def malformed(record):
    """-> None, or why the record does not meet its schema."""
    if not isinstance(record, dict) or record.get('schema_version') != 1:
        return 'schema_version is not 1'
    auths = record.get('authorisations')
    if not isinstance(auths, list) or not auths:
        return 'authorisations is not a non-empty list'
    for i, e in enumerate(auths):
        if not isinstance(e, dict):
            return 'authorisations[%d] is not an object' % i
        miss = [k for k in REQUIRED if e.get(k) in (None, '', [])]
        if miss:
            return 'authorisations[%d] lacks %s' % (i, ', '.join(miss))
        if not isinstance(e['targets'], list) or not all(isinstance(t, str) and t for t in e['targets']):
            return 'authorisations[%d].targets is not a list of names' % i
        if not isinstance(e['scans'], list) or any(s not in SCANS for s in e['scans']):
            return 'authorisations[%d].scans names something other than %s' % (i, '/'.join(SCANS))
        try:
            _date(e['authorised_on'])
            _date(e['expires_on'])
        except ValueError:
            return 'authorisations[%d] has a date that is not YYYY-MM-DD' % i
    return None


def decide(record, scan, environment, target, today):
    """-> (outcome, reason, entry id or None). Pure: the proof drives it directly."""
    if record is None:
        return UNAVAILABLE, 'absent: no %s on the default branch, or it could not be read' % RECORD_PATH, None
    bad = malformed(record)
    if bad:
        return UNAVAILABLE, 'malformed: %s' % bad, None
    scoped = [e for e in record['authorisations']
              if e['environment'] == environment and target in e['targets'] and scan in e['scans']]
    if not scoped:
        return UNAVAILABLE, ('out of scope: no entry names scan %r on target %r in environment %r'
                             % (scan, target, environment)), None
    reasons = []
    for e in scoped:
        on, exp = _date(e['authorised_on']), _date(e['expires_on'])
        if (exp - on).days > MAX_WINDOW_DAYS:
            reasons.append('%s: its window is %d days, over %d' % (e['id'], (exp - on).days, MAX_WINDOW_DAYS))
        elif today < on:
            reasons.append('%s: not yet valid (from %s)' % (e['id'], on))
        elif today > exp:
            reasons.append('%s: expired %s' % (e['id'], exp))
        else:
            return AUTHORISED, ('%s, authorised by %s on %s until %s (%s)'
                                % (e['id'], e['authorised_by'], on, exp, e['reference'])), e['id']
    return UNAVAILABLE, 'expired or not in force: ' + '; '.join(reasons), None


def read_record(local_path):
    if local_path:
        try:
            return json.load(io.open(local_path, encoding='utf-8'))
        except (OSError, ValueError):
            return None
    try:
        doc = RH.api('contents/%s' % RECORD_PATH)
        return json.loads(base64.b64decode(doc.get('content') or '').decode('utf-8'))
    except (RH.Unreadable, ValueError, AttributeError, TypeError):
        return None


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--scan', choices=SCANS, required=True)
    ap.add_argument('--environment', required=True)
    ap.add_argument('--target', required=True)
    ap.add_argument('--record', default='', help='a local record (proofs); default: the contents API')
    ap.add_argument('--today', default='', help='YYYY-MM-DD (proofs); default: today, UTC')
    ap.add_argument('--out', default='')
    ap.add_argument('--dast-evidence', default='',
                    help='the deploy evidence directory: when not authorised, dast.json records it')
    ap.add_argument('--github-output', default='')
    ap.add_argument('--summary', default='')
    a = ap.parse_args(argv)
    today = _date(a.today) if a.today else datetime.datetime.utcnow().date()
    outcome, reason, entry = decide(read_record(a.record), a.scan, a.environment, a.target, today)
    doc = {'live_target_authorisation': outcome, 'reason': reason, 'entry': entry, 'scan': a.scan,
           'environment': a.environment, 'target': a.target, 'checked_on': str(today)}
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        io.open(a.out, 'w', encoding='utf-8').write(json.dumps(doc, indent=1, sort_keys=True))
    if outcome != AUTHORISED and a.dast_evidence:
        os.makedirs(a.dast_evidence, exist_ok=True)
        io.open(os.path.join(a.dast_evidence, 'dast.json'), 'w', encoding='utf-8').write(json.dumps(
            {'result': UNAVAILABLE, 'reason': 'not run: no live-target authorisation in force (%s)' % reason},
            indent=1, sort_keys=True))
    text = '### Live-target authorisation (KREQ-558), %s: `%s`\n\n%s' % (a.scan, outcome, reason)
    if a.summary:
        io.open(a.summary, 'a', encoding='utf-8').write(text + '\n')
    print(text)
    one = reason.replace('\n', ' ').replace('::', ': :')
    print('::%s title=%s %s::%s' % ('notice' if outcome == AUTHORISED else 'error', a.scan, outcome, one))
    RH._out(a.github_output, live_target_authorisation=outcome)
    return 0 if outcome == AUTHORISED else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
