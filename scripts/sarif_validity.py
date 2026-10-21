#!/usr/bin/env python3
"""Validity rows 1-6 of PIPELINE_ORDERING_AND_SCAN_VALIDITY section 4.5, on the runner, on the
local file, BEFORE any publication (ledger L02).

WHY THIS EXISTS
    The count sites checked two of the six things a SARIF must show before its zero means
    anything: that the file exists and that it parses. Rows 3-6 lived only in the report job,
    AFTER upload-sarif -- and GitHub does not ingest `executionSuccessful` or the tool
    notifications at all (section 4.6), so a failed run uploads cleanly and presents as a
    successful scan with zero alerts. A validity check after publication validates nothing
    while looking exactly like validation; it belongs here, beside the redactor, for the same
    reason the redactor does.

THE ROWS (any one => COLLECTION_FAILED; none => VALID, and the result count is printed)
    1  file absent or empty
    2  does not parse, or is not a SARIF object with `runs`
    3  `runs` null, not an array, or empty -- no run is recorded
    4  any run's `results` absent or null   -- SARIF 3.14.23: "did not attempt". The single
                                               highest-value row: today it counts as zero.
    5  any `toolExecutionNotifications` or `toolConfigurationNotifications` entry at level
       `error`                               -- SARIF 3.20.21: "SHALL mean that the run failed"
    6  any `invocations[].executionSuccessful` false -- SARIF 3.20.14

PER-TOOL PROFILE, NOT A UNIVERSAL HOLLOW RULE (KDEC-008 OD-2)
    `rules: []` and `artifacts: []` are NOT witnesses of an empty scan: a clean bandit run emits
    exactly `results: [] rules: []` (measured, bandit 1.9.4), and no tool in the suite lists
    examined artifacts (PIPELINE_ORDERING 4.4.1). PROFILES records, per tool, what this file may
    rely on; `rules_witness` is False for every one, and rows 8-10 (the sidecar channels) are not
    built here -- the design forbids shipping them before a channel exists.

USAGE
    python3 sarif_validity.py [--tool NAME] FILE...
    python3 sarif_validity.py --self-test

EXIT
    0  every FILE is VALID            3  a FILE is COLLECTION_FAILED (row and reason printed)
    2  self-test failed / bad usage
"""
import io
import json
import os
import sys

# What each producer's SARIF can be relied on for (measured where stated; PO 4.4 / 3.6).
#   invocations     does it write runs[].invocations at all
#   disclosure      where it reports a file it could not analyse ('' = it does not)
#   rules_witness   may an empty rules[] be read as "examined nothing" -- never, per OD-2
PROFILES = {
    'bandit':     dict(invocations=True, disclosure='toolConfigurationNotifications (error)',
                       rules_witness=False),
    'semgrep':    dict(invocations=True, disclosure='', rules_witness=False),   # 1.178: silent
    'gitleaks':   dict(invocations=False, disclosure='', rules_witness=False),
    'gosec':      dict(invocations=False, disclosure='', rules_witness=False),
    'trivy':      dict(invocations=False, disclosure='', rules_witness=False),
    'checkov':    dict(invocations=False, disclosure='', rules_witness=False),
    'cppcheck':   dict(invocations=False, disclosure='', rules_witness=False),  # kit-converted
    'flawfinder': dict(invocations=False, disclosure='', rules_witness=False),
    # The two added with the last four count sites (flagship lane report row 10). UNMEASURED:
    # nothing here relies on a tool-specific channel for either; rows 1-6 apply and no more.
    'codeql':      dict(invocations=True, disclosure='', rules_witness=False),
    'osv-scanner': dict(invocations=False, disclosure='', rules_witness=False),
}
NOTIFICATIONS = ('toolExecutionNotifications', 'toolConfigurationNotifications')


def verdict(path):
    """-> ('VALID', None, results) or ('COLLECTION_FAILED', 'row N: reason', None)."""
    if not os.path.isfile(path) or os.path.getsize(path) == 0:
        return 'COLLECTION_FAILED', 'row 1: %s is absent or empty' % path, None
    try:
        doc = json.load(io.open(path, encoding='utf-8-sig'))
    except (ValueError, OSError) as exc:
        return 'COLLECTION_FAILED', 'row 2: %s does not parse (%s)' % (path, exc), None
    if not isinstance(doc, dict) or 'runs' not in doc:
        return 'COLLECTION_FAILED', 'row 2: %s is not a SARIF object with runs' % path, None
    runs = doc.get('runs')
    if not isinstance(runs, list) or not runs:
        return 'COLLECTION_FAILED', 'row 3: %s records no run (runs is %s)' % (
            path, 'empty' if isinstance(runs, list) else 'null'), None
    n = 0
    for i, run in enumerate(runs):
        if not isinstance(run, dict) or not isinstance(run.get('results'), list):
            return 'COLLECTION_FAILED', ('row 4: %s run %d has no results array -- the tool did '
                                         'not attempt (SARIF 3.14.23)' % (path, i)), None
        n += len(run['results'])
    for i, run in enumerate(runs):
        for inv in (run.get('invocations') or []):
            if not isinstance(inv, dict):
                continue
            for k in NOTIFICATIONS:
                for note in (inv.get(k) or []):
                    if isinstance(note, dict) and note.get('level') == 'error':
                        text = str((note.get('message') or {}).get('text', ''))[:120]
                        return 'COLLECTION_FAILED', ('row 5: %s run %d reports an error-level %s '
                                                     '(%s) -- the run failed, completeness may '
                                                     'not be assumed' % (path, i, k, text)), None
            if inv.get('executionSuccessful') is False:
                return 'COLLECTION_FAILED', ('row 6: %s run %d reports executionSuccessful false'
                                             % (path, i)), None
    return 'VALID', None, n


def self_test():
    import tempfile
    d = tempfile.mkdtemp(prefix='sarif-validity-')
    fails = []

    def case(name, text, want_state, want_row=None):
        p = os.path.join(d, name)
        if text is not None:
            io.open(p, 'w', encoding='utf-8').write(text)
        st, why, _n = verdict(p)
        if st != want_state or (want_row and not (why or '').startswith(want_row)):
            fails.append('%s: got %s (%s), expected %s %s' % (name, st, why, want_state,
                                                               want_row or ''))

    run = lambda **kw: json.dumps({'version': '2.1.0', 'runs': [dict(
        {'tool': {'driver': {'name': 't', 'rules': []}}}, **kw)]})
    case('absent', None, 'COLLECTION_FAILED', 'row 1')
    case('empty', '', 'COLLECTION_FAILED', 'row 1')
    case('notjson', '{"runs": [ trunc', 'COLLECTION_FAILED', 'row 2')
    case('notsarif', '[1, 2]', 'COLLECTION_FAILED', 'row 2')
    case('runsnull', '{"version": "2.1.0", "runs": null}', 'COLLECTION_FAILED', 'row 3')
    case('runsempty', '{"version": "2.1.0", "runs": []}', 'COLLECTION_FAILED', 'row 3')
    case('resultsnull', run(results=None), 'COLLECTION_FAILED', 'row 4')
    case('resultsabsent', run(), 'COLLECTION_FAILED', 'row 4')
    case('errnote', run(results=[], invocations=[{'executionSuccessful': True,
         'toolConfigurationNotifications': [{'level': 'error', 'message': {'text': 'x'}}]}]),
         'COLLECTION_FAILED', 'row 5')
    case('execfalse', run(results=[], invocations=[{'executionSuccessful': False}]),
         'COLLECTION_FAILED', 'row 6')
    case('warnnote', run(results=[], invocations=[{'executionSuccessful': True,
         'toolExecutionNotifications': [{'level': 'warning', 'message': {'text': 'x'}}]}]),
         'VALID')
    # OD-2: bandit's measured clean run -- results [], rules [] -- is VALID, not hollow.
    case('bandit_clean', run(results=[], invocations=[{'executionSuccessful': True}]), 'VALID')
    case('findings', run(results=[{'ruleId': 'x'}]), 'VALID')
    if any(p['rules_witness'] for p in PROFILES.values()):
        fails.append('a profile treats empty rules[] as a hollow-scan witness (OD-2 forbids it)')
    import shutil
    shutil.rmtree(d, ignore_errors=True)
    if fails:
        print('SELF-TEST FAILED:')
        for f in fails:
            print('  - %s' % f)
        return False
    print('self-test ok: rows 1-6 each yield COLLECTION_FAILED; a warning note, a clean bandit run '
          'and a run with findings are VALID')
    return True


def main(argv):
    if '--self-test' in argv:
        return 0 if self_test() else 2
    tool, files, i = '', [], 0
    while i < len(argv):
        if argv[i] == '--tool' and i + 1 < len(argv):
            tool, i = argv[i + 1], i + 2
            continue
        files.append(argv[i])
        i += 1
    if not files:
        print('usage: sarif_validity.py [--tool NAME] FILE...')
        return 2
    if tool and tool not in PROFILES:
        print('::warning title=No validity profile::%s has no declared profile; rows 1-6 apply, '
              'nothing tool-specific is assumed.' % tool)
    worst = 0
    for f in files:
        st, why, n = verdict(f)
        if st == 'VALID':
            print('VALID %s (%d result(s))' % (f, n))
        else:
            print('COLLECTION_FAILED %s' % why)
            worst = 3
    return worst


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
