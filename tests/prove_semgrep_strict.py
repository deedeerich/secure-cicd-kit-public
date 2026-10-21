#!/usr/bin/env python3
"""A file Semgrep could not parse must not read as a clean scan (`--strict`, exit 3).

WHY THIS EXISTS

    PIPELINE_ORDERING_AND_SCAN_VALIDITY 3.4: Semgrep files a parse failure as a WARNING-level
    notification and exits 0, and the code it skipped is reported as scanned and clean. SARIF does
    not treat a warning as a failed run, so the runner-side validity check (rows 1-6) passes it.
    The lever is `--strict`, under which Semgrep exits 3 ("invalid syntax of the scanned
    language") and still writes the SARIF. The design called it "the cheapest unbuilt thing in this
    document"; every Semgrep invocation in the kit ran without it.

    Measured locally with Semgrep 1.178.0 (2026-10-16), one file holding a hardcoded password and
    unparseable Python: without --strict, rc 0 and one warning notification; with it, rc 3.

WHAT IT PROVES
    P1  the sast-semgrep job's scan step, run AS SHIPPED with the real Semgrep, over a tree holding
        an unparseable Python file, exits non-zero and writes collection=COLLECTION_FAILED
    P2  CONTROL: the same step over a tree that parses does NOT write COLLECTION_FAILED, so P1 is
        caused by the parse failure and not by the step refusing everything
    P3  every `semgrep scan` in the flagship (the C# and Java jobs install Semgrep in-step, so
        they are checked by reading, not run) passes --strict and maps exit 3 to COLLECTION_FAILED

    NOT PROVEN HERE: the sast-semgrep job runs the semgrep/semgrep:1.90.0 container; this runs the
    locally installed Semgrep. Semgrep documents exit 3 under --strict for both; the 1.90.0 run is
    owed to a hosted run (reported, not claimed).

EXIT  0 all hold, 1 any does not, 2 could not be checked (no bash, no semgrep, no registry)
"""
import io
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _scan_step_harness as h  # noqa: E402
import prove_bootstrap_failure as pbf  # noqa: E402

JOB, SCAN = 'sast-semgrep', 'Semgrep scan'
UNPARSEABLE = 'password = "hunter2"\nif x ==== :\n  ))) (((\nclass\n'
PARSES = 'def add(a, b):\n    return a + b\n'


def static_check():
    text = io.open(h.WF, encoding='utf-8').read()
    calls = [m.start() for m in re.finditer(r'^\s*semgrep scan\b', text, re.M)]
    bad = []
    if not calls:
        bad.append('P3 no `semgrep scan` found in the flagship; this check reads nothing')
    for pos in calls:
        line_no = text.count('\n', 0, pos) + 1
        window = text[pos:pos + 700]
        cmd = window.split('\n')[0] + window.split('\n')[1]
        if '--strict' not in cmd:
            bad.append('P3 line %d: semgrep scan without --strict' % line_no)
        if not re.search(r'sg_rc=\$\?.*?"\$sg_rc" = "3".*?COLLECTION_FAILED', window, re.S):
            bad.append('P3 line %d: exit 3 is not mapped to COLLECTION_FAILED' % line_no)
    return bad, len(calls)


def main():
    bad, n_calls = static_check()
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    bash, why = pbf.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s).' % why)
        return 2
    steps = h.steps_by_name(JOB)
    if SCAN not in steps:
        print('UNKNOWN: no step %r in job %r.' % (SCAN, JOB))
        return 2
    sb = h.Sandbox('semgrep-strict-').with_bundle()
    try:
        if not h.have(bash, 'semgrep', h.path_prefix(sb.shim)):
            print('UNKNOWN: semgrep is required to RUN the step.')
            return 2
        vals = {'inputs.paths': '.', 'inputs.semgrep_config': 'p/python',
                'inputs.soft_fail_sast': 'false', 'inputs.advisory_mode': 'false'}
        results = {}
        for name, files in (('unparseable', {'app.py': UNPARSEABLE}),
                            ('parses', {'app.py': PARSES})):
            ws = sb.workspace(name, files)
            rc, log, out, _unk = sb.run(bash, steps[SCAN], vals, ws, env={'SEMGREP_APP_TOKEN': ''})
            if 'Failed to download' in log or 'ConnectionError' in log:
                print('UNKNOWN: semgrep could not fetch its registry rules.')
                return 2
            results[name] = (rc, out.get('collection', ''), log)
            print('  %-12s rc=%d collection=%s' % (name, rc, out.get('collection', '(unset)')))
        rc, coll, log = results['unparseable']
        if rc == 0 or coll != 'COLLECTION_FAILED':
            bad.append('P1 an unparseable file read as a completed scan (rc %d, collection %r)'
                       % (rc, coll))
        rc, coll, log = results['parses']
        if coll == 'COLLECTION_FAILED':
            bad.append('P2 CONTROL: a tree that parses was refused as COLLECTION_FAILED:\n%s'
                       % log[-600:])
    finally:
        sb.close()
    for b in bad:
        print('FAIL ' + b)
    if bad:
        return 1
    print('PASS: an unparseable file makes the Semgrep step COLLECTION_FAILED (exit 3 under')
    print('      --strict); a parseable tree does not; all %d `semgrep scan` sites carry it.'
          % n_calls)
    return 0


if __name__ == '__main__':
    sys.exit(main())
