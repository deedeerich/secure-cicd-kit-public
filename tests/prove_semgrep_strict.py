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

    P4  the Semgrep this runs is the release the sast-semgrep job's container pins by digest (the
        `# X.Y.Z` on its image line; tests/_semgrep_pin.py). FAILS ON 7fe3d54: the job ran the
        semgrep/semgrep 1.90.0 tag while this ran 1.178.0, so P1 held a release the job never ran.

    NOT PROVEN HERE: the same release, not the same packaging -- this runs Semgrep from PATH (pip
    in self-test, pinned to the job's release), the job runs the image. The image's own exit 3 is
    owed to a hosted run of the job (reported, not claimed).

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


def _shipped(path):
    """The flagship's text plus the scanner composites it calls through `$/` (ledger L64): a
    scanner's commands live there now, and reading the workflow alone would count fewer sites."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import _composite_expand
    return _composite_expand.shipped_text(path)


def static_check():
    text = _shipped(h.WF)
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
        # P4 the Semgrep run here is the release the job's container pins, by digest (lane L-SG)
        import _semgrep_pin
        image, pinned, problem = _semgrep_pin.flagship(h.WF)
        local = _semgrep_pin.path_version(bash, h.path_prefix(sb.shim))
        print('  P4 job image %s (%s); Semgrep on PATH %s' % (image, pinned, local))
        if problem:
            bad.append('P4 %s' % problem)
        if not pinned or local != pinned:
            bad.append('P4 this ran Semgrep %s, but the job runs %s (%s): exit 3 would be proved '
                       'for a release the job does not run' % (local, pinned, image))
        vals ={'inputs.paths': '.', 'inputs.semgrep_config': 'p/python',
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
