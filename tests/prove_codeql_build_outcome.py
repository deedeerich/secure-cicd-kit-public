#!/usr/bin/env python3
"""A CodeQL autobuild that did not succeed must not leave the analysis reading COMPLETE.

WHY THIS EXISTS

    PIPELINE_ORDERING_AND_SCAN_VALIDITY 3.5: the autobuild step carries `id: cq_build` and is
    continue-on-error, and its outcome was read nowhere. A partially successful build (some modules
    compiled, others failed on a toolchain mismatch) leaves a partial database, an analysis that
    succeeds, a valid SARIF -- and `state=COMPLETE`. The step that knew was wired to nothing.

WHAT IT PROVES (the codeql job's "declare state" step, run AS SHIPPED)
    C1  init, analyze and the SARIF validity all succeed, autobuild outcome `failure` -> PARTIAL
    C2  the same with autobuild `skipped` (it did not run) -> PARTIAL
    C3  CONTROL: autobuild `success` -> COMPLETE, so C1/C2 are caused by the build outcome

    NOT PROVEN HERE, AND REPORTED RATHER THAN CLAIMED: the gate reads the codeql job's RESULT,
    not this step's state output (matrix legs share one set of job outputs), so PARTIAL reaches
    the step summary and an annotation, not the verdict. Wiring a per-leg state to the gate is
    the decomposition plan's envelope work.

EXIT  0 all hold, 1 any does not, 2 could not be checked
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _scan_step_harness as h  # noqa: E402
import prove_bootstrap_failure as pbf  # noqa: E402

JOB, STEP = 'codeql', 'CodeQL — declare state'


def main():
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
    if STEP not in steps:
        print('UNKNOWN: no step %r in job %r.' % (STEP, JOB))
        return 2
    sb = h.Sandbox('codeql-build-')
    bad = []
    try:
        for label, build, want in (('C1', 'failure', 'PARTIAL'), ('C2', 'skipped', 'PARTIAL'),
                                   ('C3', 'success', 'COMPLETE')):
            vals = {'steps.cq_init.outcome': 'success', 'steps.cq_analyze.outcome': 'success',
                    'steps.cq_count.outputs.collection': 'COMPLETE',
                    'steps.cq_build.outcome': build, 'matrix.lang': 'java',
                    'inputs.codeql_queries': 'security-extended'}
            ws = sb.workspace(label)
            rc, log, out, _unk = sb.run(bash, steps[STEP], vals, ws)
            got = out.get('state', '(unset)')
            print('  %s autobuild=%-8s state=%s' % (label, build, got))
            if got != want:
                bad.append('%s autobuild %s gave state %s, expected %s' % (label, build, got, want))
    finally:
        sb.close()
    for b in bad:
        print('FAIL ' + b)
    if bad:
        return 1
    print('PASS: an autobuild that did not succeed reads PARTIAL; a successful one COMPLETE.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
