#!/usr/bin/env python3
"""A CodeQL autobuild that did not succeed must not leave the analysis reading COMPLETE.

WHY THIS EXISTS

    PIPELINE_ORDERING_AND_SCAN_VALIDITY 3.5: the autobuild step carries `id: cq_build` and is
    continue-on-error, and its outcome was read nowhere. A partially successful build (some modules
    compiled, others failed on a toolchain mismatch) leaves a partial database, an analysis that
    succeeds, a valid SARIF -- and `state=COMPLETE`. The step that knew was wired to nothing.

    BUILD MODE AND A LEG THAT DID NOT ANALYSE (integrate/r8, 2026-10-28). On the six-language
    cost fixture (public mirror, cost/after run 40791360475) the c-cpp, csharp and java-kotlin legs
    initialised, autobuild found no build system, `database finalize` exited 32 ("detected code
    ... but could not process any of it"), and analyze failed under continue-on-error. The leg
    declared COLLECTION_FAILED in an annotation -- and the JOB stayed green, so the gate read
    needs.codeql.result = success and the rows read execution COMPLETE, sarif NONE, UNDETERMINED.
    A leg that initialised and could not analyse is a collection failure, exactly as the count
    step's hollow-SARIF exit already treats one: it now FAILS, and the gate reads it as such.

WHAT IT PROVES (the codeql job's "declare state" step, run AS SHIPPED)
    C1  autobuild leg: init, analyze and the SARIF validity succeed, autobuild `failure` -> PARTIAL
    C2  autobuild leg: the same with autobuild `skipped` (it did not run) -> PARTIAL
    C3  CONTROL: autobuild leg, autobuild `success` -> COMPLETE, so C1/C2 are the build outcome
    C4  buildless leg (build_mode none): no autobuild ran, none was needed -> COMPLETE
    C5  init succeeded, analyze did not -> COLLECTION_FAILED and the step exits non-zero (the leg
        fails, so needs.codeql.result is failure)
    C6  init did not succeed (the licence case) -> UNAVAILABLE and the step exits 0 -- the build is
        never failed for a missing licence
    Every case writes codeql-leg/codeql-leg-<lang>.state holding exactly its state: the row builder
    reads it so each language's row carries its own leg (tests/prove_codeql_rows_read_sarif.py).

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
        cases = (
            # label, build_mode, init, analyze, autobuild, want state, want exit 0
            ('C1', 'autobuild', 'success', 'success', 'failure', 'PARTIAL', True),
            ('C2', 'autobuild', 'success', 'success', 'skipped', 'PARTIAL', True),
            ('C3', 'autobuild', 'success', 'success', 'success', 'COMPLETE', True),
            ('C4', 'none', 'success', 'success', 'skipped', 'COMPLETE', True),
            ('C5', 'none', 'success', 'failure', 'skipped', 'COLLECTION_FAILED', False),
            ('C6', 'none', 'failure', 'skipped', 'skipped', 'UNAVAILABLE', True),
        )
        for label, mode, init, analyze, build, want, zero in cases:
            vals = {'steps.cq_init.outcome': init, 'steps.cq_analyze.outcome': analyze,
                    'steps.cq_count.outputs.collection': 'COMPLETE' if analyze == 'success' else '',
                    'steps.cq_build.outcome': build, 'matrix.lang': 'c-cpp',
                    'matrix.build_mode': mode,
                    'inputs.codeql_queries': 'security-extended'}
            ws = sb.workspace(label)
            rc, log, out, unk = sb.run(bash, steps[STEP], vals, ws)
            got = out.get('state', '(unset)')
            leg = os.path.join(ws, 'codeql-leg', 'codeql-leg-c-cpp.state')
            filed = open(leg).read().strip() if os.path.exists(leg) else '(no file)'
            print('  %s mode=%-9s init=%-7s analyze=%-7s autobuild=%-7s state=%-17s file=%-17s exit=%d'
                  % (label, mode, init, analyze, build, got, filed, rc))
            if unk:
                bad.append('%s: the step reads %s, unmodelled here' % (label, unk))
            if got != want:
                bad.append('%s gave state %s, expected %s' % (label, got, want))
            if filed != want:
                bad.append('%s wrote %r to the leg state file, expected %s' % (label, filed, want))
            if (rc == 0) != zero:
                bad.append('%s: the step exited %d, expected %s' % (label, rc, 'exit 0' if zero else 'non-zero'))
    finally:
        sb.close()
    for b in bad:
        print('FAIL ' + b)
    if bad:
        return 1
    print('PASS: an autobuild leg whose build did not succeed reads PARTIAL, a successful one or a '
          'buildless leg COMPLETE; a leg that initialised and did not analyse is COLLECTION_FAILED '
          'and fails; a licence that refused init is UNAVAILABLE and does not; each leg files its state.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
