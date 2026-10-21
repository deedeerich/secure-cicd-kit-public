#!/usr/bin/env python3
"""Run the sast-bandit job's scan, count and enforce steps, as shipped, with the real bandit.

WHY THIS EXISTS (ledger L08)

    The scan step ended `${{ inputs.soft_fail_sast && '|| true' || '' }}` under a comment citing
    "the count step downstream" -- a step that did not exist. With soft-fail on, a bandit crash and
    a clean scan were the same green; with it off, ANY finding, LOW included, failed the job before
    anything counted it, and an absent report published nothing and said so in a `notice`.

MEASURED, NOT ASSUMED (bandit 1.9.4, 2026-10-14)
    * exit 1 on ANY finding -- `import subprocess` (B404, LOW, level `note`) alone fails it;
    * exit 0 when a file FAILS TO PARSE: the only trace is a `toolConfigurationNotifications`
      entry at level `error`, so the exit code cannot stand in for "the scan read the code";
    * a MEDIUM finding (B307 eval) carries NO `level` at all, and its rule has no
      `defaultConfiguration` -- its effective level is SARIF's default, `warning`;
    * a clean run is `results: []` with `rules: []` -- not hollow (KDEC-008 OD-2).

    So the count is the EFFECTIVE error level (result level, else rule default, else "warning"),
    the same reading the Semgrep count uses, and blocking follows HIGH severity only.

SCENARIOS
    seeded_enforce   shell=True + eval, soft_fail off -> count 1 (B602), enforce FAILS
    seeded_soft      the same, soft_fail on           -> count 1, enforce passes (recorded)
    low_only         `import subprocess` only          -> count 0, enforce passes (bandit exit 1)
    clean            no flaw                           -> count 0, enforce passes
    scanner_crash    bandit exits 2, writes nothing    -> COLLECTION_FAILED, enforce FAILS
    unparseable      a report that is not JSON         -> COLLECTION_FAILED, enforce FAILS
    results_null     SARIF whose run has no `results`  -> COLLECTION_FAILED (did not attempt)

EXIT
    0  every scenario decided as it must
    1  a scenario decided wrongly
    2  could not be checked (no bash, no bandit, no jq) -- UNKNOWN, never PASS
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _scan_step_harness as h  # noqa: E402
import prove_bootstrap_failure as pbf  # noqa: E402

JOB = 'sast-bandit'
SCAN, COUNT, ENFORCE = 'Bandit → SARIF', 'Bandit — count findings', 'Bandit — enforce'

SEEDED = 'import subprocess\n\n\ndef run(cmd):\n    subprocess.call(cmd, shell=True)\n    return eval(cmd)\n'
LOW = 'import subprocess\n\n\ndef nothing():\n    return subprocess\n'
CLEAN = 'def add(a, b):\n    return a + b\n'
NULL_RESULTS = json.dumps({'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'Bandit'}}}]})


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
    missing = [n for n in (SCAN, COUNT, ENFORCE) if n not in steps]
    if missing:
        print('FAIL: job %r has no step(s) %s. Bandit\'s report is published but never counted '
              'and never enforced, and an absent report reads as nothing to publish.'
              % (JOB, missing))
        return 1
    sb = h.Sandbox('bandit-probe-').with_bundle()
    bad = []
    try:
        for tool in ('bandit', 'jq'):
            if not h.have(bash, tool, h.path_prefix(sb.shim)):
                print('UNKNOWN: %s is required to RUN the steps.' % tool)
                return 2
        # `pip install` IS NOT RUN BY A PROOF. The scan step installs the pinned bandit on the
        # runner; here a `python` shim turns `-m pip install` into a no-op and the bandit already
        # on this host runs (self-test installs the same pinned release). Everything else passes
        # through to the real interpreter.
        pyshim = os.path.join(sb.root, 'pyshim')
        h.write(os.path.join(pyshim, 'python'),
                '#!/usr/bin/env bash\nif [ "${1:-}" = "-m" ] && [ "${2:-}" = "pip" ]; then\n'
                '  echo "(proof) skipped: python $*"; exit 0\nfi\nexec "%s" "$@"\n'
                % sys.executable.replace('\\', '/'))
        # A bandit that crashes before writing anything: the "scanner did not run" case.
        crash = os.path.join(sb.root, 'crash')
        h.write(os.path.join(crash, 'bandit'),
                '#!/usr/bin/env bash\necho "bandit: simulated crash" >&2\nexit 2\n')
        for d in (pyshim, crash):
            for f in os.listdir(d):
                os.chmod(os.path.join(d, f), 0o755)
        scenarios = [
            # name, files, soft, scanner?, preset report, expect collection, count, enforce ok
            ('seeded_enforce', {'app/svc.py': SEEDED}, 'false', True, None, '', '1', False),
            ('seeded_soft', {'app/svc.py': SEEDED}, 'true', True, None, '', '1', True),
            ('low_only', {'app/svc.py': LOW}, 'false', True, None, '', '0', True),
            ('clean', {'app/svc.py': CLEAN}, 'false', True, None, '', '0', True),
            ('scanner_crash', {'app/svc.py': SEEDED}, 'false', False, None, 'COLLECTION_FAILED',
             None, False),
            ('unparseable', None, 'false', True, '{"runs": [ truncated', 'COLLECTION_FAILED',
             None, False),
            ('results_null', None, 'false', True, NULL_RESULTS, 'COLLECTION_FAILED', None,
             False),
        ]
        for name, files, soft, scanner, preset, want_coll, want_n, enforce_ok in scenarios:
            ws = sb.workspace(name, files)
            vals = {'inputs.paths': '.', 'inputs.soft_fail_sast': soft,
                    'inputs.advisory_mode': 'false', 'inputs.python_version': '3.12'}
            if preset is None:
                xp = pyshim if scanner else os.pathsep.join((crash, pyshim))
                rc, log, sout, unk = sb.run(bash, steps[SCAN], vals, ws, extra_path=xp)
            else:
                h.write(os.path.join(ws, 'bandit.sarif'), preset)
                rc, log, sout, unk = 1, '', {'rc': '1'}, []
            if unk:
                bad.append('%s: scan step reads unmodelled %s' % (name, unk))
            cvals = dict(vals, **{'steps.bandit.outputs.%s' % k: v for k, v in sout.items()})
            crc, clog, cout, unk = sb.run(bash, steps[COUNT], cvals, ws)
            if unk:
                bad.append('%s: count step reads unmodelled %s' % (name, unk))
            # An output the count step did not write is absent, which GitHub renders as ''.
            evals = dict(cvals, **{'steps.bandit_count.outputs.%s' % k: cout.get(k, '')
                                   for k in ('count', 'collection')})
            erc, elog, _o, unk = sb.run(bash, steps[ENFORCE], evals, ws)
            if unk:
                bad.append('%s: enforce step reads unmodelled %s' % (name, unk))
            coll, n = cout.get('collection', ''), cout.get('count')
            print('  %-15s scan_rc=%-3s collection=%-18s count=%-3s enforce exit=%d'
                  % (name, sout.get('rc', '-'), coll or '-', n if n is not None else '-', erc))
            if (coll or '') != want_coll:
                bad.append('%s: collection=%r, expected %r\n%s' % (name, coll, want_coll,
                                                                   (log + clog)[-600:]))
            if want_n is not None and n != want_n:
                bad.append('%s: count=%r, expected %s' % (name, n, want_n))
            if enforce_ok and erc != 0:
                bad.append('%s: enforce failed (exit %d) where it must pass\n%s'
                           % (name, erc, elog[-300:]))
            if not enforce_ok and erc == 0:
                bad.append('%s: enforce PASSED. %s' % (name, (
                    'A HIGH-severity finding with soft_fail_sast off must block.'
                    if want_coll == '' else 'No evidence is not a clean scan.')))
    finally:
        sb.close()
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: the shipped bandit steps record the exit code, count the effective error level, '
          'enforce it unless softened, and read an absent, unparseable or results-null report as '
          'COLLECTION_FAILED.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
