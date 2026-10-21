#!/usr/bin/env python3
"""The caller's `paths` must reach the OSV malicious-package scan and the SBOM, as shipped.

WHY THIS EXISTS

    Every other scanner job in reusable-security.yml scopes itself to `inputs.paths`. Two did not:
    `malicious-deps` ran `osv-scanner scan source --recursive ... .` and `sbom` ran `syft dir:.`,
    both over the WHOLE checkout. Measured on consumer-path run 38779788549 (commit ec73600), whose
    clean leg is scoped to tests/consumer-fixture/clean:

      * OSV walked every lockfile in the repository, reached tests/consumer-fixture/seeded --
        whose deliberately vulnerable pins cannot be co-installed (requests 2.19.1 needs
        urllib3 < 1.24; the file pins 1.24.1) -- failed to resolve it, and reported
        COLLECTION_FAILED for the CLEAN fixture: "a lockfile could not be parsed".
      * The clean leg's SBOM listed log4j-core 2.14.1, handlebars 4.0.11 and every other seeded
        dependency of the full fixture: an inventory of code the caller did not ask about.

    A scope that one scanner honours and another ignores answers two different questions under
    one verdict. For a monorepo caller, the unscoped scanners also pay for, and fail on, other
    teams' trees.

HOW (the house pattern, tests/_scan_step_harness.py)

    The steps are extracted from the workflow AS SHIPPED, their `${{ }}` and `env:` resolved from
    the scenario, and run under bash with shims for osv-scanner and syft that record every
    argument they were handed (and inert curl/sh, so the SBOM step's installer is neither fetched
    nor run). The assertion is about the TARGET the scanner received -- which is the whole defect.

SCENARIOS
    inputs.paths = svc/app -> both osv-scanner runs scan svc/app; syft scans dir:svc/app
    inputs.paths = .       -> both scan .

EXIT
    0  both scanners receive the caller's scope
    1  a scanner was handed something other than the scope
    2  could not be checked (no PyYAML, no bash, step missing) -- UNKNOWN, never PASS
"""
import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _scan_step_harness as h  # noqa: E402
import prove_bootstrap_failure as pbf  # noqa: E402

TARGETS = [('malicious-deps', 'Scan lockfiles', 'osv-scanner'),
           ('sbom', 'Generate SBOM with Syft', 'syft')]

# One line per call: the tool name, then every argument separated by a TAB.
RECORDER = ('#!/usr/bin/env bash\n'
            'line="$(basename "$0")"\n'
            'for a in "$@"; do line="$line\t$a"; done\n'
            'printf "%s\\n" "$line" >> "$SHIM_LOG"\n'
            'exit 0\n')
INERT = '#!/usr/bin/env bash\ncat >/dev/null 2>&1 || true\nexit 0\n'


def shims(d):
    for name, body in (('osv-scanner', RECORDER), ('syft', RECORDER), ('curl', INERT),
                       ('sh', INERT)):
        p = os.path.join(d, name)
        h.write(p, body)
        os.chmod(p, 0o755)
    return d


def target(tool, args):
    """osv-scanner takes its directory LAST; syft takes a `dir:` source."""
    if tool == 'syft':
        src = [a for a in args if a.startswith('dir:')]
        return src[0][len('dir:'):] if src else None
    return args[-1] if args else None


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
    bad = []
    sb = h.Sandbox('scope-osv-syft-')
    try:
        bin_dir = shims(os.path.join(sb.root, 'bin'))
        n = 0
        for scope in ('svc/app', '.'):
            for job, step_name, tool in TARGETS:
                steps = h.steps_by_name(job)
                if step_name not in steps:
                    print('UNKNOWN: no step %r in job %r.' % (step_name, job))
                    return 2
                n += 1
                ws = sb.workspace('ws%d' % n, {'svc/app/requirements.txt': 'urllib3==2.8.0\n',
                                               'elsewhere/requirements.txt': 'urllib3==1.24.1\n'})
                log = os.path.join(sb.root, 'shim%d.log' % n)
                rc, out, _o, unk = sb.run(bash, steps[step_name], {'inputs.paths': scope}, ws,
                                          extra_path=bin_dir, env={'SHIM_LOG': log})
                if unk:
                    bad.append('%s/%s: step reads unmodelled %s' % (job, step_name, unk))
                calls = []
                if os.path.exists(log):
                    for line in io.open(log, encoding='utf-8').read().splitlines():
                        parts = line.split('\t')
                        if parts[0] == tool:
                            calls.append(target(tool, parts[1:]))
                want = 2 if tool == 'osv-scanner' else 1
                print('  paths=%-8s %-12s rc=%d targets=%s' % (scope, tool, rc, calls))
                if len(calls) != want or any(c != scope for c in calls):
                    bad.append('paths=%s: %s was handed %s, expected %d call(s) scoped to %r '
                               '(step exit %d)' % (scope, tool, calls, want, scope, rc))
    finally:
        sb.close()
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print("PASS: osv-scanner and syft are handed the caller's `paths`, as every other scanner is.")
    return 0


if __name__ == '__main__':
    sys.exit(main())
