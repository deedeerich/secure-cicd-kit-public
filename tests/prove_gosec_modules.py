#!/usr/bin/env python3
"""Run the sast-go job's gosec and enforce steps, as shipped, with the real gosec and Go.

WHY THIS EXISTS (ledger L08: "gosec drops a module silently")

    The step scans every go.mod root and merges the per-module reports. Three paths let a module
    vanish from the merge with no COLLECTION_FAILED:
      * gosec (or the container around it) exits 0 and writes NO report -- the exact shape of the
        2026-09-02 defect, when `docker run` received no arguments, did nothing and exited 0;
      * the module's report is not readable SARIF, so the path normaliser fails and the merge
        never sees a file for it;
      * the merge itself skips a file it cannot parse, printing `!!` and carrying on.
    Each yields a merged report over FEWER modules than were discovered, counted as if complete.

MEASURED, NOT ASSUMED (gosec 2.24.6, Go 1.22.12, 2026-10-14)
    * a seeded module exits 1 with five results (G702, G401, G204, G501 at `error`, G104 at
      `warning`);
    * a clean module exits 0 with `results: []`;
    * a module whose `go` directive is newer than the toolchain, or whose source does not parse,
      exits 1 with `results: []` -- a processing error by gosec's own documented exit codes.

HOW IT RUNS WITHOUT A CONTAINER RUNTIME
    The job runs gosec from the pinned `securego/gosec:2.24.6` image. Here `docker` is a shim that
    runs the SAME release natively in the mounted module directory, rewriting `/src/` to the host
    path, and can inject the two faults above for a module named `silent` or `corrupt`. Everything
    else -- discovery, the exit-code reading, normalisation, the merge, the count -- is the
    shipped step.

SCENARIOS
    seeded          one module with flaws, soft_fail off  -> count >= 1, enforce FAILS
    clean           one clean module                      -> count 0, enforce passes
    newer_beside    clean + a module that will not load   -> COLLECTION_FAILED (regression)
    silent_beside   seeded + a module that writes nothing -> COLLECTION_FAILED
    corrupt_beside  seeded + a module with broken SARIF   -> COLLECTION_FAILED

EXIT
    0  every scenario decided as it must
    1  a scenario decided wrongly
    2  could not be checked (no bash, no gosec, no go, no jq) -- UNKNOWN, never PASS
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _scan_step_harness as h  # noqa: E402
import prove_bootstrap_failure as pbf  # noqa: E402

JOB = 'sast-go'
SCAN, ENFORCE = 'gosec', 'gosec — enforce'

DOCKER = r'''#!/usr/bin/env bash
# Proof shim for `docker`: runs the same pinned gosec natively in the mounted module directory.
case "${1:-}" in
  image|pull) exit 0 ;;
  run) shift ;;
  *) echo "docker shim: unsupported: $*" >&2; exit 125 ;;
esac
vol=""
while [ $# -gt 0 ]; do
  case "$1" in
    --rm) shift ;;
    -v) vol="$2"; shift 2 ;;
    -w) shift 2 ;;
    *) break ;;
  esac
done
shift   # the image
host="${vol%:/src}"
case "$(basename "$host")" in
  silent) exit 0 ;;
  corrupt) printf '{"runs": [ truncated' > "$host/gosec.sarif"; exit 0 ;;
esac
args=()
for a in "$@"; do args+=("${a//\/src\//$host/}"); done
cd "$host" && exec gosec "${args[@]}"
'''


def module(name, go='1.21', src=None):
    return {'%s/go.mod' % name: 'module example.com/%s\n\ngo %s\n' % (name, go),
            '%s/main.go' % name: src or 'package main\n\nimport "fmt"\n\nfunc main() { fmt.Println("hi") }\n'}


SEEDED_SRC = ('package main\n\nimport (\n\t"crypto/md5"\n\t"fmt"\n\t"os"\n\t"os/exec"\n)\n\n'
              'func main() {\n\tfmt.Println(md5.Sum([]byte("x")))\n'
              '\texec.Command("sh", "-c", os.Args[1]).Run()\n}\n')


def merge(*mods):
    out = {}
    for m in mods:
        out.update(m)
    return out


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
    if SCAN not in steps or ENFORCE not in steps:
        print('UNKNOWN: step %r or %r missing from job %r.' % (SCAN, ENFORCE, JOB))
        return 2
    sb = h.Sandbox('gosec-probe-').with_bundle()
    bad = []
    try:
        for tool in ('gosec', 'go', 'jq'):
            if not h.have(bash, tool, h.path_prefix(sb.shim)):
                print('UNKNOWN: %s is required to RUN the step.' % tool)
                return 2
        dshim = os.path.join(sb.root, 'docker-shim')
        h.write(os.path.join(dshim, 'docker'), DOCKER)
        os.chmod(os.path.join(dshim, 'docker'), 0o755)
        scenarios = [
            ('seeded', module('svc', src=SEEDED_SRC), '', True, False),
            ('clean', module('svc'), '', False, True),
            ('newer_beside', merge(module('svc'), module('newer', go='1.99')),
             'COLLECTION_FAILED', None, False),
            ('silent_beside', merge(module('svc', src=SEEDED_SRC), module('silent')),
             'COLLECTION_FAILED', None, False),
            ('corrupt_beside', merge(module('svc', src=SEEDED_SRC), module('corrupt')),
             'COLLECTION_FAILED', None, False),
        ]
        for name, files, want_coll, finds, enforce_ok in scenarios:
            ws = sb.workspace(name, files)
            vals = {'inputs.paths': '.', 'inputs.soft_fail_sast': 'false',
                    'inputs.advisory_mode': 'false', 'inputs.go_version': '1.22'}
            rc, log, out, unk = sb.run(bash, steps[SCAN], vals, ws, extra_path=dshim)
            if unk:
                bad.append('%s: scan step reads unmodelled %s' % (name, unk))
            evals = dict(vals, **{'steps.gosec.outputs.%s' % k: out.get(k, '')
                                  for k in ('count', 'collection')})
            erc, elog, _o, unk = sb.run(bash, steps[ENFORCE], evals, ws)
            if unk:
                bad.append('%s: enforce step reads unmodelled %s' % (name, unk))
            coll, n = out.get('collection', ''), out.get('count', '')
            print('  %-15s scan exit=%d collection=%-18s count=%-3s enforce exit=%d'
                  % (name, rc, coll or '-', n or '-', erc))
            if coll != want_coll:
                bad.append('%s: collection=%r, expected %r -- a module was dropped from the '
                           'merge and the count read as complete\n%s'
                           % (name, coll, want_coll, log[-900:]))
            if finds is True and not (n.isdigit() and int(n) >= 1):
                bad.append('%s: the seeded module produced no counted finding\n%s'
                           % (name, log[-600:]))
            if finds is False and n != '0':
                bad.append('%s: count=%r, expected 0' % (name, n))
            if enforce_ok and erc != 0:
                bad.append('%s: enforce failed (exit %d)\n%s' % (name, erc, elog[-300:]))
            if not enforce_ok and erc == 0:
                bad.append('%s: enforce PASSED where it must fail' % name)
    finally:
        sb.close()
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: the shipped gosec step counts every discovered module or says which did not '
          'analyse: a module that writes no report, an unreadable report, or one that will not '
          'load is COLLECTION_FAILED, never silently dropped from the merge.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
