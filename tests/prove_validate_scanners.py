#!/usr/bin/env python3
"""The weekly scanner validation probes what the kit SHIPS, and its negative control can fail.

WHY THIS EXISTS (review finding W4K-116, reproduced by reading and by running the step)

    validate-scanners.yml is the weekly answer to "do the shipped scanners still detect the
    seeded defects". Two parts of it answered a different question:

      versions   Semgrep was probed at 1.181.0 while the C# and Java jobs install 1.178.0, and
                 gosec at v2.29.0 from source WITH -no-fail while the flagship runs the
                 securego/gosec:2.24.6 container WITHOUT it. A green week said the probed
                 versions detect the seeded defects, not the shipped ones.
      negative   the negative-control job never installed trivy. `trivy fs` was "command not
                 found", no report was written, and the job printed that the failed collection
                 "did not masquerade as a clean result" -- on a step that was continue-on-error.
                 It could not fail, so it proved nothing.

WHAT IT PROVES
    V1  the Semgrep probe installs the version the flagship's pip-installed Semgrep jobs pin
    V2  the gosec probe runs the flagship's gosec image, and without -no-fail
    V3  the negative-control step, run AS SHIPPED with shims:
          (a) trivy absent                                  -> the step FAILS
          (b) a trivy that exits 0 and writes an empty, well-formed report for a path that does
              not exist                                      -> the step FAILS
          (c) CONTROL: a trivy that scans a real directory and refuses a missing one
                                                            -> the step PASSES
    V4  the negative-control step is not continue-on-error (it can fail the run)

EXIT  0 all hold, 1 any does not, 2 could not run (no bash or jq)
"""
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import prove_bootstrap_failure as pbf  # noqa: E402

WFDIR = os.path.join(ROOT, '.github', 'workflows')
VALIDATE = os.path.join(WFDIR, 'validate-scanners.yml')
FLAGSHIP = os.path.join(WFDIR, 'reusable-security.yml')
STEP = 'Force a collection failure and assert it is NOT clean'

GOOD_TRIVY = r'''#!/usr/bin/env bash
out=""; prev=""; target=""
for a in "$@"; do [ "$prev" = "--output" ] && out="$a"; prev="$a"; target="$a"; done
if [ ! -e "$target" ]; then echo "no such path" >&2; exit 1; fi
printf '{"SchemaVersion":2,"Results":[]}' > "$out"
'''
LYING_TRIVY = r'''#!/usr/bin/env bash
out=""; prev=""
for a in "$@"; do [ "$prev" = "--output" ] && out="$a"; prev="$a"; done
printf '{"SchemaVersion":2,"Results":[]}' > "$out"
exit 0
'''


def _shipped(path):
    """The flagship's text plus the scanner composites it calls through `$/` (ledger L64): a
    scanner's commands live there now, and reading the workflow alone would count fewer sites."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import _composite_expand
    return _composite_expand.shipped_text(path)


def static_checks(bad):
    import yaml
    v = io.open(VALIDATE, encoding='utf-8').read()
    f = _shipped(FLAGSHIP)
    shipped = set(re.findall(r'pip install --quiet semgrep==([0-9.]+)', f))
    probed = set(re.findall(r'pip install --quiet semgrep==([0-9.]+)', v))
    print('  V1 semgrep shipped (pip) %s, probed %s' % (sorted(shipped), sorted(probed)))
    if not probed or probed != shipped:
        bad.append('V1 the Semgrep probe installs %s; the flagship pins %s'
                   % (sorted(probed), sorted(shipped)))
    img = re.findall(r"GOSEC_IMAGE='([^']+)'", f)
    print('  V2 gosec shipped image %s' % img)
    if not img or img[0] not in v:
        bad.append('V2 the gosec probe does not run the flagship image %s' % img)
    if re.search(r'gosec[^\n]*-no-fail', v):
        bad.append('V2 the gosec probe still passes -no-fail, which the flagship removed')
    doc = yaml.safe_load(io.open(VALIDATE, encoding='utf-8'))
    job = (doc.get('jobs') or {}).get('negative-control') or {}
    steps = {s.get('name'): s for s in job.get('steps') or []}
    if job.get('continue-on-error') or (steps.get(STEP) or {}).get('continue-on-error'):
        bad.append('V4 the negative control is continue-on-error, so it cannot fail the run')
    return steps.get(STEP)


def run_step(bash, body, path_dirs, cwd):
    script = os.path.join(cwd, 'step.sh')
    with open(script, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write(body)
    env = dict(os.environ, PATH=os.pathsep.join(path_dirs))
    p = subprocess.run([bash, script], cwd=cwd, env=env, capture_output=True, text=True,
                       encoding='utf-8', errors='replace')
    return p.returncode, p.stdout + p.stderr


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    bad = []
    step = static_checks(bad)
    bash, why = pbf.usable_bash()
    jq = shutil.which('jq')
    if not bash or not jq:
        print('UNKNOWN: bash (%s) and jq (%s) are needed to run the step.' % (bash or why, jq))
        return 2
    if not step:
        bad.append('V3 no step %r in the negative-control job' % STEP)
    else:
        work = tempfile.mkdtemp(prefix='validate-nc-')
        try:
            # A PATH with no trivy on it: every entry that holds one is dropped, and jq is
            # reached through a wrapper so dropping its directory cannot take jq with it.
            keep = [d for d in os.environ.get('PATH', '').split(os.pathsep)
                    if d and not any(os.path.exists(os.path.join(d, n))
                                     for n in ('trivy', 'trivy.exe', 'trivy.cmd', 'trivy.ps1'))]
            wrap = os.path.join(work, 'wrap')
            os.makedirs(wrap)
            jqp = jq.replace('\\', '/')
            with open(os.path.join(wrap, 'jq'), 'w', newline='\n') as fh:
                fh.write('#!/usr/bin/env bash\nexec "%s" "$@"\n' % jqp)
            os.chmod(os.path.join(wrap, 'jq'), 0o755)
            body = step['run']
            for label, fake, want_fail in (('a no trivy', None, True),
                                           ('b lying trivy', LYING_TRIVY, True),
                                           ('c honest trivy', GOOD_TRIVY, False)):
                case = os.path.join(work, label.split()[0])
                os.makedirs(case)
                dirs = [wrap]
                if fake:
                    sd = os.path.join(case, 'bin')
                    os.makedirs(sd)
                    with open(os.path.join(sd, 'trivy'), 'w', newline='\n') as fh:
                        fh.write(fake)
                    os.chmod(os.path.join(sd, 'trivy'), 0o755)
                    dirs.insert(0, sd)
                rc, log = run_step(bash, body, dirs + keep, case)
                print('  V3 %-15s rc=%d' % (label, rc))
                if want_fail and rc == 0:
                    bad.append('V3 (%s) the negative control PASSED: %s' % (label, log[-300:]))
                if not want_fail and rc != 0:
                    bad.append('V3 (%s) CONTROL: the negative control failed with an honest '
                               'scanner: %s' % (label, log[-400:]))
        finally:
            shutil.rmtree(work, ignore_errors=True)
    for b in bad:
        print(('FAIL ' + b).encode('ascii', 'replace').decode('ascii'))
    if bad:
        return 1
    print('PASS: the weekly probe runs the shipped Semgrep and gosec; its negative control fails')
    print('      without a scanner and with a lying one, and passes with an honest one.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
