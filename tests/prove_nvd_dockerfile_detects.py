#!/usr/bin/env python3
"""Run the NVD workflow's own Dockerfile step, as shipped, against a seeded misconfiguration.

WHY THIS EXISTS (validation deferral `nvd-dockerfile`: "seeded Dockerfile misconfiguration is detected")

    `Scan Dockerfiles for misconfiguration` finds Dockerfiles, installs Trivy, and writes
    `trivy config` output to nvd-scan-results/trivy-dockerfile.txt. This probe extracts that step
    from reusable-nvd-cve.yml AS SHIPPED and runs it under GitHub's shell with the REAL Trivy.

    SHIMMED, AND WHY: the step's install lines (curl, sha256sum, tar, sudo) are no-ops here, so the
    trivy already on PATH is the one that runs. The install itself -- pinned version, verified
    digest -- is proven statically by tests/check_pinned_installs.py and is owed to a hosted run;
    this probe proves what the step DOES with the tool. Stated rather than hidden.

    The Dockerfiles are written at run time, so no misconfigured Dockerfile sits in this repository.

SCENARIOS
    seeded         `FROM ubuntu:latest`, no USER  -> the report names DS-class failures (root user,
                   latest tag); step exits 0 (report-only by design, recorded as such)
    clean          pinned base, non-root USER, HEALTHCHECK -> no failures for the root-user check
    no_dockerfile  no Dockerfile at all             -> step exits 0 and says it skipped; no report

EXIT 0 every scenario decided as it must; 1 one decided wrongly; 2 could not be checked -- UNKNOWN.
"""
import io
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _step_harness as H  # noqa: E402

WF = '.github/workflows/reusable-nvd-cve.yml'
STEP = 'Scan Dockerfiles for misconfiguration'
SEEDED = 'FROM ubuntu:latest\nRUN apt-get update\nCOPY . /app\nCMD ["/app/run"]\n'
CLEAN = ('FROM alpine:3.20.3\nRUN adduser -D app\nCOPY --chown=app . /app\nUSER app\n'
         'HEALTHCHECK CMD ["/app/health"]\nCMD ["/app/run"]\n')
ROOT_USER = re.compile(r'\b(?:AVD-)?DS-?0*002\b')


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    if not shutil.which('trivy'):
        print('UNKNOWN: trivy is required to RUN the step.')
        return 2
    bash, why = H.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s).' % why)
        return 2
    step = H.step(WF, 'nvd-cve-scan', STEP)
    if step is None:
        print('UNKNOWN: step %r not found.' % STEP)
        return 2
    bad = []
    tmp = tempfile.mkdtemp(prefix='nvd-dockerfile-probe-')
    try:
        shims = os.path.join(tmp, 'shim')
        for n in ('curl', 'sha256sum', 'tar', 'sudo'):
            H.shim(shims, n, 'exit 0   # install line: proven by check_pinned_installs.py')
        for name, dockerfile in (('seeded', SEEDED), ('clean', CLEAN), ('no_dockerfile', None)):
            ws = os.path.join(tmp, name)
            os.makedirs(os.path.join(ws, 'nvd-scan-results'))
            if dockerfile:
                io.open(os.path.join(ws, 'Dockerfile'), 'w', newline='\n').write(dockerfile)
            r = H.run(bash, step, {'inputs.scan_dockerfiles': 'true'}, ws, shims)
            rep = os.path.join(ws, 'nvd-scan-results', 'trivy-dockerfile.txt')
            text = io.open(rep, encoding='utf-8', errors='replace').read() if os.path.exists(rep) else ''
            fails = [int(x) for x in re.findall(r'Failures:\s*(\d+)', text)]
            root = bool(ROOT_USER.search(text))
            print('  %-14s exit=%d report=%s failures=%s root-user-check=%s'
                  % (name, r['rc'], os.path.exists(rep), fails or '-', root))
            if r['rc'] != 0:
                bad.append('%s: the step failed (exit %d)\n%s' % (name, r['rc'], r['log'][-400:]))
            if name == 'seeded' and (not fails or max(fails) == 0 or not root):
                bad.append('seeded: the root-user misconfiguration was not reported:\n%s' % text[-600:])
            if name == 'clean' and root:
                bad.append('clean: a non-root Dockerfile was reported for the root-user check')
            if name == 'no_dockerfile' and (os.path.exists(rep) or 'skipping' not in r['log']):
                bad.append('no_dockerfile: expected an explicit skip and no report')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: the NVD workflow\'s shipped Dockerfile step reports a seeded root-user / latest-tag '
          'misconfiguration, does not report it for a clean Dockerfile, and skips explicitly when '
          'there is none. Report-only by design: it never fails the job.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
