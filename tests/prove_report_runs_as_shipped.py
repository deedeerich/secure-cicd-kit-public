#!/usr/bin/env python3
"""Run the reporter exactly where the report job runs it, with only what reaches that job.

WHY THIS EXISTS (C1)

    `scan_report.py` imports `finding_identity` and `finding_subject` at module top level. The report
    job ran it as `/tmp/scan_report.py`, out of a six-file bundle that ships neither module. Every
    run therefore died at import. Nothing caught it, because every proof in this repository imported
    the reporter from `scripts/`, where both modules sit beside it. A proof that runs its subject
    somewhere the subject never runs is testing its own environment.

    So this reads the report job AS SHIPPED, works out where the reporter actually executes, builds
    only what reaches the job, and runs the reporter's own `--self-test` there:

      bundle path    `/tmp/scan_report.py` -> a directory holding exactly the bundled files
                     (scripts/inline_normalizer.py SCRIPTS), materialised as the bootstrap writes them
      composite path `uses: $/.github/actions/<name>` -> a clean export of this commit (`git archive`),
                     because `$/` delivers the whole repository at the pinned commit
                     (decomposition plan header, run 38468728084), and the composite's own command

    Python runs with -E -s: no PYTHONPATH and no user site, so nothing on this machine can supply a
    module the runner would not have.

WHAT IT CANNOT ESTABLISH
    That the runner's Python matches this one, or that the report is correct. It establishes that
    the reporter STARTS and passes its own self-test in the place it is shipped to.

EXIT
    0  the reporter runs as shipped
    1  it does not (C1)
    2  could not be checked -- UNKNOWN, never PASS
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
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
WF = os.path.join(ROOT, '.github', 'workflows', 'reusable-security.yml')
JOB = 'security-gate'   # G3 (KDEC-033): the report is the first part of the gate job


def locate(doc):
    """-> ('bundle', None) | ('composite', name) | (None, why)"""
    steps = doc['jobs'][JOB].get('steps') or []
    for s in steps:
        uses = s.get('uses') or ''
        m = re.match(r'^\$/\.github/actions/([\w.-]+)$', uses)
        if m and os.path.isfile(os.path.join(ROOT, '.github', 'actions', m.group(1), 'action.yml')):
            text = io.open(os.path.join(ROOT, '.github', 'actions', m.group(1), 'action.yml'),
                           encoding='utf-8').read()
            if 'scan_report.py' in text:
                return 'composite', m.group(1)
    for s in steps:
        if '/tmp/scan_report.py' in (s.get('run') or ''):
            return 'bundle', None
    return None, 'no step in job %r runs scan_report.py' % JOB


def materialise_bundle(dest):
    import inline_normalizer as gen
    for canon, _t, _g, d in gen.SCRIPTS:
        io.open(os.path.join(dest, os.path.basename(d)), 'wb').write(gen.materialised(canon))
    return os.path.join(dest, 'scan_report.py')


def export_commit(dest):
    """The whole tracked tree at HEAD plus the working tree's tracked changes: what `$/` delivers."""
    files = subprocess.run(['git', '-C', ROOT, 'ls-files', '-z'], capture_output=True,
                           check=True).stdout.split(b'\0')
    for f in files:
        if not f:
            continue
        rel = f.decode('utf-8')
        src = os.path.join(ROOT, rel)
        if not os.path.isfile(src):
            continue
        out = os.path.join(dest, rel)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        shutil.copyfile(src, out)


def main():
    try:
        import yaml
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    doc = yaml.safe_load(io.open(WF, encoding='utf-8'))
    where, detail = locate(doc)
    if where is None:
        print('UNKNOWN: %s.' % detail)
        return 2

    work = tempfile.mkdtemp(prefix='report-as-shipped-')
    try:
        if where == 'bundle':
            reporter = materialise_bundle(work)
            print('report job runs the reporter from the BUNDLE (/tmp); materialised %d file(s)'
                  % len(os.listdir(work)))
        else:
            export_commit(work)
            reporter = os.path.join(work, 'scripts', 'scan_report.py')
            print('report job runs the reporter through composite %r; exported the tracked tree'
                  % detail)
        p = subprocess.run([sys.executable, '-E', '-s', reporter, '--self-test'],
                           capture_output=True, text=True, cwd=work)
        tail = ((p.stdout or '') + (p.stderr or '')).strip().splitlines()[-6:]
        for line in tail:
            print('    %s' % line)
        if p.returncode != 0:
            print('FAIL: the reporter exits %d where the report job runs it. Every run of the '
                  'report job fails the same way.' % p.returncode)
            return 1
        print('PASS: the reporter starts and passes its own self-test where it is shipped.')
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
