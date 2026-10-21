#!/usr/bin/env python3
"""The weekly scanner validation can fail: every probe is expected, and a broken one fails the run.

WHY THIS EXISTS (completion ledger L76; the three items W4K-116 left open)

    validate-scanners.yml is the kit's only behavioural check of the scanners themselves. After
    W4K-116 fixed the versions it probed and its negative control, three things still kept it from
    ever going red:

      matrix     the probe matrix job was `continue-on-error: true`, so a probe that exited 1 (a
                 report that was never produced, a parse failure) still left the run green
      verdict    the capability-matrix step rendered whatever result files arrived, swallowed any it
                 could not parse, and could not exit non-zero: a probe that died before writing a
                 result simply vanished from the table, and a probe that ran and detected nothing
                 was a red cross in a green job
      container  the flagship's sast-semgrep job runs the semgrep/semgrep:1.90.0 CONTAINER, and no
                 probe ran that image -- the weekly green said nothing about the scanner that job
                 actually uses

WHAT IT PROVES
    M1  the scanners job is not continue-on-error, and keeps fail-fast off so one leg cannot hide
        another
    M2  a `semgrep-container` probe runs the exact image the flagship's sast-semgrep job pins
    M3  the matrix step's roster (EXPECTED) equals the probe matrix's ids
    M4  the matrix step itself, run as shipped against seeded probe results:
          all present and proven                         -> rc 0
          a probe's result file absent                   -> rc 1 (UNKNOWN, named)
          a result file that does not parse              -> rc 1
          a probe that executed and detected nothing     -> rc 1
          the accepted, dated depcheck gap, unexpired    -> rc 0 and reported as accepted

EXIT  0 all hold   1 any does not   2 could not be checked
"""
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
VALIDATE = os.path.join(ROOT, '.github', 'workflows', 'validate-scanners.yml')
FLAGSHIP = os.path.join(ROOT, '.github', 'workflows', 'reusable-security.yml')
STEP = 'Render matrix and name what is MISSING'


def render_script(doc):
    job = (doc.get('jobs') or {}).get('capability-matrix') or {}
    for s in job.get('steps') or []:
        if s.get('name') == STEP:
            body = s.get('run') or ''
            m = re.search(r"python - <<'PY'\n(.*?)\nPY\s*$", body, re.S)
            return m.group(1) if m else None
    return None


def run_render(script, results, work):
    probes = os.path.join(work, 'probes')
    os.makedirs(probes)
    for pid, data in results.items():
        with open(os.path.join(probes, pid + '.json'), 'w', encoding='utf-8') as fh:
            fh.write(data if isinstance(data, str) else json.dumps(data))
    summary = os.path.join(work, 'summary.md')
    open(summary, 'w').close()
    p = subprocess.run([sys.executable, '-c', script], cwd=work, capture_output=True, text=True,
                       encoding='utf-8', errors='replace',
                       env=dict(os.environ, GITHUB_STEP_SUMMARY=summary, PYTHONUTF8='1'))
    return p.returncode, p.stdout + p.stderr


def main():
    try:
        import yaml
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    bad = []
    doc = yaml.safe_load(io.open(VALIDATE, encoding='utf-8'))
    job = (doc.get('jobs') or {}).get('scanners') or {}
    ids = [p.get('id') for p in (((job.get('strategy') or {}).get('matrix') or {}).get('probe') or [])]
    print('  M1 scanners continue-on-error=%r fail-fast=%r'
          % (job.get('continue-on-error'), (job.get('strategy') or {}).get('fail-fast')))
    if job.get('continue-on-error'):
        bad.append('M1 the probe matrix is continue-on-error: a probe that fails leaves the run green')
    if (job.get('strategy') or {}).get('fail-fast') is not False:
        bad.append('M1 the probe matrix must keep fail-fast off, so one leg cannot hide another')

    flagship = io.open(FLAGSHIP, encoding='utf-8').read()
    images = sorted(set(re.findall(r'image:\s*(semgrep/semgrep:[0-9.]+)', flagship)))
    probe_body = io.open(VALIDATE, encoding='utf-8').read()
    print('  M2 flagship semgrep container(s) %s; probe ids %s' % (images, ids))
    if 'semgrep-container' not in ids:
        bad.append('M2 no semgrep-container probe: the image the flagship runs is never probed')
    for img in images:
        if not re.search(r'docker run[^\n]*%s' % re.escape(img), probe_body):
            bad.append('M2 the flagship runs %s and no probe runs that image' % img)

    script = render_script(doc)
    if script is None:
        bad.append('M3 no python heredoc in the %r step' % STEP)
    else:
        m = re.search(r'EXPECTED\s*=\s*\[(.*?)\]', script, re.S)
        roster = re.findall(r'"([a-z0-9-]+)"', m.group(1)) if m else []
        print('  M3 matrix roster %s' % roster)
        if sorted(roster) != sorted(ids):
            bad.append('M3 the matrix roster %s is not the probe matrix %s' % (roster, ids))
        good = {pid: {'id': pid, 'exec': 'ok', 'detect': 'ok', 'artifact': 'ok', 'note': 'seeded'}
                for pid in ids}
        cases = [
            ('all proven', dict(good), 0, None),
            ('a result file absent', {k: v for k, v in good.items() if k != 'gosec'}, 1, 'gosec'),
            ('a result file unparseable', dict(good, osv='{"id": "osv", "exec": '), 1, 'osv'),
            ('executed, detected nothing', dict(good, trivy=dict(good['trivy'], detect='fail')),
             1, 'trivy'),
            ('accepted depcheck gap', dict(good, depcheck=dict(good.get('depcheck', {}),
                                                               detect='fail', artifact='fail')),
             0, 'accepted'),
        ]
        work = tempfile.mkdtemp(prefix='vs-matrix-')
        try:
            for i, (label, results, want, named) in enumerate(cases):
                rc, out = run_render(script, results, os.path.join(work, str(i)))
                ok = rc == want and (named is None or named in out)
                print('  M4 %-30s rc=%s %s' % (label, rc, 'ok' if ok else 'WRONG'))
                if not ok:
                    bad.append('M4 %s: rc=%s (want %s)%s' % (label, rc, want,
                               '' if named is None or named in out else ', %r not named' % named))
        finally:
            shutil.rmtree(work, ignore_errors=True)
    for b in bad:
        print(('FAIL ' + b).encode('ascii', 'replace').decode('ascii'))
    if bad:
        return 1
    print('PASS: the probe matrix can fail, the shipped semgrep container is probed, and the matrix')
    print('      step fails on an absent, unparseable or undetecting probe -- except a dated acceptance.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
