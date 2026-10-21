#!/usr/bin/env python3
"""The NVD workflow ships a CVSS gate that can block: `fail_on_cvss` defaults to 9.0 (owner ruling O-12).

WHY THIS EXISTS (completion ledger S-section-4.1, owner decision O-12)

    `reusable-nvd-cve.yml` shipped `fail_on_cvss: 11`. CVSS maxes at 10, so the default could never
    fail anything: the Dependency-Check gate was decorative at an assurance boundary, and the kit's
    own caller and starter template both passed 11 explicitly. The owner ruled (recorded
    2026-10-16/21): the shipped default is 9.0 until the rung ladder derives it.

    A decimal default meets shell that compared with `-le`: `[ 9.0 -le 10 ]` is an ERROR, not
    false, and under `2>/dev/null` the error read as "not at or below 10" -- so a 9.0 threshold would
    have been reported `ALLOWED` (nothing can block) and the posture record would have called the
    shipped default a weakening. Each comparison is now numeric.

WHAT IT PROVES
    N1  the reusable's input default is 9.0, and no kit caller or template sets fail_on_cvss above
        10 (the old value, 11, fails this)
    N2  the summary step, run as shipped: 9.0 and 9 give enforcement_state BLOCKED and no
        "BLOCKED NOTHING" banner; CONTROL 11 gives ALLOWED and the banner
    N3  the posture step, run as shipped: the fail_on_cvss row is WEAKENING_AT_BASELINE at 9.0 and
        at 9, and WEAKENING_IN_FORCE at 9.5 and 11 (a threshold above the shipped one softens it)

EXIT  0 all hold   1 any does not   2 could not be checked
"""
import glob
import io
import json
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import _step_harness as H  # noqa: E402

WF = '.github/workflows/reusable-nvd-cve.yml'
JOB = 'nvd-cve-scan'
SHIPPED = 9.0


def static(bad):
    import yaml
    doc = yaml.safe_load(io.open(os.path.join(ROOT, WF), encoding='utf-8'))
    on = doc.get(True) or doc.get('on')
    spec = on['workflow_call']['inputs']['fail_on_cvss']
    print('  N1 reusable default %r (type %s)' % (spec.get('default'), spec.get('type')))
    if spec.get('default') != SHIPPED:
        bad.append('N1 fail_on_cvss defaults to %r; the shipped default is %r (O-12)'
                   % (spec.get('default'), SHIPPED))
    callers = sorted(glob.glob(os.path.join(ROOT, '.github', 'workflows', '*.yml'))
                     + glob.glob(os.path.join(ROOT, 'templates', '*.yml')))
    for p in callers:
        text = io.open(p, encoding='utf-8').read()
        for m in re.finditer(r'^\s*fail_on_cvss:\s*([0-9.]+)', text, re.M):
            v = float(m.group(1))
            rel = os.path.relpath(p, ROOT).replace('\\', '/')
            print('  N1 %s sets fail_on_cvss %s' % (rel, m.group(1)))
            if v > 10:
                bad.append('N1 %s sets fail_on_cvss %s, which no CVSS score can reach' % (rel, v))


BASE = {'inputs.enable_trivy': 'true', 'inputs.enable_dependency_check': 'true',
        'inputs.scan_dockerfiles': 'true', 'inputs.trivy_fail_severities': '',
        'inputs.scan_paths': '.', 'inputs.trivy_severities': 'CRITICAL,HIGH,MEDIUM',
        'inputs.sbom_path': '', 'inputs.image_ref': '', 'inputs.weakening_reason': '',
        'inputs.weakening_authority': '', 'inputs.weakening_exception_ref': '',
        'inputs.weakening_expires': '', 'steps.trivy_fs.outcome': 'success',
        'steps.dc_run.outcome': 'success', 'steps.dockerfile.outcome': 'success',
        'job.status': 'success'}


def sarif(n):
    return json.dumps({'runs': [{'results': [{'ruleId': 'CVE-1-%d' % i} for i in range(n)]}]})


def workspace(tmp, name):
    ws = os.path.join(tmp, name)
    d = os.path.join(ws, 'nvd-scan-results', 'dependency-check')
    os.makedirs(d)
    io.open(os.path.join(ws, 'nvd-scan-results', 'trivy-nvd.sarif'), 'w').write(sarif(0))
    io.open(os.path.join(d, 'dependency-check-report.sarif'), 'w').write(sarif(0))
    io.open(os.path.join(ws, 'nvd-scan-results', 'trivy-dockerfile.txt'), 'w').write('Tests: 1\n')
    return ws


def dynamic(bad, bash):
    summ = H.step(WF, JOB, 'summary')
    post = H.step(WF, JOB, 'posture')
    tmp = tempfile.mkdtemp(prefix='nvd-cvss-')
    try:
        for value, want_enf in (('9.0', 'BLOCKED'), ('9', 'BLOCKED'), ('11', 'ALLOWED')):
            ws = workspace(tmp, 'summary-' + value)
            ctx = dict(BASE, **{'inputs.fail_on_cvss': value})
            r = H.run(bash, summ, ctx, ws)
            enf = r['outputs'].get('enforcement_state')
            text = r.get('summary', '')
            banner = 'BLOCKED NOTHING' in text
            print('  N2 fail_on_cvss=%-4s enforcement_state=%s banner=%s' % (value, enf, banner))
            if enf != want_enf:
                bad.append('N2 fail_on_cvss=%s: enforcement_state %r, want %s' % (value, enf, want_enf))
            if (want_enf == 'BLOCKED') == banner:
                bad.append('N2 fail_on_cvss=%s: the "blocked nothing" banner is %s'
                           % (value, 'shown' if banner else 'missing'))
        for value, want in (('9.0', 'WEAKENING_AT_BASELINE'), ('9', 'WEAKENING_AT_BASELINE'),
                            ('9.5', 'WEAKENING_IN_FORCE'), ('11', 'WEAKENING_IN_FORCE')):
            ws = workspace(tmp, 'posture-' + value)
            ctx = dict(BASE, **{'inputs.fail_on_cvss': value})
            s = H.run(bash, summ, ctx, ws)
            for k, v in s['outputs'].items():
                ctx['steps.summary.outputs.%s' % k] = v
            p = H.run(bash, post, ctx, ws)
            try:
                rows = json.loads(p['outputs'].get('weakenings') or '[]')
            except ValueError:
                rows = []
            row = next((x for x in rows if x.get('input') == 'fail_on_cvss'), {})
            print('  N3 fail_on_cvss=%-4s row state=%s baseline=%s'
                  % (value, row.get('state'), row.get('baseline')))
            if row.get('state') != want:
                bad.append('N3 fail_on_cvss=%s: posture row %r, want %s' % (value, row.get('state'), want))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    bash, why = H.usable_bash()
    if not bash or not shutil.which('jq'):
        print('UNKNOWN: bash (%s) and jq are needed to run the steps.' % (bash or why))
        return 2
    bad = []
    static(bad)
    dynamic(bad, bash)
    for b in bad:
        print('FAIL ' + b)
    if bad:
        return 1
    print('PASS: fail_on_cvss ships at 9.0 and blocks at 9.0 and 9; 11 remains reachable only as a')
    print('      recorded weakening, and a decimal threshold is compared as a number, not an error.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
