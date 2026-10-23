#!/usr/bin/env python3
"""Run the NVD workflow's own Trivy steps, as shipped, against a seeded CVE and a clean tree.

WHY THIS EXISTS (validation deferral `nvd-trivy`: "trivy path in the NVD workflow detects a seeded CVE")

    reusable-nvd-cve.yml has two trivy-action steps: a reporting pass (`Trivy filesystem scan
    (SARIF)`, exit-code 0) and an explicit gate (`Trivy gate`, exit-code 1, armed only when
    trivy_fail_severities is set). Neither has run on the current code. This probe reads each step's
    `with:` block AS SHIPPED, translates every key to the Trivy CLI flag trivy-action passes, and runs
    the REAL Trivy against a workspace built here. An input key the probe cannot translate FAILS it
    rather than being dropped. The Summary step is then run, as shipped, over the SARIF Trivy wrote,
    so the claim reaches the workflow's own assurance_state.

    The seeded tree is generated at run time (a requirements.txt pinning releases with published
    CVEs), so no vulnerable manifest sits in this repository for its own scanners to find.

SCENARIOS
    seeded_report   seeded tree, trivy_fail_severities ''          -> CVE results in the SARIF; the
                    gate step is not armed; Summary says FINDINGS
    seeded_gate     seeded tree, trivy_fail_severities CRITICAL,HIGH -> the gate step FAILS
    clean           a tree with no dependency manifest            -> zero results; gate passes;
                    Summary says PASS

EXIT 0 every scenario decided as it must; 1 one decided wrongly; 2 could not be checked (no trivy,
no vulnerability database) -- UNKNOWN, never PASS.
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _step_harness as H  # noqa: E402
import _trivy_step as ts  # noqa: E402 - the shipped Trivy step read as trivy-action's `with:`

WF = '.github/workflows/reusable-nvd-cve.yml'
JOB = 'nvd-cve-scan'
REPORT, GATE = 'Trivy filesystem scan (SARIF)', 'Trivy gate'
FLAG = {'format': '--format', 'output': '--output', 'severity': '--severity',
        'exit-code': '--exit-code', 'ignore-unfixed': '--ignore-unfixed', 'scanners': '--scanners'}
HANDLED = {'scan-type', 'scan-ref'}
SEEDED = 'Django==2.2.0\nrequests==2.19.0\nurllib3==1.24.1\n'


def translate(step, ctx, ws):
    w = ts.trivy_with(step)
    unknown = sorted(k for k in w if k not in FLAG and k not in HANDLED)
    if unknown:
        raise ValueError('cannot translate trivy-action input(s) %s' % ', '.join(unknown))
    st = H.substitute(w.get('scan-type', 'image'), ctx)[0]
    cmd = ['trivy', st, '--quiet']
    for k, flag in FLAG.items():
        if k in w:
            v = H.substitute(w[k], ctx)[0]
            if k == 'ignore-unfixed':
                if v == 'true':
                    cmd.append(flag)
            else:
                cmd += [flag, v]
    cmd.append(H.substitute(w.get('scan-ref', '.'), ctx)[0])
    return cmd


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    if not shutil.which('trivy') or not shutil.which('jq'):
        print('UNKNOWN: trivy and jq are required to RUN the steps.')
        return 2
    bash, why = H.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s).' % why)
        return 2
    report, gate, summ = (H.step(WF, JOB, k) for k in (REPORT, GATE, 'summary'))
    if not (report and gate and summ):
        print('UNKNOWN: a Trivy step or the Summary step is missing from %s.' % WF)
        return 2
    bad = []
    tmp = tempfile.mkdtemp(prefix='nvd-trivy-probe-')
    try:
        for name, manifest, fail_sev in (('seeded_report', SEEDED, ''),
                                         ('seeded_gate', SEEDED, 'CRITICAL,HIGH'),
                                         ('clean', None, 'CRITICAL,HIGH')):
            ws = os.path.join(tmp, name)
            os.makedirs(os.path.join(ws, 'nvd-scan-results'))
            if manifest:
                io.open(os.path.join(ws, 'requirements.txt'), 'w', newline='\n').write(manifest)
            else:
                io.open(os.path.join(ws, 'README.md'), 'w').write('nothing to depend on\n')
            ctx = {'inputs.trivy_severities': 'CRITICAL,HIGH,MEDIUM',
                   'inputs.trivy_fail_severities': fail_sev, 'inputs.enable_trivy': 'true'}
            try:
                cmd = translate(report, ctx, ws)
            except ValueError as e:
                print('FAIL: %s; refusing to prove a configuration it would silently drop' % e)
                return 1
            p = subprocess.run(cmd, cwd=ws, capture_output=True, text=True, encoding='utf-8',
                               errors='replace', env=dict(os.environ, PYTHONUTF8='1'))
            if 'failed to download' in (p.stderr or '').lower() or 'db error' in (p.stderr or '').lower():
                print('UNKNOWN: Trivy could not obtain its vulnerability database.')
                return 2
            sarif = os.path.join(ws, 'nvd-scan-results', 'trivy-nvd.sarif')
            rules = []
            if os.path.isfile(sarif):
                doc = json.load(io.open(sarif, encoding='utf-8'))
                rules = [r.get('ruleId', '') for run_ in doc.get('runs', [])
                         for r in run_.get('results', [])]
            # The gate step's `if:` -- armed only when trivy_fail_severities is set.
            armed = fail_sev != ''
            grc = None
            if armed:
                g = subprocess.run(translate(gate, ctx, ws), cwd=ws, capture_output=True, text=True,
                                   encoding='utf-8', errors='replace')
                grc = g.returncode
            sctx = {'inputs.enable_trivy': 'true', 'inputs.enable_dependency_check': 'false',
                    'inputs.scan_dockerfiles': 'false', 'inputs.fail_on_cvss': '11',
                    'inputs.trivy_fail_severities': fail_sev, 'inputs.sbom_path': '',
                    'inputs.image_ref': '', 'steps.trivy_fs.outcome':
                        'success' if p.returncode == 0 else 'failure'}
            s = H.run(bash, summ, sctx, ws)
            state = s['outputs'].get('assurance_state')
            cves = [r for r in rules if r.upper().startswith(('CVE-', 'GHSA-'))]
            print('  %-14s report_exit=%d results=%d gate=%s assurance=%s'
                  % (name, p.returncode, len(rules), 'not armed' if grc is None else 'exit %d' % grc,
                     state))
            if p.returncode != 0:
                bad.append('%s: the reporting pass failed (exit %d): %s'
                           % (name, p.returncode, (p.stderr or '')[-300:]))
            if manifest:
                if not cves:
                    bad.append('%s: no CVE result for the seeded dependencies' % name)
                if state != 'FINDINGS':
                    bad.append('%s: Summary assurance_state=%r over a SARIF with %d results'
                               % (name, state, len(rules)))
                if armed and grc == 0:
                    bad.append('%s: the gate PASSED seeded HIGH/CRITICAL CVEs' % name)
            else:
                if rules:
                    bad.append('%s: the clean tree produced results %s' % (name, rules))
                if grc not in (0, None):
                    bad.append('%s: the gate failed a clean tree (exit %s)' % (name, grc))
                if state != 'PASS':
                    bad.append('%s: Summary assurance_state=%r for a clean complete scan'
                               % (name, state))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: the NVD workflow\'s shipped Trivy steps report seeded CVEs into the SARIF the '
          'Summary reads (FINDINGS), the armed gate fails on them, and a clean tree passes (PASS).')
    return 0


if __name__ == '__main__':
    sys.exit(main())
