#!/usr/bin/env python3
"""Run the deps-scan and image-scan Trivy configurations EXACTLY as trivy-action runs them, and
prove the blocking threshold is a separate decision from what the SARIF reports (ledger L17).

WHY THIS EXISTS

    deps-scan's comment says "detection is never what gets turned off". The ledger read the
    `severity:` input as a filter that dropped sub-threshold findings from the SARIF. MEASURED
    (READ, from the pinned action's own source, aquasecurity/trivy-action@v0.36.0 entrypoint.sh):
    the truth is the inverse defect --

        if TRIVY_FORMAT = sarif and limit-severities-for-sarif != true:  unset TRIVY_SEVERITY

    so for a SARIF the action IGNORES `severity:` entirely: every severity is reported (good) AND
    `exit-code` fires on every severity (bad). `fail_on_severity` therefore decided nothing: a
    single LOW finding failed the build, and narrowing the threshold to CRITICAL changed nothing.
    tests/prove_image_scan_enforces.py modelled `severity:` as `--severity`, which is not what the
    action runs, so it could not see this.

    The fix separates the two decisions: Trivy reports EVERY severity with exit 0, and a count step
    applies `fail_on_severity` to the SARIF (the severity name sits in each rule's tags -- measured
    on trivy 0.71.2: `level` is `error` for HIGH and CRITICAL alike, so it cannot carry a
    CRITICAL-only threshold), then an enforce step blocks unless advisory_mode is on.

HOW THE ACTION IS REPRODUCED
    The action turns each `with:` key into a TRIVY_* environment variable and runs
    `trivy <scan-type> <ref>`; this does the same, applies the SARIF rule above, and runs the real
    Trivy. The image is a docker-save archive (`TRIVY_INPUT`), as in prove_image_scan_enforces.

SCENARIOS (per job: deps-scan over requirements.txt, image-scan over an Alpine 3.10 archive)
    default_threshold   CRITICAL,HIGH, advisory off -> SARIF keeps sub-threshold findings,
                                                       count >= 1, the job PASSES and hands the gate
                                                       findings_state=FINDINGS (lane L-S, O-24: the
                                                       gate is the single enforcement point)
    critical_only       CRITICAL (deps: no CRITICAL present) -> sub-threshold findings kept,
                                                       count 0, the job PASSES, nothing handed
    advisory            CRITICAL,HIGH, advisory on  -> findings kept, the job PASSES, nothing handed
    clean               nothing vulnerable          -> count 0, the job PASSES
    no_report           Trivy wrote nothing         -> COLLECTION_FAILED, the job FAILS

EXIT
    0  every scenario decided as it must
    1  a scenario decided wrongly
    2  could not be checked (no bash, no trivy, no database) -- UNKNOWN, never PASS
"""
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _scan_step_harness as h  # noqa: E402
import prove_bootstrap_failure as pbf  # noqa: E402
import prove_image_scan_enforces as pis  # noqa: E402

ENV = {'scan-type': None, 'scan-ref': None, 'image-ref': None, 'scanners': 'TRIVY_SCANNERS',
       'severity': 'TRIVY_SEVERITY', 'exit-code': 'TRIVY_EXIT_CODE', 'format': 'TRIVY_FORMAT',
       'output': 'TRIVY_OUTPUT', 'ignore-unfixed': 'TRIVY_IGNORE_UNFIXED',
       'limit-severities-for-sarif': None, 'timeout': 'TRIVY_TIMEOUT'}
JOBS = {
    'deps-scan': {'producer_output': 'trivy-deps.sarif',
                  'count': 'Trivy (deps) — count findings at the blocking severities',
                  'enforce': 'Trivy (deps) — enforce', 'count_id': 'trivy_deps_count'},
    'image-scan': {'producer_output': 'trivy-image.sarif',
                   'count': 'Trivy image — count findings at the blocking severities',
                   'enforce': 'Trivy image — enforce', 'count_id': 'trivy_image_count'},
}


def resolve(value, inputs):
    """The expression shapes these steps use: plain `inputs.x`, and `inputs.a && 'X' || 'Y'`."""
    v = str(value).strip()
    m = re.fullmatch(r'\$\{\{\s*(.*?)\s*\}\}', v)
    if not m:
        return v
    inner = m.group(1)
    mm = re.fullmatch(r"inputs\.(\w+)\s*&&\s*'([^']*)'\s*\|\|\s*'([^']*)'", inner)
    if mm:
        return mm.group(2) if inputs.get(mm.group(1)) == 'true' else mm.group(3)
    mm = re.fullmatch(r'inputs\.(\w+)', inner)
    if mm:
        return inputs[mm.group(1)]
    raise ValueError('unmodelled expression %r' % v)


def run_action(step, inputs, target, ws):
    """Run trivy as trivy-action@v0.36.0 does for this `with:` block. -> (rc, stderr)."""
    w = step.get('with') or {}
    unknown = [k for k in w if k not in ENV]
    if unknown:
        raise ValueError('cannot translate trivy-action input(s) %s' % unknown)
    env = dict(os.environ)
    for k, var in ENV.items():
        if var and k in w:
            env[var] = resolve(w[k], inputs)
    env['TRIVY_OUTPUT'] = os.path.join(ws, resolve(w['output'], inputs))
    if env.get('TRIVY_FORMAT') == 'sarif' and \
            str(resolve(w.get('limit-severities-for-sarif', ''), inputs)).lower() != 'true':
        env.pop('TRIVY_SEVERITY', None)            # the action's own SARIF rule, verbatim
    st = str(w.get('scan-type', 'image'))
    cmd = ['trivy', st, '--quiet']
    if st == 'image':
        cmd += ['--input', target]
    else:
        cmd += [target]
    p = subprocess.run(cmd, cwd=ws, env=env, capture_output=True, text=True, encoding='utf-8',
                       errors='replace')
    return p.returncode, p.stderr or ''


def sarif_levels(path):
    doc = json.load(open(path, encoding='utf-8'))
    out = []
    for run_ in doc.get('runs', []):
        rules = {r['id']: r for r in run_.get('tool', {}).get('driver', {}).get('rules', [])}
        for r in run_.get('results', []):
            tags = rules.get(r.get('ruleId'), {}).get('properties', {}).get('tags', [])
            out += [t for t in tags if t in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')]
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
    bad = []
    sb = h.Sandbox('trivy-threshold-').with_bundle()
    try:
        if not h.have(bash, 'trivy', ''):
            print('UNKNOWN: trivy is required.')
            return 2
        alpine = os.path.join(sb.root, 'alpine.tar')
        pis.image(alpine, {'/etc/alpine-release': '3.10.9\n',
                           '/etc/os-release': 'NAME="Alpine Linux"\nID=alpine\nVERSION_ID=3.10.9\n',
                           '/lib/apk/db/installed': pis.APK_INSTALLED}, 'probe/vuln:1')
        clean_img = os.path.join(sb.root, 'clean.tar')
        pis.image(clean_img, {'/app/hello.txt': 'hello\n'}, 'probe/clean:1')
        for job, cfg in JOBS.items():
            steps = h.steps_by_name(job)
            prod = [s for s in h.job(job).get('steps', []) if 'trivy-action' in str(s.get('uses'))
                    and str((s.get('with') or {}).get('output')) == cfg['producer_output']]
            missing = [n for n in (cfg['count'], cfg['enforce']) if n not in steps]
            if not prod:
                print('UNKNOWN: %s has no trivy-action step writing %s' % (job, cfg['producer_output']))
                return 2
            # 'handed': the job SUCCEEDS and hands the count to the security gate as
            # findings_state=FINDINGS (lane L-S, O-24: the gate is the single enforcement point).
            scen = [('default_threshold', 'CRITICAL,HIGH', 'false', 'vuln', 'handed'),
                    ('critical_only', 'CRITICAL', 'false', 'vuln', 'pass'),
                    ('advisory', 'CRITICAL,HIGH', 'true', 'vuln', 'pass'),
                    ('clean', 'CRITICAL,HIGH', 'false', 'clean', 'pass'),
                    ('no_report', 'CRITICAL,HIGH', 'false', None, 'fail')]
            for name, thr, adv, tree, expect in scen:
                inputs = {'fail_on_severity': thr, 'advisory_mode': adv, 'paths': '.',
                          'image_ref': 'probe/vuln:1'}
                files = {}
                if job == 'deps-scan' and tree == 'vuln':
                    files = {'requirements.txt': 'urllib3==1.24.1\nrequests==2.19.1\n'}
                elif job == 'deps-scan' and tree == 'clean':
                    files = {'README.md': 'nothing to resolve\n'}
                ws = sb.workspace('%s-%s' % (job, name), files)
                trc = 0
                if tree is not None:
                    target = '.' if job == 'deps-scan' else (alpine if tree == 'vuln' else clean_img)
                    trc, err = run_action(prod[0], inputs, target, ws)
                    if 'failed to download' in err.lower() or 'db error' in err.lower():
                        print('UNKNOWN: Trivy could not obtain its vulnerability database.')
                        return 2
                sarif = os.path.join(ws, cfg['producer_output'])
                sev = sarif_levels(sarif) if os.path.isfile(sarif) else []
                vals = {'inputs.%s' % k: v for k, v in inputs.items()}
                erc, coll, n, handed = trc, '', '', ''
                if not missing:
                    crc, clog, cout, unk = sb.run(bash, steps[cfg['count']], vals, ws)
                    if unk:
                        bad.append('%s/%s: count step reads unmodelled %s' % (job, name, unk))
                    vals.update({'steps.%s.outputs.%s' % (cfg['count_id'], k): cout.get(k, '')
                                 for k in ('count', 'collection')})
                    erc2, elog, eout, unk = sb.run(bash, steps[cfg['enforce']], vals, ws)
                    coll, n = cout.get('collection', ''), cout.get('count', '')
                    handed = eout.get('findings_state', '')
                    failed = trc != 0 or erc2 != 0
                else:
                    failed = trc != 0
                below = [s for s in sev if s not in thr.split(',')]
                print('  %-10s %-17s trivy=%d severities=%s count=%s collection=%s job %s%s'
                      % (job, name, trc, ','.join('%s:%d' % (k, sev.count(k))
                                                  for k in sorted(set(sev))) or '-',
                         n or '-', coll or '-', 'FAILS' if failed else 'passes',
                         ', hands the gate %s' % handed if handed else ''))
                if tree == 'vuln' and not below:
                    bad.append('%s/%s: no finding below %s survived in the SARIF -- the reporting '
                               'filter dropped evidence' % (job, name, thr))
                if expect == 'fail' and not failed:
                    bad.append('%s/%s: the job would PASS' % (job, name))
                if expect in ('pass', 'handed') and failed:
                    bad.append('%s/%s: the job would FAIL -- %s' % (job, name, (
                        'the threshold %s was not honoured: Trivy blocked on a severity outside it'
                        % thr) if name == 'critical_only' else
                        'findings go to the gate, never a failed job'))
                if expect == 'handed' and handed != 'FINDINGS':
                    bad.append('%s/%s: nothing handed to the gate (findings_state=%r) -- findings '
                               'at %s with advisory off must reach it' % (job, name, handed, thr))
                if expect == 'pass' and handed:
                    bad.append('%s/%s: findings_state=%r -- %s' % (job, name, handed, (
                        'the threshold %s was not honoured' % thr) if name == 'critical_only'
                        else 'nothing is enforced here'))
            if missing:
                bad.append('%s: no step(s) %s -- the blocking threshold is whatever trivy-action '
                           'does with `severity:` for a SARIF, which is to ignore it' % (job, missing))
    finally:
        sb.close()
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: Trivy reports every severity in both jobs; fail_on_severity alone decides what is '
          'handed to the gate (a narrower threshold hands nothing it excludes, advisory hands '
          'nothing, no report fails the job).')
    return 0


if __name__ == '__main__':
    sys.exit(main())
