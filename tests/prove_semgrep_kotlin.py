#!/usr/bin/env python3
"""Kotlin is SCANNED by the sast-semgrep job whatever the caller's rulesets, and a Kotlin scan that
examined nothing never reads as clean (lane L-SCAN-B, KDEC-026).

WHY THIS EXISTS

    Discovery called `.kt` a COVERAGE_GAP. Measured 2026-10-23 on the job's own image (1.178.0):
    the shipped default (p/default p/owasp-top-ten p/xss) happens to load 18 Kotlin rules and finds
    the planted MD5 and ECB use -- INCIDENTAL coverage, unwitnessed, and gone the moment a caller
    narrows `semgrep_config` (p/python alone loads no Kotlin rule). So, exactly as for PHP (lane
    L-PHP): p/kotlin is a FLOOR added whenever discovery finds Kotlin (or could not say), and the
    job refuses a Kotlin scan that examined no Kotlin file or loaded no Kotlin rule.

WHAT IT PROVES (the job's scan step, extracted AS SHIPPED, run with the real Semgrep)
    K1  NARROWED (p/python), Kotlin discovered -> the planted MD5 and ECB rules fire on the .kt file
        (the PLATFORM_SIGNALS semgrep-kotlin rows)
    K2  the shipped default, Kotlin discovered -> the same (control)
    K3  HOLLOW: Kotlin discovered, the only .kt file over Semgrep's size limit -> exit 1,
        COLLECTION_FAILED naming Kotlin -- never a count of zero
    K4  CONTROL: kotlin=false, Python only -> p/kotlin is not requested and the witness is silent
    FAILS ON c7e1ea9 at K1 (no floor: a narrowed config finds neither) and K3 (no witness).

EXIT  0 all hold   1 any does not   2 could not be checked (no bash, semgrep, jq, registry)
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _scan_step_harness as h  # noqa: E402
import prove_bootstrap_failure as pbf  # noqa: E402
import _platform_fixtures as pf  # noqa: E402

JOB, SCAN = 'sast-semgrep', 'Semgrep scan'
KT = 'app/src/main/java/com/example/fixture/MainActivity.kt'
PY_ONLY = {'app/main.py': 'def add(a, b):\n    return a + b\n'}


def rule_hits(sarif):
    doc = json.load(open(sarif, encoding='utf-8'))
    got = {}
    for run_ in doc.get('runs', []):
        for res in run_.get('results', []):
            uri = res['locations'][0]['physicalLocation']['artifactLocation']['uri'].replace('\\', '/')
            got.setdefault(uri, set()).add(res.get('ruleId', ''))
    return got


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
    if SCAN not in steps:
        print('UNKNOWN: no step %r in job %r.' % (SCAN, JOB))
        return 2
    step = steps[SCAN]
    doc = h.load()
    on = doc.get('on', doc.get(True)) or {}
    default_cfg = str(((on.get('workflow_call') or {}).get('inputs') or {}).get('semgrep_config', {}).get('default', ''))
    bad = []
    want = [r for t, p, tool, r in pf.SIGNALS if tool == 'semgrep-kotlin']
    kt_tree = {KT: pf.TREES['android'][KT]}
    sb = h.Sandbox('semgrep-kotlin-').with_bundle()
    try:
        for tool in ('semgrep', 'jq'):
            if not h.have(bash, tool, h.path_prefix(sb.shim)):
                print('UNKNOWN: %s is required to RUN the step.' % tool)
                return 2

        def scan(name, files, config, kotlin):
            ws = sb.workspace(name, files)
            vals = {'inputs.paths': '.', 'inputs.semgrep_config': config,
                    'needs.plan.outputs.php': 'false', 'needs.plan.outputs.kotlin': kotlin,
                    'inputs.soft_fail_sast': 'false', 'inputs.advisory_mode': 'false'}
            rc, log, out, _unk = sb.run(bash, step, vals, ws, env={'SEMGREP_APP_TOKEN': ''})
            if 'Failed to download' in log or 'ConnectionError' in log:
                raise LookupError('semgrep could not fetch its registry rules')
            sarif = os.path.join(ws, 'semgrep.sarif')
            hits = rule_hits(sarif) if os.path.isfile(sarif) else {}
            print('  %-9s config=%-34r kotlin=%-5s rc=%d count=%s collection=%s'
                  % (name, config, kotlin, rc, out.get('count', '-'), out.get('collection', '-')))
            return rc, log, out, hits

        try:
            for label, cfg in (('K1 narrow', 'p/python'), ('K2 default', default_cfg)):
                rc, log, out, hits = scan(label.split()[0], kt_tree, cfg, 'true')
                on_kt = set().union(*[v for k, v in hits.items() if k.endswith(KT)] or [set()])
                miss = [r for r in want if not any(r in x for x in on_kt)]
                if rc != 0 or miss:
                    bad.append('%s: rc %d, planted Kotlin rule(s) not reported on %s: %s\n%s'
                               % (label, rc, KT, miss, log[-400:]))
            big = {'src/Huge.kt': 'fun f() {\n' + '    val a = 1\n' * 120000 + '}\n'}
            rc, log, out, _hits = scan('K3', dict(big, **PY_ONLY), default_cfg, 'true')
            if rc == 0 or out.get('collection') != 'COLLECTION_FAILED' or 'Kotlin' not in log:
                bad.append('K3 a Kotlin scan that examined no Kotlin read as completed (rc %d, %r)'
                           % (rc, out.get('collection')))
            rc, log, out, _hits = scan('K4', PY_ONLY, default_cfg, 'false')
            if rc != 0 or 'p/kotlin' in log.split('target:')[0] or 'Kotlin:' in log:
                bad.append('K4 with no Kotlin the floor or witness fired (rc %d)' % rc)
        except LookupError as e:
            print('UNKNOWN: %s.' % e)
            return 2
    finally:
        sb.close()
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: Kotlin is scanned by sast-semgrep under a narrowed config (the p/kotlin floor), the '
          'planted MD5 and ECB rules fire, and a Kotlin scan that examined nothing is COLLECTION_FAILED.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
