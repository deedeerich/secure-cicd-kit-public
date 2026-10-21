#!/usr/bin/env python3
"""Run the sbom job's licence step, as shipped, over REAL syft output, and prove the denial
reaches the gate (ledger L16).

WHY THIS EXISTS

    sbom_licenses.py's docstring says the denial verdict "belongs to the gate". The job ran it
    `|| true` without `--out`, so the verdict was printed and went nowhere: a denied licence could
    never block. Three further defects, all measured here on syft's real output:
      * DOUBLE COUNTING. The job passes BOTH the CycloneDX and the SPDX document; every component
        was counted twice, and SPDX's document-root entry (".") was counted as an unlicensed
        component.
      * SUBSTRING DENY. `GPL-3.0` matched `LGPL-3.0-only` -- a permissive-by-design LGPL library
        reported as a GPL denial. The match must be per licence TOKEN: `GPL-3.0` denies
        `GPL-3.0-only` and `GPL-3.0-or-later`, never `LGPL-3.0-only`.
      * NO SBOM WAS EXIT 0. "no readable SBOM supplied" returned success, so a syft failure read
        as an empty licence set.

MEASURED, NOT ASSUMED (syft 1.52.0, an npm lockfile, 2026-10-14)
    CycloneDX: `{"license": {"id": "GPL-3.0-or-later"}}`, `{"expression": "MIT OR GPL-3.0-only"}`,
    no `licenses` for an undeclared package. SPDX: the same in `licenseDeclared` with
    `licenseConcluded` NOASSERTION, plus a `.` package the document DESCRIBES (the scan root).

SCENARIOS (real syft SBOM of: gpl-lib GPL-3.0-or-later, lgpl-lib LGPL-3.0-only, mit-lib MIT,
           expr-lib "MIT OR GPL-3.0-only", nolic-lib none, and the root package)
    deny_gpl        license_deny=GPL-3.0 -> FINDINGS, 2 denied (gpl-lib, expr-lib), lgpl NOT
                    denied, 6 components (not 13), verdict file written
    no_policy       license_deny empty   -> NOT_APPLICABLE, nothing denied
    no_sbom         syft wrote nothing   -> COLLECTION_FAILED, the step exits non-zero

EXIT
    0  every scenario decided as it must
    1  a scenario decided wrongly
    2  could not be checked (no bash, no syft) -- UNKNOWN, never PASS
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _scan_step_harness as h  # noqa: E402
import prove_bootstrap_failure as pbf  # noqa: E402

JOB, STEP = 'sbom', 'Dependency licences'
LIBS = [('gpl-lib', 'GPL-3.0-or-later'), ('lgpl-lib', 'LGPL-3.0-only'), ('mit-lib', 'MIT'),
        ('nolic-lib', None), ('expr-lib', '(MIT OR GPL-3.0-only)')]


def lockfile():
    pk = {'': {'name': 'probe', 'version': '1.0.0'}}
    for n, lic in LIBS:
        e = {'version': '1.0.0',
             'resolved': 'https://registry.npmjs.org/%s/-/%s-1.0.0.tgz' % (n, n)}
        if lic:
            e['license'] = lic
        pk['node_modules/' + n] = e
    return json.dumps({'name': 'probe', 'version': '1.0.0', 'lockfileVersion': 3,
                       'requires': True, 'packages': pk})


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
    if STEP not in steps:
        print('UNKNOWN: no step %r in job %r.' % (STEP, JOB))
        return 2
    outs = h.job(JOB).get('outputs') or {}
    bad = []
    for k in ('licence_state', 'licence_denied'):
        if k not in outs:
            bad.append('job %r publishes no `%s` output -- the gate cannot read the verdict'
                       % (JOB, k))
    sb = h.Sandbox('sbom-licence-').with_bundle()
    try:
        if not h.have(bash, 'syft', h.path_prefix(sb.shim)):
            print('UNKNOWN: syft is required to produce a real SBOM.')
            return 2
        src = sb.workspace('src', {'package-lock.json': lockfile()})
        p = subprocess.run([bash, '-c', 'syft dir:. -q -o cyclonedx-json=sbom.cyclonedx.json '
                                        '-o spdx-json=sbom.spdx.json'], cwd=src,
                           env=dict(os.environ, PATH=h.path_prefix(sb.shim) + os.pathsep
                                    + os.environ['PATH']), capture_output=True, text=True)
        if p.returncode != 0:
            print('UNKNOWN: syft failed (exit %d): %s' % (p.returncode, p.stderr[-300:]))
            return 2
        sboms = {f: open(os.path.join(src, f), encoding='utf-8').read()
                 for f in ('sbom.cyclonedx.json', 'sbom.spdx.json')}
        scenarios = [('deny_gpl', sboms, 'GPL-3.0'), ('no_policy', sboms, ''),
                     ('no_sbom', {}, 'GPL-3.0')]
        for name, files, deny in scenarios:
            ws = sb.workspace(name, files)
            rc, log, out, unk = sb.run(bash, steps[STEP], {'inputs.license_deny': deny}, ws)
            if unk:
                bad.append('%s: step reads unmodelled %s' % (name, unk))
            st, n = out.get('licence_state', ''), out.get('licence_denied', '')
            verdict = os.path.join(ws, 'licences.json')
            v = json.load(open(verdict, encoding='utf-8')) if os.path.isfile(verdict) else None
            comps = v.get('components') if v else None
            denied = sorted(d['name'] for d in (v or {}).get('denied', []))
            print('  %-10s exit=%d licence_state=%-18s denied=%-2s components=%s %s'
                  % (name, rc, st or '-', n or '-', comps, denied))
            if name == 'deny_gpl':
                if st != 'FINDINGS' or n != '2':
                    bad.append('deny_gpl: licence_state=%r denied=%r, expected FINDINGS / 2'
                               % (st, n))
                if v is None:
                    bad.append('deny_gpl: no verdict file (licences.json) -- `--out` unused')
                else:
                    if denied != ['expr-lib', 'gpl-lib']:
                        bad.append('deny_gpl: denied %s, expected expr-lib and gpl-lib -- '
                                   'LGPL must not match a GPL entry' % denied)
                    if comps != 6:
                        bad.append('deny_gpl: %s components, expected 6 -- CycloneDX and SPDX '
                                   'describe the same packages once' % comps)
                if rc != 0:
                    bad.append('deny_gpl: the step exited %d; the verdict belongs to the gate'
                               % rc)
            elif name == 'no_policy':
                if st != 'NOT_APPLICABLE' or n not in ('0', ''):
                    bad.append('no_policy: licence_state=%r denied=%r, expected NOT_APPLICABLE'
                               % (st, n))
            elif name == 'no_sbom':
                if st != 'COLLECTION_FAILED':
                    bad.append('no_sbom: licence_state=%r, expected COLLECTION_FAILED' % st)
                if rc == 0:
                    bad.append('no_sbom: the step exited 0 with no SBOM -- a syft failure would '
                               'read as an empty licence set')
    finally:
        sb.close()
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: the shipped licence step dedupes CycloneDX and SPDX, denies by licence token, '
          'writes the verdict, publishes it to the gate, and fails when there is no SBOM.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
