#!/usr/bin/env python3
"""sast-dotnet against a REAL-SHAPED .NET solution, not one synthetic file (lane L-SCAN-B, KDEC-026).

WHY THIS EXISTS (docs/roadmap/FUTURE_WORK.md section 5, ".NET real-repo consumer")

    "None exists in any accessible account. Only the synthetic fixture" -- one .csproj and one .cs
    file at the root. A real solution has a .sln, several projects in subdirectories, project
    references, a web project on the ASP.NET SDK, and a test project; the NuGet audit and the C#
    Semgrep run per discovered root, and nothing had shown they hold on that shape.
    tests/_platform_fixtures.py `dotnet-solution/` is that shape: Shop.sln; src/Shop.Web (ASP.NET
    Core, Newtonsoft.Json 12.0.1 -- GHSA-5crp-9r3c-p9vr, High) referencing src/Shop.Data
    (System.Data.SqlClient 4.8.5 -- GHSA-98g6-xh36-x2p7, High); tests/Shop.Tests; and an API
    controller carrying a SQL injection, a process start from request input and an open redirect.

WHAT IT PROVES (the sast-dotnet composite's steps, extracted AS SHIPPED, run with the host's real
dotnet SDK and Semgrep -- the same steps tests/prove_sast_dotnet_detects.py runs on one file)
    N1  every project and the solution are discovered as roots and restored (none failed)
    N2  the NuGet audit is COMPLETE and reports BOTH planted advisories, each at the line of the
        project file that declares it (repository-relative), and hands FINDINGS to the gate
    N3  Semgrep (C#) reports the planted SQL injection on the controller, and hands FINDINGS
    N4  discovery skips the job when no .sln / .csproj is present (dotnet=false)

    FAILS ON c7e1ea9 at N2 -- the first run of a real-shaped solution found a defect: the .sln root
    is listed first, so both advisories were filed against `Shop.sln` at line 1 and, deduplicated,
    never against the project that declares them. Each result now names the project dotnet reports.
    If the host has no dotnet SDK, or NuGet is unreachable, it is UNKNOWN (exit 2) and the hosted
    proof is the validate-scanners dotnet-solution leg.

EXIT  0 all hold   1 any does not   2 could not be checked
"""
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _scan_step_harness as h  # noqa: E402
import prove_bootstrap_failure as pbf  # noqa: E402
import _platform_fixtures as pf  # noqa: E402

JOB = 'sast-dotnet'
RESTORE, LIST = 'Restore', 'Vulnerable + deprecated NuGet packages'
COUNT, NENF = 'NuGet audit — count', 'NuGet audit — enforce'
SG, SGE = 'Semgrep (C#)', 'Semgrep (C#) — enforce'
PY3 = '#!/usr/bin/env bash\nif [ "${1:-}" = "-m" ] && [ "${2:-}" = "pip" ]; then\n  echo "(proof) skipped: python3 $*"; exit 0\nfi\nexec "%s" "$@"\n'


def results(path):
    if not os.path.isfile(path):
        return {}
    got = {}
    for run in json.load(open(path, encoding='utf-8')).get('runs') or []:
        for r in run.get('results') or []:
            loc = r['locations'][0]['physicalLocation']
            got.setdefault(loc['artifactLocation']['uri'].replace('\\', '/'), []).append(
                (r.get('ruleId', ''), (loc.get('region') or {}).get('startLine')))
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
    if not shutil.which('dotnet'):
        print('UNKNOWN: no dotnet SDK on this host; the hosted proof is validate-scanners dotnet-solution.')
        return 2
    steps = h.steps_by_name(JOB)
    miss = [n for n in (RESTORE, LIST, COUNT, NENF, SG, SGE) if n not in steps]
    if miss:
        print('FAIL: sast-dotnet lacks %s' % miss)
        return 1
    bad = []
    import test_discovery as td
    nd = td.run_case(td.extract_discovery_shell(), ['src/app.py'])
    print('  N4 discovery without .sln/.csproj: dotnet=%s' % nd.get('dotnet'))
    if nd.get('dotnet') != 'false':
        bad.append('N4 discovery did not skip .NET when no project is present')
    sb = h.Sandbox('dotnet-solution-').with_bundle()
    try:
        for tool in ('semgrep', 'jq'):
            if not h.have(bash, tool, h.path_prefix(sb.shim)):
                print('UNKNOWN: %s is required to RUN the steps.' % tool)
                return 2
        h.write(os.path.join(sb.shim, 'python3'), PY3 % sys.executable.replace('\\', '/'))
        os.chmod(os.path.join(sb.shim, 'python3'), 0o755)
        ws = sb.workspace('solution', pf.TREES['dotnet-solution'])
        vals = {'inputs.paths': '.', 'inputs.soft_fail_sast': 'false', 'inputs.advisory_mode': 'false',
                'inputs.dotnet_version': '8.0.x'}
        env = {'DOTNET_CLI_TELEMETRY_OPTOUT': '1', 'DOTNET_NOLOGO': '1'}
        rc, log, _o, _u = sb.run(bash, steps[RESTORE], vals, ws, env=env)
        roots = [l.strip() for l in open(os.path.join(ws, '.dotnet-roots.txt'), encoding='utf-8')] \
            if os.path.exists(os.path.join(ws, '.dotnet-roots.txt')) else []
        failed = open(os.path.join(ws, '.dotnet-restore-failed.txt'), encoding='utf-8').read().split() \
            if os.path.exists(os.path.join(ws, '.dotnet-restore-failed.txt')) else ['(no record)']
        print('  N1 restore rc=%d roots=%s failed=%s' % (rc, roots, failed))
        if 'Unable to load the service index' in log or 'NU1301' in log:
            print('UNKNOWN: NuGet is unreachable from this host.')
            return 2
        if len(roots) != 4 or failed:
            bad.append('N1 want 4 roots (sln + 3 csproj), all restored; got %s, failed %s\n%s'
                       % (roots, failed, log[-800:]))
        rc, log, _o, _u = sb.run(bash, steps[LIST], vals, ws, env=env)
        rc, log, out, _u = sb.run(bash, steps[COUNT], vals, ws, env=env)
        ev = dict(vals, **{'steps.nuget_count.outputs.%s' % k: out.get(k, '') for k in ('count', 'collection')})
        erc, elog, eout, _u = sb.run(bash, steps[NENF], ev, ws, env=env)
        vul = results(os.path.join(ws, 'dotnet-vuln.sarif'))
        print('  N2 audit %s count=%s handed=%r results=%s' % (out.get('collection'), out.get('count'),
                                                             eout.get('findings_state', ''), vul))
        if out.get('collection') != 'COMPLETE':
            bad.append('N2 the NuGet audit is %r, not COMPLETE\n%s' % (out.get('collection'), log[-800:]))
        for t, path, tool, rule in pf.SIGNALS:
            if t == 'dotnet-solution' and tool == 'dotnet-vuln':
                hits = vul.get(path, [])
                if not any(rule in rid for rid, _ln in hits):
                    bad.append('N2 %s not reported on %s (there: %s)' % (rule, path, hits))
                elif any(rule in rid and (ln or 1) <= 1 for rid, ln in hits):
                    bad.append('N2 %s reported on %s without the declaring line' % (rule, path))
        if eout.get('findings_state') != 'FINDINGS':
            bad.append('N2 the planted advisories were not handed to the gate')
        rc, log, out, _u = sb.run(bash, steps[SG], vals, ws, env=env)
        if 'Failed to download' in log or 'ConnectionError' in log:
            print('UNKNOWN: semgrep could not fetch its registry rules.')
            return 2
        sv = dict(vals, **{'steps.dotnet_semgrep.outputs.%s' % k: out.get(k, '') for k in ('count', 'collection')})
        erc, elog, eout, _u = sb.run(bash, steps[SGE], sv, ws, env=env)
        sg = results(os.path.join(ws, 'dotnet-semgrep.sarif'))
        print('  N3 semgrep count=%s handed=%r results=%s' % (out.get('count'), eout.get('findings_state', ''),
                                                             {k: sorted({r for r, _ in v}) for k, v in sg.items()}))
        for t, path, tool, rule in pf.SIGNALS:
            if t == 'dotnet-solution' and tool == 'semgrep-csharp':
                if not any(rule in rid.lower() for rid, _ln in sg.get(path, [])):
                    bad.append('N3 no %s rule on %s (there: %s)' % (rule, path, sg.get(path)))
        if eout.get('findings_state') != 'FINDINGS':
            bad.append('N3 the controller findings were not handed to the gate')
    finally:
        sb.close()
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: on a multi-project solution (sln, ASP.NET web project, data library, test project), '
          'sast-dotnet restores every root, reports both planted NuGet advisories at their declaring '
          'lines and the controller SQL injection, and hands them to the gate.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
