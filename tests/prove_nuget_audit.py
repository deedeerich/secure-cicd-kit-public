#!/usr/bin/env python3
"""Run the sast-dotnet job's restore, NuGet audit, count and enforce steps with the real dotnet.

WHY THIS EXISTS (ledger L08: "NuGet false pass")

    The audit ran `dotnet list package --vulnerable` from the repository ROOT, `|| true`, and then
    grepped the text for `>\\s*(Critical|High)`. Measured, two independent false passes:

      * a project that is not at the root (src/App/App.csproj, the normal layout) gives
        "A project or solution file could not be found" and exit 1 -- swallowed, nothing to grep,
        PASS;
      * when a project IS found, the table row reads `> Newtonsoft.Json  12.0.1  12.0.1  High ...`:
        the package NAME follows `>`, so the pattern can never match, and a High advisory PASSES.

    A restore failure (`|| true`) likewise left nothing for the audit to read.

    The steps are extracted as shipped, `env:` and `${{ }}` resolved from the scenario, and run
    under bash with the real dotnet SDK against throwaway projects. Restore needs nuget.org.

SCENARIOS
    vulnerable_nested  src/App/App.csproj -> Newtonsoft.Json 12.0.1 (High)  -> FINDINGS 1, handed to
                       the gate (findings_state=FINDINGS; the step succeeds -- lane L-S, O-24)
    vulnerable_soft    the same, soft_fail_sast on                           -> counted, passes
    clean              Newtonsoft.Json 13.0.3                                -> 0, passes
    no_projects        no .csproj / .sln                                     -> NOT_APPLICABLE, passes
    restore_fails      a package version that does not exist                -> COLLECTION_FAILED, FAILS

EXIT
    0  every scenario decided as it must
    1  a scenario decided wrongly
    2  could not be checked (no bash, no dotnet, no nuget.org) -- UNKNOWN, never PASS
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _scan_step_harness as h  # noqa: E402
import prove_bootstrap_failure as pbf  # noqa: E402

JOB = 'sast-dotnet'
RESTORE, AUDIT = 'Restore', 'Vulnerable + deprecated NuGet packages'
COUNT, ENFORCE = 'NuGet audit — count', 'NuGet audit — enforce'

CSPROJ = '''<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
  <ItemGroup><PackageReference Include="Newtonsoft.Json" Version="%s" /></ItemGroup>
</Project>
'''
CS = 'namespace Probe { public class A { } }\n'


def project(version):
    return {'src/App/App.csproj': CSPROJ % version, 'src/App/A.cs': CS}


def sarif_problems(name, ws, want_coll, want_n, cout):
    """THE AUDIT'S EVIDENCE MUST OUTLIVE THE RUNNER (hosted negative run 38779814703).

    The audit blocked on two vulnerable packages and wrote nothing durable: the report's
    `dotnet-vuln` row expects dotnet-vuln.sarif and nothing ever produced it, so the seeded
    `deps:dotnet-vulnerable` signal read MISSED while the job that found it was red. A COMPLETE
    audit must leave dotnet-vuln.sarif -- one result per counted (package, version, advisory),
    located at the project that declared it -- and say so in the `sarif` output. No audit result
    must leave no SARIF: an empty report would read as a clean one."""
    import json
    p = os.path.join(ws, 'dotnet-vuln.sarif')
    out = []
    if want_coll != 'COMPLETE':
        if os.path.exists(p):
            out.append('%s: dotnet-vuln.sarif written for a %s audit -- an empty report reads as '
                       'clean' % (name, want_coll))
        return out
    if cout.get('sarif') != 'true':
        out.append('%s: count step published sarif=%r, expected true' % (name, cout.get('sarif')))
    if not os.path.isfile(p):
        return out + ['%s: COMPLETE audit left no dotnet-vuln.sarif -- the finding dies with the '
                      'runner' % name]
    try:
        doc = json.load(open(p, encoding='utf-8'))
        results = [r for run in doc['runs'] for r in run['results']]
    except (ValueError, KeyError, TypeError) as exc:
        return out + ['%s: dotnet-vuln.sarif is not SARIF (%s)' % (name, exc)]
    errors = [r for r in results if r.get('level') == 'error']
    if want_n is not None and len(errors) != int(want_n):
        out.append('%s: %d error-level result(s), expected %s (the Critical/High count)'
                   % (name, len(errors), want_n))
    for r in results:
        uris = [l['physicalLocation']['artifactLocation']['uri'] for l in r.get('locations', [])]
        if not uris or not all(u.endswith('src/App/App.csproj') for u in uris):
            out.append('%s: result %s is not located at the declaring project (%s)'
                       % (name, r.get('ruleId'), uris))
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
    steps = h.steps_by_name(JOB)
    missing = [n for n in (RESTORE, AUDIT, COUNT, ENFORCE) if n not in steps]
    if missing:
        print('FAIL: job %r has no step(s) %s. The NuGet audit greps text for a pattern that '
              'cannot match a High row and passes when no project is at the root.'
              % (JOB, missing))
        return 1
    sb = h.Sandbox('nuget-probe-')
    bad = []
    try:
        if not h.have(bash, 'dotnet', h.path_prefix(sb.shim)):
            print('UNKNOWN: dotnet is required to RUN the steps.')
            return 2
        scenarios = [
            # name, files, soft, expected collection, count, enforce:
            #   HANDED (exit 0, findings_state=FINDINGS: the gate enforces, lane L-S / O-24)
            #   | PASS (exit 0, nothing handed) | FAIL (could not audit)
            ('vulnerable_nested', project('12.0.1'), 'false', 'COMPLETE', '1', 'HANDED'),
            ('vulnerable_soft', project('12.0.1'), 'true', 'COMPLETE', '1', 'PASS'),
            ('clean', project('13.0.3'), 'false', 'COMPLETE', '0', 'PASS'),
            ('no_projects', {'README.md': 'no dotnet here\n'}, 'false', 'NOT_APPLICABLE', '0',
             'PASS'),
            ('restore_fails', project('999.0.0-does-not-exist'), 'false', 'COLLECTION_FAILED',
             None, 'FAIL'),
        ]
        for name, files, soft, want_coll, want_n, enforce_ok in scenarios:
            ws = sb.workspace(name, files)
            vals = {'inputs.paths': '.', 'inputs.soft_fail_sast': soft,
                    'inputs.advisory_mode': 'false', 'inputs.dotnet_version': '8.0.x'}
            log = ''
            for st in (RESTORE, AUDIT):
                rc, l, _o, unk = sb.run(bash, steps[st], vals, ws)
                log += l
                if unk:
                    bad.append('%s: %r reads unmodelled %s' % (name, st, unk))
            if 'Unable to load the service index' in log or 'NU1301' in log:
                print('UNKNOWN: nuget.org could not be reached.')
                return 2
            crc, clog, cout, unk = sb.run(bash, steps[COUNT], vals, ws)
            if unk:
                bad.append('%s: count step reads unmodelled %s' % (name, unk))
            evals = dict(vals, **{'steps.nuget_count.outputs.%s' % k: cout.get(k, '')
                                  for k in ('count', 'collection')})
            erc, elog, eout, unk = sb.run(bash, steps[ENFORCE], evals, ws)
            if unk:
                bad.append('%s: enforce step reads unmodelled %s' % (name, unk))
            coll, n = cout.get('collection', ''), cout.get('count')
            print('  %-18s collection=%-18s count=%-3s enforce exit=%d'
                  % (name, coll or '-', n if n is not None else '-', erc))
            if coll != want_coll:
                bad.append('%s: collection=%r, expected %r\n%s' % (name, coll, want_coll,
                                                                   (log + clog)[-700:]))
            if want_n is not None and n != want_n:
                bad.append('%s: count=%r, expected %s\n%s' % (name, n, want_n, clog[-500:]))
            bad.extend(sarif_problems(name, ws, want_coll, want_n, cout))
            handed = eout.get('findings_state', '')
            if enforce_ok in ('PASS', 'HANDED') and erc != 0:
                bad.append('%s: enforce failed (exit %d) -- findings go to the gate, never a failed '
                           'job\n%s' % (name, erc, elog[-300:]))
            if enforce_ok == 'HANDED' and handed != 'FINDINGS':
                bad.append('%s: findings_state=%r -- a High advisory with soft_fail_sast off must be '
                           'handed to the gate, which enforces it' % (name, handed))
            if enforce_ok == 'PASS' and handed:
                bad.append('%s: findings_state=%r where nothing is enforced' % (name, handed))
            if enforce_ok == 'FAIL' and erc == 0:
                bad.append('%s: enforce PASSED -- no audit result is not a clean audit' % name)
    finally:
        sb.close()
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: the shipped NuGet audit lists each discovered project in JSON, counts Critical/'
          'High advisories, hands them to the gate unless softened, and reads a failed restore as '
          'COLLECTION_FAILED.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
