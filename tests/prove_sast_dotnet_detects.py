#!/usr/bin/env python3
"""Run the sast-dotnet job's own Semgrep (C#) and enforce steps against seeded and clean C#.

WHY THIS EXISTS (W4C-001 regression)

    sast-dotnet once had dependency auditing and ZERO static analysis: it published
    `dotnet-semgrep.sarif`, which no step wrote, and went green on every run (fixed in c483d6d).
    tests/check_published_sarif_has_producer.py now refuses that shape statically. This proves the
    other half: that the step which now exists FINDS a seeded C# flaw with the real Semgrep, counts
    it, and that enforce acts on the count -- including when the code sits under `tests/`, which
    Semgrep skips by default.

    Steps are extracted as shipped, inputs resolved, run under bash. `pip install semgrep` is made
    a no-op by a `python3` shim (a proof does not install into its host); the Semgrep already on
    this host runs. Registry rules (p/csharp, p/security-audit) need network.

SCENARIOS
    seeded_enforce  SQL built by concatenation, soft_fail off -> >= 1 finding, enforce FAILS
    seeded_in_tests the same file under tests/                -> still found (own .semgrepignore)
    clean           a pure function                           -> 0 findings, enforce passes
    no_csharp       no .cs files                              -> the step skips, exit 0

EXIT
    0  every scenario decided as it must
    1  a scenario decided wrongly
    2  could not be checked (no bash, semgrep, jq, registry) -- UNKNOWN, never PASS
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _scan_step_harness as h  # noqa: E402
import prove_bootstrap_failure as pbf  # noqa: E402

JOB = 'sast-dotnet'
SCAN, ENFORCE = 'Semgrep (C#)', 'Semgrep (C#) — enforce'

SEEDED = '''using System.Data.SqlClient;

public class Users
{
    public SqlDataReader ById(SqlConnection conn, string id)
    {
        var cmd = new SqlCommand("SELECT * FROM users WHERE id = '" + id + "'", conn);
        return cmd.ExecuteReader();
    }
}
'''
CLEAN = 'public class Calc\n{\n    public int Add(int a, int b) { return a + b; }\n}\n'
PY3 = '#!/usr/bin/env bash\nif [ "${1:-}" = "-m" ] && [ "${2:-}" = "pip" ]; then\n  echo "(proof) skipped: python3 $*"; exit 0\nfi\nexec "%s" "$@"\n'


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
    if SCAN not in steps or ENFORCE not in steps:
        print('FAIL: job %r has no %r / %r step -- .NET has no static analysis.' % (JOB, SCAN, ENFORCE))
        return 1
    sb = h.Sandbox('dotnet-sast-probe-').with_bundle()
    bad = []
    try:
        for tool in ('semgrep', 'jq'):
            if not h.have(bash, tool, h.path_prefix(sb.shim)):
                print('UNKNOWN: %s is required to RUN the step.' % tool)
                return 2
        h.write(os.path.join(sb.shim, 'python3'), PY3 % sys.executable.replace('\\', '/'))
        os.chmod(os.path.join(sb.shim, 'python3'), 0o755)
        scenarios = [
            ('seeded_enforce', {'src/Users.cs': SEEDED}, True, False),
            ('seeded_in_tests', {'tests/Users.cs': SEEDED}, True, False),
            ('clean', {'src/Calc.cs': CLEAN}, False, True),
            ('no_csharp', {'README.md': 'no C# here\n'}, None, True),
        ]
        for name, files, finds, enforce_ok in scenarios:
            ws = sb.workspace(name, files)
            vals = {'inputs.paths': '.', 'inputs.soft_fail_sast': 'false',
                    'inputs.advisory_mode': 'false', 'inputs.dotnet_version': '8.0.x'}
            rc, log, out, unk = sb.run(bash, steps[SCAN], vals, ws)
            if unk:
                bad.append('%s: scan step reads unmodelled %s' % (name, unk))
            if finds is None:
                print('  %-16s scan exit=%d (skip)' % (name, rc))
                if rc != 0 or 'count' in out:
                    bad.append('%s: a tree with no C# must skip cleanly (exit %d)' % (name, rc))
                continue
            if 'count' not in out:
                if 'Failed to download' in log or 'ConnectionError' in log:
                    print('UNKNOWN: semgrep could not fetch its registry rules.')
                    return 2
                bad.append('%s: no count (exit %d)\n%s' % (name, rc, log[-600:]))
                continue
            rules = []
            sarif = os.path.join(ws, 'dotnet-semgrep.sarif')
            if os.path.isfile(sarif):
                doc = json.load(open(sarif, encoding='utf-8'))
                rules = sorted({r.get('ruleId', '') for run_ in doc.get('runs', [])
                                for r in run_.get('results', [])})
            evals = dict(vals, **{'steps.dotnet_semgrep.outputs.%s' % k: out.get(k, '')
                                  for k in ('count', 'collection')})
            erc, elog, _o, unk = sb.run(bash, steps[ENFORCE], evals, ws)
            n = int(out['count'])
            print('  %-16s findings=%d enforce exit=%d %s' % (name, n, erc, ','.join(rules)[:120]))
            if finds and n < 1:
                bad.append('%s: the seeded SQL injection produced no finding' % name)
            if finds and not any('sql' in r.lower() for r in rules):
                bad.append('%s: findings %s are not the seeded SQL class' % (name, rules))
            if finds is False and n != 0:
                bad.append('%s: the clean file produced %d finding(s): %s' % (name, n, rules))
            if enforce_ok and erc != 0:
                bad.append('%s: enforce failed (exit %d)\n%s' % (name, erc, elog[-300:]))
            if not enforce_ok and erc == 0:
                bad.append('%s: enforce passed a seeded finding with soft_fail_sast off' % name)
    finally:
        sb.close()
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: the shipped sast-dotnet Semgrep step finds a seeded C# SQL injection (also under '
          'tests/), counts it, and enforce blocks it with soft_fail_sast off; clean C# yields zero.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
