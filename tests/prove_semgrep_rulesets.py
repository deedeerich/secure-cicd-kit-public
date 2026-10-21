#!/usr/bin/env python3
"""Run the sast-semgrep job's scan step and prove EVERY configured ruleset loads, and that
findings under tests/ and fixtures/ are found (W4C-001 regression).

WHY THIS EXISTS

    Two defects lived in this one step, and neither shows in a green run:
      * `--config` was not repeated. Semgrep takes targets positionally, so
        `--config p/default p/owasp-top-ten` loaded ONE ruleset and scanned the other as a path.
      * Semgrep's built-in ignore list skipped test directories, so a seeded flaw that bandit found
        in the same tree produced zero Semgrep findings.

MEASURED, NOT ASSUMED (semgrep 1.178.0, registry as of 2026-10-14)
    * Semgrep's SARIF lists EVERY loaded rule in `tool.driver.rules`, not only the ones that
      fired -- so "the ruleset loaded" is observable: its rule ids are in the report.
    * p/default: 1,074 rules; p/owasp-top-ten adds 70 beyond it; p/xss (35 rules) adds none
      beyond the other two. p/xss loading is therefore checked by its ids being present, which a
      dropped p/xss would still satisfy -- so the probe ALSO records the scanner's argv and
      requires each ruleset to arrive as its own `--config`.
    * The built-in ignore skips `tests/` but NOT `fixtures/` on this version; the step's own
      .semgrepignore must make both visible.

    The step is extracted as shipped and run with the real Semgrep; a pass-through wrapper records
    the argv before exec'ing the real binary. Each configured ruleset is ALSO run alone, and its
    rule-id set must be contained in the step's report.

EXIT
    0  every configured ruleset loaded and both seeded directories produced findings
    1  a ruleset did not load, or tests/ / fixtures/ were skipped
    2  could not be checked (no bash, semgrep, registry) -- UNKNOWN, never PASS
"""
import json
import os
import shlex
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import _scan_step_harness as h  # noqa: E402
import prove_bootstrap_failure as pbf  # noqa: E402

JOB, SCAN = 'sast-semgrep', 'Semgrep scan'
FLAW = 'import subprocess\n\n\ndef run(cmd):\n    subprocess.call(cmd, shell=True)\n'


def configured():
    import yaml
    doc = yaml.safe_load(open(h.WF, encoding='utf-8'))
    on = doc.get('on', doc.get(True)) or {}
    return str(((on.get('workflow_call') or {}).get('inputs') or {})
               .get('semgrep_config', {}).get('default', '')).split()


def rule_ids(path):
    doc = json.load(open(path, encoding='utf-8'))
    return {r['id'] for run_ in doc.get('runs', [])
            for r in (run_.get('tool', {}).get('driver', {}).get('rules') or [])}


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
    rulesets = configured()
    if len(rulesets) < 2:
        print('UNKNOWN: the semgrep_config default names %r -- fewer than two rulesets, so '
              '"every ruleset loads" is not being exercised.' % rulesets)
        return 2
    sb = h.Sandbox('semgrep-rulesets-').with_bundle()
    bad = []
    try:
        if not h.have(bash, 'semgrep', h.path_prefix(sb.shim)):
            print('UNKNOWN: semgrep is required to RUN the step.')
            return 2
        env = dict(os.environ, PATH=h.path_prefix(sb.shim) + os.pathsep + os.environ['PATH'])
        real = subprocess.run([bash, '-c', 'command -v semgrep'], env=env, capture_output=True,
                              text=True).stdout.strip()
        argv_log = os.path.join(sb.root, 'argv.txt').replace(os.sep, '/')
        wrap = os.path.join(sb.root, 'wrap')
        h.write(os.path.join(wrap, 'semgrep'),
                '#!/usr/bin/env bash\nprintf "%%s\\n" "$*" >> "%s"\nexec "%s" "$@"\n'
                % (argv_log, real))
        os.chmod(os.path.join(wrap, 'semgrep'), 0o755)
        ws = sb.workspace('tree', {'app.py': FLAW, 'tests/test_app.py': FLAW,
                                   'fixtures/fixture_app.py': FLAW})
        vals = {'inputs.paths': '.', 'inputs.semgrep_config': ' '.join(rulesets),
                'inputs.soft_fail_sast': 'false', 'inputs.advisory_mode': 'false'}
        rc, log, out, unk = sb.run(bash, steps[SCAN], vals, ws, extra_path=wrap,
                                   env={'SEMGREP_APP_TOKEN': ''})
        sarif = os.path.join(ws, 'semgrep.sarif')
        if not os.path.isfile(sarif):
            if 'Failed to download' in log or 'ConnectionError' in log:
                print('UNKNOWN: semgrep could not fetch its registry rules.')
                return 2
            print('FAIL: the scan step wrote no semgrep.sarif (exit %d)\n%s' % (rc, log[-800:]))
            return 1
        got = rule_ids(sarif)
        doc = json.load(open(sarif, encoding='utf-8'))
        uris = {r['locations'][0]['physicalLocation']['artifactLocation']['uri'].replace('\\', '/')
                for run_ in doc.get('runs', []) for r in run_.get('results', [])}
        argv = open(argv_log, encoding='utf-8').read() if os.path.exists(argv_log) else ''
        toks = shlex.split(argv.splitlines()[0]) if argv.strip() else []
        loaded = [toks[i + 1] for i, t in enumerate(toks[:-1]) if t == '--config']
        print('  step report: %d rule(s), findings in %s' % (len(got), sorted(uris)))
        print('  step argv --config: %s' % loaded)
        for rs in rulesets:
            if rs not in loaded:
                bad.append('ruleset %s never reached semgrep as its own --config' % rs)
            alone = os.path.join(ws, 'alone.sarif')
            # Through bash: `real` is the path bash resolved, which may be a POSIX path.
            subprocess.run([bash, '-c', '"$0" "$@"', real, 'scan', '--config', rs, '--sarif',
                            '--output', 'alone.sarif', '--metrics=off', '.'], cwd=ws,
                           capture_output=True, env=dict(env, PYTHONUTF8='1'))
            if not os.path.isfile(alone):
                print('UNKNOWN: could not run %s alone to establish its rule set.' % rs)
                return 2
            ids = rule_ids(alone)
            os.remove(alone)
            missing = ids - got
            print('  %-18s alone: %4d rule(s); missing from the step report: %d'
                  % (rs, len(ids), len(missing)))
            if not ids:
                bad.append('%s loaded no rules even alone -- cannot establish it' % rs)
            elif missing:
                bad.append('%s: %d of its rules are not in the step report -- it did not load'
                           % (rs, len(missing)))
        for d in ('tests/', 'fixtures/'):
            if not any(u.startswith(d) or ('/' + d) in u for u in uris):
                bad.append('the seeded flaw under %s produced no finding -- Semgrep\'s default '
                           'ignore list is back in force' % d)
    finally:
        sb.close()
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: every configured ruleset (%s) reached Semgrep as its own --config and its rules '
          'are in the report; seeded flaws under tests/ and fixtures/ were found.'
          % ', '.join(rulesets))
    return 0


if __name__ == '__main__':
    sys.exit(main())
