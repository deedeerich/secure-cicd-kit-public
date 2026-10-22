#!/usr/bin/env python3
"""Prove the Semgrep and Checkov count steps count a finding by its EFFECTIVE SARIF level.

WHY THIS EXISTS

    Both steps counted blocking findings with
        [.runs[].results[] | select((.level // "warning") == "error")]
    -- the result's own `level`, defaulting to "warning". Semgrep (measured: 1.90.0 on consumer runs,
    1.178.0 here) never writes `level` on a result; the severity lives on the RULE, as
    `tool.driver.rules[].defaultConfiguration.level`. So every ERROR-severity Semgrep finding
    counted as zero and the enforce step could never block -- while the report, which reads the
    rule's level (scan_report.py), listed them as errors. The report and the gate disagreed about
    the same file. On two real consumer runs 14 and 27 error findings both counted 0.

    SARIF 2.1.0 section 3.27.10 fixes the rule: a result's effective level is its own `level`, else
    its rule's `defaultConfiguration.level`, else "warning". This runs the steps as shipped against
    reports shaped exactly that way, plus the Semgrep step against the real tool.

SCENARIOS
    semgrep_real_error    real semgrep, an ERROR-severity rule that matches -> count 1, enforce FAILS
    semgrep_real_warning  real semgrep, a WARNING-severity rule that matches -> count 0, enforce passes
    checkov_rule_level    SARIF: result without level, rule default error   -> count 1
    checkov_result_level  SARIF: result level "error" (result overrides)    -> count 1
    checkov_note          SARIF: result without level, rule default note    -> count 0

EXIT
    0  every scenario counted as it must
    1  a scenario counted wrongly
    2  could not be checked -- UNKNOWN, never PASS
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
import prove_bootstrap_failure as pbf  # noqa: E402  (shared extraction and bash probe)


def _expand(doc):
    """The workflow with every `$/` composite step expanded into its job, as the runner sees it.

    Scanner job bodies live in `.github/actions/<scanner>/` (ledger L64); this reads the steps a
    job actually runs. One rule, tests/_composite_expand.py, for every reader.
    """
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import _composite_expand
    return _composite_expand.expanded_doc(doc)


def step(job, name):
    import yaml
    doc = _expand(yaml.safe_load(io.open(pbf.WF, encoding='utf-8')))
    for s in (doc['jobs'][job].get('steps') or []):
        if s.get('name') == name:
            return s.get('run')
    return None


def write(path, text):
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    io.open(path, 'w', encoding='utf-8', newline='\n').write(text)


def run(bash, script, ws, ctx):
    body, _ = pbf.substitute(script, ctx)
    out = os.path.join(ws, '.gh_output')
    if not os.path.exists(out):
        io.open(out, 'w').close()
    f = os.path.join(ws, '.step.sh')
    # The count site calls /tmp/sarif_validity.py from the kit bundle (L02): supply it.
    io.open(f, 'w', encoding='utf-8', newline='\n').write(pbf.with_kit_bundle(body))
    env = dict(os.environ, GITHUB_OUTPUT=out, GITHUB_STEP_SUMMARY=os.path.join(ws, '.s'),
               PYTHONUTF8='1', **pbf.env_for_run(script, ctx))
    p = subprocess.run([bash, f], capture_output=True, text=True, encoding='utf-8',
                       errors='replace', env=env, cwd=ws)
    o = {}
    for line in io.open(out, encoding='utf-8', errors='replace'):
        if '=' in line:
            k, v = line.rstrip('\n').split('=', 1)
            o[k] = v
    return p.returncode, (p.stdout or '') + (p.stderr or ''), o


RULE = '''rules:
- id: probe-eval
  pattern: eval(...)
  message: eval on input
  languages: [python]
  severity: %s
'''


def sarif(result_level, rule_level):
    res = {'ruleId': 'CKV_PROBE_1', 'message': {'text': 'probe'},
           'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'main.tf'},
                                               'region': {'startLine': 1}}}]}
    if result_level:
        res['level'] = result_level
    rule = {'id': 'CKV_PROBE_1'}
    if rule_level:
        rule['defaultConfiguration'] = {'level': rule_level}
    return json.dumps({'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'checkov',
                                                                         'rules': [rule]}},
                                                      'results': [res]}]})


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    bash, why = pbf.usable_bash()
    if not bash or not shutil.which('jq'):
        print('UNKNOWN: bash and jq are required (%s).' % (why or 'jq missing'))
        return 2
    sem_scan = step('sast-semgrep', 'Semgrep scan')
    sem_enf = step('sast-semgrep', 'Semgrep — enforce')
    ck = step('iac-scan', 'Checkov — count findings')
    if not (sem_scan and sem_enf and ck):
        print('UNKNOWN: a count or enforce step is missing.')
        return 2

    tmp = tempfile.mkdtemp(prefix='sarif-level-')
    bad = []
    try:
        if shutil.which('semgrep'):
            for name, sev, want, enforce_fails in (('semgrep_real_error', 'ERROR', '1', True),
                                                   ('semgrep_real_warning', 'WARNING', '0', False)):
                ws = os.path.join(tmp, name)
                write(os.path.join(ws, 'src', 'a.py'), 'eval(input())\n')
                write(os.path.join(ws, 'rules.yml'), RULE % sev)
                ctx = {'inputs.semgrep_config': 'rules.yml', 'inputs.paths': 'src',
                       'inputs.soft_fail_sast': 'false', 'inputs.advisory_mode': 'false'}
                rc, log, o = run(bash, sem_scan, ws, ctx)
                ectx = dict(ctx, **{'steps.semgrep.outputs.count': o.get('count', ''),
                                    'steps.semgrep.outputs.collection': o.get('collection', '')})
                erc, _, _ = run(bash, sem_enf, ws, ectx)
                print('  %-22s count=%s enforce exit=%d' % (name, o.get('count'), erc))
                if o.get('count') != want:
                    bad.append('%s: counted %r, expected %s. %s' % (
                        name, o.get('count'), want,
                        'An ERROR-severity finding counted as zero can never block.'
                        if want == '1' else ''))
                if enforce_fails and erc == 0:
                    bad.append('%s: enforce passed an ERROR finding with soft_fail_sast off' % name)
                if not enforce_fails and erc != 0:
                    bad.append('%s: enforce failed on a WARNING finding' % name)
        else:
            print('  (semgrep not installed: the real-tool scenarios are skipped; the SARIF-shape '
                  'scenarios below still decide the count rule)')

        for name, rl, dl, want in (('checkov_rule_level', None, 'error', '1'),
                                   ('checkov_result_level', 'error', 'warning', '1'),
                                   ('checkov_note', None, 'note', '0')):
            ws = os.path.join(tmp, name)
            write(os.path.join(ws, 'checkov.sarif', 'results_sarif.sarif'), sarif(rl, dl))
            rc, log, o = run(bash, ck, ws, {})
            print('  %-22s count=%s' % (name, o.get('count')))
            if o.get('count') != want:
                bad.append('%s: counted %r, expected %s' % (name, o.get('count'), want))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: Semgrep and Checkov count findings by their effective SARIF level (result level, '
          'else the rule default, else warning), so an ERROR-severity rule can block.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
