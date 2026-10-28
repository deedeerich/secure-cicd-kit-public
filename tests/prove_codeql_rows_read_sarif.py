#!/usr/bin/env python3
"""The gate's six CodeQL rows must read the SARIF CodeQL actually writes, and evidence must beat
the platform pre-flight.

WHY THIS EXISTS

    The first Level 2 dispatch of the CodeQL job (private consumer repository, run 38817782084,
    kit at 1a5f6f9) analysed two languages and the gate misread both:

      D1  analyze names its output by CodeQL's LANGUAGE ID -- javascript.sarif for the
          javascript-typescript matrix leg (java.sarif and cpp.sarif for java-kotlin and c-cpp).
          The row builder looked for <matrix-leg>.sarif, so a SARIF carrying four JavaScript
          results sat in the evidence bundle and the codeql-javascript-typescript row rendered
          sarif NONE, gate UNDETERMINED. One scanner, one file -- but the right file.

      D2  the platform probe read code scanning UNAVAILABLE on the private repository and the row
          builder took that as the language's applicability. CodeQL still initialised, analysed
          and wrote five Python and four JavaScript results; only PUBLICATION to the Security tab
          was refused. The licence governs where results can go, not whether the analysis runs,
          and a row that calls nine retained findings UNAVAILABLE is "the control found nothing"
          written over "the control found something" -- the inversion this gate exists to refuse.

WHAT IS RUN
    The report job's "Build per-scanner state" step, extracted as shipped, in a workspace holding
    what the evidence download delivered (tests/prove_image_secret_row.py's harness).

CASES (docs/PROOF_RULE.md)
    allowed     node and python discovered, platform UNAVAILABLE, javascript.sarif and python.sarif
                present (as on run 38817782084) -> each row names ITS file, is APPLICABLE, and the
                gate state is PASS (execution COMPLETE + applicable + evidence)
    aliases     java-kotlin reads java.sarif and c-cpp reads cpp.sarif; go and csharp their own
    attack      python discovered, platform UNAVAILABLE, NO python.sarif -> UNAVAILABLE and
                UNDETERMINED (the licence case where init really failed is unchanged)
    recovery    a language not discovered -> NOT_APPLICABLE, whatever the platform said
    static      the row builder passes a CodeQL file name per leg, not the leg name

EXIT 0 every case decided as it must; 1 a case decided wrongly; 2 could not be checked (UNKNOWN).
"""
import io
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import _scan_step_harness as h  # noqa: E402
import prove_bootstrap_failure as pbf  # noqa: E402

# matrix leg -> (the file analyze writes, the discovery flag that gates the leg)
LEGS = {
    'python': ('python.sarif', 'python'),
    'javascript-typescript': ('javascript.sarif', 'node'),
    'go': ('go.sarif', 'go'),
    'csharp': ('csharp.sarif', 'dotnet'),
    'java-kotlin': ('java.sarif', 'java'),
    'c-cpp': ('cpp.sarif', 'cpp'),
}


def codeql_sarif(leg, rule):
    return json.dumps({'version': '2.1.0', 'runs': [{
        'tool': {'driver': {'name': 'CodeQL', 'semanticVersion': '2.27.2', 'rules': [
            {'id': rule, 'shortDescription': {'text': rule},
             'properties': {'security-severity': '7.5', 'tags': ['security']}}]}},
        'automationDetails': {'id': '/language:%s/' % leg},
        'invocations': [{'executionSuccessful': True}],
        'results': [{'ruleId': rule, 'level': 'error', 'message': {'text': rule},
                     'locations': [{'physicalLocation': {
                         'artifactLocation': {'uri': 'src/app'},
                         'region': {'startLine': 1}}}]}]}]})


def state(states_dir, leg):
    p = os.path.join(states_dir, 'state-codeql-%s.json' % leg)
    if not os.path.exists(p):
        return None
    return json.load(io.open(p, encoding='utf-8'))


def main():
    try:
        import yaml  # noqa: F401
    except ImportError as exc:
        print('UNKNOWN: %s' % exc)
        return 2
    bash, why = pbf.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s).' % why)
        return 2
    step = h.steps_by_name('security-gate').get('Build per-scanner state')
    if step is None:
        print('UNKNOWN: the report job has no "Build per-scanner state" step.')
        return 2
    run = str(step.get('run') or '')
    bad = []

    # static: every leg is wired with the file CodeQL writes for it.
    for leg, (sarif, _flag) in LEGS.items():
        if not re.search(r'^\s*cq_lang\s+%s\s+%s\b' % (re.escape(leg), re.escape(sarif)), run, re.M):
            bad.append('static: the row builder does not read %s for the %s leg' % (sarif, leg))

    sb = h.Sandbox('codeql-rows-')
    try:
        def states_for(name, discovered, platform, files):
            vals = {'needs.codeql.result': 'success', 'inputs.image_ref': '',
                    'needs.plan.outputs.state': 'COMPLETE',
                    'needs.plan.outputs.code_scanning': platform,
                    'needs.plan.outputs.platform_source': 'api'}
            for flag in ('python', 'node', 'go', 'dotnet', 'java', 'cpp', 'iac'):
                vals['needs.plan.outputs.%s' % flag] = 'true' if flag in discovered else 'false'
            ws = sb.workspace(name, dict({'_sarif/.keep': ''}, **files))
            rc, log, _o, _u = sb.run(bash, step, vals, ws)
            if rc != 0:
                bad.append('%s: the state builder exited %d\n%s' % (name, rc, log[-400:]))
            return os.path.join(ws, '_states')

        # allowed: what run 38817782084 delivered. Both rows must name their file and be APPLICABLE.
        st = states_for('allowed', {'python', 'node'}, 'UNAVAILABLE',
                        {'_sarif/javascript.sarif': codeql_sarif('javascript-typescript', 'js/reflected-xss'),
                         '_sarif/python.sarif': codeql_sarif('python', 'py/command-line-injection')})
        for leg in ('python', 'javascript-typescript'):
            s = state(st, leg) or {}
            print('  allowed   %-22s %s' % (leg, json.dumps(s, sort_keys=True)))
            if s.get('sarif') != LEGS[leg][0] or s.get('artifact') != 'RETAINED':
                bad.append('allowed: codeql-%s must read %s (got sarif=%r artifact=%r)'
                           % (leg, LEGS[leg][0], s.get('sarif'), s.get('artifact')))
            if s.get('applicability') != 'APPLICABLE' or s.get('gate') != 'PASS':
                bad.append('allowed: codeql-%s analysed and retained results, so it is APPLICABLE '
                           'and its gate state is PASS whatever the platform pre-flight said '
                           '(got applicability=%r gate=%r)'
                           % (leg, s.get('applicability'), s.get('gate')))

        # aliases: the other four legs read their own CodeQL file names.
        st = states_for('aliases', {'go', 'dotnet', 'java', 'cpp'}, 'ENABLED',
                        {'_sarif/go.sarif': codeql_sarif('go', 'go/sql-injection'),
                         '_sarif/csharp.sarif': codeql_sarif('csharp', 'cs/sql-injection'),
                         '_sarif/java.sarif': codeql_sarif('java-kotlin', 'java/sql-injection'),
                         '_sarif/cpp.sarif': codeql_sarif('c-cpp', 'cpp/unsafe-strcat')})
        for leg in ('go', 'csharp', 'java-kotlin', 'c-cpp'):
            s = state(st, leg) or {}
            print('  aliases   %-22s sarif=%r applicability=%r gate=%r'
                  % (leg, s.get('sarif'), s.get('applicability'), s.get('gate')))
            if s.get('sarif') != LEGS[leg][0] or s.get('gate') != 'PASS':
                bad.append('aliases: codeql-%s must read %s and PASS (got sarif=%r gate=%r)'
                           % (leg, LEGS[leg][0], s.get('sarif'), s.get('gate')))

        # attack: discovered, platform UNAVAILABLE, no SARIF -- the licence case. Unchanged.
        st = states_for('attack', {'python'}, 'UNAVAILABLE', {})
        s = state(st, 'python') or {}
        print('  attack    %-22s %s' % ('python', json.dumps(s, sort_keys=True)))
        if s.get('applicability') != 'UNAVAILABLE' or s.get('gate') != 'UNDETERMINED' or s.get('sarif'):
            bad.append('attack: a discovered language with no SARIF on an UNAVAILABLE platform must '
                       'stay UNAVAILABLE / UNDETERMINED (got %s)' % json.dumps(s, sort_keys=True))

        # recovery: not discovered -> NOT_APPLICABLE, whatever the platform said.
        for platform in ('ENABLED', 'UNAVAILABLE'):
            st = states_for('recovery-%s' % platform.lower(), {'python'}, platform,
                            {'_sarif/python.sarif': codeql_sarif('python', 'py/path-injection')})
            for leg in ('javascript-typescript', 'go', 'csharp', 'java-kotlin', 'c-cpp'):
                s = state(st, leg) or {}
                if s.get('applicability') != 'NOT_APPLICABLE':
                    bad.append('recovery(%s): codeql-%s was not discovered and must be NOT_APPLICABLE '
                               '(got %r)' % (platform, leg, s.get('applicability')))
            print('  recovery  platform=%-11s absent legs NOT_APPLICABLE: %s'
                  % (platform, 'ok' if not any(b.startswith('recovery(%s)' % platform) for b in bad)
                     else 'NO'))
    finally:
        sb.close()
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: each CodeQL row reads the file analyze writes for its leg, a retained analysis is '
          'APPLICABLE and PASS whatever the platform pre-flight said, a discovered language with no '
          'SARIF stays UNAVAILABLE / UNDETERMINED, and an undiscovered one is NOT_APPLICABLE.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
