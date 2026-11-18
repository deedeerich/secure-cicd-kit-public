#!/usr/bin/env python3
"""The gate EMITS the run record (schemas/assurance-result.schema.json) and validates it. (ledger L36)

WHY THIS EXISTS

    The schema has existed since the first assurance review -- "the machine contract for a security
    run" -- and nothing emitted it: every consumer read job colour or scraped artifacts. This proves
    the security-gate job's `record` step, as shipped (the run-record composite, run from the kit):

      1  WIRED: a `record` step after `posture` and before `verdict`, `if: always()`, using
         $/.github/actions/run-record; the job and the workflow expose `assurance_result`.
      2  SCHEMA-VALID for every gate outcome: clean, findings, a secret, an unavailable scanner
         (reason INFRASTRUCTURE_UNKNOWN, never omitted), discovery unavailable, the report missing.
      3  NOTHING INVENTED: a scanner state outside the schema, or a missing commit or run id, is
         refused -- the record is not emitted, `run_record` says invalid, and the step says why;
         capture_state is BOUND only when repository, commit and run id are all present.
      4  COUNTS ONLY: no path, snippet or rule id can enter (the schema's findings block is counts).

EXIT 0 proven   1 a rule failed   2 could not be checked
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
ACTION = os.path.join(ROOT, '.github', 'actions', 'run-record', 'action.yml')
SCHEMA = os.path.join(ROOT, 'schemas', 'assurance-result.schema.json')


def main():
    try:
        import yaml
        import prove_bootstrap_failure as pbf
    except ImportError as exc:
        print('UNKNOWN: %s' % exc)
        return 2
    bad = []

    def check(c, m):
        if not c:
            bad.append(m)

    doc = yaml.safe_load(io.open(pbf.WF, encoding='utf-8'))
    job = doc['jobs']['security-gate']
    steps = job.get('steps') or []
    ids = [s.get('id') for s in steps]
    check('record' in ids, 'rule 1: security-gate has no record step')
    if 'record' in ids:
        rec = steps[ids.index('record')]
        check(ids.index('posture') < ids.index('record') < ids.index('verdict'),
              'rule 1: the record step is not between posture and verdict')
        check(str(rec.get('if', '')).startswith('always()'), 'rule 1: the record step is not if: always()')
        check(str(rec.get('uses', '')).endswith('.github/actions/run-record'), 'rule 1: not the run-record composite')
    check('assurance_result' in (job.get('outputs') or {}), 'rule 1: the job does not expose assurance_result')
    on = doc.get('on', doc.get(True)) or {}
    check('assurance_result' in ((on.get('workflow_call') or {}).get('outputs') or {}),
          'rule 1: the workflow does not expose assurance_result')
    if not os.path.isfile(ACTION):
        bad.append('rule 1: .github/actions/run-record/action.yml does not exist')
        for b in bad:
            print('FAIL: ' + b)
        return 1

    act = yaml.safe_load(io.open(ACTION, encoding='utf-8'))
    run = act['runs']['steps'][0]['run']
    bash, why = pbf.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s)' % why)
        return 2
    try:
        import jsonschema
        schema = json.load(io.open(SCHEMA, encoding='utf-8'))
    except ImportError:
        print('UNKNOWN: jsonschema is not installed; the record cannot be validated here')
        return 2

    states = {'secret-scan': 'PASS', 'sast-semgrep': 'FINDINGS', 'codeql': 'UNAVAILABLE',
              'iac-scan': 'NOT_APPLICABLE', 'deps-scan': 'PARTIAL'}
    # The composite's environment-variable names (data, not states), one per line.
    base = dict(
        ASSURANCE='FINDINGS',
        ENFORCEMENT='ADVISORY',
        SECRET_GATE='PASS',
        DISCOVERY='COMPLETE',
        SCANNER_STATES=json.dumps(states),
        REPORT_RESULT='success',
        BLOCKING_FINDINGS='3',
        EVIDENCE_ARTIFACT='security-report-1',
        REPOSITORY='o/r',
        REPOSITORY_ID='42',
        COMMIT_SHA='a' * 40,
        REF='refs/heads/main',
        RUN_ID='123')
    cases = [
        ('findings', {}, True),
        ('clean', {'ASSURANCE': 'PASS', 'ENFORCEMENT': 'ALLOWED', 'SCANNER_STATES': '{"secret-scan":"PASS"}',
                   'BLOCKING_FINDINGS': '0'}, True),
        ('secret', {'SECRET_GATE': 'FAIL', 'ENFORCEMENT': 'BLOCKED'}, True),
        # A SECRET EXCEPTED (owner ruling 2026-10-22): the record logs each one -- finding, ticket,
        # approver, expiry -- and secret_gate says EXCEPTED, never PASS.
        ('secret_excepted', dict(
            SECRET_GATE='EXCEPTED',
            SECRET_EXCEPTIONS=json.dumps([{'finding': 'a1b2c3d4e5f6', 'ticket': 'SEC-1234',
                                           'approver': 'Dana Example', 'expires': '2099-01-31',
                                           'entry': 'sx'}])), True),
        ('secret_exceptions_not_json', dict(
            SECRET_GATE='EXCEPTED',
            SECRET_EXCEPTIONS='[broken'), False),
        ('discovery_unavailable', {'ASSURANCE': 'UNDETERMINED', 'DISCOVERY': 'DISCOVERY_UNAVAILABLE'}, True),
        ('report_missing', {'REPORT_RESULT': 'failure', 'BLOCKING_FINDINGS': ''}, True),
        ('rogue_state', {'SCANNER_STATES': '{"sast-semgrep":"sort-of-fine"}'}, False),
        ('no_commit', {'COMMIT_SHA': ''}, False),
        ('no_run_id', {'RUN_ID': ''}, False),
        ('states_not_json', {'SCANNER_STATES': '{broken'}, False),
    ]
    work = tempfile.mkdtemp(prefix='run-record-')
    try:
        kit = os.path.join(work, 'kit')
        shutil.copytree(os.path.join(ROOT, 'scripts'), os.path.join(kit, 'scripts'))
        shutil.copytree(os.path.join(ROOT, 'schemas'), os.path.join(kit, 'schemas'))
        apath = os.path.join(kit, '.github', 'actions', 'run-record')
        os.makedirs(apath)
        for name, over, valid in cases:
            out = os.path.join(work, 'out')
            io.open(out, 'w').close()
            summ = os.path.join(work, 'summ')
            io.open(summ, 'w').close()
            script = os.path.join(work, 'step.sh')
            io.open(script, 'w', encoding='utf-8', newline='\n').write(run)
            env = dict(os.environ, GITHUB_ACTION_PATH=apath, GITHUB_OUTPUT=out, GITHUB_STEP_SUMMARY=summ,
                       RUNNER_TEMP=work, **dict(base, **over))
            p = subprocess.run([bash, script], capture_output=True, text=True, env=env)
            emitted = dict(l.rstrip('\n').split('=', 1) for l in io.open(out, encoding='utf-8') if '=' in l)
            print('  %-24s exit=%d run_record=%s' % (name, p.returncode, emitted.get('run_record')))
            check(p.returncode == 0, 'rule 3: %s: the record step failed the job (exit %d); it records, the '
                                     'verdict step decides' % (name, p.returncode))
            if valid:
                check(emitted.get('run_record') == 'valid', 'rule 2: %s: run_record=%r\n%s'
                      % (name, emitted.get('run_record'), (p.stdout + p.stderr)[-500:]))
                try:
                    rec = json.loads(emitted.get('assurance_result') or '')
                    jsonschema.validate(rec, schema)
                except (ValueError, jsonschema.ValidationError) as exc:
                    bad.append('rule 2: %s: the emitted record is not schema-valid: %s' % (name, str(exc)[:300]))
                    continue
                if name == 'findings':
                    cq = [s for s in rec['scanners'] if s['id'] == 'codeql'][0]
                    check(cq.get('reason') == 'INFRASTRUCTURE_UNKNOWN',
                          'rule 2: an UNAVAILABLE scanner carries no reason: %r' % cq)
                    check(rec['provenance']['capture_state'] == 'BOUND', 'rule 3: a full identity is not BOUND')
                    check(set(rec.get('findings', {})) <= {'critical', 'high', 'medium', 'low'},
                          'rule 4: the findings block carries more than counts')
                if name == 'secret_excepted':
                    sx = rec.get('secret_exceptions') or []
                    check(rec.get('secret_gate') == 'EXCEPTED' and len(sx) == 1
                          and sx[0].get('ticket') == 'SEC-1234' and sx[0].get('approver') == 'Dana Example'
                          and sx[0].get('expires') == '2099-01-31' and sx[0].get('finding') == 'a1b2c3d4e5f6',
                          'rule 2: an applied secret exception is not logged in the run record: %r' % sx)
                if name == 'report_missing':
                    check(rec['evidence_state'] != 'CANONICAL', 'rule 2: a missing report produced CANONICAL evidence')
            else:
                check(emitted.get('run_record') == 'invalid' and not emitted.get('assurance_result'),
                      'rule 3: %s: an invalid record was emitted (run_record=%r)' % (name, emitted.get('run_record')))
    finally:
        shutil.rmtree(work, ignore_errors=True)

    if bad:
        for b in bad:
            print('FAIL: ' + b)
        return 1
    print('PASS: the gate emits the run record after the posture step, schema-valid for every outcome, '
          'with a reason on every UNAVAILABLE scanner and identity BOUND only when complete; a state outside '
          'the schema or a missing identity is refused, never emitted.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
