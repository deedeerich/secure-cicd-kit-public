#!/usr/bin/env python3
"""Run the secret-scan job's own Enforce step and the gate: a secret blocks in every mode.

WHY THIS EXISTS (C2 / N1)

    The kit's rule is that secrets block from day one: advisory_mode softens enforcement on
    inherited FINDINGS and never on a leaked credential, which is live exposure, not debt. The gate
    implements that -- it sets secret_fail when the secret-scan job's result is not success, and
    checks it before advisory_mode.

    But the secret-scan job's own Enforce step consulted advisory_mode and EXITED 0 on findings
    when it was on. The job then succeeded, the gate read `success`, secret_fail was never set, and
    the policy the gate enforces so carefully had nothing to enforce. The rule held in the one
    place that could not see the finding and failed in the one place that could.

    tests/prove_bootstrap_failure.py runs the GATE. This runs the step that DECIDES what the gate
    is told: extracted from the workflow as shipped, its `${{ }}` inputs substituted, run.

    SINCE THE OWNER'S RULING OF 2026-10-22 (lane L-S) a secret may be excepted -- one finding,
    ticketed, attributed, unexpired, in the protected-branch policy register -- and only the gate
    holds the resolved policy. So the Enforce step HANDS the secret to the gate (findings_state=
    FINDINGS, secret_count) in EVERY mode instead of failing the job, and fails only when it has no
    evidence; and the gate, given that hand-over with no exception, BLOCKS in every mode. Both
    halves are run here. tests/prove_gate_policy_enforcement.py (sx_*) runs the exceptions.

SCENARIOS
    clean               0 findings, advisory off   -> exit 0  (the control)
    clean_advisory      0 findings, advisory on    -> exit 0  (the control, other mode)
    secret              3 findings, advisory off   -> exit 0, HANDED (findings_state=FINDINGS,
                                                      secret_count=3); the gate then BLOCKS
    secret_advisory     3 findings, advisory on    -> the same: advisory_mode changes nothing
                                                      (the shipped defect was the step exiting 0
                                                      and handing NOTHING over)
    collection_failed   no evidence                -> exit non-zero

EXIT
    0  every scenario decided as it must
    1  a scenario decided wrongly
    2  could not be checked -- UNKNOWN, never PASS
"""
import io
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import prove_bootstrap_failure as pbf  # noqa: E402  (shares the extraction and bash probe)

JOB, STEP = 'secret-scan', 'Enforce'


def _expand(doc):
    """The workflow with every `$/` composite step expanded into its job, as the runner sees it.

    Scanner job bodies live in `.github/actions/<scanner>/` (ledger L64); this reads the steps a
    job actually runs. One rule, tests/_composite_expand.py, for every reader.
    """
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import _composite_expand
    return _composite_expand.expanded_doc(doc)


def ctx(count, collection='COMPLETE', advisory='false'):
    return {'steps.gitleaks.outputs.count': count,
            'steps.gitleaks.outputs.collection': collection,
            'inputs.advisory_mode': advisory}


SCENARIOS = [
    ('clean', ctx('0'), True),
    ('clean_advisory', ctx('0', advisory='true'), True),
    ('secret', ctx('3'), 'HANDED'),
    ('secret_advisory', ctx('3', advisory='true'), 'HANDED'),
    ('collection_failed', ctx('', collection='COLLECTION_FAILED', advisory='true'), False),
]


def step_script():
    import yaml
    doc = _expand(yaml.safe_load(io.open(pbf.WF, encoding='utf-8')))
    for s in (doc['jobs'][JOB].get('steps') or []):
        if s.get('name') == STEP:
            return s.get('run')
    return None


def run(bash, script):
    tmp = tempfile.mkdtemp(prefix='secret-enforce-')
    try:
        out = os.path.join(tmp, 'o')
        summ = os.path.join(tmp, 's')
        io.open(out, 'w').close()
        io.open(summ, 'w').close()
        f = os.path.join(tmp, 'step.sh')
        io.open(f, 'w', encoding='utf-8', newline='\n').write(script)
        env = dict(os.environ, GITHUB_OUTPUT=out, GITHUB_STEP_SUMMARY=summ)
        p = subprocess.run([bash, f], capture_output=True, text=True, env=env, cwd=tmp)
        emitted = dict(l.rstrip('\r\n').split('=', 1) for l in io.open(out, encoding='utf-8') if '=' in l)
        return p.returncode, (p.stdout or '') + (p.stderr or ''), emitted
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


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
    script = step_script()
    if not script:
        print('UNKNOWN: no step %r in job %r.' % (STEP, JOB))
        return 2
    bad = []
    for name, values, must_pass in SCENARIOS:
        body, seen = pbf.substitute(script, values)
        unknown = sorted(k for k in seen if k not in values)
        rc, log, emitted = run(bash, body)
        print('  %-18s exit=%d findings_state=%s secret_count=%s'
              % (name, rc, emitted.get('findings_state', '-'), emitted.get('secret_count', '-')))
        if unknown:
            print('       unmodelled expression(s) resolved to empty: %s' % ', '.join(unknown))
        if must_pass is True and (rc != 0 or emitted.get('findings_state')):
            bad.append('%s: the control did not pass cleanly (exit %d, %r)' % (name, rc, emitted))
        if must_pass == 'HANDED':
            if rc != 0 or emitted.get('findings_state') != 'FINDINGS' or emitted.get('secret_count') != '3':
                bad.append('%s: the secret was not handed to the gate (exit %d, %r). A secret the gate '
                           'is not told about is a secret it can never block.' % (name, rc, emitted))
            # ...and the gate, told, BLOCKS in this mode (no exception exists).
            gate = pbf.gate_script()
            vals = pbf.ctx(advisory=values['inputs.advisory_mode'])
            vals.update({'needs.secret-scan.outputs.findings_state': emitted.get('findings_state', ''),
                         'needs.secret-scan.outputs.secret_count': emitted.get('secret_count', ''),
                         'steps.render.outputs.jobs_with_findings': 'secret-scan',
                         'steps.render.outputs.blocking_findings': '3',
                         'steps.render.outputs.secret_findings': 'a1b2c3d4e5f6 0f1e2d3c4b5a 112233445566'})
            gbody, _s = pbf.substitute(gate, vals)
            grc, gout, _glog, _gs = pbf.run(bash, gbody, pbf.gate_env(vals))
            print('  %-18s gate exit=%d secret_gate=%s' % ('', grc, gout.get('secret_gate')))
            if grc == 0 or gout.get('secret_gate') != 'FAIL':
                bad.append('%s: the gate did not block the handed secret (exit %d, secret_gate %r)'
                           % (name, grc, gout.get('secret_gate')))
        if must_pass is False and rc == 0:
            bad.append('%s: exited 0 with no evidence. No evidence is not a clean secret scan.' % name)
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: a secret finding is handed to the gate in both modes and the gate blocks it; no '
          'evidence fails the secret-scan job.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
