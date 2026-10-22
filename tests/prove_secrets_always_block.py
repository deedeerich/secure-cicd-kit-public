#!/usr/bin/env python3
"""Run the secret-scan job's own Enforce step and prove a secret finding fails it in every mode.

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

SCENARIOS
    clean               0 findings, advisory off   -> exit 0  (the control)
    clean_advisory      0 findings, advisory on    -> exit 0  (the control, other mode)
    secret              3 findings, advisory off   -> exit non-zero
    secret_advisory     3 findings, advisory on    -> exit non-zero   <- the shipped defect
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
    ('secret', ctx('3'), False),
    ('secret_advisory', ctx('3', advisory='true'), False),
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
        return p.returncode, (p.stdout or '') + (p.stderr or '')
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
        rc, log = run(bash, body)
        print('  %-18s exit=%d' % (name, rc))
        if unknown:
            print('       unmodelled expression(s) resolved to empty: %s' % ', '.join(unknown))
        if must_pass and rc != 0:
            bad.append('%s: the control did not pass (exit %d)' % (name, rc))
        if not must_pass and rc == 0:
            bad.append('%s: exited 0. A secret finding the job reports as success is a secret '
                       'the gate can never block.' % name)
    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: a secret finding fails the secret-scan job in both modes, so the gate always sees it.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
