"""Shared extraction helpers for the deploy-workflow proofs. Not a test; imported by them.

The kit's designed local proof is to extract a step from the workflow AS SHIPPED and run it under
bash with stub inputs (tests/prove_bootstrap_failure.py, tests/prove_secrets_always_block.py).
This module does that for the two deploy reusables, which pass everything through `env:` (L100):
a step's script is run verbatim, and its job-level and step-level `env:` values are resolved from
the scenario's `${{ }}` values. An expression with no scenario value resolves to '' -- exactly
what GitHub does with an absent context, so a harness gap reads as the platform's behaviour rather
than as a pass.
"""
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import prove_bootstrap_failure as pbf  # noqa: E402  (shares the proven bash probe)

WF_DIR = os.path.join(ROOT, '.github', 'workflows')
APPSERVICE = os.path.join(WF_DIR, 'reusable-deploy-appservice.yml')
CONTAINERAPP = os.path.join(WF_DIR, 'reusable-deploy-containerapp.yml')
deploy_workflows = [APPSERVICE, CONTAINERAPP]
EXPR = re.compile(r'\$\{\{\s*(.*?)\s*\}\}')


def load(path):
    import yaml
    return yaml.safe_load(io.open(path, encoding='utf-8'))


def job(doc):
    return doc['jobs']['deploy']


def steps(doc):
    return job(doc).get('steps') or []


def step_named(doc, name):
    for i, s in enumerate(steps(doc)):
        if isinstance(s, dict) and s.get('name') == name:
            return i, s
    return None, None


def inputs_of(doc):
    on = doc.get('on', doc.get(True)) or {}
    return ((on.get('workflow_call') or {}).get('inputs') or {})


def resolve(value, values):
    """Resolve every ${{ expr }} in a string from `values`; absent -> ''."""
    if not isinstance(value, str):
        if isinstance(value, bool):
            return 'true' if value else 'false'
        return '' if value is None else str(value)
    return EXPR.sub(lambda m: str(values.get(m.group(1), '')), value)


def step_env(doc, step, values):
    env = {}
    for k, v in (job(doc).get('env') or {}).items():
        env[k] = resolve(v, values)
    for k, v in (step.get('env') or {}).items():
        env[k] = resolve(v, values)
    return env


def bash():
    return pbf.usable_bash()


def run_script(bash_path, script, env_extra, cwd=None, path_prepend=None):
    """-> (rc, outputs dict, log, summary). Runs one step body in a throwaway directory."""
    tmp = tempfile.mkdtemp(prefix='deploy-step-')
    try:
        out = os.path.join(tmp, 'gh_output')
        summ = os.path.join(tmp, 'gh_summary')
        io.open(out, 'w').close()
        io.open(summ, 'w').close()
        f = os.path.join(tmp, 'step.sh')
        io.open(f, 'w', encoding='utf-8', newline='\n').write(script)
        env = dict(os.environ)
        env.update(env_extra)
        env['GITHUB_OUTPUT'] = out
        env['GITHUB_STEP_SUMMARY'] = summ
        env.setdefault('RUNNER_TEMP', tmp)
        if path_prepend:
            env['PATH'] = path_prepend + os.pathsep + env.get('PATH', '')
        p = subprocess.run([bash_path, f], capture_output=True, text=True, env=env,
                           cwd=cwd or tmp, encoding='utf-8', errors='replace')
        emitted = {}
        for line in io.open(out, encoding='utf-8', errors='replace'):
            if '=' in line:
                k, v = line.rstrip('\n').split('=', 1)
                emitted[k] = v
        return (p.returncode, emitted, (p.stdout or '') + (p.stderr or ''),
                io.open(summ, encoding='utf-8', errors='replace').read())
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
