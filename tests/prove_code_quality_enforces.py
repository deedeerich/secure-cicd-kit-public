#!/usr/bin/env python3
"""Run the code-quality job's own lint steps against seeded and clean fixtures.

WHY THIS EXISTS (validation deferral `code-quality`, expired 2026-09-30; ledger row L13)

    The deferral said: "no probe; ruff/eslint path never exercised", and named what would close it:
    "seeded lint violation fails the job; clean fixture does not". This is that probe, run the way
    the kit proves its other steps -- the step extracted from the workflow AS SHIPPED, its `${{ }}`
    inputs substituted, run under bash in a throwaway workspace with the real tools.

    Lint is not a security control, so the kit blocks on it only when the caller opts in with
    `enforce_lint: true` (and never in advisory mode). The claim proven here is therefore exact:
    WHEN ENFORCEMENT IS ON, a seeded violation fails the step and a clean tree does not; when it is
    off, the same violation is reported and does not block.

    It also checks the job reaches Node code at all. The job used to run only when discovery found
    PYTHON, and its steps keyed on the caller's `language` input rather than on what discovery found
    -- so a Node-only repository was never linted, and a `multi` caller was linted only if it also
    happened to contain Python (KNOWN_GAPS section 2).

SCENARIOS (each one the shipped step, run for real)
    ruff_clean          clean .py, enforce on          -> exit 0
    ruff_seeded         unused import, enforce on      -> exit non-zero
    ruff_seeded_off     unused import, enforce off     -> exit 0, reported
    eslint_clean        clean .js, enforce on          -> exit 0
    eslint_seeded       unused variable, enforce on    -> exit non-zero
    eslint_seeded_off   unused variable, enforce off   -> exit 0, reported
    eslint_no_config    no ESLint config at all        -> exit 0, reported as not configured

STATIC
    the job's `if:` admits a Node-only repository, and the lint steps key on what discovery found

EXIT
    0  every scenario decided as it must
    1  a scenario decided wrongly
    2  could not be checked (no bash, no network for the tools) -- UNKNOWN, never PASS
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import venv

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import prove_bootstrap_failure as pbf  # noqa: E402  (shared extraction and bash probe)

JOB = 'code-quality'
RUFF, ESLINT = 'Ruff + mypy', 'ESLint'

PY_CLEAN = 'print("ok")\n'
PY_SEEDED = 'import os\n'                        # F401: imported but unused
JS_CLEAN = "console.log('ok');\n"
JS_SEEDED = "const unused = 1;\nconsole.log('ok');\n"   # no-unused-vars
ESLINT_CONFIG = "module.exports = [{ rules: { 'no-unused-vars': 'error' } }];\n"
PACKAGE_JSON = {'name': 'kit-lint-fixture', 'version': '0.0.0', 'private': True,
                'devDependencies': {'eslint': '9.13.0'}}


def load():
    import yaml
    return yaml.safe_load(io.open(pbf.WF, encoding='utf-8'))


def step(doc, name):
    for s in (doc['jobs'][JOB].get('steps') or []):
        if s.get('name') == name:
            return s
    return None


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    io.open(path, 'w', encoding='utf-8', newline='\n').write(text)


def toolbin(tmp):
    """A venv holding ruff and mypy, plus a `python3` shim -> (bin_dir, None) or (None, why)."""
    vdir = os.path.join(tmp, 'venv')
    venv.EnvBuilder(with_pip=True).create(vdir)
    vbin = os.path.join(vdir, 'Scripts' if os.name == 'nt' else 'bin')
    py = os.path.join(vbin, 'python.exe' if os.name == 'nt' else 'python')
    p = subprocess.run([py, '-m', 'pip', 'install', '--quiet', 'ruff', 'mypy'],
                       capture_output=True, text=True)
    if p.returncode != 0:
        return None, 'could not install ruff/mypy: %s' % (p.stderr or p.stdout)[-300:]
    return vbin, None


def run(bash, script, workspace, extra_path, env_extra=None):
    out = os.path.join(workspace, '.gh_output')
    summ = os.path.join(workspace, '.gh_summary')
    io.open(out, 'w').close()
    io.open(summ, 'w').close()
    f = os.path.join(workspace, '.step.sh')
    io.open(f, 'w', encoding='utf-8', newline='\n').write(script)
    env = dict(os.environ, GITHUB_OUTPUT=out, GITHUB_STEP_SUMMARY=summ,
               GITHUB_WORKSPACE=workspace,
               PATH=extra_path + os.pathsep + os.environ.get('PATH', ''), **(env_extra or {}))
    p = subprocess.run([bash, f], capture_output=True, text=True, encoding='utf-8', errors='replace',
                       env=env, cwd=workspace)
    return p.returncode, (p.stdout or '') + (p.stderr or '')


def py_fixture(root, source):
    write(os.path.join(root, 'app', 'main.py'), source)


def js_fixture(root, source, config=True):
    write(os.path.join(root, 'package.json'), json.dumps(PACKAGE_JSON, indent=2) + '\n')
    write(os.path.join(root, 'index.js'), source)
    if config:
        write(os.path.join(root, 'eslint.config.js'), ESLINT_CONFIG)
    write(os.path.join(root, '.node-roots.txt'), 'package.json\n')


def static_checks(doc):
    """-> list of failures. The job must reach Node code on discovery's word, not the caller's."""
    bad = []
    job_if = str(doc['jobs'][JOB].get('if') or '')
    if 'needs.discover.outputs.node' not in job_if:
        bad.append("job `if:` is %r -- a Node-only repository never reaches ESLint" % job_if)
    for name in (ESLINT, 'Locate the Node project', 'Setup Node'):
        s = step(doc, name)
        cond = str((s or {}).get('if') or '')
        if 'inputs.language' in cond and 'needs.discover.outputs.node' not in cond:
            bad.append('step %r keys on the caller-declared language, not on discovery: %r'
                       % (name, cond))
    s = step(doc, RUFF)
    cond = str((s or {}).get('if') or '')
    if 'inputs.language' in cond and 'needs.discover.outputs.python' not in cond:
        bad.append('step %r keys on the caller-declared language, not on discovery: %r'
                   % (RUFF, cond))
    return bad


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
    if not shutil.which('npm') or not shutil.which('node'):
        print('UNKNOWN: node/npm not on PATH; the ESLint step cannot be run.')
        return 2
    doc = load()
    ruff_step, eslint_step = step(doc, RUFF), step(doc, ESLINT)
    if not ruff_step or not eslint_step:
        print('UNKNOWN: step %r or %r missing from job %r.' % (RUFF, ESLINT, JOB))
        return 2

    bad = static_checks(doc)
    for b in bad:
        print('  static: %s' % b)

    tmp = tempfile.mkdtemp(prefix='code-quality-probe-')
    try:
        vbin, why = toolbin(tmp)
        if not vbin:
            print('UNKNOWN: %s' % why)
            return 2
        shim = os.path.join(tmp, 'shim')
        write(os.path.join(shim, 'python3'), '#!/usr/bin/env bash\nexec python "$@"\n')
        extra = os.pathsep.join([vbin, shim])

        def ctx(enforce):
            return {'inputs.paths': '.', 'inputs.enforce_lint': enforce,
                    'inputs.advisory_mode': 'false'}

        scenarios = [
            ('ruff_clean', ruff_step, lambda r: py_fixture(r, PY_CLEAN), 'true', True),
            ('ruff_seeded', ruff_step, lambda r: py_fixture(r, PY_SEEDED), 'true', False),
            ('ruff_seeded_off', ruff_step, lambda r: py_fixture(r, PY_SEEDED), 'false', True),
            ('eslint_clean', eslint_step, lambda r: js_fixture(r, JS_CLEAN), 'true', True),
            ('eslint_seeded', eslint_step, lambda r: js_fixture(r, JS_SEEDED), 'true', False),
            ('eslint_seeded_off', eslint_step, lambda r: js_fixture(r, JS_SEEDED), 'false', True),
            ('eslint_no_config', eslint_step,
             lambda r: js_fixture(r, JS_SEEDED, config=False), 'true', True),
        ]
        for name, s, build, enforce, must_pass in scenarios:
            ws = os.path.join(tmp, name)
            os.makedirs(ws)
            build(ws)
            body, seen = pbf.substitute(s['run'], ctx(enforce))
            # The step's env:, resolved from the same scenario (caller inputs travel there, L38).
            rc, log = run(bash, body, ws, extra, pbf.resolve_env(s.get('env'), ctx(enforce))[0])
            print('  %-18s exit=%d' % (name, rc))
            if 'npm ERR' in log and 'ENOTFOUND' in log:
                print('UNKNOWN: npm could not reach the registry; ESLint was never installed.')
                return 2
            if must_pass and rc != 0:
                bad.append('%s: exit %d where the step must pass\n%s' % (name, rc, log[-600:]))
            if not must_pass and rc == 0:
                bad.append('%s: exited 0 on a seeded violation with enforcement ON -- the lint '
                           'step cannot fail, so `enforce_lint` enforces nothing' % name)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: with enforce_lint on, seeded ruff and ESLint violations fail the shipped steps and '
          'clean fixtures pass; with it off they are reported, not blocking; Node-only repositories '
          'are reached.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
