#!/usr/bin/env python3
"""Run the code-quality job's own lint steps against seeded and clean fixtures.

WHY THIS EXISTS (validation deferral `code-quality`, expired 2026-09-30; ledger row L13)

    The deferral said: "no probe; ruff/eslint path never exercised", and named what would close it:
    "seeded lint violation fails the job; clean fixture does not". This is that probe, run the way
    the kit proves its other steps -- the step extracted from the workflow AS SHIPPED, its `${{ }}`
    inputs substituted, run under bash in a throwaway workspace with the real tools.

    Lint is not a security control, so the kit blocks on it only when the caller opts in with
    `enforce_lint: true` (and never in advisory mode). The claim proven here is therefore exact:
    WHEN ENFORCEMENT IS ON, a seeded violation is handed to the security gate as
    findings_state=FINDINGS and a clean tree hands nothing; when it is off, the same violation is
    reported and not handed. The step itself fails only when its tooling could not run: the gate is
    the single enforcement point (lane L-S, owner ruling O-24). Before, the step failed on the
    violation, the job wrote no SARIF, and the gate read a failed job with nothing on record --
    a crash, EVIDENCE_UNTRUSTED -- in every mode.

    It also checks the job reaches Node code at all. The job used to run only when discovery found
    PYTHON, and its steps keyed on the caller's `language` input rather than on what discovery found
    -- so a Node-only repository was never linted, and a `multi` caller was linted only if it also
    happened to contain Python (KNOWN_GAPS section 2).

SCENARIOS (each one the shipped step, run for real)
    ruff_clean          clean .py, enforce on          -> exit 0
    ruff_seeded         unused import, enforce on      -> exit 0, findings_state=FINDINGS (handed to
                                                          the gate: lane L-S, O-24)
    ruff_seeded_off     unused import, enforce off     -> exit 0, reported, nothing handed
    eslint_clean        clean .js, enforce on          -> exit 0
    eslint_seeded       unused variable, enforce on    -> exit 0, findings_state=FINDINGS
    eslint_seeded_off   unused variable, enforce off   -> exit 0, reported, nothing handed
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


def _expand(doc):
    """The workflow with every `$/` composite step expanded into its job, as the runner sees it.

    Scanner job bodies live in `.github/actions/<scanner>/` (ledger L64); this reads the steps a
    job actually runs. One rule, tests/_composite_expand.py, for every reader.
    """
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import _composite_expand
    return _composite_expand.expanded_doc(doc)


def load():
    import yaml
    return _expand(yaml.safe_load(io.open(pbf.WF, encoding='utf-8')))


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
    # `bash -e`: the runner's default shell for a `run:` step with none named. Under plain `bash`
    # a bare `eslint .; rc=$?` survived a lint exit 1 here and ended the step on the runner.
    p = subprocess.run([bash, '-e', f], capture_output=True, text=True, encoding='utf-8',
                       errors='replace', env=env, cwd=workspace)
    emitted = {}
    for line in io.open(out, encoding='utf-8', errors='replace'):
        if '=' in line:
            k, v = line.rstrip('\n').split('=', 1)
            emitted[k] = v
    return p.returncode, (p.stdout or '') + (p.stderr or ''), emitted


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
    if 'needs.plan.outputs.node' not in job_if:
        bad.append("job `if:` is %r -- a Node-only repository never reaches ESLint" % job_if)
    for name in (ESLINT, 'Locate the Node project', 'Setup Node'):
        s = step(doc, name)
        cond = str((s or {}).get('if') or '')
        if 'inputs.language' in cond and 'needs.plan.outputs.node' not in cond:
            bad.append('step %r keys on the caller-declared language, not on discovery: %r'
                       % (name, cond))
    s = step(doc, RUFF)
    cond = str((s or {}).get('if') or '')
    if 'inputs.language' in cond and 'needs.plan.outputs.python' not in cond:
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

        # name, step, fixture, enforce_lint, handed to the gate (findings_state=FINDINGS)?
        # Every scenario's step EXITS 0: lint findings are handed to the security gate, the single
        # enforcement point (lane L-S, O-24), never a failed job.
        scenarios = [
            ('ruff_clean', ruff_step, lambda r: py_fixture(r, PY_CLEAN), 'true', False),
            ('ruff_seeded', ruff_step, lambda r: py_fixture(r, PY_SEEDED), 'true', True),
            ('ruff_seeded_off', ruff_step, lambda r: py_fixture(r, PY_SEEDED), 'false', False),
            ('eslint_clean', eslint_step, lambda r: js_fixture(r, JS_CLEAN), 'true', False),
            ('eslint_seeded', eslint_step, lambda r: js_fixture(r, JS_SEEDED), 'true', True),
            ('eslint_seeded_off', eslint_step, lambda r: js_fixture(r, JS_SEEDED), 'false', False),
            ('eslint_no_config', eslint_step,
             lambda r: js_fixture(r, JS_SEEDED, config=False), 'true', False),
        ]
        for name, s, build, enforce, must_hand in scenarios:
            ws = os.path.join(tmp, name)
            os.makedirs(ws)
            build(ws)
            body, seen = pbf.substitute(s['run'], ctx(enforce))
            # The step's env:, resolved from the same scenario (caller inputs travel there, L38).
            rc, log, emitted = run(bash, body, ws, extra,
                                   pbf.resolve_env(s.get('env'), ctx(enforce))[0])
            handed = emitted.get('findings_state', '')
            print('  %-18s exit=%d findings_state=%s' % (name, rc, handed or '-'))
            if 'npm ERR' in log and 'ENOTFOUND' in log:
                print('UNKNOWN: npm could not reach the registry; ESLint was never installed.')
                return 2
            if rc != 0:
                bad.append('%s: exit %d -- a lint step fails only when its tool could not run; '
                           'findings go to the gate\n%s' % (name, rc, log[-600:]))
            if must_hand and handed != 'FINDINGS':
                bad.append('%s: findings_state=%r on a seeded violation with enforcement ON -- '
                           'nothing reaches the gate, so `enforce_lint` enforces nothing'
                           % (name, handed))
            if not must_hand and handed:
                bad.append('%s: findings_state=%r where nothing is enforced' % (name, handed))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: with enforce_lint on, seeded ruff and ESLint violations are handed to the gate '
          '(findings_state=FINDINGS) by steps that succeed, and clean fixtures hand nothing; with it '
          'off they are reported, not handed; Node-only repositories are reached.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
