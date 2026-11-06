"""Shared harness: run ONE `run:` step of a shipped workflow or composite, as GitHub would.

Not a test (the leading underscore keeps tests/prove_tests_leave_tree_clean.py from running it).

What "as GitHub would" means here, and what it does not:

  - The step is read from the file AS SHIPPED. Nothing is re-typed into the test.
  - Every `${{ expr }}` in the step's `env:` and `run:` is replaced by the scenario's value, and an
    expression the scenario does not supply becomes '' -- exactly what GitHub renders for a context
    that is absent. Raising instead would hide the defect class where a step reads an output nobody
    produced.
  - The shell is the one GitHub uses: `bash -e {0}` for a workflow step with no `shell:`, and
    `bash --noprofile --norc -eo pipefail {0}` for `shell: bash` (always the case in a composite).
    A probe that ran the body under a laxer shell would pass a step that dies on the runner.
  - GITHUB_OUTPUT, GITHUB_ENV and GITHUB_STEP_SUMMARY are real files, read back afterwards.
  - Tools are either real (on PATH) or SHIMS written by the caller into a directory that is put
    first on PATH. A shim is a fixture, and each probe says which tools it shims and why.
  - Hosted runners are UTF-8; a Windows host's code page is not a kit fact, so the step gets
    PYTHONUTF8=1 and output is decoded as UTF-8.
"""
import io
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

EXPR = re.compile(r'\$\{\{\s*(.*?)\s*\}\}')


def _expand(doc):
    """The workflow with every `$/` composite step expanded into its job, as the runner sees it.

    Scanner job bodies live in `.github/actions/<scanner>/` (ledger L64); this reads the steps a
    job actually runs. One rule, tests/_composite_expand.py, for every reader.
    """
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import _composite_expand
    return _composite_expand.expanded_doc(doc)


def load(path):
    import yaml
    return _expand(yaml.safe_load(io.open(os.path.join(ROOT, path), encoding='utf-8')))


def step(path, job, key):
    """The step whose `id` or `name` is `key`, from job `job` (or a composite when job is None)."""
    doc = load(path)
    steps = (doc['runs']['steps'] if job is None else doc['jobs'][job].get('steps')) or []
    for s in steps:
        if s.get('id') == key or s.get('name') == key:
            s = dict(s)
            # Job-level env reaches every step of the job, as on the runner (step env wins).
            s['_job_env'] = {} if job is None else (doc['jobs'][job].get('env') or {})
            return s
    return None


def substitute(text, ctx):
    seen = set()

    def sub(m):
        seen.add(m.group(1))
        v = ctx.get(m.group(1), '')
        return 'true' if v is True else 'false' if v is False else str(v)
    return EXPR.sub(sub, str(text)), seen


def usable_bash():
    import prove_bootstrap_failure as pbf
    return pbf.usable_bash()


def shim(dirpath, name, body):
    """Write an executable bash shim `name` whose body is `body`."""
    os.makedirs(dirpath, exist_ok=True)
    p = os.path.join(dirpath, name)
    io.open(p, 'w', encoding='utf-8', newline='\n').write('#!/usr/bin/env bash\n' + body + '\n')
    os.chmod(p, 0o755)
    return p


def read_kv(path):
    out = {}
    if not os.path.exists(path):
        return out
    lines = io.open(path, encoding='utf-8', errors='replace').read().split('\n')
    i = 0
    while i < len(lines):
        line = lines[i]
        m = re.match(r'^([A-Za-z0-9_.-]+)<<(\S+)$', line)
        if m:
            buf, i = [], i + 1
            while i < len(lines) and lines[i] != m.group(2):
                buf.append(lines[i])
                i += 1
            out[m.group(1)] = '\n'.join(buf)
        elif '=' in line:
            k, v = line.split('=', 1)
            out[k] = v
        i += 1
    return out


def run(bash, s, ctx, ws, shim_dir=None, extra_env=None, composite=False):
    """Run step `s` in workspace `ws`. -> dict(rc, log, outputs, env, summary)."""
    body, _ = substitute(s.get('run') or '', ctx)
    env = dict(os.environ)
    for k, v in (s.get('_job_env') or {}).items():
        env[str(k)] = substitute(v, ctx)[0]
    for k, v in (s.get('env') or {}).items():
        env[str(k)] = substitute(v, ctx)[0]
    files = {}
    for k in ('GITHUB_OUTPUT', 'GITHUB_ENV', 'GITHUB_STEP_SUMMARY', 'GITHUB_PATH'):
        files[k] = os.path.join(ws, '.%s_%d' % (k.lower(), len(os.listdir(ws))))
        io.open(files[k], 'w').close()
        env[k] = files[k]
    env.update(GITHUB_WORKSPACE=ws, PYTHONUTF8='1', PYTHONIOENCODING='utf-8')
    if shim_dir:
        env['PATH'] = shim_dir + os.pathsep + env.get('PATH', '')
    env.update(extra_env or {})
    script = os.path.join(ws, '.step_%d.sh' % len(os.listdir(ws)))
    io.open(script, 'w', encoding='utf-8', newline='\n').write(body)
    explicit = composite or s.get('shell') == 'bash'
    argv = [bash, '--noprofile', '--norc', '-eo', 'pipefail', script] if explicit \
        else [bash, '-e', script]
    p = subprocess.run(argv, capture_output=True, text=True, encoding='utf-8', errors='replace',
                       env=env, cwd=ws)
    return {'rc': p.returncode, 'log': (p.stdout or '') + (p.stderr or ''),
            'outputs': read_kv(files['GITHUB_OUTPUT']), 'env': read_kv(files['GITHUB_ENV']),
            'summary': io.open(files['GITHUB_STEP_SUMMARY'], encoding='utf-8',
                               errors='replace').read()}
