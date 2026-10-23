"""Shared harness for proofs that RUN a scanner job's own steps, as shipped, with the real tool.

Not a test: the leading underscore keeps tests/prove_tests_leave_tree_clean.py from running it.

THE HOUSE PATTERN (tests/prove_sast_java_detects.py, prove_secret_denominator.py, ...):
  1. extract the step from the workflow AS SHIPPED -- never a copy of it;
  2. resolve its `${{ }}` in `run:` AND in `env:` from the scenario (prove_bootstrap_failure's
     `substitute` and `resolve_env`), and report any expression the scenario did not model;
  3. run it under a bash that can actually run a script, with the REAL tool, in a throwaway
     workspace; read back $GITHUB_OUTPUT and feed it to the next step as the runner would.

TWO DELIBERATE, NAMED DIFFERENCES FROM A RUNNER, and nothing else:
  * `/tmp/` -> a sandbox directory. Every job fetches the kit's scripts into the runner's /tmp; a
    test may not write there (WP0: a proof once rmtree'd the shell's /tmp, which on Windows is the
    whole user Temp folder). The bundle is materialised from the WORKFLOW's own inlined copies and
    the single prefix is repointed, in the step and inside the scripts, exactly as
    tests/prove_redaction_chain.py does.
  * PATH is prefixed with $KIT_PROOF_TOOLBIN when set, so a developer host can point the steps at
    pinned local tool builds. On CI the tools are installed on PATH and the variable is unset.
"""
import io
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import prove_bootstrap_failure as pbf  # noqa: E402

# KIT_PROOF_WORKFLOW points a proof at another revision of the workflow (e.g. `git show
# <rev>:.github/workflows/reusable-security.yml > old.yml`), so a regression proof can be shown
# FAILING on the revision that carried the defect. Unset, the proof reads the shipped file.
WF = os.environ.get('KIT_PROOF_WORKFLOW') or pbf.WF


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
    return _expand(yaml.safe_load(io.open(WF, encoding='utf-8')))


def job(name, doc=None):
    return ((doc or load()).get('jobs') or {}).get(name) or {}


def steps_by_name(job_name, doc=None):
    return {s.get('name'): s for s in (job(job_name, doc).get('steps') or [])}


def write(path, text, mode='w'):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    if isinstance(text, bytes):
        io.open(path, 'wb').write(text)
    else:
        io.open(path, mode, encoding='utf-8', newline='\n').write(text)


def outputs(path):
    out = {}
    if not os.path.exists(path):
        return out
    for line in io.open(path, encoding='utf-8', errors='replace'):
        if '=' in line:
            k, v = line.rstrip('\n').split('=', 1)
            out[k] = v
    return out


def path_prefix(extra=None):
    parts = [p for p in (extra, os.environ.get('KIT_PROOF_TOOLBIN')) if p]
    return os.pathsep.join(parts)


def python_shim(d):
    """`python3` on a Windows host is the Store stub; the runner's python3 is the interpreter."""
    write(os.path.join(d, 'python3'),
          '#!/usr/bin/env bash\nexec "%s" "$@"\n' % sys.executable.replace('\\', '/'))
    os.chmod(os.path.join(d, 'python3'), 0o755)
    return d


def have(bash, tool, prefix=''):
    """True when `tool` resolves and runs under the bash the steps will run in."""
    env = dict(os.environ)
    if prefix:
        env['PATH'] = prefix + os.pathsep + env.get('PATH', '')
    p = subprocess.run([bash, '-c', 'command -v %s >/dev/null 2>&1' % tool], env=env,
                       capture_output=True)
    return p.returncode == 0


def materialise_bundle(d):
    """Write the workflow's OWN inlined kit scripts into `d`, `/tmp/` repointed at `d`.
    -> (posix prefix ending in '/', None) or (None, missing canonical name)."""
    sys.path.insert(0, os.path.join(ROOT, 'scripts'))
    import inline_normalizer as gen
    text = io.open(WF, encoding='utf-8').read()
    posix = d.replace(os.sep, '/').rstrip('/') + '/'
    for canon, token, tag, dest in gen.SCRIPTS:
        copies = gen.extract(text, token, canon, tag)
        if not copies:
            return None, canon
        write(os.path.join(d, os.path.basename(dest)), copies[0].replace('/tmp/', posix) + '\n')
    return posix, None


class Sandbox(object):
    """A throwaway directory holding the bundle, shims and one workspace per scenario."""

    def __init__(self, prefix):
        self.root = tempfile.mkdtemp(prefix=prefix)
        self.kit = os.path.join(self.root, 'kit')
        os.makedirs(self.kit)
        self.shim = python_shim(os.path.join(self.root, 'shim'))
        self.bundle = None
        self._n = 0

    def with_bundle(self):
        self.bundle, missing = materialise_bundle(self.kit)
        if not self.bundle:
            raise RuntimeError('the workflow carries no inlined copy of %s' % missing)
        return self

    def workspace(self, name, files=None):
        ws = os.path.join(self.root, 'ws', name)
        os.makedirs(ws)
        for rel, text in (files or {}).items():
            write(os.path.join(ws, rel), text)
        return ws

    def run(self, bash, step, values, ws, extra_path=None, env=None):
        """-> (rc, log, outputs, unmodelled expressions)."""
        body, seen = pbf.substitute(step.get('run') or '', values)
        env_extra, unknown = pbf.resolve_env(step.get('env'), values)
        unknown = sorted(set(unknown) | {k for k in seen if k not in values})
        if self.bundle:
            body = body.replace('/tmp/', self.bundle)
        self._n += 1
        meta = os.path.join(self.root, 'meta')
        os.makedirs(meta, exist_ok=True)
        out = os.path.join(meta, 'out_%d' % self._n)
        summ = os.path.join(meta, 'summary')
        io.open(out, 'w').close()
        io.open(summ, 'a').close()
        f = os.path.join(meta, 'step_%d.sh' % self._n)
        write(f, body)
        e = dict(os.environ, GITHUB_OUTPUT=out, GITHUB_STEP_SUMMARY=summ, GITHUB_WORKSPACE=ws,
                 RUNNER_TEMP=meta, PYTHONUTF8='1', PYTHONIOENCODING='utf-8', **env_extra)
        e.update(env or {})
        e['PATH'] = os.pathsep.join(p for p in (extra_path, self.shim, path_prefix(),
                                                os.environ.get('PATH', '')) if p)
        p = subprocess.run([bash, f], capture_output=True, text=True, encoding='utf-8',
                           errors='replace', env=e, cwd=ws)
        return p.returncode, (p.stdout or '') + (p.stderr or ''), outputs(out), unknown

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)
