"""Run a scanner job's own steps, AS SHIPPED, inside a Linux container (lane L-SCAN-B, KDEC-026).

Not a test: the leading underscore keeps tests/prove_tests_leave_tree_clean.py from running it.

WHY A CONTAINER. tests/_scan_step_harness.py runs steps under the host's bash with the real tool on
PATH. mobsfscan (Semgrep 1.172.0 underneath), CMake, bear and an Ubuntu cppcheck do not run on a
Windows host, and a proof that installs them into its host is not allowed (a proof does not mutate
the machine it runs on). So the step text is extracted exactly as tests/_scan_step_harness.py
extracts it -- the composite expanded into the job, `${{ }}` resolved from the scenario in `run:`
and `env:` -- and executed by `docker exec` in ONE long-lived container per proof, so a step that
installs (sast-mobile's pinned mobsfscan) leaves the tool for the next step exactly as a runner does.

THE SAME DELIBERATE DIFFERENCES AS THE HOST HARNESS, and nothing else:
  * `/tmp/` -> /kit/, where the workflow's OWN inlined kit scripts are materialised;
  * $GITHUB_PATH is honoured between steps (the runner prepends it to PATH for later steps).

A missing docker, or an image that cannot be built, is UNKNOWN (exit 2), never PASS.
"""
import io
import os
import shutil
import subprocess
import sys
import tempfile
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import prove_bootstrap_failure as pbf  # noqa: E402
import _scan_step_harness as h  # noqa: E402


def docker_ok():
    try:
        p = subprocess.run(['docker', 'version', '--format', '{{.Server.Version}}'],
                           capture_output=True, text=True, timeout=60)
        return p.returncode == 0 and bool(p.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        return False


def build_image(tag, dockerfile):
    """Build `tag` from a Dockerfile text (cached by docker after the first build)."""
    p = subprocess.run(['docker', 'build', '-q', '-t', tag, '-'], input=dockerfile,
                       capture_output=True, text=True, timeout=1800)
    return p.returncode == 0, (p.stdout or '') + (p.stderr or '')


def _posix(p):
    return p.replace(os.sep, '/')


class Container(object):
    """One container, one workspace, the kit bundle at /kit, an action directory at /action."""

    def __init__(self, image, action_dir=None, prefix='kit-docker-'):
        self.root = tempfile.mkdtemp(prefix=prefix)
        self.ws = os.path.join(self.root, 'ws')
        self.kit = os.path.join(self.root, 'kit')
        self.meta = os.path.join(self.root, 'meta')
        for d in (self.ws, self.kit, self.meta):
            os.makedirs(d)
        # The workflow's own inlined scripts, repointed from the host sandbox path to /kit/.
        posix, missing = h.materialise_bundle(self.kit)
        if not posix:
            raise RuntimeError('the workflow carries no inlined copy of %s' % missing)
        for n in os.listdir(self.kit):
            fp = os.path.join(self.kit, n)
            t = io.open(fp, encoding='utf-8').read().replace(posix, '/kit/')
            io.open(fp, 'w', encoding='utf-8', newline='\n').write(t)
        self.name = 'kitproof-' + uuid.uuid4().hex[:12]
        args = ['docker', 'run', '-d', '--name', self.name,
                '-v', '%s:/ws' % self.ws, '-v', '%s:/kit' % self.kit, '-v', '%s:/meta' % self.meta]
        if action_dir:
            args += ['-v', '%s:/action:ro' % action_dir]
        args += ['-w', '/ws', image, 'sleep', 'infinity']
        p = subprocess.run(args, capture_output=True, text=True, timeout=300)
        if p.returncode != 0:
            raise RuntimeError('docker run failed: %s' % (p.stderr or p.stdout))
        self.path_extra = []
        self.env_carry = {}
        self._n = 0

    def reset_workspace(self, files=None):
        """Empty /ws (from inside: files the container wrote are root-owned) and plant `files`."""
        subprocess.run(['docker', 'exec', self.name, 'sh', '-c', 'rm -rf /ws/* /ws/.[!.]* 2>/dev/null; true'],
                       capture_output=True, timeout=120)
        for rel, text in (files or {}).items():
            h.write(os.path.join(self.ws, rel), text)

    def sh(self, cmd, timeout=600):
        p = subprocess.run(['docker', 'exec', self.name, 'bash', '-c', cmd], capture_output=True,
                           text=True, encoding='utf-8', errors='replace', timeout=timeout)
        return p.returncode, (p.stdout or '') + (p.stderr or '')

    def run(self, step, values, env=None, body_edit=None, timeout=1200):
        """-> (rc, log, outputs, unmodelled expressions). `body_edit` mutates the step text (fault
        injection only; a scenario that uses it says so)."""
        body, seen = pbf.substitute(step.get('run') or '', values)
        env_extra, unknown = pbf.resolve_env(step.get('env'), values)
        unknown = sorted(set(unknown) | {k for k in seen if k not in values})
        body = body.replace('/tmp/', '/kit/')
        if body_edit:
            body = body_edit(body)
        shell = (step.get('shell') or 'bash -e {0}')
        flags = '-e' if '-e' in shell.split('{0}')[0] else ''
        self._n += 1
        n = self._n
        io.open(os.path.join(self.meta, 'out_%d' % n), 'w').close()
        io.open(os.path.join(self.meta, 'path_%d' % n), 'w').close()
        io.open(os.path.join(self.meta, 'env_%d' % n), 'w').close()
        summ = os.path.join(self.meta, 'summary')
        io.open(summ, 'a').close()
        h.write(os.path.join(self.meta, 'step_%d.sh' % n), body)
        e = {'GITHUB_OUTPUT': '/meta/out_%d' % n, 'GITHUB_STEP_SUMMARY': '/meta/summary',
             'GITHUB_PATH': '/meta/path_%d' % n, 'GITHUB_ENV': '/meta/env_%d' % n,
             'GITHUB_WORKSPACE': '/ws',
             'RUNNER_TEMP': '/rt', 'GITHUB_ACTION_PATH': '/action',
             'PYTHONUTF8': '1'}
        e.update(self.env_carry)
        e.update(env_extra)
        e.update(env or {})
        args = ['docker', 'exec', '-w', '/ws']
        for k, v in e.items():
            args += ['-e', '%s=%s' % (k, v)]
        pre = 'mkdir -p /rt; '
        if self.path_extra:
            pre += 'export PATH="%s:$PATH"; ' % ':'.join(self.path_extra)
        args += [self.name, 'bash', '-c', pre + 'exec bash %s /meta/step_%d.sh' % (flags, n)]
        p = subprocess.run(args, capture_output=True, text=True, encoding='utf-8', errors='replace',
                           timeout=timeout)
        for line in io.open(os.path.join(self.meta, 'path_%d' % n), encoding='utf-8'):
            if line.strip() and line.strip() not in self.path_extra:
                self.path_extra.insert(0, line.strip())
        for line in io.open(os.path.join(self.meta, 'env_%d' % n), encoding='utf-8'):
            if '=' in line:
                k, v = line.rstrip('\n').split('=', 1)
                self.env_carry[k] = v
        return (p.returncode, (p.stdout or '') + (p.stderr or ''),
                h.outputs(os.path.join(self.meta, 'out_%d' % n)), unknown)

    def summary(self):
        p = os.path.join(self.meta, 'summary')
        return io.open(p, encoding='utf-8', errors='replace').read() if os.path.exists(p) else ''

    def close(self):
        subprocess.run(['docker', 'rm', '-f', self.name], capture_output=True, timeout=120)
        # Files the container wrote as root are removable by the host on Docker Desktop.
        shutil.rmtree(self.root, ignore_errors=True)
