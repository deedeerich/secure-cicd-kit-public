#!/usr/bin/env python3
"""Prove the secret scan cannot report "no secrets" over a scope in which it read nothing.

WHY THIS EXISTS (ledger L04; PIPELINE_ORDERING_AND_SCAN_VALIDITY section 5.4)

    Neither secret scanner's exit code, nor its report, can tell "read fifty thousand clean files"
    from "read nothing":

      gitleaks 8.21.2 (the pinned version), --no-git   an empty scope prints "no leaks found",
                                                       exits 0 and writes a valid SARIF with zero
                                                       results -- byte-for-byte what a clean scan
                                                       writes. It prints NO byte count in this mode.
      gitleaks, history mode                           prints "0 commits scanned." and exits 0.
      detect-secrets                                   exits 0 unconditionally; scoped to git-tracked
                                                       files by default, a failing `git ls-files` is
                                                       swallowed to an empty set; its report lists
                                                       only files WITH findings.

    The design named `scanned ~0 bytes` as the signal to wire. Measured against the pinned binary
    that string does not exist in either mode, so the design's intent is implemented the only way it
    can be: the kit establishes its own denominator -- it enumerates the scope itself and refuses
    an empty one, and in history mode it reads the commit count gitleaks DOES print.

    Each step is extracted from the workflow as shipped and run under bash with the real tools.

SCENARIOS
    tree_empty        working tree, scope holds no files   -> COLLECTION_FAILED, exit non-zero
    tree_clean        working tree, one clean file         -> count=0, files_scanned>=1, exit 0
    history_empty     history mode, repository w/o commits -> COLLECTION_FAILED, exit non-zero
    history_clean     history mode, one commit             -> count=0, commits_scanned>=1, exit 0
    ds_empty          detect-secrets over an empty scope   -> exit non-zero (nothing read)
    ds_nongit_finding detect-secrets, NOT a git checkout,
                      one file holding a credential shape  -> the finding is counted (it read files)

EXIT
    0  every scenario decided as it must
    1  a scenario decided wrongly
    2  could not be checked (no gitleaks, no detect-secrets, no bash) -- UNKNOWN, never PASS
"""
import io
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import prove_bootstrap_failure as pbf  # noqa: E402  (shared extraction and bash probe)

JOB = 'secret-scan'
RULES, GITLEAKS, DETECT = 'Write the Azure/Entra rules', 'Gitleaks (path-scoped, redacted)', \
    'detect-secrets (defense in depth)'


def steps():
    import yaml
    doc = yaml.safe_load(io.open(pbf.WF, encoding='utf-8'))
    found = {s.get('name'): s.get('run') for s in (doc['jobs'][JOB].get('steps') or [])}
    return found.get(RULES), found.get(GITLEAKS), found.get(DETECT)


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    io.open(path, 'w', encoding='utf-8', newline='\n').write(text)


def run(bash, script, ws, ctx, shim):
    body, _ = pbf.substitute(script, ctx)
    out = os.path.join(ws, '.gh_output')
    if not os.path.exists(out):
        io.open(out, 'w').close()
    summ = os.path.join(ws, '.gh_summary')
    io.open(summ, 'a').close()
    f = os.path.join(ws, '.step.sh')
    # The count site calls /tmp/sarif_validity.py from the kit bundle (L02): supply it.
    io.open(f, 'w', encoding='utf-8', newline='\n').write(pbf.with_kit_bundle(body))
    env = dict(os.environ, GITHUB_OUTPUT=out, GITHUB_STEP_SUMMARY=summ, GITHUB_WORKSPACE=ws,
               PYTHONUTF8='1', PATH=shim + os.pathsep + os.environ.get('PATH', ''),
               **pbf.env_for_run(script, ctx))
    p = subprocess.run([bash, f], capture_output=True, text=True, encoding='utf-8',
                       errors='replace', env=env, cwd=ws)
    outputs = {}
    for line in io.open(out, encoding='utf-8', errors='replace'):
        if '=' in line:
            k, v = line.rstrip('\n').split('=', 1)
            outputs[k] = v
    return p.returncode, (p.stdout or '') + (p.stderr or ''), outputs


def git(ws, *args):
    subprocess.run(['git', '-c', 'user.email=probe@example.invalid', '-c', 'user.name=probe']
                   + list(args), cwd=ws, capture_output=True, check=True)


def credential():
    """A credential-shaped value assembled at runtime, never a literal in this repository."""
    return 'AKIA' + ''.join('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'[(i * 11 + 5) % 32] for i in range(16))


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
    if not shutil.which('gitleaks') or not shutil.which('jq'):
        print('UNKNOWN: gitleaks and jq are required to RUN the step.')
        return 2
    rules, gl, ds = steps()
    if not (rules and gl and ds):
        print('UNKNOWN: a secret-scan step is missing (%r / %r / %r).' % (RULES, GITLEAKS, DETECT))
        return 2

    tmp = tempfile.mkdtemp(prefix='secret-denominator-')
    bad = []
    try:
        shim = os.path.join(tmp, 'shim')
        write(os.path.join(shim, 'python3'),
              '#!/usr/bin/env bash\nexec "%s" "$@"\n' % sys.executable.replace('\\', '/'))

        def workspace(name, files, history=None):
            ws = os.path.join(tmp, name)
            os.makedirs(os.path.join(ws, 'scope'))
            for rel, text in files.items():
                write(os.path.join(ws, 'scope', rel), text)
            if history is not None:
                git(ws, 'init', '-q')
                if history:
                    write(os.path.join(ws, 'tracked.txt'), 'hello\n')
                    git(ws, 'add', 'tracked.txt')
                    git(ws, 'commit', '-qm', 'one')
            return ws

        def gitleaks(name, files, history_mode, history=None):
            ws = workspace(name, files, history)
            ctx = {'inputs.paths': 'scope', 'inputs.scan_git_history': history_mode}
            rc, log, _ = run(bash, rules, ws, ctx, shim)
            if rc != 0:
                bad.append('%s: the rules step failed (exit %d)\n%s' % (name, rc, log[-300:]))
                return None
            return run(bash, gl, ws, ctx, shim)

        cases = [
            ('tree_empty', {}, 'false', None, False),
            ('tree_clean', {'a.txt': 'hello\n'}, 'false', None, True),
            ('history_empty', {}, 'true', False, False),
            ('history_clean', {}, 'true', True, True),
        ]
        for name, files, hist, repo, must_pass in cases:
            r = gitleaks(name, files, hist, repo)
            if r is None:
                continue
            rc, log, out = r
            print('  %-18s exit=%d collection=%-17s count=%s files=%s commits=%s'
                  % (name, rc, out.get('collection', '-'), out.get('count', '-'),
                     out.get('files_scanned', '-'), out.get('commits_scanned', '-')))
            if must_pass:
                if rc != 0 or out.get('count') != '0':
                    bad.append('%s: a clean scope must count 0 and pass (exit %d)\n%s'
                               % (name, rc, log[-400:]))
                read = out.get('commits_scanned' if hist == 'true' else 'files_scanned', '')
                if not read.isdigit() or int(read) < 1:
                    bad.append('%s: no positive denominator was emitted (%r) -- a zero that cannot '
                               'say how much it read is not a measurement' % (name, read))
            else:
                if rc == 0 or out.get('collection') != 'COLLECTION_FAILED':
                    bad.append('%s: read NOTHING and reported %s (exit %d). "No secrets found" over '
                               'an empty scope is "no files read" wearing a clean result.'
                               % (name, out.get('count', 'nothing'), rc))

        for name, files, must_find in [
                ('ds_empty', {}, None),
                ('ds_nongit_finding', {'config/settings.ini':
                                       'aws_access_key_id = %s\n' % credential()}, True)]:
            ws = workspace(name, files)
            rc, log, out = run(bash, ds, ws, {'inputs.paths': 'scope'}, shim)
            print('  %-18s exit=%d ds_count=%s ds_files=%s'
                  % (name, rc, out.get('ds_count', '-'), out.get('ds_files_scanned', '-')))
            if must_find is None and rc == 0:
                bad.append('%s: detect-secrets read nothing and passed' % name)
            if must_find and (not out.get('ds_count', '').isdigit() or int(out['ds_count']) < 1):
                bad.append('%s: outside a git checkout the seeded credential was not counted '
                           '(ds_count=%r) -- the scan read nothing\n%s'
                           % (name, out.get('ds_count'), log[-400:]))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if bad:
        for b in bad:
            print('FAIL: %s' % b)
        return 1
    print('PASS: neither secret scanner can report "no secrets" over a scope it did not read: an '
          'empty working tree or a history with no commits is COLLECTION_FAILED, a clean scope '
          'carries a positive denominator, and detect-secrets reads files without depending on git.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
