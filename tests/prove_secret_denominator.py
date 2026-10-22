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

THE SCOPE IS THE WORKSPACE ROOT, SO THE KIT MUST WRITE NOTHING INTO IT (lane L-SD)

    Since KDEC-018 (lane L-FX) the secret-scan job always hands the composite `paths: "."`. The
    scope is the checkout itself, and anything the kit writes into the working directory -- its
    rules file, logs, reports -- is counted by the denominator and read by the scanners. Hosted
    self-test job 119995060869 found the kit's own `gitleaks-azure.toml` made an empty repository
    read as "1 file scanned, 0 secrets" (this proof then counted its own harness files as well).
    So each scenario runs the steps in their shipped order -- rules, gitleaks, detect-secrets --
    with the workspace as the scope, the harness files and RUNNER_TEMP outside it, and requires the
    denominator to equal EXACTLY the number of files the consumer put there.

SCENARIOS
    tree_empty        working tree, scope holds no files   -> COLLECTION_FAILED, exit non-zero
    tree_clean        working tree, one clean file         -> count=0, files_scanned=1, exit 0
    history_empty     history mode, repository w/o commits -> COLLECTION_FAILED, exit non-zero
    history_clean     history mode, one commit             -> count=0, commits_scanned>=1, exit 0
    ds_empty          detect-secrets over an empty scope   -> exit non-zero (nothing read)
    ds_after_report   detect-secrets after gitleaks wrote
                      its report, one clean file           -> ds_files_scanned=1 (the report is the
                                                              kit's, not the consumer's)
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


def _expand(doc):
    """The workflow with every `$/` composite step expanded into its job, as the runner sees it.

    Scanner job bodies live in `.github/actions/<scanner>/` (ledger L64); this reads the steps a
    job actually runs. One rule, tests/_composite_expand.py, for every reader.
    """
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import _composite_expand
    return _composite_expand.expanded_doc(doc)


def steps():
    import yaml
    doc = _expand(yaml.safe_load(io.open(pbf.WF, encoding='utf-8')))
    found = {s.get('name'): s.get('run') for s in (doc['jobs'][JOB].get('steps') or [])}
    return found.get(RULES), found.get(GITLEAKS), found.get(DETECT)


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    io.open(path, 'w', encoding='utf-8', newline='\n').write(text)


def run(bash, script, ws, ctx, shim, harness):
    """Run one shipped step with the workspace `ws` as its working directory.

    THE WORKSPACE IS THE SCANNED SCOPE (KDEC-018: the secret-scan job always hands the composite
    `paths: "."`). So nothing the HARNESS writes may land in it -- the step file, GITHUB_OUTPUT and
    the summary live in `harness`, outside it, as the runner keeps them outside the checkout --
    and RUNNER_TEMP is a separate directory outside it too. Whatever the scope holds after a
    step is then the consumer's files plus whatever the KIT wrote there.
    """
    body, _ = pbf.substitute(script, ctx)
    os.makedirs(harness, exist_ok=True)
    out = os.path.join(harness, 'gh_output')
    io.open(out, 'w').close()
    summ = os.path.join(harness, 'gh_summary')
    io.open(summ, 'a').close()
    rtemp = os.path.join(harness, 'runner_temp')
    os.makedirs(rtemp, exist_ok=True)
    f = os.path.join(harness, 'step.sh')
    # The count site calls /tmp/sarif_validity.py from the kit bundle (L02): supply it.
    io.open(f, 'w', encoding='utf-8', newline='\n').write(pbf.with_kit_bundle(body))
    env = dict(os.environ, GITHUB_OUTPUT=out, GITHUB_STEP_SUMMARY=summ, GITHUB_WORKSPACE=ws,
               RUNNER_TEMP=rtemp, PYTHONUTF8='1',
               PATH=shim + os.pathsep + os.environ.get('PATH', ''),
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
            """-> (workspace, the set of files the CONSUMER put in it). The workspace is the scope."""
            ws = os.path.join(tmp, name, 'ws')
            os.makedirs(ws)
            for rel, text in files.items():
                write(os.path.join(ws, rel), text)
            consumer = set(files)
            if history is not None:
                git(ws, 'init', '-q')
                if history:
                    write(os.path.join(ws, 'tracked.txt'), 'hello\n')
                    git(ws, 'add', 'tracked.txt')
                    git(ws, 'commit', '-qm', 'one')
                    consumer.add('tracked.txt')
            return ws, consumer

        def foreign(ws, consumer):
            """Files in the scope the consumer did not put there: what the KIT wrote into it."""
            found = []
            for d, dirs, names in os.walk(ws):
                dirs[:] = [x for x in dirs if x != '.git']
                for n in names:
                    rel = os.path.relpath(os.path.join(d, n), ws).replace('\\', '/')
                    if rel not in consumer:
                        found.append(rel)
            return sorted(found)

        def chain(name, files, history_mode, history=None, with_ds=False):
            """The shipped order: rules, gitleaks, then (on always()) detect-secrets.

            -> dict of per-step (exit, log, outputs), plus what the kit had written into the
            scope just BEFORE each scan enumerated it.
            """
            ws, consumer = workspace(name, files, history)
            harness = os.path.join(tmp, name, 'harness')
            ctx = {'inputs.paths': '.', 'inputs.scan_git_history': history_mode}
            r = {'consumer': consumer}
            rc, log, _ = run(bash, rules, ws, ctx, shim, harness)
            if rc != 0:
                bad.append('%s: the rules step failed (exit %d)\n%s' % (name, rc, log[-300:]))
                return None
            r['before_gitleaks'] = foreign(ws, consumer)
            r['gitleaks'] = run(bash, gl, ws, ctx, shim, harness)
            if with_ds:
                r['before_ds'] = foreign(ws, consumer)
                r['ds'] = run(bash, ds, ws, ctx, shim, harness)
            return r

        cases = [
            ('tree_empty', {}, 'false', None, False),
            ('tree_clean', {'a.txt': 'hello\n'}, 'false', None, True),
            ('history_empty', {}, 'true', False, False),
            ('history_clean', {}, 'true', True, True),
        ]
        for name, files, hist, repo, must_pass in cases:
            r = chain(name, files, hist, repo)
            if r is None:
                continue
            rc, log, out = r['gitleaks']
            print('  %-18s exit=%d collection=%-17s count=%s files=%s commits=%s kit_in_scope=%s'
                  % (name, rc, out.get('collection', '-'), out.get('count', '-'),
                     out.get('files_scanned', '-'), out.get('commits_scanned', '-'),
                     ','.join(r['before_gitleaks']) or '-'))
            if r['before_gitleaks']:
                bad.append('%s: the kit wrote %s into the scanned scope before gitleaks enumerated it. '
                           'The scope is the repository root (KDEC-018): a kit file there is counted '
                           'as a file the scan read.' % (name, r['before_gitleaks']))
            if must_pass:
                if rc != 0 or out.get('count') != '0':
                    bad.append('%s: a clean scope must count 0 and pass (exit %d)\n%s'
                               % (name, rc, log[-400:]))
                if hist == 'true':
                    read = out.get('commits_scanned', '')
                    if not read.isdigit() or int(read) < 1:
                        bad.append('%s: no positive denominator was emitted (%r) -- a zero that '
                                   'cannot say how much it read is not a measurement' % (name, read))
                elif out.get('files_scanned') != str(len(r['consumer'])):
                    bad.append('%s: files_scanned=%r but the consumer put %d file(s) in the scope -- '
                               'the denominator must count the consumer\'s files and nothing else'
                               % (name, out.get('files_scanned'), len(r['consumer'])))
            else:
                if rc == 0 or out.get('collection') != 'COLLECTION_FAILED':
                    bad.append('%s: read NOTHING and reported %s (exit %d). "No secrets found" over '
                               'an empty scope is "no files read" wearing a clean result.'
                               % (name, out.get('count', 'nothing'), rc))

        for name, files, must_find in [
                ('ds_empty', {}, None),
                ('ds_after_report', {'a.txt': 'hello\n'}, False),
                ('ds_nongit_finding', {'config/settings.ini':
                                       'aws_access_key_id = %s\n' % credential()}, True)]:
            r = chain(name, files, 'false', with_ds=True)
            if r is None:
                continue
            rc, log, out = r['ds']
            print('  %-18s exit=%d ds_count=%s ds_files=%s kit_in_scope=%s'
                  % (name, rc, out.get('ds_count', '-'), out.get('ds_files_scanned', '-'),
                     ','.join(r['before_ds']) or '-'))
            if must_find is None:
                if rc == 0:
                    bad.append('%s: detect-secrets read nothing and passed (it counted %s file(s); '
                               'the kit had written %s into the scope)'
                               % (name, out.get('ds_files_scanned', '-'), r['before_ds'] or 'nothing'))
                continue
            if rc != 0:
                bad.append('%s: detect-secrets failed over a populated scope (exit %d)\n%s'
                           % (name, rc, log[-400:]))
            if out.get('ds_files_scanned') != str(len(r['consumer'])):
                bad.append('%s: ds_files_scanned=%r but the consumer put %d file(s) in the scope; '
                           'the kit had written %s there -- a kit artefact is not a file the '
                           'consumer\'s scan read' % (name, out.get('ds_files_scanned'),
                                                      len(r['consumer']), r['before_ds']))
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
          'carries a denominator equal to the consumer\'s own files (no kit artefact in the '
          'scope), and detect-secrets reads files without depending on git.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
