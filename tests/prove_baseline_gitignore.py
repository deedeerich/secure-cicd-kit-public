#!/usr/bin/env python3
"""The baseline .gitignore ignores every secret-file class it claims to, and nothing it must not.

WHY THIS EXISTS (lane L-LEAK, KDEC-031)

    A GitHub PAT leaked when a `.env` file was committed. developer-safety/gitignore/baseline.gitignore
    is the first of the leak gates (docs/adoption/LEAK_GATES.md), and its patterns were never run:
    an entry that does not match (or a negation in the wrong place) reads as protection and is none.
    This runs `git check-ignore` in a throwaway repository, so the answer is git's, not a reading.

WHAT IT PROVES
    G1  every secret-file path below is IGNORED: .env and .env.* at any depth, keys and
        certificates, *.tfstate and its backups, *.har, credentials JSON, cloud CLI caches
        (.aws, .azure, gcloud, .kube, .docker, .oci), .npmrc, .netrc, .pypirc, .git-credentials;
    G2  .env.example (at any depth) and ordinary source files are NOT ignored;
    G3  merge-baseline.sh MERGES: a repository's own entries survive, missing baseline lines are
        appended once, and a second run appends nothing (idempotent).
    G4  merge-baseline.sh never succeeds silently: each path that used to exit 0, or fail with a
        bare shell error, while merging nothing (or merging wrongly) now exits with its own code and
        named reason, and writes nothing -- REPO_DIR_MISSING (13), NOT_A_GIT_REPO (14, it used to
        create a .gitignore in any directory), BASELINE_UNREADABLE (12, an empty baseline used to
        report "already carries every baseline pattern"), PREREQUISITE_UNAVAILABLE (11, grep or
        tail not on PATH), TARGET_NOT_WRITABLE (15), FITNESS_FAILED (17: a grep that never matches used to make
        it append every pattern again on every run and exit 0), and MERGE_NOT_VERIFIED (16: a
        written file that does not carry every pattern after the merge).

EXIT  0 all hold   1 any does not   2 git unavailable -- UNKNOWN
"""
import io
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BASELINE = os.path.join(ROOT, 'developer-safety', 'gitignore', 'baseline.gitignore')
MERGE = os.path.join(ROOT, 'developer-safety', 'gitignore', 'merge-baseline.sh')
FAILS = []

MUST_IGNORE = [
    '.env', 'app/.env', 'a/b/.env', '.env.local', '.env.production', 'web/.env.dev', '.env.test',
    'id_rsa', 'keys/id_ed25519', 'id_ecdsa', 'server.pem', 'tls.key', 'c.pfx', 'c.p12', 'release.jks',
    'terraform.tfstate', 'infra/terraform.tfstate.backup', 'traces/login.har', 'session.har',
    'credentials.json', 'gcp-credentials.json', 'svc/aws-credentials-prod.json',
    '.aws/credentials', '.azure/accessTokens.json', '.config/gcloud/credentials.db',
    '.kube/config', '.docker/config.json', '.oci/config', '.npmrc', 'web/.npmrc', '.netrc',
    '.pypirc', '.git-credentials', '.terraform.d/credentials.tfrc.json',
]
MUST_TRACK = [
    '.env.example', 'app/.env.example', 'src/app.py', 'README.md', 'package.json',
    'docs/env.md', '.vscode/extensions.json', 'gradle/wrapper/gradle-wrapper.jar',
    '.github/workflows/security.yml',
]


def check(cond, msg, detail=()):
    print('  %s %s' % ('PASS' if cond else 'FAIL', msg))
    if not cond:
        for d in detail:
            print('       %s' % d)
        FAILS.append(msg)


def git(cwd, *args, **kw):
    return subprocess.run(['git', '-c', 'core.excludesFile=', '-c', 'init.defaultBranch=main'] + list(args),
                          cwd=cwd, capture_output=True, text=True, timeout=60, **kw)


def ignored(repo, paths):
    """-> the subset of `paths` git ignores, from one `check-ignore --no-index --stdin` call."""
    # Bytes, not text: a text-mode pipe on Windows writes CRLF, and git would read `.env\r`.
    p = subprocess.run(['git', '-c', 'core.excludesFile=', 'check-ignore', '--no-index', '--stdin'],
                       cwd=repo, input=('\n'.join(paths) + '\n').encode('utf-8'),
                       capture_output=True, timeout=60)
    return set(ln.strip() for ln in p.stdout.decode('utf-8', 'replace').splitlines() if ln.strip())


def bash():
    """A REAL bash (never the WSL launcher stub): tests/prove_bootstrap_failure.py usable_bash."""
    sys.path.insert(0, HERE)
    import prove_bootstrap_failure as pbf
    return pbf.usable_bash()[0]


def g4(b, work):
    """merge-baseline.sh refuses, by name, every case it used to pass silently or fail unnamed."""
    script = MERGE.replace('\\', '/')

    def run(target, script_path=script, path=None):
        env = dict(os.environ)
        if path is not None:
            env['PATH'] = path
        return subprocess.run([b, script_path, target.replace('\\', '/')], capture_output=True,
                              text=True, timeout=60, env=env)

    def expect(label, p, code, reason, unchanged=None):
        ok = p.returncode == code and reason in p.stderr
        detail = ['rc=%d' % p.returncode, 'stdout: ' + p.stdout.strip()[-300:], 'stderr: ' + p.stderr.strip()[-300:]]
        if unchanged is not None:
            path, before = unchanged
            now = io.open(path, encoding='utf-8').read() if os.path.isfile(path) else None
            ok = ok and now == before
            detail.append('.gitignore %s' % ('unchanged' if now == before else 'CHANGED or created'))
        check(ok, 'G4 %s: exit %d %s, nothing written (rc=%d)' % (label, code, reason, p.returncode), detail)

    def fresh_repo(name, gitignore='own/\n'):
        d = os.path.join(work, name)
        os.makedirs(d)
        git(d, 'init', '-q')
        if gitignore is not None:
            io.open(os.path.join(d, '.gitignore'), 'w', newline='\n').write(gitignore)
        return d

    missing = os.path.join(work, 'no-such-dir')
    expect('REPO_DIR does not exist', run(missing), 13, 'REPO_DIR_MISSING')
    check(not os.path.exists(missing), 'G4 a missing REPO_DIR is not created')

    plain = os.path.join(work, 'plain-dir')
    os.makedirs(plain)
    expect('REPO_DIR is not a git repository', run(plain), 14, 'NOT_A_GIT_REPO',
           (os.path.join(plain, '.gitignore'), None))

    # An empty (comments-only) baseline beside a copy of the script.
    kit = os.path.join(work, 'kit-empty-baseline')
    os.makedirs(kit)
    shutil.copy(MERGE, os.path.join(kit, 'merge-baseline.sh'))
    io.open(os.path.join(kit, 'baseline.gitignore'), 'w', newline='\n').write('# nothing here\n\n')
    r = fresh_repo('repo-empty-baseline')
    expect('the baseline holds no pattern', run(r, os.path.join(kit, 'merge-baseline.sh').replace('\\', '/')),
           12, 'BASELINE_UNREADABLE', (os.path.join(r, '.gitignore'), 'own/\n'))
    os.remove(os.path.join(kit, 'baseline.gitignore'))
    expect('the baseline is missing', run(r, os.path.join(kit, 'merge-baseline.sh').replace('\\', '/')),
           12, 'BASELINE_UNREADABLE', (os.path.join(r, '.gitignore'), 'own/\n'))

    # No grep / tr / tail / od on PATH: the old script treated a missing grep as "not present".
    empty_bin = os.path.join(work, 'empty-bin')
    os.makedirs(empty_bin)
    r = fresh_repo('repo-no-tools')
    expect('a tool it needs is not on PATH', run(r, path=empty_bin), 11, 'PREREQUISITE_UNAVAILABLE',
           (os.path.join(r, '.gitignore'), 'own/\n'))

    # .gitignore is a directory: it cannot be read or appended to.
    r = fresh_repo('repo-dir-target', gitignore=None)
    os.makedirs(os.path.join(r, '.gitignore'))
    expect('.gitignore is not a writable file', run(r), 15, 'TARGET_NOT_WRITABLE')

    # A grep that never matches: the old script appended every pattern on every run and exited 0.
    # The script now self-tests grep before it writes (17), and re-reads what it wrote (16).
    def grep_stub(name, body):
        d = os.path.join(work, name)
        os.makedirs(d)
        stub = os.path.join(d, 'grep')
        io.open(stub, 'w', newline='\n').write(body)
        os.chmod(stub, 0o755)
        return d + os.pathsep + os.environ.get('PATH', '')

    r = fresh_repo('repo-broken-grep')
    p = run(r, path=grep_stub('broken-bin', '#!/bin/sh\nexit 1\n'))
    expect('a grep that never matches', p, 17, 'FITNESS_FAILED', (os.path.join(r, '.gitignore'), 'own/\n'))
    # This grep passes the self-test (it delegates to the real grep for the self-test's needle) and
    # lies about every real line: only the re-read after writing can catch it.
    r = fresh_repo('repo-liar-grep')
    p = run(r, path=grep_stub('liar-bin', '#!/bin/sh\nfor a in "$@"; do\n  if [ "$a" = __merge_baseline_selftest__ ]; then\n'
                                          '    PATH="${PATH#*:}"; export PATH; exec grep "$@"\n  fi\ndone\nexit 1\n'))
    check(p.returncode == 16 and 'MERGE_NOT_VERIFIED' in p.stderr,
          'G4 a grep that lies after its self-test: exit 16 MERGE_NOT_VERIFIED, not a silent success (rc=%d)'
          % p.returncode, ['stdout: ' + p.stdout.strip()[-300:], 'stderr: ' + p.stderr.strip()[-300:]])


def main():
    if not shutil.which('git'):
        print('UNKNOWN: git unavailable.')
        return 2
    work = tempfile.mkdtemp(prefix='baseline-gitignore-')
    try:
        repo = os.path.join(work, 'repo')
        os.makedirs(repo)
        git(repo, 'init', '-q')
        shutil.copy(BASELINE, os.path.join(repo, '.gitignore'))
        got = ignored(repo, MUST_IGNORE + MUST_TRACK)
        missed = [p for p in MUST_IGNORE if p not in got]
        check(not missed, 'G1 every secret-file path is ignored (%d paths)' % len(MUST_IGNORE), missed)
        wrong = [p for p in MUST_TRACK if p in got]
        check(not wrong, 'G2 .env.example and ordinary files are not ignored (%d paths)' % len(MUST_TRACK),
              wrong)

        # G3: merge into a repository that already has its own .gitignore.
        b = bash()
        if not b or not os.path.isfile(MERGE):
            check(False, 'G3 merge-baseline.sh exists and bash is available')
        else:
            repo2 = os.path.join(work, 'repo2')
            os.makedirs(repo2)
            git(repo2, 'init', '-q')
            own = 'local-only/\n.env\n*.log\n'
            io.open(os.path.join(repo2, '.gitignore'), 'w', newline='\n').write(own)
            script = MERGE.replace('\\', '/')
            r1 = subprocess.run([b, script, '.'], cwd=repo2, capture_output=True, text=True, timeout=60)
            after1 = io.open(os.path.join(repo2, '.gitignore'), encoding='utf-8').read()
            r2 = subprocess.run([b, script, '.'], cwd=repo2, capture_output=True, text=True, timeout=60)
            after2 = io.open(os.path.join(repo2, '.gitignore'), encoding='utf-8').read()
            lines = after1.splitlines()
            check(r1.returncode == 0 and r2.returncode == 0,
                  'G3 merge-baseline.sh exits 0 twice (rc=%d,%d)' % (r1.returncode, r2.returncode),
                  [(r1.stderr + r2.stderr).strip()[-300:]])
            check(after1.startswith(own), "G3 the repository's own entries survive, first and unchanged")
            check(lines.count('.env') == 1, 'G3 a line already present is not appended again')
            check('!.env.example' in lines and '*.har' in lines, 'G3 missing baseline lines are appended')
            check(after1 == after2, 'G3 a second run appends nothing (idempotent)')
            got2 = ignored(repo2, MUST_IGNORE + MUST_TRACK)
            check(all(p in got2 for p in MUST_IGNORE) and not any(p in got2 for p in MUST_TRACK),
                  'G3 the merged file ignores exactly what the baseline does for these paths')
            g4(b, work)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    print()
    if FAILS:
        print('FAIL: %d check(s).' % len(FAILS))
        return 1
    print('PASS: git ignores every secret-file class in the baseline and keeps .env.example tracked; '
          'the merge script merges.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
