#!/usr/bin/env python3
"""Run every test in a throwaway clone and fail if any of them changes a tracked file (N51).

WHY THIS EXISTS

    A test that rewrites a tracked file is a test that can leave the repository wrong. The kit had
    several: prove_ticket_idempotency.py replaced scripts/ticket_model.py with mutants in place and
    restored it only in a `finally` -- so a killed or concurrent run left a mutant in the tree, and a
    later commit could ship it. Three self-tests rewrote fixtures under tests/fixtures/. One proof
    deleted the shell's whole /tmp (WP0). "A test must never destroy what it did not create" is the
    rule; this makes it a check rather than a hope.

HOW
    A local clone of HEAD (plus the working tree's tracked changes, so the commit under test is what
    runs) in a temp directory. Each test runs there with its own timeout. After each, `git status
    --porcelain` must be empty. Anything else -- modified, deleted or new untracked files -- is named.
    The real working tree is never touched.

    A TEST THAT RAN AND FAILED FAILS THE SWEEP TOO (lane L-R3F, 2026-10-22). This sweep is the local
    battery's one place that runs every test, and it read only the tree: an exit of 1 printed as
    `exit=1` under a PASS. The Release 3 candidate went red hosted on a stage-register negative
    control that no local gate saw fail. Exit 1 (refused) and a timeout now fail the sweep; exit 2
    stays a report, because 2 is UNKNOWN -- a tool or credential this host lacks -- not a refusal.

    AN EXIT 2 IS NEVER A PASS, AND NEITHER IS AN EXIT NOBODY DEFINED (kit revision 2026-11-25). The sweep
    printed "PASS ... none failed" over tests that exited 2, and read 3, 5 or a signal as passing. Now
    each test that exited 2 is NAMED as UNKNOWN in the summary, whose first word is then not PASS, and
    an exit that is neither 0, 1 nor 2 fails the sweep. Its own exit stays 0 when only UNKNOWNs remain:
    its verdict is the tree's, and each test's own job (under "Self-test required") enforces the test.
    tests/prove_unknown_never_passes.py U4.

EXIT  0 every test left the tree as it found it and none failed   1 one or more did not, or one
      failed (exit 1) or timed out   2 could not be checked
"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SELF = os.path.basename(__file__)
# Tools that need arguments or a live target, not self-contained tests.
SKIP = {'verify_expected_signals.py': 'needs --fixture and --sarif-dir (a runtime tool)',
        'make_fixture.py': 'a generator invoked by other tests',
        SELF: 'this file'}
TIMEOUT = 600


def verdict_of(rc):
    """-> PASS (0), UNKNOWN (2: a tool or credential this host lacks), FAIL (anything else)."""
    if rc == 0:
        return 'PASS'
    if rc == 2:
        return 'UNKNOWN'
    return 'FAIL'


def summary(dirty, failed, unknown):
    """-> (the summary line, the sweep's exit). Never PASS-first while a test is UNKNOWN."""
    if dirty or failed:
        return 'FAIL: %d test(s) changed the tree, %d failed or exited outside 0/1/2' % (len(dirty), len(failed)), 1
    if unknown:
        return ('TREE CLEAN, %d test(s) UNKNOWN (exit 2: a tool or credential this host lacks; not a pass): %s'
                % (len(unknown), ', '.join(unknown))), 0
    return ('PASS: every test left the tracked tree exactly as it found it, and none failed '
            '(exit 2 is UNKNOWN on this host and is reported, not failed).'), 0


def git(args, cwd, check=True):
    return subprocess.run(['git'] + args, cwd=cwd, capture_output=True, text=True, encoding='utf-8',
                          errors='replace', check=check)


def sandbox():
    work = tempfile.mkdtemp(prefix='tree-clean-')
    repo = os.path.join(work, 'kit')
    git(['clone', '--quiet', '--no-hardlinks', ROOT, repo], cwd=work)
    # Carry the working tree's TRACKED changes, so the tests that run are the ones on disk now.
    diff = git(['diff', 'HEAD', '--binary'], cwd=ROOT).stdout
    if diff.strip():
        p = subprocess.run(['git', 'apply', '--whitespace=nowarn', '-'], cwd=repo, input=diff,
                           text=True, encoding='utf-8', capture_output=True)
        if p.returncode != 0:
            raise RuntimeError('could not carry working-tree changes: %s' % p.stderr[:300])
        git(['-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qam', 'wip'], cwd=repo)
    # Untracked tests on disk are carried too, as committed files, so they run.
    for f in sorted(os.listdir(HERE)):
        if f.endswith('.py') and not os.path.exists(os.path.join(repo, 'tests', f)):
            shutil.copyfile(os.path.join(HERE, f), os.path.join(repo, 'tests', f))
    if git(['status', '--porcelain'], cwd=repo).stdout.strip():
        git(['add', '-A'], cwd=repo)
        git(['-c', 'user.name=t', '-c', 'user.email=t@t', 'commit', '-qm', 'untracked'], cwd=repo)
    return work, repo


def main():
    try:
        work, repo = sandbox()
    except Exception as e:  # noqa: BLE001
        print('UNKNOWN: could not build the sandbox clone: %s' % e)
        return 2
    try:
        tests = sorted(f for f in os.listdir(os.path.join(repo, 'tests'))
                       if f.endswith('.py') and not f.startswith('_'))
        dirty, failed, unknown = [], [], []
        for t in tests:
            if t in SKIP:
                print('  skip  %-40s %s' % (t, SKIP[t]))
                continue
            try:
                p = subprocess.run([sys.executable, os.path.join('tests', t)], cwd=repo,
                                   capture_output=True, text=True, encoding='utf-8',
                                   errors='replace', timeout=TIMEOUT)
                rc = p.returncode
            except subprocess.TimeoutExpired:
                rc = 'timeout'
            status = git(['status', '--porcelain'], cwd=repo).stdout.strip()
            mark = 'DIRTY' if status else 'clean'
            print('  %-5s %-40s exit=%s' % (mark, t, rc))
            v = verdict_of(rc)
            if v == 'FAIL':
                failed.append((t, rc, (p.stdout + p.stderr) if rc != 'timeout' else ''))
            elif v == 'UNKNOWN':
                unknown.append(t)
            if status:
                dirty.append((t, status.splitlines()))
                git(['checkout', '--', '.'], cwd=repo, check=False)
                git(['clean', '-fdq'], cwd=repo, check=False)
        if dirty or failed:
            print('')
            for t, lines in dirty:
                print('FAIL: %s changed the tree:' % t)
                for line in lines[:12]:
                    print('        %s' % line)
            for t, rc, out in failed:
                print('FAIL: %s %s:' % (t, 'timed out' if rc == 'timeout' else
                                        'exited 1 (refused)' if rc == 1 else
                                        'exited %s (neither a verdict nor UNKNOWN)' % rc))
                for line in out.strip().splitlines()[-12:]:
                    print('        %s' % line)
        line, code = summary(dirty, failed, unknown)
        print(line)
        return code
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == '__main__':
    sys.exit(main())
