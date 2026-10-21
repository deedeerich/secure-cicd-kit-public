#!/usr/bin/env python3
"""Continuity records must be current with the work, and a touch must not make them look current.

WHY THIS EXISTS

    The context files in this repository were written on 2026-10-01 and not updated for six days,
    while nine commits landed under them -- a stage-phase gate, a threat model, an overlay, a
    diagram generator, half an identity integration. A continuity record that stops being updated is
    worse than none, because the next cold session trusts it. That is not a hypothetical: the
    session that wrote them existed only because an earlier one had opened this repository with no
    context and confidently re-derived work that already existed.

    Writing the files was never the problem. KEEPING them was, and asking an agent to remember is
    what produced six days of drift. So this is a gate.

WHY A TIMESTAMP IS NOT ENOUGH, WHICH IS THE WHOLE DESIGN

    The obvious check is "was the context modified recently". It is worthless: `touch` passes it,
    and so does fixing a typo. Worse, it rewards the exact behaviour it should refuse -- an agent
    under time pressure opens the file, changes nothing that matters, and the gate goes green.

    So staleness is measured against the WORK, not against the clock, and freshness has to be
    EARNED by naming something:

      - the context must cite the commit it was last reconciled against
      - that commit must exist, and must be an ancestor of HEAD
      - every internal link must resolve to a file that exists
      - the review must be younger than a bounded number of commits

    A file that mentions no commit cannot be current by accident.

USAGE
    python tests/check_context_current.py
    python tests/check_context_current.py --root <repo>
    python tests/check_context_current.py --max-commits 12
    python tests/check_context_current.py --self-test

EXIT
    0  context is present, resolvable and reconciled
    1  something is missing, unresolvable, or behind the work
    2  self-test failed
"""
import argparse
import io
import os
import re
import subprocess
import sys

DEFAULT_MAX_COMMITS = 10

REQUIRED = ('current-state.md', 'active-lane.md', 'risks.md', 'continuation.md')

# The line a context file uses to say what it was reconciled against. Deliberately explicit:
# a file cannot acquire one by being edited, only by somebody stating it.
# Tolerates markdown emphasis, because the line is written for a human first and the gate
# refusing its own correctly-written marker is the kind of false failure that gets a check
# switched off.
RECONCILED = re.compile(r'(?im)^\s*>?\s*[*_]{0,2}\s*(?:reconciled|current)\s+'
                        r'(?:against|with)\s+(?:commit\s+)?[*_]{0,2}`?([0-9a-f]{7,40})`?')
LINK = re.compile(r'`([A-Za-z0-9_./-]+\.(?:md|py|ps1|csv|yml|yaml))`')


def git(root, *args):
    try:
        out = subprocess.run(['git', '-C', root] + list(args), capture_output=True, text=True,
                             timeout=30)
        return out.stdout.strip() if out.returncode == 0 else ''
    except (OSError, subprocess.SubprocessError):
        return ''


def product_dirs(root):
    base = os.path.join(root, '.context', 'products')
    if not os.path.isdir(base):
        return []
    return [os.path.join(base, d) for d in sorted(os.listdir(base))
            if os.path.isdir(os.path.join(base, d))]


def check(root, max_commits=DEFAULT_MAX_COMMITS):
    """-> (failures, notes). A failure is a context that cannot be trusted."""
    fails, notes = [], []

    prods = product_dirs(root)
    if not prods:
        return (['no .context/products/<product>/ exists. A repository with no continuity record '
                 'costs the next cold session a day, which is what this gate exists to prevent.'],
                notes)

    head = git(root, 'rev-parse', 'HEAD')

    for p in prods:
        name = os.path.basename(p)

        missing = [f for f in REQUIRED if not os.path.exists(os.path.join(p, f))]
        for f in missing:
            fails.append('%s: %s is missing' % (name, f))
        if missing:
            continue

        # Every internal link must resolve. A context pointing at a file that no longer exists is
        # how a reader learns to stop following its links.
        for f in REQUIRED:
            path = os.path.join(p, f)
            text = io.open(path, encoding='utf-8').read()
            # A PATH IS A LINK; A BARE FILENAME IS A MENTION, and they fail differently.
            #
            # The first version of this check treated both as links and produced sixteen failures
            # over prose -- `CAPABILITY_MATRIX.md` written mid-sentence about a file that exists at
            # docs/assurance/. A gate that fails on correct prose gets disabled, which is worse than
            # not having it, so the rule distinguishes the two:
            #
            #   docs/foo.md   a path. It asserts a location, so it must resolve there.
            #   FOO.md        a name. It asserts the file exists SOMEWHERE, so it is searched for,
            #                 and a miss is a note rather than a failure -- a context may
            #                 legitimately name a file in order to say it is absent, which this
            #                 repository's own continuation does.
            for m in sorted(set(LINK.findall(text))):
                if m.startswith(('http', 'D:', 'C:', '/')) or '..' in m:
                    continue
                if '/' in m:
                    if not (os.path.exists(os.path.join(root, m))
                            or os.path.exists(os.path.join(p, m))):
                        fails.append('%s/%s: link `%s` resolves to nothing' % (name, f, m))
                else:
                    found = False
                    for base, dirs, files in os.walk(root):
                        dirs[:] = [d for d in dirs if d not in ('.git', '__pycache__', '.venv')]
                        if m in files:
                            found = True
                            break
                    if not found:
                        notes.append('%s/%s: `%s` is named but no file of that name exists in the '
                                     'repository (a mention, not a link -- check it is deliberate)'
                                     % (name, f, m))

        # Reconciliation. Stated, verifiable, and bounded by the work rather than by the clock.
        text = io.open(os.path.join(p, 'current-state.md'), encoding='utf-8').read()
        m = RECONCILED.search(text)
        if not m:
            fails.append('%s/current-state.md: no "Reconciled against <commit>" line. A timestamp '
                         'is not evidence of review -- `touch` satisfies a date and names nothing. '
                         'State the commit this context was last checked against.' % name)
            continue

        sha = m.group(1)
        if not git(root, 'cat-file', '-e', sha + '^{commit}') == '' or not git(root, 'rev-parse',
                                                                              '--verify', sha):
            pass
        if not git(root, 'rev-parse', '--verify', sha + '^{commit}'):
            fails.append('%s: reconciled against %s, which is not a commit in this repository'
                         % (name, sha))
            continue

        anc = subprocess.run(['git', '-C', root, 'merge-base', '--is-ancestor', sha, 'HEAD'],
                             capture_output=True)
        if anc.returncode != 0:
            fails.append('%s: reconciled against %s, which is not an ancestor of HEAD. The context '
                         'was reconciled on a branch this one does not contain.' % (name, sha))
            continue

        behind = git(root, 'rev-list', '--count', '%s..HEAD' % sha)
        behind = int(behind) if behind.isdigit() else 0
        if behind > max_commits:
            fails.append('%s: context was reconciled against %s and HEAD is %d commits ahead '
                         '(limit %d). Read the commits since, update the context, and restate the '
                         'commit. Do not just change the date.'
                         % (name, sha[:8], behind, max_commits))
        else:
            notes.append('%s: reconciled against %s, %d commit(s) behind HEAD'
                         % (name, sha[:8], behind))

    if head and not fails:
        notes.append('HEAD is %s' % head[:8])
    return fails, notes


def self_test():
    import shutil
    import tempfile
    fails = []
    root = tempfile.mkdtemp(prefix='ctxgate-')
    try:
        subprocess.run(['git', '-C', root, 'init', '-q'], capture_output=True)
        subprocess.run(['git', '-C', root, 'config', 'user.email', 't@t'], capture_output=True)
        subprocess.run(['git', '-C', root, 'config', 'user.name', 't'], capture_output=True)
        pdir = os.path.join(root, '.context', 'products', 'thing')
        os.makedirs(pdir)

        def commit(msg):
            io.open(os.path.join(root, 'f.txt'), 'a').write(msg + '\n')
            subprocess.run(['git', '-C', root, 'add', '-A'], capture_output=True)
            subprocess.run(['git', '-C', root, 'commit', '-q', '-m', msg], capture_output=True)
            return git(root, 'rev-parse', 'HEAD')

        # FAILING FIXTURE 1: nothing there at all.
        f, _ = check(root)
        if not any('is missing' in x for x in f):
            fails.append('missing required files were not refused')

        for n in REQUIRED:
            io.open(os.path.join(pdir, n), 'w', encoding='utf-8').write('# %s\n' % n)
        base = commit('one')

        # FAILING FIXTURE 2: present, but claims nothing.
        f, _ = check(root)
        if not any('no "Reconciled against' in x for x in f):
            fails.append('a context with no reconciliation line was accepted')

        # PASSING CASE.
        io.open(os.path.join(pdir, 'current-state.md'), 'w', encoding='utf-8').write(
            '# s\n\n> Reconciled against commit `%s`.\n' % base)
        f, notes = check(root)
        if f:
            fails.append('a correctly reconciled context was refused: %s' % f[:1])
        if not any('behind HEAD' in n for n in notes):
            fails.append('the passing case did not report its distance from HEAD')

        # FAILING FIXTURE 3: the work moved and the context did not.
        for i in range(DEFAULT_MAX_COMMITS + 2):
            commit('more-%d' % i)
        f, _ = check(root)
        if not any('commits ahead' in x for x in f):
            fails.append('a context behind the work by more than the limit was accepted')

        # THE ONE THAT MATTERS: touching the file must not make it current.
        os.utime(os.path.join(pdir, 'current-state.md'), None)
        f, _ = check(root)
        if not any('commits ahead' in x for x in f):
            fails.append('TOUCHING THE FILE MADE IT PASS -- the gate is measuring the clock, not '
                         'the work')

        # A claimed commit that does not exist must be refused, not believed.
        io.open(os.path.join(pdir, 'current-state.md'), 'w', encoding='utf-8').write(
            '# s\n\n> Reconciled against commit `deadbeefdeadbeef`.\n')
        f, _ = check(root)
        if not any('not a commit' in x for x in f):
            fails.append('a reconciliation against a nonexistent commit was accepted')

        # A dangling link must be refused.
        io.open(os.path.join(pdir, 'current-state.md'), 'w', encoding='utf-8').write(
            '# s\n\n> Reconciled against commit `%s`.\n\nSee `docs/nope.md`.\n' % git(
                root, 'rev-parse', 'HEAD'))
        f, _ = check(root)
        if not any('resolves to nothing' in x for x in f):
            fails.append('a link to a nonexistent file was accepted')
    finally:
        shutil.rmtree(root, ignore_errors=True)

    if fails:
        for x in fails:
            sys.stderr.write('FAIL: %s\n' % x)
        return 2
    print('self-test ok: a missing context file is refused; a context that states no reconciliation '
          'commit is refused; a correctly reconciled one passes and reports its distance from HEAD; '
          'a context more than the limit behind the work is refused; TOUCHING THE FILE DOES NOT MAKE '
          'IT PASS, because freshness is measured against commits and not against the clock; a '
          'reconciliation against a commit that does not exist is refused rather than believed; and '
          'a link to a file that does not exist is refused')
    return 0


def main():
    ap = argparse.ArgumentParser(description='Continuity records must be current with the work.')
    ap.add_argument('--root', default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ap.add_argument('--max-commits', type=int, default=DEFAULT_MAX_COMMITS)
    ap.add_argument('--self-test', action='store_true')
    a = ap.parse_args()
    if a.self_test:
        return self_test()

    fails, notes = check(a.root, a.max_commits)
    print('')
    print('CONTEXT CURRENCY -- %s' % a.root)
    print('=' * 70)
    for n in notes:
        print('  %s' % n)
    print('')
    if fails:
        for f in fails:
            sys.stderr.write('::error::%s\n' % f)
        sys.stderr.write('\nCONTEXT_STALE -- %d problem(s). The continuity record cannot be '
                         'trusted, which means the next cold session will re-derive the work.\n'
                         % len(fails))
        return 1
    print('  Context is present, every link resolves, and the reconciliation is within range.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
