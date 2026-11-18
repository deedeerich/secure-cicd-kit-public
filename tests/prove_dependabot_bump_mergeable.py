#!/usr/bin/env python3
"""A real Dependabot dependency bump passes every drift check; real drift on a Dependabot branch still fails.

WHY THIS EXISTS (owner, 2026-11-04)

    "Dependabot things cannot sit there and trip the normalizer drift. They must be able to be
    mergeable." Dependabot PR #5 (actions/setup-java 5 -> 6) sat red on the required check
    `Normalizer drift` from 2026-10-21. Two causes, both in the kit, neither in Dependabot:

      A  run 39664961192: one REST lookup of `dorny/paths-filter@v4` did not answer, and the pin
         checker made ONE attempt per ref -- a ref that exists (refs/tags/v4) became UNKNOWN and
         the step exit 2. A Dependabot run 35 s earlier (39664885588), same read-only token, passed
         the same step. A single network blip turned a required check red.
      B  on the trunk, tests/prove_composite_move_equivalence.py digested every remote `uses:` SHA
         of the six moved scanner jobs. Any Dependabot bump of an action those composites use
         (checkout, setup-java, upload-artifact, codeql-action, cache, ...) changed the digest and
         failed the check until somebody re-pinned by hand: every such PR was red by construction.
         Reproduced 2026-11-04: setup-java v5.7.0 -> v6.2.0 (77dd5b2c) in the sast-java composite,
         "1 moved job(s) are NOT equivalent to the job they replaced".

    The fix does NOT skip anything for Dependabot. Nothing reads who opened the PR. The move proof
    still digests every step's name, id, if, uses (owner/repo/path), with, env, run and shell; only
    the 40-hex SHA of a remote `uses:` is normalised, because that SHA is a DEPENDENCY PIN and is
    held by tests/check_action_pins.py (P1 full SHA, P2 exact release comment, P4 `--online`: the
    release really is that commit). A tag or branch in place of the SHA is still a digest change.

WHAT IT PROVES
    M1  a simulated Dependabot bump of EVERY remote pin in .github/ (each SHA moved, each release
        comment moved, nothing else) passes the move-equivalence proof and the offline pin rules
        (check_action_pins.scan: P1-P3) on a copy of this tree
    M2  on that bumped tree, real drift FAILS the move-equivalence proof, each by itself:
          a  one byte changed in a moved composite's run body
          b  an action swapped for another owner's at the same SHA
          c  a SHA pin replaced by a tag
          d  a `with:` input of a remote action changed
    M3  the verdicts do not depend on who opened the PR: M1 and M2a give the same exit code with
        GITHUB_ACTOR=dependabot[bot], GITHUB_HEAD_REF=dependabot/..., GITHUB_EVENT_NAME=pull_request;
        and no job or step `if:` in self-test.yml mentions dependabot, github.actor or the head ref
    M4  a lookup is retried, boundedly, only when it did not observe (tests/_github_refs.py):
        transient twice then answered -> resolves; never answered -> UNKNOWN (None, never True)
        after exactly the bound, and then the channel is down (the next lookup tries once); an
        authentication refusal is UNKNOWN at once; "not our ref" -> False at once, one attempt; a
        404 from REST is not retried

USAGE  python3 tests/prove_dependabot_bump_mergeable.py
EXIT   0 all hold   1 any does not   2 PyYAML unavailable (UNKNOWN)
"""
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

MOVE = os.path.join(HERE, 'prove_composite_move_equivalence.py')
PIN = re.compile(r'(uses:\s*[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]+)?@)([0-9a-f]{40})(\s+#\s*v(\d+)\.(\d+)\.(\d+))')
FAILS = []


def check(cond, label):
    print('  %s %s' % ('ok  ' if cond else 'FAIL', label))
    if not cond:
        FAILS.append(label)


def bump_text(text):
    """Every remote pin moved the way Dependabot moves it: a new SHA and a new release comment."""
    def rep(m):
        new_sha = ('%040x' % (int(m.group(2), 16) ^ 0x5a5a5a5a))[-40:]
        return '%s%s # v%s.%s.%d' % (m.group(1), new_sha, m.group(4), m.group(5), int(m.group(6)) + 1)
    return PIN.subn(rep, text)


def bumped_tree():
    tmp = tempfile.mkdtemp(prefix='dependabot-bump-')
    shutil.copytree(os.path.join(ROOT, '.github'), os.path.join(tmp, '.github'))
    # The move proof reads which composites are scanner bodies from the registry.
    shutil.copy2(os.path.join(ROOT, 'scanner-registry.yaml'), os.path.join(tmp, 'scanner-registry.yaml'))
    moved = 0
    for dirpath, _dirs, files in os.walk(os.path.join(tmp, '.github')):
        for f in files:
            if not f.endswith(('.yml', '.yaml')):
                continue
            p = os.path.join(dirpath, f)
            text = io.open(p, encoding='utf-8').read()
            new, n = bump_text(text)
            if n:
                io.open(p, 'w', encoding='utf-8', newline='').write(new)
                moved += n
    return tmp, moved


def move_rc(root, env_extra=None):
    env = dict(os.environ, PYTHONIOENCODING='utf-8')
    for k in ('GITHUB_ACTOR', 'GITHUB_HEAD_REF', 'GITHUB_EVENT_NAME', 'GITHUB_TRIGGERING_ACTOR'):
        env.pop(k, None)
    env.update(env_extra or {})
    p = subprocess.run([sys.executable, MOVE, '--root', root], capture_output=True, text=True,
                       encoding='utf-8', errors='replace', env=env)
    return p.returncode, (p.stdout or '') + (p.stderr or '')


def edit(root, rel, old, new):
    p = os.path.join(root, *rel.split('/'))
    text = io.open(p, encoding='utf-8').read()
    if old not in text:
        return False
    io.open(p, 'w', encoding='utf-8', newline='').write(text.replace(old, new, 1))
    return True


def m1_m2_m3():
    import check_action_pins as cap
    root, moved = bumped_tree()
    try:
        check(moved >= 20, 'M1 the simulated bump moved every remote pin in .github/ (%d moved)' % moved)
        rc, out = move_rc(root)
        check(('tree: %s' % os.path.abspath(root)) in out, 'M1 the move proof read the bumped copy, not this tree')
        check(rc == 0, 'M1 move equivalence PASSES on the bumped tree (rc %d)%s'
              % (rc, '' if rc == 0 else ': ' + ' | '.join(out.strip().splitlines()[-4:])))
        problems, pins, files = cap.scan(root)
        check(files > 0 and not problems,
              'M1 the bumped pins obey P1-P3 offline (%d pins in %d files; %d refused)'
              % (len(pins), files, len(problems)))
        rc_db, _ = move_rc(root, {'GITHUB_ACTOR': 'dependabot[bot]', 'GITHUB_TRIGGERING_ACTOR': 'dependabot[bot]',
                                  'GITHUB_HEAD_REF': 'dependabot/github_actions/actions/setup-java-6',
                                  'GITHUB_EVENT_NAME': 'pull_request'})
        check(rc_db == rc, 'M3 the bumped tree gets the same verdict as a Dependabot run (%d = %d)' % (rc_db, rc))

        java = '.github/actions/sast-java/action.yml'
        text = io.open(os.path.join(root, *java.split('/')), encoding='utf-8').read()
        m = re.search(r'uses:\s*actions/setup-java@([0-9a-f]{40})', text)
        if not m:
            check(False, 'M2 the sast-java composite still pins actions/setup-java by SHA')
            return
        sha = m.group(1)
        run_line = re.search(r'\n(\s+)(set -[a-z]+o pipefail)\n', text)
        mutants = [
            ('a  one byte changed in a moved run body', java,
             run_line.group(2) if run_line else 'set -uo pipefail',
             (run_line.group(2) if run_line else 'set -uo pipefail') + ' ',),
            ('b  an action swapped for another owner at the same SHA', java,
             'actions/setup-java@' + sha, 'someone-else/setup-java@' + sha),
            ('c  a SHA pin replaced by a tag', java, 'actions/setup-java@' + sha, 'actions/setup-java@v6'),
        ]
        wm = re.search(r'(uses:\s*actions/setup-java@[0-9a-f]{40}[^\n]*\n(?:\s+#[^\n]*\n)*\s+with:\n)(\s+)([a-z-]+):', text)
        mutants.append(('d  a with: input of a remote action changed', java,
                        wm.group(0) if wm else '@@no-with@@',
                        (wm.group(1) + wm.group(2) + 'x-extra-input: "1"\n' + wm.group(2) + wm.group(3) + ':')
                        if wm else ''))
        for label, rel, old, new in mutants:
            work = tempfile.mkdtemp(prefix='dependabot-mutant-')
            try:
                shutil.copytree(os.path.join(root, '.github'), os.path.join(work, '.github'))
                shutil.copy2(os.path.join(root, 'scanner-registry.yaml'), os.path.join(work, 'scanner-registry.yaml'))
                if not edit(work, rel, old, new):
                    check(False, 'M2 %s: the mutant could be seeded' % label)
                    continue
                rc_m, out_m = move_rc(work)
                check(rc_m == 1, 'M2 %s FAILS on the Dependabot-bumped tree (rc %d)' % (label, rc_m))
                if label.startswith('a '):
                    rc_md, _ = move_rc(work, {'GITHUB_ACTOR': 'dependabot[bot]',
                                              'GITHUB_HEAD_REF': 'dependabot/github_actions/x',
                                              'GITHUB_EVENT_NAME': 'pull_request'})
                    check(rc_md == rc_m, 'M3 the run-body mutant fails the same way as a Dependabot run (%d = %d)'
                          % (rc_md, rc_m))
            finally:
                shutil.rmtree(work, ignore_errors=True)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def m3_static():
    import yaml
    doc = yaml.safe_load(io.open(os.path.join(ROOT, '.github', 'workflows', 'self-test.yml'),
                                 encoding='utf-8').read())
    bad = []
    pat = re.compile(r'dependabot|github\.actor|triggering_actor|head_ref|pull_request\.user', re.I)
    for jn, j in (doc.get('jobs') or {}).items():
        if pat.search(str(j.get('if') or '')):
            bad.append('job %s' % jn)
        for st in j.get('steps') or []:
            if pat.search(str(st.get('if') or '')):
                bad.append('%s / %s' % (jn, st.get('name') or st.get('uses')))
    check(not bad, 'M3 no self-test job or step is conditioned on Dependabot or the actor %s' % (bad or ''))


def m4():
    import _github_refs as gr
    calls = []

    def fake(seq):
        seq = list(seq)

        def _git(args, cwd, timeout):
            calls.append(args)
            # Past the end of the script, the last answer repeats: a retry the code should not
            # make shows as an extra call, never as an exception.
            return seq[min(len(calls) - 1, len(seq) - 1)]
        return _git
    real_git, real_sleep = gr._git, gr._sleep
    gr._sleep = lambda s: None
    try:
        ok = (0, 'ceb8a2b8f2d89434be7ff52d3de7ec3738c5cc9d\trefs/tags/v4\n', '')
        blip = (128, '', 'fatal: unable to access: Could not resolve host: github.com')
        del calls[:]
        gr._git = fake([blip, None, ok])
        r = gr.ref_resolves('dorny/paths-filter', 'v4')
        check(r is True and len(calls) == 3,
              'M4 transient twice, then answered: resolves (%r after %d attempts)' % (r, len(calls)))
        del calls[:]
        gr._git = fake([blip] * (gr.ATTEMPTS + 2))
        r = gr.ref_resolves('dorny/paths-filter', 'v4')
        check(r is None and len(calls) == gr.ATTEMPTS,
              'M4 never answered: UNKNOWN after exactly %d attempts, never a pass (%r, %d)'
              % (gr.ATTEMPTS, r, len(calls)))
        del calls[:]
        gr._git = fake([blip])
        r = gr.ref_resolves('actions/checkout', 'v4')
        check(r is None and len(calls) == 1,
              'M4 once git failed every attempt, the next lookup tries once (the breaker; %r, %d)'
              % (r, len(calls)))
        gr.reset()
        del calls[:]
        gr._git = fake([(128, '', 'remote: Invalid username or password. fatal: Authentication failed (HTTP 401)')])
        r = gr.ref_resolves('dorny/paths-filter', 'v4')
        check(r is None and len(calls) == 1,
              'M4 an authentication refusal is an answer: UNKNOWN at once, not retried (%r, %d)' % (r, len(calls)))
        del calls[:]
        gr._git = fake([(0, '', ''), (0, '', '')])
        r = gr.ref_resolves('dorny/paths-filter', 'v0.0.0-no')
        check(r is False and len(calls) == 1, 'M4 an answered "no such ref" is False at once (%r, %d)' % (r, len(calls)))
        del calls[:]
        gr._git = fake([(0, '', ''), (128, '', 'fatal: remote error: upload-pack: not our ref ' + 'f' * 40)])
        r = gr.commit_exists('actions/checkout', 'f' * 40)
        check(r is False and len(calls) == 2,
              'M4 "not our ref" is False with one fetch, not retried (%r, %d git calls incl. init)' % (r, len(calls)))
        hits = []
        real_open = gr.urllib.request.urlopen

        def no(req, timeout=15):
            hits.append(1)
            raise gr.urllib.error.HTTPError(req.full_url, 404, 'Not Found', {}, None)
        gr.urllib.request.urlopen = no
        os.environ['PIN_CHECK_GITHUB_COM_TOKEN'] = 'x'
        try:
            st, _ = gr.api_get('/repos/a/b/git/ref/tags/v1', 'proof')
        finally:
            gr.urllib.request.urlopen = real_open
            os.environ.pop('PIN_CHECK_GITHUB_COM_TOKEN', None)
        check(st == 404 and len(hits) == 1, 'M4 a REST 404 is an answer, not retried (%r, %d)' % (st, len(hits)))
    finally:
        gr._git, gr._sleep = real_git, real_sleep
        gr.reset()


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable')
        return 2
    m1_m2_m3()
    m3_static()
    m4()
    if FAILS:
        print('FAIL: %d check(s): a Dependabot bump is not mergeable, or real drift would pass.' % len(FAILS))
        return 1
    print('PASS: a Dependabot dependency bump passes the drift checks; real drift on its branch still fails; '
          'lookups retry boundedly and UNKNOWN is never a pass.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
