#!/usr/bin/env python3
"""The propose-ledger job can push ONE ref -- its own proposal branch -- and nothing else (L45, 9.3).

WHY THIS EXISTS

    SINGLE_PIPELINE_TARGET.md section 9.3: propose-ledger "is the design's single write path and
    it is deliberately narrow. It cannot write to the protected branch. Its output is a pull
    request a human merges. If that job's authority ever grows to include the protected branch,
    the ledger has stopped being a governance artifact and the whole baseline becomes a scanner
    output." A `contents: write` token can push anywhere branch protection does not forbid, and
    branch protection is repository configuration this kit cannot see. So the narrowness has to be
    STRUCTURAL in the job itself, and this file is what makes it a check rather than a hope.

WHAT IT PROVES

    static, over the job as shipped and every composite it uses
      placement      the job exists, is the last job, needs `report`, and the gate does not wait
                     for it -- a job the gate waited for could not run after the gate
      trigger        it never runs on a pull_request* event and only on the default branch
      permissions    exactly contents: write and pull-requests: write, at job level; the file-level
                     block stays read-only
      concurrency    one group per environment, never cancelled in progress (mutating work)
      pushes         every `git push` in every step is the one allowed form,
                     `git push origin "HEAD:refs/heads/$BRANCH"`: no force, no delete, no refspec
                     to any other ref, no `gh pr merge`, no API write to a ref, no third-party
                     action that pushes, and the token is the run's own github.token
      guard          the script refuses before pushing unless $BRANCH starts with
                     `baseline-proposal/` and differs from $BASE

    live, under bash against a throwaway remote (UNKNOWN when no bash can run a script)
      the pushing step, extracted from the workflow, pushes the proposal branch and nothing else;
      with BRANCH set to the default branch it refuses and the remote is untouched; with BRANCH
      set to an arbitrary name it refuses

    self-test: a job with `git push origin main`, `--force`, `gh pr merge`, a missing guard or a
    PR-event trigger is caught, or this file proves nothing.

EXIT  0 proven   1 a case failed (named)   2 could not be checked (UNKNOWN, never PASS)
"""
import copy
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
# MOVED 2026-10-15 out of reusable-security.yml into its own reusable workflow (see its header).
WF = os.path.join(ROOT, '.github', 'workflows', 'reusable-propose-ledger.yml')
JOB = 'propose-ledger'
GATE = 'security-gate'
ALLOWED_PUSH = re.compile(r'^git push origin "HEAD:refs/heads/\$BRANCH"$')
BRANCH_GUARD = re.compile(r'case "\$BRANCH" in\s+baseline-proposal/\*\)')
BASE_GUARD = re.compile(r'\[ "\$BRANCH" != "\$BASE" \]')
# L51: the proposal now carries several files (ledger, lineage, head). Each must be under .security/.
PATH_GUARD = re.compile(r'case "\$f" in\s+\.security/\*\) ;;')
ALLOWED_USES = re.compile(r'^(actions/checkout@|actions/download-artifact@|\$/\.github/actions/)')
WRITE_WORDS = re.compile(r'gh pr merge|gh api[^\n]*-X\s*(PUT|POST|PATCH|DELETE)|git push --mirror'
                         r'|git push --all|--force|--delete|\+refs/|git push [^\n]*:refs/heads/\$BASE')


def joined(text):
    return re.sub(r'\\\r?\n\s*', ' ', text or '')


def composite_runs(uses):
    """-> run texts of a `$/` composite's steps, so a push hidden in a composite is still seen."""
    import yaml
    m = re.match(r'^\$/\.github/actions/([\w.-]+)$', uses or '')
    if not m:
        return []
    p = os.path.join(ROOT, '.github', 'actions', m.group(1), 'action.yml')
    if not os.path.isfile(p):
        return []
    doc = yaml.safe_load(io.open(p, encoding='utf-8')) or {}
    return [str(s.get('run') or '') for s in (doc.get('runs') or {}).get('steps') or []]


def check_job(doc):
    """-> list of problems. Pure, so the self-test can feed it mutants."""
    problems = []
    jobs = doc.get('jobs') or {}
    job = jobs.get(JOB)
    if job is None:
        return ['%s: no such job. The ledger has no write path, so no baseline can ever be '
                'established or extended' % JOB]
    if list(jobs)[-1] != JOB:
        problems.append('placement: %s is not the last job in the file' % JOB)
    needs = job.get('needs') or []
    needs = [needs] if isinstance(needs, str) else list(needs)
    # MOVED 2026-10-15 into its own reusable workflow (a write scope inside the security workflow
    # forced every consumer to grant it to every scan). Ordering after the report is now the CALLER's
    # `needs: security`; within this file the job must need nothing, and the security workflow must
    # no longer contain it.
    if needs:
        problems.append('placement: %s needs %s inside its own workflow; the caller orders it after '
                        'the security job' % (JOB, needs))
    sec = os.path.join(ROOT, '.github', 'workflows', 'reusable-security.yml')
    import yaml
    if JOB in ((yaml.safe_load(io.open(sec, encoding="utf-8")) or {}).get("jobs") or {}):
        problems.append('placement: %s is back inside reusable-security.yml, so every consumer must '
                        'grant the security scan write access' % JOB)
    # The gate cannot wait for this job any more: they live in different workflows, which is what
    # guarantees a proposal can never fail the verdict.

    cond = str(job.get('if') or '')
    if not re.search(r"!\s*startsWith\(\s*github\.event_name\s*,\s*'pull_request'\s*\)", cond):
        problems.append('trigger: `if` does not exclude pull_request* events (%r)' % cond)
    if not re.search(r"github\.ref\s*==\s*format\('refs/heads/\{0\}',\s*github\.event\.repository\.default_branch\)",
                     cond):
        problems.append('trigger: `if` does not require the default branch ref (%r)' % cond)

    perms = job.get('permissions')
    if perms != {'contents': 'write', 'pull-requests': 'write'}:
        problems.append('permissions: job-level block is %r; exactly contents: write and '
                        'pull-requests: write are allowed, nothing more and nothing at file level' % (perms,))
    top = doc.get('permissions') or {}
    for k in ('contents', 'pull-requests'):
        if str(top.get(k, '')) == 'write':
            problems.append('permissions: the file-level block grants %s: write, which every job '
                            'inherits' % k)

    conc = job.get('concurrency')
    group = str((conc or {}).get('group', '')) if isinstance(conc, dict) else str(conc or '')
    if 'inputs.environment' not in group:
        problems.append('concurrency: group %r is not per environment' % group)
    if isinstance(conc, dict) and str(conc.get('cancel-in-progress', 'false')).lower() != 'false':
        problems.append('concurrency: cancel-in-progress on mutating work manufactures a half-state')

    scripts = []
    for s in job.get('steps') or []:
        uses = str(s.get('uses') or '')
        if uses and not ALLOWED_USES.match(uses):
            problems.append('pushes: step uses %r, which is not an allowed action here' % uses)
        if s.get('run'):
            scripts.append((s.get('name') or uses or 'step', joined(str(s['run'])), s.get('env') or {}))
        for r in composite_runs(uses):
            scripts.append((uses, joined(r), {}))
    pushes = 0
    for name, text, env in scripts:
        for line in text.splitlines():
            t = line.strip()
            if t.startswith('#'):
                continue
            if 'git push' in t:
                pushes += 1
                if not ALLOWED_PUSH.match(t):
                    problems.append('pushes: %s runs %r; the only allowed form is '
                                    '`git push origin "HEAD:refs/heads/$BRANCH"`' % (name, t))
            m = WRITE_WORDS.search(t)
            if m:
                problems.append('pushes: %s contains %r, a write beyond the proposal branch' % (name, m.group(0)))
        if 'git push' in text:
            g = BRANCH_GUARD.search(text)
            b = BASE_GUARD.search(text)
            p = text.find('git push')
            if not g or g.start() > p:
                problems.append('guard: %s pushes without first refusing a $BRANCH outside '
                                'baseline-proposal/' % name)
            if not b or b.start() > p:
                problems.append('guard: %s pushes without first refusing $BRANCH == $BASE' % name)
            pg = PATH_GUARD.search(text)
            if not pg or pg.start() > text.find('git checkout'):
                problems.append('guard: %s stages files without first refusing any outside .security/'
                                % name)
            tok = str(env.get('GH_TOKEN', ''))
            if 'github.token' not in tok and 'secrets.GITHUB_TOKEN' not in tok:
                problems.append('token: the pushing step uses %r, not the run\'s own token. A PAT '
                                'can push where branch protection lets its owner push' % tok)
    if pushes != 1:
        problems.append('pushes: expected exactly one `git push` in the job, found %d' % pushes)
    return problems


def push_step(doc):
    for s in (doc['jobs'][JOB].get('steps') or []):
        if 'git push' in str(s.get('run') or ''):
            return s
    return None


def git(cwd, *args):
    p = subprocess.run(['git', '-c', 'user.name=t', '-c', 'user.email=t@example.invalid',
                        '-c', 'commit.gpgsign=false', '-c', 'init.defaultBranch=main'] + list(args),
                       cwd=cwd, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError('git %s: %s' % (' '.join(args), p.stderr.strip()[:300]))
    return p.stdout.strip()


def live(doc):
    """Run the pushing step against a throwaway remote. -> (problems, why_unknown)."""
    import prove_bootstrap_failure as pbf
    bash, why = pbf.usable_bash()
    if not bash:
        return [], 'no usable bash (%s)' % why
    step = push_step(doc)
    if step is None:
        return ['live: no pushing step found'], None
    script = str(step['run'])
    problems = []
    work = tempfile.mkdtemp(prefix='propose-scope-')
    try:
        remote = os.path.join(work, 'remote.git')
        os.makedirs(remote)
        git(remote, 'init', '-q', '--bare')
        seed = os.path.join(work, 'seed')
        os.makedirs(seed)
        git(seed, 'init', '-q')
        io.open(os.path.join(seed, 'README'), 'w').write('x\n')
        git(seed, 'add', '-A')
        git(seed, 'commit', '-qm', 'seed')
        git(seed, 'push', '-q', remote, 'HEAD:refs/heads/main')
        main_before = git(remote, 'rev-parse', 'refs/heads/main')
        # a `gh` shim on PATH that records its arguments and succeeds
        shim = os.path.join(work, 'bin')
        os.makedirs(shim)
        io.open(os.path.join(shim, 'gh'), 'w', newline='\n').write(
            '#!/usr/bin/env bash\nprintf \'%s\\n\' "$*" >> "$GH_LOG"\n')
        os.chmod(os.path.join(shim, 'gh'), 0o755)
        # The proposal tree, as the composite's --tree-out writes it: files at repository paths.
        tree = os.path.join(work, 'tree')
        os.makedirs(os.path.join(tree, '.security'))
        io.open(os.path.join(tree, '.security', 'finding-baseline.json'), 'w').write(
            '{"schema_version": 1, "header": {}, "entries": []}\n')
        io.open(os.path.join(tree, '.security', 'finding-lineage.jsonl'), 'w').write('{}\n')
        evil = os.path.join(work, 'evil-tree')
        os.makedirs(os.path.join(evil, '.security'))
        os.makedirs(os.path.join(evil, '.github', 'workflows'))
        io.open(os.path.join(evil, '.security', 'finding-baseline.json'), 'w').write('{}\n')
        io.open(os.path.join(evil, '.github', 'workflows', 'x.yml'), 'w').write('on: push\n')
        body = os.path.join(work, 'body.md')
        io.open(body, 'w').write('proposal body\n')

        def attempt(branch, tree_dir=tree):
            clone = os.path.join(work, 'clone-%d' % len(os.listdir(work)))
            git(work, 'clone', '-q', remote, clone)
            log = os.path.join(work, 'gh-%d.log' % len(os.listdir(work)))
            io.open(log, 'w').close()
            runner = os.path.join(work, 'step.sh')
            io.open(runner, 'w', encoding='utf-8', newline='\n').write(script)
            # The step's contract, exactly as the workflow's env: block names it.
            env = dict(os.environ, BRANCH=branch, BASE='main', TREE=tree_dir.replace('\\', '/'),
                       BODY_FILE=body, TITLE='baseline (prod): 1 admitted', GH_TOKEN='unused',
                       GH_LOG=log, PATH=shim + os.pathsep + os.environ.get('PATH', ''))
            p = subprocess.run([bash, runner], cwd=clone, capture_output=True, text=True, env=env)
            refs = git(remote, 'for-each-ref', '--format=%(refname)').splitlines()
            return p.returncode, refs, io.open(log).read(), (p.stdout or '') + (p.stderr or '')

        rc, refs, calls, log = attempt('baseline-proposal/prod/900')
        if rc != 0:
            problems.append('live: the allowed proposal push failed (exit %d): %s' % (rc, log[-400:]))
        if 'refs/heads/baseline-proposal/prod/900' not in refs:
            problems.append('live: the proposal branch did not reach the remote (%r)' % refs)
        if git(remote, 'rev-parse', 'refs/heads/main') != main_before:
            problems.append('live: the default branch MOVED during the allowed push')
        if 'pr create' not in calls:
            problems.append('live: no pull request was opened (gh calls: %r)' % calls)
        pushed = git(remote, 'ls-tree', '-r', '--name-only', 'refs/heads/baseline-proposal/prod/900').splitlines()
        if '.security/finding-lineage.jsonl' not in pushed or '.security/finding-baseline.json' not in pushed:
            problems.append('live: the proposal branch lacks the proposed files (%r)' % pushed)
        # A tree naming a file outside .security/ -- by defect or by tampering -- pushes nothing.
        rc, refs, calls, log = attempt('baseline-proposal/prod/901', evil)
        if rc == 0 or 'refs/heads/baseline-proposal/prod/901' in refs or calls.strip():
            problems.append('live: a proposal tree carrying .github/workflows/x.yml was NOT refused '
                            '(exit %d, refs %r)' % (rc, refs))
        for bad in ('main', 'release/1', 'refs/heads/main'):
            rc, refs, calls, log = attempt(bad)
            if rc == 0:
                problems.append('live: BRANCH=%r was NOT refused' % bad)
            if git(remote, 'rev-parse', 'refs/heads/main') != main_before:
                problems.append('live: BRANCH=%r moved the default branch' % bad)
            if calls.strip():
                problems.append('live: BRANCH=%r still opened a pull request' % bad)
            extra = [r for r in refs if r not in ('refs/heads/main', 'refs/heads/baseline-proposal/prod/900')]
            if extra:
                problems.append('live: BRANCH=%r pushed %r' % (bad, extra))
    except RuntimeError as exc:
        return [], 'fixture could not be built: %s' % exc
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return problems, None


def self_test(doc):
    """Each mutant must be caught, or the check proves nothing."""
    if check_job(doc):
        return 'the control failed: %s' % check_job(doc)
    step = push_step(doc)
    cases = []
    d = copy.deepcopy(doc); d['jobs'][JOB]['permissions']['contents'] = 'write'; d['jobs'][JOB]['permissions']['packages'] = 'write'
    cases.append(('extra permission', d))
    d = copy.deepcopy(doc); d['jobs'][JOB]['if'] = "github.ref == 'refs/heads/main'"
    cases.append(('PR events not excluded', d))
    d = copy.deepcopy(doc); d['jobs'][JOB]['needs'] = ['report']
    cases.append(('orders itself inside its own workflow', d))
    for label, repl in (('push to main', 'git push origin "HEAD:refs/heads/$BASE"'),
                        ('force push', 'git push --force origin "HEAD:refs/heads/$BRANCH"'),
                        ('push all', 'git push --all origin')):
        d = copy.deepcopy(doc)
        s = push_step(d)
        s['run'] = str(step['run']).replace('git push origin "HEAD:refs/heads/$BRANCH"', repl)
        cases.append((label, d))
    d = copy.deepcopy(doc); s = push_step(d)
    s['run'] = str(step['run']) + '\ngh pr merge --auto "$BRANCH"\n'
    cases.append(('merges its own PR', d))
    d = copy.deepcopy(doc); s = push_step(d)
    s['run'] = re.sub(r'case "\$BRANCH" in[^\n]*\n(?:[^\n]*\n){0,4}?[^\n]*esac\n', '', str(step['run']))
    cases.append(('branch guard removed', d))
    d = copy.deepcopy(doc); s = push_step(d); s['env'] = dict(s.get('env') or {}, GH_TOKEN='${{ secrets.PUSHPAT }}')
    cases.append(('a PAT instead of the run token', d))
    d = copy.deepcopy(doc); s = push_step(d)
    s['run'] = str(step['run']).replace('.security/*) ;;', '*) ;;')
    cases.append(('path guard removed', d))
    for label, m in cases:
        if not check_job(m):
            return 'did not catch: %s' % label
    return None


def main():
    try:
        import yaml
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    doc = yaml.safe_load(io.open(WF, encoding='utf-8'))
    problems = check_job(doc)
    if problems:
        for p in problems:
            print('FAIL: ' + p)
        return 1
    err = self_test(doc)
    if err:
        print('SELF-TEST FAILED: %s. A scope check that misses its own defect class proves nothing.' % err)
        return 1
    print('self-test ok: 10 mutants caught (extra permission, PR trigger, gate dependency, push to '
          'base, force, --all, self-merge, guard removed, PAT, path guard removed), the control passes')
    live_problems, unknown = live(doc)
    if unknown:
        print('LIVE: UNKNOWN -- %s. The static half passed; the live half could not run.' % unknown)
        return 2
    if live_problems:
        for p in live_problems:
            print('FAIL: ' + p)
        return 1
    print('PASS: propose-ledger runs after the gate on default-branch non-PR runs only, holds exactly '
          'contents+pull-requests write at job level, pushes exactly one ref -- its own '
          'baseline-proposal/ branch -- opens a PR with the run token, and under bash against a '
          'throwaway remote refused main, release/1 and refs/heads/main without moving anything, and '
          'refused a proposal tree carrying a file outside .security/.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
