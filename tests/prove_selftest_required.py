#!/usr/bin/env python3
"""Self-test's required check is never green by skipping and never pending by path filter
(owner ruling 2026-10-27 on the cost redesign's step 8, KDEC-033): the adversarial test.

THE DEFECT, STATED

    GitHub counts a SKIPPED job as a passing required check. The proposal's step 8 skipped
    self-test's required job on docs-only PRs with a job-level `if:` -- "skipped = green". And a
    required workflow behind `paths:`/`paths-ignore:` never starts, so its required check is
    PENDING forever.

WHAT MUST HOLD

    S1  the pull_request trigger starts the workflow for EVERY change: no paths, paths-ignore or
        branches-ignore filter. would_start() evaluates GitHub's filter rules; a docs-only, a
        workflow-only and a mixed change all start it. The consumer templates hold the same.
    S2  `contract` (the plan) has no `if:` and no needs; `required` (the verdict, the ONE check
        branch protection requires) is `if: always()` and needs EVERY other job, so a job added
        later cannot escape it.
    S3  no job carries an `if:` except the plan-skippable ones (exactly
        `needs.contract.outputs.skip_<job> != 'true'`, needing contract) and the event-gated ones
        (exactly scripts/selftest_required.py EVENTGATED, so the table cannot drift).
    S4  PROVEN SAFE: for each plan-skippable job, no Python module it runs (its scripts, their
        local imports, the kit scripts they name, and the composites they name) holds a string
        constant naming a path in that job's safe set. Docstrings are prose, not reads. POSITIVE
        CONTROL: the same analysis over normalizer-drift finds docs reads, so it is not blind --
        and normalizer-drift is therefore not skippable.
    S5  the plan and verdict steps, run AS SHIPPED: a docs-only PR plans the skip; then the verdict
        PASSES on that skip, FAILS when the same job is skipped without the plan, FAILS when
        normalizer-drift is skipped ("skipped = green", refused), FAILS on a failed plan.
    M*  mutations, each caught: a paths-ignore on pull_request; `if: false` on normalizer-drift;
        `required` without always(); a job dropped from `required`'s needs; a docs glob added to
        normalizer-drift's safe set.

EXIT  0 all hold   1 a violation   2 could not be checked
"""
import ast
import copy
import fnmatch
import io
import json
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

import yaml  # noqa: E402
import selftest_required as sr  # noqa: E402

WF = os.path.join(ROOT, '.github', 'workflows', 'self-test.yml')
TEMPLATES = [os.path.join(ROOT, 'templates', n) for n in ('security.yml', 'build-deploy.yml')]


def on_of(doc):
    return doc.get('on', doc.get(True)) or {}


def would_start(on, event, changed):
    """GitHub's trigger filters for one event (paths, paths-ignore). Branch filters are out of scope:
    a required check on the protected branch's PRs must start for every PR to that branch."""
    if event not in on:
        return False
    spec = on.get(event) or {}
    if not isinstance(spec, dict):
        return True
    if 'branches-ignore' in spec:
        return False      # can stop a PR to the protected branch from starting: refused outright
    if 'paths' in spec:
        return any(sr.matches(f, spec['paths']) for f in changed)
    if 'paths-ignore' in spec:
        return not all(sr.matches(f, spec['paths-ignore']) for f in changed)
    return True


CHANGES = (['docs/x.md'], ['README.md'], ['.github/workflows/self-test.yml'], ['docs/x.md', 'scripts/y.py'])


def check_pending(doc, label):
    bad = []
    on = on_of(doc)
    for ch in CHANGES:
        if not would_start(on, 'pull_request', ch):
            bad.append('S1 %s does not start on a pull_request changing %s: its required check would '
                       'stay PENDING forever' % (label, ch))
    return bad


def job_if(job):
    return ' '.join(str(job.get('if', '')).split())


def check_structure(doc):
    bad = check_pending(doc, 'self-test.yml')
    jobs = doc.get('jobs') or {}
    plan, verdict = jobs.get(sr.PLANJOB), jobs.get(sr.VERDICTJOB)
    if not plan or not verdict:
        return bad + ['S2 self-test lacks the %s / %s jobs' % (sr.PLANJOB, sr.VERDICTJOB)]
    if 'if' in plan or plan.get('needs'):
        bad.append('S2 the plan job must always run: no if:, no needs')
    if job_if(verdict) != 'always()':
        bad.append('S2 the verdict job is %r, not if: always(): a failed dependency would SKIP the '
                   'required check, and skipped reads green' % verdict.get('if'))
    vn = verdict.get('needs') or []
    vn = [vn] if isinstance(vn, str) else list(vn)
    others = set(jobs) - {sr.VERDICTJOB}
    if set(vn) != others:
        bad.append('S2 the verdict does not need every job: missing %s, extra %s'
                   % (sorted(others - set(vn)), sorted(set(vn) - others)))
    if verdict.get('name') != 'Self-test required':
        bad.append('S2 the verdict job must be named "Self-test required" (the check to require)')
    for jid, job in jobs.items():
        if jid in (sr.VERDICTJOB,):
            continue
        cond = job_if(job)
        if jid in sr.SKIPPABLE:
            want = "needs.%s.outputs.skip_%s != 'true'" % (sr.PLANJOB, jid.replace('-', '_'))
            n = job.get('needs') or []
            n = [n] if isinstance(n, str) else list(n)
            if cond != want or sr.PLANJOB not in n:
                bad.append('S3 %s is skippable but its if: is %r (want %r) / needs %s' % (jid, cond, want, n))
        elif jid in sr.EVENTGATED:
            if cond != ' '.join(sr.EVENTGATED[jid].split()):
                bad.append('S3 %s if: %r differs from EVENTGATED %r' % (jid, cond, sr.EVENTGATED[jid]))
        elif cond:
            bad.append('S3 %s carries an if: (%r) the verdict cannot account for: a skip there would '
                       'be unexplained' % (jid, cond))
    for jid in sr.EVENTGATED:
        if jid not in jobs:
            bad.append('S3 EVENTGATED names %s, which is not a self-test job' % jid)
    return bad


# ── S4: what a job reads ────────────────────────────────────────────────────────────────────
def constants(path):
    """String constants in a Python file, docstrings excluded."""
    try:
        tree = ast.parse(io.open(path, encoding='utf-8').read())
    except (SyntaxError, OSError, UnicodeDecodeError):
        return None
    docs = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            b = getattr(node, 'body', [])
            if b and isinstance(b[0], ast.Expr) and isinstance(getattr(b[0], 'value', None), ast.Constant):
                docs.add(id(b[0].value))
    return [n.value for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docs]


def closure(job):
    """-> (python files, composite files) a job runs, transitively over local imports and named kit files."""
    text = json.dumps(job)
    files = set(re.findall(r'\b((?:tests|scripts)/[A-Za-z0-9_]+\.py)\b', text))
    comps = set()
    todo = list(files)
    seen = set()
    while todo:
        f = todo.pop()
        if f in seen:
            continue
        seen.add(f)
        p = os.path.join(ROOT, f)
        if not os.path.isfile(p):
            continue
        src = io.open(p, encoding='utf-8').read()
        for m in re.finditer(r'(?m)^\s*(?:import|from)\s+([A-Za-z_]\w*)', src):
            for d in ('tests', 'scripts'):
                c = '%s/%s.py' % (d, m.group(1))
                if os.path.isfile(os.path.join(ROOT, c)):
                    todo.append(c)
        for m in re.finditer(r"['\"]((?:tests|scripts)/[A-Za-z0-9_]+\.py)['\"]", src):
            todo.append(m.group(1))
        for m in re.finditer(r"\.github/actions/([a-z0-9-]+)|'actions',\s*'([a-z0-9-]+)'", src):
            comps.add(m.group(1) or m.group(2))
    return sorted(seen), sorted(comps)


def reads_of(job, globs):
    """-> [(file, constant)] for every constant naming a path inside `globs`."""
    hits = []
    pyfiles, comps = closure(job)
    dirs = sorted({g.split('/', 1)[0] for g in globs if '/' in g})
    pat = re.compile(r'(^|[/\\])(%s)([/\\]|$)' % '|'.join(re.escape(d) for d in dirs)) if dirs else None
    for f in pyfiles:
        cs = constants(os.path.join(ROOT, f))
        if cs is None:
            hits.append((f, 'UNPARSEABLE: cannot be proven'))
            continue
        for c in cs:
            if (pat and pat.search(c)) or any(fnmatch.fnmatchcase(c, g) for g in globs):
                hits.append((f, c[:80]))
    # A composite's run text is shell (and inline Python). A comment or a printed sentence that
    # mentions a doc is not a read; a doc path reached from a root (the kit, the workspace, the
    # action path, a parent directory) or handed to a command that reads files is.
    if dirs:
        alt = '|'.join(re.escape(d) for d in dirs)
        read = re.compile(r'(?:kit_root|GITHUB_WORKSPACE|GITHUB_ACTION_PATH|ROOT|\.\.)[^\s"\']*/(?:%s)/'
                          r'|\b(?:open|cat|head|tail|grep|find|ls|cp|source|less|read_text)\b[^\n]*\b(?:%s)/'
                          r'|[\'"](?:%s)[\'"]' % (alt, alt, alt))
        for c in comps:
            p = os.path.join(ROOT, '.github', 'actions', c, 'action.yml')
            if not os.path.isfile(p):
                continue
            for n, line in enumerate(io.open(p, encoding='utf-8').read().split('\n'), 1):
                if line.strip().startswith('#'):
                    continue
                if read.search(line):
                    hits.append(('.github/actions/%s:%d' % (c, n), line.strip()[:80]))
    return hits


def check_safe(doc):
    bad = []
    jobs = doc.get('jobs') or {}
    for jid, globs in sr.SKIPPABLE.items():
        if jid not in jobs:
            bad.append('S4 SKIPPABLE names %s, which is not a self-test job' % jid)
            continue
        hits = reads_of(jobs[jid], globs)
        for f, c in hits[:10]:
            bad.append('S4 %s is skippable on %s, but %s reads %r' % (jid, globs, f, c))
    # Positive control: the analysis sees docs reads where they exist.
    nd = jobs.get('normalizer-drift')
    if nd is None or not reads_of(nd, ['docs/**']):
        bad.append('S4 positive control: the analysis found no docs read in normalizer-drift, which '
                   'runs check_doc_currency -- the analysis is blind')
    if 'normalizer-drift' in sr.SKIPPABLE:
        bad.append('S4 normalizer-drift reads docs and must never be plan-skippable')
    return bad


# ── S5: the plan and verdict steps, as shipped ──────────────────────────────────────────────
def run_step(bash, step, ctx, extra_env):
    import _step_harness as h
    home = tempfile.mkdtemp(prefix='str-')
    # On the runner the step runs in the checkout; the harness runs it in a scratch directory, so
    # the one relative path it names is pointed at this tree. Nothing else in the step changes.
    step = dict(step, run=str(step.get('run') or '').replace(
        'scripts/selftest_required.py', os.path.join(ROOT, 'scripts', 'selftest_required.py').replace(os.sep, '/')))
    try:
        env = dict(extra_env)
        env['RUNNER_TEMP'] = home.replace(os.sep, '/')
        for k, v in list(env.items()):
            if k == '_CHANGED':
                io.open(os.path.join(home, 'changed.txt'), 'w', encoding='utf-8', newline='\n').write(v)
        env.pop('_CHANGED', None)
        return h.run(bash, step, ctx, home, extra_env=env)
    finally:
        shutil.rmtree(home, ignore_errors=True)


def check_steps(bash, doc):
    bad = []
    jobs = doc['jobs']
    plan_step = next((s for s in jobs[sr.PLANJOB]['steps'] if s.get('id') == 'plan'), None)
    v_step = next((s for s in jobs[sr.VERDICTJOB]['steps'] if s.get('id') == 'verdict'), None)
    if not plan_step or not v_step:
        return ['S5 the plan step (id plan) or the verdict step (id verdict) is missing']
    cwd = os.getcwd()
    os.chdir(ROOT)
    try:
        r = run_step(bash, plan_step, {'github.event_name': 'pull_request'}, {'_CHANGED': 'docs/a.md\ndocs/b/c.md\n'})
        skips = r['outputs'].get('skips')
        if r['rc'] != 0 or json.loads(skips or '{}').get('platform-scanners') is not True:
            bad.append('S5 a docs-only PR did not plan the platform-scanners skip: rc %d %r %s'
                       % (r['rc'], r['outputs'], r['log'][-300:]))
        r2 = run_step(bash, plan_step, {'github.event_name': 'pull_request'}, {'_CHANGED': 'docs/a.md\nscripts/x.py\n'})
        if json.loads(r2['outputs'].get('skips') or '{}').get('platform-scanners') is not False:
            bad.append('S5 a PR touching a script planned a skip: %r' % r2['outputs'])
        names = [j for j in jobs if j != sr.VERDICTJOB]

        def needs(**over):
            d = {}
            for j in names:
                res = 'success'
                if j in sr.EVENTGATED and sr.runs_on(sr.EVENTGATED[j], 'pull_request') is False:
                    res = 'skipped'
                d[j] = {'result': over.get(j.replace('-', '_'), res), 'outputs': {}}
            return d
        cases = (('planned skip', needs(platform_scanners='skipped'), skips, 0),
                 ('unplanned skip', needs(platform_scanners='skipped'), '{"platform-scanners":false}', 1),
                 ('skipped = green, refused', needs(normalizer_drift='skipped'), skips, 1),
                 ('failed plan', needs(contract='failure'), skips, 1),
                 ('all green', needs(), skips, 0))
        for label, nd, sk, want in cases:
            ctx = {'toJSON(needs)': json.dumps(nd), 'needs.contract.outputs.skips': sk or '',
                   'github.event_name': 'pull_request'}
            r = run_step(bash, v_step, ctx, {})
            got = 0 if r['rc'] == 0 else 1
            if got != want:
                bad.append('S5 verdict %s: rc %d, want %s: %s' % (label, r['rc'], 'pass' if not want else 'fail', r['log'][-300:]))
    finally:
        os.chdir(cwd)
    return bad


def mutations(doc):
    blind = []

    def caught(m, fn=check_structure):
        return bool(fn(m))
    m = copy.deepcopy(doc)
    on_of(m)['pull_request'] = {'paths-ignore': ['docs/**']}
    if not caught(m):
        blind.append('paths-ignore on pull_request')
    m = copy.deepcopy(doc)
    m['jobs']['normalizer-drift']['if'] = 'false'
    if not caught(m):
        blind.append('if: false on normalizer-drift')
    m = copy.deepcopy(doc)
    m['jobs'][sr.VERDICTJOB]['if'] = 'success()'
    if not caught(m):
        blind.append('required without always()')
    m = copy.deepcopy(doc)
    m['jobs'][sr.VERDICTJOB]['needs'] = [n for n in m['jobs'][sr.VERDICTJOB]['needs'] if n != 'normalizer-drift']
    if not caught(m):
        blind.append('normalizer-drift dropped from the verdict\'s needs')
    saved = dict(sr.SKIPPABLE)
    try:
        sr.SKIPPABLE['normalizer-drift'] = ['docs/**']
        if not check_safe(doc):
            blind.append('normalizer-drift made skippable on docs/**')
    finally:
        sr.SKIPPABLE.clear()
        sr.SKIPPABLE.update(saved)
    return blind


def main():
    import _step_harness as h
    doc = yaml.safe_load(io.open(WF, encoding='utf-8'))
    bad = check_structure(doc)
    for t in TEMPLATES:
        bad += check_pending(yaml.safe_load(io.open(t, encoding='utf-8')), os.path.basename(t))
    bad += check_safe(doc)
    if not any(b.startswith('S2 self-test lacks') for b in bad):
        bash, why = h.usable_bash()
        if not bash:
            print('UNKNOWN: no usable bash (%s); S5 not run.' % why)
            return 2
        bad += check_steps(bash, doc)
        bad += ['M mutation went undetected: %s' % b for b in mutations(doc)]
    for b in bad:
        print('VIOLATION: ' + b)
    if bad:
        print('FAIL: %d violation(s)' % len(bad))
        return 1
    print('PASS: self-test starts on every pull request; one always-running verdict needs every job; '
          'a skip is green only when planned and proven safe or excluded by the job\'s own event; '
          'normalizer-drift (reads docs) is never skipped; 5 mutations caught.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
