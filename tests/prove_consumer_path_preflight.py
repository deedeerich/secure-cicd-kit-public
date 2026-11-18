#!/usr/bin/env python3
"""The consumer path test is the PRE-FLIGHT a kit host runs before any real pipeline -- on ITS platform.

WHY THIS EXISTS (owner ruling, 2026-11-03)

    "If the consumer path test is no longer good why is it still in the package, or why haven't
    you fixed it so that it runs and tests things out before a true run of the pipeline?"

    The exporter left .github/workflows/consumer-path-test.yml out of every export ("it tests the
    kit where it is developed; in a recipient's copy it is a scheduled job billing their
    minutes"). But the consumer-am copy is not a mere consumer: it is that organisation's private
    HOST of the kit, which their other repositories call -- on a GHE.com host (data residency),
    GitHub-hosted runners, GitHub Advanced Security OFF. The consumer path test is exactly the
    run that proves the whole chain there -- caller -> reusable -> scanners -> finding -> gate ->
    caller fails; clean passes; skips visible -- before any real repository is wired. Their copy
    held a pre-2026-10-16 version that failed with 401s, and nothing replaced it.

    Owner, same day: "we turn off the test once we are green with it and if we run into issues
    we turn it back on to troubleshoot." So in a recipient's copy it is DISPATCH-ONLY by default.

WHAT IT PROVES

    C1  SCHEDULE IS OPT-IN. The workflow has workflow_dispatch; if it has a schedule, every job is
        conditioned on `github.event_name != 'schedule' || vars.KIT_CONSUMER_PATH_SCHEDULE ==
        'true'`, so a scheduled run with the variable unset starts no job and bills nothing.
        Evaluated, not grepped: each job's `if` is evaluated for a scheduled event with the
        variable unset (every job skips), set to 'true' (jobs run), and for workflow_dispatch
        (jobs run).
    C2  THE JOB TOKEN PERMISSIONS IT NEEDS ARE DECLARED: actions: write on the two jobs that
        dispatch the negative workflow, actions: read and security-events: read on the job that
        collects outcomes and records the GHAS rows; no job asks for more than that.
    C3  GHAS-DEPENDENT EVIDENCE IS NEVER GRADED (tests/verify_expected_signals.py --not-graded):
          allowed   every signal flagged by an open-source scanner, a CodeQL SARIF beside them:
                    exit 0, the CodeQL SARIF reported NOT GRADED;
          attack    a signal flagged ONLY by CodeQL: exit 1, MISSED -- CodeQL cannot stand in for
                    the open-source scanner on a host where it may be unavailable;
          missing   no CodeQL SARIF at all: CodeQL reported UNAVAILABLE, exit 0 for the rest; a
                    signal pinned to CodeQL is UNAVAILABLE, outside the denominator, never a pass
                    and never a miss;
          recovery  with every graded signal pinned to a not-graded tool, nothing is graded:
                    exit 1, never a vacuous pass.
        And the workflow passes --not-graded codeql to the verifier.
    C4  BEHAVIOURAL, ON A SIMULATED GHE.COM HOST WITH GHAS OFF. The three assertion jobs
        (assert-contract, assert-seeded-blocks, assert-php-blocks) are run step by step as
        shipped, under bash, with a stub gh that answers ONLY when GH_HOST is the tenant
        (example.ghe.com) and every GH_REPO names it, and answers the code-scanning API 403
        "Advanced Security must be enabled". Every job reaches its assertions and passes:
        "Consumer contract held.", the negative run dispatched and graded "Every seeded signal
        was detected", the PHP verdict asserted; the GHAS rows say UNAVAILABLE for Security-tab
        publication and for each CodeQL leg, and are never a pass. Then three counterexamples
        through the same steps: a required open-source job missing fails assert-contract; a
        signal only CodeQL flagged fails the grade; a gh call without the tenant host fails the
        preflight by name.

    C5  RELEASE 4 IS IN THE CONSUMER PATH (owner, 2026-11-06). The job `r4-consumer-surface` exists,
        carries the same opt-in conditions (C1 evaluates it), holds contents: read only, and runs
        scripts/consumer_surface_check.py. That script PASSES on this tree (rows R1-R8: deploy
        callers' deployments: write + pull-requests: read, the five weakening fields, the readiness
        attestation file, typed and manual verdicts, the durable release record, JIRA_HOST as a
        secret, the kit API's intake, the Dependabot callers) and FAILS, on the named row, in a copy
        of the tree with one Release 4 change undone: a deploy caller without deployments: write (R1),
        a promotion without weakening_approver (R2), an attestation whose issuer is not AppSec (R3),
        the manual-review fields not forwarded (R4), the Deployments API answering no id (R5),
        JIRA_HOST passed as a variable (R6), the API caller missing pull-requests: read (R7), and the
        keep-current job removed (R8).
    C6  ON DEMAND ONLY (owner, 2026-11-06: "the consumer test should only run when we want to check
        out changes to the whole structure, right?" -- yes). Every job is evaluated: a push to main
        with KIT_CONSUMER_PATH_ON_PUSH unset starts none; with it 'true' all run; there is no
        pull_request trigger; a dispatch runs them all.

    KIT_PROOF_ROOT=<dir> points C1, C2 and C4 at another tree, so the proof can be shown FAILING
    on the revision before the fix.

EXIT  0 all hold   1 any does not   2 bash, jq or PyYAML unavailable -- UNKNOWN
"""
import fnmatch
import glob
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TREE = os.environ.get('KIT_PROOF_ROOT') or ROOT
sys.path.insert(0, HERE)

CPT = '.github/workflows/consumer-path-test.yml'
GATE_VAR = 'KIT_CONSUMER_PATH_SCHEDULE'
TENANT = 'example.ghe.com'
REPO = 'example-org/kit-host'
FAILS = []


def check(cond, msg, detail=()):
    print('  %s %s' % ('ok  ' if cond else 'FAIL', msg))
    if not cond:
        for d in detail:
            print('       ' + str(d)[:600])
        FAILS.append(msg)


def posix(p):
    return p.replace('\\', '/')


def copy_lacks_cpt(label):
    """An exported copy whose exporter withholds the workflow (the neutral export) has no kit copy of
    it: SOURCE-ONLY, by name, the way prove_job_token_named.py T3/T6 and prove_export_scope.py E9 do
    it. A copy that was sent the file, or a tree without the watermark, is checked. (Public run
    41885418827: C1..C4 failed in the Release 4 candidate's exported tree.)"""
    import prove_job_token_named as pjt
    if pjt.source_only(CPT, TREE):
        print('  SOURCE-ONLY %s: nothing was checked here for %s, and nothing passed.' % (label, CPT))
        return True
    return False


def load_cpt(tree=None):
    import yaml
    f = os.path.join(tree or TREE, CPT)
    if not os.path.isfile(f):
        return None
    return yaml.safe_load(io.open(f, encoding='utf-8').read())


# ── C1: a tiny evaluator for the job `if` expressions this workflow uses ────────────────────
def eval_if(expr, ctx):
    """Evaluate a GitHub Actions `if` over ==, !=, &&, ||, !, (), always(), success(), literals
    and dotted context names. Anything else raises -- an expression this cannot read is not
    passed as true."""
    if expr is None:
        return True
    s = str(expr).strip()
    if s.startswith('${{') and s.endswith('}}'):
        s = s[3:-2].strip()
    toks = re.findall(r"\s*(\|\||&&|==|!=|!|\(|\)|'[^']*'|[A-Za-z_][A-Za-z0-9_.\-]*\(\)|[A-Za-z_][A-Za-z0-9_.\-]*)", s)
    if ''.join(t.strip() for t in toks) != re.sub(r'\s+', '', s):
        raise ValueError('unreadable expression: %r' % s)
    toks = [t.strip() for t in toks]
    pos = [0]

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else None

    def take():
        t = toks[pos[0]]
        pos[0] += 1
        return t

    def atom():
        t = take()
        if t == '(':
            v = orx()
            assert take() == ')'
            return v
        if t == '!':
            return not truthy(atom())
        if t.startswith("'"):
            return t[1:-1]
        if t in ('always()', 'success()'):
            return True
        if t in ('true', 'false'):
            return t == 'true'
        if t.endswith('()'):
            raise ValueError('unknown function %s' % t)
        return ctx.get(t, '')

    def truthy(v):
        return bool(v) and v != 'false'

    def cmp():
        v = atom()
        while peek() in ('==', '!='):
            op = take()
            w = atom()
            v = (str(v) == str(w)) if op == '==' else (str(v) != str(w))
        return v

    def andx():
        v = cmp()
        while peek() == '&&':
            take()
            w = cmp()
            v = truthy(v) and truthy(w)
        return v

    def orx():
        v = andx()
        while peek() == '||':
            take()
            w = andx()
            v = truthy(v) or truthy(w)
        return v

    v = orx()
    if pos[0] != len(toks):
        raise ValueError('trailing tokens in %r' % s)
    return truthy(v)


def c1():
    if copy_lacks_cpt('C1'):
        return
    doc = load_cpt()
    if doc is None:
        check(False, 'C1 %s exists' % CPT)
        return
    on = doc.get('on', doc.get(True)) or {}
    check(isinstance(on, dict) and 'workflow_dispatch' in on, 'C1 the workflow can be run by hand (workflow_dispatch)')
    jobs = doc.get('jobs') or {}
    scheduled = isinstance(on, dict) and 'schedule' in on
    for jid, job in sorted(jobs.items()):
        cond = job.get('if')
        try:
            off = eval_if(cond, {'github.event_name': 'schedule', 'vars.' + GATE_VAR: ''})
            on_ = eval_if(cond, {'github.event_name': 'schedule', 'vars.' + GATE_VAR: 'true'})
            disp = eval_if(cond, {'github.event_name': 'workflow_dispatch', 'vars.' + GATE_VAR: ''})
        except (ValueError, AssertionError, IndexError) as e:
            check(False, 'C1 %s: its `if` can be read (%s)' % (jid, e))
            continue
        needs = job.get('needs') or []
        if scheduled:
            check(not off or (needs and not job.get('if')),
                  'C1 %s: a scheduled run with %s unset starts nothing (if: %r)' % (jid, GATE_VAR, cond))
            check(on_, 'C1 %s: a scheduled run with %s=true runs it' % (jid, GATE_VAR))
        check(disp, 'C1 %s: a dispatched run runs it (if: %r)' % (jid, cond))


def c2():
    if copy_lacks_cpt('C2'):
        return
    doc = load_cpt()
    if doc is None:
        check(False, 'C2 %s exists' % CPT)
        return
    jobs = doc.get('jobs') or {}
    want = {'assert-seeded-blocks': {'contents': 'read', 'actions': 'write'},
            'assert-php-blocks': {'contents': 'read', 'actions': 'write'},
            'assert-contract': {'contents': 'read', 'actions': 'read', 'security-events': 'read'}}
    for jid, perms in sorted(want.items()):
        got = (jobs.get(jid) or {}).get('permissions') or {}
        check(got == perms, 'C2 %s declares exactly %s (got %s)' % (jid, perms, got))
    top = doc.get('permissions') or {}
    check(top == {'contents': 'read'}, 'C2 the workflow-level token is contents: read only (%s)' % top)


# ── C5: Release 4 in the consumer path; C6: on demand only ─────────────────────────────────────
C5_MUTANTS = [
    ('R1', 'templates/build-deploy.yml', '      deployments: write   # the deploy keeps its durable release record (KDEC-036 G6)\n', ''),
    ('R2', 'templates/build-deploy.yml', '      weakening_approver: ${{ inputs.exception_approver }}\n', ''),
    ('R3', 'tests/consumer-fixture/release4/.kit/zone-readiness.json', '"issuer_role": "appsec"', '"issuer_role": "developer"'),
    ('R4', 'templates/build-deploy.yml', '      manual_review_by: ${{ inputs.manual_review_by }}\n', ''),
    ('R5', 'scripts/reviewer_signals.py', "        dep_id = dep.get('id')\n", "        dep_id = None\n"),
    ('R6', 'templates/kit-api.yml', 'JIRA_HOST: ${{ secrets.JIRA_HOST }}', 'JIRA_HOST: ${{ vars.JIRA_HOST }}'),
    ('R7', 'templates/kit-api.yml', '      pull-requests: read   # tickets.submit reads back who approved a review record\'s pull request\n', ''),
    ('R8', 'templates/dependabot-triage.yml', 'reusable-dependabot-keep-current.yml@', 'reusable-not-keep-current.yml@'),
]


def surface(root):
    p = subprocess.run([sys.executable, os.path.join(root, 'scripts', 'consumer_surface_check.py'), '--root', root],
                       capture_output=True, text=True, encoding='utf-8', errors='replace')
    rows = {}
    for line in p.stdout.splitlines():
        m = re.match(r'^(R\d)\s+(PASS|FAIL)\s', line)
        if m:
            rows[m.group(1)] = m.group(2)
    return p.returncode, rows, p.stdout


def c5():
    if copy_lacks_cpt('C5'):
        return
    doc = load_cpt()
    if doc is None:
        check(False, 'C5 %s exists' % CPT)
        return
    job = (doc.get('jobs') or {}).get('r4-consumer-surface')
    check(job is not None, 'C5 the consumer path has the r4-consumer-surface job')
    if job is None:
        return
    check((job.get('permissions') or {}) == {'contents': 'read'}, 'C5 r4-consumer-surface holds contents: read only')
    runs = ' '.join(str(s.get('run', '')) for s in job.get('steps') or [])
    check('scripts/consumer_surface_check.py' in runs, 'C5 it runs scripts/consumer_surface_check.py')
    rc, rows, out = surface(TREE)
    check(rc == 0 and len(rows) == 8 and set(rows.values()) == {'PASS'},
          'C5 the Release 4 consumer surface PASSES on this tree (%s)' % (rows or out[-300:]))
    work = tempfile.mkdtemp(prefix='cpt-c5-')
    try:
        for d in ('templates', 'scripts', 'api', 'schemas', os.path.join('tests', 'consumer-fixture', 'release4'),
                  '.github'):
            src = os.path.join(TREE, d)
            if os.path.isdir(src):
                shutil.copytree(src, os.path.join(work, d))
        for rid, rel, old, new in C5_MUTANTS:
            path = os.path.join(work, *rel.split('/'))
            text = io.open(path, encoding='utf-8').read()
            if old not in text:
                check(False, 'C5 mutant %s: the text to undo is in %s' % (rid, rel))
                continue
            io.open(path, 'w', encoding='utf-8', newline='\n').write(text.replace(old, new, 1))
            try:
                rc, rows, out = surface(work)
            finally:
                io.open(path, 'w', encoding='utf-8', newline='\n').write(text)
            check(rc == 1 and rows.get(rid) == 'FAIL',
                  'C5 with Release 4 undone at %s, row %s FAILS (rc %s, %s)' % (rel, rid, rc, rows.get(rid)))
    finally:
        shutil.rmtree(work, ignore_errors=True)


def c6():
    if copy_lacks_cpt('C6'):
        return
    doc = load_cpt()
    if doc is None:
        return
    on = doc.get('on', doc.get(True)) or {}
    check('pull_request' not in on and 'pull_request_target' not in on,
          'C6 the consumer path never runs on a pull request (triggers: %s)' % sorted(on))
    check(((on.get('push') or {}).get('branches') or []) == ['main'], 'C6 its push trigger is main only')
    for jid, job in sorted((doc.get('jobs') or {}).items()):
        cond = job.get('if')
        try:
            off = eval_if(cond, {'github.event_name': 'push', 'vars.KIT_CONSUMER_PATH_ON_PUSH': ''})
            on_ = eval_if(cond, {'github.event_name': 'push', 'vars.KIT_CONSUMER_PATH_ON_PUSH': 'true'})
        except (ValueError, AssertionError, IndexError) as e:
            check(False, 'C6 %s: its `if` can be read (%s)' % (jid, e))
            continue
        needs = job.get('needs') or []
        check(not off or (needs and not cond), 'C6 %s: a push to main with KIT_CONSUMER_PATH_ON_PUSH unset starts nothing' % jid)
        check(on_, 'C6 %s: a push to main with KIT_CONSUMER_PATH_ON_PUSH=true runs it' % jid)


# ── C3: the verifier, with and without --not-graded ─────────────────────────────────────────
def sarif(results):
    return {'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'x'}}, 'results': [
        {'ruleId': 'r', 'message': {'text': 'm'},
         'locations': [{'physicalLocation': {'artifactLocation': {'uri': u}}}]} for u in results]}]}


def write(p, text):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with io.open(p, 'w', encoding='utf-8', newline='\n') as f:
        f.write(text)


def run_verify(fixture, sdir, extra):
    p = subprocess.run([sys.executable, os.path.join(ROOT, 'tests', 'verify_expected_signals.py'),
                        '--fixture', fixture, '--sarif-dir', sdir] + extra,
                       capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120)
    return p.returncode, p.stdout + p.stderr


def c3():
    d = tempfile.mkdtemp(prefix='cpt-c3-')
    try:
        fx = os.path.join(d, 'fx')
        for rel in ('a/vuln.py', 'b/vuln.js', 'c/quiet.md', 'd/flow.java'):
            write(os.path.join(fx, rel), 'x\n')

        def setup(expected, tools):
            write(os.path.join(fx, 'EXPECTED_SIGNALS.json'), json.dumps(expected))
            sd = os.path.join(d, 'sarif')
            shutil.rmtree(sd, ignore_errors=True)
            for tool, uris in tools.items():
                write(os.path.join(sd, 'sarif-%s-1' % tool, tool + '.sarif'), json.dumps(sarif(uris)))
            return sd

        base = [{'path': 'a/vuln.py', 'expected_signal': 'sast:py', 'tool': 'bandit'},
                {'path': 'b/vuln.js', 'expected_signal': 'sast:js'},
                {'path': 'c/quiet.md', 'expected_signal': 'negative:quiet'}]
        # allowed
        sd = setup(base, {'bandit': ['a/vuln.py'], 'semgrep': ['b/vuln.js'], 'codeql-python': ['a/vuln.py']})
        rc, out = run_verify(fx, sd, ['--not-graded', 'codeql'])
        check(rc == 0 and 'NOT GRADED' in out and 'codeql' in out,
              'C3 allowed: open-source scanners flag every signal, CodeQL beside them is NOT GRADED (rc=%d)' % rc,
              [out[-500:]])
        # attack: only CodeQL flags b/vuln.js
        sd = setup(base, {'bandit': ['a/vuln.py'], 'codeql-javascript': ['b/vuln.js']})
        rc, out = run_verify(fx, sd, ['--not-graded', 'codeql'])
        check(rc == 1 and re.search(r'MISSED\s+sast:js', out) is not None,
              'C3 attack: a signal only CodeQL flagged is MISSED with --not-graded codeql (rc=%d)' % rc, [out[-500:]])
        rc0, out0 = run_verify(fx, sd, [])
        check(rc0 == 0, 'C3 control: without --not-graded the same evidence grades as before (rc=%d)' % rc0,
              [out0[-300:]])
        # missing evidence: no CodeQL SARIF; a signal pinned to CodeQL
        pinned = base + [{'path': 'd/flow.java', 'expected_signal': 'sast:java-flow', 'tool': 'codeql-java'}]
        sd = setup(pinned, {'bandit': ['a/vuln.py'], 'semgrep': ['b/vuln.js']})
        rc, out = run_verify(fx, sd, ['--not-graded', 'codeql'])
        check(rc == 0 and re.search(r'UNAVAILABLE\s+sast:java-flow', out) is not None
              and re.search(r'UNAVAILABLE\s+codeql', out) is not None
              and 'detected 2/2' in out,
              'C3 missing: no CodeQL SARIF is UNAVAILABLE, a CodeQL-pinned signal is UNAVAILABLE and outside '
              'the denominator (rc=%d)' % rc, [out[-600:]])
        check(not re.search(r'DETECTED\s+sast:java-flow', out),
              'C3 missing: a CodeQL-pinned signal is never DETECTED with --not-graded codeql')
        # recovery: nothing graded is not a pass
        only = [{'path': 'd/flow.java', 'expected_signal': 'sast:java-flow', 'tool': 'codeql-java'}]
        sd = setup(only, {'codeql-java': ['d/flow.java']})
        rc, out = run_verify(fx, sd, ['--not-graded', 'codeql'])
        check(rc == 1, 'C3 recovery: with nothing left to grade the verifier fails, never a vacuous pass (rc=%d)' % rc,
              [out[-300:]])
    finally:
        shutil.rmtree(d, ignore_errors=True)
    if copy_lacks_cpt('C3 (the workflow half; the verifier half above ran)'):
        return
    doc = load_cpt()
    runs = [st.get('run') or '' for j in ((doc or {}).get('jobs') or {}).values() for st in (j.get('steps') or [])]
    calls = [r for r in runs if 'verify_expected_signals.py' in r]
    check(bool(calls) and all(re.search(r'--not-graded\s+codeql', r) for r in calls),
          'C3 the workflow grades with --not-graded codeql (%d call(s))' % len(calls))


# ── C4: run the assertion jobs as shipped, on a simulated GHE.com host, GHAS off ──────────────
STUB_PY = r'''
import fnmatch, json, os, shutil, sys
a = sys.argv[1:]
st = os.environ['stub_state']
with open(os.path.join(st, 'calls.log'), 'a', encoding='utf-8') as f:
    f.write(json.dumps({'argv': a, 'GH_HOST': os.environ.get('GH_HOST', ''),
                        'GH_REPO': os.environ.get('GH_REPO', '')}) + '\n')
tenant = os.environ['stub_tenant']
repo = os.environ['GITHUB_REPOSITORY']
if os.environ.get('GH_HOST') != tenant or (os.environ.get('GH_REPO') and not os.environ['GH_REPO'].startswith(tenant + '/')):
    print('{\n  "message": "Bad credentials",\n  "status": "401"\n}')
    sys.stderr.write('gh: Bad credentials (HTTP 401)\n')
    sys.exit(1)
def counter(k, v=None):
    p = os.path.join(st, k)
    if v is None:
        return open(p).read().strip() if os.path.exists(p) else ''
    open(p, 'w').write(str(v))
if a[0] == 'api':
    path = a[1]
    if path == 'repos/' + repo:
        print(json.dumps({'full_name': repo, 'visibility': 'private'})); sys.exit(0)
    if '/code-scanning/' in path:
        if os.environ.get('stub_ghas') == 'on':
            print('[]'); sys.exit(0)
        print('{"message":"Advanced Security must be enabled for this repository to use code scanning.","status":"403"}')
        sys.stderr.write('gh: Advanced Security must be enabled for this repository to use code scanning. (HTTP 403)\n')
        sys.exit(1)
    if path.endswith('/jobs'):
        sys.stdout.write(open(os.environ['stub_jobs'], encoding='utf-8').read()); sys.exit(0)
    print('{"message":"Not Found","status":"404"}'); sys.exit(1)
import subprocess
def runs(v=None):
    p = os.path.join(st, 'runs.json')
    if v is None:
        return json.load(open(p)) if os.path.exists(p) else []
    json.dump(v, open(p, 'w'))
def jq(doc, expr):
    p = subprocess.run(['jq', '-r', expr], input=json.dumps(doc), capture_output=True, text=True)
    if p.returncode:
        sys.stderr.write('stub gh: jq failed: %s\n' % p.stderr); sys.exit(1)
    sys.stdout.write(p.stdout)
def opt(name, default=''):
    for x in a:
        if x.startswith(name + '='):
            return x.split('=', 1)[1]
    return a[a.index(name) + 1] if name in a else default
if a[:2] == ['run', 'list']:
    # Newest first, like the API. A decoy (another person's or a scheduled run) can be the newest.
    wf = opt('--workflow')
    rows = [r for r in runs() if r['workflow'] == wf and r['branch'] == opt('--branch')
            and (not opt('--event') or r['event'] == opt('--event'))]
    rows = sorted(rows, key=lambda r: -r['databaseId'])[:int(opt('--limit', '20'))]
    jq(rows, opt('--jq', '.')); sys.exit(0)
if a[:2] == ['workflow', 'run']:
    rs = runs()
    nxt = lambda: max([r['databaseId'] for r in rs] + [100]) + 1
    fields = [a[i + 1] for i, x in enumerate(a) if x == '--field']
    f = dict(x.split('=', 1) for x in fields)
    scope = f.get('scope', 'full')
    cid = f.get('correlation_id', '')
    if os.environ.get('stub_nomatch') == '1':
        cid = cid + '-x'          # the run never shows the id we asked for
    def add(c, event='workflow_dispatch', concl=None, sc=scope):
        rs.append({'databaseId': nxt(), 'workflow': a[2], 'branch': opt('--ref'), 'event': event, 'scope': sc,
                   'conclusion': concl, 'displayTitle': 'Consumer path negative [%s] scope=%s' % (c or 'uncorrelated', sc)})
    add(cid)
    if os.environ.get('stub_dupe') == '1':
        add(cid)
    if os.environ.get('stub_decoy') == '1':
        # A newer run on the same branch: another person's negative run with its own id. It FAILED, as a
        # negative should, so "the latest run" would read it as this run's proof (item 11).
        add('someone-else-123', concl=os.environ.get('stub_decoy_conclusion', 'failure'))
    runs(rs)
    sys.exit(0)
if a[:2] == ['run', 'view']:
    rid = int(a[2])
    r = [x for x in runs() if x['databaseId'] == rid]
    if not r:
        sys.stderr.write('run %s not found\n' % rid); sys.exit(1)
    r = r[0]
    scope = r['scope']
    concl = r['conclusion'] or ('success' if scope == 'php' else 'failure')
    j = opt('--json')
    if j == 'jobs':
        sys.stdout.write(open(os.path.join(os.environ['stub_art'], 'jobs-' + scope + '.tsv'), encoding='utf-8').read())
        sys.exit(0)
    doc = {'status': 'completed', 'conclusion': concl, 'displayTitle': r['displayTitle'],
           'event': os.environ.get('stub_view_event') or r['event'],
           'headBranch': r['branch']}
    jq(doc, opt('--jq', '.')); sys.exit(0)
if a[:2] == ['run', 'download']:
    rid = a[2]
    pat = a[a.index('-p') + 1]
    dest = a[a.index('-D') + 1]
    src = os.path.join(os.environ['stub_art'], [x for x in runs() if str(x['databaseId']) == rid][0]['scope'])
    hit = 0
    for n in sorted(os.listdir(src)) if os.path.isdir(src) else []:
        if fnmatch.fnmatch(n, pat):
            shutil.copytree(os.path.join(src, n), os.path.join(dest, n))
            hit += 1
    if not hit:
        sys.stderr.write('no valid artifacts found to download\n'); sys.exit(1)
    sys.exit(0)
sys.stderr.write('stub gh: unhandled %r\n' % a); sys.exit(1)
'''

EXPR = re.compile(r'\$\{\{\s*(.+?)\s*\}\}')


def subst(text, ctx):
    missing = []

    def rep(m):
        k = m.group(1)
        if k not in ctx:
            missing.append(k)
            return ''
        return ctx[k]
    out = EXPR.sub(rep, text)
    if missing:
        raise KeyError('unknown expression(s): %s' % ', '.join(sorted(set(missing))))
    return out


def parse_output(path):
    kv = {}
    if os.path.isfile(path):
        for ln in io.open(path, encoding='utf-8').read().splitlines():
            if '=' in ln and '<<' not in ln.split('=', 1)[0]:
                k, v = ln.split('=', 1)
                kv[k] = v
    return kv


def tracked_copy(dest):
    """The tree's tracked tests/ and .github/ -- what a checkout holds (generated seeds are not)."""
    p = subprocess.run(['git', '-C', TREE, 'ls-files', '-z', '--', 'tests', '.github', 'scripts'],
                       capture_output=True, timeout=120)
    names = [n for n in p.stdout.decode('utf-8', 'replace').split('\0') if n] if p.returncode == 0 else []
    if not names:
        for base in ('tests', '.github', 'scripts'):
            for f in glob.glob(os.path.join(TREE, base, '**', '*'), recursive=True):
                if os.path.isfile(f) and '__pycache__' not in f and '/secrets/' not in posix(f):
                    names.append(posix(os.path.relpath(f, TREE)))
    for n in names:
        s = os.path.join(TREE, n)
        if not os.path.isfile(s):
            continue
        t = os.path.join(dest, n)
        os.makedirs(os.path.dirname(t), exist_ok=True)
        shutil.copyfile(s, t)


class World(object):
    def __init__(self, bash):
        self.bash = bash
        self.d = tempfile.mkdtemp(prefix='cpt-c4-')
        self.ws = os.path.join(self.d, 'ws')
        self.st = os.path.join(self.d, 'state')
        self.art = os.path.join(self.d, 'art')
        self.bin = os.path.join(self.d, 'bin')
        for p in (self.ws, self.st, self.art, self.bin):
            os.makedirs(p)
        tracked_copy(self.ws)
        write(os.path.join(self.bin, 'stub_gh.py'), STUB_PY)
        py = posix(sys.executable)
        write(os.path.join(self.bin, 'gh'), '#!/usr/bin/env bash\nexec "%s" "%s" "$@"\n'
              % (py, posix(os.path.join(self.bin, 'stub_gh.py'))))
        write(os.path.join(self.bin, 'python3'), '#!/usr/bin/env bash\nexec "%s" "$@"\n' % py)
        write(os.path.join(self.bin, 'sleep'), '#!/usr/bin/env bash\nexit 0\n')
        for n in ('gh', 'python3', 'sleep'):
            os.chmod(os.path.join(self.bin, n), 0o755)
        self.summary = os.path.join(self.d, 'summary.md')
        io.open(self.summary, 'w').close()

    def close(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def env(self, extra):
        e = dict(os.environ)
        e.pop('GH_HOST', None)
        e.pop('GH_REPO', None)
        e.update({'GITHUB_SERVER_URL': 'https://' + TENANT, 'GITHUB_API_URL': 'https://api.' + TENANT,
                  'GITHUB_REPOSITORY': REPO, 'GITHUB_RUN_ID': '777', 'GITHUB_RUN_ATTEMPT': '1',
                  'GITHUB_STEP_SUMMARY': posix(self.summary), 'RUNNER_TEMP': posix(self.d),
                  'stub_state': self.st, 'stub_art': self.art, 'stub_tenant': TENANT,
                  'stub_jobs': os.path.join(self.st, 'jobs.tsv'), 'PYTHONIOENCODING': 'utf-8'})
        e.update(extra)
        return e

    def run_job(self, job, ctx, extra_env=None):
        """-> (rc of the first failing step or 0, combined log, outputs by step id)."""
        log, outs = [], {}
        for i, step in enumerate(job.get('steps') or []):
            if 'run' not in step:
                continue                      # actions/checkout: the workspace is the tracked copy
            c = dict(ctx)
            for sid, kv in outs.items():
                for k, v in kv.items():
                    c['steps.%s.outputs.%s' % (sid, k)] = v
            body = subst(step['run'], c)
            env = {k: subst(str(v), c) for k, v in (step.get('env') or {}).items()}
            outp = os.path.join(self.d, 'out-%d' % i)
            io.open(outp, 'w').close()
            env['GITHUB_OUTPUT'] = posix(outp)
            script = os.path.join(self.d, 'step-%d.sh' % i)
            write(script, body)
            prefix = 'export PATH="%s:$PATH"; ' % posix(self.bin)
            if os.name == 'nt':
                prefix = 'export PATH="$(cygpath -u "%s"):$PATH"; ' % posix(self.bin)
            p = subprocess.run([self.bash, '--noprofile', '--norc', '-eo', 'pipefail', '-c',
                                prefix + 'source "%s"' % posix(script)], cwd=self.ws,
                               env=self.env(dict(env, **(extra_env or {}))), capture_output=True, text=True,
                               encoding='utf-8', errors='replace', timeout=600)
            log.append('--- %s (rc=%d)\n%s%s' % (step.get('name'), p.returncode, p.stdout, p.stderr))
            if step.get('id'):
                outs[step['id']] = parse_output(outp)
            if p.returncode != 0:
                return p.returncode, '\n'.join(log), outs
        return 0, '\n'.join(log), outs

    def calls(self):
        f = os.path.join(self.st, 'calls.log')
        return [json.loads(l) for l in io.open(f, encoding='utf-8')] if os.path.isfile(f) else []


def expected_names(job, var):
    """The job names an assertion step expects, read from its own `expect` lines."""
    out = []
    for st in job.get('steps') or []:
        r = st.get('run') or ''
        pre = {}
        for m in re.finditer(r'^\s*(\w+)="([^"]+)"\s*$', r, re.M):
            pre[m.group(1)] = m.group(2)
        for m in re.finditer(r'^\s*%s\s+(\S+)\s+"([^"]+)"' % var, r, re.M):
            concl, name = m.group(1), m.group(2)
            for k, v in pre.items():
                name = name.replace('$' + k, v)
            out.append((concl, name))
        for m in re.finditer(r'for j in ((?:"[^"]+"\s*)+); do\s*\n\s*%s (\S+) "([^"]+)"' % var, r):
            for j in re.findall(r'"([^"]+)"', m.group(1)):
                out.append((m.group(2), m.group(3).replace('$j', j)))
    return out


def seed_artifacts(w, grade_attack=False):
    """The negative run as GitHub would hold it: SARIF per scanner, the seeds, the PHP verdict."""
    fx = os.path.join(w.ws, 'tests', 'consumer-fixture', 'full')
    exp = json.load(io.open(os.path.join(fx, 'EXPECTED_SIGNALS.json'), encoding='utf-8'))
    by_tool = {}
    dropped = None
    for e in exp:
        if e['expected_signal'].startswith('negative:'):
            continue
        tool = e.get('tool') or ('trivy-deps' if e['expected_signal'].startswith('deps:') else
                                 'gitleaks' if e['expected_signal'].startswith('secret:') else 'semgrep')
        uri = 'tests/consumer-fixture/full/' + e['path']
        if grade_attack and dropped is None and tool == 'semgrep':
            dropped = uri                       # only CodeQL will flag this one
            continue
        by_tool.setdefault(tool, []).append(uri)
    full = os.path.join(w.art, 'full')
    for tool, uris in by_tool.items():
        write(os.path.join(full, 'sarif-%s-1' % tool, tool + '.sarif'), json.dumps(sarif(uris)))
    write(os.path.join(full, 'sarif-codeql-java-kotlin-1', 'java.sarif'),
          json.dumps(sarif([dropped] if dropped else ['tests/consumer-fixture/full/java/Vuln.java'])))
    write(os.path.join(full, 'sarif-codeql-leg-java-kotlin-1', 'codeql-leg-java-kotlin.state'), 'COMPLETE\n')
    gen = os.path.join(w.d, 'gen')
    subprocess.run([sys.executable, os.path.join(w.ws, 'tests', 'make_fixture.py'), '--out', gen],
                   capture_output=True, timeout=120)
    shutil.copytree(os.path.join(gen, 'secrets'), os.path.join(full, 'test-only-seeds-1', 'secrets'))
    n = 'Seeded findings MUST block the caller'
    write(os.path.join(w.art, 'jobs-full.tsv'), ''.join('%s\t%s / %s\n' % x for x in (
        ('success', n, 'Secret scan (gitleaks + detect-secrets)'), ('failure', n, 'Security gate'),
        ('success', n, 'SAST (Semgrep)'), ('success', n, 'Dependency scan (Trivy fs)'),
        ('success', n, 'SAST (CodeQL) (java-kotlin)'))))
    p = 'Seeded PHP MUST block the caller'
    write(os.path.join(w.art, 'jobs-php.tsv'), ''.join('%s\t%s / %s\n' % x for x in (
        ('success', p, 'Discover what is actually here'), ('success', p, 'SAST (Semgrep)'),
        ('success', p, 'Dependency scan (Trivy fs)'), ('success', p, 'Security gate'),
        ('skipped', p, 'SAST (Bandit, python)'), ('skipped', p, 'SAST (Java)'), ('skipped', p, 'SAST (Go)'))))
    write(os.path.join(w.art, 'php', 'php-verdict-1', 'php-verdict.json'), json.dumps(
        {'routing_result': 'PROCEED_WITH_ADVISORY', 'advisory_causes': 'FINDINGS_NOT_BLOCKED',
         'rung_effective': 'crawl', 'policy_source': 'none', 'scanner_states': '{}', 'call_result': 'success'}))


def c4(bash):
    if copy_lacks_cpt('C4'):
        return
    doc = load_cpt()
    if doc is None:
        check(False, 'C4 %s exists' % CPT)
        return
    jobs = doc.get('jobs') or {}
    states = json.dumps({'bandit': 'PASS', 'semgrep': 'PASS', 'codeql-python': 'UNAVAILABLE',
                         'codeql-javascript-typescript': 'UNAVAILABLE'}, separators=(',', ':'))
    ctx = {'github.token': 'ghs_job_token_placeholder', 'github.repository': REPO, 'github.run_id': '777',
           'github.ref_name': 'main', 'needs.clean.result': 'success', 'needs.multi.result': 'success',
           'needs.clean.outputs.scanner_states': states, 'needs.multi.outputs.scanner_states': states,
           'needs.clean.outputs.routing_result': 'PROCEED_WITH_ADVISORY',
           'needs.multi.outputs.routing_result': 'PROCEED_WITH_ADVISORY'}

    def contract_world(drop=None, ghas='off'):
        w = World(bash)
        rows = [(c, n) for c, n in expected_names(jobs.get('assert-contract') or {}, 'expect') if n != drop]
        rows += [('success', 'clean / SAST (CodeQL) (python)'), ('success', 'clean / Plan (kit scripts, discovery, versions and capability)')]
        write(os.path.join(w.st, 'jobs.tsv'), ''.join('%s\t%s\n' % r for r in rows))
        return w

    # assert-contract, GHAS off
    w = contract_world()
    try:
        try:
            rc, log, _ = w.run_job(jobs.get('assert-contract') or {}, ctx)
        except KeyError as e:
            rc, log = 99, str(e)
        summ = io.open(w.summary, encoding='utf-8').read()
        check(rc == 0 and 'Consumer contract held.' in log and 'Both positive controls passed.' in log,
              'C4 GHE.com, GHAS off: assert-contract reaches its assertions and they hold (rc=%d)' % rc, [log[-900:]])
        check(re.search(r'Security-tab publication \| UNAVAILABLE', summ) is not None,
              'C4 GHAS off: the summary records Security-tab publication UNAVAILABLE', [summ[-600:]])
        check(re.search(r'codeql-python \| UNAVAILABLE', summ) is not None,
              'C4 GHAS off: the summary records each CodeQL leg UNAVAILABLE', [summ[-600:]])
        ghas_rows = [l for l in summ.splitlines() if l.startswith('| ') and ('codeql' in l or 'Security-tab' in l)]
        check(ghas_rows and not any(re.search(r'\|\s*(PASS|DETECTED|OK)\s*\|', l) for l in ghas_rows),
              'C4 GHAS off: no GHAS-dependent row reads as a pass', ghas_rows[:6])
        bad = [c for c in w.calls() if c['GH_HOST'] != TENANT]
        check(w.calls() and not bad, 'C4 every gh call in assert-contract went to %s (%d calls)' % (TENANT, len(w.calls())), bad[:3])
    finally:
        w.close()
    # assert-contract, GHAS on: still holds, publication ENABLED
    w = contract_world()
    try:
        try:
            rc, log, _ = w.run_job(jobs.get('assert-contract') or {}, ctx, {'stub_ghas': 'on'})
        except KeyError as e:
            rc, log = 99, str(e)
        summ = io.open(w.summary, encoding='utf-8').read()
        check(rc == 0 and re.search(r'Security-tab publication \| ENABLED', summ) is not None,
              'C4 GHAS on: the same assertions hold and publication reads ENABLED (rc=%d)' % rc, [summ[-400:], log[-400:]])
    finally:
        w.close()
    # counterexample: a required open-source job is absent
    w = contract_world(drop='clean / Secret scan (gitleaks + detect-secrets)')
    try:
        try:
            rc, log, _ = w.run_job(jobs.get('assert-contract') or {}, ctx)
        except KeyError as e:
            rc, log = 99, str(e)
        check(rc != 0 and 'Job absent' in log, 'C4 counterexample: a missing secret-scan job fails assert-contract by name (rc=%d)' % rc,
              [log[-400:]])
    finally:
        w.close()
    # counterexample: the job token goes to github.com, not the tenant
    w = contract_world()
    try:
        try:
            rc, log, _ = w.run_job(jobs.get('assert-contract') or {}, ctx, {'GITHUB_SERVER_URL': 'https://github.com'})
        except KeyError as e:
            rc, log = 99, str(e)
        check(rc != 0 and 'JOB_TOKEN_REJECTED' in log,
              'C4 counterexample: a token sent to the wrong host fails the preflight as JOB_TOKEN_REJECTED (rc=%d)' % rc,
              [log[-300:]])
    finally:
        w.close()

    # assert-seeded-blocks then assert-php-blocks, GHAS off
    w = World(bash)
    try:
        seed_artifacts(w)
        try:
            rc, log, _ = w.run_job(jobs.get('assert-seeded-blocks') or {}, ctx)
        except KeyError as e:
            rc, log = 99, str(e)
        check(rc == 0 and 'Negative control passed' in log and 'Every seeded signal was detected' in log,
              'C4 GHE.com, GHAS off: assert-seeded-blocks dispatches the negative, sees it blocked at the gate '
              'and grades every open-source signal (rc=%d)' % rc, [log[-1200:]])
        check('NOT GRADED' in log, 'C4 the CodeQL SARIF of the negative run is reported NOT GRADED', [log[-400:]])
        try:
            rc, log, _ = w.run_job(jobs.get('assert-php-blocks') or {}, ctx)
        except KeyError as e:
            rc, log = 99, str(e)
        check(rc == 0 and 'crawl: PHP findings on record' in log,
              'C4 GHE.com, GHAS off: assert-php-blocks asserts the PHP verdict (rc=%d)' % rc, [log[-600:]])
        bad = [c for c in w.calls() if c['GH_HOST'] != TENANT or (c['GH_REPO'] and not c['GH_REPO'].startswith(TENANT + '/'))]
        check(w.calls() and not bad, 'C4 every gh call of the dispatch jobs named %s (%d calls)' % (TENANT, len(w.calls())), bad[:3])
    finally:
        w.close()
    # counterexample: only CodeQL flagged one Semgrep signal
    w = World(bash)
    try:
        seed_artifacts(w, grade_attack=True)
        try:
            rc, log, _ = w.run_job(jobs.get('assert-seeded-blocks') or {}, ctx)
        except KeyError as e:
            rc, log = 99, str(e)
        check(rc != 0 and 'MISSED' in log,
              'C4 counterexample: a signal only CodeQL flagged fails the grade on a GHAS-off host (rc=%d)' % rc, [log[-500:]])
    finally:
        w.close()


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    import prove_bootstrap_failure as pbf
    bash, why = pbf.usable_bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s)' % why)
        return 2
    if shutil.which('jq') is None:
        print('UNKNOWN: jq is not on PATH; the workflow steps under proof need it.')
        return 2
    print('tree under proof: %s' % TREE)
    c1()
    c2()
    c3()
    c4(bash)
    c5()
    c6()
    print()
    if FAILS:
        print('FAIL: %d check(s): the consumer path test is not yet a pre-flight a GHAS-off GHE.com host can run.'
              % len(FAILS))
        return 1
    print('PASS: the consumer path test is dispatch-only by default, declares its token, never grades GHAS-dependent')
    print('      evidence, and reaches every assertion on a simulated GHE.com host with GHAS off.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
