#!/usr/bin/env python3
"""A consumer can ESTABLISH a baseline through the shipped reusable, and only by an approved PR (F-01).

WHY THIS EXISTS

    The completion audit (F-01 / L45) found that `reusable-propose-ledger.yml` never passed
    `establish-approver-role` to the propose-ledger composite, while `propose_ledger.py` refuses when
    no ledger exists unless that role is named. So no consumer could ever establish a baseline through
    the shipped path: every run naming an environment read LEDGER_ABSENT, and `identity_routing` read
    EVIDENCE_UNTRUSTED, forever. The library proofs (prove_propose_ledger.py) called the script
    directly and never saw that the workflow could not reach it.

    The design (ETFB section 5.4, section 8.3, section 10; SINGLE_PIPELINE_TARGET.md section 9.3):
    the ledger is a governance artifact, written only by a reviewed pull request on the protected
    default branch, under CODEOWNERS. Establishment is a governance act with a NAMED APPROVER ROLE
    recorded in the ledger header; it asserts no age ("first observed by us on <date>; the finding
    may be older"). It is never automatic: a baseline nobody approved is not a baseline.

WHAT IT PROVES, BY RUNNING THE SHIPPED STEPS (not the library)

    The reusable's own steps are executed under bash, in order, against a throwaway remote: the
    propose-ledger composite's `run:` (the real scripts/propose_ledger.py through GITHUB_ACTION_PATH),
    then the pushing step, with every `${{ }}` the steps carry rendered from a stated context. The
    GitHub API is a `gh` shim on PATH that records its arguments (as prove_propose_ledger_job_scope.py
    does). Checkout and the artifact download are the only steps simulated.

    static     the reusable declares an optional `establish-approver-role` input with NO default
               role (never auto-established) and hands it to the composite; it publishes the
               proposal's `status` and `why` as workflow outputs, so a caller can see a refusal.
    refused    no ledger, no approver role      -> status refused, the reason names the missing
                                                   approver role; nothing pushed; no PR opened.
    refused    no ledger, a role, no CODEOWNERS -> refused: nothing would make the named role the
               covering the ledger path            one who merges (ETFB section 10 "under CODEOWNERS").
    establish  no ledger, a role, CODEOWNERS     -> an ESTABLISHMENT pull request: the proposal branch
                                                   carries a ledger whose header names the role, every
                                                   entry age_established false; `gh pr create` called;
                                                   the default branch never moves.
    normal     an existing ledger, no role       -> an ordinary proposal; the header is unchanged.
    no reset   an existing ledger, a role given  -> an ordinary proposal; the header is NOT rewritten
                                                   and the body says the role was ignored: the input
                                                   establishes, it never re-baselines.

EXIT  0 proven   1 a case failed (named)   2 could not be checked (UNKNOWN, never PASS)
"""
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
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
WF = os.path.join(ROOT, '.github', 'workflows', 'reusable-propose-ledger.yml')
action_dir = os.path.join(ROOT, '.github', 'actions', 'propose-ledger')
JOB = 'propose-ledger'
LEDGER = '.security/finding-baseline.json'
EXPR = re.compile(r'\$\{\{\s*(.*?)\s*\}\}')


class Unrenderable(Exception):
    pass


def git(cwd, *args):
    p = subprocess.run(['git', '-c', 'user.name=t', '-c', 'user.email=t@example.invalid',
                        '-c', 'commit.gpgsign=false', '-c', 'init.defaultBranch=main',
                        '-c', 'core.autocrlf=false'] + list(args),
                       cwd=cwd, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError('git %s: %s' % (' '.join(args), p.stderr.strip()[:300]))
    return p.stdout.strip()


def render(value, ctx):
    """Render every ${{ }} in `value` from ctx (a flat dict of dotted names). A name the context does
    not hold is UNRENDERABLE -- the harness reports UNKNOWN rather than guessing a value."""
    if value is None:
        return ''
    text = str(value)

    def one(m):
        name = m.group(1)
        if name not in ctx:
            raise Unrenderable(name)
        return str(ctx[name])
    return EXPR.sub(one, text)


def write(path, text):
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        os.makedirs(d)
    with io.open(path, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write(text)


def outputs_of(path):
    out = {}
    if os.path.exists(path):
        for line in io.open(path, encoding='utf-8').read().splitlines():
            if '=' in line:
                k, v = line.split('=', 1)
                out[k] = v
    return out


def static(doc, action):
    problems = []
    inputs = (((doc.get(True) or doc.get('on') or {}).get('workflow_call') or {}).get('inputs') or {})
    role = inputs.get('establish-approver-role')
    if role is None:
        problems.append('static: the reusable has no `establish-approver-role` input, so no consumer can '
                        'ever establish a baseline through it (every run reads LEDGER_ABSENT)')
    else:
        if role.get('required') not in (False, None):
            problems.append('static: establish-approver-role is required; establishment must be opt-in')
        if str(role.get('default') or '') != '':
            problems.append('static: establish-approver-role defaults to %r -- a default role is an '
                            'automatic establishment nobody approved' % role.get('default'))
    job = (doc.get('jobs') or {}).get(JOB) or {}
    step = next((s for s in job.get('steps') or [] if s.get('id') == 'propose'), None)
    if step is None:
        problems.append('static: no step with id `propose`')
    elif 'inputs.establish-approver-role' not in str((step.get('with') or {}).get('establish-approver-role')):
        problems.append('static: the propose step does not hand `establish-approver-role` to the composite')
    outs = (((doc.get(True) or doc.get('on') or {}).get('workflow_call') or {}).get('outputs') or {})
    for k in ('status', 'why'):
        if k not in outs:
            problems.append('static: the reusable publishes no `%s` output, so a refusal is visible only '
                            'in a step summary nobody reads' % k)
    if 'establish-approver-role' not in ((action.get('inputs') or {})):
        problems.append('static: the composite has no establish-approver-role input')
    return problems


def step_runs(cond, ctx, step_outputs):
    """Evaluate the two condition forms the reusable uses; anything else is UNRENDERABLE."""
    m = re.match(r"^steps\.([\w-]+)\.outputs\.([\w-]+) == '([^']*)'$", cond)
    if m:
        return (step_outputs.get(m.group(1)) or {}).get(m.group(2)) == m.group(3)
    m = re.match(r"^inputs\.([\w-]+) != ''$", cond)
    if m:
        if 'inputs.' + m.group(1) not in ctx:
            raise Unrenderable('inputs.%s' % m.group(1))
        return str(ctx['inputs.' + m.group(1)]) != ''
    raise Unrenderable('step condition %r' % cond)


def run_reusable(doc, action, bash, work, remote, inputs, findings, artifacts=None):
    """Run the reusable's job steps as shipped. -> dict(status, why, outputs, refs, gh, body, rc, log).
    `artifacts` maps an artifact name to {file name: text}; the report's own artifact is `findings`."""
    job = doc['jobs'][JOB]
    clone = os.path.join(work, 'ws-%d' % len(os.listdir(work)))
    git(work, 'clone', '-q', remote, clone)
    runner_temp = os.path.join(work, 'rt-' + os.path.basename(clone))
    os.makedirs(runner_temp)
    shim = os.path.join(work, 'bin')
    if not os.path.isdir(shim):
        os.makedirs(shim)
        write(os.path.join(shim, 'gh'), '#!/usr/bin/env bash\nprintf \'%s\\n\' "$*" >> "$GH_LOG"\n')
        os.chmod(os.path.join(shim, 'gh'), 0o755)
    gh_log = os.path.join(runner_temp, 'gh.log')
    write(gh_log, '')
    fwd = lambda p: p.replace('\\', '/')  # noqa: E731 -- one path form bash and python both read
    ctx = {'github.event_name': 'push', 'github.ref': 'refs/heads/main', 'github.sha': 'f' * 40,
           'github.run_id': '4242', 'github.run_attempt': '1', 'github.token': 'unused',
           'github.event.repository.default_branch': 'main'}
    for k, spec in (((doc.get(True) or doc.get('on') or {}).get('workflow_call') or {}).get('inputs') or {}).items():
        ctx['inputs.' + k] = inputs.get(k, spec.get('default', ''))
    step_outputs = {}
    result = {'status': None, 'why': None, 'outputs': {}, 'gh': '', 'body': '', 'rc': 0, 'log': ''}
    for s in job.get('steps') or []:
        uses = str(s.get('uses') or '')
        if uses.startswith('actions/checkout@'):
            continue                                   # the clone above is the checkout
        cond = str(s.get('if') or '').strip()
        if cond and not step_runs(cond, ctx, step_outputs):
            continue
        if uses.startswith('actions/download-artifact@'):
            name = render((s.get('with') or {}).get('name'), ctx)
            dest = os.path.join(clone, render((s.get('with') or {}).get('path'), ctx))
            if name == 'security-report-1':
                write(os.path.join(dest, 'findings.json'), json.dumps(findings))
            elif name in (artifacts or {}):
                for fname, text in artifacts[name].items():
                    write(os.path.join(dest, fname), text)
            else:
                result['rc'] = 1                       # download-artifact fails on a missing name
                result['log'] += 'artifact %r not found' % name
                break
            continue
        github_output = os.path.join(runner_temp, 'out-%s' % (s.get('id') or len(step_outputs)))
        write(github_output, '')
        env = dict(os.environ, GITHUB_OUTPUT=fwd(github_output), RUNNER_TEMP=fwd(runner_temp),
                   GITHUB_STEP_SUMMARY=fwd(os.path.join(runner_temp, 'summary.md')), GH_LOG=fwd(gh_log),
                   PATH=shim + os.pathsep + os.environ.get('PATH', ''))
        if uses == '$/.github/actions/propose-ledger':
            actx = dict(ctx)
            for k, spec in (action.get('inputs') or {}).items():
                given = (s.get('with') or {}).get(k)
                actx['inputs.' + k] = render(given, ctx) if given is not None else spec.get('default', '')
            for k, v in (s.get('with') or {}).items():
                if k not in (action.get('inputs') or {}):
                    raise Unrenderable('the step passes %r, which the composite does not declare' % k)
            csteps = (action.get('runs') or {}).get('steps') or []
            if len(csteps) != 1:
                raise Unrenderable('the composite has %d steps; this harness runs exactly one' % len(csteps))
            script = str(csteps[0]['run'])
            for k, v in (csteps[0].get('env') or {}).items():
                env[k] = render(v, actx)
            env['GITHUB_ACTION_PATH'] = fwd(action_dir)
        elif s.get('run'):
            script = str(s['run'])
            ectx = dict(ctx)
            for sid, outs in step_outputs.items():
                for k, v in outs.items():
                    ectx['steps.%s.outputs.%s' % (sid, k)] = v
            for k, v in (s.get('env') or {}).items():
                env[k] = render(v, ectx)
        else:
            raise Unrenderable('step %r' % (s.get('name') or uses))
        runner = os.path.join(runner_temp, 'step.sh')
        write(runner, script)
        p = subprocess.run([bash, fwd(runner)], cwd=clone, capture_output=True, text=True, env=env)
        result['log'] += (p.stdout or '') + (p.stderr or '')
        if s.get('id'):
            step_outputs[s['id']] = outputs_of(github_output)
        if p.returncode != 0:
            result['rc'] = p.returncode
            break
    ectx = dict(ctx)
    for sid, outs in step_outputs.items():
        for k, v in outs.items():
            ectx['steps.%s.outputs.%s' % (sid, k)] = v
    for k, v in (job.get('outputs') or {}).items():
        try:
            result['outputs'][k] = render(v, ectx)
        except Unrenderable:
            result['outputs'][k] = ''
    prop = step_outputs.get('propose') or {}
    result['status'], result['why'] = prop.get('status'), prop.get('why')
    result['gh'] = io.open(gh_log, encoding='utf-8').read()
    body = prop.get('body-file')
    if body and os.path.exists(body):
        result['body'] = io.open(body, encoding='utf-8').read()
    return result


def main():
    try:
        import yaml
        from finding_identity import identify
        import baseline_ledger as bl
        import prove_bootstrap_failure as pbf
    except ImportError as exc:
        print('UNKNOWN: %s' % exc)
        return 2
    doc = yaml.safe_load(io.open(WF, encoding='utf-8'))
    action = yaml.safe_load(io.open(os.path.join(action_dir, 'action.yml'), encoding='utf-8'))
    fails = static(doc, action)
    bash, why = pbf.usable_bash()
    if not bash:
        for f in fails:
            print('FAIL: ' + f)
        print('UNKNOWN: no usable bash (%s); the shipped steps could not be run.' % why)
        return 1 if fails else 2
    for tool in ('jq', 'python3'):
        if not shutil.which(tool):
            print('UNKNOWN: %s is not on PATH; the composite needs it.' % tool)
            return 2

    def finding(path, sym, construct):
        return identify({'finding_subject': 'SOURCE', 'cwe': 'CWE-78', 'rule_family': 'cmd',
                         'canonical_path': path, 'symbol_path': sym, 'construct': construct,
                         'language_family': 'hash'})
    a, c = finding('app.py', 'm.a', 'run(a)'), finding('new.py', 'm.c', 'run(c)')
    work = tempfile.mkdtemp(prefix='propose-establish-')

    def seed(files):
        remote = os.path.join(work, 'remote-%d.git' % len(os.listdir(work)))
        os.makedirs(remote)
        git(remote, 'init', '-q', '--bare')
        s = remote + '-seed'
        os.makedirs(s)
        git(s, 'init', '-q')
        write(os.path.join(s, 'README'), 'x\n')
        for rel, text in files.items():
            write(os.path.join(s, rel), text)
        git(s, 'add', '-A')
        git(s, 'commit', '-qm', 'seed')
        git(s, 'push', '-q', remote, 'HEAD:refs/heads/main')
        return remote, git(remote, 'rev-parse', 'refs/heads/main')

    def refs(remote):
        return git(remote, 'for-each-ref', '--format=%(refname)').splitlines()

    owners = {'.github/CODEOWNERS': '/.security/ @example-org/security-leads\n'}
    prov = {'run_id': '41', 'observed_at': '2026-01-05T00:00:00Z', 'observed_at_source': 'SIDECAR'}
    header = {'established_on': '2026-01-05', 'established_commit': 'e' * 40, 'approver_role': 'security-lead'}
    existing = bl.serialise(bl.new_ledger(header, [bl.entry_from_identity(a, 'prod', '2026-01-05', prov, True)]))
    try:
        # ── refused: no ledger, no approver role ─────────────────────────────
        remote, main0 = seed(owners)
        r = run_reusable(doc, action, bash, work, remote, {'environment': 'prod'}, [a, c])
        if r['status'] != 'refused' or 'approver role' not in (r['why'] or ''):
            fails.append('refused: no ledger and no role gave status %r why %r (exit %s): %s'
                         % (r['status'], r['why'], r['rc'], r['log'][-300:]))
        if r['outputs'].get('status') != 'refused' or 'approver role' not in r['outputs'].get('why', ''):
            fails.append('refused: the caller cannot see the refusal -- workflow outputs %r' % r['outputs'])
        if refs(remote) != ['refs/heads/main'] or r['gh'].strip():
            fails.append('refused: something was pushed (%r) or a PR opened (%r)' % (refs(remote), r['gh']))

        # ── refused: a role, but nothing makes that role the one who merges ──
        remote, main0 = seed({})
        r = run_reusable(doc, action, bash, work, remote,
                         {'environment': 'prod', 'establish-approver-role': 'security-lead'}, [a, c])
        if r['status'] != 'refused' or 'CODEOWNERS' not in (r['why'] or ''):
            fails.append('refused: establishment with no CODEOWNERS over %s gave %r (%r)'
                         % (LEDGER, r['status'], r['why']))
        if refs(remote) != ['refs/heads/main'] or r['gh'].strip():
            fails.append('refused: establishment without CODEOWNERS pushed %r / opened %r' % (refs(remote), r['gh']))

        # ── establish: no ledger, a role, CODEOWNERS ─────────────────────────
        remote, main0 = seed(owners)
        r = run_reusable(doc, action, bash, work, remote,
                         {'environment': 'prod', 'establish-approver-role': 'security-lead'}, [a, c])
        branch = 'refs/heads/baseline-proposal/prod/4242'
        if r['status'] != 'proposed':
            fails.append('establish: no ledger with an approver role gave %r (%r, exit %s): %s'
                         % (r['status'], r['why'], r['rc'], r['log'][-400:]))
        elif branch not in refs(remote):
            fails.append('establish: the proposal branch did not reach the remote (%r)' % refs(remote))
        else:
            text = subprocess.run(['git', 'show', '%s:%s' % (branch, LEDGER)], cwd=remote,
                                  capture_output=True, text=True).stdout
            ents, st, nt, hdr = bl.parse_ledger(text)
            if st != bl.LEDGER_INTACT or hdr.get('approver_role') != 'security-lead':
                fails.append('establish: the proposed ledger is %s with header %r (%r)' % (st, hdr, nt))
            if any(e['age_established'] for e in ents):
                fails.append('establish: establishment asserted an age')
            if 'pr create' not in r['gh'] or 'ESTABLISH' not in r['gh']:
                fails.append('establish: no establishment pull request was opened (gh: %r)' % r['gh'])
            if 'security-lead' not in r['body']:
                fails.append('establish: the PR body does not name the approver role')
        if git(remote, 'rev-parse', 'refs/heads/main') != main0:
            fails.append('establish: the default branch MOVED -- establishment must be a PR, never a push')

        # ── normal: an existing ledger, no role ──────────────────────────────
        remote, main0 = seed(dict(owners, **{LEDGER: existing}))
        r = run_reusable(doc, action, bash, work, remote, {'environment': 'prod'}, [a, c])
        if r['status'] != 'proposed' or 'ESTABLISH' in (r['gh'] or ''):
            fails.append('normal: an existing ledger gave %r (gh %r, why %r): %s'
                         % (r['status'], r['gh'], r['why'], r['log'][-300:]))

        # ── one move record, through the shipped steps (L51) ─────────────────
        remote, main0 = seed(dict(owners, **{LEDGER: existing}))
        a_moved = finding('src/app.py', 'm.a', 'run(a)')
        r = run_reusable(doc, action, bash, work, remote, {'environment': 'prod'}, [a_moved, c])
        pushed = subprocess.run(['git', 'ls-tree', '-r', '--name-only', branch], cwd=remote,
                                capture_output=True, text=True).stdout.split()
        want = [LEDGER, '.security/finding-lineage.jsonl', '.security/finding-lineage.jsonl.head']
        if r['status'] != 'proposed' or any(w not in pushed for w in want):
            fails.append('move: a moved finding proposed %r and pushed %r; the ledger, the lineage '
                         'event and its head anchor travel in ONE pull request (%s)'
                         % (r['status'], pushed, r['log'][-300:]))
        elif 'move_history' in subprocess.run(['git', 'show', '%s:%s' % (branch, LEDGER)], cwd=remote,
                                              capture_output=True, text=True).stdout:
            fails.append('move: the pushed ledger entry still carries move_history -- two move records')

        # ── no reset: an existing ledger, a role given anyway ────────────────
        remote, main0 = seed(dict(owners, **{LEDGER: existing}))
        r = run_reusable(doc, action, bash, work, remote,
                         {'environment': 'prod', 'establish-approver-role': 'someone-else'}, [a, c])
        if r['status'] != 'proposed':
            fails.append('no reset: an existing ledger with a role gave %r (%r)' % (r['status'], r['why']))
        else:
            text = subprocess.run(['git', 'show', '%s:%s' % (branch, LEDGER)], cwd=remote,
                                  capture_output=True, text=True).stdout
            _e, _s, _n, hdr = bl.parse_ledger(text)
            # The establishment record is untouched (rule 4's presence declaration may be added).
            if dict((k, hdr.get(k)) for k in header) != header:
                fails.append('no reset: the role re-wrote the ledger header to %r' % hdr)
            if 'ignored' not in r['body'] or 'ESTABLISH' in r['gh']:
                fails.append('no reset: the body does not say the role was ignored, or the PR claims '
                             'establishment (gh %r)' % r['gh'])
    except Unrenderable as exc:
        print('UNKNOWN: the harness cannot render %s; extend it rather than guess.' % exc)
        return 2
    except RuntimeError as exc:
        print('UNKNOWN: fixture could not be built: %s' % exc)
        return 2
    finally:
        shutil.rmtree(work, ignore_errors=True)

    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: the shipped reusable establishes a baseline only as a pull request: no ledger and no '
          'approver role refuses with the reason (visible as a workflow output); a role without '
          'CODEOWNERS over the ledger refuses; a role with CODEOWNERS opens an ESTABLISH pull request '
          'whose header names the role and asserts no age, and the default branch never moves; an '
          'existing ledger proposes normally, and a role given anyway re-writes nothing.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
