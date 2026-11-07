#!/usr/bin/env python3
"""`kit init` wires a repository in one command, never guesses, never writes a secret, keeps a person's edits.

WHY THIS EXISTS (owner, 2026-11-06)
    "How painful will adoption be?" -- heavy in week one without help. scripts/kit_init.py does the files
    and writes the person-only steps down with their exact commands. A generator that writes a caller with
    the wrong permissions is a startup_failure in every repository it touched, one that guesses a pipeline
    is worse than none, and one that overwrites a person's edit gets switched off. So each is proven here.

WHAT IT PROVES
  POSITIVE
    P1  one fixture repository per stack (python, node, dotnet, java, php, go, static site, container,
        terraform, bicep) and a multi-stack one: kit init writes the files, names the stack, picks the
        right caller (security.yml / build-deploy.yml / build-deploy-static.yml), and what it wrote passes
        the kit's caller-permission check (tests/check_caller_permissions.py), the consumer-surface rule
        for deploy callers (deployments: write + pull-requests: read, scripts/consumer_surface_check.py R1),
        EXACT least privilege (no job grants more than its callee requests), every kit reference pinned
        to the one SHA, no placeholder, one security caller, and `dependabot_config.py check` on the result
    P2  actionlint (the pinned 1.7.7, ACTIONLINT or on PATH) reports nothing on every generated workflow
        outside the two exact messages tests/check_actionlint.py documents (--actionlint; run in the
        actionlint job, UNKNOWN rc 2 where no actionlint exists)
    P3  idempotent: a second run is KIT_INIT_UNCHANGED and changes no byte
    P4  PR mode: ONE branch kit-init/<sha12>, ONE commit of exactly the managed files, pushed; `gh pr create`
        with the checklist as the body and GH_HOST set to the repository's host; a re-run edits the same PR,
        never opens a second; no `gh api` call (no setting is ever changed)
    P5  GHE.com: the issuer is token.actions.<tenant>.ghe.com, every subject repo:O/R:environment:E, the
        environment commands carry GH_HOST; the environments spec gates uat/prod with platform AND security
        reviewers, self-review prevented, deployments from main; dev/test ungated
    P6  "where the kit version needs it": the kit-api job grants deployments: read when the pinned
        reusable-kit-api.yml requests it, and not when a kit version does not
    P7  the wrapper: templates/kit-init.yml is workflow_dispatch only, its job holds contents: read, it
        calls the kit-init composite pinned; the composite reads every input through env, authenticates
        a push by header from the environment (never a file), and uploads the files when no token is set
    P8  the switch: a repository wired as `none` and then given a Dockerfile loses kit init's own
        security.yml (one security caller); a person's security.yml is never deleted, it is a named conflict
  NEGATIVE
    N1  unknown stack (no manifest; only Cargo.toml) -> KIT_INIT_STACK_UNKNOWN, rc 1, the plain fix, and
        NOTHING written
    N2  a person's edit wins: an edited caller, a pre-existing dependabot.yml, an edited CODEOWNERS block
        and CODEOWNERS lines outside the block are kept byte for byte and listed (HUMAN_EDIT_PRESERVED)
    N3  no secret ever written: secret-named environment variables never reach a file; a secret-shaped
        path refuses KIT_INIT_SECRET_REFUSED with nothing written
    N4  pins: no kit repository, a branch name for the SHA -> KIT_INIT_PIN_MISSING; a SHA that is not the
        checkout's HEAD -> KIT_INIT_PIN_NOT_CHECKOUT
    N5  two Dockerfiles -> KIT_INIT_MULTIPLE_IMAGES; with --dockerfile the build job gets dockerfile/context
    N6  a host that is neither github.com nor <tenant>.ghe.com -> KIT_INIT_HOST_UNSUPPORTED
    N7  --with-api without a container deploy -> KIT_INIT_API_NEEDS_CONTAINER
    N8  PR mode on a dirty tree -> KIT_INIT_DIRTY_TREE, nothing written; a refused push -> KIT_INIT_PR_NOT_OPENED
  MUTANTS (each must be killed)
    M1  a job granted more than its callee requests      -> verify() names least privilege
    M2  a deploy caller without deployments: write        -> check_caller_permissions and R1 refuse
    M3  a placeholder SHA left in a caller                -> verify() names the placeholder
    M4  the secret guard removed                          -> this proof's own scan finds the secret on disk
    M5  the lock ignored (every file treated as kit's)    -> N2's byte comparison fails
    M6  the stack refusal removed (a guess instead)       -> N1's assertion fails

EXIT 0 all hold   1 any does not   2 could not run (PyYAML, git or, with --actionlint, actionlint missing)
"""
import argparse
import contextlib
import copy
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

try:
    import yaml
except ImportError:
    print('UNKNOWN: PyYAML not available.')
    sys.exit(2)
if not shutil.which('git'):
    print('UNKNOWN: git is required.')
    sys.exit(2)

import kit_init as KI  # noqa: E402
import dependabot_config as DC  # noqa: E402
import check_caller_permissions as CCP  # noqa: E402

CCP.rel = lambda f: f.replace('\\', '/')   # generated files live outside the kit (another drive on Windows)
KIT_REPO = 'acme/secure-cicd-kit'
FAILS = []


def check(cond, label, detail=''):
    print('  %s %s%s' % ('ok  ' if cond else 'FAIL', label, ('  -- ' + str(detail)[:600]) if detail and not cond else ''))
    if not cond:
        FAILS.append(label)
    return cond


def kit_head():
    r = subprocess.run(['git', '-C', ROOT, 'rev-parse', 'HEAD'], capture_output=True, text=True)
    h = r.stdout.strip()
    return h if r.returncode == 0 and KI.SHA_RX.match(h) else None


HEAD = kit_head()
SHA = HEAD or 'a' * 40

FIXTURES = {
    'python': {'requirements.txt': 'flask==3.0.0\n', 'app.py': 'print(1)\n'},
    'node': {'package.json': '{"name":"x"}\n', 'index.js': '1\n'},
    'dotnet': {'src/App/App.csproj': '<Project/>\n'},
    'java': {'pom.xml': '<project/>\n'},
    'php': {'composer.json': '{}\n'},
    'go': {'go.mod': 'module x\n'},
    'static': {'public/index.html': '<html></html>\n', 'staticwebapp.config.json': '{}\n'},
    'container': {'Dockerfile': 'FROM busybox:1.36\n', 'requirements.txt': 'flask==3.0.0\n'},
    'terraform': {'infra/main.tf': 'terraform {}\n'},
    'bicep': {'infra/main.bicep': 'param x string\n'},
    'multi': {'Dockerfile': 'FROM busybox:1.36\n', 'requirements.txt': 'flask==3.0.0\n',
              'web/package.json': '{}\n', 'infra/main.tf': 'terraform {}\n', 'tools/Cargo.toml': '[package]\n'},
}
EXPECT_CALLER = {'static': 'build-deploy-static.yml', 'container': 'build-deploy.yml', 'multi': 'build-deploy.yml'}


def make_repo(base, name, files, git=True, remote='https://github.com/acme/%s.git'):
    d = os.path.join(base, name)
    for rel, text in files.items():
        p = os.path.join(d, *rel.split('/'))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with io.open(p, 'w', encoding='utf-8', newline='\n') as fh:
            fh.write(text)
    os.makedirs(d, exist_ok=True)
    if git:
        g = ['git', '-C', d]
        subprocess.run(g + ['init', '-q', '-b', 'main'], check=True)
        subprocess.run(g + ['config', 'core.autocrlf', 'false'], check=True)
        subprocess.run(g + ['add', '-A'], check=True)
        subprocess.run(g + ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', 'commit', '-qm', 'init',
                            '--allow-empty'], check=True)
        if remote:
            subprocess.run(g + ['remote', 'add', 'origin', remote % name], check=True)
    return d


def run(target, *args, env=None):
    cmd = [sys.executable, os.path.join(ROOT, 'scripts', 'kit_init.py'), '--target', target, '--kit-repo', KIT_REPO,
           '--kit-sha', SHA] + list(args)
    out = os.path.join(target + '.out.json')
    p = subprocess.run(cmd + ['--json', out], capture_output=True, text=True, env=env or os.environ.copy())
    res = json.load(io.open(out, encoding='utf-8')) if os.path.exists(out) else {}
    return p.returncode, res, p.stdout + p.stderr


def snapshot(d):
    out = {}
    for r, _ds, fs in os.walk(d):
        if '.git' in os.path.relpath(r, d).split(os.sep):
            continue
        for f in fs:
            p = os.path.join(r, f)
            out[os.path.relpath(p, d).replace(os.sep, '/')] = io.open(p, 'rb').read()
    return out


def generated_workflows(d):
    wf = os.path.join(d, '.github', 'workflows')
    return sorted(os.path.join(wf, n) for n in os.listdir(wf) if n.endswith('.yml')) if os.path.isdir(wf) else []


def independent_checks(d, label):
    """Every check of P1, run by this proof on the files on disk (not kit init's own verify)."""
    files = generated_workflows(d)
    cache = {}

    def load(p):
        if p not in cache:
            cache[p] = yaml.safe_load(io.open(p, encoding='utf-8')) or {}
        return cache[p]
    # tests/check_caller_permissions.py resolves owner/repo/.github/workflows/<f>@ref against THIS kit;
    # the local ./.github/workflows/build-deploy.yml call (kit-api) resolves beside the caller.
    bad = CCP.check(files, load)
    bad = [b for b in bad if 'does not exist' not in b or './.github/workflows/' not in b]
    check(not bad, '%s: tests/check_caller_permissions.py passes every generated caller' % label, bad)
    texts = {os.path.relpath(p, d).replace(os.sep, '/'): io.open(p, encoding='utf-8').read() for p in files}
    probs = KI.verify(texts, KIT_REPO, SHA)
    check(not probs, '%s: exact least privilege, pinned, no placeholder, one security caller' % label, probs)
    r1 = []
    for p in files:
        for jn, j in ((load(p).get('jobs')) or {}).items():
            if any(n in str((j or {}).get('uses') or '') for n in KI.DEPLOY_REUSABLES):
                pr = j.get('permissions') or {}
                if pr.get('deployments') != 'write' or pr.get('pull-requests') not in ('read', 'write'):
                    r1.append('%s:%s' % (os.path.basename(p), jn))
    check(not r1, '%s: consumer surface R1 -- every deploy caller grants deployments: write, pull-requests: read' % label, r1)
    probs, _w, _s = DC.check(d)
    check(not probs, '%s: dependabot_config.py check passes the generated dependabot.yml' % label, probs)
    return texts


def leaked(d, values):
    hits = []
    for rel, data in snapshot(d).items():
        t = data.decode('utf-8', 'replace')
        for v in values:
            if v in t:
                hits.append((rel, v[:6]))
        if KI.SECRET_SHAPES.search(t):
            hits.append((rel, 'secret-shaped'))
    return hits


def positive(base):
    print('POSITIVE')
    results = {}
    for name, files in FIXTURES.items():
        d = make_repo(base, name, files)
        rc, res, out = run(d, '--dry-run', '--appsec-team', '@acme/appsec', '--platform-team', '@acme/platform')
        stack = 'python' if name == 'multi' else name
        ok = rc == 0 and res.get('state') == KI.OK_WRITTEN and stack in (res.get('stacks') or [])
        check(ok, 'P1 %s: written, stack named' % name, out[-400:])
        caller = EXPECT_CALLER.get(name, 'security.yml')
        check(os.path.isfile(os.path.join(d, '.github', 'workflows', caller)), 'P1 %s: the caller is %s' % (name, caller))
        independent_checks(d, 'P1 %s' % name)
        results[name] = d
    m = results['multi']
    co = io.open(os.path.join(m, '.github', 'CODEOWNERS'), encoding='utf-8').read()
    chk = io.open(os.path.join(m, '.kit', 'ADOPTION_CHECKLIST.md'), encoding='utf-8').read()
    check('/Dockerfile ' in co and '/infra/*.tf' in co and '/.kit/zone-readiness.json' in co,
          'P1 multi: CODEOWNERS puts AppSec on the readiness file, the Dockerfile and the IaC')
    check('rust' in chk and 'Not covered by kit init' in chk, 'P1 multi: an unrecognised language is NAMED, not guessed at')
    # P3 idempotent
    before = snapshot(results['container'])
    rc, res, out = run(results['container'], '--dry-run')
    check(rc == 0 and res.get('state') == KI.OK_UNCHANGED and snapshot(results['container']) == before,
          'P3 a second run is KIT_INIT_UNCHANGED and changes no byte', out[-300:])
    return results


def gh_stub(base):
    log = os.path.join(base, 'gh.log')
    stub = os.path.join(base, 'gh_stub.py')
    with io.open(stub, 'w', encoding='utf-8') as fh:
        fh.write('import json, os, sys\n'
                 'log = %r\n' % log +
                 'with open(log, "a") as f: f.write(json.dumps({"argv": sys.argv[1:], "host": os.environ.get("GH_HOST")}) + "\\n")\n'
                 'a = sys.argv[1:]\n'
                 'state = log + ".pr"\n'
                 'if a[:2] == ["pr", "view"]:\n'
                 '    sys.exit(0 if os.path.exists(state) and print("https://example/pr/1") is None else 1)\n'
                 'if a[:2] == ["pr", "create"]:\n'
                 '    open(state, "w").write("1"); print("https://example/pr/1"); sys.exit(0)\n'
                 'if a[:2] == ["pr", "edit"]:\n'
                 '    sys.exit(0)\n'
                 'sys.exit(3)\n')
    return log, json.dumps([sys.executable, stub])


def pr_mode(base):
    print('POSITIVE: PR mode, GHE.com')
    remote = os.path.join(base, 'remote.git')
    subprocess.run(['git', 'init', '-q', '--bare', remote], check=True)
    d = make_repo(base, 'prapp', FIXTURES['container'], remote=None)
    subprocess.run(['git', '-C', d, 'remote', 'add', 'origin', remote], check=True)
    log, gh = gh_stub(base)
    env = dict(os.environ, KIT_INIT_GH=gh)
    rc, res, out = run(d, '--repo', 'acme/prapp', '--host', 'acme.ghe.com', '--appsec-team', '@acme/appsec',
                       '--platform-team', '@acme/platform', env=env)
    check(rc == 0 and res.get('state') == KI.OK_PR, 'P4 PR mode: KIT_INIT_PR_OPENED', out[-500:])
    branches = subprocess.run(['git', '-C', remote, 'branch', '--list'], capture_output=True, text=True).stdout.split()
    want = 'kit-init/' + SHA[:12]
    check(branches == [want], 'P4 one branch, %s, pushed' % want, branches)
    files = subprocess.run(['git', '-C', d, 'show', '--name-only', '--format=', 'HEAD'], capture_output=True,
                           text=True).stdout.split()
    lock = json.load(io.open(os.path.join(d, '.kit', 'kit-init.lock.json'), encoding='utf-8'))
    owned = sorted({k.split('#')[0] for k in lock['files']} | {'.kit/kit-init.lock.json'})
    check(sorted(files) == owned, 'P4 one commit of exactly the managed files', (sorted(files), owned))
    calls = [json.loads(l) for l in io.open(log, encoding='utf-8')]
    create = [c for c in calls if c['argv'][:2] == ['pr', 'create']]
    check(len(create) == 1 and '--body-file' in create[0]['argv'] and create[0]['host'] == 'acme.ghe.com',
          'P4 gh pr create once, the checklist as the body, GH_HOST the repository host', calls)
    check(not any(c['argv'][:1] == ['api'] for c in calls), 'P4 no `gh api` call: no setting is changed')
    # a re-run from main with one more answer: the same branch moves forward (no force) and the same PR is edited
    subprocess.run(['git', '-C', d, 'checkout', '-q', 'main'], check=True)
    rc, res, out = run(d, '--repo', 'acme/prapp', '--host', 'acme.ghe.com', '--with-triage', env=env)
    calls = [json.loads(l) for l in io.open(log, encoding='utf-8')]
    log2 = subprocess.run(['git', '-C', remote, 'log', '--format=%s', want], capture_output=True, text=True).stdout.splitlines()
    check(rc == 0 and len([c for c in calls if c['argv'][:2] == ['pr', 'create']]) == 1 and
          any(c['argv'][:2] == ['pr', 'edit'] for c in calls) and len(log2) == 3,
          'P4 a re-run adds a commit to the same branch and edits the same PR, never a second one', (out[-300:], log2))
    subprocess.run(['git', '-C', d, 'checkout', '-q', want], check=True)
    chk = io.open(os.path.join(d, '.kit', 'ADOPTION_CHECKLIST.md'), encoding='utf-8').read()
    spec = json.load(io.open(os.path.join(d, '.kit', 'environments.json'), encoding='utf-8'))
    check(spec['oidc']['issuer'] == 'https://token.actions.acme.ghe.com' and
          '"issuer":"https://token.actions.acme.ghe.com"' in chk, 'P5 the GHE.com issuer, in the spec and the commands')
    check(all(s == 'repo:acme/prapp:environment:%s' % e for e, s in spec['oidc']['subjects'].items()) and
          'repo:acme/prapp:environment:prod' in chk, 'P5 every subject is repo:O/R:environment:E')
    check('export GH_HOST=acme.ghe.com' in chk, 'P5 the environment commands target the repository host')
    envs = {e['name']: e for e in spec['environments']}
    gated = all(envs[n]['prevent_self_review'] and {r['team'] for r in envs[n]['required_reviewers']} ==
                {'@acme/appsec', '@acme/platform'} for n in ('uat', 'prod'))
    open_ = all(not envs[n]['required_reviewers'] and not envs[n]['prevent_self_review'] for n in ('dev', 'test'))
    check(gated and open_ and all(e['deployment_branches'] == ['main'] for e in envs.values()),
          'P5 uat/prod need platform or security, self-review prevented; dev/test ungated; main only')
    # KDEC-042: the spec the deploy reads back classes every deploy environment, the settings name the pools,
    # and the checklist carries the exact PUT per environment and the variables a push cannot edit.
    import environment_protection as ep
    settings = json.load(io.open(os.path.join(d, '.kit', 'settings.json'), encoding='utf-8'))
    classes = dict((n, ep.classify(n, 'dev', spec)[0]) for n in ('dev', 'test', 'uat', 'prod'))
    check(classes == {'dev': 'dev', 'test': 'test', 'uat': 'uat', 'prod': 'prod'} and
          all(envs[n].get('class') == n for n in classes), 'P5 the spec classes dev/test/uat/prod as the deploy reads it', classes)
    check(ep.parse_pools(settings.get('approver_pools')) == {'appsec', 'platform'},
          'P5 .kit/settings.json names the platform and security pools the deploy holds uat/prod to', settings)
    check(all(('gh api -X PUT repos/acme/prapp/environments/%s --input - <<JSON' % n) in chk for n in classes) and
          chk.count('"prevent_self_review":true') == 2 and "gh variable set KIT_APPROVER_POOLS --repo acme/prapp" in chk,
          'P5 the checklist lists the exact PUT per environment, self-review prevented at uat and prod, and the pools variable')
    return d


def api_permission(base):
    print('POSITIVE: deployments: read where the kit version needs it')
    d = make_repo(base, 'apiapp', FIXTURES['container'])
    rc, res, out = run(d, '--dry-run', '--with-api')
    api = yaml.safe_load(io.open(os.path.join(d, '.github', 'workflows', 'kit-api.yml'), encoding='utf-8'))
    check(rc == 0 and api['jobs']['api']['permissions'].get('deployments') == 'read',
          'P6 this kit version requests deployments: read, so the api job grants it', out[-300:])
    # a kit version whose reusable-kit-api.yml does not request it
    fake = os.path.join(base, 'oldkit')
    shutil.copytree(os.path.join(ROOT, 'templates'), os.path.join(fake, 'templates'))
    shutil.copytree(os.path.join(ROOT, '.github', 'workflows'), os.path.join(fake, '.github', 'workflows'))
    p = os.path.join(fake, '.github', 'workflows', 'reusable-kit-api.yml')
    t = io.open(p, encoding='utf-8').read()
    t2 = re.sub(r'(?m)^\s+deployments: read.*\n', '', t)
    io.open(p, 'w', encoding='utf-8', newline='\n').write(t2)
    d2 = make_repo(base, 'apiapp-old', FIXTURES['container'])
    saved = KI.KIT_ROOT
    try:
        KI.KIT_ROOT = fake
        opts = KI.parser().parse_args(['--target', d2, '--kit-repo', KIT_REPO, '--kit-sha', SHA, '--dry-run', '--with-api'])
        ctx = KI.apply(KI.build(opts), write=False)
        doc = yaml.safe_load(ctx['files']['.github/workflows/kit-api.yml'])
        check(t != t2 and 'deployments' not in doc['jobs']['api']['permissions'],
              'P6 a kit version that does not request it: the api job does not grant it')
    finally:
        KI.KIT_ROOT = saved


def wrapper():
    print('POSITIVE: the wrapper and its composite')
    t = yaml.safe_load(io.open(os.path.join(ROOT, 'templates', 'kit-init.yml'), encoding='utf-8'))
    on = t.get('on', t.get(True)) or {}
    job = t['jobs']['init']
    step = [s for s in job['steps'] if 'kit-init' in str(s.get('uses', ''))]
    check(set(on) == {'workflow_dispatch'} and t.get('permissions') == {} and job['permissions'] == {'contents': 'read'},
          'P7 templates/kit-init.yml: dispatch only, the job holds contents: read')
    check(len(step) == 1 and step[0]['uses'].endswith('@' + KI.ZERO_SHA) and
          step[0]['with'].get('token') == '${{ secrets.KIT_INIT_TOKEN }}', 'P7 it calls the kit-init composite, pinned')
    a = yaml.safe_load(io.open(os.path.join(ROOT, '.github', 'actions', 'kit-init', 'action.yml'), encoding='utf-8'))
    runs = [s for s in a['runs']['steps'] if s.get('run')]
    check(all('${{' not in s['run'] for s in runs), 'P7 the composite reads every input through env, never in a script')
    body = '\n'.join(s['run'] for s in runs)
    check('extraheader' in body and 'git config --global' not in body and 'set-url' not in body,
          'P7 a push authenticates by header from the environment, never a file')
    up = [s for s in a['runs']['steps'] if 'upload-artifact' in str(s.get('uses', ''))]
    check(len(up) == 1 and up[0]['with'].get('include-hidden-files') is True and "mode == 'files'" in up[0]['if'],
          'P7 without a token the files are uploaded (hidden .github and .kit included)')


def switch(base):
    print('POSITIVE: one security caller across a re-run')
    d = make_repo(base, 'switch', FIXTURES['python'])
    run(d, '--dry-run')
    check(os.path.isfile(os.path.join(d, '.github', 'workflows', 'security.yml')), 'P8 scan-only: security.yml')
    io.open(os.path.join(d, 'Dockerfile'), 'w', encoding='utf-8').write('FROM busybox:1.36\n')
    rc, res, out = run(d, '--dry-run', '--deploy', 'container')
    check(rc == 0 and not os.path.exists(os.path.join(d, '.github', 'workflows', 'security.yml')) and
          os.path.isfile(os.path.join(d, '.github', 'workflows', 'build-deploy.yml')),
          'P8 kit init\'s own security.yml goes when build-deploy.yml replaces it', out[-300:])
    d2 = make_repo(base, 'switch2', dict(FIXTURES['container'], **{'.github/workflows/security.yml': 'name: mine\non: push\njobs: {}\n'}))
    rc, res, out = run(d2, '--dry-run')
    check(os.path.isfile(os.path.join(d2, '.github', 'workflows', 'security.yml')) and
          any('security.yml' in c for c in res.get('conflicts', [])),
          'P8 a person\'s security.yml is never deleted; it is a named conflict', res.get('conflicts'))


def negative(base):
    print('NEGATIVE')
    for name, files in (('empty', {'README.md': '# x\n'}), ('rustonly', {'Cargo.toml': '[package]\n'})):
        d = make_repo(base, name, files)
        before = snapshot(d)
        rc, res, out = run(d, '--dry-run')
        check(rc == 1 and res.get('state') == KI.STACK_UNKNOWN and 'will' in res.get('what', '') and
              'requirements.txt' in res.get('fix', '') and snapshot(d) == before,
              'N1 %s: KIT_INIT_STACK_UNKNOWN, the fix named, nothing written' % name, out[-300:])
    # N2 a person's edits win
    d = make_repo(base, 'edits', dict(FIXTURES['container'], **{
        '.github/dependabot.yml': 'version: 2\nupdates: []\n', 'CODEOWNERS': '* @acme/everyone\n'}))
    run(d, '--dry-run')
    bd = os.path.join(d, '.github', 'workflows', 'build-deploy.yml')
    io.open(bd, 'a', encoding='utf-8').write('# my edit\n')
    co = os.path.join(d, 'CODEOWNERS')
    t = io.open(co, encoding='utf-8').read().replace('/.security/', '/.security/   @acme/me\n/x/')
    io.open(co, 'w', encoding='utf-8', newline='\n').write(t)
    keep = {p: snapshot(d)[p] for p in ('.github/workflows/build-deploy.yml', '.github/dependabot.yml', 'CODEOWNERS')}
    rc, res, out = run(d, '--dry-run')
    after = snapshot(d)
    check(all(after[p] == v for p, v in keep.items()), 'N2 an edited caller, a prior dependabot.yml and an edited '
          'CODEOWNERS block are kept byte for byte', [p for p, v in keep.items() if after[p] != v])
    check(after['CODEOWNERS'].startswith(b'* @acme/everyone\n'), 'N2 CODEOWNERS lines outside the block are untouched')
    pres = ' '.join(res.get('preserved', []))
    check('build-deploy.yml' in pres and 'dependabot.yml' in pres and 'CODEOWNERS' in pres,
          'N2 each kept file is listed (KIT_INIT_HUMAN_EDIT_PRESERVED)', res.get('preserved'))
    check(not os.path.exists(os.path.join(d, '.github', 'CODEOWNERS')), 'N2 the block stays in the CODEOWNERS GitHub reads')
    # N3 no secret ever written
    secrets = {'JIRA_TOKEN': 'jt-' + 'q' * 30, 'AZURE_CLIENT_SECRET': 'cs-' + 'z' * 30, 'KIT_INIT_TOKEN': 'kt-' + 'k' * 30}
    d = make_repo(base, 'secrets', FIXTURES['container'])
    rc, res, out = run(d, '--dry-run', '--with-api', env=dict(os.environ, **secrets))
    check(rc == 0 and not leaked(d, secrets.values()), 'N3 secret-named environment values never reach a file')
    shaped = 'ghp_' + 'A1b2C3d4E5' * 4
    d = make_repo(base, 'shaped', {'svc/%s/Dockerfile' % shaped: 'FROM busybox:1.36\n'})
    before = snapshot(d)
    rc, res, out = run(d, '--dry-run')
    check(rc == 1 and res.get('state') == KI.SECRET_REFUSED and snapshot(d) == before,
          'N3 a secret-shaped value refuses KIT_INIT_SECRET_REFUSED and nothing is written', out[-300:])
    # N4 pins
    d = make_repo(base, 'pins', FIXTURES['python'])
    p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'kit_init.py'), '--target', d, '--dry-run'],
                       capture_output=True, text=True)
    check(p.returncode == 1 and KI.PIN_MISSING in p.stdout, 'N4 no kit repository -> KIT_INIT_PIN_MISSING', p.stdout[-200:])
    p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'kit_init.py'), '--target', d, '--kit-repo', KIT_REPO,
                        '--kit-sha', 'main', '--dry-run'], capture_output=True, text=True)
    check(p.returncode == 1 and KI.PIN_MISSING in p.stdout, 'N4 a branch name for the SHA -> KIT_INIT_PIN_MISSING')
    if HEAD:
        other = ('b' if HEAD[0] != 'b' else 'c') * 40
        p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'kit_init.py'), '--target', d, '--kit-repo',
                            KIT_REPO, '--kit-sha', other, '--dry-run'], capture_output=True, text=True)
        check(p.returncode == 1 and KI.PIN_NOT_CHECKOUT in p.stdout, 'N4 a SHA that is not the checkout -> KIT_INIT_PIN_NOT_CHECKOUT')
    else:
        print('  note N4 PIN_NOT_CHECKOUT: this kit copy is not a git checkout, so there is no HEAD to differ from')
    # N5 images
    d = make_repo(base, 'twoimages', {'api/Dockerfile': 'FROM busybox:1.36\n', 'worker/Dockerfile': 'FROM busybox:1.36\n'})
    rc, res, out = run(d, '--dry-run')
    check(rc == 1 and res.get('state') == KI.MULTIPLE_IMAGES, 'N5 two Dockerfiles -> KIT_INIT_MULTIPLE_IMAGES', out[-200:])
    rc, res, out = run(d, '--dry-run', '--dockerfile', 'api/Dockerfile')
    bd = yaml.safe_load(io.open(os.path.join(d, '.github', 'workflows', 'build-deploy.yml'), encoding='utf-8'))
    check(rc == 0 and bd['jobs']['build']['with'].get('dockerfile') == 'api/Dockerfile' and
          bd['jobs']['build']['with'].get('context') == 'api', 'N5 with --dockerfile the build gets dockerfile and context')
    # N6, N7
    d = make_repo(base, 'host', FIXTURES['python'])
    rc, res, out = run(d, '--dry-run', '--host', 'git.example.com', '--repo', 'a/b')
    check(rc == 1 and res.get('state') == KI.HOST_UNSUPPORTED, 'N6 an unsupported host -> KIT_INIT_HOST_UNSUPPORTED')
    rc, res, out = run(d, '--dry-run', '--with-api')
    check(rc == 1 and res.get('state') == KI.API_NEEDS_CONTAINER, 'N7 --with-api without a container -> KIT_INIT_API_NEEDS_CONTAINER')
    # N8 dirty tree, refused push
    d = make_repo(base, 'dirty', FIXTURES['python'], remote=None)
    io.open(os.path.join(d, 'wip.txt'), 'w').write('x')
    before = snapshot(d)
    rc, res, out = run(d, '--repo', 'a/b', '--host', 'github.com')
    check(rc == 1 and res.get('state') == KI.DIRTY_TREE and snapshot(d) == before, 'N8 a dirty tree -> KIT_INIT_DIRTY_TREE, nothing written')
    d = make_repo(base, 'nopush', FIXTURES['python'], remote=None)
    subprocess.run(['git', '-C', d, 'remote', 'add', 'origin', os.path.join(base, 'does-not-exist.git')], check=True)
    rc, res, out = run(d, '--repo', 'a/b', '--host', 'github.com', env=dict(os.environ, KIT_INIT_GH=gh_stub(base)[1]))
    check(rc == 1 and res.get('state') == KI.PR_NOT_OPENED, 'N8 a refused push -> KIT_INIT_PR_NOT_OPENED, rc 1', out[-200:])


def mutants(base):
    print('MUTANTS')
    d = make_repo(base, 'mut', FIXTURES['container'])
    opts = KI.parser().parse_args(['--target', d, '--kit-repo', KIT_REPO, '--kit-sha', SHA, '--dry-run'])
    ctx = KI.build(opts)
    files = ctx['files']
    bd = files['.github/workflows/build-deploy.yml']
    m1 = dict(files, **{'.github/workflows/build-deploy.yml': bd.replace(
        '    permissions:\n      contents: read\n      security-events: write',
        '    permissions:\n      contents: read\n      issues: write\n      security-events: write', 1)})
    check(m1 != files and any('least privilege' in p for p in KI.verify(m1, KIT_REPO, SHA)), 'M1 an over-grant is killed')
    m2text = re.sub(r'(?m)^      deployments: write.*\n', '', bd, count=1)
    m2 = dict(files, **{'.github/workflows/build-deploy.yml': m2text})
    tmp = os.path.join(base, 'm2.yml')
    io.open(tmp, 'w', encoding='utf-8').write(m2text)
    ccp = CCP.check([tmp], lambda p: yaml.safe_load(io.open(p, encoding='utf-8')))
    check(m2text != bd and ccp and any('deployments' in p for p in KI.verify(m2, KIT_REPO, SHA)),
          'M2 a deploy caller without deployments: write is killed (check_caller_permissions and R1)')
    m3 = dict(files, **{'.github/workflows/build-deploy.yml': bd.replace('@' + SHA, '@' + KI.ZERO_SHA, 1)})
    check(any('placeholder' in p or 'pins the kit' in p for p in KI.verify(m3, KIT_REPO, SHA)), 'M3 a placeholder SHA is killed')
    # M4 the guard removed: the secret-shaped path is written, and this proof's own scan finds it
    shaped = 'ghp_' + 'Z9y8X7w6V5' * 4
    d4 = make_repo(base, 'm4', {'svc/%s/Dockerfile' % shaped: 'FROM busybox:1.36\n'})
    saved = KI.secret_leaks
    try:
        KI.secret_leaks = lambda files, environ=None: []
        o = KI.parser().parse_args(['--target', d4, '--kit-repo', KIT_REPO, '--kit-sha', SHA, '--dry-run'])
        KI.apply(KI.build(o), write=True)
    finally:
        KI.secret_leaks = saved
    check(bool(leaked(d4, [])), 'M4 with the guard removed the secret reaches a file, and the scan kills the mutant')
    # M5 the lock ignored: a person's edit is overwritten, and N2's comparison catches it
    d5 = make_repo(base, 'm5', FIXTURES['container'])
    run(d5, '--dry-run')
    p5 = os.path.join(d5, '.github', 'workflows', 'build-deploy.yml')
    io.open(p5, 'a', encoding='utf-8').write('# my edit\n')
    kept = io.open(p5, 'rb').read()
    saved = KI._merge_file
    try:
        def clobber(root, rel, text, owned, results, preserved, writes):
            writes[rel], results[rel] = text, 'updated'
            return True
        KI._merge_file = clobber
        o = KI.parser().parse_args(['--target', d5, '--kit-repo', KIT_REPO, '--kit-sha', SHA, '--dry-run'])
        KI.apply(KI.build(o), write=True)
    finally:
        KI._merge_file = saved
    check(io.open(p5, 'rb').read() != kept, 'M5 with the lock ignored the edit is lost, and the byte comparison kills it')
    # M6 the refusal removed: kit init would guess, and N1's assertion fails
    d6 = make_repo(base, 'm6', {'Cargo.toml': '[package]\n'})
    saved = KI.KNOWN_STACKS
    try:
        KI.KNOWN_STACKS = saved + ('rust',)
        KI._STACK_RX['rust'] = [re.compile(r'^Cargo\.toml$')]
        o = KI.parser().parse_args(['--target', d6, '--kit-repo', KIT_REPO, '--kit-sha', SHA, '--dry-run'])
        guessed = True
        try:
            KI.build(o)
        except KI.Refusal:
            guessed = False
    finally:
        KI.KNOWN_STACKS = saved
        KI._STACK_RX.pop('rust', None)
    check(guessed, 'M6 with the refusal removed kit init guesses, which N1 refuses (mutant killed)')


ACTIONLINT_EXCLUDED = ('specifying action "$/', 'maximum number of inputs for "workflow_dispatch" event is 10')


def actionlint_mode(base):
    exe = os.environ.get('ACTIONLINT') or shutil.which('actionlint')
    if not exe:
        print('UNKNOWN: actionlint is required for --actionlint (set ACTIONLINT or put it on PATH).')
        return 2
    files = []
    for name in ('python', 'static', 'container'):
        d = make_repo(base, 'al-' + name, FIXTURES[name])
        args = ['--dry-run', '--with-triage'] + (['--with-api'] if name == 'container' else [])
        rc, res, out = run(d, *args)
        check(rc == 0, 'P2 %s generated' % name, out[-200:])
        files += generated_workflows(d)
    p = subprocess.run([exe, '-no-color', '-shellcheck=', '-format',
                        '{{range $err := .}}{{$err.Filepath}}:{{$err.Line}}: {{$err.Message}}\n{{end}}'] + files,
                       capture_output=True, text=True)
    lines = [l for l in p.stdout.splitlines() if l.strip() and not any(x in l for x in ACTIONLINT_EXCLUDED)]
    if p.returncode not in (0, 1):
        print('UNKNOWN: actionlint exited %d: %s' % (p.returncode, p.stderr[-300:]))
        return 2
    check(not lines and len(files) >= 8, 'P2 actionlint reports nothing on %d generated workflow(s)' % len(files), lines)
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--actionlint', action='store_true', help='only P2: actionlint over the generated workflows')
    a = ap.parse_args()
    base = tempfile.mkdtemp(prefix='kit-init-proof-')
    try:
        if a.actionlint:
            rc = actionlint_mode(base)
            if rc:
                return rc
        else:
            positive(base)
            pr_mode(base)
            api_permission(base)
            wrapper()
            switch(base)
            negative(base)
            mutants(base)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    if FAILS:
        print('FAIL: %d check(s): %s' % (len(FAILS), '; '.join(FAILS)))
        return 1
    print('PASS: kit init writes what the kit checks would pass, refuses by name, keeps edits, writes no secret.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
