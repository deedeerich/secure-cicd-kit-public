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
    P2  actionlint (the pinned 1.7.12, ACTIONLINT or on PATH) reports nothing on every generated workflow
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
  OWNER RULINGS 2026-11-07
    P9  the host is DETECTED: github.com and <tenant>.ghe.com from the remote, from GITHUB_SERVER_URL/GITHUB_API_URL
        in the repository's own workflow (another job's are ignored), the API base and the OIDC issuer derived;
        the default branch detected      N9 gitlab.com or a GHES host refused by name   N10 disagreeing sources
    P10 the org overlay applied on day one (tests/fixtures/org-overlay): approver teams as uat/prod reviewers, the
        CODEOWNERS lines for .github/workflows/, .kit/, id-mappings.json, crawl with its 4/8/26-week clock, the
        clouds and the ticket routing; governed values not copied into the repository
    P11 a stricter level from the overlay or an option     P12 small-team mode reaches the spec and the checklist
    P13 O-42b: with no pools, uat/prod still name a reviewer   P14 every checklist item says What, How and Why
    N11 an option that loosens the overlay (a team, an app team, a lower level): KIT_INIT_GOVERNED_SETTING_LOOSENED
    N12 an overlay with placeholders, or two for one org: KIT_INIT_OVERLAY_INVALID   N13 overlay host vs remote
    M7  the overlay ignored   M8 the host fixed to github.com   M9 the loosening check bypassed
  OWNER ADDITIONS 2026-11-07
    P15 no CODEOWNERS: a complete default from the org's teams   P16 --codeowners customise: a draft, nothing written
    P17 a CODEOWNERS in any of GitHub's three places is never changed; lines proposed; an ignored second file named
    N14 an existing rule that would decide a kit path is flagged   N15 an edited default is the person's
    P18 connectors inventoried by name with their purpose (files; with --inventory-api, environments, secrets,
        variables)   N16 a token that cannot list: NOT_ESTABLISHED   P19/N17 teams listed, or NOT_ESTABLISHED
    M10 the never-overwrite guard
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
            subprocess.run(g + ['remote', 'add', 'origin', remote % name if '%s' in remote else remote], check=True)
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


OVERLAY = os.path.join(HERE, 'fixtures', 'org-overlay')


def host_detection(base):
    """P9 (owner 2026-11-07): kit init detects the host -- github.com and <tenant>.ghe.com -- and derives the API
    base and the OIDC issuer; N9 an unknown host and N10 disagreeing sources are refused by name."""
    print('POSITIVE/NEGATIVE: the host, detected')
    for name, remote, host, api, iss in (
            ('h-gh', 'https://github.com/acme/%s.git', 'github.com', 'https://api.github.com',
             'https://token.actions.githubusercontent.com'),
            ('h-ghe', 'git@acme.ghe.com:acme/%s.git', 'acme.ghe.com', 'https://api.acme.ghe.com',
             'https://token.actions.acme.ghe.com')):
        d = make_repo(base, name, FIXTURES['container'], remote=remote)
        rc, res, out = run(d, '--dry-run')
        st = json.load(io.open(os.path.join(d, '.kit', 'settings.json'), encoding='utf-8')) if rc == 0 else {}
        spec = json.load(io.open(os.path.join(d, '.kit', 'environments.json'), encoding='utf-8')) if rc == 0 else {}
        check(rc == 0 and st.get('host', {}).get('host') == host and st['host']['api_url'] == api and
              st['host']['oidc_issuer'] == iss and spec.get('api_url') == api and spec['oidc']['issuer'] == iss and
              'origin remote' in st['host']['source'], 'P9 %s from the remote: API %s, issuer %s' % (host, api, iss),
              (out[-300:], st.get('host')))
    # in the repository's own workflow (the kit-init button): GITHUB_SERVER_URL and GITHUB_API_URL, no remote
    d = make_repo(base, 'h-actions', FIXTURES['python'], remote=None)
    env = dict(os.environ, GITHUB_WORKSPACE=d, GITHUB_SERVER_URL='https://acme.ghe.com',
               GITHUB_API_URL='https://api.acme.ghe.com')
    rc, res, out = run(d, '--dry-run', '--repo', 'acme/h-actions', env=env)
    st = json.load(io.open(os.path.join(d, '.kit', 'settings.json'), encoding='utf-8')) if rc == 0 else {}
    check(rc == 0 and st['host']['host'] == 'acme.ghe.com' and 'GITHUB_SERVER_URL' in st['host']['source'],
          'P9 in its own workflow: the host from GITHUB_SERVER_URL and GITHUB_API_URL', out[-300:])
    # the environment of ANOTHER job (the kit's own self-test) is not the target's: it is ignored
    env = dict(os.environ, GITHUB_WORKSPACE=base, GITHUB_SERVER_URL='https://other.ghe.com')
    d = make_repo(base, 'h-elsewhere', FIXTURES['python'])
    rc, res, out = run(d, '--dry-run', env=env)
    check(rc == 0, 'P9 GITHUB_SERVER_URL of another workspace is not taken for the target\'s host', out[-200:])
    # the default branch is detected (the owner's repositories use main; another name is honoured)
    d = make_repo(base, 'h-trunk', FIXTURES['container'])
    subprocess.run(['git', '-C', d, 'branch', '-m', 'main', 'trunk'], check=True)
    rc, res, out = run(d, '--dry-run')
    spec = json.load(io.open(os.path.join(d, '.kit', 'environments.json'), encoding='utf-8')) if rc == 0 else {}
    check(rc == 0 and all(e['deployment_branches'] == ['trunk'] for e in spec.get('environments', [])) and
          spec.get('default_branch') == 'trunk', 'P9 the default branch is detected (trunk), not assumed', out[-200:])
    for name, remote, label in (('h-gitlab', 'https://gitlab.com/acme/%s.git', 'gitlab.com'),
                                ('h-ghes', 'https://github.example.com/acme/%s.git', 'a GitHub Enterprise Server host')):
        d = make_repo(base, name, FIXTURES['python'], remote=remote)
        before = snapshot(d)
        rc, res, out = run(d, '--dry-run')
        check(rc == 1 and res.get('state') == KI.HOST_UNSUPPORTED and 'origin remote' in res.get('what', '') and
              snapshot(d) == before, 'N9 %s is refused by name, nothing written' % label, out[-200:])
    d = make_repo(base, 'h-mismatch', FIXTURES['python'], remote='https://github.com/acme/%s.git')
    rc, res, out = run(d, '--dry-run', '--host', 'acme.ghe.com')
    check(rc == 1 and res.get('state') == KI.HOST_MISMATCH, 'N10 --host acme.ghe.com with a github.com remote: '
          'KIT_INIT_HOST_MISMATCH', out[-200:])
    env = dict(os.environ, GITHUB_WORKSPACE=None or '', GITHUB_SERVER_URL='')
    d = make_repo(base, 'h-apimis', FIXTURES['python'], remote=None)
    env = dict(os.environ, GITHUB_WORKSPACE=d, GITHUB_SERVER_URL='https://acme.ghe.com', GITHUB_API_URL='https://api.github.com')
    rc, res, out = run(d, '--dry-run', '--repo', 'acme/x', env=env)
    check(rc == 1 and res.get('state') == KI.HOST_MISMATCH, 'N10 GITHUB_SERVER_URL and GITHUB_API_URL disagreeing: '
          'KIT_INIT_HOST_MISMATCH', out[-200:])


def overlay(base):
    """P10-P12 / N11-N13 (owner 2026-11-07): the org overlay is applied on day one -- approver teams, CODEOWNERS
    lines for the kit-governed paths, the adoption level, the clouds, ticket routing -- and options only tighten."""
    print('POSITIVE/NEGATIVE: the org overlay, applied on day one')
    d = make_repo(base, 'app', FIXTURES['container'], remote='https://example.ghe.com/example-org/%s.git')
    rc, res, out = run(d, '--dry-run', '--org-overlay', OVERLAY)
    ok = rc == 0
    st = json.load(io.open(os.path.join(d, '.kit', 'settings.json'), encoding='utf-8')) if ok else {}
    spec = json.load(io.open(os.path.join(d, '.kit', 'environments.json'), encoding='utf-8')) if ok else {}
    co = io.open(os.path.join(d, '.github', 'CODEOWNERS'), encoding='utf-8').read() if ok else ''
    chk = io.open(os.path.join(d, '.kit', 'ADOPTION_CHECKLIST.md'), encoding='utf-8').read() if ok else ''
    envs = {e['name']: e for e in spec.get('environments', [])}
    teams = {'@example-org/platform-approvers', '@example-org/security-approvers'}
    check(ok and st['org_overlay']['state'] == 'ORG_OVERLAY_APPLIED' and
          all({r['team'] for r in envs[n]['required_reviewers']} == teams and envs[n]['prevent_self_review']
              for n in ('uat', 'prod')), 'P10 uat/prod reviewers are the overlay\'s approver teams, self-review prevented',
          out[-300:])
    check(all(re.search(r'(?m)^%s\s+@example-org/platform-approvers @example-org/security-approvers$' % re.escape(p), co)
              for p in ('/.github/workflows/', '/.kit/', '/id-mappings.json')),
          'P10 CODEOWNERS: the approver teams own .github/workflows/, .kit/ and id-mappings.json (KDEC-044)', co)
    check(st.get('rung') == 'crawl' and st['adoption']['crawl_weeks_optimal'] == 4 and
          st['adoption']['crawl_weeks_advisory'] == 8 and st['adoption']['crawl_weeks_maximum'] == 26,
          'P10 adoption starts at crawl: 4 weeks optimal, 8 advisory, 26 the hard maximum', st.get('adoption'))
    check(all(envs[n].get('azure_cloud') == 'commercial' for n in ('dev', 'test', 'uat', 'prod', 'build')) and
          st.get('ticket_routing', {}).get('project') == 'SEC' and 'project `SEC`' in chk,
          'P10 the clouds per environment and the ticket routing come from the overlay')
    check(st['approver_pools'] == {'platform': [], 'security': []} and st['app_team'] is None and
          'Leave the approver variables unset' in chk and 'gh variable set KIT_APPROVER_POOLS' not in chk,
          'P10 governed values are not copied into the repository (no pools file, no variables to set)')
    # P11 a repository the overlay holds to a stricter level; a stricter option is honoured
    d = make_repo(base, 'strict-app', FIXTURES['python'], remote='https://example.ghe.com/example-org/%s.git')
    rc, res, out = run(d, '--dry-run', '--org-overlay', OVERLAY)
    st = json.load(io.open(os.path.join(d, '.kit', 'settings.json'), encoding='utf-8')) if rc == 0 else {}
    check(rc == 0 and st.get('rung') == 'walk', 'P11 the overlay overrides the level for one repository (walk)', out[-200:])
    d = make_repo(base, 'stricter', FIXTURES['python'], remote='https://example.ghe.com/example-org/%s.git')
    rc, res, out = run(d, '--dry-run', '--org-overlay', OVERLAY, '--adoption-level', 'run')
    st = json.load(io.open(os.path.join(d, '.kit', 'settings.json'), encoding='utf-8')) if rc == 0 else {}
    check(rc == 0 and st.get('rung') == 'run', 'P11 --adoption-level run (stricter) is honoured', out[-200:])
    # P12 small-team self-approval, declared in the overlay, reaches the spec
    d = make_repo(base, 'tiny-app', FIXTURES['static'], remote='git@github.com:example-solo/%s.git')
    rc, res, out = run(d, '--dry-run', '--org-overlay', OVERLAY)
    spec = json.load(io.open(os.path.join(d, '.kit', 'environments.json'), encoding='utf-8')) if rc == 0 else {}
    chk = io.open(os.path.join(d, '.kit', 'ADOPTION_CHECKLIST.md'), encoding='utf-8').read() if rc == 0 else ''
    envs = {e['name']: e for e in spec.get('environments', [])}
    check(rc == 0 and all(not envs[n]['prevent_self_review'] and envs[n]['required_reviewers'] for n in ('uat', 'prod'))
          and 'SMALL_TEAM_SELF_APPROVAL is in force' in chk,
          'P12 small-team mode: uat/prod keep a named reviewer, self-review may be off, and the checklist says so', out[-200:])
    # P13 O-42b: no teams and no overlay -> uat/prod still name SOMEONE (a person who is not the deployer)
    d = make_repo(base, 'noteams', FIXTURES['container'])
    rc, res, out = run(d, '--dry-run')
    spec = json.load(io.open(os.path.join(d, '.kit', 'environments.json'), encoding='utf-8')) if rc == 0 else {}
    envs = {e['name']: e for e in spec.get('environments', [])}
    check(rc == 0 and all(envs[n]['required_reviewers'] and envs[n]['prevent_self_review'] for n in ('uat', 'prod')),
          'P13 no pools anywhere: uat/prod still name a reviewer, self-review prevented (O-42b)', out[-200:])
    # N11 an option that loosens the overlay
    for args, label in ((['--platform-team', '@example-org/app-devs'], 'a team outside the overlay\'s pools'),
                        (['--app-team', '@example-org/someone-else'], 'another app team')):
        d = make_repo(base, 'loose-%d' % len(label), FIXTURES['python'], remote='https://example.ghe.com/example-org/app.git')
        before = snapshot(d)
        rc, res, out = run(d, '--dry-run', '--org-overlay', OVERLAY, *args)
        check(rc == 1 and res.get('state') == KI.LOOSENED and snapshot(d) == before,
              'N11 %s: KIT_INIT_GOVERNED_SETTING_LOOSENED, nothing written' % label, out[-200:])
    d = make_repo(base, 'loose-level', FIXTURES['python'], remote='https://example.ghe.com/example-org/strict-app.git')
    rc, res, out = run(d, '--dry-run', '--org-overlay', OVERLAY, '--adoption-level', 'crawl')
    check(rc == 1 and res.get('state') == KI.LOOSENED, 'N11 --adoption-level crawl below the overlay\'s walk is refused', out[-200:])
    # N12 an overlay with placeholders, an ambiguous one
    bad = os.path.join(base, 'badov')
    for name, doc in (('a', json.load(io.open(os.path.join(ROOT, 'templates', 'kit-org-settings.example.json'), encoding='utf-8'))),):
        os.makedirs(os.path.join(bad, 'overlays', name))
        doc['github_orgs'] = ['example-org']
        doc['host'] = 'example.ghe.com'
        io.open(os.path.join(bad, 'overlays', name, 'kit-org-settings.json'), 'w', encoding='utf-8').write(json.dumps(doc))
    d = make_repo(base, 'ov-bad', FIXTURES['python'], remote='https://example.ghe.com/example-org/app.git')
    before = snapshot(d)
    rc, res, out = run(d, '--dry-run', '--org-overlay', bad)
    check(rc == 1 and res.get('state') == KI.OVERLAY_INVALID and snapshot(d) == before,
          'N12 an overlay still holding template placeholders: KIT_INIT_OVERLAY_INVALID, nothing written', out[-200:])
    amb = os.path.join(base, 'ambov')
    for name in ('one', 'two'):
        os.makedirs(os.path.join(amb, 'overlays', name))
        io.open(os.path.join(amb, 'overlays', name, 'kit-org-settings.json'), 'w', encoding='utf-8').write(
            json.dumps({'schema': 'kit-org-settings/1', 'github_orgs': ['example-org']}))
    rc, res, out = run(d, '--dry-run', '--org-overlay', amb)
    check(rc == 1 and res.get('state') == KI.OVERLAY_INVALID, 'N12 two overlays naming one org: KIT_INIT_OVERLAY_INVALID', out[-200:])
    # N13 the overlay's host disagrees with the remote
    d = make_repo(base, 'ov-host', FIXTURES['python'], remote='https://github.com/example-org/app.git')
    rc, res, out = run(d, '--dry-run', '--org-overlay', OVERLAY)
    check(rc == 1 and res.get('state') == KI.HOST_MISMATCH, 'N13 the overlay says example.ghe.com, the remote github.com: '
          'KIT_INIT_HOST_MISMATCH', out[-200:])


def what_how_why(base):
    """P14 (owner 2026-11-07): every checklist item says WHAT to do, HOW (the exact command), and WHY it matters."""
    print('POSITIVE: every checklist item says what, how and why')
    for name, files, remote, args in (('w1', FIXTURES['container'], 'https://github.com/acme/%s.git', ['--with-api', '--automerge', '--outside-landing-zone']),
                                      ('w2', FIXTURES['python'], 'https://github.com/acme/%s.git', []),
                                      ('app', FIXTURES['container'], 'https://example.ghe.com/example-org/%s.git', ['--org-overlay', OVERLAY])):
        d = make_repo(os.path.join(base, 'whw-' + name), name, files, remote=remote)
        rc, res, out = run(d, '--dry-run', *args)
        chk = io.open(os.path.join(d, '.kit', 'ADOPTION_CHECKLIST.md'), encoding='utf-8').read() if rc == 0 else ''
        items = re.split(r'(?m)^- \[ \] ', chk.split('## Only a person can do these', 1)[-1].split('## When something fails')[0])[1:]
        bad = [i.split('\n', 1)[0] for i in items if not ('**What:**' in i and '**How:**' in i and '**Why it matters:**' in i)]
        check(rc == 0 and len(items) >= 4 and not bad, 'P14 %s: %d items, each with What, How and Why it matters'
              % (name, len(items)), (out[-200:], bad))


def overlay_mutants(base):
    print('MUTANTS: the overlay and the host')
    d = make_repo(base, 'mut-ov', FIXTURES['container'], remote='https://example.ghe.com/example-org/app.git')
    saved = KI.OS.load
    try:
        KI.OS.load = lambda root, owner: (None, KI.OS.ABSENT, '', 'mutant: the overlay ignored')
        o = KI.parser().parse_args(['--target', d, '--kit-repo', KIT_REPO, '--kit-sha', SHA, '--dry-run',
                                    '--org-overlay', OVERLAY])
        ctx = KI.build(o)
        envs = {e['name']: e for e in ctx['spec']['environments']}
        teams = {r.get('team') for r in envs['prod']['required_reviewers']}
    finally:
        KI.OS.load = saved
    check('@example-org/platform-approvers' not in teams, 'M7 with the overlay ignored the approver teams are lost, '
          'which P10 refuses (mutant killed)')
    saved = KI.resolve_host
    try:
        KI.resolve_host = lambda opts, root, rh, oh=None, environ=None: {'host': 'github.com', 'api_url': 'https://api.github.com',
                                                                         'oidc_issuer': KI.issuer_for('github.com'), 'source': 'mutant'}
        o = KI.parser().parse_args(['--target', d, '--kit-repo', KIT_REPO, '--kit-sha', SHA, '--dry-run'])
        ctx = KI.build(o)
    finally:
        KI.resolve_host = saved
    check(ctx['spec']['oidc']['issuer'] != 'https://token.actions.example.ghe.com',
          'M8 with host detection replaced by a fixed github.com the GHE.com issuer is lost, which P9 refuses')
    saved = KI.governance
    try:
        def loose(opts, odoc, ostate, osrc, repo):
            opts.platform_team = None
            return saved(opts, odoc, ostate, osrc, repo)
        KI.governance = loose
        o = KI.parser().parse_args(['--target', d, '--kit-repo', KIT_REPO, '--kit-sha', SHA, '--dry-run',
                                    '--org-overlay', OVERLAY, '--platform-team', '@example-org/app-devs'])
        refused = False
        try:
            KI.build(o)
        except KI.Refusal:
            refused = True
    finally:
        KI.governance = saved
    check(not refused, 'M9 with the loosening check bypassed the option is accepted, which N11 refuses (mutant killed)')


def api_stub(base, fail=False):
    """A gh stand-in answering the read-only listings kit init may make (names only)."""
    stub = os.path.join(base, 'gh_api_stub%s.py' % ('_fail' if fail else ''))
    with io.open(stub, 'w', encoding='utf-8') as fh:
        fh.write('import sys\n'
                 'a = sys.argv[1:]\n'
                 'if %r:\n'
                 '    sys.stderr.write("HTTP 403: Resource not accessible by integration"); sys.exit(1)\n'
                 'p = a[1] if len(a) > 1 else ""\n'
                 'if p.endswith("/environments"): print("dev\\nprod\\nstaging-old")\n'
                 'elif p.endswith("/actions/secrets"): print("JIRA_TOKEN\\nOLD_DEPLOY_KEY")\n'
                 'elif p.endswith("/actions/variables"): print("KIT_CLOUD\\nKIT_SMALL_TEAM_SELF_APPROVAL\\nJIRA_HOST")\n'
                 'elif "/teams" in p: print("platform-approvers\\nsecurity-approvers\\nweb-devs")\n'
                 'else: sys.exit(3)\n' % fail)
    return json.dumps([sys.executable, stub])


def codeowners_and_connectors(base):
    """Owner additions 2026-11-07: CODEOWNERS is never overwritten (three places, the first wins), kit lines are
    proposed with the rules that would override them flagged, a default or a customisable draft when none exists;
    the checklist inventories the connectors it can see, by name, with what each is for."""
    print('POSITIVE/NEGATIVE: CODEOWNERS never overwritten; connectors inventoried')
    gov_remote = 'https://example.ghe.com/example-org/%s.git'
    # P15 no CODEOWNERS: a complete default from the overlay's approver teams
    d = make_repo(os.path.join(base, 'co1'), 'app', FIXTURES['python'], remote=gov_remote)
    rc, res, out = run(d, '--dry-run', '--org-overlay', OVERLAY)
    co = io.open(os.path.join(d, '.github', 'CODEOWNERS'), encoding='utf-8').read() if rc == 0 else ''
    check(rc == 0 and co.startswith('# CODEOWNERS written by kit init as a complete default') and
          '/.github/workflows/' in co and '@example-org/security-approvers' in co,
          'P15 no CODEOWNERS anywhere: a complete default from the org\'s approver teams', out[-200:])
    # P16 --codeowners customise: nothing written where GitHub reads; a draft for the person
    d = make_repo(os.path.join(base, 'co2'), 'app', FIXTURES['python'], remote=gov_remote)
    rc, res, out = run(d, '--dry-run', '--org-overlay', OVERLAY, '--codeowners', 'customise')
    chk = io.open(os.path.join(d, '.kit', 'ADOPTION_CHECKLIST.md'), encoding='utf-8').read() if rc == 0 else ''
    check(rc == 0 and not any(os.path.exists(os.path.join(d, *p.split('/'))) for p in KI.CODEOWNERS_PLACES) and
          os.path.isfile(os.path.join(d, '.kit', 'CODEOWNERS.proposed')) and 'Customise the CODEOWNERS draft' in chk,
          'P16 --codeowners customise: no CODEOWNERS written, a draft to finish, the step says how', out[-200:])
    # P17 an existing CODEOWNERS in each of the three places is never changed; the kit lines are proposed
    for place in KI.CODEOWNERS_PLACES:
        mine = '# ours\n* @example-org/web-devs\n/.github/workflows/ @example-org/web-devs\n'
        d = make_repo(os.path.join(base, 'co3-' + place.replace('/', '_')), 'app',
                      dict(FIXTURES['python'], **{place: mine}), remote=gov_remote)
        rc, res, out = run(d, '--dry-run', '--org-overlay', OVERLAY)
        kept = io.open(os.path.join(d, *place.split('/')), encoding='utf-8').read()
        others = [p for p in KI.CODEOWNERS_PLACES if p != place and os.path.exists(os.path.join(d, *p.split('/')))]
        chk = io.open(os.path.join(d, '.kit', 'ADOPTION_CHECKLIST.md'), encoding='utf-8').read() if rc == 0 else ''
        check(rc == 0 and kept == mine and not others and os.path.isfile(os.path.join(d, '.kit', 'CODEOWNERS.proposed')),
              'P17 %s exists: never changed, no second file, the kit lines proposed' % place, out[-200:])
        # N14 the rule that would decide a kit path instead is flagged, by line
        check('line 2 `* @example-org/web-devs`' in chk or 'line 3 `/.github/workflows/ @example-org/web-devs`' in chk,
              'N14 %s: an existing rule that also matches a kit path is flagged (last match wins)' % place)
    # P17b two CODEOWNERS: the first GitHub reads is the one; the other is named as ignored
    d = make_repo(os.path.join(base, 'co4'), 'app', dict(FIXTURES['python'], **{
        '.github/CODEOWNERS': '* @example-org/web-devs\n', 'docs/CODEOWNERS': '* @example-org/nobody\n'}), remote=gov_remote)
    rc, res, out = run(d, '--dry-run', '--org-overlay', OVERLAY)
    chk = io.open(os.path.join(d, '.kit', 'ADOPTION_CHECKLIST.md'), encoding='utf-8').read() if rc == 0 else ''
    check(rc == 0 and 'these are ignored: `docs/CODEOWNERS`' in chk, 'P17 two CODEOWNERS: the one GitHub ignores is named')
    # N15 a person edits the default kit init wrote: from then on it is theirs, and only proposed to
    d = make_repo(os.path.join(base, 'co5'), 'app', FIXTURES['python'], remote=gov_remote)
    run(d, '--dry-run', '--org-overlay', OVERLAY)
    p = os.path.join(d, '.github', 'CODEOWNERS')
    io.open(p, 'a', encoding='utf-8').write('/docs/ @example-org/web-devs\n')
    edited = io.open(p, encoding='utf-8').read()
    rc, res, out = run(d, '--dry-run', '--org-overlay', OVERLAY)
    check(rc == 0 and io.open(p, encoding='utf-8').read() == edited and 'CODEOWNERS' in ' '.join(res.get('preserved', [])),
          'N15 an edited default is the person\'s: kept byte for byte, listed, the lines proposed', out[-200:])
    # P18 connectors: hand-wired files listed with what each is for
    hand = ('on: pull_request\njobs:\n  security:\n    uses: example-org/secure-cicd-kit/.github/workflows/'
            'reusable-security.yml@' + 'a' * 40 + '\n')
    d = make_repo(os.path.join(base, 'cn1'), 'app', dict(FIXTURES['python'], **{
        '.github/workflows/security-org.yml': hand, '.github/workflows/lint.yml': 'on: push\njobs: {}\n',
        '.kit/zone-readiness.json': '{}\n'}), remote=gov_remote)
    rc, res, out = run(d, '--dry-run', '--org-overlay', OVERLAY)
    chk = io.open(os.path.join(d, '.kit', 'ADOPTION_CHECKLIST.md'), encoding='utf-8').read() if rc == 0 else ''
    check(rc == 0 and '`.github/workflows/security-org.yml` | file | calls the kit (reusable-security.yml' in chk and
          '`.github/workflows/lint.yml` | file | not a kit workflow' in chk and '`.kit/zone-readiness.json`' in chk and
          'not listed: run kit init with --inventory-api' in chk,
          'P18 the connectors it can see are listed with their purpose; the settings it cannot see are said', out[-300:])
    # P18b with --inventory-api and a token that may list: names only, each with what it is for
    d = make_repo(os.path.join(base, 'cn2'), 'app', FIXTURES['python'], remote=gov_remote)
    rc, res, out = run(d, '--dry-run', '--org-overlay', OVERLAY, '--inventory-api', '--list-teams',
                       env=dict(os.environ, KIT_INIT_GH=api_stub(base)))
    chk = io.open(os.path.join(d, '.kit', 'ADOPTION_CHECKLIST.md'), encoding='utf-8').read() if rc == 0 else ''
    check(rc == 0 and '`staging-old` | environment | not one the kit names' in chk and
          '`OLD_DEPLOY_KEY` | secret | not a kit name' in chk and
          '`KIT_SMALL_TEAM_SELF_APPROVAL` | variable | NOT a repository setting' in chk and
          'listed with the token kit init ran with' in chk,
          'P18 --inventory-api: environment, secret and variable NAMES listed, each with what it is for', out[-300:])
    check(not leaked(d, ['HTTP 403']), 'P18 nothing but names reaches a file')
    # N16 a token that may not list: NOT_ESTABLISHED, said
    d = make_repo(os.path.join(base, 'cn3'), 'app', FIXTURES['python'], remote=gov_remote)
    rc, res, out = run(d, '--dry-run', '--inventory-api', '--repo', 'example-org/app',
                       env=dict(os.environ, KIT_INIT_GH=api_stub(base, fail=True)))
    chk = io.open(os.path.join(d, '.kit', 'ADOPTION_CHECKLIST.md'), encoding='utf-8').read() if rc == 0 else ''
    check(rc == 0 and 'NOT_ESTABLISHED for those' in chk, 'N16 a token that cannot list: NOT_ESTABLISHED, said', out[-200:])
    # teams: listed when asked and the token can; NOT_ESTABLISHED otherwise
    d = make_repo(os.path.join(base, 'tm1'), 'app', FIXTURES['python'], remote='https://github.com/acme/%s.git')
    rc, res, out = run(d, '--dry-run', '--list-teams', env=dict(os.environ, KIT_INIT_GH=api_stub(base)))
    chk = io.open(os.path.join(d, '.kit', 'ADOPTION_CHECKLIST.md'), encoding='utf-8').read() if rc == 0 else ''
    check(rc == 0 and 'as the token listed them: `@acme/platform-approvers`' in chk, 'P19 --list-teams: the org teams listed for CODEOWNERS')
    d = make_repo(os.path.join(base, 'tm2'), 'app', FIXTURES['python'], remote='https://github.com/acme/%s.git')
    rc, res, out = run(d, '--dry-run')
    chk = io.open(os.path.join(d, '.kit', 'ADOPTION_CHECKLIST.md'), encoding='utf-8').read() if rc == 0 else ''
    check(rc == 0 and 'NOT_ESTABLISHED: no overlay names them' in chk, 'N17 no overlay, no teams, no listing: NOT_ESTABLISHED, said')
    # M10 the never-overwrite rule removed: a person's CODEOWNERS is changed, which P17's byte comparison catches
    d = make_repo(os.path.join(base, 'm10'), 'app', dict(FIXTURES['python'], CODEOWNERS='* @x/y\n'), remote=gov_remote)
    saved = KI.codeowners_findings
    try:
        KI.codeowners_findings = lambda e, b: []
        o = KI.parser().parse_args(['--target', d, '--kit-repo', KIT_REPO, '--kit-sha', SHA, '--dry-run'])
        ctx = KI.apply(KI.build(o), write=False)
    finally:
        KI.codeowners_findings = saved
    check('CODEOWNERS' not in ctx['writes'], 'M10 the existing CODEOWNERS is not in the write set (the guard holds)')


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
            host_detection(base)
            overlay(base)
            what_how_why(base)
            overlay_mutants(base)
            codeowners_and_connectors(base)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    if FAILS:
        print('FAIL: %d check(s): %s' % (len(FAILS), '; '.join(FAILS)))
        return 1
    print('PASS: kit init writes what the kit checks would pass, refuses by name, keeps edits, writes no secret.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
