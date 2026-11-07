#!/usr/bin/env python3
"""`kit init`: wire a repository to the secure CI/CD kit with one command, and say what only a person can do.

WHY THIS EXISTS (owner, 2026-11-06)
    The owner asked how painful adoption will be. Honest answer: heavy in week one without help, light after
    it if the rollout is done well. Developers are new to this way of working and the owner does not want
    "a million hoops". Wiring a repository by hand meant copying up to five starter templates, replacing
    YOUR_ORG and a placeholder SHA in each, working out which permissions each caller must grant, writing
    a dependabot.yml, a CODEOWNERS rule, the GitHub environments and their reviewers, the OIDC federated
    credentials -- and getting every one of them right before the first green run. This does the files
    and writes the rest down as a checklist with the exact commands.

WHAT IT DOES
    1. DETECTS the stacks (python, node, dotnet, java, php, go, static site, container, terraform, bicep;
       several at once) and the deploy shape (container, static, none). It never guesses: no recognised
       stack is a named refusal with guidance, and an unrecognised language beside a recognised one is
       named in the checklist as not covered by kit init.
    2. GENERATES, from the kit's own starter templates at the pinned commit:
         the caller workflow (build-deploy.yml for a container, build-deploy-static.yml for a static site,
           security.yml otherwise), pinned to the kit by SHA, each job that calls the kit granting EXACTLY
           the union of what the called workflow's jobs request -- no more, no less;
         dependabot-config-check.yml, and .github/dependabot.yml (scripts/dependabot_config.py generate);
         optional: dependabot-triage.yml (--with-triage), kit-api.yml (--with-api), kit-init.yml (always:
           re-running is a dispatch);
         a CODEOWNERS block (AppSec on .kit/, .kit/zone-readiness.json, .security/, the workflows,
           Dependabot config, Dockerfiles and IaC);
         .kit/environments.json (the environments SPEC: dev/test ungated, uat/prod with required reviewers
           from platform or security and self-review prevented, deployments from main only), .kit/settings.json
           (the answers, re-read on the next run) and .kit/ADOPTION_CHECKLIST.md (the PR body).
    3. VERIFIES what it generated before writing a byte: every caller grants what its callee requests
       (tests/check_caller_permissions.py) and nothing more, deploy callers grant deployments: write and
       pull-requests: read (scripts/consumer_surface_check.py R1), every kit reference is pinned to the one
       SHA, no placeholder is left, one security caller per repository, no secret value anywhere.
    4. Opens ONE branch and ONE pull request whose body is the checklist of the human-only steps (the
       environments and reviewers with the exact `gh api` commands, the OIDC federated credential per
       environment with this host's issuer, the readiness attestation outside a landing zone, the secret
       and variable NAMES to set, "Allow auto-merge" if opted in). `--dry-run` writes the files only.

WHAT IT NEVER DOES
    It never writes a secret (it takes none, and refuses output that contains a secret-shaped value or any
    secret-named environment variable's value). It never changes a repository setting, an environment, a
    reviewer, a ruleset or a credential: those are the checklist's, for a person.

IDEMPOTENT, AND A HUMAN EDIT WINS
    .kit/kit-init.lock.json records the hash of every file (and the CODEOWNERS block) it last wrote. On a
    re-run a file still byte-equal to what kit init wrote is updated; a file someone edited, or one that was
    there before kit init, is PRESERVED and listed (KIT_INIT_HUMAN_EDIT_PRESERVED) with how to take the kit's
    version (delete it, re-run). CODEOWNERS lines outside the markers are never touched.

USAGE
    python3 scripts/kit_init.py --target ../my-app --kit-repo OWNER/secure-cicd-kit [--kit-sha SHA]
        [--deploy auto|container|static|none] [--dockerfile PATH] [--site-dir DIR] [--with-triage]
        [--with-api] [--automerge] [--outside-landing-zone] [--appsec-team @org/team]
        [--platform-team @org/team] [--repo ORG/REPO] [--host github.com|<tenant>.ghe.com]
        [--dry-run] [--json FILE]
    python3 scripts/kit_init.py --detect --target DIR        print what it detects, change nothing
    python3 scripts/kit_init.py --self-test

STATES (kit_init_state in assurance-taxonomy.yaml; plain words in docs/errors/ERRORS.md)
    KIT_INIT_WRITTEN / KIT_INIT_PR_OPENED / KIT_INIT_UNCHANGED     done
    KIT_INIT_STACK_UNKNOWN          nothing kit init recognises; it will not guess
    KIT_INIT_MULTIPLE_IMAGES        several Dockerfiles and no --dockerfile
    KIT_INIT_PIN_MISSING            no kit repository, or the SHA is not 40 hex
    KIT_INIT_PIN_NOT_CHECKOUT       the SHA is not the commit these files were generated from
    KIT_INIT_HOST_UNSUPPORTED       a host other than github.com or <tenant>.ghe.com
    KIT_INIT_API_NEEDS_CONTAINER    --with-api needs build-deploy.yml (a container deploy)
    KIT_INIT_SECRET_REFUSED         the output would have carried a secret value; nothing written
    KIT_INIT_GENERATED_INVALID      the generated files failed kit init's own verification (a kit defect)
    KIT_INIT_DIRTY_TREE             PR mode, and the repository has uncommitted changes
    KIT_INIT_PR_NOT_OPENED          git or gh refused; the files are written, the reason printed
    KIT_INIT_HUMAN_EDIT_PRESERVED   (a notice) a file or block a person changed was kept

EXIT 0 done   1 refused (the state and the fix printed)   2 could not run (PyYAML missing, bad arguments)
"""
import argparse
import hashlib
import io
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
KIT_ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(KIT_ROOT, 'tests'))

import dependabot_config as DC  # noqa: E402

PLACEHOLDER_REPO = 'YOUR_ORG/secure-cicd-kit'
ZERO_SHA = '0' * 40
SHA_RX = re.compile(r'^[0-9a-f]{40}$')
LOCK = '.kit/kit-init.lock.json'
SETTINGS = '.kit/settings.json'
ENV_SPEC = '.kit/environments.json'
CHECKLIST = '.kit/ADOPTION_CHECKLIST.md'
BLOCK_BEGIN = '# >>> kit-init managed block: edit outside it; to own it, delete both marker lines'
BLOCK_END = '# <<< kit-init managed block'
HEADER = ('# kit-init: generated from %s at kit %s. Re-run kit init to update it; once you edit\n'
          '# this file kit init keeps your version and lists it (delete the file to take the kit\'s again).\n')
DOC_GETTING_STARTED = 'docs/adoption/GETTING_STARTED_1_HOUR.md'
DOC_ERRORS = 'docs/errors/ERRORS.md'

OK_WRITTEN, OK_PR, OK_UNCHANGED = 'KIT_INIT_WRITTEN', 'KIT_INIT_PR_OPENED', 'KIT_INIT_UNCHANGED'
STACK_UNKNOWN = 'KIT_INIT_STACK_UNKNOWN'
MULTIPLE_IMAGES = 'KIT_INIT_MULTIPLE_IMAGES'
PIN_MISSING = 'KIT_INIT_PIN_MISSING'
PIN_NOT_CHECKOUT = 'KIT_INIT_PIN_NOT_CHECKOUT'
HOST_UNSUPPORTED = 'KIT_INIT_HOST_UNSUPPORTED'
API_NEEDS_CONTAINER = 'KIT_INIT_API_NEEDS_CONTAINER'
SECRET_REFUSED = 'KIT_INIT_SECRET_REFUSED'
GENERATED_INVALID = 'KIT_INIT_GENERATED_INVALID'
DIRTY_TREE = 'KIT_INIT_DIRTY_TREE'
PR_NOT_OPENED = 'KIT_INIT_PR_NOT_OPENED'
HUMAN_EDIT_PRESERVED = 'KIT_INIT_HUMAN_EDIT_PRESERVED'

# ── detection ────────────────────────────────────────────────────────────────────────────────────
STACK_FILES = {
    'python': (r'^(requirements[\w.-]*\.(txt|in)|pyproject\.toml|Pipfile|setup\.py|setup\.cfg)$',),
    'node': (r'^package\.json$',),
    'dotnet': (r'.*\.(csproj|fsproj|vbproj|sln)$', r'^(global\.json|Directory\.Packages\.props)$'),
    'java': (r'^(pom\.xml|build\.gradle(\.kts)?|settings\.gradle(\.kts)?)$',),
    'php': (r'^composer\.json$',),
    'go': (r'^go\.mod$',),
    'container': (r'^Dockerfile([.-][\w.-]+)?$|.*\.Dockerfile$',),
    'terraform': (r'.*\.tf$',),
    'bicep': (r'.*\.bicep$',),
}
STATIC_MARKERS = (r'^staticwebapp\.config\.json$', r'^mkdocs\.ya?ml$', r'^hugo\.(toml|ya?ml|json)$',
                  r'^astro\.config\.(mjs|js|ts)$', r'^_config\.yml$')
STATIC_INDEX_DIRS = ('/', '/public', '/site', '/www', '/static')
# Seen, named, and NOT covered by kit init (it says so instead of guessing a pipeline for them).
UNSUPPORTED = {
    'ruby': r'^Gemfile$', 'rust': r'^Cargo\.toml$', 'elixir': r'^mix\.exs$', 'dart': r'^pubspec\.yaml$',
    'swift': r'^Package\.swift$', 'scala': r'^build\.sbt$', 'c/c++': r'^(CMakeLists\.txt|.*\.(c|cc|cpp|h|hpp))$',
}
KNOWN_STACKS = tuple(STACK_FILES) + ('static',)


def _rx(pats):
    return [re.compile(p) for p in pats]


_STACK_RX = {k: _rx(v) for k, v in STACK_FILES.items()}
_STATIC_RX = _rx(STATIC_MARKERS)
_UNSUP_RX = {k: re.compile(v) for k, v in UNSUPPORTED.items()}


def detect(root):
    """-> {stacks: {stack: [paths]}, unsupported: {lang: [paths]}, dockerfiles: [paths], static: [paths]}."""
    stacks, unsup, static = {}, {}, []
    for d, dirs, files in os.walk(root):
        rel = DC.rel_dir(root, d)
        if rel != '/' and DC.excluded_rule(rel, ()):
            dirs[:] = []
            continue
        dirs.sort()
        for f in sorted(files):
            path = (rel.rstrip('/') + '/' + f).lstrip('/')
            for stack, rxs in _STACK_RX.items():
                if any(r.match(f) for r in rxs):
                    stacks.setdefault(stack, []).append(path)
            if any(r.match(f) for r in _STATIC_RX) or (f == 'index.html' and rel in STATIC_INDEX_DIRS):
                static.append(path)
            for lang, r in _UNSUP_RX.items():
                if r.match(f):
                    unsup.setdefault(lang, []).append(path)
    if static:
        stacks['static'] = static
    return {'stacks': stacks, 'unsupported': unsup, 'dockerfiles': stacks.get('container', []),
            'static': static}


def deploy_shape(found, requested='auto'):
    """-> (shape, reason). Container when a Dockerfile exists (it states how the app ships); static when a
    static site and no Dockerfile; none otherwise. `requested` overrides, and is recorded as such."""
    if requested != 'auto':
        return requested, 'chosen with --deploy %s' % requested
    if found['dockerfiles']:
        return 'container', 'a Dockerfile is present (%s)' % ', '.join(found['dockerfiles'][:3])
    if found['static']:
        return 'static', 'a static site is present (%s) and no Dockerfile' % ', '.join(found['static'][:3])
    return 'none', 'no Dockerfile and no static site: the kit scans this repository; it deploys nothing'


# ── templates -> generated workflows ─────────────────────────────────────────────────────────────
def _load_yaml_text(text):
    import yaml
    return yaml.safe_load(text) or {}


def callee_needs(doc):
    """{scope: level} -- the union of what every job of a called workflow requests."""
    import check_caller_permissions as CCP
    need = {}
    for _job, req in CCP.requested(doc).items():
        for k, v in req.items():
            if k != '*':
                need[k] = max(need.get(k, 0), v)
    return need


LEVEL_NAME = {1: 'read', 2: 'write'}


def _job_span(lines, job):
    """(start, end) line indexes of `  job:` up to the next 2-space key."""
    start = None
    for i, ln in enumerate(lines):
        if start is None and ln.rstrip() == '  %s:' % job:
            start = i
        elif start is not None and re.match(r'^  [A-Za-z0-9_-]+:\s*$', ln):
            return start, i
    return (start, len(lines)) if start is not None else (None, None)


def set_job_permissions(text, job, need):
    """Rewrite one job's `permissions:` block to exactly `need`, keeping the comment of every kept key."""
    lines = text.split('\n')
    s, e = _job_span(lines, job)
    if s is None:
        return text
    p = None
    for i in range(s + 1, e):
        if lines[i].rstrip() == '    permissions:':
            p = i
            break
    old, j = {}, (p + 1 if p is not None else None)
    if p is not None:
        while j < e and lines[j].startswith('      ') and not lines[j].strip().startswith('#'):
            m = re.match(r'^      ([\w-]+):\s*(\w+)(\s+#.*)?$', lines[j])
            if not m:
                break
            old[m.group(1)] = (m.group(3) or '').rstrip()
            j += 1
    order = list(old) + sorted(k for k in need if k not in old)
    new = ['      %s: %s%s' % (k, LEVEL_NAME[need[k]], old.get(k, '')) for k in order if need.get(k)]
    if p is None:
        # insert after the `uses:` line
        for i in range(s + 1, e):
            if lines[i].startswith('    uses:'):
                lines[i + 1:i + 1] = ['    permissions:'] + new
                break
        return '\n'.join(lines)
    lines[p + 1:j] = new
    return '\n'.join(lines)


def _with_insert(text, job, entries):
    """Add `key: value` lines at the top of a job's `with:` block (used for dockerfile/context/site_dir)."""
    lines = text.split('\n')
    s, e = _job_span(lines, job)
    if s is None:
        return text
    for i in range(s + 1, e):
        if lines[i].rstrip() == '    with:':
            lines[i + 1:i + 1] = ['      %s: %s' % (k, v) for k, v in entries]
            return '\n'.join(lines)
    return text


def render_template(name, kit_repo, kit_sha, generated, tweak=None):
    """A starter template as the consumer's file: pinned, placeholder-free, exact permissions."""
    src = os.path.join(KIT_ROOT, 'templates', name)
    with io.open(src, encoding='utf-8') as fh:
        text = fh.read()
    # Placeholders are replaced in the YAML, never in the comments (which keep explaining the template).
    text = '\n'.join(ln if ln.lstrip().startswith('#') else ln.replace(PLACEHOLDER_REPO, kit_repo).replace(ZERO_SHA, kit_sha)
                     for ln in text.split('\n'))
    if tweak:
        text = tweak(text)
    doc = _load_yaml_text(text)
    for job, j in (doc.get('jobs') or {}).items():
        uses = str((j or {}).get('uses') or '')
        m = re.match(r'^%s/(\.github/workflows/[^@]+)@%s$' % (re.escape(kit_repo), kit_sha), uses)
        if m:
            with io.open(os.path.join(KIT_ROOT, m.group(1)), encoding='utf-8') as fh:
                text = set_job_permissions(text, job, callee_needs(_load_yaml_text(fh.read())))
        elif uses.startswith('./.github/workflows/'):
            local = generated.get(uses[2:])
            if local is not None:
                text = set_job_permissions(text, job, callee_needs(_load_yaml_text(local)))
    return (HEADER % ('templates/' + name, kit_sha)) + text


# ── secrets: none in, none out ───────────────────────────────────────────────────────────────────
SECRET_SHAPES = re.compile(
    r'(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|'
    r'xox[abpr]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,})')
SECRET_ENV_NAME = re.compile(r'(TOKEN|SECRET|PASSWORD|PASSWD|_KEY$|^KEY_|_PAT$|CREDENTIAL|PRIVATE)', re.I)


def secret_leaks(files, environ=None):
    """-> [(path, why)] for every generated file that carries a secret-shaped value or the value of a
    secret-named environment variable (kit init takes no secret; this is the second lock on the door)."""
    environ = os.environ if environ is None else environ
    values = [(k, v) for k, v in environ.items() if SECRET_ENV_NAME.search(k) and v and len(v) >= 8]
    out = []
    for path, text in files.items():
        m = SECRET_SHAPES.search(text)
        if m:
            out.append((path, 'a secret-shaped value (%s...)' % m.group(0)[:6]))
        for k, v in values:
            if v in text:
                out.append((path, 'the value of the environment variable %s' % k))
    return out


# ── verification of the generated set ───────────────────────────────────────────────────────────
DEPLOY_REUSABLES = ('reusable-deploy-containerapp.yml', 'reusable-deploy-appservice.yml',
                    'reusable-deploy-staticwebapp.yml')


def verify(files, kit_repo, kit_sha):
    """-> [problem]. Run on the generated workflows before anything is written."""
    import check_caller_permissions as CCP
    probs = []
    wf = {p: t for p, t in files.items() if p.startswith('.github/workflows/')}
    docs = {p: _load_yaml_text(t) for p, t in wf.items()}
    callers = [p for p in wf if p.endswith(('/security.yml', '/build-deploy.yml', '/build-deploy-static.yml'))]
    if len(callers) != 1:
        probs.append('one security caller per repository (KDEC-033): generated %s' % (callers or 'none'))
    for p, t in wf.items():
        for ln in t.splitlines():
            code = ln.split('#', 1)[0]
            if 'YOUR_ORG' in code or ZERO_SHA in code:
                probs.append('%s still carries a placeholder: %s' % (p, ln.strip()))
        for m in re.finditer(r'%s/\.github/(?:workflows|actions)/[\w./-]+@(\S+)' % re.escape(kit_repo), t):
            if m.group(1).strip('"\'') != kit_sha:
                probs.append('%s pins the kit at %s, not %s' % (p, m.group(1), kit_sha))
    for p, doc in docs.items():
        for job, j in (doc.get('jobs') or {}).items():
            uses = str((j or {}).get('uses') or '')
            m = re.match(r'^%s/(\.github/workflows/[^@]+)@' % re.escape(kit_repo), uses)
            if m:
                callee = _load_yaml_text(io.open(os.path.join(KIT_ROOT, m.group(1)), encoding='utf-8').read())
            elif uses.startswith('./.github/workflows/') and uses[2:] in docs:
                callee = docs[uses[2:]]
            else:
                continue
            need = callee_needs(callee)
            granted = CCP.perms(j.get('permissions'))
            if granted is None:
                probs.append('%s job %s declares no permissions' % (p, job))
                continue
            for k, v in need.items():
                if (CCP.grants(granted, k) or 0) < v:
                    probs.append('%s job %s grants %s below what %s requests (startup_failure)' % (p, job, k, uses))
            for k, v in granted.items():
                if v > need.get(k, 0):
                    probs.append('%s job %s grants %s=%s, more than %s requests (least privilege)'
                                 % (p, job, k, LEVEL_NAME.get(v, v), uses))
            if any(n in uses for n in DEPLOY_REUSABLES):
                pr = j.get('permissions') or {}
                if pr.get('deployments') != 'write' or pr.get('pull-requests') not in ('read', 'write'):
                    probs.append('%s job %s: a deploy caller needs deployments: write and pull-requests: read' % (p, job))
    return probs


# ── host, repository, environments, OIDC ─────────────────────────────────────────────────────────
def parse_remote(url):
    url = (url or '').strip()
    m = re.match(r'^(?:https?://)(?:[^@/]+@)?([^/]+)/([^/]+)/([^/]+?)(?:\.git)?/?$', url) or \
        re.match(r'^(?:ssh://)?git@([^:/]+)[:/]([^/]+)/([^/]+?)(?:\.git)?$', url)
    return (m.group(1), '%s/%s' % (m.group(2), m.group(3))) if m else (None, None)


def issuer_for(host):
    if host == 'github.com':
        return 'https://token.actions.githubusercontent.com'
    m = re.match(r'^([a-z0-9-]+)\.ghe\.com$', host or '')
    return 'https://token.actions.%s.ghe.com' % m.group(1) if m else None


def environments_spec(shape, opts, repo, host):
    envs = []
    deploy_envs = [] if shape == 'none' else ['dev', 'test', 'uat', 'prod']
    reviewers = [t for t in (opts.platform_team, opts.appsec_team) if t]
    for name in deploy_envs:
        gated = name in ('uat', 'prod')
        envs.append({'name': name, 'tier': name,
                     'required_reviewers': [{'type': 'Team', 'team': t} for t in reviewers] if gated else [],
                     'prevent_self_review': gated, 'wait_timer_minutes': 0,
                     'deployment_branches': ['main'],
                     'why': ('a production tier: a person from platform or security, never the deployer, approves '
                             'every release (same business day; ROLLOUT_PLAN.md section 4)') if gated else
                            'deployed on every merge to main; no approval, so feedback is fast'})
    if shape == 'container':
        envs.append({'name': 'build', 'tier': None, 'required_reviewers': [], 'prevent_self_review': False,
                     'wait_timer_minutes': 0, 'deployment_branches': ['main'],
                     'why': 'the build identity (AcrPush only) signs in here; never a deploy identity'})
    if opts.with_api:
        envs.append({'name': 'ticketing', 'tier': None, 'required_reviewers': [], 'prevent_self_review': False,
                     'wait_timer_minutes': 0, 'deployment_branches': ['main'],
                     'why': 'the tracker credentials live here, read only by the ticket reconciler'})
    oidc = issuer_for(host)
    return {'schema': 'kit-environments-spec/1', 'host': host, 'repository': repo,
            'applied_by': 'a person, with the commands in .kit/ADOPTION_CHECKLIST.md; kit init never applies it',
            'oidc': {'issuer': oidc, 'audience': 'api://AzureADTokenExchange',
                     'subjects': {e['name']: 'repo:%s:environment:%s' % (repo, e['name'])
                                  for e in envs if e['name'] not in ('ticketing',)}},
            'environments': envs}


# ── the checklist (the PR body) ──────────────────────────────────────────────────────────────────
def checklist(ctx):
    o, repo, host, spec = ctx['opts'], ctx['repo'], ctx['host'], ctx['spec']
    kit_url = 'https://%s/%s/blob/%s/' % (host, ctx['kit_repo'], ctx['kit_sha'])
    owner = repo.split('/')[0]
    L = ['# Adopt the secure CI/CD kit (kit init)', '',
         'kit init wrote the files below, pinned to the kit at `%s`. Everything a file can do is in this pull '
         'request. The steps under **Only a person can do these** change settings, so kit init never does them; '
         'each has the exact command. When they are done, merge, and follow [Getting started in 1 hour](%s%s).'
         % (ctx['kit_sha'], kit_url, DOC_GETTING_STARTED), '',
         '**Detected:** %s. **Deploy shape:** `%s` (%s).' % (
             ', '.join('%s (%s)' % (s, ', '.join(p[:2])) for s, p in sorted(ctx['found']['stacks'].items())),
             ctx['shape'], ctx['shape_reason'])]
    if ctx['found']['unsupported']:
        L += ['', '**Not covered by kit init** (it will not guess a pipeline for them; the security scan still '
              'reads them where the kit has a scanner): ' + ', '.join(
                  '%s (%s)' % (k, ', '.join(v[:2])) for k, v in sorted(ctx['found']['unsupported'].items()))]
    L += ['', '## What this pull request adds', '', '| file | owner |', '|---|---|']
    kept = {p.split(' ')[0] for p in ctx['preserved']}
    for path in sorted(set(ctx['files']) | {ctx['co_rel'], CHECKLIST}):
        L.append('| `%s` | %s |' % (path, 'yours: kit init keeps it as you left it' if path in kept else
                                       'kit init (the CODEOWNERS block only; your lines are yours)' if path == ctx['co_rel']
                                       else 'kit init: re-running updates it until you edit it'))
    if ctx['preserved']:
        L += ['', '**Kept as you left them** (`KIT_INIT_HUMAN_EDIT_PRESERVED`): ' + ', '.join(
            '`%s`' % p for p in ctx['preserved']) + '. kit init never overwrites a person\'s edit. To take the '
            'kit\'s version of one, delete it (or the CODEOWNERS block markers) and run kit init again.']
    for c in ctx['conflicts']:
        L += ['', '**Resolve before merging:** ' + c]
    L += ['', '## Only a person can do these', '']
    n = 0

    def step(title, body):
        nonlocal n
        n += 1
        L.extend(['- [ ] **%d. %s**' % (n, title), ''] + ['  ' + b if b else '' for b in body] + [''])

    envs = spec['environments']
    if envs:
        body = ['GitHub environments hold the approvals and the sign-in identity. Who approves uat and prod: a '
                'person from **platform or security**, never someone on this team alone and never the deployer '
                '(self-review prevented). Run as a repository admin:', '', '```bash',
                'export GH_HOST=%s   # this repository\'s host' % host]
        teams = [t for t in (o.platform_team, o.appsec_team) if t]
        for t in teams:
            slug = t.lstrip('@').split('/')[-1]
            body.append('%s_ID=$(gh api orgs/%s/teams/%s --jq .id)' % (_var(slug), owner, slug))
        for e in envs:
            rv = ','.join('{"type":"Team","id":$%s_ID}' % _var(t['team'].lstrip('@').split('/')[-1])
                          for t in e['required_reviewers'])
            body.append('gh api -X PUT repos/%s/environments/%s --input - <<JSON' % (repo, e['name']))
            body.append('{"wait_timer":0,"prevent_self_review":%s,"reviewers":[%s],'
                        '"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}'
                        % ('true' if e['prevent_self_review'] else 'false', rv))
            body.append('JSON')
            body.append('gh api -X POST repos/%s/environments/%s/deployment-branch-policies -f name=main -f type=branch'
                        % (repo, e['name']))
        body += ['```', '']
        if not teams:
            body.append('No `--platform-team` / `--appsec-team` was given, so uat and prod above have NO reviewers '
                        'yet: re-run kit init with them, or add the reviewers in Settings > Environments.')
        body.append('The spec is `.kit/environments.json`; the deploy reads the rules back and refuses an unprotected '
                    'uat or prod before it signs in (ENVIRONMENT_REVIEWERS_ABSENT).')
        step('Create the environments and their reviewers', body)
        subj = spec['oidc']['subjects']
        body = ['One federated credential per environment on the deploy identity (the landing zone vends it; '
                'outside one, the identity\'s owner adds them). This host\'s issuer is `%s`; the subject must '
                'match character for character, and it is case-sensitive.' % spec['oidc']['issuer'], '', '```bash',
                'APP_ID=<the deploy identity\'s application (client) id>']
        for env, s in sorted(subj.items()):
            if env == 'build':
                continue
            body.append('az ad app federated-credential create --id "$APP_ID" --parameters \'{"name":"gh-%s-%s",'
                        '"issuer":"%s","subject":"%s","audiences":["api://AzureADTokenExchange"]}\''
                        % (repo.split('/')[-1], env, spec['oidc']['issuer'], s))
        if 'build' in subj:
            body += ['# the BUILD identity (AcrPush on this image repository only) is a different identity:',
                     'BUILD_APP_ID=<the build identity\'s application (client) id>',
                     'az ad app federated-credential create --id "$BUILD_APP_ID" --parameters \'{"name":"gh-%s-build",'
                     '"issuer":"%s","subject":"%s","audiences":["api://AzureADTokenExchange"]}\''
                     % (repo.split('/')[-1], spec['oidc']['issuer'], subj['build'])]
        body += ['```', '', 'Check them without deploying anything: run the kit\'s `verify-azure-oidc.yml` for each '
                 'environment. `AADSTS700213` means a subject does not match; `AADSTS70025` means none exists.']
        step('Add the OIDC federated credentials (no client secret, ever)', body)
    if o.outside_landing_zone and envs:
        step('Readiness attestation (this repository deploys outside a landing zone)', [
            'AppSec writes `.kit/zone-readiness.json` from the kit\'s `templates/zone-readiness.example.json` and '
            'approves it in a pull request; CODEOWNERS already makes AppSec the required reviewer of that path. '
            'Without it a uat or prod deploy is refused before sign-in.'])
    names = secret_names(ctx)
    step('Set these variables and secrets (names only; kit init never sees a value)', [
        '| name | kind | where | required |', '|---|---|---|---|'] + [
        '| `%s` | %s | %s | %s |' % row for row in names] + [
        '', 'Set them in Settings > Secrets and variables > Actions (or per environment, as the column says). '
        'Never put a value in a file.'])
    if o.automerge:
        step('Turn on "Allow auto-merge" (you opted in)', [
            '```bash', 'gh api -X PATCH repos/%s -F allow_auto_merge=true' % repo, '```',
            'Read the risks first: [AUTOMERGE_RISKS_AND_ROLLOUT.md](%sdocs/adoption/AUTOMERGE_RISKS_AND_ROLLOUT.md). '
            'Auto-merge only helps once `security / Security gate` is a required status check: '
            '[BRANCH_PROTECTION_SETTINGS.md](%sdocs/adoption/BRANCH_PROTECTION_SETTINGS.md).' % (kit_url, kit_url)])
    if any(t.startswith('@YOUR_ORG/') for t in ctx['teams_written']):
        step('Name the real teams in CODEOWNERS', [
            'kit init was given no team, so the CODEOWNERS block names `@YOUR_ORG/...` placeholders. Re-run with '
            '`--appsec-team @<org>/<team> --platform-team @<org>/<team>`, or edit the block (kit init then keeps your edit).'])
    step('Make the security check required on main (after the first green run)', [
        'Settings > Rules: require `security / Security gate` on `main`. The exact ruleset: '
        '[BRANCH_PROTECTION_SETTINGS.md](%sdocs/adoption/BRANCH_PROTECTION_SETTINGS.md).' % kit_url])
    L += ['## When something fails', '',
          'Every refusal starts with a plain sentence and the state name in brackets, e.g. "The security scan '
          'found a committed secret, so nothing is built or deployed. [BLOCKED]". The catalogue: '
          '[ERRORS.md](%s%s).' % (kit_url, DOC_ERRORS), '',
          '_Generated by `scripts/kit_init.py` (kit %s). Re-running it updates its own files and keeps yours._'
          % ctx['kit_sha']]
    return '\n'.join(L) + '\n'


def _var(slug):
    return re.sub(r'[^A-Za-z0-9]', '_', slug).upper()


def secret_names(ctx):
    shape, o = ctx['shape'], ctx['opts']
    rows = []
    if shape in ('container', 'static'):
        for n in ('AZURE_TENANT_ID', 'AZURE_SUBSCRIPTION_ID', 'AZURE_CLIENT_ID'):
            rows.append((n, 'variable (not a secret: the identity is federated)', 'each environment', 'yes'))
        for n in ('KIT_RESOURCE_GROUP', 'KIT_APP_NAME', 'KIT_ENVIRONMENT_TIER'):
            rows.append((n, 'variable', 'each environment (vended by the landing zone)', 'yes'))
        rows.append(('KIT_CLOUD', 'variable', 'repository', 'only for Azure Government (`gov`)'))
        rows.append(('KIT_E2E_TEST_COMMAND', 'variable', 'repository', 'to promote to uat/prod ("tested")'))
    if shape == 'container':
        for n in ('KIT_ACR_LOGIN_SERVER', 'KIT_IMAGE_REPOSITORY'):
            rows.append((n, 'variable', 'repository (the build reads it)', 'yes'))
    if shape == 'static':
        rows.append(('KIT_STATIC_BUILD_COMMAND', 'variable', 'repository', 'when the site needs building (e.g. `npm ci && npm run build`)'))
    rows.append(('SEMGREP_APP_TOKEN', 'secret', 'repository', 'no (optional)'))
    if o.with_api:
        for n in ('JIRA_EMAIL', 'JIRA_TOKEN', 'JIRA_HOST'):
            rows.append((n, 'secret', 'the `ticketing` environment', 'for tickets'))
        rows.append(('KIT_API_OPERATIONS', 'variable', 'repository', 'to serve writes (reads need nothing)'))
    if o.with_triage:
        rows.append(('DEPENDABOT_METADATA_TOKEN', 'secret', 'repository', 'no (optional: alert linkage)'))
    rows.append(('KIT_INIT_TOKEN', 'secret', 'repository', 'only to let the kit-init workflow open its PR (Contents, '
                 'Pull requests and Workflows: read and write; without it the workflow uploads the files instead)'))
    return rows


# ── CODEOWNERS block ─────────────────────────────────────────────────────────────────────────────
def codeowners_block(found, appsec, platform):
    rows = [('/.kit/', appsec), ('/.kit/zone-readiness.json', appsec), ('/.security/', appsec),
            ('/.github/workflows/', '%s %s' % (platform, appsec)), ('/.github/actions/', '%s %s' % (platform, appsec)),
            ('/.github/dependabot.yml', '%s %s' % (platform, appsec)), ('/.github/CODEOWNERS', appsec),
            ('/CODEOWNERS', appsec)]
    for p in found['dockerfiles']:
        rows.append(('/' + p, '%s %s' % (platform, appsec)))
    for s in ('terraform', 'bicep'):
        for d in sorted({os.path.dirname(p) for p in found['stacks'].get(s, [])}):
            rows.append(('/%s/*.%s' % (d, 'tf' if s == 'terraform' else 'bicep') if d else '/*.%s' % (
                'tf' if s == 'terraform' else 'bicep'), '%s %s' % (platform, appsec)))
    width = max(len(r[0]) for r in rows) + 2
    body = ['# Security-relevant paths: AppSec (and platform) review every change. Last match wins, so this',
            '# block sits at the end of the file and your own rules above it cannot loosen it.']
    body += ['%s%s' % (p.ljust(width), o) for p, o in rows]
    return '\n'.join(body)


def place_block(existing, block):
    """-> (new_text, state). Appends the block, replaces it, or reports that a person edited it."""
    begin = existing.find(BLOCK_BEGIN) if existing else -1
    end = existing.find(BLOCK_END) if existing else -1
    wrapped = '%s\n%s\n%s\n' % (BLOCK_BEGIN, block, BLOCK_END)
    if begin < 0 or end < 0:
        sep = '' if not existing or existing.endswith('\n\n') else ('\n' if existing.endswith('\n') else '\n\n')
        return (existing or '') + sep + wrapped, 'appended'
    inner = existing[begin + len(BLOCK_BEGIN) + 1:end].rstrip('\n')
    return existing[:begin] + wrapped + existing[end + len(BLOCK_END) + 1:], inner


def sha(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


# ── plan, apply ──────────────────────────────────────────────────────────────────────────────────
class Refusal(Exception):
    def __init__(self, state, what, fix):
        Exception.__init__(self, '%s: %s' % (state, what))
        self.state, self.what, self.fix = state, what, fix


def _read(root, rel):
    p = os.path.join(root, *rel.split('/'))
    if not os.path.isfile(p):
        return None
    with io.open(p, encoding='utf-8', newline='') as fh:
        return fh.read()


def _git(root, *args):
    return subprocess.run(['git', '-C', root] + list(args), capture_output=True, text=True)


def resolve_pin(opts):
    if not opts.kit_repo or not re.match(r'^[\w.-]+/[\w.-]+$', opts.kit_repo) or opts.kit_repo == PLACEHOLDER_REPO:
        raise Refusal(PIN_MISSING, 'no kit repository was named (or it is the YOUR_ORG placeholder).',
                      'pass --kit-repo OWNER/REPO: the repository your organisation hosts the kit in.')
    head = None
    if os.path.isdir(os.path.join(KIT_ROOT, '.git')) or os.path.isfile(os.path.join(KIT_ROOT, '.git')):
        r = _git(KIT_ROOT, 'rev-parse', 'HEAD')
        head = r.stdout.strip() if r.returncode == 0 and SHA_RX.match(r.stdout.strip()) else None
    kit_sha = (opts.kit_sha or head or '').lower()
    if not SHA_RX.match(kit_sha):
        raise Refusal(PIN_MISSING, 'the kit commit to pin is not a 40-hex SHA (%r).' % (opts.kit_sha or ''),
                      'pass --kit-sha with the full commit SHA of the kit release you chose (a branch or tag is '
                      'refused: the verdict must come from code somebody chose).')
    if head and kit_sha != head:
        raise Refusal(PIN_NOT_CHECKOUT, 'the files would be generated from the kit at %s but pinned to %s.' % (head, kit_sha),
                      'check out the kit at %s (git -C <kit> checkout %s) and run again, or omit --kit-sha.' % (kit_sha, kit_sha))
    return opts.kit_repo, kit_sha, ('the kit checkout\'s HEAD' if head else 'given (the kit files are not a git checkout)')


def build(opts):
    """-> ctx with `files` {rel: text} and everything the checklist needs. Raises Refusal."""
    root = os.path.abspath(opts.target)
    kit_repo, kit_sha, pin_source = resolve_pin(opts)
    found = detect(root)
    known = {k: v for k, v in found['stacks'].items() if k in KNOWN_STACKS}
    if not known:
        seen = ', '.join('%s (%s)' % (k, ', '.join(v[:2])) for k, v in sorted(found['unsupported'].items())) or 'no manifest at all'
        raise Refusal(STACK_UNKNOWN, 'kit init recognises none of this repository\'s stacks (it saw: %s), and it will '
                      'not guess a pipeline.' % seen,
                      'kit init knows python, node, dotnet, java, php, go, static sites, containers, terraform and bicep. '
                      'If this repository is one of those, the manifest is missing (add it, e.g. requirements.txt or '
                      'package.json); otherwise copy templates/security.yml by hand and ask the platform team which '
                      'scanners cover your language (docs/adoption/USAGE.md).')
    shape, why = deploy_shape(found, opts.deploy)
    host, repo = opts.host, opts.repo
    if not (host and repo):
        r = _git(root, 'remote', 'get-url', 'origin')
        h, rp = parse_remote(r.stdout) if r.returncode == 0 else (None, None)
        host, repo = host or h or 'github.com', repo or rp or '<ORG>/<REPO>'
    if not issuer_for(host):
        raise Refusal(HOST_UNSUPPORTED, 'the host %r is neither github.com nor a <tenant>.ghe.com host.' % host,
                      'pass --host github.com or --host <tenant>.ghe.com (KDEC-027 names the supported hosts).')
    if opts.with_api and shape != 'container':
        raise Refusal(API_NEEDS_CONTAINER, '--with-api calls this repository\'s build-deploy.yml, which kit init writes '
                      'only for a container deploy (this one is %r).' % shape,
                      'drop --with-api for now (scans and findings need no API), or deploy a container (--deploy container).')
    dockerfile = None
    if shape == 'container':
        dfs = found['dockerfiles']
        if opts.dockerfile:
            dockerfile = opts.dockerfile.strip('/')
        elif len(dfs) > 1:
            raise Refusal(MULTIPLE_IMAGES, 'this repository has %d Dockerfiles (%s); kit init will not pick one.' % (
                len(dfs), ', '.join(dfs[:5])),
                'pass --dockerfile PATH for the image this repository deploys (one pipeline per deployable; a second '
                'image is a second repository or a second caller, docs/adoption/USAGE.md).')
        elif dfs:
            dockerfile = dfs[0]
    teams = (opts.appsec_team or '@YOUR_ORG/appsec', opts.platform_team or '@YOUR_ORG/platform')
    files, generated = {}, {}

    def add(rel, text):
        files[rel] = text
        if rel.startswith('.github/workflows/'):
            generated[rel] = text

    if shape == 'container':
        def tweak(t):
            if dockerfile and dockerfile != 'Dockerfile':
                ctxdir = os.path.dirname(dockerfile) or '.'
                t = _with_insert(t, 'build', [('dockerfile', dockerfile), ('context', ctxdir)])
            return t
        add('.github/workflows/build-deploy.yml', render_template('build-deploy.yml', kit_repo, kit_sha, generated, tweak))
    elif shape == 'static':
        site = (opts.site_dir or _guess_site_dir(found)).strip('/') or '.'

        def tweak(t):
            return re.sub(r'(?m)^(\s+path: )\S+(\s+# kit-init: site-dir)', lambda m: m.group(1) + site + m.group(2), t)
        add('.github/workflows/build-deploy-static.yml',
            render_template('build-deploy-static.yml', kit_repo, kit_sha, generated, tweak))
    else:
        add('.github/workflows/security.yml', render_template('security.yml', kit_repo, kit_sha, generated))
    add('.github/workflows/dependabot-config-check.yml',
        render_template('dependabot-config-check.yml', kit_repo, kit_sha, generated))
    if opts.with_triage:
        add('.github/workflows/dependabot-triage.yml', render_template('dependabot-triage.yml', kit_repo, kit_sha, generated))
    if opts.with_api:
        add('.github/workflows/kit-api.yml', render_template('kit-api.yml', kit_repo, kit_sha, generated))
    add('.github/workflows/kit-init.yml', render_template('kit-init.yml', kit_repo, kit_sha, generated))
    files['.github/dependabot.yml'] = DC.generate(
        root, also=[{'ecosystem': 'github-actions', 'directory': '/', 'file': '.github/workflows'}])
    spec = environments_spec(shape, opts, repo, host)
    files[ENV_SPEC] = json.dumps(spec, indent=2) + '\n'
    settings = {'schema': 'kit-settings/1', 'kit': {'repository': kit_repo, 'sha': kit_sha, 'pin_source': pin_source},
                'deploy': shape, 'deploy_requested': opts.deploy, 'dockerfile': dockerfile, 'site_dir': opts.site_dir, 'with_triage': bool(opts.with_triage),
                'with_api': bool(opts.with_api), 'automerge': bool(opts.automerge),
                'outside_landing_zone': bool(opts.outside_landing_zone),
                'appsec_team': opts.appsec_team, 'platform_team': opts.platform_team,
                'rung': 'crawl', 'note': 'kit init re-reads these answers on its next run; the kit itself reads none '
                'of them (the rung comes from the policy register, crawl when there is none).'}
    files[SETTINGS] = json.dumps(settings, indent=2) + '\n'
    return {'root': root, 'opts': opts, 'kit_repo': kit_repo, 'kit_sha': kit_sha, 'found': found, 'shape': shape,
            'shape_reason': why, 'host': host, 'repo': repo, 'spec': spec, 'files': files, 'teams': teams,
            'teams_written': list(teams), 'codeowners': codeowners_block(found, teams[0], teams[1])}


def _guess_site_dir(found):
    for p in found['static']:
        if p.endswith('staticwebapp.config.json'):
            return os.path.dirname(p) or '.'
    for p in found['static']:
        if p.endswith('index.html'):
            return os.path.dirname(p) or '.'
    return 'dist'


def _merge_file(root, rel, text, owned, results, preserved, writes):
    cur = _read(root, rel)
    if cur is None:
        writes[rel], results[rel] = text, 'created'
    elif cur == text:
        results[rel] = 'unchanged'
    elif rel in owned and sha(cur) == owned[rel]:
        writes[rel], results[rel] = text, 'updated'
    else:
        preserved.append(rel)
        results[rel] = 'kept (edited by a person, or there before kit init)'
        return False
    return True


def apply(ctx, write=True):
    """Merge the plan into the tree under the lock's rules. -> ctx with results/preserved/conflicts."""
    root = ctx['root']
    lock_text = _read(root, LOCK)
    try:
        lock = json.loads(lock_text) if lock_text else {}
    except ValueError:
        lock = {}
    owned = dict(lock.get('files') or {})
    results, preserved, conflicts, writes, deletes = {}, [], [], {}, []
    # one security caller: a kit-init security.yml goes when a build-deploy caller replaces it
    caller = [p for p in ctx['files'] if p.startswith('.github/workflows/') and
              p.endswith(('/build-deploy.yml', '/build-deploy-static.yml', '/security.yml'))]
    for other in ('.github/workflows/security.yml', '.github/workflows/build-deploy.yml',
                  '.github/workflows/build-deploy-static.yml'):
        if other in caller:
            continue
        cur = _read(root, other)
        if cur is None:
            continue
        if other in owned and sha(cur) == owned[other]:
            deletes.append(other)
            results[other] = 'removed (replaced by %s: one security caller per repository)' % caller[0]
        else:
            conflicts.append('`%s` exists and was not written by kit init; with `%s` the repository would run the '
                             'whole suite twice. Delete `%s` in this pull request (KDEC-033).' % (other, caller[0], other))
    for rel, text in ctx['files'].items():
        if not _merge_file(root, rel, text, owned, results, preserved, writes) and rel == '.github/dependabot.yml':
            probs, _w, _s = DC.check(root)
            if probs:
                conflicts.append('your `.github/dependabot.yml` has %d problem(s) (`python3 scripts/dependabot_config.py '
                                 'check` names each fix); kit init did not change it.' % len(probs))
    # CODEOWNERS: block mode, in whichever file GitHub reads first; lines outside the block are never touched
    co_rel = next((p for p in ('.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS') if _read(root, p) is not None),
                  '.github/CODEOWNERS')
    key = co_rel + '#kit-init-block'
    cur = _read(root, co_rel) or ''
    new, state = place_block(cur, ctx['codeowners'])
    block_ours = True
    if state == 'appended':
        if key in owned:   # the markers were deleted after kit init wrote them: the person owns it now
            block_ours = False
            preserved.append(co_rel + ' (the kit-init block: its markers were removed)')
            results[co_rel] = 'kept (a person took the block over)'
        else:
            writes[co_rel], results[co_rel] = new, 'created' if not cur else 'block appended (your lines kept)'
    elif state == ctx['codeowners'] or (key in owned and sha(state) == owned[key]):
        if new != cur:
            writes[co_rel], results[co_rel] = new, 'block updated (your lines kept)'
        else:
            results[co_rel] = 'unchanged'
    else:
        block_ours = False
        preserved.append(co_rel + ' (the kit-init block)')
        results[co_rel] = 'block kept (edited by a person)'
    if not block_ours:
        ctx['teams_written'] = []
    ctx.update(results=results, preserved=preserved, conflicts=conflicts, co_rel=co_rel)
    _merge_file(root, CHECKLIST, checklist(ctx), owned, results, preserved, writes)
    # nothing is written unless the whole set is clean
    leaks = secret_leaks(dict(list(writes.items()) + list(ctx['files'].items())))
    if leaks:
        raise Refusal(SECRET_REFUSED, 'the output would have carried %s; nothing was written.' % '; '.join(
            '%s in %s' % (w, p) for p, w in leaks[:3]),
            'unset the variable or remove the value from the repository file kit init read, then run again. kit init '
            'never needs a secret: it writes secret NAMES into the checklist only.')
    probs = verify(ctx['files'], ctx['kit_repo'], ctx['kit_sha'])
    if probs:
        raise Refusal(GENERATED_INVALID, 'kit init\'s own check of what it generated failed: %s' % '; '.join(probs[:4]),
                      'this is a defect in the kit, not in your repository: report it to the kit maintainers with this '
                      'output. Nothing was written.')
    new_owned = dict(owned)
    for rel, text in writes.items():
        if rel != co_rel:
            new_owned[rel] = sha(text)
    if block_ours:
        new_owned[key] = sha(ctx['codeowners'])
    for d in deletes:
        new_owned.pop(d, None)
    lock_out = json.dumps({'schema': 'kit-init-lock/1', 'files': dict(sorted(new_owned.items()))}, indent=2) + '\n'
    if lock_out != lock_text:
        writes[LOCK] = lock_out
        results[LOCK] = 'updated' if lock_text else 'created'
    ctx['writes'], ctx['deletes'] = writes, deletes
    if write:
        for rel, text in writes.items():
            p = os.path.join(root, *rel.split('/'))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with io.open(p, 'w', encoding='utf-8', newline='\n') as fh:
                fh.write(text)
        for d in deletes:
            os.remove(os.path.join(root, *d.split('/')))
    return ctx


def gh_cmd():
    """`gh`, or KIT_INIT_GH (a JSON list, e.g. a stub interpreter and script, as the proof uses)."""
    v = os.environ.get('KIT_INIT_GH') or ''
    return json.loads(v) if v.startswith('[') else (v.split() or ['gh'])


def pr_branch(kit_sha):
    return 'kit-init/%s' % kit_sha[:12]


def start_branch(root, branch):
    """Continue the kit-init branch if the remote has it (a re-run adds a commit, never a force push);
    otherwise start it from HEAD. Called BEFORE anything is written, so the branch's own settings apply."""
    have = _git(root, 'fetch', '--quiet', 'origin', 'refs/heads/%s:refs/remotes/origin/%s' % (branch, branch)).returncode == 0
    r = _git(root, 'checkout', '-q', '-B', branch, 'origin/%s' % branch if have else 'HEAD')
    if r.returncode != 0:
        raise Refusal(PR_NOT_OPENED, 'git could not start the branch %s: %s' % (branch, (r.stderr or r.stdout).strip()[-300:]),
                      'run kit init from a clean clone whose origin is the repository (or use --dry-run).')


def open_pr(ctx):
    """ONE branch, ONE pull request. Returns (state, detail). Never touches a setting."""
    root, branch = ctx['root'], pr_branch(ctx['kit_sha'])
    paths = sorted(set(ctx['writes']) | set(ctx['deletes']))
    if not paths:
        return OK_UNCHANGED, 'nothing to change'
    steps = [['add', '-A', '--'] + paths,
             ['-c', 'user.name=kit-init', '-c', 'user.email=kit-init@users.noreply.github.com',
              'commit', '-q', '-m', 'kit init: wire this repository to the secure CI/CD kit at %s' % ctx['kit_sha'][:12]],
             ['push', '-q', '-u', 'origin', branch]]
    for s in steps:
        r = _git(root, *s)
        if r.returncode != 0:
            return PR_NOT_OPENED, 'git %s refused: %s' % (s[0] if s[0] != '-c' else 'commit', (r.stderr or r.stdout).strip()[-400:])
    env = dict(os.environ, GH_HOST=ctx['host'])
    body = os.path.join(root, *CHECKLIST.split('/'))
    view = subprocess.run(gh_cmd() + ['pr', 'view', branch, '--json', 'url,state', '-q', 'select(.state == "OPEN") | .url'],
                          cwd=root, env=env, capture_output=True, text=True)
    if view.returncode == 0 and view.stdout.strip():
        r = subprocess.run(gh_cmd() + ['pr', 'edit', branch, '--body-file', body], cwd=root, env=env,
                           capture_output=True, text=True)
        return (OK_PR, view.stdout.strip()) if r.returncode == 0 else (PR_NOT_OPENED, 'gh pr edit: ' + r.stderr.strip()[-400:])
    r = subprocess.run(gh_cmd() + ['pr', 'create', '--head', branch, '--title', 'Adopt the secure CI/CD kit (kit init)',
                                   '--body-file', body], cwd=root, env=env, capture_output=True, text=True)
    if r.returncode != 0:
        return PR_NOT_OPENED, 'gh pr create: ' + (r.stderr or r.stdout).strip()[-400:]
    return OK_PR, r.stdout.strip()


def load_previous(opts):
    """A re-run takes the answers of the last run for every option not given now."""
    prev = _read(os.path.abspath(opts.target), SETTINGS)
    if not prev:
        return opts
    try:
        s = json.loads(prev)
    except ValueError:
        return opts
    for k in ('with_triage', 'with_api', 'automerge', 'outside_landing_zone'):
        if not getattr(opts, k) and s.get(k):
            setattr(opts, k, True)
    for k in ('appsec_team', 'platform_team', 'dockerfile', 'site_dir'):
        if not getattr(opts, k) and s.get(k):
            setattr(opts, k, s[k])
    if opts.deploy == 'auto' and s.get('deploy_requested') in ('container', 'static', 'none'):
        opts.deploy = s['deploy_requested']
    if not opts.kit_repo:
        opts.kit_repo = (s.get('kit') or {}).get('repository')
    return opts


def parser():
    ap = argparse.ArgumentParser(description='kit init: wire a repository to the secure CI/CD kit.')
    ap.add_argument('--target', default='.', help='the repository to wire (default: the current directory)')
    ap.add_argument('--kit-repo', help='OWNER/REPO the kit is hosted in')
    ap.add_argument('--kit-sha', help='the kit commit to pin (default: this kit checkout\'s HEAD)')
    ap.add_argument('--deploy', default='auto', choices=['auto', 'container', 'static', 'none'])
    ap.add_argument('--dockerfile', help='the Dockerfile of the image this repository deploys')
    ap.add_argument('--site-dir', help='the BUILT static site\'s directory (e.g. dist)')
    ap.add_argument('--with-triage', action='store_true', help='add the Dependabot triage caller')
    ap.add_argument('--with-api', action='store_true', help='add the kit API caller')
    ap.add_argument('--automerge', action='store_true', help='you will turn on auto-merge (the checklist says how)')
    ap.add_argument('--outside-landing-zone', action='store_true', help='this repository deploys outside a landing zone')
    ap.add_argument('--appsec-team', help='@org/team for AppSec (CODEOWNERS, uat/prod reviewers)')
    ap.add_argument('--platform-team', help='@org/team for platform (CODEOWNERS, uat/prod reviewers)')
    ap.add_argument('--repo', help='ORG/REPO of the target (default: its origin remote)')
    ap.add_argument('--host', help='github.com or <tenant>.ghe.com (default: its origin remote)')
    ap.add_argument('--dry-run', action='store_true', help='write the files only: no branch, no commit, no PR')
    ap.add_argument('--detect', action='store_true', help='print what is detected and change nothing')
    ap.add_argument('--json', help='write the outcome as JSON to this file')
    ap.add_argument('--self-test', action='store_true')
    return ap


def report(state, ctx=None, refusal=None, detail=''):
    out = {'state': state}
    if refusal:
        out.update(what=refusal.what, fix=refusal.fix)
    if ctx:
        out.update(results=ctx.get('results', {}), preserved=ctx.get('preserved', []), conflicts=ctx.get('conflicts', []),
                   shape=ctx.get('shape'), stacks=sorted(ctx['found']['stacks']), detail=detail)
    return out


def main(argv=None):
    a = parser().parse_args(argv)
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML is needed (python3 -m pip install PyYAML)')
        return 2
    if a.self_test:
        return self_test()
    if not os.path.isdir(a.target):
        print('UNKNOWN: --target %s is not a directory' % a.target)
        return 2
    if a.detect:
        found = detect(os.path.abspath(a.target))
        shape, why = deploy_shape(found, a.deploy)
        print(json.dumps(dict(found, deploy_shape=shape, reason=why), indent=1))
        return 0
    out = None
    try:
        if not a.dry_run:
            r = _git(os.path.abspath(a.target), 'status', '--porcelain')
            if r.returncode != 0:
                raise Refusal(PR_NOT_OPENED, 'the target is not a git repository, so no pull request can be opened.',
                              'run with --dry-run to write the files only, or run inside a clone.')
            if r.stdout.strip():
                raise Refusal(DIRTY_TREE, 'the repository has uncommitted changes; kit init opens its pull request from a '
                              'clean tree so it commits only its own files.',
                              'commit or stash your changes (or run with --dry-run to write the files only).')
            a = load_previous(a)
            start_branch(os.path.abspath(a.target), pr_branch(resolve_pin(a)[1]))
        a = load_previous(a)
        ctx = apply(build(a), write=True)
        state, detail = (OK_WRITTEN, 'files written; no branch or PR (--dry-run)') if a.dry_run else open_pr(ctx)
        if not ctx['writes'] and not ctx['deletes'] and state != PR_NOT_OPENED:
            state = OK_UNCHANGED
        out = report(state, ctx, detail=detail)
    except Refusal as r:
        out = report(r.state, refusal=r)
    _print(out)
    if a.json:
        with io.open(a.json, 'w', encoding='utf-8') as fh:
            fh.write(json.dumps(out, indent=1))
    return 0 if out['state'] in (OK_WRITTEN, OK_PR, OK_UNCHANGED) else 1


def _print(out):
    st = out['state']
    if 'what' in out:
        print('%s [%s]' % (out['what'], st))
        print('  Fix: %s' % out['fix'])
        return
    for p, s in sorted(out.get('results', {}).items()):
        print('  %-48s %s' % (p, s))
    for c in out.get('conflicts', []):
        print('  RESOLVE: %s' % c)
    if out.get('preserved'):
        print('  kept as a person left them [%s]: %s' % (HUMAN_EDIT_PRESERVED, ', '.join(out['preserved'])))
    print('%s: deploy shape %s; %s. The steps only a person can do are in %s. [%s]' % (
        'Done' if st != PR_NOT_OPENED else 'Files written, pull request NOT opened', out.get('shape'),
        out.get('detail') or '', CHECKLIST, st))


def self_test():
    ok = True
    for url, want in (('https://github.com/o/r.git', ('github.com', 'o/r')),
                      ('git@acme.ghe.com:o/r.git', ('acme.ghe.com', 'o/r')),
                      ('https://x@acme.ghe.com/o/r', ('acme.ghe.com', 'o/r'))):
        if parse_remote(url) != want:
            print('SELF-TEST FAILED: parse_remote(%s) = %s' % (url, parse_remote(url)))
            ok = False
    if issuer_for('acme.ghe.com') != 'https://token.actions.acme.ghe.com' or issuer_for('ghes.example.com'):
        print('SELF-TEST FAILED: issuer_for')
        ok = False
    if not secret_leaks({'f': 'token: ghp_' + 'a' * 36}, {}) or secret_leaks({'f': 'clean'}, {'X_TOKEN': 'abcdefghij'}):
        print('SELF-TEST FAILED: secret_leaks')
        ok = False
    t = '  j:\n    uses: x\n    permissions:\n      contents: read  # c\n      issues: write\n    with:\n      a: b\n'
    if 'issues' in set_job_permissions(t, 'j', {'contents': 1}) or '# c' not in set_job_permissions(t, 'j', {'contents': 1}):
        print('SELF-TEST FAILED: set_job_permissions')
        ok = False
    print('PASS: kit_init self-test' if ok else 'FAIL: kit_init self-test')
    return 0 if ok else 2


if __name__ == '__main__':
    sys.exit(main())
