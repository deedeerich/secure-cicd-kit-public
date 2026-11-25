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
         a CODEOWNERS only when there is none (a complete default, or --codeowners customise for a draft); an
           existing one is NEVER changed, its lines are proposed in .kit/CODEOWNERS.proposed with overriding rules
           flagged (AppSec on .kit/, .kit/zone-readiness.json, .security/, the workflows,
           Dependabot config, Dockerfiles and IaC);
         .kit/environments.json (the environments SPEC: dev/test ungated, uat/prod with required reviewers
           from platform or security and self-review prevented, deployments from main only; each environment's
           `class`, which the deploy reads back, KDEC-042), .kit/settings.json (the answers, re-read on the next
           run; its approver_pools and app_team are read by the deploy at uat/prod) and .kit/ADOPTION_CHECKLIST.md
           (the PR body, with the `gh api -X PUT` and `gh variable set` commands).
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

THE HOST, DETECTED (owner 2026-11-07)
    github.com (personal repositories, default branch main) and <tenant>.ghe.com (work) are both supported. The
    host comes from --host, from GITHUB_SERVER_URL / GITHUB_API_URL when kit init runs in the repository's own
    workflow, from the origin remote and from the org overlay's `host`; the API base (api.<host>) and the OIDC
    issuer are derived from it. Another host is KIT_INIT_HOST_UNSUPPORTED; two
    sources that disagree are KIT_INIT_HOST_MISMATCH. The default branch is read, never assumed when it is known.

THE ORG OVERLAY, APPLIED ON DAY ONE (owner 2026-11-07; scripts/org_settings.py)
    When the kit copy (or --org-overlay DIR) holds overlays/<org>/kit-org-settings.json for the repository's owner,
    kit init applies it: the approver teams as the uat/prod reviewers and as the CODEOWNERS of the kit-governed
    paths (.github/workflows/, .kit/, id-mappings.json; KDEC-044), the adoption level (crawl unless the overlay
    says otherwise) and its crawl clock (4 weeks optimal, 8 advisory, 26 the hard maximum: escalation, never
    auto-promotion or auto-extension), the environment classes and Azure clouds, the ticket routing and tags, and
    small-team self-approval where it is declared and in force. Options may only TIGHTEN it
    (KIT_INIT_GOVERNED_SETTING_LOOSENED); an overlay that is invalid, ambiguous or still holds template
    placeholders is KIT_INIT_OVERLAY_INVALID. Without an overlay, kit init behaves as before.

THE CHECKLIST: WHAT, HOW, WHY (owner 2026-11-07)
    Every item says what to do, how (the exact command or click path) and why it matters, in plain English.

IDEMPOTENT, AND A HUMAN EDIT WINS
    .kit/kit-init.lock.json records the hash of every file it last wrote (a CODEOWNERS only when it wrote the whole file). On a
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
    KIT_INIT_HOST_MISMATCH          two host sources disagree
    KIT_INIT_OVERLAY_INVALID        the org overlay cannot be applied (invalid, ambiguous, placeholders)
    KIT_INIT_GOVERNED_SETTING_LOOSENED  an option loosens what the org overlay governs
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
import org_settings as OS  # noqa: E402

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
HOST_MISMATCH = 'KIT_INIT_HOST_MISMATCH'
OVERLAY_INVALID = 'KIT_INIT_OVERLAY_INVALID'
LOOSENED = 'KIT_INIT_GOVERNED_SETTING_LOOSENED'
LEVEL_RANK = {'crawl': 0, 'walk': 1, 'run': 2}
GOVERNED_PATHS = ('/.github/workflows/', '/.kit/', '/id-mappings.json')

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


def api_for(host):
    """The REST API base of a supported host (KDEC-027): api.<host>, for github.com and <tenant>.ghe.com alike."""
    return 'https://api.%s' % host if issuer_for(host) else None


def _host_of(url):
    m = re.match(r'^https?://([^/:]+)', (url or '').strip().lower())
    return m.group(1) if m else None


def _api_host(url):
    """GITHUB_API_URL -> the host it serves: api.<host> -> <host>."""
    h = _host_of(url) or ''
    return h[len('api.'):] if h.startswith('api.') else h


def resolve_host(opts, root, remote_host, overlay_host=None, environ=None):
    """-> {host, api_url, oidc_issuer, source}. Owner 2026-11-07: kit init detects the host -- github.com (the
    owner's personal repositories) and <tenant>.ghe.com (work) -- from --host, from GITHUB_SERVER_URL and
    GITHUB_API_URL when kit init runs in the target's own workflow (GITHUB_WORKSPACE is the target), from the
    origin remote, and from the org overlay's `host`. Any source naming another host is refused by name
    (KIT_INIT_HOST_UNSUPPORTED); two sources naming different hosts are KIT_INIT_HOST_MISMATCH."""
    environ = os.environ if environ is None else environ
    srcs = []
    if opts.host:
        srcs.append(('--host', opts.host.strip().lower()))
    ws = environ.get('GITHUB_WORKSPACE') or ''
    in_target = bool(ws) and os.path.isdir(ws) and os.path.normcase(os.path.abspath(ws)) == os.path.normcase(root)
    if in_target and environ.get('GITHUB_SERVER_URL'):
        srcs.append(('GITHUB_SERVER_URL', _host_of(environ['GITHUB_SERVER_URL'])))
    if in_target and environ.get('GITHUB_API_URL'):
        srcs.append(('GITHUB_API_URL', _api_host(environ['GITHUB_API_URL'])))
    if remote_host:
        srcs.append(('the origin remote', remote_host.lower()))
    if overlay_host:
        srcs.append(('the org overlay', overlay_host.lower()))
    for where, h in srcs:
        if not issuer_for(h):
            raise Refusal(HOST_UNSUPPORTED, '%s names the host %r, which is neither github.com nor a <tenant>.ghe.com '
                          'host.' % (where, h), 'kit init supports github.com and <tenant>.ghe.com (KDEC-027): pass '
                          '--host github.com or --host <tenant>.ghe.com, or fix %s.' % where)
    hosts = sorted({h for _w, h in srcs})
    if len(hosts) > 1:
        raise Refusal(HOST_MISMATCH, 'the host sources disagree: %s.' % '; '.join('%s says %s' % s for s in srcs),
                      'pass --host with the repository\'s real host, or correct the origin remote or the org overlay\'s '
                      'host, so the API base and the OIDC issuer are certain.')
    host = hosts[0] if hosts else 'github.com'
    source = ', '.join(w for w, _h in srcs) or 'assumed github.com (no --host, no remote, not run in the repository\'s workflow)'
    return {'host': host, 'api_url': api_for(host), 'oidc_issuer': issuer_for(host), 'source': source}


def default_branch(root, environ=None):
    """-> (branch, source). In the repository's own workflow, the event's repository.default_branch; else the
    remote's HEAD when known, else the checked-out branch, else main."""
    environ = os.environ if environ is None else environ
    ws = environ.get('GITHUB_WORKSPACE') or ''
    if ws and os.path.normcase(os.path.abspath(ws)) == os.path.normcase(root) and environ.get('GITHUB_EVENT_PATH'):
        try:
            with io.open(environ['GITHUB_EVENT_PATH'], encoding='utf-8') as fh:
                b = ((json.load(fh).get('repository') or {}).get('default_branch') or '').strip()
            if b:
                return b, 'the workflow event\'s repository.default_branch'
        except (OSError, ValueError):
            pass
    r = _git(root, 'symbolic-ref', '--quiet', '--short', 'refs/remotes/origin/HEAD')
    if r.returncode == 0 and r.stdout.strip().startswith('origin/'):
        return r.stdout.strip()[len('origin/'):], 'the origin remote\'s HEAD'
    r = _git(root, 'rev-parse', '--abbrev-ref', 'HEAD')
    b = r.stdout.strip() if r.returncode == 0 else ''
    if b and b != 'HEAD' and not b.startswith('kit-init/'):
        return b, 'the checked-out branch'
    return 'main', 'assumed (no remote HEAD, no branch checked out)'


def environments_spec(shape, opts, repo, host, gov=None):
    """gov: what the org overlay governs for this repository (reviewers, small team, clouds, branch)."""
    gov = gov or {}
    envs = []
    branch = gov.get('branch') or 'main'
    deploy_envs = [] if shape == 'none' else ['dev', 'test', 'uat', 'prod']
    reviewers = [{'type': 'Team', 'team': t} for t in (gov.get('reviewer_teams') or
                                                      [t for t in (opts.platform_team, opts.appsec_team) if t])]
    small = gov.get('small_team_state') == OS.ST_IN_FORCE
    if small and gov.get('app_team'):
        reviewers = [{'type': 'Team', 'team': gov['app_team']}]
    if not reviewers:
        # O-42b (owner 2026-11-07): no pools is not a refusal, but uat/prod always name SOMEONE, so a deploy
        # waits until a person says yes -- even the person who pushed.
        reviewers = [{'type': 'User', 'login': '<a reviewer who is not the deployer>'}]
    for name in deploy_envs:
        gated = name in ('uat', 'prod')
        e = {'name': name, 'tier': name, 'class': name,
             'required_reviewers': reviewers if gated else [],
             'prevent_self_review': gated and not small, 'wait_timer_minutes': 0,
             'deployment_branches': [branch],
             'why': ('a production tier: SMALL_TEAM_SELF_APPROVAL is in force (the org overlay\'s declared, time-boxed '
                     'weakening): the deploy still waits for a named reviewer, who may be the developer'
                     if gated and small else
                     'a production tier: a person from platform or security, never the deployer, approves every '
                     'release (same business day; ROLLOUT_PLAN.md section 3)') if gated else
                    'deployed on every merge to %s; no approval, so feedback is fast' % branch}
        cloud = (gov.get('clouds') or {}).get(name)
        if cloud is not None:
            e['azure_cloud'] = cloud
        envs.append(e)
    if shape == 'container':
        e = {'name': 'build', 'tier': None, 'required_reviewers': [], 'prevent_self_review': False,
             'wait_timer_minutes': 0, 'deployment_branches': [branch],
             'why': 'the build identity (AcrPush only) signs in here; never a deploy identity'}
        if (gov.get('clouds') or {}).get('build') is not None:
            e['azure_cloud'] = gov['clouds']['build']
        envs.append(e)
    if opts.with_api:
        envs.append({'name': 'ticketing', 'tier': None, 'required_reviewers': [], 'prevent_self_review': False,
                     'wait_timer_minutes': 0, 'deployment_branches': [branch],
                     'why': 'the tracker credentials live here, read only by the ticket reconciler'})
    oidc = issuer_for(host)
    return {'schema': 'kit-environments-spec/1', 'host': host, 'api_url': api_for(host), 'repository': repo,
            'default_branch': branch,
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
                                       ('not written: you chose to customise it (the draft is `%s`)' % CODEOWNERS_PROPOSED
                                        if (ctx.get('co') or {}).get('mode') == 'customise' else
                                        'kit init wrote a complete default; edit it freely (kit init then only proposes)')
                                       if path == ctx['co_rel']
                                       else 'kit init: re-running updates it until you edit it'))
    if ctx['preserved']:
        L += ['', '**Kept as you left them** (`KIT_INIT_HUMAN_EDIT_PRESERVED`): ' + ', '.join(
            '`%s`' % p for p in ctx['preserved']) + '. kit init never overwrites a person\'s edit. To take the '
            'kit\'s version of one, delete it and run kit init again (a CODEOWNERS is never replaced: copy the proposed lines).']
    for c in ctx['conflicts']:
        L += ['', '**Resolve before merging:** ' + c]
    L += ['', '## Only a person can do these', '',
          'Each step says **what** to do, **how** (the exact command), and **why it matters**, in plain words.', '']
    n = 0
    branch = spec.get('default_branch') or 'main'
    gov = ctx.get('gov') or {}

    def step(title, what, how, why):
        """One checklist item: WHAT to do, HOW (the exact command or click path), and WHY it matters."""
        nonlocal n
        n += 1
        body = ['**What:** ' + what, '', '**How:**'] + (how or ['Nothing to run.']) + ['', '**Why it matters:** ' + why]
        L.extend(['- [ ] **%d. %s**' % (n, title), ''] + ['  ' + b if b else '' for b in body] + [''])

    envs = spec['environments']
    if envs:
        how = ['', '```bash', 'export GH_HOST=%s   # this repository\'s host (API %s)' % (host, spec.get('api_url'))]
        teams = sorted({t['team'] for e in envs for t in e['required_reviewers'] if t.get('type') == 'Team'})
        users = sorted({t['login'] for e in envs for t in e['required_reviewers'] if t.get('type') == 'User'})
        for t in teams:
            slug = t.lstrip('@').split('/')[-1]
            how.append('%s_ID=$(gh api orgs/%s/teams/%s --jq .id)' % (_var(slug), owner, slug))
        for u in users:
            how.append('REVIEWER_ID=$(gh api users/%s --jq .id)   # replace %s with the login' % (u, u))
        for e in envs:
            rv = ','.join(('{"type":"Team","id":$%s_ID}' % _var(t['team'].lstrip('@').split('/')[-1]))
                          if t.get('type') == 'Team' else '{"type":"User","id":$REVIEWER_ID}'
                          for t in e['required_reviewers'])
            how.append('gh api -X PUT repos/%s/environments/%s --input - <<JSON' % (repo, e['name']))
            how.append('{"wait_timer":0,"prevent_self_review":%s,"reviewers":[%s],'
                       '"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}'
                       % ('true' if e['prevent_self_review'] else 'false', rv))
            how.append('JSON')
            how.append('gh api -X POST repos/%s/environments/%s/deployment-branch-policies -f name=%s -f type=branch'
                       % (repo, e['name'], branch))
        how += ['```', '', 'Check: `gh api repos/%s/environments/prod --jq \'.protection_rules\'` lists '
                '`required_reviewers` with at least one reviewer.' % repo]
        if users:
            how += ['', 'No approver team was given and the organisation has no pools in its overlay, so uat and prod '
                    'name one person as reviewer: someone who is **not** the person deploying (Prevent self-review is '
                    'on). A team of one with nobody else can only use the organisation\'s small-team mode, declared in '
                    'the org overlay ([SETTINGS_PRECEDENCE.md](%sdocs/adoption/SETTINGS_PRECEDENCE.md)).' % kit_url]
        small = gov.get('small_team_state') == OS.ST_IN_FORCE
        why = ('uat and prod are production. The deploy waits in the environment until a reviewer says yes, even '
               'for a push straight to %s, and before it signs in the kit reads these rules back and refuses an '
               'environment that is missing (ENVIRONMENT_NOT_FOUND), names no reviewer (ENVIRONMENT_REVIEWERS_ABSENT, '
               'ENVIRONMENT_REVIEWERS_EMPTY), lets the deployer approve (ENVIRONMENT_SELF_REVIEW_ALLOWED), has no '
               'platform or security reviewer when pools exist (ENVIRONMENT_APPROVER_POOL_MISSING) or only app-team '
               'reviewers (ENVIRONMENT_APPROVERS_ALL_APP_TEAM). dev and test stay ungated so feedback is fast. An '
               'environment name the kit cannot class is refused (ENVIRONMENT_UNCLASSED): add it to '
               '`.kit/environments.json` with its class.' % branch)
        if small:
            why += (' **SMALL_TEAM_SELF_APPROVAL is in force for this repository** (the org overlay\'s declared, '
                    'time-boxed weakening: %s), so Prevent self-review is off at uat and prod: the deploy still waits '
                    'for a named reviewer, and that reviewer may be the developer who pushed. The run summary and the '
                    'release record say so. "Prevent self-review" is a GitHub environment protection setting: it governs '
                    'only deployment approvals for jobs that target that environment, never branch protection, rulesets or '
                    'pull request reviews, and the kit never sets it (this checklist prints the command; the deploy reads '
                    'it back).' % (gov.get('small_team_why') or 'see the overlay'))
        step('Create the environments and their reviewers',
             'Create dev, test, uat and prod (and build/ticketing where listed) with the reviewers and branch rule '
             'from `.kit/environments.json`. Needs a repository admin.', how, why)
        if gov.get('governed'):
            step('Leave the approver variables unset (your organisation governs them)',
                 'Do not set `KIT_APPROVER_POOLS`, `KIT_APP_TEAM` or `KIT_SMALL_TEAM_SELF_APPROVAL` in this repository '
                 'or its environments.',
                 ['', 'Nothing to run. To check none is set: `gh variable list --repo %s` (and `--env <name>` per '
                  'environment) shows none of the three.' % repo],
                 'The approver pools, the app team and the small-team mode come from your organisation\'s overlay in '
                 'the kit repository (%s). GitHub lets a repository value shadow an organisation value, so a value set '
                 'here that loosens the overlay is refused (ENVIRONMENT_GOVERNED_SETTING_LOOSENED); one that only '
                 'narrows the pools is allowed. [SETTINGS_PRECEDENCE.md](%sdocs/adoption/SETTINGS_PRECEDENCE.md).'
                 % (gov.get('source') or 'overlays/<org>/kit-org-settings.json', kit_url))
        else:
            pools = [t for t in (o.platform_team, o.appsec_team) if t]
            how = ['', '```bash', "gh variable set KIT_APPROVER_POOLS --repo %s --body '%s'" % (repo, json.dumps(
                {'platform': [o.platform_team] if o.platform_team else [],
                 'security': [o.appsec_team] if o.appsec_team else []}, separators=(',', ':')))]
            if getattr(o, 'app_team', None):
                how.append("gh variable set KIT_APP_TEAM --repo %s --body '%s'" % (repo, o.app_team))
            how += ['```']
            step('Pin who may approve, as variables',
                 'Set the approver pools%s as repository variables.' % (' and the app team' if getattr(o, 'app_team', None) else ''),
                 how,
                 'A push to %s can edit `.kit/settings.json` but not a variable, so the variable is what the deploy '
                 'trusts first. %s An organisation with an overlay in its kit repository sets these there instead.'
                 % (branch, '' if pools else 'No pools were given, so the pool check stays off until you name them '
                    '(that is not a refusal: owner O-42b).'))
        subj = spec['oidc']['subjects']
        how = ['', '```bash', 'APP_ID=<the deploy identity\'s application (client) id>']
        envc = dict((e['name'], e.get('azure_cloud')) for e in envs)
        for env, s in sorted(subj.items()):
            if env == 'build':
                continue
            aud = 'api://AzureADTokenExchangeUSGov' if envc.get(env) == 'gov' else 'api://AzureADTokenExchange'
            how.append('az ad app federated-credential create --id "$APP_ID" --parameters \'{"name":"gh-%s-%s",'
                       '"issuer":"%s","subject":"%s","audiences":["%s"]}\''
                       % (repo.split('/')[-1], env, spec['oidc']['issuer'], s, aud))
        if 'build' in subj:
            aud = 'api://AzureADTokenExchangeUSGov' if envc.get('build') == 'gov' else 'api://AzureADTokenExchange'
            how += ['# the BUILD identity (AcrPush on this image repository only) is a different identity:',
                    'BUILD_APP_ID=<the build identity\'s application (client) id>',
                    'az ad app federated-credential create --id "$BUILD_APP_ID" --parameters \'{"name":"gh-%s-build",'
                    '"issuer":"%s","subject":"%s","audiences":["%s"]}\''
                    % (repo.split('/')[-1], spec['oidc']['issuer'], subj['build'], aud)]
        how += ['```', '', 'Check without deploying: run the kit\'s `verify-azure-oidc.yml` for each environment.']
        step('Add the OIDC federated credentials (no client secret, ever)',
             'Add one federated credential per environment on that environment\'s deploy identity (the landing zone '
             'vends it; outside one, the identity\'s owner adds them).', how,
             'The deploy signs in with a short-lived token and no stored secret. This host\'s issuer is `%s`; the '
             'subject must match character for character (it is case-sensitive). `AADSTS700213` means a subject does '
             'not match; `AADSTS70025` means none exists.' % spec['oidc']['issuer'])
        clouds = gov.get('clouds') or {}
        unset = sorted(e for e, c in clouds.items() if c == '')
        if clouds:
            step('Check which Azure cloud each environment signs in to',
                 'Read the `azure_cloud` of each environment in `.kit/environments.json`%s.' % (
                     '; ask the platform team to map %s in the org overlay' % ', '.join(unset) if unset else ''),
                 ['', 'Nothing to set in this repository: the org overlay decides (`azure_clouds`). Do not set '
                  '`KIT_CLOUD` at organisation level; a value that disagrees with the overlay is refused.'],
                 'Your organisation uses more than one Azure cloud (or declares one for all). An organisation-wide '
                 'value would send every tenant to the same cloud; the kit takes each environment\'s cloud from the '
                 'overlay and refuses an unmapped one (AZURE_CLOUD_UNSET_FOR_ENVIRONMENT) before it signs in.')
    if o.outside_landing_zone and envs:
        step('Readiness attestation (this repository deploys outside a landing zone)',
             'AppSec writes `.kit/zone-readiness.json` from the kit\'s `templates/zone-readiness.example.json` and '
             'approves it in a pull request.',
             ['', 'Copy the template, fill `environment`, `state`, `issued_by`, `issued_on`, `expires_on`, '
              '`evidence_ref`, and open a pull request; CODEOWNERS already makes AppSec its required reviewer.'],
             'Outside a landing zone only AppSec may say the platform is ready for a production release; without it a '
             'uat or prod deploy is refused before sign-in (READINESS_ATTESTATION_REFUSED).')
    names = secret_names(ctx)
    step('Set these variables and secrets (names only; kit init never sees a value)',
         'Create each variable and secret below, at the level the column says.',
         ['', '| name | kind | where | required |', '|---|---|---|---|'] +
         ['| `%s` | %s | %s | %s |' % row for row in names] +
         ['', 'Settings > Secrets and variables > Actions (or per environment), or `gh variable set NAME --repo %s` / '
          '`gh secret set NAME --repo %s` (add `--env <name>` for an environment).' % (repo, repo)],
         'The workflows read these names. Values never go into a file. GitHub uses the most specific level that has '
         'a value (environment, then repository, then organisation), so set each at the level shown: '
         '[SETTINGS_PRECEDENCE.md](%sdocs/adoption/SETTINGS_PRECEDENCE.md).' % kit_url)
    ad = ctx.get('adoption') or {}
    if ad:
        s = OS._date(ad.get('started_on'))
        import datetime as _dt
        when = (lambda w: (s + _dt.timedelta(weeks=w)).isoformat()) if s else (lambda w: '%d weeks after you start' % w)
        step('Know your adoption level and the crawl clock',
             'This repository starts at **%s** (%s).' % (ad.get('level'), ad.get('source')),
             ['', '- Crawl started: %s.' % (ad.get('started_on') or 'today'),
              '- Optimal: move on by **%s** (%d weeks).' % (when(ad['crawl_weeks_optimal']), ad['crawl_weeks_optimal']),
              '- Advisory: after **%s** (%d weeks) the summary flags it; prefer no more than two months.'
              % (when(ad['crawl_weeks_advisory']), ad['crawl_weeks_advisory']),
              '- Hard maximum: **%s** (%d weeks, six months): escalated to the platform lead.'
              % (when(ad['crawl_weeks_maximum']), ad['crawl_weeks_maximum']),
              '', 'Nothing promotes or extends by itself: moving to walk is a policy-register change a person signs '
              '(POLICY_REGISTER.md).'],
             'At crawl only secrets, known-exploited vulnerabilities and malicious packages block, so the team learns '
             'the results without being blocked by an old backlog. A deadline keeps report-only from becoming '
             'permanent (ROLLOUT_PLAN.md).')
    tr = ctx.get('ticket_routing')
    if tr:
        step('Check where tickets go',
             'Tickets go to %s project `%s`, tagged %s (from your organisation\'s overlay).' % (
                 tr.get('tracker', 'jira'), tr.get('project', '?'), ', '.join('`%s`' % t for t in tr.get('tags') or []) or 'nothing extra'),
             ['', 'Nothing to set unless the platform team gave this repository its own project: then '
              '`gh variable set JIRA_PROJECT --repo %s --body <KEY>`.' % repo],
             'One routing for the organisation means findings land where the security team triages them; a repository '
             'value changes it for this repository only.')
    if o.automerge:
        step('Turn on "Allow auto-merge" (you opted in)',
             'Allow GitHub to merge an armed pull request once every required check passes.',
             ['', '```bash', 'gh api -X PATCH repos/%s -F allow_auto_merge=true' % repo, '```'],
             'Without it the Dependabot triage cannot merge anything. Read the risks first: '
             '[AUTOMERGE_RISKS_AND_ROLLOUT.md](%sdocs/adoption/AUTOMERGE_RISKS_AND_ROLLOUT.md); auto-merge only '
             'helps once `security / Security gate` is required ([BRANCH_PROTECTION_SETTINGS.md](%sdocs/adoption/'
             'BRANCH_PROTECTION_SETTINGS.md)).' % (kit_url, kit_url))
    co = ctx.get('co') or {}
    teams_line = {'TEAMS_FROM_OVERLAY': 'the approver teams from your organisation\'s overlay: %s',
                  'TEAMS_FROM_OPTIONS': 'the teams you named: %s',
                  'TEAMS_LISTED': 'your organisation\'s teams, as the token listed them: %s',
                  'TEAMS_NOT_ESTABLISHED': 'NOT_ESTABLISHED: no overlay names them, none were given, and the teams were '
                                           'not listed (re-run with --list-teams and a token that can read them)%s'}[
        ctx.get('teams_state', 'TEAMS_NOT_ESTABLISHED')] % (', '.join('`%s`' % t for t in ctx.get('teams_seen') or []) or '')
    if co.get('mode') == 'proposed':
        how = ['', 'The proposed lines are in `%s`. Copy them to the **end** of `%s` (the last matching rule wins) in '
               'this pull request, or merge the owners into your own rules.' % (CODEOWNERS_PROPOSED, co['file'])]
        how += ['', 'Rules in your file that would decide a kit path instead (approximate matching; check each):'] + \
               ['- ' + f for f in co['findings']] if co['findings'] else ['', 'No rule in your file matches a kit path today.']
        if co.get('others_ignored'):
            how += ['', 'GitHub reads only the first CODEOWNERS it finds (`.github/`, then the root, then `docs/`); these '
                    'are ignored: %s.' % ', '.join('`%s`' % p for p in co['others_ignored'])]
        step('Review the proposed CODEOWNERS lines (your CODEOWNERS is never changed)',
             'Add the kit-governed lines to your existing `%s`, owned by %s.' % (co['file'], teams_line), how,
             'The approver teams must own `.github/workflows/`, `.kit/` and `id-mappings.json`, so no change to the '
             'pipeline or its settings merges without them (KDEC-044). kit init never overwrites a person\'s '
             'CODEOWNERS; a rule placed after the kit lines would silently take the path back.')
    elif co.get('mode') == 'customise':
        step('Customise the CODEOWNERS draft, then save it as `.github/CODEOWNERS`',
             'Edit `%s` (owned by %s) and save it as `.github/CODEOWNERS` in this pull request.' % (CODEOWNERS_PROPOSED, teams_line),
             ['', 'Keep the kit-governed lines at the **end** (the last matching rule wins). Re-running kit init with '
              '`--codeowners default` writes the draft as it is instead.'],
             'Until a CODEOWNERS exists, no team owns the pipeline files, and code-owner review requires nobody.')
    else:
        step('Check the CODEOWNERS kit init wrote',
             'Read `%s`: a complete default, owned by %s.' % (co.get('file', '.github/CODEOWNERS'), teams_line),
             ['', 'Edit it freely; from then on kit init only proposes its lines. To customise before it is written, '
              'run kit init with `--codeowners customise`.'],
             'The approver teams own the kit-governed paths, so a change to the pipeline needs their review once '
             'code-owner review is required.')
    inv = ctx.get('inventory') or {}
    how = ['', '| connector | kind | what it is for |', '|---|---|---|']
    managed = set(ctx['files']) | {LOCK, SETTINGS, ENV_SPEC, CHECKLIST, CODEOWNERS_PROPOSED}
    for wn, why in [w for w in inv.get('workflows') or [] if '.github/workflows/' + w[0] not in managed]:
        how.append('| `.github/workflows/%s` | file | %s |' % (wn, why))
    for kn in [k for k in inv.get('kit_files') or [] if '.kit/' + k not in managed]:
        how.append('| `.kit/%s` | file | %s |' % (kn, 'the readiness attestation (AppSec\'s)' if kn == 'zone-readiness.json'
                                                     else 'kit init\'s own record or spec'))
    for en in inv.get('environments') or []:
        how.append('| `%s` | environment | %s |' % (en, ENV_PURPOSE.get(en, 'not one the kit names; classify it in '
                                                                         '`.kit/environments.json` if it deploys')))
    for kind in ('secrets', 'variables'):
        for cn in inv.get(kind) or []:
            how.append('| `%s` | %s | %s |' % (cn, kind[:-1], CONNECTOR_PURPOSE.get(
                cn, 'a kit setting: see SETTINGS_PRECEDENCE.md' if cn.startswith(('KIT_', 'JIRA_', 'TICKET_', 'AZURE_'))
                else 'not a kit name; the kit does not read it')))
    if len(how) == 3:
        how.append('| (none found) | | |')
    how += ['', 'Environments, secrets and variables: %s. Names only, never a value. What to keep, rename or remove when '
            'the repository was wired by hand: [MIGRATE_FROM_HAND_WIRED.md](%sdocs/adoption/MIGRATE_FROM_HAND_WIRED.md).'
            % (inv.get('api_why', 'not listed'), kit_url)]
    step('Know what is already wired (the connectors kit init can see)',
         'Read the inventory below: every workflow and `.kit` file it found%s, and what each is for.' % (
             ', and the environment, secret and variable names' if inv.get('api') in ('LISTED', 'PARTLY_LISTED') else ''),
         how,
         'A repository wired by hand keeps old callers and settings; one the kit no longer reads, or one at the wrong '
         'level, is confusing at best and shadows the organisation\'s value at worst.')
    if any(t.startswith('@YOUR_ORG/') for t in ctx['teams_written']):
        step('Name the real teams in CODEOWNERS',
             'Replace the `@YOUR_ORG/...` placeholders in the kit-init block of CODEOWNERS.',
             ['', 'Re-run with `--appsec-team @<org>/<team> --platform-team @<org>/<team>`, or edit the block (kit init '
              'then keeps your edit).'],
             'A placeholder team owns nothing, so changes to the workflows and `.kit/` would need no review.')
    step('Make the security check and code-owner review required on %s (after the first green run)' % branch,
         'Require `security / Security gate` and code-owner review on `%s`.' % branch,
         ['', 'Settings > Rules > Rulesets, or `gh api -X POST repos/%s/rulesets --input ruleset.json` with the '
          'ruleset in [BRANCH_PROTECTION_SETTINGS.md](%sdocs/adoption/BRANCH_PROTECTION_SETTINGS.md), section 3.'
          % (repo, kit_url)],
         'Until it is required, a red gate does not stop a merge, and the approver teams\' CODEOWNERS lines on '
         '`.github/workflows/`, `.kit/` and `id-mappings.json` are only advice. Not before the first green run: a '
         'required check that has never passed blocks every pull request.')
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
        if (ctx.get('gov') or {}).get('clouds'):
            rows.append(('KIT_CLOUD', 'variable', 'none: the org overlay decides each environment\'s cloud',
                         'no (a value that disagrees with the overlay is refused)'))
        else:
            rows.append(('KIT_CLOUD', 'variable', 'each deploy environment (never organisation-wide)',
                         'only for Azure Government (`gov`)'))
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


# ── connectors: what a repository already has wired for the kit (owner, 2026-11-07) ─────────────────
# "Connectors" are everything a repository needs wired for the kit: secrets, variables, environments and files
# (mostly the caller workflows). kit init inventories the ones it can see, by NAME only (never a value), and says
# what each is for. Workflow and .kit files are read from the tree; environment, secret and variable NAMES only
# with --inventory-api and a token that may list them; otherwise the checklist says they were not listed.
CONNECTOR_PURPOSE = {
    'AZURE_CLIENT_ID': 'the deploy (or build) identity of an environment, federated: no secret',
    'AZURE_TENANT_ID': 'the Entra tenant the identity signs in to', 'AZURE_SUBSCRIPTION_ID': 'the target subscription',
    'KIT_RESOURCE_GROUP': 'the deploy target (vended by the landing zone)', 'KIT_APP_NAME': 'the deploy target (vended)',
    'KIT_ENVIRONMENT_TIER': 'the environment\'s tier (vended)', 'KIT_CLOUD': 'the Azure cloud (commercial or gov), per environment',
    'KIT_ACR_LOGIN_SERVER': 'the registry the build pushes to', 'KIT_IMAGE_REPOSITORY': 'the image name',
    'KIT_E2E_TEST_COMMAND': 'the end-to-end tests that make a build promotable', 'KIT_STATIC_BUILD_COMMAND': 'the static site build',
    'KIT_APPROVER_POOLS': 'who may approve uat/prod (governed by the org overlay when there is one)',
    'KIT_APP_TEAM': 'the app team, never the only uat/prod approver (governed by the org overlay when there is one)',
    'KIT_SMALL_TEAM_SELF_APPROVAL': 'NOT a repository setting: only the org overlay declares small-team mode (remove it)',
    'JIRA_HOST': 'the Jira site (either form)', 'JIRA_PROJECT': 'the project key in PR descriptions and tickets',
    'JIRA_TOKEN': 'the Jira service account\'s token (ticketing environments only)',
    'JIRA_EMAIL': 'basic auth only; empty with bearer', 'SEMGREP_APP_TOKEN': 'optional: Semgrep\'s own dashboard',
    'KIT_INIT_TOKEN': 'lets the kit-init button open its pull request', 'SONAR_TOKEN': 'the overlay\'s Sonar step and the external findings pull',
    'SONAR_HOST_URL': 'the SonarQube URL', 'ZAP_TARGET': 'the test site the ZAP baseline scans',
    'DEPENDABOT_METADATA_TOKEN': 'optional: Dependabot alert linkage', 'DEPENDABOT_COMMAND_TOKEN': 'only if Dependabot ignores the bot (R-23)',
    'KIT_ZONE_READINESS': 'the zone readiness the landing zone vends (never self-set at uat/prod)',
    'KIT_HANDOFF_ISSUER': 'the landing zone\'s marker (written by the landing zone only)',
}
ENV_PURPOSE = {'dev': 'deploys on every merge, ungated', 'test': 'deploys on every merge, ungated',
               'uat': 'production tier: required reviewers', 'prod': 'production tier: required reviewers, promotion only',
               'build': 'the build identity (AcrPush only)', 'ticketing': 'the Jira credentials for real tickets',
               'ticketing-test': 'the Jira credentials for test tickets', 'external-findings-review': 'the security approval before Sonar/Aikido tickets'}


def workflow_purpose(name, text, kit_repo):
    tpl = os.path.join(KIT_ROOT, 'templates', name)
    calls = re.findall(r'uses:\s*([\w.-]+/[\w.-]+)/\.github/workflows/([\w.-]+)@(\S+)', text or '')
    kit = [c for c in calls if c[1].startswith('reusable-')]
    if text and text.startswith('# kit-init: generated'):
        return 'written by kit init'
    if kit:
        pins = sorted({c[2][:12] for c in kit})
        return 'calls the kit (%s, pinned at %s)%s' % (', '.join(sorted({c[1] for c in kit})[:3]), ', '.join(pins),
                                                       '; the same name as the kit template' if os.path.isfile(tpl) else '')
    if os.path.isfile(tpl):
        return 'the same name as a kit template, but it calls no kit reusable workflow'
    return 'not a kit workflow (kit init leaves it alone)'


def inventory(root, opts, repo, host, kit_repo):
    """-> dict of what is already wired, names only."""
    inv = {'workflows': [], 'kit_files': [], 'api': 'NOT_LISTED', 'environments': [], 'secrets': [], 'variables': [],
           'api_why': 'not listed: run kit init with --inventory-api and a token that can read the repository\'s settings, '
                      'or list them yourself (gh secret list, gh variable list, gh api repos/%s/environments)' % repo}
    wf = os.path.join(root, '.github', 'workflows')
    if os.path.isdir(wf):
        for n in sorted(os.listdir(wf)):
            if n.endswith(('.yml', '.yaml')):
                inv['workflows'].append((n, workflow_purpose(n, _read(root, '.github/workflows/' + n), kit_repo)))
    kd = os.path.join(root, '.kit')
    if os.path.isdir(kd):
        inv['kit_files'] = sorted(n for n in os.listdir(kd) if os.path.isfile(os.path.join(kd, n)))
    if getattr(opts, 'inventory_api', False) and '/' in repo and not repo.startswith('<'):
        env = dict(os.environ, GH_HOST=host)
        got, bad = {}, []
        for key, path, jq in (('environments', 'repos/%s/environments' % repo, '.environments[].name'),
                              ('secrets', 'repos/%s/actions/secrets' % repo, '.secrets[].name'),
                              ('variables', 'repos/%s/actions/variables' % repo, '.variables[].name')):
            r = subprocess.run(gh_cmd() + ['api', path, '--jq', jq], cwd=root, env=env, capture_output=True, text=True)
            if r.returncode == 0:
                got[key] = sorted(x for x in r.stdout.split() if x)
            else:
                bad.append(key)
        for k, v in got.items():
            inv[k] = v
        inv['api'] = 'LISTED' if not bad else ('PARTLY_LISTED' if got else 'NOT_ESTABLISHED')
        inv['api_why'] = ('listed with the token kit init ran with' if not bad else
                          'the token could not list %s (it needs repository administration read); NOT_ESTABLISHED for '
                          'those' % ', '.join(bad))
    return inv


def list_org_teams(owner, host):
    """-> (team slugs, state). Read-only; only with --list-teams (the kit-init button passes it)."""
    r = subprocess.run(gh_cmd() + ['api', 'orgs/%s/teams' % owner, '--jq', '.[].slug'], env=dict(os.environ, GH_HOST=host),
                       capture_output=True, text=True)
    if r.returncode != 0:
        return [], 'TEAMS_NOT_ESTABLISHED'
    return sorted(x for x in r.stdout.split() if x), 'TEAMS_LISTED'


# ── CODEOWNERS block ─────────────────────────────────────────────────────────────────────────────
def codeowners_block(found, appsec, platform, governed=None):
    """governed: (paths, owners) from the org overlay (KDEC-044): the approver teams own the kit-governed paths."""
    paths, owners = governed or (GOVERNED_PATHS, None)
    own = ' '.join(owners) if owners else '%s %s' % (platform, appsec)
    rows = [('/.kit/', own if '/.kit/' in paths else appsec), ('/.kit/zone-readiness.json', appsec),
            ('/.security/', appsec),
            ('/.github/workflows/', own), ('/.github/actions/', '%s %s' % (platform, appsec)),
            ('/.github/dependabot.yml', '%s %s' % (platform, appsec)), ('/.github/CODEOWNERS', appsec),
            ('/CODEOWNERS', appsec), ('/id-mappings.json', own)]
    for p in paths:
        if p not in [r[0] for r in rows]:
            rows.append((p, own))
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


CODEOWNERS_PLACES = ('.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS')   # GitHub's search order
CODEOWNERS_PROPOSED = '.kit/CODEOWNERS.proposed'
CODEOWNERS_DEFAULT_HEAD = (
    '# CODEOWNERS written by kit init as a complete default (owner, 2026-11-07): nobody customised one, so the\n'
    '# organisation\'s approver teams own the kit-governed paths. It is yours now: edit it freely; kit init keeps\n'
    '# an edited CODEOWNERS and only proposes its lines (.kit/CODEOWNERS.proposed). The LAST matching rule wins.\n\n')


def _co_regex(pat):
    """A CODEOWNERS pattern (gitignore-like) -> a regex over a repository path without a leading slash."""
    anchored = pat.startswith('/')
    p = pat.lstrip('/')
    if p.endswith('/'):
        p += '**'
    out, i = '', 0
    while i < len(p):
        if p[i:i + 2] == '**':
            out, i = out + '.*', i + 2
        elif p[i] == '*':
            out, i = out + '[^/]*', i + 1
        elif p[i] == '?':
            out, i = out + '[^/]', i + 1
        else:
            out, i = out + re.escape(p[i]), i + 1
    if not anchored and '/' not in p.rstrip('*').rstrip('/'):
        out = '(?:.*/)?' + out
    return re.compile('^' + out + '(?:/.*)?$')


def codeowners_findings(existing, block):
    """-> [finding]. For each kit line, the existing rules that also match its path. The LAST matching rule wins,
    so a rule placed after the kit lines decides instead of them; and the kit lines placed after an existing rule
    replace its owners for that path. Approximate (gitignore-like matching); said so in the checklist."""
    rules = []
    for n, ln in enumerate(existing.split('\n'), 1):
        s = ln.strip()
        if not s or s.startswith('#'):
            continue
        parts = s.split()
        rules.append((n, parts[0], ' '.join(parts[1:])))
    out = []
    for ln in block.split('\n'):
        if not ln.startswith('/'):
            continue
        kp = ln.split()[0]
        sample = kp.lstrip('/') + ('kit-path-probe.yml' if kp.endswith('/') else '')
        sample = sample.replace('*', 'x')
        hits = [(n, pat, own) for n, pat, own in rules if _co_regex(pat).match(sample)]
        if hits:
            n, pat, own = hits[-1]
            out.append('line %d `%s %s` also matches `%s` and decides it today; put the kit line AFTER it (at the end '
                       'of the file) so the approver teams own the path, or merge the owners' % (n, pat, own or '(no owner)', kp))
    return out


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
    r = _git(root, 'remote', 'get-url', 'origin')
    remote_host, remote_repo = parse_remote(r.stdout) if r.returncode == 0 else (None, None)
    repo = opts.repo or remote_repo or '<ORG>/<REPO>'
    owner = repo.split('/')[0] if '/' in repo and not repo.startswith('<') else ''
    # The org overlay (owner 2026-11-07): from --org-overlay, else this kit copy's overlays/<org>/.
    odoc, ostate, osrc, owhy = OS.load(os.path.abspath(opts.org_overlay or KIT_ROOT), owner) if owner else (
        None, OS.ABSENT, '', 'the repository\'s owner is unknown, so no org overlay is looked up')
    if ostate in (OS.INVALID, OS.AMBIGUOUS) or (ostate == OS.APPLIED and OS.placeholders(odoc)):
        raise Refusal(OVERLAY_INVALID, 'the org overlay for %r cannot be applied: %s.' % (
            owner, owhy if ostate != OS.APPLIED else 'template placeholders are still at %s' % ', '.join(OS.placeholders(odoc)[:4])),
            'run python3 scripts/org_settings.py validate %s in the kit repository and fix what it names.' % (osrc or 'overlays/<org>/kit-org-settings.json'))
    hostinfo = resolve_host(opts, root, remote_host, (odoc or {}).get('host'))
    host = hostinfo['host']
    gov = governance(opts, odoc, ostate, osrc, repo)
    branch, branch_src = default_branch(root)
    gov['branch'] = branch
    inv = inventory(root, opts, repo, host, kit_repo)
    if gov.get('reviewer_teams'):
        teams_state, teams_seen = 'TEAMS_FROM_OVERLAY', list(gov['reviewer_teams'])
    elif opts.platform_team or opts.appsec_team:
        teams_state, teams_seen = 'TEAMS_FROM_OPTIONS', [t for t in (opts.platform_team, opts.appsec_team) if t]
    elif getattr(opts, 'list_teams', False) and owner:
        slugs, teams_state = list_org_teams(owner, host)
        teams_seen = ['@%s/%s' % (owner, s) for s in slugs]
    else:
        teams_state, teams_seen = 'TEAMS_NOT_ESTABLISHED', []
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
    teams = (opts.appsec_team or gov.get('security_team') or '@YOUR_ORG/appsec',
             opts.platform_team or gov.get('platform_team') or '@YOUR_ORG/platform')
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
    if shape != 'none' and odoc and odoc.get('azure_clouds'):
        names = ['dev', 'test', 'uat', 'prod'] + (['build'] if shape == 'container' else [])
        gov['clouds'] = dict((n, OS.azure_cloud(odoc, ostate, repo, n, '', '')[0]) for n in names)
    spec = environments_spec(shape, opts, repo, host, gov)
    files[ENV_SPEC] = json.dumps(spec, indent=2) + '\n'
    adoption = gov['adoption']
    governed = bool(gov.get('governed'))
    settings = {'schema': 'kit-settings/1', 'kit': {'repository': kit_repo, 'sha': kit_sha, 'pin_source': pin_source},
                'host': hostinfo, 'default_branch': {'name': branch, 'source': branch_src},
                'deploy': shape, 'deploy_requested': opts.deploy, 'dockerfile': dockerfile, 'site_dir': opts.site_dir, 'with_triage': bool(opts.with_triage),
                'with_api': bool(opts.with_api), 'automerge': bool(opts.automerge),
                'outside_landing_zone': bool(opts.outside_landing_zone),
                'appsec_team': opts.appsec_team, 'platform_team': opts.platform_team,
                'app_team': None if governed else (opts.app_team or None),
                'approver_pools': {'platform': [], 'security': []} if governed else
                                  {'platform': [opts.platform_team] if opts.platform_team else [],
                                   'security': [opts.appsec_team] if opts.appsec_team else []},
                'org_overlay': {'state': ostate, 'source': osrc or None},
                'rung': adoption['level'], 'adoption': adoption,
                'note': 'kit init re-reads these answers on its next run. The kit\'s deploy reads two '
                'of them at uat and prod (KDEC-042): approver_pools (a reviewer must come from one) and app_team (the '
                'reviewers must not all be on it); vars.KIT_APPROVER_POOLS and vars.KIT_APP_TEAM win over them. With an '
                'org overlay those are governed there and a repository value may only tighten (SETTINGS_PRECEDENCE.md). '
                'The rung the gate obeys comes from the policy register, crawl when there is none.'}
    if gov.get('ticket_routing'):
        settings['ticket_routing'] = gov['ticket_routing']
    files[SETTINGS] = json.dumps(settings, indent=2) + '\n'
    co_gov = (tuple((odoc.get('codeowners') or {}).get('governed_paths') or GOVERNED_PATHS),
              (odoc.get('codeowners') or {}).get('owners') or gov.get('reviewer_teams') or
              ([gov['app_team']] if gov.get('app_team') else None)) if governed else None
    return {'root': root, 'opts': opts, 'kit_repo': kit_repo, 'kit_sha': kit_sha, 'found': found, 'shape': shape,
            'shape_reason': why, 'host': host, 'repo': repo, 'spec': spec, 'files': files, 'teams': teams,
            'teams_written': list(teams), 'gov': gov, 'adoption': adoption, 'ticket_routing': gov.get('ticket_routing'),
            'hostinfo': hostinfo, 'codeowners': codeowners_block(found, teams[0], teams[1], co_gov),
            'inventory': inv, 'teams_state': teams_state, 'teams_seen': teams_seen}


def governance(opts, odoc, ostate, osrc, repo):
    """What the org overlay governs for `repo`, with every option checked: options may only TIGHTEN it
    (KIT_INIT_GOVERNED_SETTING_LOOSENED otherwise). -> dict for environments_spec, the checklist and settings."""
    import datetime
    prev_start = getattr(opts, 'adoption_started_on', None)
    today = datetime.date.today().isoformat()
    gov = {'governed': ostate == OS.APPLIED, 'source': osrc, 'state': ostate}
    ad = OS.adoption(odoc, repo) if ostate == OS.APPLIED else dict(OS.ADOPTION_DEFAULTS, source='kit default (crawl)')
    level = ad['default_level']
    want = getattr(opts, 'adoption_level', None)
    if want:
        if LEVEL_RANK[want] < LEVEL_RANK[level]:
            raise Refusal(LOOSENED, '--adoption-level %s is below the level the org overlay sets for %s (%s).' % (want, repo, level),
                          'leave out --adoption-level, or choose %s or stricter.' % level)
        if want != level:
            ad['source'] = '--adoption-level %s (stricter than %s)' % (want, ad['source'])
        level = want
    gov['adoption'] = {'level': level, 'source': ad['source'], 'started_on': prev_start or today,
                       'crawl_weeks_optimal': ad['crawl_weeks_optimal'], 'crawl_weeks_advisory': ad['crawl_weeks_advisory'],
                       'crawl_weeks_maximum': ad['crawl_weeks_maximum'],
                       'rule': 'nothing promotes or extends by itself; past the maximum the platform lead decides'}
    if ostate != OS.APPLIED:
        return gov
    pools = (odoc.get('approver_pools') or {})
    plat, sec = list(pools.get('platform') or []), list(pools.get('security') or [])
    allowed = set(OS.norm(t) for t in plat + sec)
    for flag, t in (('--platform-team', opts.platform_team), ('--appsec-team', opts.appsec_team)):
        if t and allowed and OS.norm(t) not in allowed:
            raise Refusal(LOOSENED, '%s %s is not one of the approver teams the org overlay names (%s).' % (
                flag, t, ', '.join(plat + sec)), 'leave out %s: kit init takes the teams from the org overlay.' % flag)
    gov['platform_team'] = plat[0] if plat else None
    gov['security_team'] = sec[0] if sec else None
    gov['reviewer_teams'] = plat + sec
    at = OS.app_team(odoc, repo)
    if at and getattr(opts, 'app_team', None) and OS.norm(opts.app_team) != at['team']:
        raise Refusal(LOOSENED, '--app-team %s is not the app team the org overlay names for %s (@%s).' % (
            opts.app_team, repo, at['team']), 'leave out --app-team.')
    e = (odoc.get('app_teams') or {}).get(repo) or {}
    gov['app_team'] = e.get('team')
    st, _rec, why = OS.small_team(odoc, repo, today)
    gov['small_team_state'], gov['small_team_why'] = st, why
    gov['ticket_routing'] = odoc.get('ticket_routing')
    return gov


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
    # CODEOWNERS (owner, 2026-11-07): look in all three places GitHub reads (it uses the FIRST it finds) and NEVER
    # overwrite a person's file. None: write a complete default from the org's approver teams, or, with
    # --codeowners customise, a draft for the person to finish. One exists: propose the kit lines in the pull
    # request (.kit/CODEOWNERS.proposed) and flag every existing rule that would decide a kit path instead.
    present = [p for p in CODEOWNERS_PLACES if _read(root, p) is not None]
    co_rel = present[0] if present else '.github/CODEOWNERS'
    wrapped = '%s\n%s\n%s\n' % (BLOCK_BEGIN, ctx['codeowners'], BLOCK_END)
    default_text = CODEOWNERS_DEFAULT_HEAD + wrapped
    cur = _read(root, co_rel)
    legacy = co_rel + '#kit-init-block'   # a file an earlier kit init created holding only its block
    ours = cur is not None and ((co_rel in owned and sha(cur) == owned[co_rel]) or
                                (legacy in owned and cur == wrapped and sha(ctx['codeowners']) == owned[legacy]) or
                                cur == default_text)
    co = {'present': present, 'mode': None, 'findings': [], 'others_ignored': present[1:], 'file': co_rel}
    if cur is None:
        mode = getattr(ctx['opts'], 'codeowners', None) or 'default'
        co['mode'] = mode
        if mode == 'customise':
            _merge_file(root, CODEOWNERS_PROPOSED, default_text, owned, results, preserved, writes)
            results[co_rel] = 'not written: you chose to customise it (the draft is %s)' % CODEOWNERS_PROPOSED
        else:
            writes[co_rel], results[co_rel] = default_text, 'created (a complete default from the org\'s approver teams)'
    elif ours:
        co['mode'] = 'default'
        if cur != default_text:
            writes[co_rel], results[co_rel] = default_text, 'updated (kit init wrote it and nobody edited it)'
        else:
            results[co_rel] = 'unchanged'
    else:
        co['mode'] = 'proposed'
        co['findings'] = codeowners_findings(cur, ctx['codeowners'])
        if BLOCK_BEGIN in cur:
            co['findings'].insert(0, 'the file holds a kit-init block from an earlier run; replace it with the proposal')
        preserved.append(co_rel + ' (your CODEOWNERS: kit init never changes it; its lines are proposed in %s)'
                         % CODEOWNERS_PROPOSED)
        results[co_rel] = 'kept (a person\'s CODEOWNERS); kit lines proposed'
        _merge_file(root, CODEOWNERS_PROPOSED, wrapped, owned, results, preserved, writes)
    if co['mode'] != 'default':
        ctx['teams_written'] = [] if co['mode'] == 'proposed' and not any(
            t.startswith('@YOUR_ORG/') for t in ctx['teams_written']) else ctx['teams_written']
    ctx.update(results=results, preserved=preserved, conflicts=conflicts, co_rel=co_rel, co=co)
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
        new_owned[rel] = sha(text)   # a CODEOWNERS kit init wrote is recorded whole; a person's is never written
    new_owned.pop(legacy, None)
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
    for k in ('appsec_team', 'platform_team', 'app_team', 'dockerfile', 'site_dir'):
        if not getattr(opts, k) and s.get(k):
            setattr(opts, k, s[k])
    if opts.deploy == 'auto' and s.get('deploy_requested') in ('container', 'static', 'none'):
        opts.deploy = s['deploy_requested']
    ad = s.get('adoption') if isinstance(s.get('adoption'), dict) else {}
    if ad.get('started_on') and not getattr(opts, 'adoption_started_on', None):
        opts.adoption_started_on = ad['started_on']   # the crawl clock runs from the first run, never restarts
    if not getattr(opts, 'adoption_level', None) and str(ad.get('source', '')).startswith('--adoption-level') and \
            ad.get('level') in LEVEL_RANK:
        opts.adoption_level = ad['level']
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
    ap.add_argument('--app-team', help='@org/team that writes this app: never the only uat/prod approvers (KDEC-042)')
    ap.add_argument('--repo', help='ORG/REPO of the target (default: its origin remote)')
    ap.add_argument('--host', help='github.com or <tenant>.ghe.com (default: detected from the workflow, the origin '
                    'remote or the org overlay; disagreeing sources are refused)')
    ap.add_argument('--org-overlay', help='a directory holding overlays/<org>/kit-org-settings.json (default: this kit '
                    'copy): the org\'s governed settings, applied on day one')
    ap.add_argument('--codeowners', choices=['default', 'customise'],
                    help='with no CODEOWNERS in the repository: write a complete default from the org\'s approver '
                    'teams (default), or a draft for you to customise (.kit/CODEOWNERS.proposed). An existing '
                    'CODEOWNERS is never changed: its lines are proposed. Asked interactively when not given.')
    ap.add_argument('--list-teams', action='store_true',
                    help='list the organisation\'s teams (read-only, needs a token that may) to help name CODEOWNERS')
    ap.add_argument('--inventory-api', action='store_true',
                    help='also list environment, secret and variable NAMES with the token (never a value)')
    ap.add_argument('--adoption-level', choices=['crawl', 'walk', 'run'],
                    help='start stricter than the org overlay\'s level (crawl by default); never lower')
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
        root_abs = os.path.abspath(a.target)
        if not a.codeowners and not any(_read(root_abs, p) is not None for p in CODEOWNERS_PLACES) and \
                sys.stdin.isatty() and sys.stdout.isatty():
            ans = input('This repository has no CODEOWNERS. Write a complete default from your organisation\'s '
                        'approver teams [d], or a draft for you to customise first [c]? (d/c, default d): ').strip().lower()
            a.codeowners = 'customise' if ans.startswith('c') else 'default'
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
