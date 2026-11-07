#!/usr/bin/env python3
"""`kit survey`: what is ALREADY running in an organisation, compared with what the kit does, read-only.

WHY THIS EXISTS (owner, 2026-11-07)
    "A scanner of what's already running in the org first, so it can identify if there's something that's
    being done better or needs to be adopted, and we adopt it through the overlays." And: the adoption
    inventory should show how much of the estate the kit supports and secures, and where a repository turned
    the kit off, what the pain point was. An organisation that already runs CodeQL on a schedule, signs its
    commits or waits a timer before production is doing something the kit should learn from, not overwrite.

WHAT IT READS (GET only; the client has no other method, and the stand-in proof refuses any other)
    Per repository of an organisation (or of a user account): the workflow files and the actions they use
    (pinned by commit SHA or not), the scanners they already run (CodeQL, Semgrep, gitleaks, Trivy,
    SonarQube, Snyk, Aikido, Scorecard, ... by action name or command), the workflows' API state (a workflow
    disabled in the UI), branch protection and rulesets, environments and their protection rules, CODEOWNERS,
    the Dependabot configuration, Actions secret and variable NAMES (a variable's value is dropped the moment
    it is read; a secret's value is never returned by GitHub and never asked for), the kit callers and the kit
    commit they pin, the rung the repository registered, the deploy targets the workflows imply, and the
    history of .github/workflows (to find a kit caller that was removed or switched off, and why).

WHAT IT WRITES (outside the kit by default: the outputs name private repositories)
    KIT_SURVEY.csv / KIT_SURVEY.md          one row per repository
    KIT_SURVEY_COMPARISON.md                per kit capability: KIT_BETTER, ORG_BETTER, EQUIVALENT, ORG_ONLY,
                                            KIT_ONLY or GAP, the evidence row, credit for what the org does
                                            better, an "adopt via overlay" proposal and how to do it by hand
    KIT_ADOPTION_INVENTORY.md               ADOPTED (rung) / PARTIAL / TURNED_OFF / NEVER per repository, the
                                            turn-off evidence and stated reason (or REASON_NOT_RECORDED), the
                                            pain point, and the percentages with their denominators
    kit-survey.json                         everything above, machine-readable

THE HOST (KDEC-027)
    --host github.com | <tenant>.ghe.com names the host; the API is api.<host>. GITHUB_API_URL or GH_HOST
    name it when --host does not; nothing names it -> SURVEY_HOST_NOT_NAMED (never a default host). An
    --api-url that is not the named host's API (a loopback stand-in excepted) is SURVEY_HOST_MISMATCH before
    any request, and so is a repository the API answers for on a DIFFERENT host, or a next-page link to
    another host: the token goes to the host that issued it and nowhere else.

NEVER "NOTHING THERE" WHEN IT COULD NOT LOOK
    A 403/401 is NOT_ESTABLISHED, never "no branch protection". A repository with no kit caller is NEVER only
    when its whole workflow history was read; a history cut short by --history is NOT_ESTABLISHED.

USAGE
    python3 scripts/kit_survey.py --owner ORG [--host github.com|<tenant>.ghe.com] [--api-url URL]
        [--kit-repo NAME ...] [--repo NAME ...] [--history 200] [--max-repos 1000] [--org-overlay NAME]
        --out DIR
    The token is GH_TOKEN, else GITHUB_TOKEN (read-only: metadata, contents, actions, administration,
    secrets and variables READ; a missing permission shows as NOT_ESTABLISHED in that column).
    python3 scripts/kit_survey.py --self-test

EXIT 0 the survey completed (some cells may be NOT_ESTABLISHED, each named)   1 refused (the state printed)
     2 could not run (PyYAML missing, bad arguments)
"""
import argparse
import base64
import csv
import datetime
import io
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# ── states (kit_survey_state, kit_survey_cell, kit_survey_comparison, kit_adoption_state in the taxonomy) ──
SURVEY_COMPLETE = 'SURVEY_COMPLETE'
SURVEY_PARTIAL = 'SURVEY_PARTIAL'
SURVEY_HOST_NOT_NAMED = 'SURVEY_HOST_NOT_NAMED'
SURVEY_HOST_UNSUPPORTED = 'SURVEY_HOST_UNSUPPORTED'
SURVEY_HOST_MISMATCH = 'SURVEY_HOST_MISMATCH'
SURVEY_AUTH_REFUSED = 'SURVEY_AUTH_REFUSED'
SURVEY_OWNER_NOT_FOUND = 'SURVEY_OWNER_NOT_FOUND'
SURVEY_OUT_IN_KIT = 'SURVEY_OUT_IN_KIT'

READ, ABSENT, NOT_ESTABLISHED = 'READ', 'ABSENT', 'NOT_ESTABLISHED'

KIT_BETTER, ORG_BETTER, EQUIVALENT = 'KIT_BETTER', 'ORG_BETTER', 'EQUIVALENT'
ORG_ONLY, KIT_ONLY, GAP = 'ORG_ONLY', 'KIT_ONLY', 'GAP'

ADOPTED, PARTIAL, TURNED_OFF, NEVER = 'ADOPTED', 'PARTIAL', 'TURNED_OFF', 'NEVER'
KIT_HOST = 'KIT_HOST'
REASON_NOT_RECORDED = 'REASON_NOT_RECORDED'

SHA40 = re.compile(r'^[0-9a-f]{40}$')
LOOPBACK = ('127.0.0.1', 'localhost', '::1')
WORKFLOW_DIR = '.github/workflows'


class Refusal(Exception):
    def __init__(self, state, detail):
        Exception.__init__(self, '%s: %s' % (state, detail))
        self.state = state
        self.detail = detail


# ═════════════════════════════════════════════════════════════════════════════════════════════════
# HOST AND CLIENT
# ═════════════════════════════════════════════════════════════════════════════════════════════════

def api_for_host(host):
    """A named cloud host -> its API, https://api.<host> (github.com or <tenant>.ghe.com); else None."""
    host = (host or '').strip().lower().rstrip('/')
    if host.startswith('https://'):
        host = host[len('https://'):]
    if host == 'github.com':
        return 'https://api.%s' % host
    if re.match(r'^[a-z0-9-]+\.ghe\.com$', host):
        return 'https://api.%s' % host
    return None


def resolve_host(host=None, api_url=None, env=None):
    """-> (host, api_url). Refuses rather than assume a host (KDEC-027)."""
    env = os.environ if env is None else env
    host = (host or '').strip().lower()
    api_url = (api_url or '').strip().rstrip('/')
    if not host:
        if not api_url and env.get('GITHUB_API_URL'):
            api_url = env['GITHUB_API_URL'].strip().rstrip('/')
        if api_url:
            n = (urllib.parse.urlsplit(api_url).hostname or '').lower()
            if n == 'api.' + 'github.com':
                host = 'github.com'
            elif n.startswith('api.') and n.endswith('.ghe.com'):
                host = n[len('api.'):]
        if not host:
            host = (env.get('GH_HOST') or '').strip().lower()
    if not host:
        raise Refusal(SURVEY_HOST_NOT_NAMED, 'no host is named: pass --host github.com or --host <tenant>.ghe.com '
                      '(or set GITHUB_API_URL / GH_HOST). The survey never assumes github.com.')
    expected = api_for_host(host)
    if not expected:
        raise Refusal(SURVEY_HOST_UNSUPPORTED, 'the host %r is neither github.com nor a <tenant>.ghe.com host '
                      '(KDEC-027 names the supported hosts).' % host)
    if not api_url:
        return host, expected
    u = urllib.parse.urlsplit(api_url)
    if u.scheme == 'http' and (u.hostname or '') in LOOPBACK:
        return host, api_url          # a loopback stand-in (the proofs); the repositories' host is still checked
    if u.scheme != 'https' or '@' in u.netloc:
        raise Refusal(SURVEY_HOST_MISMATCH, 'the API URL must be https with no credential in it.')
    if api_url != expected:
        raise Refusal(SURVEY_HOST_MISMATCH, 'the API URL %s is not the API of the named host %s (%s): a token '
                      'goes only to the host that issued it.' % (api_url, host, expected))
    return host, api_url


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None          # never re-send the token to wherever a 3xx points


_OPENER = urllib.request.build_opener(_NoRedirect)


def _transport(req, timeout):
    return _OPENER.open(req, timeout=timeout)


class ReadOnlyClient(object):
    """GET, and nothing else, to ONE API host. The token is a header to that host only; never printed."""

    def __init__(self, api_url, token=None, timeout=30):
        self.api = api_url.rstrip('/')
        self.netloc = urllib.parse.urlsplit(self.api).netloc
        self._token = token
        self.timeout = timeout
        self.calls = 0

    def _url(self, path, params=None):
        url = path if path.startswith(('http://', 'https://')) else self.api + path
        if params:
            url += ('&' if '?' in url else '?') + urllib.parse.urlencode(params)
        if urllib.parse.urlsplit(url).netloc != self.netloc:
            raise Refusal(SURVEY_HOST_MISMATCH, 'a request would have gone to %s, not the named API host %s.'
                          % (urllib.parse.urlsplit(url).netloc, self.netloc))
        return url

    def get(self, path, params=None, raw=False):
        """-> (status, body, headers). body is parsed JSON (or bytes when raw); None on an error status."""
        url = self._url(path, params)
        headers = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28',
                   'User-Agent': 'secure-cicd-kit-survey'}
        if self._token:
            headers['Authorization'] = 'Bearer %s' % self._token
        req = urllib.request.Request(url, headers=headers, method='GET')
        self.calls += 1
        try:
            with _transport(req, self.timeout) as r:
                data = r.read()
                hdrs = dict(r.headers.items()) if hasattr(r.headers, 'items') else {}
                status = r.getcode() if hasattr(r, 'getcode') else 200
        except urllib.error.HTTPError as e:
            return e.code, None, dict(e.headers.items()) if e.headers else {}
        except (urllib.error.URLError, OSError, ValueError) as e:
            return 0, None, {'error': str(e)[:200]}
        if raw:
            return status, data, hdrs
        try:
            return status, json.loads(data.decode('utf-8') or 'null'), hdrs
        except ValueError:
            return status, None, hdrs

    def pages(self, path, key=None, params=None, limit=None):
        """-> (state, items, truncated). Follows rel=next on the SAME host only."""
        params = dict(params or {})
        params.setdefault('per_page', 100)
        url, items, first = self._url(path, params), [], True
        while url:
            status, body, hdrs = self.get(url)
            if status != 200 or body is None:
                if first:
                    return cell(status), [], False
                return NOT_ESTABLISHED, items, True
            first = False
            got = body.get(key, []) if (key and isinstance(body, dict)) else (body if isinstance(body, list) else [])
            items.extend(got)
            url = _next_link(hdrs)
            if limit and (len(items) > limit or (len(items) == limit and url)):
                return READ, items[:limit], True
            if url:
                url = self._url(url)          # a next page on another host is refused, not followed
        return READ, items, False


def _next_link(hdrs):
    link = ''
    for k, v in (hdrs or {}).items():
        if k.lower() == 'link':
            link = v
    for part in link.split(','):
        m = re.match(r'\s*<([^>]+)>\s*;\s*rel="next"', part)
        if m:
            return m.group(1)
    return None


def cell(status):
    """An HTTP status -> READ / ABSENT / NOT_ESTABLISHED. 403/401/429/5xx are NEVER "absent"."""
    if status == 200:
        return READ
    if status in (404, 409):           # 409: an empty repository has no commits
        return ABSENT
    return NOT_ESTABLISHED


def names_only(items):
    """A secret or variable listing -> its NAMES. A value (a variable's, or anything value-shaped) is dropped."""
    return sorted(str(i.get('name')) for i in items if isinstance(i, dict) and i.get('name'))


def host_of(url):
    return (urllib.parse.urlsplit(url or '').hostname or '').lower()


def repo_host_matches(repo, host):
    """The API answered for THIS host: the repository's html_url is on it."""
    return host_of(repo.get('html_url')) == host


# ═════════════════════════════════════════════════════════════════════════════════════════════════
# WHAT THE WORKFLOWS DO
# ═════════════════════════════════════════════════════════════════════════════════════════════════

# (tool, capability, action prefixes (owner/repo, lowercase), command pattern)
TOOLS = [
    ('codeql', 'codeql', ['github/codeql-action/'], r'\bcodeql\s+database\b'),
    ('semgrep', 'sast-semgrep', ['returntocorp/semgrep-action', 'semgrep/semgrep-action'], r'\bsemgrep\b'),
    ('gitleaks', 'secret-scan', ['gitleaks/gitleaks-action', 'zricethezav/gitleaks-action'], r'\bgitleaks\b'),
    ('trufflehog', 'secret-scan', ['trufflesecurity/trufflehog'], r'\btrufflehog\b'),
    ('detect-secrets', 'secret-scan', [], r'\bdetect-secrets\b'),
    ('trivy', 'deps-scan', ['aquasecurity/trivy-action', 'aquasecurity/setup-trivy'], r'\btrivy\b'),
    ('osv-scanner', 'deps-scan', ['google/osv-scanner-action'], r'\bosv-scanner\b'),
    ('dependency-review', 'deps-scan', ['actions/dependency-review-action'], None),
    ('npm-audit', 'deps-scan', [], r'\bnpm audit\b'),
    ('pip-audit', 'deps-scan', ['pypa/gh-action-pip-audit'], r'\bpip-audit\b'),
    ('grype', 'image-scan', ['anchore/scan-action'], r'\bgrype\b'),
    ('docker-scout', 'image-scan', ['docker/scout-action'], r'\bdocker scout\b'),
    ('checkov', 'iac-scan', ['bridgecrewio/checkov-action'], r'\bcheckov\b'),
    ('tfsec', 'iac-scan', ['aquasecurity/tfsec-action', 'aquasecurity/tfsec-sarif-action'], r'\btfsec\b'),
    ('kics', 'iac-scan', ['checkmarx/kics-github-action'], r'\bkics\b'),
    ('hadolint', 'iac-scan', ['hadolint/hadolint-action'], r'\bhadolint\b'),
    ('bandit', 'sast-bandit', ['pycqa/bandit-action'], r'\bbandit\b'),
    ('gosec', 'sast-go', ['securego/gosec'], r'\bgosec\b'),
    ('spotbugs', 'sast-java', [], r'\bspotbugs\b|find-sec-bugs'),
    ('cppcheck', 'sast-cpp', [], r'\bcppcheck\b|\bflawfinder\b'),
    ('dotnet-vulnerable', 'sast-dotnet', [], r'dotnet list .*--vulnerable'),
    ('mobsfscan', 'sast-mobile', ['mobsf/mobsfscan'], r'\bmobsfscan\b'),
    ('eslint', 'code-quality', [], r'\beslint\b'),
    ('ruff', 'code-quality', ['astral-sh/ruff-action', 'chartboost/ruff-action'], r'\bruff (check|\.)'),
    ('actionlint', 'workflow-lint', ['rhysd/actionlint', 'raven-actions/actionlint'], r'\bactionlint\b'),
    ('zizmor', 'workflow-lint', ['zizmorcore/zizmor-action', 'woodruffw/zizmor'], r'\bzizmor\b'),
    ('sbom', 'sbom', ['anchore/sbom-action', 'cyclonedx/'], r'\bsyft\b|cyclonedx'),
    ('attestation', 'provenance', ['actions/attest-build-provenance', 'actions/attest'], None),
    ('cosign', 'signing', ['sigstore/cosign-installer'], r'\bcosign sign\b'),
    ('sonarqube', 'sonarqube', ['sonarsource/'], r'\bsonar-scanner\b'),
    ('snyk', 'snyk', ['snyk/actions'], r'\bsnyk (test|monitor|code|iac|container)\b'),
    ('aikido', 'aikido', ['aikidosec/'], None),
    ('scorecard', 'scorecard', ['ossf/scorecard-action'], None),
    ('harden-runner', 'runner-hardening', ['step-security/harden-runner'], None),
    ('zap', 'dast', ['zaproxy/'], r'zap-baseline|zap-full-scan|zap-api-scan'),
]
DEPLOY_SIGNS = [
    ('azure', ['azure/', 'microsoft/'], r'(^|\s)az\s+(webapp|containerapp|deployment|acr|aks|functionapp|staticwebapp)\b'),
    ('aws', ['aws-actions/'], r'(^|\s)aws\s+(s3|ecs|eks|lambda|cloudformation|deploy)\b|\bcdk deploy\b|\bsam deploy\b'),
    ('gcp', ['google-github-actions/'], r'\bgcloud\s+(run|app|functions|deploy)\b'),
    ('other', ['actions/deploy-pages', 'peaceiris/actions-gh-pages', 'amondnet/vercel-action',
               'nwtgck/actions-netlify', 'akhileshns/heroku-deploy'],
     r'\bkubectl apply\b|\bhelm upgrade\b|\bterraform apply\b|\bfirebase deploy\b|\bvercel --prod\b'),
]
STATIC_CLOUD_SECRETS = ('AZURE_CREDENTIALS', 'AWS_SECRET_ACCESS_KEY', 'AWS_ACCESS_KEY_ID', 'GCP_SA_KEY',
                        'GOOGLE_CREDENTIALS', 'AZURE_CLIENT_SECRET')
PR_EVENTS = ('pull_request', 'pull_request_target', 'merge_group')


def load_yaml(text):
    import yaml
    try:
        return yaml.safe_load(text)
    except Exception:  # noqa: BLE001 -- an unparseable workflow is recorded, not fatal
        return None


def triggers(doc):
    on = doc.get('on', doc.get(True)) if isinstance(doc, dict) else None
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return set(str(x) for x in on)
    if isinstance(on, dict):
        return set(str(k) for k in on)
    return set()


def is_false_if(v):
    s = re.sub(r'\s+', '', str(v if v is not None else '')).lower()
    return s in ('false', '${{false}}', '0', "${{'false'}}") or v is False


def kit_ref_re(kit_names):
    alts = '|'.join(re.escape(n) for n in kit_names)
    return re.compile(r'^([^/\s]+)/(%s)/\.github/workflows/([A-Za-z0-9_.-]+\.ya?ml)@(\S+)$' % alts, re.I)


def parse_workflow(path, text, kit_names):
    """-> dict: triggers, actions [(uses, pinned)], tools [{tool, capability, pinned, blocking}], kit_calls,
    deploy, static_cloud_secrets, parse_ok."""
    out = {'path': path, 'parse_ok': True, 'triggers': [], 'actions': [], 'tools': [], 'kit_calls': [],
           'deploy': [], 'static_cloud_secrets': [], 'codeql_queries': ''}
    doc = load_yaml(text)
    if not isinstance(doc, dict):
        out['parse_ok'] = False
        return out
    trig = triggers(doc)
    out['triggers'] = sorted(trig)
    kre = kit_ref_re(kit_names)
    jobs = doc.get('jobs') or {}
    if not isinstance(jobs, dict):
        jobs = {}
    for jname, job in jobs.items():
        if not isinstance(job, dict):
            continue
        job_disabled = is_false_if(job.get('if')) if 'if' in job else False
        job_soft = bool(job.get('continue-on-error'))
        juses = job.get('uses')
        if isinstance(juses, str):
            m = kre.match(juses.strip())
            if m:
                w = job.get('with') or {}
                out['kit_calls'].append({
                    'job': str(jname), 'workflow': m.group(3), 'ref': m.group(4), 'kit_repo': '%s/%s' % (m.group(1), m.group(2)),
                    'pinned': bool(SHA40.match(m.group(4))), 'disabled': job_disabled,
                    'advisory_mode': str(w.get('advisory_mode', '')).lower() in ('true', '1'),
                    'weakening_reason': str(w.get('weakening_reason') or '').strip(),
                    'soft_fail_sast': str(w.get('soft_fail_sast', '')).lower() in ('true', '1')})
            elif not juses.startswith('./'):
                out['actions'].append((juses, _pinned(juses)))
            if re.search(r'reusable-deploy-|build-deploy', juses):
                out['deploy'].append('azure')
        for step in job.get('steps') or []:
            if not isinstance(step, dict):
                continue
            soft = job_soft or bool(step.get('continue-on-error'))
            uses = step.get('uses')
            run = str(step.get('run') or '')
            if isinstance(uses, str) and not uses.startswith('./') and not uses.startswith('docker://'):
                out['actions'].append((uses, _pinned(uses)))
            lu = uses.lower() if isinstance(uses, str) else ''
            w = step.get('with') or {}
            for tool, cap, prefixes, cmd in TOOLS:
                hit_action = lu and any(lu.startswith(p) for p in prefixes)
                hit_cmd = bool(cmd and run and re.search(cmd, run, re.I))
                if hit_action or hit_cmd:
                    out['tools'].append({
                        'tool': tool, 'capability': cap, 'job': str(jname),
                        'pinned': _pinned(uses) if hit_action else True,
                        'blocking': not soft and not re.search(r'\|\|\s*true\b|\|\|\s*exit 0\b', run),
                        'disabled': job_disabled})
                    if tool == 'codeql' and isinstance(w, dict) and w.get('queries'):
                        out['codeql_queries'] = str(w.get('queries'))
            for target, prefixes, cmd in DEPLOY_SIGNS:
                if (lu and any(lu.startswith(p) for p in prefixes)) or (run and re.search(cmd, run)):
                    out['deploy'].append(target)
    for s in STATIC_CLOUD_SECRETS:
        if re.search(r'secrets\.%s\b' % s, text):
            out['static_cloud_secrets'].append(s)
    out['deploy'] = sorted(set(out['deploy']))
    return out


def _pinned(uses):
    if not isinstance(uses, str) or '@' not in uses:
        return False
    return bool(SHA40.match(uses.rsplit('@', 1)[1].strip()))


# ═════════════════════════════════════════════════════════════════════════════════════════════════
# ONE REPOSITORY
# ═════════════════════════════════════════════════════════════════════════════════════════════════

def _content(client, full, path, ref):
    status, body, _ = client.get('/repos/%s/contents/%s' % (full, path), {'ref': ref} if ref else None)
    if status != 200 or not isinstance(body, dict):
        return cell(status), None
    try:
        return READ, base64.b64decode(body.get('content') or '').decode('utf-8', 'replace')
    except (ValueError, TypeError):
        return NOT_ESTABLISHED, None


def _protection(client, full, branch):
    status, body, _ = client.get('/repos/%s/branches/%s/protection' % (full, urllib.parse.quote(branch, safe='')))
    c = cell(status)
    if c != READ:
        return c, {}
    b = body or {}
    rv = b.get('required_pull_request_reviews') or {}
    attrs = {
        'reviews': bool(rv),
        'approvals': int(rv.get('required_approving_review_count') or 0),
        'code_owner': bool(rv.get('require_code_owner_reviews')),
        'last_push': bool(rv.get('require_last_push_approval')),
        'status_checks': bool((b.get('required_status_checks') or {}).get('contexts') or
                              (b.get('required_status_checks') or {}).get('checks')),
        'signatures': bool((b.get('required_signatures') or {}).get('enabled')),
        'linear': bool((b.get('required_linear_history') or {}).get('enabled')),
        'no_force_push': not bool((b.get('allow_force_pushes') or {}).get('enabled')),
        'admins_enforced': bool((b.get('enforce_admins') or {}).get('enabled')),
    }
    return READ, attrs


def _rulesets(client, full):
    state, items, _ = client.pages('/repos/%s/rulesets' % full)
    if state != READ:
        return state, {}, []
    attrs, names = {}, []
    for rs in items:
        names.append(str(rs.get('name')))
        rid = rs.get('id')
        status, body, _ = client.get('/repos/%s/rulesets/%s' % (full, rid))
        if status != 200 or not isinstance(body, dict):
            attrs['_unread'] = True
            continue
        if body.get('enforcement') != 'active':
            continue
        for rule in body.get('rules') or []:
            t, p = rule.get('type'), rule.get('parameters') or {}
            if t == 'pull_request':
                attrs['reviews'] = True
                attrs['approvals'] = max(attrs.get('approvals', 0), int(p.get('required_approving_review_count') or 0))
                attrs['code_owner'] = attrs.get('code_owner') or bool(p.get('require_code_owner_review'))
                attrs['last_push'] = attrs.get('last_push') or bool(p.get('require_last_push_approval'))
            elif t == 'required_status_checks':
                attrs['status_checks'] = True
            elif t == 'required_signatures':
                attrs['signatures'] = True
            elif t == 'required_linear_history':
                attrs['linear'] = True
            elif t == 'non_fast_forward':
                attrs['no_force_push'] = True
    return READ, attrs, names


def _environments(client, full):
    status, body, _ = client.get('/repos/%s/environments' % full, {'per_page': 100})
    c = cell(status)
    if c != READ:
        return c, []
    envs = []
    for e in (body or {}).get('environments') or []:
        rules = e.get('protection_rules') or []
        reviewers = [r for r in rules if r.get('type') == 'required_reviewers']
        wait = [r for r in rules if r.get('type') == 'wait_timer']
        bp = e.get('deployment_branch_policy') or None
        envs.append({
            'name': str(e.get('name')),
            'reviewers': sum(len(r.get('reviewers') or []) for r in reviewers),
            'prevent_self_review': any(r.get('prevent_self_review') for r in reviewers),
            'wait_timer': max([int(r.get('wait_timer') or 0) for r in wait] or [0]),
            'branch_policy': bool(bp),
        })
    return READ, envs


def _history(client, full, branch, kit_names, limit):
    """Kit-caller events in .github/workflows history, newest first.
    -> (state, events, truncated). An event: {kind: removed|disabled|weakened|added, sha, date, message, files}."""
    state, commits, truncated = client.pages('/repos/%s/commits' % full,
                                             params={'path': WORKFLOW_DIR, 'sha': branch} if branch else
                                             {'path': WORKFLOW_DIR}, limit=limit)
    if state != READ:
        return state, [], False
    kre = re.compile(r'uses:\s*["\']?[^/\s]+/(%s)/\.github/workflows/' % '|'.join(re.escape(n) for n in kit_names), re.I)
    events = []
    for c in commits:
        sha = c.get('sha')
        status, body, _ = client.get('/repos/%s/commits/%s' % (full, sha))
        if status != 200 or not isinstance(body, dict):
            events.append({'kind': 'unread', 'sha': sha})
            continue
        msg = ((body.get('commit') or {}).get('message') or '').strip()
        date = ((body.get('commit') or {}).get('committer') or {}).get('date') or ''
        removed = added = disabled = weakened = False
        files = []
        for f in body.get('files') or []:
            fn = f.get('filename') or ''
            if not fn.startswith(WORKFLOW_DIR + '/'):
                continue
            patch = f.get('patch')
            if patch is None and f.get('status') == 'removed':
                parents = body.get('parents') or []
                if parents:
                    _, old = _content(client, full, fn, parents[0].get('sha'))
                    patch = '\n'.join('-' + ln for ln in (old or '').splitlines())
            minus = [ln[1:] for ln in (patch or '').splitlines() if ln.startswith('-') and not ln.startswith('---')]
            plus = [ln[1:] for ln in (patch or '').splitlines() if ln.startswith('+') and not ln.startswith('+++')]
            r_kit = any(kre.search(ln) for ln in minus)
            a_kit = any(kre.search(ln) for ln in plus)
            if r_kit and not a_kit:
                removed = True
            elif a_kit and not r_kit:
                added = True
            if any(re.match(r'^\s*if:\s*(\$\{\{\s*)?false(\s*\}\})?\s*$', ln) for ln in plus) and (
                    a_kit or r_kit or _kit_file(client, full, fn, sha, kre)):
                disabled = True
            if any(re.match(r'^\s*(advisory_mode:\s*true|soft_fail_sast:\s*true|weakening_reason:\s*\S)', ln)
                   for ln in plus):
                weakened = True
            files.append(fn)
        for kind, hit in (('removed', removed), ('disabled', disabled), ('weakened', weakened), ('added', added)):
            if hit:
                events.append({'kind': kind, 'sha': sha, 'date': date, 'message': msg, 'files': files})
    return READ, events, truncated


def _kit_file(client, full, fn, sha, kre):
    _, text = _content(client, full, fn, sha)
    return bool(text and kre.search(text))


DEFAULT_UI_MESSAGE = re.compile(r'^(update|delete|create|remove|add|rename)\s+[\w./ -]+\.ya?ml$', re.I)
PAIN = [
    ('too slow', r'\bslow\b|\bminutes\b|\btimeout\b|\btakes? (too )?long\b|\bhours?\b'),
    ('cost', r'\bcost\b|\bbilling\b|\bminutes quota\b|\bspend\b|\bexpensive\b'),
    ('noise / false positives', r'false positive|\bnoisy?\b|\bnoise\b|too many findings|\bfp\b'),
    ('blocks delivery', r'\bblock(s|ed|ing)?\b|\bcan\'?t (merge|deploy|ship)\b|\bunblock\b'),
    ('broken / failing', r'\bbroken\b|\bfail(s|ed|ing)?\b|\bred\b|\berror\b|\bcrash'),
    ('permissions / setup', r'\bpermission|\btoken\b|\bsecret\b|\boidc\b|\baccess\b|\bnot found\b'),
    ('replaced by another tool', r'\breplac|\bmigrat|\bswitch(ed)? to\b|\binstead\b|\bsonar|\bsnyk|\baikido'),
]


def stated_reason(message, pr_bodies):
    """-> (reason text or REASON_NOT_RECORDED, pain point or '')."""
    msg = (message or '').strip()
    first = msg.splitlines()[0] if msg else ''
    rest = '\n'.join(msg.splitlines()[1:]).strip()
    texts = []
    if first and not DEFAULT_UI_MESSAGE.match(first) and len(first.split()) >= 3:
        texts.append(first)
    if rest:
        texts.append(rest)
    texts.extend(b.strip() for b in pr_bodies if b and b.strip())
    if not texts:
        return REASON_NOT_RECORDED, ''
    text = ' | '.join(texts)
    pains = [name for name, rx in PAIN if re.search(rx, text, re.I)]
    return text[:400], (', '.join(pains) if pains else 'stated, not classified')


def _pr_bodies(client, full, sha):
    status, body, _ = client.get('/repos/%s/commits/%s/pulls' % (full, sha))
    if status != 200 or not isinstance(body, list):
        return []
    return ['%s %s' % (p.get('title') or '', p.get('body') or '') for p in body[:3]]


def survey_repo(client, owner, repo, opts):
    full = repo.get('full_name') or '%s/%s' % (owner, repo.get('name'))
    branch = repo.get('default_branch') or ''
    row = {'repo': full, 'name': repo.get('name'), 'visibility': repo.get('visibility') or
           ('private' if repo.get('private') else 'public'), 'archived': bool(repo.get('archived')),
           'fork': bool(repo.get('fork')), 'default_branch': branch, 'not_established': []}
    ne = row['not_established']
    kit_names = opts['kit_names']
    row['is_kit'] = (repo.get('name') or '').lower() in [n.lower() for n in kit_names]

    # workflows: API state, then the files on the default branch
    st, wf_items, _ = client.pages('/repos/%s/actions/workflows' % full, key='workflows')
    wf_state = {}
    if st == READ:
        for w in wf_items:
            wf_state[w.get('path')] = w.get('state')
    elif st == NOT_ESTABLISHED:
        ne.append('workflow_state')
    status, listing, _ = client.get('/repos/%s/contents/%s' % (full, WORKFLOW_DIR), {'ref': branch} if branch else None)
    wf_cell = cell(status)
    parsed = []
    if wf_cell == READ and isinstance(listing, list):
        for item in listing:
            p = item.get('path') or ''
            if item.get('type') != 'file' or not p.endswith(('.yml', '.yaml')):
                continue
            c, text = _content(client, full, p, branch)
            if c != READ:
                ne.append('workflow:%s' % p)
                continue
            pw = parse_workflow(p, text, kit_names)
            pw['api_state'] = wf_state.get(p, '')
            parsed.append(pw)
    elif wf_cell == NOT_ESTABLISHED:
        ne.append('workflows')
    row['workflows_cell'] = wf_cell
    row['workflows'] = parsed
    row['workflows_disabled'] = sorted(p['path'] for p in parsed if (p.get('api_state') or '').startswith('disabled'))
    acts = [a for p in parsed for a in p['actions']]
    row['actions_used'] = sorted(set(a for a, _ in acts))
    row['actions_unpinned'] = sorted(set(a for a, pin in acts if not pin))
    row['tools'] = [dict(t, workflow=p['path'], triggers=p['triggers'], api_state=p.get('api_state', ''))
                    for p in parsed for t in p['tools']]
    row['scanners'] = sorted(set(t['tool'] for t in row['tools']))
    row['codeql_queries'] = sorted(set(p['codeql_queries'] for p in parsed if p['codeql_queries']))
    row['static_cloud_secrets_in_workflows'] = sorted(set(s for p in parsed for s in p['static_cloud_secrets']))

    # kit callers
    calls = []
    for p in parsed:
        for k in p['kit_calls']:
            calls.append(dict(k, path=p['path'], triggers=p['triggers'], api_state=p.get('api_state', '')))
    row['kit_calls'] = calls
    deploy = set(t for p in parsed for t in p['deploy'])
    row['deploy_targets'] = sorted(deploy)

    # protection
    pc, pattrs = (ABSENT, {}) if not branch else _protection(client, full, branch)
    if pc == NOT_ESTABLISHED:
        ne.append('branch_protection')
    rc, rattrs, rnames = _rulesets(client, full)
    if rc == NOT_ESTABLISHED:
        ne.append('rulesets')
    merged = dict(pattrs)
    for k, v in rattrs.items():
        if k == 'approvals':
            merged[k] = max(merged.get(k, 0), v)
        elif k != '_unread':
            merged[k] = merged.get(k) or v
    row['protection_cell'], row['rulesets_cell'] = pc, rc
    row['protection'] = merged
    row['rulesets'] = rnames

    ec, envs = _environments(client, full)
    if ec == NOT_ESTABLISHED:
        ne.append('environments')
    row['environments_cell'], row['environments'] = ec, envs

    co = NOT_ESTABLISHED
    for path in ('.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS'):
        c, _ = _content(client, full, path, branch)
        if c == READ:
            co = READ
            break
        if c == ABSENT:
            co = ABSENT
    if co == NOT_ESTABLISHED:
        ne.append('codeowners')
    row['codeowners'] = co

    dep, dep_attrs = NOT_ESTABLISHED, {}
    for path in ('.github/dependabot.yml', '.github/dependabot.yaml'):
        c, text = _content(client, full, path, branch)
        if c == READ:
            dep = READ
            d = load_yaml(text) or {}
            ups = d.get('updates') or [] if isinstance(d, dict) else []
            dep_attrs = {'ecosystems': sorted(set(str(u.get('package-ecosystem')) for u in ups if isinstance(u, dict))),
                         'groups': any(isinstance(u, dict) and u.get('groups') for u in ups),
                         'cooldown': any(isinstance(u, dict) and u.get('cooldown') for u in ups)}
            break
        if c == ABSENT:
            dep = ABSENT
    if dep == NOT_ESTABLISHED:
        ne.append('dependabot_config')
    row['dependabot'], row['dependabot_attrs'] = dep, dep_attrs

    sc, sitems, _ = client.pages('/repos/%s/actions/secrets' % full, key='secrets')
    vc, vitems, _ = client.pages('/repos/%s/actions/variables' % full, key='variables')
    if sc == NOT_ESTABLISHED:
        ne.append('secret_names')
    if vc == NOT_ESTABLISHED:
        ne.append('variable_names')
    row['secret_names'] = names_only(sitems)
    row['variable_names'] = names_only(vitems)
    row['static_cloud_secret_names'] = sorted(set(row['secret_names']) & set(STATIC_CLOUD_SECRETS))

    pr_c, pr_text = _content(client, full, '.security/policy-registration.json', branch)
    rungs = set()
    if pr_c == READ:
        try:
            for pol in (json.loads(pr_text).get('policies') or []):
                if isinstance(pol, dict) and pol.get('rung'):
                    rungs.add(str(pol['rung']))
        except (ValueError, AttributeError):
            ne.append('policy_registration')
    row['rungs'] = sorted(rungs, key=lambda r: ['crawl', 'walk', 'run'].index(r) if r in ('crawl', 'walk', 'run') else 9)

    # history (only when it could change the verdict, or when asked for)
    row['history_cell'], row['history'], row['history_truncated'] = '', [], False
    if not row['is_kit'] and opts.get('history', 0) > 0:
        hc, events, trunc = _history(client, full, branch, kit_names, opts['history'])
        row['history_cell'], row['history'], row['history_truncated'] = hc, events, trunc
        if hc == NOT_ESTABLISHED:
            ne.append('history')
    adopt(row, client)
    return row


def adopt(row, client=None):
    """ADOPTED (rung) / PARTIAL / TURNED_OFF / NEVER / NOT_ESTABLISHED / KIT_HOST, with evidence and reason."""
    row['turn_off_evidence'], row['turn_off_reason'], row['pain_point'] = '', '', ''
    if row['is_kit']:
        row['adoption'], row['adoption_level'] = KIT_HOST, ''
        return
    calls = row['kit_calls']
    active = [c for c in calls if not c['disabled'] and not (c.get('api_state') or '').startswith('disabled')]
    off = [c for c in calls if c not in active]
    sec = [c for c in active if c['workflow'].startswith('reusable-security') or 'build-deploy' in c['workflow']
           or c['workflow'].startswith('reusable-deploy-')]
    level = row['rungs'][-1] if row['rungs'] else 'crawl'
    row['kit_pin'] = ';'.join(sorted(set((c['ref'][:12] if c['pinned'] else '%s (UNPINNED)' % c['ref']) for c in calls)))
    row['kit_workflows'] = ';'.join(sorted(set(c['workflow'] for c in calls)))
    if sec:
        partial = []
        if not all(c['pinned'] for c in sec):
            partial.append('the kit is referenced by a moving ref, not a commit SHA')
        if not any(set(c['triggers']) & set(PR_EVENTS) for c in sec):
            partial.append('the security caller does not run on pull requests')
        weak = [c for c in sec if c['weakening_reason'] or c['soft_fail_sast']]
        if weak:
            partial.append('a weakening is declared: %s' % (weak[0]['weakening_reason'] or 'soft_fail_sast'))
            row['turn_off_reason'] = weak[0]['weakening_reason'] or REASON_NOT_RECORDED
            row['pain_point'] = stated_reason(weak[0]['weakening_reason'], [])[1] if weak[0]['weakening_reason'] else ''
            row['turn_off_evidence'] = 'weakening record in %s (job %s)' % (weak[0]['path'], weak[0]['job'])
        if any(c['advisory_mode'] for c in sec):
            level = 'crawl'
        if partial:
            row['adoption'], row['adoption_level'] = PARTIAL, level
            row['partial_because'] = partial
        else:
            row['adoption'], row['adoption_level'] = ADOPTED, level
        return
    if active:          # only non-security kit workflows (Dependabot, tickets ...)
        row['adoption'], row['adoption_level'] = PARTIAL, ''
        row['partial_because'] = ['only %s; no kit security or deploy caller' % ', '.join(sorted(set(c['workflow'] for c in active)))]
        return
    if off:
        c = off[0]
        why = 'job %s has if: false' % c['job'] if c['disabled'] else 'workflow state %s (API)' % c['api_state']
        row['adoption'], row['adoption_level'] = TURNED_OFF, ''
        row['turn_off_evidence'] = '%s in %s' % (why, c['path'])
        ev = [e for e in row['history'] if e['kind'] == 'disabled']
        if ev and c['disabled'] and client is not None:
            row['turn_off_evidence'] += '; commit %s' % ev[0]['sha'][:12]
            row['turn_off_reason'], row['pain_point'] = stated_reason(ev[0]['message'], _pr_bodies(client, row['repo'], ev[0]['sha']))
        else:
            row['turn_off_reason'] = REASON_NOT_RECORDED
        return
    removed = [e for e in row['history'] if e['kind'] in ('removed', 'disabled')]
    if removed:
        e = removed[0]
        row['adoption'], row['adoption_level'] = TURNED_OFF, ''
        row['turn_off_evidence'] = 'commit %s (%s) %s the kit caller in %s' % (
            e['sha'][:12], e['date'][:10], 'removed' if e['kind'] == 'removed' else 'disabled', ', '.join(e['files']))
        bodies = _pr_bodies(client, row['repo'], e['sha']) if client is not None else []
        row['turn_off_reason'], row['pain_point'] = stated_reason(e['message'], bodies)
        return
    if row['workflows_cell'] == NOT_ESTABLISHED or row['history_cell'] in (NOT_ESTABLISHED, '') \
            or row['history_truncated'] or any(e['kind'] == 'unread' for e in row['history']):
        row['adoption'], row['adoption_level'] = NOT_ESTABLISHED, ''
        row['turn_off_reason'] = ('the workflow history was not read in full (raise --history)'
                                  if row['history_truncated'] or row['history_cell'] == '' else
                                  'the workflows or their history could not be read')
        return
    row['adoption'], row['adoption_level'] = NEVER, ''


# ═════════════════════════════════════════════════════════════════════════════════════════════════
# THE KIT'S CAPABILITY INVENTORY, AND THE COMPARISON
# ═════════════════════════════════════════════════════════════════════════════════════════════════

SCANNER_KIT_ATTRS = {'pinned', 'on_pr', 'blocking'}
NATIVE_OWNERS = ('actions/', 'github/', 'azure/', 'microsoft/')
# id -> (title, kit_has, how the kit does it, the kit's attributes)
GOVERNANCE = [
    ('action-pinning', 'Actions pinned by commit SHA', True,
     'every action the kit uses is pinned by SHA (tests/check_action_pins.py, scripts/pin-actions.sh)', set()),
    ('branch-protection', 'Default-branch protection', True,
     'docs/adoption/BRANCH_PROTECTION_SETTINGS.md: application profile = 1 approval, code owners, last-push '
     'approval, required checks, no force push; the infrastructure profile adds 2 approvals, signed commits and '
     'linear history', {'reviews', 'code_owner', 'last_push', 'status_checks', 'no_force_push'}),
    ('environment-protection', 'uat/prod environment approval', True,
     'KDEC-042: uat and prod need a reviewer from outside the app team, self-review prevented, deployments from '
     'main only (.kit/environments.json from kit init)', {'reviewers', 'prevent_self_review', 'branch_policy'}),
    ('codeowners', 'CODEOWNERS on security-relevant paths', True,
     'kit init writes a CODEOWNERS block (AppSec on .kit/, .security/, workflows, Dependabot, Dockerfiles, IaC)', {'present'}),
    ('dependabot-config', 'Dependabot configuration matches the manifests', True,
     'scripts/dependabot_config.py generates and checks it (grouped updates; every manifest covered)', {'present', 'groups'}),
    ('oidc-cloud-login', 'Cloud login by OIDC, no stored cloud keys', True,
     'the kit deploys log in to Azure by OIDC (.github/actions/azure-login-oidc); no client secret is stored', {'oidc'}),
]
EXTERNAL = [
    # id, title, kit_has, how (or why not), expected_baseline (a GAP when neither has it)
    ('workflow-lint', 'Workflow linting (actionlint, zizmor)', True, 'deps-scan runs actionlint and zizmor', False),
    ('provenance', 'Build provenance attestation', True, 'reusable-security.yml attests with actions/attest-build-provenance', False),
    ('signing', 'Artifact signing (cosign)', False, 'not built: attestation signing is named not live (docs/START-HERE.md)', True),
    ('dast', 'Dynamic scan of the running app (DAST)', False,
     'a neutral hook only: KIT_DAST_COMMAND / PROMOTION_DAST_SARIF; an overlay supplies the tool (ZAP baseline)', True),
    ('runner-hardening', 'Runner egress hardening', False, 'not built in the kit', True),
    ('scorecard', 'OpenSSF Scorecard posture', False, 'not built in the kit', False),
    ('sonarqube', 'SonarQube code analysis', False,
     'the kit does not run it; it PULLS SonarQube findings into its intake (reusable-external-findings.yml)', False),
    ('aikido', 'Aikido', False, 'the kit does not run it; it PULLS Aikido findings into its intake', False),
    ('snyk', 'Snyk', False, 'not built in the kit', False),
]


def capability_inventory(root=ROOT):
    """-> list of {id, title, kit_has, how, attrs, kind, baseline}. Scanner rows from capability-floor.json."""
    caps, source = [], 'capability-floor.json'
    try:
        with io.open(os.path.join(root, 'capability-floor.json'), encoding='utf-8') as fh:
            floor = json.load(fh).get('floor') or []
    except (OSError, ValueError):
        floor, source = [], 'capability-floor.json NOT READ'
    for f in floor:
        caps.append({'id': f['capability'], 'title': 'Scanner: %s' % f['capability'], 'kit_has': True,
                     'how': 'reusable-security.yml (%s), in the protected capability floor' % ', '.join(f.get('identities') or []),
                     'attrs': SCANNER_KIT_ATTRS, 'kind': 'scanner', 'baseline': False})
    for cid, title, has, how, attrs in GOVERNANCE:
        caps.append({'id': cid, 'title': title, 'kit_has': has, 'how': how, 'attrs': attrs, 'kind': 'governance',
                     'baseline': False})
    for cid, title, has, how, base in EXTERNAL:
        caps.append({'id': cid, 'title': title, 'kit_has': has, 'how': how, 'attrs': SCANNER_KIT_ATTRS if has else set(),
                     'kind': 'external', 'baseline': base})
    return caps, source


def _org_practice(cap, rows):
    """-> list of {repo, evidence, attrs set, credit_attrs set} for the ORG'S OWN practice (never via the kit)."""
    out, unread = [], 0
    cid = cap['id']
    for r in rows:
        if r['is_kit'] or r['archived']:
            continue
        if cap['kind'] in ('scanner', 'external'):
            for t in r['tools']:
                if t['capability'] != cid or t['disabled']:
                    continue
                a = set()
                if t['pinned']:
                    a.add('pinned')
                if set(t['triggers']) & set(PR_EVENTS):
                    a.add('on_pr')
                if t['blocking']:
                    a.add('blocking')
                if 'schedule' in t['triggers']:
                    a.add('scheduled')
                if cid == 'codeql' and any('security-and-quality' in q for q in r['codeql_queries']):
                    a.add('broader_queries')
                out.append({'repo': r['repo'], 'evidence': '%s: %s (job %s)' % (t['workflow'], t['tool'], t['job']),
                            'attrs': a, 'tool': t['tool']})
        elif cid == 'action-pinning':
            if r['actions_used']:
                a = {'all_pinned'} if not r['actions_unpinned'] else set()
                out.append({'repo': r['repo'], 'attrs': a, 'tool': '',
                            'evidence': '%d actions, %d unpinned' % (len(r['actions_used']), len(r['actions_unpinned']))})
        elif cid == 'branch-protection':
            if r['protection_cell'] == NOT_ESTABLISHED and r['rulesets_cell'] == NOT_ESTABLISHED:
                unread += 1
            p = r['protection']
            if p:
                a = set(k for k in ('reviews', 'code_owner', 'last_push', 'status_checks', 'no_force_push',
                                    'signatures', 'linear') if p.get(k))
                if p.get('approvals', 0) >= 2:
                    a.add('two_approvals')
                out.append({'repo': r['repo'], 'attrs': a, 'tool': '', 'evidence': 'default branch %s: %s' % (
                    r['default_branch'], ', '.join(sorted(a)) or 'protected, no rule the kit compares')})
        elif cid == 'environment-protection':
            if r['environments_cell'] == NOT_ESTABLISHED:
                unread += 1
            for e in r['environments']:
                if not re.search(r'prod|uat|stag|live', e['name'], re.I):
                    continue
                a = set()
                if e['reviewers']:
                    a.add('reviewers')
                if e['prevent_self_review']:
                    a.add('prevent_self_review')
                if e['branch_policy']:
                    a.add('branch_policy')
                if e['wait_timer']:
                    a.add('wait_timer')
                out.append({'repo': r['repo'], 'attrs': a, 'tool': '', 'evidence': 'environment %s: %s' % (
                    e['name'], ', '.join(sorted(a)) or 'no protection rule')})
        elif cid == 'codeowners':
            if r['codeowners'] == NOT_ESTABLISHED:
                unread += 1
            if r['codeowners'] == READ:
                out.append({'repo': r['repo'], 'attrs': {'present'}, 'tool': '', 'evidence': 'CODEOWNERS present'})
        elif cid == 'dependabot-config':
            if r['dependabot'] == READ:
                a = {'present'}
                if r['dependabot_attrs'].get('groups'):
                    a.add('groups')
                if r['dependabot_attrs'].get('cooldown'):
                    a.add('cooldown')
                out.append({'repo': r['repo'], 'attrs': a, 'tool': '', 'evidence': '.github/dependabot.yml (%s)' % (
                    ', '.join(r['dependabot_attrs'].get('ecosystems') or []) or 'no ecosystems')})
        elif cid == 'oidc-cloud-login':
            if r['deploy_targets'] and not any(c for c in r['kit_calls']):
                static = r['static_cloud_secrets_in_workflows'] or r['static_cloud_secret_names']
                out.append({'repo': r['repo'], 'attrs': set() if static else {'oidc'}, 'tool': '',
                            'evidence': ('stored cloud key NAMES: %s' % ', '.join(static)) if static
                            else 'deploys (%s) with no stored cloud key name' % ', '.join(r['deploy_targets'])})
    return out, unread


CREDIT = {
    'scheduled': 'runs on a schedule as well as on change, so an advisory published today is found in code nobody '
                 'touched; the kit security caller runs on push and pull request (its daily deployed scan covers '
                 'serving images only)',
    'broader_queries': 'runs CodeQL with security-and-quality, broader than the kit default security-extended',
    'signatures': 'requires signed commits on an application repository; the kit asks for them on infrastructure only',
    'linear': 'requires linear history on an application repository; the kit asks for it on infrastructure only',
    'two_approvals': 'requires two approvals; the kit application profile asks for one',
    'wait_timer': 'waits a timer before a production deployment proceeds; the kit has no wait timer',
    'cooldown': 'sets a Dependabot cooldown (a new release waits before an update PR opens); the kit config has none',
}
KIT_ADVANTAGE = {
    'pinned': 'the org references the tool by a moving tag; the kit pins every action by SHA',
    'on_pr': 'the org runs it off the pull request path, so a finding lands after the merge; the kit runs on every PR',
    'blocking': 'the org runs it non-blocking (continue-on-error or `|| true`); the kit routes it by rung and evidence',
    'all_pinned': 'the org has unpinned actions; the kit pins every action by SHA',
    'reviews': 'no required review', 'code_owner': 'no code-owner review', 'last_push': 'no last-push approval',
    'status_checks': 'no required status check', 'no_force_push': 'force pushes allowed',
    'reviewers': 'no required reviewer', 'prevent_self_review': 'self-review not prevented',
    'branch_policy': 'any branch may deploy', 'present': 'absent', 'groups': 'updates not grouped',
    'oidc': 'a stored cloud key is used; the kit logs in by OIDC',
}


def compare(rows, root=ROOT):
    caps, source = capability_inventory(root)
    results = []
    for cap in caps:
        practice, unread = _org_practice(cap, rows)
        kit_attrs = set(cap['attrs'])
        if cap['id'] == 'action-pinning':
            kit_attrs = {'all_pinned'}
        res = {'id': cap['id'], 'title': cap['title'], 'kit_has': cap['kit_has'], 'how': cap['how'],
               'repos': sorted(set(p['repo'] for p in practice)), 'evidence': _dedupe(practice)[:8], 'credit': [],
               'kit_better': [], 'unread': unread}
        if not practice:
            if unread and unread == len([r for r in rows if not r['is_kit'] and not r['archived']]):
                res['verdict'] = NOT_ESTABLISHED
            elif cap['kit_has']:
                res['verdict'] = KIT_ONLY
            elif cap['baseline']:
                res['verdict'] = GAP
            else:
                continue                       # nobody does it and it is not expected: not a row
        elif not cap['kit_has']:
            res['verdict'] = ORG_ONLY
            res['credit'] = ['the org runs %s in %d repositories' % (', '.join(sorted(set(p['tool'] for p in practice if p['tool'])))
                                                                     or cap['title'], len(res['repos']))]
        else:
            strengths = set()
            for p in practice:
                strengths |= (p['attrs'] - kit_attrs) & set(CREDIT)
            best = max(practice, key=lambda p: len(p['attrs'] & kit_attrs))
            lacking = kit_attrs - best['attrs']
            res['credit'] = ['%s (%s)' % (CREDIT[s], ', '.join(sorted(set(p['repo'] for p in practice if s in p['attrs']))[:5]))
                             for s in sorted(strengths)]
            res['kit_better'] = [KIT_ADVANTAGE.get(a, a) for a in sorted(lacking)]
            res['verdict'] = ORG_BETTER if strengths else (KIT_BETTER if lacking else EQUIVALENT)
        if res['verdict'] in (ORG_BETTER, ORG_ONLY):
            res['proposal'] = proposal(cap, practice, res)
        results.append(res)
    return results, source


def _dedupe(practice):
    seen, out = set(), []
    for p in practice:
        k = (p['repo'], p['evidence'])
        if k not in seen:
            seen.add(k)
            out.append(p)
    return out


def _native(practice, cap):
    tools = [p for p in practice if p['tool']]
    if not tools:
        return True                    # a setting (protection, environment, Dependabot): GitHub-native
    for row in TOOLS:
        if row[0] in set(p['tool'] for p in tools):
            if not any(pre.startswith(NATIVE_OWNERS) for pre in row[2]):
                return False
    return True


STRENGTH_STEPS = {
    'scheduled': ('overlays/<org>/templates/security.yml (the org copy of the kit caller with a weekly `schedule:`); '
                  'a neutral template change only through a KDEC (GitHub-native)', [
        'Copy templates/security.yml from the kit repository to overlays/<org>/templates/security.yml.',
        'Under `on:` add `schedule:` with one line `- cron: "23 4 * * 1"` (weekly, Monday 04:23 UTC; pick a quiet hour).',
        'Leave push and pull_request as they are: the schedule is in addition, not instead.',
        'Open a pull request on the kit repository; AppSec reviews it (CODEOWNERS); merge.',
        'In one pilot repository replace .github/workflows/security.yml with the overlay copy (keep its pinned SHA), '
        'then run it once by hand: Actions -> Security -> Run workflow. Keep the run link.']),
    'broader_queries': ('overlays/<org>/templates/security.yml with `codeql_queries: security-and-quality`; the kit '
                        'input already exists, so only the org default changes', [
        'In the org copy of the security caller (overlays/<org>/templates/security.yml) add under `with:` the line '
        '`codeql_queries: security-and-quality`.',
        'Open a pull request on the kit repository; AppSec reviews it; merge.',
        "Run one pilot repository's security caller by hand and compare its CodeQL finding count with the last run: "
        'more findings at lower precision is the expected trade.']),
    'signatures': ('overlays/<org>/docs/ORG_SETTINGS_ADOPTED.md (the application ruleset with required_signatures); '
                   'a neutral profile change only through a KDEC', [
        'Copy the "A consumer application repository" ruleset JSON from docs/adoption/BRANCH_PROTECTION_SETTINGS.md '
        'into overlays/<org>/docs/ORG_SETTINGS_ADOPTED.md and add `{"type": "required_signatures"}` to its rules.',
        'Write beside it which repositories already require signed commits (the evidence above) and the date.',
        'Open a pull request on the kit repository; AppSec reviews it; merge.',
        'Apply it to one pilot repository: Settings -> Rules -> Rulesets -> the main ruleset -> Require signed '
        'commits, or `gh api -X PUT repos/<org>/<repo>/rulesets/<id> --input ruleset.json`.',
        'Confirm every contributor of that repository can sign (git config commit.gpgsign true, or SSH signing) '
        'before turning it on wider.']),
    'linear': ('overlays/<org>/docs/ORG_SETTINGS_ADOPTED.md (required_linear_history on application repositories)', [
        'Add `{"type": "required_linear_history"}` to the overlay copy of the application ruleset '
        '(overlays/<org>/docs/ORG_SETTINGS_ADOPTED.md) and note the repositories that already require it.',
        'Open a pull request on the kit repository; AppSec reviews it; merge.',
        'Apply it to one pilot repository (Settings -> Rules -> Rulesets) and check its merge method is squash or rebase.']),
    'two_approvals': ('overlays/<org>/docs/ORG_SETTINGS_ADOPTED.md (required_approving_review_count 2 where the org '
                      'already asks for it)', [
        'In the overlay copy of the application ruleset set `"required_approving_review_count": 2` and write which '
        'kind of repository it applies to (two approvals on a team of two blocks every merge).',
        'Open a pull request on the kit repository; AppSec reviews it; merge.',
        'Apply it to one pilot repository and watch one pull request through.']),
    'wait_timer': ("overlays/<org>/docs/ORG_SETTINGS_ADOPTED.md (a production wait timer); kit init's environments "
                   'spec stays the neutral default', [
        'Write the wait timer the org already uses (the evidence above, in minutes) into '
        'overlays/<org>/docs/ORG_SETTINGS_ADOPTED.md for the prod row.',
        'For each repository after kit init: Settings -> Environments -> prod -> Wait timer -> the minutes, or '
        'edit the `gh api -X PUT repos/<org>/<repo>/environments/prod` command in .kit/ADOPTION_CHECKLIST.md: '
        '`"wait_timer":<minutes>`.',
        'Open a pull request on the kit repository for the overlay doc; AppSec reviews it; merge.']),
    'cooldown': ('overlays/<org>/docs/ORG_SETTINGS_ADOPTED.md (a Dependabot cooldown); a neutral generator change only '
                 'through a KDEC (GitHub-native)', [
        'In one pilot repository add under each `updates:` entry of .github/dependabot.yml: `cooldown:` then '
        "`default-days: 5` (the evidence repository's value).",
        "Run the kit's Dependabot config check (dependabot-config-check.yml) by hand: it must still pass.",
        'Write the setting and its evidence in overlays/<org>/docs/ORG_SETTINGS_ADOPTED.md; open a pull request; merge.']),
}


def proposal(cap, practice, res):
    native = _native(practice, cap)
    first = practice[0]
    tool = first['tool'] or cap['id']
    if res['verdict'] == ORG_BETTER:
        strengths = sorted(set(a for p in practice for a in p['attrs']) & set(STRENGTH_STEPS))
        where, steps = [], []
        for st in strengths:
            w, ss = STRENGTH_STEPS[st]
            where.append(w)
            steps += ['[%s] %s' % (st, x) for x in ss]
        return {'where': '; '.join(where), 'native': True, 'by_hand': steps}
    where = ("overlays/<org>/workflows/%s.yml (the org's practice, credited), and a neutral kit change only through "
             'a KDEC because it is GitHub- or Microsoft-native' % tool) if native else (
             'overlays/<org>/workflows/%s.yml and overlays/<org>/docs/%s.md ONLY: it is a vendor or proprietary '
             'practice, so it never enters the neutral kit' % (tool, tool.upper()))
    steps = [
        'Open %s in the evidence repository (%s) and copy the job that runs %s.' % (
            first['evidence'].split(':')[0], first['repo'], tool),
        "In the org's kit repository create overlays/<org>/workflows/%s.yml with that job as a reusable workflow "
        '(`on: workflow_call`), `permissions: {}` at the top and only what the job needs on the job.' % tool,
        'Pin every `uses:` by commit SHA: run `SEARCH_PATHS=overlays scripts/pin-actions.sh --apply` and keep the '
        '`# vX.Y.Z` comment it writes.',
        'Make it report, never pass silently: no `continue-on-error`, no `|| true`; write SARIF or JSON so the kit '
        'report can read it.',
        'Add a row to overlays/<org>/docs/ADOPTED_FROM_ORG.md: what, from which repository, credit, the date.',
        'Open a pull request on the kit repository; AppSec and the pipeline maintainers review it; merge.',
        'In one pilot repository add a job that calls the overlay workflow beside the kit caller, run it once by '
        'hand (Actions -> the workflow -> Run workflow), and keep the run link.',
    ]
    return {'where': where, 'native': native, 'by_hand': steps}


# ═════════════════════════════════════════════════════════════════════════════════════════════════
# THE WHOLE SURVEY
# ═════════════════════════════════════════════════════════════════════════════════════════════════

def owner_kind(client, owner):
    status, body, _ = client.get('/users/%s' % urllib.parse.quote(owner))
    if status in (401, 403):
        raise Refusal(SURVEY_AUTH_REFUSED, 'the API refused the token (HTTP %d) reading %s.' % (status, owner))
    if status != 200 or not isinstance(body, dict):
        raise Refusal(SURVEY_OWNER_NOT_FOUND, 'no organisation or user %r on this host (HTTP %s).' % (owner, status))
    return 'org' if body.get('type') == 'Organization' else 'user'


def list_repos(client, owner, kind, max_repos):
    if kind == 'org':
        return client.pages('/orgs/%s/repos' % owner, params={'type': 'all'}, limit=max_repos)
    status, me, _ = client.get('/user')
    if status == 200 and isinstance(me, dict) and (me.get('login') or '').lower() == owner.lower():
        st, items, trunc = client.pages('/user/repos', params={'affiliation': 'owner', 'visibility': 'all'},
                                        limit=max_repos)
        return st, items, trunc
    return client.pages('/users/%s/repos' % owner, params={'type': 'owner'}, limit=max_repos)


def run_survey(owner, host=None, api_url=None, token=None, kit_names=('secure-cicd-kit',), only=(),
               history=200, max_repos=1000, env=None):
    host, api_url = resolve_host(host, api_url, env)
    client = ReadOnlyClient(api_url, token)
    kind = owner_kind(client, owner)
    st, repos, trunc = list_repos(client, owner, kind, max_repos)
    if st != READ:
        raise Refusal(SURVEY_AUTH_REFUSED, 'the repository list of %s could not be read.' % owner)
    opts = {'kit_names': list(kit_names), 'history': history}
    rows = []
    for repo in repos:
        if only and repo.get('name') not in only:
            continue
        if not repo_host_matches(repo, host):
            raise Refusal(SURVEY_HOST_MISMATCH, 'the API answered for a repository on %s, not the named host %s.'
                          % (host_of(repo.get('html_url')), host))
        rows.append(survey_repo(client, owner, repo, opts))
    comparison, source = compare(rows)
    summary = totals(rows)
    partial = any(r['not_established'] for r in rows) or trunc
    return {'schema': 'kit-survey/1', 'owner': owner, 'owner_kind': kind, 'host': host,
            'generated': datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'state': SURVEY_PARTIAL if partial else SURVEY_COMPLETE, 'repo_list_truncated': trunc,
            'requests': client.calls, 'rows': rows, 'comparison': comparison, 'inventory_source': source,
            'totals': summary}


def totals(rows):
    counted = [r for r in rows if not r['is_kit'] and not r['archived'] and not r['fork']]
    deploying = [r for r in counted if r['deploy_targets']]

    def pct(n, d):
        return '%.0f%%' % (100.0 * n / d) if d else 'n/a (denominator 0)'
    by = {}
    for r in counted:
        by[r['adoption']] = by.get(r['adoption'], 0) + 1
    sup = [r for r in counted if r['adoption'] in (ADOPTED, PARTIAL)]
    sec = [r for r in counted if r['adoption'] == ADOPTED]
    dsup = [r for r in deploying if r['adoption'] in (ADOPTED, PARTIAL)]
    dsec = [r for r in deploying if r['adoption'] == ADOPTED]
    return {
        'denominator': len(counted), 'deploying_denominator': len(deploying),
        'excluded': {'kit_host': sum(1 for r in rows if r['is_kit']),
                     'archived': sum(1 for r in rows if r['archived'] and not r['is_kit']),
                     'fork': sum(1 for r in rows if r['fork'] and not r['archived'] and not r['is_kit'])},
        'by_state': by,
        'supported': len(sup), 'supported_pct': pct(len(sup), len(counted)),
        'secured': len(sec), 'secured_pct': pct(len(sec), len(counted)),
        'deploying_supported': len(dsup), 'deploying_supported_pct': pct(len(dsup), len(deploying)),
        'deploying_secured': len(dsec), 'deploying_secured_pct': pct(len(dsec), len(deploying)),
    }


# ═════════════════════════════════════════════════════════════════════════════════════════════════
# OUTPUT
# ═════════════════════════════════════════════════════════════════════════════════════════════════

CSV_COLUMNS = ['repo', 'visibility', 'archived', 'fork', 'default_branch', 'workflows', 'workflows_disabled',
               'actions_used', 'actions_unpinned', 'scanners', 'branch_protection', 'rulesets', 'environments',
               'codeowners', 'dependabot', 'secret_names', 'variable_names', 'kit_workflows', 'kit_pin',
               'adoption', 'adoption_level', 'turn_off_evidence', 'turn_off_reason', 'pain_point',
               'deploy_targets', 'not_established']


def _prot_text(r):
    if r['protection']:
        p = r['protection']
        return ', '.join(sorted(k for k, v in p.items() if v is True)) + (' approvals=%d' % p.get('approvals', 0)
                                                                             if p.get('reviews') else '')
    if NOT_ESTABLISHED in (r['protection_cell'], r['rulesets_cell']):
        return NOT_ESTABLISHED
    return 'none'


def csv_row(r):
    return {
        'repo': r['repo'], 'visibility': r['visibility'], 'archived': r['archived'], 'fork': r['fork'],
        'default_branch': r['default_branch'],
        'workflows': NOT_ESTABLISHED if r['workflows_cell'] == NOT_ESTABLISHED else len(r['workflows']),
        'workflows_disabled': ';'.join(r['workflows_disabled']),
        'actions_used': len(r['actions_used']), 'actions_unpinned': ';'.join(r['actions_unpinned']),
        'scanners': ';'.join(r['scanners']), 'branch_protection': _prot_text(r),
        'rulesets': NOT_ESTABLISHED if r['rulesets_cell'] == NOT_ESTABLISHED else ';'.join(r['rulesets']),
        'environments': NOT_ESTABLISHED if r['environments_cell'] == NOT_ESTABLISHED else ';'.join(
            '%s[rev=%d%s%s]' % (e['name'], e['reviewers'], ',noself' if e['prevent_self_review'] else '',
                                ',wait=%d' % e['wait_timer'] if e['wait_timer'] else '') for e in r['environments']),
        'codeowners': r['codeowners'], 'dependabot': r['dependabot'],
        'secret_names': ';'.join(r['secret_names']), 'variable_names': ';'.join(r['variable_names']),
        'kit_workflows': r.get('kit_workflows', ''), 'kit_pin': r.get('kit_pin', ''),
        'adoption': r['adoption'], 'adoption_level': r['adoption_level'],
        'turn_off_evidence': r['turn_off_evidence'], 'turn_off_reason': r['turn_off_reason'],
        'pain_point': r['pain_point'], 'deploy_targets': ';'.join(r['deploy_targets']),
        'not_established': ';'.join(r['not_established']),
    }


def write_outputs(result, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    rows = result['rows']
    with io.open(os.path.join(out_dir, 'KIT_SURVEY.csv'), 'w', encoding='utf-8', newline='') as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow(csv_row(r))
    t = result['totals']
    L = ['# Kit survey: %s (%s, %s)' % (result['owner'], result['owner_kind'], result['host']), '',
         'Generated %s by scripts/kit_survey.py, read-only. State: **%s**. %d repositories read, %d API requests.'
         % (result['generated'], result['state'], len(rows), result['requests']), '',
         'NOT_ESTABLISHED means the survey could not read that cell (a permission or rate limit), never "none".', '',
         '| repo | adoption | scanners already running | unpinned actions | protection | environments | deploys | not readable |',
         '|---|---|---|---|---|---|---|---|']
    for r in rows:
        c = csv_row(r)
        L.append('| %s | %s %s | %s | %d | %s | %s | %s | %s |' % (
            r['repo'], r['adoption'], r['adoption_level'], c['scanners'] or '-', len(r['actions_unpinned']),
            c['branch_protection'], c['environments'] or '-', c['deploy_targets'] or '-', c['not_established'] or '-'))
    L += ['', 'Secret and variable NAMES only are kept (KIT_SURVEY.csv); no value was read or written.', '']
    _w(out_dir, 'KIT_SURVEY.md', L)
    _w(out_dir, 'KIT_SURVEY_COMPARISON.md', comparison_md(result))
    _w(out_dir, 'KIT_ADOPTION_INVENTORY.md', inventory_md(result))
    with io.open(os.path.join(out_dir, 'kit-survey.json'), 'w', encoding='utf-8') as fh:
        json.dump(result, fh, indent=1, sort_keys=True, default=sorted)
    return t


def _w(d, name, lines):
    with io.open(os.path.join(d, name), 'w', encoding='utf-8', newline='\n') as fh:
        fh.write('\n'.join(lines) + '\n')


def comparison_md(result):
    L = ['# What the org already does, compared with the kit: %s' % result['owner'], '',
         'Per capability in the kit\'s inventory (%s plus its governance and external rows): KIT_BETTER, '
         'ORG_BETTER, EQUIVALENT, ORG_ONLY, KIT_ONLY, GAP or NOT_ESTABLISHED. The org\'s practice is read from '
         'its own workflows and settings, never from a kit caller. Proprietary or vendor practice is adopted into '
         'overlays/<org>/ only; the neutral kit takes only what is neutral or GitHub/Microsoft-native, through a KDEC.'
         % result['inventory_source'], '',
         '| capability | verdict | org repositories | the kit |', '|---|---|---|---|']
    for c in result['comparison']:
        L.append('| %s | **%s** | %d | %s |' % (c['title'], c['verdict'], len(c['repos']), 'yes' if c['kit_has'] else 'no'))
    for c in result['comparison']:
        L += ['', '## %s: %s' % (c['title'], c['verdict']), '', 'The kit: %s.' % c['how']]
        if c['evidence']:
            L.append('Evidence:')
            L += ['- %s: %s' % (e['repo'], e['evidence']) for e in c['evidence']]
        if c['credit']:
            L.append('Credit to the org:')
            L += ['- %s' % x for x in c['credit']]
        if c['kit_better']:
            L.append('Where the kit is stronger:')
            L += ['- %s' % x for x in c['kit_better']]
        if c['verdict'] == NOT_ESTABLISHED:
            L.append('The survey could not read this for any repository (a permission); grant read and re-run.')
        if c['verdict'] == GAP:
            L.append('Neither the org nor the kit does this. It is a kit gap to build, not a finding against the org.')
        p = c.get('proposal')
        if p:
            L += ['', '### Adopt via overlay', '', 'Where: %s.' % p['where'], '', '### How to do it by hand', '']
            L += ['%d. %s' % (i + 1, s) for i, s in enumerate(p['by_hand'])]
    return L


def inventory_md(result):
    t = result['totals']
    L = ['# Kit adoption inventory: %s' % result['owner'], '',
         'Denominator: **%d** repositories (not archived, not forks, not the kit itself; excluded: %d kit, %d '
         'archived, %d forks). A NOT_ESTABLISHED repository is IN the denominator and counted neither way.'
         % (t['denominator'], t['excluded']['kit_host'], t['excluded']['archived'], t['excluded']['fork']), '',
         '| measure | count | percent |', '|---|---|---|',
         '| supported by the kit (ADOPTED or PARTIAL), of all %d | %d | %s |' % (t['denominator'], t['supported'], t['supported_pct']),
         '| secured by the kit (ADOPTED), of all %d | %d | %s |' % (t['denominator'], t['secured'], t['secured_pct']),
         '| deploying repositories supported, of %d deploying | %d | %s |' % (t['deploying_denominator'], t['deploying_supported'], t['deploying_supported_pct']),
         '| deploying repositories secured, of %d deploying | %d | %s |' % (t['deploying_denominator'], t['deploying_secured'], t['deploying_secured_pct']),
         '', 'By state: %s' % ', '.join('%s %d' % kv for kv in sorted(t['by_state'].items())), '',
         '| repo | state | rung | kit pin | evidence | stated reason | pain point |', '|---|---|---|---|---|---|---|']
    for r in result['rows']:
        L.append('| %s | %s | %s | %s | %s | %s | %s |' % (
            r['repo'], r['adoption'], r['adoption_level'] or '-', r.get('kit_pin') or '-',
            (r['turn_off_evidence'] or '; '.join(r.get('partial_because') or []) or '-').replace('|', '/'),
            (r['turn_off_reason'] or '-').replace('|', '/').replace('\n', ' '), r['pain_point'] or '-'))
    L += ['', 'TURNED_OFF evidence is a commit, a job `if: false`, or a workflow disabled through the API. '
          'REASON_NOT_RECORDED means no commit message, pull request body or weakening record said why: ask the team.']
    return L


def _inside_kit(path):
    kit = os.path.normcase(os.path.abspath(ROOT))
    p = os.path.normcase(os.path.abspath(path))
    return p == kit or p.startswith(kit + os.sep)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--owner')
    ap.add_argument('--host')
    ap.add_argument('--api-url')
    ap.add_argument('--kit-repo', action='append', default=[], help='the kit repository NAME (repeatable)')
    ap.add_argument('--repo', action='append', default=[], help='survey only these repository names')
    ap.add_argument('--history', type=int, default=200, help='workflow-history commits read per repository')
    ap.add_argument('--max-repos', type=int, default=1000)
    ap.add_argument('--out')
    ap.add_argument('--allow-out-in-kit', action='store_true', help=argparse.SUPPRESS)
    ap.add_argument('--self-test', action='store_true')
    a = ap.parse_args(argv)
    if a.self_test:
        return self_test()
    if not a.owner or not a.out:
        ap.error('--owner and --out are required')
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('PyYAML is required (python3 -m pip install PyYAML)')
        return 2
    try:
        if _inside_kit(a.out) and not a.allow_out_in_kit:
            raise Refusal(SURVEY_OUT_IN_KIT, 'refusing to write the survey inside the kit (%s): it names private '
                          'repositories. Choose a directory outside the repository.' % os.path.normpath(a.out))
        token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN') or None
        result = run_survey(a.owner, a.host, a.api_url, token, a.kit_repo or ['secure-cicd-kit'], a.repo,
                            a.history, a.max_repos)
    except Refusal as e:
        print('%s\n  %s' % (e.state, e.detail))
        return 1
    t = write_outputs(result, a.out)
    print('%s: %d repositories; supported %s, secured %s of %d; deploying supported %s of %d. Written to %s'
          % (result['state'], len(result['rows']), t['supported_pct'], t['secured_pct'], t['denominator'],
             t['deploying_supported_pct'], t['deploying_denominator'], os.path.normpath(a.out)))
    return 0


def self_test():
    bad = []
    if api_for_host('acme.ghe.com') != 'https://api.acme.ghe.com' or api_for_host('ghes.example.com'):
        bad.append('api_for_host')
    for args, want in (((None, None, {}), SURVEY_HOST_NOT_NAMED),
                       (('ghes.example.com', None, {}), SURVEY_HOST_UNSUPPORTED),
                       (('acme.ghe.com', api_for_host('github.com'), {}), SURVEY_HOST_MISMATCH)):
        try:
            resolve_host(*args)
            bad.append('resolve_host %r did not refuse' % (args,))
        except Refusal as e:
            if e.state != want:
                bad.append('resolve_host %r -> %s' % (args, e.state))
    if resolve_host(None, None, {'GITHUB_API_URL': 'https://api.acme.ghe.com'}) != ('acme.ghe.com', 'https://api.acme.ghe.com'):
        bad.append('GITHUB_API_URL not read')
    if names_only([{'name': 'A', 'value': 'v'}]) != ['A']:
        bad.append('names_only kept a value')
    if cell(403) != NOT_ESTABLISHED or cell(404) != ABSENT:
        bad.append('cell')
    if stated_reason('Delete .github/workflows/security.yml', [])[0] != REASON_NOT_RECORDED:
        bad.append('a UI default message read as a reason')
    if 'too slow' not in stated_reason('Remove the kit scan: it takes 40 minutes', [])[1]:
        bad.append('pain point')
    print('kit_survey self-test: %s' % ('PASS' if not bad else 'FAIL ' + '; '.join(bad)))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
