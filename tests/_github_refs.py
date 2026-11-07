"""Resolve GitHub action refs without sending a token anywhere it was not issued (KDEC-027).

Shared by tests/check_pinned_artifacts.py and tests/check_action_pins.py.

PRIMARY PATH: GIT, NO TOKEN, NO REST RATE LIMIT
    A tag or branch:  `git ls-remote https://github.com/<owner>/<repo> refs/tags/<ref>
                       refs/tags/<ref>^{} refs/heads/<ref>`, matched exactly (no prefix).
    A full SHA:       `git fetch --depth=1 --filter=tree:0 <url> <sha>` into a temporary bare
                      repository. Success: the commit exists. "not our ref" / "couldn't find remote
                      ref": it does not. Anything else (network, timeout, a private or missing
                      repository): unknown.
    Git runs in a temporary directory with no system or global config, no credential helper, no
    extra headers and prompts disabled, so it never carries a credential -- including the
    `http.<server>.extraheader` that actions/checkout writes into the job's repository.

SECONDARY PATH: THE REST API, ONLY WITH A TOKEN IT ISSUED
    A run's GITHUB_TOKEN / GH_TOKEN is issued by the run's API host ($GITHUB_API_URL). On GitHub
    Enterprise Cloud with data residency that is `api.<tenant>.ghe.com`, and api.github.com answers
    401 to it. The token goes to api.github.com only when every statement of its issuer --
    $GITHUB_API_URL, and $PIN_CHECK_TOKEN_HOST when set -- names api.github.com; unset means a
    developer's own github.com token. It is never sent to any other host. Without such a token the
    REST path is not used at all (unauthenticated is 60 requests an hour per IP).

Unknown stays unknown (None), and None is never a pass -- and an UNKNOWN NAMES ITS CAUSE
(2026-11-02, KNOWN_DEFECTS D-11): every failed git or REST lookup is recorded, classified the way
scripts/api_token_cause.sh classifies it (JOB_TOKEN_REJECTED, ORG_IP_ALLOW_LIST_BLOCKS_RUNNER,
ORG_SSO_BLOCKS_TOKEN, RATE_LIMITED, API_UNREACHABLE, TOKEN_PREFLIGHT_UNCLASSIFIED), and explain()
says which, so a 401 is never reported as "rate-limited". tests/prove_job_token_named.py T2/T7.

A LOOKUP THAT DID NOT OBSERVE IS RETRIED, BOUNDEDLY (2026-11-04). Dependabot PR #5 sat red on the
required check `Normalizer drift` because ONE lookup of a ref that exists (dorny/paths-filter@v4,
run 39664961192) did not answer, and every lookup was a single attempt. Now a TRANSIENT failure -- a
git call that timed out or could not reach the host (API_UNREACHABLE), or a REST call with no HTTP
answer or a 5xx -- is tried up to ATTEMPTS times with a short pause (BACKOFF seconds). An ANSWER is
never retried: "not our ref", a 404, a 401/403/429, an SSO or allow-list refusal are observations.
After the last attempt the result is still None -- UNKNOWN, never a pass. And once one lookup on a
channel (git, REST) has failed every attempt, that channel is DOWN for the rest of the run: later
lookups make one attempt each, so a runner with no route to github.com reports UNKNOWN in seconds per
ref instead of retrying every pin. reset() closes the breaker. tests/prove_dependabot_bump_mergeable.py M4.

PIN_CHECK_GITHUB_COM_TOKEN, when set, is a token github.com issued (a separate secret, optional):
it is sent to api.github.com only, and used instead of the run's token on a run whose own token
another host issued. Never required: the git path needs no token.
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

GITHUB_API = 'https://api.github.com'
GITHUB_GIT = 'https://github.com'
REPO_RE = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')
REF_RE = re.compile(r'^[A-Za-z0-9_.][A-Za-z0-9_./-]*$')
SHA40 = re.compile(r'^[0-9a-f]{40}$')
GIT_TIMEOUT = 60
ATTEMPTS = 3
BACKOFF = (2, 5)
_sleep = time.sleep
# Channels that failed every attempt once in this run: no more retries on them (the breaker).
_DOWN = set()


def _pause(attempt):
    _sleep(BACKOFF[min(attempt, len(BACKOFF) - 1)])


def _attempts(channel):
    return 1 if channel in _DOWN else ATTEMPTS


def _transient_git(out):
    """A git result worth another try: no result at all, or a failure classified as unreachable or
    as a 5xx. An authentication, SSO, allow-list or rate-limit answer is an observation."""
    if out is None:
        return True
    if out[0] == 0:
        return False
    err = out[2] or ''
    return api_cause(None, err) == 'API_UNREACHABLE' or bool(re.search(r'\b5\d\d\b', err))
# What git says when the server has no such object. Everything else is not an observation.
MISSING_OBJECT = ('not our ref', "couldn't find remote ref", 'unadvertised object')


def _rmtree(path):
    """Remove a temp dir; git marks pack files read-only, which Windows refuses to delete."""
    def onerror(func, p, _exc):
        try:
            os.chmod(p, 0o700)
            func(p)
        except OSError:
            pass
    shutil.rmtree(path, onerror=onerror)


def _host(url):
    u = (url or '').strip().lower()
    if '://' in u:
        u = u.split('://', 1)[1]
    return u.split('/', 1)[0]


def api_token(env=None):
    """The run's token, if and only if api.github.com issued it; else None. A separate
    PIN_CHECK_GITHUB_COM_TOKEN (github.com-issued by definition) wins when set."""
    env = os.environ if env is None else env
    if env.get('PIN_CHECK_GITHUB_COM_TOKEN'):
        return env.get('PIN_CHECK_GITHUB_COM_TOKEN')
    token = env.get('GITHUB_TOKEN') or env.get('GH_TOKEN')
    if not token:
        return None
    issuers = [env.get(k) for k in ('GITHUB_API_URL', 'PIN_CHECK_TOKEN_HOST') if env.get(k)]
    if any(_host(i) != 'api.github.com' for i in issuers):
        return None
    return token


def valid(repo, ref):
    """A ref that would read as a git option, or a repo that is not owner/name, is never run."""
    return bool(REPO_RE.match(repo or '')) and bool(REF_RE.match(ref or '')) and '..' not in ref


# What failed, for explain(): {'git': [cause, ...], 'api': [(cause, status), ...], 'no_token': bool}
_SEEN = {'git': [], 'api': [], 'no_token': False}

_ADVICE = {
    'JOB_TOKEN_REJECTED': 'organisation owner, then workflow maintainer: GitHub answered 401 Bad '
                          'credentials. Check that GITHUB_API_URL is api.github.com (a ghe.com '
                          "run's token is never sent there, KDEC-027), the organisation IP allow "
                          'list, Actions workflow permissions, and a proxy stripping Authorization',
    'ORG_IP_ALLOW_LIST_BLOCKS_RUNNER': "organisation owner: the IP allow list refuses this runner's address",
    'ORG_SSO_BLOCKS_TOKEN': 'organisation owner: SAML single sign-on refuses the token; authorise it for SSO',
    'RATE_LIMITED': 'workflow maintainer: the REST rate limit is spent; re-run after the reset',
    'API_UNREACHABLE': "runner administrator: no answer from github.com; check the runner's egress, proxy and DNS",
    'TOKEN_PREFLIGHT_UNCLASSIFIED': 'workflow maintainer: refused for a reason the kit does not classify',
}


def api_cause(status, text):
    """The word scripts/api_token_cause.sh (kit_api_cause) gives the same answer. `status` is the
    HTTP status, or None when there was no HTTP answer."""
    t = (('http %d ' % status) if status else '') + (text or '')
    t = t.lower()
    if 'ip allow list' in t or 'ip allowlist' in t:
        return 'ORG_IP_ALLOW_LIST_BLOCKS_RUNNER'
    if 'saml' in t or 'single sign-on' in t:
        return 'ORG_SSO_BLOCKS_TOKEN'
    if 'rate limit' in t or 'http 429' in t:
        return 'RATE_LIMITED'
    if 'bad credentials' in t or 'http 401' in t or 'requires authentication' in t:
        return 'JOB_TOKEN_REJECTED'
    if re.search(r'http [45][0-9][0-9]', t):
        return 'TOKEN_PREFLIGHT_UNCLASSIFIED'
    if any(w in t for w in ('could not resolve', 'no such host', 'name resolution', 'getaddrinfo',
                            'connection refused', 'timed out', 'timeout', 'error connecting',
                            'dial tcp', 'network is unreachable', 'connection reset',
                            'failed to connect', 'proxyconnect', 'urlopen error')):
        return 'API_UNREACHABLE'
    return 'TOKEN_PREFLIGHT_UNCLASSIFIED'


def reset():
    _SEEN['git'], _SEEN['api'], _SEEN['no_token'] = [], [], False
    _DOWN.clear()


def explain():
    """One line: why lookups were UNKNOWN. Cause words, statuses and fixed text only -- nothing a
    server sent is repeated."""
    parts = []
    if _SEEN['git']:
        parts.append('git to github.com: %s' % ', '.join(sorted(set(_SEEN['git']))))
    if _SEEN['api']:
        seen = sorted(set(_SEEN['api']), key=lambda x: (x[0], x[1] or 0))
        parts.append('REST api.github.com: %s' % ', '.join(
            '%s (%s)' % (c, 'HTTP %d' % s if s else 'no HTTP answer') for c, s in seen))
        for c in sorted({c for c, _ in seen}):
            parts.append('%s -- %s' % (c, _ADVICE.get(c, _ADVICE['TOKEN_PREFLIGHT_UNCLASSIFIED'])))
    elif _SEEN['no_token']:
        parts.append('REST not used: no token api.github.com issued (GITHUB_API_URL=%s; a run token is '
                     'never sent to another host, KDEC-027; set PIN_CHECK_GITHUB_COM_TOKEN for a '
                     'github.com fallback)' % (os.environ.get('GITHUB_API_URL') or 'unset'))
    return '; '.join(parts) or 'no failed lookup was recorded'


def api_get(path, user_agent, timeout=15):
    """-> (status, json-or-None). (None, None) when there is no token api.github.com issued: the
    REST path is then not taken at all. A failure is recorded with its cause for explain()."""
    token = api_token()
    if not token:
        _SEEN['no_token'] = True
        return None, None
    headers = {'User-Agent': user_agent, 'Accept': 'application/vnd.github+json',
               'Authorization': 'Bearer ' + token}
    n = _attempts('api')
    for attempt in range(n):
        last = attempt == n - 1
        try:
            req = urllib.request.Request(GITHUB_API + path, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.getcode(), json.load(r)
        except urllib.error.HTTPError as e:
            if e.code >= 500 and not last:
                _pause(attempt)
                continue
            if e.code >= 500 and n > 1:
                _DOWN.add('api')
            if e.code != 404:
                try:
                    body = e.read().decode('utf-8', 'replace')[:2000]
                except Exception:  # noqa: BLE001
                    body = ''
                _SEEN['api'].append((api_cause(e.code, body), e.code))
            return e.code, None
        except Exception as e:  # noqa: BLE001 - network trouble is a status of None, never a verdict
            if not last:
                _pause(attempt)
                continue
            if n > 1:
                _DOWN.add('api')
            _SEEN['api'].append((api_cause(None, str(e)), None))
            return None, None
    return None, None


def _git_env():
    env = dict(os.environ)
    for k in list(env):
        if k.startswith('GIT_CONFIG_') or k in ('GIT_ASKPASS', 'SSH_ASKPASS', 'GIT_DIR',
                                                 'GIT_WORK_TREE', 'GITHUB_TOKEN', 'GH_TOKEN'):
            env.pop(k, None)
    env.update(GIT_TERMINAL_PROMPT='0', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
    return env


def _git(args, cwd, timeout):
    """-> (rc, stdout, stderr), or None when git could not be run or timed out."""
    cmd = ['git', '-c', 'credential.helper=', '-c', 'http.extraHeader=',
           '-c', 'protocol.allow=never', '-c', 'protocol.https.allow=always'] + args
    try:
        p = subprocess.run(cmd, cwd=cwd, env=_git_env(), capture_output=True, text=True,
                           timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return None
    return p.returncode, p.stdout or '', p.stderr or ''


def ls_remote(repo, ref, timeout=GIT_TIMEOUT):
    """-> {refname: sha} for the exact tag (and its peeled commit) and branch, or None."""
    if not valid(repo, ref):
        return None
    out = None
    n = _attempts('git')
    for attempt in range(n):
        tmp = tempfile.mkdtemp(prefix='pin-ls-')
        try:
            out = _git(['ls-remote', '%s/%s' % (GITHUB_GIT, repo), 'refs/tags/' + ref,
                        'refs/tags/%s^{}' % ref, 'refs/heads/' + ref], tmp, timeout)
        finally:
            _rmtree(tmp)
        if not _transient_git(out):
            break
        if attempt < n - 1:
            _pause(attempt)
        elif n > 1:
            _DOWN.add('git')
    if out is None or out[0] != 0:
        _SEEN['git'].append('API_UNREACHABLE' if out is None else api_cause(None, out[2]))
        return None
    refs = {}
    for line in out[1].splitlines():
        parts = line.strip().split('\t')
        if len(parts) == 2 and SHA40.match(parts[0]):
            refs[parts[1]] = parts[0]
    return refs


def ref_resolves(repo, ref, timeout=GIT_TIMEOUT):
    """Tag or branch: True / False / None, exact match only."""
    refs = ls_remote(repo, ref, timeout)
    if refs is None:
        return None
    return ('refs/tags/' + ref) in refs or ('refs/heads/' + ref) in refs


def tag_commit(repo, tag, timeout=GIT_TIMEOUT):
    """-> the commit a tag names (annotated tags peeled), False if no such tag, None if unknown."""
    refs = ls_remote(repo, tag, timeout)
    if refs is None:
        return None
    return refs.get('refs/tags/%s^{}' % tag) or refs.get('refs/tags/' + tag) or False


def commit_exists(repo, sha, timeout=GIT_TIMEOUT):
    """Full SHA: True / False / None."""
    if not valid(repo, sha) or not SHA40.match(sha):
        return None
    tmp = tempfile.mkdtemp(prefix='pin-sha-')
    try:
        bare = os.path.join(tmp, 'r.git')
        init = _git(['init', '-q', '--bare', bare], tmp, timeout)
        if init is None or init[0] != 0:
            return None
        n = _attempts('git')
        for attempt in range(n):
            out = _git(['-C', bare, 'fetch', '-q', '--no-tags', '--depth=1', '--filter=tree:0',
                        '%s/%s' % (GITHUB_GIT, repo), sha], tmp, timeout)
            if out is not None and any(m in out[2].lower() for m in MISSING_OBJECT):
                break
            if not _transient_git(out):
                break
            if attempt < n - 1:
                _pause(attempt)
            elif n > 1:
                _DOWN.add('git')
    finally:
        _rmtree(tmp)
    if out is None:
        _SEEN['git'].append('API_UNREACHABLE')
        return None
    if out[0] == 0:
        return True
    if any(m in out[2].lower() for m in MISSING_OBJECT):
        return False
    _SEEN['git'].append(api_cause(None, out[2]))
    return None
