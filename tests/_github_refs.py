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

Unknown stays unknown (None), and None is never a pass.
"""
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request

GITHUB_API = 'https://api.github.com'
GITHUB_GIT = 'https://github.com'
REPO_RE = re.compile(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')
REF_RE = re.compile(r'^[A-Za-z0-9_.][A-Za-z0-9_./-]*$')
SHA40 = re.compile(r'^[0-9a-f]{40}$')
GIT_TIMEOUT = 60
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
    """The run's token, if and only if api.github.com issued it; else None."""
    env = os.environ if env is None else env
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


def api_get(path, user_agent, timeout=15):
    """-> (status, json-or-None). (None, None) when there is no token api.github.com issued: the
    REST path is then not taken at all."""
    token = api_token()
    if not token:
        return None, None
    headers = {'User-Agent': user_agent, 'Accept': 'application/vnd.github+json',
               'Authorization': 'Bearer ' + token}
    try:
        req = urllib.request.Request(GITHUB_API + path, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.getcode(), json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception:  # noqa: BLE001 - network trouble is a status of None, never a verdict
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
    tmp = tempfile.mkdtemp(prefix='pin-ls-')
    try:
        out = _git(['ls-remote', '%s/%s' % (GITHUB_GIT, repo), 'refs/tags/' + ref,
                    'refs/tags/%s^{}' % ref, 'refs/heads/' + ref], tmp, timeout)
    finally:
        _rmtree(tmp)
    if out is None or out[0] != 0:
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
        out = _git(['-C', bare, 'fetch', '-q', '--no-tags', '--depth=1', '--filter=tree:0',
                    '%s/%s' % (GITHUB_GIT, repo), sha], tmp, timeout)
    finally:
        _rmtree(tmp)
    if out is None:
        return None
    if out[0] == 0:
        return True
    if any(m in out[2].lower() for m in MISSING_OBJECT):
        return False
    return None
