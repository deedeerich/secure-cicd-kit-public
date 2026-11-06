#!/usr/bin/env python3
"""Prove a run's GitHub token is only ever sent to the API host that issued it, and that action refs
resolve without the REST API at all.

WHY THIS EXISTS (KDEC-027)

    `tests/check_pinned_artifacts.py` and `tests/check_action_pins.py --online` called
    `https://api.github.com` and attached `GITHUB_TOKEN` as a Bearer token, always. On GitHub
    Enterprise Cloud with data residency (`<tenant>.ghe.com`) the run's token is issued by
    `api.<tenant>.ghe.com`, so api.github.com answered 401, every action ref came back UNKNOWN, the
    self-test printed "SELF-TEST UNKNOWN" and exited 2 within seconds -- on every PR, Dependabot's
    included. It was also a credential-hygiene defect: a token sent to a host that did not issue it.
    And unauthenticated api.github.com allows 60 requests an hour per IP, which already produced an
    UNKNOWN on github.com once (run 39664961192, dorny/paths-filter@v4 "????").

    `scripts/reconcile_tickets.py`'s GitHub Issues backend had the same shape: api.github.com
    hard-coded, the run's GH_TOKEN attached.

WHAT IT PROVES (no network: subprocess and urllib are replaced, and sockets refuse)

    A  GITHUB_API_URL=https://api.example.ghe.com: no Authorization header reaches api.github.com,
       from either checker; and the ref still resolves (through git).
    B  GITHUB_API_URL=https://api.github.com (or unset, a laptop): the token IS attached when the
       REST path is used. PIN_CHECK_TOKEN_HOST naming another host withholds it.
    C  An API 401/403 does not decide anything: git resolves the ref. Git unreachable AND API 401 is
       UNKNOWN (None), never a pass.
    D  The git path says False for a nonexistent tag and a nonexistent SHA ("not our ref",
       "couldn't find remote ref"), None on a network error or timeout, and removes its temp dirs.
    E  A ref that starts with `-` never reaches git as an argument (it would be an option).
    F  The ticket backend's GitHub requests go to GITHUB_API_URL, not to api.github.com.

EXIT
    0  all hold
    1  a token crossed hosts, or a resolver answered wrongly
"""
import glob
import io
import os
import re
import socket
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

TOKEN = 'ghs_placeholder_not_a_real_token'
SHA_REAL = '11bd71901bbe5b1630ceea73d27597364c9af683'
SHA_FAKE = '1' * 40
FAILS = []


def check(cond, msg):
    print('  %s %s' % ('ok  ' if cond else 'FAIL', msg))
    if not cond:
        FAILS.append(msg)


def _no_socket(*a, **k):
    raise AssertionError('a real network connection was attempted: %r' % (a,))


socket.create_connection = _no_socket
socket.socket.connect = lambda self, *a, **k: _no_socket(*a)


class Net(object):
    """Scripted git and HTTP. `git` maps an action to (rc, stdout, stderr) or 'timeout'."""

    def __init__(self, git=None, api=200, api_body=None):
        self.git = git or {}
        self.api = api
        self.api_body = api_body
        self.requests = []      # (url, headers dict)
        self.git_calls = []
        self.tempdirs = []

    def run(self, args, **kw):
        args = list(args)
        self.git_calls.append(args)
        if 'init' in args:
            return subprocess.CompletedProcess(args, 0, '', '')
        if 'ls-remote' in args:
            out = self.git.get('ls-remote', (0, '', ''))
        elif 'fetch' in args:
            out = self.git.get('fetch', (0, '', ''))
        else:
            out = (0, '', '')
        if out == 'timeout':
            raise subprocess.TimeoutExpired(args, kw.get('timeout') or 1)
        rc, so, se = out
        return subprocess.CompletedProcess(args, rc, so, se)

    def urlopen(self, req, timeout=None, **kw):
        url = req.full_url if hasattr(req, 'full_url') else str(req)
        hdrs = dict((k.lower(), v) for k, v in req.header_items()) if hasattr(req, 'header_items') else {}
        self.requests.append((url, hdrs))
        if 'hub.docker.com' in url:
            body = b'{"name": "x"}'
        elif self.api != 200:
            raise urllib.error.HTTPError(url, self.api, 'stub', {}, io.BytesIO(b'{}'))
        else:
            body = (self.api_body or b'{}')
        return _Resp(body)

    def mkdtemp(self, *a, **k):
        d = _real_mkdtemp(*a, **k)
        self.tempdirs.append(d)
        return d

    def tokens_sent_to(self, host):
        return [h.get('authorization') for u, h in self.requests
                if u.split('/')[2].lower() == host and h.get('authorization')]


class _Resp(io.BytesIO):
    status = 200
    headers = {}

    def getcode(self):
        return 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


_real_mkdtemp = tempfile.mkdtemp
_real_run = subprocess.run
_real_urlopen = urllib.request.urlopen
ENV_KEYS = ('GITHUB_TOKEN', 'GH_TOKEN', 'GITHUB_API_URL', 'PIN_CHECK_TOKEN_HOST')


def scenario(net, env):
    saved = dict((k, os.environ.get(k)) for k in ENV_KEYS)
    for k in ENV_KEYS:
        os.environ.pop(k, None)
    os.environ.update(env)
    subprocess.run = net.run
    urllib.request.urlopen = net.urlopen
    tempfile.mkdtemp = net.mkdtemp

    def restore():
        subprocess.run = _real_run
        urllib.request.urlopen = _real_urlopen
        tempfile.mkdtemp = _real_mkdtemp
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return restore


def run(net, env, fn, *a):
    restore = scenario(net, env)
    try:
        return fn(*a)
    finally:
        restore()


LS_V4 = (0, '%s\trefs/tags/v4\n' % SHA_REAL, '')
LS_ANNOTATED = (0, 'd4ca2e3147b409459955613c152220f4db848ee1\trefs/tags/v9\n'
                   '%s\trefs/tags/v9^{}\n' % SHA_REAL, '')
NET_DOWN = (128, '', "fatal: unable to access 'https://github.com/a/b/': Could not resolve host: github.com\n")
NOT_OUR_REF = (128, '', 'fatal: remote error: upload-pack: not our ref %s\n' % SHA_FAKE)
NO_REMOTE_REF = (128, '', 'fatal: couldn\'t find remote ref %s\n' % SHA_FAKE)
REF_BODY = b'{"ref": "refs/tags/v4", "object": {"type": "commit", "sha": "%s"}}' % SHA_REAL.encode()
GHE = {'GITHUB_TOKEN': TOKEN, 'GITHUB_API_URL': 'https://api.example.ghe.com'}
DOTCOM = {'GITHUB_TOKEN': TOKEN, 'GITHUB_API_URL': 'https://api.github.com'}


GH_CALL = re.compile(r'(^|[\s;(|&$"\'=])gh\s+(api|run|attestation|pr|issue|release|workflow|repo|label|'
                     r'secret|variable|cache|search)\b', re.M)
GH_HOST_SET = re.compile(r'\bGH_HOST=')
SHIPPED = ['.github/workflows/*.yml', '.github/actions/**/action.yml', 'templates/**/*.yml',
           'overlays/**/*.yml']


def gh_steps_without_host(root=ROOT):
    """Steps that hand gh a token and do not name the host. `gh api PATH`, `-R owner/repo` and
    `--repo owner/repo` resolve against github.com unless GH_HOST says otherwise, so on a GHE.com
    tenant the run's token would go to api.github.com."""
    import yaml
    out = []
    for pat in SHIPPED:
        for f in sorted(glob.glob(os.path.join(root, pat), recursive=True)):
            try:
                doc = yaml.safe_load(io.open(f, encoding='utf-8').read()) or {}
            except Exception:  # noqa: BLE001 - a file that does not parse is another check's job
                continue
            if not isinstance(doc, dict):
                continue
            wenv = doc.get('env') or {}
            groups = []
            for job in (doc.get('jobs') or {}).values():
                if isinstance(job, dict):
                    groups.append((dict(wenv, **(job.get('env') or {})), job.get('steps') or []))
            runs = doc.get('runs')
            if isinstance(runs, dict):
                groups.append((wenv, runs.get('steps') or []))
            for env, steps in groups:
                for st in steps:
                    if not isinstance(st, dict) or not isinstance(st.get('run'), str):
                        continue
                    run = '\n'.join(ln for ln in st['run'].split('\n')
                                    if not ln.lstrip().startswith('#'))
                    m = GH_CALL.search(run)
                    if not m:
                        continue
                    senv = dict(env, **(st.get('env') or {}))
                    if 'GH_HOST' in senv or not ({'GH_TOKEN', 'GITHUB_TOKEN'} & set(senv)):
                        continue
                    h = GH_HOST_SET.search(run)
                    if h and h.start() < m.start():
                        continue
                    out.append('%s: step "%s"' % (os.path.relpath(f, root).replace('\\', '/'),
                                                   st.get('name') or st.get('id') or '?'))
    return out


def main():
    import check_pinned_artifacts as cpa
    import check_action_pins as cap

    print('A  a ghe.com token never reaches api.github.com')
    for name, git in (('git up', {'ls-remote': LS_V4}), ('git down', {'ls-remote': NET_DOWN})):
        net = Net(git=git, api=401)
        r = run(net, GHE, cpa.action_resolves, 'actions/checkout', 'v4')
        check(not net.tokens_sent_to('api.github.com'),
              'check_pinned_artifacts, %s: no Authorization to api.github.com (sent %d)'
              % (name, len(net.tokens_sent_to('api.github.com'))))
        check(r is (True if name == 'git up' else None),
              'check_pinned_artifacts, %s: resolves %r' % (name, r))
        net = Net(git=git, api=401)
        r = run(net, GHE, cap.tag_commit, 'actions/checkout', 'v4')
        check(not net.tokens_sent_to('api.github.com'),
              'check_action_pins, %s: no Authorization to api.github.com' % name)
        check(r == (SHA_REAL if name == 'git up' else None), 'check_action_pins, %s: -> %r' % (name, r))
    net = Net(git={'fetch': NET_DOWN}, api=401)
    run(net, GHE, cpa.action_resolves, 'actions/checkout', SHA_REAL)
    check(not net.tokens_sent_to('api.github.com'), 'SHA path, git down: no Authorization to api.github.com')
    net = Net(git={'ls-remote': NET_DOWN})
    run(net, dict(GHE, GITHUB_API_URL='https://api.github.com/', PIN_CHECK_TOKEN_HOST='api.example.ghe.com'),
        cpa.action_resolves, 'actions/checkout', 'v4')
    check(not net.tokens_sent_to('api.github.com'),
          'PIN_CHECK_TOKEN_HOST naming another host withholds the token')
    net = Net(git={'ls-remote': NET_DOWN})
    run(net, {'GH_TOKEN': TOKEN, 'GITHUB_API_URL': 'https://api.example.ghe.com'},
        cpa.action_resolves, 'actions/checkout', 'v4')
    check(not net.tokens_sent_to('api.github.com'), 'GH_TOKEN is held to the same rule')
    check(all(u.split('/')[2] in ('api.github.com', 'hub.docker.com') for u, _ in net.requests),
          'no request to any other host')

    print('B  a github.com token is attached on the REST path')
    for env in (DOTCOM, {'GITHUB_TOKEN': TOKEN}):
        net = Net(git={'ls-remote': NET_DOWN}, api=200, api_body=REF_BODY)
        r = run(net, env, cpa.action_resolves, 'actions/checkout', 'v4')
        sent = net.tokens_sent_to('api.github.com')
        check(sent and sent[0] == 'Bearer ' + TOKEN,
              'GITHUB_API_URL=%s: Bearer token attached' % env.get('GITHUB_API_URL', '(unset)'))
        check(r is True, 'and the API resolves it (%r)' % r)
        net = Net(git={'ls-remote': NET_DOWN}, api=200, api_body=REF_BODY)
        r = run(net, env, cap.tag_commit, 'actions/checkout', 'v4')
        check(net.tokens_sent_to('api.github.com') and r == SHA_REAL,
              'check_action_pins: token attached, -> %r' % r)

    print('C  an API 401/403 falls back to git; both failing is UNKNOWN')
    for code in (401, 403):
        net = Net(git={'ls-remote': LS_V4}, api=code)
        check(run(net, DOTCOM, cpa.action_resolves, 'actions/checkout', 'v4') is True,
              'API %d, git resolves the tag -> True' % code)
        net = Net(git={'fetch': (0, '', '')}, api=code)
        check(run(net, DOTCOM, cpa.action_resolves, 'actions/checkout', SHA_REAL) is True,
              'API %d, git fetches the SHA -> True' % code)
        net = Net(git={'ls-remote': NET_DOWN}, api=code)
        check(run(net, DOTCOM, cpa.action_resolves, 'actions/checkout', 'v4') is None,
              'API %d and git down -> None (UNKNOWN), never True' % code)
        net = Net(git={'ls-remote': LS_V4}, api=code)
        check(run(net, DOTCOM, cap.tag_commit, 'actions/checkout', 'v4') == SHA_REAL,
              'check_action_pins: API %d, git resolves' % code)

    print('D  the git path can say NO, and says UNKNOWN when it cannot see')
    net = Net(git={'ls-remote': (0, '', '')}, api=401)
    check(run(net, GHE, cpa.action_resolves, 'actions/checkout', 'v0.0.0-nope') is False,
          'nonexistent tag -> False')
    net = Net(git={'ls-remote': (0, '%s\trefs/tags/v4.2\n' % SHA_REAL, '')}, api=401)
    check(run(net, GHE, cpa.action_resolves, 'actions/checkout', 'v4') is False,
          'a different tag that merely shares a prefix -> False (exact match)')
    net = Net(git={'ls-remote': (0, '%s\trefs/heads/main\n' % SHA_REAL, '')}, api=401)
    check(run(net, GHE, cpa.action_resolves, 'actions/checkout', 'main') is True, 'a branch -> True')
    for label, out in (('not our ref', NOT_OUR_REF), ("couldn't find remote ref", NO_REMOTE_REF)):
        net = Net(git={'fetch': out}, api=401)
        check(run(net, GHE, cpa.action_resolves, 'actions/checkout', SHA_FAKE) is False,
              'nonexistent SHA (%s) -> False' % label)
        check(net.tempdirs and not any(os.path.exists(d) for d in net.tempdirs),
              'temp repo removed (%d made)' % len(net.tempdirs))
    for label, out in (('network error', NET_DOWN), ('timeout', 'timeout')):
        net = Net(git={'fetch': out, 'ls-remote': out}, api=401)
        check(run(net, GHE, cpa.action_resolves, 'actions/checkout', SHA_FAKE) is None,
              'SHA, %s -> None' % label)
        check(run(net, GHE, cpa.action_resolves, 'actions/checkout', 'v4') is None,
              'tag, %s -> None' % label)
        check(not any(os.path.exists(d) for d in net.tempdirs), 'temp repo removed after %s' % label)
    net = Net(git={'ls-remote': LS_ANNOTATED})
    check(run(net, GHE, cap.tag_commit, 'actions/checkout', 'v9') == SHA_REAL,
          'check_action_pins: an annotated tag is peeled to its commit')
    net = Net(git={'ls-remote': (0, '', '')})
    check(run(net, GHE, cap.tag_commit, 'actions/checkout', 'v0.0.0-nope') is False,
          'check_action_pins: nonexistent tag -> False')
    net = Net(git={'ls-remote': LS_V4}, api=401)
    calls = net.git_calls
    run(net, GHE, cpa.action_resolves, 'actions/checkout', 'v4')
    lsr = [c for c in calls if 'ls-remote' in c]
    check(lsr and 'https://github.com/actions/checkout' in lsr[0]
          and 'refs/tags/v4' in lsr[0] and 'refs/heads/v4' in lsr[0],
          'git ls-remote is asked for the exact tag and branch at github.com')
    check(lsr and any('credential.helper=' in a for a in lsr[0]),
          'git runs with no credential helper (no credential leaves with it)')

    print('E  a ref that looks like an option never reaches git')
    net = Net(git={'ls-remote': LS_V4})
    r = run(net, GHE, cpa.action_resolves, 'actions/checkout', '--upload-pack=x')
    check(r is None and not net.git_calls, 'ref "--upload-pack=x" -> None, git not run')

    print('F  the ticket backend sends GH_TOKEN to GITHUB_API_URL only')
    import reconcile_tickets as rt
    env = {'TICKET_BACKEND': 'github', 'GH_TOKEN': TOKEN, 'TICKET_REPO': 'o/r',
           'TICKET_STAMP_LABEL': 'kit', 'GITHUB_API_URL': 'https://api.example.ghe.com'}
    b, note = rt.choose_backend(env)
    net = Net(api=200, api_body=b'{"has_issues": true}')
    restore = scenario(net, {})
    try:
        b.probe()
    finally:
        restore()
    check(net.requests and not net.tokens_sent_to('api.github.com'),
          'ticket backend on ghe.com: no Authorization to api.github.com')
    check(net.requests and net.requests[0][0].startswith('https://api.example.ghe.com/repos/o/r'),
          'ticket backend asks the issuing host (%s)' % (net.requests[0][0] if net.requests else '-'))
    b, _ = rt.choose_backend(dict(env, GITHUB_API_URL=''))
    net = Net(api=200, api_body=b'{"has_issues": true}')
    restore = scenario(net, {})
    try:
        b.probe()
    finally:
        restore()
    check(net.requests and net.requests[0][0].startswith('https://api.github.com/repos/o/r'),
          'unset GITHUB_API_URL: api.github.com, as before')

    print('G  every `gh` step names its host (gh api / -R / --repo default to github.com)')
    bare = gh_steps_without_host()
    for where in bare:
        print('       %s' % where)
    check(not bare, '%d step(s) run gh with a token and no GH_HOST' % len(bare))

    print()
    if FAILS:
        print('FAIL: %d check(s): a token crossed hosts or a resolver answered wrongly.' % len(FAILS))
        return 1
    print('PASS: the run token stays on its issuing host; refs resolve through git; UNKNOWN never passes.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
