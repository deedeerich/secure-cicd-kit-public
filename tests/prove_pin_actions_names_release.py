#!/usr/bin/env python3
"""scripts/pin-actions.sh writes the EXACT release beside the SHA, so its output passes the kit's
own pin check (ledger L82, lane L-H follow-up).

WHY THIS EXISTS

    pin-actions.sh resolved `owner/repo@v7` to a commit and wrote `# v7` beside it: the moving major
    it had just replaced, as the comment. tests/check_action_pins.py refuses that comment (P2) --
    a reader, and Dependabot, need the release the SHA IS, not the pointer that happened to name it
    that day. So the kit's own tool produced output the kit's own gate rejects, and the L-H sweep
    had to resolve exact releases by hand.

    It also exempted `actions,github,azure,docker,hashicorp` by default. The kit pins every owner
    (PINNING.md, "Current state"); a tool whose default leaves the most-used actions on tags cannot
    produce a tree the kit would accept.

WHAT IT PROVES (offline: a local stand-in for the GitHub REST API on 127.0.0.1, via GITHUB_API_URL)
    A1  a major tag (`@v2`) is rewritten to its commit with `# v2.3.1`, the exact release tag at
        that commit, found on the SECOND page of tags (pagination is followed)
    A2  an exact tag (`@v1.0.4`) keeps its own name as the comment
    A3  a composite's step is rewritten the same way
    A4  with TRUSTED_ORGS unset, `actions/checkout@v7` is pinned too: no owner exempt by default
    A5  the rewritten files pass tests/check_action_pins.py's per-file rules (P1, P2)
    A6  a tag whose commit carries NO exact release is refused (exit 1) and its line left as it was
        -- never written with a moving-major comment

EXIT  0 all hold   1 any does not   2 could not be checked (no bash, curl or jq)
"""
import http.server
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

S_TOOL = '1' * 40
S_OLD = '2' * 40
S_EXACT = '3' * 40
# The commit check_action_pins.py's table records for actions/checkout v7.0.1, so its P3 spot check
# applies to this stand-in exactly as it does to the real tree.
S_CO = '3d3c42e5aac5ba805825da76410c181273ba90b1'
S_NOREL = '5' * 40

COMMITS = {('acme/tool', 'v2'): S_TOOL, ('acme/exact', 'v1.0.4'): S_EXACT,
           ('actions/checkout', 'v7'): S_CO, ('acme/norel', 'v9'): S_NOREL}
TAGS = {
    # The exact release is on page 2: page 1 holds only other tags.
    'acme/tool': [[{'name': 'v2', 'commit': {'sha': S_TOOL}},
                   {'name': 'v2.3.0', 'commit': {'sha': S_OLD}}],
                  [{'name': 'v2.3.1', 'commit': {'sha': S_TOOL}}]],
    'acme/exact': [[{'name': 'v1.0.4', 'commit': {'sha': S_EXACT}}]],
    'actions/checkout': [[{'name': 'v7', 'commit': {'sha': S_CO}},
                          {'name': 'v7.0.1', 'commit': {'sha': S_CO}}]],
    'acme/norel': [[{'name': 'v9', 'commit': {'sha': S_NOREL}}]],
}

WF = ('name: w\non: push\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-latest\n'
      '    steps:\n      - uses: actions/checkout@v7\n      - uses: acme/tool@v2\n'
      '      - uses: acme/exact@v1.0.4\n      - uses: ./.github/actions/local\n')
COMP = ('name: c\ndescription: d\nruns:\n  using: composite\n  steps:\n    - uses: acme/tool@v2\n')
NOREL = ('name: n\non: push\npermissions:\n  contents: read\njobs:\n  a:\n    runs-on: ubuntu-latest\n'
         '    steps:\n      - uses: acme/norel@v9\n')


AUTH_SEEN = []   # the Authorization header of every request the stand-in received ('' = none)


class Api(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
        pass

    def do_GET(self):
        AUTH_SEEN.append(self.headers.get('Authorization') or '')
        path, _, query = self.path.partition('?')
        parts = path.strip('/').split('/')
        body, code = None, 404
        if len(parts) == 5 and parts[0] == 'repos' and parts[3] == 'commits':
            sha = COMMITS.get(('%s/%s' % (parts[1], parts[2]), parts[4]))
            if sha:
                body, code = {'sha': sha}, 200
        elif len(parts) == 4 and parts[0] == 'repos' and parts[3] == 'tags':
            pages = TAGS.get('%s/%s' % (parts[1], parts[2]))
            if pages is not None:
                q = dict(kv.split('=', 1) for kv in query.split('&') if '=' in kv)
                n = int(q.get('page', '1'))
                body, code = (pages[n - 1] if 0 < n <= len(pages) else []), 200
        data = json.dumps(body if body is not None else {'message': 'Not Found'}).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def run(bash, work, port, extra=None):
    # PIN_ACTIONS_API is where the PUBLIC action repositories are read (github.com in real use);
    # GITHUB_API_URL is the host that issued GITHUB_TOKEN. Here both are the stand-in, so the token
    # is attached; A7 makes them differ (KDEC-027).
    env = dict(os.environ, GITHUB_TOKEN='offline-stand-in', GITHUB_API_URL='http://127.0.0.1:%d' % port,
               PIN_ACTIONS_API='http://127.0.0.1:%d' % port, PYTHON=sys.executable.replace('\\', '/'))
    env.pop('TRUSTED_ORGS', None)
    env.pop('PIN_CHECK_TOKEN_HOST', None)
    env.update(extra or {})
    p = subprocess.run([bash, os.path.join(ROOT, 'scripts', 'pin-actions.sh').replace('\\', '/'), '--apply'],
                       cwd=work, env=env, capture_output=True, text=True, encoding='utf-8', errors='replace',
                       timeout=120)
    return p.returncode, p.stdout + p.stderr


def main():
    bash = shutil.which('bash')
    if not bash or not shutil.which('curl') or not shutil.which('jq'):
        print('UNKNOWN: bash, curl and jq are required to run pin-actions.sh.')
        return 2
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    import check_action_pins as cap
    srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Api)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    work = tempfile.mkdtemp(prefix='pin-actions-')
    bad = []
    try:
        t1 = os.path.join(work, 't1')
        wf = os.path.join(t1, '.github', 'workflows', 'w.yml')
        ac = os.path.join(t1, '.github', 'actions', 'c', 'action.yml')
        for p, text in ((wf, WF), (ac, COMP)):
            os.makedirs(os.path.dirname(p), exist_ok=True)
            io.open(p, 'w', encoding='utf-8', newline='\n').write(text)
        rc, out = run(bash, t1, port)
        print('  run 1 (major, exact, composite, default owners): rc=%s' % rc)
        w = io.open(wf, encoding='utf-8').read()
        c = io.open(ac, encoding='utf-8').read()
        want = (('A1 major -> exact release', w, 'uses: acme/tool@%s # v2.3.1' % S_TOOL),
                ('A2 exact tag keeps its name', w, 'uses: acme/exact@%s # v1.0.4' % S_EXACT),
                ('A3 composite step', c, 'uses: acme/tool@%s # v2.3.1' % S_TOOL),
                ('A4 actions/* not exempt by default', w, 'uses: actions/checkout@%s # v7.0.1' % S_CO))
        for label, text, line in want:
            ok = line in text
            print('  %-40s %s' % (label, 'ok' if ok else 'WRONG'))
            if not ok:
                bad.append('%s: no line `%s`' % (label, line))
        if rc != 0:
            bad.append('run 1 exited %s: %s' % (rc, out[-600:]))
        problems, pins = [], []
        for p, rel in ((wf, '.github/workflows/w.yml'), (ac, '.github/actions/c/action.yml')):
            cap.check_file(rel, io.open(p, encoding='utf-8').read(), problems, pins)
        print('  %-40s %s' % ('A5 output passes check_action_pins', 'ok' if not problems else 'WRONG'))
        if problems:
            bad.append('A5 check_action_pins refuses the output: %s' % problems)

        t2 = os.path.join(work, 't2')
        nw = os.path.join(t2, '.github', 'workflows', 'n.yml')
        os.makedirs(os.path.dirname(nw))
        io.open(nw, 'w', encoding='utf-8', newline='\n').write(NOREL)
        rc, out = run(bash, t2, port)
        after = io.open(nw, encoding='utf-8').read()
        ok = rc == 1 and after == NOREL
        print('  %-40s rc=%s %s' % ('A6 no exact release is refused', rc, 'ok' if ok else 'WRONG'))
        if not ok:
            bad.append('A6 a commit with no exact release: rc=%s, file %s' % (
                rc, 'unchanged' if after == NOREL else 'REWRITTEN: ' + after.strip().splitlines()[-1]))

        # A7 (KDEC-027): a GHE.com run's token is issued by api.<tenant>.ghe.com. It must never be
        # sent to the public API the action repositories are read from; the rewrite still works.
        t3 = os.path.join(work, 't3')
        w3 = os.path.join(t3, '.github', 'workflows', 'w.yml')
        os.makedirs(os.path.dirname(w3))
        io.open(w3, 'w', encoding='utf-8', newline='\n').write(WF)
        del AUTH_SEEN[:]
        rc, out = run(bash, t3, port, {'GITHUB_API_URL': 'https://api.example.ghe.com'})
        leaked = [a for a in AUTH_SEEN if a]
        ok = rc == 0 and AUTH_SEEN and not leaked and \
            ('uses: acme/tool@%s # v2.3.1' % S_TOOL) in io.open(w3, encoding='utf-8').read()
        print('  %-40s %s' % ('A7 ghe.com token not sent cross-host', 'ok' if ok else 'WRONG'))
        if not ok:
            bad.append('A7 GITHUB_API_URL=api.example.ghe.com: rc=%s, %d request(s), %d carried a '
                       'token: %s' % (rc, len(AUTH_SEEN), len(leaked), out[-400:]))
        # A8: the token IS attached when its issuer is the host being read (github.com in real use).
        io.open(w3, 'w', encoding='utf-8', newline='\n').write(WF)
        del AUTH_SEEN[:]
        rc, out = run(bash, t3, port)
        ok = rc == 0 and AUTH_SEEN and all(a == 'Bearer offline-stand-in' for a in AUTH_SEEN)
        print('  %-40s %s' % ('A8 same-host token attached', 'ok' if ok else 'WRONG'))
        if not ok:
            bad.append('A8 the issuing host read without its token: rc=%s %s' % (rc, AUTH_SEEN[:3]))
    finally:
        srv.shutdown()
        shutil.rmtree(work, ignore_errors=True)
    for b in bad:
        print(('FAIL ' + b).encode('ascii', 'replace').decode('ascii'))
    if bad:
        return 1
    print('PASS: pin-actions.sh writes the exact release beside the SHA, pins every owner by default, '
          'and refuses a commit with no exact release.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
