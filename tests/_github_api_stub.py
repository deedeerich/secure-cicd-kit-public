#!/usr/bin/env python3
"""A STATEFUL stand-in for the slice of the GitHub REST API the kit's API uses (KDEC-035).

NO NETWORK BY CONSTRUCTION. Two front-ends over ONE in-memory state:

    StubGitHub.transport(req, timeout)   replaces kit_api._transport in-process, so the client and
                                         the server code run unmodified against a SIMULATED
                                         GHE.com host (api.example.ghe.com, KDEC-027) and every
                                         request is recorded with its host and headers;
    StubGitHub.serve()                   the same routes on a loopback HTTP server, for a step
                                         extracted from a workflow and run under bash.

What it models, in the documented shapes only: a repository with a default branch; a
workflow_dispatch and a repository_dispatch, each creating a queued run whose display title is
the workflow's run-name (`kit-api <correlation id>`); runs, their artifacts (zip bytes) and the
artifact download, which answers 302 to a DIFFERENT host the way GitHub hands off to blob
storage; check runs (create, update, list by commit and name); environments with protection
rules; pending deployments. A request nothing models is refused loudly (and recorded), so an
unexpected call cannot quietly succeed.

THE TOKEN RULE IS OBSERVED, NOT ASSUMED: every request is kept with the host it went to and its
Authorization header, so a proof can assert the token reached only the issuing host and that
the blob host received no credential.
"""
import io
import json
import re
import threading
import urllib.error
import urllib.parse
import zipfile

API_HOST = 'api.example.ghe.com'
API_URL = 'https://%s' % API_HOST
BLOB_HOST = 'results-receiver.blob.example.invalid'
TOKEN = 'stub-run-token-not-a-credential'


def zip_bytes(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        for name, data in files.items():
            z.writestr(name, data if isinstance(data, (bytes, str)) else json.dumps(data))
    return buf.getvalue()


class _Resp(object):
    def __init__(self, status, body, headers):
        self.status = status
        self._body = body
        self.headers = headers

    def read(self):
        return self._body

    def getcode(self):
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class StubGitHub(object):
    def __init__(self, repo='octo-org/app', default_branch='main', head_sha='a' * 40,
                 require_token=True):
        self.repo = repo
        self.default_branch = default_branch
        self.head_sha = head_sha
        self.require_token = require_token
        self.requests = []
        self.unanswered = []
        self.runs = {}               # id -> run
        self.next_run = 9001
        self.artifacts = {}          # id -> {name, run_id, expired, data}
        self.next_artifact = 500
        self.check_runs = {}         # id -> check run
        self.next_check = 70001
        self.environments = {}       # name -> environment document
        self.pending = {}            # run id -> [pending deployment]
        self.dispatches = []
        self.fail = {}               # (method, path regex) -> status, to force an error
        # KDEC-037: the pull request that merged a review record, and who approved it.
        self.commits_by_path = {}    # repository path -> [commit sha, newest first]
        self.commit_pulls = {}       # commit sha -> [pull request]
        self.pull_reviews = {}       # pull request number -> [review]
        self.teams = {}              # (org, slug) -> [login]  (KDEC-037: the approver team)
        self.lock = threading.Lock()

    def merge_review_record(self, path, sha, number, author, approvers, merged=True, base=None):
        """A review record merged to the default branch by pull request `number`."""
        self.commits_by_path.setdefault(path, []).insert(0, sha)
        self.commit_pulls[sha] = [{'number': number, 'user': {'login': author},
                                   'merged_at': '2026-11-03T10:00:00Z' if merged else None,
                                   'base': {'ref': base or self.default_branch}}]
        self.pull_reviews[number] = [{'user': {'login': a}, 'state': 'APPROVED'} for a in approvers]

    # ── state helpers a proof calls ────────────────────────────────────────────────────
    def add_run(self, workflow='build-deploy.yml', branch=None, status='completed',
                conclusion='success', title='Build & Deploy', event='push', head_sha=None):
        rid = self.next_run
        self.next_run += 1
        self.runs[rid] = {'id': rid, 'name': title, 'display_title': title,
                          'path': '.github/workflows/%s' % workflow, 'workflow': workflow,
                          'head_branch': branch or self.default_branch, 'event': event,
                          'head_sha': head_sha or self.head_sha, 'status': status,
                          'conclusion': conclusion if status == 'completed' else None,
                          'run_attempt': 1,
                          'html_url': 'https://example.ghe.com/%s/actions/runs/%d' % (self.repo, rid)}
        return rid

    def add_artifact(self, run_id, name, files, expired=False):
        aid = self.next_artifact
        self.next_artifact += 1
        self.artifacts[aid] = {'id': aid, 'name': name, 'run_id': run_id, 'expired': expired,
                               'data': zip_bytes(files)}
        return aid

    def protect(self, env, reviewers=1, prevent_self_review=True):
        rules = []
        if reviewers:
            rules.append({'type': 'required_reviewers', 'prevent_self_review': prevent_self_review,
                          'reviewers': [{'type': 'Team', 'reviewer': {'slug': 'platform'}}]
                          * reviewers})
        self.environments[env] = {'name': env, 'protection_rules': rules}

    def check_run_named(self, name):
        hits = [c for c in self.check_runs.values() if c['name'] == name]
        return hits[-1] if hits else None

    # ── the routes ─────────────────────────────────────────────────────────────────────
    def handle(self, method, url, headers, body):
        """-> (status, body bytes, headers). One place both front-ends call."""
        u = urllib.parse.urlsplit(url)
        rec = {'method': method, 'url': url, 'host': u.hostname, 'path': u.path,
               'query': dict(urllib.parse.parse_qsl(u.query)),
               'authorization': headers.get('authorization') or '',
               'json': None}
        if body:
            try:
                rec['json'] = json.loads(body.decode('utf-8'))
            except ValueError:
                rec['json'] = None
        with self.lock:
            self.requests.append(rec)
        if u.hostname == BLOB_HOST:
            m = re.match(r'^/blob/(\d+)$', u.path)
            if method == 'GET' and m and int(m.group(1)) in self.artifacts:
                return 200, self.artifacts[int(m.group(1))]['data'], {}
            return 404, b'{}', {}
        for (fm, fp), st in self.fail.items():
            if fm == method and re.search(fp, u.path):
                return st, json.dumps({'message': 'forced'}).encode(), {}
        if self.require_token and rec['authorization'] != 'Bearer %s' % TOKEN:
            return 401, json.dumps({'message': 'Bad credentials'}).encode(), {}
        repo = '/repos/%s' % self.repo
        p = u.path
        q = rec['query']
        j = rec['json'] or {}

        def ok(doc, status=200, hdrs=None):
            return status, (json.dumps(doc).encode() if doc is not None else b''), hdrs or {}

        if method == 'GET' and p == repo:
            return ok({'full_name': self.repo, 'default_branch': self.default_branch})
        m = re.match(r'^%s/actions/workflows/([^/]+)/dispatches$' % re.escape(repo), p)
        if method == 'POST' and m:
            inputs = j.get('inputs') or {}
            self.dispatches.append({'workflow': m.group(1), 'ref': j.get('ref'), 'inputs': inputs})
            rid = self.add_run(workflow=m.group(1), branch=j.get('ref'), status='queued',
                               title='kit-api %s' % inputs.get('correlation_id', ''),
                               event='workflow_dispatch')
            self.runs[rid]['inputs'] = inputs
            return ok(None, 204)
        if method == 'POST' and p == '%s/dispatches' % repo:
            cp = j.get('client_payload') or {}
            self.dispatches.append({'event_type': j.get('event_type'), 'client_payload': cp})
            rid = self.add_run(workflow='kit-api.yml', status='queued',
                               title='kit-api %s' % cp.get('correlation_id', ''),
                               event='repository_dispatch')
            self.runs[rid]['client_payload'] = cp
            return ok(None, 204)
        m = re.match(r'^%s/actions/workflows/([^/]+)/runs$' % re.escape(repo), p)
        if method == 'GET' and m:
            runs = [r for r in sorted(self.runs.values(), key=lambda r: -r['id'])
                    if r['workflow'] == m.group(1)
                    and (not q.get('branch') or r['head_branch'] == q['branch'])
                    and (not q.get('status') or r['status'] == q['status'])
                    and (not q.get('event') or r['event'] == q['event'])]
            return ok({'total_count': len(runs), 'workflow_runs': runs})
        m = re.match(r'^%s/actions/runs/(\d+)$' % re.escape(repo), p)
        if method == 'GET' and m:
            r = self.runs.get(int(m.group(1)))
            return ok(r) if r else ok({'message': 'Not Found'}, 404)
        m = re.match(r'^%s/actions/runs/(\d+)/pending_deployments$' % re.escape(repo), p)
        if method == 'GET' and m:
            return ok(self.pending.get(int(m.group(1)), []))
        m = re.match(r'^%s/actions/runs/(\d+)/artifacts$' % re.escape(repo), p)
        if method == 'GET' and m:
            arts = [self._art(a) for a in self.artifacts.values() if a['run_id'] == int(m.group(1))]
            if q.get('name'):
                arts = [a for a in arts if a['name'] == q['name']]
            return ok({'total_count': len(arts), 'artifacts': arts})
        if method == 'GET' and p == '%s/actions/artifacts' % repo:
            arts = [self._art(a) for a in sorted(self.artifacts.values(), key=lambda a: -a['id'])]
            if q.get('name'):
                arts = [a for a in arts if a['name'] == q['name']]
            return ok({'total_count': len(arts), 'artifacts': arts})
        m = re.match(r'^%s/actions/artifacts/(\d+)/zip$' % re.escape(repo), p)
        if method == 'GET' and m:
            a = self.artifacts.get(int(m.group(1)))
            if not a or a['expired']:
                return ok({'message': 'Artifact has expired'}, 410)
            return 302, b'', {'Location': 'https://%s/blob/%d?sig=signed-not-a-credential'
                                          % (BLOB_HOST, a['id'])}
        if method == 'POST' and p == '%s/check-runs' % repo:
            cid = self.next_check
            self.next_check += 1
            c = dict(j, id=cid)
            self.check_runs[cid] = c
            return ok(c, 201)
        m = re.match(r'^%s/check-runs/(\d+)$' % re.escape(repo), p)
        if method == 'PATCH' and m:
            c = self.check_runs.get(int(m.group(1)))
            if c is None:
                return ok({'message': 'Not Found'}, 404)
            c.update(j)
            return ok(c)
        m = re.match(r'^%s/commits/([0-9a-f]{7,40})/check-runs$' % re.escape(repo), p)
        if method == 'GET' and m:
            hits = [c for c in self.check_runs.values() if c.get('head_sha') == m.group(1)
                    and (not q.get('check_name') or c.get('name') == q['check_name'])]
            return ok({'total_count': len(hits), 'check_runs': hits})
        m = re.match(r'^/orgs/([^/]+)/teams/([^/]+)/members$', p)
        if method == 'GET' and m:
            if (m.group(1), m.group(2)) not in self.teams:
                return ok({'message': 'Not Found'}, 404)
            return ok([{'login': x} for x in self.teams[(m.group(1), m.group(2))]])
        if method == 'GET' and p == '%s/commits' % repo:
            shas = self.commits_by_path.get(q.get('path') or '', [])
            return ok([{'sha': s} for s in shas[:int(q.get('per_page') or 30)]])
        m = re.match(r'^%s/commits/([0-9a-f]{7,40})/pulls$' % re.escape(repo), p)
        if method == 'GET' and m:
            return ok(self.commit_pulls.get(m.group(1), []))
        m = re.match(r'^%s/pulls/(\d+)/reviews$' % re.escape(repo), p)
        if method == 'GET' and m:
            return ok(self.pull_reviews.get(int(m.group(1)), []))
        m = re.match(r'^%s/environments/([^/]+)$' % re.escape(repo), p)
        if method == 'GET' and m:
            e = self.environments.get(urllib.parse.unquote(m.group(1)))
            return ok(e) if e else ok({'message': 'Not Found'}, 404)
        self.unanswered.append('%s %s' % (method, url))
        return 404, json.dumps({'message': 'NO ROUTE in the stub: %s %s' % (method, p)}).encode(), {}

    def _art(self, a):
        return {'id': a['id'], 'name': a['name'], 'expired': a['expired'],
                'size_in_bytes': len(a['data']),
                'archive_download_url': '%s/repos/%s/actions/artifacts/%d/zip' % (API_URL, self.repo,
                                                                                 a['id']),
                'workflow_run': {'id': a['run_id'],
                                 'head_branch': (self.runs.get(a['run_id']) or {}).get('head_branch')}}

    # ── front-end 1: in-process, replacing kit_api._transport ───────────────────────────
    def transport(self, req, timeout=None):
        headers = dict((k.lower(), v) for k, v in req.header_items())
        status, body, hdrs = self.handle(req.get_method(), req.full_url, headers, req.data)
        if status >= 300:
            # The no-redirect opener raises HTTPError for a 3xx exactly as for an error.
            raise urllib.error.HTTPError(req.full_url, status, 'stub', hdrs, io.BytesIO(body))
        return _Resp(status, body, hdrs)

    # ── front-end 2: the same routes on a loopback HTTP server ───────────────────────────
    def serve(self):
        """-> (base_url, stop). Requests arrive with the loopback host; they are routed as if
        they had gone to API_URL, so one set of routes serves both front-ends."""
        import http.server
        stub = self

        class H(http.server.BaseHTTPRequestHandler):
            def _do(self):
                n = int(self.headers.get('Content-Length') or 0)
                body = self.rfile.read(n) if n else b''
                hdrs = dict((k.lower(), v) for k, v in self.headers.items())
                status, data, extra = stub.handle(self.command, API_URL + self.path, hdrs, body)
                self.send_response(status)
                for k, v in extra.items():
                    self.send_header(k, v)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PATCH = do_PUT = _do

            def log_message(self, *a):
                return

        srv = http.server.HTTPServer(('127.0.0.1', 0), H)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()

        def stop():
            srv.shutdown()
            srv.server_close()
        return 'http://127.0.0.1:%d' % srv.server_address[1], stop
