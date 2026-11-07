#!/usr/bin/env python3
"""A loopback stand-in (127.0.0.1, an ephemeral port) for the GitHub REST reads kit_survey and kit_org_init make.

Routes: path (no query) -> (status, body[, headers]) or a callable(query dict) returning the same. Anything not
set answers 404, the way GitHub answers an absent file or setting. EVERY request is recorded (method, path,
query, whether an Authorization header came), and ANY method other than GET is answered 405 and recorded, so
a proof can assert the tools never wrote. No network beyond loopback.

Fixture helpers build the documented response shapes for an organisation on github.com and one on a GHE.com
tenant (the html_url host is the only difference the API shows: KDEC-027).
"""
import base64
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class StandIn(object):
    def __init__(self, routes=None):
        self.routes = dict(routes or {})
        self.requests = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def _answer(self):
                u = urllib.parse.urlsplit(self.path)
                q = dict((k, v[0]) for k, v in urllib.parse.parse_qs(u.query).items())
                outer.requests.append({'method': self.command, 'path': u.path, 'query': q,
                                       'auth': bool(self.headers.get('Authorization'))})
                if self.command != 'GET':
                    status, body, hdrs = 405, {'message': 'the stand-in refuses every write'}, {}
                else:
                    r = outer.routes.get(u.path, (404, {'message': 'Not Found'}))
                    if callable(r):
                        r = r(q)
                    status, body = r[0], r[1]
                    hdrs = r[2] if len(r) > 2 else {}
                data = json.dumps(body).encode('utf-8')
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                for k, v in hdrs.items():
                    self.send_header(k, v.replace('{base}', outer.url))
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _answer  # noqa: N815

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), H)
        self.url = 'http://127.0.0.1:%d' % self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    def reset(self, routes):
        self.routes = dict(routes)
        self.requests = []

    def writes(self):
        return [r for r in self.requests if r['method'] != 'GET']


def content(text):
    return (200, {'type': 'file', 'encoding': 'base64',
                  'content': base64.b64encode(text.encode('utf-8')).decode('ascii')})


def listing(paths):
    return (200, [{'type': 'file', 'name': p.rsplit('/', 1)[-1], 'path': p} for p in paths])


def repo_obj(owner, name, host, **kw):
    d = {'name': name, 'full_name': '%s/%s' % (owner, name), 'html_url': 'https://%s/%s/%s' % (host, owner, name),
         'default_branch': 'main', 'private': True, 'visibility': 'private', 'archived': False, 'fork': False}
    d.update(kw)
    return d
