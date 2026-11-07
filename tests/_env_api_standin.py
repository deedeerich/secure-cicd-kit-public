#!/usr/bin/env python3
"""A loopback stand-in (127.0.0.1, an ephemeral port) for the GitHub REST reads the deploy's protection step makes.

Routes are set per case: path (no query) -> (status, JSON body). Anything not set answers 404, the way
GitHub answers an absent environment or file. Every request is recorded (path, query, headers) so a proof
can assert which host and ref were read. No network beyond loopback; no credential (the script sends its
token only to https URLs).
"""
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class StandIn(object):
    def __init__(self):
        self.routes = {}
        self.requests = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                u = urllib.parse.urlsplit(self.path)
                outer.requests.append({'path': u.path, 'query': urllib.parse.parse_qs(u.query),
                                       'headers': dict(self.headers)})
                status, body = outer.routes.get(u.path, (404, {'message': 'Not Found'}))
                data = json.dumps(body).encode('utf-8')
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

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
