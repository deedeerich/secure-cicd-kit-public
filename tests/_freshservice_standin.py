#!/usr/bin/env python3
"""A Freshservice stand-in on 127.0.0.1, for tests/prove_freshservice_tracker.py. NOT a tracker, and never live.

It answers in the shapes scripts/tracker_freshservice.py relies on -- the documented ones (api.freshservice.com,
retrieved 2026-11-06: tickets, filter by tag 30 per page, the list 100 per page, PUT replacing the tag list WHOLE,
activities newest first with next_page_url, ticket_form_fields, 429 with Retry-After) and the UNVERIFIED ones the
adapter names (notes, conversations with user_id, agents/me, the words of an activity's tag change). Every
UNVERIFIED shape here is the adapter's assumption, mirrored, not a fact about the live service.

Two API keys: the kit's and a PERSON's, each an agent. `human_put` is a person saving the ticket form;
`before_kit_put` lets a proof make that save land BETWEEN the kit's read and the kit's write -- the lost update
Freshservice's whole-list tag write invites.
"""
import base64
import datetime
import json
import re
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KIT_KEY, HUMAN_KEY = 'kit-standin-key', 'person-standin-key'
KIT_AGENT, HUMAN_AGENT = 9001, 4242
STAMP_FIELD = 'cf_kit_cluster_key'


class Store(object):
    def __init__(self):
        self.lock = threading.RLock()
        self.tickets = {}
        self.activities = {}      # id -> [activity] oldest first
        self.notes = {}           # id -> [conversation]
        self.next_id = 100
        self.clock = datetime.datetime(2026, 11, 6, 9, 0, 0)
        self.requests = []
        self.fail = {}            # (METHOD, regex) -> status
        self.throttle = 0         # answer this many next requests 429
        self.me_available = True
        self.stamp_field_type = 'custom_text'
        self.list_has_description = True
        self.tag_words = 'standard'   # 'standard' | 'opaque' (a tag change in words the adapter cannot read)
        self.before_kit_put = None    # callable(store, ticket_id, payload) run before a kit PUT applies

    def tick(self):
        self.clock += datetime.timedelta(seconds=1)
        return self.clock.strftime('%Y-%m-%dT%H:%M:%SZ')

    def activity(self, tid, agent, content, subs=()):
        self.activities.setdefault(tid, []).append({
            'actor': {'id': agent, 'name': 'kit integration' if agent == KIT_AGENT else 'a person'},
            'content': content, 'sub_contents': list(subs), 'created_at': self.tick()})

    def _tag_subs(self, before, after):
        add = [t for t in after if t not in before]
        rem = [t for t in before if t not in after]
        if self.tag_words == 'opaque' and (add or rem):
            return ['Tags were changed']
        out = []
        if add:
            out.append('Tags: added %s' % ', '.join("'%s'" % t for t in add))
        if rem:
            out.append('Tags: removed %s' % ', '.join("'%s'" % t for t in rem))
        return out

    def create(self, agent, body):
        with self.lock:
            tid = self.next_id
            self.next_id += 1
            now = self.tick()
            desc = body.get('description') or ''
            t = {'id': tid, 'subject': body.get('subject') or '', 'description': desc,
                 'description_text': re.sub(r'<[^>]*>', '', desc), 'tags': list(body.get('tags') or []),
                 'status': int(body.get('status') or 2), 'priority': int(body.get('priority') or 2),
                 'source': body.get('source'), 'requester_id': body.get('requester_id'),
                 'custom_fields': dict(body.get('custom_fields') or {}), 'created_at': now, 'updated_at': now}
            self.tickets[tid] = t
            self.activity(tid, agent, 'created the ticket')
            return t

    def update(self, agent, tid, body):
        with self.lock:
            t = self.tickets[tid]
            subs = []
            if 'tags' in body:
                subs += self._tag_subs(t['tags'], list(body['tags']))
                t['tags'] = list(body['tags'])          # THE WHOLE LIST IS REPLACED (documented)
            for k in ('status', 'priority', 'subject'):
                if k in body:
                    subs.append('%s set to %s' % (k, body[k]))
                    t[k] = body[k]
            if 'description' in body:
                t['description'] = body['description']
                t['description_text'] = re.sub(r'<[^>]*>', '', body['description'])
                subs.append('description updated')
            if 'custom_fields' in body:
                t['custom_fields'].update(body['custom_fields'])
            t['updated_at'] = self.tick()
            self.activity(tid, agent, 'updated the ticket', subs)
            return t

    def human_put(self, tid, add=(), remove=()):
        """A person saving the form: they send the WHOLE tag list they see."""
        with self.lock:
            t = self.tickets[tid]
            tags = [x for x in t['tags'] if x not in remove] + [x for x in add if x not in t['tags']]
            return self.update(HUMAN_AGENT, tid, {'tags': tags})

    def human_note(self, tid, text):
        with self.lock:
            self.notes.setdefault(tid, []).append({'id': len(self.notes.get(tid, [])) + 1, 'user_id': HUMAN_AGENT,
                                                    'body': '<pre>%s</pre>' % text, 'private': True})

    def manual(self, subject, text, tags=(), stamp=None):
        t = self.create(HUMAN_AGENT, {'subject': subject, 'description': '<p>%s</p>' % text, 'tags': list(tags),
                                      'custom_fields': {STAMP_FIELD: stamp} if stamp else {}})
        return str(t['id'])


def _agent(headers):
    h = headers.get('Authorization') or ''
    if not h.startswith('Basic '):
        return None
    try:
        user = base64.b64decode(h[6:]).decode('utf-8').split(':', 1)[0]
    except (ValueError, UnicodeDecodeError):
        return None
    return {KIT_KEY: KIT_AGENT, HUMAN_KEY: HUMAN_AGENT}.get(user)


def make_handler(store):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            return

        def _send(self, status, doc=None, headers=None):
            raw = json.dumps(doc).encode('utf-8') if doc is not None else b''
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('X-RateLimit-Total', '160')
            self.send_header('X-RateLimit-Remaining', '159')
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _body(self):
            n = int(self.headers.get('Content-Length') or 0)
            return json.loads(self.rfile.read(n).decode('utf-8')) if n else {}

        def handle_one(self, method):
            u = urllib.parse.urlsplit(self.path)
            q = urllib.parse.parse_qs(u.query)
            body = self._body() if method in ('POST', 'PUT') else None
            store.requests.append({'method': method, 'path': u.path, 'query': u.query, 'json': body,
                                   'host': self.headers.get('Host')})
            agent = _agent(self.headers)
            if agent is None:
                return self._send(401, {'code': 'access_denied'})
            if store.throttle > 0:
                store.throttle -= 1
                return self._send(429, {'message': 'slow down'}, {'Retry-After': '1'})
            for (m, rx), st in list(store.fail.items()):
                if m == method and re.search(rx, self.path):
                    return self._send(st, {'message': 'stand-in failure'})
            p = u.path
            with store.lock:
                if method == 'GET' and p == '/api/v2/ticket_form_fields':
                    return self._send(200, {'ticket_fields': [
                        {'name': 'subject', 'field_type': 'default_subject'},
                        {'name': STAMP_FIELD, 'field_type': store.stamp_field_type}]})
                if method == 'GET' and p == '/api/v2/agents/me':
                    if not store.me_available:
                        return self._send(404, {'message': 'not found'})
                    return self._send(200, {'agent': {'id': agent, 'first_name': 'agent'}})
                if method == 'POST' and p == '/api/v2/tickets':
                    return self._send(201, {'ticket': store.create(agent, body)},
                                      {'Location': '/api/v2/tickets/%d' % store.next_id})
                if method == 'GET' and p == '/api/v2/tickets/filter':
                    query = (q.get('query') or [''])[0]
                    want = re.findall(r"tag:'([^']*)'", query)
                    hits = [t for _i, t in sorted(store.tickets.items()) if all(w in t['tags'] for w in want)]
                    page = int((q.get('page') or ['1'])[0])
                    rows = [dict((k, v) for k, v in t.items() if k not in ('description', 'description_text'))
                            for t in hits[(page - 1) * 30:page * 30]]
                    return self._send(200, {'tickets': rows, 'total': len(hits)})
                if method == 'GET' and p == '/api/v2/tickets':
                    per = int((q.get('per_page') or ['30'])[0])
                    if per > 100:
                        return self._send(400, {'message': 'per_page is at most 100'})
                    page = int((q.get('page') or ['1'])[0])
                    hits = [t for _i, t in sorted(store.tickets.items())]
                    rows = []
                    for t in hits[(page - 1) * per:page * per]:
                        r = dict(t)
                        if not store.list_has_description:
                            r.pop('description', None)
                            r.pop('description_text', None)
                        rows.append(r)
                    return self._send(200, {'tickets': rows})
                m = re.match(r'^/api/v2/tickets/(\d+)(/[a-z_]+)?$', p)
                if not m or int(m.group(1)) not in store.tickets:
                    return self._send(404, {'message': 'no such ticket'})
                tid, sub = int(m.group(1)), m.group(2) or ''
                if method == 'GET' and not sub:
                    return self._send(200, {'ticket': store.tickets[tid]})
                if method == 'PUT' and not sub:
                    if agent == KIT_AGENT and store.before_kit_put:
                        hook, store.before_kit_put = store.before_kit_put, None
                        hook(store, tid, body)
                    return self._send(200, {'ticket': store.update(agent, tid, body)})
                if method == 'POST' and sub == '/notes':
                    c = {'id': len(store.notes.get(tid, [])) + 1, 'user_id': agent, 'body': body.get('body') or '',
                         'private': bool(body.get('private'))}
                    store.notes.setdefault(tid, []).append(c)
                    store.activity(tid, agent, 'added a private note')
                    return self._send(201, {'conversation': c})
                if method == 'GET' and sub == '/conversations':
                    per = int((q.get('per_page') or ['30'])[0])
                    page = int((q.get('page') or ['1'])[0])
                    return self._send(200, {'conversations': store.notes.get(tid, [])[(page - 1) * per:page * per]})
                if method == 'GET' and sub == '/activities':
                    acts = list(reversed(store.activities.get(tid, [])))
                    page = int((q.get('page') or ['1'])[0])
                    rows = acts[(page - 1) * 20:page * 20]
                    doc = {'activities': rows}
                    if page * 20 < len(acts):
                        doc['next_page_url'] = 'http://%s/api/v2/tickets/%d/activities?page=%d' % (
                            self.headers.get('Host'), tid, page + 1)
                    return self._send(200, doc)
            return self._send(404, {'message': 'not served by the stand-in'})

        def do_GET(self):
            self.handle_one('GET')

        def do_POST(self):
            self.handle_one('POST')

        def do_PUT(self):
            self.handle_one('PUT')
    return H


class StandIn(object):
    def __init__(self):
        self.store = Store()
        self.srv = ThreadingHTTPServer(('127.0.0.1', 0), make_handler(self.store))
        self.srv.daemon_threads = True
        self.thread = threading.Thread(target=self.srv.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
        self.thread.start()
        self.host = 'http://127.0.0.1:%d' % self.srv.server_address[1]

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.thread.join(timeout=10)
