#!/usr/bin/env python3
"""Each release's record is kept in the target's lease store, `releases/`, create-only, so the landing
zone reads it durably. (OF-5 K-4; KDEC-030 kit item 2; KDEC-034 PROPOSED)

WHY THIS EXISTS

    The kit's promotion record was a GitHub artifact, kept 30 days. The landing zone's evidence is Git
    state, kept as long as the repository: its seam detector compares each kit-owned field with "the
    kit's release record for the target", its destroy evidence names the serving release, and its
    status cites the kit run and routing_result -- after 30 days there was nothing to read (P10, P12 of
    the LZ-vs-kit review). KDEC-030 put a `releases/` folder in each target's lease container for it.
    Now `target_lease.py record` writes the record there after every deploy that took the lease:
    create-only (If-None-Match: *, so a record is never overwritten), named by time, run and attempt so
    the newest sorts last, with the fields the landing zone reads (digest, now_serving, run,
    routing_result, validity, target, environment) beside the full promotion record. Retention is the
    store's: the landing zone sets a time-based immutability policy on the container (the hand-off
    contract) at least as long as its Git evidence; the kit reads the container's properties and
    records whether a policy is in force, and warns when none is.

WHAT IS PROVEN (against a local HTTP emulation of the Blob service: Put Blob with a body and
If-None-Match, Get Blob, Get Container Properties)

    R1  a record is written to the target's container under releases/<environment>/, with the LZ fields
    R2  the same name twice is refused, never overwritten (RELEASE_RECORD_NOT_KEPT), and the first stays
    R3  a container the landing zone never vended -> RELEASE_RECORD_NOT_KEPT, exit 2 (fail closed)
    R4  the store unreachable -> RELEASE_RECORD_NOT_KEPT, exit 2
    R5  the retention policy is read and recorded: present -> recorded; absent -> kept, warned
    R6  no lease token (the run never took the target) -> LEASE_NOT_HELD, nothing written
    R7  no promotion record to keep -> RELEASE_RECORD_NOT_KEPT, nothing written
    W1  both deploy reusables run `record` after the promotion record, on every path, only when the
        lease was acquired, passing the deploy's own routing result; the posture-independent outcome is
        a step output

EXIT 0 proven   1 a case failed   2 could not be checked
"""
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPT = os.path.join(ROOT, 'scripts', 'target_lease.py')
sys.path.insert(0, HERE)
FAILS = []
RID = ('/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-app-prod/'
       'providers/Microsoft.App/containerApps/app-a')
DIGEST = 'sha256:' + '5e' * 32


def expect(cond, label):
    print('%s  %s' % ('ok  ' if cond else 'FAIL', label))
    if not cond:
        FAILS.append(label)


def container_for(rid):
    return 't-' + hashlib.sha256(rid.strip().rstrip('/').lower().encode()).hexdigest()[:40]


class Store(object):
    def __init__(self, vended, immutable):
        self.vended, self.immutable = set(vended), dict(immutable)
        self.blobs = {}
        self.lock = threading.Lock()

    def handler(self):
        st = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, headers=None, err=None, body=b''):
                self.send_response(code)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                if err:
                    self.send_header('x-ms-error-code', err)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                if body and self.command != 'HEAD':
                    self.wfile.write(body)

            def _go(self, method):
                u = urlparse(self.path)
                parts = [p for p in u.path.split('/') if p]
                q = parse_qs(u.query)
                if not self.headers.get('Authorization', '').startswith('Bearer ') or not self.headers.get('x-ms-version'):
                    return self._send(401, err='NoAuthenticationInformation')
                container, blob = parts[0], '/'.join(parts[1:])
                with st.lock:
                    if container not in st.vended:
                        return self._send(404, err='ContainerNotFound')
                    if (q.get('restype') or [''])[0] == 'container' and not blob:
                        h = {'x-ms-has-immutability-policy': 'true' if st.immutable.get(container) else 'false',
                             'x-ms-has-legal-hold': 'false'}
                        return self._send(200, h)
                    key = (container, blob)
                    if method == 'PUT':
                        n = int(self.headers.get('Content-Length') or 0)
                        data = self.rfile.read(n) if n else b''
                        if self.headers.get('If-None-Match') == '*' and key in st.blobs:
                            return self._send(409, err='BlobAlreadyExists')
                        st.blobs[key] = {'data': data, 'type': self.headers.get('Content-Type'),
                                         'meta': {k.lower(): v for k, v in self.headers.items()
                                                  if k.lower().startswith('x-ms-meta-')}}
                        return self._send(201)
                    if method == 'GET':
                        if key not in st.blobs:
                            return self._send(404, err='BlobNotFound')
                        return self._send(200, body=st.blobs[key]['data'])
                    return self._send(400, err='UnsupportedHttpVerb')

            def do_PUT(self):
                self._go('PUT')

            def do_GET(self):
                self._go('GET')

            def do_HEAD(self):
                self._go('HEAD')
        return H


def run(cwd, *args, env_extra=None):
    env = dict(os.environ, TARGET_LEASE_BEARER='test-bearer')
    env.pop('GITHUB_OUTPUT', None)
    env.update(env_extra or {})
    p = subprocess.run([sys.executable, SCRIPT] + list(args), cwd=cwd, env=env, capture_output=True,
                       text=True, timeout=60)
    out = dict(re.findall(r'^((?:release_record|target_lease)[a-z_]*)=(.*)$', p.stdout, re.M))
    return p.returncode, out, p.stdout + p.stderr


def token(path, rid, endpoint, account='seamleasedev'):
    io.open(path, 'w', encoding='utf-8').write(json.dumps(
        {'target': rid.lower(), 'lease_id': 'L1', 'generation': 3, 'holder': 'kit-deploy:o/r/77-1',
         'took_over': None, 'account': account, 'endpoint': endpoint, 'cloud': 'public', 'ttl': 600}))


def promotion_record(path):
    rec = {'schema': 'kit-promotion-record/1', 'record_id': '77-1-prod', 'state': 'verified-for-promotion',
           'artifact': {'digest': DIGEST}, 'environment': {'name': 'prod', 'tier': 'prod',
                                                           'target_resource_id': RID},
           'provenance': {'gate_routing_result': 'PROCEED'},
           'validity': {'verified_at': '2026-10-28T10:00:00Z', 'expires_at': '2026-11-11T10:00:00Z'},
           'live_state': {'deployment_outcome': 'DEPLOY_HEALTHY',
                          'now_serving': [{'row': 'revision app-a--r2', 'value': 'reg/app@' + DIGEST}]},
           'run': {'id': '77', 'attempt': '1', 'url': 'https://github.com/o/r/actions/runs/77'}}
    io.open(path, 'w', encoding='utf-8').write(json.dumps(rec))


def cli_cases(base):
    other = RID[:-1] + 'z'
    st = Store([container_for(RID), container_for(other)], {container_for(RID): True})
    srv = ThreadingHTTPServer(('127.0.0.1', 0), st.handler())
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    ep = 'http://127.0.0.1:%d' % srv.server_address[1]
    try:
        tok, rec = os.path.join(base, 'token.json'), os.path.join(base, 'promotion-record.json')
        token(tok, RID, ep)
        promotion_record(rec)
        args = ['record', '--token-file', tok, '--record-file', rec, '--environment', 'prod',
                '--routing-result', 'PROCEED', '--now', '1761645600']
        rc, o, log = run(base, *args)
        names = [b for (c, b) in st.blobs if c == container_for(RID)]
        expect(rc == 0 and o.get('release_record') == 'RELEASE_RECORD_KEPT' and len(names) == 1 and
               names[0].startswith('releases/prod/') and names[0].endswith('-77-1.json'),
               'R1 the record is kept under releases/prod/ in the target\'s container (rc=%s %s %s)'
               % (rc, o, names or log[-300:]))
        if names:
            doc = json.loads(st.blobs[(container_for(RID), names[0])]['data'].decode('utf-8'))
            want = {'digest': DIGEST, 'routing_result': 'PROCEED', 'environment': 'prod',
                    'target_resource_id': RID.lower()}
            expect(all(doc.get(k) == v for k, v in want.items()) and doc.get('now_serving') and
                   (doc.get('run') or {}).get('id') == '77' and (doc.get('validity') or {}).get('verified_at') and
                   doc.get('schema') == 'kit-release-record/1' and (doc.get('promotion_record') or {}).get('record_id'),
                   'R1 it carries the fields the landing zone reads (digest, now_serving, run, routing_result, '
                   'validity, target, environment) and the full promotion record')
            expect(doc.get('retention_policy') == 'present' and o.get('release_record_retention') == 'present',
                   'R5 a container with an immutability policy is recorded as retained (present)')
            first = st.blobs[(container_for(RID), names[0])]['data']
            rc, o, _ = run(base, *args)
            expect(rc == 1 and o.get('release_record') == 'RELEASE_RECORD_NOT_KEPT' and
                   st.blobs[(container_for(RID), names[0])]['data'] == first,
                   'R2 the same record name twice is refused and the first is not overwritten (rc=%s)' % rc)
        tok2 = os.path.join(base, 'token-other.json')
        token(tok2, other, ep)
        rc, o, log = run(base, 'record', '--token-file', tok2, '--record-file', rec, '--environment', 'prod',
                         '--routing-result', 'PROCEED')
        expect(rc == 0 and o.get('release_record') == 'RELEASE_RECORD_KEPT' and
               o.get('release_record_retention') == 'absent' and 'immutability' in log.lower(),
               'R5 no immutability policy: kept, recorded absent, and warned (rc=%s %s)' % (rc, o))
        tok3 = os.path.join(base, 'token-unvended.json')
        token(tok3, RID[:-1] + 'q', ep)
        rc, o, _ = run(base, 'record', '--token-file', tok3, '--record-file', rec, '--environment', 'prod')
        expect(rc == 2 and o.get('release_record') == 'RELEASE_RECORD_NOT_KEPT',
               'R3 a container never vended -> RELEASE_RECORD_NOT_KEPT, exit 2 (rc=%s %s)' % (rc, o))
        tok4 = os.path.join(base, 'token-down.json')
        token(tok4, RID, 'http://127.0.0.1:9')
        rc, o, _ = run(base, 'record', '--token-file', tok4, '--record-file', rec, '--environment', 'prod')
        expect(rc == 2 and o.get('release_record') == 'RELEASE_RECORD_NOT_KEPT',
               'R4 the store unreachable -> RELEASE_RECORD_NOT_KEPT, exit 2 (rc=%s %s)' % (rc, o))
        before = len(st.blobs)
        rc, o, _ = run(base, 'record', '--token-file', os.path.join(base, 'absent.json'), '--record-file', rec,
                       '--environment', 'prod')
        expect(rc == 1 and o.get('target_lease') == 'LEASE_NOT_HELD' and len(st.blobs) == before,
               'R6 no lease token -> LEASE_NOT_HELD, nothing written (rc=%s %s)' % (rc, o))
        rc, o, _ = run(base, 'record', '--token-file', tok, '--record-file', os.path.join(base, 'none.json'),
                       '--environment', 'prod')
        expect(rc == 1 and o.get('release_record') == 'RELEASE_RECORD_NOT_KEPT' and len(st.blobs) == before,
               'R7 no promotion record -> RELEASE_RECORD_NOT_KEPT, nothing written (rc=%s %s)' % (rc, o))
    finally:
        srv.shutdown()


def wiring():
    import _step_harness as H
    for wf in ('.github/workflows/reusable-deploy-appservice.yml', '.github/workflows/reusable-deploy-containerapp.yml',
               '.github/workflows/reusable-deploy-staticwebapp.yml'):
        steps = H.load(wf)['jobs']['deploy']['steps']
        ids = [s.get('id') for s in steps]
        ok = 'release_record' in ids and 'promotion_record' in ids
        expect(ok, 'W1 %s: a release_record step exists' % wf)
        if not ok:
            continue
        s = steps[ids.index('release_record')]
        cond = str(s.get('if') or '')
        expect(ids.index('promotion_record') < ids.index('release_record'),
               'W1 %s: the record is kept after the promotion record is written' % wf)
        expect('always()' in cond and "env.KIT_TARGET_LEASE_ACCOUNT != ''" in cond and
               "steps.lease_acquire.outcome == 'success'" in cond,
               'W1 %s: on every path, only when the lease is on and was acquired (%s)' % (wf, cond))
        run_ = s.get('run') or ''
        expect('target_lease.py" record' in run_ and '--record-file' in run_ and '--routing-result' in run_,
               'W1 %s: it runs target_lease.py record with the record and the routing result' % wf)
        expect('steps.posture.outputs.routing_result' in str(s.get('env')),
               'W1 %s: the routing result is the deploy\'s own (the posture step\'s)' % wf)


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    base = tempfile.mkdtemp(prefix='release-record-')
    try:
        cli_cases(base)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    wiring()
    if FAILS:
        print('FAIL: %d case(s).' % len(FAILS))
        return 1
    print('PASS: every deploy that took the target lease keeps its release record in the target\'s '
          'releases/ folder, create-only and never overwritten, with the fields the landing zone reads; '
          'an unvended container or an unreachable store fails closed; the store\'s retention policy is '
          'read and recorded.')
    print('      EMULATED: no call has reached real Azure Storage (KDEC-030 U6, U11); the immutability '
          'policy is the landing zone\'s to set (the hand-off contract).')
    return 0


if __name__ == '__main__':
    sys.exit(main())
