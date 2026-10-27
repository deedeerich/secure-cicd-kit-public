#!/usr/bin/env python3
"""Two repositories contend for one target lease, over the wire (KDEC-030 draft, lane L-SEAM2).

WHY THIS EXISTS (docs/architecture/LZ_KIT_SEAM_CONTRACT.md, "The lease: one lock across both
repositories")

    A GitHub Actions concurrency group is evaluated inside one repository ("if another job or
    workflow using the same concurrency group in the repository is in progress", GitHub Docs,
    "Control the concurrency of workflows and jobs"). The landing-zone (LZ) apply runs in the
    platform repository and the kit's deploy in the application repository, so no group name can
    make them wait for each other. The cross-repository lock is the per-target Azure blob lease
    with a fencing token, taken by BOTH sides.

    tests/prove_target_lease.py proves the protocol in one process. This proof runs it the way
    the two repositories will: two INDEPENDENT callers -- separate processes, separate working
    directories ("repo-lz", "repo-app"), separate token files -- each invoking the shipped CLI
    (scripts/target_lease.py) through its live REST adapter, against a local HTTP emulation of
    the Blob service's Lease Blob / Set Blob Metadata / Get Blob Properties / Put Blob calls.
    The emulation's lease semantics are the model's BlobLeaseStore (the test double the first
    proof checks against the documented status codes); only the transport is new here.

    It also checks the opt-in wiring statically: the composite both sides call, and the steps in
    both deploy reusables that take, fence and release the lease only when the environment
    variable KIT_TARGET_LEASE_ACCOUNT is set -- so a consumer who sets nothing is unaffected.

THE CASES
    X1   the LZ (repo-lz) acquires the target by its ARM resource id
    X2   the kit (repo-app) is refused LEASE_HELD, naming the LZ holder -- also when it spells the
         resource id in another case (ARM ids are case-insensitive; one target, one lease)
    X3   CONTROL: the kit acquires a DIFFERENT target in parallel
    X4   the break authority breaks the LZ's lease; an actor outside it is refused
    X5   FENCING: the kit acquires; the LZ's next fence and its next begin are refused
         STALE_LEASE_HOLDER -- the stale holder is stopped before its next call
    X6   RENEWAL: a holder that heart-beats keeps the target past the original expiry; a contender
         at that moment is still refused LEASE_HELD
    X7   EXPIRY: a holder that stops heart-beating with the target CLEAN is taken over after its
         logical expiry (generation + 1, took_over recorded), and is then fenced
    X8   EXPIRY MID-MUTATION: a holder that expired while marked mutating is NOT taken over:
         LEASE_ABANDONED_MID_MUTATION; and it cannot release while mutating
    X9   an after-fence on a lease lost in flight reports MUTATED_WITHOUT_LEASE (the change may
         have landed: the fence cannot recall it)
    X10  CONTROL: the rightful holder begins, ends (MUTATED_UNDER_LEASE) and releases; the other
         side then acquires
    X11  fail closed: an unreachable store is LEASE_STORE_UNREACHABLE (exit 2); a container that
         was never vended is LEASE_TARGET_NOT_VENDED; plain http to a non-loopback host is refused
    W1-W6 the wiring (static): the composite; both deploy reusables acquire after Azure login and
         before the first capture, fence before every mutating step, guard the reversal on its
         fence, release after the last mutation; every lease step is off unless
         KIT_TARGET_LEASE_ACCOUNT is set

EXIT  0 all hold   1 any does not   2 could not be checked (UNKNOWN, never PASS)
"""
import hashlib
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
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

FAILS = []


def expect(cond, label):
    print('%s  %s' % ('ok  ' if cond else 'FAIL', label))
    if not cond:
        FAILS.append(label)


# ----------------------------------------------------------------------------- the emulator
class Emulator(object):
    """The Blob service's lease, metadata and properties calls over HTTP, backed by the model."""

    def __init__(self, T, vended):
        import time
        self.T, self.time = T, time
        self.store = T.BlobLeaseStore()
        self.vended = set(vended)       # container names the "LZ vend" created
        self.exists = set()             # (container, blob) created by Put Blob
        self.calls = []
        self.lock = threading.Lock()

    def handler(self):
        emu = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, headers=None, err=None):
                self.send_response(code)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                if err:
                    self.send_header('x-ms-error-code', err)
                self.send_header('Content-Length', '0')
                self.end_headers()

            def _route(self, method):
                u = urlparse(self.path)
                parts = [p for p in u.path.split('/') if p]
                comp = (parse_qs(u.query).get('comp') or [''])[0]
                if not self.headers.get('Authorization', '').startswith('Bearer '):
                    return self._send(401, err='NoAuthenticationInformation')
                if not self.headers.get('x-ms-version'):
                    return self._send(400, err='MissingRequiredHeader')
                if len(parts) != 2:
                    return self._send(400, err='InvalidUri')
                container, blob = parts
                with emu.lock:
                    emu.calls.append((method, container, comp, self.headers.get('x-ms-lease-action')))
                    if container not in emu.vended:
                        return self._send(404, err='ContainerNotFound')
                    key = container + '/' + blob
                    now = emu.time.time()
                    lid = self.headers.get('x-ms-lease-id')
                    try:
                        if method == 'PUT' and comp == '':
                            if (container, blob) in emu.exists:
                                return self._send(409, err='BlobAlreadyExists')
                            emu.exists.add((container, blob))
                            return self._send(201)
                        if (container, blob) not in emu.exists:
                            return self._send(404, err='BlobNotFound')
                        if method == 'PUT' and comp == 'lease':
                            act = self.headers.get('x-ms-lease-action')
                            if act == 'acquire':
                                got = emu.store.acquire(key, int(self.headers.get('x-ms-lease-duration')),
                                                        self.headers.get('x-ms-proposed-lease-id'), now)
                                return self._send(201, {'x-ms-lease-id': got})
                            if act == 'break':
                                p = self.headers.get('x-ms-lease-break-period')
                                w = emu.store.break_lease(key, None if p is None else int(p), now)
                                return self._send(202, {'x-ms-lease-time': str(int(w))})
                            if act == 'release':
                                emu.store.release(key, lid, now)
                                return self._send(200)
                            if act == 'renew':
                                emu.store.renew(key, lid, now)
                                return self._send(200, {'x-ms-lease-id': lid})
                            return self._send(400, err='InvalidHeaderValue')
                        if method == 'PUT' and comp == 'metadata':
                            md = {}
                            for k, v in self.headers.items():
                                if k.lower().startswith('x-ms-meta-'):
                                    md[k.lower()[len('x-ms-meta-'):]] = v
                            emu.store.write(key, lid, md, now)
                            return self._send(200)
                        if method == 'HEAD' and comp == '':
                            md = emu.store.read(key, lid, now)
                            h = {'x-ms-lease-state': emu.store.state(key, now)}
                            for k, v in md.items():
                                h['x-ms-meta-' + k] = v
                            return self._send(200, h)
                    except emu.T.LeaseError as e:
                        return self._send(int(e.code), err='LeaseError')
                    return self._send(400, err='UnsupportedHttpVerb')

            def do_PUT(self):
                n = int(self.headers.get('Content-Length') or 0)
                if n:
                    self.rfile.read(n)
                self._route('PUT')

            def do_HEAD(self):
                self._route('HEAD')

        return H


def container_for(rid):
    return 't-' + hashlib.sha256(rid.strip().rstrip('/').lower().encode()).hexdigest()[:40]


# ----------------------------------------------------------------------------- the two callers
class Caller(object):
    """One repository's pipeline: its own working directory and token file, the shipped CLI."""

    def __init__(self, base, name, endpoint):
        self.cwd = os.path.join(base, name)
        os.makedirs(self.cwd)
        self.token = os.path.join(self.cwd, 'lease-token.json')
        self.endpoint = endpoint

    def run(self, *args, now=None):
        cmd = [sys.executable, SCRIPT] + list(args)
        if now is not None:
            cmd += ['--now', str(now)]
        env = dict(os.environ, TARGET_LEASE_BEARER='test-bearer')
        env.pop('GITHUB_OUTPUT', None)
        p = subprocess.run(cmd, cwd=self.cwd, env=env, capture_output=True, text=True, timeout=60)
        out = dict(re.findall(r'^(target_lease[a-z_]*)=(.*)$', p.stdout, re.M))
        return p.returncode, out, p.stdout + p.stderr

    def acquire(self, rid, holder, now, endpoint=None, account='seamleasedev', ttl=None):
        extra = ['--ttl', str(ttl)] if ttl else []
        return self.run('acquire', '--resource-id', rid, '--holder', holder, '--account', account,
                        '--endpoint', endpoint or self.endpoint, '--token-file', self.token, *extra, now=now)

    def op(self, verb, now, *extra):
        return self.run(verb, '--token-file', self.token, *extra, now=now)


def cross_repo_cases(T, base):
    rid_a = ('/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-app-prod/'
             'providers/Microsoft.App/containerApps/app-a')
    rid_b = rid_a[:-1] + 'b'
    rid_c = rid_a[:-1] + 'c'
    rid_d = rid_a[:-1] + 'd'
    rid_e = rid_a[:-1] + 'e'
    emu = Emulator(T, [container_for(r) for r in (rid_a, rid_b, rid_c, rid_d, rid_e)])
    srv = ThreadingHTTPServer(('127.0.0.1', 0), emu.handler())
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    ep = 'http://127.0.0.1:%d' % srv.server_address[1]
    try:
        lz = Caller(base, 'repo-lz', ep)
        app = Caller(base, 'repo-app', ep)
        LZ, KIT = 'lz-apply:org/platform/run-11-1', 'kit-deploy:org/app-a/run-22-1'
        t0 = 1000000.0

        rc, o, log = lz.acquire(rid_a, LZ, t0)
        expect(rc == 0 and o.get('target_lease') == 'LEASE_ACQUIRED',
               'X1 repo-lz acquires the target by its resource id (rc=%s %s)' % (rc, o or log.strip()[-200:]))

        rc, o, _ = app.acquire(rid_a, KIT, t0 + 5)
        expect(rc == 1 and o.get('target_lease') == 'LEASE_HELD' and LZ in o.get('target_lease_reason', ''),
               'X2 repo-app is refused LEASE_HELD while repo-lz holds it, naming the LZ holder')
        rc, o, _ = app.acquire(rid_a.upper().replace('/SUBSCRIPTIONS/', '/subscriptions/'), KIT, t0 + 5)
        expect(rc == 1 and o.get('target_lease') == 'LEASE_HELD',
               'X2b the same target spelled in another case is the same lease (refused LEASE_HELD)')

        other = Caller(base, 'repo-app-b', ep)
        rc, o, _ = other.acquire(rid_b, 'kit-deploy:org/app-b/run-1-1', t0 + 6)
        expect(rc == 0 and o.get('target_lease') == 'LEASE_ACQUIRED',
               'X3 CONTROL: another target is acquired in parallel')

        # X4: break authority.
        rc, o, _ = app.run('break', '--resource-id', rid_a, '--account', 'seamleasedev', '--endpoint', ep,
                           '--actor', 'kit-deploy-identity', '--reason', 'impatient', now=t0 + 7)
        expect(rc == 1 and o.get('target_lease') == 'BREAK_NOT_AUTHORISED',
               'X4 a break by an actor outside the break authority is refused')
        rc, o, _ = app.run('break', '--resource-id', rid_a, '--account', 'seamleasedev', '--endpoint', ep,
                           '--actor', 'platform-admins', '--reason', 'apply runner lost', now=t0 + 8)
        expect(rc == 0 and o.get('target_lease') == 'LEASE_BROKEN',
               'X4b the break authority breaks the LZ lease, recorded')

        # X5: fencing across repositories.
        rc, o, _ = app.acquire(rid_a, KIT, t0 + 9)
        expect(rc == 0 and o.get('target_lease') == 'LEASE_ACQUIRED',
               'X5a repo-app acquires after the break')
        rc, o, _ = lz.op('fence', t0 + 10)
        expect(rc == 1 and o.get('target_lease') == 'STALE_LEASE_HOLDER',
               'X5b FENCING: the broken LZ holder\'s next fence is refused STALE_LEASE_HOLDER')
        rc, o, _ = lz.op('begin', t0 + 10, '--what', 'terraform apply')
        expect(rc == 1 and o.get('target_lease') == 'STALE_LEASE_HOLDER',
               'X5c FENCING: the broken LZ holder cannot mark a mutation (stopped before its next call)')

        # X6: renewal keeps the target; X7 expiry hands it over.
        rc, o, _ = app.op('fence', t0 + 500)            # heartbeat: expires_at -> t0 + 1100
        rc2, o2, _ = lz.acquire(rid_a, LZ, t0 + 700)    # past the ORIGINAL expiry (t0 + 609)
        rc3, o3, _ = app.op('fence', t0 + 1000)
        expect(rc == 0 and o.get('target_lease') == 'LEASE_FENCE_PASSED' and rc2 == 1
               and o2.get('target_lease') == 'LEASE_HELD' and rc3 == 0,
               'X6 RENEWAL: a heart-beating holder keeps the target past the original expiry')
        rc, o, _ = lz.acquire(rid_a, LZ, t0 + 1700)      # past the renewed expiry (t0 + 1600)
        expect(rc == 0 and o.get('target_lease') == 'LEASE_ACQUIRED' and KIT in o.get('target_lease_took_over', ''),
               'X7 EXPIRY: a silent holder that left the target clean is taken over, recorded')
        rc, o, _ = app.op('fence', t0 + 1701)
        expect(rc == 1 and o.get('target_lease') == 'STALE_LEASE_HOLDER',
               'X7b the expired holder is fenced after the takeover')

        # X8: expiry mid-mutation is a human decision.
        c1, c2 = Caller(base, 'repo-lz-c', ep), Caller(base, 'repo-app-c', ep)
        c1.acquire(rid_c, LZ, t0)
        c1.op('begin', t0 + 1, '--what', 'terraform apply (template)')
        rc, o, _ = c2.acquire(rid_c, KIT, t0 + 900)
        expect(rc == 1 and o.get('target_lease') == 'LEASE_ABANDONED_MID_MUTATION',
               'X8 a holder that expired mid-mutation is NOT taken over')
        rc, o, _ = c1.op('release', t0 + 2)
        expect(rc == 1 and o.get('target_lease') == 'RELEASE_MID_MUTATION',
               'X8b a holder cannot release while marked mutating')

        # X9: the lease lost while the mutation was in flight.
        d1 = Caller(base, 'repo-app-d', ep)
        d1.acquire(rid_d, KIT, t0)
        d1.op('begin', t0 + 1, '--what', 'containerapp update')
        d1.run('break', '--resource-id', rid_d, '--account', 'seamleasedev', '--endpoint', ep,
               '--actor', 'platform-admins', '--reason', 'test', now=t0 + 2)
        rc, o, _ = d1.op('end', t0 + 3)
        expect(rc == 1 and o.get('target_lease') == 'MUTATED_WITHOUT_LEASE',
               'X9 the after-fence reports MUTATED_WITHOUT_LEASE (the sent call is not recalled)')

        # X10: control.
        e1, e2 = Caller(base, 'repo-app-e', ep), Caller(base, 'repo-lz-e', ep)
        r = [e1.acquire(rid_e, KIT, t0)[1].get('target_lease'),
             e1.op('begin', t0 + 1, '--what', 'deploy')[1].get('target_lease'),
             e1.op('fence', t0 + 2)[1].get('target_lease'),
             e1.op('end', t0 + 3)[1].get('target_lease'),
             e1.op('release', t0 + 4)[1].get('target_lease'),
             e2.acquire(rid_e, LZ, t0 + 5)[1].get('target_lease')]
        expect(r == ['LEASE_ACQUIRED', 'LEASE_MUTATION_MARKED', 'LEASE_FENCE_PASSED', 'MUTATED_UNDER_LEASE',
                     'LEASE_RELEASED', 'LEASE_ACQUIRED'],
               'X10 CONTROL: acquire, begin, fence, end, release; the other side then acquires: %s' % r)

        # X11: fail closed.
        f = Caller(base, 'repo-app-f', ep)
        rc, o, _ = f.acquire(rid_a, KIT, t0, endpoint='http://127.0.0.1:1')
        expect(rc == 2 and o.get('target_lease') == 'LEASE_STORE_UNREACHABLE',
               'X11 an unreachable store fails closed: LEASE_STORE_UNREACHABLE, exit 2')
        rc, o, _ = f.acquire(rid_a[:-1] + 'z', KIT, t0)
        expect(rc == 2 and o.get('target_lease') == 'LEASE_TARGET_NOT_VENDED',
               'X11b a target whose container was never vended: LEASE_TARGET_NOT_VENDED')
        rc, o, _ = f.acquire(rid_a, KIT, t0, endpoint='http://seamleasedev.blob.core.windows.net')
        expect(rc == 2 and not os.path.exists(f.token),
               'X11c plain http to a non-loopback host is refused before any call')
        expect(not any(c[3] == 'break' and c[1] == container_for(rid_c) for c in emu.calls),
               'X8c no machine broke the lease of the target abandoned mid-mutation')
        hold_cases(T, base, ep, emu)
        az_hook_cases(base, ep, emu)
    finally:
        srv.shutdown()


# ----------------------------------------------------------------------------- holding through a period
RID = ('/subscriptions/00000000-0000-0000-0000-000000000002/resourceGroups/rg-app-prod/'
       'providers/Microsoft.Web/sites/app-%s')


def child(seconds, marker, code=0):
    return [sys.executable, '-c', 'import sys,time; time.sleep(%s); open(sys.argv[1],"w").write("done"); '
            'sys.exit(%d)' % (seconds, code), marker]


def hold_cases(T, base, ep, emu):
    """H1-H4: `hold` renews the lease while a long step (the e2e test period, a rollback sequence)
    runs, and a failed renewal stops the step and fails closed: LEASE_LOST, sticky."""
    import time
    for k in 'hijk':
        emu.vended.add(container_for(RID % k))
    KIT = 'kit-deploy:org/app/run-5-1'
    env = dict(os.environ, TARGET_LEASE_BEARER='test-bearer')
    env.pop('GITHUB_OUTPUT', None)

    # H1: a 3 s lease renewed every second outlives itself; a contender is refused meanwhile.
    h = Caller(base, 'repo-app-h', ep)
    h.acquire(RID % 'h', KIT, None, ttl=3)
    done = os.path.join(h.cwd, 'done')
    p = subprocess.Popen([sys.executable, SCRIPT, 'hold', '--token-file', h.token, '--every', '1', '--']
                         + child(6, done), cwd=h.cwd, env=env, stdout=subprocess.PIPE, text=True)
    time.sleep(4.5)
    rc2, o2, _ = Caller(base, 'repo-lz-h', ep).acquire(RID % 'h', 'lz-apply:org/platform/run-9-1', None)
    p.communicate(timeout=60)
    expect(p.returncode == 0 and os.path.exists(done) and rc2 == 1 and o2.get('target_lease') == 'LEASE_HELD',
           'H1 hold renews a 3 s lease through a 6 s period; a contender at 4.5 s is refused LEASE_HELD '
           '(rc=%s, contender %s)' % (p.returncode, o2.get('target_lease')))
    rc, o, _ = h.op('release', None)
    expect(rc == 0 and o.get('target_lease') == 'LEASE_RELEASED', 'H1b released after the held period')

    # H2: the lease is broken mid-period: the step is stopped, LEASE_LOST, and it stays lost.
    i = Caller(base, 'repo-app-i', ep)
    i.acquire(RID % 'i', KIT, None, ttl=30)
    done = os.path.join(i.cwd, 'done')
    t0 = time.time()
    p = subprocess.Popen([sys.executable, SCRIPT, 'hold', '--token-file', i.token, '--every', '1', '--']
                         + child(20, done), cwd=i.cwd, env=env, stdout=subprocess.PIPE, text=True)
    time.sleep(2)
    i.run('break', '--resource-id', RID % 'i', '--account', 'seamleasedev', '--endpoint', ep,
          '--actor', 'platform-admins', '--reason', 'test')
    out, _ = p.communicate(timeout=60)
    el = time.time() - t0
    time.sleep(1)
    lost = dict(re.findall(r'^(target_lease[a-z_]*)=(.*)$', out, re.M))
    expect(p.returncode == 1 and lost.get('target_lease') == 'LEASE_LOST' and not os.path.exists(done) and el < 15,
           'H2 a failed renewal stops the held step at once and fails closed: LEASE_LOST (rc=%s, %.1fs)'
           % (p.returncode, el))
    rc, o, _ = i.op('fence', None)
    expect(rc == 1 and o.get('target_lease') == 'LEASE_LOST',
           'H2b LEASE_LOST is sticky: the next fence is refused without asking the store again')

    # H3/H4: --mark-mutating (the rollback sequence): clean after a verified sequence, still
    # `mutating` after a halted one (a human decides), which release then refuses.
    j = Caller(base, 'repo-app-j', ep)
    j.acquire(RID % 'j', 'kit-rollback:org/app/run-6-1', None)
    rc = subprocess.run([sys.executable, SCRIPT, 'hold', '--token-file', j.token, '--every', '1',
                         '--mark-mutating', 'rollback sequence', '--'] + child(1, os.path.join(j.cwd, 'd')),
                        cwd=j.cwd, env=env, capture_output=True, text=True).returncode
    _, st, _ = j.run('status', '--resource-id', RID % 'j', '--account', 'seamleasedev', '--endpoint', ep)
    expect(rc == 0 and 'state clean' in st.get('target_lease_reason', ''),
           'H3 a held sequence that succeeds is marked mutating during it and clean after')
    k = Caller(base, 'repo-app-k', ep)
    k.acquire(RID % 'k', 'kit-rollback:org/app/run-7-1', None)
    rc = subprocess.run([sys.executable, SCRIPT, 'hold', '--token-file', k.token, '--every', '1',
                         '--mark-mutating', 'rollback sequence', '--'] + child(1, os.path.join(k.cwd, 'd'), 3),
                        cwd=k.cwd, env=env, capture_output=True, text=True).returncode
    _, st, _ = k.run('status', '--resource-id', RID % 'k', '--account', 'seamleasedev', '--endpoint', ep)
    rc2, o2, _ = k.op('release', None)
    expect(rc == 3 and 'state mutating' in st.get('target_lease_reason', '')
           and o2.get('target_lease') == 'RELEASE_MID_MUTATION',
           'H4 a halted sequence keeps its exit code and leaves the lease mutating; release refuses')


# ----------------------------------------------------------------------------- every mutating az call
DRIVE = ('import sys, json\n'
         'sys.path.insert(0, sys.argv[1])\n'
         'import deploy_contract as dc\n'
         'out = []\n'
         'for a in json.loads(sys.argv[2]):\n'
         '    ok, _, err = dc.az(*a)\n'
         '    out.append([ok, err])\n'
         'print("RESULT=" + json.dumps(out))\n')


def az_hook_cases(base, ep, emu):
    """A1-A5: deploy_contract.az fences before EVERY mutating az call when the lease is on -- the
    single path every kit mutation takes (the deploy steps, the reversal, the rollback sequence and
    the generic ARM rollback all call it) -- and is inert when the lease is off."""
    stub = os.path.join(base, 'az-stub')
    os.makedirs(stub)
    log = os.path.join(base, 'az-calls.log')
    fake = os.path.join(stub, 'fake_az.py')
    with open(fake, 'w') as f:
        f.write('import sys, os\nopen(os.environ["AZ_STUB_LOG"], "a").write(" ".join(sys.argv[1:]) + "\\n")\n'
                'print("{}")\n')
    with open(os.path.join(stub, 'az'), 'w', newline='\n') as f:
        f.write('#!/bin/bash\nexec "%s" "%s" "$@"\n' % (sys.executable.replace('\\', '/'), fake.replace('\\', '/')))
    os.chmod(os.path.join(stub, 'az'), 0o755)
    with open(os.path.join(stub, 'az.cmd'), 'w', newline='\r\n') as f:
        f.write('@echo off\n"%s" "%s" %%*\n' % (sys.executable, fake))

    def run(calls, token, lease_on=True):
        if os.path.exists(log):
            os.remove(log)
        env = dict(os.environ, PATH=stub + os.pathsep + os.environ.get('PATH', ''), AZ_STUB_LOG=log,
                   TARGET_LEASE_BEARER='test-bearer', RUNNER_TEMP=os.path.join(base, 'rt'))
        env.pop('GITHUB_OUTPUT', None)
        env.pop('KIT_TARGET_LEASE_ACCOUNT', None)
        env.pop('KIT_TARGET_LEASE_TOKEN', None)
        if lease_on:
            env['KIT_TARGET_LEASE_ACCOUNT'] = 'seamleasedev'
            env['KIT_TARGET_LEASE_TOKEN'] = token
        p = subprocess.run([sys.executable, '-c', DRIVE, os.path.join(ROOT, 'scripts'), json.dumps(calls)],
                           env=env, capture_output=True, text=True, timeout=120)
        m = re.search(r'^RESULT=(.*)$', p.stdout, re.M)
        made = open(log).read().splitlines() if os.path.exists(log) else []
        return (json.loads(m.group(1)) if m else None), made, p.stdout + p.stderr

    rid = RID % 'z'
    emu.vended.add(container_for(rid))
    a = Caller(base, 'repo-app-a1', ep)
    a.acquire(rid, 'kit-deploy:org/app/run-8-1', None)
    SHOW = ['containerapp', 'show', '-n', 'app', '-g', 'rg']
    UPD = ['containerapp', 'update', '-n', 'app', '-g', 'rg', '--image', 'r/i@sha256:' + '0' * 64]
    TAG = ['tag', 'update', '--resource-id', rid, '--operation', 'Merge', '--tags', 'k=v']
    res, made, log_ = run([SHOW, UPD], a.token)
    expect(res is not None and res[0][0] and res[1][0] and len(made) == 2,
           'A1 lease held: the mutating call is fenced and made (%s)' % (res or log_.strip()[-300:]))
    a.run('break', '--resource-id', rid, '--account', 'seamleasedev', '--endpoint', ep,
          '--actor', 'platform-admins', '--reason', 'test')
    res, made, log_ = run([SHOW, UPD, TAG], a.token)
    expect(res is not None and res[0][0] and not res[1][0] and 'STALE_LEASE_HOLDER' in (res[1][1] or '')
           and not res[2][0] and len(made) == 1 and made[0].startswith('containerapp show'),
           'A2 lease broken: every mutating az call is refused before it is sent; reads still run (%s)' % res)
    res, made, _ = run([UPD], os.path.join(base, 'no-such-token.json'))
    expect(res is not None and not res[0][0] and 'LEASE_NOT_HELD' in (res[0][1] or '') and not made,
           'A3 lease on but never acquired: the mutating call is refused LEASE_NOT_HELD')
    res, made, _ = run([UPD, TAG], '', lease_on=False)
    expect(res is not None and res[0][0] and res[1][0] and len(made) == 2,
           'A4 lease off: az behaves exactly as before (no fence, no store)')
    try:
        sys.path.insert(0, os.path.join(ROOT, 'scripts'))
        import deploy_contract as dc
        cls = dc.az_is_mutating
        muts = [UPD, TAG, ['containerapp', 'ingress', 'traffic', 'set'], ['containerapp', 'revision', 'activate'],
                ['containerapp', 'revision', 'deactivate'], ['webapp', 'deployment', 'slot', 'swap'],
                ['webapp', 'config', 'container', 'set'], ['rest', '--method', 'put', '--url', 'x'],
                ['rest', '--method', 'delete', '--url', 'x'], ['rest', '--method', 'patch', '--url', 'x'],
                ['webapp', 'restart'], ['resource', 'delete']]
        reads = [SHOW, ['containerapp', 'revision', 'list'], ['webapp', 'show'], ['webapp', 'config', 'show'],
                 ['rest', '--method', 'get', '--url', 'x'], ['containerapp', 'revision', 'show'],
                 ['account', 'get-access-token']]
        ok = all(cls(*m) for m in muts) and not any(cls(*r) for r in reads)
    except Exception as e:  # noqa: BLE001
        print('     classifier: %r' % e)
        ok = False
    expect(ok, 'A5 the classifier calls every mutating verb the kit sends mutating, and no read')


# ----------------------------------------------------------------------------- the wiring
def wiring_cases():
    act = os.path.join(ROOT, '.github', 'actions', 'target-lease', 'action.yml')
    try:
        a = open(act, encoding='utf-8').read()
    except OSError:
        a = ''
    expect('scripts/target_lease.py' in a and 'GITHUB_ACTION_PATH' in a and '${{ inputs.' not in
           re.sub(r'(?s)^.*?runs:', '', a).split('run: |', 1)[-1],
           'W1 the composite both sides call runs the shipped scripts/target_lease.py, inputs as env data')
    for wf, mutators in (('reusable-deploy-containerapp.yml',
                          ['Deploy by digest', 'Move traffic to the verified revision',
                           "Reverse this run's changes", 'Stamp provenance (after health and a live read)']),
                         ('reusable-deploy-appservice.yml',
                          ['Set container image (digest-pinned) and restart', 'Swap slot into production',
                           "Reverse this run's changes", 'Stamp provenance (after health and a live read)'])):
        text = open(os.path.join(ROOT, '.github', 'workflows', wf), encoding='utf-8').read()
        steps = re.split(r'\n      - name: ', text)
        names = [s.split('\n', 1)[0].strip() for s in steps]
        lease_idx = [i for i, s in enumerate(steps) if 'uses: $/.github/actions/target-lease' in s]
        ok_off = bool(lease_idx) and all("env.KIT_TARGET_LEASE_ACCOUNT != ''" in steps[i] for i in lease_idx)
        expect(ok_off and 'KIT_TARGET_LEASE_ACCOUNT: ${{ vars.KIT_TARGET_LEASE_ACCOUNT }}' in text,
               'W2 %s: every lease step is off unless KIT_TARGET_LEASE_ACCOUNT is set' % wf)

        def op_of(i):
            m = re.search(r'\n\s+op: (\w+)', steps[i])
            return m.group(1) if m else ''
        try:
            login, capture = names.index('Azure login (OIDC)'), names.index('Capture pre-change state (rollback point)')
        except ValueError:
            login = capture = -1
        acq = [i for i in lease_idx if op_of(i) == 'acquire']
        expect(len(acq) == 1 and login < acq[0] < capture,
               'W3 %s: the lease is acquired after Azure login and before the first capture' % wf)
        fenced = True
        for m in mutators:
            try:
                j = names.index(m)
            except ValueError:
                fenced = False
                break
            k = j - 1
            while k > 0 and 'actions/target-lease' not in steps[k] and not any(
                    names[k] == mm for mm in mutators):
                k -= 1
            fenced = fenced and 'uses: $/.github/actions/target-lease' in steps[k] and op_of(k) in ('begin', 'fence')
        expect(fenced, 'W4 %s: a lease begin/fence precedes every mutating step' % wf)
        rev = steps[names.index("Reverse this run's changes")] if "Reverse this run's changes" in names else ''
        expect("KIT_TARGET_LEASE_ACCOUNT == ''" in rev and 'steps.lease_fence_reversal.outcome' in rev,
               'W5 %s: the reversal runs only when the lease is off or its own fence passed' % wf)
        rel = [i for i in lease_idx if op_of(i) == 'release']
        prov = names.index('Stamp provenance (after health and a live read)') if \
            'Stamp provenance (after health and a live read)' in names else 10 ** 6
        expect(len(rel) == 1 and rel[0] > prov and any(op_of(i) == 'end' for i in lease_idx if prov < i < rel[0]),
               'W6 %s: end then release after the last mutating step' % wf)
    # W7: the runner is an input (the lease store is private: D-2), default unchanged.
    for wf in ('reusable-deploy-containerapp.yml', 'reusable-deploy-appservice.yml', 'reusable-rollback-sequence.yml'):
        text = open(os.path.join(ROOT, '.github', 'workflows', wf), encoding='utf-8').read()
        m = re.search(r'\n      runner_label:\n(?:        .*\n)+?        default: "?ubuntu-latest"?\n', text)
        expect(bool(m) and 'runs-on: ${{ inputs.runner_label }}' in text and 'runs-on: ubuntu-latest' not in text
               and re.search(r'posture runner_label\s+NOT_A_CONTROL_SURFACE', text) is not None,
               'W7 %s: runs-on is the runner_label input (default ubuntu-latest), recorded in the posture' % wf)
    # W8: the deploys hold the lease through the e2e test period, then release.
    for wf in ('reusable-deploy-containerapp.yml', 'reusable-deploy-appservice.yml'):
        text = open(os.path.join(ROOT, '.github', 'workflows', wf), encoding='utf-8').read()
        steps = re.split(r'\n      - name: ', text)
        names = [s_.split('\n', 1)[0].strip() for s_ in steps]
        tp = names.index('End-to-end test period (KDEC-021, KDEC-029)') if \
            'End-to-end test period (KDEC-021, KDEC-029)' in names else -1
        ends = [i for i, s_ in enumerate(steps) if 'uses: $/.github/actions/target-lease' in s_ and '\n          op: end' in s_]
        rels = [i for i, s_ in enumerate(steps) if 'uses: $/.github/actions/target-lease' in s_ and '\n          op: release' in s_]
        expect(tp > 0 and 'target_lease.py" hold' in steps[tp] and bool(ends) and ends[0] < tp
               and bool(rels) and rels[0] > tp,
               'W8 %s: end before the test period, hold (heartbeat) through it, release after it' % wf)
    # W9: the rollback sequence: one lease for the whole sequence, held with heartbeats, marked mutating.
    text = open(os.path.join(ROOT, '.github', 'workflows', 'reusable-rollback-sequence.yml'), encoding='utf-8').read()
    steps = re.split(r'\n      - name: ', text)
    names = [s_.split('\n', 1)[0].strip() for s_ in steps]
    login = names.index('Azure login (OIDC)') if 'Azure login (OIDC)' in names else -1
    seq = [i for i, s_ in enumerate(steps) if '\n        id: sequence\n' in s_]
    acq = [i for i, s_ in enumerate(steps) if 'target_lease.py" acquire' in s_]
    rel = [i for i, s_ in enumerate(steps) if 'target_lease.py" release' in s_]
    expect('KIT_TARGET_LEASE_ACCOUNT: ${{ vars.KIT_TARGET_LEASE_ACCOUNT }}' in text and bool(seq) and bool(acq)
           and bool(rel) and login < acq[0] < seq[0] < rel[0] and 'target_lease.py" hold' in steps[seq[0]]
           and '--mark-mutating' in steps[seq[0]]
           and all("env.KIT_TARGET_LEASE_ACCOUNT != ''" in steps[i] for i in acq + rel),
           'W9 rollback sequence: acquire once after login, hold through every step (marked mutating), release; '
           'all off unless opted in')
    # W10: the deploys carry target_lease.py with the contract they inline (the az fence imports it).
    gen = open(os.path.join(ROOT, 'scripts', 'inline_deploy_scripts.py'), encoding='utf-8').read()
    ok = "'target_lease.py'" in gen
    for wf in ('reusable-deploy-containerapp.yml', 'reusable-deploy-appservice.yml'):
        ok = ok and 'kit-deploy/target_lease.py' in open(os.path.join(ROOT, '.github', 'workflows', wf),
                                                          encoding='utf-8').read()
    expect(ok, 'W10 target_lease.py is materialised beside deploy_contract.py in both deploys')


def main():
    try:
        import target_lease as T
    except Exception as e:  # noqa: BLE001
        print('UNKNOWN: scripts/target_lease.py could not be imported (%s)' % e)
        return 2
    base = tempfile.mkdtemp(prefix='lease-xrepo-')
    try:
        cross_repo_cases(T, base)
        wiring_cases()
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        print('UNKNOWN: the proof could not run (%s)' % e)
        return 2
    finally:
        shutil.rmtree(base, ignore_errors=True)
    print()
    if FAILS:
        print('NOT PROVEN: %d case(s) decided wrongly.' % len(FAILS))
        return 1
    print('PROVEN: two repositories contend for one target lease; the second is refused, the stale holder '
          'is fenced, expiry and renewal behave, and the wiring is off unless opted in.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
