#!/usr/bin/env python3
"""The cross-repository target lease, as a model: one lease per deploy target, a fencing token.
(KDEC-030 draft, lane L-SEAM; docs/architecture/LZ_KIT_SEAM_CONTRACT.md, "The lease".)

WHY THIS EXISTS

    A GitHub Actions concurrency group is evaluated inside one repository. The landing-zone apply
    runs in the platform repository and the kit's deploy runs in the application repository, so
    the two never wait for each other, whatever their groups are called. KDEC-030 proposes ONE
    lease per target that every pipeline mutating the target acquires first: an Azure Storage blob
    lease on a blob named for the target, plus a GENERATION number kept in the blob's metadata.
    The pair (lease id, generation) is the fencing token. A holder checks it again immediately
    before every mutation, and once more after it; a holder that lost the lease -- broken, taken
    over, past its own expiry -- is refused before it touches the target, or reported after.

    This module is the model only: pure Python, standard library, no network. `BlobLeaseStore`
    emulates the Lease Blob REST operation's documented states and status codes (Microsoft Learn,
    "Lease Blob": acquire / renew / change / release / break; Available, Leased, Expired,
    Breaking, Broken; 409 and 412). `TargetLease` is the seam protocol on top of it;
    tests/prove_target_lease.py proves the protocol.

    Since lane L-SEAM2 (2026-10-27): `AzureBlobLeaseStore` sends the same calls to the Blob REST
    API with an Entra bearer token, keyed by the target's ARM resource id, and `run_cli` gives
    each pipeline step a subcommand (acquire, begin, fence, end, release, status, break). The
    composite .github/actions/target-lease runs it for BOTH sides -- the landing-zone apply and
    the kit's deploy reusables (opt-in: KIT_TARGET_LEASE_ACCOUNT). tests/prove_target_lease_crossrepo.py
    proves it across two independent callers against a local Blob-service emulation. Not yet
    run against real Azure Storage.

THE PROTOCOL
    acquire     an INFINITE blob lease (an apply runs 4-27 minutes, a rollback sequence up to 240;
                a 15-60 s lease would need a renewer that can die silently) with a LOGICAL expiry,
                `expires_at`, in the metadata, extended by heartbeat. Generation + 1. A target held
                by a live holder is refused LEASE_HELD, naming the holder.
    takeover    a holder past `expires_at` that left the target CLEAN is broken and replaced
                automatically, recorded (`took_over`). One that left it MID-MUTATION is not:
                LEASE_ABANDONED_MID_MUTATION -- a human decides (the break authority).
    fence       before every mutation: a read conditional on the lease id (the service answers
                409/412 when the id is no longer the blob's lease), the generation and holder
                compared with the token, and the logical expiry checked. Any miss is
                STALE_LEASE_HOLDER or LEASE_EXPIRED_HOLDER; the mutation does not happen.
    mutate      fence, mark `mutating`, mutate, fence again. A lease lost during the mutation is
                MUTATED_WITHOUT_LEASE and ROLLBACK_REQUIRES_HUMAN_DECISION, never a clean result.
    break       only an actor in the break authority (the platform admins by default). The blob
                service lets ANY caller with blob write break a lease (Lease Blob: "Any authorized
                request can break the lease"), so the authority is enforced by this protocol and by
                audit, not by Azure RBAC; the generation bump makes every broken holder fenced.

WHAT THE FENCE DOES NOT CLOSE (stated in the contract): fencing stops a stale holder before its
next call; it cannot recall an Azure mutation already sent. The Azure target itself does not check
the token, so a mutation already sent when the lease is lost lands. The after-fence detects it.
"""
import argparse
import base64
import copy
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from email.utils import formatdate
from urllib.parse import urlparse

# ----------------------------------------------------------------------------- the blob service
AVAILABLE, LEASED, EXPIRED, BREAKING, BROKEN = 'available', 'leased', 'expired', 'breaking', 'broken'


class LeaseError(Exception):
    """`code` is an HTTP status (int) from the blob emulation, or a seam outcome (str)."""

    def __init__(self, code, message=''):
        Exception.__init__(self, '%s: %s' % (code, message) if message else str(code))
        self.code = code


class BlobLeaseStore(object):
    """In-memory emulation of the Lease Blob operation over named blobs (one per target).

    Times are plain numbers (seconds) passed in, so a proof controls the clock."""

    def __init__(self):
        self._b = {}

    def _blob(self, key):
        return self._b.setdefault(key, {'state': AVAILABLE, 'lease_id': None, 'duration': None,
                                         'expires': None, 'break_at': None, 'md': {},
                                         'written_after_expiry': False})

    def _tick(self, key, now):
        b = self._blob(key)
        if b['state'] == LEASED and b['duration'] != -1 and now >= b['expires']:
            b['state'], b['written_after_expiry'] = EXPIRED, False
        if b['state'] == BREAKING and now >= b['break_at']:
            b['state'] = BROKEN
        return b

    def state(self, key, now):
        return self._tick(key, now)['state']

    def acquire(self, key, duration, proposed_id, now):
        if not (duration == -1 or 15 <= duration <= 60):
            raise LeaseError(400, 'a lease is 15-60 seconds or -1 (infinite)')
        b = self._tick(key, now)
        lid = proposed_id or str(uuid.uuid4())
        if b['state'] == BREAKING or (b['state'] == LEASED and lid != b['lease_id']):
            raise LeaseError(409, 'the blob has an active lease')
        b.update(state=LEASED, lease_id=lid, duration=duration,
                 expires=None if duration == -1 else now + duration, break_at=None)
        return lid

    def renew(self, key, lease_id, now):
        b = self._tick(key, now)
        if lease_id != b['lease_id'] or b['state'] in (AVAILABLE, BREAKING, BROKEN):
            raise LeaseError(409, 'the lease cannot be renewed')
        if b['state'] == EXPIRED and b['written_after_expiry']:
            raise LeaseError(409, 'the blob was modified since the lease expired')
        b.update(state=LEASED, expires=None if b['duration'] == -1 else now + b['duration'])
        return lease_id

    def release(self, key, lease_id, now):
        b = self._tick(key, now)
        if b['state'] == AVAILABLE or lease_id != b['lease_id']:
            raise LeaseError(409, 'the lease id does not match')
        b.update(state=AVAILABLE, lease_id=None, break_at=None)

    def break_lease(self, key, period, now):
        """No lease id needed. Returns the seconds until a new lease can be acquired."""
        b = self._tick(key, now)
        if b['state'] == AVAILABLE:
            raise LeaseError(409, 'there is currently no lease on the blob')
        if b['state'] in (BROKEN, EXPIRED):
            b['state'] = BROKEN
            return 0
        remaining = None if (b['state'] == LEASED and b['duration'] == -1) else \
            ((b['expires'] if b['state'] == LEASED else b['break_at']) - now)
        if period is None:
            wait = 0 if remaining is None else remaining
        else:
            wait = period if remaining is None else min(period, remaining)
        if wait <= 0:
            b['state'] = BROKEN
            return 0
        b.update(state=BREAKING, break_at=now + wait)
        return wait

    def write(self, key, lease_id, md, now):
        """Set Blob Metadata: the write rules of the documented outcome table."""
        b = self._tick(key, now)
        st, held = b['state'], b['lease_id']
        if st == LEASED:
            if lease_id is None:
                raise LeaseError(412, 'there is a lease on the blob and no lease id was given')
            if lease_id != held:
                raise LeaseError(409, 'the lease id does not match')
        elif st == BREAKING:
            if lease_id != held:
                raise LeaseError(412, 'the lease is breaking')
        elif lease_id is not None:
            raise LeaseError(412, 'there is no active lease with that id')
        elif st in (BROKEN, EXPIRED):
            b.update(state=AVAILABLE, lease_id=None)
        if st == EXPIRED:
            b['written_after_expiry'] = True
        b['md'] = copy.deepcopy(md)

    def read(self, key, lease_id, now):
        """Get Blob Properties, conditional on the lease id when one is given."""
        b = self._tick(key, now)
        if lease_id is not None:
            st = b['state']
            if st in (AVAILABLE, BROKEN, EXPIRED):
                raise LeaseError(412, 'there is no active lease with that id')
            if lease_id != b['lease_id']:
                raise LeaseError(409, 'the lease id does not match')
        return copy.deepcopy(b['md'])


# ----------------------------------------------------------------------------- the seam protocol
CLEAN, MUTATING, broken_mark = 'clean', 'mutating', 'broken'
HUMAN = 'ROLLBACK_REQUIRES_HUMAN_DECISION'


class Token(object):
    """The fencing token a holder carries: (target, lease id, generation, holder)."""

    def __init__(self, target, lease_id, generation, holder, took_over=None):
        self.target, self.lease_id, self.generation = target, lease_id, generation
        self.holder, self.took_over = holder, took_over

    def __repr__(self):
        return 'Token(%s gen=%s holder=%s)' % (self.target, self.generation, self.holder)


class TargetLease(object):
    def __init__(self, store, heartbeat_ttl=600, break_authority=()):
        self.store, self.ttl = store, heartbeat_ttl
        self.authority = set(break_authority)

    # -- acquisition
    def acquire(self, target, holder, now):
        lid, took_over = str(uuid.uuid4()), None
        try:
            self.store.acquire(target, -1, lid, now)
        except LeaseError as e:
            if e.code != 409:
                raise
            md = self.store.read(target, None, now)
            exp = md.get('expires_at')
            if exp is None or now <= exp:
                raise LeaseError('LEASE_HELD', 'target %s is held by %s (generation %s) until %s'
                                 % (target, md.get('holder', '?'), md.get('generation'), exp))
            if md.get('state') == MUTATING:
                raise LeaseError('LEASE_ABANDONED_MID_MUTATION',
                                 '%s expired at %s while mutating (%s); a human decides before '
                                 'anyone takes the target' % (md.get('holder'), exp,
                                                              md.get('mutation')))
            self.store.break_lease(target, 0, now)
            took_over = md.get('holder')
            self.store.acquire(target, -1, lid, now)
        md = self.store.read(target, lid, now)
        gen = int(md.get('generation') or 0) + 1
        hist = list(md.get('history') or [])
        hist.append({'generation': gen, 'holder': holder, 'acquired_at': now,
                     'took_over': took_over})
        self.store.write(target, lid, {'generation': gen, 'holder': holder,
                                       'expires_at': now + self.ttl, 'state': CLEAN,
                                       'mutation': None, 'history': hist[-20:]}, now)
        return Token(target, lid, gen, holder, took_over)

    # -- the fence
    def fence(self, token, now):
        try:
            md = self.store.read(token.target, token.lease_id, now)
        except LeaseError as e:
            if e.code in UNKNOWN_CODES:   # a store that cannot be read is not a lost lease: fail closed
                raise
            raise LeaseError('STALE_LEASE_HOLDER', '%r no longer holds the lease (%s)' % (token, e.code))
        if md.get('generation') != token.generation or md.get('holder') != token.holder:
            raise LeaseError('STALE_LEASE_HOLDER', '%r: the blob is at generation %s, holder %s'
                             % (token, md.get('generation'), md.get('holder')))
        if now > md.get('expires_at', -1):
            raise LeaseError('LEASE_EXPIRED_HOLDER', '%r expired at %s' % (token, md.get('expires_at')))
        return md

    def _put(self, token, md, now):
        self.store.write(token.target, token.lease_id, md, now)

    def heartbeat(self, token, now):
        md = self.fence(token, now)
        md['expires_at'] = now + self.ttl
        self._put(token, md, now)

    def begin_mutation(self, token, what, now):
        md = self.fence(token, now)
        md.update(state=MUTATING, mutation=what)
        self._put(token, md, now)

    def end_mutation(self, token, now):
        md = self.fence(token, now)
        md.update(state=CLEAN, mutation=None)
        self._put(token, md, now)

    def mutate(self, token, what, fn, now, after):
        """Fence, mark, mutate, fence again. -> a result dict; never raises for a lost lease."""
        self.begin_mutation(token, what, now)
        try:
            fn()
        except Exception as e:  # noqa: BLE001 -- the mutation's own failure, recorded
            return {'outcome': 'MUTATION_FAILED', 'rollback_state': HUMAN, 'reason': str(e)}
        try:
            self.end_mutation(token, after)
        except LeaseError as e:
            return {'outcome': 'MUTATED_WITHOUT_LEASE', 'rollback_state': HUMAN,
                    'reason': '%s: the lease was lost while "%s" was in flight' % (e.code, what)}
        return {'outcome': 'MUTATED_UNDER_LEASE', 'rollback_state': None, 'reason': ''}

    def release(self, token, now):
        md = self.fence(token, now)
        if md.get('state') == MUTATING:
            raise LeaseError('RELEASE_MID_MUTATION', '%r is mid-mutation (%s); end or record it '
                             'first' % (token, md.get('mutation')))
        self.store.release(token.target, token.lease_id, now)

    # -- break authority
    def break_lease(self, target, actor, reason, now):
        if actor not in self.authority:
            raise LeaseError('BREAK_NOT_AUTHORISED', '%s is not in the break authority' % actor)
        md = self.store.read(target, None, now)
        self.store.break_lease(target, 0, now)
        md.update(generation=int(md.get('generation') or 0) + 1, broken_by=actor, reason=reason,
                  broken_at=now, state_at_break=md.get('state'), state=broken_mark,
                  expires_at=now)
        self.store.write(target, None, md, now)
        return md


# ----------------------------------------------------------------------------- the live adapter
API_VERSION = '2021-12-02'
STORAGE_RESOURCE = 'https://storage.azure.com/'
BLOB_SUFFIX = {'public': 'blob.core.windows.net', 'gov': 'blob.core.usgovcloudapi.net'}
LEASE_BLOB = 'lease'
META_KEY = 'seam'      # the whole metadata dict, JSON then base64: Azure metadata values are strings


def normalise_target(resource_id):
    """An ARM resource id, lower-cased (ARM ids are case-insensitive): one target, one lease."""
    rid = (resource_id or '').strip().rstrip('/').lower()
    if not re.match(r'^/subscriptions/[0-9a-f-]+/resourcegroups/[^/]+/providers/[^/]+/[^/]+/[^/]+', rid):
        raise ValueError('not an ARM resource id: %r' % resource_id)
    return rid


def container_for(target):
    """The per-target container the LZ vend creates: 't-' + the first 40 hex of sha256(id)."""
    return 't-' + hashlib.sha256(normalise_target(target).encode('utf-8')).hexdigest()[:40]


def bearer_from_az():
    """A storage-scoped Entra token for the identity `az login` (azure/login) signed in."""
    try:
        p = subprocess.run(['az', 'account', 'get-access-token', '--resource', STORAGE_RESOURCE,
                            '--query', 'accessToken', '-o', 'tsv'],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        raise LeaseError('LEASE_STORE_UNREACHABLE', 'no storage token: %s' % e)
    if p.returncode != 0 or not p.stdout.strip():
        raise LeaseError('LEASE_STORE_UNREACHABLE', 'no storage token: %s'
                         % (p.stderr.strip().splitlines() or ['az failed'])[-1])
    return p.stdout.strip()


class AzureBlobLeaseStore(object):
    """The same five calls as BlobLeaseStore, sent to the Blob service's REST API.

    Entra (OAuth bearer) only; shared keys are never used. One container per target, vended by the
    landing zone; the blob `lease` inside it is created on first use. `now` is accepted for the
    model's signature and ignored: the service keeps its own clock, and the protocol's logical
    expiry is the caller's clock (TargetLease). HTTP status codes become LeaseError(status), as the
    emulation raises them; anything that is not a lease answer fails closed."""

    def __init__(self, account=None, endpoint=None, cloud='public', bearer=None, timeout=30):
        if endpoint:
            u = urlparse(endpoint)
            if u.scheme != 'https' and not (u.scheme == 'http' and u.hostname in ('127.0.0.1', 'localhost')):
                raise ValueError('the lease store is reached over https (plain http only to a local '
                                 'test emulator): %s' % endpoint)
            self.base = endpoint.rstrip('/')
        else:
            if not re.match(r'^[a-z0-9]{3,24}$', account or ''):
                raise ValueError('not a storage account name: %r' % account)
            self.base = 'https://%s.%s' % (account, BLOB_SUFFIX.get(cloud, BLOB_SUFFIX['public']))
        self._bearer, self.timeout = bearer, timeout

    def _token(self):
        if not self._bearer:
            self._bearer = os.environ.get('TARGET_LEASE_BEARER') or bearer_from_az()
        return self._bearer

    def _call(self, method, key, comp='', headers=None, blob=LEASE_BLOB, query='', data=None):
        url = '%s/%s' % (self.base, container_for(key)) + ('/' + blob if blob else '')
        q = '&'.join(x for x in (query, 'comp=' + comp if comp else '') if x)
        url += '?' + q if q else ''
        h = {'Authorization': 'Bearer ' + self._token(), 'x-ms-version': API_VERSION,
             'x-ms-date': formatdate(usegmt=True)}
        h.update({k: v for k, v in (headers or {}).items() if v is not None})
        if data is None and method == 'PUT':
            data = b''
        req = urllib.request.Request(url, data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.status, {k.lower(): v for k, v in r.headers.items()}
        except urllib.error.HTTPError as e:
            code, err = e.code, (e.headers.get('x-ms-error-code') or '')
            if code == 404 and err == 'ContainerNotFound':
                raise LeaseError('LEASE_TARGET_NOT_VENDED', 'no lease container %s for %s: the landing '
                                 'zone vends it with the target' % (container_for(key), key))
            if code in (404, 409, 412):
                raise LeaseError(code, err or 'blob service %s' % code)
            raise LeaseError('LEASE_STORE_UNREACHABLE', 'blob service answered %s %s' % (code, err))
        except (urllib.error.URLError, OSError) as e:
            raise LeaseError('LEASE_STORE_UNREACHABLE', '%s: %s' % (self.base, getattr(e, 'reason', e)))

    def _ensure_blob(self, key):
        try:
            self._call('PUT', key, headers={'x-ms-blob-type': 'BlockBlob', 'If-None-Match': '*',
                                            'Content-Length': '0'})
        except LeaseError as e:
            if e.code not in (409, 412):      # it exists already (or is leased): both fine
                raise

    def state(self, key, now=None):
        try:
            return self._call('HEAD', key)[1].get('x-ms-lease-state', AVAILABLE)
        except LeaseError as e:
            if e.code == 404:
                return AVAILABLE
            raise

    def acquire(self, key, duration, proposed_id, now=None):
        hdr = {'x-ms-lease-action': 'acquire', 'x-ms-lease-duration': str(duration),
               'x-ms-proposed-lease-id': proposed_id or str(uuid.uuid4())}
        try:
            return self._call('PUT', key, 'lease', hdr)[1].get('x-ms-lease-id', hdr['x-ms-proposed-lease-id'])
        except LeaseError as e:
            if e.code != 404:
                raise
        self._ensure_blob(key)
        return self._call('PUT', key, 'lease', hdr)[1].get('x-ms-lease-id', hdr['x-ms-proposed-lease-id'])

    def release(self, key, lease_id, now=None):
        self._call('PUT', key, 'lease', {'x-ms-lease-action': 'release', 'x-ms-lease-id': lease_id})

    def break_lease(self, key, period, now=None):
        h = self._call('PUT', key, 'lease', {'x-ms-lease-action': 'break',
                                             'x-ms-lease-break-period': None if period is None else str(period)})[1]
        return int(h.get('x-ms-lease-time') or 0)

    def write(self, key, lease_id, md, now=None):
        enc = base64.b64encode(json.dumps(md, sort_keys=True).encode('utf-8')).decode('ascii')
        self._call('PUT', key, 'metadata', {'x-ms-lease-id': lease_id, 'x-ms-meta-' + META_KEY: enc})

    # OF-5 K-4 (KDEC-030 kit item 2): the target's durable `releases/` folder, beside its lease blob.
    def put_record(self, key, name, data):
        """Create `releases/...` once (If-None-Match: *): a record is never overwritten (409 instead)."""
        self._call('PUT', key, blob=name, data=data,
                   headers={'x-ms-blob-type': 'BlockBlob', 'If-None-Match': '*',
                            'Content-Type': 'application/json', 'Content-Length': str(len(data)),
                            'x-ms-meta-kind': 'kit-release-record'})

    def retention_policy(self, key):
        """-> 'present' | 'absent' | 'unreadable': whether the container carries an immutability
        policy (or a legal hold) -- the landing zone's retention of what the kit keeps there."""
        try:
            h = self._call('HEAD', key, blob='', query='restype=container')[1]
        except LeaseError as e:
            if e.code == 'LEASE_TARGET_NOT_VENDED':
                raise
            return 'unreadable'
        flags = [h.get('x-ms-has-immutability-policy'), h.get('x-ms-has-legal-hold'),
                 h.get('x-ms-immutable-storage-with-versioning-enabled')]
        if any(str(f).lower() == 'true' for f in flags):
            return 'present'
        return 'absent' if any(f is not None for f in flags) else 'unreadable'

    def read(self, key, lease_id, now=None):
        try:
            h = self._call('HEAD', key, headers={'x-ms-lease-id': lease_id})[1]
        except LeaseError as e:
            if e.code == 404 and lease_id is None:
                return {}
            raise
        raw = h.get('x-ms-meta-' + META_KEY)
        if not raw:
            return {}
        try:
            return json.loads(base64.b64decode(raw).decode('utf-8'))
        except (ValueError, TypeError) as e:
            raise LeaseError('LEASE_STORE_UNREACHABLE', 'the lease metadata is unreadable (%s)' % e)


# ----------------------------------------------------------------------------- the command line
# One subcommand per pipeline step; the token file carries the fencing token between steps.
# Prints `target_lease=<VALUE>` and `target_lease_reason=<text>` (and appends them to
# $GITHUB_OUTPUT when set). EXIT 0 done; 1 refused, by name; 2 could not check -- fail closed.
#
#   hold  runs a long step (the e2e test period, a whole rollback sequence) as a child process
#         and renews the lease every --every seconds (default 180, below a third of the 10-minute
#         TTL). A failed renewal stops the child at once and ends LEASE_LOST, exit 1; the loss is
#         recorded beside the token, so every later fence of this run -- including the one each
#         mutating az call takes (deploy_contract.az) -- is refused LEASE_LOST without asking the
#         store again: no further mutation. --mark-mutating marks the lease `mutating` for the
#         child's whole run and clean only when it exits 0 (a halted rollback stays a human decision).
UNKNOWN_CODES = ('LEASE_STORE_UNREACHABLE', 'LEASE_TARGET_NOT_VENDED')
ARM_TYPES = {'containerapp': 'Microsoft.App/containerApps', 'appservice': 'Microsoft.Web/sites',
             'staticwebapp': 'Microsoft.Web/staticSites'}
LOST_SUFFIX = '.lost'
DEFAULT_TOKEN = os.path.join('kit-target-lease', 'token.json')


def default_token_file():
    """Where a job keeps its token: KIT_TARGET_LEASE_TOKEN, else $RUNNER_TEMP/kit-target-lease/token.json."""
    return os.environ.get('KIT_TARGET_LEASE_TOKEN') or os.path.join(
        os.environ.get('RUNNER_TEMP') or '.', DEFAULT_TOKEN)


def target_id(adapter, subscription, resource_group, name):
    """The ARM resource id of a kit target. App Service: the SITE, never a slot (a swap changes both)."""
    if adapter not in ARM_TYPES:
        raise ValueError('no lease target type for adapter %r' % adapter)
    return '/subscriptions/%s/resourceGroups/%s/providers/%s/%s' % (subscription, resource_group,
                                                                    ARM_TYPES[adapter], name)


def _emit(values, github_output):
    lines = []
    for k, v in values.items():
        lines.append('%s=%s' % (k, ' '.join(str(v if v is not None else '').split())))
    print('\n'.join(lines))
    sys.stdout.flush()
    if github_output:
        with open(github_output, 'a', encoding='utf-8') as f:
            f.write('\n'.join(lines) + '\n')


def _store(a):
    return AzureBlobLeaseStore(account=a.account, endpoint=a.endpoint, cloud=a.cloud)


def _load_token(path):
    with open(path, encoding='utf-8') as f:
        d = json.load(f)
    a = argparse.Namespace(account=d.get('account'), endpoint=d.get('endpoint'), cloud=d.get('cloud'),
                           ttl=d.get('ttl', 600))
    return a, Token(d['target'], d['lease_id'], d['generation'], d['holder'], d.get('took_over'))


def check_not_lost(path):
    marker = path + LOST_SUFFIX
    if os.path.exists(marker):
        with open(marker, encoding='utf-8') as f:
            why = f.read().strip()
        raise LeaseError('LEASE_LOST', 'this run lost the lease earlier (%s); nothing further is mutated' % why)


def mark_lost(path, why):
    with open(path + LOST_SUFFIX, 'w', encoding='utf-8') as f:
        f.write(' '.join(str(why).split()))


def fence_token_file(path=None, now=None, mark=True):
    """The fence a mutating call takes, and the hold's renewal: fence + heartbeat. -> the token.

    Raises LeaseError: LEASE_NOT_HELD (no token: this run never acquired the target), LEASE_LOST
    (lost earlier in this run), or the fence's own refusal. With `mark`, any refusal is recorded as
    lost, so nothing later in the run mutates on a lease that failed once."""
    path = path or default_token_file()
    if not os.path.exists(path):
        raise LeaseError('LEASE_NOT_HELD', 'no lease token at %s: this run never acquired the target' % path)
    check_not_lost(path)
    cfg, tok = _load_token(path)
    lease = TargetLease(_store(cfg), heartbeat_ttl=int(cfg.ttl or 600))
    try:
        lease.heartbeat(tok, time.time() if now is None else now)
    except LeaseError as e:
        if mark:
            mark_lost(path, '%s: %s' % (e.code, e))
        raise
    return tok


def _stop(child):
    try:
        if os.name == 'posix':
            import signal
            os.killpg(child.pid, signal.SIGTERM)
        else:
            child.terminate()
        child.wait(timeout=15)
    except Exception:  # noqa: BLE001 -- stopping is best effort, then forced
        try:
            if os.name == 'posix':
                import signal
                os.killpg(child.pid, signal.SIGKILL)
            else:
                child.kill()
        except Exception:  # noqa: BLE001
            pass


def _hold(a, cmd, done):
    if not cmd:
        raise ValueError('hold needs the command to run after --')
    path = a.token_file or default_token_file()

    def lost(e):
        return done('LEASE_LOST', '%s: %s; the held step was stopped and nothing further is mutated'
                    % (e.code, e), 1)
    try:
        tok = fence_token_file(path)
        if a.mark_mutating:
            cfg, _ = _load_token(path)
            TargetLease(_store(cfg), heartbeat_ttl=int(cfg.ttl or 600)).begin_mutation(
                tok, a.mark_mutating, time.time())
    except LeaseError as e:
        if not os.path.exists(path + LOST_SUFFIX) and os.path.exists(path):
            mark_lost(path, '%s: %s' % (e.code, e))
        return lost(e)
    kw = {'start_new_session': True} if os.name == 'posix' else {}
    child = subprocess.Popen(cmd, **kw)
    while True:
        try:
            rc = child.wait(timeout=max(1, a.every))
            break
        except subprocess.TimeoutExpired:
            try:
                fence_token_file(path)
            except LeaseError as e:
                _stop(child)
                return lost(e)
    try:
        tok = fence_token_file(path)
        if a.mark_mutating and rc == 0:
            cfg, _ = _load_token(path)
            TargetLease(_store(cfg), heartbeat_ttl=int(cfg.ttl or 600)).end_mutation(tok, time.time())
    except LeaseError as e:
        if not os.path.exists(path + LOST_SUFFIX):
            mark_lost(path, '%s: %s' % (e.code, e))
        return lost(e)
    return done('LEASE_FENCE_PASSED', '%r held through the step (exit %s)%s' % (
        tok, rc, '' if not a.mark_mutating else (', clean' if rc == 0 else ', left mutating: a human decides')),
        rc)


RELEASE_RECORD_SCHEMA = 'kit-release-record/1'
RECORD_KEPT = 'RELEASE_RECORD_KEPT'
RECORD_NOT_KEPT = 'RELEASE_RECORD_NOT_KEPT'


def release_record(rec, target, environment, routing_result, written_at, tok):
    """The record the landing zone reads (OF-5 K-4): its fields first, the promotion record whole."""
    live = rec.get('live_state') or {}
    return {'schema': RELEASE_RECORD_SCHEMA, 'kind': 'kit-release', 'written_at': written_at,
            'target_resource_id': target, 'environment': environment,
            'digest': (rec.get('artifact') or {}).get('digest'),
            'now_serving': live.get('now_serving') or [],
            'deployment_outcome': live.get('deployment_outcome'),
            'state': rec.get('state'), 'validity': rec.get('validity') or {},
            'run': rec.get('run') or {}, 'routing_result': routing_result or None,
            'gate_routing_result': (rec.get('provenance') or {}).get('gate_routing_result'),
            'lease': {'holder': tok.holder, 'generation': tok.generation},
            'promotion_record': rec}


def _record(a, now, github_output):
    """`record`: keep this run's release record in the target's releases/ folder, create-only.

    Uses the run's lease token for the target and the store (the lease need not still be held: the
    folder is not the leased blob). EXIT 0 kept; 1 refused (no record, a name that already exists);
    2 the store could not be reached or the target's container was never vended -- fail closed."""
    def done(value, why, code, **extra):
        _emit(dict({'release_record': value, 'release_record_reason': why}, **extra), github_output)
        return code
    path = a.token_file or default_token_file()
    if not os.path.exists(path):
        _emit({'target_lease': 'LEASE_NOT_HELD', 'target_lease_reason': 'no lease token at %s: this run '
               'never acquired the target, so it has no release record to keep there' % path}, github_output)
        return 1
    cfg, tok = _load_token(path)
    try:
        with open(a.record_file, encoding='utf-8') as f:
            rec = json.load(f)
        if not isinstance(rec, dict):
            raise ValueError('not an object')
    except (OSError, ValueError) as e:
        return done(RECORD_NOT_KEPT, 'there is no promotion record to keep (%s)' % e, 1)
    stamp = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime(now))
    env_slug = re.sub(r'[^A-Za-z0-9._-]', '-', a.environment or 'env')[:40]
    run = rec.get('run') or {}
    name = 'releases/%s/%s-%s-%s.json' % (env_slug, stamp, re.sub(r'\D', '', str(run.get('id') or '')) or 'local',
                                          re.sub(r'\D', '', str(run.get('attempt') or '')) or '1')
    store = _store(cfg)
    try:
        retention = store.retention_policy(tok.target)
        doc = release_record(rec, tok.target, a.environment, a.routing_result,
                             time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(now)), tok)
        doc['retention_policy'] = retention
        store.put_record(tok.target, name, json.dumps(doc, indent=1, sort_keys=True).encode('utf-8'))
    except LeaseError as e:
        if e.code in (409, 412):
            return done(RECORD_NOT_KEPT, '%s already exists in %s: a release record is never overwritten'
                        % (name, container_for(tok.target)), 1)
        return done(RECORD_NOT_KEPT, '%s: %s' % (e.code, e), 2)
    if retention != 'present':
        print('::warning title=Release record retention not established::%s/%s is kept, but the container '
              'carries %s immutability policy. The landing zone sets a time-based retention on it at least '
              'as long as its Git evidence (docs/architecture/LZ_KIT_HANDOFF_CONTRACT.md).'
              % (container_for(tok.target), name, 'no' if retention == 'absent' else 'an unreadable'))
    return done(RECORD_KEPT, 'kept as %s/%s' % (container_for(tok.target), name), 0,
                release_record_path='%s/%s' % (container_for(tok.target), name),
                release_record_retention=retention)


def run_cli(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = []
    if '--' in argv:
        k = argv.index('--')
        argv, cmd = argv[:k], argv[k + 1:]
    p = argparse.ArgumentParser(description='The cross-repository target lease (KDEC-030 draft).')
    p.add_argument('op', choices=['acquire', 'fence', 'begin', 'end', 'release', 'status', 'break', 'hold',
                                  'record'])
    p.add_argument('--resource-id', default='')
    p.add_argument('--adapter', default='', help='with --subscription --resource-group --name: builds the id')
    p.add_argument('--subscription', default='')
    p.add_argument('--resource-group', default='')
    p.add_argument('--name', default='')
    p.add_argument('--holder', default='')
    p.add_argument('--account', default='')
    p.add_argument('--endpoint', default='', help='test emulator only; the account name decides the URL')
    p.add_argument('--cloud', default=os.environ.get('CLOUD') or 'public')
    p.add_argument('--ttl', type=int, default=600, help='heartbeat TTL in seconds (KDEC-030 O-5)')
    p.add_argument('--token-file', default='')
    p.add_argument('--what', default='')
    p.add_argument('--every', type=int, default=180, help='hold: seconds between renewals (below TTL/3)')
    p.add_argument('--mark-mutating', default='', help='hold: mark the lease mutating for the child run')
    p.add_argument('--actor', default='')
    p.add_argument('--reason', default='')
    p.add_argument('--authority', default=os.environ.get('TARGET_LEASE_BREAK_AUTHORITY') or 'platform-admins')
    p.add_argument('--now', type=float, default=None, help='a fixed clock, for proofs only')
    p.add_argument('--github-output', default=os.environ.get('GITHUB_OUTPUT') or '')
    p.add_argument('--record-file', default='', help='record: the promotion record to keep in releases/')
    p.add_argument('--environment', default='', help='record: the GitHub environment (the folder)')
    p.add_argument('--routing-result', default='', help='record: the routing_result of the deploy itself')
    a = p.parse_args(argv)
    now = a.now if a.now is not None else time.time()
    out = {}

    def done(value, reason='', code=0, **extra):
        out.update(target_lease=value, target_lease_reason=reason, **extra)
        _emit(out, a.github_output)
        return code

    try:
        if a.op == 'record':
            return _record(a, now, a.github_output)
        if a.op == 'hold':
            return _hold(a, cmd, done)
        if a.op in ('acquire', 'status', 'break'):
            rid = a.resource_id or (target_id(a.adapter, a.subscription, a.resource_group, a.name)
                                    if a.adapter else '')
            target = normalise_target(rid)
            store = _store(a)
            lease = TargetLease(store, heartbeat_ttl=a.ttl, break_authority=a.authority.split(','))
            if a.op == 'status':
                md = store.read(target, None, now)
                return done('LEASE_STATUS', 'holder %s generation %s state %s expires_at %s'
                            % (md.get('holder'), md.get('generation'), md.get('state'), md.get('expires_at')))
            if a.op == 'break':
                md = lease.break_lease(target, a.actor, a.reason, now)
                return done('LEASE_BROKEN', '%s broke generation %s (%s): %s' % (
                    a.actor, int(md['generation']) - 1, md.get('state_at_break'), a.reason))
            if not a.holder:
                raise ValueError('acquire needs --holder')
            token_file = a.token_file or default_token_file()
            tok = lease.acquire(target, a.holder, now)
            d = os.path.dirname(os.path.abspath(token_file))
            os.makedirs(d, exist_ok=True)
            if os.path.exists(token_file + LOST_SUFFIX):
                os.remove(token_file + LOST_SUFFIX)
            with open(token_file, 'w', encoding='utf-8') as f:
                json.dump({'target': tok.target, 'lease_id': tok.lease_id, 'generation': tok.generation,
                           'holder': tok.holder, 'took_over': tok.took_over, 'account': a.account,
                           'endpoint': a.endpoint, 'cloud': a.cloud, 'ttl': a.ttl}, f)
            return done('LEASE_ACQUIRED', '%s holds %s at generation %s' % (tok.holder, target, tok.generation),
                        target_lease_generation=tok.generation, target_lease_took_over=tok.took_over or '')
        token_file = a.token_file or default_token_file()
        if not os.path.exists(token_file):
            raise LeaseError('LEASE_NOT_HELD', 'no lease token at %s: this run never acquired the target'
                             % token_file)
        check_not_lost(token_file)
        cfg, tok = _load_token(token_file)
        lease = TargetLease(_store(cfg), heartbeat_ttl=int(cfg.ttl or 600))
        if a.op == 'fence':
            lease.heartbeat(tok, now)
            return done('LEASE_FENCE_PASSED', '%r, renewed for %ss' % (tok, lease.ttl))
        if a.op == 'begin':
            lease.heartbeat(tok, now)
            lease.begin_mutation(tok, a.what or 'mutation', now)
            return done('LEASE_MUTATION_MARKED', '%r: %s' % (tok, a.what or 'mutation'))
        if a.op == 'end':
            try:
                lease.end_mutation(tok, now)
            except LeaseError as e:
                if e.code in UNKNOWN_CODES:
                    raise
                return done('MUTATED_WITHOUT_LEASE', '%s: %s; %s' % (e.code, e, HUMAN), 1)
            return done('MUTATED_UNDER_LEASE', repr(tok))
        lease.release(tok, now)
        return done('LEASE_RELEASED', repr(tok))
    except LeaseError as e:
        code = e.code if isinstance(e.code, str) else 'LEASE_STORE_UNREACHABLE'
        return done(code, str(e), 2 if code in UNKNOWN_CODES else 1)
    except ValueError as e:
        print('UNKNOWN: %s' % e, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(run_cli())
