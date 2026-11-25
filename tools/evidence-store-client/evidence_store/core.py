"""The five operations. Plain functions: no argparse, no print, no process-wide identity.

Every function takes the StoreTarget (where), a token provider (who -- per call), the store
contract where writes happen, and returns a result dataclass (see results.py) whose to_dict()
serialises to JSON. Expected failures (refusal, auth, network, conflict) are returned as statuses,
not raised, so a CLI or an HTTP front end can map them without catching.
"""
import json
import mimetypes
import os
from typing import Callable, Optional

from . import publication as P
from . import records as R
from . import results as S
from .auth import get_token, writer_from_token
from .blob import BlobService, StoreTarget, block_id
from .contract import (LAYERS, MANIFEST_DIR, RECEIPT_SUFFIX, StoreContract, check_write,
                       normalise_blob_name)
from .errors import (AuthError, EvidenceStoreError, NetworkError, RefusedError, ServiceError,
                     redact)

TokenProvider = Callable[[], str]

DEFAULT_BLOCK_THRESHOLD = 32 * 1024 * 1024
DEFAULT_BLOCK_SIZE = 8 * 1024 * 1024
SEAL_CONTAINER = 'seal'
INDEX_CONTAINER = 'index'


def _kind(e):
    return {'REFUSED': S.REFUSED, 'AUTH': S.AUTH, 'NETWORK': S.NETWORK}.get(e.kind, S.ERROR)


def _join(prefix, rel):
    rel = rel.replace('\\', '/')
    if not prefix:
        return rel
    return prefix.rstrip('/') + '/' + rel


def _content_type(path, override=None):
    if override:
        return override
    t, _ = mimetypes.guess_type(path)
    return t or 'application/octet-stream'


def _collect(source):
    """-> list of (abs_path, relative_path). A file -> its basename. Never follows symlinks."""
    source = os.path.abspath(source)
    if os.path.isfile(source):
        return [(source, os.path.basename(source))], True
    if not os.path.isdir(source):
        raise RefusedError('source %s is not a file or directory' % source)
    out = []
    for base, dirs, files in os.walk(source, followlinks=False):
        dirs.sort()
        for f in sorted(files):
            p = os.path.join(base, f)
            out.append((p, os.path.relpath(p, source).replace(os.sep, '/')))
    return out, False


def _existing_sha(svc, container, name):
    """-> (sha256, size, version_id) of the stored blob, or None when it does not exist."""
    r = svc.get_blob(container, name)
    if r is None:
        return None
    return R.sha256_bytes(r.body), len(r.body), r.header('x-ms-version-id')


def _put_once(svc, container, name, data=None, path=None, size=0, content_type='',
              block_threshold=DEFAULT_BLOCK_THRESHOLD, block_size=DEFAULT_BLOCK_SIZE,
              sha256=None):
    """Put-once. -> (status, version_id, method, message). Never overwrites."""
    if data is None and size > block_threshold:
        if svc.head_blob(container, name) is not None:
            resp = None
        else:
            ids = []
            with open(path, 'rb') as fh:
                n = 0
                while True:
                    chunk = fh.read(block_size)
                    if not chunk:
                        break
                    bid = block_id(n)
                    svc.put_block(container, name, bid, chunk)
                    ids.append(bid)
                    n += 1
            resp = svc.put_block_list_once(container, name, ids, content_type)
        method = 'PutBlock+PutBlockList'
    else:
        if data is None:
            with open(path, 'rb') as fh:
                data = fh.read()
        resp = svc.put_blob_once(container, name, data, content_type)
        method = 'PutBlob'
    if resp is not None and resp.status == 201:
        return S.CREATED, resp.header('x-ms-version-id'), method, ''
    if resp is not None and resp.status not in (409, 412, 403):
        svc.fail('put %s/%s' % (container, name), resp)
    # 409/412: the blob exists. 403: a create-only role may be refused an overwrite -- look.
    found = _existing_sha(svc, container, name)
    if found is None:
        if resp is not None and resp.status == 403:
            raise AuthError('put %s/%s: HTTP 403 %s (not permitted to create here)'
                            % (container, name, resp.error_code() or ''), 403)
        raise ServiceError('put %s/%s: service reported a conflict but the blob is not readable'
                           % (container, name))
    if found[0] == sha256:
        return S.ALREADY_PRESENT, found[2], method, 'identical bytes already stored'
    return (S.CONFLICT, found[2], method,
            'a different object is stored at this name (stored sha256 %s); never overwritten'
            % found[0])


def _write_receipt(svc, container, name, receipt, expected_sha):
    rname = R.receipt_name(name)
    body = R.dumps(receipt)
    resp = svc.put_blob_once(container, rname, body, 'application/json')
    if resp.status == 201:
        return rname, S.CREATED, ''
    if resp.status not in (409, 412, 403):
        svc.fail('put receipt %s/%s' % (container, rname), resp)
    existing = svc.get_blob(container, rname)
    if existing is None:
        if resp.status == 403:
            raise AuthError('put receipt %s/%s: HTTP 403' % (container, rname), 403)
        raise ServiceError('receipt %s/%s conflict but unreadable' % (container, rname))
    try:
        old = json.loads(existing.body.decode('utf-8'))
        old_sha = old['object']['sha256']
    except Exception:
        return rname, S.CONFLICT, 'an unreadable receipt is already stored at this name'
    if old_sha == expected_sha:
        return rname, S.ALREADY_PRESENT, 'receipt for the same sha256 already stored'
    return rname, S.CONFLICT, 'stored receipt names sha256 %s' % old_sha


def push(target: StoreTarget, token_provider: TokenProvider, contract: StoreContract, *,
         tool: str, source: str, container: str, prefix: str = '', layer: Optional[str] = None,
         case_id: Optional[str] = None, package_id: Optional[str] = None,
         run_id: Optional[str] = None, index_fields: Optional[dict] = None,
         content_type: Optional[str] = None, write_manifest: Optional[bool] = None,
         block_threshold: int = DEFAULT_BLOCK_THRESHOLD, block_size: int = DEFAULT_BLOCK_SIZE,
         env: Optional[dict] = None, now=None,
         api_context: Optional[dict] = None) -> S.PushResult:
    """Push a file or directory, put-once, with a receipt per object and (for a directory) a
    manifest. Every path is checked against the contract before the first network call; one
    refusal refuses the whole batch.

    api_context: set only by an HTTP front end. Written verbatim as the `api` field of every
    receipt and manifest (the caller the front end authenticated, its request id). Absent from
    the documents when None."""
    res = S.PushResult(status=S.OK, container=container, prefix=prefix, tool=tool)
    ids = {'case_id': case_id, 'package_id': package_id, 'run_id': run_id}
    # ── 1. local checks, no network ────────────────────────────────────────────────
    try:
        if index_fields:
            unknown = sorted(set(index_fields) - set(R.INDEX_FIELDS))
            if unknown:
                raise RefusedError('unknown index field(s) %s; allowed: %s'
                                   % (unknown, list(R.INDEX_FIELDS)))
        if layer and layer not in LAYERS:
            raise RefusedError('unknown layer %r' % layer)
        if prefix:
            normalise_blob_name(prefix.rstrip('/'))
        files, single = _collect(source)
        if write_manifest is None:
            write_manifest = not single
        if not files:
            raise RefusedError('nothing to push: %s is empty' % source)
    except EvidenceStoreError as e:
        res.status, res.message = _kind(e), str(e)
        return res
    plan, refused = [], False
    for path, rel in files:
        o = S.ObjectResult(container=container, name=_join(prefix, rel), status=S.NOT_ATTEMPTED,
                           relative_path=rel)
        try:
            if os.path.islink(path):
                raise RefusedError('%s is a symbolic link; links are not followed' % rel)
            o.layer = check_write(contract, tool, container, o.name, layer)
            o.content_type = _content_type(path, content_type)
            _publication_check(container, o.name, path, o.content_type, ids, index_fields)
        except EvidenceStoreError as e:
            o.status, o.message, refused = S.REFUSED, str(e), True
        plan.append((path, o))
        res.objects.append(o)
    if refused:
        for _, o in plan:
            if o.status == S.NOT_ATTEMPTED:
                o.message = 'not attempted: another path in this batch was refused'
        res.status = S.REFUSED
        res.message = 'refused before any network call; nothing was written'
        res.counts = _push_counts(res.objects)
        return res
    # ── 2. network ─────────────────────────────────────────────────────────────────
    try:
        svc = BlobService(target, token_provider)
        token = get_token(token_provider)
    except EvidenceStoreError as e:
        res.status, res.message = _kind(e), str(e)
        return res
    writer = writer_from_token(token)
    gh = R.github_context(env)
    stop = None
    for path, o in plan:
        if stop:
            o.message = 'not attempted: %s' % stop
            continue
        try:
            o.sha256, o.size = R.sha256_file(path)
            o.status, o.version_id, o.upload_method, o.message = _put_once(
                svc, container, o.name, path=path, size=o.size, content_type=o.content_type,
                block_threshold=block_threshold, block_size=block_size, sha256=o.sha256)
            if o.status in (S.CREATED, S.ALREADY_PRESENT):
                rec = R.build_receipt(
                    container=container, blob_name=o.name, sha256=o.sha256, size=o.size,
                    content_type=o.content_type, tool=tool, layer=o.layer, ids=ids,
                    source_relative_path=o.relative_path, writer=writer,
                    written_at=now or R.utc_now(), contract=contract,
                    index_fields=index_fields, github=gh, upload_method=o.upload_method,
                    api=api_context)
                o.receipt_name, o.receipt_status, msg = _write_receipt(svc, container, o.name,
                                                                       rec, o.sha256)
                if o.receipt_status == S.CONFLICT:
                    o.status, o.message = S.CONFLICT, 'receipt conflict: ' + msg
        except (AuthError, NetworkError) as e:
            o.status, o.message = _kind(e), str(e)
            stop = '%s on %s' % (o.status, o.name)
        except EvidenceStoreError as e:
            o.status, o.message = S.ERROR, str(e)
    # ── 3. manifest ────────────────────────────────────────────────────────────────
    res.counts = _push_counts(res.objects)
    if write_manifest and not stop:
        res.manifest = _write_manifest(svc, contract, tool, container, prefix, layer, ids, writer,
                                       gh, res, now or R.utc_now(), api_context)
    statuses = [o.status for o in res.objects]
    if res.manifest is not None:
        statuses.append(res.manifest.status)
    res.status = _overall_push(statuses)
    return res


def _publication_check(container, name, path, content_type, ids, index_fields):
    """The publication gate (PROTOCOL.md 4.2) for the six Tines-readable result containers:
    schema-valid, scanned objects only; their ids, index fields and name scanned too. Raw
    containers pass through. A refusal is a RefusedError (exit 5), before any network call."""
    pol = P.load_policy()
    if not pol.gated(container):
        return
    try:
        P.check_metadata(container, [('blob name', name)]
                         + [('id %s' % k, v) for k, v in sorted((ids or {}).items())]
                         + [('index field %s' % k, v)
                            for k, v in sorted((index_fields or {}).items())], pol)
        size = os.path.getsize(path)
        if size > pol.max_bytes:
            raise P.PublicationRefused(P.PUB_TOO_LARGE, '%s: %d bytes is over the publication '
                                       'limit of %d' % (name, size, pol.max_bytes))
        with open(path, 'rb') as fh:
            P.check_object(container, name, fh.read(), content_type, pol)
    except P.PublicationRefused as e:
        raise RefusedError(str(e))


def _publish_doc_check(container, name, body):
    try:
        P.check_object(container, name, body, 'application/json')
    except P.PublicationRefused as e:
        raise RefusedError(str(e))


def _push_counts(objs):
    c = {'files_present': len(objs)}
    for k in (S.CREATED, S.ALREADY_PRESENT, S.CONFLICT, S.REFUSED):
        c[k.lower()] = sum(1 for o in objs if o.status == k)
    c['failed'] = c['files_present'] - sum(c[k] for k in ('created', 'already_present',
                                                          'conflict', 'refused'))
    return c


def _overall_push(statuses):
    w = S.worst([S.OK if s == S.CREATED else s for s in statuses])
    if w == S.NOT_ATTEMPTED:
        return S.ERROR
    if S.NOT_ATTEMPTED in statuses and w in (S.OK, S.ALREADY_PRESENT):
        return S.ERROR
    if w == S.ALREADY_PRESENT and S.CREATED in statuses:
        return S.OK
    return w


def _write_manifest(svc, contract, tool, container, prefix, layer, ids, writer, gh, res, now,
                    api=None):
    files = [{'relative_path': o.relative_path, 'blob_name': o.name, 'sha256': o.sha256,
              'size': o.size, 'status': o.status, 'version_id': o.version_id,
              'receipt_name': o.receipt_name} for o in res.objects]
    doc, listing_sha = R.build_manifest(container=container, prefix=prefix, tool=tool,
                                        layer=layer, ids=ids, writer=writer, created_at=now,
                                        files=files, counts=res.counts, github=gh,
                                        contract=contract, api=api)
    # Named by the batch digest, not the clock: an identical retry (same objects, hashes, outcomes
    # and run metadata) finds its own manifest and is ALREADY_PRESENT, at any time; a different
    # batch in the same second gets a different name (PROTOCOL.md section 4).
    name = _join(prefix, '%s/%s.json' % (MANIFEST_DIR, doc['batch_sha256']))
    m = S.ObjectResult(container=container, name=name, status=S.NOT_ATTEMPTED,
                       content_type='application/json')
    try:
        m.layer = check_write(contract, tool, container, name, layer, internal=True)
        body = R.dumps(doc)
        m.sha256, m.size = R.sha256_bytes(body), len(body)
        m.status, m.version_id, m.upload_method, m.message = _put_once(
            svc, container, name, data=body, size=m.size, content_type=m.content_type,
            sha256=m.sha256)
        if m.status == S.CONFLICT:
            # the bytes differ (created_at, statuses, writer); the BATCH is what is compared, and
            # it is RECOMPUTED from the stored content, never taken from its declared field
            stored = svc.get_blob(container, name)
            same, _, why = R.check_stored_manifest(stored.body if stored is not None else None,
                                                   doc['batch_sha256'])
            if same:
                m.sha256, m.size = R.sha256_bytes(stored.body), len(stored.body)
                m.version_id = stored.header('x-ms-version-id')
                m.status, m.message = S.ALREADY_PRESENT, why
            else:
                m.message = why + '; never overwritten'
        if m.status in (S.CREATED, S.ALREADY_PRESENT):
            rec = R.build_receipt(container=container, blob_name=name, sha256=m.sha256,
                                  size=m.size, content_type=m.content_type, tool=tool,
                                  layer=m.layer, ids=ids, source_relative_path=None,
                                  writer=writer, written_at=now, contract=contract, github=gh,
                                  api=api)
            m.receipt_name, m.receipt_status, _ = _write_receipt(svc, container, name, rec,
                                                                 m.sha256)
    except EvidenceStoreError as e:
        m.status, m.message = _kind(e), str(e)
    return m


# ── verify ─────────────────────────────────────────────────────────────────────────
def _targets(svc, container, name=None, prefix=None):
    if name:
        return [normalise_blob_name(name)]
    return sorted(b['name'] for b in svc.list_blobs(container, prefix or '')
                  if not b['name'].endswith(RECEIPT_SUFFIX))


def _receipt_of(svc, container, name):
    r = svc.get_blob(container, R.receipt_name(name))
    if r is None:
        return None, None
    try:
        return json.loads(r.body.decode('utf-8')), R.sha256_bytes(r.body)
    except ValueError:
        return {}, R.sha256_bytes(r.body)


def _check_one(svc, container, name):
    v = S.Verdict(container=container, name=name, verdict=S.VERIFIED,
                  receipt_name=R.receipt_name(name))
    blob = svc.get_blob(container, name)
    if blob is None:
        v.verdict = S.MISSING
        v.notes.append('no blob at this name')
        return v, None
    v.version_id = blob.header('x-ms-version-id')
    v.sha256_actual, v.size_actual = R.sha256_bytes(blob.body), len(blob.body)
    rec, _ = _receipt_of(svc, container, name)
    if rec is None:
        v.verdict = S.NO_RECEIPT
        v.notes.append('no %s beside the object' % RECEIPT_SUFFIX)
        return v, None
    obj = (rec or {}).get('object') or {}
    v.sha256_receipt, v.size_receipt = obj.get('sha256'), obj.get('size')
    if v.sha256_receipt != v.sha256_actual:
        v.verdict = S.MISMATCH
        v.notes.append('stored bytes do not hash to the receipt sha256')
    elif v.size_receipt is not None and v.size_receipt != v.size_actual:
        v.verdict = S.MISMATCH
        v.notes.append('stored size differs from the receipt size')
    return v, rec


def verify(target: StoreTarget, token_provider: TokenProvider, *, container: str,
           name: Optional[str] = None, prefix: Optional[str] = None,
           check_seal: bool = False) -> S.VerifyResult:
    """Download, rehash, compare with the receipt; optionally with the seal chain."""
    res = S.VerifyResult(status=S.OK, container=container)
    try:
        svc = BlobService(target, token_provider)
        chain = None
        if check_seal:
            chain = verify_seal_chain(svc, container)
            res.seal_chain = {k: v for k, v in chain.items() if k != '_entries'}
        for n in _targets(svc, container, name, prefix):
            v, _ = _check_one(svc, container, n)
            if chain is not None and v.verdict == S.VERIFIED:
                hit = _seal_lookup(chain, n, v.version_id)
                if hit is None:
                    v.verdict = S.NOT_SEALED
                    v.notes.append('not listed in any seal of %s' % container)
                else:
                    v.sealed_in, v.sha256_seal = hit['seal'], hit.get('sha256_actual')
                    if v.sha256_seal != v.sha256_actual:
                        v.verdict = S.MISMATCH
                        v.notes.append('stored bytes differ from the sealed sha256')
                    if chain['status'] != 'INTACT':
                        v.notes.append('seal chain is %s' % chain['status'])
            res.verdicts.append(v)
    except EvidenceStoreError as e:
        res.status, res.message = _kind(e), str(e)
        return res
    res.counts = {}
    for v in res.verdicts:
        res.counts[v.verdict] = res.counts.get(v.verdict, 0) + 1
    if not res.verdicts:
        res.status, res.message = S.VERIFY_FAILED, 'nothing to verify at that name/prefix'
    elif any(v.verdict != S.VERIFIED for v in res.verdicts):
        res.status = S.VERIFY_FAILED
    if res.seal_chain and res.seal_chain['status'] == 'BROKEN':
        res.status = S.CHAIN_BROKEN
    return res


# ── seal chain ─────────────────────────────────────────────────────────────────────
def _seal_lookup(chain, name, version_id):
    for e in chain['_entries'].get(name, []):
        if version_id is None or e.get('version_id') in (None, version_id):
            return e
    return None


def verify_seal_chain(svc: BlobService, container: str) -> dict:
    """Read every seal of `container`, in number order, and check each link.

    Checks: numbers run 1..N without gaps; seal 1 has no predecessor; every later seal names the
    previous seal and its sha256 equals the sha256 of the previous seal's stored bytes; each
    seal's entries_sha256 matches its entries. LIMIT: the newest seal has no successor, so its
    replacement is detectable only against an external copy of its hash (the index holds one,
    and the index is rewritable) -- stated in the result.
    """
    seals = []
    for b in svc.list_blobs(SEAL_CONTAINER, container + '/'):
        if not b['name'].endswith('.json'):
            continue
        r = svc.get_blob(SEAL_CONTAINER, b['name'])
        if r is None:
            continue
        try:
            doc = json.loads(r.body.decode('utf-8'))
        except ValueError:
            doc = {}
        seals.append({'name': b['name'], 'sha256': R.sha256_bytes(r.body), 'doc': doc})
    seals.sort(key=lambda s: (s['doc'].get('seal_number') or 0, s['name']))
    breaks, entries, out = [], {}, []
    prev = None
    for i, s in enumerate(seals, 1):
        d = s['doc']
        if d.get('seal_number') != i:
            breaks.append('%s: seal_number %r where %d was expected' % (s['name'],
                                                                         d.get('seal_number'), i))
        p = d.get('previous_seal')
        if prev is None:
            if p:
                breaks.append('%s: first seal names a predecessor %r' % (s['name'], p))
        elif not p or p.get('name') != prev['name'] or p.get('sha256') != prev['sha256']:
            breaks.append('%s: previous_seal does not match %s (stored sha256 %s, recorded %s)'
                          % (s['name'], prev['name'], prev['sha256'], (p or {}).get('sha256')))
        if R.sha256_bytes(R.dumps(d.get('entries', []))) != d.get('entries_sha256'):
            breaks.append('%s: entries do not hash to entries_sha256' % s['name'])
        for e in d.get('entries', []):
            entries.setdefault(e.get('name'), []).append(dict(e, seal=s['name']))
        out.append({'name': s['name'], 'seal_number': d.get('seal_number'),
                    'sha256': s['sha256'], 'entries': len(d.get('entries', []))})
        prev = s
    status = 'EMPTY' if not seals else ('BROKEN' if breaks else 'INTACT')
    return {'status': status, 'container': container, 'seals': out, 'breaks': breaks,
            'limit': 'the newest seal is anchored only by the index pointer and external copies',
            '_entries': entries, '_last': prev}


# ── seal ───────────────────────────────────────────────────────────────────────────
def seal(target: StoreTarget, token_provider: TokenProvider, contract: StoreContract, *,
         container: str, tool: str = 'sealer', skip_if_empty: bool = False,
         now=None) -> S.SealResult:
    """Seal everything in `container` not in an earlier seal; rewrite the nightly index; set the
    ten index tags on each sealed object from its receipt."""
    res = S.SealResult(status=S.OK, container=container)
    now = now or R.utc_now()
    try:
        if contract is None:
            raise RefusedError('no store contract supplied')
        if tool != contract.sealer_tool:
            raise RefusedError('tool %r is not the contract sealer %r' % (tool,
                                                                         contract.sealer_tool))
        if container in (SEAL_CONTAINER, INDEX_CONTAINER):
            raise RefusedError('the seal and index containers are not themselves sealed here')
        contract.rule(container)
        svc = BlobService(target, token_provider)
        writer = writer_from_token(get_token(token_provider))
        chain = verify_seal_chain(svc, container)
        res.chain_before = {k: v for k, v in chain.items() if not k.startswith('_')}
        if chain['status'] == 'BROKEN':
            res.status = S.CHAIN_BROKEN
            res.message = 'refusing to extend a broken seal chain: ' + '; '.join(chain['breaks'])
            return res
        sealed = set()
        for lst in chain['_entries'].values():
            for e in lst:
                sealed.add((e.get('name'), e.get('version_id')))
        listing = sorted(svc.list_blobs(container, '', include_versions=True),
                         key=lambda b: (b['name'], b['version_id'] or ''))
        entries, receipts = [], {}
        for b in listing:
            if (b['name'], b['version_id']) in sealed:
                continue
            ver = b['version_id'] if b['version_id'] and not b['is_current'] else None
            blob = svc.get_blob(container, b['name'], ver)
            if blob is None:
                continue
            e = {'name': b['name'], 'version_id': b['version_id'],
                 'kind': 'receipt' if b['name'].endswith(RECEIPT_SUFFIX) else 'object',
                 'size': len(blob.body), 'sha256_actual': R.sha256_bytes(blob.body)}
            if e['kind'] == 'object':
                rec, rsha = _receipt_of(svc, container, b['name'])
                if rec is None:
                    e.update(sha256_receipt=None, receipt_sha256=None, rehash='NO_RECEIPT')
                else:
                    e['sha256_receipt'] = ((rec or {}).get('object') or {}).get('sha256')
                    e['receipt_sha256'] = rsha
                    e['rehash'] = 'MATCH' if e['sha256_receipt'] == e['sha256_actual'] \
                        else 'MISMATCH'
                    if e['rehash'] == 'MATCH':
                        receipts[b['name']] = (rec, b['version_id'] if ver else None)
            entries.append(e)
        counts = {'entries': len(entries),
                  'objects': sum(1 for e in entries if e['kind'] == 'object'),
                  'receipts': sum(1 for e in entries if e['kind'] == 'receipt'),
                  'rehash_match': sum(1 for e in entries if e.get('rehash') == 'MATCH'),
                  'rehash_mismatch': sum(1 for e in entries if e.get('rehash') == 'MISMATCH'),
                  'no_receipt': sum(1 for e in entries if e.get('rehash') == 'NO_RECEIPT')}
        res.counts = counts
        if not entries and skip_if_empty:
            res.message = 'nothing new to seal; skipped'
            return res
        last = chain['_last']
        n = (last['doc'].get('seal_number') or 0) + 1 if last else 1
        prev = {'name': last['name'], 'sha256': last['sha256']} if last else None
        doc = {'schema': R.SEAL_SCHEMA, 'container': container, 'seal_number': n,
               'sealed_at_utc': R.iso(now), 'sealer': writer,
               'client': {'name': R.CLIENT_NAME, 'version': R.__version__},
               'previous_seal': prev, 'counts': counts, 'entries': entries,
               'entries_sha256': R.sha256_bytes(R.dumps(entries)), 'note': R.SEAL_NOTE}
        name = '%s/%04d/%02d/%02d/seal-%d.json' % (container, now.year, now.month, now.day, n)
        check_write(contract, tool, SEAL_CONTAINER, name, internal=True)
        body = R.dumps(doc)
        _publish_doc_check(SEAL_CONTAINER, name, body)
        status, _, _, msg = _put_once(svc, SEAL_CONTAINER, name, data=body, size=len(body),
                                      content_type='application/json',
                                      sha256=R.sha256_bytes(body))
        res.seal_name, res.seal_sha256, res.seal_number = name, R.sha256_bytes(body), n
        res.previous_seal = prev
        if status == S.CONFLICT:
            res.status, res.message = S.CONFLICT, msg
            return res
        # tags: from the receipt, only where the bytes still match it
        for oname in sorted(receipts):
            rec, ver = receipts[oname]
            try:
                svc.set_tags(container, oname, R.tags_from_receipt(rec), ver)
                res.tagged += 1
            except EvidenceStoreError as e:
                res.tag_failures.append({'name': oname, 'error': str(e)})
        res.index_name, res.index_sha256 = _write_index(svc, contract, tool, container, chain,
                                                        doc, res, now)
        if res.tag_failures:
            res.status = S.ERROR
            res.message = '%d tag write(s) failed' % len(res.tag_failures)
    except EvidenceStoreError as e:
        res.status, res.message = _kind(e), str(e)
    return res


def _write_index(svc, contract, tool, container, chain, doc, res, now):
    seals = list(chain['seals']) + [{'name': res.seal_name, 'seal_number': res.seal_number,
                                     'sha256': res.seal_sha256,
                                     'entries': len(doc['entries'])}]
    totals = {'objects': 0, 'receipts': 0, 'rehash_mismatch': 0, 'no_receipt': 0}
    by_layer = {}
    all_entries = [e for lst in chain['_entries'].values() for e in lst] + doc['entries']
    for e in all_entries:
        totals['objects' if e.get('kind') == 'object' else 'receipts'] += 1
        if e.get('rehash') == 'MISMATCH':
            totals['rehash_mismatch'] += 1
        if e.get('rehash') == 'NO_RECEIPT':
            totals['no_receipt'] += 1
        if e.get('kind') == 'object':
            first = (e.get('name') or '').split('/', 1)[0]
            key = first if first in LAYERS else '(no layer)'
            by_layer[key] = by_layer.get(key, 0) + 1
    idx = {'schema': R.INDEX_SCHEMA, 'container': container, 'generated_at_utc': R.iso(now),
           'latest_seal': {'name': res.seal_name, 'sha256': res.seal_sha256,
                           'seal_number': res.seal_number},
           'seal_count': len(seals), 'seals': seals, 'totals': totals,
           'objects_by_layer': by_layer,
           'note': 'Derived and regenerable. A search and dashboard aid, never the provenance '
                   'record; the receipts and the seal chain are.'}
    name = 'nightly/%s.json' % container
    check_write(contract, tool, INDEX_CONTAINER, name, internal=True)
    body = R.dumps(idx)
    _publish_doc_check(INDEX_CONTAINER, name, body)
    svc.put_blob_overwrite(INDEX_CONTAINER, name, body, 'application/json')
    return name, R.sha256_bytes(body)


# ── find ───────────────────────────────────────────────────────────────────────────
def find(target: StoreTarget, token_provider: TokenProvider, *,
         container: Optional[str] = None, prefix: Optional[str] = None,
         where: Optional[str] = None) -> S.FindResult:
    """List by prefix (needs container), or Find Blobs by Tags with a tag expression."""
    res = S.FindResult(status=S.OK, query={'container': container, 'prefix': prefix,
                                           'where': where})
    try:
        svc = BlobService(target, token_provider)
        if where:
            res.items = list(svc.find_by_tags(where, container))
        elif container:
            for b in svc.list_blobs(container, prefix or ''):
                b['container'] = container
                b['is_receipt'] = b['name'].endswith(RECEIPT_SUFFIX)
                res.items.append(b)
        else:
            raise RefusedError('find needs a container (with optional prefix) or a tag expression')
    except EvidenceStoreError as e:
        res.status, res.message = _kind(e), str(e)
    res.count = len(res.items)
    return res


# ── pull ───────────────────────────────────────────────────────────────────────────
def safe_local_path(dest, blob_name):
    """Resolve blob_name under dest; refuse anything that would land outside it."""
    if not blob_name or '\x00' in blob_name:
        raise RefusedError('empty blob name')
    n = blob_name.replace('\\', '/')
    parts = n.split('/')
    if n.startswith('/') or any(p in ('', '.', '..') for p in parts) or \
            any(':' in p for p in parts):
        raise RefusedError('blob name %r would resolve outside the target directory' % blob_name)
    root = os.path.realpath(dest)
    full = os.path.realpath(os.path.join(root, *parts))
    if os.path.commonpath([root, full]) != root or full == root:
        raise RefusedError('blob name %r would resolve outside the target directory' % blob_name)
    return full


def pull(target: StoreTarget, token_provider: TokenProvider, *, container: str, dest: str,
         name: Optional[str] = None, prefix: Optional[str] = None,
         allow_unverified: bool = False) -> S.PullResult:
    """Download, verify against the receipt, write under dest (never outside, never over a
    different local file). Unverified objects are not written unless allow_unverified."""
    res = S.PullResult(status=S.OK, container=container, dest=os.path.abspath(dest))
    try:
        svc = BlobService(target, token_provider)
        names = [name] if name else _targets(svc, container, None, prefix)
        os.makedirs(dest, exist_ok=True)
        for n in names:
            p = S.PulledObject(name=n, verdict=S.NOT_ATTEMPTED)
            res.objects.append(p)
            try:
                local = safe_local_path(dest, n)
                safe_local_path(dest, R.receipt_name(n))
            except RefusedError as e:
                p.verdict, p.message = S.REFUSED, str(e)
                continue
            blob = svc.get_blob(container, n)
            if blob is None:
                p.verdict = S.MISSING
                continue
            p.sha256_actual = R.sha256_bytes(blob.body)
            rraw = svc.get_blob(container, R.receipt_name(n))
            rec = None
            if rraw is None:
                p.verdict = S.NO_RECEIPT
            else:
                try:
                    rec = json.loads(rraw.body.decode('utf-8'))
                except ValueError:
                    rec = {}
                p.sha256_receipt = ((rec or {}).get('object') or {}).get('sha256')
                p.verdict = S.VERIFIED if p.sha256_receipt == p.sha256_actual else S.MISMATCH
            if p.verdict != S.VERIFIED and not allow_unverified:
                p.message = 'not written: %s' % p.verdict
                continue
            p.local_path = local
            if os.path.exists(local):
                h, _ = R.sha256_file(local)
                if h == p.sha256_actual:
                    p.message = 'identical local file already present'
                    continue
                p.verdict, p.message = S.CONFLICT, 'a different local file exists; not overwritten'
                continue
            os.makedirs(os.path.dirname(local), exist_ok=True)
            with open(local, 'xb') as fh:
                fh.write(blob.body)
            if rraw is not None:
                rlocal = local + RECEIPT_SUFFIX
                if not os.path.exists(rlocal):
                    with open(rlocal, 'xb') as fh:
                        fh.write(rraw.body)
            p.written = True
    except EvidenceStoreError as e:
        res.status, res.message = _kind(e), str(e)
        return res
    res.counts = {}
    for p in res.objects:
        res.counts[p.verdict] = res.counts.get(p.verdict, 0) + 1
    vs = [p.verdict for p in res.objects]
    if S.REFUSED in vs:
        res.status = S.REFUSED
    elif S.CONFLICT in vs:
        res.status = S.CONFLICT
    elif any(v != S.VERIFIED for v in vs) or not vs:
        res.status = S.VERIFY_FAILED
    return res


__all__ = ['push', 'verify', 'seal', 'find', 'pull', 'verify_seal_chain', 'safe_local_path',
           'StoreTarget', 'TokenProvider', 'redact']
