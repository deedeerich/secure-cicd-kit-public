"""HTTPS transport to the hosted evidence API (stdlib only).

Owner decisions 2026-11-24: every tool writes through ITS OWN API app (one app per tool) by
default; the library's direct path is the fallback (no API URL configured) and the large-object
path. Objects over the API's object limit, batches over its batch limits, or a 413 `too_large`
answer are written directly with the same writer identity (decision 7); the API never stages
blocks.

    push_via_api(api, api_token_provider, contract, *, tool, source, container, prefix, ...,
                 direct=(store_target, storage_token_provider) or None)

The same local contract checks as the direct path run first, before any request. The bearer token
is for the API audience (api://<app>), never for storage, and is never written to a result.
"""
import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from . import core
from . import records as R
from . import results as S
from .auth import get_token, refuse_shared_key_material
from .blob import _LOOPBACK
from .contract import check_write
from .errors import EvidenceStoreError, NetworkError, RefusedError, redact

MiB = 1024 * 1024
EXIT = {S.OK: 0, S.ERROR: 1, S.ALREADY_PRESENT: 3, S.CONFLICT: 4, S.REFUSED: 5, S.AUTH: 6,
        S.NETWORK: 7, S.VERIFY_FAILED: 8, S.CHAIN_BROKEN: 9}
_STATUSES = set(EXIT)


@dataclass
class ApiTarget:
    """Where the tool's API app is. Configuration only -- carries no identity. The limits mirror
    the API's defaults (EVIDENCE_API_MAX_*); a 413 answer is honoured whatever they are."""
    url: str
    timeout: float = 120.0
    max_object_bytes: int = 32 * MiB
    max_batch_bytes: int = 32 * MiB
    max_batch_files: int = 500

    def base_url(self):
        u = (self.url or '').rstrip('/')
        refuse_shared_key_material(u, 'the API URL')
        p = urllib.parse.urlsplit(u)
        if p.query or p.fragment:
            raise RefusedError('the API URL must not carry a query string')
        if p.scheme == 'http':
            if p.hostname not in _LOOPBACK:
                raise RefusedError('plain http to the API is refused except to a loopback test '
                                   'server; a bearer token is never sent in clear text')
        elif p.scheme != 'https':
            raise RefusedError('the API URL scheme must be https')
        return u


@dataclass
class ApiPushResult:
    """status: the overall client status; doc: the JSON emitted (the API's answer, or the direct
    path's result), with transport and transport_reason added."""
    status: str
    doc: dict
    transport: str = 'api'
    transport_reason: str = ''


def exit_code(r):
    return EXIT.get(r.status, 1)


def _result(status, doc, transport='api', reason=''):
    doc = dict(doc)
    doc['transport'] = transport
    if reason:
        doc['transport_reason'] = reason
    doc.setdefault('operation', 'push')
    doc['status'] = status
    return ApiPushResult(status=status, doc=doc, transport=transport, transport_reason=reason)


def _direct(direct, contract, reason, kw):
    if direct is None:
        return _result(S.REFUSED, {'message': 'over the API limits (%s): write these objects '
                                              'directly with the client library from the tool\'s '
                                              'own job (no --api-url), see docs/HOSTED_API.md '
                                              'section 2.3' % reason}, 'api', reason)
    target, tp = direct
    r = core.push(target, tp, contract, **kw)
    return _result(r.status, r.to_dict(), 'direct', reason)


def push_via_api(api, token_provider, contract, *, tool, source, container, prefix='',
                 layer=None, case_id=None, package_id=None, run_id=None, index_fields=None,
                 content_type=None, write_manifest=None, env=None, direct=None,
                 block_threshold=core.DEFAULT_BLOCK_THRESHOLD,
                 block_size=core.DEFAULT_BLOCK_SIZE):
    kw = dict(tool=tool, source=source, container=container, prefix=prefix, layer=layer,
              case_id=case_id, package_id=package_id, run_id=run_id, index_fields=index_fields,
              content_type=content_type, write_manifest=write_manifest, env=env,
              block_threshold=block_threshold, block_size=block_size)
    prefix = (prefix or '').rstrip('/')
    # ── 1. local checks, no network (the same refusals as the direct path) ───────
    try:
        base = api.base_url()
        files, single = core._collect(source)
        if not files:
            raise RefusedError('nothing to push: %s is empty' % source)
        if layer and layer not in core.LAYERS:
            raise RefusedError('unknown layer %r' % layer)
        if index_fields:
            unknown = sorted(set(index_fields) - set(R.INDEX_FIELDS))
            if unknown:
                raise RefusedError('unknown index field(s) %s' % unknown)
        for p, rel in files:
            name = core._join(prefix, rel)
            check_write(contract, tool, container, name, layer)
            # the publication gate (PROTOCOL.md 4.2), the same check the direct path and the API
            # run: a refusal here sends nothing
            core._publication_check(container, name, p, core._content_type(p, content_type),
                                    {'case_id': case_id, 'package_id': package_id,
                                     'run_id': run_id}, index_fields)
    except EvidenceStoreError as e:
        return _result(core._kind(e), {'container': container, 'prefix': prefix, 'tool': tool,
                                       'message': str(e)})
    if write_manifest is None:
        write_manifest = not single
    sizes = [os.path.getsize(p) for p, _ in files]
    # ── 2. the large-object path (decision 7) ─────────────────────────────────────
    if any(s > api.max_object_bytes for s in sizes):
        return _direct(direct, contract, 'over_api_object_limit', kw)
    use_batch = write_manifest or not single
    if use_batch and (sum(sizes) > api.max_batch_bytes or len(files) > api.max_batch_files):
        return _direct(direct, contract, 'over_api_batch_limit', kw)
    if not single and not write_manifest:
        # The API writes a manifest with every batch; a manifest-less directory goes direct.
        return _direct(direct, contract, 'directory_without_manifest', kw)
    # The caller's run context, github_* keys only (the API labels it AS_ASSERTED_BY_API_CALLER).
    run_ctx = {k: v for k, v in (R.github_context(env) or {}).items() if k.startswith('github_')}
    ids = {k: v for k, v in (('case_id', case_id), ('package_id', package_id),
                             ('run_id', run_id)) if v}
    try:
        token = get_token(token_provider)
        if use_batch:
            out = []
            for (p, rel) in files:
                with open(p, 'rb') as fh:
                    data = fh.read()
                out.append({'path': rel, 'content_base64': base64.b64encode(data).decode('ascii'),
                            'sha256': R.sha256_bytes(data)})
            doc = dict(container=container, prefix=prefix, files=out, **ids)
            if layer:
                doc['layer'] = layer
            if index_fields:
                doc['index_fields'] = dict(index_fields)
            if run_ctx:
                doc['run_context'] = run_ctx
            body = json.dumps(doc).encode('utf-8')
            req = urllib.request.Request(base + '/v1/batches', data=body, method='POST')
            req.add_header('Content-Type', 'application/json')
        else:
            p, rel = files[0]
            with open(p, 'rb') as fh:
                body = fh.read()
            q = dict(ids)
            if layer:
                q['layer'] = layer
            q.update(index_fields or {})
            name = core._join(prefix, rel)
            url = '%s/v1/objects/%s/%s' % (base, urllib.parse.quote(container),
                                           urllib.parse.quote(name, safe='/'))
            if q:
                url += '?' + urllib.parse.urlencode(sorted(q.items()))
            req = urllib.request.Request(url, data=body, method='PUT')
            req.add_header('Content-Type', core._content_type(p, content_type))
            req.add_header('X-Content-SHA256', R.sha256_bytes(body))
            if run_ctx:
                req.add_header('X-Evidence-Run-Context', json.dumps(run_ctx, sort_keys=True))
        req.add_header('Authorization', 'Bearer ' + token)
        req.add_header('Accept', 'application/json')
        code, answer = _send(req, api.timeout)
    except EvidenceStoreError as e:
        return _result(core._kind(e), {'container': container, 'prefix': prefix, 'tool': tool,
                                       'message': str(e)})
    if code == 413 and answer.get('reason') == 'too_large':
        return _direct(direct, contract, 'api_refused_too_large', kw)
    status = answer.get('status')
    if status not in _STATUSES:
        status = {401: S.AUTH, 403: S.REFUSED, 409: S.CONFLICT, 502: S.NETWORK}.get(code, S.ERROR)
    answer = {k: v for k, v in answer.items() if not isinstance(v, str) or token not in v}
    answer['http_status'] = code
    return _result(status, answer)


def _send(req, timeout):
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            code, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        code, raw = e.code, e.read()
    except (urllib.error.URLError, OSError) as e:
        raise NetworkError('the evidence API could not be reached: %s'
                           % redact(type(e).__name__ + ': ' + str(e))[:300])
    try:
        doc = json.loads(raw.decode('utf-8')) if raw else {}
    except (ValueError, UnicodeDecodeError):
        doc = {'message': 'the API answered HTTP %d with a non-JSON body' % code}
    if not isinstance(doc, dict):
        doc = {'message': 'the API answered HTTP %d with a non-object body' % code}
    return code, doc
