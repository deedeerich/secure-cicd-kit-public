"""Receipts, manifests, seals and index documents: their exact shapes.

Field names and the NOT ESTABLISHED convention follow the evidence harness: anything the client
cannot know is written as an explicit marker, never omitted ("a missing line reads as an
oversight; NOT ESTABLISHED reads as a statement" -- harness bulk_receipts.py).

Integrity is not authenticity. A sha256 in a receipt says the bytes are the bytes that were
written. It does not say who produced them or that they are true. Every document says so.
"""
import datetime
import hashlib
import json
import os
import re

from . import __version__

BLANK = 'NOT ESTABLISHED'
CLIENT_NAME = 'evidence-store-client/python'

RECEIPT_SCHEMA = 'evidence-store.receipt/v1'
MANIFEST_SCHEMA = 'evidence-store.manifest/v1'
SEAL_SCHEMA = 'evidence-store.seal/v1'
INDEX_SCHEMA = 'evidence-store.index/v1'

INTEGRITY_NOTE = ('sha256 binds these bytes (integrity). It does not establish who produced them '
                  'or that their content is true (authenticity).')
SEAL_NOTE = ('Unsigned seal: a hash-chained stamp, not an attestation. It shows that the listed '
             'bytes existed when the sealer ran and that earlier seals were not replaced; it does '
             'not establish authenticity.')

# The ten blob index tags (TAGGING standard 05 §3). `product` comes from the receipt's tool.
INDEX_FIELDS = ('source_system', 'instance', 'collection_id', 'completed_at', 'provenance_tier',
                'coverage', 'data_class', 'review_id', 'query_hash')
TAG_KEYS = ('source-system', 'instance', 'collection-id', 'completed-at', 'provenance-tier',
            'coverage', 'data-class', 'review-id', 'product', 'query-hash')
_TAG_OK = re.compile(r'[^A-Za-z0-9 +\-./:=_]')

GITHUB_ENV = ('GITHUB_REPOSITORY', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_SHA',
              'GITHUB_WORKFLOW_REF', 'GITHUB_REF', 'GITHUB_ACTOR', 'GITHUB_SERVER_URL')


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)


def iso(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')


def compact(dt):
    return dt.strftime('%Y%m%dT%H%M%SZ')


def dumps(doc):
    """The one serialisation used for every document this client writes."""
    return (json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + '\n').encode('utf-8')


def sha256_bytes(b):
    return hashlib.sha256(b).hexdigest()


def sha256_file(path, chunk=1024 * 1024):
    h = hashlib.sha256()
    n = 0
    with open(path, 'rb') as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                break
            h.update(b)
            n += len(b)
    return h.hexdigest(), n


def github_context(env=None):
    """GitHub run context from the environment, or None when not in Actions. As asserted by env."""
    env = os.environ if env is None else env
    got = {k.lower(): env.get(k) for k in GITHUB_ENV if env.get(k)}
    if not got:
        return None
    got['basis'] = 'AS_ASSERTED_BY_RUNNER_ENVIRONMENT: GITHUB_* variables, not verified'
    return got


def receipt_name(blob_name):
    return blob_name + '.receipt.json'


def build_receipt(*, container, blob_name, sha256, size, content_type, tool, layer, ids,
                  source_relative_path, writer, written_at, contract=None, index_fields=None,
                  github=None, upload_method='PutBlob', api=None):
    ids = ids or {}
    fields = dict((k, BLANK) for k in INDEX_FIELDS)
    for k, v in (index_fields or {}).items():
        if k in fields and v not in (None, ''):
            fields[k] = str(v)
    rule = contract.containers.get(container) if contract is not None else None
    doc = {
        'schema': RECEIPT_SCHEMA,
        'object': {'container': container, 'name': blob_name, 'sha256': sha256, 'size': size,
                   'content_type': content_type},
        'tool': tool,
        'layer': layer if layer else BLANK,
        'ids': {'case_id': ids.get('case_id') or BLANK,
                'package_id': ids.get('package_id') or BLANK,
                'run_id': ids.get('run_id') or BLANK},
        'source_relative_path': source_relative_path or BLANK,
        'written_at_utc': iso(written_at),
        'written_at_basis': 'CLIENT_CLOCK: the writing machine\'s clock, not a trusted timestamp',
        'client': {'name': CLIENT_NAME, 'version': __version__},
        'writer': writer,
        'github': github if github else BLANK,
        'index_fields': fields,
        'store_contract': {'sha256': contract.sha256 if contract is not None else BLANK,
                           'immutability_at_write': rule.immutability if rule else BLANK,
                           'basis': 'AS_DECLARED_BY_CONTRACT_FILE'},
        'upload_method': upload_method,
        'integrity_note': INTEGRITY_NOTE,
    }
    if api is not None:
        doc['api'] = api
    return doc


def build_manifest(*, container, prefix, tool, layer, ids, writer, created_at, files, counts,
                   github=None, contract=None, api=None):
    """files: list of {relative_path, blob_name, sha256, size, status, version_id}, sorted."""
    files = sorted(files, key=lambda f: f['blob_name'])
    listing_sha = listing_sha256(files)
    doc = {
        'schema': MANIFEST_SCHEMA,
        'container': container,
        'prefix': prefix,
        'tool': tool,
        'layer': layer or BLANK,
        'ids': {'case_id': (ids or {}).get('case_id') or BLANK,
                'package_id': (ids or {}).get('package_id') or BLANK,
                'run_id': (ids or {}).get('run_id') or BLANK},
        'created_at_utc': iso(created_at),
        'client': {'name': CLIENT_NAME, 'version': __version__},
        'writer': writer,
        'github': github if github else BLANK,
        'store_contract_sha256': contract.sha256 if contract is not None else BLANK,
        'counts': counts,
        'coverage_identity': ('files_present == created + already_present + conflict + refused '
                              '+ failed'),
        'listing_sha256': listing_sha,
        'listing_form': LISTING_FORM,
        'batch_sha256': batch_sha256(container=container, prefix=prefix, tool=tool, layer=layer,
                                     ids=ids, contract=contract, files=files),
        'batch_form': BATCH_FORM,
        'files': files,
        'integrity_note': INTEGRITY_NOTE,
    }
    if api is not None:
        doc['api'] = api
    return doc, listing_sha


LISTING_FORM = ('sha256 of UTF-8 lines "<sha256> <size> <blob_name>\\n", one per file, sorted by '
                'blob_name (ordinal); a file with no sha256 is written as "-"')


BATCH_FORM = ('sha256 of UTF-8 lines: "evidence-store.batch/v1", then container=, prefix=, tool=, '
              'layer=, case_id=, package_id=, run_id=, store_contract_sha256= (NOT ESTABLISHED when '
              'unknown), then one "<sha256> <size> <outcome> <blob_name>" per file sorted by blob_name '
              '(ordinal), outcome STORED for CREATED or ALREADY_PRESENT, else the status; every line '
              'ends "\\n". Not in it: times, writer, GitHub context, version ids. The manifest is named '
              '<prefix>/_manifests/<batch_sha256>.json.')
BATCH_LINE = 'evidence-store.batch/v1'
_STORED = ('CREATED', 'ALREADY_PRESENT')


def batch_sha256(*, container, prefix, tool, layer, ids, contract, files):
    """The batch digest: what was pushed and with which run metadata, never when or by which
    attempt. An identical retry has the same digest (so the same manifest name); a different batch
    in the same second has a different one. Client-independent (the PowerShell client matches)."""
    return _batch_digest(container=container, prefix=prefix, tool=tool, layer=layer, ids=ids,
                         contract_sha=contract.sha256 if contract is not None else None,
                         files=files)


def _batch_digest(*, container, prefix, tool, layer, ids, contract_sha, files):
    ids = ids or {}
    head = [BATCH_LINE, 'container=%s' % container, 'prefix=%s' % (prefix or ''),
            'tool=%s' % tool, 'layer=%s' % (layer or BLANK)]
    head += ['%s=%s' % (k, ids.get(k) or BLANK) for k in ('case_id', 'package_id', 'run_id')]
    head.append('store_contract_sha256=%s' % (contract_sha or BLANK))
    rows = sorted(files, key=lambda f: f['blob_name'].encode('utf-8'))
    body = ['%s %s %s %s' % (f.get('sha256') or '-',
                             f.get('size') if f.get('size') is not None else '-',
                             'STORED' if f.get('status') in _STORED else (f.get('status') or '-'),
                             f['blob_name']) for f in rows]
    return sha256_bytes(''.join(l + '\n' for l in head + body).encode('utf-8'))


# Why a stored manifest at the expected name is not this batch (2026-11-24 external review):
MANIFEST_MALFORMED = 'MANIFEST_MALFORMED'              # not a parseable v1 manifest
MANIFEST_DIGEST_MISMATCH = 'MANIFEST_DIGEST_MISMATCH'  # declared batch_sha256 != its own content
MANIFEST_OTHER_BATCH = 'MANIFEST_OTHER_BATCH'          # self-consistent, but another batch
_HEX64 = re.compile(r'^[0-9a-f]{64}$')


def _str_or_none(x):
    return x is None or isinstance(x, str)


def _int_or_none(x):
    return x is None or (isinstance(x, int) and not isinstance(x, bool))


def batch_sha256_of_manifest(doc):
    """Recompute the batch digest (PROTOCOL.md section 4.1) from a stored manifest's OWN content:
    container, prefix, tool, layer, ids, store_contract_sha256 and files. The declared
    `batch_sha256` field is not read. Raises ValueError when the document is not a v1 manifest."""
    if not isinstance(doc, dict) or doc.get('schema') != MANIFEST_SCHEMA:
        raise ValueError('not an %s document' % MANIFEST_SCHEMA)
    for k in ('container', 'tool'):
        if not isinstance(doc.get(k), str) or not doc.get(k):
            raise ValueError('field %r missing or not a string' % k)
    for k in ('prefix', 'layer', 'store_contract_sha256'):
        if not _str_or_none(doc.get(k)):
            raise ValueError('field %r is not a string' % k)
    ids = doc.get('ids')
    if not isinstance(ids, dict) or not all(_str_or_none(ids.get(k))
                                            for k in ('case_id', 'package_id', 'run_id')):
        raise ValueError('field ids missing or malformed')
    files = doc.get('files')
    if not isinstance(files, list):
        raise ValueError('field files missing or not a list')
    for f in files:
        if (not isinstance(f, dict) or not isinstance(f.get('blob_name'), str)
                or not f['blob_name'] or not _str_or_none(f.get('sha256'))
                or not _int_or_none(f.get('size')) or not _str_or_none(f.get('status'))):
            raise ValueError('a files[] entry is malformed')
    layer = doc.get('layer')
    contract_sha = doc.get('store_contract_sha256')
    return _batch_digest(container=doc['container'], prefix=doc.get('prefix') or '',
                         tool=doc['tool'], layer=None if layer == BLANK else layer, ids=ids,
                         contract_sha=None if contract_sha == BLANK else contract_sha,
                         files=files)


def check_stored_manifest(body, expected):
    """Is the manifest stored at <prefix>/_manifests/<expected>.json this very batch?

    -> (same, reason, message). same is True only when the digest RECOMPUTED from the stored
    content equals `expected` AND the stored document's declared `batch_sha256` field equals the
    recomputed value. A declared field is never trusted on its own: a planted or edited manifest
    that keeps the expected field but lists other objects is not this batch."""
    try:
        if body is None:
            raise ValueError('nothing readable is stored at the manifest name')
        doc = json.loads(body.decode('utf-8'))
        recomputed = batch_sha256_of_manifest(doc)
    except (ValueError, UnicodeDecodeError, AttributeError, TypeError) as e:
        return False, MANIFEST_MALFORMED, ('%s: the stored manifest is malformed (%s)'
                                           % (MANIFEST_MALFORMED, e))
    declared = doc.get('batch_sha256')
    if not isinstance(declared, str) or not _HEX64.match(declared) or declared != recomputed:
        return False, MANIFEST_DIGEST_MISMATCH, (
            '%s: the stored manifest declares batch_sha256 %s but its content hashes to %s '
            '(tampered or forged manifest)' % (MANIFEST_DIGEST_MISMATCH, declared, recomputed))
    if recomputed != expected:
        return False, MANIFEST_OTHER_BATCH, (
            '%s: the stored manifest records another batch (%s), not this one (%s)'
            % (MANIFEST_OTHER_BATCH, recomputed, expected))
    return True, None, 'the same batch is already recorded (digest recomputed from the content)'


def listing_sha256(files):
    """Client-independent: the Python and PowerShell clients compute the same value."""
    rows = sorted(files, key=lambda f: f['blob_name'].encode('utf-8'))
    text = ''.join('%s %s %s\n' % (f.get('sha256') or '-', f.get('size') if f.get('size')
                                   is not None else '-', f['blob_name']) for f in rows)
    return sha256_bytes(text.encode('utf-8'))


def tag_value(v):
    s = _TAG_OK.sub('_', str(v if v not in (None, '') else BLANK))
    return s[:256]


def tags_from_receipt(receipt):
    f = receipt.get('index_fields') or {}
    tags = {
        'source-system': f.get('source_system', BLANK),
        'instance': f.get('instance', BLANK),
        'collection-id': f.get('collection_id', BLANK),
        'completed-at': f.get('completed_at', BLANK),
        'provenance-tier': f.get('provenance_tier', BLANK),
        'coverage': f.get('coverage', BLANK),
        'data-class': f.get('data_class', BLANK),
        'review-id': f.get('review_id', BLANK),
        'product': receipt.get('tool', BLANK),
        'query-hash': f.get('query_hash', BLANK),
    }
    return {k: tag_value(v) for k, v in tags.items()}
