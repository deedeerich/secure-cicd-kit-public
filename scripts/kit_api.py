#!/usr/bin/env python3
"""The kit's API: the client every program uses, and the contract the run enforces (KDEC-035).

WHAT THE API IS

    A versioned, schema-defined way for another program -- a Tines 3B automation or agent first,
    then anything holding a GitHub credential -- to ask a repository's copy of the kit to do one
    of its things: write, read and search finding tickets through the kit's own reconciler, read
    and search the findings a security run established, request a release through the
    repository's own pipeline, request a scan, and read the result of any of those.

    It is GitHub-native and adds NO SERVER. A request is the `request` input of a
    workflow_dispatch of the repository's `kit-api.yml` (templates/kit-api.yml), or a
    repository_dispatch of event type `kit-api`. The run that answers it is an ordinary Actions run
    named `kit-api <correlation id>`; its answer is a JSON result (api/v1/result.schema.json)
    written three ways: an artifact, the run summary, and the text of a check run named
    `kit-api/<correlation id>`. A caller with only the API host reachable (a Tines 3B step behind
    its credential proxy) reads the check run; nothing it needs lives on another host.

    This file is the client AND the contract: scripts/kit_api_server.py (the run's side) imports
    the validator, the operation table and the refusal names from here, so the two cannot drift.
    Standard library only, one file, so a Tines 3B step or any runner can carry it.

THE RULES IT HOLDS

    * The host is never assumed. KIT_API_URL, else GITHUB_API_URL, else derived from GH_HOST
      (github.com or <tenant>.ghe.com -> the api. host of that name, anything else
      -> https://<host>/api/v3). Nothing named is API_HOST_NOT_NAMED -- never github.com
      (KDEC-027: a run's token goes only to the API host that issued it).
    * The token goes to that host and nowhere else. GitHub answers an artifact download with a
      redirect to blob storage; the shipped opener does NOT follow redirects, and the client
      follows that one itself WITHOUT the Authorization header. KIT_API_AUTH=proxy sends no
      credential at all: a Tines 3B connector's proxy adds it outside the code.
    * A refusal the client can see is made before anything is sent, by name.
    * A dispatch answer is API_ACCEPTED -- received, never done. A finished run is not a finished
      call: only a result that validates against the schema and names this correlation id is one.
    * Every wait is bounded, and a wait that runs out returns the last word it saw (exit 3).

USAGE
    kit_api.py submit --repo OWNER/REPO --operation OP --params JSON|@FILE
                      [--idempotency-key K] [--ref REF] [--on-behalf-of WHO] [--dry-run]
                      [--transport workflow_dispatch|repository_dispatch] [--workflow kit-api.yml]
    kit_api.py status --repo OWNER/REPO --correlation-id CID [--workflow kit-api.yml]
    kit_api.py call   (submit's arguments) [--wait-seconds 300] [--poll-seconds 10]
    kit_api.py validate --request FILE
    kit_api.py evidence-hash --params FILE   the evidence set a review concurs with (tickets.submit)
    Credentials: GH_TOKEN, GITHUB_TOKEN or KIT_API_TOKEN, or KIT_API_AUTH=proxy.

EXIT
    0  API_COMPLETED (or API_ACCEPTED from submit)
    1  API_REFUSED, by name
    2  usage
    3  no completed answer: still queued, running, awaiting approval, not found, failed,
       cancelled, or a result that could not be read
"""
import argparse
import datetime
import hashlib
import io
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
API_VERSION = 'v1'
CLIENT_NAME = 'kit_api.py'
CLIENT_VERSION = '1.0.0'
DEFAULT_WORKFLOW = 'kit-api.yml'
REPOSITORY_DISPATCH_EVENT = 'kit-api'
# A workflow_dispatch input holds 65535 characters; the envelope must fit with room to spare.
REQUEST_MAX = 60000
# A check run's output text holds 65535 characters; the run keeps its result under this.
RESULT_TEXT_MAX = 60000
MAX_WAIT_SECONDS = 3600

CORRELATION_RE = re.compile(r'^kapi-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$')
IDEMPOTENCY_RE = re.compile(r'^[A-Za-z0-9._:-]{8,128}$')
REPO_RE = re.compile(r'^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$')

# ── THE OPERATIONS (docs/api/README.md) ────────────────────────────────────────────────
#   write: needs an idempotency key, and the repository must enable it
#   job:   which job of the API run carries it out (`client` = answered here, nothing sent)
OPERATIONS = {
    'tickets.write': {'write': True, 'job': 'tickets'},
    # KDEC-037: tickets from a finalized, human-concurred review, through templates.
    'tickets.submit': {'write': True, 'job': 'tickets'},
    'tickets.comment': {'write': True, 'job': 'tickets'},
    'tickets.get': {'write': False, 'job': 'tickets'},
    'tickets.search': {'write': False, 'job': 'tickets'},
    'findings.get': {'write': False, 'job': 'findings'},
    'findings.search': {'write': False, 'job': 'findings'},
    # KDEC-039: the kit's half of the per-app evidence bundle, one repository at a commit or a release.
    'evidence.export': {'write': False, 'job': 'findings'},
    'deploy.request': {'write': True, 'job': 'deploy'},
    'scan.request': {'write': False, 'job': 'scan'},
    'status.get': {'write': False, 'job': 'client'},
}
WRITE_OPERATIONS = tuple(sorted(op for op, d in OPERATIONS.items() if d['write']))
# What a repository serves when it says nothing (vars.KIT_API_OPERATIONS): every read and the
# scan. A write -- a ticket, a comment, a release request -- is on only where the repository's
# owner turned it on.
DEFAULT_ENABLED = tuple(sorted(op for op, d in OPERATIONS.items()
                               if not d['write'] and d['job'] != 'client'))

# ── THE STATE WORDS (assurance-taxonomy.yaml :: kit_api_state) ─────────────────────────
API_ACCEPTED = 'API_ACCEPTED'
API_NOT_FOUND = 'API_NOT_FOUND'
API_QUEUED = 'API_QUEUED'
API_IN_PROGRESS = 'API_IN_PROGRESS'
API_AWAITING_APPROVAL = 'API_AWAITING_APPROVAL'
API_COMPLETED = 'API_COMPLETED'
API_REFUSED = 'API_REFUSED'
API_FAILED = 'API_FAILED'
API_CANCELLED = 'API_CANCELLED'
API_RESULT_UNREADABLE = 'API_RESULT_UNREADABLE'
API_STATES = (API_ACCEPTED, API_NOT_FOUND, API_QUEUED, API_IN_PROGRESS, API_AWAITING_APPROVAL,
              API_COMPLETED, API_REFUSED, API_FAILED, API_CANCELLED, API_RESULT_UNREADABLE)
TERMINAL = (API_COMPLETED, API_REFUSED, API_FAILED, API_CANCELLED, API_RESULT_UNREADABLE)

# ── THE REFUSALS (assurance-taxonomy.yaml :: kit_api_refusal; api/v1/refusals.json) ────
API_HOST_NOT_NAMED = 'API_HOST_NOT_NAMED'
API_HOST_INSECURE = 'API_HOST_INSECURE'
API_CREDENTIAL_ABSENT = 'API_CREDENTIAL_ABSENT'
API_REQUEST_UNPARSEABLE = 'API_REQUEST_UNPARSEABLE'
API_REQUEST_TOO_LARGE = 'API_REQUEST_TOO_LARGE'
API_VERSION_UNSUPPORTED = 'API_VERSION_UNSUPPORTED'
API_OPERATION_UNKNOWN = 'API_OPERATION_UNKNOWN'
API_OPERATION_NOT_ENABLED = 'API_OPERATION_NOT_ENABLED'
API_SCHEMA_VIOLATION = 'API_SCHEMA_VIOLATION'
API_CORRELATION_MISMATCH = 'API_CORRELATION_MISMATCH'
API_IDEMPOTENCY_KEY_REQUIRED = 'API_IDEMPOTENCY_KEY_REQUIRED'
API_DUPLICATE_REQUEST = 'API_DUPLICATE_REQUEST'
API_IDEMPOTENCY_UNVERIFIED = 'API_IDEMPOTENCY_UNVERIFIED'
API_REF_NOT_DEFAULT_BRANCH = 'API_REF_NOT_DEFAULT_BRANCH'
API_TRANSPORT_NOT_PERMITTED = 'API_TRANSPORT_NOT_PERMITTED'
API_REPOSITORY_NOT_SERVED = 'API_REPOSITORY_NOT_SERVED'
API_EVIDENCE_UNAVAILABLE = 'API_EVIDENCE_UNAVAILABLE'
API_FINDING_NOT_KIT_ESTABLISHED = 'API_FINDING_NOT_KIT_ESTABLISHED'
API_DISPOSITION_NOT_VIA_API = 'API_DISPOSITION_NOT_VIA_API'
API_TICKET_NOT_KIT_STAMPED = 'API_TICKET_NOT_KIT_STAMPED'
API_FILTER_NEEDS_FINDINGS_RUN = 'API_FILTER_NEEDS_FINDINGS_RUN'
API_RELEASE_PATH_NOT_PERMITTED = 'API_RELEASE_PATH_NOT_PERMITTED'
API_ENVIRONMENT_NOT_PERMITTED = 'API_ENVIRONMENT_NOT_PERMITTED'
API_PROMOTION_SOURCE_REQUIRED = 'API_PROMOTION_SOURCE_REQUIRED'
API_DEPLOY_NEEDS_HUMAN_APPROVAL = 'API_DEPLOY_NEEDS_HUMAN_APPROVAL'
# KDEC-037 (ticket templates).
API_TEMPLATE_INVALID = 'API_TEMPLATE_INVALID'
API_REVIEW_NOT_FINALIZED = 'API_REVIEW_NOT_FINALIZED'
API_TEMPLATE_RULE_REFUSED = 'API_TEMPLATE_RULE_REFUSED'
API_TRACKER_QUERY_REFUSED = 'API_TRACKER_QUERY_REFUSED'
REFUSALS = (API_HOST_NOT_NAMED, API_HOST_INSECURE, API_CREDENTIAL_ABSENT, API_REQUEST_UNPARSEABLE,
            API_REQUEST_TOO_LARGE, API_VERSION_UNSUPPORTED, API_OPERATION_UNKNOWN,
            API_OPERATION_NOT_ENABLED, API_SCHEMA_VIOLATION, API_CORRELATION_MISMATCH,
            API_IDEMPOTENCY_KEY_REQUIRED, API_DUPLICATE_REQUEST, API_IDEMPOTENCY_UNVERIFIED,
            API_REF_NOT_DEFAULT_BRANCH, API_TRANSPORT_NOT_PERMITTED, API_REPOSITORY_NOT_SERVED,
            API_EVIDENCE_UNAVAILABLE, API_FINDING_NOT_KIT_ESTABLISHED, API_DISPOSITION_NOT_VIA_API,
            API_TICKET_NOT_KIT_STAMPED, API_FILTER_NEEDS_FINDINGS_RUN,
            API_RELEASE_PATH_NOT_PERMITTED, API_ENVIRONMENT_NOT_PERMITTED,
            API_PROMOTION_SOURCE_REQUIRED, API_DEPLOY_NEEDS_HUMAN_APPROVAL, API_TEMPLATE_INVALID,
            API_REVIEW_NOT_FINALIZED, API_TEMPLATE_RULE_REFUSED, API_TRACKER_QUERY_REFUSED)


def refusal(code, detail, field=''):
    out = {'code': code, 'detail': str(detail)[:2000]}
    if field:
        out['field'] = str(field)[:200]
    return out


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


def iso(dt=None):
    return (dt or now_utc()).strftime('%Y-%m-%dT%H:%M:%SZ')


def new_correlation_id(now=None, rand=None):
    """kapi-<yyyymmddThhmmssZ>-<12 hex>. Made by the caller; the run only checks it."""
    rand = rand or random.SystemRandom()
    return 'kapi-%s-%012x' % ((now or now_utc()).strftime('%Y%m%dT%H%M%SZ'), rand.getrandbits(48))


def sha256(text):
    return hashlib.sha256(text.encode('utf-8') if isinstance(text, str) else text).hexdigest()


def run_title(correlation_id):
    """The run-name templates/kit-api.yml gives the run that answers a call."""
    return 'kit-api %s' % correlation_id


def check_run_name(correlation_id):
    return 'kit-api/%s' % correlation_id


# ═════════════════════════════════════════════════════════════════════════════════════
# THE CONTRACT: a JSON Schema subset, validated here so no third-party package is needed
# ═════════════════════════════════════════════════════════════════════════════════════

def schema_dir(env=None):
    env = os.environ if env is None else env
    explicit = (env.get('KIT_API_SCHEMAS') or '').strip()
    if explicit:
        return explicit
    for cand in (os.path.join(HERE, '..', 'api', 'v1'), os.path.join(HERE, 'api', 'v1'),
                 os.path.join(HERE, 'v1')):
        if os.path.isfile(os.path.join(cand, 'request.schema.json')):
            return os.path.normpath(cand)
    return os.path.normpath(os.path.join(HERE, '..', 'api', 'v1'))


def load_schemas(directory=None):
    """-> {'request': doc, 'result': doc, 'params': {operation: doc}}. A schema that cannot be read
    raises: a contract nobody can read is not a contract anyone can be held to."""
    d = directory or schema_dir()
    out = {'params': {}}
    for name in ('request', 'result'):
        out[name] = json.load(io.open(os.path.join(d, '%s.schema.json' % name), encoding='utf-8'))
    for op in OPERATIONS:
        out['params'][op] = json.load(io.open(os.path.join(d, 'params', '%s.schema.json' % op),
                                              encoding='utf-8'))
    return out


_TYPES = {'object': dict, 'array': list, 'string': str, 'boolean': bool, 'null': type(None)}


def _is_type(v, t):
    if t == 'integer':
        return isinstance(v, int) and not isinstance(v, bool)
    if t == 'number':
        return isinstance(v, (int, float)) and not isinstance(v, bool)
    return isinstance(v, _TYPES.get(t, ()))


def validate(instance, schema, path='$'):
    """-> [(path, message)]. The subset the v1 schemas use: type (one or a list), enum, const,
    pattern (searched), minLength, maxLength, minimum, maximum, required, properties,
    additionalProperties (false or a schema), items, minItems, maxItems, uniqueItems. A keyword
    applies only to the types it is defined for, as JSON Schema says."""
    errs = []
    if not isinstance(schema, dict):
        return errs
    t = schema.get('type')
    if t is not None:
        types = t if isinstance(t, list) else [t]
        if not any(_is_type(instance, x) for x in types):
            return [(path, 'is %s, not %s' % (type(instance).__name__, '/'.join(types)))]
    if 'enum' in schema and instance not in schema['enum']:
        errs.append((path, 'is not one of %s' % ', '.join(map(str, schema['enum']))))
    if 'const' in schema and (instance != schema['const'] or type(instance) is not type(schema['const'])):
        errs.append((path, 'must be %r' % (schema['const'],)))
    if isinstance(instance, str):
        if 'pattern' in schema and not re.search(schema['pattern'], instance):
            errs.append((path, 'does not match the pattern %s' % schema['pattern']))
        if 'minLength' in schema and len(instance) < schema['minLength']:
            errs.append((path, 'is shorter than %d' % schema['minLength']))
        if 'maxLength' in schema and len(instance) > schema['maxLength']:
            errs.append((path, 'is longer than %d' % schema['maxLength']))
    if _is_type(instance, 'number'):
        if 'minimum' in schema and instance < schema['minimum']:
            errs.append((path, 'is below %s' % schema['minimum']))
        if 'maximum' in schema and instance > schema['maximum']:
            errs.append((path, 'is above %s' % schema['maximum']))
    if isinstance(instance, dict):
        for r in schema.get('required') or []:
            if r not in instance:
                errs.append(('%s.%s' % (path, r), 'is required'))
        props = schema.get('properties') or {}
        for k, v in instance.items():
            if k in props:
                errs.extend(validate(v, props[k], '%s.%s' % (path, k)))
            elif schema.get('additionalProperties') is False:
                errs.append(('%s.%s' % (path, k), 'is not a field of this object'))
            elif isinstance(schema.get('additionalProperties'), dict):
                errs.extend(validate(v, schema['additionalProperties'], '%s.%s' % (path, k)))
    if isinstance(instance, list):
        if 'minItems' in schema and len(instance) < schema['minItems']:
            errs.append((path, 'has fewer than %d items' % schema['minItems']))
        if 'maxItems' in schema and len(instance) > schema['maxItems']:
            errs.append((path, 'has more than %d items' % schema['maxItems']))
        if schema.get('uniqueItems'):
            seen = [json.dumps(x, sort_keys=True) for x in instance]
            if len(set(seen)) != len(seen):
                errs.append((path, 'has duplicate items'))
        if isinstance(schema.get('items'), dict):
            for i, v in enumerate(instance):
                errs.extend(validate(v, schema['items'], '%s[%d]' % (path, i)))
    return errs


def check_request(envelope, schemas=None, enforce_write_key=True):
    """-> None when the envelope is a well-formed v1 request, else the refusal (the FIRST problem,
    named). Order matters and is fixed: size, shape, version, operation, schema, key."""
    schemas = schemas or load_schemas()
    if not isinstance(envelope, dict):
        return refusal(API_REQUEST_UNPARSEABLE, 'the request is %s, not a JSON object'
                       % type(envelope).__name__)
    size = len(json.dumps(envelope, sort_keys=True))
    if size > REQUEST_MAX:
        return refusal(API_REQUEST_TOO_LARGE, 'the request is %d characters; the limit is %d'
                       % (size, REQUEST_MAX))
    if envelope.get('api_version') != API_VERSION:
        if isinstance(envelope.get('api_version'), str):
            return refusal(API_VERSION_UNSUPPORTED, 'api_version %r is not served; this kit serves %s'
                           % (envelope.get('api_version')[:20], API_VERSION), 'api_version')
    op = envelope.get('operation')
    if isinstance(op, str) and op not in OPERATIONS and re.match(r'^[a-z]{2,16}\.[a-z]{2,16}$', op):
        return refusal(API_OPERATION_UNKNOWN, 'operation %r is not in the v1 contract' % op,
                       'operation')
    errs = validate(envelope, schemas['request'])
    if errs:
        p, m = errs[0]
        return refusal(API_SCHEMA_VIOLATION, '%s %s' % (p, m), p)
    if op not in OPERATIONS:
        return refusal(API_OPERATION_UNKNOWN, 'operation %r is not in the v1 contract' % op, 'operation')
    errs = validate(envelope['params'], schemas['params'][op], '$.params')
    if errs:
        p, m = errs[0]
        return refusal(API_SCHEMA_VIOLATION, '%s %s' % (p, m), p)
    if enforce_write_key and OPERATIONS[op]['write'] and not envelope.get('idempotency_key'):
        return refusal(API_IDEMPOTENCY_KEY_REQUIRED, '%s is a write: it needs an idempotency key, so '
                       'a retry can never do it twice' % op, 'idempotency_key')
    return None


def result_doc(correlation_id, operation, api_state, refusal_=None, data=None, notes=None, **extra):
    out = {'api_version': API_VERSION, 'correlation_id': correlation_id or '',
           'operation': operation or '', 'api_state': api_state, 'refusal': refusal_,
           'data': data or {}, 'notes': list(notes or [])[:50]}
    out.update(extra)
    return out


def check_result(doc, correlation_id, schemas=None):
    """-> None when `doc` is a v1 result for THIS call, else why not."""
    schemas = schemas or load_schemas()
    if not isinstance(doc, dict):
        return 'the result is not a JSON object'
    errs = validate(doc, schemas['result'])
    if errs:
        return 'the result breaks the schema: %s %s' % errs[0]
    if doc.get('correlation_id') != correlation_id:
        return 'the result names correlation id %r, not %r' % (doc.get('correlation_id'), correlation_id)
    if doc.get('api_state') == API_REFUSED and not doc.get('refusal'):
        return 'the result says API_REFUSED and names no refusal'
    return None


# ═════════════════════════════════════════════════════════════════════════════════════
# THE HOST AND THE TOKEN (KDEC-027)
# ═════════════════════════════════════════════════════════════════════════════════════

LOOPBACK = ('127.0.0.1', 'localhost', '::1')


def resolve_api_url(env=None):
    """-> (api base URL, None) or (None, refusal). NEVER a default host."""
    env = os.environ if env is None else env
    raw = (env.get('KIT_API_URL') or env.get('GITHUB_API_URL') or '').strip()
    if not raw:
        host = (env.get('GH_HOST') or '').strip().lower().rstrip('/')
        if host.startswith('https://'):
            host = host[len('https://'):]
        if not host:
            return None, refusal(API_HOST_NOT_NAMED, 'no API host is named: set KIT_API_URL, '
                                 'GITHUB_API_URL or GH_HOST. The client never assumes github.com -- '
                                 'a token goes only to the host that issued it (KDEC-027)')
        if host == 'github.com' or host.endswith('.ghe.com'):
            # The API host of a NAMED cloud host: api.<host>. Never a default.
            raw = 'https://api.%s' % host
        else:
            raw = 'https://%s/api/v3' % host
    u = urllib.parse.urlsplit(raw)
    if u.scheme == 'http' and (u.hostname or '') in LOOPBACK:
        return raw.rstrip('/'), None
    if u.scheme != 'https' or not u.hostname or '@' in u.netloc:
        return None, refusal(API_HOST_INSECURE, 'the API URL must be https with no credential in it '
                             '(plain http only to a loopback address)')
    return raw.rstrip('/'), None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """THE OPENER NEVER FOLLOWS A REDIRECT ITSELF. urllib's default handler re-sends every header,
    Authorization included, to wherever a 3xx points -- for an artifact download that is blob
    storage, a host that did not issue the token. A 3xx therefore surfaces as an HTTPError and the
    one caller that expects it (Client.download) follows it WITHOUT the credential."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _transport(req, timeout):
    """The ONE way this file reaches the network. Proofs replace it; nothing else does."""
    return _OPENER.open(req, timeout=timeout)


def _no_credential_in(text):
    low = str(text).lower()
    for marker in ('authorization', 'bearer ', 'basic ', 'token ', 'password'):
        if marker in low:
            return 'detail withheld: it contained something credential-shaped'
    return str(text)[:500]


class Client(object):
    """The REST calls the API makes, to ONE host. The token (if any) is held here, sent as a header
    to that host only, and never printed, written or put in a message."""

    def __init__(self, api_url, token=None, proxy=False, timeout=30):
        self.api_url = api_url.rstrip('/')
        self.host = urllib.parse.urlsplit(self.api_url).hostname
        self._token = None if proxy else token
        self.proxy = bool(proxy)
        self.timeout = timeout
        self.calls = 0

    def _headers(self):
        h = [('Accept', 'application/vnd.github+json'), ('X-GitHub-Api-Version', '2022-11-28'),
             ('User-Agent', '%s/%s' % (CLIENT_NAME, CLIENT_VERSION))]
        if self._token:
            h.append(('Authorization', 'Bearer %s' % self._token))
        return h

    def request(self, method, path, payload=None):
        """-> (status, doc, headers, err). `err` is None on 2xx; a 3xx is an err with its headers."""
        url = path if path.startswith('http') else self.api_url + path
        if urllib.parse.urlsplit(url).hostname != self.host:
            # Belt and braces: nothing in this file builds such a URL; if one ever did, the token
            # does not go with it.
            return None, None, {}, 'refused: %s is not the API host %s' % (url, self.host)
        data = json.dumps(payload).encode('utf-8') if payload is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        for k, v in self._headers():
            req.add_header(k, v)
        if data is not None:
            req.add_header('Content-Type', 'application/json')
        self.calls += 1
        try:
            with _transport(req, self.timeout) as resp:
                raw = resp.read()
                hdrs = dict(getattr(resp, 'headers', {}) or {})
                status = getattr(resp, 'status', None) or resp.getcode()
                text = raw.decode('utf-8') if isinstance(raw, bytes) else (raw or '')
                try:
                    doc = json.loads(text) if text.strip() else None
                except ValueError:
                    doc = raw
                return status, doc, hdrs, None
        except urllib.error.HTTPError as exc:
            hdrs = dict(exc.headers or {})
            body = b''
            try:
                body = exc.read() or b''
            except Exception:  # noqa: BLE001
                pass
            try:
                doc = json.loads(body.decode('utf-8')) if body else None
            except ValueError:
                doc = None
            return exc.code, doc, hdrs, _no_credential_in('HTTP %s' % exc.code)
        except Exception as exc:  # noqa: BLE001 -- reported, never swallowed
            return None, None, {}, _no_credential_in('%s: %s' % (type(exc).__name__, exc))

    def get(self, path):
        return self.request('GET', path)

    def download(self, path):
        """-> bytes or None. GitHub answers 302 to a signed blob URL; that hop carries NO credential
        (the signature is the authority) and never goes back to the API host's token."""
        status, doc, hdrs, err = self.request('GET', path)
        if status in (301, 302, 303, 307, 308):
            loc = hdrs.get('Location') or hdrs.get('location')
            if not loc:
                return None
            u = urllib.parse.urlsplit(loc)
            if u.scheme != 'https' and (u.hostname or '') not in LOOPBACK:
                return None
            req = urllib.request.Request(loc, method='GET')
            req.add_header('User-Agent', '%s/%s' % (CLIENT_NAME, CLIENT_VERSION))
            self.calls += 1
            try:
                with _transport(req, self.timeout) as resp:
                    return resp.read()
            except Exception:  # noqa: BLE001 -- an unreadable download is None, never empty bytes
                return None
        if err is None and isinstance(doc, (bytes, bytearray)):
            return bytes(doc)
        return None


def client_from_env(env=None):
    """-> (Client, None) or (None, refusal)."""
    env = os.environ if env is None else env
    url, ref = resolve_api_url(env)
    if url is None:
        return None, ref
    if (env.get('KIT_API_AUTH') or '').strip().lower() == 'proxy':
        return Client(url, proxy=True), None
    token = (env.get('KIT_API_TOKEN') or env.get('GH_TOKEN') or env.get('GITHUB_TOKEN') or '').strip()
    if not token:
        return None, refusal(API_CREDENTIAL_ABSENT, 'no token in KIT_API_TOKEN, GH_TOKEN or '
                             'GITHUB_TOKEN, and KIT_API_AUTH is not proxy')
    return Client(url, token=token), None


# ═════════════════════════════════════════════════════════════════════════════════════
# SUBMIT, STATUS, CALL
# ═════════════════════════════════════════════════════════════════════════════════════

def build_request(operation, params, idempotency_key=None, on_behalf_of=None, dry_run=False,
                  correlation_id=None, now=None):
    env = {'api_version': API_VERSION, 'operation': operation,
           'correlation_id': correlation_id or new_correlation_id(now),
           'client': {'name': CLIENT_NAME, 'version': CLIENT_VERSION}, 'params': params}
    if idempotency_key:
        env['idempotency_key'] = idempotency_key
    if on_behalf_of:
        env['on_behalf_of'] = on_behalf_of
    if dry_run:
        env['dry_run'] = True
    return env


def default_branch(client, repo):
    status, doc, _h, err = client.get('/repos/%s' % repo)
    if err or not isinstance(doc, dict) or not doc.get('default_branch'):
        return None, 'the repository %s could not be read (%s)' % (repo, err or status)
    return doc['default_branch'], ''


def submit(client, repo, operation, params, idempotency_key=None, ref=None, on_behalf_of=None,
           dry_run=False, transport='workflow_dispatch', workflow=DEFAULT_WORKFLOW, schemas=None,
           now=None):
    """-> a result: API_ACCEPTED (received -- never done) or API_REFUSED (nothing was sent)."""
    envelope = build_request(operation, params, idempotency_key, on_behalf_of, dry_run, now=now)
    cid = envelope['correlation_id']

    def refused(r):
        return result_doc(cid, operation, API_REFUSED, r, transport='client',
                          repository=repo or '',
                          notes=['refused by the client before anything was sent'])
    if not REPO_RE.match(repo or ''):
        return refused(refusal(API_SCHEMA_VIOLATION, 'the repository must be OWNER/NAME', 'repository'))
    if operation == 'status.get':
        return refused(refusal(API_OPERATION_UNKNOWN, 'status.get is answered by `status`, never '
                               'dispatched', 'operation'))
    r = check_request(envelope, schemas)
    if r:
        return refused(r)
    if transport not in ('workflow_dispatch', 'repository_dispatch'):
        return refused(refusal(API_SCHEMA_VIOLATION, 'transport must be workflow_dispatch or '
                               'repository_dispatch', 'transport'))
    body = json.dumps(envelope, sort_keys=True)
    if transport == 'workflow_dispatch':
        at = ref or (params.get('ref') if operation == 'scan.request' else None)
        if not at:
            at, why = default_branch(client, repo)
            if not at:
                return result_doc(cid, operation, API_FAILED, None, transport=transport,
                                  repository=repo, notes=[why])
        status, _doc, _h, err = client.request(
            'POST', '/repos/%s/actions/workflows/%s/dispatches' % (repo, workflow),
            {'ref': at, 'inputs': {'correlation_id': cid, 'idempotency_key': idempotency_key or '',
                                   'request': body}})
    else:
        status, _doc, _h, err = client.request('POST', '/repos/%s/dispatches' % repo, {
            'event_type': REPOSITORY_DISPATCH_EVENT,
            'client_payload': {'correlation_id': cid, 'idempotency_key': idempotency_key or '',
                               'request': body}})
    if err or status not in (200, 201, 204):
        return result_doc(cid, operation, API_FAILED, None, transport=transport, repository=repo,
                          notes=['the dispatch was not accepted (%s); nothing will run'
                                 % (err or 'HTTP %s' % status)])
    return result_doc(cid, operation, API_ACCEPTED, None, transport=transport, repository=repo,
                      received_at=iso(now),
                      notes=['received, not done: read the answer with status --correlation-id %s'
                             % cid])


def _find_run(client, repo, correlation_id, workflow):
    """The run named for this correlation id -- EXACTLY one (item 11, 2026-11-06). Two runs carrying the
    same id (a replayed dispatch, a hand-made run-name) cannot be told apart: NOT_ESTABLISHED, named,
    never the first one found. tests/prove_dispatch_correlation.py K1-K3."""
    title = run_title(correlation_id)
    found = []
    for page in (1, 2, 3):
        status, doc, _h, err = client.get('/repos/%s/actions/workflows/%s/runs?per_page=100&page=%d'
                                          % (repo, workflow, page))
        if err or not isinstance(doc, dict):
            return None, 'the runs of %s could not be read (%s)' % (workflow, err or status)
        runs = doc.get('workflow_runs') or []
        found += [r for r in runs if (r.get('display_title') or r.get('name') or '') == title]
        if len(runs) < 100:
            break
    ids = {r.get('id') for r in found}
    if len(ids) > 1:
        return None, ('NOT_ESTABLISHED: %d runs of %s are named %s; the answer cannot be paired with one'
                      % (len(ids), workflow, title))
    return (found[0], '') if found else (None, '')


def _read_result(client, repo, run, correlation_id, schemas):
    """-> (result or None, why)."""
    sha = run.get('head_sha') or ''
    status, doc, _h, err = client.get('/repos/%s/commits/%s/check-runs?check_name=%s&per_page=10'
                                      % (repo, sha, urllib.parse.quote(check_run_name(correlation_id))))
    if err or not isinstance(doc, dict):
        return None, 'the check run could not be read (%s)' % (err or status)
    runs = [c for c in doc.get('check_runs') or [] if c.get('name') == check_run_name(correlation_id)]
    if not runs:
        return None, 'the run wrote no check run named %s' % check_run_name(correlation_id)
    text = ((runs[-1].get('output') or {}).get('text') or '')
    try:
        res = json.loads(text)
    except ValueError:
        return None, 'the check run text is not JSON'
    why = check_result(res, correlation_id, schemas)
    if why:
        return None, why
    return res, ''


def status(client, repo, correlation_id, workflow=DEFAULT_WORKFLOW, schemas=None):
    """-> the call's result as far as it exists. Nothing is dispatched."""
    schemas = schemas or load_schemas()
    if not CORRELATION_RE.match(correlation_id or ''):
        return result_doc(correlation_id if isinstance(correlation_id, str) and
                          len(correlation_id) < 60 else '', 'status.get', API_REFUSED,
                          refusal(API_SCHEMA_VIOLATION, 'the correlation id is malformed',
                                  'correlation_id'), transport='client')
    run, why = _find_run(client, repo, correlation_id, workflow)
    base = {'transport': 'client', 'repository': repo}
    if run is None:
        notes = [why] if why else ['no run is named %s yet: a dispatch can take seconds to appear; '
                                   'not found is not refused' % run_title(correlation_id)]
        return result_doc(correlation_id, '', API_FAILED if why else API_NOT_FOUND, notes=notes, **base)
    info = {'id': run.get('id'), 'attempt': run.get('run_attempt') or 1,
            'url': run.get('html_url') or '', 'status': run.get('status') or '',
            'conclusion': run.get('conclusion')}
    st = run.get('status')
    if st in ('queued', 'requested', 'waiting', 'pending'):
        return result_doc(correlation_id, '', API_QUEUED, run=info, **base)
    if st != 'completed':
        _s, pend, _h, err = client.get('/repos/%s/actions/runs/%s/pending_deployments'
                                       % (repo, run.get('id')))
        envs = [((p.get('environment') or {}).get('name') or '') for p in (pend or [])
                if isinstance(p, dict)] if isinstance(pend, list) else []
        partial, _w = _read_result(client, repo, run, correlation_id, schemas)
        data = dict((partial or {}).get('data') or {})
        if envs:
            data['awaiting_environments'] = envs
            return result_doc(correlation_id, (partial or {}).get('operation', ''),
                              API_AWAITING_APPROVAL, data=data, run=info,
                              notes=['a person must approve the deployment to %s; the API never '
                                     'approves' % ', '.join(envs)], **base)
        return result_doc(correlation_id, (partial or {}).get('operation', ''), API_IN_PROGRESS,
                          data=data, run=info, **base)
    res, why = _read_result(client, repo, run, correlation_id, schemas)
    if res is not None and res.get('api_state') not in TERMINAL:
        # THE RUN ENDED AND ITS ANSWER STILL SAYS IT IS RUNNING: the job that answers never ran or
        # never finished (an environment that refused the ref, a cancelled job). Not in progress.
        why = 'the run ended (%s) and its check run still says %s' % (run.get('conclusion'),
                                                                     res.get('api_state'))
        res = None
    if res is not None:
        res = dict(res)
        res['run'] = dict(res.get('run') or {}, **info)
        return res
    if run.get('conclusion') == 'cancelled':
        return result_doc(correlation_id, '', API_CANCELLED, run=info,
                          notes=['the run was cancelled before it wrote a result (a newer request '
                                 'with the same idempotency key replaces a pending one); resubmit '
                                 'with the same key', why], **base)
    return result_doc(correlation_id, '', API_RESULT_UNREADABLE, run=info,
                      notes=['the run finished (%s) and its result is not readable: %s. A finished '
                             'run is not a finished call.' % (run.get('conclusion'), why)], **base)


def call(client, repo, operation, params, wait_seconds=300, poll_seconds=10, sleep=time.sleep,
         clock=time.monotonic, **kw):
    """submit, then status until a terminal word or the bound. Never longer than asked."""
    wait_seconds = max(0, min(int(wait_seconds), MAX_WAIT_SECONDS))
    poll_seconds = max(1, int(poll_seconds))
    first = submit(client, repo, operation, params, **kw)
    if first['api_state'] != API_ACCEPTED:
        return first
    cid = first['correlation_id']
    start = clock()
    last = first
    while True:
        left = wait_seconds - (clock() - start)
        if left <= 0:
            break
        sleep(min(poll_seconds, left))
        last = status(client, repo, cid, workflow=kw.get('workflow', DEFAULT_WORKFLOW),
                      schemas=kw.get('schemas'))
        if last['api_state'] in TERMINAL:
            return last
    last = dict(last)
    last['notes'] = list(last.get('notes') or []) + [
        'the bounded wait (%d s) ended before the call finished; poll again with status '
        '--correlation-id %s' % (wait_seconds, cid)]
    return last


def exit_code(result):
    s = (result or {}).get('api_state')
    if s in (API_COMPLETED, API_ACCEPTED):
        return 0
    if s == API_REFUSED:
        return 1
    return 3


# ═════════════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════════════

def _params(text):
    if text.startswith('@'):
        text = io.open(text[1:], encoding='utf-8').read()
    return json.loads(text)


def main(argv=None):
    ap = argparse.ArgumentParser(description='Call the secure CI/CD kit through its API (KDEC-035).')
    sub = ap.add_subparsers(dest='cmd')
    for name in ('submit', 'call'):
        p = sub.add_parser(name)
        p.add_argument('--repo', required=True)
        p.add_argument('--operation', required=True)
        p.add_argument('--params', default='{}')
        p.add_argument('--idempotency-key', default='')
        p.add_argument('--ref', default='')
        p.add_argument('--on-behalf-of', default='')
        p.add_argument('--dry-run', action='store_true')
        p.add_argument('--transport', default='workflow_dispatch')
        p.add_argument('--workflow', default=DEFAULT_WORKFLOW)
        if name == 'call':
            p.add_argument('--wait-seconds', type=int, default=300)
            p.add_argument('--poll-seconds', type=int, default=10)
    p = sub.add_parser('status')
    p.add_argument('--repo', required=True)
    p.add_argument('--correlation-id', required=True)
    p.add_argument('--workflow', default=DEFAULT_WORKFLOW)
    p = sub.add_parser('validate')
    p.add_argument('--request', required=True)
    p = sub.add_parser('evidence-hash')
    p.add_argument('--params', required=True)
    a = ap.parse_args(argv)
    if not a.cmd:
        ap.print_help()
        return 2
    if a.cmd == 'evidence-hash':
        # KDEC-037: what a finalized review's evidence_set_sha256 must be for these tickets.submit
        # params -- the server's own function, so the two cannot drift.
        sys.path.insert(0, HERE)
        import ticket_templates as tt
        try:
            params = _params('@' + a.params)
        except (OSError, ValueError) as exc:
            print('--params is not JSON: %s' % exc, file=sys.stderr)
            return 2
        print(tt.evidence_set_sha256(params))
        return 0
    if a.cmd == 'validate':
        try:
            doc = json.load(io.open(a.request, encoding='utf-8'))
        except (OSError, ValueError) as exc:
            print(json.dumps({'valid': False, 'refusal': refusal(API_REQUEST_UNPARSEABLE, exc)}))
            return 1
        r = check_request(doc)
        print(json.dumps({'valid': r is None, 'refusal': r}, indent=2))
        return 0 if r is None else 1
    cl, ref = client_from_env()
    if cl is None:
        res = result_doc('', getattr(a, 'operation', 'status.get'), API_REFUSED, ref,
                         transport='client', notes=['refused by the client before anything was sent'])
        print(json.dumps(res, indent=2, sort_keys=True))
        return exit_code(res)
    if a.cmd == 'status':
        res = status(cl, a.repo, a.correlation_id, workflow=a.workflow)
    else:
        try:
            params = _params(a.params)
        except (OSError, ValueError) as exc:
            print('--params is not JSON: %s' % exc, file=sys.stderr)
            return 2
        kw = dict(idempotency_key=a.idempotency_key or None, ref=a.ref or None,
                  on_behalf_of=a.on_behalf_of or None, dry_run=a.dry_run, transport=a.transport,
                  workflow=a.workflow)
        if a.cmd == 'submit':
            res = submit(cl, a.repo, a.operation, params, **kw)
        else:
            res = call(cl, a.repo, a.operation, params, wait_seconds=a.wait_seconds,
                       poll_seconds=a.poll_seconds, **kw)
    print(json.dumps(res, indent=2, sort_keys=True))
    return exit_code(res)


if __name__ == '__main__':
    sys.exit(main())
