"""Minimal Azure Blob REST client over urllib (stdlib only), bearer-token auth only.

One BlobService instance = one endpoint + one token provider. It holds no process-wide state.
"""
import base64
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from .auth import get_token, refuse_shared_key_material
from .errors import AuthError, NetworkError, RefusedError, ServiceError, redact

# VERIFIED 2026-11-23 against Microsoft Learn "Versioning for Azure Storage": "As of October 29,
# 2026, the latest fully deployed version of the Azure Storage service is 2026-04-06."
DEFAULT_API_VERSION = '2026-04-06'
DEFAULT_ENDPOINT_SUFFIX = 'core.windows.net'
GOV_ENDPOINT_SUFFIX = 'core.usgovcloudapi.net'
_LOOPBACK = ('127.0.0.1', 'localhost', '::1')


@dataclass
class StoreTarget:
    """Where the store is. Configuration only -- carries no identity."""
    account: str = ''
    endpoint_suffix: str = DEFAULT_ENDPOINT_SUFFIX
    endpoint_url: str = ''           # override, e.g. a test server; https unless loopback
    api_version: str = DEFAULT_API_VERSION
    timeout: float = 60.0
    retries: int = 3

    def base_url(self):
        if self.endpoint_url:
            u = self.endpoint_url.rstrip('/')
        else:
            if not self.account:
                raise RefusedError('no storage account given (--account or the contract)')
            u = 'https://%s.blob.%s' % (self.account, self.endpoint_suffix)
        refuse_shared_key_material(u, 'the endpoint URL')
        p = urllib.parse.urlsplit(u)
        if p.query or p.fragment:
            raise RefusedError('the endpoint URL must not carry a query string (no SAS)')
        if p.scheme == 'http':
            if p.hostname not in _LOOPBACK:
                raise RefusedError('plain http is refused except to a loopback test server; '
                                   'a bearer token is never sent in clear text')
        elif p.scheme != 'https':
            raise RefusedError('endpoint scheme must be https')
        return u


@dataclass
class Response:
    status: int
    headers: dict = field(default_factory=dict)
    body: bytes = b''

    def header(self, name, default=None):
        return self.headers.get(name.lower(), default)

    def error_code(self):
        c = self.header('x-ms-error-code')
        if c:
            return c
        try:
            return ET.fromstring(self.body).findtext('Code')
        except Exception:
            return None


def quote_blob(name):
    return urllib.parse.quote(name, safe='/~-._')


class BlobService(object):
    def __init__(self, target, token_provider):
        self.target = target
        self.token_provider = token_provider
        self.base = target.base_url()

    # ── transport ──────────────────────────────────────────────────────────────────
    def request(self, method, path, query=None, headers=None, body=None, ok=(200, 201, 202)):
        url = self.base + path
        if query:
            url += '?' + urllib.parse.urlencode(query)
        token = get_token(self.token_provider)
        h = {'Authorization': 'Bearer ' + token, 'x-ms-version': self.target.api_version,
             'x-ms-date': time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())}
        if headers:
            h.update(headers)
        if body is not None:
            h['Content-Length'] = str(len(body))
        elif method in ('PUT', 'POST'):
            h['Content-Length'] = '0'
        last = None
        for attempt in range(max(1, self.target.retries)):
            req = urllib.request.Request(url, data=body, method=method, headers=h)
            try:
                with urllib.request.urlopen(req, timeout=self.target.timeout) as r:
                    resp = Response(r.status, {k.lower(): v for k, v in r.headers.items()},
                                    r.read())
            except urllib.error.HTTPError as e:
                try:
                    data = e.read()
                except Exception:
                    data = b''
                resp = Response(e.code, {k.lower(): v for k, v in (e.headers or {}).items()},
                                data)
            except (urllib.error.URLError, socket.timeout, ConnectionError, OSError) as e:
                last = NetworkError('%s %s failed: %s' % (method, self._safe(url),
                                                          type(e).__name__))
                time.sleep(min(2 ** attempt, 8) * 0.25)
                continue
            if resp.status >= 500:
                last = NetworkError('%s %s returned %d (%s)' % (method, self._safe(url),
                                                               resp.status, resp.error_code()))
                time.sleep(min(2 ** attempt, 8) * 0.25)
                continue
            if resp.status in ok:
                return resp
            if resp.status == 401:
                raise AuthError('%s %s: 401 %s' % (method, self._safe(url), resp.error_code()),
                                401)
            if resp.status == 403 and resp.error_code() == 'AuthorizationFailure':
                # Live finding F-8 (2026-11-24): the storage NETWORK RULES refused the request
                # (public network access off, not on the allow-list, not via the private
                # endpoint). Not an identity problem: NETWORK (exit 7). RBAC/ABAC refusals are
                # AuthorizationPermissionMismatch and stay with the caller (AUTH).
                raise NetworkError('%s %s: 403 AuthorizationFailure -- refused by the storage '
                                   'network rule (public network access off or not on the '
                                   'allow-list); run from a network that reaches the private '
                                   'endpoint' % (method, self._safe(url)), 403)
            return resp  # caller interprets 403/404/409/412
        raise last

    @staticmethod
    def _safe(url):
        return redact(url.split('?')[0])

    def fail(self, what, resp):
        msg = '%s: HTTP %d %s' % (what, resp.status, resp.error_code() or '')
        if resp.status == 403:
            raise AuthError(msg, 403)
        raise ServiceError(msg, resp.status)

    # ── blob operations ──────────────────────────────────────────────────────────────
    def put_blob_once(self, container, name, data, content_type):
        """Put Blob with If-None-Match: * -> Response (201 created, or 409/412/403 as returned)."""
        return self.request('PUT', '/%s/%s' % (container, quote_blob(name)),
                            headers={'x-ms-blob-type': 'BlockBlob', 'If-None-Match': '*',
                                     'Content-Type': content_type}, body=data,
                            ok=(201,))

    def put_blob_overwrite(self, container, name, data, content_type):
        """Sealer only (index/nightly). Writers never call this."""
        r = self.request('PUT', '/%s/%s' % (container, quote_blob(name)),
                         headers={'x-ms-blob-type': 'BlockBlob', 'Content-Type': content_type},
                         body=data, ok=(201,))
        if r.status != 201:
            self.fail('Put Blob %s/%s' % (container, name), r)
        return r

    def put_block(self, container, name, block_id, data):
        r = self.request('PUT', '/%s/%s' % (container, quote_blob(name)),
                         query={'comp': 'block', 'blockid': block_id}, body=data, ok=(201,))
        if r.status != 201:
            self.fail('Put Block %s/%s' % (container, name), r)
        return r

    def put_block_list_once(self, container, name, block_ids, content_type):
        xml = '<?xml version="1.0" encoding="utf-8"?><BlockList>%s</BlockList>' % ''.join(
            '<Latest>%s</Latest>' % b for b in block_ids)
        return self.request('PUT', '/%s/%s' % (container, quote_blob(name)),
                            query={'comp': 'blocklist'},
                            headers={'If-None-Match': '*', 'x-ms-blob-content-type': content_type,
                                     'Content-Type': 'application/xml'},
                            body=xml.encode('utf-8'), ok=(201,))

    def get_blob(self, container, name, version_id=None):
        """-> Response or None when 404."""
        q = {'versionid': version_id} if version_id else None
        r = self.request('GET', '/%s/%s' % (container, quote_blob(name)), query=q, ok=(200,))
        if r.status == 404:
            return None
        if r.status != 200:
            self.fail('Get Blob %s/%s' % (container, name), r)
        return r

    def head_blob(self, container, name):
        r = self.request('HEAD', '/%s/%s' % (container, quote_blob(name)), ok=(200,))
        if r.status == 404:
            return None
        if r.status != 200:
            self.fail('Head Blob %s/%s' % (container, name), r)
        return r

    def list_blobs(self, container, prefix='', include_versions=False, page_size=5000):
        """Yield dicts {name, version_id, size, content_type, last_modified, is_current}."""
        marker = ''
        while True:
            q = {'restype': 'container', 'comp': 'list', 'maxresults': str(page_size)}
            if prefix:
                q['prefix'] = prefix
            if marker:
                q['marker'] = marker
            if include_versions:
                q['include'] = 'versions'
            r = self.request('GET', '/%s' % container, query=q, ok=(200,))
            if r.status == 404:
                return
            if r.status != 200:
                self.fail('List Blobs %s' % container, r)
            root = ET.fromstring(r.body)
            for b in root.iter('Blob'):
                props = b.find('Properties')
                yield {'name': b.findtext('Name'), 'version_id': b.findtext('VersionId'),
                       'is_current': (b.findtext('IsCurrentVersion') or 'true') == 'true',
                       'size': int(props.findtext('Content-Length') or 0) if props is not None
                       else None,
                       'content_type': props.findtext('Content-Type') if props is not None
                       else None,
                       'last_modified': props.findtext('Last-Modified') if props is not None
                       else None}
            marker = root.findtext('NextMarker') or ''
            if not marker:
                return

    def set_tags(self, container, name, tags, version_id=None):
        parts = ''.join('<Tag><Key>%s</Key><Value>%s</Value></Tag>' % (_x(k), _x(v))
                        for k, v in sorted(tags.items()))
        body = ('<?xml version="1.0" encoding="utf-8"?><Tags><TagSet>%s</TagSet></Tags>'
                % parts).encode('utf-8')
        q = {'comp': 'tags'}
        if version_id:
            q['versionid'] = version_id
        r = self.request('PUT', '/%s/%s' % (container, quote_blob(name)), query=q,
                         headers={'Content-Type': 'application/xml; charset=UTF-8'}, body=body,
                         ok=(204, 200))
        if r.status not in (200, 204):
            self.fail('Set Blob Tags %s/%s' % (container, name), r)

    def get_tags(self, container, name):
        r = self.request('GET', '/%s/%s' % (container, quote_blob(name)),
                         query={'comp': 'tags'}, ok=(200,))
        if r.status != 200:
            self.fail('Get Blob Tags %s/%s' % (container, name), r)
        root = ET.fromstring(r.body)
        return {t.findtext('Key'): t.findtext('Value') for t in root.iter('Tag')}

    def find_by_tags(self, where, container=None):
        """Find Blobs by Tags. Account level, or container level when `container` is given."""
        marker = ''
        while True:
            if container:
                path, q = '/%s' % container, {'restype': 'container', 'comp': 'blobs',
                                              'where': where}
            else:
                path, q = '/', {'comp': 'blobs', 'where': where}
            if marker:
                q['marker'] = marker
            r = self.request('GET', path, query=q, ok=(200,))
            if r.status != 200:
                self.fail('Find Blobs by Tags', r)
            root = ET.fromstring(r.body)
            for b in root.iter('Blob'):
                yield {'container': b.findtext('ContainerName') or container,
                       'name': b.findtext('Name'),
                       'tags': {t.findtext('Key'): t.findtext('Value') for t in b.iter('Tag')}}
            marker = root.findtext('NextMarker') or ''
            if not marker:
                return


def _x(s):
    return (str(s).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            .replace('"', '&quot;'))


def block_id(n):
    """Fixed-length base64 block ids, as the service requires equal lengths within a blob."""
    return base64.b64encode(('blk-%08d' % n).encode('ascii')).decode('ascii')
