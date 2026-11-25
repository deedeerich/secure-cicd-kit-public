"""Bearer tokens for https://storage.azure.com/ -- and nothing else.

A token provider is any zero-argument callable that returns an access token string. The core
never stores a provider globally: every operation takes one as an argument, so a caller (a CLI
run, a test, or a future HTTP front end acting per caller) decides whose identity is used.

Order used by default_token_provider():
  1. env EVIDENCE_STORE_TOKEN_FILE  (a path; the file holds only the token)
  2. `az account get-access-token --resource https://storage.azure.com/`
     (works after azure/login with OIDC in GitHub Actions, or after a person's `az login`)

Never accepted, anywhere: Shared Key, account keys, SAS tokens, connection strings.
Tokens are never printed, logged or written by this library.
"""
import base64
import json
import os
import shutil
import subprocess
import time

from .errors import AuthError, RefusedError, redact, remember_secret

STORAGE_RESOURCE = 'https://storage.azure.com/'
TOKEN_FILE_ENV = 'EVIDENCE_STORE_TOKEN_FILE'

_FORBIDDEN_MARKERS = ('accountkey=', 'sharedaccesssignature=', 'defaultendpointsprotocol=',
                      'sig=', 'sv=', '&se=', '?se=', 'blobendpoint=')


def refuse_shared_key_material(value, what='value'):
    """Raise RefusedError if `value` looks like a SAS, account key or connection string."""
    if not value:
        return
    low = str(value).lower()
    for m in _FORBIDDEN_MARKERS:
        if m in low:
            raise RefusedError('%s looks like a SAS token, account key or connection string; '
                               'this client accepts Entra bearer tokens only' % what)


def _check_token(tok, source):
    tok = (tok or '').strip()
    if not tok:
        raise AuthError('no token from %s' % source)
    refuse_shared_key_material(tok, 'the token from %s' % source)
    if any(c.isspace() for c in tok):
        raise AuthError('the token from %s contains whitespace; expected one bearer token' % source)
    remember_secret(tok)
    return tok


class StaticTokenProvider(object):
    """For tests and for callers that already hold a token. Not for production config."""

    def __init__(self, token):
        self._token = _check_token(token, 'the injected provider')

    def __call__(self):
        return self._token

    def __repr__(self):
        return 'StaticTokenProvider([REDACTED])'


class FileTokenProvider(object):
    """Reads the token from a file on every call (the file may be refreshed by another process)."""

    def __init__(self, path):
        self.path = path

    def __call__(self):
        try:
            with open(self.path, 'r', encoding='utf-8') as fh:
                raw = fh.read()
        except OSError as e:
            raise AuthError('cannot read token file %s: %s' % (self.path, type(e).__name__))
        return _check_token(raw, 'token file')

    def __repr__(self):
        return 'FileTokenProvider(%r)' % self.path


class AzCliTokenProvider(object):
    """`az account get-access-token`, cached until five minutes before expiry. Bounded wait."""

    def __init__(self, resource=STORAGE_RESOURCE, timeout=60):
        self.resource = resource
        self.timeout = timeout
        self._tok = None
        self._exp = 0.0

    def __call__(self):
        if self._tok and time.time() < self._exp - 300:
            return self._tok
        az = shutil.which('az') or shutil.which('az.cmd')
        if not az:
            raise AuthError('no token: EVIDENCE_STORE_TOKEN_FILE is not set and the Azure CLI '
                            '(az) is not on PATH')
        try:
            p = subprocess.run([az, 'account', 'get-access-token', '--resource', self.resource,
                                '-o', 'json'], capture_output=True, text=True,
                               timeout=self.timeout)
        except subprocess.TimeoutExpired:
            raise AuthError('az account get-access-token did not answer within %ss' % self.timeout)
        if p.returncode != 0:
            raise AuthError('az account get-access-token failed (exit %d): %s'
                            % (p.returncode, redact(p.stderr)[:400]))
        try:
            d = json.loads(p.stdout)
        except ValueError:
            raise AuthError('az account get-access-token returned non-JSON output')
        tok = _check_token(d.get('accessToken'), 'az')
        exp = d.get('expires_on')
        try:
            self._exp = float(exp) if exp else time.time() + 600
        except (TypeError, ValueError):
            self._exp = time.time() + 600
        self._tok = tok
        return tok

    def __repr__(self):
        return 'AzCliTokenProvider(%r)' % self.resource


class ChainTokenProvider(object):
    def __init__(self, providers):
        self.providers = list(providers)

    def __call__(self):
        errs = []
        for p in self.providers:
            try:
                return p()
            except AuthError as e:
                errs.append(str(e))
        raise AuthError('no token source worked: ' + ' | '.join(errs))


def default_token_provider(token_file=None, az_timeout=60):
    """token_file (explicit) > env EVIDENCE_STORE_TOKEN_FILE > az CLI."""
    path = token_file or os.environ.get(TOKEN_FILE_ENV)
    if path:
        return FileTokenProvider(path)
    return AzCliTokenProvider(timeout=az_timeout)


def get_token(provider):
    """Call a provider and validate what it returns (also registers it for redaction)."""
    if provider is None:
        raise AuthError('no token provider was supplied')
    try:
        tok = provider()
    except AuthError:
        raise
    except Exception as e:  # a provider bug must not leak a token through its message
        raise AuthError('token provider raised %s: %s' % (type(e).__name__, redact(str(e))))
    return _check_token(tok, 'the token provider')


def writer_from_token(token):
    """Decode (NOT verify) the JWT claims that name the caller.

    The signature is not checked here: the storage service checks it when it authorises the
    request. This is therefore the writer AS ASSERTED BY THE TOKEN, and is labelled so.
    """
    out = {'basis': 'AS_ASSERTED_BY_TOKEN: claims decoded by the client, signature NOT verified '
                    'locally; the storage service authorised the request with this token',
           'oid': None, 'appid': None, 'tid': None, 'idtyp': None}
    try:
        part = token.split('.')[1]
        part += '=' * (-len(part) % 4)
        claims = json.loads(base64.urlsafe_b64decode(part.encode('ascii')).decode('utf-8'))
    except Exception:
        out['basis'] = 'NOT ESTABLISHED: the token is not a decodable JWT'
        return out
    out['oid'] = claims.get('oid')
    out['appid'] = claims.get('appid') or claims.get('azp')
    out['tid'] = claims.get('tid')
    out['idtyp'] = claims.get('idtyp')
    return out
