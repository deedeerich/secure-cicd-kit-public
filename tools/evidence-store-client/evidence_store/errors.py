"""Error types. Every message passes through redact() before it is raised or shown."""
import re

_BEARER = re.compile(r'(?i)(bearer\s+)[A-Za-z0-9\-_.~+/=]+')
_JWT = re.compile(r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*')
_SIG = re.compile(r'(?i)(sig|accountkey|sharedaccesssignature)=[^&;\s]+')

_KNOWN_SECRETS = set()


def remember_secret(value):
    """Register a token so redact() removes it verbatim even if it is not JWT-shaped."""
    if value and len(value) >= 8:
        _KNOWN_SECRETS.add(value)


def redact(text):
    s = '' if text is None else str(text)
    for v in sorted(_KNOWN_SECRETS, key=len, reverse=True):
        s = s.replace(v, '[REDACTED]')
    s = _BEARER.sub(r'\1[REDACTED]', s)
    s = _JWT.sub('[REDACTED-JWT]', s)
    s = _SIG.sub(r'\1=[REDACTED]', s)
    return s


class EvidenceStoreError(Exception):
    """Base class. `kind` maps to an exit code in the CLI and a status in results."""
    kind = 'ERROR'

    def __init__(self, message, status=None):
        super().__init__(redact(message))
        self.status = status


class RefusedError(EvidenceStoreError):
    """Refused locally before any network call (contract, path, forbidden credential)."""
    kind = 'REFUSED'


class AuthError(EvidenceStoreError):
    """No token, or the service said 401/403."""
    kind = 'AUTH'


class NetworkError(EvidenceStoreError):
    """Transport failure, a 5xx after bounded retries, or a 403 AuthorizationFailure (the
    storage network rules refused the request)."""
    kind = 'NETWORK'


class ServiceError(EvidenceStoreError):
    """An unexpected HTTP status from the service."""
    kind = 'SERVICE'
