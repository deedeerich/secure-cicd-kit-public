"""Structured results. Every result is a dataclass with to_dict() that serialises to JSON.

Status vocabulary (one place, imported everywhere):
  object status : CREATED, ALREADY_PRESENT, CONFLICT, REFUSED, AUTH, NETWORK, ERROR, NOT_ATTEMPTED
  verify verdict: VERIFIED, MISMATCH, NO_RECEIPT, NOT_SEALED, MISSING
  overall       : OK, ALREADY_PRESENT, CONFLICT, REFUSED, AUTH, NETWORK, VERIFY_FAILED,
                  CHAIN_BROKEN, ERROR
"""
from dataclasses import asdict, dataclass, field
from typing import List, Optional

CREATED = 'CREATED'
ALREADY_PRESENT = 'ALREADY_PRESENT'
CONFLICT = 'CONFLICT'
REFUSED = 'REFUSED'
AUTH = 'AUTH'
NETWORK = 'NETWORK'
ERROR = 'ERROR'
NOT_ATTEMPTED = 'NOT_ATTEMPTED'

VERIFIED = 'VERIFIED'
MISMATCH = 'MISMATCH'
NO_RECEIPT = 'NO_RECEIPT'
NOT_SEALED = 'NOT_SEALED'
MISSING = 'MISSING'

OK = 'OK'
VERIFY_FAILED = 'VERIFY_FAILED'
CHAIN_BROKEN = 'CHAIN_BROKEN'

# Worst first. Overall status = the worst status present.
_SEVERITY = [AUTH, NETWORK, ERROR, REFUSED, CHAIN_BROKEN, CONFLICT, VERIFY_FAILED,
             ALREADY_PRESENT, OK]

VERIFY_MEANING = ('VERIFIED means the stored bytes hash to the sha256 in the receipt (and, with '
                  'check_seal, in an intact seal chain). That is integrity. It does not establish '
                  'who produced the bytes or that they are true (authenticity).')


def worst(statuses):
    s = set(statuses)
    for x in _SEVERITY:
        if x in s:
            return x
    return OK


class _Dict(object):
    def to_dict(self):
        return asdict(self)


@dataclass
class ObjectResult(_Dict):
    container: str
    name: str
    status: str
    relative_path: Optional[str] = None
    sha256: Optional[str] = None
    size: Optional[int] = None
    content_type: Optional[str] = None
    layer: Optional[str] = None
    version_id: Optional[str] = None
    upload_method: Optional[str] = None
    receipt_name: Optional[str] = None
    receipt_status: Optional[str] = None
    message: str = ''


@dataclass
class PushResult(_Dict):
    status: str
    operation: str = 'push'
    container: str = ''
    prefix: str = ''
    tool: str = ''
    counts: dict = field(default_factory=dict)
    objects: List[ObjectResult] = field(default_factory=list)
    manifest: Optional[ObjectResult] = None
    message: str = ''


@dataclass
class Verdict(_Dict):
    container: str
    name: str
    verdict: str
    version_id: Optional[str] = None
    sha256_actual: Optional[str] = None
    sha256_receipt: Optional[str] = None
    size_actual: Optional[int] = None
    size_receipt: Optional[int] = None
    receipt_name: Optional[str] = None
    sealed_in: Optional[str] = None
    sha256_seal: Optional[str] = None
    notes: List[str] = field(default_factory=list)


@dataclass
class VerifyResult(_Dict):
    status: str
    operation: str = 'verify'
    container: str = ''
    counts: dict = field(default_factory=dict)
    verdicts: List[Verdict] = field(default_factory=list)
    seal_chain: Optional[dict] = None
    meaning: str = VERIFY_MEANING
    message: str = ''


@dataclass
class SealResult(_Dict):
    status: str
    operation: str = 'seal'
    container: str = ''
    seal_name: Optional[str] = None
    seal_sha256: Optional[str] = None
    seal_number: Optional[int] = None
    previous_seal: Optional[dict] = None
    counts: dict = field(default_factory=dict)
    tagged: int = 0
    tag_failures: List[dict] = field(default_factory=list)
    index_name: Optional[str] = None
    index_sha256: Optional[str] = None
    chain_before: Optional[dict] = None
    message: str = ''


@dataclass
class FindResult(_Dict):
    status: str
    operation: str = 'find'
    query: dict = field(default_factory=dict)
    count: int = 0
    items: List[dict] = field(default_factory=list)
    message: str = ''


@dataclass
class PulledObject(_Dict):
    name: str
    verdict: str
    local_path: Optional[str] = None
    written: bool = False
    sha256_actual: Optional[str] = None
    sha256_receipt: Optional[str] = None
    message: str = ''


@dataclass
class PullResult(_Dict):
    status: str
    operation: str = 'pull'
    container: str = ''
    dest: str = ''
    counts: dict = field(default_factory=dict)
    objects: List[PulledObject] = field(default_factory=list)
    meaning: str = VERIFY_MEANING
    message: str = ''
