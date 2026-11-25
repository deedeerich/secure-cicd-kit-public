"""The store contract: container -> writer tool -> allowed prefixes -> immutability state.

The Terraform lane emits it as an output named `store_contract` whose value is
`jsonencode(local.store_contract)`, i.e. a JSON STRING. Accepted shapes:
  * the contract object itself                      (`terraform output -raw store_contract`)
  * a JSON string literal holding it                (`terraform output -json store_contract`)
  * {"store_contract": {...}}                       (one output, unwrapped)
  * {"store_contract": {"value": {...} | "<JSON>"}} (`terraform output -json`)

Field names: the Terraform's `account_name` / `blob_endpoint` and the sample's `account` /
`endpoint_suffix`; `immutability` as a string or as `{state, retention_days}`; `layered` given, or
derived (every allowed prefix is a layer directory). `writer_tool: null` = the container has no
writer (a tool left out of the root). `allowed_prefixes: []` = NOTHING may be written there;
`[""]` is the whole container.

Everything here is a LOCAL check, made before any network call. The service's RBAC and ABAC
conditions remain the enforcing control; this check only stops a wrong push early and loudly.
"""
import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

from .errors import RefusedError

LAYERS = ('reported', 'evaluated', 'corroborated', 'approved')
SEALER_ONLY = ('seal', 'index')
RECEIPT_SUFFIX = '.receipt.json'
MANIFEST_DIR = '_manifests'
IMMUTABILITY_STATES = ('none', 'unlocked', 'locked', 'unknown')


@dataclass
class ContainerRule:
    name: str
    writer_tool: Optional[str]
    allowed_prefixes: list
    layered: bool = False
    immutability: str = 'unknown'
    retention_days: Optional[int] = None


@dataclass
class StoreContract:
    containers: dict
    account: str = ''
    endpoint_suffix: str = ''
    sealer_tool: str = 'sealer'
    sha256: str = ''
    source: str = ''
    raw: dict = field(default_factory=dict)

    def rule(self, container):
        r = self.containers.get(container)
        if r is None:
            raise RefusedError('container %r is not in the store contract' % container)
        return r

    def containers_for(self, tool):
        return sorted(c for c, r in self.containers.items() if r.writer_tool == tool)


def _decode_if_string(d):
    """A Terraform output value made with jsonencode() is a JSON string: decode it once more."""
    if isinstance(d, str):
        return json.loads(d)
    return d


def _unwrap(d):
    d = _decode_if_string(d)
    if isinstance(d, dict) and 'store_contract' in d and 'containers' not in d:
        d = _decode_if_string(d['store_contract'])
        if isinstance(d, dict) and 'value' in d and 'containers' not in d:
            d = _decode_if_string(d['value'])
    return d


def _layer_dir(p):
    return p.endswith('/') and p.count('/') == 1 and p[:-1] in LAYERS


def _endpoint(d, source):
    """-> (account, endpoint_suffix) from account/endpoint_suffix or account_name/blob_endpoint."""
    account = d.get('account') or d.get('account_name') or ''
    suffix = d.get('endpoint_suffix') or ''
    ep = d.get('blob_endpoint')
    if ep and not suffix:
        host = (urlsplit(ep).hostname or '').lower()
        acct, sep, rest = host.partition('.blob.')
        if not sep or not rest or (account and acct != account.lower()):
            raise RefusedError('store contract %s: blob_endpoint %r does not name the account %r '
                               'as https://<account>.blob.<suffix>/' % (source, ep, account))
        account, suffix = account or acct, rest
    return account, suffix


def _immutability(name, v):
    days = None
    if isinstance(v, dict):
        days = v.get('retention_days')
        v = v.get('state', 'unknown')
    imm = str('unknown' if v is None else v).lower()
    if imm not in IMMUTABILITY_STATES:
        raise RefusedError('contract container %r: immutability %r is not one of %s'
                           % (name, imm, IMMUTABILITY_STATES))
    if days is not None and (isinstance(days, bool) or not isinstance(days, int)):
        raise RefusedError('contract container %r: retention_days must be a whole number' % name)
    return imm, days


def parse_contract(data, source='<memory>'):
    """dict or bytes/str JSON -> StoreContract. Raises RefusedError when malformed."""
    if isinstance(data, (bytes, bytearray)):
        raw_bytes = bytes(data)
    elif isinstance(data, str):
        raw_bytes = data.encode('utf-8')
    else:
        raw_bytes = json.dumps(data, sort_keys=True).encode('utf-8')
    try:
        d = _unwrap(json.loads(raw_bytes.decode('utf-8-sig')))
    except ValueError:
        raise RefusedError('store contract %s is not valid JSON' % source)
    if not isinstance(d, dict) or not isinstance(d.get('containers'), dict):
        raise RefusedError('store contract %s has no "containers" object' % source)
    rules = {}
    for name, c in d['containers'].items():
        if not isinstance(c, dict) or 'writer_tool' not in c:
            raise RefusedError('contract container %r has no writer_tool' % name)
        tool = c['writer_tool']
        if tool is not None and (not isinstance(tool, str) or not tool):
            raise RefusedError('contract container %r: writer_tool must be a name or null' % name)
        prefixes = c.get('allowed_prefixes', [''])
        if not isinstance(prefixes, list) or not all(isinstance(p, str) for p in prefixes):
            raise RefusedError('contract container %r: allowed_prefixes must be a list of strings'
                               % name)
        imm, days = _immutability(name, c.get('immutability', 'unknown'))
        if 'layered' in c:
            layered = bool(c['layered'])
        else:
            layered = bool(prefixes) and all(_layer_dir(p) for p in prefixes)
        rules[name] = ContainerRule(name, tool, prefixes, layered, imm, days)
    account, suffix = _endpoint(d, source)
    return StoreContract(rules, account, suffix, d.get('sealer_tool', 'sealer'),
                         hashlib.sha256(raw_bytes).hexdigest(), source, d)


def load_contract(path):
    try:
        with open(path, 'rb') as fh:
            return parse_contract(fh.read(), path)
    except OSError as e:
        raise RefusedError('cannot read store contract %s: %s' % (path, type(e).__name__))


def normalise_blob_name(name):
    """Reject traversal and absolute names; return the posix-normalised name."""
    if not name or '\x00' in name:
        raise RefusedError('empty or NUL-containing blob name')
    n = name.replace('\\', '/')
    if n.startswith('/') or (len(n) > 1 and n[1] == ':'):
        raise RefusedError('absolute blob name refused: %r' % name)
    parts = n.split('/')
    if any(p in ('..', '.', '') for p in parts):
        raise RefusedError('blob name with ., .. or empty segments refused: %r' % name)
    if len(n) > 1024:
        raise RefusedError('blob name longer than 1024 characters refused')
    return n


def check_write(contract, tool, container, blob_name, layer=None, internal=False):
    """Refuse locally a write outside the tool's container/prefix. Returns the derived layer.

    internal=True is used for receipts and manifests the client itself creates.
    """
    if contract is None:
        raise RefusedError('no store contract supplied: pushes are refused without one')
    if not tool:
        raise RefusedError('no tool (writer identity) given')
    rule = contract.rule(container)
    if container in SEALER_ONLY and not internal:
        raise RefusedError('container %r is written only by the seal operation' % container)
    if rule.writer_tool is None:
        raise RefusedError('container %r has no writer in the store contract' % container)
    if not rule.allowed_prefixes:
        raise RefusedError('container %r: allowed_prefixes is empty in the store contract, so '
                           'nothing may be written there' % container)
    if rule.writer_tool != tool:
        raise RefusedError('tool %r may not write to container %r (writer is %r; %r writes %s)'
                           % (tool, container, rule.writer_tool, tool,
                              contract.containers_for(tool) or 'nothing'))
    name = normalise_blob_name(blob_name)
    if not internal:
        if name.endswith(RECEIPT_SUFFIX):
            raise RefusedError('%r: names ending %s are reserved for receipts' % (name,
                                                                                 RECEIPT_SUFFIX))
        if ('/' + MANIFEST_DIR + '/') in ('/' + name):
            raise RefusedError('%r: the %s/ segment is reserved for manifests' % (name,
                                                                                 MANIFEST_DIR))
    if not any(name.startswith(p) for p in rule.allowed_prefixes):
        raise RefusedError('%r is outside the allowed prefixes of %r: %s'
                           % (name, container, rule.allowed_prefixes))
    derived = None
    if rule.layered:
        first = name.split('/', 1)[0]
        if first not in LAYERS:
            raise RefusedError('%r: container %r is layered; the first segment must be one of %s'
                               % (name, container, LAYERS))
        derived = first
        if layer and layer != derived:
            raise RefusedError('layer %r given but the path is in layer %r' % (layer, derived))
    elif layer:
        if layer not in LAYERS:
            raise RefusedError('unknown layer %r' % layer)
        derived = layer
    return derived
