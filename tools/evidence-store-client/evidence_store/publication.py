"""The publication gate: what may be written where Tines reads (PROTOCOL.md section 4.2).

A container boundary is not data classification. Tines reads the seven result containers
(`usr-reviews`, `adr`, `lz-vending`, `cicd-kit-gates`, `seal`, `index`, `ciso-harness-verdicts`); an object written there is
"readable by Tines" only when it is a schema-valid, scanned object:

1. its content type is on the allow-list (JSON by default); anything else -- text, archives,
   binary blobs -- is refused unless the reviewed policy DECLARES that type for that container and
   prefix (none is declared by default);
2. a JSON document declares its type: the top-level field `schema`; else `kind` + `schema_version`
   (the kit's deploy state); else -- only for the kit files that carry no id -- a declaration BY
   NAME in the reviewed policy. That id must be registered for this container and prefix, and the
   document must validate against the shipped JSON Schema (`publication/<file>.schema.json`);
3. a content scanner finds no credential or secret shape (the client's `redact()` shapes and the
   evidence harness's collection-output classes);
4. configurable denylists find no likely PHI/CUI marker (SSN-like numbers, an MRN pattern, CUI
   banner markings).

A refusal is status REFUSED (exit 5; API 422 `publication_refused`) with a reason code, the
object, and the CLASS of what matched -- never the matched text. Raw containers are not gated.

The policy (`publication/policy.json`) ships inside the vendored, tree-hashed package, so a
change to it is a reviewed re-pin. An extra denylist (EVIDENCE_PUBLICATION_DENYLIST, a JSON file)
can ADD patterns; it can never remove a built-in one or declare a new type.

Stdlib only.
"""
import json
import os
import re

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'publication')
POLICY_FILE = os.path.join(HERE, 'policy.json')
POLICY_SCHEMA = 'evidence-store.publication-policy/v1'
EXTRA_DENYLIST_ENV = 'EVIDENCE_PUBLICATION_DENYLIST'

# reason codes (stable; tests and the API branch on them)
PUB_CONTENT_TYPE = 'PUB_CONTENT_TYPE'      # content type not on the allow-list
PUB_BINARY = 'PUB_BINARY'                  # bytes that are not UTF-8 text, not declared
PUB_NOT_JSON = 'PUB_NOT_JSON'              # declared JSON but does not parse / not an object
PUB_NO_SCHEMA = 'PUB_NO_SCHEMA'            # no schema id in the document
PUB_UNKNOWN_SCHEMA = 'PUB_UNKNOWN_SCHEMA'  # schema id not registered for this container/prefix
PUB_SCHEMA_INVALID = 'PUB_SCHEMA_INVALID'  # does not validate against its schema
PUB_SECRET = 'PUB_SECRET'                  # a credential or secret shape
PUB_PHI_CUI = 'PUB_PHI_CUI'                # a likely PHI/CUI marker
PUB_TOO_LARGE = 'PUB_TOO_LARGE'            # over the gate's size limit
PUB_METADATA = 'PUB_METADATA'              # a secret/PHI/CUI shape in ids, index fields or the path

PREFIX = 'PUBLICATION_REFUSED'
_POLICY = None


class PublicationRefused(Exception):
    def __init__(self, reason, message):
        super().__init__('%s %s: %s' % (PREFIX, reason, message))
        self.reason = reason


def _compile(pairs, what):
    out = []
    for p in pairs:
        if not (isinstance(p, list) and len(p) == 2 and all(isinstance(x, str) for x in p)):
            raise ValueError('%s entries are [name, regex] pairs' % what)
        out.append((p[0], re.compile(p[1])))
    return out


class Policy(object):
    def __init__(self, doc, extra=None):
        if doc.get('schema') != POLICY_SCHEMA:
            raise ValueError('not a %s document' % POLICY_SCHEMA)
        self.doc = doc
        self.containers = tuple(doc['containers'])
        self.schema_keys = tuple(doc['schema_keys'])
        self.json_types = tuple(doc['json_content_types'])
        self.allowed_types = tuple(doc['allowed_content_types'])
        self.declared = list(doc.get('declared_non_json') or [])
        self.by_name = list(doc.get('declared_by_name') or [])
        self.kind_version = tuple(doc['kind_version_keys'])
        self.max_bytes = int(doc['max_object_bytes'])
        self.types = dict(doc['types'])
        self.secret = _compile(doc['secret_patterns'], 'secret_patterns')
        self.phi_cui = _compile(doc['phi_cui_patterns'], 'phi_cui_patterns')
        if extra:
            self.secret += _compile(extra.get('secret_patterns') or [], 'secret_patterns')
            self.phi_cui += _compile(extra.get('phi_cui_patterns') or [], 'phi_cui_patterns')
            unknown = sorted(set(extra) - {'secret_patterns', 'phi_cui_patterns', 'note'})
            if unknown:
                raise ValueError('an extra denylist may only add secret_patterns and '
                                 'phi_cui_patterns, not %s' % unknown)
        self._schemas = {}

    def gated(self, container):
        return container in self.containers

    def schema_for(self, schema_id):
        if schema_id not in self._schemas:
            with open(os.path.join(HERE, self.types[schema_id]['file']), encoding='utf-8') as fh:
                self._schemas[schema_id] = json.load(fh)
        return self._schemas[schema_id]


def load_policy(path=None, env=None):
    """The built-in policy, plus an additive denylist file when EVIDENCE_PUBLICATION_DENYLIST is
    set. Cached for the default call."""
    global _POLICY
    env = os.environ if env is None else env
    extra_path = env.get(EXTRA_DENYLIST_ENV)
    if path is None and not extra_path and _POLICY is not None:
        return _POLICY
    with open(path or POLICY_FILE, encoding='utf-8') as fh:
        doc = json.load(fh)
    extra = None
    if extra_path:
        with open(extra_path, encoding='utf-8') as fh:
            extra = json.load(fh)
    pol = Policy(doc, extra)
    if path is None and not extra_path:
        _POLICY = pol
    return pol


# ── a small JSON Schema subset (the same keywords the repo's schema tests use) ──────────────────
_TYPES = {'object': dict, 'array': list, 'string': str, 'integer': int, 'boolean': bool,
          'null': type(None), 'number': (int, float)}


def _resolve(ref, root):
    if not isinstance(ref, str) or not ref.startswith('#/'):
        raise ValueError('only local $ref is supported: %r' % ref)
    node = root
    for part in ref[2:].split('/'):
        node = node[part.replace('~1', '/').replace('~0', '~')]
    return node


def validate(doc, schema, path='$', root=None):
    """-> list of error strings (empty = valid). Keywords: type, required, properties,
    additionalProperties (false, or a schema), const, enum, pattern, minLength, minimum, items,
    oneOf, local $ref (#/$defs/...)."""
    root = schema if root is None else root
    if '$ref' in schema:
        schema = _resolve(schema['$ref'], root)
    errs = []
    if 'const' in schema and doc != schema['const']:
        errs.append('%s: not the const value' % path)
    if 'enum' in schema and doc not in schema['enum']:
        errs.append('%s: not in enum' % path)
    if 'oneOf' in schema:
        if sum(1 for s in schema['oneOf'] if not validate(doc, s, path, root)) != 1:
            errs.append('%s: matches not exactly one of oneOf' % path)
    t = schema.get('type')
    if t:
        ts = t if isinstance(t, list) else [t]
        ok = any(isinstance(doc, _TYPES[x]) and not (x in ('integer', 'number')
                                                     and isinstance(doc, bool)) for x in ts)
        if not ok:
            return errs + ['%s: not of type %s' % (path, t)]
    if isinstance(doc, str):
        if 'pattern' in schema and not re.search(schema['pattern'], doc):
            errs.append('%s: does not match %s' % (path, schema['pattern']))
        if 'minLength' in schema and len(doc) < schema['minLength']:
            errs.append('%s: shorter than %d' % (path, schema['minLength']))
    if isinstance(doc, (int, float)) and not isinstance(doc, bool) and 'minimum' in schema:
        if doc < schema['minimum']:
            errs.append('%s: below %s' % (path, schema['minimum']))
    if isinstance(doc, dict):
        for k in schema.get('required', []):
            if k not in doc:
                errs.append('%s: missing %s' % (path, k))
        props = schema.get('properties', {})
        extra = schema.get('additionalProperties')
        for k in doc:
            if k in props:
                continue
            if extra is False:
                errs.append('%s: unexpected %s' % (path, k))
            elif isinstance(extra, dict):
                errs += validate(doc[k], extra, '%s.%s' % (path, k), root)
        for k, s in props.items():
            if k in doc:
                errs += validate(doc[k], s, '%s.%s' % (path, k), root)
    if isinstance(doc, list) and 'items' in schema:
        for i, x in enumerate(doc):
            errs += validate(x, schema['items'], '%s[%d]' % (path, i), root)
    return errs


# ── scanning ─────────────────────────────────────────────────────────────────────────────
def _line_of(text, pos):
    return text.count('\n', 0, pos) + 1


def scan_text(text, policy=None):
    """-> (reason, class, line) of the first finding, or None. Never returns the matched text."""
    pol = policy or load_policy()
    for name, rx in pol.secret:
        m = rx.search(text)
        if m:
            return PUB_SECRET, name, _line_of(text, m.start())
    for name, rx in pol.phi_cui:
        m = rx.search(text)
        if m:
            return PUB_PHI_CUI, name, _line_of(text, m.start())
    return None


def _match_prefix(name, prefixes):
    return any(name.startswith(p) for p in prefixes)


def _by_name(entries, container, name):
    for d in entries:
        if d.get('container') == container and re.match(d['name_regex'], name):
            return d
    return None


def _base_type(ctype):
    return (ctype or '').split(';', 1)[0].strip().lower()


def _schema_id(pol, doc, container, name):
    """In-document id first (`schema`; else `kind` + `schema_version`), then a declaration by
    name in the reviewed policy (kit files that carry no id). -> (schema_id, how) or (None, '')."""
    if isinstance(doc, dict):
        for k in pol.schema_keys:
            if isinstance(doc.get(k), str) and doc.get(k):
                return doc[k], 'in-document %s' % k
        kk, vk = pol.kind_version
        kind, ver = doc.get(kk), doc.get(vk)
        if isinstance(kind, str) and kind and isinstance(ver, int) and not isinstance(ver, bool):
            return '%s/%d' % (kind, ver), 'in-document %s + %s' % (kk, vk)
    d = _by_name(pol.by_name, container, name)
    if d is not None:
        return d['schema_id'], 'declared by name in the publication policy'
    return None, ''


def check_metadata(container, values, policy=None):
    """ids, index fields and the blob name end up in receipts, tags and the index, all readable
    by Tines: they are scanned too. values: iterable of (label, value)."""
    pol = policy or load_policy()
    if not pol.gated(container):
        return
    for label, v in values:
        if v in (None, ''):
            continue
        hit = scan_text(str(v), pol)
        if hit:
            raise PublicationRefused(PUB_METADATA, '%s holds a %s shape (%s); nothing was written'
                                     % (label, hit[1], hit[0]))


def check_object(container, name, data, content_type, policy=None):
    """Raise PublicationRefused unless `data` may be published at container/name.
    -> the schema id (or the declared type id), or None for a container that is not gated."""
    pol = policy or load_policy()
    if not pol.gated(container):
        return None
    if len(data) > pol.max_bytes:
        raise PublicationRefused(PUB_TOO_LARGE, '%s: %d bytes is over the publication limit of %d'
                                 % (name, len(data), pol.max_bytes))
    ctype = _base_type(content_type)
    declared = _by_name(pol.declared, container, name)
    is_json = declared is None and ctype in pol.json_types
    if declared is None and not is_json:
        raise PublicationRefused(PUB_CONTENT_TYPE, '%s: content type %r is not allowed in a result '
                                 'container (allowed: %s; any other type only where the '
                                 'publication policy declares it)'
                                 % (name, ctype, ', '.join(pol.allowed_types)))
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        if declared is not None and declared.get('kind') == 'binary':
            hit = scan_text(data.decode('latin-1'), pol)
            if hit:
                raise PublicationRefused(hit[0], '%s: a %s shape near line %d; nothing was written'
                                         % (name, hit[1], hit[2]))
            return declared['schema_id']
        raise PublicationRefused(PUB_BINARY, '%s: binary content is refused in a result container '
                                 'unless the publication policy declares it' % name)
    if text.startswith('﻿'):
        text = text[1:]
    hit = scan_text(text, pol)
    if hit:
        raise PublicationRefused(hit[0], '%s: a %s shape at line %d; nothing was written'
                                 % (name, hit[1], hit[2]))
    if declared is not None:
        return declared['schema_id']
    try:
        doc = json.loads(text)
    except ValueError:
        raise PublicationRefused(PUB_NOT_JSON, '%s: not parseable JSON' % name)
    sid, how = _schema_id(pol, doc, container, name)
    if sid is None:
        raise PublicationRefused(PUB_NO_SCHEMA, '%s: no schema id (a top-level %s, or %s + %s), '
                                 'and the publication policy declares none for this name'
                                 % (name, ' or '.join(pol.schema_keys), pol.kind_version[0],
                                    pol.kind_version[1]))
    entry = pol.types.get(sid)
    if entry is None or container not in entry['containers'] or not _match_prefix(
            name, entry['containers'][container]):
        raise PublicationRefused(PUB_UNKNOWN_SCHEMA, '%s: schema %r (%s) is not registered for %s '
                                 'at this prefix' % (name, sid[:120], how, container))
    errs = validate(doc, pol.schema_for(sid))
    if errs:
        raise PublicationRefused(PUB_SCHEMA_INVALID, '%s: does not validate against %s (%s%s)'
                                 % (name, sid, '; '.join(errs[:3]),
                                    '' if len(errs) <= 3 else '; +%d more' % (len(errs) - 3)))
    return sid
