#!/usr/bin/env python3
"""Cross-edited rollback: resource classes, the dependency review and the dependency graph.
(KDEC-023, owner 2026-10-23, lane L-RB3. Used by scripts/rollback_sequence.py for `adapter: arm`.)

WHY THIS EXISTS

    Owner, 2026-10-23: "if someone else or a different service edited something then we need to
    follow the same cross edited rollback rules. If it's a resource or service that is not shared
    and multi-configurable for each thing think frontdoor or NSGs or firewall rules and routing or
    WAF rules and routing that are shared but only the product's configs were changed those things
    can be rolled back but if a solid stable resource like an app service or a database or a
    container or something is changed by something else the dependency review and refusal to
    rollback fully and the partial or no rollback with reasons and dependency graph is provided to
    the user."

    The deploy contract reverses what ONE run changed on ONE App Service or Container App. A
    release can also change entries in resources many products share (an NSG rule, a Front Door
    route, a gateway listener) and other stable resources (a Key Vault, a storage account, a
    database). Reversing the whole release when somebody else has since changed one of them is how a
    rollback breaks a service it never owned; refusing all of it when only another product's entry
    moved leaves a broken release standing for no reason.

THE RESOURCE CLASS (rollback-resource-classes.yaml; assurance-taxonomy.yaml rollback_resource_class)

    SHARED_MULTI_CONFIG  the product's ENTRIES are reversed, nothing else of the resource; every
                         other entry, and the parent, is read before and after and must be
                         byte-identical. Another product moving its own entries does not matter.
    STABLE               the resource is reversed whole, and only if nothing else changed it.
    unregistered         never guessed: a human decision, and so is everything tied to it.

THE EVIDENCE (`resources.json` in the deploying run's deploy evidence, written by the deployer)

    {"schema_version": 1, "release_id": "run-<id>-<attempt>", "product": "...",
     "target": {"resource_group": "...", "name": "..."}, "app_url": "https://...",
     "nodes": [{"id": "<ARM id>", "action": "CREATED" | "MODIFIED", "prior": <body before> | null,
                "post": <body the release left>, ["depends_on": [ids]]}],
     ["others_at_deploy": {"<entry id>": "<sha256 of its canonical body>"}],
     ["observed": {"<id of something it depends on>": "<sha256>"}]}

    `post` is what the release LEFT (read back after the deploy). The product's own entries are the
    nodes this evidence names; a live entry that carries the product's name but is not here is
    reported and left alone.

THE DEPENDENCY REVIEW, from a FRESH live read (every node through `az rest`)

    MARK each node: changed-by-this-release (it holds exactly what the release left),
    changed-by-other (it does not, or carries another release's stamp, or is gone), unknown (it
    could not be read), unchanged / not-judged (a resource the release depends on but did not
    change: unchanged when a baseline was recorded and still holds, not-judged without one).
    EDGES: `depends_on` from the evidence; every ARM resource id found in a node's body (app
    settings, connection strings by resource id, subnet ids, private endpoints, role assignment
    scopes...); every host one node USES that another PROVIDES (a Key Vault reference by vault URI,
    a host name); an entry -> its shared parent; and, in collections evaluated together (NSG rules
    and route-table routes by priority or prefix, firewall and WAF rules by priority), the
    product's entries are coupled to each other.
    BLOCKED: a node changed by another actor or unreadable, a node no machine may reverse
    (unregistered type, `reversal: human`, a data-bearing resource the release CREATED), and every
    release node that depends on one of those, or that one of those depends on, or that is
    evaluated together with one.
    DECIDE:
      nothing blocked              ROLLBACK_DEPENDENCY_CLEAR (stable only) or
                                   ROLLBACK_SCOPED_TO_PRODUCT_CONFIG (shared entries involved):
                                   the FULL rollback runs
      some blocked, some free      ROLLBACK_PARTIAL_DEPENDENCY_CONFLICT: the full rollback is
                                   refused; the free nodes are reversed (ELIGIBLE_OWNED_PART_SEPARABLE,
                                   the existing rule: the unit of conflict is the mutation)
      nothing free                 ROLLBACK_REFUSED_DEPENDENCY_CONFLICT: nothing is touched
    A partial or refused review is ROLLBACK_REQUIRES_HUMAN_DECISION (rollback_state): a person
    decides the nodes left, from the graph (JSON and Mermaid), each with its reason.

REVERSAL, dependents first: a MODIFIED node gets its prior body PUT back (read-only fields
stripped); a CREATED node is DELETEd; an inline entry (an Application Gateway listener) is
changed inside one PUT of its parent that changes only the product's elements. Each reversed
node is read back against its prior state; every other entry of each shared parent, and the
parent, against the read taken just before.

USAGE  imported; `rollback_dependencies.py --self-test` checks the registry and the decision rules.
"""
import copy
import hashlib
import io
import json
import os
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import deploy_contract as dc  # noqa: E402

REGISTRY = os.path.join(os.path.dirname(HERE), 'rollback-resource-classes.yaml')

SHARED = 'SHARED_MULTI_CONFIG'
STABLE = 'STABLE'
# rollback_dependency_outcome (assurance-taxonomy.yaml)
CLEAR = 'ROLLBACK_DEPENDENCY_CLEAR'
SCOPED = 'ROLLBACK_SCOPED_TO_PRODUCT_CONFIG'
PARTIAL = 'ROLLBACK_PARTIAL_DEPENDENCY_CONFLICT'
REFUSED = 'ROLLBACK_REFUSED_DEPENDENCY_CONFLICT'
# rollback_state, reused
HUMAN = 'ROLLBACK_REQUIRES_HUMAN_DECISION'
AUTO = 'AUTO_ROLLBACK_ALLOWED'
# rollback_step_eligibility, reused
UNTOUCHED = 'ELIGIBLE_UNTOUCHED'
OWNED_PART = 'ELIGIBLE_OWNED_PART_SEPARABLE'

mark_release, mark_other, mark_unknown = 'changed-by-this-release', 'changed-by-other', 'unknown'
mark_unchanged, mark_not_judged = 'unchanged', 'not-judged'
ARM_ID = re.compile(r'/subscriptions/[0-9A-Za-z-]+/resourceGroups/[^\s"\'?#<>()]+', re.I)
URL_HOST = re.compile(r'https?://([A-Za-z0-9.-]+)', re.I)
PROVIDER_KEYS = ('vaultUri', 'defaultHostName', 'fullyQualifiedDomainName', 'hostName', 'loginServer',
                 'documentEndpoint', 'primaryEndpoints', 'fqdn')


# ----------------------------------------------------------------------------- registry
def load_registry(path=None):
    """The registry body is flow-style YAML (JSON with whole-line comments): read without PyYAML."""
    text = io.open(path or REGISTRY, encoding='utf-8').read()
    doc = json.loads('\n'.join(x for x in text.split('\n') if not x.lstrip().startswith('#')))
    doc['_types'] = dict((k.lower(), dict(v, name=k)) for k, v in (doc.get('types') or {}).items())
    return doc


def _split(rid):
    """-> (prefix through '/providers/', [namespace, type1, name1, type2, name2, ...])."""
    low = rid.lower()
    i = low.rfind('/providers/')
    if i < 0:
        return None, []
    j = i + len('/providers/')
    return rid[:j], [x for x in rid[j:].strip('/').split('/') if x != '']


def arm_type(rid_or_type):
    if '/providers/' not in rid_or_type.lower():
        return rid_or_type
    _p, rest = _split(rid_or_type)
    if not rest:
        return ''
    return '/'.join([rest[0]] + rest[1::2])


def resolve(reg, rid):
    """-> what the registry says about one id: class, the shared parent, the entry collection."""
    t = arm_type(rid)
    tl = t.lower().split('/')
    best = None
    for k in reg['_types']:
        kl = k.split('/')
        if tl[:len(kl)] == kl and (best is None or len(kl) > len(best.split('/'))):
            best = k
    out = {'type': t, 'class': None, 'spec': None, 'parent': None, 'entry': False,
           'collection': None, 'mode': None}
    if best is None:
        return out
    spec = reg['_types'][best]
    out.update({'class': spec.get('class'), 'spec': spec})
    depth = len(best.split('/')) - 1
    prefix, rest = _split(rid)
    if prefix is None:
        return out
    head, sub = rest[:1 + 2 * depth], rest[1 + 2 * depth:]
    out['parent'] = prefix + '/'.join(head)
    if spec.get('class') == SHARED and len(sub) >= 2:
        out['entry'] = True
        out['collection'] = '/'.join(sub[k] if k % 2 == 0 else '*' for k in range(len(sub) - 1))
        if out['collection'] in (spec.get('inline_collections') or {}):
            out['mode'] = 'inline'
        elif out['collection'] in (spec.get('child_collections') or []):
            out['mode'] = 'child'
    return out


def classify(reg, type_or_id):
    return resolve(reg, type_or_id)['class']


# ----------------------------------------------------------------------------- bodies
def canon(x):
    return json.dumps(x, sort_keys=True, separators=(',', ':'))


def sha(x):
    return hashlib.sha256(canon(x).encode('utf-8')).hexdigest()


def strip(body, fields):
    b = copy.deepcopy(body)
    for f in fields:
        parts = f.split('.')
        cur = b
        for p in parts[:-1]:
            cur = cur.get(p) if isinstance(cur, dict) else None
        if isinstance(cur, dict):
            cur.pop(parts[-1], None)
    return b


def norm(reg, body):
    return canon(strip(body, reg.get('read_only_fields') or []))


def diff_paths(a, b, where=''):
    """Leaf paths that differ between two bodies, with old -> new (for the record and the report)."""
    if isinstance(a, dict) and isinstance(b, dict):
        out = []
        for k in sorted(set(a) | set(b)):
            out += diff_paths(a.get(k), b.get(k), '%s.%s' % (where, k) if where else k)
        return out
    if a != b:
        return [(where or '(body)', a, b)]
    return []


def _short(v):
    s = v if isinstance(v, str) else json.dumps(v, sort_keys=True)
    return s if len(s) <= 60 else s[:57] + '...'


def describe(changes, limit=4):
    return '; '.join('%s %s -> %s' % (p, _short(a), _short(b)) for p, a, b in changes[:limit]) + (
        '; and %d more' % (len(changes) - limit) if len(changes) > limit else '')


def _get_path(body, dotted):
    cur = body
    for p in dotted.split('.'):
        cur = cur.get(p) if isinstance(cur, dict) else None
    return cur


def _set_path(body, dotted, value):
    parts = dotted.split('.')
    cur = body
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = value


# ----------------------------------------------------------------------------- ARM
def api_version(info):
    return ((info or {}).get('spec') or {}).get('api_version') or '2023-09-01'


def arm_get(rid, apiv):
    """-> ('ok', body) | ('absent', None) | ('error', text). A read failure is never 'absent'."""
    ok, doc, err = dc.az('rest', '--method', 'get', '--url', '%s?api-version=%s' % (rid, apiv))
    if ok:
        return 'ok', doc
    if 'NotFound' in (err or '') or 'Not Found' in (err or ''):
        return 'absent', None
    return 'error', err or 'unreadable'


def arm_put(rid, body, apiv):
    fd, path = tempfile.mkstemp(suffix='.json')
    try:
        with io.open(fd, 'w', encoding='utf-8') as fh:
            fh.write(json.dumps(body))
        ok, _doc, err = dc.az('rest', '--method', 'put', '--url', '%s?api-version=%s' % (rid, apiv),
                              '--body', '@' + path)
        return ok, err
    finally:
        os.remove(path)


def arm_delete(rid, apiv):
    ok, _doc, err = dc.az('rest', '--method', 'delete', '--url', '%s?api-version=%s' % (rid, apiv))
    return ok, err


def _element(parent_body, info, name):
    arr = _get_path(parent_body or {}, info['spec']['inline_collections'][info['collection']]) or []
    for e in arr:
        if isinstance(e, dict) and e.get('name') == name:
            return e
    return None


def read_node(n, reg):
    """-> ('ok', body) | ('absent', None) | ('error', text) for a node, inline entries included."""
    info = n['_info']
    if info['mode'] == 'inline':
        st, parent = arm_get(info['parent'], api_version(info))
        if st != 'ok':
            return st, parent
        e = _element(parent, info, n['name'])
        return ('ok', e) if e is not None else ('absent', None)
    return arm_get(n['id'], api_version(info))


def list_entries(parent, info):
    """Every entry of a shared parent: {entry id: body}, child collections expanded, inline arrays
    read from the parent. -> (entries, problem)."""
    spec, apiv = info['spec'], api_version(info)
    out = {}
    for pattern in spec.get('child_collections') or []:
        bases = [parent]
        for seg in pattern.split('/'):
            if seg == '*':
                continue
            nxt = []
            for b in bases:
                st, doc = arm_get(b + '/' + seg, apiv)
                if st == 'absent':
                    continue
                if st != 'ok':
                    return None, 'could not list %s/%s: %s' % (b, seg, doc)
                for v in (doc or {}).get('value') or []:
                    rid = v.get('id') or '%s/%s/%s' % (b, seg, v.get('name'))
                    nxt.append(rid)
                    if seg == pattern.split('/')[-1]:
                        out[rid] = v
            bases = nxt
    st, body = arm_get(parent, apiv)
    if st != 'ok':
        return None, 'could not read %s: %s' % (parent, body)
    for coll, path in (spec.get('inline_collections') or {}).items():
        for e in _get_path(body, path) or []:
            if isinstance(e, dict):
                out[e.get('id') or '%s/%s/%s' % (parent, coll, e.get('name'))] = e
    return {'parent': body, 'entries': out}, None


def parent_view(snapshot, info, mine):
    """The parent with what ARM mirrors from children, its etag and the release's own inline
    elements removed: what must not change when only the product's entries are reversed."""
    b = strip(snapshot['parent'], list(info['spec'].get('parent_excludes') or []) + ['etag'])
    for coll, path in (info['spec'].get('inline_collections') or {}).items():
        arr = _get_path(b, path)
        if isinstance(arr, list):
            _set_path(b, path, [e for e in arr if not (isinstance(e, dict) and
                                                       (e.get('id') or '').lower() in mine)])
    return canon(b)


# ----------------------------------------------------------------------------- the review
def _node(n, reg, release):
    info = resolve(reg, n['id'])
    return {'id': n['id'], 'name': n['id'].rstrip('/').rsplit('/', 1)[-1], 'type': info['type'],
            'class': info['class'], 'kind': 'entry' if info['entry'] else 'resource',
            'parent': info['parent'] if info['entry'] else None, 'collection': info['collection'],
            'action': n.get('action'), 'in_release': True, 'mark': None, 'decision': None,
            'reason': '', '_info': info, '_ev': n, '_live': None}


def _stamp_of(body):
    return dc._stamp_release(((body or {}).get('tags') or {}).get('release_ownership_stamp', '')) if \
        isinstance(body, dict) else ''


def mark_node(node, reg, release, sequence_releases):
    """Judge one release node against live state. Sets mark and reason; returns the live body."""
    ev, info = node['_ev'], node['_info']
    st, live = read_node(node, reg)
    node['_live'] = live
    if st == 'error':
        node['mark'], node['reason'] = mark_unknown, 'it could not be read (%s): an unknown is a human decision' % live
        return
    if st == 'absent':
        node['mark'] = mark_other
        node['reason'] = 'it no longer exists: another actor deleted it after the release'
        return
    stamp = _stamp_of(live)
    if stamp and stamp != release and stamp not in sequence_releases:
        node['mark'] = mark_other
        node['reason'] = ('it carries the ownership stamp of %s, not %s: another actor (or a release '
                          'outside this sequence) changed it' % (stamp, release))
        return
    if norm(reg, live) != norm(reg, ev.get('post') or {}):
        changes = diff_paths(strip(ev.get('post') or {}, reg.get('read_only_fields') or []),
                             strip(live, reg.get('read_only_fields') or []))
        node['mark'] = mark_other
        node['reason'] = 'another actor changed it after the release (%s)' % describe(changes)
        return
    node['mark'] = mark_release
    node['reason'] = 'it holds exactly what the release left'


def _hosts_provided(body):
    out = set()

    def walk(x, key=None):
        if isinstance(x, dict):
            for k, v in x.items():
                walk(v, k)
        elif isinstance(x, list):
            for v in x:
                walk(v, key)
        elif isinstance(x, str) and key in PROVIDER_KEYS:
            m = URL_HOST.match(x)
            out.add((m.group(1) if m else x).lower().rstrip('/'))
    if isinstance(body, dict):
        for k in PROVIDER_KEYS:
            walk((body.get('properties') or {}).get(k), k)
    return out


def _hosts_used(body):
    return set(h.lower() for h in URL_HOST.findall(canon(body or {})))


def build_graph(nodes, ev, reg):
    """-> edges [{from, to, kind}] and dependency-only nodes added to `nodes`."""
    edges, seen = [], set()

    def add(a, b, kind):
        if a and b and a != b and (a, b, kind) not in seen:
            seen.add((a, b, kind))
            edges.append({'from': a, 'to': b, 'kind': kind})
    by_low = dict((k.lower(), k) for k in nodes)
    for nid, n in list(nodes.items()):
        if not n['in_release']:
            continue
        for d in n['_ev'].get('depends_on') or []:
            if d.lower() not in by_low:
                nodes[d] = _dep_only(d, reg, ev)
                by_low[d.lower()] = d
            add(nid, by_low[d.lower()], 'declared')
        text = canon(n['_ev'].get('post') or {}) + canon(n['_live'] or {})
        for found in set(ARM_ID.findall(text)):
            fl = found.lower().rstrip('/')
            best = None
            for low, real in by_low.items():
                if (fl == low or fl.startswith(low + '/')) and (best is None or len(low) > len(best)):
                    best = low
            if best is None:
                info = resolve(reg, found)
                target = info['parent'] or found
                if target.lower() not in by_low:
                    nodes[target] = _dep_only(target, reg, ev)
                    by_low[target.lower()] = target
                best = target.lower()
            if by_low[best] != nid and not (n['parent'] and by_low[best].lower() == n['parent'].lower()):
                add(nid, by_low[best], 'references')
        if n['parent']:
            if n['parent'].lower() not in by_low:
                p = _dep_only(n['parent'], reg, ev)
                p['kind'] = 'shared-resource'
                nodes[n['parent']] = p
                by_low[n['parent'].lower()] = n['parent']
            add(nid, by_low[n['parent'].lower()], 'entry-of')
    provided = {}
    for nid, n in nodes.items():
        for h in _hosts_provided(n['_ev'].get('post') if n['in_release'] else None) | _hosts_provided(n['_live']):
            provided[h] = nid
    for nid, n in nodes.items():
        if not n['in_release']:
            continue
        own = _hosts_provided(n['_ev'].get('post')) | _hosts_provided(n['_live'])
        for h in _hosts_used(n['_ev'].get('post')) | _hosts_used(n['_live']):
            if h in provided and h not in own:
                add(nid, provided[h], 'references')
    # Entries evaluated together (priority / prefix order) couple the product's entries.
    groups = {}
    for nid, n in nodes.items():
        if n['in_release'] and n['kind'] == 'entry' and \
                n['collection'] in ((n['_info']['spec'] or {}).get('interacting') or []):
            groups.setdefault((n['parent'].lower(), n['collection']), []).append(nid)
    for members in groups.values():
        for a in members:
            for b in members:
                if a < b:
                    add(a, b, 'evaluated-together')
    return edges


def _dep_only(rid, reg, ev):
    info = resolve(reg, rid)
    base = (ev.get('observed') or {})
    n = {'id': rid, 'name': rid.rstrip('/').rsplit('/', 1)[-1], 'type': info['type'], 'class': info['class'],
         'kind': 'resource', 'parent': None, 'collection': None, 'action': None, 'in_release': False,
         'mark': mark_not_judged, 'decision': 'not-in-release',
         'reason': 'not changed by this release; no baseline was recorded, so it is not judged',
         '_info': info, '_ev': {}, '_live': None}
    want = dict((k.lower(), v) for k, v in base.items()).get(rid.lower())
    if want:
        st, live = arm_get(rid, api_version(info))
        n['_live'] = live if st == 'ok' else None
        if st == 'ok' and sha(strip(live, reg.get('read_only_fields') or [])) == want:
            n['mark'], n['reason'] = mark_unchanged, 'not changed by this release, and unchanged since it'
        elif st == 'error':
            n['mark'], n['reason'] = mark_unknown, 'a dependency that could not be read'
        else:
            n['mark'], n['reason'] = mark_other, 'a dependency another actor changed since the release'
    return n


def _held_by_policy(n):
    info = n['_info']
    if info['class'] is None:
        return 'its type %s is not in rollback-resource-classes.yaml: a rollback never guesses' % info['type']
    if info['entry'] and info['mode'] is None:
        return 'its collection %s of %s is not a registered entry collection' % (info['collection'], info['type'])
    spec = info['spec'] or {}
    if spec.get('reversal') == 'human':
        return 'reversing a %s has consequences a machine should not weigh (ROLLBACK_CONTRACT.md)' % info['type']
    if spec.get('data') and n['action'] == 'CREATED' and not info['entry']:
        return 'the release created this data-bearing resource; deleting it would delete data'
    return None


def review(ev, reg, sequence_releases=()):
    """The dependency review of one release, from a fresh live read. -> review dict (with private
    keys the reversal uses; `public()` strips them for the record)."""
    release = ev.get('release_id') or ''
    nodes = {}
    for raw in ev.get('nodes') or []:
        n = _node(raw, reg, release)
        nodes[n['id']] = n
        mark_node(n, reg, release, set(sequence_releases))
    edges = build_graph(nodes, ev, reg)
    blockers = {}
    for nid, n in nodes.items():
        held = _held_by_policy(n) if n['in_release'] else None
        if n['mark'] in (mark_other, mark_unknown):
            blockers[nid] = n['reason']
        elif held:
            blockers[nid] = held
            n['reason'] = held
    down, up, together = {}, {}, {}
    for e in edges:
        if e['kind'] == 'evaluated-together':
            together.setdefault(e['from'], set()).add(e['to'])
            together.setdefault(e['to'], set()).add(e['from'])
        else:
            down.setdefault(e['from'], set()).add(e['to'])
            up.setdefault(e['to'], set()).add(e['from'])

    def reach(start, adj):
        seen, todo = set(), [start]
        while todo:
            for x in adj.get(todo.pop(), ()):
                if x not in seen:
                    seen.add(x)
                    todo.append(x)
        return seen
    for nid, n in nodes.items():
        if not n['in_release']:
            continue
        if nid in blockers:
            n['decision'] = 'left'
            continue
        why = None
        dn, upn = reach(nid, down), reach(nid, up)
        for b in sorted(blockers):
            short = nodes[b]['name']
            if b in dn:
                why = 'it depends on %s, which is not reversible (%s)' % (short, blockers[b])
            elif b in upn:
                why = '%s depends on it, and %s is not reversible (%s)' % (short, short, blockers[b])
            elif b in together.get(nid, ()):
                why = ('it is evaluated together with %s in %s of %s (priority order), and %s is not '
                       'reversible (%s)' % (short, n['collection'], n['parent'].rsplit('/', 1)[-1], short,
                                            blockers[b]))
            if why:
                break
        if why:
            n['decision'], n['reason'] = 'left', why
        else:
            n['decision'] = 'reverse'
    rel = [n for n in nodes.values() if n['in_release']]
    free = [n for n in rel if n['decision'] == 'reverse']
    has_entries = any(n['kind'] == 'entry' for n in rel)
    if not blockers:
        outcome = SCOPED if has_entries else CLEAR
    elif free:
        outcome = PARTIAL
    else:
        outcome = REFUSED
    moved = others_moved(ev, nodes, reg) if not blockers else []
    basis = None
    if outcome in (SCOPED, CLEAR):
        basis = OWNED_PART if moved else UNTOUCHED
    elif outcome == PARTIAL:
        basis = OWNED_PART
    why = {CLEAR: 'nothing else changed what the release changed: the full rollback runs',
           SCOPED: 'only the product\'s own entries in the shared resources are reversed%s' % (
               '; other products moved their own entries since (%s), which is theirs and is left'
               % ', '.join(moved[:5]) if moved else ''),
           PARTIAL: 'a FULL rollback is refused: %d of %d nodes the release changed are cross-edited '
                    'or tied to one that is; the %d independent of them are reversed and the rest '
                    'left for a human decision' % (len(rel) - len(free), len(rel), len(free)),
           REFUSED: 'no rollback: every node the release changed is cross-edited or tied to one that '
                    'is; nothing is touched and a human decides'}[outcome]
    for n in rel:
        if n['decision'] == 'reverse':
            n['reason'] = n['reason'] or 'independent of every cross-edit'
    rv = {'outcome': outcome, 'rollback_state': HUMAN if blockers else AUTO, 'basis': basis,
          'full_rollback': 'eligible' if not blockers else 'refused', 'why': why,
          'nodes': [], 'edges': edges, 'mermaid': '', 'reversed': [],
          'not_reversed': [{'id': n['id'], 'reason': n['reason']} for n in rel if n['decision'] == 'left'],
          'others_untouched': [], 'graph_path': None, '_nodes': nodes, '_release': release}
    refresh(rv)
    return rv


def others_moved(ev, nodes, reg):
    """Other products' entries that changed since the deploy (from `others_at_deploy`)."""
    base = ev.get('others_at_deploy') or {}
    out = []
    parents = {}
    for n in nodes.values():
        if n['in_release'] and n['kind'] == 'entry':
            parents[n['parent']] = n['_info']
    for p, info in parents.items():
        snap, _problem = list_entries(p, info)
        for rid, body in ((snap or {}).get('entries') or {}).items():
            want = dict((k.lower(), v) for k, v in base.items()).get(rid.lower())
            if want and sha(body) != want:
                out.append(rid.rsplit('/', 1)[-1])
    return sorted(out)


def refresh(rv):
    """Rebuild the public node list and the Mermaid text from the private nodes."""
    nodes = rv['_nodes']
    rv['nodes'] = [dict((k, v) for k, v in n.items() if not k.startswith('_'))
                   for n in sorted(nodes.values(), key=lambda x: (not x['in_release'], x['id'].lower()))]
    rv['mermaid'] = mermaid(rv['nodes'], rv['edges'])


LABEL = {mark_release: 'changed by this release', mark_other: 'changed by other', mark_unknown: 'unknown',
         mark_unchanged: 'unchanged', mark_not_judged: 'not judged'}


def mermaid(nodes, edges):
    ids = dict((n['id'], 'n%d' % i) for i, n in enumerate(nodes))
    out = ['graph LR']
    for n in nodes:
        dec = {'reversed': 'rolled back', 'reverse': 'to roll back', 'left': 'LEFT',
               'not-in-release': 'not in release'}.get(n.get('decision') or '', n.get('decision') or '')
        label = '%s<br/>%s<br/>%s%s' % (n['name'], n['type'], LABEL.get(n['mark'], n['mark']),
                                        (' -- ' + dec) if dec else '')
        cls = {mark_other: 'other', mark_unknown: 'other'}.get(n['mark'],
                                                               'left' if n.get('decision') == 'left' else
                                                               'done' if n.get('decision') == 'reversed' else 'plain')
        out.append('  %s["%s"]:::%s' % (ids[n['id']], label.replace('"', "'"), cls))
    for e in edges:
        if e['from'] in ids and e['to'] in ids:
            arrow = '<-.->' if e['kind'] == 'evaluated-together' else '-->'
            out.append('  %s %s|%s| %s' % (ids[e['from']], arrow, e['kind'], ids[e['to']]))
    out += ['  classDef other fill:#f8d7da,stroke:#842029,color:#000',
            '  classDef left fill:#fff3cd,stroke:#997404,color:#000',
            '  classDef done fill:#d1e7dd,stroke:#0f5132,color:#000',
            '  classDef plain fill:#e9ecef,stroke:#495057,color:#000']
    return '\n'.join(out)


def public(rv):
    return dict((k, v) for k, v in rv.items() if not k.startswith('_'))


def single(adapter, target, why):
    """A one-node review for an App Service / Container App step changed outside the kit: the
    resource is STABLE and is the whole release, so a full rollback is refused and nothing is left
    to reverse on its own."""
    n = {'id': target, 'name': target.rsplit('/', 1)[-1], 'type': {'appservice': 'Microsoft.Web/sites',
                                                                  'containerapp': 'Microsoft.App/containerApps'}.get(adapter, adapter),
         'class': STABLE, 'kind': 'resource', 'parent': None, 'collection': None, 'action': 'MODIFIED',
         'in_release': True, 'mark': mark_other, 'decision': 'left', 'reason': why}
    return {'outcome': REFUSED, 'rollback_state': HUMAN, 'basis': None, 'full_rollback': 'refused',
            'why': 'no rollback: the one resource the release changed was changed by another actor',
            'nodes': [n], 'edges': [], 'mermaid': mermaid([n], []), 'reversed': [],
            'not_reversed': [{'id': target, 'reason': why}], 'others_untouched': [], 'graph_path': None}


# ----------------------------------------------------------------------------- the reversal
def _order(rv):
    """Dependents first: a node is reversed before anything it depends on."""
    nodes = rv['_nodes']
    todo = [n['id'] for n in nodes.values() if n['decision'] == 'reverse']
    down = {}
    for e in rv['edges']:
        down.setdefault(e['from'], set()).add(e['to'])
    order, placed = [], set()
    while todo:
        progressed = False
        for nid in sorted(todo, key=str.lower):
            # nid may go once nothing still waiting depends on it
            if not any(nid in down.get(o, ()) for o in todo if o != nid):
                order.append(nid)
                placed.add(nid)
                todo.remove(nid)
                progressed = True
                break
        if not progressed:
            order += sorted(todo, key=str.lower)
            break
    return order


def reverse(rv, reg):
    """Reverse the nodes the review freed, verify each, and read every other entry back. -> result
    ('ROLLBACK_VERIFIED' | 'ROLLBACK_PARTIAL' | 'STATUS_UNTRUSTED'), with rv updated in place."""
    nodes = rv['_nodes']
    order = _order(rv)
    mine = set(n['id'].lower() for n in nodes.values() if n['in_release'])
    parents = {}
    for nid in order + [n['id'] for n in nodes.values() if n['in_release']]:
        n = nodes[nid]
        if n['kind'] == 'entry':
            parents.setdefault(n['parent'], n['_info'])
    before = {}
    trouble = []
    for p, info in parents.items():
        snap, problem = list_entries(p, info)
        if problem:
            trouble.append(problem)
        before[p] = snap
    fields = reg.get('read_only_fields') or []
    inline = {}
    for nid in order:
        n = nodes[nid]
        info, ev = n['_info'], n['_ev']
        if info['mode'] == 'inline':
            inline.setdefault(n['parent'], []).append(n)
            continue
        if n['action'] == 'CREATED':
            ok, err = arm_delete(nid, api_version(info))
            op = 'delete'
        else:
            ok, err = arm_put(nid, strip(ev.get('prior') or {}, fields), api_version(info))
            op = 'restore prior'
        rv['reversed'].append({'id': nid, 'op': op, 'applied': ok, 'verified': False,
                               'detail': '' if ok else (err or '')[:300]})
    for p, members in inline.items():
        info = members[0]['_info']
        st, body = arm_get(p, api_version(info))
        if st != 'ok':
            for n in members:
                rv['reversed'].append({'id': n['id'], 'op': 'inline', 'applied': False, 'verified': False,
                                       'detail': 'the parent could not be read: %s' % body})
            continue
        body = strip(body, fields)
        for n in members:
            path = info['spec']['inline_collections'][n['collection']]
            arr = [e for e in (_get_path(body, path) or []) if not (isinstance(e, dict) and e.get('name') == n['name'])]
            if n['action'] != 'CREATED':
                arr.append(copy.deepcopy(n['_ev'].get('prior')))
            _set_path(body, path, arr)
        ok, err = arm_put(p, body, api_version(info))
        for n in members:
            rv['reversed'].append({'id': n['id'], 'op': 'delete (inline)' if n['action'] == 'CREATED'
                                   else 'restore prior (inline)', 'applied': ok, 'verified': False,
                                   'detail': '' if ok else (err or '')[:300]})
    for r in rv['reversed']:
        n = nodes[r['id']]
        n['decision'] = 'reversed'
        st, live = read_node(n, reg)
        if n['action'] == 'CREATED':
            r['verified'] = st == 'absent'
            r['live'] = 'absent' if st == 'absent' else ('unreadable' if st == 'error' else 'still present')
        else:
            r['verified'] = st == 'ok' and norm(reg, live) == norm(reg, n['_ev'].get('prior') or {})
            r['live'] = 'prior' if r['verified'] else ('unreadable' if st == 'error' else 'differs')
        if st == 'error':
            trouble.append('%s could not be read back' % r['id'])
    for p, info in parents.items():
        snap, problem = list_entries(p, info)
        if problem or before.get(p) is None:
            trouble.append(problem or 'the entries of %s could not be read before the reversal' % p)
            rv['others_untouched'].append({'id': p, 'owner': 'shared parent', 'identical': False})
            continue
        for rid, body in sorted(before[p]['entries'].items()):
            if rid.lower() in mine and nodes.get(rid, {}).get('decision') == 'reversed':
                continue
            owner = 'the product (left)' if rid.lower() in mine else 'other'
            rv['others_untouched'].append({'id': rid, 'owner': owner,
                                           'identical': canon(body) == canon(snap['entries'].get(rid))})
        rv['others_untouched'].append({'id': p, 'owner': 'shared parent',
                                       'identical': parent_view(before[p], info, mine) ==
                                       parent_view(snap, info, mine)})
    refresh(rv)
    good = all(r['applied'] and r['verified'] for r in rv['reversed']) and \
        all(o['identical'] for o in rv['others_untouched']) and not trouble
    if trouble:
        rv['problems'] = trouble
    if not good:
        return 'STATUS_UNTRUSTED' if trouble else 'ROLLBACK_PARTIAL'
    if rv['outcome'] in (SCOPED, CLEAR):
        rv['full_rollback'] = 'performed'
        return 'ROLLBACK_VERIFIED'
    return 'ROLLBACK_PARTIAL'


def summary(rv, label):
    """Markdown for the run summary: the outcome, every node with its reason, and the graph."""
    out = ['', '#### %s -- dependency review: `%s`' % (label, rv['outcome']), '',
           '%s. Full rollback: **%s**. rollback_state: `%s`.' % (rv['why'], rv['full_rollback'],
                                                                rv['rollback_state']), '',
           '| node | class | mark | decision | reason |', '|---|---|---|---|---|']
    for n in rv['nodes']:
        out.append('| `%s` | %s | %s | %s | %s |' % (n['name'], n['class'] or 'unregistered',
                                                      LABEL.get(n['mark'], n['mark']), n.get('decision') or '',
                                                      (n.get('reason') or '').replace('|', '/')))
    if rv.get('others_untouched'):
        bad = [o['id'] for o in rv['others_untouched'] if not o['identical']]
        out += ['', 'Other entries read back: %d, byte-identical: %s.' % (
            len(rv['others_untouched']), 'all' if not bad else 'NOT ' + ', '.join(bad))]
    out += ['', '```mermaid', rv['mermaid'], '```']
    return out


def self_test():
    reg = load_registry()
    fails = []
    for t, want in (('Microsoft.Network/networkSecurityGroups', SHARED), ('Microsoft.Web/sites', STABLE),
                    ('Microsoft.Sql/servers/databases', STABLE), ('Microsoft.Example/unknown', None)):
        if classify(reg, t) != want:
            fails.append('%s classed %r' % (t, classify(reg, t)))
    rid = '/subscriptions/0/resourceGroups/g/providers/Microsoft.Cdn/profiles/p/afdEndpoints/e/routes/r'
    info = resolve(reg, rid)
    if not (info['entry'] and info['collection'] == 'afdEndpoints/*/routes' and info['mode'] == 'child'
            and info['parent'].endswith('/profiles/p')):
        fails.append('a Front Door route did not resolve as a child entry of its profile: %r' % info)
    info = resolve(reg, '/subscriptions/0/resourceGroups/g/providers/Microsoft.Network/applicationGateways/a/httpListeners/l')
    if info['mode'] != 'inline':
        fails.append('a gateway listener did not resolve as an inline entry')
    if set(v.get('class') for v in reg['types'].values()) != {SHARED, STABLE}:
        fails.append('a registry type has neither class')
    for f in fails:
        print('SELF-TEST FAILED: ' + f)
    if fails:
        return 2
    print('rollback_dependencies self-test ok: the registry classes every type as SHARED_MULTI_CONFIG '
          'or STABLE, entries resolve to their shared parent, an unregistered type is not guessed. The '
          'full proof is tests/prove_rollback_dependencies.py.')
    return 0


if __name__ == '__main__':
    if sys.argv[1:] == ['--self-test']:
        sys.exit(self_test())
    print('usage: rollback_dependencies.py --self-test (the engine is imported by rollback_sequence.py)')
    sys.exit(2)
