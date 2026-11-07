#!/usr/bin/env python3
"""Ticket governance rules the trackers share (KDEC-043 PROPOSED, lane tickets, 2026-11-06).

FOUR RULES, ONE MODULE. Every tracker adapter (Jira, Azure DevOps, GitHub Issues, Freshservice) and
both write paths (scripts/reconcile_tickets.py, scripts/ticket_submit.py) call these. Nothing here
reads or writes a tracker except through the adapter it is handed.

1  THE CORRELATION KEY IS NEVER TRUNCATED AS IDENTITY
       The full 32-hex key lives in a governed place: the tracker's stamp field, the stamp line of the
       kit's machine-owned block (`secure-cicd-kit-cluster: <key>`), or, on a ticket a person made and
       a reviewer linked, a link line (`secure-cicd-kit-correlation-key: <key>`) the kit appends in its
       own block. A LABEL IS ONLY A SEARCH AID. GitHub cuts nothing for us: a label over 50 characters
       is refused there, so the kit writes a deterministic short form (search_label) and says so. A label
       hit is VERIFIED against the full key in the body or the field before it counts:
           verified     the body or the field carries this exact key            -> exact
           collision    the body or the field carries a DIFFERENT full key      -> CORRELATION_LABEL_COLLISION:
                        a search ambiguity, for a person; the full key decides
           unverified   no full key anywhere on the ticket                       -> CORRELATION_LABEL_UNVERIFIED:
                        a person confirms (link) or rejects (new)
2  A `via` LABEL IS A CLAIM
       `<stamp>-via-<integration>` says which integration wrote a ticket. It proves nothing by itself.
       Provenance is the AUTHENTICATED identity the kit's credential resolved to at run start, compared with
       the tracker's own record of who made the write (the creator, or the activity's actor), and with the
       identity registered for the claimed integration (KIT_INTEGRATION_IDENTITIES, `name=identity,...`).
           PROVENANCE_ESTABLISHED      all three agree
           PROVENANCE_MISMATCH         any two disagree: flagged on the ticket and sent to a person
           PROVENANCE_NOT_ESTABLISHED  a side could not be read: said so, never assumed
3  `area-unresolved` IS A TRIAGE STATE, NOT A DEAD END
       A finding the routing could not give an owning area (routing is configured, no rule and no default
       matched, so it fell to the kit default) is created with `<stamp>-area-unresolved` and `<stamp>-triage`,
       an OWNER ROLE (routing `unresolved.owner_role`, default `security-triage`) and a DEADLINE (routing
       `unresolved.deadline_days`, kit default 5). Past the deadline it is AREA_UNRESOLVED_OVERDUE in every
       reconcile run's output, unasked, and the run exits 1 (a decision is owed). It leaves the state when a
       later run's routing resolves it.
4  A MULTICLOUD FINDING IS ONE IDENTITY WITH CHILD OBLIGATIONS
       One parent ticket, keyed once, and one child obligation per cloud asset (Azure, AWS), each with its own
       owner role and its own closure. A child closes only by the kit's rescan or a second person's
       verification (the same closure template, on the child). THE PARENT CLOSES ONLY WHEN EVERY CHILD IS
       CLOSED-VERIFIED; a parent closure asked for earlier is CHILD_OBLIGATION_OPEN, and a child whose state
       cannot be read keeps the parent open.
"""
import datetime
import hashlib
import re
import sys

STAMP_PREFIX = 'secure-cicd-kit-cluster:'
LINK_PREFIX = 'secure-cicd-kit-correlation-key:'
FULL_KEY_RE = re.compile(r'^[0-9a-f]{32}$')

# ── 1: the correlation key ─────────────────────────────────────────────────────────────
LABEL_VERIFIED = 'verified'
CORRELATION_LABEL_UNVERIFIED = 'CORRELATION_LABEL_UNVERIFIED'
CORRELATION_LABEL_COLLISION = 'CORRELATION_LABEL_COLLISION'

# Mutation switch for tests/prove_ticket_governance.py M1: True is correct. False lets a label hit count as
# exact without the body check -- the defect this rule exists to stop.
verify_label_hits = True


def _s(v):
    return str(v or '').strip()


def is_full_key(value):
    return bool(FULL_KEY_RE.match(_s(value).lower()))


def full_keys(text):
    """-> the set of FULL correlation keys a ticket's text carries on a stamp line or a link line. A value
    that is not 32 hex characters is not a key (a cut label copied into a body proves nothing)."""
    out = set()
    for line in str(text or '').split('\n'):
        s = line.strip()
        for prefix in (STAMP_PREFIX, LINK_PREFIX):
            if s.startswith(prefix):
                v = s[len(prefix):].strip().strip('`').lower()
                if is_full_key(v):
                    out.add(v)
    return out


def ticket_keys(ticket):
    """-> every full key a tracker ticket (an intake row: stamp, _text) carries in a governed place."""
    keys = full_keys((ticket or {}).get('_text') or (ticket or {}).get('body') or '')
    st = _s((ticket or {}).get('stamp')).lower()
    if is_full_key(st):
        keys.add(st)
    return keys


def ck_label(stamp, ck):
    return '%s-ck-%s' % (stamp or 'secure-cicd-kit', ck)


def search_label(name, limit):
    """-> `name`, or, past `limit` characters, a DETERMINISTIC short form: the head of the name, a dash and 8
    hex of its sha256. A search aid only -- never compared as identity (rule 1). Two different long names
    therefore never share a short form by sharing a prefix."""
    name = str(name)
    if limit is None or len(name) <= int(limit):
        return name
    tail = hashlib.sha256(name.encode('utf-8')).hexdigest()[:8]
    return '%s-%s' % (name[:int(limit) - 9], tail)


def verify_label_hit(ticket, ck):
    """-> (verdict, other_keys). A label hit counts only when the ticket's governed key is this key."""
    keys = ticket_keys(ticket)
    if not verify_label_hits:
        return LABEL_VERIFIED, set()
    if _s(ck).lower() in keys:
        return LABEL_VERIFIED, set()
    if keys:
        return CORRELATION_LABEL_COLLISION, keys
    return CORRELATION_LABEL_UNVERIFIED, set()


def link_keys(text):
    """-> the full keys on LINK lines only (the ones the kit wrote on a person's ticket)."""
    out = set()
    for line in str(text or '').split('\n'):
        s = line.strip()
        if s.startswith(LINK_PREFIX):
            v = s[len(LINK_PREFIX):].strip().strip('`').lower()
            if is_full_key(v):
                out.add(v)
    return out


def link_block(keys):
    """The kit's machine-owned block on a ticket a PERSON made and a reviewer linked: one link line per
    full key, between the kit's delimiters. Spliced (replaced, or appended when absent), never written over
    the person's text."""
    import reconcile_tickets as rt
    keys = sorted(set(k for k in keys if is_full_key(k)))
    return '\n'.join([rt.BLOCK_OPEN, 'Linked to the secure-cicd-kit finding(s) below by a finalized review.', ''] +
                     ['%s %s' % (LINK_PREFIX, k) for k in keys] + [rt.BLOCK_CLOSE])


def write_link(backend, ref, ck):
    """Read the description, splice the link block with this key added, write it back. -> (ok, detail).
    A description that cannot be read is not written (the reconciler's rule): the link is owed."""
    desc, ok, detail = backend.read_description(ref)
    if not ok:
        return False, 'the description of %s could not be read (%s): the link line is owed' % (ref, detail)
    have = link_keys(backend.description_text(desc))
    if _s(ck).lower() in have:
        return True, 'the link line is already there'
    new, _found = backend.splice_description(desc, link_block(have | {_s(ck).lower()}))
    return backend.write_description(ref, new, desc)


# ── 2: provenance ───────────────────────────────────────────────────────────────────────
PROVENANCE_ESTABLISHED = 'PROVENANCE_ESTABLISHED'
PROVENANCE_MISMATCH = 'PROVENANCE_MISMATCH'
PROVENANCE_NOT_ESTABLISHED = 'PROVENANCE_NOT_ESTABLISHED'

# Mutation switch (M2): True is correct. False trusts the via label and skips the comparison.
compare_provenance = True


def slug(v):
    return re.sub(r'[^a-z0-9._-]+', '-', _s(v).lower()).strip('-')[:60]


def via_label(stamp, via):
    return '%s-via-%s' % (stamp or 'secure-cicd-kit', slug(via)) if slug(via) else ''


def integrations_from(text):
    """KIT_INTEGRATION_IDENTITIES `name=identity,name=identity` -> {name: identity}. Roles and ids only;
    the kit names no person and no employer."""
    out = {}
    for part in str(text or '').split(','):
        if '=' in part:
            k, v = part.split('=', 1)
            if slug(k) and _s(v):
                out[slug(k)] = _s(v)
    return out


def provenance(claimed_via, authenticated, write_actor, integrations):
    """-> {state, claimed_via, authenticated, write_actor, expected, reasons}. Never ESTABLISHED on a side
    that was not read."""
    claimed = slug(claimed_via)
    rec = {'claimed_via': claimed or None, 'authenticated': _s(authenticated) or None,
           'write_actor': _s(write_actor) or None, 'expected': None, 'reasons': []}
    if not compare_provenance:
        rec['state'] = PROVENANCE_ESTABLISHED
        return rec
    if not rec['authenticated']:
        rec['reasons'].append('the identity the kit\'s credential resolved to was not established at run start')
    if not rec['write_actor']:
        rec['reasons'].append('the tracker\'s record of who made the write could not be read')
    if rec['authenticated'] and rec['write_actor'] and rec['authenticated'] != rec['write_actor']:
        rec['reasons'].append('the tracker records the write by %s, and the kit authenticated as %s'
                              % (rec['write_actor'], rec['authenticated']))
        rec['state'] = PROVENANCE_MISMATCH
    if claimed:
        exp = (integrations or {}).get(claimed)
        rec['expected'] = exp
        if not exp:
            rec['reasons'].append('the via claim %r has no registered identity (KIT_INTEGRATION_IDENTITIES)'
                                  % claimed)
        elif rec['authenticated'] and exp != rec['authenticated']:
            rec['reasons'].append('the via claim %r is registered as %s, and the kit authenticated as %s'
                                  % (claimed, exp, rec['authenticated']))
            rec['state'] = PROVENANCE_MISMATCH
        elif rec['write_actor'] and exp != rec['write_actor']:
            rec['reasons'].append('the via claim %r is registered as %s, and the tracker records %s'
                                  % (claimed, exp, rec['write_actor']))
            rec['state'] = PROVENANCE_MISMATCH
    if 'state' not in rec:
        rec['state'] = PROVENANCE_ESTABLISHED if not rec['reasons'] else PROVENANCE_NOT_ESTABLISHED
    return rec


# ── 3: area-unresolved ──────────────────────────────────────────────────────────────────
AREA_UNRESOLVED = 'AREA_UNRESOLVED'
AREA_UNRESOLVED_OVERDUE = 'AREA_UNRESOLVED_OVERDUE'
AREA_RESOLVED = 'AREA_RESOLVED'
DEFAULT_AREA_OWNER_ROLE = 'security-triage'
DEFAULT_AREA_DEADLINE_DAYS = 5

# Mutation switch (M3): True is correct. False lets an overdue unresolved area pass silently.
surface_overdue_area = True


def area_resolution(route, routing):
    """-> None when the routing gave this finding an owning area, else {owner_role, deadline_days}. With no
    routing configured the kit default IS the owner's chosen area (one project per repository)."""
    routing = routing if isinstance(routing, dict) else {}
    configured = bool(routing.get('rules') or routing.get('default'))
    if not configured or not isinstance(route, dict) or route.get('rule') != 'kit-default':
        return None
    un = routing.get('unresolved') if isinstance(routing.get('unresolved'), dict) else {}
    days = un.get('deadline_days')
    return {'owner_role': _s(un.get('owner_role')) or DEFAULT_AREA_OWNER_ROLE,
            'deadline_days': int(days) if isinstance(days, int) and not isinstance(days, bool) and days > 0
            else DEFAULT_AREA_DEADLINE_DAYS}


def area_record(res, today):
    td = datetime.date.fromisoformat(today) if today else datetime.date.today()
    return {'state': AREA_UNRESOLVED, 'owner_role': res['owner_role'], 'since': td.isoformat(),
            'due': (td + datetime.timedelta(days=res['deadline_days'])).isoformat()}


def area_labels(stamp, rec):
    p = stamp or 'secure-cicd-kit'
    return ['%s-area-unresolved' % p, '%s-triage' % p, '%s-area-owner-%s' % (p, slug(rec['owner_role'])),
            '%s-area-due-%s' % (p, rec['due'])]


def area_overdue(ledger, today):
    """-> every ledger entry still AREA_UNRESOLVED, each with `overdue` (True past its due date). Over the
    WHOLE ledger, like the past-due deferral sweep: a finding that went quiet keeps its triage debt."""
    out = []
    try:
        td = datetime.date.fromisoformat(today) if today else None
    except ValueError:
        td = None
    for key in sorted(ledger or {}):
        e = (ledger or {}).get(key)
        a = e.get('area') if isinstance(e, dict) else None
        if not isinstance(a, dict) or a.get('state') != AREA_UNRESOLVED:
            continue
        try:
            due = datetime.date.fromisoformat(str(a.get('due')))
        except ValueError:
            due = None
        late = bool(td and due and td > due) if surface_overdue_area else False
        out.append({'cluster_key': key, 'ref': e.get('ref'), 'key': e.get('key'), 'owner_role': a.get('owner_role'),
                    'due': a.get('due'), 'overdue': late,
                    'state': AREA_UNRESOLVED_OVERDUE if late else AREA_UNRESOLVED,
                    'overdue_days': (td - due).days if late else 0})
    return out


# ── 4: multicloud child obligations ─────────────────────────────────────────────────────
CHILD_OBLIGATION_OPEN = 'CHILD_OBLIGATION_OPEN'
CLOUDS = ('azure', 'aws')

# Mutation switch (M4): True is correct. False lets a parent close with a child still open.
hold_parent_for_children = True


def child_label(stamp, child_id, ref):
    return '%s-child-%s-%s' % (stamp or 'secure-cicd-kit', slug(child_id), _s(ref))


def obligation_label(stamp, child_id):
    return '%s-obligation-%s' % (stamp or 'secure-cicd-kit', slug(child_id))


def parent_label(stamp, ref):
    return '%s-parent-%s' % (stamp or 'secure-cicd-kit', _s(ref))


def owner_label(stamp, role):
    return '%s-owner-%s' % (stamp or 'secure-cicd-kit', slug(role))


def expected_label(stamp, n):
    return '%s-obligations-%d' % (stamp or 'secure-cicd-kit', int(n))


def expected_children(labels, stamp):
    """-> how many child obligations the parent was CREATED with (`<stamp>-obligations-<n>`, set at creation), or 0."""
    pre = '%s-obligations-' % (stamp or 'secure-cicd-kit')
    for x in labels or []:
        if str(x).startswith(pre) and str(x)[len(pre):].isdigit():
            return int(str(x)[len(pre):])
    return 0


def children_of(labels, stamp):
    """-> [(child_id, ref)] from a parent's `<stamp>-child-<id>-<ref>` labels (the tracker is the record)."""
    pre = '%s-child-' % (stamp or 'secure-cicd-kit')
    out = []
    for x in labels or []:
        x = str(x)
        if x.startswith(pre):
            cid, _sep, ref = x[len(pre):].rpartition('-')
            if cid and ref:
                out.append((cid, ref))
    return sorted(set(out))


def parent_of(labels, stamp):
    pre = '%s-parent-' % (stamp or 'secure-cicd-kit')
    for x in labels or []:
        if str(x).startswith(pre):
            return str(x)[len(pre):]
    return ''


def parent_may_close(backend, parent_labels, stamp):
    """-> (ok, open_children, detail). Every child must carry `<stamp>-verified` -- written only by a rescan's or a
    second person's verification. A child whose labels cannot be read keeps the parent open."""
    kids = children_of(parent_labels, stamp)
    want = expected_children(parent_labels, stamp)
    if not kids and not want:
        return True, [], 'no child obligations'
    open_ = []
    if len(set(c for c, _r in kids)) < want:
        # A child that was never created is an obligation nobody can close -- so the parent cannot close either.
        open_.append({'obligation': 'missing', 'ref': None, 'readable': True,
                      'detail': '%d of %d child obligation(s) exist' % (len(set(c for c, _r in kids)), want)})
    for cid, ref in kids:
        labels, ok, _d = backend.labels_of(ref)
        if not ok or '%s-verified' % (stamp or 'secure-cicd-kit') not in (labels or []):
            open_.append({'obligation': cid, 'ref': ref, 'readable': bool(ok)})
    if open_ and hold_parent_for_children:
        return False, open_, ('%s: %d of %d child obligation(s) are not closed-verified (%s); the parent closes '
                              'only when every child is closed by a rescan or a second person'
                              % (CHILD_OBLIGATION_OPEN, len(open_), len(kids),
                                 ', '.join('%s %s' % (o['obligation'], o['ref']) for o in open_)))
    return True, [], 'every child obligation is closed-verified (%d)' % len(kids)


def validate_obligations(obligations, asset_key_fn, where):
    """-> '' or why the obligations are not one multicloud identity's children. `asset_key_fn` is
    ticket_templates.asset_key."""
    if not isinstance(obligations, list) or len(obligations) < 2:
        return '%s.obligations: a multicloud finding names at least two child obligations' % where
    seen, clouds = set(), set()
    for j, o in enumerate(obligations):
        w = '%s.obligations[%d]' % (where, j)
        if not isinstance(o, dict):
            return '%s is not an object' % w
        cid, cloud = slug(o.get('id')), o.get('cloud')
        if not cid or cid in seen:
            return '%s.id %r is empty or repeated: each child has its own id' % (w, o.get('id'))
        seen.add(cid)
        if cloud not in CLOUDS:
            return '%s.cloud %r is not one of %s' % (w, cloud, ', '.join(CLOUDS))
        clouds.add(cloud)
        if not slug(o.get('owner_role')):
            return '%s.owner_role is required: each child has its own owner' % w
        want = {'azure': 'azure-resource', 'aws': 'aws-resource'}[cloud]
        if (o.get('asset') or {}).get('scheme') != want:
            return '%s.asset is not a %s asset (a %s child names one)' % (w, want, cloud)
        _k, _d, _n, bad = asset_key_fn(o.get('asset'))
        if bad:
            return '%s.asset: %s' % (w, bad)
    if len(clouds) < 2:
        return '%s.obligations name one cloud (%s); a multicloud finding has children in Azure AND AWS' % (
            where, ', '.join(sorted(clouds)))
    return ''


def _selftest():
    bad = []
    ck = 'a' * 32
    t = {'_text': '%s %s' % (STAMP_PREFIX, ck)}
    if verify_label_hit(t, ck)[0] != LABEL_VERIFIED:
        bad.append('a body stamp did not verify')
    if verify_label_hit({'_text': '%s %s' % (STAMP_PREFIX, 'b' * 32)}, ck)[0] != CORRELATION_LABEL_COLLISION:
        bad.append('a different full key was not a collision')
    if verify_label_hit({'_text': '%s %s' % (STAMP_PREFIX, ck[:31])}, ck)[0] != CORRELATION_LABEL_UNVERIFIED:
        bad.append('a cut key in a body verified')
    long_ = ck_label('secure-cicd-kit', ck)
    if len(search_label(long_, 50)) != 50 or search_label(long_, 50) == long_[:50]:
        bad.append('the short label is not the deterministic hashed form')
    if provenance('tines', 'u1', 'u1', {'tines': 'u1'})['state'] != PROVENANCE_ESTABLISHED or \
            provenance('tines', 'u1', 'u2', {'tines': 'u1'})['state'] != PROVENANCE_MISMATCH or \
            provenance('tines', None, 'u1', {'tines': 'u1'})['state'] != PROVENANCE_NOT_ESTABLISHED:
        bad.append('provenance comparison')
    for b in bad:
        sys.stderr.write('FAIL: %s\n' % b)
    if bad:
        return 2
    print('ticket_governance selftest ok: label hits verified against the full key; short labels hashed; '
          'provenance compared, never assumed.')
    return 0


if __name__ == '__main__':
    sys.exit(_selftest() if sys.argv[1:] == ['--self-test'] else 2)
