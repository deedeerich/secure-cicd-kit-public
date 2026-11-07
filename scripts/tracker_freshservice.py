#!/usr/bin/env python3
"""Freshservice as a ticket tracker: the backend and the intake adapter, search-first, to the same contract
as Jira, Azure DevOps and GitHub Issues (KDEC-043 PROPOSED, lane tickets, 2026-11-06).

THE ONE FACT THAT SHAPES THIS ADAPTER

    Freshservice's ticket update takes the tag list WHOLE: "all the tags that need to stay associated with
    the Ticket should be provided in the PUT request payload" (api.freshservice.com, Update a Ticket,
    retrieved 2026-11-06). There is no add-a-tag call and no documented precondition (no If-Match, no
    version; updated_at is a read-only timestamp). So a kit write between a person's read and save, or a
    person's save between the kit's read and write, can silently drop the other's tags. This adapter
    therefore:

      1  SETS TAGS AT CREATION. The umbrella tag, the family and every template label go in the create call.
      2  AVOIDS TAG UPDATES ON EXISTING TICKETS. By default (FRESHSERVICE_MARK_MODE=notes) a lifecycle marker on
         an existing ticket (pending-verification, sla-overdue, duplicate, ...) is a PRIVATE NOTE whose lines
         read `secure-cicd-kit-marker: <label>`. Notes are created, never replaced, so nothing a person wrote
         can be lost. A marker counts only when the note's author is the identity the kit authenticated as
         (a person cannot forge one), so with that identity unknown labels_of refuses rather than guess.
      3  WHEN TAGS MUST CHANGE (FRESHSERVICE_MARK_MODE=tags, for dashboards that filter on tags): READ, MERGE,
         WRITE, RE-READ AND VERIFY, under a PER-TICKET LOCK that serialises the kit's own writers, with a
         bounded retry. After the write it reads the ticket's ACTIVITY HISTORY: any activity since the read by
         an actor other than the kit is a concurrent edit; its tag changes are parsed and RECONCILED (a person's
         added tag is put back, a person's removed tag stays removed unless the kit is adding it now) and
         verified again. When the history cannot be read, the kit's identity is unknown, or a concurrent
         activity cannot be parsed, preservation is TAG_PRESERVATION_NOT_ESTABLISHED: a private note asks a
         person to check, and the run reports it. It never claims a preservation it cannot prove.

    The full correlation key lives in a governed custom field (FRESHSERVICE_STAMP_FIELD, a single-line text
    field a human adds once) AND in the stamp line of the machine-owned block; tags are search aids
    (KDEC-043 rule 1).

THE DOCUMENTATION THIS RELIES ON (https://api.freshservice.com/, retrieved 2026-11-06)

    VERIFIED from the page
        Basic auth with the API key as the user name and X as the password (`-u api_key:X`)
        429 with Retry-After in seconds; X-RateLimit-Total / -Remaining / -Used-CurrentRequest headers
        page from 1, per_page at most 100 (default 30), the `link` header names the next page
        GET /api/v2/tickets (only the last 30 days unless updated_since is given), GET /api/v2/tickets/[id]
        GET /api/v2/tickets/filter?query="..." (URL-encoded, at most 512 characters, 30 per page; `tag` is
            filterable; custom fields only of type Number, Checkbox, Dropdown and Date -- so the TEXT stamp
            field cannot be filtered on, and the sweep filters on the umbrella TAG and reads the field)
        POST /api/v2/tickets (201, the ticket under "ticket"; subject, description HTML, requester_id,
            status, priority, source, tags as an array of strings, custom_fields)
        PUT /api/v2/tickets/[id] (the tags array replaces the list -- see above)
        GET /api/v2/tickets/[id]/activities (actor {id, name}, content, sub_contents, created_at; the 20 most
            recent, older ones by next_page_url)
        GET /api/v2/ticket_form_fields; status 2 open, 3 pending, 4 resolved, 5 closed
    UNVERIFIED (not found on the page, or not confirmed; each is a named risk, R-29)
        POST /api/v2/tickets/[id]/notes {body, private}; GET /api/v2/tickets/[id]/conversations and its
            user_id; GET /api/v2/agents/me (the identity the key resolves to); the filter's response shape
            {"tickets": [...]} and whether it returns tags; whether the list returns description_text;
            the text of an activity's tag change (parsed by TAG_CHANGE below); priority 1-4 (low..urgent);
            source 2; the ticket_form_fields shape {"ticket_fields": [{name, field_type}]} and the type name
            `custom_text`; whether a tag has a length limit; whether creation appears as an activity
"""
import base64
import datetime
import html
import os
import re
import sys
import threading
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import reconcile_tickets as rt  # noqa: E402
import ticket_intake as ti  # noqa: E402

DOCS = 'https://api.freshservice.com/ (retrieved 2026-11-06)'
UNVERIFIED = ('notes endpoint', 'conversations endpoint and user_id', 'agents/me', 'filter response shape and tags',
              'list description_text', 'activity tag-change text', 'priority numbering', 'source value',
              'ticket_form_fields shape', 'tag length limit', 'creation activity')

STATUS_OPEN, STATUS_PENDING, STATUS_RESOLVED, STATUS_CLOSED = 2, 3, 4, 5
FILTER_PAGE = 30
LIST_PAGE = 100
MAX_PAGES = 100
FILTER_MAX_CHARS = 512
MARKER_PREFIX = 'secure-cicd-kit-marker:'
MARK_MODES = ('notes', 'tags')
PRIORITY_BY_SEVERITY = {'critical': 4, 'high': 3, 'medium': 2, 'moderate': 2, 'low': 1, 'info': 1}

TAG_PRESERVATION_ESTABLISHED = 'TAG_PRESERVATION_ESTABLISHED'
TAG_PRESERVATION_NOT_ESTABLISHED = 'TAG_PRESERVATION_NOT_ESTABLISHED'
TICKET_WRITE_LOCK_HELD = 'TICKET_WRITE_LOCK_HELD'

# Mutation switches for tests/prove_freshservice_tracker.py; True is correct for each.
verify_after_write = True          # M-F1: the re-read after a tag write
reconcile_from_history = True      # M-F2: the activity-history reconcile of a concurrent edit
lock_per_ticket = True             # M-F3: the per-ticket writer lock
markers_need_kit_author = True     # M-F4: a marker note counts only when the kit wrote it

_sleep = time.sleep
LOCK_WAIT_SECONDS = 30
LOCK_STALE_SECONDS = 600


# ═════════════════════════════════════════════════════════════════════════════════════
# THE PER-TICKET WRITER LOCK
# ═════════════════════════════════════════════════════════════════════════════════════

class TicketLocks(object):
    """Serialises the kit's own writers per ticket: an in-process lock per ticket, and -- when a lock directory
    is configured (FRESHSERVICE_LOCK_DIR, e.g. a path every writer on one host shares) -- an exclusive lock file
    per ticket. Across hosts the reusable workflows' concurrency group `kit-ticket-writes-<repository>` already
    makes one writer per repository; two repositories writing ONE ticket is the residual (R-30)."""

    def __init__(self, lock_dir=''):
        self.lock_dir = lock_dir or ''
        self._guard = threading.Lock()
        self._locks = {}
        self.held = []

    def _thread_lock(self, ref):
        with self._guard:
            return self._locks.setdefault(str(ref), threading.Lock())

    def acquire(self, ref, wait=LOCK_WAIT_SECONDS):
        """-> (ok, detail). Bounded: never waits longer than `wait` seconds."""
        if not lock_per_ticket:
            return True, 'no lock (mutant)'
        lk = self._thread_lock(ref)
        if not lk.acquire(timeout=max(0.0, float(wait))):
            return False, '%s: another kit writer in this run holds ticket %s' % (TICKET_WRITE_LOCK_HELD, ref)
        if not self.lock_dir:
            self.held.append(str(ref))
            return True, 'in-process lock'
        path = os.path.join(self.lock_dir, 'freshservice-ticket-%s.lock' % re.sub(r'[^0-9A-Za-z_-]', '_', str(ref)))
        deadline = time.time() + max(0.0, float(wait))
        while True:
            try:
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(fd, ('%d %s\n' % (os.getpid(), datetime.datetime.utcnow().isoformat())).encode('ascii'))
                os.close(fd)
                self.held.append(str(ref))
                return True, 'lock file %s' % os.path.basename(path)
            except FileExistsError:
                try:
                    age = time.time() - os.path.getmtime(path)
                except OSError:
                    age = 0
                if age > LOCK_STALE_SECONDS:
                    try:
                        os.remove(path)
                    except OSError:
                        pass
                    continue
                if time.time() >= deadline:
                    lk.release()
                    return False, ('%s: another kit writer holds ticket %s (lock file %s); this write is owed to '
                                   'the next run' % (TICKET_WRITE_LOCK_HELD, ref, os.path.basename(path)))
                _sleep(0.2)

    def release(self, ref):
        if not lock_per_ticket:
            return
        if self.lock_dir:
            path = os.path.join(self.lock_dir, 'freshservice-ticket-%s.lock' % re.sub(r'[^0-9A-Za-z_-]', '_', str(ref)))
            try:
                os.remove(path)
            except OSError:
                pass
        try:
            self._thread_lock(ref).release()
        except RuntimeError:
            pass


# ═════════════════════════════════════════════════════════════════════════════════════
# THE ACTIVITY HISTORY: a concurrent edit, and the tags it changed
# ═════════════════════════════════════════════════════════════════════════════════════

# UNVERIFIED: the documentation shows `content` and `sub_contents` but not the words of a tag change. The kit
# reads "added"/"removed" followed by quoted tag names, in either field; anything else that mentions tags is
# unparseable, and unparseable is NOT_ESTABLISHED, never "no change".
TAG_WORD = re.compile(r'(?i)\btags?\b')
TAG_TOKEN = re.compile(r"(?i)\b(added|removed)\b|'([^']*)'")


def parse_tag_changes(activity):
    """-> (added, removed, touches_tags, parsed)."""
    texts = [str(activity.get('content') or '')] + [str(x) for x in activity.get('sub_contents') or []]
    added, removed, touches, parsed = set(), set(), False, True
    for t in texts:
        if not TAG_WORD.search(t):
            continue
        touches = True
        verb, got = None, False
        for m in TAG_TOKEN.finditer(t):
            if m.group(1):
                verb = m.group(1).lower()
            elif verb and m.group(2) is not None:
                (added if verb == 'added' else removed).add(m.group(2))
                got = True
        if not got:
            parsed = False
    return added, removed, touches, parsed


# ═════════════════════════════════════════════════════════════════════════════════════
# THE BACKEND
# ═════════════════════════════════════════════════════════════════════════════════════

def _html_body(text):
    return '<pre>%s</pre>' % html.escape(str(text or ''))


class Freshservice(rt.HttpBackend):
    """Freshservice tickets (helpdesk), to the reconciler's backend contract."""

    name = 'freshservice'

    def __init__(self, host, api_key, stamp_field, requester_id, calibration='', stamp_label='', workspace_id='',
                 mark_mode='notes', tag_retries=2, lock_dir='', retry_ceiling=0, create_ceiling=None, source=2,
                 status_done=STATUS_CLOSED):
        self.host = (host or '').rstrip('/')
        self.stamp_field = stamp_field or ''
        self.requester_id = str(requester_id or '').strip()
        self.calibration = str(calibration or '').strip()
        self.stamp_label = stamp_label or rt.DEFAULT_STAMP_LABEL
        self.workspace_id = str(workspace_id or '').strip()
        self.mark_mode = mark_mode if mark_mode in MARK_MODES else 'notes'
        self.markers_outside_tags = self.mark_mode == 'notes'
        self.tag_retries = max(0, int(tag_retries or 0))
        self.locks = TicketLocks(lock_dir)
        self.create_ceiling = create_ceiling
        self.source = int(source or 2)
        self.status_done = int(status_done or STATUS_CLOSED)
        self.identity = None
        self.identity_detail = 'not read yet'
        self.preservation = []        # every tag write's outcome, for the run record
        self._auth = base64.b64encode(('%s:X' % (api_key or '')).encode('utf-8')).decode('ascii')
        self._init_http(retry_ceiling)

    def _headers(self):
        return [('Accept', 'application/json'), ('Authorization', 'Basic %s' % self._auth)]

    def _req(self, method, path, payload=None):
        return self._http(method, self.host + path, payload)

    # ── shapes ──────────────────────────────────────────────────────────────────────────
    def _ticket(self, ref):
        doc, status, err = self._req('GET', '/api/v2/tickets/%s' % ref)
        t = (doc or {}).get('ticket') if isinstance(doc, dict) else None
        if err or not isinstance(t, dict):
            return None, 'ticket %s could not be read (status %s)' % (ref, status)
        return t, 'read'

    def _stamp_of(self, t):
        v = (t.get('custom_fields') or {}).get(self.stamp_field) if self.stamp_field else ''
        return str(v or '').strip()

    def _state(self, t):
        return 'closed' if int(t.get('status') or 0) in (STATUS_RESOLVED, STATUS_CLOSED) else 'open'

    def authenticated_identity(self):
        return self.identity

    # ── run start ───────────────────────────────────────────────────────────────────────
    def validate(self):
        doc, status, err = self._req('GET', '/api/v2/ticket_form_fields')
        if err or not isinstance(doc, dict):
            return False, rt.first_read_refusal(status, 'FRESHSERVICE_HOST', 'FRESHSERVICE_API_KEY',
                                                'FRESHSERVICE_STAMP_FIELD', self.stamp_field)
        fields = [f for f in doc.get('ticket_fields') or [] if isinstance(f, dict)]
        stamp = [f for f in fields if f.get('name') == self.stamp_field]
        if not stamp:
            return False, ('FRESHSERVICE_STAMP_FIELD %s is not a ticket field (have %d field(s)); a human adds it '
                           'once, as single-line text' % (self.stamp_field, len(fields)))
        if str(stamp[0].get('field_type') or '') != 'custom_text':
            return False, ('FRESHSERVICE_STAMP_FIELD %s is %r, not a single-line text field (custom_text, '
                           'UNVERIFIED type name)' % (self.stamp_field, stamp[0].get('field_type')))
        me, status, err = self._req('GET', '/api/v2/agents/me')
        agent = (me or {}).get('agent') if isinstance(me, dict) else None
        if err or not isinstance(agent, dict) or agent.get('id') is None:
            # NOT fatal: tickets can still be written. What it costs is named: provenance, marker notes and the
            # tag reconcile cannot tell the kit's writes from a person's, so they say NOT_ESTABLISHED.
            self.identity = None
            self.identity_detail = ('the identity the API key resolves to could not be read (GET /api/v2/agents/me, '
                                    'UNVERIFIED; status %s)' % status)
        else:
            self.identity = str(agent['id'])
            self.identity_detail = 'agent %s' % self.identity
        return True, 'ticket fields and the stamp field established; identity: %s' % self.identity_detail

    def probe(self):
        if not self.calibration:
            return False, ('no calibration ticket configured (FRESHSERVICE_CALIBRATION_TICKET), so no not-found this '
                           'run may license a creation')
        t, d = self._ticket(self.calibration)
        if t is None:
            return False, 'the calibration ticket did not resolve (%s)' % d
        if self._stamp_of(t) or self.stamp_label in (t.get('tags') or []):
            return False, ('the calibration ticket carries our stamp or umbrella tag, so it may be one this kit '
                           'created; it cannot calibrate foreign visibility')
        return True, 'calibration probe resolved a known-present foreign ticket'

    # ── the sweep: the umbrella TAG through the filter, the stamp from the governed field ──
    def filter_query(self, clauses):
        q = '"%s"' % ' AND '.join(clauses)
        return q if len(q) <= FILTER_MAX_CHARS else None

    def sweep(self, known_refs=()):
        out, page = {}, 1
        q = self.filter_query(["tag:'%s'" % self.stamp_label])
        while True:
            doc, status, err = self._req('GET', '/api/v2/tickets/filter?query=%s&page=%d'
                                         % (urllib.parse.quote(q), page))
            rows = (doc or {}).get('tickets') if isinstance(doc, dict) else None
            if err or not isinstance(rows, list):
                return out, False, 'sweep stopped at page %d (status %s)' % (page, status)
            for t in rows:
                stamp = self._stamp_of(t)
                if not stamp or self.stamp_label not in (t.get('tags') or []):
                    continue
                labels = list(t.get('tags') or [])
                if self.mark_mode == 'notes':
                    # The lifecycle markers ARE labels to everything that reads a sweep (the dedupe re-run, the
                    # clocks' once-per-cycle rule), so they are read here. Unreadable: the tags alone, said so --
                    # a marker missed makes a reminder repeat, it never loses a ticket.
                    marks, ok_m, _dm = self.markers_of(t.get('id'))
                    labels = sorted(set(labels) | set(marks)) if ok_m else labels
                    if not ok_m:
                        self.marker_gaps = getattr(self, 'marker_gaps', 0) + 1
                out.setdefault(stamp, []).append({
                    'ref': str(t.get('id')), 'key': '#%s' % t.get('id'),
                    'url': '%s/api/v2/tickets/%s' % (self.host, t.get('id')), 'state': self._state(t),
                    'status_name': str(t.get('status') or ''), 'labels': labels, 'body': ''})
            print('  ... swept page %d (%d ticket(s))' % (page, len(rows)), file=sys.stderr)
            if len(rows) < FILTER_PAGE:
                return out, True, 'swept %d page(s)' % page
            page += 1
            if page > MAX_PAGES:
                return out, False, 'the sweep ran past %d page(s): PARTIAL' % MAX_PAGES

    def resolve(self, ref):
        t, d = self._ticket(ref)
        return (t, True, 'resolved') if t else (None, False, 'did not resolve (%s)' % d)

    # ── writes ──────────────────────────────────────────────────────────────────────────
    def _create(self, title, body, tags, stamp=None, priority=None):
        payload = {'subject': title, 'description': _html_body(body), 'requester_id': int(self.requester_id),
                   'status': STATUS_OPEN, 'priority': int(priority or 2), 'source': self.source,
                   # TAGS AT CREATION: the one write of the list that cannot drop anybody's tag.
                   'tags': list(tags or [])}
        if stamp is not None:
            payload['custom_fields'] = {self.stamp_field: stamp}
        if self.workspace_id:
            payload['workspace_id'] = int(self.workspace_id)
        doc, status, err = self._req('POST', '/api/v2/tickets', payload)
        t = (doc or {}).get('ticket') if isinstance(doc, dict) else None
        if err or not isinstance(t, dict) or t.get('id') is None:
            return None, 'create failed (status %s)' % status
        return str(t['id']), 'created ticket %s' % t['id']

    def create(self, cluster, body, title):
        tags = [self.stamp_label] + ([rt.family_of(cluster)] if rt.family_of(cluster) else []) + \
            [x for x in cluster.get('extra_labels') or [] if x]
        pr = 4 if cluster.get('urgent') else PRIORITY_BY_SEVERITY.get(str(cluster.get('severity') or '').lower(), 2)
        ref, detail = self._create(title, body, sorted(set(tags), key=tags.index), stamp=cluster['cluster_key'],
                                   priority=pr)
        if ref:
            # The GOVERNED key is read back: a field that did not take is said so (the block's stamp line still
            # carries it), never assumed.
            t, _d = self._ticket(ref)
            if t is None or self._stamp_of(t) != cluster['cluster_key']:
                self.preservation.append({'ref': ref, 'state': 'STAMP_FIELD_NOT_CONFIRMED',
                                          'detail': 'the stamp field did not read back as the full key'})
        return ref, detail

    def create_instance(self, parent_ref, member, body, title):
        # No umbrella tag and no stamp: an instance (a duplicate record, or a child obligation) is found through
        # its parent, never by a sweep of its own. Its own labels go in at creation.
        return self._create(title, body, list((member or {}).get('labels') or []))

    def comment(self, ref, text):
        doc, status, err = self._req('POST', '/api/v2/tickets/%s/notes' % ref,
                                     {'body': _html_body(text), 'private': True})
        return (err is None and doc is not None), 'note status %s' % status

    def _conversations(self, ref):
        out, page = [], 1
        while page <= MAX_PAGES:
            doc, status, err = self._req('GET', '/api/v2/tickets/%s/conversations?per_page=%d&page=%d'
                                         % (ref, LIST_PAGE, page))
            rows = (doc or {}).get('conversations') if isinstance(doc, dict) else None
            if err or not isinstance(rows, list):
                return None, 'the conversations of %s could not be read (status %s)' % (ref, status)
            out.extend(rows)
            if len(rows) < LIST_PAGE:
                return out, 'read'
            page += 1
        return None, 'the conversations of %s ran past %d page(s)' % (ref, MAX_PAGES)

    def markers_of(self, ref):
        """-> (markers, ok, detail): the kit's marker notes. A note counts only when its author is the kit."""
        if markers_need_kit_author and not self.identity:
            return [], False, ('the kit\'s own identity is not established (%s), so a marker note cannot be told from '
                               'a person\'s' % self.identity_detail)
        convs, d = self._conversations(ref)
        if convs is None:
            return [], False, d
        out = []
        for c in convs:
            if markers_need_kit_author and str(c.get('user_id')) != str(self.identity):
                continue
            text = rt.html_text_lines(c.get('body') or '') + '\n' + str(c.get('body_text') or '')
            for line in text.split('\n'):
                s = line.strip()
                if s.startswith(MARKER_PREFIX):
                    out.append(s[len(MARKER_PREFIX):].strip())
        return sorted(set(x for x in out if x)), True, 'read'

    def labels_of(self, ref):
        t, d = self._ticket(ref)
        if t is None:
            return [], False, d
        tags = list(t.get('tags') or [])
        if self.mark_mode != 'notes':
            return tags, True, 'read'
        marks, ok, d2 = self.markers_of(ref)
        if not ok:
            return tags, False, d2
        return sorted(set(tags) | set(marks)), True, 'read'

    def read_description(self, ref):
        t, d = self._ticket(ref)
        if t is None:
            return None, False, 'the description could not be read (%s)' % d
        return {'html': t.get('description') or '', 'updated_at': t.get('updated_at')}, True, 'read'

    def description_text(self, description):
        return rt.html_text_lines((description or {}).get('html') or '')

    def splice_description(self, description, block):
        new_html, found = rt.html_splice((description or {}).get('html') or '', block)
        return dict(description or {}, html=new_html), found

    def write_description(self, ref, new_description, read):
        """No precondition exists, so: under the ticket's lock, re-read updated_at and write only if nothing changed
        since the read. A change is a refusal (the update is owed). The seconds between that re-read and the PUT
        are the named residual (R-30)."""
        ok_l, why = self.locks.acquire(ref)
        if not ok_l:
            return False, why
        try:
            t, d = self._ticket(ref)
            if t is None:
                return False, d
            if (read or {}).get('updated_at') and t.get('updated_at') != read.get('updated_at'):
                return False, ('ticket %s changed since it was read (updated_at %s -> %s): not written over; the '
                               'update is owed to the next run' % (ref, read.get('updated_at'), t.get('updated_at')))
            doc, status, err = self._req('PUT', '/api/v2/tickets/%s' % ref,
                                         {'description': (new_description or {}).get('html') or ''})
            return (err is None and doc is not None), 'description update status %s' % status
        finally:
            self.locks.release(ref)

    def _status(self, ref, value, verb):
        doc, status, err = self._req('PUT', '/api/v2/tickets/%s' % ref, {'status': int(value)})
        if err or doc is None:
            return False, 'the %s (status %d) was refused (HTTP %s)' % (verb, value, status)
        return True, '%s (status %d)' % (verb, value)

    def close(self, ref):
        return self._status(ref, self.status_done, 'closed')

    def reopen(self, ref):
        return self._status(ref, STATUS_OPEN, 'reopened')

    # ── marks: notes by default; tags read-merge-write-verify when the owner chose tags ──
    def mark(self, ref, labels=(), bump_priority=False):
        labels = [x for x in labels if x]
        ok_l, why = self.locks.acquire(ref)
        if not ok_l:
            return False, why, {'labels': [], 'state': TICKET_WRITE_LOCK_HELD}
        try:
            applied = {'labels': [], 'mode': self.mark_mode}
            ok, detail = True, 'nothing to change'
            if labels and self.mark_mode == 'notes':
                have, ok_r, d_r = self.labels_of(ref)
                if not ok_r:
                    return False, 'the markers could not be read: %s' % d_r, applied
                add = [x for x in labels if x not in have]
                if add:
                    ok, detail = self.comment(ref, 'secure-cicd-kit lifecycle marker(s) (a private note; tags are left '
                                              'alone so no one\'s tags are replaced):\n' +
                                              '\n'.join('%s %s' % (MARKER_PREFIX, x) for x in add))
                    applied['labels'] = add if ok else []
                applied['preservation'] = TAG_PRESERVATION_ESTABLISHED
            elif labels:
                ok, detail, rec = self.merge_tags(ref, labels)
                applied['labels'] = rec.get('added') or []
                applied['preservation'] = rec['state']
            if bump_priority:
                ok_p, d_p, pr = self._bump(ref)
                applied.update(pr)
                ok, detail = ok and ok_p, '%s; %s' % (detail, d_p)
            return ok, detail, applied
        finally:
            self.locks.release(ref)

    def _bump(self, ref):
        t, d = self._ticket(ref)
        if t is None:
            return False, d, {}
        cur = t.get('priority')
        if not isinstance(cur, int) or isinstance(cur, bool) or cur >= 4:
            return True, 'priority unchanged', {'priority_note': 'priority %r is already the highest (4) or not a '
                                                                 'number' % (cur,)}
        _d, status, err = self._req('PUT', '/api/v2/tickets/%s' % ref, {'priority': cur + 1})
        t2, _d2 = self._ticket(ref)
        ok = err is None and t2 is not None and t2.get('priority') == cur + 1
        return ok, 'priority %s -> %s %s' % (cur, cur + 1, 'verified' if ok else 'NOT verified'), \
            {'priority': [cur, cur + 1]}

    def _activities_since(self, ref, since):
        """-> (foreign activities since `since`, ok, detail). Newest first; older pages by next_page_url (bounded)."""
        out, path, pages = [], '/api/v2/tickets/%s/activities' % ref, 0
        while path and pages < 5:
            doc, status, err = self._req('GET', path)
            rows = (doc or {}).get('activities') if isinstance(doc, dict) else None
            if err or not isinstance(rows, list):
                return [], False, 'the activity history of %s could not be read (status %s)' % (ref, status)
            pages += 1
            older = False
            for a in rows:
                when = str(a.get('created_at') or '')
                if since and when and when < since:
                    older = True
                    continue
                if str((a.get('actor') or {}).get('id')) != str(self.identity):
                    out.append(a)
            nxt = doc.get('next_page_url') if isinstance(doc, dict) else None
            path = None
            if nxt and not older:
                u = urllib.parse.urlsplit(nxt)
                path = u.path + ('?' + u.query if u.query else '')
        return out, True, 'read'

    def merge_tags(self, ref, labels):
        """READ, MERGE, WRITE, RE-READ, VERIFY -- reconciling a concurrent edit from the activity history. The
        caller holds the ticket's lock. -> (ok, detail, record)."""
        rec = {'ref': str(ref), 'added': [], 'attempts': 0, 'concurrent': [], 'state': TAG_PRESERVATION_NOT_ESTABLISHED}
        want_add = list(labels)
        for attempt in range(self.tag_retries + 1):
            rec['attempts'] = attempt + 1
            t0, d = self._ticket(ref)
            if t0 is None:
                rec['detail'] = d
                break
            tags0, since = list(t0.get('tags') or []), str(t0.get('updated_at') or '')
            merged = tags0 + [x for x in want_add if x not in tags0]
            if merged != tags0:
                _doc, status, err = self._req('PUT', '/api/v2/tickets/%s' % ref, {'tags': merged})
                if err:
                    rec['detail'] = 'the tag write was refused (HTTP %s)' % status
                    continue
            if not verify_after_write:
                rec.update(state=TAG_PRESERVATION_ESTABLISHED, added=[x for x in want_add if x not in tags0])
                break
            t1, d1 = self._ticket(ref)
            if t1 is None:
                rec['detail'] = d1
                continue
            tags1 = list(t1.get('tags') or [])
            if not self.identity:
                rec['detail'] = ('the kit\'s own identity is not established, so the activity history cannot show '
                                 'whether a person edited the tags meanwhile')
                rec['added'] = [x for x in want_add if x in tags1 and x not in tags0]
                break
            foreign, ok_h, dh = self._activities_since(ref, since)
            if not ok_h:
                rec['detail'] = dh
                rec['added'] = [x for x in want_add if x in tags1 and x not in tags0]
                break
            h_add, h_rem, unparsed = set(), set(), False
            for a in foreign:
                a_add, a_rem, touches, parsed = parse_tag_changes(a)
                if touches:
                    rec['concurrent'].append({'actor': (a.get('actor') or {}).get('name') or (a.get('actor') or {}).get('id'),
                                              'at': a.get('created_at'), 'added': sorted(a_add),
                                              'removed': sorted(a_rem), 'parsed': parsed})
                    unparsed = unparsed or not parsed
                    h_add |= a_add
                    h_rem |= a_rem
            if unparsed:
                rec['detail'] = 'a concurrent tag change in the history could not be read; nothing is claimed'
                rec['added'] = [x for x in want_add if x in tags1 and x not in tags0]
                break
            if h_add or h_rem:
                if not reconcile_from_history:
                    rec['state'] = TAG_PRESERVATION_ESTABLISHED
                    rec['added'] = [x for x in want_add if x in tags1]
                    break
                # A person's added tag is put back; a person's removed tag stays removed, unless the kit is adding it.
                target = [x for x in tags1 if not (x in h_rem and x not in want_add)]
                target += [x for x in sorted(h_add) if x not in target and x not in h_rem - h_add]
                target += [x for x in want_add if x not in target]
                if target != tags1:
                    _doc, status, err = self._req('PUT', '/api/v2/tickets/%s' % ref, {'tags': target})
                    if err:
                        rec['detail'] = 'the reconciling tag write was refused (HTTP %s)' % status
                        continue
                    t2, d2 = self._ticket(ref)
                    if t2 is None:
                        rec['detail'] = d2
                        continue
                    tags1 = list(t2.get('tags') or [])
                    # The reconciling write itself may have raced: read the history again, once more round the loop.
                    later, ok_l2, _dl = self._activities_since(ref, str(t2.get('updated_at') or ''))
                    if not ok_l2 or any(parse_tag_changes(a)[2] for a in later):
                        rec['detail'] = 'tags changed again during the reconcile'
                        continue
                if set(want_add) <= set(tags1) and (h_add - h_rem) <= set(tags1) and not (h_rem - set(want_add)) & set(tags1):
                    rec.update(state=TAG_PRESERVATION_ESTABLISHED, added=[x for x in want_add if x not in tags0],
                               reconciled=True)
                    break
                rec['detail'] = 'the reconciled tags did not read back'
                continue
            if set(want_add) <= set(tags1) and set(tags0) <= set(tags1):
                rec.update(state=TAG_PRESERVATION_ESTABLISHED, added=[x for x in want_add if x not in tags0])
                break
            rec['detail'] = 'the tags did not read back as written (attempt %d)' % (attempt + 1)
        self.preservation.append(rec)
        if rec['state'] != TAG_PRESERVATION_ESTABLISHED:
            # NEVER CLAIMED: a person is asked to check, on the ticket, and the run reports it.
            self.comment(ref, '%s (secure-cicd-kit): the kit changed this ticket\'s tags (%s) and could not prove that '
                              'no one else\'s tag change was lost (%s). Please check the tags against the activity '
                              'history.' % (TAG_PRESERVATION_NOT_ESTABLISHED, ', '.join(want_add),
                                            rec.get('detail') or 'retries exhausted'))
            return False, '%s: %s' % (TAG_PRESERVATION_NOT_ESTABLISHED, rec.get('detail') or 'retries exhausted'), rec
        return True, 'tags merged and verified%s' % (' (a concurrent edit reconciled from the history)'
                                                    if rec.get('reconciled') else ''), rec

    # ── provenance (KDEC-043 rule 2) ──────────────────────────────────────────────────────
    def write_event(self, ref):
        """-> (actor id or None, detail): the OLDEST activity's actor -- who made the ticket (UNVERIFIED that the
        creation is an activity)."""
        path, pages, oldest = '/api/v2/tickets/%s/activities' % ref, 0, None
        while path and pages < 5:
            doc, status, err = self._req('GET', path)
            rows = (doc or {}).get('activities') if isinstance(doc, dict) else None
            if err or not isinstance(rows, list):
                return None, 'the activity history of %s could not be read (status %s)' % (ref, status)
            pages += 1
            for a in rows:
                if oldest is None or str(a.get('created_at') or '') <= str(oldest.get('created_at') or ''):
                    oldest = a
            nxt = doc.get('next_page_url')
            path = None
            if nxt:
                u = urllib.parse.urlsplit(nxt)
                path = u.path + ('?' + u.query if u.query else '')
        if not oldest or (oldest.get('actor') or {}).get('id') is None:
            return None, 'no activity names who made ticket %s' % ref
        return str(oldest['actor']['id']), 'the oldest activity'


# ═════════════════════════════════════════════════════════════════════════════════════
# THE INTAKE ADAPTER (scripts/ticket_intake.py's contract: {state, tickets, next_page_token, detail})
# ═════════════════════════════════════════════════════════════════════════════════════

class FreshserviceIntake(ti._PagedById):
    """Every ticket, manual ones included. Exact: the governed stamp field, or the correlation-key TAG verified
    against the full key (ticket_intake.match). Near: the subject and description text -- Freshservice has no
    documented text search, so the list (with updated_since, or it shows only 30 days) is read and matched here;
    a list row with no description text makes the search PARTIAL, never a quiet subject-only match."""

    name = 'freshservice'

    def __init__(self, backend):
        self.b = backend
        self.allowed_projects = [backend.workspace_id] if backend.workspace_id else []

    def refuse_query(self, projects, jql):
        extra = [x for x in projects or [] if str(x) not in self.allowed_projects]
        if extra:
            return ('workspace(s) %s are not this repository\'s Freshservice workspace (%s)'
                    % (', '.join(str(x) for x in extra), ', '.join(self.allowed_projects) or 'none configured'))
        if jql:
            return 'jql is Jira\'s query language; a Freshservice intake takes tags (labels) and text'
        return ''

    def _shape(self, t):
        text = t.get('description_text')
        if text is None and t.get('description') is not None:
            text = rt.html_text_lines(t.get('description') or '')
        return {'ref': str(t.get('id')), 'key': '#%s' % t.get('id'), 'summary': str(t.get('subject') or '')[:255],
                'labels': list(t.get('tags') or []), 'state': self.b._state(t), 'status_name': str(t.get('status') or ''),
                'stamp': self.b._stamp_of(t), '_text': text if text is not None else None}

    def search(self, projects=None, labels=None, jql=None, page_token=None, max_results=100, text=None,
               ck_label=None):
        why = self.refuse_query(projects, jql)
        if why:
            return {'state': ti.TRACKER_QUERY_REFUSED, 'tickets': [], 'next_page_token': None, 'detail': why}
        page = int(page_token or 1)
        found, full = {}, False
        # The correlation-key tag is a SEARCH AID (KDEC-043): match() verifies every hit against the full key.
        tag_clauses = ["tag:'%s'" % ck_label] if ck_label else ["tag:'%s'" % x for x in labels or []]
        if tag_clauses:
            q = self.b.filter_query(tag_clauses)
            if q is None:
                return {'state': ti.TRACKER_QUERY_REFUSED, 'tickets': [], 'next_page_token': None,
                        'detail': 'the filter query would be over %d characters' % FILTER_MAX_CHARS}
            doc, status, err = self.b._req('GET', '/api/v2/tickets/filter?query=%s&page=%d' % (urllib.parse.quote(q), page))
            rows = (doc or {}).get('tickets') if isinstance(doc, dict) else None
            if err or not isinstance(rows, list):
                return {'state': ti.TRACKER_INTAKE_PARTIAL, 'tickets': [], 'next_page_token': None,
                        'detail': 'the ticket filter did not answer (status %s): nothing was looked at' % status}
            full = len(rows) >= FILTER_PAGE
            for t in rows:
                if t.get('description_text') is None and t.get('description') is None:
                    # A tag hit is only a search hit until the full key is read (KDEC-043 rule 1), so a row the filter
                    # returned without its description is read in full; one that cannot be read is not concluded.
                    full_t, d = self.b._ticket(t['id'])
                    if full_t is None:
                        return {'state': ti.TRACKER_INTAKE_PARTIAL, 'tickets': [], 'next_page_token': None,
                                'detail': 'a tag hit could not be read in full (%s)' % d}
                    t = full_t
                found[int(t['id'])] = t
        if text or not tag_clauses:
            doc, status, err = self.b._req('GET', '/api/v2/tickets?per_page=%d&page=%d&updated_since=%s'
                                           % (LIST_PAGE, page, urllib.parse.quote('2000-01-01T00:00:00Z')))
            rows = (doc or {}).get('tickets') if isinstance(doc, dict) else None
            if err or not isinstance(rows, list):
                return {'state': ti.TRACKER_INTAKE_PARTIAL, 'tickets': [], 'next_page_token': None,
                        'detail': 'the ticket list did not answer (status %s): nothing was looked at' % status}
            full = full or len(rows) >= LIST_PAGE
            for t in rows:
                if text:
                    if t.get('description_text') is None and t.get('description') is None:
                        return {'state': ti.TRACKER_INTAKE_PARTIAL, 'tickets': [], 'next_page_token': None,
                                'detail': ('the ticket list did not return the description of #%s, so a near match '
                                           'cannot be established over it (UNVERIFIED field)' % t.get('id'))}
                    hay = ('%s\n%s' % (t.get('subject') or '', t.get('description_text') or
                                       rt.html_text_lines(t.get('description') or ''))).lower()
                    if str(text).lower() not in hay:
                        continue
                found[int(t['id'])] = t
        out = [self._shape(found[n]) for n in sorted(found)]
        return {'state': ti.TRACKER_INTAKE_COMPLETE, 'tickets': out, 'next_page_token': str(page + 1) if full else None,
                'detail': 'page %d: %d ticket(s)' % (page, len(out))}


# ═════════════════════════════════════════════════════════════════════════════════════
# CONFIGURATION (read by reconcile_tickets.choose_backend)
# ═════════════════════════════════════════════════════════════════════════════════════

def host_problem(value):
    """https origin, or plain http to 127.0.0.1 ONLY (the stand-in the proofs run against)."""
    v = (value or '').strip().rstrip('/')
    u = urllib.parse.urlsplit(v)
    if u.scheme == 'http' and u.hostname == '127.0.0.1' and '@' not in u.netloc and u.path in ('', '/') \
            and not u.query and not u.fragment:
        return ''
    return rt.https_origin_problem('FRESHSERVICE_HOST', v)


def config_problem(env):
    bad = host_problem(env.get('FRESHSERVICE_HOST'))
    if bad:
        return bad
    if not re.match(r'^cf_[a-z0-9_]{1,60}$', (env.get('FRESHSERVICE_STAMP_FIELD') or '').strip()):
        return ('FRESHSERVICE_STAMP_FIELD must be the NAME of a single-line text custom field (cf_<name>), added '
                'once by a human')
    if not (env.get('FRESHSERVICE_REQUESTER_ID') or '').strip().isdigit():
        return 'FRESHSERVICE_REQUESTER_ID must be the numeric id of the requester the kit files tickets as'
    for k in ('FRESHSERVICE_CALIBRATION_TICKET', 'FRESHSERVICE_WORKSPACE_ID'):
        v = (env.get(k) or '').strip()
        if v and not v.isdigit():
            return '%s must be a numeric id' % k
    mode = (env.get('FRESHSERVICE_MARK_MODE') or 'notes').strip().lower()
    if mode not in MARK_MODES:
        return 'FRESHSERVICE_MARK_MODE is %r; it must be notes (the default) or tags' % mode
    label = (env.get(rt.ENV_STAMP_LABEL) or '').strip()
    if "'" in label or '"' in label:
        return '%s may not contain a quote: it is placed inside a Freshservice filter query' % rt.ENV_STAMP_LABEL
    retries = (env.get('FRESHSERVICE_TAG_RETRIES') or '').strip()
    if retries and not (retries.isdigit() and int(retries) <= 5):
        return 'FRESHSERVICE_TAG_RETRIES must be a whole number from 0 to 5 (unset: 2)'
    return rt.common_config_problem(env)


def build(env, retry_ceiling):
    bad = config_problem(env)
    if bad:
        return None, 'CONFIGURATION REFUSED: %s' % bad
    label = (env.get(rt.ENV_STAMP_LABEL) or '').strip()
    if not label:
        return None, ('%s is unset. The umbrella tag is provisioned once by a human; one this program invented '
                      'would make every sweep find nothing.' % rt.ENV_STAMP_LABEL)
    b = Freshservice(env.get('FRESHSERVICE_HOST'), env.get('FRESHSERVICE_API_KEY'),
                     (env.get('FRESHSERVICE_STAMP_FIELD') or '').strip(),
                     (env.get('FRESHSERVICE_REQUESTER_ID') or '').strip(),
                     calibration=(env.get('FRESHSERVICE_CALIBRATION_TICKET') or '').strip(),
                     stamp_label=label, workspace_id=(env.get('FRESHSERVICE_WORKSPACE_ID') or '').strip(),
                     mark_mode=(env.get('FRESHSERVICE_MARK_MODE') or 'notes').strip().lower(),
                     tag_retries=int((env.get('FRESHSERVICE_TAG_RETRIES') or '2').strip() or 2),
                     lock_dir=(env.get('FRESHSERVICE_LOCK_DIR') or '').strip(), retry_ceiling=retry_ceiling,
                     create_ceiling=int(env.get('TICKET_CREATE_CEILING')))
    return b, 'freshservice backend configured (mark mode %s)' % b.mark_mode
