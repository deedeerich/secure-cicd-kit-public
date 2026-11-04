#!/usr/bin/env python3
"""Ticket intake: read EVERY existing ticket -- manually created ones included -- and match findings
to them. (KDEC-037; the owner, 2026-11-03: "it truly needs to look at all even the manually created
tickets".)

TWO USES, ONE ADAPTER

    tickets.search tracker_query   one page of the tracker's tickets (project / labels / JQL), with
                                   their numbers and status, joined to the findings, for findings
                                   views and dashboards
    dedupe before every create     for each finding, look for an existing ticket FIRST:
        exact      the kit's stamp field, the kit's correlation-key label, or the stamp line in the
                   body carries this finding's correlation key -> LINKED, never a second ticket
        candidate  a ticket whose text names this asset AND this identifier, or this identifier and a
                   title at or above the similarity threshold -> surfaced for a person to confirm
                   (link) or reject (new). NEVER merged unless exact.
        none       only after a COMPLETE search: a partial search is "nothing was looked at", not
                   "nothing found", and nothing is created from it.

THE ADAPTER SEAM

    jira          built: the enhanced search (POST /rest/api/3/search/jql), paged by nextPageToken,
                  bounded, inside the projects this repository's routing and ledger name
    freshservice  the seam: TRACKER_INTAKE_NOT_CONFIGURED until an adapter is built (the owner's
                  "FreshService comes later")
    azdo          built (KDEC-037 O-37h, owner 2026-11-04): WIQL inside the project, paged by id, then
                  workitemsbatch; exact by the stamp field or the correlation-key tag
    github        built: the issues list by the correlation-key label, the search API for text, paged

    An adapter answers {state, tickets, next_page_token, detail}; nothing else in the kit depends on
    which tracker it is.
"""
import difflib
import re

TRACKER_INTAKE_COMPLETE = 'TRACKER_INTAKE_COMPLETE'
TRACKER_INTAKE_PARTIAL = 'TRACKER_INTAKE_PARTIAL'
TRACKER_INTAKE_NOT_CONFIGURED = 'TRACKER_INTAKE_NOT_CONFIGURED'
TRACKER_QUERY_REFUSED = 'TRACKER_QUERY_REFUSED'
MAX_PAGES = 10


def _q(v):
    return str(v or '').replace('\\', '\\\\').replace('"', '\\"')


class NotConfigured(object):
    """The seam's empty socket: an adapter that is not built says so, every time."""

    def __init__(self, name, why):
        self.name = name
        self.why = why
        self.allowed_projects = []

    def search(self, **_kw):
        return {'state': TRACKER_INTAKE_NOT_CONFIGURED, 'tickets': [], 'next_page_token': None,
                'detail': self.why}


class JiraIntake(object):
    name = 'jira'

    def __init__(self, backend):
        self.b = backend
        self.allowed_projects = list(backend.projects())

    def refuse_query(self, projects, jql):
        """-> '' or why the query is refused. Projects inside the repository's own; no ORDER BY, no
        statement break: the caller's JQL is a filter wrapped in parentheses, never a whole query."""
        extra = [p for p in projects or [] if p not in self.allowed_projects]
        if extra:
            return ('project(s) %s are not among this repository\'s ticket projects (%s): the API reads only '
                    'the projects its routing and ledger name' % (', '.join(extra), ', '.join(self.allowed_projects)))
        if jql and (re.search(r'(?i)\border\s+by\b', jql) or any(c in jql for c in ';\n\r')):
            return 'the JQL carries ORDER BY or a statement break; it is a filter, wrapped as project in (...) AND (<jql>)'
        return ''

    def jql(self, projects, labels=None, jql=None, text=None, ck_label=None):
        ps = projects or self.allowed_projects
        parts = ['project in (%s)' % ', '.join('"%s"' % _q(p) for p in ps)]
        if labels:
            parts.append('labels in (%s)' % ', '.join('"%s"' % _q(x) for x in labels))
        if jql:
            parts.append('(%s)' % jql)
        ors = []
        if ck_label:
            ors.append('labels = "%s"' % _q(ck_label))
        if text:
            ors.append('text ~ "\\"%s\\""' % _q(text))
        if ors:
            parts.append('(%s)' % ' OR '.join(ors))
        return ' AND '.join(parts) + ' ORDER BY created ASC'

    def search(self, projects=None, labels=None, jql=None, page_token=None, max_results=50, text=None,
               ck_label=None):
        why = self.refuse_query(projects, jql)
        if why:
            return {'state': TRACKER_QUERY_REFUSED, 'tickets': [], 'next_page_token': None, 'detail': why}
        import reconcile_tickets as rt
        fields = ['summary', 'labels', 'status', 'description'] + ([self.b.stamp_field] if self.b.stamp_field else [])
        payload = {'jql': self.jql(projects, labels, jql, text, ck_label), 'maxResults': int(max_results or 50),
                   'fields': fields}
        if page_token:
            payload['nextPageToken'] = page_token
        doc, status, err = self.b._req('POST', '/rest/api/3/search/jql', payload)
        if err or not isinstance(doc, dict):
            return {'state': TRACKER_INTAKE_PARTIAL, 'tickets': [], 'next_page_token': None,
                    'detail': 'the tracker search did not answer (status %s): nothing was looked at' % status}
        out = []
        for issue in doc.get('issues') or []:
            f = issue.get('fields') or {}
            st = f.get('status') or {}
            desc = f.get('description')
            text_body = rt.adf_text_lines(desc) if isinstance(desc, dict) else str(desc or '')
            stamp = f.get(self.b.stamp_field) if self.b.stamp_field else ''
            out.append({'ref': str(issue.get('id') or ''), 'key': issue.get('key') or '',
                        'summary': str(f.get('summary') or '')[:255], 'labels': list(f.get('labels') or []),
                        'state': ('closed' if (st.get('statusCategory') or {}).get('key') == 'done' else 'open')
                        if st else '', 'status_name': st.get('name') or '',
                        'stamp': stamp.strip() if isinstance(stamp, str) else '',
                        '_text': text_body})
        nxt = doc.get('nextPageToken') or None
        # A PAGE is complete when it answered; whether the SET is complete is search_all's question.
        return {'state': TRACKER_INTAKE_COMPLETE, 'tickets': out,
                'next_page_token': nxt, 'detail': 'one page of %d ticket(s)' % len(out)}

    def search_all(self, max_pages=MAX_PAGES, page_size=100, **kw):
        """-> (tickets, state, detail): every page, bounded. Past the bound is PARTIAL."""
        tickets, token = [], None
        for n in range(max_pages):
            page = self.search(page_token=token, max_results=page_size, **kw)
            if page['state'] != TRACKER_INTAKE_COMPLETE:
                return tickets, page['state'], page['detail']
            tickets.extend(page['tickets'])
            token = page['next_page_token']
            if not token:
                return tickets, TRACKER_INTAKE_COMPLETE, '%d page(s), %d ticket(s)' % (n + 1, len(tickets))
        return tickets, TRACKER_INTAKE_PARTIAL, ('the search ran past %d page(s): the rest was not looked at, so '
                                                 'no absence is established' % max_pages)


class _PagedById(object):
    """Shared paging for the adapters below: a page is a batch of tickets, the cursor the last one read."""

    def search_all(self, max_pages=MAX_PAGES, page_size=100, **kw):
        tickets, token = [], None
        for n in range(max_pages):
            page = self.search(page_token=token, max_results=page_size, **kw)
            if page['state'] != TRACKER_INTAKE_COMPLETE:
                return tickets, page['state'], page['detail']
            tickets.extend(page['tickets'])
            token = page['next_page_token']
            if not token:
                return tickets, TRACKER_INTAKE_COMPLETE, '%d page(s), %d ticket(s)' % (n + 1, len(tickets))
        return tickets, TRACKER_INTAKE_PARTIAL, ('the search ran past %d page(s): the rest was not looked at, so '
                                                 'no absence is established' % max_pages)


class AzdoIntake(_PagedById):
    """Azure DevOps Boards (KDEC-037 O-37h, owner 2026-11-04: search-first, to the Jira contract). WIQL for the
    ids inside the project (paged by id), then workitemsbatch for the fields. Exact: the kit's stamp field or
    the correlation-key TAG; near: the title or description naming the identifier."""
    name = 'azdo'

    def __init__(self, backend):
        self.b = backend
        self.allowed_projects = [backend.project]

    def refuse_query(self, projects, jql):
        extra = [x for x in projects or [] if x != self.b.project]
        if extra:
            return 'project(s) %s are not this repository\'s Azure DevOps project %s' % (', '.join(extra), self.b.project)
        if jql:
            return 'jql is Jira\'s query language; an Azure DevOps intake takes projects, labels (tags) and text'
        return ''

    def search(self, projects=None, labels=None, jql=None, page_token=None, max_results=100, text=None,
               ck_label=None):
        import reconcile_tickets as rt
        why = self.refuse_query(projects, jql)
        if why:
            return {'state': TRACKER_QUERY_REFUSED, 'tickets': [], 'next_page_token': None, 'detail': why}
        last = int(page_token or 0)
        where = ["[System.TeamProject] = @project", "[System.Id] > %d" % last]
        for lb in labels or []:
            where.append("[System.Tags] CONTAINS '%s'" % rt._wiql_quote(lb))
        ors = []
        if ck_label:
            ors.append("[System.Tags] CONTAINS '%s'" % rt._wiql_quote(ck_label))
        if text:
            ors += ["[System.Title] CONTAINS '%s'" % rt._wiql_quote(text),
                    "[System.Description] CONTAINS '%s'" % rt._wiql_quote(text)]
        if ors:
            where.append('(%s)' % ' OR '.join(ors))
        q = 'SELECT [System.Id] FROM WorkItems WHERE %s ORDER BY [System.Id]' % ' AND '.join(where)
        doc, status, err = self.b._req('POST', '/_apis/wit/wiql?$top=%d' % int(max_results or 100), {'query': q})
        if err or not isinstance(doc, dict):
            return {'state': TRACKER_INTAKE_PARTIAL, 'tickets': [], 'next_page_token': None,
                    'detail': 'the WIQL search did not answer (status %s): nothing was looked at' % status}
        ids = sorted(int(w['id']) for w in doc.get('workItems') or [] if 'id' in w)[:int(max_results or 100)]
        out = []
        for n in range(0, len(ids), rt.AZDO_BATCH_MAX):
            chunk = ids[n:n + rt.AZDO_BATCH_MAX]
            fields = ['System.Id', 'System.Title', 'System.State', 'System.Tags', 'System.Description']
            if self.b.stamp_field:
                fields.append(self.b.stamp_field)
            bdoc, status, err = self.b._req('POST', '/_apis/wit/workitemsbatch', {'ids': chunk, 'fields': fields})
            if err or not isinstance(bdoc, dict):
                return {'state': TRACKER_INTAKE_PARTIAL, 'tickets': out, 'next_page_token': None,
                        'detail': 'the batch read did not answer (status %s)' % status}
            for item in bdoc.get('value') or []:
                f = item.get('fields') or {}
                tags = [x.strip() for x in str(f.get('System.Tags') or '').split(';') if x.strip()]
                state = f.get('System.State') or ''
                out.append({'ref': str(item.get('id')), 'key': '#%s' % item.get('id'),
                            'summary': str(f.get('System.Title') or '')[:255], 'labels': tags,
                            'state': 'closed' if state == self.b.state_done else 'open', 'status_name': state,
                            'stamp': str(f.get(self.b.stamp_field) or '').strip() if self.b.stamp_field else '',
                            '_text': rt.html_text_lines(f.get('System.Description') or '')})
        nxt = str(ids[-1]) if len(ids) >= int(max_results or 100) else None
        return {'state': TRACKER_INTAKE_COMPLETE, 'tickets': out, 'next_page_token': nxt,
                'detail': 'one page of %d work item(s)' % len(out)}


class GitHubIntake(_PagedById):
    """GitHub Issues (KDEC-037 O-37h). Exact: the correlation-key LABEL (the issues list, by label); near: the
    search API's text match inside the one repository; everything: the issues list, paged. Pull requests are not
    tickets and are dropped. The token goes only to the API host that issued it (KDEC-027)."""
    name = 'github'

    def __init__(self, backend):
        self.b = backend
        self.allowed_projects = [backend.repo]

    def refuse_query(self, projects, jql):
        extra = [x for x in projects or [] if x != self.b.repo]
        if extra:
            return 'repositories %s are not this ticket repository %s' % (', '.join(extra), self.b.repo)
        if jql:
            return 'jql is Jira\'s query language; a GitHub intake takes labels and text'
        return ''

    def _shape(self, i):
        import reconcile_tickets as rt
        labels = [(x.get('name') if isinstance(x, dict) else x) for x in i.get('labels') or []]
        return {'ref': str(i.get('number')), 'key': '#%s' % i.get('number'), 'summary': str(i.get('title') or '')[:255],
                'labels': labels, 'state': 'closed' if i.get('state') == 'closed' else 'open',
                'status_name': i.get('state') or '', 'stamp': rt.stamp_from_body(i.get('body') or ''),
                '_text': i.get('body') or ''}

    def search(self, projects=None, labels=None, jql=None, page_token=None, max_results=100, text=None,
               ck_label=None):
        import urllib.parse
        why = self.refuse_query(projects, jql)
        if why:
            return {'state': TRACKER_QUERY_REFUSED, 'tickets': [], 'next_page_token': None, 'detail': why}
        page = int(page_token or 1)
        size = int(max_results or 100)
        found, full = {}, False
        if text or ck_label:
            if ck_label:
                import reconcile_tickets as rt
                doc, status, err = self.b._req('GET', '/repos/%s/issues?state=all&per_page=%d&page=%d&labels=%s'
                                               % (self.b.repo, size, page, urllib.parse.quote(rt.fit_label(ck_label))))
                if err or not isinstance(doc, list):
                    return {'state': TRACKER_INTAKE_PARTIAL, 'tickets': [], 'next_page_token': None,
                            'detail': 'the issues list did not answer (status %s)' % status}
                full = full or len(doc) >= size
                for i in doc:
                    if 'pull_request' not in i:
                        found[i['number']] = i
            if text:
                q = 'repo:%s "%s"' % (self.b.repo, text)
                doc, status, err = self.b._req('GET', '/search/issues?q=%s&per_page=%d&page=%d'
                                               % (urllib.parse.quote(q), size, page))
                if err or not isinstance(doc, dict) or doc.get('incomplete_results'):
                    return {'state': TRACKER_INTAKE_PARTIAL, 'tickets': [], 'next_page_token': None,
                            'detail': 'the issue search did not answer completely (status %s)' % status}
                items = doc.get('items') or []
                full = full or len(items) >= size
                for i in items:
                    if 'pull_request' not in i:
                        found[i['number']] = i
        else:
            q = '/repos/%s/issues?state=all&per_page=%d&page=%d' % (self.b.repo, size, page)
            if labels:
                q += '&labels=%s' % urllib.parse.quote(','.join(labels))
            doc, status, err = self.b._req('GET', q)
            if err or not isinstance(doc, list):
                return {'state': TRACKER_INTAKE_PARTIAL, 'tickets': [], 'next_page_token': None,
                        'detail': 'the issues list did not answer (status %s)' % status}
            full = len(doc) >= size
            for i in doc:
                if 'pull_request' not in i:
                    found[i['number']] = i
        out = [self._shape(found[n]) for n in sorted(found)]
        return {'state': TRACKER_INTAKE_COMPLETE, 'tickets': out, 'next_page_token': str(page + 1) if full else None,
                'detail': 'page %d: %d issue(s)' % (page, len(out))}


def adapter_for(backend, name=''):
    want = (name or getattr(backend, 'name', '') or '').lower()
    if want == 'freshservice':
        return NotConfigured('freshservice', 'the FreshService intake adapter is the seam, not yet built '
                                             '(TRACKER_INTAKE_NOT_CONFIGURED); nothing was read')
    if want == 'jira' and getattr(backend, 'name', '') == 'jira':
        return JiraIntake(backend)
    if want == 'azdo' and getattr(backend, 'name', '') == 'azdo':
        return AzdoIntake(backend)
    if want == 'github' and getattr(backend, 'name', '') == 'github':
        return GitHubIntake(backend)
    if getattr(backend, 'name', '') == 'recording' and hasattr(backend, 'intake_search'):
        return backend.intake_search()
    return NotConfigured(want or 'none', 'no intake adapter for the %s tracker; nothing could be searched, so a '
                                         'ticket is created in triage as dedupe-pending rather than lost'
                         % (want or 'unconfigured'))


def public(ticket):
    """A ticket as the API returns it: no description, no body text."""
    return dict((k, v) for k, v in ticket.items() if not k.startswith('_'))


def _fit(label):
    import reconcile_tickets as rt
    return rt.fit_label(label)


def match(record, tickets, ck_label, stamp_line, threshold):
    """-> {'exact': [(ticket, basis)], 'candidates': [(ticket, basis, score)]}. Exact only by the key."""
    ck = record['correlation_key']
    exact, cands = [], []
    ident = str(record.get('rule') or '').lower()
    needles = [ident] + list(record.get('aliases') or [])
    asset = str(record.get('asset_needle') or '').lower()
    title = str(record.get('title') or '').lower()
    for t in tickets:
        text = ('%s\n%s\n%s' % (t.get('summary') or '', ' '.join(t.get('labels') or []), t.get('_text') or '')).lower()
        if t.get('stamp') == ck:
            exact.append((t, 'stamp'))
            continue
        # Both sides fitted the same way: a GitHub label is cut to 50 characters (reconcile_tickets.fit_label).
        if ck_label in (t.get('labels') or []) or _fit(ck_label) in [_fit(x) for x in t.get('labels') or []]:
            exact.append((t, 'correlation-label'))
            continue
        if (stamp_line + ' ' + ck).lower() in text:
            exact.append((t, 'body-stamp'))
            continue
        has_id = any(n and n in text for n in needles)
        if not has_id:
            continue
        if asset and asset in text:
            cands.append((t, 'asset+identifier', 100))
            continue
        ratio = int(round(100 * difflib.SequenceMatcher(None, title, str(t.get('summary') or '').lower()).ratio()))
        if ratio >= threshold:
            cands.append((t, 'identifier+title', ratio))
    return {'exact': exact, 'candidates': cands}
