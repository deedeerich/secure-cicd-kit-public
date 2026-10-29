#!/usr/bin/env python3
"""The ticket backends, driven through a stubbed HTTP layer. NO NETWORK, BY CONSTRUCTION.

WHY THIS EXISTS

    `scripts/reconcile_tickets.py --self-test` proves the cascade against an in-memory backend,
    and that is necessary: the cascade has no backend-specific branch. It is not sufficient. The
    Jira, Azure DevOps and GitHub classes each turn the cascade's five questions into requests,
    and nothing proved what those requests are, what a documented response does to them, or that
    a throttle, an empty transitions list or a capped query is read the way TICKETING_BACKENDS.md
    says. Those are the places a real tracker differs from a dictionary.

HOW

    `urllib.request.urlopen` -- the only way any backend reaches the network -- is REPLACED for
    the whole run by `Replay`, which answers from a script of documented request/response shapes
    and records every request. A request nothing scripted answers is refused loudly and fails the
    case, so an unexpected call cannot quietly succeed and no call can leave the machine. Sleep is
    replaced too, so a Retry-After of 30 seconds costs nothing and is still observed.

    Backends are built through `choose_backend(env)`, the real entry point, from placeholder
    values. No real credential is used, and none could be: there is nowhere to send it.

WHAT THIS DOES NOT PROVE

    That the documented shapes are what the live services return. That is TICKETING_BACKENDS.md
    R-1 and R-2, against the owner's personal Jira and personal Azure DevOps, run by a person with
    a transcript (tests/live_ticketing_run.py). Until then every shape here is the documentation's
    word, cited in TICKETING_BACKENDS.md and TICKETING_CONTRACT.md.

EXIT  0 every case held  1 a case failed  2 could not be checked
"""
import io
import json
import os
import re
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

# Placeholders. Nothing here is, or could be used as, a credential.
JIRA_ENV = {'TICKET_BACKEND': 'jira', 'JIRA_HOST': 'https://example.atlassian.net',
            'JIRA_EMAIL': 'someone@example.invalid', 'JIRA_TOKEN': 'placeholder-token',
            'JIRA_PROJECT': 'KIT', 'JIRA_STAMP_FIELD': 'customfield_10001',
            'JIRA_EPIC_ID': '10000', 'JIRA_CALIBRATION_ISSUE': '10002',
            'TICKET_CREATE_CEILING': '25'}
GH_ENV = {'TICKET_BACKEND': 'github', 'GH_TOKEN': 'placeholder-token', 'TICKET_REPO': 'o/r',
          'TICKET_STAMP_LABEL': 'secure-cicd-kit', 'TICKET_CALIBRATION_REF': '7'}
SECRETS = ('placeholder-token', 'placeholder-pat')


class _Resp(object):
    def __init__(self, status, body, headers):
        self.status = status
        self._body = body
        self.headers = headers

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class Replay(object):
    """urlopen's stand-in. Routes are (METHOD, url regex, handler); a handler takes the request
    record and returns (status, json-able body or None, headers dict)."""

    def __init__(self):
        self.routes = []
        self.requests = []
        self.unanswered = []

    def on(self, method, pattern, handler):
        self.routes.insert(0, (method, re.compile(pattern), handler))
        return self

    def __call__(self, req, timeout=None, **_kw):
        body = req.data.decode('utf-8') if req.data else ''
        rec = {'method': req.get_method(), 'url': req.full_url,
               'json': json.loads(body) if body else None,
               'headers': dict((k.lower(), v) for k, v in req.header_items())}
        self.requests.append(rec)
        for method, rx, handler in self.routes:
            if method == rec['method'] and rx.search(rec['url']):
                status, doc, headers = handler(rec)
                raw = json.dumps(doc).encode('utf-8') if doc is not None else b''
                if status >= 400:
                    raise urllib.error.HTTPError(rec['url'], status, 'stub', headers or {},
                                                 io.BytesIO(raw))
                return _Resp(status, raw, headers or {})
        self.unanswered.append('%s %s' % (rec['method'], rec['url']))
        raise urllib.error.URLError('NO NETWORK: nothing scripted answers %s %s'
                                    % (rec['method'], rec['url']))


def ok(doc, status=200, headers=None):
    return lambda rec: (status, doc, headers or {})


def install(replay):
    urllib.request.urlopen = replay
    return replay


def backend(rt, env):
    b, note = rt.choose_backend(env)
    if b is None:
        raise AssertionError('choose_backend refused a complete placeholder config: %s' % note)
    return b


# ── J-3 / L54: THE CALIBRATION PROBE RESOLVES A KNOWN FOREIGN TICKET ─────────────────────

def case_probe(rt, fails):
    """TC 4.5: before any not-found may license a creation, a KNOWN-PRESENT ticket this credential
    did not create must resolve. Reading the project proves reach, not visibility."""
    jira_project = {'id': '10010', 'key': 'KIT'}
    foreign = {'id': '10002', 'key': 'KIT-2', 'fields': {'customfield_10001': None}}
    ours = {'id': '10002', 'key': 'KIT-2', 'fields': {'customfield_10001': 'abc123'}}
    scenarios = [
        ('project readable, calibration ticket NOT FOUND', None, False),
        ('project readable, calibration ticket is one of OURS (stamped)', ours, False),
        ('project readable, calibration ticket resolves and is foreign', foreign, True),
    ]
    for label, calib, want in scenarios:
        r = install(Replay())
        r.on('GET', r'/rest/api/3/project/KIT$', ok(jira_project))
        if calib is None:
            r.on('GET', r'/rest/api/3/issue/10002', lambda rec: (404, {'errorMessages': ['x']}, {}))
        else:
            r.on('GET', r'/rest/api/3/issue/10002', ok(calib))
        observable, detail = backend(rt, JIRA_ENV).probe()
        if bool(observable) != want:
            fails.append('jira probe, %s: observable=%r, expected %r (%s)'
                         % (label, observable, want, detail))
    # Unset: the probe cannot be calibrated, so it is not observable.
    r = install(Replay())
    r.on('GET', r'/rest/api/3/project/KIT$', ok(jira_project))
    env = dict(JIRA_ENV)
    env.pop('JIRA_CALIBRATION_ISSUE')
    b, _n = rt.choose_backend(env)
    if b is not None and b.probe()[0]:
        fails.append('jira probe with NO calibration ticket configured reported the channel '
                     'observable from a project read alone (L54)')

    # GitHub: the same rule (L54), even though the backend is not otherwise extended.
    gh_repo = {'has_issues': True}
    for label, calib, want in (
            ('calibration issue NOT FOUND', None, False),
            ('calibration issue carries the umbrella label (ours)',
             {'number': 7, 'labels': [{'name': 'secure-cicd-kit'}]}, False),
            ('calibration issue resolves and is foreign',
             {'number': 7, 'labels': [{'name': 'bug'}]}, True)):
        r = install(Replay())
        r.on('GET', r'/repos/o/r$', ok(gh_repo))
        if calib is None:
            r.on('GET', r'/repos/o/r/issues/7$', lambda rec: (404, {'message': 'Not Found'}, {}))
        else:
            r.on('GET', r'/repos/o/r/issues/7$', ok(calib))
        observable, detail = backend(rt, GH_ENV).probe()
        if bool(observable) != want:
            fails.append('github probe, %s: observable=%r, expected %r (%s)'
                         % (label, observable, want, detail))


# ── J-4 / T-5: 429 AND 503 ARE WAITED OUT, BOUNDED, AND REPORTED ─────────────────────────

CREATEMETA_TYPES = {'issueTypes': [{'id': '10004', 'name': 'Story'},
                                   {'id': '10005', 'name': 'Subtask', 'subtask': True},
                                   {'id': '10006', 'name': 'Epic'}]}
CREATEMETA_STORY = {'fields': [{'fieldId': 'summary', 'schema': {'type': 'string'}},
                               {'fieldId': 'customfield_10001', 'schema': {'type': 'string'}},
                               {'fieldId': 'labels', 'schema': {'type': 'array'}}]}


def _jira_healthy(r):
    r.on('GET', r'/rest/api/3/myself$', ok({'accountId': 'stub'}))
    r.on('GET', r'/rest/api/3/project/KIT$', ok({'id': '10010', 'key': 'KIT'}))
    r.on('GET', r'/rest/api/3/issue/10002', ok({'id': '10002', 'fields': {}}))
    r.on('GET', r'/rest/api/3/issue/createmeta/KIT/issuetypes$', ok(CREATEMETA_TYPES))
    r.on('GET', r'/rest/api/3/issue/createmeta/KIT/issuetypes/10004$', ok(CREATEMETA_STORY))
    r.on('GET', r'/rest/api/3/issue/10000\b', ok({'id': '10000', 'fields': {
        'project': {'key': 'KIT'}, 'issuetype': {'name': 'Epic'}}}))
    return r


def _sleeps(rt):
    waited = []
    rt._sleep = waited.append
    return waited


def case_throttle(rt, fails):
    env = dict(JIRA_ENV, TICKET_RETRY_CEILING='2')
    page = {'issues': [], 'isLast': True}

    # (a) Retry-After in SECONDS, then success: waited exactly that, sweep complete, reported.
    r = _jira_healthy(install(Replay()))
    seq = [(429, {'errorMessages': ['rate limited']}, {'Retry-After': '7'}), (200, page, {})]
    r.on('POST', r'/rest/api/3/search/jql', lambda rec: seq.pop(0))
    waited = _sleeps(rt)
    b = backend(rt, env)
    _map, complete, detail = b.sweep()
    if not complete:
        fails.append('a 429 with Retry-After: 7 followed by success left the sweep PARTIAL: %s'
                     % detail)
    if waited != [7]:
        fails.append('a 429 with Retry-After: 7 was waited %r, not [7] (T-5)' % waited)
    if len(getattr(b, 'throttles', []) or []) != 1:
        fails.append('the 429 was not recorded for the run report (every 429 seen is reported)')

    # (b) Retry-After as an HTTP-DATE, 503: waited a bounded, non-negative time.
    r = _jira_healthy(install(Replay()))
    seq = [(503, None, {'Retry-After': 'Wed, 21 Oct 2015 07:28:00 GMT'}), (200, page, {})]
    r.on('POST', r'/rest/api/3/search/jql', lambda rec: seq.pop(0))
    waited = _sleeps(rt)
    _m, complete, _d = backend(rt, env).sweep()
    if not complete or len(waited) != 1 or waited[0] < 0:
        fails.append('a 503 with an HTTP-date Retry-After was not waited out once: waited %r, '
                     'complete %r' % (waited, complete))

    # (c) No Retry-After: bounded exponential backoff, then success.
    r = _jira_healthy(install(Replay()))
    seq = [(429, None, {}), (200, page, {})]
    r.on('POST', r'/rest/api/3/search/jql', lambda rec: seq.pop(0))
    waited = _sleeps(rt)
    _m, complete, _d = backend(rt, env).sweep()
    if not complete or len(waited) != 1 or not waited[0] > 0:
        fails.append('a 429 with no Retry-After was not backed off once: waited %r' % waited)

    # (d) THROTTLED PAST THE CEILING: BINDING_UNESTABLISHED, nothing created, claim untrusted.
    r = _jira_healthy(install(Replay()))
    r.on('POST', r'/rest/api/3/search/jql',
         lambda rec: (429, {'errorMessages': ['rate limited']}, {'Retry-After': '1'}))
    r.on('POST', r'/rest/api/3/issue$', lambda rec: (201, {'id': '1', 'key': 'KIT-1'}, {}))
    waited = _sleeps(rt)
    b = backend(rt, env)
    recs = [rt._rec('trivy', 'CVE-T5', 'go.mod', 'id-t5', aliases=['cve-t5'])]
    res = rt.reconcile(*rt.build_clusters(recs), backend=b, ledger={}, apply_changes=True)
    if any(q['method'] == 'POST' and q['url'].endswith('/rest/api/3/issue') for q in r.requests):
        fails.append('a sweep throttled past the ceiling was followed by a CREATE (T-5)')
    if res['outcomes'].get(rt.BINDING_UNESTABLISHED) != 1:
        fails.append('throttled past the ceiling did not classify %s: %r'
                     % (rt.BINDING_UNESTABLISHED, res['outcomes']))
    if (res.get('ticketing_claim') or {}).get('routing_result') != rt.EVIDENCE_UNTRUSTED:
        fails.append('throttled past the ceiling did not make the claim EVIDENCE_UNTRUSTED')
    if len(waited) != 2:
        fails.append('the retry ceiling of 2 was not honoured: waited %r' % waited)
    if not res.get('throttles') or res.get('calls') is None:
        fails.append('the run record does not carry calls spent and every 429 seen')
    if '429' not in rt.render_summary(res):
        fails.append('the run summary does not state the 429s seen')

    # (e) THE CREATE ITSELF throttled past the ceiling: the obligation is carried, not dropped
    #     into a note, and the claim is untrusted.
    r = _jira_healthy(install(Replay()))
    r.on('POST', r'/rest/api/3/search/jql', ok(page))
    r.on('POST', r'/rest/api/3/issue$', lambda rec: (429, None, {'Retry-After': '1'}))
    _sleeps(rt)
    res = rt.reconcile(*rt.build_clusters(recs), backend=backend(rt, env), ledger={},
                       apply_changes=True)
    if not res.get('obligations') or \
            (res.get('ticketing_claim') or {}).get('routing_result') != rt.EVIDENCE_UNTRUSTED:
        fails.append('a create throttled past the ceiling left no obligation and claim %r'
                     % (res.get('ticketing_claim') or {}).get('routing_result'))


# ── J-1: THE SWEEP ASKS FOR STAMPED TIER-0 ITEMS, NOT THE WHOLE PROJECT ──────────────────

def jira_issue(iid, stamp, status_cat='new', status='To Do'):
    return {'id': str(iid), 'key': 'KIT-%s' % iid,
            'fields': {'customfield_10001': stamp, 'labels': ['secure-cicd-kit', 'sca'],
                       'status': {'name': status, 'statusCategory': {'key': status_cat}}}}


def case_jira_sweep(rt, fails):
    r = _jira_healthy(install(Replay()))
    r.on('POST', r'/rest/api/3/search/jql', ok({'issues': [
        jira_issue(101, 'k1'), jira_issue(102, 'k2', 'done', 'Done')], 'isLast': True}))
    _sleeps(rt)
    m, complete, _d = backend(rt, JIRA_ENV).sweep()
    sent = [q for q in r.requests if q['url'].endswith('/rest/api/3/search/jql')]
    if not sent:
        fails.append('the sweep sent no search request')
        return
    jql = sent[0]['json'].get('jql', '')
    for need in ('project = "KIT"', 'labels = "secure-cicd-kit"', 'issuetype = "Story"'):
        if need not in jql:
            fails.append('the sweep JQL lacks %s, so it sweeps more than the stamped tier-0 '
                         'items: %r (J-1)' % (need, jql))
    if sorted(sent[0]['json'].get('fields') or []) != sorted(['customfield_10001', 'status',
                                                              'labels']):
        fails.append('the sweep requested fields %r; TICKETING_BACKENDS.md 3.3 asks for the stamp '
                     'field, status and labels only' % sent[0]['json'].get('fields'))
    if not complete or sorted(m) != ['k1', 'k2']:
        fails.append('the sweep map was %r (complete %r)' % (sorted(m), complete))
    elif m['k2'][0].get('state') != 'closed' or m['k1'][0].get('state') != 'open':
        fails.append('the sweep did not read status: k1 %r, k2 %r (a Done item must read closed)'
                     % (m['k1'][0].get('state'), m['k2'][0].get('state')))


# ── J-5: READ-AFTER-WRITE CONSISTENCY FOR EXACTLY THE REFERENCES THE LEDGER HOLDS ───────

def case_reconcile_issues(rt, fails):
    """Enhanced search is eventually consistent; `reconcileIssues` buys read-after-write for the
    ids passed. They are the ledger's references -- the set where a false absence costs most."""
    r = _jira_healthy(install(Replay()))
    r.on('POST', r'/rest/api/3/search/jql', ok({'issues': [jira_issue(101, 'k1')],
                                                 'isLast': True}))
    _sleeps(rt)
    recs = [rt._rec('trivy', 'CVE-J5', 'go.mod', 'id-j5', aliases=['cve-j5'])]
    clusters, w = rt.build_clusters(recs)
    ledger = {'k1': {'ref': '101', 'backend': 'jira'}, 'k9': {'ref': '109', 'backend': 'jira'},
              'kx': {'owed': {'outcome': 'BINDING_UNESTABLISHED'}}}
    rt.reconcile(clusters, w, backend(rt, JIRA_ENV), ledger, apply_changes=False)
    sent = [q for q in r.requests if q['url'].endswith('/rest/api/3/search/jql')]
    got = sorted((sent[0]['json'] or {}).get('reconcileIssues') or []) if sent else None
    if got != [101, 109]:
        fails.append('the sweep passed reconcileIssues=%r; expected the ledger\'s numeric ids '
                     '[101, 109] (J-5)' % (got,))


# ── J-2: ONE CREATE CALL SETS EVERYTHING ─────────────────────────────────────────────────

def adf_text(doc):
    """All text nodes of an ADF document, joined by newlines -- what a reader of it would see."""
    out = []

    def walk(n):
        if isinstance(n, dict):
            if n.get('type') == 'text':
                out.append(n.get('text') or '')
            for c in n.get('content') or []:
                walk(c)
    walk(doc)
    return '\n'.join(out)


def _jira_created(r):
    r.on('POST', r'/rest/api/3/search/jql', ok({'issues': [], 'isLast': True}))
    r.on('POST', r'/rest/api/3/issue$', lambda rec: (201, {'id': '20001', 'key': 'KIT-1'}, {}))
    return r


def case_jira_create(rt, fails):
    r = _jira_created(_jira_healthy(install(Replay())))
    _sleeps(rt)
    recs = [rt._rec('trivy', 'CVE-J2', 'go.mod', 'id-j2', aliases=['cve-j2'],
                    subject='SOURCE_DEPENDENCY')]
    clusters, w = rt.build_clusters(recs)
    ledger = {}
    rt.reconcile(clusters, w, backend(rt, JIRA_ENV), ledger, apply_changes=True)
    creates = [q for q in r.requests if q['method'] == 'POST'
               and q['url'].endswith('/rest/api/3/issue')]
    if len(creates) != 1:
        fails.append('expected exactly one create call, saw %d' % len(creates))
        return
    f = (creates[0]['json'] or {}).get('fields') or {}
    key = clusters[0]['cluster_key']
    checks = [
        ((f.get('issuetype') or {}).get('name') == 'Story', 'issuetype is not the tier-0 Story'),
        ('secure-cicd-kit' in (f.get('labels') or []), 'the umbrella label is not set'),
        ('sca' in (f.get('labels') or []), 'the family label (sca) is not set'),
        ((f.get('parent') or {}).get('id') == '10000', 'the parent is not the product epic'),
        (f.get('customfield_10001') == key, 'the stamp field does not carry the cluster key'),
        (isinstance(f.get('description'), dict) and f['description'].get('type') == 'doc',
         'the description is not an ADF document'),
        ('machine-owned block' in adf_text(f.get('description')) and key in adf_text(
            f.get('description')), 'the description does not carry the machine-owned block'),
    ]
    for passed, why in checks:
        if not passed:
            fails.append('jira create: %s (J-2): %r' % (why, sorted(f)))
    if (ledger.get(key) or {}).get('ref') != '20001':
        fails.append('the ledger did not record the NUMERIC id the create returned: %r'
                     % ledger.get(key))
    if any(q['method'] == 'POST' and q['url'].endswith('/search/jql')
           for q in r.requests[r.requests.index(creates[0]):]):
        fails.append('the run searched after it wrote -- Jira search is eventually consistent; '
                     'never read after write')


# ── J-7 / T-11: CONFIGURATION AND SHAPE ARE ESTABLISHED BEFORE ANYTHING IS WRITTEN ────────

def case_jira_shape(rt, fails):
    # (a) Values refused BY NAME when the configuration is read (TICKETING_BACKENDS.md 3.1).
    for label, change, name in (
            ('a host with a path', {'JIRA_HOST': 'https://example.atlassian.net/jira'},
             'JIRA_HOST'),
            ('a host carrying credentials',
             {'JIRA_HOST': 'https://user:pw@example.atlassian.net'}, 'JIRA_HOST'),
            ('a plain-http host', {'JIRA_HOST': 'http://example.atlassian.net'}, 'JIRA_HOST'),
            ('a stamp field that is not customfield_<id>', {'JIRA_STAMP_FIELD': 'Cluster Key'},
             'JIRA_STAMP_FIELD'),
            ('a non-numeric epic id', {'JIRA_EPIC_ID': 'KIT-1'}, 'JIRA_EPIC_ID'),
            ('no epic id', {'JIRA_EPIC_ID': ''}, 'JIRA_EPIC_ID'),
            ('an umbrella label with a space', {'TICKET_STAMP_LABEL': 'secure cicd'},
             'TICKET_STAMP_LABEL'),
            ('no creation ceiling', {'TICKET_CREATE_CEILING': ''}, 'TICKET_CREATE_CEILING'),
            ('a zero creation ceiling', {'TICKET_CREATE_CEILING': '0'},
             'TICKET_CREATE_CEILING')):
        b, note = rt.choose_backend(dict(JIRA_ENV, **change))
        if b is not None or name not in (note or ''):
            fails.append('%s was not refused by name (%s): %r' % (label, name, note))

    # (b) The shape on the site, established at run start. Each failure: NOTHING created or
    #     updated, the obligation carried, the claim untrusted.
    recs = [rt._rec('trivy', 'CVE-J7', 'go.mod', 'id-j7', aliases=['cve-j7'])]
    bad_shapes = [
        ('the stamp field is not on the create screen',
         lambda r: r.on('GET', r'createmeta/KIT/issuetypes/10004$', ok({'fields': [
             {'fieldId': 'summary', 'schema': {'type': 'string'}}]}))),
        ('the stamp field is not single-line text',
         lambda r: r.on('GET', r'createmeta/KIT/issuetypes/10004$', ok({'fields': [
             {'fieldId': 'customfield_10001', 'schema': {'type': 'option'}}]}))),
        ('the cluster issue type does not exist',
         lambda r: r.on('GET', r'createmeta/KIT/issuetypes$', ok({'issueTypes': [
             {'id': '10005', 'name': 'Subtask'}]}))),
        ('the epic is in another project',
         lambda r: r.on('GET', r'/rest/api/3/issue/10000\b', ok({'id': '10000', 'fields': {
             'project': {'key': 'OTHER'}}}))),
        ('createmeta could not be read',
         lambda r: r.on('GET', r'createmeta/KIT/issuetypes$',
                        lambda rec: (403, {'errorMessages': ['no']}, {}))),
    ]
    for label, breaker in bad_shapes:
        r = _jira_created(_jira_healthy(install(Replay())))
        breaker(r)
        _sleeps(rt)
        res = rt.reconcile(*rt.build_clusters(recs), backend=backend(rt, JIRA_ENV), ledger={},
                           apply_changes=True)
        wrote = [q for q in r.requests if q['method'] in ('POST', 'PUT')
                 and not q['url'].endswith('/search/jql')]
        if wrote:
            fails.append('%s: the run still wrote %d request(s) (J-7)' % (label, len(wrote)))
        if (res.get('ticketing_claim') or {}).get('routing_result') != rt.EVIDENCE_UNTRUSTED \
                or not res.get('obligations'):
            fails.append('%s: claim %r with %d obligation(s); expected EVIDENCE_UNTRUSTED with '
                         'the obligation carried (J-7)'
                         % (label, (res.get('ticketing_claim') or {}).get('routing_result'),
                            len(res.get('obligations') or [])))

    # (d) R-1 FOUND LIVE, 2026-10-15: Jira Cloud answers a BAD TOKEN as an anonymous caller, so the
    #     project read is a 404, not a 401 -- and the refusal named JIRA_PROJECT for a broken
    #     JIRA_TOKEN. The credential is established FIRST (/myself), so each value is named by
    #     its own failure; the control shows a good credential still names a missing project.
    for label, myself_status, want, not_want in (
            ('a bad token (Jira: /myself 401, project 404)', 401, 'JIRA_TOKEN', 'JIRA_PROJECT'),
            ('a good token and a missing project', 200, 'JIRA_PROJECT', 'JIRA_TOKEN')):
        r = install(Replay())
        r.on('GET', r'/rest/api/3/myself$',
             lambda rec, s=myself_status: (s, {'accountId': 'x'} if s == 200 else
                                           {'errorMessages': ['unauthorized']}, {}))
        r.on('GET', r'/rest/api/3/project/KIT$', lambda rec: (404, {'errorMessages': ['no']}, {}))
        ok_v, detail = backend(rt, JIRA_ENV).validate()
        if ok_v or want not in (detail or '') or not_want in (detail or ''):
            fails.append('R-1 %s: refusal must name %s and not %s, got ok=%r %r'
                         % (label, want, not_want, ok_v, detail))

    # (c) The valid counterpart: the healthy shape creates.
    r = _jira_created(_jira_healthy(install(Replay())))
    _sleeps(rt)
    res = rt.reconcile(*rt.build_clusters(recs), backend=backend(rt, JIRA_ENV), ledger={},
                       apply_changes=True)
    if len(res.get('created') or []) != 1:
        fails.append('a healthy site shape did not create: %r' % res.get('outcomes'))


# ── J-6 / T-7 / T-8: REOPEN BY A NAMED TRANSITION; AN EMPTY LIST IS THE SUCCESSOR PATH ─────

def case_jira_reopen(rt, fails):
    env = dict(JIRA_ENV, JIRA_TRANSITION_REOPEN='Reopen')
    recs = [rt._rec('trivy', 'CVE-J6', 'go.mod', 'id-j6', aliases=['cve-j6'])]
    for label, transitions, want_post, want_successor in (
            ('the named transition is offered',
             {'transitions': [{'id': '31', 'name': 'Done'}, {'id': '41', 'name': 'Reopen'}]},
             True, False),
            ('an EMPTY transitions list (not permitted and not applicable look the same)',
             {'transitions': []}, False, True),
            ('the named transition is absent', {'transitions': [{'id': '31', 'name': 'Done'}]},
             False, True)):
        clusters, _w = rt.build_clusters(recs)
        key = clusters[0]['cluster_key']
        r = _jira_created(_jira_healthy(install(Replay())))
        r.on('POST', r'/rest/api/3/search/jql', ok({'issues': [
            jira_issue(301, key, 'done', 'Done')], 'isLast': True}))
        r.on('GET', r'/rest/api/3/issue/301/transitions$', ok(transitions))
        r.on('POST', r'/rest/api/3/issue/301/transitions$', lambda rec: (204, None, {}))
        r.on('POST', r'/rest/api/3/issue/301/comment$', lambda rec: (201, {'id': '1'}, {}))
        _sleeps(rt)
        ledger = {key: {'ref': '301', 'backend': 'jira', 'member_identities': ['id-j6']}}
        res = rt.reconcile(clusters, [], backend(rt, env), ledger, apply_changes=True,
                           today='2026-10-14')
        posts = [q for q in r.requests if q['method'] == 'POST'
                 and q['url'].endswith('/issue/301/transitions')]
        creates = [q for q in r.requests if q['method'] == 'POST'
                   and q['url'].endswith('/rest/api/3/issue')]
        if bool(posts) != want_post:
            fails.append('%s: transition posted=%r, expected %r (J-6)' % (label, bool(posts),
                                                                         want_post))
        if posts and (posts[0]['json'] or {}).get('transition', {}).get('id') != '41':
            fails.append('%s: posted transition %r, not the id named Reopen'
                         % (label, posts[0]['json']))
        if bool(creates) != want_successor:
            fails.append('%s: successor created=%r, expected %r (T-8)'
                         % (label, bool(creates), want_successor))
        # T-08: a reopen says why, as one ADF comment on the reopened ticket.
        comments = [q for q in r.requests if q['method'] == 'POST'
                    and q['url'].endswith('/issue/301/comment')]
        if want_post and (len(comments) != 1 or 'unbacked' not in adf_text(
                (comments[0]['json'] or {}).get('body'))):
            fails.append('%s: the reopen posted %d comment(s); expected one naming %r (T-08)'
                         % (label, len(comments), 'unbacked'))
        if want_successor and 'why it was reopened' not in (adf_text(
                (creates[0]['json'] or {}).get('fields', {}).get('description')) if creates
                else ''):
            fails.append('%s: the successor does not say why its predecessor needed reopening '
                         '(T-08)' % label)
        if want_successor:
            entry = ledger.get(key) or {}
            if entry.get('ref') != '20001' or '301' not in (entry.get('predecessors') or []):
                fails.append('%s: the ledger does not bind the successor and keep the '
                             'predecessor: %r' % (label, entry))
            if 'DISTINCTION_NOT_OBSERVABLE' not in json.dumps(entry) and not transitions[
                    'transitions']:
                fails.append('%s: the refusal reason does not say an empty list is ambiguous'
                             % label)
            body = adf_text((creates[0]['json'] or {}).get('fields', {}).get('description')) \
                if creates else ''
            if '301' not in body:
                fails.append('%s: the successor does not reference its predecessor' % label)


# ── J-8: INSTANCES ARE SUBTASKS UNDER THE TIER-0 ITEM, UP TO A PER-CLASS THRESHOLD ─────────

def case_jira_instances(rt, fails):
    recs = [rt._rec('trivy', 'CVE-J8', 'go.mod', 'id-j8a', aliases=['cve-j8']),
            rt._rec('grype', 'GHSA-J8', 'go.mod', 'id-j8b', aliases=['cve-j8']),
            rt._rec('osv', 'CVE-J8', 'go.mod', 'id-j8c', aliases=['cve-j8'])]
    for label, threshold, want in (('threshold 2, three instances', '2', 2),
                                   ('threshold unset', None, 0)):
        env = dict(JIRA_ENV)
        if threshold is not None:
            env['TICKET_INSTANCE_THRESHOLD'] = threshold
        r = _jira_healthy(install(Replay()))
        r.on('POST', r'/rest/api/3/search/jql', ok({'issues': [], 'isLast': True}))
        made = []

        def create(rec):
            made.append(rec['json'])
            n = 20001 + len(made) - 1
            return 201, {'id': str(n), 'key': 'KIT-%d' % n}, {}
        r.on('POST', r'/rest/api/3/issue$', create)
        _sleeps(rt)
        clusters, w = rt.build_clusters(recs)
        ledger = {}
        res = rt.reconcile(clusters, w, backend(rt, env), ledger, apply_changes=True)
        tier0 = [m for m in made if (m['fields'].get('issuetype') or {}).get('name') == 'Story']
        subs = [m for m in made if (m['fields'].get('issuetype') or {}).get('name') == 'Subtask']
        if len(tier0) != 1 or len(subs) != want:
            fails.append('%s: %d tier-0 and %d instance(s) created, expected 1 and %d (J-8)'
                         % (label, len(tier0), len(subs), want))
            continue
        for s in subs:
            if (s['fields'].get('parent') or {}).get('id') != '20001':
                fails.append('%s: an instance is not under its tier-0 item: %r'
                             % (label, s['fields'].get('parent')))
            if 'customfield_10001' in s['fields']:
                fails.append('%s: an instance carries the stamp; the stamp lives on the tier-0 '
                             'item only' % label)
        entry = ledger.get(clusters[0]['cluster_key']) or {}
        if len(entry.get('instances') or {}) != want or \
                entry.get('instances_not_itemised') != 3 - want:
            fails.append('%s: the ledger records %r instances and %r not itemised; expected %d '
                         'and %d' % (label, len(entry.get('instances') or {}),
                                     entry.get('instances_not_itemised'), want, 3 - want))


# ── A-1: AZURE DEVOPS BOARDS, SECTION 4 ──────────────────────────────────────────────────

AZDO = 'https://dev.azure.com/example'
AZDO_KW = dict(org_url=AZDO, project='kit', pat='placeholder-pat',
               stamp_field='Custom.KitClusterKey', epic_id='1', calibration='2',
               stamp_label='secure-cicd-kit', create_ceiling=25)


def azdo_item(i, stamp=None, state='To Do', tags='secure-cicd-kit; sca', project='kit'):
    f = {'System.Id': i, 'System.State': state, 'System.Tags': tags,
         'System.TeamProject': project}
    if stamp is not None:
        f['Custom.KitClusterKey'] = stamp
    return {'id': i, 'fields': f}


class AzdoTracker(object):
    """A STATEFUL stand-in for one Azure DevOps project, speaking the documented shapes: WIQL
    returns ids only, workitemsbatch returns fields for at most 200 ids, create takes a JSON
    Patch. State persists across runs, so idempotency can be proven against it (T-1)."""

    def __init__(self, replay, wiql_ids=None):
        self.items = {1: azdo_item(1, tags='', state='Doing'), 2: azdo_item(2, tags='bug')}
        self.next_id = 500
        self.batches = []
        self.wiql_ids = wiql_ids
        self.patches = []
        self.refuse_state = False
        # Work item revisions (the documented `rev`), and ids whose read answers 500.
        self.revs = {}
        self.unreadable = set()
        base = r'^https://dev\.azure\.com/example'
        replay.on('GET', base + r'/_apis/projects/kit\?', ok({'id': 'p1', 'name': 'kit'}))
        replay.on('GET', base + r'/kit/_apis/wit/workitemtypes\?', ok({'value': [
            {'name': 'Epic'}, {'name': 'Issue'}, {'name': 'Task'}]}))
        replay.on('GET', base + r'/kit/_apis/wit/workitemtypes/Issue/fields\?', ok({'value': [
            {'referenceName': 'System.Title', 'type': 'string'},
            {'referenceName': 'Custom.KitClusterKey', 'type': 'string'}]}))
        replay.on('GET', base + r'/kit/_apis/wit/workitemtypes/Issue/states\?', ok({'value': [
            {'name': 'To Do'}, {'name': 'Doing'}, {'name': 'Done'}]}))
        replay.on('GET', base + r'/kit/_apis/wit/workitems/(\d+)\?', self._get)
        replay.on('POST', base + r'/kit/_apis/wit/wiql\?', self._wiql)
        replay.on('POST', base + r'/kit/_apis/wit/workitemsbatch\?', self._batch)
        replay.on('POST', base + r'/kit/_apis/wit/workitems/\$(\w+)\?', self._create)
        replay.on('PATCH', base + r'/kit/_apis/wit/workitems/(\d+)\?', self._patch)
        self.comments = []
        replay.on('POST', base + r'/kit/_apis/wit/workItems/(\d+)/comments\?', self._comment)

    def _comment(self, rec):
        i = int(re.search(r'/workItems/(\d+)/comments', rec['url']).group(1))
        self.comments.append((i, (rec['json'] or {}).get('text') or ''))
        return 200, {'id': len(self.comments), 'workItemId': i}, {}

    def _get(self, rec):
        i = int(re.search(r'/workitems/(\d+)', rec['url']).group(1))
        if i in self.unreadable:
            return 500, {'message': 'internal'}, {}
        if i not in self.items:
            return 404, {'message': 'nf'}, {}
        item = dict(self.items[i])
        item.setdefault('rev', self.revs.get(i, 1))
        return 200, item, {}

    def _wiql(self, rec):
        q = rec['json']['query']
        last = int((re.search(r'\[System\.Id\] > (\d+)', q) or [0, 0])[1])
        self.wiql_calls = getattr(self, 'wiql_calls', 0) + 1
        if self.wiql_ids is not None:
            ids = [i for i in self.wiql_ids if i > last][:20000]
        else:
            ids = sorted(i for i, it in self.items.items()
                         if i > last and 'secure-cicd-kit' in it['fields'].get('System.Tags', '')
                         and it['fields'].get('Custom.KitClusterKey'))
        return 200, {'workItems': [{'id': i} for i in ids]}, {}

    def _batch(self, rec):
        ids = rec['json']['ids']
        self.batches.append(len(ids))
        if len(ids) > 200:
            return 400, {'message': 'too many ids'}, {}
        return 200, {'value': [self.items.get(i) or azdo_item(i, stamp='k%d' % i)
                               for i in ids]}, {}

    def _create(self, rec):
        ops = rec['json']
        f = dict((o['path'][len('/fields/'):], o['value']) for o in ops
                 if o['path'].startswith('/fields/'))
        i = self.next_id
        self.next_id += 1
        # Microsoft.VSTS.Common.Priority defaults to 2 on the Basic process's Issue and Task.
        self.items[i] = {'id': i, 'fields': dict({'Microsoft.VSTS.Common.Priority': 2}, **dict(
            f, **{'System.Id': i, 'System.State': 'To Do'})),
            'ops': ops, 'type': re.search(r'\$(\w+)', rec['url']).group(1)}
        return 200, {'id': i, 'fields': self.items[i]['fields']}, {}

    def _patch(self, rec):
        i = int(re.search(r'/workitems/(\d+)', rec['url']).group(1))
        self.patches.append(rec['json'])
        if self.refuse_state and any(o['path'] == '/fields/System.State' for o in rec['json']):
            return 400, {'message': 'TF401320: Rule Error for field State'}, {}
        # JSON Patch `test` on /rev: the documented optimistic-concurrency guard. A mismatch is
        # refused and NOTHING in the patch is applied.
        rev = self.revs.get(i, 1)
        for o in rec['json']:
            if o.get('op') == 'test' and o.get('path') == '/rev' and o.get('value') != rev:
                return 412, {'message': 'TF26071: the work item has been updated by someone '
                                        'else'}, {}
        for o in rec['json']:
            if o.get('op') in ('add', 'replace') and o['path'].startswith('/fields/'):
                self.items[i]['fields'][o['path'][len('/fields/'):]] = o['value']
        self.revs[i] = rev + 1
        return 200, self.items[i], {}


def case_azdo(rt, fails):
    if not hasattr(rt, 'AzureDevOps'):
        fails.append('there is no AzureDevOps(TicketBackend) at all (A-1)')
        return
    _sleeps(rt)
    # Probe: a foreign, unstamped item resolves -> observable; one of ours -> not.
    r = install(Replay())
    t = AzdoTracker(r)
    if not rt.AzureDevOps(**AZDO_KW).probe()[0]:
        fails.append('azdo probe: a known-present foreign work item did not calibrate the channel')
    t.items[2] = azdo_item(2, stamp='k-ours')
    if rt.AzureDevOps(**AZDO_KW).probe()[0]:
        fails.append('azdo probe: a STAMPED calibration item calibrated the channel (L54)')
    if any('placeholder-pat' in q['url'] for q in r.requests):
        fails.append('the PAT appeared in a request URL')
    auth = [q['headers'].get('authorization', '') for q in r.requests]
    if not auth or not all(a.startswith('Basic ') for a in auth):
        fails.append('azdo requests do not carry Basic auth with the PAT')

    # Run-start shape: healthy ok; a missing stamp field refuses.
    r = install(Replay())
    AzdoTracker(r)
    ok_v, d_v = rt.AzureDevOps(**AZDO_KW).validate()
    if not ok_v:
        fails.append('azdo validate refused a healthy shape: %s' % d_v)
    r.on('GET', r'/kit/_apis/wit/workitemtypes/Issue/fields\?', ok({'value': [
        {'referenceName': 'System.Title', 'type': 'string'}]}))
    ok_v, d_v = rt.AzureDevOps(**AZDO_KW).validate()
    if ok_v or 'Custom.KitClusterKey' not in d_v:
        fails.append('azdo validate accepted a type without the stamp field: %s' % d_v)

    # Sweep: WIQL ids, then workitemsbatch in chunks of at most 200; exact tag match.
    r = install(Replay())
    t = AzdoTracker(r, wiql_ids=list(range(1000, 1250)))
    m, complete, d = rt.AzureDevOps(**AZDO_KW).sweep()
    if sorted(t.batches) != [50, 200]:
        fails.append('the batch read was chunked %r, not [200, 50] (the documented max is 200)'
                     % sorted(t.batches))
    if not complete or len(m) != 250:
        fails.append('a 250-item sweep returned %d stamps, complete=%r: %s' % (len(m), complete,
                                                                              d))
    wiql = [q for q in r.requests if '/_apis/wit/wiql' in q['url']][0]['json']['query']
    for need in ("[System.TeamProject] = @project", "[System.WorkItemType] = 'Issue'",
                 "[System.Tags] CONTAINS 'secure-cicd-kit'", 'ORDER BY [System.Id]'):
        if need not in wiql:
            fails.append('the WIQL lacks %s: %r' % (need, wiql))

    # THE WIQL CAP: a result count at the cap is PARTIAL, never complete.
    r = install(Replay())
    t = AzdoTracker(r, wiql_ids=list(range(10, 20015)))
    m, complete, d = rt.AzureDevOps(**AZDO_KW).sweep()
    if complete:
        fails.append('a WIQL result AT the 20,000 cap was read as a complete sweep (A-1, T-4)')
    if t.wiql_calls != 2 or len(m) != 20005:
        fails.append('at the cap the sweep did not page on by [System.Id] > last: %d WIQL '
                     'call(s), %d item(s) seen of 20005' % (t.wiql_calls, len(m)))

    # A tag that merely CONTAINS the umbrella is not the umbrella (WIQL CONTAINS is substring).
    r = install(Replay())
    t = AzdoTracker(r, wiql_ids=[700, 701])
    t.items[700] = azdo_item(700, stamp='k700', tags='secure-cicd-kit-old')
    t.items[701] = azdo_item(701, stamp='k701', tags='secure-cicd-kit', state='Done')
    m, _c, _d = rt.AzureDevOps(**AZDO_KW).sweep()
    if 'k700' in m or 'k701' not in m:
        fails.append('the sweep did not match the umbrella TAG exactly: %r' % sorted(m))
    elif m['k701'][0].get('state') != 'closed':
        fails.append('a Done work item did not read closed')

    # Create: one JSON Patch call with title, tags, stamp, HTML description, parent relation.
    r = install(Replay())
    t = AzdoTracker(r)
    b = rt.AzureDevOps(**AZDO_KW)
    recs = [rt._rec('trivy', 'CVE-A1', 'go.mod', 'id-a1', aliases=['cve-a1'],
                    subject='SOURCE_DEPENDENCY')]
    clusters, w = rt.build_clusters(recs)
    ledger = {}
    rt.reconcile(clusters, w, b, ledger, apply_changes=True)
    creates = [q for q in r.requests if re.search(r'/workitems/\$Issue', q['url'])]
    if len(creates) != 1:
        fails.append('azdo: %d create call(s), expected 1' % len(creates))
    else:
        c = creates[0]
        ops = dict((o['path'], o['value']) for o in c['json'] if o['op'] == 'add')
        if c['headers'].get('content-type') != 'application/json-patch+json':
            fails.append('azdo create is not sent as application/json-patch+json')
        if ops.get('/fields/Custom.KitClusterKey') != clusters[0]['cluster_key']:
            fails.append('azdo create does not set the stamp field')
        if 'secure-cicd-kit' not in str(ops.get('/fields/System.Tags')) or \
                'sca' not in str(ops.get('/fields/System.Tags')):
            fails.append('azdo create does not tag umbrella and family: %r'
                         % ops.get('/fields/System.Tags'))
        if 'machine-owned block' not in str(ops.get('/fields/System.Description')):
            fails.append('azdo create does not carry the block in System.Description')
        rel = ops.get('/relations/-') or {}
        if rel.get('rel') != 'System.LinkTypes.Hierarchy-Reverse' or \
                not str(rel.get('url', '')).endswith('/_apis/wit/workItems/1'):
            fails.append('azdo create has no parent relation to the epic: %r' % rel)
    if (ledger.get(clusters[0]['cluster_key']) or {}).get('ref') != '500':
        fails.append('the ledger did not record the created work item id')

    # Reopen: a state write; a process-rule refusal takes the successor path.
    for label, refuse, want_successor in (('state write accepted', False, False),
                                          ('state write refused by a rule', True, True)):
        r = install(Replay())
        t = AzdoTracker(r)
        t.refuse_state = refuse
        clusters, w = rt.build_clusters(recs)
        key = clusters[0]['cluster_key']
        t.items[600] = azdo_item(600, stamp=key, state='Done')
        led = {key: {'ref': '600', 'backend': 'azdo', 'member_identities': ['id-a1']}}
        res = rt.reconcile(clusters, w, rt.AzureDevOps(**AZDO_KW), led, apply_changes=True,
                           today='2026-10-14')
        if bool(res.get('successors')) != want_successor:
            fails.append('azdo reopen, %s: successors %r' % (label, res.get('successors')))
        if not refuse and t.items[600]['fields'].get('System.State') != 'To Do':
            fails.append('azdo reopen did not write the reopen state')
        # T-08: the reopen says why, as one comment on the work item.
        if not refuse and not any(i == 600 and 'unbacked' in text
                                  for i, text in t.comments):
            fails.append('azdo reopen posted no comment naming %r (T-08): %r'
                         % ('unbacked', t.comments))

    # Slowing down BEFORE being delayed: a Retry-After on a SUCCESSFUL response is honoured.
    r = install(Replay())
    AzdoTracker(r)
    r.on('POST', r'/_apis/wit/wiql\?', lambda rec: (200, {'workItems': []},
                                                     {'Retry-After': '3',
                                                      'X-RateLimit-Remaining': '5'}))
    waited = _sleeps(rt)
    rt.AzureDevOps(**AZDO_KW).sweep()
    if waited != [3]:
        fails.append('an advisory Retry-After on a 200 was not honoured before the next call: '
                     'waited %r' % waited)


# ── C-2: choose_backend ACCEPTS azdo AND REFUSES TWO AT ONCE ─────────────────────────────

AZDO_ENV = {'TICKET_BACKEND': 'azdo', 'AZDO_ORG_URL': 'https://dev.azure.com/example',
            'AZDO_PROJECT': 'kit', 'AZDO_PAT': 'placeholder-pat',
            'AZDO_STAMP_FIELD': 'Custom.KitClusterKey', 'AZDO_EPIC_ID': '1',
            'AZDO_CALIBRATION_ITEM': '2', 'TICKET_CREATE_CEILING': '25'}


def case_choose(rt, fails):
    for label, env in (('the dev.azure.com form', AZDO_ENV),
                       ('the legacy visualstudio.com form',
                        dict(AZDO_ENV, AZDO_ORG_URL='https://example.visualstudio.com')),
                       ('the older AZDO_ORG name',
                        dict(dict((k, v) for k, v in AZDO_ENV.items() if k != 'AZDO_ORG_URL'),
                             AZDO_ORG='https://dev.azure.com/example'))):
        b, note = rt.choose_backend(env)
        if b is None or getattr(b, 'name', '') != 'azdo':
            fails.append('azdo was not selected from %s: %r (C-2)' % (label, note))
    for label, change, name in (
            ('an org URL with no organisation', {'AZDO_ORG_URL': 'https://dev.azure.com'},
             'AZDO_ORG_URL'),
            ('an org URL with a project path',
             {'AZDO_ORG_URL': 'https://dev.azure.com/example/kit'}, 'AZDO_ORG_URL'),
            ('a plain-http org URL', {'AZDO_ORG_URL': 'http://dev.azure.com/example'},
             'AZDO_ORG_URL'),
            ('an org URL on another host', {'AZDO_ORG_URL': 'https://example.invalid/example'},
             'AZDO_ORG_URL'),
            ('a stamp field that is not a reference name', {'AZDO_STAMP_FIELD': 'Cluster Key'},
             'AZDO_STAMP_FIELD'),
            ('a non-numeric epic', {'AZDO_EPIC_ID': 'EPIC'}, 'AZDO_EPIC_ID'),
            ('no PAT', {'AZDO_PAT': ''}, 'AZDO_PAT')):
        b, note = rt.choose_backend(dict(AZDO_ENV, **change))
        if b is not None or name not in (note or ''):
            fails.append('%s was not refused by name (%s): %r (C-2, T-11)' % (label, name, note))
    # TWO AT ONCE is a policy defect (TC 4.6), refused by name -- with or without a selector.
    both = dict(JIRA_ENV, **dict((k, v) for k, v in AZDO_ENV.items() if k != 'TICKET_BACKEND'))
    for sel in ('', 'azdo', 'jira'):
        env = dict(both, TICKET_BACKEND=sel) if sel else dict(
            (k, v) for k, v in both.items() if k != 'TICKET_BACKEND')
        b, note = rt.choose_backend(env)
        if b is not None or 'CONFIGURATION DEFECT' not in (note or ''):
            fails.append('jira and azdo both configured (selector %r) were not refused by name: %r'
                         % (sel, note))


# ── X-1: THE DESIGN'S T-TESTS, PER BACKEND, AGAINST STATEFUL STAND-INS ────────────────────

class JiraTracker(object):
    """A STATEFUL stand-in for one Jira project: search honours the JQL's label and type clauses,
    create stores, transitions move status. Documented shapes only."""

    def __init__(self, replay, page_size=100, fail_page=None):
        self.issues = {}
        self.next_id = 30001
        self.page_size = page_size
        self.fail_page = fail_page
        self.searches = 0
        # Issue ids whose description read answers 500 (TC 5.4: unreadable is never a blind write).
        self.unreadable = set()
        self.puts = []
        # KDEC-024 (lane L-TKT): the lifecycle half of a Jira project -- comments, the workflow's
        # transitions (Done out of an open status, Reopen out of a done one) and priority. A
        # transition list is per issue and per status, as Jira documents it.
        self.comments = []
        self.transitions_posted = []
        self.refuse_reopen = False
        _jira_healthy(replay)
        replay.on('POST', r'/rest/api/3/search/jql$', self._search)
        replay.on('POST', r'/rest/api/3/issue$', self._create)
        replay.on('PUT', r'/rest/api/3/issue/\d+$', self._put)
        replay.on('GET', r'/rest/api/3/issue/\d+\?fields=description$', self._get_description)
        replay.on('GET', r'/rest/api/3/issue/\d+\?fields=priority,labels$', self._get_priority)
        replay.on('POST', r'/rest/api/3/issue/\d+/comment$', self._comment)
        replay.on('GET', r'/rest/api/3/issue/\d+/transitions$', self._transitions)
        replay.on('POST', r'/rest/api/3/issue/\d+/transitions$', self._transition)

    @staticmethod
    def _id(rec):
        return re.search(r'/issue/(\d+)', rec['url']).group(1)

    def status_of(self, i):
        return ((self.issues.get(str(i)) or {}).get('fields') or {}).get('status') or {}

    def _comment(self, rec):
        i = self._id(rec)
        if i not in self.issues:
            return 404, {'errorMessages': ['Issue does not exist']}, {}
        self.comments.append((i, adf_text((rec['json'] or {}).get('body'))))
        return 201, {'id': str(len(self.comments))}, {}

    def _transitions(self, rec):
        i = self._id(rec)
        if i not in self.issues:
            return 404, {'errorMessages': ['Issue does not exist']}, {}
        done = (self.status_of(i).get('statusCategory') or {}).get('key') == 'done'
        if done:
            offered = [] if self.refuse_reopen else [
                {'id': '41', 'name': 'Reopen', 'to': {'name': 'To Do',
                                                      'statusCategory': {'key': 'new'}}}]
        else:
            offered = [{'id': '21', 'name': 'In Progress',
                        'to': {'name': 'In Progress', 'statusCategory': {'key': 'indeterminate'}}},
                       {'id': '31', 'name': 'Done', 'to': {'name': 'Done',
                                                          'statusCategory': {'key': 'done'}}}]
        return 200, {'transitions': offered}, {}

    def _transition(self, rec):
        i = self._id(rec)
        tid = str(((rec['json'] or {}).get('transition') or {}).get('id'))
        self.transitions_posted.append((i, tid))
        to = {'31': ('Done', 'done'), '41': ('To Do', 'new'),
              '21': ('In Progress', 'indeterminate')}.get(tid)
        if i not in self.issues or to is None:
            return 400, {'errorMessages': ['transition not valid']}, {}
        self.issues[i]['fields']['status'] = {'name': to[0], 'statusCategory': {'key': to[1]}}
        return 204, None, {}

    def _get_priority(self, rec):
        i = self._id(rec)
        if i not in self.issues:
            return 404, {'errorMessages': ['Issue does not exist']}, {}
        f = self.issues[i]['fields']
        return 200, {'id': i, 'fields': {'priority': {'name': f.get('priority') or 'Medium'},
                                         'labels': list(f.get('labels') or [])}}, {}

    def _get_description(self, rec):
        i = re.search(r'/issue/(\d+)\?', rec['url']).group(1)
        if i in self.unreadable:
            return 500, {'errorMessages': ['internal']}, {}
        if i not in self.issues:
            return 404, {'errorMessages': ['Issue does not exist']}, {}
        return 200, {'id': i, 'fields': {
            'description': self.issues[i].get('description')}}, {}

    def _put(self, rec):
        i = re.search(r'/issue/(\d+)$', rec['url']).group(1)
        self.puts.append(rec['json'])
        f = (rec['json'] or {}).get('fields') or {}
        if i in self.issues and 'description' in f:
            self.issues[i]['description'] = f['description']
        if i in self.issues and 'priority' in f:
            self.issues[i]['fields']['priority'] = (f['priority'] or {}).get('name')
        for op in (((rec['json'] or {}).get('update') or {}).get('labels') or []):
            if i in self.issues and op.get('add'):
                labels = self.issues[i]['fields'].setdefault('labels', [])
                if op['add'] not in labels:
                    labels.append(op['add'])
        return 204, None, {}

    def _search(self, rec):
        self.searches += 1
        body = rec['json']
        label = re.search(r'labels = "([^"]+)"', body['jql']).group(1)
        itype = re.search(r'issuetype = "([^"]+)"', body['jql']).group(1)
        hits = [i for i in sorted(self.issues.values(), key=lambda x: int(x['id']))
                if label in i['fields']['labels'] and i['type'] == itype]
        start = int(body.get('nextPageToken') or 0)
        page = hits[start:start + self.page_size]
        if self.fail_page is not None and start // self.page_size == self.fail_page:
            return 500, {'errorMessages': ['internal']}, {}
        doc = {'issues': page, 'isLast': start + self.page_size >= len(hits)}
        if not doc['isLast']:
            doc['nextPageToken'] = str(start + self.page_size)
        return 200, doc, {}

    def _create(self, rec):
        f = rec['json']['fields']
        i = str(self.next_id)
        self.next_id += 1
        self.issues[i] = {'id': i, 'key': 'KIT-%s' % i, 'type': f['issuetype']['name'],
                          'fields': {'customfield_10001': f.get('customfield_10001'),
                                     'labels': f.get('labels') or [],
                                     'status': {'name': 'To Do',
                                                'statusCategory': {'key': 'new'}}},
                          'description': f.get('description')}
        return 201, {'id': i, 'key': 'KIT-%s' % i}, {}


class GitHubTracker(object):
    """A STATEFUL stand-in for one GitHub repository's issues (KDEC-024, lane L-TKT): the list
    endpoint filtered by label and paged at 100, create with labels in the same call, PATCH for
    body and state, comments, and labels added to an issue. Documented shapes only."""

    def __init__(self, replay, repo='o/r'):
        self.issues = {7: {'number': 7, 'state': 'open', 'labels': [{'name': 'bug'}],
                           'body': 'a foreign issue', 'title': 'calibration'}}
        self.next_number = 100
        self.comments = []
        self.patches = []
        base = r'^https://api\.github\.com/repos/' + re.escape(repo)
        replay.on('GET', base + r'$', ok({'has_issues': True}))
        replay.on('GET', base + r'/issues/(\d+)$', self._get)
        replay.on('GET', base + r'/issues\?', self._list)
        replay.on('POST', base + r'/issues$', self._create)
        replay.on('PATCH', base + r'/issues/(\d+)$', self._patch)
        replay.on('POST', base + r'/issues/(\d+)/comments$', self._comment)
        replay.on('POST', base + r'/issues/(\d+)/labels$', self._labels)

    @staticmethod
    def _n(rec):
        return int(re.search(r'/issues/(\d+)', rec['url']).group(1))

    def _get(self, rec):
        n = self._n(rec)
        if n not in self.issues:
            return 404, {'message': 'Not Found'}, {}
        return 200, dict(self.issues[n], url='https://api.github.com/x/%d' % n), {}

    def _list(self, rec):
        label = re.search(r'labels=([^&]+)', rec['url']).group(1)
        page = int(re.search(r'[?&]page=(\d+)', rec['url']).group(1))
        hits = [i for _n, i in sorted(self.issues.items())
                if label in [lb['name'] for lb in i['labels']]]
        return 200, [dict(i, url='https://api.github.com/x/%d' % i['number'], node_id='N%d'
                          % i['number']) for i in hits[(page - 1) * 100:page * 100]], {}

    def _create(self, rec):
        body = rec['json'] or {}
        n = self.next_number
        self.next_number += 1
        self.issues[n] = {'number': n, 'state': 'open', 'title': body.get('title'),
                          'body': body.get('body') or '',
                          'labels': [{'name': x} for x in body.get('labels') or []]}
        return 201, dict(self.issues[n]), {}

    def _patch(self, rec):
        n = self._n(rec)
        self.patches.append((n, rec['json']))
        if n not in self.issues:
            return 404, {'message': 'Not Found'}, {}
        for k in ('state', 'body', 'state_reason'):
            if k in (rec['json'] or {}):
                self.issues[n][k] = rec['json'][k]
        return 200, dict(self.issues[n]), {}

    def _comment(self, rec):
        n = self._n(rec)
        if n not in self.issues:
            return 404, {'message': 'Not Found'}, {}
        self.comments.append((n, (rec['json'] or {}).get('body') or ''))
        return 201, {'id': len(self.comments)}, {}

    def _labels(self, rec):
        n = self._n(rec)
        if n not in self.issues:
            return 404, {'message': 'Not Found'}, {}
        for x in (rec['json'] or {}).get('labels') or []:
            if x not in [lb['name'] for lb in self.issues[n]['labels']]:
                self.issues[n]['labels'].append({'name': x})
        return 200, self.issues[n]['labels'], {}


def _jira_backend(rt, r, **change):
    return backend(rt, dict(JIRA_ENV, **change))


def case_t_matrix(rt, fails):
    """T-1 two runs, same tickets; T-2 a narrowed membership, no duplicate; T-3 probe fails, no
    create; T-4 partial sweep (page cap / mid-sweep error), no create; T-6 two stamped tickets,
    nothing created or updated, every candidate named -- on Jira AND Azure DevOps."""
    a = rt._rec('trivy', 'CVE-X1', 'go.mod', 'id-x1a', aliases=['cve-x1', 'ghsa-x1'])
    b = rt._rec('grype', 'GHSA-X1', 'go.mod', 'id-x1b', aliases=['ghsa-x1'])
    _sleeps(rt)

    def jira():
        r = install(Replay())
        return r, JiraTracker(r), lambda: _jira_backend(rt, r)

    def azdo():
        r = install(Replay())
        return r, AzdoTracker(r), lambda: rt.AzureDevOps(**AZDO_KW)

    def count(tracker):
        if isinstance(tracker, JiraTracker):
            return sum(1 for i in tracker.issues.values() if i['type'] == 'Story')
        return sum(1 for i in tracker.items.values() if i.get('type') == 'Issue')

    for name, make in (('jira', jira), ('azdo', azdo)):
        # T-1 and T-2: join, repeat, narrow -- ONE ticket throughout, with the ledger carried.
        r, t, mk = make()
        ledger = {}
        for members in ([a], [a, b], [a, b], [b]):
            rt.reconcile(*rt.build_clusters(members), backend=mk(), ledger=ledger,
                         apply_changes=True, today='2026-10-14')
        if count(t) != 1:
            fails.append('%s T-1/T-2: one obligation over four runs (join, repeat, narrow) made %d '
                         'tickets' % (name, count(t)))

        # T-3: the calibration probe fails -> no not-found licenses a creation.
        r, t, mk = make()
        if name == 'jira':
            r.on('GET', r'/rest/api/3/issue/10002', lambda rec: (404, {'errorMessages': []}, {}))
        else:
            t.items.pop(2)
        res = rt.reconcile(*rt.build_clusters([a]), backend=mk(), ledger={}, apply_changes=True)
        if count(t) or res['outcomes'].get(rt.BINDING_ABSENT):
            fails.append('%s T-3: a failed calibration probe still licensed a creation' % name)

        # T-6: two stamped tickets for one cluster -> nothing created or updated, all named.
        r, t, mk = make()
        key = rt.build_clusters([a])[0][0]['cluster_key']
        if name == 'jira':
            for i in ('901', '902'):
                t.issues[i] = {'id': i, 'type': 'Story', 'fields': {
                    'customfield_10001': key, 'labels': ['secure-cicd-kit'],
                    'status': {'name': 'To Do', 'statusCategory': {'key': 'new'}}}}
        else:
            for i in (901, 902):
                t.items[i] = dict(azdo_item(i, stamp=key), type='Issue')
        before = len(r.requests)
        res = rt.reconcile(*rt.build_clusters([a]), backend=mk(), ledger={}, apply_changes=True)
        writes = [q for q in r.requests[before:] if q['method'] in ('PUT', 'PATCH') or (
            q['method'] == 'POST' and not re.search(r'search/jql|wiql|workitemsbatch', q['url']))]
        cands = [str(c) for d in res['needs_decision'] for c in d.get('candidates') or []]
        if writes or res['outcomes'].get(rt.BINDING_AMBIGUOUS) != 1 or \
                sorted(cands) != ['901', '902']:
            fails.append('%s T-6: two stamped tickets -> %d write(s), outcomes %r, candidates %r'
                         % (name, len(writes), res['outcomes'], cands))

    # T-4 (Jira): the sweep breaks on page 2 -> PARTIAL, no creation from a miss.
    r = install(Replay())
    t = JiraTracker(r, page_size=1, fail_page=1)
    for i in ('801', '802'):
        t.issues[i] = {'id': i, 'type': 'Story', 'fields': {
            'customfield_10001': 'k' + i, 'labels': ['secure-cicd-kit'],
            'status': {'name': 'To Do', 'statusCategory': {'key': 'new'}}}}
    res = rt.reconcile(*rt.build_clusters([a]), backend=_jira_backend(rt, r), ledger={},
                       apply_changes=True)
    created = [q for q in r.requests if q['method'] == 'POST' and q['url'].endswith('/issue')]
    if created or res['outcomes'].get(rt.BINDING_UNESTABLISHED) != 1:
        fails.append('jira T-4: a sweep that failed mid-way licensed a creation: %r'
                     % res['outcomes'])


# ── T-9 / T-10: FINDING TEXT IS DATA; A SECRET'S TICKET CARRIES NO SECRET ─────────────────

HOSTILE = ('src/$(touch /tmp/pwned)/`id`/"q\'uote/<script>alert(1)</script>/'
           '{"type":"doc","content":[]}/&amp;/' + 'A' * 10240 + '.py')
SECRET = 'hunter2-correct-horse-battery'
PARTIAL_FP = 'f00dfacecafebeef0123456789abcdef'


def case_injection_and_secret(rt, fails):
    import html as _html
    rec = rt._rec('gitleaks', 'generic-api-key', HOSTILE, 'id-t9', aliases=['secret-t9'],
                  subject='SOURCE')
    rec['is_secret_finding'] = 'true'
    rec['message'] = 'Found secret %s in %s' % (SECRET, HOSTILE)
    rec['snippet'] = 'password = "%s"' % SECRET
    rec['partialFingerprints'] = {'primaryLocationLineHash': PARTIAL_FP}
    _sleeps(rt)
    for name in ('jira', 'azdo'):
        r = install(Replay())
        if name == 'jira':
            JiraTracker(r)
            b = _jira_backend(rt, r)
        else:
            AzdoTracker(r)
            b = rt.AzureDevOps(**AZDO_KW)
        rt.reconcile(*rt.build_clusters([rec]), backend=b, ledger={}, apply_changes=True)
        creates = [q for q in r.requests if q['method'] == 'POST' and
                   (q['url'].endswith('/rest/api/3/issue') or '/workitems/$' in q['url'])]
        if len(creates) != 1:
            fails.append('%s T-9: the hostile finding produced %d create(s)' % (name,
                                                                               len(creates)))
            continue
        body = creates[0]['json']
        blob = json.dumps(body)
        # T-10: no secret material of any kind, in any field of the request.
        for what, val in (('the matched secret', SECRET), ('the scanner partial fingerprint',
                                                           PARTIAL_FP)):
            if val in blob:
                fails.append('%s T-10: the create request carries %s' % (name, what))
        if name == 'jira':
            f = body['fields']
            title, text = f.get('summary') or '', adf_text(f.get('description'))
            nodes = [n for p in f['description']['content'] for n in p.get('content') or []]
            if any(n.get('type') != 'text' or n.get('marks') for n in nodes):
                fails.append('jira T-9: the description contains a node other than plain text, '
                             'so finding text was interpreted as markup')
        else:
            ops = dict((o['path'], o['value']) for o in body)
            title = ops.get('/fields/System.Title') or ''
            raw = ops.get('/fields/System.Description') or ''
            if '<script>' in raw:
                fails.append('azdo T-9: raw <script> reached System.Description unescaped')
            text = _html.unescape(raw)
        # T-9: the hostile path survives VERBATIM, as text, in the body.
        if HOSTILE not in text:
            fails.append('%s T-9: the 10 KB hostile path did not arrive verbatim in the body'
                         % name)
        # Titles are bounded by both trackers (255 characters); an unbounded title would make
        # the create itself fail on any long path.
        if len(title) > 255:
            fails.append('%s T-9: the title is %d characters; both trackers cap it at 255, so '
                         'the create would be refused' % (name, len(title)))
    if os.path.exists('/tmp/pwned'):
        fails.append('T-9: something EXECUTED the finding path')


# ── T-02 / TC 5.4: A MEMBERS-ADDED UPDATE REPLACES THE BLOCK AND NOTHING ELSE ────────────
#
# THE DEFECT (completion ledger row T-02). The Jira and Azure DevOps sweeps return no body, and the
# members-added update rendered the block against that empty body -- so the PUT/PATCH rewrote the
# whole description as the kit's block alone, ERASING every sentence a person wrote around it.
# The live T-2 "joined" case took exactly that path on a synthetic ticket nobody had annotated.
#
# THE CONTRACT. Automation writes inside the delimiters and nowhere else (TC 5.4, 5.2 "anything
# outside the machine-owned block"). So the description is READ IN FULL before the write, only the
# delimited block is replaced, and every other node (Jira ADF) or byte (Azure DevOps HTML) is
# written back exactly as read. A description that cannot be read is NOT written: that is an
# unestablished binding (BINDING_UNESTABLISHED, claim EVIDENCE_UNTRUSTED), never a blind overwrite.

HUMAN_BEFORE_ADF = [
    {'type': 'paragraph', 'content': [
        {'type': 'text', 'text': 'Triage: ', 'marks': [{'type': 'strong'}]},
        {'type': 'text', 'text': 'owned by the payments team; '},
        {'type': 'mention', 'attrs': {'id': 'acct-123', 'text': '@reviewer'}}]},
    {'type': 'heading', 'attrs': {'level': 3},
     'content': [{'type': 'text', 'text': 'Notes written before the block'}]},
]
HUMAN_AFTER_ADF = [
    {'type': 'paragraph', 'content': [{'type': 'text', 'text': 'Workaround: pinned in prod.'}]},
    {'type': 'bulletList', 'content': [{'type': 'listItem', 'content': [
        {'type': 'paragraph', 'content': [{'type': 'text', 'text': 'ask before upgrading'}]}]}]},
]
HUMAN_BEFORE_HTML = '<div><b>Triage:</b> owned by the payments team &amp; @reviewer</div>'
HUMAN_AFTER_HTML = '<p>Workaround: pinned in prod.</p><ul><li>ask before upgrading</li></ul>'


def _members_added(rt, mk, ledger_mode):
    """Run 1 creates over member a; run 2 sees a and b. -> (result of run 2, run-2 records)."""
    a = rt._rec('trivy', 'CVE-T02', 'go.mod', 'id-t02a', aliases=['cve-t02', 'ghsa-t02'])
    b = rt._rec('grype', 'GHSA-T02', 'go.mod', 'id-t02b', aliases=['ghsa-t02', 'cve-t02'])
    ledger = {}
    rt.reconcile(*rt.build_clusters([a]), backend=mk(), ledger=ledger, apply_changes=True,
                 today='2026-10-16')
    return a, b, (ledger if ledger_mode == 'carried' else {})


def case_human_text_preserved(rt, fails):
    import html as _html
    _sleeps(rt)
    for ledger_mode in ('carried', 'absent'):
        # ── JIRA: the description is ADF. Human nodes before and after the block survive. ──
        r = install(Replay())
        t = JiraTracker(r)
        mk = lambda: _jira_backend(rt, r)   # noqa: E731 - one-line factory
        a, b, ledger = _members_added(rt, mk, ledger_mode)
        stories = [i for i in t.issues.values() if i['type'] == 'Story']
        if len(stories) != 1:
            fails.append('T-02 jira (%s ledger): run 1 made %d ticket(s), expected 1'
                         % (ledger_mode, len(stories)))
            continue
        issue = stories[0]
        made = (issue.get('description') or {}).get('content') or []
        issue['description'] = {'type': 'doc', 'version': 1,
                                'content': json.loads(json.dumps(HUMAN_BEFORE_ADF)) + made
                                + json.loads(json.dumps(HUMAN_AFTER_ADF))}
        puts_before = len(t.puts)
        res = rt.reconcile(*rt.build_clusters([a, b]), backend=mk(), ledger=ledger,
                           apply_changes=True, today='2026-10-16')
        if len(t.puts) == puts_before:
            fails.append('T-02 jira (%s ledger): a member joined and NO description write '
                         'happened, so nothing about preservation was tested' % ledger_mode)
            continue
        got = (issue.get('description') or {}).get('content') or []
        n_b, n_a = len(HUMAN_BEFORE_ADF), len(HUMAN_AFTER_ADF)
        if got[:n_b] != HUMAN_BEFORE_ADF:
            fails.append('T-02 jira (%s ledger): the human text BEFORE the block was erased or '
                         'altered by a members-added update: %r' % (ledger_mode, got[:n_b]))
        if got[-n_a:] != HUMAN_AFTER_ADF:
            fails.append('T-02 jira (%s ledger): the human text AFTER the block was erased or '
                         'altered by a members-added update: %r' % (ledger_mode, got[-n_a:]))
        if 'id-t02b' not in adf_text({'content': got}):
            fails.append('T-02 jira (%s ledger): the joined member is not in the rewritten block'
                         % ledger_mode)
        if adf_text({'content': got}).count('machine-owned block. Edits') != 1:
            fails.append('T-02 jira (%s ledger): the description carries %d blocks after the '
                         'update, expected exactly 1' % (ledger_mode, adf_text(
                             {'content': got}).count('machine-owned block. Edits')))
        if (res.get('ticketing_claim') or {}).get('routing_result') != 'PROCEED':
            fails.append('T-02 jira (%s ledger): a clean members-added update made the claim %r'
                         % (ledger_mode, (res.get('ticketing_claim') or {}).get('routing_result')))
        # T-13: the same members again is no delta -- no write, and the human text stays.
        puts_before = len(t.puts)
        rt.reconcile(*rt.build_clusters([a, b]), backend=mk(), ledger=ledger,
                     apply_changes=True, today='2026-10-17')
        if len(t.puts) != puts_before:
            fails.append('T-13 jira (%s ledger): an unchanged run wrote the description %d '
                         'time(s)' % (ledger_mode, len(t.puts) - puts_before))

        # ── AZURE DEVOPS: the description is HTML. Every byte outside the block survives. ──
        r = install(Replay())
        t = AzdoTracker(r)
        mk = lambda: rt.AzureDevOps(**AZDO_KW)   # noqa: E731
        a, b, ledger = _members_added(rt, mk, ledger_mode)
        mine = [i for i, it in t.items.items() if it.get('type') == 'Issue']
        if len(mine) != 1:
            fails.append('T-02 azdo (%s ledger): run 1 made %d work item(s), expected 1'
                         % (ledger_mode, len(mine)))
            continue
        f = t.items[mine[0]]['fields']
        f['System.Description'] = HUMAN_BEFORE_HTML + f['System.Description'] + HUMAN_AFTER_HTML
        patches_before = len(t.patches)
        res = rt.reconcile(*rt.build_clusters([a, b]), backend=mk(), ledger=ledger,
                           apply_changes=True, today='2026-10-16')
        if len(t.patches) == patches_before:
            fails.append('T-02 azdo (%s ledger): a member joined and NO description write '
                         'happened, so nothing about preservation was tested' % ledger_mode)
            continue
        got = f.get('System.Description') or ''
        if not got.startswith(HUMAN_BEFORE_HTML):
            fails.append('T-02 azdo (%s ledger): the human HTML BEFORE the block was erased or '
                         'altered: %r' % (ledger_mode, got[:120]))
        if not got.endswith(HUMAN_AFTER_HTML):
            fails.append('T-02 azdo (%s ledger): the human HTML AFTER the block was erased or '
                         'altered: %r' % (ledger_mode, got[-120:]))
        if 'id-t02b' not in _html.unescape(got):
            fails.append('T-02 azdo (%s ledger): the joined member is not in the rewritten block'
                         % ledger_mode)
        last = t.patches[-1]
        patches_before = len(t.patches)
        rt.reconcile(*rt.build_clusters([a, b]), backend=mk(), ledger=ledger,
                     apply_changes=True, today='2026-10-17')
        if len(t.patches) != patches_before:
            fails.append('T-13 azdo (%s ledger): an unchanged run wrote the description %d '
                         'time(s)' % (ledger_mode, len(t.patches) - patches_before))
        if not any(o.get('op') == 'test' and o.get('path') == '/rev' for o in last):
            fails.append('T-02 azdo (%s ledger): the description write carries no `test` on '
                         '/rev, so a person editing between the read and the write would be '
                         'overwritten' % ledger_mode)

    # ── UNREADABLE: the description cannot be read -> NOTHING is written, and it is said. ──
    for name in ('jira', 'azdo'):
        r = install(Replay())
        if name == 'jira':
            t = JiraTracker(r)
            mk = lambda: _jira_backend(rt, r)   # noqa: E731
        else:
            t = AzdoTracker(r)
            mk = lambda: rt.AzureDevOps(**AZDO_KW)   # noqa: E731
        a, b, ledger = _members_added(rt, mk, 'carried')
        if name == 'jira':
            ref = [i for i, it in t.issues.items() if it['type'] == 'Story'][0]
            t.unreadable.add(ref)
            writes_before = len(t.puts)
        else:
            ref = [i for i, it in t.items.items() if it.get('type') == 'Issue'][0]
            t.unreadable.add(ref)
            writes_before = len(t.patches)
        res = rt.reconcile(*rt.build_clusters([a, b]), backend=mk(), ledger=ledger,
                           apply_changes=True, today='2026-10-16')
        wrote = (len(t.puts) if name == 'jira' else len(t.patches)) - writes_before
        if wrote:
            fails.append('T-02 %s: the description could NOT be read and the run wrote it '
                         'anyway (%d write(s)) -- a blind overwrite of whatever a person wrote'
                         % (name, wrote))
        owed = [o for o in res.get('obligations') or []
                if o.get('outcome') == rt.BINDING_UNESTABLISHED]
        if not owed:
            fails.append('T-02 %s: an unreadable description left no %s obligation, so the '
                         'withheld update is invisible' % (name, rt.BINDING_UNESTABLISHED))
        if (res.get('ticketing_claim') or {}).get('routing_result') != rt.EVIDENCE_UNTRUSTED:
            fails.append('T-02 %s: an unreadable description left the claim %r, not %s'
                         % (name, (res.get('ticketing_claim') or {}).get('routing_result'),
                            rt.EVIDENCE_UNTRUSTED))


# ── T-12: THE BOT NEVER WRITES A DISPOSITION, APPROVER, EXPIRY OR SLA DATE ────────────────

FORBIDDEN_FIELD = re.compile(r'due|disposition|approv|expir|\bsla\b|deadline|resolution',
                             re.I)
WRITE_METHODS = ('create', 'create_instance', '_create', 'update_block', 'write_description',
                 'splice_description', 'comment', 'reopen',
                 # KDEC-024: closure on clearance / supersede, and the escalation write.
                 'close', 'mark')


def _field_names(obj, out):
    """Every JSON key at any depth, and every JSON Patch path -- field NAMES, not text values."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.append(str(k))
            if k == 'path' and isinstance(v, str):
                out.append(v)
            _field_names(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _field_names(v, out)
    return out


def write_field_names_in_source(src):
    """STATIC: dict keys and '/fields/...' paths inside each backend's write methods."""
    import ast
    names = []
    for cls in ast.parse(src).body:
        if not isinstance(cls, ast.ClassDef):
            continue
        for fn in cls.body:
            if isinstance(fn, ast.FunctionDef) and fn.name in WRITE_METHODS:
                for node in ast.walk(fn):
                    if isinstance(node, ast.Dict):
                        names += ['%s.%s:%s' % (cls.name, fn.name, k.value) for k in node.keys
                                  if isinstance(k, ast.Constant) and isinstance(k.value, str)]
                    if isinstance(node, ast.Constant) and isinstance(node.value, str) and \
                            node.value.startswith('/fields/'):
                        names.append('%s.%s:%s' % (cls.name, fn.name, node.value))
    return names


def case_never_writes_governance(rt, fails):
    src = io.open(os.path.join(ROOT, 'scripts', 'reconcile_tickets.py'), encoding='utf-8').read()
    static = write_field_names_in_source(src)
    if not static:
        fails.append('T-12: the static check found no write-method field names at all, so it '
                     'proves nothing')
    for n in static:
        if FORBIDDEN_FIELD.search(n.split(':', 1)[1]):
            fails.append('T-12 static: a write method sets %s' % n)
    # DYNAMIC: every write a full Jira and Azure DevOps run sends, including reopen and instances.
    _sleeps(rt)
    recs = [rt._rec('trivy', 'CVE-12', 'go.mod', 'id-12', aliases=['cve-12'])]
    for name in ('jira', 'azdo'):
        r = install(Replay())
        if name == 'jira':
            JiraTracker(r)
            b = _jira_backend(rt, r, TICKET_INSTANCE_THRESHOLD='3')
        else:
            AzdoTracker(r)
            b = rt.AzureDevOps(**AZDO_KW)
            b.instance_threshold = 3
        rt.reconcile(*rt.build_clusters(recs), backend=b, ledger={}, apply_changes=True)
        writes = [q for q in r.requests if q['method'] in ('PUT', 'PATCH') or (
            q['method'] == 'POST' and not re.search(r'search/jql|wiql|workitemsbatch', q['url']))]
        if not writes:
            fails.append('T-12 %s: no write was observed, so nothing was checked' % name)
        for q in writes:
            for n in _field_names(q['json'], []):
                if FORBIDDEN_FIELD.search(n):
                    fails.append('T-12 %s: a write sets field %r (%s)' % (name, n, q['url'][:80]))


# ── B-1: PERSONAL TO CONSUMER CHANGES CONFIGURATION VALUES ONLY ──────────────────────────

def _jira_any_project(r, key):
    r.on('GET', r'/rest/api/3/myself$', ok({'accountId': 'stub'}))
    r.on('GET', r'/rest/api/3/project/%s$' % key, ok({'id': '1', 'key': key}))
    r.on('GET', r'/rest/api/3/issue/createmeta/%s/issuetypes$' % key, ok(CREATEMETA_TYPES))
    r.on('GET', r'/rest/api/3/issue/createmeta/%s/issuetypes/10004$' % key, ok({'fields': [
        {'fieldId': f, 'schema': {'type': 'string'}} for f in ('customfield_10001',
                                                                 'customfield_20777')]}))
    r.on('GET', r'/rest/api/3/issue/\d+\?fields=project', ok({'fields': {'project': {'key': key}}}))
    r.on('GET', r'/rest/api/3/issue/\d+\?fields=customfield', ok({'id': '1', 'fields': {}}))
    r.on('POST', r'/rest/api/3/search/jql$', ok({'issues': [], 'isLast': True}))
    return r


def case_portability(rt, fails):
    personal = dict(JIRA_ENV)
    consumer = dict(JIRA_ENV, JIRA_HOST='https://consumer-example.atlassian.net',
                    JIRA_EMAIL='bot@consumer.invalid', JIRA_TOKEN='placeholder-token-2',
                    JIRA_PROJECT='SEC', JIRA_STAMP_FIELD='customfield_20777',
                    JIRA_EPIC_ID='40000', JIRA_CALIBRATION_ISSUE='40002')
    changed = sorted(k for k in consumer if consumer[k] != personal.get(k))
    recs = [rt._rec('trivy', 'CVE-B1', 'go.mod', 'id-b1', aliases=['cve-b1'])]
    _sleeps(rt)
    streams, keys = {}, {}
    for label, env in (('personal', personal), ('consumer', consumer)):
        r = _jira_any_project(install(Replay()), env['JIRA_PROJECT'])
        b, note = rt.choose_backend(env)
        if b is None:
            fails.append('B-1: the %s configuration was refused: %s' % (label, note))
            return
        clusters, w = rt.build_clusters(recs)
        keys[label] = clusters[0]['cluster_key']
        res = rt.reconcile(clusters, w, b, {}, apply_changes=False)
        if res['outcomes'].get(rt.BINDING_ABSENT) != 1:
            fails.append('B-1: the %s dry plan did not reach BINDING_ABSENT: %r'
                         % (label, res['outcomes']))
        # Normalise: replace every configured value by the variable's NAME.
        norm = []
        for q in r.requests:
            s = json.dumps([q['method'], q['url'], q['json']], sort_keys=True)
            for k in sorted(env, key=lambda k: -len(env[k])):
                if env[k]:
                    s = s.replace(env[k], '<%s>' % k)
            norm.append(s)
        streams[label] = norm
    if keys['personal'] != keys['consumer']:
        fails.append('B-1: the cluster stamp differs between configurations; the stamp format must '
                     'be byte-identical')
    if streams.get('personal') != streams.get('consumer'):
        diff = [(a, b) for a, b in zip(streams['personal'], streams['consumer']) if a != b][:1]
        fails.append('B-1: the request streams differ beyond the configured values (%s): %r'
                     % (', '.join(changed), diff))
    # Nothing configuration-specific is hard-coded in the code or the workflow.
    for path in ('scripts/reconcile_tickets.py', '.github/workflows/reusable-ticket-reconcile.yml'):
        text = io.open(os.path.join(ROOT, path), encoding='utf-8').read()
        for k in changed:
            for v in (personal[k], consumer[k]):
                if v and len(v) > 4 and v in text:
                    fails.append('B-1: %s hard-codes the %s value %r' % (path, k, v))


CASES = [('J-3 / L54 calibration probe', case_probe),
         ('J-4 / T-5 throttling', case_throttle),
         ('J-1 Jira sweep query', case_jira_sweep),
         ('J-5 reconcileIssues', case_reconcile_issues),
         ('J-2 Jira create', case_jira_create),
         ('J-7 / T-11 Jira shape at run start', case_jira_shape),
         ('J-6 / T-7 / T-8 Jira reopen and successor', case_jira_reopen),
         ('J-8 Jira instances', case_jira_instances),
         ('A-1 Azure DevOps backend', case_azdo),
         ('C-2 choose_backend', case_choose),
         ('X-1 T-1/T-2/T-3/T-4/T-6 per backend', case_t_matrix),
         ('X-1 T-9 / T-10 injection and secret', case_injection_and_secret),
         ('X-1 T-12 no governance field is ever written', case_never_writes_governance),
         ('T-02 human text outside the block survives', case_human_text_preserved),
         ('X-1 B-1 portability: configuration only', case_portability)]


def main():
    try:
        import reconcile_tickets as rt
    except Exception as exc:                          # noqa: BLE001 - reported as UNKNOWN
        print('UNKNOWN: could not import reconcile_tickets: %s' % exc)
        return 2
    real_urlopen = urllib.request.urlopen
    fails, transcript = [], []
    try:
        for label, fn in CASES:
            before = len(fails)
            replay_log = []
            try:
                fn(rt, fails)
            except AssertionError as exc:
                fails.append('%s: %s' % (label, exc))
            except Exception as exc:                  # noqa: BLE001 - a crash is a failure
                fails.append('%s crashed: %s: %s' % (label, type(exc).__name__, exc))
            stub = urllib.request.urlopen
            if isinstance(stub, Replay):
                for u in stub.unanswered:
                    replay_log.append(u)
                for req in stub.requests:
                    blob = json.dumps(req)
                    for s in SECRETS:
                        if s in blob and 'authorization' not in json.dumps(req['headers']).lower():
                            fails.append('%s: a credential appeared outside the auth header'
                                         % label)
            print('  %-44s %s' % (label, 'ok' if len(fails) == before else 'FAIL'))
            transcript.extend(replay_log)
    finally:
        urllib.request.urlopen = real_urlopen
    if fails:
        print('')
        for i, f in enumerate(fails, 1):
            print('  %d. %s' % (i, f))
        print('::error title=Ticket backend unproven::%d failure(s)' % len(fails))
        return 1
    print('every backend case held against the documented shapes; no request left the machine.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
