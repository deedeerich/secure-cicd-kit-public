#!/usr/bin/env python3
"""Ticket templates, external findings, the review-finalize gate, dedupe against EVERY ticket, the
corroboration score, closure, extensions, the no-fix re-check and tracker intake (KDEC-037).

WHY THIS EXISTS

    The owner (2026-11-03) amended KDEC-035: external findings are ACCEPTED through templates
    (O-35f), and Tines may WRITE tickets through the API, but only after a recorded human approval
    of the finalized review (O-35g). Each way that can go wrong is a case here, run through the
    API's real run side (scripts/kit_api_server.py intake -> tickets -> finish) against the
    simulated GHE.com host (tests/_github_api_stub.py) and the stateful Jira stand-in of
    tests/prove_ticket_backends.py -- no request leaves the machine.

CASES (each a refusal by name AND its allowed counterpart, docs/PROOF_RULE.md)
    T1  every template: a valid item accepted; each template refusal produced by name; every asset
        scheme an identity; routing by template, source type and environment
    T2  the finalize gate: no record, a draft, another evidence set, a concurrer not on the list,
        the submitter or the API caller concurring, a stale concurrence, a pull request the
        concurrer did not approve, a record pushed past review, an unreadable history -- each
        API_REVIEW_NOT_FINALIZED with nothing read from the tracker; a finalized one writes; a dry
        run shows exactly what would be written and writes nothing
    T3  dedupe against ALL tickets (v2): a manual ticket with no stamp naming the asset and identifier is
        a CANDIDATE on the dry run; a person's link decision records a CLOSED DUPLICATE under it and the
        next submission finds it EXACT; "new" creates; the kit's own stamp is exact; a partial search
        creates the ticket DEDUPE PENDING; two tools on one asset and identifier are one ticket naming both
    T4  the corroboration score: rises with independent sources, an exact identifier and
        evidence; falls when contested; NOT ESTABLISHED (None) without an identity; never the tier
    T5  closure (v2): the fixer verifying their own fix is PENDING VERIFICATION, never closed; an
        unlinked manual ticket is TICKET_NOT_KIT_LINKED; a scan that never saw an external finding is
        CLOSURE_NOT_VERIFIED; an approved reviewer who is not the fixer closes it (comment, label, done)
    T6  extensions: self-approval (SOD_SELF_APPROVAL), a count that disagrees with the ticket, past the maximum, past
        the ceiling -- each refused by name; a valid one comments and records extension 1
    T7  no-fix re-check: one ticket with the exemption and the re-check due; FIX_AVAILABLE later
        reopens it as remediation; the clock raises a due re-check once
    T8  compliance requests: each of the four opens a request-class ticket beside the finding's,
        under the review's concurrence; no disposition is written
    T9  tracker intake: paged through 230 tickets with the tracker's cursor, manual ones included;
        another repository's project and ORDER BY refused; FreshService NOT_CONFIGURED; tickets
        joined to a findings run by their correlation key
    T10 every new API refusal is produced here; the CLI's evidence hash is the server's

EXIT  0 every case held  1 a case failed  2 could not be checked
"""
import copy
import io
import json
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
sys.path.insert(0, HERE)

FAILS = []
PRODUCED = set()
NEW_REFUSALS = ('API_TEMPLATE_INVALID', 'API_REVIEW_NOT_FINALIZED', 'API_TEMPLATE_RULE_REFUSED',
                'API_TRACKER_QUERY_REFUSED')
REVIEWER = 'security-reviewer'
TODAY = '2026-11-03'


def check(cond, msg):
    if not cond:
        FAILS.append(msg)
    return cond


def imports():
    try:
        import kit_api
        import kit_api_server
        import reconcile_tickets
        import prove_ticket_backends as tb
        import prove_kit_api_server as ps
        import ticket_templates as tt
        import finding_correlation as fc
        return kit_api, kit_api_server, reconcile_tickets, tb, ps, tt, fc
    except (ImportError, AttributeError) as exc:
        print('FAIL: cannot import the template machinery (%s)' % exc)
        return None


# ── the Jira stand-in, widened: every ticket, manual ones included, searchable by text ────────

def install_intake_search(tb, t, replay, fail=False):
    """The enhanced search for queries the kit's stamp sweep does not make (no issuetype clause):
    project in (...), labels = / labels in, text ~ "\\"x\\"", paged by nextPageToken."""
    orig_create = t._create

    def create(rec):
        st, doc, h = orig_create(rec)
        if st < 300:
            t.issues[doc['id']]['summary'] = rec['json']['fields'].get('summary')
        return st, doc, h

    def search(rec):
        jql = rec['json']['jql']
        if 'issuetype' in jql:
            return t._search(rec)
        if fail:
            return 500, {'errorMessages': ['internal']}, {}
        t.searches += 1
        projects = re.findall(r'"([A-Z][A-Z0-9_]+)"', re.search(r'project in \(([^)]*)\)', jql).group(1))
        lab_eq = re.findall(r'labels = "([^"]+)"', jql)
        lab_in = re.search(r'labels in \(([^)]*)\)', jql)
        lab_in = re.findall(r'"([^"]+)"', lab_in.group(1)) if lab_in else []
        texts = [x.lower() for x in re.findall(r'text ~ "\\"([^"\\]+)\\""', jql)]
        hits = []
        for i in sorted(t.issues.values(), key=lambda x: int(x['id'])):
            proj = i.get('project') or 'KIT'
            if proj not in projects:
                continue
            labels = i['fields'].get('labels') or []
            if lab_in and not set(lab_in) & set(labels):
                continue
            body = (str(i.get('summary') or '') + ' ' + tb.adf_text(i.get('description'))).lower()
            ors = [x in labels for x in lab_eq] + [x in body for x in texts]
            if ors and not any(ors):
                continue
            hits.append(i)
        size = int(rec['json'].get('maxResults') or 50)
        start = int(rec['json'].get('nextPageToken') or 0)
        page = hits[start:start + size]
        doc = {'issues': [{'id': i['id'], 'key': i['key'],
                           'fields': dict(i['fields'], summary=i.get('summary') or '',
                                          description=i.get('description'))} for i in page]}
        if start + size < len(hits):
            doc['nextPageToken'] = str(start + size)
        return 200, doc, {}
    replay.on('POST', r'/rest/api/3/search/jql$', search)
    replay.on('POST', r'/rest/api/3/issue$', create)


def manual_ticket(tb, t, summary, text, labels=(), project='KIT', status=('To Do', 'new')):
    """A ticket a PERSON made: no stamp field, no kit label, its own words."""
    i = str(t.next_id)
    t.next_id += 1
    t.issues[i] = {'id': i, 'key': '%s-%s' % (project, i), 'type': 'Task', 'project': project, 'summary': summary,
                   'fields': {'customfield_10001': None, 'labels': list(labels),
                              'status': {'name': status[0], 'statusCategory': {'key': status[1]}}},
                   'description': {'type': 'doc', 'version': 1,
                                   'content': [{'type': 'paragraph', 'content': [{'type': 'text', 'text': text}]}]}}
    return i


# ── the world: a repository, its tracker, its review records ────────────────────────────────

class W(object):
    def __init__(self, mods, tmp, fail_search=False):
        ka, ks, rt, tb, ps, tt, fc = mods
        self.ka, self.ks, self.rt, self.tb, self.ps, self.tt = ka, ks, rt, tb, ps, tt
        self.replay = tb.install(tb.Replay())
        self.t = tb.JiraTracker(self.replay)
        install_intake_search(tb, self.t, self.replay, fail=fail_search)
        tb._sleeps(rt)
        self.w = ps.World(ka, tb.JIRA_ENV, tmp, ps.observations(fc))
        self.reviews = os.path.join(tmp, 'reviews')
        os.makedirs(self.reviews)
        io.open(os.path.join(self.reviews, 'approvers.json'), 'w', encoding='utf-8').write(
            json.dumps({'approver_lists': {'review-concurrence': [REVIEWER, 'other-reviewer']}}))
        ops = self.w.env['KIT_API_OPERATIONS'] + ',tickets.submit'
        self.w.env.update({'KIT_API_OPERATIONS': ops, 'KIT_API_REVIEWS_DIR': self.reviews, 'KIT_API_TODAY': TODAY,
                           'JIRA_TRANSITION_REOPEN': 'Reopen'})
        self.pr = 400

    def finalize(self, review_id, params, concurred_by=REVIEWER, status='FINALIZED', on=TODAY, approved_by=None,
                 author='tines-kit-app[bot]', merged=True, sha=None, evidence=None, decision='AGREE',
                 alternative=None, item_decisions=None, submitted_by='tines-kit-app[bot]', run_started_by=None,
                 triaged_by=None):
        """Write the record (kit-review-record/2), and merge it by a pull request the concurrer approved."""
        p = dict(params, review_id=review_id)
        rec = {'schema': 'kit-review-record/2', 'review_id': review_id, 'status': status,
               'submitted_by': submitted_by, 'concurred_by': concurred_by, 'concurred_on': on,
               'decision': decision, 'evidence_set_sha256': evidence or self.tt.evidence_set_sha256(p),
               'statement': 'I concur with these findings and this evidence.'}
        for k, v in (('alternative', alternative), ('item_decisions', item_decisions),
                     ('run_started_by', run_started_by), ('triaged_by', triaged_by)):
            if v is not None:
                rec[k] = v
        io.open(os.path.join(self.reviews, '%s.json' % review_id), 'w', encoding='utf-8').write(json.dumps(rec))
        self.pr += 1
        self.w.stub.merge_review_record('.security/reviews/%s.json' % review_id, sha or ('%040x' % self.pr), self.pr,
                                        author, [concurred_by] if approved_by is None else approved_by, merged=merged)
        return p

    def submit(self, params, key, dry_run=False):
        res, seen, intake = self.w.call(self.ks, 'tickets.submit', params, key=key, dry_run=dry_run)
        for r in (intake.get('refusal'), res.get('refusal')):
            if r:
                PRODUCED.add(r['code'])
        return res, seen

    def search(self, params):
        res, _s, intake = self.w.call(self.ks, 'tickets.search', params)
        for r in (intake.get('refusal'), res.get('refusal')):
            if r:
                PRODUCED.add(r['code'])
        return res


def finding(tt, **over):
    return tt.example_finding(**over)


def items_of(res):
    return (res.get('data') or {}).get('items') or []


def tref(res):
    return (res.get('refusal') or {}).get('code'), ((res.get('data') or {}).get('template_refusal') or {}).get('code')


# ── T1 ─────────────────────────────────────────────────────────────────────────────────────

def t1(mods, tmp):
    ka, ks, rt, tb, ps, tt, fc = mods
    import ticket_routing as troute
    f = finding(tt)
    ok = {'finding': f,
          'false-positive': {'finding': f, 'justification': 'the scanner reads a test fixture, not the product',
                             'requested_by': 'app-team', 'evidence': f['evidence'], 'rule_id': 'R-1',
                             'tool_version': '4.2.0'},
          'accepted-risk': {'finding': f, 'justification': 'decommissioned next quarter, compensated meanwhile',
                            'owner': 'ops-lead', 'review_date': '2027-01-31', 'risk_register_ref': 'RISK-1',
                            'requested_by': 'app-team', 'evidence': f['evidence']},
          'exception': {'finding': f, 'justification': 'parameterised traffic the WAF misreads as an injection',
                        'scope': {'from': 'gw', 'to': '/api/orders', 'condition': 'rule 942100 on POST'},
                        'compensating_controls': ['schema validation'], 'expires': '2026-12-31',
                        'requested_by': 'app-team', 'evidence': f['evidence']},
          'compliance-exception': {'finding': f, 'framework': 'PCI DSS 4.0', 'control_id': '4.2.1',
                                   'requirement_text': 'strong cryptography in transit', 'expires': '2027-01-31',
                                   'scope': {'from': 'pos', 'to': 'acct1', 'condition': 'until replacement'},
                                   'compensating_controls': ['private link only'], 'approving_authority': 'ciso',
                                   'justification': 'the terminal fleet is replaced in Q1', 'requested_by': 'app-team',
                                   'evidence': f['evidence']},
          'triage': {'ref': 'KIT-30001', 'original_ref': 'KIT-30002', 'decision': 'separate',
                     'triaged_by': 'engineer-one', 'reason': 'different storage accounts entirely'},
          'mitigation': {'finding': f, 'justification': 'the account is reachable only on a private endpoint',
                         'expires': '2027-01-31', 'requested_by': 'app-team', 'evidence': f['evidence'],
                         'compensating_control': 'private endpoint only, public network access disabled'},
          'exemption': {'finding': f, 'justification': 'a legacy integration that cannot speak TLS 1.2 until March',
                        'review_every_days': 90, 'requested_by': 'app-team', 'evidence': f['evidence'],
                        'register_scope': 'repository'},
          'extension': {'ref': 'KIT-30001', 'new_expiry': '2026-12-31', 'reason': 'the vendor moved the release by a month',
                        'extensions_used': 0, 'requested_by': 'app-team', 'evidence': f['evidence'],
                        'waiting_on': 'fix'},
          'nofix-recheck': {'finding': finding(tt, fix_status='NO_FIX_AVAILABLE'), 'vendor': 'Contoso',
                            'requested_by': 'app-team', 'evidence': f['evidence']},
          'closure': {'ref': 'KIT-30001', 'action': 'verify', 'requested_by': 'app-team', 'fixed_by': 'dev-one',
                      'evidence': f['evidence'], 'verification': {'kind': 'reviewer'}}}
    for name in tt.WRITE_TEMPLATES:
        r = tt.validate_item(name, ok[name], 0, today=TODAY)
        check(r is None, 'T1 a valid %s item was refused: %r' % (name, r))
    check(tt.validate_item('nonsense', {})['code'] == tt.TEMPLATE_UNKNOWN, 'T1 an unknown template was not named')
    for label, tpl, item, code in (
            ('missing field', 'finding', dict((k, v) for k, v in f.items() if k != 'evidence'), tt.TEMPLATE_FIELD_INVALID),
            ('bad severity', 'finding', dict(f, severity='urgent'), tt.TEMPLATE_FIELD_INVALID),
            ('azure subscription mismatch', 'finding',
             dict(f, asset=dict(f['asset'], subscription_id='99999999-bbbb-cccc-dddd-eeeeeeeeeeee')),
             tt.TEMPLATE_ASSET_IDENTITY_INVALID),
            ('aws account mismatch', 'finding',
             dict(f, asset={'scheme': 'aws-resource', 'account_id': '111111111111', 'region': 'us-east-1',
                            'arn': 'arn:aws:s3:us-east-1:222222222222:bucket/x'}), tt.TEMPLATE_ASSET_IDENTITY_INVALID),
            ('scheme field missing', 'finding', dict(f, asset={'scheme': 'repo-path', 'repository': 'o/r'}),
             tt.TEMPLATE_ASSET_IDENTITY_INVALID),
            ('caller key mismatch', 'finding', dict(f, correlation_key='0' * 32), tt.TEMPLATE_FIELD_INVALID),
            ('review date passed', 'accepted-risk', dict(ok['accepted-risk'], review_date='2026-01-01'),
             tt.TEMPLATE_FIELD_INVALID),
            ('nofix with a fix', 'nofix-recheck', dict(ok['nofix-recheck'], finding=f), tt.TEMPLATE_FIELD_INVALID),
            ('nofix too long', 'nofix-recheck', dict(ok['nofix-recheck'], exemption_days=200), tt.NOFIX_EXEMPTION_TOO_LONG),
            ('extension past ceiling', 'extension', dict(ok['extension'], new_expiry='2027-12-31'),
             tt.EXTENSION_CEILING_EXCEEDED),
            ('extension with no waiting_on', 'extension', dict((k, v) for k, v in ok['extension'].items()
                                                               if k != 'waiting_on'), tt.TEMPLATE_FIELD_INVALID),
            ('scan closure without its run', 'closure', dict(ok['closure'], verification={'kind': 'scan'}),
             tt.TEMPLATE_FIELD_INVALID)):
        r = tt.validate_item(tpl, item, 0, today=TODAY) or {}
        check(r.get('code') == code, 'T1 %s: %r, expected %s' % (label, r, code))
    r = tt.validate_submit({'template': 'finding', 'template_version': 1, 'items': [f]})
    check((r or {}).get('code') == tt.TEMPLATE_VERSION_UNSUPPORTED, 'T1 version 1 (superseded) was %r' % r)
    r = tt.validate_submit({'template': 'finding', 'template_version': 2, 'items': [f],
                            'link_decisions': [{'correlation_key': '1' * 32, 'decision': 'new'}]})
    check((r or {}).get('code') == tt.LINK_DECISION_INVALID, 'T1 a decision for no item was %r' % r)
    # Every asset scheme is an identity, and the identity ignores who reported it.
    for asset in ({'scheme': 'repo-path', 'repository': 'o/r', 'path': 'src/app.py', 'line': 4},
                  {'scheme': 'aws-resource', 'account_id': '111111111111', 'region': 'us-gov-west-1',
                   'arn': 'arn:aws-us-gov:s3:us-gov-west-1:111111111111:bucket/x'},
                  {'scheme': 'github-repo', 'host': 'example.ghe.com', 'org': 'o', 'repo': 'r'},
                  {'scheme': 'engagement', 'engagement_id': 'PT-2026-07', 'kind': 'pentest', 'target': 'portal'},
                  dict(f['asset'], cloud='azure-government')):
        k, _d, _n, bad = tt.asset_key(asset)
        check(k and not bad, 'T1 the %s asset is not an identity: %s' % (asset['scheme'], bad))
    a = tt.normalize('finding', finding(tt, source_tool='defender'), {})
    b = tt.normalize('finding', finding(tt, source_tool='prowler', source_type='usr'), {})
    check(a['identity'] == b['identity'] and a['correlation_key'] == b['correlation_key'],
          'T1 two sources on one asset and identifier are two identities')
    gov = tt.normalize('finding', finding(tt, asset=dict(f['asset'], cloud='azure-government')), {})
    check(gov['identity'] != a['identity'], 'T1 the same resource id in Azure Government is the commercial identity')
    # Routing: by template, source type and environment (glob).
    routing = {'rules': [{'id': 'gov', 'match': {'environment': ['azure-government-*']}, 'project': 'GOVSEC'},
                         {'id': 'pentest', 'match': {'source_type': ['pentest'], 'template': ['finding']},
                          'project': 'PENTEST'},
                         {'id': 'requests', 'match': {'template': ['accepted-risk', 'exemption']}, 'project': 'GRC'}],
               'default': {'project': 'SEC'}}
    probs = troute.check_routing(routing, 'entry', 'REGISTRATION_UNAVAILABLE')
    check(not probs, 'T1 the routing facts template/source_type/environment are not accepted: %r' % probs)

    def where(rec):
        cl, _w = rt.build_clusters([rec])
        return troute.route(rt.routing_facts(cl[0], 'o/r'), routing, 'KIT')['project']
    check(where(tt.normalize('finding', finding(tt, environment='azure-government-prod'), {})) == 'GOVSEC',
          'T1 an Azure Government finding was not routed by environment')
    check(where(tt.normalize('finding', finding(tt, source_type='pentest'), {})) == 'PENTEST',
          'T1 a pentest finding was not routed by source type')
    check(where(tt.normalize('accepted-risk', ok['accepted-risk'], {})) == 'GRC',
          'T1 an accepted-risk request was not routed by template')
    check(where(tt.normalize('finding', f, {})) == 'SEC', 'T1 the default did not apply')


# ── T2 ─────────────────────────────────────────────────────────────────────────────────────

def t2(mods, tmp):
    ka, ks, rt, tb, ps, tt, fc = mods
    w = W(mods, tmp)
    base = {'template': 'finding', 'template_version': 2, 'items': [finding(tt)]}
    n = [0]

    def attempt(p, label):
        n[0] += 1
        before = len(w.replay.requests)
        res, seen = w.submit(p, 'review-gate-%04d' % n[0])
        jira = [q for q in w.replay.requests[before:]]
        code = (res.get('refusal') or {}).get('code')
        check(code == 'API_REVIEW_NOT_FINALIZED', 'T2 %s: %r, expected API_REVIEW_NOT_FINALIZED' % (label, code))
        check(((res.get('data') or {}).get('review') or {}).get('state') == 'REVIEW_NOT_FINALIZED',
              'T2 %s: the review state is not REVIEW_NOT_FINALIZED: %r' % (label, (res.get('data') or {}).get('review')))
        check(not jira, 'T2 %s: the tracker was reached before the review was finalized (%d request(s))'
              % (label, len(jira)))
        check(seen.get('api_state') == 'API_REFUSED', 'T2 %s: the caller read %r' % (label, seen.get('api_state')))
        check(not w.t.issues, 'T2 %s: a ticket exists' % label)
    attempt(dict(base, review_id='USR-NONE-001'), 'no record')
    attempt(dict(base), 'no review id')
    attempt(w.finalize('USR-DRAFT-01', base, status='DRAFT'), 'a draft')
    p = w.finalize('USR-OTHER-01', base, evidence='0' * 64)
    attempt(p, 'another evidence set')
    attempt(w.finalize('USR-NOTLIST-1', base, concurred_by='random-dev'), 'a concurrer not on the list')
    attempt(w.finalize('USR-SELF-001', base, concurred_by='tines-kit-app'), 'the API caller concurring')
    w.w.env['GITHUB_ACTOR'] = 'other-reviewer'
    attempt(w.finalize('USR-ACTOR-01', base, concurred_by='other-reviewer'), 'the actor concurring')
    w.w.env['GITHUB_ACTOR'] = 'tines-kit-app[bot]'
    attempt(w.finalize('USR-STALE-01', base, on='2026-08-01'), 'a stale concurrence')
    attempt(w.finalize('USR-FUTURE-1', base, on='2026-12-01'), 'a concurrence in the future')
    attempt(w.finalize('USR-NOAPPR-1', base, approved_by=['someone-else']), 'a PR the concurrer did not approve')
    attempt(w.finalize('USR-SELFPR-1', base, author=REVIEWER), 'the concurrer authored the PR')
    attempt(w.finalize('USR-PUSHED-1', base, merged=False), 'a record pushed past review')
    w.w.stub.fail[('GET', r'/pulls/\d+/reviews$')] = 500
    attempt(w.finalize('USR-UNREAD-1', base), 'an unreadable review history')
    w.w.stub.fail.clear()
    # The allowed counterpart: finalized, concurred, approved -- and a dry run first.
    p = w.finalize('USR-2026-11-03', base)
    res, _s = w.submit(p, 'review-gate-dry', dry_run=True)
    it = items_of(res)
    check(res.get('api_state') == 'API_COMPLETED' and not w.t.issues and it and
          it[0].get('outcome') == tt.TEMPLATE_TICKET_PLANNED and it[0].get('title'),
          'T2: the dry run did not show exactly what would be written: %r / %r' % (res.get('api_state'), it))
    check(((res.get('data') or {}).get('review') or {}).get('concurred_by') == REVIEWER,
          'T2: the dry run does not name the concurring reviewer')
    res, seen = w.submit(p, 'review-gate-real')
    it = items_of(res)
    check(res.get('api_state') == 'API_COMPLETED' and len(w.t.issues) == 1 and it and
          it[0].get('outcome') == tt.TEMPLATE_TICKET_CREATED,
          'T2: a finalized review did not write its ticket: %r %r %r' % (res.get('api_state'), it, res.get('notes')))
    if w.t.issues:
        issue = list(w.t.issues.values())[0]
        body = tb.adf_text(issue.get('description'))
        check('USR-2026-11-03' in body and 'defender' in body and 'e' * 64 in body,
              'T2: the ticket does not carry its provenance (review, tool, evidence hash)')
        check(any(x.startswith('secure-cicd-kit-ck-') for x in issue['fields']['labels']) and
              'secure-cicd-kit-src-cloud-tool' in issue['fields']['labels'],
              'T2: the ticket does not carry the tagging labels: %r' % issue['fields']['labels'])


# ── T3 ─────────────────────────────────────────────────────────────────────────────────────

def t3(mods, tmp):
    """Dedupe against EVERY ticket (v2): a person's link makes a CLOSED DUPLICATE under the manual ticket, which is
    then found EXACT; a bad link is refused; "new" creates; the kit's stamp is exact; a search that did not
    complete creates the ticket DEDUPE PENDING; two tools on one asset and identifier are one ticket. (The near
    match created for triage, the regression and the outbox: tests/prove_ticket_intake_v2.py V5.)"""
    ka, ks, rt, tb, ps, tt, fc = mods
    w = W(mods, os.path.join(tmp, 'a'))
    f = finding(tt)
    manual = manual_ticket(tb, w.t, 'TLS 1.0 still enabled on acct1',
                           'Found by the audit: storage account %s allows TLS 1.0 (AZURE-STORAGE-TLS-1-0).'
                           % f['asset']['resource_id'])
    base = {'template': 'finding', 'template_version': 2, 'items': [f]}
    ck = tt.normalize('finding', f, {})['correlation_key']
    res, _s = w.submit(w.finalize('USR-DEDUPE-01', base, ), 'dedupe-0001', dry_run=True)
    it = items_of(res)
    check(it and [c.get('ref') for c in it[0].get('candidates') or []] == [manual] and len(w.t.issues) == 1 and
          (it[0].get('candidates') or [{}])[0].get('basis') == 'asset+identifier',
          'T3: a dry run did not surface the manual ticket as a candidate: %r' % it)
    linked = dict(base, link_decisions=[{'correlation_key': ck, 'decision': 'link', 'ref': manual}])
    res, _s = w.submit(w.finalize('USR-DEDUPE-02', linked), 'dedupe-0002')
    it = items_of(res)
    labels = w.t.issues[manual]['fields']['labels']
    check(it and it[0].get('outcome') == tt.TEMPLATE_CLOSED_DUPLICATE and len(w.t.issues) == 2 and
          'secure-cicd-kit-ck-%s' % ck in labels and 'secure-cicd-kit-linked' in labels,
          'T3: the confirmed link did not record a closed duplicate and label the manual ticket: %r %r' % (it, labels))
    res, _s = w.submit(w.finalize('USR-DEDUPE-03', base), 'dedupe-0003')
    it = items_of(res)
    # KDEC-043: the link wrote the FULL key into the kit's own block on the person's ticket; the next lookup is exact
    # by that key (body-stamp), not by trusting the label, and the person's own sentence is still there.
    desc = tb.adf_text(w.t.issues[manual].get('description'))
    check(it and it[0].get('outcome') == tt.TEMPLATE_LINKED_EXACT and it[0].get('basis') == 'body-stamp'
          and len(w.t.issues) == 2 and ('secure-cicd-kit-correlation-key: %s' % ck) in desc and
          'Found by the audit' in desc, 'T3: a linked manual ticket was not found exact next time: %r' % it)
    bad = dict(base, link_decisions=[{'correlation_key': ck, 'decision': 'link', 'ref': '99999'}])
    w2 = W(mods, os.path.join(tmp, 'b'))
    manual_ticket(tb, w2.t, 'TLS 1.0 still enabled on acct1', 'audit: %s AZURE-STORAGE-TLS-1-0' % f['asset']['resource_id'])
    res, _s = w2.submit(w2.finalize('USR-DEDUPE-04', bad), 'dedupe-0004')
    check(tref(res) == ('API_TEMPLATE_RULE_REFUSED', tt.LINK_DECISION_INVALID) and len(w2.t.issues) == 1,
          'T3: a link to a ticket that is not a candidate was %r' % (tref(res),))
    new = dict(base, link_decisions=[{'correlation_key': ck, 'decision': 'new'}])
    res, _s = w2.submit(w2.finalize('USR-DEDUPE-05', new), 'dedupe-0005')
    it = items_of(res)
    made = [i for i in w2.t.issues.values() if i['fields'].get('customfield_10001')]
    check(it and it[0].get('outcome') == tt.TEMPLATE_TICKET_CREATED and len(w2.t.issues) == 2 and made and
          'secure-cicd-kit-possible-duplicate' not in made[0]['fields']['labels'],
          'T3: a "new" decision did not create one unflagged ticket: %r' % it)
    res, _s = w2.submit(w2.finalize('USR-DEDUPE-06', base), 'dedupe-0006')
    it = items_of(res)
    check(it and it[0].get('outcome') == tt.TEMPLATE_TICKET_BOUND and len(w2.t.issues) == 2,
          'T3: the kit\'s own ticket was not found by its stamp: %r' % it)
    w3 = W(mods, os.path.join(tmp, 'c'), fail_search=True)
    res, _s = w3.submit(w3.finalize('USR-DEDUPE-07', base), 'dedupe-0007')
    it = items_of(res)
    check(len(w3.t.issues) == 1 and it and it[0].get('outcome') == tt.TEMPLATE_DEDUPE_PENDING,
          'T3: a search that did not answer lost the ticket or created it unflagged: %r %r' % (res.get('api_state'), it))
    w4 = W(mods, os.path.join(tmp, 'd'))
    two = {'template': 'finding', 'template_version': 2,
           'items': [finding(tt, source_tool='defender'), finding(tt, source_tool='prowler', source_type='usr')]}
    res, _s = w4.submit(w4.finalize('USR-DEDUPE-08', two), 'dedupe-0008')
    check(len(w4.t.issues) == 1, 'T3: two sources on one finding made %d ticket(s)' % len(w4.t.issues))
    if w4.t.issues:
        body = tb.adf_text(list(w4.t.issues.values())[0].get('description'))
        check('defender' in body and 'prowler' in body, 'T3: the one ticket does not name both tools')
    sc = [x.get('confidence') for x in items_of(res)]
    check(sc and all(isinstance(s, int) for s in sc), 'T3: no corroboration score on the items: %r' % sc)


# ── T4 ─────────────────────────────────────────────────────────────────────────────────────

def t4(mods, tmp):
    ka, ks, rt, tb, ps, tt, fc = mods
    a = tt.normalize('finding', finding(tt, source_tool='defender'), {})
    b = tt.normalize('finding', finding(tt, source_tool='prowler', source_type='usr'), {})
    c = tt.normalize('finding', finding(tt, source_tool='wiz', source_type='resource'), {})
    a2 = tt.normalize('finding', finding(tt, source_tool='defender'), {})
    s = {}
    for label, obs in (('one', [a]), ('two', [a, b]), ('three', [a, b, c]), ('same tool twice', [a, a2])):
        corr = fc.correlate(obs)
        s[label] = fc.corroboration_score(corr['clusters'][0], obs)
    check(s['one'][0] < s['two'][0] < s['three'][0], 'T4: the score does not rise with independent sources: %r'
          % dict((k, v[0]) for k, v in s.items()))
    check(s['same tool twice'][0] == s['one'][0] + 20 or s['same tool twice'][0] < s['two'][0],
          'T4: one tool twice counted as two independent sources: %r' % (s['same tool twice'],))
    corr = fc.correlate([a, b])
    cont = fc.corroboration_score(corr['clusters'][0], [a, b], contested=True)[0]
    check(cont < s['two'][0], 'T4: a contested cluster did not score lower')
    check(fc.corroboration_score({'tier': 'singleton', 'identity_established': False, 'members': [0]}, [{}])[0]
          is None, 'T4: a finding with no identity got a number')
    check('independent source' in s['two'][1] and 'evidence hash' in s['two'][1], 'T4: the basis does not name its terms')
    noev = dict(a, provenance=dict(a['provenance'], evidence_sha256=''))
    corr1 = fc.correlate([noev])
    check(fc.corroboration_score(corr1['clusters'][0], [noev])[0] == s['one'][0] - 10,
          'T4: evidence did not count')
    check(corr['clusters'][0]['tier'] == 'anchored', 'T4: the score replaced the tier')


# ── T5 / T6 ─────────────────────────────────────────────────────────────────────────────────

def _ticketed(mods, tmp, rid):
    """A world with one kit ticket made from a finalized finding review."""
    tt = mods[5]
    w = W(mods, tmp)
    base = {'template': 'finding', 'template_version': 2, 'items': [finding(tt)]}
    res, _s = w.submit(w.finalize(rid, base), 'seed-%s' % rid.lower())
    ref = (items_of(res) or [{}])[0].get('ref')
    return w, ref


def t5(mods, tmp):
    """Closure (v2): a fixer verifying is PENDING, never refused and never final; an unlinked manual ticket is
    TICKET_NOT_KIT_LINKED; a kit scan that never saw an external finding is CLOSURE_NOT_VERIFIED; an approved
    reviewer who is not the fixer closes it."""
    ka, ks, rt, tb, ps, tt, fc = mods
    w, ref = _ticketed(mods, tmp, 'USR-CLOSE-00')
    check(bool(ref), 'T5: the seed ticket was not created')
    if not ref:
        return
    ev = {'ref': 'pull/88', 'sha256': 'd' * 64}

    def close(item, rid, key):
        p = {'template': 'closure', 'template_version': 2, 'items': [dict(item, action='verify')]}
        if rid:
            p = w.finalize(rid, p)
        return w.submit(p, key)[0]
    res = close({'ref': ref, 'requested_by': 'app-team', 'fixed_by': REVIEWER, 'evidence': ev,
                 'verification': {'kind': 'reviewer'}}, 'USR-CLOSE-02', 'close-0002')
    check((items_of(res) or [{}])[0].get('outcome') == tt.TEMPLATE_PENDING_VERIFICATION and
          (w.t.status_of(ref).get('statusCategory') or {}).get('key') != 'done',
          'T5: the fixer verifying their own fix was not left pending: %r' % (items_of(res),))
    m = manual_ticket(tb, w.t, 'someone else\'s ticket', 'unrelated')
    res = close({'ref': m, 'requested_by': 'app-team', 'fixed_by': 'dev-one', 'evidence': ev,
                 'verification': {'kind': 'reviewer'}}, 'USR-CLOSE-03', 'close-0003')
    check(tref(res) == ('API_TEMPLATE_RULE_REFUSED', tt.TICKET_NOT_KIT_LINKED), 'T5: an unlinked manual ticket was %r'
          % (tref(res),))
    res = close({'ref': ref, 'requested_by': 'app-team', 'fixed_by': 'dev-one', 'evidence': ev,
                 'verification': {'kind': 'scan', 'run_id': w.w.sec_run}}, None, 'close-0004')
    check(tref(res) == ('API_TEMPLATE_RULE_REFUSED', tt.CLOSURE_NOT_VERIFIED),
          'T5: a kit scan that never observed an external finding verified it: %r' % (tref(res),))
    check(not w.t.transitions_posted, 'T5: a refused or pending closure moved a ticket')
    res = close({'ref': ref, 'requested_by': 'app-team', 'fixed_by': 'dev-one', 'evidence': ev,
                 'verification': {'kind': 'reviewer'}}, 'USR-CLOSE-05', 'close-0005')
    it = items_of(res)
    st = (w.t.status_of(ref).get('statusCategory') or {}).get('key')
    check(it and it[0].get('outcome') == tt.TEMPLATE_TICKET_CLOSED and st == 'done' and
          'secure-cicd-kit-remediated' in w.t.issues[ref]['fields']['labels'] and
          any(i == ref and REVIEWER in c and 'd' * 64 in c for i, c in w.t.comments),
          'T5: an approved reviewer\'s closure did not close with its evidence: %r %r' % (it, st))


def t5b(mods, tmp):
    """The scan path's allowed counterpart: a kit finding the pipeline ticketed, verified absent by a later
    completed default-branch run whose scanner covered the file, closes with no review; the same request
    against a run that still reports it is CLOSURE_NOT_VERIFIED."""
    ka, ks, rt, tb, ps, tt, fc = mods
    w = W(mods, tmp)
    obs = w.w.findings
    fpath, cpath = os.path.join(tmp, 'f.json'), os.path.join(tmp, 'findings-coverage.json')
    io.open(fpath, 'w', encoding='utf-8').write(json.dumps(obs))
    io.open(cpath, 'w', encoding='utf-8').write(json.dumps(ps.COVERAGE))
    env = dict(tb.JIRA_ENV, JIRA_TRANSITION_REOPEN='Reopen')
    ps._pipeline(rt, env, fpath, w.w.ledger, cpath)
    led = ps.read_ledger(w.w.ledger)
    key_a = [k for k, v in led.items() if 'a1' * 16 in (v.get('member_identities') or [])]
    if not check(key_a, 'T5b: the pipeline did not ticket the kit finding'):
        return
    ref = led[key_a[0]]['ref']
    still = w.w.sec_run
    fixed = w.w.stub.add_run(workflow='build-deploy.yml', head_sha='f' * 40)
    w.w.stub.add_artifact(fixed, 'security-report-1', {
        'findings.json': json.dumps([o for o in obs if o['identity'] != 'a1' * 16]),
        'findings-coverage.json': json.dumps(ps.COVERAGE)})
    ev = {'ref': 'pull/91', 'sha256': 'b' * 64}
    for label, run, want in (('a run that still reports it', still, tt.CLOSURE_NOT_VERIFIED),
                             ('a run that verified it absent', fixed, None)):
        p = {'template': 'closure', 'template_version': 2,
             'items': [{'ref': ref, 'action': 'verify', 'requested_by': 'app-team', 'fixed_by': 'dev-one',
                        'evidence': ev, 'verification': {'kind': 'scan', 'run_id': run}}]}
        res, _s = w.submit(p, 'scan-close-%d' % run)
        if want:
            check(tref(res) == ('API_TEMPLATE_RULE_REFUSED', want), 'T5b %s: %r' % (label, tref(res)))
        else:
            check(res.get('api_state') == 'API_COMPLETED' and
                  (w.t.status_of(ref).get('statusCategory') or {}).get('key') == 'done' and
                  ((res.get('data') or {}).get('review') or {}).get('state') == 'not required',
                  'T5b %s: the verified closure did not close the ticket: %r %r' % (label, res.get('api_state'),
                                                                                  tref(res)))


def t6(mods, tmp):
    ka, ks, rt, tb, ps, tt, fc = mods
    w, ref = _ticketed(mods, tmp, 'USR-EXT-00')
    if not check(bool(ref), 'T6: the seed ticket was not created'):
        return
    ev = {'ref': 'vendor-mail-12', 'sha256': 'c' * 64}
    n = [0]

    def extend(**over):
        n[0] += 1
        item = dict({'ref': ref, 'new_expiry': '2026-12-15', 'reason': 'the vendor moved the patch date by a month',
                     'extensions_used': 0, 'requested_by': 'app-team', 'evidence': ev, 'waiting_on': 'fix'}, **over)
        p = w.finalize('USR-EXT-%02d' % n[0], {'template': 'extension', 'template_version': 2, 'items': [item]})
        return w.submit(p, 'extend-%04d' % n[0])[0]
    res = extend(requested_by=REVIEWER)
    check(tref(res) == ('API_TEMPLATE_RULE_REFUSED', tt.SOD_SELF_APPROVAL), 'T6: a self-approved extension was %r'
          % (tref(res),))
    res = extend(extensions_used=1)
    check(tref(res) == ('API_TEMPLATE_RULE_REFUSED', tt.EXTENSION_COUNT_MISMATCH), 'T6: a wrong count was %r'
          % (tref(res),))
    res = extend(new_expiry='2027-09-01')
    check(tref(res) == ('API_TEMPLATE_INVALID', tt.EXTENSION_CEILING_EXCEEDED), 'T6: past the ceiling was %r'
          % (tref(res),))
    res = extend()
    it = items_of(res)
    check(it and it[0].get('outcome') == tt.TEMPLATE_TICKET_UPDATED and
          'secure-cicd-kit-extension-1' in w.t.issues[ref]['fields']['labels'] and
          any(i == ref and '2026-12-15' in c and 'extension 1 of 2' in c.lower() for i, c in w.t.comments),
          'T6: a valid extension did not record extension 1: %r' % it)
    res = extend(extensions_used=1, new_expiry='2027-01-15')
    check(res.get('api_state') == 'API_COMPLETED', 'T6: a second extension within the maximum was refused: %r'
          % (tref(res),))
    res = extend(extensions_used=2, new_expiry='2027-01-20')
    check(tref(res) == ('API_TEMPLATE_RULE_REFUSED', tt.EXTENSION_LIMIT_REACHED), 'T6: a third extension was %r'
          % (tref(res),))
    res = extend(extensions_used=0)
    check(tref(res) == ('API_TEMPLATE_RULE_REFUSED', tt.EXTENSION_COUNT_MISMATCH),
          'T6: a request hiding two extensions was %r' % (tref(res),))


# ── T7 ─────────────────────────────────────────────────────────────────────────────────────

def t7(mods, tmp):
    ka, ks, rt, tb, ps, tt, fc = mods
    w = W(mods, tmp)
    nf = finding(tt, fix_status='NO_FIX_AVAILABLE')
    p = w.finalize('USR-NOFIX-01', {'template': 'nofix-recheck', 'template_version': 2,
                                    'items': [{'finding': nf, 'vendor': 'Contoso', 'requested_by': 'app-team',
                                               'evidence': nf['evidence'], 'recheck_days': 10}]})
    res, _s = w.submit(p, 'nofix-0001')
    it = items_of(res)
    ref = (it or [{}])[0].get('ref')
    if not check(ref and 'secure-cicd-kit-nofix' in w.t.issues[ref]['fields']['labels'],
                 'T7: the no-fix ticket was not created with its label: %r' % it):
        return
    body = tb.adf_text(w.t.issues[ref].get('description'))
    check('2026-12-03' in body and '2026-11-13' in body and 'never a gate exception' in body,
          'T7: the ticket does not carry the exemption and the re-check due date')
    # The clock: due on the 13th, raised once.
    ledger = {}
    for day in ('2026-11-12', '2026-11-14', '2026-11-15'):
        rt.resurface(ledger, rt.choose_backend(tb.JIRA_ENV)[0], True, day)
    due = [c for i, c in w.t.comments if i == ref and 'RE-CHECK DUE' in c]
    check(len(due) == 1 and 'secure-cicd-kit-recheck-1' in w.t.issues[ref]['fields']['labels'],
          'T7: the clock raised the re-check %d time(s), expected once' % len(due))
    # A fix ships: the same finding, FIX_AVAILABLE, reopens it as remediation.
    w.t.issues[ref]['fields']['status'] = {'name': 'Done', 'statusCategory': {'key': 'done'}}
    p = w.finalize('USR-NOFIX-02', {'template': 'finding', 'template_version': 2,
                                    'items': [finding(tt, fix_status='FIX_AVAILABLE')]})
    res, _s = w.submit(p, 'nofix-0002')
    it = items_of(res)
    check(it and it[0].get('outcome') == tt.TEMPLATE_REOPENED_AS_REMEDIATION and
          (w.t.status_of(ref).get('statusCategory') or {}).get('key') == 'new' and
          'secure-cicd-kit-fix-available' in w.t.issues[ref]['fields']['labels'] and len(w.t.issues) == 1,
          'T7: a fix becoming available did not reopen the ticket as remediation: %r' % it)


# ── T8 ─────────────────────────────────────────────────────────────────────────────────────

def t8(mods, tmp):
    ka, ks, rt, tb, ps, tt, fc = mods
    w, ref = _ticketed(mods, tmp, 'USR-REQ-00')
    f = finding(tt)
    ev = f['evidence']
    items = {
        'false-positive': {'finding': f, 'justification': 'the rule matches a test fixture only', 'rule_id': 'R-1',
                           'tool_version': '4.2.0', 'requested_by': 'app-team', 'evidence': ev},
        'exception': {'finding': f, 'justification': 'parameterised traffic the WAF misreads',
                      'scope': {'from': 'gw', 'to': '/api/orders', 'condition': 'rule 942100 on POST'},
                      'compensating_controls': ['schema validation'], 'expires': '2026-12-31',
                      'requested_by': 'app-team', 'evidence': ev},
        'exemption': {'finding': f, 'justification': 'the integration stays on this protocol by design',
                      'review_every_days': 90, 'requested_by': 'app-team', 'evidence': ev},
        'accepted-risk': {'finding': f, 'justification': 'legacy hardware awaiting migration funding',
                          'owner': 'ops-lead', 'review_date': '2027-02-01', 'risk_register_ref': 'RISK-42',
                          'requested_by': 'app-team', 'evidence': ev},
        'mitigation': {'finding': f, 'justification': 'reachable only on a private endpoint', 'expires': '2027-02-01',
                       'compensating_control': 'private endpoint only, public network access disabled',
                       'requested_by': 'app-team', 'evidence': ev}}
    want = {'false-positive': 'FALSE_POSITIVE_REQUEST', 'exception': 'EXCEPTION_REQUEST',
            'exemption': 'EXEMPTION_REQUEST', 'accepted-risk': 'ACCEPTED_RISK_REQUEST', 'mitigation': 'MITIGATED_REQUEST'}
    for n, (tpl, cls) in enumerate(sorted(want.items()), 1):
        before = len(w.t.issues)
        res, _s = w.submit(w.finalize('USR-REQ-%02d' % n, {'template': tpl, 'template_version': 2,
                                                           'items': [items[tpl]]}), 'request-%04d' % n)
        created = ((res.get('data') or {}).get('reconcile') or {}).get('created') or []
        check(len(w.t.issues) == before + 1 and created and created[0].get('ticket_class') == cls,
              'T8 %s: no %s ticket beside the finding\'s: %r %r' % (tpl, cls, created, res.get('notes')))
        new = [i for i in w.t.issues.values() if int(i['id']) > int(ref)]
        body = tb.adf_text(new[-1].get('description')) if new else ''
        check('a REQUEST' in body and tt.normalize('finding', f, {})['correlation_key'] in body,
              'T8 %s: the request does not say it is a request or name the finding\'s key' % tpl)
    res, _s = w.submit({'template': 'accepted-risk', 'template_version': 2, 'items': [items['accepted-risk']]},
                       'request-norev')
    check((res.get('refusal') or {}).get('code') == 'API_REVIEW_NOT_FINALIZED', 'T8: a request with no review was %r'
          % (tref(res),))


# ── T9 ─────────────────────────────────────────────────────────────────────────────────────

def t9(mods, tmp):
    ka, ks, rt, tb, ps, tt, fc = mods
    w = W(mods, tmp)
    obs = w.w.findings
    ck_a = [o['cluster_key'] for o in obs if o['identity'] == 'a1' * 16][0]
    # KDEC-043: ticket 7 carries the label AND the kit's link line (the full key) -- it is linked. Ticket 9 carries
    # the label alone: a label is a search aid, so it is only a hint, never a link.
    for n in range(230):
        manual_ticket(tb, w.t, 'manual ticket %d' % n,
                      ('text %d\nsecure-cicd-kit-correlation-key: %s' % (n, ck_a)) if n == 7 else 'text %d' % n,
                      labels=['secure-cicd-kit-ck-%s' % ck_a] if n in (7, 9) else ['ops'])
    manual_ticket(tb, w.t, 'other board', 'x', project='OTHER')
    seen, token, pages = [], None, 0
    while pages < 5:
        q = {'max_results': 100}
        if token:
            q['page_token'] = token
        res = w.search({'tracker_query': q, 'findings_run_id': w.w.sec_run})
        data = res.get('data') or {}
        seen += data.get('tickets') or []
        token = data.get('next_page_token')
        pages += 1
        if not token:
            break
    check(len(seen) == 230 and pages == 3, 'T9: paging read %d ticket(s) in %d page(s), expected 230 in 3'
          % (len(seen), pages))
    j = [x for x in seen if x.get('linked_cluster_keys')]
    check(len(j) == 1 and j[0]['linked_cluster_keys'] == [ck_a] and j[0].get('manual') is True,
          'T9: the manual ticket carrying the full key was not joined to its finding: %r' % j)
    h = [x for x in seen if x.get('label_key_hints')]
    check(len(h) == 1 and not h[0].get('linked_cluster_keys') and h[0]['label_key_hints'] == [ck_a],
          'T9: a label with no full key behind it was read as a link (KDEC-043): %r' % h)
    check(all('_text' not in x and 'description' not in x for x in seen), 'T9: ticket text left the run')
    res = w.search({'tracker_query': {'projects': ['OTHER']}})
    check((res.get('refusal') or {}).get('code') == 'API_TRACKER_QUERY_REFUSED', 'T9: another project was %r'
          % (tref(res),))
    res = w.search({'tracker_query': {'jql': 'status = Done ORDER BY key'}})
    check((res.get('refusal') or {}).get('code') == 'API_TRACKER_QUERY_REFUSED', 'T9: ORDER BY was %r' % (tref(res),))
    res = w.search({'tracker_query': {'adapter': 'freshservice'}})
    check((res.get('data') or {}).get('intake_state') == 'TRACKER_INTAKE_NOT_CONFIGURED' and
          res.get('api_state') == 'API_FAILED', 'T9: FreshService answered %r' % (res.get('data'),))
    res = w.search({'tracker_query': {'labels': ['ops'], 'max_results': 5}})
    check(len((res.get('data') or {}).get('tickets') or []) == 5, 'T9: a labels query answered %r'
          % len((res.get('data') or {}).get('tickets') or []))


# ── T10 ────────────────────────────────────────────────────────────────────────────────────

def t10(mods, tmp):
    ka, ks, rt, tb, ps, tt, fc = mods
    w = W(mods, tmp)
    res, _s = w.submit({'template': 'finding', 'template_version': 2, 'items': [dict(finding(tt), severity='urgent')]},
                       'invalid-0001')
    check(tref(res) == ('API_TEMPLATE_INVALID', tt.TEMPLATE_FIELD_INVALID), 'T10: an invalid item was %r' % (tref(res),))
    check(not w.replay.requests, 'T10: an invalid item reached the tracker')
    for code in NEW_REFUSALS:
        check(code in PRODUCED, 'T10: the refusal %s is never produced by a case' % code)
    doc = json.load(io.open(os.path.join(ROOT, 'api', 'v1', 'refusals.json'), encoding='utf-8'))
    for code in NEW_REFUSALS:
        check(code in doc['refusals'] and code in ka.REFUSALS, 'T10: %s is not in refusals.json and the client' % code)
    p = {'template': 'finding', 'template_version': 2, 'review_id': 'USR-X-001', 'items': [finding(tt)]}
    path = os.path.join(tmp, 'p.json')
    io.open(path, 'w', encoding='utf-8').write(json.dumps(p))
    out = io.StringIO()
    old = sys.stdout
    try:
        sys.stdout = out
        rc = ka.main(['evidence-hash', '--params', path])
    finally:
        sys.stdout = old
    check(rc == 0 and out.getvalue().strip() == tt.evidence_set_sha256(p),
          'T10: the CLI evidence hash is not the server\'s (%r)' % out.getvalue().strip()[:20])


def main():
    mods = imports()
    if mods is None:
        return 1
    tmp = tempfile.mkdtemp(prefix='kit-templates-')
    real_urlopen = __import__('urllib.request').request.urlopen
    try:
        for case in (t1, t2, t3, t4, t5, t5b, t6, t7, t8, t9, t10):
            d = tempfile.mkdtemp(dir=tmp)
            for sub in ('a', 'b', 'c', 'd'):
                os.makedirs(os.path.join(d, sub))
            try:
                case(mods, d)
            except (Exception, SystemExit) as exc:  # noqa: BLE001 -- a crash is a failed case, named
                import traceback
                FAILS.append('%s crashed: %s: %s\n%s' % (case.__name__, type(exc).__name__, exc,
                                                         traceback.format_exc()[-2500:]))
    finally:
        __import__('urllib.request').request.urlopen = real_urlopen
        shutil.rmtree(tmp, ignore_errors=True)
    for f in FAILS:
        print('FAIL: %s' % f)
    if FAILS:
        print('\n%d failure(s)' % len(FAILS))
        return 1
    print('prove_ticket_templates: T1..T10 hold -- every template checked and refused by name; nothing is written '
          'without a finalized, human-concurred review bound to the evidence set; every ticket, manual ones included, '
          'is searched before a create and a candidate is never merged; the corroboration score rises with '
          'independent evidence; closure is verified and never self-verified; extensions are counted and capped; a '
          'no-fix re-check reopens as remediation; tracker intake pages')
    return 0


if __name__ == '__main__':
    sys.exit(main())
