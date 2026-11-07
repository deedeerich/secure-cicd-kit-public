#!/usr/bin/env python3
"""Jira without a personal binding, and tickets routed to the right board. NO NETWORK.

(KDEC-028, lane L-AM, owner 2026-10-23: "Jira auth without a personal binding" and "ticket routing to
different projects/boards" -- e.g. IaC and cloud findings to an Azure Security project, everything
else to the IT Security board or the product's own.)

WHAT IT PROVES -- urlopen is the Replay of tests/prove_ticket_backends.py; nothing leaves the machine.

  BEARER (JIRA_AUTH_MODE=bearer: JIRA_TOKEN alone, through Atlassian's gateway)
    B1  bearer sends `Authorization: Bearer <JIRA_TOKEN>` to https://api.atlassian.com/ex/jira/<cloudId>
        and NOTHING to the site host; no email is needed or sent
    B2  with no JIRA_CLOUD_ID the cloud id is looked up at https://<host>/_edge/tenant_info, a call
        that carries NO credential, and the gateway is then used with what it returned
    B3  a lookup that fails (404, no cloudId, a malformed one) refuses by name (JIRA_CLOUD_ID) and
        sends nothing to the gateway; nothing is created
    B4  basic stays the default and is used whenever JIRA_EMAIL is set -- even beside
        JIRA_AUTH_MODE=bearer, which the backend note then names; basic with JIRA_CLOUD_ID set goes
        through the gateway (a scoped token needs it)
    B5  misconfiguration is refused by name: an unknown JIRA_AUTH_MODE, bearer with no JIRA_TOKEN,
        basic with no JIRA_EMAIL, a malformed JIRA_CLOUD_ID
    B6  a 401 under bearer names JIRA_TOKEN, never JIRA_EMAIL
    B7  every Jira caller takes it: exception_due's chooser, check_env's required list, both reusable
        workflows (JIRA_AUTH_MODE and JIRA_CLOUD_ID reach the step; JIRA_EMAIL is optional); the PR
        reference gate and an overlay's run_jira_step make NO Jira API call, so carry no credential
  ROUTING (`ticket_routing` in the policy register)
    R1  precedence: repository > product/team > org > enterprise > kit default (JIRA_PROJECT); a
        narrower scope overrides freely -- routing is not a security floor
    R2  `inherit: false` replaces the inherited rules; the default comes from the most specific scope
    R3  `project: "none"` for a secret, KEV or malicious class is REFUSED by name
        (TICKET_ROUTING_BELOW_FLOOR, BLOCKED), and at run time a none-rule or none-default never
        stops a floor-class finding from being ticketed (it falls through to JIRA_PROJECT)
    R4  end to end on a stateful two-project Jira: an IaC finding lands in AZSEC with the rule's
        issue type, components and labels, a SAST finding in SEC; the sweep covers both projects;
        every routed project is validated at run start
    R5  a RULE CHANGE never moves or duplicates a ticket: the next run finds the ticket where it
        is (the ledger remembers the project, the sweep covers it), comments on it, creates nothing
    R6  rerunning with the same rule creates nothing

EXIT  0 proven   1 a case failed (named)   2 could not be checked
"""
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

import prove_ticket_backends as ptb  # noqa: E402

CLOUD = '11111111-2222-3333-4444-555555555555'
GATEWAY = 'https://api.atlassian.com/ex/jira/%s' % CLOUD
TOKEN = 'placeholder-token'
BEARER_ENV = dict((k, v) for k, v in ptb.JIRA_ENV.items() if k != 'JIRA_EMAIL')
BEARER_ENV['JIRA_AUTH_MODE'] = 'bearer'
TODAY = '2026-10-23'
RUN = {'run_url': 'https://github.example/o/r/actions/runs/1', 'commit': 'a' * 40}


def _healthy_project(r, key, pid):
    r.on('GET', r'/rest/api/3/project/%s$' % key, ptb.ok({'id': pid, 'key': key}))
    r.on('GET', r'/rest/api/3/issue/createmeta/%s/issuetypes$' % key, ptb.ok(
        {'issueTypes': [{'id': '10004', 'name': 'Story'}, {'id': '10005', 'name': 'Subtask'},
                        {'id': '10007', 'name': 'Bug'}]}))
    for tid in ('10004', '10007'):
        r.on('GET', r'/rest/api/3/issue/createmeta/%s/issuetypes/%s$' % (key, tid),
             ptb.ok(ptb.CREATEMETA_STORY))


# ── BEARER ───────────────────────────────────────────────────────────────────────────────

def case_bearer(rt, fails):
    # B1
    r = ptb.install(ptb.Replay())
    ptb._jira_healthy(r)
    env = dict(BEARER_ENV, JIRA_CLOUD_ID=CLOUD)
    b, note = rt.choose_backend(env)
    if b is None:
        fails.append('B1: bearer with JIRA_TOKEN + JIRA_CLOUD_ID and no JIRA_EMAIL was refused: %s'
                     % note)
        return
    ok, detail = b.validate()
    if not ok:
        fails.append('B1: bearer validation failed against a healthy gateway: %s' % detail)
    if not r.requests:
        fails.append('B1: no request was made')
    for q in r.requests:
        if not q['url'].startswith(GATEWAY + '/rest/api/3/'):
            fails.append('B1: bearer sent a request outside the gateway: %s' % q['url'])
        auth = q['headers'].get('authorization', '')
        if auth != 'Bearer %s' % TOKEN:
            fails.append('B1: bearer request carried Authorization %r, not the bearer token'
                         % (auth[:12] + '...'))
    # B2: the cloud id looked up, with no credential on the lookup
    r = ptb.install(ptb.Replay())
    ptb._jira_healthy(r)
    r.on('GET', r'^https://example\.atlassian\.net/_edge/tenant_info$', ptb.ok({'cloudId': CLOUD}))
    b, note = rt.choose_backend(dict(BEARER_ENV))
    if b is None:
        fails.append('B2: bearer with no JIRA_CLOUD_ID was refused instead of looked up: %s' % note)
        return
    ok, detail = b.validate()
    looked = [q for q in r.requests if q['url'].endswith('/_edge/tenant_info')]
    if len(looked) != 1:
        fails.append('B2: the tenant_info lookup ran %d time(s), expected once' % len(looked))
    elif 'authorization' in looked[0]['headers']:
        fails.append('B2: the tenant_info lookup carried an Authorization header -- the credential '
                     'went to an endpoint that needs none')
    if not ok or not any(q['url'].startswith(GATEWAY) for q in r.requests):
        fails.append('B2: after the lookup the gateway was not used (%s)' % detail)
    # B3: lookup failures, each refused by name, nothing sent to the gateway
    for label, handler in (
            ('404', lambda rec: (404, {'errorMessages': ['no']}, {})),
            ('no cloudId in the answer', lambda rec: (200, {'something': 'else'}, {})),
            ('malformed cloudId', lambda rec: (200, {'cloudId': '../../evil'}, {}))):
        r = ptb.install(ptb.Replay())
        ptb._jira_healthy(r)
        r.on('GET', r'/_edge/tenant_info$', handler)
        b, _n = rt.choose_backend(dict(BEARER_ENV))
        if b is None:
            fails.append('B3 %s: refused at configuration, before the lookup could fail' % label)
            continue
        ok, detail = b.validate()
        if ok or 'JIRA_CLOUD_ID' not in detail:
            fails.append('B3 %s: a failed cloud id lookup did not refuse naming JIRA_CLOUD_ID '
                         '(ok=%r, %s)' % (label, ok, detail))
        if any('/rest/api/' in q['url'] for q in r.requests):
            fails.append('B3 %s: a request reached the API after the lookup failed' % label)
    # B4: basic is the default and wins whenever JIRA_EMAIL is set
    r = ptb.install(ptb.Replay())
    ptb._jira_healthy(r)
    b, note = rt.choose_backend(dict(ptb.JIRA_ENV, JIRA_AUTH_MODE='bearer'))
    if b is None:
        fails.append('B4: JIRA_EMAIL beside JIRA_AUTH_MODE=bearer was refused: %s' % note)
    else:
        b.validate()
        auths = set(q['headers'].get('authorization', '')[:6] for q in r.requests)
        if auths != {'Basic '} or any(not q['url'].startswith('https://example.atlassian.net/')
                                      for q in r.requests):
            fails.append('B4: with JIRA_EMAIL set the requests were not basic to the site: %r'
                         % sorted(auths))
        if 'JIRA_AUTH_MODE' not in note or 'basic' not in note.lower():
            fails.append('B4: basic overriding JIRA_AUTH_MODE=bearer was not named in the backend '
                         'note: %r' % note)
    r = ptb.install(ptb.Replay())
    ptb._jira_healthy(r)
    b, note = rt.choose_backend(dict(ptb.JIRA_ENV, JIRA_CLOUD_ID=CLOUD))
    if b is None:
        fails.append('B4: basic with JIRA_CLOUD_ID was refused: %s' % note)
    else:
        b.validate()
        if not r.requests or any(not q['url'].startswith(GATEWAY) for q in r.requests) or \
                any(not q['headers'].get('authorization', '').startswith('Basic ')
                    for q in r.requests):
            fails.append('B4: basic with JIRA_CLOUD_ID did not go to the gateway with basic auth')
    # B5: refusals by name
    for label, env, name in (
            ('unknown JIRA_AUTH_MODE', dict(BEARER_ENV, JIRA_AUTH_MODE='oauth'), 'JIRA_AUTH_MODE'),
            ('bearer, no token', dict(BEARER_ENV, JIRA_TOKEN=''), 'JIRA_TOKEN'),
            ('basic, no email', dict(BEARER_ENV, JIRA_AUTH_MODE='basic'), 'JIRA_EMAIL'),
            ('malformed JIRA_CLOUD_ID', dict(BEARER_ENV, JIRA_CLOUD_ID='not-a-cloud-id'),
             'JIRA_CLOUD_ID')):
        b, note = rt.choose_backend(env)
        if b is not None or name not in note:
            fails.append('B5 %s: not refused naming %s (%s)' % (label, name, note))
    # B6: a refused bearer token names JIRA_TOKEN
    r = ptb.install(ptb.Replay())
    r.on('GET', r'/rest/api/3/myself$', lambda rec: (401, {'message': 'Unauthorized'}, {}))
    b, _n = rt.choose_backend(dict(BEARER_ENV, JIRA_CLOUD_ID=CLOUD))
    if b is not None:
        ok, detail = b.validate()
        if ok or 'JIRA_TOKEN' not in detail or 'JIRA_EMAIL' in detail:
            fails.append('B6: a 401 under bearer did not name JIRA_TOKEN alone: %s' % detail)


def case_callers(rt, fails):
    """B7: every Jira caller."""
    import exception_due as ed
    b, state, why = ed.choose(dict(BEARER_ENV, JIRA_CLOUD_ID=CLOUD), None)
    if b is None or getattr(b, 'name', '') != 'jira':
        fails.append('B7: exception_due refused a bearer configuration: %s %s' % (state, why))
    import check_env as ce
    req = ce.required_for('jira', {'JIRA_AUTH_MODE': 'bearer'})
    if 'JIRA_EMAIL' in req:
        fails.append('B7: check_env requires JIRA_EMAIL in bearer mode')
    if 'JIRA_EMAIL' not in ce.required_for('jira', {}):
        fails.append('B7: check_env no longer requires JIRA_EMAIL in the default basic mode')
    for wf in ('reusable-ticket-reconcile.yml', 'reusable-exception-due.yml'):
        text = io.open(os.path.join(ROOT, '.github', 'workflows', wf), encoding='utf-8').read()
        for var in ('JIRA_AUTH_MODE: ${{ vars.JIRA_AUTH_MODE }}',
                    'JIRA_CLOUD_ID: ${{ vars.JIRA_CLOUD_ID }}'):
            if var not in text:
                fails.append('B7: %s does not pass %s to the Jira step' % (wf, var.split(':')[0]))
        m = re.search(r'\n      JIRA_EMAIL:\n((?:        .*\n)+)', text)
        if not m or 'required: false' not in m.group(1):
            fails.append('B7: %s declares JIRA_EMAIL as required; bearer needs none' % wf)
    import glob
    # The reference gate and every overlay's run of its step (found by glob: this file names none).
    for path in (['.github/workflows/reusable-ticket-reference.yml'] +
                 sorted(os.path.relpath(p, ROOT) for p in glob.glob(
                     os.path.join(ROOT, 'overlays', '*', 'tests', 'run_jira_step.py')))):
        text = io.open(os.path.join(ROOT, path), encoding='utf-8').read()
        if 'JIRA_TOKEN' in text or 'secrets.JIRA' in text or '/rest/api/' in text:
            fails.append('B7: %s now reaches Jira with a credential; the reference gate reads the '
                         'pull request only' % path)


# ── ROUTING ──────────────────────────────────────────────────────────────────────────────

DECISION = {'authority': 'Dana Example', 'reason': 'route findings to the owning board',
            'decided_on': '2026-10-22', 'expires': '2027-10-22',
            'environment_reviewers': ['platform-approvers']}


def central(routing_by_scope):
    pols = []
    for i, (scope, routing) in enumerate(routing_by_scope):
        pols.append({'id': 'r%d' % i, 'scope': scope, 'ticket_routing': routing,
                     'decision': DECISION})
    return {'schema_version': 2, 'register_id': 'routing-proof',
            'sign_off': {'by': 'Dana Example', 'role': 'security-lead', 'date': '2026-10-22'},
            'orgs': {'org-a': 'ent'},
            'repositories': {'org-a/app': {'team': 'payments', 'product': 'ledger'}},
            'policies': pols}


def repo_file(routing):
    return {'schema_version': 2, 'register_id': 'repo',
            'sign_off': {'by': 'Dana Example', 'role': 'security-lead', 'date': '2026-10-22'},
            'policies': [{'id': 'repo', 'scope': {}, 'ticket_routing': routing,
                          'decision': DECISION}]}


IAC = {'scanner_family': ['iac'], 'category': ['IAC_PLAN', 'RESOURCE', 'POLICY']}
FACTS_IAC = {'class': 'finding', 'floor': False, 'scanner_family': 'iac', 'scanners': ['checkov'],
             'category': 'IAC_PLAN', 'severity': 'high', 'repository': 'org-a/app'}
FACTS_SAST = dict(FACTS_IAC, scanner_family='sast', scanners=['semgrep'], category='SOURCE')
FACTS_SECRET = dict(FACTS_IAC, **{'class': 'secret', 'floor': True, 'scanner_family': 'secrets',
                                   'scanners': ['gitleaks'], 'category': 'SOURCE'})


def case_routing_resolution(rt, fails):
    import ticket_routing as tr
    import policy_registration as pr
    ent = ({'enterprise': 'ent'}, {'rules': [{'id': 'e-iac', 'match': IAC, 'project': 'ENTSEC'}],
                                   'default': {'project': 'ENTDEF'}})
    org = ({'org': 'org-a'}, {'rules': [{'id': 'o-iac', 'match': IAC, 'project': 'AZSEC',
                                         'issue_type': 'Bug', 'components': ['Azure'],
                                         'labels': ['cloud']}],
                              'default': {'project': 'SEC'}})
    prod = ({'org': 'org-a', 'product': 'ledger'},
            {'rules': [{'id': 'p-sast', 'match': {'scanner_family': ['sast']}, 'project': 'LEDG'}]})
    # R1: the chain, most specific first
    doc = central([ent, org, prod])
    probs = pr.check_document(doc, pr.ORIGIN_CENTRAL)
    if probs:
        fails.append('R1: a valid routing register was refused: %s' % probs)
        return
    routing = tr.resolve_routing(doc, None, 'org-a/app')
    got = tr.route(FACTS_IAC, routing, 'KIT')
    if got['project'] != 'AZSEC' or got.get('issue_type') != 'Bug' or \
            got.get('components') != ['Azure'] or 'cloud' not in (got.get('labels') or []):
        fails.append('R1: the org rule (over the enterprise one) did not route IaC to AZSEC with its '
                     'type, component and label: %r' % got)
    got = tr.route(FACTS_SAST, routing, 'KIT')
    if got['project'] != 'LEDG':
        fails.append('R1: the product rule did not route SAST to LEDG: %r' % got)
    got = tr.route(dict(FACTS_SAST, scanner_family='sca', category='SOURCE_DEPENDENCY'), routing,
                   'KIT')
    if got['project'] != 'SEC':
        fails.append('R1: the org default (over the enterprise default) did not apply: %r' % got)
    # repository file beats everything
    rdoc = repo_file({'rules': [{'id': 'mine', 'match': IAC, 'project': 'APP'}]})
    if pr.check_document(rdoc, pr.ORIGIN_REPOSITORY):
        fails.append('R1: a repository file carrying ticket_routing was refused: %s'
                     % pr.check_document(rdoc, pr.ORIGIN_REPOSITORY))
    routing = tr.resolve_routing(doc, rdoc, 'org-a/app')
    if tr.route(FACTS_IAC, routing, 'KIT')['project'] != 'APP':
        fails.append('R1: the repository entry did not win over the org rule')
    # unmapped repository in another org, no register: the kit default
    if tr.route(FACTS_IAC, tr.resolve_routing(None, None, 'x/y'), 'KIT')['project'] != 'KIT':
        fails.append('R1: with no register the kit default (JIRA_PROJECT) did not apply')
    # R2: inherit false replaces; default comes from the most specific scope that sets one
    rdoc = repo_file({'inherit': False, 'rules': [{'id': 'only', 'match': {'severity': ['critical']},
                                                   'project': 'CRIT'}]})
    routing = tr.resolve_routing(doc, rdoc, 'org-a/app')
    if tr.route(FACTS_IAC, routing, 'KIT')['project'] != 'SEC':
        fails.append('R2: inherit false did not drop the inherited IaC rule (default SEC expected)')
    if tr.route(dict(FACTS_IAC, severity='critical'), routing, 'KIT')['project'] != 'CRIT':
        fails.append('R2: the repository\'s own rule did not apply')
    # R3: none for a floor class, refused by name
    for cls in ('secret', 'kev', 'malicious'):
        bad = central([({'org': 'org-a'}, {'rules': [{'id': 'quiet', 'match': {'class': [cls]},
                                                      'project': 'none'}]})])
        codes = [c for c, _m in pr.check_document(bad, pr.ORIGIN_CENTRAL)]
        if tr.TICKET_ROUTING_BELOW_FLOOR not in codes:
            fails.append('R3: routing class %s to none was not refused as %s (got %r)'
                         % (cls, tr.TICKET_ROUTING_BELOW_FLOOR, codes))
        r = pr.resolve(bad, None, 'org-a/app', 'prod', 'push', {}, TODAY)
        if r['state'] != tr.TICKET_ROUTING_BELOW_FLOOR or r['routes_to'] != 'BLOCKED':
            fails.append('R3: the resolver did not refuse %s routed to none by name, BLOCKED: %s %s'
                         % (cls, r['state'], r.get('routes_to')))
    # run time: a none default and an unconstrained none-rule never swallow a floor finding
    quiet = central([({'org': 'org-a'}, {'rules': [{'id': 'drop-low', 'match': {
        'severity': ['high']}, 'project': 'none'}], 'default': {'project': 'none'}})])
    if pr.check_document(quiet, pr.ORIGIN_CENTRAL):
        fails.append('R3: a none default / an unconstrained none-rule was refused statically; it '
                     'is legal for ordinary findings (got %s)'
                     % pr.check_document(quiet, pr.ORIGIN_CENTRAL))
    routing = tr.resolve_routing(quiet, None, 'org-a/app')
    got = tr.route(FACTS_SECRET, routing, 'KIT')
    if got['project'] != 'KIT' or not any(tr.TICKET_ROUTING_BELOW_FLOOR in n
                                          for n in got.get('notes') or []):
        fails.append('R3: a secret finding under a none-rule/none-default was not ticketed in the '
                     'kit default project with a named note: %r' % got)
    if tr.route(FACTS_SAST, routing, 'KIT')['project'] is not None:
        fails.append('R3: an ordinary finding under a none-rule was still ticketed')
    # structure refused (not silently ignored)
    for label, routing_obj in (('unknown match key', {'rules': [{'match': {'colour': 'red'},
                                                                 'project': 'SEC'}]}),
                               ('bad project key', {'default': {'project': 'sec board'}}),
                               ('unknown rule field', {'rules': [{'project': 'SEC', 'x': 1}]})):
        codes = [c for c, _m in pr.check_document(
            central([({'org': 'org-a'}, routing_obj)]), pr.ORIGIN_CENTRAL)]
        if not codes:
            fails.append('R3: a malformed ticket_routing (%s) was accepted' % label)


class TwoProjectJira(ptb.JiraTracker):
    """The stateful Jira of prove_ticket_backends, with projects: create stores the project and keys
    the issue by it, search honours `project = ` and `project in (...)`."""

    def __init__(self, replay, projects=('KIT', 'AZSEC', 'SEC')):
        super(TwoProjectJira, self).__init__(replay)
        self.created_in = {}
        self.jql_seen = []
        for i, key in enumerate(projects):
            _healthy_project(replay, key, str(10010 + i))
        replay.on('POST', r'/rest/api/3/search/jql$', self._search_p)
        replay.on('POST', r'/rest/api/3/issue$', self._create_p)

    def _search_p(self, rec):
        jql = rec['json']['jql']
        self.jql_seen.append(jql)
        m = re.search(r'project in \(([^)]*)\)', jql)
        allowed = set(re.findall(r'"([^"]+)"', m.group(1))) if m else \
            set(re.findall(r'project = "([^"]+)"', jql))
        label = re.search(r'labels = "([^"]+)"', jql).group(1)
        m = re.search(r'issuetype in \(([^)]*)\)', jql)
        types = set(re.findall(r'"([^"]+)"', m.group(1))) if m else \
            set(re.findall(r'issuetype = "([^"]+)"', jql))
        hits = [x for i, x in sorted(self.issues.items(), key=lambda kv: int(kv[0]))
                if self.created_in.get(i, 'KIT') in allowed and label in x['fields']['labels']
                and x['type'] in types]
        return 200, {'issues': hits, 'isLast': True}, {}

    def _create_p(self, rec):
        f = rec['json']['fields']
        status, doc, h = self._create(rec)
        proj = (f.get('project') or {}).get('key')
        self.created_in[doc['id']] = proj
        self.issues[doc['id']]['key'] = '%s-%s' % (proj, doc['id'])
        self.issues[doc['id']]['fields']['issuetype'] = f.get('issuetype')
        self.issues[doc['id']]['fields']['components'] = f.get('components')
        return status, dict(doc, key='%s-%s' % (proj, doc['id'])), h


def obs(scanner, rule, path, ident, job, subject, severity='HIGH'):
    return {'scanner': scanner, 'tool': scanner, 'scanner_version': '', 'rule_id': rule,
            'severity': severity, 'line': 3, 'canonical_path': path, 'finding_subject': subject,
            'state': 'FINGERPRINTED', 'identity': ident, 'what': rule, 'where': path,
            'content': '', 'identity_scope': '', 'what_aliases': [], 'cwe': '', 'reason': '',
            'detail': '', 'fp': ident[:12].ljust(12, '0'), 'job': job, 'row_established': True}


RECORDS = [obs('checkov', 'CKV_AZURE_1', 'infra/main.tf', 'id-iac-1', 'iac-scan', 'IAC_PLAN'),
           obs('semgrep', 'php.lang.sqli', 'app/db.php', 'id-sast-1', 'sast-semgrep', 'SOURCE')]


def _routing(tr, iac_project):
    doc = central([({'org': 'org-a'}, {
        'rules': [{'id': 'cloud', 'match': IAC, 'project': iac_project, 'issue_type': 'Bug',
                   'components': ['Azure'], 'labels': ['cloud-security']}],
        'default': {'project': 'SEC'}})])
    return tr.resolve_routing(doc, None, 'org-a/app')


def _run(rt, jira, records, ledger, routing, extra=None):
    clusters, withheld = rt.build_clusters(records)
    b = ptb.backend(rt, dict(ptb.JIRA_ENV, **(extra or {})))
    return rt.reconcile(clusters, withheld, b, ledger, True, today=TODAY,
                        context=dict(RUN, coverage=None, numbers=None, exceptions={},
                                     routing=routing, repository='org-a/app'))


def case_routing_end_to_end(rt, fails):
    import ticket_routing as tr
    r = ptb.install(ptb.Replay())
    jira = TwoProjectJira(r)
    ledger = {}
    res = _run(rt, jira, RECORDS, ledger, _routing(tr, 'AZSEC'))
    where = sorted(jira.created_in.values())
    if where != ['AZSEC', 'SEC']:
        fails.append('R4: tickets were created in %r, expected one in AZSEC and one in SEC (%s)'
                     % (where, '; '.join(res.get('notes') or [])[:300]))
    for i, p in jira.created_in.items():
        f = jira.issues[i]['fields']
        if p == 'AZSEC' and ((f.get('issuetype') or {}).get('name') != 'Bug' or
                             f.get('components') != [{'name': 'Azure'}] or
                             'cloud-security' not in (f.get('labels') or [])):
            fails.append('R4: the AZSEC ticket did not carry the rule\'s type, component and label: '
                         '%r' % f)
    if not any('project in (' in q and '"AZSEC"' in q and '"SEC"' in q for q in jira.jql_seen):
        fails.append('R4: the sweep did not cover every routed project: %r' % jira.jql_seen[:2])
    checked = set(re.search(r'/project/([A-Z]+)$', q['url']).group(1) for q in r.requests
                  if re.search(r'/rest/api/3/project/[A-Z]+$', q['url']))
    if not {'AZSEC', 'SEC', 'KIT'} <= checked:
        fails.append('R4: run-start validation did not read every routed project (read %r)'
                     % sorted(checked))
    for key, entry in ledger.items():
        if not entry.get('project'):
            fails.append('R4: the ledger entry %s does not record the project its ticket is in'
                         % key[:12])
    # R6: same rule, rerun: nothing new
    before = len(jira.issues)
    _run(rt, jira, RECORDS, ledger, _routing(tr, 'AZSEC'))
    if len(jira.issues) != before:
        fails.append('R6: rerunning with the same rule created %d more ticket(s)'
                     % (len(jira.issues) - before))
    # R5: the rule changes (IaC now to KIT): the AZSEC ticket stays, is commented, nothing is created
    azsec = [i for i, p in jira.created_in.items() if p == 'AZSEC']
    _run(rt, jira, RECORDS, ledger, _routing(tr, 'KIT'))
    if len(jira.issues) != before:
        fails.append('R5: a rule change created %d duplicate ticket(s)' % (len(jira.issues) - before))
    if [jira.created_in[i] for i in azsec] != ['AZSEC']:
        fails.append('R5: the existing ticket moved project')
    if '"AZSEC"' not in (jira.jql_seen[-1] if jira.jql_seen else ''):
        fails.append('R5: after the rule change the sweep no longer covered AZSEC, where the ticket '
                     'is (from the ledger): %r' % jira.jql_seen[-1:])
    said = [c for i, c in jira.comments if i in azsec and 'routing' in c.lower() and 'KIT' in c]
    if len(said) != 1:
        fails.append('R5: the ticket that stays in AZSEC did not get exactly one comment naming the '
                     'new route (got %d)' % len(said))
    _run(rt, jira, RECORDS, ledger, _routing(tr, 'KIT'))
    said2 = [c for i, c in jira.comments if i in azsec and 'routing' in c.lower() and 'KIT' in c]
    if len(said2) != len(said) or len(jira.issues) != before:
        fails.append('R5: a rerun under the changed rule commented again or created a ticket')
    # Without a ledger the sweep still finds it while AZSEC is still named anywhere in the routing.
    r3 = ptb.install(ptb.Replay())
    jira3 = TwoProjectJira(r3)
    _run(rt, jira3, RECORDS, {}, _routing(tr, 'AZSEC'))
    n3 = len(jira3.issues)
    both = _routing(tr, 'KIT')
    both['rules'].append({'id': 'old', 'match': {'scanner': ['nothing-matches']},
                          'project': 'AZSEC', 'source': 'org'})
    _run(rt, jira3, RECORDS, {}, both)
    if len(jira3.issues) != n3:
        fails.append('R5: with no ledger and AZSEC still named, a rule change duplicated a ticket')


def case_test_mode(rt, fails):
    """T1-T6: test ticketing is chosen by the REF, never a variable someone swaps back
    (owner 2026-10-23: forgetting to put it back to main would be catastrophic)."""
    import ticket_routing as tr
    test_env = dict(ptb.JIRA_ENV, TICKETING_MODE='test', JIRA_PROJECT='SECTEST',
                    JIRA_REAL_PROJECTS='SEC,AZSEC')
    # T1: no JIRA_REAL_PROJECTS -> refused by name (it cannot be shown the sandbox is not real)
    b, note = rt.choose_backend(dict(test_env, JIRA_REAL_PROJECTS=''))
    if b is not None or rt.TICKETING_TEST_TARGETS_REAL_PROJECT not in note:
        fails.append('T1: a test run with no JIRA_REAL_PROJECTS was not refused by name: %s' % note)
    # T2: the sandbox IS a real project
    b, note = rt.choose_backend(dict(test_env, JIRA_PROJECT='SEC'))
    if b is not None or rt.TICKETING_TEST_TARGETS_REAL_PROJECT not in note:
        fails.append('T2: a test run whose JIRA_PROJECT is in JIRA_REAL_PROJECTS was not refused: %s'
                     % note)
    # T3: a sandbox run with real routing in the register: everything to SECTEST, labelled, [TEST]
    r = ptb.install(ptb.Replay())
    jira = TwoProjectJira(r, projects=('KIT', 'SECTEST', 'AZSEC', 'SEC'))
    r.on('GET', r'/rest/api/3/issue/10000\b', ptb.ok({'id': '10000', 'fields': {
        'project': {'key': 'SECTEST'}, 'issuetype': {'name': 'Epic'}}}))
    ledger = {'realkey': {'ref': '777', 'project': 'SEC', 'member_identities': ['id-iac-1']}}
    clusters, withheld = rt.build_clusters(RECORDS)
    b = ptb.backend(rt, test_env)
    res = rt.reconcile(clusters, withheld, b, ledger, True, today=TODAY,
                       context=dict(RUN, coverage=None, numbers=None, exceptions={},
                                    routing=_routing(tr, 'AZSEC'), repository='org-a/app'))
    where = sorted(set(jira.created_in.values()))
    if where != ['SECTEST'] or len(jira.created_in) != 2:
        fails.append('T3: a test run created tickets in %r (%d), expected two in SECTEST only (%s)'
                     % (where, len(jira.created_in), '; '.join(res.get('notes') or [])[:300]))
    for i in jira.created_in:
        f = jira.issues[i]['fields']
        if rt.TEST_LABEL not in (f.get('labels') or []):
            fails.append('T3: test ticket %s does not carry the label %s' % (i, rt.TEST_LABEL))
    summaries = [q['json']['fields']['summary'] for q in r.requests
                 if q['method'] == 'POST' and q['url'].endswith('/rest/api/3/issue')]
    if not summaries or any(not s.startswith(rt.TEST_PREFIX) for s in summaries):
        fails.append('T3: a test ticket summary lacks the %s prefix: %r' % (rt.TEST_PREFIX,
                                                                          summaries[:2]))
    if any('"SEC"' in q or '"AZSEC"' in q for q in jira.jql_seen):
        fails.append('T3: a test run swept a real project: %r' % jira.jql_seen)
    if any(re.search(r'/issue/777\b', q['url']) for q in r.requests):
        fails.append('T3: a test run touched a ticket the REAL ledger binds')
    if 'realkey' not in ledger or ledger['realkey'].get('test') or \
            not any(k.startswith(rt.TEST_LEDGER_PREFIX) for k in ledger):
        fails.append('T3: the ledger was not partitioned (real binding kept, test bindings under '
                     '%s): %r' % (rt.TEST_LEDGER_PREFIX, sorted(ledger)))
    # T4: the sandbox is named by the register's real routing -> refused, nothing written
    r = ptb.install(ptb.Replay())
    jira = TwoProjectJira(r, projects=('KIT', 'SECTEST', 'AZSEC', 'SEC'))
    b = ptb.backend(rt, dict(test_env, JIRA_PROJECT='SEC', JIRA_REAL_PROJECTS='OTHER'))
    res = rt.reconcile(*rt.build_clusters(RECORDS), b, {}, True, today=TODAY,
                       context=dict(RUN, coverage=None, numbers=None, exceptions={},
                                    routing=_routing(tr, 'AZSEC'), repository='org-a/app'))
    if jira.created_in or any(q['method'] != 'GET' for q in r.requests if '/search/' not in q['url']):
        fails.append('T4: a test run whose sandbox the real routing names wrote to Jira')
    if rt.TICKETING_TEST_TARGETS_REAL_PROJECT not in json.dumps(res.get('shape') or {}):
        fails.append('T4: the refusal was not named %s: %r'
                     % (rt.TICKETING_TEST_TARGETS_REAL_PROJECT, res.get('shape')))
    # T5: a real run never sees a test binding
    r = ptb.install(ptb.Replay())
    jira = TwoProjectJira(r)
    ledger = {rt.TEST_LEDGER_PREFIX + 'x': {'ref': '888', 'test': True, 'member_identities': []}}
    rt.reconcile(*rt.build_clusters(RECORDS), ptb.backend(rt, ptb.JIRA_ENV), ledger, True,
                 today=TODAY, context=dict(RUN, coverage=None, numbers=None, exceptions={}))
    if any(re.search(r'/issue/888\b', q['url']) for q in r.requests) or \
            rt.TEST_LEDGER_PREFIX + 'x' not in ledger:
        fails.append('T5: a real run touched or dropped a test binding')
    # T6: the workflows derive the mode from the ref; nothing to swap
    for wf in ('reusable-ticket-reconcile.yml', 'reusable-exception-due.yml'):
        text = io.open(os.path.join(ROOT, '.github', 'workflows', wf), encoding='utf-8').read()
        if 'test_environment:' not in text or 'TICKETING_MODE:' not in text or \
                'JIRA_REAL_PROJECTS: ${{ vars.JIRA_REAL_PROJECTS }}' not in text:
            fails.append('T6: %s does not select the test environment and TICKETING_MODE from the '
                         'ref, or does not pass JIRA_REAL_PROJECTS' % wf)
        if re.search(r'vars\.TICKETING_MODE|inputs\.ticketing_mode', text):
            fails.append('T6: %s lets a variable or input choose the ticketing mode' % wf)
    for tpl in ('ticket-reconcile.yml', 'exception-due.yml'):
        text = io.open(os.path.join(ROOT, 'templates', tpl), encoding='utf-8').read()
        if 'environment: ticketing' not in text or 'test_environment: ticketing-test' not in text:
            fails.append('T6: templates/%s does not name both environments (ticketing for the '
                         'default branch, ticketing-test for any other)' % tpl)


CASES = [('B1-B6 bearer auth', case_bearer),
         ('T1-T6 test ticketing chosen by the ref, never swapped', case_test_mode),
         ('B7 every Jira caller', case_callers),
         ('R1-R3 routing resolution and the floor refusal', case_routing_resolution),
         ('R4-R6 routing end to end, rule change, idempotency', case_routing_end_to_end)]


def main():
    try:
        import reconcile_tickets as rt
    except Exception as exc:                          # noqa: BLE001
        print('UNKNOWN: could not import reconcile_tickets: %s' % exc)
        return 2
    real = urllib.request.urlopen
    fails = []
    try:
        for label, fn in CASES:
            before = len(fails)
            try:
                fn(rt, fails)
            except Exception as exc:                  # noqa: BLE001 - a crash is a failure
                fails.append('%s crashed: %s: %s' % (label, type(exc).__name__, exc))
            print('  %-52s %s' % (label, 'ok' if len(fails) == before else 'FAIL'))
    finally:
        urllib.request.urlopen = real
    if fails:
        print('')
        for i, f in enumerate(fails, 1):
            print('  %d. %s' % (i, f))
        print('::error title=Jira auth / routing unproven::%d failure(s)' % len(fails))
        return 1
    print('bearer auth through the gateway, every Jira caller, routing precedence, the floor refusal '
          'and rule-change idempotency held; no request left the machine.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
