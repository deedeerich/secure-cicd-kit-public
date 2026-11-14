#!/usr/bin/env python3
"""SonarQube and Aikido findings come into the kit's intake complete, mapped, deduplicated -- or refused by name.

WHY THIS EXISTS (owner, 2026-11-06): "SonarQube org secrets and Aikido API secrets [are] set at work, so we
can test the SonarQube stuff ... and pull those vulns and findings down." scripts/external_findings_pull.py
pulls both, read-only, into `finding` template items (KDEC-037). This runs it against a STAND-IN HTTP
server on 127.0.0.1 answering in the documented shapes (the response examples cited in the script),
with the real HTTP client, headers and paging.

WHAT IT PROVES
  POSITIVE
    P1  Sonar: issues and hotspots over several pages, every page read; each open one an item that
        passes the `finding` template; ACCEPTED/FALSE_POSITIVE listed as source_closed, not items; the
        security impact mapped to severity; the rule lookup's CWE carried; the Bearer header sent
    P2  Aikido: the client-credentials exchange (HTTP Basic, grant_type=client_credentials), then 1,201
        issues over three pages of 500; CVE as the identifier, cwe_classes as CWE-n, patched_versions as
        FIX_AVAILABLE; a cloud finding NOT_MAPPED with the reason; a non-open one source_closed
    P3  a second pull of the same data yields the same identities (an idempotent intake)
  NEVER A DROP (owner ruling 2026-11-11, KDEC-049: "It should never drop the vuln it should enhance the
  existing ticket with additional evidence.")
    E1  a finding the kit already has (same path, line, CWE; or a CVE on the same path) is an ITEM that
        ENHANCES_EXISTING_FINDING, linked by the kit finding's cluster key, every evidence field kept
    E2  a second record of one identity keeps its whole evidence on the item (CORROBORATES_PULLED_ITEM)
    E3-E5  through tickets.submit (the kit API's run side, the Jira stand-in): the existing finding's ticket
        gets ONE comment with every evidence field (vendor keys, sha256s, CVE, severity as rated, title, the
        corroborating record) and additive labels; a higher source severity is flagged severity-review, the
        ticket's own severity kept; the same evidence again is TEMPLATE_TICKET_BOUND
    E6  an enhancement whose ticket is not found is CREATED in triage (TEMPLATE_POSSIBLE_DUPLICATE), never lost
    NE1 an enhancement cannot bypass the review gate (API_REVIEW_NOT_FINALIZED, nothing written)
    NE2 no second ticket is created
    M1  MUTANT: the old drop restored in finish() -> caught, naming ENHANCES_EXISTING_FINDING
    M2  MUTANT: the enhancement planned as the old closed duplicate -> caught by NE2
    E5b / M3  a re-pull whose only change is a new corroborating record is appended; MUTANT: idempotency on
        the primary sha256 only -> caught by E5b
  NEGATIVE
    N1  a bad Sonar token: SOURCE_AUTH_REFUSED, exit 1, no items -- never "no findings"
    N2  a bad Aikido secret: SOURCE_AUTH_REFUSED at the token exchange
    N3  no secret appears in stdout or the output file, even when the server echoes it in an error body
    N4  a source that stops returning pages before its stated total: SOURCE_TRUNCATED
    N5  a total past the search depth: SOURCE_TRUNCATED with the fix, never a partial pull
    N6  no secret configured: SOURCE_NOT_CONFIGURED, exit 1
    N7  a plain-http host that is not 127.0.0.1: SOURCE_HOST_REFUSED, nothing sent
    N8  two issues of one rule in one file are one identity until the SAST identity lands (the seam):
        both vendor keys kept as aliases, nothing lost

EXIT 0 all hold   1 any does not   2 could not run
"""
import base64
import contextlib
import copy
import io
import json
import os
import shutil
import sys
import tempfile
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
sys.path.insert(1, HERE)
import external_findings_pull as EFP  # noqa: E402

SONAR_TOKEN = 'squ_' + 'f' * 36
AIKIDO_ID, AIKIDO_SECRET = 'aik-client-7f3a', 'aik-secret-' + 'e' * 30
AIKIDO_ACCESS = 'aik-access-' + 'd' * 30
FAILS = []
STATE = {'calls': [], 'mode': 'ok'}
kit_ck_code, kit_ck_dep = 'c0de' * 8, 'de00' * 8   # the kit findings' cluster keys (their tickets' stamps)


def check(cond, label, detail=''):
    print('  %s %s%s' % ('ok  ' if cond else 'FAIL', label, ('  -- ' + str(detail)[:300]) if detail and not cond else ''))
    if not cond:
        FAILS.append(label)


def sonar_issue(n, line, status='OPEN', impact='HIGH', rule='javasecurity:S3649', path='src/Db.java'):
    return {'key': 'AY%04d' % n, 'rule': rule, 'component': 'proj-a:%s' % path, 'project': 'proj-a', 'line': line,
            'message': 'SQL injection %d' % n, 'issueStatus': status, 'status': 'OPEN', 'severity': 'MAJOR',
            'impacts': [{'softwareQuality': 'SECURITY', 'severity': impact}]}


SONAR_ISSUES = [sonar_issue(1, 10), sonar_issue(2, 20, impact='BLOCKER', rule='javasecurity:S2076', path='src/Run.java'),
                sonar_issue(3, 30, status='ACCEPTED'), sonar_issue(4, 40, impact='LOW', rule='java:S5332', path='src/Net.java'),
                sonar_issue(5, 50, rule='java:S2068', path='src/Conf.java')]
SONAR_HOTSPOTS = [{'key': 'HS1', 'component': 'proj-a:src/Web.java', 'project': 'proj-a', 'securityCategory': 'xss',
                   'vulnerabilityProbability': 'MEDIUM', 'status': 'TO_REVIEW', 'line': 7, 'message': 'reflected',
                   'ruleKey': 'java:S5131'}]
RULE_CWE = {'javasecurity:S3649': 'cwe:89', 'javasecurity:S2076': 'cwe:78'}


def aikido_rows():
    rows = []
    for i in range(1201):
        rows.append({'id': 1000 + i, 'group_id': i, 'type': 'open_source', 'severity': 'high', 'severity_score': 70,
                     'status': 'open', 'first_detected_at': 1, 'actionable_at': 1, 'attack_surface': 'backend',
                     'cve_id': 'CVE-2026-%05d' % (10000 + i), 'cwe_classes': ['CWE-502'], 'affected_package': 'pkg%d' % i,
                     'affected_file': 'package-lock.json', 'code_repo_name': 'app-one', 'patched_versions': ['2.0.0']})
    rows[1].update(type='sast', cve_id=None, rule='SQL injection', rule_id='AIK-SQLI', cwe_classes=['89'],
                   affected_file='src/db.py', start_line=12, patched_versions=[])
    rows[2].update(code_repo_name=None, cloud_id=5, cloud_name='prod-cloud', affected_file=None)
    rows[3].update(status='ignored')
    return rows


AIKIDO = aikido_rows()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body):
        data = json.dumps(body).encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        body = self.rfile.read(int(self.headers.get('Content-Length') or 0)).decode()
        STATE['calls'].append(('POST', u.path, self.headers.get('Authorization', ''), body))
        if u.path == '/api/oauth/token':
            want = 'Basic ' + base64.b64encode(('%s:%s' % (AIKIDO_ID, AIKIDO_SECRET)).encode()).decode()
            if self.headers.get('Authorization') != want or 'grant_type=client_credentials' not in body:
                return self.send(401, {'error': 'invalid_client'})
            return self.send(200, {'access_token': AIKIDO_ACCESS, 'token_type': 'bearer', 'expires_in': 3600})
        self.send(404, {})

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        auth = self.headers.get('Authorization', '')
        STATE['calls'].append(('GET', u.path, auth, q))
        mode = STATE['mode']
        if u.path.startswith('/api/public/v1/'):
            if auth != 'Bearer ' + AIKIDO_ACCESS:
                return self.send(401, {})
            if u.path.endswith('/issues/export'):
                pp, pg = int(q.get('per_page')), int(q.get('page'))
                return self.send(200, AIKIDO[pg * pp:(pg + 1) * pp])
            return self.send(404, {})
        if auth != 'Bearer ' + SONAR_TOKEN:
            return self.send(401, {'errors': [{'msg': 'Not authorized'}]})
        if mode == 'echo':
            return self.send(500, {'errors': [{'msg': 'boom, your header was %s and the token %s' % (auth, auth.split(' ', 1)[-1])}]})
        per = 2  # the stand-in serves two per page, so the client must page
        if u.path == '/api/issues/search':
            p = int(q.get('p', 1))
            total = 20000 if mode == 'deep' else len(SONAR_ISSUES)
            page = [] if (mode == 'short' and p > 1) else SONAR_ISSUES[(p - 1) * per:p * per]
            return self.send(200, {'paging': {'pageIndex': p, 'pageSize': per, 'total': total}, 'issues': page,
                                   'components': [{'key': i['component'], 'path': i['component'].split(':', 1)[1]}
                                                  for i in page]})
        if u.path == '/api/hotspots/search':
            p = int(q.get('p', 1))
            return self.send(200, {'paging': {'pageIndex': p, 'pageSize': per, 'total': len(SONAR_HOTSPOTS)},
                                   'hotspots': SONAR_HOTSPOTS[(p - 1) * per:p * per], 'components': []})
        if u.path == '/api/rules/show':
            r = q.get('key')
            return self.send(200, {'rule': {'key': r, 'securityStandards': [RULE_CWE[r]] if r in RULE_CWE else []}})
        self.send(404, {})


def run(argv, env):
    old = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            rc = EFP.main(argv)
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return rc, buf.getvalue()


def intake_claims(mod):
    """-> the enhancement claims that do NOT hold for `mod` (the shipped module, or a mutant of it)."""
    issues = [dict(sonar_issue(2, 20, impact='BLOCKER', rule='javasecurity:S2076', path='src/Run.java'), _project='proj-a')]
    items, closed, unmapped = mod.sonar_items(issues, [], {}, {'javasecurity:S2076': 'CWE-78'},
                                              {'proj-a': 'example-org/app-a'}, 'code', 'SonarQube', 'h')
    kit = [{'scanner': 'semgrep', 'rule_id': 'python.sqli', 'canonical_path': 'src/Run.java', 'line': 20,
            'cwe': 'CWE-78', 'what_aliases': [], 'cluster_key': kit_ck_code}]
    res = mod.finish('sonarqube', items, closed, unmapped, kit, {})
    out = []
    its = [i for i in res.get('items') or [] if 'sonar:AY0002' in i.get('aliases', [])]
    if len(its) != 1 or (its[0].get('enhances') or {}).get('correlation_key') != kit_ck_code:
        out.append('the kit match is not an item that %s (%d item(s))' % (EFP.ENHANCES, len(res.get('items') or [])))
    if [e.get('state') for e in res.get('enhancements') or []] != [EFP.ENHANCES]:
        out.append('the kit match is not listed %s' % EFP.ENHANCES)
    if (res.get('counts') or {}).get('items') != 1:
        out.append('the item count is %r, not 1 (%s)' % ((res.get('counts') or {}).get('items'), EFP.ENHANCES))
    return out


def mutant_module(mod, old, new):
    """The module's own source with ONE change, loaded as a separate module (the shipped file is untouched)."""
    import types
    src = io.open(mod.__file__, encoding='utf-8').read()
    if src.count(old) != 1:
        raise SystemExit('mutant anchor not found exactly once in %s: %r' % (mod.__file__, old[:80]))
    m = types.ModuleType(mod.__name__ + '_mutant')
    m.__file__ = mod.__file__
    exec(compile(src.replace(old, new), mod.__file__, 'exec'), m.__dict__)
    return m


def _aik(n, sev, pkg):
    return {'id': n, 'type': 'open_source', 'severity': sev, 'status': 'open', 'cve_id': 'CVE-2026-20001',
            'cwe_classes': ['CWE-502'], 'affected_package': pkg, 'affected_file': 'package-lock.json',
            'code_repo_name': 'app-one', 'patched_versions': ['2.0.0']}


def _submit_run(PT, mods, work, name, mutant):
    """One world: the existing finding's ticket, then an Aikido pull that enhances it, through tickets.submit."""
    tt = mods[5]
    out = []

    def claim(label, ok, detail=''):
        out.append((label, bool(ok), detail))
    d = os.path.join(work, name)
    os.makedirs(d)
    w = PT.W(mods, d)
    base = {'source_type': 'scan-app', 'source_tool': 'osv-scanner', 'environment': 'code',
            'asset': {'scheme': 'repo-path', 'repository': 'example-org/app-one', 'path': 'package-lock.json'},
            'identifier': 'GHSA-aaaa-bbbb-cccc', 'severity': 'high', 'fix_status': 'FIX_AVAILABILITY_NOT_ESTABLISHED',
            'evidence': {'ref': 'kit-run/1/findings.json', 'sha256': 'b' * 64}, 'title': 'Unsafe deserialisation in pkgx'}
    res, _s = w.submit(w.finalize('XF-BASE-01', {'template': 'finding', 'template_version': 2, 'items': [base]}),
                       'xf-base-0001')
    made = PT.items_of(res)
    if not made or made[0].get('outcome') != tt.TEMPLATE_TICKET_CREATED:
        return [('E3 the existing finding\'s ticket was created first', False, made)]
    ref = str(made[0]['ref'])
    kck = tt.normalize('finding', base, {})['correlation_key']
    items, closed, unmapped = EFP.aikido_items([_aik(9001, 'critical', 'pkgx'), _aik(9002, 'high', 'pkgx-copy')],
                                               {'app-one': 'example-org/app-one'}, 'code')
    kit = [{'scanner': 'osv-scanner', 'rule_id': 'GHSA-aaaa-bbbb-cccc', 'canonical_path': 'package-lock.json',
            'what_aliases': ['CVE-2026-20001'], 'cluster_key': kck, 'severity': 'high'}]
    pulled = EFP.finish('aikido', items, closed, unmapped, kit, {})
    claim('E3 the pull holds one item that %s and one record carried on it (%s)' % (EFP.ENHANCES, EFP.CORROBORATES),
          pulled['counts']['items'] == 1 and pulled['counts']['enhancements'] == 1 and
          pulled['counts']['corroborations'] == 1, pulled['counts'])
    (params, _h), = EFP.batches(pulled, 'XF-ENH-01')
    item = params['items'][0]
    n_issues, n_comments = len(w.t.issues), len(w.t.comments)
    desc0 = json.dumps(w.t.issues[ref].get('description'), sort_keys=True)
    labels0 = set(w.t.issues[ref]['fields'].get('labels') or [])
    status0 = w.t.status_of(ref)

    # N-E1 THE REVIEW GATE: an enhancement with no finalized review writes nothing.
    res, _s = w.submit(params, 'xf-norev-0001')
    claim('NE1 an enhancement cannot bypass the review gate: API_REVIEW_NOT_FINALIZED, nothing written',
          (res.get('refusal') or {}).get('code') == 'API_REVIEW_NOT_FINALIZED' and len(w.t.comments) == n_comments
          and len(w.t.issues) == n_issues, res.get('refusal'))

    # E4 THE ENHANCEMENT: the existing ticket is told every evidence field; nothing is created or overwritten.
    res, _s = w.submit(w.finalize('XF-ENH-01', params), 'xf-enh-0001')
    it = PT.items_of(res)
    claim('E4 the outcome is %s on the existing finding\'s ticket' % tt.TEMPLATE_ENHANCED_EXISTING,
          it and it[0].get('outcome') == tt.TEMPLATE_ENHANCED_EXISTING and str(it[0].get('ref')) == ref, it)
    claim('NE2 no second ticket is created (%d -> %d), %s' % (n_issues, len(w.t.issues), tt.TEMPLATE_ENHANCED_EXISTING),
          len(w.t.issues) == n_issues, sorted(w.t.issues))
    new = [c for c in w.t.comments[n_comments:] if str(c[0]) == ref]
    text = new[0][1] if len(new) == 1 else ''
    c2 = item['corroborating_evidence'][0]
    want = ['aikido:9001', 'CVE-2026-20001', item['evidence']['sha256'], item['evidence']['ref'], 'Aikido',
            'severity as the source rated it: critical', item['title'], 'aikido:9002', c2['evidence']['sha256'],
            'SEVERITY HIGHER AT THE SOURCE', tt.TEMPLATE_ENHANCED_EXISTING]
    claim('E4 one comment carries every evidence field (tool, vendor keys, sha256s, CVE, severity as rated, title, '
          'the corroborating record)', text and all(x in text for x in want), [x for x in want if x not in text] or new)
    labels = set(w.t.issues[ref]['fields'].get('labels') or [])
    claim('E4 labels are only added (evidence, enhanced, severity-review), the ticket\'s own sev-high kept',
          labels0 <= labels and {'secure-cicd-kit-ev-%s' % item['evidence']['sha256'][:16], 'secure-cicd-kit-enhanced',
                                 'secure-cicd-kit-severity-review', 'secure-cicd-kit-sev-high'} <= labels,
          sorted(labels - labels0))
    claim('E4 nothing overwritten: the description and the status are unchanged, the priority untouched',
          json.dumps(w.t.issues[ref].get('description'), sort_keys=True) == desc0 and w.t.status_of(ref) == status0
          and it and it[0].get('severity_comparison') == 'HIGHER', (it[0].get('severity_comparison') if it else None))

    # E5 the same evidence again adds nothing (no repeated comment, no ticket)
    res, _s = w.submit(w.finalize('XF-ENH-02', params), 'xf-enh-0002')
    it = PT.items_of(res)
    claim('E5 the same evidence again is %s: no new comment, no ticket' % tt.TEMPLATE_TICKET_BOUND,
          it and it[0].get('outcome') == tt.TEMPLATE_TICKET_BOUND and len(w.t.issues) == n_issues and
          len([c for c in w.t.comments if str(c[0]) == ref]) == len([c for c in w.t.comments[:n_comments] if str(c[0]) == ref]) + 1,
          it)
    # E5b a re-pull whose only change is a NEW corroborating record is appended, not taken as already there
    items, closed, unmapped = EFP.aikido_items([_aik(9001, 'critical', 'pkgx'), _aik(9002, 'high', 'pkgx-copy'),
                                                _aik(9003, 'low', 'pkgx-third')], {'app-one': 'example-org/app-one'}, 'code')
    (p3, _h), = EFP.batches(EFP.finish('aikido', items, closed, unmapped, kit, {}), 'XF-ENH-04')
    before = len(w.t.comments)
    res, _s = w.submit(w.finalize('XF-ENH-04', p3), 'xf-enh-0004')
    it = PT.items_of(res)
    claim('E5b a new corroborating record on a re-pull is appended (%s), not taken as already there'
          % tt.TEMPLATE_ENHANCED_EXISTING,
          it and it[0].get('outcome') == tt.TEMPLATE_ENHANCED_EXISTING and len(w.t.issues) == n_issues and
          any('aikido:9003' in c[1] for c in w.t.comments[before:]), it)
    if mutant:
        return out

    # E6 the existing finding's ticket is not there: CREATED in triage with the link, never dropped.
    d2 = os.path.join(work, name + '-missing')
    os.makedirs(d2)
    w2 = PT.W(mods, d2)
    lost = copy.deepcopy(params)
    lost['items'][0]['enhances']['correlation_key'] = 'f' * 32
    res, _s = w2.submit(w2.finalize('XF-ENH-03', lost), 'xf-enh-0003')
    it = PT.items_of(res)
    mk = [i for i in w2.t.issues.values()]
    claim('E6 an enhancement whose ticket is not found is CREATED in triage (%s), the evidence kept'
          % tt.TEMPLATE_POSSIBLE_DUPLICATE,
          it and it[0].get('outcome') == tt.TEMPLATE_POSSIBLE_DUPLICATE and len(mk) == 1 and
          {'secure-cicd-kit-triage', 'secure-cicd-kit-possible-duplicate'} <= set(mk[0]['fields'].get('labels') or [])
          and any('ENHANCES AN EXISTING FINDING' in c[1] for c in w2.t.comments), it)
    return out


def submit_claims(work):
    """E3-E6 through the kit API's own run side (tests/prove_ticket_templates.py's world), and M2: the enhancement
    planned as the old closed duplicate must be caught by the "no second ticket" claim."""
    import prove_ticket_templates as PT
    import ticket_submit as TS
    mods = PT.imports()
    if mods is None:
        return [('E3 the ticket machinery imports', False, '')]
    out = _submit_run(PT, mods, work, 'enh', False)
    real = TS._plan_enhance
    TS._plan_enhance = lambda plan, grp, target, basis, stamp, conf, trust: TS._plan_exact(
        None, plan, grp, dict(target, manual=False), basis, stamp, conf, trust)
    try:
        got = _submit_run(PT, mods, work, 'enh-mutant', True)
    finally:
        TS._plan_enhance = real
    failed = [lb for lb, ok, _d in got if not ok]
    out.append(('M2 the mutant "plan the enhancement as the old closed duplicate" is caught by the no-second-ticket '
                'claim, naming %s' % mods[5].TEMPLATE_ENHANCED_EXISTING,
                any(lb.startswith('NE2') and mods[5].TEMPLATE_ENHANCED_EXISTING in lb for lb in failed), failed))
    real_key = TS._evidence_key
    TS._evidence_key = lambda rec: str(rec['provenance'].get('evidence_sha256') or '')[:16]
    try:
        got = _submit_run(PT, mods, work, 'enh-mutant3', True)
    finally:
        TS._evidence_key = real_key
    failed = [lb for lb, ok, _d in got if not ok]
    out.append(('M3 the mutant "idempotency on the primary sha256 only" is caught by E5b, naming %s'
                % mods[5].TEMPLATE_ENHANCED_EXISTING,
                failed and all(lb.startswith('E5b') for lb in failed) and
                mods[5].TEMPLATE_ENHANCED_EXISTING in failed[0], failed))
    return out


def main():
    srv = HTTPServer(('127.0.0.1', 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    host = 'http://127.0.0.1:%d' % srv.server_address[1]
    work = tempfile.mkdtemp(prefix='efp-')
    try:
        rmap = os.path.join(work, 'map.json')
        io.open(rmap, 'w').write(json.dumps({'proj-a': 'example-org/app-a', 'app-one': 'example-org/app-one'}))
        kit = os.path.join(work, 'kit.json')
        io.open(kit, 'w').write(json.dumps([
            {'scanner': 'semgrep', 'rule_id': 'python.sqli', 'canonical_path': 'src/Run.java', 'line': 20, 'cwe': 'CWE-78',
             'what_aliases': [], 'cluster_key': kit_ck_code, 'severity': 'high'},
            {'scanner': 'osv', 'rule_id': 'GHSA-x', 'canonical_path': 'package-lock.json', 'line': 1, 'cwe': '',
             'what_aliases': ['CVE-2026-10000'], 'cluster_key': kit_ck_dep}]))
        out = os.path.join(work, 'out.json')
        senv = {'SONAR_TOKEN': SONAR_TOKEN}
        print('External findings pull (scripts/external_findings_pull.py) against a stand-in on %s:' % host)

        # P1 Sonar
        STATE['calls'][:] = []
        rc, so = run(['sonar', '--host', host, '--project', 'proj-a', '--organization', 'example-org', '--rule-lookup',
                      '--repo-map', rmap, '--kit-findings', kit, '--out', out], senv)
        doc = json.load(io.open(out))
        pages = [c for c in STATE['calls'] if c[1] == '/api/issues/search']
        check(rc == 0 and doc['state'] == EFP.PULLED, 'P1 Sonar pulled (rc %s)' % rc, so)
        check(len(pages) == 3 and all(c[3].get('organization') == 'example-org' and c[3].get('impactSoftwareQualities') == 'SECURITY'
                                      for c in pages), 'P1 every issues page read (3 pages of 2), organization and SECURITY sent')
        check(all(c[2] == 'Bearer ' + SONAR_TOKEN for c in STATE['calls']), 'P1 the token goes in the Bearer header')
        items = {i['aliases'][0]: i for i in doc['items']}
        check(set(items) == {'sonar:AY0001', 'sonar:AY0002', 'sonar:AY0004', 'sonar:AY0005', 'sonar-hotspot:HS1'},
              'P1 the open issues and the hotspot are items (%s)' % sorted(items))
        check([c['source_key'] for c in doc['source_closed']] == ['sonar:AY0003'], 'P1 the ACCEPTED issue is source_closed')
        check(items['sonar:AY0001']['severity'] == 'high' and items['sonar:AY0004']['severity'] == 'low' and
              items['sonar-hotspot:HS1']['severity'] == 'medium', 'P1 severity from the SECURITY impact / hotspot probability')
        check(items['sonar:AY0001'].get('cwe') == 'CWE-89' and items['sonar:AY0001']['asset'] ==
              {'scheme': 'repo-path', 'repository': 'example-org/app-a', 'path': 'src/Db.java', 'line': 10},
              'P1 the CWE from the rule lookup and the repo-path asset with its line')
        e = items.get('sonar:AY0002', {}).get('enhances') or {}
        check([(d['source_key'], d['state']) for d in doc.get('enhancements') or []] == [('sonar:AY0002', EFP.ENHANCES)]
              and e.get('basis') == 'kit-finding-path-line-cwe' and e.get('correlation_key') == kit_ck_code and
              e.get('scanner') == 'semgrep' and e.get('line') == 20 and doc['counts'].get('enhancements') == 1,
              'E1 the issue the kit already found (same path, line, CWE) is an item that %s, linked to the kit '
              'finding\'s key -- never dropped' % EFP.ENHANCES, doc.get('enhancements'))
        x = items.get('sonar:AY0002', {})
        check(x.get('severity') == 'critical' and x.get('title') and len((x.get('evidence') or {}).get('sha256', '')) == 64
              and x.get('aliases') == ['sonar:AY0002'] and x.get('source_tool') == 'SonarQube',
              'E1 the enhancement keeps every evidence field (tool, vendor key, sha256, severity as rated, title)')
        import ticket_templates as tt
        check(all(tt.validate_item('finding', i) is None for i in doc['items']), 'P1 every item passes the finding template')
        ids1 = sorted(tt.normalize('finding', i, {}, 0)['identity'] for i in doc['items'])

        # P3 idempotent
        rc, so = run(['sonar', '--host', host, '--project', 'proj-a', '--organization', 'example-org', '--rule-lookup',
                      '--repo-map', rmap, '--kit-findings', kit, '--out', out], senv)
        ids2 = sorted(tt.normalize('finding', i, {}, 0)['identity'] for i in json.load(io.open(out))['items'])
        check(ids1 == ids2 and ids1, 'P3 a second pull yields the same identities')

        # P2 Aikido
        STATE['calls'][:] = []
        aenv = {'AIKIDO_CLIENT_ID': AIKIDO_ID, 'AIKIDO_CLIENT_SECRET': AIKIDO_SECRET}
        rc, so = run(['aikido', '--base', host + '/api/public/v1', '--repo-map', rmap, '--kit-findings', kit, '--out', out], aenv)
        doc = json.load(io.open(out))
        exports = [c for c in STATE['calls'] if c[1].endswith('/issues/export')]
        check(rc == 0 and doc['state'] == EFP.PULLED, 'P2 Aikido pulled (rc %s)' % rc, so)
        check(STATE['calls'][0][1] == '/api/oauth/token' and STATE['calls'][0][2].startswith('Basic ')
              and 'grant_type=client_credentials' in STATE['calls'][0][3], 'P2 client credentials over HTTP Basic first')
        check([int(c[3]['page']) for c in exports] == [0, 1, 2] and all(c[3]['filter_status'] == 'open' for c in exports),
              'P2 three pages of 500 read, open only (%s)' % [c[3].get('page') for c in exports])
        a = {i['aliases'][0] if i['aliases'][0].startswith('aikido:') else i['aliases'][-1]: i for i in doc['items']}
        sast = [i for i in doc['items'] if 'aikido:1001' in i['aliases']]
        check(len(sast) == 1 and sast[0]['identifier'] == 'aikido:sast:AIK-SQLI' and sast[0].get('cwe') == 'CWE-89' and
              sast[0]['fix_status'] == 'FIX_AVAILABILITY_NOT_ESTABLISHED' and sast[0]['asset'].get('line') == 12,
              'P2 a SAST issue: identifier, CWE-n from "89", line, no fix established')
        dep = [i for i in doc['items'] if 'aikido:1004' in i['aliases']]
        check(len(dep) == 1 and dep[0]['identifier'] == 'CVE-2026-10004' and dep[0]['fix_status'] == 'FIX_AVAILABLE' and
              dep[0]['finding_subject'] == 'SOURCE_DEPENDENCY', 'P2 a dependency issue: CVE identifier, FIX_AVAILABLE')
        check(any(u['source_key'] == 'aikido:1002' and 'cloud' in u['why'] for u in doc['not_mapped']),
              'P2 a cloud finding is NOT_MAPPED, with the reason')
        enh = [i for i in doc['items'] if 'aikido:1000' in i['aliases']]
        check([d['source_key'] for d in doc.get('enhancements') or []] == ['aikido:1000'] and len(enh) == 1 and
              (enh[0].get('enhances') or {}).get('basis') == 'kit-finding-cve-path' and 'CVE-2026-10000' in enh[0]['aliases']
              and (enh[0].get('enhances') or {}).get('correlation_key') == kit_ck_dep,
              'E1 the CVE the kit already found on that path is an item that %s, its CVE alias kept' % EFP.ENHANCES)
        check([c['source_key'] for c in doc['source_closed']] == ['aikido:1003'], 'P2 an ignored issue is source_closed')
        check(doc['counts']['items'] == 1201 - 2 and doc['counts']['enhancements'] == 1,
              'P2 every other issue is an item, the enhancement included (%d)' % doc['counts']['items'])

        # N1 bad Sonar token
        rc, so = run(['sonar', '--host', host, '--project', 'proj-a', '--out', out], {'SONAR_TOKEN': 'squ_wrong'})
        d = json.load(io.open(out))
        check(rc == 1 and d['state'] == EFP.AUTH_REFUSED and d['items'] == [] and 'not "no findings"' in so,
              'N1 a bad Sonar token is SOURCE_AUTH_REFUSED, never "no findings"', so)
        # N2 bad Aikido secret
        rc, so = run(['aikido', '--base', host + '/api/public/v1', '--out', out],
                     {'AIKIDO_CLIENT_ID': AIKIDO_ID, 'AIKIDO_CLIENT_SECRET': 'wrong'})
        check(rc == 1 and json.load(io.open(out))['state'] == EFP.AUTH_REFUSED, 'N2 a bad Aikido secret is SOURCE_AUTH_REFUSED')
        # N3 secrets never printed
        STATE['mode'] = 'echo'
        rc, so = run(['sonar', '--host', host, '--project', 'proj-a', '--out', out], senv)
        STATE['mode'] = 'ok'
        blob = so + io.open(out).read()
        check(rc == 1 and SONAR_TOKEN not in blob and '[redacted]' in blob,
              'N3 a token echoed back by the server is redacted from stdout and the file')
        rc, so = run(['aikido', '--base', host + '/api/public/v1', '--repo-map', rmap, '--out', out], aenv)
        blob = so + io.open(out).read()
        check(AIKIDO_SECRET not in blob and AIKIDO_ACCESS not in blob and AIKIDO_ID not in blob,
              'N3 no Aikido credential or access token in stdout or the file')
        # N4 short pages
        STATE['mode'] = 'short'
        rc, so = run(['sonar', '--host', host, '--project', 'proj-a', '--out', out], senv)
        check(rc == 1 and json.load(io.open(out))['state'] == EFP.TRUNCATED, 'N4 pages that stop short: SOURCE_TRUNCATED', so)
        # N5 too deep
        STATE['mode'] = 'deep'
        rc, so = run(['sonar', '--host', host, '--project', 'proj-a', '--out', out], senv)
        check(rc == 1 and json.load(io.open(out))['state'] == EFP.TRUNCATED and 'split the pull' in so,
              'N5 a total past the search depth: SOURCE_TRUNCATED with the fix')
        STATE['mode'] = 'ok'
        # N6 not configured
        rc, so = run(['sonar', '--host', host, '--project', 'proj-a', '--out', out], {'SONAR_TOKEN': ''})
        check(rc == 1 and json.load(io.open(out))['state'] == EFP.NOT_CONFIGURED, 'N6 no token: SOURCE_NOT_CONFIGURED')
        # N7 plain http elsewhere
        STATE['calls'][:] = []
        rc, so = run(['sonar', '--host', 'http://sonar.example.com', '--project', 'p', '--out', out], senv)
        check(rc == 1 and json.load(io.open(out))['state'] == EFP.HOST_REFUSED and not STATE['calls'],
              'N7 a plain-http host is refused before anything is sent')
        # N8 the seam: one rule, one file, two lines
        items, closed, unmapped = EFP.sonar_items(
            [dict(sonar_issue(8, 1), _project='proj-a'), dict(sonar_issue(9, 2), _project='proj-a')], [],
            {}, {}, {'proj-a': 'example-org/app-a'}, 'code', 'SonarQube', 'h')
        res = EFP.finish('sonarqube', items, closed, unmapped, [], {})
        check(len(res['items']) == 1 and set(res['items'][0]['aliases']) == {'sonar:AY0008', 'sonar:AY0009'},
              'N8 one rule in one file is one identity until the SAST identity lands, both vendor keys kept')
        ce = (res['items'][0].get('corroborating_evidence') or [{}]) if res['items'] else [{}]
        check(len(ce) == 1 and ce[0].get('source_key') == 'sonar:AY0009' and ce[0].get('line') == 2 and
              ce[0].get('evidence') == items[1]['evidence'] and ce[0]['evidence'] != items[0]['evidence'] and
              ce[0].get('severity') == 'high' and ce[0].get('title') and ce[0].get('source_tool') == 'SonarQube' and
              [(c['source_key'], c['state']) for c in res['corroborations']] == [('sonar:AY0009', EFP.CORROBORATES)]
              and tt.validate_item('finding', res['items'][0]) is None,
              'E2 the second record of one identity keeps its WHOLE evidence on the item (%s), and the item still '
              'passes the template' % EFP.CORROBORATES, ce)

        # M1 THE NAMED MUTANT: restore the old drop in finish(); the intake claims must fail, naming the state.
        check(intake_claims(EFP) == [], 'M1 the shipped finish() holds the enhancement claims', intake_claims(EFP))
        mut = mutant_module(EFP, "            enhancements.append(_listed(it, ENHANCES, {'enhances': it['enhances']}))\n",
                            "            enhancements.append(_listed(it, ENHANCES, {'enhances': it['enhances']}))\n"
                            "            continue\n")
        got = intake_claims(mut)
        check(got and any(EFP.ENHANCES in g for g in got),
              'M1 the mutant "drop the kit match again" is caught, naming %s' % EFP.ENHANCES, got)

        # E3-E6 + M2: the enhancement through tickets.submit, the review gate and the tracker stand-in
        for label, ok, detail in submit_claims(work):
            check(ok, label, detail)
    finally:
        srv.shutdown()
        srv.server_close()
        shutil.rmtree(work, ignore_errors=True)
    if FAILS:
        print('FAIL: %d claim(s)' % len(FAILS))
        return 1
    print('PASS: both sources pull completely, map into the finding template, dedupe, and refuse by name.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
