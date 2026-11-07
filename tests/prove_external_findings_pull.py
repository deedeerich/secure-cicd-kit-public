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
        security impact mapped to severity; the rule lookup's CWE carried; a finding the kit already has
        (same path, line, CWE) listed as DUPLICATE_OF_KIT_FINDING, not an item; the Bearer header sent
    P2  Aikido: the client-credentials exchange (HTTP Basic, grant_type=client_credentials), then 1,201
        issues over three pages of 500; CVE as the identifier, cwe_classes as CWE-n, patched_versions as
        FIX_AVAILABLE; a cloud finding NOT_MAPPED with the reason; a CVE the kit already found on the
        same path a duplicate; a non-open one source_closed
    P3  a second pull of the same data yields the same identities (an idempotent intake)
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
import external_findings_pull as EFP  # noqa: E402

SONAR_TOKEN = 'squ_' + 'f' * 36
AIKIDO_ID, AIKIDO_SECRET = 'aik-client-7f3a', 'aik-secret-' + 'e' * 30
AIKIDO_ACCESS = 'aik-access-' + 'd' * 30
FAILS = []
STATE = {'calls': [], 'mode': 'ok'}


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
             'what_aliases': []},
            {'scanner': 'osv', 'rule_id': 'GHSA-x', 'canonical_path': 'package-lock.json', 'line': 1, 'cwe': '',
             'what_aliases': ['CVE-2026-10000']}]))
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
        check(set(items) == {'sonar:AY0001', 'sonar:AY0004', 'sonar:AY0005', 'sonar-hotspot:HS1'},
              'P1 the open issues and the hotspot are items (%s)' % sorted(items))
        check([c['source_key'] for c in doc['source_closed']] == ['sonar:AY0003'], 'P1 the ACCEPTED issue is source_closed')
        check(items['sonar:AY0001']['severity'] == 'high' and items['sonar:AY0004']['severity'] == 'low' and
              items['sonar-hotspot:HS1']['severity'] == 'medium', 'P1 severity from the SECURITY impact / hotspot probability')
        check(items['sonar:AY0001'].get('cwe') == 'CWE-89' and items['sonar:AY0001']['asset'] ==
              {'scheme': 'repo-path', 'repository': 'example-org/app-a', 'path': 'src/Db.java', 'line': 10},
              'P1 the CWE from the rule lookup and the repo-path asset with its line')
        check([d['source_key'] for d in doc['duplicates_of_kit']] == ['sonar:AY0002'],
              'P1 the issue the kit already found (same path, line, CWE) is a duplicate, not an item')
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
        check([d['source_key'] for d in doc['duplicates_of_kit']] == ['aikido:1000'],
              'P2 the CVE the kit already found on that path is a duplicate')
        check([c['source_key'] for c in doc['source_closed']] == ['aikido:1003'], 'P2 an ignored issue is source_closed')
        check(doc['counts']['items'] == 1201 - 3, 'P2 every other issue is an item (%d)' % doc['counts']['items'])

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
