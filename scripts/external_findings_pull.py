#!/usr/bin/env python3
"""Pull SonarQube / SonarQube Cloud and Aikido findings into the kit's external-findings intake, read-only.

WHY THIS EXISTS (owner, 2026-11-06)
    "SonarQube org secrets and Aikido API secrets [are] set at work, so we can test the SonarQube stuff
    ... and pull those vulns and findings down." The kit takes findings it did not produce through the
    `finding` ticket template (scripts/ticket_templates.py, KDEC-037): validated, normalised into the
    kit's finding model with provenance, deduplicated, and written to a tracker only through tickets.submit
    behind the review gate. This script is the READ half for two sources: it pulls, maps every field it
    can into a `finding` item, validates each item against the template, deduplicates against the kit's
    own findings, and writes one file. It never writes to either vendor and never to a tracker.

THE VENDOR APIS (official documentation read 2026-11-06; UNVERIFIED marks what it did not confirm)
    SonarQube Server and SonarQube Cloud Web API
      auth      `Authorization: Bearer <token>` (docs.sonarsource.com/sonarqube-server/extension-guide/web-api/,
                "we recommend that you use the bearer authentication scheme"); SonarQube Cloud: the same
                header (UNVERIFIED on Cloud by a live call)
      issues    GET <host>/api/issues/search  (sonarcloud.io/api/webservices/list): componentKeys,
                organization (Cloud), impactSoftwareQualities=SECURITY,
                issueStatuses=OPEN,CONFIRMED,ACCEPTED,FALSE_POSITIVE (fixed history is not pulled),
                p (1-based), ps (<= 500); answer paging{pageIndex,pageSize,total}, issues[]{key, rule,
                component, project, line, textRange, message, issueStatus, status, severity (deprecated),
                impacts[{softwareQuality, severity}]}, components[]{key, path}
                (sonarcloud.io/api/webservices/response_example?controller=api/issues&action=search)
      hotspots  GET <host>/api/hotspots/search: projectKey, status=TO_REVIEW, p, ps; answer
                hotspots[]{key, component, project, securityCategory, vulnerabilityProbability, status,
                line, message, ruleKey}. SonarQube Cloud marks it "deprecated as of 16 June, 2026"; its
                replacement is UNVERIFIED.
      CWE       not in either answer. Optional rule lookup GET <host>/api/rules/show?key=<rule> reading
                `securityStandards` ("cwe:89") -- that field is NOT in the documented example: UNVERIFIED.
                Without it the CWE is left empty, never guessed.
      10 000    the Web API's search depth limit is UNVERIFIED in the pages read; a total above it, or a
                page short of the stated total, is SOURCE_TRUNCATED, never a quiet partial pull.
    Aikido public REST API
      auth      POST https://app.aikido.dev/api/oauth/token, `grant_type=client_credentials`, HTTP Basic
                with the client id and secret (apidocs.aikido.dev/reference/authorization); the answer's
                `access_token` field name is the OAuth 2.0 standard's (UNVERIFIED on the page read)
      issues    GET <base>/issues/export (apidocs.aikido.dev/reference/exportissues), base
                https://app.aikido.dev/api/public/v1 (EU) or https://app.us.aikido.dev/api/public/v1 (US);
                scope issues:read; format=json, filter_status=open, page (0-based), per_page (10..5000);
                issue {id, group_id, type, severity, severity_score, status, rule, rule_id,
                affected_package, affected_file, cve_id, cwe_classes, start_line, code_repo_name,
                patched_versions, ...}. The last page is the one shorter than per_page (UNVERIFIED: the
                page does not state the end condition).

MAPPING INTO THE `finding` TEMPLATE (api/v1/tickets/finding.schema.json)
    identifier   Sonar: the rule key; Aikido: the CVE when there is one, else aikido:<type>:<rule_id>
    severity     Sonar SECURITY impact BLOCKER->critical HIGH->high MEDIUM->medium LOW->low INFO->info,
                 else the legacy severity BLOCKER->critical CRITICAL->high MAJOR->medium MINOR->low
                 INFO->info; a hotspot's vulnerabilityProbability HIGH/MEDIUM/LOW; Aikido as given
    cwe          Aikido cwe_classes[0] as CWE-<n>; Sonar only through the rule lookup (UNVERIFIED)
    asset        repo-path: the repository from --repo-map (project key or repo name -> org/repo), the
                 file path, the line; a finding with no file or no mapped repository is NOT_MAPPED, named
    status       only open findings become items (Sonar OPEN/CONFIRMED, hotspot TO_REVIEW, Aikido open);
                 a closed one in the answer is listed under source_closed with its status, never an item
    aliases      the vendor's own key (sonar:<key>, aikido:<id>) and the CVE: a re-pull is the same finding
    evidence     ref: the vendor's key; sha256: of the vendor's record as received (canonical JSON)

    CODE FINDINGS AND THE SAST IDENTITY (the SAST/evidence-export lane is building it on the trunk). Until it
    lands, `kit_duplicate()` below matches a code finding to a kit finding by path, line and CWE, and a
    dependency finding by CVE and path. The seam is that one function: replace its code branch with the
    SAST identity's match when the lane merges.

SECRETS ARE NEVER PRINTED. Tokens come from the environment (SONAR_TOKEN; AIKIDO_CLIENT_ID and
AIKIDO_CLIENT_SECRET), are sent only in the Authorization header to the configured host over HTTPS (plain
HTTP only to 127.0.0.1 for tests), and every error text has them replaced before it is shown.

USAGE
    SONAR_TOKEN=... python3 scripts/external_findings_pull.py sonar --host https://sonarcloud.io \
        --organization ORG --project KEY [--project KEY ...] --repo-map map.json --out pulled.json
    AIKIDO_CLIENT_ID=... AIKIDO_CLIENT_SECRET=... python3 scripts/external_findings_pull.py aikido \
        --base https://app.aikido.dev/api/public/v1 --repo-map map.json --out pulled.json
    [--kit-findings findings.json]  deduplicate against the kit's own findings (scan_report findings.json)
    python3 scripts/external_findings_pull.py batch --in pulled.json --review-id REVIEW --out-dir batches/
        tickets.submit params of at most 20 items, each with the evidence-set hash its review must concur with
EXIT  0 pulled completely (zero findings is a result)   1 refused, named (SOURCE_*)   2 usage
"""
import argparse
import base64
import datetime
import hashlib
import io
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import finding_ids  # noqa: E402  (THE id normaliser for every source, owner 2026-11-06)
import unknown_ids  # noqa: E402  (unknown ids logged and routed to a person, owner ruling 2026-11-06)
UNKNOWN = unknown_ids.UnknownLog()

# Named states (assurance-taxonomy.yaml :: external_findings_pull)
PULLED = 'SOURCE_PULLED'
NOT_CONFIGURED = 'SOURCE_NOT_CONFIGURED'
AUTH_REFUSED = 'SOURCE_AUTH_REFUSED'
UNREACHABLE = 'SOURCE_UNREACHABLE'
RESPONSE_INVALID = 'SOURCE_RESPONSE_INVALID'
TRUNCATED = 'SOURCE_TRUNCATED'
HOST_REFUSED = 'SOURCE_HOST_REFUSED'
NOT_MAPPED = 'NOT_MAPPED'
DUPLICATE_OF_KIT = 'DUPLICATE_OF_KIT_FINDING'

SONAR_PS = 500
SONAR_DEPTH = 10000          # UNVERIFIED limit; above it the pull is refused as TRUNCATED
AIKIDO_PER_PAGE = 500
MAX_PAGES = 400              # a bound on any loop, so a misbehaving source cannot hold the run
SONAR_IMPACT = {'BLOCKER': 'critical', 'HIGH': 'high', 'MEDIUM': 'medium', 'LOW': 'low', 'INFO': 'info'}
SONAR_LEGACY = {'BLOCKER': 'critical', 'CRITICAL': 'high', 'MAJOR': 'medium', 'MINOR': 'low', 'INFO': 'info'}
HOTSPOT_PROB = {'HIGH': 'high', 'MEDIUM': 'medium', 'LOW': 'low'}
AIKIDO_SUBJECT = {'open_source': 'SOURCE_DEPENDENCY', 'app_level_open_source': 'SOURCE_DEPENDENCY',
                  'license': 'SOURCE_DEPENDENCY', 'sast': 'SOURCE', 'leaked_secret': 'SOURCE',
                  'iac': 'IAC_PLAN', 'docker_container': 'IMAGE'}
SONAR_OPEN = ('OPEN', 'CONFIRMED')


class Refused(Exception):
    def __init__(self, state, detail):
        Exception.__init__(self, '%s: %s' % (state, detail))
        self.state, self.detail = state, detail


class Http(object):
    """GET/POST JSON with one credential, to one host. Never prints the credential."""

    def __init__(self, base, secrets=(), timeout=30):
        u = urllib.parse.urlparse(base)
        local = u.hostname in ('127.0.0.1', 'localhost')
        if u.scheme != 'https' and not (u.scheme == 'http' and local):
            raise Refused(HOST_REFUSED, 'the host %s is not https (plain http only to 127.0.0.1)' % u.netloc)
        self.base, self.host = base.rstrip('/'), u.netloc
        self.secrets = [s for s in secrets if s]
        self.timeout = timeout
        self.auth = None
        self.calls = 0

    def scrub(self, text):
        text = str(text or '')
        for s in self.secrets + ([self.auth.split(' ', 1)[-1]] if self.auth else []):
            if s:
                text = text.replace(s, '[redacted]')
        return re.sub(r'(?i)(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}', r'\1 [redacted]', text)[:300]

    def request(self, method, url, data=None, headers=None):
        if not url.startswith(self.base) and urllib.parse.urlparse(url).netloc != self.host:
            raise Refused(HOST_REFUSED, 'refusing to send the credential to another host')
        self.calls += 1
        h = {'Accept': 'application/json'}
        h.update(headers or {})
        req = urllib.request.Request(url, data=data, method=method, headers=h)
        if self.auth:
            req.add_unredirected_header('Authorization', self.auth)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode('utf-8', 'replace')
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise Refused(AUTH_REFUSED, 'the source answered HTTP %d: the credential was refused or lacks '
                                            'the permission (this is not "no findings")' % e.code)
            raise Refused(UNREACHABLE, 'HTTP %d from %s: %s' % (e.code, self.host, self.scrub(e.read()[:300])))
        except (urllib.error.URLError, OSError) as e:
            raise Refused(UNREACHABLE, 'could not reach %s (%s)' % (self.host, self.scrub(e)))
        try:
            return json.loads(body or '{}')
        except ValueError:
            raise Refused(RESPONSE_INVALID, 'the answer from %s was not JSON' % self.host)

    def get(self, path, params):
        return self.request('GET', '%s/%s?%s' % (self.base, path.lstrip('/'), urllib.parse.urlencode(params, doseq=True)))


def evidence_of(prefix, rec):
    blob = json.dumps(rec, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return {'ref': '%s' % prefix, 'sha256': hashlib.sha256(blob).hexdigest()}


def repo_for(key, repo_map):
    v = (repo_map or {}).get(key) or (repo_map or {}).get('*')
    if v and '{}' in v:
        v = v.replace('{}', key)
    return v if v and re.match(r'^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$', v) else None


def ident_ok(s):
    return bool(re.match(r'^[A-Za-z0-9][A-Za-z0-9._:/-]{1,127}$', s or ''))


# ───────────────────────────────────────────────────────────── SonarQube
def sonar_pull(http, projects, organization='', environment='code', rule_lookup=False, tool='SonarQube'):
    issues, hotspots, components = [], [], {}
    for proj in projects:
        p = 1
        while True:
            params = {'componentKeys': proj, 'impactSoftwareQualities': 'SECURITY',
                      'issueStatuses': 'OPEN,CONFIRMED,ACCEPTED,FALSE_POSITIVE', 'p': p, 'ps': SONAR_PS}
            if organization:
                params['organization'] = organization
            doc = http.get('api/issues/search', params)
            paging = doc.get('paging') if isinstance(doc, dict) else None
            page = doc.get('issues') if isinstance(doc, dict) else None
            if not isinstance(paging, dict) or not isinstance(page, list) or not isinstance(paging.get('total'), int):
                raise Refused(RESPONSE_INVALID, 'api/issues/search answered without paging.total or issues[]')
            total = paging['total']
            if total > SONAR_DEPTH:
                raise Refused(TRUNCATED, 'project %s has %d security issues, past the %d the search returns; '
                                         'split the pull (by branch or date)' % (proj, total, SONAR_DEPTH))
            for c in doc.get('components') or []:
                if isinstance(c, dict) and c.get('key'):
                    components[c['key']] = c.get('path') or ''
            issues.extend(dict(i, _project=proj) for i in page if isinstance(i, dict))
            got = sum(1 for i in issues if i.get('_project') == proj)
            if got >= total:
                break
            if not page or p >= MAX_PAGES:
                raise Refused(TRUNCATED, 'project %s: %d of %d issues returned before the pages ran out' % (proj, got, total))
            p += 1
        p = 1
        while True:
            doc = http.get('api/hotspots/search', {'projectKey': proj, 'status': 'TO_REVIEW', 'p': p, 'ps': SONAR_PS})
            paging = doc.get('paging') if isinstance(doc, dict) else None
            page = doc.get('hotspots') if isinstance(doc, dict) else None
            if not isinstance(paging, dict) or not isinstance(page, list) or not isinstance(paging.get('total'), int):
                raise Refused(RESPONSE_INVALID, 'api/hotspots/search answered without paging.total or hotspots[]')
            for c in doc.get('components') or []:
                if isinstance(c, dict) and c.get('key'):
                    components[c['key']] = c.get('path') or ''
            hotspots.extend(dict(h, _project=proj) for h in page if isinstance(h, dict))
            got = sum(1 for h in hotspots if h.get('_project') == proj)
            if got >= paging['total']:
                break
            if not page or p >= MAX_PAGES:
                raise Refused(TRUNCATED, 'project %s: %d of %d hotspots returned' % (proj, got, paging['total']))
            p += 1
    cwe_of = {}
    if rule_lookup:
        for r in sorted({i.get('rule') for i in issues if i.get('rule')} | {h.get('ruleKey') for h in hotspots if h.get('ruleKey')}):
            try:
                rule = (http.get('api/rules/show', {'key': r}).get('rule') or {})
            except Refused as e:
                if e.state == AUTH_REFUSED:
                    raise
                continue
            # THE shared normaliser (scripts/finding_ids.py): `cwe:89` and every other CWE spelling.
            cw = [x for x in rule.get('securityStandards') or [] if str(x).lower().startswith('cwe')]
            found, _bad = finding_ids.normalize_cwes(cw)
            if found:
                cwe_of[r] = found[0]
            for why in _bad:
                UNKNOWN.record('cwe', 'sonarqube', r, json.dumps(cw)[:200], 'api/rules/show securityStandards', why)
    return issues, hotspots, components, cwe_of


def sonar_items(issues, hotspots, components, cwe_of, repo_map, environment, tool, host):
    items, closed, unmapped = [], [], []

    def path_of(rec):
        comp = rec.get('component') or ''
        return components.get(comp) or (comp.split(':', 1)[1] if ':' in comp else '')

    for i in issues:
        key = str(i.get('key') or '')
        status = str(i.get('issueStatus') or i.get('status') or '').upper()
        if status not in SONAR_OPEN:
            closed.append({'source_key': 'sonar:%s' % key, 'status': status})
            continue
        sec = [x for x in i.get('impacts') or [] if isinstance(x, dict) and x.get('softwareQuality') == 'SECURITY']
        sev = SONAR_IMPACT.get(str(sec[0].get('severity')).upper()) if sec else SONAR_LEGACY.get(str(i.get('severity')).upper())
        items.append(_code_item(tool, environment, repo_for(i['_project'], repo_map), path_of(i), i.get('line'),
                                str(i.get('rule') or ''), sev, cwe_of.get(i.get('rule')), str(i.get('message') or ''),
                                'sonar:%s' % key, i, unmapped, host))
    for h in hotspots:
        key = str(h.get('key') or '')
        if str(h.get('status') or '').upper() != 'TO_REVIEW':
            closed.append({'source_key': 'sonar-hotspot:%s' % key, 'status': str(h.get('status'))})
            continue
        items.append(_code_item(tool, environment, repo_for(h['_project'], repo_map), path_of(h), h.get('line'),
                                str(h.get('ruleKey') or ''), HOTSPOT_PROB.get(str(h.get('vulnerabilityProbability')).upper()),
                                cwe_of.get(h.get('ruleKey')), 'Security hotspot: %s' % (h.get('message') or ''),
                                'sonar-hotspot:%s' % key, h, unmapped, host))
    return [x for x in items if x], closed, unmapped


def _code_item(tool, environment, repo, path, line, rule, sev, cwe, title, source_key, raw, unmapped, host):
    why = []
    if not repo:
        why.append('no repository mapped for project %s (--repo-map)' % raw.get('_project'))
    if not path:
        why.append('no file path')
    if not ident_ok(rule):
        why.append('rule %r is not a usable identifier' % rule)
    if not sev:
        why.append('no severity')
    if why:
        unmapped.append({'source_key': source_key, 'state': NOT_MAPPED, 'why': '; '.join(why)})
        return None
    raw = dict((k, v) for k, v in raw.items() if not k.startswith('_'))
    asset = {'scheme': 'repo-path', 'repository': repo, 'path': path.lstrip('/')}
    if isinstance(line, int) and line >= 1:
        asset['line'] = line
    item = {'source_type': 'scan-app', 'source_tool': tool, 'environment': environment, 'asset': asset,
            'identifier': rule, 'aliases': [source_key], 'severity': sev,
            'fix_status': 'FIX_AVAILABILITY_NOT_ESTABLISHED', 'finding_subject': 'SOURCE',
            'evidence': evidence_of('%s %s' % (host, source_key), raw), 'title': (title or rule)[:300]}
    if cwe and re.match(r'^CWE-[0-9]{1,5}$', cwe):
        item['cwe'] = cwe
    return item


# ───────────────────────────────────────────────────────────── Aikido
def aikido_token(token_url, client_id, client_secret):
    http = Http(token_url.rsplit('/api/', 1)[0], secrets=(client_id, client_secret))
    basic = base64.b64encode(('%s:%s' % (client_id, client_secret)).encode('utf-8')).decode('ascii')
    http.auth = 'Basic %s' % basic
    doc = http.request('POST', token_url, data=urllib.parse.urlencode({'grant_type': 'client_credentials'}).encode(),
                       headers={'Content-Type': 'application/x-www-form-urlencoded'})
    tok = doc.get('access_token') if isinstance(doc, dict) else None
    if not tok:
        raise Refused(AUTH_REFUSED, 'the token endpoint answered without an access_token')
    return tok


def aikido_pull(http):
    out, page = [], 0
    while True:
        doc = http.get('issues/export', {'format': 'json', 'filter_status': 'open', 'page': page,
                                         'per_page': AIKIDO_PER_PAGE})
        rows = doc if isinstance(doc, list) else (doc.get('issues') if isinstance(doc, dict) else None)
        if not isinstance(rows, list):
            raise Refused(RESPONSE_INVALID, 'issues/export did not answer a JSON list of issues')
        out.extend(r for r in rows if isinstance(r, dict))
        if len(rows) < AIKIDO_PER_PAGE:
            return out
        page += 1
        if page >= MAX_PAGES:
            raise Refused(TRUNCATED, 'issues/export still had pages after %d; nothing past them was read' % MAX_PAGES)


def aikido_items(rows, repo_map, environment, tool='Aikido', id_refusals=None):
    items, closed, unmapped = [], [], []
    id_refusals = [] if id_refusals is None else id_refusals
    for r in rows:
        rid = str(r.get('id') or '')
        sk = 'aikido:%s' % rid
        if str(r.get('status') or '').lower() != 'open':
            closed.append({'source_key': sk, 'status': r.get('status')})
            continue
        typ = str(r.get('type') or '')
        # THE shared normaliser (scripts/finding_ids.py): `cve-2026-1`, `CVE 2026-1` are one CVE; an id in
        # a form it does not know is not a CVE (refused by name and listed), never a guess.
        cve, cve_kind = finding_ids.normalize_vuln_id(r.get('cve_id')) if r.get('cve_id') else (None, '')
        if r.get('cve_id') and (not cve or cve_kind != 'cve'):
            id_refusals.append({'source_key': sk, 'field': 'cve_id', 'why': cve_kind if not cve else
                                '%s is a %s id, not a CVE' % (cve, cve_kind)})
            UNKNOWN.record('vuln-id', 'aikido', typ or 'issue', r.get('cve_id'), 'issues/export cve_id',
                           id_refusals[-1]['why'])
            cve = None
        ident = cve if cve else 'aikido:%s:%s' % (typ or 'issue', r.get('rule_id') or r.get('rule') or rid)
        ident = re.sub(r'[^A-Za-z0-9._:/-]', '-', ident)[:128]
        repo = repo_for(str(r.get('code_repo_name') or ''), repo_map) if r.get('code_repo_name') else None
        path = str(r.get('affected_file') or '')
        why = []
        if not repo:
            why.append('not a code-repository finding with a mapped repository (cloud, container and domain '
                       'findings need their own asset scheme)' if not r.get('code_repo_name')
                       else 'no repository mapped for %s (--repo-map)' % r.get('code_repo_name'))
        if not path:
            why.append('no affected_file')
        sev = str(r.get('severity') or '').lower()
        if sev not in ('critical', 'high', 'medium', 'low'):
            why.append('severity %r is not critical/high/medium/low' % r.get('severity'))
        if why:
            unmapped.append({'source_key': sk, 'state': NOT_MAPPED, 'why': '; '.join(why)})
            continue
        asset = {'scheme': 'repo-path', 'repository': repo, 'path': path.lstrip('/')}
        if isinstance(r.get('start_line'), int) and r['start_line'] >= 1:
            asset['line'] = r['start_line']
        # cwe_classes is a field that holds CWEs, so a bare number counts (numeric_ok); its exact
        # spelling is UNVERIFIED, so every member goes through THE shared normaliser.
        found, bad_cwes = finding_ids.normalize_cwes(r.get('cwe_classes') or [], numeric_ok=True)
        cwe = found[0] if found else ''
        for b in bad_cwes:
            id_refusals.append({'source_key': sk, 'field': 'cwe_classes', 'why': b})
            UNKNOWN.record('cwe', 'aikido', typ or 'issue', json.dumps(r.get('cwe_classes'))[:200],
                           'issues/export cwe_classes', b)
        item = {'source_type': 'scan-app', 'source_tool': tool, 'environment': environment, 'asset': asset,
                'identifier': ident, 'aliases': [sk] + ([cve] if cve else []), 'severity': sev,
                'fix_status': 'FIX_AVAILABLE' if r.get('patched_versions') else 'FIX_AVAILABILITY_NOT_ESTABLISHED',
                'finding_subject': AIKIDO_SUBJECT.get(typ, 'SOURCE'),
                'evidence': evidence_of('aikido issue %s' % rid, r),
                'title': ('%s%s' % (r.get('rule') or typ or 'Aikido issue',
                                    (' in %s' % r['affected_package']) if r.get('affected_package') else ''))[:300]}
        if cwe:
            item['cwe'] = cwe
        items.append(item)
    return items, closed, unmapped


# ───────────────────────────────────────────────────────────── normalise, validate, dedupe
def kit_duplicate(item, kit):
    """THE SEAM for the SAST identity (the SAST/evidence-export lane). -> the matching kit observation, or None.
    Dependency: a shared CVE on the same path. Code: same path, same line and the same CWE."""
    path = item['asset']['path'].lower()
    cves = {a.upper() for a in item.get('aliases', []) if a.upper().startswith('CVE-')}
    for o in kit:
        kp = str(o.get('canonical_path') or '').lower().lstrip('/')
        if kp != path and not kp.endswith('/' + path) and not path.endswith('/' + kp):
            continue
        if cves and cves & {str(a).upper() for a in o.get('what_aliases') or []}:
            return o
        if (item.get('cwe') and str(o.get('cwe') or '').upper() == item['cwe'].upper() and
                item['asset'].get('line') and o.get('line') == item['asset'].get('line')):
            return o
    return None


def finish(source, items, closed, unmapped, kit_findings, provenance):
    import ticket_templates as tt
    out_items, dup_kit, seen = [], [], {}
    for idx, it in enumerate(items):
        prob = tt.validate_item('finding', it, idx)
        if prob:
            unmapped.append({'source_key': it['aliases'][0], 'state': NOT_MAPPED,
                             'why': '%s: %s' % (prob.get('code'), prob.get('detail'))})
            continue
        rec = tt.normalize('finding', it, provenance, idx)
        if rec['identity'] in seen:
            seen[rec['identity']]['aliases'] = sorted(set(seen[rec['identity']]['aliases']) | set(it['aliases']))
            continue
        k = kit_duplicate(it, kit_findings or [])
        if k is not None:
            dup_kit.append({'source_key': it['aliases'][0], 'state': DUPLICATE_OF_KIT,
                            'kit': {'scanner': k.get('scanner'), 'rule_id': k.get('rule_id'),
                                    'path': k.get('canonical_path'), 'line': k.get('line')}})
            continue
        seen[rec['identity']] = it
        out_items.append(it)
    return {'source': source, 'state': PULLED, 'pulled_at': datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
            'counts': {'items': len(out_items), 'duplicates_of_kit': len(dup_kit), 'source_closed': len(closed),
                       'not_mapped': len(unmapped)},
            'items': out_items, 'duplicates_of_kit': dup_kit, 'source_closed': closed, 'not_mapped': unmapped}


def batches(pulled, review_id, size=20):
    """-> [(params, evidence_sha256)]: tickets.submit params of at most `size` items, each bound to
    review_id, with the evidence-set hash the review must concur with (ticket_templates). The request
    for each must fit the kit API's size limit; a batch that does not is split until it does."""
    import kit_api as ka
    import ticket_templates as tt
    items = list((pulled or {}).get('items') or [])
    out, i = [], 0
    while i < len(items):
        n = min(size, len(items) - i)
        while True:
            params = {'template': 'finding', 'template_version': tt.TEMPLATE_VERSION, 'review_id': review_id,
                      'items': items[i:i + n]}
            req = ka.build_request('tickets.submit', params, idempotency_key='x' * 16,
                                   correlation_id='kapi-20260101T000000Z-000000000000')
            if len(json.dumps(req, sort_keys=True)) <= ka.REQUEST_MAX or n == 1:
                break
            n = max(1, n // 2)
        out.append((params, tt.evidence_set_sha256(params)))
        i += n
    return out


def load_json(path, default):
    if not path:
        return default
    with io.open(path, encoding='utf-8') as fh:
        return json.load(fh)


def batch_main(argv):
    ap = argparse.ArgumentParser(description='Split a pull into tickets.submit params bound to a review id.')
    ap.add_argument('--in', dest='src', required=True)
    ap.add_argument('--review-id', required=True)
    ap.add_argument('--size', type=int, default=20)
    ap.add_argument('--out-dir', required=True)
    a = ap.parse_args(argv)
    if not re.match(r'^[A-Za-z0-9][A-Za-z0-9._-]{2,79}$', a.review_id):
        print('usage: --review-id must match the tickets.submit review_id pattern')
        return 2
    pulled = load_json(a.src, {})
    if pulled.get('state') != PULLED:
        print('%s: the pull did not complete (%s); nothing to submit' % (pulled.get('state'), pulled.get('detail', '')))
        return 1
    os.makedirs(a.out_dir, exist_ok=True)
    rows = batches(pulled, a.review_id, max(1, min(50, a.size)))
    for n, (params, h) in enumerate(rows, 1):
        io.open(os.path.join(a.out_dir, 'batch-%03d.params.json' % n), 'w', encoding='utf-8').write(
            json.dumps(params, sort_keys=True))
        print('batch-%03d  %3d item(s)  evidence_sha256 %s' % (n, len(params['items']), h))
    print('%d batch(es) for review %s: the review record must concur with each evidence_sha256 above.' % (len(rows), a.review_id))
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ['batch']:
        return batch_main(argv[1:])
    ap = argparse.ArgumentParser(description='Pull SonarQube or Aikido findings into the kit intake (read-only).')
    ap.add_argument('source', choices=['sonar', 'aikido'])
    ap.add_argument('--host', default=os.environ.get('SONAR_HOST_URL', ''))
    ap.add_argument('--organization', default=os.environ.get('SONAR_ORGANIZATION', ''))
    ap.add_argument('--project', action='append', default=[])
    ap.add_argument('--rule-lookup', action='store_true', help='Sonar: read CWE from api/rules/show (UNVERIFIED field)')
    ap.add_argument('--base', default=os.environ.get('AIKIDO_API_BASE', 'https://app.aikido.dev/api/public/v1'))
    ap.add_argument('--token-url', default='')
    ap.add_argument('--repo-map', help='JSON {project key or repo name: "org/repo"}; "*": "org/{}" maps every name')
    ap.add_argument('--environment', default='code')
    ap.add_argument('--kit-findings')
    ap.add_argument('--out', required=True)
    a = ap.parse_args(argv)
    try:
        repo_map = load_json(a.repo_map, {})
        kit = load_json(a.kit_findings, [])
        if isinstance(kit, dict):
            kit = kit.get('findings') or kit.get('observations') or []
    except (OSError, ValueError) as e:
        print('usage: a --repo-map or --kit-findings file could not be read (%s)' % type(e).__name__)
        return 2
    prov = {'submitted_by': 'external-findings-pull', 'review_id': ''}
    try:
        if a.source == 'sonar':
            token = os.environ.get('SONAR_TOKEN', '')
            if not token or not a.host or not a.project:
                raise Refused(NOT_CONFIGURED, 'needs SONAR_TOKEN (a secret), SONAR_HOST_URL and at least one --project; '
                                              'nothing was pulled, which is not "no findings"')
            http = Http(a.host, secrets=(token,))
            http.auth = 'Bearer %s' % token
            tool = 'SonarQube Cloud' if 'sonarcloud.io' in a.host else 'SonarQube'
            iss, hs, comps, cwe_of = sonar_pull(http, a.project, a.organization, a.environment, a.rule_lookup, tool)
            items, closed, unmapped = sonar_items(iss, hs, comps, cwe_of, repo_map, a.environment, tool,
                                                  urllib.parse.urlparse(a.host).netloc)
            result = finish('sonarqube', items, closed, unmapped, kit, prov)
        else:
            cid, csec = os.environ.get('AIKIDO_CLIENT_ID', ''), os.environ.get('AIKIDO_CLIENT_SECRET', '')
            if not cid or not csec:
                raise Refused(NOT_CONFIGURED, 'needs AIKIDO_CLIENT_ID and AIKIDO_CLIENT_SECRET (secrets); nothing '
                                              'was pulled, which is not "no findings"')
            base = a.base.rstrip('/')
            token_url = a.token_url or base.split('/api/public/', 1)[0] + '/api/oauth/token'
            tok = aikido_token(token_url, cid, csec)
            http = Http(base, secrets=(cid, csec, tok))
            http.auth = 'Bearer %s' % tok
            rows = aikido_pull(http)
            id_refusals = []
            items, closed, unmapped = aikido_items(rows, repo_map, a.environment, id_refusals=id_refusals)
            result = finish('aikido', items, closed, unmapped, kit, prov)
            result['id_refusals'] = id_refusals
    except Refused as e:
        result = {'source': a.source, 'state': e.state, 'detail': e.detail, 'items': []}
        io.open(a.out, 'w', encoding='utf-8').write(json.dumps(result, indent=1))
        print('%s: %s' % (e.state, e.detail))
        return 1
    # THE UNKNOWNS LOG beside the pull (owner ruling 2026-11-06): kept in the artifact, listed for the
    # reviewer who concurs with the batches, never dropped and never guessed.
    result['unknown_ids'] = UNKNOWN.entries()
    UNKNOWN.write(os.path.join(os.path.dirname(os.path.abspath(a.out)), unknown_ids.FILENAME))
    io.open(a.out, 'w', encoding='utf-8').write(json.dumps(result, indent=1, sort_keys=True))
    c = result['counts']
    print('%s %s: %d item(s) for the intake, %d already a kit finding, %d closed at the source, %d not mapped'
          % (PULLED, result['source'], c['items'], c['duplicates_of_kit'], c['source_closed'], c['not_mapped']))
    for u in result['not_mapped'][:20]:
        print('  NOT_MAPPED %s: %s' % (u['source_key'], u['why']))
    for u in result['unknown_ids']:
        print('  NEEDS_MAPPING %s %s %r (seen %d): a person maps it in id-mappings.json' % (
            u['kind'], u['tool'], u['raw'], u['count']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
