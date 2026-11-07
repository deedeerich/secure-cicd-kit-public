#!/usr/bin/env python3
"""evidence.export: the kit's half of the per-app evidence bundle, read-only, one repository. NO NETWORK.

WHY (the owner, 2026-11-06: "the back half of the bundle")
    The evidence harness builds one folder per app for a CAB change or an adoption review
    (src/app_evidence_bundle.py, docs/APP_EVIDENCE_BUNDLE.md). Its kit half was a pile of downloaded
    artifacts that expire, and it found three facts no kit record carried: whether any finding is on
    CISA KEV, the SBOM's digest, and who authored the commit. evidence.export answers, for one
    repository at one commit or one release, with every section the bundle reads -- or a section that
    says NOT ESTABLISHED and why, never an empty one.

WHAT IT PROVES (scripts/evidence_export.py, scripts/kit_api_server.py, scripts/reviewer_signals.py)
  POSITIVE
    E1  the export of a fixture repository has every section ESTABLISHED: security record, review signals,
        promotion records, release records (from the durable GitHub deployment record, with the deploy
        evidence artifact EXPIRED), findings, ticket outbox, ticket links, KEV, SBOM, author; and it
        validates against api/v1/evidence-export.schema.json.
    E2  idempotent: the same reads give the same bytes; a release id gives the same export as its commit.
    E3  the harness reads it: unpacked, src/app_evidence_bundle.py builds a bundle that establishes the
        security run, the release, the promotion, the findings and the outbox (run where the harness source
        is present: the evidence_harness_src variable, upper-cased; otherwise reported as not run, never as passed).
    E4  the API contract: evidence.export is a read (no idempotency key), enabled by default; exactly one of
        commit and release; another repository is API_REPOSITORY_NOT_SERVED; an unknown release is
        API_EVIDENCE_UNAVAILABLE; the run answers API_COMPLETED with the export and writes the unpacked copy.
    E5  the security record carries the KEV verdict, the SBOM digest and the commit author (a pseudonym and
        the committer verification state).
  NEGATIVE
    N1  another repository's records are never included (counted, never copied).
    N2  missing records are NOT ESTABLISHED with a reason -- never an empty list or a zero.
    N3  no secret and no free text: a credential planted in a record, a finding's message and an outbox's
        params never reach the export.
    N4  the author is a pseudonym: no login, no email, anywhere in the export.
  MUTANTS
    M1  the repository filter removed               -> N1 fails
    M2  a missing section rendered as empty         -> N2 fails
    M3  records copied whole (no allowlist)         -> N3 fails
    M4  the author recorded by email                -> N4 fails

EXIT  0 proven   1 a case failed (named)   2 could not be checked
"""
import copy
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))

FAILS = []
REPO = 'example-org/orders-api'
OTHER = 'other-org/other-app'
SHA = 'c' * 40
PLANTED = 'gh' + 'p_' + 'Z9' * 18                      # a token-shaped value, assembled at run time
author_login, author_email = 'dev-one', 'dev.one@example.invalid'


def check(cond, msg):
    print('  %s %s' % ('ok  ' if cond else 'FAIL', msg))
    if not cond:
        FAILS.append(msg)
    return bool(cond)


def zblob(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        for name, doc in files.items():
            z.writestr(name, doc if isinstance(doc, (bytes, str)) else json.dumps(doc))
    return buf.getvalue()


def security_record(repo=REPO, run_id='5001', with_new=True):
    rec = {'schema': 'kit-security-record/1',
           'run': {'repository': repo, 'run_id': run_id, 'run_attempt': '1', 'commit': SHA, 'ref': 'refs/heads/main',
                   'actor': 'dev-one', 'triggering_actor': 'dev-one'},
           'verdict': {'routing_result': 'PROCEED_WITH_ADVISORY', 'advisory_causes': ['FINDINGS_NOT_BLOCKED']},
           'weakening': {'attribution': '', 'check': {'state': 'WEAKENING_ATTRIBUTED', 'missing': [],
                                                      'why': ['approved; note ' + PLANTED]}},
           'capability_floor': {'state': 'HELD', 'missing': []}, 'token_preflight': 'TOKEN_ACCEPTED',
           'leak_gates': {'push_protection': 'ON'}, 'leak_gate_alarm': '',
           'policy': {'source': 'KIT_DEFAULT', 'resolution': 'POLICY_RESOLVED', 'rung_effective': 'crawl',
                      'environment_tier': 'prod', 'notices': []},
           'deploy_coverage': {'no_kit_adapter': [], 'deploy_targets': {}},
           'kit': {'state': 'WATERMARK_BOUND', 'source_commit': 'b' * 40, 'kit_ref': 'a' * 40},
           'evidence': {'artifact': 'security-report-1', 'record_artifact': 'kit-security-record-1',
                        'retention_days': 90, 'retention': 'EVIDENCE_RETENTION_DEFAULT'},
           'run_record': {'assurance_state': 'ESTABLISHED', 'enforcement_state': 'ADVISORY', 'secret_gate': 'PASS'}}
    if with_new:
        rec['kev'] = {'state': 'ESTABLISHED', 'verdict': 'CLEAR', 'kev_state': 'AVAILABLE', 'on_kev': False}
        rec['sbom'] = {'state': 'ESTABLISHED', 'digest': 'sha256:' + 'e' * 64, 'artifact': 'sbom'}
        rec['author'] = {'state': 'ESTABLISHED', 'id': 'person:' + hashlib.sha256(author_login.encode()).hexdigest()[:10],
                         'committer_id': 'person:' + hashlib.sha256(b'web-flow').hexdigest()[:10],
                         'verification': {'verified': True, 'reason': 'valid'}}
    return rec


def release_payload(repo=REPO, env='prod', run_id='5002'):
    return {'schema': 'kit-release-record/1', 'repository': repo, 'run_id': run_id, 'run_attempt': '1', 'commit': SHA,
            'environment': env, 'tier': env, 'adapter': 'appservice', 'digest': 'sha256:' + 'd' * 64,
            'routing_result': 'PROCEED', 'deployment_outcome': 'DEPLOY_HEALTHY',
            'release_approval': 'RELEASE_APPROVAL_VERIFIED', 'release_approval_by': ['lead-two'],
            'zone_readiness': 'READY', 'release_block': 'RELEASE_NOT_BLOCKED', 'verdict_provenance': 'VERDICT_FROM_GATE',
            'weakening_check': 'WEAKENING_ATTRIBUTED', 'tier_source': 'TIER_VENDED', 'tier_reality': 'TIER_CONSISTENT',
            'readiness_source': 'READINESS_SOURCE_LZ_HANDOFF', 'lease': 'LEASE_NOT_IN_FORCE',
            'seam': 'SEAM_OWNERSHIP_NOT_IN_FORCE', 'kit_watermark': 'WATERMARK_BOUND', 'kit_source_commit': 'b' * 40,
            'release_record': 'RELEASE_RECORD_KEPT_DEPLOYMENT', 'release_record_ref': '9001',
            'evidence_artifact': 'deploy-evidence-%s-1' % run_id, 'retention_days': 90,
            'promotion': {'record_id': '%s-1-%s' % (run_id, env), 'state': 'verified-for-promotion',
                          'release_path': 'normal', 'expires_at': '2031-06-10T00:00:00Z',
                          'target_resource_id': '/subscriptions/s/resourceGroups/rg/providers/Microsoft.Web/sites/orders'}}


FINDINGS = [
    {'identity': 'f' * 32, 'fp': 'a1b2c3d4e5f6', 'scanner': 'bandit', 'tool': 'Bandit', 'scanner_version': '1.7.10',
     'job': 'sast', 'rule_id': 'B602', 'severity': 'HIGH', 'canonical_path': 'app/run.py', 'line': 6,
     'finding_subject': 'SOURCE', 'cwe': 'CWE-78', 'state': 'FINGERPRINTED', 'reason': '', 'detail': 'x',
     'row_established': True, 'rule_family': 'os-command-injection', 'ticket_anchor': '1' * 32,
     'ticket_key_state': 'CODE_KEYED', 'message': 'subprocess with shell=True: ' + PLANTED, 'snippet': PLANTED},
    {'identity': None, 'fp': '0f0f0f0f0f0f', 'scanner': 'gitleaks', 'tool': 'gitleaks', 'job': 'secret-scan',
     'rule_id': 'aws-access-token', 'severity': 'HIGH', 'canonical_path': 'config/settings.py', 'line': 3,
     'finding_subject': 'SOURCE', 'state': 'UNFINGERPRINTABLE', 'reason': 'SECRET_SUBJECT_NOT_BASELINEABLE',
     'row_established': True, 'secret_family': 'aws-access-key', 'secret_key': '2' * 32,
     'ticket_key_state': 'SECRET_KEYED', 'is_secret_finding': True},
    {'identity': 'e' * 32, 'fp': '9e9e9e9e9e9e', 'scanner': 'trivy', 'job': 'deps-scan', 'rule_id': 'CVE-2019-20477',
     'what_aliases': ['CVE-2019-20477'], 'severity': 'CRITICAL', 'canonical_path': 'requirements.txt',
     'finding_subject': 'SOURCE_DEPENDENCY', 'state': 'FINGERPRINTED', 'row_established': True},
]
LEDGER = {'k' * 32: {'ref': '10101', 'key': 'SEC-105', 'member_identities': ['f' * 32]},
          's' * 32: {'ref': '10102', 'key': 'SEC-106', 'member_identities': ['secret:' + '2' * 32]},
          'o' * 32: {'ref': '10999', 'key': 'SEC-999', 'member_identities': ['9' * 32]}}


class FakeGitHub(object):
    """The GitHub reads evidence.export makes, from a fixture. `expired` artifact names come back expired."""

    def __init__(self, full=True, expired=(), other_repo_record=True):
        self.calls = []
        arts, blobs = [], {}
        n = [100]

        def art(run_id, name, files, exp=False):
            n[0] += 1
            arts.append({'id': n[0], 'name': name, 'expired': exp or name in expired, 'workflow_run': {'id': int(run_id)},
                         'run_id': int(run_id)})
            blobs[n[0]] = zblob(files)
        if full:
            art(5001, 'kit-security-record-1', {'kit-security-record.json': security_record()})
            art(5001, 'security-report-1', {'findings.json': FINDINGS, 'report.md': '# report'})
            art(5001, 'sbom', {'sbom.cyclonedx.json': '{"bomFormat": "CycloneDX"}'})
            art(5002, 'deploy-evidence-5002-1', {'review-signals.json': release_payload()}, exp=True)
            art(5002, 'kit-promotion-record-prod', {'promotion-record.json': {
                'schema': 'kit-promotion-record/1', 'record_id': '5002-1-prod', 'state': 'verified-for-promotion',
                'release_path': 'normal', 'artifact': {'digest': 'sha256:' + 'd' * 64},
                'environment': {'name': 'prod', 'tier': 'prod', 'adapter': 'appservice', 'target_resource_id': '/x'},
                'validity': {'expires_at': '2031-06-10T00:00:00Z'},
                'run': {'id': '5002', 'attempt': '1', 'url': 'https://example.ghe.com/%s/actions/runs/5002' % REPO}}})
            art(7000, 'kit-ticket-outbox-kapi-20261106T101010Z-aaaaaaaaaaaa', {'outbox.json': {
                'schema': 'kit-ticket-outbox/1', 'correlation_id': 'kapi-20261106T101010Z-aaaaaaaaaaaa',
                'created_at': '2026-11-06T10:10:10Z', 'reason': 'tracker returned 503', 'items': [0, 1],
                'params': {'note': PLANTED}, 'repository': REPO}})
            art(7001, 'kit-ticket-outbox-kapi-20261105T101010Z-bbbbbbbbbbbb', {'outbox.json': {
                'schema': 'kit-ticket-outbox/1', 'correlation_id': 'kapi-20261105T101010Z-bbbbbbbbbbbb',
                'items': [0], 'repository': REPO}})
            art(7002, 'kit-ticket-outbox-done-kapi-20261106T111111Z-cccccccccccc', {'outbox-done.json': {
                'drained': ['kapi-20261105T101010Z-bbbbbbbbbbbb']}})
        if other_repo_record:
            art(5001, 'kit-security-record-2', {'kit-security-record.json': security_record(repo=OTHER, run_id='7777')})
        self.arts, self.blobs = arts, blobs
        self.deployments = []
        if full:
            self.deployments = [
                {'id': 9001, 'sha': SHA, 'task': 'kit-release-record', 'environment': 'prod',
                 'created_at': '2026-11-05T12:00:00Z', 'payload': release_payload()},
                {'id': 9002, 'sha': SHA, 'task': 'kit-release-record', 'environment': 'test',
                 'created_at': '2026-11-04T12:00:00Z', 'payload': release_payload(OTHER, 'test', '4990')},
                {'id': 9003, 'sha': SHA, 'task': 'deploy', 'environment': 'prod', 'payload': {}}]
        self.runs = [{'id': 5001, 'head_sha': SHA, 'status': 'completed', 'name': 'security'},
                     {'id': 5002, 'head_sha': SHA, 'status': 'completed', 'name': 'deploy'}]

    def get(self, path):
        self.calls.append(path)
        p = path.split('?')[0]
        if p.endswith('/actions/runs'):
            return 200, {'workflow_runs': self.runs, 'total_count': len(self.runs)}, {}, None
        if '/actions/runs/' in p and p.endswith('/artifacts'):
            rid = int(p.split('/actions/runs/')[1].split('/')[0])
            return 200, {'artifacts': [a for a in self.arts if a['run_id'] == rid]}, {}, None
        if p.endswith('/actions/artifacts'):
            return 200, {'artifacts': list(self.arts), 'total_count': len(self.arts)}, {}, None
        if p.endswith('/deployments'):
            return 200, [d for d in self.deployments if d['sha'] == SHA and ('task=kit-release-record' not in path
                                                                              or d['task'] == 'kit-release-record')], {}, None
        if '/deployments/' in p and p.endswith('/statuses'):
            return 200, [{'state': 'success', 'created_at': '2026-11-05T12:01:00Z'}], {}, None
        if '/deployments/' in p:
            did = int(p.rsplit('/', 1)[1])
            hit = [d for d in self.deployments if d['id'] == did]
            return (200, hit[0], {}, None) if hit else (404, {'message': 'Not Found'}, {}, 'HTTP 404')
        if '/commits/' in p:
            return 200, {'sha': SHA, 'author': {'login': author_login}, 'committer': {'login': 'web-flow'},
                         'commit': {'author': {'name': 'Dev One', 'email': author_email},
                                    'committer': {'email': 'noreply@github.com'},
                                    'verification': {'verified': True, 'reason': 'valid'}}}, {}, None
        return 404, {'message': 'Not Found'}, {}, 'HTTP 404'

    def download(self, path):
        aid = int(path.split('/actions/artifacts/')[1].split('/')[0])
        a = [x for x in self.arts if x['id'] == aid]
        if not a or a[0]['expired']:
            return None
        return self.blobs[aid]


def make_export(ee, client, **kw):
    params = dict({'commit': SHA}, **kw)
    return ee.export(client, REPO, params, ledger=copy.deepcopy(LEDGER), ledger_note='read from the default branch')


def harness_leg(ee, doc, work):
    src = os.environ.get('evidence_harness_src'.upper(), '').strip()
    if not src or not os.path.isfile(os.path.join(src, 'app_evidence_bundle.py')):
        print('  NOT RUN E3 the harness reads it: the harness source variable (evidence_harness_src, upper-cased) names no src/app_evidence_bundle.py on this '
              'host (the unpacked records are still checked against the harness\'s record schemas below)')
        return None
    sys.path.insert(0, src)
    try:
        import app_evidence_bundle as aeb
    except Exception as exc:  # noqa: BLE001
        check(False, 'E3 the harness module could not be imported: %s' % exc)
        return False
    case, kit_fx, tk = os.path.join(work, 'case'), os.path.join(work, 'kit-fx'), os.path.join(work, 'tickets.json')
    aeb._fixture(case, kit_fx, tk)
    kit = os.path.join(work, 'kit-export')
    ee.unpack(doc, kit)
    import datetime
    ctx, _out = aeb.build(case, 'orders-api', datetime.date(2031, 5, 20), kit, tk, 'CHG-1', write=False)
    facts = getattr(ctx, 'facts', None) or []
    text = json.dumps(facts, default=str)
    ok = check('PROCEED_WITH_ADVISORY' in text, 'E3 the harness read the security run\'s routing_result')
    ok &= check('VERDICT_FROM_GATE' in text and 'RELEASE_RECORD_KEPT_DEPLOYMENT' in text,
                'E3 the harness read the release record (verdict provenance, the durable record)')
    ok &= check('verified-for-promotion' in text, 'E3 the harness read the promotion record')
    exc_rows = json.dumps(getattr(ctx, 'exc', []), default=str)
    ok &= check('SEC-105' in exc_rows, 'E3 the harness read the findings with their ticket links')
    ok &= check('outbox_held' in exc_rows.lower() and 'aaaaaaaaaaaa' in exc_rows and 'bbbbbbbbbbbb' not in exc_rows,
                'E3 the harness read the pending outbox (and not the drained one)')
    ok &= check(OTHER not in text, 'E3 nothing of another repository reached the harness')
    return ok


def main():
    try:
        import evidence_export as ee
        import kit_api as ka
        import kit_api_server as ks
    except Exception as exc:  # noqa: BLE001
        print('FAIL: a module could not be imported: %s: %s' % (type(exc).__name__, exc))
        return 1
    work = tempfile.mkdtemp(prefix='kit-export-')
    try:
        return run(ee, ka, ks, work)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def run(ee, ka, ks, work):
    schema_path = os.path.join(ROOT, 'api', 'v1', 'evidence-export.schema.json')
    schema = json.load(io.open(schema_path, encoding='utf-8')) if os.path.isfile(schema_path) else None
    print('E1 the export of a fixture repository has every section')
    doc, ref = make_export(ee, FakeGitHub())
    check(ref is None and isinstance(doc, dict), 'E1 the export completed (%s)' % (ref,))
    secs = (doc or {}).get('sections') or {}
    for s in ee.SECTIONS:
        check((secs.get(s) or {}).get('state') == ee.ESTABLISHED,
              'E1 section %s is ESTABLISHED (%s)' % (s, ((secs.get(s) or {}).get('why') or '')[:90]))
    check(schema is not None and not ka.validate(doc, schema),
          'E1 the export validates against api/v1/evidence-export.schema.json (%s)'
          % ((ka.validate(doc, schema)[:2]) if schema else 'schema absent'))
    rel = (secs.get('release_records') or {}).get('records') or []
    check(len(rel) == 1 and rel[0].get('deployment_id') == 9001 and rel[0].get('status') == 'success',
          'E1 the release record comes from the durable deployment record (artifact expired)')
    check((secs.get('kev') or {}).get('verdict') == 'CLEAR' and (secs.get('sbom') or {}).get('digest') == 'sha256:' + 'e' * 64,
          'E1 the KEV verdict and the SBOM digest are carried')
    links = (secs.get('ticket_links') or {}).get('links') or []
    check(sorted(l.get('key') for l in links) == ['SEC-105', 'SEC-106'],
          'E1 ticket links name the code and the secret ticket, and not another commit\'s (%s)' % [l.get('key') for l in links])
    ob = secs.get('ticket_outbox') or {}
    check([e.get('correlation_id') for e in ob.get('pending') or []] == ['kapi-20261106T101010Z-aaaaaaaaaaaa']
          and 'kapi-20261105T101010Z-bbbbbbbbbbbb' in (ob.get('drained') or []),
          'E1 the outbox state: one pending, one drained')

    print('E2 idempotent')
    doc2, _r = make_export(ee, FakeGitHub())
    check(json.dumps(doc, sort_keys=True) == json.dumps(doc2, sort_keys=True), 'E2 the same reads give the same bytes')
    doc3, r3 = ee.export(FakeGitHub(), REPO, {'release': 9001}, ledger=copy.deepcopy(LEDGER), ledger_note='read from the default branch')
    check(r3 is None and doc3['commit'] == SHA and doc3['subject'] == {'kind': 'release', 'ref': '9001'}
          and doc3['sections'] == doc['sections'], 'E2 a release id exports the same sections as its commit')

    print('E3 the harness reads it')
    out = os.path.join(work, 'unpacked')
    written = ee.unpack(doc, out)
    names = sorted(os.path.relpath(p, out).replace(os.sep, '/') for p in written)
    check(any(n.endswith('kit-security-record.json') for n in names) and any(n.startswith('release-record-') for n in names)
          and any(n.endswith('promotion-record.json') for n in names) and any(n.endswith('findings.json') for n in names)
          and any(n.endswith('outbox.json') for n in names), 'E3 unpacked into the record files the harness reads: %s' % names)
    sec_file = [p for p in written if p.endswith('kit-security-record.json')]
    if sec_file:
        rec = json.load(io.open(sec_file[0], encoding='utf-8'))
        check(rec.get('schema') == 'kit-security-record/1' and rec['run']['repository'] == REPO,
              'E3 the security record keeps its schema (kit-security-record/1) and repository')
    harness_leg(ee, doc, work)

    print('E4 the API contract')
    sch = ka.load_schemas()
    env = lambda **p: {'api_version': 'v1', 'operation': 'evidence.export', 'correlation_id': 'kapi-20261106T120000Z-0123456789ab',
                       'params': p}
    check('evidence.export' in ka.OPERATIONS and not ka.OPERATIONS['evidence.export']['write']
          and 'evidence.export' in ka.DEFAULT_ENABLED, 'E4 evidence.export is a read, enabled by default')
    check(ka.check_request(env(commit=SHA), sch) is None, 'E4 {commit} is accepted without an idempotency key')
    check(ka.check_request(env(release=9001), sch) is None, 'E4 {release} is accepted')
    r = ka.check_request(env(commit='xyz'), sch)
    check(r and r['code'] == ka.API_SCHEMA_VIOLATION, 'E4 a malformed commit is API_SCHEMA_VIOLATION')
    for bad, label in ((dict(commit=SHA, release=9001), 'both'), ({}, 'neither')):
        rr = ee.params_problem(bad, REPO)
        check(rr and rr['code'] == ka.API_SCHEMA_VIOLATION, 'E4 %s of commit and release refused by name' % label)
    rr = ee.params_problem(dict(commit=SHA, repository=OTHER), REPO)
    check(rr and rr['code'] == ka.API_REPOSITORY_NOT_SERVED, 'E4 another repository is API_REPOSITORY_NOT_SERVED')
    _d, rr = ee.export(FakeGitHub(), REPO, {'release': 12345}, ledger={}, ledger_note='')
    check(rr and rr['code'] == ka.API_EVIDENCE_UNAVAILABLE, 'E4 an unknown release is API_EVIDENCE_UNAVAILABLE')
    _d, rr = ee.export(FakeGitHub(), REPO, {'release': 9003}, ledger={}, ledger_note='')
    check(rr and rr['code'] == ka.API_EVIDENCE_UNAVAILABLE, 'E4 a deployment that is not a kit release record is refused')
    srv_out = os.path.join(work, 'srv')
    intake = {'accepted': True, 'operation': 'evidence.export', 'correlation_id': 'kapi-20261106T120000Z-0123456789ab',
              'request': env(commit=SHA)}
    lpath = os.path.join(work, 'ledger.json')
    io.open(lpath, 'w', encoding='utf-8').write(json.dumps(LEDGER))
    ans = ks.findings(intake, {'GITHUB_REPOSITORY': REPO, 'KIT_API_LEDGER': lpath, 'KIT_API_DEFAULT_BRANCH': 'main'},
                      FakeGitHub(), srv_out)
    check(ans.get('api_state') == ka.API_COMPLETED and (ans.get('data') or {}).get('export', {}).get('schema') == ee.SCHEMA,
          'E4 the run answers API_COMPLETED with the export (%s)' % (ans.get('refusal'),))
    check(os.path.isfile(os.path.join(srv_out, 'evidence-export', 'evidence-export.json')),
          'E4 the run writes the unpacked copy for the artifact kit-evidence-export-<correlation id>')

    print('E5 the security record carries the KEV verdict, the SBOM digest and the author')
    import reviewer_signals as rs
    saved = dict(os.environ)
    try:
        os.environ.update(dict((k.upper(), v) for k, v in {
            's_kev_verdict': 'BLOCKED', 's_kev_state': 'AVAILABLE', 's_sbom_digest': 'e' * 64,
            'github_repository': REPO, 'github_sha': SHA, 'github_run_id': '5001', 'github_run_attempt': '1'}.items()))
        fake = FakeGitHub()
        rec = rs.security_record_additions(lambda path: fake.get('/repos/%s/%s' % (REPO, path))[1])
    finally:
        os.environ.clear()
        os.environ.update(saved)
    check(rec['kev'].get('verdict') == 'BLOCKED' and rec['kev'].get('on_kev') is True, 'E5 KEV verdict BLOCKED -> on_kev true')
    check(rec['sbom'].get('digest') == 'sha256:' + 'e' * 64, 'E5 the SBOM digest is recorded')
    check(rec['author'].get('id', '').startswith('person:') and rec['author'].get('verification', {}).get('verified') is True,
          'E5 the author is a pseudonym with the verification state')
    check(author_email not in json.dumps(rec) and author_login not in json.dumps(rec), 'E5 no login and no email in it')
    try:
        os.environ.update(dict((k.upper(), v) for k, v in {
            's_kev_verdict': 'UNAVAILABLE', 's_sbom_digest': '', 'github_sha': SHA}.items()))
        rec2 = rs.security_record_additions(lambda path: None)
    finally:
        os.environ.clear()
        os.environ.update(saved)
    check(rec2['kev'].get('state') == ee.NOT_ESTABLISHED and rec2['kev'].get('on_kev') is None
          and rec2['sbom'].get('state') == ee.NOT_ESTABLISHED and rec2['author'].get('state') == ee.NOT_ESTABLISHED,
          'E5 unknown KEV, no SBOM, unreadable author are NOT ESTABLISHED (on_kev is never false by default)')

    print('N1 another repository\'s records are never included')
    blob = json.dumps(doc)
    n1 = check(OTHER not in blob and '7777' not in blob and '4990' not in blob,
               'N1 no record of %s is in the export' % OTHER)
    n1 &= check((doc.get('excluded_other_repository') or {}).get('count') == 2,
                'N1 the two records naming another repository are counted (%s)' % doc.get('excluded_other_repository'))

    print('N2 missing records are NOT ESTABLISHED, not empty')
    bare, _r = make_export(ee, FakeGitHub(full=False, other_repo_record=False))
    bs = bare.get('sections') or {}
    n2 = True
    for s in ('security_record', 'release_records', 'promotion_records', 'findings', 'review_signals', 'kev', 'sbom'):
        sec = bs.get(s) or {}
        n2 &= check(sec.get('state') == ee.NOT_ESTABLISHED and sec.get('why') and not any(
            isinstance(v, list) and v == [] for k, v in sec.items() if k not in ('why',)),
            'N2 %s is NOT ESTABLISHED with a reason, no empty list (%s)' % (s, (sec.get('why') or '')[:70]))
    n2 &= check(sorted(bare.get('not_established') or []) == sorted(
        s for s in ee.SECTIONS if (bs.get(s) or {}).get('state') == ee.NOT_ESTABLISHED),
        'N2 not_established names every such section')
    check(schema is not None and not ka.validate(bare, schema), 'N2 the bare export still validates')

    print('N3 no secret and no free text')
    n3 = check(PLANTED not in blob and 'subprocess with shell' not in blob and '"params"' not in blob,
               'N3 the planted credential, a finding\'s message and the outbox params are absent')

    print('N4 the author is a pseudonym')
    n4 = check(author_email not in blob and '"%s"' % author_login not in json.dumps(secs.get('author')) and
               str((secs.get('author') or {}).get('id', '')).startswith('person:'),
               'N4 no email and no login in the author section (%s)' % (secs.get('author') or {}).get('id'))

    print('MUTANTS')
    mutant(ee, 'repository_filter', False, lambda: OTHER not in json.dumps(make_export(ee, FakeGitHub())[0]),
           'M1 without the repository filter another repository leaks in')
    def m2():
        b, _ = make_export(ee, FakeGitHub(full=False, other_repo_record=False))
        return all((b['sections'].get(s) or {}).get('state') == ee.NOT_ESTABLISHED for s in ('findings', 'release_records'))
    mutant(ee, 'missing_as_empty', True, m2, 'M2 a missing section rendered as empty is caught')
    mutant(ee, 'copy_whole_records', True, lambda: PLANTED not in json.dumps(make_export(ee, FakeGitHub())[0]),
           'M3 records copied whole carry the planted credential')
    mutant(ee, 'author_by_email', True, lambda: author_email not in json.dumps(
        ee.export(_NoRecordAuthor(), REPO, {'commit': SHA}, ledger={}, ledger_note='')[0]),
        'M4 an author recorded by email is caught')
    print()
    if FAILS:
        print('FAIL: %d check(s): evidence.export does not yet produce the kit\'s half of the bundle.' % len(FAILS))
        return 1
    print('PASS: evidence.export returns every section the bundle reads, for one repository, or NOT ESTABLISHED by name; '
          'idempotent; no secret, no free text, no email; the security record now carries KEV, SBOM and the author.')
    return 0


class _NoRecordAuthor(FakeGitHub):
    """The security record lacks the author (an older kit), so the export reads the commit itself."""

    def __init__(self):
        FakeGitHub.__init__(self)
        for a in self.arts:
            if a['name'] == 'kit-security-record-1':
                rec = security_record(with_new=False)
                self.blobs[a['id']] = zblob({'kit-security-record.json': rec})


def mutant(mod, attr, value, still_passes, label):
    if not hasattr(mod, attr):
        check(False, '%s (the module has no %s to mutate)' % (label, attr))
        return
    saved = getattr(mod, attr)
    try:
        setattr(mod, attr, value)
        try:
            survived = still_passes()
        except Exception as exc:  # noqa: BLE001
            survived = False
            print('      (mutant raised %s)' % type(exc).__name__)
        check(not survived, label)
    finally:
        setattr(mod, attr, saved)


if __name__ == '__main__':
    sys.exit(main())
