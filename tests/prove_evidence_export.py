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

THE QUALIFIERS (xprod 2026-11-09; independent review: the harness must never read a kit promotion or lineage
record as STRONGER than the kit establishes)
    Q1  a finding's disposition_basis is exported verbatim: DISPOSITION_CARRIED_BY_LINEAGE (pending
        reaffirmation), lineage-refused, LINEAGE_RECONCILIATION_UNRESOLVED
    Q2  a promotion record's gate verdict and the refusal codes a break-glass overrode are exported verbatim
        (PROMOTION_REFUSED_HISTORY_INCOMPLETE, _TARGET_UNKNOWN), and a refused promotion keeps its refusal
    Q3  the DURABLE release record's promotion summary (reviewer_signals.promotion_summary) carries the same
        gate and codes, and the export keeps them
    QN  negative: an override's free-text why and by (an exception ref) never reach the export
    QE3 the harness keeps every qualifier: open findings flagged PENDING_DECISION <basis>, never an approval;
        with a harness at HDEC-XPROD2 also F12 (DispositionBasis / ApprovalStatus on every row), F13 (the split
        promotion facts) and F16 (the unpacked records agree with the export on every qualifier)
        kind; the promotion state FLAGGED, the codes verbatim, PROMOTION_NOT_ESTABLISHED (run where the harness
        source is present; against a harness that drops them this FAILS, by design)
    M6  the predecessor dropped from the promotion allowlist      -> Q2 fails
    M7  gate / overridden dropped from the durable summary allowlist -> Q3 fails
    M8  disposition_basis dropped from the finding allowlist    -> Q1 fails

THE EVALUATED DECISION (R-45 M5, KDEC-048: export what the kit's disposition evaluator decided, never the
register's raw status; scan_report.evaluated_decision writes it into findings.json at the run's date)
    D1  an approved, in-date direct decision is APPROVED_EFFECTIVE, with scope, expiry, register key and the
        evaluation date; it never clears the finding; separation of duties NOT_ESTABLISHED
    D2  an expired approval and a legacy key past its window are NOT_EFFECTIVE, the evaluator's reason verbatim
    D3  a carried decision stays PENDING_REAFFIRMATION although its predecessor is approved
    D4  the export carries the evaluator's object verbatim, deterministic, schema-valid
    DN1 a tampered object (carried read as approved, a "cleared" finding, an extra field, a basis mismatch) is
        exported DECISION_NOT_ESTABLISHED with the reason; DN2 an older report exports no object
    QE4 the harness reads APPROVED_EFFECTIVE only where the evaluator said so (with the harness source variable)
    M9  the object copied unchecked -> DN1   M10 the object dropped -> D4
    M11 an evaluator ignoring expiry -> D2   M12 a carried decision mapped to approved -> D3
    THE SCHEMA DESCRIBES THE OBJECT (R3 closeout C2, KDEC-048 M1: api/v1/evidence-export.schema.json)
    D5  both forms the exporter emits (evaluated, and DECISION_NOT_ESTABLISHED) validate against the schema's
        disposition_decision, in place in the export; an export without the object still validates
    DN3 a malformed object is REJECTED BY THE SCHEMA: a property outside the eleven, a value outside the
        vocabulary, a missing required property, a wrongly typed scope / expires / evaluation date
    DN4 a text field (expires, separation_of_duties, basis) that is not a string or null in the report is
        exported DECISION_NOT_ESTABLISHED, never passed through; the export still validates
    M13 the schema without its disposition_decision (items allow anything again) -> DN3
    M14 the text-field type check removed from decision_of -> DN4
    M15 an unbounded DECISION_NOT_ESTABLISHED reason (the defect D5 found: the slice bound to the tuple) -> D5

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


# ── the qualifiers (xprod) ─────────────────────────────────────────────────────────────────────────
CARRIED, REFUSED_CARRY, UNRESOLVED = 'DISPOSITION_CARRIED_BY_LINEAGE', 'lineage-refused', 'LINEAGE_RECONCILIATION_UNRESOLVED'
HIST, TGT = 'PROMOTION_REFUSED_HISTORY_INCOMPLETE', 'PROMOTION_REFUSED_TARGET_UNKNOWN'


def qualified_promotion(env, state, path, gate, over, rid):
    return {'schema': 'kit-promotion-record/1', 'record_id': '%s-1-%s' % (rid, env), 'state': state,
            'release_path': path, 'artifact': {'digest': 'sha256:' + 'd' * 64},
            'environment': {'name': env, 'tier': env, 'adapter': 'appservice',
                            'target_resource_id': None if TGT in over else '/x'},
            'predecessor': {'required': 'uat' if env == 'prod' else 'test', 'promoted_from': {'run_id': '4999'},
                            'gate': gate, 'overridden': [{'code': c, 'why': 'the history: ' + PLANTED,
                                                          'by': 'break-glass exception EXC-PLANTED-7'} for c in over]},
            'validity': {'expires_at': None},
            'run': {'id': rid, 'attempt': '1', 'url': 'https://example.ghe.com/%s/actions/runs/%s' % (REPO, rid)}}


class QualifiedGitHub(FakeGitHub):
    """The fixture with the three qualifiers: carried / refused / unresolved lineage bases on the findings, a
    break-glass prod promotion over HISTORY_INCOMPLETE + TARGET_UNKNOWN, a uat promotion REFUSED for an
    incomplete history, and the durable release record's summary built by reviewer_signals.promotion_summary."""

    def __init__(self):
        import reviewer_signals as rs
        FakeGitHub.__init__(self)
        findings = copy.deepcopy(FINDINGS)
        for f, b in zip(findings, (CARRIED, REFUSED_CARRY, UNRESOLVED)):
            f['disposition_basis'] = b
        self.prod = qualified_promotion('prod', 'BREAK_GLASS', 'break-glass', 'PROMOTION_ALLOWED', (HIST, TGT), '5002')
        uat = qualified_promotion('uat', 'not-verified', 'normal', HIST, (), '5003')
        for a in self.arts:
            if a['name'] == 'security-report-1':
                self.blobs[a['id']] = zblob({'findings.json': findings, 'report.md': '# report'})
            if a['name'] == 'kit-promotion-record-prod':
                self.blobs[a['id']] = zblob({'promotion-record.json': self.prod})
        n = max(a['id'] for a in self.arts) + 1
        self.arts.append({'id': n, 'name': 'kit-promotion-record-uat', 'expired': False,
                          'workflow_run': {'id': 5002}, 'run_id': 5002})
        self.blobs[n] = zblob({'promotion-record.json': uat})
        for d in self.deployments:
            if d['id'] == 9001:
                d['payload'] = dict(d['payload'], promotion=rs.promotion_summary(self.prod))


def qualifiers_of(doc):
    """-> (finding bases, {env: (gate, [codes])} of the records, (gate, [codes]) of the durable summary)."""
    secs = (doc or {}).get('sections') or {}
    bases = sorted(str(f.get('disposition_basis')) for f in (secs.get('findings') or {}).get('findings') or [])
    recs, summ = {}, None
    for r in (secs.get('promotion_records') or {}).get('records') or []:
        if r.get('record'):
            p = r['record'].get('predecessor') or {}
            recs[(r['record'].get('environment') or {}).get('name')] = (
                p.get('gate'), [o.get('code') for o in p.get('overridden') or []])
        elif r.get('summary'):
            summ = (r['summary'].get('gate'), r['summary'].get('overridden'))
    return bases, recs, summ


def qualifier_checks(ee, work):
    print('Q the qualifiers are exported verbatim, never stronger than the kit establishes')
    doc, ref = make_export(ee, QualifiedGitHub())
    bases, recs, summ = qualifiers_of(doc)
    check(ref is None and bases == sorted((CARRIED, REFUSED_CARRY, UNRESOLVED)),
          'Q1 every finding keeps its disposition_basis verbatim (%s)' % bases)
    check(recs.get('prod') == ('PROMOTION_ALLOWED', [HIST, TGT]) and recs.get('uat') == (HIST, []),
          'Q2 the gate verdict and the overridden refusal codes are exported verbatim (%s)' % recs)
    check(summ == ('PROMOTION_ALLOWED', [HIST, TGT]),
          'Q3 the durable release record\'s promotion summary keeps the gate and the codes (%s)' % (summ,))
    schema_path = os.path.join(ROOT, 'api', 'v1', 'evidence-export.schema.json')
    import kit_api as ka
    check(not ka.validate(doc, json.load(io.open(schema_path, encoding='utf-8'))),
          'Q the qualified export still validates against api/v1/evidence-export.schema.json')
    blob = json.dumps(doc)
    check(PLANTED not in blob and 'EXC-PLANTED-7' not in blob and 'the history: ' not in blob,
          'QN an override\'s free-text why and by never reach the export (codes only)')
    full = ee.PROMOTION_RECORD
    mutant(ee, 'PROMOTION_RECORD', dict((k, v) for k, v in full.items() if k != 'predecessor'),
           lambda: qualifiers_of(make_export(ee, QualifiedGitHub())[0])[1].get('prod') == ('PROMOTION_ALLOWED', [HIST, TGT]),
           'M6 the predecessor dropped from the promotion allowlist is caught by Q2')
    rel = dict(ee.RELEASE_RECORD, promotion=tuple(k for k in ee.RELEASE_RECORD['promotion']
                                                  if k not in ('gate', 'overridden')))
    mutant(ee, 'RELEASE_RECORD', rel,
           lambda: qualifiers_of(make_export(ee, QualifiedGitHub())[0])[2] == ('PROMOTION_ALLOWED', [HIST, TGT]),
           'M7 gate and overridden dropped from the durable summary allowlist are caught by Q3')
    mutant(ee, 'FINDING', tuple(k for k in ee.FINDING if k != 'disposition_basis'),
           lambda: qualifiers_of(make_export(ee, QualifiedGitHub())[0])[0] == sorted((CARRIED, REFUSED_CARRY, UNRESOLVED)),
           'M8 disposition_basis dropped from the finding allowlist is caught by Q1')
    harness_qualifiers_leg(ee, doc, work)


def harness_qualifiers_leg(ee, doc, work):
    src = os.environ.get('evidence_harness_src'.upper(), '').strip()
    if not src or not os.path.isfile(os.path.join(src, 'app_evidence_bundle.py')):
        print('  NOT RUN QE3 the harness keeps the qualifiers: the harness source variable names no '
              'src/app_evidence_bundle.py on this host')
        return None
    sys.path.insert(0, src)
    import app_evidence_bundle as aeb
    import datetime
    q = os.path.join(work, 'q')
    case, kit_fx, tk = os.path.join(q, 'case'), os.path.join(q, 'kit-fx'), os.path.join(q, 'tickets.json')
    aeb._fixture(case, kit_fx, tk)
    kit = os.path.join(q, 'kit-export')
    ee.unpack(doc, kit)
    ctx, _out = aeb.build(case, 'orders-api', datetime.date(2031, 5, 20), kit, tk, 'CHG-1', write=False)
    rows = [x for x in ctx.exc if x['Source'] == 'kit findings']
    approval = getattr(aeb, 'APPROVAL_KINDS', ())
    ok = check(sorted(x['Flags'].split(' -- ')[0] for x in rows) ==
               sorted('PENDING_DECISION: ' + b for b in (CARRIED, REFUSED_CARRY, UNRESOLVED)) and
               all(x['Kind'] == 'FINDING' and x['Open'] == 'YES' and x['Kind'] not in approval for x in rows),
               'QE3 each qualified finding stays an open FINDING flagged PENDING_DECISION <basis>, verbatim, never '
               'an approval (%s)' % [x['Flags'][:60] for x in rows])
    facts = ctx.facts
    st = dict((f['Subject'], f['State']) for f in facts if f['Fact'] == 'promotion state')
    over = [f['Value'] for f in facts if f['Subject'] == 'promotion prod' and f['Fact'] == 'promotion gate overridden']
    gate = [f['Value'] for f in facts if f['Subject'] == 'promotion uat' and f['Fact'] == 'promotion gate']
    summ = [f['State'] for f in facts if f['Fact'] == 'promotion summary (durable release record)']
    ok &= check(st.get('promotion prod') == 'FLAGGED' and st.get('promotion uat') == 'FLAGGED' and
                over == ['%s;%s' % (HIST, TGT)] and gate == [HIST] and summ == ['FLAGGED'] and
                len([f for f in ctx.flags if f[0] == 'PROMOTION_NOT_ESTABLISHED']) >= 3,
                'QE3 a break-glass over HISTORY_INCOMPLETE + TARGET_UNKNOWN and a refused promotion are FLAGGED with the '
                'codes verbatim and PROMOTION_NOT_ESTABLISHED, in the record and the durable summary (%s %s %s %s)'
                % (st, over, gate, summ))
    # R2 F12 (harness HDEC-XPROD2): every finding row carries DispositionBasis verbatim; a carried approval is
    # NOT_AN_APPROVAL, never an ordinary approval
    if 'DispositionBasis' not in getattr(aeb, 'EXC_COLUMNS', ()):
        print('  NOT RUN QE3 F12/F13/F16: this harness predates DispositionBasis (harness HDEC-XPROD2)')
        return ok
    ok &= check(sorted(x['DispositionBasis'] for x in rows) == sorted((CARRIED, REFUSED_CARRY, UNRESOLVED)) and
                all(x['ApprovalStatus'].endswith('_NOT_AN_APPROVAL') for x in rows) and
                sorted(x['ReconciliationState'] for x in rows) == sorted(
                    ('CARRIED_PENDING_REAFFIRMATION', 'LINEAGE_REFUSED', 'RECONCILIATION_UNRESOLVED')),
                'QE3 F12 every finding row carries its DispositionBasis verbatim, and a carried / refused / unresolved '
                'one reads NOT_AN_APPROVAL (%s)' % [(x['DispositionBasis'], x['ApprovalStatus']) for x in rows])
    # R2 F13: a valid record of a refused / overridden promotion: integrity ESTABLISHED, the decision apart
    sp = dict(((f['Subject'], f['Fact']), f['Value']) for f in facts)
    integ = 'INTEGRITY_NOT_VERIFIED' if hasattr(aeb, 'record_verification') else 'ESTABLISHED'   # harness HDEC-017
    want = {('promotion prod', 'record_integrity_state'): integ,
            ('promotion prod', 'promotion_decision_state'): 'OVERRIDDEN',
            ('promotion prod', 'target_identity_state'): 'TARGET_UNKNOWN',
            ('promotion prod', 'history_completeness_state'): 'HISTORY_INCOMPLETE',
            ('promotion uat', 'record_integrity_state'): integ,
            ('promotion uat', 'promotion_decision_state'): 'REFUSED',
            ('promotion uat', 'history_completeness_state'): 'HISTORY_INCOMPLETE',
            ('promotion prod (durable summary)', 'promotion_decision_state'): 'OVERRIDDEN',
            ('promotion prod (durable summary)', 'target_identity_state'): 'TARGET_UNKNOWN'}
    got = dict((k, sp.get(k)) for k in want)
    ok &= check(got == want, 'QE3 F13 the promotion facts are kept apart: integrity ' + integ + ' (never inferred '
                'from present fields, harness HDEC-017), decision '
                'REFUSED / OVERRIDDEN, TARGET_UNKNOWN, HISTORY_INCOMPLETE, record and durable summary (%s)'
                % dict((k[0] + '/' + k[1], v) for k, v in got.items() if v != want[k]))
    # R2 F16: the folder the kit unpacked agrees with its own export on every qualifier (no conflict)
    ok &= check(not ctx.export_conflicts and not any(f[0] == 'KIT_EXPORT_QUALIFIER_CONFLICT' for f in ctx.flags),
                'QE3 F16 the unpacked records agree with the export on every qualifier (conflicts: %s)'
                % sorted(ctx.export_conflicts))
    return ok


# ── R-45 M5 (KDEC-048): the EVALUATED disposition decision is exported, not the register's raw status ──
DAY = '2031-05-20'
DEC_PRED = 'd' * 32       # the predecessor of a carried decision


def _reg_entry(key, scanner, rule, path, expires, state='approved'):
    return {'schema_version': '1', 'fingerprint': key, 'scanner': scanner, 'rule': rule, 'scope_path': path,
            'disposition_type': 'ACCEPTED_RISK', 'evidence_ref': 'RISK-REG-7',
            'rationale': 'the input is a constant list; reviewed by the security lead',
            'approver_role': 'security-lead', 'created': '2031-01-02', 'expires': expires, 'state': state}


DEC_REGISTER = {'f' * 32: _reg_entry('f' * 32, 'bandit', 'B602', 'app/run.py', '2031-12-31'),
                'e' * 32: _reg_entry('e' * 32, 'trivy', 'CVE-2019-20477', 'requirements.txt', '2031-01-01'),
                '0f0f0f0f0f0f': _reg_entry('0f0f0f0f0f0f', 'gitleaks', 'aws-access-token', 'config/settings.py',
                                           '2031-12-31'),
                DEC_PRED: _reg_entry(DEC_PRED, 'bandit', 'B602', 'app/old.py', '2031-12-31')}


def decision_findings(tamper=None):
    """FINDINGS + a carried one, each with the basis and the object the kit's own evaluator produced."""
    import datetime
    import scan_report as sr
    day = datetime.date(*[int(x) for x in DAY.split('-')])
    out = copy.deepcopy(FINDINGS)
    carried = dict(copy.deepcopy(FINDINGS[0]), identity='c' * 32, fp='c1c1c1c1c1c1', canonical_path='app/new.py')
    out.append(carried)
    for f in out:
        g = dict(f, rule=f.get('rule_id'), uri=f.get('canonical_path'))
        if f is carried:
            # the lineage resolver is proven in tests/prove_lineage_consumers.py; here its answer is given
            # (an APPROVED, in-date decision on the predecessor) and the evaluator must still not approve
            saved = sr.disposition_for
            sr.disposition_for = lambda *a, **k: (DEC_REGISTER[DEC_PRED], sr.LINEAGE_CARRIED, 'carried')
            try:
                f['disposition_basis'] = sr.LINEAGE_CARRIED
                f['disposition_decision'] = sr.evaluated_decision(g, DEC_REGISTER, day, register='dispositions.json')
            finally:
                sr.disposition_for = saved
        else:
            f['disposition_basis'] = sr.disposition_for(g, DEC_REGISTER, day)[1]
            f['disposition_decision'] = sr.evaluated_decision(g, DEC_REGISTER, day, register='dispositions.json')
    if tamper:
        tamper(out)
    return out


class DecisionGitHub(FakeGitHub):
    def __init__(self, tamper=None, drop=False):
        FakeGitHub.__init__(self)
        fs = decision_findings(tamper)
        if drop:
            for f in fs:
                f.pop('disposition_decision', None)
        for a in self.arts:
            if a['name'] == 'security-report-1':
                self.blobs[a['id']] = zblob({'findings.json': fs, 'report.md': '# report'})


def decisions_of(doc):
    """-> {identity or fp: the exported disposition_decision, or None}."""
    secs = (doc or {}).get('sections') or {}
    return dict((f.get('identity') or f.get('fp'), f.get('disposition_decision'))
                for f in (secs.get('findings') or {}).get('findings') or [])


def decision_checks(ee, work):
    import scan_report as sr
    print('D the evaluated disposition decision (R-45 M5, KDEC-048): the evaluator\'s, never re-decided')
    doc, ref = make_export(ee, DecisionGitHub())
    d = decisions_of(doc)
    ok = d.get('f' * 32) or {}
    check(ref is None and ok.get('effective_decision') == 'APPROVED_EFFECTIVE' and ok.get('finding_cleared') is False
          and ok.get('evaluated_on') == DAY and ok.get('expires') == '2031-12-31'
          and ok.get('scope') == {'scanner': 'bandit', 'rule': 'B602', 'scope_path': 'app/run.py'}
          and ok.get('source_register') == {'register': 'dispositions.json', 'key': 'f' * 32}
          and ok.get('separation_of_duties') == 'NOT_ESTABLISHED'
          and ok.get('recorded_decision') == {'disposition_type': 'ACCEPTED_RISK', 'state': 'approved',
                                              'recorded_on': 'this_finding'},
          'D1 an approved, in-date direct decision is APPROVED_EFFECTIVE with its scope, expiry, register key and '
          'evaluation date; it never clears the finding; separation of duties NOT_ESTABLISHED (%s)' % ok)
    ex, lc = d.get('e' * 32) or {}, d.get('0f0f0f0f0f0f') or {}
    check(ex.get('effective_decision') == 'NOT_EFFECTIVE' and str(ex.get('reason')).startswith('EXPIRED 2031-01-01')
          and lc.get('effective_decision') == 'NOT_EFFECTIVE' and lc.get('basis') == 'legacy-closed',
          'D2 an expired approval and a legacy key past its window are NOT_EFFECTIVE, the evaluator\'s reason verbatim '
          '(%s / %s)' % (ex.get('reason'), lc.get('basis')))
    ca = d.get('c' * 32) or {}
    check(ca.get('effective_decision') == 'PENDING_REAFFIRMATION' and ca.get('basis') == sr.LINEAGE_CARRIED
          and (ca.get('recorded_decision') or {}).get('state') == 'approved'
          and (ca.get('recorded_decision') or {}).get('recorded_on') == 'predecessor',
          'D3 a carried decision stays PENDING_REAFFIRMATION although its predecessor is approved and in date (%s)'
          % ca.get('effective_decision'))
    doc2, _r = make_export(ee, DecisionGitHub())
    schema = json.load(io.open(os.path.join(ROOT, 'api', 'v1', 'evidence-export.schema.json'), encoding='utf-8'))
    import kit_api as ka
    want = dict((f.get('identity') or f.get('fp'), f.get('disposition_decision')) for f in decision_findings())
    check(json.dumps(doc, sort_keys=True) == json.dumps(doc2, sort_keys=True) and d == want
          and not ka.validate(doc, schema),
          'D4 the export carries the evaluator\'s object verbatim, the same bytes twice, and validates')
    # negatives: a tampered or older report
    def tamper(fs):
        fs[3]['disposition_decision']['effective_decision'] = 'APPROVED_EFFECTIVE'     # carried read as approved
        fs[0]['disposition_decision']['finding_cleared'] = True
        fs[2]['disposition_decision']['approved_by'] = 'someone'                         # outside the allowlist
        fs[1]['disposition_decision']['basis'] = 'durable'                               # not the finding's basis
    t = decisions_of(make_export(ee, DecisionGitHub(tamper))[0])
    check(all((t.get(k) or {}).get('effective_decision') == ee.DECISION_NOT_ESTABLISHED
              for k in ('c' * 32, 'f' * 32, 'e' * 32, '0f0f0f0f0f0f'))
          and 'someone' not in json.dumps(t),
          'DN1 a carried object reading APPROVED_EFFECTIVE, a "cleared" finding, a field outside the allowlist and '
          'a basis mismatch are each exported DECISION_NOT_ESTABLISHED with the reason, never repaired (%s)'
          % dict((k[:6], (v or {}).get('effective_decision')) for k, v in t.items()))
    old = decisions_of(make_export(ee, DecisionGitHub(drop=True))[0])
    check(old and all(v is None for v in old.values()),
          'DN2 a security report that predates the object exports none: the reader keeps "not exported"')
    mutant(ee, 'decision_of', lambda obj, basis: obj,
           lambda: all((decisions_of(make_export(ee, DecisionGitHub(tamper))[0]).get(k) or {}).get(
               'effective_decision') == ee.DECISION_NOT_ESTABLISHED for k in ('c' * 32, 'f' * 32)),
           'M9 the object copied unchecked is caught by DN1')
    mutant(ee, 'decision_of', lambda obj, basis: None,
           lambda: decisions_of(make_export(ee, DecisionGitHub())[0]) == want,
           'M10 the object dropped from the export is caught by D4')
    mutant(sr, 'not_suppressed_because', lambda dd, today=None: '',
           lambda: (decisions_of(make_export(ee, DecisionGitHub())[0]).get('e' * 32) or {}).get(
               'effective_decision') == 'NOT_EFFECTIVE',
           'M11 an evaluator that ignores expiry is caught by D2 (the object follows the evaluator, never a copy of it)')
    mutant(sr, 'DECISION_PENDING_REAFFIRMATION', 'APPROVED_EFFECTIVE',
           lambda: (decisions_of(make_export(ee, DecisionGitHub())[0]).get('c' * 32) or {}).get(
               'effective_decision') == 'PENDING_REAFFIRMATION',
           'M12 a carried decision mapped to APPROVED_EFFECTIVE is caught by D3')
    schema_describes_decision(ee, ka, schema, doc, tamper, make_export(ee, DecisionGitHub(drop=True))[0])
    harness_decision_leg(ee, doc, make_export(ee, DecisionGitHub(tamper))[0], work)


def decision_schema(schema):
    """-> the schema's description of findings[].disposition_decision, or None when it has none."""
    cur = schema
    for k in ('properties', 'sections', 'properties', 'findings', 'properties', 'findings', 'items', 'properties',
              'disposition_decision'):
        cur = cur.get(k) if isinstance(cur, dict) else None
    return cur if isinstance(cur, dict) else None


def malformed_decisions(good):
    """-> [(what, object)]: each a single departure from a well-formed evaluated object."""
    def edit(**over):
        o = copy.deepcopy(good)
        for k, v in over.items():
            if v is KeyError:
                o.pop(k, None)
            else:
                o[k] = v
        return o
    return [('a property outside the eleven', edit(approved_by='someone')),
            ('a value outside the vocabulary', edit(effective_decision='APPROVED')),
            ('a missing required property', edit(reason=KeyError)),
            ('a scope that is not an object', edit(scope='app/run.py')),
            ('a scope with a property of its own', edit(scope=dict(good['scope'], extra='x'))),
            ('an expiry that is not a string', edit(expires=20311231)),
            ('an evaluation date that is not a date', edit(evaluated_on='2031-5-1')),
            ('a finding_cleared that is not a boolean', edit(finding_cleared='no')),
            ('a reason longer than the bound', edit(reason='x' * 301))]


def schema_describes_decision(ee, ka, schema, doc, tamper, older):
    import scan_report as sr
    print('D the export schema DESCRIBES the decision object (R3 closeout C2, KDEC-048 M1)')
    dsch = decision_schema(schema)
    check(dsch is not None and dsch.get('additionalProperties') is False,
          'D5 api/v1/evidence-export.schema.json describes findings[].disposition_decision, closed to other properties')
    good = decisions_of(doc)

    def d5():
        tampered = make_export(ee, DecisionGitHub(tamper))[0]
        ne = decisions_of(tampered)
        return (dsch is not None and len(good) == 4 and len(ne) == 4
                and all(v and len(v) == 11 and not ka.validate(v, dsch) for v in good.values())
                and all(v and len(v) == 6 and v.get('effective_decision') == ee.DECISION_NOT_ESTABLISHED
                        and len(v.get('reason') or '') <= sr.DECISION_REASON_MAX and not ka.validate(v, dsch)
                        for v in ne.values())
                and not ka.validate(doc, schema) and not ka.validate(tampered, schema)
                and not ka.validate(older, schema))
    check(d5(), 'D5 both forms the exporter emits validate (evaluated: eleven properties; DECISION_NOT_ESTABLISHED: '
          'six, its reason bounded), in place in the export; an export without the object still validates')

    def rejected_in_place(sch):
        """-> [what] the schema `sch` did NOT reject, each planted in the first finding of a whole export."""
        missed = []
        for what, obj in malformed_decisions(good['f' * 32]):
            d = copy.deepcopy(doc)
            d['sections']['findings']['findings'][0]['disposition_decision'] = obj
            errs = ka.validate(d, sch)
            if not any('disposition_decision' in p for p, _m in errs):
                missed.append(what)
        return missed
    missed = rejected_in_place(schema)
    check(not missed, 'DN3 a malformed decision object is rejected by the schema, at its own path: %s'
          % (missed or 'all %d departures' % len(malformed_decisions(good['f' * 32]))))

    def mistyped(fs):
        fs[0]['disposition_decision']['expires'] = True
        fs[1]['disposition_decision']['separation_of_duties'] = 7
        fs[2]['disposition_decision']['expires'] = ['2031-12-31']

    def dn4():
        d4 = make_export(ee, DecisionGitHub(mistyped))[0]
        got = decisions_of(d4)
        return (all((got.get(k) or {}).get('effective_decision') == ee.DECISION_NOT_ESTABLISHED
                    and 'not a string or null' in str((got.get(k) or {}).get('reason'))
                    for k in ('f' * 32, 'e' * 32, '0f0f0f0f0f0f'))
                and (got.get('c' * 32) or {}).get('effective_decision') == 'PENDING_REAFFIRMATION'
                and not ka.validate(d4, schema))
    check(dn4(), 'DN4 a text field that is not a string or null in the report is exported DECISION_NOT_ESTABLISHED '
          'with the reason, never passed through; the untouched finding keeps its decision; the export validates')
    loose = copy.deepcopy(schema)
    items = loose['properties']['sections']['properties']['findings']['properties']['findings']['items']
    items['properties'].pop('disposition_decision', None)
    check(len(rejected_in_place(loose)) == len(malformed_decisions(good['f' * 32])) and not ka.validate(doc, loose),
          'M13 the schema without its disposition_decision accepts every malformed object: caught by DN3')
    mutant(ee, 'decision_text_problems', lambda obj: [], dn4,
           'M14 the text-field type check removed from decision_of is caught by DN4')
    mutant(sr, 'DECISION_REASON_MAX', 10 ** 6, d5,
           'M15 an unbounded DECISION_NOT_ESTABLISHED reason (as before this fix) is caught by D5')


def harness_decision_leg(ee, doc, tampered, work):
    src = os.environ.get('evidence_harness_src'.upper(), '').strip()
    if not src or not os.path.isfile(os.path.join(src, 'app_evidence_bundle.py')):
        print('  NOT RUN QE4 the harness reads the evaluated decision: the harness source variable names no '
              'src/app_evidence_bundle.py on this host')
        return None
    sys.path.insert(0, src)
    import app_evidence_bundle as aeb
    import datetime
    if not hasattr(aeb, 'DECISION_STATUS'):
        print('  NOT RUN QE4: this harness predates the evaluated decision (harness HDEC-018)')
        return None
    got = {}
    for name, d in (('d', doc), ('t', tampered)):
        q = os.path.join(work, 'qe4' + name)
        case, kit_fx, tk = os.path.join(q, 'case'), os.path.join(q, 'kit-fx'), os.path.join(q, 'tickets.json')
        aeb._fixture(case, kit_fx, tk)
        kit = os.path.join(q, 'kit-export')
        ee.unpack(d, kit)
        ctx, _out = aeb.build(case, 'orders-api', datetime.date(2031, 5, 20), kit, tk, 'CHG-1', write=False)
        got[name] = ([x['ApprovalStatus'] for x in ctx.exc if x['Source'] == 'kit findings'], ctx)
    vals = sorted(got['d'][0])
    ok = check('APPROVED_EFFECTIVE' in vals and 'DIRECT_DECISION_NOT_EFFECTIVE' in vals and
               'CARRIED_BY_LINEAGE_NOT_AN_APPROVAL' in vals and not got['d'][1].export_conflicts,
               'QE4 the harness reads APPROVED_EFFECTIVE only where the kit\'s evaluator said so, NOT_EFFECTIVE for the '
               'expired and closed keys, and a carried one stays NOT_AN_APPROVAL; the unpacked records agree (%s)' % vals)
    tv = sorted(got['t'][0])
    ok &= check('APPROVED_EFFECTIVE' not in tv and 'DIRECT_DECISION_NOT_ESTABLISHED' in tv,
                'QE4 a tampered object never reads APPROVED_EFFECTIVE in the harness (%s)' % tv)
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
    # External review 2026-11-07 item 4: a listing longer than one page.
    class _Paged(FakeGitHub):
        def __init__(self, second_page_ok):
            FakeGitHub.__init__(self)
            self.second_page_ok = second_page_ok
        def get(self, path):
            if path.startswith('https://') and 'page=2' in path:
                self.calls.append(path)
                if not self.second_page_ok:
                    return 502, None, {}, 'HTTP 502'
                return 200, {'workflow_runs': [{'id': 5999, 'head_sha': 'f' * 40, 'status': 'completed'}],
                             'total_count': 3}, {}, None
            st, doc, h, err = FakeGitHub.get(self, path)
            if path.split('?')[0].endswith('/actions/runs') and isinstance(doc, dict):
                doc = dict(doc, total_count=3)
                h = {'Link': '<https://api.example.test/repos/%s/actions/runs?head_sha=%s&per_page=100&page=2>; rel="next"'
                     % (REPO, SHA)}
            return st, doc, h, err
    pdoc, _ = make_export(ee, _Paged(True))
    check((pdoc['sections'].get('security_record') or {}).get('state') == ee.ESTABLISHED,
          'P6 a second page of runs is read to the end; the record stays ESTABLISHED')
    sdoc, _ = make_export(ee, _Paged(False))
    ssec = sdoc['sections'].get('security_record') or {}
    check(ssec.get('state') == ee.NOT_ESTABLISHED and 'incomplete read' in (ssec.get('why') or '')
          and 'page 2 could not be read' in (ssec.get('why') or ''),
          'N5 a page that fails mid-listing makes the sections it feeds NOT ESTABLISHED, the missing population named')
    check((sdoc['sections'].get('release_records') or {}).get('state') == ee.ESTABLISHED,
          'N5 a short runs listing does not touch the deployments it does not feed')
    def m5():
        d, _ = make_export(ee, _Paged(False))
        return (d['sections'].get('security_record') or {}).get('state') == ee.NOT_ESTABLISHED
    mutant(ee, 'paging_ignored', True, m5, 'M5 reading page one as the whole population is caught')
    qualifier_checks(ee, work)
    decision_checks(ee, work)
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
