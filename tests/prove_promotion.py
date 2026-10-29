#!/usr/bin/env python3
"""Build once, promote the same digest: every promotion refusal, the success path, the parallel
dev+test shape, hotfix and break-glass, prod's passive checks, and the daily deployed scan.
(KDEC-029, owner 2026-10-26, closing O-11.)

WHY THIS EXISTS

    The deploy contract computed `promotion` and could never read "verified" (COMPLETION_LEDGER
    DCR-11, DEPLOYMENT_CONTRACT_RECONCILIATION gap 11): three conditions had no source and nothing
    consumed the answer. KDEC-029 gave every condition a source and added the promotion gate. This
    file proves the gate refuses for each reason, NAMING the reason, before the deploy identity is
    used; that the success path deploys exactly the digest the predecessor verified; and that the
    records dev and test write in parallel are independent, so a dev success never satisfies a test
    or uat predecessor.

HOW
    P  the gate and the preflight as pure functions (scripts/promotion.py judge, preflight_codes)
    J  the deploy JOB as shipped (tests/_workflow_runner.py) against the stub cloud and a recorded
       GitHub API: a build-mode deploy into dev and into test from one digest, then the record test
       wrote is promoted into prod, and each refusal is provoked on that chain. gh (V1), trivy (the
       SBOM re-scan) and the DAST command are stand-ins; the KEV composite's outputs are recorded.
    S  the daily deployed scan: reconcile, artifact drift, security drift, break-glass owed, posture;
       the findings it writes are read by the core report (scan_report --batch) for ticketing.
    T  templates: dev and test in parallel from one build; promote with no build; prod passive; the
       daily scan scheduled; the record matches schemas/promotion-record.schema.json.

    STUBBED, NOT LIVE. A hosted run on the owner's personal tenant is owed (see KDEC-029).

EXIT  0 proven   1 a case decided wrongly   2 could not be checked (UNKNOWN, never PASS)
"""
import datetime
import hashlib
import io
import json
import os
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
import _workflow_runner as W  # noqa: E402
import promotion as PR  # noqa: E402

SIGNER = 'o/secure-cicd-kit/.github/workflows/reusable-build-docker.yml'
SBOM = json.dumps({'spdxVersion': 'SPDX-2.3', 'name': 'web', 'packages': []}).encode('utf-8')
SBOM_SHA = hashlib.sha256(SBOM).hexdigest()
OTHER = 'sha256:' + 'c' * 64
BUILD_RUN = '111'

GH = r'''
import json, sys
a = sys.argv[1:]
ref = [x for x in a if x.startswith('oci://')]
d = ref[0].rsplit('@sha256:', 1)[1] if ref else ''
print(json.dumps([{'verificationResult': {'statement': {'subject': [{'name': 'x', 'digest': {'sha256': d}}]}}}]))
'''
TRIVY = r'''
import json, os, sys
a = sys.argv[1:]
if '--version' in a or (a and a[0] == 'version'):
    print('Version: 0.71.2'); sys.exit(0)
out = a[a.index('--output') + 1]
if a[0] == 'sbom':
    vulns = json.loads(os.environ.get('FAKE_TRIVY_FINDINGS') or '[]')
    json.dump({'Results': [{'Target': 'sbom', 'Vulnerabilities': vulns}]}, open(out, 'w'))
elif a[0] == 'convert':
    doc = json.load(open(a[-1]))
    res = [{'ruleId': v['VulnerabilityID'], 'level': 'error', 'message': {'text': v['VulnerabilityID']},
            'locations': [{'physicalLocation': {'artifactLocation': {'uri': 'pkg/' + v['PkgName']},
                                                'region': {'startLine': 1}}}]}
           for r in doc['Results'] for v in r.get('Vulnerabilities') or []]
    json.dump({'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'Trivy', 'version': '0.71.2'}},
                                             'results': res}]}, open(out, 'w'))
'''
DAST = r'''
import json, os, sys
results = json.loads(os.environ.get('FAKE_DAST_RESULTS') or '[]')
if os.environ.get('FAKE_DAST_NO_REPORT'):
    sys.exit(3)
json.dump({'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'dast'}}, 'results': results}]},
          open(os.environ['PROMOTION_DAST_SARIF'], 'w'))
'''
TOOLS = {'gh': GH, 'trivy': TRIVY, 'fakedast': DAST}
KEV_CLEAR = {'promotion_kev': {'kev_state': 'AVAILABLE', 'kev_verdict': 'CLEAR', 'kev_blocking': ''}}


def now():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)


def meta(digest=W.NEW):
    return json.dumps({'schema': 'deploy-provenance/3', 'image_digest': digest, 'sbom_sha256': SBOM_SHA,
                       'artifact_identity': 'REGISTRY_IDENTITY_PROVEN', 'git_sha': 'f' * 40,
                       'git_ref': 'refs/heads/main', 'run_id': BUILD_RUN})


def ca(envname, tier, **over):
    i = dict(github_environment=envname, routing_result='PROCEED', environment_tier=tier,
             resource_group='rg-a', containerapp_name='web', acr_login_server=W.REG,
             image_repository=W.REPO, image_digest=W.NEW, cloud='commercial', health_path='/health',
             health_retries=1, health_interval_seconds=0, rollback_on_failure=True,
             version_metadata=meta(), attestation_signer_workflow=SIGNER, attestations_available=True,
             artifact_identity='REGISTRY_IDENTITY_PROVEN', e2e_test_command='exit 0',
             e2e_test_period_minutes=0.001, e2e_check_interval_minutes=0, e2e_timeout_minutes=1,
             dast_command='', release_path='normal', promotion_predecessor='test',
             promote_from_run_id='', promote_from_environment='')
    i.update(over)
    return i


def run_env(run_id, extra=None):
    e = {'GITHUB_REF': 'refs/heads/main', 'GITHUB_RUN_ID': run_id, 'GITHUB_RUN_ATTEMPT': '1',
         'GITHUB_SHA': 'f' * 40}
    e.update(extra or {})
    return e


def zipped(name, body):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        zf.writestr(name, body)
    return buf.getvalue()


def world_api(records, sbom=True, revocations=None, approvals=True):
    """-> (api_files, api_binary): artifact listing with the records (each (record, run_id,
    head_branch, created_at)) and the build's SBOM; optional revocation register."""
    arts, binary, files = [], {}, {}
    for n, (rec, run_id, branch, created) in enumerate(records):
        z = 'zips/rec%d.zip' % n
        binary[z] = zipped('promotion-record.json', json.dumps(rec))
        arts.append({'id': 100 + n, 'name': PR.record_key(rec['environment']['name']), 'expired': False,
                     'created_at': created, 'archive_download_url': '@API_ROOT@/' + z,
                     'workflow_run': {'id': int(run_id), 'head_branch': branch}})
    if sbom:
        binary['zips/sbom.zip'] = zipped('sbom.spdx.json', SBOM)
        arts.append({'id': 99, 'name': 'sbom-' + W.NEW.split(':')[1], 'expired': False,
                     'created_at': '2026-10-20T00:00:00Z', 'archive_download_url': '@API_ROOT@/zips/sbom.zip',
                     'workflow_run': {'id': int(BUILD_RUN), 'head_branch': 'main'}})
    files['repos/o/r/actions/artifacts'] = json.dumps({'total_count': len(arts), 'artifacts': arts})
    if revocations is not None:
        files['repos/o/r/contents/.security/promotion-revocations.json'] = json.dumps(
            {'revocations': revocations})
    if approvals:
        for rid in ('201', '202', '301'):
            files['repos/o/r/actions/runs/%s/approvals' % rid] = json.dumps(
                [{'state': 'approved', 'comment': 'ok %s' % W.NEW, 'user': {'login': 'approver-a'},
                  # OF-5 K-1: an independent approval of the environment the run deploys, quoting the
                  # digest (scripts/release_gates.py refuses anything less at uat and prod).
                  'environments': [{'name': 'test'}, {'name': 'prod'}]}])
    return files, binary


def deploy(envname, tier, run_id, inputs=None, api=None, state=None, extra=None, kev=KEV_CLEAR,
           wf=None):
    files, binary = api or world_api([])
    res, final, calls = W.run_world(wf or W.D.CONTAINERAPP, inputs or ca(envname, tier), state or W.containerapp_state(),
                                    api_files=files, api_binary=binary, tools=TOOLS,
                                    env_extra=run_env(run_id, extra), uses_outputs=kev)
    return res, final, calls


def record_of(res):
    r = res['evidence'].get('promotion-record.json')
    return r if isinstance(r, dict) else {}


def az_writes(calls):
    return [c for c in calls if c[0] == 'az' and any(w in ' '.join(c[1:]) for w in
                                                     ('update', 'set', 'activate', 'deactivate', 'swap', 'restart', 'tag'))]


# ----------------------------------------------------------------------------- P: pure
def pure(fails):
    t = PR.parse_ts('2026-10-26T12:00:00Z')
    d1, d2 = 'sha256:' + '1' * 64, 'sha256:' + '2' * 64

    def rec(digest=d1, envname='test', tier='test', state=PR.VERIFIED, at='2026-10-25T12:00:00Z',
            ref='refs/heads/main', branch='main', approver='approver-a'):
        return {'schema': PR.SCHEMA, 'state': state, 'artifact': {'digest': digest},
                'environment': {'name': envname, 'tier': tier},
                'provenance': {'source_ref': ref, 'build_workflow': SIGNER},
                'conditions': {'missing': [] if state == PR.VERIFIED else ['end-to-end test period passed']},
                'validity': {'verified_at': at}, 'run': {'id': '7'},
                'approval': {'approvers': [{'login': approver}]}, '_artifact': {'head_branch': branch}}

    def ctx(**o):
        c = {'digest': d1, 'required_predecessor': 'test', 'source_environment': 'test', 'source': rec(),
             'history': [], 'revocations': [], 'rescan': {'state': 'COMPLETE', 'critical': [], 'high': []},
             'kev': {'state': 'AVAILABLE', 'blocking': []}, 'attestation': 'ATTESTATION_VERIFIED',
             'release_path': 'normal', 'exception': {}, 'now': t}
        c.update(o)
        return c
    exc = {'reason': 'incident 42', 'authority': 'release-approvers', 'exception_ref': 'EXC-9',
           'expires': '2026-10-29'}
    cases = [
        ('success', ctx(), 'PROMOTION_ALLOWED', None),
        ('dev success is not a test predecessor', ctx(source=rec(envname='dev', tier='dev'), source_environment='dev'),
         'PROMOTION_REFUSED_WRONG_PREDECESSOR', 'dev'),
        ('dev record relabelled test', ctx(source=rec(envname='test', tier='dev')),
         'PROMOTION_REFUSED_WRONG_PREDECESSOR', 'tier dev'),
        ('uat required, test given', ctx(required_predecessor='uat'), 'PROMOTION_REFUSED_WRONG_PREDECESSOR', 'uat'),
        ('substituted digest', ctx(digest=d2), 'PROMOTION_REFUSED_DIGEST_MISMATCH', d2),
        ('not verified', ctx(source=rec(state=PR.NOT_VERIFIED)), 'PROMOTION_REFUSED_NOT_VERIFIED', 'end-to-end'),
        ('feature branch', ctx(source=rec(ref='refs/heads/feature/x', branch='feature/x')),
         'PROMOTION_REFUSED_NOT_FROM_MAIN', 'feature/x'),
        ('signature held', ctx(attestation='ATTESTATION_HELD_BY_PLAN'), 'PROMOTION_REFUSED_SIGNATURE', 'HELD'),
        ('signature contradicted', ctx(attestation='ATTESTATION_CONTRADICTED'), 'PROMOTION_REFUSED_SIGNATURE', 'CONTRADICTED'),
        ('kev', ctx(kev={'state': 'AVAILABLE', 'blocking': ['CVE-2026-1@promotion-rescan:x']}),
         'PROMOTION_REFUSED_REVOKED', 'NEW_KNOWN_EXPLOITED'),
        ('critical', ctx(rescan={'state': 'COMPLETE', 'critical': ['CVE-2026-2@openssl:3'], 'high': []}),
         'PROMOTION_REFUSED_REVOKED', 'NEW_CRITICAL_FINDING'),
        ('high', ctx(rescan={'state': 'COMPLETE', 'critical': [], 'high': ['CVE-2026-3@zlib:1']}),
         'PROMOTION_REFUSED_NEW_FINDING', 'CVE-2026-3'),
        ('revoked digest', ctx(revocations=[{'kind': 'digest', 'match': d1, 'reason': 'bad build'}]),
         'PROMOTION_REFUSED_REVOKED', 'DIGEST_REVOKED'),
        ('revoked signer', ctx(revocations=[{'kind': 'signer', 'match': SIGNER, 'reason': 'key compromise'}]),
         'PROMOTION_REFUSED_REVOKED', 'SIGNING_IDENTITY_REVOKED'),
        ('revoked approval', ctx(revocations=[{'kind': 'approval', 'match': 'approver-a', 'reason': 'left'}]),
         'PROMOTION_REFUSED_REVOKED', 'APPROVAL_REVOKED'),
        ('invalidated tests', ctx(revocations=[{'kind': 'test-evidence', 'match': '7', 'reason': 'flaky suite'}]),
         'PROMOTION_REFUSED_REVOKED', 'TEST_EVIDENCE_INVALIDATED'),
        ('recheck incomplete', ctx(kev={'state': 'UNAVAILABLE', 'blocking': []}),
         'PROMOTION_REFUSED_RECHECK_INCOMPLETE', 'KEV UNAVAILABLE'),
        ('sbom missing', ctx(rescan={'state': 'NOT_ESTABLISHED', 'why': 'no SBOM', 'critical': [], 'high': []}),
         'PROMOTION_REFUSED_RECHECK_INCOMPLETE', 'no SBOM'),
        ('stale', ctx(source=rec(at='2026-10-11T11:00:00Z')), 'PROMOTION_REFUSED_STALE', '15 days'),
        ('superseded', ctx(history=[rec(digest=d2, at='2026-10-26T01:00:00Z')]),
         'PROMOTION_REFUSED_SUPERSEDED', d2),
        ('older verified is no supersession', ctx(history=[rec(digest=d2, at='2026-10-20T01:00:00Z')]),
         'PROMOTION_ALLOWED', None),
        ('newer but not verified is no supersession', ctx(history=[rec(digest=d2, state=PR.NOT_VERIFIED,
                                                                        at='2026-10-26T01:00:00Z')]),
         'PROMOTION_ALLOWED', None),
        ('unreadable source', ctx(source=None, source_error='run 9 published no record'),
         'PROMOTION_REFUSED_SOURCE_UNREADABLE', 'run 9'),
        ('rollback decision selects an older build', ctx(source=rec(at='2026-10-01T00:00:00Z'),
                                                         release_path='rollback', exception=exc),
         'PROMOTION_ALLOWED', None),
        ('rollback without attribution stays stale', ctx(source=rec(at='2026-10-01T00:00:00Z'),
                                                         release_path='rollback', exception={}),
         'PROMOTION_REFUSED_STALE', None),
        ('rollback cannot lift supersession', ctx(source=rec(at='2026-10-01T00:00:00Z'), release_path='rollback',
                                                  exception=exc, history=[rec(digest=d2, at='2026-10-05T00:00:00Z')]),
         'PROMOTION_REFUSED_SUPERSEDED', None),
        ('break-glass lifts testing refusals', ctx(source=rec(state=PR.NOT_VERIFIED), release_path='break-glass',
                                                   exception=exc), 'PROMOTION_ALLOWED', None),
        ('break-glass never lifts a revocation', ctx(release_path='break-glass', exception=exc,
                                                     revocations=[{'kind': 'signer', 'match': SIGNER}]),
         'PROMOTION_REFUSED_REVOKED', None),
        ('break-glass never lifts a substitution', ctx(digest=d2, release_path='break-glass', exception=exc),
         'PROMOTION_REFUSED_DIGEST_MISMATCH', None),
    ]
    for label, c, want, phrase in cases:
        res = PR.judge(c)
        why = ' '.join(r['why'] for r in res['refusals'])
        ok = res['verdict'] == want and (phrase is None or phrase in why)
        print('  P  %-44s %s' % (label, res['verdict']))
        if not ok:
            fails.append('P %s: %s (%s), wanted %s naming %r' % (label, res['verdict'], why[:200], want, phrase))
    today = datetime.date(2026, 10, 26)
    pre = [
        ('prod from a build', ('prod', False, 'normal', False, 15, True, {}), 'PROMOTION_REFUSED_NO_PREDECESSOR'),
        ('uat from a build', ('uat', False, 'normal', False, 15, True, {}), 'PROMOTION_REFUSED_NO_PREDECESSOR'),
        ('dast at prod', ('prod', True, 'normal', True, 15, True, {}), 'DAST_REFUSED_PRODUCTION_TARGET'),
        ('dast at uat', ('uat', True, 'normal', True, 15, True, {}), None),
        ('path unknown', ('test', False, 'yolo', False, 15, True, {}), 'PROMOTION_REFUSED_PATH_UNKNOWN'),
        ('break-glass unattributed', ('prod', False, 'break-glass', False, 15, True, {}),
         'BREAK_GLASS_REFUSED_NO_EXCEPTION'),
        ('break-glass expired', ('prod', False, 'break-glass', False, 15, True, dict(exc, expires='2026-10-01')),
         'BREAK_GLASS_REFUSED_EXPIRED'),
        ('break-glass too long', ('prod', False, 'break-glass', False, 15, True, dict(exc, expires='2026-12-31')),
         'BREAK_GLASS_REFUSED_TOO_LONG'),
        ('period 0', ('test', False, 'hotfix', False, 0, True, {}), 'TEST_PERIOD_REFUSED_OUT_OF_BOUNDS'),
        ('period 300', ('test', False, 'normal', False, 300, True, {}), 'TEST_PERIOD_REFUSED_OUT_OF_BOUNDS'),
        ('hotfix 5 minutes', ('test', False, 'hotfix', False, 5, True, {}), None),
        ('prod promoted', ('prod', True, 'normal', False, 15, True, {}), None),
        ('break-glass attributed', ('prod', False, 'break-glass', False, 15, True, exc), None),
    ]
    for label, args, want in pre:
        codes = [c for c, _ in PR.preflight_codes(*(args + (today,)))]
        got = codes[0] if codes else None
        print('  P  preflight %-34s %s' % (label, got or 'passes'))
        if got != want:
            fails.append('P preflight %s: %s, wanted %s' % (label, codes, want))


# ----------------------------------------------------------------------------- J: the job
def job(fails):
    # J1 -- dev and test deploy IN PARALLEL from one build: two independent jobs, one digest.
    recs = {}
    for envname, run_id in (('dev', '201'), ('test', '202')):
        res, _f, _c = deploy(envname, envname, run_id)
        r = record_of(res)
        recs[envname] = r
        print('  J1 build -> %-5s outcome=%s state=%s missing=%s' % (
            envname, r.get('live_state', {}).get('deployment_outcome'), r.get('state'),
            r.get('conditions', {}).get('missing')))
        if r.get('state') != PR.VERIFIED:
            fails.append('J1 %s: a healthy, tested deploy did not read verified-for-promotion (%r; log %s)'
                         % (envname, r.get('conditions'), res['log'][-1500:]))
        if (r.get('environment') or {}).get('name') != envname or (r.get('artifact') or {}).get('digest') != W.NEW:
            fails.append('J1 %s: the record does not name its own environment and the build digest' % envname)
        for k in ('target_resource_id', 'oidc_subject'):
            if not (r.get('environment') or {}).get(k):
                fails.append('J1 %s: the record has no environment %s' % (envname, k))
        if (r.get('approval') or {}).get('state') != 'APPROVED':
            fails.append('J1 %s: approval not recorded (%r)' % (envname, r.get('approval')))
        if not (r.get('live_state') or {}).get('verified_serving'):
            fails.append('J1 %s: the live read-back is not in the record' % envname)
        if (r.get('provenance') or {}).get('source_sha') != 'f' * 40:
            fails.append('J1 %s: the build provenance is not in the record' % envname)
        if 'dynamic scan shows no new blocking finding' not in (r.get('conditions') or {}).get('established', []):
            fails.append('J1 %s: DAST not configured must not block verification' % envname)
        if res['steps'].get('promotion_collect', {}).get('outcome') != 'skipped':
            fails.append('J1 %s: a build-mode deploy ran the promotion gate' % envname)
    if recs.get('dev', {}).get('record_id') == recs.get('test', {}).get('record_id'):
        fails.append('J1: dev and test wrote one record; each environment must be recorded independently')
    test_rec, dev_rec = recs.get('test') or {}, recs.get('dev') or {}
    if not test_rec or not dev_rec:
        fails.append('J: no records to promote; the rest is UNKNOWN')
        return
    created = (now() - datetime.timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')

    def promote(label, source_rec, src_env='test', run='202', branch='main', inputs=None, history=(),
                extra=None, kev=KEV_CLEAR, revocations=None, sbom=True, want=None, phrase=None):
        recs_api = [(source_rec, run, branch, created)] + list(history)
        files, binary = world_api(recs_api, sbom=sbom, revocations=revocations)
        inp = inputs or ca('prod', 'prod', promote_from_run_id=run, promote_from_environment=src_env,
                           e2e_test_command='')
        res, final, calls = deploy('prod', 'prod', '301', inputs=inp, api=(files, binary), extra=extra, kev=kev)
        gate = res['steps'].get('promotion_gate', {}).get('outputs', {}).get('promotion_gate')
        pre = res['steps'].get('promotion_preflight', {}).get('outputs', {}).get('promotion_preflight')
        got = pre if pre and pre != 'PREFLIGHT_PASSED' else gate
        text = res['log'] + res['summary']
        writes = az_writes(calls)
        print('  J2 %-42s gate=%s az-writes=%d' % (label, got, len(writes)))
        if want == 'PROMOTION_ALLOWED':
            if got != 'PROMOTION_ALLOWED' or res['failed']:
                fails.append('J2 %s: %s, failed=%s\n%s' % (label, got, res['failed'], res['log'][-2500:]))
        else:
            if got != want or writes or not res['failed']:
                fails.append('J2 %s: %s with %d mutation(s), failed=%s; wanted %s refused before login'
                             % (label, got, len(writes), res['failed'], want))
            if phrase and phrase not in text:
                fails.append('J2 %s: the refusal does not name its reason (%r)' % (label, phrase))
        return res, final

    res, final = promote('success: test -> prod, same digest', test_rec, want='PROMOTION_ALLOWED')
    r = record_of(res)
    serving = [t for t in final['containerapp']['traffic'] if t.get('weight')]
    if (r.get('predecessor') or {}).get('gate') != 'PROMOTION_ALLOWED' or \
            ((r.get('predecessor') or {}).get('promoted_from') or {}).get('run_id') != '202':
        fails.append('J2 success: the prod record does not name what it was promoted from (%r)' % r.get('predecessor'))
    if ((r.get('tests') or {}).get('e2e_test_period') or {}).get('result') != 'NOT_APPLICABLE_PASSIVE' or \
            ((r.get('tests') or {}).get('dast') or {}).get('result') != 'NOT_APPLICABLE_PASSIVE':
        fails.append('J2 success: prod ran an active check (%r)' % (r.get('tests'),))
    if ((r.get('tests') or {}).get('security_settings') or {}).get('result') != 'POSTURE_PASSED':
        fails.append('J2 success: prod did not run its passive posture check')
    if (r.get('provenance') or {}).get('build_run_id') != BUILD_RUN:
        fails.append('J2 success: the build provenance was not carried from the predecessor record')
    if not serving or final['containerapp']['revisions'][final['containerapp']['latestRevisionName']]['image'] != W.ref(W.NEW):
        fails.append('J2 success: prod does not serve the promoted digest')

    promote('dev success never satisfies test', dev_rec, src_env='dev', run='201',
            inputs=ca('prod', 'prod', promote_from_run_id='201', promote_from_environment='dev',
                      e2e_test_command=''), want='PROMOTION_REFUSED_WRONG_PREDECESSOR', phrase='dev')
    promote('substituted digest', test_rec,
            inputs=ca('prod', 'prod', promote_from_run_id='202', promote_from_environment='test',
                      e2e_test_command='', image_digest=OTHER, version_metadata=meta(OTHER)),
            want='PROMOTION_REFUSED_DIGEST_MISMATCH', phrase=OTHER)
    unverified = dict(test_rec, state=PR.NOT_VERIFIED,
                      conditions={'established': [], 'missing': ['end-to-end test period passed']})
    promote('not verified in the predecessor', unverified, want='PROMOTION_REFUSED_NOT_VERIFIED',
            phrase='end-to-end test period passed')
    promote('built on a feature branch', dict(test_rec, provenance=dict(test_rec['provenance'],
                                                                        source_ref='refs/heads/feature/x')),
            branch='feature/x', want='PROMOTION_REFUSED_NOT_FROM_MAIN', phrase='feature/x')
    old = (now() - datetime.timedelta(days=15)).strftime('%Y-%m-%dT%H:%M:%SZ')
    promote('stale (15 days)', dict(test_rec, validity=dict(test_rec['validity'], verified_at=old)),
            want='PROMOTION_REFUSED_STALE', phrase='maximum is 14')
    newer = json.loads(json.dumps(test_rec))
    newer['artifact']['digest'] = OTHER
    newer['validity']['verified_at'] = now().strftime('%Y-%m-%dT%H:%M:%SZ')
    newer['run']['id'] = '250'
    older = dict(test_rec, validity=dict(test_rec['validity'],
                                         verified_at=(now() - datetime.timedelta(days=2)).strftime('%Y-%m-%dT%H:%M:%SZ')))
    promote('superseded by a newer verified build', older, history=[(newer, '250', 'main', created)],
            want='PROMOTION_REFUSED_SUPERSEDED', phrase=OTHER)
    promote('KEV re-check finds a known-exploited CVE', test_rec,
            kev={'promotion_kev': {'kev_state': 'AVAILABLE', 'kev_verdict': 'BLOCKED',
                                   'kev_blocking': 'CVE-2026-9999@promotion-rescan:ab12'}},
            extra={'FAKE_TRIVY_FINDINGS': json.dumps([{'VulnerabilityID': 'CVE-2026-9999', 'PkgName': 'openssl',
                                                       'InstalledVersion': '3.0', 'Severity': 'HIGH'}])},
            want='PROMOTION_REFUSED_REVOKED', phrase='NEW_KNOWN_EXPLOITED')
    promote('new HIGH finding since the build', test_rec,
            extra={'FAKE_TRIVY_FINDINGS': json.dumps([{'VulnerabilityID': 'CVE-2026-1234', 'PkgName': 'zlib',
                                                       'InstalledVersion': '1.2', 'Severity': 'HIGH'}])},
            want='PROMOTION_REFUSED_NEW_FINDING', phrase='CVE-2026-1234')
    promote('revoked signing identity', test_rec,
            revocations=[{'kind': 'signer', 'match': SIGNER, 'reason': 'signing key rotated after compromise',
                          'revoked_by': 'security', 'revoked_at': '2026-10-26'}],
            want='PROMOTION_REFUSED_REVOKED', phrase='SIGNING_IDENTITY_REVOKED')
    promote('KEV feed unavailable', test_rec, kev={'promotion_kev': {'kev_state': 'UNAVAILABLE'}},
            want='PROMOTION_REFUSED_RECHECK_INCOMPLETE', phrase='KEV UNAVAILABLE')
    promote('SBOM expired', test_rec, sbom=False, want='PROMOTION_REFUSED_RECHECK_INCOMPLETE', phrase='SBOM')
    promote('prod from a build (no predecessor)', test_rec,
            inputs=ca('prod', 'prod', e2e_test_command=''), want='PROMOTION_REFUSED_NO_PREDECESSOR')
    promote('active DAST against prod', test_rec,
            inputs=ca('prod', 'prod', promote_from_run_id='202', promote_from_environment='test',
                      e2e_test_command='', dast_command='fakedast'),
            want='DAST_REFUSED_PRODUCTION_TARGET', phrase='DAST_REFUSED_PRODUCTION_TARGET')

    # J3 -- what "tested" means, each half failing on its own.
    st = W.containerapp_state()
    st['containerapp']['allowInsecure'] = True
    for label, inp, state, extra, want_missing in (
            ('e2e fails', ca('test', 'test', e2e_test_command='exit 3'), None, None, 'end-to-end test period passed'),
            ('no e2e command', ca('test', 'test', e2e_test_command=''), None, None, 'end-to-end test period passed'),
            ('insecure ingress', ca('test', 'test'), st, None, 'security-settings posture passed'),
            ('DAST blocking result', ca('test', 'test', dast_command='fakedast'), None,
             {'FAKE_DAST_RESULTS': json.dumps([{'ruleId': '40018', 'level': 'error',
                                                'message': {'text': 'SQL Injection'}}])},
             'dynamic scan shows no new blocking finding'),
            ('DAST left no report', ca('test', 'test', dast_command='fakedast'), None,
             {'FAKE_DAST_NO_REPORT': '1'}, 'dynamic scan shows no new blocking finding'),
            ('identity not proven', ca('test', 'test', artifact_identity='IDENTITY_UNVERIFIED',
                                       version_metadata=''), None, None, 'exact artefact identity established')):
        res, _f, _c = deploy('test', 'test', '202', inputs=inp, state=state, extra=extra)
        r = record_of(res)
        print('  J3 %-22s state=%s' % (label, r.get('state')))
        dres = ((r.get('tests') or {}).get('dast') or {}).get('result')
        want_dast = {'DAST blocking result': 'DAST_BLOCKING_FINDINGS', 'DAST left no report': 'DAST_INCOMPLETE'}.get(label)
        if want_dast and dres != want_dast:
            fails.append('J3 %s: DAST read %s, wanted %s' % (label, dres, want_dast))
        if r.get('state') != PR.NOT_VERIFIED or want_missing not in (r.get('conditions') or {}).get('missing', []):
            fails.append('J3 %s: the record should be not-verified with %r missing (%r)' % (
                label, want_missing, r.get('conditions')))
    res, _f, _c = deploy('test', 'test', '202', inputs=ca('test', 'test', dast_command='fakedast'),
                         extra={'FAKE_DAST_RESULTS': json.dumps([
                             {'ruleId': '10038', 'level': 'warning', 'message': {'text': 'CSP header'}},
                             {'ruleId': '40012', 'level': 'error', 'message': {'text': 'accepted XSS'},
                              'suppressions': [{'kind': 'external', 'status': 'accepted'}]}])})
    r = record_of(res)
    print('  J3 %-22s state=%s dast=%s' % ('DAST warning/accepted', r.get('state'),
                                          ((r.get('tests') or {}).get('dast') or {}).get('result')))
    if r.get('state') != PR.VERIFIED or ((r.get('tests') or {}).get('dast') or {}).get('result') != 'DAST_PASSED':
        fails.append('J3 DAST warning/accepted: a non-blocking or accepted result stopped verification')

    # J4 -- hotfix: the same path, compressed, recorded.
    res, _f, _c = deploy('test', 'test', '202', inputs=ca('test', 'test', release_path='hotfix',
                                                         e2e_test_period_minutes=0.001))
    tp = ((record_of(res).get('tests') or {}).get('e2e_test_period') or {})
    print('  J4 hotfix              state=%s compressed=%s' % (record_of(res).get('state'), tp.get('compressed')))
    if record_of(res).get('release_path') != 'hotfix' or 'hotfix' not in str(tp.get('compressed')):
        fails.append('J4 hotfix: the compressed test period is not recorded as a hotfix (%r)' % tp)

    # J5 -- break-glass: proceeds, records BREAK_GLASS, testing owed.
    res, final, _c = deploy('prod', 'prod', '301', inputs=W.break_glass(ca('prod', 'prod', e2e_test_command='')))
    r = record_of(res)
    print('  J5 break-glass         state=%s owed=%s' % (r.get('state'), (r.get('break_glass') or {}).get('testing_owed')))
    if r.get('state') != PR.BREAK_GLASS or not (r.get('break_glass') or {}).get('testing_owed') or \
            (r.get('break_glass') or {}).get('exception', {}).get('exception_ref') != 'EXC-PROOF-1':
        fails.append('J5 break-glass: not recorded BREAK_GLASS with the exception and the testing owed (%r)'
                     % r.get('break_glass'))
    J_RECORDS.extend([test_rec, r])


J_RECORDS = []


# ----------------------------------------------------------------------------- S: daily scan
def daily(fails):
    import subprocess
    if len(J_RECORDS) < 2:
        fails.append('S: no records from J to scan against')
        return
    test_rec, bg = J_RECORDS
    prod_rec = json.loads(json.dumps(test_rec))
    prod_rec['environment'] = dict(prod_rec['environment'], name='prod', tier='prod')
    work = tempfile.mkdtemp(prefix='deployed-scan-')
    try:
        for label, rec, serving_digest, findings, insecure, want_rules in (
                ('reconciled, no drift', prod_rec, W.NEW, [], False, []),
                # The drifted digest has no SBOM on record: it is reported, never scanned as if it were the
                # promoted one, and never rebuilt.
                ('artifact drift', prod_rec, OTHER, [], False, ['KIT-ARTIFACT-DRIFT', 'KIT-RESCAN-NOT-ESTABLISHED']),
                ('security drift', prod_rec, W.NEW, [{'VulnerabilityID': 'CVE-2026-7777', 'PkgName': 'openssl',
                                                      'InstalledVersion': '3.0', 'Severity': 'CRITICAL'}], False, []),
                ('posture drift', prod_rec, W.NEW, [], True, ['KIT-SECURITY-SETTINGS']),
                ('break-glass owed', dict(bg, environment=dict(bg['environment'], name='prod')), W.NEW, [], False,
                 ['KIT-BREAK-GLASS-TESTING-OWED'])):
            d = tempfile.mkdtemp(dir=work)
            files, binary = world_api([(rec, '301', 'main', '2026-10-26T00:00:00Z')])
            api = os.path.join(d, 'api')
            for rel, body in list(files.items()) + [(k, v) for k, v in binary.items()]:
                p = os.path.join(api, *rel.split('/'))
                os.makedirs(os.path.dirname(p), exist_ok=True)
                url = 'file:///' + api.replace('\\', '/').lstrip('/')
                io.open(p, 'wb').write(body if isinstance(body, bytes) else body.replace('@API_ROOT@', url).encode('utf-8'))
            st = W.containerapp_state()
            st['containerapp']['revisions']['web--r1']['image'] = W.ref(serving_digest)
            st['containerapp']['allowInsecure'] = insecure
            state_path, log_path = os.path.join(d, 's.json'), os.path.join(d, 'c.jsonl')
            io.open(state_path, 'w').write(json.dumps(st))
            io.open(log_path, 'w').close()
            bin_dir = W.stub_bin(state_path, log_path)
            W.add_tools(bin_dir, TOOLS)
            rt = os.path.join(d, 'rt')
            os.makedirs(rt)
            env = dict(os.environ, PATH=bin_dir + os.pathsep + os.environ.get('PATH', ''), RUNNER_TEMP=rt,
                       fake_az_state=state_path, fake_az_log=log_path, GITHUB_REPOSITORY='o/r',
                       GITHUB_API_URL='file:///' + api.replace('\\', '/').lstrip('/'),
                       DEPLOY_ENVIRONMENT='prod', CONTAINERAPP_NAME='web', RESOURCE_GROUP='rg-a',
                       FAKE_TRIVY_FINDINGS=json.dumps(findings), AZURE_CONFIG_DIR=os.path.join(d, 'noaz'),
                       GITHUB_OUTPUT=os.path.join(d, 'out.txt'))
            p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'promotion.py'), 'deployed-scan',
                                '--adapter', 'containerapp'], env=env, capture_output=True, text=True,
                               encoding='utf-8', errors='replace')
            if p.returncode == 0:
                # Phase 2: the KEV composite's answer (recorded here) joins the state findings.
                env2 = dict(env, KEV_STATE='AVAILABLE', KEV_BLOCKING='')
                p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'promotion.py'),
                                    'deployed-finish', '--adapter', 'containerapp'], env=env2,
                                   capture_output=True, text=True, encoding='utf-8', errors='replace')
            doc = PR.jload(os.path.join(rt, 'promotion', 'deployed', 'deployed-scan-prod.json')) or {}
            sar = PR.jload(os.path.join(rt, 'promotion', 'deployed', 'deployed-state-prod.sarif')) or {}
            rules = sorted(set(r['ruleId'] for r in (sar.get('runs') or [{}])[0].get('results') or []))
            calls = [json.loads(l) for l in io.open(log_path) if l.strip()]
            print('  S  %-22s artifact_drift=%s security_drift=%s rules=%s' % (
                label, doc.get('artifact_drift'), doc.get('security_drift'), rules))
            if p.returncode != 0 or not doc:
                fails.append('S %s: the scan failed (%s)' % (label, (p.stdout + p.stderr)[-1500:]))
            if rules != want_rules:
                fails.append('S %s: state findings %s, wanted %s' % (label, rules, want_rules))
            if label == 'artifact drift' and doc.get('artifact_drift') is not True:
                fails.append('S artifact drift: not reported as artifact drift')
            if label == 'security drift' and (doc.get('security_drift') is not True or doc.get('artifact_drift')):
                fails.append('S security drift: not reported separately from artifact drift (%r)' % doc)
            if not doc.get('serving') or doc['serving'][0].get('weight') != 100:
                fails.append('S %s: the serving revision and its weight were not reconciled' % label)
            if az_writes(calls):
                fails.append('S %s: the daily scan wrote to the target (%r) -- it never rolls back' % (
                    label, az_writes(calls)))
            if label == 'security drift':
                # The core report reads the rows, so the reconcile path can ticket them.
                ddir = os.path.join(rt, 'promotion', 'deployed')
                q = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'promotion.py'), 'deployed-report',
                                    '--state-dir', ddir], env=dict(env, GITHUB_STEP_SUMMARY=''),
                                   capture_output=True, text=True, encoding='utf-8', errors='replace')
                f = PR.jload(os.path.join(ddir, 'findings.json'))
                n = len(f) if isinstance(f, list) else len((f or {}).get('findings') or []) if isinstance(f, dict) else 0
                print('  S  findings.json for the reconcile path: %d record(s) (rc %d)' % (n, q.returncode))
                if not n:
                    fails.append('S security drift: scan_report produced no findings for ticketing (%s)'
                                 % (q.stdout + q.stderr)[-600:])
            import shutil
            shutil.rmtree(bin_dir, ignore_errors=True)
    finally:
        import shutil
        shutil.rmtree(work, ignore_errors=True)


# ----------------------------------------------------------------------------- T: templates, schema
def templates(fails):
    import yaml
    t = yaml.safe_load(io.open(os.path.join(ROOT, 'templates', 'build-deploy.yml'), encoding='utf-8'))
    jobs = t.get('jobs') or {}
    dev, test = jobs.get('deploy-dev') or {}, jobs.get('deploy-test') or {}
    for name, j in (('deploy-dev', dev), ('deploy-test', test)):
        needs = j.get('needs') or []
        if 'build' not in needs or any(n.startswith('deploy-') for n in needs):
            fails.append('T %s: must need the build and no other deploy (parallel), got %r' % (name, needs))
        w = j.get('with') or {}
        if 'needs.build.outputs.image_digest' not in str(w.get('image_digest')):
            fails.append('T %s: does not deploy the build digest' % name)
        if j.get('with', {}).get('github_environment') != name.split('-')[1]:
            fails.append('T %s: environment %r' % (name, j.get('with', {}).get('github_environment')))
    prom = jobs.get('promote') or {}
    if 'build' in str(prom.get('needs')) or 'promote_from_run_id' not in (prom.get('with') or {}):
        fails.append('T promote: must not need a build and must pass promote_from_run_id')
    dast = str((prom.get('with') or {}).get('dast_command') or '')
    if "inputs.environment != 'prod'" not in dast or not dast.rstrip(' }').endswith("''"):
        fails.append('T promote: DAST is not held to none at prod (%r)' % dast)
    if 'promotion_predecessor' not in (prom.get('with') or {}):
        fails.append('T promote: the product\'s predecessor policy is not passed')
    s = yaml.safe_load(io.open(os.path.join(ROOT, 'templates', 'deployed-scan.yml'), encoding='utf-8'))
    on = s.get('on', s.get(True)) or {}
    if not (on.get('schedule') and on['schedule'][0].get('cron')):
        fails.append('T deployed-scan: not scheduled')
    rw = yaml.safe_load(io.open(os.path.join(ROOT, '.github', 'workflows', 'reusable-deployed-scan.yml'),
                                encoding='utf-8'))
    perms = json.dumps(rw.get('permissions') or {})
    if 'id-token' in perms:
        fails.append('T reusable-deployed-scan: id-token granted workflow-wide')
    print('  T  templates: dev+test parallel, promote without a build, daily scan scheduled')
    try:
        import jsonschema
    except ImportError:
        print('  T  schema: UNKNOWN (jsonschema not installed)')
        return
    schema = json.load(io.open(os.path.join(ROOT, 'schemas', 'promotion-record.schema.json'), encoding='utf-8'))
    for r in J_RECORDS:
        try:
            jsonschema.validate({k: v for k, v in r.items() if not k.startswith('_')}, schema)
        except jsonschema.ValidationError as exc:
            fails.append('T schema: a record the job wrote does not validate: %s' % exc.message)
    print('  T  schema: %d record(s) validate' % len(J_RECORDS))


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    if not W.D.bash()[0]:
        print('UNKNOWN: no usable bash.')
        return 2
    fails = []
    for fn in (pure, job, daily, templates):
        try:
            fn(fails)
        except Exception as exc:  # noqa: BLE001 -- a crashed section is a failure, never a pass
            import traceback
            fails.append('%s crashed: %s\n%s' % (fn.__name__, exc, traceback.format_exc()[-1500:]))
    if fails:
        for f in fails:
            print('FAIL: ' + f)
        return 1
    print('PASS: every promotion refusal names its reason before login; the success path deploys the')
    print('      digest the predecessor verified; dev and test record independently and a dev success')
    print('      never satisfies a predecessor; prod is passive; break-glass and hotfix are recorded;')
    print('      the daily scan reconciles, reports artifact and security drift apart, never mutates.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
