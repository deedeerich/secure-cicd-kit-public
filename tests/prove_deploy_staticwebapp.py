#!/usr/bin/env python3
"""A static site is released like any kit target: one artefact by digest, staged before it serves,
verified by reading back what serves, reversed when it fails, refused before login when it should be.
(OF-5 K-8; the LZ-vs-kit deployment review; KDEC-034 PROPOSED)

WHY THIS EXISTS

    The owner approved Azure Static Web Apps for Phase 1 (G13). Until now the kit had no adapter for it:
    the landing zone reported "target vended, release pending" (its no-kit-adapter report) and a
    static site could only be deployed around the kit -- with GitHub's own SWA workflow, by a token in a
    repository secret, with no verdict, no digest, no read-back and no way back. This proves the adapter
    the kit now ships:

      .github/actions/static-site-package   writes kit-release.json (the TREE digest of every other file,
                                            and the build's provenance) into the built site, uploads it
                                            as `kit-static-site-<hex>` and its SBOM as `sbom-<hex>`
      reusable-deploy-staticwebapp.yml      the deploy, step for step the contract of the other two
      scripts/static_site_contract.py       the SWA-specific steps

THE RULE A DIGEST HAS HERE (an independent oracle below, not the script's own code)

    sha256 over the lines "<posix relative path>\\0<sha256 hex of the file>\\n", sorted by path, for every
    file of the site except the root's kit-release.json. A site with the same files has the same digest
    whatever the build machine; one changed byte, a renamed or an added file changes it.

CASES (docs/PROOF_RULE.md), the reusable run AS SHIPPED (tests/_workflow_runner.py) against the stub
cloud (tests/_fake_az.py's staticwebapp slice), a `swa` CLI stand-in, curl serving each environment's
marker, and a recorded GitHub API holding the artefacts:

    P1  packaging writes the marker, and its digest is the oracle's; a changed file changes it
    J1  allowed: dev, prior release standing -> preview deployed and verified, then production; NOW
        SERVING read from the live marker; provenance tags written after health; DEPLOY_HEALTHY;
        the deployment token never appears in a log, summary, output or evidence file (only in the
        ::add-mask:: command that hides it)
    J2  attack: the artefact's files do not hash to the digest being released -> refused before login
        (SITE_DIGEST_MISMATCH), zero az and swa calls
    J3  attack: preview '' at uat -> refused before login, zero az calls
    J4  unhealthy preview -> production never touched, the preview environment removed,
        ROLLBACK_VERIFIED
    J5  unhealthy production -> the prior release's artefact redeployed and verified on the live
        marker, ROLLBACK_VERIFIED
    J6  missing-evidence: the prior artefact has expired -> rollback_capability UNAVAILABLE: recorded
        at dev (the deploy proceeds), refused at prod before any mutation
    J7  missing-evidence: production serves content with no kit marker -> previous_state UNKNOWN,
        refused before any mutation
    J8  a site never deployed -> previous_state EMPTY, NO_PRIOR_STATE, the first release proceeds
    J9  the landing zone's stop reaches it: KIT_RELEASE_BLOCK platform_halted -> refused before login
    S1  the shared steps (bind, zone, protection, verdict, approval) are byte-identical to the other
        deploy reusables', in the same order before login; the scripts are materialised and in sync
    J11 the seam (KDEC-030 R3, OF-5 K-6; parity with the container deploys, integrate/r8): with the lease
        on, KIT_SETTING_KEYS naming a production app setting that is a Key Vault reference (secret-backed:
        the landing zone's) -> SEAM_SETTING_OWNERSHIP_CONFLICT before the first mutation, zero swa calls,
        the value never shown, posture BLOCKED; the settings unreadable -> SEAM_OWNERSHIP_NOT_ESTABLISHED,
        zero swa calls; a plain kit key -> SEAM_OWNERSHIP_HELD (control); the lease off -> no seam step
    J12 the edge purge (KDEC-030 D-4, OF-5 K-7; parity): a verified release with KIT_EDGE_ENDPOINT vended
        purges exactly that endpoint once, after the provenance stamp (EDGE_PURGED); an unhealthy
        production purges nothing; none vended -> EDGE_PURGE_NOT_APPLICABLE, no call; not an endpoint id
        -> EDGE_PURGE_REFUSED, no call; a failed purge -> EDGE_PURGE_FAILED, the release still
        DEPLOY_HEALTHY, routed PROCEED_WITH_ADVISORY and named in the posture record

EXIT 0 proven   1 a case failed   2 could not be checked (UNKNOWN, never PASS)
"""
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
import _workflow_runner as W  # noqa: E402

WF = os.path.join(ROOT, '.github', 'workflows', 'reusable-deploy-staticwebapp.yml')
CA = os.path.join(ROOT, '.github', 'workflows', 'reusable-deploy-containerapp.yml')
CONTRACT = os.path.join(ROOT, 'scripts', 'static_site_contract.py')
TOKEN = 'SWA-DEPLOY-TOKEN-' + 'q7' * 12
FAILS = []
SWA_TOOL = r'''
import io, json, os, sys
st = os.environ['fake_az_state']
s = json.load(io.open(st, encoding='utf-8'))
a = sys.argv[1:]
io.open(os.environ['fake_az_log'], 'a', encoding='utf-8').write(json.dumps(['swa'] + a) + '\n')
if a[:1] == ['--version']:
    print('2.0.2'); sys.exit(0)
if a[:1] != ['deploy']:
    print('unmodelled swa command'); sys.exit(2)
env = a[a.index('--env') + 1]
if os.environ.get('SWA_CLI_DEPLOYMENT_TOKEN') != s['staticwebapp']['apiKey']:
    print('The deployment token is invalid.'); sys.exit(1)
if env in (s.get('swa_fail') or []):
    print('deployment failed'); sys.exit(1)
marker = json.load(io.open(os.path.join(a[1], 'kit-release.json'), encoding='utf-8'))
name = 'default' if env == 'production' else env
s['staticwebapp']['environments'][name] = {'status': 'Ready', 'marker': marker}
s['mutated'] = True
io.open(st, 'w', encoding='utf-8').write(json.dumps(s, indent=1))
print('Project deployed to https://example')
'''


def expect(cond, label):
    print('%s  %s' % ('ok  ' if cond else 'FAIL', label))
    if not cond:
        FAILS.append(label)


def oracle(files):
    """The documented tree digest, computed independently of the shipped script."""
    lines = ''.join('%s\0%s\n' % (p, hashlib.sha256(b).hexdigest()) for p, b in sorted(files.items())
                    if p != 'kit-release.json')
    return 'sha256:' + hashlib.sha256(lines.encode('utf-8')).hexdigest()


def site(version):
    files = {'index.html': ('<html><body>shop %s</body></html>' % version).encode('utf-8'),
             'assets/app.%s.js' % version: ('console.log(%r)' % version).encode('utf-8'),
             'health': b'ok'}
    d = oracle(files)
    files['kit-release.json'] = json.dumps({'schema': 'kit-static-site/1', 'tree_digest': d,
                                            'repository': 'o/r', 'run_id': '4242'}).encode('utf-8')
    return d, files


def zipped(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        for p, b in sorted(files.items()):
            zf.writestr(p, b)
    return buf.getvalue()


_prior = site('v1')
_new = site('v2')
PRIOR_D = _prior[0]
PRIOR = _prior[1]
NEW_D = _new[0]
NEW = _new[1]
SIGNER = W.PROMOTION_SIGNER


def world(prior_artifact=True, new_files=None, extra_arts=()):
    arts, binary = [], {}

    def add(n, digest, files, run):
        binary['zips/site%d.zip' % n] = zipped(files)
        arts.append({'id': 500 + n, 'name': 'kit-static-site-' + digest.split(':', 1)[1], 'expired': False,
                     'created_at': '2026-10-28T00:00:%02dZ' % n, 'archive_download_url': '@API_ROOT@/zips/site%d.zip' % n,
                     'workflow_run': {'id': int(run), 'head_branch': 'main'}})
    add(1, NEW_D, new_files or NEW, '4242')
    if prior_artifact:
        add(2, PRIOR_D, PRIOR, '4100')
    for a in extra_arts:
        arts.append(a)
    # K-1: an independent reviewer's approval of the run's environment, quoting the site digest.
    approvals = [{'state': 'approved', 'user': {'login': 'independent-reviewer'}, 'comment': 'approve %s' % NEW_D,
                  'environments': [{'name': n} for n in ('dev', 'uat-env', 'prod-env')]}]
    return {'repos/o/r/actions/artifacts': json.dumps({'total_count': len(arts), 'artifacts': arts}),
            'repos/o/r/actions/runs/4242/approvals': json.dumps(approvals)}, binary


def state(prior='kit', **faults):
    envs = {}
    if prior == 'kit':
        envs['default'] = {'status': 'Ready', 'marker': json.loads(PRIOR['kit-release.json'])}
    elif prior == 'nonkit':
        envs['default'] = {'status': 'Ready', 'marker': None, 'nonkit': True}
    s = {'staticwebapp': {'name': 'site', 'id': '/subscriptions/0/resourceGroups/rg-a/providers/Microsoft.Web/staticSites/site',
                          'host': 'site.azurestaticapps.example', 'tags': {}, 'sku': 'Standard',
                          'repositoryUrl': None, 'apiKey': TOKEN, 'environments': envs}}
    s.update(faults)
    return s


def inputs(envname='dev', tier='dev', **over):
    i = dict(github_environment=envname, routing_result='PROCEED', environment_tier=tier,
             resource_group='rg-a', site_name='site', site_digest=NEW_D, artifact_run_id='',
             cloud='commercial', preview_environment='staging', health_path='/health', health_retries=1,
             health_interval_seconds=0, rollback_on_failure=True, version_metadata='{"git_sha": "f"}',
             attestation_signer_workflow='', attestations_available=False, e2e_test_command='exit 0',
             e2e_test_period_minutes=0.001, e2e_check_interval_minutes=0, e2e_timeout_minutes=1,
             dast_command='', release_path='normal', promotion_predecessor='test', promote_from_run_id='',
             promote_from_environment='')
    i.update(over)
    return i


def run(inp, st, prior_artifact=True, new_files=None, env_extra=None, extra_arts=(), binary_extra=None,
        tools=None, uses_outputs=None):
    files, binary = world(prior_artifact, new_files, extra_arts)
    binary.update(binary_extra or {})
    return W.run_world(WF, inp, st, api_files=files, api_binary=binary, tools=dict({'swa': SWA_TOOL}, **(tools or {})),
                       uses_outputs=uses_outputs,
                       env_extra=dict({'GITHUB_REF': 'refs/heads/main', 'GITHUB_SHA': 'f' * 40}, **(env_extra or {})))


# V1 for a static site: gh verifies the MARKER FILE; this stand-in answers a statement naming the
# file's sha256, as gh does for a verified local artefact.
GH_FILE_VERIFIED = r'''
import hashlib, json, sys
f = [x for x in sys.argv[1:] if x.endswith('kit-release.json')]
d = hashlib.sha256(open(f[0], 'rb').read()).hexdigest() if f else ''
print(json.dumps([{'verificationResult': {'statement': {'subject': [{'name': 'kit-release.json', 'digest': {'sha256': d}}]}}}]))
'''


def promotion_world(verified_in='test', run_id='90', sbom=True):
    """A test record that verified NEW_D, and the site's SBOM: what a prod promotion reads."""
    import datetime
    at = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
    body = b'{"spdxVersion": "SPDX-2.3", "packages": []}'
    rec = {'schema': 'kit-promotion-record/1', 'record_id': '%s-1-%s' % (run_id, verified_in),
           'state': 'verified-for-promotion',
           'artifact': {'digest': NEW_D, 'sbom_sha256': hashlib.sha256(body).hexdigest()},
           'environment': {'name': verified_in, 'tier': 'test', 'adapter': 'staticwebapp'},
           'provenance': {'source_ref': 'refs/heads/main', 'build_workflow': SIGNER, 'build_run_id': run_id},
           'conditions': {'established': [], 'missing': []}, 'validity': {'verified_at': at},
           'run': {'id': run_id}, 'approval': {'approvers': []}}

    def z(name, b):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as zf:
            zf.writestr(name, b)
        return buf.getvalue()
    arts = [{'id': 801, 'name': 'kit-promotion-record-%s' % verified_in, 'expired': False, 'created_at': at,
             'archive_download_url': '@API_ROOT@/zips/rec.zip', 'workflow_run': {'id': int(run_id), 'head_branch': 'main'}}]
    binary = {'zips/rec.zip': z('promotion-record.json', json.dumps(rec))}
    if sbom:
        arts.append({'id': 802, 'name': 'sbom-' + NEW_D.split(':', 1)[1], 'expired': False, 'created_at': at,
                     'archive_download_url': '@API_ROOT@/zips/sbom.zip',
                     'workflow_run': {'id': int(run_id), 'head_branch': 'main'}})
        binary['zips/sbom.zip'] = z('sbom.spdx.json', body)
    return arts, binary


def az(calls):
    return [c for c in calls if c[0] == 'az']


def swa_calls(calls):
    return [c for c in calls if c[0] == 'swa' and 'deploy' in c]


def step(res, sid):
    return res['steps'].get(sid) or {}


def outcome(res):
    return (res['evidence'].get('outcome.json') or {}).get('deployment_outcome') \
        if isinstance(res['evidence'].get('outcome.json'), dict) else None


def prod_marker(final):
    return ((final['staticwebapp']['environments'].get('default') or {}).get('marker') or {}).get('tree_digest')


def no_token(res, label):
    blobs = [res['log'], res['summary'], json.dumps(res['evidence'])]
    blobs += [json.dumps(st.get('outputs') or {}) for st in res['steps'].values()]
    leaked = [b for b in blobs if TOKEN in '\n'.join(l for l in b.split('\n') if '::add-mask::' not in l)]
    expect(not leaked, '%s: the deployment token appears nowhere but the ::add-mask:: command' % label)


def package_case():
    if not os.path.exists(CONTRACT):
        expect(False, 'P1 scripts/static_site_contract.py exists')
        return
    d = tempfile.mkdtemp(prefix='swa-pkg-')
    try:
        for p, b in NEW.items():
            if p == 'kit-release.json':
                continue
            os.makedirs(os.path.dirname(os.path.join(d, p)) or d, exist_ok=True)
            io.open(os.path.join(d, p), 'wb').write(b)
        out = os.path.join(d, '..', os.path.basename(d) + '.out')
        env = dict(os.environ, GITHUB_OUTPUT=out, GITHUB_REPOSITORY='o/r', GITHUB_RUN_ID='4242', GITHUB_SHA='f' * 40)
        p = subprocess.run([sys.executable, CONTRACT, 'package', '--dir', d], env=env, capture_output=True, text=True)
        o = dict(l.split('=', 1) for l in io.open(out, encoding='utf-8').read().split('\n') if '=' in l) \
            if os.path.exists(out) else {}
        marker = json.load(io.open(os.path.join(d, 'kit-release.json'), encoding='utf-8')) \
            if os.path.exists(os.path.join(d, 'kit-release.json')) else {}
        expect(p.returncode == 0 and o.get('site_digest') == NEW_D and marker.get('tree_digest') == NEW_D and
               o.get('artifact_name') == 'kit-static-site-' + NEW_D.split(':', 1)[1],
               'P1 packaging writes the marker and the oracle\'s tree digest (%s)' % (o or p.stderr[-200:]))
        io.open(os.path.join(d, 'index.html'), 'ab').write(b' ')
        p = subprocess.run([sys.executable, CONTRACT, 'package', '--dir', d], env=env, capture_output=True, text=True)
        o2 = dict(l.split('=', 1) for l in io.open(out, encoding='utf-8').read().split('\n') if '=' in l)
        expect(o2.get('site_digest') not in (None, NEW_D), 'P1 one changed byte changes the digest')
        if os.path.exists(out):
            os.remove(out)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def static_case():
    if not os.path.exists(WF):
        expect(False, 'S1 .github/workflows/reusable-deploy-staticwebapp.yml exists')
        return
    import yaml
    s = yaml.safe_load(io.open(WF, encoding='utf-8'))['jobs']['deploy']['steps']
    c = yaml.safe_load(io.open(CA, encoding='utf-8'))['jobs']['deploy']['steps']
    sid = dict((x.get('id'), x) for x in s if x.get('id'))
    cid = dict((x.get('id'), x) for x in c if x.get('id'))
    for k in ('bind', 'zone', 'protection', 'verdict', 'approval'):
        expect(k in sid and sid[k].get('run') == cid[k].get('run'),
               'S1 the %s step is byte-identical to the Container Apps reusable\'s' % k)
    ids = [x.get('id') for x in s]
    login = next((i for i, x in enumerate(s) if 'azure/login' in str(x.get('uses', ''))), len(s))
    order = ['bind', 'zone', 'protection', 'verdict', 'tier', 'verify_artifact', 'attestation', 'approval']
    expect(all(k in ids for k in order) and [ids.index(k) for k in order] == sorted(ids.index(k) for k in order)
           and ids.index('approval') < login, 'S1 the refusals before login run in order, all before azure/login')
    mat = next((x for x in s if x.get('name') == 'Materialise the deploy contract scripts'), {})
    expect('static_site_contract.py' in (mat.get('run') or ''), 'S1 static_site_contract.py is materialised')
    p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'inline_deploy_scripts.py'), '--check'],
                       capture_output=True, text=True)
    expect(p.returncode == 0 and 'staticwebapp' in p.stdout + p.stderr or p.returncode == 0,
           'S1 inline_deploy_scripts --check covers it and is in sync (%s)' % (p.stdout + p.stderr).strip()[-160:])


def jobs():
    if not os.path.exists(WF):
        for j in range(1, 11):
            expect(False, 'J%d the reusable exists to be run' % j)
        return
    # J1
    # The compressed test period is a recorded weakening: attributed here, so the healthy deploy routes
    # PROCEED_WITH_ADVISORY rather than owing a decision.
    res, final, calls = run(inputs(weakening_reason='a proof\'s compressed test period',
                                   weakening_authority='kit-maintainer'), state())
    sw = swa_calls(calls)
    envs = [c[c.index('--env') + 1] for c in sw]
    expect(outcome(res) == 'DEPLOY_HEALTHY' and envs == ['staging', 'production'] and prod_marker(final) == NEW_D,
           'J1 dev: preview then production, DEPLOY_HEALTHY, production serves the new digest (%s, %s, %s)'
           % (outcome(res), envs, (res['log'][-600:] if outcome(res) != 'DEPLOY_HEALTHY' else '')))
    rows = json.dumps((res['evidence'].get('outcome.json') or {}).get('now_serving') or [])
    expect(NEW_D in rows, 'J1 NOW SERVING names the digest read from the live marker')
    tags = final['staticwebapp'].get('tags') or {}
    expect(tags.get('deploy_provenance_digest') == NEW_D and tags.get('release_ownership_stamp'),
           'J1 provenance and the ownership stamp are tags on the static site (%s)' % sorted(tags))
    rec = res['evidence'].get('promotion-record.json') or {}
    expect(((rec.get('environment') or {}).get('adapter')) == 'staticwebapp' and
           (rec.get('artifact') or {}).get('digest') == NEW_D,
           'J1 the promotion record names the static site adapter and the digest')
    expect(step(res, 'posture').get('outputs', {}).get('routing_result') in ('PROCEED', 'PROCEED_WITH_ADVISORY'),
           'J1 the posture routes the healthy deploy (%s)' % step(res, 'posture').get('outputs', {}).get('routing_result'))
    no_token(res, 'J1')
    # J2
    bad = dict(NEW)
    bad['index.html'] = b'<html>tampered</html>'
    res, final, calls = run(inputs(), state(), new_files=bad)
    expect(step(res, 'verify_artifact').get('outcome') == 'failure' and not az(calls) and not swa_calls(calls)
           and 'SITE_DIGEST_MISMATCH' in res['log'],
           'J2 files that do not hash to the digest: SITE_DIGEST_MISMATCH before login, zero az/swa calls')
    expect(step(res, 'posture').get('outputs', {}).get('routing_result') == 'BLOCKED',
           'J2 the posture routes it BLOCKED')
    # J3
    res, final, calls = run(W.break_glass(inputs('uat-env', 'uat', preview_environment='')), state())
    expect(step(res, 'tier').get('outcome') == 'failure' and not az(calls),
           'J3 preview \'\' at uat refused before login (%s, %d az call(s))' % (step(res, 'tier').get('outcome'), len(az(calls))))
    # J4
    res, final, calls = run(inputs(), state(unhealthy_digests=[NEW_D]))
    envs = [c[c.index('--env') + 1] for c in swa_calls(calls)]
    expect(envs == ['staging'] and prod_marker(final) == PRIOR_D and 'staging' not in final['staticwebapp']['environments']
           and outcome(res) == 'ROLLBACK_VERIFIED',
           'J4 unhealthy preview: production untouched, preview removed, ROLLBACK_VERIFIED (%s, %s)' % (envs, outcome(res)))
    # J5
    res, final, calls = run(inputs(), state(unhealthy_host_digest={'site.azurestaticapps.example': NEW_D}))
    envs = [c[c.index('--env') + 1] for c in swa_calls(calls)]
    expect(envs == ['staging', 'production', 'production'] and prod_marker(final) == PRIOR_D and
           outcome(res) == 'ROLLBACK_VERIFIED',
           'J5 unhealthy production: the prior artefact redeployed and verified (%s, %s)' % (envs, outcome(res)))
    no_token(res, 'J5')
    # J6
    res, final, calls = run(inputs(), state(), prior_artifact=False)
    cap = step(res, 'capability').get('outputs', {}).get('rollback_capability')
    expect(cap == 'UNAVAILABLE' and outcome(res) == 'DEPLOY_HEALTHY',
           'J6 dev, prior artefact expired: UNAVAILABLE recorded, the deploy proceeds (%s, %s)' % (cap, outcome(res)))
    res, final, calls = run(W.break_glass(inputs('prod-env', 'prod', e2e_test_command='')), state(), prior_artifact=False)
    expect(step(res, 'capability').get('outcome') == 'failure' and not swa_calls(calls) and prod_marker(final) == PRIOR_D,
           'J6 prod, prior artefact expired: refused before any mutation (%s, %d swa call(s))'
           % (step(res, 'capability').get('outcome'), len(swa_calls(calls))))
    # J7
    res, final, calls = run(inputs(), state(prior='nonkit'))
    expect(step(res, 'before').get('outputs', {}).get('previous_state') == 'UNKNOWN' and not swa_calls(calls)
           and outcome(res) == 'DEPLOY_REFUSED',
           'J7 content with no kit marker: UNKNOWN, refused before any mutation (%s)' % outcome(res))
    # J8
    res, final, calls = run(inputs(), state(prior='none'))
    expect(step(res, 'before').get('outputs', {}).get('previous_state') == 'EMPTY' and
           step(res, 'capability').get('outputs', {}).get('rollback_capability') == 'NO_PRIOR_STATE' and
           outcome(res) == 'DEPLOY_HEALTHY', 'J8 a never-deployed site: EMPTY, NO_PRIOR_STATE, released (%s)' % outcome(res))
    # J9
    res, final, calls = run(inputs(), state(), env_extra={'KIT_RELEASE_BLOCK': 'platform_halted'})
    expect(step(res, 'zone').get('outcome') == 'failure' and not az(calls) and not swa_calls(calls),
           'J9 the landing zone\'s stop refuses the release before login')
    # J10: prod is PROMOTED (KDEC-029): the test record of exactly this digest, the site's SBOM re-scanned,
    # KEV, and V1 on the marker -- the same gate as an image; without the SBOM the re-check is incomplete.
    arts, binary = promotion_world()
    prom = inputs('prod-env', 'prod', e2e_test_command='', promote_from_run_id='90', promote_from_environment='test',
                  attestation_signer_workflow=SIGNER, attestations_available=True)
    kev = {'promotion_kev': {'kev_state': 'AVAILABLE', 'kev_verdict': 'CLEAR', 'kev_blocking': ''}}
    res, final, calls = run(prom, state(), extra_arts=arts, binary_extra=binary, uses_outputs=kev,
                            tools={'gh': GH_FILE_VERIFIED, 'trivy': W._TRIVY_CLEAN})
    gate = step(res, 'promotion_gate').get('outputs', {}).get('promotion_gate')
    expect(gate == 'PROMOTION_ALLOWED' and step(res, 'attestation').get('outputs', {}).get('outcome') ==
           'ATTESTATION_VERIFIED' and outcome(res) == 'DEPLOY_HEALTHY' and prod_marker(final) == NEW_D,
           'J10 a prod promotion of the verified test digest: V1 on the marker VERIFIED, PROMOTION_ALLOWED, '
           'released (%s, %s, %s)' % (gate, step(res, 'attestation').get('outputs', {}).get('outcome'), outcome(res)))
    arts, binary = promotion_world(sbom=False)
    res, final, calls = run(prom, state(), extra_arts=arts, binary_extra=binary, uses_outputs=kev,
                            tools={'gh': GH_FILE_VERIFIED, 'trivy': W._TRIVY_CLEAN})
    gate = step(res, 'promotion_gate').get('outputs', {}).get('promotion_gate')
    expect(gate == 'PROMOTION_REFUSED_RECHECK_INCOMPLETE' and not az(calls) and not swa_calls(calls),
           'J10 no SBOM to re-scan: PROMOTION_REFUSED_RECHECK_INCOMPLETE before login (%s)' % gate)


EP = ('/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg-edge/providers/'
      'Microsoft.Cdn/profiles/afd-shared/afdEndpoints/ep-site')
KV_REF = '@Microsoft.KeyVault(SecretUri=https://kv-lz.vault.example/secrets/api-key/)'
WEAK = dict(weakening_reason="a proof's compressed test period", weakening_authority='kit-maintainer')


def mutating_az(calls):
    return [c for c in az(calls) if any(w in c[1:5] for w in ('update', 'set', 'delete', 'create', 'purge'))]


def seam_cases():
    """J11: the seam step, run as shipped."""
    lease = {'KIT_TARGET_LEASE_ACCOUNT': 'seamleasedev'}
    for label, settings, keys, faults, want in (
            ('a kit key the landing zone backs with a Key Vault reference', {'api_key': KV_REF}, 'api_key', {},
             'SEAM_SETTING_OWNERSHIP_CONFLICT'),
            ('the settings unreadable', {}, '', {'fail': ['staticwebapp appsettings list']},
             'SEAM_OWNERSHIP_NOT_ESTABLISHED'),
            ('a plain kit key (control)', {'feature_x': '1', 'mode': 'lz'}, 'feature_x', {}, 'SEAM_OWNERSHIP_HELD')):
        st = state(**faults)
        st['staticwebapp']['appsettings'] = settings
        res, final, calls = run(inputs(**WEAK), st, env_extra=dict(lease, KIT_SETTING_KEYS=keys))
        sm = step(res, 'seam')
        got = (sm.get('outputs') or {}).get('seam_ownership')
        refused = want != 'SEAM_OWNERSHIP_HELD'
        expect(got == want and sm.get('outcome') == ('failure' if refused else 'success') and
               ((not swa_calls(calls) and not mutating_az(calls)) if refused else True),
               'J11 %s -> %s (%s, %s, %d swa / %d mutating az call(s))'
               % (label, want, got, sm.get('outcome'), len(swa_calls(calls)), len(mutating_az(calls))))
        if want == 'SEAM_SETTING_OWNERSHIP_CONFLICT':
            blobs = res['log'] + res['summary'] + json.dumps(res['evidence'])
            expect('kv-lz.vault.example' not in blobs, 'J11 the Key Vault reference is never shown')
            expect(step(res, 'posture').get('outputs', {}).get('routing_result') == 'BLOCKED',
                   'J11 the posture routes the seam refusal BLOCKED (%s)'
                   % step(res, 'posture').get('outputs', {}).get('routing_result'))
    res, final, calls = run(inputs(**WEAK), state())
    expect(step(res, 'seam').get('outcome') in ('skipped', None) and outcome(res) == 'DEPLOY_HEALTHY' and
           any(n.startswith('Field ownership at the seam') for n, _o in res['order']),
           'J11 the lease off: the seam step is skipped, the release is as before (%s, %s)'
           % (step(res, 'seam').get('outcome'), outcome(res)))


def purge_cases():
    """J12: the edge purge, run as shipped."""
    def purges(calls):
        return [c for c in az(calls) if c[1:4] == ['afd', 'endpoint', 'purge']]

    def edge(res):
        return (step(res, 'purge').get('outputs') or {}).get('edge_purge')
    res, final, calls = run(inputs(**WEAK), state(), env_extra={'KIT_EDGE_ENDPOINT': EP})
    order = [n for n, _o in res['order']]
    pv = 'Stamp provenance (after health and a live read)'
    pi = next((i for i, n in enumerate(order) if n.startswith('Purge the app')), -1)
    p = purges(calls)
    expect(len(p) == 1 and 'ep-site' in p[0] and 'afd-shared' in p[0] and 'rg-edge' in p[0] and
           edge(res) == 'EDGE_PURGED' and pv in order and order.index(pv) < pi and outcome(res) == 'DEPLOY_HEALTHY',
           'J12 a verified release purges the vended endpoint once, after the provenance stamp (%d call(s), %s, %s)'
           % (len(p), edge(res), outcome(res)))
    res, final, calls = run(inputs(**WEAK), state(unhealthy_host_digest={'site.azurestaticapps.example': NEW_D}),
                            env_extra={'KIT_EDGE_ENDPOINT': EP})
    expect(not purges(calls) and outcome(res) == 'ROLLBACK_VERIFIED',
           'J12 an unhealthy production purges nothing (%s)' % outcome(res))
    res, final, calls = run(inputs(**WEAK), state())
    expect(not purges(calls) and edge(res) == 'EDGE_PURGE_NOT_APPLICABLE',
           'J12 none vended -> EDGE_PURGE_NOT_APPLICABLE, no call (%s)' % edge(res))
    res, final, calls = run(inputs(**WEAK), state(), env_extra={
        'KIT_EDGE_ENDPOINT': '/subscriptions/x/resourceGroups/rg/providers/Microsoft.Web/staticSites/other'})
    expect(not purges(calls) and edge(res) == 'EDGE_PURGE_REFUSED',
           'J12 not an afdEndpoints id -> EDGE_PURGE_REFUSED, no call (%s)' % edge(res))
    res, final, calls = run(inputs(**WEAK), state(fail=['afd endpoint purge']), env_extra={'KIT_EDGE_ENDPOINT': EP})
    route = step(res, 'posture').get('outputs', {}).get('routing_result')
    expect(edge(res) == 'EDGE_PURGE_FAILED' and outcome(res) == 'DEPLOY_HEALTHY' and route == 'PROCEED_WITH_ADVISORY'
           and '| edge purge (D-4) | `EDGE_PURGE_FAILED` |' in res['summary'],
           'J12 a failed purge -> EDGE_PURGE_FAILED, still DEPLOY_HEALTHY, PROCEED_WITH_ADVISORY, in the posture '
           'record (%s, %s, %s)' % (edge(res), outcome(res), route))


def main():
    try:
        import yaml  # noqa: F401
    except ImportError:
        print('UNKNOWN: PyYAML unavailable.')
        return 2
    bash, why = W.D.bash()
    if not bash:
        print('UNKNOWN: no usable bash (%s).' % why)
        return 2
    package_case()
    static_case()
    jobs()
    seam_cases()
    purge_cases()
    if FAILS:
        print('FAIL: %d case(s).' % len(FAILS))
        return 1
    print('PASS: a static site is packaged with a content digest, released by that digest through a preview '
          'environment, verified on the live marker, reversed to the prior artefact when it fails, and refused '
          'before login on a mismatched artefact, a direct-to-production path at uat/prod, a stopped platform; '
          'an unknown prior state or an unrecoverable one at prod is refused before any mutation; the deployment '
          'token never reaches a log or a record.')
    print('      STUBBED: the Azure side is tests/_fake_az.py and the SWA CLI a stand-in; a live run on the '
          'owner\'s personal tenant is owed (deploy-staticwebapp-live).')
    return 0


if __name__ == '__main__':
    sys.exit(main())
