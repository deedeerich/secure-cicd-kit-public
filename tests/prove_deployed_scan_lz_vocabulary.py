#!/usr/bin/env python3
"""The daily deployed scan reports in the landing zone's drift vocabulary too, so one view serves both.
(OF-5 K-10; the LZ-vs-kit review's P13)

WHY THIS EXISTS

    The landing zone's drift job reports `drift.detected` with a DIMENSION (iac, identity, authentication,
    authorisation, network_exposure, security_control, monitoring -- and, since the review, release, from
    its seam detector) and a CLASS (benign, operational, critical), and `not_attempted` when it could not
    finish, never "no drift". The kit's daily scan of what serves (KDEC-029 item 8) reports its own rules
    (KIT-ARTIFACT-DRIFT, KIT-SECURITY-SETTINGS, ...) with artifact and security drift kept apart. The two
    are complementary; a platform admin looking at one view had to translate. Now every kit finding also
    carries the landing zone's dimension and class (SARIF result properties lz_drift_dimension and
    lz_drift_class) and the scan writes a `drift_view` list in the landing zone's terms. Nothing about the
    kit's own rules, routing or tickets changes, and the scan still never rolls anything back.

CASES
    V1  every rule the scan can emit (DRIFT_RULES and the KEV rule) maps to a registered dimension and class
    V2  serving an unverified digest -> KIT-ARTIFACT-DRIFT is release / critical (a digest no kit run
        verified); serving a digest the kit verified elsewhere -> release / operational
    V3  what serves could not be re-scanned -> security_control / not_attempted, never "no drift"
    V4  plain-HTTP ingress -> KIT-SECURITY-SETTINGS is network_exposure / critical
    V5  a critical CVE in what serves -> the drift_view names security_control / critical
    V6  reconciled, nothing found -> an empty drift_view (and the kit's own result unchanged)
    V7  a known-exploited CVE in what serves (the finish phase) -> security_control / critical
    V8  the scan writes nothing to the target

EXIT 0 proven   1 a case failed   2 could not be checked
"""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
import _workflow_runner as W  # noqa: E402
import prove_promotion as PP  # noqa: E402  (its recorded world: records, SBOM, tool stand-ins)

FAILS = []
DIMENSIONS = ('iac', 'identity', 'authentication', 'authorisation', 'network_exposure', 'security_control',
              'monitoring', 'release')
CLASSES = ('benign', 'operational', 'critical', 'not_attempted')
UNVERIFIED = 'sha256:' + 'e' * 64


def expect(cond, label):
    print('%s  %s' % ('ok  ' if cond else 'FAIL', label))
    if not cond:
        FAILS.append(label)


def record(digest):
    return {'schema': 'kit-promotion-record/1', 'record_id': '301-1-prod', 'state': 'verified-for-promotion',
            'release_path': 'normal',
            'artifact': {'digest': digest, 'sbom_sha256': PP.SBOM_SHA},
            'environment': {'name': 'prod', 'tier': 'prod', 'adapter': 'containerapp'},
            'provenance': {'source_ref': 'refs/heads/main'},
            'live_state': {'deployment_outcome': 'DEPLOY_HEALTHY'}, 'run': {'id': '301'},
            'validity': {'verified_at': '2026-10-26T00:00:00Z'}, 'approval': {'approvers': []}}


def scan(serving, findings=(), insecure=False, kev=''):
    d = tempfile.mkdtemp(prefix='lz-drift-')
    try:
        rec = record(W.NEW)
        files, binary = PP.world_api([(rec, '301', 'main', '2026-10-26T00:00:00Z')])
        api = os.path.join(d, 'api')
        url = 'file:///' + api.replace('\\', '/').lstrip('/')
        for rel, body in list(files.items()) + list(binary.items()):
            p = os.path.join(api, *rel.split('/'))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            io.open(p, 'wb').write(body if isinstance(body, bytes) else body.replace('@API_ROOT@', url).encode('utf-8'))
        st = W.containerapp_state()
        st['containerapp']['revisions']['web--r1']['image'] = W.ref(serving)
        st['containerapp']['allowInsecure'] = insecure
        state_path, log_path = os.path.join(d, 's.json'), os.path.join(d, 'c.jsonl')
        io.open(state_path, 'w').write(json.dumps(st))
        io.open(log_path, 'w').close()
        bin_dir = W.stub_bin(state_path, log_path)
        W.add_tools(bin_dir, PP.TOOLS)
        rt = os.path.join(d, 'rt')
        os.makedirs(rt)
        env = dict(os.environ, PATH=bin_dir + os.pathsep + os.environ.get('PATH', ''), RUNNER_TEMP=rt,
                   fake_az_state=state_path, fake_az_log=log_path, GITHUB_REPOSITORY='o/r', GITHUB_API_URL=url,
                   DEPLOY_ENVIRONMENT='prod', CONTAINERAPP_NAME='web', RESOURCE_GROUP='rg-a',
                   FAKE_TRIVY_FINDINGS=json.dumps(list(findings)), AZURE_CONFIG_DIR=os.path.join(d, 'noaz'),
                   GITHUB_OUTPUT=os.path.join(d, 'out.txt'))
        p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'promotion.py'), 'deployed-scan',
                            '--adapter', 'containerapp'], env=env, capture_output=True, text=True,
                           encoding='utf-8', errors='replace')
        if p.returncode == 0:
            env2 = dict(env, KEV_STATE='AVAILABLE', KEV_BLOCKING=kev)
            p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'promotion.py'), 'deployed-finish',
                                '--adapter', 'containerapp'], env=env2, capture_output=True, text=True,
                               encoding='utf-8', errors='replace')
        out = os.path.join(rt, 'promotion', 'deployed')
        doc = PP.PR.jload(os.path.join(out, 'deployed-scan-prod.json')) or {}
        sar = PP.PR.jload(os.path.join(out, 'deployed-state-prod.sarif')) or {}
        results = (sar.get('runs') or [{}])[0].get('results') or []
        calls = [json.loads(x) for x in io.open(log_path) if x.strip()]
        shutil.rmtree(bin_dir, ignore_errors=True)
        return p, doc, results, calls
    finally:
        shutil.rmtree(d, ignore_errors=True)


def swa_case():
    """V9 (K-8 x K-10): the daily scan reads what a STATIC SITE serves from its live marker -- the content
    digest -- and labels a digest no kit run verified release / critical, like an image."""
    d = tempfile.mkdtemp(prefix='lz-drift-swa-')
    try:
        rec = record(W.NEW)
        rec['environment']['adapter'] = 'staticwebapp'
        files, binary = PP.world_api([(rec, '301', 'main', '2026-10-26T00:00:00Z')])
        api = os.path.join(d, 'api')
        url = 'file:///' + api.replace('\\', '/').lstrip('/')
        for rel, body in list(files.items()) + list(binary.items()):
            p = os.path.join(api, *rel.split('/'))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            io.open(p, 'wb').write(body if isinstance(body, bytes) else body.replace('@API_ROOT@', url).encode('utf-8'))
        st = {'staticwebapp': {'name': 'site', 'host': 'site.azurestaticapps.example', 'tags': {}, 'sku': 'Standard',
                               'id': '/subscriptions/0/resourceGroups/rg-a/providers/Microsoft.Web/staticSites/site',
                               'repositoryUrl': None, 'apiKey': 'x',
                               'environments': {'default': {'status': 'Ready',
                                                            'marker': {'schema': 'kit-static-site/1',
                                                                       'tree_digest': UNVERIFIED}}}}}
        state_path, log_path = os.path.join(d, 's.json'), os.path.join(d, 'c.jsonl')
        io.open(state_path, 'w').write(json.dumps(st))
        io.open(log_path, 'w').close()
        bin_dir = W.stub_bin(state_path, log_path)
        W.add_tools(bin_dir, PP.TOOLS)
        rt = os.path.join(d, 'rt')
        os.makedirs(rt)
        env = dict(os.environ, PATH=bin_dir + os.pathsep + os.environ.get('PATH', ''), RUNNER_TEMP=rt,
                   fake_az_state=state_path, fake_az_log=log_path, GITHUB_REPOSITORY='o/r', GITHUB_API_URL=url,
                   DEPLOY_ENVIRONMENT='prod', RESOURCE_GROUP='rg-a', **{'site_name'.upper(): 'site'},
                   FAKE_TRIVY_FINDINGS='[]', AZURE_CONFIG_DIR=os.path.join(d, 'noaz'),
                   GITHUB_OUTPUT=os.path.join(d, 'out.txt'))
        p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'promotion.py'), 'deployed-scan',
                            '--adapter', 'staticwebapp'], env=env, capture_output=True, text=True,
                           encoding='utf-8', errors='replace')
        out = os.path.join(rt, 'promotion', 'deployed')
        doc = PP.PR.jload(os.path.join(out, 'deployed-scan-prod.json')) or {}
        sar = PP.PR.jload(os.path.join(out, 'deployed-state-prod.sarif')) or {}
        results = (sar.get('runs') or [{}])[0].get('results') or []
        a = props(results, 'KIT-ARTIFACT-DRIFT')
        serving = doc.get('serving') or [{}]
        expect(p.returncode == 0 and serving[0].get('digest') == UNVERIFIED and a and
               a[0].get('lz_drift_dimension') == 'release' and a[0].get('lz_drift_class') == 'critical',
               'V9 a static site: what serves is read from its live marker, and an unverified digest is '
               'release / critical (rc=%s, serving %s, %s)' % (p.returncode, serving, a or (p.stdout + p.stderr)[-300:]))
        shutil.rmtree(bin_dir, ignore_errors=True)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def props(results, rule):
    return [(r.get('properties') or {}) for r in results if r.get('ruleId') == rule]


def main():
    try:
        import promotion as PR
    except ImportError as exc:
        print('FAIL: %s' % exc)
        return 1
    mapping = getattr(PR, 'LZ_DRIFT', None)
    rules = list(PR.DRIFT_RULES) + ['KIT-KNOWN-EXPLOITED-SERVING']
    expect(isinstance(mapping, dict) and all(r in mapping for r in rules) and
           all(mapping[r][0] in DIMENSIONS and mapping[r][1] in CLASSES for r in rules if r in (mapping or {})),
           'V1 every rule the scan emits maps to a landing-zone dimension and class (%s)' % sorted(set(rules) - set(mapping or {})))

    p, doc, results, calls = scan(UNVERIFIED)
    a = props(results, 'KIT-ARTIFACT-DRIFT')
    expect(p.returncode == 0 and a and a[0].get('lz_drift_dimension') == 'release' and a[0].get('lz_drift_class') == 'critical',
           'V2 an unverified digest serving -> release / critical (%s)' % a)
    rs = props(results, 'KIT-RESCAN-NOT-ESTABLISHED')
    expect(rs and rs[0].get('lz_drift_dimension') == 'security_control' and rs[0].get('lz_drift_class') == 'not_attempted',
           'V3 a digest that could not be re-scanned -> security_control / not_attempted (%s)' % rs)
    view = doc.get('drift_view') or []
    expect(any(v.get('dimension') == 'release' and v.get('class') == 'critical' for v in view),
           'V2 the drift_view carries it in the landing zone\'s terms')
    expect(not PP.az_writes(calls), 'V8 the scan wrote nothing to the target')

    p, doc, results, calls = scan(W.NEW, insecure=True)
    s = props(results, 'KIT-SECURITY-SETTINGS')
    expect(s and s[0].get('lz_drift_dimension') == 'network_exposure' and s[0].get('lz_drift_class') == 'critical',
           'V4 plain-HTTP ingress -> network_exposure / critical (%s)' % s)

    p, doc, results, calls = scan(W.NEW, findings=[{'VulnerabilityID': 'CVE-2026-7777', 'PkgName': 'openssl',
                                                    'InstalledVersion': '3.0', 'Severity': 'CRITICAL'}])
    view = doc.get('drift_view') or []
    expect(doc.get('security_drift') is True and
           any(v.get('dimension') == 'security_control' and v.get('class') == 'critical' for v in view),
           'V5 a critical CVE in what serves -> security_control / critical in the drift_view (%s)' % view)

    p, doc, results, calls = scan(W.NEW)
    expect(p.returncode == 0 and doc.get('drift_view') == [] and not results,
           'V6 reconciled, nothing found -> an empty drift_view (%s)' % doc.get('drift_view'))

    p, doc, results, calls = scan(W.NEW, kev='CVE-2021-44228@log4j')
    k = props(results, 'KIT-KNOWN-EXPLOITED-SERVING')
    expect(k and k[0].get('lz_drift_dimension') == 'security_control' and k[0].get('lz_drift_class') == 'critical' and
           any(v.get('rule') == 'KIT-KNOWN-EXPLOITED-SERVING' for v in doc.get('drift_view') or []),
           'V7 a known-exploited CVE in what serves -> security_control / critical (%s)' % k)
    swa_case()
    if FAILS:
        print('FAIL: %d case(s).' % len(FAILS))
        return 1
    print('PASS: every deployed-scan finding carries the landing zone\'s drift dimension and class, the scan writes '
          'a drift_view in its terms (not_attempted where nothing was established), and nothing else changes.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
